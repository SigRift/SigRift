"""Tests for SAFBuffer (store-and-forward) in detection_reporter.py.

Covers enqueue/peek, mark_sent, mark_failed, pending_count,
cleanup, FIFO ordering, JSON roundtrip, empty-queue edge cases,
concurrent access, and integration with DetectionReporter.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from sigrift.bridge.detection_reporter import SAFBuffer


def _make_payload(batch_id: str = "batch-1", n_detections: int = 3) -> dict:
    """Build a minimal detection batch payload for testing."""
    return {
        "node_id": "node-test-01",
        "batch_id": batch_id,
        "period_start": time.time() - 10,
        "period_end": time.time(),
        "detections": [
            {
                "id": f"det-{i}",
                "node_id": "node-test-01",
                "signal_class": "bpsk",
                "confidence": 0.95,
                "freq_hz": 433.92e6,
                "snr_db": 15.0,
                "power_dbm": -65.0,
            }
            for i in range(n_detections)
        ],
        "summary": {
            "total_detections": n_detections,
            "class_counts": {"bpsk": n_detections},
            "avg_confidence": 0.95,
            "dominant_class": "bpsk",
            "dominant_family": "PSK",
        },
    }


class TestSAFBufferEnqueuePeek(unittest.TestCase):
    """Enqueue stores payload, peek retrieves it."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_enqueue_and_peek(self):
        payload = _make_payload("batch-enq-1")
        queue_id = self.saf.enqueue(payload)
        self.assertIsInstance(queue_id, int)
        self.assertGreater(queue_id, 0)

        results = self.saf.peek(limit=10)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], queue_id)
        self.assertEqual(results[0][1]["batch_id"], "batch-enq-1")

    def test_peek_returns_full_payload(self):
        payload = _make_payload("batch-full", n_detections=5)
        self.saf.enqueue(payload)
        results = self.saf.peek()
        _, retrieved = results[0]
        self.assertEqual(len(retrieved["detections"]), 5)
        self.assertEqual(retrieved["summary"]["total_detections"], 5)


class TestSAFBufferMarkSent(unittest.TestCase):
    """mark_sent removes the batch from the queue."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_mark_sent_removes_from_queue(self):
        qid = self.saf.enqueue(_make_payload("batch-sent-1"))
        self.assertEqual(self.saf.pending_count(), 1)

        self.saf.mark_sent(qid)
        self.assertEqual(self.saf.pending_count(), 0)
        self.assertEqual(self.saf.peek(), [])

    def test_mark_sent_only_removes_target(self):
        qid1 = self.saf.enqueue(_make_payload("batch-s1"))
        qid2 = self.saf.enqueue(_make_payload("batch-s2"))
        self.saf.mark_sent(qid1)
        results = self.saf.peek()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0][0], qid2)


class TestSAFBufferMarkFailed(unittest.TestCase):
    """mark_failed increments the attempt counter."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_mark_failed_increments_attempts(self):
        qid = self.saf.enqueue(_make_payload("batch-fail-1"))
        self.saf.mark_failed(qid)
        self.saf.mark_failed(qid)

        # Still pending after failures
        self.assertEqual(self.saf.pending_count(), 1)

        # Check attempt count directly
        with self.saf._connect() as conn:
            row = conn.execute(
                "SELECT attempts FROM saf_queue WHERE id = ?", (qid,)
            ).fetchone()
        self.assertEqual(row[0], 2)

    def test_mark_failed_sets_last_attempt(self):
        qid = self.saf.enqueue(_make_payload("batch-fail-ts"))
        self.saf.mark_failed(qid)

        with self.saf._connect() as conn:
            row = conn.execute(
                "SELECT last_attempt FROM saf_queue WHERE id = ?", (qid,)
            ).fetchone()
        self.assertIsNotNone(row[0])


class TestSAFBufferPendingCount(unittest.TestCase):
    """pending_count returns accurate counts."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_empty_count(self):
        self.assertEqual(self.saf.pending_count(), 0)

    def test_count_after_enqueue(self):
        self.saf.enqueue(_make_payload("b1"))
        self.saf.enqueue(_make_payload("b2"))
        self.saf.enqueue(_make_payload("b3"))
        self.assertEqual(self.saf.pending_count(), 3)

    def test_count_after_mark_sent(self):
        qid1 = self.saf.enqueue(_make_payload("b1"))
        self.saf.enqueue(_make_payload("b2"))
        self.saf.mark_sent(qid1)
        self.assertEqual(self.saf.pending_count(), 1)


class TestSAFBufferCleanup(unittest.TestCase):
    """cleanup removes batches older than max_age_hours."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_cleanup_removes_old_entries(self):
        # Insert with artificially old timestamp
        with self.saf._connect() as conn:
            conn.execute(
                "INSERT INTO saf_queue (payload, created_at, status) VALUES (?, ?, 'pending')",
                ('{"old": true}', "2020-01-01T00:00:00"),
            )
        self.assertEqual(self.saf.pending_count(), 1)

        removed = self.saf.cleanup(max_age_hours=1)
        self.assertEqual(removed, 1)
        self.assertEqual(self.saf.pending_count(), 0)

    def test_cleanup_preserves_recent(self):
        self.saf.enqueue(_make_payload("recent"))
        removed = self.saf.cleanup(max_age_hours=1)
        self.assertEqual(removed, 0)
        self.assertEqual(self.saf.pending_count(), 1)

    def test_cleanup_mixed_ages(self):
        # One old, one recent
        with self.saf._connect() as conn:
            conn.execute(
                "INSERT INTO saf_queue (payload, created_at, status) VALUES (?, ?, 'pending')",
                ('{"old": true}', "2020-01-01T00:00:00"),
            )
        self.saf.enqueue(_make_payload("recent"))
        self.assertEqual(self.saf.pending_count(), 2)

        removed = self.saf.cleanup(max_age_hours=1)
        self.assertEqual(removed, 1)
        self.assertEqual(self.saf.pending_count(), 1)


class TestSAFBufferFIFO(unittest.TestCase):
    """Batches are returned in FIFO order by peek."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_fifo_ordering(self):
        self.saf.enqueue(_make_payload("first"))
        self.saf.enqueue(_make_payload("second"))
        self.saf.enqueue(_make_payload("third"))

        results = self.saf.peek(limit=10)
        batch_ids = [r[1]["batch_id"] for r in results]
        self.assertEqual(batch_ids, ["first", "second", "third"])

    def test_peek_limit(self):
        for i in range(5):
            self.saf.enqueue(_make_payload(f"b-{i}"))
        results = self.saf.peek(limit=2)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1]["batch_id"], "b-0")
        self.assertEqual(results[1][1]["batch_id"], "b-1")


class TestSAFBufferJSONRoundtrip(unittest.TestCase):
    """Payloads survive JSON serialization/deserialization."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_roundtrip_preserves_types(self):
        payload = _make_payload("rt-1", n_detections=2)
        self.saf.enqueue(payload)
        results = self.saf.peek()
        retrieved = results[0][1]

        # Numeric types preserved
        self.assertIsInstance(retrieved["detections"][0]["confidence"], float)
        self.assertIsInstance(retrieved["detections"][0]["freq_hz"], float)
        # String types preserved
        self.assertIsInstance(retrieved["batch_id"], str)
        self.assertEqual(retrieved["batch_id"], "rt-1")

    def test_roundtrip_nested_structure(self):
        payload = _make_payload("rt-nested")
        self.saf.enqueue(payload)
        retrieved = self.saf.peek()[0][1]
        self.assertIn("summary", retrieved)
        self.assertEqual(retrieved["summary"]["dominant_class"], "bpsk")


class TestSAFBufferEmptyQueue(unittest.TestCase):
    """Operations on an empty queue should not error."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_peek_empty(self):
        self.assertEqual(self.saf.peek(), [])

    def test_pending_count_empty(self):
        self.assertEqual(self.saf.pending_count(), 0)

    def test_cleanup_empty(self):
        removed = self.saf.cleanup()
        self.assertEqual(removed, 0)

    def test_mark_sent_nonexistent(self):
        # Should not raise
        self.saf.mark_sent(999)

    def test_mark_failed_nonexistent(self):
        # Should not raise
        self.saf.mark_failed(999)


class TestSAFBufferConcurrency(unittest.TestCase):
    """SAFBuffer is safe for concurrent access from multiple threads."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"
        self.saf = SAFBuffer(db_path=self.tmp)

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_concurrent_enqueue(self):
        errors = []

        def enqueue_batch(thread_id: int):
            try:
                for i in range(10):
                    self.saf.enqueue(_make_payload(f"t{thread_id}-b{i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=enqueue_batch, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(self.saf.pending_count(), 40)

    def test_concurrent_enqueue_and_peek(self):
        errors = []

        def writer():
            try:
                for i in range(20):
                    self.saf.enqueue(_make_payload(f"w-{i}"))
            except Exception as e:
                errors.append(e)

        def reader():
            try:
                for _ in range(20):
                    self.saf.peek(limit=5)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(errors, [])


class TestSAFReporterIntegration(unittest.TestCase):
    """SAF integrates correctly with DetectionReporter upload failure path."""

    def setUp(self):
        self._tmpdir = Path(tempfile.mkdtemp())
        self.tmp = self._tmpdir / "saf.db"

    def tearDown(self):
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_upload_failure_enqueues_to_saf(self):
        from sigrift.bridge.detection_reporter import DetectionReporter

        reporter = DetectionReporter(
            server_url="https://localhost:9999",
            api_key="test-key",
            node_id="node-saf-1",
            max_retries=1,
            base_retry_delay=0.01,
            max_retry_delay=0.01,
            saf_db_path=self.tmp,
        )

        # Report enough detections to trigger a flush
        for i in range(5):
            reporter.report(
                {"class": "bpsk", "confidence": 0.9, "family": "PSK", "inference_ms": 1.0},
                freq_hz=433.92e6 + i * 1e6,  # unique freqs to avoid dedup
                snr_db=15.0,
                power_dbm=-65.0,
            )

        # Force flush - upload will fail (no server)
        reporter._do_flush()

        # Batch should be in SAF
        stats = reporter.get_stats()
        self.assertGreater(stats["saf_enqueued"], 0)
        self.assertGreater(stats["saf_pending"], 0)

    def test_saf_stats_in_get_stats(self):
        from sigrift.bridge.detection_reporter import DetectionReporter

        reporter = DetectionReporter(
            server_url="https://localhost:9999",
            api_key="test-key",
            node_id="node-stats-1",
            saf_db_path=self.tmp,
        )
        stats = reporter.get_stats()
        self.assertIn("saf_enqueued", stats)
        self.assertIn("saf_replayed", stats)
        self.assertIn("saf_pending", stats)
        self.assertEqual(stats["saf_enqueued"], 0)
        self.assertEqual(stats["saf_replayed"], 0)
        self.assertEqual(stats["saf_pending"], 0)

    def test_replay_saf_calls_upload(self):
        from sigrift.bridge.detection_reporter import DetectionReporter

        reporter = DetectionReporter(
            server_url="https://localhost:9999",
            api_key="test-key",
            node_id="node-replay-1",
            max_retries=1,
            base_retry_delay=0.01,
            max_retry_delay=0.01,
            saf_db_path=self.tmp,
        )

        # Manually enqueue a batch
        payload = _make_payload("replay-test")
        reporter._saf.enqueue(payload)
        self.assertEqual(reporter._saf.pending_count(), 1)

        # Mock _upload to succeed
        reporter._upload = MagicMock(return_value=True)
        replayed = reporter._replay_saf()

        self.assertEqual(replayed, 1)
        self.assertEqual(reporter._saf.pending_count(), 0)
        reporter._upload.assert_called_once()

    def test_replay_saf_stops_on_failure(self):
        from sigrift.bridge.detection_reporter import DetectionReporter

        reporter = DetectionReporter(
            server_url="https://localhost:9999",
            api_key="test-key",
            node_id="node-replay-fail-1",
            max_retries=1,
            base_retry_delay=0.01,
            max_retry_delay=0.01,
            saf_db_path=self.tmp,
        )

        # Enqueue multiple batches
        reporter._saf.enqueue(_make_payload("stop-1"))
        reporter._saf.enqueue(_make_payload("stop-2"))
        reporter._saf.enqueue(_make_payload("stop-3"))

        # Upload always fails
        reporter._upload = MagicMock(return_value=False)
        replayed = reporter._replay_saf()

        # Should stop after first failure
        self.assertEqual(replayed, 0)
        self.assertEqual(reporter._saf.pending_count(), 3)
        reporter._upload.assert_called_once()


if __name__ == "__main__":
    unittest.main()
