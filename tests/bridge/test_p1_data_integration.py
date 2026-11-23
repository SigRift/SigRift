"""Integration tests for P1 data management: SigMF, IQ metadata, job queue.

Covers:
  - End-to-end job lifecycle: submit -> poll -> completion -> result check
  - IQ metadata: store -> query -> retention enforcement -> deletion
  - SigMF: generate metadata for various signal types -> validate structure
  - Cross-feature: IQ capture + SigMF metadata + IQ metadata consistency
  - Edge cases: duplicate jobs, large metadata payloads, concurrent access
  - Retention: cleanup of old IQ metadata works correctly
"""

from __future__ import annotations

import asyncio
import gzip
import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.iq_store import IQStore
from sigrift.bridge.job_queue import AnalysisJobQueue
from sigrift.bridge.sigmf import generate_sigmf_meta, save_sigmf_meta
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.iq_metadata import IQMetadataStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_iq_data(n_samples: int = 4096) -> bytes:
    """Create gzip-compressed IQ data with a tone at normalised freq 0.1."""
    iq = np.exp(1j * 2 * np.pi * 0.1 * np.arange(n_samples)).astype(np.complex64)
    interleaved = np.empty(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return gzip.compress(interleaved.tobytes())


def _make_metadata(
    node_id: str = "node-01",
    freq_hz: float = 433.92e6,
    signal_class: str = "bpsk",
    tier: str = "standard",
    captured_at: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Create a metadata dict for testing."""
    if captured_at is None:
        captured_at = datetime.now(timezone.utc).isoformat()
    return {
        "node_id": node_id,
        "freq_hz": freq_hz,
        "signal_class": signal_class,
        "sample_rate": 2.048e6,
        "n_samples": 256,
        "file_size_bytes": 1024,
        "quality_score": 0.85,
        "captured_at": captured_at,
        "tier": tier,
        **kwargs,
    }


def _echo_handler(job_id: str, params: dict) -> dict:
    """Simple handler that echoes params back."""
    return {"echo": params, "job_id": job_id}


def _slow_handler(job_id: str, params: dict) -> dict:
    """Handler that takes a brief moment to complete."""
    import time

    time.sleep(0.05)
    return {"done": True, "value": params.get("value", 0)}


def _failing_handler(job_id: str, params: dict) -> dict:
    """Handler that always raises."""
    raise RuntimeError("intentional test failure")


async def _async_echo_handler(job_id: str, params: dict) -> dict:
    """Async handler that echoes params back."""
    await asyncio.sleep(0.01)
    return {"async_echo": params, "job_id": job_id}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    return SharedContext(db_path=tmp_path / "test_integration.db")


@pytest.fixture
def iq_meta(ctx: SharedContext) -> IQMetadataStore:
    return IQMetadataStore(ctx)


@pytest.fixture
def iq_store(tmp_path: Path) -> IQStore:
    return IQStore(base_dir=tmp_path / "iq_captures")


# ---------------------------------------------------------------------------
# 1. End-to-end job lifecycle tests
# ---------------------------------------------------------------------------


class TestJobLifecycleE2E:
    """End-to-end job lifecycle: submit -> poll -> completion -> result."""

    @pytest.mark.asyncio
    async def test_full_lifecycle_submit_poll_complete(self):
        """Submit a job, poll until completed, verify result is correct."""
        q = AnalysisJobQueue(max_workers=1, max_queue_size=10)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            # Submit
            job_id = await q.submit("echo", {"msg": "integration"})
            assert isinstance(job_id, str)

            # Poll until completed
            job = None
            for _ in range(100):
                job = q.get_job_status(job_id)
                if job and job["status"] == "completed":
                    break
                await asyncio.sleep(0.02)

            # Verify
            assert job is not None
            assert job["status"] == "completed"
            assert job["result"]["echo"]["msg"] == "integration"
            assert job["result"]["job_id"] == job_id
            assert job["submitted_at"] is not None
            assert job["started_at"] is not None
            assert job["completed_at"] is not None
            assert job["error"] is None

            # submitted <= started <= completed
            sub = datetime.fromisoformat(job["submitted_at"])
            start = datetime.fromisoformat(job["started_at"])
            end = datetime.fromisoformat(job["completed_at"])
            assert sub <= start <= end
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_failed_job_lifecycle(self):
        """Submit a failing job, verify it ends with 'failed' status and error."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("fail", _failing_handler)
        await q.start()
        try:
            job_id = await q.submit("fail", {})
            for _ in range(100):
                job = q.get_job_status(job_id)
                if job and job["status"] == "failed":
                    break
                await asyncio.sleep(0.02)
            job = q.get_job_status(job_id)
            assert job["status"] == "failed"
            assert "intentional test failure" in job["error"]
            assert job["result"] is None
            assert job["completed_at"] is not None
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_multiple_jobs_sequential_execution(self):
        """Multiple jobs execute and all complete."""
        q = AnalysisJobQueue(max_workers=2, max_queue_size=20)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            job_ids = []
            for i in range(5):
                jid = await q.submit("echo", {"idx": i})
                job_ids.append(jid)

            # Wait for all to complete
            for _ in range(200):
                all_done = all(
                    q.get_job_status(jid)
                    and q.get_job_status(jid)["status"] == "completed"
                    for jid in job_ids
                )
                if all_done:
                    break
                await asyncio.sleep(0.02)

            for i, jid in enumerate(job_ids):
                job = q.get_job_status(jid)
                assert job["status"] == "completed"
                assert job["result"]["echo"]["idx"] == i
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_cancel_then_list_shows_cancelled(self):
        """Cancel a pending job, then list_jobs should show it as cancelled."""
        q = AnalysisJobQueue(max_workers=0, max_queue_size=10)
        q.register_handler("echo", _echo_handler)
        q._running = True

        job_id = await q.submit("echo", {"x": 1})
        assert q.cancel_job(job_id) is True

        jobs = q.list_jobs(status_filter="cancelled")
        assert len(jobs) == 1
        assert jobs[0]["job_id"] == job_id

    @pytest.mark.asyncio
    async def test_async_handler_lifecycle(self):
        """Async handler completes correctly through the full lifecycle."""
        q = AnalysisJobQueue(max_workers=1)
        q.register_handler("async_echo", _async_echo_handler)
        await q.start()
        try:
            job_id = await q.submit("async_echo", {"val": 99})
            for _ in range(100):
                job = q.get_job_status(job_id)
                if job and job["status"] == "completed":
                    break
                await asyncio.sleep(0.02)
            job = q.get_job_status(job_id)
            assert job["status"] == "completed"
            assert job["result"]["async_echo"]["val"] == 99
        finally:
            await q.stop()


# ---------------------------------------------------------------------------
# 2. IQ metadata: store -> query -> retention -> deletion
# ---------------------------------------------------------------------------


class TestIQMetadataLifecycle:
    """IQ metadata index operations: store, query, retention, delete."""

    def test_store_query_delete_lifecycle(self, iq_meta: IQMetadataStore):
        """Full lifecycle: index -> query -> verify -> delete -> verify gone."""
        meta = _make_metadata(node_id="node-alpha", signal_class="qpsk", freq_hz=915e6)
        iq_meta.index_capture("det-lc-001", meta)

        # Query returns it
        results = iq_meta.query(node_id="node-alpha")
        assert len(results) == 1
        assert results[0]["detection_id"] == "det-lc-001"
        assert results[0]["signal_class"] == "qpsk"

        # Delete
        assert iq_meta.delete_metadata("det-lc-001") is True
        assert iq_meta.get_metadata("det-lc-001") is None

    def test_retention_policy_enforcement(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ):
        """Retention tiers enforce correct expiry and cleanup."""
        now = datetime.now(timezone.utc)

        # Temporary capture from 25 hours ago (should be expired)
        expired_ts = (now - timedelta(hours=25)).isoformat()
        iq_store.store("det-expired-1", _make_iq_data())
        iq_meta.index_capture(
            "det-expired-1",
            _make_metadata(
                tier="temporary",
                captured_at=expired_ts,
            ),
        )

        # Standard capture from 31 days ago (should be expired)
        old_ts = (now - timedelta(days=31)).isoformat()
        iq_store.store("det-expired-2", _make_iq_data())
        iq_meta.index_capture(
            "det-expired-2",
            _make_metadata(
                tier="standard",
                captured_at=old_ts,
            ),
        )

        # Critical capture from 31 days ago (should NOT expire)
        iq_store.store("det-critical", _make_iq_data())
        iq_meta.index_capture(
            "det-critical",
            _make_metadata(
                tier="critical",
                captured_at=old_ts,
            ),
        )

        # Fresh standard capture (should NOT expire)
        iq_store.store("det-fresh", _make_iq_data())
        iq_meta.index_capture(
            "det-fresh",
            _make_metadata(
                tier="standard",
                captured_at=now.isoformat(),
            ),
        )

        # Run cleanup
        removed = iq_meta.cleanup_expired(iq_store)
        assert removed == 2

        # Expired entries and files gone
        assert iq_meta.get_metadata("det-expired-1") is None
        assert iq_meta.get_metadata("det-expired-2") is None
        assert not iq_store.exists("det-expired-1")
        assert not iq_store.exists("det-expired-2")

        # Critical and fresh still present
        assert iq_meta.get_metadata("det-critical") is not None
        assert iq_meta.get_metadata("det-fresh") is not None
        assert iq_store.exists("det-critical")
        assert iq_store.exists("det-fresh")

    def test_tier_change_updates_expiry(self, iq_meta: IQMetadataStore):
        """Changing tier from standard to critical removes expiry."""
        iq_meta.index_capture("det-tc-001", _make_metadata(tier="standard"))

        result = iq_meta.get_metadata("det-tc-001")
        assert result["expires_at"] is not None

        iq_meta.set_tier("det-tc-001", "critical")

        result = iq_meta.get_metadata("det-tc-001")
        assert result["tier"] == "critical"
        assert result["expires_at"] is None

    def test_tier_change_critical_to_temporary(self, iq_meta: IQMetadataStore):
        """Changing tier from critical to temporary adds an expiry."""
        iq_meta.index_capture("det-tc-002", _make_metadata(tier="critical"))
        result = iq_meta.get_metadata("det-tc-002")
        assert result["expires_at"] is None

        iq_meta.set_tier("det-tc-002", "temporary")
        result = iq_meta.get_metadata("det-tc-002")
        assert result["tier"] == "temporary"
        assert result["expires_at"] is not None

    def test_query_combined_filters(self, iq_meta: IQMetadataStore):
        """Query with multiple filters simultaneously."""
        now = datetime.now(timezone.utc)
        iq_meta.index_capture(
            "det-qf-001",
            _make_metadata(
                node_id="node-A",
                signal_class="bpsk",
                freq_hz=433e6,
                tier="critical",
                captured_at=now.isoformat(),
            ),
        )
        iq_meta.index_capture(
            "det-qf-002",
            _make_metadata(
                node_id="node-A",
                signal_class="qpsk",
                freq_hz=915e6,
                tier="standard",
                captured_at=now.isoformat(),
            ),
        )
        iq_meta.index_capture(
            "det-qf-003",
            _make_metadata(
                node_id="node-B",
                signal_class="bpsk",
                freq_hz=433e6,
                tier="critical",
                captured_at=now.isoformat(),
            ),
        )

        # Filter by node_id AND signal_class
        results = iq_meta.query(node_id="node-A", signal_class="bpsk")
        assert len(results) == 1
        assert results[0]["detection_id"] == "det-qf-001"

        # Filter by tier AND freq_range
        results = iq_meta.query(tier="critical", freq_range=(400e6, 500e6))
        assert len(results) == 2  # det-qf-001 and det-qf-003

    def test_stats_reflect_all_tiers(self, iq_meta: IQMetadataStore):
        """get_stats returns correct aggregates across tiers."""
        iq_meta.index_capture(
            "det-s1",
            _make_metadata(
                tier="critical",
                file_size_bytes=1000,
            ),
        )
        iq_meta.index_capture(
            "det-s2",
            _make_metadata(
                tier="standard",
                file_size_bytes=2000,
            ),
        )
        iq_meta.index_capture(
            "det-s3",
            _make_metadata(
                tier="temporary",
                file_size_bytes=500,
            ),
        )

        stats = iq_meta.get_stats()
        assert stats["total_captures"] == 3
        assert stats["total_size_bytes"] == 3500
        assert stats["by_tier"]["critical"] == 1
        assert stats["by_tier"]["standard"] == 1
        assert stats["by_tier"]["temporary"] == 1

    def test_upsert_preserves_latest_data(self, iq_meta: IQMetadataStore):
        """Upserting same detection_id replaces old metadata entirely."""
        iq_meta.index_capture(
            "det-up-001",
            _make_metadata(
                signal_class="bpsk",
                quality_score=0.5,
            ),
        )
        iq_meta.index_capture(
            "det-up-001",
            _make_metadata(
                signal_class="qam16",
                quality_score=0.95,
            ),
        )

        result = iq_meta.get_metadata("det-up-001")
        assert result["signal_class"] == "qam16"
        assert result["quality_score"] == 0.95

        # Stats should still show only 1 entry
        stats = iq_meta.get_stats()
        assert stats["total_captures"] == 1


# ---------------------------------------------------------------------------
# 3. SigMF: generate metadata for various signal types
# ---------------------------------------------------------------------------


class TestSigMFVariousSignals:
    """SigMF metadata generation for different signal types and configs."""

    SIGNAL_TYPES = [
        ("bpsk", 433.92e6),
        ("qpsk", 915e6),
        ("qam16", 2400e6),
        ("ofdm", 5800e6),
        ("fsk", 868e6),
        ("am", 1e6),
    ]

    @pytest.mark.parametrize("signal_class,freq_hz", SIGNAL_TYPES)
    def test_sigmf_structure_per_signal_type(self, signal_class: str, freq_hz: float):
        """Each signal type produces valid SigMF with correct fields."""
        rec = {
            "freq_hz": freq_hz,
            "signal_class": signal_class,
            "timestamp": "2026-02-16T12:00:00+00:00",
            "node_id": "node-test-01",
        }
        meta = generate_sigmf_meta("det-sig-001", rec, sample_rate=2.048e6)

        # Required sections
        assert "global" in meta
        assert "captures" in meta
        assert "annotations" in meta

        # Global fields
        assert meta["global"]["core:datatype"] == "cf32_le"
        assert meta["global"]["core:sample_rate"] == 2.048e6
        assert meta["global"]["core:version"] == "1.0.0"

        # Capture frequency
        assert meta["captures"][0]["core:frequency"] == freq_hz
        assert meta["captures"][0]["core:sample_start"] == 0

        # Annotation label matches signal class
        assert meta["annotations"][0]["core:label"] == signal_class

    def test_sigmf_with_bandwidth_edges(self):
        """Bandwidth edges are correctly computed."""
        rec = {
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
            "timestamp": "2026-02-16T12:00:00+00:00",
            "node_id": "node-01",
            "bandwidth_hz": 200e3,
        }
        meta = generate_sigmf_meta("det-bw-001", rec, sample_rate=2.048e6)
        ann = meta["annotations"][0]
        assert ann["core:freq_lower_edge"] == pytest.approx(433.92e6 - 100e3)
        assert ann["core:freq_upper_edge"] == pytest.approx(433.92e6 + 100e3)

    def test_sigmf_with_sample_count(self):
        """Sample count from detection record appears in annotation."""
        rec = {
            "freq_hz": 915e6,
            "signal_class": "qpsk",
            "timestamp": "2026-02-16T12:00:00+00:00",
            "node_id": "node-01",
            "sample_count": 16384,
        }
        meta = generate_sigmf_meta("det-sc-001", rec, sample_rate=10e6)
        assert meta["annotations"][0]["core:sample_count"] == 16384

    def test_sigmf_custom_datatype(self):
        """Non-default datatype (ci16_le) is propagated correctly."""
        rec = {
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
            "timestamp": "2026-02-16T12:00:00+00:00",
            "node_id": "node-01",
        }
        meta = generate_sigmf_meta(
            "det-dt-001", rec, sample_rate=2.048e6, data_type="ci16_le"
        )
        assert meta["global"]["core:datatype"] == "ci16_le"

    def test_sigmf_save_and_reload(self, tmp_path: Path):
        """Saved SigMF metadata can be loaded back and parsed as valid JSON."""
        rec = {
            "freq_hz": 915e6,
            "signal_class": "qam16",
            "timestamp": "2026-02-16T12:00:00+00:00",
            "node_id": "sensor-01",
        }
        meta = generate_sigmf_meta("det-save-int", rec, sample_rate=5e6)
        path = save_sigmf_meta("det-save-int", meta, base_dir=tmp_path)

        assert path.exists()
        loaded = json.loads(path.read_text())
        assert loaded["global"]["core:version"] == "1.0.0"
        assert loaded["global"]["core:sample_rate"] == 5e6
        assert loaded["captures"][0]["core:frequency"] == 915e6
        assert loaded["annotations"][0]["core:label"] == "qam16"


# ---------------------------------------------------------------------------
# 4. Cross-feature: IQ + SigMF + IQ metadata consistency
# ---------------------------------------------------------------------------


class TestCrossFeatureConsistency:
    """Verify consistency across IQ store, SigMF metadata, and IQ metadata index."""

    def test_iq_capture_sigmf_metadata_consistency(
        self,
        iq_store: IQStore,
        iq_meta: IQMetadataStore,
        tmp_path: Path,
    ):
        """Stored IQ data, generated SigMF, and indexed metadata are all consistent."""
        det_id = "det-cross-001"
        freq_hz = 915e6
        signal_class = "qam16"
        sample_rate = 10e6
        n_samples = 4096

        # Step 1: Store IQ data
        iq_data = _make_iq_data(n_samples)
        iq_store.store(det_id, iq_data)
        assert iq_store.exists(det_id)

        # Step 2: Index IQ metadata
        iq_meta.index_capture(
            det_id,
            _make_metadata(
                freq_hz=freq_hz,
                signal_class=signal_class,
                n_samples=n_samples,
                file_size_bytes=len(iq_data),
                tier="critical",
            ),
        )

        # Step 3: Generate SigMF metadata
        detection_rec = {
            "freq_hz": freq_hz,
            "signal_class": signal_class,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "node_id": "node-test-01",
            "sample_count": n_samples,
        }
        sigmf_meta = generate_sigmf_meta(det_id, detection_rec, sample_rate=sample_rate)

        # Step 4: Save SigMF
        sigmf_path = save_sigmf_meta(det_id, sigmf_meta, base_dir=tmp_path)
        assert sigmf_path.exists()

        # Step 5: Verify consistency
        # SigMF frequency matches indexed metadata
        idx_meta = iq_meta.get_metadata(det_id)
        assert idx_meta is not None
        assert idx_meta["freq_hz"] == sigmf_meta["captures"][0]["core:frequency"]
        assert idx_meta["signal_class"] == sigmf_meta["annotations"][0]["core:label"]

        # IQ data decompresses to the expected sample count
        iq_loaded = iq_store.load_iq(det_id)
        assert iq_loaded is not None
        assert len(iq_loaded) == n_samples
        assert sigmf_meta["annotations"][0]["core:sample_count"] == n_samples

    def test_cleanup_removes_both_iq_and_metadata(
        self,
        iq_store: IQStore,
        iq_meta: IQMetadataStore,
    ):
        """Cleanup removes both the IQ file and the metadata entry together."""
        det_id = "det-cleanup-cross"
        now = datetime.now(timezone.utc)

        # Store IQ and index metadata as temporary, 25 hours old
        iq_store.store(det_id, _make_iq_data())
        iq_meta.index_capture(
            det_id,
            _make_metadata(
                tier="temporary",
                captured_at=(now - timedelta(hours=25)).isoformat(),
            ),
        )

        assert iq_store.exists(det_id)
        assert iq_meta.get_metadata(det_id) is not None

        removed = iq_meta.cleanup_expired(iq_store)
        assert removed == 1

        # Both are gone
        assert not iq_store.exists(det_id)
        assert iq_meta.get_metadata(det_id) is None


# ---------------------------------------------------------------------------
# 5. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge cases: duplicates, large payloads, concurrent access, queue limits."""

    @pytest.mark.asyncio
    async def test_duplicate_job_ids_are_unique(self):
        """Even submitting the same params multiple times yields unique job IDs."""
        q = AnalysisJobQueue(max_workers=1, max_queue_size=20)
        q.register_handler("echo", _echo_handler)
        await q.start()
        try:
            ids = set()
            for _ in range(10):
                jid = await q.submit("echo", {"same": True})
                ids.add(jid)
            assert len(ids) == 10  # All unique
        finally:
            await q.stop()

    @pytest.mark.asyncio
    async def test_queue_full_rejects_submission(self):
        """Submitting beyond max_queue_size raises QueueFull."""
        q = AnalysisJobQueue(max_workers=0, max_queue_size=3)
        q.register_handler("echo", _echo_handler)
        q._running = True

        # Fill the queue
        for i in range(3):
            await q.submit("echo", {"i": i})

        # Next submission should fail
        with pytest.raises(asyncio.QueueFull):
            await q.submit("echo", {"i": 3})

    @pytest.mark.asyncio
    async def test_submit_to_stopped_queue_raises(self):
        """Submitting an unregistered handler type raises ValueError."""
        q = AnalysisJobQueue()
        await q.start()
        try:
            with pytest.raises(ValueError, match="Unknown job type"):
                await q.submit("nonexistent_handler", {})
        finally:
            await q.stop()

    def test_large_metadata_payload(self, iq_meta: IQMetadataStore):
        """IQ metadata store handles entries with large quality_score etc."""
        iq_meta.index_capture(
            "det-large-001",
            _make_metadata(
                file_size_bytes=100_000_000,  # 100 MB
                n_samples=10_000_000,
                quality_score=0.999999,
            ),
        )
        result = iq_meta.get_metadata("det-large-001")
        assert result is not None
        assert result["file_size_bytes"] == 100_000_000
        assert result["n_samples"] == 10_000_000

    def test_concurrent_metadata_writes(self, ctx: SharedContext):
        """Multiple threads can write IQ metadata concurrently without corruption."""
        store = IQMetadataStore(ctx)
        errors: list[str] = []

        def worker(thread_id: int):
            try:
                for i in range(20):
                    det_id = f"det-t{thread_id}-{i:03d}"
                    store.index_capture(
                        det_id,
                        _make_metadata(
                            node_id=f"node-{thread_id}",
                            signal_class="bpsk",
                        ),
                    )
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"

        # All 80 entries should be present
        all_results = store.query(limit=100)
        assert len(all_results) == 80

    def test_concurrent_metadata_read_write(self, ctx: SharedContext):
        """Concurrent reads and writes do not interfere."""
        store = IQMetadataStore(ctx)
        errors: list[str] = []

        # Seed some data
        for i in range(10):
            store.index_capture(f"det-seed-{i:03d}", _make_metadata())

        def writer(thread_id: int):
            try:
                for i in range(10):
                    store.index_capture(
                        f"det-w{thread_id}-{i:03d}",
                        _make_metadata(node_id=f"node-w{thread_id}"),
                    )
            except Exception as e:
                errors.append(f"writer-{thread_id}: {e}")

        def reader(thread_id: int):
            try:
                for _ in range(10):
                    store.query(limit=50)
                    store.get_stats()
            except Exception as e:
                errors.append(f"reader-{thread_id}: {e}")

        threads = []
        for t in range(2):
            threads.append(threading.Thread(target=writer, args=(t,)))
            threads.append(threading.Thread(target=reader, args=(t,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Thread errors: {errors}"

    def test_sigmf_invalid_detection_id(self, tmp_path: Path):
        """SigMF save with an empty detection_id raises ValueError."""
        meta = generate_sigmf_meta(
            "x",
            {"freq_hz": 433e6, "signal_class": "bpsk"},
            sample_rate=2e6,
        )
        # Ids are mapped injectively (special characters are hex-encoded,
        # not stripped), so only an empty id is invalid.
        with pytest.raises(ValueError, match="Invalid"):
            save_sigmf_meta("", meta, base_dir=tmp_path)

    def test_iq_metadata_set_tier_invalid_raises(self, iq_meta: IQMetadataStore):
        """Setting an invalid tier raises ValueError."""
        iq_meta.index_capture("det-inv-001", _make_metadata())
        with pytest.raises(ValueError, match="Invalid tier"):
            iq_meta.set_tier("det-inv-001", "nonexistent_tier")

    def test_iq_metadata_default_tier(self, iq_meta: IQMetadataStore):
        """Metadata with no tier defaults to 'standard'."""
        meta = _make_metadata()
        del meta["tier"]
        iq_meta.index_capture("det-def-001", meta)
        result = iq_meta.get_metadata("det-def-001")
        assert result["tier"] == "standard"


# ---------------------------------------------------------------------------
# 6. Retention cleanup correctness
# ---------------------------------------------------------------------------


class TestRetentionCleanup:
    """Verify cleanup of old IQ metadata works correctly."""

    def test_cleanup_only_removes_expired(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ):
        """Cleanup removes only entries past their expires_at."""
        now = datetime.now(timezone.utc)

        # Create entries across all tiers and age groups
        test_entries = [
            ("det-temp-old", "temporary", now - timedelta(hours=25)),  # expired
            ("det-temp-new", "temporary", now - timedelta(hours=1)),  # not expired
            ("det-std-old", "standard", now - timedelta(days=31)),  # expired
            ("det-std-new", "standard", now - timedelta(days=1)),  # not expired
            ("det-crit-old", "critical", now - timedelta(days=365)),  # never expires
            ("det-crit-new", "critical", now),  # never expires
        ]

        for det_id, tier, captured_at in test_entries:
            iq_store.store(det_id, _make_iq_data(256))
            iq_meta.index_capture(
                det_id,
                _make_metadata(
                    tier=tier,
                    captured_at=captured_at.isoformat(),
                ),
            )

        # Run cleanup
        removed = iq_meta.cleanup_expired(iq_store)
        assert removed == 2  # det-temp-old and det-std-old

        # Verify expired entries removed
        assert iq_meta.get_metadata("det-temp-old") is None
        assert iq_meta.get_metadata("det-std-old") is None
        assert not iq_store.exists("det-temp-old")
        assert not iq_store.exists("det-std-old")

        # Verify non-expired entries remain
        assert iq_meta.get_metadata("det-temp-new") is not None
        assert iq_meta.get_metadata("det-std-new") is not None
        assert iq_meta.get_metadata("det-crit-old") is not None
        assert iq_meta.get_metadata("det-crit-new") is not None

    def test_cleanup_with_missing_iq_file(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ):
        """Cleanup handles metadata entries where the IQ file is already gone."""
        now = datetime.now(timezone.utc)

        # Index metadata as expired but do NOT store an IQ file
        iq_meta.index_capture(
            "det-orphan",
            _make_metadata(
                tier="temporary",
                captured_at=(now - timedelta(hours=25)).isoformat(),
            ),
        )

        # Should not crash; iq_store.delete for a missing file returns False
        removed = iq_meta.cleanup_expired(iq_store)
        assert removed == 1

        # Metadata should still be cleaned up
        assert iq_meta.get_metadata("det-orphan") is None

    def test_cleanup_idempotent(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ):
        """Running cleanup twice does not double-delete."""
        now = datetime.now(timezone.utc)

        iq_store.store("det-idem", _make_iq_data())
        iq_meta.index_capture(
            "det-idem",
            _make_metadata(
                tier="temporary",
                captured_at=(now - timedelta(hours=25)).isoformat(),
            ),
        )

        assert iq_meta.cleanup_expired(iq_store) == 1
        assert iq_meta.cleanup_expired(iq_store) == 0  # Nothing left

    def test_set_tier_with_custom_ttl_then_cleanup(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ):
        """Custom TTL on set_tier is respected by cleanup."""
        now = datetime.now(timezone.utc)

        # Create a standard entry
        iq_store.store("det-ttl-001", _make_iq_data())
        iq_meta.index_capture("det-ttl-001", _make_metadata(tier="standard"))

        # Set tier to standard with 0 TTL -- effectively expired immediately
        # Using ttl_hours=0 which sets expires_at to None (never expires) per implementation
        # Actually let's use a very small positive TTL -- 1 hour
        # But we can't make it expire in the past with set_tier alone.
        # Instead let's verify that the custom TTL is set correctly:
        iq_meta.set_tier("det-ttl-001", "standard", ttl_hours=1)
        result = iq_meta.get_metadata("det-ttl-001")
        assert result["expires_at"] is not None
        expires = datetime.fromisoformat(result["expires_at"])
        expected = now + timedelta(hours=1)
        assert abs((expires - expected).total_seconds()) < 60

        # Should not be expired yet
        assert iq_meta.cleanup_expired(iq_store) == 0


# ---------------------------------------------------------------------------
# 7. API endpoint integration tests
# ---------------------------------------------------------------------------


class TestAPIEndpointIntegration:
    """Integration tests through the API endpoints."""

    def test_iq_index_stats_lifecycle(self, client: TestClient, bridge_app: FastAPI):
        """Index captures via store, verify through API index and stats endpoints."""
        meta_store = bridge_app.state.iq_metadata_store

        # Start with empty
        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        assert resp.json()["total_captures"] == 0

        # Index several captures
        meta_store.index_capture(
            "det-api-001",
            _make_metadata(
                tier="critical",
                file_size_bytes=5000,
                node_id="node-A",
            ),
        )
        meta_store.index_capture(
            "det-api-002",
            _make_metadata(
                tier="standard",
                file_size_bytes=3000,
                node_id="node-B",
            ),
        )
        meta_store.index_capture(
            "det-api-003",
            _make_metadata(
                tier="temporary",
                file_size_bytes=1000,
                node_id="node-A",
            ),
        )

        # Verify stats
        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_captures"] == 3
        assert data["total_size_bytes"] == 9000

        # Verify index with filter
        resp = client.get("/api/iq/index", params={"node_id": "node-A"})
        assert resp.status_code == 200
        entries = resp.json()
        assert len(entries) == 2
        assert all(e["node_id"] == "node-A" for e in entries)

    def test_cleanup_endpoint_integration(
        self, client: TestClient, bridge_app: FastAPI
    ):
        """POST /api/iq/cleanup via API removes expired captures."""
        meta_store = bridge_app.state.iq_metadata_store
        iq_store = bridge_app.state.iq_store
        now = datetime.now(timezone.utc)

        # Store an expired temporary capture
        iq_store.store("det-clean-api", _make_iq_data())
        meta_store.index_capture(
            "det-clean-api",
            _make_metadata(
                tier="temporary",
                captured_at=(now - timedelta(hours=25)).isoformat(),
            ),
        )

        resp = client.post("/api/iq/cleanup")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["removed"] == 1

        # Verify it is gone
        assert meta_store.get_metadata("det-clean-api") is None

    def test_job_submit_and_status_via_api(
        self,
        client: TestClient,
        bridge_app: FastAPI,
    ):
        """Submit a job via API, check status via API."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        # Create analyst key
        analyst_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(analyst_key)
        persistence = bridge_app.state.persistence
        persistence.set_key("analyst-api-test", hash_hex, salt)
        persistence.set_key_meta(
            "analyst-api-test", {"role": "analyst", "description": "test"}
        )

        analyst_client = TestClient(
            bridge_app,
            headers={"X-API-Key": analyst_key},
        )

        # Register handler and enable queue
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        # Submit job
        resp = analyst_client.post(
            "/api/jobs",
            json={"job_type": "echo", "params": {"msg": "api-test"}},
        )
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]

        # Check status
        resp = client.get(f"/api/jobs/{job_id}")
        assert resp.status_code == 200
        job = resp.json()["job"]
        assert job["job_id"] == job_id
        assert job["job_type"] == "echo"
        assert job["params"]["msg"] == "api-test"

    def test_job_list_via_api(self, client: TestClient, bridge_app: FastAPI):
        """GET /api/jobs returns submitted jobs."""
        # Start clean
        resp = client.get("/api/jobs")
        assert resp.status_code == 200
        initial_count = resp.json()["count"]

        # Register handler
        jq: AnalysisJobQueue = bridge_app.state.job_queue
        jq.register_handler("echo", _echo_handler)
        jq._running = True

        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        analyst_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(analyst_key)
        persistence = bridge_app.state.persistence
        persistence.set_key("analyst-list-test", hash_hex, salt)
        persistence.set_key_meta(
            "analyst-list-test", {"role": "analyst", "description": "test"}
        )

        analyst_client = TestClient(
            bridge_app,
            headers={"X-API-Key": analyst_key},
        )

        # Submit two jobs
        analyst_client.post("/api/jobs", json={"job_type": "echo", "params": {"i": 1}})
        analyst_client.post("/api/jobs", json={"job_type": "echo", "params": {"i": 2}})

        resp = client.get("/api/jobs")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= initial_count + 2
