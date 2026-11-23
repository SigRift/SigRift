"""Tests for P2-9: INSERT OR IGNORE → ON CONFLICT(col) DO NOTHING.

Verifies that the explicit conflict-target syntax works correctly for
duplicate handling in detections and fhss_events tables.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Detections: ON CONFLICT(detection_id) DO NOTHING
# ---------------------------------------------------------------------------

class TestDetectionOnConflict:
    """Verify ON CONFLICT(detection_id) DO NOTHING for detections table."""

    def test_duplicate_detection_id_skipped(
        self, detection_store: DetectionStore,
    ) -> None:
        """Inserting the same detection_id twice results in only 1 row."""
        det = make_detection(detection_id="dup-001")
        detection_store.insert_batch([det])
        detection_store.insert_batch([det])
        assert detection_store.row_count() == 1

    def test_non_duplicate_inserts_succeed(
        self, detection_store: DetectionStore,
    ) -> None:
        """Two records with different IDs both insert successfully."""
        d1 = make_detection(detection_id="uniq-001")
        d2 = make_detection(detection_id="uniq-002")
        detection_store.insert_batch([d1])
        detection_store.insert_batch([d2])
        assert detection_store.row_count() == 2

    def test_batch_mixed_new_and_duplicate(
        self, detection_store: DetectionStore,
    ) -> None:
        """Batch with a mix of new and duplicate IDs inserts only the new ones."""
        existing = make_detection(detection_id="batch-001")
        detection_store.insert_batch([existing])
        assert detection_store.row_count() == 1

        batch = [
            make_detection(detection_id="batch-001"),  # duplicate
            make_detection(detection_id="batch-002"),  # new
            make_detection(detection_id="batch-003"),  # new
        ]
        detection_store.insert_batch(batch)
        assert detection_store.row_count() == 3

    def test_concurrent_same_id_safe(
        self, detection_store: DetectionStore,
    ) -> None:
        """Two threads inserting the same detection_id do not crash."""
        det = make_detection(detection_id="race-001")
        errors: list[Exception] = []

        def _insert():
            try:
                detection_store.insert_batch([det])
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_insert)
        t2 = threading.Thread(target=_insert)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not errors, f"Thread raised: {errors}"
        assert detection_store.row_count() == 1

# ---------------------------------------------------------------------------
# FHSS: ON CONFLICT(fhss_id) DO NOTHING
# ---------------------------------------------------------------------------

class TestFHSSOnConflict:
    """Verify ON CONFLICT(fhss_id) DO NOTHING for fhss_events table."""

    def _make_fhss_event(self, fhss_id: str = "fhss-001", **overrides) -> dict:
        base = {
            "fhss_id": fhss_id,
            "node_id": "node-test-01",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hop_rate_hz": 100.0,
            "hop_set": [433.0e6, 434.0e6, 435.0e6],
            "bandwidth_hz": 500e3,
            "dwell_time_ms": 10.0,
            "duration_sec": 5.0,
            "signal_class": "fhss",
            "detection_count": 3,
            "confidence": 0.9,
        }
        base.update(overrides)
        return base

    def test_fhss_duplicate_id_skipped(
        self, detection_store: DetectionStore,
    ) -> None:
        """Inserting the same fhss_id twice results in only 1 row."""
        evt = self._make_fhss_event(fhss_id="fhss-dup-001")
        detection_store.insert_fhss_events([evt])
        detection_store.insert_fhss_events([evt])
        assert detection_store.count_fhss_events(hours=1) == 1

    def test_fhss_non_duplicate_inserts_succeed(
        self, detection_store: DetectionStore,
    ) -> None:
        """Two FHSS events with different IDs both insert."""
        e1 = self._make_fhss_event(fhss_id="fhss-uniq-001")
        e2 = self._make_fhss_event(fhss_id="fhss-uniq-002")
        detection_store.insert_fhss_events([e1])
        detection_store.insert_fhss_events([e2])
        assert detection_store.count_fhss_events(hours=1) == 2

    def test_fhss_batch_mixed_new_and_duplicate(
        self, detection_store: DetectionStore,
    ) -> None:
        """Batch with duplicates only inserts the new FHSS events."""
        existing = self._make_fhss_event(fhss_id="fhss-batch-001")
        detection_store.insert_fhss_events([existing])

        batch = [
            self._make_fhss_event(fhss_id="fhss-batch-001"),  # duplicate
            self._make_fhss_event(fhss_id="fhss-batch-002"),  # new
            self._make_fhss_event(fhss_id="fhss-batch-003"),  # new
        ]
        detection_store.insert_fhss_events(batch)
        assert detection_store.count_fhss_events(hours=1) == 3

    def test_fhss_concurrent_same_id_safe(
        self, detection_store: DetectionStore,
    ) -> None:
        """Two threads inserting the same fhss_id do not crash."""
        evt = self._make_fhss_event(fhss_id="fhss-race-001")
        errors: list[Exception] = []

        def _insert():
            try:
                detection_store.insert_fhss_events([evt])
            except Exception as exc:
                errors.append(exc)

        t1 = threading.Thread(target=_insert)
        t2 = threading.Thread(target=_insert)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not errors, f"Thread raised: {errors}"
        assert detection_store.count_fhss_events(hours=1) == 1
