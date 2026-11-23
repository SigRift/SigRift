"""Tests for AGC gain tracking: migration, model, ingest, scoring."""

from __future__ import annotations

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# Migration
# ---------------------------------------------------------------------------


class TestAGCMigration:
    """Verify migration 7 adds gain_db and lna_state columns."""

    def test_gain_columns_exist(self, detection_store: DetectionStore):
        """After init, detections table should have gain_db and lna_state."""
        conn = detection_store._ctx.get_conn()
        cursor = conn.execute("PRAGMA table_info(detections)")
        columns = {row["name"] for row in cursor.fetchall()}
        assert "gain_db" in columns
        assert "lna_state" in columns

    def test_migration_version_recorded(self, detection_store: DetectionStore):
        conn = detection_store._ctx.get_conn()
        row = conn.execute(
            "SELECT version FROM schema_version WHERE version = 7"
        ).fetchone()
        assert row is not None
        assert row["version"] == 7

    def test_gain_columns_nullable(self, detection_store: DetectionStore):
        """gain_db and lna_state should accept NULL."""
        det = make_detection()
        inserted = detection_store.insert_batch([det])
        assert inserted == 1
        row = detection_store.get_detection_by_id(det.detection_id)
        assert row["gain_db"] is None
        assert row["lna_state"] is None


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class TestDetectionRecordModel:
    def test_gain_fields_optional(self):
        """DetectionRecord should allow omitting gain_db/lna_state."""
        det = DetectionRecord(
            node_id="node-01",
            signal_class="bpsk",
            confidence=0.9,
        )
        assert det.gain_db is None
        assert det.lna_state is None

    def test_gain_fields_set(self):
        det = DetectionRecord(
            node_id="node-01",
            signal_class="bpsk",
            confidence=0.9,
            gain_db=40.2,
            lna_state="auto",
        )
        assert det.gain_db == 40.2
        assert det.lna_state == "auto"


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


class TestAGCIngest:
    def test_insert_with_gain(self, detection_store: DetectionStore):
        det = make_detection(gain_db=38.5, lna_state="max")
        inserted = detection_store.insert_batch([det])
        assert inserted == 1
        row = detection_store.get_detection_by_id(det.detection_id)
        assert row["gain_db"] == pytest.approx(38.5)
        assert row["lna_state"] == "max"

    def test_insert_without_gain(self, detection_store: DetectionStore):
        det = make_detection()
        detection_store.insert_batch([det])
        row = detection_store.get_detection_by_id(det.detection_id)
        assert row["gain_db"] is None
        assert row["lna_state"] is None

    def test_batch_mixed_gain(self, detection_store: DetectionStore):
        """Batch with mix of gain/no-gain records."""
        dets = [
            make_detection(signal_class="bpsk", gain_db=30.0, lna_state="auto"),
            make_detection(signal_class="qpsk"),
            make_detection(signal_class="ook", gain_db=45.0, lna_state="off"),
        ]
        inserted = detection_store.insert_batch(dets)
        assert inserted == 3

        r0 = detection_store.get_detection_by_id(dets[0].detection_id)
        assert r0["gain_db"] == pytest.approx(30.0)
        r1 = detection_store.get_detection_by_id(dets[1].detection_id)
        assert r1["gain_db"] is None
        r2 = detection_store.get_detection_by_id(dets[2].detection_id)
        assert r2["lna_state"] == "off"


# ---------------------------------------------------------------------------
# Scoring normalization
# ---------------------------------------------------------------------------


class TestAGCScoringNormalization:
    """Test that scorer normalizes power_dbm by gain_db."""

    @pytest.fixture
    def baseline_mgr(self) -> BaselineManager:
        mgr = BaselineManager(alpha=0.05)
        # Build baseline at received power ~-90 dBm with some variance
        for i in range(150):
            mgr.update(433_920_000, "fm", 0.9, -90.0 + (i % 5) * 0.5, 10)
        return mgr

    def test_normalized_power_scores_low(self, baseline_mgr):
        """Detection with gain info should normalize: power - gain = received."""
        scorer = AnomalyScorer(baseline_mgr)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -49.0,
            "gain_db": 40.0,  # Normalized: -49 - 40 = -89 (close to baseline ~-89)
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.dimensions["power_zscore"] < 0.4

    def test_without_gain_uses_raw_power(self, baseline_mgr):
        """Without gain_db, raw power_dbm is used (may look anomalous)."""
        scorer = AnomalyScorer(baseline_mgr)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            # No gain_db — uses -50 directly vs baseline of -90
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        # -50 vs baseline -90 = 40 dB difference, should score higher
        assert result.dimensions["power_zscore"] > 0.0

    def test_gain_zero_no_change(self, baseline_mgr):
        """gain_db=0 normalizes to same power."""
        scorer = AnomalyScorer(baseline_mgr)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -89.0,
            "gain_db": 0.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.dimensions["power_zscore"] < 0.3
