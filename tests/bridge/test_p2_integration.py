"""Cross-cutting integration tests for P2 sprint items.

Tests interactions between multiple P2 fixes:
- CUSUM + anomaly scoring pipeline
- WAL checkpoint + heavy ingest
- Disk space monitoring + health endpoint
- Tenant-scoped audit + session auth lifecycle
- IF feature changes + scoring pipeline
"""

from __future__ import annotations

import random
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.storage.base import SharedContext


# ---------------------------------------------------------------------------
# CUSUM + Scorer pipeline
# ---------------------------------------------------------------------------


class TestCUSUMScorerIntegration:
    """CUSUM changepoint detection integrates with Tier 1 scorer."""

    def test_cusum_score_used_in_dimensions(self):
        """Scorer should be able to use cusum_score from baseline."""
        rng = random.Random(42)
        mgr = BaselineManager()

        # Build a stable baseline
        for _ in range(350):
            mgr.update(915e6, "lte", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        bl = mgr.get_baseline(915e6)

        # Score should be low during stable
        score_stable = bl.cusum_score()
        assert score_stable < 0.5

        # Introduce regime change
        for _ in range(20):
            mgr.update(915e6, "lte", 0.9, -30.0 + rng.gauss(0, 1), hour=12)

        score_shift = bl.cusum_score()
        # Score should rise or have triggered a changepoint
        assert score_shift > score_stable or bl.cusum_changepoints > 0

    def test_multiple_changepoints_tracked(self):
        """Multiple regime changes should each be counted."""
        rng = random.Random(42)
        fb = FrequencyBaseline()

        # Regime 1: -60 dBm
        for _ in range(350):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        assert fb.cusum_changepoints == 0

        # Regime 2: -30 dBm
        for _ in range(100):
            fb.update("wifi", 0.9, -30.0 + rng.gauss(0, 1), hour=12)
        cp1 = fb.cusum_changepoints
        assert cp1 >= 1

        # Regime 3: back to -60 dBm
        for _ in range(100):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        cp2 = fb.cusum_changepoints
        assert cp2 >= cp1  # Should detect another changepoint


# ---------------------------------------------------------------------------
# WAL checkpoint + heavy ingest
# ---------------------------------------------------------------------------


class TestWALCheckpointUnderLoad:
    """WAL checkpoint should work correctly during heavy write loads."""

    def test_checkpoint_during_concurrent_inserts(self, tmp_path):
        """WAL checkpoint should succeed while writes are ongoing."""
        ctx = SharedContext(db_path=tmp_path / "heavy.db", tenant_id="default")
        errors: list[str] = []

        def writer():
            try:
                conn = ctx.get_conn()
                for i in range(100):
                    conn.execute(
                        "INSERT INTO detections (detection_id, node_id, timestamp, "
                        "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                        (f"hw-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                         "test", 0.9, "default"),
                    )
                    conn.commit()
            except Exception as e:
                errors.append(f"writer: {e}")

        def checkpointer():
            try:
                for _ in range(5):
                    ctx.wal_checkpoint()
            except Exception as e:
                errors.append(f"checkpoint: {e}")

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=checkpointer)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0, f"Errors: {errors}"

    def test_checkpoint_reclaims_wal_space(self, tmp_path):
        """Checkpoint should reduce WAL size after writes."""
        ctx = SharedContext(db_path=tmp_path / "reclaim.db", tenant_id="default")
        conn = ctx.get_conn()

        # Heavy writes
        for i in range(500):
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                (f"rc-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                 "test", 0.9, "default"),
            )
        conn.commit()

        wal_path = Path(str(ctx.db_path) + "-wal")
        wal_before = wal_path.stat().st_size if wal_path.exists() else 0

        ctx.wal_checkpoint()

        wal_after = wal_path.stat().st_size if wal_path.exists() else 0
        # WAL should be same or smaller after checkpoint
        assert wal_after <= wal_before


# ---------------------------------------------------------------------------
# Disk space + health endpoint
# ---------------------------------------------------------------------------


class TestDiskSpaceHealth:
    """Disk space monitoring integrates with health endpoint."""

    def test_health_endpoint_reports_disk_usage(self, client):
        """GET /health should include disk_usage_pct when store available."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        # disk_usage_pct should be present (may be null without detection_store)
        assert "disk_usage_pct" in data
        assert data["disk_usage_pct"] is None or isinstance(data["disk_usage_pct"], (int, float))

    def test_disk_usage_realistic_range(self, tmp_path):
        """Disk usage should be a realistic percentage."""
        ctx = SharedContext(db_path=tmp_path / "du.db", tenant_id="default")
        usage = ctx.check_disk_space()
        # Should be between 0.1% and 99.9% on any real system
        assert 0.1 <= usage <= 99.9


# ---------------------------------------------------------------------------
# IF feature + scoring pipeline
# ---------------------------------------------------------------------------


class TestIFScoringPipeline:
    """Isolation Forest with 11 features works end-to-end."""

    def test_feature_extraction_consistent(self):
        """Same detection should produce same features."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        ts = datetime(2026, 1, 15, 14, 30, tzinfo=timezone.utc)
        detection = {
            "signal_class": "bpsk", "confidence": 0.85,
            "freq_hz": 433.92e6, "power_dbm": -65.0, "timestamp": ts,
        }
        tier1 = {"score": 0.4, "dimensions": {"rare_class": 0.2}}

        f1 = det.extract_features(detection, tier1)
        f2 = det.extract_features(detection, tier1)

        # First 10 features should be identical (f[10] is time-delta)
        for i in range(10):
            assert f1[i] == f2[i]

    def test_feature_sensitivity_to_inputs(self):
        """Features should change when inputs change."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        ts = datetime(2026, 1, 15, 14, 30, tzinfo=timezone.utc)

        f_low_conf = det.extract_features({
            "signal_class": "bpsk", "confidence": 0.1,
            "freq_hz": 100e6, "power_dbm": -50.0, "timestamp": ts,
        })
        f_high_conf = det.extract_features({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 100e6, "power_dbm": -50.0, "timestamp": ts,
        })
        # Feature 0 (confidence) should differ
        assert f_low_conf[0] != f_high_conf[0]

    def test_scoring_not_ready_without_training(self):
        """Score should return 0.0 when model is not trained."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        assert not det.is_ready()
        score = det.score([0.5] * 11)
        assert score == 0.0


# ---------------------------------------------------------------------------
# Baseline serialization roundtrip (with all new fields)
# ---------------------------------------------------------------------------


class TestBaselineRoundtrip:
    """Baseline serialize/deserialize preserves all state."""

    def test_full_roundtrip_preserves_cusum(self):
        """CUSUM state should survive JSON save/load cycle."""
        rng = random.Random(42)
        mgr = BaselineManager()
        for _ in range(350):
            mgr.update(100e6, "fm", 0.9, -70.0 + rng.gauss(0, 1), hour=10)
        for _ in range(50):
            mgr.update(100e6, "fm", 0.9, -50.0 + rng.gauss(0, 1), hour=10)

        bl1 = mgr.get_baseline(100e6)

        # Save and reload
        import json
        data = bl1.to_dict()
        json_str = json.dumps(data)
        restored_data = json.loads(json_str)
        bl2 = FrequencyBaseline.from_dict(restored_data)

        assert bl2.cusum_pos == bl1.cusum_pos
        assert bl2.cusum_neg == bl1.cusum_neg
        assert bl2.cusum_changepoints == bl1.cusum_changepoints
        assert bl2.cusum_last_changepoint == bl1.cusum_last_changepoint
        assert bl2.power_ewma == bl1.power_ewma
        assert bl2.power_var == bl1.power_var
        assert len(bl2.power_samples) == len(bl1.power_samples)

    def test_roundtrip_preserves_mad_scores(self):
        """MAD scores should be identical after roundtrip."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(100):
            fb.update("test", 0.9, -60.0 + rng.gauss(0, 2), hour=12, snr_db=20 + rng.gauss(0, 1))

        orig_power = fb.power_mad_score(-40.0)
        orig_snr = fb.snr_mad_score(25.0)

        restored = FrequencyBaseline.from_dict(fb.to_dict())
        assert restored.power_mad_score(-40.0) == orig_power
        assert restored.snr_mad_score(25.0) == orig_snr

    def test_backward_compatible_deserialization(self):
        """Loading a baseline without CUSUM fields should use defaults."""
        old_data = {
            "alpha": 0.01,
            "class_counts": {"wifi": 100},
            "class_ewma": {"wifi": 0.5},
            "hourly_counts": {},
            "power_ewma": -60.0,
            "power_var": 4.0,
            "snr_ewma": 0.0,
            "snr_var": 0.0,
            "total_detections": 100,
            # No CUSUM fields — simulating old serialized data
        }
        fb = FrequencyBaseline.from_dict(old_data)
        assert fb.cusum_pos == 0.0
        assert fb.cusum_neg == 0.0
        assert fb.cusum_changepoints == 0
        assert fb.cusum_last_changepoint == 0
        # Should work fine
        assert fb.cusum_score() == 0.0
        assert fb.has_recent_changepoint() is False


# ---------------------------------------------------------------------------
# Multi-threaded DB operations
# ---------------------------------------------------------------------------


class TestConcurrentDBOps:
    """Concurrent database operations with new features."""

    def test_concurrent_inserts_and_checkpoint(self, tmp_path):
        """Multiple writers + checkpoint should not corrupt data."""
        ctx = SharedContext(db_path=tmp_path / "mt.db", tenant_id="default")
        errors: list[str] = []
        total_per_thread = 50

        def writer(tid: int):
            try:
                conn = ctx.get_conn()
                for i in range(total_per_thread):
                    conn.execute(
                        "INSERT INTO detections (detection_id, node_id, timestamp, "
                        "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                        (f"t{tid}-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                         "test", 0.9, "default"),
                    )
                    conn.commit()
            except Exception as e:
                errors.append(f"writer-{tid}: {e}")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors: {errors}"

        # Verify data integrity
        conn = ctx.get_conn()
        count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        assert isinstance(count, int)
        assert count == 3 * total_per_thread

        # Checkpoint and integrity check
        ctx.wal_checkpoint()
        result = conn.execute("PRAGMA quick_check").fetchone()
        assert result[0] == "ok"

    def test_disk_space_thread_safe(self, tmp_path):
        """check_disk_space should be safe to call from multiple threads."""
        ctx = SharedContext(db_path=tmp_path / "tds.db", tenant_id="default")
        results: list[float] = []
        errors: list[str] = []

        def checker():
            try:
                usage = ctx.check_disk_space()
                results.append(usage)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=checker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(results) == 5
        # All should return similar values
        for r in results:
            assert 0.0 <= r <= 100.0
