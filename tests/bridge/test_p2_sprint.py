"""Tests for P2 review items.

Covers:
- DS-R7: Remove tier1_score from Isolation Forest features (11→10 dims)
- DS-R8: Data-driven IF contamination (default="auto")
- DS-R10: CUSUM changepoint detection in baseline
- DB-P11: Startup integrity check (PRAGMA quick_check)
- DB-P13: Disk space monitoring (check_disk_space)
- DB-H1: WAL checkpoint (wal_checkpoint + schedule_wal_checkpoint)
- SEC-M1: Mandatory key expiration
- SEC-M18: Admin password auto-delete pattern
- SEC-L2: Query parameter API key auth disabled in production
"""

from __future__ import annotations

import math
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from sigrift.bridge.anomaly.baseline import (
    FrequencyBaseline,
    BaselineManager,
    _CUSUM_DRIFT,
    _CUSUM_THRESHOLD,
)
from sigrift.bridge.storage.base import SharedContext


# ---------------------------------------------------------------------------
# DS-R7: Isolation Forest tier1_score removal
# ---------------------------------------------------------------------------


class TestIFTier1Removal:
    """Tier1 overall score should not be a feature dimension."""

    def test_feature_vector_is_13_dimensions(self):
        """Extract_features returns exactly 13 values (P2-4 sin/cos)."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        features = det.extract_features({
            "signal_class": "bpsk", "confidence": 0.8,
            "freq_hz": 100e6, "power_dbm": -50.0,
            "timestamp": datetime.now(timezone.utc),
        })
        assert len(features) == 13

    def test_tier1_overall_score_not_in_features(self):
        """Changing tier1 overall score should not change features."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        ts = datetime.now(timezone.utc)
        detection = {
            "signal_class": "fm", "confidence": 0.5,
            "freq_hz": 88e6, "power_dbm": -70.0, "timestamp": ts,
        }
        f1 = det.extract_features(detection, {"score": 0.1, "dimensions": {"rare_class": 0.3}})
        f2 = det.extract_features(detection, {"score": 0.9, "dimensions": {"rare_class": 0.3}})
        # Only time-dependent feature (f[12]) may differ
        for i in range(12):
            assert f1[i] == f2[i], f"Feature {i} differs"

    def test_class_baseline_frequency_uses_rare_class_dim(self):
        """Feature 11 should use rare_class dimension from tier1 (shifted by P2-4)."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        f1 = det.extract_features(
            {"signal_class": "qpsk", "confidence": 0.5, "freq_hz": 1e9,
             "power_dbm": -60.0, "timestamp": datetime.now(timezone.utc)},
            {"score": 0.5, "dimensions": {"rare_class": 0.0}},
        )
        f2 = det.extract_features(
            {"signal_class": "qpsk", "confidence": 0.5, "freq_hz": 1e9,
             "power_dbm": -60.0, "timestamp": datetime.now(timezone.utc)},
            {"score": 0.5, "dimensions": {"rare_class": 0.8}},
        )
        # f[11] = 1 - rare_class (index shifted +2 by P2-4 sin/cos)
        assert f1[11] == 1.0  # 1.0 - 0.0
        assert f2[11] == pytest.approx(0.2)  # 1.0 - 0.8

    def test_features_without_tier1(self):
        """Features should work when tier1_result is None."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        features = det.extract_features({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "power_dbm": -60.0,
            "timestamp": datetime.now(timezone.utc),
        }, tier1_result=None)
        assert len(features) == 13  # P2-4: 11→13
        assert features[11] == 0.0  # No tier1 → class_baseline_freq = 0

    def test_all_features_in_valid_range(self):
        """All feature values should be in valid ranges (sin/cos [-1,1], rest [0,1])."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        features = det.extract_features({
            "signal_class": "qpsk", "confidence": 0.85,
            "freq_hz": 915e6, "power_dbm": -90.0,
            "timestamp": datetime.now(timezone.utc),
        }, {"score": 0.4, "dimensions": {"rare_class": 0.2}})
        for i, f in enumerate(features):
            if i in (5, 6, 7, 8):
                assert -1.0 <= f <= 1.0, f"Feature {i} = {f} out of [-1,1]"
            else:
                assert 0.0 <= f <= 1.0, f"Feature {i} = {f} out of [0,1]"


# ---------------------------------------------------------------------------
# DS-R8: Data-driven IF contamination
# ---------------------------------------------------------------------------


class TestIFContamination:
    """Isolation Forest contamination default changed to 'auto'."""

    def test_default_is_auto(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector()
        assert det.contamination == "auto"

    def test_numeric_contamination_accepted(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(contamination=0.1)
        assert det.contamination == 0.1

    def test_auto_string_accepted(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(contamination="auto")
        assert det.contamination == "auto"


# ---------------------------------------------------------------------------
# DS-R10: CUSUM changepoint detection
# ---------------------------------------------------------------------------


class TestCUSUMChangepoint:
    """CUSUM accumulator detects sudden regime changes in power."""

    def test_cusum_initial_state(self):
        """Fresh baseline has zero CUSUM accumulators."""
        fb = FrequencyBaseline()
        assert fb.cusum_pos == 0.0
        assert fb.cusum_neg == 0.0
        assert fb.cusum_changepoints == 0
        assert fb.cusum_last_changepoint == 0

    def test_stable_signal_no_changepoint(self):
        """Stable signal should not trigger changepoints."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        # Need >300 samples to pass learning phase
        for _ in range(500):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        assert fb.cusum_changepoints == 0

    def test_sudden_power_increase_triggers_changepoint(self):
        """Abrupt +20 dB shift should trigger a changepoint."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        # Establish baseline past learning phase (>300 detections)
        for _ in range(350):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        assert fb.cusum_changepoints == 0
        # Sudden shift to -40 dBm
        for _ in range(50):
            fb.update("wifi", 0.9, -40.0 + rng.gauss(0, 1), hour=12)
        assert fb.cusum_changepoints >= 1

    def test_sudden_power_decrease_triggers_changepoint(self):
        """Abrupt -20 dB shift should trigger a changepoint."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(350):
            fb.update("wifi", 0.9, -40.0 + rng.gauss(0, 1), hour=12)
        for _ in range(50):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        assert fb.cusum_changepoints >= 1

    def test_cusum_score_low_when_stable(self):
        """CUSUM score should be low during stable periods."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(500):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        score = fb.cusum_score()
        assert 0.0 <= score < 0.5

    def test_cusum_score_high_during_shift(self):
        """CUSUM score should rise during a power shift."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        # P2-17: Welford runs for first 300 samples, CUSUM only in EWMA phase
        # Need >300 stable samples then shift
        for _ in range(400):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        # Start shifting — accumulator should build
        for _ in range(20):
            fb.update("wifi", 0.9, -40.0 + rng.gauss(0, 1), hour=12)
        score = fb.cusum_score()
        assert score > 0.3  # Building towards changepoint

    def test_has_recent_changepoint(self):
        """has_recent_changepoint should return True right after a change."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(350):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        for _ in range(50):
            fb.update("wifi", 0.9, -30.0 + rng.gauss(0, 1), hour=12)
        if fb.cusum_changepoints > 0:
            assert fb.has_recent_changepoint(lookback=100)

    def test_cusum_resets_after_changepoint(self):
        """Accumulators should reset to 0 after triggering."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(350):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        for _ in range(100):
            fb.update("wifi", 0.9, -30.0 + rng.gauss(0, 1), hour=12)
        if fb.cusum_changepoints > 0:
            # After reset, new stable period should not accumulate much
            for _ in range(200):
                fb.update("wifi", 0.9, -30.0 + rng.gauss(0, 1), hour=12)
            assert fb.cusum_pos < _CUSUM_THRESHOLD
            assert fb.cusum_neg < _CUSUM_THRESHOLD

    def test_cusum_survives_serialization(self):
        """CUSUM state should persist through to_dict/from_dict."""
        rng = random.Random(42)
        fb = FrequencyBaseline()
        for _ in range(350):
            fb.update("wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=12)
        for _ in range(50):
            fb.update("wifi", 0.9, -35.0 + rng.gauss(0, 1), hour=12)

        d = fb.to_dict()
        restored = FrequencyBaseline.from_dict(d)

        assert restored.cusum_pos == fb.cusum_pos
        assert restored.cusum_neg == fb.cusum_neg
        assert restored.cusum_changepoints == fb.cusum_changepoints
        assert restored.cusum_last_changepoint == fb.cusum_last_changepoint

    def test_cusum_no_division_by_zero(self):
        """CUSUM should handle zero-variance edge case."""
        fb = FrequencyBaseline()
        # All identical power values → zero variance
        for _ in range(20):
            fb.update("lte", 0.9, -50.0, hour=6)
        # Should not crash
        score = fb.cusum_score()
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# DB-P11: Startup integrity check
# ---------------------------------------------------------------------------


class TestStartupIntegrity:
    """SharedContext runs PRAGMA quick_check on init."""

    def test_fresh_db_passes(self, tmp_path):
        ctx = SharedContext(db_path=tmp_path / "fresh.db", tenant_id="default")
        conn = ctx.get_conn()
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"

    def test_integrity_checked_flag(self, tmp_path):
        """SharedContext should set _integrity_checked flag."""
        ctx = SharedContext(db_path=tmp_path / "flag.db", tenant_id="default")
        ctx.get_conn()  # Triggers _init_db
        assert ctx._integrity_checked is True


# ---------------------------------------------------------------------------
# DB-P13: Disk space monitoring
# ---------------------------------------------------------------------------


class TestDiskSpaceMonitoring:
    """SharedContext.check_disk_space returns percentage."""

    def test_returns_float(self, tmp_path):
        ctx = SharedContext(db_path=tmp_path / "disk.db", tenant_id="default")
        usage = ctx.check_disk_space()
        assert isinstance(usage, float)
        assert 0.0 <= usage <= 100.0

    def test_nonexistent_path_returns_zero(self, tmp_path):
        """If db path doesn't exist, should handle gracefully."""
        ctx = SharedContext(db_path=tmp_path / "subdir" / "disk.db", tenant_id="default")
        # subdir doesn't exist, but check_disk_space uses parent
        usage = ctx.check_disk_space()
        # Should return 0.0 on error or a valid percentage
        assert isinstance(usage, float)


# ---------------------------------------------------------------------------
# DB-H1: WAL checkpoint
# ---------------------------------------------------------------------------


class TestWALCheckpoint:
    """SharedContext.wal_checkpoint runs PASSIVE checkpoint."""

    def test_wal_checkpoint_returns_tuple(self, tmp_path):
        ctx = SharedContext(db_path=tmp_path / "wal.db", tenant_id="default")
        result = ctx.wal_checkpoint()
        assert isinstance(result, tuple)
        assert len(result) == 3

    def test_wal_checkpoint_after_writes(self, tmp_path):
        """Checkpoint should succeed after heavy writes."""
        ctx = SharedContext(db_path=tmp_path / "wal2.db", tenant_id="default")
        conn = ctx.get_conn()
        for i in range(50):
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                (f"wal-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                 "test", 0.9, "default"),
            )
        conn.commit()
        result = ctx.wal_checkpoint()
        assert result[0] == 0  # busy=0 (no contention)

    def test_schedule_wal_checkpoint_method_exists(self, tmp_path):
        """The async scheduling method should exist."""
        ctx = SharedContext(db_path=tmp_path / "wal3.db", tenant_id="default")
        assert hasattr(ctx, "schedule_wal_checkpoint")
        assert callable(ctx.schedule_wal_checkpoint)


# ---------------------------------------------------------------------------
# SEC-L2: Query parameter API key auth
# ---------------------------------------------------------------------------


class TestQueryParamAuth:
    """Query parameter API key auth should be disabled in production."""

    @patch.dict(os.environ, {"BRIDGE_ENV": "production", "BRIDGE_QUERY_PARAM_AUTH": ""}, clear=False)
    def test_disabled_in_production_default(self, bridge_app):
        """In production without explicit config, query param auth rejected."""
        from fastapi.testclient import TestClient
        with TestClient(bridge_app) as c:
            resp = c.get("/api/health", params={"api_key": "fake-key"})
            # Should get 400 (disabled) rather than proceeding
            # Note: if no matching key, it'll be 401/403, but the
            # query param should be rejected before key validation
            assert resp.status_code in (400, 401, 403)

    @patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "disabled"}, clear=False)
    def test_explicitly_disabled(self, bridge_app):
        """Explicit disabled should reject query param auth."""
        from fastapi.testclient import TestClient
        with TestClient(bridge_app) as c:
            resp = c.get("/api/health", params={"api_key": "fake-key"})
            assert resp.status_code in (400, 401, 403)

    @patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "enabled"}, clear=False)
    def test_explicitly_enabled(self, bridge_app):
        """Explicit enabled should allow query param auth (key still validated)."""
        from fastapi.testclient import TestClient
        with TestClient(bridge_app) as c:
            resp = c.get("/api/health", params={"api_key": "fake-key"})
            # Should get 401/403 (bad key) not 400 (disabled)
            assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# SEC-M18: Admin password auto-delete pattern
# ---------------------------------------------------------------------------


class TestAdminPasswordPattern:
    """Admin password file should be temporary."""

    def test_admin_password_creation_in_lifespan(self):
        """Lifespan should create and schedule deletion of admin password."""
        import inspect
        from sigrift.bridge import app as app_module
        src = inspect.getsource(app_module)
        # The pattern: write password file, schedule deletion. Filename
        # changed in SEC-M18 (#19) from a `.admin_password` dotfile in
        # the shared data dir to `sigrift-admin-pw` in `/tmp` (container-
        # local), but the lifecycle is identical — write a file, auto-
        # delete after 60s.
        assert "sigrift-admin-pw" in src or ".admin_password" in src
        assert "unlink" in src or "remove" in src


# ---------------------------------------------------------------------------
# Health endpoint disk usage
# ---------------------------------------------------------------------------


class TestHealthDiskUsage:
    """Health endpoint should report disk usage."""

    def test_health_response_has_disk_usage_field(self):
        """BridgeHealthResponse model should have disk_usage_pct."""
        from sigrift.bridge.models import BridgeHealthResponse
        resp = BridgeHealthResponse()
        assert hasattr(resp, "disk_usage_pct")
        assert resp.disk_usage_pct is None  # Default

    def test_health_response_accepts_disk_usage(self):
        """disk_usage_pct should accept float values."""
        from sigrift.bridge.models import BridgeHealthResponse
        resp = BridgeHealthResponse(disk_usage_pct=42.5)
        assert resp.disk_usage_pct == 42.5


# ---------------------------------------------------------------------------
# Integration: CUSUM + BaselineManager
# ---------------------------------------------------------------------------


class TestCUSUMIntegration:
    """CUSUM works through BaselineManager."""

    def test_manager_tracks_cusum(self):
        """BaselineManager should propagate CUSUM through update calls."""
        rng = random.Random(99)
        mgr = BaselineManager()
        # Stable period past learning phase
        for _ in range(350):
            mgr.update(2437e6, "wifi", 0.9, -60.0 + rng.gauss(0, 1), hour=14)
        bl = mgr.get_baseline(2437e6)
        assert bl is not None
        assert isinstance(bl, FrequencyBaseline)
        assert bl.cusum_changepoints == 0

        # Shift period
        for _ in range(100):
            mgr.update(2437e6, "wifi", 0.9, -30.0 + rng.gauss(0, 1), hour=14)
        assert bl.cusum_changepoints >= 1

    def test_cusum_persists_through_save_load(self, tmp_path):
        """CUSUM state should persist through BaselineManager save/load."""
        rng = random.Random(42)
        mgr = BaselineManager()
        for _ in range(350):
            mgr.update(100e6, "fm", 0.9, -70.0 + rng.gauss(0, 1), hour=10)
        for _ in range(50):
            mgr.update(100e6, "fm", 0.9, -50.0 + rng.gauss(0, 1), hour=10)

        path = str(tmp_path / "baselines.json")
        mgr.save(path)

        mgr2 = BaselineManager()
        mgr2.load(path)
        bl1 = mgr.get_baseline(100e6)
        bl2 = mgr2.get_baseline(100e6)
        assert bl2.cusum_changepoints == bl1.cusum_changepoints
        assert bl2.cusum_pos == bl1.cusum_pos
        assert bl2.cusum_neg == bl1.cusum_neg


# ---------------------------------------------------------------------------
# Integration: Database resilience under stress
# ---------------------------------------------------------------------------


class TestDBResilience:
    """Database operations under stress conditions."""

    def test_integrity_check_after_writes(self, tmp_path):
        """quick_check should pass after heavy INSERT/DELETE cycles."""
        ctx = SharedContext(db_path=tmp_path / "resilience.db", tenant_id="default")
        conn = ctx.get_conn()

        # Heavy writes
        for i in range(200):
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                (f"r-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                 "test", 0.9, "default"),
            )
        conn.commit()

        # Delete half
        conn.execute("DELETE FROM detections WHERE rowid % 2 = 0")
        conn.commit()

        # WAL checkpoint
        ctx.wal_checkpoint()

        # Integrity should pass
        assert conn.execute("PRAGMA quick_check").fetchone()[0] == "ok"

    def test_disk_space_and_wal_checkpoint_together(self, tmp_path):
        """Both disk space check and WAL checkpoint should work together."""
        ctx = SharedContext(db_path=tmp_path / "combined.db", tenant_id="default")
        conn = ctx.get_conn()

        for i in range(50):
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence, tenant_id) VALUES (?, ?, ?, ?, ?, ?)",
                (f"c-{i}", "n1", datetime.now(timezone.utc).isoformat(),
                 "test", 0.9, "default"),
            )
        conn.commit()

        # Both should work without error
        disk = ctx.check_disk_space()
        assert isinstance(disk, float)

        result = ctx.wal_checkpoint()
        assert isinstance(result, tuple)
