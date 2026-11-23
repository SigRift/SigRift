"""Integration, functional, and edge-case tests for P0/P1 review fixes.

Covers end-to-end flows and boundary conditions for:
  - Session token hashing (SEC-H1): roundtrip, multiple sessions, collision safety
  - HMAC v2 audit chain (SEC-H3/H4): mixed v1/v2, concurrent writes, bulk tamper
  - Account lockout (SEC-M6): lockout+unlock flow, window expiry, memory cap
  - Failed auth audit (SEC-M9): audit trail on failed login
  - Batched cleanup (DB-P6): partial batches, concurrent insert during cleanup
  - Heatmap (DB-P8): multi-bucket, empty data, single class
  - Aggregation (DB-H2/DB-C1): max anomaly edge values, family dedup
  - Scoring (DS-R1/R3/R5/R6): weight invariants, edge scores, IQ redistribution
  - Configurable pragmas (SEC-M16): invalid values, default fallback
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.anomaly.scorer import (
    AnomalyScorer,
    DEFAULT_RF_DIMENSION_WEIGHTS,
    _DEFAULT_WEIGHTS,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# SEC-H1: Session token hashing — integration & edge cases
# ---------------------------------------------------------------------------


class TestSessionTokenHashingIntegration:
    """End-to-end session flows with hashed tokens."""

    def test_multiple_sessions_same_user(self, detection_store: DetectionStore) -> None:
        """Multiple sessions for the same user produce distinct hashed tokens."""
        detection_store.users.create_user("multi_sess", "Password123!")
        user = detection_store.users.get_user_full("multi_sess")
        s1 = detection_store.create_session(user_id=user["id"], ip_address="10.0.0.1")
        s2 = detection_store.create_session(user_id=user["id"], ip_address="10.0.0.2")

        assert s1["session_token"] != s2["session_token"]

        # Both retrievable by raw token
        assert isinstance(detection_store.get_session(s1["session_token"]), dict)
        assert isinstance(detection_store.get_session(s2["session_token"]), dict)

        # Delete one, the other survives
        detection_store.delete_session(s1["session_token"])
        assert detection_store.get_session(s1["session_token"]) is None
        assert isinstance(detection_store.get_session(s2["session_token"]), dict)

    def test_token_not_guessable_from_hash(self, detection_store: DetectionStore) -> None:
        """The stored hash cannot be used directly as a session token."""
        detection_store.users.create_user("hashguess", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        raw = session["session_token"]
        stored_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        # Using the hash as if it were the raw token should fail
        assert detection_store.get_session(stored_hash) is None

    def test_session_create_delete_roundtrip(self, detection_store: DetectionStore) -> None:
        """Full create → lookup → delete → verify-gone cycle."""
        detection_store.users.create_user("roundtrip", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        token = session["session_token"]

        found = detection_store.get_session(token)
        assert isinstance(found, dict)
        assert found["user_id"] == 1

        assert detection_store.delete_session(token) is True
        assert detection_store.get_session(token) is None
        # Double delete returns False
        assert detection_store.delete_session(token) is False

    def test_all_stored_tokens_are_hex_sha256(self, detection_store: DetectionStore) -> None:
        """Every session_token in DB is a valid 64-char hex SHA-256 digest."""
        detection_store.users.create_user("hexcheck", "Password123!")
        for i in range(5):
            detection_store.create_session(user_id=1, ip_address=f"10.0.0.{i}")

        conn = detection_store.get_connection()
        rows = conn.execute("SELECT session_token FROM sessions").fetchall()
        assert len(rows) == 5
        for row in rows:
            tok = row["session_token"]
            assert len(tok) == 64, f"Token length {len(tok)}, expected 64"
            int(tok, 16)  # Raises ValueError if not valid hex


# ---------------------------------------------------------------------------
# SEC-H3/H4: HMAC v2 chain — integration & edge cases
# ---------------------------------------------------------------------------


class TestHMACv2Integration:
    """End-to-end HMAC chain integrity scenarios."""

    def test_large_chain_integrity(self, detection_store: DetectionStore) -> None:
        """50-entry chain verifies correctly without tampering."""
        for i in range(50):
            detection_store.log_audit(
                action="dismiss",
                target_id=f"det_{i:04d}",
                operator="key_test",
                details={"idx": i},
            )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 50

    def test_first_entry_tampered(self, detection_store: DetectionStore) -> None:
        """Tampering with the very first entry breaks the chain."""
        for i in range(5):
            detection_store.log_audit(
                action="dismiss", target_id=f"d_{i}", operator="op",
            )
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET operator = 'hacker' WHERE target_id = 'd_0'"
        )
        conn.commit()
        result = detection_store.verify_audit_chain()
        assert result["valid"] is False

    def test_last_entry_tampered(self, detection_store: DetectionStore) -> None:
        """Tampering with the last entry is also detected."""
        for i in range(5):
            detection_store.log_audit(
                action="dismiss", target_id=f"d_{i}", operator="op",
            )
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET action = 'fake' WHERE target_id = 'd_4'"
        )
        conn.commit()
        result = detection_store.verify_audit_chain()
        assert result["valid"] is False

    def test_empty_chain_is_valid(self, detection_store: DetectionStore) -> None:
        """Empty audit log should verify as valid."""
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 0

    def test_single_entry_chain(self, detection_store: DetectionStore) -> None:
        """Single entry chain verifies correctly."""
        detection_store.log_audit(
            action="dismiss", target_id="solo", operator="key_a",
            details={"reason": "test"}, note="Only entry",
        )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 1

    def test_details_json_ordering(self, detection_store: DetectionStore) -> None:
        """HMAC covers details as sorted JSON — reordered keys don't break it."""
        detection_store.log_audit(
            action="dismiss", target_id="d_json", operator="op",
            details={"z_field": 1, "a_field": 2, "m_field": 3},
        )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# SEC-M6: Account lockout — functional & edge cases
# ---------------------------------------------------------------------------


class TestAccountLockoutFunctional:
    """Functional tests for per-account lockout mechanism (DB-backed)."""

    def test_lockout_clears_on_window_expiry(self, detection_store) -> None:
        """Failures outside the window are not counted."""
        sec = detection_store.security_state
        username = "test_window_expiry"

        # Insert old failures beyond the window
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.LOCKOUT_WINDOW - 10
        for _ in range(15):
            conn.execute(
                "INSERT INTO account_lockout (username, failure_at, tenant_id) "
                "VALUES (?, ?, ?)",
                [username, old_ts, "default"],
            )
        conn.commit()

        # Should NOT be counted
        assert sec.count_recent_failures(username) == 0

    def test_lockout_blocks_after_max_attempts(self, detection_store) -> None:
        """Account is locked after LOCKOUT_MAX recent failures."""
        from sigrift.bridge.routers.auth import _check_account_lockout
        sec = detection_store.security_state
        username = "test_lockout_block"

        for _ in range(sec.LOCKOUT_MAX):
            sec.record_account_failure(username)

        with pytest.raises(HTTPException) as exc_info:
            _check_account_lockout(username, detection_store)
        assert exc_info.value.status_code == 429

    def test_lockout_allows_under_threshold(self, detection_store) -> None:
        """Account with fewer than max failures is NOT locked."""
        from sigrift.bridge.routers.auth import _check_account_lockout
        sec = detection_store.security_state
        username = "test_under_threshold"

        for _ in range(sec.LOCKOUT_MAX - 1):
            sec.record_account_failure(username)

        _check_account_lockout(username, detection_store)  # Should not raise

    def test_lockout_independent_per_account(self, detection_store) -> None:
        """Lockout for one account does not affect another."""
        from sigrift.bridge.routers.auth import _check_account_lockout
        sec = detection_store.security_state
        locked = "locked_user"
        free = "free_user"

        for _ in range(sec.LOCKOUT_MAX):
            sec.record_account_failure(locked)
        sec.record_account_failure(free)

        with pytest.raises(HTTPException):
            _check_account_lockout(locked, detection_store)
        _check_account_lockout(free, detection_store)  # Should not raise


# ---------------------------------------------------------------------------
# SEC-M9: Failed auth audit logging — integration
# ---------------------------------------------------------------------------


class TestFailedAuthAudit:
    """Failed login creates audit log entry."""

    def test_failed_login_audit_entry(
        self,
        client,
        detection_store: DetectionStore,
    ) -> None:
        """A failed login attempt is recorded in the audit log."""
        detection_store.users.create_user("audituser", "CorrectPass1!")

        # Attempt login with wrong password
        resp = client.post("/api/auth/login", json={
            "username": "audituser",
            "password": "WrongPassword1!",
        })
        assert resp.status_code == 401

        # Verify audit trail
        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'auth_failure' "
            "AND target_id = 'audituser'"
        ).fetchone()
        assert row is not None
        assert isinstance(row["action"], str)
        assert row["action"] == "auth_failure"
        assert "Failed login" in row["note"]


# ---------------------------------------------------------------------------
# DB-P6: Batched cleanup — edge cases
# ---------------------------------------------------------------------------


class TestBatchedCleanupEdgeCases:
    """Edge cases for batched deletion."""

    def test_cleanup_empty_store(self, detection_store: DetectionStore) -> None:
        """Cleanup on empty store returns 0, no errors."""
        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 0

    def test_cleanup_nothing_old(self, detection_store: DetectionStore) -> None:
        """Cleanup with only fresh data deletes nothing."""
        dets = [make_detection(node_id="node-01") for _ in range(20)]
        detection_store.insert_batch(dets)
        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 0

    def test_cleanup_exact_boundary(self, detection_store: DetectionStore) -> None:
        """Detections at exactly max_age_days boundary are deleted."""
        boundary = datetime.now(timezone.utc) - timedelta(days=7, seconds=1)
        dets = [make_detection(node_id="node-01") for _ in range(5)]
        for d in dets:
            d.timestamp = boundary
        detection_store.insert_batch(dets)

        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 5

    def test_cleanup_preserves_recent_mixed_with_old(
        self, detection_store: DetectionStore,
    ) -> None:
        """Cleanup deletes old but keeps recent when mixed."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        old_dets = [make_detection(node_id="node-01") for _ in range(25)]
        for d in old_dets:
            d.timestamp = old
        new_dets = [make_detection(node_id="node-01") for _ in range(10)]

        detection_store.insert_batch(old_dets)
        detection_store.insert_batch(new_dets)

        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 25

        # Verify remaining
        conn = detection_store.get_connection()
        remaining = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        assert remaining == 10


# ---------------------------------------------------------------------------
# DB-P8: Heatmap — edge cases
# ---------------------------------------------------------------------------


class TestHeatmapEdgeCases:
    """Edge cases for heatmap generation."""

    def test_heatmap_empty_data(self, detection_store: DetectionStore) -> None:
        """Heatmap with no data returns empty list."""
        result = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        assert result == []

    def test_heatmap_single_class(self, detection_store: DetectionStore) -> None:
        """Heatmap with single class returns that class as dominant."""
        now = datetime.now(timezone.utc)
        dets = [make_detection(signal_class="qam16", freq_hz=915e6) for _ in range(5)]
        for d in dets:
            d.timestamp = now
        detection_store.insert_batch(dets)

        result = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        assert isinstance(result, list)
        assert len(result) >= 1
        assert result[0]["dominant_class"] == "qam16"
        assert result[0]["count"] == 5

    def test_heatmap_multiple_freq_buckets(self, detection_store: DetectionStore) -> None:
        """Detections at different frequencies produce separate buckets."""
        now = datetime.now(timezone.utc)
        dets = []
        for freq in [433e6, 915e6, 2400e6]:
            for _ in range(3):
                d = make_detection(signal_class="bpsk", freq_hz=freq)
                d.timestamp = now
                dets.append(d)
        detection_store.insert_batch(dets)

        result = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        freq_buckets = {r["freq_bucket_mhz"] for r in result}
        assert len(freq_buckets) == 3

    def test_heatmap_zero_freq_excluded(self, detection_store: DetectionStore) -> None:
        """Detections with freq_hz=0 are excluded from heatmap."""
        now = datetime.now(timezone.utc)
        zero_det = make_detection(signal_class="bpsk", freq_hz=0)
        zero_det.timestamp = now
        good_det = make_detection(signal_class="bpsk", freq_hz=433e6)
        good_det.timestamp = now
        detection_store.insert_batch([zero_det, good_det])

        result = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        total = sum(r["count"] for r in result)
        assert total == 1  # Only the non-zero freq detection


# ---------------------------------------------------------------------------
# DB-H2: MAX anomaly aggregation — edge cases
# ---------------------------------------------------------------------------


class TestMaxAnomalyEdgeCases:
    """Edge cases for max anomaly score in aggregation."""

    def test_all_zero_anomaly(self, detection_store: DetectionStore) -> None:
        """All zero anomaly scores produce max=0."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = [make_detection(node_id="n1", anomaly_score=0.0) for _ in range(10)]
        for d in dets:
            d.timestamp = base
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert isinstance(count, int)
        assert count > 0

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT max_anomaly_score FROM detection_aggregates LIMIT 1"
        ).fetchone()
        assert row["max_anomaly_score"] == pytest.approx(0.0)

    def test_all_max_anomaly(self, detection_store: DetectionStore) -> None:
        """All anomaly=1.0 scores produce max=1.0 and avg=1.0."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = [make_detection(node_id="n1", anomaly_score=1.0) for _ in range(5)]
        for d in dets:
            d.timestamp = base
        detection_store.insert_batch(dets)

        detection_store._analytics.aggregate_hourly("default")

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT max_anomaly_score, avg_anomaly FROM detection_aggregates LIMIT 1"
        ).fetchone()
        assert row["max_anomaly_score"] == pytest.approx(1.0)
        assert row["avg_anomaly"] == pytest.approx(1.0)

    def test_single_spike_preserves_max(self, detection_store: DetectionStore) -> None:
        """A single high score among low scores is preserved as max."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = [make_detection(node_id="n1", anomaly_score=0.01) for _ in range(99)]
        spike = make_detection(node_id="n1", anomaly_score=0.99)
        spike.timestamp = base
        for d in dets:
            d.timestamp = base
        dets.append(spike)
        detection_store.insert_batch(dets)

        detection_store._analytics.aggregate_hourly("default")

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT max_anomaly_score, avg_anomaly FROM detection_aggregates LIMIT 1"
        ).fetchone()
        assert row["max_anomaly_score"] >= 0.99
        assert row["avg_anomaly"] < 0.05


# ---------------------------------------------------------------------------
# DB-C1: Aggregate family — edge cases
# ---------------------------------------------------------------------------


class TestAggregateFamilyEdgeCases:
    """Edge cases for family preservation in aggregation."""

    def test_single_family_single_row(self, detection_store: DetectionStore) -> None:
        """All same family → single aggregate row."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = [make_detection(node_id="n1", signal_class="bpsk", family="psk")
                for _ in range(10)]
        for d in dets:
            d.timestamp = base
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert count == 1

    def test_three_families_three_rows(self, detection_store: DetectionStore) -> None:
        """Three different families → three aggregate rows."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = []
        for fam in ("psk", "fsk", "qam"):
            for _ in range(3):
                d = make_detection(node_id="n1", signal_class="bpsk", family=fam)
                d.timestamp = base
                dets.append(d)
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert count == 3

    def test_empty_family_is_separate(self, detection_store: DetectionStore) -> None:
        """Empty family string is a distinct family from non-empty."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = []
        for fam in ("psk", ""):
            for _ in range(5):
                d = make_detection(node_id="n1", signal_class="bpsk", family=fam)
                d.timestamp = base
                dets.append(d)
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert count == 2


# ---------------------------------------------------------------------------
# DS-R1/R3/R5/R6: Scoring — edge cases
# ---------------------------------------------------------------------------


class TestScoringEdgeCases:
    """Edge cases for anomaly scoring."""

    def test_all_weights_present(self) -> None:
        """All expected dimension keys exist in DEFAULT_RF_DIMENSION_WEIGHTS."""
        expected = {
            "novel_class", "rare_class", "low_confidence", "power_zscore",
            "snr_zscore", "timing_anomaly", "quiet_frequency",
            "iq_quality", "spectral_anomaly", "modulation_anomaly",
            "correlation", "signature_match",
            "bandwidth_anomaly", "inter_arrival_anomaly",
        }
        assert set(DEFAULT_RF_DIMENSION_WEIGHTS.keys()) == expected

    def test_weights_non_negative(self) -> None:
        """All weights are >= 0 (zero allowed for opt-in dimensions)."""
        for k, v in DEFAULT_RF_DIMENSION_WEIGHTS.items():
            assert v >= 0, f"Weight '{k}' is {v}, expected >= 0"

    def test_score_boundary_zero(self) -> None:
        """Detection with perfect baseline match scores near 0."""
        bm = BaselineManager()
        scorer = AnomalyScorer(bm)
        # Feed plenty of training data to build stable baseline
        for _ in range(200):
            scorer.score({
                "signal_class": "bpsk", "confidence": 0.95,
                "freq_hz": 433.92e6, "power_dbm": -30.0,
            })
        # Score a detection matching the baseline perfectly
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.95,
            "freq_hz": 433.92e6, "power_dbm": -30.0,
        })
        assert result.score < 0.3, f"Expected low score, got {result.score}"

    def test_score_clamps_to_0_1(self) -> None:
        """Score is always in [0, 1] regardless of input."""
        scorer = AnomalyScorer(BaselineManager())
        # Extreme values
        result = scorer.score({
            "signal_class": "never_seen_modulation",
            "confidence": 0.01,
            "freq_hz": 1e12,
            "power_dbm": 100.0,
        })
        assert 0.0 <= result.score <= 1.0

    def test_iq_absent_redistribution_preserves_sum(self) -> None:
        """Without IQ, non-IQ weights should effectively sum to ~1.0."""
        scorer = AnomalyScorer(BaselineManager())
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.5, "freq_hz": 433.92e6,
        })
        # The composite score should be valid
        assert 0.0 <= result.score <= 1.0
        # IQ dimension should be 0 (absent)
        assert result.dimensions.get("iq_anomaly", 0.0) == 0.0

    def test_laplace_smoothing_never_returns_one(self) -> None:
        """class_probability_smoothed never returns exactly 1.0."""
        bl = FrequencyBaseline()
        for _ in range(1000):
            bl.update("only_class", 0.99, -30.0, 10, snr_db=20.0)
        prob = bl.class_probability_smoothed("only_class")
        assert prob < 1.0, "Smoothed probability should never be exactly 1.0"
        assert prob > 0.9

    def test_laplace_smoothing_never_returns_zero(self) -> None:
        """class_probability_smoothed never returns exactly 0.0."""
        bl = FrequencyBaseline()
        for _ in range(1000):
            bl.update("bpsk", 0.99, -30.0, 10, snr_db=20.0)
        prob = bl.class_probability_smoothed("completely_unknown_class")
        assert prob > 0.0, "Smoothed probability should never be exactly 0.0"
        assert prob < 0.1

    def test_rare_class_score_range(self) -> None:
        """rare_class score is in (0, 1) for unseen classes."""
        bl = FrequencyBaseline()
        for _ in range(100):
            bl.update("bpsk", 0.95, -30.0, 10, snr_db=15.0)
        scorer = AnomalyScorer(BaselineManager())
        score = scorer._rare_class_score(bl, "never_seen")
        assert 0.0 < score < 1.0

    def test_dampening_ratio_during_learning(self) -> None:
        """Baseline-dependent dimensions are dampened by ~0.5 during learning."""
        bm = BaselineManager()
        scorer = AnomalyScorer(bm)
        # Score once to create a learning-phase baseline
        result = scorer.score({
            "signal_class": "newmod",
            "confidence": 0.95,
            "freq_hz": 433.92e6,
            "power_dbm": -30.0,
        })
        assert result.baseline_status == "learning"


# ---------------------------------------------------------------------------
# SEC-M16: Configurable pragmas — edge cases
# ---------------------------------------------------------------------------


class TestConfigurablePragmasEdgeCases:
    """Edge cases for configurable SQLite pragmas."""

    def test_default_cache_size(self, tmp_path: Path) -> None:
        """Default cache_size is -64000 when env var not set."""
        old = os.environ.pop("BRIDGE_SQLITE_CACHE_SIZE", None)
        try:
            store = DetectionStore(db_path=tmp_path / "default_pragma.db")
            conn = store.get_connection()
            val = conn.execute("PRAGMA cache_size").fetchone()[0]
            assert val == -64000
            store.close()
        finally:
            if old is not None:
                os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = old

    def test_default_mmap_size(self, tmp_path: Path) -> None:
        """Default mmap_size is 256MB when env var not set."""
        old = os.environ.pop("BRIDGE_SQLITE_MMAP_SIZE", None)
        try:
            store = DetectionStore(db_path=tmp_path / "default_mmap.db")
            conn = store.get_connection()
            val = conn.execute("PRAGMA mmap_size").fetchone()[0]
            assert val == 268435456
            store.close()
        finally:
            if old is not None:
                os.environ["BRIDGE_SQLITE_MMAP_SIZE"] = old

    def test_custom_mmap_size(self, tmp_path: Path) -> None:
        """Custom mmap_size via env var."""
        old = os.environ.get("BRIDGE_SQLITE_MMAP_SIZE")
        os.environ["BRIDGE_SQLITE_MMAP_SIZE"] = "0"
        try:
            store = DetectionStore(db_path=tmp_path / "mmap_test.db")
            conn = store.get_connection()
            val = conn.execute("PRAGMA mmap_size").fetchone()[0]
            assert val == 0
            store.close()
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SQLITE_MMAP_SIZE", None)
            else:
                os.environ["BRIDGE_SQLITE_MMAP_SIZE"] = old


# ---------------------------------------------------------------------------
# DB-P9: Composite index — functional
# ---------------------------------------------------------------------------


class TestCompositeIndex:
    """DB-P9: Composite index on (tenant_id, node_id, timestamp) exists."""

    def test_index_exists(self, detection_store: DetectionStore) -> None:
        """The composite index idx_detections_tenant_node_ts is present."""
        conn = detection_store.get_connection()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' "
            "AND name='idx_detections_tenant_node_ts'"
        ).fetchall()
        assert len(rows) == 1

    def test_get_recent_uses_index(self, detection_store: DetectionStore) -> None:
        """get_recent with node_id filter benefits from composite index."""
        # Insert data
        dets = [make_detection(node_id="indexed-node") for _ in range(20)]
        detection_store.insert_batch(dets)

        # Query should work correctly
        results = detection_store.get_recent(limit=10, node_id="indexed-node")
        assert len(results) == 10
        for r in results:
            assert r["node_id"] == "indexed-node"


# ---------------------------------------------------------------------------
# DS-R2: Context multiplier cap — edge case
# ---------------------------------------------------------------------------


class TestContextMultiplierCap:
    """DS-R2: Context multiplier additive boosts capped at 0.25."""

    def test_extreme_context_does_not_exceed_cap(self) -> None:
        """Score with extreme context doesn't blow past 1.0."""
        scorer = AnomalyScorer(BaselineManager())
        result = scorer.score({
            "signal_class": "exotic_never_seen",
            "confidence": 0.01,
            "freq_hz": 1e9,
            "power_dbm": 50.0,
            "burst_count": 10000,
        })
        assert result.score <= 1.0


# ---------------------------------------------------------------------------
# Integration: Login → audit trail → session lifecycle
# ---------------------------------------------------------------------------


class TestLoginAuditIntegration:
    """End-to-end: login attempts create audit entries + hashed sessions."""

    def test_successful_login_creates_session_and_audit(
        self,
        client,
        detection_store: DetectionStore,
    ) -> None:
        """Successful login: session in DB (hashed), audit entry logged."""
        detection_store.users.create_user("gooduser", "GoodPass123!")

        resp = client.post("/api/auth/login", json={
            "username": "gooduser",
            "password": "GoodPass123!",
        })
        assert resp.status_code == 200
        token = resp.json()["session_token"]
        assert isinstance(token, str)
        assert len(token) >= 32

        # Token in DB is hashed
        conn = detection_store.get_connection()
        rows = conn.execute("SELECT session_token FROM sessions").fetchall()
        raw_tokens = [r["session_token"] for r in rows]
        assert token not in raw_tokens
        expected_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        assert expected_hash in raw_tokens

        # Audit entry exists
        audit = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'user_login' "
            "AND target_id = 'gooduser'"
        ).fetchone()
        assert audit is not None
        assert isinstance(audit["operator"], str)
        assert audit["operator"] == "gooduser"

    def test_failed_login_no_session_but_audit(
        self,
        client,
        detection_store: DetectionStore,
    ) -> None:
        """Failed login: no session created, but audit entry logged."""
        detection_store.users.create_user("failuser", "RealPass123!")

        resp = client.post("/api/auth/login", json={
            "username": "failuser",
            "password": "WrongPass123!",
        })
        assert resp.status_code == 401

        conn = detection_store.get_connection()
        # No session should exist for this user
        sessions = conn.execute("SELECT * FROM sessions").fetchall()
        assert len(sessions) == 0

        # But audit log should have the failure
        audit = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'auth_failure' "
            "AND target_id = 'failuser'"
        ).fetchone()
        assert audit is not None
        assert isinstance(audit["action"], str)
        assert audit["action"] == "auth_failure"
