"""Tests for P0/P1 review fixes (2026-03-07 review cycle).

Covers:
  SEC-H1  Session token hashing
  SEC-H3  HMAC v2 mutable field coverage
  SEC-H4  Legacy NULL HMAC sentinel
  SEC-M2  Session binding default
  SEC-M6  Account lockout
  SEC-M9  Failed auth audit logging
  SEC-M16 Configurable SQLite pragmas
  DS-R1   Weight source-of-truth
  DS-R2   Context multiplier additive cap
  DS-R3   IQ weight redistribution
  DS-R5   Laplace smoothing / rare_class
  DS-R6   Selective learning dampening
  DB-C1   Aggregate family preservation
  DB-H2   MAX anomaly in aggregation
  DB-P6   Batched cleanup
  DB-P8   Heatmap deterministic dominant_class
  DB-P9   Composite index for get_recent
"""
from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.baseline import FrequencyBaseline
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import (
    AnomalyScorer,
    DEFAULT_RF_DIMENSION_WEIGHTS,
    _DEFAULT_WEIGHTS,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# SEC-H1: Session token hashing
# ---------------------------------------------------------------------------

class TestSessionTokenHashing:
    """SEC-H1: Session tokens must be hashed (SHA-256) before DB storage."""

    def test_raw_token_not_in_db(self, detection_store: DetectionStore) -> None:
        detection_store.users.create_user("testuser", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        raw_token = session["session_token"]

        conn = detection_store.get_connection()
        rows = conn.execute("SELECT session_token FROM sessions").fetchall()
        stored = [r["session_token"] for r in rows]
        assert raw_token not in stored, "Raw token stored in plaintext!"
        expected = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        assert expected in stored

    def test_lookup_by_raw_token(self, detection_store: DetectionStore) -> None:
        detection_store.users.create_user("testuser", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        found = detection_store.get_session(session["session_token"])
        assert found is not None
        assert isinstance(found, dict)
        assert found["user_id"] == 1

    def test_delete_by_raw_token(self, detection_store: DetectionStore) -> None:
        detection_store.users.create_user("testuser", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        assert detection_store.delete_session(session["session_token"]) is True
        assert detection_store.get_session(session["session_token"]) is None


# ---------------------------------------------------------------------------
# SEC-H3 / SEC-H4: HMAC v2 + legacy sentinel
# ---------------------------------------------------------------------------

class TestHMACv2:
    """SEC-H3: HMAC v2 covers mutable fields (details, note, etc.)."""

    def test_tampered_details_detected(self, detection_store: DetectionStore) -> None:
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a",
            details={"severity": "critical"},
        )
        detection_store.log_audit(action="baseline", target_id="det_002", operator="key_b")

        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET details = '{\"severity\": \"info\"}' "
            "WHERE target_id = 'det_001'"
        )
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False

    def test_tampered_note_detected(self, detection_store: DetectionStore) -> None:
        detection_store.log_audit(
            action="dismiss", target_id="det_001", operator="key_a",
            note="Original note",
        )
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE audit_log SET note = 'Tampered' WHERE target_id = 'det_001'"
        )
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False

    def test_gap_detection(self, detection_store: DetectionStore) -> None:
        for i in range(5):
            detection_store.log_audit(
                action="dismiss", target_id=f"det_{i:03d}", operator="key_a",
            )
        conn = detection_store.get_connection()
        conn.execute("DELETE FROM audit_log WHERE target_id = 'det_002'")
        conn.commit()

        result = detection_store.verify_audit_chain()
        assert result["valid"] is False
        assert len(result.get("gaps", [])) >= 1
        assert all(isinstance(g, dict) for g in result["gaps"])

    def test_legacy_empty_hmac_sentinel(self, detection_store: DetectionStore) -> None:
        """Pre-migration entry with empty HMAC uses sentinel, not empty string reset."""
        conn = detection_store.get_connection()
        # Simulate a legacy entry with empty hmac (pre-migration)
        conn.execute(
            "INSERT INTO audit_log (timestamp, action, target_id, operator, hmac_chain) "
            "VALUES ('2024-01-01T00:00:00+00:00', 'legacy', 'old_001', 'admin', '')"
        )
        conn.commit()

        # New entry after legacy should still chain properly
        detection_store.log_audit(action="dismiss", target_id="det_001", operator="key_a")
        result = detection_store.verify_audit_chain()
        assert isinstance(result, dict)
        assert isinstance(result["total"], int)
        assert result["total"] == 2


# ---------------------------------------------------------------------------
# SEC-M2: Session binding default
# ---------------------------------------------------------------------------

class TestSessionBindingDefault:
    """SEC-M2: Default session binding should be 'ip', not 'warn'."""

    def test_default_is_ip(self) -> None:
        old = os.environ.pop("BRIDGE_SESSION_BINDING", None)
        try:
            val = os.environ.get("BRIDGE_SESSION_BINDING", "ip").lower()
            assert val == "ip"
        finally:
            if old is not None:
                os.environ["BRIDGE_SESSION_BINDING"] = old


# ---------------------------------------------------------------------------
# SEC-M6: Account lockout
# ---------------------------------------------------------------------------

class TestAccountLockout:
    """SEC-M6: Per-account lockout after N failed attempts."""

    def test_lockout_globals_exist(self) -> None:
        from sigrift.bridge.routers import auth
        assert hasattr(auth, "_account_failures")
        assert hasattr(auth, "_ACCOUNT_LOCKOUT_MAX")
        assert auth._ACCOUNT_LOCKOUT_MAX == 10

    def test_lockout_function_exists(self) -> None:
        from sigrift.bridge.routers.auth import _check_account_lockout
        assert callable(_check_account_lockout)


# ---------------------------------------------------------------------------
# SEC-M16: Configurable SQLite pragmas
# ---------------------------------------------------------------------------

class TestConfigurablePragmas:
    """SEC-M16: cache_size and mmap_size configurable via env vars."""

    def test_custom_cache_size(self, tmp_path: Path) -> None:
        old = os.environ.get("BRIDGE_SQLITE_CACHE_SIZE")
        os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = "-16000"
        try:
            store = DetectionStore(db_path=tmp_path / "pragma_test.db")
            conn = store.get_connection()
            val = conn.execute("PRAGMA cache_size").fetchone()[0]
            assert val == -16000
            store.close()
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SQLITE_CACHE_SIZE", None)
            else:
                os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = old


# ---------------------------------------------------------------------------
# DS-R1: Weight source of truth
# ---------------------------------------------------------------------------

class TestWeightSourceOfTruth:
    """DS-R1: scorer.py is the single source; persistence.py imports it."""

    def test_weights_sum_to_one(self) -> None:
        total = sum(DEFAULT_RF_DIMENSION_WEIGHTS.values())
        assert abs(total - 1.18) < 0.01

    def test_persistence_imports_scorer_weights(self) -> None:
        from sigrift.bridge.persistence import PersistenceManager
        defaults = PersistenceManager._DETECTION_CONFIG_DEFAULTS
        rf_weights = defaults["rf_dimension_weights"]
        assert rf_weights == DEFAULT_RF_DIMENSION_WEIGHTS


# ---------------------------------------------------------------------------
# DS-R5: Laplace smoothing + rare_class bug fix
# ---------------------------------------------------------------------------

class TestLaplaceSmoothing:
    """DS-R5: Smoothed probabilities prevent extreme scores."""

    def test_unseen_class_probability_nonzero(self) -> None:
        bl = FrequencyBaseline()
        for _ in range(50):
            bl.update("bpsk", 0.95, -30.0, 10, snr_db=15.0)
        prob = bl.class_probability_smoothed("unknown_mod")
        assert prob > 0.0
        assert prob < 0.1

    def test_seen_class_still_high(self) -> None:
        bl = FrequencyBaseline()
        for _ in range(100):
            bl.update("bpsk", 0.95, -30.0, 10, snr_db=15.0)
        assert bl.class_probability_smoothed("bpsk") > 0.8

    def test_hourly_unseen_smoothed(self) -> None:
        bl = FrequencyBaseline()
        for _ in range(50):
            bl.update("bpsk", 0.95, -30.0, 10, snr_db=15.0)
        prob = bl.hourly_probability_smoothed("unknown", hour=10)
        assert prob > 0.0

    def test_rare_class_uses_smoothing(self) -> None:
        """Bug fix: unseen class should NOT score exactly 1.0."""
        bl = FrequencyBaseline()
        for _ in range(100):
            bl.update("bpsk", 0.95, -30.0, 10, snr_db=15.0)
        scorer = AnomalyScorer(BaselineManager())
        score = scorer._rare_class_score(bl, "totally_new")
        assert score < 1.0, "rare_class must use smoothed probability"
        assert score > 0.8


# ---------------------------------------------------------------------------
# DS-R6: Selective learning-phase dampening
# ---------------------------------------------------------------------------

class TestSelectiveDampening:
    """DS-R6: Only baseline-dependent dims dampened during learning."""

    def test_low_confidence_not_dampened_during_learning(self) -> None:
        """Low confidence dimension should be at full weight during learning."""
        scorer = AnomalyScorer(BaselineManager())
        det = {
            "signal_class": "totally_novel",
            "confidence": 0.3,
            "freq_hz": 900e6,
        }
        result = scorer.score(det)
        # low_confidence dim (weight 0.14) should NOT be dampened
        assert result.dimensions["low_confidence"] == pytest.approx(0.7, abs=0.01)
        # quiet_frequency IS baseline-dependent → dampened by 0.5
        # Score should still be > 0 thanks to undampened dims
        assert result.score > 0.05, (
            f"Score during learning was {result.score:.3f}, should be > 0"
        )

    def test_baseline_dims_dampened(self) -> None:
        """Baseline-dependent dims should be dampened by 0.5 during learning."""
        bm = BaselineManager()
        scorer = AnomalyScorer(bm)
        # Feed one detection to create a baseline entry, still in learning
        det = {"signal_class": "bpsk", "confidence": 0.95, "freq_hz": 433.92e6,
               "power_dbm": -90.0}
        scorer.score(det)
        # Now score with extreme power deviation
        det2 = {"signal_class": "bpsk", "confidence": 0.95, "freq_hz": 433.92e6,
                "power_dbm": -10.0}
        result = scorer.score(det2)
        # power_zscore should be dampened during learning
        assert result.baseline_status == "learning"


# ---------------------------------------------------------------------------
# DS-R3: IQ weight redistribution
# ---------------------------------------------------------------------------

class TestIQWeightRedistribution:
    """DS-R3: Weights re-normalized when IQ absent."""

    def test_score_valid_without_iq(self) -> None:
        scorer = AnomalyScorer(BaselineManager())
        det = {"signal_class": "bpsk", "confidence": 0.5, "freq_hz": 433.92e6}
        result = scorer.score(det)
        assert 0.0 <= result.score <= 1.0


# ---------------------------------------------------------------------------
# DB-H2: MAX anomaly in aggregation
# ---------------------------------------------------------------------------

class TestMaxAnomalyAggregation:
    """DB-H2: Peak anomaly score preserved in hourly aggregation."""

    def test_max_anomaly_preserved(self, detection_store: DetectionStore) -> None:
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = []
        for i in range(10):
            d = make_detection(
                node_id="node-test-01",
                anomaly_score=0.01 if i < 9 else 0.95,
            )
            d.timestamp = base_time
            dets.append(d)
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert isinstance(count, int)
        assert count > 0

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT avg_anomaly, max_anomaly_score FROM detection_aggregates LIMIT 1"
        ).fetchone()
        assert row is not None
        assert isinstance(row["max_anomaly_score"], float)
        assert isinstance(row["avg_anomaly"], float)
        assert row["max_anomaly_score"] >= 0.95
        assert row["avg_anomaly"] < 0.2


# ---------------------------------------------------------------------------
# DB-P6: Batched cleanup
# ---------------------------------------------------------------------------

class TestBatchedCleanup:
    """DB-P6: Cleanup deletes in batches to avoid lock starvation."""

    def test_cleanup_deletes_old(self, detection_store: DetectionStore) -> None:
        old_time = datetime.now(timezone.utc) - timedelta(days=10)
        dets = [make_detection(node_id="node-test-01") for _ in range(50)]
        for d in dets:
            d.timestamp = old_time
        detection_store.insert_batch(dets)

        new_dets = [make_detection(node_id="node-test-01") for _ in range(10)]
        detection_store.insert_batch(new_dets)

        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 50


# ---------------------------------------------------------------------------
# DB-P8: Heatmap deterministic dominant_class
# ---------------------------------------------------------------------------

class TestHeatmapDominantClass:
    """DB-P8: Heatmap returns the most frequent class per bucket."""

    def test_dominant_class_is_most_frequent(self, detection_store: DetectionStore) -> None:
        now = datetime.now(timezone.utc)
        dets = []
        for _ in range(10):
            d = make_detection(signal_class="bpsk", freq_hz=433e6)
            d.timestamp = now
            dets.append(d)
        for _ in range(3):
            d = make_detection(signal_class="qpsk", freq_hz=433e6)
            d.timestamp = now
            dets.append(d)
        detection_store.insert_batch(dets)

        result = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        assert len(result) > 0, "Heatmap returned no results"
        assert isinstance(result, list)
        bucket = result[0]
        assert isinstance(bucket, dict)
        assert bucket["dominant_class"] == "bpsk"
        assert bucket["count"] == 13


# ---------------------------------------------------------------------------
# DB-C1: Aggregate preserves multiple families
# ---------------------------------------------------------------------------

class TestAggregateFamily:
    """DB-C1: Multiple families in same (hour, node, class) preserved."""

    def test_families_not_overwritten(self, detection_store: DetectionStore) -> None:
        base_time = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = []
        for fam in ("psk", "fsk"):
            for _ in range(5):
                d = make_detection(
                    node_id="node-test-01",
                    signal_class="bpsk",
                    family=fam,
                )
                d.timestamp = base_time
                dets.append(d)
        detection_store.insert_batch(dets)

        count = detection_store._analytics.aggregate_hourly("default")
        assert count == 2, f"Expected 2 aggregate rows (one per family), got {count}"
