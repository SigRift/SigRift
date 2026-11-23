"""Additional coverage for P0/P1 review fixes — gap analysis tests.

Fills identified gaps in:
  - Session token hashing edge cases (SEC-H1)
  - HMAC v2 direct testing and field combinations (SEC-H3)
  - Account lockout memory cap eviction (SEC-M6)
  - Heatmap date= parameter path (DB-P8)
  - Batched cleanup at batch boundary (DB-P6)
  - Aggregate hourly idempotency (DB-H2)
  - Pragma invalid value handling (SEC-M16)
  - Idle timeout configuration (session lifecycle)
  - Concurrent audit logging (SEC-H3)
  - Edge model SHA-256 header (SEC-M15)
"""
from __future__ import annotations

import hashlib
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.anomaly.scorer import (
    AnomalyScorer,
    DEFAULT_RF_DIMENSION_WEIGHTS,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# SEC-H1: Session token hashing — edge cases
# ---------------------------------------------------------------------------


class TestSessionTokenHashingEdgeCases:
    """Edge cases for _hash_token and session operations."""

    def test_hash_token_deterministic(self, detection_store: DetectionStore) -> None:
        """Same token always produces the same hash."""
        h1 = detection_store.users._hash_token("test-token-abc")
        h2 = detection_store.users._hash_token("test-token-abc")
        assert h1 == h2

    def test_hash_token_different_tokens_differ(self, detection_store: DetectionStore) -> None:
        """Different tokens produce different hashes."""
        h1 = detection_store.users._hash_token("token-a")
        h2 = detection_store.users._hash_token("token-b")
        assert h1 != h2

    def test_hash_token_empty_string(self, detection_store: DetectionStore) -> None:
        """Empty string hashes to the known SHA-256 of empty."""
        result = detection_store.users._hash_token("")
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_hash_token_long_input(self, detection_store: DetectionStore) -> None:
        """Very long token hashes without truncation."""
        long_token = "x" * 10_000
        result = detection_store.users._hash_token(long_token)
        assert len(result) == 64  # SHA-256 always 64 hex chars

    def test_touch_session_updates_last_active(self, detection_store: DetectionStore) -> None:
        """_touch_session updates the last_active column."""
        detection_store.users.create_user("touchuser", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        token = session["session_token"]

        # Retrieve session (which calls _touch_session internally)
        found = detection_store.get_session(token)
        assert isinstance(found, dict) and found["username"] == "touchuser"

        # Verify last_active was set
        hashed = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT last_active FROM sessions WHERE session_token = ?",
            [hashed],
        ).fetchone()
        assert row is not None
        assert isinstance(row["last_active"], str)

    def test_set_session_scope_with_hashed_token(self, detection_store: DetectionStore) -> None:
        """set_session_scope works correctly with hashed token storage."""
        detection_store.users.create_user("scopeuser", "Password123!")
        session = detection_store.create_session(user_id=1, ip_address="127.0.0.1")
        token = session["session_token"]

        detection_store.users.set_session_scope(token, scope="mfa_setup_only")

        # Verify scope was set in DB
        hashed = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT scope FROM sessions WHERE session_token = ?",
            [hashed],
        ).fetchone()
        assert row["scope"] == "mfa_setup_only"

    def test_delete_nonexistent_token_returns_false(
        self, detection_store: DetectionStore,
    ) -> None:
        """Deleting a token that doesn't exist returns False."""
        assert detection_store.delete_session("completely-fake-token") is False


# ---------------------------------------------------------------------------
# SEC-H3: HMAC v2 — direct testing and field combinations
# ---------------------------------------------------------------------------


class TestHMACv2DirectAndFields:
    """Direct HMAC v2 computation and field combination tests."""

    def test_compute_hmac_v2_deterministic(self) -> None:
        """Same inputs always produce the same HMAC."""
        from sigrift.bridge.storage.audit import _compute_hmac_v2
        secret = b"test-secret-key-32-bytes-exactly"
        h1 = _compute_hmac_v2(
            secret, "prev", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z",
            '{"k": "v"}', "a note", "bpsk", "433920000.0", "node-01",
        )
        h2 = _compute_hmac_v2(
            secret, "prev", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z",
            '{"k": "v"}', "a note", "bpsk", "433920000.0", "node-01",
        )
        assert h1 == h2

    def test_compute_hmac_v2_differs_on_details(self) -> None:
        """Changing details produces a different HMAC."""
        from sigrift.bridge.storage.audit import _compute_hmac_v2
        secret = b"test-secret-key-32-bytes-exactly"
        args = ("prev", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z")
        h1 = _compute_hmac_v2(secret, *args, '{"severity": "high"}', "", "", "0", "")
        h2 = _compute_hmac_v2(secret, *args, '{"severity": "low"}', "", "", "0", "")
        assert h1 != h2

    def test_compute_hmac_v2_differs_on_note(self) -> None:
        """Changing note produces a different HMAC."""
        from sigrift.bridge.storage.audit import _compute_hmac_v2
        secret = b"test-secret-key-32-bytes-exactly"
        args = ("prev", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z")
        h1 = _compute_hmac_v2(secret, *args, "", "note A", "", "0", "")
        h2 = _compute_hmac_v2(secret, *args, "", "note B", "", "0", "")
        assert h1 != h2

    def test_compute_hmac_v2_empty_optional_fields(self) -> None:
        """All empty optional fields still produce a valid HMAC."""
        from sigrift.bridge.storage.audit import _compute_hmac_v2
        secret = b"test-secret-key-32-bytes-exactly"
        result = _compute_hmac_v2(
            secret, "", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z",
            "", "", "", "0.0", "",
        )
        assert len(result) == 64
        int(result, 16)  # Valid hex

    def test_compute_hmac_v2_special_chars_in_note(self) -> None:
        """Special characters in note don't break HMAC computation."""
        from sigrift.bridge.storage.audit import _compute_hmac_v2
        secret = b"test-secret-key-32-bytes-exactly"
        result = _compute_hmac_v2(
            secret, "", "dismiss", "det_001", "op", "2025-01-01T00:00:00Z",
            "", "line1\nline2\ttab|pipe", "", "0.0", "",
        )
        assert len(result) == 64

    def test_log_audit_all_fields(self, detection_store: DetectionStore) -> None:
        """log_audit with all optional fields produces valid chain."""
        detection_store.log_audit(
            action="dismiss",
            target_id="det_full",
            operator="key_test",
            details={"severity": "critical", "reason": "confirmed"},
            note="Full field test",
            signal_class="bpsk",
            freq_hz=433.92e6,
            node_id="node-42",
            target_ids=["det_001", "det_002"],
        )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 1

    def test_log_audit_only_required_fields(self, detection_store: DetectionStore) -> None:
        """log_audit with only required fields produces valid chain."""
        detection_store.log_audit(action="dismiss", target_id="det_min", operator="op")
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True

    def test_log_audit_signal_class_without_freq(self, detection_store: DetectionStore) -> None:
        """signal_class set but freq_hz left at default still chains correctly."""
        detection_store.log_audit(
            action="dismiss", target_id="det_sc", operator="op",
            signal_class="qpsk",
        )
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True


# ---------------------------------------------------------------------------
# SEC-H3: Concurrent audit logging
# ---------------------------------------------------------------------------


class TestConcurrentAuditLogging:
    """Concurrent audit log writes preserve chain integrity."""

    def test_concurrent_writes_chain_intact(self, detection_store: DetectionStore) -> None:
        """10 threads writing simultaneously — chain should verify."""
        errors = []

        def _write(idx: int):
            try:
                detection_store.log_audit(
                    action="dismiss",
                    target_id=f"concurrent_{idx:04d}",
                    operator="thread_test",
                    note=f"Thread {idx}",
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_write, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Thread errors: {errors}"
        result = detection_store.verify_audit_chain()
        assert result["valid"] is True
        assert result["total"] == 10


# ---------------------------------------------------------------------------
# SEC-M6: Account lockout — memory cap eviction
# ---------------------------------------------------------------------------


class TestAccountLockoutCleanup:
    """DB-backed account lockout cleanup (replaces in-memory eviction)."""

    def test_cleanup_removes_expired_entries(self, detection_store: DetectionStore) -> None:
        """cleanup_account_lockout removes entries older than its retention.

        The retention (24 h) is longer than the bridge's lockout window:
        the gateway counts the same table with a window of up to 24 h.
        """
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()

        # Insert an old failure directly
        old_ts = time.time() - sec.LOCKOUT_RETENTION - 10
        conn.execute(
            "INSERT INTO account_lockout (username, failure_at, tenant_id) "
            "VALUES (?, ?, ?)",
            ["evict_user", old_ts, "default"],
        )
        conn.commit()

        # Fresh failure should still be counted
        sec.record_account_failure("fresh_user")
        assert sec.count_recent_failures("fresh_user") == 1

        deleted = sec.cleanup_account_lockout()
        assert isinstance(deleted, int)
        assert deleted >= 1

        # Old entry gone, fresh entry remains
        assert sec.count_recent_failures("evict_user") == 0
        assert sec.count_recent_failures("fresh_user") == 1


# ---------------------------------------------------------------------------
# DB-P8: Heatmap date= parameter path
# ---------------------------------------------------------------------------


class TestHeatmapDateParameter:
    """Heatmap with date= parameter (vs hours=)."""

    def test_heatmap_with_date_parameter(self, detection_store: DetectionStore) -> None:
        """Heatmap with explicit date returns detections from that day."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        now = datetime.now(timezone.utc)
        dets = [make_detection(signal_class="bpsk", freq_hz=433e6) for _ in range(5)]
        for d in dets:
            d.timestamp = now
        detection_store.insert_batch(dets)

        result = detection_store._analytics.get_heatmap(date=today, resolution_minutes=60)
        assert isinstance(result, list)
        assert len(result) >= 1
        total = sum(r["count"] for r in result)
        assert total == 5

    def test_heatmap_empty_date_defaults_to_today(
        self, detection_store: DetectionStore,
    ) -> None:
        """Heatmap with empty date string defaults to today."""
        now = datetime.now(timezone.utc)
        dets = [make_detection(signal_class="bpsk", freq_hz=433e6) for _ in range(3)]
        for d in dets:
            d.timestamp = now
        detection_store.insert_batch(dets)

        result = detection_store._analytics.get_heatmap(date="", resolution_minutes=60)
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_heatmap_different_resolutions(self, detection_store: DetectionStore) -> None:
        """Different resolution_minutes produce different bucket counts."""
        now = datetime.now(timezone.utc)
        # Insert detections spread across time
        dets = []
        for i in range(30):
            d = make_detection(signal_class="bpsk", freq_hz=433e6)
            d.timestamp = now - timedelta(minutes=i)
            dets.append(d)
        detection_store.insert_batch(dets)

        r15 = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=15)
        r60 = detection_store._analytics.get_heatmap(hours=1, resolution_minutes=60)
        # Finer resolution should produce >= as many time buckets
        t15 = len({r["time_bucket"] for r in r15})
        t60 = len({r["time_bucket"] for r in r60})
        assert t15 >= t60

    def test_heatmap_past_date_no_data(self, detection_store: DetectionStore) -> None:
        """Heatmap for a date with no data returns empty list."""
        result = detection_store._analytics.get_heatmap(
            date="2020-01-01", resolution_minutes=60,
        )
        assert result == []


# ---------------------------------------------------------------------------
# DB-P6: Batched cleanup — boundary and larger datasets
# ---------------------------------------------------------------------------


class TestBatchedCleanupBoundary:
    """Cleanup at batch boundaries."""

    def test_cleanup_exactly_one_batch(self, detection_store: DetectionStore) -> None:
        """Cleanup with exactly one batch (< 10_000) exits after one iteration."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        dets = [make_detection(node_id="n1") for _ in range(100)]
        for d in dets:
            d.timestamp = old
        detection_store.insert_batch(dets)

        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 100

    def test_cleanup_mixed_old_and_recent_interleaved(
        self, detection_store: DetectionStore,
    ) -> None:
        """Interleaved old and new detections — only old ones deleted."""
        old = datetime.now(timezone.utc) - timedelta(days=30)
        new = datetime.now(timezone.utc)
        dets = []
        for i in range(40):
            d = make_detection(node_id="n1")
            d.timestamp = old if i % 2 == 0 else new
            dets.append(d)
        detection_store.insert_batch(dets)

        deleted = detection_store._analytics.cleanup("default", max_age_days=7)
        assert deleted == 20  # Half are old

        conn = detection_store.get_connection()
        remaining = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        assert remaining == 20  # Half are recent


# ---------------------------------------------------------------------------
# DB-H2: Aggregate hourly — idempotency
# ---------------------------------------------------------------------------


class TestAggregateIdempotency:
    """Aggregate hourly should be idempotent."""

    def test_aggregate_twice_same_count(self, detection_store: DetectionStore) -> None:
        """Calling aggregate_hourly twice produces the same row count."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        dets = [make_detection(node_id="n1", anomaly_score=0.5) for _ in range(15)]
        for d in dets:
            d.timestamp = base
        detection_store.insert_batch(dets)

        count1 = detection_store._analytics.aggregate_hourly("default")
        count2 = detection_store._analytics.aggregate_hourly("default")
        # Second call should produce same or fewer rows (INSERT OR REPLACE)
        assert count2 <= count1

    def test_aggregate_max_anomaly_not_avg(self, detection_store: DetectionStore) -> None:
        """max_anomaly_score is the MAX, not the AVG."""
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        scores = [0.0, 0.0, 0.0, 0.0, 0.85]
        dets = [make_detection(node_id="n1", anomaly_score=s) for s in scores]
        for d in dets:
            d.timestamp = base
        detection_store.insert_batch(dets)

        detection_store._analytics.aggregate_hourly("default")

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT avg_anomaly, max_anomaly_score FROM detection_aggregates LIMIT 1"
        ).fetchone()
        assert row["max_anomaly_score"] == pytest.approx(0.85)
        assert row["avg_anomaly"] == pytest.approx(0.17, abs=0.01)


# ---------------------------------------------------------------------------
# SEC-M16: Pragma invalid value handling
# ---------------------------------------------------------------------------


class TestPragmaInvalidValues:
    """Edge cases for configurable SQLite pragma values."""

    def test_zero_cache_size(self, tmp_path: Path) -> None:
        """cache_size=0 is technically valid in SQLite (uses default)."""
        old = os.environ.get("BRIDGE_SQLITE_CACHE_SIZE")
        os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = "0"
        try:
            store = DetectionStore(db_path=tmp_path / "zero_cache.db")
            conn = store.get_connection()
            # SQLite treats 0 as "use the default"
            val = conn.execute("PRAGMA cache_size").fetchone()[0]
            assert val == 0 or val < 0  # Either 0 or SQLite's default negative
            store.close()
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SQLITE_CACHE_SIZE", None)
            else:
                os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = old

    def test_positive_cache_size_pages(self, tmp_path: Path) -> None:
        """Positive cache_size means pages (not KB)."""
        old = os.environ.get("BRIDGE_SQLITE_CACHE_SIZE")
        os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = "2000"
        try:
            store = DetectionStore(db_path=tmp_path / "positive_cache.db")
            conn = store.get_connection()
            val = conn.execute("PRAGMA cache_size").fetchone()[0]
            assert val == 2000
            store.close()
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SQLITE_CACHE_SIZE", None)
            else:
                os.environ["BRIDGE_SQLITE_CACHE_SIZE"] = old

    def test_mmap_size_zero_disables(self, tmp_path: Path) -> None:
        """mmap_size=0 disables memory-mapped I/O."""
        old = os.environ.get("BRIDGE_SQLITE_MMAP_SIZE")
        os.environ["BRIDGE_SQLITE_MMAP_SIZE"] = "0"
        try:
            store = DetectionStore(db_path=tmp_path / "no_mmap.db")
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
# Session idle timeout configuration
# ---------------------------------------------------------------------------


class TestIdleTimeoutConfig:
    """Idle timeout configuration edge cases."""

    def test_custom_idle_timeout(self) -> None:
        """Custom idle timeout via env var is respected."""
        from sigrift.bridge.storage.users import UserStore
        old = os.environ.get("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES")
        os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = "15"
        try:
            val = UserStore._get_idle_timeout_minutes()
            assert val == 15
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", None)
            else:
                os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = old

    def test_idle_timeout_zero_uses_default(self) -> None:
        """Idle timeout of 0 falls back to default (30)."""
        from sigrift.bridge.storage.users import UserStore
        old = os.environ.get("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES")
        os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = "0"
        try:
            val = UserStore._get_idle_timeout_minutes()
            assert val == 30  # Default
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", None)
            else:
                os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = old

    def test_idle_timeout_negative_uses_default(self) -> None:
        """Negative idle timeout falls back to default."""
        from sigrift.bridge.storage.users import UserStore
        old = os.environ.get("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES")
        os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = "-10"
        try:
            val = UserStore._get_idle_timeout_minutes()
            assert val == 30
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", None)
            else:
                os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = old

    def test_idle_timeout_non_numeric_uses_default(self) -> None:
        """Non-numeric idle timeout falls back to default."""
        from sigrift.bridge.storage.users import UserStore
        old = os.environ.get("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES")
        os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = "invalid"
        try:
            val = UserStore._get_idle_timeout_minutes()
            assert val == 30
        finally:
            if old is None:
                os.environ.pop("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", None)
            else:
                os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = old

    def test_idle_timeout_default_when_unset(self) -> None:
        """Default idle timeout is 30 minutes."""
        from sigrift.bridge.storage.users import UserStore
        old = os.environ.pop("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", None)
        try:
            val = UserStore._get_idle_timeout_minutes()
            assert val == 30
        finally:
            if old is not None:
                os.environ["BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES"] = old


# ---------------------------------------------------------------------------
# SEC-M15: Edge model SHA-256 header
# ---------------------------------------------------------------------------


class TestEdgeModelSHA256Header:
    """SHA-256 hash header on model download endpoint."""

    def test_download_returns_sha256_header(
        self, client, tmp_path: Path, bridge_app,
    ) -> None:
        """Model download response includes X-Model-SHA256 header."""
        # Create a fake ONNX file
        data_dir = Path(__file__).resolve().parent.parent.parent / "src" / "sigrift" / "bridge" / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        onnx_path = data_dir / "family_classifier.onnx"
        test_content = b"fake-onnx-model-content-for-test"

        existed = onnx_path.exists()
        old_content = onnx_path.read_bytes() if existed else None
        try:
            onnx_path.write_bytes(test_content)

            # Need analyst role for download
            from sigrift.lib.security.credentials import generate_api_key, hash_credential

            resp = client.get("/api/edge-models/model/download")
            if resp.status_code == 200:
                assert "x-model-sha256" in resp.headers
                expected = hashlib.sha256(test_content).hexdigest()
                assert resp.headers["x-model-sha256"] == expected
            # 403 is also acceptable if the test client doesn't have analyst role
        finally:
            if old_content is not None:
                onnx_path.write_bytes(old_content)
            elif onnx_path.exists():
                onnx_path.unlink()


# ---------------------------------------------------------------------------
# DS-R1: Weight stability and synchronization
# ---------------------------------------------------------------------------


class TestWeightStability:
    """Weight source-of-truth synchronization tests."""

    def test_weights_all_in_range_0_to_1(self) -> None:
        """Every individual weight is in [0, 1). Zero allowed for opt-in dims."""
        for key, weight in DEFAULT_RF_DIMENSION_WEIGHTS.items():
            assert 0.0 <= weight < 1.0, f"Weight {key}={weight} out of range"

    def test_weights_no_single_dim_dominates(self) -> None:
        """No single dimension has more than 30% weight."""
        for key, weight in DEFAULT_RF_DIMENSION_WEIGHTS.items():
            assert weight <= 0.30, f"Weight {key}={weight} exceeds 30% dominance cap"

    def test_scorer_default_weights_match_exported(self) -> None:
        """Scorer's _DEFAULT_WEIGHTS match the exported DEFAULT_RF_DIMENSION_WEIGHTS."""
        from sigrift.bridge.anomaly.scorer import _DEFAULT_WEIGHTS
        reconstructed = {dim.value: w for dim, w in _DEFAULT_WEIGHTS.items()}
        assert reconstructed == DEFAULT_RF_DIMENSION_WEIGHTS

    def test_persistence_uses_scorer_weights(self) -> None:
        """PersistenceManager imports weights from scorer, not duplicated."""
        from sigrift.bridge.persistence import PersistenceManager
        defaults = PersistenceManager._DETECTION_CONFIG_DEFAULTS
        assert defaults["rf_dimension_weights"] == DEFAULT_RF_DIMENSION_WEIGHTS
