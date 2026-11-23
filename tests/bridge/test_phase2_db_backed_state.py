"""Tests for Phase 2: Single-process state → DB-backed (D-10, TD-1, TD-2, TD-3).

D-10: Login rate limit counters persisted in SQLite
TD-1: Account lockout counters persisted in SQLite
TD-2: OIDC auth states persisted in SQLite
TD-3: TOTP replay cache persisted in SQLite
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.security_state import SecurityStateStore

#: The longest UC_LOCKOUT_WINDOW the gateway accepts (its
#: MAX_LOCKOUT_WINDOW_SECS). The gateway counts the bridge-owned
#: account_lockout table with that window.
GATEWAY_MAX_LOCKOUT_WINDOW = 86400
_GATEWAY_SECURITY_STATE = (
    Path(__file__).resolve().parents[2]
    / "src/gateway/crates/sigrift-gateway-core/src/storage/security_state.rs"
)


# ---------------------------------------------------------------------------
# D-10: Login rate limiting — DB-backed
# ---------------------------------------------------------------------------


class TestDBLoginRateLimit:
    """D-10: Login rate limit counters survive process restart."""

    def test_record_and_count_attempts(self, detection_store):
        sec = detection_store.security_state
        ip = "10.0.0.1"
        sec.record_login_attempt(ip)
        sec.record_login_attempt(ip)
        assert sec.count_recent_login_attempts(ip) == 2

    def test_different_ips_independent(self, detection_store):
        sec = detection_store.security_state
        sec.record_login_attempt("10.0.0.1")
        sec.record_login_attempt("10.0.0.1")
        sec.record_login_attempt("10.0.0.2")
        assert sec.count_recent_login_attempts("10.0.0.1") == 2
        assert sec.count_recent_login_attempts("10.0.0.2") == 1

    def test_expired_attempts_not_counted(self, detection_store):
        """Attempts older than the window are not counted."""
        sec = detection_store.security_state
        ip = "10.0.0.3"

        # Insert an old attempt directly
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.RATE_LIMIT_WINDOW - 10
        conn.execute(
            "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) "
            "VALUES (?, ?, ?)",
            [ip, old_ts, "default"],
        )
        conn.commit()

        assert sec.count_recent_login_attempts(ip) == 0

    def test_cleanup_removes_old_entries(self, detection_store):
        """cleanup_login_attempts removes expired entries."""
        sec = detection_store.security_state
        ip = "10.0.0.4"

        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.RATE_LIMIT_WINDOW - 10
        conn.execute(
            "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) "
            "VALUES (?, ?, ?)",
            [ip, old_ts, "default"],
        )
        conn.commit()

        deleted = sec.cleanup_login_attempts()
        assert isinstance(deleted, int)
        assert deleted >= 1

    def test_rate_limit_enforced_via_router(self, client):
        """Login endpoint returns 429 after too many attempts."""
        # Make max+1 login attempts with bad credentials
        for i in range(6):
            resp = client.post("/api/auth/login", json={
                "username": "nonexistent", "password": "wrong",
            })
            if resp.status_code == 429:
                assert "Too many" in resp.json()["detail"]
                return
        # If we get here, the rate limit wasn't triggered within 6 attempts
        # (some may have been 401s) — verify we got at least one 429
        resp = client.post("/api/auth/login", json={
            "username": "nonexistent", "password": "wrong",
        })
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# TD-1: Account lockout — DB-backed
# ---------------------------------------------------------------------------


class TestDBAccountLockout:
    """TD-1: Account lockout counters survive process restart."""

    def test_record_and_count_failures(self, detection_store):
        sec = detection_store.security_state
        sec.record_account_failure("testuser")
        sec.record_account_failure("testuser")
        assert sec.count_recent_failures("testuser") == 2

    def test_clear_failures(self, detection_store):
        sec = detection_store.security_state
        sec.record_account_failure("clearme")
        sec.record_account_failure("clearme")
        assert sec.count_recent_failures("clearme") == 2

        sec.clear_account_failures("clearme")
        assert sec.count_recent_failures("clearme") == 0

    def test_expired_failures_not_counted(self, detection_store):
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.LOCKOUT_WINDOW - 10
        conn.execute(
            "INSERT INTO account_lockout (username, failure_at, tenant_id) "
            "VALUES (?, ?, ?)",
            ["expired_user", old_ts, "default"],
        )
        conn.commit()
        assert sec.count_recent_failures("expired_user") == 0

    def test_lockout_threshold(self, detection_store):
        """After LOCKOUT_MAX failures, user is locked out."""
        sec = detection_store.security_state
        username = "lockout_test"
        for _ in range(sec.LOCKOUT_MAX):
            sec.record_account_failure(username)
        assert sec.count_recent_failures(username) == sec.LOCKOUT_MAX

    def test_cleanup_keeps_failures_a_longer_gateway_window_counts(
        self, detection_store
    ):
        """The gateway counts this table with UC_LOCKOUT_WINDOW (up to 24 h).

        Regression: the bridge's periodic cleanup deleted every failure
        older than its own 30-minute window, so with UC_LOCKOUT_WINDOW=86400
        a locked account was unlocked by the next cleanup (about 10 guesses
        every 30 to 60 minutes instead of 10 a day).
        """
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        now = time.time()
        aged = now - sec.LOCKOUT_WINDOW - 60  # outside the bridge's window
        for _ in range(sec.LOCKOUT_MAX):
            conn.execute(
                "INSERT INTO account_lockout (username, failure_at, tenant_id) "
                "VALUES (?, ?, ?)",
                ["alice", aged, "default"],
            )
        conn.execute(
            "INSERT INTO account_lockout (username, failure_at, tenant_id) "
            "VALUES (?, ?, ?)",
            ["stale", now - GATEWAY_MAX_LOCKOUT_WINDOW - 10, "default"],
        )
        conn.commit()

        sec.cleanup_all()

        def gateway_count(username: str) -> int:
            # The gateway's reserve_account_attempt count, longest window.
            return conn.execute(
                "SELECT COUNT(*) FROM account_lockout "
                "WHERE username = ? AND failure_at > ? AND tenant_id = ?",
                [username, now - GATEWAY_MAX_LOCKOUT_WINDOW, "default"],
            ).fetchone()[0]

        assert gateway_count("alice") == sec.LOCKOUT_MAX  # still locked there
        assert conn.execute(
            "SELECT COUNT(*) FROM account_lockout WHERE username = 'stale'"
        ).fetchone()[0] == 0  # counted by no window: pruned
        # The bridge's own lockout still uses its 30-minute window.
        assert sec.count_recent_failures("alice") == 0

    def test_retention_covers_the_longest_gateway_lockout_window(self):
        """The gateway refuses a UC_LOCKOUT_WINDOW the bridge would prune.

        Its ``MAX_LOCKOUT_WINDOW_SECS`` (read from the gateway's source) must
        not exceed what the bridge's cleanup keeps.
        """
        source = _GATEWAY_SECURITY_STATE.read_text(encoding="utf-8")
        match = re.search(r"pub const MAX_LOCKOUT_WINDOW_SECS: u64 = ([\d_]+);", source)
        assert match, f"MAX_LOCKOUT_WINDOW_SECS not found in {_GATEWAY_SECURITY_STATE}"
        gateway_max = int(match.group(1).replace("_", ""))
        assert gateway_max == GATEWAY_MAX_LOCKOUT_WINDOW
        assert SecurityStateStore.LOCKOUT_RETENTION >= gateway_max
        assert SecurityStateStore.LOCKOUT_RETENTION >= SecurityStateStore.LOCKOUT_WINDOW

    def test_cleanup_removes_old_lockout_entries(self, detection_store):
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - GATEWAY_MAX_LOCKOUT_WINDOW - 10
        conn.execute(
            "INSERT INTO account_lockout (username, failure_at, tenant_id) "
            "VALUES (?, ?, ?)",
            ["old_lockout", old_ts, "default"],
        )
        conn.commit()
        deleted = sec.cleanup_account_lockout()
        assert isinstance(deleted, int)
        assert deleted >= 1

    def test_lockout_enforced_via_router(self, client, detection_store):
        """Login endpoint returns 429 when account is locked."""
        sec = detection_store.security_state
        username = "locked_user"
        # Pre-load failures directly
        for _ in range(sec.LOCKOUT_MAX):
            sec.record_account_failure(username)

        resp = client.post("/api/auth/login", json={
            "username": username, "password": "anything",
        })
        assert resp.status_code == 429
        assert "locked" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# TD-2: OIDC state — DB-backed
# ---------------------------------------------------------------------------


class TestDBOIDCState:
    """TD-2: OIDC authorization states survive process restart."""

    def test_create_and_consume_state(self, detection_store):
        sec = detection_store.security_state
        sec.create_oidc_state("state-1", "nonce-1", "/dashboard")

        data = sec.consume_oidc_state("state-1")
        assert isinstance(data, dict)
        assert isinstance(data["nonce"], str)
        assert data["nonce"] == "nonce-1"
        assert isinstance(data["redirect_to"], str)
        assert data["redirect_to"] == "/dashboard"

    def test_consume_removes_state(self, detection_store):
        sec = detection_store.security_state
        sec.create_oidc_state("state-2", "nonce-2")

        data1 = sec.consume_oidc_state("state-2")
        assert isinstance(data1, dict) and data1["nonce"] == "nonce-2"

        data2 = sec.consume_oidc_state("state-2")
        assert data2 is None  # Already consumed

    def test_nonexistent_state_returns_none(self, detection_store):
        sec = detection_store.security_state
        assert sec.consume_oidc_state("nonexistent") is None

    def test_expired_state_returns_none(self, detection_store):
        sec = detection_store.security_state

        # Insert an expired state directly
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.OIDC_STATE_MAX_AGE - 10
        conn.execute(
            "INSERT INTO oidc_states (state, nonce, redirect_to, created_at, tenant_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["expired-state", "n", "/", old_ts, "default"],
        )
        conn.commit()

        assert sec.consume_oidc_state("expired-state") is None

    def test_cleanup_removes_expired(self, detection_store):
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.OIDC_STATE_MAX_AGE - 10
        conn.execute(
            "INSERT INTO oidc_states (state, nonce, redirect_to, created_at, tenant_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ["old-state", "n", "/", old_ts, "default"],
        )
        conn.commit()

        deleted = sec.cleanup_oidc_states()
        assert isinstance(deleted, int)
        assert deleted >= 1


# ---------------------------------------------------------------------------
# TD-3: TOTP replay cache — DB-backed
# ---------------------------------------------------------------------------


class TestDBTOTPReplay:
    """TD-3: TOTP replay cache survives process restart."""

    def test_new_code_not_reused(self, detection_store):
        sec = detection_store.security_state
        assert sec.is_totp_reused("user1", "123456") is False

    def test_used_code_is_reused(self, detection_store):
        sec = detection_store.security_state
        sec.record_totp_use("user2", "654321")
        assert sec.is_totp_reused("user2", "654321") is True

    def test_different_users_independent(self, detection_store):
        sec = detection_store.security_state
        sec.record_totp_use("userA", "111111")
        assert sec.is_totp_reused("userA", "111111") is True
        assert sec.is_totp_reused("userB", "111111") is False

    def test_expired_code_not_reused(self, detection_store):
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.TOTP_REUSE_TTL - 10
        conn.execute(
            "INSERT INTO totp_replay_cache (username, totp_code, used_at, tenant_id) "
            "VALUES (?, ?, ?, ?)",
            ["expired_user", "999999", old_ts, "default"],
        )
        conn.commit()
        assert sec.is_totp_reused("expired_user", "999999") is False

    def test_cleanup_removes_old_entries(self, detection_store):
        sec = detection_store.security_state
        conn = detection_store._ctx.get_conn()
        old_ts = time.time() - sec.TOTP_REUSE_TTL - 10
        conn.execute(
            "INSERT INTO totp_replay_cache (username, totp_code, used_at, tenant_id) "
            "VALUES (?, ?, ?, ?)",
            ["cleanup_user", "000000", old_ts, "default"],
        )
        conn.commit()
        deleted = sec.cleanup_totp_replay()
        assert isinstance(deleted, int)
        assert deleted >= 1


# ---------------------------------------------------------------------------
# Combined cleanup
# ---------------------------------------------------------------------------


class TestSecurityStateCleanup:
    """Combined security state cleanup."""

    def test_cleanup_all(self, detection_store):
        sec = detection_store.security_state
        result = sec.cleanup_all()
        assert isinstance(result["login_attempts"], int) and result["login_attempts"] >= 0
        assert isinstance(result["account_lockout"], int) and result["account_lockout"] >= 0
        assert isinstance(result["oidc_states"], int) and result["oidc_states"] >= 0
        assert isinstance(result["totp_replay"], int) and result["totp_replay"] >= 0


# ---------------------------------------------------------------------------
# Multi-tenant isolation
# ---------------------------------------------------------------------------


class TestMultiTenantIsolation:
    """Verify tenant_id scoping prevents cross-tenant data leakage."""

    @pytest.fixture
    def tenant_stores(self, tmp_path):
        db_path = str(tmp_path / "multi_tenant.db")
        ctx_a = SharedContext(db_path=db_path, tenant_id="tenant_a")
        ctx_b = SharedContext(db_path=db_path, tenant_id="tenant_b")
        return SecurityStateStore(ctx_a), SecurityStateStore(ctx_b)

    def test_login_attempts_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        ip = "192.168.1.1"
        store_a.record_login_attempt(ip)
        store_a.record_login_attempt(ip)
        store_b.record_login_attempt(ip)

        assert store_a.count_recent_login_attempts(ip) == 2
        assert store_b.count_recent_login_attempts(ip) == 1

    def test_account_failures_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        username = "shared_user"
        store_a.record_account_failure(username)
        store_a.record_account_failure(username)
        store_a.record_account_failure(username)
        store_b.record_account_failure(username)

        assert store_a.count_recent_failures(username) == 3
        assert store_b.count_recent_failures(username) == 1

    def test_clear_failures_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        username = "cleartest"
        store_a.record_account_failure(username)
        store_b.record_account_failure(username)

        store_a.clear_account_failures(username)
        assert store_a.count_recent_failures(username) == 0
        assert store_b.count_recent_failures(username) == 1

    def test_oidc_state_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        store_a.create_oidc_state("shared-state", "nonce-a", "/a")

        # Tenant B cannot consume tenant A's state
        assert store_b.consume_oidc_state("shared-state") is None
        # Tenant A can still consume its own state
        data = store_a.consume_oidc_state("shared-state")
        assert isinstance(data, dict)
        assert data["nonce"] == "nonce-a"

    def test_totp_replay_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        store_a.record_totp_use("user1", "123456")

        assert store_a.is_totp_reused("user1", "123456") is True
        assert store_b.is_totp_reused("user1", "123456") is False

    def test_cleanup_isolated(self, tenant_stores):
        store_a, store_b = tenant_stores
        ip = "10.0.0.99"

        # Insert old entries for both tenants directly
        conn = store_a._ctx.get_conn()
        old_ts = time.time() - store_a.RATE_LIMIT_WINDOW - 10
        conn.execute(
            "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) "
            "VALUES (?, ?, ?)",
            [ip, old_ts, "tenant_a"],
        )
        conn.execute(
            "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) "
            "VALUES (?, ?, ?)",
            [ip, old_ts, "tenant_b"],
        )
        conn.commit()

        # Cleanup tenant A only
        deleted = store_a.cleanup_login_attempts()
        assert deleted == 1

        # Tenant B's expired entry still exists (not cleaned by tenant A)
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM rate_limit_login "
            "WHERE tenant_id = 'tenant_b'",
        ).fetchone()
        assert row["cnt"] == 1
