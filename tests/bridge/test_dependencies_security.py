"""Security-path tests for ``sigrift.bridge.dependencies``.

Complements the existing auth suites (test_auth_session_lifecycle.py,
test_api_key_auth_offload.py, test_key_state_auth.py, test_round3/4/5_*.py,
test_tenant_boundaries.py, test_gateway_cert_trust.py) with the paths they
leave open:

* rate limiting: per-key 429 + ``Retry-After``, the 10/min sensitive bucket,
  stale-key cleanup and eviction, lazy construction from config;
* WebSocket connection limits (per-minute, concurrent, release);
* API-key metadata that must fail closed (unknown role, non-string or
  naive expiry), the verified-key cache bounds, legacy-scan saturation and
  submit failures, the fast-index mismatch fallback and a failed legacy
  re-hash;
* credentials changing between the auth snapshots (index moved, revoked);
* session scope / role names that are unknown or not even text;
* session-expiry headers for naive, past and unparsable expiries;
* a forged client-certificate assertion with a non-ASCII proxy header or
  none at all (HTTP, WebSocket upgrade and revalidation), a non-ASCII
  secret and duplicate proxy headers that disagree;
* trusted-proxy parsing (CIDR, invalid CIDR, literal IPs, host names) and
  client-IP resolution behind fully trusted hops;
* node binding races (re-roled, no longer a node key, removed meanwhile)
  and the 422 for an invalid node id;
* WebSocket revalidation of a session that became restricted, a key with
  no persistence and a vanished certificate assertion.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, HTTPException, Request, WebSocketException
from fastapi.testclient import TestClient
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketDisconnect

import sigrift.bridge.dependencies as deps
from sigrift.bridge.dependencies import Role
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.config import MLRFConfig
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_SECRET = "p3-deps-proxy-secret-0123456789abcdef"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_module_state():
    """Restore every module-level singleton these tests may replace."""
    saved = (
        deps._rate_limiter,
        deps._ws_limiter,
        deps._config_singleton,
        deps._legacy_overflow_warned,
    )
    deps._verified_key_cache.clear()
    deps._cert_mismatch_logged.clear()
    yield
    (
        deps._rate_limiter,
        deps._ws_limiter,
        deps._config_singleton,
        deps._legacy_overflow_warned,
    ) = saved
    deps._verified_key_cache.clear()
    deps._cert_mismatch_logged.clear()


def _add_key(
    persistence: PersistenceManager,
    key_id: str,
    role: Any = "viewer",
    **meta_fields: Any,
) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    meta.update(meta_fields)
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _session(
    store: DetectionStore, username: str, *, role: str = "viewer", scope: str = ""
) -> str:
    if store.users.get_user(username) is None:
        store.create_user(username=username, password="Password123!", role=role)
    user = store.users.get_user(username)
    token = store.create_session(user_id=user["id"])["session_token"]
    if scope:
        store.users.set_session_scope(token, scope=scope)
    return token


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _hashed(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _conn(peer: str = "10.0.0.1", headers: dict[str, str] | None = None) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "client": (peer, 0),
        }
    )


@pytest.fixture
def anon(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


class TestRateLimitDependencies:
    def test_rate_limited_key_gets_429_with_retry_after(
        self, bridge_app, master_key
    ) -> None:
        deps.set_rate_limiter(deps.RateLimiter(max_requests=2, window_seconds=60.0))
        c = TestClient(bridge_app, headers={"X-API-Key": master_key})
        assert c.get("/api/keys/").status_code == 200
        assert c.get("/api/keys/").status_code == 200
        resp = c.get("/api/keys/")
        assert resp.status_code == 429
        assert resp.json() == {"detail": "Rate limit exceeded"}
        assert 1 <= int(resp.headers["Retry-After"]) <= 61

    def test_buckets_are_per_principal(
        self, bridge_app, master_key, persistence
    ) -> None:
        deps.set_rate_limiter(deps.RateLimiter(max_requests=1, window_seconds=60.0))
        viewer = _add_key(persistence, "v1", "viewer")
        master = TestClient(bridge_app, headers={"X-API-Key": master_key})
        other = TestClient(bridge_app, headers={"X-API-Key": viewer})
        assert master.get("/api/keys/").status_code == 200
        assert master.get("/api/keys/").status_code == 429
        assert other.get("/api/keys/").status_code == 200

    def test_sensitive_bucket_refuses_the_eleventh_call(
        self, bridge_app, master_key, persistence
    ) -> None:
        limiter = deps.RateLimiter(max_requests=1000, window_seconds=60.0)
        deps.set_rate_limiter(limiter)
        for _ in range(10):
            limiter.record("sensitive:master")
        c = TestClient(bridge_app, headers={"X-API-Key": master_key})
        resp = c.post("/api/keys/", json={"key_id": "never-created"})
        assert resp.status_code == 429
        assert resp.json() == {"detail": "Rate limit exceeded for sensitive endpoint"}
        assert int(resp.headers["Retry-After"]) >= 1
        assert "never-created" not in persistence.get_key_store()

    def test_lazy_limiter_uses_the_configured_rate(self) -> None:
        cfg = MLRFConfig()
        cfg.security.rate_limit_per_minute = 7
        deps.set_config(cfg)
        deps._rate_limiter = None
        limiter = deps.get_rate_limiter()
        assert limiter.max_requests == 7
        assert deps.get_rate_limiter() is limiter
        assert deps.get_config() is cfg


class TestRateLimiterUnit:
    def test_check_does_not_record_and_reports_retry(self) -> None:
        rl = deps.RateLimiter(max_requests=2, window_seconds=30.0)
        assert rl.check("k") == (True, 0)
        assert rl.is_allowed("k") == (True, 0)
        assert rl.is_allowed("k") == (True, 0)
        allowed, retry = rl.is_allowed("k")
        assert allowed is False
        assert 1 <= retry <= 31
        # A refused request is not recorded (it cannot extend the lockout).
        assert len(rl._requests["k"]) == 2

    def test_reset_one_key_and_all_keys(self) -> None:
        rl = deps.RateLimiter(max_requests=1)
        rl.record("a")
        rl.record("b")
        rl.reset("a")
        assert rl.is_allowed("a")[0] is True
        assert rl.is_allowed("b")[0] is False
        rl.reset("missing")  # no error
        rl.reset()
        assert rl.is_allowed("b")[0] is True

    def test_cleanup_drops_stale_keys_and_evicts_the_oldest(self) -> None:
        rl = deps.RateLimiter(max_requests=10, window_seconds=60.0, max_keys=2)
        now = time.monotonic()
        rl._requests["stale"] = [now - 1000.0]
        rl._requests["empty"] = []
        rl._requests["old"] = [now - 10.0]
        rl._requests["mid"] = [now - 5.0]
        rl._requests["new"] = [now - 1.0]
        rl._last_cleanup = now - 10_000.0
        rl.check("probe")
        # Stale and empty keys are gone; of the live ones only the most
        # recent max_keys survive (plus the probe recreated by the check).
        assert "stale" not in rl._requests
        assert "empty" not in rl._requests
        assert "old" not in rl._requests
        assert {"mid", "new"} <= set(rl._requests)

    def test_cleanup_under_the_key_cap_keeps_live_keys(self) -> None:
        rl = deps.RateLimiter(max_requests=10, window_seconds=60.0, max_keys=100)
        now = time.monotonic()
        rl._requests["stale"] = [now - 1000.0]
        rl._requests["live"] = [now - 1.0]
        rl._last_cleanup = now - 10_000.0
        rl._cleanup_stale()
        assert set(rl._requests) == {"live"}
        assert rl._last_cleanup >= now

    def test_cleanup_is_rate_limited(self) -> None:
        rl = deps.RateLimiter(window_seconds=60.0)
        rl._requests["stale"] = [time.monotonic() - 1000.0]
        rl._last_cleanup = time.monotonic()
        rl._cleanup_stale()
        assert "stale" in rl._requests


class TestWSConnectionLimiter:
    def test_per_minute_limit(self) -> None:
        lim = deps.WSConnectionLimiter(max_concurrent=10, max_per_minute=2)
        assert lim.try_acquire("1.1.1.1") == (True, "")
        lim.release("1.1.1.1")
        assert lim.try_acquire("1.1.1.1") == (True, "")
        lim.release("1.1.1.1")
        assert lim.try_acquire("1.1.1.1") == (
            False,
            "WebSocket connection rate limit exceeded",
        )
        assert lim.try_acquire("2.2.2.2")[0] is True

    def test_concurrent_limit_and_release(self) -> None:
        lim = deps.WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        assert lim.try_acquire("ip")[0] is True
        assert lim.try_acquire("ip") == (
            False,
            "Too many concurrent WebSocket connections",
        )
        lim.release("ip")
        assert "ip" not in lim._active
        lim.release("ip")  # releasing twice never goes negative
        assert "ip" not in lim._active
        assert lim.try_acquire("ip")[0] is True

    def test_lazy_limiter(self) -> None:
        deps.set_ws_limiter(None)
        lim = deps.get_ws_limiter()
        assert isinstance(lim, deps.WSConnectionLimiter)
        assert deps.get_ws_limiter() is lim

    def test_upgrade_over_the_limit_is_closed_1008(
        self, bridge_app, master_key
    ) -> None:
        deps.set_ws_limiter(deps.WSConnectionLimiter(max_concurrent=0))
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", master_key]
            ):
                pass
        assert exc.value.code == 1008

    def test_refused_upgrade_releases_its_slot(self, bridge_app) -> None:
        lim = deps.WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        deps.set_ws_limiter(lim)
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", "bogus"]
            ):
                pass
        assert exc.value.code == 4001
        assert lim._active == {}


# ---------------------------------------------------------------------------
# API-key metadata that must fail closed
# ---------------------------------------------------------------------------


class TestKeyMetadataFailsClosed:
    @pytest.mark.parametrize("role", ["superuser", "", None, 5, ["admin"]], ids=repr)
    def test_unknown_role_is_least_privilege(self, bridge_app, persistence, role):
        raw = _add_key(persistence, "odd-role", role)
        c = TestClient(bridge_app, headers={"X-API-Key": raw})
        me = c.get("/api/auth/me")
        assert me.status_code == 200, me.text
        assert me.json() == {
            "auth_type": "api_key",
            "key_id": "odd-role",
            "role": "viewer",
        }
        assert c.get("/api/admin/users").status_code == 403

    @pytest.mark.parametrize(
        "expires_at",
        ["2000-01-01T00:00:00", 1_700_000_000, ["2999-01-01"], "not-a-date"],
        ids=repr,
    )
    def test_naive_past_or_non_string_expiry_is_refused(
        self, bridge_app, persistence, expires_at
    ) -> None:
        raw = _add_key(persistence, "exp", "admin", expires_at=expires_at)
        resp = TestClient(bridge_app, headers={"X-API-Key": raw}).get("/api/auth/me")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid API key"}

    def test_naive_future_expiry_is_accepted(self, bridge_app, persistence) -> None:
        raw = _add_key(persistence, "exp", "viewer", expires_at="2999-01-01T00:00:00")
        resp = TestClient(bridge_app, headers={"X-API-Key": raw}).get("/api/auth/me")
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "meta, usable",
        [
            ({}, True),
            ({"expires_at": "  "}, True),
            ({"revoked": True}, False),
            ({"revoked": "yes"}, True),  # only a literal True revokes
            ({"enabled": False}, False),
            ({"enabled": 0}, True),  # only a literal False disables
            ({"expires_at": "2000-01-01T00:00:00+00:00"}, False),
        ],
    )
    def test_key_usable_flags(self, meta, usable) -> None:
        assert deps._key_usable(meta) is usable

    def test_master_key_is_admin_whatever_its_metadata(self) -> None:
        assert deps._resolve_key_role("master", {"master": {"role": "viewer"}}) == (
            "master",
            Role.ADMIN,
        )
        assert deps.stored_key_role("master", {"role": "sensor"}) is Role.ADMIN
        assert deps.stored_key_role("k", None) is Role.VIEWER
        # ...but a revoked master record still cannot authenticate.
        assert deps._resolve_key_role("master", {"master": {"revoked": True}}) == (
            None,
            None,
        )


# ---------------------------------------------------------------------------
# Verified-key cache, legacy scans, lookup fallbacks
# ---------------------------------------------------------------------------


class TestVerifiedKeyCacheBounds:
    @pytest.mark.parametrize(
        "raw, ttl", [("", 60.0), ("abc", 60.0), ("-5", 0.0), (" 2.5 ", 2.5)]
    )
    def test_ttl_parsing(self, monkeypatch, raw, ttl) -> None:
        monkeypatch.setenv("BRIDGE_KEY_VERIFY_CACHE_TTL", raw)
        assert deps._VerifiedKeyCache._ttl() == ttl

    def test_a_full_cache_is_cleared_not_grown(self) -> None:
        cache = deps._VerifiedKeyCache()
        cache._MAX_ENTRIES = 2
        cache.put("h1", "k1", "x", b"s")
        cache.put("h2", "k2", "x", b"s")
        cache.put("h3", "k3", "x", b"s")
        assert set(cache._entries) == {"h3"}

    def test_expired_entry_is_dropped(self, monkeypatch) -> None:
        cache = deps._VerifiedKeyCache()
        cache.put("h", "k", "x", b"s")
        store = {"k": ("x", b"s")}
        index = {"h": "k"}
        assert cache.get("h", store, index) == "k"
        key_id, expected, salt, _ = cache._entries["h"]
        cache._entries["h"] = (key_id, expected, salt, time.monotonic() - 1)
        assert cache.get("h", store, index) is None
        assert "h" not in cache._entries


class TestLegacyScanLimits:
    def test_overflow_is_warned_once_and_capped(self, caplog) -> None:
        deps._legacy_overflow_warned = False
        store = {f"k{i}": ("00", b"s") for i in range(deps.MAX_LEGACY_SCAN + 3)}
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            first = deps._legacy_candidates(store, {}, {}, None)
            second = deps._legacy_candidates(store, {}, {}, None)
        assert len(first) == len(second) == deps.MAX_LEGACY_SCAN
        warned = [r for r in caplog.records if "no lookup hash" in r.getMessage()]
        assert len(warned) == 1

    def test_indexed_and_unusable_keys_are_never_scanned(self) -> None:
        store = {"a": ("0", b""), "b": ("0", b""), "c": ("0", b""), "d": ("0", b"")}
        meta = {"c": {"revoked": True}}
        got = deps._legacy_candidates(store, meta, {"h": "a"}, ["b"])
        assert got == ["d"]

    def test_saturated_pool_sheds_without_running_and_logs_once(self, caplog) -> None:
        pool = deps._LegacyScanPool(workers=1, max_pending=0)
        ran: list = []
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            assert pool.try_submit(ran.append, 1) is None
            assert pool.try_submit(ran.append, 2) is None
        assert ran == []
        assert pool._executor is None
        shed = [r for r in caplog.records if "saturated" in r.getMessage()]
        assert len(shed) == 1

    def test_failed_submit_releases_its_slot(self) -> None:
        pool = deps._LegacyScanPool(workers=1, max_pending=1)

        class _Broken:
            def submit(self, *a, **k):
                raise RuntimeError("executor shut down")

        pool._executor = _Broken()
        with pytest.raises(RuntimeError):
            pool.try_submit(print)
        assert pool._pending == 0

    def test_saturated_pool_rejects_an_unknown_key(self, monkeypatch) -> None:
        monkeypatch.setattr(
            deps, "_legacy_scan_pool", deps._LegacyScanPool(1, max_pending=0)
        )
        digest, salt = hash_credential("legacy-secret")
        got = asyncio.run(
            deps._lookup_key_async("legacy-secret", {"legacy": (digest, salt)}, {})
        )
        assert got == (None, None)


class TestLookupFallbacks:
    def test_sync_lookup_refuses_an_unusable_indexed_key_without_pbkdf2(
        self, monkeypatch
    ) -> None:
        calls: list = []
        monkeypatch.setattr(
            deps, "verify_credential", lambda *a: calls.append(a) or True
        )
        lookup = compute_lookup_hash("raw")
        got = deps._lookup_key(
            "raw",
            {"k": ("h", b"s")},
            {"k": {"revoked": True}},
            {lookup: "k"},
        )
        assert got == (None, None)
        assert calls == []

    def test_stale_index_entry_falls_back_to_the_legacy_key(self) -> None:
        raw = generate_api_key(32)
        other_hash, other_salt = hash_credential(generate_api_key(32))
        legacy_hash, legacy_salt = hash_credential(raw)
        store = {
            "indexed": (other_hash, other_salt),
            "legacy": (legacy_hash, legacy_salt),
        }
        index = {compute_lookup_hash(raw): "indexed"}
        meta = {"legacy": {"role": "analyst"}}
        got = asyncio.run(deps._lookup_key_async(raw, store, meta, index, ["indexed"]))
        assert got == ("legacy", Role.ANALYST)

    def test_failed_legacy_rehash_keeps_the_matched_credential(self, caplog) -> None:
        class _Persistence:
            def replace_key_credential(self, *a, **k):
                raise OSError("disk full")

        matched = ("hash", b"salt")
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            got = deps._upgrade_legacy_key(_Persistence(), "k", "raw", matched)
        assert got == matched
        assert any("auto-upgrade" in r.getMessage() for r in caplog.records)

    def test_rehash_lost_to_a_rotation_keeps_the_matched_credential(self) -> None:
        class _Persistence:
            def replace_key_credential(self, *a, **k):
                return None  # the key changed meanwhile

        matched = ("hash", b"salt")
        assert deps._upgrade_legacy_key(_Persistence(), "k", "raw", matched) == matched


class _SnapshotPersistence:
    """Serves a scripted sequence of key-auth snapshots."""

    def __init__(self, snapshots: list[tuple]) -> None:
        self._snapshots = list(snapshots)
        self.calls = 0

    def get_key_auth_snapshot(self):
        snap = self._snapshots[min(self.calls, len(self._snapshots) - 1)]
        self.calls += 1
        return snap


class TestAuthSnapshotsRechecked:
    @pytest.fixture
    def key(self):
        raw = generate_api_key(32)
        digest, salt = hash_credential(raw)
        return raw, (digest, salt), compute_lookup_hash(raw)

    def test_index_moved_to_another_key_meanwhile_is_refused(self, key) -> None:
        raw, cred, lookup = key
        before = ({"k": cred}, {"k": {"role": "admin"}}, {lookup: "k"}, {"k"})
        after = (
            {"k": cred, "other": cred},
            {"k": {"role": "admin"}},
            {lookup: "other"},
            {"k", "other"},
        )
        p = _SnapshotPersistence([before, after])
        assert asyncio.run(deps._authenticate_api_key(raw, p)) == (None, None)

    def test_revoked_between_snapshots_is_refused(self, key) -> None:
        raw, cred, lookup = key
        before = ({"k": cred}, {"k": {"role": "admin"}}, {lookup: "k"}, {"k"})
        after = (
            {"k": cred},
            {"k": {"role": "admin", "revoked": True}},
            {lookup: "k"},
            {"k"},
        )
        p = _SnapshotPersistence([before, after])
        assert asyncio.run(deps._authenticate_api_key(raw, p)) == (None, None)

    def test_role_comes_from_the_latest_snapshot(self, key) -> None:
        raw, cred, lookup = key
        before = ({"k": cred}, {"k": {"role": "admin"}}, {lookup: "k"}, {"k"})
        after = ({"k": cred}, {"k": {"role": "sensor"}}, {lookup: "k"}, {"k"})
        p = _SnapshotPersistence([before, after])
        # No connection: nothing to bind the tenant to, the role still updates.
        assert asyncio.run(deps._authenticate_api_key(raw, p)) == ("k", Role.SENSOR)


# ---------------------------------------------------------------------------
# Sessions: unknown scopes and role names, expiry headers
# ---------------------------------------------------------------------------


class TestSessionScopeAndRole:
    def test_unknown_scope_is_confined_on_dependency_routes(
        self, anon, detection_store
    ) -> None:
        token = _session(detection_store, "odd", role="admin", scope="future_scope")
        auth = _bearer(token)
        resp = anon.get("/api/keys/", headers=auth)
        assert resp.status_code == 403
        assert resp.json() == {
            "detail": "Session is restricted and cannot access this endpoint"
        }
        assert anon.get("/api/auth/me", headers=auth).status_code == 200
        assert anon.post("/api/auth/logout", headers=auth).status_code == 200

    def test_mfa_setup_scope_is_confined(self, anon, detection_store) -> None:
        token = _session(
            detection_store, "pending", role="admin", scope="mfa_setup_only"
        )
        resp = anon.get("/api/keys/", headers=_bearer(token))
        assert resp.status_code == 403
        assert resp.json() == {
            "detail": "MFA setup required before accessing other endpoints"
        }

    @pytest.mark.parametrize(
        "scope, path, allowed",
        [
            ("", "/api/anything", True),
            ("password_change_only", "/api/auth/change-password", True),
            ("password_change_only", "/api/auth/mfa/setup", False),
            ("mfa_setup_only", "/api/auth/mfa/setup", True),
            ("mfa_setup_only", "/api/auth/change-password", False),
            ("mfa_setup_only", "/api/auth/mfaX", False),
            ("other", "/api/auth/logout", True),
            ("other", "/api/auth/mfa/setup", False),
        ],
    )
    def test_session_scope_allows(self, scope, path, allowed) -> None:
        assert deps.session_scope_allows(scope, path) is allowed

    def test_non_text_scope_fails_closed(self, anon, detection_store) -> None:
        token = _session(detection_store, "blob", role="admin", scope="placeholder")
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE sessions SET scope = ? WHERE session_token = ?",
            [b"\x01", _hashed(token)],
        )
        conn.commit()
        resp = anon.get("/api/keys/", headers=_bearer(token))
        assert resp.status_code == 403
        assert anon.get("/api/auth/me", headers=_bearer(token)).status_code == 200

    def test_unknown_stored_role_is_least_privilege(
        self, anon, detection_store
    ) -> None:
        token = _session(detection_store, "rooty", role="admin")
        conn = detection_store.get_connection()
        conn.execute("UPDATE users SET role = 'root' WHERE username = 'rooty'")
        conn.commit()
        auth = _bearer(token)
        assert anon.get("/api/keys/", headers=auth).status_code == 200  # viewer
        resp = anon.get("/api/admin/users", headers=auth)
        assert resp.status_code == 403
        assert resp.json() == {"detail": "Admin role required"}


class TestSessionExpiryHeaders:
    def _patched(self, monkeypatch, store: DetectionStore, expires_at: Any) -> None:
        real = store.get_session

        def _get_session(token: str):
            session = real(token)
            if session is not None:
                session = {**session, "expires_at": expires_at}
            return session

        monkeypatch.setattr(store, "get_session", _get_session)

    def test_naive_expiry_is_read_as_utc(self, anon, detection_store, monkeypatch):
        token = _session(detection_store, "naive")
        soon = (
            datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=120)
        ).isoformat()
        self._patched(monkeypatch, detection_store, soon)
        resp = anon.get("/api/auth/me", headers=_bearer(token))
        assert resp.status_code == 200
        assert 0 < int(resp.headers["X-Session-Expires-In"]) <= 120
        assert resp.headers["X-Session-Warning"] == "expiring-soon"

    def test_past_expiry_reports_zero(self, anon, detection_store, monkeypatch):
        token = _session(detection_store, "past")
        self._patched(monkeypatch, detection_store, "2000-01-01T00:00:00+00:00")
        resp = anon.get("/api/auth/me", headers=_bearer(token))
        assert resp.headers["X-Session-Expires-In"] == "0"
        assert resp.headers["X-Session-Warning"] == "expiring-soon"

    @pytest.mark.parametrize("expires_at", ["garbage", None, 12345])
    def test_unreadable_or_missing_expiry_sends_no_header(
        self, anon, detection_store, monkeypatch, expires_at
    ) -> None:
        token = _session(detection_store, "bad-exp")
        self._patched(monkeypatch, detection_store, expires_at)
        resp = anon.get("/api/auth/me", headers=_bearer(token))
        assert resp.status_code == 200
        assert "X-Session-Expires-In" not in resp.headers
        assert "X-Session-Warning" not in resp.headers


# ---------------------------------------------------------------------------
# require_api_key edge paths
# ---------------------------------------------------------------------------


class TestRequireApiKeyEdges:
    def test_missing_persistence_is_503(self, bridge_app, master_key) -> None:
        bridge_app.state.persistence = None
        resp = TestClient(bridge_app, headers={"X-API-Key": master_key}).get(
            "/api/auth/me"
        )
        assert resp.status_code == 503
        assert resp.json() == {"detail": "Service not ready"}

    def test_production_default_disables_query_param_keys(
        self, bridge_app, master_key, monkeypatch
    ) -> None:
        monkeypatch.delenv("BRIDGE_QUERY_PARAM_AUTH", raising=False)
        monkeypatch.setenv("BRIDGE_ENV", "production")
        resp = TestClient(bridge_app).get(f"/api/auth/me?api_key={master_key}")
        assert resp.status_code == 400
        assert "disabled" in resp.json()["detail"]

    def test_bearer_prefix_is_case_insensitive(self, anon, detection_store) -> None:
        token = _session(detection_store, "casey")
        resp = anon.get("/api/auth/me", headers={"Authorization": f"bEaReR {token}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "casey"

    def test_session_cookie_authenticates(self, bridge_app, detection_store) -> None:
        token = _session(detection_store, "cookie-user")
        c = TestClient(bridge_app, cookies={"session_token": token})
        resp = c.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["username"] == "cookie-user"

    def test_disabled_users_session_falls_back_to_no_credential(
        self, anon, detection_store
    ) -> None:
        token = _session(detection_store, "gone", role="admin")
        conn = detection_store.get_connection()
        conn.execute("UPDATE users SET enabled = 0 WHERE username = 'gone'")
        conn.commit()
        resp = anon.get("/api/auth/me", headers=_bearer(token))
        assert resp.status_code == 401


class TestGatewayCertAssertion:
    def test_missing_identity_or_role_falls_through_to_401(
        self, anon, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        base = {"x-auth-method": "client-cert", "x-rust-proxy": _SECRET}
        for extra in (
            {"x-auth-role": "admin"},
            {"x-auth-key-id": "edge-1"},
            {"x-auth-key-id": "  ", "x-auth-role": "admin"},
        ):
            resp = anon.get("/api/keys/", headers={**base, **extra})
            assert resp.status_code == 401, extra

    def test_valid_assertion_is_scoped_to_its_role(self, anon, monkeypatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        headers = {
            "x-auth-method": "client-cert",
            "x-rust-proxy": _SECRET,
            "x-auth-key-id": "edge-1",
            "x-auth-role": "viewer",
        }
        assert anon.get("/api/keys/", headers=headers).status_code == 200
        assert (
            anon.post("/api/keys/", headers=headers, json={"key_id": "x"}).status_code
            == 403
        )

    def test_non_ascii_proxy_header_is_unauthenticated_not_500(
        self, bridge_app, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        c = TestClient(bridge_app, raise_server_exceptions=False)
        resp = c.get(
            "/api/keys/",
            headers={
                "x-auth-method": "client-cert",
                "x-rust-proxy": b"\xff" + _SECRET.encode(),
                "x-auth-key-id": "attacker",
                "x-auth-role": "admin",
            },
        )
        assert resp.status_code == 401

    def test_non_ascii_proxy_header_on_ws_upgrade_is_4001(
        self, bridge_app, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        lim = deps.WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        deps.set_ws_limiter(lim)
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status",
                headers={
                    "x-auth-method": "client-cert",
                    "x-rust-proxy": b"\xff" + _SECRET.encode(),
                    "x-auth-key-id": "attacker",
                    "x-auth-role": "admin",
                },
            ):
                pass
        assert exc.value.code == 4001
        assert lim._active == {}

    def test_assertion_without_proxy_header_is_not_trusted(
        self, monkeypatch, caplog
    ) -> None:
        # Every copy must match, and all([]) is True: no copy at all must
        # still be a mismatch.
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        conn = _cert_conn([])
        assert deps.rust_proxy_header_valid(conn) is False
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            assert deps._gateway_cert_auth(conn) is None
        assert "x-rust-proxy mismatch" in caplog.text

    def test_assertion_without_proxy_header_is_401(self, anon, monkeypatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        headers = {
            "x-auth-method": "client-cert",
            "x-auth-key-id": "attacker",
            "x-auth-role": "admin",
        }
        assert anon.get("/api/keys/", headers=headers).status_code == 401
        # Control: the same assertion through the gateway is trusted.
        resp = anon.get("/api/keys/", headers={**headers, "x-rust-proxy": _SECRET})
        assert resp.status_code == 200

    def test_assertion_without_proxy_header_on_ws_upgrade_is_4001(
        self, bridge_app, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        lim = deps.WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        deps.set_ws_limiter(lim)
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status",
                headers={
                    "x-auth-method": "client-cert",
                    "x-auth-key-id": "attacker",
                    "x-auth-role": "admin",
                },
            ):
                pass
        assert exc.value.code == 4001
        assert lim._active == {}

    @pytest.mark.parametrize(
        "presented",
        [
            b"\xff" + _SECRET.encode(),
            "é".encode() + _SECRET.encode(),
            _SECRET.encode() + b"\x80",
        ],
    )
    def test_non_ascii_proxy_header_is_a_mismatch(
        self, monkeypatch, caplog, presented
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        conn = _cert_conn([(b"x-rust-proxy", presented)])
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            assert deps._gateway_cert_auth(conn) is None
        assert "x-rust-proxy mismatch" in caplog.text
        assert deps.rust_proxy_header_valid(conn) is False

    def test_non_ascii_secret_matches_only_its_utf8_bytes(self, monkeypatch) -> None:
        # The same encoding as the proxy middleware (UC_PROXY_SECRET.encode()).
        secret = "pröxy-sécret-Ω-0123456789abcdef"
        monkeypatch.setenv("UC_PROXY_SECRET", secret)
        good = _cert_conn([(b"x-rust-proxy", secret.encode())])
        assert deps._gateway_cert_auth(good) == ("edge-1", Role.ADMIN)
        assert deps.rust_proxy_header_valid(good) is True
        ascii_only = _cert_conn([(b"x-rust-proxy", b"proxy-secret-0123456789abcdef")])
        assert deps._gateway_cert_auth(ascii_only) is None
        latin1 = _cert_conn([(b"x-rust-proxy", secret.encode("latin-1", "replace"))])
        assert deps._gateway_cert_auth(latin1) is None

    @pytest.mark.parametrize(
        "values",
        [
            [b"\xff", _SECRET.encode()],
            [_SECRET.encode(), b"forged"],
            [b"forged", _SECRET.encode()],
            [_SECRET.encode(), b""],
        ],
    )
    def test_disagreeing_duplicate_proxy_headers_are_refused(
        self, monkeypatch, values
    ) -> None:
        # The proxy middleware reads the last copy and Starlette the first:
        # copies that disagree must not pass either check.
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        conn = _cert_conn([(b"x-rust-proxy", v) for v in values])
        assert deps.rust_proxy_header_valid(conn) is False
        assert deps._gateway_cert_auth(conn) is None

    def test_repeated_identical_proxy_header_is_accepted(self, monkeypatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        conn = _cert_conn([(b"x-rust-proxy", _SECRET.encode())] * 2)
        assert deps.rust_proxy_header_valid(conn) is True
        assert deps._gateway_cert_auth(conn) == ("edge-1", Role.ADMIN)

    def test_unset_and_default_secret_keep_their_own_warning(
        self, monkeypatch, caplog
    ) -> None:
        for secret in ("", "uppercrust-internal"):
            monkeypatch.setenv("UC_PROXY_SECRET", secret)
            conn = _cert_conn([(b"x-rust-proxy", secret.encode())])
            caplog.clear()
            with caplog.at_level(logging.WARNING, logger=deps.logger.name):
                assert deps._gateway_cert_auth(conn) is None
            assert "UC_PROXY_SECRET is unset or default" in caplog.text
            assert "mismatch" not in caplog.text


def _cert_conn(extra: list[tuple[bytes, bytes]]) -> HTTPConnection:
    """A connection carrying a gateway client-cert assertion plus *extra*."""
    headers = [
        (b"x-auth-method", b"client-cert"),
        (b"x-auth-key-id", b"edge-1"),
        (b"x-auth-role", b"admin"),
        *extra,
    ]
    return HTTPConnection(
        {"type": "http", "method": "GET", "path": "/", "headers": headers}
    )


# ---------------------------------------------------------------------------
# Trusted proxies and the client IP
# ---------------------------------------------------------------------------


@pytest.fixture
def restore():
    """Restore the trusted-proxy configuration a test reloads."""
    saved = (deps._TRUSTED_PROXIES, deps._TRUSTED_PROXY_NETS, deps._TRUSTED_PROXY_HOSTS)
    yield
    (
        deps._TRUSTED_PROXIES,
        deps._TRUSTED_PROXY_NETS,
        deps._TRUSTED_PROXY_HOSTS,
    ) = saved


class TestClientIpOverHttp:
    """The client IP the login limit and session binding see, end to end."""

    def _wrong_login(self, c: TestClient, xff: str | None = None):
        headers = {"X-Forwarded-For": xff} if xff else {}
        return c.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "wrong-password"},
            headers=headers,
        )

    def test_spoofed_forwarded_for_cannot_dodge_the_login_limit(
        self, bridge_app, restore, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "")
        deps.reload_trusted_proxies()
        attacker = TestClient(bridge_app, client=("198.51.100.7", 4000))
        codes = [
            self._wrong_login(attacker, f"203.0.113.{i}").status_code for i in range(7)
        ]
        assert codes[:5] == [401] * 5
        assert codes[5:] == [429, 429]

    def test_clients_behind_a_trusted_proxy_have_their_own_buckets(
        self, bridge_app, restore, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "10.0.0.0/8")
        deps.reload_trusted_proxies()
        gateway = TestClient(bridge_app, client=("10.0.0.2", 4000))
        for _ in range(5):
            assert self._wrong_login(gateway, "203.0.113.1").status_code == 401
        limited = self._wrong_login(gateway, "203.0.113.1")
        assert limited.status_code == 429
        assert limited.headers["Retry-After"] == "60"
        assert self._wrong_login(gateway, "203.0.113.2").status_code == 401
        # The client cannot pick a fresh bucket by prepending addresses: the
        # right-most untrusted hop is what counts.
        spoof = self._wrong_login(gateway, "192.0.2.50, 203.0.113.1")
        assert spoof.status_code == 429

    def test_session_is_bound_to_the_forwarded_client_ip(
        self, bridge_app, detection_store, restore, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "10.0.0.0/8")
        monkeypatch.delenv("BRIDGE_SESSION_BINDING", raising=False)  # "ip"
        deps.reload_trusted_proxies()
        detection_store.create_user(username="ivy", password="Password123!")
        gateway = TestClient(bridge_app, client=("10.0.0.2", 4000))
        login = gateway.post(
            "/api/auth/login",
            json={"username": "ivy", "password": "Password123!"},
            headers={"X-Forwarded-For": "203.0.113.5"},
        )
        assert login.status_code == 200, login.text
        token = login.json()["session_token"]
        assert detection_store.get_session(token)["ip_address"] == "203.0.113.5"

        def me(xff: str):
            return gateway.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": xff},
            ).status_code

        assert me("203.0.113.5") == 200
        assert me("203.0.113.6") == 401  # stolen token from another address
        # Direct from a different, untrusted host: XFF is not believed.
        thief = TestClient(bridge_app, client=("198.51.100.9", 4000))
        resp = thief.get(
            "/api/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Forwarded-For": "203.0.113.5",
            },
        )
        assert resp.status_code == 401
        assert me("203.0.113.5") == 200  # the owner is unaffected


class TestTrustedProxies:
    def test_parsing_ips_cidrs_and_names(self, monkeypatch, caplog) -> None:
        monkeypatch.setattr(
            deps, "_resolve_proxy_host", lambda name: frozenset({"192.0.2.10"})
        )
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            plain, nets, resolver = deps._load_trusted_proxies(
                " 10.0.0.5, ::ffff:10.0.0.6 ,172.29.84.0/28, 300.1.1.1/8, gateway,,"
            )
        assert {"127.0.0.1", "::1", "10.0.0.5", "10.0.0.6"} <= plain
        assert [str(n) for n in nets] == ["172.29.84.0/28"]
        assert any("invalid CIDR" in r.getMessage() for r in caplog.records)
        # "300.1.1.1" is not an IP, so it is a host name for the resolver.
        assert resolver is not None
        assert resolver.hosts == ("gateway",)
        assert resolver.addresses == frozenset({"192.0.2.10"})

    def test_only_listed_networks_are_trusted(self, restore, monkeypatch) -> None:
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "172.29.84.0/28")
        deps.reload_trusted_proxies()
        assert deps._peer_is_trusted("172.29.84.3") is True
        assert deps._peer_is_trusted("172.29.84.17") is False
        assert deps._peer_is_trusted("not-an-ip") is False
        # From a trusted proxy the right-most untrusted hop is the client.
        conn = _conn("172.29.84.3", {"X-Forwarded-For": "6.6.6.6, 203.0.113.9"})
        assert deps.get_client_ip(conn) == "203.0.113.9"
        # From anyone else the header is ignored.
        conn = _conn("198.51.100.1", {"X-Forwarded-For": "203.0.113.9"})
        assert deps.get_client_ip(conn) == "198.51.100.1"

    def test_trusted_peer_without_forwarded_header(self, restore, monkeypatch):
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "")
        deps.reload_trusted_proxies()
        assert deps.get_client_ip(_conn("127.0.0.1")) == "127.0.0.1"
        conn = _conn("127.0.0.1", {"X-Forwarded-For": " , "})
        assert deps.get_client_ip(conn) == "127.0.0.1"

    def test_every_hop_trusted_uses_the_left_end(self, restore, monkeypatch):
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "10.0.0.0/8")
        deps.reload_trusted_proxies()
        conn = _conn("10.0.0.1", {"X-Forwarded-For": "10.1.1.1, 10.2.2.2"})
        assert deps.get_client_ip(conn) == "10.1.1.1"

    def test_missing_client_is_unknown(self) -> None:
        req = Request({"type": "http", "headers": [], "query_string": b""})
        assert deps.get_client_ip(req) == "unknown"


class TestProxyHostResolver:
    def test_recent_attempt_is_not_repeated(self, monkeypatch) -> None:
        calls: list = []
        monkeypatch.setattr(
            deps, "_resolve_proxy_host", lambda n: calls.append(n) or None
        )
        r = deps._ProxyHostResolver(["gw"])
        t = r._refresh_in_background(60.0)
        assert t is not None
        t.join(5)
        assert r._refresh_in_background(60.0) is None
        assert calls == ["gw"]

    def test_failed_background_refresh_is_logged_and_cleared(
        self, monkeypatch, caplog
    ) -> None:
        r = deps._ProxyHostResolver(["gw"])

        def _boom(*a, **k):
            raise RuntimeError("resolver crashed")

        monkeypatch.setattr(r, "resolve", _boom)
        with caplog.at_level(logging.WARNING, logger=deps.logger.name):
            t = r._refresh_in_background(0.0)
            assert t is not None
            t.join(5)
        assert r._refreshing is False
        assert any("refresh failed" in rec.getMessage() for rec in caplog.records)

    def test_stale_trusted_address_triggers_a_refresh(self, monkeypatch) -> None:
        monkeypatch.setattr(
            deps, "_resolve_proxy_host", lambda n: frozenset({"192.0.2.1"})
        )
        r = deps._ProxyHostResolver(["gw"])
        r.resolve()
        r._resolved_at = time.monotonic() - r.REFRESH_SECONDS - 1
        started = threading.Event()
        monkeypatch.setattr(r, "_refresh_in_background", lambda min_age: started.set())
        assert r.is_trusted("192.0.2.1", refresh_on_miss=False) is True
        assert started.is_set()


# ---------------------------------------------------------------------------
# Node binding (K4 / K7b)
# ---------------------------------------------------------------------------


class _NodePersistence:
    """Just enough persistence for the node-binding routines."""

    def __init__(
        self,
        keys: dict[str, dict[str, Any]],
        nodes: tuple[str, ...] = (),
        bind_result: Any = "same",
    ) -> None:
        self._meta = keys
        self._nodes = {n: {} for n in nodes}
        self._bind_result = bind_result
        self.bind_calls: list[tuple] = []

    def get_key_meta(self):
        return self._meta

    def get_key_store(self):
        return {k: ("h", b"s") for k in self._meta}

    def get_nodes(self):
        return self._nodes

    def bind_key_to_node(self, key_id, node_id, holds_node=None):
        self.bind_calls.append((key_id, node_id))
        return node_id if self._bind_result == "same" else self._bind_result


def _node_request(role: Role, persistence: Any) -> Any:
    return SimpleNamespace(
        state=SimpleNamespace(key_role=role),
        app=SimpleNamespace(state=SimpleNamespace(persistence=persistence)),
    )


class TestNodeBindingRaces:
    def test_node_named_key_that_is_not_stored_is_its_node(self) -> None:
        p = _NodePersistence({}, nodes=("edge-1",))
        assert asyncio.run(deps.existing_node_binding(p, "edge-1")) == "edge-1"
        assert p.bind_calls == []

    def test_node_named_key_already_bound_elsewhere_reports_that(self) -> None:
        p = _NodePersistence({"edge-1": {"role": "node"}}, ("edge-1",), "edge-9")
        assert asyncio.run(deps.existing_node_binding(p, "edge-1")) == "edge-9"

    def test_unknown_key_cannot_be_bound(self) -> None:
        p = _NodePersistence({})
        got = asyncio.run(deps.bind_node_key(p, "ghost", "edge-1"))
        assert got.outcome is deps.NodeBindOutcome.UNKNOWN_KEY
        assert p.bind_calls == []

    def test_key_removed_during_bind_is_unknown(self) -> None:
        p = _NodePersistence({"s": {"role": "sensor"}}, bind_result=None)
        got = asyncio.run(deps.bind_node_key(p, "s", "edge-1"))
        assert got.outcome is deps.NodeBindOutcome.UNKNOWN_KEY

    def test_concurrent_bind_elsewhere_is_reported(self) -> None:
        p = _NodePersistence({"s": {"role": "sensor"}}, bind_result="edge-2")
        got = asyncio.run(deps.bind_node_key(p, "s", "edge-1"))
        assert got == deps.NodeKeyBinding(deps.NodeBindOutcome.BOUND, "edge-2")

    def test_missing_persistence_is_503(self) -> None:
        req = _node_request(Role.SENSOR, None)
        with pytest.raises(HTTPException) as exc:
            asyncio.run(deps.enforce_node_binding(req, "s", "edge-1"))
        assert exc.value.status_code == 503

    def test_invalid_node_id_is_422_and_binds_nothing(self) -> None:
        p = _NodePersistence({"s": {"role": "sensor"}})
        req = _node_request(Role.SENSOR, p)
        with pytest.raises(HTTPException) as exc:
            asyncio.run(deps.enforce_node_binding(req, "s", "../etc"))
        assert exc.value.status_code == 422
        assert p.bind_calls == []

    def test_key_re_roled_to_operator_meanwhile_may_act(self, monkeypatch) -> None:
        async def _bind(*a):
            return deps.NodeKeyBinding(deps.NodeBindOutcome.OPERATOR_KEY)

        monkeypatch.setattr(deps, "bind_node_key", _bind)
        req = _node_request(Role.SENSOR, _NodePersistence({"s": {"role": "sensor"}}))
        assert asyncio.run(deps.enforce_node_binding(req, "s", "edge-1")) is None

    @pytest.mark.parametrize(
        "binding, detail",
        [
            (
                deps.NodeKeyBinding(deps.NodeBindOutcome.NOT_NODE_KEY),
                deps.NODE_KEY_REQUIRED,
            ),
            (
                deps.NodeKeyBinding(deps.NodeBindOutcome.BOUND, None),
                "cannot be bound to node 'edge-1'",
            ),
            (
                deps.NodeKeyBinding(deps.NodeBindOutcome.BOUND, "edge-2"),
                "is bound to node 'edge-2'",
            ),
        ],
        ids=["not-node-key", "removed", "bound-elsewhere"],
    )
    def test_races_that_end_in_403(self, monkeypatch, binding, detail) -> None:
        async def _bind(*a):
            return binding

        monkeypatch.setattr(deps, "bind_node_key", _bind)
        req = _node_request(Role.NODE, _NodePersistence({"s": {"role": "node"}}))
        with pytest.raises(HTTPException) as exc:
            asyncio.run(deps.enforce_node_binding(req, "s", "edge-1"))
        assert exc.value.status_code == 403
        assert detail in exc.value.detail

    def test_mismatch_log_map_is_bounded(self, monkeypatch) -> None:
        monkeypatch.setattr(deps, "_CERT_MISMATCH_LOG_MAX", 1)
        deps._log_cert_node_mismatch("a", "n1")
        deps._log_cert_node_mismatch("b", "n2")
        assert list(deps._cert_mismatch_logged) == [("b", "n2")]


# ---------------------------------------------------------------------------
# WebSocket auth and revalidation
# ---------------------------------------------------------------------------


def _ws(app: Any, headers: dict[str, str] | None = None):
    from fastapi import WebSocket

    async def _receive():
        return {"type": "websocket.connect"}

    async def _send(message):
        return None

    return WebSocket(
        {
            "type": "websocket",
            "app": app,
            "path": "/ws",
            "headers": [
                (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
            ],
            "query_string": b"",
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send,
    )


class TestWebSocketRevalidation:
    def test_upgrade_with_no_persistence_is_4001(self, bridge_app, master_key):
        bridge_app.state.persistence = None
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status", headers={"X-API-Key": master_key}
            ):
                pass
        assert exc.value.code == 4001

    def test_session_restricted_after_upgrade_is_4003(
        self, bridge_app, detection_store
    ) -> None:
        token = _session(detection_store, "streamer")
        user = f"user:{detection_store.users.get_user('streamer')['username']}"
        detection_store.users.set_session_scope(token, scope="password_change_only")
        ws = _ws(bridge_app)
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("session", token, user), Role.VIEWER)
            )
        assert exc.value.code == 4003

    def test_session_for_another_principal_is_4003(
        self, bridge_app, detection_store
    ) -> None:
        token = _session(detection_store, "streamer")
        ws = _ws(bridge_app)
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(
                    ws, ("session", token, "user:someone-else"), Role.VIEWER
                )
            )
        assert exc.value.code == 4003

    def test_session_downgraded_below_min_role_is_4003(
        self, bridge_app, detection_store
    ) -> None:
        token = _session(detection_store, "streamer", role="viewer")
        ws = _ws(bridge_app)
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(
                    ws, ("session", token, "user:streamer"), Role.ADMIN
                )
            )
        assert exc.value.code == 4003
        assert exc.value.reason == "Role is no longer permitted"

    def test_api_key_without_persistence_is_4001(self) -> None:
        app = SimpleNamespace(state=SimpleNamespace(persistence=None))
        ws = _ws(app)
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("api_key", "raw", "k"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_certificate_assertion_gone_is_4001(self, monkeypatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        app = SimpleNamespace(state=SimpleNamespace())
        ws = _ws(app, {"x-auth-method": "client-cert", "x-rust-proxy": "wrong"})
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("cert", "", "cert:e1"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_certificate_assertion_without_proxy_header_is_4001(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        app = SimpleNamespace(state=SimpleNamespace())
        ws = _ws(
            app,
            {
                "x-auth-method": "client-cert",
                "x-auth-key-id": "e1",
                "x-auth-role": "admin",
            },
        )
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("cert", "", "cert:e1"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_certificate_assertion_with_non_ascii_proxy_header_is_4001(
        self, monkeypatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        app = SimpleNamespace(state=SimpleNamespace())
        ws = _ws(
            app,
            {
                "x-auth-method": "client-cert",
                "x-rust-proxy": "é" + _SECRET,
                "x-auth-key-id": "e1",
                "x-auth-role": "admin",
            },
        )
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("cert", "", "cert:e1"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_certificate_identity_changed_is_4001(self, monkeypatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        app = SimpleNamespace(state=SimpleNamespace())
        ws = _ws(
            app,
            {
                "x-auth-method": "client-cert",
                "x-rust-proxy": _SECRET,
                "x-auth-key-id": "e2",
                "x-auth-role": "admin",
            },
        )
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("cert", "", "cert:e1"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_certificate_assertion_raised_to_keymaster_is_4001(
        self, monkeypatch
    ) -> None:
        # KEYMASTER is never delegated to a certificate: an assertion that
        # carries it is no assertion, even with the proxy secret.
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        app = SimpleNamespace(state=SimpleNamespace())
        ws = _ws(
            app,
            {
                "x-auth-method": "client-cert",
                "x-rust-proxy": _SECRET,
                "x-auth-key-id": "e1",
                "x-auth-role": "keymaster",
            },
        )
        with pytest.raises(WebSocketException) as exc:
            asyncio.run(
                deps._revalidate_ws_principal(ws, ("cert", "", "cert:e1"), Role.VIEWER)
            )
        assert exc.value.code == 4001

    def test_refused_payload_is_never_sent_even_if_close_fails(self) -> None:
        sent: list = []

        async def _send(message):
            if message["type"] == "websocket.close":
                raise RuntimeError("peer already gone")
            sent.append(message)

        ws = SimpleNamespace(
            state=SimpleNamespace(ws_winning_credential=("cert", "", "cert:e1")),
            headers={},
            send=_send,
        )
        deps._guard_ws_payloads(ws, Role.VIEWER)

        async def _go():
            with pytest.raises(WebSocketDisconnect) as first:
                await ws.send({"type": "websocket.send", "text": "secret"})
            with pytest.raises(WebSocketDisconnect) as second:
                await ws.send({"type": "websocket.send", "text": "secret-2"})
            return first.value.code, second.value.code

        assert asyncio.run(_go()) == (4001, 4003)
        assert sent == []

    @pytest.mark.parametrize(
        "raw, expected", [("", 0.0), ("nan", 1.0), ("x", 1.0), ("99", 30.0)]
    )
    def test_revalidate_interval_bounds(self, monkeypatch, raw, expected) -> None:
        monkeypatch.setenv("BRIDGE_WS_REVALIDATE_SECONDS", raw)
        if raw == "":
            # An empty value is not a number: the default applies.
            expected = 1.0
        assert deps._ws_revalidate_interval() == expected


# ---------------------------------------------------------------------------
# Tenant helpers
# ---------------------------------------------------------------------------


class TestTenantHelpers:
    def test_ws_tenant_mismatch_is_4003(self) -> None:
        conn = HTTPConnection(
            {
                "type": "websocket",
                "app": SimpleNamespace(state=SimpleNamespace(detection_store=None)),
                "headers": [],
            }
        )
        with pytest.raises(WebSocketException) as exc:
            deps.require_instance_tenant(conn, "other")
        assert exc.value.code == 4003

    @pytest.mark.parametrize("tenant", [None, "", 3])
    def test_malformed_tenant_is_refused(self, tenant) -> None:
        conn = HTTPConnection(
            {
                "type": "http",
                "app": SimpleNamespace(state=SimpleNamespace(detection_store=None)),
                "headers": [],
            }
        )
        with pytest.raises(HTTPException) as exc:
            deps.require_instance_tenant(conn, tenant)
        assert exc.value.status_code == 403
