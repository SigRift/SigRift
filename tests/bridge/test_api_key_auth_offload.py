"""PBKDF2 credential checks stay off the event loop and off unknown keys.

The 600k-iteration PBKDF2 check used to run synchronously inside the
``async def`` auth dependencies (HTTP API key, WebSocket) and the login
handler, stalling every other request for ~0.3 s per check.  An unknown key
also triggered a PBKDF2 scan over *every* stored key.
"""

from __future__ import annotations

import asyncio
import os
import threading
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
from sigrift.bridge.dependencies import Role, _lookup_key
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.users import UserStore
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
    verify_credential,
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


class _CountingVerify:
    """Wraps verify_credential, recording calls and the calling thread."""

    def __init__(self) -> None:
        self.calls = 0
        self.on_event_loop: list[bool] = []

    def __call__(self, credential, expected_hash, salt):
        self.calls += 1
        try:
            asyncio.get_running_loop()
            self.on_event_loop.append(True)
        except RuntimeError:
            self.on_event_loop.append(False)
        return verify_credential(credential, expected_hash, salt)


def _keys(n: int, *, indexed: bool = True):
    raw = {f"k{i}": generate_api_key(32) for i in range(n)}
    store, index = {}, {}
    for kid, key in raw.items():
        store[kid] = hash_credential(key)
        if indexed:
            index[compute_lookup_hash(key)] = kid
    return raw, store, index


class TestLookupKey:
    def test_unknown_key_skips_pbkdf2_when_all_keys_indexed(self):
        _, store, index = _keys(5)
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key("not-a-real-key", store, {}, index) == (None, None)
        assert counter.calls == 0

    def test_unknown_key_only_scans_unindexed_keys(self):
        _, store, index = _keys(4)
        legacy_raw = generate_api_key(32)
        store["legacy"] = hash_credential(legacy_raw)  # no lookup hash
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key("not-a-real-key", store, {}, index) == (None, None)
            assert counter.calls == 1
            # The legacy key itself is still found via the slow path.
            assert _lookup_key(legacy_raw, store, {}, index)[0] == "legacy"

    def test_known_key_found_via_index(self):
        raw, store, index = _keys(3)
        meta = {"k1": {"role": "analyst"}}
        assert _lookup_key(raw["k1"], store, meta, index) == ("k1", Role.ANALYST)

    def test_stale_index_entry_does_not_trigger_full_scan(self):
        raw, store, index = _keys(5)
        # k0 was re-keyed but its old lookup hash still points at it.
        store["k0"] = hash_credential(generate_api_key(32))
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key(raw["k0"], store, {}, index) == (None, None)
        assert counter.calls == 1

    def test_success_is_cached(self):
        raw, store, index = _keys(2)
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            for _ in range(3):
                assert _lookup_key(raw["k0"], store, {}, index)[0] == "k0"
        assert counter.calls == 1

    def test_cache_disabled_with_zero_ttl(self):
        raw, store, index = _keys(1)
        counter = _CountingVerify()
        with (
            patch.dict(os.environ, {"BRIDGE_KEY_VERIFY_CACHE_TTL": "0"}),
            patch.object(deps, "verify_credential", counter),
        ):
            _lookup_key(raw["k0"], store, {}, index)
            _lookup_key(raw["k0"], store, {}, index)
        assert counter.calls == 2

    def test_cache_invalidated_by_rotation(self):
        raw, store, index = _keys(1)
        assert _lookup_key(raw["k0"], store, {}, index)[0] == "k0"
        # Rotate: new credential, new hash/salt, new lookup hash.
        new_raw = generate_api_key(32)
        store["k0"] = hash_credential(new_raw)
        index = {compute_lookup_hash(new_raw): "k0"}
        assert _lookup_key(raw["k0"], store, {}, index) == (None, None)
        assert _lookup_key(new_raw, store, {}, index)[0] == "k0"

    def test_cache_invalidated_by_removal(self):
        raw, store, index = _keys(2)
        assert _lookup_key(raw["k0"], store, {}, index)[0] == "k0"
        del store["k0"]
        assert _lookup_key(raw["k0"], store, {}, index) == (None, None)

    def test_cached_key_still_checks_expiry(self):
        raw, store, index = _keys(1)
        assert _lookup_key(raw["k0"], store, {}, index)[0] == "k0"
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        meta = {"k0": {"role": "viewer", "expires_at": past}}
        assert _lookup_key(raw["k0"], store, meta, index) == (None, None)


class TestPersistenceIndexHygiene:
    def test_remove_key_drops_index_entry(self, persistence):
        raw = generate_api_key(32)
        h, s = hash_credential(raw)
        persistence.set_key("k", h, s, lookup_hash=compute_lookup_hash(raw))
        assert "k" in persistence.get_key_fast_index().values()
        persistence.remove_key("k")
        assert "k" not in persistence.get_key_fast_index().values()

    def test_set_key_without_lookup_drops_stale_entry(self, persistence):
        raw = generate_api_key(32)
        h, s = hash_credential(raw)
        persistence.set_key("k", h, s, lookup_hash=compute_lookup_hash(raw))
        new_raw = generate_api_key(32)
        h2, s2 = hash_credential(new_raw)
        persistence.set_key("k", h2, s2)
        assert "k" not in persistence.get_key_fast_index().values()
        # The new credential is found (via the unindexed slow path).
        key_id, _ = _lookup_key(
            new_raw,
            persistence.get_key_store(),
            persistence.get_key_meta(),
            persistence.get_key_fast_index(),
        )
        assert key_id == "k"


class TestOffEventLoop:
    def test_http_api_key_check_runs_in_worker_thread(
        self, bridge_app: FastAPI, master_key: str
    ):
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            client = TestClient(bridge_app)
            resp = client.get("/api/nodes", headers={"X-API-Key": master_key})
        assert resp.status_code == 200
        assert counter.calls >= 1
        assert not any(counter.on_event_loop)

    def test_invalid_api_key_rejected(self, bridge_app: FastAPI):
        client = TestClient(bridge_app)
        resp = client.get("/api/nodes", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401

    def test_websocket_api_key_check_runs_in_worker_thread(
        self, bridge_app: FastAPI, master_key: str
    ):
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            client = TestClient(bridge_app)
            with client.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", master_key]
            ) as ws:
                assert ws.receive_json()["type"] == "snapshot"
        assert counter.calls >= 1
        assert not any(counter.on_event_loop)

    def test_login_password_check_runs_in_worker_thread(
        self, bridge_app: FastAPI, detection_store
    ):
        detection_store.create_user("offloop", "OffLoopPass123!", role="viewer")
        import sigrift.bridge.storage.users as users_mod

        counter = _CountingVerify()
        with patch.object(users_mod, "verify_credential", counter):
            client = TestClient(bridge_app)
            resp = client.post(
                "/api/auth/login",
                json={"username": "offloop", "password": "OffLoopPass123!"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.json()["session_token"]
        assert counter.calls == 1
        assert counter.on_event_loop == [False]


class TestBackupCodes:
    def test_pbkdf2_runs_without_write_lock_and_code_is_single_use(self, tmp_path):
        import sigrift.bridge.storage.users as users_mod

        ctx = SharedContext(db_path=tmp_path / "codes.db")
        users = UserStore(ctx)
        users.create_user("coder", "Password123!", role="viewer")
        uid = users.get_user("coder")["id"]
        codes = ["aaaa-1111", "bbbb-2222"]
        users.store_backup_codes(uid, [hash_credential(c) for c in codes])

        lock_held: list[bool] = []

        def _verify(credential, expected_hash, salt):
            got = ctx.write_lock.acquire(blocking=False)
            if got:
                ctx.write_lock.release()
            lock_held.append(not got)
            return verify_credential(credential, expected_hash, salt)

        with patch.object(users_mod, "verify_credential", _verify):
            assert users.verify_backup_code(uid, "bbbb-2222") is True
        assert lock_held and not any(lock_held)

        # Single use, including under concurrent attempts.
        assert users.verify_backup_code(uid, "bbbb-2222") is False
        results: list[bool] = []
        threads = [
            threading.Thread(
                target=lambda: results.append(users.verify_backup_code(uid, "aaaa-1111"))
            )
            for _ in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert results.count(True) == 1
        assert users.get_backup_code_count(uid) == 0
        ctx.close()
