"""API-key store integrity: one credential per key_id, bounded PBKDF2.

Regression tests for the second review round of F5:

* BRIDGE_LOCAL_NODE_KEY used to be stored under two key_ids
  (``node_local_edge`` and ``local-edge``).  The fast index maps one lookup
  hash to one key_id and ``_save_keys`` inverted it, so ``node_local_edge``
  was written to keys.json without a lookup hash — and every unknown API
  key then cost a PBKDF2 against it, in the bridge and in the gateway.
* The Python legacy-key scan had no cap and ran on the shared default
  executor.
* ``get_key_meta()`` deep-copied a dict the event loop mutated in place,
  from a worker thread.
* rotate / create checked existence, awaited PBKDF2, then wrote — a
  revocation that landed in between was undone.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
from sigrift.bridge.dependencies import (
    MAX_LEGACY_SCAN,
    Role,
    _LegacyScanPool,
    _lookup_key,
    _lookup_key_async,
    require_api_key,
)
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
    verify_credential,
)

from .test_lifespan import (
    _lifespan_env,
    _make_app_with_lifespan,
    _patch_data_paths,
    _patch_detection_store,
    _patch_iq_store,
    _patch_pcap_store,
    _patch_persistence_dir,
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


class _CountingVerify:
    """Wraps verify_credential, recording calls and the calling thread."""

    def __init__(self, *, real: bool = True) -> None:
        self.calls = 0
        self.threads: list[str] = []
        self._real = real
        self._lock = threading.Lock()

    def __call__(self, credential, expected_hash, salt):
        with self._lock:
            self.calls += 1
            self.threads.append(threading.current_thread().name)
        if not self._real:
            return False
        return verify_credential(credential, expected_hash, salt)


def _wait_for_idle(pool: _LegacyScanPool) -> None:
    """Wait for the pool's done-callbacks (they run after result())."""
    deadline = time.monotonic() + 10
    while pool._pending and time.monotonic() < deadline:
        time.sleep(0.01)


def _snapshot(pm: PersistenceManager):
    return (
        pm.get_key_store(),
        pm.get_key_meta(),
        pm.get_key_fast_index(),
        pm.get_indexed_key_ids(),
    )


def _keys_json(data_dir: Path) -> dict:
    return json.loads((data_dir / "keys.json").read_text())["keys"]


# ---------------------------------------------------------------------------
# Lifespan: BRIDGE_LOCAL_NODE_KEY is one key, always indexed
# ---------------------------------------------------------------------------


class TestLocalNodeKeySeeding:
    def _boot(self, data: Path, **env_values: str) -> PersistenceManager:
        """Run the real lifespan once against *data*; return its persistence."""
        app = _make_app_with_lifespan()
        env = _lifespan_env(data)
        env.update(
            {
                "BRIDGE_ENV": "",
                "BRIDGE_MODE": "",
                "BRIDGE_LOCAL_NODE_KEY": "",
                "BRIDGE_MASTER_KEY": "",
            }
        )
        env.update(env_values)
        with (
            patch.dict(os.environ, env),
            _patch_data_paths(data),
            _patch_persistence_dir(data),
            _patch_detection_store(data),
            _patch_iq_store(data),
            _patch_pcap_store(data),
        ):
            with TestClient(app):
                return app.state.persistence

    @pytest.fixture
    def data(self, tmp_path: Path) -> Path:
        d = tmp_path / "data"
        d.mkdir()
        return d

    @pytest.fixture
    def env(self) -> dict[str, str]:
        return {
            "BRIDGE_MASTER_KEY": generate_api_key(32),
            "BRIDGE_LOCAL_NODE_KEY": generate_api_key(32),
        }

    def _assert_all_indexed_and_unknown_key_is_free(
        self, data: Path, pm: PersistenceManager
    ) -> None:
        on_disk = _keys_json(data)
        assert set(on_disk) == {"master", LOCAL_SCANNER_KEY_ID}
        assert all(entry.get("lookup_hash") for entry in on_disk.values()), on_disk
        assert pm.get_indexed_key_ids() == set(pm.get_key_store())

        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            for _ in range(5):
                unknown = generate_api_key(32)
                assert _lookup_key(unknown, *_snapshot(pm)) == (None, None)
                assert asyncio.run(_lookup_key_async(unknown, *_snapshot(pm))) == (
                    None,
                    None,
                )
        assert counter.calls == 0

    def test_single_entry_indexed_across_restarts(self, data, env):
        for _boot in range(2):
            pm = self._boot(data, **env)
            self._assert_all_indexed_and_unknown_key_is_free(data, pm)
            key_id, role = _lookup_key(env["BRIDGE_LOCAL_NODE_KEY"], *_snapshot(pm))
            assert (key_id, role) == (LOCAL_SCANNER_KEY_ID, Role.NODE)

    def test_restart_does_not_rehash_an_in_sync_key(self, data, env):
        self._boot(data, **env)
        before = _keys_json(data)[LOCAL_SCANNER_KEY_ID]
        self._boot(data, **env)
        after = _keys_json(data)[LOCAL_SCANNER_KEY_ID]
        assert (after["hash"], after["salt"]) == (before["hash"], before["salt"])

    def test_upgraded_install_loses_duplicate_entry(self, data, env):
        # keys.json as the previous release left it after its first boot.
        local = env["BRIDGE_LOCAL_NODE_KEY"]
        master = env["BRIDGE_MASTER_KEY"]
        old = {}
        for key_id, raw, desc, with_lookup in (
            ("master", master, "", True),
            (
                "node_local_edge",
                local,
                "Auto-seeded local edge agent (BRIDGE_LOCAL_NODE_KEY)",
                False,
            ),
            (LOCAL_SCANNER_KEY_ID, local, "In-stack scanner key", True),
        ):
            h, s = hash_credential(raw)
            entry = {"hash": h, "salt": s.hex(), "role": "node", "description": desc}
            if with_lookup:
                entry["lookup_hash"] = compute_lookup_hash(raw)
            old[key_id] = entry
        old["master"]["role"] = "admin"
        (data / "keys.json").write_text(json.dumps({"keys": old}))

        pm = self._boot(data, **env)
        assert "node_local_edge" not in pm.get_key_store()
        self._assert_all_indexed_and_unknown_key_is_free(data, pm)

    def test_duplicate_removed_even_when_env_changed(self, data, env):
        # The auto-seeded copy holds an older value of the env var.
        h, s = hash_credential(generate_api_key(32))
        (data / "keys.json").write_text(
            json.dumps(
                {
                    "keys": {
                        "node_local_edge": {
                            "hash": h,
                            "salt": s.hex(),
                            "role": "node",
                            "description": (
                                "Auto-seeded local edge agent (BRIDGE_LOCAL_NODE_KEY)"
                            ),
                        }
                    }
                }
            )
        )
        pm = self._boot(data, **env)
        assert "node_local_edge" not in pm.get_key_store()

    def test_operator_key_reusing_the_id_is_kept(self, data, env):
        raw = generate_api_key(32)
        h, s = hash_credential(raw)
        (data / "keys.json").write_text(
            json.dumps(
                {
                    "keys": {
                        "node_local_edge": {
                            "hash": h,
                            "salt": s.hex(),
                            "lookup_hash": compute_lookup_hash(raw),
                            "role": "node",
                            "description": "my own edge box",
                        }
                    }
                }
            )
        )
        pm = self._boot(data, **env)
        assert "node_local_edge" in pm.get_key_store()
        assert _lookup_key(raw, *_snapshot(pm))[0] == "node_local_edge"

    def test_legacy_master_entry_gets_indexed(self, data, env):
        h, s = hash_credential(env["BRIDGE_MASTER_KEY"])
        (data / "keys.json").write_text(
            json.dumps(
                {"keys": {"master": {"hash": h, "salt": s.hex(), "role": "admin"}}}
            )
        )
        pm = self._boot(data, **env)
        self._assert_all_indexed_and_unknown_key_is_free(data, pm)
        assert _lookup_key(env["BRIDGE_MASTER_KEY"], *_snapshot(pm)) == (
            "master",
            Role.ADMIN,
        )

    def test_role_forced_back_to_node(self, data, env):
        pm = self._boot(data, **env)
        pm.update_key_role(LOCAL_SCANNER_KEY_ID, "admin")
        pm = self._boot(data, **env)
        assert pm.get_key_meta()[LOCAL_SCANNER_KEY_ID]["role"] == "node"

    def test_local_key_equal_to_master_refused(self, data):
        same = generate_api_key(32)
        with pytest.raises(RuntimeError, match="must differ from BRIDGE_MASTER_KEY"):
            self._boot(data, BRIDGE_MASTER_KEY=same, BRIDGE_LOCAL_NODE_KEY=same)

    @staticmethod
    def _write_old_shared_layout(data: Path, shared: str) -> None:
        """keys.json as the previous release left it with LOCAL == MASTER.

        Three entries hold one credential; the fast index (the only lookup
        hash written) resolved it to the in-stack entry.
        """
        old = {}
        for key_id, desc, with_lookup in (
            ("master", None, False),
            (
                "node_local_edge",
                "Auto-seeded local edge agent (BRIDGE_LOCAL_NODE_KEY)",
                False,
            ),
            (
                LOCAL_SCANNER_KEY_ID,
                "In-stack scanner key (BRIDGE_LOCAL_NODE_KEY)",
                True,
            ),
        ):
            h, s = hash_credential(shared)
            entry = {"hash": h, "salt": s.hex()}
            if desc is not None:
                entry.update({"role": "node", "description": desc})
            if with_lookup:
                entry["lookup_hash"] = compute_lookup_hash(shared)
            old[key_id] = entry
        (data / "keys.json").write_text(json.dumps({"keys": old}))

    def test_shared_key_install_boots_after_local_key_changed(self, data):
        # The first boot refuses LOCAL == MASTER and says to set a new
        # BRIDGE_LOCAL_NODE_KEY; doing exactly that must then boot, without
        # being told to rotate the master key.
        master = generate_api_key(32)
        self._write_old_shared_layout(data, master)
        with pytest.raises(RuntimeError, match="must differ from BRIDGE_MASTER_KEY"):
            self._boot(data, BRIDGE_MASTER_KEY=master, BRIDGE_LOCAL_NODE_KEY=master)

        env = {
            "BRIDGE_MASTER_KEY": master,
            "BRIDGE_LOCAL_NODE_KEY": generate_api_key(32),
        }
        for _boot in range(2):
            pm = self._boot(data, **env)
            self._assert_all_indexed_and_unknown_key_is_free(data, pm)
            snap = _snapshot(pm)
            assert _lookup_key(master, *snap) == ("master", Role.ADMIN)
            assert _lookup_key(env["BRIDGE_LOCAL_NODE_KEY"], *snap) == (
                LOCAL_SCANNER_KEY_ID,
                Role.NODE,
            )
        assert pm.get_key_meta()[LOCAL_SCANNER_KEY_ID]["role"] == "node"

    def test_shared_key_install_boots_after_local_key_unset(self, data):
        # The other way to follow "must differ": drop BRIDGE_LOCAL_NODE_KEY.
        # The in-stack entry still holding the master credential is stale.
        master = generate_api_key(32)
        self._write_old_shared_layout(data, master)
        pm = self._boot(data, BRIDGE_MASTER_KEY=master)
        assert set(pm.get_key_store()) == {"master"}
        assert _lookup_key(master, *_snapshot(pm)) == ("master", Role.ADMIN)
        assert all(entry.get("lookup_hash") for entry in _keys_json(data).values())

    def test_master_and_local_keys_swapped(self, data, env):
        # Each env value is still indexed under the other key's id when the
        # master is synced; neither boot step may refuse the other's value.
        self._boot(data, **env)
        swapped = {
            "BRIDGE_MASTER_KEY": env["BRIDGE_LOCAL_NODE_KEY"],
            "BRIDGE_LOCAL_NODE_KEY": env["BRIDGE_MASTER_KEY"],
        }
        pm = self._boot(data, **swapped)
        self._assert_all_indexed_and_unknown_key_is_free(data, pm)
        snap = _snapshot(pm)
        assert _lookup_key(swapped["BRIDGE_MASTER_KEY"], *snap) == (
            "master",
            Role.ADMIN,
        )
        assert _lookup_key(swapped["BRIDGE_LOCAL_NODE_KEY"], *snap) == (
            LOCAL_SCANNER_KEY_ID,
            Role.NODE,
        )

    def test_master_conflict_with_operator_key_still_refused(self, data, env):
        # Only the in-stack entries are treated as stale: a credential that
        # an unrelated key holds is still refused for the master.
        self._boot(data, **env)
        raw = generate_api_key(32)
        h, s = hash_credential(raw)
        keys = _keys_json(data)
        keys["operator-key"] = {
            "hash": h,
            "salt": s.hex(),
            "lookup_hash": compute_lookup_hash(raw),
            "role": "analyst",
        }
        (data / "keys.json").write_text(json.dumps({"keys": keys}))
        with pytest.raises(
            RuntimeError, match="BRIDGE_MASTER_KEY cannot be registered"
        ):
            self._boot(data, **{**env, "BRIDGE_MASTER_KEY": raw})

    def test_http_unknown_key_runs_no_pbkdf2(self, data, env):
        pm = self._boot(data, **env)
        reloaded = PersistenceManager(data_dir=data, auto_save_interval=0)
        reloaded.load_all()

        app = FastAPI()

        @app.get("/probe")
        async def probe(key_id: str = Depends(require_api_key)):
            return {"key_id": key_id}

        app.state.persistence = reloaded
        app.state.detection_store = None
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            client = TestClient(app)
            for _ in range(5):
                resp = client.get("/probe", headers={"X-API-Key": generate_api_key(32)})
                assert resp.status_code == 401
            assert counter.calls == 0
            resp = client.get(
                "/probe", headers={"X-API-Key": env["BRIDGE_LOCAL_NODE_KEY"]}
            )
        assert resp.status_code == 200
        assert resp.json() == {"key_id": LOCAL_SCANNER_KEY_ID}
        assert pm.get_key_store().keys() == reloaded.get_key_store().keys()


# ---------------------------------------------------------------------------
# Persistence: one credential, one key_id; lookup hashes never dropped
# ---------------------------------------------------------------------------


def _add(pm: PersistenceManager, key_id: str, raw: str | None = None) -> str:
    raw = raw or generate_api_key(32)
    h, s = hash_credential(raw)
    pm.set_key(key_id, h, s, lookup_hash=compute_lookup_hash(raw))
    return raw


class TestOneCredentialOneKeyId:
    def test_set_key_refuses_second_key_id_for_same_credential(self, persistence):
        raw = _add(persistence, "a")
        h, s = hash_credential(raw)
        with pytest.raises(ValueError, match="already registered as API key 'a'"):
            persistence.set_key("b", h, s, lookup_hash=compute_lookup_hash(raw))
        assert "b" not in persistence.get_key_store()
        assert persistence.get_key_fast_index() == {compute_lookup_hash(raw): "a"}

    def test_same_key_id_may_be_rehashed(self, persistence):
        raw = _add(persistence, "a")
        _add(persistence, "a", raw)  # same credential, same key_id: fine
        assert _lookup_key(raw, *_snapshot(persistence))[0] == "a"

    def test_save_keeps_lookup_hash_of_every_key(self, tmp_path):
        # A hand-edited keys.json with two ids for one credential: both stay
        # indexed on save (the gateway's by_lookup accepts that), neither is
        # PBKDF2-scanned for an unknown key, and the first one wins.
        data = tmp_path / "data"
        data.mkdir()
        raw = generate_api_key(32)
        lh = compute_lookup_hash(raw)
        entries = {}
        for key_id in ("first", "second"):
            h, s = hash_credential(raw)
            entries[key_id] = {"hash": h, "salt": s.hex(), "lookup_hash": lh}
        (data / "keys.json").write_text(json.dumps({"keys": entries}))

        pm = PersistenceManager(data_dir=data, auto_save_interval=0)
        pm.load_all()
        assert pm.get_indexed_key_ids() == {"first", "second"}
        assert pm.get_key_fast_index() == {lh: "first"}
        _add(pm, "other")  # triggers a save
        on_disk = _keys_json(data)
        assert on_disk["first"]["lookup_hash"] == lh
        assert on_disk["second"]["lookup_hash"] == lh

        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key("unknown", *_snapshot(pm)) == (None, None)
        assert counter.calls == 0
        assert _lookup_key(raw, *_snapshot(pm))[0] == "first"

        # Removing the index owner hands the entry to the other id.
        pm.remove_key("first")
        assert pm.get_key_fast_index()[lh] == "second"
        assert _lookup_key(raw, *_snapshot(pm))[0] == "second"


# ---------------------------------------------------------------------------
# Legacy scan: capped, on its own small pool, shed when saturated
# ---------------------------------------------------------------------------


def _legacy_store(n: int, *, expired: int = 0, real: bool = True):
    store, meta = {}, {}
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    for i in range(n):
        store[f"legacy{i}"] = (
            hash_credential(f"raw-{i}") if real else ("0" * 64, b"salt")
        )
        if i < expired:
            meta[f"legacy{i}"] = {"expires_at": past}
    return store, meta


class TestLegacyScan:
    def test_scan_is_capped(self):
        store, meta = _legacy_store(MAX_LEGACY_SCAN + 4, real=False)
        counter = _CountingVerify(real=False)
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key("unknown", store, meta, {}) == (None, None)
        assert counter.calls == MAX_LEGACY_SCAN

    def test_expired_legacy_keys_are_not_scanned(self):
        store, meta = _legacy_store(3, expired=2)
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            assert _lookup_key("unknown", store, meta, {}) == (None, None)
            assert _lookup_key("raw-2", store, meta, {})[0] == "legacy2"
        assert counter.calls == 2

    def test_indexed_ids_are_never_scanned(self):
        store, meta = _legacy_store(2)
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            got = _lookup_key("unknown", store, meta, {}, indexed_ids={"legacy0"})
        assert got == (None, None)
        assert counter.calls == 1

    def test_async_scan_runs_on_dedicated_pool(self):
        store, meta = _legacy_store(2)
        counter = _CountingVerify()
        with patch.object(deps, "verify_credential", counter):
            got = asyncio.run(_lookup_key_async("raw-1", store, meta, {}))
        assert got[0] == "legacy1"
        assert counter.threads
        assert all(t.startswith("bridge-legacy-key-scan") for t in counter.threads)

    def test_async_unknown_key_without_legacy_keys_needs_no_thread(self):
        store = {"k": hash_credential("raw")}
        index = {compute_lookup_hash("raw"): "k"}
        with patch.object(
            deps.asyncio, "to_thread", side_effect=AssertionError("no thread hop")
        ):
            got = asyncio.run(_lookup_key_async("unknown", store, {}, index))
        assert got == (None, None)

    def test_saturated_pool_rejects_without_pbkdf2(self):
        pool = _LegacyScanPool(workers=1, max_pending=1)
        release = threading.Event()
        blocker = pool.try_submit(release.wait, 10)
        assert blocker is not None
        store, meta = _legacy_store(2)
        counter = _CountingVerify()
        try:
            with (
                patch.object(deps, "_legacy_scan_pool", pool),
                patch.object(deps, "verify_credential", counter),
            ):
                got = asyncio.run(_lookup_key_async("raw-0", store, meta, {}))
        finally:
            release.set()
        assert got == (None, None)
        assert counter.calls == 0
        blocker.result(timeout=10)
        _wait_for_idle(pool)
        assert pool._pending == 0

    def test_slot_released_when_request_is_cancelled(self):
        pool = _LegacyScanPool(workers=1, max_pending=2)
        started, release = threading.Event(), threading.Event()

        def slow_scan(*_args):
            started.set()
            release.wait(10)

        async def main():
            with (
                patch.object(deps, "_legacy_scan_pool", pool),
                patch.object(deps, "_scan_legacy_keys", slow_scan),
            ):
                store, meta = _legacy_store(1)
                task = asyncio.create_task(_lookup_key_async("x", store, meta, {}))
                await asyncio.to_thread(started.wait, 10)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                # The scan still runs, so its slot is still taken ...
                assert pool._pending == 1
                release.set()

        asyncio.run(main())
        # ... and is released once it actually finishes.
        _wait_for_idle(pool)
        assert pool._pending == 0


# ---------------------------------------------------------------------------
# Key metadata snapshots are safe from any thread (R8)
# ---------------------------------------------------------------------------


class TestKeyMetaCopyOnWrite:
    def test_published_state_is_never_mutated_in_place(self, persistence):
        _add(persistence, "a")
        persistence.set_key_meta("a", {"role": "node", "description": "x"})
        published_meta = persistence._key_meta
        inner = published_meta["a"]
        published_keys = persistence._keys
        before = (dict(published_meta), dict(inner), dict(published_keys))

        persistence.update_key_role("a", "analyst")
        persistence.set_key_meta("b", {"role": "viewer"})
        _add(persistence, "c")
        h, s = hash_credential("new")
        persistence.replace_key_credential(
            "a", h, s, lookup_hash=None, meta_update={"rotated_at": "now"}
        )
        persistence.add_key("d", h, s, lookup_hash=None, meta={"role": "viewer"})
        persistence.remove_key("c")

        assert (dict(published_meta), dict(inner), dict(published_keys)) == before
        assert persistence.get_key_meta()["a"]["role"] == "analyst"

    def test_set_key_meta_stores_a_private_copy(self, persistence):
        _add(persistence, "a")
        meta = {"role": "node"}
        persistence.set_key_meta("a", meta)
        meta["role"] = "admin"
        assert persistence.get_key_meta()["a"]["role"] == "node"

    def test_concurrent_reads_never_fail(self, persistence):
        _add(persistence, "a")
        errors: list[BaseException] = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    persistence.get_key_meta()
                    persistence.get_key_store()
                    persistence.get_key_fast_index()
                except BaseException as exc:  # pragma: no cover - the bug
                    errors.append(exc)
                    return

        threads = [threading.Thread(target=reader) for _ in range(2)]
        for t in threads:
            t.start()
        try:
            for i in range(60):
                persistence.set_key_meta(f"k{i}", {"role": "viewer", "n": i})
                persistence.update_key_role("a", "node" if i % 2 else "viewer")
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=10)
        assert errors == []

    def test_http_auth_snapshots_off_the_event_loop(self, bridge_app, master_key):
        persistence = bridge_app.state.persistence
        real = persistence.get_key_auth_snapshot
        callers: list[bool] = []

        def recording():
            try:
                asyncio.get_running_loop()
                callers.append(True)
            except RuntimeError:
                callers.append(False)
            return real()

        with patch.object(persistence, "get_key_auth_snapshot", recording):
            resp = TestClient(bridge_app).get(
                "/api/nodes", headers={"X-API-Key": master_key}
            )
        assert resp.status_code == 200
        # The atomic snapshot can wait for a durable writer: both the initial
        # credential read and the post-verification refresh must stay off-loop.
        assert len(callers) >= 2
        assert not any(callers)


# ---------------------------------------------------------------------------
# rotate / create cannot undo a concurrent revoke or replace a key (R9)
# ---------------------------------------------------------------------------


class TestAtomicKeyChanges:
    def test_replace_credential_of_removed_key_is_refused(self, persistence):
        _add(persistence, "gone")
        persistence.remove_key("gone")
        h, s = hash_credential("new")
        assert (
            persistence.replace_key_credential(
                "gone", h, s, lookup_hash=compute_lookup_hash("new")
            )
            is None
        )
        assert "gone" not in persistence.get_key_store()

    def test_replace_credential_with_stale_expectation_is_refused(self, persistence):
        _add(persistence, "k")
        stale = persistence.get_key_store()["k"]
        _add(persistence, "k")  # rotated meanwhile
        current = persistence.get_key_store()["k"]
        h, s = hash_credential("upgrade")
        got = persistence.replace_key_credential(
            "k", h, s, lookup_hash=None, expected=stale
        )
        assert got is None
        assert persistence.get_key_store()["k"] == current

    def test_add_key_never_replaces(self, persistence):
        raw = _add(persistence, "k")
        h, s = hash_credential("other")
        assert not persistence.add_key("k", h, s, lookup_hash=None, meta={})
        assert _lookup_key(raw, *_snapshot(persistence))[0] == "k"

    @staticmethod
    def _hash_then(action):
        """hash_credential stand-in that runs *action* once, mid-hash."""
        fired = []

        def fake(raw, salt=None):
            if not fired:
                fired.append(True)
                action()
            return hash_credential(raw, salt)

        return fake

    def test_keys_rotate_racing_revoke_stays_revoked(self, client, persistence):
        assert client.post("/api/keys/", json={"key_id": "node_x"}).status_code == 201
        import sigrift.bridge.routers.keys as keys_router

        revoke = self._hash_then(lambda: persistence.remove_key("node_x"))
        with patch.object(keys_router, "hash_credential", revoke):
            resp = client.put("/api/keys/node_x/rotate")
        assert resp.status_code == 404
        assert "node_x" not in persistence.get_key_store()
        assert "node_x" not in persistence.get_key_meta()

    def test_admin_rotate_racing_revoke_stays_revoked(self, client, persistence):
        assert client.post("/api/keys/", json={"key_id": "node_y"}).status_code == 201
        import sigrift.lib.security.credentials as creds

        revoke = self._hash_then(lambda: persistence.remove_key("node_y"))
        with patch.object(creds, "hash_credential", revoke):
            resp = client.post(
                "https://testserver/api/admin/keys/node_y/rotate",
                json={"deploy_to_node": False},
            )
        assert resp.status_code == 404
        assert "node_y" not in persistence.get_key_store()

    def test_concurrent_create_does_not_replace_first_key(self, client, persistence):
        import sigrift.bridge.routers.keys as keys_router

        winner = {}

        def other_create():
            raw = generate_api_key(32)
            h, s = hash_credential(raw)
            assert persistence.add_key(
                "dup",
                h,
                s,
                lookup_hash=compute_lookup_hash(raw),
                meta={"role": "analyst", "description": "first"},
            )
            winner["raw"] = raw

        with patch.object(
            keys_router, "hash_credential", self._hash_then(other_create)
        ):
            resp = client.post("/api/keys/", json={"key_id": "dup"})
        assert resp.status_code == 409
        assert _lookup_key(winner["raw"], *_snapshot(persistence))[0] == "dup"
        assert persistence.get_key_meta()["dup"]["description"] == "first"

    def test_rotate_still_works(self, client, persistence):
        # Not an edge key id: those are NODE keys (test_persistence_security).
        resp = client.post("/api/keys/", json={"key_id": "ops_z"})
        old_raw = resp.json()["raw_key"]
        resp = client.put("/api/keys/ops_z/rotate")
        assert resp.status_code == 200
        new_raw = resp.json()["raw_key"]
        snap = _snapshot(persistence)
        assert _lookup_key(new_raw, *snap)[0] == "ops_z"
        assert _lookup_key(old_raw, *snap) == (None, None)
        assert persistence.get_key_meta()["ops_z"]["rotated_at"]
        # The rotated key keeps its role (analyst for /api/keys keys).
        assert persistence.get_key_meta()["ops_z"]["role"] == "analyst"
