"""Regression tests for JSON state durability and multi-worker safety (C7, C8).

C7: writes are fsync-ed through unique temp files; workers sharing the data
directory merge instead of overwriting each other (a revoked key is never
resurrected by another worker's periodic save); an unreadable keys.json is
restored from keys.json.bak or refused, never treated as empty.

C8: save_all() does its file I/O without holding the state lock.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

import sigrift.bridge.persistence as persistence_mod
from sigrift.bridge.persistence import KeyStoreCorruptError, PersistenceManager
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture(autouse=True)
def _instant_key_refresh(monkeypatch: pytest.MonkeyPatch):
    # Readers re-check keys.json at most once a second; make it immediate.
    monkeypatch.setattr(persistence_mod, "_KEYS_REFRESH_INTERVAL", 0.0)


def _pm(data_dir: Path) -> PersistenceManager:
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    pm.load_all()
    return pm


def _add_key(pm: PersistenceManager, key_id: str, **meta) -> str:
    raw = generate_api_key(32)
    h, s = hash_credential(raw)
    assert pm.add_key(
        key_id,
        h,
        s,
        lookup_hash=compute_lookup_hash(raw),
        meta={"role": "viewer", "description": "", "created_at": "", **meta},
    )
    return raw


def _keys_on_disk(data_dir: Path) -> dict:
    return json.loads((data_dir / "keys.json").read_text())["keys"]


class TestTwoWorkers:
    def test_revoked_key_not_resurrected_by_other_workers_save(
        self, tmp_path: Path
    ) -> None:
        data = tmp_path / "data"
        a = _pm(data)
        _add_key(a, "victim")
        b = _pm(data)  # second worker, loaded while "victim" existed
        assert b.has_key("victim")

        assert a.remove_key("victim")
        b.set_node("n1", {"node_id": "n1"})
        b.save_all()  # periodic save of the stale worker
        assert "victim" not in _keys_on_disk(data)

        _add_key(b, "other")  # a key change in the stale worker
        on_disk = _keys_on_disk(data)
        assert "victim" not in on_disk and "other" in on_disk
        # ... and the stale worker stopped accepting the revoked key.
        assert "victim" not in b.get_key_store()
        assert "victim" not in b.get_key_meta()

    def test_rotation_in_stale_worker_does_not_recreate_revoked_key(
        self, tmp_path: Path
    ) -> None:
        data = tmp_path / "data"
        a = _pm(data)
        _add_key(a, "k")
        b = _pm(data)
        expected = b.get_key_store()["k"]
        a.remove_key("k")
        h, s = hash_credential("new-secret")
        assert (
            b.replace_key_credential(
                "k", h, s, lookup_hash=None, expected=tuple(expected)
            )
            is None
        )
        assert "k" not in _keys_on_disk(data)

    def test_state_changes_of_both_workers_survive(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        a, b = _pm(data), _pm(data)
        a.set_node("node-a", {"node_id": "node-a"})
        b.set_node("node-b", {"node_id": "node-b"})
        a.add_alert({"alert_id": "alert-a"})
        b.add_alert({"alert_id": "alert-b"})
        a.save_all()
        b.save_all()
        fresh = _pm(data)
        assert set(fresh.get_nodes()) == {"node-a", "node-b"}
        assert {x["alert_id"] for x in fresh.get_alerts()} == {"alert-a", "alert-b"}
        # The worker that saved last adopted the other's changes.
        assert set(b.get_nodes()) == {"node-a", "node-b"}

    def test_removal_in_one_worker_is_not_undone_by_the_other(
        self, tmp_path: Path
    ) -> None:
        data = tmp_path / "data"
        seed = _pm(data)
        seed.set_node("gone", {"node_id": "gone"})
        seed.set_node("kept", {"node_id": "kept"})
        seed.save_all()
        a, b = _pm(data), _pm(data)
        assert a.remove_node("gone")
        a.save_all()
        b.set_node("kept", {"node_id": "kept", "status": "online"})
        b.save_all()
        nodes = _pm(data).get_nodes()
        assert "gone" not in nodes
        assert nodes["kept"]["status"] == "online"


class TestDurableWrites:
    def test_concurrent_writers_never_share_a_temp_file(self, tmp_path: Path) -> None:
        target = tmp_path / "keys.json"
        errors: list[BaseException] = []

        def writer(n: int) -> None:
            try:
                for i in range(40):
                    persistence_mod._atomic_write(target, {"writer": n, "i": i})
            except BaseException as exc:  # pragma: no cover - the bug
                errors.append(exc)

        threads = [threading.Thread(target=writer, args=(n,)) for n in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert errors == []
        assert "writer" in json.loads(target.read_text())
        assert [p.name for p in tmp_path.iterdir()] == ["keys.json"]

    def test_write_fsyncs_file_and_directory(self, tmp_path: Path) -> None:
        synced: list[int] = []
        real_fsync = os.fsync

        def recording_fsync(fd: int) -> None:
            synced.append(fd)
            real_fsync(fd)

        with patch.object(persistence_mod.os, "fsync", recording_fsync):
            persistence_mod._atomic_write(tmp_path / "x.json", {"a": 1})
        assert len(synced) >= 2  # the temp file, then the directory

    def test_key_files_are_private(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        _add_key(_pm(data), "k")
        for name in ("keys.json", "keys.json.bak"):
            mode = stat.S_IMODE((data / name).stat().st_mode)
            assert mode == 0o600, (name, oct(mode))

    def test_periodic_save_does_not_rewrite_unchanged_keys(
        self, tmp_path: Path
    ) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        _add_key(pm, "k")
        before = os.stat(data / "keys.json")
        pm.set_node("n", {"node_id": "n"})
        pm.save_all()
        after = os.stat(data / "keys.json")
        # The gateway reloads keys.json (and drops its auth cache) whenever
        # it changes; an unchanged key set must leave the file alone.
        assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)


class TestUnreadableKeysFile:
    @pytest.mark.parametrize("content", ["", "{truncated", "[1, 2]"])
    def test_restored_from_backup(self, tmp_path: Path, content: str) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        raw = _add_key(pm, "operator")
        (data / "keys.json").write_text(content)  # e.g. power loss

        restored = _pm(data)
        assert "operator" in restored.get_key_store()
        assert restored.get_key_fast_index()[compute_lookup_hash(raw)] == "operator"
        assert "operator" in _keys_on_disk(data)  # the gateway sees it again
        assert [p.name for p in data.iterdir() if ".corrupt-" in p.name]

    def test_backup_created_for_a_keys_file_from_an_older_release(
        self, tmp_path: Path
    ) -> None:
        data = tmp_path / "data"
        _add_key(_pm(data), "legacy")
        (data / "keys.json.bak").unlink()  # as an older release left it
        _pm(data)  # startup
        (data / "keys.json").write_text("")
        assert "legacy" in _pm(data).get_key_store()

    def test_refused_without_backup(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        data.mkdir()
        (data / "keys.json").write_text("{not json")
        pm = PersistenceManager(data_dir=data, auto_save_interval=0)
        with pytest.raises(KeyStoreCorruptError):
            pm.load_all()
        # The unreadable file is left for the operator, not overwritten.
        assert (data / "keys.json").read_text() == "{not json"

    def test_runtime_corruption_keeps_last_good_set(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        _add_key(pm, "k")
        (data / "keys.json").write_text("{bad")
        assert "k" in pm.get_key_store()
        assert "k" in pm.get_key_meta()


class TestKeyMetadataRoundTrip:
    def test_node_binding_and_flags_survive_reload(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        _add_key(pm, "node_edge1", node_id="edge-1")
        meta = pm.get_key_meta()["node_edge1"]
        pm.set_key_meta("node_edge1", {**meta, "enabled": False})
        entry = _keys_on_disk(data)["node_edge1"]
        assert entry["node_id"] == "edge-1"  # the gateway enforces it
        assert entry["enabled"] is False
        reloaded = _pm(data).get_key_meta()["node_edge1"]
        assert reloaded["node_id"] == "edge-1"
        assert reloaded["enabled"] is False


class TestSaveDoesNotBlockWriters:
    def test_set_node_proceeds_while_files_are_written(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        pm.set_node("n0", {"node_id": "n0"})
        writing = threading.Event()
        release = threading.Event()
        real_write = persistence_mod._atomic_write

        def slow_write(path, payload, **kwargs):
            if path.name == "nodes.json":
                writing.set()
                release.wait(10)
            return real_write(path, payload, **kwargs)

        with patch.object(persistence_mod, "_atomic_write", slow_write):
            saver = threading.Thread(target=pm.save_all)
            saver.start()
            assert writing.wait(10)
            started = time.monotonic()
            pm.set_node("n1", {"node_id": "n1"})  # event-loop style caller
            pm.add_alert({"alert_id": "x"})
            elapsed = time.monotonic() - started
            release.set()
            saver.join(10)
        assert elapsed < 1.0
        # The change made during the save is saved next time.
        pm.save_all()
        assert set(_pm(data).get_nodes()) == {"n0", "n1"}


class TestAlertRuleTriggerStats:
    def test_record_alert_rule_trigger_persists(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        pm.add_alert_rule({"rule_id": "r1", "name": "x", "trigger_count": 0})
        pm.record_alert_rule_trigger("r1", "2026-11-05T10:00:00+00:00")
        pm.record_alert_rule_trigger("r1", "2026-11-05T11:00:00+00:00")
        assert pm.record_alert_rule_trigger("missing", "t") is None
        pm.save_all()
        [rule] = _pm(data).get_alert_rules()
        assert rule["trigger_count"] == 2
        assert rule["last_triggered_at"] == "2026-11-05T11:00:00+00:00"


class TestKeyRoutesWriteOffTheLoop:
    """C8: key changes fsync keys.json (+ .bak) under the inter-process
    lock; the key routes run them through the ``async_*`` wrappers, i.e. in
    a worker thread, not on the event loop."""

    _METHODS = (
        "add_key",
        "remove_key",
        "set_key_meta",
        "replace_key_credential",
        "update_key_role",
        "update_key_access",
    )

    @pytest.fixture
    def on_loop_calls(self, bridge_app, monkeypatch: pytest.MonkeyPatch):
        import asyncio

        persistence = bridge_app.state.persistence
        calls: list[tuple[str, bool]] = []

        def recording(name: str):
            real = getattr(persistence, name)

            def wrapper(*args, **kwargs):
                try:
                    asyncio.get_running_loop()
                    on_loop = True
                except RuntimeError:
                    on_loop = False
                calls.append((name, on_loop))
                return real(*args, **kwargs)

            return wrapper

        for name in self._METHODS:
            monkeypatch.setattr(persistence, name, recording(name))
        return calls

    def test_keys_router(self, client, on_loop_calls) -> None:
        resp = client.post("/api/keys/", json={"key_id": "c8-key"})
        assert resp.status_code == 201, resp.text
        assert client.put("/api/keys/c8-key/rotate").status_code == 200
        assert client.delete("/api/keys/c8-key").status_code == 200
        assert client.post("/api/keys/rotate-master").status_code == 200
        names = [name for name, _ in on_loop_calls]
        assert {"add_key", "replace_key_credential", "remove_key"} <= set(names)
        assert [c for c in on_loop_calls if c[1]] == []

    def test_admin_router(self, client, on_loop_calls) -> None:
        resp = client.post("/api/admin/keys", json={"role": "viewer"})
        assert resp.status_code == 201, resp.text
        key_id = resp.json()["key_id"]
        resp = client.post(
            f"https://testserver/api/admin/keys/{key_id}/rotate", json={}
        )
        assert resp.status_code == 200, resp.text
        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions", json={"role": "analyst"}
        )
        assert resp.status_code == 200, resp.text
        assert client.delete(f"/api/admin/keys/{key_id}").status_code == 200
        names = {name for name, _ in on_loop_calls}
        assert {
            "add_key",
            "replace_key_credential",
            "update_key_access",
            "remove_key",
        } <= names
        assert [c for c in on_loop_calls if c[1]] == []
