"""Key writes never hold up node / alert state; key recovery is crash-safe.

Q9: key changes held ``persistence._lock`` — the lock ``set_node`` /
``add_alert`` / ``add_history_entry`` / ``record_alert_rule_trigger`` take
on the event loop — across four fsyncs and the wait for another worker's
``.persistence.lock``.  They now use a separate key lock.

Q11: recovering an unreadable keys.json *moved* it aside before writing
the restored copy; a crash in between left no keys.json, which loaded as
an empty key store, and the next key write overwrote keys.json.bak.
"""

from __future__ import annotations

import json
import os
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

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]


@pytest.fixture(autouse=True)
def _instant_key_refresh(monkeypatch: pytest.MonkeyPatch):
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


def _keys(path: Path) -> dict:
    return json.loads(path.read_text())["keys"]


def _state_calls_duration(pm: PersistenceManager) -> float:
    """Time the event-loop style state updates (they must not touch disk)."""
    started = time.monotonic()
    pm.set_node("n1", {"node_id": "n1"})
    pm.add_alert({"alert_id": "a1"})
    pm.add_history_entry("n1", {"t": 1})
    pm.record_alert_rule_trigger("r1", "2026-11-06T00:00:00+00:00")
    return time.monotonic() - started


# ---------------------------------------------------------------------------
# Q9
# ---------------------------------------------------------------------------


class TestKeyWritesDoNotBlockState:
    FSYNC_DELAY = 0.4

    def test_set_node_does_not_wait_for_key_fsyncs(self, tmp_path: Path) -> None:
        pm = _pm(tmp_path / "data")
        _add_key(pm, "k")
        pm.add_alert_rule({"rule_id": "r1", "name": "x", "trigger_count": 0})
        in_fsync = threading.Event()
        real_fsync = os.fsync

        def slow_fsync(fd: int) -> None:
            in_fsync.set()
            time.sleep(self.FSYNC_DELAY)
            real_fsync(fd)

        with patch.object(persistence_mod.os, "fsync", slow_fsync):
            writer = threading.Thread(
                target=pm.set_key_meta, args=("k", {"role": "analyst"})
            )
            writer.start()
            assert in_fsync.wait(10)
            elapsed = _state_calls_duration(pm)
            meta_started = time.monotonic()
            assert "k" in pm.get_key_meta()  # readers do not wait either
            meta_elapsed = time.monotonic() - meta_started
            writer.join(30)
        assert not writer.is_alive()
        # The key write took >= 4 fsyncs (keys.json, dir, .bak, dir).
        assert elapsed < self.FSYNC_DELAY / 4, elapsed
        assert meta_elapsed < self.FSYNC_DELAY / 4, meta_elapsed
        assert _keys(tmp_path / "data" / "keys.json")["k"]["role"] == "analyst"

    @pytest.mark.skipif(fcntl is None, reason="needs POSIX flock")
    def test_key_write_waiting_for_another_worker(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        _add_key(pm, "victim")
        _add_key(pm, "other")
        pm.add_alert_rule({"rule_id": "r1", "name": "x", "trigger_count": 0})
        # "Another worker" holds the inter-process lock ...
        fd = os.open(data / ".persistence.lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            removing = threading.Thread(target=pm.remove_key, args=("victim",))
            removing.start()
            time.sleep(0.3)
            assert removing.is_alive()  # ... so the revocation waits for it
            # ... and has just rewritten keys.json, which readers re-read.
            os.utime(data / "keys.json")
            elapsed = _state_calls_duration(pm)
            started = time.monotonic()
            assert "other" in pm.get_key_store()
            read_elapsed = time.monotonic() - started
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        removing.join(10)
        assert not removing.is_alive()
        assert elapsed < 0.1, elapsed
        assert read_elapsed < 0.1, read_elapsed
        assert "victim" not in _keys(data / "keys.json")
        assert "victim" not in pm.get_key_store()

    def test_key_writers_are_still_serialised(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        pm = _pm(data)
        errors: list[BaseException] = []

        def add(i: int) -> None:
            try:
                _add_key(pm, f"k{i}")
            except BaseException as exc:  # pragma: no cover - the bug
                errors.append(exc)

        threads = [threading.Thread(target=add, args=(i,)) for i in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        assert errors == []
        assert set(_keys(data / "keys.json")) == {f"k{i}" for i in range(12)}
        assert set(_pm(data).get_key_store()) == {f"k{i}" for i in range(12)}


# ---------------------------------------------------------------------------
# Q11
# ---------------------------------------------------------------------------


def _store_with_corrupt_keys(data: Path) -> None:
    pm = _pm(data)
    _add_key(pm, "operator")
    _add_key(pm, "node_edge1", role="node")
    (data / "keys.json").write_text("{truncated")  # e.g. power loss


class TestCrashSafeRecovery:
    def test_crash_while_writing_the_restored_file(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        _store_with_corrupt_keys(data)
        real_write = persistence_mod._atomic_write

        def crash_on_keys(path, payload, **kwargs):
            if path.name == "keys.json":
                raise OSError("killed before the rename")
            return real_write(path, payload, **kwargs)

        with patch.object(persistence_mod, "_atomic_write", crash_on_keys):
            with pytest.raises(OSError):
                PersistenceManager(data_dir=data, auto_save_interval=0).load_all()
        # keys.json was never moved away: it is still the unreadable file.
        assert (data / "keys.json").read_text() == "{truncated"
        assert [p for p in data.iterdir() if ".corrupt-" in p.name]

        # Next start: recovered again; every key survives a master-key write.
        pm = _pm(data)
        assert {"operator", "node_edge1"} <= set(pm.get_key_store())
        h, s = hash_credential("master-secret")
        pm.set_key("master", h, s)
        for name in ("keys.json", "keys.json.bak"):
            assert {"operator", "node_edge1", "master"} <= set(_keys(data / name))

    def test_corrupt_copy_failure_still_restores(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        _store_with_corrupt_keys(data)

        def failing_copy(src, dest):
            raise OSError("disk full")

        with patch.object(persistence_mod, "_copy_file_durably", failing_copy):
            pm = _pm(data)
        assert {"operator", "node_edge1"} <= set(pm.get_key_store())
        assert "operator" in _keys(data / "keys.json")

    def test_corrupt_copy_is_private(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        _store_with_corrupt_keys(data)
        _pm(data)
        [aside] = [p for p in data.iterdir() if ".corrupt-" in p.name]
        assert aside.read_text() == "{truncated"
        assert (aside.stat().st_mode & 0o777) == 0o600


class TestMissingKeysFile:
    def test_restored_from_backup(self, tmp_path: Path, caplog) -> None:
        # An older release crashed between moving the corrupt keys.json
        # aside and writing the restored one: only keys.json.bak is left.
        data = tmp_path / "data"
        pm = _pm(data)
        _add_key(pm, "operator")
        (data / "keys.json").unlink()

        with caplog.at_level("CRITICAL"):
            pm = _pm(data)
        assert "operator" in pm.get_key_store()
        assert "operator" in _keys(data / "keys.json")  # the gateway sees it
        msg = " ".join(r.getMessage() for r in caplog.records)
        assert "keys.json.bak" in msg and "aside" in msg
        # The startup master-key write no longer reduces the backup to it.
        h, s = hash_credential("master-secret")
        pm.set_key("master", h, s)
        assert {"operator", "master"} <= set(_keys(data / "keys.json.bak"))

    def test_unreadable_backup_refuses_startup(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        data.mkdir()
        (data / "keys.json.bak").write_text("{bad")
        with pytest.raises(KeyStoreCorruptError):
            PersistenceManager(data_dir=data, auto_save_interval=0).load_all()
        assert not (data / "keys.json").exists()

    def test_fresh_install_is_empty(self, tmp_path: Path) -> None:
        pm = _pm(tmp_path / "data")
        assert pm.get_key_store() == {}

    def test_both_moved_aside_is_empty(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        _add_key(_pm(data), "operator")
        (data / "keys.json").rename(data / "keys.json.old")
        (data / "keys.json.bak").rename(data / "keys.json.bak.old")
        assert _pm(data).get_key_store() == {}

    def test_empty_backup_is_a_fresh_store(self, tmp_path: Path) -> None:
        data = tmp_path / "data"
        data.mkdir()
        (data / "keys.json.bak").write_text(json.dumps({"keys": {}}))
        assert _pm(data).get_key_store() == {}
