"""Multi-worker merge and fail-closed guards of the JSON persistence layer.

Two :class:`PersistenceManager` instances on one data directory stand in
for two bridge workers.  Covers what ``test_persistence_security.py``
leaves out, against real files on disk:

* a pending (unsaved) revocation or disable that meets another worker's
  conflicting change to the same flag keeps the stricter value;
* a pending downgrade survives another worker's write to a different key;
* a pending downgrade that drops the role field (read as viewer) wins over
  another worker's smaller downgrade;
* re-enabling (un-revoking) a key is undone when keys.json cannot be
  written, as any change that grants access;
* a key store whose inter-process lock cannot be taken refuses the change
  and leaves the lock usable;
* the auto-save loop retries a pending revocation even when nothing else
  is dirty;
* a removed or unreadable webhook authority is not recreated by a periodic
  save;
* a whitelist entry removed by one worker is not brought back by another
  worker's stale save;
* an unreadable keys.json is still restored from its backup when the disk
  fills up while its unreadable bytes are copied aside, and no partial copy
  of the key store is left behind.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import hashlib
import json
import os
import threading
import types

import pytest

from sigrift.bridge import persistence as persistence_module
from sigrift.bridge.persistence import KeyStoreWriteError, PersistenceManager
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import hash_credential

GOOD_HOOK = {"id": "h1", "url": "https://hooks.example.invalid/a", "enabled": True}


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch):
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture
def data_dir(tmp_path):
    path = tmp_path / "data"
    path.mkdir()
    return path


@pytest.fixture
def full_disk(monkeypatch):
    """``full_disk["on"] = True`` makes every keys.json write fail (ENOSPC).

    Patches the module-level writer, so it works as root too and leaves
    keys.json.bak and the other state files writable.
    """
    real_write = persistence_module._atomic_write
    state = {"on": False}

    def write(path, data, *args, **kwargs):
        if state["on"] and os.path.basename(path) == "keys.json":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(persistence_module, "_atomic_write", write)
    return state


def manager(data_dir, **kwargs):
    kwargs.setdefault("auto_save_interval", 0)
    pm = PersistenceManager(data_dir=data_dir, **kwargs)
    pm.load_all()
    return pm


def add(pm, key_id, role="viewer", **meta):
    raw = f"raw-{key_id}"
    hash_hex, salt = hash_credential(raw)
    assert pm.add_key(
        key_id,
        hash_hex,
        salt,
        lookup_hash=hashlib.sha256(raw.encode()).hexdigest(),
        meta={"role": role, **meta},
    )


def disk_keys(data_dir):
    return json.loads((data_dir / "keys.json").read_text())["keys"]


def pending(full_disk, change):
    """Run *change* while keys.json cannot be written; it stays applied here."""
    full_disk["on"] = True
    try:
        with pytest.raises(KeyStoreWriteError) as excinfo:
            change()
        assert excinfo.value.applied_here is True
    finally:
        full_disk["on"] = False


# ---------------------------------------------------------------------------
# keys.json: conflicting changes of two workers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "restricted", "granted"),
    [("revoked", True, False), ("enabled", False, True)],
)
def test_conflicting_flag_changes_keep_the_key_restricted(
    data_dir, full_disk, field, restricted, granted
):
    """A pending revoke/disable wins over another worker's re-enable of the key."""
    a = manager(data_dir)
    add(a, "k1", role="admin")
    b = manager(data_dir)
    pending(
        full_disk,
        lambda: a.set_key_meta("k1", {**a.get_key_meta()["k1"], field: restricted}),
    )

    # Meanwhile another worker saves the opposite value for the same flag.
    b.set_key_meta("k1", {**b.get_key_meta()["k1"], field: granted})
    assert disk_keys(data_dir)["k1"][field] is granted

    a.save_all()  # the retried save merges both changes
    assert disk_keys(data_dir)["k1"][field] is restricted
    assert a.get_key_meta()["k1"][field] is restricted
    assert manager(data_dir).get_key_meta()["k1"][field] is restricted
    # Neither worker's view lets the key in again: B re-reads keys.json.
    assert b.get_key_auth_snapshot()[1]["k1"][field] is restricted


def test_a_pending_downgrade_survives_another_workers_write_to_another_key(
    data_dir, full_disk
):
    a = manager(data_dir)
    add(a, "k1", role="admin")
    b = manager(data_dir)
    pending(full_disk, lambda: a.update_key_role("k1", "viewer"))
    assert disk_keys(data_dir)["k1"]["role"] == "admin"

    add(b, "k2", role="analyst")  # B writes keys.json for an unrelated key

    a.save_all()
    saved = disk_keys(data_dir)
    assert saved["k1"]["role"] == "viewer"
    assert saved["k2"]["role"] == "analyst"
    fresh = manager(data_dir).get_key_meta()
    assert (fresh["k1"]["role"], fresh["k2"]["role"]) == ("viewer", "analyst")
    assert a.get_saved_key_meta("k1")["role"] == "viewer"


def test_a_pending_downgrade_that_drops_the_role_wins_over_a_smaller_one(
    data_dir, full_disk
):
    """No role reads as viewer: it is stricter than the analyst role B saved."""
    a = manager(data_dir)
    add(a, "k1", role="admin")
    b = manager(data_dir)
    roleless = {k: v for k, v in a.get_key_meta()["k1"].items() if k != "role"}
    pending(full_disk, lambda: a.set_key_meta("k1", roleless))

    assert b.update_key_role("k1", "analyst")
    assert disk_keys(data_dir)["k1"]["role"] == "analyst"

    a.save_all()
    assert "role" not in disk_keys(data_dir)["k1"]
    views = {
        "here": a.get_key_meta()["k1"],
        "other worker": b.get_key_auth_snapshot()[1]["k1"],
        "restart": manager(data_dir).get_key_meta()["k1"],
    }
    assert {view: meta.get("role", "viewer") for view, meta in views.items()} == {
        view: "viewer" for view in views
    }
    assert set(manager(data_dir).get_key_store()) == {"k1"}  # still a key


@pytest.mark.parametrize(
    "unrevoke",
    [
        lambda meta: {**meta, "revoked": False},
        lambda meta: {k: v for k, v in meta.items() if k != "revoked"},
    ],
    ids=["revoked-false", "revoked-dropped"],
)
def test_unrevoking_a_key_is_undone_when_it_cannot_be_saved(
    data_dir, full_disk, unrevoke
):
    pm = manager(data_dir)
    add(pm, "k1", role="admin", revoked=True)
    on_disk = (data_dir / "keys.json").read_bytes()

    full_disk["on"] = True
    try:
        with pytest.raises(KeyStoreWriteError) as excinfo:
            pm.set_key_meta("k1", unrevoke(pm.get_key_meta()["k1"]))
        assert excinfo.value.applied_here is False
    finally:
        full_disk["on"] = False

    assert pm.get_key_meta()["k1"]["revoked"] is True
    pm.save_all()  # nothing is pending: the undone change is not retried
    assert (data_dir / "keys.json").read_bytes() == on_disk
    assert manager(data_dir).get_key_meta()["k1"]["revoked"] is True


# ---------------------------------------------------------------------------
# The inter-process lock
# ---------------------------------------------------------------------------


def test_a_key_store_lock_that_cannot_be_taken_refuses_the_change(
    data_dir, monkeypatch
):
    """flock failing (EIO, ENOLCK on NFS): nothing changes and the lock stays usable."""
    pm = manager(data_dir)
    add(pm, "k1", role="admin")
    on_disk = (data_dir / "keys.json").read_bytes()

    def failing_flock(fd, operation):
        if operation == fcntl.LOCK_EX:
            raise OSError(errno.ENOLCK, "No locks available")
        return fcntl.flock(fd, operation)

    stub = types.SimpleNamespace(
        LOCK_EX=fcntl.LOCK_EX, LOCK_UN=fcntl.LOCK_UN, flock=failing_flock
    )
    with monkeypatch.context() as patch:
        patch.setattr(persistence_module, "_fcntl", stub)
        for change in (
            lambda: pm.remove_key("k1"),
            lambda: add(pm, "k2", role="admin"),
        ):
            with pytest.raises(KeyStoreWriteError) as excinfo:
                change()
            assert excinfo.value.applied_here is False
            assert ".persistence.lock" in str(excinfo.value)
    assert set(pm.get_key_store()) == {"k1"}
    assert (data_dir / "keys.json").read_bytes() == on_disk

    # The failed attempts left no lock held: another thread can revoke now.
    outcome = {}

    def revoke():
        outcome["removed"] = pm.remove_key("k1")

    worker = threading.Thread(target=revoke, daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "the key lock was left held by the failed attempt"
    assert outcome == {"removed": True}
    assert "k1" not in disk_keys(data_dir)


# ---------------------------------------------------------------------------
# Auto-save retries a pending revocation
# ---------------------------------------------------------------------------


def test_auto_save_retries_a_pending_revocation_when_nothing_else_changed(
    data_dir, full_disk, monkeypatch
):
    interval = 3600.0
    pm = manager(data_dir, auto_save_interval=interval)
    add(pm, "k1", role="admin")
    add(pm, "k2")
    pending(full_disk, lambda: pm.remove_key("k1"))
    # A periodic save while the disk is still full: the other state files
    # are saved (nothing else is dirty now), keys.json still is not.
    full_disk["on"] = True
    pm.save_all()
    full_disk["on"] = False
    assert "k1" in disk_keys(data_dir)

    real_sleep = asyncio.sleep
    ticks = {"n": 0}

    async def run() -> set:
        second_tick = asyncio.Event()

        async def fake_sleep(delay, *args, **kwargs):
            if delay != interval:
                return await real_sleep(delay, *args, **kwargs)
            ticks["n"] += 1
            if ticks["n"] == 1:
                return None  # the first interval elapses at once
            second_tick.set()  # one full loop iteration is done
            await asyncio.Event().wait()  # park until cancelled

        with monkeypatch.context() as patch:
            patch.setattr(asyncio, "sleep", fake_sleep)
            await pm.start_auto_save()
            await second_tick.wait()
            saved = set(disk_keys(data_dir))
        await pm.stop_auto_save()
        return saved

    assert asyncio.run(run()) == {"k2"}
    assert set(manager(data_dir).get_key_store()) == {"k2"}


# ---------------------------------------------------------------------------
# Webhook authority
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("damage", ["removed", "unreadable"])
def test_a_lost_webhook_authority_is_not_recreated_by_a_periodic_save(
    data_dir, damage, caplog
):
    pm = manager(data_dir)
    pm.set_webhooks([GOOD_HOOK])
    path = data_dir / "webhooks.json"
    if damage == "removed":
        path.unlink()
    else:
        path.write_text("{not json")
    pm.set_node("n1", {"status": "online"})

    pm.save_all()

    if damage == "removed":
        assert not path.exists()
    else:
        assert path.read_text() == "{not json"
    assert "Failed to save webhooks.json" in caplog.text
    # The rest of the state is saved; the failure is retried by the next save.
    assert json.loads((data_dir / "nodes.json").read_text())["nodes"] == {
        "n1": {"status": "online"}
    }
    pm.save_all()
    if damage == "removed":
        assert not path.exists()
    # Delivery workers keep seeing the failure instead of "no endpoints".
    expected = (
        FileNotFoundError if damage == "removed" else persistence_module._UnreadableFile
    )
    with pytest.raises(expected):
        pm.current_webhooks()


# ---------------------------------------------------------------------------
# List state files: per-item merge
# ---------------------------------------------------------------------------


def test_a_removed_whitelist_entry_is_not_brought_back_by_a_stale_worker(data_dir):
    """Revoking trust in an AP survives other workers' saves of their snapshot."""
    ap = {"bssid": "aa:aa:aa:aa:aa:aa", "ssid": "corp"}
    other = {"bssid": "bb:bb:bb:bb:bb:bb", "ssid": "lab"}
    seed = manager(data_dir)
    seed.set_wifi_whitelist([ap, other])
    seed.save_all()

    a = manager(data_dir)
    b = manager(data_dir)
    added = {"bssid": "cc:cc:cc:cc:cc:cc", "ssid": "guest"}
    a.set_wifi_whitelist([*a.get_wifi_whitelist(), added])
    a.save_all()

    # B, which has not seen A's addition, revokes ap and edits other.
    edited = {**other, "note": "reviewed"}
    b.set_wifi_whitelist([edited])
    b.save_all()

    def on_disk():
        return json.loads((data_dir / "wifi_whitelist.json").read_text())["whitelist"]

    expected = [edited, added]
    assert on_disk() == expected
    assert b.get_wifi_whitelist() == expected  # B adopts A's addition

    # A still holds ap in memory; its next save must not write it back.
    a.set_node("n1", {"status": "online"})
    a.save_all()
    assert on_disk() == expected
    assert a.get_wifi_whitelist() == expected
    assert manager(data_dir).get_wifi_whitelist() == expected


# ---------------------------------------------------------------------------
# Recovery of an unreadable keys.json
# ---------------------------------------------------------------------------


class _DiskFillsUp:
    """A binary file that takes half of what is written, then fails with ENOSPC."""

    def __init__(self, real):
        self._real = real

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._real.close()
        return False

    def fileno(self):
        return self._real.fileno()

    def flush(self):
        return self._real.flush()

    def write(self, data):
        self._real.write(data[: len(data) // 2])
        self._real.flush()
        raise OSError(errno.ENOSPC, "No space left on device")


def test_a_full_disk_while_keeping_the_unreadable_key_store_leaves_no_partial_copy(
    data_dir, monkeypatch, caplog
):
    pm = manager(data_dir)
    add(pm, "k1", role="admin")
    (data_dir / "keys.json").write_text('{"keys": {"k1": ')  # torn write
    real_fdopen = os.fdopen

    def fdopen(fd, mode="r", *args, **kwargs):
        handle = real_fdopen(fd, mode, *args, **kwargs)
        # Binary writes are the copy of the unreadable file; the JSON state
        # files (the restored keys.json among them) are written as text.
        return _DiskFillsUp(handle) if mode == "wb" else handle

    with monkeypatch.context() as patch:
        patch.setattr(persistence_module.os, "fdopen", fdopen)
        restored = manager(data_dir)

    assert set(restored.get_key_store()) == {"k1"}
    assert set(disk_keys(data_dir)) == {"k1"}  # the gateway reads it again
    assert "Could not keep a copy of the unreadable keys.json" in caplog.text
    leftovers = sorted(p.name for p in data_dir.iterdir() if "corrupt" in p.name)
    assert leftovers == []
