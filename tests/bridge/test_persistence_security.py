"""Security paths of the JSON persistence layer, against real files on disk.

Covers what the existing persistence suites leave out: the edge-key role
guard, malformed key entries, trust-on-first-use node binding (K4/K7b) and
explicit rebinding, revocation durability when keys.json cannot be written
(pending revocations and downgrades, their retry and audit, the lock file,
startup refusals), the session-binding preference, webhook-authority refusals, config
snapshots (key store never captured, malformed rows, retention, restore
targets), and tampered state files.  End-to-end checks go through the real
admin key routes and read keys.json and the audit log back.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone

import pytest

from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import hash_credential
from sigrift.bridge import persistence as persistence_module
from sigrift.bridge.dependencies import Role, stored_key_role
from sigrift.bridge.persistence import (
    ConfigSnapshotRejected,
    ConfigSnapshotRestoreError,
    KeyStoreCorruptError,
    KeyStoreWriteError,
    NodeAlreadyBound,
    PersistenceManager,
)
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.utils import KEY_CHANGE_NOT_SAVED, KEY_CHANGE_PENDING

EDGE_PREFIXES = ("node_", "rtlsdr_", "hackrf_", "sensor_", "edge_", "sdr_")


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch):
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture
def data_dir(tmp_path):
    path = tmp_path / "data"
    path.mkdir()
    return path


def manager(data_dir):
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    pm.load_all()
    return pm


def entry(raw, role="viewer", **extra):
    hash_hex, salt = hash_credential(raw)
    return {
        "hash": hash_hex,
        "salt": salt.hex(),
        "lookup_hash": hashlib.sha256(raw.encode()).hexdigest(),
        "role": role,
        "description": "",
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires_at": None,
        **extra,
    }


def write_keys(data_dir, entries):
    (data_dir / "keys.json").write_text(json.dumps({"keys": entries}))


def disk_keys(data_dir, name="keys.json"):
    return json.loads((data_dir / name).read_text())["keys"]


def signature(path):
    st = os.stat(path)
    return (st.st_ino, st.st_size, st.st_mtime_ns)


def add(pm, key_id, raw=None, role="viewer", **meta):
    raw = raw or f"raw-{key_id}"
    hash_hex, salt = hash_credential(raw)
    assert pm.add_key(
        key_id,
        hash_hex,
        salt,
        lookup_hash=hashlib.sha256(raw.encode()).hexdigest(),
        meta={"role": role, **meta},
    )


# ---------------------------------------------------------------------------
# Edge/sensor keys never carry analyst-or-higher privileges
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", EDGE_PREFIXES)
@pytest.mark.parametrize("role", ["admin", "analyst"])
def test_edge_keys_lose_elevated_roles_on_load(data_dir, prefix, role, caplog):
    key_id = f"{prefix}01"
    write_keys(data_dir, {key_id: entry("r1", role=role, node_id="n1")})
    pm = manager(data_dir)

    meta = pm.get_key_meta()[key_id]
    assert meta["role"] == "node"
    assert meta["node_id"] == "n1"
    assert stored_key_role(key_id, meta) == Role.NODE
    assert f"Downgrading edge key {key_id}" in caplog.text


@pytest.mark.parametrize(
    ("key_id", "role", "expected"),
    [
        ("node_01", "viewer", "viewer"),
        ("sensor_01", "sensor", "sensor"),
        ("ops_admin", "admin", "admin"),
        ("nodes-admin", "admin", "admin"),
        ("my_node_key", "analyst", "analyst"),
    ],
)
def test_role_guard_matches_prefixes_only(data_dir, key_id, role, expected):
    write_keys(data_dir, {key_id: entry("r1", role=role)})
    assert manager(data_dir).get_key_meta()[key_id]["role"] == expected


@pytest.mark.parametrize("role", ["keymaster", "ADMIN", "Analyst", "KeyMaster"])
def test_edge_keys_never_load_with_a_role_above_viewer(data_dir, role):
    write_keys(data_dir, {"node_01": entry("r1", role=role)})
    meta = manager(data_dir).get_key_meta()["node_01"]
    assert stored_key_role("node_01", meta) < Role.ANALYST


@pytest.mark.parametrize("how", ["update_key_role", "add_key"])
def test_edge_keys_cannot_be_elevated_at_runtime(data_dir, how):
    pm = manager(data_dir)
    if how == "update_key_role":
        add(pm, "node_01", role="node")
        pm.update_key_role("node_01", "admin")
    else:
        add(pm, "node_01", role="admin")
    assert stored_key_role("node_01", pm.get_key_meta()["node_01"]) < Role.ANALYST


def test_the_guard_ranks_roles_as_auth_does():
    assert persistence_module._ROLE_ORDER == tuple(r.name for r in sorted(Role))


@pytest.mark.parametrize("role", ["admin", "Analyst", "KeyMaster"])
@pytest.mark.parametrize("how", ["set_key_meta", "rotate", "rotate_default"])
def test_every_runtime_role_write_keeps_edge_keys_node(data_dir, how, role, caplog):
    pm = manager(data_dir)
    new_hash, new_salt = hash_credential("new-raw")
    if how == "set_key_meta":
        add(pm, "sensor_01", role="sensor")
        pm.set_key_meta("sensor_01", {**pm.get_key_meta()["sensor_01"], "role": role})
    elif how == "rotate":
        add(pm, "sensor_01", role="sensor")
        pm.replace_key_credential(
            "sensor_01",
            new_hash,
            new_salt,
            lookup_hash=None,
            meta_update={"role": role},
        )
    else:
        pm.set_key("sensor_01", *hash_credential("r1"))
        pm.replace_key_credential(
            "sensor_01",
            new_hash,
            new_salt,
            lookup_hash=None,
            meta_default={"role": role},
        )
    assert pm.get_key_meta()["sensor_01"]["role"] == "node"
    assert disk_keys(data_dir)["sensor_01"]["role"] == "node"
    other_worker = manager(data_dir).get_key_meta()["sensor_01"]
    assert stored_key_role("sensor_01", other_worker) == Role.NODE
    assert "Downgrading edge key sensor_01" in caplog.text


@pytest.mark.parametrize("role", ["viewer", "node", "sensor", "unknown"])
def test_edge_keys_keep_roles_up_to_viewer_at_runtime(data_dir, role):
    pm = manager(data_dir)
    add(pm, "node_01", role="node")
    assert pm.update_key_role("node_01", role) is True
    assert pm.get_key_meta()["node_01"]["role"] == role
    assert disk_keys(data_dir)["node_01"]["role"] == role


def test_malformed_key_entries_never_authenticate(data_dir, caplog):
    write_keys(
        data_dir,
        {
            "good": entry("good-raw", role="analyst"),
            "bad_salt": {**entry("x"), "salt": "zz-not-hex"},
            "none_salt": {**entry("y"), "salt": None},
            "not_a_dict": "admin",
        },
    )
    pm = manager(data_dir)
    assert set(pm.get_key_store()) == {"good"}
    assert set(pm.get_key_meta()) == {"good"}
    assert set(pm.get_indexed_key_ids()) == {"good"}
    assert "Invalid salt for key bad_salt" in caplog.text


# A key section that holds no usable key is not an empty key store: read as
# one, startup also replaced keys.json.bak with it, so the keys were lost.
_UNUSABLE_KEY_SECTIONS = {
    "list": lambda: [entry("r")],
    "string": lambda: "admin",
    "number": lambda: 5,
    "all-invalid": lambda: {"a": "admin", "b": {**entry("x"), "salt": "zz"}},
}


@pytest.mark.parametrize("section", sorted(_UNUSABLE_KEY_SECTIONS))
def test_an_unusable_key_section_is_restored_from_the_backup(data_dir, section):
    pm = manager(data_dir)
    add(pm, "operator", raw="operator-raw", role="analyst")
    backup = (data_dir / "keys.json.bak").read_bytes()
    bad = json.dumps({"keys": _UNUSABLE_KEY_SECTIONS[section]()})
    (data_dir / "keys.json").write_text(bad)

    restored = manager(data_dir)
    assert set(restored.get_key_store()) == {"operator"}
    assert (data_dir / "keys.json.bak").read_bytes() == backup
    assert set(disk_keys(data_dir)) == {"operator"}
    kept = [p for p in data_dir.iterdir() if ".corrupt-" in p.name]
    assert [p.read_text() for p in kept] == [bad]


@pytest.mark.parametrize("section", sorted(_UNUSABLE_KEY_SECTIONS))
def test_an_unusable_key_section_without_a_backup_refuses_startup(data_dir, section):
    bad = json.dumps({"keys": _UNUSABLE_KEY_SECTIONS[section]()})
    (data_dir / "keys.json").write_text(bad)
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    with pytest.raises(KeyStoreCorruptError):
        pm.load_all()
    assert (data_dir / "keys.json").read_text() == bad
    assert not (data_dir / "keys.json.bak").exists()


@pytest.mark.parametrize(
    "missing", [True, False], ids=["keys-missing", "keys-unreadable"]
)
def test_an_unusable_backup_is_not_restored(data_dir, missing):
    (data_dir / "keys.json.bak").write_text(json.dumps({"keys": [entry("r")]}))
    if not missing:
        (data_dir / "keys.json").write_text("{truncated")
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    with pytest.raises(KeyStoreCorruptError):
        pm.load_all()
    assert not missing or not (data_dir / "keys.json").exists()


@pytest.mark.parametrize("content", [{}, {"keys": {}}, {"keys": None}])
def test_an_empty_key_section_is_an_empty_key_store(data_dir, content):
    (data_dir / "keys.json").write_text(json.dumps(content))
    pm = manager(data_dir)
    assert pm.get_key_store() == {}
    assert pm.get_key_fast_index() == {}


@pytest.mark.parametrize("section", sorted(_UNUSABLE_KEY_SECTIONS))
def test_an_unusable_key_section_at_runtime_keeps_the_last_good_set(
    data_dir, section, caplog
):
    pm = manager(data_dir)
    add(pm, "operator", raw="operator-raw")
    (data_dir / "keys.json").write_text(
        json.dumps({"keys": _UNUSABLE_KEY_SECTIONS[section]()})
    )
    with pm._key_lock:
        pm._refresh_keys_locked()
    assert set(pm.get_key_store()) == {"operator"}
    assert "cannot be read" in caplog.text
    # The next key change writes the last good set back, not an empty one.
    add(pm, "second", raw="second-raw")
    assert set(disk_keys(data_dir)) == {"operator", "second"}
    assert set(disk_keys(data_dir, "keys.json.bak")) == {"operator", "second"}


# ---------------------------------------------------------------------------
# Unknown keys: no change, no write
# ---------------------------------------------------------------------------


def test_operations_on_unknown_keys_change_nothing_on_disk(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    path = data_dir / "keys.json"
    before = (signature(path), path.read_bytes())

    assert pm.remove_key("missing") is False
    assert pm.update_key_role("missing", "admin") is False
    assert pm.set_key_node("missing", "n1") is False
    assert pm.bind_key_to_node("missing", "n1") is None
    assert pm.has_key("missing") is False
    assert (
        pm.replace_key_credential("missing", "ab" * 32, b"s" * 16, lookup_hash=None)
        is None
    )

    assert (signature(path), path.read_bytes()) == before
    assert set(pm.get_key_meta()) == {"k1"}


def test_key_files_stay_owner_only_after_every_kind_of_change(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    pm.update_key_role("k1", "analyst")
    pm.set_key_node("k1", "n1")
    pm.remove_key("k1")
    for name in ("keys.json", "keys.json.bak"):
        assert stat.S_IMODE(os.stat(data_dir / name).st_mode) == 0o600


# ---------------------------------------------------------------------------
# Node binding: trust on first use (K4) and explicit admin binding (K7b)
# ---------------------------------------------------------------------------


def holder_of(node_id):
    return lambda other, meta: meta.get("node_id") == node_id


def test_first_binding_wins_and_is_durable(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    assert pm.bind_key_to_node("k1", "n1") == "n1"
    assert disk_keys(data_dir)["k1"]["node_id"] == "n1"
    assert disk_keys(data_dir, "keys.json.bak")["k1"]["node_id"] == "n1"

    path = data_dir / "keys.json"
    before = signature(path)
    # A later first-use claim for another node never moves the binding.
    assert pm.bind_key_to_node("k1", "n2") == "n1"
    assert signature(path) == before
    assert manager(data_dir).get_key_meta()["k1"]["node_id"] == "n1"


def test_binding_refuses_a_node_another_key_holds(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    add(pm, "k2")
    pm.bind_key_to_node("k1", "n1", holds_node=holder_of("n1"))

    with pytest.raises(NodeAlreadyBound) as excinfo:
        pm.bind_key_to_node("k2", "n1", holds_node=holder_of("n1"))
    assert (excinfo.value.node_id, excinfo.value.owner_key_id) == ("n1", "k1")
    assert "already has a bound key" in str(excinfo.value)
    assert "node_id" not in pm.get_key_meta()["k2"]
    assert "node_id" not in disk_keys(data_dir)["k2"]

    # The key's own binding is never counted against it.
    assert pm.bind_key_to_node("k2", "n2", holds_node=holder_of("n2")) == "n2"


def test_empty_binding_is_treated_as_unbound(data_dir):
    pm = manager(data_dir)
    add(pm, "k1", node_id="")
    assert pm.bind_key_to_node("k1", "n1") == "n1"
    assert disk_keys(data_dir)["k1"]["node_id"] == "n1"


def test_explicit_binding_rebinds_and_unbinds_durably(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    pm.bind_key_to_node("k1", "n1")
    assert pm.set_key_node("k1", "n2") is True
    assert disk_keys(data_dir)["k1"]["node_id"] == "n2"
    assert pm.set_key_node("k1", None) is True
    assert "node_id" not in disk_keys(data_dir)["k1"]
    assert "node_id" not in manager(data_dir).get_key_meta()["k1"]
    assert pm.set_key_node("k1", "") is True
    assert "node_id" not in disk_keys(data_dir)["k1"]


# ---------------------------------------------------------------------------
# Revocation when keys.json cannot be written
# ---------------------------------------------------------------------------

needs_unprivileged = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0,
    reason="root ignores directory permissions",
)


@needs_unprivileged
def test_unwritten_revocation_is_retried_by_the_next_save(data_dir, caplog):
    pm = manager(data_dir)
    add(pm, "k1")
    add(pm, "k2")
    os.chmod(data_dir, 0o500)
    try:
        with pytest.raises(OSError):
            pm.remove_key("k1")
        assert "k1" not in pm.get_key_store()
        assert "Failed to save keys" in caplog.text
        assert "k1" in disk_keys(data_dir)
    finally:
        os.chmod(data_dir, 0o700)

    pm.save_all()
    assert set(disk_keys(data_dir)) == {"k2"}
    assert set(disk_keys(data_dir, "keys.json.bak")) == {"k2"}
    assert set(manager(data_dir).get_key_store()) == {"k2"}


@needs_unprivileged
def test_revocation_is_never_reported_while_the_key_stays_on_disk(data_dir):
    pm = manager(data_dir)
    add(pm, "k1")
    other_worker = manager(data_dir)
    os.chmod(data_dir, 0o500)
    try:
        try:
            result = pm.remove_key("k1")
        except OSError:
            result = None
        still_on_disk = "k1" in disk_keys(data_dir)
        still_accepted = "k1" in other_worker.get_key_auth_snapshot()[0]
    finally:
        os.chmod(data_dir, 0o700)
    if result is True:
        assert not still_on_disk
        assert not still_accepted


@needs_unprivileged
def test_unsaved_key_changes_that_grant_access_are_undone(data_dir):
    pm = manager(data_dir)
    add(pm, "k1", role="viewer")
    state = (pm.get_key_store(), pm.get_key_meta(), pm.get_key_fast_index())
    on_disk = (data_dir / "keys.json").read_bytes()
    new_hash, new_salt = hash_credential("new-raw")
    changes = [
        lambda: add(pm, "k2"),
        lambda: pm.set_key("k3", new_hash, new_salt, lookup_hash="ab" * 32),
        lambda: pm.update_key_role("k1", "admin"),
        lambda: pm.replace_key_credential(
            "k1", new_hash, new_salt, lookup_hash="cd" * 32, meta_update={"x": 1}
        ),
        lambda: pm.set_key_node("k1", "n1"),
        lambda: pm.bind_key_to_node("k1", "n1"),
        lambda: pm.set_key_meta("k1", {**state[1]["k1"], "role": "analyst"}),
        lambda: pm.set_key_meta("k1", {**state[1]["k1"], "enabled": True}),
    ]
    os.chmod(data_dir, 0o500)
    try:
        for change in changes:
            with pytest.raises(KeyStoreWriteError):
                change()
            assert (
                pm.get_key_store(),
                pm.get_key_meta(),
                pm.get_key_fast_index(),
            ) == state
    finally:
        os.chmod(data_dir, 0o700)
    pm.save_all()
    assert (data_dir / "keys.json").read_bytes() == on_disk


@needs_unprivileged
def test_unsaved_downgrades_stay_in_effect_and_are_retried(data_dir):
    pm = manager(data_dir)
    add(pm, "k1", role="admin")
    add(pm, "k2", role="analyst")
    os.chmod(data_dir, 0o500)
    try:
        with pytest.raises(KeyStoreWriteError):
            pm.update_key_role("k1", "viewer")
        with pytest.raises(KeyStoreWriteError):
            pm.set_key_meta("k2", {**pm.get_key_meta()["k2"], "revoked": True})
        assert pm.get_key_meta()["k1"]["role"] == "viewer"
        assert pm.get_key_meta()["k2"]["revoked"] is True
        assert disk_keys(data_dir)["k1"]["role"] == "admin"
        pm.save_all()  # periodic saves still only log the failure
    finally:
        os.chmod(data_dir, 0o700)
    pm.save_all()
    fresh = manager(data_dir).get_key_meta()
    assert (fresh["k1"]["role"], fresh["k2"]["revoked"]) == ("viewer", True)


@needs_unprivileged
def test_repeating_an_unsaved_revocation_retries_it(data_dir):
    pm = manager(data_dir)
    add(pm, "k1", role="admin")
    add(pm, "k2")
    os.chmod(data_dir, 0o500)
    try:
        for _attempt in range(2):
            with pytest.raises(KeyStoreWriteError) as excinfo:
                pm.remove_key("k1")
            assert excinfo.value.applied_here is True
        assert "k1" not in pm.get_key_store()
        # What the other workers and the gateway still see.
        assert pm.get_saved_key_meta("k1")["role"] == "admin"
    finally:
        os.chmod(data_dir, 0o700)
    assert pm.remove_key("k1") is True
    assert set(disk_keys(data_dir)) == {"k2"}
    assert pm.get_saved_key_meta("k1") is None
    assert pm.remove_key("k1") is False


@needs_unprivileged
def test_saved_key_meta_shows_unsaved_downgrades(data_dir):
    from sigrift.bridge.dependencies import highest_key_role

    pm = manager(data_dir)
    add(pm, "k1", role="keymaster")
    # As keys.json holds it, i.e. as another worker loads it.
    assert pm.get_saved_key_meta("k1") == manager(data_dir).get_key_meta()["k1"]
    assert pm.get_saved_key_meta("missing") is None
    os.chmod(data_dir, 0o500)
    try:
        with pytest.raises(KeyStoreWriteError) as excinfo:
            pm.update_key_role("k1", "viewer")
        assert excinfo.value.applied_here is True
        with pytest.raises(KeyStoreWriteError) as excinfo:
            pm.update_key_role("k1", "admin")  # not a downgrade from viewer
        assert excinfo.value.applied_here is False
    finally:
        os.chmod(data_dir, 0o700)
    assert pm.get_key_meta()["k1"]["role"] == "viewer"
    assert pm.get_saved_key_meta("k1")["role"] == "keymaster"
    assert highest_key_role(pm, "k1") == Role.KEYMASTER
    pm.save_all()
    assert pm.get_saved_key_meta("k1")["role"] == "viewer"
    assert highest_key_role(pm, "k1") == Role.VIEWER


@needs_unprivileged
def test_a_key_store_that_cannot_be_locked_refuses_key_changes(data_dir):
    pm = manager(data_dir)
    add(pm, "k1", role="admin")
    state = (pm.get_key_store(), pm.get_key_meta(), pm.get_key_fast_index())
    on_disk = (data_dir / "keys.json").read_bytes()
    new_hash, new_salt = hash_credential("new-raw")
    changes = [
        lambda: pm.remove_key("k1"),
        lambda: pm.update_key_role("k1", "viewer"),
        lambda: add(pm, "k2"),
        lambda: pm.set_key("k3", new_hash, new_salt, lookup_hash=None),
        lambda: pm.bind_key_to_node("k1", "n1"),
    ]
    # A read-only (or full) data directory without the lock file.
    (data_dir / ".persistence.lock").unlink()
    os.chmod(data_dir, 0o500)
    try:
        for change in changes:
            with pytest.raises(KeyStoreWriteError) as excinfo:
                change()
            assert excinfo.value.applied_here is False
            assert ".persistence.lock" in str(excinfo.value)
            assert (
                pm.get_key_store(),
                pm.get_key_meta(),
                pm.get_key_fast_index(),
            ) == state
    finally:
        os.chmod(data_dir, 0o700)
    assert (data_dir / "keys.json").read_bytes() == on_disk


# ---------------------------------------------------------------------------
# A pending (unsaved) restriction meets another worker's later key change.
# Two managers on one data directory stand in for two bridge workers.


@pytest.fixture
def full_disk(monkeypatch):
    """``full_disk["on"] = True`` makes every keys.json write fail (ENOSPC).

    Patches the module-level writer, so it does not depend on directory
    permissions (works as root) and leaves keys.json.bak writable.
    """
    real_write = persistence_module._atomic_write
    state = {"on": False}

    def write(path, data, *args, **kwargs):
        if state["on"] and os.path.basename(path) == "keys.json":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(persistence_module, "_atomic_write", write)
    return state


def pending_change(full_disk, change):
    """Run *change* while keys.json cannot be written; it stays applied here."""
    full_disk["on"] = True
    try:
        with pytest.raises(KeyStoreWriteError) as excinfo:
            change()
        assert excinfo.value.applied_here is True
    finally:
        full_disk["on"] = False


@pytest.mark.parametrize(
    "restrict",
    [
        lambda pm: pm.update_key_role("k1", "viewer"),
        lambda pm: pm.set_key_meta("k1", {**pm.get_key_meta()["k1"], "revoked": True}),
        lambda pm: pm.set_key_meta("k1", {**pm.get_key_meta()["k1"], "enabled": False}),
    ],
    ids=["downgrade", "revoked-flag", "disabled"],
)
def test_a_pending_restriction_never_undoes_another_workers_revocation(
    data_dir, full_disk, restrict
):
    a = manager(data_dir)
    add(a, "k1", role="admin")
    add(a, "k2")
    b = manager(data_dir)
    pending_change(full_disk, lambda: restrict(a))

    # The disk has room again; another worker revokes the key.
    assert b.remove_key("k1") is True
    assert "k1" not in disk_keys(data_dir)

    # Worker A picks the revocation up as soon as it re-reads keys.json...
    assert "k1" not in a.get_key_auth_snapshot()[0]
    # ...and its retried save (auto-save) does not write the key back.
    a.save_all()
    assert set(disk_keys(data_dir)) == {"k2"}
    assert set(manager(data_dir).get_key_store()) == {"k2"}
    assert "k1" not in a.get_key_store()


def test_a_pending_downgrade_keeps_another_workers_rotated_credential(
    data_dir, full_disk
):
    a = manager(data_dir)
    add(a, "k1", raw="old-raw", role="admin")
    b = manager(data_dir)
    old_entry = disk_keys(data_dir)["k1"]
    pending_change(full_disk, lambda: a.update_key_role("k1", "viewer"))

    # Another worker rotates the key (e.g. after a leak).
    new_hash, new_salt = hash_credential("new-raw")
    new_lookup = hashlib.sha256(b"new-raw").hexdigest()
    assert b.replace_key_credential(
        "k1",
        new_hash,
        new_salt,
        lookup_hash=new_lookup,
        meta_update={"rotated_at": "2026-11-09T00:00:00+00:00"},
    )

    a.save_all()
    saved = disk_keys(data_dir)["k1"]
    # The new credential stays; the old (leaked) one is not brought back.
    assert (saved["hash"], saved["salt"], saved["lookup_hash"]) == (
        new_hash,
        new_salt.hex(),
        new_lookup,
    )
    assert saved["hash"] != old_entry["hash"]
    # Both changes are kept: the rotation's metadata and A's downgrade.
    assert saved["rotated_at"] == "2026-11-09T00:00:00+00:00"
    assert saved["role"] == "viewer"
    for pm in (a, manager(data_dir)):
        assert pm.get_key_store()["k1"] == (new_hash, new_salt)
        assert pm.get_key_fast_index() == {new_lookup: "k1"}
        assert pm.get_key_meta()["k1"]["role"] == "viewer"


@pytest.mark.parametrize(
    ("pending", "saved_later", "expected"),
    [
        ("analyst", "viewer", "viewer"),  # a later, stricter downgrade stays
        ("viewer", "analyst", "viewer"),  # the pending downgrade still lands
    ],
)
def test_conflicting_role_changes_keep_the_lower_role(
    data_dir, full_disk, pending, saved_later, expected
):
    a = manager(data_dir)
    add(a, "k1", role="admin")
    b = manager(data_dir)
    pending_change(full_disk, lambda: a.update_key_role("k1", pending))
    assert b.update_key_role("k1", saved_later) is True

    a.save_all()
    assert disk_keys(data_dir)["k1"]["role"] == expected
    assert a.get_key_meta()["k1"]["role"] == expected
    assert manager(data_dir).get_key_meta()["k1"]["role"] == expected


def test_a_pending_revocation_still_wins_over_a_later_rotation(data_dir, full_disk):
    a = manager(data_dir)
    add(a, "k1", role="admin")
    add(a, "k2")
    b = manager(data_dir)
    pending_change(full_disk, lambda: a.remove_key("k1"))
    new_hash, new_salt = hash_credential("new-raw")
    assert b.replace_key_credential(
        "k1", new_hash, new_salt, lookup_hash=hashlib.sha256(b"new-raw").hexdigest()
    )
    a.save_all()
    assert set(disk_keys(data_dir)) == {"k2"}


def test_unwritable_backup_does_not_block_startup_or_key_writes(data_dir, caplog):
    write_keys(data_dir, {"k1": entry("r1")})
    (data_dir / "keys.json.bak").mkdir()  # cannot be replaced by a file
    pm = manager(data_dir)
    assert set(pm.get_key_store()) == {"k1"}
    assert "Failed to write" in caplog.text

    add(pm, "k2")
    assert set(disk_keys(data_dir)) == {"k1", "k2"}
    assert "Failed to update" in caplog.text


# ---------------------------------------------------------------------------
# Startup when keys.json cannot be written
# ---------------------------------------------------------------------------


def boot(tmp_path, keys_dir, **env_values):
    """Run the real lifespan once, with the key store in *keys_dir*.

    Everything else (database, IQ and pcap stores) lives in a writable
    directory, so only the key store's directory is read-only.
    """
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from .test_lifespan import (
        _lifespan_env,
        _make_app_with_lifespan,
        _patch_data_paths,
        _patch_detection_store,
        _patch_iq_store,
        _patch_pcap_store,
        _patch_persistence_dir,
    )

    data = tmp_path / "other"
    data.mkdir(exist_ok=True)
    app = _make_app_with_lifespan()
    env = _lifespan_env(data)
    env.update(
        {
            "BRIDGE_ENV": "",
            "BRIDGE_MODE": "",
            "BRIDGE_LOCAL_NODE_KEY": "",
            "BRIDGE_MASTER_KEY": "",
            **env_values,
        }
    )
    with (
        patch.dict(os.environ, env),
        _patch_data_paths(data),
        _patch_persistence_dir(keys_dir),
        _patch_detection_store(data),
        _patch_iq_store(data),
        _patch_pcap_store(data),
    ):
        with TestClient(app):
            return app.state.persistence


@pytest.fixture
def read_only_keys_dir(data_dir):
    """*data_dir*, made read-only once the test has set it up.

    With the files startup needs to find (it writes them when missing): the
    lock file and an initialised webhook configuration.
    """
    (data_dir / ".persistence.lock").touch(mode=0o600)
    (data_dir / "webhooks.json").write_text(json.dumps({"webhooks": []}))

    def seal():
        os.chmod(data_dir, 0o500)

    yield seal
    os.chmod(data_dir, 0o700)


@needs_unprivileged
def test_first_start_refuses_to_run_without_a_saved_master_key(
    tmp_path, data_dir, read_only_keys_dir, caplog
):
    read_only_keys_dir()
    # With BRIDGE_MASTER_KEY set the lifespan writes no master_key.txt.
    with pytest.raises(KeyStoreWriteError):
        boot(tmp_path, data_dir, BRIDGE_MASTER_KEY="first-master-raw")
    assert not (data_dir / "keys.json").exists()
    assert "Refusing to start: the initial master key" in caplog.text
    assert str(data_dir / "keys.json") in caplog.text


@needs_unprivileged
def test_start_refuses_a_master_key_out_of_sync_it_cannot_save(
    tmp_path, data_dir, read_only_keys_dir, caplog
):
    write_keys(data_dir, {"master": entry("old-master-raw", role="admin")})
    before = (data_dir / "keys.json").read_bytes()
    read_only_keys_dir()
    with pytest.raises(KeyStoreWriteError):
        boot(tmp_path, data_dir, BRIDGE_MASTER_KEY="new-master-raw")
    assert (data_dir / "keys.json").read_bytes() == before
    assert "Refusing to start: BRIDGE_MASTER_KEY" in caplog.text


@needs_unprivileged
def test_start_only_logs_a_legacy_duplicate_key_it_cannot_remove(
    tmp_path, data_dir, read_only_keys_dir, caplog
):
    from sigrift.bridge.app import (
        _LEGACY_LOCAL_EDGE_DESCRIPTION,
        _LEGACY_LOCAL_EDGE_KEY_ID,
    )

    write_keys(
        data_dir,
        {
            "master": entry("master-raw", role="admin"),
            _LEGACY_LOCAL_EDGE_KEY_ID: entry(
                "edge-raw", role="node", description=_LEGACY_LOCAL_EDGE_DESCRIPTION
            ),
        },
    )
    read_only_keys_dir()
    pm = boot(tmp_path, data_dir)
    assert _LEGACY_LOCAL_EDGE_KEY_ID not in pm.get_key_store()
    assert _LEGACY_LOCAL_EDGE_KEY_ID in disk_keys(data_dir)
    assert "master" in pm.get_key_store()
    assert f"Duplicate API key '{_LEGACY_LOCAL_EDGE_KEY_ID}' removed in memory" in (
        caplog.text
    )


# ---------------------------------------------------------------------------
# Session-binding preference
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode", ["STRICT", "", "none ", "off", "strict'; --", "ip\x00"]
)
def test_invalid_session_binding_is_refused_and_not_written(data_dir, mode):
    pm = manager(data_dir)
    pm.set_session_binding("strict")
    before = (data_dir / "session_binding.json").read_bytes()
    with pytest.raises(ValueError, match="invalid session binding mode"):
        pm.set_session_binding(mode)
    assert (data_dir / "session_binding.json").read_bytes() == before
    assert pm.get_session_binding() == "strict"


@pytest.mark.parametrize("mode", ["strict", "ip", "warn", "none"])
def test_session_binding_survives_restart(data_dir, monkeypatch, mode):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "warn" if mode != "warn" else "ip")
    manager(data_dir).set_session_binding(mode)
    assert manager(data_dir).get_session_binding() == mode


@pytest.mark.parametrize(
    ("saved", "env", "expected"),
    [
        ('{"mode": "disabled"}', "", "none"),
        ('{"mode": "STRICT"}', "IP", "ip"),
        ("not json", " Strict ", "strict"),
        ('["strict"]', "", "none"),
        ('{"mode": 1}', "bogus", "none"),
        (None, "warn", "warn"),
    ],
)
def test_tampered_session_binding_falls_back_to_env_then_default(
    data_dir, monkeypatch, saved, env, expected
):
    if saved is not None:
        (data_dir / "session_binding.json").write_text(saved)
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", env)
    assert manager(data_dir).get_session_binding() == expected


# ---------------------------------------------------------------------------
# Webhook security configuration is refused, not partially applied
# ---------------------------------------------------------------------------

GOOD_HOOK = {"id": "h1", "url": "https://hooks.example.invalid/a", "enabled": True}


@pytest.mark.parametrize(
    "webhooks",
    [
        [{"id": "", "url": "https://x.invalid"}],
        [{"id": "h2", "url": ""}],
        [{"id": "h2", "url": "https://x.invalid", "enabled": "yes"}],
        [{"id": "h2", "url": "https://x.invalid", "signing_secret": 123}],
        [GOOD_HOOK, dict(GOOD_HOOK)],
        [{"id": 7, "url": "https://x.invalid"}],
        ["https://x.invalid"],
    ],
)
def test_invalid_webhook_configuration_is_not_written(data_dir, webhooks):
    pm = manager(data_dir)
    pm.set_webhooks([GOOD_HOOK])
    before = (data_dir / "webhooks.json").read_bytes()
    # A non-dict entry fails before validation (TypeError); either way
    # nothing reaches the file.
    with pytest.raises((ValueError, TypeError)):
        pm.set_webhooks(webhooks)
    assert (data_dir / "webhooks.json").read_bytes() == before
    assert [h["id"] for h in pm.get_webhooks()] == ["h1"]


@pytest.mark.parametrize("revision", ["x" * 32, "ABCDEF" + "0" * 26, "0" * 31, 12])
def test_tampered_delivery_revision_is_refused(data_dir, revision):
    pm = manager(data_dir)
    pm.set_webhooks([GOOD_HOOK])
    (data_dir / "webhooks.json").write_text(
        json.dumps({"webhooks": [{**GOOD_HOOK, "delivery_revision": revision}]})
    )
    with pytest.raises(ValueError, match="delivery revision"):
        pm.current_webhooks()


def test_webhook_mutations_refuse_conflicts_and_unknown_ids(data_dir):
    pm = manager(data_dir)
    pm.change_webhook("h1", create=GOOD_HOOK)
    before = (data_dir / "webhooks.json").read_bytes()

    with pytest.raises(ValueError, match="already exists or is invalid"):
        pm.change_webhook("h1", create={**GOOD_HOOK, "url": "https://evil.invalid"})
    with pytest.raises(ValueError, match="already exists or is invalid"):
        pm.change_webhook("h2", create=GOOD_HOOK)
    with pytest.raises(KeyError):
        pm.change_webhook("h9", updates={"url": "https://evil.invalid"})
    with pytest.raises(KeyError):
        pm.change_webhook("h9", delete=True)
    assert (data_dir / "webhooks.json").read_bytes() == before


def test_security_field_changes_rotate_the_delivery_revision(data_dir):
    pm = manager(data_dir)
    values, _ = pm.change_webhook("h1", create=GOOD_HOOK)
    first = values[0]["delivery_revision"]

    values, previous = pm.change_webhook("h1", updates={"name": "renamed"})
    assert values[0]["delivery_revision"] == first
    assert previous["delivery_revision"] == first

    values, _ = pm.change_webhook("h1", updates={"signing_secret": "s3cret"})
    assert values[0]["delivery_revision"] != first

    # A record that lost its revision gets a fresh one on any update.
    raw = json.loads((data_dir / "webhooks.json").read_text())
    del raw["webhooks"][0]["delivery_revision"]
    (data_dir / "webhooks.json").write_text(json.dumps(raw))
    values, _ = pm.change_webhook("h1", updates={"name": "again"})
    assert len(values[0]["delivery_revision"]) == 32


def test_removed_webhook_authority_is_not_silently_recreated(data_dir):
    pm = manager(data_dir)
    with pytest.raises(FileNotFoundError):
        pm.initialize_webhooks(allow_empty=False)
    assert pm.initialize_webhooks(allow_empty=True) == []
    (data_dir / "webhooks.json").unlink()

    with pytest.raises(FileNotFoundError):
        pm.change_webhook("h1", create=GOOD_HOOK)
    with pytest.raises(FileNotFoundError):
        pm.initialize_webhooks(allow_empty=True)
    assert not (data_dir / "webhooks.json").exists()


# ---------------------------------------------------------------------------
# Config snapshots
# ---------------------------------------------------------------------------


@pytest.fixture
def snap_db(tmp_path):
    ctx = SharedContext(tmp_path / "snapshots.db")
    yield ctx.get_conn()
    ctx.close()


def insert_snapshot(conn, files, timestamp=None):
    with conn:
        cur = conn.execute(
            "INSERT INTO config_snapshots (timestamp, trigger, description, files) "
            "VALUES (?, 'manual', '', ?)",
            (timestamp or datetime.now(timezone.utc).isoformat(), files),
        )
    return cur.lastrowid


def test_snapshot_never_captures_the_key_store(data_dir, snap_db):
    pm = manager(data_dir)
    add(pm, "k1", raw="raw-secret-key")
    pm.set_session_binding("strict")
    pm.set_detection_config({"rf_anomaly_alert_threshold": 0.5})
    pm.set_webhooks([{**GOOD_HOOK, "signing_secret": "hook-secret"}])

    snap_id = pm.create_config_snapshot("manual", "x' OR '1'='1", db_conn=snap_db)
    snap = pm.get_config_snapshot(snap_db, snap_id)
    assert snap["description"] == "x' OR '1'='1"
    assert set(snap["files"]) <= set(PersistenceManager._SNAPSHOT_FILES)
    assert {"detection_config.json", "webhooks.json"} <= set(snap["files"])
    stored = snap_db.execute(
        "SELECT files FROM config_snapshots WHERE id = ?", (snap_id,)
    ).fetchone()[0]
    key_entry = disk_keys(data_dir)["k1"]
    for secret in (key_entry["hash"], key_entry["salt"], key_entry["lookup_hash"]):
        assert secret not in stored
    assert "keys.json" not in stored


def test_snapshot_needs_a_database(data_dir):
    assert manager(data_dir).create_config_snapshot("manual") is None


def test_snapshot_database_failure_returns_none(data_dir, snap_db):
    with snap_db:
        snap_db.execute("DROP TABLE config_snapshots")
    assert manager(data_dir).create_config_snapshot("manual", db_conn=snap_db) is None
    assert not snap_db.in_transaction


def test_malformed_snapshot_rows_read_as_empty(data_dir, snap_db):
    bad = insert_snapshot(snap_db, "not json")
    listed = PersistenceManager.list_config_snapshots(snap_db)
    assert [(s["id"], s["file_count"]) for s in listed] == [(bad, 0)]
    assert PersistenceManager.get_config_snapshot(snap_db, bad)["files"] == {}
    assert PersistenceManager.get_config_snapshot(snap_db, bad + 1) is None

    pm = manager(data_dir)
    add(pm, "k1")
    assert pm.restore_config_snapshot(snap_db, bad) == []
    assert pm.restore_config_snapshot(snap_db, bad + 1) == []
    assert set(pm.get_key_store()) == {"k1"}


@pytest.mark.parametrize("files", ["[]", '["keys.json"]', "5", "null", '"x"'])
def test_snapshot_rows_whose_files_are_not_an_object_restore_nothing(
    data_dir, snap_db, files
):
    pm = manager(data_dir)
    add(pm, "k1")
    files_before = sorted(p.name for p in data_dir.iterdir())
    snap_id = insert_snapshot(snap_db, files)
    snap = PersistenceManager.get_config_snapshot(snap_db, snap_id)
    assert PersistenceManager.config_snapshot_files(snap) == ({}, [])
    assert pm.restore_config_snapshot(snap_db, snap_id) == []
    assert sorted(p.name for p in data_dir.iterdir()) == files_before
    assert set(pm.get_key_store()) == {"k1"}


def test_retired_snapshot_files_are_skipped_and_the_rest_restored(
    data_dir, snap_db, monkeypatch, caplog
):
    monkeypatch.setattr(
        PersistenceManager, "_RETIRED_SNAPSHOT_FILES", frozenset({"old_ui.json"})
    )
    pm = manager(data_dir)
    snap_id = insert_snapshot(
        snap_db,
        json.dumps(
            {
                "watch_bands.json": {"watch_bands": [{"watch_id": "w1"}]},
                "old_ui.json": {"theme": "dark"},
            }
        ),
    )
    assert pm.restore_config_snapshot(snap_db, snap_id) == ["watch_bands.json"]
    assert pm.get_watch_bands() == [{"watch_id": "w1"}]
    assert not (data_dir / "old_ui.json").exists()
    assert "no longer restores, skipped: ['old_ui.json']" in caplog.text


def test_snapshot_deletion_and_retention(snap_db):
    old = insert_snapshot(
        snap_db,
        "{}",
        (datetime.now(timezone.utc) - timedelta(days=120)).isoformat(),
    )
    recent = insert_snapshot(snap_db, "{}")
    assert PersistenceManager.cleanup_old_snapshots(snap_db, retention_days=90) == 1
    assert PersistenceManager.cleanup_old_snapshots(snap_db, retention_days=90) == 0
    assert [s["id"] for s in PersistenceManager.list_config_snapshots(snap_db)] == [
        recent
    ]
    assert PersistenceManager.delete_config_snapshot(snap_db, old) is False
    assert PersistenceManager.delete_config_snapshot(snap_db, recent) is True
    assert PersistenceManager.list_config_snapshots(snap_db) == []


def test_restore_of_invalid_webhooks_reports_failure_and_keeps_current(
    data_dir, snap_db
):
    pm = manager(data_dir)
    pm.set_webhooks([GOOD_HOOK])
    snap_id = insert_snapshot(
        snap_db,
        json.dumps(
            {
                "webhooks.json": {"webhooks": [{"id": "", "url": ""}]},
                "watch_bands.json": {"watch_bands": [{"watch_id": "w1"}]},
            }
        ),
    )
    with pytest.raises(ConfigSnapshotRestoreError) as excinfo:
        pm.restore_config_snapshot(snap_db, snap_id)
    assert excinfo.value.failed_files == ["webhooks.json"]
    assert excinfo.value.restored_files == ["watch_bands.json"]
    assert [h["id"] for h in pm.get_webhooks()] == ["h1"]
    assert pm.get_watch_bands() == [{"watch_id": "w1"}]


@pytest.mark.parametrize(
    "name",
    [
        "keys.json.bak",
        ".persistence.lock",
        "session_binding.json",
        "sub/nodes.json",
        "..\\nodes.json",
        "Nodes.json",
        "nodes.json ",
        "absolute",
    ],
)
def test_restore_refuses_the_whole_snapshot_for_any_other_name(
    data_dir, snap_db, tmp_path, name
):
    if name == "absolute":
        name = str(tmp_path / "absolute.json")
    pm = manager(data_dir)
    files_before = sorted(p.name for p in data_dir.iterdir())
    snap_id = insert_snapshot(
        snap_db,
        json.dumps(
            {
                "watch_bands.json": {"watch_bands": [{"watch_id": "w1"}]},
                name: {"watch_bands": []},
            }
        ),
    )
    with pytest.raises(ConfigSnapshotRejected) as excinfo:
        pm.restore_config_snapshot(snap_db, snap_id)
    assert excinfo.value.rejected_files == [name]
    assert isinstance(excinfo.value, ValueError)
    # Every name is checked before anything is written: the valid file in
    # the same row is not restored either.
    assert sorted(p.name for p in data_dir.iterdir()) == files_before
    assert pm.get_watch_bands() == []
    assert not (tmp_path / "absolute.json").exists()
    assert not (data_dir / "sub").exists()


@pytest.mark.parametrize("target", ["keys.json", "../outside.json"])
def test_restore_writes_only_snapshot_files(data_dir, snap_db, target):
    pm = manager(data_dir)
    add(pm, "k1")
    keys_before = (data_dir / "keys.json").read_bytes()
    snap_id = insert_snapshot(
        snap_db, json.dumps({target: {"keys": {"evil": entry("evil", "admin")}}})
    )
    try:
        pm.restore_config_snapshot(snap_db, snap_id)
    except (ConfigSnapshotRestoreError, ValueError):
        pass
    assert (data_dir / "keys.json").read_bytes() == keys_before
    assert "evil" not in pm.get_key_store()
    assert not (data_dir.parent / "outside.json").exists()


# ---------------------------------------------------------------------------
# Tampered state files
# ---------------------------------------------------------------------------


def test_type_confused_state_files_load_as_empty(data_dir):
    write_keys(data_dir, {"k1": entry("r1")})
    (data_dir / "nodes.json").write_text("[1, 2, 3]")
    (data_dir / "alerts.json").write_text(json.dumps({"alerts": {"a": 1}}))
    (data_dir / "history.json").write_text(
        json.dumps({"history": {"n1": "not-a-list", "n2": [{"t": 1}]}})
    )
    (data_dir / "jobs.json").write_bytes(b"\xff\xfe\x00garbage")
    (data_dir / "webhooks.json").write_text(json.dumps({"webhooks": "x"}))
    (data_dir / "wifi_whitelist.json").write_text(json.dumps({"whitelist": 5}))
    (data_dir / "alert_rules.json").write_text("{")

    pm = manager(data_dir)
    assert pm.get_nodes() == {}
    assert pm.get_alerts() == []
    assert pm.get_history() == {"n2": [{"t": 1}]}
    assert pm.get_jobs() == {}
    assert pm.get_webhooks() == []
    assert pm.get_wifi_whitelist() == []
    assert pm.get_alert_rules() == []
    assert set(pm.get_key_store()) == {"k1"}


# ---------------------------------------------------------------------------
# End to end through the admin key routes
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_key(monkeypatch):
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "persistence-http-audit-key")


def audit_rows(detection_store, action):
    return (
        detection_store.get_connection()
        .execute(
            "SELECT target_id, operator, details FROM audit_log WHERE action = ? "
            "ORDER BY id",
            [action],
        )
        .fetchall()
    )


def test_http_key_lifecycle_is_durable_and_audited(
    audit_key, client, persistence, detection_store
):
    data_dir = persistence.data_dir
    description = "O'Brien \"; DROP TABLE keys; -- 🙂"
    resp = client.post(
        "/api/admin/keys",
        json={"role": "viewer", "description": description, "node_id": "node-7"},
    )
    assert resp.status_code == 201, resp.text
    key_id, raw = resp.json()["key_id"], resp.json()["raw_key"]

    on_disk = disk_keys(data_dir)[key_id]
    assert (on_disk["role"], on_disk["node_id"], on_disk["description"]) == (
        "viewer",
        "node-7",
        description,
    )
    assert raw not in (data_dir / "keys.json").read_text()
    assert raw not in (data_dir / "keys.json.bak").read_text()
    assert stat.S_IMODE(os.stat(data_dir / "keys.json").st_mode) == 0o600
    assert [
        r["target_id"] for r in audit_rows(detection_store, "admin_create_key")
    ] == [key_id]
    assert client.get("/api/nodes", headers={"X-API-Key": raw}).status_code == 200

    rebind = client.put(
        f"/api/admin/keys/{key_id}/permissions", json={"node_id": "node-8"}
    )
    assert rebind.status_code == 200
    assert disk_keys(data_dir)[key_id]["node_id"] == "node-8"
    updates = audit_rows(detection_store, "admin_update_key_permissions")
    assert json.loads(updates[-1]["details"])["changes"] == [
        {"key": "node_id", "old": "node-7", "new": "node-8"}
    ]

    before = (data_dir / "keys.json").read_bytes()
    for bad in ("../etc", "node-8'; --", "n" * 65, "node 8"):
        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions", json={"node_id": bad}
        )
        assert resp.status_code == 400
    assert (data_dir / "keys.json").read_bytes() == before
    assert len(audit_rows(detection_store, "admin_update_key_permissions")) == 1

    revoked = client.delete(f"/api/admin/keys/{key_id}")
    assert revoked.status_code == 200
    assert key_id not in disk_keys(data_dir)
    assert key_id not in disk_keys(data_dir, "keys.json.bak")
    assert client.get("/api/nodes", headers={"X-API-Key": raw}).status_code == 401
    assert [
        r["target_id"] for r in audit_rows(detection_store, "admin_revoke_key")
    ] == [key_id]
    assert key_id not in manager(data_dir).get_key_store()
    assert client.get("/api/admin/audit/verify").json()["valid"] is True


def test_http_master_key_cannot_be_revoked_or_rerolled(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    before = disk_keys(persistence.data_dir)
    assert client.delete("/api/admin/keys/master").status_code == 403
    assert (
        client.put(
            "/api/admin/keys/master/permissions", json={"role": "viewer"}
        ).status_code
        == 403
    )
    assert client.delete("/api/admin/keys/does-not-exist").status_code == 404
    assert disk_keys(persistence.data_dir) == before
    assert "master" in persistence.get_key_store()
    assert audit_rows(detection_store, "admin_revoke_key") == []


def test_http_edge_keys_never_get_an_operator_role(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "node_02", role="node")
    path = persistence.data_dir / "keys.json"
    before = path.read_bytes()
    for role in ("analyst", "ADMIN"):
        resp = client.put("/api/admin/keys/node_02/permissions", json={"role": role})
        assert resp.status_code == 400, resp.text
        assert "edge/sensor node key" in resp.json()["detail"]
    assert path.read_bytes() == before
    assert audit_rows(detection_store, "admin_update_key_permissions") == []

    resp = client.put("/api/admin/keys/node_02/permissions", json={"role": "viewer"})
    assert (resp.status_code, resp.json()["role"]) == (200, "viewer")
    assert disk_keys(persistence.data_dir)["node_02"]["role"] == "viewer"


def test_http_keys_created_with_an_edge_id_are_node_keys(client, persistence):
    resp = client.post("/api/keys/", json={"key_id": "node_77"})
    assert (resp.status_code, resp.json()["role"]) == (201, "node")
    assert persistence.get_key_meta()["node_77"]["role"] == "node"
    assert disk_keys(persistence.data_dir)["node_77"]["role"] == "node"
    assert manager(persistence.data_dir).get_key_meta()["node_77"]["role"] == "node"

    resp = client.post("/api/keys/", json={"key_id": "ops_77"})
    assert (resp.status_code, resp.json()["role"]) == (201, "analyst")


@needs_unprivileged
def test_http_unsaved_key_changes_are_refused_and_not_audited(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "victim", raw="victim-raw", role="viewer")
    add(persistence, "ops_v", raw="ops-raw", role="viewer")
    data_dir = persistence.data_dir
    before = disk_keys(data_dir)
    state = (persistence.get_key_store(), persistence.get_key_meta())
    # Over TLS (key rotation refuses plaintext), so only the save can fail.
    attempts = [
        ("POST", "/api/admin/keys", {"role": "viewer"}),
        ("PUT", "/api/admin/keys/victim/permissions", {"role": "analyst"}),
        ("PUT", "/api/admin/keys/victim/permissions", {"node_id": "edge-1"}),
        ("POST", "/api/admin/keys/victim/rotate", {"deploy_to_node": False}),
        ("POST", "/api/keys/", {"key_id": "ops_new"}),
        ("PUT", "/api/keys/ops_v/rotate", None),
        ("POST", "/api/keys/rotate-master", None),
    ]
    os.chmod(data_dir, 0o500)
    try:
        for method, url, body in attempts:
            resp = client.request(method, f"https://testserver{url}", json=body)
            assert resp.status_code == 503, (method, url, resp.text)
            assert resp.json() == {"detail": KEY_CHANGE_NOT_SAVED}
        assert disk_keys(data_dir) == before
        # Another worker (and the gateway) still accept both keys ...
        assert {"victim", "ops_v"} <= set(manager(data_dir).get_key_store())
    finally:
        os.chmod(data_dir, 0o700)

    for action in (
        "admin_create_key",
        "admin_update_key_permissions",
        "admin_rotate_key",
        "master_key_rotated",
    ):
        assert audit_rows(detection_store, action) == []
    # ... and so does this worker: no added key, no elevation, no binding,
    # no new credential (the master key still works).
    assert (persistence.get_key_store(), persistence.get_key_meta()) == state
    assert client.get("/api/nodes").status_code == 200
    persistence.save_all()
    assert disk_keys(data_dir) == before


def pending_rows(detection_store, action):
    return [
        (row["target_id"], json.loads(row["details"]) if row["details"] else None)
        for row in audit_rows(detection_store, action)
    ]


@needs_unprivileged
@pytest.mark.parametrize("router", ["admin", "keys"])
def test_http_unsaved_revocation_is_pending_and_a_retry_saves_it(
    audit_key, client, persistence, detection_store, router
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "victim", raw="victim-raw", role="viewer")
    data_dir = persistence.data_dir
    url = f"/api/{router}/keys/victim" if router == "admin" else "/api/keys/victim"
    pending = {"pending": "not yet saved"}
    os.chmod(data_dir, 0o500)
    try:
        # A repeat while keys.json is still unwritable is not "not found".
        for _attempt in range(2):
            resp = client.delete(url)
            assert resp.status_code == 503, resp.text
            assert resp.json() == {"detail": KEY_CHANGE_PENDING}
        # The other workers and the gateway still accept the key ...
        assert "victim" in disk_keys(data_dir)
        assert "victim" in manager(data_dir).get_key_store()
        assert persistence.get_saved_key_meta("victim")["role"] == "viewer"
    finally:
        os.chmod(data_dir, 0o700)
    # ... this worker does not.
    assert "victim" not in persistence.get_key_store()
    nodes = client.get("/api/nodes", headers={"X-API-Key": "victim-raw"})
    assert nodes.status_code == 401
    if router == "admin":
        assert pending_rows(detection_store, "admin_revoke_key") == [
            ("victim", pending),
            ("victim", pending),
        ]

    resp = client.delete(url)
    assert resp.status_code == 200, resp.text
    assert "victim" not in disk_keys(data_dir)
    assert "victim" not in manager(data_dir).get_key_store()
    assert persistence.get_saved_key_meta("victim") is None
    if router == "admin":
        assert pending_rows(detection_store, "admin_revoke_key")[2:] == [
            ("victim", None)
        ]
    assert client.delete(url).status_code == 404


@needs_unprivileged
def test_http_unsaved_downgrade_is_pending_and_audited_against_the_saved_role(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "victim", role="analyst")
    add(persistence, "other", role="analyst")
    data_dir = persistence.data_dir
    url = "/api/admin/keys/{}/permissions"
    downgrade = {
        "changes": [{"key": "role", "old": "analyst", "new": "viewer"}],
        "pending": "not yet saved",
    }
    os.chmod(data_dir, 0o500)
    try:
        for key_id in ("victim", "other"):
            resp = client.put(url.format(key_id), json={"role": "viewer"})
            assert resp.status_code == 503, resp.text
            assert resp.json() == {"detail": KEY_CHANGE_PENDING}
        assert persistence.get_key_meta()["victim"]["role"] == "viewer"
        assert disk_keys(data_dir)["victim"]["role"] == "analyst"
    finally:
        os.chmod(data_dir, 0o700)
    assert pending_rows(detection_store, "admin_update_key_permissions") == [
        ("victim", downgrade),
        ("other", downgrade),
    ]

    # A repeat saves it and audits the change from the saved role.
    resp = client.put(url.format("victim"), json={"role": "viewer"})
    assert (resp.status_code, resp.json()["role"]) == (200, "viewer")
    assert disk_keys(data_dir)["victim"]["role"] == "viewer"
    assert pending_rows(detection_store, "admin_update_key_permissions")[2:] == [
        ("victim", {"changes": downgrade["changes"]})
    ]
    # Either way the pending downgrade of "other" was audited, even though
    # the save that wrote it (above) was not its own request.
    assert manager(data_dir).get_key_meta()["other"]["role"] == "viewer"


@needs_unprivileged
@pytest.mark.parametrize("role", ["analyst", "sensor"])
def test_http_role_and_binding_are_saved_together_or_not_at_all(
    audit_key, client, persistence, detection_store, monkeypatch, role
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "victim", role="viewer", node_id="edge-1")
    data_dir = persistence.data_dir
    before = disk_keys(data_dir)
    real_write = persistence_module._atomic_write

    def full_disk_for_the_binding(path, data, *args, **kwargs):
        # Only a keys.json that binds the key to edge-2 cannot be written:
        # a role change saved on its own would go through.
        entry = data.get("keys", {}).get("victim", {}) if "keys" in data else {}
        if entry.get("node_id") == "edge-2":
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(path, data, *args, **kwargs)

    monkeypatch.setattr(persistence_module, "_atomic_write", full_disk_for_the_binding)
    resp = client.put(
        "/api/admin/keys/victim/permissions",
        json={"role": role, "node_id": "edge-2"},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json() == {"detail": KEY_CHANGE_NOT_SAVED}
    assert disk_keys(data_dir) == before
    meta = persistence.get_key_meta()["victim"]
    assert (meta["role"], meta["node_id"]) == ("viewer", "edge-1")
    assert audit_rows(detection_store, "admin_update_key_permissions") == []


@needs_unprivileged
def test_http_role_ceiling_applies_to_the_saved_role(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    add(persistence, "ops_admin", raw="admin-raw", role="admin")
    add(persistence, "km", role="keymaster")
    add(persistence, "km2", role="keymaster")
    data_dir = persistence.data_dir
    os.chmod(data_dir, 0o500)
    try:
        # A keymaster's downgrade and revocation that keys.json could not
        # record: the keys are still keymaster keys everywhere else.
        with pytest.raises(KeyStoreWriteError):
            persistence.update_key_role("km", "viewer")
        with pytest.raises(KeyStoreWriteError):
            persistence.remove_key("km2")
    finally:
        os.chmod(data_dir, 0o700)
    admin = {"X-API-Key": "admin-raw"}
    for method, url, body in [
        ("PUT", "/api/admin/keys/km/permissions", {"role": "analyst"}),
        ("POST", "/api/admin/keys/km/rotate", {"deploy_to_node": False}),
        ("DELETE", "/api/admin/keys/km", None),
        ("DELETE", "/api/admin/keys/km2", None),
        ("PUT", "/api/keys/km/rotate", None),
        ("DELETE", "/api/keys/km2", None),
    ]:
        resp = client.request(
            method, f"https://testserver{url}", json=body, headers=admin
        )
        assert resp.status_code == 403, (method, url, resp.text)
        assert "keymaster" in resp.json()["detail"]
    assert disk_keys(data_dir)["km"]["role"] == "keymaster"
    assert "km2" in disk_keys(data_dir)


def test_http_tampered_snapshot_is_refused_and_not_audited(
    audit_key, client, persistence, detection_store
):
    # The first authenticated request may index the master key; start after it.
    assert client.get("/api/nodes").status_code == 200
    keys_path = persistence.data_dir / "keys.json"
    keys_before = keys_path.read_bytes()
    snap_id = insert_snapshot(
        detection_store.get_connection(),
        json.dumps(
            {
                "watch_bands.json": {"watch_bands": [{"watch_id": "w1"}]},
                "keys.json": {"keys": {"evil": entry("evil-raw", "admin")}},
            }
        ),
    )
    snapshots = PersistenceManager.list_config_snapshots(
        detection_store.get_connection()
    )
    resp = client.post(f"/api/admin/config-snapshots/{snap_id}/restore")
    assert resp.status_code == 422, resp.text
    assert "keys.json" in resp.json()["detail"]
    assert keys_path.read_bytes() == keys_before
    # Refused before the pre-restore backup is taken: no stray backup row.
    assert (
        PersistenceManager.list_config_snapshots(detection_store.get_connection())
        == snapshots
    )
    assert persistence.get_watch_bands() == []
    assert audit_rows(detection_store, "admin_config_snapshot_restore") == []
    evil = client.get("/api/nodes", headers={"X-API-Key": "evil-raw"})
    assert evil.status_code == 401
