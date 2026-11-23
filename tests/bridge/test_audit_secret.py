"""Real development key-storage failures must not break untampered audit chains."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest

from sigrift.bridge.storage import audit
from sigrift.bridge.storage.base import SharedContext


@pytest.fixture
def dev_path(tmp_path, monkeypatch):
    for name in (
        "BRIDGE_AUDIT_KEY",
        "BRIDGE_AUDIT_SECRET",
        "BRIDGE_MASTER_KEY",
        "BRIDGE_ENV",
        "BRIDGE_MODE",
        "BRIDGE_DB_ENCRYPTION_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BRIDGE_ENV", "development")
    # Relocate only the existing key-path input; execute the actual module,
    # store and cryptography without copying sources or replacing file I/O.
    module_path = tmp_path / "bridge" / "storage" / "audit.py"
    monkeypatch.setattr(audit, "__file__", str(module_path))
    data = module_path.parent.parent / "data"
    data.parent.mkdir(parents=True)
    return data


def obstruction(path):
    path.write_bytes(b"existing file obstructs the data directory")


def test_failed_persistence_returns_one_secret_and_reports_once(dev_path, caplog):
    obstruction(dev_path)
    secrets = [audit._get_audit_secret() for _ in range(4)]
    distinct_keys = len(set(secrets))
    assert distinct_keys == 1
    assert len(secrets[0]) == 32
    assert dev_path.read_bytes() == b"existing file obstructs the data directory"
    assert caplog.text.count("ephemeral key") == 1


@pytest.mark.parametrize("obstructed", [False, True])
def test_concurrent_initial_resolution_uses_one_key(dev_path, obstructed):
    if obstructed:
        obstruction(dev_path)
    ready = threading.Barrier(12)

    def resolve(_):
        ready.wait(timeout=5)
        return audit._get_audit_secret()

    with ThreadPoolExecutor(max_workers=12) as pool:
        keys = list(pool.map(resolve, range(12)))
    distinct_keys = len(set(keys))
    assert distinct_keys == 1
    if not obstructed:
        expected = hashlib.sha256((dev_path / "audit.key").read_bytes()).digest()
        matches_disk = all(key == expected for key in keys)
        assert matches_disk


def test_ephemeral_key_keeps_real_chain_valid_after_recovery_and_store_reopen(
    dev_path, tmp_path
):
    obstruction(dev_path)
    db = tmp_path / "audit.db"
    ctx = SharedContext(db)
    try:
        store = audit.AuditStore(ctx)
        store.log_audit("create", "one", operator="tester", details={"value": 1})
        store.log_audit("update", "two", operator="tester", note="original note")
        assert store.verify_chain()["valid"] is True
        # Recovery must not choose a new key or overwrite an operator's file.
        dev_path.unlink()
        dev_path.mkdir()
        (dev_path / "audit.key").write_text("later-disk-key")
        store.log_audit("update", "three", operator="tester")
        result = store.verify_chain()
        assert result["valid"] is True
        assert result["checked"] == 3
        assert result["errors"] == []
        assert (dev_path / "audit.key").read_text() == "later-disk-key"
    finally:
        ctx.close()
    reopened = SharedContext(db)
    try:
        store = audit.AuditStore(reopened)
        assert store.verify_chain()["valid"] is True
        reopened.get_conn().execute("UPDATE audit_log SET note='tampered' WHERE id=2")
        reopened.get_conn().commit()
        assert store.verify_chain()["valid"] is False
    finally:
        reopened.close()


def test_concurrent_real_audit_appends_keep_one_valid_chain(dev_path, tmp_path):
    obstruction(dev_path)
    ctx = SharedContext(tmp_path / "audit.db")
    store = audit.AuditStore(ctx)
    ready = threading.Barrier(8)

    def append(index):
        ready.wait(timeout=5)
        store.log_audit("update", str(index), operator="tester")

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(append, range(8)))
        result = store.verify_chain()
        assert result["valid"] is True
        assert result["checked"] == 8
        assert result["errors"] == []
    finally:
        ctx.close()


@pytest.mark.parametrize("initial", ["generated", "stored", "ephemeral"])
def test_key_is_pinned_until_restart_even_if_disk_changes(dev_path, initial):
    if initial == "ephemeral":
        obstruction(dev_path)
    elif initial == "stored":
        dev_path.mkdir()
        (dev_path / "audit.key").write_text("first-disk-key\n")
    first = audit._get_audit_secret()
    if dev_path.is_file():
        dev_path.unlink()
        dev_path.mkdir()
    (dev_path / "audit.key").write_text("replacement-disk-key")
    unchanged = audit._get_audit_secret() == first
    assert unchanged
    # A real new interpreter reads the replacement; no process cache is reset
    # by the test or claimed to persist across restarts.
    script = """
import hashlib, json, sys
from sigrift.bridge.storage import audit
audit.__file__ = sys.argv[1]
print(json.dumps({'replacement_loaded': audit._get_audit_secret() == hashlib.sha256(b'replacement-disk-key').digest()}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, audit.__file__],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert json.loads(result.stdout) == {"replacement_loaded": True}


def test_different_key_paths_have_independent_stable_ephemeral_keys(
    dev_path, tmp_path, monkeypatch
):
    obstruction(dev_path)
    first_path = audit.__file__
    first = audit._get_audit_secret()
    second_path = tmp_path / "second" / "storage" / "audit.py"
    second_path.parent.parent.mkdir()
    obstruction(second_path.parent.parent / "data")
    monkeypatch.setattr(audit, "__file__", str(second_path))
    second = audit._get_audit_secret()
    distinct_keys = len({first, second})
    assert distinct_keys == 2
    unchanged = audit._get_audit_secret() == second
    assert unchanged
    monkeypatch.setattr(audit, "__file__", first_path)
    unchanged = audit._get_audit_secret() == first
    assert unchanged


def test_configured_keys_keep_precedence_over_cached_development_key(
    dev_path, monkeypatch
):
    obstruction(dev_path)
    fallback = audit._get_audit_secret()
    monkeypatch.setenv("BRIDGE_MASTER_KEY", " master ")
    configured_wins = (
        audit._get_audit_secret()
        == hashlib.sha256(b"bridge-audit-hmac:master").digest()
    )
    assert configured_wins
    monkeypatch.setenv("BRIDGE_AUDIT_SECRET", " legacy ")
    configured_wins = audit._get_audit_secret() == hashlib.sha256(b"legacy").digest()
    assert configured_wins
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", " preferred ")
    configured_wins = audit._get_audit_secret() == hashlib.sha256(b"preferred").digest()
    assert configured_wins
    monkeypatch.setenv("BRIDGE_ENV", "production")
    configured_wins = audit._get_audit_secret() == hashlib.sha256(b"preferred").digest()
    assert configured_wins
    for name in ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"):
        monkeypatch.delenv(name)
    with pytest.raises(RuntimeError, match="No audit HMAC key configured"):
        audit._get_audit_secret()
    monkeypatch.setenv("BRIDGE_ENV", "development")
    unchanged = audit._get_audit_secret() == fallback
    assert unchanged


@pytest.mark.parametrize("env", ["BRIDGE_ENV", "BRIDGE_MODE"])
@pytest.mark.parametrize("value", ["production", " PROD "])
def test_production_never_uses_file_or_cached_fallback(
    dev_path, monkeypatch, env, value
):
    dev_path.mkdir()
    (dev_path / "audit.key").write_text("development-only-disk-key")
    audit._get_audit_secret()
    monkeypatch.setenv(env, value)
    with pytest.raises(RuntimeError, match="No audit HMAC key configured"):
        audit._get_audit_secret()


@pytest.mark.skipif(not hasattr(os, "fork"), reason="OS does not support fork")
def test_fork_while_another_thread_holds_key_lock_does_not_hang(dev_path):
    obstruction(dev_path)
    script = """
import json, os, select, signal, sys, threading
from sigrift.bridge.storage import audit
audit.__file__ = sys.argv[1]
expected = audit._get_audit_secret()
held = threading.Event()
release = threading.Event()
def hold_lock():
    with audit._DEV_AUDIT_SECRET_LOCK:
        held.set()
        release.wait(8)
thread = threading.Thread(target=hold_lock)
thread.start()
if not held.wait(2):
    raise RuntimeError('worker did not acquire key lock')
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    # Boolean proof only: never emit secret or HMAC key bytes.
    same = audit._get_audit_secret() == expected
    os.write(writer, b'1' if same else b'0')
    os.close(writer)
    os._exit(0)
os.close(writer)
try:
    readable, _, _ = select.select([reader], [], [], 3)
    if readable:
        inherited = os.read(reader, 1) == b'1'
    else:
        os.kill(pid, signal.SIGKILL)
        inherited = False
    _, status = os.waitpid(pid, 0)
finally:
    os.close(reader)
    release.set()
    thread.join(timeout=2)
print(json.dumps({'child_completed': bool(readable), 'inherited_key': inherited,
                  'exit_ok': status == 0, 'parent_thread_finished': not thread.is_alive()}))
"""
    result = subprocess.run(
        [sys.executable, "-c", script, audit.__file__],
        capture_output=True,
        text=True,
        timeout=12,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "child_completed": True,
        "inherited_key": True,
        "exit_ok": True,
        "parent_thread_finished": True,
    }


@pytest.mark.parametrize("kind", ["empty_file", "key_path_directory"])
def test_unusable_key_file_resolves_once_without_fabricated_io_errors(
    dev_path, caplog, kind
):
    dev_path.mkdir()
    key_file = dev_path / "audit.key"
    if kind == "empty_file":
        key_file.write_text(" \n")
    else:
        key_file.mkdir()
    first = audit._get_audit_secret()
    unchanged = audit._get_audit_secret() == first
    assert unchanged
    if kind == "empty_file":
        matches_disk = first == hashlib.sha256(key_file.read_bytes()).digest()
        assert matches_disk
        assert caplog.text.count("Generated random key") == 1
    else:
        assert key_file.is_dir()
        assert caplog.text.count("ephemeral key") == 1
