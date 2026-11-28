"""The installers' lifecycle engine against data the bridge's own stores wrote.

The engine (the lifecycle-engine block of scripts/install-release.sh) runs
inside the bridge image with bridge_data mounted; here it is exec'd in
process with a REQUEST, against a data directory built in tmp_path by
DetectionStore, the user store (TOTP secrets under BRIDGE_MFA_KEY) and
the audit store (entries under an audit key).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage import users as users_mod
from sigrift.bridge.storage.base import _MIGRATIONS

ROOT = Path(__file__).resolve().parents[2]
INSTALL_RELEASE = ROOT / "scripts" / "install-release.sh"
BLOCK = re.search(r"(?ms)^# >>> shared: lifecycle-engine .*?^# <<< shared: lifecycle-engine\n",
                  INSTALL_RELEASE.read_text()).group(0)
ENGINE = re.search(r"cat <<'PY'\n(.*?)\nPY\n", BLOCK, re.S).group(1) + "\n"
BOOTSTRAP = re.search(r"^LC_ENGINE_BOOTSTRAP='(.*?)'$", BLOCK, re.S | re.M).group(1)

KEY_A = base64.urlsafe_b64encode(bytes(range(32))).decode()
KEY_B = base64.urlsafe_b64encode(bytes(range(32, 64))).decode()
AUDIT_KEY = "engine-test-audit-key"
SECRETS = (KEY_A, KEY_B, AUDIT_KEY, "engine-test-master-key", "engine-test-legacy")
ENV_NAMES = ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY", "BRIDGE_MFA_KEY",
             "BRIDGE_KEYSTORE_KEY", "BRIDGE_ENV", "BRIDGE_MODE")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    users_mod._fernet_instance = None
    yield
    users_mod._fernet_instance = None


def build(tmp_path: Path, name="data", *, mfa=KEY_A, totp=True, audit_env=None, entries=3,
          crypto=True) -> Path:
    """A bridge_data directory written by the bridge's own stores."""
    d = tmp_path / name
    d.mkdir()
    store = DetectionStore(db_path=d / "detections.db")
    try:
        if totp:
            os.environ["BRIDGE_MFA_KEY"] = mfa
            users_mod._fernet_instance = None
            store._users.create_user("operator", "Password123!x", role="admin")
            user = store._users.get_user("operator")
            store._users.set_totp_secret(user["id"], "JBSWY3DPEHPK3PXP")
            os.environ.pop("BRIDGE_MFA_KEY")
            users_mod._fernet_instance = None
        if entries:
            env = audit_env if audit_env is not None else {"BRIDGE_AUDIT_KEY": AUDIT_KEY}
            os.environ.update(env)
            for i in range(entries):
                store.log_audit("dismiss", f"target-{i}", operator="operator")
            for k in env:
                os.environ.pop(k)
        if crypto:
            store.get_connection().execute(
                "INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, key_hash) "
                "VALUES ('k1', 'dmr', 'site', x'00', 'h')")
            store.get_connection().commit()
    finally:
        store.close()
    return d


def run(req: dict):
    ns = {"__name__": "sigrift_engine_test", "REQUEST": req}
    exec(compile(ENGINE, "<sigrift-engine>", "exec"), ns)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = ns["run"](req)
    return rc, json.loads(out.getvalue())


def facts(d: Path, **candidates):
    rc, reply = run({"format": 1, "op": "facts", "data_dir": str(d),
                     "candidates": {"env": candidates.pop("env", {}), **candidates}})
    assert rc == 0 and reply["ok"], reply
    return reply


def snapshot(d: Path) -> dict:
    return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in sorted(d.iterdir())
            if p.is_file()}


def test_facts_counts_schema_and_newest_migration(tmp_path):
    d = build(tmp_path)
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    newest = max(v for v, _, _ in _MIGRATIONS)
    assert f["db"]["present"] and not f["db"]["encrypted"] and f["db"]["schema"] == newest
    assert f["db"]["bytes"] == (d / "detections.db").stat().st_size
    c = f["counts"]
    assert (c["users"], c["totp_fernet"], c["crypto_keys"]) == (1, 1, 1)
    assert c["audit_rows"] >= 3 and c["audit_head_id"] >= 3
    rc, info = run({"format": 1, "op": "image-info", "data_dir": str(d)})
    assert rc == 0 and info["newest_migration"] == newest


def test_detections_are_counted_by_rowid(tmp_path):
    # detections has a TEXT primary key and no id column. MAX(id) is an unknown
    # column, which reads as "no detections", so the upgrade check that the
    # highest detection did not fall would never run.
    from sigrift.bridge.tests.conftest import make_detection

    d = build(tmp_path)
    store = DetectionStore(db_path=d / "detections.db")
    try:
        assert store.insert_batch([make_detection() for _ in range(3)]) == 3
    finally:
        store.close()
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    assert f["counts"]["detections_max_id"] == 3


def test_mfa_candidates_verify_without_decrypting(tmp_path):
    d = build(tmp_path)
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A}, container={"BRIDGE_MFA_KEY": KEY_B},
              shell={"BRIDGE_MFA_KEY": KEY_A[:-1]})
    assert f["candidates"]["env"]["mfa"] == "ok"
    assert f["candidates"]["container"]["mfa"] == "fail"
    assert f["candidates"]["shell"]["mfa"] == "invalid-key"
    # The same key in the standard alphabet is the same key.
    std = KEY_A.replace("-", "+").replace("_", "/")
    assert facts(d, env={"BRIDGE_MFA_KEY": std})["candidates"]["env"]["mfa"] == "ok"
    assert facts(d, env={})["candidates"]["env"]["mfa"] == "missing"
    empty = build(tmp_path, "no-totp", totp=False)
    assert facts(empty, env={"BRIDGE_MFA_KEY": KEY_B})["candidates"]["env"]["mfa"] == "n/a"
    same = facts(d, env={"BRIDGE_MFA_KEY": KEY_A}, container={"same_as": "env"})
    assert same["candidates"]["container"] == {"same_as": "env"}


def test_audit_candidates_use_the_bridges_resolution_order(tmp_path):
    d = build(tmp_path)
    ok = facts(d, env={"BRIDGE_AUDIT_KEY": AUDIT_KEY, "BRIDGE_MASTER_KEY": "ignored"})
    a = ok["candidates"]["env"]["audit"]
    assert (a["result"], a["source"], a["valid"]) == ("ok", "env-key", True)
    assert a["checked"] >= 3 and a["mismatches"] == 0
    legacy = facts(d, env={"BRIDGE_AUDIT_SECRET": AUDIT_KEY})["candidates"]["env"]["audit"]
    assert (legacy["result"], legacy["source"]) == ("ok", "legacy-secret")
    wrong = facts(d, env={"BRIDGE_AUDIT_KEY": "another"})["candidates"]["env"]["audit"]
    assert wrong["result"] == "fail" and wrong["mismatches"] == wrong["checked"]
    master = build(tmp_path, "master", totp=False,
                   audit_env={"BRIDGE_MASTER_KEY": "engine-test-master-key"})
    m = facts(master, env={"BRIDGE_MASTER_KEY": "engine-test-master-key"})["candidates"]["env"]["audit"]
    assert (m["result"], m["source"]) == ("ok", "master")
    # The development key file: SHA-256 of its stripped text, like an env key.
    filed = build(tmp_path, "file", totp=False, audit_env={"BRIDGE_AUDIT_KEY": "file-key"})
    (filed / "audit.key").write_text("file-key\n")
    fa = facts(filed, env={})["candidates"]["env"]["audit"]
    assert (fa["result"], fa["source"]) == ("ok", "file")
    none = build(tmp_path, "none", totp=False)
    na = facts(none, env={})["candidates"]["env"]["audit"]
    assert (na["result"], na["source"]) == ("no-key", "none")
    assert not (none / "audit.key").exists()
    for k in ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"):
        assert k not in os.environ


def test_keystore_rows_are_counted_and_pre_51_databases_report_zero(tmp_path):
    d = build(tmp_path)
    f = facts(d, env={"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert f["counts"]["crypto_keys"] == 1
    assert f["candidates"]["env"]["keystore"] == {"present": True, "valid": True}
    old = tmp_path / "old"
    old.mkdir()
    conn = sqlite3.connect(old / "detections.db")
    conn.executescript("CREATE TABLE schema_version (version INTEGER); INSERT INTO schema_version "
                       "VALUES (50); CREATE TABLE users (id INTEGER, totp_secret TEXT);")
    conn.close()
    f = facts(old, env={"BRIDGE_KEYSTORE_KEY": "short"})
    assert f["counts"]["crypto_keys"] == 0 and f["db"]["schema"] == 50
    assert f["candidates"]["env"]["keystore"] == {"present": True, "valid": False}


UNKNOWN = {"users": None, "totp_fernet": None, "audit_rows": None, "audit_head_id": None,
           "crypto_keys": None, "detections_max_id": None}


def test_encrypted_header_is_detected_and_not_opened(tmp_path):
    d = tmp_path / "enc"
    d.mkdir()
    (d / "detections.db").write_bytes(os.urandom(4096))
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    assert f["db"]["encrypted"] and f["db"]["present"] and f["db"]["schema"] is None
    assert f["db"]["error"] is None
    # Nothing could be counted, which is not "no rows": a run must not
    # generate a new data-bound key under it.
    assert f["counts"] == UNKNOWN
    assert f["candidates"]["env"]["mfa"] == "unchecked"
    assert f["candidates"]["env"]["audit"]["result"] == "unchecked"


def test_a_failing_query_leaves_the_counts_unknown(tmp_path, monkeypatch):
    d = build(tmp_path)
    # A malformed page, a recovery the read-only open cannot do, a lock:
    # every query after the schema read fails.
    real = sqlite3.connect

    class Failing:
        def __init__(self, conn):
            self.conn = conn
            self.row_factory = None

        def execute(self, sql, *a):
            if "schema_version" in sql:
                return self.conn.execute(sql, *a)
            raise sqlite3.DatabaseError("database disk image is malformed")

        def close(self):
            self.conn.close()

    monkeypatch.setattr(sqlite3, "connect", lambda *a, **k: Failing(real(*a, **k)))
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    assert f["db"]["error"].startswith("DatabaseError: database disk image is malformed")
    assert f["counts"] == UNKNOWN
    assert f["candidates"]["env"]["mfa"] == "unchecked"
    assert f["candidates"]["env"]["audit"]["result"] == "unchecked"


def test_a_table_an_older_schema_lacks_still_counts_zero(tmp_path):
    d = tmp_path / "old"
    d.mkdir()
    conn = sqlite3.connect(d / "detections.db")
    conn.executescript("CREATE TABLE schema_version (version INTEGER); INSERT INTO schema_version "
                       "VALUES (50); CREATE TABLE users (id INTEGER, totp_secret TEXT);")
    conn.close()
    f = facts(d, env={})
    assert f["db"]["error"] is None
    assert (f["counts"]["users"], f["counts"]["audit_rows"], f["counts"]["crypto_keys"]) == (0, 0, 0)


def test_missing_database_reports_zeros(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    assert not f["db"]["present"] and f["db"]["schema"] is None
    assert f["counts"] == {"users": 0, "totp_fernet": 0, "audit_rows": 0, "audit_head_id": None,
                           "crypto_keys": 0, "detections_max_id": None}
    assert f["candidates"]["env"]["mfa"] == "n/a"
    assert f["candidates"]["env"]["audit"]["result"] == "n/a"


def test_restore_marker_and_volume_record_are_reported(tmp_path, monkeypatch):
    d = build(tmp_path, totp=False, entries=0, crypto=False)
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    ns = {"__name__": "sigrift_engine_test", "REQUEST": {}}
    exec(compile(ENGINE, "<sigrift-engine>", "exec"), ns)
    assert ns["SECRETS_DIR"] == "/app/secrets"
    engine = ENGINE.replace('SECRETS_DIR = "/app/secrets"', 'SECRETS_DIR = %r' % str(secrets_dir))
    monkeypatch.setitem(globals(), "ENGINE", engine)
    assert facts(d)["restore_marker"] is False and facts(d)["record"] is None
    assert facts(d)["restore_markers"] == []
    (d / ".sigrift-restore-incomplete").write_text('{"format": 1}\n')
    (d / ".sigrift-install.json").write_text('{"format": 1, "install_id": "abc"}\n')
    f = facts(d)
    assert f["restore_marker"] is True and f["record"] == {"format": 1, "install_id": "abc"}
    assert f["restore_markers"] == ["bridge_data"]
    # The marker at the root of bridge_secrets counts too (Phase 3's bridge
    # refuses on either), also as a dangling symlink.
    (d / ".sigrift-restore-incomplete").unlink()
    (secrets_dir / ".sigrift-restore-incomplete").symlink_to(tmp_path / "gone")
    f = facts(d)
    assert f["restore_marker"] is True and f["restore_markers"] == ["bridge_secrets"]


def test_facts_are_read_only(tmp_path):
    d = build(tmp_path)
    (d / ".sigrift-install.json").write_text('{"format": 1}\n')
    before = snapshot(d)
    facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY},
          container={"BRIDGE_MFA_KEY": KEY_B})
    assert snapshot(d) == before
    # With a live writer the -wal and -shm exist; a reader leaves them be.
    writer = sqlite3.connect(d / "detections.db")
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, "
                   "key_hash) VALUES ('k2', 'dmr', 'b', x'00', 'h2')")
    writer.commit()
    try:
        live = snapshot(d)
        assert "detections.db-wal" in live
        facts(d, env={"BRIDGE_MFA_KEY": KEY_A})
        after = snapshot(d)
        assert after["detections.db"] == live["detections.db"]
        assert after["detections.db-wal"] == live["detections.db-wal"]
    finally:
        writer.close()


def test_facts_never_contain_a_secret_value(tmp_path):
    d = build(tmp_path)
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY,
                      "BRIDGE_KEYSTORE_KEY": KEY_B},
              container={"BRIDGE_MASTER_KEY": "engine-test-master-key",
                         "BRIDGE_AUDIT_SECRET": "engine-test-legacy"})
    text = json.dumps(f)
    for secret in SECRETS:
        assert secret not in text
        assert hashlib.sha256(secret.encode()).hexdigest() not in text
    for raw in (bytes(range(32)), bytes(range(32, 64))):
        assert raw.hex() not in text


def test_fingerprint_vectors(tmp_path):
    d = tmp_path / "fp"
    d.mkdir()
    fps = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY,
                        "BRIDGE_KEYSTORE_KEY": KEY_A})["candidates"]["env"]["fingerprints"]

    def fp(secret: bytes, name: str) -> str:
        return hmac.new(secret, b"sigrift-key-fingerprint-v1:" + name.encode(),
                        hashlib.sha256).hexdigest()[:32]

    assert fps["mfa"] == fp(bytes(range(32)), "mfa")
    assert fps["keystore"] == fp(bytes(range(32)), "keystore")
    assert fps["audit"] == fp(hashlib.sha256(AUDIT_KEY.encode()).digest(), "audit")
    # Pinned values: a change to the derivation breaks every volume record.
    assert fps["mfa"] == "db91c926cb9718d3f03af49e4a4ee61f"
    assert len({fps["mfa"], fps["keystore"]}) == 2  # the name separates them


def test_write_record_is_atomic_and_0600(tmp_path):
    d = build(tmp_path, totp=False, crypto=False)
    rc, reply = run({"format": 1, "op": "write-record", "data_dir": str(d),
                     "record": {"format": 1, "install_id": "abc", "project": "lab"},
                     "secrets": {"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY}})
    assert rc == 0 and reply == {"format": 1, "ok": True, "op": "write-record"}
    path = d / ".sigrift-install.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    rec = json.loads(path.read_text())
    assert rec["install_id"] == "abc" and rec["schema"] == max(v for v, _, _ in _MIGRATIONS)
    assert rec["fingerprints"]["audit"]["source"] == "env-key"
    assert rec["fingerprints"]["mfa"] == "db91c926cb9718d3f03af49e4a4ee61f"
    assert not list(d.glob("*.tmp"))
    for secret in SECRETS:
        assert secret not in path.read_text()
    # The record proves the same .env against the same data later.
    f = facts(d, env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
    assert f["record"]["fingerprints"]["audit"]["fp"] == f["candidates"]["env"]["fingerprints"]["audit"]


def test_engine_source_is_ascii_and_the_bootstrap_holds_no_secret(tmp_path):
    ENGINE.encode("ascii")
    BOOTSTRAP.encode("ascii")
    assert "environ" not in BOOTSTRAP and "KEY" not in BOOTSTRAP
    # The bootstrap reads the engine and the request from stdin, as the
    # installers send them, and runs the op.
    d = build(tmp_path, totp=False, entries=0, crypto=False)
    req = json.dumps({"format": 1, "op": "facts", "data_dir": str(d),
                      "candidates": {"env": {"BRIDGE_MFA_KEY": KEY_A}}}).encode()
    src = ENGINE.encode()
    payload = b"%d\n%s%d\n%s" % (len(src), src, len(req), req)
    env = {k: v for k, v in os.environ.items() if not k.startswith("BRIDGE_")}
    env["PYTHONPATH"] = str(ROOT / "src")
    r = subprocess.run([sys.executable, "-c", BOOTSTRAP], input=payload, capture_output=True,
                       env=env, timeout=60)
    assert r.returncode == 0, r.stderr
    reply = json.loads(r.stdout)
    assert reply["ok"] and reply["candidates"]["env"]["mfa"] == "n/a"
    short = subprocess.run([sys.executable, "-c", BOOTSTRAP], input=b"100\nabc", capture_output=True,
                           env=env, timeout=60)
    assert short.returncode != 0 and b"engine: short input" in short.stderr
