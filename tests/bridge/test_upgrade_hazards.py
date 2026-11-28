"""The state engine against data the bridge's own stores wrote (phase1b-spec 11.3).

The state-engine and lifecycle-engine sources of scripts/install-release.sh
run in process as one module (as in the bridge image). The fixture volume
is written by DetectionStore (users with TOTP, backup codes, sessions, the
audit chain), PersistenceManager (API keys, webhooks) and the
CertificateAuthority (issued and revoked client certificates); a rollback
is snapshot -> changes to the live data -> stage -> carry, and every rule
of 4.6 is checked with the bridge reading the result back.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import struct
from pathlib import Path

import pytest

from sigrift.bridge import persistence as persistence_mod
from sigrift.bridge.ca import CertificateAuthority
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.storage import users as users_mod
from sigrift.bridge.storage.audit import AuditStore

ROOT = Path(__file__).resolve().parents[2]
TEXT = (ROOT / "scripts" / "install-release.sh").read_text()


def block(name):
    return re.search(r"(?ms)^# >>> shared: %s .*?^# <<< shared: %s\n" % (name, name),
                     TEXT).group(0)


ENGINE = (re.search(r"cat <<'PY'\n(.*?)\nPY\n", block("state-engine"), re.S).group(1) + "\n"
          + re.search(r"cat <<'PY'\n(.*?)\nPY\n", block("lifecycle-engine"), re.S).group(1)
          + "\n")
TOOL_SRC = re.search(r"<<'PY'\n(.*?)\nPY\n", block("state-tool"), re.S).group(1) + "\n"
MFA_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode()
AUDIT_KEY = "hazards-audit-key"
RB = "20261127T120000Z"
RP = "20261127T110000Z-v0.1.0-full"
EXCLUDES = ["backups", "exports", "detections.db.pre-migration", "detections.db.pre-migration.*",
            "detections.db.failed-migration-*", "detections.db-wal.failed-migration-*",
            "detections.db-shm.failed-migration-*", "*.corrupt-*", "detections.db-shm"]
KEEP_BACK = ["backups", "exports", "*.failed-migration-*", "*.corrupt-*"]
pytestmark = pytest.mark.xdist_group("upgrade_hazards")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("BRIDGE_MFA_KEY", "BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY",
                 "BRIDGE_SECRETS_DIR"):
        monkeypatch.delenv(name, raising=False)
    users_mod._fernet_instance = None
    yield
    users_mod._fernet_instance = None


def key_hash(raw: str) -> tuple[str, bytes]:
    salt = hashlib.sha256(raw.encode()).digest()[:16]
    return hashlib.pbkdf2_hmac("sha256", raw.encode(), salt, 1000).hex(), salt


def open_store(data: Path) -> DetectionStore:
    return DetectionStore(db_path=data / "detections.db")


def write_volume(base: Path) -> tuple[Path, Path]:
    data, secrets = base / "data", base / "secrets"
    data.mkdir(parents=True)
    secrets.mkdir()
    os.environ["BRIDGE_MFA_KEY"] = MFA_KEY
    os.environ["BRIDGE_AUDIT_KEY"] = AUDIT_KEY
    users_mod._fernet_instance = None
    store = open_store(data)
    try:
        for name, role in (("admin", "admin"), ("alice", "analyst"), ("bob", "viewer")):
            store._users.create_user(name, "Password123!" + name, role=role)
        admin = store._users.get_user("admin")
        store._users.set_totp_secret(admin["id"], "JBSWY3DPEHPK3PXP")
        store._users.enable_mfa(admin["id"])
        store._users.store_backup_codes(admin["id"], [("h1", b"s1"), ("h2", b"s2")])
        store._users.create_session(admin["id"])
        for i in range(3):
            store.log_audit("dismiss", "target-%d" % i, operator="admin")
        conn = store.get_connection()
        conn.execute("INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, "
                     "key_hash) VALUES ('ck1', 'dmr', 'site', x'00', 'h1')")
        conn.execute("INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, "
                     "key_hash) VALUES ('ck2', 'p25', 'site2', x'00', 'h2')")
        conn.commit()
    finally:
        store.close()
        os.environ.pop("BRIDGE_MFA_KEY")
        os.environ.pop("BRIDGE_AUDIT_KEY")
        users_mod._fernet_instance = None
    pm = PersistenceManager(data_dir=data)
    pm.load_all()
    for kid, role in (("master", "admin"), ("edge_pi1", "sensor"), ("ops", "analyst"),
                      ("rot", "viewer"), ("gone", "viewer"), ("bindme", "sensor")):
        h, salt = key_hash(kid)
        pm.add_key(kid, h, salt, lookup_hash=hashlib.sha256(kid.encode()).hexdigest(),
                   meta={"role": role, "description": kid, "created_at": "2026-11-01"})
    for wid in ("wh1", "wh2"):
        pm.change_webhook(wid, create={"id": wid, "url": "https://hooks.example/" + wid,
                                       "enabled": True, "signing_secret": "secret-" + wid,
                                       "events": ["alert"]})
    os.environ["BRIDGE_SECRETS_DIR"] = str(secrets)
    try:
        ca = CertificateAuthority(data / "ca", key_dir=secrets / "ca")
        ca.ensure_ca()
        for ident in ("edge-a", "edge-b"):
            ca.issue_cert(identity=ident, role="node")
    finally:
        os.environ.pop("BRIDGE_SECRETS_DIR")
    return data, secrets


@pytest.fixture(scope="module")
def template(tmp_path_factory):
    base = tmp_path_factory.mktemp("bridge-volume")
    write_volume(base)
    return base


class Rollback:
    """Two volumes copied from the template, the engine, the steps of 6.3."""

    def __init__(self, template: Path, tmp: Path):
        shutil.copytree(template, tmp / "vols", symlinks=True)
        self.data, self.secrets = tmp / "vols" / "data", tmp / "vols" / "secrets"
        self.ns = {"__name__": "sigrift_engine_hazards", "REQUEST": {}}
        exec(compile(ENGINE, "<sigrift-engine>", "exec"), self.ns)
        self.snaps = None
        self.R = self.data / (".sigrift-restore-" + RB)
        self.RS = self.secrets / (".sigrift-restore-" + RB)

    def call(self, op, stdin=b"", **req):
        out = io.BytesIO()
        self.ns["ST_IO"]["out"] = out
        self.ns["ST_IO"]["in"] = io.BufferedReader(io.BytesIO(stdin))
        full = {"format": 1, "op": op, "framed": True, "data_dir": str(self.data),
                "secrets_dir": str(self.secrets)}
        full.update(req)
        try:
            rc = self.ns["run"](full)
        except SystemExit as e:
            rc = e.code
        b, frames, i = out.getvalue(), [], 0
        while i < len(b):
            n = struct.unpack(">Q", b[i + 1:i + 9])[0]
            frames.append((b[i:i + 1], b[i + 9:i + 9 + n]))
            i += 9 + n
        return rc, json.loads(frames[-1][1]), frames

    def ok(self, op, stdin=b"", **req):
        rc, reply, frames = self.call(op, stdin, **req)
        assert rc == 0, reply
        return reply

    def take(self):
        """The restore point: both archives, the state and rf rows."""
        self.snaps = {}
        for vol in ("bridge_secrets", "bridge_data"):
            rc, r, frames = self.call("snapshot-volume", volume=vol,
                                      excludes=EXCLUDES if vol == "bridge_data" else [])
            assert rc == 0, r
            self.snaps[vol] = (b"".join(p for k, p in frames if k == b"D"),
                               b"".join(p for k, p in frames if k == b"M"), r)
        rc, st, frames = self.call("state", rf_rows=True,
                                   env={"BRIDGE_MFA_KEY": MFA_KEY, "BRIDGE_AUDIT_KEY": AUDIT_KEY})
        rows = {"streams": [], "fences": [], "summary_hours": {}}
        for line in b"".join(p for k, p in frames if k == b"M").decode().splitlines():
            o = json.loads(line)
            if "s" in o:
                rows["streams"].append(o["s"])
            elif "f" in o:
                rows["fences"].append(o["f"])
            elif "h" in o:
                rows["summary_hours"][o["h"]] = o["v"]
        self.state, self.rows = st, json.dumps(rows).encode()
        return st

    def rp(self):
        st = self.state
        rp = dict((k, st[k]) for k in ("marks", "security", "captures", "counts", "db"))
        rp.update(rf_summary=st["rf"], audit={"head_id": st["audit"]["head_id"]},
                  created_at="2026-11-27T11:00:00Z")
        return rp

    def compare(self, **extra):
        return self.ok("compare", section(self.rows), rp=self.rp(), rf_rows_section=True,
                       **extra)

    def stage(self):
        for vol, (arch, mem, r) in self.snaps.items():
            rc, reply, _ = self.call(
                "stage", section(mem) + section(arch), volume=vol, rb_id=RB, restore_point=RP,
                archive_sha256=r["archive_sha256"], archive_bytes=r["archive_bytes"],
                members_file_sha256=r["members_sha256"],
                keep_back=KEEP_BACK if vol == "bridge_data" else [],
                excludes=EXCLUDES if vol == "bridge_data" else [], reserve_bytes=0)
            assert rc == 0, reply

    def carry(self, no_carry=False, keep_master=True):
        return self.call("carry", rb_id=RB, no_carry=no_carry, keep_current_master=keep_master)

    def swap(self):
        for vol in ("bridge_secrets", "bridge_data"):
            self.ok("swap", volume=vol, rb_id=RB, restore_point=RP, keep_back=KEEP_BACK)

    def live_pm(self):
        pm = PersistenceManager(data_dir=self.data)
        pm.load_all()
        return pm

    def live_store(self):
        return open_store(self.data)


def loaded(path):
    pm = PersistenceManager(data_dir=path)
    pm.load_all()
    return pm


def section(data: bytes) -> bytes:
    step = 1 << 20
    return b"".join(b"%d\n" % len(data[i:i + step]) + data[i:i + step]
                    for i in range(0, len(data), step)) + b"0\n"


@pytest.fixture
def rb(template, tmp_path):
    return Rollback(template, tmp_path)


def db(path: Path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


# ── 1-6 quiesce, table classes, no false positive ──────────────────────


def test_quiesce_checkpoints_the_wal_and_strict_mode_refuses_a_corrupt_db(rb):
    writer = db(rb.data / "detections.db")
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, "
                   "key_hash) VALUES ('ck9', 'dmr', 'x', x'00', 'h9')")
    writer.commit()
    writer.close()
    r = rb.ok("quiesce", mode="strict")
    assert r["db"]["quick_check"] == "ok"
    assert not (rb.data / "detections.db-wal").exists() or \
        (rb.data / "detections.db-wal").stat().st_size == 0
    raw = bytearray((rb.data / "detections.db").read_bytes())
    for off in range(4096 * 3, min(len(raw), 4096 * 6)):
        raw[off] = 0x55
    (rb.data / "detections.db").write_bytes(bytes(raw))
    rc, reply, _ = rb.call("quiesce", mode="strict")
    assert rc == 1 and reply["code"] in ("quick-check", "io")
    # report mode (a rollback, which replaces this database anyway) goes on
    rc, reply, _ = rb.call("quiesce", mode="report")
    assert rc == 1 or reply["db"]["quick_check"] != "ok"


def test_volatile_derived_and_queue_names_exist_at_schema_56(rb):
    ns = rb.ns
    tables = set(r[0] for r in db(rb.data / "detections.db").execute(
        "SELECT name FROM sqlite_master WHERE type='table'"))
    gateway_only = {"mfa_attempts", "pending_commands"}
    lazily_created = {"saf_queue", "webhook_retries", "iq_capture_requests", "ingest_hook_claims",
                      "protocol_decode_claims"}
    for name in ns["ST_VOLATILE"] + ns["ST_DERIVED"] + ns["ST_CONTENT"]:
        assert name in tables or name in gateway_only, name
    for name in ns["ST_QUEUE"]:
        assert name in tables or name in gateway_only | lazily_created, name
    state = rb.ok("state")
    assert state["schema"] == 56


def grep_sources(pattern):
    hits = []
    for base in (ROOT / "src" / "sigrift" / "bridge", ROOT / "src" / "gateway"):
        for p in base.rglob("*"):
            if p.suffix not in (".py", ".rs") or "tests" in p.parts or not p.is_file():
                continue
            text = p.read_text(errors="replace")
            for m in re.finditer(pattern, text, re.I | re.S):
                hits.append((p.relative_to(ROOT).as_posix(), text[:m.start()].count("\n") + 1,
                             m.group(0)))
    return hits


DERIVED_WRITERS = {
    "detection_aggregates": "storage/detection_analytics.py",
    "wifi_metadata_hourly": "storage/wifi_metadata.py",
    "bt_devices_hourly": "storage/bt_metadata.py",
    "zigbee_devices_hourly": "storage/zigbee_metadata.py",
    "device_lifecycles_daily": "storage/device_lifecycle.py",
    "fhss_event_summaries": "storage/fhss_store.py",
}


def test_derived_tables_have_no_direct_writer(rb):
    for table in rb.ns["ST_DERIVED"]:
        hits = grep_sources(r"INSERT\s+(?:OR\s+\w+\s+)?INTO\s+%s\b" % table)
        assert hits, table
        for path, line, _ in hits:
            assert path.endswith(DERIVED_WRITERS[table]), (table, path, line)


def test_the_bridges_own_rollup_and_cleanup_jobs_leave_compare_nothing_new(rb):
    rb.take()
    store = rb.live_store()
    try:
        store.aggregate_hourly()
        store.aggregate_wifi_hourly()
        store.aggregate_bt_hourly()
        store.aggregate_zigbee_hourly()
        store._detection_summaries.rollup_from_raw()
        store.cleanup()
        store.cleanup_wifi_metadata()
        store.cleanup_spectrum_snapshots()
    finally:
        store.close()
    r = rb.compare()
    assert r["checkable"] is True and r["nothing_new"] is True, (r["discards"], r["carries"])


def test_raw_only_nodes_leave_the_rf_tables_empty(rb):
    store = rb.live_store()
    try:
        conn = store.get_connection()
        conn.execute("INSERT INTO detections (detection_id, timestamp, node_id, signal_class, "
                     "freq_hz, confidence, tenant_id) VALUES ('raw1', '2026-01-01T00:00:00Z', "
                     "'raw-node', 'fm', 1e8, 0.9, 'default')")
        conn.commit()
        store._detection_summaries.rollup_from_raw()
    finally:
        store.close()
    c = db(rb.data / "detections.db")
    assert c.execute("SELECT COUNT(*) FROM rf_summary_streams").fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM rf_summary_components WHERE component = "
                     "'raw_rollup'").fetchone()[0] == 0


def stream_rows(conn, hour="2026-11-27T10:00:00Z", generation=1):
    conn.execute("INSERT OR IGNORE INTO rf_summary_streams VALUES ('default', 'n1', 's1')")
    conn.execute("INSERT OR REPLACE INTO rf_summary_generations VALUES ('default', 'n1', 's1', ?, ?, "
                 "'d', X'7b7d', 0)", (hour, generation))
    conn.commit()


@pytest.mark.parametrize("change", ["new-hour", "retired", "pre56"])
def test_rf_guard_refuses_a_new_hour_at_the_same_generation_a_retired_flip_and_a_pre56_point_with_live_rows(rb, change):
    conn = db(rb.data / "detections.db")
    if change != "pre56":
        stream_rows(conn)
    rb.take()
    if change == "pre56":
        rb.state["rf"] = {"tables": False, "rows": {}, "digest": "sha256:" + "0" * 64}
        stream_rows(conn)
    elif change == "new-hour":
        stream_rows(conn, hour="2026-11-27T11:00:00Z")
    else:
        conn.execute("UPDATE rf_summary_generations SET retired = 1")
        conn.commit()
    conn.close()
    r = rb.compare()
    want = {"pre56": "absent-rp", "new-hour": "changed", "retired": "changed"}[change]
    assert r["discards"]["rf"] == want and r["nothing_new"] is False
    import types
    tool = types.ModuleType("tool")
    exec(compile(TOOL_SRC, "<lc_state_tool>", "exec"), tool.__dict__)

    class P:
        id = RP
    import contextlib
    err = io.StringIO()
    with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as e:
        tool.rf_guard("/tmp", P, {"from_version": "v0.1.0"}, r, accept=False)
    assert e.value.code == 3
    assert ("predates the RF summary tables" in err.getvalue()) is (change == "pre56")


def test_compare_ignores_the_master_key_lookup_hash_added_at_boot(rb):
    rb.take()
    keys = json.loads((rb.data / "keys.json").read_text())
    keys["keys"]["master"]["lookup_hash"] = "added-at-boot"
    (rb.data / "keys.json").write_text(json.dumps(keys))
    assert rb.compare()["nothing_new"] is True


# ── 7-19 the carry-forward ────────────────────────────────────────────


def test_carry_key_rules_match_stricter_key_field(rb):
    _stricter = persistence_mod._stricter_key_field
    roles = ["sensor", "node", "viewer", "analyst", "admin", "keymaster"]
    rank = rb.ns["st_rank"]
    for ours in roles:
        for theirs in roles:
            want = _stricter("role", theirs, ours)
            got = theirs if rank(theirs) < rank(ours) else ours
            assert rank(got) == rank(want), (ours, theirs)
    for field, values in (("revoked", (True, False)), ("enabled", (True, False))):
        for live in values:
            for restored in values:
                want = _stricter(field, live, restored)
                if field == "revoked":
                    got = True if live is True else restored
                else:
                    got = False if live is False else restored
                assert got == want, (field, live, restored)


def mutate_keys(rb, fn):
    pm = rb.live_pm()
    fn(pm)


def test_carry_takes_an_earlier_expiry_an_added_node_binding_and_a_rotated_credential(rb):
    rb.take()

    def change(pm):
        meta = pm.get_saved_key_meta("ops") or {}
        pm.set_key_meta("ops", dict(meta, expires_at="2026-12-01T00:00:00+00:00"))
        pm.update_key_access("bindme", node_id="pi-7", set_node=True)
        h, salt = key_hash("rot-v2")
        pm.set_key("rot", h, salt, lookup_hash=hashlib.sha256(b"rot-v2").hexdigest())
    mutate_keys(rb, change)
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0, rep
    assert rep["api_keys_expiry_earlier"] == ["ops"] and rep["api_keys_bound"] == ["bindme"]
    assert rep["api_keys_rotated"] == ["rot"]
    restored = loaded(rb.R)
    meta = restored.get_key_meta()
    assert meta["ops"]["expires_at"] == "2026-12-01T00:00:00+00:00"
    assert meta["bindme"]["node_id"] == "pi-7"
    assert restored.get_key_store()["rot"][0] == key_hash("rot-v2")[0]
    assert json.loads((rb.R / "keys.json").read_text()) == json.loads(
        (rb.R / "keys.json.bak").read_text())


def test_restored_bridge_rejects_a_revoked_key_and_accepts_a_rotated_one(rb):
    rb.take()

    def change(pm):
        meta = pm.get_saved_key_meta("ops") or {}
        pm.set_key_meta("ops", dict(meta, revoked=True))
        pm.remove_key("gone")
        h, salt = key_hash("rot-v2")
        pm.set_key("rot", h, salt, lookup_hash=hashlib.sha256(b"rot-v2").hexdigest())
    mutate_keys(rb, change)
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["api_keys_revoked"] == ["ops"] and rep["api_keys_removed"] == ["gone"]
    rb.swap()
    pm = rb.live_pm()
    assert pm.get_key_meta()["ops"].get("revoked") is True and not pm.has_key("gone")
    assert pm.get_key_store()["rot"] == (key_hash("rot-v2")[0], key_hash("rot-v2")[1])
    assert pm.get_key_fast_index().get(hashlib.sha256(b"rot-v2").hexdigest()) == "rot"


def test_carried_registry_marks_the_serial_revoked_for_the_ca(rb):
    ca = CertificateAuthority(rb.data / "ca", key_dir=rb.secrets / "ca")
    serials = [c["serial"] for c in ca.list_certs()]
    rb.take()
    ca.revoke(serials[0])
    reg = json.loads((rb.data / "ca" / "registry.json").read_text())
    del reg["issued"][serials[1]]
    (rb.data / "ca" / "registry.json").write_text(json.dumps(reg))
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and sorted(rep["ca_serials_revoked"]) == sorted(serials)
    restored = CertificateAuthority(rb.R / "ca", key_dir=rb.RS / "ca")
    states = {c["serial"]: c["revoked"] for c in restored.list_certs()}
    assert states == {serials[0]: True, serials[1]: True}


def test_a_replaced_ca_is_carried_and_the_old_cas_certificates_are_refused(rb):
    rb.take()
    (rb.data / "ca" / "ca.crt").unlink()
    (rb.secrets / "ca" / "ca.key").unlink()
    os.environ["BRIDGE_SECRETS_DIR"] = str(rb.secrets)
    try:
        CertificateAuthority(rb.data / "ca", key_dir=rb.secrets / "ca").ensure_ca()
    finally:
        os.environ.pop("BRIDGE_SECRETS_DIR")
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["ca_replaced"] is True and len(rep["ca_serials_revoked"]) == 2
    assert (rb.R / "ca" / "ca.crt").read_bytes() == (rb.data / "ca" / "ca.crt").read_bytes()
    assert (rb.RS / "ca" / "ca.key").read_bytes() == (rb.secrets / "ca" / "ca.key").read_bytes()
    restored = CertificateAuthority(rb.R / "ca", key_dir=rb.RS / "ca")
    assert all(c["revoked"] for c in restored.list_certs())
    assert json.loads((rb.R / ".sigrift-carried").read_text())["ca_carried"] is True


def user_row(path, name):
    return db(path / "detections.db").execute("SELECT * FROM users WHERE username = ?",
                                              (name,)).fetchone()


def test_carry_users_deleted_or_disabled_stay_disabled_and_roles_only_go_down(rb):
    rb.take()
    store = rb.live_store()
    try:
        store._users.disable_user("bob")
        store._users.update_user("alice", role="viewer")
        store.get_connection().execute("DELETE FROM users WHERE username = 'bob'")
        store.get_connection().commit()
    finally:
        store.close()
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["users_disabled"] == ["bob"] and rep["users_role_lowered"] == ["alice"]
    assert user_row(rb.R, "bob")["enabled"] == 0 and user_row(rb.R, "alice")["role"] == "viewer"


def test_carry_backup_codes_used_or_regenerated_stay_unusable(rb):
    rb.take()
    c = db(rb.data / "detections.db")
    first = c.execute("SELECT MIN(id) FROM mfa_backup_codes").fetchone()[0]
    c.execute("UPDATE mfa_backup_codes SET used = 1 WHERE id = ?", (first,))
    c.execute("DELETE FROM mfa_backup_codes WHERE id != ?", (first,))
    c.execute("INSERT INTO mfa_backup_codes (user_id, code_hash, salt, used, created_at) "
              "VALUES (1, 'new', x'00', 0, 'now')") if "salt" in [
        r[1] for r in c.execute("PRAGMA table_info(mfa_backup_codes)")] else None
    c.commit()
    c.close()
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["backup_codes_invalidated"] == {"admin": 2}
    assert db(rb.R / "detections.db").execute(
        "SELECT COUNT(*) FROM mfa_backup_codes WHERE used = 0").fetchone()[0] == 0


def test_carry_ends_every_session_mfa_token_and_oidc_state(rb):
    rb.take()
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["sessions"]["ended"] >= 1
    r = db(rb.R / "detections.db")
    for t in ("sessions", "mfa_tokens", "oidc_states"):
        assert r.execute("SELECT COUNT(*) FROM %s" % t).fetchone()[0] == 0


def test_carry_crypto_keys_deleted_since_are_deleted_and_created_since_are_counted(rb):
    rb.take()
    c = db(rb.data / "detections.db")
    c.execute("DELETE FROM crypto_keys WHERE id = 'ck1'")
    c.execute("UPDATE crypto_keys SET revoked_at = '2026-11-27T11:30:00Z' WHERE id = 'ck2'")
    c.execute("INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, key_hash) "
              "VALUES ('ck3', 'meshtastic', 'lab', x'00', 'h3')")
    c.commit()
    c.close()
    cmp_ = rb.compare()
    assert cmp_["carries"]["crypto_keys_deleted"] == ["ck1"]
    assert cmp_["discards"]["crypto_keys_imported"] == [{"protocol": "meshtastic", "label": "lab"}]
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rep["crypto_keys_deleted"] == ["ck1"] and rep["crypto_keys_revoked"] == ["ck2"]
    rows = dict(db(rb.R / "detections.db").execute("SELECT id, revoked_at FROM crypto_keys"))
    assert rows == {"ck2": "2026-11-27T11:30:00Z"}


def test_carry_webhooks_deleted_or_disabled_since_stay_so_with_the_live_revision(rb):
    rb.take()
    pm = rb.live_pm()
    pm.change_webhook("wh1", updates={"enabled": False})
    pm.change_webhook("wh2", delete=True)
    live_rev = [w for w in pm.current_webhooks() if w["id"] == "wh1"][0]["delivery_revision"]
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rep["webhooks_disabled"] == ["wh1"] and rep["webhooks_removed"] == ["wh2"]
    restored = json.loads((rb.R / "webhooks.json").read_text())["webhooks"]
    assert [(w["id"], w["enabled"], w["delivery_revision"]) for w in restored] == [
        ("wh1", False, live_rev)]
    assert loaded(rb.R).current_webhooks()[0]["enabled"] is False


def test_carry_tenant_mfa_requirement_stays_on(rb):
    rb.take()
    c = db(rb.data / "detections.db")
    c.execute("INSERT OR REPLACE INTO tenant_settings (tenant_id, mfa_required, updated_at) "
              "VALUES ('default', 1, 'now')")
    c.commit()
    c.close()
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rep["mfa_required_on"] == ["default"]
    assert db(rb.R / "detections.db").execute(
        "SELECT mfa_required FROM tenant_settings WHERE tenant_id='default'").fetchone()[0] == 1


def test_carry_lists_password_totp_and_webhook_secret_changes_without_applying_them(rb):
    rb.take()
    old_pw = user_row(rb.data, "alice")["password_hash"]
    os.environ["BRIDGE_MFA_KEY"] = MFA_KEY
    users_mod._fernet_instance = None
    store = rb.live_store()
    try:
        store._users.set_password("alice", "AnotherPassword9!")
        admin = store._users.get_user("admin")
        store._users.set_totp_secret(admin["id"], "KRSXG5CTMVRXEZLU")
    finally:
        store.close()
        os.environ.pop("BRIDGE_MFA_KEY")
        users_mod._fernet_instance = None
    rb.live_pm().change_webhook("wh2", updates={"signing_secret": "rotated"})
    cmp_ = rb.compare()
    cred = cmp_["not_carried"]["credentials"]
    assert cred["passwords_changed"] == ["alice"] and cred["totp_changed"] == ["admin"]
    assert cred["webhook_secrets_changed"] == ["wh2"]
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rep["not_carried"]["credentials"]["passwords_changed"] == ["alice"]
    assert user_row(rb.R, "alice")["password_hash"] == old_pw
    assert [w["signing_secret"] for w in json.loads((rb.R / "webhooks.json").read_text())[
        "webhooks"] if w["id"] == "wh2"] == ["secret-wh2"]


def test_master_rotation_is_not_carried_when_no_audit_key_is_set(rb):
    rb.take()
    h, salt = key_hash("master-v2")
    rb.live_pm().set_key("master", h, salt, lookup_hash="new")
    assert rb.compare(keep_current_master=False)["not_carried"]["credentials"][
        "keys_rotated_back"] == ["master"]
    rb.stage()
    rc, rep, _ = rb.carry(keep_master=False)
    assert rep["api_keys_rotated"] == [] and rep["not_carried"]["credentials"][
        "keys_rotated_back"] == ["master"]
    assert loaded(rb.R).get_key_store()["master"][0] == key_hash("master")[0]


def test_carry_is_idempotent(rb):
    rb.take()
    pm = rb.live_pm()
    pm.set_key_meta("ops", dict(pm.get_saved_key_meta("ops") or {}, revoked=True))
    rb.stage()
    rc, first, _ = rb.carry()
    before = {p: p.read_bytes() for p in rb.R.rglob("*") if p.is_file()}
    rc, second, _ = rb.carry()
    assert rc == 0 and second.pop("already") is True and second == first
    assert {p: p.read_bytes() for p in rb.R.rglob("*") if p.is_file()} == before


def test_a_crash_inside_carry_is_finished_with_the_first_report(rb, monkeypatch):
    rb.take()
    pm = rb.live_pm()
    pm.set_key_meta("ops", dict(pm.get_saved_key_meta("ops") or {}, revoked=True))
    pm.change_webhook("wh2", delete=True)
    rb.stage()
    real = rb.ns["st_carry_webhooks"]

    def crash(R, L, rep, apply):
        if apply:
            raise KeyboardInterrupt("killed while applying")
        return real(R, L, rep, apply)
    monkeypatch.setitem(rb.ns, "st_carry_webhooks", crash)
    with pytest.raises(KeyboardInterrupt):
        rb.carry()
    monkeypatch.setitem(rb.ns, "st_carry_webhooks", real)
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["api_keys_revoked"] == ["ops"] and rep["webhooks_removed"] == ["wh2"]
    assert json.loads((rb.R / "webhooks.json").read_text())["webhooks"][0]["id"] == "wh1"


@pytest.mark.parametrize("what", ["keys", "registry", "webhooks"])
def test_unreadable_live_state_fails_unless_no_carry_and_then_only_sessions_end(rb, what):
    rb.take()
    path = {"keys": rb.data / "keys.json", "registry": rb.data / "ca" / "registry.json",
            "webhooks": rb.data / "webhooks.json"}[what]
    path.write_text("{not json")
    if what == "keys":
        (rb.data / "keys.json.bak").write_text("{not json")
    rb.stage()
    rc, reply, _ = rb.carry()
    assert rc == 1 and reply["code"] == "unreadable"
    keys_before = (rb.R / "keys.json").read_bytes()
    rc, rep, _ = rb.carry(no_carry=True)
    assert rc == 0 and rep["sessions"]["ended"] >= 1 and rep["api_keys_revoked"] == []
    assert (rb.R / "keys.json").read_bytes() == keys_before


def test_encrypted_header_snapshot_is_opaque_and_its_checks_report_not_done(rb):
    raw = bytearray((rb.data / "detections.db").read_bytes())
    raw[:16] = os.urandom(16)
    (rb.data / "detections.db").write_bytes(bytes(raw))
    st = rb.take()
    assert st["db"]["encrypted"] is True and st["marks"] is None and \
        st["security"]["readable"]["db"] is False
    assert rb.compare()["checkable"] is False
    rb.stage()
    rc, rep, _ = rb.carry()
    assert rc == 0 and rep["db"].startswith("not done")


# ── 20-25 audit, round trip, secrets, verify-carry, watermarks, queues ────


def test_discarded_audit_export_has_exactly_the_rows_after_the_head(rb):
    st = rb.take()
    head = st["audit"]["head_id"]
    os.environ["BRIDGE_AUDIT_KEY"] = AUDIT_KEY
    store = rb.live_store()
    try:
        store.log_audit("login", "bob", operator="bob")
        store.log_audit("logout", "bob", operator="bob")
    finally:
        store.close()
        os.environ.pop("BRIDGE_AUDIT_KEY")
    rc, r, frames = rb.call("export-audit", after=head, rb_id=RB)
    lines = [json.loads(x) for x in b"".join(p for k, p in frames if k == b"D").decode()
             .splitlines()]
    assert [x["id"] for x in lines] == [head + 1, head + 2] and all(x["rb_id"] == RB
                                                                    for x in lines)
    assert r["rows"] == 2 and r["last_hmac"] == lines[-1]["hmac_chain"]


def verify_chain(path: Path):
    from sigrift.bridge.storage import audit as audit_mod
    conn = sqlite3.connect(path / "detections.db")
    conn.row_factory = sqlite3.Row

    class Ctx:
        tenant_id = "default"

        def get_conn(self):
            return conn

        def tenant_filter(self, *a, **k):
            return "", []
    original = audit_mod._get_audit_secret
    audit_mod._get_audit_secret = lambda: hashlib.sha256(AUDIT_KEY.encode()).digest()
    try:
        return AuditStore(Ctx()).verify_chain()
    finally:
        audit_mod._get_audit_secret = original
        conn.close()


def test_audit_append_writes_one_rollback_entry_with_the_restored_versions_writer_and_the_chain_verifies(rb):
    st = rb.take()
    rb.stage()
    assert rb.carry()[0] == 0
    req = dict(rb_id=RB, restore_point=RP, from_version="v0.2.0", to_version="v0.1.0",
               env={"BRIDGE_AUDIT_KEY": AUDIT_KEY},
               discarded={"first_id": 4, "last_id": 9, "count": 6, "last_hmac": "x",
                          "export_sha256": "e" * 64})
    r = rb.ok("audit-append", **req)
    assert r["written"] is True and r["id"] == st["audit"]["head_id"] + 1
    row = db(rb.R / "detections.db").execute("SELECT * FROM audit_log ORDER BY id DESC "
                                             "LIMIT 1").fetchone()
    assert (row["action"], row["target_id"], row["operator"]) == ("installer_rollback", RB,
                                                                 "install-release.sh")
    assert json.loads(row["details"])["discarded"]["export_sha256"] == "e" * 64
    v = verify_chain(rb.R)
    assert v["valid"] is True and not v.get("errors")
    again = rb.ok("audit-append", **req)
    assert again["already"] is True and again["id"] == r["id"]
    assert rb.ok("audit-append", **dict(req, env={}))["already"] is True
    c = db(rb.R / "detections.db")
    c.execute("DELETE FROM audit_log WHERE action = 'installer_rollback'")
    c.commit()
    c.close()
    assert rb.ok("audit-append", **dict(req, env={}))["written"] is False


def test_round_trip_of_a_bridge_written_volume_is_byte_identical(rb):
    def files(root):
        return {p.relative_to(root).as_posix(): (p.read_bytes() if p.is_file() else
                                                 os.readlink(p) if p.is_symlink() else None,
                                                 p.lstat().st_mode & 0o777,
                                                 p.lstat().st_mtime_ns)
                for p in root.rglob("*") if not p.relative_to(root).as_posix().startswith(
                    (".sigrift-", "backups"))}
    want_d, want_s = files(rb.data), files(rb.secrets)
    rb.take()
    rb.stage()
    for vol in ("bridge_secrets", "bridge_data"):
        root = rb.secrets if vol == "bridge_secrets" else rb.data
        S = root / (".sigrift-restore-" + RB)
        got = files(S)
        got.pop(".sigrift-staged", None)
        assert got == (want_s if vol == "bridge_secrets" else want_d)


def test_state_and_compare_never_contain_a_secret_or_a_full_credential_hash(rb):
    st = rb.take()
    text = json.dumps(st) + json.dumps(rb.compare())
    assert MFA_KEY not in text and AUDIT_KEY not in text
    keys = json.loads((rb.data / "keys.json").read_text())["keys"]
    for e in keys.values():
        assert e["hash"] not in text and e["salt"] not in text
    pw = user_row(rb.data, "alice")["password_hash"]
    assert pw not in text and "secret-wh1" not in text
    totp = user_row(rb.data, "admin")["totp_secret"]
    assert totp not in text


def test_verify_carry_detects_a_resurrected_key(rb):
    rb.take()
    pm = rb.live_pm()
    pm.set_key_meta("ops", dict(pm.get_saved_key_meta("ops") or {}, revoked=True))
    pm.remove_key("gone")
    rb.stage()
    rc, rep, _ = rb.carry()
    rb.swap()
    report = json.dumps(rep).encode()
    assert rb.ok("verify-carry", section(report))["carry_ok"] is True
    keys = json.loads((rb.data / "keys.json").read_text())
    keys["keys"]["gone"] = {"hash": "x", "salt": "00", "role": "admin"}
    keys["keys"]["ops"].pop("revoked")
    (rb.data / "keys.json").write_text(json.dumps(keys))
    r = rb.ok("verify-carry", section(report))
    assert r["carry_ok"] is False and len(r["mismatches"]) == 2


# Updates that only the bridge's own jobs make (no new input): (table, reason).
OWN_UPDATES = {
    "detections": "set_has_iq_capture and the analysis jobs (the IQ stub has its watermark)",
    "users": "last_login and the role/enable changes are in the security projection",
    "sessions": "VOLATILE", "mfa_tokens": "VOLATILE", "account_lockout": "VOLATILE",
    "rate_limit_login": "VOLATILE", "totp_replay_cache": "VOLATILE", "oidc_states": "VOLATILE",
    "mfa_backup_codes": "in the security projection (used)",
    "crypto_keys": "in the security projection (revoked_at)",
    "tenant_settings": "has updated_at",
    "audit_anchor": "the audit chain anchor moves with the head, which is compared",
}


def test_every_in_place_update_site_has_a_watermark(rb):
    ns = rb.ns
    rb.take()
    marks = rb.state["marks"]
    watermarked = set(k.split(".")[0] for k in marks["updates"])
    counted = set(marks["tables"])
    sites = grep_sources(r"\bUPDATE\s+([a-z_][a-z0-9_]*)\s+SET\b") + grep_sources(
        r"INSERT\s+INTO\s+([a-z_][a-z0-9_]*)\b[^;]{0,400}?ON\s+CONFLICT[^;]{0,200}?DO\s+UPDATE")
    names_ = set()
    for path, line, text in sites:
        m = re.search(r"(?:UPDATE|INTO)\s+([a-z_][a-z0-9_]*)", text, re.I)
        names_.add(m.group(1).lower())
    skip = set(ns["ST_VOLATILE"]) | set(ns["ST_DERIVED"]) | set(ns["ST_CONTENT"])
    missing = []
    for t in sorted(names_):
        if t in skip or t in OWN_UPDATES or t not in counted:
            continue
        if t in watermarked or t in ("nodes", "pending_commands"):
            continue
        missing.append(t)
    # Tables updated in place with neither a watermark nor a reason here make
    # condition (b) blind to a change: each needs one (phase1b-spec 4.5).
    assert set(missing) <= set(IN_PLACE_REASONS), sorted(set(missing) - set(IN_PLACE_REASONS))


# Counted tables updated in place with no watermark, and why that cannot hide new
# data from condition (b): an automatic rollback needs a gateway that was never
# healthy, so no operator action reached the bridge, and ingest adds counted rows.
IN_PLACE_REASONS = {
    "audit_log": "append-only; compared by id and by its head",
    "bt_anomalies": "dismiss/snooze are operator actions; repeat sightings come with new "
                    "bt_devices and detections rows",
    "rf_anomalies": "dismiss/snooze and rescoring are operator actions; stale-resolved is "
                    "the bridge's own job",
    "wifi_anomalies": "dismiss/snooze are operator actions; repeat sightings come with new "
                      "wifi_metadata rows",
    "sweeps": "sweep status is driven by sweep results, which are counted rows",
    "sweep_zones": "zone edits are operator actions; anomaly_count moves with new anomaly rows",
}


def test_queue_tables_are_counted_and_marked_for_verify(rb):
    st = rb.take()
    assert set(st["marks"]["queue"]) == set(rb.ns["ST_QUEUE"]) & set(st["marks"]["tables"])


def test_facts_report_lifecycle_entries_and_both_markers(rb):
    (rb.secrets / ".sigrift-restore-incomplete").write_text(json.dumps({"id": RB}))
    P = rb.data / (".sigrift-replaced-" + RB)
    P.mkdir()
    (P / ".sigrift-phase").write_text(json.dumps({"phase": "done"}))
    (rb.data / "detections.db.pre-migration").write_bytes(b"x" * 10)
    ns = rb.ns
    ns["SECRETS_DIR"] = str(rb.secrets)
    f = ns["op_facts"]({"data_dir": str(rb.data), "secrets_dir": str(rb.secrets),
                        "candidates": {}})
    assert f["restore_markers"] == ["bridge_secrets"] and f["markers"]["bridge_secrets"] == {
        "id": RB} and f["markers"]["bridge_data"] is None
    assert f["lifecycle"]["replaced"][0]["phase"] == "done"
    assert f["premigration"]["bytes"] == 10
