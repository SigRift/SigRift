"""Make the golden archives of format v1 (phase2-spec 3.9). Run by hand, never by CI:

    PYTHONPATH=src python3 tests/bridge/fixtures/state_archive/make_v1.py

It writes v1-golden.sigrift-archive (Argon2id 2^16 KiB, 1 pass, 1 lane;
segments of 64 KiB, n = 3) and v1-golden-max.sigrift-archive (Argon2id
2^18 KiB, 4 passes, 4 lanes; one 4 MiB segment) from fixed inputs: the
passphrase, salt, data key, nonce prefix and write_salt below go through
the engine's URANDOM indirection, every metadata field is a literal here
(nothing is read from this host), and the restore point is synthetic
(a manifest, rf_rows.json with one stream, files/.env with dummy values,
placeholder bytes for tls/cert.pem, tls/key.pem and ca/ca.key, and a
bridge_data with detections.db of 3 rows, keys.json, audit.key and some
padding). The engine ops ar-wrap and ar-write run in process, as
tests/bridge/test_state_archive.py runs them. Every later release must
read these files (14.1 #10); a writer that writes other bytes for the
same inputs fails 14.1 #11. Its printout is what test_state_archive.py
pins.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
TEXT = (ROOT / "scripts" / "install-release.sh").read_text()

PASSPHRASE = b"correct horse battery staple"
SALT = bytes(range(16))
DATA_KEY = bytes(range(32))
NONCE_PREFIX = bytes(range(0xA0, 0xA7))
WRITE_SALT = bytes(range(32, 48))
ARCHIVE_ID = "00000000-0000-4000-8000-000000000001"
CREATED_AT = "2026-12-01T00:00:00Z"
CRYPTO = {"cryptography": "50.0.2", "openssl": "OpenSSL 3.5.7 golden"}
PLACEHOLDER = b"placeholder-not-a-key\n"
MTIME_NS = 1764547200 * 10 ** 9
RP_ID = "20261201T000000Z-v0.2.0-full"
METADATA = {
    "tool": "install-release.sh", "installer_release": "v0.2.0", "sigrift_version": "v0.2.0",
    "bridge_release": "v0.2.0", "install_type": "release",
    "install_id": "00000000-0000-4000-8000-0000000000aa", "project": "sigrift-v020",
    "moved": True,
    "source": {"hostname": "golden-host", "arch": "arm64",
               "host_id": "0123456789abcdef0123456789abcdef",
               "working_dir": "/home/pi/sigrift-v0.2.0", "addresses": ["192.0.2.40"],
               "port": 8444, "bind": "0.0.0.0", "tls_names": ["golden-host", "192.0.2.40"],
               "tls_cert_sha256": "00" * 32,
               "host_keys": {"SIGRIFT_BIND": "0.0.0.0",
                             "SIGRIFT_BACKEND_SUBNET": "172.30.0.0/24"}},
    "schema_version": 56, "db_encrypted": False,
    "audit": {"source": "env-key", "result": "ok", "head_id": 3},
    "env": {"keys": {"BRIDGE_AUDIT_KEY": "set", "BRIDGE_ENV": "set", "BRIDGE_MASTER_KEY": "set",
                     "BRIDGE_MFA_KEY": "set", "SIGRIFT_BACKEND_SUBNET": "set",
                     "SIGRIFT_BIND": "set", "UC_PROXY_SECRET": "set"},
            "parse": "ok", "audit_value": "n/a"},
    "counts": {"users": 1, "keys": 2, "nodes": 1, "webhooks": 0, "crypto_keys": 0,
               "detections": 3, "totp_fernet": 0},
    "summary_nodes": ["golden-edge"], "in_stack_node": None,
    "parts": [{"name": "bridge_secrets", "bytes_raw": 22}, {"name": "bridge_data",
                                                            "bytes_raw": 160038}],
    "captures": "included", "kept_out": {"backups_bytes": 0, "exports_bytes": 0},
}
ENV_TEXT = ("BRIDGE_ENV=production\nBRIDGE_MFA_KEY=dummy-mfa-value\n"
            "BRIDGE_AUDIT_KEY=dummy-audit-value\nBRIDGE_MASTER_KEY=dummy-master-value\n"
            "UC_PROXY_SECRET=dummy-proxy-value\nSIGRIFT_BIND=0.0.0.0\n"
            "SIGRIFT_BACKEND_SUBNET=172.30.0.0/24\n")
PARAMS = {"v1-golden.sigrift-archive": (16, 1, 1, 65536),
          "v1-golden-max.sigrift-archive": (18, 4, 4, 4194304)}


def block(name):
    return re.search(r"(?ms)^# >>> shared: %s .*?^# <<< shared: %s\n" % (name, name),
                     TEXT).group(0)


def engine_source():
    return "".join(re.search(r"cat <<'PY'\n(.*?)\nPY\n", block(n), re.S).group(1) + "\n"
                   for n in ("state-engine", "archive-engine", "lifecycle-engine"))


def load():
    ns = {"__name__": "sigrift_engine_make_v1", "REQUEST": {}}
    exec(compile(engine_source(), "<sigrift-engine>", "exec"), ns)
    return ns


def frames(b):
    out, i = [], 0
    while i < len(b):
        kind, n = b[i:i + 1], struct.unpack(">Q", b[i + 1:i + 9])[0]
        out.append((kind, b[i + 9:i + 9 + n]))
        i += 9 + n
    return out


def section(data):
    step = 1 << 20
    return b"".join(b"%d\n" % len(data[i:i + step]) + data[i:i + step]
                    for i in range(0, len(data), step)) + b"0\n"


def run(ns, op, req, stdin=b"", urandom=(), roots=None):
    queue = list(urandom)

    def fixed(n):
        b = queue.pop(0)
        assert len(b) == n
        return b
    ns["URANDOM"] = fixed
    out = io.BytesIO()
    ns["ST_IO"]["out"] = out
    ns["ST_IO"]["in"] = io.BufferedReader(io.BytesIO(stdin))
    full = {"format": 1, "op": op, "framed": True,
            "data_dir": str((roots or {}).get("data", "/nonexistent")),
            "secrets_dir": str((roots or {}).get("secrets", "/nonexistent"))}
    full.update(req)
    hooks = sys.excepthook
    try:
        try:
            ns["run"](full)
        except SystemExit:
            pass
    finally:
        sys.excepthook = hooks
    fr = frames(out.getvalue())
    kind, payload = fr[-1]
    obj = json.loads(payload)
    assert kind == b"R", obj
    return obj, b"".join(p for k, p in fr if k == b"D"), b"".join(p for k, p in fr if k == b"M")


def pad_bytes(n):
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(b"sigrift-golden-pad:%d" % i).digest()
        i += 1
    return out[:n]


def touch(root):
    for dirpath, dirs, names in os.walk(root, topdown=False):
        for n in names + dirs:
            os.utime(os.path.join(dirpath, n), ns=(MTIME_NS, MTIME_NS), follow_symlinks=False)
    os.utime(root, ns=(MTIME_NS, MTIME_NS))


def synthetic_point(ns, tmp):
    """{member name: bytes} of the synthetic restore point, in 3.6 order."""
    data, secrets = tmp / "data", tmp / "secrets"
    (secrets / "ca").mkdir(parents=True)
    (secrets / "ca" / "ca.key").write_bytes(PLACEHOLDER)
    (data / "iq_captures").mkdir(parents=True)
    conn = sqlite3.connect(data / "detections.db")
    conn.executescript(
        "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, description TEXT, "
        "applied_at TEXT);\nINSERT INTO schema_version VALUES (56, 'golden', "
        "'2026-12-01T00:00:00Z');\nCREATE TABLE detections (detection_id TEXT PRIMARY KEY, "
        "timestamp TEXT NOT NULL, node_id TEXT);\n"
        "INSERT INTO detections VALUES ('d1', '2026-12-01T00:00:01Z', 'golden-edge');\n"
        "INSERT INTO detections VALUES ('d2', '2026-12-01T00:00:02Z', 'golden-edge');\n"
        "INSERT INTO detections VALUES ('d3', '2026-12-01T00:00:03Z', 'golden-edge');\n")
    conn.commit()
    conn.close()
    (data / "keys.json").write_text(json.dumps({"keys": {
        "master": {"hash": "golden-hash-1", "salt": "golden-salt-1", "role": "admin"},
        "golden-edge": {"hash": "golden-hash-2", "salt": "golden-salt-2", "role": "sensor",
                        "node_id": "golden-edge"}}}, indent=2, sort_keys=True) + "\n")
    (data / "audit.key").write_bytes(b"dummy-audit-file-value\n")
    (data / "iq_captures" / "pad.iq.gz").write_bytes(pad_bytes(140 * 1024))
    for p in list(data.rglob("*")) + list(secrets.rglob("*")):
        p.chmod(0o700 if p.is_dir() else 0o600)
    touch(data)
    touch(secrets)
    roots = {"data": data, "secrets": secrets}
    vols, payload = [], {}
    for vol in ("bridge_secrets", "bridge_data"):
        r, arch, mem = run(ns, "snapshot-volume", {"volume": vol, "excludes": []}, roots=roots)
        vols.append({"name": vol, "docker_volume": "sigrift-v020_" + vol,
                     "archive": "volumes/%s.tar.gz" % vol, "archive_sha256": r["archive_sha256"],
                     "archive_bytes": r["archive_bytes"], "bytes_raw": r["bytes_raw"],
                     "members": r["members"], "members_file_sha256": r["members_sha256"],
                     "excludes": [], "keep_back": ["backups", "exports"] if vol == "bridge_data"
                     else []})
        payload["volumes/%s.members.json" % vol] = mem
        payload["volumes/%s.tar.gz" % vol] = arch
    rows = (json.dumps({"format": 1, "tables": True, "streams": ["0" * 32], "fences": [],
                        "summary_hours": {}}, sort_keys=True) + "\n").encode()
    files = [(".env", ENV_TEXT.encode()), ("tls/cert.pem", b"placeholder-not-a-cert\n"),
             ("tls/key.pem", PLACEHOLDER)]
    manifest = {"format": 1, "kind": "full", "id": RP_ID, "reason": "export",
                "created_at": CREATED_AT, "from_version": "v0.2.0", "to_version": None,
                "install_id": METADATA["install_id"], "project": METADATA["project"],
                "installer_release": "v0.2.0", "schema_version": 56,
                "db": {"present": True, "encrypted": False, "bytes": 0},
                "audit": {"source": "env-key", "result": "ok", "entries": 3, "head_id": 3},
                "counts": {"users": 1, "keys": 2, "nodes": 1, "detections": 3,
                           "crypto_keys": 0, "totp_fernet": 0, "sessions": 0},
                "rf_summary": {"tables": True, "rows_file_sha256":
                               hashlib.sha256(rows).hexdigest()},
                "captures": {"mode": "included", "excluded": []},
                "files": [{"path": p, "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b),
                           "mode": "0600", "via_helper": p == "tls/key.pem",
                           "restore_on_rollback": p == ".env"} for p, b in files],
                "volumes": vols, "nodes": [{"node_id": "golden-edge", "last_seen": None,
                                            "summary": True}],
                "kept_out": {"backups_bytes": 0, "exports_bytes": 0}}
    out = {"manifest.json": (json.dumps(manifest, indent=1, sort_keys=True) + "\n").encode(),
           "rf_rows.json": rows}
    for p, b in files:
        out["files/" + p] = b
    for vol in ("bridge_secrets", "bridge_data"):
        for kind in ("members.json", "tar.gz"):
            out["volumes/%s.%s" % (vol, kind)] = payload["volumes/%s.%s" % (vol, kind)]
    return out


def write_archive(ns, members, mem_log2, t, lanes, seg):
    """The archive bytes for MEMBERS ({name: bytes}, in order)."""
    wrap, _, _ = run(ns, "ar-wrap", {
        "passphrase_b64": base64.b64encode(PASSPHRASE).decode(),
        "data_key": base64.b64encode(DATA_KEY).decode(),
        "kdf": {"mem_log2": mem_log2, "t": t, "lanes": lanes}, "segment_size": seg},
        urandom=[SALT, NONCE_PREFIX])
    meta = dict(METADATA)
    lst = [{"n": n, "s": len(b), "h": hashlib.sha256(b).hexdigest()} for n, b in members.items()]
    req = {"data_key": base64.b64encode(DATA_KEY).decode(), "metadata": meta, "members": lst,
           "wrap": {"prefix": wrap["prefix"], "wrapped": wrap["wrapped"],
                    "wrap_check": wrap["wrap_check"], "archive_id": ARCHIVE_ID,
                    "created_at": CREATED_AT, "crypto": CRYPTO}}
    r, data, _ = run(ns, "ar-write", req, stdin=b"".join(section(b) for b in members.values()),
                     urandom=[WRITE_SALT])
    assert len(data) == r["archive_bytes"]
    return data, wrap, r


def main():
    ns = load()
    with tempfile.TemporaryDirectory() as tmp:
        members = synthetic_point(ns, Path(tmp))
    for name, (mem_log2, t, lanes, seg) in PARAMS.items():
        data, wrap, r = write_archive(ns, members, mem_log2, t, lanes, seg)
        (HERE / name).write_bytes(data)
        print(name)
        print("  sha256          ", hashlib.sha256(data).hexdigest())
        print("  bytes, segments ", len(data), r["segments"])
        print("  header checksum ", r["header_checksum"])
        print("  prefix          ", base64.b64decode(wrap["prefix"]).hex())
        print("  wrapped         ", base64.b64decode(wrap["wrapped"]).hex())
        print("  wrap_check      ", wrap["wrap_check"])
    m = json.loads(members["manifest.json"])
    print("  parts           ", [(v["name"], v["bytes_raw"]) for v in m["volumes"]])
    for n in ("manifest.json", "rf_rows.json", "volumes/bridge_data.tar.gz"):
        print("  member %-26s %s" % (n, hashlib.sha256(members[n]).hexdigest()))


if __name__ == "__main__":
    main()
