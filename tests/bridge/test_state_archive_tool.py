"""The archive subcommands of lc_state_tool (phase2-spec 5.2) on the fake host.

The state tool runs in process (scripts/tests/lifecycle_fakes.py's
load_state_tool), the engine through the fake docker: the real bootstrap
and the real engine sources, with cryptography, on real volume
directories. One export (ar-wrap, ops-adopt, ar-write, ar-verify,
ar-publish) and one import (ar-header, ar-probe, ops-adopt, env-import,
ar-stage, state --root staging, ar-forget) from a 1b restore point, and the
refusals and key-file rules around them. PART B's flows (the move block)
build on exactly these calls.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "tests"))

from lifecycle_fakes import (  # noqa: E402
    FakeDockerHost,
    engine_bootstrap,
    load_lifecycle_tool,
    load_state_tool,
    release_install,
    seed_volume,
)

PROJECT = "sigrift-v010"
TARGET = "sigrift-v020"
IMAGE = "ghcr.io/sigrift/sigrift-bridge:v0.1.0"
JID = "20261127T101455Z"
EXP = "20261127T111500Z"
IMP = "20261127T121500Z"
PASS = b"a long archive passphrase 2026\n"
KDF = ("--mem-log2", "16", "--t", "1", "--lanes", "1", "--segment-size", "65536")
pytestmark = [pytest.mark.timeout(120), pytest.mark.xdist_group("state_archive_tool")]


class Run:
    def __init__(self, rc, result, out, err):
        self.rc, self.result, self.out, self.err = rc, result, out, err

    def __repr__(self):
        return "Run(rc=%r, err=%r, result=%r)" % (self.rc, self.err[-1500:], self.result)


class Tool:
    def __init__(self, host, tmp, monkeypatch):
        self.host = host
        self.t = load_state_tool()
        monkeypatch.setenv("PATH", f"{host.bin}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_DOCKER_STATE", str(host.state_path))
        monkeypatch.setenv("LC_ENGINE_BOOTSTRAP", engine_bootstrap())
        monkeypatch.setenv("LC_HELPER_IMAGE", IMAGE)
        for k in ("SIGRIFT_SNAPSHOT_DIR", "LC_CALLER_DIR", "LC_SELF_DIR", "LC_FACTS_JSON",
                  "LC_ENGINE_STALL_SECONDS", "COMPOSE_FILE", "LC_STATE_DIR"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("SIGRIFT_SNAPSHOT_RESERVE", "1M")
        self.res = tmp / "result.json"

    def __call__(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        if self.res.exists():
            self.res.unlink()
        fd = None
        if stdin is not None:
            r, w = os.pipe()
            os.write(w, stdin)
            os.close(w)
            fd = r
            argv = argv + ("--passphrase-fd", str(fd))
        with redirect_stdout(out), redirect_stderr(err):
            try:
                self.t.main([str(a) for a in argv] + ["--result", str(self.res)])
                rc = 0
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            finally:
                if fd is not None:
                    os.close(fd)
        result = json.loads(self.res.read_text()) if self.res.exists() else None
        return Run(rc, result, out.getvalue(), err.getvalue())

    def ok(self, *argv, stdin=None):
        r = self(*argv, stdin=stdin)
        assert r.rc == 0, r
        return r.result


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


@pytest.fixture
def tool(host, tmp_path, monkeypatch):
    hooks = sys.excepthook
    yield Tool(host, tmp_path, monkeypatch)
    sys.excepthook = hooks


@pytest.fixture
def inst(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True, running=False)
    seed_volume(host, PROJECT)
    return d


def export_point(tool, d):
    """A 1b full restore point with reason export (rp-create on the fake host)."""
    lc = load_lifecycle_tool()
    sid, _ = lc.take_snapshot(str(d), "upgrade", "v0.1.0", "v0.1.0", "dev", PROJECT, None)
    j = {"format": 1, "id": JID, "op": "export", "state": "running", "project": PROJECT,
         "steps": ["snapshot", "restore-point"], "done": ["snapshot"], "snapshot": sid}
    tool.t.journal_save(str(d), j)
    imgs = d.parent / "images.json"
    imgs.write_text(json.dumps({"bridge": {"ref": IMAGE, "id": "sha256:" + "b" * 64}}))
    r = tool.ok("rp-create", "--dir", d, "--project", PROJECT, "--image", IMAGE,
                "--journal-id", JID, "--files-snapshot", sid, "--reason", "export",
                "--from", "v0.1.0", "--to", "-", "--install-id", "00000000-0000-4000-8000-0000000000cc",
                "--images-file", imgs)
    return r["id"]


def export(tool, d, out, rp):
    w = tool.ok("ar-wrap", "--dir", d, "--image", IMAGE, "--project", PROJECT, *KDF,
                stdin=PASS)
    pending = Path(w["pending"])
    assert pending.parent == d / ".sigrift" / "ops" and pending.name.startswith(".pending-")
    assert stat.S_IMODE(pending.stat().st_mode) == 0o700
    key = pending / "archive.key"
    assert stat.S_IMODE(key.stat().st_mode) == 0o600 and key.stat().st_size == 32
    wrap = json.loads((pending / "wrap.json").read_text())
    assert set(wrap) >= {"salt", "kdf", "prefix", "wrapped", "wrap_check", "nonce_prefix",
                         "archive_id", "created_at", "crypto"}
    tool.ok("ops-adopt", "--from", pending, "--dir", d, "--jid", EXP)
    assert (d / ".sigrift" / "ops" / EXP / "archive.key").exists() and not pending.exists()
    j = tool.t.journal_load(str(d))
    j["id"] = EXP
    tool.t.journal_save(str(d), j)
    w2 = tool.ok("ar-write", "--dir", d, "--jid", EXP, "--image", IMAGE, "--rp", rp,
                 "--out", out, "--project", PROJECT, "--installer-release", "v0.2.0",
                 "--sigrift-version", "v0.1.0")
    part = Path(w2["partial"])
    assert part.parent == out.parent and part.name.startswith("." + out.name + ".")
    assert part.name.endswith(".sigrift-partial") and stat.S_IMODE(part.stat().st_mode) == 0o600
    assert tool.t.journal_load(str(d))["partial"] == str(part)
    tool.ok("ar-verify", "--dir", d, "--jid", EXP, "--image", IMAGE, "--file", part, "--rp", rp)
    tool.ok("ar-publish", "--file", out, "--dir", d, "--jid", EXP)
    assert out.exists() and not part.exists()
    assert not (d / ".sigrift" / "ops" / EXP / "archive.key").exists()
    return w2


def test_export_then_import_through_the_state_tool(tool, inst, host, tmp_path):
    rp = export_point(tool, inst)
    out = tmp_path / "usb" / "lab.sigrift-archive"
    out.parent.mkdir(mode=0o700)
    w = export(tool, inst, out, rp)
    data = out.read_bytes()
    assert hashlib.sha256(data).hexdigest() == w["archive_sha256"]
    tool.ok("ar-forget", "--dir", inst, "--jid", EXP)
    assert not (inst / ".sigrift" / "ops" / EXP).exists()
    # The passphrase is nowhere but where it went: the engine's stdin.
    blob = b""
    for p in list(inst.rglob("*")) + list(host.dir.glob("docker-log*")):
        if p.is_file():
            blob += p.read_bytes()
    assert PASS.strip() not in blob and base64.b64encode(PASS.strip()) not in blob
    for c in host.calls():
        if "ar-" in " ".join(c["argv"]):
            assert "--ulimit" in c["argv"] and "core=0" in c["argv"], c["argv"]
            assert c["argv"][c["argv"].index("--log-driver") + 1] == "none"
    # Import into a new release folder.
    d2 = tmp_path / "sigrift-v0.2.0"
    d2.mkdir()
    hc = tool.ok("ar-header", "--file", out)["header_checksum"]
    assert w["header_checksum"] == hc
    r = tool("ar-header", "--file", out, "--expect", "0" * 16)
    assert r.rc == 3 and "is archive %s, not 0000000000000000" % hc[:16] in r.err
    r = tool("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, "--expect", hc[:16],
             stdin=b"not the passphrase at all\n")
    assert r.rc == 3 and "the passphrase does not open" in r.err, r
    assert not (d2 / ".sigrift").exists()  # this run made it: removed again
    dry = tool.ok("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, "--no-key",
                  "--expect", hc[:16].upper(), stdin=PASS)
    assert not (Path(dry["pending"]) / "archive.key").exists()
    tool.ok("ar-forget", "--dir", d2, "--pending", dry["pending"])
    p = tool.ok("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, stdin=PASS)
    pending = Path(p["pending"])
    probe = json.loads((pending / "probe.json").read_text())
    assert probe["metadata"]["source"]["working_dir"] == str(inst)
    assert probe["manifest"]["id"] == rp and "data_key" not in json.dumps(probe)
    assert (pending / "archive.key").stat().st_size == 32
    tool.ok("ops-adopt", "--from", pending, "--dir", d2, "--jid", IMP)
    dry_env = tool.ok("env-import", "--dir", d2, "--jid", IMP, "--target", "release", "--dry")
    assert dry_env["switch"] is None
    host.add_project(TARGET, d2, containers=False)
    parts = json.dumps([{"name": "bridge_secrets", "action": "stage"},
                        {"name": "bridge_data", "action": "stage"}])
    s = tool.ok("ar-stage", "--dir", d2, "--jid", IMP, "--image", IMAGE, "--file", out,
                "--parts", parts, "--project", TARGET)
    assert [x["volume"] for x in s["staged"]] == ["bridge_secrets", "bridge_data"]
    ops = d2 / ".sigrift" / "ops" / IMP
    assert not (ops / "archive.key").exists() and not (ops / "host-part.bin").exists()
    payload = ops / "payload"
    assert (payload / "manifest.json").read_bytes() == (
        inst / ".sigrift" / "snapshots" / rp / "manifest.json").read_bytes()
    assert (payload / "files" / ".env").read_text() == (inst / ".env").read_text()
    for f in payload.rglob("*"):
        if f.is_file():
            assert stat.S_IMODE(f.stat().st_mode) == 0o600
    real = tool.ok("env-import", "--dir", d2, "--jid", IMP, "--target", "release",
                   "--backend", json.dumps({"SIGRIFT_BACKEND_SUBNET": "172.31.5.0/28"}))
    env_new = (ops / "env.new").read_text()
    assert "SIGRIFT_BACKEND_SUBNET=172.31.5.0/28" in env_new and "BRIDGE_MFA_KEY=" in env_new
    assert real["env_text_sha256"] == hashlib.sha256(env_new.encode()).hexdigest()
    st = tool.ok("state", "--project", TARGET, "--image", IMAGE, "--root", "staging:" + IMP,
                 "--env-file", ops / "env.new")
    assert st["schema"] == 56 and st["audit"]["result"] in ("ok", "unchecked")
    assert [n["node_id"] for n in st["nodes"]] == ["pi-1"]
    staged = host.volume(TARGET + "_bridge_data") / (".sigrift-restore-" + IMP)
    assert (staged / "keys.json").read_bytes() == (
        host.volume(PROJECT + "_bridge_data") / "keys.json").read_bytes()
    rules = tool.ok("import-rules", "--dir", d2, "--project", TARGET, "--image", IMAGE,
                    "--rb-id", IMP, "--revoke", "edge_pi1")
    assert rules["revoked"] == ["edge_pi1"] and rules["sessions"]["ended"] == 1
    keys = json.loads((staged / "keys.json").read_text())["keys"]
    assert keys["edge_pi1"]["revoked"] is True
    tool.ok("ar-forget", "--dir", d2, "--jid", IMP)
    assert not ops.exists()
    # The file swapped after the probe for one with a damaged last segment: a late
    # refusal that leaves no staging and no host part.
    p2 = tool.ok("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, stdin=PASS)
    jid2 = "20261127T131500Z"
    tool.ok("ops-adopt", "--from", p2["pending"], "--dir", d2, "--jid", jid2)
    tool.ok("discard-staging", "--dir", d2, "--project", TARGET, "--image", IMAGE,
            "--rb-id", IMP)
    other = tmp_path / "other.sigrift-archive"
    other.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    r = tool("ar-stage", "--dir", d2, "--jid", jid2, "--image", IMAGE, "--file", other,
             "--parts", parts, "--project", TARGET, "--undone", "Undone: the staging.")
    assert r.rc == 3 and "fails authentication" in r.err and "Undone: the staging." in r.err, r
    assert not list(host.volume(TARGET + "_bridge_data").glob(".sigrift-restore-*"))
    assert not (d2 / ".sigrift" / "ops" / jid2 / "host-part.bin").exists()


def test_key_file_and_state_dir_rules(tool, inst, tmp_path):
    t = tool.t
    d = tmp_path / "plain"
    d.mkdir()
    sd = t.StateDir(str(d))
    name, dfd = sd.new_pending()
    t.key_write(dfd, b"k" * 32)
    assert t.key_read(dfd) == b"k" * 32
    os.chmod(sd.ops + "/" + name + "/archive.key", 0o644)
    assert t.key_read(dfd) is None
    os.chmod(sd.ops + "/" + name + "/archive.key", 0o600)
    with open(sd.ops + "/" + name + "/archive.key", "ab") as f:
        f.write(b"x")
    assert t.key_read(dfd) is None
    os.close(dfd)
    sd.close()
    # An ops/ open to others, a symlinked ops/, a state dir of mode 0750.
    for bad in ("mode-ops", "symlink-ops", "mode-state"):
        d = tmp_path / bad
        (d / ".sigrift").mkdir(parents=True, mode=0o700)
        if bad == "mode-ops":
            (d / ".sigrift" / "ops").mkdir(mode=0o777)
            os.chmod(d / ".sigrift" / "ops", 0o777)
        elif bad == "symlink-ops":
            (tmp_path / "elsewhere").mkdir(mode=0o700, exist_ok=True)
            (d / ".sigrift" / "ops").symlink_to(tmp_path / "elsewhere")
        else:
            os.chmod(d / ".sigrift", 0o750)
        with pytest.raises(t.StateUnsafe):
            t.StateDir(str(d))
        r = tool("ar-forget", "--dir", d, "--jid", IMP)
        assert r.rc == 3 and "the archive key cannot be kept there" in r.err, r
    # ar-key-check before any step that stops the stack (exit 3).
    sd = t.StateDir(str(inst))
    os.mkdir(IMP, 0o700, dir_fd=sd.ops_fd)
    sd.close()
    r = tool("ar-key-check", "--dir", inst, "--jid", IMP)
    assert r.rc == 3 and "is damaged; nothing was decrypted with it" in r.err
    # lc-clean removes every ops/ entry no active journal names.
    t.journal_save(str(inst), {"format": 1, "id": "20261127T000000Z", "op": "import",
                               "state": "done"})
    r = tool.ok("lc-clean", "--project", PROJECT, "--dir", inst)
    assert IMP in r["removed_ops"] and list((inst / ".sigrift" / "ops").iterdir()) == []


def test_ar_write_failures_remove_the_partial(tool, inst, tmp_path, host):
    rp = export_point(tool, inst)
    out = tmp_path / "usb" / "x.sigrift-archive"
    out.parent.mkdir(mode=0o700)
    w = tool.ok("ar-wrap", "--dir", inst, "--image", IMAGE, "--project", PROJECT, *KDF,
                stdin=PASS)
    tool.ok("ops-adopt", "--from", w["pending"], "--dir", inst, "--jid", EXP)
    # A restore point that no longer matches its checksums: exit 1, no partial.
    point = inst / ".sigrift" / "snapshots" / rp
    rows = point / "rf_rows.json"
    keep = rows.read_bytes()
    rows.write_bytes(keep.replace(b"}", b" }", 1))
    r = tool("ar-write", "--dir", inst, "--jid", EXP, "--image", IMAGE, "--rp", rp, "--out", out)
    assert r.rc == 1 and "the restore point no longer matches its own checksums" in r.err, r
    assert not list(out.parent.iterdir())
    rows.write_bytes(keep)
    # A damaged archive.key: M-AR-KEY-DAMAGED inside the step (exit 1).
    key = inst / ".sigrift" / "ops" / EXP / "archive.key"
    key.write_bytes(b"")
    r = tool("ar-write", "--dir", inst, "--jid", EXP, "--image", IMAGE, "--rp", rp, "--out", out)
    assert r.rc == 1 and "archive key file of this export" in r.err, r
    assert not list(out.parent.iterdir())
    os.unlink(key)
    fd = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, os.urandom(32))
    os.close(fd)
    r = tool("ar-write", "--dir", inst, "--jid", EXP, "--image", IMAGE, "--rp", rp, "--out", out)
    assert r.rc == 1 and "archive key file of this export is damaged" in r.err, r
    assert not list(out.parent.iterdir())
    r = tool("ar-key-check", "--dir", inst, "--jid", EXP, "--export")
    assert r.rc == 3 and "nothing was encrypted with it" in r.err


def test_ar_probe_reports_length_errors_and_passphrase_rules(tool, inst, tmp_path):
    rp = export_point(tool, inst)
    out = tmp_path / "usb" / "x.sigrift-archive"
    out.parent.mkdir(mode=0o700)
    export(tool, inst, out, rp)
    d2 = tmp_path / "new"
    d2.mkdir()
    cut = tmp_path / "cut.sigrift-archive"
    cut.write_bytes(out.read_bytes()[:-100])
    r = tool("ar-probe", "--file", cut, "--image", IMAGE, "--dir", d2, "--no-key", stdin=PASS)
    assert r.rc == 3 and "bytes shorter than its header says" in r.err, r
    assert not (d2 / ".sigrift").exists()  # this run made it: removed again
    for raw, needle in ((b"", "needs a passphrase: standard input is not a terminal"),
                        (b"short\n", "must be 12 to 1024 characters"),
                        (b"\xff\xfe not utf-8 at all\n", "not valid UTF-8")):
        r = tool("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, "--no-key",
                 stdin=raw)
        assert r.rc == 3 and needle in r.err, (raw, r)
    # A passphrase file that others can read is refused.
    pf = tmp_path / "pass.txt"
    pf.write_bytes(PASS)
    pf.chmod(0o644)
    fd = os.open(pf, os.O_RDONLY)
    try:
        r = tool("ar-wrap", "--dir", inst, "--image", IMAGE, "--passphrase-fd", str(fd), *KDF)
    finally:
        os.close(fd)
    assert r.rc == 3 and "readable or writable by group or others (mode 0644)" in r.err, r
    # A weak passphrase at export.
    r = tool("ar-wrap", "--dir", inst, "--image", IMAGE, *KDF, stdin=b"qwertyuiop[]\n")
    assert r.rc == 3 and "too easy to guess" in r.err
    r = tool("ar-header", "--file", tmp_path / "pass.txt")
    assert r.rc == 3 and "is not a SigRift archive" in r.err


def probe_json(d, jid, meta):
    sd = d / ".sigrift" / "ops" / jid
    sd.mkdir(parents=True, mode=0o700)
    os.chmod(d / ".sigrift", 0o700)
    os.chmod(d / ".sigrift" / "ops", 0o700)
    (sd / "probe.json").write_text(json.dumps({"metadata": meta, "header_checksum": "ab" * 32,
                                               "manifest": {}}))
    return sd / "probe.json"


def test_import_plan_refusals_and_moved_away_projects(tool, host, tmp_path):
    d = tmp_path / "new"
    d.mkdir()
    meta = {"archive_id": "00000000-0000-4000-8000-0000000000a1", "install_id": "iid-7",
            "created_at": "2026-12-02T10:15:31Z", "install_type": "release", "moved": True,
            "source": {"hostname": "pi5", "port": 47123, "host_keys": {}}}
    probe_json(d, IMP, meta)
    host.add_project("oldproj", tmp_path / "old", running=True)
    host.update(records={"oldproj_bridge_data": {"install_id": "iid-7",
                                                 "working_dir": str(tmp_path / "old")}})
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert r.rc == 3 and "runs on this host in" in r.err, r
    host.load()
    for c in host.state["containers"]:
        c["state"] = "exited"
    host.save()
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert r.rc == 3 and "was not moved into this archive" in r.err, r
    (host.volume("oldproj_bridge_data") / ".sigrift-restore-incomplete").write_text(json.dumps(
        {"format": 1, "op": "move", "id": meta["archive_id"]}))
    res = tool.ok("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert res["moved_away"][0]["project"] == "oldproj"
    assert res["moved_away"][0]["rm"].startswith("docker volume rm oldproj_bridge_data")
    host.add_project(TARGET, d, containers=False)
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert r.rc == 3 and "--project %s-2" % TARGET in r.err
    host.update(records={"oldproj_bridge_data": {"install_id": "iid-7", "imported_from": {
        "archive_id": meta["archive_id"], "at": "x"}}})
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", "other")
    assert r.rc == 3 and "was already imported here" in r.err


def test_live_source_probe_refuses_the_same_certificate(tool, tmp_path):
    import datetime
    import socket
    import ssl
    import threading

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "live-test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "k.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]

    def serve():
        for _ in range(2):
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(c, server_side=True) as t:
                    t.recv(1)
            except (OSError, ssl.SSLError):
                pass
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    der = cert.public_bytes(serialization.Encoding.DER)
    probe = tmp_path / "probe.json"
    meta = {"source": {"addresses": ["127.0.0.1"], "tls_names": [], "port": port,
                       "tls_cert_sha256": hashlib.sha256(der).hexdigest()}}
    probe.write_text(json.dumps({"metadata": meta}))
    r = tool("live-source-probe", "--probe", probe)
    assert r.rc == 3 and "still answers at 127.0.0.1:%d with the same certificate" % port in r.err
    assert r.result["answered"] == [{"target": "127.0.0.1", "port": port, "same_cert": True}]
    meta["source"]["tls_cert_sha256"] = "00" * 32
    probe.write_text(json.dumps({"metadata": meta}))
    res = tool.ok("live-source-probe", "--probe", probe)
    assert res["answered"][0]["same_cert"] is False
    srv.close()
    th.join(5)
    res = tool.ok("live-source-probe", "--probe", probe)
    assert res["unreachable"] == ["127.0.0.1"]


def test_ar_stage_failures_leave_no_decrypted_host_part(tool, inst, host, tmp_path, monkeypatch):
    """Fix round (5.2, Appendix C D): every failure of ar-stage but a
    finished split removes host-part.bin and payload/ (an injected ENOSPC in
    the split, an fsync error); a damaged key or a wrong DK (E integrity) is
    a late refusal (exit 3, the --undone text) for the caller's undo; after
    the split, staged.json records the stage, so a resume needs no key; a
    pass file in the archive's folder gets 2.4's NOTE."""
    import errno
    rp = export_point(tool, inst)
    out = tmp_path / "usb" / "lab.sigrift-archive"
    out.parent.mkdir(mode=0o700)
    export(tool, inst, out, rp)
    d2 = tmp_path / "sigrift-v0.2.0"
    d2.mkdir()
    pf = out.parent / "pass.txt"
    pf.write_bytes(PASS)
    pf.chmod(0o600)
    fd = os.open(pf, os.O_RDONLY)
    try:
        p = tool("ar-probe", "--file", out, "--image", IMAGE, "--dir", d2, "--passphrase-fd",
                 str(fd))
    finally:
        os.close(fd)
    assert p.rc == 0 and "NOTE: the passphrase file is in the same directory as the archive" \
        in p.err, p
    tool.ok("ops-adopt", "--from", p.result["pending"], "--dir", d2, "--jid", IMP)
    host.add_project(TARGET, d2, containers=False)
    parts = json.dumps([{"name": "bridge_secrets", "action": "stage"},
                        {"name": "bridge_data", "action": "stage"}])
    ops = d2 / ".sigrift" / "ops" / IMP

    def stage():
        return tool("ar-stage", "--dir", d2, "--jid", IMP, "--image", IMAGE, "--file", out,
                    "--parts", parts, "--project", TARGET, "--undone", "Undone: the staging.")

    def no_secrets():
        assert not (ops / "host-part.bin").exists() and not (ops / "payload").exists()

    real_write = tool.t.write_all
    calls = {"n": 0}

    def enospc(fd_, data):
        calls["n"] += 1
        raise OSError(errno.ENOSPC, "No space left on device")
    monkeypatch.setattr(tool.t, "write_all", enospc)
    with pytest.raises(OSError):
        stage()
    assert calls["n"] == 1
    no_secrets()
    assert (ops / "archive.key").exists()  # resumable: the key stays
    monkeypatch.setattr(tool.t, "write_all", real_write)
    real_fsync = os.fsync
    seen = {"n": 0}

    def bad_fsync(fd_):
        # The fsync of host-part.bin after the engine's reply fails.
        hp = ops / "host-part.bin"
        if hp.exists() and os.fstat(fd_).st_ino == hp.stat().st_ino:
            seen["n"] += 1
            raise OSError(errno.EIO, "I/O error")
        return real_fsync(fd_)
    monkeypatch.setattr(os, "fsync", bad_fsync)
    with pytest.raises(OSError):
        stage()
    monkeypatch.setattr(os, "fsync", real_fsync)
    assert seen["n"] == 1
    no_secrets()
    # A wrong DK of the right shape: E integrity, a late refusal (exit 3).
    key = ops / "archive.key"
    good = key.read_bytes()
    key.write_bytes(bytes(32))
    r = stage()
    assert r.rc == 3 and "is damaged; nothing was decrypted with it" in r.err, r
    assert "Undone: the staging." in r.err and r.err.rstrip().endswith("Nothing was changed.")
    no_secrets()
    key.unlink()
    r = stage()
    assert r.rc == 3 and "Undone: the staging." in r.err and r.result["code"] == "key-damaged", r
    fd2 = os.open(key, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd2, good)
    os.close(fd2)
    s = stage()
    assert s.rc == 0, s
    staged = json.loads((ops / "staged.json").read_text())
    assert staged["staged"] == s.result["staged"] and not key.exists()
    assert not (ops / "host-part.bin").exists() and (ops / "payload" / "manifest.json").exists()
    # ar-wrap's NOTE for a pass file beside the archive (--archive-dir).
    fd = os.open(pf, os.O_RDONLY)
    try:
        w = tool("ar-wrap", "--dir", inst, "--image", IMAGE, "--project", PROJECT, *KDF,
                 "--passphrase-fd", str(fd), "--archive-dir", out.parent)
    finally:
        os.close(fd)
    assert w.rc == 0 and "is in the same directory as the archive" in w.err, w
    tool.ok("ar-forget", "--dir", inst, "--pending", w.result["pending"])


def test_import_plan_running_moved_project_docker_errors_and_plan_lines(tool, host, tmp_path):
    """Fix round: a running project of the same install is the same install
    running whatever its markers (6.2, 6.4); a Docker error is a failure,
    never "nothing runs"; 11.4's files/TLS/edges/--replace lines, with a
    sealed hostname's control characters escaped."""
    d = tmp_path / "new"
    d.mkdir()
    meta = {"archive_id": "00000000-0000-4000-8000-0000000000a2", "install_id": "iid-8",
            "created_at": "2026-12-02T10:15:31Z", "install_type": "release", "moved": True,
            "source": {"hostname": "pi\x1b]0;x\x075", "port": 47124, "host_keys": {},
                       "tls_names": ["pi5.lan"]}}
    sd = probe_json(d, IMP, meta)
    probe = json.loads(sd.read_text())
    probe["manifest"] = {"files": [{"path": ".env"}, {"path": "docker-compose.override.yml"}],
                         "nodes": [{"node_id": "pi-2", "summary": True},
                                   {"node_id": "pi-1", "summary": False}]}
    sd.write_text(json.dumps(probe))
    host.add_project("oldproj", tmp_path / "old", running=True)
    host.update(records={"oldproj_bridge_data": {"install_id": "iid-8",
                                                 "working_dir": str(tmp_path / "old")}})
    (host.volume("oldproj_bridge_data") / ".sigrift-restore-incomplete").write_text(json.dumps(
        {"format": 1, "op": "move", "id": meta["archive_id"]}))
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert r.rc == 3 and "runs on this host in" in r.err, r
    host.update(fail_at={r"^ps --filter label=com\.docker\.compose\.project --format": 1})
    r = tool("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET)
    assert r.rc == 1 and "could not list the running containers" in r.err, r
    host.update(fail_at={})
    host.load()
    for c in host.state["containers"]:
        c["state"] = "exited"
    host.save()
    res = tool.ok("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET, "--replace")
    later = res["later_lines"]
    assert later["files"] == ("files     docker-compose.override.yml -> "
                              "docker-compose.override.yml.imported (inactive)")
    assert later["tls"].startswith("TLS       kept; this host's names ")
    assert later["edges"] == "edges     summary mode: pi-2 (keep their URL); other: pi-1"
    # F-D21: the --replace lines (relation, DISCARDS, KEEPS) come from
    # import-relate and compare --import-jid (lc_tool im-plan), not from here.
    assert "replace" not in later
    assert "pi\\x1b]0;x\\x075" in res["lines"][0] and "\x1b" not in json.dumps(res)
    res = tool.ok("import-plan", "--dir", d, "--jid", IMP, "--project", TARGET,
                  "--regenerate-tls")
    assert res["later_lines"]["tls"] == "TLS       regenerated for this host (--regenerate-tls)"
    assert "replace" not in res["later_lines"]


def test_reactivate_and_verify_helpers(tool, host, tmp_path, monkeypatch):
    """Fix round: same-install-running (--reactivate, 7.4), tls-served
    (im-verify's served certificate), volume-lifecycle-only (an import's
    --abort removes only a volume of lifecycle entries)."""
    host.add_project("lab", tmp_path / "lab", running=True)
    host.update(records={"lab_bridge_data": {"install_id": "iid-9",
                                             "working_dir": str(tmp_path / "lab")}})
    r = tool.ok("same-install-running", "--install-id", "iid-9", "--project", "old")
    assert r["running"] == [{"project": "lab", "working_dir": str(tmp_path / "lab")}]
    assert tool.ok("same-install-running", "--install-id", "iid-9", "--project", "lab")[
        "running"] == []
    assert tool.ok("same-install-running", "--install-id", "other", "--project", "x")[
        "running"] == []
    monkeypatch.setattr(tool.t, "TLS_PEER", lambda h, p: "ab" * 32)
    assert tool.ok("tls-served", "--port", "8444", "--sha256", "AB" * 32) == {
        "ok": True, "answered": True, "same": True}
    assert tool.ok("tls-served", "--port", "8444", "--sha256", "cd" * 32)["same"] is False
    monkeypatch.setattr(tool.t, "TLS_PEER", lambda h, p: None)
    assert tool.ok("tls-served", "--port", "8444", "--sha256", "ab" * 32)["answered"] is False
    vol = host.volume("lab_bridge_data")
    for p in list(vol.iterdir()):
        if p.is_dir():
            import shutil
            shutil.rmtree(p)
        else:
            p.unlink()
    (vol / ".sigrift-restore-x").mkdir()
    (vol / ".sigrift-install.json").write_text("{}")
    assert tool.ok("volume-lifecycle-only", "--volume", "lab_bridge_data")["only_lifecycle"] is True
    (vol / "detections.db").write_bytes(b"x")
    r = tool.ok("volume-lifecycle-only", "--volume", "lab_bridge_data")
    assert r["only_lifecycle"] is False and r["other"] == 1


def test_import_relate_decides_which_copy_is_newer_from_the_audit_heads(tool, tmp_path):
    """phase2-notes F-D21, the decision table of import-relate: same,
    live-newer, archive-newer (only once the staged copy holds the current
    head entry), diverged and unknown (no chain value, no entry, an
    unreadable log); diverged and unknown refuse with the opt-out as the one
    Next line unless --no-carry (or --report, a dry run); a relation the plan
    did not allow refuses too."""
    d = tmp_path / "inst"
    d.mkdir()
    sd = probe_json(d, IMP, {"install_id": "iid-1"})
    probe = json.loads(sd.read_text())
    probe["manifest"] = {"audit": {"head_id": 5, "head_tag": "a5"}}
    sd.write_text(json.dumps(probe))

    def side(name, head_id, head_tag, at=None, chain="ok", facts=True):
        c = {"chain": chain, "head_id": head_id, "head_tag": head_tag, "at": at or {}}
        p = tmp_path / ("%s.json" % name)
        p.write_text(json.dumps({"ok": True, "audit_chain": c} if facts else {"audit": c}))
        return p

    def relate(live, *extra):
        return tool("import-relate", "--dir", d, "--jid", IMP, "--live", live, "--project", PROJECT,
                    "--cmd", "bash install-release.sh --import f --replace", *extra)
    cases = [
        (side("same", 5, "a5", {"5": "a5"}), (), "same", False),
        (side("newer", 7, "l7", {"5": "a5"}), (), "live-newer", True),
        (side("older", 3, "l3", {"5": None}), (), "archive-newer?", False),
        (side("older", 3, "l3", {"5": None}),
         ("--staged", side("staged", 5, "a5", {"3": "l3"}, facts=False)), "archive-newer", False),
    ]
    for live, extra, want, carry in cases:
        r = relate(live, *extra)
        assert r.rc == 0 and r.result["relation"] == want and r.result["carry"] is carry, (want, r)
    refused = [
        (side("fork", 5, "b5", {"5": "b5"}), (), "diverged", "audit entry 5 differs"),
        (side("fork2", 7, "l7", {"5": "b5"}), (), "diverged", "audit entry 5 differs"),
        (side("older", 3, "l3", {"5": None}),
         ("--staged", side("staged2", 5, "a5", {"3": "x3"}, facts=False)), "diverged",
         "audit entry 3 differs"),
        (side("gap", 7, "l7", {"5": None}), (), "unknown", "has no entry 5 (the archive's head)"),
        (side("legacy", 5, "", {"5": ""}), (), "unknown", "the current audit head 5 has no chain value"),
        (side("bad", None, None, chain="unreadable"), (), "unknown", "cannot be read"),
        (side("none", None, None, chain="empty"), (), "unknown", "the current audit log is empty"),
    ]
    for live, extra, want, needle in refused:
        r = relate(live, *extra)
        assert r.rc == 3 and r.result["relation"] == want and needle in r.err, (want, r)
        assert [x for x in r.err.splitlines() if x.startswith("Next: ")] == [
            "Next: bash install-release.sh --import f --replace --no-carry-revocations"], r
        for opt in ("--no-carry", "--report"):
            r2 = relate(live, *(extra + (opt,)))
            assert r2.rc == 0 and r2.result["relation"] == want and r2.result["carry"] is False, r2
    # A relation the plan did not allow (later runs may only find more data).
    r = relate(side("newer", 7, "l7", {"5": "a5"}), "--planned", "same")
    assert r.rc == 0 and r.result["relation"] == "live-newer"
    r = relate(side("same", 5, "a5", {"5": "a5"}), "--planned", "live-newer")
    assert r.rc == 3 and "changed after the import was planned (it was live-newer" in r.err, r
    # F-D22: the last common entry (compare --common-head dates what changes
    # without an audit entry against it).
    commons = [(side("same", 5, "a5", {"5": "a5"}), (), 5),
               (side("newer", 7, "l7", {"5": "a5"}), (), 5),
               (side("older", 3, "l3", {"5": None}), (), 3),
               (side("fork", 5, "b5", {"5": "b5"}), ("--report",), None)]
    for live, extra, want in commons:
        assert relate(live, *extra).result["common_head"] == want
    # F-D22: with the staged copy read, its head must be the archive's head
    # entry whatever the relation (same and live-newer too): else unknown.
    for live in (side("same", 5, "a5", {"5": "a5"}), side("newer", 7, "l7", {"5": "a5"})):
        for staged in (side("forged", 5, "x5", {}, facts=False),
                       side("short", 4, "a4", {}, facts=False)):
            r = relate(live, "--staged", staged)
            assert r.rc == 3 and r.result["relation"] == "unknown", r
            assert "the staged copy's audit head is not the archive's" in r.err, r
        r = relate(live, "--staged", side("good", 5, "a5", {}, facts=False))
        assert r.rc == 0 and r.result["relation"] in ("same", "live-newer"), r
    # The archive's own head must have a chain value.
    probe["manifest"] = {"audit": {"head_id": 5}}
    sd.write_text(json.dumps(probe))
    r = relate(side("same", 5, "a5", {"5": "a5"}))
    assert r.rc == 3 and "the archive's audit head 5 has no chain value" in r.err, r
