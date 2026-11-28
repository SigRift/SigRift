"""Phase 2 PART A's hooks in the 1b engine and state tool (phase2-spec 1.2, 4.3).

st_stage_volume and the pki part's owners, state --root staging and its
nodes, compare and rf-check --exempt-nodes, the move and import markers,
rp-create --volumes, rp-resolve's pre-import rule, retention of export and
pre-import points, the export and import space plans, the edge_data and pki
mounts, and release_render_compose --port --owner --version. Standard
library only; the engine runs in process, the tool against the fake host.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import struct
import subprocess
from bash_file import script_argv  # noqa: E402
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from lifecycle_fakes import (
    BASH,
    INSTALL_RELEASE,
    FakeDockerHost,
    engine_bootstrap,
    load_engine,
    load_state_tool,
    release_install,
    seed_tree,
    seed_volume,
    shared_block,
)

RB = "20261201T000200Z"
PROJECT = "sigrift-v010"
IMAGE = "ghcr.io/sigrift/sigrift-bridge:v0.1.0"
AID = "00000000-0000-4000-8000-000000000009"
pytestmark = pytest.mark.timeout(120)


def frames(b):
    out, i = [], 0
    while i < len(b):
        n = struct.unpack(">Q", b[i + 1:i + 9])[0]
        out.append((b[i:i + 1], b[i + 9:i + 9 + n]))
        i += 9 + n
    return out


def section(data):
    return (b"%d\n" % len(data) + data if data else b"") + b"0\n"


@pytest.fixture(scope="module")
def ns():
    return load_engine()


class V:
    def __init__(self, ns, tmp):
        self.ns, self.tmp = ns, tmp
        self.data, self.secrets, self.edge = tmp / "d", tmp / "s", tmp / "e"
        for p in (self.data, self.secrets, self.edge):
            p.mkdir()

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
        fr = frames(out.getvalue())
        return rc, json.loads(fr[-1][1]), fr


@pytest.fixture
def v(ns, tmp_path):
    return V(ns, tmp_path)


def test_state_root_staging_reads_the_staging_and_lists_nodes(v):
    seed_tree(v.data, v.secrets)
    S = v.data / (".sigrift-restore-" + RB)
    seed_tree(S, v.secrets / (".sigrift-restore-" + RB))
    conn = sqlite3.connect(S / "detections.db")
    conn.execute("INSERT INTO nodes VALUES ('pi-edge-2', NULL, 'default')")
    conn.execute("INSERT INTO rf_summary_streams VALUES ('default', 'pi-edge-2', 's1')")
    conn.commit()
    conn.close()
    rc, live, _ = v.call("state", env={})
    rc2, staged, _ = v.call("state", env={}, root="staging:" + RB)
    assert rc == rc2 == 0
    assert [n["node_id"] for n in live["nodes"]] == ["pi-1"]
    assert staged["nodes"] == [{"node_id": "pi-1", "last_seen": "2026-11-27T10:00:00Z",
                                "summary": False},
                               {"node_id": "pi-edge-2", "last_seen": None, "summary": True}]
    rc, r, _ = v.call("state", env={}, root="staging:../../etc")
    assert rc == 1 and r["code"] == "unsafe"
    rc, r, _ = v.call("state", env={}, root="staging:20261201T000300Z")
    assert rc == 1 and r["code"] == "phase"


def test_exempt_nodes_leave_the_in_stack_node_out_of_the_rf_digest(v):
    seed_tree(v.data, v.secrets)
    conn = sqlite3.connect(v.data / "detections.db")
    conn.execute("INSERT INTO rf_summary_streams VALUES ('default', 'local-edge', 's1')")
    conn.execute("INSERT INTO rf_summary_streams VALUES ('default', 'pi-2', 's2')")
    conn.commit()
    conn.close()
    _, a, _ = v.call("state", env={}, exempt_nodes=["local-edge"])
    _, b, _ = v.call("state", env={})
    assert a["rf"]["digest"] != b["rf"]["digest"] and a["rf"]["exempt_nodes"] == ["local-edge"]
    conn = sqlite3.connect(v.data / "detections.db")
    conn.execute("UPDATE rf_summary_streams SET stream_id = 's9' WHERE node_id = 'local-edge'")
    conn.commit()
    conn.close()
    _, a2, _ = v.call("state", env={}, exempt_nodes=["local-edge"])
    assert a2["rf"]["digest"] == a["rf"]["digest"]
    rows = json.dumps({"streams": [], "fences": [], "summary_hours": {}}).encode()
    rp = {"rf_summary": a["rf"], "marks": a["marks"], "security": a["security"],
          "counts": a["counts"], "captures": a["captures"], "audit": {}}
    _, cmp_, _ = v.call("compare", section(rows), rp=rp, rf_rows_section=True,
                        exempt_nodes=["local-edge"])
    assert cmp_["discards"]["rf"] == "same"
    _, cmp_, _ = v.call("compare", section(rows), rp=rp, rf_rows_section=True)
    assert cmp_["discards"]["rf"] == "cannot"


def test_move_and_import_markers_with_edge_data(v):
    rc, r, _ = v.call("mark", marker_op="move", marker_id=AID, edge_dir=str(v.edge))
    assert rc == 0 and r["written"] == ["bridge_secrets", "edge_data", "bridge_data"]
    m = json.loads((v.edge / ".sigrift-restore-incomplete").read_text())
    assert m["op"] == "move" and m["id"] == AID
    rc, r, _ = v.call("mark", marker_op="import", marker_id=RB, edge_dir=str(v.edge))
    assert rc == 1 and r["code"] == "phase"
    for bad in ({"marker_op": "sideways", "marker_id": AID}, {"marker_op": "move",
                                                               "marker_id": "../x"}):
        rc, r, _ = v.call("mark", **bad)
        assert rc == 1 and r["code"] == "unsafe"
    rc, r, _ = v.call("unmark", marker_op="move", marker_id=AID, edge_dir=str(v.edge))
    assert rc == 0 and len(r["removed"]) == 3
    rc, r, _ = v.call("mark", rb_id=RB)
    assert rc == 0 and json.loads((v.data / ".sigrift-restore-incomplete").read_text())[
        "op"] == "rollback"


def test_pki_part_records_and_restores_owners_only_from_the_allowed_set(v, ns, monkeypatch):
    pki = v.tmp / "pki"
    (pki / "certs").mkdir(parents=True)
    (pki / "certs" / "ca.pem").write_text("placeholder-not-a-cert\n")
    rc, r, fr = v.call("snapshot-volume", volume="opt-sigrift-pki", pki_dir=str(pki),
                       excludes=[])
    assert rc == 0, r
    arch = b"".join(p for k, p in fr if k == b"D")
    mem = b"".join(p for k, p in fr if k == b"M")
    me = "%d:%d" % (os.getuid(), os.getgid())
    lines = [json.loads(x) for x in mem.decode().splitlines()]
    assert all(x["o"] == me for x in lines)
    target = v.tmp / "pki-new"
    target.mkdir()
    req = dict(volume="opt-sigrift-pki", pki_dir=str(target), rb_id=RB, restore_point="x",
               archive_sha256=r["archive_sha256"], archive_bytes=r["archive_bytes"],
               keep_back=[], excludes=[], reserve_bytes=0)
    if me not in ("0:0", "1500:1500"):
        rc, e, _ = v.call("stage", section(mem) + section(arch), members_file_sha256=hashlib.sha256(
            mem).hexdigest(), **req)
        assert rc == 1 and e["code"] == "unsafe"
    good = mem.replace(('"o":"%s"' % me).encode(), b'"o":"1500:1500"')
    chowned = []
    monkeypatch.setitem(ns, "CHOWN", lambda name, uid, gid, **kw: chowned.append((name, uid,
                                                                                  gid)))
    rc, e, _ = v.call("stage", section(good) + section(arch),
                      members_file_sha256=hashlib.sha256(good).hexdigest(), **req)
    assert rc == 0, e
    assert sorted(chowned) == [("ca.pem", 1500, 1500), ("certs", 1500, 1500)]


# ── the state tool on the fake host ─────────────────────────────────────


class Tool:
    def __init__(self, host, tmp, monkeypatch):
        self.t = load_state_tool()
        monkeypatch.setenv("PATH", f"{host.bin}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_DOCKER_STATE", str(host.state_path))
        monkeypatch.setenv("LC_ENGINE_BOOTSTRAP", engine_bootstrap())
        for k in ("SIGRIFT_SNAPSHOT_DIR", "LC_CALLER_DIR", "LC_SELF_DIR", "LC_FACTS_JSON",
                  "LC_STATE_DIR"):
            monkeypatch.delenv(k, raising=False)
        monkeypatch.setenv("SIGRIFT_SNAPSHOT_RESERVE", "1M")
        self.res = tmp / "result.json"

    def __call__(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        if self.res.exists():
            self.res.unlink()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                self.t.main([str(a) for a in argv] + ["--result", str(self.res)])
                rc = 0
            except SystemExit as e:
                rc = e.code if isinstance(e.code, int) else 1
        res = json.loads(self.res.read_text()) if self.res.exists() else None
        return rc, res, err.getvalue()


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


@pytest.fixture
def tool(host, tmp_path, monkeypatch):
    return Tool(host, tmp_path, monkeypatch)


@pytest.fixture
def inst(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True, running=False)
    seed_volume(host, PROJECT)
    return d


def rp_create(tool, d, *extra, reason="export"):
    from lifecycle_fakes import load_lifecycle_tool
    sid, _ = load_lifecycle_tool().take_snapshot(str(d), "upgrade", "v0.1.0", "v0.1.0", "dev",
                                                PROJECT, None)
    tool.t.journal_save(str(d), {"format": 1, "id": "20261127T101455Z", "op": "export",
                                 "state": "running", "project": PROJECT, "snapshot": sid})
    imgs = d.parent / "images.json"
    imgs.write_text("{}")
    return tool("rp-create", "--dir", d, "--project", PROJECT, "--image", IMAGE,
                "--journal-id", "20261127T101455Z", "--files-snapshot", sid, "--reason", reason,
                "--from", "v0.1.0", "--to", "-", "--install-id", "iid", "--images-file", imgs,
                *extra)


def test_rp_create_volumes_edge_data_pki_and_the_exempt_node(tool, inst, host, tmp_path):
    host.load()
    host.state["volumes"].append({"name": PROJECT + "_edge_data", "project": PROJECT,
                                  "volume": "edge_data"})
    pki = tmp_path / "opt-pki"
    pki.mkdir()
    (pki / "ca.pem").write_text("placeholder-not-a-cert\n")
    host.state["host_paths"] = {"/opt/sigrift/pki": str(pki)}
    host.save()
    (host.volume(PROJECT + "_edge_data")).mkdir(parents=True, exist_ok=True)
    (host.volume(PROJECT + "_edge_data") / "journal.db").write_bytes(b"edge")
    rc, r, err = rp_create(tool, inst, "--volumes", "bridge_secrets,bridge_data,edge_data,pki",
                           "--exempt-nodes", "local-edge", "--install-type", "source",
                           "--git-commit", "a" * 40)
    assert rc == 0, err
    m = json.loads((inst / ".sigrift" / "snapshots" / r["id"] / "manifest.json").read_text())
    assert [v["name"] for v in m["volumes"]] == ["bridge_secrets", "bridge_data", "edge_data",
                                                 "opt-sigrift-pki"]
    pv = m["volumes"][3]
    assert pv["docker_volume"] is None and pv["host_path"] == "/opt/sigrift/pki" and pv["owners"]
    assert m["volumes"][2]["docker_volume"] == PROJECT + "_edge_data"
    assert m["rf_summary"]["exempt_nodes"] == ["local-edge"] and m["install_type"] == "source"
    assert m["git_commit"] == "a" * 40 and m["reason"] == "export"
    assert m["nodes"] == [{"node_id": "pi-1", "last_seen": "2026-11-27T10:00:00Z",
                           "summary": False}]
    assert m["kept_out"]["backups_bytes"] > 0
    runs = [c["argv"] for c in host.calls() if c["argv"][:1] == ["run"]]
    pki_run = [a for a in runs if any("/opt/sigrift/pki:/v/pki" in x for x in a)]
    assert pki_run and all(a[a.index("--user") + 1] == "0:0" and "DAC_READ_SEARCH" in a
                           and "--ulimit" in a and "/opt/sigrift/pki:/v/pki:ro" in a
                           for a in pki_run)
    edge_run = [a for a in runs if any(x.endswith(":/app/edge_data:ro") for x in a)]
    assert edge_run
    assert tool("rp-verify", "--dir", inst, "--id", r["id"])[0] == 0
    rc, _, err = rp_create(tool, inst, "--volumes", "bridge_data")
    assert rc == 1 and "unknown part" in err


def full_point(tool, inst, rid, reason, install_id="iid"):
    p = inst / ".sigrift" / "snapshots" / rid
    p.mkdir(parents=True)
    p.parent.chmod(0o700)
    man = {"format": 1, "kind": "full", "id": rid, "reason": reason, "created_at":
           rid[:4] + "-" + rid[4:6] + "-" + rid[6:8] + "T00:00:00Z", "from_version": "v0.1.0",
           "project": PROJECT, "install_id": install_id, "volumes": []}
    raw = (json.dumps(man) + "\n").encode()
    (p / "manifest.json").write_bytes(raw)
    (p / "COMPLETE").write_text(tool.t.mac_of(tool.t.rp_key(str(inst), create=True), raw) + "\n")
    return p


def test_retention_drops_export_points_and_keeps_pre_import_ones(tool, inst):
    ex = full_point(tool, inst, "20261105T000000Z-v0.1.0-full", "export")
    pre = full_point(tool, inst, "20261101T000000Z-v0.1.0-full", "pre-import")
    up = full_point(tool, inst, "20261102T000000Z-v0.1.0-full", "upgrade")
    rc, r, err = tool("rp-prune", "--dir", inst, "--protect", "")
    assert rc == 0, err
    assert r["removed"] == [ex.name] and pre.exists() and up.exists()
    ex2 = full_point(tool, inst, "20261106T000000Z-v0.1.0-full", "export")
    rc, r, _ = tool("rp-prune", "--dir", inst, "--id", ex2.name)
    assert r["removed"] == [ex2.name] and not ex2.exists()
    rc, _, err = tool("rp-prune", "--dir", inst, "--id", up.name)
    assert rc == 1 and up.exists()


def test_rp_resolve_accepts_the_pre_import_point_of_the_import_that_replaced_it(tool, inst):
    pre = full_point(tool, inst, "20261101T000000Z-v0.1.0-full", "pre-import",
                     install_id="old-install")
    rec = {"install_id": "new-install", "project": PROJECT, "history": [
        {"op": "import", "result": "ok", "replaced": {"install_id": "old-install",
                                                     "restore_point": pre.name}}]}
    (inst / ".sigrift" / "install.json").write_text(json.dumps(rec))
    rc, r, err = tool("rp-resolve", "--dir", inst, "--id", pre.name, "--current", "v0.1.0")
    assert rc == 0, err
    assert r["replaced"]["install_id"] == "old-install"
    rec["history"][0]["replaced"]["install_id"] = "someone-else"
    (inst / ".sigrift" / "install.json").write_text(json.dumps(rec))
    rc, _, err = tool("rp-resolve", "--dir", inst, "--id", pre.name, "--current", "v0.1.0")
    assert rc == 3 and "belongs to another install" in err


def test_space_plans_of_export_and_import(tool, inst, tmp_path, host):
    out = tmp_path / "usb" / "x.sigrift-archive"
    out.parent.mkdir()
    rc, r, err = tool("space-plan", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--kind", "export", "--file", out)
    assert rc == 0, err
    assert r["kind"] == "export" and r["archive"] >= 1 << 20 and r["fat_too_big"] is False
    assert r["kept_out"]["backups_bytes"] > 0
    probe = tmp_path / "probe.json"
    probe.write_text(json.dumps({"metadata": {"parts": [{"name": "bridge_data",
                                                         "bytes_raw": 1000},
                                                        {"name": "bridge_secrets",
                                                         "bytes_raw": 10}]},
                                 "manifest": {"db": {"bytes": 4096}}}))
    rc, r, err = tool("space-plan", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--kind", "import", "--probe", probe)
    assert rc == 0, err
    assert r["st"] == 1010 + (64 << 20) and r["dv"] == 4096
    os.environ["SIGRIFT_SNAPSHOT_RESERVE"] = "100T"
    try:
        rc, r, err = tool("space-plan", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                          "--kind", "import", "--probe", probe)
    finally:
        os.environ["SIGRIFT_SNAPSHOT_RESERVE"] = "1M"
    assert rc == 3 and "the import stages" in err
    assert tool.t.FAT_MAX == (4 << 30) - 1


def test_release_render_compose_port_owner_and_version(tmp_path, host):
    text = INSTALL_RELEASE.read_text()

    def fn(name):
        return re.search(r"(?ms)^%s\(\) \{\n.*?^\}\n" % re.escape(name), text).group(0)
    script = "\n".join([fn("release_write_compose"), fn("release_render_compose"),
                        "VERSION=v0.2.0 OWNER=sigrift PORT=8444",
                        'release_render_compose --port 9555 --owner acme-labs --version v0.2.1 '
                        '"$1/a.yml" && echo ok-a',
                        'release_render_compose "$1/b.yml" && echo ok-b',
                        'release_render_compose --port 99999 "$1/c.yml"; echo "c=$?"',
                        'release_render_compose --owner "Bad Owner" "$1/d.yml"; echo "d=$?"',
                        'release_render_compose --port "1;x" "$1/e.yml"; echo "e=$?"'])
    r = subprocess.run(script_argv(BASH, script, str(tmp_path)), capture_output=True, text=True)
    assert "ok-a" in r.stdout and "ok-b" in r.stdout, r.stderr
    a = (tmp_path / "a.yml").read_text()
    assert "ghcr.io/acme-labs/sigrift-bridge:v0.2.1" in a
    assert '- "${SIGRIFT_BIND:-127.0.0.1}:9555:8444"' in a
    assert "ghcr.io/sigrift/sigrift-gateway:v0.2.0" in (tmp_path / "b.yml").read_text()
    for k in ("c=2", "d=2", "e=2"):
        assert k in r.stdout
    assert not any((tmp_path / n).exists() for n in ("c.yml", "d.yml", "e.yml"))
    assert shared_block(INSTALL_RELEASE, "archive-engine")


def test_stage_verify_and_discard_cover_every_part_of_the_point(tool, inst, host):
    host.load()
    host.state["volumes"].append({"name": PROJECT + "_edge_data", "project": PROJECT,
                                  "volume": "edge_data"})
    host.save()
    edge = host.volume(PROJECT + "_edge_data")
    edge.mkdir(parents=True, exist_ok=True)
    (edge / "journal.db").write_bytes(b"edge-journal")
    rc, r, err = rp_create(tool, inst, "--volumes", "bridge_secrets,bridge_data,edge_data")
    assert rc == 0, err
    rc, s, err = tool("stage", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--rp", r["id"], "--rb-id", RB)
    assert rc == 0, err
    assert set(s["volumes"]) == {"bridge_secrets", "bridge_data", "edge_data"}
    staged = edge / (".sigrift-restore-" + RB) / "journal.db"
    assert staged.read_bytes() == b"edge-journal"
    rc, v, err = tool("verify-staged", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--rp", r["id"], "--rb-id", RB)
    assert rc == 0 and v["ok"] is True, (err, v)
    rc, d, err = tool("discard-staging", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--rb-id", RB, "--volumes", "bridge_secrets,bridge_data,edge_data")
    assert rc == 0, err
    assert set(d) == {"bridge_secrets", "bridge_data", "edge_data"} and not staged.exists()
    rc, _, err = tool("swap", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                      "--rb-id", RB, "--volumes", "bridge_data,nonsense")
    assert rc == 1 and "unknown part" in err
