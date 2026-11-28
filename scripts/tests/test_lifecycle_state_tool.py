"""The state tool (Phase 1b, state-tool block) on the fake host.

lc_state_tool's source is imported from scripts/install-release.sh and its
subcommands run in process; `docker` is FakeDockerHost's, which runs every
framed engine op through the real bootstrap and the real state engine on
real volume directories (phase1b-spec 11.2, 11.6). The space plan and the
.env rules are pure functions and are called directly.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
from bash_file import script_argv  # noqa: E402
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from lifecycle_fakes import (
    BASH,
    INSTALL_RELEASE,
    INSTALLED_ENV,
    KEY_A,
    QUICKSTART,
    SECRET_VALUES,
    FakeDockerHost,
    engine_bootstrap,
    full_engine_source,
    load_lifecycle_tool,
    load_state_tool,
    release_install,
    seed_tree,
    seed_volume,
    shared_block,
)

PROJECT = "sigrift-v010"
IMAGE = "ghcr.io/sigrift/sigrift-bridge:v0.1.0"
JID = "20261127T101455Z"
pytestmark = pytest.mark.timeout(120)


class Run:
    def __init__(self, rc, result, out, err):
        self.rc, self.result, self.out, self.err = rc, result, out, err

    def __repr__(self):
        return "Run(rc=%r, err=%r, result=%r)" % (self.rc, self.err[-800:], self.result)


class Tool:
    def __init__(self, host, tmp, monkeypatch):
        self.host = host
        self.t = load_state_tool()
        monkeypatch.setenv("PATH", f"{host.bin}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("FAKE_DOCKER_STATE", str(host.state_path))
        monkeypatch.setenv("LC_ENGINE_BOOTSTRAP", engine_bootstrap())
        for k in ("SIGRIFT_SNAPSHOT_DIR", "LC_CRITICAL", "LC_CALLER_DIR", "LC_SELF_DIR",
                  "LC_FACTS_JSON", "LC_ENGINE_STALL_SECONDS", "COMPOSE_FILE"):
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
                rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
        result = json.loads(self.res.read_text()) if self.res.exists() else None
        return Run(rc, result, out.getvalue(), err.getvalue())

    def ok(self, *argv):
        r = self(*argv)
        assert r.rc == 0, r
        return r.result


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


def journal(d: Path) -> dict:
    return json.loads((d / ".sigrift" / "journal.json").read_text())


def start_journal(tool, d, jid=JID, **extra):
    """An upgrade journal at prechecks, with the quiesced state in pre_state."""
    lc = load_lifecycle_tool()
    sid, _ = lc.take_snapshot(str(d), "upgrade", "v0.1.0", "v0.2.0", "dev", PROJECT, None)
    j = {"format": 1, "id": jid, "op": "upgrade", "state": "running", "project": PROJECT,
         "steps": ["snapshot", "stop", "hold", "prechecks", "restore-point", "switch"],
         "done": ["snapshot", "stop", "hold"], "snapshot": sid, "pre": {"schema": 56}}
    j.update(extra)
    tool.t.journal_save(str(d), j)
    tool.ok("quiesce", "--project", PROJECT, "--image", IMAGE, "--mode", "strict",
            "--env-file", d / ".env", "--journal-key", "pre_state", "--dir", d)
    return sid


def images_file(tmp: Path) -> Path:
    p = tmp / "images.json"
    p.write_text(json.dumps({svc: {"ref": "ghcr.io/sigrift/sigrift-%s:v0.1.0" % svc,
                                   "id": "sha256:" + hashlib.sha256(svc.encode()).hexdigest(),
                                   "digest": "ghcr.io/sigrift/sigrift-%s@sha256:%s" % (
                                       svc, "d" * 64)} for svc in ("bridge", "gateway")}))
    return p


def rp_create(tool, d, sid, *extra, reason="upgrade", frm="v0.1.0", to="v0.2.0", jid=JID):
    return tool("rp-create", "--dir", d, "--project", PROJECT, "--image", IMAGE,
                "--journal-id", jid, "--files-snapshot", sid, "--reason", reason,
                "--from", frm, "--to", to, "--install-id", "iid-1234567890",
                "--images-file", images_file(d.parent), "--prechecks-from-journal", *extra)


def make_point(tool, d, **kw):
    sid = start_journal(tool, d)
    r = rp_create(tool, d, sid, **kw)
    assert r.rc == 0, r
    return r.result["id"], sid


def point_dir(d, rid):
    return d / ".sigrift" / "snapshots" / rid


# ── 1-5 rp-create ───────────────────────────────────────────────────────


def test_rp_create_layout_modes_and_complete_written_last(tool, inst, monkeypatch):
    sid = start_journal(tool, inst)
    order = []
    real = tool.t.atomic_write

    def spy(path, data, mode):
        order.append(os.path.basename(path))
        return real(path, data, mode)
    monkeypatch.setattr(tool.t, "atomic_write", spy)
    r = rp_create(tool, inst, sid)
    assert r.rc == 0, r
    rid = r.result["id"]
    assert re.fullmatch(r"\d{8}T\d{6}Z-v0\.1\.0-full", rid)
    p = point_dir(inst, rid)
    # rp_partial in the journal, the manifest, COMPLETE last in the point, then the
    # journal names the restore point.
    assert [o for o in order if o in ("journal.json", "manifest.json", "COMPLETE")] == [
        "journal.json", "manifest.json", "COMPLETE", "journal.json"]
    for path in [p] + list(p.rglob("*")):
        mode = stat.S_IMODE(path.lstat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path
    key = (inst / ".sigrift" / "rp.key").read_bytes()
    assert len(key) == 32 and stat.S_IMODE((inst / ".sigrift" / "rp.key").stat().st_mode) == 0o600
    import hmac as hmac_
    want = "hmac-sha256:" + hmac_.new(key, (p / "manifest.json").read_bytes(),
                                      hashlib.sha256).hexdigest()
    assert (p / "COMPLETE").read_text() == want + "\n"
    m = json.loads((p / "manifest.json").read_text())
    assert m["kind"] == "full" and m["from_version"] == "v0.1.0" and m["to_version"] == "v0.2.0"
    assert m["files_snapshot"] == sid and m["install_id"] == "iid-1234567890"
    assert [v["name"] for v in m["volumes"]] == ["bridge_secrets", "bridge_data"]
    assert m["marks"]["tables"]["detections"] == 2 and m["db"]["quick_check"] == "ok"
    assert {f["path"]: f["restore_on_rollback"] for f in m["files"]}[".env"] is True
    assert journal(inst)["restore_point"] == rid
    assert tool.ok("rp-verify", "--dir", inst, "--id", rid)["id"] == rid


def test_rp_partial_is_journaled_before_the_directory_exists(tool, inst, monkeypatch):
    sid = start_journal(tool, inst)
    seen = []
    real = tool.t.journal_put

    def spy(d, key, value):
        if key == "rp_partial":
            seen.append(os.path.exists(os.path.join(value["root"], value["id"])))
        return real(d, key, value)
    monkeypatch.setattr(tool.t, "journal_put", spy)
    tool.host.update(engine_faults={"snapshot-volume": {"rc": 137, "after": 2}})
    r = rp_create(tool, inst, sid)
    assert r.rc == 1 and "kind=stream" in r.err or "kind=engine" in r.err
    assert seen == [False]
    j = journal(inst)
    assert j["rp_partial"]["id"] and "restore_point" not in j
    assert not point_dir(inst, j["rp_partial"]["id"]).exists()


def test_rp_files_come_from_the_files_only_point_not_from_the_folder(tool, inst):
    original = (inst / "docker-compose.yml").read_bytes()
    sid = start_journal(tool, inst)
    (inst / "docker-compose.yml").write_text("# SigRift hold stub: held\n")
    (inst / "install-release.sh").write_text("# the new installer\n")
    r = rp_create(tool, inst, sid)
    assert r.rc == 0, r
    files = point_dir(inst, r.result["id"]) / "files"
    assert (files / "docker-compose.yml").read_bytes() == original
    assert (files / "install-release.sh").read_bytes() == INSTALL_RELEASE.read_bytes()


def test_reserve_reached_while_writing_removes_the_engine_and_the_partial(tool, inst,
                                                                         monkeypatch):
    sid = start_journal(tool, inst)
    real = os.statvfs
    calls = {"n": 0}

    def statvfs(path):
        s = real(path)
        calls["n"] += 1
        free = 1 << 40 if calls["n"] <= 1 else 1
        bav = free // s.f_frsize
        return os.statvfs_result((s.f_bsize, s.f_frsize, s.f_blocks, bav, bav, s.f_files,
                                  s.f_ffree, s.f_favail, s.f_flag, s.f_namemax))
    monkeypatch.setattr(tool.t, "STATVFS", statvfs)
    monkeypatch.setattr(tool.t, "MONITOR_STEP", 1)
    r = rp_create(tool, inst, sid)
    assert r.rc == 7 and "kind=space" in r.err, r
    assert any(a.startswith("rm -f sigrift-lc-%s-snapshot-volume-" % PROJECT)
               for a in tool.host.argvs())
    assert not any(n for n in os.listdir(inst / ".sigrift" / "snapshots") if "full" in n)


def test_stall_watchdog_removes_the_engine_and_fails_the_step(tool, inst, monkeypatch):
    sid = start_journal(tool, inst)
    monkeypatch.setenv("LC_ENGINE_STALL_SECONDS", "0.3")
    # A blocked worker whose heartbeat keeps sending the same P frame.
    tool.host.update(engine_faults={"snapshot-volume": {"stall": True}})
    r = rp_create(tool, inst, sid)
    assert r.rc == 1 and "kind=stream" in r.err and "sent nothing" in r.err, r
    assert any(a.startswith("rm -f sigrift-lc-") for a in tool.host.argvs())
    assert not any("full" in n for n in os.listdir(inst / ".sigrift" / "snapshots"))


@pytest.mark.parametrize("raw, why", [
    ("52" + "%016x" % 2 + "7b7d" + "52" + "%016x" % 2 + "7b7d", "after the terminal"),
    ("50" + "%016x" % (3 << 20), "over 2 MiB"),
    ("52" + "%016x" % 9 + "7b7d", "truncated"),
    ("51" + "%016x" % 2 + "7b7d", "unknown frame kind"),
    ("", "without a reply")])
def test_truncated_trailing_or_oversized_frames_are_refused(tool, inst, raw, why):
    tool.host.update(engine_faults={"state": {"raw": raw}})
    r = tool("state", "--project", PROJECT, "--image", IMAGE)
    assert r.rc == 1 and why in r.err, r


# ── 6-11 the space plan ─────────────────────────────────────────────────


GB = 10 ** 9


def fake_state(db=1 * GB, captures=2 * GB, other=200 * 10 ** 6, replaced=(), premig=(),
               free=40 * GB, size=64 * GB):
    return {"db": {"bytes": db},
            "sizes": {"bridge_data": {"classes": {"db": db, "captures": captures, "other": other},
                                      "total_raw": db + captures + other,
                                      "replaced": list(replaced), "premigration": list(premig)},
                      "bridge_secrets": {"total_raw": 0}},
            "fs": {"bridge_data": {"frsize": 4096, "blocks": size // 4096,
                                   "bavail": free // 4096, "files": 1000}}}


@pytest.fixture
def disk(tool, inst, monkeypatch):
    """The host filesystem of the restore-point root: FREE bytes free of SIZE."""
    box = {"free": 40 * GB, "size": 64 * GB, "same": True}
    monkeypatch.delenv("SIGRIFT_SNAPSHOT_RESERVE")

    def statvfs(path):
        return os.statvfs_result((4096, 4096, box["size"] // 4096, box["free"] // 4096,
                                  box["free"] // 4096, 1000, 1000, 1000, 0, 255))
    monkeypatch.setattr(tool.t, "STATVFS", statvfs)
    monkeypatch.setattr(tool.t, "same_fs", lambda root, fs: box["same"])
    return box


def plan(tool, inst, state, kind="upgrade", excl=(), rp=None, mig=False):
    return tool.t.space_plan(str(inst), PROJECT, kind, state, set(excl), rp, mig)


def test_space_plan_counts_premigration_replaced_and_older_points_as_used(tool, inst, disk):
    rid, _ = make_point(tool, inst)
    tool.t.newest_ratio = lambda d: {}  # before the first measured ratio
    st = fake_state(replaced=[{"id": "x", "bytes": 3 * GB, "phase": "done"}],
                    premig=[{"name": "detections.db.pre-migration", "bytes": GB,
                             "mtime_ns": 1}])
    p = plan(tool, inst, st)
    assert p["used"]["replaced"] == 3 * GB and p["used"]["premigration"] == GB
    assert p["used"]["older_points"] > 0
    # the worked example of 7.3: RP = 3.2 GB x 1.10 + 64 MiB, the reserve 5 % of 64 GB
    assert abs(p["rp"] - (3.2e9 * 1.10 + (64 << 20))) < 1e6
    assert p["reserve"] == int(64 * GB * 0.05) and p["ok"] is True


def test_space_plan_uses_the_measured_compression_ratio(tool, inst, disk):
    rid, _ = make_point(tool, inst)
    m = point_dir(inst, rid) / "manifest.json"
    ratio = [v for v in json.loads(m.read_text())["volumes"] if v["name"] == "bridge_data"][0]
    assert set(ratio["ratio"]) == {"db", "captures", "other"}
    assert ratio["ratio"]["db"] is None  # a class below 64 MiB measures nothing
    monkeypatch_ratio = {"db": 0.4, "captures": 1.0, "other": 0.3}
    tool.t.newest_ratio = lambda d: monkeypatch_ratio
    p = plan(tool, inst, fake_state(), excl=())
    assert abs(p["est"]["db"] - 1e9 * 0.4 * 1.1) < 10 and abs(p["est"]["other"] - 2e8 * 0.3 * 1.1) < 10


def test_same_filesystem_by_st_dev_or_statvfs_fingerprint(tool, inst, monkeypatch, tmp_path):
    t = tool.t
    monkeypatch.setattr(t, "docker_root", lambda: str(tmp_path))
    assert t.same_fs(str(inst / ".sigrift" / "snapshots"), {}) is True
    monkeypatch.setattr(t, "docker_root", lambda: "/nonexistent/docker")
    s = os.statvfs(str(inst))
    fs = {"frsize": s.f_frsize, "blocks": s.f_blocks, "files": s.f_files, "bavail": s.f_bavail}
    assert t.same_fs(str(inst), fs) is True
    assert t.same_fs(str(inst), dict(fs, blocks=s.f_blocks + 1)) is False
    assert t.same_fs(str(inst), dict(fs, bavail=int(s.f_bavail * 0.5))) is False
    assert t.same_fs(str(inst), dict(fs, files=int(s.f_files * 1.5))) is False


def full_point(tool, inst, rid, reason, from_version="v0.1.0", nbytes=GB, created=None):
    """A COMPLETE full restore point with a valid MAC (its archives are stand-ins)."""
    p = point_dir(inst, rid)
    p.mkdir(parents=True)
    p.parent.chmod(0o700)  # as rp-create leaves its root (check_root)
    (p / "blob").write_bytes(b"x")
    man = {"format": 1, "kind": "full", "id": rid, "reason": reason,
           "created_at": created or rid[:4] + "-" + rid[4:6] + "-" + rid[6:8] + "T00:00:00Z",
           "from_version": from_version, "to_version": "v0.2.0", "project": PROJECT,
           "install_id": None, "volumes": [{"name": "bridge_data", "bytes_raw": nbytes,
                                            "ratio": {"db": 1.0}}]}
    raw = (json.dumps(man) + "\n").encode()
    (p / "manifest.json").write_bytes(raw)
    key = tool.t.rp_key(str(inst), create=True)
    (p / "COMPLETE").write_text(tool.t.mac_of(key, raw) + "\n")
    tool.t.tree_bytes = (lambda real: lambda path: nbytes if str(path).startswith(str(p))
                         else real(path))(tool.t.tree_bytes)
    return p


def history(inst, *entries):
    rec = {"install_id": None, "project": PROJECT, "history": list(entries)}
    (inst / ".sigrift").mkdir(exist_ok=True)
    (inst / ".sigrift" / "install.json").write_text(json.dumps(rec))


def test_space_plan_remedies_in_order_and_only_as_far_as_needed(tool, inst, disk):
    for rid in ("20261101T000000Z-v0.0.7-full", "20261102T000000Z-v0.0.8-full",
                "20261103T000000Z-v0.0.9-full", "20261104T000000Z-v0.1.0-full"):
        full_point(tool, inst, rid, "upgrade")
    full_point(tool, inst, "20261105T000000Z-v0.1.0-full", "manual")
    history(inst, {"op": "upgrade", "result": "ok", "restore_point":
                   "20261103T000000Z-v0.0.9-full", "to": "v0.1.0"})
    # Needs RP 3.6 GB + DV 0 + reserve 3.2 GB = 6.8 GB; free 4.9 GB: one prune of 1 GB is not
    # enough, two are.
    disk["free"] = int(4.9 * GB)
    p = plan(tool, inst, fake_state())
    assert [r["id"] for r in p["remedies"]] == ["20261101T000000Z-v0.0.7-full",
                                                 "20261102T000000Z-v0.0.8-full"]
    assert p["ok"] is True
    # Never the newest upgrade point, the default target or a manual one, also when the
    # newest point overall is manual.
    disk["free"] = 1 * GB
    p = plan(tool, inst, fake_state())
    ids = [r["id"] for r in p["remedies"]]
    assert "20261104T000000Z-v0.1.0-full" not in ids and "20261103T000000Z-v0.0.9-full" not in ids
    assert "20261105T000000Z-v0.1.0-full" not in ids and p["ok"] is False


def test_space_plan_never_removes_replaced_manual_files_only_points_or_captures_and_names_them(
        tool, inst, disk):
    full_point(tool, inst, "20261105T000000Z-v0.1.0-full", "manual")
    disk["free"] = 2 * GB
    p = plan(tool, inst, fake_state(replaced=[{"id": "20261106T000000Z", "bytes": 5 * GB,
                                               "phase": "done"}]))
    assert p["ok"] is False and p["remedies"] == []
    kinds = [o["kind"] for o in p["operator_options"]]
    assert kinds == ["finish", "exclude", "manual", "snapshot-dir"]
    r = Run(0, None, "", "")
    try:
        with redirect_stderr(io.StringIO()) as err:
            tool.t.space_refusal(str(inst), "upgrade", p)
    except SystemExit as e:
        r = Run(e.code, None, "", err.getvalue())
    assert r.rc == 3 and "--rollback --finish frees" in r.err and "rm -rf" in r.err
    assert r.err.rstrip().endswith("Nothing was changed.")


@pytest.mark.parametrize("free, replaced, want", [
    (6 * GB, 3 * GB, "--rollback --finish"),
    (5 * GB, 0, "--exclude iq,pcap"),
    (int(3.3 * GB), 0, "SIGRIFT_SNAPSHOT_DIR="),
    (1 * GB, 0, "df -h")])
def test_space_refusal_next_is_the_single_sufficient_option_and_nothing_changed(
        tool, inst, disk, free, replaced, want):
    disk["free"], disk["same"] = free, True
    st = fake_state(replaced=[{"id": "20261106T000000Z", "bytes": replaced, "phase": "done"}]
                    if replaced else [], free=free)
    if want.startswith("SIGRIFT"):
        disk["same"] = False
        st = fake_state(free=10 * GB)
    before = sorted(str(p) for p in inst.rglob("*"))
    p = plan(tool, inst, st)
    assert p["ok"] is False
    with redirect_stderr(io.StringIO()) as err:
        with pytest.raises(SystemExit) as e:
            tool.t.space_refusal(str(inst), "upgrade", p, "bash install-release.sh")
    nxt = [x for x in err.getvalue().splitlines() if x.startswith("Next: ")][0]
    assert e.value.code == 3 and want in nxt, err.getvalue()
    assert sorted(str(p) for p in inst.rglob("*")) == before


def test_rollback_space_plan_needs_the_raw_staging_and_names_finish(tool, inst, disk):
    full_point(tool, inst, "20261104T000000Z-v0.1.0-full", "upgrade", nbytes=3 * GB)
    disk["free"] = 4 * GB
    p = plan(tool, inst, fake_state(free=4 * GB, replaced=[{"id": "20261106T000000Z",
                                                            "bytes": GB, "phase": "done"}]),
             kind="rollback", rp="20261104T000000Z-v0.1.0-full")
    assert p["st"] == 3 * GB + (64 << 20) and p["ok"] is False and p["short"] == "docker"
    with redirect_stderr(io.StringIO()) as err:
        with pytest.raises(SystemExit):
            tool.t.space_refusal(str(inst), "rollback", p)
    assert "Next: bash install-release.sh --rollback --finish" in err.getvalue()


def test_automatic_rollback_room_is_a_note_not_a_refusal(tool, inst, disk):
    disk["free"] = 9 * GB
    p = plan(tool, inst, fake_state(free=9 * GB))
    assert p["ok"] is True and p["note"].startswith("NOTE: an automatic rollback would not")


# ── 12-14 resolve, verify, prune ────────────────────────────────────────


def test_rp_resolve_default_target_and_every_refusal(tool, inst, monkeypatch):
    up = full_point(tool, inst, "20261104T000000Z-v0.1.0-full", "upgrade").name
    full_point(tool, inst, "20261105T000000Z-v0.3.0-full", "manual", from_version="v0.3.0")
    ad = full_point(tool, inst, "20261106T000000Z-v0.1.0-full", "upgrade").name
    resolve = lambda *a: tool("rp-resolve", "--dir", inst, "--current", "v0.2.0", *a)  # noqa: E731
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": up})
    assert resolve().result["id"] == up
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": up},
            {"op": "adopt", "result": "ok", "restore_point": ad})
    assert resolve().result["id"] == ad
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": up},
            {"op": "rollback", "result": "ok", "to": "v0.1.0"})
    r = resolve()
    assert r.rc == 3 and "the last operation was a rollback to v0.1.0" in r.err
    assert resolve("--id", "20261105T000000Z-v0.3.0-full").rc == 3
    assert "newer than the installed" in resolve("--id", "20261105T000000Z-v0.3.0-full").err
    assert "is not in" in resolve("--id", "20261101T000000Z-v0.0.1-full").err
    partial = point_dir(inst, "20261107T000000Z-v0.1.0-full")
    partial.mkdir()
    (partial / "manifest.json").write_text("{}")
    assert "no valid COMPLETE" in resolve("--id", partial.name).err
    m = json.loads((point_dir(inst, up) / "manifest.json").read_text())
    other = full_point(tool, inst, "20261108T000000Z-v0.1.0-full", "upgrade")
    raw = (json.dumps(dict(m, id=other.name, project="someone-else")) + "\n").encode()
    (other / "manifest.json").write_bytes(raw)
    (other / "COMPLETE").write_text(tool.t.mac_of(tool.t.rp_key(str(inst)), raw) + "\n")
    assert "belongs to project someone-else" in resolve("--id", other.name).err
    rec = json.loads((inst / ".sigrift" / "install.json").read_text())
    rec["snapshot_dirs"] = [str(inst / "unmounted")]
    (inst / ".sigrift" / "install.json").write_text(json.dumps(rec))
    assert "which is not there now" in resolve("--id", "20261109T000000Z-v0.1.0-full").err
    tool.t.journal_save(str(inst), {"id": JID, "op": "upgrade", "state": "failed",
                                    "restore_point": up})
    r = resolve("--id", ad)
    assert r.rc == 3 and "the interrupted upgrade can only go back to %s" % up in r.err
    assert resolve().result["id"] == up


def test_default_target_skips_a_refused_rollback_and_takes_an_accepted_upgrade(tool, inst):
    up = full_point(tool, inst, "20261104T000000Z-v0.1.0-full", "upgrade").name
    acc = full_point(tool, inst, "20261106T000000Z-v0.2.0-full", "upgrade",
                     from_version="v0.2.0").name
    resolve = lambda: tool("rp-resolve", "--dir", inst, "--current", "v0.2.1")  # noqa: E731
    # A rollback refused at its late guard changed nothing (8.2).
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": up},
            {"op": "rollback", "result": "aborted", "restore_point": up})
    assert resolve().result["id"] == up
    # --resume --accept installed v0.2.1 too: its point, never the older one.
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": up},
            {"op": "upgrade", "result": "accepted", "restore_point": acc})
    assert resolve().result["id"] == acc


def test_a_point_is_bound_to_its_name_and_install(tool, inst):
    rid, _ = make_point(tool, inst)
    assert tool("rp-verify", "--dir", inst, "--id", rid).rc == 0
    renamed = "20991231T000000Z-v0.1.0-full"
    point_dir(inst, rid).rename(point_dir(inst, renamed))
    r = tool("rp-verify", "--dir", inst, "--id", renamed)
    assert r.rc == 3 and "is damaged (its manifest names %s" % rid in r.err
    point_dir(inst, renamed).rename(point_dir(inst, rid))
    assert tool("rp-verify", "--dir", inst, "--id", rid).rc == 0


def test_rp_delete_partial_keeps_a_point_with_a_complete_file(tool, inst):
    rid, _ = make_point(tool, inst)
    j = journal(inst)
    assert j["restore_point"] == rid and j["rp_partial"] is None  # COMPLETE: no longer partial
    # A key this run cannot read (sudo, a replaced key): the MAC is unknown,
    # the point is not deleted.
    (inst / ".sigrift" / "rp.key").write_bytes(os.urandom(32))
    r = tool("rp-delete-partial", "--dir", inst, "--id", rid)
    assert r.rc == 0 and r.result["kept"] is True and point_dir(inst, rid).is_dir()


def test_a_root_run_accepts_the_folder_owners_key_and_roots_and_gives_them_back(
        tool, inst, monkeypatch):
    rid, _ = make_point(tool, inst)  # as the user
    me = os.stat(inst)
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, u, g: calls.append(("fd", u, g)))
    monkeypatch.setattr(os, "lchown", lambda path, u, g: calls.append((str(path), u, g)))
    # sudo reads the user's key and roots (1a keeps the folder owner).
    assert tool.t.rp_key(str(inst)) is not None
    assert tool.t.dir_problem(str(point_dir(inst, rid).parent), str(inst)) is None
    assert tool("rp-verify", "--dir", inst, "--id", rid).rc == 0
    # A key sudo creates, and the point it writes, belong to the folder's owner.
    (inst / ".sigrift" / "rp.key").unlink()
    assert tool.t.rp_key(str(inst), create=True) is not None
    assert ("fd", me.st_uid, me.st_gid) in calls
    calls.clear()
    sid = start_journal(tool, inst, jid="20261127T101456Z")
    r = rp_create(tool, inst, sid, jid="20261127T101456Z")
    assert r.rc == 0, r
    owned = set(c[0] for c in calls if c[1:] == (me.st_uid, me.st_gid))
    p = point_dir(inst, r.result["id"])
    assert {str(p / "COMPLETE"), str(p / "manifest.json"),
            str(p / "volumes" / "bridge_data.tar.gz")} <= owned


def test_restore_files_writes_the_env_it_checked_from_a_checked_root(tool, inst, monkeypatch):
    rid = rp_with_env(tool, inst, V010_ENV)
    real, seen = tool.t.read_nofollow, []

    def swapped(path, *a):
        # The first read of files/.env sees other bytes than the later ones.
        if str(path).endswith("/files/.env"):
            seen.append(path)
            if len(seen) == 1:
                return b"BRIDGE_ENV=development\n"
        return real(path, *a)
    monkeypatch.setattr(tool.t, "read_nofollow", swapped)
    r = tool("restore-files", "--dir", inst, "--rp", rid)
    assert r.rc == 3 and "files/.env does not match its manifest" in r.err
    assert "BRIDGE_ENV=development" not in (inst / ".env").read_text()
    monkeypatch.setattr(tool.t, "read_nofollow", real)
    (inst / ".sigrift" / "snapshots").chmod(0o750)
    r = tool("restore-files", "--dir", inst, "--rp", rid)
    assert r.rc == 3 and "does not keep mode 0700" in r.err


def test_premigration_copy_stays_when_its_point_is_pruned_in_the_same_plan(tool, inst, disk):
    a = full_point(tool, inst, "20261101T000000Z-v0.1.0-full", "upgrade").name
    b = full_point(tool, inst, "20261103T000000Z-v0.2.0-full", "upgrade",
                   from_version="v0.2.0").name
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": a, "to": "v0.2.0",
                   "bridge_started_at": "2026-11-01T00:00:10Z", "at": "2026-11-01T00:05:00Z"},
            {"op": "upgrade", "result": "ok", "restore_point": b, "to": "v0.2.1",
             "bridge_started_at": "2026-11-03T00:00:10Z", "at": "2026-11-03T00:05:00Z"})
    mt = int(tool.t.epoch("2026-11-01T00:01:00Z")) * 10 ** 9
    disk["free"] = 1 * GB
    p = plan(tool, inst, fake_state(premig=[{"name": "detections.db.pre-migration",
                                             "bytes": 2 * GB, "mtime_ns": mt}]))
    # E18: A goes, so the copy of the same database is not reclaimed with it.
    assert [(r["kind"], r.get("id")) for r in p["remedies"]] == [("prune", a)]
    # At apply time too: a reclaim whose point is gone is skipped.
    vol = tool.host.volume(PROJECT + "_bridge_data")
    copy = vol / "detections.db.pre-migration"
    copy.write_bytes(b"x" * 10)
    s = copy.stat()
    remedy = {"kind": "premig", "name": copy.name, "bytes": 10, "mtime_ns": s.st_mtime_ns,
              "restore_point": "20261101T000000Z-v0.0.1-full"}
    r = tool.ok("rp-apply-remedies", "--dir", inst, "--project", PROJECT, "--image", IMAGE,
                "--plan", json.dumps({"remedies": [remedy]}))
    assert r["done"] == [] and copy.exists()


@pytest.mark.parametrize("where", ["files", "members"])
def test_rp_verify_detects_a_flipped_byte_in_files_and_members(tool, inst, where):
    rid, _ = make_point(tool, inst)
    p = point_dir(inst, rid)
    target = p / "files" / ".env" if where == "files" else \
        p / "volumes" / "bridge_data.members.json"
    data = bytearray(target.read_bytes())
    data[3] ^= 1
    target.write_bytes(bytes(data))
    r = tool("rp-verify", "--dir", inst, "--id", rid)
    assert r.rc == 3 and "is damaged" in r.err and "does not match its manifest" in r.err


@pytest.mark.parametrize("how", ["edited", "other-key"])
def test_a_point_with_a_bad_mac_is_listed_damaged_and_never_staged(tool, inst, how):
    rid, _ = make_point(tool, inst)
    p = point_dir(inst, rid)
    if how == "edited":
        m = json.loads((p / "manifest.json").read_text())
        m["images"]["bridge"]["ref"] = "ghcr.io/attacker/sigrift-bridge:v0.1.0"
        raw = (json.dumps(m) + "\n").encode()
        (p / "manifest.json").write_bytes(raw)
        (p / "COMPLETE").write_text("hmac-sha256:" + hashlib.sha256(raw).hexdigest() + "\n")
    else:
        (inst / ".sigrift" / "rp.key").write_bytes(os.urandom(32))
    listing = tool.ok("rp-list", "--dir", inst)
    entry = [e for e in listing["restore_points"] if e["id"] == rid][0]
    assert entry["status"] == "damaged" and entry["complete"] is False
    r = tool("stage", "--dir", inst, "--project", PROJECT, "--image", IMAGE, "--rp", rid,
             "--rb-id", "20261127T120000Z", "--reserve", "0")
    assert r.rc == 3 and "is damaged" in r.err
    assert not any(n.startswith(".sigrift-restore-") for n in
                   os.listdir(tool.host.volume(PROJECT + "_bridge_data")))


def test_prune_keeps_two_upgrade_points_every_manual_referenced_and_newest_and_never_an_incomplete_one(
        tool, inst):
    ids = ["20261101T000000Z-v0.0.6-full", "20261102T000000Z-v0.0.7-full",
           "20261103T000000Z-v0.0.8-full", "20261104T000000Z-v0.0.9-full"]
    for rid in ids:
        full_point(tool, inst, rid, "upgrade")
    full_point(tool, inst, "20261100T000000Z-v0.0.5-full", "manual")
    inc = point_dir(inst, "20261099T000000Z-v0.0.4-full")
    inc.mkdir()
    tool.t.journal_save(str(inst), {"id": JID, "op": "upgrade", "state": "done",
                                    "restore_point": ids[0]})
    removed = tool.ok("rp-prune", "--dir", inst, "--protect", "")["removed"]
    assert removed == [ids[1]]
    left = sorted(os.listdir(inst / ".sigrift" / "snapshots"))
    assert ids[0] in left and ids[2] in left and ids[3] in left and inc.name in left
    assert "20261100T000000Z-v0.0.5-full" in left


def test_a_kill_mid_prune_leaves_no_complete_looking_point(tool, inst, monkeypatch):
    p = full_point(tool, inst, "20261101T000000Z-v0.0.6-full", "upgrade")
    for rid in ("20261102T000000Z-v0.0.7-full", "20261103T000000Z-v0.0.8-full"):
        full_point(tool, inst, rid, "upgrade")
    monkeypatch.setattr(tool.t, "rmtree", lambda path: (_ for _ in ()).throw(KeyboardInterrupt))
    with pytest.raises(KeyboardInterrupt):
        tool.t.main(["rp-prune", "--dir", str(inst), "--protect", ""])
    root = inst / ".sigrift" / "snapshots"
    assert not p.exists() and (root / (".pruning-" + p.name)).is_dir()
    monkeypatch.undo()
    listed = [e["id"] for e in tool.t.list_snapshots_json(str(inst))["restore_points"]]
    assert p.name not in listed and ".pruning-" + p.name not in listed
    tool.ok("lc-clean", "--project", PROJECT, "--dir", inst)
    assert not (root / (".pruning-" + p.name)).exists()


# ── 15 restore-files, the .env rules ───────────────────────────────────


def rp_with_env(tool, inst, env_text, *, compose=None, missing=(), extra_files=None):
    """A COMPLETE full point whose files/ hold ENV_TEXT as .env (and a compose)."""
    rid = "20261104T000000Z-v0.1.0-full"
    p = point_dir(inst, rid)
    (p / "files").mkdir(parents=True)
    p.parent.chmod(0o700)  # as rp-create leaves its root (check_root)
    files = {".env": env_text.encode(),
             "docker-compose.yml": (compose or "# Generated by install-release.sh @ v0.1.0.\n")
             .encode(), "VERSION": b"v0.1.0\n"}
    files.update(extra_files or {})
    entries = []
    for rel, data in files.items():
        (p / "files" / rel).parent.mkdir(parents=True, exist_ok=True)
        (p / "files" / rel).write_bytes(data)
        entries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
                        "bytes": len(data), "mode": "0600",
                        "restore_on_rollback": rel in tool.t.RESTORE_ON_ROLLBACK})
    rows = b"{}\n"
    (p / "rf_rows.json").write_bytes(rows)
    man = {"format": 1, "kind": "full", "id": rid, "reason": "upgrade", "from_version": "v0.1.0",
           "created_at": "2026-11-04T00:00:00Z", "project": PROJECT, "files": entries,
           "missing": list(missing), "volumes": [],
           "rf_summary": {"rows_file_sha256": hashlib.sha256(rows).hexdigest()}}
    raw = (json.dumps(man) + "\n").encode()
    (p / "manifest.json").write_bytes(raw)
    (p / "COMPLETE").write_text(tool.t.mac_of(tool.t.rp_key(str(inst), create=True), raw) + "\n")
    return rid


V010_ENV = (f"BRIDGE_ENV=production\nBRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=audit-old\n"
            "BRIDGE_MASTER_KEY=master-old\nUC_PROXY_SECRET=proxy-old\nSIGRIFT_BIND=0.0.0.0\n"
            "UC_CSP_MODE=report-only\n")


def test_restore_files_keeps_pin_host_keys_and_the_master_rule_and_writes_compose_into_held(
        tool, inst):
    rid = rp_with_env(tool, inst, V010_ENV, missing=["docker-compose.override.yml"])
    (inst / ".env").write_text(
        f"BRIDGE_ENV=production\nBRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=audit-old\n"
        "BRIDGE_MASTER_KEY=master-rotated\nUC_PROXY_SECRET=proxy-new\n"
        "SIGRIFT_BIND=127.0.0.1\nSIGRIFT_BACKEND_SUBNET=10.9.0.0/28\nUC_CSP_MODE=strict\n"
        "BRIDGE_KEYSTORE_KEY=ks-new\nCOMPOSE_PROJECT_NAME=sigrift-v010\n")
    r = tool.ok("restore-files", "--dir", inst, "--rp", rid)
    env = tool.t.env_effective((inst / ".env").read_text())
    assert env["COMPOSE_PROJECT_NAME"] == "sigrift-v010"
    assert env["SIGRIFT_BIND"] == "127.0.0.1" and env["SIGRIFT_BACKEND_SUBNET"] == "10.9.0.0/28"
    assert env["BRIDGE_MASTER_KEY"] == "master-rotated"  # an audit key is set: kept
    assert env["UC_CSP_MODE"] == "strict" and env["UC_PROXY_SECRET"] == "proxy-old"
    assert "BRIDGE_KEYSTORE_KEY" not in env
    assert sorted(r["env_reverted"]) == ["BRIDGE_KEYSTORE_KEY", "UC_PROXY_SECRET"]
    assert set(r["env_kept"]) >= {"COMPOSE_PROJECT_NAME", "SIGRIFT_BIND", "BRIDGE_MASTER_KEY",
                                  "UC_CSP_MODE"}
    assert (inst / ".sigrift" / "held" / "docker-compose.yml").read_text().startswith(
        "# Generated by install-release.sh @ v0.1.0.")
    assert not (inst / ".sigrift" / "held" / "docker-compose.override.yml").exists()
    assert (inst / "VERSION").read_text() == "v0.1.0\n"
    assert len(list(inst.glob(".env.bak.*~"))) == 1
    assert "master-rotated" not in json.dumps(r) and "proxy" not in json.dumps(r)
    again = tool.ok("restore-files", "--dir", inst, "--rp", rid)
    assert again["restored"] == [] and len(list(inst.glob(".env.bak.*~"))) == 1


def test_master_key_comes_back_without_an_audit_key_and_is_a_credential(tool, inst):
    rid = rp_with_env(tool, inst, "BRIDGE_MASTER_KEY=master-old\nUC_PROXY_SECRET=p\n")
    (inst / ".env").write_text("BRIDGE_MASTER_KEY=master-new\nUC_PROXY_SECRET=p\n")
    r = tool.ok("restore-files", "--dir", inst, "--rp", rid)
    assert r["env_credentials"] == ["BRIDGE_MASTER_KEY"]
    assert tool.t.env_effective((inst / ".env").read_text())["BRIDGE_MASTER_KEY"] == "master-old"


STRICTER = [
    ("BRIDGE_ENV", "production", "development", True),
    ("BRIDGE_ENV", "development", "production", False),
    ("UC_CSP_MODE", "strict", "report-only", True),
    ("UC_CSP_MODE", "disabled", "report-only", False),
    ("BRIDGE_SESSION_BINDING", "strict", "ip", True),
    ("BRIDGE_SESSION_BINDING", "none", "warn", False),
    ("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "", "1", True),
    ("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "1", "", False),
    ("BRIDGE_TRUSTED_PROXIES", "10.0.0.2", "10.0.0.2,10.0.0.3", True),
    ("BRIDGE_TRUSTED_PROXIES", "10.0.0.2,10.0.0.9", "10.0.0.2", False),
]


@pytest.mark.parametrize("key, cur, old, kept", STRICTER)
def test_restore_files_keeps_stricter_security_settings(tool, inst, key, cur, old, kept):
    base = (f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\nUC_PROXY_SECRET=p\n"
            "BRIDGE_MASTER_KEY=m\n")
    rid = rp_with_env(tool, inst, base + "%s=%s\n" % (key, old))
    (inst / ".env").write_text(base + "%s=%s\n" % (key, cur))
    r = tool.ok("restore-files", "--dir", inst, "--rp", rid)
    got = tool.t.env_effective((inst / ".env").read_text()).get(key) or ""
    assert got == (cur if kept else old)
    assert (key in r["env_kept"]) is kept and (key in r["env_reverted"]) is not kept


def test_production_is_kept_only_with_its_four_secrets(tool, inst):
    rid = rp_with_env(tool, inst, "BRIDGE_ENV=development\nBRIDGE_MFA_KEY=\n")
    (inst / ".env").write_text("BRIDGE_ENV=production\n")
    tool.ok("restore-files", "--dir", inst, "--rp", rid)
    assert tool.t.env_effective((inst / ".env").read_text())["BRIDGE_ENV"] == "development"


def test_keys_the_upgrade_wrote_go_back_silently(tool, inst):
    rid = rp_with_env(tool, inst, "UC_PROXY_SECRET=p\n")
    (inst / ".env").write_text("UC_PROXY_SECRET=p\nBRIDGE_KEYSTORE_KEY=ks-written\nOTHER=x\n")
    history(inst, {"op": "upgrade", "result": "ok", "restore_point": rid,
                   "env_written": {"BRIDGE_KEYSTORE_KEY": tool.t.tag("ks-written")}})
    r = tool.ok("restore-files", "--dir", inst, "--rp", rid)
    assert r["env_undone_with_upgrade"] == ["BRIDGE_KEYSTORE_KEY"]
    assert r["env_reverted"] == ["OTHER"]


@pytest.mark.parametrize("case", ["dotdot", "absolute", "missing", "compose-file", "profiles"])
def test_restore_files_refuses_paths_outside_the_installer_set_and_compose_class_keys(
        tool, inst, case):
    env = "UC_PROXY_SECRET=p\n"
    extra, missing = None, ()
    if case == "dotdot":
        extra = {"../x": b"evil"}
    elif case == "absolute":
        extra = {"/etc/x": b"evil"}
    elif case == "missing":
        missing = ("../../etc/passwd",)
    elif case == "compose-file":
        env += "COMPOSE_FILE=/tmp/evil.yml\n"
    else:
        env += "COMPOSE_PROFILES=evil\n"
    if case in ("dotdot", "absolute"):
        rid = rp_with_env(tool, inst, env)
        p = point_dir(inst, rid)
        m = json.loads((p / "manifest.json").read_text())
        m["files"].append({"path": list(extra)[0], "sha256": "0" * 64, "bytes": 4})
        raw = (json.dumps(m) + "\n").encode()
        (p / "manifest.json").write_bytes(raw)
        (p / "COMPLETE").write_text(tool.t.mac_of(tool.t.rp_key(str(inst)), raw) + "\n")
    else:
        rid = rp_with_env(tool, inst, env, missing=missing)
    before = {str(p): p.read_bytes() for p in inst.rglob("*") if p.is_file()}
    r = tool("restore-files", "--dir", inst, "--rp", rid)
    assert r.rc == 3 and r.err.rstrip().endswith("Nothing was changed."), r
    assert {str(p): p.read_bytes() for p in inst.rglob("*") if p.is_file()} == before
    assert ("COMPOSE" in r.err) is case.startswith(("compose", "profiles"))


def test_abort_restore_from_a_files_only_point_puts_back_byte_identical_files_under_a_hold(
        tool, inst):
    lc = load_lifecycle_tool()
    before = {n: (inst / n).read_bytes() for n in (".env", "docker-compose.yml",
                                                     "docker-compose.override.yml")}
    sid, _ = lc.take_snapshot(str(inst), "rollback", "v0.2.0", "v0.1.0", "dev", PROJECT, None)
    held = inst / ".sigrift" / "held"
    held.mkdir()
    (held / "docker-compose.yml").write_text("restored by the rollback\n")
    (inst / "docker-compose.yml").write_text("# SigRift hold stub: held\n")
    (inst / ".env").write_text("CHANGED=1\n")
    tool.ok("restore-files", "--dir", inst, "--files-snapshot", sid, "--all")
    assert (inst / ".env").read_bytes() == before[".env"]
    assert (held / "docker-compose.yml").read_bytes() == before["docker-compose.yml"]
    assert (held / "docker-compose.override.yml").read_bytes() == \
        before["docker-compose.override.yml"]
    assert (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub")
    # a files-only point that recorded the stub is refused
    (inst / "docker-compose.yml").unlink()
    shutil.move(str(held / "docker-compose.yml"), str(inst / "docker-compose.yml"))
    (inst / "docker-compose.yml").write_text("# SigRift hold stub: held\n")
    # (PART B's take_snapshot never records a stub; build such a point the
    # way 1a's plain one would have, blind to the hold header.)
    lc.HOLD_HEADER = "# not the hold header"
    sid2 = lc.take_snapshot(str(inst), "x", "v", "v", "dev", PROJECT, None)[0]
    r = tool("restore-files", "--dir", inst, "--files-snapshot", sid2, "--all")
    assert r.rc == 3 and "hold stub" in r.err


# ── 16 the copied helpers, the wrapper, results ─────────────────────────

DOTENV_CORPUS = [
    "A=1\nB='two words'\nexport C=\"x\"\n# comment\nD=val # trailing\nE=\nF='unterminated\n",
    "K: v\nK=again\n  L = spaced  \nM=$HOME\nN=\"a\\nb\"\n",
    "",
    "X=1",
]


def test_copied_helpers_match_lc_tool(tool, tmp_path):
    lc, st = load_lifecycle_tool(), tool.t
    for text in DOTENV_CORPUS:
        a = [(x.name, x.value, x.start, x.end, x.line_start, x.line_end, x.odd)
             for x in lc.parse_dotenv(text)]
        b = [(x.name, x.value, x.start, x.end, x.line_start, x.line_end, x.odd)
             for x in st.parse_dotenv(text)]
        assert a == b and lc.env_effective(text) == st.env_effective(text)
    for x, y in (("v0.1.0", "v0.2.0"), ("v0.2.0-rc1", "v0.2.0"), ("main", "v0.1.0"),
                 ("v1.0.0", "v1.0.0")):
        assert lc.version_cmp(x, y) == st.version_cmp(x, y)
    for v in ("abc", "a b", "it's", "x\ny", "$x"):
        assert lc.dotenv_value(v) == st.dotenv_value(v)
    rows = [("p_bridge_data", "p", "bridge_data"), ("q_bridge_data", "q", "bridge_data")]
    assert lc.project_volumes("p", rows) == st.project_volumes("p", rows)
    st.atomic_write(str(tmp_path / "f"), b"data", 0o640)
    assert stat.S_IMODE((tmp_path / "f").stat().st_mode) == 0o640
    d = tmp_path / "inst"
    d.mkdir()
    st.journal_save(str(d), {"id": "x", "a": {"b": 1}})
    assert lc.journal_load(str(d))["a"] == {"b": 1} and st.journal_load(str(d))["updated_at"]
    assert lc.SNAPSHOT_FILES == st.SNAPSHOT_FILES and lc.OVERRIDES == st.OVERRIDES
    for mod in (lc, st):
        with redirect_stderr(io.StringIO()) as err, pytest.raises(SystemExit) as e:
            mod.refuse("x is wrong", ["detail"], next_cmd="do y")
        assert e.value.code == 3
        assert err.getvalue() == "Error: x is wrong\n  detail\nNext: do y\nNothing was changed.\n"


def bash_tool(args, env=None, stdin=""):
    block = shared_block(INSTALL_RELEASE, "state-tool")
    script = block + '\nHELPER_IMAGE=helper:1\nlc_state_tool "$@"\n'
    full = dict(os.environ)
    full.update(env or {})
    return subprocess.run(script_argv(BASH, script, *args), capture_output=True,
                          text=True, input=stdin, env=full)


def test_state_tool_refusals_exit_3_inside_the_critical_section(tmp_path):
    r = bash_tool(["rp-resolve", "--dir", str(tmp_path), "--current", "v0.2.0", "--result",
                   str(tmp_path / "r.json")], env={"LC_CRITICAL": "1", "LC_STEP": "rb-stage"})
    assert r.returncode == 3 and "Nothing was changed." in r.stderr
    assert "stopped at step" not in r.stderr


def test_state_tool_gets_the_engine_bootstrap_and_helper_image(tmp_path):
    probe = ("import os, sys; sys.stdout.write(os.environ.get('LC_ENGINE_BOOTSTRAP', '-') + '|' "
             "+ os.environ.get('LC_HELPER_IMAGE', '-') + '|' + str(len(open(3, 'rb').read())))")
    block = shared_block(INSTALL_RELEASE, "state-tool")
    block = re.sub(r"<<'PY'\n.*?\nPY\n", "<<'PY'\n" + probe + "\nPY\n", block, flags=re.S)
    script = block + '\nLC_ENGINE_BOOTSTRAP=boot HELPER_IMAGE=helper:1\nlc_state_tool x\n'
    r = subprocess.run(script_argv(BASH, script), capture_output=True, text=True, input="SOURCE")
    assert r.stdout == "boot|helper:1|6", r.stderr
    # The names never reach a docker child: TOOL_ENV of the lifecycle tool strips them.
    assert {"LC_ENGINE_BOOTSTRAP", "LC_HELPER_IMAGE", "LC_FACTS_JSON"} <= set(
        load_lifecycle_tool().TOOL_ENV)


def test_results_go_to_the_result_file_and_never_to_stdout_or_argv(tool, inst):
    sid = start_journal(tool, inst)
    r = rp_create(tool, inst, sid)
    assert r.rc == 0 and r.out.strip() == "\n".join(
        x for x in r.out.splitlines() if x.startswith("    ")).strip()
    assert r.result["id"] and r.result["id"] not in r.out.replace("restore point:", "")
    for c in tool.host.calls():
        for secret in SECRET_VALUES:
            assert secret not in " ".join(c["argv"])
    assert all(s not in r.out + r.err for s in SECRET_VALUES)


def test_quiesce_into_pre_state_keeps_the_flat_keys_1a_verify_reads(tool, inst):
    start_journal(tool, inst)
    j = journal(inst)
    pre = j["pre"]
    assert pre["schema"] == 56 and pre["audit_head_id"] == 1 and pre["audit_rows"] == 1
    assert pre["detections_max_id"] == 2 and pre["totp_fernet"] == 1
    assert pre["encrypted"] is False and set(tool.t.PRE_KEYS) <= set(pre)
    assert j["pre_state"]["marks"]["tables"]["detections"] == 2
    tool.ok("compare", "--project", PROJECT, "--image", IMAGE, "--dir", inst, "--rp",
            make_point_on(tool, inst), "--journal-key", "auto_rollback.b_live")
    b = journal(inst)["auto_rollback"]["b_live"]
    assert set(b) == {"checkable", "nothing_new", "rf", "counts"} and b["nothing_new"] is True


def make_point_on(tool, inst):
    j = journal(inst)
    r = rp_create(tool, inst, j["snapshot"])
    assert r.rc == 0, r
    return r.result["id"]


# ── 17-23 images, health, the run arguments, listing, roots, ids ──────────


def test_images_ensure_by_id_tag_pull_by_digest_or_refuse(tool, inst):
    rid = rp_with_env(tool, inst, "X=1\n")
    p = point_dir(inst, rid)
    m = json.loads((p / "manifest.json").read_text())
    bid, gid = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    m["images"] = {"bridge": {"ref": IMAGE, "id": bid, "digest": "ghcr.io/sigrift/sigrift-bridge@sha256:" + "a" * 64},
                   "gateway": {"ref": "ghcr.io/sigrift/sigrift-gateway:v0.1.0", "id": gid,
                               "digest": "ghcr.io/sigrift/sigrift-gateway@sha256:" + "b" * 64}}
    raw = (json.dumps(m) + "\n").encode()
    (p / "manifest.json").write_bytes(raw)
    (p / "COMPLETE").write_text(tool.t.mac_of(tool.t.rp_key(str(inst)), raw) + "\n")
    tool.host.update(image_ids_strict=True, images={
        IMAGE: {"id": bid}, "old/gateway:other-tag": {"id": gid}},
        registry={})
    assert tool.ok("images-ensure", "--rp", rid, "--dir", inst) == {"bridge": "present",
                                                                   "gateway": "retagged"}
    assert tool.host.load()["images"]["ghcr.io/sigrift/sigrift-gateway:v0.1.0"]["id"] == gid
    tool.host.update(images={}, registry={m["images"]["bridge"]["digest"]: {"id": bid}})
    r = tool("images-ensure", "--rp", rid, "--dir", inst, "--check")
    assert r.rc == 1 and r.result["bridge"] == "pullable"
    assert not any(a.startswith("pull ") for a in tool.host.argvs())
    r = tool("images-ensure", "--rp", rid, "--dir", inst, "--pull-allowed")
    assert r.rc == 3 and "could not be pulled by its digest" in r.err  # the gateway's is absent
    assert "pull " + m["images"]["bridge"]["digest"] in tool.host.argvs()


def test_gateway_ever_healthy_reads_the_health_log_since_t(tool, host):
    host.update(containers=[{"id": "gw1", "name": "p-gateway-1", "project": "p",
                             "service": "gateway", "state": "running", "image": "g",
                             "started_at_iso": "2026-11-27T10:05:00.123456789Z",
                             "health_log": [{"Start": "2026-11-27T10:04:00Z", "ExitCode": 0},
                                            {"Start": "2026-11-27T10:06:00Z", "ExitCode": 1}]}])
    ask = lambda since, child: tool.ok("gateway-ever-healthy", "--container", "gw1",  # noqa: E731
                                       "--since", since, "--child-start", child)["answer"]
    assert ask("2026-11-27T10:05:00Z", "2026-11-27T10:00:00Z") == "no"
    assert ask("2026-11-27T10:03:00Z", "2026-11-27T10:00:00Z") == "yes"
    assert ask("2026-11-27T10:03:00Z", "2026-11-27T10:06:00Z") == "unwatched"


def test_every_engine_run_has_log_driver_none_network_none_cap_drop_a_name_a_label_and_no_secret(
        tool, inst):
    src = shared_block(INSTALL_RELEASE, "state-tool")
    for run in re.findall(r'args = \["run",[^\]]*\]', src):
        assert '"--log-driver", "none"' in run and '"--network", "none"' in run
    tool.ok("state", "--project", PROJECT, "--image", IMAGE, "--env-file", inst / ".env")
    runs = [c["argv"] for c in tool.host.calls() if c["argv"][:1] == ["run"]]
    assert runs
    for argv in runs:
        joined = " ".join(argv)
        for flag in ("--log-driver none", "--network none", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--user 1500:1500",
                     "--label com.sigrift.lifecycle=state-engine",
                     "--label com.sigrift.lifecycle.project=%s" % PROJECT):
            assert flag in joined, (flag, joined)
        assert re.search(r"--name sigrift-lc-%s-state-[0-9a-f]{6}\b" % PROJECT, joined)
        assert not any(s in joined for s in SECRET_VALUES)
    assert any(b"audit-123456" in x for x in tool.host.engine_inputs())  # stdin only


def test_list_json_schema(tool, inst):
    rid, sid = make_point(tool, inst)
    (point_dir(inst, "20261128T000000Z-v0.1.0-full")).mkdir()
    os.environ["LC_FACTS_JSON"] = json.dumps({"lifecycle": {"replaced": [
        {"volume": "bridge_data", "id": "20261120T000000Z", "phase": "done", "bytes": 5}]}})
    try:
        r = tool("rp-list", "--dir", inst, "--json", "--verify")
    finally:
        del os.environ["LC_FACTS_JSON"]
    assert r.rc == 0, r
    j = json.loads(r.out)
    assert j == r.result
    assert set(j) >= {"format", "restore_points", "incomplete_restore_points", "replaced",
                      "finish_pending"} and j["format"] == 1
    full = [e for e in j["restore_points"] if e["kind"] == "full"][0]
    assert set(full) >= {"id", "kind", "reason", "complete", "from_version", "to_version",
                         "created_at", "bytes", "captures", "root", "default_target",
                         "protected", "rollback_cmd"}
    assert full["complete"] is True and full["verified"] is True and full["status"] == "COMPLETE"
    assert full["rollback_cmd"] == "bash install-release.sh --rollback " + rid
    files = [e for e in j["restore_points"] if e["kind"] == "files"]
    assert files and all(e["complete"] and e["verified"] for e in files)
    assert [e["id"] for e in j["incomplete_restore_points"]] == ["20261128T000000Z-v0.1.0-full"]
    assert j["replaced"] == [{"id": "20261120T000000Z", "volume": "bridge_data",
                              "phase": "done", "bytes": 5}]
    arch = point_dir(inst, rid) / "volumes" / "bridge_data.tar.gz"
    data = bytearray(arch.read_bytes())
    data[len(data) // 2] ^= 0xFF
    arch.write_bytes(bytes(data))
    r = tool("rp-list", "--dir", inst, "--json", "--verify")
    assert r.rc == 1 and [e for e in r.result["restore_points"] if e["id"] == rid][0][
        "status"] == "damaged"


def test_list_snapshots_starts_no_container(tool, inst):
    make_point(tool, inst)
    tool.host.clear_log()
    tool.ok("rp-list", "--dir", inst, "--json", "--verify")
    assert not [a for a in tool.host.argvs() if a.startswith("run ")]


@pytest.mark.parametrize("mode, why", [(0o777, "others can write without the sticky bit"),
                                       (0o1777, None), (0o755, None)])
def test_snapshot_dir_with_a_writable_non_sticky_ancestor_is_refused(tool, inst, tmp_path,
                                                                   monkeypatch, mode, why):
    parent = tmp_path / "usb"
    parent.mkdir()
    parent.chmod(mode)
    monkeypatch.setenv("SIGRIFT_SNAPSHOT_DIR", str(parent / "points"))
    (parent / "points").mkdir()
    (parent / "points").chmod(0o700)
    root = tool.t.new_root(str(inst), PROJECT)
    problem = tool.t.dir_problem(root, str(inst))
    assert (problem is None) if why is None else (why in problem)
    (parent / "points").chmod(0o750)
    assert tool.t.dir_problem(str(parent / "points"), str(inst)) in (
        "does not keep mode 0700", "lies under %s, which others can write without the sticky "
                                   "bit" % parent)
    assert "inside tls/" in tool.t.dir_problem(str(inst / "tls" / "x"), str(inst))


def test_install_id_file_names_the_install_before_its_first_record(tool, inst):
    (inst / ".sigrift").mkdir(exist_ok=True)
    (inst / ".sigrift" / "install-id").write_text("iid-1234567890\n")
    rid, _ = make_point(tool, inst)
    assert tool.t.install_id(str(inst)) == "iid-1234567890"
    r = tool("rp-resolve", "--dir", inst, "--id", rid, "--current", "v0.2.0")
    assert r.rc == 0, r
    (inst / ".sigrift" / "install-id").write_text("another-install\n")
    r = tool("rp-resolve", "--dir", inst, "--id", rid, "--current", "v0.2.0")
    assert r.rc == 3 and "another install (id iid-1234" in r.err


# ── the rollback's volume steps through the tool, end to end ──────────────


def test_stage_carry_mark_swap_and_back_through_the_tool(tool, inst, host):
    rid, _ = make_point(tool, inst)
    data = host.volume(PROJECT + "_bridge_data")
    keys = json.loads((data / "keys.json").read_text())
    keys["keys"]["ops"]["revoked"] = True
    (data / "keys.json").write_text(json.dumps(keys))
    conn = sqlite3.connect(data / "detections.db")
    conn.execute("INSERT INTO detections VALUES ('d9', '2026-11-27T11:00:00Z', 'pi-1', 'fm', '', "
                 "1, 1, 1, 1, 1, 'default')")
    conn.commit()
    conn.close()
    live = sorted(os.listdir(data))
    rb = "20261127T120000Z"
    common = ["--dir", inst, "--project", PROJECT, "--image", IMAGE, "--rb-id", rb]
    cmp_ = tool.ok("compare", "--project", PROJECT, "--image", IMAGE, "--dir", inst,
                   "--rp", rid)
    assert cmp_["discards"]["rows"] == {"detections": 1} and cmp_["carries"]["api_keys_revoked"] \
        == ["ops"]
    assert cmp_["not_carried"]["settings"]["env_keys_reverted"] == []
    tool.ok("stage", *common, "--rp", rid, "--reserve", "0")
    assert tool.ok("verify-staged", *common, "--rp", rid)["ok"] is True
    rep = tool.ok("carry", *common, "--keep-current-master", "1")
    assert rep["api_keys_revoked"] == ["ops"] and rep["sessions"]["ended"] == 1
    assert json.loads((inst / ".sigrift" / "logs" / ("rollback-" + rb) / "carry.json")
                      .read_text())["api_keys_revoked"] == ["ops"]
    tool.ok("mark", *common, "--rp", rid)
    tool.ok("swap", *common, "--rp", rid)
    assert json.loads((data / "keys.json").read_text())["keys"]["ops"]["revoked"] is True
    conn = sqlite3.connect(data / "detections.db")
    assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 2
    assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    conn.close()
    assert tool.ok("verify-carry", *common)["carry_ok"] is True
    tool.ok("unmark", *common)
    tool.ok("unswap", *common, "--rp", rid)
    assert sorted(os.listdir(data)) == live
    tool.ok("discard-staging", *common)


def test_export_audit_writes_the_rows_after_the_head_tagged_with_the_rollback(tool, inst, host, tmp_path):
    rid, _ = make_point(tool, inst)
    data = host.volume(PROJECT + "_bridge_data")
    conn = sqlite3.connect(data / "detections.db")
    conn.execute("INSERT INTO audit_log (timestamp, action, target_id, hmac_chain) VALUES "
                 "('t', 'login', 'bob', 'h2')")
    conn.commit()
    conn.close()
    out = tmp_path / "discarded.jsonl"
    r = tool.ok("export-audit", "--project", PROJECT, "--image", IMAGE, "--after", "1",
                "--rb-id", "20261127T120000Z", "--out", out)
    lines = [json.loads(x) for x in out.read_text().splitlines()]
    assert [x["id"] for x in lines] == [2] and lines[0]["rb_id"] == "20261127T120000Z"
    assert r["sha256"] == hashlib.sha256(out.read_bytes()).hexdigest() and r["last_hmac"] == "h2"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_lc_clean_removes_this_installs_leftover_lifecycle_containers(tool, host, inst):
    host.update(containers=host.load()["containers"] + [
        {"id": "e1", "name": "sigrift-lc-%s-stage-abc123" % PROJECT, "project": "",
         "service": "", "state": "running", "image": "x",
         "labels": {"com.sigrift.lifecycle": "state-engine",
                    "com.sigrift.lifecycle.project": PROJECT}},
        {"id": "e2", "name": "old-1a-engine", "project": "", "service": "", "state": "running",
         "image": "x", "mounts": [PROJECT + "_bridge_data"],
         "labels": {"com.sigrift.lifecycle": "engine"}},
        {"id": "e3", "name": "someone-elses", "project": "", "service": "", "state": "running",
         "image": "x", "mounts": ["other_bridge_data"],
         "labels": {"com.sigrift.lifecycle": "engine"}}])
    r = tool.ok("lc-clean", "--project", PROJECT)
    assert sorted(r["removed_containers"]) == ["e1", "e2"]


# ── 11.6 the fake host itself ─────────────────────────────────────────────


def test_fake_host_reads_markers_lifecycle_premigration_and_records_from_the_volume_dirs(
        host, tmp_path):
    host.add_project(PROJECT, tmp_path)
    data, secrets = seed_volume(host, PROJECT, lambda d, s: None)
    (secrets / ".sigrift-restore-incomplete").symlink_to(tmp_path / "gone")
    P = data / ".sigrift-replaced-20261120T000000Z"
    P.mkdir()
    (P / ".sigrift-phase").write_text(json.dumps({"phase": "kept-done"}))
    (P / "f").write_bytes(b"12345")
    S = data / ".sigrift-restore-20261121T000000Z"
    S.mkdir()
    (S / ".sigrift-staged").write_text("{}")
    (data / "detections.db.pre-migration").write_bytes(b"x" * 7)
    (data / ".sigrift-install.json").write_text(json.dumps({"install_id": "abc"}))
    payload = b"".join(str(len(b)).encode() + b"\n" + b for b in (
        b"src", json.dumps({"op": "facts", "data_dir": "/app/src/sigrift/bridge/data"}).encode()))
    r = subprocess.run(["docker", "run", "--rm", "-i", "--entrypoint", "python3", "-v",
                        PROJECT + "_bridge_data:/app/src/sigrift/bridge/data", "-v",
                        PROJECT + "_bridge_secrets:/app/secrets:ro", "img", "-c", "boot"],
                       input=payload, capture_output=True, env=host.env())
    f = json.loads(r.stdout)
    assert f["restore_markers"] == ["bridge_secrets"] and f["markers"]["bridge_secrets"] == {
        "unparsed": True}
    assert f["lifecycle"]["replaced"] == [{"volume": "bridge_data", "id": "20261120T000000Z",
                                           "phase": "kept-done",
                                           "bytes": 5 + (P / ".sigrift-phase").stat().st_size}]
    assert f["lifecycle"]["staging"][0]["staged"] is True
    assert f["premigration"]["bytes"] == 7 and f["record"] == {"install_id": "abc"}


def test_quickstart_carries_the_state_blocks_and_calls_none(tool):
    """Quickstart's own code reaches the state tool only through the blocks'
    functions (Phase 2's wiring calls the parents, never lc_state_tool)."""
    qs = QUICKSTART.read_text()
    for name in ("state-tool", "state-engine", "restore", "archive-engine", "move"):
        body = shared_block(QUICKSTART, name)
        qs = qs.replace(body, "")
    assert "lc_state_tool" not in qs.replace(shared_block(QUICKSTART, "lifecycle-engine"), "")
