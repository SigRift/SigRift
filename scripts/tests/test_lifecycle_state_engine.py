"""The state engine (Phase 1b, state-engine block), in process.

The state-engine and lifecycle-engine sources of scripts/install-release.sh
are exec'd as one module, as the bootstrap does in the bridge image. Each op
runs on tmp directories standing in for the two volumes, its frames are
captured from ST_IO, and the crash and space cases patch RENAME, FSYNC,
SYNC, STATVFS and CLOCK. Standard library only: scripts/tests has neither
cryptography nor the bridge's code (phase1b-spec 11.1).
"""

from __future__ import annotations

import ast
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import struct
import tarfile
from pathlib import Path

import pytest

from lifecycle_fakes import ROOT, load_engine, seed_tree, state_engine_source

RB = "20261127T101500Z"
RP = "20261127T101400Z-v0.1.0-full"
DATA_EXCLUDES = ["backups", "exports", "detections.db.pre-migration",
                 "detections.db.pre-migration.*", "detections.db.failed-migration-*",
                 "detections.db-wal.failed-migration-*", "detections.db-shm.failed-migration-*",
                 "*.corrupt-*", "detections.db-shm"]
KEEP_BACK = ["backups", "exports", "*.failed-migration-*", "*.corrupt-*"]


class Vols:
    def __init__(self, ns, tmp: Path):
        self.ns = ns
        self.data = tmp / "data"
        self.secrets = tmp / "secrets"
        self.data.mkdir(exist_ok=True)
        self.secrets.mkdir(exist_ok=True)

    def root(self, vol):
        return self.data if vol == "bridge_data" else self.secrets

    def call(self, op, stdin=b"", **req):
        """(rc, reply, frames) of engine OP; exactly one terminal frame."""
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
        frames = parse_frames(out.getvalue())
        terminal = [f for f in frames if f[0] in (b"R", b"E")]
        assert len(terminal) == 1 and frames[-1] is terminal[0], [f[0] for f in frames]
        return rc, json.loads(terminal[0][1]), frames

    def ok(self, op, stdin=b"", **req):
        rc, reply, frames = self.call(op, stdin, **req)
        assert rc == 0, reply
        return reply

    def err(self, op, code, stdin=b"", **req):
        rc, reply, _ = self.call(op, stdin, **req)
        assert rc == 1 and reply["ok"] is False and reply["code"] == code, reply
        return reply

    def snapshot(self, vol, excludes=None):
        rc, r, frames = self.call("snapshot-volume", volume=vol,
                                  excludes=DATA_EXCLUDES if excludes is None else excludes)
        assert rc == 0, r
        arch = b"".join(p for k, p in frames if k == b"D")
        mem = b"".join(p for k, p in frames if k == b"M")
        return arch, mem, r

    def stage(self, vol, arch, mem, r, **extra):
        req = dict(volume=vol, rb_id=RB, restore_point=RP, archive_sha256=r["archive_sha256"],
                   archive_bytes=r["archive_bytes"], members_file_sha256=r["members_sha256"],
                   keep_back=KEEP_BACK if vol == "bridge_data" else [],
                   excludes=DATA_EXCLUDES if vol == "bridge_data" else [], reserve_bytes=0)
        req.update(extra)
        return self.call("stage", section(mem) + section(arch), **req)


def parse_frames(b: bytes):
    out, i = [], 0
    while i < len(b):
        kind, n = b[i:i + 1], struct.unpack(">Q", b[i + 1:i + 9])[0]
        out.append((kind, b[i + 9:i + 9 + n]))
        i += 9 + n
    assert i == len(b)
    return out


def section(data: bytes, step=1 << 20) -> bytes:
    out = b"".join(b"%d\n" % len(data[i:i + step]) + data[i:i + step]
                   for i in range(0, len(data), step))
    return out + b"0\n"


def tree(root: Path, skip=lambda n: n.startswith(".sigrift-")) -> dict:
    """path -> (type, mode, size or target, sha256, mtime_ns), lifecycle names skipped."""
    out = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if skip(rel.split("/")[0]):
            continue
        s = p.lstat()
        if stat.S_ISLNK(s.st_mode):
            out[rel] = ("l", None, os.readlink(p), None, s.st_mtime_ns)
        elif stat.S_ISDIR(s.st_mode):
            out[rel] = ("d", stat.S_IMODE(s.st_mode), None, None, s.st_mtime_ns)
        else:
            out[rel] = ("f", stat.S_IMODE(s.st_mode), s.st_size,
                        hashlib.sha256(p.read_bytes()).hexdigest(), s.st_mtime_ns)
    return out


def names(root: Path) -> list:
    return sorted(os.listdir(root))


@pytest.fixture(scope="module")
def engine_ns():
    return load_engine()


@pytest.fixture
def v(engine_ns, tmp_path, monkeypatch):
    ns = engine_ns
    for name in ("RENAME", "FSYNC", "SYNC", "STATVFS", "CLOCK", "SLEEP"):
        monkeypatch.setitem(ns, name, ns[name])
    monkeypatch.setitem(ns, "SLEEP", lambda s: None)
    monkeypatch.setitem(ns, "ST_IO", {})
    return Vols(ns, tmp_path)


@pytest.fixture
def seeded(v):
    seed_tree(v.data, v.secrets)
    return v


def staged_rollback(v, mutate=None):
    """Snapshot both volumes, stage them (after MUTATE changed the live
    tree), carry; -> the live tree before the mutation."""
    snaps = {vol: v.snapshot(vol) for vol in ("bridge_secrets", "bridge_data")}
    before = tree(v.data)
    if mutate:
        mutate(v)
    for vol, (arch, mem, r) in snaps.items():
        rc, reply, _ = v.stage(vol, arch, mem, r)
        assert rc == 0, reply
    v.ok("carry", rb_id=RB, no_carry=False, keep_current_master=True)
    return before, snaps


def swap_both(v, **extra):
    for vol in ("bridge_secrets", "bridge_data"):
        v.ok("swap", volume=vol, rb_id=RB, restore_point=RP, keep_back=KEEP_BACK, **extra)


# ── 1-2 frames and the stream protocol ────────────────────────────────


def test_frames_have_exactly_one_terminal_frame(seeded):
    for op, req in (("state", {}), ("mark", {"rb_id": RB}), ("unmark", {"rb_id": RB}),
                    ("discard-staging", {"volume": "bridge_data", "rb_id": RB})):
        rc, reply, frames = seeded.call(op, **req)
        assert rc == 0 and frames[-1][0] == b"R"
    rc, reply, frames = seeded.call("stage", b"", volume="bridge_data", rb_id="../x")
    assert rc == 1 and frames[-1][0] == b"E" and reply["code"] == "unsafe"


def test_member_lines_go_in_m_frames_and_the_reply_stays_small(v):
    for i in range(20):
        d = v.data / ("d%02d" % i)
        d.mkdir()
        for j in range(1000):
            os.close(os.open(d / ("f%04d" % j), os.O_CREAT | os.O_WRONLY, 0o600))
    rc, r, frames = v.call("snapshot-volume", volume="bridge_data", excludes=[])
    assert rc == 0 and r["members"] == 20020
    lines = b"".join(p for k, p in frames if k == b"M")
    assert hashlib.sha256(lines).hexdigest() == r["members_sha256"]
    assert lines.count(b"\n") == 20020
    assert all(len(p) <= 1 << 20 for k, p in frames)
    assert len(frames[-1][1]) < 4096  # the reply holds hashes and counts only


def test_upload_without_the_terminator_is_short_input(seeded):
    arch, mem, r = seeded.snapshot("bridge_data")
    full = section(mem) + section(arch)
    rc, reply, _ = seeded.call("stage", full[:-2], volume="bridge_data", rb_id=RB,
                               restore_point=RP, archive_sha256=r["archive_sha256"],
                               archive_bytes=r["archive_bytes"],
                               members_file_sha256=r["members_sha256"], keep_back=KEEP_BACK,
                               excludes=DATA_EXCLUDES, reserve_bytes=0)
    assert rc == 1 and reply["code"] == "short-input"
    assert not (seeded.data / (".sigrift-restore-" + RB)).exists()


# ── 3-7 snapshot-volume ───────────────────────────────────────────────


def test_snapshot_volume_is_gzip_pax_in_walk_order_with_member_hashes(v):
    (v.data / "a").mkdir()
    (v.data / "a" / "x").write_text("x")
    (v.data / "a.b").write_text("ab")
    (v.data / "a-b").write_text("a-b")
    arch, mem, r = v.snapshot("bridge_data", excludes=[])
    order = [json.loads(line)["p"] for line in mem.decode().splitlines()]
    assert order == ["a", "a/x", "a-b", "a.b"]
    assert arch[:2] == b"\x1f\x8b" and hashlib.sha256(arch).hexdigest() == r["archive_sha256"]
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(arch)), mode="r:") as tar:
        members = tar.getmembers()
        assert [m.name.rstrip("/") for m in members] == order
        assert tar.format == tarfile.PAX_FORMAT or all(m.pax_headers is not None for m in members)
    m = dict((json.loads(x)["p"], json.loads(x)) for x in mem.decode().splitlines())
    assert m["a.b"]["h"] == hashlib.sha256(b"ab").hexdigest() and m["a"]["t"] == "d"
    rc, reply, _ = v.stage("bridge_data", arch, mem, r, keep_back=[], excludes=[])
    assert rc == 0 and reply["members"] == 4


def test_snapshot_excludes_backups_forensic_premigration_shm_and_lifecycle_entries(seeded):
    d = seeded.data
    for name in ("detections.db.pre-migration", "detections.db.pre-migration.tmp1",
                 "detections.db.failed-migration-1", "keys.json.corrupt-2", "detections.db-shm",
                 ".sigrift-restore-incomplete", ".sigrift-install.json"):
        (d / name).write_text(name)
    (d / "exports").mkdir()
    (d / (".sigrift-replaced-" + RB)).mkdir()
    (d / (".sigrift-restore-" + RB)).mkdir()
    (d / "ca" / "registry.json.corrupt-3").write_text("x")
    _, mem, _ = seeded.snapshot("bridge_data")
    tops = set(json.loads(x)["p"].split("/")[0] for x in mem.decode().splitlines())
    assert tops == {".sigrift-install.json", "alerts.json", "ca", "detections.db", "iq_captures",
                    "keys.json", "pcap_captures", "webhooks.json"}
    assert "ca/registry.json.corrupt-3" in mem.decode()  # forensic copies below the root stay


def test_exclude_iq_pcap_leaves_captures_out_and_keeps_them_back(seeded):
    ex = DATA_EXCLUDES + ["iq_captures", "pcap_captures"]
    kb = KEEP_BACK + ["iq_captures", "pcap_captures"]
    arch, mem, r = seeded.snapshot("bridge_data", excludes=ex)
    assert "iq_captures" not in mem.decode()
    a2, m2, r2 = seeded.snapshot("bridge_secrets", excludes=[])
    (seeded.data / "iq_captures" / "c2.iq.gz").write_bytes(b"later")
    assert seeded.stage("bridge_secrets", a2, m2, r2)[0] == 0
    assert seeded.stage("bridge_data", arch, mem, r, keep_back=kb, excludes=ex)[0] == 0
    seeded.ok("carry", rb_id=RB, no_carry=False)
    for vol in ("bridge_secrets", "bridge_data"):
        seeded.ok("swap", volume=vol, rb_id=RB, restore_point=RP, keep_back=kb,
                  captures_excluded=True, pcap_after=5)
    assert names(seeded.data / "iq_captures") == ["c1.iq.gz", "c2.iq.gz"]


def test_snapshot_fails_when_a_file_changes_while_it_is_read(seeded, monkeypatch):
    cls = seeded.ns["StHashReader"]
    orig = cls.read

    def read(self, n=-1):
        b = orig(self, n)
        if b and self.left == 0 and not getattr(cls, "_done", False):
            # Something writes the file being archived (its mtime moves).
            cls._done = True
            os.utime(self.f.fileno(), ns=(1, 1))
        return b
    monkeypatch.setattr(cls, "read", read)
    monkeypatch.setattr(cls, "_done", False, raising=False)
    rc, reply, _ = seeded.call("snapshot-volume", volume="bridge_data", excludes=DATA_EXCLUDES)
    assert rc == 1 and reply["code"] == "changed" and "still writes" in reply["error"]


def test_snapshot_skips_sockets_refuses_fifos_and_stores_hard_links_as_files(v, monkeypatch):
    (v.data / "a").write_text("same inode")
    os.link(v.data / "a", v.data / "b")
    monkeypatch.chdir(v.data)
    sock = socket.socket(socket.AF_UNIX)
    sock.bind("s.sock")
    try:
        arch, mem, r = v.snapshot("bridge_data", excludes=[])
        assert r["skipped"] == ["s.sock"]
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(arch)), mode="r:") as tar:
            assert [(m.name, m.isreg()) for m in tar.getmembers()] == [("a", True), ("b", True)]
    finally:
        sock.close()
    os.mkfifo(v.data / "f")
    v.err("snapshot-volume", "unsafe", volume="bridge_data", excludes=[])


# ── 8-12 stage ────────────────────────────────────────────────────────


def test_stage_restores_bytes_modes_mtimes_symlinks_and_empty_dirs_exactly(v):
    d = v.data
    (d / "keys.json").write_text("live keys, never touched through a link")
    (d / "sub").mkdir()
    (d / "sub" / "f").write_bytes(os.urandom(3000))
    (d / "sub" / "f").chmod(0o640)
    (d / "empty").mkdir()
    (d / "sticky").mkdir()
    (d / "sticky").chmod(0o1777)
    (d / "suid").write_text("x")
    (d / "suid").chmod(0o4755)
    (d / "sub" / "escape").symlink_to("../keys.json")
    (d / "dangling").symlink_to("nowhere/at/all")
    for i, p in enumerate(("sub/f", "suid", "empty", "sticky", "sub")):
        os.utime(d / p, ns=(1_700_000_000_123_456_789 + i, 1_700_000_000_123_456_789 + i))
    os.utime(d / "sub" / "escape", ns=(1_600_000_000_000_000_001,) * 2, follow_symlinks=False)
    want = tree(d)
    keys_before = (d / "keys.json").stat()
    arch, mem, r = v.snapshot("bridge_data", excludes=[])
    rc, reply, _ = v.stage("bridge_data", arch, mem, r, keep_back=[], excludes=[])
    assert rc == 0, reply
    got = tree(d / (".sigrift-restore-" + RB), skip=lambda n: n.startswith(".sigrift-"))
    for p, w in want.items():
        g = got[p]
        if w[0] == "d" and w[1] & 0o7000:
            w = (w[0], w[1] & 0o777) + w[2:]
        if w[0] == "f" and w[1] & 0o7000:
            w = (w[0], w[1] & 0o777) + w[2:]
        if w[0] == "l":
            g, w = g[:3] + (g[4],), w[:3] + (w[4],)
        assert g == w, p
    assert (d / "keys.json").stat().st_mtime_ns == keys_before.st_mtime_ns


def craft(members):
    """(archive, members file) for crafted members: (TarInfo kwargs, data, line)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for kw, data, _ in members:
            ti = tarfile.TarInfo(kw.pop("name"))
            for k, val in kw.items():
                setattr(ti, k, val)
            if data is not None:
                ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data) if data is not None else None)
    arch = gzip.compress(raw.getvalue(), compresslevel=1, mtime=0)
    mem = b"".join((json.dumps(line, sort_keys=True, separators=(",", ":")) + "\n").encode()
                   for _, _, line in members)
    return arch, mem


def fline(p, data, m="0600"):
    return {"p": p, "t": "f", "m": m, "s": len(data), "h": hashlib.sha256(data).hexdigest(),
            "mt": 1}


BAD_MEMBERS = {
    "absolute": [({"name": "/etc/x", "mode": 0o600}, b"x", fline("/etc/x", b"x"))],
    "dotdot": [({"name": "../x", "mode": 0o600}, b"x", fline("../x", b"x"))],
    "hardlink": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"x")),
                 ({"name": "b", "mode": 0o600, "type": tarfile.LNKTYPE, "linkname": "a"}, None,
                  fline("b", b""))],
    "device": [({"name": "dev", "mode": 0o600, "type": tarfile.CHRTYPE}, None, fline("dev", b""))],
    "duplicate": [({"name": "a", "mode": 0o600}, b"x", fline("a", b"x")),
                  ({"name": "a", "mode": 0o600}, b"x", fline("a", b"x"))],
    "reordered": [({"name": "b", "mode": 0o600}, b"x", fline("a", b"x")),
                  ({"name": "a", "mode": 0o600}, b"x", fline("b", b"x"))],
    "extra": [({"name": "a", "mode": 0o600}, b"x", None)],
    "lifecycle": [({"name": ".sigrift-restore-incomplete", "mode": 0o600}, b"x",
                   fline(".sigrift-restore-incomplete", b"x"))],
    "keepback": [({"name": "backups", "mode": 0o700, "type": tarfile.DIRTYPE}, None,
                  {"p": "backups", "t": "d", "m": "0700", "mt": 1})],
    "under-a-link": [({"name": "l", "mode": 0o777, "type": tarfile.SYMTYPE, "linkname": "/tmp"},
                      None, {"p": "l", "t": "l", "m": "0777", "mt": 1, "l": "/tmp"}),
                     ({"name": "l/x", "mode": 0o600}, b"x", fline("l/x", b"x"))],
}


@pytest.mark.parametrize("case", sorted(BAD_MEMBERS))
def test_stage_refuses_absolute_dotdot_hardlink_device_duplicate_reordered_extra_lifecycle_and_keepback_members(v, case):
    members = [(dict(kw), data, line) for kw, data, line in BAD_MEMBERS[case]]
    lines = [m for m in members if m[2] is not None]
    arch, _ = craft(members)
    mem = b"".join((json.dumps(m[2], sort_keys=True, separators=(",", ":")) + "\n").encode()
                   for m in lines)
    rc, reply, _ = v.stage("bridge_data", arch, mem,
                           {"archive_sha256": hashlib.sha256(arch).hexdigest(),
                            "archive_bytes": len(arch),
                            "members_sha256": hashlib.sha256(mem).hexdigest()})
    assert rc == 1 and reply["code"] in ("unsafe", "integrity"), reply
    assert not (v.data / (".sigrift-restore-" + RB)).exists()
    assert not Path("/tmp/x").exists() or Path("/tmp/x").read_bytes() != b"x"


def test_stage_refuses_a_members_section_with_another_sha256(seeded):
    arch, mem, r = seeded.snapshot("bridge_data")
    rc, reply, _ = seeded.stage("bridge_data", arch, mem + b"\n", r)
    assert rc == 1 and reply["code"] == "integrity"


@pytest.mark.parametrize("what", ["member", "stream"])
def test_stage_refuses_a_member_or_stream_hash_mismatch_and_leaves_no_staging(seeded, what):
    arch, mem, r = seeded.snapshot("bridge_data")
    if what == "member":
        lines = [json.loads(x) for x in mem.decode().splitlines()]
        for m in lines:
            if m["p"] == "keys.json":
                m["h"] = "0" * 64
        mem = b"".join((json.dumps(m, sort_keys=True, separators=(",", ":")) + "\n").encode()
                       for m in lines)
        r = dict(r, members_sha256=hashlib.sha256(mem).hexdigest())
    else:
        r = dict(r, archive_sha256="0" * 64)
    rc, reply, _ = seeded.stage("bridge_data", arch, mem, r)
    assert rc == 1 and reply["code"] == "integrity"
    assert not (seeded.data / (".sigrift-restore-" + RB)).exists()


def test_stage_after_a_crash_discards_the_partial_staging(seeded):
    arch, mem, r = seeded.snapshot("bridge_data")
    s = seeded.data / (".sigrift-restore-" + RB)
    s.mkdir()
    (s / "half-written").write_text("left by a killed stage")
    rc, reply, _ = seeded.stage("bridge_data", arch, mem, r)
    assert rc == 0 and not (s / "half-written").exists() and (s / ".sigrift-staged").exists()


def test_complete_staging_is_skipped(seeded):
    arch, mem, r = seeded.snapshot("bridge_data")
    assert seeded.stage("bridge_data", arch, mem, r)[0] == 0
    marker = (seeded.data / (".sigrift-restore-" + RB) / ".sigrift-staged").stat().st_mtime_ns
    rc, reply, _ = seeded.call("stage", b"", volume="bridge_data", rb_id=RB, restore_point=RP,
                               members_file_sha256=r["members_sha256"])
    assert rc == 0 and reply["already"] is True
    assert (seeded.data / (".sigrift-restore-" + RB) / ".sigrift-staged").stat().st_mtime_ns == marker


def test_stage_stops_at_the_reserve(seeded, monkeypatch):
    arch, mem, r = seeded.snapshot("bridge_data")
    real = os.statvfs

    def low(path):
        s = real(path)
        return os.statvfs_result((s.f_bsize, s.f_frsize, s.f_blocks, 1, 1, s.f_files, s.f_ffree,
                                  s.f_favail, s.f_flag, s.f_namemax))
    monkeypatch.setitem(seeded.ns, "STATVFS", low)
    rc, reply, _ = seeded.stage("bridge_data", arch, mem, r, reserve_bytes=1 << 30)
    assert rc == 1 and reply["code"] == "no-space"
    assert not (seeded.data / (".sigrift-restore-" + RB)).exists()


# ── 13-17 swap, unswap ────────────────────────────────────────────────


def test_swap_moves_live_out_staged_in_keep_back_back_and_never_the_premigration_copy_or_shm(seeded):
    def mutate(v):
        (v.data / "detections.db.pre-migration").write_text("copy")
        (v.data / "detections.db-shm").write_text("shm")
        (v.data / "keys.json.corrupt-9").write_text("forensic")
        (v.data / "new-since").write_text("discarded")
        (v.data / "backups" / "b2.tar.gz").write_text("kept")
    before, _ = staged_rollback(seeded, mutate)
    swap_both(seeded)
    P = seeded.data / (".sigrift-replaced-" + RB)
    live = tree(seeded.data)
    assert set(live) - set(before) == {"keys.json.corrupt-9", "backups/b2.tar.gz"}
    assert (P / "detections.db.pre-migration").exists() and (P / "detections.db-shm").exists()
    assert (P / "new-since").exists() and not (seeded.data / "new-since").exists()
    assert json.loads((P / ".sigrift-phase").read_text())["phase"] == "done"
    assert not (seeded.data / (".sigrift-restore-" + RB)).exists()


def test_swap_refuses_an_undo_phase(seeded):
    staged_rollback(seeded)
    P = seeded.data / (".sigrift-replaced-" + RB)
    P.mkdir()
    (P / ".sigrift-phase").write_text(json.dumps({"format": 1, "phase": "undo-in"}))
    seeded.err("swap", "phase", volume="bridge_data", rb_id=RB, keep_back=KEEP_BACK)


class Crash(Exception):
    pass


def crash_after(ns, monkeypatch, k):
    real = ns["RENAME"]
    count = {"n": 0}

    def rename(a, b):
        count["n"] += 1
        if count["n"] > k:
            raise Crash("killed after %d renames" % k)
        return real(a, b)
    monkeypatch.setitem(ns, "RENAME", rename)
    return lambda: monkeypatch.setitem(ns, "RENAME", real)


def run_until(v, op, monkeypatch, k, **req):
    restore = crash_after(v.ns, monkeypatch, k)
    rc, reply, _ = v.call(op, **req)
    restore()
    return rc, reply


def test_swap_converges_after_a_crash_at_every_rename(seeded, tmp_path, monkeypatch):
    import shutil
    staged_rollback(seeded)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP, keep_back=KEEP_BACK)
    base = tmp_path / "base"
    shutil.copytree(seeded.data, base, symlinks=True)
    counter = {"n": 0}
    real = seeded.ns["RENAME"]

    def counting(a, b):
        counter["n"] += 1
        return real(a, b)
    monkeypatch.setitem(seeded.ns, "RENAME", counting)
    seeded.ok("swap", **req)
    monkeypatch.setitem(seeded.ns, "RENAME", real)
    want = tree(seeded.data)
    assert counter["n"] > 10
    for k in range(counter["n"]):
        shutil.rmtree(seeded.data)
        shutil.copytree(base, seeded.data, symlinks=True)
        rc, _ = run_until(seeded, "swap", monkeypatch, k, **req)
        assert rc == 1
        seeded.ok("swap", **req)
        assert tree(seeded.data) == want, k


def phase_of(v, vol="bridge_data"):
    p = v.root(vol) / (".sigrift-replaced-" + RB) / ".sigrift-phase"
    return json.loads(p.read_text())["phase"] if p.exists() else None


@pytest.mark.parametrize("stop", ["out", "out-done", "in-done", "kept-done", "done"])
def test_unswap_from_every_phase_restores_the_live_tree_exactly(seeded, monkeypatch, stop):
    staged_rollback(seeded)
    live = tree(seeded.data)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP, keep_back=KEEP_BACK)
    # Stop the swap right after it recorded STOP (one more rename would follow).
    real = seeded.ns["st_set_phase"]

    def set_phase(P, r, vol, phase, info=None):
        out = real(P, r, vol, phase, info)
        if phase == stop and stop != "done":
            raise Crash("killed at " + phase)
        return out
    monkeypatch.setitem(seeded.ns, "st_set_phase", set_phase)
    seeded.call("swap", **req)
    monkeypatch.setitem(seeded.ns, "st_set_phase", real)
    assert phase_of(seeded) == stop
    seeded.ok("unswap", **req)
    assert tree(seeded.data) == live
    assert not any(n.startswith(".sigrift-") for n in names(seeded.data))


def test_unswap_after_a_partial_move_out_never_discards_a_live_entry(seeded, monkeypatch):
    staged_rollback(seeded)
    live = tree(seeded.data)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP, keep_back=KEEP_BACK)
    rc, _ = run_until(seeded, "swap", monkeypatch, 3, **req)
    assert rc == 1 and phase_of(seeded) == "out"
    seeded.ok("unswap", **req)
    assert tree(seeded.data) == live


def test_lifecycle_entries_are_never_moved_or_archived(seeded):
    other = seeded.data / ".sigrift-replaced-20261101T000000Z"
    other.mkdir()
    (other / ".sigrift-phase").write_text(json.dumps({"phase": "done"}))
    (seeded.data / ".sigrift-replaced-20261102T000000Z").mkdir()
    _, mem, _ = seeded.snapshot("bridge_data")
    assert b".sigrift-replaced" not in mem
    staged_rollback(seeded)
    seeded.ok("mark", rb_id=RB, restore_point=RP)
    swap_both(seeded)
    assert other.is_dir() and (seeded.data / ".sigrift-replaced-20261102T000000Z").is_dir()
    assert (seeded.data / ".sigrift-restore-incomplete").exists()
    assert not (seeded.data / (".sigrift-replaced-" + RB) / ".sigrift-restore-incomplete").exists()


def test_carry_adds_nothing_but_its_marker_to_the_staging_root(seeded):
    rp_names = set(names(seeded.data)) - {"backups"}
    staged_rollback(seeded, lambda v: (v.data / "keys.json").write_text(json.dumps(
        {"keys": {"master": {"hash": "m-hash", "salt": "m-salt", "role": "admin"}}})))
    S = seeded.data / (".sigrift-restore-" + RB)
    assert set(names(S)) == rp_names | {".sigrift-staged", ".sigrift-carried"}
    swap_both(seeded)
    assert set(n for n in names(seeded.data) if not n.startswith(".sigrift-")) == \
        (rp_names | {"backups"}) - {".sigrift-install.json"}
    assert not list(seeded.data.rglob("carry.json"))


# ── 18-21 mark, finish, reclaim, pcap ───────────────────────────────────


def test_mark_and_unmark_both_volumes_in_order_and_idempotent(seeded, monkeypatch):
    order = []
    real = seeded.ns["st_atomic_json"]

    def spy(path, obj, mode=0o600):
        order.append(str(path))
        return real(path, obj, mode)
    monkeypatch.setitem(seeded.ns, "st_atomic_json", spy)
    r = seeded.ok("mark", rb_id=RB, restore_point=RP)
    assert r["written"] == ["bridge_secrets", "bridge_data"]
    assert order[0].startswith(str(seeded.secrets)) and order[1].startswith(str(seeded.data))
    assert seeded.ok("mark", rb_id=RB, restore_point=RP)["written"] == []
    info = json.loads((seeded.data / ".sigrift-restore-incomplete").read_text())
    assert info == {"format": 1, "op": "rollback", "id": RB, "restore_point": RP,
                    "created_at": info["created_at"]}
    assert seeded.ok("unmark", rb_id=RB)["removed"] == ["bridge_secrets", "bridge_data"]
    assert seeded.ok("unmark", rb_id=RB)["removed"] == []


def test_mark_refuses_another_restores_marker(seeded):
    (seeded.secrets / ".sigrift-restore-incomplete").write_text(json.dumps({"id": "20261101T000000Z"}))
    seeded.err("mark", "phase", rb_id=RB, restore_point=RP)
    assert not (seeded.data / ".sigrift-restore-incomplete").exists()


def test_finish_removes_only_done_replaced_copies_with_a_valid_id(seeded):
    for rid, phase in (("20261101T000000Z", "done"), ("20261102T000000Z", "in-done")):
        P = seeded.data / (".sigrift-replaced-" + rid)
        (P / "x").mkdir(parents=True)
        (P / "x" / "f").write_text("old data")
        (P / ".sigrift-phase").write_text(json.dumps({"phase": phase}))
    r = seeded.ok("finish", volume="bridge_data", ids=["20261101T000000Z"])
    assert r["removed"] == ["20261101T000000Z"] and r["freed_bytes"] > 0
    seeded.err("finish", "phase", volume="bridge_data", ids=["20261102T000000Z"])
    seeded.err("finish", "unsafe", volume="bridge_data", ids=["../../etc"])
    assert (seeded.data / ".sigrift-replaced-20261102T000000Z").is_dir()


def test_reclaim_removes_only_the_measured_premigration_copy(seeded):
    p = seeded.data / "detections.db.pre-migration"
    p.write_bytes(b"x" * 100)
    s = p.stat()
    r = seeded.ok("reclaim", name=p.name, bytes=s.st_size, mtime_ns=s.st_mtime_ns + 1)
    assert r["removed"] is False and p.exists()
    seeded.err("reclaim", "unsafe", name="detections.db", bytes=1, mtime_ns=1)
    r = seeded.ok("reclaim", name=p.name, bytes=s.st_size, mtime_ns=s.st_mtime_ns)
    assert r["removed"] is True and not p.exists()


def set_anomalies(v, sql):
    conn = sqlite3.connect(v.data / "detections.db")
    conn.executescript(sql)
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


@pytest.mark.parametrize("history", ["rows", "never", "deleted"])
def test_pcap_files_of_anomalies_newer_than_the_restore_point_go_to_the_replaced_copy_and_come_back_on_unswap(seeded, history):
    if history == "never":
        set_anomalies(seeded, "DELETE FROM wifi_anomalies; DELETE FROM sqlite_sequence;")
    elif history == "deleted":
        set_anomalies(seeded, "INSERT INTO wifi_anomalies (bssid, timestamp) VALUES ('x', 't');"
                              "DELETE FROM wifi_anomalies;")
    after = seeded.ok("state")["captures"]["pcap_after"]
    assert after == {"rows": 1, "never": 0, "deleted": 2}[history]
    ex = DATA_EXCLUDES + ["iq_captures", "pcap_captures"]
    kb = KEEP_BACK + ["iq_captures", "pcap_captures"]
    snaps = {vol: seeded.snapshot(vol, excludes=ex if vol == "bridge_data" else [])
             for vol in ("bridge_secrets", "bridge_data")}
    for n in (2, 3):
        (seeded.data / "pcap_captures" / ("%d.pcap.gz" % n)).write_text("anomaly %d" % n)
    live = tree(seeded.data)
    for vol, (arch, mem, r) in snaps.items():
        assert seeded.stage(vol, arch, mem, r, keep_back=kb if vol == "bridge_data" else [],
                            excludes=ex if vol == "bridge_data" else [])[0] == 0
    seeded.ok("carry", rb_id=RB)
    for vol in ("bridge_secrets", "bridge_data"):
        seeded.ok("swap", volume=vol, rb_id=RB, restore_point=RP, keep_back=kb,
                  captures_excluded=True, pcap_after=after)
    kept = names(seeded.data / "pcap_captures")
    moved = names(seeded.data / (".sigrift-replaced-" + RB) / ".sigrift-pcap-after-rp")
    assert sorted(kept + moved) == ["1.pcap.gz", "2.pcap.gz", "3.pcap.gz"]
    assert all(int(n.split(".")[0]) > after for n in moved)
    assert all(int(n.split(".")[0]) <= after for n in kept)
    # The restored bridge hands out the ids above pcap_after again: its
    # captures for them belong to rows the undo discards (E19, undone).
    (seeded.data / "pcap_captures" / "9.pcap.gz").write_text("restored bridge, anomaly 9")
    for vol in ("bridge_data", "bridge_secrets"):
        seeded.ok("unswap", volume=vol, rb_id=RB, restore_point=RP, keep_back=kb,
                  captures_excluded=True, pcap_after=after)
    assert tree(seeded.data) == live


def test_an_undo_of_a_swap_stopped_inside_the_pcap_set_aside_keeps_every_original(
        seeded, monkeypatch):
    after = seeded.ok("state")["captures"]["pcap_after"]
    ex = DATA_EXCLUDES + ["iq_captures", "pcap_captures"]
    kb = KEEP_BACK + ["iq_captures", "pcap_captures"]
    snaps = {vol: seeded.snapshot(vol, excludes=ex if vol == "bridge_data" else [])
             for vol in ("bridge_secrets", "bridge_data")}
    for n in (2, 3):
        (seeded.data / "pcap_captures" / ("%d.pcap.gz" % n)).write_text("anomaly %d" % n)
    live = tree(seeded.data)
    for vol, (arch, mem, r) in snaps.items():
        assert seeded.stage(vol, arch, mem, r, keep_back=kb if vol == "bridge_data" else [],
                            excludes=ex if vol == "bridge_data" else [])[0] == 0
    seeded.ok("carry", rb_id=RB)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP, keep_back=kb,
               captures_excluded=True, pcap_after=after)
    real = seeded.ns["RENAME"]

    def rename(a, b):
        real(a, b)
        if ".sigrift-pcap-after-rp" in str(b):
            raise Crash("killed after the first file set aside")
    monkeypatch.setitem(seeded.ns, "RENAME", rename)
    assert seeded.call("swap", **req)[0] == 1
    monkeypatch.setitem(seeded.ns, "RENAME", real)
    assert phase_of(seeded) == "in-done"  # one original above pcap_after is still live
    seeded.ok("unswap", **req)
    assert tree(seeded.data) == live


# ── 22-28 encoding, digests, table classes, compare ──────────────────────


def test_canon_value_vectors(engine_ns):
    canon = engine_ns["st_canon"]
    assert canon(None) == "n" and canon(7) == "i7" and canon(-1) == "i-1"
    assert canon(0.1) == "f0x1.999999999999ap-4" and canon(1.0) == "f0x1.0000000000000p+0"
    assert canon("é\x1f") == 's"\\u00e9\\u001f"'
    assert canon(b"\x00\xff") == "b00ff"
    assert engine_ns["st_canon_row"]((1, None, "a")) == 'i1\x1fn\x1fs"a"\n'


def rf_db(path, rows=True):
    conn = sqlite3.connect(path)
    conn.executescript(re.search(r"CREATE TABLE rf_summary_streams.*?;\n(?=INSERT)",
                                 __import__("lifecycle_fakes").SEED_SQL, re.S).group(0))
    if rows:
        conn.executescript(
            "INSERT INTO rf_summary_streams VALUES ('default', 'n1', 's1');"
            "INSERT INTO rf_summary_generations VALUES ('default', 'n1', 's1', "
            "'2026-11-27T10:00:00Z', 1, 'd1', X'7b7d', 0);"
            "INSERT INTO rf_summary_components VALUES ('default', 'n1', 's1', 'stream_summary', "
            "'2026-11-27T10:00:00Z', 'fm', '', 1e8, 3, '{}');")
    conn.commit()
    return conn


def rf_digest(ns, conn):
    block, streams, fences = ns["st_rf"](conn, ns["st_tables"](conn))
    return block, streams, fences


def test_rf_digest_vectors(engine_ns, tmp_path):
    conn = sqlite3.connect(tmp_path / "empty.db")
    block, _, _ = rf_digest(engine_ns, conn)
    want = hashlib.sha256(b"Arf_summary_streams\nArf_summary_generations\n"
                          b"Arf_summary_components\n").hexdigest()
    assert block == {"tables": False, "rows": {"streams": 0, "generations": 0, "components": 0},
                     "digest": "sha256:" + want}
    conn = rf_db(tmp_path / "rf.db")
    block, streams, fences = rf_digest(engine_ns, conn)
    h = hashlib.sha256()
    h.update(b"Trf_summary_streams\n" + b'sdefault"\x1fs"n1"\x1fs"s1"\n'.replace(b'sdefault"', b's"default"'))
    h.update(b"Trf_summary_generations\n" + 's"default"\x1fs"n1"\x1fs"s1"\x1fs"2026-11-27T10:00:00Z"'
             '\x1fi1\x1fs"d1"\x1fb7b7d\x1fi0\n'.encode())
    h.update(b"Trf_summary_components\n" + 's"default"\x1fs"n1"\x1fs"s1"\x1fs"stream_summary"\x1f'
             's"2026-11-27T10:00:00Z"\x1fs"fm"\x1fs""\x1ff0x1.7d78400000000p+26\x1fi3\x1fs"{}"\n'
             .encode())
    assert block["digest"] == "sha256:" + h.hexdigest() and block["tables"] is True
    assert len(streams) == 1 and len(fences[0]) == 32


@pytest.mark.parametrize("change", [
    "INSERT INTO rf_summary_generations VALUES ('default', 'n1', 's1', '2026-11-27T11:00:00Z', 1, 'd2', X'00', 0)",
    "UPDATE rf_summary_generations SET generation = 2",
    "UPDATE rf_summary_generations SET retired = 1, payload = '{}'",
    "DELETE FROM rf_summary_components"])
def test_rf_digest_changes_on_a_new_hour_a_new_generation_a_retired_flip_and_a_retention_delete(engine_ns, tmp_path, change):
    conn = rf_db(tmp_path / "rf.db")
    before = rf_digest(engine_ns, conn)[0]["digest"]
    conn.execute(change)
    assert rf_digest(engine_ns, conn)[0]["digest"] != before


def state_rows(v):
    rc, reply, frames = v.call("state", rf_rows=True)
    assert rc == 0
    rows = {"streams": [], "fences": [], "summary_hours": {}}
    for line in b"".join(p for k, p in frames if k == b"M").decode().splitlines():
        o = json.loads(line)
        if "s" in o:
            rows["streams"].append(o["s"])
        elif "f" in o:
            rows["fences"].append(o["f"])
        elif "h" in o:
            rows["summary_hours"][o["h"]] = o["v"]
    return reply, json.dumps(rows).encode()


def test_rf_check_passes_after_retention_and_fails_on_a_missing_fence(seeded):
    conn = sqlite3.connect(seeded.data / "detections.db")
    conn.executescript(
        "INSERT INTO rf_summary_streams VALUES ('default', 'n1', 's1');"
        "INSERT INTO rf_summary_generations VALUES ('default', 'n1', 's1', '2026-11-27T10:00:00Z',"
        " 1, 'd1', X'7b7d', 0);"
        "INSERT INTO rf_summary_components VALUES ('default', 'n1', 's1', 'stream_summary', "
        "'2026-11-27T10:00:00Z', 'fm', '', 1e8, 3, '{}');")
    conn.commit()
    _, rows = state_rows(seeded)
    conn.executescript("DELETE FROM rf_summary_components; UPDATE rf_summary_generations "
                       "SET retired = 1, payload = '{}';")
    conn.commit()
    assert seeded.ok("rf-check", section(rows))["missing"] == 0
    conn.execute("DELETE FROM rf_summary_generations")
    conn.commit()
    conn.close()
    assert seeded.ok("rf-check", section(rows))["fences_missing"] == 1


def test_table_classes_count_every_rowid_table_except_volatile_and_derived(seeded):
    conn = sqlite3.connect(seeded.data / "detections.db")
    conn.executescript("CREATE TABLE decoded_messages (id INTEGER PRIMARY KEY, m TEXT);"
                       "INSERT INTO decoded_messages VALUES (41, 'x');"
                       "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID;"
                       "INSERT INTO kv VALUES ('a', 'b'), ('c', 'd');")
    conn.commit()
    conn.close()
    marks = seeded.ok("state")["marks"]
    t = marks["tables"]
    assert t["decoded_messages"] == 41 and t["detections"] == 2 and t["kv"] == 2
    assert marks["without_rowid"] == ["kv"]
    for name in ("sessions", "mfa_tokens", "oidc_states", "schema_version", "detection_aggregates",
                 "detection_summaries_hourly", "rf_summary_streams", "sqlite_sequence"):
        assert name not in t
    assert "detection_aggregates" in marks["derived_skipped"]
    assert {"sessions", "schema_version"} <= set(marks["volatile_skipped"])
    assert "pending_commands" in marks["queue"] and "pending_commands" in t


def baseline(v):
    """(compare request, rf_rows section) for the state right now."""
    reply, rows = state_rows(v)
    rp = dict((k, reply[k]) for k in ("marks", "security", "captures", "counts", "db"))
    rp.update(rf_summary=reply["rf"], audit={"head_id": reply["audit"]["head_id"]},
              created_at="2026-11-27T10:30:00Z")
    return {"rp": rp, "rf_rows_section": True}, rows


def compare(v, base):
    req, rows = base
    return v.ok("compare", section(rows), **req)


def sql(v, text):
    conn = sqlite3.connect(v.data / "detections.db")
    conn.executescript(text)
    conn.commit()
    conn.close()


def test_compare_finds_new_rows_in_any_counted_table_and_non_empty_new_tables(seeded):
    base = baseline(seeded)
    assert compare(seeded, base)["nothing_new"] is True
    sql(seeded, "INSERT INTO detections VALUES ('d3', '2026-11-27T11:00:00Z', 'pi-1', 'fm', '', "
                "1, 1, 1, 1, 1, 'default');"
                "INSERT INTO audit_log (timestamp, action, target_id) VALUES ('t', 'a', 'b');"
                "CREATE TABLE packet_detections (id INTEGER PRIMARY KEY, x TEXT);"
                "INSERT INTO packet_detections (x) VALUES ('p');"
                "CREATE TABLE still_empty (id INTEGER PRIMARY KEY);")
    r = compare(seeded, base)
    assert r["checkable"] is True and r["nothing_new"] is False
    assert r["discards"]["rows"] == {"detections": 1, "audit_log": 1}
    assert r["discards"]["new_tables"] == {"packet_detections": 1}


def test_compare_ignores_volatile_and_derived_tables(seeded):
    base = baseline(seeded)
    sql(seeded, "INSERT INTO sessions (session_token, user_id, created_at, expires_at) VALUES "
                "('tok-2', 1, 'a', 'b'); INSERT OR REPLACE INTO detection_aggregates (bucket, n) "
                "VALUES ('b1', 1); INSERT INTO oidc_states VALUES ('s', 't');")
    assert compare(seeded, base)["nothing_new"] is True


@pytest.mark.parametrize("case", ["missing-table", "keys", "encrypted", "state-file"])
def test_compare_is_not_checkable_on_a_missing_table_unreadable_keys_or_an_encrypted_db(seeded, case):
    base = baseline(seeded)
    if case == "missing-table":
        sql(seeded, "DROP TABLE nodes")
    elif case == "keys":
        (seeded.data / "keys.json").write_text("{not json")
    elif case == "encrypted":
        (seeded.data / "detections.db").write_bytes(b"\x8f" * 4096)
    else:
        (seeded.data / "alerts.json").write_text("{broken")
    r = compare(seeded, base)
    assert r["checkable"] is False and r["nothing_new"] is False and r["why_not_checkable"]


IN_PLACE = {
    "heartbeat": ("UPDATE nodes SET last_seen = '2026-11-27T12:00:00Z'", "nodes"),
    "registration": ("INSERT OR REPLACE INTO nodes VALUES ('pi-1', '2026-11-27T12:00:01Z', "
                     "'default')", "nodes"),
    "dispatch": ("UPDATE pending_commands SET dispatched_at = '2026-11-27T12:00:00Z'",
                 "pending_commands_dispatched"),
    "iq-stub": ("UPDATE detections SET signal_class = 'fm' WHERE detection_id = 'd2'",
                "iq_stubs_completed"),
    "updated_at": ("UPDATE tenant_settings SET updated_at = '2026-11-27T12:00:00Z'",
                   "tenant_settings"),
}


@pytest.mark.parametrize("case", sorted(IN_PLACE))
def test_compare_sees_rows_changed_in_place(seeded, case):
    base = baseline(seeded)
    stmt, key = IN_PLACE[case]
    sql(seeded, stmt)
    r = compare(seeded, base)
    assert r["nothing_new"] is False and r["discards"]["updated"][key] >= 1, r["discards"]


def test_compare_sees_direct_summary_ingest_and_counts_changed_hours(seeded):
    base = baseline(seeded)
    sql(seeded, "INSERT INTO detection_summaries_hourly (hour, node_id, signal_class, "
                "detection_count) VALUES ('2026-11-27T11:00:00Z', 'legacy-edge', 'fm', 9);"
                "UPDATE detection_summaries_hourly SET detection_count = 4 "
                "WHERE hour = '2026-11-27T09:00:00Z';")
    r = compare(seeded, base)
    assert r["nothing_new"] is False and r["discards"]["summaries_changed_hours"] == 2
    assert r["discards"]["rows"] == {}


def test_compare_sees_a_changed_state_file_but_not_saved_at(seeded):
    base = baseline(seeded)
    p = seeded.data / "alerts.json"
    obj = json.loads(p.read_text())
    p.write_text(json.dumps(dict(obj, saved_at="2026-11-27T12:00:00Z")))
    assert compare(seeded, base)["nothing_new"] is True
    p.write_text(json.dumps({"alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}],
                             "saved_at": "x"}))
    r = compare(seeded, base)
    assert r["discards"]["state_files_changed"] == ["alerts"] and r["nothing_new"] is False


# ── 29-35 the source itself, read-only ops, progress ─────────────────────


def test_role_rank_table_matches_persistence(engine_ns):
    text = (ROOT / "src" / "sigrift" / "bridge" / "persistence.py").read_text()
    m = re.search(r"^_ROLE_ORDER = (\(.*?\))$", text, re.M)
    assert m and ast.literal_eval(m.group(1)) == engine_ns["ST_ROLE_ORDER"]
    rank = engine_ns["st_rank"]
    assert rank("admin") > rank("Analyst") > rank("viewer") > rank("sensor")
    assert rank("no-such-role") == rank("viewer")


ALLOWED = {"base64", "binascii", "errno", "fnmatch", "gzip", "hashlib", "hmac", "io", "json", "os",
           "re", "shutil", "sqlite3", "stat", "struct", "sys", "tarfile", "threading", "time",
           "zlib"}


def test_state_engine_is_ascii_and_imports_only_the_allowed_modules():
    src = state_engine_source()
    src.encode("ascii")
    tree_ = ast.parse(src)
    mods = set()
    for node in ast.walk(tree_):
        if isinstance(node, ast.Import):
            mods |= set(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add((node.module or "").split(".")[0])
    # audit-append imports the restored bridge's own audit code, lazily.
    assert mods - ALLOWED == {"sigrift"}
    imports_sigrift = [n for n in ast.walk(tree_) if isinstance(n, ast.ImportFrom)
                       and (n.module or "").startswith("sigrift")]
    assert len(imports_sigrift) == 1
    # It reads no environment variable.
    attrs = set(n.attr for n in ast.walk(tree_) if isinstance(n, ast.Attribute))
    assert not attrs & {"environ", "getenv", "environb", "putenv"}


def snapshot_bytes(root: Path) -> dict:
    return dict((str(p), (p.read_bytes() if p.is_file() else None, p.lstat().st_mtime_ns))
                for p in sorted(root.rglob("*")))


def test_read_only_ops_write_nothing(seeded):
    base = baseline(seeded)
    before = snapshot_bytes(seeded.data), snapshot_bytes(seeded.secrets)
    seeded.ok("state")
    compare(seeded, base)
    seeded.call("snapshot-volume", volume="bridge_data", excludes=DATA_EXCLUDES)
    assert (snapshot_bytes(seeded.data), snapshot_bytes(seeded.secrets)) == before
    assert not (seeded.data / "detections.db-wal").exists()


def test_verify_staged_finds_an_edit_an_extra_file_and_a_retargeted_symlink(seeded):
    (seeded.data / "link").symlink_to("keys.json")
    arch, mem, r = seeded.snapshot("bridge_data")
    assert seeded.stage("bridge_data", arch, mem, r)[0] == 0
    S = seeded.data / (".sigrift-restore-" + RB)
    req = dict(volume="bridge_data", rb_id=RB, members_file_sha256=r["members_sha256"])
    assert seeded.ok("verify-staged", section(mem), **req)["ok_staged"] is True
    (S / "keys.json").write_text("written by the running bridge")
    (S / "extra").write_text("x")
    (S / "link").unlink()
    (S / "link").symlink_to("../../etc/passwd")
    reply = seeded.ok("verify-staged", section(mem), **req)
    assert reply["ok_staged"] is False and set(reply["mismatches"]) == {"keys.json", "extra",
                                                                         "link"}


@pytest.mark.parametrize("plant", ["carried", "staged"])
def test_verify_staged_refuses_a_carry_marker_or_another_points_staged_file(seeded, plant):
    # Written into the staging while the stack serves, before rb-carry: a
    # complete .sigrift-carried would make carry skip every rule.
    arch, mem, r = seeded.snapshot("bridge_data")
    assert seeded.stage("bridge_data", arch, mem, r)[0] == 0
    S = seeded.data / (".sigrift-restore-" + RB)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP,
               members_file_sha256=r["members_sha256"])
    assert seeded.ok("verify-staged", section(mem), **req)["ok_staged"] is True
    if plant == "carried":
        (S / ".sigrift-carried").write_text(json.dumps(
            {"format": 1, "no_carry": False, "complete": True, "report": {}}))
    else:
        info = json.loads((S / ".sigrift-staged").read_text())
        (S / ".sigrift-staged").write_text(json.dumps(dict(info, restore_point="other")))
    reply = seeded.ok("verify-staged", section(mem), **req)
    assert reply["ok_staged"] is False and reply["mismatches"] == [".sigrift-" + plant]


def test_carry_and_compare_take_a_key_moved_to_another_node(seeded):
    base = baseline(seeded)

    def rebind(v):
        keys = json.loads((v.data / "keys.json").read_text())
        keys["keys"]["edge_pi1"]["node_id"] = "pi-9"
        (v.data / "keys.json").write_text(json.dumps(keys))
    rebind(seeded)
    assert compare(seeded, base)["carries"]["api_keys_bound"] == ["edge_pi1"]
    keys = json.loads((seeded.data / "keys.json").read_text())
    keys["keys"]["edge_pi1"]["node_id"] = "pi-1"
    (seeded.data / "keys.json").write_text(json.dumps(keys))
    staged_rollback(seeded, rebind)
    S = seeded.data / (".sigrift-restore-" + RB)
    rep = json.loads((S / ".sigrift-carried").read_text())["report"]
    assert rep["api_keys_bound"] == ["edge_pi1"]
    assert json.loads((S / "keys.json").read_text())["keys"]["edge_pi1"]["node_id"] == "pi-9"


def test_progress_counter_moves_for_every_long_phase(seeded, monkeypatch):
    sql(seeded, "CREATE TABLE big (id INTEGER PRIMARY KEY, x TEXT);"
                "WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM c WHERE i < 3000) "
                "INSERT INTO big (x) SELECT hex(randomblob(40)) FROM c;")
    # A clock that moves 10 s per reading: every step sends its P frame.
    clock = {"t": 1_700_000_000.0}

    def tick():
        clock["t"] += 10
        return clock["t"]
    monkeypatch.setitem(seeded.ns, "CLOCK", tick)
    rc, reply, frames = seeded.call("quiesce", mode="strict")
    assert rc == 0
    prog = [json.loads(p) for k, p in frames if k == b"P"]
    by_phase = {}
    for p in prog:
        by_phase.setdefault(p["phase"], []).append(p["progress"])
    # quick_check advances through SQLite's progress handler; a checkpoint
    # is one VM step, so it is announced as its own phase (the host gives it
    # the sync allowance) and the state that follows goes on counting.
    assert by_phase["quick_check"][-1] > 0 and "checkpoint" in by_phase
    assert max(by_phase["state"]) >= max(by_phase["quick_check"])
    # The heartbeat repeats the last P frame; it never advances the counter.
    out = seeded.ns["StOut"](io.BytesIO())
    out.step(n=5, phase="x")
    before = out.progress
    out.frame(b"P", out.p_payload())
    assert out.progress == before


def test_unswap_and_swap_crash_matrix_with_the_undo_steps(seeded, tmp_path, monkeypatch):
    import shutil
    staged_rollback(seeded)
    live = tree(seeded.data)
    req = dict(volume="bridge_data", rb_id=RB, restore_point=RP, keep_back=KEEP_BACK)
    seeded.ok("swap", **req)
    base = tmp_path / "swapped"
    shutil.copytree(seeded.data, base, symlinks=True)
    counter = {"n": 0}
    real = seeded.ns["RENAME"]

    def counting(a, b):
        counter["n"] += 1
        return real(a, b)
    monkeypatch.setitem(seeded.ns, "RENAME", counting)
    seeded.ok("unswap", **req)
    monkeypatch.setitem(seeded.ns, "RENAME", real)
    assert tree(seeded.data) == live
    for k in range(counter["n"]):
        shutil.rmtree(seeded.data)
        shutil.copytree(base, seeded.data, symlinks=True)
        rc, _ = run_until(seeded, "unswap", monkeypatch, k, **req)
        assert rc == 1
        ph = phase_of(seeded)
        if ph and ph.startswith("undo-"):
            seeded.err("swap", "phase", **req)
        seeded.ok("unswap", **req)
        assert tree(seeded.data) == live, k


def test_state_runs_on_fernet_rows_without_cryptography(seeded, monkeypatch):
    from lifecycle_fakes import KEY_A
    import sys
    # As in the CI scripts job: neither cryptography nor the bridge's code.
    for mod in ("cryptography", "cryptography.fernet", "sigrift", "sigrift.bridge",
                "sigrift.bridge.storage", "sigrift.bridge.storage.audit"):
        monkeypatch.setitem(sys.modules, mod, None)
    r = seeded.ok("state", env={"BRIDGE_MFA_KEY": KEY_A, "BRIDGE_AUDIT_KEY": "k"})
    assert r["counts"]["totp_fernet"] == 1
    assert r["mfa"] == "unchecked" and r["audit"]["result"] == "unchecked"
    assert KEY_A not in json.dumps(r) and '"k"' not in json.dumps(r["fingerprints"])


# ── Phase 2 F-D21: the audit chain's head, as tags ────────────────────


def audit_tag(value):
    return hashlib.sha256(b"sigrift-audit-chain-v1:" + value.encode()).hexdigest()[:32]


def test_state_and_facts_name_the_audit_head_by_a_tag_of_its_chain_value(seeded, engine_ns):
    """phase2-notes F-D21: state names the audit head's id and a tag of its
    chain value (sha256 with a domain, 32 hex) and, with audit_at, each named
    entry's tag (None: no such entry); 1a's facts give the same through the
    state engine's st_audit_chain (one module). No reply holds the value."""
    db = sqlite3.connect(seeded.data / "detections.db")
    db.execute("INSERT INTO audit_log (timestamp, action, target_id, hmac_chain) "
               "VALUES ('2026-11-28T10:00:00Z', 'key_revoke', 'ops', 'chain-value-2')")
    db.commit()
    db.close()
    r = seeded.ok("state", audit_at=[1, 9])
    au = r["audit"]
    assert (au["head_id"], au["head_tag"], au["chain"]) == (2, audit_tag("chain-value-2"), "ok")
    assert au["at"] == {"1": audit_tag("h1"), "9": None}
    assert "chain-value-2" not in json.dumps(r) and '"h1"' not in json.dumps(r)
    assert "at" not in seeded.ok("state")["audit"]
    facts = engine_ns["op_facts"]({"op": "facts", "data_dir": str(seeded.data), "audit_at": [1]})
    assert facts["audit_chain"] == {"chain": "ok", "head_id": 2, "head_tag": audit_tag("chain-value-2"),
                                    "at": {"1": audit_tag("h1")}}
    chain = engine_ns["st_audit_chain"]
    conn = sqlite3.connect(":memory:")
    assert chain(conn)["chain"] == "no-table"
    conn.execute("CREATE TABLE audit_log (id INTEGER PRIMARY KEY, action TEXT)")
    assert chain(conn)["chain"] == "no-column"
    conn.execute("ALTER TABLE audit_log ADD COLUMN hmac_chain TEXT")
    assert chain(conn, [1]) == {"chain": "empty", "head_id": None, "head_tag": None, "at": {"1": None}}
    conn.execute("INSERT INTO audit_log VALUES (5, 'legacy', NULL)")
    assert chain(conn, [5]) == {"chain": "ok", "head_id": 5, "head_tag": "", "at": {"5": ""}}
    # An unreadable database: never a guess.
    (seeded.data / "detections.db").write_bytes(b"not a database at all, sixteen+ bytes")
    for p in seeded.data.glob("detections.db-*"):
        p.unlink()
    assert seeded.ok("state")["audit"]["chain"] == "unreadable"
    facts = engine_ns["op_facts"]({"op": "facts", "data_dir": str(seeded.data)})
    assert facts["audit_chain"]["chain"] == "unreadable"


def test_import_compare_matches_rows_against_the_staged_copy_and_dates_unrecorded_changes(seeded):
    """phase2-notes F-D22, compare of an import --replace. staged_rb: the rows
    the live data has that the staged copy (the archive's data) lacks or holds
    differently are counted by key and every common column, also below the
    export point's mark (both copies wrote after they parted), and so are the
    capture files it lacks. common_head: the API keys, certificates and
    protocol keys the point has and the live data lacks are dated against that
    audit entry's time (made after it, or with no time: unrecorded.after)."""
    base, rows = baseline(seeded)
    staged = seeded.data / ".sigrift-restore-20261128T000000Z"
    staged.mkdir()
    shutil.copy2(seeded.data / "detections.db", staged / "detections.db")
    for d in ("iq_captures", "pcap_captures"):
        shutil.copytree(seeded.data / d, staged / d)
    # The staged copy wrote d3 after the parting; the live data wrote its own
    # row at the same rowid (below the staged mark), changed d1 in place and
    # added a capture.
    # d2 was written again there (a new rowid, the same row): matched by its
    # primary key, it is not counted.
    sc = sqlite3.connect(staged / "detections.db")
    sc.execute("INSERT INTO detections VALUES ('d3', '2026-11-28T10:00:00Z', 'pi-1', 'fm', '', 1e8, "
               "0.9, 10, -50, 0.1, 'default')")
    row = sc.execute("SELECT * FROM detections WHERE detection_id = 'd2'").fetchone()
    sc.execute("DELETE FROM detections WHERE detection_id = 'd2'")
    sc.execute("INSERT INTO detections VALUES (%s)" % ", ".join("?" for _ in row), row)
    sc.commit()
    sc.close()
    sql(seeded, "INSERT INTO detections VALUES ('live-only', '2026-11-28T09:00:00Z', 'pi-1', 'fm', "
                "'', 1e8, 0.9, 10, -50, 0.1, 'default');"
                "UPDATE detections SET snr_db = 11 WHERE detection_id = 'd1';")
    # A capture the live data wrote with an old time, and one it removed:
    # neither the point's newest time nor the file count sees it.
    new_cap = seeded.data / "pcap_captures" / "2.pcap.gz"
    new_cap.write_bytes(b"\x1f\x8bnew")
    os.utime(new_cap, (1e9, 1e9))
    (seeded.data / "iq_captures" / "c1.iq.gz").unlink()
    req, _ = base, rows
    plain = seeded.ok("compare", section(rows), **req)
    assert plain["discards"]["rows"].get("detections", 0) < 2 and plain["discards"]["captures_added"] == 0
    r = seeded.ok("compare", section(rows), **dict(req, staged_rb="20261128T000000Z"))
    d = r["discards"]
    assert d["rows_basis"] == "staged" and d["rows"].get("detections") == 2, d["rows"]
    assert d["captures_added"] == 1 and d["updated"] == {} and r["checkable"] is True
    # A staged copy that is not a database: the compare cannot check.
    (staged / "detections.db").write_bytes(b"not a database at all, sixteen+ bytes")
    r = seeded.ok("compare", section(rows), **dict(req, staged_rb="20261128T000000Z"))
    assert r["checkable"] is False and "the staged database cannot be compared" in r["why_not_checkable"]
    # Dated against the common entry (audit entry 1, 2026-11-27T10:00:00Z).
    rp = json.loads(json.dumps(req["rp"]))
    rp["security"]["keys"]["old"] = rp["security"]["keys"]["ops"]
    rp["security"]["keys"]["new"] = rp["security"]["keys"]["ops"]
    rp["security"]["keys"]["undated"] = rp["security"]["keys"]["ops"]
    rp["security"]["created"]["keys"] = {"old": "2026-11-01T00:00:00Z", "new": "2026-11-28T00:00:00Z"}
    rp["security"]["registry"]["901"] = {"revoked": False}
    rp["security"]["created"]["registry"] = {"901": "2026-11-27T09:59:59Z"}
    rp["security"]["crypto_keys"] = list(rp["security"]["crypto_keys"]) + ["ck-new"]
    rp["security"]["created"]["crypto_keys"] = {"ck-new": "2026-11-27 10:00:01"}
    r = seeded.ok("compare", section(rows), **dict(req, rp=rp, common_head=1))
    assert r["unrecorded"] == {"common_head": 1, "common_ts": "2026-11-27T10:00:00Z",
                               "after": {"api_keys": ["new", "undated"], "certs": [],
                                         "crypto_keys": ["ck-new"]}}, r["unrecorded"]
    assert sorted(r["carries"]["api_keys_removed"]) == ["new", "old", "undated"]
    # No such entry: nothing is dated, all of them are after.
    r = seeded.ok("compare", section(rows), **dict(req, rp=rp, common_head=99))
    assert r["unrecorded"]["after"]["api_keys"] == ["new", "old", "undated"]
    assert "unrecorded" not in seeded.ok("compare", section(rows), **dict(req, rp=rp))
    # The live projection names the creation times it found.
    st = seeded.ok("state")["security"]["created"]
    assert st["registry"] == {"101": "2026-11-01T00:00:00Z", "102": "2026-11-01T00:00:00Z"}
