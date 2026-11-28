"""Phase 2 PART B: --export, --move, --import and --reactivate end to end.

phase2-spec 14.3. The installer runs for real (bash) against the fake host
of scripts/tests/lifecycle_fakes.py; every engine run is the real
bootstrap with the real state and archive engines, with cryptography
(hence tests/bridge, G14), on real volume directories. Argon2id runs at
its smallest accepted cost (LC_AR_MEM_LOG2=16, one pass, one lane) and
the segments are 64 KiB, so an archive of the seeded volumes has a few
segments. Each scenario checks several items of 14.3 (named in its
docstring); what is left to the drills is listed in phase2-notes.md.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "tests"))
ROOT_SRC = Path(__file__).resolve().parents[2] / "src"

from lifecycle_fakes import (  # noqa: E402
    BASH,
    FakeDockerHost,
    changing_calls,
    release_install,
    run_installer,
    seed_volume,
    source_checkout,
    tree_digest,
    unpacked_release,
)

# The runners are several times slower than a dev machine for these end-to-end
# installer runs; 240 s timed some out there.
pytestmark = pytest.mark.timeout(900)
PROJECT = "sigrift-v010"
TARGET = "sigrift-v020"
PASS = "a long archive passphrase 2026"
KDF = {"LC_AR_MEM_LOG2": "16", "LC_AR_T": "1", "LC_AR_LANES": "1", "LC_AR_SEGMENT": "65536",
       "SIGRIFT_SNAPSHOT_RESERVE": "1M", "SIGRIFT_PULL": "never"}
AR_OPS = ("ar-wrap", "ar-write", "ar-verify", "ar-probe", "ar-stage")


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


@pytest.fixture
def inst(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    seed_volume(host, PROJECT)
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.2.0")
    host.add_image("ghcr.io/sigrift/sigrift-gateway:v0.2.0")
    return d


@pytest.fixture
def usb(tmp_path):
    d = tmp_path / "usb"
    d.mkdir(mode=0o700)
    return d


def run(folder, *args, host, stdin=PASS + "\n", env=None):
    return run_installer(folder, *args, host=host, stdin=stdin, env=dict(KDF, **(env or {})))


def out(r):
    return r.stdout + r.stderr


def journal(d):
    return json.loads((d / ".sigrift" / "journal.json").read_text())


def engine_runs(host):
    """(op, argv) of every engine run, from the engine stdin the fake saved."""
    runs = []
    inputs = sorted(host.dir.glob("engine-stdin.*"), key=lambda p: int(p.suffix[1:]))
    argvs = [c["argv"] for c in host.calls() if c["argv"][:1] == ["run"] and "--entrypoint" in c["argv"]]
    for p, argv in zip(inputs, argvs):
        data = p.read_bytes()
        n1 = data.index(b"\n")
        rest = data[n1 + 1 + int(data[:n1]):]
        n2 = rest.index(b"\n")
        req = json.loads(rest[n2 + 1: n2 + 1 + int(rest[:n2])])
        runs.append((req.get("op"), argv))
    return runs


def blob_of(*folders, host):
    """Every byte a log, journal, result or the fake's argv/env log holds."""
    blob = b""
    for f in folders:
        for p in Path(f).rglob("*"):
            if p.is_file() and not p.name.endswith(".sigrift-archive"):
                blob += p.read_bytes()
    for p in host.dir.glob("docker-log*"):
        blob += p.read_bytes()
    return blob


def run_from_file(folder, *args, host, path, env=None):
    """The installer with stdin from PATH (a pass file: fd 4 a regular file)."""
    with open(path) as fh:
        return subprocess.run([BASH, str(folder / "install-release.sh"), *args], stdin=fh,
                              capture_output=True, text=True, cwd=folder,
                              env=host.env(**dict(KDF, **(env or {}))), timeout=240)


def ar_seen(host):
    """The ar-* engine runs since the last clear_log, each checked for 5.1's
    run options (14.3 #4)."""
    seen = set()
    for op, a in engine_runs(host):
        if op in AR_OPS:
            seen.add(op)
            assert a[a.index("--log-driver") + 1] == "none" and a[a.index("--network") + 1] == "none"
            assert a[a.index("--ulimit") + 1] == "core=0", a
    return seen


def fd4_only_in_the_parent(host):
    """14.3 #6 (2.4): no docker call of the detached part (another session)
    has fd 4; the parent's do until it closes fd 4."""
    me = os.getsid(0)
    calls = host.calls()
    child = [c for c in calls if c.get("sid") != me]
    assert child, "no call of the detached part was logged"
    assert not [c["argv"][:3] for c in child if c.get("fd4")]


def no_raw_control(text):
    """No C0 byte but the line ends, no DEL or C1 code point (11, Appendix C P)."""
    return not re.search(r"[\x00-\x09\x0b-\x1f\x7f-\x9f]", text)


def export(d, usb, host, *extra, name="lab.sigrift-archive"):
    r = run(d, "--export", str(usb / name), *extra, host=host)
    assert r.returncode == 0, out(r)
    hc = re.search(r"--expect ([0-9a-f]{16})", r.stdout).group(1)
    return usb / name, hc, r


def vol_members(host, name):
    root = host.volume(name)
    skip = (".sigrift-install.json", ".sigrift-restore-incomplete")
    return sorted(str(p.relative_to(root)) for p in root.rglob("*")
                  if p.is_file() and not p.name.startswith(skip) and ".sigrift-" not in str(p))


def test_export_call_order_downtime_and_secret_hygiene(inst, usb, host, tmp_path):
    """14.3 #1, #2, #3, #4, #33 (M-EXPORTED's wording), #28 (the --expect line)."""
    host.clear_log()
    f, hc, r = export(inst, usb, host)
    argv = host.argvs()

    def first(pat, start=0):
        return next(i for i, a in enumerate(argv) if i >= start and re.search(pat, a))
    stop = first(r"^compose stop")
    ops = [op for op, _ in engine_runs(host)]
    assert ops.index("quiesce") < ops.index("snapshot-volume") < ops.index("ar-write") \
        < ops.index("ar-verify"), ops
    up = first(r"^compose up -d --pull never --remove-orphans bridge$", stop)
    write_run = [i for i, a in enumerate(argv) if a.startswith("run ") and "--entrypoint" in a]
    # The stack serves again before the archive is written (#2).
    nth_write = ops.index("ar-write")
    assert stop < up < write_run[nth_write], (stop, up, write_run[nth_write])
    j = journal(inst)
    assert j["op"] == "export" and j["state"] == "done" and j["published"] is True
    assert j["done"][-4:] == ["ar-publish", "ar-drop-rp", "record", "ar-forget"]
    assert "--move" not in r.stdout and "the stack was stopped for" in r.stdout
    assert "verified as read back from" in r.stdout
    assert ("Import it with: bash install-release.sh --import lab.sigrift-archive --expect %s" % hc) \
        in r.stdout
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    # The export's restore point is gone; no key, no partial, no ops dir.
    assert not [p for p in (inst / ".sigrift" / "snapshots").iterdir() if p.name.endswith("-full")]
    assert not list((inst / ".sigrift" / "ops").iterdir())
    assert not list(usb.glob(".*sigrift-partial"))
    # #3: the passphrase is in no log, journal, result, argv or environment.
    blob = blob_of(inst, tmp_path / "usb", host=host)
    assert PASS.encode() not in blob and b"YSBsb25nIGFyY2hpdmUgcGFzc3BocmFzZSAyMDI2" not in blob
    # #4: every engine run that holds the passphrase or a data key.
    assert ar_seen(host) == {"ar-wrap", "ar-write", "ar-verify"}
    # 11.3: the sizes left out, a known medium (or "the medium").
    assert re.search(r"Not included: Docker images, backups/ \([^)]+\) and exports/ \([^)]+\)", r.stdout)
    assert "read back from unknown" not in r.stdout
    # The stack runs again and a plain --status is clean.
    r = run(inst, "--status", host=host)
    assert r.returncode == 0 and "journal   export" in r.stdout


def test_move_then_import_round_trip(inst, usb, host, tmp_path):
    """14.3 #7, #10, #11, #18, #26, #27, #28 (--expect accepted), #31."""
    before = {v: vol_members(host, "%s_%s" % (PROJECT, v)) for v in ("bridge_data", "bridge_secrets")}
    pf = usb / "pass.txt"
    pf.write_text(PASS + "\n")
    pf.chmod(0o600)
    host.clear_log()
    r = run_from_file(inst, "--export", str(usb / "lab.sigrift-archive"), "--move", host=host, path=pf)
    assert r.returncode == 0, out(r)
    f, hc = usb / "lab.sigrift-archive", re.search(r"--expect ([0-9a-f]{16})", r.stdout).group(1)
    # 2.4's NOTE: the pass file sits beside the archive.
    assert "NOTE: the passphrase file is in the same directory as the archive" in r.stderr
    assert "is stopped and held: docker compose up there starts only a placeholder" in r.stdout
    fd4_only_in_the_parent(host)
    seen = ar_seen(host)
    # #7: the stub, the markers and moved.json; other commands refuse.
    assert (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub: this install was moved")
    moved = json.loads((inst / ".sigrift" / "moved.json").read_text())
    assert moved["archive_id"] == journal(inst)["archive_id"]
    for v in ("bridge_data", "bridge_secrets"):
        m = json.loads((host.volume("%s_%s" % (PROJECT, v)) / ".sigrift-restore-incomplete").read_text())
        assert m["op"] == "move" and m["id"] == moved["archive_id"] and m["restore_point"] is None
    for args in ((), ("--rollback",), ("--snapshot",)):
        r = run(inst, *args, host=host)
        assert r.returncode == 3 and "was moved to another host on" in r.stderr, (args, out(r))
        assert "To start it here again: bash install-release.sh --reactivate" in r.stderr
    s = json.loads(run(inst, "--status", "--json", host=host).stdout)
    assert s["moved"]["archive_id"] == moved["archive_id"]
    assert s["next"].startswith("nothing to do here: moved to another host")
    # The moved folder takes an import only with --replace (M-MOVED-HERE).
    r = run(inst, "--import", str(f), host=host)
    assert r.returncode == 3 and "was moved to another host on" in r.stderr, out(r)
    # The import, with the --expect value the export printed.
    new = unpacked_release(tmp_path)
    host.clear_log()
    r = run(new, "--import", str(f), "--expect", hc.upper(), host=host)
    assert r.returncode == 0, out(r)
    assert "==> Header authenticated; archive %s" % hc in r.stdout
    # #4 across the export and the import: all five ops, each with the options.
    assert seen | ar_seen(host) == set(AR_OPS)
    fd4_only_in_the_parent(host)
    assert "the archive was not checked against its export" not in r.stdout
    assert "NOTE: the old volumes of sigrift-v010 are still on this host: docker volume rm" in r.stdout
    assert "Other edges" in r.stdout and "pi-1" in r.stdout  # #26
    # #10: the volumes come from docker compose create, with the project labels.
    argv = host.argvs()
    create = [a for a in argv if " create --no-build --pull never bridge" in a]
    assert create and create[0].startswith("compose -p %s --project-directory . --env-file " % TARGET)
    st = json.loads(host.state_path.read_text())
    vols = {(v["project"], v["volume"]) for v in st["volumes"]}
    assert {(TARGET, "bridge_data"), (TARGET, "bridge_secrets")} <= vols
    # #11: the volumes equal the source's (apart from lifecycle entries, and
    # backups/ and exports/, which no archive holds: G15).
    for v in ("bridge_data", "bridge_secrets"):
        want = [m for m in before[v] if not m.startswith(("backups/", "exports/"))]
        assert vol_members(host, "%s_%s" % (TARGET, v)) == want, v
    # #18: every session ended.
    db = sqlite3.connect(host.volume(TARGET + "_bridge_data") / "detections.db")
    assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    db.close()
    # #31: no key, host part or decrypted file once the import is done.
    assert not list((new / ".sigrift" / "ops").iterdir())
    # Records: the install id travels (G10), imported_from, the volume record.
    hr = json.loads((new / ".sigrift" / "install.json").read_text())
    assert hr["install_id"] == moved["install_id"]
    assert hr["imported_from"]["archive_id"] == moved["archive_id"]
    assert hr["history"][-1]["op"] == "import"
    vrec = json.loads((host.volume(TARGET + "_bridge_data") / ".sigrift-install.json").read_text())
    assert vrec["last_op"] == "import" and vrec["imported_from"]["archive_id"] == moved["archive_id"]
    assert "history_tail" not in vrec["imported_from"]
    env = (new / ".env").read_text()
    assert "COMPOSE_PROJECT_NAME=%s" % TARGET in env and "BRIDGE_MFA_KEY=" in env
    assert stat.S_IMODE((new / ".env").stat().st_mode) == 0o600
    assert (new / "docker-compose.override.yml.imported").exists()
    assert not (new / "docker-compose.override.yml").exists()  # G6: never active
    s = json.loads(run(new, "--status", "--json", host=host).stdout)
    assert s["imported"]["archive_id"] == moved["archive_id"]
    assert s["imported"]["edges"]["other"] == ["pi-1"]
    # The same archive again here: refused (M-IMPORT-AGAIN).
    again = unpacked_release(tmp_path, name="again")
    r = run(again, "--import", str(f), host=host)
    assert r.returncode == 3 and "was already imported here" in r.stderr, out(r)
    # 7.4: the imported copy runs on this host, so the old folder is not
    # reactivated (a second live gateway of one install).
    r = run(inst, "--reactivate", "--confirm", PROJECT, host=host)
    assert r.returncode == 3 and "%s (in " % TARGET in r.stderr and "the same install" in r.stderr, \
        out(r)
    assert (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub")


def test_import_refusals_change_nothing(inst, usb, host, tmp_path):
    """14.3 #12 (same running, not empty, project taken), #28 (another
    archive's --expect, before the passphrase is read), #32 (a cut-off copy
    in a dry run), a wrong passphrase."""
    f, hc, _ = export(inst, usb, host)
    new = unpacked_release(tmp_path)
    cut = usb / "cut.sigrift-archive"
    cut.write_bytes(f.read_bytes()[:-70000])
    os.chmod(cut, 0o600)
    cases = [
        ((str(f), "--expect", "0" * 16), "", "not 0000000000000000: an older archive, or another install's"),
        ((str(f),), "not the passphrase at all\n", "the passphrase does not open"),
        ((str(cut), "--dry-run"), PASS + "\n", "bytes shorter than its header says"),
        ((str(f),), PASS + "\n", "runs on this host in"),
    ]
    st0 = json.loads(host.state_path.read_text())["volumes"]
    for args, stdin, needle in cases:
        before = tree_digest(new)
        host.clear_log()
        r = run(new, "--import", *args, host=host, stdin=stdin)
        assert r.returncode == 3 and needle in r.stderr, (args, out(r))
        assert r.stderr.rstrip().endswith("Nothing was changed."), out(r)
        assert tree_digest(new) == before, args
        assert json.loads(host.state_path.read_text())["volumes"] == st0
        assert changing_calls(host) == [], (args, changing_calls(host))
    # An existing install with data is never filled without --replace.
    r = run(inst, "--import", str(f), host=host)
    assert r.returncode == 3 and "--import fills an empty install" in r.stderr, out(r)
    # The plan of 11.4 (a dry run, once the install it came from is stopped):
    # source, files, TLS and edges lines; nothing changed.
    host.load()
    for c in host.state["containers"]:
        if c["project"] == PROJECT:
            c["state"] = "exited"
    host.save()
    (host.volume(PROJECT + "_bridge_data") / ".sigrift-restore-incomplete").write_text(json.dumps(
        {"format": 1, "op": "move", "id": "00000000-0000-4000-8000-00000000ffff"}))
    before = tree_digest(new)
    r = run(new, "--import", str(f), "--dry-run", host=host)
    assert r.returncode == 0, out(r)
    lines = r.stdout.splitlines()
    for head in ("  source    ", "  .env      ", "  files     ", "  TLS       kept; ", "  edges     "):
        assert any(x.startswith(head) for x in lines), (head, r.stdout)
    assert "skipped (this host)" in r.stdout and "other: pi-1" in r.stdout
    assert tree_digest(new) == before
    # A newer schema than the target's bridge, a newer release than this
    # installer's: refused before any change (M-IMPORT-SCHEMA-NEWER, -VERSION-NEWER).
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.2.0", newest_migration=50)
    r = run(new, "--import", str(f), "--dry-run", host=host)
    assert r.returncode == 3 and "the archive is schema 56, newer than this installer's bridge (50)" \
        in r.stderr, out(r)
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.2.0")
    old = unpacked_release(tmp_path, version="v0.0.9", name="old-release")
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.0.9")
    host.add_image("ghcr.io/sigrift/sigrift-gateway:v0.0.9")
    r = run(old, "--import", str(f), "--dry-run", host=host)
    assert r.returncode == 3 and "newer than this installer's release (v0.0.9)" in r.stderr, out(r)


def test_late_archive_error_undoes_volumes_staging_and_files(inst, usb, host, tmp_path):
    """14.3 #14, #22 (a refusal at im-stage leaves no key, host part or
    payload), #3 on an error path."""
    f, hc, _ = export(inst, usb, host, "--move")
    data = bytearray(f.read_bytes())
    data[-1] ^= 1  # the last segment's tag: ar-probe never reads it
    bad = usb / "bad.sigrift-archive"
    bad.write_bytes(bytes(data))
    os.chmod(bad, 0o600)
    new = unpacked_release(tmp_path)
    before = tree_digest(new)
    vols0 = json.loads(host.state_path.read_text())["volumes"]
    r = run(new, "--import", str(bad), host=host)
    assert r.returncode == 3, out(r)
    text = out(r)
    assert "fails authentication" in text and "Undone: the staging, the volumes this import created" in text
    assert text.rstrip().endswith("Nothing was changed.")
    assert json.loads(host.state_path.read_text())["volumes"] == vols0
    assert journal(new)["state"] == "aborted"
    assert not list((new / ".sigrift" / "ops").iterdir())
    after = {k: v for k, v in tree_digest(new).items() if "/.sigrift/" not in k}
    assert after == before
    assert PASS.encode() not in blob_of(new, host=host)


def test_reactivate_needs_the_project_typed_and_starts_the_stack(inst, usb, host):
    """14.3 #9, and M-REACTIVATE-NOTHING."""
    r = run(inst, "--reactivate", host=host)
    assert r.returncode == 0 and "Nothing to reactivate" in r.stdout
    export(inst, usb, host, "--move")
    r = run(inst, "--reactivate", host=host)
    assert r.returncode == 3 and "Next: bash install-release.sh --reactivate --confirm %s" % PROJECT \
        in r.stderr, out(r)
    r = run(inst, "--reactivate", "--confirm", "other", host=host)
    assert r.returncode == 3 and "does not name the project" in r.stderr, out(r)
    r = run(inst, "--reactivate", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    assert "%s runs again here. If archive" % PROJECT in r.stdout
    assert not (inst / ".sigrift" / "moved.json").exists()
    assert list((inst / ".sigrift" / "logs").glob("moved-*.json"))
    assert not (host.volume(PROJECT + "_bridge_data") / ".sigrift-restore-incomplete").exists()
    assert not (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub")
    running = [c for c in json.loads(host.state_path.read_text())["containers"]
               if c["project"] == PROJECT and c["state"] == "running"]
    assert {c["service"] for c in running} >= {"bridge", "gateway"}


def test_export_failure_resume_abort_and_the_key_check(inst, usb, host):
    """14.3 #21: a failed ar-verify (exit 1, the stack up, the partial gone),
    --resume writes a new partial, an --abort after the archive was
    published is refused (M-ABORT-EXPORT-DONE), a damaged archive.key is
    refused before any step (M-AR-KEY-DAMAGED)."""
    host.update(engine_faults={"ar-verify": {"rc": 1, "once": True}})
    r = run(inst, "--export", str(usb / "x.sigrift-archive"), host=host)
    assert r.returncode == 1, out(r)
    j = journal(inst)
    assert j["state"] == "failed" and j["next"] == "ar-verify"
    first_partial = j["partial"]
    assert not Path(first_partial).exists()
    assert (inst / ".sigrift" / "ops" / j["id"] / "archive.key").exists()
    # A damaged key: refused before anything runs.
    key = inst / ".sigrift" / "ops" / j["id"] / "archive.key"
    good = key.read_bytes()
    key.write_bytes(good[:31])
    r = run(inst, "--resume", host=host)
    assert r.returncode == 3 and "is damaged; nothing was encrypted with it" in r.stderr, out(r)
    key.write_bytes(good)
    os.chmod(key, 0o600)
    # A mark that fails during --move would leave the journal past publish;
    # here: resume finishes the export (a fresh partial under a new salt).
    r = run(inst, "--resume", host=host)
    assert r.returncode == 0, out(r)
    assert journal(inst)["partial"] != first_partial and (usb / "x.sigrift-archive").exists()
    # A kill inside ar-publish after link(partial, FILE), before the journal
    # says published: --abort sees the file with the archive's sha256 and
    # refuses (M-ABORT-EXPORT-DONE; 10, ar-publish row).
    jp = inst / ".sigrift" / "journal.json"
    kept = jp.read_text()
    j = json.loads(kept)
    j.update(state="failed", next="ar-publish", published=False,
             done=j["done"][:j["done"].index("ar-publish")])
    jp.write_text(json.dumps(j))
    r = run(inst, "--abort", host=host)
    assert r.returncode == 3 and "the archive is already written; --abort cannot undo that" in r.stderr, \
        out(r)
    jp.write_text(kept)
    # --move whose mark step fails after the publish: --abort is refused.
    host.update(engine_faults={"mark": {"rc": 1, "once": True}})
    r = run(inst, "--export", str(usb / "y.sigrift-archive"), "--move", host=host)
    assert r.returncode == 4, out(r)
    # 14.3 #31: the key is gone right after ar-publish, the journal active.
    assert not (inst / ".sigrift" / "ops" / journal(inst)["id"] / "archive.key").exists()
    assert (inst / ".sigrift" / "ops" / journal(inst)["id"]).is_dir()
    r = run(inst, "--abort", host=host)
    assert r.returncode == 3 and "the archive is already written; --abort cannot undo that" in r.stderr
    assert "then, to start it here again: bash install-release.sh --reactivate" in r.stderr
    r = run(inst, "--resume", host=host)
    assert r.returncode == 0, out(r)
    assert (inst / ".sigrift" / "moved.json").exists()


def test_passphrase_channel_and_escaped_names(inst, usb, host, tmp_path):
    """14.3 #6 (no TTY: one line of stdin; empty stdin and a pass file of mode
    0644 refused; nothing prompted), #34 (C0 and C1 in a file name escaped),
    #5 (an existing file, a directory others can write)."""
    weird = usb / "lab\x1b[31m.sigrift-archive"
    r = run(inst, "--export", str(weird), "--dry-run", host=host)
    assert r.returncode == 0 and "\\x1b[31m" in r.stdout and "\x1b" not in r.stdout, out(r)
    r = run(inst, "--export", str(usb / "e.sigrift-archive"), host=host, stdin="")
    assert r.returncode == 3 and "needs a passphrase" in r.stderr, out(r)
    pf = tmp_path / "pass.txt"
    pf.write_text(PASS + "\r\n")
    os.chmod(pf, 0o644)
    env = host.env(**KDF)
    with open(pf) as fh:
        p = subprocess.run([BASH, str(inst / "install-release.sh"), "--export",
                            str(usb / "f.sigrift-archive")], stdin=fh, capture_output=True,
                           text=True, cwd=inst, env=env, timeout=120)
    assert p.returncode == 3 and "chmod 600" in p.stderr, p.stderr
    (usb / "exists.sigrift-archive").write_text("x")
    r = run(inst, "--export", str(usb / "exists.sigrift-archive"), host=host)
    assert r.returncode == 3 and "exists; an export never overwrites a file" in r.stderr
    shared = tmp_path / "shared"
    shared.mkdir()
    os.chmod(shared, 0o777)
    r = run(inst, "--export", str(shared / "s.sigrift-archive"), host=host)
    assert r.returncode == 3 and "writable by others without the sticky bit" in r.stderr, out(r)
    r = run(inst, "--export", str(inst / "tls" / "t.sigrift-archive"), host=host)
    assert r.returncode == 3, out(r)
    # Usage: --move only with --export, --expect only with --import, and HC16;
    # 1b's guard flags with --import only with --replace (F-D21: its plan
    # compares the current data; a fresh import has none).
    for args in (("--import", "x", "--move"), ("--export", "x", "--expect", "0" * 16),
                 ("--import", "x", "--expect", "xyz"), ("--export", "-"),
                 ("--import", "x", "--no-carry-revocations"),
                 ("--import", "x", "--accept-summary-reset"),
                 ("--import", "x", "--revert-credentials")):
        assert run(inst, *args, host=host).returncode == 2, args
    # #34: a damaged header under a hostile name: the Error and the Next
    # lines carry no raw control byte (Next pastes back as $'...').
    golden = Path(__file__).resolve().parent / "fixtures" / "state_archive" / "v1-golden.sigrift-archive"
    data = bytearray(golden.read_bytes())
    data[30] ^= 1
    hostile = usb / "x\x1b]0;pwned\x07\nNothing was changed.\n.sigrift-archive"
    hostile.write_bytes(bytes(data))
    fresh = unpacked_release(tmp_path, name="fresh")
    r = run(fresh, "--import", str(hostile), host=host)
    assert r.returncode == 3 and "is damaged" in r.stderr, out(r)
    assert no_raw_control(out(r)), out(r)
    assert "Next: sha256sum $'" in r.stderr and "\\x1b]0;pwned\\x07\\x0a" in r.stderr
    assert [x for x in r.stderr.splitlines() if x == "Nothing was changed."] == ["Nothing was changed."]
    # 2.4: a pipe on fd 4 and a terminal on stderr: the notice before the read.
    m, sl = os.openpty()
    proc = subprocess.Popen([BASH, str(inst / "install-release.sh"), "--export",
                             str(usb / "n.sigrift-archive")], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=sl, cwd=inst, env=host.env(**KDF))
    os.close(sl)
    proc.stdin.close()
    err = b""
    while True:
        try:
            chunk = os.read(m, 4096)
        except OSError:
            break
        if not chunk:
            break
        err += chunk
    proc.wait(timeout=120)
    proc.stdout.close()
    os.close(m)
    assert proc.returncode == 3, err
    assert b"Reading the archive passphrase from standard input (one line)." in err, err
    assert b"needs a passphrase" in err


def marker_of(host, vol):
    p = host.volume(vol) / ".sigrift-restore-incomplete"
    return json.loads(p.read_text()) if p.exists() else None


def add_edge_data(host, project):
    st = json.loads(host.state_path.read_text())
    st["volumes"].append({"name": project + "_edge_data", "project": project, "volume": "edge_data"})
    host.state_path.write_text(json.dumps(st))
    host.volume(project + "_edge_data").mkdir(parents=True, exist_ok=True)
    (host.volume(project + "_edge_data") / "journal.db").write_bytes(b"edge")


def test_export_from_a_moved_folder_keeps_it_moved(inst, usb, host):
    """Fix round (6.1, G8): --export without --move in a moved folder leaves
    its move stub, markers and moved.json (which gains archives[]); --status
    still says moved."""
    f, hc, _ = export(inst, usb, host, "--move")
    aid = json.loads((inst / ".sigrift" / "moved.json").read_text())["archive_id"]
    _, _, r = export(inst, usb, host, name="second.sigrift-archive")
    assert "the stack was not running (moved folder)" in r.stdout, out(r)
    # unhold is done at creation (6.1), not run (and only then kept by its guard).
    assert "the move stub stays" not in out(r) and "the real compose file is back" not in out(r)
    assert (inst / "docker-compose.yml").read_text().startswith(
        "# SigRift hold stub: this install was moved"), out(r)
    moved = json.loads((inst / ".sigrift" / "moved.json").read_text())
    assert moved["archive_id"] == aid and len(moved["archives"]) == 1
    assert moved["archives"][0]["file"] == str(usb / "second.sigrift-archive")
    for v in ("bridge_data", "bridge_secrets"):
        assert marker_of(host, "%s_%s" % (PROJECT, v))["id"] == aid
    assert "unhold" in journal(inst)["done"]
    s = json.loads(run(inst, "--status", "--json", host=host).stdout)
    assert s["moved"]["archive_id"] == aid


def test_switch_back_into_the_moved_folder(inst, usb, host, tmp_path):
    """Fix round, 6.2 "Moved folder" (14.3 #19's moved case): A --move, B
    imports it and gets a new API key, B --move, then A --import --replace:
    prechecks run (the pre-import point needs them), nothing of B is carried
    away by the older data (no carry_from_live), edge_data loses its move
    marker; an --abort after im-files puts A's files, stub and markers
    back."""
    add_edge_data(host, PROJECT)
    env_a = (inst / ".env").read_text()
    f1, _, _ = export(inst, usb, host, "--move")
    assert marker_of(host, PROJECT + "_edge_data")["op"] == "move"
    new = unpacked_release(tmp_path)
    r = run(new, "--import", str(f1), host=host)
    assert r.returncode == 0, out(r)
    keys_p = host.volume(TARGET + "_bridge_data") / "keys.json"
    keys = json.loads(keys_p.read_text())
    keys["keys"]["edge_new"] = dict(keys["keys"]["edge_pi1"], revoked=False)
    keys_p.write_text(json.dumps(keys))
    # B audits the key it created (F-D21: B's chain continues A's).
    add_audit(host, TARGET + "_bridge_data", "h2", action="key_create", target="edge_new")
    f2, hc2, _ = export(new, usb, host, "--move", name="back.sigrift-archive")
    # The switch back runs this release's installer in A (its release files
    # were updated, as an --export --from DIR does): A's VERSION is v0.2.0.
    (inst / "VERSION").write_text("v0.2.0\n")
    env_a = (inst / ".env").read_text()
    # A failed start after im-files, then --abort: A as it was, still moved.
    host.update(exit_on_up={"bridge": True})
    r = run(inst, "--import", str(f2), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 4, out(r)
    assert "prechecks" in journal(inst)["done"] and journal(inst).get("pre_state")
    # 14.3 #31 while the journal is active: after im-stage no key, after
    # im-unmark no decrypted .env, TLS key or promote/.
    jops = inst / ".sigrift" / "ops" / journal(inst)["id"]
    assert journal(inst)["state"] == "failed" and "im-unmark" in journal(inst)["done"]
    assert not (jops / "archive.key").exists() and (jops / "payload").is_dir()
    for rel in ("payload/files/.env", "payload/files/tls/key.pem", "payload/promote", "env.new"):
        assert not (jops / rel).exists(), rel
    host.update(exit_on_up={})
    r = run(inst, "--abort", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    assert (inst / ".env").read_text() == env_a
    assert not list(inst.glob("*.imported")) and not (inst / ".env.imported").exists()
    assert (inst / "docker-compose.yml").read_text().startswith(
        "# SigRift hold stub: this install was moved")
    assert (inst / ".sigrift" / "moved.json").exists()
    for v in ("bridge_data", "bridge_secrets", "edge_data"):
        assert marker_of(host, "%s_%s" % (PROJECT, v))["op"] == "move", v
    # The switch back.
    r = run(inst, "--import", str(f2), "--replace", "--confirm", PROJECT, "--expect", hc2, host=host)
    assert r.returncode == 0, out(r)
    live = json.loads((host.volume(PROJECT + "_bridge_data") / "keys.json").read_text())
    assert "edge_new" in live["keys"] and live["keys"]["edge_new"]["revoked"] is False
    for v in ("bridge_data", "bridge_secrets", "edge_data"):
        assert marker_of(host, "%s_%s" % (PROJECT, v)) is None, v
    assert not (inst / ".sigrift" / "moved.json").exists()
    assert not (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub")
    hr = json.loads((inst / ".sigrift" / "install.json").read_text())
    assert hr["history"][-1]["op"] == "import" and hr["history"][-1]["replaced"]["restore_point"]
    assert journal(inst)["relation"] == "archive-newer"
    assert [q["rules"]["carry_from_live"] for q in engine_requests(host, "import-rules")][-1] is False


def test_replace_abort_after_a_kill_inside_im_mark(inst, usb, host):
    """Fix round (10, im-mark row; 6.2 --replace): a --replace killed while
    im-mark wrote its markers (not journaled done): --abort removes this
    import's marker, so the replaced install starts again; then the
    --replace itself (with its prechecks and pre-import point)."""
    f, hc, _ = export(inst, usb, host)
    env0 = (inst / ".env").read_text()
    # The pre-import point fails (lc_rp_failed): the undo of im-stage, not a
    # bare unhold: no staging, key or payload left, the install back up.
    host.update(engine_faults={"snapshot-volume": {"rc": 1, "once": True}})
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 1 and "the pre-import restore point could not be taken" in out(r), out(r)
    assert journal(inst)["state"] == "aborted" and not list((inst / ".sigrift" / "ops").iterdir())
    for v in ("bridge_data", "bridge_secrets"):
        assert not list(host.volume("%s_%s" % (PROJECT, v)).glob(".sigrift-restore-*")), v
    assert (inst / ".env").read_text() == env0
    assert not (inst / "docker-compose.yml").read_text().startswith("# SigRift hold stub")
    host.update(engine_faults={"mark": {"after": 0, "once": True}})
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 4, out(r)
    j = journal(inst)
    assert j["next"] == "im-mark" and "im-mark" not in j["done"]
    assert marker_of(host, PROJECT + "_bridge_secrets")["op"] == "import"
    r = run(inst, "--abort", host=host)
    assert r.returncode == 0, out(r)
    for v in ("bridge_data", "bridge_secrets"):
        assert marker_of(host, "%s_%s" % (PROJECT, v)) is None, v
    assert journal(inst)["state"] == "aborted" and (inst / ".env").read_text() == env0
    running = {c["service"] for c in json.loads(host.state_path.read_text())["containers"]
               if c["project"] == PROJECT and c["state"] == "running"}
    assert {"bridge", "gateway"} <= running
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    j = journal(inst)
    assert j["state"] == "done" and j["restore_point"] and "prechecks" in j["done"]
    # F-D21: the plan relates the two copies by their audit chains (the same
    # data here) and lists what the replace drops.
    assert "  relation  the same data: the current data and the archive end at the same " \
        "audit entry 1" in r.stdout, r.stdout
    assert any(x.startswith("  DISCARDS  ") for x in r.stdout.splitlines())


def test_fresh_import_resumes_after_the_stage_and_aborts_after_the_start(inst, usb, host, tmp_path):
    """Fix round: ar-stage done (staged.json, its key unlinked) but im-stage
    not journaled: --resume goes on without the key (10: never
    M-AR-KEY-DAMAGED there); a fresh import aborted after its bridge started
    removes its containers, then its volumes, whose roots hold lifecycle
    entries only (6.2 --abort)."""
    f, hc, _ = export(inst, usb, host, "--move")
    new = unpacked_release(tmp_path)
    before = tree_digest(new)
    host.update(engine_faults={"import-rules": {"rc": 1, "once": True}}, volume_rm_in_use=True)
    r = run(new, "--import", str(f), host=host)
    assert r.returncode == 4, out(r)
    jp = new / ".sigrift" / "journal.json"
    j = json.loads(jp.read_text())
    ops = new / ".sigrift" / "ops" / j["id"]
    assert (ops / "staged.json").exists() and not (ops / "archive.key").exists()
    j["done"] = j["done"][:j["done"].index("im-stage")]
    j["next"] = "im-stage"
    jp.write_text(json.dumps(j))
    host.update(exit_on_up={"gateway": True})
    r = run(new, "--resume", host=host)
    assert r.returncode == 4 and "is damaged" not in r.stderr, out(r)
    assert journal(new)["bridge_started_at"]
    host.update(exit_on_up={})
    r = run(new, "--abort", "--confirm", TARGET, host=host)
    assert r.returncode == 0, out(r)
    st = json.loads(host.state_path.read_text())
    assert not [v for v in st["volumes"] if v["project"] == TARGET], st["volumes"]
    assert not [c for c in st["containers"] if c["project"] == TARGET]
    assert {k: v for k, v in tree_digest(new).items() if "/.sigrift/" not in k} == before


def test_quickstart_import_into_a_fresh_checkout(inst, usb, host, tmp_path):
    """Fix round (7.1, release -> source): scripts/quickstart.sh --import into a
    fresh checkout builds every image under the import's project, writes
    quickstart's own override for the mode (the gateway's ./tls mount; the
    archive's override stays .imported), the generated BRIDGE_LOCAL_NODE_KEY
    is in .env, and the host record names the checkout's commit."""
    f, hc, _ = export(inst, usb, host, "--move")
    d = source_checkout(tmp_path, "SigRift")
    head = tmp_path / "git-head"
    head.write_text("c" * 40 + "\n")
    git = host.bin / "git"
    git.write_text('#!/bin/sh\nwhile [ "$1" = -C ]; do shift 2; done\ncase "$1" in\n'
                   '  rev-parse) cat "$FAKE_GIT_HEAD" 2>/dev/null || exit 1 ;;\n'
                   '  *) exit 0 ;;\nesac\n')
    git.chmod(0o755)
    ids = dict((svc, "sha256:" + svc[0] * 64) for svc in ("bridge", "gateway", "edge"))
    host.update(compose_services="bridge\ngateway\nedge\n",
                build_images=dict((svc, "lab-" + svc) for svc in ids), build_ids=ids)
    host.clear_log()
    r = run_installer(d, "--import", str(f), "--project", "lab", "--expect", hc, host=host,
                      script="scripts/quickstart.sh", stdin=PASS + "\n",
                      env=dict(KDF, FAKE_GIT_HEAD=str(head)))
    assert r.returncode == 0, out(r)
    assert "compose -p lab build" in host.argvs(), host.argvs()
    ov = (d / "docker-compose.override.yml").read_text()
    assert ov.startswith("# Generated by scripts/quickstart.sh") and "./tls:/app/tls:ro" in ov
    assert (d / "docker-compose.override.yml.imported").exists()
    env = dict(x.split("=", 1) for x in (d / ".env").read_text().splitlines()
               if "=" in x and not x.startswith("#"))
    assert len(env.get("BRIDGE_LOCAL_NODE_KEY", "")) >= 32, env.keys()
    assert env["SIGRIFT_QUICKSTART_MODE"] == "dashboard-only" and env["COMPOSE_PROJECT_NAME"] == "lab"
    assert "BRIDGE_LOCAL_NODE_KEY" not in (d / ".env.imported").read_text()
    hr = json.loads(next((tmp_path / ".local" / "state").rglob("install.json")).read_text())
    assert hr["git_commit"] == "c" * 40 and hr["install_type"] == "source"
    assert hr["imported_from"]["archive_id"]



# ── F-D21: which copy is newer, decided from the audit chains ─────────────


def engine_requests(host, op):
    """The requests of every engine run of OP (no secret is in these)."""
    out = []
    for p in sorted(host.dir.glob("engine-stdin.*"), key=lambda p: int(p.suffix[1:])):
        data = p.read_bytes()
        n1 = data.index(b"\n")
        rest = data[n1 + 1 + int(data[:n1]):]
        n2 = rest.index(b"\n")
        req = json.loads(rest[n2 + 1: n2 + 1 + int(rest[:n2])])
        if req.get("op") == op:
            out.append(req)
    return out


def add_audit(host, vol, chain, action="key_revoke", target="ops"):
    """One audit entry with chain value CHAIN, as the bridge appends it."""
    db = sqlite3.connect(host.volume(vol) / "detections.db")
    db.execute("INSERT INTO audit_log (timestamp, action, target_id, hmac_chain) "
               "VALUES ('2026-11-28T10:00:00Z', ?, ?, ?)", (action, target, chain))
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.close()


def edit_keys(host, vol, fn):
    p = host.volume(vol) / "keys.json"
    k = json.loads(p.read_text())
    fn(k["keys"])
    p.write_text(json.dumps(k))


def keys_of(host, vol):
    return json.loads((host.volume(vol) / "keys.json").read_text())["keys"]


def save_volumes(host, project, to):
    for v in ("bridge_data", "bridge_secrets"):
        shutil.copytree(host.volume("%s_%s" % (project, v)), to / v, symlinks=True)


def put_back_volumes(host, project, saved):
    """The volumes as SAVED held them: the live copy older than an archive
    made of the same install after it."""
    for v in ("bridge_data", "bridge_secrets"):
        shutil.rmtree(host.volume("%s_%s" % (project, v)))
        shutil.copytree(saved / v, host.volume("%s_%s" % (project, v)), symlinks=True)


def no_ops_left(d):
    """No key, probe or pending directory of an import is left (G3)."""
    ops = d / ".sigrift" / "ops"
    return not ops.exists() or not list(ops.iterdir())


def plan_line(text, head):
    return next((x for x in text.splitlines() if x.startswith("  %-9s " % head)), "")


DATA = PROJECT + "_bridge_data"


def test_replace_of_newer_live_data_carries_its_revocation(inst, usb, host):
    """F-D21 live-newer (and the plan's DISCARDS): the current data continues
    the archive's audit chain (an audited revocation and a detection after the
    export). The plan names the relation, DISCARDS by count and kind and
    KEEPS; with data discarded the typed confirmation is needed (1b 2.3), and
    the confirmed replace carries the revocation into the archive's data."""
    f, hc, _ = export(inst, usb, host)
    add_audit(host, DATA, "h2")
    edit_keys(host, DATA, lambda k: k["ops"].update(revoked=True))
    db = sqlite3.connect(host.volume(DATA) / "detections.db")
    db.execute("INSERT INTO detections VALUES ('d3', '2026-11-28T10:00:00Z', 'pi-1', 'fm', '', "
               "1e8, 0.9, 10, -50, 0.1, 'default')")
    db.commit()
    db.close()
    r = run(inst, "--import", str(f), "--replace", "--dry-run", host=host)
    assert r.returncode == 0, out(r)
    assert plan_line(r.stdout, "relation").endswith(
        "the current data is newer: it continues the archive's audit chain (1 -> 2); what was "
        "revoked, disabled or deleted here since the archive was made is carried into the "
        "archive's data"), r.stdout
    disc = plan_line(r.stdout, "DISCARDS")
    assert "what the current data has that the archive lacks: new rows: detections 1" in disc, disc
    assert "1 audit entries" in disc and "0 API keys" in disc, disc
    assert "1 API keys stay revoked" in plan_line(r.stdout, "KEEPS"), r.stdout
    assert "type %s when asked, or add --confirm %s" % (PROJECT, PROJECT) in plan_line(r.stdout, "confirm")
    env0, compose0 = (inst / ".env").read_text(), (inst / "docker-compose.yml").read_text()
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3 and "there is no terminal to ask you to type the project" in r.stderr, out(r)
    assert "Next: bash install-release.sh --import %s --replace --confirm %s" % (f, PROJECT) in r.stderr
    assert changing_calls(host) == [] and no_ops_left(inst)
    assert (inst / ".env").read_text() == env0 and (inst / "docker-compose.yml").read_text() == compose0
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    assert journal(inst)["relation"] == "live-newer"
    assert [q["rules"]["carry_from_live"] for q in engine_requests(host, "import-rules")] == [True]
    assert keys_of(host, DATA)["ops"]["revoked"] is True
    # The archive's data is what came back: the detection of the current
    # data is gone (in the replaced copy and the pre-import point).
    db = sqlite3.connect(host.volume(DATA) / "detections.db")
    assert db.execute("SELECT COUNT(*) FROM detections WHERE detection_id = 'd3'").fetchone()[0] == 0
    db.close()


def test_replace_by_a_newer_archive_keeps_a_key_created_after_the_live_copy(inst, usb, host, tmp_path):
    """F-D21 archive-newer: a folder exported from without --move, replaced
    later by an archive of the same install made after it (its chain
    continues the current one, checked in the staged copy). Nothing is
    carried, so a key created after the live copy stays. F-D22: the bridge
    writes no audit entry for an API key, so a key the archive has and the
    current data lacks, made after the last common entry (or with no
    creation time), may also be one revoked here: the plan names it under
    UNRECORDED and the typed confirmation is needed; nothing is discarded."""
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "live-copy")
    add_audit(host, DATA, "h2", action="key_create", target="k_new")
    edit_keys(host, DATA, lambda k: k.__setitem__("k_new", {"hash": "n-hash", "salt": "n-salt",
                                                            "role": "sensor"}))
    f, hc, _ = export(inst, usb, host, name="newer.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "live-copy")
    assert "k_new" not in keys_of(host, DATA)
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3 and "there is no terminal to ask you to type the project" in r.stderr, out(r)
    assert changing_calls(host) == [] and no_ops_left(inst)
    assert plan_line(r.stdout, "relation").endswith(
        "the archive is newer: its audit head 2 is above the current 1; the staged copy must "
        "hold the current head entry (checked before anything changes); nothing is carried"), \
        r.stdout
    assert plan_line(r.stdout, "DISCARDS").endswith(
        "nothing in the archive's export record; rows are matched against the staged copy "
        "before the stop"), r.stdout
    assert plan_line(r.stdout, "KEEPS").endswith("nothing of the current data is carried into "
                                                 "the archive's")
    assert plan_line(r.stdout, "UNRECORDED").startswith(
        "  UNRECORDED in the archive and not here, made after audit entry 1 (the last common "
        "one) or with no creation time: 1 API keys (k_new), 0 client certificates, 0 protocol "
        "decryption keys;"), r.stdout
    assert "type %s when asked" % PROJECT in plan_line(r.stdout, "confirm")
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    assert journal(inst)["relation"] == "archive-newer"
    assert [q["rules"]["carry_from_live"] for q in engine_requests(host, "import-rules")] == [False]
    assert keys_of(host, DATA)["k_new"]["hash"] == "n-hash"


def test_replace_by_the_same_data_carries_nothing(inst, usb, host):
    """F-D21 same: equal audit heads, no carry needed; nothing is discarded,
    so the replace runs without the typed confirmation."""
    f, hc, _ = export(inst, usb, host)
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 0, out(r)
    assert plan_line(r.stdout, "relation").endswith(
        "the same data: the current data and the archive end at the same audit entry 1; nothing "
        "needs to be carried"), r.stdout
    assert journal(inst)["relation"] == "same"
    assert [q["rules"]["carry_from_live"] for q in engine_requests(host, "import-rules")] == [False]


def test_replace_of_diverged_data_refuses_and_the_opt_out_needs_the_confirmation(inst, usb, host, tmp_path):
    """F-D21 diverged: the current data and the archive each hold an audit
    entry 2 the other lacks. The --replace refuses before any change with one
    Next line (the opt-out, 1b's --no-carry-revocations); the opt-out needs
    the typed confirmation (1b 2.3: an override flag), and with it the
    archive's data comes in as it is (sessions ended, nothing carried)."""
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "parted")
    add_audit(host, DATA, "h2a")
    f, hc, _ = export(inst, usb, host, name="other.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "parted")
    add_audit(host, DATA, "h2b")
    env0 = (inst / ".env").read_text()
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    assert "each hold audit entries the other lacks (audit entry 2 differs" in r.stderr, out(r)
    nxt = [x for x in r.stderr.splitlines() if x.startswith("Next: ")]
    assert nxt == ["Next: bash install-release.sh --import %s --replace --no-carry-revocations" % f]
    assert r.stderr.rstrip().endswith("Nothing was changed.")
    assert changing_calls(host) == [] and no_ops_left(inst)
    assert (inst / ".env").read_text() == env0
    # The opt-out without the confirmation: refused, nothing changed.
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--no-carry-revocations", host=host)
    assert r.returncode == 3 and "there is no terminal to ask you to type the project" in r.stderr, out(r)
    assert "Next: bash install-release.sh --import %s --replace --no-carry-revocations --confirm %s" % (
        f, PROJECT) in r.stderr
    assert changing_calls(host) == [] and (inst / ".env").read_text() == env0
    assert "diverged: audit entry 2 differs between the current data and the archive; " \
           "--no-carry-revocations: nothing is carried" in plan_line(r.stdout, "relation"), r.stdout
    # With it: the archive's data as it is, nothing carried.
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--no-carry-revocations", "--confirm", PROJECT,
            host=host)
    assert r.returncode == 0, out(r)
    rules = engine_requests(host, "import-rules")
    assert [(q["rules"]["carry_from_live"], q["rules"]["no_carry"]) for q in rules] == [(False, True)]
    j = journal(inst)
    assert j["relation"] == "diverged" and j["flags"]["no_carry"] is True and j["confirmed"] is True


def test_replace_whose_staged_copy_lacks_the_current_head_refuses_before_the_stop(inst, usb, host, tmp_path):
    """F-D21: the archive's head (3) is above the current one (2), so the plan
    can only say "the archive is newer" once the staged copy shows the current
    head entry; its entry 2 differs, so im-relate refuses while the current
    stack still serves: the staging undone, the stack never stopped."""
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "parted")
    add_audit(host, DATA, "h2a")
    add_audit(host, DATA, "h3a")
    f, hc, _ = export(inst, usb, host, name="further.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "parted")
    add_audit(host, DATA, "h2b")
    keys0 = keys_of(host, DATA)
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    text = out(r)
    assert "each hold audit entries the other lacks (audit entry 2 differs" in text, text
    assert "Undone: the staging and the files it wrote" in text
    assert text.rstrip().endswith("Nothing was changed.")
    assert not [a for a in host.argvs() if re.match(r"compose (.* )?stop\b", a)], host.argvs()
    j = journal(inst)
    assert j["state"] == "aborted" and "im-stage" in j["done"] and "im-relate" not in j["done"]
    for v in ("bridge_data", "bridge_secrets"):
        assert not list(host.volume("%s_%s" % (PROJECT, v)).glob(".sigrift-restore-*")), v
    assert no_ops_left(inst)
    assert keys_of(host, DATA) == keys0


def test_replace_with_an_unreadable_audit_chain_refuses(inst, usb, host):
    """F-D21 unknown: the current head entry has no chain value, or the
    current audit log cannot be read: refused before any change (never a
    guess), with the opt-out as the one Next line."""
    f, hc, _ = export(inst, usb, host)
    db = sqlite3.connect(host.volume(DATA) / "detections.db")
    db.execute("UPDATE audit_log SET hmac_chain = '' WHERE id = 1")
    db.commit()
    db.close()
    for needle in ("(the current audit head 1 has no chain value)",
                   "(the current audit log cannot be read)"):
        host.clear_log()
        r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
        assert r.returncode == 3, out(r)
        assert "the installer cannot tell whether the current data or the archive is the newer " \
               "copy " + needle in r.stderr, out(r)
        assert [x for x in r.stderr.splitlines() if x.startswith("Next: ")] == [
            "Next: bash install-release.sh --import %s --replace --no-carry-revocations" % f]
        assert changing_calls(host) == [] and no_ops_left(inst)
        st = json.loads(host.state_path.read_text())
        st["data"][DATA]["audit_chain"] = {"chain": "unreadable", "head_id": None,
                                           "head_tag": None, "at": {}}
        host.state_path.write_text(json.dumps(st))


def test_a_kill_inside_im_relate_resumes_to_the_same_decision(inst, usb, host):
    """F-D21, 10: a kill of the step's engine run inside im-relate (after
    im-stage, before the stop) leaves the journal at im-relate and the stack
    serving; --resume runs it again and the import carries as planned."""
    f, hc, _ = export(inst, usb, host)
    add_audit(host, DATA, "h2")
    edit_keys(host, DATA, lambda k: k["ops"].update(revoked=True))
    host.update(on_call=[{"match": "--name sigrift-lc-%s-ar-stage-" % PROJECT,
                          "set": {"engine_faults": {"state": {"after": 0, "once": True}}}}])
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode in (1, 4), out(r)
    j = journal(inst)
    assert j["next"] == "im-relate" and "im-stage" in j["done"] and j["relation"] == "live-newer", j
    assert not [a for a in host.argvs() if re.match(r"compose (.* )?stop\b", a)]
    host.update(on_call=[], engine_faults={})
    r = run(inst, "--resume", host=host)
    assert r.returncode == 0, out(r)
    j = journal(inst)
    assert j["state"] == "done" and j["relation"] == "live-newer"
    assert keys_of(host, DATA)["ops"]["revoked"] is True



def test_data_audited_after_the_plan_is_checked_again_once_the_stack_stopped(inst, usb, host):
    """F-D21 (1b rb-guard's rules): the plan found the same data (no
    confirmation needed), then the current stack audited a revocation before
    the stop. im-guard relates the quiesced data again (now the newer copy),
    and, the run unconfirmed, refuses late with the undo (the stack started
    again) and the current data as the stack left it."""
    f, hc, _ = export(inst, usb, host)
    db = str(host.volume(DATA) / "detections.db")
    late = [{"match": r"^compose (.* )?stop\b",
             "sql": {db: "INSERT INTO audit_log (timestamp, action, target_id, hmac_chain) "
                         "VALUES ('2026-11-28T11:00:00Z', 'key_revoke', 'ops', 'h2');"},
             "write": {str(host.volume(DATA) / "keys.json"): json.dumps(
                 {"keys": dict(keys_of(host, DATA), ops=dict(keys_of(host, DATA)["ops"],
                                                              revoked=True))})}}]
    host.update(on_call=late)
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3, out(r)
    assert "  confirm   not needed" in r.stdout
    assert "data arrived after the import was planned" in out(r) and "without a confirmation" in out(r)
    assert out(r).rstrip().endswith("Nothing was changed.")
    j = journal(inst)
    assert j["state"] == "aborted" and "im-guard" not in j["done"] and j["relation"] == "live-newer", j
    running = {c["service"] for c in json.loads(host.state_path.read_text())["containers"]
               if c["project"] == PROJECT and c["state"] == "running"}
    assert {"bridge", "gateway"} <= running
    # The current data is as the stack left it (the revocation not lost).
    assert keys_of(host, DATA)["ops"]["revoked"] is True


def test_replace_of_another_install_lists_all_its_data_and_carries_nothing(inst, usb, host, tmp_path):
    """F-D21: a --replace whose target holds another install (no record of
    the archive's install id): relation other-install, DISCARDS is all of its
    data, nothing is carried, so the typed confirmation is needed; confirmed,
    the archive's data replaces it as it is."""
    f, hc, _ = export(inst, usb, host, "--move")
    other = release_install(host, tmp_path, name="sigrift-other", pinned=True)
    seed_volume(host, "sigrift-other")
    edit_keys(host, "sigrift-other_bridge_data", lambda k: k["ops"].update(revoked=True))
    host.clear_log()
    r = run(other, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3 and "there is no terminal to ask you to type the project" in r.stderr, out(r)
    assert plan_line(r.stdout, "relation").endswith(
        "another install than the archive's is replaced; nothing of it is carried"), r.stdout
    assert plan_line(r.stdout, "DISCARDS").startswith(
        "  DISCARDS  all of the current install's data: rows: "), r.stdout
    assert "3 API keys" in plan_line(r.stdout, "DISCARDS") and "2 users" in plan_line(r.stdout, "DISCARDS")
    assert changing_calls(host) == [] and no_ops_left(other)
    host.clear_log()
    r = run(other, "--import", str(f), "--replace", "--confirm", "sigrift-other", host=host)
    assert r.returncode == 0, out(r)
    assert journal(other)["relation"] == "other-install"
    assert [q["rules"]["carry_from_live"] for q in engine_requests(host, "import-rules")] == [False]
    assert keys_of(host, "sigrift-other_bridge_data")["ops"].get("revoked") is not True


# ── F-D22: what changes without an audit entry, rows both copies wrote ───


def add_detection(host, vol, did, ts):
    db = sqlite3.connect(host.volume(vol) / "detections.db")
    db.execute("INSERT INTO detections VALUES (?, ?, 'pi-1', 'fm', '', 1e8, 0.9, 10, -50, 0.1, "
               "'default')", (did, ts))
    db.commit()
    db.close()


def has_detection(host, vol, did):
    db = sqlite3.connect(host.volume(vol) / "detections.db")
    try:
        return db.execute("SELECT COUNT(*) FROM detections WHERE detection_id = ?",
                          (did,)).fetchone()[0]
    finally:
        db.close()


def stack_running(host, project=PROJECT):
    return {c["service"] for c in json.loads(host.state_path.read_text())["containers"]
            if c["project"] == project and c["state"] == "running"}


def test_replace_by_the_same_data_refuses_a_revocation_no_audit_entry_records(inst, usb, host):
    """F-D22 (review R1): the bridge revokes an API key without an audit
    entry, so the heads stay equal (same) though the current data took access
    away. Importing the archive as it is would make the key work again: the
    replace refuses before any change, with the opt-out as the one Next line;
    the opt-out lists it under COMES BACK and needs the typed confirmation."""
    f, hc, _ = export(inst, usb, host)
    edit_keys(host, DATA, lambda k: k["ops"].update(revoked=True))
    env0 = (inst / ".env").read_text()
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3, out(r)
    assert "the current data revoked, disabled or deleted 1 API keys (ops), 0 client " \
           "certificates, 0 protocol decryption keys that the archive still has, and no audit " \
           "entry records it" in r.stderr, out(r)
    assert [x for x in r.stderr.splitlines() if x.startswith("Next: ")] == [
        "Next: bash install-release.sh --import %s --replace --no-carry-revocations" % f]
    assert changing_calls(host) == [] and no_ops_left(inst)
    assert (inst / ".env").read_text() == env0 and keys_of(host, DATA)["ops"]["revoked"] is True
    # The dry run shows it and never refuses for it.
    r = run(inst, "--import", str(f), "--replace", "--dry-run", host=host)
    assert r.returncode == 0, out(r)
    assert plan_line(r.stdout, "UNRECORDED").startswith(
        "  UNRECORDED revoked, disabled or deleted here with no audit entry: 1 API keys (ops)"), r.stdout
    assert "  COMES BACK (only with --no-carry-revocations): 1 API keys (ops), 0 client " \
           "certificates" in r.stdout, r.stdout
    # The opt-out without the confirmation: refused, nothing changed.
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--no-carry-revocations", host=host)
    assert r.returncode == 3 and "there is no terminal to ask you to type the project" in r.stderr, out(r)
    assert "  COMES BACK (--no-carry-revocations given): 1 API keys (ops), 0 client " \
           "certificates" in r.stdout, r.stdout
    assert changing_calls(host) == [] and keys_of(host, DATA)["ops"]["revoked"] is True
    # With it: the archive's data as it is (the key active again, as typed).
    r = run(inst, "--import", str(f), "--replace", "--no-carry-revocations", "--confirm", PROJECT,
            host=host)
    assert r.returncode == 0, out(r)
    assert journal(inst)["relation"] == "same" and journal(inst)["flags"]["no_carry"] is True
    assert keys_of(host, DATA)["ops"].get("revoked") is not True


def test_replace_by_a_newer_archive_refuses_a_key_deleted_here_that_existed_before(inst, usb, host, tmp_path):
    """F-D22 (review R2): archive-newer, and the current (older) copy deleted
    an API key without an audit entry. The key was made before the last
    common audit entry (its created_at), so it existed in both copies and the
    current data deleted it: importing as it is would bring it back, so the
    replace refuses before any change (a key made after that entry would be
    named under UNRECORDED instead: the archive's copy may have made it)."""
    edit_keys(host, DATA, lambda k: k["ops"].update(created_at="2026-11-01T00:00:00+00:00"))
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "live-copy")
    add_audit(host, DATA, "h2", action="user_login", target="admin")
    f, hc, _ = export(inst, usb, host, name="newer.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "live-copy")
    edit_keys(host, DATA, lambda k: k.pop("ops"))
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    assert "the current data revoked, disabled or deleted 1 API keys (ops)" in r.stderr, out(r)
    assert [x for x in r.stderr.splitlines() if x.startswith("Next: ")] == [
        "Next: bash install-release.sh --import %s --replace --no-carry-revocations" % f], r.stderr
    assert changing_calls(host) == [] and no_ops_left(inst) and "ops" not in keys_of(host, DATA)


def test_a_revocation_no_audit_entry_records_after_the_plan_is_caught_once_the_stack_stopped(inst, usb, host):
    """F-D22 (review R6): the plan finds the same data, then an API key is
    revoked without an audit entry before the stop. im-guard compares the
    quiesced data again: a late refusal with the undo, the current stack
    started again and the revocation kept. Its Next line keeps every option
    as typed (the --expect pin too, review finding 5)."""
    f, hc, _ = export(inst, usb, host)
    late = [{"match": r"^compose (.* )?stop\b",
             "write": {str(host.volume(DATA) / "keys.json"): json.dumps(
                 {"keys": dict(keys_of(host, DATA), ops=dict(keys_of(host, DATA)["ops"],
                                                              revoked=True))})}}]
    host.update(on_call=late)
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--regenerate-tls", "--expect", hc, host=host)
    assert r.returncode == 3, out(r)
    assert "  confirm   not needed" in r.stdout
    assert "the current data revoked, disabled or deleted 1 API keys (ops)" in out(r), out(r)
    assert [x for x in out(r).splitlines() if x.startswith("Next: ")] == [
        "Next: bash install-release.sh --import %s --replace --regenerate-tls --expect %s "
        "--no-carry-revocations" % (f, hc)], out(r)
    assert out(r).rstrip().endswith("Nothing was changed.")
    j = journal(inst)
    assert j["state"] == "aborted" and "im-guard" not in j["done"], j
    assert {"bridge", "gateway"} <= stack_running(host)
    assert keys_of(host, DATA)["ops"]["revoked"] is True


def test_a_second_replace_by_the_same_archive_keeps_the_first_ones_carry(inst, usb, host):
    """F-D22 (review R3): a live-newer replace that carried a revocation
    records it in the imported audit chain (installer_import, its target the
    import id), so a second replace by the same archive finds the current
    data the newer copy again and carries it again. A kill of that step's
    engine run (after it wrote the entry) resumes to one entry."""
    host.update(engine_sys_path={"ops": ["audit-append"], "path": [str(ROOT_SRC)]})
    f, hc, _ = export(inst, usb, host)
    add_audit(host, DATA, "h2")
    edit_keys(host, DATA, lambda k: k["ops"].update(revoked=True))
    host.update(engine_faults={"audit-append": {"after": 0, "once": True}})
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode in (1, 4), out(r)
    j = journal(inst)
    assert j["next"] == "im-carry" and j["relation"] == "live-newer", j
    host.update(engine_faults={})
    r = run(inst, "--resume", host=host)
    assert r.returncode == 0, out(r)
    j = journal(inst)
    assert j["import_audit"]["written"] is True and keys_of(host, DATA)["ops"]["revoked"] is True
    db = sqlite3.connect(host.volume(DATA) / "detections.db")
    rows = db.execute("SELECT id, action, target_id, operator FROM audit_log ORDER BY id").fetchall()
    db.close()
    assert [x[1:] for x in rows] == [("dismiss", "d1", ""),
                                     ("installer_import", j["id"], "install-release.sh")], rows
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 0, out(r)
    assert journal(inst)["relation"] == "live-newer"
    assert keys_of(host, DATA)["ops"]["revoked"] is True


def test_rows_the_older_copy_wrote_after_the_parting_are_found_in_the_staged_copy(inst, usb, host, tmp_path):
    """F-D22 (review R4): archive-newer, and the current copy kept scanning
    after the copies parted: its detection sits below the archive's mark, so
    the plan (the export point's marks) cannot see it. Once staged, the rows
    are matched against the staged copy: the unconfirmed replace refuses
    while the current stack still serves, the detection kept."""
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "live-copy")
    add_audit(host, DATA, "h2", action="user_login", target="admin")
    add_detection(host, DATA, "new-a", "2026-11-28T10:00:00Z")
    add_detection(host, DATA, "new-b", "2026-11-28T10:01:00Z")
    f, hc, _ = export(inst, usb, host, name="newer.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "live-copy")
    add_detection(host, DATA, "old-only", "2026-11-28T09:00:00Z")
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", host=host)
    assert r.returncode == 3, out(r)
    assert plan_line(r.stdout, "DISCARDS").endswith(
        "nothing in the archive's export record; rows are matched against the staged copy "
        "before the stop"), r.stdout
    assert "(1 detection)" in out(r) and "without a confirmation" in out(r), out(r)
    assert [x for x in out(r).splitlines() if x.startswith("Next: ")] == [
        "Next: bash install-release.sh --import %s --replace --confirm %s" % (f, PROJECT)], out(r)
    assert not [a for a in host.argvs() if re.match(r"compose (.* )?stop\b", a)], host.argvs()
    j = journal(inst)
    assert j["state"] == "aborted" and "im-relate" not in j["done"] and j["relation"] == "archive-newer"
    assert has_detection(host, DATA, "old-only") == 1 and no_ops_left(inst)


def test_live_newer_names_a_key_absent_here_made_after_the_common_entry(inst, usb, host, tmp_path):
    """F-D22 (review R5): live-newer, and the archive's copy made an API key
    without an audit entry after the copies parted. The carry cannot tell it
    from a key deleted here since (the bridge's DELETE /keys leaves no trace),
    so it takes access away (leaves it out), but the plan names it under
    UNRECORDED, does not count it as revoked here, and needs the typed
    confirmation."""
    export(inst, usb, host, name="first.sigrift-archive")
    save_volumes(host, PROJECT, tmp_path / "live-copy")
    edit_keys(host, DATA, lambda k: k.__setitem__("k_y", {"hash": "y-hash", "salt": "y-salt",
                                                          "role": "sensor"}))
    f, hc, _ = export(inst, usb, host, name="newer.sigrift-archive")
    put_back_volumes(host, PROJECT, tmp_path / "live-copy")
    add_audit(host, DATA, "h2", action="user_login", target="admin")
    r = run(inst, "--import", str(f), "--replace", "--dry-run", host=host)
    assert r.returncode == 0, out(r)
    assert "the current data is newer" in plan_line(r.stdout, "relation"), r.stdout
    assert "0 API keys stay revoked or deleted" in plan_line(r.stdout, "KEEPS"), r.stdout
    assert plan_line(r.stdout, "UNRECORDED").startswith(
        "  UNRECORDED absent here and made after audit entry 1 (the last common one) or with no "
        "creation time: 1 API keys (k_y), 0 client certificates, 0 protocol decryption keys; "
        "deleted here since, or made in the archive's copy"), r.stdout
    assert "type %s when asked" % PROJECT in plan_line(r.stdout, "confirm")


def test_a_staged_copy_whose_head_entry_is_not_the_archives_refuses_before_the_stop(inst, usb, host):
    """F-D22 (review finding 6): the same audit head id, but the staged
    copy's head entry has another chain value than the archive's manifest
    names: whatever the relation, the import refuses while the current stack
    still serves (unknown), never carries or swaps it in."""
    f, hc, _ = export(inst, usb, host)
    staged = str(host.volume(DATA) / ".sigrift-restore-2*" / "detections.db")
    host.update(on_call=[{"match": ".", "sql": {
        staged: "UPDATE audit_log SET hmac_chain = 'forged' WHERE id = 1;"}}])
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    assert "(the staged copy's audit head is not the archive's)" in out(r), out(r)
    assert not [a for a in host.argvs() if re.match(r"compose (.* )?stop\b", a)], host.argvs()
    j = journal(inst)
    assert j["state"] == "aborted" and "im-relate" not in j["done"], j
    assert no_ops_left(inst) and {"bridge", "gateway"} <= stack_running(host)


def test_a_staged_head_entry_changed_after_im_relate_is_caught_by_im_guard(inst, usb, host):
    """F-D22 (review finding 6, im-guard's own check): the staged copy's head
    entry changes once im-relate has passed (at the stop). im-guard compares
    the staged head's chain value (its tag) with the manifest's, not only its
    id, and refuses late with the undo, the current stack started again."""
    f, hc, _ = export(inst, usb, host)
    staged = str(host.volume(DATA) / ".sigrift-restore-2*" / "detections.db")
    host.update(on_call=[{"match": r"^compose (.* )?stop\b", "sql": {
        staged: "UPDATE audit_log SET hmac_chain = 'forged' WHERE id = 1;"}}])
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    assert "the staged copy's audit head entry is not the one the archive's manifest names" in out(r), out(r)
    j = journal(inst)
    assert j["state"] == "aborted" and "im-relate" in j["done"] and "im-guard" not in j["done"], j
    assert no_ops_left(inst) and {"bridge", "gateway"} <= stack_running(host)


def test_replace_by_the_same_data_refuses_when_the_current_keys_cannot_be_read(inst, usb, host):
    """F-D22: with no carry (same), what was revoked here without an audit
    entry is read from keys.json; when it cannot be read, the replace refuses
    before any change (never a guess), the opt-out on the second line."""
    f, hc, _ = export(inst, usb, host)
    (host.volume(DATA) / "keys.json").write_text("{not json")
    host.clear_log()
    r = run(inst, "--import", str(f), "--replace", "--confirm", PROJECT, host=host)
    assert r.returncode == 3, out(r)
    assert "the current keys.json and keys.json.bak cannot be read, so the import cannot check " \
           "what was revoked or deleted here without an audit entry" in r.stderr, out(r)
    assert "--replace --no-carry-revocations." in r.stderr
    assert changing_calls(host) == [] and no_ops_left(inst)
