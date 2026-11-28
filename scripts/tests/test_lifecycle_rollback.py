"""Restore points and rollback end to end (Phase 1b PART B, phase1b-spec 11.5).

The installers run for real against FakeDockerHost (lifecycle_fakes.py),
whose framed engine runs are the real state engine on real volume
directories. To keep the serial CI step short, each worker builds two
worlds once (a v0.1.0 install, and the same install upgraded to v0.2.0 by
the new installer) and every test starts from a byte copy of one of them
at the same path; a test then runs one scenario and checks every effect of
it (several 11.5 items each). The in-process crash matrices are PART A's
(test_lifecycle_state_engine.py, test_lifecycle_state_tool.py); here one
interruption per step class.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
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
    changing_calls,
    release_install,
    run_installer,
    seed_tree,
    seed_volume,
    shared_block,
    tree_digest,
    unpacked_release,
)

ROOT = Path(__file__).resolve().parents[2]
V010_INSTALLER = ROOT / "scripts" / "tests" / "fixtures" / "install-release-v0.1.0.sh"
PROJECT = "sigrift-v010"
NEW_BRIDGE = "ghcr.io/sigrift/sigrift-bridge:v0.2.0"
NEW_GATEWAY = "ghcr.io/sigrift/sigrift-gateway:v0.2.0"
ENV = {"SIGRIFT_SNAPSHOT_RESERVE": "1M"}
STUB = "# SigRift hold stub"
# The new release's bridge fails to start: its .env (and only its) has the
# keystore key the upgrade adds; the restored v0.1.0 .env has none.
FAIL_NEW_BRIDGE = {r"compose up .*bridge$": {"rc": 1, "env_has": "BRIDGE_KEYSTORE_KEY"}}
# One worker per module builds the worlds once (--dist loadgroup in CI).
pytestmark = [pytest.mark.timeout(300), pytest.mark.xdist_group("lifecycle-rollback")]


def t0_compose(version="v0.1.0") -> str:
    """docker-compose.yml as the v0.1.0 installer wrote it (template t0)."""
    body = re.search(r"cat > docker-compose\.yml <<EOF\n(.*?)\nEOF\n", V010_INSTALLER.read_text(),
                     re.S).group(1)
    return subprocess.run([BASH, "-c", "VERSION=%s OWNER=sigrift PORT=8444\ncat <<EOF\n%s\nEOF\n"
                           % (version, body)], capture_output=True, text=True, check=True).stdout


def seed(data: Path, secrets: Path) -> None:
    """PART A's seed, with TOTP secrets the install's MFA key really decrypts
    (when cryptography is there; else MFA is simply not checked)."""
    seed_tree(data, secrets)
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return
    token = "fernet:" + Fernet(KEY_A.encode()).encrypt(b"JBSWY3DPEHPK3PXP").decode()
    with sqlite3.connect(data / "detections.db") as c:
        c.execute("UPDATE users SET totp_secret = ? WHERE username = 'admin'", (token,))


def stamp(installer: Path, release: str) -> None:
    """release.yml's stamping step (phase1b 5.2) on an installer copy."""
    text = installer.read_text()
    assert text.count("\nINSTALLER_RELEASE=dev\n") == 1
    installer.write_text(text.replace("\nINSTALLER_RELEASE=dev\n", "\nINSTALLER_RELEASE=%s\n"
                                      % release))


class World:
    """One fake host, built once per worker and restored for every test."""

    def __init__(self, base: Path):
        self.work = base / "rb-work"
        if self.work.exists():
            shutil.rmtree(self.work)
        self.work.mkdir()
        self.stores = {}
        self.host = FakeDockerHost(self.work)
        self.host.update(registry={NEW_BRIDGE: {"newest_migration": 56}, NEW_GATEWAY: {}})
        self.d = release_install(self.host, self.work)
        (self.d / "docker-compose.yml").write_text(t0_compose())
        shutil.copy(V010_INSTALLER, self.d / "install-release.sh")
        seed_volume(self.host, PROJECT, seed)
        self.new = unpacked_release(self.work)
        stamp(self.new / "install-release.sh", "v0.2.0")
        self.t0 = (self.d / "docker-compose.yml").read_bytes()
        self.env0 = (self.d / ".env").read_text()
        self.save("fresh", base)
        self.upgrade = run_installer(self.new, host=self.host, env=ENV)
        assert self.upgrade.returncode == 0, self.upgrade.stdout + self.upgrade.stderr
        self.save("upgraded", base)

    def save(self, name, base):
        store = base / ("rb-store-" + name)
        if store.exists():
            shutil.rmtree(store)
        shutil.copytree(self.work, store, symlinks=True)
        self.stores[name] = store

    def restore(self, name):
        shutil.rmtree(self.work)
        shutil.copytree(self.stores[name], self.work, symlinks=True)
        self.host.load()
        self.host.clear_log()
        return self

    def run(self, *args, folder=None, env=None, **kw):
        return run_installer(folder or self.d, *args, host=self.host, env=dict(ENV, **(env or {})),
                             **kw)

    def vol(self, v="bridge_data") -> Path:
        return self.host.volume("%s_%s" % (PROJECT, v))

    def db(self):
        return sqlite3.connect(self.vol() / "detections.db")

    def journal(self) -> dict:
        return json.loads((self.d / ".sigrift" / "journal.json").read_text())

    def record(self) -> dict:
        return json.loads((self.d / ".sigrift" / "install.json").read_text())

    def volume_record(self) -> dict:
        return json.loads((self.vol() / ".sigrift-install.json").read_text())

    def digest(self) -> dict:
        """The install folder (but its .sigrift/ bookkeeping) and both volumes
        (but SQLite's shared-memory index, which every reader rewrites)."""
        out = tree_digest(self.d, self.vol(), self.vol("bridge_secrets"))
        return dict((k, v) for k, v in out.items() if "/.sigrift/" not in k
                    and not k.endswith("-shm"))

    def replaced(self) -> dict:
        return dict((v, sorted(p.name for p in self.vol(v).glob(".sigrift-replaced-*")))
                    for v in ("bridge_data", "bridge_secrets"))

    def points(self, kind="full") -> list:
        root = self.d / ".sigrift" / "snapshots"
        return sorted(p.name for p in root.iterdir() if p.name.endswith("-" + kind)) \
            if root.exists() else []


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    return World(tmp_path_factory.getbasetemp())


@pytest.fixture
def upgraded(world):
    return world.restore("upgraded")


@pytest.fixture
def fresh(world):
    return world.restore("fresh")


def env_of(d: Path) -> dict:
    return dict(line.split("=", 1) for line in (d / ".env").read_text().splitlines()
                if "=" in line and not line.startswith("#"))


def tail(r, n=2):
    return r.stderr.rstrip().splitlines()[-n:]


def out_tail(r, n=2):
    """The last lines a detached child wrote: the follower prints its log on stdout."""
    return r.stdout.rstrip().splitlines()[-n:]


def no_secret_in_argv(w: World):
    for c in w.host.calls():
        joined = " ".join(c["argv"])
        for s in SECRET_VALUES:
            assert s not in joined, joined[:200]


# ── 11.5 #1, #43, #47: the upgrade's restore point, its numbered lines, JSON ──


def test_upgrade_takes_a_full_restore_point_and_reports_it_as_json(world):
    out = world.upgrade.stdout
    for n, text in ((1, "preflight ok"), (2, "images pulled"), (3, "restore point "),
                    (4, "installer and release files installed"), (5, "stack stopped and held"),
                    (6, "database checked (quick_check ok, checkpointed)"), (7, "restore point "),
                    (8, "compose regenerated from the v0.2.0 template, VERSION and .env switched"),
                    (9, "bridge healthy"), (10, "schema 56")):
        assert "==> [%d/10] %s" % (n, text) in out, (n, out)
    assert "    Undo it: cd %s && bash install-release.sh --rollback" % world.d.resolve() in out
    assert "NOTE: this installer comes from a checkout" not in world.upgrade.stderr  # stamped
    w = world.restore("upgraded")
    [rp] = w.points()
    j = w.journal()
    assert j["steps"][:6] == ["snapshot", "installer", "stop", "hold", "prechecks", "restore-point"]
    assert j["restore_point"] == rp and j["install_id"] == w.record()["install_id"]
    man = json.loads((w.d / ".sigrift" / "snapshots" / rp / "manifest.json").read_text())
    assert (man["from_version"], man["to_version"], man["reason"]) == ("v0.1.0", "v0.2.0", "upgrade")
    assert man["installer_release"] == "v0.2.0" and man["install_id"] == j["install_id"]
    assert man["compose_template_sha256"] and man["files_snapshot"] == j["snapshot"]
    assert (w.d / ".sigrift" / "rp.key").stat().st_mode & 0o777 == 0o600
    rec = w.record()
    assert rec["installer"]["release"] == "v0.2.0" and rec["compose_template"] == "t1"
    assert rec["history"][-1]["restore_point"] == rp
    assert rec["history"][-1]["env_written"].keys() == {"BRIDGE_KEYSTORE_KEY"}
    # --status --json and --list-snapshots --json (3.8): the drill's fields.
    r = w.run("--status", "--json")
    assert r.returncode == 0, r.stderr
    s = json.loads(r.stdout)
    assert (s["format"], s["version"], s["next"], s["rollback_cmd"]) == (
        1, "v0.2.0", "nothing to do", "bash install-release.sh --rollback")
    assert s["identity"]["pinned"] is True and s["identity"]["install_id"] == rec["install_id"]
    assert s["journal"]["op"] == "upgrade" and s["journal"]["state"] == "done"
    assert s["journal"]["pid_alive"] is False
    assert s["health"] == {"bridge": "running/healthy", "gateway": "running/healthy"}
    assert s["markers"] == {"bridge_data": None, "bridge_secrets": None}
    assert s["incomplete_restore_points"] == [] and s["replaced"] == [] and s["finish_pending"] == []
    r = w.run("--list-snapshots", "--json", "--verify")
    assert r.returncode == 0, r.stderr
    ls = json.loads(r.stdout)
    full = [p for p in ls["restore_points"] if p["kind"] == "full"]
    assert [p["id"] for p in full] == [rp]
    assert full[0]["complete"] and full[0]["verified"] and full[0]["default_target"]
    # E37: while an operation runs, neither starts a container.
    (w.d / ".sigrift" / "lock-owner.json").write_text(json.dumps(
        {"pid": os.getpid(), "op": "rollback", "log": "x"}))
    w.host.clear_log()
    for args in (("--status", "--json"), ("--list-snapshots", "--json")):
        r = w.run(*args)
        assert r.returncode == 0, r.stderr
    assert not [c for c in w.host.argvs() if c.startswith("run ")], w.host.argvs()
    assert json.loads(w.run("--status", "--json").stdout)["schema"]["note"] == \
        "not read while an operation runs"
    (w.d / ".sigrift" / "lock-owner.json").unlink()
    # A changed manifest no longer matches its MAC: damaged, never restored.
    man_path = w.d / ".sigrift" / "snapshots" / rp / "manifest.json"
    man_path.write_text(man_path.read_text().replace('"upgrade"', '"manual"', 1))
    r = w.run("--list-snapshots", "--json", "--verify")
    assert r.returncode == 1 and json.loads(r.stdout)["restore_points"][0]["status"] == "damaged"
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 3 and "is damaged" in r.stderr


# ── 11.5 #17, #18, #21, #25, #26, #32, #45: rollback, confirm, re-upgrade ─────


def test_rollback_dry_run_confirmation_result_and_upgrade_again(upgraded):
    w = upgraded
    with w.db() as c:
        c.execute("INSERT INTO detections VALUES ('d9', '2026-11-27T11:00:00Z', 'pi-1', 'fm', '', "
                  "1e8, 0.5, 1, -60, 0.1, 'default')")
        c.execute("UPDATE users SET enabled = 0 WHERE username = 'bob'")
    keys = json.loads((w.vol() / "keys.json").read_text())
    keys["keys"]["ops"]["revoked"] = True
    (w.vol() / "keys.json").write_text(json.dumps(keys))
    pre_compose = (w.d / "docker-compose.yml").read_bytes()
    cert = (w.d / "tls" / "cert.pem").read_bytes()
    installer = (w.d / "install-release.sh").read_bytes()
    before = w.digest()
    # The dry run: the plan, nothing changed, nothing changing ran.
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "==> Rollback plan (--dry-run: nothing was changed)" in r.stdout
    plan = dict((line.split()[0], line) for line in r.stdout.splitlines() if line.startswith("  "))
    assert "new rows: detections 1, " in plan["DISCARDS"] and "0 API keys" in plan["DISCARDS"]
    assert "0 users, 0 webhooks" in plan["DISCARDS"]
    assert "1 API keys stay revoked" in plan["KEEPS"] and "1 users stay disabled" in plan["KEEPS"]
    assert "type v0.1.0 when asked, or add --confirm v0.1.0" in plan["confirm"]
    assert w.digest() == before and changing_calls(w.host) == []
    # Without a terminal it needs the version: the drill's exact last lines.
    r = w.run("--rollback")
    assert r.returncode == 3, r.stdout + r.stderr
    assert "discards data written since" in r.stderr and "1 detection" in r.stderr
    assert tail(r) == ["Next: bash install-release.sh --rollback --confirm v0.1.0",
                       "Nothing was changed."]
    r = w.run("--rollback", "--confirm", "v9.9.9")
    assert r.returncode == 3 and "--confirm v9.9.9 does not name the version" in r.stderr
    assert w.digest() == before
    w.host.clear_log()
    r = w.run("--rollback", "--confirm", "v0.1.0")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SigRift v0.1.0 is up again in %s" % w.d.resolve() in r.stdout
    # Files: the restore point's, the pin kept, tls/ and the installer kept.
    assert (w.d / "VERSION").read_text() == "v0.1.0\n"
    assert (w.d / "docker-compose.yml").read_bytes() == w.t0 != pre_compose
    env = env_of(w.d)
    assert env["COMPOSE_PROJECT_NAME"] == PROJECT and "BRIDGE_KEYSTORE_KEY" not in env
    assert env["BRIDGE_MFA_KEY"] == KEY_A and not (w.d / ".sigrift" / "held").exists()
    assert (w.d / "tls" / "cert.pem").read_bytes() == cert
    assert (w.d / "install-release.sh").read_bytes() == installer
    # Data: the restore point's rows, the revocations carried, sessions gone.
    with w.db() as c:
        assert c.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 2
        assert c.execute("SELECT enabled FROM users WHERE username = 'bob'").fetchone()[0] == 0
        assert c.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert json.loads((w.vol() / "keys.json").read_text())["keys"]["ops"]["revoked"] is True
    assert not (w.vol() / ".sigrift-restore-incomplete").exists()
    rb = w.journal()["rb_id"]
    assert w.replaced() == {"bridge_data": [".sigrift-replaced-" + rb],
                            "bridge_secrets": [".sigrift-replaced-" + rb]}
    j, rec = w.journal(), w.record()
    assert (j["op"], j["state"], j["cause"], j["restore_point"]) == (
        "rollback", "done", "manual", w.points()[0])
    assert [(h["op"], h["result"]) for h in rec["history"]][-2:] == [("upgrade", "ok"),
                                                                    ("rollback", "ok")]
    assert rec["version"] == "v0.1.0" and [x["id"] for x in rec["finish_pending"]] == [rb]
    assert rec["compose_template"] == "t0-v0.1.0" and rec["history"][-1]["cause"] == "manual"
    vrec = w.volume_record()
    assert (vrec["last_op"], vrec["last_version"], vrec["restored_from"]) == (
        "rollback", "v0.1.0", j["restore_point"])
    logs = w.d / ".sigrift" / "logs" / ("rollback-" + rb)
    for name in ("plan.json", "carry.json", "final.json"):
        assert (logs / name).stat().st_mode & 0o777 == 0o600, name
    assert "ops" in json.loads((logs / "plan.json").read_text())["carries"]["api_keys_revoked"]
    # The hold stub covers every call from the stop to the restored start,
    # and nothing starts while a marker exists (7.5 invariants).
    argvs, heads = w.host.argvs(), [c["compose_file_head"] for c in w.host.calls()]
    mark = next(i for i, a in enumerate(argvs) if re.search(r"--name sigrift-lc-\S+-mark-", a))
    unmark = next(i for i, a in enumerate(argvs) if re.search(r"--name sigrift-lc-\S+-unmark-", a))
    stop = next(i for i, a in enumerate(argvs) if a == "compose stop")
    up = next(i for i, a in enumerate(argvs) if a.startswith("compose up"))
    held = next(i for i, h in enumerate(heads) if h.startswith(STUB))
    assert stop < held < mark < unmark < up
    assert all(h.startswith(STUB) for h in heads[held:up])
    assert not any(re.match(r"compose (up|start)|start |run -d", a) for a in argvs[mark:unmark])
    assert argvs[up] == "compose up -d --pull never --remove-orphans --force-recreate bridge"
    no_secret_in_argv(w)
    # --status after it (the drill's rollback checks).
    s = json.loads(w.run("--status", "--json").stdout)
    assert (s["version"], s["journal"]["op"], s["journal"]["state"]) == ("v0.1.0", "rollback",
                                                                         "done")
    assert len(s["finish_pending"]) == 1 and {x["volume"] for x in s["replaced"]} == {
        "bridge_data", "bridge_secrets"}
    # Upgrade again (7.2 T3): a fresh restore point, the kept copy removed.
    r = w.run(folder=w.new)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "this upgrade replaces it." in r.stdout
    assert len(w.points()) == 2 and w.replaced() == {"bridge_data": [], "bridge_secrets": []}
    rec = w.record()
    assert [h["op"] for h in rec["history"]][-4:] == ["upgrade", "rollback", "upgrade", "finish"]
    assert rec["history"][-1]["cause"] == "implied" and rec["finish_pending"] == []
    assert w.volume_record()["last_version"] == "v0.2.0"
    assert w.journal()["restore_point"] != j["restore_point"]


# ── 11.5 #17 (credentials), #19 (late guard) ─────────────────────────────


def test_credentials_coming_back_need_revert_credentials(upgraded):
    w = upgraded
    with w.db() as c:
        c.execute("UPDATE users SET password_hash = 'pw-new' WHERE username = 'admin'")
    before = w.digest()
    for args in (("--rollback",), ("--rollback", "--confirm", "v0.1.0")):
        r = w.run(*args)
        assert r.returncode == 3, r.stdout + r.stderr
        assert "would bring back credentials changed since" in r.stderr
        assert "passwords of admin" in r.stderr
        assert tail(r) == ["Next: bash install-release.sh --rollback --dry-run",
                           "Nothing was changed."]
    r = w.run("--rollback", "--revert-credentials")
    assert r.returncode == 3 and "brings back the passwords of admin" in r.stderr
    assert tail(r)[0] == "Next: bash install-release.sh --rollback --revert-credentials " \
                         "--confirm v0.1.0"
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 0
    assert "credentials passwords of: admin (their old passwords work again)" in r.stdout
    assert "credentials come back only with --revert-credentials" in r.stdout
    assert w.digest() == before and changing_calls(w.host) == []


def test_late_guard_refuses_a_credential_changed_while_staging_even_with_confirm(upgraded):
    w = upgraded
    with w.db() as c:
        c.execute("INSERT INTO detections VALUES ('d9', '2026-11-27T11:00:00Z', 'pi-1', 'fm', '', "
                  "1e8, 0.5, 1, -60, 0.1, 'default')")
    hooks = json.loads((w.vol() / "webhooks.json").read_text())
    hooks["webhooks"][0]["signing_secret"] = "s1-rotated"
    # A webhook secret changes after the plan (while the stack still serves).
    w.host.update(on_call=[{"match": r"^compose stop$",
                            "write": {str(w.vol() / "webhooks.json"): json.dumps(hooks)}}])
    r = w.run("--rollback", "--confirm", "v0.1.0")
    out = r.stdout + r.stderr
    assert r.returncode == 3, out
    assert "something the plan did not show would come back (wh1)" in out
    assert "v0.2.0 was stopped for this check and started again" in out
    assert out_tail(r) == ["Next: bash install-release.sh --rollback --dry-run",
                           "Nothing was changed."]
    assert (w.d / "VERSION").read_text() == "v0.2.0\n" and not (w.d / ".sigrift" / "held").exists()
    assert not list(w.vol().glob(".sigrift-restore-*")) and w.replaced()["bridge_data"] == []
    assert w.journal()["state"] == "aborted"
    running = {c["service"]: c["image"] for c in w.host.load()["containers"]
               if c["state"] == "running"}
    assert running == {"bridge": NEW_BRIDGE, "gateway": NEW_GATEWAY}


def test_a_wrong_confirm_is_refused_and_late_data_without_one_stops_the_rollback(upgraded):
    w = upgraded
    before = w.digest()
    # The plan needs no confirmation here; a --confirm that names another
    # version is still refused, first (2.3 rule 1, M-CONFIRM-WRONG).
    r = w.run("--rollback", "--confirm", "v9.9.9")
    assert r.returncode == 3 and "--confirm v9.9.9 does not name the version" in r.stderr
    assert tail(r) == ["Next: bash install-release.sh --rollback --confirm v0.1.0",
                       "Nothing was changed."]
    assert w.digest() == before and changing_calls(w.host) == []
    # Data arrives after the plan, while the stack serves: without a
    # confirmation the late guard stops it (11.5 #19, M-CONFIRM-NEEDED-LATE).
    capture = w.vol() / "iq_captures" / "late.iq.gz"
    w.host.update(on_call=[{"match": r"^compose stop$", "write": {str(capture): "arrived late"}}])
    r = w.run("--rollback")
    out = r.stdout + r.stderr
    assert r.returncode == 3, out
    assert "data arrived after the rollback was planned (1 capture)" in out
    assert out_tail(r) == ["Next: bash install-release.sh --rollback --confirm v0.1.0",
                           "Nothing was changed."]
    assert capture.exists() and (w.d / "VERSION").read_text() == "v0.2.0\n"
    assert w.journal()["state"] == "aborted" and w.journal()["confirmed"] is False
    # The refusal changed nothing and hides nothing: v0.2.0 is recorded, and
    # a plain --rollback still finds the upgrade's restore point (E23).
    rec = w.record()
    assert rec["version"] == "v0.2.0"
    assert (rec["history"][-1]["op"], rec["history"][-1]["result"]) == ("rollback", "aborted")
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 0, r.stdout + r.stderr


# ── 11.5 #9, #15, #22, #44, #46: the automatic rollback ──────────────────


def test_auto_rollback_when_the_bridge_never_turns_healthy_and_nothing_is_new(fresh):
    w = fresh
    # A lifecycle container a killed run left behind is removed first (E6).
    w.host.load()
    w.host.state["containers"].append({
        "id": "stale0engine", "name": "sigrift-lc-x-state-1", "project": "", "service": "",
        "state": "exited", "image": "x", "mounts": ["%s_bridge_data" % PROJECT],
        "labels": {"com.sigrift.lifecycle": "engine"}})
    w.host.state["fail_at"] = FAIL_NEW_BRIDGE
    w.host.save()
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 5, out  # what the follower returns: the child's .rc
    assert "rm -f stale0engine" in w.host.argvs()
    assert "==> The bridge of v0.2.0 did not become healthy (it exited). It never served as " \
           "healthy and nothing arrived after the restore point, so this run rolls back to " \
           "v0.1.0 by itself" in out
    assert "The upgrade to v0.2.0 failed and was rolled back: SigRift v0.1.0 is up again" in out
    assert "SigRift v0.2.0 is up" not in out and "Dashboard:" not in out
    j = w.journal()
    assert (j["op"], j["state"], j["cause"]) == ("rollback", "done", "auto")
    assert j["upgrade"]["state"] == "rolled_back" and j["log"] == j["upgrade"]["log"]
    assert j["upgrade"]["auto_rollback"]["decision"] == "rollback"
    # The staging keeps the space plan's reserve free, as a manual one does.
    assert j["reserve"] == j["upgrade"]["auto_rollback"]["reserve"] == 1 << 20
    assert (w.d / ".sigrift" / "logs" / ("journal-%s.json" % j["upgrade"]["id"])).exists()
    assert (w.d / j["log"]).read_text().count("rolls back to v0.1.0 by itself") == 1
    assert (w.d / j["log"].replace(".log", ".rc")).read_text().strip() == "5"
    rec = w.record()
    assert [(h["op"], h["result"], h.get("cause")) for h in rec["history"]] == [
        ("upgrade", "rolled_back", None), ("rollback", "ok", "auto")]
    # v0.1.0 as it was: its compose byte for byte (no name:), the pin kept.
    assert (w.d / "docker-compose.yml").read_bytes() == w.t0
    assert (w.d / "VERSION").read_text() == "v0.1.0\n"
    assert env_of(w.d)["COMPOSE_PROJECT_NAME"] == PROJECT
    running = {c["service"]: c["image"] for c in w.host.load()["containers"]
               if c["state"] == "running" and c["project"] == PROJECT}
    assert running == {"bridge": "ghcr.io/sigrift/sigrift-bridge:v0.1.0",
                       "gateway": "ghcr.io/sigrift/sigrift-gateway:v0.1.0"}
    assert (w.d / ".sigrift" / "logs" / ("failed-%s" % j["upgrade"]["id"]) / "compose.log").exists()
    s = json.loads(w.run("--status", "--json").stdout)
    assert s["last_auto_rollback"]["decision"] == "rollback" and len(s["finish_pending"]) == 1
    # The new installer, now in the rolled-back v0.1.0 folder: a re-run
    # there stays at v0.1.0, tag-only (7.1, 11.5 #24a).
    w.host.update(fail_at={})
    r = w.run()
    assert r.returncode == 0, r.stdout + r.stderr
    assert (w.d / "docker-compose.yml").read_bytes() == w.t0
    assert "BRIDGE_KEYSTORE_KEY" not in r.stderr


def test_auto_rollback_never_brings_back_an_env_edit(fresh):
    w = fresh
    # The operator edits .env while the new version fails to start: the
    # engine sees nothing new, the rollback would revert the edit (E16).
    w.host.update(fail_at=FAIL_NEW_BRIDGE, on_call=[
        {"match": r"^compose ps --all --format json$",
         "append": {str(w.d / ".env"): "BRIDGE_LOG_LEVEL=debug\n"}}])
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "It was not rolled back automatically, because a rollback would bring back what " \
           "was changed since the restore point (.env keys BRIDGE_LOG_LEVEL)." in out
    j = w.journal()
    assert (j["op"], j["state"], j["auto_rollback"]["decision"]) == ("upgrade", "failed", "kept")
    assert "BRIDGE_LOG_LEVEL=debug" in (w.d / ".env").read_text()
    assert (w.d / "VERSION").read_text() == "v0.2.0\n"
    assert [a for a in w.host.argvs() if a == "compose stop"] == ["compose stop"]


def test_quiesced_recheck_that_finds_new_data_restarts_the_failed_version(fresh):
    w = fresh
    capture = w.vol() / "iq_captures" / "c3.iq.gz"
    # Written while the automatic rollback stops the stack (its own stop,
    # after the upgrade's): 6.2 step 5 finds it (11.5 #13).
    w.host.update(fail_at=FAIL_NEW_BRIDGE, on_call=[
        {"match": r"^compose stop$", "skip": 1, "write": {str(capture): "late capture"}}])
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "because data arrived while it was being checked: 1 capture." in out
    j = w.journal()
    assert (j["op"], j["state"], j["auto_rollback"]["decision"]) == ("upgrade", "failed", "kept")
    argvs = w.host.argvs()
    stops = [i for i, a in enumerate(argvs) if a == "compose stop"]
    assert len(stops) == 2
    assert "compose up -d --pull never --remove-orphans" in argvs[stops[1]:]
    assert not (w.d / "docker-compose.yml").read_text().startswith(STUB) and capture.exists()
    assert (w.d / "VERSION").read_text() == "v0.2.0\n" and w.replaced()["bridge_data"] == []


# ── 11.5 #2, #4/#5 (restore-point): a restore point that fails ────────────


def test_a_failed_restore_point_puts_everything_back_or_keeps_the_step_to_resume(fresh):
    w = fresh
    installer = (w.d / "install-release.sh").read_bytes()
    w.host.update(engine_faults={"snapshot-volume": {"rc": 1, "once": True}})
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 1, out
    assert "The upgrade did not go on: the restore point could not be taken" in out
    assert out_tail(r)[-1].startswith("Next: bash install-release.sh --status")
    assert "stopped at step" not in out  # put back: the journal says aborted
    assert w.journal()["state"] == "aborted" and w.points() == []
    assert (w.d / "VERSION").read_text() == "v0.1.0\n" and not (w.d / "LICENSE").exists()
    assert (w.d / "install-release.sh").read_bytes() == installer
    running = {c["service"]: c["image"] for c in w.host.load()["containers"]
               if c["state"] == "running" and c["project"] == PROJECT}
    assert running == {"bridge": "ghcr.io/sigrift/sigrift-bridge:v0.1.0",
                       "gateway": "ghcr.io/sigrift/sigrift-gateway:v0.1.0"}
    # Again, and this time the files cannot be put back either: nothing is
    # started, the stack stays held and the journal keeps the step (exit 4).
    snapfile = w.d / ".sigrift" / "snapshots" / "*-files" / "files" / "install-release.sh"
    w.host.update(engine_faults={"snapshot-volume": {"rc": 1, "once": True}}, on_call=[
        {"match": r"--name sigrift-lc-\S+-snapshot-volume-", "write": {str(snapfile): "x\n"}}])
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "could not be put back" in out and "the stack stays stopped and held" in out
    assert "Next: bash install-release.sh --abort" in out
    j = w.journal()
    assert (j["state"], j["next"]) == ("failed", "restore-point") and "put back" in j["error"]
    assert (w.d / "docker-compose.yml").read_text().startswith(STUB)
    # The files-only point repaired, --resume takes the restore point again.
    snap = w.d / ".sigrift" / "snapshots" / j["snapshot"]
    (snap / "files" / "install-release.sh").write_bytes(installer)
    w.host.update(on_call=[])
    r = w.run("--resume")
    assert r.returncode == 0, r.stdout + r.stderr
    assert w.journal()["state"] == "done" and (w.d / "VERSION").read_text() == "v0.2.0\n"
    assert len(w.points()) == 1


# ── 11.5 #30, #44: an automatic rollback that stops, undone ───────────────


def test_abort_of_an_auto_rollback_brings_back_the_failed_upgrade_for_good(fresh):
    w = fresh
    w.host.update(fail_at=FAIL_NEW_BRIDGE,
                  engine_faults={"swap": {"after": 1, "rc": 137, "once": True}})
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "The automatic rollback to v0.1.0 stopped at step rb-swap" in out
    assert (w.journal()["op"], w.journal()["cause"]) == ("rollback", "auto")
    # Undone: the upgrade journal is back, failed, and never rolls back by itself.
    r = w.run("--abort")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "the failed upgrade to v0.2.0 is left as it was found and no longer rolls back by " \
           "itself" in out
    j = w.journal()
    assert (j["op"], j["state"], j["auto_rollback"]["decision"]) == ("upgrade", "failed", "aborted")
    assert j["flags"]["no_auto_rollback"] is True
    assert (w.d / "VERSION").read_text() == "v0.2.0\n" and w.replaced()["bridge_secrets"] == []
    assert not (w.vol("bridge_secrets") / ".sigrift-restore-incomplete").exists()
    # --resume retries the start; a new failure stops for good (exit 4).
    r = w.run("--resume")
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "It was not rolled back automatically, because its automatic rollback was aborted." \
        in out
    assert w.journal()["auto_rollback"]["decision"] == "skipped"


# ── 11.5 #12, #29: new data blocks it; --rollback then takes the upgrade over ─


def test_no_auto_rollback_when_new_data_arrived_then_rollback_takes_it_over(fresh):
    w = fresh
    capture = w.vol() / "iq_captures" / "c2.iq.gz"
    w.host.update(fail_at=FAIL_NEW_BRIDGE, on_call=[
        {"match": r"^compose ps --all --format json$", "write": {str(capture): "new capture"}}])
    r = w.run(folder=w.new)
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "It was not rolled back automatically, because data arrived after the restore " \
           "point: 1 capture." in out
    assert "A rollback to v0.1.0 would discard: 1 capture" in out
    assert "Next: cd %s && bash install-release.sh --rollback --confirm v0.1.0" % w.d.resolve() \
        in out
    j = w.journal()
    assert (j["op"], j["state"], j["auto_rollback"]["decision"]) == ("upgrade", "failed", "kept")
    stops = [a for a in w.host.argvs() if a == "compose stop"]
    assert len(stops) == 1  # the upgrade's own stop; the failed version was left as found
    # --rollback takes the interrupted upgrade over (cause interrupted-upgrade).
    w.host.update(fail_at={})
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 0 and "1 captures created since" in r.stdout
    # Something in the serving stack writes into the staging (11.5 #20): the
    # guard refuses, and the upgrade it took over is in progress again.
    w.host.update(on_call=[{"match": r"^compose stop$", "write": {
        str(w.vol() / ".sigrift-restore-*" / "stray.txt"): "written while serving"}}])
    r = w.run("--rollback", "--confirm", "v0.1.0")
    out = r.stdout + r.stderr
    assert r.returncode == 3, out
    assert "changed while v0.2.0 kept serving" in out and "bridge_data:stray.txt" in out
    j = w.journal()
    assert (j["op"], j["state"]) == ("upgrade", "failed")
    assert "refused at rb-guard: M-RB-STAGING-CHANGED" in j["error"]
    assert not list(w.vol().glob(".sigrift-restore-*")) and capture.exists()
    w.host.update(on_call=[])
    r = w.run("--rollback", "--confirm", "v0.1.0")
    assert r.returncode == 0, r.stdout + r.stderr
    j = w.journal()
    assert (j["op"], j["cause"], j["upgrade"]["state"]) == ("rollback", "interrupted-upgrade",
                                                            "rolled_back")
    assert [(h["op"], h["result"]) for h in w.record()["history"]][-2:] == [
        ("upgrade", "rolled_back"), ("rollback", "ok")]
    assert not capture.exists() and (w.d / "VERSION").read_text() == "v0.1.0\n"


# ── 11.5 #6, #7, #31a, #31b, #44: an interrupted rollback, resumed or undone ──


def test_interrupted_rollback_resumes_or_is_undone_and_a_killed_undo_is_resumed(upgraded, world):
    w = upgraded
    before = w.digest()
    pre_compose = (w.d / "docker-compose.yml").read_bytes()
    # The swap of bridge_secrets is done, its reply lost (a kill): the
    # rollback stops between the two volumes' swaps.
    w.host.update(engine_faults={"swap": {"after": 1, "rc": 137, "once": True}})
    r = w.run("--rollback")
    out = r.stdout + r.stderr
    assert r.returncode == 4, out  # stopped mid-operation, the journal holds it (2.2)
    assert "The rollback stopped at step rb-swap (exit 4)" in out
    assert w.journal()["next"] == "rb-swap" and w.journal()["state"] == "failed"
    assert (w.vol("bridge_secrets") / ".sigrift-restore-incomplete").exists()
    s = json.loads(w.run("--status", "--json").stdout)
    assert s["journal"]["next"] == "rb-swap" and s["markers"]["bridge_data"]["op"] == "rollback"
    world.save("interrupted", w.work.parent)
    # Resumed: the end state of an uninterrupted rollback.
    r = w.run("--resume")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (w.d / "VERSION").read_text() == "v0.1.0\n" and w.journal()["state"] == "done"
    assert len(w.replaced()["bridge_data"]) == 1 == len(w.replaced()["bridge_secrets"])
    # Undone instead, and the undo itself killed in the middle of its unswap.
    world.restore("interrupted")
    w.host.update(engine_faults={"unswap": {"after": 1, "rc": 137, "once": True}})
    r = w.run("--abort")
    assert r.returncode == 4, r.stdout + r.stderr
    assert "The undo of the rollback stopped at step ab-unswap" in r.stdout + r.stderr
    assert w.journal()["state"] == "aborting" and w.journal()["next"] == "ab-unswap"
    assert "the undo of the rollback to v0.1.0 stopped at ab-unswap" in w.run("--status").stdout
    # A plain run refuses (M-INTERRUPTED-OP), --resume goes on with the undo.
    r = w.run(env={"SIGRIFT_VERSION": "v0.2.0"})
    assert r.returncode == 3 and "the undo (--abort) of a rollback to v0.1.0" in r.stderr
    r = w.run("--resume")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "The rollback to v0.1.0 was undone: v0.2.0 is back" in r.stdout
    assert w.digest() == before and (w.d / "docker-compose.yml").read_bytes() == pre_compose
    assert w.replaced() == {"bridge_data": [], "bridge_secrets": []}
    j = w.journal()
    assert (j["op"], j["state"]) == ("rollback", "aborted")
    assert w.record()["history"][-1]["op"] == "abort"
    running = {c["service"]: c["image"] for c in w.host.load()["containers"]
               if c["state"] == "running"}
    assert running == {"bridge": NEW_BRIDGE, "gateway": NEW_GATEWAY}
    # A forward step after the swap refuses a volume the undo unswapped.
    j.update(state="failed", next="rb-files", done=[s for s in j["abort"]["forward_steps"]
                                                    if s not in ("rb-files",) and
                                                    j["abort"]["forward_steps"].index(s) <
                                                    j["abort"]["forward_steps"].index("rb-files")],
             steps=j["abort"]["forward_steps"])
    (w.d / ".sigrift" / "journal.json").write_text(json.dumps(j))
    r = w.run("--resume")
    assert r.returncode == 4 and "the swap of this rollback is not complete" in r.stdout + r.stderr
    assert (w.d / "VERSION").read_text() == "v0.2.0\n"


def test_an_undo_after_the_restored_bridge_started_needs_confirm_and_marks_both_volumes(
        upgraded):
    w = upgraded
    pre_compose = (w.d / "docker-compose.yml").read_bytes()
    w.host.update(fail_at={r"--force-recreate bridge$": 1})
    r = w.run("--rollback")
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    j = w.journal()
    assert (j["state"], j["next"]) == ("failed", "rb-start-bridge") and j["bridge_started_at"]
    assert not (w.vol() / ".sigrift-restore-incomplete").exists()  # rb-unmark ran
    w.host.update(fail_at={}, fail_counts={})
    # 11.5 #31: the restored bridge may have written data, so --abort needs
    # the version typed; a wrong one is refused too.
    r = w.run("--abort")
    assert r.returncode == 3 and "may have written data" in r.stderr
    r = w.run("--abort", "--confirm", "v9.9.9")
    assert r.returncode == 3 and "--confirm v9.9.9 does not name the version" in r.stderr
    # The volumes cannot be read now: the journal says the swap ran, so the
    # marker goes into both anyway, and the unswap waits (7.5).
    w.host.update(fail_at={r"--name sigrift-lc-\S+-facts-": 1})
    r = w.run("--abort", "--confirm", "v0.2.0")
    out = r.stdout + r.stderr
    assert r.returncode == 4, out
    assert "the undo cannot tell whether the swap began" in out
    j = w.journal()
    assert (j["state"], j["next"]) == ("aborting", "ab-unswap")
    for v in ("bridge_data", "bridge_secrets"):
        assert json.loads((w.vol(v) / ".sigrift-restore-incomplete").read_text())["id"] == \
            j["rb_id"], v
    w.host.update(fail_at={}, fail_counts={})
    r = w.run("--resume")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "The rollback to v0.1.0 was undone: v0.2.0 is back" in r.stdout
    assert (w.d / "docker-compose.yml").read_bytes() == pre_compose
    assert w.replaced() == {"bridge_data": [], "bridge_secrets": []}
    assert not (w.vol("bridge_secrets") / ".sigrift-restore-incomplete").exists()


# ── 11.5 #34, #35: --rollback --finish, --snapshot ────────────────────────


def test_finish_removes_only_the_kept_copies_and_snapshot_takes_a_manual_point(upgraded):
    w = upgraded
    rb = "20261127T120000Z"
    for v in ("bridge_data", "bridge_secrets"):
        p = w.vol(v) / (".sigrift-replaced-" + rb)
        p.mkdir()
        (p / "keys.json").write_text("{}")
        (p / ".sigrift-phase").write_text(json.dumps({"format": 1, "phase": "done", "rb_id": rb}))
    rec = w.record()
    rec["finish_pending"] = [{"id": rb, "bytes": 2, "created_at": "2026-11-27T12:00:00Z"}]
    (w.d / ".sigrift" / "install.json").write_text(json.dumps(rec))
    before = w.digest()
    r = w.run("--rollback", "--finish", "--dry-run")
    assert r.returncode == 0 and ".sigrift-replaced-" + rb in r.stdout and w.digest() == before
    r = w.run("--rollback", "--finish")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "==> Freed " in r.stdout and w.replaced() == {"bridge_data": [], "bridge_secrets": []}
    assert not [a for a in w.host.argvs() if a == "compose stop"]  # online
    rec = w.record()
    assert rec["finish_pending"] == [] and rec["history"][-1]["op"] == "finish"
    assert rec["history"][-1]["cause"] == "manual"
    assert w.run("--rollback", "--finish").stdout.strip().endswith("volumes.")  # nothing left
    # --snapshot: a manual full point, the stack restarted unchanged.
    compose = (w.d / "docker-compose.yml").read_bytes()
    assert w.run("--snapshot", "--dry-run").returncode == 0
    r = w.run("--snapshot")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "taken; SigRift v0.2.0 is up again. Restore it with: bash install-release.sh " \
           "--rollback " in r.stdout
    assert (w.d / "docker-compose.yml").read_bytes() == compose
    assert w.journal()["state"] == "done" and len(w.points()) == 2
    ls = json.loads(w.run("--list-snapshots", "--json").stdout)
    manual = [p for p in ls["restore_points"] if p["reason"] == "manual"]
    # Never pruned: named by the journal that took it, and manual.
    assert len(manual) == 1 and manual[0]["protected"] in ("journal", "manual")


# ── refusals that change nothing (11.5 #28, #29, #38, #39, #40, #42) ─────────


def test_refusals_before_any_change(fresh, tmp_path):
    w = fresh
    before = w.digest()
    for args, rc in ((("--finish",), 2), (("--rollback", "--json"), 2), (("--exclude", "x"), 2),
                     (("--snapshot", "--no-snapshot"), 2), (("--status", "--confirm", "v"), 2)):
        assert w.run(*args, folder=w.new).returncode == rc, args
    r = w.run("--no-snapshot", folder=w.new)
    assert r.returncode == 3 and "it needs SIGRIFT_I_HAVE_A_BACKUP=1" in r.stderr
    r = w.run("--upgrade", str(w.d), "--no-auto-rollback", "--no-snapshot", folder=w.new)
    assert r.returncode == 3 and tail(r)[0] == "Next: SIGRIFT_I_HAVE_A_BACKUP=1 bash " \
        "install-release.sh --upgrade %s --no-auto-rollback --no-snapshot" % w.d
    # Nothing to roll back: v0.1.0's installer took no restore point.
    shutil.copy(INSTALL_RELEASE, w.d / "install-release.sh")
    r = w.run("--rollback")
    assert r.returncode == 3 and "there is nothing to roll back here" in r.stderr
    # An installer older than the requested minor release (E26).
    old = tmp_path / "installer"
    old.mkdir()
    shutil.copy(w.new / "install-release.sh", old / "install-release.sh")
    r = run_installer(old, host=w.host, env={"SIGRIFT_VERSION": "v0.3.0"})
    assert r.returncode == 3 and "this installer is from v0.2.0, and v0.3.0 is a newer minor" \
        in r.stderr
    # SIGRIFT_PULL=never needs the images on this host (E28).
    r = w.run(folder=w.new, env={"SIGRIFT_PULL": "never"})
    assert r.returncode == 3 and "SIGRIFT_PULL=never, but ghcr.io/sigrift/sigrift-bridge:v0.2.0 " \
        "is not on this host." in r.stderr
    assert not [a for a in w.host.argvs() if a.startswith("pull")]
    shutil.copy(V010_INSTALLER, w.d / "install-release.sh")
    assert w.digest() == before


def test_rollback_refusals_name_the_way_on(upgraded):
    w = upgraded
    before = w.digest()
    # 11.5 #37: an older release over newer data: the way back is a rollback.
    r = w.run("--dry-run", folder=w.new, env={"SIGRIFT_VERSION": "v0.1.0"})
    assert r.returncode == 3 and "Full restore points at v0.1.0: %s" % w.points()[0] in r.stderr
    assert tail(r)[0] == "Next: bash install-release.sh --rollback"
    # 11.5 #47: an unsafe SIGRIFT_SNAPSHOT_DIR is refused before anything stops.
    bad = w.work / "open"
    bad.mkdir()
    bad.chmod(0o777)
    w.host.clear_log()
    r = w.run("--snapshot", env={"SIGRIFT_SNAPSHOT_DIR": str(bad)})
    assert r.returncode == 3, r.stdout + r.stderr
    assert tail(r) == ["Next: mkdir -m 0700 -p /path/of/your/own && SIGRIFT_SNAPSHOT_DIR="
                       "/path/of/your/own bash install-release.sh --snapshot",
                       "Nothing was changed."]
    # Volumes that cannot be read are unknown, never "nothing left there".
    w.host.update(fail_at={r"--name sigrift-lc-\S+-facts-": 1})
    for args in (("--snapshot",), ("--rollback", "--dry-run")):
        r = w.run(*args)
        assert r.returncode == 3 and "could not read this install's volumes" in r.stderr, \
            (args, r.stderr)
    assert "compose stop" not in w.host.argvs()
    w.host.update(fail_at={}, fail_counts={})
    # A marker in bridge_secrets alone: --status shows it, --rollback refuses.
    marker = w.vol("bridge_secrets") / ".sigrift-restore-incomplete"
    marker.write_text(json.dumps({"format": 1, "op": "rollback", "id": "20260101T000000Z"}))
    s = json.loads(w.run("--status", "--json").stdout)
    assert s["markers"]["bridge_secrets"]["id"] == "20260101T000000Z"
    assert s["markers"]["bridge_data"] is None
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 3 and "bridge_secrets holds .sigrift-restore-incomplete (rollback " \
        "20260101T000000Z) from an earlier restore" in r.stderr
    marker.unlink()
    staging = w.vol() / ".sigrift-restore-20260101T000000Z"
    staging.mkdir()
    r = w.run("--rollback", "--dry-run")
    assert r.returncode == 3 and "bridge_data holds .sigrift-restore-20260101T000000Z from an " \
        "earlier restore that no journal here names" in r.stderr
    staging.rmdir()
    j = w.journal()
    # An upgrade interrupted before its bridge started: --abort, not a rollback.
    j.update(state="failed", next="switch", bridge_started_at=None)
    (w.d / ".sigrift" / "journal.json").write_text(json.dumps(j))
    r = w.run("--rollback")
    assert r.returncode == 3 and "--abort puts the files back without a restore" in r.stderr
    assert tail(r)[0] == "Next: bash install-release.sh --abort"
    # An interrupted rollback: every other run points to --resume.
    j.update(op="rollback", next="rb-swap", to_version="v0.1.0")
    (w.d / ".sigrift" / "journal.json").write_text(json.dumps(j))
    for args in ((), ("--snapshot",), ("--rollback",)):
        r = w.run(*args, env={"SIGRIFT_VERSION": "v0.2.0"} if not args else None)
        assert r.returncode == 3, (args, r.stderr)
        assert "a rollback to v0.1.0 started at" in r.stderr and \
            tail(r)[0] == "Next: bash install-release.sh --resume", (args, r.stderr)
    # 11.5 #41: an unattended renewal waits while any operation is in progress.
    r = w.run("--renew-tls")
    assert r.returncode == 0 and "==> TLS renewal deferred: a rollback to v0.1.0" in r.stderr
    r = w.run("--rollback", "--finish")
    assert r.returncode == 3 and "a rollback is in progress here" in r.stderr
    assert w.digest() == before


# ── static ───────────────────────────────────────────────────────────────


def test_quickstart_calls_only_the_parents_of_the_restore_block():
    """Phase 2 (8): quickstart runs --rollback, --snapshot and --rollback
    --finish through the restore block's parents only (phase2-spec 14.6);
    never a step or the automatic rollback, which it does not have (G12)."""
    qs = QUICKSTART.read_text()
    block = shared_block(QUICKSTART, "restore")
    assert block == shared_block(INSTALL_RELEASE, "restore")
    names = re.findall(r"(?m)^(lc_[a-z_]+)\(\) \{", block)
    assert {"lc_rb_main", "lc_snapshot_main", "lc_finish_main", "lc_after_start_failure",
            "lc_step_rb_swap", "lc_step_ab_unswap"} <= set(names)
    own = qs
    for name in ("lifecycle-tool", "lifecycle-engine", "identity", "preflight", "lifecycle",
                 "state-tool", "state-engine", "restore", "archive-engine", "move"):
        own = own.replace(shared_block(QUICKSTART, name), "")
    called = {n for n in names if re.search(r"\b%s\b" % n, own)}
    assert called == {"lc_rb_main", "lc_snapshot_main", "lc_finish_main", "lc_list_snapshots"}
    assert "--rollback" in own and "--snapshot" in own and "LC_AUTO_ROLLBACK=0" in own


def test_the_cli_and_its_exit_codes_are_the_specs():
    text = INSTALL_RELEASE.read_text()
    identity = shared_block(INSTALL_RELEASE, "identity")
    assert "LC_EXIT_STOPPED=4 LC_EXIT_ROLLED_BACK=5" in identity
    assert "LC_DOWNGRADE_NEXT='bash install-release.sh --rollback'" in identity
    usage = re.search(r"(?ms)^release_usage\(\) \{\n(.*?)^\}", text).group(1)
    for flag in ("--rollback [ID]", "--confirm VERSION", "--accept-summary-reset",
                 "--no-carry-revocations", "--accept-unverified", "--revert-credentials",
                 "--rollback --finish", "--snapshot [--exclude iq,pcap]",
                 "--list-snapshots [--json] [--verify [ID]]", "--status [--json]",
                 "--no-auto-rollback", "--no-snapshot"):
        assert flag in usage, flag
    assert text.count("\nINSTALLER_RELEASE=dev\n") == 1
    # quickstart.sh has no --status (14.19): the docs never send anyone there.
    for doc in ("INSTALL.md", "TROUBLESHOOTING.md", "src/sigrift/bridge/UPGRADE.md"):
        assert "quickstart.sh --status" not in (ROOT / doc).read_text(), doc
    restore = shared_block(INSTALL_RELEASE, "restore")
    for steps in ('LC_ROLLBACK_STEPS="snapshot rb-stage stop hold rb-guard rb-carry rb-audit '
                  'rb-mark rb-swap rb-files rb-images rb-unmark rb-start-bridge rb-start-rest '
                  'rb-verify rb-record"',
                  'LC_ABORT_ROLLBACK_STEPS="ab-stop ab-hold ab-mark ab-unswap ab-files ab-unmark '
                  'ab-unhold ab-start ab-record"'):
        assert steps in restore
    for step in re.findall(r"[a-z-]+", re.search(r'LC_ROLLBACK_STEPS="([^"]+)"', restore).group(1) +
                           " " + re.search(r'LC_ABORT_ROLLBACK_STEPS="([^"]+)"', restore).group(1)
                           + " prechecks restore-point unhold snap-record finish-delete "
                             "finish-record"):
        assert "lc_step_%s()" % step.replace("-", "_") in text, step
