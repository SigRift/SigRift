"""scripts/quickstart.sh's own use of the lifecycle blocks, run end to end.

Quickstart runs for real against FakeDockerHost (lifecycle_fakes.py) as far
as its .env, pin and identity steps go; later steps (building images, the
smoke test) fail against the fake and are not what these tests look at.
What they must show: an existing .env is never replaced (the old keep-test
was only a BRIDGE_ADMIN_PASSWORD= line), a new one is pinned, a secret the
data contradicts is refused before anything else happens, and each
lifecycle flag changes the decision.
"""

from __future__ import annotations

import socket

import pytest

from lifecycle_fakes import (
    INSTALLED_ENV,
    KEY_A,
    KEY_B,
    FakeDockerHost,
    changing_calls,
    release_install,
    run_installer,
    source_checkout,
    tree_digest,
)

pytestmark = pytest.mark.timeout(240)
QUICKSTART = "scripts/quickstart.sh"
DASHBOARD = "SIGRIFT_QUICKSTART_MODE=dashboard-only\n"
NO_PASSWORD = "".join(line + "\n" for line in INSTALLED_ENV.splitlines()
                      if not line.startswith("BRIDGE_ADMIN_PASSWORD="))
PASSWORD = "a-good-password\na-good-password\n"


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


def env_values(folder):
    out = {}
    for line in (folder / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def free_port() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return str(port)


def checkout_with_data(host, tmp_path, env, container_env=None, **data):
    d = source_checkout(tmp_path, "SigRift", env=env)
    model = {"users": 1, "totp_fernet": 2, "mfa_key": KEY_A, "audit_rows": 40,
             "audit_values": {"BRIDGE_AUDIT_KEY": "audit-123456"}, "schema": 56}
    model.update(data)
    cenv = container_env or dict(line.split("=", 1) for line in env.splitlines() if "=" in line)
    host.add_project("sigrift", d, image="sigrift-bridge", env=cenv, data=model)
    return d


def test_an_env_without_the_admin_password_line_keeps_every_secret(host, tmp_path):
    d = checkout_with_data(host, tmp_path, NO_PASSWORD + DASHBOARD)
    before = env_values(d)
    r = run_installer(d, host=host, script=QUICKSTART, stdin=PASSWORD)
    out = r.stdout + r.stderr
    assert "Admin password" not in out and "Wrote .env" not in out, out
    after = env_values(d)
    # Kept as they were; only the keys nothing depends on were added.
    assert {k: after[k] for k in before} == before
    assert sorted(set(after) - set(before)) == [
        "BRIDGE_KEYSTORE_KEY", "BRIDGE_LOCAL_NODE_KEY", "COMPOSE_PROJECT_NAME"]
    assert after["COMPOSE_PROJECT_NAME"] == "sigrift"
    assert len(list(d.glob(".env.bak.*~"))) == 1


def test_a_fresh_checkout_gets_its_project_pinned(host, tmp_path):
    d = source_checkout(tmp_path, "SigRift")
    r = run_installer(d, "--dashboard-only", host=host, script=QUICKSTART, stdin=PASSWORD)
    assert "==> Wrote .env (chmod 600)" in r.stdout, r.stdout + r.stderr
    assert env_values(d)["COMPOSE_PROJECT_NAME"] == "sigrift"


def test_a_secret_the_data_contradicts_is_refused_before_anything_else(host, tmp_path):
    d = checkout_with_data(host, tmp_path, INSTALLED_ENV.replace(KEY_A, KEY_B) + DASHBOARD,
                           container_env=dict(line.split("=", 1)
                                              for line in INSTALLED_ENV.splitlines()))
    before = tree_digest(d)
    r = run_installer(d, "--scanners=none", host=host, script=QUICKSTART)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "the running bridge uses a different BRIDGE_MFA_KEY than .env, and the data needs " \
        "the running one" in r.stderr
    assert r.stderr.rstrip().splitlines()[-2:] == [
        "Next: scripts/quickstart.sh --keep-running-secrets", "Nothing was changed."]
    assert "==>" not in r.stdout.replace("==> Quickstart mode", "")
    assert tree_digest(d) == before and changing_calls(host) == []
    # --keep-running-secrets takes the running bridge's value.
    r = run_installer(d, "--keep-running-secrets", host=host, script=QUICKSTART)
    assert "BRIDGE_MFA_KEY now holds the value the running bridge uses" in r.stdout, r.stderr
    assert env_values(d)["BRIDGE_MFA_KEY"] == KEY_A


def test_new_instance_beside_another_install_starts_a_separate_stack(host, tmp_path):
    release_install(host, tmp_path)
    d = source_checkout(tmp_path, "second")
    r = run_installer(d, "--dashboard-only", host=host, script=QUICKSTART, stdin=PASSWORD)
    assert r.returncode == 3 and "a fresh quickstart here would start a second" in r.stderr
    r = run_installer(d, "--dashboard-only", "--new-instance", host=host, script=QUICKSTART,
                      stdin=PASSWORD, env={"UC_PORT": free_port()})
    assert "==> Wrote .env (chmod 600)" in r.stdout, r.stdout + r.stderr
    assert env_values(d)["COMPOSE_PROJECT_NAME"] == "second"


def test_adopt_project_takes_a_renamed_checkouts_data(host, tmp_path):
    d = checkout_with_data(host, tmp_path, INSTALLED_ENV + DASHBOARD, totp_fernet=0, audit_rows=0)
    lab = d.rename(tmp_path / "lab")
    r = run_installer(lab, host=host, script=QUICKSTART)
    assert r.returncode == 3 and "Next: scripts/quickstart.sh --adopt-project=sigrift" in r.stderr
    r = run_installer(lab, "--adopt-project=sigrift", host=host, script=QUICKSTART)
    assert "==> Adopted project sigrift" in r.stdout, r.stdout + r.stderr
    assert env_values(lab)["COMPOSE_PROJECT_NAME"] == "sigrift"


# ── Phase 2 (phase2-spec 8, 14.4): the guarded upgrade and --rollback ──────

import json  # noqa: E402
import os  # noqa: E402

from lifecycle_fakes import load_lifecycle_tool, seed_volume  # noqa: E402

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
QS_ENV = (INSTALLED_ENV + DASHBOARD + "COMPOSE_PROJECT_NAME=sigrift\n"
          "BRIDGE_LOCAL_NODE_KEY=nodekey-123456\nBRIDGE_KEYSTORE_KEY=" + KEY_A + "\n")


class Git:
    """A `git` on the fake host's PATH: HEAD from a file, a dirty flag."""

    def __init__(self, host, tmp_path):
        self.head = tmp_path / "git-head"
        script = host.bin / "git"
        script.write_text('#!/bin/sh\nwhile [ "$1" = -C ]; do shift 2; done\ncase "$1" in\n'
                          '  rev-parse) cat "$FAKE_GIT_HEAD" 2>/dev/null || exit 1 ;;\n'
                          '  diff) [ ! -e "$FAKE_GIT_HEAD.dirty" ] ;;\n  *) exit 0 ;;\nesac\n')
        script.chmod(0o755)

    def at(self, commit, dirty=False):
        self.head.write_text(commit + "\n")
        flag = Path(str(self.head) + ".dirty")
        if dirty:
            flag.write_text("1")
        elif flag.exists():
            flag.unlink()


from pathlib import Path  # noqa: E402


@pytest.fixture
def qs(host, tmp_path):
    """A checkout with data and a fake git at commit A."""
    git = Git(host, tmp_path)
    git.at(COMMIT_A)
    d = checkout_with_data(host, tmp_path, QS_ENV)
    data, _ = seed_volume(host, "sigrift")
    # No TOTP secret the fake's real Fernet check would find undecryptable.
    import sqlite3
    db = sqlite3.connect(data / "detections.db")
    db.execute("UPDATE users SET totp_secret = NULL, mfa_enabled = 0")
    db.commit()
    db.close()
    import hashlib
    images = dict((ref, {"id": "sha256:" + hashlib.sha256(ref.encode()).hexdigest(),
                         "newest_migration": 56}) for ref in ("sigrift-bridge", "sigrift-gateway"))
    host.update(compose_services="bridge\ngateway\nedge\n", images=images)
    return d, git


def qrun(d, *args, host, git, env=None):
    return run_installer(d, *args, host=host, script=QUICKSTART,
                         env=dict({"FAKE_GIT_HEAD": str(git.head), "SIGRIFT_SNAPSHOT_RESERVE": "1M"},
                                  **(env or {})))


def state_dir(tmp_path):
    return tmp_path / ".local" / "state" / "sigrift" / "sigrift"


def test_state_dir_and_pointer_resolution_with_another_home(tmp_path, monkeypatch):
    """14.4 #1, #2: the pointer first (another $HOME finds the same dir);
    its target must be a real 0700 directory of the checkout's owner that
    belongs to this checkout."""
    t = load_lifecycle_tool()
    d = tmp_path / "SigRift"
    d.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home1"))
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert t.cmd_qs_state.__doc__
    import contextlib
    import io

    def resolve(**env):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            t.cmd_qs_state(["--checkout", str(d), "--project", "sigrift"])
        return buf.getvalue().strip()
    assert resolve() == str(tmp_path / "home1" / ".local" / "state" / "sigrift" / "sigrift")
    sd = tmp_path / "state"
    sd.mkdir(mode=0o700)
    t.cmd_qs_pointer(["--checkout", str(d), "--state", str(sd)])
    assert (d / ".sigrift-state").read_text() == str(sd) + "\n"
    monkeypatch.setenv("HOME", str(tmp_path / "home2"))
    assert resolve() == str(sd)
    refusals = []
    for case in ("mode", "symlink", "other"):
        if case == "mode":
            os.chmod(sd, 0o755)
        elif case == "symlink":
            os.chmod(sd, 0o700)
            (tmp_path / "link").symlink_to(sd)
            (d / ".sigrift-state").write_text(str(tmp_path / "link") + "\n")
        else:
            (d / ".sigrift-state").write_text(str(sd) + "\n")
            (sd / "install.json").write_text(json.dumps({"working_dir": "/elsewhere"}))
        err = io.StringIO()
        with contextlib.redirect_stderr(err), pytest.raises(SystemExit) as e:
            resolve()
        assert e.value.code == 3
        refusals.append(err.getvalue())
    assert "is not mode 0700" in refusals[0] and "is a symlink" in refusals[1]
    assert "belongs to /elsewhere" in refusals[2]
    assert all("Next: cat .sigrift-state" in x for x in refusals)


def test_guarded_upgrade_tags_prev_takes_a_point_and_never_rolls_back(qs, host, tmp_path):
    """14.4 #3, #4, #6, #7, #9, #16: the first guarded run tags
    sigrift-prev-unknown and its point has no commit (its rollback refuses);
    a re-run at the same HEAD takes no point; HEAD B is a guarded upgrade
    with the prev tag of A, edge_data in the point; a failed start exits 4
    without an automatic rollback; --status exists."""
    d, git = qs
    st = json.loads(host.state_path.read_text())
    st["volumes"].append({"name": "sigrift_edge_data", "project": "sigrift", "volume": "edge_data"})
    host.state_path.write_text(json.dumps(st))
    host.volume("sigrift_edge_data").mkdir(parents=True, exist_ok=True)
    (host.volume("sigrift_edge_data") / "journal.db").write_bytes(b"edge")
    r = qrun(d, host=host, git=git)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no commit is recorded for this install yet" in r.stdout
    sd = state_dir(tmp_path)
    assert (d / ".sigrift-state").read_text().strip() == str(sd)
    assert stat_mode(sd) == 0o700
    images = json.loads(host.state_path.read_text())["images"]
    assert any(ref.endswith(":sigrift-prev-unknown") for ref in images), sorted(images)
    hr = json.loads((sd / "install.json").read_text())
    assert hr["git_commit"] == COMMIT_A and hr["install_type"] == "source"
    points = [p for p in (sd / "snapshots").iterdir() if p.name.endswith("-full")]
    assert len(points) == 1
    m = json.loads((points[0] / "manifest.json").read_text())
    assert [v["name"] for v in m["volumes"]] == ["bridge_secrets", "bridge_data", "edge_data"]
    assert m.get("git_commit") is None
    r = qrun(d, "--rollback", host=host, git=git)
    assert r.returncode == 3 and "does not know the commit its images came from" in r.stderr, \
        r.stdout + r.stderr
    # The same HEAD and images again: a re-run, no new point.
    r = qrun(d, host=host, git=git)
    assert "Guarded upgrade" not in r.stdout, r.stdout + r.stderr
    assert len([p for p in (sd / "snapshots").iterdir() if p.name.endswith("-full")]) == 1
    # HEAD B: a guarded upgrade with A's prev tag; the bridge never gets healthy.
    git.at(COMMIT_B)
    host.update(exit_on_up={"bridge": True})
    r = qrun(d, host=host, git=git)
    assert r.returncode == 4, r.stdout + r.stderr
    text = r.stdout + r.stderr
    assert "Quickstart does not roll back by itself. To go back to aaaaaaaaaaaa: git -C" in text
    assert "rolled back" not in text.replace("does not roll back", "")
    images = json.loads(host.state_path.read_text())["images"]
    assert any(ref.endswith(":sigrift-prev-aaaaaaaaaaaa") for ref in images)
    j = json.loads((sd / "journal.json").read_text())
    assert j["op"] == "upgrade" and j["git_commit_from"] == COMMIT_A and "auto_rollback" not in j
    r = qrun(d, "--status", host=host, git=git)
    assert r.returncode == 0 and "journal   upgrade" in r.stdout, r.stdout + r.stderr


def stat_mode(p):
    import stat as _stat
    return _stat.S_IMODE(os.stat(p).st_mode)


def test_rollback_head_gate_dirty_compose_and_retag(qs, host, tmp_path):
    """14.4 #10, #11, #5: at B --rollback refuses (M-QS-RB-HEAD), a modified
    tracked compose file refuses (M-QS-RB-DIRTY); at A, clean, the rollback
    re-tags the kept images and starts with --no-build; a failed build
    changes nothing."""
    d, git = qs
    r = qrun(d, host=host, git=git)
    assert r.returncode == 0, r.stdout + r.stderr
    git.at(COMMIT_B)
    r = qrun(d, host=host, git=git)
    assert r.returncode == 0, r.stdout + r.stderr
    r = qrun(d, "--rollback", host=host, git=git)
    assert r.returncode == 3 and "the checkout is at bbbbbbbbbbbb, the restore point at aaaaaaaaaaaa" \
        in r.stderr, r.stdout + r.stderr
    assert "Next: git -C" in r.stderr and "checkout aaaaaaaaaaaa && scripts/quickstart.sh --rollback" \
        in r.stderr
    git.at(COMMIT_A, dirty=True)
    r = qrun(d, "--rollback", host=host, git=git)
    assert r.returncode == 3 and "differ from commit aaaaaaaaaaaa" in r.stderr, r.stdout + r.stderr
    git.at(COMMIT_A)
    host.clear_log()
    r = qrun(d, "--rollback", "--confirm", "aaaaaaaaaaaa", host=host, git=git)
    assert r.returncode == 0, r.stdout + r.stderr
    argv = host.argvs()
    assert any(a.startswith("compose up -d --pull never --no-build") for a in argv), argv
    assert any(a.startswith("tag ") for a in argv)
    # A build that fails changes nothing, also when the run wrote files
    # before its build (B-D3: here .env gains UC_PROXY_SECRET, which 1a's
    # env_plan adds): they go back from the files-only point (fix round).
    git.at(COMMIT_B)
    host.update(build_rc=1)
    envp = d / ".env"
    envp.write_text("".join(x + "\n" for x in envp.read_text().splitlines()
                            if not x.startswith("UC_PROXY_SECRET=")))
    before = tree_digest(d)
    host.clear_log()
    r = qrun(d, host=host, git=git)
    assert tree_digest(d) == before
    assert r.returncode == 3 and "docker compose build failed; the running stack was not touched" \
        in r.stderr, r.stdout + r.stderr
    assert not [a for a in changing_calls(host) if not a.startswith("compose create")]


@pytest.mark.parametrize("args", [
    ("--status", "--confirm", "x"), ("--export", "f", "--accept-summary-reset"),
    ("--import", "f", "--revert-credentials"), ("--import", "f", "--no-carry-revocations"),
    ("--reactivate", "--accept"), ("--status", "--dry-run"), ("--resume", "--dry-run"),
    ("--dry-run",), ("--import", "f", "--scanners=wifi"), ("--import", "f", "--wifi-interface=wlan1"),
    ("--export", "f", "--accept-unverified"), ("--snapshot", "--verify")])
def test_quickstart_lifecycle_options_belong_to_their_command(args, host, tmp_path):
    """Fix round (2.2, as release_parse_args): an option of another command,
    a --dry-run where none exists and a scanner choice that an import does
    not run are usage errors (exit 2), before anything else."""
    d = source_checkout(tmp_path, "SigRift")
    r = run_installer(d, *args, host=host, script=QUICKSTART)
    assert r.returncode == 2 and r.stderr.startswith("usage: "), (args, r.stdout, r.stderr)
    assert host.calls() == []


def test_quickstart_import_takes_its_project_and_expect_values(host, tmp_path):
    """--project NAME and --expect HC16 in the space form are each their own
    value (the parser shifted before it looked at the flag)."""
    d = source_checkout(tmp_path, "SigRift")
    r = run_installer(d, "--import", str(tmp_path / "none.sigrift-archive"), "--project", "lab",
                      "--expect", "0123456789ABCDEF", host=host, script=QUICKSTART)
    assert r.returncode == 3 and not r.stderr.startswith("usage: "), r.stderr
