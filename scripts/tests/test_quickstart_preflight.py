"""Fail-fast quickstart CLI contracts without touching a running Docker daemon."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import textwrap
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
BASH = shutil.which("bash")
DOCKER = shutil.which("docker")


class Checkout:
    def __init__(self, root):
        self.root = root / "checkout"
        self.bin = root / "bin"
        self.bin.mkdir()
        (self.root / "scripts").mkdir(parents=True)
        self.script = self.root / "scripts/quickstart.sh"
        shutil.copyfile(ROOT / "scripts/quickstart.sh", self.script)
        self.log = root / "commands.jsonl"
        self.pid_file = root / "probe-pids.json"
        self.env = {
            "PATH": str(self.bin),
            "HOME": str(root),
            "LC_ALL": "C",
            "PREFLIGHT_COMMAND_LOG": str(self.log),
            "PREFLIGHT_PID_FILE": str(self.pid_file),
        }
        for name in ("dirname", "cat"):
            target = shutil.which(name)
            assert target, name
            (self.bin / name).symlink_to(target)
        self.command(
            "python3",
            """
            import os, sys
            if sys.argv[1:] == ['-']:
                if os.environ.get('PREFLIGHT_OLD_PYTHON'):
                    sys.version_info = (3, 10, 14, 'final', 0)
                exec(compile(sys.stdin.read(), '<quickstart-preflight>', 'exec'))
            else:
                os.execv(sys.executable, [sys.executable, *sys.argv[1:]])
            """,
        )
        for name in ("openssl", "curl"):
            self.command(
                name,
                f"""
                import json, os, sys
                with open(os.environ['PREFLIGHT_COMMAND_LOG'], 'a') as log:
                    log.write(json.dumps({{'tool': {name!r}, 'args': sys.argv[1:]}})+'\\n')
                sys.exit(97)
                """,
            )
        self.command(
            "docker",
            """
            import json, os, signal, subprocess, sys, time
            args = sys.argv[1:]
            with open(os.environ['PREFLIGHT_COMMAND_LOG'], 'a') as log:
                log.write(json.dumps({'tool': 'docker', 'args': args,
                    'context': os.environ.get('DOCKER_CONTEXT'),
                    'host': os.environ.get('DOCKER_HOST')})+'\\n')
            if args == ['compose', 'config', '--environment']:
                sys.exit(0)
            if args == ['compose', 'version']:
                sys.exit(int(os.environ.get('PREFLIGHT_COMPOSE_RC', '0')))
            if args == ['info', '--format', '{{.ServerVersion}}']:
                if os.environ.get('PREFLIGHT_HANG'):
                    child = subprocess.Popen([sys.executable, '-c',
                        'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])
                    with open(os.environ['PREFLIGHT_PID_FILE'], 'w') as pids:
                        json.dump([os.getpid(), child.pid], pids)
                    time.sleep(60)
                sys.exit(int(os.environ.get('PREFLIGHT_DAEMON_RC', '0')))
            sys.exit(97)
            """,
        )

    def command(self, name, body):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
        path.chmod(0o755)

    def existing_configuration(self):
        (self.root / ".env").write_text(
            'BRIDGE_ADMIN_PASSWORD="existing-disposable-password"\n'
        )
        (self.root / ".env").chmod(0o600)
        (self.root / "tls").mkdir()
        (self.root / "tls/key.pem").write_text("existing fixture key\n")
        (self.root / "tls/key.pem").chmod(0o600)
        (self.root / "tls/cert.pem").write_text("existing fixture certificate\n")
        (self.root / "docker-compose.override.yml").write_text("# operator override\n")
        (self.root / "models").mkdir()
        (self.root / "models/current.onnx").write_bytes(b"existing fixture model")

    def snapshot(self):
        return {
            str(p.relative_to(self.root)): (
                p.stat().st_mode & 0o777,
                p.read_bytes() if p.is_file() else None,
            )
            for p in self.root.rglob("*")
        }

    def calls(self):
        return (
            [json.loads(line) for line in self.log.read_text().splitlines()]
            if self.log.exists()
            else []
        )

    def run(self, *args, timeout=20):
        return subprocess.run(
            [BASH, str(self.script), *args],
            env=self.env,
            input="",
            text=True,
            capture_output=True,
            timeout=timeout,
        )


@pytest.fixture
def checkout(tmp_path):
    assert BASH, "Quickstart tests require bash"
    return Checkout(tmp_path)


def assert_failure_before_setup(checkout, before, result, message):
    assert result.returncode == 1
    assert message in result.stderr
    assert "This installer will create" not in result.stdout
    assert "Using existing .env" not in result.stdout
    assert "Admin password:" not in result.stderr
    assert checkout.snapshot() == before
    assert all(
        call["tool"] == "docker"
        and call["args"]
        in (["compose", "version"], ["info", "--format", "{{.ServerVersion}}"])
        for call in checkout.calls()
    )


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize(
    "problem,message",
    [
        ("curl", "curl is required"),
        ("old-python", "Python 3.11 or newer is required"),
        ("daemon", "Docker daemon is unavailable"),
    ],
)
def test_missing_runtime_prerequisite_stops_before_any_setup_mutation(
    checkout, existing, problem, message
):
    if existing:
        checkout.existing_configuration()
    if problem == "curl":
        (checkout.bin / "curl").unlink()
    elif problem == "old-python":
        checkout.env["PREFLIGHT_OLD_PYTHON"] = "1"
    else:
        checkout.env["PREFLIGHT_DAEMON_RC"] = "1"
    before = checkout.snapshot()
    result = checkout.run()
    assert_failure_before_setup(checkout, before, result, message)


@pytest.mark.parametrize(
    "missing,message",
    [
        ("docker", "docker not found"),
        ("python3", "Python 3.11 or newer is required"),
        ("openssl", "openssl required"),
    ],
)
def test_missing_command_is_actionable_before_prompts(checkout, missing, message):
    (checkout.bin / missing).unlink()
    before = checkout.snapshot()
    assert_failure_before_setup(checkout, before, checkout.run(), message)


def test_compose_failure_is_actionable_and_does_not_probe_or_change_daemon(checkout):
    checkout.env["PREFLIGHT_COMPOSE_RC"] = "1"
    before = checkout.snapshot()
    result = checkout.run()
    assert_failure_before_setup(
        checkout, before, result, "Docker Compose plugin is unavailable"
    )
    assert [call["args"] for call in checkout.calls()] == [["compose", "version"]]


def test_installed_but_unexecutable_docker_fails_with_plugin_guidance(checkout):
    # command -v succeeds, but the executable's interpreter no longer exists.
    (checkout.bin / "docker").write_text("#!/nonexistent/preflight-interpreter\n")
    before = checkout.snapshot()
    result = checkout.run()
    assert_failure_before_setup(
        checkout, before, result, "Docker Compose plugin is unavailable"
    )
    assert "https://docs.docker.com/compose/install/" in result.stderr


@pytest.mark.parametrize("args", [(), ("--renew-tls",)])
def test_daemon_probe_preserves_selected_context_and_existing_configuration(
    checkout, args
):
    checkout.existing_configuration()
    checkout.env.update(
        DOCKER_CONTEXT="operator-context",
        DOCKER_HOST="unix:///operator/socket",
        PREFLIGHT_DAEMON_RC="1",
    )
    before = checkout.snapshot()
    result = checkout.run(*args)
    assert_failure_before_setup(
        checkout, before, result, "Docker daemon is unavailable"
    )
    assert all(
        call["context"] == "operator-context"
        and call["host"] == "unix:///operator/socket"
        for call in checkout.calls()
    )


def test_healthy_preflight_reaches_password_prompt_without_premature_writes(checkout):
    before = checkout.snapshot()
    result = checkout.run("--dashboard-only")
    # Empty stdin deliberately stops at the real password prompt, before setup.
    assert result.returncode != 0
    assert "This installer will create a local admin account" in result.stdout
    assert "Error:" not in result.stderr
    assert checkout.snapshot() == before
    assert [call["args"] for call in checkout.calls()] == [
        ["compose", "version"],
        ["info", "--format", "{{.ServerVersion}}"],
        ["compose", "config", "--environment"],
    ]


def process_running(pid):
    # A killed Linux child can briefly be a zombie until its new parent reaps it.
    stat = Path(f"/proc/{pid}/stat")
    if stat.exists() and stat.read_text().split(") ", 1)[1].startswith("Z"):
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_daemon_probe_has_real_deadline_and_reaps_owned_descendants(checkout):
    checkout.env["PREFLIGHT_HANG"] = "1"
    before = checkout.snapshot()
    pids = []
    started = time.monotonic()
    try:
        result = checkout.run(timeout=16)
        elapsed = time.monotonic() - started
        assert 9 <= elapsed < 15
        assert_failure_before_setup(
            checkout, before, result, "Docker daemon probe timed out after 10 seconds"
        )
        pids = json.loads(checkout.pid_file.read_text())
        deadline = time.monotonic() + 2
        while any(process_running(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not any(process_running(pid) for pid in pids)
    finally:
        if checkout.pid_file.exists():
            for pid in json.loads(checkout.pid_file.read_text()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_interrupted_probe_reaps_owned_descendants_without_setup_writes(
    checkout, signum
):
    checkout.env["PREFLIGHT_HANG"] = "1"
    before = checkout.snapshot()
    process = subprocess.Popen(
        [BASH, str(checkout.script)],
        env=checkout.env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not checkout.pid_file.exists() and time.monotonic() < deadline:
            assert process.poll() is None
            time.sleep(0.02)
        assert checkout.pid_file.exists()
        os.killpg(process.pid, signum)
        stdout, _stderr = process.communicate(timeout=5)
        assert process.returncode != 0
        assert "This installer will create" not in stdout
        assert checkout.snapshot() == before
        pids = json.loads(checkout.pid_file.read_text())
        deadline = time.monotonic() + 2
        while any(process_running(pid) for pid in pids) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not any(process_running(pid) for pid in pids)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        if checkout.pid_file.exists():
            for pid in json.loads(checkout.pid_file.read_text()):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.mark.skipif(not DOCKER, reason="Real Docker CLI not installed")
def test_real_unreachable_docker_endpoint_fails_before_setup(checkout):
    # Only the daemon probe is delegated to the actual CLI. Compose presence
    # is a separate command-boundary contract above; no live daemon is queried.
    checkout.command(
        "docker",
        f"""
        import os, sys
        if sys.argv[1:] == ['compose', 'version']:
            sys.exit(0)
        os.execv({DOCKER!r}, [{DOCKER!r}, *sys.argv[1:]])
        """,
    )
    checkout.env["DOCKER_HOST"] = "unix://" + str(checkout.root / "absent-docker.sock")
    before = checkout.snapshot()
    result = checkout.run()
    assert_failure_before_setup(
        checkout, before, result, "Docker daemon is unavailable"
    )
    assert "docker info" in result.stderr
