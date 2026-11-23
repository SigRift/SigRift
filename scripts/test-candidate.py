#!/usr/bin/env python3
"""Build and test an isolated, disposable source candidate without GHCR.

Requires Python 3.11+, Docker/Compose, openssl, curl, jq and a Python environment
with pytest-playwright, pytest-timeout and Chromium. The work directory must be
shared with Docker. Only results.json and junit.xml are safe to share by default;
private/ contains local logs/browser evidence that can include test credentials.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
OVERRIDE = """# Disposable source candidate; hardware adapters are excluded.
services:
  bridge:
    environment:
      BRIDGE_ENV: production
  gateway:
    environment:
      BRIDGE_ENV: production
    volumes:
      - ./tls:/app/tls:ro
  edge:
    volumes:
      - ./tls/cert.pem:/app/tls/cert.pem:ro
    environment:
      MLRF_CA_CERT: /app/tls/cert.pem
  rtl-tcp:
    profiles: [hardware]
  scan:
    profiles: [hardware]
  wifi-scan:
    profiles: [hardware]
  bt-scan:
    profiles: [hardware]
"""


def isolated_environment():
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(
            ("COMPOSE_", "BRIDGE_", "UC_", "MLRF_", "SIGRIFT_", "PYTEST_")
        )
        and key != "PYTHONOPTIMIZE"
    }


def isolate_curl_configuration(environment, directory):
    """Suppress ambient curlrc without changing HOME or Docker configuration.

    An existing empty file is required: curl falls back to HOME when CURL_HOME
    names an empty directory. Callers must supply their own private directory;
    legacy callers of isolated_environment alone retain their previous behavior.
    """
    directory.mkdir(mode=0o700)
    with (directory / ".curlrc").open("x"):
        pass
    # Curl/Python TLS diagnostics must not export session secrets or traces to
    # paths selected by the caller. Raw harness logs stay in the owned output.
    isolated = {
        key: value
        for key, value in environment.items()
        if key not in {"SSLKEYLOGFILE", "QLOGDIR"}
    }
    return isolated | {"CURL_HOME": str(directory.resolve())}


def verify_browser_report(path, expected=None):
    cases = ET.parse(path).getroot().findall(".//testcase")
    if not cases or any(
        child.tag in {"skipped", "failure", "error"} for case in cases for child in case
    ):
        raise RuntimeError(
            "Browser suite must execute tests with zero skips, failures or errors"
        )
    if expected is not None and len(cases) != expected:
        raise RuntimeError("Browser report must contain exactly the collected tests")
    return len(cases)


# Browser time is dominated by a few real-time tests and by login-heavy tests
# that honour one server Retry-After of up to 60 seconds, not by test count.
# The base covers those, the per-test allowance keeps headroom as the suite
# grows, the floor is the original fixed deadline and the cap keeps a finite,
# fail-closed hang guard equal to the Runner.run default.
BROWSER_DEADLINE_BASE = 300
BROWSER_DEADLINE_PER_TEST = 40
BROWSER_DEADLINE_FLOOR = 900
BROWSER_DEADLINE_CAP = 1800


def browser_deadline(tests):
    if type(tests) is not int or tests < 1:
        raise RuntimeError("Browser suite must collect at least one test")
    return min(
        BROWSER_DEADLINE_CAP,
        max(
            BROWSER_DEADLINE_FLOOR,
            BROWSER_DEADLINE_BASE + BROWSER_DEADLINE_PER_TEST * tests,
        ),
    )


ANSI_SGR = re.compile(r"\x1b\[[0-9;]*m")


COLLECTED = re.compile(r"(\d+)(?:/\d+)? tests? collected\b(?: \((\d+) deselected\))?")


def collection_summary(output):
    """pytest --collect-only -q's one summary: (collected, deselected)."""
    counts = [
        (int(match.group(1)), int(match.group(2) or 0))
        for line in ANSI_SGR.sub("", output).splitlines()
        if (match := COLLECTED.match(line.strip()))
    ]
    if len(counts) != 1 or counts[0][0] < 1:
        raise RuntimeError(
            "Browser suite collection must report one positive test count"
        )
    return counts[0]


def collected_test_count(output):
    """Read pytest --collect-only -q's one "N[/M] tests collected" summary."""
    return collection_summary(output)[0]


# Collection only imports the suite; a hang there is not a slow browser test.
BROWSER_COLLECT_TIMEOUT = 120


def collect_browser_tests(
    runner, python, arguments, env, timeout=BROWSER_COLLECT_TIMEOUT
):
    # Same interpreter, environment, rootdir (the source cwd) and arguments as
    # the real run. A collection, usage or configuration error or an empty
    # suite exits non-zero and a hang meets the deadline: the step fails
    # closed. Like every step, stdout and stderr reach only its private log.
    # --color=no keeps an inherited PY_COLORS/FORCE_COLOR off the summary.
    return collection_summary(
        collect_browser_output(runner, python, arguments, env, timeout)
    )[0]


def collect_browser_output(
    runner, python, arguments, env, timeout=BROWSER_COLLECT_TIMEOUT
):
    runner.run(
        "browser-collect",
        [python, "-m", "pytest", *arguments, "--collect-only", "-q", "--color=no"],
        env=env,
        timeout=timeout,
    )
    log = runner.private / "browser-collect.log"
    return log.read_text(errors="replace")


def verify_known_bug_report(path, expected):
    """Every case of the known-bug lane failed as expected, for a "BUG:" reason.

    pytest records a strict xfail that failed as <skipped type="pytest.xfail">
    with its reason, and one that passed as a failure. Anything else (a pass,
    a plain skip, an error) means the lane did not show the bug.
    """
    cases = ET.parse(path).getroot().findall(".//testcase")
    for case in cases:
        children = list(case)
        if not (
            len(children) == 1
            and children[0].tag == "skipped"
            and children[0].get("type") == "pytest.xfail"
            and children[0].get("message", "").startswith("BUG:")
        ):
            raise RuntimeError(
                "Known-bug lane: every test must still fail for its BUG reason; "
                "delete the marker of a fixed bug"
            )
    if len(cases) != expected:
        raise RuntimeError("Known-bug lane must run exactly the deselected tests")
    return len(cases)


def run_known_bug_lane(runner, python, base_url, env, results, expected):
    """Run the open-bug regressions the browser suite deselected.

    tests/e2e/conftest.py deselects strict "BUG:" xfail tests from ordinary
    runs (pytest reports an expected failure as a skip, which a required run
    refuses) and runs only them under SIGRIFT_E2E_KNOWN_BUGS=1, where their
    expected failure is accepted and a pass (strict XPASS) fails the step.
    Browser JavaScript coverage stays the required suite's evidence.
    """
    results["known_bugs"] = 0
    if not expected:
        return
    lane_env = {
        key: value for key, value in env.items() if key != "SIGRIFT_E2E_JS_COVERAGE"
    } | {"SIGRIFT_E2E_KNOWN_BUGS": "1"}
    report = runner.private / "browser-known-bugs-junit.xml"
    runner.run(
        "browser-known-bugs",
        [
            python,
            "-m",
            "pytest",
            "tests/e2e",
            "--base-url",
            base_url,
            "--timeout=120",
            "--tracing=retain-on-failure",
            "--screenshot=only-on-failure",
            f"--output={runner.private / 'browser-known-bugs'}",
            f"--junitxml={report}",
        ],
        env=lane_env,
        timeout=browser_deadline(expected),
    )
    results["known_bugs"] = verify_known_bug_report(report, expected)


def run_browser_suite(runner, python, base_url, env, results):
    arguments = [
        "tests/e2e",
        "--base-url",
        base_url,
        "--timeout=120",
        "--tracing=retain-on-failure",
        "--screenshot=only-on-failure",
        f"--output={runner.private / 'browser'}",
    ]
    # Under ordinary runs the suite deselects only its open-bug regressions.
    collected, known_bugs = collection_summary(
        collect_browser_output(runner, python, arguments, env)
    )
    timeout = browser_deadline(collected)
    # Record before running so a deadline failure still shows its budget.
    results["browser_budget"] = {
        "collected_tests": collected,
        "timeout_seconds": timeout,
    }
    report = runner.private / "browser-junit.xml"
    runner.run(
        "browser",
        [python, "-m", "pytest", *arguments, f"--junitxml={report}"],
        env=env,
        timeout=timeout,
    )
    results["browser_tests"] = verify_browser_report(report, collected)
    return known_bugs


def verify_compose_scope(config, project, port):
    if set(config["services"]) != {"bridge", "gateway", "edge"}:
        raise RuntimeError("Candidate must contain only bridge, gateway and edge")
    for kind in ("networks", "volumes"):
        for resource in config.get(kind, {}).values():
            if resource.get("external") or not resource.get("name", "").startswith(
                project + "_"
            ):
                raise RuntimeError(
                    "Candidate resources must belong to its unique project"
                )
    for service in config["services"].values():
        if (
            service.get("container_name")
            or service.get("privileged")
            or service.get("network_mode") == "host"
        ):
            raise RuntimeError("Candidate services must stay isolated")
    ports = config["services"]["gateway"]["ports"]
    if (
        len(ports) != 1
        or ports[0].get("host_ip") != "127.0.0.1"
        or int(ports[0]["published"]) != port
    ):
        raise RuntimeError(
            "Candidate gateway must bind only its selected loopback port"
        )


def source_snapshot(root, destination, allow_dirty):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args])

    sha = git("rev-parse", "HEAD").decode().strip()
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    if dirty and not allow_dirty:
        raise RuntimeError(
            "Source tree is dirty; commit it or explicitly use --allow-dirty"
        )
    # A gitlink's code lives in another repository; staging the empty or
    # checked-out directory would claim this commit's provenance without it.
    tracked = {}
    for entry in git("ls-files", "-z", "--stage").decode().split("\0"):
        if entry:
            meta, _, name = entry.partition("\t")
            tracked[name] = meta.split(" ", 1)[0]
    gitlinks = sorted(name for name, mode in tracked.items() if mode == "160000")
    if gitlinks:
        raise RuntimeError(
            "Source tree contains git submodules, which candidates cannot stage: "
            + ", ".join(gitlinks)
        )
    git_directories = {}

    def enclosing_bare_repository(name):
        # A bare repository has no .git entry, so git lists its files (config
        # included, which can hold credentialed remote URLs) individually.
        # Git's own test for a git directory: HEAD, objects/ and refs/.
        for parent in reversed(Path(name).parents):
            key = parent.as_posix()
            if key == ".":
                continue
            if key not in git_directories:
                path = root / parent
                git_directories[key] = (
                    (path / "HEAD").is_file()
                    and (path / "objects").is_dir()
                    and (path / "refs").is_dir()
                )
            if git_directories[key]:
                return key
        return None

    names = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    digest = hashlib.sha256()
    count = 0
    nested = set()
    for name in sorted(set(names.decode().rstrip("\0").split("\0"))):
        if not name:
            continue
        path = root / name
        if not path.exists() and not path.is_symlink():
            continue
        # Only untracked files (so only --allow-dirty trees): committed
        # fixtures that look like a git directory are this commit's code.
        if name not in tracked and (bare := enclosing_bare_repository(name)):
            nested.add(bare)
            continue
        # is_dir() follows symlinks; tracked symlinks to directories are copied.
        if not path.is_symlink() and path.is_dir():
            if name.endswith("/") or os.path.lexists(path / ".git"):
                # Git does not descend into a nested repository or worktree,
                # whether untracked (listed with a trailing slash) or
                # replacing a tracked file (listed by its tracked name only).
                # Never copy its .git into the build context; the entry
                # already makes the tree dirty.
                nested.add(name.rstrip("/"))
                continue
            if name in tracked:
                # A tracked file replaced by a plain directory: already dirty,
                # and git lists the directory's own files individually.
                continue
            raise RuntimeError(f"Unexpected directory in source listing: {name}")
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target, follow_symlinks=False)
        content = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        digest.update(name.encode() + b"\0" + hashlib.sha256(content).digest())
        count += 1
    return {
        "commit": sha,
        "dirty": dirty,
        "source_sha256": digest.hexdigest(),
        "files": count,
        # Relative paths only (results.json is shareable); not in the digest.
        "skipped_nested_repositories": sorted(nested),
    }


class Runner:
    def __init__(self, source, output, env):
        self.source, self.output, self.env = source, output, env
        self.steps = []
        self.private = output / "private"
        self.private.mkdir(mode=0o700)

    def run(self, name, command, *, stdin=None, env=None, timeout=1800):
        print(f"[{name}] running", flush=True)
        started = time.monotonic()
        logfile = self.private / f"{name}.log"
        with logfile.open("w") as log:
            process = subprocess.Popen(
                command,
                cwd=self.source,
                env=self.env if env is None else env,
                stdin=subprocess.PIPE,
                text=True,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                process.communicate(stdin, timeout=timeout)
                ok = process.returncode == 0
            except subprocess.TimeoutExpired:
                ok = False
                self.terminate(process)
                log.write("\nCandidate step exceeded its deadline.\n")
            except BaseException:
                self.terminate(process)
                raise
        self.steps.append(
            {
                "name": name,
                "passed": ok,
                "seconds": round(time.monotonic() - started, 2),
            }
        )
        print(f"[{name}] {'PASS' if ok else 'FAIL'}", flush=True)
        if not ok:
            raise RuntimeError(f"{name} failed; inspect private/{name}.log locally")

    @staticmethod
    def terminate(process, grace=10):
        # A shell can exit before its child browser/build process. Always
        # address the session's process group, even after that parent exits.
        def signal_group(signum):
            try:
                os.killpg(process.pid, signum)
            except PermissionError as error:
                # macOS can return EPERM while this child is dying but has
                # not yet been reaped. Reap it, then retry the group: living
                # descendants still need the signal after the parent exits.
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    raise error
                try:
                    os.killpg(process.pid, signum)
                except ProcessLookupError:
                    return False
            except ProcessLookupError:
                return False
            return True

        if not signal_group(signal.SIGTERM):
            process.wait()
            return
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            process.poll()  # Reap the parent so its zombie does not hold the group.
            if not signal_group(0):
                break
            time.sleep(0.05)
        signal_group(signal.SIGKILL)
        process.wait()

    def capture(self, *command, env=None):
        return subprocess.check_output(
            command,
            cwd=self.source,
            env=self.env if env is None else env,
            text=True,
            timeout=60,
        )


def recreate_gateway_with_live_bridge(runner, bridge):
    started = runner.capture(
        "docker", "inspect", "--format", "{{.State.StartedAt}}", bridge
    )
    runner.run(
        "gateway-recreate",
        [
            "docker",
            "compose",
            "up",
            "-d",
            "--no-deps",
            "--no-build",
            "--force-recreate",
            "--wait",
            "--wait-timeout",
            "240",
            "gateway",
        ],
        timeout=300,
    )
    current = runner.capture("docker", "compose", "ps", "-q", "bridge").strip()
    if (
        current != bridge
        or runner.capture(
            "docker", "inspect", "--format", "{{.State.StartedAt}}", bridge
        )
        != started
    ):
        raise RuntimeError("Gateway-only restart also restarted the bridge")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--work-dir",
        type=Path,
        required=True,
        help="Docker-shared parent for isolated runs",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python with pytest-playwright and Chromium installed",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Local development only; records dirty provenance",
    )
    parser.add_argument(
        "--keep-on-failure",
        action="store_true",
        help="Debug only: retain this isolated project and private credentials on failure",
    )
    args = parser.parse_args()

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    if sys.version_info < (3, 11):
        parser.error("Python 3.11+ is required")
    if not __debug__:
        parser.error("Assertions must be enabled; do not use python -O/PYTHONOPTIMIZE")
    for command in ("git", "docker", "openssl", "curl", "jq"):
        if not shutil.which(command):
            parser.error(f"Required command missing: {command}")
    # Keep every raw diagnostic and generated credential private on the host.
    os.umask(0o077)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    output = Path(
        tempfile.mkdtemp(prefix="sigrift-candidate-", dir=args.work_dir.resolve())
    )
    source = output / "source"
    source.mkdir()
    env = isolate_curl_configuration(isolated_environment(), output / "private-curl")
    project = "sigrift-test-" + secrets.token_hex(6)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env.update(
        COMPOSE_PROJECT_NAME=project,
        SIGRIFT_BIND="127.0.0.1",
        UC_PORT=str(port),
        SIGRIFT_PRESET="none",
    )
    runner = Runner(source, output, env)
    results = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "project": project,
        "port": port,
        "passed": False,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
    }
    failure = None
    scope_verified = False
    print(f"Private run directory: {output}", flush=True)
    try:
        results["source"] = source_snapshot(ROOT, source, args.allow_dirty)
        (source / "docker-compose.override.yml").write_text(OVERRIDE)
        # mktemp defaults to 0700. Container uid1500 must read staged source/TLS
        # bind mounts; source files contain no credentials at this point.
        source.chmod(0o755)
        for directory in source.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        results["python"] = runner.capture(args.python, "--version").strip()
        results["browser_tools"] = json.loads(
            runner.capture(
                args.python,
                "-c",
                "import importlib.metadata,json; print(json.dumps({name: importlib.metadata.version(name) for name in ('pytest', 'pytest-playwright', 'playwright')}))",
            )
        )
        results["docker"] = runner.capture(
            "docker", "version", "--format", "{{.Server.Version}}"
        ).strip()
        results["docker_platform"] = runner.capture(
            "docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"
        ).strip()
        results["compose"] = runner.capture(
            "docker", "compose", "version", "--short"
        ).strip()
        runner.run(
            "browser-preflight",
            [
                args.python,
                "-c",
                "import pytest, pytest_playwright; from playwright.sync_api import sync_playwright; p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop()",
            ],
            timeout=60,
        )
        verify_compose_scope(
            json.loads(
                runner.capture("docker", "compose", "config", "--format", "json")
            ),
            project,
            port,
        )
        scope_verified = True
        # Refuse an unshared directory before a long build (Colima does not
        # share /private/tmp by default). Use the already pinned Python base.
        base = (
            (source / "src/sigrift/bridge/Dockerfile")
            .read_text()
            .split("FROM ", 1)[1]
            .split()[0]
        )
        marker = secrets.token_hex(16)
        (source / ".candidate-bind-check").write_text(marker)
        runner.run(
            "bind-mount-preflight",
            [
                "docker",
                "run",
                "--rm",
                "--mount",
                f"type=bind,src={source},dst=/candidate,readonly",
                base,
                "python3",
                "-c",
                f"from pathlib import Path; assert Path('/candidate/.candidate-bind-check').read_text() == {marker!r}, 'work directory is not shared with Docker'",
            ],
            timeout=180,
        )
        password = secrets.token_urlsafe(32)
        runner.run(
            "fresh-install",
            ["bash", "scripts/quickstart.sh", "--scanners=none"],
            stdin=f"{password}\n{password}\n",
        )
        cfg = json.loads(
            runner.capture("docker", "compose", "config", "--format", "json")
        )
        verify_compose_scope(cfg, project, port)
        assert set(cfg["services"]) == {"bridge", "gateway", "edge"}
        assert all(
            cfg["services"][name]["environment"]["BRIDGE_ENV"] == "production"
            for name in ("bridge", "gateway")
        )
        assert cfg["services"]["gateway"]["ports"][0]["host_ip"] == "127.0.0.1"
        results["backend_network"] = cfg["networks"]["backend"]["ipam"]["config"]
        results["gateway_backend_ip"] = cfg["services"]["gateway"]["networks"][
            "backend"
        ]["ipv4_address"]
        base_url = f"https://127.0.0.1:{port}"
        test_env = env | {
            "BASE_URL": base_url,
            "BRIDGE_ADMIN_USER": "admin",
            "BRIDGE_ADMIN_PASSWORD": password,
            "BRIDGE_LOCAL_NODE_KEY": cfg["services"]["bridge"]["environment"][
                "BRIDGE_LOCAL_NODE_KEY"
            ],
            "LOG_DIR": str(runner.private),
            "SIGRIFT_E2E_REQUIRED": "1",
            "SIGRIFT_E2E_DISPOSABLE": "1",
            # The stack is this commit's build: every page must carry the
            # reviewed CSP (tests/e2e/conftest.py), not just any policy.
            "SIGRIFT_E2E_CSP": "reviewed",
            "SIGRIFT_E2E_CA_CERT": str(source / "tls/cert.pem"),
            "SIGRIFT_E2E_JS_COVERAGE": str(runner.private / "browser-js"),
            "PYTHONPATH": str(source / "src"),
        }
        bridge = runner.capture("docker", "compose", "ps", "-q", "bridge").strip()
        runner.run(
            "staging-smoke",
            ["bash", "scripts/staging-smoke.sh"],
            env=test_env,
            timeout=120,
        )
        core_command = [
            args.python,
            "scripts/smoke-core.py",
            "--disposable",
            "--base-url",
            base_url,
            "--ca-cert",
            "tls/cert.pem",
            "--bridge-container",
            bridge,
        ]
        runner.run(
            "core-security",
            core_command,
            env=test_env,
            timeout=300,
        )
        state_script = """import json, sqlite3
with sqlite3.connect('/app/src/sigrift/bridge/data/detections.db') as db:
    assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
    users = [r[0] for r in db.execute("SELECT username FROM users WHERE username LIKE 'smoke_%' ORDER BY username")]
    detections = [r[0] for r in db.execute("SELECT detection_id FROM detections WHERE detection_id LIKE 'smoke-detection-%' ORDER BY detection_id")]
    assert users and detections
    print(json.dumps({'users':users, 'detections':detections}))
"""

        def state():
            return json.loads(
                runner.capture(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "bridge",
                    "python3",
                    "-c",
                    state_script,
                )
            )

        before = state()
        # Stopping both processes can conceal a lost SQLite WAL lock. Keep
        # the migrated bridge alive across gateway exit, then authenticate
        # afresh and exercise native ingest plus proxied reads/writes/hooks.
        recreate_gateway_with_live_bridge(runner, bridge)
        assert state() == before, (
            "Seeded users/detections changed across gateway restart"
        )
        runner.run("gateway-recreate-security", core_command, env=test_env, timeout=300)
        results["persistence"] = {"gateway_only_restart": True}
        before = state()  # The second smoke added its own unique fixtures.
        runner.run("persistent-stop", ["docker", "compose", "down"], timeout=120)
        runner.run(
            "persistent-start",
            [
                "docker",
                "compose",
                "up",
                "-d",
                "--no-build",
                "--wait",
                "--wait-timeout",
                "240",
            ],
            timeout=300,
        )
        assert state() == before, "Seeded users/detections changed across stop/start"
        results["persistence"]["stop_start"] = True
        runner.run(
            "installer-rerun",
            ["bash", "scripts/quickstart.sh", "--scanners=none"],
            stdin="",
        )
        assert state() == before, (
            "Seeded users/detections changed across installer rerun"
        )
        results["persistence"]["installer_rerun"] = True
        known_bugs = run_browser_suite(runner, args.python, base_url, test_env, results)
        run_known_bug_lane(runner, args.python, base_url, test_env, results, known_bugs)
        results["images"] = json.loads(
            runner.capture("docker", "compose", "images", "--format", "json")
        )
        results["passed"] = True
    except (Exception, KeyboardInterrupt) as exc:
        failure = exc
        results["passed"] = False
        with (runner.private / "failure.txt").open("w") as diagnostic:
            traceback.print_exc(file=diagnostic)
        # Exception messages can contain subprocess output or credentials.
        print(
            f"Candidate FAILED ({type(exc).__name__}); inspect private diagnostics.",
            file=sys.stderr,
        )
    finally:
        cleaned = False
        if scope_verified:
            for name, command in (
                ("containers", ["docker", "compose", "ps", "--all"]),
                (
                    "service-logs",
                    ["docker", "compose", "logs", "--no-color", "--tail=100"],
                ),
                ("cleanup", ["docker", "compose", "down", "-v", "--remove-orphans"]),
            ):
                if name == "cleanup" and failure is not None and args.keep_on_failure:
                    results["retained_for_debug"] = True
                    print(
                        f"Debug stack retained: project {project}, source {source}",
                        flush=True,
                    )
                    continue
                try:
                    if name == "cleanup":
                        verify_compose_scope(
                            json.loads(
                                runner.capture(
                                    "docker", "compose", "config", "--format", "json"
                                )
                            ),
                            project,
                            port,
                        )
                    runner.run(name, command, timeout=120)
                    if name == "cleanup":
                        cleaned = True
                except Exception:
                    if name == "cleanup":
                        results["passed"] = False
                        print(
                            f"Cleanup failed for project {project}; retry from {source} with COMPOSE_PROJECT_NAME={project}.",
                            file=sys.stderr,
                        )
        # Do not retain fresh installer secrets in the staged source tree.
        if cleaned:
            (source / ".env").unlink(missing_ok=True)
            shutil.rmtree(source / "tls", ignore_errors=True)
        results["steps"] = runner.steps
        results["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        suite = ET.Element(
            "testsuite", name="source-candidate", tests=str(len(runner.steps))
        )
        for step in runner.steps:
            case = ET.SubElement(
                suite, "testcase", name=step["name"], time=str(step["seconds"])
            )
            if not step["passed"]:
                ET.SubElement(case, "failure", message="See private local diagnostics")
        if failure is not None:
            case = ET.SubElement(suite, "testcase", name="candidate-contract")
            ET.SubElement(case, "failure", message=type(failure).__name__)
        suite.set("tests", str(len(suite)))
        suite.set("failures", str(len(suite.findall("testcase/failure"))))
        ET.ElementTree(suite).write(output / "junit.xml", encoding="unicode")
        print(f"Result: {output / 'results.json'}", flush=True)
    return 0 if results.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
