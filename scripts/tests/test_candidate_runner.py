"""Fail-closed boundaries for the disposable candidate runner."""

import importlib.util
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from threading import Thread
import time

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "test-candidate.py"
SPEC = importlib.util.spec_from_file_location("candidate_runner", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def test_external_compose_and_pytest_settings_cannot_change_scope(monkeypatch):
    for name in (
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_PROFILES",
        "BRIDGE_ADMIN_PASSWORD",
        "UC_PORT",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTHONOPTIMIZE",
    ):
        monkeypatch.setenv(name, "unexpected")
    env = runner.isolated_environment()
    assert not any(
        name.startswith(("COMPOSE_", "BRIDGE_", "UC_", "PYTEST_")) for name in env
    )
    assert "PYTHONOPTIMIZE" not in env
    assert env["PATH"] == os.environ["PATH"]


@pytest.mark.parametrize("config_variable", ["HOME", "CURL_HOME", "XDG_CONFIG_HOME"])
def test_owned_curl_config_suppresses_real_ambient_headers_without_changing_docker(
    tmp_path, monkeypatch, config_variable
):
    ambient = tmp_path / "ambient"
    ambient.mkdir()
    for variable in ("CURL_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(variable, raising=False)
    ordinary_home = tmp_path / "ordinary-home"
    ordinary_home.mkdir()
    monkeypatch.setenv("HOME", str(ordinary_home))
    monkeypatch.setenv(config_variable, str(ambient))
    monkeypatch.setenv("DOCKER_CONFIG", str(ambient / "docker"))
    monkeypatch.setenv("SSLKEYLOGFILE", str(ambient / "foreign-tls-secrets"))
    monkeypatch.setenv("QLOGDIR", str(ambient / "foreign-traces"))
    # Bundled macOS curl uses .curlrc for XDG; upstream documents curlrc.
    # Separate HOME ensures either filename is loaded from the intended source.
    for filename in ("curlrc", ".curlrc"):
        (ambient / filename).write_text(
            'header = "X-Candidate-Dummy: ambient-config"\n'
        )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(self.headers.get("X-Candidate-Dummy")).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--max-time",
        "5",
        f"http://127.0.0.1:{server.server_port}/",
    ]
    try:
        original = runner.isolated_environment()
        assert (
            json.loads(subprocess.check_output(command, env=original))
            == "ambient-config"
        )
        isolated = runner.isolate_curl_configuration(
            original, tmp_path / "private-curl"
        )
        assert isolated["HOME"] == original["HOME"]
        assert isolated["DOCKER_CONFIG"] == original["DOCKER_CONFIG"]
        assert "SSLKEYLOGFILE" not in isolated and "QLOGDIR" not in isolated
        assert (Path(isolated["CURL_HOME"]) / ".curlrc").read_text() == ""
        assert json.loads(subprocess.check_output(command, env=isolated)) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<testcase><skipped/></testcase>",
        "<testcase><failure/></testcase>",
        "<testcase><error/></testcase>",
    ],
)
def test_browser_report_requires_actual_unskipped_assertions(tmp_path, body):
    path = tmp_path / "browser.xml"
    path.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    with pytest.raises(RuntimeError):
        runner.verify_browser_report(path)


def test_browser_report_counts_executed_tests(tmp_path):
    path = tmp_path / "browser.xml"
    path.write_text(
        '<testsuites><testsuite><testcase name="login"/><testcase name="dashboard"/></testsuite></testsuites>'
    )
    assert runner.verify_browser_report(path) == 2


def test_browser_report_must_match_the_collected_suite(tmp_path):
    path = tmp_path / "browser.xml"
    path.write_text(
        '<testsuites><testsuite><testcase name="login"/><testcase name="dashboard"/></testsuite></testsuites>'
    )
    assert runner.verify_browser_report(path, 2) == 2
    for expected in (1, 3):
        with pytest.raises(RuntimeError, match="collected"):
            runner.verify_browser_report(path, expected)


def test_browser_deadline_has_floor_scaling_and_hard_cap():
    deadline = runner.browser_deadline
    # Never below the original fixed 900-second deadline.
    assert deadline(1) == deadline(9) == 900
    # Measured: 33 tests in 660.08 s on macOS arm64; the native Pi is slower.
    assert deadline(33) == 300 + 40 * 33 >= 2 * 660.08
    growing = [deadline(tests) for tests in range(16, 38)]
    assert growing == sorted(set(growing)) and growing[0] > 900
    # A finite, fail-closed hang guard no longer than the Runner default.
    timeout = runner.Runner.run.__kwdefaults__["timeout"]
    assert timeout == 1800 and deadline(38) == deadline(10_000) == timeout
    assert all(900 <= deadline(tests) <= timeout for tests in range(1, 500))
    for invalid in (0, -1, True, 1.5, None):
        with pytest.raises(RuntimeError, match="at least one test"):
            deadline(invalid)


@pytest.mark.parametrize(
    "summary, expected",
    [
        ("33 tests collected in 0.42s", 33),
        ("1 test collected in 0.01s", 1),
        ("4/5 tests collected (1 deselected) in 0.00s", 4),
        ("33 tests collected in 61.20s (0:01:01)", 33),
    ],
)
def test_collected_test_count_reads_the_selected_total(summary, expected):
    output = (
        "tests/e2e/test_a.py::test_one\n\n"
        "=== warnings summary ===\ntests/e2e/test_a.py:5\n  DeprecationWarning\n\n"
        f"{summary}\n"
    )
    assert runner.collected_test_count(output) == expected


@pytest.mark.parametrize(
    "output",
    [
        "",
        "no tests collected in 0.01s\n",
        "0 tests collected in 0.01s\n",
        "tests/e2e/test_a.py::test_one\n",
        "2 tests collected in 0.1s\n3 tests collected in 0.1s\n",
    ],
)
def test_collected_test_count_fails_closed_without_one_positive_total(output):
    with pytest.raises(RuntimeError, match="collection"):
        runner.collected_test_count(output)


def test_collected_test_count_ignores_terminal_colour():
    # What pytest prints under PY_COLORS=1 or FORCE_COLOR=1, even to a pipe.
    output = "\x1b[32m\x1b[32m2 tests collected\x1b[0m\x1b[32m in 0.01s\x1b[0m\n"
    assert runner.collected_test_count(output) == 2


def _collection_fixture(tmp_path):
    source, output = tmp_path / "source", tmp_path / "output"
    suite = source / "tests/e2e"
    suite.mkdir(parents=True)
    output.mkdir()
    (source / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\n"
        "addopts = \"-m 'not performance' --strict-markers\"\n"
        'markers = ["performance: excluded by default"]\n'
    )
    (suite / "conftest.py").write_text(
        "import os, time\n"
        "import pytest\n"
        "if os.environ.get('CANDIDATE_FIXTURE') == 'hang':\n"
        "    time.sleep(30)\n"
        "def pytest_configure(config):\n"
        "    if os.environ.get('CANDIDATE_FIXTURE') == 'usage':\n"
        "        raise pytest.UsageError('CANDIDATE-USAGE-ERROR needs a setting')\n"
        "def pytest_collection_modifyitems(config, items):\n"
        "    if os.environ.get('CANDIDATE_FIXTURE') != 'browser':\n"
        "        items.clear()\n"
    )
    (suite / "test_suite.py").write_text(
        "import warnings\n"
        "import pytest\n"
        "warnings.warn('collection-time warning', DeprecationWarning)\n"
        "@pytest.mark.parametrize('case', ['a::b', 'c d'])\n"
        "def test_parametrized(case): pass\n"
        "@pytest.mark.performance\n"
        "def test_excluded(): pass\n"
        "@pytest.mark.timeout(300)\n"
        "def test_long(): pass\n"
    )
    task = runner.Runner(source, output, runner.isolated_environment())
    return task, suite, output / "private/browser-collect.log"


def test_browser_collection_uses_the_step_environment_and_real_pytest(tmp_path):
    task, suite, log = _collection_fixture(tmp_path)
    env = runner.isolated_environment() | {"CANDIDATE_FIXTURE": "browser"}
    arguments = ["tests/e2e", "--timeout=120"]
    assert runner.collect_browser_tests(task, sys.executable, arguments, env) == 3
    assert "tests/e2e/test_suite.py::test_long" in log.read_text()
    assert task.steps[-1]["name"] == "browser-collect" and task.steps[-1]["passed"]
    # Collection runs with the browser step's environment, not the runner's:
    # without it no tests are collected, and pytest's exit status fails closed.
    with pytest.raises(RuntimeError, match="browser-collect failed"):
        runner.collect_browser_tests(task, sys.executable, arguments, task.env)
    assert task.steps[-1]["passed"] is False
    (suite / "test_broken.py").write_text("raise ImportError('broken suite')\n")
    with pytest.raises(RuntimeError, match="browser-collect failed"):
        runner.collect_browser_tests(task, sys.executable, arguments, env)
    assert "broken suite" in log.read_text()


def test_browser_collection_ignores_inherited_colour_settings(tmp_path):
    task, _suite, log = _collection_fixture(tmp_path)
    env = runner.isolated_environment() | {
        "CANDIDATE_FIXTURE": "browser",
        "PY_COLORS": "1",
        "FORCE_COLOR": "1",
    }
    # Real pytest colours its summary under these even when output is a file.
    assert runner.collect_browser_tests(task, sys.executable, ["tests/e2e"], env) == 3
    assert "3/4 tests collected" in log.read_text() and "\x1b" not in log.read_text()


@pytest.mark.parametrize("failure", ["argument", "conftest"])
def test_browser_collection_errors_reach_only_the_private_log(tmp_path, capfd, failure):
    task, _suite, log = _collection_fixture(tmp_path)
    env = runner.isolated_environment() | {"CANDIDATE_FIXTURE": "browser"}
    arguments = ["tests/e2e"]
    if failure == "argument":
        arguments.append("--candidate-unknown-option")
        expected = "--candidate-unknown-option"
    else:
        env["CANDIDATE_FIXTURE"] = "usage"
        expected = "CANDIDATE-USAGE-ERROR"
    capfd.readouterr()
    with pytest.raises(RuntimeError, match="browser-collect failed") as error:
        runner.collect_browser_tests(task, sys.executable, arguments, env)
    console = capfd.readouterr()
    # Pytest writes usage and configuration errors to stderr, with rootdir.
    assert expected in log.read_text()
    assert expected not in console.out + console.err + str(error.value)
    assert str(tmp_path) not in console.out + console.err


def test_browser_collection_deadline_fails_closed_with_a_log(tmp_path):
    task, _suite, log = _collection_fixture(tmp_path)
    env = runner.isolated_environment() | {"CANDIDATE_FIXTURE": "hang"}
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="browser-collect failed"):
        runner.collect_browser_tests(
            task, sys.executable, ["tests/e2e"], env, timeout=0.5
        )
    assert time.monotonic() - started < 20
    assert "exceeded its deadline" in log.read_text()
    assert task.steps[-1]["name"] == "browser-collect"
    assert task.steps[-1]["passed"] is False


class BrowserSteps:
    def __init__(self, private, collected, executed, passed=True):
        self.private = private
        self.collected, self.executed, self.passed = collected, executed, passed
        self.collect = self.ran = None

    def run(self, name, command, *, env=None, timeout=1800):
        if name == "browser-collect":
            self.collect = (command, env, timeout)
            (self.private / "browser-collect.log").write_text(
                f"tests/e2e/test_a.py::test_one\n\n{self.collected} tests collected in 0.1s\n"
            )
            return
        self.ran = (name, command, env, timeout)
        cases = "".join(f'<testcase name="t{n}"/>' for n in range(self.executed))
        (self.private / "browser-junit.xml").write_text(
            f"<testsuites><testsuite>{cases}</testsuite></testsuites>"
        )
        if not self.passed:
            raise RuntimeError(f"{name} failed; inspect private/{name}.log locally")


def test_browser_step_deadline_is_sized_from_its_own_collection(tmp_path):
    steps = BrowserSteps(tmp_path, 33, 33)
    env = {"BASE_URL": "https://127.0.0.1:18444"}
    results = {}
    runner.run_browser_suite(
        steps, "/venv/python", "https://127.0.0.1:18444", env, results
    )
    assert results["browser_budget"] == {"collected_tests": 33, "timeout_seconds": 1620}
    assert results["browser_tests"] == 33
    name, command, run_env, timeout = steps.ran
    assert name == "browser" and timeout == 1620 and run_env is env
    collect, collect_env, collect_timeout = steps.collect
    assert collect_env is env and collect_timeout == 120
    junit = f"--junitxml={tmp_path / 'browser-junit.xml'}"
    assert command[:3] == ["/venv/python", "-m", "pytest"] and junit in command
    # Collection mirrors the run: same interpreter, suite and arguments.
    assert collect == [c for c in command if c != junit] + [
        "--collect-only",
        "-q",
        "--color=no",
    ]
    assert "--timeout=120" in command and "tests/e2e" in command


@pytest.mark.parametrize("executed", [32, 34])
def test_browser_step_fails_closed_when_report_differs_from_collection(
    tmp_path, executed
):
    steps = BrowserSteps(tmp_path, 33, executed)
    results = {}
    with pytest.raises(RuntimeError, match="collected"):
        runner.run_browser_suite(steps, "python", "https://127.0.0.1:1", {}, results)
    assert "browser_tests" not in results


def test_browser_budget_is_recorded_even_when_the_step_times_out(tmp_path):
    steps = BrowserSteps(tmp_path, 33, 33, passed=False)
    results = {}
    with pytest.raises(RuntimeError, match="browser failed"):
        runner.run_browser_suite(steps, "python", "https://127.0.0.1:1", {}, results)
    assert results["browser_budget"]["timeout_seconds"] == 1620
    assert "browser_tests" not in results


@pytest.mark.parametrize(
    "summary, expected",
    [
        ("33 tests collected in 0.1s", (33, 0)),
        ("1 test collected in 0.1s", (1, 0)),
        ("33/36 tests collected (3 deselected) in 0.1s", (33, 3)),
    ],
)
def test_collection_summary_reports_the_deselected_count(summary, expected):
    assert runner.collection_summary(f"a.py::t\n\n{summary}\n") == expected


class DeselectingSteps(BrowserSteps):
    def run(self, name, command, **kwargs):
        super().run(name, command, **kwargs)
        if name == "browser-collect":
            (self.private / "browser-collect.log").write_text(
                "tests/e2e/test_a.py::test_one\n\n"
                "33/36 tests collected (3 deselected) in 0.1s\n"
            )


def test_browser_suite_returns_the_tests_it_deselected(tmp_path):
    steps = DeselectingSteps(tmp_path, 33, 33)
    results = {}
    known = runner.run_browser_suite(
        steps, "python", "https://127.0.0.1:1", {}, results
    )
    assert known == 3 and results["browser_tests"] == 33
    assert results["browser_budget"]["collected_tests"] == 33


XFAIL = '<skipped type="pytest.xfail" message="{}"/>'


def known_bug_report(path, *cases):
    body = "".join(
        f'<testcase name="t{n}">{case}</testcase>' for n, case in enumerate(cases)
    )
    path.write_text(f"<testsuites><testsuite>{body}</testsuite></testsuites>")
    return path


def test_known_bug_report_counts_expected_failures_for_a_bug(tmp_path):
    path = known_bug_report(
        tmp_path / "lane.xml", XFAIL.format("BUG: one"), XFAIL.format("BUG: two")
    )
    assert runner.verify_known_bug_report(path, 2) == 2


@pytest.mark.parametrize(
    "case",
    [
        "",  # passed: a non-strict marker, or the bug is gone
        '<failure message="[XPASS(strict)] BUG: fixed"/>',
        "<error/>",
        '<skipped type="pytest.skip" message="BUG: skipped"/>',
        XFAIL.format("flaky: not a bug"),
        XFAIL.format("BUG: one") + "<system-out/>",
    ],
)
def test_known_bug_report_refuses_anything_but_a_bugs_expected_failure(tmp_path, case):
    path = known_bug_report(tmp_path / "lane.xml", XFAIL.format("BUG: one"), case)
    with pytest.raises(RuntimeError, match="BUG reason"):
        runner.verify_known_bug_report(path, 2)


@pytest.mark.parametrize("expected", [1, 3])
def test_known_bug_report_must_hold_every_deselected_test(tmp_path, expected):
    path = known_bug_report(
        tmp_path / "lane.xml", XFAIL.format("BUG: one"), XFAIL.format("BUG: two")
    )
    with pytest.raises(RuntimeError, match="exactly the deselected"):
        runner.verify_known_bug_report(path, expected)


class LaneSteps:
    def __init__(self, private, cases, passed=True):
        self.private, self.cases, self.passed = private, cases, passed
        self.ran = []

    def run(self, name, command, *, env=None, timeout=1800):
        self.ran.append((name, command, env, timeout))
        known_bug_report(self.private / "browser-known-bugs-junit.xml", *self.cases)
        if not self.passed:
            raise RuntimeError(f"{name} failed; inspect private/{name}.log locally")


def test_known_bug_lane_is_not_run_without_known_bugs(tmp_path):
    steps, results = LaneSteps(tmp_path, []), {}
    runner.run_known_bug_lane(steps, "python", "https://127.0.0.1:1", {}, results, 0)
    assert steps.ran == [] and results == {"known_bugs": 0}


def test_known_bug_lane_runs_only_the_lane_without_coverage_capture(tmp_path):
    steps = LaneSteps(tmp_path, [XFAIL.format("BUG: one"), XFAIL.format("BUG: two")])
    env = {"BASE_URL": "https://127.0.0.1:1", "SIGRIFT_E2E_JS_COVERAGE": "/js"}
    env["SIGRIFT_E2E_REQUIRED"] = "1"
    results = {}
    runner.run_known_bug_lane(
        steps, "/venv/python", "https://127.0.0.1:1", env, results, 2
    )
    assert results == {"known_bugs": 2}
    [(name, command, lane_env, timeout)] = steps.ran
    assert name == "browser-known-bugs" and timeout == runner.browser_deadline(2)
    assert command[:4] == ["/venv/python", "-m", "pytest", "tests/e2e"]
    assert f"--junitxml={tmp_path / 'browser-known-bugs-junit.xml'}" in command
    assert lane_env == {
        "BASE_URL": "https://127.0.0.1:1",
        "SIGRIFT_E2E_REQUIRED": "1",
        "SIGRIFT_E2E_KNOWN_BUGS": "1",
    }
    assert env["SIGRIFT_E2E_JS_COVERAGE"] == "/js"  # the suite's own env is kept


def test_known_bug_lane_fails_closed_when_a_bug_no_longer_fails(tmp_path):
    steps = LaneSteps(tmp_path, [XFAIL.format("BUG: one"), ""], passed=False)
    results = {}
    with pytest.raises(RuntimeError, match="browser-known-bugs failed"):
        runner.run_known_bug_lane(
            steps, "python", "https://127.0.0.1:1", {}, results, 2
        )
    assert results == {"known_bugs": 0}


def test_failed_step_keeps_details_private(tmp_path):
    task = runner.Runner(tmp_path, tmp_path, runner.isolated_environment())
    with pytest.raises(RuntimeError, match="failed; inspect private") as error:
        task.run(
            "failure",
            [sys.executable, "-c", "print('SECRET-CREDENTIAL'); raise SystemExit(2)"],
        )
    assert "SECRET-CREDENTIAL" not in str(error.value)
    assert task.steps[0]["passed"] is False
    assert "SECRET-CREDENTIAL" in (tmp_path / "private/failure.log").read_text()


def test_successful_step_receives_stdin_environment_and_working_directory(tmp_path):
    task = runner.Runner(
        tmp_path,
        tmp_path,
        runner.isolated_environment() | {"CANDIDATE_FIXTURE": "ready"},
    )
    task.run(
        "success",
        [
            sys.executable,
            "-c",
            "import os,sys,pathlib; "
            "assert os.environ['CANDIDATE_FIXTURE'] == 'ready'; "
            "assert sys.stdin.read() == 'input fixture'; "
            "pathlib.Path('step-result').write_text('complete')",
        ],
        stdin="input fixture",
    )
    assert (tmp_path / "step-result").read_text() == "complete"
    assert task.steps[0]["passed"] is True
    assert task.steps[0]["seconds"] >= 0


def test_step_deadline_fails_and_reaps_the_process(tmp_path, monkeypatch):
    task = runner.Runner(tmp_path, tmp_path, runner.isolated_environment())
    stopped = []
    terminate = task.terminate

    def stop(process):
        stopped.append(process)
        terminate(process, grace=0.1)

    monkeypatch.setattr(task, "terminate", stop)
    with pytest.raises(RuntimeError, match="deadline failed"):
        task.run(
            "deadline",
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=0.1,
        )
    assert len(stopped) == 1 and stopped[0].poll() is not None
    assert task.steps[0]["passed"] is False
    assert "exceeded its deadline" in (tmp_path / "private/deadline.log").read_text()


def test_interrupted_step_reaps_the_process_before_propagating(tmp_path, monkeypatch):
    task = runner.Runner(tmp_path, tmp_path, runner.isolated_environment())
    interrupted = []

    def interrupt(process, *_args, **_kwargs):
        interrupted.append(process)
        raise KeyboardInterrupt

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt)
    with pytest.raises(KeyboardInterrupt):
        task.run("interrupted", [sys.executable, "-c", "import time; time.sleep(30)"])
    assert len(interrupted) == 1 and interrupted[0].poll() is not None


def test_dirty_source_requires_explicit_opt_in_and_ignores_secrets(tmp_path):
    source, dest = tmp_path / "repo", tmp_path / "copy"
    source.mkdir()
    dest.mkdir()

    def git(*args):
        subprocess.run(["git", *args], cwd=source, capture_output=True, check=True)

    git("init")
    (source / ".gitignore").write_text(".env\n")
    (source / "app.py").write_text("print('committed')\n")
    git("add", ".")
    git(
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    (source / "app.py").write_text("print('changed')\n")
    (source / ".env").write_text("PASSWORD=secret\n")
    with pytest.raises(RuntimeError, match="dirty"):
        runner.source_snapshot(source, dest, False)
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["dirty"] is True
    assert (dest / "app.py").read_text() == "print('changed')\n"
    assert not (dest / ".env").exists()


def test_snapshot_preserves_clean_provenance_and_tracked_deletions(tmp_path):
    source, clean, dirty = (tmp_path / name for name in ("repo", "clean", "dirty"))
    source.mkdir()
    clean.mkdir()
    dirty.mkdir()

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source)

    git("init", "-q")
    (source / "app.py").write_text("print('retained')\n")
    (source / "deleted.py").write_text("print('remove before candidate')\n")
    (source / "entry.py").symlink_to("app.py")
    git("add", ".")
    git(
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    before = runner.source_snapshot(source, clean, False)
    assert before["dirty"] is False
    assert before["commit"] == git("rev-parse", "HEAD").decode().strip()
    assert before["files"] == 3
    assert (clean / "entry.py").is_symlink()
    assert os.readlink(clean / "entry.py") == "app.py"
    (source / "deleted.py").unlink()
    after = runner.source_snapshot(source, dirty, True)
    assert after["dirty"] is True and after["files"] == 2
    assert after["source_sha256"] != before["source_sha256"]
    assert not (dirty / "deleted.py").exists()
    assert (dirty / "entry.py").read_text() == (source / "app.py").read_text()


def _repository(source):
    """A committed fixture with a tracked symlink to a directory."""
    source.mkdir()

    def git(*args):
        return subprocess.check_output(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "-c",
                "protocol.file.allow=always",
                *args,
            ],
            cwd=source,
            stderr=subprocess.DEVNULL,
        )

    git("init", "-q")
    (source / "pkg").mkdir()
    (source / "pkg/mod.py").write_text("print('package')\n")
    (source / "app.py").write_text("print('retained')\n")
    (source / "link").symlink_to("pkg")
    git("add", ".")
    git("commit", "-qm", "fixture")
    return git


def _expected_digest(root, names):
    digest = hashlib.sha256()
    for name in sorted(names):
        path = root / name
        content = os.readlink(path).encode() if path.is_symlink() else path.read_bytes()
        digest.update(name.encode() + b"\0" + hashlib.sha256(content).digest())
    return digest.hexdigest()


def test_snapshot_digest_algorithm_is_unchanged_for_clean_trees(tmp_path):
    # Earlier results.json digests are quoted as evidence; keep them comparable.
    source, dest = tmp_path / "repo", tmp_path / "copy"
    _repository(source)
    dest.mkdir()
    provenance = runner.source_snapshot(source, dest, False)
    assert provenance["source_sha256"] == _expected_digest(
        source, ["app.py", "link", "pkg/mod.py"]
    )
    assert provenance["files"] == 3 and provenance["dirty"] is False
    assert provenance["skipped_nested_repositories"] == []


def test_snapshot_skips_untracked_nested_repositories_only_when_dirty_allowed(
    tmp_path,
):
    # Non-ignored paths: .claude/ is ignored by the project, which would hide
    # agent worktrees there without exercising the snapshot code at all.
    source = tmp_path / "repo"
    git = _repository(source)
    clean = tmp_path / "clean"
    clean.mkdir()
    baseline = runner.source_snapshot(source, clean, False)
    git("worktree", "add", "-q", "tools/agent-worktree")
    inner = source / "vendor/inner"
    inner.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=inner, check=True)
    (inner / "vendored.py").write_text("print('foreign repository')\n")
    (source / "new.py").write_text("print('untracked but staged')\n")

    refused = tmp_path / "refused"
    refused.mkdir()
    with pytest.raises(RuntimeError, match="dirty"):
        runner.source_snapshot(source, refused, False)
    assert list(refused.iterdir()) == []

    dest = tmp_path / "copy"
    dest.mkdir()
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["dirty"] is True
    assert provenance["commit"] == baseline["commit"]
    assert provenance["skipped_nested_repositories"] == [
        "tools/agent-worktree",
        "vendor/inner",
    ]
    # Shareable provenance: relative paths only.
    assert str(tmp_path) not in json.dumps(provenance)
    assert not (dest / "tools").exists() and not (dest / "vendor").exists()
    assert not list(dest.rglob(".git"))
    assert (dest / "new.py").read_text() == "print('untracked but staged')\n"
    assert provenance["files"] == baseline["files"] + 1
    assert provenance["source_sha256"] == _expected_digest(
        source, ["app.py", "link", "new.py", "pkg/mod.py"]
    )
    # Tracked symlinks to directories are still copied as symlinks.
    assert (dest / "link").is_symlink() and os.readlink(dest / "link") == "pkg"
    assert not (dest / "pkg/mod.py").is_symlink()


@pytest.mark.parametrize("checkout", ["populated", "unpopulated"])
def test_snapshot_refuses_tracked_gitlinks_instead_of_omitting_code(tmp_path, checkout):
    source = tmp_path / "repo"
    git = _repository(source)
    module = tmp_path / "module"
    module.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=module, check=True)
    (module / "lib.py").write_text("print('submodule code')\n")
    subprocess.run(["git", "add", "."], cwd=module, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "module",
        ],
        cwd=module,
        check=True,
    )
    git("submodule", "add", "-q", str(module), "sub")
    git("commit", "-qm", "add submodule")
    if checkout == "unpopulated":
        # A clone without --recurse-submodules: clean status, empty directory.
        git("submodule", "deinit", "-q", "-f", "sub")
        assert (source / "sub").is_dir() and not list((source / "sub").iterdir())
    assert git("status", "--porcelain", "--untracked-files=all") == b""
    for allow_dirty in (False, True):
        dest = tmp_path / f"copy-{allow_dirty}"
        dest.mkdir()
        with pytest.raises(RuntimeError, match="submodule") as error:
            runner.source_snapshot(source, dest, allow_dirty)
        assert "sub" in str(error.value) and str(tmp_path) not in str(error.value)


def test_snapshot_stages_contents_of_tracked_file_replaced_by_directory(tmp_path):
    source = tmp_path / "repo"
    _repository(source)
    (source / "app.py").unlink()
    (source / "app.py").mkdir()
    (source / "app.py/inner.py").write_text("print('inner')\n")
    refused = tmp_path / "refused"
    refused.mkdir()
    with pytest.raises(RuntimeError, match="dirty"):
        runner.source_snapshot(source, refused, False)
    dest = tmp_path / "copy"
    dest.mkdir()
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["dirty"] is True
    assert provenance["skipped_nested_repositories"] == []
    assert (dest / "app.py/inner.py").read_text() == "print('inner')\n"
    assert provenance["files"] == 3
    assert provenance["source_sha256"] == _expected_digest(
        source, ["app.py/inner.py", "link", "pkg/mod.py"]
    )


def test_snapshot_records_nested_repository_replacing_a_tracked_file(tmp_path):
    source = tmp_path / "repo"
    git = _repository(source)
    (source / "app.py").unlink()
    (source / "app.py").mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source / "app.py", check=True)
    (source / "app.py/inner.py").write_text("print('foreign repository')\n")
    # Git lists only the tracked name: no trailing slash and no inner files.
    listing = git("ls-files", "-z", "--cached", "--others", "--exclude-standard")
    assert sorted(listing.decode().rstrip("\0").split("\0")) == [
        "app.py",
        "link",
        "pkg/mod.py",
    ]
    dest = tmp_path / "copy"
    dest.mkdir()
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["dirty"] is True
    assert provenance["skipped_nested_repositories"] == ["app.py"]
    assert not (dest / "app.py").exists() and not list(dest.rglob(".git"))
    assert provenance["files"] == 2


@pytest.mark.parametrize(
    "entry, repository, expected",
    [
        # Each detector alone must suffice; git normally reports both.
        ("vendor/inner", True, ["vendor/inner"]),
        ("vendor/inner/", False, ["vendor/inner"]),
        # Neither: an unexplained directory is refused, never silently dropped.
        ("vendor/inner", False, None),
    ],
)
def test_snapshot_classifies_each_listed_directory(
    tmp_path, monkeypatch, entry, repository, expected
):
    # Git does not normally produce these listings; a change between the
    # listing and the copy can. Feed them through the real snapshot code.
    source = tmp_path / "repo"
    _repository(source)
    inner = source / "vendor/inner"
    inner.mkdir(parents=True)
    (inner / "vendored.py").write_text("print('not listed')\n")
    if repository:
        subprocess.run(["git", "init", "-q"], cwd=inner, check=True)
    real = subprocess.check_output

    def listing(command, *args, **kwargs):
        output = real(command, *args, **kwargs)
        if "--others" in command:
            # Replace whatever git reported under vendor/ with the one entry.
            names = [n for n in output.split(b"\0") if n and b"vendor/" not in n]
            output = b"\0".join([*names, entry.encode()]) + b"\0"
        return output

    monkeypatch.setattr(subprocess, "check_output", listing)
    dest = tmp_path / "copy"
    dest.mkdir()
    if expected is None:
        with pytest.raises(RuntimeError, match="Unexpected directory") as error:
            runner.source_snapshot(source, dest, True)
        assert str(tmp_path) not in str(error.value)
        return
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["skipped_nested_repositories"] == expected
    assert not (dest / "vendor").exists()
    assert provenance["files"] == 3


def test_snapshot_skips_untracked_bare_repositories_but_stages_fixtures(tmp_path):
    source = tmp_path / "repo"
    git = _repository(source)
    # A committed fixture shaped like a git directory is this commit's code.
    fixture = source / "fixtures/sample.git"
    for name in ("HEAD", "objects/.keep", "refs/.keep"):
        (fixture / name).parent.mkdir(parents=True, exist_ok=True)
        (fixture / name).write_text("ref: refs/heads/main\n" if name == "HEAD" else "")
    git("add", ".")
    git("commit", "-qm", "bare-shaped fixture")
    clean = tmp_path / "clean"
    clean.mkdir()
    baseline = runner.source_snapshot(source, clean, False)
    assert baseline["files"] == 6 and baseline["skipped_nested_repositories"] == []
    assert (clean / "fixtures/sample.git/HEAD").is_file()

    secret = "https://user:CANDIDATE-SECRET@example.invalid/mirror.git"
    for bare in ("mirror.git", "vendor/deep.git"):
        subprocess.run(["git", "init", "-q", "--bare", str(source / bare)], check=True)
        subprocess.run(
            ["git", "-C", str(source / bare), "config", "remote.origin.url", secret],
            check=True,
        )
    # Git lists a bare repository's files individually, config included.
    assert b"mirror.git/config" in git("ls-files", "--others", "--exclude-standard")
    (source / "fixtures/sample.git/objects/new").write_text("untracked\n")
    (source / "new.py").write_text("print('untracked but staged')\n")
    dest = tmp_path / "copy"
    dest.mkdir()
    provenance = runner.source_snapshot(source, dest, True)
    assert provenance["dirty"] is True
    assert provenance["skipped_nested_repositories"] == [
        "fixtures/sample.git",
        "mirror.git",
        "vendor/deep.git",
    ]
    assert not (dest / "mirror.git").exists() and not (dest / "vendor").exists()
    assert not (dest / "fixtures/sample.git/objects/new").exists()
    assert (dest / "fixtures/sample.git/HEAD").is_file()
    assert (dest / "new.py").is_file() and provenance["files"] == 7
    assert not any(
        b"CANDIDATE-SECRET" in path.read_bytes()
        for path in dest.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


def test_optimized_python_is_rejected_before_creating_run(tmp_path):
    result = subprocess.run(
        [sys.executable, "-O", str(SCRIPT), "--work-dir", str(tmp_path / "runs")],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 2
    assert "Assertions must be enabled" in result.stderr
    assert not (tmp_path / "runs").exists()


@pytest.mark.parametrize(
    "change",
    [
        "foreign-volume",
        "external-network",
        "extra-service",
        "public-port",
        "fixed-container",
    ],
)
def test_scope_check_refuses_resources_outside_disposable_project(change):
    config = {
        "services": {
            "bridge": {},
            "edge": {},
            "gateway": {"ports": [{"host_ip": "127.0.0.1", "published": "18444"}]},
        },
        "volumes": {"data": {"name": "sigrift-test-123_data"}},
        "networks": {"default": {"name": "sigrift-test-123_default"}},
    }
    runner.verify_compose_scope(config, "sigrift-test-123", 18444)
    bad = copy.deepcopy(config)
    if change == "foreign-volume":
        bad["volumes"]["data"]["name"] = "production_data"
    elif change == "external-network":
        bad["networks"]["default"]["external"] = True
    elif change == "extra-service":
        bad["services"]["scanner"] = {}
    elif change == "public-port":
        bad["services"]["gateway"]["ports"][0]["host_ip"] = "0.0.0.0"
    else:
        bad["services"]["bridge"]["container_name"] = "production-bridge"
    with pytest.raises(RuntimeError):
        runner.verify_compose_scope(bad, "sigrift-test-123", 18444)


def test_termination_kills_descendant_after_parent_exits(tmp_path):
    marker = tmp_path / "escaped-child"
    child = (
        "import signal,time,pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "print('ready',flush=True); time.sleep(1); "
        f"pathlib.Path({str(marker)!r}).write_text('escaped')"
    )
    parent = (
        "import subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c',{child!r}],stdout=subprocess.PIPE,text=True); "
        "p.stdout.readline(); print('ready',flush=True); time.sleep(30)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", parent],
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        assert process.stdout.readline().strip() == "ready"
        runner.Runner.terminate(process, grace=0.1)
        time.sleep(1.1)
        assert not marker.exists(), "SIGTERM-ignoring descendant survived its parent"
    finally:
        runner.Runner.terminate(process, grace=0)


@pytest.mark.parametrize("changed", [None, "container", "start-time"])
def test_gateway_lifecycle_cannot_pass_if_bridge_was_restarted(changed):
    class Lifecycle:
        def __init__(self):
            self.starts = iter(
                ["original-start", "new-start" if changed else "original-start"]
            )
            self.command = None

        def capture(self, *command):
            if command[1] == "inspect":
                return next(self.starts)
            return "replacement-bridge" if changed == "container" else "original-bridge"

        def run(self, name, command, **kwargs):
            self.command = command
            assert name == "gateway-recreate" and kwargs["timeout"] == 300
            assert command[-1] == "gateway" and "--no-deps" in command

    lifecycle = Lifecycle()
    if changed:
        with pytest.raises(RuntimeError, match="also restarted the bridge"):
            runner.recreate_gateway_with_live_bridge(lifecycle, "original-bridge")
    else:
        runner.recreate_gateway_with_live_bridge(lifecycle, "original-bridge")
    assert lifecycle.command is not None
