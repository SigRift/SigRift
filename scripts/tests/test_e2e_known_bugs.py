"""The browser suite's open-bug lane, through the real conftest hooks.

tests/e2e/conftest.py deselects strict "BUG:" xfail tests from ordinary runs
and, under SIGRIFT_E2E_KNOWN_BUGS=1, runs only them; a required run accepts
their expected failure there, nothing else. Its hooks see the whole session,
so they must leave tests outside the suite's own directory alone.
"""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.e2e import conftest as e2e
from tests.e2e import diagnostics as diag

BUG = '@pytest.mark.xfail(strict=True, reason="BUG: {what}")\n'
SUITE = (
    "import pytest\n"
    "@pytest.fixture(autouse=True)\n"
    "def no_uncaught_browser_errors():\n"
    "    yield\n"
    "def test_ordinary():\n"
    "    pass\n" + BUG.format(what="still broken") + "def test_open_bug():\n"
    "    assert False\n"
)
# A strict "BUG:" xfail in another suite of the same session.
OUTSIDE = (
    "import pytest\n" + BUG.format(what="elsewhere") + "def test_other_bug():\n"
    "    assert False\n"
)


def run(tmp_path, suite=SUITE, **environment):
    package = tmp_path / "suite"
    package.mkdir(exist_ok=True)
    (package / "__init__.py").write_text("")
    (package / "conftest.py").write_text(Path(e2e.__file__).read_text())
    (package / "diagnostics.py").write_text(Path(diag.__file__).read_text())
    (package / "test_suite.py").write_text(suite)
    other = tmp_path / "other"
    other.mkdir(exist_ok=True)
    (other / "test_other.py").write_text(OUTSIDE)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(package),
            str(other),
            "--rootdir",
            str(tmp_path),
            "-c",
            os.devnull,
            "-p",
            "no:cacheprovider",
            "-q",
            "-rA",
        ],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            **environment,
        },
        capture_output=True,
        text=True,
        timeout=60,
    )
    outcomes = {}
    for line in result.stdout.splitlines():
        word, _, rest = line.partition(" ")
        if word in {"PASSED", "FAILED", "XFAIL", "XPASS", "SKIPPED", "ERROR"}:
            outcomes.setdefault(rest.split(" ")[0].split("::")[-1], set()).add(word)
    return result.returncode, outcomes, result.stdout


REQUIRED = {"SIGRIFT_E2E_REQUIRED": "1", "BRIDGE_ADMIN_PASSWORD": "unused"}


def test_ordinary_runs_leave_out_only_this_suites_open_bugs(tmp_path):
    code, outcomes, output = run(tmp_path)
    assert code == 0, output
    assert outcomes == {"test_ordinary": {"PASSED"}, "test_other_bug": {"XFAIL"}}


def test_required_lane_runs_only_this_suites_open_bugs_and_accepts_them(tmp_path):
    code, outcomes, output = run(tmp_path, SIGRIFT_E2E_KNOWN_BUGS="1", **REQUIRED)
    assert code == 0, output
    # Other suites are not the lane's: their tests are neither dropped nor
    # held to the browser suite's required-run rule.
    assert outcomes == {"test_open_bug": {"XFAIL"}, "test_other_bug": {"XFAIL"}}


def test_lane_fails_when_an_open_bug_test_passes(tmp_path):
    fixed = SUITE.replace("    assert False\n", "    pass\n")
    code, outcomes, output = run(
        tmp_path, fixed, SIGRIFT_E2E_KNOWN_BUGS="1", **REQUIRED
    )
    assert code == 1, output
    assert outcomes["test_open_bug"] == {"FAILED"}, output


@pytest.mark.parametrize(
    "mark",
    [
        # Only a strict xfail whose reason starts "BUG:" is an open bug.
        '@pytest.mark.xfail(strict=False, reason="BUG: lenient")\n',
        '@pytest.mark.xfail(strict=True, reason="flaky")\n',
        '@pytest.mark.skip(reason="BUG: skipped")\n',
    ],
)
def test_required_runs_refuse_any_other_skip_or_expected_failure(tmp_path, mark):
    suite = SUITE + mark + "def test_not_a_known_bug():\n    assert False\n"
    code, outcomes, output = run(tmp_path, suite, **REQUIRED)
    assert code == 1, output
    # A skip is decided at setup, so pytest names its refusal an error.
    assert outcomes["test_not_a_known_bug"] & {"FAILED", "ERROR"}, output
    assert not outcomes["test_not_a_known_bug"] & {"XFAIL", "SKIPPED"}, output
