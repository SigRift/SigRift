"""The browser suite's CSP modes and the script-policy rewrite they use."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.e2e import conftest as e2e

ROOT = Path(__file__).resolve().parents[2]
TABLE = json.loads(
    (
        ROOT
        / "src/gateway/crates/sigrift-gateway-core/testdata/security_headers_parity.json"
    ).read_text()
)
OLD_GATEWAY_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-hashes'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
    "https://*.tile.openstreetmap.org; connect-src 'self' wss: ws:; "
    "font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def directives(policy):
    return {d.split()[0]: d.split()[1:] for d in policy.split(";") if d.split()}


def test_the_reviewed_policy_is_the_shared_table():
    assert e2e.reviewed_csp() == TABLE["content-security-policy"]
    assert directives(e2e.reviewed_csp())["script-src"] == ["'self'"]


def test_an_older_gateway_policy_gets_the_reviewed_script_policy():
    """The f9380cc gateway's policy, as an older staging build sends it."""
    tightened = e2e.tighten_script_policy(OLD_GATEWAY_CSP)
    # Exactly the reviewed policy: that policy differs only in scripts.
    assert directives(tightened) == directives(e2e.reviewed_csp())
    assert "unsafe-hashes" not in tightened


def test_only_script_and_object_sources_change():
    tightened = e2e.tighten_script_policy(
        "default-src 'none'; SCRIPT-SRC *; script-src 'unsafe-eval'; "
        "img-src https://example.test; sandbox"
    )
    assert directives(tightened) == {
        "default-src": ["'none'"],
        "script-src": ["'self'"],
        "object-src": ["'none'"],
        "img-src": ["https://example.test"],
        "sandbox": [],
    }


def test_a_page_without_a_policy_gets_the_whole_reviewed_one():
    assert e2e.tighten_script_policy("") == e2e.reviewed_csp()
    assert e2e.tighten_script_policy(" ; ") == e2e.reviewed_csp()


def test_urls_in_reports_lose_query_and_fragment():
    assert (
        e2e.without_query("https://h.test/static/x.js?api_key=secret#frag")
        == "https://h.test/static/x.js"
    )
    assert e2e.without_query(None) == ""
    assert e2e.same_origin("https://h.test:8444/a", "https://h.test:8444")
    assert not e2e.same_origin("https://h.test:8445/a", "https://h.test:8444")
    assert not e2e.same_origin("data:image/png;base64,AA", "https://h.test:8444")


@pytest.mark.parametrize(
    ("value", "mode"),
    [
        (None, "served"),
        ("", "served"),
        ("reviewed", "reviewed"),
        (" Enforce ", "enforce"),
    ],
)
def test_mode_comes_from_the_environment(monkeypatch, value, mode):
    if value is None:
        monkeypatch.delenv("SIGRIFT_E2E_CSP", raising=False)
    else:
        monkeypatch.setenv("SIGRIFT_E2E_CSP", value)
    assert e2e.csp_mode() == mode


def test_an_unknown_mode_is_a_usage_error():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/e2e", "--collect-only", "-q"],
        cwd=ROOT,
        env=os.environ | {"SIGRIFT_E2E_CSP": "relaxed", "BRIDGE_ADMIN_PASSWORD": ""},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 4, result.stdout + result.stderr
    assert "SIGRIFT_E2E_CSP must be one of" in result.stdout + result.stderr


def test_the_gates_that_test_this_build_require_the_reviewed_policy():
    candidate = (ROOT / "scripts/test-candidate.py").read_text()
    assert '"SIGRIFT_E2E_CSP": "reviewed"' in candidate
    workflow = (ROOT / ".github/workflows/quickstart-smoke.yml").read_text()
    assert "SIGRIFT_E2E_CSP: reviewed" in workflow


class _Page:
    def __init__(self):
        self.handlers = {}

    def on(self, event, handler):
        self.handlers.setdefault(event, []).append(handler)


class _Watcher:
    def __init__(self, problems):
        self._problems = problems

    def problems(self):
        return list(self._problems)


def _run_fixture(problems):
    """The suite's autouse error fixture around a test, with a stand-in
    watcher that reports *problems*."""
    fixture = e2e.no_uncaught_browser_errors.__wrapped__
    page = _Page()
    settings = e2e.Settings("https://h.test:8444", "admin", "x", None)
    steps = fixture(page, settings, _Watcher(problems))
    next(steps)
    assert set(page.handlers) == {"pageerror", "response"}
    with pytest.raises(StopIteration):
        next(steps)


def test_every_browser_test_fails_on_a_csp_problem():
    """The watcher's problems fail the test (the e2e positive control,
    tests/e2e/test_csp.py, checks that the watcher records them)."""
    _run_fixture([])
    problem = "CSP violation on /dashboard: script-src-attr blocked inline"
    with pytest.raises(AssertionError, match="script-src-attr blocked inline"):
        _run_fixture([problem])
