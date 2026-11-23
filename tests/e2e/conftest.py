"""Real HTTP/browser fixtures without database access or synthetic sessions.

The full suite requires SIGRIFT_E2E_DISPOSABLE=1. Existing deployments can
explicitly select ``-m 'not disposable'``. Synthetic scanner data exercises
software delivery and rendering; it does not verify physical radio capture.

Every test fails on a Content-Security-Policy violation in its pages.
SIGRIFT_E2E_CSP=reviewed (the candidate gate) also requires every page to
carry the reviewed policy; ``enforce`` applies its script policy to an
older build's pages (see ``CSP_MODES``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import math
import os
import re
import secrets
import ssl
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlsplit

import pytest

from . import diagnostics

USER_AGENT = "SigRift-browser-regression/1.0"
_USED_TOTP_WINDOWS = {}

#: The reviewed Content-Security-Policy, shared with the gateway and the
#: bridge (their tests read the same table).
SECURITY_HEADERS_TABLE = (
    Path(__file__).resolve().parents[2]
    / "src/gateway/crates/sigrift-gateway-core/testdata/security_headers_parity.json"
)
#: What the browser suite does with each page's CSP (SIGRIFT_E2E_CSP):
#: - ``served`` (default): pages run under the policy the server sends, so
#:   the suite also runs against an older build (e2e-staging);
#: - ``reviewed``: every document from the server must carry exactly the
#:   reviewed policy (the candidate gate, which tests the build of this
#:   commit);
#: - ``enforce``: the browser gets each document with its script policy
#:   replaced by the reviewed one, whatever the server sent, to run the
#:   suite under that policy against a build that serves another. Not a
#:   document reached through a server redirect: Playwright does not route
#:   the request a redirect makes, so that one keeps the server's policy.
#: In every mode a test fails on any CSP violation its pages report.
CSP_MODES = {"served", "reviewed", "enforce"}


def enabled(name):
    return os.environ.get(name, "").lower() in {"1", "true", "yes"}


def csp_mode():
    return os.environ.get("SIGRIFT_E2E_CSP", "").strip().lower() or "served"


def reviewed_csp():
    table = json.loads(SECURITY_HEADERS_TABLE.read_text(encoding="utf-8"))
    return table["content-security-policy"]


def pytest_configure(config):
    if enabled("SIGRIFT_E2E_REQUIRED") and not os.environ.get("BRIDGE_ADMIN_PASSWORD"):
        raise pytest.UsageError("SIGRIFT_E2E_REQUIRED=1 requires BRIDGE_ADMIN_PASSWORD")
    if csp_mode() not in CSP_MODES:
        raise pytest.UsageError(
            "SIGRIFT_E2E_CSP must be one of " + ", ".join(sorted(CSP_MODES))
        )
    config.addinivalue_line(
        "markers",
        "disposable: creates synthetic data/users; requires a disposable stack",
    )


E2E_DIRECTORY = Path(__file__).resolve().parent


def in_this_suite(item):
    # Collection hooks see the whole session: leave other suites alone.
    return E2E_DIRECTORY in Path(item.path).resolve().parents


def known_bug(item):
    """True for a regression test of an open bug: a strict xfail "BUG: ..."."""
    marker = item.get_closest_marker("xfail")
    return bool(
        in_this_suite(item)
        and marker
        and marker.kwargs.get("strict") is True
        and str(marker.kwargs.get("reason", "")).startswith("BUG:")
    )


def pytest_collection_modifyitems(config, items):
    # pytest reports an expected failure as a skip, which a required run
    # refuses. So the open-bug regressions run in a lane of their own,
    # SIGRIFT_E2E_KNOWN_BUGS=1, which runs nothing else from this suite:
    # each must still fail there, and one that passes fails the lane
    # (strict xfail). Fixing the bug means deleting its marker, which moves
    # the test to every ordinary run. scripts/test-candidate.py runs the
    # lane after the required suite.
    lane = enabled("SIGRIFT_E2E_KNOWN_BUGS")
    deselected = [
        item for item in items if in_this_suite(item) and known_bug(item) != lane
    ]
    if deselected:
        config.hook.pytest_deselected(items=deselected)
        dropped = set(map(id, deselected))
        items[:] = [item for item in items if id(item) not in dropped]


def pytest_sessionfinish(session, exitstatus):
    # Keep the original failure primary if recording also failed. A successful
    # run with incomplete requested evidence must not silently appear complete.
    if exitstatus != 0:
        diagnostics.record(stage="session", category="test_failure")
    if not diagnostics.finish() and exitstatus == 0:
        session.exitstatus = 1


def expect(target):
    # Keep collection and required-mode guard tests usable without installing
    # a browser stack in the lightweight scripts CI job.
    from playwright.sync_api import expect as playwright_expect

    return playwright_expect(target)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    expected_failure = (
        enabled("SIGRIFT_E2E_KNOWN_BUGS")
        and hasattr(report, "wasxfail")
        and known_bug(item)
    )
    if enabled("SIGRIFT_E2E_REQUIRED") and report.skipped and not expected_failure:
        report.outcome = "failed"
        report.longrepr = "Required E2E test skipped; all selected tests must execute."
        # pytest neither counts nor records as a failure a report that still
        # carries an expected-failure reason: the run would exit 0.
        if hasattr(report, "wasxfail"):
            del report.wasxfail
    if report.failed:
        diagnostics.record(
            stage={
                "setup": "test_setup",
                "call": "test_call",
                "teardown": "test_teardown",
            }.get(report.when, "unknown"),
            category="test_failure",
        )


@dataclass(repr=False)
class Settings:
    base_url: str
    username: str
    password: str = field(repr=False)
    context: ssl.SSLContext = field(repr=False)


@pytest.fixture(scope="session")
def settings(base_url):
    base_url = (base_url or os.environ.get("BASE_URL", "")).rstrip("/")
    if urlsplit(base_url).scheme not in {"http", "https"}:
        pytest.fail("Set --base-url or BASE_URL to the live gateway", pytrace=False)
    password = os.environ.get("BRIDGE_ADMIN_PASSWORD", "")
    if not password:
        pytest.fail("BRIDGE_ADMIN_PASSWORD is required", pytrace=False)
    context = ssl.create_default_context(cafile=os.environ.get("SIGRIFT_E2E_CA_CERT"))
    return Settings(
        base_url, os.environ.get("BRIDGE_ADMIN_USER", "admin"), password, context
    )


def cookie_attribute(cookie, name):
    """A Set-Cookie attribute http.cookiejar kept, matched in any letter case.

    The jar keeps attributes it does not model (HttpOnly, SameSite) as
    received; the gateway writes ``HttpOnly`` and ``SameSite=Lax``, the
    standalone bridge (Starlette) ``SameSite=strict``. ``(False, None)`` when
    absent, else ``(True, value)``; a flag such as HttpOnly has the value None.
    """
    for key, value in cookie._rest.items():
        if key.lower() == name.lower():
            return True, value
    return False, None


def is_session_cookie(cookie):
    """The HttpOnly ``session_token`` cookie a login sets (with a value)."""
    return (
        cookie.name == "session_token"
        and bool(cookie.value)
        and cookie_attribute(cookie, "HttpOnly")[0]
    )


def cooldown_delay(status, headers, attempt):
    retry = headers.get("retry-after", headers.get("Retry-After", ""))
    if (
        status == 429
        and attempt == 0
        and retry.isascii()
        and retry.isdecimal()
        and 1 <= int(retry) <= 60
    ):
        return min(int(retry) + 1, 60)
    return None


class Client:
    """Verified TLS, server-issued cookies and CSRF; never print secret bodies."""

    def __init__(self, settings):
        self.settings = settings
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=settings.context),
            urllib.request.HTTPCookieProcessor(self.cookies),
        )

    def request(
        self,
        method,
        path,
        body=None,
        *,
        status=200,
        key=None,
        raw=None,
        retry_key_cleanup=False,
        retry_key_creation=False,
        stage="request",
    ):
        """*body* is sent as JSON; *raw* bytes as ``application/octet-stream``."""
        if raw is not None and (body is not None or not isinstance(raw, bytes)):
            raise ValueError("Send either a JSON body or raw bytes")
        if retry_key_cleanup and not (
            method == "DELETE" and re.fullmatch(r"/api/admin/keys/[A-Za-z0-9_-]+", path)
        ):
            raise ValueError("Cleanup retry is restricted to deleting a synthetic key")
        if retry_key_creation and not (
            method == "POST" and path == "/api/admin/keys" and status == 201
        ):
            raise ValueError("Creation retry is restricted to creating a synthetic key")
        headers = {
            "Content-Type": "application/json"
            if raw is None
            else "application/octet-stream",
            "User-Agent": USER_AGENT,
        }
        if key:
            headers["X-API-Key"] = key
        for cookie in self.cookies:
            if cookie.name == "csrf_token":
                headers["X-CSRF-Token"] = cookie.value
        expected = (status,) if isinstance(status, int) else status
        try:
            req = urllib.request.Request(
                self.settings.base_url + path,
                data=raw
                if raw is not None
                else json.dumps(body).encode()
                if body is not None
                else None,
                method=method,
                headers=headers,
            )
        except (TypeError, ValueError):
            diagnostics.record(
                method,
                path,
                expected=expected,
                stage=stage,
                category="request_contract",
            )
            raise
        for attempt in range(2):
            try:
                response = self.opener.open(req, timeout=20)
            except urllib.error.HTTPError as error:
                response = error
            except Exception:
                diagnostics.record(
                    method, path, expected=expected, stage=stage, category="transport"
                )
                raise
            with response:
                delay = (
                    cooldown_delay(response.status, response.headers, attempt)
                    if path == "/api/auth/login"
                    or retry_key_cleanup
                    or retry_key_creation
                    else None
                )
                if delay is None:
                    if response.status not in expected:
                        diagnostics.record(
                            method,
                            path,
                            status=response.status,
                            expected=expected,
                            stage=stage,
                            category="unexpected_status",
                        )
                    assert response.status in expected, (
                        f"{method} {path}: HTTP {response.status}, expected {expected}"
                    )
                    try:
                        raw = response.read()
                    except Exception:
                        diagnostics.record(
                            method,
                            path,
                            status=response.status,
                            expected=expected,
                            stage=stage,
                            category="transport",
                        )
                        raise
                    try:
                        result = json.loads(raw) if raw else {}
                    except (ValueError, UnicodeError):
                        diagnostics.record(
                            method,
                            path,
                            status=response.status,
                            expected=expected,
                            stage=stage,
                            category="invalid_json",
                        )
                        raise
                    diagnostics.record(
                        method,
                        path,
                        status=response.status,
                        expected=expected,
                        stage=stage,
                        category="ok",
                    )
                    return result
                diagnostics.record(
                    method,
                    path,
                    status=response.status,
                    expected=expected,
                    stage=stage,
                    category="cooldown",
                )
            # Honor one server-directed cooldown; never weaken rate limits.
            time.sleep(delay)
        raise AssertionError("request cooldown exhausted")

    def login(self, username, password):
        return self.request(
            "POST", "/api/auth/login", {"username": username, "password": password}
        )

    def has_session(self):
        """True once the server set an HttpOnly session cookie in this jar.

        The session is the cookie, not the login body: newer gateways stop
        returning ``session_token`` in JSON. Works with either contract.
        """
        return any(is_session_cookie(cookie) for cookie in self.cookies)

    def browser_cookies(self):
        """This jar's cookies for Playwright, with the attributes the server
        set: the gateway's ``SameSite=Lax`` (Lax also when none was sent, as
        browsers default) rather than a stricter value the server never
        chose. Playwright takes only Strict, Lax or None."""
        cookies = []
        for cookie in self.cookies:
            same_site = (cookie_attribute(cookie, "SameSite")[1] or "Lax").capitalize()
            cookies.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                    "secure": cookie.secure,
                    "httpOnly": cookie_attribute(cookie, "HttpOnly")[0],
                    "sameSite": same_site
                    if same_site in {"Strict", "Lax", "None"}
                    else "Lax",
                }
            )
        return cookies


def totp(secret):
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(
        key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1
    ).digest()
    offset = digest[-1] & 15
    return f"{(struct.unpack('>I', digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1000000:06d}"


def fresh_totp(secret):
    # Staging may reuse the same MFA admin across independent login tests.
    # Respect the server's replay protection rather than reusing its code.
    identity = hashlib.sha256(secret.encode()).hexdigest()
    window = int(time.time()) // 30
    if _USED_TOTP_WINDOWS.get(identity) == window:
        time.sleep(30 - time.time() % 30 + 0.1)
        window = int(time.time()) // 30
    _USED_TOTP_WINDOWS[identity] = window
    return totp(secret)


@pytest.fixture(scope="session")
def admin_api(settings):
    client = Client(settings)
    result = client.login(settings.username, settings.password)
    if result.get("mfa_required"):
        secret = os.environ.get("BRIDGE_ADMIN_TOTP_SECRET")
        assert secret, (
            "Admin MFA requires BRIDGE_ADMIN_TOTP_SECRET for this test account"
        )
        result = client.request(
            "POST",
            "/api/auth/mfa/verify",
            {"mfa_token": result["mfa_token"], "totp_code": fresh_totp(secret)},
        )
    assert client.has_session(), "Admin did not receive a session"
    assert not result.get("password_change_required"), (
        "Complete the test admin's password change before running E2E"
    )
    assert not result.get("mfa_setup_required"), (
        "Complete the test admin's MFA enrollment before running E2E"
    )
    assert client.request("GET", "/api/auth/me")["username"] == settings.username
    yield client
    client.request("POST", "/api/auth/logout", {})


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    # Browser trust for the self-signed test origin; HTTP setup verifies its
    # CA. CSP and real application routing remain enabled.
    return {
        **browser_context_args,
        "ignore_https_errors": True,
        "user_agent": USER_AGENT,
    }


def failed_static_asset(url, status, origin):
    target, base = urlsplit(url), urlsplit(origin)
    if (
        (target.scheme, target.netloc) == (base.scheme, base.netloc)
        and target.path.startswith("/static/")
        and status >= 400
    ):
        return f"HTTP {status} {target.path}"
    return None


@pytest.fixture
def csp_watcher(page, settings):
    """The :class:`CspWatcher` of the test's browser context (its pages and
    popups), in the suite's ``SIGRIFT_E2E_CSP`` mode."""
    return CspWatcher(page.context, settings.base_url, csp_mode())


@pytest.fixture(autouse=True)
def no_uncaught_browser_errors(page, settings, csp_watcher):
    """Fail the test on an uncaught page error, a failed static asset, or a
    Content-Security-Policy problem (``csp_watcher``)."""
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def check_static(response):
        failure = failed_static_asset(response.url, response.status, settings.base_url)
        if failure:
            errors.append(failure)

    page.on("response", check_static)
    yield
    errors.extend(csp_watcher.problems())
    assert not errors, "Uncaught browser errors: " + "; ".join(errors)


def same_origin(url, origin):
    target, base = urlsplit(url), urlsplit(origin)
    return (target.scheme, target.netloc) == (base.scheme, base.netloc)


def without_query(url):
    """*url* without its query and fragment, which may carry credentials."""
    if not isinstance(url, str):
        return ""
    return url.split("?", 1)[0].split("#", 1)[0][:200]


def tighten_script_policy(policy):
    """*policy* with its ``script-src`` and ``object-src`` replaced by the
    reviewed ones (added when missing); with no policy, the reviewed one."""
    if not any(directive.split() for directive in policy.split(";")):
        return reviewed_csp()
    replaced = {"script-src", "object-src"}
    reviewed = [
        directive.strip()
        for directive in reviewed_csp().split(";")
        if directive.split()[:1] and directive.split()[0] in replaced
    ]
    kept = [
        directive.strip()
        for directive in policy.split(";")
        if directive.split() and directive.split()[0].lower() not in replaced
    ]
    return "; ".join(kept[:1] + reviewed + kept[1:])


def enforce_reviewed_script_policy(route):
    """Route handler: the document with the reviewed script policy.

    The generalised form of the startup test's strict-policy route: the
    page and response are the server's (any status, a redirect included,
    which the browser then follows), only the script policy is tightened.
    The request a redirect makes is not routed (Playwright), so the page
    it lands on keeps the server's policy.
    """
    if route.request.resource_type != "document":
        route.fallback()
        return
    response = route.fetch(max_redirects=0)
    headers = dict(response.headers)
    headers["content-security-policy"] = tighten_script_policy(
        headers.get("content-security-policy", "")
    )
    route.fulfill(response=response, headers=headers)


#: Reports each CSP violation of a page (every document, popups included)
#: to the test, through a binding that survives navigation. On the window,
#: not the document: a popup opened with ``window.open(url)`` runs this in
#: its initial about:blank document, and the page it then loads replaces
#: that document but keeps the window (it has the opener's origin).
_CSP_VIOLATION_LISTENER = """
if (!window.__sigriftCspListening) {
window.__sigriftCspListening = true;
window.addEventListener('securitypolicyviolation', function (event) {
    if (typeof window.__sigriftCspViolation !== 'function') return;
    window.__sigriftCspViolation({
        directive: event.effectiveDirective || event.violatedDirective || '',
        blocked: event.blockedURI || '',
        source: event.sourceFile || '',
        line: event.lineNumber || 0,
        disposition: event.disposition || '',
        sample: event.sample || ''
    });
}, true);
}
"""


class CspWatcher:
    """Watches a browser context's pages for Content-Security-Policy problems.

    Under the gateway's ``script-src 'self'`` an inline script, an
    ``onclick=`` attribute or a ``javascript:`` URL is refused, and the
    control it drives silently does nothing. The browser reports each
    refusal as a ``securitypolicyviolation`` event; each one is a problem,
    report-only ones too. In ``reviewed`` mode (``SIGRIFT_E2E_CSP``) so is
    a same-origin document without exactly the reviewed policy; in
    ``enforce`` mode documents reach the browser with the reviewed script
    policy. Pages the context's pages open (popups) are watched too, as
    the whole browser context is; other browser contexts are not.

    Every gate expects no problem, so a watcher that stopped recording
    would pass them all: ``tests/e2e/test_csp.py`` is its positive control.
    """

    def __init__(self, context, base_url, mode):
        self.context = context
        self.base_url = base_url
        self.mode = mode
        #: Each violation reported, as the listener sent it plus ``page``,
        #: the path of the document that reported it.
        self.violations = []
        #: Documents that did not carry the reviewed policy (``reviewed``).
        self.mismatches = []
        context.expose_binding("__sigriftCspViolation", self._report)
        context.add_init_script(_CSP_VIOLATION_LISTENER)
        if mode == "reviewed":
            self.expected = reviewed_csp()
            context.on("response", self._check_policy)
        elif mode == "enforce":
            context.route(
                lambda url: same_origin(url, base_url),
                enforce_reviewed_script_policy,
            )

    def _report(self, source, violation):
        frame = source.get("frame")
        self.violations.append(
            {
                **(violation if isinstance(violation, dict) else {}),
                "page": urlsplit(frame.url).path if frame else "?",
            }
        )

    def _check_policy(self, response):
        if response.request.resource_type != "document" or not same_origin(
            response.url, self.base_url
        ):
            return
        served = response.headers.get("content-security-policy")
        if served != self.expected:
            self.mismatches.append(
                f"Not the reviewed CSP: {urlsplit(response.url).path}"
                f" (HTTP {response.status}): {served!r}"
            )

    def settle(self):
        """Let violations still on their way from the open pages arrive."""
        for open_page in self.context.pages:
            try:
                open_page.evaluate("() => new Promise(done => setTimeout(done, 50))")
            except Exception:
                pass

    def wait_for_violations(self, count, timeout=10.0):
        """The violations once at least *count* arrived (or the timeout)."""
        deadline = time.monotonic() + timeout
        self.settle()
        while len(self.violations) < count and time.monotonic() < deadline:
            self.settle()
        return list(self.violations)

    def problems(self):
        """Every problem so far, one line each (a violation's URLs without
        their query, which may carry credentials)."""
        self.settle()
        return [
            "CSP violation on {page}: {directive} blocked {blocked}"
            " ({source}:{line}, {disposition}) {sample!r}".format(
                page=violation["page"],
                directive=violation.get("directive", ""),
                blocked=without_query(violation.get("blocked", "")),
                source=without_query(violation.get("source", "")),
                line=violation.get("line", 0),
                disposition=violation.get("disposition", ""),
                sample=str(violation.get("sample", ""))[:60],
            )
            for violation in self.violations
        ] + self.mismatches

    def clear(self):
        """Forget the problems so far (those a test caused on purpose)."""
        self.violations.clear()
        self.mismatches.clear()


@pytest.fixture(autouse=True)
def collect_javascript_coverage(request):
    destination = os.environ.get("SIGRIFT_E2E_JS_COVERAGE")
    if not destination:
        yield
        return
    from pathlib import Path
    from .javascript_coverage import BrowserCoverage

    page = request.getfixturevalue("page")
    settings = request.getfixturevalue("settings")
    collector = BrowserCoverage(
        page, settings.base_url, Path(__file__).resolve().parents[2], destination
    )
    yield
    collector.finish()


def navigate(page, url):
    response = page.goto(url, wait_until="domcontentloaded")
    assert response is not None and response.status == 200, f"Navigation failed: {url}"
    return response


def browser_login(
    page, settings, *, username=None, password=None, expect_mfa=False, next_path=None
):
    login_path = "/login"
    if next_path is not None:
        login_path += "?next=" + quote(next_path, safe="")
    navigate(page, settings.base_url + login_path)
    page.locator("#username").fill(username or settings.username)
    page.locator("#password").fill(password or settings.password)
    for attempt in range(2):
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/api/auth/login"
        ) as pending:
            page.locator("#login-submit").click()
        response = pending.value
        delay = cooldown_delay(response.status, response.headers, attempt)
        if delay is None:
            assert response.status == 200, (
                f"Browser login returned HTTP {response.status}"
            )
            # A successful non-MFA login navigates immediately; Chromium can
            # discard its response body when the login document is unloaded.
            # Assert the resulting UI, and only read a challenge while the
            # MFA flow intentionally stays on this document.
            return response.json() if expect_mfa else {}
        page.wait_for_timeout(delay * 1000)
    raise AssertionError("Browser login cooldown exhausted")


def expect_dashboard(page):
    expect(page).to_have_url(re.compile(r"/dashboard(?:[?#].*)?$"))
    expect(page.locator(".dashboard-header")).to_be_visible()
    expect(page.locator('[data-tab="summary"]')).to_be_visible()


def expect_admin_ready(page, settings):
    # Admin bootstrap may honor one real Retry-After of at most 60 seconds.
    # Wait for successful initialization, never sleep or silently reauthenticate.
    expect(page).to_have_url(re.compile(r"/admin(?:[?#].*)?$"))
    assert page.request.get(settings.base_url + "/api/auth/me").status == 200
    expect(page.locator("#admin-status .status-text")).to_have_text(
        "Authenticated", timeout=65_000
    )
    expect(page).to_have_url(re.compile(r"/admin(?:[?#].*)?$"))


@pytest.fixture
def authenticated_page(page, settings, admin_api):
    # Cookies came from the real login endpoint, retaining HttpOnly. No
    # legacy bridge_token, fake session row, or navigation override.
    page.context.add_cookies(admin_api.browser_cookies())
    navigate(page, settings.base_url + "/dashboard")
    expect_dashboard(page)
    return page


@dataclass(repr=False)
class DisposableAdmin:
    username: str
    password: str = field(repr=False)
    # Logged in through the real login endpoint; its own session.
    client: Client = field(repr=False)


@pytest.fixture(scope="module")
def disposable_admin(disposable, admin_api, settings):
    """An admin account of this test module's own, with an HTTP session.

    Its sessions, and the bridge's per-user admin rate-limit bucket (ten
    sensitive admin requests a minute; the admin page spends two loading),
    are separate from the shared admin's, so a module can log it out or
    drive the admin page without spending the shared admin's budget. One
    per module, not per test: every login counts against the gateway's
    per-address limit of five a minute. A browser login creates another
    session for the same account; the HTTP client's session stays valid.
    """
    username = "e2e_admin_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "admin"},
        status=201,
    )
    try:
        client = Client(settings)
        assert client.login(username, password).get("session_token"), (
            "Disposable admin did not receive a session"
        )
        yield DisposableAdmin(username, password, client)
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))


@pytest.fixture(scope="session")
def disposable():
    if not enabled("SIGRIFT_E2E_DISPOSABLE"):
        pytest.fail(
            "This test creates synthetic data: use a disposable stack and SIGRIFT_E2E_DISPOSABLE=1, or explicitly select -m 'not disposable'",
            pytrace=False,
        )


@pytest.fixture(scope="session")
def synthetic_scanner(disposable, admin_api, settings):
    suffix = secrets.token_hex(5)
    node_id = "e2e-synthetic-" + suffix
    with diagnostics.fixture_stage("scanner_register"):
        admin_api.request(
            "POST",
            "/api/nodes/register",
            {
                "node_id": node_id,
                "host": "synthetic.invalid",
                "capabilities": {"test_fixture": True, "role": "synthetic-scanner"},
            },
            stage="scanner_register",
        )
    with diagnostics.fixture_stage("scanner_client"):
        sensor = Client(settings)
    with diagnostics.fixture_stage("scanner_key"):
        key = admin_api.request(
            "POST",
            "/api/admin/keys",
            {
                "description": "disposable E2E synthetic scanner",
                "role": "node",
                "node_id": node_id,
            },
            status=201,
            # The bridge's admin dependency returns 429 before creating a key.
            # Only that rejection may retry; a lost/failed response may have
            # already created a key and must remain a hard failure.
            retry_key_creation=True,
            stage="scanner_key",
        )
    detection_id = "e2e-detection-" + suffix
    detection_batch = {
        "node_id": node_id,
        "batch_id": "e2e-batch-" + suffix,
        "detections": [
            {
                "detection_id": detection_id,
                "signal_class": "bpsk",
                "confidence": 0.98,
                "freq_hz": 433920000,
                "snr_db": 24,
            }
        ],
    }
    try:
        with diagnostics.fixture_stage("scanner_key"):
            assert isinstance(key, dict) and all(
                isinstance(key.get(field), str) and bool(key[field])
                for field in ("key_id", "raw_key")
            ), "Scanner key response contract failed"
        with diagnostics.fixture_stage("scanner_detection"):
            result = sensor.request(
                "POST",
                "/api/detections/batch",
                detection_batch,
                key=key["raw_key"],
                stage="scanner_detection",
            )
            assert result["inserted"] == 1 and result["rejected"] == 0
        ssid = "E2E-Synthetic-" + suffix
        with diagnostics.fixture_stage("scanner_wifi"):
            result = sensor.request(
                "POST",
                "/api/wifi/ingest",
                {
                    "node_id": node_id,
                    "records": [
                        {
                            "bssid": "02:00:"
                            + ":".join(suffix[i : i + 2] for i in range(0, 8, 2)),
                            "ssid": ssid,
                            "channel": 6,
                            "band": "2.4GHz",
                            "security": "WPA2",
                            "signal_dbm": -45,
                            "frame_type": "beacon",
                        }
                    ],
                },
                key=key["raw_key"],
                status=201,
                stage="scanner_wifi",
            )
            assert result["inserted"] == 1

        def report(protocol, state, *, target=None, status=200):
            # Explicit synthetic lifecycle, never evidence of a physical radio.
            result = sensor.request(
                "POST",
                f"/api/nodes/{target or node_id}/scanner-status",
                {"protocol": protocol, "state": state},
                key=key["raw_key"],
                status=status,
                stage="scanner_status",
            )
            if status == 200:
                assert result["protocol"] == protocol and result["state"] == state
                assert result["active"] is (state == "running")
                assert result["expires_in_seconds"] == (
                    120 if state == "running" else 0
                )
            return result

        def upload_iq(target):
            # A synthetic tone, never a physical capture: float32 I/Q pairs.
            samples = [
                value
                for n in range(4096)
                for value in (
                    math.cos(2 * math.pi * n / 32),
                    math.sin(2 * math.pi * n / 32),
                )
            ]
            return sensor.request(
                "PUT",
                f"/api/detections/{target}/iq",
                raw=struct.pack(f"<{len(samples)}f", *samples),
                key=key["raw_key"],
                status=201,
                stage="scanner_iq",
            )

        yield {
            "node_id": node_id,
            "detection_id": detection_id,
            "ssid": ssid,
            "report": report,
            "observe_rf": lambda: fresh_rf_observation(sensor, key, node_id),
            "upload_iq": upload_iq,
        }
    finally:
        with diagnostics.fixture_stage("scanner_cleanup"):
            revoke_scanner_key(admin_api, sensor, key, detection_batch)
            sensor.request(
                "POST",
                f"/api/nodes/{node_id}/scanner-status",
                {"protocol": "wifi", "state": "running"},
                key=key["raw_key"],
                status=401,
                stage="scanner_revocation",
            )


def fresh_rf_observation(sensor, key, node_id):
    """Submit a new observation; session seed age must not control live tests."""
    suffix = secrets.token_hex(8)
    detection_id = "e2e-fresh-detection-" + suffix
    now = time.time()
    result = sensor.request(
        "POST",
        "/api/detections/batch",
        {
            "node_id": node_id,
            "batch_id": "e2e-fresh-batch-" + suffix,
            "period_start": now,
            "period_end": now,
            # Omit timestamp: actual ingest supplies current server time.
            "detections": [
                {
                    "detection_id": detection_id,
                    "node_id": node_id,
                    "signal_class": "bpsk",
                    "confidence": 0.98,
                    "freq_hz": 433920000,
                    "snr_db": 24,
                }
            ],
        },
        key=key["raw_key"],
        stage="scanner_detection",
    )
    assert result["accepted"] is True
    assert result["inserted"] == result["total"] == 1
    return detection_id


def revoke_scanner_key(admin_api, sensor, key, detection_batch):
    # Fast browser runs share the production admin bucket with UI reads.
    # Honor one explicit cooldown for cleanup; every assertion stays strict.
    admin_api.request(
        "DELETE",
        f"/api/admin/keys/{key['key_id']}",
        retry_key_cleanup=True,
        stage="scanner_cleanup",
    )
    # Reuse the exact valid ingest that already worked with this key. A 200
    # DELETE alone does not establish that the credential became unusable.
    sensor.request(
        "POST",
        "/api/detections/batch",
        detection_batch,
        key=key["raw_key"],
        status=401,
        stage="scanner_revocation",
    )


@pytest.fixture
def scanner_lease(synthetic_scanner):
    """Per-test synthetic lifecycle; the node-bound key traverses the gateway."""
    from contextlib import contextmanager

    @contextmanager
    def active(protocol):
        try:
            synthetic_scanner["report"](protocol, "running")
            yield
        finally:
            synthetic_scanner["report"](protocol, "stopped")

    return active
