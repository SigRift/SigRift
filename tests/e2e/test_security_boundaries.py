"""Cross-tier security boundaries of the deployed Rust gateway + Python bridge.

These checks exercise the REAL running stack through the external gateway URL
(verified TLS, the gateway CA, server-issued cookies/keys). They target the
boundaries that only exist once the tiers run together — the gateway's security
headers, path canonicalisation, CSRF double-submit, cross-tier authorisation,
identity-header stripping, the gateway-only bridge API, and WebSocket admission
— rather than any single tier's unit behaviour. Nothing here injects into the
database, bypasses CSP, or skips on missing setup; every synthetic identity is
minted and revoked through the same public admin API an operator would use.

Where a real browser is not required, the assertions run at the HTTP level with
the fixtures' urllib client and the gateway CA: the gateway refuses WebSocket
upgrades, cross-origin handshakes and malformed paths before any upgrade or
proxy, so an HTTP request observes the exact refusal a browser would. Each test
still loads a shipped page once, because the suite's autouse coverage collector
requires real JavaScript to execute.
"""

from __future__ import annotations

import html
import json
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

import pytest

from .conftest import USER_AGENT, Client, cooldown_delay, navigate

# A documentation/test-net address that is never a real client, used to prove
# the gateway does not honour a client-supplied X-Forwarded-For / X-Real-IP.
SPOOFED_IP = "203.0.113.99"
# A cross-site origin an attacker page would present.
CROSS_SITE_ORIGIN = "https://evil.example"


@dataclass
class HttpResult:
    status: int
    headers: dict  # lower-cased header name -> value
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def send(opener, settings, method, path, *, headers=None, body=None):
    """Issue one request through *opener*, returning status, headers and body.

    ``opener`` decides which credentials travel: the shared admin client's
    opener carries its HttpOnly session + CSRF cookies, a fresh
    ``Client(settings)`` opener is anonymous. The conftest ``Client`` discards
    response headers, so this helper exists to assert on them and to send
    headers (CSRF, Origin, forged identity) the client would never add itself.
    """
    merged = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if body is not None:
        merged["Content-Type"] = "application/json"
    if headers:
        merged.update(headers)
    request = urllib.request.Request(
        settings.base_url + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers=merged,
    )
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read()
    return HttpResult(
        response.status,
        {key.lower(): value for key, value in response.headers.items()},
        raw,
    )


def csrf_value(client):
    """The CSRF double-submit token the server set for *client*'s session."""
    return next(
        cookie.value for cookie in client.cookies if cookie.name == "csrf_token"
    )


@pytest.fixture
def anon(settings):
    """A credential-free HTTP client against the live gateway (empty cookie jar)."""
    return Client(settings)


@pytest.fixture(scope="session")
def viewer_key(admin_api, disposable, settings):
    """One shared, disposable VIEWER API key for read-only / role-ceiling checks.

    Session-scoped so the admin sensitive-key bucket (PRE-22/PRE-32) sees only
    one create and one delete for every test that reuses it. Tests that revoke a
    key mint their own instead.
    """
    description = "e2e-sec viewer key " + secrets.token_hex(5)
    key = admin_api.request(
        "POST",
        "/api/admin/keys",
        {"description": description, "role": "viewer"},
        status=201,
        retry_key_creation=True,
    )
    assert key.get("raw_key") and key.get("key_id"), "Viewer key response contract"
    try:
        yield key
    finally:
        admin_api.request(
            "DELETE",
            f"/api/admin/keys/{key['key_id']}",
            status=(200, 404),
            retry_key_cleanup=True,
        )


def assert_security_headers(result, *, where, expect_hsts=True):
    """Every gateway response (HTML, JSON, asset, error) carries the hardening set."""
    headers = result.headers
    assert headers.get("x-content-type-options") == "nosniff", where
    assert headers.get("x-frame-options") == "DENY", where
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin", where
    assert "permissions-policy" in headers, where
    csp = headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, f"{where}: CSP frame-ancestors missing"
    assert "script-src" in csp, f"{where}: CSP script-src missing"
    assert "base-uri 'self'" in csp, f"{where}: CSP base-uri missing"
    assert "form-action 'self'" in csp, f"{where}: CSP form-action missing"
    if expect_hsts:
        assert "max-age=" in headers.get("strict-transport-security", ""), (
            f"{where}: HSTS missing on an HTTPS response"
        )


# ---------------------------------------------------------------------------
# 1. Security response headers on HTML, API JSON, static assets AND errors.
# ---------------------------------------------------------------------------


@pytest.mark.disposable  # the 403 sample is a disposable viewer key
def test_security_headers_on_content_and_error_responses(
    page, settings, admin_api, viewer_key, anon, disposable
):
    navigate(page, settings.base_url + "/login")  # exercise shipped JS for coverage

    # HTML page (unauthenticated login document).
    html = send(anon.opener, settings, "GET", "/login")
    assert html.status == 200 and "text/html" in html.headers.get("content-type", "")
    assert_security_headers(html, where="HTML /login")
    assert "no-store" in html.headers.get("cache-control", ""), (
        "HTML page must not be cached"
    )

    # Authenticated API JSON.
    me = send(admin_api.opener, settings, "GET", "/api/auth/me")
    assert me.status == 200 and "application/json" in me.headers.get("content-type", "")
    assert_security_headers(me, where="API /api/auth/me")
    assert "no-store" in me.headers.get("cache-control", ""), (
        "Authenticated API response must be no-store"
    )

    # Static asset (shipped JavaScript).
    asset = send(anon.opener, settings, "GET", "/static/login.js")
    assert asset.status == 200, asset.status
    assert_security_headers(asset, where="static /static/login.js")

    # Error responses: 401, 403, 404, 405 all pass through the header layer.
    unauthorised = send(anon.opener, settings, "GET", "/api/auth/me")
    assert unauthorised.status == 401
    assert_security_headers(unauthorised, where="401 /api/auth/me")
    assert "no-store" in unauthorised.headers.get("cache-control", "")

    forbidden = send(
        anon.opener,
        settings,
        "GET",
        "/api/admin/users",
        headers={"X-API-Key": viewer_key["raw_key"]},
    )
    assert forbidden.status == 403
    assert_security_headers(forbidden, where="403 /api/admin/users")

    not_found = send(
        anon.opener,
        settings,
        "GET",
        "/api/this-route-does-not-exist-" + secrets.token_hex(4),
    )
    assert not_found.status == 404
    assert_security_headers(not_found, where="404 unknown route")

    method_not_allowed = send(anon.opener, settings, "POST", "/api/auth/me")
    assert method_not_allowed.status == 405
    assert_security_headers(method_not_allowed, where="405 /api/auth/me")


# ---------------------------------------------------------------------------
# 2. Path-normalisation bypass attempts on a protected route, no credentials.
# ---------------------------------------------------------------------------

# Each targets the admin users route (native, Admin-only). A successful bypass
# would route one path at the gateway while the bridge served another, or reach
# the native route without its auth. None may answer 200; the expected status is
# recorded alongside each attempt.
NORMALISATION_CASES = [
    ("encoded_unreserved_u", "/api/admin/%75sers", {401}),
    ("encoded_slash_trailing", "/api/admin/users%2f", {400}),
    ("encoded_slash_mid", "/api/admin%2fusers", {400}),
    ("encoded_slash_upper", "/api/admin/users%2F", {400}),
    ("dot_segment", "/api/admin/./users", {400}),
    ("dotdot_segment", "/api/admin/../admin/users", {400}),
    ("trailing_dotdot", "/api/admin/users/..", {400}),
    ("backslash", "/api/admin\\users", {400}),
    ("null_byte", "/api/admin/users%00", {400}),
    ("encoded_tab", "/api/admin/users%09", {400}),
    ("encoded_dot_suffix", "/api/admin/users%2e", {401, 404}),
    ("mixed_case", "/API/admin/users", {401, 404}),
    ("trailing_semicolon", "/api/admin/users;", {401, 404}),
    ("double_encoded_slash", "/api/admin/users%252f", {401, 404}),
]


@pytest.mark.parametrize(
    "path,expected",
    [(path, expected) for _, path, expected in NORMALISATION_CASES],
    ids=[name for name, _, _ in NORMALISATION_CASES],
)
def test_path_normalisation_cannot_reach_protected_data(
    page, settings, anon, path, expected
):
    navigate(page, settings.base_url + "/login")
    result = send(anon.opener, settings, "GET", path)
    # None may return protected data: an unauthenticated 200 is the only failure.
    assert result.status != 200, f"{path}: bypass returned 200 {result.text[:200]!r}"
    assert result.status in (expected | {401, 403, 404}), (
        f"{path}: unexpected status {result.status}"
    )
    assert "password_hash" not in result.text and '"users"' not in result.text


# ---------------------------------------------------------------------------
# 3. CSRF double-submit on state-changing requests with a valid session.
# ---------------------------------------------------------------------------

CONDITION_RULES = "/api/alerts/rules/conditions"


def _condition_rule_body():
    suffix = secrets.token_hex(5)
    return {
        "name": "e2e-sec-csrf-" + suffix,
        "conditions": [
            {"field": "node_id", "operator": "eq", "value": "never-" + suffix}
        ],
        "cooldown_seconds": 0,
        "notify_webhook": False,
    }


@pytest.mark.disposable
def test_csrf_rejects_forged_state_changes(page, settings, admin_api, disposable):
    navigate(page, settings.base_url + "/login")
    token = csrf_value(admin_api)

    # Missing token: the session cookie travels, but no X-CSRF-Token header.
    missing = send(
        admin_api.opener, settings, "POST", CONDITION_RULES, body=_condition_rule_body()
    )
    assert missing.status == 403, missing.status

    # Wrong token.
    wrong = send(
        admin_api.opener,
        settings,
        "POST",
        CONDITION_RULES,
        headers={"X-CSRF-Token": "not-" + token},
        body=_condition_rule_body(),
    )
    assert wrong.status == 403, wrong.status

    # Cross-site forgery: an attacker page can set Origin/Referer but cannot
    # read the double-submit token, so the request is refused. (SameSite=Lax +
    # the unreadable token are the mechanism; the server does not accept it.)
    cross_site = send(
        admin_api.opener,
        settings,
        "POST",
        CONDITION_RULES,
        headers={"Origin": CROSS_SITE_ORIGIN, "Referer": CROSS_SITE_ORIGIN + "/"},
        body=_condition_rule_body(),
    )
    assert cross_site.status == 403, cross_site.status


@pytest.mark.disposable
def test_csrf_accepts_matching_double_submit_token(
    page, settings, admin_api, disposable
):
    navigate(page, settings.base_url + "/login")
    token = csrf_value(admin_api)
    created = send(
        admin_api.opener,
        settings,
        "POST",
        CONDITION_RULES,
        headers={"X-CSRF-Token": token},
        body=_condition_rule_body(),
    )
    assert created.status == 201, f"Valid CSRF token rejected: {created.status}"
    rule_id = json.loads(created.body)["rule_id"]
    # admin_api.request supplies the token automatically for the cleanup DELETE.
    admin_api.request("DELETE", f"{CONDITION_RULES}/{rule_id}", status=(200, 404))


# ---------------------------------------------------------------------------
# 4. Authorisation across tiers.
# ---------------------------------------------------------------------------

UNAUTH_PROTECTED = [
    ("admin_users_native", "GET", "/api/admin/users"),
    ("admin_audit_native", "GET", "/api/admin/audit"),
    ("alert_rules_proxied", "GET", CONDITION_RULES),
    ("detections_recent", "GET", "/api/detections/recent"),
]


@pytest.mark.parametrize(
    "method,path",
    [(m, p) for _, m, p in UNAUTH_PROTECTED],
    ids=[name for name, _, _ in UNAUTH_PROTECTED],
)
def test_unauthenticated_requests_are_rejected(page, settings, anon, method, path):
    navigate(page, settings.base_url + "/login")
    result = send(anon.opener, settings, method, path)
    assert result.status == 401, f"{path}: expected 401, got {result.status}"


@pytest.mark.disposable
def test_viewer_role_forbidden_on_admin_and_analyst_writes(
    page, settings, viewer_key, disposable
):
    navigate(page, settings.base_url + "/login")
    key = viewer_key["raw_key"]
    opener = Client(settings).opener  # anonymous jar; only the API key authenticates

    # Admin-only native route.
    admin_route = send(
        opener, settings, "GET", "/api/admin/users", headers={"X-API-Key": key}
    )
    assert admin_route.status == 403, admin_route.status

    # Analyst write, proxied to the bridge's role check.
    analyst_write = send(
        opener,
        settings,
        "POST",
        CONDITION_RULES,
        headers={"X-API-Key": key},
        body=_condition_rule_body(),
    )
    assert analyst_write.status == 403, analyst_write.status

    # Native analyst-level gate: a non-node credential may not ingest a batch.
    batch = send(
        opener,
        settings,
        "POST",
        "/api/detections/batch",
        headers={"X-API-Key": key},
        body={
            "node_id": "e2e-sec-" + secrets.token_hex(4),
            "batch_id": "e2e-sec-" + secrets.token_hex(4),
            "detections": [
                {
                    "detection_id": "e2e-sec-" + secrets.token_hex(4),
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433920000,
                }
            ],
        },
    )
    assert batch.status == 403, batch.status


@pytest.mark.disposable
def test_api_key_rejected_after_revocation(page, settings, admin_api, disposable):
    navigate(page, settings.base_url + "/login")
    description = "e2e-sec revoke " + secrets.token_hex(5)
    key = admin_api.request(
        "POST",
        "/api/admin/keys",
        {"description": description, "role": "viewer"},
        status=201,
        retry_key_creation=True,
    )
    sensor = Client(settings)
    revoked = False
    try:
        # The key reads before revocation.
        sensor.request("GET", "/api/detections/recent", key=key["raw_key"])
        admin_api.request(
            "DELETE",
            f"/api/admin/keys/{key['key_id']}",
            retry_key_cleanup=True,
        )
        revoked = True
        # The identical read is refused once the credential is gone.
        sensor.request("GET", "/api/detections/recent", key=key["raw_key"], status=401)
    finally:
        if not revoked:
            admin_api.request(
                "DELETE",
                f"/api/admin/keys/{key['key_id']}",
                status=(200, 404),
                retry_key_cleanup=True,
            )


@pytest.mark.disposable
def test_disabled_user_session_rejected_on_next_request(
    page, settings, admin_api, disposable
):
    navigate(page, settings.base_url + "/login")
    username = "e2e_sec_disable_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "viewer"},
        status=201,
    )
    try:
        actor = Client(settings)
        actor.login(username, password)
        assert actor.has_session(), "no session"
        assert actor.request("GET", "/api/auth/me")["username"] == username
        # Admin disables the account (sessions revoked atomically, PRE-30).
        admin_api.request("DELETE", f"/api/admin/users/{username}")
        actor.request("GET", "/api/auth/me", status=401)
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))


@pytest.mark.disposable
def test_password_reset_revokes_old_sessions(page, settings, admin_api, disposable):
    navigate(page, settings.base_url + "/login")
    username = "e2e_sec_reset_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "viewer"},
        status=201,
    )
    try:
        actor = Client(settings)
        actor.login(username, password)
        assert actor.has_session(), "no session"
        assert actor.request("GET", "/api/auth/me")["username"] == username
        new_password = "E2E-" + secrets.token_urlsafe(24) + "7!"
        admin_api.request(
            "POST",
            f"/api/admin/users/{username}/reset-password",
            {"new_password": new_password},
        )
        # The pre-reset session no longer authenticates.
        actor.request("GET", "/api/auth/me", status=401)
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))


@pytest.mark.disposable
def test_cross_site_text_plain_login_sets_no_session(
    page, settings, admin_api, disposable
):
    """Login CSRF: a cross-site form cannot sign the browser in.

    Login is CSRF-exempt, and the gateway read its body as JSON whatever the
    Content-Type, so an attacker page's ``enctype="text/plain"`` form (no
    preflight) whose field spells a JSON object signed the victim's browser
    into the attacker's account. It now answers 415 and sets no cookie. The
    form posts from a second, opaque origin in a real browser.

    Marked ``disposable`` (it creates a user), which also keeps it off
    ``e2e-staging`` until staging runs a gateway with the 415.
    """
    navigate(page, settings.base_url + "/login")
    username = "e2e_sec_csrf_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "viewer"},
        status=201,
    )
    try:
        # text/plain sends `name=value` + CRLF: this field name and value
        # make the body {"username":…,"password":…,"x":"="}.
        name = json.dumps({"username": username, "password": password})[:-1]
        name += ', "x": "'
        value = '"}'
        form = (
            '<form method="post" enctype="text/plain" '
            f'action="{html.escape(settings.base_url)}/api/auth/login">'
            f'<input type="hidden" name="{html.escape(name)}" '
            f'value="{html.escape(value)}"></form>'
        )
        attacker = page.context.new_page()
        try:
            attacker.set_content(form)
            with attacker.expect_response(
                lambda r: r.url == settings.base_url + "/api/auth/login"
            ) as answer:
                attacker.evaluate("document.forms[0].submit()")
            assert answer.value.status == 415, answer.value.status
        finally:
            attacker.close()
        assert not [
            cookie
            for cookie in page.context.cookies(settings.base_url)
            if cookie["name"] == "session_token" and cookie["value"]
        ], "a cross-site form signed the browser in"

        # The same refusal without a browser, and it costs the account
        # nothing: no rate-limit attempt, no lockout failure.
        actor = Client(settings)
        body = json.dumps({"username": username, "password": password}).encode()
        request = urllib.request.Request(
            settings.base_url + "/api/auth/login",
            data=body,
            method="POST",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "text/plain;charset=application/json",
                "Origin": CROSS_SITE_ORIGIN,
            },
        )
        try:
            response = actor.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == 415, response.status
        assert not actor.has_session()
        actor.login(username, password)
        assert actor.has_session()
        assert actor.request("GET", "/api/auth/me")["username"] == username
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))


@pytest.mark.disposable
def test_cross_site_logout_form_keeps_the_session(
    page, settings, admin_api, disposable
):
    """Forced sign-out: a cross-site form cannot sign the browser out.

    Logout is CSRF-exempt, and a cross-site form post carries none of the
    ``SameSite=Lax`` cookies, so it gets the "no token" 401. A browser
    applies the ``Set-Cookie`` of a top-level navigation's response whatever
    its SameSite, so when that 401 expired the cookies, any page could sign
    a visitor's dashboard out on every visit (the session itself lived on).
    The 401 now sets no cookie for a request that carried none of them.

    Marked ``disposable`` because it creates a user.
    """
    navigate(page, settings.base_url + "/login")
    username = "e2e_sec_logout_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "viewer"},
        status=201,
    )
    try:
        actor = Client(settings)
        actor.login(username, password)
        assert actor.has_session()
        page.context.add_cookies(actor.browser_cookies())
        form = (
            f'<form method="post" action="{html.escape(settings.base_url)}'
            '/api/auth/logout"><input type="hidden" name="x" value="1"></form>'
        )
        attacker = page.context.new_page()
        try:
            attacker.set_content(form)
            with attacker.expect_response(
                lambda r: r.url == settings.base_url + "/api/auth/logout"
            ) as answer:
                attacker.evaluate("document.forms[0].submit()")
            assert answer.value.status == 401, answer.value.status
            assert "set-cookie" not in answer.value.all_headers()
        finally:
            attacker.close()
        kept = {
            cookie["name"]
            for cookie in page.context.cookies(settings.base_url)
            if cookie["value"]
        }
        assert {"session_token", "csrf_token"} <= kept, kept
        me = page.request.get(settings.base_url + "/api/auth/me")
        assert me.status == 200 and me.json()["username"] == username
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))


# ---------------------------------------------------------------------------
# 5. Identity-header spoofing.
# ---------------------------------------------------------------------------

# The gateway owns x-rust-proxy / x-auth-* / x-license-*; it strips any
# client-supplied copy at ingress, and only it resolves the client IP.
FORGED_IDENTITY = {
    "X-Auth-User": "admin",
    "X-Auth-Role": "admin",
    "X-Auth-Key-Id": "master",
    "X-Auth-Method": "client-cert",
    "X-Forwarded-User": "admin",
    "X-Rust-Proxy": "forged-" + secrets.token_hex(8),
    "X-Forwarded-For": SPOOFED_IP,
    "X-Real-IP": SPOOFED_IP,
}


def test_forged_identity_headers_grant_no_access(page, settings, anon):
    navigate(page, settings.base_url + "/login")
    # No real credential, only forged trust/identity headers: still 401.
    result = send(
        anon.opener, settings, "GET", "/api/admin/users", headers=dict(FORGED_IDENTITY)
    )
    assert result.status == 401, f"forged identity granted access: {result.status}"


@pytest.mark.disposable
def test_forged_role_header_does_not_escalate_a_viewer_key(
    page, settings, viewer_key, disposable
):
    navigate(page, settings.base_url + "/login")
    headers = dict(FORGED_IDENTITY)
    headers["X-API-Key"] = viewer_key["raw_key"]
    # A real VIEWER key plus a forged X-Auth-Role: admin must stay a viewer.
    result = send(
        Client(settings).opener, settings, "GET", "/api/admin/users", headers=headers
    )
    assert result.status == 403, f"forged role escalated a viewer key: {result.status}"


def test_forwarded_for_is_not_honoured_for_rate_limit_identity(
    page, settings, admin_api, anon
):
    navigate(page, settings.base_url + "/login")
    # One failed login carrying a forged X-Forwarded-For / X-Real-IP. The IP the
    # gateway binds to rate-limit, lockout and the audit note is the resolved
    # peer, never the client-supplied value; proving the note is not the spoofed
    # address proves the same IP cannot be used to shard the rate-limit bucket.
    probe_user = "e2e_sec_xff_" + secrets.token_hex(6)
    for attempt in range(2):
        failed = send(
            anon.opener,
            settings,
            "POST",
            "/api/auth/login",
            headers={"X-Forwarded-For": SPOOFED_IP, "X-Real-IP": SPOOFED_IP},
            body={"username": probe_user, "password": "wrong-" + secrets.token_hex(8)},
        )
        # Honour one server-directed login cooldown so the attempt reaches the
        # handler (and is audited) rather than being rate-limited away.
        delay = cooldown_delay(failed.status, failed.headers, attempt)
        if delay is None:
            break
        time.sleep(delay)
    assert failed.status == 401, failed.status

    entries = admin_api.request(
        "GET", f"/api/admin/audit?target_id={probe_user}&limit=20"
    )["entries"]
    # The attempt was recorded, and no record reflects the forged address.
    assert entries, "the failed login was not audited, so the IP binding is unproven"
    for entry in entries:
        assert SPOOFED_IP not in entry.get("note", ""), (
            "a client-supplied X-Forwarded-For reached the gateway's IP binding"
        )


# ---------------------------------------------------------------------------
# 6. Internal-only bridge endpoints are not reachable through the gateway.
# ---------------------------------------------------------------------------

INTERNAL_SPELLINGS = [
    ("bind_plain", "POST", "/api/internal/bind-node-key"),
    ("hook_plain", "POST", "/api/internal/ingest-hook"),
    ("bind_get", "GET", "/api/internal/bind-node-key"),
    ("encoded_i", "GET", "/api/%69nternal/ingest-hook"),
    ("encoded_slash", "POST", "/api/internal%2Fingest-hook"),
    ("backslash", "POST", "/api/internal\\ingest-hook"),
    ("mixed_case", "GET", "/API/Internal/ingest-hook"),
    ("double_slash", "GET", "/api//internal/ingest-hook"),
]


@pytest.mark.parametrize(
    "method,path",
    [(m, p) for _, m, p in INTERNAL_SPELLINGS],
    ids=[name for name, _, _ in INTERNAL_SPELLINGS],
)
def test_internal_bridge_api_unreachable_through_gateway(
    page, settings, admin_api, anon, method, path
):
    navigate(page, settings.base_url + "/login")
    # Anonymous and admin alike are refused before auth or proxying: the gateway
    # answers 404 for the bridge's gateway-only API however the path is spelled.
    anon_result = send(anon.opener, settings, method, path)
    assert anon_result.status == 404, f"{path} (anon): {anon_result.status}"
    # The gateway's own refusal, not a bridge handler leaking through the proxy.
    assert "not found" in anon_result.text.lower(), anon_result.text[:200]

    admin_result = send(
        admin_api.opener,
        settings,
        method,
        path,
        headers={"X-CSRF-Token": csrf_value(admin_api)},
        body={} if method != "GET" else None,
    )
    assert admin_result.status == 404, f"{path} (admin): {admin_result.status}"


# ---------------------------------------------------------------------------
# 7. WebSocket admission: no credentials, and cross-site origin, are refused.
# ---------------------------------------------------------------------------

WS_UPGRADE_HEADERS = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}


def test_websocket_upgrade_without_credentials_is_refused(page, settings, anon):
    navigate(page, settings.base_url + "/login")
    result = send(
        anon.opener, settings, "GET", "/ws/feed", headers=dict(WS_UPGRADE_HEADERS)
    )
    # Refused (401) before any upgrade; never a 101 switching protocols.
    assert result.status == 401, result.status
    assert "not authenticated" in result.text.lower()


def test_websocket_cross_site_origin_with_session_is_refused(page, settings, admin_api):
    navigate(page, settings.base_url + "/login")
    headers = dict(WS_UPGRADE_HEADERS)
    headers["Origin"] = CROSS_SITE_ORIGIN
    # The admin session cookie travels on the shared opener; a browser would
    # attach it to a cross-site handshake, which the gateway rejects (403).
    result = send(admin_api.opener, settings, "GET", "/ws/feed", headers=headers)
    assert result.status == 403, result.status
    assert "cross-origin" in result.text.lower()
