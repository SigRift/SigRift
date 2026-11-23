"""Session and origin boundaries that only the deployed tiers show together.

Each case drives the real stack through its public gateway: a page on
another origin of the same site (so the browser attaches the session
cookie) cannot use an admin's session, and the gateway grants that origin
no CORS access to it; a session the gateway refuses for its client binding
cannot reach bridge routes through the proxy, whichever header carries it,
while a session bound to that client can; and logging out in one tab ends
the session that another tab still holds. Disposable identities are minted
and removed through the admin API.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import urllib.error
import urllib.request
from contextlib import ExitStack
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from .conftest import (
    USER_AGENT,
    browser_login,
    expect,
    expect_admin_ready,
    expect_dashboard,
    navigate,
)

REPO = Path(__file__).resolve().parents[2]


def _keys_described(api, description):
    return [
        key["key_id"]
        for key in api.request("GET", "/api/admin/keys")
        if key.get("description") == description
    ]


def _delete_keys(api, key_ids):
    for key_id in key_ids:
        api.request(
            "DELETE",
            f"/api/admin/keys/{key_id}",
            status=(200, 404),
            retry_key_cleanup=True,
        )


# ---------------------------------------------------------------------------
# 1. A same-site page on another origin cannot drive admin actions.
# ---------------------------------------------------------------------------

# Served (through the browser's request routing) on the gateway's host but
# another port: the same site, so the SameSite session cookie travels with
# its requests, and the same host, so it can read the CSRF cookie (cookies
# are not isolated by port). A form post cannot add the X-CSRF-Token header;
# a script that adds it needs CORS access the gateway must not grant.
ATTACK_PAGE = """<!doctype html>
<meta charset="utf-8"><title>Unrelated page</title>
<form id="forged" method="POST" enctype="text/plain"></form>
"""


def _submit_forged_form(page, url, body):
    """Post *body* as JSON from the attacker page; return the response.

    A text/plain form sends ``name=value``: *body* holds exactly one "=",
    inside a string, so the posted bytes are that JSON object.
    """
    name, separator, value = json.dumps(body).partition("=")
    assert separator and "=" not in value
    with page.expect_response(lambda response: response.url == url) as pending:
        page.evaluate(
            """({url, name, value}) => {
                const form = document.getElementById('forged');
                form.action = url;
                const field = document.createElement('input');
                field.name = name;
                field.value = value;
                form.appendChild(field);
                form.submit();
            }""",
            {"url": url, "name": name, "value": value},
        )
    return pending.value


def _cors_answer(api, method, path, headers):
    """The status and CORS grants the gateway sends this request.

    Sent with the session cookie *api* holds, as a browser would send it
    for a script on another origin; only the response headers are read.
    """
    request = urllib.request.Request(
        api.settings.base_url + path,
        method=method,
        headers={"User-Agent": USER_AGENT, **headers},
    )
    try:
        response = api.opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        response.read()
    grants = {
        name.lower(): value
        for name, value in response.headers.items()
        if name.lower().startswith("access-control-allow-")
    }
    return response.status, grants


def _shares_session_with(grants, origin):
    # What a browser needs before a script on *origin* may send credentials
    # with its request, or read the answer to one: this exact origin named,
    # and credentials allowed.
    return (
        grants.get("access-control-allow-origin") == origin
        and grants.get("access-control-allow-credentials", "").lower() == "true"
    )


@pytest.mark.disposable
def test_same_site_page_on_another_origin_cannot_use_the_admin_session(
    page, settings, disposable_admin
):
    api = disposable_admin.client
    suffix = secrets.token_hex(5)
    username = "e2e_csrf_" + suffix
    description = "e2e csrf forged key=" + suffix
    gateway = urlsplit(settings.base_url)
    port = gateway.port or {"https": 443, "http": 80}[gateway.scheme]
    attacker_origin = f"{gateway.scheme}://{gateway.hostname}:{port % 65535 + 1}"
    attacker_page = attacker_origin + "/innocent"
    forgeries = [
        # A route the gateway serves itself: a new admin account.
        (
            "/api/admin/users",
            {
                "username": username,
                "role": "admin",
                "password": "E2E-" + secrets.token_urlsafe(18) + "=9!",
            },
        ),
        # A route it forwards to the bridge: a new admin API key.
        ("/api/admin/keys", {"description": description, "role": "admin"}),
    ]
    page.context.add_cookies(api.browser_cookies())
    try:
        # The browser holds a working admin session.
        navigate(page, settings.base_url + "/admin")
        expect_admin_ready(page, settings)
        page.route(
            attacker_origin + "/**",
            lambda route: route.fulfill(
                status=200, content_type="text/html", body=ATTACK_PAGE
            ),
        )
        for path, body in forgeries:
            navigate(page, attacker_page)
            response = _submit_forged_form(page, settings.base_url + path, body)
            sent = response.request.all_headers().get("cookie", "")
            assert "session_token=" in sent, "The browser did not attach the session"
            assert response.status == 403, f"{path}: HTTP {response.status}"

            # A script on that page would add the token it can read: its
            # request needs the gateway's preflight approval first.
            status, grants = _cors_answer(
                api,
                "OPTIONS",
                path,
                {
                    "Origin": attacker_origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type,x-csrf-token",
                },
            )
            assert not _shares_session_with(grants, attacker_origin), (
                f"OPTIONS {path}: HTTP {status}, {grants}"
            )
            # Nor may it read what the session can: the cookie is valid,
            # and the answer names no other origin.
            status, grants = _cors_answer(api, "GET", path, {"Origin": attacker_origin})
            assert status == 200, f"GET {path}: HTTP {status}"
            assert not _shares_session_with(grants, attacker_origin), (
                f"GET {path}: {grants}"
            )
        assert all(
            user["username"] != username
            for user in api.request("GET", "/api/admin/users")
        ), "A cross-origin page created an admin account"
    finally:
        page.unroute(attacker_origin + "/**")
        api.request("DELETE", f"/api/admin/users/{username}", status=(200, 404))
        forged_keys = _keys_described(api, description)
        _delete_keys(api, forged_keys)
    assert not forged_keys, "A cross-origin page created an admin API key"


# ---------------------------------------------------------------------------
# 2. A session the gateway refuses never reaches the bridge through the proxy.
# ---------------------------------------------------------------------------

# Runs inside the stack's edge container: another client address on the
# stack's own network. The gateway binds a session to the address that
# logged in (its default BRIDGE_SESSION_BINDING=ip), the bridge does not
# (the shipped compose file sets it to none there), so only the proxy's
# refusal to pass a client's own session credentials keeps such a session
# out of bridge routes. The probe first logs in itself, from its own
# address, and sends the "control" requests with that session: they must
# succeed, so a refusal of the others is the binding, not the route. Its
# session never leaves the container; it logs out at the end. Requests and
# the password arrive on stdin, never in argv; it prints statuses only.
EDGE_PROBE = r"""
import json, os, ssl, sys, urllib.error, urllib.request
context = ssl.create_default_context(cafile=os.environ["MLRF_CA_CERT"])
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))

def send(item, own=None):
    headers = item["headers"]
    if own is not None:
        headers = {name: value.format(**own) for name, value in headers.items()}
    request = urllib.request.Request(
        os.environ["MLRF_API_URL"] + item["path"], method=item["method"],
        headers=headers,
        data=None if item["body"] is None else json.dumps(item["body"]).encode())
    try:
        response = opener.open(request, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.read()

job = json.load(sys.stdin)
status, body = send({"method": "POST", "path": "/api/auth/login",
                     "headers": {"Content-Type": "application/json"},
                     "body": job["login"]})
own = json.loads(body) if status == 200 else {}
result = {"login": status}
if own.get("session_token") and own.get("csrf_token"):
    result["control"] = [send(item, own)[0] for item in job["control"]]
    result["refused"] = [send(item)[0] for item in job["refused"]]
    result["logout"] = send({"method": "POST", "path": "/api/auth/logout",
                             "headers": {"Content-Type": "application/json",
                                         "Cookie": "session_token={session_token}; csrf_token={csrf_token}",
                                         "X-CSRF-Token": "{csrf_token}"},
                             "body": {}}, own)[0]
print(json.dumps(result))
"""


def from_edge_container(job):
    """Run *job* (see EDGE_PROBE) from the in-stack edge container."""
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "edge", "python3", "-c", EDGE_PROBE],
        input=json.dumps(job),
        capture_output=True,
        text=True,
        cwd=REPO,
        timeout=90,
    )
    # Output names statuses only; stderr can quote request headers.
    assert result.returncode == 0, "Edge container probe failed to run"
    return json.loads(result.stdout)


def _carrier_requests(carriers, paths, rule, csrf):
    requests, labels = [], []
    for carrier, headers in carriers.items():
        for path in paths:
            requests.append(
                {"method": "GET", "path": path, "headers": headers, "body": None}
            )
            labels.append(f"{carrier} GET {path}")
        requests.append(
            {
                "method": "POST",
                "path": "/api/alerts/rules/conditions",
                "headers": {
                    **headers,
                    "X-CSRF-Token": csrf,
                    "Content-Type": "application/json",
                },
                "body": rule,
            }
        )
        labels.append(f"{carrier} POST rule")
    return requests, labels


def _rule(name):
    return {
        "name": name,
        "conditions": [
            {"field": "node_id", "operator": "eq", "value": "never-" + name}
        ],
        "cooldown_seconds": 0,
        "notify_webhook": False,
    }


@pytest.mark.disposable
def test_session_refused_for_its_binding_cannot_reach_bridge_routes(
    page, settings, disposable_admin
):
    navigate(page, settings.base_url + "/login")  # shipped JS for coverage
    api = disposable_admin.client
    token = next(c.value for c in api.cookies if c.name == "session_token")
    csrf = next(c.value for c in api.cookies if c.name == "csrf_token")
    rule_name = "e2e-binding-" + secrets.token_hex(5)
    control_rule_name = rule_name + "-own"
    proxied = ["/api/alerts/rules/conditions", "/api/nodes/", "/api/wifi/networks"]
    paths = ["/api/auth/me", "/api/admin/users", *proxied]
    # The session is valid from the address that logged in.
    for path in proxied:
        api.request("GET", path)

    def carriers(session, csrf_cookie):
        return {
            "cookie": {"Cookie": f"session_token={session}; csrf_token={csrf_cookie}"},
            "bearer": {"Authorization": "Bearer " + session},
            "header": {"X-Session-Token": session},
        }

    refused, labels = _carrier_requests(
        carriers(token, csrf), paths, _rule(rule_name), csrf
    )
    # The same requests with the edge container's own session (filled in
    # there) must work. Its rule is written once, with the browser's cookie.
    control, control_labels = [], []
    for request, label in zip(
        *_carrier_requests(
            carriers("{session_token}", "{csrf_token}"),
            paths,
            _rule(control_rule_name),
            "{csrf_token}",
        )
    ):
        if "POST" not in label or label.startswith("cookie"):
            control.append(request)
            control_labels.append(label)
    try:
        outcome = from_edge_container(
            {
                "login": {
                    "username": disposable_admin.username,
                    "password": disposable_admin.password,
                },
                "control": control,
                "refused": refused,
            }
        )
        assert outcome["login"] == 200, outcome["login"]
        expected = {"GET": 200, "POST": 201}
        failed = [
            f"{label}: {status}"
            for label, status in zip(control_labels, outcome["control"])
            if status != expected[label.split()[1]]
        ]
        assert len(outcome["control"]) == len(control) and not failed, (
            "A session bound to the edge container was refused: " + "; ".join(failed)
        )
        assert len(outcome["refused"]) == len(refused)
        reached = [
            f"{label}: {status}"
            for label, status in zip(labels, outcome["refused"])
            if status != 401
        ]
        assert not reached, "Refused session answered other than 401: " + "; ".join(
            reached
        )
        assert outcome["logout"] == 200, outcome["logout"]
        # Refusal is per request: the session still works from its own address.
        assert (
            api.request("GET", "/api/auth/me")["username"] == disposable_admin.username
        )
    finally:
        rules = {
            item["name"]: item["rule_id"]
            for item in api.request("GET", "/api/alerts/rules/conditions")
            if item.get("name") in (rule_name, control_rule_name)
        }
        for rule_id in rules.values():
            api.request(
                "DELETE", "/api/alerts/rules/conditions/" + rule_id, status=(200, 404)
            )
    assert control_rule_name in rules, "The edge container's own session wrote no rule"
    assert rule_name not in rules, "A refused session created a rule"


# ---------------------------------------------------------------------------
# 3. Logging out in one tab ends the session another tab still holds.
# ---------------------------------------------------------------------------


def _log_out_from(page):
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/auth/logout"
    ) as logout:
        page.locator("#logout-btn").click()
    assert logout.value.status == 200
    expect(page).to_have_url(re.compile(r"/login(?:[?#].*)?$"))


# What the admin page loads once it is authenticated (/api/admin/stats)
# on its Keys tab: a refusal of any of them would also leave for the login
# page, so each must have answered before the session ends elsewhere.
ADMIN_FIRST_LOADS = (
    "/api/auth/me",
    "/api/admin/keys",
    "/api/ca/certs",
    "/api/training/runs",
)


def _sign_in(page, settings, admin, next_path):
    """Sign in through the login page, which hands this tab the token.

    The test's HTTP client keeps its own session of the same account.
    """
    with ExitStack() as first_loads:
        if next_path == "/admin":
            for path in ADMIN_FIRST_LOADS:
                first_loads.enter_context(
                    page.expect_response(
                        lambda response, path=path: (
                            urlsplit(response.url).path == path
                            and urlsplit(response.frame.url).path == "/admin"
                        ),
                        # The admin bootstrap may honour one Retry-After.
                        timeout=65_000,
                    )
                )
        browser_login(
            page,
            settings,
            username=admin.username,
            password=admin.password,
            next_path=next_path,
        )
        if next_path == "/admin":
            expect_admin_ready(page, settings)
        else:
            expect_dashboard(page)


def _session_credential(headers):
    """The session credential a request carried in a header, as (name, value)."""
    for name in ("x-session-token", "authorization"):
        if headers.get(name):
            return name, headers[name]
    return None


@pytest.mark.disposable
def test_logout_in_one_tab_refuses_the_admin_action_of_another(
    page, settings, disposable_admin
):
    description = "e2e other-tab key " + secrets.token_hex(5)
    api = disposable_admin.client  # a separate session of the same account
    other_tab = None
    try:
        _sign_in(page, settings, disposable_admin, "/admin")
        # A second tab shares the cookie session; it holds no token itself.
        other_tab = page.context.new_page()
        navigate(other_tab, settings.base_url + "/dashboard")
        expect_dashboard(other_tab)
        _log_out_from(other_tab)

        # The admin tab still shows its form and holds its token. Its next
        # action reaches the gateway with that token alone and is refused.
        page.locator("#new-key-desc").fill(description)
        page.locator("#new-key-role").select_option("admin")
        with page.expect_response(
            lambda response: urlsplit(response.url).path == "/api/admin/keys"
            and response.request.method == "POST"
        ) as create:
            page.locator("#create-key-btn").click()
        headers = create.value.request.all_headers()
        credential = _session_credential(headers)
        assert credential, "The tab no longer sent its token"
        assert "session_token=" not in headers.get("cookie", "")
        assert create.value.status == 401, create.value.status
        expect(page).to_have_url(re.compile(r"/login\?next=%2Fadmin$"))
        expect(page.locator("#login-submit")).to_be_visible()
        # The server ended that session: its token is refused on its own,
        # from the address it was issued to, for a plain read.
        holder = urllib.request.Request(
            settings.base_url + "/api/auth/me",
            headers={"User-Agent": USER_AGENT, credential[0]: credential[1]},
        )
        try:
            with api.opener.open(holder, timeout=20) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.status
        assert status == 401, f"The logged-out session still answers: HTTP {status}"
    finally:
        if other_tab is not None:
            other_tab.close()
        made = _keys_described(api, description)
        _delete_keys(api, made)
    assert not made, "A logged-out tab made a key"


@pytest.mark.disposable
def test_logout_in_one_tab_sends_another_dashboard_tab_to_login(
    page, settings, disposable_admin
):
    from playwright.sync_api import Error as PlaywrightError

    other_tab = None
    refused = []

    def note_refusal(response):
        path = urlsplit(response.url).path
        if response.status == 401 and path.startswith("/api/"):
            refused.append(path)

    try:
        _sign_in(page, settings, disposable_admin, "/dashboard")
        other_tab = page.context.new_page()
        navigate(other_tab, settings.base_url + "/dashboard")
        expect_dashboard(other_tab)
        page.on("response", note_refusal)
        _log_out_from(other_tab)

        # Opening the Alerts tab asks for alerts, which the server refuses.
        # The tab's own polls (nodes, status, setup, summary) are refused
        # too and may send it to sign-in before the click lands; whichever
        # refusal comes first must take it there.
        if not refused:
            try:
                page.locator('[data-tab="alerts"]').click(timeout=10_000)
            except PlaywrightError:
                pass  # The tab left for sign-in before the click landed.
        # A page that handles the refusal leaves at once, as the admin
        # page does, and comes back here after sign-in; this waits for
        # that, not for a timer.
        expect(page).to_have_url(re.compile(r"/login\?next=%2Fdashboard$"))
        assert refused, "The tab went to sign-in although no request was refused"
        expect(page.locator("#login-submit")).to_be_visible()
    finally:
        if other_tab is not None:
            other_tab.close()
