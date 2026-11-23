"""Real browser login, logout, cookie-only navigation and authenticated writes."""

import html
import os
import re
import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import (
    Client,
    browser_login,
    expect,
    expect_admin_ready,
    expect_dashboard,
    fresh_totp,
    navigate,
)


def test_browser_login_and_logout_revokes_session(page, settings):
    secret = os.environ.get("BRIDGE_ADMIN_TOTP_SECRET")
    # Normalizing this local URL creates a double-slash pathname. The
    # controller must not reinterpret that pathname as an external host.
    result = browser_login(
        page, settings, expect_mfa=bool(secret), next_path="/.//evil.example"
    )
    if result.get("mfa_required"):
        assert secret, "Set BRIDGE_ADMIN_TOTP_SECRET for the test admin"
        page.locator("#mfa-code").fill(fresh_totp(secret))
        page.locator("#mfa-submit").click()
    expect(page).to_have_url(settings.base_url + "//evil.example")
    assert urlsplit(page.url).netloc == urlsplit(settings.base_url).netloc
    # The local malformed route is allowed to return 404; prove the login
    # session still works at the actual dashboard before checking logout.
    navigate(page, settings.base_url + "/dashboard")
    expect_dashboard(page)
    expect(page.locator("#logout-btn")).to_be_visible()
    assert page.request.get(settings.base_url + "/api/auth/me").status == 200
    old_session = next(
        cookie["value"]
        for cookie in page.context.cookies()
        if cookie["name"] == "session_token"
    )
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/auth/logout"
    ) as pending:
        page.locator("#logout-btn").click()
    assert pending.value.status == 200
    expect(page).to_have_url(re.compile(r"/login(?:[?#].*)?$"))
    assert page.request.get(settings.base_url + "/api/auth/me").status == 401
    replay = page.request.get(
        settings.base_url + "/api/auth/me",
        headers={"Cookie": "session_token=" + old_session},
    )
    assert replay.status == 401, "Logout left the previous server session usable"
    navigate(page, settings.base_url + "/dashboard")
    expect(page).to_have_url(re.compile(r"/login(?:[?#].*)?$"))
    expect(page.locator("#login-submit")).to_be_visible()


def test_cookie_only_dashboard_and_admin_render(authenticated_page, settings):
    page = authenticated_page
    assert page.evaluate("sessionStorage.getItem('bridge_session_token')") is None
    expect(page.locator("#logout-btn")).to_be_visible()
    expect(page.locator("#user-display-name")).not_to_be_empty()
    response = navigate(page, settings.base_url + "/admin")
    expect_admin_ready(page, settings)
    assert "script-src" in response.headers.get("content-security-policy", ""), (
        "CSP missing"
    )
    expect(page).to_have_url(re.compile(r"/admin(?:[?#].*)?$"))
    expect(page.locator("#keys-table")).to_be_visible()
    expect(page.locator("#alerts-link")).to_be_visible()


def test_cookie_only_logout_revokes_server_session(page, settings):
    # Separate real session: logging out must not revoke the shared API
    # fixture used to prepare and clean up the other tests.
    client = Client(settings)
    result = client.login(settings.username, settings.password)
    if result.get("mfa_required"):
        secret = os.environ.get("BRIDGE_ADMIN_TOTP_SECRET")
        assert secret, "Set BRIDGE_ADMIN_TOTP_SECRET for the test admin"
        client.request(
            "POST",
            "/api/auth/mfa/verify",
            {"mfa_token": result["mfa_token"], "totp_code": fresh_totp(secret)},
        )
    page.context.add_cookies(client.browser_cookies())
    navigate(page, settings.base_url + "/dashboard")
    expect_dashboard(page)
    expect(page.locator("#logout-btn")).to_be_visible()
    old_session = next(
        cookie["value"]
        for cookie in page.context.cookies()
        if cookie["name"] == "session_token"
    )
    # A failed network request must keep the current session visible and
    # usable, so the operator can retry instead of receiving false success.
    page.context.set_offline(True)
    page.locator("#logout-btn").click()
    expect(
        page.get_by_text("Could not sign out. Please try again.", exact=True)
    ).to_be_visible()
    expect(page).to_have_url(re.compile(r"/dashboard(?:[?#].*)?$"))
    assert client.request("GET", "/api/auth/me")["username"] == settings.username
    page.context.set_offline(False)
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/auth/logout"
    ) as pending:
        page.locator("#logout-btn").click()
    assert pending.value.status == 200
    assert page.request.get(settings.base_url + "/api/auth/me").status == 401
    replay = page.request.get(
        settings.base_url + "/api/auth/me",
        headers={"Cookie": "session_token=" + old_session},
    )
    assert replay.status == 401, "Cookie logout left the previous server session usable"


@pytest.mark.disposable
def test_admin_can_create_edit_and_read_back_condition_rule(
    authenticated_page, settings, admin_api, disposable
):
    page = authenticated_page
    suffix = secrets.token_hex(5)
    name = (
        f"E2E '{suffix}' <img src=x onerror=window.__alertTextExecuted=1> &amp; &#x27;"
    )
    navigate(page, settings.base_url + "/admin")
    expect_admin_ready(page, settings)
    page.locator("#alerts-link").click()
    page.locator("#admin-create-condition-rule-btn").click()
    page.locator("#condition-rule-name").fill(name)
    page.locator("#condition-rule-webhook").uncheck()
    page.locator("#condition-rule-enabled").uncheck()
    page.locator("#condition-rows .cond-field").select_option("node_id")
    page.locator("#condition-rows .cond-op").select_option("eq")
    page.locator("#condition-rows .cond-val").fill("synthetic-never-matches")
    with page.expect_response(
        lambda response: urlsplit(response.url).path == "/api/alerts/rules/conditions"
        and response.request.method == "POST"
    ) as pending:
        page.locator("#condition-rule-save-btn").click()
    assert pending.value.status == 201
    rule = pending.value.json()
    try:
        expect(page.locator("#condition-rules-tbody")).to_contain_text(name)
        persisted = admin_api.request(
            "GET", f"/api/alerts/rules/conditions/{rule['rule_id']}"
        )
        assert persisted["name"] == html.escape(name) and persisted["enabled"] is False
        page.locator(f'[data-edit-crule="{rule["rule_id"]}"]').click()
        expect(page.locator("#condition-rule-name")).to_have_value(name)
        # Changing another field must not re-encode the unchanged visible name.
        updated_name = name
        page.locator("#condition-rule-cooldown").fill("42")
        with page.expect_response(
            lambda response: urlsplit(response.url).path
            == f"/api/alerts/rules/conditions/{rule['rule_id']}"
            and response.request.method == "PUT"
        ) as update:
            page.locator("#condition-rule-save-btn").click()
        assert update.value.status == 200
        expect(page.locator("#condition-rules-tbody")).to_contain_text(updated_name)
        persisted = admin_api.request(
            "GET", f"/api/alerts/rules/conditions/{rule['rule_id']}"
        )
        assert persisted["name"] == html.escape(updated_name)
        assert persisted["cooldown_seconds"] == 42
        assert persisted["enabled"] is False
        # A success response alone did not catch edits made to detached
        # persistence copies. A new document must read the stored change.
        page.reload()
        expect_admin_ready(page, settings)
        page.locator("#alerts-link").click()
        expect(page.locator("#condition-rules-tbody")).to_contain_text(updated_name)
        page.locator(f'[data-edit-crule="{rule["rule_id"]}"]').click()
        expect(page.locator("#condition-rule-name")).to_have_value(name)
        # Preserve the original name-change persistence regression as well as
        # the unchanged-name encoding round trip above.
        updated_name = name + "-edited"
        page.locator("#condition-rule-name").fill(updated_name)
        with page.expect_response(
            lambda response: urlsplit(response.url).path
            == f"/api/alerts/rules/conditions/{rule['rule_id']}"
            and response.request.method == "PUT"
        ) as renamed:
            page.locator("#condition-rule-save-btn").click()
        assert renamed.value.status == 200
        persisted = admin_api.request(
            "GET", f"/api/alerts/rules/conditions/{rule['rule_id']}"
        )
        assert persisted["name"] == html.escape(updated_name)
        assert persisted["cooldown_seconds"] == 42
        assert persisted["enabled"] is False
        page.reload()
        expect_admin_ready(page, settings)
        page.locator("#alerts-link").click()
        expect(page.locator("#condition-rules-tbody")).to_contain_text(updated_name)
        page.locator(f'[data-edit-crule="{rule["rule_id"]}"]').click()
        expect(page.locator("#condition-rule-name")).to_have_value(updated_name)
        expect(page.locator('[onerror*="__alertTextExecuted"]')).to_have_count(0)
        assert page.evaluate("window.__alertTextExecuted || 0") == 0
        # The dashboard's second editor must show the same plain text, too.
        navigate(page, settings.base_url + "/dashboard")
        page.locator('[data-tab="summary"]').click()
        page.locator(f'[data-cr-edit="{rule["rule_id"]}"]').click()
        expect(page.locator("#cb-rule-name")).to_have_value(updated_name)
        expect(page.locator("#cb-title")).to_have_text("Edit Rule: " + updated_name)
        expect(page.locator('[onerror*="__alertTextExecuted"]')).to_have_count(0)
        assert page.evaluate("window.__alertTextExecuted || 0") == 0
    finally:
        admin_api.request("DELETE", f"/api/alerts/rules/conditions/{rule['rule_id']}")
