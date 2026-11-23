"""Exercise the shipped login controller against real MFA API handlers."""

import secrets
from urllib.parse import urlsplit

import pytest

from .conftest import Client, browser_login, expect, expect_dashboard, totp


@pytest.mark.disposable
def test_browser_mfa_totp_and_backup_code_login(page, settings, admin_api, disposable):
    username = "e2e_mfa_" + secrets.token_hex(5)
    password = "E2E-" + secrets.token_urlsafe(24) + "9!"
    admin_api.request(
        "POST",
        "/api/admin/users",
        {"username": username, "password": password, "role": "analyst"},
        status=201,
    )
    try:
        user = Client(settings)
        user.login(username, password)
        assert user.has_session(), "New user did not get a session"
        setup = user.request("POST", "/api/auth/mfa/setup", {})
        user.request(
            "POST", "/api/auth/mfa/verify-setup", {"totp_code": totp(setup["secret"])}
        )
        user.request("POST", "/api/auth/logout", {})
        for method in ("totp", "backup"):
            page.context.clear_cookies()
            challenge = browser_login(
                page, settings, username=username, password=password, expect_mfa=True
            )
            assert bool(challenge.get("mfa_required") and challenge.get("mfa_token")), (
                "MFA challenge missing"
            )
            expect(page.locator("#mfa-code")).to_be_visible()
            assert page.request.get(settings.base_url + "/api/auth/me").status == 401
            # Compute after login: its bounded cooldown can outlast a TOTP.
            code = (
                totp(setup["secret"]) if method == "totp" else setup["backup_codes"][0]
            )
            page.locator("#mfa-code").fill(code)
            with page.expect_response(
                lambda response: urlsplit(response.url).path == "/api/auth/mfa/verify"
            ) as pending:
                page.locator("#mfa-submit").click()
            assert pending.value.status == 200
            expect_dashboard(page)
            me = page.request.get(settings.base_url + "/api/auth/me")
            assert me.status == 200 and me.json()["username"] == username
            assert any(
                cookie["name"] == "session_token" and cookie["httpOnly"]
                for cookie in page.context.cookies()
            )
    finally:
        admin_api.request("DELETE", f"/api/admin/users/{username}")
