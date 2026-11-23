"""Integration tests for the authentication landing page.

Tests that:
  - GET /login serves the login page
  - GET / serves index.html with auth guard (no auth overlay)
  - GET /admin serves admin.html with auth guard (no admin-auth-prompt)
  - Login page contains expected elements (form, tabs, branding)
  - Dashboard page has app-content wrapper hidden by default
  - Auth overlay is fully removed from index.html
  - Admin auth prompt is fully removed from admin.html
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def page_client() -> TestClient:
    """TestClient using the real app (with templates/static mounted)."""
    from sigrift.bridge.app import app
    return TestClient(app)


class TestLoginPage:
    """Tests for GET /login."""

    def test_login_returns_200(self, page_client: TestClient):
        r = page_client.get("/login")
        assert r.status_code == 200

    def test_login_is_html(self, page_client: TestClient):
        r = page_client.get("/login")
        assert "text/html" in r.headers.get("content-type", "")

    def test_login_has_branding(self, page_client: TestClient):
        html = page_client.get("/login").text
        assert "The Bridge" in html
        assert "login-logo" in html

    def test_login_has_username_password_form(self, page_client: TestClient):
        html = page_client.get("/login").text
        assert 'id="username"' in html
        assert 'id="password"' in html
        assert 'id="login-submit"' in html

    def test_login_has_apikey_tab(self, page_client: TestClient):
        html = page_client.get("/login").text
        assert 'data-tab="apikey"' in html
        assert 'id="apikey"' in html

    def test_login_has_mfa_section(self, page_client: TestClient):
        html = page_client.get("/login").text
        assert 'id="mfa-section"' in html
        assert 'id="mfa-code"' in html

    def test_login_js_posts_to_auth_endpoint(self, page_client: TestClient):
        r = page_client.get("/static/login.js")
        assert r.status_code == 200
        assert "/api/auth/login" in r.text

    def test_login_uses_external_script(self, page_client: TestClient):
        """Login page should use external login.js for CSP compliance."""
        html = page_client.get("/login").text
        assert "login.js" in html

    def test_login_has_no_external_css(self, page_client: TestClient):
        """Login page should be self-contained with inline styles."""
        html = page_client.get("/login").text
        assert 'rel="stylesheet"' not in html
        assert "<style>" in html


class TestDashboardAuthGuard:
    """Tests for GET /dashboard — dashboard should have auth guard, no overlay."""

    def test_root_redirects_to_login(self, page_client: TestClient):
        r = page_client.get("/", follow_redirects=False)
        assert r.status_code in (301, 302, 307)
        assert "/login" in r.headers.get("location", "")

    def test_dashboard_returns_200(self, page_client: TestClient):
        r = page_client.get("/dashboard")
        assert r.status_code == 200

    def test_dashboard_has_auth_guard_script(self, page_client: TestClient):
        html = page_client.get("/dashboard").text
        assert "auth_guard.js" in html

    def test_dashboard_has_app_content_wrapper(self, page_client: TestClient):
        html = page_client.get("/dashboard").text
        assert 'id="app-content"' in html
        assert 'style="display:none"' in html

    def test_dashboard_no_auth_overlay(self, page_client: TestClient):
        """The old auth-overlay modal must be completely removed."""
        html = page_client.get("/dashboard").text
        assert "auth-overlay" not in html

    def test_dashboard_no_auth_input_fields(self, page_client: TestClient):
        """Old inline auth inputs must be removed from dashboard."""
        html = page_client.get("/dashboard").text
        assert "auth-username-input" not in html
        assert "auth-password-input" not in html
        assert "auth-key-input" not in html

    def test_dashboard_no_auth_submit_button(self, page_client: TestClient):
        """Old auth-submit button must be removed."""
        html = page_client.get("/dashboard").text
        assert 'id="auth-submit"' not in html

    def test_dashboard_keeps_logout_button(self, page_client: TestClient):
        html = page_client.get("/dashboard").text
        assert "logout-btn" in html


class TestAdminAuthGuard:
    """Tests for GET /admin — admin should have auth guard, no inline prompt."""

    def test_admin_returns_200(self, page_client: TestClient):
        r = page_client.get("/admin")
        assert r.status_code == 200

    def test_admin_has_auth_guard_script(self, page_client: TestClient):
        html = page_client.get("/admin").text
        assert "auth_guard.js" in html

    def test_admin_has_app_content_wrapper(self, page_client: TestClient):
        html = page_client.get("/admin").text
        assert 'id="app-content"' in html

    def test_admin_no_auth_prompt(self, page_client: TestClient):
        """The old admin-auth-prompt div must be removed."""
        html = page_client.get("/admin").text
        assert "admin-auth-prompt" not in html

    def test_admin_no_master_key_input(self, page_client: TestClient):
        """Old admin-key-input must be removed."""
        html = page_client.get("/admin").text
        assert "admin-key-input" not in html
        assert "admin-auth-btn" not in html

    def test_admin_panels_visible_by_default(self, page_client: TestClient):
        """Admin panels should not be hidden with display:none."""
        html = page_client.get("/admin").text
        # The panels div should exist without display:none
        assert 'id="admin-panels"' in html
        # Should NOT have the old style="display:none"
        idx = html.index('id="admin-panels"')
        # Check that the tag containing admin-panels doesn't have display:none
        tag_start = html.rfind("<", 0, idx)
        tag_end = html.index(">", idx)
        tag = html[tag_start:tag_end + 1]
        assert "display:none" not in tag
