"""Session binding against actual SQLite sessions and real HTTP request objects."""

import os
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from sigrift.bridge.dependencies import Role, _extract_session_token, _try_session_auth
from sigrift.bridge.detection_store import DetectionStore


def request_for(
    store=None, *, ip="1.2.3.4", ua="TestBrowser/1.0", token=None, cookie=None
):
    app = FastAPI()
    app.state.detection_store = store
    headers = [(b"user-agent", ua.encode())]
    if token is not None:
        headers.append((b"authorization", ("Bearer " + token).encode()))
    if cookie is not None:
        headers.append((b"cookie", ("session_token=" + cookie).encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/auth/me",
            "scheme": "http",
            "query_string": b"",
            "headers": headers,
            "client": (ip, 12345),
            "server": ("testserver", 80),
            "app": app,
        }
    )


@pytest.fixture
def binding_request(tmp_path):
    store = DetectionStore(tmp_path / "sessions.db")
    try:
        store.create_user("testuser", "fixture-password-long", role="admin")
        user = store.get_user("testuser")

        def make(
            *,
            ip="1.2.3.4",
            ua="TestBrowser/1.0",
            session_ip="1.2.3.4",
            session_ua="TestBrowser/1.0",
            missing=False,
        ):
            token = (
                "nonexistent-session"
                if missing
                else store.create_session(
                    user["id"],
                    ip_address=session_ip,
                    user_agent=session_ua,
                )["session_token"]
            )
            return request_for(store, ip=ip, ua=ua, token=token)

        yield make
    finally:
        store.close()


def test_session_binding_warn_mode_allows_ip_mismatch(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "warn")
    username, role = _try_session_auth(binding_request(ip="5.6.7.8"))
    assert username == "testuser"
    assert role == Role.ADMIN


def test_session_binding_strict_rejects_ip_mismatch(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "strict")
    assert _try_session_auth(binding_request(ip="5.6.7.8")) == (None, None)


def test_session_binding_strict_rejects_ua_mismatch(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "strict")
    assert _try_session_auth(binding_request(ua="DifferentBrowser/2.0")) == (None, None)


def test_session_binding_ip_mode_rejects_ip_mismatch(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "ip")
    assert _try_session_auth(
        binding_request(ip="5.6.7.8", ua="DifferentBrowser/2.0")
    ) == (None, None)


def test_session_binding_ip_mode_allows_ua_mismatch(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "ip")
    assert _try_session_auth(binding_request(ua="DifferentBrowser/2.0")) == (
        "testuser",
        Role.ADMIN,
    )


def test_session_binding_none_mode_allows_everything(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "none")
    assert _try_session_auth(
        binding_request(ip="5.6.7.8", ua="DifferentBrowser/2.0")
    ) == ("testuser", Role.ADMIN)


def test_session_binding_matching_ip_ua_always_passes(binding_request, monkeypatch):
    for mode in ("strict", "ip", "warn", "none"):
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", mode)
        assert _try_session_auth(binding_request()) == ("testuser", Role.ADMIN), mode


def test_session_binding_default_mode_is_ip(binding_request, monkeypatch):
    monkeypatch.delenv("BRIDGE_SESSION_BINDING", raising=False)
    assert _try_session_auth(binding_request(ip="5.6.7.8")) == (None, None)


def test_session_binding_missing_ip_in_session(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "strict")
    assert _try_session_auth(binding_request(ip="5.6.7.8", session_ip="")) == (
        "testuser",
        Role.ADMIN,
    )


def test_session_binding_missing_ua_in_session(binding_request, monkeypatch):
    monkeypatch.setenv("BRIDGE_SESSION_BINDING", "strict")
    assert _try_session_auth(
        binding_request(ua="DifferentBrowser/2.0", session_ua="")
    ) == ("testuser", Role.ADMIN)


def test_session_not_found_returns_none(binding_request):
    assert _try_session_auth(binding_request(missing=True)) == (None, None)


def test_session_cookie_extraction():
    assert (
        _extract_session_token(request_for(cookie="cookie-tok-456")) == "cookie-tok-456"
    )


def test_session_bearer_takes_precedence_over_cookie():
    assert (
        _extract_session_token(request_for(token="header-tok", cookie="cookie-tok"))
        == "header-tok"
    )


# ---------------------------------------------------------------------------
# Integration: login -> use with binding
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    from sigrift.bridge.routers.auth import _login_attempts

    _login_attempts.clear()
    yield
    _login_attempts.clear()


class TestSessionBindingIntegration:
    """Full login -> use-from-different-context flow through the real app."""

    def test_strict_binding_rejects_different_ua(
        self,
        client: TestClient,
        detection_store,
    ):
        """Login with one UA, then use session with another UA under strict mode — rejected."""
        detection_store.create_user(
            username="bindtest",
            password="BindTest123!",
            role="viewer",
        )
        plain = TestClient(client.app)

        # Login with UA-1
        resp = plain.post(
            "/api/auth/login",
            json={"username": "bindtest", "password": "BindTest123!"},
            headers={"User-Agent": "Browser/1.0"},
        )
        assert resp.status_code == 200
        token = resp.json()["session_token"]

        # Use session with UA-2 under strict binding
        with patch.dict(os.environ, {"BRIDGE_SESSION_BINDING": "strict"}):
            resp = plain.get(
                "/api/auth/me",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "DifferentBrowser/2.0",
                },
            )
        assert resp.status_code == 401

    def test_warn_binding_allows_different_ua(
        self,
        client: TestClient,
        detection_store,
    ):
        """Login with one UA, use with another under warn mode — allowed."""
        detection_store.create_user(
            username="warntest",
            password="WarnTest123!",
            role="viewer",
        )
        plain = TestClient(client.app)

        resp = plain.post(
            "/api/auth/login",
            json={"username": "warntest", "password": "WarnTest123!"},
            headers={"User-Agent": "Browser/1.0"},
        )
        assert resp.status_code == 200
        token = resp.json()["session_token"]

        with patch.dict(os.environ, {"BRIDGE_SESSION_BINDING": "warn"}):
            resp = plain.get(
                "/api/auth/me",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "DifferentBrowser/2.0",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["username"] == "warntest"

    def test_none_binding_allows_everything(
        self,
        client: TestClient,
        detection_store,
    ):
        """Under 'none' mode, any context switch is allowed."""
        detection_store.create_user(
            username="nonetest",
            password="NoneTest123!",
            role="analyst",
        )
        plain = TestClient(client.app)

        resp = plain.post(
            "/api/auth/login",
            json={"username": "nonetest", "password": "NoneTest123!"},
            headers={"User-Agent": "Original/1.0"},
        )
        assert resp.status_code == 200
        token = resp.json()["session_token"]

        with patch.dict(os.environ, {"BRIDGE_SESSION_BINDING": "none"}):
            resp = plain.get(
                "/api/auth/me",
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "Completely/Different",
                },
            )
        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"

    def test_session_cookie_auth_through_real_app(
        self,
        client: TestClient,
        detection_store,
    ):
        """Session token passed via cookie (OIDC-style) works through the full stack."""
        detection_store.create_user(
            username="cookieuser",
            password="CookieTest123!",
            role="viewer",
        )
        plain = TestClient(client.app)

        resp = plain.post(
            "/api/auth/login",
            json={"username": "cookieuser", "password": "CookieTest123!"},
        )
        assert resp.status_code == 200
        token = resp.json()["session_token"]

        # Use cookie instead of Bearer header
        with patch.dict(os.environ, {"BRIDGE_SESSION_BINDING": "none"}):
            plain.cookies.set("session_token", token)
            resp = plain.get("/api/auth/me")
        assert resp.status_code == 200
        assert resp.json()["username"] == "cookieuser"
