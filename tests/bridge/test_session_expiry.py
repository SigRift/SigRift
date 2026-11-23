"""Tests for Sprint 8 session expiry warning headers.

Verifies that:
  - Session-authenticated requests include X-Session-Expires-In header
  - X-Session-Warning header appears when session is close to expiry (<300s)
  - API key requests do NOT include session expiry headers
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_user_and_login(
    client: TestClient,
    detection_store: DetectionStore,
    username: str = "expiryuser",
    password: str = "ExpiryPass1!",
    role: str = "viewer",
) -> tuple[str, dict]:
    """Create a user, login, and return (session_token, login_response)."""
    detection_store.create_user(
        username=username,
        password=password,
        role=role,
    )
    plain = TestClient(client.app)
    resp = plain.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    data = resp.json()
    return data["session_token"], data


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_login_limiter():
    """Clear the login rate limiter before each test."""
    from sigrift.bridge.routers.auth import _login_attempts
    _login_attempts.clear()
    yield
    _login_attempts.clear()


# ---------------------------------------------------------------------------
# Session expiry headers
# ---------------------------------------------------------------------------


class TestSessionExpiryHeaders:
    """X-Session-Expires-In and X-Session-Warning on session-authenticated requests."""

    def test_session_request_includes_expires_in_header(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Session-authenticated request includes X-Session-Expires-In header."""
        token, _ = _create_user_and_login(
            client, detection_store, "expiry1", "ExpiryOne1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert "x-session-expires-in" in resp.headers
        remaining = int(resp.headers["x-session-expires-in"])
        # A freshly-created session should have substantial time remaining
        assert remaining > 0

    def test_no_warning_header_when_session_not_near_expiry(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """X-Session-Warning is absent when session has plenty of time left."""
        token, _ = _create_user_and_login(
            client, detection_store, "expiry2", "ExpiryTwo1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        # Fresh session should not be expiring soon
        remaining = int(resp.headers["x-session-expires-in"])
        assert remaining >= 300
        assert "x-session-warning" not in resp.headers

    def test_warning_header_when_session_near_expiry(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """X-Session-Warning is 'expiring-soon' when <300s remain."""
        detection_store.create_user(
            username="expiry3", password="ExpiryThree1!", role="viewer",
        )
        user = detection_store.users.get_user_full("expiry3")
        session = detection_store.create_session(user_id=user["id"])

        # Set the session to expire in 60 seconds (use hashed token for DB)
        import hashlib
        conn = detection_store.get_connection()
        soon = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()
        hashed = hashlib.sha256(session["session_token"].encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [soon, hashed],
        )
        conn.commit()

        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {session['session_token']}"},
        )
        assert resp.status_code == 200
        assert "x-session-expires-in" in resp.headers
        remaining = int(resp.headers["x-session-expires-in"])
        assert remaining <= 60
        assert resp.headers.get("x-session-warning") == "expiring-soon"

    def test_expires_in_is_zero_when_just_expired(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """X-Session-Expires-In is 0 when session has just expired.

        Note: the session may still be returned by get_session if the expiry
        check is in the header logic rather than get_session. If the session
        is outright rejected (401), that's also acceptable.
        """
        detection_store.create_user(
            username="expiry4", password="ExpiryFour1!", role="viewer",
        )
        user = detection_store.users.get_user_full("expiry4")
        session = detection_store.create_session(user_id=user["id"])

        # Set the session to have just expired (1 second ago)
        import hashlib
        conn = detection_store.get_connection()
        past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        hashed = hashlib.sha256(session["session_token"].encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [past, hashed],
        )
        conn.commit()

        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {session['session_token']}"},
        )
        # Either the session is rejected (401) or it's accepted with 0 remaining
        if resp.status_code == 200:
            assert resp.headers.get("x-session-expires-in") == "0"
            assert resp.headers.get("x-session-warning") == "expiring-soon"
        else:
            assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API key requests should NOT have session expiry headers
# ---------------------------------------------------------------------------


class TestAPIKeyNoExpiryHeaders:
    """API key authenticated requests must not include session expiry headers."""

    def test_api_key_request_no_expires_in_header(
        self, client: TestClient,
    ) -> None:
        """X-Session-Expires-In is absent on API key-authenticated requests."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "x-session-expires-in" not in resp.headers

    def test_api_key_request_no_warning_header(
        self, client: TestClient,
    ) -> None:
        """X-Session-Warning is absent on API key-authenticated requests."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "x-session-warning" not in resp.headers

    def test_api_key_via_query_param_no_expiry_headers(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """API key via ?api_key= query param also lacks session expiry headers."""
        plain = TestClient(bridge_app)
        resp = plain.get(f"/api/health?api_key={master_key}")
        assert resp.status_code == 200
        assert "x-session-expires-in" not in resp.headers
        assert "x-session-warning" not in resp.headers


# ---------------------------------------------------------------------------
# Dual auth: session headers only on session auth path
# ---------------------------------------------------------------------------


class TestDualAuthExpiryHeaders:
    """When both session and API key are present, session wins and headers appear."""

    def test_session_wins_with_expiry_headers(
        self, client: TestClient, detection_store: DetectionStore,
        master_key: str,
    ) -> None:
        """When session token AND API key are both provided, session auth wins
        and expiry headers are present."""
        token, _ = _create_user_and_login(
            client, detection_store, "dual1", "DualAuth1!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={
                "Authorization": f"Bearer {token}",
                "X-API-Key": master_key,
            },
        )
        assert resp.status_code == 200
        # Session auth won, so expiry headers should be present
        assert "x-session-expires-in" in resp.headers
