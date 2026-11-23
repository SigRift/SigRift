"""Auth boundary and edge case tests.

Tests expired sessions, tampered tokens, malformed auth headers,
rate limiter boundaries, API key role enforcement, and concurrent
auth requests.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
    expires_at: str | None = None,
) -> str:
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict[str, Any] = {"role": role}
    if expires_at is not None:
        meta["expires_at"] = expires_at
    persistence.set_key_meta(key_id, meta)
    return raw_key


def _create_user_and_login(
    client: TestClient,
    detection_store: DetectionStore,
    username: str = "edgeuser",
    password: str = "EdgePass123!",
    role: str = "viewer",
) -> tuple[str, dict]:
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


@pytest.fixture
def unauth_client(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "auth_viewer_key", role="viewer")


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "auth_sensor_key", role="sensor")


# ---------------------------------------------------------------------------
# Empty and malformed auth headers
# ---------------------------------------------------------------------------


class TestMalformedAuthHeaders:
    """Tests for empty, missing, and malformed authentication headers."""

    def test_empty_api_key_header(self, bridge_app: FastAPI):
        """Empty X-API-Key header returns 401."""
        tc = TestClient(bridge_app, headers={"X-API-Key": ""})
        resp = tc.get("/api/health")
        # Health endpoint may not require auth; try a protected endpoint
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_no_auth_header(self, unauth_client: TestClient):
        """Request with no auth at all returns 401 on protected endpoints."""
        resp = unauth_client.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_bearer_token_empty(self, bridge_app: FastAPI):
        """Authorization: Bearer (empty) returns 401."""
        tc = TestClient(bridge_app, headers={"Authorization": "Bearer "})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_bearer_token_garbage(self, bridge_app: FastAPI):
        """Authorization: Bearer with random garbage returns 401."""
        tc = TestClient(bridge_app, headers={"Authorization": "Bearer AAAA_not_a_real_token"})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_malformed_bearer_prefix(self, bridge_app: FastAPI):
        """Authorization header without Bearer prefix returns 401."""
        tc = TestClient(bridge_app, headers={"Authorization": "Basic dXNlcjpwYXNz"})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_api_key_with_special_chars(self, bridge_app: FastAPI):
        """API key with special characters returns 401 (not a crash)."""
        tc = TestClient(bridge_app, headers={"X-API-Key": "key!@#$%^&*()\x00\n\r\t"})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Expired session token access
# ---------------------------------------------------------------------------


class TestExpiredSession:
    """Tests for accessing endpoints with expired or invalidated sessions."""

    def test_logged_out_session_rejected(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """After logout, session token is no longer valid."""
        token, _ = _create_user_and_login(client, detection_store, username="logout_user")
        session_client = TestClient(
            client.app,
            headers={"Authorization": f"Bearer {token}"},
        )
        # Should work before logout
        resp = session_client.get("/api/detections/recent")
        assert resp.status_code == 200

        # Logout
        resp = session_client.post("/api/auth/logout")
        assert resp.status_code == 200

        # Should be rejected after logout
        resp = session_client.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_tampered_session_token(self, client: TestClient, detection_store: DetectionStore):
        """Session token with tampered payload is rejected."""
        token, _ = _create_user_and_login(client, detection_store, username="tamper_user")
        # Tamper with the token
        tampered = token[:-4] + "XXXX"
        tc = TestClient(client.app, headers={"Authorization": f"Bearer {tampered}"})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401

    def test_completely_fake_session_token(self, bridge_app: FastAPI):
        """A fabricated session token is rejected."""
        tc = TestClient(
            bridge_app,
            headers={"Authorization": "Bearer fake-session-token-000000"},
        )
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API key role enforcement
# ---------------------------------------------------------------------------


class TestAPIKeyRoleEnforcement:
    """Tests for role-based access control with API keys."""

    def test_sensor_key_cannot_read_detections(
        self, bridge_app: FastAPI, sensor_key: str,
    ):
        """Sensor-role key cannot access viewer endpoints (detections list)."""
        tc = TestClient(bridge_app, headers={"X-API-Key": sensor_key})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 403

    def test_viewer_key_cannot_access_admin(
        self, bridge_app: FastAPI, viewer_key: str,
    ):
        """Viewer-role key cannot access admin endpoints."""
        tc = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
        resp = tc.get("/api/admin/keys")
        assert resp.status_code == 403

    def test_expired_api_key_rejected(self, bridge_app: FastAPI, persistence: PersistenceManager):
        """API key with past expiration date is rejected."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        raw_key = _make_key_and_store(persistence, "expired_key", role="admin", expires_at=past)
        tc = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Login rate limiter
# ---------------------------------------------------------------------------


class TestLoginRateLimiter:
    """Tests for the login rate limiter boundary conditions."""

    def test_rate_limit_at_exact_threshold(self, client: TestClient, detection_store: DetectionStore):
        """After exactly RATE_LIMIT_MAX logins, the next attempt returns 429."""
        from sigrift.bridge.storage.security_state import SecurityStateStore

        rate_max = SecurityStateStore.RATE_LIMIT_MAX
        plain = TestClient(client.app)
        for i in range(rate_max):
            resp = plain.post("/api/auth/login", json={
                "username": "nonexistent",
                "password": "wrong",
            })
            # Should be 401 (bad credentials), not 429 yet
            assert resp.status_code == 401, f"Request {i+1} got {resp.status_code}"

        # Next request should hit the rate limit
        resp = plain.post("/api/auth/login", json={
            "username": "nonexistent",
            "password": "wrong",
        })
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_rate_limit_includes_successful_logins(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """Rate limiter counts all attempts including successful ones."""
        from sigrift.bridge.storage.security_state import SecurityStateStore

        rate_max = SecurityStateStore.RATE_LIMIT_MAX
        detection_store.create_user(
            username="ratelimit_user", password="RateLimit1!", role="viewer",
        )
        plain = TestClient(client.app)

        # Make RATE_LIMIT_MAX attempts (mix of success and failure)
        for i in range(rate_max):
            resp = plain.post("/api/auth/login", json={
                "username": "ratelimit_user",
                "password": "RateLimit1!",
            })
            assert resp.status_code == 200

        # Next attempt should be rate-limited
        resp = plain.post("/api/auth/login", json={
            "username": "ratelimit_user",
            "password": "RateLimit1!",
        })
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Concurrent auth requests
# ---------------------------------------------------------------------------


class TestConcurrentAuth:
    """Tests for concurrent authentication requests."""

    def test_multiple_sessions_same_user(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """Multiple valid sessions for the same user can coexist."""
        detection_store.create_user(
            username="multi_session", password="MultiPass1!", role="viewer",
        )
        plain = TestClient(client.app)

        tokens = []
        for _ in range(3):
            resp = plain.post("/api/auth/login", json={
                "username": "multi_session",
                "password": "MultiPass1!",
            })
            assert resp.status_code == 200
            tokens.append(resp.json()["session_token"])

        # All sessions should work
        for token in tokens:
            tc = TestClient(client.app, headers={"Authorization": f"Bearer {token}"})
            resp = tc.get("/api/detections/recent")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# X-Session-Token header auth
# ---------------------------------------------------------------------------


class TestSessionTokenHeaders:
    """Tests for session token authentication via different header formats."""

    def test_x_session_token_header(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """X-Session-Token header is accepted for auth."""
        token, _ = _create_user_and_login(
            client, detection_store, username="header_user",
        )
        tc = TestClient(client.app, headers={"X-Session-Token": token})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 200

    def test_empty_x_session_token_header(self, bridge_app: FastAPI):
        """Empty X-Session-Token falls through to 401."""
        tc = TestClient(bridge_app, headers={"X-Session-Token": ""})
        resp = tc.get("/api/detections/recent")
        assert resp.status_code == 401
