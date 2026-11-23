"""Comprehensive integration tests for the dual auth system (API keys + session tokens).

Covers the ENTIRE auth surface of The Bridge:
  - Session lifecycle: login -> use -> logout -> verify invalid
  - Session expiration and cleanup
  - Multiple concurrent sessions
  - Dual auth compatibility (same endpoint, both auth methods)
  - RBAC enforcement consistency between API key and session auth
  - WebSocket auth with API keys and session tokens
  - Admin endpoints via session tokens (require_master_key)
  - Edge cases: empty headers, malformed tokens, dual auth, revoked sessions
  - Query parameter auth (?api_key=) with session tokens

Auth Matrix:
  - require_api_key: accepts API key (X-API-Key header / ?api_key query) + session token
  - require_role(min_role): delegates to require_api_key, then checks role
  - require_master_key: delegates to require_api_key, then checks role >= ADMIN
  - require_ws_auth: accepts API key (Sec-WebSocket-Protocol) + session token fallback
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

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
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict = {"role": role}
    if expires_at is not None:
        meta["expires_at"] = expires_at
    persistence.set_key_meta(key_id, meta)
    return raw_key


def _create_user_and_login(
    client: TestClient,
    detection_store: DetectionStore,
    username: str = "testuser",
    password: str = "TestPass123!",
    role: str = "viewer",
) -> tuple[str, dict[str, Any]]:
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


@pytest.fixture
def plain_client(bridge_app: FastAPI) -> TestClient:
    """TestClient with NO auth headers (for testing unauthenticated flows)."""
    return TestClient(bridge_app)


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "viewer_key", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_key", role="analyst")


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "sensor_key", role="sensor")


# ===========================================================================
# 1. SESSION LIFECYCLE
# ===========================================================================


class TestSessionLifecycle:
    """Login -> get token -> use for API -> logout -> verify token invalid."""

    def test_full_lifecycle(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Complete login -> use -> logout -> reject flow."""
        token, data = _create_user_and_login(
            client, detection_store, "lifecycle", "LifePass123!", "analyst",
        )
        assert isinstance(token, str) and len(token) >= 32
        assert data["user"]["username"] == "lifecycle"
        assert data["user"]["role"] == "analyst"
        assert isinstance(data["expires_at"], str) and "T" in data["expires_at"]

        plain = TestClient(client.app)

        # Use session token to access endpoint
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["auth_type"] == "session"
        assert resp.json()["username"] == "lifecycle"

        # Logout
        resp = plain.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Token should now be invalid
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_login_wrong_password(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        detection_store.create_user(
            username="wrongpw", password="RightPass123!", role="viewer",
        )
        plain = TestClient(client.app)
        resp = plain.post(
            "/api/auth/login",
            json={"username": "wrongpw", "password": "WrongPass123!"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, plain_client: TestClient) -> None:
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "ghost", "password": "NoUser123!"},
        )
        assert resp.status_code == 401

    def test_multiple_concurrent_sessions(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Multiple logins for the same user create distinct valid sessions."""
        detection_store.create_user(
            username="multi", password="MultiPass123!", role="viewer",
        )
        plain = TestClient(client.app)

        tokens = []
        for _ in range(3):
            resp = plain.post(
                "/api/auth/login",
                json={"username": "multi", "password": "MultiPass123!"},
            )
            assert resp.status_code == 200
            tokens.append(resp.json()["session_token"])

        # All tokens should be unique
        assert len(set(tokens)) == 3

        # All tokens should be valid
        for tok in tokens:
            resp = plain.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {tok}"},
            )
            assert resp.status_code == 200
            assert resp.json()["username"] == "multi"

        # Logout one - others still valid
        plain.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )
        assert resp.status_code == 401

        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {tokens[1]}"},
        )
        assert resp.status_code == 200

    def test_session_expiration(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Expired sessions are rejected."""
        detection_store.create_user(
            username="expuser", password="ExpirePass1!", role="viewer",
        )
        user = detection_store.users.get_user_full("expuser")
        session = detection_store.create_session(user_id=user["id"])

        # Manually expire the session (use hashed token for DB update)
        import hashlib
        conn = detection_store.get_connection()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        hashed = hashlib.sha256(session["session_token"].encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [past, hashed],
        )
        conn.commit()

        plain = TestClient(client.app)
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {session['session_token']}"},
        )
        assert resp.status_code == 401

    def test_session_token_format_validation(
        self, plain_client: TestClient,
    ) -> None:
        """Random garbage as session token is rejected."""
        resp = plain_client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer not-a-valid-token-at-all"},
        )
        assert resp.status_code == 401

    def test_disabled_user_session_rejected(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Session for a disabled user should be rejected."""
        token, _ = _create_user_and_login(
            client, detection_store, "todisable", "DisablePass1!", "viewer",
        )
        plain = TestClient(client.app)

        # Session works before disable
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Disable the user
        detection_store.disable_user("todisable")

        # Session should now be rejected
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_login_survives_an_absurd_absolute_timeout(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An absolute timeout past year 9999 falls back to 24 hours.

        It used to overflow the expiry date in create_session, so every
        login answered 500.
        """
        monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", "70000000")
        token, data = _create_user_and_login(
            client, detection_store, "longlife", "LongLife123!", "viewer",
        )
        lifetime = datetime.fromisoformat(data["expires_at"]) - datetime.now(
            timezone.utc
        )
        assert timedelta(hours=23) < lifetime <= timedelta(hours=24)

        plain = TestClient(client.app)
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    @pytest.mark.parametrize(
        "damaged", ["not-a-timestamp", "", " ", "2099-13-45T99:99:99+00:00"]
    )
    def test_idle_session_is_not_revived_by_a_damaged_last_active(
        self, client: TestClient, detection_store: DetectionStore, damaged: str,
    ) -> None:
        """An idle session stays refused after its last_active is damaged.

        An unreadable last_active used to skip the idle check, and the touch
        then reset it to now, so the session was accepted again.
        """
        import hashlib

        token, _ = _create_user_and_login(
            client, detection_store, "idleuser", "IdlePass123!", "viewer",
        )
        hashed = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn = detection_store.get_connection()
        idle = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        conn.execute(
            "UPDATE sessions SET last_active = ? WHERE session_token = ?",
            [idle, hashed],
        )
        conn.execute(
            "UPDATE sessions SET last_active = ? WHERE session_token = ?",
            [damaged, hashed],
        )
        conn.commit()

        plain = TestClient(client.app)
        for _ in range(2):
            resp = plain.get(
                "/api/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 401
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE session_token = ?", [hashed]
        ).fetchone()
        assert row is None


# ===========================================================================
# 2. DUAL AUTH COMPATIBILITY
# ===========================================================================


class TestDualAuthCompatibility:
    """Verify the same endpoints work with both API key and session token."""

    def test_health_with_api_key(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_with_session_token(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "healthuser", "HealthPass1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_detections_stats_with_api_key(self, client: TestClient) -> None:
        resp = client.get("/api/detections/stats")
        assert resp.status_code == 200

    def test_detections_stats_with_session_token(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "statsuser", "StatsPass1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/detections/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_anomalies_with_api_key(self, client: TestClient) -> None:
        resp = client.get("/api/detections/anomalies")
        assert resp.status_code == 200

    def test_anomalies_with_session_token(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "anomuser", "AnomPass1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/detections/anomalies",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_auth_me_api_key_reports_api_key_type(
        self, client: TestClient,
    ) -> None:
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "api_key"
        assert data["key_id"] == "master"

    def test_auth_me_session_reports_session_type(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "meuser", "MePass1234!", "analyst",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "session"
        assert data["username"] == "meuser"
        assert data["role"] == "analyst"

    def test_mixed_requests_in_sequence(
        self, client: TestClient, detection_store: DetectionStore,
        master_key: str,
    ) -> None:
        """Alternate between API key and session token requests."""
        token, _ = _create_user_and_login(
            client, detection_store, "mixuser", "MixPass123!", "viewer",
        )
        plain = TestClient(client.app)

        # Request 1: API key
        resp = client.get("/api/health")
        assert resp.status_code == 200

        # Request 2: Session token
        resp = plain.get(
            "/api/health",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Request 3: API key again
        resp = client.get("/api/detections/stats")
        assert resp.status_code == 200

        # Request 4: Session token again
        resp = plain.get(
            "/api/detections/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_api_key_via_query_param(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """API key passed as ?api_key= query parameter works."""
        plain = TestClient(bridge_app)
        resp = plain.get(f"/api/health?api_key={master_key}")
        assert resp.status_code == 200

    def test_x_session_token_header(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Session token via X-Session-Token header works."""
        token, _ = _create_user_and_login(
            client, detection_store, "xheader", "XHeaderPass1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/health",
            headers={"X-Session-Token": token},
        )
        assert resp.status_code == 200


# ===========================================================================
# 3. RBAC WITH SESSIONS
# ===========================================================================


class TestRBACWithSessions:
    """RBAC enforcement is consistent between API key and session auth."""

    def test_viewer_session_can_read_health(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "v_health", "ViewHealth1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get("/api/health", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_viewer_session_can_read_stats(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "v_stats", "ViewStats1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/detections/stats",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_viewer_session_cannot_dismiss_anomaly(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Viewer session should be rejected (403) on analyst endpoints."""
        token, _ = _create_user_and_login(
            client, detection_store, "v_dismiss", "ViewDismiss1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.put(
            "/api/detections/anomalies/1/dismiss",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_analyst_session_can_dismiss(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Analyst session should pass the role check (may get 404 for missing detection)."""
        token, _ = _create_user_and_login(
            client, detection_store, "a_dismiss", "AnalystDismiss1!", "analyst",
        )
        plain = TestClient(client.app)
        resp = plain.put(
            "/api/detections/anomalies/1/dismiss",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Should not be 403 (role allowed), may be 404 (detection doesn't exist)
        assert resp.status_code != 403

    def test_viewer_session_cannot_access_admin_keys(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Viewer cannot reach admin (require_master_key) endpoints."""
        token, _ = _create_user_and_login(
            client, detection_store, "v_admin", "ViewAdmin1!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_session_can_access_admin_keys(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Admin session can reach admin endpoints."""
        token, _ = _create_user_and_login(
            client, detection_store, "a_admin", "AdminAdmin1!!", "admin",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_admin_session_can_manage_users(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Admin session can create/list users via /api/admin/users."""
        token, _ = _create_user_and_login(
            client, detection_store, "usermgr", "UserMgr123!!", "admin",
        )
        plain = TestClient(client.app)

        # Create user
        resp = plain.post(
            "/api/admin/users",
            json={
                "username": "created_by_session",
                "password": "SessionCreated1!",
                "role": "viewer",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "created_by_session"

        # List users
        resp = plain.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        users_list = resp.json()
        assert isinstance(users_list, list)
        usernames = {u["username"] for u in users_list}
        assert "created_by_session" in usernames

    def test_viewer_key_matches_viewer_session_restrictions(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI, viewer_key: str,
    ) -> None:
        """Viewer API key and viewer session have same restrictions."""
        # Session auth
        token, _ = _create_user_and_login(
            client, detection_store, "v_match", "ViewMatch1!!", "viewer",
        )
        plain = TestClient(client.app)

        session_resp = plain.put(
            "/api/detections/anomalies/1/dismiss",
            headers={"Authorization": f"Bearer {token}"},
        )

        # API key auth
        key_client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
        key_resp = key_client.put("/api/detections/anomalies/1/dismiss")

        # Both should be 403
        assert session_resp.status_code == 403
        assert key_resp.status_code == 403

    def test_analyst_session_cannot_admin(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Analyst session should be 403 on admin endpoints."""
        token, _ = _create_user_and_login(
            client, detection_store, "a_noadmin", "AnalystNoAdmin1!", "analyst",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# ===========================================================================
# 4. WEBSOCKET AUTH
# ===========================================================================


class TestWebSocketAuth:
    """WebSocket authentication via Sec-WebSocket-Protocol header."""

    def test_ws_auth_with_api_key(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """WebSocket auth via Sec-WebSocket-Protocol with API key."""
        client = TestClient(bridge_app)
        with client.websocket_connect(
            "/api/nodes/ws/status",
            subprotocols=["bridge-v1", master_key],
        ) as ws:
            # Connection established - auth passed
            # Consume the initial snapshot so the handler doesn't block on send
            data = ws.receive_json()
            assert data["type"] == "snapshot"

    def test_ws_auth_with_session_token(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI,
    ) -> None:
        """WebSocket auth via Sec-WebSocket-Protocol with session token."""
        token, _ = _create_user_and_login(
            client, detection_store, "wsuser", "WsPass123!!", "viewer",
        )
        ws_client = TestClient(bridge_app)
        with ws_client.websocket_connect(
            "/api/nodes/ws/status",
            subprotocols=["bridge-v1", token],
        ) as ws:
            # Connection established - session token auth passed
            # Consume the initial snapshot so the handler doesn't block on send
            data = ws.receive_json()
            assert data["type"] == "snapshot"

    def test_ws_auth_invalid_key_rejected(
        self, bridge_app: FastAPI,
    ) -> None:
        """WebSocket with invalid credentials is rejected."""
        ws_client = TestClient(bridge_app)
        with pytest.raises((WebSocketDisconnect, Exception)):
            with ws_client.websocket_connect(
                "/api/nodes/ws/status",
                subprotocols=["bridge-v1", "invalid-key-value"],
            ) as ws:
                pass

    def test_ws_no_auth_rejected(
        self, bridge_app: FastAPI,
    ) -> None:
        """WebSocket with no auth is rejected."""
        ws_client = TestClient(bridge_app)
        with pytest.raises((WebSocketDisconnect, Exception)):
            with ws_client.websocket_connect("/api/nodes/ws/status") as ws:
                pass

    @pytest.mark.parametrize("carrier", ["subprotocol", "bearer"])
    def test_ws_session_store_unreadable_fails_closed(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI, carrier: str,
    ) -> None:
        """A session token whose row cannot be read (a storage error) is
        refused with 1011, as the gateway answers 503: not treated as "no
        session" and refused as an invalid credential (4001), and not left
        to escape as an unhandled error."""
        token, _ = _create_user_and_login(
            client, detection_store, f"wsbroken_{carrier}", "WsBroken123!!", "viewer",
        )
        conn = detection_store._ctx.get_conn()
        conn.execute("ALTER TABLE sessions RENAME TO sessions_moved")
        conn.commit()
        ws_client = TestClient(bridge_app)
        if carrier == "subprotocol":
            kwargs: dict[str, Any] = {"subprotocols": ["bridge-v1", token]}
        else:
            kwargs = {"headers": {"Authorization": f"Bearer {token}"}}
        with pytest.raises(WebSocketDisconnect) as refused:
            with ws_client.websocket_connect("/api/nodes/ws/status", **kwargs):
                pass
        assert refused.value.code == 1011

    @pytest.mark.parametrize(
        "change",
        [
            "UPDATE users SET role = X'00' WHERE username = ?",
            "UPDATE users SET enabled = 'yes' WHERE username = ?",
            "UPDATE users SET username = X'00' WHERE username = ?",
        ],
    )
    def test_ws_session_with_any_unreadable_field_fails_closed(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI, change: str,
    ) -> None:
        """Any session or user column the bridge acts on that holds a value
        of the wrong type is a storage error, refused with 1011 as the
        gateway answers 503 (its
        a_subprotocol_session_with_any_unreadable_field_is_503): not guessed
        (an unreadable role taken as viewer, 'yes' as enabled) and not
        "no session" (4001).  A sqlite3.DatabaseError, not only the
        OperationalError of a missing table.  (An unreadable scope is
        refused as a restricted one instead; see the next test.)"""
        token, _ = _create_user_and_login(
            client, detection_store, "wsfield", "WsField123!!", "viewer",
        )
        # A full session with a scope column (added on first use).
        detection_store.users.set_session_scope(token, "")
        ws_client = TestClient(bridge_app)
        offer = {"subprotocols": ["bridge-v1", token]}
        with ws_client.websocket_connect("/api/nodes/ws/status", **offer):
            pass
        conn = detection_store._ctx.get_conn()
        conn.execute(change, ["wsfield"])
        conn.commit()
        with pytest.raises(WebSocketDisconnect) as refused:
            with ws_client.websocket_connect("/api/nodes/ws/status", **offer):
                pass
        assert refused.value.code == 1011

    def test_ws_session_with_an_unreadable_scope_is_restricted(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI,
    ) -> None:
        """A scope of the wrong type fails closed as a restricted scope
        (4003), as on HTTP (test_non_text_scope_fails_closed); the gateway
        answers 503. Both refuse the socket."""
        token, _ = _create_user_and_login(
            client, detection_store, "wsscope", "WsScope123!!", "viewer",
        )
        detection_store.users.set_session_scope(token, "")
        conn = detection_store._ctx.get_conn()
        conn.execute(
            "UPDATE sessions SET scope = X'00' WHERE user_id = "
            "(SELECT id FROM users WHERE username = 'wsscope')"
        )
        conn.commit()
        ws_client = TestClient(bridge_app)
        with pytest.raises(WebSocketDisconnect) as refused:
            with ws_client.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", token]
            ):
                pass
        assert refused.value.code == 4003

    def test_http_session_with_an_unreadable_role_is_not_a_viewer(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI,
    ) -> None:
        """The same row on HTTP fails closed (a server error), never
        authenticates as a viewer."""
        token, _ = _create_user_and_login(
            client, detection_store, "httpfield", "HttpField123!!", "viewer",
        )
        http = TestClient(bridge_app, raise_server_exceptions=False)
        bearer = {"Authorization": f"Bearer {token}"}
        assert http.get("/api/auth/me", headers=bearer).status_code == 200
        conn = detection_store._ctx.get_conn()
        conn.execute("UPDATE users SET role = X'00' WHERE username = 'httpfield'")
        conn.commit()
        assert http.get("/api/auth/me", headers=bearer).status_code >= 500

    def test_ws_session_sqlcipher_error_fails_closed(
        self, client: TestClient, detection_store: DetectionStore,
        bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An encrypted store raises pysqlcipher3's own errors, which do not
        inherit from sqlite3.Error: they fail closed with 1011 too."""
        from types import SimpleNamespace

        from sigrift.bridge.storage import encryption

        class CipherOperationalError(Exception):
            """Stands in for pysqlcipher3.dbapi2.OperationalError."""

        monkeypatch.setattr(encryption, "_HAS_SQLCIPHER", True)
        monkeypatch.setattr(
            encryption, "_sqlcipher_db", SimpleNamespace(Error=CipherOperationalError)
        )
        token, _ = _create_user_and_login(
            client, detection_store, "wscipher", "WsCipher123!!", "viewer",
        )

        def unreadable(_token: str) -> None:
            raise CipherOperationalError("no such table: sessions")

        monkeypatch.setattr(detection_store, "get_session", unreadable)
        ws_client = TestClient(bridge_app)
        with pytest.raises(WebSocketDisconnect) as refused:
            with ws_client.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", token]
            ):
                pass
        assert refused.value.code == 1011


# ===========================================================================
# 5. EDGE CASES
# ===========================================================================


class TestEdgeCases:
    """Edge cases: empty auth, malformed tokens, dual auth, revoked sessions."""

    def test_no_auth_at_all(self, plain_client: TestClient) -> None:
        """Request with no auth headers or query params returns 401."""
        resp = plain_client.get("/api/health")
        assert resp.status_code == 401

    def test_empty_api_key_header(self, bridge_app: FastAPI) -> None:
        """Empty X-API-Key header returns 401."""
        client = TestClient(bridge_app, headers={"X-API-Key": ""})
        resp = client.get("/api/health")
        assert resp.status_code == 401

    def test_empty_bearer_token(self, plain_client: TestClient) -> None:
        """Empty Bearer token returns 401."""
        resp = plain_client.get(
            "/api/health",
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401

    def test_malformed_authorization_header(
        self, plain_client: TestClient,
    ) -> None:
        """Authorization header without 'Bearer' prefix is not treated as session."""
        resp = plain_client.get(
            "/api/health",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert resp.status_code == 401

    def test_valid_api_key_format_wrong_value(
        self, bridge_app: FastAPI,
    ) -> None:
        """API key that looks valid but is wrong returns 401."""
        fake_key = generate_api_key(length=32)
        client = TestClient(bridge_app, headers={"X-API-Key": fake_key})
        resp = client.get("/api/health")
        assert resp.status_code == 401

    def test_revoked_session_rejected(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Deleting a session directly makes the token invalid."""
        token, _ = _create_user_and_login(
            client, detection_store, "revoke", "RevokePass1!", "viewer",
        )
        plain = TestClient(client.app)

        # Works before revocation
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Revoke by deleting session
        detection_store.delete_session(token)

        # Should now fail
        resp = plain.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_session_token_priority_over_api_key(
        self, client: TestClient, detection_store: DetectionStore,
        master_key: str,
    ) -> None:
        """When both session token and API key are provided, session token wins.

        The code checks session auth first in require_api_key, so a valid
        session token takes precedence.
        """
        token, _ = _create_user_and_login(
            client, detection_store, "priority", "PriorityP1!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/auth/me",
            headers={
                "Authorization": f"Bearer {token}",
                "X-API-Key": master_key,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        # Session auth wins
        assert data["auth_type"] == "session"
        assert data["username"] == "priority"

    def test_invalid_session_falls_back_to_api_key(
        self, client: TestClient, master_key: str,
    ) -> None:
        """If session token is invalid but API key is valid, API key is used."""
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/auth/me",
            headers={
                "Authorization": "Bearer invalid-session-token",
                "X-API-Key": master_key,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "api_key"

    def test_logout_without_token_returns_401(
        self, plain_client: TestClient,
    ) -> None:
        """Logout without providing a session token returns 401."""
        resp = plain_client.post("/api/auth/logout")
        assert resp.status_code == 401

    def test_logout_with_invalid_token_returns_401(
        self, plain_client: TestClient,
    ) -> None:
        """Logout with an invalid token returns 401."""
        resp = plain_client.post(
            "/api/auth/logout",
            headers={"Authorization": "Bearer totally-invalid-token"},
        )
        assert resp.status_code == 401

    def test_double_logout(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Logging out twice with the same token fails the second time."""
        token, _ = _create_user_and_login(
            client, detection_store, "dblout", "DoubleOut1!!", "viewer",
        )
        plain = TestClient(client.app)

        # First logout succeeds
        resp = plain.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

        # Second logout fails
        resp = plain.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


# ===========================================================================
# 6. ADMIN ENDPOINTS VIA SESSION TOKEN
# ===========================================================================


class TestAdminEndpointsViaSession:
    """Admin endpoints (require_master_key) work with admin session tokens."""

    def test_admin_session_list_keys(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "admkeys", "AdminKeys1!!", "admin",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        keys = resp.json()
        assert isinstance(keys, list)
        assert all(isinstance(k, dict) for k in keys)

    def test_admin_session_create_key(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "admcreate", "AdminCreate1!", "admin",
        )
        plain = TestClient(client.app)
        resp = plain.post(
            "/api/admin/keys",
            json={"description": "session-created key", "role": "viewer"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "viewer"
        assert isinstance(data["raw_key"], str) and len(data["raw_key"]) >= 32

    def test_admin_session_view_audit(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "admaudit", "AdminAudit1!!", "admin",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/audit",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        audit_data = resp.json()
        assert isinstance(audit_data["entries"], list)
        assert "total" in audit_data
        assert isinstance(audit_data["total"], int)

    def test_admin_session_view_config(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "admcfg", "AdminCfg123!!", "admin",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/config",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200

    def test_analyst_session_cannot_list_keys(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "analkeys", "AnalystKeys1!", "analyst",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/admin/keys",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_viewer_session_cannot_create_key(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        token, _ = _create_user_and_login(
            client, detection_store, "viewcreate", "ViewCreate1!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.post(
            "/api/admin/keys",
            json={"description": "should fail", "role": "viewer"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403


# ===========================================================================
# 7. API KEY REGRESSION TESTS
# ===========================================================================


class TestAPIKeyRegression:
    """Ensure API key auth still works correctly after session auth changes."""

    def test_master_key_admin_access(self, client: TestClient) -> None:
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200

    def test_master_key_health(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_viewer_key_read_only(
        self, bridge_app: FastAPI, viewer_key: str,
    ) -> None:
        vc = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
        # Can read
        resp = vc.get("/api/health")
        assert resp.status_code == 200
        resp = vc.get("/api/detections/stats")
        assert resp.status_code == 200
        # Cannot admin
        resp = vc.get("/api/admin/keys")
        assert resp.status_code == 403

    def test_analyst_key_mid_level(
        self, bridge_app: FastAPI, analyst_key: str,
    ) -> None:
        ac = TestClient(bridge_app, headers={"X-API-Key": analyst_key})
        # Can read
        resp = ac.get("/api/health")
        assert resp.status_code == 200
        # Cannot admin
        resp = ac.get("/api/admin/keys")
        assert resp.status_code == 403

    def test_expired_api_key_rejected(
        self, bridge_app: FastAPI, persistence: PersistenceManager,
    ) -> None:
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        raw = _make_key_and_store(persistence, "exp_key", role="admin", expires_at=past)
        ec = TestClient(bridge_app, headers={"X-API-Key": raw})
        resp = ec.get("/api/health")
        assert resp.status_code == 401

    def test_no_key_no_access(self, bridge_app: FastAPI) -> None:
        nc = TestClient(bridge_app)
        resp = nc.get("/api/health")
        assert resp.status_code == 401


# ===========================================================================
# 8. SESSION + SPECIFIC ENDPOINT COVERAGE
# ===========================================================================


class TestSessionEndpointCoverage:
    """Verify session auth works on various endpoint categories."""

    def test_session_on_export_endpoint(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Export endpoints accept session auth."""
        token, _ = _create_user_and_login(
            client, detection_store, "exporter", "ExportPass1!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/export/csv",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Should not be 401 (may be 200 or some other non-auth error)
        assert resp.status_code != 401

    def test_session_on_wifi_endpoint(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """WiFi endpoints accept session auth."""
        token, _ = _create_user_and_login(
            client, detection_store, "wifiuser", "WifiPass123!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/wifi/scans",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code != 401

    def test_session_on_bluetooth_endpoint(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Bluetooth endpoints accept session auth."""
        token, _ = _create_user_and_login(
            client, detection_store, "btuser", "BtPass12345!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/bluetooth/devices",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code != 401

    def test_session_on_nodes_list(
        self, client: TestClient, detection_store: DetectionStore,
    ) -> None:
        """Node list endpoint accepts session auth."""
        token, _ = _create_user_and_login(
            client, detection_store, "nodeuser", "NodePass123!!", "viewer",
        )
        plain = TestClient(client.app)
        resp = plain.get(
            "/api/nodes/list",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code != 401
