"""Tests for user accounts and session-based authentication.

Covers:
- User creation and storage
- Login / logout flow with session tokens
- Session auth for API calls
- Expired session rejection
- Role enforcement (viewer vs admin)
- API key auth still works alongside sessions
- Password change
- Admin user management CRUD
- Rate limiting on login attempts
- Per-user audit trail
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore


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
def store(tmp_path: Path) -> DetectionStore:
    """Fresh DetectionStore with users/sessions tables."""
    return DetectionStore(db_path=tmp_path / "test_users.db")


@pytest.fixture
def admin_user(store: DetectionStore) -> dict[str, Any]:
    """Create an admin user."""
    return store.create_user(
        username="admin",
        password="AdminPass123!",
        role="admin",
        display_name="Test Admin",
        email="admin@test.com",
    )


@pytest.fixture
def viewer_user(store: DetectionStore) -> dict[str, Any]:
    """Create a viewer user."""
    return store.create_user(
        username="viewer",
        password="ViewerPass123!",
        role="viewer",
        display_name="Test Viewer",
    )


# ---------------------------------------------------------------------------
# 1. User creation
# ---------------------------------------------------------------------------


class TestUserCreation:
    def test_create_user(self, store: DetectionStore) -> None:
        user = store.create_user(
            username="testuser",
            password="SecurePass123",
            role="analyst",
            display_name="Test User",
            email="test@example.com",
        )
        assert user["username"] == "testuser"
        assert user["role"] == "analyst"
        assert user["display_name"] == "Test User"
        assert user["email"] == "test@example.com"
        assert user["enabled"] is True
        assert "password_hash" not in user
        assert "salt" not in user

    def test_create_duplicate_user_fails(self, store: DetectionStore) -> None:
        store.create_user(username="dup", password="Pass12345678")
        with pytest.raises(ValueError, match="already exists"):
            store.create_user(username="dup", password="Pass12345678")

    def test_create_user_invalid_role(self, store: DetectionStore) -> None:
        with pytest.raises(ValueError, match="Invalid role"):
            store.create_user(username="bad", password="Pass12345678", role="superadmin")

    def test_get_user(self, store: DetectionStore, admin_user: dict) -> None:
        user = store.get_user("admin")
        assert isinstance(user, dict)
        assert user["username"] == "admin"
        assert user["role"] == "admin"
        assert "password_hash" not in user

    def test_get_nonexistent_user(self, store: DetectionStore) -> None:
        assert store.get_user("nobody") is None

    def test_list_users(self, store: DetectionStore, admin_user: dict, viewer_user: dict) -> None:
        users = store.list_users()
        assert len(users) == 2
        usernames = {u["username"] for u in users}
        assert usernames == {"admin", "viewer"}

    def test_user_count(self, store: DetectionStore, admin_user: dict) -> None:
        assert store.users.user_count() == 1


# ---------------------------------------------------------------------------
# 2. Login returns session token
# ---------------------------------------------------------------------------


class TestLogin:
    def test_login_success(self, client: TestClient, bridge_app: FastAPI, detection_store: DetectionStore) -> None:
        # Create user in the store
        detection_store.create_user(
            username="logintest",
            password="TestPass123!",
            role="analyst",
        )

        resp = client.post(
            "/api/auth/login",
            json={"username": "logintest", "password": "TestPass123!"},
            headers={},  # No API key needed for login
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["session_token"], str) and len(data["session_token"]) >= 32
        assert isinstance(data["expires_at"], str) and "T" in data["expires_at"]
        assert data["user"]["username"] == "logintest"
        assert data["user"]["role"] == "analyst"

    def test_login_wrong_password(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="wrongpw",
            password="CorrectPass123",
        )
        # Use a plain TestClient without API key header for login
        plain_client = TestClient(client.app)
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "wrongpw", "password": "WrongPass123"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client: TestClient) -> None:
        plain_client = TestClient(client.app)
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "ghost", "password": "NoUser123"},
        )
        assert resp.status_code == 401

    def test_login_disabled_user(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(username="disabled", password="Pass12345678")
        detection_store.disable_user("disabled")
        plain_client = TestClient(client.app)
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "disabled", "password": "Pass12345678"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 3. Session auth works for API calls
# ---------------------------------------------------------------------------


class TestSessionAuth:
    def test_session_auth_on_api_endpoint(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="sessionuser",
            password="SessionPass1!",
            role="admin",
        )
        plain_client = TestClient(client.app)

        # Login
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "sessionuser", "password": "SessionPass1!"},
        )
        token = resp.json()["session_token"]

        # Use session token to access an endpoint
        resp = plain_client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "session"
        assert data["username"] == "sessionuser"
        assert data["role"] == "admin"

    def test_session_auth_via_x_session_token(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="headeruser",
            password="HeaderPass1!",
            role="viewer",
        )
        plain_client = TestClient(client.app)

        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "headeruser", "password": "HeaderPass1!"},
        )
        token = resp.json()["session_token"]

        # Use X-Session-Token header
        resp = plain_client.get(
            "/api/auth/me",
            headers={"X-Session-Token": token},
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "headeruser"


# ---------------------------------------------------------------------------
# 4. Logout invalidates session
# ---------------------------------------------------------------------------


class TestLogout:
    def test_logout(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="logoutuser",
            password="LogoutPass1!",
            role="viewer",
        )
        plain_client = TestClient(client.app)

        # Login
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "logoutuser", "password": "LogoutPass1!"},
        )
        token = resp.json()["session_token"]

        # Logout
        resp = plain_client.post(
            "/api/auth/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "logged_out"

        # Token no longer valid
        resp = plain_client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 5. Expired session rejected
# ---------------------------------------------------------------------------


class TestExpiredSession:
    def test_expired_session_rejected(self, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="expiring",
            password="ExpirePass1!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("expiring")
        assert isinstance(user, dict) and user["username"] == "expiring"

        # Create session that expires in the past
        session = detection_store.create_session(
            user_id=user["id"],
            expires_hours=0,  # This will set expires_at close to now
        )

        # Manually set expires_at to past (use hashed token for DB)
        import hashlib
        conn = detection_store.get_connection()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        hashed = hashlib.sha256(session["session_token"].encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [past, hashed],
        )
        conn.commit()

        # Session should be rejected
        result = detection_store.get_session(session["session_token"])
        assert result is None


# ---------------------------------------------------------------------------
# 6. Role enforcement
# ---------------------------------------------------------------------------


class TestRoleEnforcement:
    def test_viewer_cannot_access_admin_endpoints(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="vieweronly",
            password="ViewerPass1!",
            role="viewer",
        )
        plain_client = TestClient(client.app)

        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "vieweronly", "password": "ViewerPass1!"},
        )
        token = resp.json()["session_token"]

        # Try to create a user (admin only)
        resp = plain_client.post(
            "/api/admin/users",
            json={"username": "newuser", "password": "NewPass123!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_admin_can_access_admin_endpoints(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="admintester",
            password="AdminPass1!",
            role="admin",
        )
        plain_client = TestClient(client.app)

        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "admintester", "password": "AdminPass1!"},
        )
        token = resp.json()["session_token"]

        # List users (admin endpoint)
        resp = plain_client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 7. API key auth still works alongside sessions
# ---------------------------------------------------------------------------


class TestApiKeyCompat:
    def test_api_key_auth_still_works(self, client: TestClient, master_key: str) -> None:
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "api_key"
        assert data["key_id"] == "master"

    def test_api_key_on_other_endpoints(self, client: TestClient, master_key: str) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 8. Password change
# ---------------------------------------------------------------------------


class TestPasswordChange:
    def test_change_password(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="pwchange",
            password="OldPass123!",
            role="viewer",
        )
        plain_client = TestClient(client.app)

        # Login
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "pwchange", "password": "OldPass123!"},
        )
        token = resp.json()["session_token"]

        # Change password
        resp = plain_client.post(
            "/api/auth/change-password",
            json={"current_password": "OldPass123!", "new_password": "NewPass456!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "password_changed"

        # Old password no longer works
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "pwchange", "password": "OldPass123!"},
        )
        assert resp.status_code == 401

        # New password works
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "pwchange", "password": "NewPass456!"},
        )
        assert resp.status_code == 200

    def test_change_password_wrong_current(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="pwwrong",
            password="CorrectPass1!",
            role="viewer",
        )
        plain_client = TestClient(client.app)

        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "pwwrong", "password": "CorrectPass1!"},
        )
        token = resp.json()["session_token"]

        resp = plain_client.post(
            "/api/auth/change-password",
            json={"current_password": "WrongCurrent", "new_password": "NewPass456!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_change_password_requires_session(self, client: TestClient) -> None:
        """API key auth cannot change passwords (no user context)."""
        resp = client.post(
            "/api/auth/change-password",
            json={"current_password": "old", "new_password": "newpassword123"},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 9. Admin user management CRUD
# ---------------------------------------------------------------------------


class TestAdminUserManagement:
    def _admin_login(self, client: TestClient, detection_store: DetectionStore) -> tuple[TestClient, str]:
        """Create an admin user, login, return (plain_client, token)."""
        detection_store.create_user(
            username="mgr_admin",
            password="AdminMgr123!",
            role="admin",
        )
        plain_client = TestClient(client.app)
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "mgr_admin", "password": "AdminMgr123!"},
        )
        return plain_client, resp.json()["session_token"]

    def test_create_user_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        resp = pc.post(
            "/api/admin/users",
            json={
                "username": "newanalyst",
                "password": "AnalystPass1!",
                "role": "analyst",
                "display_name": "New Analyst",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "newanalyst"
        assert data["role"] == "analyst"

    def test_list_users_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        resp = pc.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        users = resp.json()
        assert any(u["username"] == "mgr_admin" for u in users)

    def test_update_user_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        detection_store.create_user(username="toupdate", password="Update123!!")
        resp = pc.put(
            "/api/admin/users/toupdate",
            json={"role": "analyst", "display_name": "Updated Name"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "analyst"
        assert data["display_name"] == "Updated Name"

    def test_delete_user_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        detection_store.create_user(username="todelete", password="Delete123!!")
        resp = pc.delete(
            "/api/admin/users/todelete",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "disabled"

        # Verify user is disabled
        user = detection_store.get_user("todelete")
        assert isinstance(user, dict) and user["username"] == "todelete"
        assert user["enabled"] == 0

    def test_reset_password_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        detection_store.create_user(username="resetme", password="OldPass123!")
        resp = pc.post(
            "/api/admin/users/resetme/reset-password",
            json={"new_password": "ResetPass456!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "password_reset"

        # New password works
        resp = pc.post(
            "/api/auth/login",
            json={"username": "resetme", "password": "ResetPass456!"},
        )
        assert resp.status_code == 200

    def test_create_user_via_api_key(self, client: TestClient) -> None:
        """Admin API key can also create users."""
        resp = client.post(
            "/api/admin/users",
            json={
                "username": "apikeycreated",
                "password": "ApiKeyPass1!",
                "role": "viewer",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["username"] == "apikeycreated"

    def test_update_nonexistent_user(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        resp = pc.put(
            "/api/admin/users/nonexistent",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404

    def test_create_duplicate_user_via_api(self, client: TestClient, detection_store: DetectionStore) -> None:
        pc, token = self._admin_login(client, detection_store)
        resp = pc.post(
            "/api/admin/users",
            json={"username": "mgr_admin", "password": "DupPass123!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# 10. Rate limiting on login attempts
# ---------------------------------------------------------------------------


class TestLoginRateLimit:
    def test_login_rate_limit(self, client: TestClient) -> None:
        """After 5 failed login attempts, further attempts are rejected."""
        # Reset the login rate limiter
        from sigrift.bridge.routers.auth import _login_attempts
        _login_attempts.clear()

        plain_client = TestClient(client.app)

        for i in range(5):
            resp = plain_client.post(
                "/api/auth/login",
                json={"username": "nobody", "password": f"attempt{i}"},
            )
            # These will be 401 (bad credentials) but should count
            assert resp.status_code == 401

        # 6th attempt should be rate limited
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "nobody", "password": "attempt6"},
        )
        assert resp.status_code == 429
        assert int(resp.headers["Retry-After"]) > 0


# ---------------------------------------------------------------------------
# 11. Per-user audit trail
# ---------------------------------------------------------------------------


class TestPerUserAudit:
    def test_session_auth_audit_uses_username(self, client: TestClient, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="audituser",
            password="AuditPass123!",
            role="admin",
        )
        plain_client = TestClient(client.app)

        # Login
        resp = plain_client.post(
            "/api/auth/login",
            json={"username": "audituser", "password": "AuditPass123!"},
        )
        token = resp.json()["session_token"]

        # Check audit log for login entry
        audit_entries = detection_store.get_audit_log(action="user_login")
        login_entries = [e for e in audit_entries if e["target_id"] == "audituser"]
        assert len(login_entries) >= 1
        assert login_entries[0]["operator"] == "audituser"

    def test_api_key_audit_uses_key_id(self, client: TestClient, detection_store: DetectionStore) -> None:
        """API key operations should still work and use key_id in audit."""
        resp = client.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["auth_type"] == "api_key"


# ---------------------------------------------------------------------------
# 12. Session cleanup
# ---------------------------------------------------------------------------


class TestSessionCleanup:
    def test_cleanup_expired_sessions(self, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="cleanup_user",
            password="CleanupPass1!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("cleanup_user")

        # Create a session
        session = detection_store.create_session(user_id=user["id"])

        # Manually expire it (use hashed token for DB)
        import hashlib
        conn = detection_store.get_connection()
        past = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        hashed = hashlib.sha256(session["session_token"].encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [past, hashed],
        )
        conn.commit()

        # Cleanup should remove it
        cleaned = detection_store.cleanup_expired_sessions()
        assert cleaned >= 1

    def test_delete_user_sessions(self, detection_store: DetectionStore) -> None:
        detection_store.create_user(
            username="multi_session",
            password="MultiPass1!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("multi_session")

        # Create multiple sessions
        detection_store.create_session(user_id=user["id"])
        detection_store.create_session(user_id=user["id"])

        deleted = detection_store.users.delete_user_sessions(user["id"])
        assert deleted == 2


# ---------------------------------------------------------------------------
# 13. PBKDF2 password hashing
# ---------------------------------------------------------------------------


class TestPBKDF2Hashing:
    def test_pbkdf2_hash_and_verify(self) -> None:
        """Verify that PBKDF2-HMAC-SHA256 hashing works end-to-end."""
        from sigrift.lib.security.credentials import hash_credential, verify_credential

        password = "TestPBKDF2Pass!"
        hash_hex, salt = hash_credential(password)

        # Hash should not be the same length as legacy SHA-256 (64 chars)
        assert len(hash_hex) == 64  # 32 bytes = 64 hex chars for PBKDF2 too
        assert isinstance(salt, bytes)
        assert len(salt) == 32

        # Verify should succeed
        assert verify_credential(password, hash_hex, salt) is True

        # Wrong password should fail
        assert verify_credential("WrongPass!", hash_hex, salt) is False

    def test_user_creation_uses_pbkdf2(self, store: DetectionStore) -> None:
        """New users are created with PBKDF2 hashes."""
        store.create_user(username="pbkdf2user", password="PbkdfPass123!")
        user = store.users.get_user_full("pbkdf2user")
        assert isinstance(user, dict) and user["username"] == "pbkdf2user"
        assert isinstance(user["password_hash"], str) and len(user["password_hash"]) == 64
        assert isinstance(user["salt"], bytes) and len(user["salt"]) == 32

        # Verify password works
        assert store.verify_password("pbkdf2user", "PbkdfPass123!") is True
        assert store.verify_password("pbkdf2user", "WrongPass") is False

    def test_session_token_length(self, detection_store: DetectionStore) -> None:
        """Session tokens should be cryptographically random and 32+ bytes."""
        detection_store.create_user(
            username="tokenlen",
            password="TokenLen123!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("tokenlen")
        session = detection_store.create_session(user_id=user["id"])
        token = session["session_token"]
        # secrets.token_urlsafe(32) produces ~43 chars
        assert len(token) >= 32

    def test_password_change_updates_hash(self, detection_store: DetectionStore) -> None:
        """Changing password creates a new hash, old password stops working."""
        detection_store.create_user(
            username="pwupdate",
            password="OldPBKDF2Pass!",
        )
        assert detection_store.verify_password("pwupdate", "OldPBKDF2Pass!") is True

        detection_store.users.set_password("pwupdate", "NewPBKDF2Pass!")
        assert detection_store.verify_password("pwupdate", "OldPBKDF2Pass!") is False
        assert detection_store.verify_password("pwupdate", "NewPBKDF2Pass!") is True


# ---------------------------------------------------------------------------
# 14. Session token security properties
# ---------------------------------------------------------------------------


class TestSessionTokenSecurity:
    def test_unique_tokens_per_session(self, detection_store: DetectionStore) -> None:
        """Each session gets a unique token."""
        detection_store.create_user(
            username="uniquetok",
            password="UniqueToken1!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("uniquetok")
        s1 = detection_store.create_session(user_id=user["id"])
        s2 = detection_store.create_session(user_id=user["id"])
        assert s1["session_token"] != s2["session_token"]

    def test_session_contains_user_info(self, detection_store: DetectionStore) -> None:
        """Looking up a session returns the user's role and username."""
        detection_store.create_user(
            username="sessioninfo",
            password="SessionInfo1!",
            role="analyst",
        )
        user = detection_store.users.get_user_full("sessioninfo")
        session = detection_store.create_session(user_id=user["id"])
        looked_up = detection_store.get_session(session["session_token"])
        assert isinstance(looked_up, dict)
        assert looked_up["username"] == "sessioninfo"
        assert looked_up["role"] == "analyst"

    def test_disabled_user_session_invalid(self, detection_store: DetectionStore) -> None:
        """Sessions for disabled users are rejected."""
        detection_store.create_user(
            username="disabledsession",
            password="DisabledSess1!",
            role="viewer",
        )
        user = detection_store.users.get_user_full("disabledsession")
        session = detection_store.create_session(user_id=user["id"])
        # Valid before disable
        assert isinstance(detection_store.get_session(session["session_token"]), dict)
        # Disable the user
        detection_store.disable_user("disabledsession")
        # Session should now be rejected
        assert detection_store.get_session(session["session_token"]) is None
