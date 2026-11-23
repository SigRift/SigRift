"""Tests for the /api/keys/* endpoints.

Covers:
  - POST /api/keys/   (create key, requires master key auth)
  - GET  /api/keys/   (list all keys)
  - DELETE /api/keys/{key_id}  (revoke key, requires master key)
  - Non-master keys cannot create/delete keys
  - Revoked keys cannot access protected endpoints
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient



# ---------------------------------------------------------------------------
# Key creation
# ---------------------------------------------------------------------------


class TestCreateKey:
    """Tests for POST /api/keys/."""

    def test_create_key_success(self, client: TestClient) -> None:
        """Master key can create a new API key."""
        resp = client.post("/api/keys/", json={
            "key_id": "node-key-1",
            "description": "Test node key",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["key_id"] == "node-key-1"
        assert "raw_key" in data
        assert len(data["raw_key"]) > 0
        assert data["description"] == "Test node key"
        assert "message" in data

    def test_create_key_with_expiry(self, client: TestClient) -> None:
        """Key creation with expiry hours."""
        resp = client.post("/api/keys/", json={
            "key_id": "expiring-key",
            "description": "Expires in 24h",
            "expires_in_hours": 24,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["expires_at"] is not None

    def test_create_key_with_node_id(self, client: TestClient) -> None:
        """Key creation with associated node_id."""
        resp = client.post("/api/keys/", json={
            "key_id": "node-bound-key",
            "description": "Bound to node",
            "node_id": "node-test-01",
        })
        assert resp.status_code == 201
        assert resp.json()["node_id"] == "node-test-01"

    def test_create_duplicate_key_conflict(self, client: TestClient) -> None:
        """Duplicate key_id returns 409."""
        client.post("/api/keys/", json={
            "key_id": "dup-key",
            "description": "First",
        })
        resp = client.post("/api/keys/", json={
            "key_id": "dup-key",
            "description": "Second",
        })
        assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Key listing
# ---------------------------------------------------------------------------


class TestListKeys:
    """Tests for GET /api/keys/."""

    def test_list_keys_includes_master(self, client: TestClient) -> None:
        """Listing keys shows the master key."""
        resp = client.get("/api/keys/")
        assert resp.status_code == 200
        keys = resp.json()
        key_ids = [k["key_id"] for k in keys]
        assert "master" in key_ids

    def test_list_keys_after_create(self, client: TestClient) -> None:
        """Newly created key appears in listing."""
        client.post("/api/keys/", json={
            "key_id": "listed-key",
            "description": "Should appear",
        })
        resp = client.get("/api/keys/")
        assert resp.status_code == 200
        key_ids = [k["key_id"] for k in resp.json()]
        assert "listed-key" in key_ids

    def test_list_keys_never_exposes_hash(self, client: TestClient) -> None:
        """Key listing never returns raw keys or hashes."""
        resp = client.get("/api/keys/")
        assert resp.status_code == 200
        for key in resp.json():
            assert "raw_key" not in key
            assert "hash" not in key
            assert "salt" not in key


# ---------------------------------------------------------------------------
# Key revocation
# ---------------------------------------------------------------------------


class TestRevokeKey:
    """Tests for DELETE /api/keys/{key_id}."""

    def test_revoke_key_success(self, client: TestClient) -> None:
        """Master key can revoke a key."""
        client.post("/api/keys/", json={
            "key_id": "to-revoke",
            "description": "Will be revoked",
        })
        resp = client.delete("/api/keys/to-revoke")
        assert resp.status_code == 200
        assert resp.json()["revoked"] == "to-revoke"

    def test_revoke_nonexistent_key_404(self, client: TestClient) -> None:
        """Revoking a nonexistent key returns 404."""
        resp = client.delete("/api/keys/ghost-key")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Non-master key restrictions
# ---------------------------------------------------------------------------


class TestNonMasterRestrictions:
    """Non-master keys cannot create or delete keys."""

    def test_non_master_cannot_create(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """Non-master key gets 403 on key creation."""
        # Create a non-master key first
        resp = client.post("/api/keys/", json={
            "key_id": "worker-key",
            "description": "Worker",
        })
        raw_key = resp.json()["raw_key"]

        # Use the non-master key
        worker_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = worker_client.post("/api/keys/", json={
            "key_id": "sneaky-key",
            "description": "Should fail",
        })
        assert resp.status_code == 403

    def test_non_master_cannot_delete(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """Non-master key gets 403 on key deletion."""
        # Create a non-master key
        resp = client.post("/api/keys/", json={
            "key_id": "worker-key-2",
            "description": "Worker 2",
        })
        raw_key = resp.json()["raw_key"]

        # Create a target key to try to delete
        client.post("/api/keys/", json={
            "key_id": "target-key",
            "description": "Target",
        })

        worker_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = worker_client.delete("/api/keys/target-key")
        assert resp.status_code == 403

    def test_non_master_can_list_keys(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """Non-master keys can still list keys (read-only)."""
        resp = client.post("/api/keys/", json={
            "key_id": "reader-key",
            "description": "Reader",
        })
        raw_key = resp.json()["raw_key"]

        reader_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = reader_client.get("/api/keys/")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Revoked key access
# ---------------------------------------------------------------------------


class TestRevokedKeyAccess:
    """Revoked keys cannot access protected endpoints."""

    def test_revoked_key_rejected(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """A revoked key is rejected on subsequent requests."""
        # Create and capture raw key
        resp = client.post("/api/keys/", json={
            "key_id": "temp-key",
            "description": "Temporary",
        })
        raw_key = resp.json()["raw_key"]

        # Verify it works before revocation
        temp_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = temp_client.get("/api/detections/stats")
        assert resp.status_code == 200

        # Revoke it
        resp = client.delete("/api/keys/temp-key")
        assert resp.status_code == 200

        # Now the key should fail
        resp = temp_client.get("/api/detections/stats")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Master key rotation
# ---------------------------------------------------------------------------


class TestMasterKeyRotation:
    """Tests for POST /api/keys/rotate-master."""

    def test_rotate_master_success(
        self, bridge_app: FastAPI, client: TestClient, master_key: str,
    ) -> None:
        """Master key rotation returns a new raw key."""
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rotated"
        assert "raw_key" in data
        assert len(data["raw_key"]) > 0
        assert "rotated_at" in data
        assert "message" in data
        assert data["raw_key"] != master_key

    def test_old_key_stops_working_after_rotation(
        self, bridge_app: FastAPI, client: TestClient, master_key: str,
    ) -> None:
        """After rotation, the old master key is rejected."""
        # Rotate the master key
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200

        # Old key should no longer work
        resp = client.get("/api/keys/")
        assert resp.status_code == 401

    def test_new_key_works_after_rotation(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """After rotation, the new key authenticates successfully."""
        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200
        new_key = resp.json()["raw_key"]

        # Use the new key
        new_client = TestClient(
            bridge_app, headers={"X-API-Key": new_key},
        )
        resp = new_client.get("/api/keys/")
        assert resp.status_code == 200

    def test_non_admin_cannot_rotate_master(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """Non-admin keys get 403 on master key rotation."""
        # Create a non-master key
        resp = client.post("/api/keys/", json={
            "key_id": "worker-rotate",
            "description": "Worker trying to rotate",
        })
        raw_key = resp.json()["raw_key"]

        worker_client = TestClient(
            bridge_app, headers={"X-API-Key": raw_key},
        )
        resp = worker_client.post("/api/keys/rotate-master")
        assert resp.status_code == 403

    def test_rotate_master_audit_log(
        self, bridge_app: FastAPI, client: TestClient,
    ) -> None:
        """Master key rotation creates an audit trail entry."""
        app_state = bridge_app.state.app_state

        initial_log_count = len(app_state.activity_log)

        resp = client.post("/api/keys/rotate-master")
        assert resp.status_code == 200

        # Check that a log entry was created
        assert len(app_state.activity_log) > initial_log_count
        # Find the rotation event
        rotation_events = [
            e for e in app_state.activity_log
            if e.get("event_type") == "master_key_rotated"
        ]
        assert len(rotation_events) >= 1

    def test_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Request without any API key is rejected."""
        no_auth_client = TestClient(bridge_app)
        resp = no_auth_client.post("/api/keys/rotate-master")
        assert resp.status_code == 401
