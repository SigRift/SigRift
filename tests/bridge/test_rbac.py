"""Tests for the RBAC (Role-Based Access Control) system.

Covers:
  - Role enum hierarchy and construction
  - _lookup_key role resolution and expiry handling
  - Endpoint-level RBAC enforcement (viewer / analyst / admin)
  - Key management with roles via admin API
  - Expired key rejection
  - Master key role protection
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.dependencies import Role, _lookup_key
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
    expires_at: str | None = None,
    description: str = "",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict = {"role": role, "description": description or f"test {role}"}
    if expires_at is not None:
        meta["expires_at"] = expires_at
    persistence.set_key_meta(key_id, meta)
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    """Create a viewer-role API key and return the raw key."""
    return _make_key_and_store(persistence, "viewer_key", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    """Create an analyst-role API key and return the raw key."""
    return _make_key_and_store(persistence, "analyst_key", role="analyst")


@pytest.fixture
def admin_key(persistence: PersistenceManager, master_key: str) -> str:
    """Return the master key (which is admin role by default)."""
    return master_key


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    """TestClient authenticated with a viewer-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    """TestClient authenticated with an analyst-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


# ---------------------------------------------------------------------------
# TestRoleEnum
# ---------------------------------------------------------------------------


class TestRoleEnum:
    """Tests for the Role IntEnum definition."""

    def test_role_hierarchy(self) -> None:
        """SENSOR < NODE < VIEWER < ANALYST < ADMIN in numeric order."""
        assert Role.SENSOR < Role.NODE
        assert Role.NODE < Role.VIEWER
        assert Role.VIEWER < Role.ANALYST
        assert Role.ANALYST < Role.ADMIN

    def test_role_from_string(self) -> None:
        """Role[name] lookup produces the correct enum member."""
        assert Role["SENSOR"] == Role.SENSOR
        assert Role["NODE"] == Role.NODE
        assert Role["VIEWER"] == Role.VIEWER
        assert Role["ANALYST"] == Role.ANALYST
        assert Role["ADMIN"] == Role.ADMIN

    def test_role_values(self) -> None:
        """Roles have the expected integer values."""
        assert int(Role.SENSOR) == 0
        assert int(Role.NODE) == 1
        assert int(Role.VIEWER) == 2
        assert int(Role.ANALYST) == 3
        assert int(Role.ADMIN) == 4


# ---------------------------------------------------------------------------
# TestLookupKey
# ---------------------------------------------------------------------------


class TestLookupKey:
    """Tests for the _lookup_key helper function."""

    def test_lookup_returns_role(self) -> None:
        """Key with role='viewer' in meta returns (key_id, Role.VIEWER)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"test_key": (hash_hex, salt)}
        key_meta = {"test_key": {"role": "viewer"}}

        key_id, role = _lookup_key(raw_key, key_store, key_meta)
        assert key_id == "test_key"
        assert role == Role.VIEWER

    def test_lookup_default_viewer(self) -> None:
        """Key without role in meta defaults to Role.VIEWER (least-privilege)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"no_role_key": (hash_hex, salt)}
        key_meta = {"no_role_key": {}}

        key_id, role = _lookup_key(raw_key, key_store, key_meta)
        assert key_id == "no_role_key"
        assert role == Role.VIEWER

    def test_lookup_no_meta_defaults_viewer(self) -> None:
        """Key with no meta entry at all defaults to Role.VIEWER (least-privilege)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"orphan_key": (hash_hex, salt)}

        key_id, role = _lookup_key(raw_key, key_store, None)
        assert key_id == "orphan_key"
        assert role == Role.VIEWER

    def test_lookup_expired_key(self) -> None:
        """Key with a past expires_at returns (None, None)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"exp_key": (hash_hex, salt)}

        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        key_meta = {"exp_key": {"role": "admin", "expires_at": past}}

        key_id, role = _lookup_key(raw_key, key_store, key_meta)
        assert key_id is None
        assert role is None

    def test_lookup_valid_expiry(self) -> None:
        """Key with a future expires_at returns valid (key_id, role)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"future_key": (hash_hex, salt)}

        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        key_meta = {"future_key": {"role": "analyst", "expires_at": future}}

        key_id, role = _lookup_key(raw_key, key_store, key_meta)
        assert key_id == "future_key"
        assert role == Role.ANALYST

    def test_lookup_invalid_key(self) -> None:
        """Wrong API key returns (None, None)."""
        raw_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw_key)
        key_store = {"good_key": (hash_hex, salt)}

        key_id, role = _lookup_key("completely-wrong-key", key_store, None)
        assert key_id is None
        assert role is None


# ---------------------------------------------------------------------------
# TestRBACEndpoints
# ---------------------------------------------------------------------------


class TestRBACEndpoints:
    """Integration tests verifying role-based endpoint access control."""

    # -- Viewer: read-only access -------------------------------------------

    def test_viewer_can_read_health(self, viewer_client: TestClient) -> None:
        """Viewer key can access GET /api/health."""
        resp = viewer_client.get("/api/health")
        assert resp.status_code == 200

    def test_viewer_can_read_detections(self, viewer_client: TestClient) -> None:
        """Viewer key can access GET /api/detections/anomalies."""
        resp = viewer_client.get("/api/detections/anomalies")
        assert resp.status_code == 200

    def test_viewer_can_read_stats(self, viewer_client: TestClient) -> None:
        """Viewer key can access GET /api/detections/stats."""
        resp = viewer_client.get("/api/detections/stats")
        assert resp.status_code == 200

    def test_viewer_cannot_post_batch(
        self,
        viewer_client: TestClient,
        registered_node: str,
    ) -> None:
        """An unbound viewer key is refused (403) on POST /api/detections/batch.

        The ingest endpoint's role floor is SENSOR, which VIEWER passes, but
        node-scoped routes need a node credential (contract K7b): a viewer
        key that no admin bound to the node is never bound on first use.
        (Before round 5 it was bound to the first node it named — W1.)
        """
        now = datetime.now(timezone.utc)
        resp = viewer_client.post(
            "/api/detections/batch",
            json={
                "node_id": registered_node,
                "period_start": (now - timedelta(minutes=1)).isoformat(),
                "period_end": now.isoformat(),
                "detections": [],
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Node endpoints require a node API key"

    def test_viewer_cannot_dismiss(self, viewer_client: TestClient) -> None:
        """Viewer key is rejected (403) on PUT /api/detections/anomalies/{id}/dismiss."""
        resp = viewer_client.put("/api/detections/anomalies/1/dismiss")
        assert resp.status_code == 403

    def test_viewer_cannot_submit_feedback(self, viewer_client: TestClient) -> None:
        """Viewer key is rejected (403) on POST /api/detections/anomalies/{id}/feedback."""
        resp = viewer_client.post(
            "/api/detections/anomalies/test-det-id/feedback",
            json={"label": "false_positive"},
        )
        assert resp.status_code == 403

    # -- Analyst: write access, but not admin --------------------------------

    def test_analyst_can_post_batch(
        self,
        analyst_client: TestClient,
        registered_node: str,
    ) -> None:
        """Analyst key is accepted on POST /api/detections/batch (not 403)."""
        now = datetime.now(timezone.utc)
        resp = analyst_client.post(
            "/api/detections/batch",
            json={
                "node_id": registered_node,
                "period_start": (now - timedelta(minutes=1)).isoformat(),
                "period_end": now.isoformat(),
                "detections": [
                    {
                        "node_id": registered_node,
                        "signal_class": "bpsk",
                        "confidence": 0.9,
                        "family": "psk",
                        "freq_hz": 433.92e6,
                    },
                ],
            },
        )
        # Should succeed (201) or at least not be a 403
        assert resp.status_code != 403
        assert resp.status_code == 201

    def test_analyst_cannot_admin(self, analyst_client: TestClient) -> None:
        """Analyst key is rejected (403) on admin endpoints."""
        resp = analyst_client.get("/api/admin/keys")
        assert resp.status_code == 403

    def test_analyst_cannot_admin_config(self, analyst_client: TestClient) -> None:
        """Analyst key is rejected (403) on GET /api/admin/config."""
        resp = analyst_client.get("/api/admin/config")
        assert resp.status_code == 403

    # -- Admin: full access -------------------------------------------------

    def test_admin_can_admin(self, client: TestClient) -> None:
        """Admin (master) key can access GET /api/admin/keys."""
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200

    def test_admin_can_read_health(self, client: TestClient) -> None:
        """Admin key can access GET /api/health."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    # -- Expired key --------------------------------------------------------

    def test_expired_key_rejected(
        self,
        bridge_app: FastAPI,
        persistence: PersistenceManager,
    ) -> None:
        """Key with a past expiry date returns 401 on any endpoint."""
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        raw_key = _make_key_and_store(
            persistence,
            "expired_key",
            role="admin",
            expires_at=past,
        )
        expired_client = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        resp = expired_client.get("/api/health")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestKeyManagement
# ---------------------------------------------------------------------------


class TestKeyManagement:
    """Tests for admin key management with RBAC roles."""

    def test_create_key_with_role(self, client: TestClient) -> None:
        """POST /api/admin/keys with role='viewer' returns the role in response."""
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "read-only key",
                "role": "viewer",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "viewer"
        assert isinstance(data["raw_key"], str) and len(data["raw_key"]) >= 32
        assert isinstance(data["key_id"], str) and len(data["key_id"]) > 0

    def test_create_key_default_role(self, client: TestClient) -> None:
        """POST /api/admin/keys without explicit role defaults to 'analyst'."""
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "default role key",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "analyst"

    def test_create_key_invalid_role(self, client: TestClient) -> None:
        """POST /api/admin/keys with an invalid role returns 400."""
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "bad role",
                "role": "superuser",
            },
        )
        assert resp.status_code == 400

    def test_list_keys_shows_metadata(self, client: TestClient) -> None:
        """GET /api/admin/keys includes role, description, expires fields."""
        # Create a key with known metadata
        client.post(
            "/api/admin/keys",
            json={
                "description": "metadata test",
                "role": "viewer",
                "expires_days": 30,
            },
        )

        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert isinstance(keys, list)

        # Find our created key
        viewer_keys = [k for k in keys if k.get("role") == "viewer"]
        assert len(viewer_keys) >= 1
        k = viewer_keys[0]
        assert k["role"] == "viewer"
        assert isinstance(k["description"], str) and len(k["description"]) > 0
        assert isinstance(k.get("expires_at"), str)

    def test_update_key_role(self, client: TestClient) -> None:
        """PUT /api/admin/keys/{key_id}/permissions with role='analyst' updates."""
        # Create a viewer key first
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "will be promoted",
                "role": "viewer",
            },
        )
        assert resp.status_code == 201
        key_id = resp.json()["key_id"]

        # Update role to analyst
        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions",
            json={
                "role": "analyst",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "analyst"

    def test_cannot_change_master_role(self, client: TestClient) -> None:
        """PUT /api/admin/keys/master/permissions returns 403."""
        resp = client.put(
            "/api/admin/keys/master/permissions",
            json={
                "role": "viewer",
            },
        )
        assert resp.status_code == 403

    def test_created_viewer_key_enforced(
        self,
        bridge_app: FastAPI,
        client: TestClient,
    ) -> None:
        """A key created via admin API with role='viewer' is actually enforced."""
        # Create viewer key through admin API
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "enforced viewer",
                "role": "viewer",
            },
        )
        assert resp.status_code == 201
        raw_key = resp.json()["raw_key"]

        # Use that key -- should be blocked from analyst endpoints
        viewer = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        resp = viewer.put("/api/detections/anomalies/1/dismiss")
        assert resp.status_code == 403

        # But should be able to read
        resp = viewer.get("/api/detections/stats")
        assert resp.status_code == 200

    def test_role_upgrade_takes_effect(
        self,
        bridge_app: FastAPI,
        client: TestClient,
    ) -> None:
        """Upgrading a key's role via admin API is immediately effective."""
        # Create a viewer key
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "to be promoted",
                "role": "viewer",
            },
        )
        assert resp.status_code == 201
        key_id = resp.json()["key_id"]
        raw_key = resp.json()["raw_key"]

        # Verify viewer cannot dismiss
        key_client = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        resp = key_client.put("/api/detections/anomalies/1/dismiss")
        assert resp.status_code == 403

        # Promote to analyst
        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions",
            json={
                "role": "analyst",
            },
        )
        assert resp.status_code == 200

        # Now the same key should be able to dismiss (not 403)
        resp = key_client.put("/api/detections/anomalies/1/dismiss")
        assert resp.status_code != 403
