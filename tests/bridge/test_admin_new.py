"""Tests for new admin.py endpoints: key rotation and node_id in list_keys.

Covers:
  - POST /api/admin/keys/{key_id}/rotate — happy path, TLS enforcement,
    master key rejection, key-not-found, response shapes
  - GET /api/admin/keys — node_id field presence in list output
  - RBAC: viewer and analyst keys are rejected on rotate endpoint
  - Input validation: ssh_user pattern
"""

from __future__ import annotations


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
    node_id: str | None = None,
    description: str = "",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict = {"role": role, "description": description or f"test {role}"}
    if node_id is not None:
        meta["node_id"] = node_id
    persistence.set_key_meta(key_id, meta)
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "viewer_key", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_key", role="analyst")


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


# ---------------------------------------------------------------------------
# TestListKeysNodeId — node_id field in GET /api/admin/keys
# ---------------------------------------------------------------------------


class TestListKeysNodeId:
    """Tests that the node_id field is present in list_keys output."""

    def test_list_keys_includes_node_id_field(self, client: TestClient) -> None:
        """Every key object returned by GET /api/admin/keys has 'node_id'."""
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert isinstance(keys, list)
        for k in keys:
            assert "node_id" in k, f"key {k['key_id']} missing 'node_id' field"

    def test_list_keys_node_id_populated(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """Keys with a node_id in meta expose it through list_keys."""
        _make_key_and_store(
            persistence, "node_key_1", role="admin", node_id="node-abc-01",
        )
        resp = client.get("/api/admin/keys")
        keys_by_id = {k["key_id"]: k for k in resp.json()}
        assert keys_by_id["node_key_1"]["node_id"] == "node-abc-01"


# ---------------------------------------------------------------------------
# TestRotateKeyTLS — TLS enforcement
# ---------------------------------------------------------------------------


class TestRotateKeyTLS:
    """POST /api/admin/keys/{key_id}/rotate requires TLS."""

    def test_rejected_without_tls(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """A plaintext request is 403."""
        _make_key_and_store(persistence, "rot_tls_key")
        resp = client.post(
            "/api/admin/keys/rot_tls_key/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 403

    def test_accepted_over_tls(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """A request that arrived over TLS passes the check."""
        _make_key_and_store(persistence, "rot_tls_ok")
        resp = client.post(
            "https://testserver/api/admin/keys/rot_tls_ok/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TestRotateKeyBasic — core rotation behaviour
# ---------------------------------------------------------------------------


class TestRotateKeyBasic:
    """Happy-path key rotation tests (no SSH deployment)."""

    def test_rotate_returns_new_key(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """Rotation returns raw_key, key_id, rotated_at, deployed=False."""
        _make_key_and_store(persistence, "rot_basic")
        resp = client.post(
            "https://testserver/api/admin/keys/rot_basic/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key_id"] == "rot_basic"
        assert isinstance(data["raw_key"], str)
        assert len(data["raw_key"]) > 0
        assert data["deployed"] is False
        assert isinstance(data["rotated_at"], str)

    def test_rotated_key_differs_from_original(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """The raw key returned after rotation is different from the original."""
        original_raw = _make_key_and_store(persistence, "rot_diff")
        resp = client.post(
            "https://testserver/api/admin/keys/rot_diff/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 200
        new_raw = resp.json()["raw_key"]
        assert new_raw != original_raw

    def test_rotate_nonexistent_key_404(self, client: TestClient) -> None:
        """Rotating a key that doesn't exist returns 404."""
        resp = client.post(
            "https://testserver/api/admin/keys/no_such_key/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 404

    def test_rotate_master_key_rejected(self, client: TestClient) -> None:
        """Rotating the master key is forbidden (403)."""
        resp = client.post(
            "https://testserver/api/admin/keys/master/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TestRotateKeyInputValidation
# ---------------------------------------------------------------------------


class TestRotateKeyInputValidation:
    """Input validation on the RotateKeyRequest body."""

    def test_ssh_user_invalid_characters(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """ssh_user with shell metacharacters is rejected by pattern validation."""
        _make_key_and_store(persistence, "val_user")
        resp = client.post(
            "https://testserver/api/admin/keys/val_user/rotate",
            json={"deploy_to_node": True, "ssh_user": "root; rm -rf /"},
        )
        assert resp.status_code == 422

    def test_ssh_user_valid_default(
        self, client: TestClient, persistence: PersistenceManager,
    ) -> None:
        """Default ssh_user ('pi') is accepted."""
        _make_key_and_store(persistence, "val_default_user")
        resp = client.post(
            "https://testserver/api/admin/keys/val_default_user/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TestRotateKeyRBAC — viewer/analyst cannot rotate
# ---------------------------------------------------------------------------


class TestRotateKeyRBAC:
    """RBAC enforcement: only admin (master) key can access rotate endpoint."""

    def test_viewer_cannot_rotate(
        self,
        viewer_client: TestClient,
        persistence: PersistenceManager,
    ) -> None:
        """Viewer key is rejected (403) on rotate endpoint."""
        _make_key_and_store(persistence, "rbac_rot_key")
        resp = viewer_client.post(
            "https://testserver/api/admin/keys/rbac_rot_key/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 403

    def test_analyst_cannot_rotate(
        self,
        analyst_client: TestClient,
        persistence: PersistenceManager,
    ) -> None:
        """Analyst key is rejected (403) on rotate endpoint."""
        _make_key_and_store(persistence, "rbac_rot_key2")
        resp = analyst_client.post(
            "https://testserver/api/admin/keys/rbac_rot_key2/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 403

    def test_unauthenticated_cannot_rotate(self, bridge_app: FastAPI) -> None:
        """Request without any API key is rejected (401)."""
        unauth = TestClient(bridge_app)
        resp = unauth.post(
            "https://testserver/api/admin/keys/any_key/rotate",
            json={"deploy_to_node": False},
        )
        assert resp.status_code == 401
