"""Tests for new system_config.py endpoints.

Covers the uncommitted additions:
  - Bluetooth device whitelist CRUD (GET/POST/DELETE /api/admin/bt-whitelist)
  - Config snapshots CRUD (GET/POST/DELETE /api/admin/config-snapshots)
  - Config snapshot restore (POST /api/admin/config-snapshots/{id}/restore)
  - Auto-rescan configuration (GET/POST /api/admin/auto-rescan)
  - Auto-snapshot side-effect on PUT /api/admin/detection-config
  - Expanded table list in GET /api/admin/stats
  - RBAC: admin-only endpoints reject unauthenticated and non-admin callers
  - Input validation and error paths
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
) -> str:
    """Create an API key with a given role in persistence and return raw key."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "sc_viewer_key", role="viewer")


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def unauth_client(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


# =========================================================================
# Bluetooth Whitelist
# =========================================================================


class TestBtWhitelistList:
    """GET /api/admin/bt-whitelist"""

    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/admin/bt-whitelist")
        assert resp.status_code == 200
        data = resp.json()
        assert data["whitelist"] == []

    def test_list_after_add(self, client: TestClient):
        client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:01",
        })
        resp = client.get("/api/admin/bt-whitelist")
        assert resp.status_code == 200
        assert len(resp.json()["whitelist"]) == 1

    def test_list_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/admin/bt-whitelist")
        assert resp.status_code == 401

    def test_list_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/admin/bt-whitelist")
        assert resp.status_code == 403


class TestBtWhitelistAdd:
    """POST /api/admin/bt-whitelist"""

    def test_add_valid(self, client: TestClient):
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:FF",
            "device_name": "Test BT Device",
            "notes": "Lab sensor",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        entry = data["entry"]
        assert entry["device_addr"] == "AA:BB:CC:DD:EE:FF"
        assert entry["device_name"] == "Test BT Device"
        assert entry["notes"] == "Lab sensor"
        assert isinstance(entry["id"], str)
        assert isinstance(entry["added_at"], str)

    def test_add_minimal_fields(self, client: TestClient):
        """Only device_addr is required."""
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "11:22:33:44:55:66",
        })
        assert resp.status_code == 201
        entry = resp.json()["entry"]
        assert entry["device_name"] == ""
        assert entry["notes"] == ""

    def test_add_invalid_format(self, client: TestClient):
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "not-a-mac",
        })
        assert resp.status_code == 400
        assert "Invalid device address" in resp.json()["detail"]

    def test_add_invalid_format_too_short(self, client: TestClient):
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC",
        })
        assert resp.status_code == 400

    def test_add_stores_name_as_given(self, client: TestClient):
        # Like the device it names: stored as given, escaped where shown.
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:03",
            "device_name": " <script>alert(1)</script> Joe's ",
        })
        assert resp.status_code == 201
        assert resp.json()["entry"]["device_name"] == "<script>alert(1)</script> Joe's"

    def test_add_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:FF",
        })
        assert resp.status_code == 401

    def test_add_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:FF",
        })
        assert resp.status_code == 403


class TestBtWhitelistRemove:
    """DELETE /api/admin/bt-whitelist/{entry_id}"""

    def test_remove_existing(self, client: TestClient):
        resp = client.post("/api/admin/bt-whitelist", json={
            "device_addr": "AA:BB:CC:DD:EE:FF",
        })
        entry_id = resp.json()["entry"]["id"]
        resp = client.delete(f"/api/admin/bt-whitelist/{entry_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deleted"
        assert data["entry_id"] == entry_id

        # Confirm it is removed
        resp = client.get("/api/admin/bt-whitelist")
        assert len(resp.json()["whitelist"]) == 0

    def test_remove_not_found(self, client: TestClient):
        resp = client.delete("/api/admin/bt-whitelist/does_not_exist")
        assert resp.status_code == 404

    def test_remove_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.delete("/api/admin/bt-whitelist/fake_id")
        assert resp.status_code == 401

    def test_remove_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.delete("/api/admin/bt-whitelist/fake_id")
        assert resp.status_code == 403


# =========================================================================
# Config Snapshots
# =========================================================================


class TestConfigSnapshotsList:
    """GET /api/admin/config-snapshots"""

    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/admin/config-snapshots")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["snapshots"], list)

    def test_list_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/admin/config-snapshots")
        assert resp.status_code == 401

    def test_list_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/admin/config-snapshots")
        assert resp.status_code == 403


class TestConfigSnapshotCreate:
    """POST /api/admin/config-snapshots"""

    def test_create_no_body(self, client: TestClient):
        resp = client.post("/api/admin/config-snapshots")
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "created"
        assert isinstance(data["snapshot_id"], int)

    def test_create_with_description(self, client: TestClient):
        resp = client.post("/api/admin/config-snapshots", json={
            "description": "Before policy change",
        })
        assert resp.status_code == 201
        assert resp.json()["status"] == "created"

    def test_create_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.post("/api/admin/config-snapshots")
        assert resp.status_code == 401

    def test_create_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.post("/api/admin/config-snapshots")
        assert resp.status_code == 403


class TestConfigSnapshotDelete:
    """DELETE /api/admin/config-snapshots/{snapshot_id}"""

    def test_delete_existing(self, client: TestClient):
        create_resp = client.post("/api/admin/config-snapshots", json={
            "description": "to delete",
        })
        snap_id = create_resp.json()["snapshot_id"]
        resp = client.delete(f"/api/admin/config-snapshots/{snap_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "deleted"
        assert data["snapshot_id"] == snap_id

    def test_delete_not_found(self, client: TestClient):
        resp = client.delete("/api/admin/config-snapshots/999999")
        assert resp.status_code == 404

    def test_delete_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.delete("/api/admin/config-snapshots/1")
        assert resp.status_code == 401

    def test_delete_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.delete("/api/admin/config-snapshots/1")
        assert resp.status_code == 403


# =========================================================================
# Auto-Rescan Configuration
# =========================================================================


class TestAutoRescanGet:
    """GET /api/admin/auto-rescan"""

    def test_get_default(self, client: TestClient):
        resp = client.get("/api/admin/auto-rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["auto_rescan"], dict)
        ar = data["auto_rescan"]
        assert ar["enabled"] is False
        assert ar["confidence_threshold"] == 0.5
        assert ar["max_retries"] == 2

    def test_get_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/admin/auto-rescan")
        assert resp.status_code == 401

    def test_get_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/admin/auto-rescan")
        assert resp.status_code == 403


class TestAutoRescanSet:
    """POST /api/admin/auto-rescan"""

    def test_set_enabled(self, client: TestClient):
        resp = client.post("/api/admin/auto-rescan", json={
            "enabled": True,
            "confidence_threshold": 0.3,
            "max_retries": 4,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        ar = data["auto_rescan"]
        assert ar["enabled"] is True
        assert ar["confidence_threshold"] == 0.3
        assert ar["max_retries"] == 4

    def test_set_persists(self, client: TestClient):
        client.post("/api/admin/auto-rescan", json={
            "enabled": True,
            "confidence_threshold": 0.7,
            "max_retries": 3,
        })
        resp = client.get("/api/admin/auto-rescan")
        assert resp.status_code == 200
        ar = resp.json()["auto_rescan"]
        assert ar["enabled"] is True
        assert ar["confidence_threshold"] == 0.7
        assert ar["max_retries"] == 3

    def test_set_threshold_boundary_zero(self, client: TestClient):
        resp = client.post("/api/admin/auto-rescan", json={
            "confidence_threshold": 0.0,
        })
        assert resp.status_code == 200
        assert resp.json()["auto_rescan"]["confidence_threshold"] == 0.0

    def test_set_threshold_boundary_one(self, client: TestClient):
        resp = client.post("/api/admin/auto-rescan", json={
            "confidence_threshold": 1.0,
        })
        assert resp.status_code == 200
        assert resp.json()["auto_rescan"]["confidence_threshold"] == 1.0

    def test_set_threshold_too_high(self, client: TestClient):
        resp = client.post("/api/admin/auto-rescan", json={
            "confidence_threshold": 1.5,
        })
        assert resp.status_code == 422

    def test_set_threshold_negative(self, client: TestClient):
        resp = client.post("/api/admin/auto-rescan", json={
            "confidence_threshold": -0.1,
        })
        assert resp.status_code == 422

    def test_set_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.post("/api/admin/auto-rescan", json={
            "enabled": True,
        })
        assert resp.status_code == 401

    def test_set_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.post("/api/admin/auto-rescan", json={
            "enabled": True,
        })
        assert resp.status_code == 403


# =========================================================================
# BT whitelist integration
# =========================================================================


class TestBtWhitelistIntegration:
    """End-to-end scenarios for BT whitelist management."""

    def test_add_remove_cycle(self, client: TestClient):
        """Add multiple devices, verify list, remove one, verify updated list."""
        addrs = ["11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"]
        ids = []
        for addr in addrs:
            r = client.post("/api/admin/bt-whitelist", json={"device_addr": addr})
            assert r.status_code == 201
            ids.append(r.json()["entry"]["id"])

        # All three present
        wl = client.get("/api/admin/bt-whitelist").json()["whitelist"]
        assert len(wl) == 3

        # Remove middle one
        client.delete(f"/api/admin/bt-whitelist/{ids[1]}")
        wl = client.get("/api/admin/bt-whitelist").json()["whitelist"]
        assert len(wl) == 2


class TestConfigSnapshotIntegration:
    """End-to-end snapshot create / list / get / delete cycle."""

    def test_full_lifecycle(self, client: TestClient):
        # Create two snapshots
        r1 = client.post("/api/admin/config-snapshots", json={"description": "first"})
        assert r1.status_code == 201
        id1 = r1.json()["snapshot_id"]

        r2 = client.post("/api/admin/config-snapshots", json={"description": "second"})
        assert r2.status_code == 201
        id2 = r2.json()["snapshot_id"]

        # List should have both
        snaps = client.get("/api/admin/config-snapshots").json()["snapshots"]
        snap_ids = [s["id"] for s in snaps]
        assert id1 in snap_ids
        assert id2 in snap_ids

        # Delete first
        dr = client.delete(f"/api/admin/config-snapshots/{id1}")
        assert dr.status_code == 200

        # First is gone, second remains
        snaps = client.get("/api/admin/config-snapshots").json()["snapshots"]
        snap_ids = [s["id"] for s in snaps]
        assert id1 not in snap_ids
        assert id2 in snap_ids


# =========================================================================
# Session Binding (admin toggle; gateway reads env var at startup)
# =========================================================================


class TestSessionBindingGet:
    """GET /api/admin/session-binding"""

    def test_get_default_when_no_env_no_saved(
        self, client: TestClient, monkeypatch
    ):
        monkeypatch.delenv("BRIDGE_SESSION_BINDING", raising=False)
        resp = client.get("/api/admin/session-binding")
        assert resp.status_code == 200
        data = resp.json()
        assert data["saved"] == "none"
        assert data["gateway_active"] == "unset"
        assert data["restart_required"] is False
        assert data["valid_modes"] == ["strict", "ip", "warn", "none"]
        assert data["default"] == "none"

    def test_get_reflects_env_when_no_saved(
        self, client: TestClient, monkeypatch
    ):
        """With no admin save, saved reflects the gateway's env var."""
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", "ip")
        resp = client.get("/api/admin/session-binding")
        assert resp.status_code == 200
        data = resp.json()
        assert data["saved"] == "ip"
        assert data["gateway_active"] == "ip"
        assert data["restart_required"] is False

    def test_get_flags_drift(self, client: TestClient, monkeypatch):
        """Saved preference differs from gateway env → restart required."""
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", "none")
        client.put(
            "/api/admin/session-binding",
            json={"mode": "strict"},
        )
        resp = client.get("/api/admin/session-binding")
        assert resp.status_code == 200
        data = resp.json()
        assert data["saved"] == "strict"
        assert data["gateway_active"] == "none"
        assert data["restart_required"] is True

    def test_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/admin/session-binding")
        assert resp.status_code == 401

    def test_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/admin/session-binding")
        assert resp.status_code == 403


class TestSessionBindingPut:
    """PUT /api/admin/session-binding"""

    def test_put_valid_mode_persists(self, client: TestClient):
        resp = client.put(
            "/api/admin/session-binding",
            json={"mode": "strict"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["saved"] == "strict"

        # Re-read: persisted
        get_resp = client.get("/api/admin/session-binding")
        assert get_resp.json()["saved"] == "strict"

    def test_put_all_valid_modes(self, client: TestClient):
        for mode in ["strict", "ip", "warn", "none"]:
            resp = client.put(
                "/api/admin/session-binding",
                json={"mode": mode},
            )
            assert resp.status_code == 200, f"mode={mode}"
            assert resp.json()["saved"] == mode

    def test_put_normalizes_case(self, client: TestClient):
        resp = client.put(
            "/api/admin/session-binding",
            json={"mode": "STRICT"},
        )
        assert resp.status_code == 200
        assert resp.json()["saved"] == "strict"

    def test_put_rejects_invalid_mode(self, client: TestClient):
        resp = client.put(
            "/api/admin/session-binding",
            json={"mode": "invalid-mode"},
        )
        assert resp.status_code == 400
        assert "must be one of" in resp.json()["detail"]

    def test_put_rejects_extra_fields(self, client: TestClient):
        """Pydantic `extra: forbid` guards the payload schema."""
        resp = client.put(
            "/api/admin/session-binding",
            json={"mode": "strict", "bonus_field": "x"},
        )
        assert resp.status_code == 422

    def test_put_requires_auth(self, unauth_client: TestClient):
        resp = unauth_client.put(
            "/api/admin/session-binding",
            json={"mode": "strict"},
        )
        assert resp.status_code == 401

    def test_put_requires_admin(self, viewer_client: TestClient):
        resp = viewer_client.put(
            "/api/admin/session-binding",
            json={"mode": "strict"},
        )
        assert resp.status_code == 403

    def test_put_logs_audit_on_change(self, client: TestClient, detection_store):
        """Mode changes are recorded in the audit log."""
        client.put(
            "/api/admin/session-binding",
            json={"mode": "ip"},
        )
        # Persistence default on a fresh store is "none" (no env); change
        # to "ip" should produce an audit entry.
        entries = detection_store.get_audit_log(limit=20)
        assert any(
            e.get("action") == "admin_update_session_binding"
            and (e.get("details") or {}).get("new") == "ip"
            for e in entries
        )


class TestSessionBindingPersistence:
    """PersistenceManager.{get,set}_session_binding"""

    def test_default_is_none(self, persistence: PersistenceManager, monkeypatch):
        monkeypatch.delenv("BRIDGE_SESSION_BINDING", raising=False)
        assert persistence.get_session_binding() == "none"

    def test_env_fallback(self, persistence: PersistenceManager, monkeypatch):
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", "warn")
        assert persistence.get_session_binding() == "warn"

    def test_saved_wins_over_env(
        self, persistence: PersistenceManager, monkeypatch
    ):
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", "ip")
        persistence.set_session_binding("strict")
        assert persistence.get_session_binding() == "strict"

    def test_set_rejects_invalid(self, persistence: PersistenceManager):
        with pytest.raises(ValueError, match="invalid session binding mode"):
            persistence.set_session_binding("totally-invalid")

    def test_set_accepts_all_valid_modes(
        self, persistence: PersistenceManager
    ):
        for mode in ["strict", "ip", "warn", "none"]:
            persistence.set_session_binding(mode)
            assert persistence.get_session_binding() == mode
