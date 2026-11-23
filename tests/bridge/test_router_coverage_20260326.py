"""Integration tests for incidents, crypto, and sweep router endpoints —
covering CRUD, state transitions, filters, and error paths via the HTTP API.
"""

from __future__ import annotations

import os

os.environ.setdefault("BRIDGE_CSRF", "disabled")
os.environ.setdefault("BRIDGE_ENV", "test")

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_key(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    from sigrift.lib.security.credentials import generate_api_key, hash_credential
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app(tmp_path) -> FastAPI:
    from sigrift.bridge.app import create_test_app
    return create_test_app(tmp_path)


@pytest.fixture()
def persistence(app) -> PersistenceManager:
    return app.state.persistence


@pytest.fixture()
def admin_client(app, persistence) -> TestClient:
    key = _make_api_key(persistence, "rc_admin", "admin")
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def analyst_client(app, persistence) -> TestClient:
    key = _make_api_key(persistence, "rc_analyst", "analyst")
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def viewer_client(app, persistence) -> TestClient:
    key = _make_api_key(persistence, "rc_viewer", "viewer")
    return TestClient(app, headers={"X-API-Key": key})


# ===================================================================
# Incident Router Tests
# ===================================================================


class TestIncidentEndpoints:

    def test_create_incident(self, analyst_client: TestClient):
        resp = analyst_client.post("/api/incidents/", json={
            "title": "Unknown transmitter on 433 MHz",
            "severity": "critical",
            "description": "Detected unknown signal near secure area",
            "freq_hz": 433_920_000,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Unknown transmitter on 433 MHz"
        assert data["status"] == "open"
        assert data["severity"] == "critical"
        assert "incident_id" in data

    def test_list_incidents(self, analyst_client: TestClient):
        analyst_client.post("/api/incidents/", json={"title": "Inc A"})
        analyst_client.post("/api/incidents/", json={"title": "Inc B"})
        resp = analyst_client.get("/api/incidents/")
        assert resp.status_code == 200
        data = resp.json()
        assert "incidents" in data
        assert data["count"] >= 2
        assert data["total"] >= 2

    def test_get_incident(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Detail test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.get(f"/api/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["incident_id"] == inc_id

    def test_incident_not_found(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/incidents/nonexistent-id-999")
        assert resp.status_code == 404

    def test_incident_status_transition(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Status flow"})
        inc_id = create_resp.json()["incident_id"]

        # open -> investigating
        resp = analyst_client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "investigating",
            "note": "Starting investigation",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

        # investigating -> resolved
        resp = analyst_client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "resolved",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"

    def test_incident_invalid_status(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Bad status"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "invalid_phase",
        })
        assert resp.status_code == 422

    def test_add_note(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Note test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.post(f"/api/incidents/{inc_id}/notes", json={
            "note": "Signal intermittent, 2-second bursts at 15 dBm",
        })
        assert resp.status_code == 200
        assert resp.json()["event_type"] == "note"

    def test_add_note_not_found(self, analyst_client: TestClient):
        resp = analyst_client.post("/api/incidents/nonexistent/notes", json={
            "note": "Should fail",
        })
        assert resp.status_code == 404

    def test_link_detection(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Link test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.post(f"/api/incidents/{inc_id}/detections", json={
            "detection_id": "det-abc-123",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Verify linked
        resp2 = analyst_client.get(f"/api/incidents/{inc_id}/detections")
        assert resp2.status_code == 200
        assert "det-abc-123" in resp2.json()["detection_ids"]

    def test_incident_timeline(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Timeline test"})
        inc_id = create_resp.json()["incident_id"]
        analyst_client.post(f"/api/incidents/{inc_id}/notes", json={"note": "First note"})
        analyst_client.put(f"/api/incidents/{inc_id}/status", json={"status": "investigating"})

        resp = analyst_client.get(f"/api/incidents/{inc_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 3  # created + note + state_change
        types = [e["event_type"] for e in data["events"]]
        assert "created" in types
        assert "note" in types

    def test_resolve_incident(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Resolve test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.put(f"/api/incidents/{inc_id}/resolve", json={
            "resolution": "false_alarm",
            "resolution_note": "Known device identified",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "resolved"
        assert resp.json()["resolution"] == "false_alarm"

    def test_resolve_invalid_type(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Bad resolve"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.put(f"/api/incidents/{inc_id}/resolve", json={
            "resolution": "not_a_valid_type",
        })
        assert resp.status_code == 422

    def test_assign_incident(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Assign test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.put(f"/api/incidents/{inc_id}/assign", json={
            "assigned_to": "operator-alice",
        })
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == "operator-alice"

    def test_add_evidence(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/incidents/", json={"title": "Evidence test"})
        inc_id = create_resp.json()["incident_id"]
        resp = analyst_client.post(f"/api/incidents/{inc_id}/evidence", json={
            "evidence_type": "iq_capture",
            "reference": "capture-001",
            "description": "IQ capture at 433 MHz",
        })
        assert resp.status_code == 200
        assert resp.json()["evidence_type"] == "iq_capture"

    def test_sla_metrics(self, viewer_client: TestClient, analyst_client: TestClient):
        analyst_client.post("/api/incidents/", json={"title": "Metrics test"})
        resp = viewer_client.get("/api/incidents/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "open" in data
        assert "total" in data


# ===================================================================
# Decoded Messages Router Tests
# ===================================================================
# Crypto Router Tests
# ===================================================================


class TestCryptoEndpoints:

    def test_list_crypto_keys_returns_builtins(self, analyst_client: TestClient):
        """The key store is wired at startup with the builtin Meshtastic defaults."""
        resp = analyst_client.get("/api/crypto/keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert any(k["source"] == "builtin" for k in keys)
        assert all("key_material" not in k for k in keys)

    def test_import_crypto_key(self, admin_client: TestClient):
        resp = admin_client.post("/api/crypto/keys", json={
            "protocol": "meshtastic",
            "key_name": "default-key",
            "raw_key_hex": "0102030405060708090a0b0c0d0e0f10",
            "algorithm": "aes-128",
        })
        assert resp.status_code == 201
        assert resp.json()["key_id"]

    def test_import_then_revoke_crypto_key(self, admin_client: TestClient):
        resp = admin_client.post("/api/crypto/keys", json={
            "protocol": "dmr",
            "key_name": "revoke-me",
            "raw_key_hex": "0f" * 16,
            "algorithm": "aes-128",
        })
        key_id = resp.json()["key_id"]
        resp = admin_client.delete(f"/api/crypto/keys/{key_id}")
        assert resp.status_code == 200
        assert resp.json()["revoked"] == key_id

    def test_delete_unknown_crypto_key_404(self, admin_client: TestClient):
        resp = admin_client.delete("/api/crypto/keys/some-id")
        assert resp.status_code == 404

    def test_decrypt_garbage_payload_fails_cleanly(self, analyst_client: TestClient):
        resp = analyst_client.post("/api/crypto/decrypt", json={
            "payload_hex": "aabbccdd",
            "protocol": "meshtastic",
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is False


# ===================================================================
# Sweep Router Tests
# ===================================================================


class TestSweepEndpoints:

    def test_create_sweep(self, analyst_client: TestClient):
        resp = analyst_client.post("/api/sweeps/", json={
            "name": "Building A Floor 3",
            "location": "Building A, 3rd floor conference rooms",
            "scope_description": "Full TSCM sweep",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Building A Floor 3"
        assert data["phase"] == "pre_assessment"
        assert "sweep_id" in data

    def test_list_sweeps(self, analyst_client: TestClient):
        analyst_client.post("/api/sweeps/", json={"name": "Sweep A"})
        analyst_client.post("/api/sweeps/", json={"name": "Sweep B"})
        resp = analyst_client.get("/api/sweeps/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 2

    def test_get_sweep(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Detail sweep"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.get(f"/api/sweeps/{sweep_id}")
        assert resp.status_code == 200
        assert resp.json()["sweep_id"] == sweep_id

    def test_sweep_not_found(self, viewer_client: TestClient):
        resp = viewer_client.get("/api/sweeps/nonexistent-sweep")
        assert resp.status_code == 404

    def test_sweep_phase_transition(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Phase test"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.put(f"/api/sweeps/{sweep_id}/phase", json={
            "phase": "active",
        })
        assert resp.status_code == 200
        assert resp.json()["phase"] == "active"

    def test_sweep_invalid_phase(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Bad phase"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.put(f"/api/sweeps/{sweep_id}/phase", json={
            "phase": "nonexistent_phase",
        })
        assert resp.status_code == 422

    def test_add_zone(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Zone test"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.post(f"/api/sweeps/{sweep_id}/zones", json={
            "zone_name": "Conference Room A",
        })
        assert resp.status_code == 201
        assert resp.json()["zone_name"] == "Conference Room A"

    def test_get_zones(self, analyst_client: TestClient, viewer_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Zones list"})
        sweep_id = create_resp.json()["sweep_id"]
        analyst_client.post(f"/api/sweeps/{sweep_id}/zones", json={"zone_name": "Room 1"})
        analyst_client.post(f"/api/sweeps/{sweep_id}/zones", json={"zone_name": "Room 2"})
        resp = viewer_client.get(f"/api/sweeps/{sweep_id}/zones")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_update_zone_status(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Zone status"})
        sweep_id = create_resp.json()["sweep_id"]
        zone_resp = analyst_client.post(f"/api/sweeps/{sweep_id}/zones", json={
            "zone_name": "Lobby",
        })
        zone_id = zone_resp.json()["zone_id"]
        resp = analyst_client.put(f"/api/sweeps/{sweep_id}/zones/{zone_id}/status", json={
            "status": "cleared",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "cleared"

    def test_sweep_link_detection(self, analyst_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Link det"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.post(f"/api/sweeps/{sweep_id}/detections", json={
            "detection_id": "det-sweep-001",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_sweep_link_incident(self, analyst_client: TestClient):
        # Create an incident first
        inc_resp = analyst_client.post("/api/incidents/", json={"title": "Sweep incident"})
        inc_id = inc_resp.json()["incident_id"]

        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Link inc"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = analyst_client.post(f"/api/sweeps/{sweep_id}/incidents", json={
            "incident_id": inc_id,
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_sweep_summary(self, analyst_client: TestClient, viewer_client: TestClient):
        create_resp = analyst_client.post("/api/sweeps/", json={"name": "Summary test"})
        sweep_id = create_resp.json()["sweep_id"]
        resp = viewer_client.get(f"/api/sweeps/{sweep_id}/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert "sweep_id" in data or "name" in data


# ===================================================================
# MFA Backup Code Regeneration (session-only endpoint)
# ===================================================================


class TestMFARegenBackupCodes:
    """MFA endpoints are now handled exclusively by the Rust gateway.

    These tests verify that the Python app correctly returns 404/405
    for MFA routes, confirming they are NOT mounted here.
    """

    def test_mfa_not_mounted_regenerate(self, analyst_client: TestClient):
        """MFA regenerate-backup-codes should not be served by Python."""
        resp = analyst_client.post("/api/auth/mfa/regenerate-backup-codes", json={
            "totp_code": "123456",
        })
        assert resp.status_code in (404, 405)

    def test_mfa_not_mounted_setup(self, analyst_client: TestClient):
        """MFA setup should not be served by Python."""
        resp = analyst_client.post("/api/auth/mfa/setup")
        assert resp.status_code in (404, 405)
