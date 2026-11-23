"""Tests for incident lifecycle management — storage, API, state machine,
evidence linking, timeline, and SLA metrics.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_api_key(persistence: PersistenceManager, key_id: str, role: str = "admin") -> str:
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
def app(tmp_path):
    from sigrift.bridge.app import create_test_app
    return create_test_app(tmp_path)


@pytest.fixture()
def persistence(app) -> PersistenceManager:
    return app.state.persistence


@pytest.fixture()
def client(app, persistence):
    admin_key = _make_api_key(persistence, "inc_admin", "admin")
    return TestClient(app, headers={"X-API-Key": admin_key})


@pytest.fixture()
def analyst_client(app, persistence):
    key = _make_api_key(persistence, "inc_analyst", "analyst")
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def viewer_client(app, persistence):
    key = _make_api_key(persistence, "inc_viewer", "viewer")
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def incident_store(app):
    return app.state.incident_store


# ---------------------------------------------------------------------------
# Storage layer tests
# ---------------------------------------------------------------------------


class TestIncidentStore:

    def test_create_incident(self, incident_store):
        inc = incident_store.create_incident(
            title="Test Incident",
            severity="critical",
            description="Found unknown transmitter",
            node_id="node-1",
            freq_hz=433_920_000,
        )
        assert inc["title"] == "Test Incident"
        assert inc["status"] == "open"
        assert inc["severity"] == "critical"
        assert inc["incident_id"]
        assert isinstance(inc["incident_id"], str)

    def test_get_incident(self, incident_store):
        inc = incident_store.create_incident(title="Get Test")
        fetched = incident_store.get_incident(inc["incident_id"])
        assert fetched is not None
        assert isinstance(fetched, dict)
        assert fetched["title"] == "Get Test"

    def test_get_nonexistent(self, incident_store):
        assert incident_store.get_incident("nonexistent") is None

    def test_list_incidents(self, incident_store):
        incident_store.create_incident(title="Inc A")
        incident_store.create_incident(title="Inc B")
        results = incident_store.list_incidents()
        assert len(results) >= 2
        assert all(isinstance(r, dict) for r in results)

    def test_list_filter_status(self, incident_store):
        incident_store.create_incident(title="Open Inc")
        results = incident_store.list_incidents(status="open")
        assert all(r["status"] == "open" for r in results)

    def test_assign_incident(self, incident_store):
        inc = incident_store.create_incident(title="Assign Test")
        result = incident_store.assign_incident(
            inc["incident_id"], "operator-1", actor="admin",
        )
        assert result["assigned_to"] == "operator-1"

    def test_update_status(self, incident_store):
        inc = incident_store.create_incident(title="Status Test")
        result = incident_store.update_status(
            inc["incident_id"], "investigating", actor="admin",
        )
        assert result["status"] == "investigating"

    def test_invalid_status(self, incident_store):
        inc = incident_store.create_incident(title="Bad Status")
        result = incident_store.update_status(
            inc["incident_id"], "invalid_state",
        )
        assert result is None

    def test_resolve_incident(self, incident_store):
        inc = incident_store.create_incident(title="Resolve Test")
        result = incident_store.resolve_incident(
            inc["incident_id"], "confirmed_threat",
            resolution_note="Physical device recovered",
        )
        assert result["status"] == "resolved"
        assert result["resolution"] == "confirmed_threat"
        assert result["resolved_at"] is not None
        assert isinstance(result["resolved_at"], str)

    def test_invalid_resolution(self, incident_store):
        inc = incident_store.create_incident(title="Bad Resolution")
        result = incident_store.resolve_incident(
            inc["incident_id"], "invalid_type",
        )
        assert result is None

    def test_add_note(self, incident_store):
        inc = incident_store.create_incident(title="Note Test")
        result = incident_store.add_note(
            inc["incident_id"], "Signal intermittent, 2-second bursts",
        )
        assert result["event_type"] == "note"

    def test_add_evidence(self, incident_store):
        inc = incident_store.create_incident(title="Evidence Test")
        result = incident_store.add_evidence(
            inc["incident_id"],
            evidence_type="iq_capture",
            reference="capture-001",
            description="IQ capture at 433 MHz",
        )
        assert result["evidence_type"] == "iq_capture"

    def test_link_detection(self, incident_store):
        inc = incident_store.create_incident(title="Link Test")
        ok = incident_store.link_detection(
            inc["incident_id"], "det-001",
        )
        assert ok is True
        ids = incident_store.get_linked_detections(inc["incident_id"])
        assert "det-001" in ids

    def test_link_detection_idempotent(self, incident_store):
        inc = incident_store.create_incident(title="Idempotent Link")
        incident_store.link_detection(inc["incident_id"], "det-002")
        incident_store.link_detection(inc["incident_id"], "det-002")
        ids = incident_store.get_linked_detections(inc["incident_id"])
        assert ids.count("det-002") == 1

    def test_timeline(self, incident_store):
        inc = incident_store.create_incident(title="Timeline Test")
        incident_store.add_note(inc["incident_id"], "First note")
        incident_store.update_status(inc["incident_id"], "investigating")
        incident_store.add_evidence(
            inc["incident_id"], "photo", "photo-001",
        )
        timeline = incident_store.get_timeline(inc["incident_id"])
        assert len(timeline) >= 4  # created + note + state_change + evidence
        assert all(isinstance(e, dict) for e in timeline)
        types = [e["event_type"] for e in timeline]
        assert "created" in types
        assert "note" in types
        assert "state_change" in types
        assert "evidence" in types

    def test_sla_metrics(self, incident_store):
        incident_store.create_incident(title="Open Inc")
        inc2 = incident_store.create_incident(title="Resolved Inc")
        incident_store.resolve_incident(inc2["incident_id"], "false_alarm")
        metrics = incident_store.get_sla_metrics()
        assert isinstance(metrics, dict)
        assert metrics["open"] >= 1
        assert isinstance(metrics["open"], int)
        assert metrics["resolved"] >= 1
        assert isinstance(metrics["resolved"], int)
        assert metrics["total"] >= 2
        assert isinstance(metrics["total"], int)

    def test_count_incidents(self, incident_store):
        incident_store.create_incident(title="Count Test")
        count = incident_store.count_incidents()
        assert isinstance(count, int)
        assert count >= 1


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestIncidentEndpoints:

    def test_create_via_api(self, client):
        resp = client.post("/api/incidents/", json={
            "title": "API Incident",
            "severity": "critical",
            "freq_hz": 433_920_000,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "API Incident"
        assert data["status"] == "open"

    def test_list_via_api(self, client):
        client.post("/api/incidents/", json={"title": "List Test"})
        resp = client.get("/api/incidents/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)

    def test_get_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Get Test"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.get(f"/api/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["title"] == "Get Test"

    def test_get_not_found(self, client):
        resp = client.get("/api/incidents/nonexistent")
        assert resp.status_code == 404

    def test_assign_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Assign API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.put(f"/api/incidents/{inc_id}/assign", json={
            "assigned_to": "operator-1",
        })
        assert resp.status_code == 200
        assert resp.json()["assigned_to"] == "operator-1"

    def test_update_status_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Status API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "investigating",
            "note": "Starting investigation",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "investigating"

    def test_invalid_status_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Bad Status"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "invalid",
        })
        assert resp.status_code == 422

    def test_resolve_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Resolve API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.put(f"/api/incidents/{inc_id}/resolve", json={
            "resolution": "confirmed_threat",
            "resolution_note": "Device found and removed",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "resolved"
        assert data["resolution"] == "confirmed_threat"

    def test_invalid_resolution_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Bad Resolve"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.put(f"/api/incidents/{inc_id}/resolve", json={
            "resolution": "invalid_type",
        })
        assert resp.status_code == 422

    def test_add_note_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Note API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.post(f"/api/incidents/{inc_id}/notes", json={
            "note": "Signal appears intermittent",
        })
        assert resp.status_code == 200
        assert resp.json()["event_type"] == "note"

    def test_add_evidence_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Evidence API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.post(f"/api/incidents/{inc_id}/evidence", json={
            "evidence_type": "iq_capture",
            "reference": "cap-001",
            "description": "IQ at 433 MHz",
        })
        assert resp.status_code == 200
        assert resp.json()["evidence_type"] == "iq_capture"

    def test_link_detection_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Link API"})
        inc_id = create_resp.json()["incident_id"]
        resp = client.post(f"/api/incidents/{inc_id}/detections", json={
            "detection_id": "det-api-001",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_get_linked_detections_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Links API"})
        inc_id = create_resp.json()["incident_id"]
        client.post(f"/api/incidents/{inc_id}/detections", json={
            "detection_id": "det-api-002",
        })
        resp = client.get(f"/api/incidents/{inc_id}/detections")
        assert resp.status_code == 200
        data = resp.json()
        assert "det-api-002" in data["detection_ids"]

    def test_timeline_via_api(self, client):
        create_resp = client.post("/api/incidents/", json={"title": "Timeline API"})
        inc_id = create_resp.json()["incident_id"]
        client.post(f"/api/incidents/{inc_id}/notes", json={"note": "Test"})
        resp = client.get(f"/api/incidents/{inc_id}/timeline")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 2  # created + note
        assert isinstance(data["count"], int)

    def test_sla_metrics_via_api(self, client):
        client.post("/api/incidents/", json={"title": "Metric Test"})
        resp = client.get("/api/incidents/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "open" in data
        assert isinstance(data["open"], int)
        assert "total" in data
        assert isinstance(data["total"], int)

    def test_full_lifecycle(self, client):
        """Test the complete incident lifecycle: create -> assign -> investigate -> resolve -> close."""
        # Create
        resp = client.post("/api/incidents/", json={
            "title": "Full Lifecycle Test",
            "severity": "critical",
            "freq_hz": 433_920_000,
            "signal_class": "fm",
        })
        assert resp.status_code == 201
        inc_id = resp.json()["incident_id"]

        # Assign
        resp = client.put(f"/api/incidents/{inc_id}/assign", json={
            "assigned_to": "operator-1",
        })
        assert resp.json()["assigned_to"] == "operator-1"

        # Investigate
        resp = client.put(f"/api/incidents/{inc_id}/status", json={
            "status": "investigating",
        })
        assert resp.json()["status"] == "investigating"

        # Add note
        client.post(f"/api/incidents/{inc_id}/notes", json={
            "note": "Found intermittent OOK signal",
        })

        # Add evidence
        client.post(f"/api/incidents/{inc_id}/evidence", json={
            "evidence_type": "iq_capture",
            "reference": "iq-001",
        })

        # Link detection
        client.post(f"/api/incidents/{inc_id}/detections", json={
            "detection_id": "det-lifecycle-001",
        })

        # Resolve
        resp = client.put(f"/api/incidents/{inc_id}/resolve", json={
            "resolution": "confirmed_threat",
            "resolution_note": "Covert mic found behind ceiling tile",
        })
        assert resp.json()["status"] == "resolved"
        assert resp.json()["resolution"] == "confirmed_threat"

        # Check timeline
        resp = client.get(f"/api/incidents/{inc_id}/timeline")
        events = resp.json()["events"]
        types = [e["event_type"] for e in events]
        assert "created" in types
        assert "assigned" in types
        assert "state_change" in types
        assert "note" in types
        assert "evidence" in types
        assert "detection_linked" in types
        assert "resolved" in types

    def test_viewer_can_read(self, viewer_client, client):
        """Viewers can list and read incidents."""
        client.post("/api/incidents/", json={"title": "Viewer Read"})
        resp = viewer_client.get("/api/incidents/")
        assert resp.status_code == 200

    def test_list_filter_status_via_api(self, client):
        client.post("/api/incidents/", json={"title": "Filter Open"})
        resp = client.get("/api/incidents/?status=open")
        assert resp.status_code == 200
        for inc in resp.json()["incidents"]:
            assert inc["status"] == "open"
