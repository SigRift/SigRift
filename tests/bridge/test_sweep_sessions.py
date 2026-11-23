"""Tests for TSCM sweep session lifecycle.

Covers: CRUD, phase transitions, zone state machine,
detection/incident linking, summary stats, and API endpoints.
"""

from __future__ import annotations

import os

os.environ.setdefault("BRIDGE_CSRF", "disabled")

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.sweeps import (
    SWEEP_PHASES,
    ZONE_STATUSES,
    SweepStore,
)
from sigrift.bridge.storage.incidents import IncidentStore


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def ctx(detection_store: DetectionStore):
    return detection_store._ctx


@pytest.fixture
def sweep_store(ctx) -> SweepStore:
    return SweepStore(ctx)


@pytest.fixture
def incident_store(ctx) -> IncidentStore:
    return IncidentStore(ctx)


# ── Storage Unit Tests ────────────────────────────────────────────────────


class TestSweepStore:
    """Unit tests for SweepStore CRUD and state machine."""

    def test_create_sweep(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(
            name="Office Sweep Q1",
            location="Building A, Floor 3",
            scope_description="Full RF sweep of executive offices",
            threat_profile="corporate_espionage",
        )
        assert sweep["name"] == "Office Sweep Q1"
        assert sweep["location"] == "Building A, Floor 3"
        assert sweep["phase"] == "pre_assessment"
        assert sweep["status"] == "active"
        assert sweep["sweep_id"]
        assert sweep["start_time"]

    def test_get_sweep(self, sweep_store: SweepStore) -> None:
        created = sweep_store.create_sweep(name="Test Sweep")
        fetched = sweep_store.get_sweep(created["sweep_id"])
        assert fetched is not None
        assert fetched["name"] == "Test Sweep"

    def test_get_sweep_not_found(self, sweep_store: SweepStore) -> None:
        assert sweep_store.get_sweep("nonexistent") is None

    def test_list_sweeps(self, sweep_store: SweepStore) -> None:
        sweep_store.create_sweep(name="Sweep A")
        sweep_store.create_sweep(name="Sweep B")
        result = sweep_store.list_sweeps()
        assert len(result) == 2

    def test_list_sweeps_filter_phase(self, sweep_store: SweepStore) -> None:
        s1 = sweep_store.create_sweep(name="Sweep Pre")
        s2 = sweep_store.create_sweep(name="Sweep Active")
        sweep_store.update_phase(s2["sweep_id"], "active")

        pre = sweep_store.list_sweeps(phase="pre_assessment")
        active = sweep_store.list_sweeps(phase="active")
        assert len(pre) == 1
        assert len(active) == 1

    def test_count_sweeps(self, sweep_store: SweepStore) -> None:
        for i in range(3):
            sweep_store.create_sweep(name=f"Sweep {i}")
        assert sweep_store.count_sweeps() == 3

    def test_phase_transitions(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Phase Test")
        sid = sweep["sweep_id"]

        for phase in ("active", "analysis", "reporting", "closed"):
            updated = sweep_store.update_phase(sid, phase)
            assert updated["phase"] == phase

        # Closed sweep has end_time and completed status
        final = sweep_store.get_sweep(sid)
        assert final["end_time"] is not None
        assert final["status"] == "completed"

    def test_invalid_phase_rejected(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Invalid Phase")
        result = sweep_store.update_phase(sweep["sweep_id"], "invalid_phase")
        assert result is None

    def test_add_zone(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Zone Test")
        zone = sweep_store.add_zone(sweep["sweep_id"], "Executive Suite")
        assert zone["zone_name"] == "Executive Suite"
        assert zone["status"] == "pending"
        assert zone["zone_id"]

    def test_update_zone_status(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Zone Status")
        zone = sweep_store.add_zone(sweep["sweep_id"], "Server Room")

        # pending → sweeping
        updated = sweep_store.update_zone_status(zone["zone_id"], "sweeping")
        assert updated["status"] == "sweeping"

        # sweeping → cleared
        cleared = sweep_store.update_zone_status(zone["zone_id"], "cleared")
        assert cleared["status"] == "cleared"
        assert cleared["cleared_at"] is not None

    def test_zone_flagged_with_reason(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Flag Test")
        zone = sweep_store.add_zone(sweep["sweep_id"], "Conference Room B")

        flagged = sweep_store.update_zone_status(
            zone["zone_id"], "flagged",
            flagged_reason="Unknown RF emission at 433 MHz",
        )
        assert flagged["status"] == "flagged"
        assert flagged["flagged_reason"] == "Unknown RF emission at 433 MHz"

    def test_invalid_zone_status_rejected(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Invalid Zone")
        zone = sweep_store.add_zone(sweep["sweep_id"], "Test Zone")
        result = sweep_store.update_zone_status(zone["zone_id"], "invalid")
        assert result is None

    def test_get_zones(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Multi Zone")
        sweep_store.add_zone(sweep["sweep_id"], "Zone A")
        sweep_store.add_zone(sweep["sweep_id"], "Zone B")
        sweep_store.add_zone(sweep["sweep_id"], "Zone C")

        zones = sweep_store.get_zones(sweep["sweep_id"])
        assert len(zones) == 3
        names = [z["zone_name"] for z in zones]
        assert "Zone A" in names
        assert "Zone B" in names
        assert "Zone C" in names

    def test_link_detection(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Det Link")
        ok = sweep_store.link_detection(sweep["sweep_id"], "det-001")
        assert ok is True

        linked = sweep_store.get_linked_detections(sweep["sweep_id"])
        assert "det-001" in linked

    def test_link_detection_idempotent(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Det Idempotent")
        sid = sweep["sweep_id"]
        sweep_store.link_detection(sid, "det-dup")
        sweep_store.link_detection(sid, "det-dup")

        linked = sweep_store.get_linked_detections(sid)
        assert linked.count("det-dup") == 1

    def test_link_detection_with_zone(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Det Zone Link")
        zone = sweep_store.add_zone(sweep["sweep_id"], "Zone X")

        sweep_store.link_detection(
            sweep["sweep_id"], "det-z1", zone_id=zone["zone_id"],
        )
        # Zone anomaly_count should be incremented
        zones = sweep_store.get_zones(sweep["sweep_id"])
        z = next(z for z in zones if z["zone_id"] == zone["zone_id"])
        assert z["anomaly_count"] == 1

    def test_link_incident(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Inc Link")
        ok = sweep_store.link_incident(sweep["sweep_id"], "inc-001")
        assert ok is True

        linked = sweep_store.get_linked_incidents(sweep["sweep_id"])
        assert "inc-001" in linked

    def test_link_incident_idempotent(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Inc Idempotent")
        sid = sweep["sweep_id"]
        sweep_store.link_incident(sid, "inc-dup")
        sweep_store.link_incident(sid, "inc-dup")

        linked = sweep_store.get_linked_incidents(sid)
        assert linked.count("inc-dup") == 1

    def test_sweep_summary(self, sweep_store: SweepStore) -> None:
        sweep = sweep_store.create_sweep(name="Summary Test")
        sid = sweep["sweep_id"]

        # Add zones with varied statuses
        z1 = sweep_store.add_zone(sid, "Zone Alpha")
        z2 = sweep_store.add_zone(sid, "Zone Beta")
        z3 = sweep_store.add_zone(sid, "Zone Gamma")
        sweep_store.update_zone_status(z1["zone_id"], "cleared")
        sweep_store.update_zone_status(z2["zone_id"], "flagged", "Suspicious signal")

        # Link detections and incidents
        for i in range(5):
            sweep_store.link_detection(sid, f"det-s{i}")
        sweep_store.link_incident(sid, "inc-s1")
        sweep_store.link_incident(sid, "inc-s2")

        summary = sweep_store.get_sweep_summary(sid)
        assert summary is not None
        assert summary["zone_summary"]["total"] == 3
        assert summary["zone_summary"]["cleared"] == 1
        assert summary["zone_summary"]["flagged"] == 1
        assert summary["zone_summary"]["pending"] == 1
        assert summary["detection_count"] == 5
        assert summary["incident_count"] == 2

    def test_summary_not_found(self, sweep_store: SweepStore) -> None:
        assert sweep_store.get_sweep_summary("nonexistent") is None


# ── Cross-Module Integration ──────────────────────────────────────────────


class TestSweepIncidentIntegration:
    """Test sweep ↔ incident linking with actual incident store."""

    def test_sweep_links_to_real_incidents(
        self, sweep_store: SweepStore, incident_store: IncidentStore,
    ) -> None:
        """Create incidents, link to sweep, verify both stores."""
        inc1 = incident_store.create_incident(
            title="Bug in conference room",
            severity="critical",
            freq_hz=433.92e6,
        )
        inc2 = incident_store.create_incident(
            title="Suspicious WiFi device",
            severity="warning",
        )

        sweep = sweep_store.create_sweep(name="Cross-module Sweep")
        sid = sweep["sweep_id"]

        sweep_store.link_incident(sid, inc1["incident_id"])
        sweep_store.link_incident(sid, inc2["incident_id"])

        linked = sweep_store.get_linked_incidents(sid)
        assert inc1["incident_id"] in linked
        assert inc2["incident_id"] in linked


# ── API Endpoint Tests ────────────────────────────────────────────────────


class TestSweepEndpoints:
    """Test sweep API endpoints through the HTTP layer."""

    def test_create_sweep_api(self, client: TestClient) -> None:
        resp = client.post("/api/sweeps/", json={
            "name": "API Sweep",
            "location": "Headquarters",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "API Sweep"
        assert data["phase"] == "pre_assessment"

    def test_list_sweeps_api(self, client: TestClient) -> None:
        client.post("/api/sweeps/", json={"name": "List Test A"})
        client.post("/api/sweeps/", json={"name": "List Test B"})

        resp = client.get("/api/sweeps/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2

    def test_get_sweep_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Get Test"})
        sid = create_resp.json()["sweep_id"]

        resp = client.get(f"/api/sweeps/{sid}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    def test_get_sweep_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/sweeps/nonexistent-id")
        assert resp.status_code == 404

    def test_phase_transition_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Phase API"})
        sid = create_resp.json()["sweep_id"]

        resp = client.put(f"/api/sweeps/{sid}/phase", json={"phase": "active"})
        assert resp.status_code == 200
        assert resp.json()["phase"] == "active"

    def test_invalid_phase_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Bad Phase"})
        sid = create_resp.json()["sweep_id"]

        resp = client.put(f"/api/sweeps/{sid}/phase", json={"phase": "bogus"})
        assert resp.status_code == 422

    def test_add_zone_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Zone API"})
        sid = create_resp.json()["sweep_id"]

        resp = client.post(f"/api/sweeps/{sid}/zones", json={
            "zone_name": "Board Room",
        })
        assert resp.status_code == 201
        assert resp.json()["zone_name"] == "Board Room"

    def test_update_zone_status_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Zone Status API"})
        sid = create_resp.json()["sweep_id"]

        zone_resp = client.post(f"/api/sweeps/{sid}/zones", json={
            "zone_name": "Lobby",
        })
        zid = zone_resp.json()["zone_id"]

        resp = client.put(f"/api/sweeps/{sid}/zones/{zid}/status", json={
            "status": "cleared",
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "cleared"

    def test_get_zones_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Zones List API"})
        sid = create_resp.json()["sweep_id"]

        client.post(f"/api/sweeps/{sid}/zones", json={"zone_name": "Zone 1"})
        client.post(f"/api/sweeps/{sid}/zones", json={"zone_name": "Zone 2"})

        resp = client.get(f"/api/sweeps/{sid}/zones")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_link_detection_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Det API"})
        sid = create_resp.json()["sweep_id"]

        resp = client.post(f"/api/sweeps/{sid}/detections", json={
            "detection_id": "det-api-1",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_link_incident_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Inc API"})
        sid = create_resp.json()["sweep_id"]

        resp = client.post(f"/api/sweeps/{sid}/incidents", json={
            "incident_id": "inc-api-1",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_summary_api(self, client: TestClient) -> None:
        create_resp = client.post("/api/sweeps/", json={"name": "Summary API"})
        sid = create_resp.json()["sweep_id"]

        # Add zones and link items
        client.post(f"/api/sweeps/{sid}/zones", json={"zone_name": "Z1"})
        client.post(f"/api/sweeps/{sid}/detections", json={"detection_id": "d1"})
        client.post(f"/api/sweeps/{sid}/incidents", json={"incident_id": "i1"})

        resp = client.get(f"/api/sweeps/{sid}/summary")
        assert resp.status_code == 200
        summary = resp.json()
        assert summary["zone_summary"]["total"] == 1
        assert summary["detection_count"] == 1
        assert summary["incident_count"] == 1

    def test_full_sweep_workflow_api(self, client: TestClient) -> None:
        """Full workflow: create → zones → sweep → link → close."""
        # Create
        resp = client.post("/api/sweeps/", json={
            "name": "Full Workflow",
            "location": "Client HQ",
            "scope_description": "TSCM sweep of all executive areas",
            "threat_profile": "state_level",
        })
        assert resp.status_code == 201
        sid = resp.json()["sweep_id"]

        # Add zones
        z1 = client.post(f"/api/sweeps/{sid}/zones", json={
            "zone_name": "CEO Office",
        }).json()
        z2 = client.post(f"/api/sweeps/{sid}/zones", json={
            "zone_name": "Board Room",
        }).json()

        # Move to active phase
        client.put(f"/api/sweeps/{sid}/phase", json={"phase": "active"})

        # Sweep zones
        client.put(f"/api/sweeps/{sid}/zones/{z1['zone_id']}/status",
                    json={"status": "sweeping"})
        client.put(f"/api/sweeps/{sid}/zones/{z1['zone_id']}/status",
                    json={"status": "cleared"})

        client.put(f"/api/sweeps/{sid}/zones/{z2['zone_id']}/status",
                    json={"status": "sweeping"})
        client.put(f"/api/sweeps/{sid}/zones/{z2['zone_id']}/status",
                    json={"status": "flagged", "flagged_reason": "433 MHz emission"})

        # Link detections to flagged zone
        client.post(f"/api/sweeps/{sid}/detections", json={
            "detection_id": "det-wf1",
            "zone_id": z2["zone_id"],
        })

        # Move through remaining phases
        client.put(f"/api/sweeps/{sid}/phase", json={"phase": "analysis"})
        client.put(f"/api/sweeps/{sid}/phase", json={"phase": "reporting"})
        client.put(f"/api/sweeps/{sid}/phase", json={"phase": "closed"})

        # Verify final state
        final = client.get(f"/api/sweeps/{sid}").json()
        assert final["phase"] == "closed"
        assert final["status"] == "completed"
        assert final["end_time"] is not None

        summary = client.get(f"/api/sweeps/{sid}/summary").json()
        assert summary["zone_summary"]["cleared"] == 1
        assert summary["zone_summary"]["flagged"] == 1
        assert summary["detection_count"] == 1
