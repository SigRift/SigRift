"""Tests for TSCM sweep report generation.

Covers: data collection, HTML rendering, section completeness,
and the report API endpoint.
"""

from __future__ import annotations

import os

os.environ.setdefault("BRIDGE_CSRF", "disabled")

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.incidents import IncidentStore
from sigrift.bridge.storage.sweeps import SweepStore
from sigrift.bridge.sweep_report import SweepReportGenerator
from sigrift.bridge.tests.conftest import make_detection


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


@pytest.fixture
def report_gen(
    sweep_store: SweepStore,
    incident_store: IncidentStore,
    detection_store: DetectionStore,
) -> SweepReportGenerator:
    return SweepReportGenerator(sweep_store, incident_store, detection_store)


@pytest.fixture
def populated_sweep(
    sweep_store: SweepStore,
    incident_store: IncidentStore,
    detection_store: DetectionStore,
) -> str:
    """Create a sweep with zones, detections, and incidents. Returns sweep_id."""
    # Create sweep
    sweep = sweep_store.create_sweep(
        name="Test Report Sweep",
        location="Client Headquarters",
        scope_description="Full TSCM sweep of floors 3-5",
        threat_profile="corporate_espionage",
    )
    sid = sweep["sweep_id"]

    # Add zones
    z1 = sweep_store.add_zone(sid, "Executive Suite")
    z2 = sweep_store.add_zone(sid, "Server Room")
    sweep_store.update_zone_status(z1["zone_id"], "cleared")
    sweep_store.update_zone_status(
        z2["zone_id"], "flagged",
        flagged_reason="Unknown 433 MHz emission detected",
    )

    # Insert detections into DB and link to sweep
    dets = [
        make_detection(
            signal_class="fm",
            freq_hz=433.92e6,
            anomaly_score=0.8,
            power_dbm=-35.0,
        ),
        make_detection(
            signal_class="ook",
            freq_hz=315e6,
            anomaly_score=0.6,
            power_dbm=-50.0,
        ),
    ]
    detection_store.insert_batch(dets)
    for d in dets:
        sweep_store.link_detection(sid, d.detection_id, zone_id=z2["zone_id"])

    # Create and link incident
    inc = incident_store.create_incident(
        title="Covert audio transmitter",
        severity="critical",
        freq_hz=433.92e6,
        signal_class="fm",
        anomaly_score=0.8,
    )
    incident_store.resolve_incident(
        inc["incident_id"], "confirmed_threat",
        resolution_note="Device found behind wall plate in server room",
    )
    sweep_store.link_incident(sid, inc["incident_id"], zone_id=z2["zone_id"])

    return sid


# ── Data Collection Tests ────────────────────────────────────────────────


class TestReportDataCollection:

    def test_collect_data_returns_complete_structure(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        data = report_gen.collect_data(populated_sweep)
        assert data is not None
        assert isinstance(data, dict)
        assert "sweep" in data
        assert isinstance(data["sweep"], dict)
        assert "zones" in data
        assert isinstance(data["zones"], list)
        assert "incidents" in data
        assert isinstance(data["incidents"], list)
        assert "detections" in data
        assert isinstance(data["detections"], list)
        assert "generated_at" in data
        assert isinstance(data["generated_at"], str)

    def test_collect_data_not_found(
        self, report_gen: SweepReportGenerator,
    ) -> None:
        assert report_gen.collect_data("nonexistent") is None

    def test_collect_data_zones(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        data = report_gen.collect_data(populated_sweep)
        zones = data["zones"]
        assert isinstance(zones, list)
        assert len(zones) == 2
        names = [z["zone_name"] for z in zones]
        assert "Executive Suite" in names
        assert "Server Room" in names

    def test_collect_data_incidents(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        data = report_gen.collect_data(populated_sweep)
        incidents = data["incidents"]
        assert isinstance(incidents, list)
        assert len(incidents) == 1
        assert incidents[0]["title"] == "Covert audio transmitter"
        assert "timeline" in incidents[0]
        assert isinstance(incidents[0]["timeline"], list)

    def test_collect_data_detections(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        data = report_gen.collect_data(populated_sweep)
        detections = data["detections"]
        assert isinstance(detections, list)
        assert len(detections) == 2
        classes = [d["signal_class"] for d in detections]
        assert "fm" in classes
        assert "ook" in classes


# ── HTML Rendering Tests ─────────────────────────────────────────────────


class TestReportRendering:

    def test_render_returns_html(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert html is not None
        assert isinstance(html, str)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html

    def test_render_not_found(
        self, report_gen: SweepReportGenerator,
    ) -> None:
        assert report_gen.render_html("nonexistent") is None

    def test_render_contains_executive_summary(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert "Executive Summary" in html
        assert "FINDINGS PRESENT" in html  # flagged zones exist

    def test_render_contains_zone_coverage(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert "Zone Coverage" in html
        assert "Executive Suite" in html
        assert "Server Room" in html
        assert "cleared" in html
        assert "flagged" in html

    def test_render_contains_findings(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert "Findings" in html
        assert "Covert audio transmitter" in html
        assert "confirmed_threat" in html

    def test_render_contains_detections(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert "Detection Inventory" in html
        assert "433.920 MHz" in html  # 433.92e6 / 1e6

    def test_render_contains_recommendations(
        self, report_gen: SweepReportGenerator, populated_sweep: str,
    ) -> None:
        html = report_gen.render_html(populated_sweep)
        assert "Recommendations" in html
        # Has flagged zones and confirmed threat
        assert "follow-up physical inspection" in html
        assert "forensic analysis" in html

    def test_render_clear_sweep(
        self, report_gen: SweepReportGenerator, sweep_store: SweepStore,
    ) -> None:
        """A sweep with no findings shows CLEAR status."""
        sweep = sweep_store.create_sweep(name="Clean Sweep")
        zone = sweep_store.add_zone(sweep["sweep_id"], "All Clear Zone")
        sweep_store.update_zone_status(zone["zone_id"], "cleared")

        html = report_gen.render_html(sweep["sweep_id"])
        assert html is not None
        assert isinstance(html, str)
        assert "CLEAR" in html
        assert "No immediate action required" in html


# ── API Endpoint Tests ────────────────────────────────────────────────────


class TestReportEndpoint:

    def test_report_endpoint(self, client: TestClient) -> None:
        # Create a minimal sweep
        resp = client.post("/api/sweeps/", json={
            "name": "Report Endpoint Test",
            "location": "Test Building",
        })
        sid = resp.json()["sweep_id"]

        # Add a zone
        client.post(f"/api/sweeps/{sid}/zones", json={"zone_name": "Zone R1"})

        # Get report
        resp = client.get(f"/api/sweeps/{sid}/report")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "TSCM Sweep Report" in resp.text
        assert "Report Endpoint Test" in resp.text

    def test_report_not_found(self, client: TestClient) -> None:
        resp = client.get("/api/sweeps/nonexistent/report")
        assert resp.status_code == 404
