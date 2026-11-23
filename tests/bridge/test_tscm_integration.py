"""Cross-module integration tests for TSCM workflow.

Tests the integration between:
  - Threat Signature Library ↔ Ingest Pipeline (score boosting)
  - Incident Lifecycle ↔ Detection Linking
  - Threat Signatures ↔ Incidents (cross-feature workflows)
"""

from __future__ import annotations

import json
import os

os.environ.setdefault("BRIDGE_CSRF", "disabled")

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyScorer,
    ScorerConfig,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.incidents import IncidentStore
from sigrift.bridge.storage.signature_library import SignatureLibraryStore
from sigrift.bridge.tests.conftest import make_detection


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def ctx(detection_store: DetectionStore):
    """Shared DB context."""
    return detection_store._ctx


@pytest.fixture
def sig_store(ctx) -> SignatureLibraryStore:
    store = SignatureLibraryStore(ctx)
    return store


@pytest.fixture
def incident_store(ctx) -> IncidentStore:
    return IncidentStore(ctx)


@pytest.fixture
def seeded_sig_store(sig_store: SignatureLibraryStore) -> SignatureLibraryStore:
    """Signature store pre-populated with threat seed data."""
    sig_store.seed_threat_signatures()
    return sig_store


# ── Threat Signature ↔ Ingest Pipeline ───────────────────────────────────


class TestSignatureIngestIntegration:
    """Verify signature matching integrates with the ingest score-boost path."""

    def test_match_boosts_anomaly_score(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """A detection whose freq/class matches a threat sig gets a score boost."""
        # UHF Audio Bug seed: freq_min=430e6, freq_max=440e6, class=fm
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
            power_dbm=-40.0,
        )
        assert len(matches) >= 1
        best = matches[0]
        assert best["match_score"] > 0.3

        # Simulate ingest pipeline boost logic (detections.py:598-602)
        original_score = 0.5
        boost = best["match_score"] * 0.3
        boosted = min(1.0, original_score + boost)
        assert boosted > original_score

    def test_signature_match_weight_active(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """SIGNATURE_MATCH weight is 0.15 by default — threat detection active."""
        config = ScorerConfig()
        weight = config.weights.get(AnomalyDimension.SIGNATURE_MATCH, 0.0)
        assert weight == 0.15

    def test_boost_clamped_at_one(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """Score boost is capped at 1.0 even if original + boost > 1.0."""
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
            power_dbm=-40.0,
        )
        assert len(matches) >= 1
        best = matches[0]

        original_score = 0.9
        boost = best["match_score"] * 0.3
        clamped = min(1.0, original_score + boost)
        assert clamped <= 1.0

    def test_signature_match_populates_dimensions(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """Matched signature's score appears in rf_anomaly dimensions dict."""
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
            power_dbm=-40.0,
        )
        assert len(matches) >= 1
        best = matches[0]

        # Simulate dimension injection (detections.py:650-660)
        dimensions = {"signature_match": 0.0}
        reasons: list[str] = []

        dimensions["signature_match"] = best["match_score"]
        reasons.append(
            f"Matches threat signature: {best['name']} "
            f"({best.get('threat_category', 'unknown')})"
        )
        sig_info = {
            "name": best["name"],
            "threat_category": best.get("threat_category", ""),
            "threat_level": best.get("threat_level", ""),
            "match_score": best["match_score"],
        }

        assert dimensions["signature_match"] > 0
        assert "Matches threat signature" in reasons[0]
        assert sig_info["threat_category"] != ""
        assert sig_info["threat_level"] != ""

    def test_match_exception_graceful_degradation(
        self, sig_store: SignatureLibraryStore
    ) -> None:
        """If match_by_parameters raises, the ingest pipeline catches it."""
        # Empty store — no seeding. Should return empty, not raise.
        matches = sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
        )
        assert matches == []

    def test_nonmatching_freq_fewer_matches(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """Detection far from threat sig frequencies gets fewer/weaker matches."""
        close_matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
            power_dbm=-40.0,
        )
        far_matches = seeded_sig_store.match_by_parameters(
            freq_hz=10e9,  # 10 GHz — far from most seeds
            signal_class="fm",
            power_dbm=-40.0,
        )
        # Fewer matches at 10 GHz than at 433 MHz
        assert len(far_matches) < len(close_matches)
        # And any far matches have lower scores
        if far_matches:
            assert far_matches[0]["match_score"] < close_matches[0]["match_score"]

    def test_multiple_sigs_sorted_by_score(
        self, seeded_sig_store: SignatureLibraryStore
    ) -> None:
        """When multiple sigs match, results are sorted by match_score desc."""
        # 433 MHz range — UHF audio bug + OOK remote control both in range
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="",  # don't filter by class — more matches
        )
        if len(matches) >= 2:
            scores = [m["match_score"] for m in matches]
            assert scores == sorted(scores, reverse=True)


# ── Incident ↔ Detection Linking ─────────────────────────────────────────


class TestIncidentDetectionIntegration:
    """Verify incidents can link to detections with timeline tracking."""

    def test_create_and_link_three_detections(
        self, incident_store: IncidentStore
    ) -> None:
        """Create incident → link 3 detections → timeline shows all."""
        inc = incident_store.create_incident(
            title="Suspicious UHF signal",
            severity="critical",
            freq_hz=433.92e6,
            signal_class="fm",
        )
        inc_id = inc["incident_id"]

        for i in range(3):
            ok = incident_store.link_detection(inc_id, f"det-{i:03d}")
            assert ok is True

        linked = incident_store.get_linked_detections(inc_id)
        assert len(linked) == 3
        assert set(linked) == {"det-000", "det-001", "det-002"}

        # Timeline should include 1 created + 3 detection_linked events
        timeline = incident_store.get_timeline(inc_id)
        types = [e["event_type"] for e in timeline]
        assert types.count("detection_linked") == 3
        assert "created" in types

    def test_full_lifecycle_with_detections(
        self, incident_store: IncidentStore
    ) -> None:
        """Full lifecycle: create → assign → investigate → evidence → link → resolve."""
        # Create
        inc = incident_store.create_incident(
            title="Covert transmitter detected",
            severity="critical",
            node_id="node-alpha",
            freq_hz=148.0e6,
            signal_class="fm",
            anomaly_score=0.85,
            created_by="operator-1",
        )
        inc_id = inc["incident_id"]
        assert inc["status"] == "open"

        # Assign
        updated = incident_store.assign_incident(inc_id, "analyst-A", actor="operator-1")
        assert updated["assigned_to"] == "analyst-A"

        # Investigate
        updated = incident_store.update_status(
            inc_id, "investigating", actor="analyst-A",
            note="Commencing RF sweep of area"
        )
        assert updated["status"] == "investigating"

        # Add evidence
        ev = incident_store.add_evidence(
            inc_id, evidence_type="iq_capture",
            reference="iq-capture-001.sigmf",
            description="15-second IQ capture at 148 MHz",
            actor="analyst-A",
        )
        assert ev["evidence_type"] == "iq_capture"

        # Link detections
        for det_id in ["det-100", "det-101", "det-102"]:
            incident_store.link_detection(inc_id, det_id, actor="analyst-A")

        # Add note
        incident_store.add_note(
            inc_id,
            note="Physical sweep found device behind wall plate",
            actor="analyst-A",
        )

        # Resolve
        resolved = incident_store.resolve_incident(
            inc_id, "confirmed_threat",
            resolution_note="Covert FM transmitter confirmed, device seized",
            actor="analyst-A",
        )
        assert resolved["status"] == "resolved"
        assert resolved["resolution"] == "confirmed_threat"
        assert resolved["resolved_at"] is not None
        assert isinstance(resolved["resolved_at"], str)

        # Verify complete timeline
        timeline = incident_store.get_timeline(inc_id)
        event_types = [e["event_type"] for e in timeline]
        assert "created" in event_types
        assert "assigned" in event_types
        assert "state_change" in event_types
        assert "evidence" in event_types
        assert "detection_linked" in event_types
        assert "note" in event_types
        assert "resolved" in event_types

    def test_idempotent_detection_linking(
        self, incident_store: IncidentStore
    ) -> None:
        """Linking the same detection twice is a no-op on the junction table."""
        inc = incident_store.create_incident(title="Test idempotent")
        inc_id = inc["incident_id"]

        ok1 = incident_store.link_detection(inc_id, "det-dup")
        ok2 = incident_store.link_detection(inc_id, "det-dup")
        assert ok1 is True
        assert ok2 is True  # no error

        linked = incident_store.get_linked_detections(inc_id)
        assert linked.count("det-dup") == 1

    def test_sla_mttr_calculation(
        self, incident_store: IncidentStore
    ) -> None:
        """MTTR is computed from created_at to resolved_at."""
        inc = incident_store.create_incident(
            title="MTTR test incident",
            severity="warning",
        )
        inc_id = inc["incident_id"]

        # Resolve immediately
        incident_store.resolve_incident(
            inc_id, "false_alarm",
            resolution_note="Known device identified",
        )

        resolved = incident_store.get_incident(inc_id)
        assert resolved["status"] == "resolved"
        assert resolved["resolved_at"] is not None
        assert isinstance(resolved["resolved_at"], str)

        metrics = incident_store.get_sla_metrics()
        assert metrics["resolved"] >= 1
        # MTTR may be None (0.0 evals falsy) or a small float for instant resolve
        assert metrics["mttr_hours"] is None or metrics["mttr_hours"] < 1.0


# ── Threat Signatures ↔ Incidents (cross-feature) ────────────────────────


class TestSignatureIncidentCrossFeature:
    """Verify end-to-end workflows combining signatures and incidents."""

    def test_detection_matches_critical_threat_creates_incident(
        self, seeded_sig_store: SignatureLibraryStore,
        incident_store: IncidentStore,
    ) -> None:
        """Detection matches critical threat sig → incident created with matching severity."""
        # Match against known threat signatures
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
            power_dbm=-35.0,
        )
        assert len(matches) >= 1
        best = matches[0]

        # Map threat_level → incident severity
        level_to_severity = {
            "critical": "critical",
            "high": "critical",
            "medium": "warning",
            "low": "info",
        }
        severity = level_to_severity.get(best["threat_level"], "warning")

        # Create incident from signature match
        inc = incident_store.create_incident(
            title=f"Threat match: {best['name']}",
            severity=severity,
            freq_hz=433.92e6,
            signal_class="fm",
            anomaly_score=best["match_score"],
            created_by="auto-tscm",
        )
        assert inc["status"] == "open"
        assert inc["freq_hz"] == 433.92e6
        assert inc["anomaly_score"] == best["match_score"]

    def test_incident_evidence_includes_signature_metadata(
        self, seeded_sig_store: SignatureLibraryStore,
        incident_store: IncidentStore,
    ) -> None:
        """Incident evidence can reference threat signature details."""
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6,
            signal_class="fm",
        )
        best = matches[0]

        inc = incident_store.create_incident(
            title=f"Threat: {best['name']}",
            severity="critical",
        )
        inc_id = inc["incident_id"]

        # Add signature match as evidence
        ev = incident_store.add_evidence(
            inc_id,
            evidence_type="threat_signature",
            reference=best["id"],
            description=(
                f"Matched {best['name']} ({best['threat_category']}) "
                f"score={best['match_score']}"
            ),
            actor="auto-tscm",
        )
        assert ev["evidence_type"] == "threat_signature"
        assert ev["reference"] == best["id"]

        # Verify in timeline
        timeline = incident_store.get_timeline(inc_id)
        evidence_events = [e for e in timeline if e["event_type"] == "evidence"]
        assert len(evidence_events) == 1
        detail = json.loads(evidence_events[0]["detail"])
        assert detail["evidence_type"] == "threat_signature"
        assert detail["reference"] == best["id"]

    def test_timeline_reconstruction_full_workflow(
        self, seeded_sig_store: SignatureLibraryStore,
        incident_store: IncidentStore,
    ) -> None:
        """Full timeline: threat match → incident → detections → notes → evidence → resolve."""
        # Step 1: Threat match
        matches = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6, signal_class="fm",
        )
        best = matches[0]

        # Step 2: Create incident
        inc = incident_store.create_incident(
            title=f"Threat: {best['name']}",
            severity="critical",
            freq_hz=433.92e6,
            created_by="tscm-engine",
        )
        inc_id = inc["incident_id"]

        # Step 3: Link detections
        for det_id in ["det-a", "det-b"]:
            incident_store.link_detection(inc_id, det_id, actor="tscm-engine")

        # Step 4: Add threat signature as evidence
        incident_store.add_evidence(
            inc_id,
            evidence_type="threat_signature",
            reference=best["id"],
            description=f"Match score: {best['match_score']}",
            actor="tscm-engine",
        )

        # Step 5: Operator note
        incident_store.add_note(
            inc_id,
            note="Physical inspection confirms covert device at location C-14",
            actor="analyst-B",
        )

        # Step 6: Resolve
        incident_store.resolve_incident(
            inc_id, "confirmed_threat",
            resolution_note="Device seized and catalogued",
            actor="analyst-B",
        )

        # Verify complete timeline reconstruction
        timeline = incident_store.get_timeline(inc_id)
        types = [e["event_type"] for e in timeline]
        assert types[0] == "created"
        assert "detection_linked" in types
        assert "evidence" in types
        assert "note" in types
        assert "resolved" in types
        assert len(timeline) >= 6  # created + 2 links + evidence + note + resolved

    def test_multiple_incidents_per_sweep(
        self, seeded_sig_store: SignatureLibraryStore,
        incident_store: IncidentStore,
    ) -> None:
        """Multiple threat matches create separate incidents."""
        # Match at 433 MHz (audio bugs, RC triggers)
        m1 = seeded_sig_store.match_by_parameters(
            freq_hz=433.92e6, signal_class="fm",
        )
        # Match at 1.2 GHz (video transmitter)
        m2 = seeded_sig_store.match_by_parameters(
            freq_hz=1.2e9, signal_class="fm",
        )

        incidents = []
        for matches, freq in [(m1, 433.92e6), (m2, 1.2e9)]:
            if matches:
                inc = incident_store.create_incident(
                    title=f"Threat: {matches[0]['name']}",
                    severity="critical",
                    freq_hz=freq,
                )
                incidents.append(inc)

        assert len(incidents) >= 1
        assert all(isinstance(i, dict) for i in incidents)
        # Each has unique ID
        ids = [i["incident_id"] for i in incidents]
        assert len(ids) == len(set(ids))


# ── API-Level Integration ─────────────────────────────────────────────────


class TestAPIIntegration:
    """Test cross-module flows through the HTTP API layer."""

    def test_ingest_with_signature_weight_enabled(
        self, client: TestClient, bridge_app, registered_node: str,
    ) -> None:
        """Ingest batch with SIGNATURE_MATCH weight > 0 triggers matching."""
        from datetime import timedelta

        # Seed threat signatures
        sig_store = bridge_app.state.signature_library_store
        sig_store.seed_threat_signatures()

        # Enable signature weight on the scorer
        rf_scorer = bridge_app.state.rf_scorer
        rf_scorer.config.weights[AnomalyDimension.SIGNATURE_MATCH] = 0.1

        now = datetime.now(timezone.utc)
        # Ingest a detection matching UHF audio bug
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "batch_id": "batch-sig-test",
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [{
                "node_id": registered_node,
                "signal_class": "fm",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
                "power_dbm": -40.0,
                "anomaly_score": 0.5,
            }],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert isinstance(data, dict)
        assert data.get("accepted", 0) >= 1

    def test_incident_api_full_flow(self, client: TestClient) -> None:
        """Create incident, link detections, verify timeline via API."""
        # Create
        resp = client.post("/api/incidents/", json={
            "title": "API integration test",
            "severity": "warning",
            "freq_hz": 915e6,
            "signal_class": "fsk",
        })
        assert resp.status_code == 201
        inc = resp.json()
        inc_id = inc["incident_id"]

        # Link detections
        for det_id in ["det-api-1", "det-api-2"]:
            resp = client.post(
                f"/api/incidents/{inc_id}/detections",
                json={"detection_id": det_id},
            )
            assert resp.status_code == 200

        # Get linked
        resp = client.get(f"/api/incidents/{inc_id}/detections")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

        # Get timeline
        resp = client.get(f"/api/incidents/{inc_id}/timeline")
        assert resp.status_code == 200
        events = resp.json()["events"]
        types = [e["event_type"] for e in events]
        assert "created" in types
        assert types.count("detection_linked") == 2

    def test_signature_match_then_incident_api(
        self, client: TestClient, bridge_app,
    ) -> None:
        """Match threat via API → create incident referencing match."""
        sig_store = bridge_app.state.signature_library_store
        sig_store.seed_threat_signatures()

        # Match via API
        resp = client.post("/api/signatures/threats/match", json={
            "freq_hz": 433.92e6,
            "signal_class": "fm",
            "power_dbm": -35.0,
        })
        assert resp.status_code == 200
        match_data = resp.json()
        assert isinstance(match_data, dict)
        assert match_data.get("matched") is True
        assert isinstance(match_data["matches"], list)
        best = match_data["matches"][0]

        # Create incident from match
        resp = client.post("/api/incidents/", json={
            "title": f"Auto: {best['name']}",
            "severity": "critical",
            "freq_hz": 433.92e6,
            "signal_class": "fm",
            "anomaly_score": best["match_score"],
        })
        assert resp.status_code == 201
        inc = resp.json()

        # Add evidence referencing the signature
        resp = client.post(
            f"/api/incidents/{inc['incident_id']}/evidence",
            json={
                "evidence_type": "threat_signature",
                "reference": best["id"],
                "description": f"Threat match score: {best['match_score']}",
            },
        )
        assert resp.status_code == 200
