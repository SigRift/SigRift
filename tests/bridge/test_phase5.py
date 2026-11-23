"""Tests for Phase 5 features: alert integration, export enhancement,
and node comparison endpoint.

Covers:
  - Auto-alert creation from high-anomaly detections
  - Alert cooldown rate limiting (5-min per node+freq)
  - Anomaly export (CSV and JSON)
  - Detection export with min_confidence and min_anomaly_score filters
  - Node comparison endpoint with Jaccard similarity
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

def _ingest_batch(
    client: TestClient,
    node_id: str,
    detections: list[dict[str, Any]],
) -> dict[str, Any]:
    """Helper to ingest a batch of detections."""
    now = datetime.now(timezone.utc)
    resp = client.post("/api/detections/batch", json={
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=5)).isoformat(),
        "period_end": now.isoformat(),
        "detections": detections,
    })
    assert resp.status_code == 201
    return resp.json()

# ---------------------------------------------------------------------------
# Alert auto-creation tests
# ---------------------------------------------------------------------------

class TestAnomalyAlertAutoCreation:
    """Test auto-alert creation from high-anomaly batch ingestion."""

    def test_high_anomaly_creates_alert(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score >= 0.7 creates an alert."""
        data = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 433.92e6,
            },
        ])
        assert data["alerts_created"] == 1

        # Verify alert exists
        resp = client.get("/api/alerts/")
        alerts = resp.json()
        anomaly_alerts = [a for a in alerts if a["name"] == "anomaly_detected"]
        assert len(anomaly_alerts) >= 1
        assert isinstance(anomaly_alerts[0], dict)
        assert "0.80" in anomaly_alerts[0]["message"]

    def test_low_anomaly_no_alert(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score < 0.7 does NOT create an alert."""
        data = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "anomaly_score": 0.5,
                "freq_hz": 433.92e6,
            },
        ])
        assert data["alerts_created"] == 0

    def test_critical_severity_threshold(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score >= 0.85 gets critical severity."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "unknown",
                "confidence": 0.2,
                "anomaly_score": 0.92,
                "freq_hz": 868e6,
            },
        ])
        resp = client.get("/api/alerts/")
        alerts = resp.json()
        anomaly_alerts = [a for a in alerts if a["name"] == "anomaly_detected"]
        assert len(anomaly_alerts) >= 1
        assert isinstance(anomaly_alerts[-1], dict)
        assert anomaly_alerts[-1]["severity"] == "critical"

    def test_warning_severity_threshold(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with 0.7 <= score < 0.85 gets warning severity."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "ofdm-256",
                "confidence": 0.4,
                "anomaly_score": 0.75,
                "freq_hz": 2400e6,
            },
        ])
        resp = client.get("/api/alerts/")
        alerts = resp.json()
        anomaly_alerts = [a for a in alerts if a["name"] == "anomaly_detected"]
        assert len(anomaly_alerts) >= 1
        assert isinstance(anomaly_alerts[-1], dict)
        assert anomaly_alerts[-1]["severity"] == "warning"

    def test_cooldown_prevents_duplicate_alerts(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Same node+freq within 5 min should not create duplicate alerts."""
        # First batch — should create alert
        data1 = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 433.92e6,
            },
        ])
        assert data1["alerts_created"] == 1

        # Second batch — same freq, should be cooled down
        data2 = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.25,
                "anomaly_score": 0.85,
                "freq_hz": 433.92e6,
            },
        ])
        assert data2["alerts_created"] == 0

    def test_different_freq_bypasses_cooldown(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Different frequency should not be affected by cooldown."""
        # First batch at 433 MHz
        data1 = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 433.92e6,
            },
        ])
        assert data1["alerts_created"] == 1

        # Second batch at 915 MHz — different freq bucket
        data2 = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 915e6,
            },
        ])
        assert data2["alerts_created"] == 1

    def test_multiple_anomalies_in_batch(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Multiple high-anomaly detections at different freqs in one batch."""
        data = _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 100e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "qpsk",
                "confidence": 0.3,
                "anomaly_score": 0.9,
                "freq_hz": 200e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "ofdm-256",
                "confidence": 0.5,
                "anomaly_score": 0.4,  # Below threshold
                "freq_hz": 300e6,
            },
        ])
        assert data["alerts_created"] == 2

    def test_alert_logs_activity(
        self, client: TestClient, registered_node: str, bridge_app,
    ) -> None:
        """Auto-alert creation should log an activity event."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 500e6,
            },
        ])
        app_state = bridge_app.state.app_state
        events = [e for e in app_state.activity_log
                  if e["event_type"] == "anomaly_alert"]
        assert len(events) >= 1
        assert isinstance(events[0], dict)

# ---------------------------------------------------------------------------
# Export enhancement tests
# ---------------------------------------------------------------------------

class TestExportAnomalies:
    """Test GET /api/export/anomalies endpoint."""

    def test_export_anomalies_json_empty(
        self, client: TestClient,
    ) -> None:
        """Anomaly export on empty store returns empty list."""
        resp = client.get("/api/export/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 0
        assert data["anomalies"] == []

    def test_export_anomalies_json(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Anomaly export returns high-score detections as JSON."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "anomaly_score": 0.1,
                "freq_hz": 433.92e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "unknown",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 868e6,
            },
        ])
        resp = client.get("/api/export/anomalies", params={
            "min_score": 0.5, "format": "json",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 1
        assert len(data["anomalies"]) == 1
        assert data["anomalies"][0]["anomaly_score"] == 0.8

    def test_export_anomalies_csv(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Anomaly export as CSV returns valid CSV content."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.9,
                "freq_hz": 433.92e6,
            },
        ])
        resp = client.get("/api/export/anomalies", params={
            "min_score": 0.5, "format": "csv",
        })
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")
        content = resp.text
        assert isinstance(content, str)
        assert "detection_id" in content
        assert "anomaly_score" in content

    def test_export_anomalies_with_node_filter(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Anomaly export respects node_id filter."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.3,
                "anomaly_score": 0.9,
                "freq_hz": 433.92e6,
            },
        ])
        resp = client.get("/api/export/anomalies", params={
            "node_id": "nonexistent-node",
            "min_score": 0.5,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 0

class TestExportDetectionsEnhanced:
    """Test enhanced detection export with new filter params."""

    def test_export_detections_min_confidence(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection export filters by min_confidence."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
            },
            {
                "node_id": registered_node,
                "signal_class": "qpsk",
                "confidence": 0.4,
            },
        ])
        resp = client.get("/api/export/detections", params={
            "min_confidence": 0.7,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 1

    def test_export_detections_min_anomaly_score(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection export filters by min_anomaly_score."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "anomaly_score": 0.1,
            },
            {
                "node_id": registered_node,
                "signal_class": "unknown",
                "confidence": 0.3,
                "anomaly_score": 0.8,
            },
        ])
        resp = client.get("/api/export/detections", params={
            "min_anomaly_score": 0.5,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 1
        assert data["detections"][0]["anomaly_score"] == 0.8

    def test_export_detections_csv_format(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection export as CSV works with new params."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
            },
        ])
        resp = client.get("/api/export/detections", params={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers.get("content-type", "")

    def test_export_detections_custom_limit(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection export respects custom limit."""
        dets = [
            {
                "node_id": registered_node,
                "signal_class": f"class-{i}",
                "confidence": 0.9,
            }
            for i in range(5)
        ]
        _ingest_batch(client, registered_node, dets)
        resp = client.get("/api/export/detections", params={"limit": 2})
        assert resp.status_code == 200
        data = resp.json()
        assert data["meta"]["record_count"] == 2

# ---------------------------------------------------------------------------
# Node comparison tests
# ---------------------------------------------------------------------------

class TestNodeComparison:
    """Test GET /api/detections/nodes/compare endpoint."""

    def test_compare_empty(self, client: TestClient) -> None:
        """Compare with no nodes returns empty."""
        resp = client.get("/api/detections/nodes/compare")
        assert resp.status_code == 200
        data = resp.json()
        assert data["nodes"] == []
        assert data["cross_correlation"] == {}

    def test_compare_single_node(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Compare with a single node returns its profile."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "family": "psk",
                "freq_hz": 433.92e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.85,
                "family": "qam",
                "freq_hz": 915e6,
            },
        ])
        resp = client.get("/api/detections/nodes/compare", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) == 1
        profile = data["nodes"][0]
        assert profile["node_id"] == registered_node
        assert profile["total_detections"] == 2
        assert profile["unique_classes"] == 2
        assert isinstance(profile["class_distribution"], dict)
        assert "bpsk" in profile["class_distribution"]
        assert isinstance(profile["class_distribution"]["bpsk"], int)
        assert "qam16" in profile["class_distribution"]
        assert isinstance(profile["class_distribution"]["qam16"], int)

        # Self-correlation should be 1.0
        cc = data["cross_correlation"]
        assert cc[registered_node][registered_node] == 1.0

    def test_compare_two_nodes(self, client: TestClient) -> None:
        """Compare two nodes with overlapping and unique classes."""
        # Register two nodes
        node_a = "node-alpha"
        node_b = "node-beta"
        client.post("/api/nodes/register", json={
            "node_id": node_a, "host": "10.0.0.1", "port": 8080,
        })
        client.post("/api/nodes/register", json={
            "node_id": node_b, "host": "10.0.0.2", "port": 8080,
        })

        # Node A: bpsk, qpsk
        _ingest_batch(client, node_a, [
            {"node_id": node_a, "signal_class": "bpsk", "confidence": 0.9},
            {"node_id": node_a, "signal_class": "qpsk", "confidence": 0.85},
        ])
        # Node B: bpsk, qam16
        _ingest_batch(client, node_b, [
            {"node_id": node_b, "signal_class": "bpsk", "confidence": 0.8},
            {"node_id": node_b, "signal_class": "qam16", "confidence": 0.75},
        ])

        resp = client.get("/api/detections/nodes/compare", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) == 2

        cc = data["cross_correlation"]
        # A has {bpsk, qpsk}, B has {bpsk, qam16}
        # Jaccard = |{bpsk}| / |{bpsk, qpsk, qam16}| = 1/3 ≈ 0.3333
        assert cc[node_a][node_b] == pytest.approx(1 / 3, abs=0.01)
        assert cc[node_b][node_a] == pytest.approx(1 / 3, abs=0.01)

        # Self-correlation = 1.0
        assert cc[node_a][node_a] == 1.0
        assert cc[node_b][node_b] == 1.0

    def test_compare_node_with_no_detections(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Node with no detections shows zero stats."""
        resp = client.get("/api/detections/nodes/compare", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["nodes"]) == 1
        profile = data["nodes"][0]
        assert profile["total_detections"] == 0
        assert profile["unique_classes"] == 0
        assert profile["avg_confidence"] == 0.0

    def test_compare_anomaly_count(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Node comparison includes anomaly count."""
        _ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "anomaly_score": 0.1,
                "freq_hz": 100e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "unknown",
                "confidence": 0.3,
                "anomaly_score": 0.8,
                "freq_hz": 200e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.4,
                "anomaly_score": 0.75,
                "freq_hz": 300e6,
            },
        ])
        resp = client.get("/api/detections/nodes/compare", params={"hours": 1})
        data = resp.json()
        profile = data["nodes"][0]
        assert profile["anomaly_count"] == 2  # 0.8 and 0.75 >= 0.7

    def test_compare_top_class(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Node comparison returns the correct top class."""
        _ingest_batch(client, registered_node, [
            {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
            {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.85},
            {"node_id": registered_node, "signal_class": "qam16", "confidence": 0.8},
        ])
        resp = client.get("/api/detections/nodes/compare", params={"hours": 1})
        data = resp.json()
        profile = data["nodes"][0]
        assert profile["top_class"] == "bpsk"

    def test_compare_hours_parameter(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Node comparison uses the hours parameter."""
        _ingest_batch(client, registered_node, [
            {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
        ])
        resp = client.get("/api/detections/nodes/compare", params={"hours": 168})
        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 168
