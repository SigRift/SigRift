"""Tests for the compliance/incident report endpoint (GET /api/export/report)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient


def _seed_report_data(client: TestClient, node_id: str) -> None:
    """Seed detections, alerts, and anomalies for report tests."""
    now = datetime.now(timezone.utc)
    client.post("/api/detections/batch", json={
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=10)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "node_id": node_id,
                "signal_class": "bpsk",
                "confidence": 0.92,
                "family": "psk",
                "freq_hz": 433.92e6,
                "snr_db": 15.0,
            },
            {
                "node_id": node_id,
                "signal_class": "qam16",
                "confidence": 0.85,
                "family": "qam",
                "freq_hz": 915e6,
                "anomaly_score": 0.75,
            },
        ],
    })
    client.post("/api/alerts/rules", json={
        "name": "Report Test Alert",
        "severity": "warning",
    })


class TestComplianceReportJSON:
    """GET /api/export/report?format=json — JSON compliance report."""

    def test_report_json_with_data(self, client: TestClient, registered_node: str):
        _seed_report_data(client, registered_node)
        now = datetime.now(timezone.utc)
        resp = client.get("/api/export/report", params={
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
            "format": "json",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["anomaly_summary"], dict)
        assert isinstance(data["top_signals"], list)
        assert isinstance(data["operator_actions"], dict)
        assert isinstance(data["operator_actions"]["total"], int)
        assert isinstance(data["alerts"], list)
        assert isinstance(data["node_summary"], list)
        assert isinstance(data["period"], dict)
        assert data["detection_count"] >= 2

    def test_report_json_empty_range(self, client: TestClient, registered_node: str):
        """A range with no data should return zero counts, not error."""
        resp = client.get("/api/export/report", params={
            "start": "2020-01-01T00:00:00+00:00",
            "end": "2020-01-02T00:00:00+00:00",
            "format": "json",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_count"] == 0
        assert data["anomaly_summary"]["wifi_total"] == 0
        assert data["anomaly_summary"]["rf_total"] == 0

    def test_report_top_signals_ranked(self, client: TestClient, registered_node: str):
        _seed_report_data(client, registered_node)
        now = datetime.now(timezone.utc)
        resp = client.get("/api/export/report", params={
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
            "format": "json",
        })
        data = resp.json()
        signals = data["top_signals"]
        assert len(signals) >= 1
        assert isinstance(signals[0], dict)
        # Verify sorted descending by count
        counts = [s["count"] for s in signals]
        assert counts == sorted(counts, reverse=True)


class TestComplianceReportHTML:
    """GET /api/export/report?format=html — HTML compliance report."""

    def test_report_html_returns_html(self, client: TestClient, registered_node: str):
        _seed_report_data(client, registered_node)
        now = datetime.now(timezone.utc)
        resp = client.get("/api/export/report", params={
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
            "format": "html",
        })
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        body = resp.text
        assert "<!DOCTYPE html>" in body
        assert "Anomaly Summary" in body
        assert "Top Signals" in body
        assert "Operator Actions" in body
        assert "Node Status" in body

    def test_report_html_default_format(self, client: TestClient, registered_node: str):
        """HTML is the default format."""
        now = datetime.now(timezone.utc)
        resp = client.get("/api/export/report", params={
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
        })
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_report_html_has_inline_css(self, client: TestClient, registered_node: str):
        now = datetime.now(timezone.utc)
        resp = client.get("/api/export/report", params={
            "start": (now - timedelta(hours=1)).isoformat(),
            "end": (now + timedelta(hours=1)).isoformat(),
            "format": "html",
        })
        body = resp.text
        assert "<style>" in body
        # No external stylesheet references
        assert "stylesheet" not in body.lower()


class TestComplianceReportValidation:
    """Validation and error handling for /api/export/report."""

    def test_report_invalid_start_date(self, client: TestClient):
        resp = client.get("/api/export/report", params={
            "start": "not-a-date",
            "end": "2030-01-01T00:00:00+00:00",
        })
        assert resp.status_code == 400

    def test_report_invalid_end_date(self, client: TestClient):
        resp = client.get("/api/export/report", params={
            "start": "2020-01-01T00:00:00+00:00",
            "end": "bad-date",
        })
        assert resp.status_code == 400

    def test_report_end_before_start(self, client: TestClient):
        resp = client.get("/api/export/report", params={
            "start": "2025-06-01T00:00:00+00:00",
            "end": "2025-01-01T00:00:00+00:00",
        })
        assert resp.status_code == 400
        assert "end must be after start" in resp.json()["detail"]

    def test_report_missing_params(self, client: TestClient):
        """Both start and end are required."""
        resp = client.get("/api/export/report")
        assert resp.status_code == 422
