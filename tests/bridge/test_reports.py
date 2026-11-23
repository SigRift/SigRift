"""Tests for the report generation endpoint (/api/reports/generate).

Validates HTML and JSON report generation, section filtering,
parameter validation, and content correctness.
"""

from __future__ import annotations


from fastapi.testclient import TestClient



class TestReportGeneration:
    """Tests for GET /api/reports/generate."""

    def test_generate_html_report_default(self, client: TestClient) -> None:
        """Default HTML report returns 200 with HTML content."""
        resp = client.get("/api/reports/generate")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "Content-Disposition" in resp.headers
        assert "rf_sigint_report" in resp.headers["Content-Disposition"]
        body = resp.text
        assert "<!DOCTYPE html>" in body
        assert "RF SIGINT Activity Report" in body
        assert "Executive Summary" in body

    def test_generate_json_report(self, client: TestClient) -> None:
        """JSON report returns structured data."""
        resp = client.get("/api/reports/generate?format=json")
        assert resp.status_code == 200
        assert "application/json" in resp.headers.get("content-type", "")
        data = resp.json()
        assert isinstance(data, dict)
        assert isinstance(data["period"], dict)
        assert isinstance(data["generated_at"], str)
        assert len(data["generated_at"]) > 0
        assert isinstance(data["summary"], dict)
        assert isinstance(data["sections"], list)
        assert len(data["sections"]) > 0
        summary = data["summary"]
        assert isinstance(summary["total_detections"], int)
        assert summary["total_detections"] >= 0
        assert isinstance(summary["total_anomalies"], int)
        assert summary["total_anomalies"] >= 0
        assert isinstance(summary["total_alerts"], int)
        assert summary["total_alerts"] >= 0
        assert isinstance(summary["active_nodes"], int)
        assert summary["active_nodes"] >= 0

    def test_generate_report_custom_hours(self, client: TestClient) -> None:
        """Reports respect the hours parameter."""
        resp = client.get("/api/reports/generate?format=json&hours=4")
        assert resp.status_code == 200
        data = resp.json()
        assert data["period"]["hours"] == 4

    def test_generate_report_specific_sections(self, client: TestClient) -> None:
        """Only requested sections appear in the report."""
        resp = client.get(
            "/api/reports/generate?format=json&sections=detections,nodes"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["sections"], list)
        assert "detections" in data["sections"]
        assert "nodes" in data["sections"]
        # anomalies, spectrum, alerts should not be present as keys
        assert "anomalies" not in data
        assert "alerts" not in data

    def test_generate_report_invalid_section(self, client: TestClient) -> None:
        """Invalid section names are rejected."""
        resp = client.get(
            "/api/reports/generate?format=json&sections=detections,bogus"
        )
        assert resp.status_code == 400
        assert "bogus" in resp.json()["detail"]

    def test_generate_report_invalid_format(self, client: TestClient) -> None:
        """Invalid format is rejected."""
        resp = client.get("/api/reports/generate?format=pdf")
        assert resp.status_code == 400
        assert "pdf" in resp.json()["detail"]

    def test_generate_report_invalid_hours(self, client: TestClient) -> None:
        """Hours out of range returns 422."""
        resp = client.get("/api/reports/generate?format=json&hours=0")
        assert resp.status_code == 422

    def test_html_report_contains_sections(self, client: TestClient) -> None:
        """HTML report contains section headers for all requested sections."""
        resp = client.get("/api/reports/generate?format=html")
        assert resp.status_code == 200
        body = resp.text
        assert "Detection Breakdown" in body
        assert "Anomaly Summary" in body
        assert "Spectrum Activity" in body
        assert "Node Status" in body
        assert "Alert History" in body

    def test_html_report_single_section(self, client: TestClient) -> None:
        """HTML report with single section only includes that section."""
        resp = client.get("/api/reports/generate?format=html&sections=nodes")
        assert resp.status_code == 200
        body = resp.text
        assert "Node Status" in body
        # Other sections should not appear
        assert "Detection Breakdown" not in body
        assert "Anomaly Summary" not in body

    def test_report_with_detections(
        self,
        client: TestClient,
        detection_store,
        sample_detections,
    ) -> None:
        """Report includes detection data when detections exist."""
        detection_store.insert_batch(sample_detections)
        resp = client.get(
            "/api/reports/generate?format=json&sections=detections&hours=24"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["summary"]["total_detections"], int)
        assert data["summary"]["total_detections"] > 0
        assert isinstance(data["detections"], dict)
        assert isinstance(data["detections"]["total"], int)
        assert data["detections"]["total"] > 0
        assert isinstance(data["detections"]["by_class"], list)
        assert len(data["detections"]["by_class"]) > 0

    def test_report_with_detections_html_chart(
        self,
        client: TestClient,
        detection_store,
        sample_detections,
    ) -> None:
        """HTML report includes SVG bar chart when detections exist."""
        detection_store.insert_batch(sample_detections)
        resp = client.get(
            "/api/reports/generate?format=html&sections=detections&hours=24"
        )
        assert resp.status_code == 200
        body = resp.text
        assert "<svg" in body
        assert "Detections by Signal Class" in body

    def test_report_with_registered_node(
        self,
        client: TestClient,
        registered_node: str,
    ) -> None:
        """Report includes node data for registered nodes."""
        resp = client.get(
            "/api/reports/generate?format=json&sections=nodes"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["summary"]["total_nodes"], int)
        assert data["summary"]["total_nodes"] >= 1
        assert isinstance(data["nodes"], list)
        assert len(data["nodes"]) >= 1
        node_ids = [n["node_id"] for n in data["nodes"]]
        assert registered_node in node_ids

    def test_report_no_auth_returns_401(self, bridge_app) -> None:
        """Unauthenticated request returns 401/403."""
        no_auth_client = TestClient(bridge_app)
        resp = no_auth_client.get("/api/reports/generate")
        assert resp.status_code in (401, 403)

    def test_report_content_disposition_html(self, client: TestClient) -> None:
        """HTML report has correct Content-Disposition header."""
        resp = client.get("/api/reports/generate?format=html")
        assert resp.status_code == 200
        cd = resp.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert ".html" in cd

    def test_report_content_disposition_json(self, client: TestClient) -> None:
        """JSON report has correct Content-Disposition header."""
        resp = client.get("/api/reports/generate?format=json")
        assert resp.status_code == 200
        cd = resp.headers.get("Content-Disposition", "")
        assert "attachment" in cd
        assert ".json" in cd

    def test_report_print_styles(self, client: TestClient) -> None:
        """HTML report includes print media query styles."""
        resp = client.get("/api/reports/generate?format=html")
        assert resp.status_code == 200
        assert "@media print" in resp.text
