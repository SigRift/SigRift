"""Tests for alerts router endpoints."""

from __future__ import annotations


from fastapi.testclient import TestClient


class TestListAlerts:
    """GET /api/alerts/ — list alerts with optional filters."""

    def test_list_empty(self, client: TestClient):
        resp = client.get("/api/alerts/")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_after_creating_rule(self, client: TestClient):
        client.post("/api/alerts/rules", json={
            "name": "High CPU Alert",
            "severity": "critical",
        })
        resp = client.get("/api/alerts/")
        assert resp.status_code == 200
        alerts = resp.json()
        assert len(alerts) >= 1
        assert alerts[-1]["name"] == "High CPU Alert"

    def test_filter_by_severity(self, client: TestClient):
        client.post("/api/alerts/rules", json={"name": "Info Alert", "severity": "info"})
        client.post("/api/alerts/rules", json={"name": "Critical Alert", "severity": "critical"})
        resp = client.get("/api/alerts/", params={"severity": "critical"})
        assert resp.status_code == 200
        alerts = resp.json()
        assert all(a["severity"] == "critical" for a in alerts)

    def test_filter_by_acknowledged(self, client: TestClient):
        resp = client.get("/api/alerts/", params={"acknowledged": False})
        assert resp.status_code == 200


class TestCreateAlertRule:
    """POST /api/alerts/rules — create an alert rule."""

    def test_create_basic_rule(self, client: TestClient):
        resp = client.post("/api/alerts/rules", json={
            "name": "Test Rule",
            "severity": "warning",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test Rule"
        assert data["severity"] == "warning"
        assert data["acknowledged"] is False

    def test_create_critical_rule(self, client: TestClient):
        resp = client.post("/api/alerts/rules", json={
            "name": "CPU Overload",
            "severity": "critical",
            "node_id": "node-01",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["severity"] == "critical"
        assert data["node_id"] == "node-01"


class TestAcknowledgeAlert:
    """PUT /api/alerts/{alert_id}/ack — acknowledge an alert."""

    def test_acknowledge_alert(self, client: TestClient):
        # Create an alert first
        create_resp = client.post("/api/alerts/rules", json={
            "name": "Ack Test",
            "severity": "warning",
        })
        alert_id = create_resp.json()["alert_id"]

        # Acknowledge it
        resp = client.put(f"/api/alerts/{alert_id}/ack")
        assert resp.status_code == 200
        data = resp.json()
        assert data["acknowledged"] is True
        assert data["acknowledged_at"] is not None

    def test_acknowledge_nonexistent(self, client: TestClient):
        resp = client.put("/api/alerts/nonexistent-id/ack")
        assert resp.status_code == 404


class TestDeleteAlertRule:
    """DELETE /api/alerts/rules/{rule_id} — delete an alert rule."""

    def test_delete_rule(self, client: TestClient):
        create_resp = client.post("/api/alerts/rules", json={
            "name": "Delete Test",
            "severity": "info",
        })
        alert_id = create_resp.json()["alert_id"]

        resp = client.delete(f"/api/alerts/rules/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == alert_id

    def test_delete_nonexistent(self, client: TestClient):
        resp = client.delete("/api/alerts/rules/nonexistent-id")
        assert resp.status_code == 404


class TestAlertHistory:
    """GET /api/alerts/history — alert history with date filters."""

    def test_history_no_filters(self, client: TestClient):
        client.post("/api/alerts/rules", json={"name": "History Test", "severity": "info"})
        resp = client.get("/api/alerts/history")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_history_with_start_filter(self, client: TestClient):
        resp = client.get("/api/alerts/history", params={
            "start": "2020-01-01T00:00:00+00:00",
        })
        assert resp.status_code == 200

    def test_history_with_end_filter(self, client: TestClient):
        resp = client.get("/api/alerts/history", params={
            "end": "2030-01-01T00:00:00+00:00",
        })
        assert resp.status_code == 200

    def test_history_invalid_start(self, client: TestClient):
        resp = client.get("/api/alerts/history", params={"start": "not-a-date"})
        assert resp.status_code == 400

    def test_history_invalid_end(self, client: TestClient):
        resp = client.get("/api/alerts/history", params={"end": "not-a-date"})
        assert resp.status_code == 400
