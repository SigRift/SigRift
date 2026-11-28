"""Tests for the health, status, metrics, and version endpoints.

Tests cover:
  - GET /api/health — returns 200, correct structure, version matches __version__
  - GET /api/status — returns 200, all expected fields
  - GET /api/metrics — returns 200, ws_clients, uptime_seconds
  - GET /api/version — returns 200 without auth, correct structure
  - Auth required on health/status/metrics (not version)
  - Status reflects actual state (e.g., node_count increases after registration)
"""

from __future__ import annotations


from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge import API_VERSION, SUPPORTED_API_VERSIONS, WS_PROTOCOL, __version__


# ---------------------------------------------------------------------------
# 1. GET /api/version — unauthenticated
# ---------------------------------------------------------------------------


class TestVersionEndpoint:
    """Test the /api/version endpoint which requires no authentication."""

    def test_version_returns_200_no_auth(self, bridge_app: FastAPI) -> None:
        """GET /api/version succeeds without authentication."""
        with TestClient(bridge_app) as tc:
            resp = tc.get("/api/version")
            assert resp.status_code == 200

    def test_version_response_structure(self, bridge_app: FastAPI, monkeypatch) -> None:
        """GET /api/version returns all expected fields."""
        monkeypatch.delenv("SIGRIFT_RELEASE", raising=False)
        with TestClient(bridge_app) as tc:
            resp = tc.get("/api/version")
            data = resp.json()
            assert data["api_version"] == API_VERSION
            assert data["server_version"] == __version__
            assert data["release"] == "dev"
            assert data["ws_protocol"] == WS_PROTOCOL
            assert data["supported_versions"] == SUPPORTED_API_VERSIONS

    def test_version_with_auth_also_works(self, client: TestClient) -> None:
        """GET /api/version also works when auth header is present."""
        resp = client.get("/api/version")
        assert resp.status_code == 200
        assert resp.json()["server_version"] == __version__


# ---------------------------------------------------------------------------
# 2. GET /api/health — authenticated
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    """Test the /api/health endpoint."""

    def test_health_returns_200(self, client: TestClient) -> None:
        """GET /api/health returns 200 with valid auth."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_health_response_structure(self, client: TestClient) -> None:
        """GET /api/health returns correct structure with status, version, timestamp."""
        resp = client.get("/api/health")
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == __version__
        assert isinstance(data["timestamp"], str)

    def test_health_requires_auth(self, bridge_app: FastAPI) -> None:
        """GET /api/health without auth returns 401 or 403."""
        with TestClient(bridge_app) as tc:
            resp = tc.get("/api/health")
            assert resp.status_code in (401, 403)

    def test_health_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """GET /api/health with invalid key returns 401 or 403."""
        with TestClient(bridge_app, headers={"X-API-Key": "bad-key-value"}) as tc:
            resp = tc.get("/api/health")
            assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 3. GET /api/status — authenticated
# ---------------------------------------------------------------------------


class TestStatusEndpoint:
    """Test the /api/status endpoint."""

    def test_status_returns_200(self, client: TestClient) -> None:
        """GET /api/status returns 200 with valid auth."""
        resp = client.get("/api/status")
        assert resp.status_code == 200

    def test_status_response_has_all_fields(self, client: TestClient) -> None:
        """GET /api/status returns all expected fields from BridgeSystemStatus."""
        resp = client.get("/api/status")
        data = resp.json()

        int_fields = [
            "node_count",
            "active_nodes",
            "stale_nodes",
            "offline_nodes",
            "alert_count",
            "pending_jobs",
            "running_jobs",
            "total_detections_24h",
            "active_anomalies",
            "unacked_alerts",
            "active_frequencies",
        ]
        for field_name in int_fields:
            assert isinstance(data[field_name], int), f"{field_name} should be int"
        assert isinstance(data["spectrum_connected"], bool)
        assert isinstance(data["training_running"], bool)
        assert isinstance(data["uptime_seconds"], (int, float))
        assert isinstance(data["detections_per_second"], (int, float))

    def test_status_uptime_positive(self, client: TestClient) -> None:
        """GET /api/status returns a positive uptime."""
        resp = client.get("/api/status")
        data = resp.json()
        assert data["uptime_seconds"] >= 0

    def test_status_requires_auth(self, bridge_app: FastAPI) -> None:
        """GET /api/status without auth returns 401 or 403."""
        with TestClient(bridge_app) as tc:
            resp = tc.get("/api/status")
            assert resp.status_code in (401, 403)

    def test_status_node_count_increases_after_registration(
        self, client: TestClient,
    ) -> None:
        """After registering a node, node_count in status should increase."""
        # Check initial node count
        resp = client.get("/api/status")
        initial_count = resp.json()["node_count"]

        # Register a node
        reg_resp = client.post("/api/nodes/register", json={
            "node_id": "node-status-test-01",
            "host": "10.0.0.99",
            "port": 8080,
        })
        assert reg_resp.status_code == 200

        # Check that node_count increased
        resp = client.get("/api/status")
        new_count = resp.json()["node_count"]
        assert new_count == initial_count + 1

    def test_status_alert_count_increases_after_alert(
        self, client: TestClient,
    ) -> None:
        """After creating an alert rule, alert_count in status should increase."""
        resp = client.get("/api/status")
        initial_count = resp.json()["alert_count"]

        # Create an alert rule
        alert_resp = client.post("/api/alerts/rules", json={
            "name": "test_status_alert",
            "severity": "warning",
            "thresholds": {"cpu_percent": 80.0},
        })
        assert alert_resp.status_code == 201

        # Check that alert_count increased
        resp = client.get("/api/status")
        new_count = resp.json()["alert_count"]
        assert new_count == initial_count + 1

    def test_status_local_scanner_key_registered_default_false(
        self, client: TestClient,
    ) -> None:
        """PR-6: without a pre-registered local-edge key the field is False."""
        resp = client.get("/api/status")
        data = resp.json()
        assert "local_scanner_key_registered" in data
        assert data["local_scanner_key_registered"] is False

    def test_status_local_scanner_key_registered_true_when_present(
        self,
        client: TestClient,
        persistence,
    ) -> None:
        """PR-6: registering a key under the canonical local-edge key_id
        flips local_scanner_key_registered to True. This is the signal
        the dashboard banner uses to suppress the misleading "mint a
        NODE key" prompt for quickstart-path operators.
        """
        from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
        from sigrift.lib.security.credentials import (
            compute_lookup_hash,
            generate_api_key,
            hash_credential,
        )

        raw = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw)
        persistence.set_key(
            LOCAL_SCANNER_KEY_ID,
            hash_hex,
            salt,
            lookup_hash=compute_lookup_hash(raw),
        )

        resp = client.get("/api/status")
        data = resp.json()
        assert data["local_scanner_key_registered"] is True


# ---------------------------------------------------------------------------
# 4. GET /api/metrics — authenticated
# ---------------------------------------------------------------------------


class TestMetricsEndpoint:
    """Test the /api/metrics endpoint."""

    def test_metrics_returns_200(self, client: TestClient) -> None:
        """GET /api/metrics returns 200 with valid auth."""
        resp = client.get("/api/metrics")
        assert resp.status_code == 200

    def test_metrics_has_uptime_seconds(self, client: TestClient) -> None:
        """GET /api/metrics includes uptime_seconds."""
        resp = client.get("/api/metrics")
        data = resp.json()
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0

    def test_metrics_has_ws_clients(self, client: TestClient) -> None:
        """GET /api/metrics includes ws_clients with expected sub-fields."""
        resp = client.get("/api/metrics")
        data = resp.json()
        assert isinstance(data["ws_clients"], dict)
        ws = data["ws_clients"]
        assert isinstance(ws["detections"], int)
        assert isinstance(ws["anomalies"], int)
        assert isinstance(ws["spectrum"], int)
        assert isinstance(ws["wifi"], int)
        assert isinstance(ws["total"], int)

    def test_metrics_ws_clients_all_zero_initially(self, client: TestClient) -> None:
        """With no WS clients connected, all ws_clients counts should be zero."""
        resp = client.get("/api/metrics")
        data = resp.json()
        ws = data["ws_clients"]
        assert ws["detections"] == 0
        assert ws["anomalies"] == 0
        assert ws["wifi"] == 0
        assert ws["total"] == 0

    def test_metrics_requires_auth(self, bridge_app: FastAPI) -> None:
        """GET /api/metrics without auth returns 401 or 403."""
        with TestClient(bridge_app) as tc:
            resp = tc.get("/api/metrics")
            assert resp.status_code in (401, 403)

    def test_metrics_has_ingest_section(self, client: TestClient) -> None:
        """GET /api/metrics includes ingest section with detection store."""
        resp = client.get("/api/metrics")
        data = resp.json()
        # Detection store is configured in conftest, so ingest should be present
        assert isinstance(data["ingest"], dict)
        assert isinstance(data["ingest"]["detections_1h"], int)
        assert isinstance(data["ingest"]["detections_per_second"], (int, float))
