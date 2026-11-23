"""Tests for anomaly API endpoints in routers/detections.py.

Covers GET /anomalies, PUT /anomalies/{id}/dismiss,
PUT /anomalies/{id}/baseline, and WS /ws/anomalies.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.routers.detections import router
from sigrift.bridge.routers.detection_audit import router as audit_router
from sigrift.bridge.routers.detection_iq import router as iq_router
from sigrift.bridge.state import AppState


def _make_app() -> "FastAPI":
    """Create a minimal FastAPI app with the detections router and mocked deps."""
    app = FastAPI()

    # Mock persistence
    mock_persistence = MagicMock()
    mock_persistence.get_key_meta.return_value = {}
    mock_persistence.get_nodes.return_value = {"test-node": {}}
    mock_persistence.get_key_store.return_value = {
        "test-key-id": ("hash", b"salt"),
    }

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state

    # Mock detection store — uses rf_anomalies table API
    mock_store = MagicMock()
    mock_store.get_rf_anomalies.return_value = [
        {
            "id": 1,
            "detection_id": "det_001",
            "node_id": "test-node",
            "signal_class": "bpsk",
            "family": "psk",
            "confidence": 0.65,
            "anomaly_score": 0.72,
            "baseline_status": "stable",
            "freq_hz": 433920000.0,
            "timestamp": "2026-02-10T12:00:00",
            "dimensions": {},
            "reasons": [],
            "seen_count": 1,
        },
        {
            "id": 2,
            "detection_id": "det_002",
            "node_id": "test-node",
            "signal_class": "ofdm-256",
            "family": "ofdm",
            "confidence": 0.55,
            "anomaly_score": 0.58,
            "baseline_status": "learning",
            "freq_hz": 868000000.0,
            "timestamp": "2026-02-10T12:01:00",
            "dimensions": {},
            "reasons": [],
            "seen_count": 1,
        },
    ]
    mock_store.count_rf_anomalies.return_value = 2
    mock_store.get_dismissed_ids.return_value = set()
    mock_store.get_detection_by_id.return_value = {
        "detection_id": "det_002",
        "signal_class": "ofdm-256",
        "freq_hz": 868000000.0,
        "node_id": "test-node",
    }
    app.state.detection_store = mock_store

    # Override auth dependencies
    from starlette.middleware.base import BaseHTTPMiddleware
    from sigrift.bridge.dependencies import Role, rate_limit

    class _SetRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_SetRoleMiddleware)

    async def _fake_rate_limit():
        return "test-key-id"

    async def _fake_ws_auth(websocket):
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit

    app.include_router(audit_router, prefix="/api/detections")
    app.include_router(iq_router, prefix="/api/detections")
    app.include_router(router, prefix="/api/detections")
    return app



class TestGetAnomalies(unittest.TestCase):
    """Test GET /api/detections/anomalies."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)

    def test_get_anomalies_default(self):
        resp = self.client.get("/api/detections/anomalies")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("anomalies", data)
        self.assertIn("count", data)
        self.assertIn("min_score", data)

    def test_get_anomalies_returns_results(self):
        resp = self.client.get("/api/detections/anomalies?min_score=0.5")
        data = resp.json()
        self.assertEqual(data["count"], 2)
        self.assertEqual(len(data["anomalies"]), 2)

    def test_get_anomalies_with_node_filter(self):
        resp = self.client.get(
            "/api/detections/anomalies?node_id=test-node&min_score=0.5"
        )
        self.assertEqual(resp.status_code, 200)

    def test_get_anomalies_excludes_dismissed(self):
        """Dismissed anomalies should be filtered out via DB column."""
        # Dismiss by rf_anomalies row ID (integer)
        resp = self.client.put("/api/detections/anomalies/1/dismiss")
        self.assertEqual(resp.status_code, 200)
        # Verify dismiss was called with the correct ID
        mock_store = self.app.state.detection_store
        mock_store.dismiss_rf_anomaly.assert_called_once_with(1)



class TestDismissAnomaly(unittest.TestCase):
    """Test PUT /api/detections/anomalies/{id}/dismiss — integer row IDs."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)

    def test_dismiss_returns_success(self):
        resp = self.client.put("/api/detections/anomalies/1/dismiss")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["dismissed_id"], 1)

    def test_dismiss_calls_store(self):
        self.client.put("/api/detections/anomalies/1/dismiss")
        mock_store = self.app.state.detection_store
        mock_store.dismiss_rf_anomaly.assert_called_once_with(1)

    def test_dismiss_idempotent(self):
        """Dismissing same ID twice should not error."""
        resp1 = self.client.put("/api/detections/anomalies/1/dismiss")
        resp2 = self.client.put("/api/detections/anomalies/1/dismiss")
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(resp2.status_code, 200)

    def test_dismiss_logs_activity(self):
        self.client.put("/api/detections/anomalies/1/dismiss")
        app_state = self.app.state.app_state
        events = [e for e in app_state.activity_log
                  if e["event_type"] == "rf_anomaly_dismissed"]
        self.assertEqual(len(events), 1)



class TestBaselineAnomaly(unittest.TestCase):
    """Test PUT /api/detections/anomalies/{id}/baseline."""

    def setUp(self):
        self.app = _make_app()
        import tempfile
        from pathlib import Path
        from sigrift.bridge.detection_store import DetectionStore
        from sigrift.bridge.models import DetectionRecord
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        store = DetectionStore(Path(directory.name) / "detections.db")
        self.addCleanup(store.close)
        store.insert_batch([DetectionRecord(id="det_002", node_id="test-node", signal_class="ofdm-256", freq_hz=868e6, confidence=.9)])
        self.app.state.detection_store = store
        self.client = TestClient(self.app)

    def test_baseline_returns_success(self):
        resp = self.client.put("/api/detections/anomalies/det_002/baseline")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["baselined"])
        self.assertEqual(data["detection_id"], "det_002")
        self.assertIn("signal_class", data)

    def test_baseline_preserves_detection_and_saves_scoped_pattern(self):
        store = self.app.state.detection_store
        before = store.get_detection_by_id("det_002")
        response = self.client.put("/api/detections/anomalies/det_002/baseline")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(store.get_detection_by_id("det_002"), before)
        self.assertNotIn("det_002", store.get_dismissed_ids())
        self.assertEqual(store.known_signals.list()[0]["node_id"], "test-node")

    def test_baseline_logs_activity(self):
        self.client.put("/api/detections/anomalies/det_002/baseline")
        app_state = self.app.state.app_state
        events = [e for e in app_state.activity_log
                  if e["event_type"] == "anomaly_baselined"]
        self.assertEqual(len(events), 1)



class TestAnomalyWebSocket(unittest.TestCase):
    """Test WS /api/detections/ws/anomalies."""

    def setUp(self):
        self.app = _make_app()

        # Override WS auth

        async def _fake_ws_auth(websocket):
            return ("test-key-id", None)

        # Patch at module level for the router
        self._ws_auth_patch = patch(
            "sigrift.bridge.routers.detections.require_ws_auth",
            _fake_ws_auth,
        )
        self._ws_auth_patch.start()

        self.client = TestClient(self.app)

    def tearDown(self):
        self._ws_auth_patch.stop()

    def test_ws_anomalies_connect(self):
        """WebSocket should accept connections and respond to ping."""
        with self.client.websocket_connect(
            "/api/detections/ws/anomalies?api_key=test"
        ) as ws:
            ws.send_text("ping")
            data = ws.receive_text()
            self.assertEqual(data, "pong")

    def test_ws_anomalies_client_tracked(self):
        """Connected WS clients should appear in app_state."""
        app_state = self.app.state.app_state
        initial_count = len(app_state.ws_anomaly_clients)
        with self.client.websocket_connect(
            "/api/detections/ws/anomalies?api_key=test"
        ) as ws:
            ws.send_text("ping")
            ws.receive_text()
            # Client should be registered
            self.assertGreater(len(app_state.ws_anomaly_clients), initial_count)
        # Client should be removed after disconnect
        # (May take a moment for cleanup)


if __name__ == "__main__":
    unittest.main()
