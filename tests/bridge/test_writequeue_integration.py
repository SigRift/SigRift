"""Tests for the WriteQueue vs direct-insert routing in POST /batch.

The ingest_batch endpoint in routers/detections.py routes detections
through WriteQueue.enqueue_batch when write_queue is running, and
falls back to store.insert_batch when it is not (or is absent).
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.dependencies import Role, rate_limit
from sigrift.bridge.routers.detections import router
from sigrift.bridge.state import AppState


def _make_batch_payload(node_id: str = "test-node", n: int = 2) -> dict:
    """Build a minimal valid DetectionBatch JSON payload."""
    dets = []
    for i in range(n):
        dets.append({
            "node_id": node_id,
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433920000.0,
            "timestamp": "2026-03-04T12:00:00",
        })
    return {
        "node_id": node_id,
        "batch_id": "batch-wq-test",
        "period_start": "2026-03-04T11:59:00",
        "period_end": "2026-03-04T12:01:00",
        "detections": dets,
    }


def _make_app(write_queue=None) -> "FastAPI":
    """Create a minimal FastAPI app with mocked dependencies.

    Parameters
    ----------
    write_queue:
        Mock WriteQueue to attach (or None to omit).
    """
    app = FastAPI()

    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {"test-node": {}}
    mock_persistence.get_alert_rules.return_value = []

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state

    mock_store = MagicMock()
    mock_store.insert_batch.return_value = 2
    mock_store.insert_rf_anomalies_batch.return_value = None
    app.state.detection_store = mock_store

    if write_queue is not None:
        app.state.write_queue = write_queue

    # Inject ADMIN role so RBAC passes
    from starlette.middleware.base import BaseHTTPMiddleware

    class _SetRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_SetRoleMiddleware)

    async def _fake_rate_limit():
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit

    app.include_router(router, prefix="/api/detections")
    return app



class TestWriteQueueRouting(unittest.TestCase):
    """Detections always use direct insert (WriteQueue bypassed for reliability)."""

    def test_direct_insert_even_with_running_writequeue(self):
        mock_wq = MagicMock()
        mock_wq.is_running = True
        mock_wq.enqueue_batch = AsyncMock(return_value=None)

        app = _make_app(write_queue=mock_wq)
        client = TestClient(app)

        payload = _make_batch_payload(n=3)
        resp = client.post(
            "/api/detections/batch",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["accepted"])
        self.assertEqual(data["inserted"], 2)  # mock returns 2

        # WriteQueue is bypassed — direct insert is always used
        mock_wq.enqueue_batch.assert_not_called()
        store = app.state.detection_store
        store.insert_batch.assert_called_once()



class TestDirectInsertFallback(unittest.TestCase):
    """When write_queue is absent or not running, use store.insert_batch."""

    def test_no_writequeue_uses_direct_insert(self):
        app = _make_app(write_queue=None)
        client = TestClient(app)

        payload = _make_batch_payload(n=2)
        resp = client.post(
            "/api/detections/batch",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertTrue(data["accepted"])
        self.assertEqual(data["inserted"], 2)

        store = app.state.detection_store
        store.insert_batch.assert_called_once()

    def test_stopped_writequeue_uses_direct_insert(self):
        mock_enqueue = AsyncMock(return_value=None)
        mock_wq = MagicMock()
        mock_wq.is_running = False
        mock_wq.enqueue_batch = mock_enqueue

        app = _make_app(write_queue=mock_wq)
        client = TestClient(app)

        payload = _make_batch_payload(n=2)
        resp = client.post(
            "/api/detections/batch",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(resp.status_code, 201)

        # enqueue_batch should NOT have been called
        mock_enqueue.assert_not_called()
        store = app.state.detection_store
        store.insert_batch.assert_called_once()



class TestWriteQueueFallbackBehavior(unittest.TestCase):
    """Verify the response structure is consistent regardless of routing path."""

    def test_response_fields_with_writequeue(self):
        mock_wq = MagicMock()
        mock_wq.is_running = True
        mock_wq.enqueue_batch = AsyncMock(return_value=None)

        app = _make_app(write_queue=mock_wq)
        client = TestClient(app)

        payload = _make_batch_payload(n=1)
        resp = client.post(
            "/api/detections/batch",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        self.assertIn("accepted", data)
        self.assertIn("batch_id", data)
        self.assertIn("inserted", data)
        self.assertIn("total", data)

    def test_response_fields_without_writequeue(self):
        app = _make_app(write_queue=None)
        client = TestClient(app)

        payload = _make_batch_payload(n=1)
        resp = client.post(
            "/api/detections/batch",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        data = resp.json()
        self.assertIn("accepted", data)
        self.assertIn("batch_id", data)
        self.assertIn("inserted", data)
        self.assertIn("total", data)


if __name__ == "__main__":
    unittest.main()
