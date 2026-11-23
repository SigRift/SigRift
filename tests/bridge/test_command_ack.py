"""Tests for POST /{node_id}/commands/{command_id}/ack endpoint.

Covers the Sprint 8 command acknowledgment lifecycle:
queued -> dispatched -> acked, 404 for missing commands,
and 409 for invalid state transitions.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.dependencies import Role
from sigrift.bridge.routers.nodes import router
from sigrift.bridge.state import AppState


def _make_app() -> "FastAPI":
    """Create a minimal FastAPI app with the nodes router and mocked deps."""
    app = FastAPI()

    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {
        "node-alpha": {
            "host": "10.0.0.1",
            "port": 5000,
            "capabilities": {},
            "registered_at": "2026-03-01T00:00:00",
            "last_seen": "2026-03-01T00:00:00",
        },
    }

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state

    mock_store = MagicMock()
    app.state.detection_store = mock_store

    # Middleware to inject key_role so require_role passes
    from starlette.middleware.base import BaseHTTPMiddleware

    class _SetRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_SetRoleMiddleware)

    from sigrift.bridge.dependencies import rate_limit

    async def _fake_rate_limit():
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit

    app.include_router(router, prefix="/api/nodes")
    return app


def _seed_command(app_state: AppState, node_id: str, command_id: str,
                  cmd_status: str = "queued") -> dict:
    """Insert a command entry into command_history and return it."""
    entry = {
        "command_id": command_id,
        "node_id": node_id,
        "command": "scan",
        "status": cmd_status,
        "params": {},
        "queued_at": "2026-03-01T00:00:00",
        "lease_expires_at": "2026-03-01T00:05:00",
        "dispatched_at": None,
        "acked_at": None,
        "completed_at": None,
    }
    app_state.command_history.append(entry)
    return entry



class TestAckQueuedCommand(unittest.TestCase):
    """Acking a queued command should succeed and set acked_at."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)
        self.app_state = self.app.state.app_state

    def test_ack_queued_returns_200(self):
        _seed_command(self.app_state, "node-alpha", "cmd-001", "queued")
        resp = self.client.post("/api/nodes/node-alpha/commands/cmd-001/ack")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["command_id"], "cmd-001")
        self.assertEqual(data["status"], "acked")

    def test_ack_sets_acked_at(self):
        _seed_command(self.app_state, "node-alpha", "cmd-002", "queued")
        self.client.post("/api/nodes/node-alpha/commands/cmd-002/ack")
        entry = next(
            e for e in self.app_state.command_history
            if e["command_id"] == "cmd-002"
        )
        self.assertIsNotNone(entry["acked_at"])

    def test_ack_dispatched_returns_200(self):
        """Dispatched commands should also be ackable."""
        _seed_command(self.app_state, "node-alpha", "cmd-003", "dispatched")
        resp = self.client.post("/api/nodes/node-alpha/commands/cmd-003/ack")
        self.assertEqual(resp.status_code, 200)



class TestAckStatusTransition(unittest.TestCase):
    """Command status must transition correctly: queued -> acked."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)
        self.app_state = self.app.state.app_state

    def test_status_transitions_to_acked(self):
        entry = _seed_command(self.app_state, "node-alpha", "cmd-010", "queued")
        self.assertEqual(entry["status"], "queued")
        self.client.post("/api/nodes/node-alpha/commands/cmd-010/ack")
        self.assertEqual(entry["status"], "acked")

    def test_dispatched_transitions_to_acked(self):
        entry = _seed_command(self.app_state, "node-alpha", "cmd-011", "dispatched")
        self.client.post("/api/nodes/node-alpha/commands/cmd-011/ack")
        self.assertEqual(entry["status"], "acked")

    def test_completed_command_returns_409(self):
        """Cannot ack a command that is already completed."""
        _seed_command(self.app_state, "node-alpha", "cmd-012", "completed")
        resp = self.client.post("/api/nodes/node-alpha/commands/cmd-012/ack")
        self.assertEqual(resp.status_code, 409)

    def test_already_acked_returns_409(self):
        """Cannot ack a command that is already acked."""
        _seed_command(self.app_state, "node-alpha", "cmd-013", "acked")
        resp = self.client.post("/api/nodes/node-alpha/commands/cmd-013/ack")
        self.assertEqual(resp.status_code, 409)



class TestAckNonexistent(unittest.TestCase):
    """Acking a command that doesn't exist should return 404."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)

    def test_nonexistent_command_returns_404(self):
        resp = self.client.post(
            "/api/nodes/node-alpha/commands/no-such-cmd/ack"
        )
        self.assertEqual(resp.status_code, 404)

    def test_wrong_node_returns_404(self):
        """Command exists for node-alpha but ack targets node-beta."""
        app_state = self.app.state.app_state
        _seed_command(app_state, "node-alpha", "cmd-020", "queued")
        resp = self.client.post(
            "/api/nodes/node-beta/commands/cmd-020/ack"
        )
        self.assertEqual(resp.status_code, 404)



class TestAckActivityLog(unittest.TestCase):
    """Acking a command via the queue_command flow should log activity."""

    def setUp(self):
        self.app = _make_app()
        self.client = TestClient(self.app)
        self.app_state = self.app.state.app_state

    def test_queue_command_logs_activity(self):
        """Queuing a command via the endpoint logs command_queued."""
        resp = self.client.post(
            "/api/nodes/node-alpha/command",
            json={"command": "restart", "params": {}},
        )
        self.assertEqual(resp.status_code, 200)
        events = [
            e for e in self.app_state.activity_log
            if e["event_type"] == "command_queued"
        ]
        self.assertGreaterEqual(len(events), 1)
        self.assertIn("node-alpha", events[-1]["message"])

    def test_full_lifecycle_logged(self):
        """Queue then ack — both actions produce trackable state changes."""
        # Queue via the API
        resp = self.client.post(
            "/api/nodes/node-alpha/command",
            json={"command": "restart", "params": {}},
        )
        self.assertEqual(resp.status_code, 200)
        command_id = resp.json()["command_id"]

        # Ack the queued command
        resp2 = self.client.post(
            f"/api/nodes/node-alpha/commands/{command_id}/ack"
        )
        self.assertEqual(resp2.status_code, 200)

        # Verify history entry reflects acked state
        entry = next(
            e for e in self.app_state.command_history
            if e["command_id"] == command_id
        )
        self.assertEqual(entry["status"], "acked")
        self.assertIsNotNone(entry["acked_at"])


def _make_app_with_role(role: "Role") -> "FastAPI":
    """Create a minimal FastAPI app that injects a specific role."""
    app = FastAPI()

    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {
        "node-alpha": {
            "host": "10.0.0.1",
            "port": 5000,
            "capabilities": {},
            "registered_at": "2026-03-01T00:00:00",
            "last_seen": "2026-03-01T00:00:00",
        },
    }
    # Bind test-key-id to node-alpha for ownership validation
    mock_persistence.get_key_meta.return_value = {
        "test-key-id": {"node_id": "node-alpha"},
    }

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state

    mock_store = MagicMock()
    app.state.detection_store = mock_store

    from starlette.middleware.base import BaseHTTPMiddleware

    _injected_role = role

    class _SetSpecificRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = _injected_role
            return await call_next(request)

    app.add_middleware(_SetSpecificRoleMiddleware)

    from sigrift.bridge.dependencies import rate_limit

    async def _fake_rate_limit():
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit

    app.include_router(router, prefix="/api/nodes")
    return app



class TestAckRBAC(unittest.TestCase):
    """Verify that the ack endpoint enforces Role.NODE RBAC guard."""

    def test_sensor_role_gets_403(self):
        """SENSOR (lower than NODE) must be rejected with 403."""
        app = _make_app_with_role(Role.SENSOR)
        app_state = app.state.app_state
        _seed_command(app_state, "node-alpha", "cmd-rbac-1", "queued")
        client = TestClient(app)
        resp = client.post("/api/nodes/node-alpha/commands/cmd-rbac-1/ack")
        self.assertEqual(resp.status_code, 403)

    def test_node_role_not_forbidden(self):
        """NODE role should pass the RBAC guard (200 or 404, never 403)."""
        app = _make_app_with_role(Role.NODE)
        app_state = app.state.app_state
        _seed_command(app_state, "node-alpha", "cmd-rbac-2", "queued")
        client = TestClient(app)
        resp = client.post("/api/nodes/node-alpha/commands/cmd-rbac-2/ack")
        self.assertIn(resp.status_code, (200, 404))
        self.assertNotEqual(resp.status_code, 403)

    def test_node_role_acks_successfully(self):
        """NODE role should successfully ack a queued command."""
        app = _make_app_with_role(Role.NODE)
        app_state = app.state.app_state
        _seed_command(app_state, "node-alpha", "cmd-rbac-3", "queued")
        client = TestClient(app)
        resp = client.post("/api/nodes/node-alpha/commands/cmd-rbac-3/ack")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["status"], "acked")


if __name__ == "__main__":
    unittest.main()
