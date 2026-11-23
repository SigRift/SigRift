"""Tests for config_hash in heartbeat response (Sprint 8).

Covers _compute_config_hash() and the config_hash field returned
by POST /api/nodes/heartbeat.
"""

from __future__ import annotations

import hashlib
import json
import os
import unittest
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.dependencies import Role, rate_limit
from sigrift.bridge.routers.nodes import _compute_config_hash, router
from sigrift.bridge.state import AppState


# ---------------------------------------------------------------------------
# Unit tests for _compute_config_hash
# ---------------------------------------------------------------------------


class TestComputeConfigHash(unittest.TestCase):
    """Unit tests for _compute_config_hash()."""

    def test_consistent_hash(self):
        """Same inputs must produce the same hash."""
        node_data = {"capabilities": {"model_version": "v2", "scan_ranges": [433e6]}}
        det_cfg = {"iq_capture_enabled": True}
        h1 = _compute_config_hash(node_data, det_cfg)
        h2 = _compute_config_hash(node_data, det_cfg)
        self.assertEqual(h1, h2)

    def test_different_inputs_different_hash(self):
        """Different capability sets must produce different hashes."""
        node_a = {"capabilities": {"model_version": "v1", "scan_ranges": []}}
        node_b = {"capabilities": {"model_version": "v2", "scan_ranges": [915e6]}}
        det_cfg = {}
        h_a = _compute_config_hash(node_a, det_cfg)
        h_b = _compute_config_hash(node_b, det_cfg)
        self.assertNotEqual(h_a, h_b)

    def test_hash_is_hex_string_of_expected_length(self):
        """Hash should be a 16-char hex string (SHA-256[:16] = 32 hex truncated to 16)."""
        node_data = {"capabilities": {}}
        det_cfg = {}
        h = _compute_config_hash(node_data, det_cfg)
        self.assertEqual(len(h), 16)
        # Must be valid hex
        int(h, 16)

    def test_detection_config_affects_hash(self):
        """Changing detection_config while keeping node_data the same changes the hash."""
        node_data = {"capabilities": {"model_version": "v1"}}
        h1 = _compute_config_hash(node_data, {"iq_capture_enabled": False})
        h2 = _compute_config_hash(node_data, {"iq_capture_enabled": True})
        self.assertNotEqual(h1, h2)

    def test_empty_capabilities_defaults(self):
        """Missing capabilities key should use defaults and not crash."""
        h = _compute_config_hash({}, {})
        self.assertEqual(len(h), 16)

    def test_matches_manual_computation(self):
        """Hash must match a manually-computed SHA-256 of the canonical JSON."""
        node_data = {"capabilities": {"model_version": "v3", "anomaly_enabled": True}}
        det_cfg = {"iq_capture_enabled": False}
        config_dict = {
            "model_version": "v3",
            "scan_ranges": [],
            "anomaly_enabled": True,
            "iq_capture_enabled": False,
        }
        expected = hashlib.sha256(
            json.dumps(config_dict, sort_keys=True).encode()
        ).hexdigest()[:16]
        self.assertEqual(_compute_config_hash(node_data, det_cfg), expected)


# ---------------------------------------------------------------------------
# Integration test: heartbeat returns config_hash
# ---------------------------------------------------------------------------


def _make_node_app() -> "FastAPI":
    """Create a minimal FastAPI app with the nodes router and mocked deps."""
    app = FastAPI()

    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {
        "edge-01": {
            "host": "10.0.0.1",
            "port": 8080,
            "capabilities": {"model_version": "v2"},
            "last_seen": "2026-03-01T00:00:00",
            "registered_at": "2026-03-01T00:00:00",
        },
    }
    mock_persistence.set_node = MagicMock()
    # The heartbeat needs a key allowed to act for the node (contract K4:
    # an unbound key would be bound on first use, which this mock cannot do).
    mock_persistence.get_key_meta.return_value = {
        "test-key-id": {"role": "node", "node_id": "edge-01"}
    }

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state
    app.state.detection_config = {"iq_capture_enabled": False}

    mock_store = MagicMock()
    app.state.detection_store = mock_store

    # Bypass auth
    async def _fake_rate_limit():
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit

    app.include_router(router, prefix="/api/nodes")
    return app


class TestHeartbeatConfigHash(unittest.TestCase):
    """Integration test: POST /api/nodes/heartbeat includes config_hash."""

    def setUp(self):
        self.app = _make_node_app()
        self.client = TestClient(self.app)

    def test_heartbeat_response_contains_config_hash(self):
        resp = self.client.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-01"},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("config_hash", data)
        self.assertIsInstance(data["config_hash"], str)
        self.assertEqual(len(data["config_hash"]), 16)
        # Must be valid hex
        int(data["config_hash"], 16)

    def test_heartbeat_unregistered_node_404(self):
        resp = self.client.post(
            "/api/nodes/heartbeat",
            json={"node_id": "nonexistent"},
        )
        self.assertEqual(resp.status_code, 404)


if __name__ == "__main__":
    unittest.main()
