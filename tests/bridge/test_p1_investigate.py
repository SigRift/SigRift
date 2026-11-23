"""Tests for P1-3 (Investigate command channel) and P1-4 (Auto-rescan on low confidence).

Covers:
  - Investigate endpoint queues correct command to edge node
  - Investigate requires ANALYST role
  - Investigate returns 404 for unknown detection
  - Investigate command has correct parameters
  - Investigate is recorded in audit log
  - Auto-rescan config GET/POST endpoints
  - Auto-rescan disabled by default
  - Auto-rescan helper queues rescan on low-confidence detections
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "viewer_key", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_key", role="analyst")


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


# ---------------------------------------------------------------------------
# P1-3: Investigate command channel
# ---------------------------------------------------------------------------


class TestInvestigateDetection:
    """Tests for POST /api/detections/{detection_id}/investigate."""

    def test_investigate_queues_command(
        self,
        analyst_client: TestClient,
        detection_store: Any,
        app_state: AppState,
        registered_node: str,
    ) -> None:
        """Investigate returns 200 with command details and queues to node."""
        det = make_detection(node_id=registered_node, confidence=0.8, freq_hz=433.92e6)
        detection_store.insert_batch([det])
        detection_id = det.detection_id

        resp = analyst_client.post(f"/api/detections/{detection_id}/investigate")
        assert resp.status_code == 200

        data = resp.json()
        assert data["ok"] is True
        assert data["node_id"] == registered_node
        assert data["detection_id"] == detection_id
        assert "command_id" in data
        assert isinstance(data["command_id"], str)
        assert data["command"]["command"] == "investigate"

    def test_investigate_requires_analyst(
        self,
        viewer_client: TestClient,
        detection_store: Any,
        registered_node: str,
    ) -> None:
        """VIEWER role gets 403 when trying to investigate."""
        det = make_detection(node_id=registered_node, confidence=0.8)
        detection_store.insert_batch([det])

        resp = viewer_client.post(f"/api/detections/{det.detection_id}/investigate")
        assert resp.status_code == 403

    def test_investigate_unknown_detection(
        self,
        analyst_client: TestClient,
    ) -> None:
        """Returns 404 for a nonexistent detection ID."""
        resp = analyst_client.post("/api/detections/nonexistent123/investigate")
        assert resp.status_code == 404

    def test_investigate_command_has_correct_params(
        self,
        analyst_client: TestClient,
        detection_store: Any,
        app_state: AppState,
        registered_node: str,
    ) -> None:
        """Queued command includes freq_hz, sample_rate, duration_ms, sample_count."""
        det = make_detection(
            node_id=registered_node,
            confidence=0.9,
            freq_hz=915e6,
            signal_class="qam16",
        )
        detection_store.insert_batch([det])

        resp = analyst_client.post(
            f"/api/detections/{det.detection_id}/investigate",
            json={"sample_rate": 10e6, "duration_ms": 5000, "gain_db": 50.0},
        )
        assert resp.status_code == 200

        cmd = resp.json()["command"]
        params = cmd["params"]
        assert params["freq_hz"] == 915e6
        assert params["sample_rate"] == 10e6
        assert params["sample_count"] == 65536
        assert params["duration_ms"] == 5000
        assert params["gain_db"] == 50.0
        assert params["detection_id"] == det.detection_id
        assert params["signal_class"] == "qam16"

    def test_investigate_audit_logged(
        self,
        analyst_client: TestClient,
        detection_store: Any,
        registered_node: str,
    ) -> None:
        """Audit log contains investigation entry after investigate call."""
        det = make_detection(node_id=registered_node, confidence=0.85)
        detection_store.insert_batch([det])

        resp = analyst_client.post(f"/api/detections/{det.detection_id}/investigate")
        assert resp.status_code == 200

        # Check audit log
        conn = detection_store.get_connection()
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'investigate_queued' "
            "AND target_id = ?",
            (det.detection_id,),
        ).fetchall()
        assert len(rows) >= 1
        assert isinstance(rows[0]["node_id"], str)
        assert rows[0]["node_id"] == registered_node

    def test_investigate_default_params(
        self,
        analyst_client: TestClient,
        detection_store: Any,
        app_state: AppState,
        registered_node: str,
    ) -> None:
        """Default investigate params use 2.4MHz sample rate, 2000ms duration, 40dB gain."""
        det = make_detection(node_id=registered_node, confidence=0.7)
        detection_store.insert_batch([det])

        resp = analyst_client.post(f"/api/detections/{det.detection_id}/investigate")
        assert resp.status_code == 200

        params = resp.json()["command"]["params"]
        assert params["sample_rate"] == 2.4e6
        assert params["duration_ms"] == 2000
        assert params["gain_db"] == 40.0

    def test_investigate_command_queued_in_pending(
        self,
        analyst_client: TestClient,
        detection_store: Any,
        app_state: AppState,
        registered_node: str,
    ) -> None:
        """Verify the command appears in app_state.pending_commands for the node."""
        det = make_detection(node_id=registered_node, confidence=0.75)
        detection_store.insert_batch([det])

        resp = analyst_client.post(f"/api/detections/{det.detection_id}/investigate")
        assert resp.status_code == 200

        command_id = resp.json()["command_id"]
        pending = app_state.pending_commands.get(registered_node, [])
        assert any(c["command_id"] == command_id for c in pending)


# ---------------------------------------------------------------------------
# P1-4: Auto-rescan configuration
# ---------------------------------------------------------------------------


class TestAutoRescanConfig:
    """Tests for GET/POST /api/admin/auto-rescan."""

    def test_auto_rescan_config_get(
        self,
        client: TestClient,
    ) -> None:
        """GET auto-rescan returns current settings."""
        resp = client.get("/api/admin/auto-rescan")
        assert resp.status_code == 200
        data = resp.json()
        assert "auto_rescan" in data
        assert isinstance(data["auto_rescan"], dict)

    def test_auto_rescan_disabled_by_default(
        self,
        client: TestClient,
    ) -> None:
        """Default config has enabled=false."""
        resp = client.get("/api/admin/auto-rescan")
        assert resp.status_code == 200
        auto_rescan = resp.json()["auto_rescan"]
        assert auto_rescan["enabled"] is False

    def test_auto_rescan_config_set(
        self,
        client: TestClient,
    ) -> None:
        """POST config returns 200 and updates settings."""
        resp = client.post("/api/admin/auto-rescan", json={
            "enabled": True,
            "confidence_threshold": 0.4,
            "max_retries": 3,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["auto_rescan"]["enabled"] is True
        assert data["auto_rescan"]["confidence_threshold"] == 0.4
        assert data["auto_rescan"]["max_retries"] == 3

        # Verify via GET
        resp2 = client.get("/api/admin/auto-rescan")
        assert resp2.status_code == 200
        assert resp2.json()["auto_rescan"]["enabled"] is True
        assert resp2.json()["auto_rescan"]["confidence_threshold"] == 0.4

    def test_auto_rescan_config_validation(
        self,
        client: TestClient,
    ) -> None:
        """Invalid threshold value is rejected."""
        resp = client.post("/api/admin/auto-rescan", json={
            "enabled": True,
            "confidence_threshold": 1.5,
        })
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# P1-4: Auto-rescan helper function
# ---------------------------------------------------------------------------


class TestCheckAutoRescan:
    """Tests for check_auto_rescan utility function."""

    def test_check_auto_rescan_queues_command(
        self,
        client: TestClient,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
    ) -> None:
        """Low-confidence detection queues rescan when auto-rescan is enabled."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        # Enable auto-rescan
        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }
        persistence.set_detection_config(config)

        # Clear retry tracker
        _auto_rescan_retries.clear()

        detection = {
            "node_id": registered_node,
            "confidence": 0.3,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }

        result = check_auto_rescan(detection, app_state, persistence)
        assert result is True

        # Verify command was queued
        pending = app_state.pending_commands.get(registered_node, [])
        assert len(pending) >= 1
        assert isinstance(pending[0], dict)
        rescan_cmds = [c for c in pending if c["command"] == "rescan"]
        assert len(rescan_cmds) >= 1
        assert isinstance(rescan_cmds[0], dict)
        assert rescan_cmds[0]["params"]["reason"] == "low_confidence_auto_rescan"
        assert rescan_cmds[0]["params"]["original_confidence"] == 0.3

    def test_check_auto_rescan_disabled_noop(
        self,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
        client: TestClient,
    ) -> None:
        """When auto-rescan is disabled, no command is queued."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        _auto_rescan_retries.clear()

        detection = {
            "node_id": registered_node,
            "confidence": 0.3,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }

        result = check_auto_rescan(detection, app_state, persistence)
        assert result is False

    def test_check_auto_rescan_high_confidence_noop(
        self,
        client: TestClient,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
    ) -> None:
        """Detection above threshold does not trigger rescan."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }
        persistence.set_detection_config(config)

        _auto_rescan_retries.clear()

        detection = {
            "node_id": registered_node,
            "confidence": 0.8,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }

        result = check_auto_rescan(detection, app_state, persistence)
        assert result is False

    def test_check_auto_rescan_max_retries(
        self,
        client: TestClient,
        app_state: AppState,
        persistence: PersistenceManager,
        registered_node: str,
    ) -> None:
        """Auto-rescan stops after max_retries."""
        from sigrift.bridge.routers.detection_iq import (
            _auto_rescan_retries,
            check_auto_rescan,
        )

        config = persistence.get_detection_config()
        config["auto_rescan"] = {
            "enabled": True,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        }
        persistence.set_detection_config(config)

        _auto_rescan_retries.clear()

        detection = {
            "node_id": registered_node,
            "confidence": 0.3,
            "freq_hz": 433.92e6,
            "signal_class": "bpsk",
        }

        # First two should succeed
        assert check_auto_rescan(detection, app_state, persistence) is True
        assert check_auto_rescan(detection, app_state, persistence) is True

        # Third should be blocked
        assert check_auto_rescan(detection, app_state, persistence) is False
