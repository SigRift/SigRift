"""Tests for aircraft router and cross-correlation wiring."""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.app import create_test_app
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.lib.security.credentials import generate_api_key


@pytest.fixture
def _test_env(tmp_path: Path):
    """Set up a fully wired test app and client."""
    store = DetectionStore(db_path=tmp_path / "test.db")
    pm = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    pm.load_all()
    app_state = AppState()
    key = generate_api_key(length=32)
    app = create_test_app(
        tmp_path=tmp_path,
        detection_store=store,
        persistence=pm,
        app_state=app_state,
        master_key=key,
    )
    client = TestClient(app, headers={"X-API-Key": key})
    return app, client, store, pm, app_state, key


# ---------------------------------------------------------------------------
# Aircraft router tests
# ---------------------------------------------------------------------------


class TestAircraftRouter:
    """Test /api/aircraft endpoints."""

    def test_list_active_aircraft_empty(self, _test_env):
        _, client, *_ = _test_env
        resp = client.get("/api/aircraft/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["aircraft"] == []
        assert data["count"] == 0

    def test_list_active_aircraft_with_max_age(self, _test_env):
        _, client, *_ = _test_env
        resp = client.get("/api/aircraft/?max_age=600")
        assert resp.status_code == 200
        data = resp.json()
        assert "aircraft" in data
        assert "count" in data

    def test_aircraft_trail_empty(self, _test_env):
        _, client, *_ = _test_env
        resp = client.get("/api/aircraft/A1B2C3/trail")
        assert resp.status_code == 200
        data = resp.json()
        assert data["trail"] == []

    def test_aircraft_trail_icao(self, _test_env):
        _, client, *_ = _test_env
        resp = client.get("/api/aircraft/DEADBE/trail?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        # No aircraft store wired, so returns early-exit with just "trail"
        assert data["trail"] == []

    def test_aircraft_stats_empty(self, _test_env):
        _, client, *_ = _test_env
        resp = client.get("/api/aircraft/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_active"] == 0
        assert data["by_source"] == {}


# ---------------------------------------------------------------------------
# Cross-correlation wiring tests
# ---------------------------------------------------------------------------


class TestCrossCorrelationWiring:
    """Verify cross-correlator is called after ingest operations."""

    def test_cross_correlator_on_app_state(self, _test_env):
        """CrossCorrelator should be wired to app.state."""
        app, *_ = _test_env
        assert hasattr(app.state, "cross_correlator")
        assert app.state.cross_correlator is not None

    def test_sdr_ingest_triggers_cross_correlation(self, _test_env):
        """SDR batch ingest should call cross_correlator.correlate."""
        app, client, store, pm, app_state, key = _test_env

        # Register a node
        client.post("/api/nodes/register", json={
            "node_id": "node-cc-01", "host": "10.0.0.1", "port": 8080,
        })

        mock_correlator = MagicMock()
        mock_correlator.correlate.return_value = []
        app.state.cross_correlator = mock_correlator

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        def _make_batch(batch_id: str) -> dict:
            return {
                "node_id": "node-cc-01",
                "batch_id": batch_id,
                "period_start": now_iso,
                "period_end": now_iso,
                "detections": [
                    {
                        "node_id": "node-cc-01",
                        "signal_class": "bpsk",
                        "confidence": 0.9,
                        "freq_hz": 433.92e6,
                        "snr_db": 15.0,
                        "power_dbm": -50.0,
                        "timestamp": now_iso,
                    },
                ],
            }

        # Submit enough batches for _run_analysis to trigger (every 5th)
        for i in range(6):
            resp = client.post(
                "/api/detections/batch",
                json=_make_batch(f"test-batch-cc-{i}"),
            )
            assert resp.status_code == 201, resp.json()

        # After enough batches, correlator should have been called at least once
        # (on every 5th batch _run_analysis is True)
        assert mock_correlator.correlate.call_count >= 1
        # Verify it was called with "sdr" source
        calls = mock_correlator.correlate.call_args_list
        sdr_calls = [c for c in calls if c[0][0] == "sdr"]
        assert len(sdr_calls) >= 1

    def test_wifi_ingest_triggers_cross_correlation(self, _test_env):
        """WiFi ingest should call cross_correlator.correlate."""
        app, client, store, pm, *_ = _test_env

        # The router has a PerNodeThrottle that fires every Nth call.
        # This test checks wiring, not the throttle — drop N to 1.
        import sigrift.bridge.routers.wifi as wifi_router

        wifi_router._corr_throttle._every_n = 1
        wifi_router._corr_throttle._counts.clear()

        mock_correlator = MagicMock()
        mock_correlator.correlate.return_value = []
        app.state.cross_correlator = mock_correlator

        now = datetime.now(timezone.utc).isoformat()
        resp = client.post(
            "/api/wifi/ingest",
            json={
                "node_id": "node-wifi-01",
                "records": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "ssid": "TestNet",
                        "channel": 6,
                        "channel_width": 20,
                        "band": "2.4GHz",
                        "security": "WPA2",
                        "signal_dbm": -45.0,
                        "noise_dbm": -90.0,
                        "frame_type": "beacon",
                        "client_mac": "11:22:33:44:55:66",
                        "data_rate_mbps": 54.0,
                        "retry_flag": False,
                    },
                ],
            },
        )
        assert resp.status_code == 201
        assert mock_correlator.correlate.call_count == 1
        args = mock_correlator.correlate.call_args[0]
        assert args[0] == "wifi"
        assert args[2] == "node-wifi-01"

    def test_bt_ingest_triggers_cross_correlation(self, _test_env):
        """BT ingest should call cross_correlator.correlate."""
        app, client, *_ = _test_env

        import sigrift.bridge.routers.bluetooth as bt_router

        bt_router._corr_throttle._every_n = 1
        bt_router._corr_throttle._counts.clear()

        mock_correlator = MagicMock()
        mock_correlator.correlate.return_value = []
        app.state.cross_correlator = mock_correlator

        resp = client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": "node-bt-01",
                "records": [
                    {
                        "device_addr": "AA:BB:CC:DD:EE:FF",
                        "device_name": "TestDevice",
                        "device_type": "ble",
                        "rssi_dbm": -55.0,
                    },
                ],
            },
            headers={"X-API-Key": _test_env[5], "Content-Type": "application/json"},
        )
        assert resp.status_code == 201
        assert mock_correlator.correlate.call_count == 1
        args = mock_correlator.correlate.call_args[0]
        assert args[0] == "bt"
        assert args[2] == "node-bt-01"

    def test_zigbee_ingest_triggers_cross_correlation(self, _test_env):
        """Zigbee ingest should call cross_correlator.correlate."""
        app, client, *_ = _test_env

        import sigrift.bridge.routers.zigbee as zb_router

        zb_router._corr_throttle._every_n = 1
        zb_router._corr_throttle._counts.clear()

        mock_correlator = MagicMock()
        mock_correlator.correlate.return_value = []
        app.state.cross_correlator = mock_correlator

        resp = client.post(
            "/api/zigbee/ingest",
            json={
                "node_id": "node-zb-01",
                "records": [
                    {
                        "ieee_addr": "00:11:22:33:44:55:66:77",
                        "short_addr": "0x1234",
                        "device_type": "router",
                        "channel": 15,
                        "rssi_dbm": -60.0,
                        "lqi": 200,
                    },
                ],
            },
            headers={"X-API-Key": _test_env[5], "Content-Type": "application/json"},
        )
        assert resp.status_code == 201
        assert mock_correlator.correlate.call_count == 1
        args = mock_correlator.correlate.call_args[0]
        assert args[0] == "zigbee"
        assert args[2] == "node-zb-01"

    def test_cross_correlator_error_does_not_break_ingest(self, _test_env):
        """Cross-correlator errors should not prevent ingest from succeeding."""
        app, client, *_ = _test_env

        mock_correlator = MagicMock()
        mock_correlator.correlate.side_effect = RuntimeError("DB locked")
        app.state.cross_correlator = mock_correlator

        resp = client.post(
            "/api/wifi/ingest",
            json={
                "node_id": "node-err-01",
                "records": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "ssid": "TestNet",
                        "channel": 6,
                        "channel_width": 20,
                        "band": "2.4GHz",
                        "security": "WPA2",
                        "signal_dbm": -45.0,
                        "noise_dbm": -90.0,
                        "frame_type": "beacon",
                        "client_mac": "11:22:33:44:55:66",
                        "data_rate_mbps": 54.0,
                        "retry_flag": False,
                    },
                ],
            },
        )
        # Ingest should succeed even though correlator threw
        assert resp.status_code == 201


