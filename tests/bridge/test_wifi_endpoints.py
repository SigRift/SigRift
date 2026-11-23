"""Tests for WiFi SIGINT API endpoints."""

from __future__ import annotations

import gzip
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _clear_wifi_rate_limit():
    """Clear per-node WiFi ingest rate limiter between tests."""
    from sigrift.bridge.routers.wifi import _wifi_ingest_cooldown
    _wifi_ingest_cooldown.clear()


class TestWifiNetworks:
    def test_get_networks_empty(self, client: TestClient):
        resp = client.get("/api/wifi/networks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["networks"] == []

    def test_get_networks_after_ingest(self, client: TestClient, registered_node: str):
        # Ingest some WiFi metadata
        resp = client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {
                    "bssid": "aa:bb:cc:11:22:33",
                    "ssid": "TestNet",
                    "channel": 6,
                    "band": "2.4GHz",
                    "security": "WPA2",
                    "signal_dbm": -45.0,
                },
                {
                    "bssid": "dd:ee:ff:44:55:66",
                    "ssid": "OtherNet",
                    "channel": 11,
                    "band": "2.4GHz",
                    "security": "WPA3",
                    "signal_dbm": -60.0,
                },
            ],
        })
        assert resp.status_code == 201

        resp = client.get("/api/wifi/networks")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2

    def test_get_networks_band_filter(self, client: TestClient, registered_node: str):
        client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net24", "channel": 6, "band": "2.4GHz", "signal_dbm": -50.0},
                {"bssid": "dd:ee:ff:44:55:66", "ssid": "Net5", "channel": 36, "band": "5GHz", "signal_dbm": -55.0},
            ],
        })

        resp = client.get("/api/wifi/networks?band=5GHz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["networks"][0]["band"] == "5GHz"


class TestWifiNetworkDetail:
    def test_network_detail(self, client: TestClient, registered_node: str):
        client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "TestNet", "channel": 6, "band": "2.4GHz", "signal_dbm": -45.0, "client_mac": "c1:c1:c1:c1:c1:c1"},
            ],
        })

        resp = client.get("/api/wifi/networks/aa:bb:cc:11:22:33")
        assert resp.status_code == 200
        data = resp.json()
        assert data["network"]["bssid"] == "aa:bb:cc:11:22:33"
        assert "clients" in data
        assert isinstance(data["clients"], list)
        assert "timeline" in data
        assert isinstance(data["timeline"], list)

    def test_network_detail_404(self, client: TestClient):
        resp = client.get("/api/wifi/networks/xx:xx:xx:xx:xx:xx")
        assert resp.status_code == 404


class TestWifiClients:
    def test_get_clients(self, client: TestClient, registered_node: str):
        client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net1", "channel": 6, "band": "2.4GHz", "signal_dbm": -50.0, "client_mac": "c1:c1:c1:c1:c1:c1"},
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net1", "channel": 6, "band": "2.4GHz", "signal_dbm": -55.0, "client_mac": "c2:c2:c2:c2:c2:c2"},
            ],
        })

        resp = client.get("/api/wifi/clients")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert data["count"] >= 2


class TestWifiChannels:
    def test_get_channels(self, client: TestClient, registered_node: str):
        client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net1", "channel": 1, "band": "2.4GHz", "signal_dbm": -50.0},
                {"bssid": "dd:ee:ff:44:55:66", "ssid": "Net2", "channel": 6, "band": "2.4GHz", "signal_dbm": -60.0},
            ],
        })

        resp = client.get("/api/wifi/channels?band=2.4GHz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["band"] == "2.4GHz"
        assert isinstance(data["count"], int)
        assert data["count"] >= 1


class TestWifiTimeline:
    def test_get_timeline(self, client: TestClient, registered_node: str):
        client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net1", "channel": 6, "band": "2.4GHz", "signal_dbm": -50.0},
            ],
        })

        resp = client.get("/api/wifi/timeline?bssid=aa:bb:cc:11:22:33&hours=24")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bssid"] == "aa:bb:cc:11:22:33"


class TestWifiStats:
    def test_get_stats(self, client: TestClient):
        resp = client.get("/api/wifi/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_networks" in data
        assert isinstance(data["total_networks"], int)
        assert "total_clients" in data
        assert isinstance(data["total_clients"], int)
        assert "busiest_channel" in data
        assert "band_breakdown" in data
        assert isinstance(data["band_breakdown"], dict)


class TestWifiIngest:
    def test_batch_insert(self, client: TestClient, registered_node: str):
        resp = client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [
                {"bssid": "aa:bb:cc:11:22:33", "ssid": "Net1", "channel": 6, "band": "2.4GHz", "signal_dbm": -50.0},
                {"bssid": "dd:ee:ff:44:55:66", "ssid": "Net2", "channel": 11, "band": "2.4GHz", "signal_dbm": -60.0},
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 2
        assert data["total"] == 2

    def test_ingest_validates_required_fields(self, client: TestClient):
        resp = client.post("/api/wifi/ingest", json={
            "records": [{"bssid": "aa:bb:cc:11:22:33"}],
        })
        assert resp.status_code == 422  # Missing node_id

    def test_ingest_empty_records(self, client: TestClient, registered_node: str):
        resp = client.post("/api/wifi/ingest", json={
            "node_id": registered_node,
            "records": [],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted"] == 0


class TestWifiIngestSummary:
    def test_summary_plain_json(self, client: TestClient, registered_node: str):
        resp = client.post("/api/wifi/ingest-summary", json={
            "node_id": registered_node,
            "scan_period_s": 60.0,
            "total_frames": 100,
            "networks": [],
        })
        assert resp.status_code == 201

    def test_summary_gzipped_body(self, client: TestClient, registered_node: str):
        """Gzipped summary bodies are accepted — same contract as the BT
        summary route (read_json_body); guards against the 2026-06-10
        staging regression where compressed scanner POSTs got 400s."""
        payload = {
            "node_id": registered_node,
            "scan_period_s": 60.0,
            "total_frames": 100,
            "networks": [],
        }
        resp = client.post(
            "/api/wifi/ingest-summary",
            content=gzip.compress(json.dumps(payload).encode("utf-8")),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 201


class TestWifiWebSocket:
    def test_ws_connect_and_ping(self, client: TestClient, master_key: str):
        with client.websocket_connect(
            "/api/wifi/ws/wifi",
            subprotocols=["bridge-v1", master_key],
        ) as ws:
            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"
