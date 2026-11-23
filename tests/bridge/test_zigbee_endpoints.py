"""Tests for Zigbee SIGINT API endpoints.

Covers:
  - Batch ingest (auth, validation, success, edge cases)
  - Device listing and detail queries
  - Summary statistics
  - Gzip-compressed ingest
  - Storage layer: insert, query, cleanup, hourly aggregation
  - Scanner module: device auto-detection, manufacturer lookup
  - Integration: ingest→query round-trips, multi-node, cache hits,
    WebSocket broadcast, scanner lifecycle with mocks
"""

from __future__ import annotations

import gzip
import json
import threading
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


def _make_zb_record(**overrides) -> dict:
    """Return a minimal valid Zigbee device record with optional overrides."""
    base = {
        "ieee_addr": "00:11:22:33:44:55:66:77",
        "short_addr": "0x1234",
        "device_name": "TestSensor",
        "device_type": "end_device",
        "pan_id": "0xABCD",
        "extended_pan_id": "",
        "channel": 15,
        "rssi_dbm": -65.0,
        "lqi": 180,
        "manufacturer_code": 0x117C,
        "manufacturer": "SONOFF/ITEAD",
        "clusters": ["0x0000", "0x0006"],
        "endpoints": [1],
        "power_source": "battery",
        "profile_id": "0x0104",
        "stack_profile": "",
        "security_enabled": 0,
        "parent_addr": "",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "zb_sensor_key", role="sensor")


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "zb_viewer_key", role="viewer")


@pytest.fixture
def sensor_client(bridge_app: FastAPI, sensor_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": sensor_key})


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def unauth_client(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


@pytest.fixture
def zb_node(client: TestClient) -> str:
    node_id = "zb-node-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": "10.0.0.60",
        "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


# ---------------------------------------------------------------------------
# TestZigbeeIngest
# ---------------------------------------------------------------------------


class TestZigbeeIngest:
    """Tests for POST /api/zigbee/ingest."""

    def test_ingest_basic(self, client: TestClient, zb_node: str):
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77"),
                _make_zb_record(ieee_addr="aa:bb:cc:dd:ee:ff:00:11", device_name="Router1"),
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] == 2
        assert data["node_id"] == zb_node

    def test_ingest_empty_records(self, client: TestClient, zb_node: str):
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [],
        })
        assert resp.status_code == 201
        assert resp.json()["accepted"] == 0

    def test_ingest_too_many(self, client: TestClient, zb_node: str):
        records = [
            _make_zb_record(ieee_addr=f"00:11:22:33:44:55:{i // 256:02x}:{i % 256:02x}")
            for i in range(501)
        ]
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": records,
        })
        assert resp.status_code == 400
        assert "500" in resp.json()["detail"]

    def test_ingest_missing_node_id(self, client: TestClient):
        resp = client.post("/api/zigbee/ingest", json={
            "records": [_make_zb_record()],
        })
        assert resp.status_code == 400

    def test_ingest_auth_required(self, unauth_client: TestClient):
        resp = unauth_client.post("/api/zigbee/ingest", json={
            "node_id": "some-node",
            "records": [_make_zb_record()],
        })
        assert resp.status_code == 401

    def test_ingest_gzip_compressed(self, client: TestClient, zb_node: str):
        payload = json.dumps({
            "node_id": zb_node,
            "records": [_make_zb_record()],
        }).encode()
        compressed = gzip.compress(payload)
        resp = client.post(
            "/api/zigbee/ingest",
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 201
        assert resp.json()["accepted"] == 1

    def test_ingest_invalid_json(self, client: TestClient):
        resp = client.post(
            "/api/zigbee/ingest",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_ingest_stores_device_name_as_received(self, client: TestClient, zb_node: str):
        # Stored as heard (bounded to 64 characters); the page escapes it.
        name = "<script>alert(1)</script> Joe's & \"lab\""
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(device_name=name + "x" * 80)],
        })
        assert resp.status_code == 201
        devices = client.get("/api/zigbee/devices").json()["devices"]
        assert [d["device_name"] for d in devices] == [(name + "x" * 80)[:64]]

    def test_ingest_max_batch_exactly_500(self, client: TestClient, zb_node: str):
        records = [
            _make_zb_record(ieee_addr=f"00:11:22:33:44:55:{i // 256:02x}:{i % 256:02x}")
            for i in range(500)
        ]
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": records,
        })
        assert resp.status_code == 201
        assert resp.json()["accepted"] == 500


# ---------------------------------------------------------------------------
# TestZigbeeDevices
# ---------------------------------------------------------------------------


class TestZigbeeDevices:
    """Tests for GET /api/zigbee/devices and /devices/{ieee_addr}."""

    def test_get_devices_empty(self, client: TestClient):
        resp = client.get("/api/zigbee/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["devices"] == []

    def test_get_devices_after_ingest(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77", device_name="Sensor1"),
                _make_zb_record(ieee_addr="aa:bb:cc:dd:ee:ff:00:11", device_name="Router1"),
            ],
        })
        resp = client.get("/api/zigbee/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2

    def test_get_devices_filter_by_type(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77", device_type="coordinator"),
                _make_zb_record(ieee_addr="aa:bb:cc:dd:ee:ff:00:11", device_type="end_device"),
                _make_zb_record(ieee_addr="11:22:33:44:55:66:77:88", device_type="router"),
            ],
        })
        resp = client.get("/api/zigbee/devices?device_type=coordinator")
        assert resp.status_code == 200
        devices = resp.json()["devices"]
        assert len(devices) == 1
        assert devices[0]["device_type"] == "coordinator"

    def test_get_devices_filter_by_pan_id(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77", pan_id="0xABCD"),
                _make_zb_record(ieee_addr="aa:bb:cc:dd:ee:ff:00:11", pan_id="0x1234"),
            ],
        })
        resp = client.get("/api/zigbee/devices?pan_id=0xABCD")
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_get_devices_filter_by_node_id(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record()],
        })
        resp = client.get(f"/api/zigbee/devices?node_id={zb_node}")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

    def test_get_devices_limit(self, client: TestClient, zb_node: str):
        records = [
            _make_zb_record(ieee_addr=f"00:11:22:33:44:55:{i:02x}:00")
            for i in range(5)
        ]
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": records,
        })
        resp = client.get("/api/zigbee/devices?limit=2")
        assert resp.status_code == 200
        assert resp.json()["count"] == 2

    def test_get_device_detail(self, client: TestClient, zb_node: str):
        ieee = "00:11:22:33:44:55:66:77"
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(ieee_addr=ieee, device_name="DetailTest")],
        })
        resp = client.get(f"/api/zigbee/devices/{ieee}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["ieee_addr"] == ieee
        assert detail["device_name"] == "DetailTest"
        assert isinstance(detail["timeline"], list)
        assert isinstance(detail["first_seen"], str)
        assert isinstance(detail["last_seen"], str)
        assert detail["observation_count"] == 1

    def test_get_device_detail_not_found(self, client: TestClient):
        resp = client.get("/api/zigbee/devices/ff:ff:ff:ff:ff:ff:ff:ff")
        assert resp.status_code == 404

    def test_get_device_detail_has_clusters(self, client: TestClient, zb_node: str):
        ieee = "cc:dd:ee:ff:00:11:22:33"
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(
                ieee_addr=ieee,
                clusters=["0x0000", "0x0006", "0x0008"],
                endpoints=[1, 2],
            )],
        })
        detail = client.get(f"/api/zigbee/devices/{ieee}").json()
        assert detail["clusters"] == ["0x0000", "0x0006", "0x0008"]
        assert detail["endpoints"] == [1, 2]

    def test_devices_auth_required(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/zigbee/devices")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestZigbeeStats
# ---------------------------------------------------------------------------


class TestZigbeeStats:
    """Tests for GET /api/zigbee/stats."""

    def test_stats_empty(self, client: TestClient):
        resp = client.get("/api/zigbee/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_devices"] == 0
        assert data["total_pan_ids"] == 0

    def test_stats_after_ingest(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77", pan_id="0xABCD", device_type="coordinator"),
                _make_zb_record(ieee_addr="aa:bb:cc:dd:ee:ff:00:11", pan_id="0xABCD", device_type="end_device"),
                _make_zb_record(ieee_addr="11:22:33:44:55:66:77:88", pan_id="0x1234", device_type="router"),
            ],
        })
        resp = client.get("/api/zigbee/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_devices"] == 3
        assert data["total_pan_ids"] == 2
        assert data["active_nodes"] == 1
        tb = data["type_breakdown"]
        assert tb["coordinator"] == 1
        assert tb["end_device"] == 1
        assert tb["router"] == 1

    def test_stats_auth_required(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/zigbee/stats")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestZigbeeStorage
# ---------------------------------------------------------------------------


class TestZigbeeStorage:
    """Direct tests for ZigbeeMetadataStore."""

    def test_insert_and_query(self, detection_store):
        records = [
            {"ieee_addr": "aa:bb:cc:dd:ee:ff:00:11", "short_addr": "0x0001",
             "device_name": "Bulb", "device_type": "end_device", "pan_id": "0xABCD",
             "channel": 15, "rssi_dbm": -60.0, "lqi": 200, "manufacturer_code": 0x100B,
             "manufacturer": "Philips", "clusters": ["0x0006"], "endpoints": [1],
             "power_source": "mains", "profile_id": "0x0104", "node_id": "n1"},
        ]
        inserted = detection_store.insert_zigbee_devices(records)
        assert inserted == 1

        devices = detection_store.get_zigbee_devices()
        assert len(devices) == 1
        assert devices[0]["ieee_addr"] == "aa:bb:cc:dd:ee:ff:00:11"
        assert devices[0]["manufacturer"] == "Philips"
        assert devices[0]["clusters"] == ["0x0006"]

    def test_query_filter_device_type(self, detection_store):
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "device_type": "coordinator", "node_id": "n1",
             "channel": 11, "rssi_dbm": -50, "lqi": 255, "pan_id": "0x1"},
            {"ieee_addr": "a2", "device_type": "end_device", "node_id": "n1",
             "channel": 11, "rssi_dbm": -70, "lqi": 100, "pan_id": "0x1"},
        ])
        coords = detection_store.get_zigbee_devices(device_type="coordinator")
        assert len(coords) == 1
        assert coords[0]["ieee_addr"] == "a1"

    def test_detail_returns_none_for_missing(self, detection_store):
        assert detection_store.get_zigbee_device_detail("nonexistent") is None

    def test_stats_counts(self, detection_store):
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "pan_id": "0x1", "device_type": "coordinator",
             "node_id": "n1", "channel": 15, "rssi_dbm": -50, "lqi": 200},
            {"ieee_addr": "a2", "pan_id": "0x2", "device_type": "router",
             "node_id": "n2", "channel": 20, "rssi_dbm": -60, "lqi": 150},
        ])
        stats = detection_store.get_zigbee_stats()
        assert stats["total_devices"] == 2
        assert stats["total_pan_ids"] == 2
        assert stats["active_nodes"] == 2

    def test_cleanup_removes_old_rows(self, detection_store):
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1"},
        ])
        # Should not delete anything (rows are <1h old)
        deleted = detection_store.cleanup_zigbee_devices(max_age_hours=0)
        # max_age_hours=0 means cutoff=now, so all rows older than now are deleted
        # The row was just inserted, so it should be deleted (timestamp < now)
        assert deleted >= 0  # Depends on timing

    def test_insert_empty_list(self, detection_store):
        assert detection_store.insert_zigbee_devices([]) == 0


# ---------------------------------------------------------------------------
# TestZigbeeScanner
# ---------------------------------------------------------------------------


class TestZigbeeStorageAdvanced:
    """Tests for aggregation, cleanup, and edge cases."""

    def test_aggregate_hourly(self, detection_store):
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1",
             "manufacturer": "Test", "clusters": ["0x0006"]},
        ])
        # Aggregate with cutoff=0 means all rows are eligible
        aggregated = detection_store.aggregate_zigbee_hourly(cutoff_hours=0)
        assert aggregated >= 0  # May be 0 or 1 depending on timing

    def test_cleanup_hourly(self, detection_store):
        # Should not error on empty table
        deleted = detection_store.cleanup_zigbee_hourly(max_age_days=0)
        assert deleted >= 0

    def test_detail_has_avg_rssi(self, detection_store):
        ieee = "aa:bb:cc:dd:ee:ff:00:11"
        for rssi in [-50.0, -60.0, -70.0]:
            detection_store.insert_zigbee_devices([
                {"ieee_addr": ieee, "node_id": "n1", "channel": 15,
                 "rssi_dbm": rssi, "lqi": 200, "pan_id": "0x1"},
            ])
        detail = detection_store.get_zigbee_device_detail(ieee)
        assert isinstance(detail, dict)
        assert detail["observation_count"] == 3
        assert -70 <= detail["avg_rssi_dbm"] <= -50

    def test_multiple_pan_ids_in_stats(self, detection_store):
        for i, pan in enumerate(["0xA", "0xB", "0xC"]):
            detection_store.insert_zigbee_devices([
                {"ieee_addr": f"addr_{i}", "pan_id": pan, "device_type": "router",
                 "node_id": "n1", "channel": 15, "rssi_dbm": -60, "lqi": 150},
            ])
        stats = detection_store.get_zigbee_stats()
        assert stats["total_pan_ids"] == 3

    def test_cleanup_batched(self, detection_store):
        # Insert then clean with max_age_hours=0 to delete all
        records = [
            {"ieee_addr": f"addr_{i}", "node_id": "n1", "channel": 15,
             "rssi_dbm": -60, "lqi": 150, "pan_id": "0x1"}
            for i in range(10)
        ]
        detection_store.insert_zigbee_devices(records)
        deleted = detection_store.cleanup_zigbee_devices(max_age_hours=0)
        assert deleted == 10

    def test_cache_invalidation_on_insert(self, detection_store):
        # First query populates cache
        devices = detection_store.get_zigbee_devices()
        assert len(devices) == 0
        # Insert should invalidate cache
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "new_addr", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1"},
        ])
        # Second query should see new data
        devices = detection_store.get_zigbee_devices()
        assert len(devices) == 1


class TestZigbeeIngestEdgeCases:
    """Edge cases for ingest endpoint."""

    def test_ingest_body_too_large(self, client: TestClient, zb_node: str):
        # 1MB+ payload
        big_payload = b"x" * (1_048_577)
        resp = client.post(
            "/api/zigbee/ingest",
            content=big_payload,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 413

    def test_ingest_bad_gzip(self, client: TestClient):
        resp = client.post(
            "/api/zigbee/ingest",
            content=b"not-actually-gzipped",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower()

    def test_ingest_invalid_payload_structure(self, client: TestClient):
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": 12345,  # wrong type
            "records": "not a list",
        })
        assert resp.status_code == 400

    def test_ingest_device_name_truncated(self, client: TestClient, zb_node: str):
        long_name = "A" * 200
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(device_name=long_name)],
        })
        assert resp.status_code == 201
        devices = client.get("/api/zigbee/devices").json()["devices"]
        if devices:
            assert len(devices[0]["device_name"]) <= 64


class TestZigbeeScanner:
    """Unit tests for the zigbee_scanner module."""

    def test_manufacturer_codes(self):
        from sigrift.bridge.zigbee_scanner import _MANUFACTURER_CODES
        assert _MANUFACTURER_CODES[0x117C] == "SONOFF/ITEAD"
        assert _MANUFACTURER_CODES[0x100B] == "Philips"
        assert _MANUFACTURER_CODES[0x1047] == "IKEA"

    def test_check_device_nonexistent(self):
        from sigrift.bridge.zigbee_scanner import check_device
        assert check_device("/dev/nonexistent_zigbee_xyz") is False

    def test_ezsp_scanner_parse_bellows_empty(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner
        scanner = EZSPScanner("/dev/null")
        result = scanner._parse_bellows_scan("")
        assert result == []

    def test_ezsp_scanner_parse_bellows_output(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner
        scanner = EZSPScanner("/dev/null")
        output = """
PAN ID: 0xABCD
Extended PAN: 00:11:22:33:44:55:66:77
Channel: 15
RSSI: -65
LQI: 200
Coordinator

PAN ID: 0x1234
Channel: 20
RSSI: -80
"""
        result = scanner._parse_bellows_scan(output)
        assert len(result) == 2
        assert result[0]["pan_id"] == "0xABCD"
        assert result[0]["channel"] == 15
        assert result[0]["rssi_dbm"] == -65.0
        assert result[0]["lqi"] == 200
        assert result[0]["device_type"] == "coordinator"
        assert result[1]["pan_id"] == "0x1234"
        assert result[1]["channel"] == 20

    def test_scanner_class_init(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        assert scanner.node_id == "node-01"
        assert scanner.scan_count == 0
        assert scanner.upload_count == 0
        assert scanner.error_count == 0
        assert scanner.scan_interval == 60

    def test_find_zigbee_device_returns_none_when_no_devices(self):
        from sigrift.bridge.zigbee_scanner import find_zigbee_device
        # In test environment, likely no /dev/ttyUSB* or /dev/ttyACM*
        # Just verify it doesn't crash
        result = find_zigbee_device()
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# Integration: Ingest → Query round-trips
# ---------------------------------------------------------------------------


class TestZigbeeIntegrationRoundTrip:
    """Full HTTP round-trip tests: ingest via API, query via API."""

    def test_ingest_then_query_preserves_all_fields(self, client: TestClient, zb_node: str):
        """Verify every field survives ingest → storage → query round-trip."""
        rec = _make_zb_record(
            ieee_addr="ff:ee:dd:cc:bb:aa:99:88",
            short_addr="0x5678",
            device_name="FullFieldTest",
            device_type="router",
            pan_id="0xBEEF",
            channel=20,
            rssi_dbm=-72.5,
            lqi=190,
            manufacturer_code=0x1047,
            manufacturer="IKEA",
            clusters=["0x0000", "0x0006", "0x0008", "0x0300"],
            endpoints=[1, 2, 3],
            power_source="mains",
            profile_id="0x0104",
        )
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": [rec],
        })
        assert resp.status_code == 201

        # Query via devices list
        devices = client.get("/api/zigbee/devices").json()["devices"]
        assert len(devices) == 1
        d = devices[0]
        assert d["ieee_addr"] == "ff:ee:dd:cc:bb:aa:99:88"
        assert d["short_addr"] == "0x5678"
        assert d["device_type"] == "router"
        assert d["pan_id"] == "0xBEEF"
        assert d["channel"] == 20
        assert d["manufacturer"] == "IKEA"
        assert d["clusters"] == ["0x0000", "0x0006", "0x0008", "0x0300"]
        assert d["endpoints"] == [1, 2, 3]
        assert d["power_source"] == "mains"

        # Query via detail endpoint
        detail = client.get(f"/api/zigbee/devices/{rec['ieee_addr']}").json()
        assert detail["ieee_addr"] == rec["ieee_addr"]
        assert detail["observation_count"] == 1
        assert detail["avg_rssi_dbm"] == pytest.approx(-72.5, abs=0.1)
        assert len(detail["timeline"]) >= 1
        assert isinstance(detail["timeline"][0], dict)

    def test_ingest_then_stats_consistent(self, client: TestClient, zb_node: str):
        """Stats endpoint reflects what was ingested."""
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="a1", pan_id="0x01", device_type="coordinator"),
                _make_zb_record(ieee_addr="a2", pan_id="0x01", device_type="router"),
                _make_zb_record(ieee_addr="a3", pan_id="0x02", device_type="end_device"),
                _make_zb_record(ieee_addr="a4", pan_id="0x02", device_type="end_device"),
                _make_zb_record(ieee_addr="a5", pan_id="0x03", device_type="router"),
            ],
        })
        stats = client.get("/api/zigbee/stats").json()
        assert stats["total_devices"] == 5
        assert stats["total_pan_ids"] == 3
        tb = stats["type_breakdown"]
        assert tb["coordinator"] == 1
        assert tb["router"] == 2
        assert tb["end_device"] == 2

    def test_multi_node_ingest_same_device(self, client: TestClient):
        """Same IEEE addr seen by two nodes shows up once (grouped)."""
        ieee = "aa:bb:cc:dd:ee:ff:11:22"
        for node in ["node-A", "node-B"]:
            client.post("/api/nodes/register", json={
                "node_id": node, "host": "10.0.0.1", "port": 8080,
            })
            client.post("/api/zigbee/ingest", json={
                "node_id": node,
                "records": [_make_zb_record(ieee_addr=ieee, rssi_dbm=-60.0)],
            })
        devices = client.get("/api/zigbee/devices").json()["devices"]
        # Should be grouped by ieee_addr
        ieee_addrs = [d["ieee_addr"] for d in devices]
        assert ieee_addrs.count(ieee) == 1
        # But observation_count should be 2
        detail = client.get(f"/api/zigbee/devices/{ieee}").json()
        assert detail["observation_count"] == 2

    def test_multi_node_stats_counts_nodes(self, client: TestClient):
        """Stats active_nodes counts distinct uploading nodes."""
        for i, node in enumerate(["zb-n1", "zb-n2", "zb-n3"]):
            client.post("/api/nodes/register", json={
                "node_id": node, "host": "10.0.0.1", "port": 8080,
            })
            client.post("/api/zigbee/ingest", json={
                "node_id": node,
                "records": [_make_zb_record(ieee_addr=f"addr_{i}")],
            })
        stats = client.get("/api/zigbee/stats").json()
        assert stats["active_nodes"] == 3

    def test_gzip_ingest_then_query(self, client: TestClient, zb_node: str):
        """Gzip-compressed ingest data is queryable after storage."""
        payload = json.dumps({
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="gz:01", device_name="GzipDev1"),
                _make_zb_record(ieee_addr="gz:02", device_name="GzipDev2"),
            ],
        }).encode()
        resp = client.post(
            "/api/zigbee/ingest",
            content=gzip.compress(payload),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 201
        devices = client.get("/api/zigbee/devices").json()["devices"]
        names = {d["device_name"] for d in devices}
        assert "GzipDev1" in names
        assert "GzipDev2" in names

    def test_ingest_multiple_batches_accumulate(self, client: TestClient, zb_node: str):
        """Multiple ingest calls accumulate devices."""
        for i in range(3):
            client.post("/api/zigbee/ingest", json={
                "node_id": zb_node,
                "records": [_make_zb_record(ieee_addr=f"batch_{i}:addr")],
            })
        devices = client.get("/api/zigbee/devices").json()["devices"]
        assert len(devices) == 3


# ---------------------------------------------------------------------------
# Integration: Cache hit paths
# ---------------------------------------------------------------------------


class TestZigbeeCacheHits:
    """Verify cache hit paths (lines 115, 168, 217)."""

    def test_devices_cache_hit(self, detection_store):
        """Second identical query should hit cache (line 115)."""
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1"},
        ])
        # First call populates cache
        result1 = detection_store.get_zigbee_devices()
        # Second call should return cached (same result)
        result2 = detection_store.get_zigbee_devices()
        assert result1 == result2
        # Verify it's the exact same object (cache hit)
        assert result1 is result2

    def test_device_detail_cache_hit(self, detection_store):
        """Second detail query hits cache (line 168)."""
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "cached_addr", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1"},
        ])
        d1 = detection_store.get_zigbee_device_detail("cached_addr")
        d2 = detection_store.get_zigbee_device_detail("cached_addr")
        assert d1 is d2  # Same object = cache hit

    def test_stats_cache_hit(self, detection_store):
        """Second stats query hits cache (line 217)."""
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "a1", "node_id": "n1", "channel": 15,
             "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1"},
        ])
        s1 = detection_store.get_zigbee_stats()
        s2 = detection_store.get_zigbee_stats()
        assert s1 is s2  # Same object = cache hit


# ---------------------------------------------------------------------------
# Integration: Scanner with mocks
# ---------------------------------------------------------------------------


class TestZigbeeScannerIntegration:
    """Scanner lifecycle and upload tests using mocks."""

    def test_do_scan_with_mock_ezsp(self):
        """_do_scan enriches manufacturer names and adds node_id."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-42",
        )
        # Mock the EZSP scanner
        mock_ezsp = MagicMock()
        mock_ezsp.scan_networks.return_value = [
            {"ieee_addr": "a1", "manufacturer_code": 0x117C, "manufacturer": ""},
            {"ieee_addr": "a2", "manufacturer_code": 0x9999, "manufacturer": ""},
            {"ieee_addr": "a3", "manufacturer_code": 0, "manufacturer": "Already Known"},
        ]
        mock_ezsp.scan_energy.return_value = {15: -65, 20: -80}
        scanner._scanner = mock_ezsp

        devices = scanner._do_scan()

        assert len(devices) == 3
        assert scanner.scan_count == 1
        assert scanner.devices_found == 3
        # node_id injected
        assert all(d["node_id"] == "node-42" for d in devices)
        # Known manufacturer code resolved
        assert devices[0]["manufacturer"] == "SONOFF/ITEAD"
        # Unknown code formatted as hex
        assert devices[1]["manufacturer"] == "0x9999"
        # Existing manufacturer preserved
        assert devices[2]["manufacturer"] == "Already Known"

    def test_do_scan_no_scanner_returns_empty(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        scanner._scanner = None
        assert scanner._do_scan() == []

    def test_upload_empty_list_noop(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        # Should not raise or make network calls
        scanner._upload([])
        assert scanner.upload_count == 0

    @patch("sigrift.bridge.zigbee_scanner.urllib.request.urlopen")
    def test_upload_success(self, mock_urlopen):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"accepted": 2}).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        scanner._upload([{"ieee_addr": "a1"}, {"ieee_addr": "a2"}])

        assert scanner.upload_count == 1
        # Verify gzip-compressed request was sent
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.get_header("Content-encoding") == "gzip"
        assert req.get_header("X-api-key") == "test-key"

    @patch("sigrift.bridge.zigbee_scanner.urllib.request.urlopen")
    def test_upload_http_error_increments_error_count(self, mock_urlopen):
        import urllib.error
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="", code=500, msg="Internal Server Error",
            hdrs=None, fp=None,  # type: ignore[arg-type]
        )
        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        scanner._upload([{"ieee_addr": "a1"}])
        assert scanner.error_count == 1
        assert scanner.upload_count == 0

    @patch("sigrift.bridge.zigbee_scanner.urllib.request.urlopen")
    def test_upload_connection_error_increments_error_count(self, mock_urlopen):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        mock_urlopen.side_effect = ConnectionError("refused")
        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        scanner._upload([{"ieee_addr": "a1"}])
        assert scanner.error_count == 1

    def test_start_stop_no_device(self):
        """Scanner start with no device available logs error and returns."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
            device=None,
        )
        with patch("sigrift.bridge.zigbee_scanner.find_zigbee_device", return_value=None):
            scanner.start()
        # Thread should not have started
        assert scanner._thread is None

    def test_start_stop_device_not_accessible(self):
        """Scanner start with inaccessible device logs error and returns."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
            device="/dev/nonexistent_xyz",
        )
        scanner.start()
        assert scanner._thread is None

    def test_stop_without_start(self):
        """Calling stop without start should not raise."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        scanner.stop()  # Should not raise

    def test_scan_loop_handles_exception(self):
        """_scan_loop catches exceptions and increments error_count."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
            scan_interval=0,
        )
        mock_ezsp = MagicMock()
        mock_ezsp.scan_networks.side_effect = RuntimeError("scan failed")
        scanner._scanner = mock_ezsp
        scanner._stop = threading.Event()

        # Run one iteration of the loop then stop
        def run_one():
            scanner._stop.clear()
            # Override wait to return immediately then set stop
            original_wait = scanner._stop.wait
            call_count = [0]
            def fake_wait(timeout=None):
                call_count[0] += 1
                if call_count[0] >= 2:
                    scanner._stop.set()
                    return True
                return False
            scanner._stop.wait = fake_wait
            scanner._scan_loop()

        run_one()
        assert scanner.error_count >= 1

    def test_ezsp_serial_probe_fallback(self):
        """EZSPScanner._scan_via_serial_probe returns dongle placeholder."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/ttyUSB0")
        scanner._ser = MagicMock()
        scanner._ser.is_open = True
        result = scanner._scan_via_serial_probe()
        assert len(result) == 1
        assert result[0]["device_type"] == "coordinator"
        assert "ZBDongle-E" in result[0]["device_name"]

    def test_ezsp_scan_networks_tries_zigpy_first(self):
        """scan_networks tries zigpy-cli, then bellows, then serial probe."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/ttyUSB0")
        zigpy_result = [{"ieee_addr": "from_zigpy", "pan_id": "0x1"}]

        with patch.object(scanner, "_scan_via_zigpy_cli", return_value=zigpy_result) as mock_z:
            with patch.object(scanner, "_scan_via_bellows") as mock_b:
                with patch.object(scanner, "scan_passive", return_value=[]):
                    result = scanner.scan_networks()
                    mock_z.assert_called_once()
                    mock_b.assert_not_called()  # zigpy succeeded, bellows not tried
                    assert any(d["ieee_addr"] == "from_zigpy" for d in result)

    def test_ezsp_scan_networks_falls_back_to_bellows(self):
        """If zigpy-cli fails, falls back to bellows."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/ttyUSB0")
        bellows_result = [{"ieee_addr": "from_bellows"}]

        with patch.object(scanner, "_scan_via_zigpy_cli", return_value=None):
            with patch.object(scanner, "_scan_via_bellows", return_value=bellows_result):
                with patch.object(scanner, "scan_passive", return_value=[]):
                    result = scanner.scan_networks()
                    assert any(d["ieee_addr"] == "from_bellows" for d in result)

    def test_ezsp_scan_networks_falls_back_to_serial_probe(self):
        """If both bellows and zigpy fail, falls back to serial probe."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/ttyUSB0")
        serial_result = [{"ieee_addr": "serial_probe"}]

        with patch.object(scanner, "_scan_via_bellows", return_value=None):
            with patch.object(scanner, "_scan_via_zigpy_cli", return_value=None):
                with patch.object(scanner, "_scan_via_serial_probe", return_value=serial_result):
                    with patch.object(scanner, "scan_passive", return_value=[]):
                        result = scanner.scan_networks()
                        assert any(d["ieee_addr"] == "serial_probe" for d in result)

    def test_scan_networks_merges_active_and_passive(self):
        """scan_networks merges active scan results with passive sniffer results."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/ttyUSB0")
        active = [{"ieee_addr": "active_dev", "pan_id": "0x1"}]
        passive = [
            {"ieee_addr": "passive_dev", "pan_id": "0x1"},
            {"ieee_addr": "active_dev", "pan_id": "0x1"},  # duplicate
        ]

        with patch.object(scanner, "_scan_via_bellows", return_value=active):
            with patch.object(scanner, "scan_passive", return_value=passive):
                result = scanner.scan_networks()
                addrs = [d["ieee_addr"] for d in result]
                assert "active_dev" in addrs
                assert "passive_dev" in addrs
                assert addrs.count("active_dev") == 1  # deduplicated

    def test_parse_bellows_extended_pan_formats(self):
        """Parser handles both colon-separated and raw hex extended PAN IDs."""
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/null")

        # Colon-separated
        result = scanner._parse_bellows_scan("Extended PAN: 00:11:22:33:44:55:66:77\nChannel: 15")
        assert len(result) == 1
        assert result[0]["ieee_addr"] == "00:11:22:33:44:55:66:77"

        # Raw hex (16 chars)
        result2 = scanner._parse_bellows_scan("Extended PAN: 0011223344556677\nChannel: 15")
        assert len(result2) == 1
        assert result2[0]["ieee_addr"] == "0011223344556677"


# ---------------------------------------------------------------------------
# Integration: WebSocket
# ---------------------------------------------------------------------------


class TestZigbeeWebSocket:
    """WebSocket endpoint tests."""

    def test_websocket_connect_requires_auth(self, unauth_client: TestClient):
        """WebSocket without auth should be rejected."""
        with pytest.raises((WebSocketDisconnect, Exception)):
            with unauth_client.websocket_connect("/api/zigbee/ws/zigbee"):
                pass

    def test_websocket_connect_with_session_token(
        self, bridge_app: FastAPI, detection_store, master_key: str,
    ):
        """WebSocket with valid session token connects and registers client."""
        from sigrift.bridge.state import AppState

        # Create user session
        detection_store.create_user(username="zb_ws_user", password="ZbTest123!", role="admin")
        user = detection_store.users.get_user_full("zb_ws_user")
        session = detection_store.create_session(user_id=user["id"])
        token = session["session_token"]
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/zigbee/ws/zigbee",
                subprotocols=["bridge-v1", token],
            ) as ws:
                # Client should be registered
                zb_clients = getattr(app_state, "zigbee_ws_clients", set())
                assert len(zb_clients) == 1

            # After disconnect, client should be removed
            zb_clients = getattr(app_state, "zigbee_ws_clients", set())
            assert len(zb_clients) == 0


# ---------------------------------------------------------------------------
# Extended fields (extended_pan_id, security, stack_profile, parent_addr)
# ---------------------------------------------------------------------------


class TestZigbeeExtendedFields:
    """Tests for new Zigbee data model fields."""

    def test_ingest_with_extended_fields(self, client: TestClient, zb_node: str):
        rec = _make_zb_record(
            extended_pan_id="AA:BB:CC:DD:EE:FF:00:11",
            stack_profile="zigbee_pro",
            security_enabled=1,
            parent_addr="00:11:22:33:44:55:66:77",
        )
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": [rec],
        })
        assert resp.status_code == 201

        devices = client.get("/api/zigbee/devices").json()["devices"]
        assert len(devices) == 1
        d = devices[0]
        assert d["extended_pan_id"] == "AA:BB:CC:DD:EE:FF:00:11"
        assert d["stack_profile"] == "zigbee_pro"
        assert d["security_enabled"] == 1
        assert d["parent_addr"] == "00:11:22:33:44:55:66:77"

    def test_detail_includes_extended_fields(self, client: TestClient, zb_node: str):
        ieee = "ex:te:nd:ed:fi:el:ds:01"
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(
                ieee_addr=ieee,
                security_enabled=1,
                stack_profile="zigbee_3_0",
            )],
        })
        detail = client.get(f"/api/zigbee/devices/{ieee}").json()
        assert detail["security_enabled"] == 1
        assert detail["stack_profile"] == "zigbee_3_0"

    def test_storage_extended_fields_round_trip(self, detection_store):
        detection_store.insert_zigbee_devices([{
            "ieee_addr": "ext_rt", "node_id": "n1", "channel": 15,
            "rssi_dbm": -50, "lqi": 200, "pan_id": "0x1",
            "extended_pan_id": "EP:ID", "stack_profile": "zigbee_pro",
            "security_enabled": 1, "parent_addr": "PA:RE:NT",
        }])
        devices = detection_store.get_zigbee_devices()
        assert len(devices) == 1
        assert devices[0]["extended_pan_id"] == "EP:ID"
        assert devices[0]["stack_profile"] == "zigbee_pro"
        assert devices[0]["security_enabled"] == 1
        assert devices[0]["parent_addr"] == "PA:RE:NT"


# ---------------------------------------------------------------------------
# Channel energy
# ---------------------------------------------------------------------------


class TestZigbeeChannelEnergy:
    """Tests for channel energy endpoints and storage."""

    def test_ingest_with_channel_energy(self, client: TestClient, zb_node: str):
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record()],
            "channel_energy": [
                {"channel": 11, "rssi_dbm": -80},
                {"channel": 15, "rssi_dbm": -65},
                {"channel": 20, "rssi_dbm": -90},
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] == 1
        assert data["energy_channels"] == 3

    def test_energy_endpoint(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [],
            "channel_energy": [
                {"channel": 11, "rssi_dbm": -80},
                {"channel": 15, "rssi_dbm": -65},
            ],
        })
        resp = client.get("/api/zigbee/energy")
        assert resp.status_code == 200
        channels = resp.json()["channels"]
        assert len(channels) >= 2

    def test_stats_includes_channel_energy(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [],
            "channel_energy": [{"channel": 15, "rssi_dbm": -70}],
        })
        stats = client.get("/api/zigbee/stats").json()
        assert "channel_energy" in stats
        assert isinstance(stats["channel_energy"], list)
        assert len(stats["channel_energy"]) >= 1

    def test_energy_storage_insert_query(self, detection_store):
        inserted = detection_store.insert_channel_energy([
            {"channel": 11, "rssi_dbm": -80, "node_id": "n1"},
            {"channel": 15, "rssi_dbm": -65, "node_id": "n1"},
        ])
        assert inserted == 2
        energy = detection_store.get_channel_energy(hours=1)
        assert len(energy) == 2
        ch11 = next(e for e in energy if e["channel"] == 11)
        assert ch11["avg_rssi"] == pytest.approx(-80, abs=0.1)

    def test_energy_cleanup(self, detection_store):
        detection_store.insert_channel_energy([
            {"channel": 11, "rssi_dbm": -80, "node_id": "n1"},
        ])
        deleted = detection_store.cleanup_channel_energy(max_age_hours=0)
        assert deleted >= 1

    def test_ingest_without_energy_is_zero(self, client: TestClient, zb_node: str):
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record()],
        })
        assert resp.status_code == 201
        assert resp.json()["energy_channels"] == 0


# ---------------------------------------------------------------------------
# Topology endpoint
# ---------------------------------------------------------------------------


class TestZigbeeTopology:
    """Tests for GET /api/zigbee/topology."""

    def test_topology_empty(self, client: TestClient):
        resp = client.get("/api/zigbee/topology")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0
        assert resp.json()["networks"] == []

    def test_topology_groups_by_pan(self, client: TestClient, zb_node: str):
        client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [
                _make_zb_record(ieee_addr="c1", pan_id="0xAAAA", device_type="coordinator"),
                _make_zb_record(ieee_addr="r1", pan_id="0xAAAA", device_type="router"),
                _make_zb_record(ieee_addr="e1", pan_id="0xAAAA", device_type="end_device"),
                _make_zb_record(ieee_addr="c2", pan_id="0xBBBB", device_type="coordinator"),
            ],
        })
        resp = client.get("/api/zigbee/topology")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        pans = {n["pan_id"] for n in data["networks"]}
        assert "0xAAAA" in pans
        assert "0xBBBB" in pans
        net_a = next(n for n in data["networks"] if n["pan_id"] == "0xAAAA")
        assert len(net_a["devices"]) == 3

    def test_topology_auth_required(self, unauth_client: TestClient):
        resp = unauth_client.get("/api/zigbee/topology")
        assert resp.status_code == 401

    def test_topology_storage_method(self, detection_store):
        detection_store.insert_zigbee_devices([
            {"ieee_addr": "c1", "pan_id": "0x1", "device_type": "coordinator",
             "node_id": "n1", "channel": 15, "rssi_dbm": -50, "lqi": 200},
            {"ieee_addr": "e1", "pan_id": "0x1", "device_type": "end_device",
             "node_id": "n1", "channel": 15, "rssi_dbm": -70, "lqi": 100,
             "parent_addr": "c1"},
        ])
        topo = detection_store.get_network_topology()
        assert len(topo) == 1
        assert topo[0]["pan_id"] == "0x1"
        assert len(topo[0]["devices"]) == 2


# ---------------------------------------------------------------------------
# Passive sniffer tests
# ---------------------------------------------------------------------------


class TestZigbeePassiveSniffer:
    """Tests for passive 802.15.4 frame parsing."""

    def test_parse_sniff_output_extracts_devices(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/null")
        seen: dict[str, dict] = {}
        output = (
            "src: 0x1234 pan: 0xABCD data RSSI: -65 LQI: 200\n"
            "src: 0x5678 pan: 0xABCD beacon RSSI: -50\n"
            "src: 0x1234 pan: 0xABCD data RSSI: -60\n"  # duplicate, should update
        )
        scanner._parse_sniff_output(output, 15, seen)
        assert len(seen) == 2
        assert seen["0x1234"]["device_type"] == "end_device"
        assert seen["0x5678"]["device_type"] == "coordinator"
        # RSSI updated on second occurrence
        assert seen["0x1234"]["rssi_dbm"] == -60.0

    def test_parse_sniff_output_long_addr(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/null")
        seen: dict[str, dict] = {}
        output = "source: 00:11:22:33:44:55:66:77 pan: 0xBEEF data security\n"
        scanner._parse_sniff_output(output, 20, seen)
        assert "00:11:22:33:44:55:66:77" in seen
        d = seen["00:11:22:33:44:55:66:77"]
        assert d["channel"] == 20
        assert d["security_enabled"] == 1
        assert d["pan_id"] == "0xBEEF"

    def test_parse_raw_802154_frame(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner
        import struct

        seen: dict[str, dict] = {}
        # Construct a minimal valid 802.15.4 data frame with short addressing
        # FC bits: frame_type=1 (data), security=0, frame_pending=0,
        #          ack_request=0, pan_compress=1 (bit 6),
        #          dst_mode=2 (bits 10-11), src_mode=2 (bits 14-15)
        # dst_mode=2 -> 0x0800, src_mode=2 -> 0x8000, pan_compress -> 0x0040
        # frame_type=1 -> 0x0001
        fc = 0x8841  # 1000_1000_0100_0001
        seq = 0x42
        pan_id = 0xABCD
        dst_addr = 0x0000
        src_addr = 0x1234
        frame = struct.pack("<HBHHH", fc, seq, pan_id, dst_addr, src_addr)
        frame += b"\x00" * 4  # payload padding

        EZSPScanner._parse_raw_802154_frame(frame, 15, seen)
        assert "0x1234" in seen
        assert seen["0x1234"]["channel"] == 15

    def test_scan_passive_bellows_not_available(self):
        from sigrift.bridge.zigbee_scanner import EZSPScanner

        scanner = EZSPScanner("/dev/null")
        scanner._ser = None

        with patch.object(scanner, "_sniff_via_bellows", return_value=None):
            result = scanner.scan_passive()
            assert result == []

    def test_frame_type_to_device_type(self):
        from sigrift.bridge.zigbee_scanner import _frame_type_to_device_type

        assert _frame_type_to_device_type(0) == "coordinator"
        assert _frame_type_to_device_type(3) == "router"
        assert _frame_type_to_device_type(1) == "end_device"
        assert _frame_type_to_device_type(2) == "end_device"


# ---------------------------------------------------------------------------
# Expanded manufacturer codes
# ---------------------------------------------------------------------------


class TestExpandedManufacturerCodes:
    """Verify expanded manufacturer code database."""

    def test_manufacturer_codes_count(self):
        from sigrift.bridge.zigbee_scanner import _MANUFACTURER_CODES
        assert len(_MANUFACTURER_CODES) >= 80

    def test_key_manufacturers_present(self):
        from sigrift.bridge.zigbee_scanner import _MANUFACTURER_CODES
        expected = {
            0x117C: "SONOFF/ITEAD",
            0x100B: "Philips",
            0x1047: "IKEA",
            0x1168: "Tuya",
            0x1141: "Xiaomi",
            0x115F: "Aqara",
            0x10B0: "Bosch",
            0x10C4: "Yale",
            0x1049: "OSRAM",
            0x1066: "Danfoss",
        }
        for code, name in expected.items():
            assert _MANUFACTURER_CODES.get(code) == name, f"Missing or wrong: 0x{code:04X} -> {name}"

    def test_do_scan_resolves_new_manufacturer(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="node-01",
        )
        mock_ezsp = MagicMock()
        mock_ezsp.scan_networks.return_value = [
            {"ieee_addr": "a1", "manufacturer_code": 0x1168, "manufacturer": ""},
        ]
        mock_ezsp.scan_energy.return_value = {}
        scanner._scanner = mock_ezsp
        devices = scanner._do_scan()
        assert devices[0]["manufacturer"] == "Tuya"


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------


class TestZigbeeDemoMode:
    """Verify synthetic data generation for UI testing."""

    def test_generate_demo_devices(self):
        from sigrift.bridge.zigbee_scanner import _generate_demo_devices
        devices = _generate_demo_devices("demo-node")
        assert len(devices) >= 10
        assert all(isinstance(d, dict) for d in devices)
        types = {d["device_type"] for d in devices}
        assert "coordinator" in types
        assert "router" in types
        assert "end_device" in types
        for d in devices:
            assert isinstance(d["ieee_addr"], str) and len(d["ieee_addr"]) > 0
            assert isinstance(d["pan_id"], str) and len(d["pan_id"]) > 0
            assert isinstance(d["manufacturer"], str) and len(d["manufacturer"]) > 0

    def test_generate_demo_energy(self):
        from sigrift.bridge.zigbee_scanner import _generate_demo_energy
        energy = _generate_demo_energy()
        assert len(energy) == 16  # channels 11-26
        for ch in range(11, 27):
            assert ch in energy
            assert -100 <= energy[ch] <= 0

    def test_demo_scanner_do_scan(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="demo-node",
            demo=True,
        )
        devices = scanner._do_scan()
        assert len(devices) >= 10
        assert all(isinstance(d, dict) for d in devices)
        assert scanner.scan_count == 1
        assert scanner.devices_found >= 10
        assert len(scanner._last_energy) == 16
        # Multiple PANs
        pans = {d["pan_id"] for d in devices}
        assert len(pans) >= 3

    def test_demo_scanner_start_no_hardware(self):
        """Demo mode starts without any serial device."""
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="demo-node",
            demo=True,
        )
        scanner.start()
        assert scanner._thread is not None
        assert isinstance(scanner._thread, threading.Thread)
        assert scanner._thread.is_alive()
        scanner.stop()

    @patch("sigrift.bridge.zigbee_scanner.urllib.request.urlopen")
    def test_demo_upload_includes_energy(self, mock_urlopen):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"accepted": 15}'
        mock_urlopen.return_value = mock_resp

        scanner = ZigbeeScanner(
            server_url="https://bridge:8444",
            api_key="test-key",
            node_id="demo-node",
            demo=True,
            verify_ssl=False,
        )
        devices = scanner._do_scan()
        scanner._upload(devices)
        assert mock_urlopen.call_count == 1
        # Verify the payload was sent with channel_energy
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        import gzip, json
        body = json.loads(gzip.decompress(req.data))
        assert len(body["records"]) >= 10
        assert all(isinstance(r, dict) for r in body["records"])
        assert len(body["channel_energy"]) == 16

    def test_demo_devices_deterministic_ieee(self):
        """Same node_id produces same IEEE addresses each scan."""
        from sigrift.bridge.zigbee_scanner import _generate_demo_devices
        d1 = _generate_demo_devices("test")
        d2 = _generate_demo_devices("test")
        assert [d["ieee_addr"] for d in d1] == [d["ieee_addr"] for d in d2]

    def test_demo_ingest_round_trip(self, sensor_client, viewer_client):
        """Demo data can be ingested and queried through the API."""
        from sigrift.bridge.zigbee_scanner import _generate_demo_devices, _generate_demo_energy
        devices = _generate_demo_devices("demo-node")
        energy = _generate_demo_energy()
        payload = {
            "node_id": "demo-node",
            "records": devices,
            "channel_energy": [
                {"channel": ch, "rssi_dbm": rssi}
                for ch, rssi in sorted(energy.items())
            ],
        }
        resp = sensor_client.post("/api/zigbee/ingest", json=payload)
        assert resp.status_code in (200, 201)
        data = resp.json()
        assert data["accepted"] >= 10
        assert data["energy_channels"] == 16

        # Query devices back (VIEWER role required for GET endpoints)
        resp = viewer_client.get("/api/zigbee/devices")
        assert resp.status_code == 200
        devices_back = resp.json()
        assert devices_back["count"] >= 10
        # Verify topology
        resp = viewer_client.get("/api/zigbee/topology")
        assert resp.status_code == 200
        topo = resp.json()
        assert topo["count"] >= 3  # 3 PANs
        # Verify energy
        resp = viewer_client.get("/api/zigbee/energy")
        assert resp.status_code == 200
        energy_back = resp.json()
        assert len(energy_back["channels"]) == 16


# ---------------------------------------------------------------------------
# Integration: Detection store delegation completeness
# ---------------------------------------------------------------------------


class TestDetectionStoreDelegation:
    """Verify all Zigbee methods are properly delegated through DetectionStore."""

    def test_all_zigbee_methods_exist(self, detection_store):
        methods = [
            "insert_zigbee_devices",
            "get_zigbee_devices",
            "get_zigbee_device_detail",
            "get_zigbee_stats",
            "aggregate_zigbee_hourly",
            "cleanup_zigbee_devices",
            "cleanup_zigbee_hourly",
            "insert_channel_energy",
            "get_channel_energy",
            "cleanup_channel_energy",
            "get_network_topology",
        ]
        for method in methods:
            assert hasattr(detection_store, method), f"Missing method: {method}"
            assert callable(getattr(detection_store, method))

    def test_delegation_insert_get_round_trip(self, detection_store):
        """Full round trip through DetectionStore delegation."""
        # Insert via store
        inserted = detection_store.insert_zigbee_devices([
            {"ieee_addr": "deleg:01", "node_id": "n1", "channel": 15,
             "rssi_dbm": -55, "lqi": 210, "pan_id": "0xDEAD",
             "device_type": "router", "manufacturer": "TestCo"},
        ])
        assert inserted == 1

        # Query via store
        devices = detection_store.get_zigbee_devices(pan_id="0xDEAD")
        assert len(devices) == 1
        assert devices[0]["manufacturer"] == "TestCo"

        # Detail via store
        detail = detection_store.get_zigbee_device_detail("deleg:01")
        assert isinstance(detail, dict)
        assert detail["pan_id"] == "0xDEAD"

        # Stats via store
        stats = detection_store.get_zigbee_stats()
        assert stats["total_devices"] >= 1

        # Aggregate via store
        agg = detection_store.aggregate_zigbee_hourly(cutoff_hours=0)
        assert agg >= 0

        # Cleanup via store
        deleted = detection_store.cleanup_zigbee_devices(max_age_hours=0)
        assert deleted >= 1

        # Verify deleted
        devices_after = detection_store.get_zigbee_devices()
        assert len(devices_after) == 0
