"""Cross-protocol ingest edge case tests.

Tests boundary conditions for BT, WiFi, Zigbee, and RF detection ingest
endpoints including batch size limits, encoding edge cases, concurrent
ingest from multiple nodes, and gzip error paths.
"""

from __future__ import annotations

import gzip
import json
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

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


def _make_bt_record(**overrides) -> dict:
    base = {
        "device_addr": "aa:bb:cc:dd:ee:ff",
        "device_name": "TestDevice",
        "device_type": "ble",
        "device_class": 0,
        "device_class_name": "",
        "appearance": 0,
        "rssi_dbm": -55.0,
        "tx_power_dbm": None,
        "manufacturer_id": None,
        "manufacturer": "Acme",
        "service_uuids": [],
        "adv_data": {},
        "connectable": True,
        "bonded": False,
        "channel": 37,
    }
    base.update(overrides)
    return base


def _make_wifi_record(**overrides) -> dict:
    base = {
        "bssid": "aa:bb:cc:11:22:33",
        "ssid": "TestNet",
        "channel": 6,
        "band": "2.4GHz",
        "security": "WPA2",
        "signal_dbm": -45.0,
    }
    base.update(overrides)
    return base


def _make_zb_record(**overrides) -> dict:
    base = {
        "ieee_addr": "00:11:22:33:44:55:66:77",
        "short_addr": "0x1234",
        "device_name": "TestSensor",
        "device_type": "end_device",
        "pan_id": "0xABCD",
        "channel": 15,
        "rssi_dbm": -65.0,
        "lqi": 180,
        "manufacturer_code": 0x117C,
        "manufacturer": "SONOFF/ITEAD",
        "clusters": ["0x0000", "0x0006"],
        "endpoints": [1],
        "power_source": "battery",
        "profile_id": "0x0104",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "ingest_sensor_key", role="sensor")


@pytest.fixture
def sensor_client(bridge_app: FastAPI, sensor_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": sensor_key})


@pytest.fixture
def bt_node(client: TestClient) -> str:
    node_id = "bt-edge-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id, "host": "10.0.0.50", "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


@pytest.fixture
def wifi_node(client: TestClient) -> str:
    node_id = "wifi-edge-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id, "host": "10.0.0.51", "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


@pytest.fixture
def zb_node(client: TestClient) -> str:
    node_id = "zb-edge-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id, "host": "10.0.0.52", "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


# ---------------------------------------------------------------------------
# Empty batches (0 records)
# ---------------------------------------------------------------------------


class TestEmptyBatches:
    """Verify all protocols accept empty record lists gracefully."""

    def test_bt_empty_batch(self, client: TestClient, bt_node: str):
        """BT ingest with zero records returns 201 with 0 inserted."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node, "records": [],
        })
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 0

    def test_wifi_empty_batch(self, client: TestClient, wifi_node: str):
        """WiFi ingest with zero records returns 201 with 0 inserted."""
        resp = client.post("/api/wifi/ingest", json={
            "node_id": wifi_node, "records": [],
        })
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 0

    def test_zigbee_empty_batch(self, client: TestClient, zb_node: str):
        """Zigbee ingest with zero records returns 201 with 0 accepted."""
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": [],
        })
        assert resp.status_code == 201
        assert resp.json()["accepted"] == 0


# ---------------------------------------------------------------------------
# Exactly-at-limit batch sizes (500)
# ---------------------------------------------------------------------------


class TestExactLimitBatch:
    """Verify that batches with exactly 500 records are accepted."""

    def test_bt_500_records(self, client: TestClient, bt_node: str):
        """BT ingest with exactly 500 records is accepted."""
        records = [
            _make_bt_record(device_addr=f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}")
            for i in range(500)
        ]
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node, "records": records,
        })
        assert resp.status_code == 201

    def test_zigbee_500_records(self, client: TestClient, zb_node: str):
        """Zigbee ingest with exactly 500 records is accepted."""
        records = [
            _make_zb_record(ieee_addr=f"00:11:22:33:44:55:{i // 256:02x}:{i % 256:02x}")
            for i in range(500)
        ]
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": records,
        })
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# One-over-limit batch sizes (501)
# ---------------------------------------------------------------------------


class TestOverLimitBatch:
    """Verify that batches exceeding 500 records are rejected."""

    def test_bt_501_records(self, client: TestClient, bt_node: str):
        """BT ingest with 501 records is rejected with 400."""
        records = [
            _make_bt_record(device_addr=f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}")
            for i in range(501)
        ]
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node, "records": records,
        })
        assert resp.status_code == 400
        assert "500" in resp.json()["detail"]

    def test_zigbee_501_records(self, client: TestClient, zb_node: str):
        """Zigbee ingest with 501 records is rejected with 400."""
        records = [
            _make_zb_record(ieee_addr=f"00:11:22:33:44:55:{i // 256:02x}:{i % 256:02x}")
            for i in range(501)
        ]
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": records,
        })
        assert resp.status_code == 400
        assert "500" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Unicode / emoji in device names
# ---------------------------------------------------------------------------


class TestUnicodeDeviceNames:
    """Verify that Unicode/emoji device names are handled safely."""

    def test_bt_emoji_device_name(self, client: TestClient, bt_node: str):
        """BT device with emoji name is accepted."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(
                device_name="My\u2764Device\U0001F4F6",
                device_addr="aa:bb:cc:dd:00:01",
            )],
        })
        assert resp.status_code == 201

    def test_wifi_unicode_ssid(self, client: TestClient, wifi_node: str):
        """WiFi SSID with CJK characters is accepted."""
        resp = client.post("/api/wifi/ingest", json={
            "node_id": wifi_node,
            "records": [_make_wifi_record(
                ssid="\u5bcc\u58eb\u5c71WiFi",
                bssid="aa:bb:cc:dd:00:02",
            )],
        })
        assert resp.status_code == 201

    def test_zigbee_emoji_device_name(self, client: TestClient, zb_node: str):
        """Zigbee device with emoji name is accepted."""
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(
                device_name="Sensor\U0001F321\u2600",
                ieee_addr="00:11:22:33:44:55:00:01",
            )],
        })
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Extreme RSSI values
# ---------------------------------------------------------------------------


class TestExtremeRSSI:
    """Verify handling of extreme but valid RSSI values."""

    def test_bt_rssi_minus_120(self, client: TestClient, bt_node: str):
        """BT device at -120 dBm (near noise floor) is accepted."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(rssi_dbm=-120.0, device_addr="aa:bb:cc:dd:00:03")],
        })
        assert resp.status_code == 201

    def test_bt_rssi_zero(self, client: TestClient, bt_node: str):
        """BT device at 0 dBm (maximum signal) is accepted."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(rssi_dbm=0.0, device_addr="aa:bb:cc:dd:00:04")],
        })
        assert resp.status_code == 201

    def test_wifi_rssi_minus_120(self, client: TestClient, wifi_node: str):
        """WiFi AP at -120 dBm is accepted."""
        resp = client.post("/api/wifi/ingest", json={
            "node_id": wifi_node,
            "records": [_make_wifi_record(signal_dbm=-120.0, bssid="aa:bb:cc:dd:00:05")],
        })
        assert resp.status_code == 201

    def test_zigbee_rssi_minus_120(self, client: TestClient, zb_node: str):
        """Zigbee device at -120 dBm is accepted."""
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(
                rssi_dbm=-120.0,
                ieee_addr="00:11:22:33:44:55:00:02",
            )],
        })
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Duplicate records in same batch
# ---------------------------------------------------------------------------


class TestDuplicateRecords:
    """Verify that duplicate device entries in a single batch are handled."""

    def test_bt_duplicate_addr_same_batch(self, client: TestClient, bt_node: str):
        """Two BT records with same device_addr in one batch are accepted."""
        rec = _make_bt_record(device_addr="aa:bb:cc:dd:ee:ff")
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [rec, rec],
        })
        assert resp.status_code == 201

    def test_wifi_duplicate_bssid_same_batch(self, client: TestClient, wifi_node: str):
        """Two WiFi records with same BSSID in one batch are accepted."""
        rec = _make_wifi_record(bssid="aa:bb:cc:11:22:33")
        resp = client.post("/api/wifi/ingest", json={
            "node_id": wifi_node,
            "records": [rec, rec],
        })
        assert resp.status_code == 201

    def test_zigbee_duplicate_ieee_same_batch(self, client: TestClient, zb_node: str):
        """Two Zigbee records with same IEEE addr in one batch are accepted."""
        rec = _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77")
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [rec, rec],
        })
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Concurrent ingest from multiple nodes (same device seen by 2+ nodes)
# ---------------------------------------------------------------------------


class TestConcurrentMultiNodeIngest:
    """Verify that the same device ingested by different nodes concurrently is handled."""

    def test_bt_multi_node_same_device(self, client: TestClient, bt_node: str):
        """Same BT device reported by two nodes in sequence is accepted."""
        # Register a second node
        node2 = "bt-edge-02"
        client.post("/api/nodes/register", json={
            "node_id": node2, "host": "10.0.0.60", "port": 8080,
        })
        rec = _make_bt_record(device_addr="aa:bb:cc:dd:ee:ff")

        resp1 = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node, "records": [rec],
        })
        resp2 = client.post("/api/bluetooth/ingest", json={
            "node_id": node2, "records": [rec],
        })
        assert resp1.status_code == 201
        assert resp2.status_code == 201

    def test_zigbee_multi_node_same_device(self, client: TestClient, zb_node: str):
        """Same Zigbee device reported by two nodes in sequence is accepted."""
        node2 = "zb-edge-02"
        client.post("/api/nodes/register", json={
            "node_id": node2, "host": "10.0.0.62", "port": 8080,
        })
        rec = _make_zb_record(ieee_addr="00:11:22:33:44:55:66:77")

        resp1 = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node, "records": [rec],
        })
        resp2 = client.post("/api/zigbee/ingest", json={
            "node_id": node2, "records": [rec],
        })
        assert resp1.status_code == 201
        assert resp2.status_code == 201


# ---------------------------------------------------------------------------
# Gzip edge cases
# ---------------------------------------------------------------------------


class TestGzipEdgeCases:
    """Test gzip-compressed ingest error paths."""

    def test_bt_gzip_empty_payload(self, client: TestClient, bt_node: str):
        """Gzip-compressed empty JSON object should succeed or fail gracefully."""
        payload = json.dumps({"node_id": bt_node, "records": []}).encode()
        compressed = gzip.compress(payload)
        resp = client.post(
            "/api/bluetooth/ingest",
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 0

    def test_bt_gzip_invalid_data(self, client: TestClient):
        """Gzip header with non-gzip data returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=b"this is not gzip at all",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower() or "gzip" in resp.json()["detail"].lower()

    def test_bt_gzip_truncated_data(self, client: TestClient, bt_node: str):
        """Truncated gzip stream gets a clean 400 (EOFError is caught)."""
        payload = json.dumps({"node_id": bt_node, "records": [_make_bt_record()]}).encode()
        compressed = gzip.compress(payload)
        truncated = compressed[:len(compressed) // 2]
        resp = client.post(
            "/api/bluetooth/ingest",
            content=truncated,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower()

    def test_zigbee_gzip_invalid_data(self, client: TestClient):
        """Zigbee ingest with corrupted gzip gets a clean 400."""
        resp = client.post(
            "/api/zigbee/ingest",
            content=b"\x1f\x8b\x08\x00CORRUPT",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 400

    def test_bt_plain_with_gzip_header(self, client: TestClient, bt_node: str):
        """Sending plain JSON with Content-Encoding: gzip header returns 400."""
        payload = json.dumps({"node_id": bt_node, "records": []}).encode()
        resp = client.post(
            "/api/bluetooth/ingest",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        assert resp.status_code == 400

    def test_bt_gzip_without_header(self, client: TestClient, bt_node: str):
        """Sending gzip data without Content-Encoding header fails to parse as JSON."""
        payload = json.dumps({"node_id": bt_node, "records": [_make_bt_record()]}).encode()
        compressed = gzip.compress(payload)
        resp = client.post(
            "/api/bluetooth/ingest",
            content=compressed,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": client.headers.get("X-API-Key", ""),
            },
        )
        # Without the gzip header, the server tries to parse compressed data as JSON
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# XSS / HTML injection in device names
# ---------------------------------------------------------------------------


class TestMarkupInDeviceNames:
    """Device names are stored as heard, not HTML-escaped.

    The pages escape them on output (tests/bridge/js/); escaping them here
    as well showed entities such as &#x27; in place of the name.
    """

    def test_bt_markup_name_stored_as_heard(self, client: TestClient, bt_node: str):
        name = '<img src=x onerror="alert(1)"> Joe\'s & co'
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(device_name=name, device_addr="aa:bb:cc:dd:00:10")],
        })
        assert resp.status_code == 201
        devices = client.get("/api/bluetooth/devices").json()["devices"]
        assert [d["device_name"] for d in devices] == [name]

    def test_zigbee_markup_name_stored_as_heard(self, client: TestClient, zb_node: str):
        name = '<script>document.cookie</script> & "x"'
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(device_name=name, ieee_addr="00:11:22:33:44:55:00:10")],
        })
        assert resp.status_code == 201
        devices = client.get("/api/zigbee/devices").json()["devices"]
        assert [d["device_name"] for d in devices] == [name]


# ---------------------------------------------------------------------------
# Large field values
# ---------------------------------------------------------------------------


class TestLargeFieldValues:
    """Verify that extremely large field values are handled safely."""

    def test_bt_long_device_name(self, client: TestClient, bt_node: str):
        """BT device with extremely long name is accepted (truncated or escaped)."""
        long_name = "A" * 1000
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(device_name=long_name, device_addr="aa:bb:cc:dd:00:20")],
        })
        assert resp.status_code == 201

    def test_wifi_long_ssid(self, client: TestClient, wifi_node: str):
        """WiFi SSID exceeding 32 bytes is truncated to spec limit."""
        long_ssid = "X" * 255
        resp = client.post("/api/wifi/ingest", json={
            "node_id": wifi_node,
            "records": [_make_wifi_record(ssid=long_ssid, bssid="aa:bb:cc:dd:00:21")],
        })
        assert resp.status_code == 201
        # Verify SSID was truncated to at most 32 bytes
        networks = client.get("/api/wifi/networks").json()["networks"]
        for n in networks:
            if n.get("bssid") == "aa:bb:cc:dd:00:21":
                assert len(n.get("ssid", "").encode("utf-8")) <= 32

    def test_zigbee_long_device_name(self, client: TestClient, zb_node: str):
        """Zigbee device with 1000-char name is accepted (truncated to 64)."""
        long_name = "Z" * 1000
        resp = client.post("/api/zigbee/ingest", json={
            "node_id": zb_node,
            "records": [_make_zb_record(device_name=long_name, ieee_addr="00:11:22:33:44:55:00:20")],
        })
        assert resp.status_code == 201
        # Verify the name was truncated
        devices = client.get("/api/zigbee/devices").json()["devices"]
        for d in devices:
            if d.get("ieee_addr") == "00:11:22:33:44:55:00:20":
                assert len(d.get("device_name", "")) <= 64
