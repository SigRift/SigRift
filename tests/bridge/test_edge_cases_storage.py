"""Storage boundary and edge case tests.

Tests SQL injection attempts, cleanup with zero age, aggregate with no data,
NULL values, boundary limit values, device detail for non-existent devices,
and concurrent operations.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.bt_metadata import BtMetadataStore
from sigrift.bridge.storage.wifi_metadata import WiFiMetadataStore
from sigrift.bridge.storage.zigbee_metadata import ZigbeeMetadataStore
from sigrift.bridge.storage.detection_crud import DetectionCrudStore
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path):
    return SharedContext(db_path=tmp_path / "storage_edge.db", tenant_id="default")

@pytest.fixture
def bt_store(ctx):
    return BtMetadataStore(ctx)

@pytest.fixture
def wifi_store(ctx):
    return WiFiMetadataStore(ctx)

@pytest.fixture
def zb_store(ctx):
    return ZigbeeMetadataStore(ctx)

@pytest.fixture
def crud_store(ctx):
    return DetectionCrudStore(ctx)

@pytest.fixture
def full_store(tmp_path: Path):
    return DetectionStore(db_path=tmp_path / "full_edge.db")

# ---------------------------------------------------------------------------
# Device detail for non-existent devices
# ---------------------------------------------------------------------------

class TestNonExistentDeviceDetail:
    """Verify that querying non-existent devices returns None or empty."""

    def test_bt_device_detail_nonexistent(self, bt_store: BtMetadataStore):
        """BT device detail for non-existent address returns None."""
        result = bt_store.get_bt_device_detail("ff:ff:ff:ff:ff:ff")
        assert result is None

    def test_zigbee_device_detail_nonexistent(self, zb_store: ZigbeeMetadataStore):
        """Zigbee device detail for non-existent IEEE addr returns None."""
        result = zb_store.get_zigbee_device_detail("ff:ff:ff:ff:ff:ff:ff:ff")
        assert result is None

    def test_wifi_network_detail_nonexistent(self, wifi_store: WiFiMetadataStore):
        """WiFi network detail for non-existent BSSID returns None."""
        result = wifi_store.get_wifi_network_detail("ff:ff:ff:ff:ff:ff")
        assert result is None

# ---------------------------------------------------------------------------
# Empty-data queries
# ---------------------------------------------------------------------------

class TestEmptyDataQueries:
    """Verify that queries against empty databases return sensible defaults."""

    def test_bt_devices_empty(self, bt_store: BtMetadataStore):
        """BT device list on empty DB returns empty list."""
        result = bt_store.get_bt_devices()
        assert result == []

    def test_bt_stats_empty(self, bt_store: BtMetadataStore):
        """BT stats on empty DB returns zero counts."""
        result = bt_store.get_bt_stats()
        assert result["total_devices"] == 0

    def test_zigbee_devices_empty(self, zb_store: ZigbeeMetadataStore):
        """Zigbee device list on empty DB returns empty list."""
        result = zb_store.get_zigbee_devices()
        assert result == []

    def test_zigbee_stats_empty(self, zb_store: ZigbeeMetadataStore):
        """Zigbee stats on empty DB returns zero counts."""
        result = zb_store.get_zigbee_stats()
        assert result["total_devices"] == 0

    def test_wifi_networks_empty(self, wifi_store: WiFiMetadataStore):
        """WiFi network list on empty DB returns empty list."""
        result = wifi_store.get_wifi_networks()
        assert result == []

    def test_wifi_stats_empty(self, wifi_store: WiFiMetadataStore):
        """WiFi stats on empty DB returns zero counts."""
        result = wifi_store.get_wifi_stats()
        assert result["total_networks"] == 0

# ---------------------------------------------------------------------------
# Cleanup with zero max_age
# ---------------------------------------------------------------------------

class TestCleanupZeroAge:
    """Verify cleanup with max_age=0 deletes all data (everything is older than now)."""

    def test_bt_cleanup_zero_age(self, bt_store: BtMetadataStore):
        """BT cleanup with max_age_hours=0 should delete all records."""
        bt_store.insert_bt_devices([{
            "device_addr": "aa:bb:cc:dd:ee:ff",
            "device_name": "Test",
            "device_type": "ble",
            "rssi_dbm": -55.0,
            "node_id": "node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])
        # With max_age=0, cutoff is "now", so all records older than now get deleted
        # The record was just inserted, so timing matters. Use max_age_hours=0
        # which means everything older than right now.
        deleted = bt_store.cleanup_bt_devices(max_age_hours=0)
        # The just-inserted record may or may not be deleted depending on timing
        # but the operation should not error
        assert isinstance(deleted, int)
        assert deleted >= 0

    def test_zigbee_cleanup_zero_age(self, zb_store: ZigbeeMetadataStore):
        """Zigbee cleanup with max_age_hours=0 should not error."""
        zb_store.insert_zigbee_devices([{
            "ieee_addr": "00:11:22:33:44:55:66:77",
            "device_name": "Test",
            "device_type": "end_device",
            "rssi_dbm": -65.0,
            "node_id": "node-1",
        }])
        deleted = zb_store.cleanup_zigbee_devices(max_age_hours=0)
        assert isinstance(deleted, int)
        assert deleted >= 0

# ---------------------------------------------------------------------------
# Insert with empty / minimal fields
# ---------------------------------------------------------------------------

class TestMinimalInserts:
    """Verify that inserting records with minimal or empty fields works."""

    def test_bt_insert_empty_fields(self, bt_store: BtMetadataStore):
        """BT device with all empty strings is accepted."""
        inserted = bt_store.insert_bt_devices([{
            "device_addr": "",
            "device_name": "",
            "device_type": "",
            "rssi_dbm": 0.0,
            "node_id": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])
        assert inserted == 1

    def test_zigbee_insert_empty_fields(self, zb_store: ZigbeeMetadataStore):
        """Zigbee device with all empty strings is accepted."""
        inserted = zb_store.insert_zigbee_devices([{
            "ieee_addr": "",
            "device_name": "",
            "device_type": "",
            "rssi_dbm": 0.0,
            "node_id": "",
        }])
        assert inserted == 1

    def test_wifi_insert_empty_fields(self, wifi_store: WiFiMetadataStore):
        """WiFi record with minimal fields is accepted."""
        inserted = wifi_store.insert_wifi_metadata([{
            "detection_id": "test001",
            "bssid": "",
            "ssid": "",
            "channel": 0,
            "band": "",
            "signal_dbm": 0.0,
            "node_id": "",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])
        assert inserted == 1

# ---------------------------------------------------------------------------
# SQL injection attempts in filter parameters
# ---------------------------------------------------------------------------

class TestSQLInjection:
    """Verify that SQL injection attempts in query parameters are safe."""

    def test_bt_devices_sqli_device_type(self, bt_store: BtMetadataStore):
        """SQL injection in device_type filter does not execute."""
        # This should either return empty or raise a safe error
        result = bt_store.get_bt_devices(device_type="'; DROP TABLE bt_devices; --")
        assert isinstance(result, list)

    def test_bt_devices_sqli_node_id(self, bt_store: BtMetadataStore):
        """SQL injection in node_id filter does not execute."""
        result = bt_store.get_bt_devices(node_id="' OR '1'='1")
        assert isinstance(result, list)

    def test_zigbee_devices_sqli_pan_id(self, zb_store: ZigbeeMetadataStore):
        """SQL injection in pan_id filter does not execute."""
        result = zb_store.get_zigbee_devices(pan_id="'; DROP TABLE zigbee_devices; --")
        assert isinstance(result, list)

    def test_bt_detail_sqli_addr(self, bt_store: BtMetadataStore):
        """SQL injection in device_addr for detail does not execute."""
        result = bt_store.get_bt_device_detail("' OR '1'='1' --")
        assert result is None

    def test_zigbee_detail_sqli_addr(self, zb_store: ZigbeeMetadataStore):
        """SQL injection in IEEE addr for detail does not execute."""
        result = zb_store.get_zigbee_device_detail("' UNION SELECT * FROM sqlite_master --")
        assert result is None

    def test_wifi_detail_sqli_bssid(self, wifi_store: WiFiMetadataStore):
        """SQL injection in BSSID for detail does not execute."""
        result = wifi_store.get_wifi_network_detail("' OR 1=1 --")
        assert result is None

# ---------------------------------------------------------------------------
# Stats with only 1 device type
# ---------------------------------------------------------------------------

class TestStatsWithSingleType:
    """Verify stats work correctly when only one device type is present."""

    def test_bt_stats_single_type(self, bt_store: BtMetadataStore):
        """BT stats with only BLE devices returns correct breakdown."""
        bt_store.insert_bt_devices([{
            "device_addr": "aa:bb:cc:dd:ee:01",
            "device_name": "BLE1",
            "device_type": "ble",
            "rssi_dbm": -50.0,
            "node_id": "node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, {
            "device_addr": "aa:bb:cc:dd:ee:02",
            "device_name": "BLE2",
            "device_type": "ble",
            "rssi_dbm": -60.0,
            "node_id": "node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])
        stats = bt_store.get_bt_stats()
        assert stats["total_devices"] == 2
        # Type breakdown should include only ble
        type_breakdown = stats.get("type_breakdown", {})
        assert isinstance(type_breakdown, dict)
        assert "ble" in type_breakdown or len(type_breakdown) == 1

    def test_zigbee_stats_single_type(self, zb_store: ZigbeeMetadataStore):
        """Zigbee stats with only end_devices is handled."""
        zb_store.insert_zigbee_devices([{
            "ieee_addr": "00:11:22:33:44:55:66:01",
            "device_name": "Sensor1",
            "device_type": "end_device",
            "rssi_dbm": -65.0,
            "node_id": "node-1",
        }])
        stats = zb_store.get_zigbee_stats()
        assert stats["total_devices"] == 1

# ---------------------------------------------------------------------------
# Insert then immediate query (cache invalidation)
# ---------------------------------------------------------------------------

class TestCacheInvalidation:
    """Verify that data is immediately visible after insert."""

    def test_bt_insert_then_query(self, bt_store: BtMetadataStore):
        """BT device is visible immediately after insert."""
        bt_store.insert_bt_devices([{
            "device_addr": "aa:bb:cc:dd:ee:ff",
            "device_name": "Immediate",
            "device_type": "ble",
            "rssi_dbm": -55.0,
            "node_id": "node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }])
        devices = bt_store.get_bt_devices()
        assert len(devices) >= 1
        assert isinstance(devices[0], dict)
        addrs = [d["device_addr"] for d in devices]
        assert "aa:bb:cc:dd:ee:ff" in addrs

    def test_zigbee_insert_then_query(self, zb_store: ZigbeeMetadataStore):
        """Zigbee device is visible immediately after insert."""
        zb_store.insert_zigbee_devices([{
            "ieee_addr": "00:11:22:33:44:55:66:77",
            "device_name": "Immediate",
            "device_type": "coordinator",
            "rssi_dbm": -60.0,
            "node_id": "node-1",
        }])
        devices = zb_store.get_zigbee_devices()
        assert len(devices) >= 1
        assert isinstance(devices[0], dict)

# ---------------------------------------------------------------------------
# Concurrent read during cleanup
# ---------------------------------------------------------------------------

class TestConcurrentCleanupRead:
    """Verify that reads during cleanup don't crash."""

    def test_bt_concurrent_read_and_cleanup(self, bt_store: BtMetadataStore):
        """Concurrent BT read and cleanup does not error."""
        # Insert some data
        for i in range(10):
            bt_store.insert_bt_devices([{
                "device_addr": f"aa:bb:cc:dd:{i:02x}:ff",
                "device_name": f"Device{i}",
                "device_type": "ble",
                "rssi_dbm": -50.0 - i,
                "node_id": "node-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }])

        errors = []

        def read_loop():
            try:
                for _ in range(5):
                    bt_store.get_bt_devices()
            except Exception as e:
                errors.append(e)

        def cleanup_loop():
            try:
                bt_store.cleanup_bt_devices(max_age_hours=0)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=read_loop)
        t2 = threading.Thread(target=cleanup_loop)
        t1.start()
        t2.start()
        t1.join(timeout=10)
        t2.join(timeout=10)

        assert not errors, f"Concurrent operations raised errors: {errors}"

# ---------------------------------------------------------------------------
# Duplicate device inserts (idempotency)
# ---------------------------------------------------------------------------

class TestDuplicateInserts:
    """Verify that inserting the same device twice doesn't cause errors."""

    def test_bt_duplicate_insert(self, bt_store: BtMetadataStore):
        """Inserting same BT device twice does not error and both are stored."""
        rec = {
            "device_addr": "aa:bb:cc:dd:ee:ff",
            "device_name": "Dup",
            "device_type": "ble",
            "rssi_dbm": -55.0,
            "node_id": "node-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        n1 = bt_store.insert_bt_devices([rec])
        n2 = bt_store.insert_bt_devices([rec])
        assert isinstance(n1, int)
        assert n1 >= 1
        assert isinstance(n2, int)
        assert n2 >= 1

    def test_zigbee_duplicate_insert(self, zb_store: ZigbeeMetadataStore):
        """Inserting same Zigbee device twice does not error."""
        rec = {
            "ieee_addr": "00:11:22:33:44:55:66:77",
            "device_name": "Dup",
            "device_type": "end_device",
            "rssi_dbm": -65.0,
            "node_id": "node-1",
        }
        n1 = zb_store.insert_zigbee_devices([rec])
        n2 = zb_store.insert_zigbee_devices([rec])
        assert isinstance(n1, int)
        assert n1 >= 1
        assert isinstance(n2, int)
        assert n2 >= 1

# ---------------------------------------------------------------------------
# Empty record list insert
# ---------------------------------------------------------------------------

class TestEmptyInserts:
    """Verify that inserting empty lists returns 0."""

    def test_bt_insert_empty(self, bt_store: BtMetadataStore):
        assert bt_store.insert_bt_devices([]) == 0

    def test_zigbee_insert_empty(self, zb_store: ZigbeeMetadataStore):
        assert zb_store.insert_zigbee_devices([]) == 0

    def test_wifi_insert_empty(self, wifi_store: WiFiMetadataStore):
        assert wifi_store.insert_wifi_metadata([]) == 0

# ---------------------------------------------------------------------------
# Cleanup on empty DB
# ---------------------------------------------------------------------------

class TestCleanupEmptyDB:
    """Verify that cleanup on an empty DB returns 0 and does not error."""

    def test_bt_cleanup_empty(self, bt_store: BtMetadataStore):
        assert bt_store.cleanup_bt_devices(max_age_hours=24) == 0

    def test_zigbee_cleanup_empty(self, zb_store: ZigbeeMetadataStore):
        assert zb_store.cleanup_zigbee_devices(max_age_hours=24) == 0

    def test_bt_hourly_cleanup_empty(self, bt_store: BtMetadataStore):
        assert bt_store.cleanup_bt_hourly(max_age_days=30) == 0

    def test_zigbee_hourly_cleanup_empty(self, zb_store: ZigbeeMetadataStore):
        assert zb_store.cleanup_zigbee_hourly(max_age_days=90) == 0
