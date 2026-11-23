"""Unit tests for 4 storage modules that previously lacked direct tests.

Modules:
  - storage/tdoa_store.py (TDOAStore)
  - storage/fhss_store.py (FHSSStore)
  - storage/detection_crud.py (DetectionCrudStore)
  - storage/bt_metadata.py (BtMetadataStore)

All use in-memory SQLite via SharedContext(tmp_path).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip(
    "sigrift.bridge.storage.tdoa_store",
    reason="TDOAStore is enterprise-only and not shipped in community",
)

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.tdoa_store import TDOAStore
from sigrift.bridge.storage.fhss_store import FHSSStore
from sigrift.bridge.storage.detection_crud import DetectionCrudStore
from sigrift.bridge.storage.bt_metadata import BtMetadataStore
from sigrift.bridge.models import DetectionRecord

# ---------------------------------------------------------------------------
# TDOAStore
# ---------------------------------------------------------------------------

class TestTDOAStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "tdoa_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return TDOAStore(ctx)

    def test_store_and_retrieve(self, store):
        est = {
            "estimate_id": "tdoa-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "node_count": 3,
            "contributing_nodes": ["n1", "n2", "n3"],
            "coordinate_mode": "2d",
            "location": {"x_m": 10.0, "y_m": 20.0},
            "cep_m": 5.0,
            "gdop": 1.2,
            "confidence": 0.85,
            "time_spread_ms": 0.5,
            "tdoa_pairs": [{"pair": "n1-n2", "delta_ns": 100}],
        }
        result_id = store.store_tdoa_estimate(est)
        assert result_id == "tdoa-001"

        retrieved = store.get_tdoa_estimate_by_id("tdoa-001")
        assert retrieved is not None
        assert isinstance(retrieved, dict)
        assert retrieved["signal_class"] == "bpsk"
        assert retrieved["confidence"] == 0.85

    def test_empty_estimate_id_returns_empty(self, store):
        result = store.store_tdoa_estimate({"estimate_id": ""})
        assert result == ""

    def test_get_nonexistent_returns_none(self, store):
        assert store.get_tdoa_estimate_by_id("bogus") is None

    def test_list_with_signal_class_filter(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.store_tdoa_estimate({
            "estimate_id": "t1", "timestamp": now,
            "signal_class": "bpsk", "freq_hz": 100e6,
        })
        store.store_tdoa_estimate({
            "estimate_id": "t2", "timestamp": now,
            "signal_class": "qpsk", "freq_hz": 200e6,
        })
        results = store.get_tdoa_estimates(hours=1, signal_class="bpsk")
        assert len(results) == 1
        assert results[0]["signal_class"] == "bpsk"

    def test_count(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.store_tdoa_estimate({
            "estimate_id": "c1", "timestamp": now,
            "signal_class": "bpsk",
        })
        assert store.count_tdoa_estimates(hours=1) == 1

    def test_heatmap_empty(self, store):
        assert store.get_tdoa_heatmap(hours=1) == []

# ---------------------------------------------------------------------------
# FHSSStore
# ---------------------------------------------------------------------------

class TestFHSSStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "fhss_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return FHSSStore(ctx)

    def test_insert_empty_list(self, store):
        assert store.insert_fhss_events([]) == []

    def test_insert_and_query(self, store):
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "fhss_id": "fhss-001",
                "node_id": "n1",
                "timestamp": now,
                "hop_rate_hz": 1600.0,
                "hop_set": [2402e6, 2426e6, 2480e6],
                "bandwidth_hz": 1e6,
                "dwell_time_ms": 0.625,
                "duration_sec": 5.0,
                "signal_class": "bluetooth",
                "detection_count": 8,
                "confidence": 0.92,
            },
        ]
        ids = store.insert_fhss_events(events)
        assert ids == ["fhss-001"]

        results = store.get_fhss_events(hours=1)
        assert len(results) == 1
        assert results[0]["hop_rate_hz"] == 1600.0
        assert isinstance(results[0]["hop_set"], list)
        assert len(results[0]["hop_set"]) == 3

    def test_get_by_id(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.insert_fhss_events([{
            "fhss_id": "fhss-x",
            "node_id": "n1",
            "timestamp": now,
            "hop_rate_hz": 50.0,
        }])
        result = store.get_fhss_event_by_id("fhss-x")
        assert result is not None
        assert isinstance(result, dict)
        assert result["hop_rate_hz"] == 50.0
        assert store.get_fhss_event_by_id("bogus") is None

    def test_count(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.insert_fhss_events([
            {"fhss_id": "f1", "node_id": "n1", "timestamp": now, "hop_rate_hz": 100},
            {"fhss_id": "f2", "node_id": "n1", "timestamp": now, "hop_rate_hz": 200},
        ])
        assert store.count_fhss_events(hours=1) == 2
        assert store.count_fhss_events(hours=1, node_id="n1") == 2

    def test_skip_events_without_fhss_id(self, store):
        ids = store.insert_fhss_events([
            {"fhss_id": "", "node_id": "n1", "timestamp": datetime.now(timezone.utc).isoformat()},
        ])
        assert ids == []

    def test_filter_by_node_id(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.insert_fhss_events([
            {"fhss_id": "a", "node_id": "n1", "timestamp": now, "hop_rate_hz": 100},
            {"fhss_id": "b", "node_id": "n2", "timestamp": now, "hop_rate_hz": 200},
        ])
        results = store.get_fhss_events(hours=1, node_id="n1")
        assert len(results) == 1
        assert results[0]["node_id"] == "n1"

# ---------------------------------------------------------------------------
# DetectionCrudStore
# ---------------------------------------------------------------------------

class TestDetectionCrudStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "crud_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return DetectionCrudStore(ctx)

    def _make_record(self, **kwargs) -> DetectionRecord:
        defaults = {
            "node_id": "n1",
            "signal_class": "bpsk",
            "confidence": 0.9,
            "family": "psk",
            "freq_hz": 433.92e6,
            "snr_db": 15.0,
        }
        defaults.update(kwargs)
        return DetectionRecord(**defaults)

    def test_insert_empty_list(self, store):
        assert store.insert_batch([]) == 0

    def test_insert_and_get_by_id(self, store):
        rec = self._make_record()
        store.insert_batch([rec])
        result = store.get_detection_by_id(rec.detection_id)
        assert result is not None
        assert isinstance(result, dict)
        assert result["signal_class"] == "bpsk"
        assert result["confidence"] == 0.9

    def test_get_nonexistent_returns_none(self, store):
        assert store.get_detection_by_id("bogus") is None

    def test_row_count(self, store):
        recs = [self._make_record(signal_class=f"class{i}") for i in range(5)]
        store.insert_batch(recs)
        assert store.row_count() == 5

    def test_get_recent(self, store):
        rec = self._make_record()
        store.insert_batch([rec])
        recent = store.get_recent(minutes=5)
        assert isinstance(recent, list)
        assert len(recent) == 1

    def test_duplicate_ids_ignored(self, store):
        rec = self._make_record()
        store.insert_batch([rec])
        store.insert_batch([rec])  # duplicate
        assert store.row_count() == 1

# ---------------------------------------------------------------------------
# BtMetadataStore
# ---------------------------------------------------------------------------

class TestBtMetadataStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "bt_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return BtMetadataStore(ctx)

    def test_insert_empty_list(self, store):
        assert store.insert_bt_devices([]) == 0

    def test_insert_and_query(self, store):
        now = datetime.now(timezone.utc).isoformat()
        records = [
            {
                "device_addr": "aa:bb:cc:11:22:33",
                "device_name": "TestDevice",
                "device_type": "le",
                "rssi_dbm": -70.0,
                "manufacturer": "TestCo",
                "timestamp": now,
                "node_id": "n1",
            },
        ]
        inserted = store.insert_bt_devices(records)
        assert isinstance(inserted, int)
        assert inserted >= 1

        devices = store.get_bt_devices()
        assert isinstance(devices, list)
        assert len(devices) >= 1
        assert devices[0]["device_addr"] == "aa:bb:cc:11:22:33"

    def test_get_device_detail(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.insert_bt_devices([{
            "device_addr": "11:22:33:44:55:66",
            "device_name": "Foo",
            "device_type": "classic",
            "rssi_dbm": -65.0,
            "timestamp": now,
            "node_id": "n1",
        }])
        detail = store.get_bt_device_detail("11:22:33:44:55:66")
        assert detail is not None
        assert isinstance(detail, dict)
        assert detail["device_name"] == "Foo"
        assert store.get_bt_device_detail("ff:ff:ff:ff:ff:ff") is None

    def test_anonymize_mac(self):
        mac = "aa:bb:cc:11:22:33"
        secret = b"test-secret"
        anon = BtMetadataStore._anonymize_mac(mac, secret)
        # OUI preserved
        assert anon.startswith("aa:bb:cc")
        # Device portion changed
        assert anon != mac

    def test_anonymize_mac_empty(self):
        assert BtMetadataStore._anonymize_mac("", b"s") == ""

    def test_insert_with_mac_anonymization(self, store):
        now = datetime.now(timezone.utc).isoformat()
        store.insert_bt_devices(
            [{"device_addr": "aa:bb:cc:dd:ee:ff", "timestamp": now, "node_id": "n1"}],
            mac_secret="my-secret",
        )
        devices = store.get_bt_devices()
        assert isinstance(devices, list)
        assert len(devices) >= 1
        # OUI should be preserved but device portion anonymized
        addr = devices[0]["device_addr"]
        assert addr.startswith("aa:bb:cc")
        assert addr != "aa:bb:cc:dd:ee:ff"
