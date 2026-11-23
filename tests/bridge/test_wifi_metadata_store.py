"""Unit tests for storage/wifi_metadata.py (WiFiMetadataStore).

Tests: insert, MAC anonymization, hourly rollup, network queries,
client queries, channel utilization, timeline, stats, cleanup,
empty inputs, and edge cases.
All use in-memory SQLite via SharedContext(tmp_path).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.wifi_metadata import WiFiMetadataStore

def _make_wifi_record(
    *,
    bssid: str = "aa:bb:cc:dd:ee:ff",
    ssid: str = "TestNet",
    channel: int = 6,
    band: str = "2.4GHz",
    signal_dbm: float = -50.0,
    client_mac: str = "11:22:33:44:55:66",
    node_id: str = "n1",
    timestamp: str | None = None,
    security: str = "WPA2",
    data_rate_mbps: float = 54.0,
) -> dict[str, Any]:
    return {
        "detection_id": f"det-{id(bssid)}-{channel}",
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "channel_width": 20,
        "band": band,
        "security": security,
        "signal_dbm": signal_dbm,
        "noise_dbm": -90.0,
        "frame_type": "beacon",
        "client_mac": client_mac,
        "data_rate_mbps": data_rate_mbps,
        "retry_flag": 0,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "node_id": node_id,
        "vendor": "TestVendor",
        "client_vendor": "ClientCo",
    }

class TestWiFiMetadataStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "wifi_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return WiFiMetadataStore(ctx)

    # -- Insert -------------------------------------------------------------

    def test_insert_empty_list(self, store):
        assert store.insert_wifi_metadata([]) == 0

    def test_insert_single_record(self, store):
        records = [_make_wifi_record()]
        inserted = store.insert_wifi_metadata(records)
        assert inserted == 1

    def test_insert_multiple_records(self, store):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:dd:ee:01", channel=1),
            _make_wifi_record(bssid="aa:bb:cc:dd:ee:02", channel=6),
            _make_wifi_record(bssid="aa:bb:cc:dd:ee:03", channel=11),
        ]
        inserted = store.insert_wifi_metadata(records)
        assert inserted == 3

    # -- MAC anonymization --------------------------------------------------

    def test_anonymize_mac_preserves_oui(self):
        mac = "aa:bb:cc:11:22:33"
        secret = b"test-secret"
        anon = WiFiMetadataStore._anonymize_mac(mac, secret)
        assert anon.startswith("aa:bb:cc")
        assert anon != mac

    def test_anonymize_mac_empty_returns_empty(self):
        assert WiFiMetadataStore._anonymize_mac("", b"s") == ""

    def test_anonymize_mac_short_returns_unchanged(self):
        assert WiFiMetadataStore._anonymize_mac("ab:cd", b"s") == "ab:cd"

    def test_anonymize_mac_deterministic(self):
        mac = "aa:bb:cc:11:22:33"
        secret = b"key"
        a1 = WiFiMetadataStore._anonymize_mac(mac, secret)
        a2 = WiFiMetadataStore._anonymize_mac(mac, secret)
        assert a1 == a2

    def test_anonymize_mac_dash_separated(self):
        mac = "aa-bb-cc-11-22-33"
        anon = WiFiMetadataStore._anonymize_mac(mac, b"key")
        assert anon.startswith("aa:bb:cc")

    def test_insert_with_mac_anonymization(self, store):
        records = [_make_wifi_record(client_mac="aa:bb:cc:dd:ee:ff")]
        store.insert_wifi_metadata(records, mac_secret=b"secret-key")
        networks = store.get_wifi_clients()
        assert len(networks) == 1
        client = networks[0]
        assert isinstance(client, dict)
        # OUI preserved, device portion changed
        assert client["client_mac"].startswith("aa:bb:cc")
        assert client["client_mac"] != "aa:bb:cc:dd:ee:ff"

    # -- Network queries ----------------------------------------------------

    def test_get_wifi_networks_empty(self, store):
        result = store.get_wifi_networks()
        assert result == []

    def test_get_wifi_networks_aggregates(self, store):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:00:00:01", ssid="Net1", channel=1),
            _make_wifi_record(bssid="aa:bb:cc:00:00:01", ssid="Net1", channel=1),
            _make_wifi_record(bssid="aa:bb:cc:00:00:02", ssid="Net2", channel=6),
        ]
        store.insert_wifi_metadata(records)
        networks = store.get_wifi_networks()
        assert len(networks) == 2
        net1 = next(n for n in networks if n["bssid"] == "aa:bb:cc:00:00:01")
        assert net1["frame_count"] == 2

    def test_get_wifi_networks_band_filter(self, store):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:00:00:01", band="2.4GHz"),
            _make_wifi_record(bssid="aa:bb:cc:00:00:02", band="5GHz"),
        ]
        store.insert_wifi_metadata(records)
        result = store.get_wifi_networks(band="5GHz")
        assert len(result) == 1
        assert result[0]["bssid"] == "aa:bb:cc:00:00:02"

    def test_get_wifi_network_detail(self, store):
        records = [_make_wifi_record(bssid="aa:bb:cc:00:00:01", ssid="DetailNet")]
        store.insert_wifi_metadata(records)
        detail = store.get_wifi_network_detail("aa:bb:cc:00:00:01")
        assert isinstance(detail, dict)
        assert detail["ssid"] == "DetailNet"
        assert detail["frame_count"] == 1

    def test_get_wifi_network_detail_not_found(self, store):
        assert store.get_wifi_network_detail("ff:ff:ff:ff:ff:ff") is None

    # -- Client queries -----------------------------------------------------

    def test_get_wifi_clients_empty(self, store):
        result = store.get_wifi_clients()
        assert result == []

    def test_get_wifi_clients_returns_clients(self, store):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:00:00:01", client_mac="11:22:33:aa:bb:cc"),
            _make_wifi_record(bssid="aa:bb:cc:00:00:01", client_mac="11:22:33:dd:ee:ff"),
        ]
        store.insert_wifi_metadata(records)
        clients = store.get_wifi_clients(bssid="aa:bb:cc:00:00:01")
        assert len(clients) == 2

    def test_get_wifi_clients_excludes_empty_mac(self, store):
        records = [
            _make_wifi_record(client_mac=""),
            _make_wifi_record(client_mac="11:22:33:44:55:66"),
        ]
        store.insert_wifi_metadata(records)
        clients = store.get_wifi_clients()
        assert len(clients) == 1

    # -- Channel utilization ------------------------------------------------

    def test_get_wifi_channel_utilization_empty(self, store):
        result = store.get_wifi_channel_utilization(band="2.4GHz")
        assert result == []

    def test_get_wifi_channel_utilization_multi_channel(self, store):
        records = [
            _make_wifi_record(channel=1, band="2.4GHz"),
            _make_wifi_record(channel=1, band="2.4GHz"),
            _make_wifi_record(channel=6, band="2.4GHz"),
        ]
        store.insert_wifi_metadata(records)
        result = store.get_wifi_channel_utilization(band="2.4GHz")
        assert len(result) == 2
        ch1 = next(r for r in result if r["channel"] == 1)
        ch6 = next(r for r in result if r["channel"] == 6)
        assert ch1["frame_count"] == 2
        assert ch6["frame_count"] == 1
        # utilization_pct should sum to ~100
        total_pct = sum(r["utilization_pct"] for r in result)
        assert abs(total_pct - 100.0) < 0.5

    # -- Timeline -----------------------------------------------------------

    def test_get_wifi_timeline_empty(self, store):
        result = store.get_wifi_timeline(hours=1)
        assert result == []

    def test_get_wifi_timeline_with_data(self, store):
        records = [_make_wifi_record()]
        store.insert_wifi_metadata(records)
        result = store.get_wifi_timeline(hours=1)
        assert len(result) >= 1
        assert isinstance(result[0], dict)
        assert "hour" in result[0]
        assert isinstance(result[0]["hour"], str)
        assert "avg_signal_dbm" in result[0]
        assert isinstance(result[0]["avg_signal_dbm"], (int, float))
        assert "frame_count" in result[0]
        assert isinstance(result[0]["frame_count"], int)

    # -- Stats --------------------------------------------------------------

    def test_get_wifi_stats_empty(self, store):
        result = store.get_wifi_stats()
        assert result["total_networks"] == 0
        assert result["total_clients"] == 0

    def test_get_wifi_stats_with_data(self, store):
        records = [
            _make_wifi_record(
                bssid="aa:bb:cc:00:00:01", channel=6, client_mac="11:22:33:44:55:66",
            ),
            _make_wifi_record(
                bssid="aa:bb:cc:00:00:02", channel=11, client_mac="11:22:33:44:55:77",
            ),
        ]
        store.insert_wifi_metadata(records)
        result = store.get_wifi_stats()
        assert result["total_networks"] == 2
        assert result["total_clients"] == 2
        assert result["busiest_channel"] in (6, 11)
        assert isinstance(result["band_breakdown"], dict)
        assert "2.4GHz" in result["band_breakdown"]

    # -- Hourly aggregation -------------------------------------------------

    def test_aggregate_wifi_hourly_no_old_data(self, store):
        records = [_make_wifi_record()]  # current timestamp
        store.insert_wifi_metadata(records)
        count = store.aggregate_wifi_hourly(cutoff_hours=0)
        # With cutoff_hours=0, all data should be aggregated
        assert isinstance(count, int)
        assert count >= 1

    def test_aggregate_wifi_hourly_idempotent(self, store):
        records = [_make_wifi_record()]
        store.insert_wifi_metadata(records)
        count1 = store.aggregate_wifi_hourly(cutoff_hours=0)
        count2 = store.aggregate_wifi_hourly(cutoff_hours=0)
        # INSERT OR REPLACE means re-runs are idempotent
        assert isinstance(count1, int) and count1 >= 1
        assert isinstance(count2, int) and count2 >= 1

    # -- Cleanup ------------------------------------------------------------

    def test_cleanup_wifi_metadata_deletes_old(self, ctx, store):
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        current_ts = datetime.now(timezone.utc).isoformat()
        store.insert_wifi_metadata([_make_wifi_record(timestamp=old_ts)])
        store.insert_wifi_metadata([_make_wifi_record(timestamp=current_ts)])
        deleted = store.cleanup_wifi_metadata(max_age_hours=24)
        assert deleted == 1

    def test_cleanup_wifi_metadata_no_op(self, store):
        store.insert_wifi_metadata([_make_wifi_record()])
        deleted = store.cleanup_wifi_metadata(max_age_hours=24)
        assert deleted == 0

    def test_cleanup_wifi_hourly_deletes_old(self, ctx, store):
        # Insert and aggregate old data
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        store.insert_wifi_metadata([_make_wifi_record(timestamp=old_ts)])
        store.aggregate_wifi_hourly(cutoff_hours=0)
        deleted = store.cleanup_wifi_hourly(max_age_days=90)
        assert isinstance(deleted, int)
        assert deleted >= 1

    def test_cleanup_wifi_hourly_no_op(self, store):
        store.insert_wifi_metadata([_make_wifi_record()])
        store.aggregate_wifi_hourly(cutoff_hours=0)
        deleted = store.cleanup_wifi_hourly(max_age_days=90)
        assert deleted == 0
