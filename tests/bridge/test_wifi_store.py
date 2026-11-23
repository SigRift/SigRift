"""Tests for WiFi metadata storage layer in DetectionStore."""

from __future__ import annotations

from datetime import datetime, timezone

from sigrift.bridge.detection_store import DetectionStore

def _make_wifi_record(
    bssid: str = "aa:bb:cc:dd:ee:ff",
    ssid: str = "TestNetwork",
    channel: int = 6,
    band: str = "2.4GHz",
    signal_dbm: float = -45.0,
    client_mac: str = "",
    node_id: str = "node-test-01",
    detection_id: str = "",
    **kwargs,
) -> dict:
    import uuid
    return {
        "detection_id": detection_id or uuid.uuid4().hex[:16],
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "channel_width": 20,
        "band": band,
        "security": "WPA2",
        "signal_dbm": signal_dbm,
        "noise_dbm": -90.0,
        "frame_type": "beacon",
        "client_mac": client_mac,
        "data_rate_mbps": 54.0,
        "retry_flag": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_id": node_id,
        **kwargs,
    }

class TestWifiMetadataInsert:
    def test_insert_and_count(self, detection_store: DetectionStore):
        records = [_make_wifi_record() for _ in range(5)]
        inserted = detection_store.insert_wifi_metadata(records)
        assert inserted == 5

    def test_insert_empty_list(self, detection_store: DetectionStore):
        inserted = detection_store.insert_wifi_metadata([])
        assert inserted == 0

    def test_insert_with_mac_anonymization(self, detection_store: DetectionStore):
        secret = b"test-secret-key-1234"
        records = [_make_wifi_record(client_mac="11:22:33:44:55:66")]
        detection_store.insert_wifi_metadata(records, mac_secret=secret)

        clients = detection_store.get_wifi_clients()
        assert len(clients) == 1
        # OUI (11:22:33) should be preserved
        mac = clients[0]["client_mac"]
        assert mac.startswith("11:22:33")
        # Device portion should be anonymized (not original 44:55:66)
        assert mac != "11:22:33:44:55:66"

class TestWifiNetworks:
    def test_aggregate_by_bssid(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", ssid="Net1", channel=1),
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", ssid="Net1", channel=1),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", ssid="Net2", channel=6),
        ]
        detection_store.insert_wifi_metadata(records)
        networks = detection_store.get_wifi_networks()
        assert len(networks) == 2
        # First should be the one with more frames
        net1 = next(n for n in networks if n["bssid"] == "aa:bb:cc:11:22:33")
        assert net1["frame_count"] == 2

    def test_client_count_aggregation(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1"),
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c2:c2:c2:c2:c2:c2"),
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1"),
        ]
        detection_store.insert_wifi_metadata(records)
        networks = detection_store.get_wifi_networks()
        assert len(networks) == 1
        assert networks[0]["client_count"] == 2  # 2 unique clients

    def test_filter_by_band(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", band="2.4GHz"),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", band="5GHz"),
        ]
        detection_store.insert_wifi_metadata(records)
        networks = detection_store.get_wifi_networks(band="5GHz")
        assert len(networks) == 1
        assert networks[0]["band"] == "5GHz"

    def test_filter_by_node_id(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", node_id="node-a"),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", node_id="node-b"),
        ]
        detection_store.insert_wifi_metadata(records)
        networks = detection_store.get_wifi_networks(node_id="node-a")
        assert len(networks) == 1

class TestWifiClients:
    def test_get_clients(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1"),
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c2:c2:c2:c2:c2:c2"),
        ]
        detection_store.insert_wifi_metadata(records)
        clients = detection_store.get_wifi_clients()
        assert len(clients) == 2

    def test_filter_by_bssid(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1"),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", client_mac="c2:c2:c2:c2:c2:c2"),
        ]
        detection_store.insert_wifi_metadata(records)
        clients = detection_store.get_wifi_clients(bssid="aa:bb:cc:11:22:33")
        assert len(clients) == 1
        assert clients[0]["client_mac"] == "c1:c1:c1:c1:c1:c1"

class TestWifiChannelUtilization:
    def test_per_band_breakdown(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(channel=1, band="2.4GHz"),
            _make_wifi_record(channel=1, band="2.4GHz"),
            _make_wifi_record(channel=6, band="2.4GHz"),
        ]
        detection_store.insert_wifi_metadata(records)
        channels = detection_store.get_wifi_channel_utilization(band="2.4GHz")
        assert len(channels) == 2
        ch1 = next(c for c in channels if c["channel"] == 1)
        assert ch1["frame_count"] == 2

class TestWifiTimeline:
    def test_hourly_signal_aggregation(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", signal_dbm=-50.0),
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", signal_dbm=-60.0),
        ]
        detection_store.insert_wifi_metadata(records)
        timeline = detection_store.get_wifi_timeline(
            bssid="aa:bb:cc:11:22:33", hours=24,
        )
        assert len(timeline) >= 1
        assert isinstance(timeline[0], dict)
        assert timeline[0]["frame_count"] >= 2
        assert isinstance(timeline[0]["frame_count"], int)

class TestWifiStats:
    def test_summary_accuracy(self, detection_store: DetectionStore):
        records = [
            _make_wifi_record(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1", channel=1),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", client_mac="c2:c2:c2:c2:c2:c2", channel=6),
            _make_wifi_record(bssid="dd:ee:ff:44:55:66", client_mac="c3:c3:c3:c3:c3:c3", channel=6),
        ]
        detection_store.insert_wifi_metadata(records)
        stats = detection_store.get_wifi_stats()
        assert stats["total_networks"] == 2
        assert stats["total_clients"] == 3
        assert stats["busiest_channel"] == 6  # 2 frames vs 1

class TestWifiForeignKey:
    def test_detection_id_link(self, detection_store: DetectionStore):
        """WiFi metadata should reference valid detection IDs."""
        from sigrift.bridge.tests.conftest import make_detection
        det = make_detection()
        detection_store.insert_batch([det])

        records = [_make_wifi_record(detection_id=det.detection_id)]
        detection_store.insert_wifi_metadata(records)

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT detection_id FROM wifi_metadata WHERE detection_id = ?",
            [det.detection_id],
        ).fetchone()
        assert row is not None
        assert row[0] == det.detection_id

class TestWifiEmptyDatabase:
    def test_empty_networks(self, detection_store: DetectionStore):
        assert detection_store.get_wifi_networks() == []

    def test_empty_clients(self, detection_store: DetectionStore):
        assert detection_store.get_wifi_clients() == []

    def test_empty_channels(self, detection_store: DetectionStore):
        assert detection_store.get_wifi_channel_utilization() == []

    def test_empty_timeline(self, detection_store: DetectionStore):
        assert detection_store.get_wifi_timeline() == []

    def test_empty_stats(self, detection_store: DetectionStore):
        stats = detection_store.get_wifi_stats()
        assert stats["total_networks"] == 0
        assert stats["total_clients"] == 0
        assert stats["busiest_channel"] == 0
