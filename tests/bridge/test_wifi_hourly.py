"""Tests for WiFi hourly aggregation, cleanup, and merged read paths."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sigrift.bridge.detection_store import DetectionStore

def _hours_ago(h: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()

def _days_ago(d: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=d)).isoformat()

def _make_wifi(
    bssid: str = "aa:bb:cc:dd:ee:ff",
    ssid: str = "TestNet",
    channel: int = 6,
    band: str = "2.4GHz",
    signal_dbm: float = -45.0,
    noise_dbm: float = -90.0,
    client_mac: str = "",
    node_id: str = "node-01",
    timestamp: str | None = None,
    data_rate_mbps: float = 54.0,
    retry_flag: int = 0,
    **kw,
) -> dict:
    import uuid
    return {
        "detection_id": uuid.uuid4().hex[:16],
        "bssid": bssid,
        "ssid": ssid,
        "channel": channel,
        "channel_width": 20,
        "band": band,
        "security": "WPA2",
        "signal_dbm": signal_dbm,
        "noise_dbm": noise_dbm,
        "frame_type": "beacon",
        "client_mac": client_mac,
        "data_rate_mbps": data_rate_mbps,
        "retry_flag": retry_flag,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "node_id": node_id,
        **kw,
    }

class TestAggregateWifiHourly:
    """Tests for aggregate_wifi_hourly()."""

    def test_basic_aggregation(self, detection_store: DetectionStore):
        """Rows older than cutoff are aggregated into hourly table."""
        ts = _hours_ago(3)
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-40.0, timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-50.0, timestamp=ts),
        ]
        detection_store.insert_wifi_metadata(records)

        count = detection_store.aggregate_wifi_hourly(cutoff_hours=2)
        assert isinstance(count, int)
        assert count >= 1

        conn = detection_store.get_connection()
        rows = conn.execute("SELECT * FROM wifi_metadata_hourly").fetchall()
        assert len(rows) >= 1
        row = dict(rows[0])
        assert row["bssid"] == "aa:bb:cc:11:22:33"
        assert row["frame_count"] == 2
        assert -50.0 <= row["avg_signal_dbm"] <= -40.0

    def test_recent_rows_not_aggregated(self, detection_store: DetectionStore):
        """Rows newer than cutoff are NOT aggregated."""
        records = [_make_wifi(timestamp=datetime.now(timezone.utc).isoformat())]
        detection_store.insert_wifi_metadata(records)

        count = detection_store.aggregate_wifi_hourly(cutoff_hours=2)
        assert count == 0

    def test_idempotent_reaggregation(self, detection_store: DetectionStore):
        """Running aggregation twice produces the same result."""
        ts = _hours_ago(5)
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-42.0, timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-48.0, timestamp=ts),
        ]
        detection_store.insert_wifi_metadata(records)

        detection_store.aggregate_wifi_hourly(cutoff_hours=2)
        detection_store.aggregate_wifi_hourly(cutoff_hours=2)

        conn = detection_store.get_connection()
        rows = conn.execute(
            "SELECT * FROM wifi_metadata_hourly WHERE bssid = 'aa:bb:cc:11:22:33'"
        ).fetchall()
        assert len(rows) == 1
        assert dict(rows[0])["frame_count"] == 2

    def test_client_macs_json(self, detection_store: DetectionStore):
        """client_macs_json contains distinct client MACs as JSON array."""
        ts = _hours_ago(4)
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1", timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c2:c2:c2:c2:c2:c2", timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1", timestamp=ts),
        ]
        detection_store.insert_wifi_metadata(records)
        detection_store.aggregate_wifi_hourly(cutoff_hours=2)

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT client_macs_json, client_count FROM wifi_metadata_hourly "
            "WHERE bssid = 'aa:bb:cc:11:22:33'"
        ).fetchone()
        assert row is not None
        macs = json.loads(row["client_macs_json"])
        assert isinstance(macs, list)
        assert len(macs) == 2
        assert set(macs) == {"c1:c1:c1:c1:c1:c1", "c2:c2:c2:c2:c2:c2"}
        assert row["client_count"] == 2

    def test_signal_statistics(self, detection_store: DetectionStore):
        """min/max/avg signal_dbm are computed correctly."""
        ts = _hours_ago(3)
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-30.0, timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-60.0, timestamp=ts),
        ]
        detection_store.insert_wifi_metadata(records)
        detection_store.aggregate_wifi_hourly(cutoff_hours=2)

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT min_signal_dbm, max_signal_dbm, avg_signal_dbm "
            "FROM wifi_metadata_hourly WHERE bssid = 'aa:bb:cc:11:22:33'"
        ).fetchone()
        assert row["min_signal_dbm"] == -60.0
        assert row["max_signal_dbm"] == -30.0
        assert row["avg_signal_dbm"] == pytest.approx(-45.0)

    def test_retry_count(self, detection_store: DetectionStore):
        """retry_count sums retry_flag across rows."""
        ts = _hours_ago(3)
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", retry_flag=1, timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", retry_flag=0, timestamp=ts),
            _make_wifi(bssid="aa:bb:cc:11:22:33", retry_flag=1, timestamp=ts),
        ]
        detection_store.insert_wifi_metadata(records)
        detection_store.aggregate_wifi_hourly(cutoff_hours=2)

        conn = detection_store.get_connection()
        row = conn.execute(
            "SELECT retry_count FROM wifi_metadata_hourly "
            "WHERE bssid = 'aa:bb:cc:11:22:33'"
        ).fetchone()
        assert row["retry_count"] == 2

class TestCleanupWifiHourly:
    """Tests for cleanup_wifi_hourly()."""

    def test_deletes_old_summaries(self, detection_store: DetectionStore):
        """Summaries older than max_age_days are deleted."""
        conn = detection_store.get_connection()
        old_hour = (datetime.now(timezone.utc) - timedelta(days=100)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        recent_hour = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%dT%H:00:00"
        )

        conn.execute(
            "INSERT INTO wifi_metadata_hourly (hour, bssid, band, channel, node_id, frame_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', '2.4GHz', 6, 'n1', 100)",
            [old_hour],
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly (hour, bssid, band, channel, node_id, frame_count) "
            "VALUES (?, 'dd:ee:ff:44:55:66', '2.4GHz', 6, 'n1', 50)",
            [recent_hour],
        )
        conn.commit()

        deleted = detection_store.cleanup_wifi_hourly(max_age_days=90)
        assert deleted == 1

        remaining = conn.execute("SELECT * FROM wifi_metadata_hourly").fetchall()
        assert len(remaining) == 1
        assert dict(remaining[0])["bssid"] == "dd:ee:ff:44:55:66"

    def test_keeps_recent_summaries(self, detection_store: DetectionStore):
        """Summaries within retention are kept."""
        conn = detection_store.get_connection()
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly (hour, bssid, band, channel, node_id, frame_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', '2.4GHz', 6, 'n1', 100)",
            [recent],
        )
        conn.commit()

        deleted = detection_store.cleanup_wifi_hourly(max_age_days=90)
        assert deleted == 0

class TestMergedGetWifiNetworks:
    """Tests for get_wifi_networks() merging raw + hourly data."""

    def test_raw_only(self, detection_store: DetectionStore):
        """With no hourly data, returns only raw results."""
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1"),
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1"),
        ]
        detection_store.insert_wifi_metadata(records)
        networks = detection_store.get_wifi_networks()
        assert len(networks) == 1
        assert networks[0]["bssid"] == "aa:bb:cc:11:22:33"
        assert networks[0]["frame_count"] == 2

    def test_hourly_only(self, detection_store: DetectionStore):
        """With no raw data, returns hourly results."""
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', -50.0, 500, 3)",
            [hour],
        )
        conn.commit()

        networks = detection_store.get_wifi_networks()
        assert len(networks) == 1
        assert networks[0]["bssid"] == "aa:bb:cc:11:22:33"
        assert networks[0]["frame_count"] == 500

    def test_merged_raw_and_hourly(self, detection_store: DetectionStore):
        """Combined raw + hourly data yields merged frame counts."""
        # Insert hourly data
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', -50.0, 1000, 5)",
            [hour],
        )
        conn.commit()

        # Insert raw data
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1", signal_dbm=-40.0),
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1", signal_dbm=-40.0),
        ]
        detection_store.insert_wifi_metadata(records)

        networks = detection_store.get_wifi_networks()
        net = next(n for n in networks if n["bssid"] == "aa:bb:cc:11:22:33")
        assert net["frame_count"] == 1002  # 1000 hourly + 2 raw

    def test_empty_tables(self, detection_store: DetectionStore):
        """Empty tables return empty list."""
        networks = detection_store.get_wifi_networks()
        assert networks == []

class TestMergedGetWifiClients:
    """Tests for get_wifi_clients() merging raw + hourly data."""

    def test_raw_clients_only(self, detection_store: DetectionStore):
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1"),
        ]
        detection_store.insert_wifi_metadata(records)
        clients = detection_store.get_wifi_clients()
        assert len(clients) == 1
        assert clients[0]["client_mac"] == "c1:c1:c1:c1:c1:c1"

    def test_historical_clients_via_hourly(self, detection_store: DetectionStore):
        """Clients from hourly data (via json_each) appear in results."""
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=10)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, avg_data_rate_mbps, frame_count, client_count, client_macs_json) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', "
            "-50.0, 54.0, 100, 2, ?)",
            [hour, '["c1:c1:c1:c1:c1:c1","c2:c2:c2:c2:c2:c2"]'],
        )
        conn.commit()

        clients = detection_store.get_wifi_clients()
        assert len(clients) == 2
        macs = {c["client_mac"] for c in clients}
        assert "c1:c1:c1:c1:c1:c1" in macs
        assert "c2:c2:c2:c2:c2:c2" in macs

    def test_merged_client_data(self, detection_store: DetectionStore):
        """Client appearing in both raw and hourly is merged."""
        # Hourly historical
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=10)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, avg_data_rate_mbps, frame_count, client_count, client_macs_json) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', "
            "-50.0, 54.0, 100, 1, ?)",
            [hour, '["c1:c1:c1:c1:c1:c1"]'],
        )
        conn.commit()

        # Raw recent
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1", signal_dbm=-40.0),
            _make_wifi(bssid="aa:bb:cc:11:22:33", client_mac="c1:c1:c1:c1:c1:c1", signal_dbm=-40.0),
        ]
        detection_store.insert_wifi_metadata(records)

        clients = detection_store.get_wifi_clients()
        assert len(clients) == 1
        c = clients[0]
        assert c["client_mac"] == "c1:c1:c1:c1:c1:c1"
        # Should have combined frames: 100 hourly + 2 raw
        assert c["frame_count"] == 102

    def test_empty_tables(self, detection_store: DetectionStore):
        clients = detection_store.get_wifi_clients()
        assert clients == []

class TestMergedGetWifiChannelUtilization:
    """Tests for get_wifi_channel_utilization() merging raw + hourly."""

    def test_merged_channel_data(self, detection_store: DetectionStore):
        # Hourly data
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', -50.0, 500, 3)",
            [hour],
        )
        conn.commit()

        # Raw data on same channel
        records = [
            _make_wifi(bssid="dd:ee:ff:44:55:66", channel=6, signal_dbm=-40.0),
        ]
        detection_store.insert_wifi_metadata(records)

        channels = detection_store.get_wifi_channel_utilization(band="2.4GHz")
        ch6 = next((c for c in channels if c["channel"] == 6), None)
        assert ch6 is not None
        assert isinstance(ch6, dict)
        assert ch6["frame_count"] == 501  # 500 hourly + 1 raw

    def test_empty_tables(self, detection_store: DetectionStore):
        channels = detection_store.get_wifi_channel_utilization()
        assert channels == []

class TestMergedGetWifiTimeline:
    """Tests for get_wifi_timeline() merging raw + hourly."""

    def test_timeline_continuity(self, detection_store: DetectionStore):
        """Timeline spans both raw and hourly hours."""
        # Hourly data from 10 hours ago
        conn = detection_store.get_connection()
        old_hour = (datetime.now(timezone.utc) - timedelta(hours=10)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', -50.0, 200, 5)",
            [old_hour],
        )
        conn.commit()

        # Raw data from now
        records = [_make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-40.0)]
        detection_store.insert_wifi_metadata(records)

        timeline = detection_store.get_wifi_timeline(
            bssid="aa:bb:cc:11:22:33", hours=24,
        )
        assert isinstance(timeline, list)
        assert len(timeline) >= 2
        hours = [t["hour"] for t in timeline]
        assert old_hour in hours

    def test_overlapping_hours_combined(self, detection_store: DetectionStore):
        """Overlapping raw and hourly data for same hour are combined."""
        now = datetime.now(timezone.utc)
        current_hour = now.strftime("%Y-%m-%dT%H:00:00")

        # Hourly data for current hour
        conn = detection_store.get_connection()
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'n1', -50.0, 100, 3)",
            [current_hour],
        )
        conn.commit()

        # Raw data for current hour
        records = [_make_wifi(bssid="aa:bb:cc:11:22:33", signal_dbm=-40.0)]
        detection_store.insert_wifi_metadata(records)

        timeline = detection_store.get_wifi_timeline(
            bssid="aa:bb:cc:11:22:33", hours=2,
        )
        current = next((t for t in timeline if t["hour"] == current_hour), None)
        assert current is not None
        assert isinstance(current, dict)
        # Should combine: 100 hourly + 1 raw
        assert current["frame_count"] == 101

    def test_empty_tables(self, detection_store: DetectionStore):
        timeline = detection_store.get_wifi_timeline()
        assert timeline == []

class TestGetWifiNetworkDetail:
    """Tests for get_wifi_network_detail()."""

    def test_raw_only(self, detection_store: DetectionStore):
        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1", signal_dbm=-45.0),
        ]
        detection_store.insert_wifi_metadata(records)
        detail = detection_store.get_wifi_network_detail("aa:bb:cc:11:22:33")
        assert detail is not None
        assert isinstance(detail, dict)
        assert detail["bssid"] == "aa:bb:cc:11:22:33"
        assert detail["ssid"] == "Net1"
        assert detail["frame_count"] == 1

    def test_not_found(self, detection_store: DetectionStore):
        assert detection_store.get_wifi_network_detail("ff:ff:ff:ff:ff:ff") is None

    def test_merged_detail(self, detection_store: DetectionStore):
        conn = detection_store.get_connection()
        hour = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime(
            "%Y-%m-%dT%H:00:00"
        )
        conn.execute(
            "INSERT INTO wifi_metadata_hourly "
            "(hour, bssid, ssid, channel, channel_width, band, security, node_id, "
            "avg_signal_dbm, frame_count, client_count) "
            "VALUES (?, 'aa:bb:cc:11:22:33', 'Net1', 6, 20, '2.4GHz', 'WPA2', 'node-h', -50.0, 500, 5)",
            [hour],
        )
        conn.commit()

        records = [
            _make_wifi(bssid="aa:bb:cc:11:22:33", ssid="Net1", signal_dbm=-40.0, node_id="node-r"),
        ]
        detection_store.insert_wifi_metadata(records)

        detail = detection_store.get_wifi_network_detail("aa:bb:cc:11:22:33")
        assert detail is not None
        assert isinstance(detail, dict)
        assert detail["frame_count"] == 501
        assert "node-h" in detail["node_ids"]
        assert "node-r" in detail["node_ids"]
