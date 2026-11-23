"""Tests for cross-correlation engine."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from sigrift.bridge.correlation_engine import (
    CrossCorrelator,
    CrossCorrelation,
    WIFI_CHANNEL_FREQ,
    _bt_channel_to_freq,
    _zigbee_channel_to_freq,
)


@pytest.fixture
def mock_ctx():
    """Create mock SharedContext with in-memory database."""
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE detections (
            detection_id TEXT PRIMARY KEY,
            node_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signal_class TEXT NOT NULL DEFAULT '',
            confidence REAL NOT NULL DEFAULT 0.0,
            family TEXT NOT NULL DEFAULT '',
            freq_hz REAL NOT NULL DEFAULT 0.0,
            snr_db REAL,
            power_dbm REAL,
            anomaly_score REAL NOT NULL DEFAULT 0.0,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE wifi_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id TEXT NOT NULL DEFAULT '',
            bssid TEXT NOT NULL DEFAULT '',
            ssid TEXT NOT NULL DEFAULT '',
            channel INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE bt_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_addr TEXT NOT NULL DEFAULT '',
            device_name TEXT NOT NULL DEFAULT '',
            channel INTEGER DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE zigbee_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ieee_addr TEXT NOT NULL DEFAULT '',
            channel INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL,
            node_id TEXT NOT NULL DEFAULT '',
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
        CREATE TABLE cross_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_a TEXT NOT NULL,
            source_a_id TEXT DEFAULT '',
            source_b TEXT NOT NULL DEFAULT '',
            source_b_id TEXT DEFAULT '',
            freq_hz REAL NOT NULL DEFAULT 0.0,
            time_delta_ms REAL NOT NULL DEFAULT 0.0,
            correlation_type TEXT NOT NULL DEFAULT '',
            node_id TEXT NOT NULL DEFAULT '',
            timestamp TEXT NOT NULL,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        );
    """)
    ctx = MagicMock()
    ctx.get_conn.return_value = conn
    return ctx


# ---------------------------------------------------------------------------
# Frequency conversion unit tests
# ---------------------------------------------------------------------------


class TestFrequencyConversions:
    def test_wifi_channel_1(self):
        assert WIFI_CHANNEL_FREQ[1] == 2412

    def test_wifi_channel_6(self):
        assert WIFI_CHANNEL_FREQ[6] == 2437

    def test_wifi_channel_36_5ghz(self):
        assert WIFI_CHANNEL_FREQ[36] == 5180

    def test_wifi_channel_165_5ghz(self):
        assert WIFI_CHANNEL_FREQ[165] == 5825

    def test_bt_channel_0(self):
        assert _bt_channel_to_freq(0) == 2402e6

    def test_bt_channel_39(self):
        assert _bt_channel_to_freq(39) == 2441e6

    def test_bt_channel_78(self):
        assert _bt_channel_to_freq(78) == 2480e6

    def test_zigbee_channel_11(self):
        assert _zigbee_channel_to_freq(11) == 2405e6

    def test_zigbee_channel_26(self):
        assert _zigbee_channel_to_freq(26) == 2480e6

    def test_zigbee_invalid_channel(self):
        assert _zigbee_channel_to_freq(5) == 0.0

    def test_zigbee_channel_15(self):
        assert _zigbee_channel_to_freq(15) == 2425e6


# ---------------------------------------------------------------------------
# CrossCorrelator tests
# ---------------------------------------------------------------------------


class TestCrossCorrelator:
    def test_sdr_wifi_confirmed(self, mock_ctx):
        """SDR detection at 2.4 GHz matches WiFi scanner."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2412e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0].source_a == "sdr"
        assert confirmed[0].source_b == "wifi"

    def test_sdr_bt_confirmed(self, mock_ctx):
        """SDR detection at 2.4 GHz matches Bluetooth device."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO bt_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (39, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2441e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0].source_b == "bt"

    def test_sdr_zigbee_confirmed(self, mock_ctx):
        """SDR detection at 2.4 GHz matches Zigbee device."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO zigbee_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (15, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2425e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0].source_b == "zigbee"

    def test_sdr_unmatched(self, mock_ctx):
        """SDR detection with no matching protocol scanner."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 433e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        assert len(results) == 1
        assert results[0].correlation_type == "unmatched_sdr"
        assert results[0].source_b == ""

    def test_protocol_unmatched(self, mock_ctx):
        """WiFi scanner with no SDR match."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"channel": 1, "timestamp": ts, "id": "w1"}]
        results = correlator.correlate("wifi", events, "node1")

        assert len(results) == 1
        assert results[0].correlation_type == "unmatched_protocol"

    def test_bt_unmatched_is_protocol(self, mock_ctx):
        """BT scanner with no SDR match yields unmatched_protocol."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"channel": 20, "timestamp": ts, "id": "bt1"}]
        results = correlator.correlate("bt", events, "node1")

        assert len(results) == 1
        assert results[0].correlation_type == "unmatched_protocol"

    def test_time_window_respected(self, mock_ctx):
        """Events outside time window are not correlated."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        old = (now - timedelta(seconds=10)).isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, old, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=500)
        events = [{"freq_hz": 2412e6, "timestamp": now.isoformat(), "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        unmatched = [r for r in results if r.correlation_type == "unmatched_sdr"]
        assert len(unmatched) == 1

    def test_freq_tolerance_exceeded(self, mock_ctx):
        """Events outside frequency tolerance are not correlated."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        # 900 MHz is far outside WiFi 2.4 GHz tolerance
        events = [{"freq_hz": 900e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        assert results[0].correlation_type == "unmatched_sdr"

    def test_multi_source(self, mock_ctx):
        """Matches in 2+ other sources yields multi_source."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node1"),
        )
        conn.execute(
            "INSERT INTO bt_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (10, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        # 2412 MHz overlaps WiFi ch1 and BT ch10 (2412 MHz exact)
        events = [{"freq_hz": 2412e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        multi = [r for r in results if r.correlation_type == "multi_source"]
        assert len(multi) >= 1

    def test_correlations_stored(self, mock_ctx):
        """Correlations are persisted to cross_correlations table."""
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 433e6, "timestamp": ts, "id": "det1"}]
        correlator.correlate("sdr", events, "node1")

        conn = mock_ctx.get_conn()
        count = conn.execute("SELECT COUNT(*) FROM cross_correlations").fetchone()[0]
        assert count >= 1

    def test_correlation_summary(self, mock_ctx):
        """get_correlation_summary returns type counts."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO cross_correlations
               (source_a, source_b, freq_hz, time_delta_ms, correlation_type, node_id, timestamp)
               VALUES (?,?,?,?,?,?,?)""",
            ("sdr", "wifi", 2412e6, 10.0, "confirmed", "node1", now),
        )
        conn.execute(
            """INSERT INTO cross_correlations
               (source_a, source_b, freq_hz, time_delta_ms, correlation_type, node_id, timestamp)
               VALUES (?,?,?,?,?,?,?)""",
            ("sdr", "", 433e6, 0, "unmatched_sdr", "node1", now),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        summary = correlator.get_correlation_summary("node1", hours=1)
        assert summary.get("confirmed") == 1
        assert summary.get("unmatched_sdr") == 1

    def test_get_correlation_for_detection(self, mock_ctx):
        """Lookup correlation type by detection ID."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO cross_correlations
               (source_a, source_a_id, source_b, freq_hz, time_delta_ms, correlation_type, node_id, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            ("sdr", "42", "wifi", 2412e6, 5.0, "confirmed", "node1", now),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        result = correlator.get_correlation_for_detection("42")
        assert result == "confirmed"

    def test_get_correlation_for_detection_missing(self, mock_ctx):
        """Returns None when detection has no correlation record."""
        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        result = correlator.get_correlation_for_detection("nonexistent")
        assert result is None

    def test_empty_events(self, mock_ctx):
        """Empty event list returns empty results."""
        correlator = CrossCorrelator(mock_ctx)
        results = correlator.correlate("sdr", [], "node1")
        assert results == []

    def test_missing_freq_skipped(self, mock_ctx):
        """Events without freq_hz or channel are skipped."""
        correlator = CrossCorrelator(mock_ctx)
        events = [{"timestamp": datetime.now(timezone.utc).isoformat()}]
        results = correlator.correlate("sdr", events, "node1")
        assert results == []

    def test_missing_timestamp_skipped(self, mock_ctx):
        """Events without valid timestamp are skipped."""
        correlator = CrossCorrelator(mock_ctx)
        events = [{"freq_hz": 2412e6, "timestamp": "not-a-date"}]
        results = correlator.correlate("sdr", events, "node1")
        assert results == []

    def test_reverse_correlation_wifi_to_sdr(self, mock_ctx):
        """WiFi source correlating against SDR detections."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO detections (detection_id, freq_hz, timestamp, signal_class, node_id, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            ("d1", 2412e6, ts, "ofdm", "node1", 0.9),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"channel": 1, "timestamp": ts, "id": "w1"}]
        results = correlator.correlate("wifi", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        assert confirmed[0].source_a == "wifi"
        assert confirmed[0].source_b == "sdr"

    def test_multiple_events_batch(self, mock_ctx):
        """Multiple events in a single correlate call."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (6, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [
            {"freq_hz": 2437e6, "timestamp": ts, "id": "det1"},  # ch6 match
            {"freq_hz": 900e6, "timestamp": ts, "id": "det2"},   # no match
        ]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        unmatched = [r for r in results if r.correlation_type == "unmatched_sdr"]
        assert len(confirmed) >= 1
        assert len(unmatched) == 1

    def test_cross_node_isolation(self, mock_ctx):
        """Events from different nodes do not correlate."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node2"),  # different node
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2412e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        assert results[0].correlation_type == "unmatched_sdr"

    def test_time_delta_populated(self, mock_ctx):
        """time_delta_ms is populated for confirmed correlations."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO wifi_metadata (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (1, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2412e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1
        # Same timestamp so delta should be very small
        assert confirmed[0].time_delta_ms < 100

    def test_freq_tolerance_lookup(self, mock_ctx):
        """Frequency tolerance is source-pair specific."""
        correlator = CrossCorrelator(mock_ctx)
        assert correlator._get_freq_tolerance("sdr", "wifi") == 10_000_000
        assert correlator._get_freq_tolerance("sdr", "bt") == 2_000_000
        assert correlator._get_freq_tolerance("sdr", "zigbee") == 5_000_000
        # Order should not matter
        assert correlator._get_freq_tolerance("wifi", "sdr") == 10_000_000
        # Unknown pair uses default
        assert correlator._get_freq_tolerance("sdr", "aircraft") == 1_000_000
        assert correlator._get_freq_tolerance("foo", "bar") == 5_000_000

    def test_zigbee_channel_correlation(self, mock_ctx):
        """Zigbee event with channel field correlates to SDR detection."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO detections (detection_id, freq_hz, timestamp, signal_class, node_id, confidence) VALUES (?, ?, ?, ?, ?, ?)",
            ("d1", 2425e6, ts, "zigbee", "node1", 0.8),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"channel": 15, "timestamp": ts, "id": "zb1"}]
        results = correlator.correlate("zigbee", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1

    def test_bt_zero_channel_uses_center(self, mock_ctx):
        """BT device with channel=0 uses default 2402 MHz freq."""
        conn = mock_ctx.get_conn()
        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        conn.execute(
            "INSERT INTO bt_devices (channel, timestamp, node_id) VALUES (?, ?, ?)",
            (0, ts, "node1"),
        )
        conn.commit()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 2402e6, "timestamp": ts, "id": "det1"}]
        results = correlator.correlate("sdr", events, "node1")

        confirmed = [r for r in results if r.correlation_type == "confirmed"]
        assert len(confirmed) >= 1

    def test_store_failure_does_not_raise(self, mock_ctx):
        """Storage failure is logged but does not raise."""
        conn = mock_ctx.get_conn()
        # Drop table to force storage error
        conn.execute("DROP TABLE cross_correlations")
        conn.commit()

        now = datetime.now(timezone.utc)
        ts = now.isoformat()

        correlator = CrossCorrelator(mock_ctx, time_window_ms=1000)
        events = [{"freq_hz": 433e6, "timestamp": ts, "id": "det1"}]
        # Should not raise despite missing table
        results = correlator.correlate("sdr", events, "node1")
        assert len(results) == 1
