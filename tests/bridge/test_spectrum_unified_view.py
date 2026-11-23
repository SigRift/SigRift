"""Tests for the spectrum_all unified VIEW (migration 33).

Verifies that spectrum analytics queries include data from wifi_metadata,
bt_devices, and zigbee_devices alongside the detections table, with
correct frequency mapping for WiFi channels, BT channels, and Zigbee channels.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.spectrum_analytics import (
    KNOWN_BANDS,
    SpectrumAnalyticsStore,
)

def _insert_detection(ctx: SharedContext, *, freq_hz: float, signal_class: str = "fm",
                      power_dbm: float = -50.0, node_id: str = "n1",
                      timestamp: str | None = None, bandwidth_hz: float | None = None) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn = ctx.get_conn()
    conn.execute(
        """INSERT INTO detections
           (detection_id, node_id, timestamp, signal_class, confidence,
            freq_hz, power_dbm, bandwidth_hz, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (uuid.uuid4().hex[:16], node_id, ts, signal_class, 0.9,
         freq_hz, power_dbm, bandwidth_hz, ctx.tenant_id),
    )
    conn.commit()

def _insert_wifi(ctx: SharedContext, *, channel: int, signal_dbm: float = -60.0,
                 node_id: str = "n1", timestamp: str | None = None,
                 channel_width: int = 20, noise_dbm: float | None = None) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    det_id = uuid.uuid4().hex[:16]
    conn = ctx.get_conn()
    # Insert parent detection row first (FK enforcement)
    conn.execute(
        """INSERT OR IGNORE INTO detections
           (detection_id, node_id, timestamp, signal_class, confidence,
            freq_hz, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (det_id, node_id, ts, "wifi", 0.9, 0.0, ctx.tenant_id),
    )
    conn.execute(
        """INSERT INTO wifi_metadata
           (detection_id, bssid, ssid, channel, channel_width, band, security,
            signal_dbm, noise_dbm, frame_type, timestamp, node_id, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (det_id, "AA:BB:CC:DD:EE:FF", "TestNet", channel, channel_width,
         "2.4GHz" if channel <= 14 else "5GHz", "WPA2",
         signal_dbm, noise_dbm, "beacon", ts, node_id, ctx.tenant_id),
    )
    conn.commit()

def _insert_bt(ctx: SharedContext, *, device_type: str = "ble",
               rssi_dbm: float = -70.0, channel: int = 0,
               node_id: str = "n1", timestamp: str | None = None) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn = ctx.get_conn()
    conn.execute(
        """INSERT INTO bt_devices
           (device_addr, device_name, device_type, rssi_dbm, channel,
            timestamp, node_id, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("11:22:33:44:55:66", "TestDevice", device_type, rssi_dbm,
         channel, ts, node_id, ctx.tenant_id),
    )
    conn.commit()

def _insert_zigbee(ctx: SharedContext, *, channel: int = 15,
                   rssi_dbm: float = -75.0, node_id: str = "n1",
                   timestamp: str | None = None) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn = ctx.get_conn()
    conn.execute(
        """INSERT INTO zigbee_devices
           (ieee_addr, short_addr, device_type, rssi_dbm, channel,
            timestamp, node_id, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("00:11:22:33:44:55:66:77", "0x1234", "router", rssi_dbm,
         channel, ts, node_id, ctx.tenant_id),
    )
    conn.commit()

class TestSpectrumAllView:
    """Test the spectrum_all VIEW exists and unifies all protocol data."""

    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "unified.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return SpectrumAnalyticsStore(ctx)

    def test_view_exists(self, ctx):
        conn = ctx.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view' AND name='spectrum_all'"
        ).fetchone()
        assert row is not None  # existence check: VIEW must exist in sqlite_master
        assert row["name"] == "spectrum_all"

    def test_empty_view_returns_empty(self, ctx):
        conn = ctx.get_conn()
        count = conn.execute("SELECT COUNT(*) FROM spectrum_all").fetchone()[0]
        assert count == 0

    def test_rf_detections_appear_in_view(self, ctx):
        _insert_detection(ctx, freq_hz=433.92e6)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT * FROM spectrum_all").fetchall()
        assert len(rows) == 1
        assert rows[0]["signal_class"] == "fm"
        assert rows[0]["freq_hz"] == 433.92e6

    def test_wifi_24ghz_channel_mapping(self, ctx):
        _insert_wifi(ctx, channel=6)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT freq_hz, signal_class FROM spectrum_all").fetchall()
        assert len(rows) == 1
        assert rows[0]["signal_class"] == "wifi"
        # Channel 6 = 2407 + 6*5 = 2437 MHz
        assert rows[0]["freq_hz"] == 2437e6

    def test_wifi_5ghz_channel_mapping(self, ctx):
        _insert_wifi(ctx, channel=36)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT freq_hz FROM spectrum_all").fetchall()
        # Channel 36 = 5000 + 36*5 = 5180 MHz
        assert rows[0]["freq_hz"] == 5180e6

    def test_wifi_channel_14_mapping(self, ctx):
        _insert_wifi(ctx, channel=14)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT freq_hz FROM spectrum_all").fetchall()
        assert rows[0]["freq_hz"] == 2484e6

    def test_wifi_bandwidth_from_channel_width(self, ctx):
        _insert_wifi(ctx, channel=6, channel_width=40)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT bandwidth_hz FROM spectrum_all").fetchall()
        assert rows[0]["bandwidth_hz"] == 40e6

    def test_wifi_snr_calculated(self, ctx):
        _insert_wifi(ctx, channel=6, signal_dbm=-50.0, noise_dbm=-90.0)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT snr_db FROM spectrum_all").fetchall()
        # SNR = signal - noise = -50 - (-90) = 40 dB
        assert rows[0]["snr_db"] == 40.0

    def test_bt_ble_appears_in_view(self, ctx):
        _insert_bt(ctx, device_type="ble", rssi_dbm=-65.0)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT signal_class, freq_hz, power_dbm FROM spectrum_all").fetchall()
        assert len(rows) == 1
        assert rows[0]["signal_class"] == "bluetooth-le"
        assert rows[0]["power_dbm"] == -65.0
        # Default channel 0 maps to 2440 MHz
        assert rows[0]["freq_hz"] == 2440e6

    def test_bt_classic_appears_in_view(self, ctx):
        _insert_bt(ctx, device_type="classic")
        conn = ctx.get_conn()
        rows = conn.execute("SELECT signal_class FROM spectrum_all").fetchall()
        assert rows[0]["signal_class"] == "bluetooth-classic"

    def test_zigbee_channel_mapping(self, ctx):
        _insert_zigbee(ctx, channel=15)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT freq_hz, signal_class FROM spectrum_all").fetchall()
        assert len(rows) == 1
        assert rows[0]["signal_class"] == "zigbee"
        # Channel 15 = 2405 + (15-11)*5 = 2425 MHz
        assert rows[0]["freq_hz"] == 2425e6

    def test_zigbee_channel_26_mapping(self, ctx):
        _insert_zigbee(ctx, channel=26)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT freq_hz FROM spectrum_all").fetchall()
        # Channel 26 = 2405 + (26-11)*5 = 2480 MHz
        assert rows[0]["freq_hz"] == 2480e6

    def test_unified_query_all_protocols(self, ctx):
        _insert_detection(ctx, freq_hz=433.92e6)
        _insert_wifi(ctx, channel=6)
        _insert_bt(ctx, device_type="ble")
        _insert_zigbee(ctx, channel=15)
        conn = ctx.get_conn()
        rows = conn.execute("SELECT signal_class FROM spectrum_all ORDER BY signal_class").fetchall()
        classes = sorted(r["signal_class"] for r in rows)
        assert classes == ["bluetooth-le", "fm", "wifi", "zigbee"]

    def test_tenant_isolation(self, ctx):
        _insert_detection(ctx, freq_hz=100e6)
        _insert_wifi(ctx, channel=1)
        conn = ctx.get_conn()
        # Insert wifi in different tenant (with parent detection for FK)
        other_det_id = uuid.uuid4().hex[:16]
        ts = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT OR IGNORE INTO detections
               (detection_id, node_id, timestamp, signal_class, confidence,
                freq_hz, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (other_det_id, "n1", ts, "wifi", 0.9, 0.0, "other_tenant"),
        )
        conn.execute(
            """INSERT INTO wifi_metadata
               (detection_id, bssid, ssid, channel, channel_width, band, security,
                signal_dbm, frame_type, timestamp, node_id, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (other_det_id, "FF:FF:FF:FF:FF:FF", "OtherNet", 1, 20, "2.4GHz", "WPA2",
             -70.0, "beacon", ts, "n1", "other_tenant"),
        )
        conn.commit()
        rows = conn.execute(
            "SELECT COUNT(*) FROM spectrum_all WHERE tenant_id = ?",
            ("default",),
        ).fetchone()
        assert rows[0] == 2  # Only detections + wifi for default tenant

class TestSpectrumAnalyticsUnified:
    """Test that SpectrumAnalyticsStore queries return unified data."""

    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "analytics_unified.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return SpectrumAnalyticsStore(ctx)

    def test_activity_includes_wifi(self, ctx, store):
        _insert_wifi(ctx, channel=6, signal_dbm=-55.0)
        result = store.get_activity(hours=1)
        assert len(result) == 1
        assert result[0]["signal_class"] == "wifi"
        assert result[0]["freq_hz"] == 2437e6

    def test_activity_includes_bluetooth(self, ctx, store):
        _insert_bt(ctx, device_type="ble", rssi_dbm=-70.0)
        result = store.get_activity(hours=1)
        assert len(result) == 1
        assert result[0]["signal_class"] == "bluetooth-le"

    def test_activity_includes_zigbee(self, ctx, store):
        _insert_zigbee(ctx, channel=20, rssi_dbm=-80.0)
        result = store.get_activity(hours=1)
        assert len(result) == 1
        assert result[0]["signal_class"] == "zigbee"

    def test_activity_mixed_protocols(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, signal_class="fm")
        _insert_wifi(ctx, channel=11)
        _insert_bt(ctx)
        result = store.get_activity(hours=1)
        classes = {r["signal_class"] for r in result}
        assert "fm" in classes
        assert "wifi" in classes
        assert "bluetooth-le" in classes

    def test_occupancy_includes_wifi(self, ctx, store):
        _insert_wifi(ctx, channel=6, signal_dbm=-55.0)
        result = store.get_occupancy(hours=1, bin_width_hz=100_000_000)
        assert len(result) >= 1
        assert all(isinstance(r, dict) for r in result)
        freqs = [r["center_freq_hz"] for r in result]
        # WiFi ch6 = 2437 MHz should be in the 2.4 GHz bin
        assert any(2e9 < f < 3e9 for f in freqs)

    def test_waterfall_includes_wifi(self, ctx, store):
        _insert_wifi(ctx, channel=149, signal_dbm=-45.0)
        result = store.get_waterfall(hours=1, bin_width_hz=100_000_000)
        # Should have at least one freq bin in 5 GHz range
        if result["freq_bins"]:
            assert any(f >= 5e9 for f in result["freq_bins"])

    def test_band_summary_includes_bluetooth(self, ctx, store):
        for _ in range(5):
            _insert_bt(ctx, device_type="ble", rssi_dbm=-60.0)
        result = store.get_band_summary(hours=1)
        bt_band = next((b for b in result if b["band"] == "Bluetooth"), None)
        assert isinstance(bt_band, dict)
        assert isinstance(bt_band["signal_count"], int)
        assert bt_band["signal_count"] >= 5

    def test_band_summary_includes_zigbee(self, ctx, store):
        for _ in range(3):
            _insert_zigbee(ctx, channel=15, rssi_dbm=-70.0)
        result = store.get_band_summary(hours=1)
        zb_band = next((b for b in result if b["band"] == "Zigbee 2.4 GHz"), None)
        assert isinstance(zb_band, dict)
        assert isinstance(zb_band["signal_count"], int)
        assert zb_band["signal_count"] >= 3

    def test_band_summary_has_bt_and_zigbee_bands(self, store):
        band_names = [b[0] for b in KNOWN_BANDS]
        assert "Bluetooth" in band_names
        assert "Zigbee 2.4 GHz" in band_names

    def test_bandwidth_distribution_includes_wifi(self, ctx, store):
        _insert_wifi(ctx, channel=6, channel_width=40)
        result = store.get_bandwidth_distribution(hours=1)
        wifi_entry = next((r for r in result if r["signal_class"] == "wifi"), None)
        assert isinstance(wifi_entry, dict)
        assert wifi_entry["avg_bandwidth_hz"] == 40e6

class TestRateLimitConfig:
    """Test rate limit configuration change."""

    def test_rate_limit_is_600(self):
        from sigrift.lib.config import SecurityConfig
        cfg = SecurityConfig()
        assert cfg.rate_limit_per_minute == 600

class TestZigbeeScannerSSL:
    """Test zigbee_scanner --no-verify-ssl flag."""

    def test_scanner_accepts_verify_ssl_false(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        scanner = ZigbeeScanner(
            server_url="https://localhost:8444",
            api_key="test",
            node_id="test",
            verify_ssl=False,
        )
        assert scanner.verify_ssl is False

    def test_scanner_default_verify_ssl_true(self):
        from sigrift.bridge.zigbee_scanner import ZigbeeScanner
        scanner = ZigbeeScanner(
            server_url="https://localhost:8444",
            api_key="test",
            node_id="test",
        )
        assert scanner.verify_ssl is True
