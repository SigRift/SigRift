"""Smoke tests for 5 core modules that previously had zero test coverage.

Modules:
  - syslog_forwarder.py (SyslogForwarder, format_rfc5424, _matches_filter)
  - edge_syslog.py (EdgeSyslogClient, build_rfc5424)
  - spectrum_sweeper.py (SpectrumSweeper helpers, parsers)
  - storage/emitter_store.py (EmitterStore CRUD)
  - storage/geo_analytics.py (GeoAnalyticsStore queries)
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# syslog_forwarder.py
# ---------------------------------------------------------------------------

from sigrift.bridge.syslog_forwarder import (
    SyslogForwarder,
    format_rfc5424,
    _compute_priority,
    _matches_filter,
)


class TestSyslogForwarderInit:
    def test_constructor_creates_empty_targets(self):
        fwd = SyslogForwarder()
        assert fwd.targets == []

    def test_add_target_returns_config(self):
        fwd = SyslogForwarder()
        target = fwd.add_target("syslog.example.com", port=514, protocol="udp")
        assert isinstance(target, dict)
        assert target["host"] == "syslog.example.com"
        assert target["port"] == 514
        assert target["protocol"] == "udp"
        assert target["enabled"] is True
        assert "id" in target
        assert isinstance(target["id"], str)
        assert len(fwd.targets) == 1

    def test_remove_target(self):
        fwd = SyslogForwarder()
        t = fwd.add_target("host", port=514)
        assert fwd.remove_target(t["id"]) is True
        assert len(fwd.targets) == 0
        assert fwd.remove_target("nonexistent") is False

    def test_update_target(self):
        fwd = SyslogForwarder()
        t = fwd.add_target("host", port=514)
        updated = fwd.update_target(t["id"], {"port": 1514, "enabled": False})
        assert updated is not None
        assert isinstance(updated, dict)
        assert updated["port"] == 1514
        assert updated["enabled"] is False

    def test_update_nonexistent_target_returns_none(self):
        fwd = SyslogForwarder()
        assert fwd.update_target("bogus", {"port": 999}) is None


class TestFormatRfc5424:
    def test_basic_formatting(self):
        alert = {
            "severity": "warning",
            "alert_id": "test-123",
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "node_id": "node-01",
            "message": "Test alert message",
        }
        msg = format_rfc5424(alert, hostname="testhost")
        assert isinstance(msg, bytes)
        assert len(msg) > 0
        text = msg.decode("utf-8")
        assert "testhost" in text
        assert "SigRift" in text
        assert "Test alert message" in text

    def test_empty_alert_produces_valid_message(self):
        msg = format_rfc5424({}, hostname="h")
        assert isinstance(msg, bytes)
        assert len(msg) > 10

    def test_compute_priority(self):
        # local0 (16) * 8 + warning (4) = 132
        assert _compute_priority("local0", "warning") == 132
        # user (1) * 8 + info (6) = 14
        assert _compute_priority("user", "info") == 14


class TestMatchesFilter:
    def test_no_filters_matches_all(self):
        assert _matches_filter({"severity": "info"}, {}) is True

    def test_severity_filter(self):
        target = {"severity_filter": ["critical"]}
        assert _matches_filter({"severity": "critical"}, target) is True
        assert _matches_filter({"severity": "info"}, target) is False

    def test_freq_range_filter(self):
        target = {"freq_min_hz": 400e6, "freq_max_hz": 500e6}
        assert _matches_filter({"freq_hz": 433e6}, target) is True
        assert _matches_filter({"freq_hz": 900e6}, target) is False

    def test_node_filter(self):
        target = {"node_filter": ["node-01", "node-02"]}
        assert _matches_filter({"node_id": "node-01"}, target) is True
        assert _matches_filter({"node_id": "node-99"}, target) is False


class TestSyslogForwarderForward:
    def test_forward_with_no_targets_returns_zero(self):
        fwd = SyslogForwarder()
        assert fwd.forward({"severity": "info", "message": "test"}) == 0

    def test_forward_skips_disabled_target(self):
        fwd = SyslogForwarder()
        t = fwd.add_target("localhost", port=9999)
        fwd.update_target(t["id"], {"enabled": False})
        assert fwd.forward({"severity": "info", "message": "test"}) == 0

    def test_close_all_no_error(self):
        fwd = SyslogForwarder()
        fwd.close_all()  # should not raise


# ---------------------------------------------------------------------------
# edge_syslog.py
# ---------------------------------------------------------------------------

from sigrift.bridge.edge_syslog import (
    EdgeSyslogClient,
    build_rfc5424,
    SEVERITY_MAP,
    FACILITY_MAP,
    _escape_sd_value,
)


class TestEdgeSyslogClientInit:
    def test_constructor_defaults(self):
        client = EdgeSyslogClient(host="localhost", port=514, protocol="udp")
        assert client.host == "localhost"
        assert client.port == 514
        assert client.protocol == "udp"

    def test_invalid_protocol_raises(self):
        with pytest.raises(ValueError, match="protocol"):
            EdgeSyslogClient(host="h", protocol="http")

    def test_invalid_facility_raises(self):
        with pytest.raises(ValueError, match="facility"):
            EdgeSyslogClient(host="h", facility="bogus")

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="severity"):
            EdgeSyslogClient(host="h", severity_threshold="bogus")

    def test_stats_initial(self):
        client = EdgeSyslogClient(host="h")
        s = client.stats()
        assert isinstance(s, dict)
        assert s["sent"] == 0
        assert s["dropped"] == 0
        assert s["errors"] == 0


class TestBuildRfc5424:
    def test_basic_message(self):
        msg = build_rfc5424(
            facility=16, severity=6,
            hostname="node-01", app_name="mlrf-edge",
            proc_id="-", msg_id="test",
            message="hello world",
        )
        assert isinstance(msg, str)
        assert "<134>" in msg  # 16*8+6=134
        assert "node-01" in msg
        assert "hello world" in msg

    def test_structured_data(self):
        sd = {"mlrf@0": {"class": "bpsk", "freq": "433920000"}}
        msg = build_rfc5424(
            facility=16, severity=6,
            hostname="n1", app_name="mlrf-edge",
            proc_id="-", msg_id="-",
            message="test", structured_data=sd,
        )
        assert isinstance(msg, str)
        assert 'class="bpsk"' in msg
        assert "[mlrf@0" in msg

    def test_escape_sd_value(self):
        assert _escape_sd_value('test"val') == 'test\\"val'
        assert _escape_sd_value("test]val") == "test\\]val"


class TestEdgeSyslogSend:
    def test_send_below_threshold_dropped(self):
        client = EdgeSyslogClient(host="h", severity_threshold="warning")
        # "info" (6) is below "warning" (4) threshold, should be dropped
        result = client.send("info", "test message")
        assert result is False

    def test_send_at_threshold_enqueued(self):
        client = EdgeSyslogClient(host="h", severity_threshold="info")
        result = client.send("info", "test message")
        assert result is True
        assert client._queue.qsize() == 1

    def test_forward_detection_enqueues(self):
        client = EdgeSyslogClient(host="h", severity_threshold="info")
        result = client.forward_detection({
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433e6,
            "snr_db": 15.0,
            "power_dbm": -60.0,
            "anomaly_score": 0.1,
        })
        assert result is True


# ---------------------------------------------------------------------------
# spectrum_sweeper.py (helpers / parsers only -- no SDR hardware)
# ---------------------------------------------------------------------------

from sigrift.bridge.spectrum_sweeper import (
    _estimate_noise_floor,
    _detect_peaks,
    _parse_rtl_power_csv,
    _parse_hackrf_sweep_output,
    SpectrumSweeper,
)


class TestSpectrumSweeperHelpers:
    def test_noise_floor_empty(self):
        assert _estimate_noise_floor([]) == -120.0

    def test_noise_floor_median(self):
        # median of [-100, -90, -80] = -90
        assert _estimate_noise_floor([-100, -90, -80]) == -90.0

    def test_detect_peaks_above_threshold(self):
        psd = [-100, -100, -80, -100, -100]
        peaks = _detect_peaks(psd, start_freq_hz=100e6, bin_width_hz=1e6, threshold_db=10.0)
        assert len(peaks) == 1
        assert isinstance(peaks[0], dict)
        assert peaks[0]["freq_hz"] == 102e6  # index 2

    def test_detect_peaks_none_above(self):
        psd = [-100, -100, -100, -100]
        peaks = _detect_peaks(psd, start_freq_hz=100e6, bin_width_hz=1e6, threshold_db=10.0)
        assert len(peaks) == 0

    def test_parse_rtl_power_empty(self):
        assert _parse_rtl_power_csv("") == []

    def test_parse_rtl_power_valid(self):
        # Simulate a minimal rtl_power CSV line
        csv = "2026-02-28, 12:00:00, 100000000, 200000000, 1000000, 10, -90.0, -80.0, -70.0\n"
        result = _parse_rtl_power_csv(csv)
        assert len(result) == 1
        assert isinstance(result[0], dict)
        assert result[0]["fft_size"] == 3
        assert result[0]["freq_start_hz"] == 100000000

    def test_parse_hackrf_sweep_empty(self):
        assert _parse_hackrf_sweep_output("") == []


class TestSpectrumSweeperInit:
    @patch("sigrift.bridge.spectrum_sweeper._check_tool", return_value=False)
    def test_constructor_with_explicit_backend(self, mock_check):
        s = SpectrumSweeper(
            server_url="https://localhost:8444",
            api_key="test",
            node_id="n1",
            backend="rtl_power",
        )
        assert s._backend == "rtl_power"
        assert s.is_running is False

    @patch("sigrift.bridge.spectrum_sweeper._check_tool", return_value=False)
    def test_stats_initial(self, mock_check):
        s = SpectrumSweeper(
            server_url="https://localhost:8444",
            api_key="test",
            node_id="n1",
            backend="rtl_power",
        )
        stats = s.stats()
        assert isinstance(stats, dict)
        assert stats["sweep_count"] == 0
        assert stats["upload_count"] == 0
        assert stats["running"] is False

    def test_invalid_backend_raises(self):
        with pytest.raises(ValueError, match="Unknown sweep backend"):
            SpectrumSweeper(
                server_url="https://localhost:8444",
                api_key="test",
                node_id="n1",
                backend="bogus_tool",
            )


# ---------------------------------------------------------------------------
# storage/emitter_store.py
# ---------------------------------------------------------------------------

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.emitter_store import EmitterStore


class TestEmitterStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return EmitterStore(ctx)

    def test_upsert_empty_list(self, store):
        assert store.upsert_emitters([]) == 0

    def test_upsert_and_list(self, store):
        emitters = [
            {
                "emitter_id": "em-001",
                "primary_freq_hz": 433.92e6,
                "bandwidth_hz": 25e3,
                "signal_class": "bpsk",
                "detection_count": 10,
            },
            {
                "emitter_id": "em-002",
                "primary_freq_hz": 915e6,
                "bandwidth_hz": 50e3,
                "signal_class": "qpsk",
                "detection_count": 5,
            },
        ]
        assert store.upsert_emitters(emitters) == 2
        results = store.list_emitters()
        assert len(results) == 2
        assert all(isinstance(r, dict) for r in results)
        assert results[0]["emitter_id"] == "em-001"  # higher detection_count first

    def test_get_emitter_by_id(self, store):
        store.upsert_emitters([{
            "emitter_id": "em-x",
            "primary_freq_hz": 100e6,
            "signal_class": "fm",
        }])
        result = store.get_emitter(emitter_id="em-x")
        assert result is not None
        assert isinstance(result, dict)
        assert result["signal_class"] == "fm"
        assert store.get_emitter("nonexistent") is None

    def test_count_and_delete(self, store):
        store.upsert_emitters([{
            "emitter_id": "em-d",
            "primary_freq_hz": 200e6,
            "signal_class": "ook",
        }])
        assert store.count() == 1
        deleted = store.delete_all()
        assert deleted == 1
        assert store.count() == 0

    def test_filter_by_signal_class(self, store):
        store.upsert_emitters([
            {"emitter_id": "a", "primary_freq_hz": 100e6, "signal_class": "bpsk"},
            {"emitter_id": "b", "primary_freq_hz": 200e6, "signal_class": "qpsk"},
        ])
        results = store.list_emitters(signal_class="bpsk")
        assert len(results) == 1
        assert isinstance(results[0], dict)
        assert results[0]["emitter_id"] == "a"


# ---------------------------------------------------------------------------
# storage/geo_analytics.py
# ---------------------------------------------------------------------------

from sigrift.bridge.storage.geo_analytics import GeoAnalyticsStore


class TestGeoAnalyticsStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "geo_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return GeoAnalyticsStore(ctx)

    def _insert_detections(self, ctx, records):
        conn = ctx.get_conn()
        for r in records:
            conn.execute(
                "INSERT INTO detections "
                "(detection_id, node_id, timestamp, signal_class, confidence, "
                "family, freq_hz, snr_db, anomaly_score, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    r.get("detection_id", f"det-{id(r)}"),
                    r["node_id"], r["timestamp"], r["signal_class"],
                    r.get("confidence", 0.9), r.get("family", ""),
                    r.get("freq_hz", 433e6), r.get("snr_db", 15.0),
                    r.get("anomaly_score", 0.0), "default",
                ),
            )
        conn.commit()

    def test_node_summary_empty(self, store, ctx):
        result = store.get_node_detection_summary("node-01", "2020-01-01T00:00:00")
        assert isinstance(result, dict)
        assert result["detection_count"] == 0
        assert result["top_signals"] == []
        assert result["anomaly_count"] == 0

    def test_node_summary_with_data(self, store, ctx):
        now = datetime.now(timezone.utc).isoformat()
        self._insert_detections(ctx, [
            {"node_id": "n1", "timestamp": now, "signal_class": "bpsk",
             "detection_id": "d1", "anomaly_score": 0.5},
            {"node_id": "n1", "timestamp": now, "signal_class": "bpsk",
             "detection_id": "d2", "anomaly_score": 0.1},
        ])
        result = store.get_node_detection_summary("n1", "2020-01-01T00:00:00")
        assert isinstance(result, dict)
        assert result["detection_count"] == 2
        assert isinstance(result["top_signals"], list)
        assert "bpsk" in result["top_signals"]
        assert result["anomaly_count"] == 1  # only score >= 0.3

    def test_heatmap_weight(self, store, ctx):
        now = datetime.now(timezone.utc).isoformat()
        self._insert_detections(ctx, [
            {"node_id": "n1", "timestamp": now, "signal_class": "bpsk",
             "detection_id": "h1"},
        ])
        weight = store.get_heatmap_weight("n1", "2020-01-01T00:00:00")
        assert weight == 1

    def test_coverage_stats_empty(self, store, ctx):
        result = store.get_coverage_stats("n1")
        assert isinstance(result, dict)
        assert result["detection_classes"] == []
        assert result["avg_snr_db"] == 0.0

    def test_activity_feed_empty_node_ids(self, store):
        assert store.get_activity_feed([], "2020-01-01T00:00:00") == []
