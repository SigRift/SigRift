"""Tests for CEF syslog output (P3-17a).

Tests CEFFormatter class, CEF event ID mapping, severity computation,
extension field mapping, and SyslogForwarder CEF integration.
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

from datetime import datetime, timezone

import pytest

from sigrift.bridge.syslog_forwarder import (
    CEF_EVENT_BT_ALERT,
    CEF_EVENT_RF_ANOMALY,
    CEF_EVENT_RF_DETECTION,
    CEF_EVENT_WIFI_ALERT,
    CEFFormatter,
    SyslogForwarder,
    _cef_escape,
    _cef_header_escape,
)


# ---------------------------------------------------------------------------
# CEF header format tests
# ---------------------------------------------------------------------------


class TestCEFHeaderFormat:

    def test_basic_header_structure(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert result.startswith("CEF:0|SigRift|SigRift|1.0|")

    def test_header_has_seven_pipe_separated_fields(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        # CEF header ends with | before extensions
        header_part = result.split("|", 7)
        assert len(header_part) == 8

    def test_severity_zero_for_no_anomaly(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        # Severity field is the 7th pipe-separated value
        parts = result.split("|")
        severity_field = parts[6]
        assert severity_field == "0"

    def test_severity_five_for_half_anomaly(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.5}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "5"

    def test_severity_ten_for_full_anomaly(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 1.0}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "10"

    def test_severity_seven_for_anomalous_priority(self):
        alert = {"signal_class": "bpsk", "priority": "Anomalous"}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "7"

    def test_severity_three_for_normal_priority(self):
        alert = {"signal_class": "bpsk", "priority": "Normal"}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "3"

    def test_severity_ten_for_critical_priority(self):
        alert = {"signal_class": "bpsk", "priority": "Critical"}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "10"

    def test_severity_clamped_at_ten(self):
        # anomaly_score > 1.0 should still clamp to 10
        alert = {"signal_class": "bpsk", "anomaly_score": 1.5}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        assert parts[6] == "10"


# ---------------------------------------------------------------------------
# CEF event ID tests
# ---------------------------------------------------------------------------


class TestCEFEventIDs:

    def test_rf_detection_event_id(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_RF_DETECTION}|" in result
        assert "|RF Detection|" in result

    def test_rf_anomaly_event_id(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.7}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_RF_ANOMALY}|" in result
        assert "|RF Anomaly|" in result

    def test_wifi_alert_event_id_from_class(self):
        alert = {"signal_class": "wifi_beacon", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_WIFI_ALERT}|" in result
        assert "|WiFi Alert|" in result

    def test_wifi_alert_event_id_from_name(self):
        alert = {"signal_class": "beacon", "name": "wifi_rogue_ap", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_WIFI_ALERT}|" in result

    def test_bt_alert_event_id_from_class(self):
        alert = {"signal_class": "bluetooth_le", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_BT_ALERT}|" in result
        assert "|Bluetooth Alert|" in result

    def test_bt_alert_event_id_from_bt_class(self):
        alert = {"signal_class": "bt_classic", "anomaly_score": 0.0}
        result = CEFFormatter.format(alert)
        assert f"|{CEF_EVENT_BT_ALERT}|" in result


# ---------------------------------------------------------------------------
# Extension field mapping tests
# ---------------------------------------------------------------------------


class TestCEFExtensions:

    def test_src_node_id(self):
        alert = {"node_id": "node-01", "signal_class": "bpsk"}
        result = CEFFormatter.format(alert)
        assert "src=node-01" in result

    def test_signal_class_cs1(self):
        alert = {"signal_class": "qam16"}
        result = CEFFormatter.format(alert)
        assert "cs1=qam16 cs1Label=SignalClass" in result

    def test_freq_hz_cs2(self):
        alert = {"signal_class": "bpsk", "freq_hz": 433920000.0}
        result = CEFFormatter.format(alert)
        assert "cs2=433920000.0 cs2Label=FrequencyHz" in result

    def test_power_dbm_cn1(self):
        alert = {"signal_class": "bpsk", "power_dbm": -65.3}
        result = CEFFormatter.format(alert)
        assert "cn1=-65.3 cn1Label=PowerDBm" in result

    def test_snr_db_cn2(self):
        alert = {"signal_class": "bpsk", "snr_db": 12.5}
        result = CEFFormatter.format(alert)
        assert "cn2=12.5 cn2Label=SNRdB" in result

    def test_anomaly_score_cfp1(self):
        alert = {"signal_class": "bpsk", "anomaly_score": 0.85}
        result = CEFFormatter.format(alert)
        assert "cfp1=0.85 cfp1Label=AnomalyScore" in result

    def test_message_field(self):
        alert = {"signal_class": "bpsk", "message": "Test alert message"}
        result = CEFFormatter.format(alert)
        assert "msg=Test alert message" in result

    def test_reasons_list_joined(self):
        alert = {"signal_class": "bpsk", "reasons": ["high power", "unknown freq"]}
        result = CEFFormatter.format(alert)
        assert "msg=high power unknown freq" in result

    def test_timestamp_epoch_ms(self):
        ts = "2026-03-11T10:00:00+00:00"
        alert = {"signal_class": "bpsk", "triggered_at": ts}
        result = CEFFormatter.format(alert)
        assert "rt=" in result
        # Verify epoch ms is reasonable
        dt = datetime.fromisoformat(ts)
        expected_ms = int(dt.timestamp() * 1000)
        assert f"rt={expected_ms}" in result

    def test_category_from_priority(self):
        alert = {"signal_class": "bpsk", "priority": "Anomalous"}
        result = CEFFormatter.format(alert)
        assert "cat=Anomalous" in result

    def test_category_from_severity(self):
        alert = {"signal_class": "bpsk", "severity": "critical"}
        result = CEFFormatter.format(alert)
        assert "cat=critical" in result

    def test_full_extension_set(self):
        alert = {
            "node_id": "edge-03",
            "signal_class": "qpsk",
            "freq_hz": 915e6,
            "power_dbm": -40.0,
            "snr_db": 20.0,
            "anomaly_score": 0.6,
            "message": "Elevated anomaly",
            "triggered_at": "2026-03-11T12:00:00+00:00",
            "severity": "warning",
        }
        result = CEFFormatter.format(alert)
        assert "src=edge-03" in result
        assert "cs1=qpsk cs1Label=SignalClass" in result
        assert "cs2=" in result
        assert "cn1=-40.0" in result
        assert "cn2=20.0" in result
        assert "cfp1=0.6" in result
        assert "msg=Elevated anomaly" in result
        assert "rt=" in result
        assert "cat=warning" in result


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestCEFEdgeCases:

    def test_missing_signal_class(self):
        alert = {}
        result = CEFFormatter.format(alert)
        assert isinstance(result, str)
        assert result.startswith("CEF:0|")

    def test_missing_node_id(self):
        alert = {"signal_class": "bpsk"}
        result = CEFFormatter.format(alert)
        assert "src=" not in result

    def test_missing_freq(self):
        alert = {"signal_class": "bpsk"}
        result = CEFFormatter.format(alert)
        assert "cs2=" not in result

    def test_unicode_signal_class(self):
        alert = {"signal_class": "test_signal"}
        result = CEFFormatter.format(alert)
        assert "cs1=test_signal" in result

    def test_equals_sign_escaped(self):
        result = _cef_escape("key=value")
        assert "\\=" in result

    def test_backslash_escaped(self):
        result = _cef_escape("path\\file")
        assert "\\\\" in result

    def test_pipe_escaped_in_header(self):
        result = _cef_header_escape("test|value")
        assert "\\|" in result

    def test_invalid_anomaly_score_type(self):
        alert = {"signal_class": "bpsk", "anomaly_score": "invalid"}
        result = CEFFormatter.format(alert)
        # Should not crash, severity defaults to 0
        parts = result.split("|")
        assert parts[6] == "0"

    def test_none_anomaly_score(self):
        alert = {"signal_class": "bpsk", "anomaly_score": None}
        result = CEFFormatter.format(alert)
        parts = result.split("|")
        # None treated as 0
        assert parts[6] == "0"

    def test_zero_freq_hz_included(self):
        alert = {"signal_class": "bpsk", "freq_hz": 0}
        result = CEFFormatter.format(alert)
        assert "cs2=0 cs2Label=FrequencyHz" in result

    def test_negative_power_dbm(self):
        alert = {"signal_class": "bpsk", "power_dbm": -120.5}
        result = CEFFormatter.format(alert)
        assert "cn1=-120.5" in result


# ---------------------------------------------------------------------------
# SyslogForwarder integration tests
# ---------------------------------------------------------------------------


class TestSyslogForwarderCEF:

    def test_format_cef_method(self):
        forwarder = SyslogForwarder()
        alert = {
            "signal_class": "bpsk",
            "anomaly_score": 0.5,
            "node_id": "node-01",
        }
        result = forwarder.format_cef(alert)
        assert isinstance(result, str)
        assert result.startswith("CEF:0|")
        assert "src=node-01" in result

    def test_add_target_with_cef_format(self):
        forwarder = SyslogForwarder()
        target = forwarder.add_target(
            host="syslog.example.com",
            fmt="cef",
        )
        assert isinstance(target, dict)
        assert target["format"] == "cef"

    def test_add_target_default_format(self):
        forwarder = SyslogForwarder()
        target = forwarder.add_target(host="syslog.example.com")
        assert isinstance(target, dict)
        assert target["format"] == "rfc5424"

    def test_format_message_cef(self):
        forwarder = SyslogForwarder()
        alert = {"signal_class": "bpsk", "anomaly_score": 0.5}
        target = {"format": "cef", "facility": "local0"}
        msg = forwarder._format_message(alert, target)
        assert isinstance(msg, bytes)
        decoded = msg.decode("utf-8")
        assert decoded.startswith("CEF:0|")

    def test_format_message_rfc5424(self):
        forwarder = SyslogForwarder()
        alert = {"signal_class": "bpsk", "severity": "info"}
        target = {"format": "rfc5424", "facility": "local0"}
        msg = forwarder._format_message(alert, target)
        assert isinstance(msg, bytes)
        decoded = msg.decode("utf-8")
        assert "SigRift" in decoded

    def test_format_message_default_is_rfc5424(self):
        forwarder = SyslogForwarder()
        alert = {"signal_class": "bpsk", "severity": "info"}
        target = {"facility": "local0"}  # no format key
        msg = forwarder._format_message(alert, target)
        decoded = msg.decode("utf-8")
        assert "SigRift" in decoded
        assert not decoded.startswith("CEF:0|")

    def test_update_target_format(self):
        forwarder = SyslogForwarder()
        target = forwarder.add_target(host="syslog.example.com", fmt="rfc5424")
        updated = forwarder.update_target(target["id"], {"format": "cef"})
        assert updated is not None
        assert isinstance(updated, dict)
        assert updated["format"] == "cef"
