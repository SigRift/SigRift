"""Tests for the Bluetooth vulnerability scanner (BtVulnScanner).

Covers:
  - Known CVE matching (vulnerable BT device fingerprint)
  - No-match case (clean/modern device)
  - Edge cases (empty input, malformed data, missing fields)
  - Severity classification and risk level mapping
  - Protocol risk scoring (deprecated versions, connectable, MAC randomization)
  - Service exposure scoring (risky services, HID on non-input device)
  - Behavioral anomaly scoring (RSSI anomalies, drive-by, MAC churn)
  - Batch assessment and sorting
  - Risk summary aggregation
  - OUI manufacturer lookup
  - UUID16 extraction from various formats
  - Version range checking
  - Random MAC detection
  - Custom weight overrides
"""

from __future__ import annotations

import pytest

from sigrift.bridge.bt_vuln_scanner import (
    BtVulnScanner,
    _is_random_mac,
    _parse_major_class,
    _risk_level,
    _version_in_range,
    _version_index,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> BtVulnScanner:
    return BtVulnScanner()


# ---------------------------------------------------------------------------
# Helper device builders
# ---------------------------------------------------------------------------

def _vulnerable_classic_device() -> dict:
    """A classic BT 4.0 device with risky services -- should match multiple CVEs."""
    return {
        "device_addr": "00:17:C9:AA:BB:CC",
        "device_name": "OldPhone",
        "device_type": "classic",
        "device_class": 0x000200,  # Phone major class (bits 12-8 = 0x02)
        "rssi_dbm": -50.0,
        "service_uuids": ["1105", "1106", "1101"],  # OBEX Push, OBEX FTP, SPP
        "manufacturer": "",
        "connectable": True,
        "bonded": False,
        "bt_version": "4.0",
    }


def _clean_modern_device() -> dict:
    """A modern BLE 5.3 device with only audio services -- should be low risk."""
    return {
        "device_addr": "7A:BB:CC:DD:EE:FF",  # Random MAC (bit 1 set)
        "device_name": "AirPods Pro",
        "device_type": "ble",
        "device_class": 0x000400,  # Audio/Video major class (bits 12-8 = 0x04)
        "rssi_dbm": -65.0,
        "service_uuids": ["110b", "180f"],  # A2DP Sink, Battery
        "manufacturer": "Apple",
        "connectable": True,
        "bonded": True,
        "bt_version": "5.3",
    }


def _dual_mode_device() -> dict:
    """A dual-mode BT 4.2 device -- vulnerable to BLURtooth."""
    return {
        "device_addr": "00:22:D0:11:22:33",
        "device_name": "FitnessBand",
        "device_type": "dual",
        "device_class": 0x000700,  # Wearable (bits 12-8 = 0x07)
        "rssi_dbm": -40.0,
        "service_uuids": ["180a", "180f", "1812"],  # DevInfo, Battery, HID over GATT
        "manufacturer": "",
        "connectable": True,
        "bonded": False,
        "bt_version": "4.2",
    }


# ---------------------------------------------------------------------------
# CVE matching tests
# ---------------------------------------------------------------------------


class TestCVEMatching:
    def test_vulnerable_classic_matches_cves(self, scanner):
        result = scanner.assess_device(_vulnerable_classic_device())
        cve_ids = [c["cve_id"] for c in result["matched_cves"]]
        # BT 4.0, classic, connectable, not bonded -> should match several
        assert "CVE-2017-0781" in cve_ids  # BlueBorne RCE
        assert "CVE-2019-9506" in cve_ids  # KNOB
        assert "CVE-2020-10135" in cve_ids  # BIAS
        assert isinstance(result["vuln_match"], float)
        assert result["vuln_match"] > 0

    def test_bluffs_matches_bt42_through_54(self, scanner):
        """CVE-2023-24023 (BLUFFS) should match BT 4.2-5.4 devices."""
        device = _clean_modern_device()
        device["bt_version"] = "5.2"
        device["device_type"] = "ble"
        result = scanner.assess_device(device)
        cve_ids = [c["cve_id"] for c in result["matched_cves"]]
        assert "CVE-2023-24023" in cve_ids

    def test_bluffs_does_not_match_old_bt(self, scanner):
        """BLUFFS should NOT match BT 3.0."""
        device = _vulnerable_classic_device()
        device["bt_version"] = "3.0"
        result = scanner.assess_device(device)
        cve_ids = [c["cve_id"] for c in result["matched_cves"]]
        assert "CVE-2023-24023" not in cve_ids

    def test_blurtooth_requires_dual_mode(self, scanner):
        """CVE-2020-15802 (BLURtooth) requires dual-mode device."""
        dual = _dual_mode_device()
        result = scanner.assess_device(dual)
        cve_ids = [c["cve_id"] for c in result["matched_cves"]]
        assert "CVE-2020-15802" in cve_ids

        # Same version but classic-only should NOT match
        classic = dict(dual)
        classic["device_type"] = "classic"
        result_classic = scanner.assess_device(classic)
        cve_ids_classic = [c["cve_id"] for c in result_classic["matched_cves"]]
        assert "CVE-2020-15802" not in cve_ids_classic

    def test_sweyntooth_requires_ble(self, scanner):
        """CVE-2020-SWEYNTOOTH should match BLE but not classic-only."""
        ble_device = {
            "device_addr": "AA:BB:CC:DD:EE:FF",
            "device_name": "BLE Sensor",
            "device_type": "ble",
            "bt_version": "4.2",
            "connectable": True,
            "bonded": False,
        }
        result = scanner.assess_device(ble_device)
        cve_ids = [c["cve_id"] for c in result["matched_cves"]]
        assert "CVE-2020-SWEYNTOOTH" in cve_ids

    def test_modern_bt54_has_fewer_cves(self, scanner):
        """BT 5.4 should have fewer CVE matches than BT 4.0."""
        old = _vulnerable_classic_device()
        old["bt_version"] = "4.0"
        new = dict(old)
        new["bt_version"] = "5.4"
        result_old = scanner.assess_device(old)
        result_new = scanner.assess_device(new)
        assert len(result_old["matched_cves"]) >= len(result_new["matched_cves"])


# ---------------------------------------------------------------------------
# No-match / clean device tests
# ---------------------------------------------------------------------------


class TestCleanDevice:
    def test_modern_ble_low_risk(self, scanner):
        result = scanner.assess_device(_clean_modern_device())
        assert isinstance(result["risk_level"], str)
        assert result["risk_level"] in ("safe", "low_risk")
        assert isinstance(result["risk_score"], float)
        assert result["risk_score"] < 0.45

    def test_bonded_device_reduces_bias_risk(self, scanner):
        """Bonded devices are more likely to have Secure Connections."""
        device = _vulnerable_classic_device()
        device["bonded"] = True
        result = scanner.assess_device(device)
        # Still matches BIAS but bonded flag should reduce protocol risk
        assert isinstance(result["protocol_risk"], float)
        assert result["protocol_risk"] < 1.0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_device_info(self, scanner):
        result = scanner.assess_device({})
        assert result["device_addr"] == ""
        assert result["device_name"] == ""
        assert result["risk_score"] >= 0.0
        assert result["risk_level"] in ("safe", "low_risk", "medium_risk", "high_risk", "critical")
        assert isinstance(result["matched_cves"], list)
        assert isinstance(result["flags"], list)

    def test_missing_service_uuids(self, scanner):
        result = scanner.assess_device({"device_addr": "AA:BB:CC:DD:EE:FF"})
        assert result["service_exposure"] == 0.0
        assert result["risky_services"] == []

    def test_service_uuids_as_json_string(self, scanner):
        device = {
            "device_addr": "AA:BB:CC:DD:EE:FF",
            "service_uuids": '["1101", "1105"]',
        }
        result = scanner.assess_device(device)
        assert isinstance(result["risky_services"], list)
        assert len(result["risky_services"]) > 0

    def test_service_uuids_invalid_json_string(self, scanner):
        device = {
            "device_addr": "AA:BB:CC:DD:EE:FF",
            "service_uuids": "not-valid-json",
        }
        result = scanner.assess_device(device)
        assert result["service_exposure"] == 0.0

    def test_none_service_uuids(self, scanner):
        device = {
            "device_addr": "AA:BB:CC:DD:EE:FF",
            "service_uuids": None,
        }
        result = scanner.assess_device(device)
        assert result["service_exposure"] == 0.0

    def test_malformed_mac_address(self, scanner):
        result = scanner.assess_device({"device_addr": "ZZ:ZZ"})
        assert result["is_random_mac"] is False
        assert result["manufacturer"] == ""

    def test_empty_mac_address(self, scanner):
        result = scanner.assess_device({"device_addr": ""})
        assert result["is_random_mac"] is False

    def test_unknown_device_type(self, scanner):
        result = scanner.assess_device({"device_type": "unknown"})
        assert result["bt_version"] == ""

    def test_unknown_bt_version_no_cve_match(self, scanner):
        """Devices with unknown BT version should not spuriously match CVEs."""
        result = scanner.assess_device({"device_type": "unknown", "bt_version": "99.9"})
        assert len(result["matched_cves"]) == 0


# ---------------------------------------------------------------------------
# Risk level classification
# ---------------------------------------------------------------------------


class TestRiskLevel:
    def test_safe_threshold(self):
        assert _risk_level(0.0) == "safe"
        assert _risk_level(0.19) == "safe"

    def test_low_risk_threshold(self):
        assert _risk_level(0.20) == "low_risk"
        assert _risk_level(0.44) == "low_risk"

    def test_medium_risk_threshold(self):
        assert _risk_level(0.45) == "medium_risk"
        assert _risk_level(0.69) == "medium_risk"

    def test_high_risk_threshold(self):
        assert _risk_level(0.70) == "high_risk"
        assert _risk_level(0.84) == "high_risk"

    def test_critical_threshold(self):
        assert _risk_level(0.85) == "critical"
        assert _risk_level(1.0) == "critical"


# ---------------------------------------------------------------------------
# Protocol risk scoring
# ---------------------------------------------------------------------------


class TestProtocolRisk:
    def test_deprecated_version_flagged(self, scanner):
        device = {"bt_version": "2.1", "device_type": "classic"}
        result = scanner.assess_device(device)
        assert isinstance(result["protocol_risk"], float)
        assert result["protocol_risk"] > 0
        assert any("deprecated" in f for f in result["flags"])

    def test_connectable_not_bonded_flagged(self, scanner):
        device = {"connectable": True, "bonded": False, "bt_version": "5.0"}
        result = scanner.assess_device(device)
        assert "connectable_not_bonded" in result["flags"]

    def test_non_randomized_mac_flagged(self, scanner):
        device = {"device_addr": "00:17:C9:AA:BB:CC"}  # Public OUI
        result = scanner.assess_device(device)
        assert "non_randomized_mac" in result["flags"]

    def test_randomized_mac_not_flagged(self, scanner):
        device = {"device_addr": "7A:BB:CC:DD:EE:FF"}  # Random (bit 1 set)
        result = scanner.assess_device(device)
        assert "non_randomized_mac" not in result["flags"]


# ---------------------------------------------------------------------------
# Service exposure scoring
# ---------------------------------------------------------------------------


class TestServiceExposure:
    def test_obex_services_flagged(self, scanner):
        device = {"service_uuids": ["1105", "1106"]}  # OBEX Push + FTP
        result = scanner.assess_device(device)
        assert isinstance(result["service_exposure"], float)
        assert result["service_exposure"] > 0
        svc_names = [s["service"] for s in result["risky_services"]]
        assert "OBEX Object Push" in svc_names
        assert "OBEX File Transfer" in svc_names

    def test_hid_on_non_input_device_flagged(self, scanner):
        device = {
            "device_class": 0x000400,  # Audio/Video (bits 12-8 = 0x04)
            "service_uuids": ["1812"],  # HID over GATT
        }
        result = scanner.assess_device(device)
        assert "hid_on_non_input_device" in result["flags"]

    def test_hid_on_peripheral_not_flagged(self, scanner):
        device = {
            "device_class": 0x002540,  # Peripheral major class (bits 12-8 = 0x05)
            "service_uuids": ["1812"],
        }
        result = scanner.assess_device(device)
        assert "hid_on_non_input_device" not in result["flags"]

    def test_many_services_flagged(self, scanner):
        device = {
            "service_uuids": [
                "1101", "1105", "1106", "1108", "110a",
                "110b", "110c", "180a",
            ],
        }
        result = scanner.assess_device(device)
        assert any("many_services" in f for f in result["flags"])

    def test_audio_only_services_low_risk(self, scanner):
        device = {"service_uuids": ["110b", "110c", "180f"]}
        result = scanner.assess_device(device)
        assert result["risky_services"] == []

    def test_full_128bit_uuid_resolved(self, scanner):
        device = {
            "service_uuids": ["00001101-0000-1000-8000-00805f9b34fb"],
        }
        result = scanner.assess_device(device)
        svc_names = [s["service"] for s in result["risky_services"]]
        assert "SPP - Serial Port" in svc_names

    def test_0x_prefixed_uuid(self, scanner):
        device = {"service_uuids": ["0x1101"]}
        result = scanner.assess_device(device)
        svc_names = [s["service"] for s in result["risky_services"]]
        assert "SPP - Serial Port" in svc_names


# ---------------------------------------------------------------------------
# Behavioral anomaly scoring
# ---------------------------------------------------------------------------


class TestBehavioralAnomaly:
    def test_strong_rssi_flagged(self, scanner):
        device = {"rssi_dbm": -10.0}
        result = scanner.assess_device(device)
        assert any("unusually_strong_rssi" in f for f in result["flags"])

    def test_normal_rssi_not_flagged(self, scanner):
        device = {"rssi_dbm": -60.0}
        result = scanner.assess_device(device)
        assert not any("unusually_strong_rssi" in f for f in result["flags"])

    def test_high_rssi_variance_flagged(self, scanner):
        device = {"rssi_dbm": -50.0, "min_rssi_dbm": -90.0, "max_rssi_dbm": -20.0}
        result = scanner.assess_device(device)
        assert any("rssi_variance_high" in f for f in result["flags"])

    def test_drive_by_indicator(self, scanner):
        device = {"observation_count": 1}
        result = scanner.assess_device(device)
        assert "possible_drive_by" in result["flags"]

    def test_excessive_connection_attempts(self, scanner):
        device = {"connection_attempts": 50}
        result = scanner.assess_device(device)
        assert any("excessive_connection_attempts" in f for f in result["flags"])

    def test_rapid_mac_rotation(self, scanner):
        device = {
            "device_addr": "7A:BB:CC:DD:EE:FF",  # Random MAC
            "observation_count": 1,
        }
        result = scanner.assess_device(device)
        assert "rapid_mac_rotation_suspected" in result["flags"]

    def test_unnamed_connectable_flagged(self, scanner):
        device = {"device_name": "", "connectable": True}
        result = scanner.assess_device(device)
        assert "unnamed_connectable_device" in result["flags"]

    def test_hid_on_audio_device_flagged(self, scanner):
        device = {
            "device_class": 0x000400,  # Audio/Video (bits 12-8 = 0x04)
            "service_uuids": ["1124"],  # HID
        }
        result = scanner.assess_device(device)
        assert "hid_service_on_audio_device" in result["flags"]


# ---------------------------------------------------------------------------
# Batch assessment
# ---------------------------------------------------------------------------


class TestBatchAssessment:
    def test_batch_sorts_by_risk_descending(self, scanner):
        devices = [_clean_modern_device(), _vulnerable_classic_device()]
        results = scanner.assess_batch(devices)
        assert results[0]["risk_score"] >= results[1]["risk_score"]

    def test_batch_returns_all_devices(self, scanner):
        devices = [_clean_modern_device(), _vulnerable_classic_device(), _dual_mode_device()]
        results = scanner.assess_batch(devices)
        assert len(results) == 3

    def test_empty_batch(self, scanner):
        results = scanner.assess_batch([])
        assert results == []


# ---------------------------------------------------------------------------
# Risk summary
# ---------------------------------------------------------------------------


class TestRiskSummary:
    def test_summary_empty_input(self, scanner):
        summary = scanner.get_risk_summary([])
        assert summary["total_devices"] == 0
        assert summary["avg_risk_score"] == 0.0
        assert summary["max_risk_score"] == 0.0
        assert summary["critical_devices"] == []

    def test_summary_counts_devices(self, scanner):
        devices = [_vulnerable_classic_device(), _clean_modern_device()]
        assessments = scanner.assess_batch(devices)
        summary = scanner.get_risk_summary(assessments)
        assert summary["total_devices"] == 2

    def test_summary_risk_distribution(self, scanner):
        devices = [_vulnerable_classic_device(), _clean_modern_device()]
        assessments = scanner.assess_batch(devices)
        summary = scanner.get_risk_summary(assessments)
        assert isinstance(summary["risk_distribution"], dict)
        dist = summary["risk_distribution"]
        total = sum(dist.values())
        assert total == 2

    def test_summary_cve_frequency(self, scanner):
        devices = [_vulnerable_classic_device(), _dual_mode_device()]
        assessments = scanner.assess_batch(devices)
        summary = scanner.get_risk_summary(assessments)
        assert isinstance(summary["cve_frequency"], dict)
        assert len(summary["cve_frequency"]) > 0

    def test_summary_critical_devices_listed(self, scanner):
        devices = [_vulnerable_classic_device()]
        assessments = scanner.assess_batch(devices)
        summary = scanner.get_risk_summary(assessments)
        # Vulnerable classic device should be high_risk or critical
        high_crit = summary["risk_distribution"].get("high_risk", 0) + \
                    summary["risk_distribution"].get("critical", 0)
        if high_crit > 0:
            assert isinstance(summary["critical_devices"], list)
            assert len(summary["critical_devices"]) > 0

    def test_summary_top_flags(self, scanner):
        devices = [_vulnerable_classic_device(), _dual_mode_device()]
        assessments = scanner.assess_batch(devices)
        summary = scanner.get_risk_summary(assessments)
        assert isinstance(summary["top_flags"], list)
        if summary["top_flags"]:
            assert "flag" in summary["top_flags"][0]
            assert isinstance(summary["top_flags"][0]["flag"], str)
            assert "count" in summary["top_flags"][0]
            assert isinstance(summary["top_flags"][0]["count"], int)


# ---------------------------------------------------------------------------
# OUI lookup
# ---------------------------------------------------------------------------


class TestOUILookup:
    def test_known_samsung_oui(self, scanner):
        result = scanner.assess_device({"device_addr": "00:17:C9:AA:BB:CC"})
        assert result["oui_manufacturer"] == "Samsung Electronics"

    def test_known_apple_oui(self, scanner):
        result = scanner.assess_device({"device_addr": "44:D8:84:AA:BB:CC"})
        assert result["oui_manufacturer"] == "Apple"

    def test_unknown_oui(self, scanner):
        result = scanner.assess_device({"device_addr": "FF:FF:FF:AA:BB:CC"})
        assert result["oui_manufacturer"] == ""

    def test_short_address(self, scanner):
        result = scanner.assess_device({"device_addr": "AA:BB"})
        assert result["oui_manufacturer"] == ""

    def test_manufacturer_fallback_to_oui(self, scanner):
        """When manufacturer is empty, OUI lookup should fill it in."""
        device = {"device_addr": "00:17:C9:AA:BB:CC", "manufacturer": ""}
        result = scanner.assess_device(device)
        assert result["manufacturer"] == "Samsung Electronics"

    def test_explicit_manufacturer_not_overridden(self, scanner):
        """When manufacturer is explicitly set, OUI should not override."""
        device = {"device_addr": "00:17:C9:AA:BB:CC", "manufacturer": "CustomVendor"}
        result = scanner.assess_device(device)
        assert result["manufacturer"] == "CustomVendor"


# ---------------------------------------------------------------------------
# UUID extraction
# ---------------------------------------------------------------------------


class TestUUID16Extraction:
    def test_raw_4digit_hex(self):
        assert BtVulnScanner._extract_uuid16("1101") == "1101"

    def test_0x_prefix(self):
        assert BtVulnScanner._extract_uuid16("0x110B") == "110b"

    def test_full_128bit_uuid(self):
        assert BtVulnScanner._extract_uuid16(
            "00001101-0000-1000-8000-00805f9b34fb"
        ) == "1101"

    def test_non_bt_128bit_uuid(self):
        """Non-Bluetooth-Base UUIDs should return empty."""
        assert BtVulnScanner._extract_uuid16(
            "12345678-1234-1234-1234-123456789abc"
        ) == ""

    def test_empty_string(self):
        assert BtVulnScanner._extract_uuid16("") == ""

    def test_whitespace_stripped(self):
        assert BtVulnScanner._extract_uuid16("  1101  ") == "1101"


# ---------------------------------------------------------------------------
# Version utilities
# ---------------------------------------------------------------------------


class TestVersionUtils:
    def test_version_index_known(self):
        assert _version_index("4.0") == 6
        assert _version_index("5.0") == 9

    def test_version_index_unknown(self):
        assert _version_index("99.0") == -1

    def test_version_in_range_inclusive(self):
        assert _version_in_range("4.0", "4.0", "5.0") is True
        assert _version_in_range("5.0", "4.0", "5.0") is True

    def test_version_out_of_range(self):
        assert _version_in_range("5.1", "4.0", "5.0") is False
        assert _version_in_range("3.0", "4.0", "5.0") is False

    def test_unknown_version_not_in_range(self):
        assert _version_in_range("99.0", "4.0", "5.0") is False


# ---------------------------------------------------------------------------
# Random MAC detection
# ---------------------------------------------------------------------------


class TestRandomMAC:
    def test_random_mac_detected(self):
        # 0x7A = 0111_1010 -> bit 1 set = locally administered
        assert _is_random_mac("7A:BB:CC:DD:EE:FF") is True

    def test_public_mac_not_random(self):
        # 0x00 = 0000_0000 -> bit 1 not set
        assert _is_random_mac("00:17:C9:AA:BB:CC") is False

    def test_empty_mac(self):
        assert _is_random_mac("") is False

    def test_short_mac(self):
        assert _is_random_mac("A") is False

    def test_hyphen_format(self):
        assert _is_random_mac("7A-BB-CC-DD-EE-FF") is True

    def test_dot_format(self):
        assert _is_random_mac("7ABB.CCDD.EEFF") is True


# ---------------------------------------------------------------------------
# Major device class parsing
# ---------------------------------------------------------------------------


class TestMajorClassParsing:
    def test_phone_class(self):
        major_id, name = _parse_major_class(0x000200)
        assert name == "Phone"

    def test_audio_video_class(self):
        major_id, name = _parse_major_class(0x000400)
        assert name == "Audio/Video"

    def test_peripheral_class(self):
        major_id, name = _parse_major_class(0x002540)
        assert name == "Peripheral"

    def test_unknown_class(self):
        _, name = _parse_major_class(0x000000)
        assert name == "Unknown"


# ---------------------------------------------------------------------------
# Custom weights
# ---------------------------------------------------------------------------


class TestCustomWeights:
    def test_vuln_only_weight(self):
        """Scanner with all weight on vuln_match should amplify CVE scores."""
        scanner = BtVulnScanner(weights={
            "protocol_risk": 0.0,
            "service_exposure": 0.0,
            "vuln_match": 1.0,
            "behavioral_anomaly": 0.0,
        })
        device = _vulnerable_classic_device()
        result = scanner.assess_device(device)
        # Risk score should equal the vuln_match sub-score
        assert result["risk_score"] == pytest.approx(result["vuln_match"], abs=0.01)

    def test_protocol_only_weight(self):
        scanner = BtVulnScanner(weights={
            "protocol_risk": 1.0,
            "service_exposure": 0.0,
            "vuln_match": 0.0,
            "behavioral_anomaly": 0.0,
        })
        device = _vulnerable_classic_device()
        result = scanner.assess_device(device)
        assert result["risk_score"] == pytest.approx(result["protocol_risk"], abs=0.01)


# ---------------------------------------------------------------------------
# BT version inference
# ---------------------------------------------------------------------------


class TestVersionInference:
    def test_ble_infers_40(self, scanner):
        result = scanner.assess_device({"device_type": "ble"})
        assert result["bt_version"] == "4.0"

    def test_classic_infers_30(self, scanner):
        result = scanner.assess_device({"device_type": "classic"})
        assert result["bt_version"] == "3.0"

    def test_dual_infers_40(self, scanner):
        result = scanner.assess_device({"device_type": "dual"})
        assert result["bt_version"] == "4.0"

    def test_explicit_version_overrides_inference(self, scanner):
        result = scanner.assess_device({
            "device_type": "ble",
            "bt_version": "5.2",
        })
        assert result["bt_version"] == "5.2"

    def test_unknown_type_empty_version(self, scanner):
        result = scanner.assess_device({"device_type": "unknown"})
        assert result["bt_version"] == ""
