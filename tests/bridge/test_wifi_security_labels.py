"""Incomplete radio observations must not invent an open network or downgrade."""

from __future__ import annotations

import importlib
import struct
from unittest.mock import patch

import pytest

from sigrift.bridge.anomaly.wifi_scorer import (
    WifiAnomalyScorer,
    WifiBaseline,
    WifiBaselineManager,
)


@pytest.fixture(scope="module")
def wifi():
    # No interface/capture is started; suppress the optional import-time file log.
    with patch("pathlib.Path.mkdir", side_effect=PermissionError):
        return importlib.import_module("sigrift.edge.wifi_scan")


def beacon(capability, *elements):
    return struct.pack("<QHH", 0, 100, capability) + b"".join(elements)


def element(kind, data):
    return bytes((kind, len(data))) + data


RSN_WPA2 = bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac02")
RSN_WPA3 = bytes.fromhex("0100 000fac04 0100 000fac04 0100 000fac08")
WPA_IE = bytes.fromhex("0050f201 0100 0050f202 0100 0050f202 0100 0050f202")


@pytest.mark.parametrize("capability", [0x10, 0x11])
def test_privacy_without_recognized_protocol_is_protected_unspecified(wifi, capability):
    result = wifi.FrameParser.parse_beacon_ies(beacon(capability))
    assert result["security"] == "Protected (unspecified)"


@pytest.mark.parametrize("size", [0, 1, 10, 11])
def test_incomplete_fixed_beacon_fields_are_unknown(wifi, size):
    assert wifi.FrameParser.parse_beacon_ies(b"\x00" * size)["security"] == "Unknown"


@pytest.mark.parametrize("capability", [0, 1])
def test_complete_unprotected_beacon_still_reports_open(wifi, capability):
    assert wifi.FrameParser.parse_beacon_ies(beacon(capability))["security"] == "Open"


@pytest.mark.parametrize(
    "elements,expected",
    [
        ((element(221, WPA_IE),), "WPA"),
        ((element(48, RSN_WPA2),), "WPA2"),
        ((element(48, RSN_WPA3),), "WPA3"),
        ((element(48, RSN_WPA2), element(221, WPA_IE)), "WPA2/WPA"),
    ],
)
def test_recognized_protocol_labels_keep_their_existing_precedence(
    wifi, elements, expected
):
    assert (
        wifi.FrameParser.parse_beacon_ies(beacon(0x11, *elements))["security"]
        == expected
    )


@pytest.mark.parametrize(
    "unknown", ["", "Unknown", "Protected (unspecified)", "future-protocol"]
)
def test_unknown_observation_does_not_lock_first_known_baseline(unknown):
    baseline = WifiBaseline()
    baseline.update("network", 6, unknown, -45, 0, 0, 12)
    assert baseline.expected_security == ""
    baseline.update("network", 6, "WPA2", -45, 0, 0, 12)
    assert baseline.expected_security == "WPA2"
    baseline.update("network", 6, unknown, -45, 0, 0, 12)
    assert baseline.expected_security == "WPA2"


@pytest.mark.parametrize(
    "unknown", ["Unknown", "Protected (unspecified)", "future-protocol"]
)
def test_saved_unranked_baseline_can_learn_later_known_protocol(unknown):
    baseline = WifiBaseline.from_dict({"expected_security": unknown})
    baseline.update("network", 6, "WPA2", -45, 0, 0, 12)
    assert baseline.expected_security == "WPA2"


def stable_scorer(protocol):
    manager = WifiBaselineManager()
    for _ in range(50):
        manager.update("02:aa:bb:cc:dd:ee", "network", 6, protocol, -45, 0, 0, 12)
    return manager, WifiAnomalyScorer(manager)


def record(security):
    return {
        "bssid": "02:aa:bb:cc:dd:ee",
        "ssid": "network",
        "channel": 6,
        "security": security,
        "signal_dbm": -45,
        "frame_type": "beacon",
    }


@pytest.mark.parametrize(
    "unknown", ["", "Unknown", "Protected (unspecified)", "future-protocol"]
)
def test_public_batch_does_not_score_missing_protocol_as_open(unknown):
    manager, scorer = stable_scorer("WPA2")
    results = scorer.score_batch([record(unknown)], "test-node")
    assert all(result.dimensions["security_downgrade"] == 0 for result in results)
    assert manager.get_baseline("02:aa:bb:cc:dd:ee").expected_security == "WPA2"


@pytest.mark.parametrize(
    "expected,current,score",
    [
        ("WPA2", "Open", 1),
        ("WPA3", "WEP", 1),
        ("WPA3", "WPA2", 0.5),
        ("WPA2", "WPA2/WPA", 0.5),
        ("WPA2/WPA", "Open", 0.5),
    ],
)
def test_public_batch_retains_real_downgrades_and_ranks_mixed_mode_as_wpa(
    expected, current, score
):
    _manager, scorer = stable_scorer(expected)
    results = scorer.score_batch([record(current)], "test-node")
    assert len(results) == 1
    assert results[0].dimensions["security_downgrade"] == score
    if score == 1:
        assert any("Security downgrade" in reason for reason in results[0].reasons)


@pytest.mark.parametrize(
    "body,label", [(b"\x00" * 11, "Unknown"), (beacon(0x11), "Protected (unspecified)")]
)
def test_real_beacon_bytes_reach_consumer_and_scorer_without_false_downgrade(
    wifi, body, label
):
    radiotap = struct.pack("<BBHIHHb", 0, 0, 13, 0x28, 2437, 0, -45)
    mac = bytes.fromhex("80000000 ffffffffffff 02aabbccddee 02aabbccddee 1000")
    scanner = wifi.WifiScanner("unused-test-interface")
    observation = scanner._parse_packet(radiotap + mac + body)
    assert observation is not None and observation["security"] == label
    manager, scorer = stable_scorer("WPA2")
    results = scorer.score_batch([observation], "test-node")
    assert all(result.dimensions["security_downgrade"] == 0 for result in results)
    assert manager.get_baseline(observation["bssid"]).expected_security == "WPA2"
