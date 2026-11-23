"""Byte-level parser oracles; no interface, capture process, or network access.

Radiotap layouts follow https://www.radiotap.org/ and its reference parser's
alignment table (including FHSS alignment2). Packet construction deliberately
does not call the parser's own mapping/layout helpers.
"""

from __future__ import annotations

import importlib
import struct
import sys
from unittest.mock import patch

import pytest


@pytest.fixture(scope="module")
def wifi():
    # The standalone scanner installs a file logger at import time. Exercise
    # only the parser and never create /opt/rf-edge or need elevated privileges.
    name = "sigrift.edge.wifi_scan"
    if name in sys.modules:
        return sys.modules[name]
    with patch("pathlib.Path.mkdir", side_effect=PermissionError):
        return importlib.import_module(name)


def radiotap(mask, payload=b"", *, extensions=(), version=0, length=None):
    words = b"".join(struct.pack("<I", word) for word in extensions)
    size = 8 + len(words) + len(payload) if length is None else length
    return struct.pack("<BBHI", version, 0, size, mask) + words + payload


def ie(tag, payload):
    return bytes((tag, len(payload))) + payload


def beacon_body(*elements):
    # A valid beacon's TSF, interval and capability precede the tagged fields.
    return struct.pack("<QHH", 0x0102030405060708, 100, 1) + b"".join(elements)


def rsn(*akms, pairwise=(b"\x00\x0f\xac\x04",)):
    return (
        b"\x01\x00\x00\x0f\xac\x04"
        + struct.pack("<H", len(pairwise))
        + b"".join(pairwise)
        + struct.pack("<H", len(akms))
        + b"".join(akms)
    )


def test_radiotap_all_supported_fields_and_signed_units(wifi):
    payload = struct.pack(
        "<QBBHHBBbb", 0x0102030405060708, 0x10, 108, 5180, 0x140, 3, 9, -47, -92
    )
    packet = radiotap(0x7F, payload)
    assert wifi.FrameParser.parse_radiotap(packet) == {
        "header_len": 26,
        "flags": 0x10,
        "data_rate_mbps": 54.0,
        "freq_mhz": 5180,
        "signal_dbm": -47,
        "noise_dbm": -92,
    }


def test_radiotap_fhss_alignment_does_not_shift_signal_or_noise(wifi):
    # Flags at8; alignment pad at9; FHSS at10..11; dBm fields at12,13.
    packet = radiotap(0x72, b"\x10\x7f\x03\x09\xd1\xa4")
    assert wifi.FrameParser.parse_radiotap(packet) == {
        "header_len": 14,
        "flags": 0x10,
        "signal_dbm": -47,
        "noise_dbm": -92,
    }


def test_radiotap_channel_alignment_and_half_megabit_rate(wifi):
    # One-byte rate makes the channel require a byte of alignment padding.
    packet = radiotap(0x0C, b"\x0b\xff\x6c\x09\xa0\x00")
    assert wifi.FrameParser.parse_radiotap(packet) == {
        "header_len": 14,
        "data_rate_mbps": 5.5,
        "freq_mhz": 2412,
    }


@pytest.mark.parametrize("extensions", [(0,), (0x80000000, 0)])
def test_radiotap_extended_presence_masks_and_tsft_alignment(wifi, extensions):
    # One extension ends at12 (four padding bytes); two end naturally at16.
    padding = b"\x7f" * (4 if len(extensions) == 1 else 0)
    payload = padding + struct.pack("<Qb", 123456, -64)
    packet = radiotap(0x80000021, payload, extensions=extensions)
    assert wifi.FrameParser.parse_radiotap(packet) == {
        "header_len": 25,
        "signal_dbm": -64,
    }


def test_radiotap_ignores_unrecognized_later_fields_without_reading_mac_body(wifi):
    packet = radiotap(1 << 7, b"\x34\x12") + b"not radiotap metadata"
    assert wifi.FrameParser.parse_radiotap(packet) == {"header_len": 10}


@pytest.mark.parametrize(
    "packet",
    [
        b"",
        b"\x00" * 7,
        radiotap(0, length=0),
        radiotap(0, length=7),
        radiotap(0, length=9),
        radiotap(0, version=1),
        radiotap(1 << 31),
        radiotap(1 << 31, length=12),
        radiotap(1 << 31, extensions=(1 << 31,)),
        radiotap(1 << 31, b"\x00\x00", length=10),
    ],
)
def test_invalid_radiotap_envelope_is_rejected_without_out_of_bounds_reads(
    wifi, packet
):
    assert wifi.FrameParser.parse_radiotap(packet) == {"header_len": 0}


@pytest.mark.parametrize(
    "bit,size", [(0, 8), (1, 1), (2, 1), (3, 4), (4, 2), (5, 1), (6, 1)]
)
def test_claimed_radiotap_fields_must_fit_inside_header(wifi, bit, size):
    # Appended MAC bytes must not repair an incomplete declared radiotap field.
    packet = radiotap(1 << bit, b"\x00" * (size - 1)) + b"\xff" * 24
    assert wifi.FrameParser.parse_radiotap(packet) == {"header_len": 0}


@pytest.mark.parametrize("size", [0, 1, 7, 8, 23])
def test_80211_header_requires_all_three_addresses(wifi, size):
    assert wifi.FrameParser.parse_80211(b"\xff" * size) is None


@pytest.mark.parametrize(
    "control,expected_type,subtype,retry",
    [(0x0080, 0, 8, 0), (0x0908, 2, 0, 1)],
)
def test_80211_mac_addresses_frame_type_and_retry_bit(
    wifi, control, expected_type, subtype, retry
):
    # Address bytes intentionally contain zeros, high bits and a broadcast DA.
    packet = struct.pack("<HH", control, 0) + bytes.fromhex(
        "ffffffffffff 021122334455 02aabbccddee 1000"
    )
    assert wifi.FrameParser.parse_80211(packet) == {
        "frame_type": expected_type,
        "frame_subtype": subtype,
        "retry_flag": retry,
        "addr1": bytes.fromhex("ffffffffffff"),
        "addr2": bytes.fromhex("021122334455"),
        "addr3": bytes.fromhex("02aabbccddee"),
    }
    assert wifi.FrameParser.format_mac(packet[10:16]) == "02:11:22:33:44:55"


@pytest.mark.parametrize(
    "packet",
    [
        bytes.fromhex("d4000000 021122334455"),  # ACK: RA only,10 bytes before FCS
        bytes.fromhex("b4000000 021122334455 02aabbccddee"),  # RTS: RA/TA,16 bytes
    ],
)
def test_short_control_frame_layouts_are_explicitly_unsupported(wifi, packet):
    # This parser currently requires the three-address management/data layout.
    # Its type-label helper does not imply support for shorter control frames.
    assert wifi.FrameParser.parse_80211(packet) is None


def test_beacon_utf8_ssid_and_channel_skip_unrelated_elements(wifi):
    body = beacon_body(ie(42, b"\xff"), ie(0, "café".encode()), ie(3, b"\x0b"))
    assert wifi.FrameParser.parse_beacon_ies(body) == {
        "ssid": "café",
        "channel_from_ie": 11,
        "security": "Open",
    }


@pytest.mark.parametrize(
    "ssid,expected",
    [(b"", ""), (b"\xffA\xc3", "�A�"), (b"<script>&amp;", "<script>&amp;")],
)
def test_beacon_ssid_decoding_preserves_data_without_interpreting_markup(
    wifi, ssid, expected
):
    assert (
        wifi.FrameParser.parse_beacon_ies(beacon_body(ie(0, ssid)))["ssid"] == expected
    )


@pytest.mark.parametrize("tail", [b"\x00", b"\x00\x05ab", b"\x03\x00", b"\xdd\x03abc"])
def test_truncated_or_empty_information_elements_do_not_overread(wifi, tail):
    result = wifi.FrameParser.parse_beacon_ies(beacon_body(ie(0, b"valid")) + tail)
    assert result == {"ssid": "valid", "channel_from_ie": 0, "security": "Open"}


@pytest.mark.parametrize("length", [0, 1, 11, 12])
def test_short_beacon_fixed_fields_have_no_elements(wifi, length):
    assert wifi.FrameParser.parse_beacon_ies(b"\x00" * length) == {
        "ssid": "",
        "channel_from_ie": 0,
        "security": "Unknown" if length < 12 else "Open",
    }


@pytest.mark.parametrize(
    "elements,security",
    [
        ((), "Open"),
        ((ie(221, b"\x00\x50\xf2\x01"),), "WPA"),
        ((ie(221, b"\x00\x50\xf2\x02"),), "Open"),
        ((ie(48, rsn(b"\x00\x0f\xac\x02")),), "WPA2"),
        ((ie(48, rsn(b"\x00\x0f\xac\x08")),), "WPA3"),
        ((ie(48, rsn(b"\x01\x0f\xac\x08")),), "WPA2"),
        ((ie(48, rsn(b"\x00\x0f\xac\x02")), ie(221, b"\x00\x50\xf2\x01")), "WPA2/WPA"),
        (
            (
                ie(48, rsn(b"\x00\x0f\xac\x02", b"\x00\x0f\xac\x08")),
                ie(221, b"\x00\x50\xf2\x01"),
            ),
            "WPA3",
        ),
        (
            (
                ie(
                    48,
                    rsn(
                        b"\x00\x0f\xac\x08",
                        pairwise=(b"\x00\x0f\xac\x02", b"\x00\x0f\xac\x04"),
                    ),
                ),
            ),
            "WPA3",
        ),
    ],
)
def test_beacon_security_from_distinct_real_suite_selectors(wifi, elements, security):
    assert (
        wifi.FrameParser.parse_beacon_ies(beacon_body(*elements))["security"]
        == security
    )


@pytest.mark.parametrize(
    "rsn_payload",
    [
        b"",
        b"\x01" * 7,
        b"\x01\x00\x00\x0f\xac\x04\xff\xff",
        rsn()[:-1],
        rsn(b"\x00\x0f\xac\x08")[:-1],
    ],
)
def test_incomplete_rsn_never_reads_sae_from_following_element(wifi, rsn_payload):
    # Preserve the parser's existing RSN-presence classification, but prove
    # missing suite bytes cannot be borrowed from the following SSID element.
    body = beacon_body(ie(48, rsn_payload), ie(0, b"\x00\x0f\xac\x08"))
    assert wifi.FrameParser.parse_beacon_ies(body)["security"] == "WPA2"


@pytest.mark.parametrize(
    "kind,subtype,label",
    [
        (0, 0, "assoc_req"),
        (0, 1, "assoc_resp"),
        (0, 4, "probe_req"),
        (0, 5, "probe_resp"),
        (0, 8, "beacon"),
        (0, 11, "auth"),
        (0, 12, "deauth"),
        (0, 10, "disassoc"),
        (0, 15, "mgmt_0xf"),
        (1, 13, "ctrl"),
        (2, 8, "data"),
        (3, 0, "unknown"),
    ],
)
def test_frame_type_labels(wifi, kind, subtype, label):
    assert wifi.FrameParser.frame_type_label(kind, subtype) == label


@pytest.mark.parametrize(
    "frequency,band",
    [
        (0, "unknown"),
        (2399, "unknown"),
        (2400, "2.4GHz"),
        (2500, "2.4GHz"),
        (2501, "unknown"),
        (5149, "unknown"),
        (5150, "5GHz"),
        (5900, "5GHz"),
        (5901, "unknown"),
        (5924, "unknown"),
        (5925, "6GHz"),
        (7125, "6GHz"),
        (7126, "unknown"),
    ],
)
def test_frequency_band_boundaries(wifi, frequency, band):
    assert wifi.freq_to_band(frequency) == band


@pytest.mark.parametrize(
    "frequency,channel",
    [
        (2412, 1),
        (2462, 11),
        (2467, 12),
        (2472, 13),
        (5180, 36),
        (5250, 50),
        (5825, 165),
        (0, 0),
        (2400, 0),
        (5925, 0),
    ],
)
def test_frequency_channel_known_centers_and_supported_fallbacks(
    wifi, frequency, channel
):
    assert wifi.freq_to_channel(frequency) == channel


@pytest.mark.parametrize(
    "control,addresses,kind,bssid,client",
    [
        (
            0x0040,
            "ffffffffffff 021122334455 ffffffffffff",
            "probe_req",
            "ff:ff:ff:ff:ff:ff",
            "02:11:22:33:44:55",
        ),
        (
            0x0000,
            "02aabbccddee 021122334455 02aabbccddee",
            "assoc_req",
            "02:aa:bb:cc:dd:ee",
            "02:11:22:33:44:55",
        ),
        (
            0x0908,
            "02aabbccddee 021122334455 021234567890",
            "data",
            "02:aa:bb:cc:dd:ee",
            "02:11:22:33:44:55",
        ),
        (
            0x0A08,
            "021122334455 02aabbccddee 021234567890",
            "data",
            "02:aa:bb:cc:dd:ee",
            "02:11:22:33:44:55",
        ),
    ],
)
def test_parser_outputs_feed_scanner_client_metadata_without_capture(
    wifi, control, addresses, kind, bssid, client
):
    # Construction does not enable an interface. The consumer receives exactly
    # the packet bytes; there is no mocked metadata or radio/capture process.
    scanner = wifi.WifiScanner("unused-test-interface")
    mac = struct.pack("<HH", control, 0) + bytes.fromhex(addresses) + b"\x10\x00"
    packet = radiotap(0x28, struct.pack("<HHb", 2412, 0xA0, -59)) + mac
    observation = scanner._parse_packet(packet)
    assert observation is not None
    assert {
        key: observation[key]
        for key in (
            "frame_type",
            "bssid",
            "client_mac",
            "channel",
            "band",
            "signal_dbm",
            "retry_flag",
        )
    } == {
        "frame_type": kind,
        "bssid": bssid,
        "client_mac": client,
        "channel": 1,
        "band": "2.4GHz",
        "signal_dbm": -59,
        "retry_flag": int(kind == "data"),
    }


def test_scanner_discards_invalid_radiotap_without_consuming_mac_as_metadata(wifi):
    scanner = wifi.WifiScanner("unused-test-interface")
    # The advertised extension cannot fit in the radiotap header; following
    # MAC bytes are not an extension, even though the packet itself is long.
    packet = radiotap(1 << 31) + b"\x00" * 24
    assert scanner._parse_packet(packet) is None


def test_scanner_beacon_observation_uses_parsed_ssid_security_and_channel(wifi):
    scanner = wifi.WifiScanner("unused-test-interface")
    mac = bytes.fromhex("80000000 ffffffffffff 02aabbccddee 02aabbccddee 1000")
    body = beacon_body(
        ie(0, b"test-network"), ie(3, b"\x06"), ie(48, rsn(b"\x00\x0f\xac\x08"))
    )
    observation = scanner._parse_packet(
        radiotap(0x28, struct.pack("<HHb", 2437, 0xA0, -42)) + mac + body
    )
    assert observation is not None
    assert {
        key: observation[key]
        for key in ("ssid", "security", "channel", "bssid", "client_mac", "frame_type")
    } == {
        "ssid": "test-network",
        "security": "WPA3",
        "channel": 6,
        "bssid": "02:aa:bb:cc:dd:ee",
        "client_mac": "",
        "frame_type": "beacon",
    }
