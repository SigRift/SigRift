"""Synthetic radiotap/FCS boundaries; no radio, capture, or interface access.

Flags semantics: https://radiotap.org/fields/Flags.html (0x10 includes FCS,
0x40 reports a failed FCS check). The fixed CRC-valid frame was constructed
independently of the scanner; zlib is an independent CRC oracle in tests only.
"""

from __future__ import annotations

import gzip
import importlib
import io
import struct
import sys
from types import SimpleNamespace
from unittest.mock import patch
import zlib

import pytest


FRAME = bytes.fromhex(
    "80000000ffffffffffff02aabbccddee02aabbccddee1000"
    "080706050403020164000100000c746573742d6e6574776f726b030106"
    "dd080011223397ad0000"
)
FCS = bytes.fromhex("0002abf7")


@pytest.fixture(scope="module")
def wifi():
    name = "sigrift.edge.wifi_scan"
    if name in sys.modules:
        return sys.modules[name]
    # Scanner import configures a file logger; keep this byte-only test free
    # of /opt/rf-edge writes without replacing any parser or CRC operation.
    with patch("pathlib.Path.mkdir", side_effect=PermissionError):
        return importlib.import_module(name)


def packet(frame, flags=None):
    if flags is None:
        return bytes.fromhex("0000080000000000") + frame
    return bytes.fromhex("0000090002000000") + bytes((flags,)) + frame


def test_crc_valid_fcs_cannot_overwrite_the_real_ssid(wifi):
    assert zlib.crc32(FRAME).to_bytes(4, "little") == FCS
    # Its first two bytes resemble a second SSID element of length two.
    assert FCS[:2] == b"\x00\x02"
    raw = packet(FRAME + FCS, 0x10)
    scanner = wifi.WifiScanner("unused-test-interface")
    observed = scanner._parse_packet(raw)
    assert observed is not None
    assert observed["ssid"] == "test-network"
    assert observed["channel"] == 6
    assert observed["bssid"] == "02:aa:bb:cc:dd:ee"
    assert raw == bytes.fromhex("000009000200000010") + FRAME + FCS


@pytest.mark.parametrize("flags", [None, 0, 1, 2, 4, 8, 0x80])
def test_other_or_absent_flags_preserve_the_last_four_payload_bytes(wifi, flags):
    # The final four bytes are a complete, legitimate SSID IE, not an FCS.
    frame = FRAME[:36] + b"\x00\x02AB"
    observed = wifi.WifiScanner("unused-test-interface")._parse_packet(
        packet(frame, flags)
    )
    assert observed is not None
    assert observed["ssid"] == "AB"


def test_included_fcs_removes_exactly_four_bytes_after_final_payload_ie(wifi):
    frame = FRAME[:36] + b"\x00\x02AB"
    crc = zlib.crc32(frame).to_bytes(4, "little")
    observed = wifi.WifiScanner("unused-test-interface")._parse_packet(
        packet(frame + crc, 0x10)
    )
    assert observed is not None
    assert observed["ssid"] == "AB"


@pytest.mark.parametrize("flags", [0x40, 0x50, 0xD0])
def test_driver_reported_failed_fcs_is_rejected_even_for_valid_bytes(wifi, flags):
    assert zlib.crc32(FRAME).to_bytes(4, "little") == FCS
    assert (
        wifi.WifiScanner("unused-test-interface")._parse_packet(
            packet(FRAME + FCS, flags)
        )
        is None
    )


@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 23, 24, 25, 26, 27])
def test_short_flagged_frames_cannot_borrow_fcs_bytes_for_mac_header(wifi, size):
    assert (
        wifi.WifiScanner("unused-test-interface")._parse_packet(
            packet((FRAME[:24] + FCS)[:size], 0x10)
        )
        is None
    )


def test_minimum_three_address_header_is_accepted_after_fcs_removal(wifi):
    # Existing parser supports this 24-byte management header without IEs.
    frame = FRAME[:24]
    crc = zlib.crc32(frame).to_bytes(4, "little")
    scanner = wifi.WifiScanner("unused-test-interface")
    expected = scanner._parse_packet(packet(frame))
    assert expected is not None
    assert scanner._parse_packet(packet(frame + crc, 0x10)) == expected


def test_included_fcs_does_not_introduce_an_unrequested_crc_validator(wifi):
    # Driver flags, rather than a new software CRC implementation, decide
    # rejection in this bounded parser fix.
    assert zlib.crc32(FRAME) != 0
    result = wifi.WifiScanner("unused-test-interface")._parse_packet(
        packet(FRAME + b"\x00" * 4, 0x10)
    )
    assert result is not None
    assert result["ssid"] == "test-network"


@pytest.mark.parametrize("flags,observations", [(0x10, 1), (0x50, 0)])
def test_pcap_ring_retains_original_flags_and_fcs_even_for_rejected_frames(
    wifi, flags, observations
):
    raw = packet(FRAME + FCS, flags)
    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127)
    record_header = struct.pack("<IIII", 17, 123, len(raw), len(raw))
    stream = global_header + record_header + raw
    scanner = wifi.WifiScanner("unused-test-interface")
    scanner._proc = SimpleNamespace(stdout=io.BytesIO(stream))
    scanner._running = True
    result = list(scanner.read_frames())
    assert len(result) == observations
    if result:
        assert result[0]["ssid"] == "test-network"
    assert list(scanner._pcap_ring) == [(17_000_123, raw)]
    assert gzip.decompress(scanner.drain_pcap_ring()) == stream
