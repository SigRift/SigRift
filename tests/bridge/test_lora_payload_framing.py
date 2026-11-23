"""Regression tests: LoRa demodulator honours the header payload length/CRC.

``decode_payload`` returns every byte the symbols carry (payload, CRC and
block padding).  Before the fix ``demodulate_and_decode`` handed all of it
to the strict Meshtastic ``Data`` parser, so valid frames failed.
"""

import struct

import numpy as np
import pytest

from sigrift.lib.dsp import lora_demodulator as ld


def _crc16_ccitt(data: bytes) -> int:
    """Independent CRC-16/CCITT (poly 0x1021, init 0x0000), MSB first."""
    crc = 0
    for byte in data:
        for bit in range(7, -1, -1):
            top = (crc >> 15) & 1
            crc = (crc << 1) & 0xFFFF
            if top ^ ((byte >> bit) & 1):
                crc ^= 0x1021
    return crc


def _cleartext_channel_hash() -> int:
    for h in range(256):
        if h not in ld._MESHTASTIC_DEFAULT_KEYS:
            return h
    raise AssertionError("no free channel hash")


def _meshtastic_frame() -> bytes:
    header = struct.pack("<III", 0xFFFFFFFF, 0xCAFEBABE, 4242)
    header += bytes([0x03, _cleartext_channel_hash(), 0x00, 0x00])
    text = b"hi there"
    data = b"\x08\x01\x12" + bytes([len(text)]) + text  # Data{portnum=1}
    return header + data


def _run(monkeypatch, decoded: bytes, payload_len: int, has_crc: bool):
    monkeypatch.setattr(ld, "dechirp", lambda *a, **k: np.zeros(16, np.int32))
    monkeypatch.setattr(
        ld,
        "extract_header",
        lambda s: {
            "sync_word": 0x12,
            "cr": 1,
            "has_crc": has_crc,
            "payload_len": payload_len,
        },
    )
    monkeypatch.setattr(ld, "decode_payload", lambda s, cr: decoded)
    return ld.demodulate_and_decode(np.zeros(1), sf=7, bw=125e3, fs=250e3)


def test_payload_trimmed_and_crc_checked(monkeypatch):
    frame = _meshtastic_frame()
    crc = _crc16_ccitt(frame)
    decoded = frame + bytes([crc >> 8, crc & 0xFF]) + b"\x00\x00\x00"
    result = _run(monkeypatch, decoded, len(frame), True)
    assert result.rf_params["crc_ok"] is True
    assert result.encryption_status == "cleartext"
    assert result.port_num == 1
    assert result.decoded_text == "hi there"
    assert result.source_node_id == "!cafebabe"


def test_payload_trimmed_without_crc(monkeypatch):
    frame = _meshtastic_frame()
    result = _run(monkeypatch, frame + b"\x00\x00", len(frame), False)
    assert result.rf_params["crc_ok"] is None
    assert result.decoded_text == "hi there"


@pytest.mark.parametrize("flip", [0, 5, 20])
def test_crc_mismatch_drops_frame(monkeypatch, flip):
    frame = bytearray(_meshtastic_frame())
    crc = _crc16_ccitt(bytes(frame))
    frame[flip] ^= 0x01
    decoded = bytes(frame) + bytes([crc >> 8, crc & 0xFF])
    result = _run(monkeypatch, decoded, len(frame), True)
    assert result.rf_params["crc_ok"] is False
    assert result.encryption_status == "unknown"
    assert result.port_num is None
    assert result.source_node_id is None


def test_truncated_frame_dropped(monkeypatch):
    frame = _meshtastic_frame()
    result = _run(monkeypatch, frame[:10], len(frame), True)
    assert result.rf_params["crc_ok"] is False
    assert result.source_node_id is None
