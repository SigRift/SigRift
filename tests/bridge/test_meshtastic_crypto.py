"""Meshtastic crypto + decoding tests against the firmware wire format.

Covers the three decoders that handle Meshtastic packets:

* ``sigrift.lib.crypto.aes_decrypt``    (nonce, trial decryption)
* ``sigrift.lib.protocol.meshtastic``   (MeshtasticDecoder)
* ``sigrift.lib.dsp.lora_demodulator``  (post-PHY Meshtastic layer)

Reference: firmware ``CryptoEngine::initNonce`` -- the 16-byte AES-CTR nonce
is ``packetId`` as a little-endian uint64 (bytes 0-7), ``fromNode`` as a
little-endian uint32 (bytes 8-11), and zeros (bytes 12-15).  The payload
after the 16-byte radio header is an encrypted ``Data`` protobuf
(mesh.proto) whose ``portnum`` selects the inner payload type.  The test
packets are built here with an independent protobuf encoder.
"""

from __future__ import annotations

import os
import random
import struct

import numpy as np
import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

from sigrift.lib.crypto.aes_decrypt import (  # noqa: E402
    build_meshtastic_nonce,
    decrypt_meshtastic,
    try_decrypt,
)
from sigrift.lib.crypto.key_store import KeyStore  # noqa: E402
from sigrift.lib.dsp import lora_demodulator as ld  # noqa: E402
from sigrift.lib.protocol.base import DecodedPacket, DecodeError  # noqa: E402
from sigrift.lib.protocol.meshtastic import (  # noqa: E402
    MeshtasticDecoder,
    _parse_protobuf_fields,
    parse_data_message,
)

# Default channel PSK -- expansion of the one-byte PSK "AQ==".
DEFAULT_PSK = bytes.fromhex("d4f1bb3a20290759f0bcffabcf4e6901")
LONGFAST_HASH = 0x08  # xorHash("LongFast") ^ xorHash(DEFAULT_PSK)

POSITION_APP = 3
TEXT_MESSAGE_APP = 1
NODEINFO_APP = 4
TELEMETRY_APP = 67


# ---------------------------------------------------------------------------
# Independent protobuf / packet builders
# ---------------------------------------------------------------------------


def _varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64  # int32/int64 negatives: 10-byte two's complement
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field: int, wire_type: int) -> bytes:
    return _varint((field << 3) | wire_type)


def pb_varint(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def pb_bytes(field: int, value: bytes) -> bytes:
    return _tag(field, 2) + _varint(len(value)) + value


def pb_fixed32(field: int, value: int) -> bytes:
    return _tag(field, 5) + struct.pack("<I", value & 0xFFFFFFFF)


def pb_sfixed32(field: int, value: int) -> bytes:
    return _tag(field, 5) + struct.pack("<i", value)


def encode_position(lat_i: int, lon_i: int, altitude: int, time: int) -> bytes:
    """mesh.proto Position: sfixed32 lat/lon (1,2), int32 altitude (3), fixed32 time (4)."""
    return (
        pb_sfixed32(1, lat_i)
        + pb_sfixed32(2, lon_i)
        + pb_varint(3, altitude)
        + pb_fixed32(4, time)
    )


def encode_data(portnum: int, payload: bytes, **extra: int) -> bytes:
    """mesh.proto Data: portnum (1, varint), payload (2, bytes), ..."""
    msg = pb_varint(1, portnum) + pb_bytes(2, payload)
    if "want_response" in extra:
        msg += pb_varint(3, extra["want_response"])
    if "request_id" in extra:
        msg += pb_fixed32(6, extra["request_id"])
    if "bitfield" in extra:
        msg += pb_varint(9, extra["bitfield"])
    return msg


def firmware_nonce(packet_id: int, from_node: int) -> bytes:
    """Re-implementation of CryptoEngine::initNonce for the tests."""
    nonce = bytearray(16)
    nonce[0:8] = packet_id.to_bytes(8, "little")
    nonce[8:12] = from_node.to_bytes(4, "little")
    return bytes(nonce)


def aes_ctr(key: bytes, nonce: bytes, data: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def build_packet(
    data: bytes,
    *,
    key: bytes = DEFAULT_PSK,
    dest: int = 0xFFFFFFFF,
    source: int = 0x1234ABCD,
    packet_id: int = 0x5EED1234,
    channel_hash: int = LONGFAST_HASH,
    flags: int = 0x63,  # hop_start=3, hop_limit=3
) -> bytes:
    header = struct.pack("<III", dest, source, packet_id) + bytes(
        [flags, channel_hash, 0, 0]
    )
    return header + aes_ctr(key, firmware_nonce(packet_id, source), data)


# Golden Position (Amsterdam-ish, below sea level to exercise negative int32)
LAT_I = 523_676_000
LON_I = 49_041_000
ALT_M = -4
GPS_TIME = 1_762_300_800
POSITION_PB = encode_position(LAT_I, LON_I, ALT_M, GPS_TIME)
POSITION_DATA = encode_data(POSITION_APP, POSITION_PB)


# ---------------------------------------------------------------------------
# Nonce
# ---------------------------------------------------------------------------


class TestNonceLayout:
    @pytest.mark.parametrize(
        ("packet_id", "from_node"),
        [(0x12345678, 0xCAFEBABE), (1, 2), (0xFFFFFFFF, 0xFFFFFFFF), (0, 0)],
    )
    def test_matches_firmware_init_nonce(self, packet_id: int, from_node: int) -> None:
        assert build_meshtastic_nonce(packet_id, from_node) == firmware_nonce(
            packet_id, from_node
        )

    def test_explicit_bytes(self) -> None:
        nonce = build_meshtastic_nonce(0x12345678, 0xCAFEBABE)
        assert len(nonce) == 16
        assert nonce == bytes.fromhex("7856341200000000bebafeca00000000")

    def test_decrypt_meshtastic_reports_nonce(self) -> None:
        result = decrypt_meshtastic(b"\x00" * 8, DEFAULT_PSK, 0x12345678, 0xCAFEBABE)
        assert result.nonce_hex == "7856341200000000bebafeca00000000"


# ---------------------------------------------------------------------------
# Golden packet round-trips
# ---------------------------------------------------------------------------


class TestGoldenPositionPacket:
    def test_meshtastic_decoder_recovers_position(self) -> None:
        raw = build_packet(POSITION_DATA)
        dec = MeshtasticDecoder()
        pkt = dec.decode_packet(raw)
        assert pkt.metadata["decrypted"] is True
        assert pkt.payload == POSITION_DATA
        assert pkt.errors == []

        msgs = dec.extract_messages(pkt)
        assert len(msgs) == 1
        msg = msgs[0]
        assert msg.message_type == "POSITION"
        assert msg.source_id == "!1234abcd"
        assert msg.dest_id == "!ffffffff"
        assert msg.decrypted is True
        assert msg.gps_lat == pytest.approx(LAT_I / 1e7)
        assert msg.gps_lon == pytest.approx(LON_I / 1e7)
        assert msg.gps_alt == ALT_M
        assert msg.metadata["gps_time"] == GPS_TIME
        assert msg.metadata["portnum"] == POSITION_APP
        assert msg.metadata["hop_limit"] == 3

    def test_aes_decrypt_module_recovers_data(self) -> None:
        raw = build_packet(POSITION_DATA)
        result = decrypt_meshtastic(raw[16:], DEFAULT_PSK, 0x5EED1234, 0x1234ABCD)
        assert result.error is None
        assert result.plaintext == POSITION_DATA
        assert result.confidence > 0.5
        assert result.algorithm == "aes-128-ctr"

    def test_lora_layer_recovers_position(self) -> None:
        raw = build_packet(POSITION_DATA)
        decrypted = ld.try_decrypt_meshtastic(
            raw[16:], LONGFAST_HASH, packet_id=0x5EED1234, source_node=0x1234ABCD
        )
        assert decrypted == POSITION_DATA
        data = parse_data_message(decrypted)
        assert data is not None and data["portnum"] == POSITION_APP
        pos = ld.decode_meshtastic_protobuf(data["payload"], data["portnum"])[
            "position"
        ]
        assert pos["lat"] == pytest.approx(LAT_I / 1e7)
        assert pos["lon"] == pytest.approx(LON_I / 1e7)
        assert pos["altitude"] == ALT_M
        assert pos["time"] == GPS_TIME

    def test_demodulate_and_decode_dispatches_on_data_portnum(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Post-PHY pipeline: portnum comes from the decrypted Data, not byte 14."""
        # Header byte 14 (next_hop) deliberately set to TEXT_MESSAGE_APP's value.
        raw = bytearray(build_packet(POSITION_DATA))
        raw[14] = TEXT_MESSAGE_APP
        monkeypatch.setattr(ld, "dechirp", lambda *a, **k: np.zeros(16, dtype=np.int32))
        # The real extract_header always returns payload_len/has_crc, and
        # demodulate_and_decode now cuts the payload to payload_len.
        monkeypatch.setattr(
            ld,
            "extract_header",
            lambda s: {
                "sync_word": 0x12,
                "cr": 1,
                "payload_len": len(raw),
                "has_crc": False,
            },
        )
        monkeypatch.setattr(ld, "decode_payload", lambda s, cr: bytes(raw))

        result = ld.demodulate_and_decode(np.zeros(1), sf=7, bw=125e3, fs=250e3)
        assert result is not None
        assert result.protocol == "meshtastic"
        assert result.encryption_status == "default_key"
        assert result.port_num == POSITION_APP
        assert result.source_node_id == "!1234abcd"
        assert result.decoded_position["lat"] == pytest.approx(LAT_I / 1e7)
        assert result.decoded_position["altitude"] == ALT_M
        assert result.decoded_text is None

    def test_demodulate_and_decode_custom_key_not_decoded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = build_packet(POSITION_DATA, key=os.urandom(16))
        monkeypatch.setattr(ld, "dechirp", lambda *a, **k: np.zeros(16, dtype=np.int32))
        # The real extract_header always returns payload_len/has_crc, and
        # demodulate_and_decode now cuts the payload to payload_len.
        monkeypatch.setattr(
            ld,
            "extract_header",
            lambda s: {
                "sync_word": 0x12,
                "cr": 1,
                "payload_len": len(raw),
                "has_crc": False,
            },
        )
        monkeypatch.setattr(ld, "decode_payload", lambda s, cr: raw)
        result = ld.demodulate_and_decode(np.zeros(1), sf=7, bw=125e3, fs=250e3)
        assert result is not None
        assert result.encryption_status == "custom_encrypted"
        assert result.port_num is None
        assert result.decoded_position is None

    def test_text_message_roundtrip(self) -> None:
        raw = build_packet(encode_data(TEXT_MESSAGE_APP, "héllo mesh".encode()))
        dec = MeshtasticDecoder()
        msg = dec.extract_messages(dec.decode_packet(raw))[0]
        assert msg.message_type == "TEXT_MESSAGE"
        assert msg.text == "héllo mesh"

    def test_aes256_key(self) -> None:
        key = bytes(range(32))
        raw = build_packet(POSITION_DATA, key=key, channel_hash=0x42)
        dec = MeshtasticDecoder(keys=[DEFAULT_PSK, key])
        pkt = dec.decode_packet(raw)
        assert pkt.metadata["decrypted"] is True
        assert pkt.payload == POSITION_DATA
        result = decrypt_meshtastic(raw[16:], key, 0x5EED1234, 0x1234ABCD)
        assert result.algorithm == "aes-256-ctr"
        assert result.plaintext == POSITION_DATA

    def test_key_store_default_key_matches(self) -> None:
        ks = KeyStore()
        ks.load_builtin_defaults()
        keys = [
            (bytes(k.key_material), k.key_id)
            for k in ks.lookup_by_protocol("meshtastic")
        ]
        raw = build_packet(POSITION_DATA)
        result = try_decrypt(
            raw[16:], "meshtastic", keys, packet_id=0x5EED1234, source_node=0x1234ABCD
        )
        assert result is not None
        assert result.plaintext == POSITION_DATA


# ---------------------------------------------------------------------------
# Trial decryption must reject wrong keys
# ---------------------------------------------------------------------------


def _random_data_message(rng: random.Random) -> bytes:
    portnum = rng.choice([TEXT_MESSAGE_APP, POSITION_APP, NODEINFO_APP, TELEMETRY_APP])
    payload = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 200)))
    extra = {}
    if rng.random() < 0.3:
        extra["want_response"] = 1
    if rng.random() < 0.3:
        extra["request_id"] = rng.getrandbits(32)
    if rng.random() < 0.3:
        extra["bitfield"] = rng.getrandbits(3)
    return encode_data(portnum, payload, **extra)


class TestWrongKeyRejection:
    N_PACKETS = 2000

    def test_wrong_keys_never_accepted(self) -> None:
        rng = random.Random(0xC0FFEE)
        wrong_keys = [bytes(rng.getrandbits(8) for _ in range(16)) for _ in range(5)]
        assert DEFAULT_PSK not in wrong_keys
        keyed = [(k, f"wrong-{i}") for i, k in enumerate(wrong_keys)]

        false_pos_payload = 0
        false_pos_try = 0
        for _ in range(self.N_PACKETS):
            data = _random_data_message(rng)
            pkt_id = rng.getrandbits(32)
            src = rng.getrandbits(32)
            ct = aes_ctr(DEFAULT_PSK, firmware_nonce(pkt_id, src), data)
            if (
                MeshtasticDecoder.decrypt_payload(ct, pkt_id, src, wrong_keys)
                is not None
            ):
                false_pos_payload += 1
            if try_decrypt(ct, "meshtastic", keyed, packet_id=pkt_id, source_node=src):
                false_pos_try += 1
            # Sanity: the right key is accepted for the same packet.
            assert (
                MeshtasticDecoder.decrypt_payload(ct, pkt_id, src, [DEFAULT_PSK])
                == data
            )

        assert false_pos_payload == 0
        assert false_pos_try == 0

    def test_random_ciphertext_rejected_by_default_key(self) -> None:
        rng = random.Random(1234)
        accepted = 0
        for _ in range(self.N_PACKETS):
            ct = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 230)))
            if MeshtasticDecoder.decrypt_payload(ct, 1, 2, [DEFAULT_PSK]) is not None:
                accepted += 1
            if ld.try_decrypt_meshtastic(ct, LONGFAST_HASH, 1, 2) is not None:
                accepted += 1
        assert accepted == 0

    def test_decode_packet_wrong_key_reports_failure(self) -> None:
        raw = build_packet(POSITION_DATA, key=os.urandom(16))
        dec = MeshtasticDecoder()
        pkt = dec.decode_packet(raw)
        assert pkt.metadata["decrypted"] is False
        assert "decryption failed or no matching key" in pkt.errors
        msgs = dec.extract_messages(pkt)
        assert len(msgs) == 1
        assert msgs[0].message_type == "raw"
        assert msgs[0].gps_lat is None
        # nonce inputs are surfaced so downstream trial decryption can work
        assert msgs[0].metadata["packet_id"] == 0x5EED1234
        assert msgs[0].metadata["source_node"] == 0x1234ABCD


class TestParseDataMessage:
    def test_valid(self) -> None:
        data = parse_data_message(encode_data(POSITION_APP, b"\x01\x02", request_id=7))
        assert data is not None
        assert data["portnum"] == POSITION_APP
        assert data["payload"] == b"\x01\x02"
        assert data["request_id"] == 7

    @pytest.mark.parametrize(
        "blob",
        [
            b"",
            pb_bytes(2, b"abc"),  # portnum missing
            pb_varint(1, 0) + pb_bytes(2, b"x"),  # UNKNOWN_APP
            pb_varint(1, 512) + pb_bytes(2, b"x"),  # beyond PortNum.MAX
            pb_varint(1, 3) + pb_bytes(2, b"abc") + b"\x00",  # trailing byte
            pb_varint(1, 3) + _tag(2, 2) + _varint(10) + b"abc",  # overrun
            pb_varint(1, 3) + _tag(2, 0) + _varint(5),  # wrong wire type
            pb_varint(1, 3) + pb_varint(12, 1),  # not a Data field
            pb_varint(1, 3) + b"\x10\xff",  # truncated varint
            b"\x08" + b"\xff" * 11,  # over-long varint
            pb_varint(1, 3) + b"\x0b",  # start-group wire type
        ],
    )
    def test_rejects_malformed(self, blob: bytes) -> None:
        assert parse_data_message(blob) is None


# ---------------------------------------------------------------------------
# Position / NodeInfo wire types
# ---------------------------------------------------------------------------


class TestPayloadWireTypes:
    def test_position_negative_coordinates(self) -> None:
        pos = MeshtasticDecoder.extract_position(
            encode_position(-338_688_000, -1_512_093_000, -120, 0xFFFFFFF0)
        )
        assert pos["latitude"] == pytest.approx(-33.8688)
        assert pos["longitude"] == pytest.approx(-151.2093)
        assert pos["altitude"] == -120
        assert pos["time"] == 0xFFFFFFF0  # fixed32 is unsigned

    def test_position_ignores_wrong_wire_type(self) -> None:
        # A zigzag varint latitude is NOT the firmware encoding -> ignored.
        pos = MeshtasticDecoder.extract_position(pb_varint(1, 1045352000))
        assert pos["latitude"] is None

    def test_nodeinfo_hw_model_is_field_5(self) -> None:
        user = (
            pb_bytes(1, b"!1234abcd")
            + pb_bytes(2, b"Base Station")
            + pb_bytes(3, b"BS")
            + pb_varint(5, 43)  # hw_model = HELTEC_V3
            + pb_varint(6, 1)  # is_licensed
        )
        info = MeshtasticDecoder.extract_nodeinfo(user)
        assert info == {
            "id": "!1234abcd",
            "long_name": "Base Station",
            "short_name": "BS",
            "hw_model": 43,
        }

    def test_telemetry_device_metrics(self) -> None:
        metrics = (
            pb_varint(1, 87)
            + _tag(2, 5)
            + struct.pack("<f", 4.12)
            + _tag(3, 5)
            + struct.pack("<f", 12.5)
        )
        telem = pb_fixed32(1, GPS_TIME) + pb_bytes(2, metrics)
        out = ld.decode_meshtastic_protobuf(telem, TELEMETRY_APP)["telemetry"]
        assert out == {"battery_level": 87, "voltage": 4.12, "channel_util": 12.5}


# ---------------------------------------------------------------------------
# Malformed input must never crash
# ---------------------------------------------------------------------------

_BAD_INNER = [
    b"\xff",
    b"\x08\xff",
    b"\x08" + b"\xff" * 12,
    b"\x12\x7f",
    b"\x0b\x0c",
    b"\x0d\x01",
    b"\x00\x00\x00",
    b"\x15",
]


class TestMalformedInput:
    def test_lenient_parser_never_raises(self) -> None:
        for blob in _BAD_INNER:
            assert isinstance(_parse_protobuf_fields(blob), list)

    def test_strict_parser_raises_decode_error(self) -> None:
        for blob in _BAD_INNER:
            with pytest.raises(DecodeError):
                _parse_protobuf_fields(blob, strict=True)

    @pytest.mark.parametrize(
        "portnum", [TEXT_MESSAGE_APP, POSITION_APP, NODEINFO_APP, TELEMETRY_APP]
    )
    @pytest.mark.parametrize("inner", _BAD_INNER)
    def test_bad_inner_payload_does_not_crash(self, portnum: int, inner: bytes) -> None:
        dec = MeshtasticDecoder()
        pkt = dec.decode_packet(build_packet(encode_data(portnum, inner)))
        assert pkt.metadata["decrypted"] is True
        msgs = dec.extract_messages(pkt)
        assert len(msgs) == 1
        assert ld.decode_meshtastic_protobuf(inner, portnum) is not None

    def test_random_payloads_never_crash_extract_messages(self) -> None:
        rng = random.Random(42)
        dec = MeshtasticDecoder()
        for i in range(3000):
            blob = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 64)))
            if i % 2:
                # Random bytes wrapped in a valid Data so the extractors run.
                blob = encode_data(rng.choice([1, 3, 4, 67]), blob)
            pkt = DecodedPacket(
                protocol="meshtastic",
                raw_bytes=b"",
                payload=blob,
                metadata={
                    "mac": {"source": 1, "dest": 2, "packet_id": 3},
                    "decrypted": True,
                },
            )
            msgs = dec.extract_messages(pkt)
            assert len(msgs) == 1
            for port in (1, 3, 4, 67):
                assert isinstance(ld.decode_meshtastic_protobuf(blob, port), dict)
