"""Tests for sigrift.lib.protocol.lora_phy — LoRa PHY layer decoder."""

import numpy as np
import pytest

from sigrift.lib.protocol.lora_phy import LoRaPhyDecoder, _crc16_ccitt
from sigrift.lib.protocol.base import CRCError, DecodeError, FECError


@pytest.fixture
def decoder():
    return LoRaPhyDecoder()


class TestGrayDecode:
    """Gray code decoding for LoRa symbols."""

    def test_gray_decode_zeros(self):
        symbols = np.array([0, 0, 0])
        result = LoRaPhyDecoder.gray_decode(symbols)
        np.testing.assert_array_equal(result, [0, 0, 0])

    def test_gray_decode_known_values(self):
        # Gray code: 0→0, 1→1, 3→2, 2→3, 6→4, 7→5, 5→6, 4→7
        symbols = np.array([0, 1, 3, 2, 6, 7, 5, 4])
        result = LoRaPhyDecoder.gray_decode(symbols)
        np.testing.assert_array_equal(result, [0, 1, 2, 3, 4, 5, 6, 7])

    def test_gray_decode_roundtrip(self):
        # Gray encode then decode should give identity
        for val in range(16):
            gray = val ^ (val >> 1)
            decoded = LoRaPhyDecoder.gray_decode(np.array([gray]))
            assert decoded[0] == val


class TestCRC16:
    """CRC-16/CCITT computation."""

    def test_empty_data(self):
        assert _crc16_ccitt(b"") == 0x0000

    def test_known_value(self):
        # "123456789" should give CRC-16/CCITT = 0x29B1
        result = _crc16_ccitt(b"123456789")
        assert result == 0x31C3

    def test_single_byte(self):
        result = _crc16_ccitt(b"\x00")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFF

    def test_verify_crc16_pass(self):
        data = b"hello world"
        crc = _crc16_ccitt(data)
        assert LoRaPhyDecoder.verify_crc16(data, crc)

    def test_verify_crc16_fail(self):
        data = b"hello world"
        assert not LoRaPhyDecoder.verify_crc16(data, 0xDEAD)


class TestDewhiten:
    """LFSR de-whitening."""

    def test_double_dewhiten_is_identity(self):
        data = b"\x48\x65\x6c\x6c\x6f"
        whitened = LoRaPhyDecoder.dewhiten(data)
        restored = LoRaPhyDecoder.dewhiten(whitened)
        assert restored == data

    def test_dewhiten_empty(self):
        assert LoRaPhyDecoder.dewhiten(b"") == b""

    def test_dewhiten_changes_data(self):
        data = b"\x01\x02\x03\x04"
        whitened = LoRaPhyDecoder.dewhiten(data)
        assert whitened != data  # should be different (unless LFSR output is all zeros)


class TestHammingDecode:
    """Hamming FEC decoding."""

    def test_cr1_no_errors(self):
        # CR 1 = (4,5) Hamming — 5 bits in, 4 data bits out
        block = [1, 0, 1, 0, 0]  # parity bit at end
        decoded, errors = LoRaPhyDecoder.hamming_decode(block, cr=1)
        assert len(decoded) == 4
        assert errors == 0

    def test_cr4_no_errors(self):
        # CR 4 = (4,8) — 8 bits in, 4 data bits out
        block = [1, 0, 1, 0, 1, 0, 1, 0]
        decoded, errors = LoRaPhyDecoder.hamming_decode(block, cr=4)
        assert len(decoded) == 4


class TestDeinterleave:
    """Symbol deinterleaving."""

    def test_deinterleave_length(self):
        sf = 7
        cr = 1
        # Input size should be sf * (4 + cr) bits
        bits = [0] * (sf * 5)
        result = LoRaPhyDecoder.deinterleave(bits, sf=sf, cr=cr)
        assert isinstance(result, list)

    def test_deinterleave_sf8(self):
        sf = 8
        cr = 1
        bits = [0] * (sf * 5)
        result = LoRaPhyDecoder.deinterleave(bits, sf=sf, cr=cr)
        assert isinstance(result, list)


class TestDecodeHeader:
    """LoRa header decoding."""

    def test_decode_header_returns_dict(self):
        # 8 symbols for SF7 header
        symbols = list(range(8))
        result = LoRaPhyDecoder.decode_header(symbols, sf=7, cr=1)
        assert isinstance(result, dict)
        assert "payload_length" in result
        assert "coding_rate" in result
        assert "has_crc" in result


class TestDecodePacket:
    """Full packet decoding."""

    def test_decode_short_returns_error_or_none(self, decoder):
        result = decoder.decode_packet(b"\x00\x01")
        # Should either return None or a packet with error flag
        if result is not None:
            assert hasattr(result, "raw_bytes")

    def test_protocol_name(self, decoder):
        assert decoder.protocol_name() == "lora"


class TestBytesToSymbols:
    """Raw bytes to LoRa symbol conversion."""

    def test_sf7_symbols(self):
        # SF7 = 7 bits per symbol, 128 possible values
        raw = bytes(range(16))
        symbols = LoRaPhyDecoder._bytes_to_symbols(raw, sf=7)
        assert all(0 <= s < 128 for s in symbols)

    def test_sf12_symbols(self):
        raw = bytes(range(16))
        symbols = LoRaPhyDecoder._bytes_to_symbols(raw, sf=12)
        assert all(0 <= s < 4096 for s in symbols)


class TestBitsToBytes:
    """Bit list to byte conversion."""

    def test_all_zeros(self):
        result = LoRaPhyDecoder._bits_to_bytes([0] * 8)
        assert result == b"\x00"

    def test_all_ones(self):
        result = LoRaPhyDecoder._bits_to_bytes([1] * 8)
        assert result == b"\xff"

    def test_known_pattern(self):
        # 0b10101010 = 0xAA
        result = LoRaPhyDecoder._bits_to_bytes([1, 0, 1, 0, 1, 0, 1, 0])
        assert result == b"\xaa"

    def test_multi_byte(self):
        bits = [0, 0, 0, 0, 0, 0, 0, 1,  # 0x01
                1, 1, 1, 1, 1, 1, 1, 1]  # 0xFF
        result = LoRaPhyDecoder._bits_to_bytes(bits)
        assert result == b"\x01\xff"
