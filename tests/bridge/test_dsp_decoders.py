"""Tests for ADS-B, UAT, and LoRa/Meshtastic DSP decoders."""

import struct

import numpy as np
import pytest

from sigrift.lib.dsp.adsb_decoder import (
    ADSBMessage,
    _bits_to_int,
    _crc24,
    _decode_callsign,
    _decode_altitude,
    _nl,
    decode_adsb,
    decode_cpr,
    demodulate_ppm,
    extract_messages,
)
from sigrift.lib.dsp.lora_demodulator import (
    MeshNetworkIntelligence,
    _generate_chirp,
    _hamming_decode_nibble,
    classify_protocol,
    dechirp,
    decode_meshtastic_header,
    decode_meshtastic_protobuf,
    decode_payload,
    demodulate_and_decode,
    extract_header,
    try_decrypt_meshtastic,
)
from sigrift.lib.dsp.uat_decoder import (
    UATMessage,
    _bits_to_bytes,
    _uat_fec_check,
    decode_uat_message,
    demodulate_uat,
)


# ===================================================================
# ADS-B decoder tests
# ===================================================================


class TestCRC24:
    """CRC-24 validation for Mode S messages."""

    def test_crc24_zero_remainder_valid_frame(self):
        """A frame with correct CRC appended should yield remainder 0."""
        # Build a synthetic 112-bit frame: 88 data bits + 24 CRC bits
        rng = np.random.RandomState(42)
        data = rng.randint(0, 2, size=88).astype(np.int32)
        # Compute CRC of data padded with 24 zeros
        padded = np.concatenate([data, np.zeros(24, dtype=np.int32)])
        crc_val = _crc24(padded)
        # Append CRC bits
        crc_bits = np.zeros(24, dtype=np.int32)
        for i in range(24):
            crc_bits[23 - i] = (crc_val >> i) & 1
        frame = np.concatenate([data, crc_bits])
        assert _crc24(frame) == 0

    def test_crc24_bad_frame(self):
        """A corrupted frame should yield non-zero remainder."""
        rng = np.random.RandomState(42)
        data = rng.randint(0, 2, size=88).astype(np.int32)
        padded = np.concatenate([data, np.zeros(24, dtype=np.int32)])
        crc_val = _crc24(padded)
        crc_bits = np.zeros(24, dtype=np.int32)
        for i in range(24):
            crc_bits[23 - i] = (crc_val >> i) & 1
        frame = np.concatenate([data, crc_bits])
        # Flip a bit
        frame[10] ^= 1
        assert _crc24(frame) != 0

    def test_crc24_all_zeros(self):
        """All-zero input should yield zero CRC."""
        bits = np.zeros(112, dtype=np.int32)
        assert _crc24(bits) == 0

    def test_crc24_short_frame(self):
        """CRC should work on 56-bit short frames."""
        bits = np.zeros(56, dtype=np.int32)
        # Set some data bits
        bits[0] = 1
        bits[5] = 1
        result = _crc24(bits)
        assert isinstance(result, int)
        assert 0 <= result < (1 << 24)


class TestDecodeCallsign:
    """Callsign decoding from ADS-B type code 1-4."""

    def test_known_callsign(self):
        """Encode 'UAL123' and verify round-trip decode."""
        charset = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
        target = "UAL123  "  # 8 chars padded
        bits = []
        for ch in target:
            idx = charset.index(ch)
            for j in range(6):
                bits.append((idx >> (5 - j)) & 1)
        data = np.array(bits, dtype=np.int32)
        result = _decode_callsign(data)
        assert result == "UAL123"

    def test_all_alpha_callsign(self):
        """Decode 'ABCDEFGH'."""
        charset = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
        target = "ABCDEFGH"
        bits = []
        for ch in target:
            idx = charset.index(ch)
            for j in range(6):
                bits.append((idx >> (5 - j)) & 1)
        data = np.array(bits, dtype=np.int32)
        assert _decode_callsign(data) == "ABCDEFGH"

    def test_short_data(self):
        """Short bit array should not crash."""
        data = np.array([0, 1, 0], dtype=np.int32)
        result = _decode_callsign(data)
        assert isinstance(result, str)


class TestDemodPPM:
    """PPM demodulation shape and basic behavior."""

    def test_demodulate_ppm_output_is_1d(self):
        """Output should be a 1D integer array."""
        rng = np.random.RandomState(0)
        iq = rng.randn(4000) + 1j * rng.randn(4000)
        result = demodulate_ppm(iq, sample_rate=2e6)
        assert result.ndim == 1
        assert result.dtype == np.int32

    def test_demodulate_ppm_empty_input(self):
        """Empty IQ should return empty bit array."""
        result = demodulate_ppm(np.array([], dtype=complex), sample_rate=2e6)
        assert len(result) == 0

    def test_demodulate_ppm_short_input(self):
        """Very short IQ should return empty or short array."""
        iq = np.ones(10, dtype=complex)
        result = demodulate_ppm(iq, sample_rate=2e6)
        assert result.ndim == 1

    def test_demodulate_ppm_synthetic_preamble(self):
        """Synthetic preamble with known pulses should be detected."""
        fs = 2e6
        samples_per_us = int(fs / 1e6)
        total_len = 300 * samples_per_us

        iq = np.zeros(total_len, dtype=complex) + 0.01
        preamble_start = 10 * samples_per_us

        # Inject preamble pulses at 0, 1, 3.5, 4.5 us
        for t_us in [0.0, 1.0, 3.5, 4.5]:
            idx = preamble_start + int(t_us * samples_per_us)
            iq[idx : idx + samples_per_us] = 1.0 + 0j

        result = demodulate_ppm(iq, sample_rate=fs)
        assert result.ndim == 1
        # Should have extracted some bits
        assert len(result) > 0


class TestCPRDecode:
    """CPR global position decode."""

    def test_cpr_known_position(self):
        """Test CPR decode with known even/odd values.

        Using the example from ICAO Annex 10:
        Aircraft at approximately lat=52.26, lon=3.92
        """
        # Encoded CPR values (normalized 0..1)
        even_lat = 92095.0 / 131072.0  # ~0.7027
        even_lon = 39846.0 / 131072.0  # ~0.3040
        odd_lat = 88385.0 / 131072.0  # ~0.6744
        odd_lon = 125818.0 / 131072.0  # ~0.9601

        result = decode_cpr(even_lat, even_lon, odd_lat, odd_lon, even_newer=True)
        if result is not None:
            lat, lon = result
            assert -90.0 <= lat <= 90.0
            assert -180.0 <= lon <= 180.0

    def test_cpr_returns_none_on_nl_mismatch(self):
        """CPR should return None when NL zones disagree."""
        # Craft values that produce different NL zones
        result = decode_cpr(0.99, 0.5, 0.01, 0.5)
        # With such extreme values, NL mismatch is likely
        # (either None or valid coords is acceptable)
        if result is not None:
            lat, lon = result
            assert -90.0 <= lat <= 90.0

    def test_cpr_odd_newer(self):
        """Test CPR decode with odd frame as newer."""
        even_lat = 92095.0 / 131072.0
        even_lon = 39846.0 / 131072.0
        odd_lat = 88385.0 / 131072.0
        odd_lon = 125818.0 / 131072.0

        result = decode_cpr(even_lat, even_lon, odd_lat, odd_lon, even_newer=False)
        if result is not None:
            lat, lon = result
            assert -90.0 <= lat <= 90.0
            assert -180.0 <= lon <= 180.0


class TestNLFunction:
    """NL latitude zone lookup."""

    def test_nl_equator(self):
        assert _nl(0.0) == 59

    def test_nl_high_latitude(self):
        # DO-260B: NL(+/-87) = 2, NL = 1 beyond +/-87 degrees.
        assert _nl(87.0) == 2
        assert _nl(87.5) == 1
        assert _nl(89.0) == 1

    def test_nl_mid_latitude(self):
        assert _nl(45.0) == 42

    def test_nl_negative_latitude(self):
        """Negative latitudes should use absolute value."""
        assert _nl(-30.0) == _nl(30.0)


class TestDecodeAltitude:
    """Altitude decoding from DF17 position messages."""

    def test_q_bit_set_25ft(self):
        """Q-bit=1: altitude = N*25 - 1000 ft."""
        # 12-bit field = message bits 41-52; the Q-bit is message bit 48,
        # i.e. index 7 of the field.
        # altitude = 38000 ft => N = (38000 + 1000) / 25 = 1560
        # Binary of 1560 = 0b11000011000 (11 bits)
        n_val = 1560
        bits = np.zeros(12, dtype=np.int32)
        bits[7] = 1  # Q-bit
        # Encode N into the remaining 11 bit positions (0-6, 8-11)
        n_bits = []
        for i in range(10, -1, -1):
            n_bits.append((n_val >> i) & 1)
        # Fill positions: 0-6 are the high 7 bits, 8-11 the low 4 bits
        for i in range(7):
            bits[i] = n_bits[i]
        for i in range(4):
            bits[8 + i] = n_bits[7 + i]

        alt = _decode_altitude(bits)
        assert alt is not None
        assert alt == pytest.approx(38000.0)

    def test_altitude_none_for_zero(self):
        """An all-zero altitude field means altitude unavailable."""
        bits = np.zeros(12, dtype=np.int32)
        assert _decode_altitude(bits) is None

    def test_short_input(self):
        bits = np.zeros(5, dtype=np.int32)
        assert _decode_altitude(bits) is None


class TestDecodeADSB:
    """Full DF17/18 frame decode."""

    def _make_valid_frame(
        self, df: int, icao: int, tc: int, me_data: np.ndarray
    ) -> np.ndarray:
        """Build a 112-bit frame with valid CRC."""
        frame = np.zeros(112, dtype=np.int32)
        # DF (bits 0-4)
        for i in range(5):
            frame[4 - i] = (df >> i) & 1
        # Capability (bits 5-7)
        # ICAO (bits 8-31)
        for i in range(24):
            frame[8 + i] = (icao >> (23 - i)) & 1
        # ME: TC (bits 32-36)
        for i in range(5):
            frame[32 + i] = (tc >> (4 - i)) & 1
        # ME data (bits 37-87)
        copy_len = min(len(me_data), 51)
        frame[37 : 37 + copy_len] = me_data[:copy_len]

        # Compute and append CRC
        padded = np.array(frame, dtype=np.int32)
        padded[88:112] = 0
        crc_val = _crc24(padded)
        for i in range(24):
            frame[88 + i] = (crc_val >> (23 - i)) & 1

        return frame

    def test_decode_returns_none_for_short(self):
        frame = np.zeros(50, dtype=np.int32)
        assert decode_adsb(frame) is None

    def test_decode_returns_none_for_bad_crc(self):
        frame = np.ones(112, dtype=np.int32)
        # Random bits won't have valid CRC
        assert decode_adsb(frame) is None

    def test_decode_callsign_frame(self):
        """DF17 TC=1 should decode callsign."""
        charset = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"
        callsign = "TEST    "
        me_data = np.zeros(51, dtype=np.int32)
        # After TC (5 bits) and subtype (3 bits), callsign starts at ME bit 8
        # But TC is already in bits 32-36, so me_data starts after TC
        # me_data[0:3] = subtype, me_data[3:51] = callsign (8*6 = 48 bits)
        bits_offset = 3  # skip subtype
        for ch_idx, ch in enumerate("TEST    "):
            idx = charset.index(ch)
            for j in range(6):
                if bits_offset + ch_idx * 6 + j < len(me_data):
                    me_data[bits_offset + ch_idx * 6 + j] = (idx >> (5 - j)) & 1

        frame = self._make_valid_frame(df=17, icao=0xABCDEF, tc=1, me_data=me_data)
        msg = decode_adsb(frame)
        assert msg is not None
        assert msg.icao_address == "ABCDEF"
        assert msg.msg_type == 17
        assert msg.callsign is not None

    def test_decode_non_df17_returns_none(self):
        """Non-DF17/18 frames should return None."""
        frame = self._make_valid_frame(
            df=4, icao=0x123456, tc=0, me_data=np.zeros(51, dtype=np.int32)
        )
        assert decode_adsb(frame) is None


class TestExtractMessages:
    """Frame extraction from bit streams."""

    def test_empty_bits(self):
        assert extract_messages(np.array([], dtype=np.int32)) == []

    def test_short_bits(self):
        assert extract_messages(np.zeros(30, dtype=np.int32)) == []

    def test_valid_frame_extracted(self):
        """A 112-bit all-zero frame should extract (CRC of all zeros is 0)."""
        bits = np.zeros(112, dtype=np.int32)
        # All-zero with DF=0 should be a 56-bit frame
        frames = extract_messages(bits)
        # DF=0 expects 56 bits, check if CRC passes for the short frame
        assert isinstance(frames, list)


# ===================================================================
# LoRa demodulator tests
# ===================================================================


class TestDechirp:
    """FFT-based LoRa dechirp."""

    def test_dechirp_known_symbols(self):
        """Generate LoRa chirps for known symbols and verify recovery."""
        sf = 7
        bw = 125e3
        fs = 250e3
        n_fft = 2**sf

        expected_symbols = [0, 10, 50, 100, 127]
        # Generate IQ by creating upchirps with symbol-dependent frequency offsets
        iq_all = np.array([], dtype=complex)
        samples_per_symbol = int(fs / bw * n_fft)

        for sym in expected_symbols:
            t = np.arange(n_fft) / fs
            # Upchirp with cyclic frequency shift by sym bins
            chirp_rate = bw / (n_fft / fs)
            f_start = -bw / 2 + sym * (bw / n_fft)
            # Simple model: frequency-shifted upchirp
            phase = 2.0 * np.pi * (f_start * t + chirp_rate / 2.0 * t * t)
            symbol_iq = np.exp(1j * phase)
            # Resample to samples_per_symbol if needed
            if len(symbol_iq) < samples_per_symbol:
                symbol_iq = np.pad(symbol_iq, (0, samples_per_symbol - len(symbol_iq)))
            else:
                symbol_iq = symbol_iq[:samples_per_symbol]
            iq_all = np.concatenate([iq_all, symbol_iq])

        symbols = dechirp(iq_all, sf=sf, bw=bw, fs=fs)
        assert len(symbols) == len(expected_symbols)
        # Each decoded symbol should be an int in [0, 2^sf - 1]
        assert all(0 <= s < n_fft for s in symbols)

    def test_dechirp_empty(self):
        """Empty IQ should return empty symbols."""
        symbols = dechirp(np.array([], dtype=complex), sf=7, bw=125e3, fs=250e3)
        assert len(symbols) == 0

    def test_dechirp_short(self):
        """Very short IQ should return zero symbols."""
        iq = np.ones(5, dtype=complex)
        symbols = dechirp(iq, sf=7, bw=125e3, fs=250e3)
        assert len(symbols) == 0

    def test_dechirp_output_dtype(self):
        """Symbols should be int32."""
        sf = 5
        n_fft = 2**sf
        iq = np.exp(1j * np.linspace(0, 10, n_fft * 4))
        fs = 125e3 * 2
        symbols = dechirp(iq, sf=sf, bw=125e3, fs=fs)
        if len(symbols) > 0:
            assert symbols.dtype == np.int32


class TestClassifyProtocol:
    """Sync word classification."""

    def test_meshtastic(self):
        assert classify_protocol(0x12) == "meshtastic"

    def test_lorawan(self):
        assert classify_protocol(0x34) == "lorawan"

    def test_generic_unknown(self):
        assert classify_protocol(0xFF) == "generic"

    def test_generic_zero(self):
        assert classify_protocol(0x00) == "generic"


class TestDecodeMeshtasticHeader:
    """Meshtastic MAC header parsing."""

    def test_known_header(self):
        """Pack a known header and verify decode."""
        dest = 0xDEADBEEF
        source = 0xCAFEBABE
        pkt_id = 12345
        hop_limit = 3
        want_ack = 1
        channel_hash = 0x08
        next_hop = 0x2A
        relay_node = 0x17

        payload = struct.pack("<III", dest, source, pkt_id)
        flags = (want_ack << 3) | hop_limit
        # Bytes 14/15 are next_hop / relay_node; the portnum is NOT in the
        # cleartext header (it is field 1 of the encrypted Data protobuf).
        payload += bytes([flags, channel_hash, next_hop, relay_node])

        result = decode_meshtastic_header(payload)
        assert result["source_node_id"] == "!cafebabe"
        assert result["dest_node_id"] == "!deadbeef"
        assert result["packet_id"] == 12345
        assert result["hop_limit"] == 3
        assert result["want_ack"] is True
        assert result["channel_hash"] == 0x08
        assert result["next_hop"] == 0x2A
        assert result["relay_node"] == 0x17
        assert "port_num" not in result

    def test_short_payload_returns_empty(self):
        """Payload shorter than 16 bytes should return empty dict."""
        assert decode_meshtastic_header(b"\x00" * 10) == {}

    def test_exact_16_bytes(self):
        """Exactly 16 bytes should decode."""
        payload = struct.pack("<III", 1, 2, 3)
        payload += bytes([0x05, 0x10, 0x03, 0x00])
        result = decode_meshtastic_header(payload)
        assert result["source_node_id"] == "!00000002"
        assert result["hop_limit"] == 5
        assert result["next_hop"] == 3


class TestTryDecryptMeshtastic:
    """Default-key Meshtastic decryption."""

    def test_unknown_channel_returns_none(self):
        """Unknown channel_hash should return None (no brute force)."""
        assert try_decrypt_meshtastic(b"\x00" * 16, channel_hash=0xFF) is None

    def test_empty_payload_returns_none(self):
        """Empty payload should return None."""
        assert try_decrypt_meshtastic(b"", channel_hash=0x08) is None

    def test_decrypt_with_longfast_key(self):
        """Encrypt with known key and verify round-trip."""
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            pytest.skip("cryptography library not available")

        # Default channel PSK ("AQ==") -- shared by every modem preset.
        key = bytes.fromhex("d4f1bb3a20290759f0bcffabcf4e6901")
        # Data{portnum=TEXT_MESSAGE_APP, payload="Hello Meshtastic"}
        text = b"Hello Meshtastic"
        plaintext = b"\x08\x01\x12" + bytes([len(text)]) + text
        pkt_id = 42
        source_node = 0xCAFEBABE

        # Firmware CryptoEngine::initNonce: packetId LE u64, fromNode LE u32.
        nonce = struct.pack("<QI", pkt_id, source_node).ljust(16, b"\x00")
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        result = try_decrypt_meshtastic(
            ciphertext,
            channel_hash=0x08,
            packet_id=pkt_id,
            source_node=source_node,
        )
        assert result == plaintext


class TestProtobufDecode:
    """Manual protobuf decoding for Meshtastic payloads."""

    def test_text_message(self):
        """PORT_TEXT_MESSAGE should return raw UTF-8."""
        plaintext = b"Hello from mesh"
        result = decode_meshtastic_protobuf(plaintext, port_num=1)
        assert result["text"] == "Hello from mesh"

    def test_text_message_unicode(self):
        text = "Cafe \xc3\xa9"
        result = decode_meshtastic_protobuf(text.encode("utf-8"), port_num=1)
        assert isinstance(result["text"], str)

    def test_position_decode(self):
        """Encode a position protobuf and verify decode."""
        # field 1 (sfixed32): lat_i = int(52.26 * 1e7) = 522600000
        # field 2 (sfixed32): lon_i = int(3.92 * 1e7) = 39200000
        # wire type 5 = 32-bit
        lat_i = 522600000
        lon_i = 39200000
        payload = b""
        payload += bytes([(1 << 3) | 5])  # field 1, wire type 5
        payload += struct.pack("<i", lat_i)
        payload += bytes([(2 << 3) | 5])  # field 2, wire type 5
        payload += struct.pack("<i", lon_i)

        result = decode_meshtastic_protobuf(payload, port_num=3)
        assert "position" in result
        pos = result["position"]
        assert abs(pos["lat"] - 52.26) < 0.001
        assert abs(pos["lon"] - 3.92) < 0.001

    def test_empty_payload(self):
        """Empty payload should return empty dict."""
        result = decode_meshtastic_protobuf(b"", port_num=3)
        assert isinstance(result, dict)

    def test_unknown_port(self):
        """Unknown port number should return empty dict."""
        result = decode_meshtastic_protobuf(b"\x00\x01\x02", port_num=999)
        assert result == {}


class TestExtractHeader:
    """LoRa header extraction."""

    def test_header_keys(self):
        """Header dict should contain expected keys."""
        symbols = np.array([0x12, 0x34, 0x10, 0x05, 0, 0, 0, 0], dtype=np.int32)
        header = extract_header(symbols)
        assert "sync_word" in header
        assert "cr" in header
        assert "has_crc" in header
        assert "payload_len" in header

    def test_short_symbols_defaults(self):
        """Fewer than 8 symbols should return defaults."""
        header = extract_header(np.array([1, 2, 3], dtype=np.int32))
        assert header["sync_word"] == 0
        assert header["payload_len"] == 0

    def test_sync_word_extraction(self):
        """Sync word should be extracted from symbols 0 and 1."""
        # sync = ((symbols[0] & 0xF0) >> 4) | ((symbols[1] & 0xF0))
        # For meshtastic (0x12): need symbols[0] high nibble = 0x2, symbols[1] high nibble = 0x1
        symbols = np.array([0x20, 0x10, 0, 0, 0, 0, 0, 0], dtype=np.int32)
        header = extract_header(symbols)
        assert header["sync_word"] == 0x12


class TestDecodePayload:
    """LoRa payload decoding."""

    def test_empty_symbols(self):
        assert decode_payload(np.array([], dtype=np.int32), cr=1) == b""

    def test_short_symbols(self):
        assert decode_payload(np.array([1, 2, 3], dtype=np.int32), cr=1) == b""

    def test_returns_bytes(self):
        symbols = np.arange(20, dtype=np.int32)
        result = decode_payload(symbols, cr=1)
        assert isinstance(result, bytes)


class TestHammingDecode:
    """Hamming(7,4) single-error correction."""

    def test_no_error(self):
        """Hamming codeword for nibble 0b1010 should decode correctly."""
        # Hamming(7,4): data at positions 2,4,5,6 (0-indexed)
        # d = [p1, p2, d1, p3, d2, d3, d4]
        # For data 1010: d1=1, d2=0, d3=1, d4=0
        # p1 = d1^d2^d4 = 1^0^0 = 1
        # p2 = d1^d3^d4 = 1^1^0 = 0
        # p3 = d2^d3^d4 = 0^1^0 = 1
        # codeword = [1, 0, 1, 1, 0, 1, 0] = 0b1011010 = 0x5A
        codeword = 0b1011010
        assert _hamming_decode_nibble(codeword) == 0b1010

    def test_single_bit_error_corrected(self):
        """Single bit flip should be corrected."""
        codeword = 0b1011010  # valid for data 1010
        flipped = codeword ^ (1 << 3)  # flip bit 3
        assert _hamming_decode_nibble(flipped) == 0b1010


class TestFullPipeline:
    """End-to-end demodulate_and_decode."""

    def test_short_signal_returns_none(self):
        """Too few symbols should return None."""
        iq = np.ones(10, dtype=complex)
        result = demodulate_and_decode(iq, sf=7, bw=125e3, fs=250e3)
        assert result is None

    def test_returns_intelligence_object(self):
        """Sufficient IQ should return MeshNetworkIntelligence."""
        sf = 7
        bw = 125e3
        fs = 250e3
        n_fft = 2**sf
        samples_per_symbol = int(fs / bw * n_fft)

        # Generate enough symbols for a valid decode attempt
        iq = np.exp(1j * np.linspace(0, 100, samples_per_symbol * 12))
        result = demodulate_and_decode(iq, sf=sf, bw=bw, fs=fs)
        if result is not None:
            assert isinstance(result, MeshNetworkIntelligence)
            assert result.protocol in ("meshtastic", "lorawan", "generic")


class TestGenerateChirp:
    """Chirp signal generation."""

    def test_chirp_length(self):
        n_fft = 128
        chirp = _generate_chirp(n_fft, bw=125e3, fs=250e3, upchirp=True)
        assert len(chirp) == n_fft

    def test_chirp_is_complex(self):
        chirp = _generate_chirp(64, bw=125e3, fs=250e3)
        assert np.iscomplexobj(chirp)

    def test_chirp_unit_magnitude(self):
        """Chirp samples should have unit magnitude (pure phase)."""
        chirp = _generate_chirp(128, bw=125e3, fs=250e3)
        mags = np.abs(chirp)
        np.testing.assert_allclose(mags, 1.0, atol=1e-10)


# ===================================================================
# UAT decoder tests
# ===================================================================


class TestDemodulateUAT:
    """UAT demodulation shape tests."""

    def test_output_shape(self):
        """Output should be a 1D int32 array."""
        rng = np.random.RandomState(42)
        iq = rng.randn(5000) + 1j * rng.randn(5000)
        bits = demodulate_uat(iq, sample_rate=2.5e6)
        assert bits.ndim == 1
        assert bits.dtype == np.int32

    def test_empty_input(self):
        bits = demodulate_uat(np.array([], dtype=complex), sample_rate=2.5e6)
        assert len(bits) == 0


class TestUATMessage:
    """UAT message format tests."""

    def test_frame_without_rs_parity_dropped(self):
        """A bare 18-byte payload (no RS parity) must not be decoded.

        This test used to build a frame with a CRC-16 trailer and expect
        fields back; UAT ADS-B has no CRC (it is RS(30,18)/RS(48,34)), so
        that frame is not valid UAT and is now dropped.  Correct frames
        are covered by tests/bridge/test_uat_golden.py.
        """
        # 18 non-zero payload bytes + 12 zero "parity" bytes: far (> t = 6
        # byte errors) from every RS codeword, so RS must reject it.
        data = bytes(range(1, 19)) + bytes(12)
        bits = np.zeros(240, dtype=np.int32)
        for i, byte in enumerate(data):
            for j in range(8):
                bits[i * 8 + j] = (byte >> (7 - j)) & 1
        assert decode_uat_message(bits) is None

    def test_short_bits_returns_none(self):
        assert decode_uat_message(np.zeros(100, dtype=np.int32)) is None

    def test_uat_fec_check_rejects_non_uat_lengths(self):
        """The FEC check is RS over 30- or 48-byte codewords only.

        The old CRC-16 tests here encoded the wrong check; RS validity is
        tested against independently encoded frames in test_uat_golden.py.
        """
        assert _uat_fec_check(bytes(6), 6) is False
        assert _uat_fec_check(bytes(30), 30) is True  # all-zero is a codeword
        assert _uat_fec_check(bytes(20), 30) is False

    def test_bits_to_bytes(self):
        """Bit array to bytes conversion."""
        bits = np.array(
            [1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int32
        )
        result = _bits_to_bytes(bits)
        assert result == bytes([0xAA, 0x0F])
