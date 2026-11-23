"""LoRa PHY-layer decoder.

Implements deinterleaving, Hamming FEC decoding, LFSR de-whitening,
Gray decoding, CRC-16 verification, and explicit/implicit header
parsing for LoRa chirp spread spectrum signals.

Reference: Semtech AN1200.22 (LoRa Modulation Basics), LoRa reverse
engineering by Matt Knight (DEF CON 24).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import numpy as np

from sigrift.lib.protocol.base import (
    DecodedMessage,
    DecodedPacket,
    FECError,
    ProtocolDecoder,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# LoRa CRC-16/CCITT (polynomial 0x1021, init 0x0000)
_CRC16_POLY = 0x1021

# LFSR de-whitening polynomial: x^8 + x^6 + x^5 + x^4 + 1
_LFSR_POLY = 0x71  # taps at bits 6, 5, 4 of an 8-bit register

# Coding rate to Hamming scheme mapping
_CR_MAP = {
    1: (4, 5),  # 4/5
    2: (4, 6),  # 4/6
    3: (4, 7),  # 4/7
    4: (4, 8),  # 4/8
}


# ---------------------------------------------------------------------------
# Helper: CRC-16/CCITT
# ---------------------------------------------------------------------------


def _crc16_ccitt(data: bytes, init: int = 0x0000) -> int:
    """Compute CRC-16/CCITT over *data*."""
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ _CRC16_POLY
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


# ---------------------------------------------------------------------------
# LoRa PHY Decoder
# ---------------------------------------------------------------------------


class LoRaPhyDecoder(ProtocolDecoder):
    """LoRa PHY-layer protocol decoder."""

    def protocol_name(self) -> str:
        return "lora"

    # -- Gray decode --------------------------------------------------------

    @staticmethod
    def gray_decode(symbols: np.ndarray) -> np.ndarray:
        """Reverse Gray coding on an array of integer symbols.

        Parameters
        ----------
        symbols : np.ndarray
            Array of Gray-coded unsigned integers.

        Returns
        -------
        np.ndarray
            Binary-coded integers.
        """
        symbols = np.asarray(symbols, dtype=np.uint32)
        result = np.copy(symbols)
        mask = result >> 1
        while np.any(mask > 0):
            result ^= mask
            mask >>= 1
        return result

    # -- Deinterleave -------------------------------------------------------

    @staticmethod
    def deinterleave(bits: list[int], sf: int, cr: int) -> list[int]:
        """Reverse LoRa diagonal interleaving.

        LoRa interleaves data bits diagonally across *sf* rows of
        *(cr + 4)* columns.  This reverses that operation.

        Parameters
        ----------
        bits : list[int]
            Interleaved bit stream.
        sf : int
            Spreading factor (7-12).
        cr : int
            Coding rate index (1-4).

        Returns
        -------
        list[int]
            De-interleaved bit stream.
        """
        n_cols = cr + 4
        block_size = sf * n_cols

        output: list[int] = []
        offset = 0
        while offset + block_size <= len(bits):
            block = bits[offset : offset + block_size]

            # Arrange into sf rows of n_cols columns (as transmitted)
            matrix = []
            for r in range(sf):
                row = block[r * n_cols : (r + 1) * n_cols]
                matrix.append(row)

            # Read out column by column (reverse of diagonal write)
            for c in range(n_cols):
                for r in range(sf):
                    output.append(matrix[r][(c + r) % n_cols])

            offset += block_size

        # Remaining partial block passed through unchanged
        if offset < len(bits):
            output.extend(bits[offset:])

        return output

    # -- Hamming decode -----------------------------------------------------

    @staticmethod
    def hamming_decode(block: list[int], cr: int) -> tuple[list[int], int]:
        """Decode a Hamming-coded block.

        Supports coding rates 4/5 through 4/8.  Returns the 4 data
        bits per codeword and the total number of corrected errors.

        Parameters
        ----------
        block : list[int]
            Coded bits (length must be a multiple of (cr + 4)).
        cr : int
            Coding rate index (1-4).

        Returns
        -------
        tuple[list[int], int]
            (data_bits, total_errors_corrected)

        Raises
        ------
        FECError
            When an uncorrectable error is detected (cr >= 3 only).
        """
        if cr not in _CR_MAP:
            raise FECError(f"Invalid coding rate index: {cr}")

        _, cw_len = _CR_MAP[cr]
        if len(block) % cw_len != 0:
            # Pad to multiple of codeword length
            pad = cw_len - (len(block) % cw_len)
            block = list(block) + [0] * pad

        data_bits: list[int] = []
        total_errors = 0
        n_codewords = len(block) // cw_len

        for i in range(n_codewords):
            cw = block[i * cw_len : (i + 1) * cw_len]

            if cw_len == 5:
                # Hamming(4,5): single parity check
                d = cw[:4]
                parity = cw[4]
                computed = d[0] ^ d[1] ^ d[2] ^ d[3]
                if computed != parity:
                    total_errors += 1
                    # Cannot correct, just flag it
                data_bits.extend(d)

            elif cw_len == 6:
                # Hamming(4,6): detect up to 2 errors, correct 1
                d = cw[:4]
                p0 = cw[4]
                p1 = cw[5]
                s0 = d[0] ^ d[1] ^ d[2] ^ p0
                s1 = d[1] ^ d[2] ^ d[3] ^ p1
                syndrome = (s0 << 1) | s1
                if syndrome != 0:
                    total_errors += 1
                    # Attempt single-bit correction in data
                    if syndrome <= 4:
                        idx = syndrome - 1
                        if idx < 4:
                            d[idx] ^= 1
                data_bits.extend(d)

            elif cw_len == 7:
                # Hamming(7,4): correct 1 error
                d = cw[:4]
                p = cw[4:7]
                s0 = d[0] ^ d[1] ^ d[3] ^ p[0]
                s1 = d[0] ^ d[2] ^ d[3] ^ p[1]
                s2 = d[1] ^ d[2] ^ d[3] ^ p[2]
                syndrome = (s2 << 2) | (s1 << 1) | s0
                if syndrome != 0:
                    total_errors += 1
                    # Map syndrome to bit position (1-indexed)
                    # Positions: p0=1, p1=2, d0=3, p2=4, d1=5, d2=6, d3=7
                    error_map = {3: 0, 5: 1, 6: 2, 7: 3}
                    if syndrome in error_map:
                        d[error_map[syndrome]] ^= 1
                    elif syndrome > 7:
                        raise FECError(
                            f"Uncorrectable error in Hamming(7,4) codeword {i}"
                        )
                data_bits.extend(d)

            elif cw_len == 8:
                # Hamming(8,4): SECDED — correct 1, detect 2
                d = cw[:4]
                p = cw[4:8]
                s0 = d[0] ^ d[1] ^ d[3] ^ p[0]
                s1 = d[0] ^ d[2] ^ d[3] ^ p[1]
                s2 = d[1] ^ d[2] ^ d[3] ^ p[2]
                overall = 0
                for b in cw:
                    overall ^= b
                syndrome = (s2 << 2) | (s1 << 1) | s0
                if syndrome != 0 and overall != 0:
                    # Single-bit error — correctable
                    total_errors += 1
                    error_map = {3: 0, 5: 1, 6: 2, 7: 3}
                    if syndrome in error_map:
                        d[error_map[syndrome]] ^= 1
                elif syndrome != 0 and overall == 0:
                    # Double-bit error — uncorrectable
                    raise FECError(
                        f"Uncorrectable double-bit error in Hamming(8,4) codeword {i}"
                    )
                data_bits.extend(d)

        return data_bits, total_errors

    # -- De-whitening -------------------------------------------------------

    @staticmethod
    def dewhiten(data: bytes) -> bytes:
        """Remove LoRa LFSR whitening.

        LFSR polynomial: x^8 + x^6 + x^5 + x^4 + 1 (0x171, mask 0x71).
        Initial state 0xFF.

        Parameters
        ----------
        data : bytes
            Whitened payload bytes.

        Returns
        -------
        bytes
            De-whitened payload bytes.
        """
        state = 0xFF
        output = bytearray(len(data))

        for i, byte in enumerate(data):
            prn_byte = 0
            for bit in range(8):
                # Output bit is LSB of state
                prn_bit = state & 1
                prn_byte |= prn_bit << bit

                # Feedback from taps at positions 4, 5, 6 (0-indexed)
                feedback = ((state >> 4) ^ (state >> 5) ^ (state >> 6)) & 1
                state = ((state >> 1) | (feedback << 7)) & 0xFF

            output[i] = byte ^ prn_byte

        return bytes(output)

    # -- CRC verification ---------------------------------------------------

    @staticmethod
    def verify_crc16(data: bytes, expected: int) -> bool:
        """Verify LoRa CRC-16/CCITT.

        Parameters
        ----------
        data : bytes
            Payload bytes to check.
        expected : int
            Expected 16-bit CRC value.

        Returns
        -------
        bool
            True if CRC matches.
        """
        computed = _crc16_ccitt(data)
        return computed == (expected & 0xFFFF)

    # -- Header decode ------------------------------------------------------

    @staticmethod
    def decode_header(symbols: list[int], sf: int, cr: int) -> dict:
        """Parse LoRa explicit or implicit header from demodulated symbols.

        The explicit header occupies the first 8 symbols (always at CR 4/8)
        and contains payload length, coding rate, and CRC presence flag.

        Parameters
        ----------
        symbols : list[int]
            Demodulated symbol values (integers 0..2^sf-1).
        sf : int
            Spreading factor (7-12).
        cr : int
            Coding rate index for implicit header mode (1-4).

        Returns
        -------
        dict
            Keys: ``payload_length``, ``coding_rate``, ``has_crc``,
            ``header_ok``, ``implicit``.
        """
        result = {
            "payload_length": 0,
            "coding_rate": cr,
            "has_crc": False,
            "header_ok": False,
            "implicit": True,
        }

        if len(symbols) < 8:
            logger.warning("Insufficient symbols for header decode: %d", len(symbols))
            return result

        # Explicit header: first 8 symbols carry header + header CRC
        # After Gray decode and de-interleave, extract header nibbles
        header_bits = []
        for s in symbols[:8]:
            for b in range(sf - 1, -1, -1):
                header_bits.append((s >> b) & 1)

        if len(header_bits) < 20:
            return result

        # Header fields (per Semtech spec):
        # bits 0-7:   payload length
        # bits 8-10:  coding rate (1-4)
        # bit 11:     CRC present
        # bits 12-19: header checksum (8-bit)
        payload_length = 0
        for i in range(8):
            payload_length = (payload_length << 1) | header_bits[i]

        coding_rate = 0
        for i in range(8, 11):
            coding_rate = (coding_rate << 1) | header_bits[i]

        has_crc = bool(header_bits[11])

        header_crc = 0
        for i in range(12, 20):
            header_crc = (header_crc << 1) | header_bits[i]

        # Simple header CRC check: XOR of first 12 bits in nibbles
        check = 0
        for i in range(12):
            check ^= header_bits[i] << (i % 8)
        check &= 0xFF

        result["payload_length"] = payload_length
        result["coding_rate"] = max(1, min(4, coding_rate))
        result["has_crc"] = has_crc
        result["header_ok"] = check == header_crc
        result["implicit"] = False

        return result

    # -- Packet decode ------------------------------------------------------

    def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
        """Decode a raw LoRa PHY frame.

        Parameters
        ----------
        raw : bytes
            Raw captured bytes (post-demodulation symbol stream packed
            as bytes, or raw payload if ``pre_decoded=True``).
        **kwargs
            Optional keys:

            - ``sf`` (int): spreading factor, default 7.
            - ``cr`` (int): coding rate index, default 1.
            - ``implicit_header`` (bool): implicit header mode, default False.
            - ``pre_decoded`` (bool): if True, *raw* is already the
              de-whitened payload (skip PHY decode). Default False.

        Returns
        -------
        DecodedPacket
        """
        sf: int = kwargs.get("sf", 7)
        cr: int = kwargs.get("cr", 1)
        implicit_header: bool = kwargs.get("implicit_header", False)
        pre_decoded: bool = kwargs.get("pre_decoded", False)

        errors: list[str] = []
        metadata = {"sf": sf, "cr": cr, "implicit_header": implicit_header}
        now = datetime.now(timezone.utc).isoformat()

        if pre_decoded:
            return DecodedPacket(
                protocol="lora",
                raw_bytes=raw,
                payload=raw,
                metadata=metadata,
                timestamp=now,
                confidence=0.8,
                errors=errors,
            )

        # Unpack bytes to symbol values (each symbol is sf bits wide)
        symbols = self._bytes_to_symbols(raw, sf)
        if not symbols:
            errors.append("no symbols extracted from raw bytes")
            return DecodedPacket(
                protocol="lora",
                raw_bytes=raw,
                payload=b"",
                metadata=metadata,
                timestamp=now,
                confidence=0.0,
                errors=errors,
            )

        # Gray decode
        gray_decoded = self.gray_decode(np.array(symbols, dtype=np.uint32))
        symbols_decoded = gray_decoded.tolist()

        # Parse header if explicit
        if not implicit_header:
            header = self.decode_header(symbols_decoded, sf, cr)
            metadata["header"] = header
            if header["header_ok"]:
                cr = header["coding_rate"]
                metadata["cr"] = cr
            else:
                errors.append("header CRC mismatch")

        # Convert symbols to bits for de-interleaving
        all_bits: list[int] = []
        for s in symbols_decoded:
            for b in range(sf - 1, -1, -1):
                all_bits.append((s >> b) & 1)

        # Skip header symbols for payload bits (8 symbols for explicit)
        payload_start = 0 if implicit_header else 8 * sf
        payload_bits = all_bits[payload_start:]

        # De-interleave
        try:
            deinterleaved = self.deinterleave(payload_bits, sf, cr)
        except Exception as exc:
            errors.append(f"deinterleave failed: {exc}")
            deinterleaved = payload_bits

        # Hamming FEC decode
        fec_errors = 0
        try:
            data_bits, fec_errors = self.hamming_decode(deinterleaved, cr)
        except FECError as exc:
            errors.append(f"FEC decode failed: {exc}")
            data_bits = deinterleaved
        if fec_errors > 0:
            errors.append(f"FEC corrected {fec_errors} errors")
            metadata["fec_errors"] = fec_errors

        # Pack bits to bytes
        payload_bytes = self._bits_to_bytes(data_bits)

        # De-whiten
        payload_bytes = self.dewhiten(payload_bytes)

        # CRC check (last 2 bytes if CRC present)
        has_crc = metadata.get("header", {}).get("has_crc", False)
        if has_crc and len(payload_bytes) >= 3:
            crc_expected = (payload_bytes[-2] << 8) | payload_bytes[-1]
            payload_data = payload_bytes[:-2]
            if not self.verify_crc16(payload_data, crc_expected):
                errors.append("CRC-16 mismatch")
            else:
                metadata["crc_ok"] = True
            payload_bytes = payload_data
        else:
            metadata["crc_ok"] = None  # no CRC to check

        # Confidence based on error count
        confidence = 0.9
        if fec_errors > 0:
            confidence -= min(0.3, fec_errors * 0.05)
        if errors:
            confidence -= 0.1 * len(errors)
        confidence = max(0.0, min(1.0, confidence))

        return DecodedPacket(
            protocol="lora",
            raw_bytes=raw,
            payload=payload_bytes,
            metadata=metadata,
            timestamp=now,
            confidence=round(confidence, 4),
            errors=errors,
        )

    # -- Message extraction -------------------------------------------------

    def extract_messages(self, packet: DecodedPacket) -> list[DecodedMessage]:
        """Extract a single message containing the raw LoRa payload.

        LoRa PHY does not define addressing or message types — that is
        left to upper layers (LoRaWAN, Meshtastic, etc.).

        Parameters
        ----------
        packet : DecodedPacket
            A decoded LoRa PHY packet.

        Returns
        -------
        list[DecodedMessage]
        """
        if not packet.payload:
            return []

        return [
            DecodedMessage(
                protocol="lora",
                source_id="",
                dest_id="",
                message_type="raw",
                payload=packet.payload,
                metadata=dict(packet.metadata),
                confidence=packet.confidence,
            )
        ]

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _bytes_to_symbols(raw: bytes, sf: int) -> list[int]:
        """Unpack raw bytes into a list of *sf*-bit symbol values."""
        if sf < 1 or not raw:
            return []

        # Convert bytes to a flat bit array
        bits: list[int] = []
        for byte in raw:
            for b in range(7, -1, -1):
                bits.append((byte >> b) & 1)

        # Extract sf-bit symbols
        symbols: list[int] = []
        for i in range(0, len(bits) - sf + 1, sf):
            val = 0
            for b in range(sf):
                val = (val << 1) | bits[i + b]
            symbols.append(val)

        return symbols

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        """Pack a bit list into bytes (MSB first, zero-padded)."""
        # Pad to multiple of 8
        padded = list(bits)
        while len(padded) % 8 != 0:
            padded.append(0)

        result = bytearray()
        for i in range(0, len(padded), 8):
            byte = 0
            for b in range(8):
                byte = (byte << 1) | padded[i + b]
            result.append(byte)

        return bytes(result)
