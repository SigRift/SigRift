"""APCO Project 25 (P25) Phase 1 protocol decoder.

Decodes P25 Phase 1 frames: HDU, LDU1, LDU2, TSDU/TSBK, PDU, TDU, TDULC.
Extracts unit IDs, talk group IDs, encryption status, and trunking
signaling from raw bit streams.

References:
    TIA-102.BAAA (P25 Common Air Interface)
    TIA-102.BABA (P25 Trunking Signaling)
"""

from __future__ import annotations

import logging
from enum import IntEnum

from sigrift.lib.protocol.base import (
    DecodeError,
    DecodedMessage,
    DecodedPacket,
    FECError,
    FrameSyncError,
    ProtocolDecoder,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

P25_FRAME_SYNC = 0x5575F5FF77FF  # 48-bit frame sync word
_FRAME_SYNC_BITS = [(P25_FRAME_SYNC >> (47 - i)) & 1 for i in range(48)]
_FRAME_SYNC_LEN = 48


class DUID(IntEnum):
    """P25 Data Unit ID values."""

    HDU = 0x0
    TDU = 0x3
    LDU1 = 0x5
    TSDU = 0x7
    LDU2 = 0xA
    PDU = 0xC
    TDULC = 0xF  # Terminator Data Unit with Link Control (trunked call end)


# Encryption algorithm IDs
ALGID_UNENCRYPTED = 0x80
ALGID_DES_OFB = 0x81
ALGID_AES_256 = 0x84

_ALGID_NAMES: dict[int, str] = {
    ALGID_UNENCRYPTED: "unencrypted",
    ALGID_DES_OFB: "DES-OFB",
    ALGID_AES_256: "AES-256",
}

# ---------------------------------------------------------------------------
# Golay(24,12) lookup table
# ---------------------------------------------------------------------------

# Standard Golay generator polynomial: x^11 + x^9 + x^7 + x^6 + x^5 + x + 1
_GOLAY_POLY = 0xAE3  # 0b101011100011

_GOLAY_SYNDROME_TABLE: dict[int, int] | None = None


def _build_golay_tables() -> dict[int, int]:
    """Build syndrome -> error pattern lookup for Golay(24,12)."""
    table: dict[int, int] = {}

    def _syndrome(codeword: int) -> int:
        """Compute 12-bit syndrome of a 24-bit codeword."""
        r = codeword
        for i in range(23, 11, -1):
            if r & (1 << i):
                r ^= _GOLAY_POLY << (i - 11)
        return r & 0xFFF

    # Weight-0 error (no error)
    table[0] = 0

    # Weight-1 errors
    for i in range(24):
        e = 1 << i
        table[_syndrome(e)] = e

    # Weight-2 errors
    for i in range(24):
        for j in range(i + 1, 24):
            e = (1 << i) | (1 << j)
            s = _syndrome(e)
            if s not in table:
                table[s] = e

    # Weight-3 errors
    for i in range(24):
        for j in range(i + 1, 24):
            for k in range(j + 1, 24):
                e = (1 << i) | (1 << j) | (1 << k)
                s = _syndrome(e)
                if s not in table:
                    table[s] = e

    return table


def _get_golay_table() -> dict[int, int]:
    """Lazily initialize and return the Golay syndrome table."""
    global _GOLAY_SYNDROME_TABLE
    if _GOLAY_SYNDROME_TABLE is None:
        _GOLAY_SYNDROME_TABLE = _build_golay_tables()
    return _GOLAY_SYNDROME_TABLE


def golay_decode(bits_24: list[int]) -> tuple[list[int], int]:
    """Decode a Golay(24,12) codeword.

    Parameters
    ----------
    bits_24 : list[int]
        24-bit codeword (MSB first).

    Returns
    -------
    tuple[list[int], int]
        (12 data bits MSB-first, number of errors corrected).

    Raises
    ------
    FECError
        If more than 3 bit errors are detected (uncorrectable).
    """
    if len(bits_24) != 24:
        raise FECError(f"Golay(24,12) requires 24 bits, got {len(bits_24)}")

    codeword = 0
    for b in bits_24:
        codeword = (codeword << 1) | (b & 1)

    # Compute syndrome
    r = codeword
    for i in range(23, 11, -1):
        if r & (1 << i):
            r ^= _GOLAY_POLY << (i - 11)
    syndrome = r & 0xFFF

    if syndrome == 0:
        data_bits = [(codeword >> (23 - i)) & 1 for i in range(12)]
        return data_bits, 0

    table = _get_golay_table()
    if syndrome not in table:
        raise FECError(f"Golay(24,12) uncorrectable error, syndrome=0x{syndrome:03X}")

    error_pattern = table[syndrome]
    corrected = codeword ^ error_pattern
    errors = bin(error_pattern).count("1")

    data_bits = [(corrected >> (23 - i)) & 1 for i in range(12)]
    return data_bits, errors


# ---------------------------------------------------------------------------
# Bit manipulation helpers
# ---------------------------------------------------------------------------


def _bits_to_int(bits: list[int]) -> int:
    """Convert a list of bits (MSB first) to an integer."""
    val = 0
    for b in bits:
        val = (val << 1) | (b & 1)
    return val


def _int_to_bits(val: int, width: int) -> list[int]:
    """Convert an integer to a list of bits (MSB first)."""
    return [(val >> (width - 1 - i)) & 1 for i in range(width)]


# ---------------------------------------------------------------------------
# Frame sync detection
# ---------------------------------------------------------------------------


def detect_frame_sync(bits: list[int]) -> int | None:
    """Find the P25 48-bit frame sync pattern in a bit stream.

    Parameters
    ----------
    bits : list[int]
        Input bit stream to search.

    Returns
    -------
    int or None
        Bit offset of the first sync match, or None if not found.
    """
    if len(bits) < _FRAME_SYNC_LEN:
        return None

    for offset in range(len(bits) - _FRAME_SYNC_LEN + 1):
        match = True
        for i in range(_FRAME_SYNC_LEN):
            if bits[offset + i] != _FRAME_SYNC_BITS[i]:
                match = False
                break
        if match:
            return offset

    return None


# ---------------------------------------------------------------------------
# Status symbols
# ---------------------------------------------------------------------------

# A status dibit follows every 70 information bits (35 dibits), counted from
# the first bit of the frame sync, so bits 70-71 of every 72 are status.
_STATUS_PERIOD = 72
_STATUS_OFFSET = 70


def strip_status_symbols(frame_bits: list[int]) -> list[int]:
    """Remove the status dibits from a bit stream that starts at frame sync."""
    return [b for i, b in enumerate(frame_bits) if i % _STATUS_PERIOD < _STATUS_OFFSET]


# ---------------------------------------------------------------------------
# BCH(63,16,23) over GF(2^6) for the NID
# ---------------------------------------------------------------------------

# Generator polynomial (TIA-102.BAAA), octal 6331 1413 6723 5453: the LCM of
# the minimal polynomials of alpha^1 .. alpha^22 in GF(64), x^6 + x + 1.
BCH_63_16_GENERATOR = 0o6331141367235453
_BCH_N = 63
_BCH_K = 16
_BCH_T = 11

_GF64_EXP = [0] * 126
_GF64_LOG = [0] * 64
_v = 1
for _i in range(63):
    _GF64_EXP[_i] = _v
    _GF64_LOG[_v] = _i
    _v <<= 1
    if _v & 0x40:
        _v ^= 0x43
for _i in range(63, 126):
    _GF64_EXP[_i] = _GF64_EXP[_i - 63]
del _v, _i


def _gf64_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF64_EXP[_GF64_LOG[a] + _GF64_LOG[b]]


def _gf64_inv(a: int) -> int:
    return _GF64_EXP[63 - _GF64_LOG[a]]


def _bch_syndromes(cw: list[int]) -> list[int]:
    """S_1 .. S_2t of the received word (cw[0] is the x^62 coefficient)."""
    synd = []
    for i in range(1, 2 * _BCH_T + 1):
        acc = 0
        for j, bit in enumerate(cw):
            if bit:
                acc ^= _GF64_EXP[(i * (_BCH_N - 1 - j)) % 63]
        synd.append(acc)
    return synd


def bch_63_16_decode(bits: list[int]) -> tuple[list[int], int] | None:
    """Decode a BCH(63,16) codeword (MSB first); correct up to 11 errors.

    Returns ``(info_bits_16, n_corrected)`` or None when uncorrectable.
    """
    if len(bits) < _BCH_N:
        return None
    cw = [b & 1 for b in bits[:_BCH_N]]
    synd = _bch_syndromes(cw)
    if not any(synd):
        return cw[:_BCH_K], 0

    # Berlekamp-Massey (synd[k] is S_(k+1)).
    n_roots = 2 * _BCH_T
    lam = [1] + [0] * n_roots
    prev = [1] + [0] * n_roots
    degree = 0
    shift = 1
    prev_disc = 1
    for k in range(n_roots):
        disc = synd[k]
        for i in range(1, degree + 1):
            disc ^= _gf64_mul(lam[i], synd[k - i])
        if disc == 0:
            shift += 1
            continue
        coef = _gf64_mul(disc, _gf64_inv(prev_disc))
        new = list(lam)
        for i in range(n_roots + 1 - shift):
            new[i + shift] ^= _gf64_mul(coef, prev[i])
        if 2 * degree <= k:
            prev = lam
            degree = k + 1 - degree
            prev_disc = disc
            shift = 1
        else:
            shift += 1
        lam = new

    if degree == 0 or degree > _BCH_T:
        return None

    # Chien search: an error at index j has locator alpha^(62 - j).
    positions = []
    for j in range(_BCH_N):
        x_inv = _GF64_EXP[(63 - (_BCH_N - 1 - j)) % 63]
        val = 0
        for i in range(degree, -1, -1):
            val = _gf64_mul(val, x_inv) ^ lam[i]
        if val == 0:
            positions.append(j)
    if len(positions) != degree:
        return None
    for j in positions:
        cw[j] ^= 1
    if any(_bch_syndromes(cw)):
        return None
    return cw[:_BCH_K], degree


# ---------------------------------------------------------------------------
# NID decoding
# ---------------------------------------------------------------------------


def decode_nid(bits: list[int]) -> dict:
    """Decode the 64-bit Network ID (status symbols already removed).

    The NID is a BCH(63,16,23) codeword carrying the 12-bit NAC and 4-bit
    DUID, followed by one parity bit.  NAC and DUID are only reported when
    the BCH decode succeeds (``bch_ok``); otherwise they are None.

    Returns
    -------
    dict
        Keys: nac, duid, duid_name, bch_ok, bch_errors, parity_ok.

    Raises
    ------
    DecodeError
        If fewer than 64 bits are provided.
    """
    if len(bits) < 64:
        raise DecodeError(f"NID requires 64 bits, got {len(bits)}")

    decoded = bch_63_16_decode(bits[:63])
    if decoded is None:
        return {
            "nac": None,
            "duid": None,
            "duid_name": None,
            "bch_ok": False,
            "bch_errors": None,
            "parity_ok": None,
        }

    info, n_errors = decoded
    nac = _bits_to_int(info[0:12])
    duid = _bits_to_int(info[12:16])
    corrected = info + _int_to_bits(_bch_parity(_bits_to_int(info)), _BCH_N - _BCH_K)
    parity_ok = (sum(corrected) + (bits[63] & 1)) % 2 == 0

    try:
        duid_name = DUID(duid).name
    except ValueError:
        duid_name = f"UNKNOWN(0x{duid:X})"

    return {
        "nac": nac,
        "duid": duid,
        "duid_name": duid_name,
        "bch_ok": True,
        "bch_errors": n_errors,
        "parity_ok": parity_ok,
    }


def _bch_parity(info16: int) -> int:
    """47 systematic parity bits for a 16-bit BCH(63,16) information word."""
    rem = info16 << (_BCH_N - _BCH_K)
    for bit in range(_BCH_N - 1, _BCH_N - _BCH_K - 1, -1):
        if rem & (1 << bit):
            rem ^= BCH_63_16_GENERATOR << (bit - (_BCH_N - _BCH_K))
    return rem


# ---------------------------------------------------------------------------
# Frame decoders
# ---------------------------------------------------------------------------


def decode_hdu(bits: list[int]) -> dict:
    """Decode a Header Data Unit (HDU).

    Extracts the Message Indicator, Manufacturer ID, Algorithm ID,
    Key ID, and Talk Group ID from the HDU bit fields.

    Parameters
    ----------
    bits : list[int]
        HDU data bits (at least 328 bits after NID).

    Returns
    -------
    dict
        Keys: mi (bytes, 9), mfid (int), algid (int), algid_name (str),
        kid (int), tgid (int), encrypted (bool).

    Raises
    ------
    DecodeError
        If insufficient bits are provided.
    """
    if len(bits) < 328:
        raise DecodeError(f"HDU requires at least 328 bits, got {len(bits)}")

    offset = 0

    # Message Indicator — 72 bits (9 bytes)
    mi_val = _bits_to_int(bits[offset : offset + 72])
    mi_bytes = mi_val.to_bytes(9, "big")
    offset += 72

    # MFID — 8 bits
    mfid = _bits_to_int(bits[offset : offset + 8])
    offset += 8

    # ALGID — 8 bits
    algid = _bits_to_int(bits[offset : offset + 8])
    offset += 8

    # KID — 16 bits
    kid = _bits_to_int(bits[offset : offset + 16])
    offset += 16

    # TGID — 16 bits
    tgid = _bits_to_int(bits[offset : offset + 16])

    encrypted = algid != ALGID_UNENCRYPTED

    return {
        "mi": mi_bytes,
        "mfid": mfid,
        "algid": algid,
        "algid_name": _ALGID_NAMES.get(algid, f"0x{algid:02X}"),
        "kid": kid,
        "tgid": tgid,
        "encrypted": encrypted,
    }


def decode_ldu1(bits: list[int]) -> dict:
    """Decode a Link Data Unit 1 (LDU1).

    Extracts the Link Control Word carrying unit addressing and
    the emergency flag.

    Parameters
    ----------
    bits : list[int]
        LDU1 LC data bits (at least 72 bits).

    Returns
    -------
    dict
        Keys: lc_format (int), mfid (int), source_unit (int),
        dest_unit_or_tgid (int), emergency (bool).

    Raises
    ------
    DecodeError
        If insufficient bits are provided.
    """
    if len(bits) < 72:
        raise DecodeError(f"LDU1 LC requires at least 72 bits, got {len(bits)}")

    lc_format = _bits_to_int(bits[0:8])
    mfid = _bits_to_int(bits[8:16])

    # Emergency flag is bit 16 of the LC
    emergency = bool(bits[16])

    source_unit = _bits_to_int(bits[24:48])
    dest_unit_or_tgid = _bits_to_int(bits[48:72])

    return {
        "lc_format": lc_format,
        "mfid": mfid,
        "source_unit": source_unit,
        "dest_unit_or_tgid": dest_unit_or_tgid,
        "emergency": emergency,
    }


def decode_ldu2(bits: list[int]) -> dict:
    """Decode a Link Data Unit 2 (LDU2).

    Extracts the Encryption Sync Word: Message Indicator, Algorithm ID,
    and Key ID.

    Parameters
    ----------
    bits : list[int]
        LDU2 encryption sync bits (at least 96 bits).

    Returns
    -------
    dict
        Keys: mi (bytes, 9), algid (int), algid_name (str), kid (int),
        encrypted (bool).

    Raises
    ------
    DecodeError
        If insufficient bits are provided.
    """
    if len(bits) < 96:
        raise DecodeError(f"LDU2 ES requires at least 96 bits, got {len(bits)}")

    mi_val = _bits_to_int(bits[0:72])
    mi_bytes = mi_val.to_bytes(9, "big")

    algid = _bits_to_int(bits[72:80])
    kid = _bits_to_int(bits[80:96])
    encrypted = algid != ALGID_UNENCRYPTED

    return {
        "mi": mi_bytes,
        "algid": algid,
        "algid_name": _ALGID_NAMES.get(algid, f"0x{algid:02X}"),
        "kid": kid,
        "encrypted": encrypted,
    }


def decode_tsbk(bits: list[int]) -> dict:
    """Decode a Trunking Signaling Block (TSBK).

    Parameters
    ----------
    bits : list[int]
        TSBK data bits (at least 80 bits).

    Returns
    -------
    dict
        Keys: opcode (int), source (int), target (int), channel_info (int),
        last_block (bool).

    Raises
    ------
    DecodeError
        If insufficient bits are provided.
    """
    if len(bits) < 80:
        raise DecodeError(f"TSBK requires at least 80 bits, got {len(bits)}")

    # Bit 0: last block flag
    last_block = bool(bits[0])

    opcode = _bits_to_int(bits[8:16])
    source = _bits_to_int(bits[16:40])
    target = _bits_to_int(bits[40:64])
    channel_info = _bits_to_int(bits[64:80])

    return {
        "opcode": opcode,
        "source": source,
        "target": target,
        "channel_info": channel_info,
        "last_block": last_block,
    }


# ---------------------------------------------------------------------------
# P25 Decoder
# ---------------------------------------------------------------------------


class P25Decoder(ProtocolDecoder):
    """APCO Project 25 Phase 1 protocol decoder."""

    def protocol_name(self) -> str:
        return "p25"

    def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
        """Decode a raw P25 frame from bytes.

        The raw bytes are treated as a packed bit stream.  The decoder
        searches for the 48-bit frame sync, extracts the NID, and then
        dispatches to the appropriate frame-type decoder.

        Parameters
        ----------
        raw : bytes
            Raw captured bytes containing a P25 frame.
        **kwargs
            Optional: ``bit_offset`` (int) to skip leading bits.

        Returns
        -------
        DecodedPacket

        Raises
        ------
        FrameSyncError
            If no P25 frame sync is found.
        DecodeError
            On other decode failures.
        """
        bit_offset = kwargs.get("bit_offset", 0)

        # Unpack bytes to bits
        bits: list[int] = []
        for byte in raw:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        bits = bits[bit_offset:]

        # Find frame sync
        sync_offset = detect_frame_sync(bits)
        if sync_offset is None:
            raise FrameSyncError("P25 frame sync not found in input")

        # Status dibits are interleaved from the frame sync onwards.
        frame = strip_status_symbols(bits[sync_offset:])
        pos = _FRAME_SYNC_LEN

        # Decode NID
        if len(frame) < pos + 64:
            raise DecodeError("Truncated frame: insufficient bits for NID")

        nid = decode_nid(frame[pos : pos + 64])
        pos += 64

        errors: list[str] = []
        metadata: dict = {"nid": nid, "sync_offset": sync_offset}

        if not nid["bch_ok"]:
            errors.append("NID BCH(63,16) decode failed: uncorrectable")
            return DecodedPacket(
                protocol="p25",
                raw_bytes=raw,
                payload=b"",
                metadata=metadata,
                confidence=0.0,
                errors=errors,
            )

        # The data-unit bodies are protected by Golay/Hamming/RS/trellis
        # codes that are not decoded here, so no body fields are reported.
        remaining = frame[pos:]
        metadata["body_bits"] = len(remaining)
        metadata["body_fields_decoded"] = False

        payload_bytes = bytearray()
        for i in range(0, len(remaining) - 7, 8):
            payload_bytes.append(_bits_to_int(remaining[i : i + 8]))

        # 0.95 for a clean NID, falling to 0.5 at the 11-error BCH limit.
        confidence = 0.95 - 0.45 * nid["bch_errors"] / _BCH_T

        return DecodedPacket(
            protocol="p25",
            raw_bytes=raw,
            payload=bytes(payload_bytes),
            metadata=metadata,
            confidence=round(confidence, 4),
            errors=errors,
        )

    def extract_messages(self, packet: DecodedPacket) -> list[DecodedMessage]:
        """Extract higher-level messages from a decoded P25 packet.

        Emits one message per frame whose NID passed BCH(63,16) decoding:
        the message type follows the DUID and the metadata carries the
        NAC.  Unit IDs, talk groups and encryption fields are not reported,
        because the data-unit bodies' FEC is not decoded.  Frames whose NID
        failed BCH decoding yield no messages.

        Parameters
        ----------
        packet : DecodedPacket
            A previously decoded P25 packet.

        Returns
        -------
        list[DecodedMessage]
        """
        meta = packet.metadata
        nid = meta.get("nid", {})
        if not nid.get("bch_ok"):
            return []

        duid = nid.get("duid")
        return [
            DecodedMessage(
                protocol="p25",
                source_id="",
                dest_id="",
                message_type=_DUID_MESSAGE_TYPES.get(duid, "unknown_duid"),
                payload=b"" if duid in (DUID.TDU, DUID.TDULC) else packet.payload,
                metadata={
                    "nac": nid.get("nac"),
                    "duid": duid,
                    "duid_name": nid.get("duid_name"),
                    "bch_errors": nid.get("bch_errors"),
                    "body_fields_decoded": False,
                },
                confidence=packet.confidence,
            )
        ]


# Message type per DUID (only the NID is FEC-decoded; see decode_packet).
_DUID_MESSAGE_TYPES: dict[int, str] = {
    DUID.HDU: "hdu_call_setup",
    DUID.LDU1: "ldu1_voice",
    DUID.LDU2: "ldu2_encryption_sync",
    DUID.TSDU: "tsbk_trunking",
    DUID.TDU: "tdu_termination",
    DUID.TDULC: "tdulc_termination",
    DUID.PDU: "pdu_data",
}
