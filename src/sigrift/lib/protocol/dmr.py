"""DMR (Digital Mobile Radio) ETSI TS 102 361 decoder.

Implements sync detection, burst framing, slot-type Golay(20,8) decoding,
BPTC(196,96) de-interleaving with Hamming(15,11)/(13,9) error correction,
and per-data-type integrity checks (CRC-CCITT with the data-type mask,
RS(12,9) for full link control) before any field is reported.

Burst layout (264 bits, ETSI TS 102 361-1 clause 4.2)::

    info 98 | slot type 10 | sync / embedded 48 | slot type 10 | info 98

Voice bursts carry 108 + 108 voice bits around the sync and no slot type.

Reference: ETSI TS 102 361-1 (DMR air interface protocol), annex B (FEC
and CRC).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import numpy as np

from sigrift.lib.protocol.base import (
    DecodedMessage,
    DecodedPacket,
    FrameSyncError,
    ProtocolDecoder,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DMR sync patterns (48 bits)
# ---------------------------------------------------------------------------

SYNC_BS_VOICE = 0x755FD7DF75F7
SYNC_BS_DATA = 0xDFF57D75DF5D
SYNC_MS_VOICE = 0x7F7D5DD57DFD
SYNC_MS_DATA = 0xD5D7F77FD757

_SYNC_PATTERNS = {
    "bs_voice": SYNC_BS_VOICE,
    "bs_data": SYNC_BS_DATA,
    "ms_voice": SYNC_MS_VOICE,
    "ms_data": SYNC_MS_DATA,
}

_SYNC_BITS: dict[str, list[int]] = {}
for _name, _val in _SYNC_PATTERNS.items():
    _SYNC_BITS[_name] = [(_val >> (47 - i)) & 1 for i in range(48)]

# Maximum Hamming distance for sync detection (allow a few bit errors)
_SYNC_MAX_ERRORS = 4

# Burst geometry (ETSI TS 102 361-1 figure 4.2).
_BURST_LEN = 264
_INFO1_BITS = 98
_SLOT_TYPE_HALF = 10
_SYNC_BITS_LEN = 48
_INFO2_BITS = 98
_SYNC_START = _INFO1_BITS + _SLOT_TYPE_HALF  # 108
_SYNC_END = _SYNC_START + _SYNC_BITS_LEN  # 156
_INFO2_START = _SYNC_END + _SLOT_TYPE_HALF  # 166

_BPTC_DATA_BITS = 96

# Slot-type data types (ETSI TS 102 361-1 table 6.x).
_DATA_TYPES = {
    0: "PI_HEADER",
    1: "VOICE_LC_HEADER",
    2: "TERMINATOR_WITH_LC",
    3: "CSBK",
    4: "MBC_HEADER",
    5: "MBC_CONTINUATION",
    6: "DATA_HEADER",
    7: "RATE_1_2_DATA",
    8: "RATE_3_4_DATA",
    9: "IDLE",
    10: "RATE_1_DATA",
}

# BPTC(196,96)-coded data types.
_BPTC_TYPES = {0, 1, 2, 3, 4, 5, 6, 7, 9}

# CRC-CCITT masks per data type (annex B, table B.21).
_CRC16_MASKS = {0: 0x6969, 3: 0xA5A5, 4: 0xAAAA, 6: 0xCCCC}

# RS(12,9) parity masks for full link control.
_RS_LC_MASKS = {1: 0x96, 2: 0x99}

# Recognised CSBK opcodes (CSBKO), ETSI TS 102 361-2 table 7.1.
_CSBK_OPCODES = {
    0x04: "UU_V_REQ",
    0x05: "UU_ANS_RSP",
    0x07: "CT_CSBK",
    0x26: "NACK_RSP",
    0x38: "BS_DWN_ACT",
    0x3D: "PREAMBLE",
}

# Per-opcode address-field layout.  The CSBK address fields are NOT in the
# same order for every opcode, so a single "target @ 4-6, source @ 7-9" rule
# mislabels several of them (ETSI TS 102 361-2; cf. MMDVMHost DMRCSBK.cpp).
# Each entry maps a field name to the (start, stop) bit slice within the
# 96-bit CSBK payload (octet N spans bits 8N..8N+7).  Opcodes absent here, and
# CT_CSBK (channel-timing fields, no unit addresses), carry no source/target.
_CSBK_ADDR_FIELDS: dict[int, dict[str, tuple[int, int]]] = {
    0x04: {"target": (32, 56), "source": (56, 80)},  # UU_V_Req
    0x05: {"target": (32, 56), "source": (56, 80)},  # UU_Ans_Rsp
    0x3D: {"target": (32, 56), "source": (56, 80)},  # Preamble
    0x26: {"source": (32, 56), "target": (56, 80)},  # NACK_Rsp (source first)
    0x38: {"bs_id": (32, 56), "source": (56, 80)},  # BS_Dwn_Act (BS id, no tgt)
    0x07: {},  # CT_CSBK: sync age / generation / leader IDs, no src/tgt
}

# Full LC opcodes.
_FLCO_NAMES = {0x00: "GROUP_VOICE", 0x03: "UNIT_TO_UNIT_VOICE"}


# ---------------------------------------------------------------------------
# Golay(20,8): shortened extended Golay(24,12), g(x) = 0xC75, plus an
# overall even-parity bit (annex B.3.1).  Corrects up to 3 bit errors.
# ---------------------------------------------------------------------------

_GOLAY_G = 0xC75


def _golay2087_parity(info8: int) -> int:
    rem = info8 << 11
    for bit in range(18, 10, -1):
        if rem & (1 << bit):
            rem ^= _GOLAY_G << (bit - 11)
    p11 = rem & 0x7FF
    overall = (bin(info8).count("1") + bin(p11).count("1")) & 1
    return (p11 << 1) | overall


def golay2087_encode(info8: int) -> int:
    """Return the 20-bit codeword (info in the top 8 bits)."""
    return ((info8 & 0xFF) << 12) | _golay2087_parity(info8 & 0xFF)


_GOLAY_SYNDROMES: dict[int, int] | None = None


def _golay_syndrome(cw20: int) -> int:
    return _golay2087_parity(cw20 >> 12) ^ (cw20 & 0xFFF)


def _golay_table() -> dict[int, int]:
    global _GOLAY_SYNDROMES
    if _GOLAY_SYNDROMES is None:
        table: dict[int, int] = {}
        for a in range(20):
            for b in range(a, 20):
                for c in range(b, 20):
                    e = (1 << a) | (1 << b) | (1 << c)
                    table.setdefault(_golay_syndrome(e), e)
        _GOLAY_SYNDROMES = table
    return _GOLAY_SYNDROMES


def golay2087_decode(cw20: int) -> tuple[int, int] | None:
    """Decode a 20-bit codeword; return (info8, n_corrected) or None."""
    s = _golay_syndrome(cw20)
    if s == 0:
        return cw20 >> 12, 0
    e = _golay_table().get(s)
    if e is None:
        return None
    return (cw20 ^ e) >> 12, bin(e).count("1")


# ---------------------------------------------------------------------------
# Hamming(15,11,3) / (13,9,3): cyclic Hamming code g(x) = x^4 + x + 1 and
# its shortened form (annex B.3.4 / B.3.5).  Bits are MSB (highest degree)
# first; the 4 parity bits follow the data bits.
# ---------------------------------------------------------------------------


def _hamming_parity(data_bits: list[int]) -> list[int]:
    rem = 0
    for b in data_bits + [0, 0, 0, 0]:
        rem = (rem << 1) | b
        if rem & 0x10:
            rem ^= 0x13
    return [(rem >> 3) & 1, (rem >> 2) & 1, (rem >> 1) & 1, rem & 1]


def _hamming_correct(word: list[int]) -> tuple[list[int], bool, bool]:
    """Correct one bit; return (word, corrected, ok)."""
    k = len(word) - 4
    if _hamming_parity(word[:k]) == word[k:]:
        return word, False, True
    for i in range(len(word)):
        trial = list(word)
        trial[i] ^= 1
        if _hamming_parity(trial[:k]) == trial[k:]:
            return trial, True, True
    return word, False, False


# ---------------------------------------------------------------------------
# CRC-CCITT and RS(12,9)
# ---------------------------------------------------------------------------


def _crc_ccitt(data: bytes) -> int:
    """CRC-CCITT (x^16 + x^12 + x^5 + 1), init 0, inverted (annex B.3.7)."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc ^ 0xFFFF


_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]
del _x, _i


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs129_ok(block12: bytes) -> bool:
    """True when the RS(12,9) syndromes at alpha^1..alpha^3 are all zero."""
    for root in (_GF_EXP[1], _GF_EXP[2], _GF_EXP[3]):
        acc = 0
        for c in block12:
            acc = _gf_mul(acc, root) ^ c
        if acc:
            return False
    return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bits_to_int(bits: list[int]) -> int:
    val = 0
    for b in bits:
        val = (val << 1) | (b & 1)
    return val


def _bits_to_bytes(bits: list[int]) -> bytes:
    padded = list(bits) + [0] * ((-len(bits)) % 8)
    return bytes(_bits_to_int(padded[i : i + 8]) for i in range(0, len(padded), 8))


# ---------------------------------------------------------------------------
# DMR Decoder
# ---------------------------------------------------------------------------


class DMRDecoder(ProtocolDecoder):
    """DMR Tier II protocol decoder."""

    def protocol_name(self) -> str:
        return "dmr"

    # -- 4FSK symbol to bit conversion --------------------------------------

    @staticmethod
    def symbols_to_bits(symbols: np.ndarray | list[float]) -> list[int]:
        """Convert 4FSK symbols to dibit pairs.

        DMR 4FSK deviation levels map to dibits:
            +3 -> 01
            +1 -> 00
            -1 -> 10
            -3 -> 11
        """
        symbols_arr = np.asarray(symbols, dtype=np.float64).ravel()
        if len(symbols_arr) == 0:
            return []

        max_abs = np.max(np.abs(symbols_arr))
        if max_abs > 0:
            symbols_arr = symbols_arr * (3.0 / max_abs)

        bits: list[int] = []
        for s in symbols_arr:
            if s >= 2.0:
                bits.extend([0, 1])  # +3
            elif s >= 0.0:
                bits.extend([0, 0])  # +1
            elif s >= -2.0:
                bits.extend([1, 0])  # -1
            else:
                bits.extend([1, 1])  # -3

        return bits

    # -- Sync detection -----------------------------------------------------

    @staticmethod
    def detect_sync(
        bits: list[int], min_offset: int = 0, max_offset: int | None = None
    ) -> tuple[str, int]:
        """Find a DMR sync pattern starting in ``[min_offset, max_offset]``.

        Returns ``(sync_type, bit_offset)``: the first exact match, else the
        best one within the error threshold.  The window lets a caller
        consider only syncs whose whole 264-bit burst lies in the stream
        (``min_offset=108``, ``max_offset=len(bits) - 156``), so a cut-off
        burst at either end can never win over a complete one.  By default
        the whole stream is searched.

        Raises
        ------
        FrameSyncError
            If no sync pattern is found within the error threshold.
        """
        if len(bits) < _SYNC_BITS_LEN:
            raise FrameSyncError("Bit stream too short for sync detection")

        best_type = ""
        best_offset = -1
        best_errors = _SYNC_MAX_ERRORS + 1

        start = max(0, min_offset)
        stop = len(bits) - _SYNC_BITS_LEN
        if max_offset is not None:
            stop = min(stop, max_offset)
        for offset in range(start, stop + 1):
            window = bits[offset : offset + _SYNC_BITS_LEN]
            for sync_name, sync_bits in _SYNC_BITS.items():
                errors = 0
                for i in range(_SYNC_BITS_LEN):
                    if window[i] != sync_bits[i]:
                        errors += 1
                        if errors > _SYNC_MAX_ERRORS:
                            break
                if errors < best_errors:
                    best_errors = errors
                    best_type = sync_name
                    best_offset = offset
                if errors == 0:
                    return best_type, best_offset

        if best_offset >= 0 and best_errors <= _SYNC_MAX_ERRORS:
            return best_type, best_offset

        raise FrameSyncError("No DMR sync pattern found")

    # -- Burst extraction ---------------------------------------------------

    @staticmethod
    def extract_burst(bits: list[int], offset: int) -> dict:
        """Split the 264-bit burst whose sync starts at bit *offset*.

        Returns keys ``info1`` (98), ``slot_type`` (20: the 10 bits before
        and the 10 after the sync), ``sync`` (48), ``info2`` (98),
        ``burst_bits`` (264) and ``complete`` (False when the stream does
        not hold the whole burst; the missing bits are then absent, not
        padded, and the burst must not be decoded).
        """
        start = offset - _SYNC_START
        complete = start >= 0 and start + _BURST_LEN <= len(bits)
        burst = list(bits[max(0, start) : start + _BURST_LEN]) if complete else []
        if not complete:
            return {
                "info1": [],
                "slot_type": [],
                "sync": list(bits[offset : offset + _SYNC_BITS_LEN]),
                "info2": [],
                "burst_bits": [],
                "complete": False,
            }
        return {
            "info1": burst[0:_INFO1_BITS],
            "slot_type": burst[_INFO1_BITS:_SYNC_START] + burst[_SYNC_END:_INFO2_START],
            "sync": burst[_SYNC_START:_SYNC_END],
            "info2": burst[_INFO2_START:_BURST_LEN],
            "burst_bits": burst,
            "complete": True,
        }

    # -- BPTC(196,96) -------------------------------------------------------

    @staticmethod
    def _bptc_deinterleave_raw(bits: list[int]) -> list[int]:
        """Undo the (a * 181) mod 196 interleave; returns 196 bits."""
        raw = list(bits[:196]) + [0] * max(0, 196 - len(bits))
        return [raw[(a * 181) % 196] for a in range(196)]

    @staticmethod
    def _bptc_extract(deint: list[int]) -> list[int]:
        """Take the 96 data bits from a de-interleaved 196-bit matrix."""
        data = deint[4:12]  # row 0: R(2..0) at 1-3, then 8 data bits
        for r in range(1, 9):
            base = 1 + r * 15
            data += deint[base : base + 11]
        return data

    @classmethod
    def bptc_deinterleave(cls, bits: list[int]) -> list[int]:
        """BPTC(196,96) de-interleave and data extraction, without FEC.

        Use :meth:`bptc_decode` to also apply the Hamming row/column codes.
        """
        return cls._bptc_extract(cls._bptc_deinterleave_raw(bits))

    @classmethod
    def bptc_decode(cls, bits: list[int]) -> tuple[list[int], int] | None:
        """De-interleave and error-correct a BPTC(196,96) block.

        The de-interleaved matrix is 13 rows x 15 columns after the R(3)
        bit: rows 0-8 are Hamming(15,11,3) codewords, every column is a
        Hamming(13,9,3) codeword.  Rows and columns are corrected in turn
        until stable.  Returns (96 data bits, bits corrected) or None when
        a row or column still fails its check.
        """
        if len(bits) < 196:
            return None
        m = cls._bptc_deinterleave_raw(bits)
        corrected = 0
        for _ in range(5):
            changed = False
            for c in range(15):
                col = [m[1 + c + 15 * r] for r in range(13)]
                col, fixed, _ok = _hamming_correct(col)
                if fixed:
                    corrected += 1
                    changed = True
                    for r in range(13):
                        m[1 + c + 15 * r] = col[r]
            for r in range(9):
                base = 1 + 15 * r
                row, fixed, _ok = _hamming_correct(m[base : base + 15])
                if fixed:
                    corrected += 1
                    changed = True
                    m[base : base + 15] = row
            if not changed:
                break

        for r in range(9):
            base = 1 + 15 * r
            if _hamming_parity(m[base : base + 11]) != m[base + 11 : base + 15]:
                return None
        for c in range(15):
            col = [m[1 + c + 15 * r] for r in range(13)]
            if _hamming_parity(col[:9]) != col[9:]:
                return None
        return cls._bptc_extract(m), corrected

    # -- Field parsers (expect FEC/CRC-checked bits) --------------------------

    @staticmethod
    def decode_data_header(data_bits: list[int]) -> dict:
        """Parse a data header (data type 6) from 96 checked bits.

        Octet 0: G/I, A, HC, POC, DPF(4); octets 2-4 destination LLID;
        octets 5-7 source LLID.
        """
        if len(data_bits) < 64:
            return {"data_type": 0, "group": False, "dest_id": 0, "source_id": 0}
        return {
            "data_type": _bits_to_int(data_bits[4:8]),  # DPF
            "group": bool(data_bits[0]),
            "dest_id": _bits_to_int(data_bits[16:40]),
            "source_id": _bits_to_int(data_bits[40:64]),
        }

    @staticmethod
    def decode_csbk(data_bits: list[int]) -> dict:
        """Parse a CSBK from 96 checked bits.

        Octet 0: LB, PF, CSBKO(6); octet 1: FID.  The address-field order
        depends on the opcode (see ``_CSBK_ADDR_FIELDS``); opcodes with no
        unit addresses (e.g. CT_CSBK) report ``source``/``target`` as None.
        """
        if len(data_bits) < 80:
            return {
                "opcode": 0,
                "opcode_name": "UNKNOWN",
                "protect": False,
                "last": False,
                "source": None,
                "target": None,
            }
        opcode = _bits_to_int(data_bits[2:8])
        name = _CSBK_OPCODES.get(opcode)
        result: dict = {
            "opcode": opcode,
            "opcode_name": name or f"UNKNOWN_0x{opcode:02X}",
            "protect": bool(data_bits[1]),
            "last": bool(data_bits[0]),
            "fid": _bits_to_int(data_bits[8:16]),
            "source": None,
            "target": None,
        }
        for field, (lo, hi) in _CSBK_ADDR_FIELDS.get(opcode, {}).items():
            result[field] = _bits_to_int(data_bits[lo:hi])
        return result

    @staticmethod
    def decode_full_lc(data_bits: list[int]) -> dict:
        """Parse a full link control word (voice LC header / terminator)."""
        flco = _bits_to_int(data_bits[2:8])
        return {
            "protect": bool(data_bits[0]),
            "flco": flco,
            "flco_name": _FLCO_NAMES.get(flco, f"UNKNOWN_0x{flco:02X}"),
            "fid": _bits_to_int(data_bits[8:16]),
            "service_options": _bits_to_int(data_bits[16:24]),
            "dest_id": _bits_to_int(data_bits[24:48]),
            "source_id": _bits_to_int(data_bits[48:72]),
            "group": flco == 0x00,
        }

    # -- Packet decode ------------------------------------------------------

    def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
        """Decode a raw DMR burst.

        ``symbols=True`` treats *raw* as float32 4FSK symbols.  Fields are
        reported only when the slot type, BPTC and the data type's CRC/RS
        checks pass; otherwise the packet has confidence 0.0, no payload
        and a reason in ``errors``.
        """
        errors: list[str] = []
        now = datetime.now(timezone.utc).isoformat()
        metadata: dict = {}

        if kwargs.get("symbols", False):
            sym = np.frombuffer(raw, dtype=np.float32)
            bits = self.symbols_to_bits(sym)
            metadata["n_symbols"] = len(sym)
        else:
            bits = [(byte >> b) & 1 for byte in raw for b in range(7, -1, -1)]
        metadata["n_bits"] = len(bits)

        def _fail(reason: str) -> DecodedPacket:
            errors.append(reason)
            return DecodedPacket(
                protocol="dmr",
                raw_bytes=raw,
                payload=b"",
                metadata=metadata,
                timestamp=now,
                confidence=0.0,
                errors=errors,
            )

        # Only a sync whose whole 264-bit burst fits in the stream may be
        # chosen: 108 bits before it and 108 after its 48.  A capture that
        # starts or ends mid-burst has a cut-off sync at that end; searching
        # the full stream would let that sync (exact) win over a complete
        # burst whose sync has a bit error, and the decodable burst would be
        # skipped.
        try:
            sync_type, sync_offset = self.detect_sync(
                bits,
                min_offset=_SYNC_START,
                max_offset=len(bits) - (_BURST_LEN - _SYNC_START),
            )
        except FrameSyncError as exc:
            try:  # only cut-off bursts?  Say so rather than "no sync".
                self.detect_sync(bits)
            except FrameSyncError:
                return _fail(str(exc))
            return _fail("truncated burst: 264 bits around the sync not available")
        burst = self.extract_burst(bits, sync_offset)
        if not burst["complete"]:  # pragma: no cover - the window guarantees it
            return _fail("truncated burst: 264 bits around the sync not available")

        sync_errors = sum(
            a != b
            for a, b in zip(bits[sync_offset : sync_offset + 48], _SYNC_BITS[sync_type])
        )
        metadata["sync_type"] = sync_type
        metadata["sync_offset"] = sync_offset
        metadata["sync_errors"] = sync_errors
        metadata["burst_extracted"] = True

        if "voice" in sync_type:
            # Voice bursts: 216 AMBE bits, no slot type.  Only the sync is
            # checked here, so confidence reflects the sync match alone.
            voice = burst["burst_bits"][:_SYNC_START] + burst["burst_bits"][_SYNC_END:]
            return DecodedPacket(
                protocol="dmr",
                raw_bytes=raw,
                payload=_bits_to_bytes(voice),
                metadata=metadata,
                timestamp=now,
                confidence=round(0.8 - 0.1 * sync_errors, 4),
                errors=errors,
            )

        slot = golay2087_decode(_bits_to_int(burst["slot_type"]))
        if slot is None:
            return _fail("slot type Golay(20,8) uncorrectable")
        slot_info, golay_errors = slot
        data_type = slot_info & 0x0F
        metadata["slot_type"] = {
            "colour_code": slot_info >> 4,
            "data_type": data_type,
            "data_type_name": _DATA_TYPES.get(data_type, f"RESERVED_{data_type}"),
            "golay_errors": golay_errors,
        }
        corrections = golay_errors + sync_errors

        if data_type not in _BPTC_TYPES:
            # Rate 3/4 (trellis) and rate 1 data are not decoded here.
            metadata["payload_fec"] = "not decoded"
            return DecodedPacket(
                protocol="dmr",
                raw_bytes=raw,
                payload=b"",
                metadata=metadata,
                timestamp=now,
                confidence=round(max(0.3, 0.6 - 0.05 * corrections), 4),
                errors=errors,
            )

        bptc = self.bptc_decode(burst["info1"] + burst["info2"])
        if bptc is None:
            return _fail("BPTC(196,96) Hamming check failed")
        data_bits, bptc_errors = bptc
        metadata["bptc_errors"] = bptc_errors
        metadata["data_bits_len"] = len(data_bits)
        corrections += bptc_errors
        data = _bits_to_bytes(data_bits)

        verified = False
        if data_type in _CRC16_MASKS:
            crc = _crc_ccitt(data[:10]) ^ _CRC16_MASKS[data_type]
            if crc != (data[10] << 8) | data[11]:
                return _fail(f"{_DATA_TYPES[data_type]} CRC-CCITT mismatch")
            metadata["crc_ok"] = True
            verified = True
        elif data_type in _RS_LC_MASKS:
            mask = _RS_LC_MASKS[data_type]
            block = data[:9] + bytes(b ^ mask for b in data[9:12])
            if not _rs129_ok(block):
                return _fail(f"{_DATA_TYPES[data_type]} RS(12,9) check failed")
            metadata["rs_ok"] = True
            metadata["lc"] = self.decode_full_lc(data_bits)
            verified = True

        if data_type == 3:
            metadata["csbk"] = self.decode_csbk(data_bits)
        elif data_type == 6:
            metadata["data_header"] = self.decode_data_header(data_bits)

        # A data-type check (CRC/RS) backs the fields; FEC-only blocks
        # (idle, MBC continuation, rate 1/2 data) score lower.
        base = 0.95 if verified else 0.6
        confidence = max(0.3, base - 0.03 * corrections)

        return DecodedPacket(
            protocol="dmr",
            raw_bytes=raw,
            payload=data,
            metadata=metadata,
            timestamp=now,
            confidence=round(confidence, 4),
            errors=errors,
        )

    # -- Message extraction -------------------------------------------------

    def extract_messages(self, packet: DecodedPacket) -> list[DecodedMessage]:
        """Extract one message from a decoded DMR burst.

        Packets that failed a check (confidence 0, no payload) yield none.
        """
        if not packet.payload or packet.confidence <= 0.0:
            return []

        metadata = packet.metadata
        sync_type = metadata.get("sync_type", "unknown")
        is_voice = "voice" in sync_type

        source_id = ""
        dest_id = ""
        msg_type = "voice" if is_voice else "data"

        if "lc" in metadata:
            lc = metadata["lc"]
            source_id = str(lc["source_id"])
            dest_id = str(lc["dest_id"])
            dt = metadata["slot_type"]["data_type"]
            msg_type = "voice_lc_header" if dt == 1 else "terminator_lc"
        elif "data_header" in metadata:
            hdr = metadata["data_header"]
            source_id = str(hdr.get("source_id", ""))
            dest_id = str(hdr.get("dest_id", ""))
            if hdr.get("group"):
                msg_type = "group_data"
        elif "csbk" in metadata:
            csbk = metadata["csbk"]
            if not csbk["opcode_name"].startswith("UNKNOWN"):
                src = csbk.get("source")
                tgt = csbk.get("target")
                source_id = "" if src is None else str(src)
                dest_id = "" if tgt is None else str(tgt)
                msg_type = f"csbk_{csbk['opcode_name'].lower()}"
            else:
                msg_type = "csbk"

        return [
            DecodedMessage(
                protocol="dmr",
                source_id=source_id,
                dest_id=dest_id,
                message_type=msg_type,
                payload=packet.payload,
                metadata={
                    "sync_type": sync_type,
                    "is_voice": is_voice,
                    **{
                        k: v
                        for k, v in metadata.items()
                        if k not in ("burst_extracted",)
                    },
                },
                confidence=packet.confidence,
            )
        ]

    # -- Internal helpers ---------------------------------------------------

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        """Pack a bit list into bytes (MSB first, zero-padded)."""
        return _bits_to_bytes(bits)
