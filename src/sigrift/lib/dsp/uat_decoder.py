"""UAT (Universal Access Transceiver) 978 MHz ADS-B downlink decoder.

Implements the DO-282B ADS-B downlink:

* **Demodulation** -- UAT is binary CPFSK (h = 0.6, 1.041667 Mbit/s): a
  ``1`` is a positive frequency deviation, a ``0`` a negative one.  The
  signal has a constant envelope, so bits come from an FM discriminator
  (the phase difference between successive samples), not from the
  amplitude.
* **Sync** -- the 36-bit ADS-B sync word ``0xEACDDA4E2`` (up to 4 bit
  errors) precedes the frame.
* **FEC** -- Basic frames are RS(30,18) and Long frames RS(48,34) over
  GF(256) with field polynomial x^8 + x^7 + x^2 + x + 1 (0x187) and
  generator roots alpha^120 .. alpha^(120 + nroots - 1).  A frame is only
  decoded when RS decoding succeeds (and its payload type matches the
  frame length); anything else is dropped.  There is no CRC in UAT ADS-B.
* **Fields** -- header (payload type, address qualifier, address), state
  vector (lat/lon/altitude/NIC) and, for payload types 1 and 3, the mode
  status element (emitter category, call sign, NACp), all read from the
  RS-corrected payload.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

# UAT bit rate: 1.041667 Mbps (bit period = 0.96 us)
UAT_BIT_RATE = 1_041_667

# UAT sync words (36 bits).  The ground uplink uses the bitwise complement.
_SYNC_ADSB = 0xEACDDA4E2
_SYNC_UPLINK = 0x153225B1D
_SYNC_BITS = 36
_SYNC_MAX_ERRORS = 4

# Kept for callers of the old names (the "long" name was always the uplink
# sync word, which this module does not decode).
_SYNC_BASIC = _SYNC_ADSB
_SYNC_LONG = _SYNC_UPLINK

# Frame geometry (bytes): payload + RS parity.
_BASIC_DATA = 18
_BASIC_PARITY = 12
_LONG_DATA = 34
_LONG_PARITY = 14
_BASIC_BITS = (_BASIC_DATA + _BASIC_PARITY) * 8  # 240
_LONG_BITS = (_LONG_DATA + _LONG_PARITY) * 8  # 384

# Emitter category descriptions (DO-282B Table 2-75)
_EMITTER_CATEGORIES = {
    0: "no_info",
    1: "light",
    2: "small",
    3: "large",
    4: "high_vortex_large",
    5: "heavy",
    6: "high_performance",
    7: "rotorcraft",
    9: "glider",
    10: "lighter_than_air",
    11: "parachutist",
    12: "ultralight",
    14: "unmanned_aerial_vehicle",
    15: "space_vehicle",
    17: "surface_emergency_vehicle",
    18: "surface_service_vehicle",
    19: "point_obstacle",
    20: "cluster_obstacle",
}

# Mode-status call sign alphabet (base 40).
_BASE40 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ  .."


@dataclass
class UATMessage:
    """Decoded UAT ADS-B message (fields taken from the RS-corrected payload)."""

    icao_address: str
    msg_type: str
    lat: float | None
    lon: float | None
    altitude_ft: float | None
    nic: int | None
    nac: int | None
    emitter_category: int | None
    raw_bytes: bytes
    payload_type: int | None = None
    address_qualifier: int | None = None
    callsign: str | None = None
    rs_errors: int = 0


# ---------------------------------------------------------------------------
# GF(256) Reed-Solomon (DO-282B parameters)
# ---------------------------------------------------------------------------

_GF_POLY = 0x187
_RS_FCR = 120

_GF_EXP = [0] * 512
_GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    _GF_EXP[_i] = _x
    _GF_LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= _GF_POLY
for _i in range(255, 512):
    _GF_EXP[_i] = _GF_EXP[_i - 255]
del _x, _i


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_inv(a: int) -> int:
    return _GF_EXP[255 - _GF_LOG[a]]


def _gf_pow_alpha(e: int) -> int:
    return _GF_EXP[e % 255]


def _poly_eval_codeword(cw: list[int], x: int) -> int:
    """Evaluate the codeword polynomial (cw[0] is the highest power) at x."""
    acc = 0
    for c in cw:
        acc = _gf_mul(acc, x) ^ c
    return acc


def _rs_syndromes(cw: list[int], nroots: int) -> list[int]:
    return [_poly_eval_codeword(cw, _gf_pow_alpha(_RS_FCR + i)) for i in range(nroots)]


def rs_decode(block: bytes, nroots: int) -> tuple[bytes, int] | None:
    """Correct a (shortened) RS codeword; return (codeword, n_errors) or None.

    *block* is the whole codeword (data then parity).  Up to ``nroots // 2``
    byte errors are corrected.  None means the block is uncorrectable.
    """
    cw = list(block)
    n = len(cw)
    if n <= nroots or n > 255:
        return None
    synd = _rs_syndromes(cw, nroots)
    if not any(synd):
        return bytes(cw), 0

    # Berlekamp-Massey: error locator Lambda(x), lowest degree first.
    lam = [1] + [0] * nroots
    prev = [1] + [0] * nroots
    degree = 0
    shift = 1
    prev_disc = 1
    for k in range(nroots):
        disc = synd[k]
        for i in range(1, degree + 1):
            disc ^= _gf_mul(lam[i], synd[k - i])
        if disc == 0:
            shift += 1
            continue
        coef = _gf_mul(disc, _gf_inv(prev_disc))
        new = list(lam)
        for i in range(nroots + 1 - shift):
            new[i + shift] ^= _gf_mul(coef, prev[i])
        if 2 * degree <= k:
            prev = lam
            degree = k + 1 - degree
            prev_disc = disc
            shift = 1
        else:
            shift += 1
        lam = new

    if degree == 0 or degree > nroots // 2:
        return None

    # Chien search over the positions that exist in the shortened code.
    positions: list[int] = []
    for j in range(n):
        power = n - 1 - j
        x_inv = _gf_pow_alpha(-power)
        val = 0
        for i in range(degree, -1, -1):
            val = _gf_mul(val, x_inv) ^ lam[i]
        if val == 0:
            positions.append(j)
    if len(positions) != degree:
        return None

    # Omega(x) = S(x) * Lambda(x) mod x^nroots.
    omega = [0] * nroots
    for i in range(nroots):
        acc = 0
        for j in range(min(i, degree) + 1):
            acc ^= _gf_mul(lam[j], synd[i - j])
        omega[i] = acc

    # Forney: e = X^(1 - fcr) * Omega(X^-1) / Lambda'(X^-1).
    for j in positions:
        power = n - 1 - j
        x_inv = _gf_pow_alpha(-power)
        num = 0
        for i in range(nroots - 1, -1, -1):
            num = _gf_mul(num, x_inv) ^ omega[i]
        den = 0
        for i in range(1, degree + 1, 2):  # formal derivative: odd terms
            den ^= _gf_mul(lam[i], _gf_pow_alpha(-power * (i - 1)))
        if den == 0:
            return None
        mag = _gf_mul(_gf_mul(num, _gf_inv(den)), _gf_pow_alpha(power * (1 - _RS_FCR)))
        cw[j] ^= mag

    if any(_rs_syndromes(cw, nroots)):
        return None
    return bytes(cw), degree


def _uat_fec_check(data: bytes, expected_len: int) -> bool:
    """Return True when *data* is a valid (correctable) UAT RS codeword.

    *expected_len* is the codeword length: 30 (Basic) or 48 (Long).
    """
    if expected_len == _BASIC_DATA + _BASIC_PARITY:
        nroots = _BASIC_PARITY
    elif expected_len == _LONG_DATA + _LONG_PARITY:
        nroots = _LONG_PARITY
    else:
        return False
    if len(data) < expected_len:
        return False
    return rs_decode(bytes(data[:expected_len]), nroots) is not None


def correct_adsb_frame(frame: bytes) -> tuple[bytes, int] | None:
    """RS-correct a downlink frame; return (payload, n_errors) or None.

    Tries Long (RS(48,34), payload type != 0) first, then Basic
    (RS(30,18), payload type == 0), as the frame length is not signalled.
    """
    if len(frame) >= _LONG_DATA + _LONG_PARITY:
        res = rs_decode(bytes(frame[: _LONG_DATA + _LONG_PARITY]), _LONG_PARITY)
        if res is not None and (res[0][0] >> 3) != 0:
            return res[0][:_LONG_DATA], res[1]
    if len(frame) >= _BASIC_DATA + _BASIC_PARITY:
        res = rs_decode(bytes(frame[: _BASIC_DATA + _BASIC_PARITY]), _BASIC_PARITY)
        if res is not None and (res[0][0] >> 3) == 0:
            return res[0][:_BASIC_DATA], res[1]
    return None


# ---------------------------------------------------------------------------
# Demodulation
# ---------------------------------------------------------------------------


def _sync_bits(word: int) -> np.ndarray:
    return np.array([(word >> (_SYNC_BITS - 1 - i)) & 1 for i in range(_SYNC_BITS)])


def demodulate_uat(iq: np.ndarray, sample_rate: float) -> np.ndarray:
    """Demodulate a UAT ADS-B burst to the bits that follow its sync word.

    FM discriminator (phase difference of successive samples, positive =
    ``1``), then a search for the 36-bit ADS-B sync word over every sample
    phase.  Returns up to 384 bits after the sync (a Long frame; a Basic
    frame uses the first 240), or an empty array when no sync is found.
    """
    iq = np.asarray(iq)
    sps = float(sample_rate) / UAT_BIT_RATE
    if len(iq) < 2 or sps < 1.0:
        return np.array([], dtype=np.int32)

    x = iq.astype(np.complex128)
    disc = np.angle(x[1:] * np.conj(x[:-1]))
    sync = _sync_bits(_SYNC_ADSB)
    n_disc = len(disc)

    # Integrate the discriminator over each bit so noise averages out.
    win = max(1, int(round(sps)))
    smoothed = np.convolve(disc, np.ones(win), mode="full")[win - 1 : n_disc + win - 1]

    def _sample(start: float, count: int) -> np.ndarray | None:
        # Bit k is centred at start + (k + 0.5) * sps; the smoothed value at
        # index m covers disc[m - win + 1 .. m], so read at the bit's end.
        idx = np.floor(start + (np.arange(count) + 1.0) * sps - 1.0).astype(int)
        if idx[-1] >= n_disc or idx[0] < 0:
            return None
        return (smoothed[idx] > 0).astype(np.int32)

    best: tuple[int, float] | None = None
    max_start = n_disc - int(np.ceil((_SYNC_BITS + _BASIC_BITS) * sps))
    for start in range(max(0, max_start + 1)):
        bits = _sample(float(start), _SYNC_BITS)
        if bits is None:
            break
        errors = int(np.count_nonzero(bits != sync))
        if errors <= _SYNC_MAX_ERRORS and (best is None or errors < best[0]):
            best = (errors, float(start))
            if errors == 0:
                break
    if best is None:
        return np.array([], dtype=np.int32)

    data_start = best[1] + _SYNC_BITS * sps
    available = int((n_disc - data_start) // sps)
    count = min(_LONG_BITS, available)
    if count < _BASIC_BITS:
        return np.array([], dtype=np.int32)
    out = _sample(data_start, count)
    return out if out is not None else np.array([], dtype=np.int32)


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    """Convert bit array to bytes, MSB first."""
    n_bytes = len(bits) // 8
    result = bytearray(n_bytes)
    for i in range(n_bytes):
        val = 0
        for j in range(8):
            val = (val << 1) | int(bits[i * 8 + j])
        result[i] = val
    return bytes(result)


# ---------------------------------------------------------------------------
# Field decoding (corrected payload only)
# ---------------------------------------------------------------------------


def _decode_lat_lon(data: bytes, offset: int = 4) -> tuple[float | None, float | None]:
    """Decode the state-vector position (23-bit lat, 24-bit lon, LSB 360/2^24).

    Returns (None, None) when NIC and both raw fields are zero (no position).
    """
    if len(data) < offset + 8:
        return None, None
    raw_lat = (data[offset] << 15) | (data[offset + 1] << 7) | (data[offset + 2] >> 1)
    raw_lon = (
        ((data[offset + 2] & 0x01) << 23)
        | (data[offset + 3] << 15)
        | (data[offset + 4] << 7)
        | (data[offset + 5] >> 1)
    )
    nic = data[offset + 7] & 0x0F
    if nic == 0 and raw_lat == 0 and raw_lon == 0:
        return None, None
    lat = raw_lat * 360.0 / 16777216.0
    if lat > 90.0:
        lat -= 180.0
    lon = raw_lon * 360.0 / 16777216.0
    if lon > 180.0:
        lon -= 360.0
    return lat, lon


def _decode_altitude_uat(data: bytes, offset: int = 10) -> float | None:
    """Decode the 12-bit altitude: 0 = unknown, else (raw - 1) * 25 - 1000 ft."""
    if len(data) < offset + 2:
        return None
    raw = (data[offset] << 4) | (data[offset + 1] >> 4)
    if raw == 0:
        return None
    return float((raw - 1) * 25 - 1000)


def _decode_mode_status(data: bytes) -> tuple[int, str, int]:
    """Return (emitter_category, callsign, nac_p) from the MS element."""
    v1 = (data[17] << 8) | data[18]
    v2 = (data[19] << 8) | data[20]
    v3 = (data[21] << 8) | data[22]
    emitter = (v1 // 1600) % 40
    chars = [
        _BASE40[(v1 // 40) % 40],
        _BASE40[v1 % 40],
        _BASE40[(v2 // 1600) % 40],
        _BASE40[(v2 // 40) % 40],
        _BASE40[v2 % 40],
        _BASE40[(v3 // 1600) % 40],
        _BASE40[(v3 // 40) % 40],
        _BASE40[v3 % 40],
    ]
    nac_p = (data[25] >> 4) & 0x0F
    return emitter, "".join(chars).rstrip(), nac_p


def decode_uat_message(bits: np.ndarray) -> UATMessage | None:
    """Decode a UAT ADS-B frame from the bits after the sync word.

    *bits* must hold at least a Basic frame (240 bits); 384 bits allow a
    Long frame.  The frame is RS-corrected first and dropped (None) when
    correction fails, so every returned field is backed by the FEC.
    """
    if len(bits) < _BASIC_BITS:
        return None

    frame = _bits_to_bytes(np.asarray(bits)[:_LONG_BITS])
    corrected = correct_adsb_frame(frame)
    if corrected is None:
        logger.debug("UAT frame failed Reed-Solomon decoding; dropped")
        return None
    data, n_errors = corrected

    payload_type = data[0] >> 3
    address_qualifier = data[0] & 0x07
    icao = f"{data[1]:02X}{data[2]:02X}{data[3]:02X}"

    if address_qualifier in (2, 3):
        msg_type = "tisb"
    elif payload_type == 0:
        msg_type = "basic"
    else:
        msg_type = "long"

    # The State Vector (position, altitude, NIC) is only present for payload
    # type codes 0-10 (DO-282B; cf. dump978 uat_decode_adsb_mdb, which decodes
    # the SV only for mdb_type 0-10 and treats 11-31 as header-only reserved
    # types).  Decoding SV bytes for a reserved type would invent a position
    # and altitude from fields that are not a state vector.
    if payload_type <= 10:
        lat, lon = _decode_lat_lon(data)
        altitude = _decode_altitude_uat(data)
        nic = data[11] & 0x0F
    else:
        lat = lon = None
        altitude = None
        nic = None

    emitter_cat: int | None = None
    callsign: str | None = None
    nac: int | None = None
    if payload_type in (1, 3) and len(data) >= _LONG_DATA:
        emitter_cat, callsign, nac = _decode_mode_status(data)
        callsign = callsign or None

    return UATMessage(
        icao_address=icao,
        msg_type=msg_type,
        lat=lat,
        lon=lon,
        altitude_ft=altitude,
        nic=nic,
        nac=nac,
        emitter_category=emitter_cat,
        raw_bytes=bytes(data),
        payload_type=payload_type,
        address_qualifier=address_qualifier,
        callsign=callsign,
        rs_errors=n_errors,
    )
