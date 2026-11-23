"""ADS-B Mode S and extended squitter decoder.

Demodulates PPM-encoded ADS-B signals at 1090 MHz, validates CRC-24,
and decodes position (CPR), velocity, and identification messages from
DF17/DF18 extended squitter frames.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)

# CRC-24 generator polynomial for Mode S (x^24 + x^23 + x^10 + x^3 + 1)
CRC24_POLY = 0xFFF409

# Callsign character set (AIS/ICAO encoding)
_CALLSIGN_CHARSET = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"

# CPR: number of geographic latitude zones between the equator and a pole
# (DO-260B §A.1.7.2).  NL() is derived from it in closed form below.
_CPR_NZ = 15
_CPR_NL_A = 1.0 - math.cos(math.pi / (2.0 * _CPR_NZ))


@dataclass
class ADSBMessage:
    """Decoded ADS-B message."""

    icao_address: str
    msg_type: int
    callsign: str | None
    altitude_ft: float | None
    lat: float | None
    lon: float | None
    velocity_kts: float | None
    heading_deg: float | None
    squawk: str | None
    raw_bits: str
    # Raw CPR fields of an airborne position frame (TC 9-18), normalised to
    # [0, 1).  A full position needs an even/odd pair: see decode_cpr().
    cpr_odd: bool | None = None
    cpr_lat: float | None = None
    cpr_lon: float | None = None


def _bits_to_int(bits: np.ndarray) -> int:
    """Convert a bit array to an integer, MSB first."""
    val = 0
    for b in bits:
        val = (val << 1) | int(b)
    return val


def _crc24(bits: np.ndarray) -> int:
    """Compute CRC-24 over a Mode S bit array.

    Parameters
    ----------
    bits : np.ndarray
        Bit array of length 112 (DF17/18) or 56 (short).

    Returns
    -------
    int
        24-bit CRC remainder.  Zero indicates valid frame.
    """
    n = len(bits)
    # Work on a mutable copy
    buf = np.array(bits, dtype=np.int32)
    poly_bits = np.zeros(25, dtype=np.int32)
    for i in range(25):
        poly_bits[24 - i] = (CRC24_POLY >> i) & 1

    for i in range(n - 24):
        if buf[i]:
            buf[i : i + 25] ^= poly_bits

    return _bits_to_int(buf[n - 24 : n])


def demodulate_ppm(iq: np.ndarray, sample_rate: float) -> np.ndarray:
    """Demodulate PPM-encoded ADS-B signal to bit stream.

    ADS-B uses pulse position modulation at 1 Mbps:
    - 8 us preamble: pulses at 0, 1, 3.5, 4.5 us
    - Data: 1 us chips, pulse in first 0.5 us = 1, second 0.5 us = 0

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples.
    sample_rate : float
        Sample rate in Hz (typically 2e6 for RTL-SDR).

    Returns
    -------
    np.ndarray
        Bit array (values 0 or 1).
    """
    if len(iq) == 0:
        return np.array([], dtype=np.int32)

    envelope = np.abs(iq)
    samples_per_us = sample_rate / 1e6
    samples_per_half_chip = max(1, int(samples_per_us * 0.5))
    samples_per_chip = max(1, int(samples_per_us))

    # Adaptive threshold: median + 2 * MAD
    median_val = np.median(envelope)
    mad = np.median(np.abs(envelope - median_val))
    threshold = median_val + 2.0 * max(mad, 1e-10)

    # Find preamble: strong pulses at 0, 1, 3.5, 4.5 us
    preamble_offsets_us = [0.0, 1.0, 3.5, 4.5]
    preamble_offsets = [int(t * samples_per_us) for t in preamble_offsets_us]
    preamble_len = int(8.0 * samples_per_us)

    best_offset = -1
    best_score = 0.0

    search_end = min(
        len(envelope) - preamble_len - 112 * samples_per_chip, len(envelope)
    )
    if search_end <= 0:
        return np.array([], dtype=np.int32)

    for start in range(0, int(search_end)):
        score = 0.0
        valid = True
        for off in preamble_offsets:
            idx = start + off
            if idx >= len(envelope):
                valid = False
                break
            score += envelope[idx]
        if not valid:
            continue
        if score > best_score and all(
            envelope[start + off] > threshold
            for off in preamble_offsets
            if start + off < len(envelope)
        ):
            best_score = score
            best_offset = start

    if best_offset < 0:
        return np.array([], dtype=np.int32)

    # Extract bits after preamble
    data_start = best_offset + preamble_len
    bits = []
    for i in range(112):
        chip_start = data_start + i * samples_per_chip
        first_half = chip_start
        second_half = chip_start + samples_per_half_chip

        if second_half + samples_per_half_chip > len(envelope):
            break

        e_first = np.mean(envelope[first_half : first_half + samples_per_half_chip])
        e_second = np.mean(envelope[second_half : second_half + samples_per_half_chip])

        bits.append(1 if e_first > e_second else 0)

    return np.array(bits, dtype=np.int32)


def extract_messages(bits: np.ndarray) -> list[np.ndarray]:
    """Extract Mode S frames from a bit stream.

    Parameters
    ----------
    bits : np.ndarray
        Demodulated bit array.

    Returns
    -------
    list[np.ndarray]
        List of 56-bit or 112-bit frames with valid CRC.
    """
    frames = []
    if len(bits) < 56:
        return frames

    # Determine frame length from downlink format
    df = _bits_to_int(bits[0:5])
    if df in (0, 4, 5, 11):
        frame_len = 56
    elif df in (16, 17, 18, 19, 20, 21, 24):
        frame_len = 112
    else:
        frame_len = 112  # default to long

    if len(bits) >= frame_len:
        frame = bits[:frame_len]
        if _crc24(frame) == 0:
            frames.append(frame)

    return frames


def _nl(lat: float) -> int:
    """Number of longitude zones for a given latitude (CPR NL function).

    Parameters
    ----------
    lat : float
        Latitude in degrees.

    Returns
    -------
    int
        Number of longitude zones (1..59).

    Closed form from DO-260B / "The 1090 MHz Riddle"::

        NL(lat) = floor(2*pi / acos(1 - (1 - cos(pi / (2*NZ))) / cos^2(pi*lat/180)))

    with NL(0) = 59, NL(+/-87) = 2 and NL = 1 beyond +/-87 degrees.
    """
    abs_lat = abs(lat)
    if abs_lat == 87.0:
        return 2
    if abs_lat > 87.0:
        return 1
    cos_lat = math.cos(math.radians(abs_lat))
    arg = 1.0 - _CPR_NL_A / (cos_lat * cos_lat)
    nl = int(math.floor(2.0 * math.pi / math.acos(max(-1.0, min(1.0, arg)))))
    # At lat == 0 the formula is exactly 60 in theory; the spec value is 59.
    return max(1, min(59, nl))


def _decode_callsign(data: np.ndarray) -> str:
    """Decode callsign from ADS-B type code 1-4.

    Parameters
    ----------
    data : np.ndarray
        48 bits of ME field after type code (bits 40-87 of frame).

    Returns
    -------
    str
        Decoded callsign, stripped of padding.
    """
    callsign = ""
    for i in range(8):
        idx = 0
        for j in range(6):
            if i * 6 + j < len(data):
                idx = (idx << 1) | int(data[i * 6 + j])
        if 0 <= idx < len(_CALLSIGN_CHARSET):
            callsign += _CALLSIGN_CHARSET[idx]
    return callsign.strip()


def _gray_to_int(gray: int) -> int:
    """Convert a reflected-binary Gray code to an integer."""
    n = gray
    shift = 1
    while (gray >> shift) > 0:
        n ^= gray >> shift
        shift += 1
    return n


def _decode_gillham(data: np.ndarray) -> float | None:
    """Decode a 100-ft Gillham (Mode C) altitude from the 12-bit AC field.

    Bit order of the airborne-position altitude field (Q = 0) is
    ``C1 A1 C2 A2 C4 A4 B1 Q B2 D2 B4 D4`` (D1 is not transmitted).
    """
    c1, a1, c2, a2, c4, a4, b1, _q, b2, d2, b4, d4 = (int(b) for b in data[:12])
    n500 = _gray_to_int(_bits_to_int([d2, d4, a1, a2, a4, b1, b2, b4]))
    n100 = _gray_to_int(_bits_to_int([c1, c2, c4]))
    if n100 in (0, 5, 6):
        return None  # illegal C-pulse combination
    if n100 == 7:
        n100 = 5
    if n500 % 2:
        n100 = 6 - n100
    return float(n500 * 500 + n100 * 100 - 1300)


def _decode_altitude(data: np.ndarray) -> float | None:
    """Decode altitude from DF17 airborne position (TC 9-18).

    Parameters
    ----------
    data : np.ndarray
        12-bit altitude field from ME (ME bits 9-20, i.e. message bits
        41-52).  The Q-bit is message bit 48, which is index 7 here.

    Returns
    -------
    float or None
        Altitude in feet, or None if unavailable.
    """
    if len(data) < 12:
        return None

    field = data[:12]
    if _bits_to_int(field) == 0:
        return None  # all-zero altitude field: no altitude information

    q_bit = int(field[7])
    if q_bit == 1:
        # 25-ft resolution: the 11-bit N is the field with the Q-bit removed.
        n = _bits_to_int(np.concatenate([field[0:7], field[8:12]]))
        return float(n * 25 - 1000)

    # Q = 0: 100-ft Gillham (Mode C) code, used above 50175 ft.
    return _decode_gillham(field)


def decode_cpr(
    even_lat: float,
    even_lon: float,
    odd_lat: float,
    odd_lon: float,
    even_newer: bool = True,
) -> tuple[float, float] | None:
    """Compact Position Reporting (CPR) global decode.

    Decodes latitude/longitude from even (F=0) and odd (F=1) position
    frames using the globally unambiguous CPR algorithm.

    Parameters
    ----------
    even_lat, even_lon : float
        Encoded latitude/longitude from even frame (17-bit, normalized 0..1).
    odd_lat, odd_lon : float
        Encoded latitude/longitude from odd frame (17-bit, normalized 0..1).
    even_newer : bool
        True if the even frame is the most recent.

    Returns
    -------
    tuple[float, float] or None
        (latitude, longitude) in degrees, or None if decode fails.
    """
    d_lat_even = 360.0 / 60.0
    d_lat_odd = 360.0 / 59.0

    # Compute latitude index j
    j = int(math.floor(59.0 * even_lat - 60.0 * odd_lat + 0.5))

    lat_even = d_lat_even * ((j % 60) + even_lat)
    lat_odd = d_lat_odd * ((j % 59) + odd_lat)

    # Normalize to [-90, 90]
    if lat_even >= 270.0:
        lat_even -= 360.0
    if lat_odd >= 270.0:
        lat_odd -= 360.0

    # Check NL consistency
    if _nl(lat_even) != _nl(lat_odd):
        return None

    # Compute longitude
    if even_newer:
        lat = lat_even
        nl_val = max(_nl(lat), 1)
        d_lon = 360.0 / nl_val if nl_val > 0 else 360.0
        m = int(math.floor(even_lon * (_nl(lat) - 1) - odd_lon * _nl(lat) + 0.5))
        lon = d_lon * ((m % nl_val) + even_lon)
    else:
        lat = lat_odd
        nl_val = max(_nl(lat) - 1, 1)
        d_lon = 360.0 / nl_val if nl_val > 0 else 360.0
        m = int(math.floor(even_lon * (_nl(lat) - 1) - odd_lon * _nl(lat) + 0.5))
        lon = d_lon * ((m % nl_val) + odd_lon)

    if lon >= 180.0:
        lon -= 360.0

    # Sanity check
    if not (-90.0 <= lat <= 90.0) or not (-180.0 <= lon <= 180.0):
        return None

    return (lat, lon)


def _decode_velocity(data: np.ndarray) -> tuple[float | None, float | None]:
    """Decode airborne velocity from TC 19 subtype 1/2 (ground speed).

    Parameters
    ----------
    data : np.ndarray
        The 51 ME bits that follow the 5-bit type code (ME bits 6-56).
        Layout: subtype (3), intent change (1), IFR capability (1),
        NUCv (3), Dew (1), Vew (10), Dns (1), Vns (10), ...

    Returns
    -------
    tuple[float | None, float | None]
        (velocity_kts, heading_deg) or (None, None) on failure.
    """
    if len(data) < 30:
        return None, None

    subtype = _bits_to_int(data[0:3])

    if subtype in (1, 2):
        # data[3] = intent change flag, data[4] = IFR capability,
        # data[5:8] = NUCv -- none of them affect the velocity vector.
        dew = int(data[8])
        vew_raw = _bits_to_int(data[9:19])
        dns = int(data[19])
        vns_raw = _bits_to_int(data[20:30])

        # A raw value of 0 means "no velocity information available".
        if vew_raw == 0 or vns_raw == 0:
            return None, None
        vew = vew_raw - 1
        vns = vns_raw - 1

        if subtype == 2:  # supersonic: 4-kt resolution
            vew *= 4
            vns *= 4

        # Sign: 1 = west/south, 0 = east/north
        vx = -vew if dew else vew
        vy = -vns if dns else vns

        speed = math.sqrt(vx**2 + vy**2)
        heading = math.degrees(math.atan2(vx, vy)) % 360.0

        return speed, heading

    return None, None


def decode_adsb(frame: np.ndarray) -> ADSBMessage | None:
    """Decode a single ADS-B extended squitter (DF17/18) frame.

    Parameters
    ----------
    frame : np.ndarray
        112-bit Mode S frame.

    Returns
    -------
    ADSBMessage or None
        Decoded message, or None if CRC fails or unsupported type.
    """
    if len(frame) < 112:
        return None

    # Validate CRC
    if _crc24(frame) != 0:
        return None

    df = _bits_to_int(frame[0:5])
    if df not in (17, 18):
        return None

    icao = f"{_bits_to_int(frame[8:32]):06X}"
    me = frame[32:88]  # 56-bit message field
    tc = _bits_to_int(me[0:5])

    raw_bits = "".join(str(int(b)) for b in frame)

    msg = ADSBMessage(
        icao_address=icao,
        msg_type=df,
        callsign=None,
        altitude_ft=None,
        lat=None,
        lon=None,
        velocity_kts=None,
        heading_deg=None,
        squawk=None,
        raw_bits=raw_bits,
    )

    if 1 <= tc <= 4:
        # Aircraft identification
        msg.callsign = _decode_callsign(me[8:56])

    elif 9 <= tc <= 18:
        # Airborne position
        alt_bits = me[8:20]
        msg.altitude_ft = _decode_altitude(alt_bits)
        # CPR encoded lat/lon stored as normalized values
        # (caller must pair even/odd for full decode via decode_cpr).
        # ME layout: T (bit 20), F (bit 21), LAT-CPR (22-38), LON-CPR (39-55).
        msg.cpr_odd = bool(me[21])
        msg.cpr_lat = _bits_to_int(me[22:39]) / 131072.0
        msg.cpr_lon = _bits_to_int(me[39:56]) / 131072.0

    elif tc == 19:
        # Airborne velocity
        vel, hdg = _decode_velocity(me[5:56])
        msg.velocity_kts = vel
        msg.heading_deg = hdg

    return msg
