"""TX safety controls for protocol fuzzing.

SAFETY-CRITICAL MODULE — prevents transmission on forbidden frequency
bands (aviation, military, emergency, GNSS) and enforces hard caps on
TX gain and duration.  Forbidden bands are hard-coded and cannot be
overridden by environment variables.

Zero external dependencies beyond the Python standard library.
"""

from __future__ import annotations

import logging
import math
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Forbidden bands — HARD-CODED, NO ENV VAR OVERRIDE
# ---------------------------------------------------------------------------

FORBIDDEN_BANDS: list[tuple[float, float, str]] = [
    (118e6, 137e6, "Aviation VHF"),
    (225e6, 400e6, "Military UHF"),
    (960e6, 1215e6, "Aviation L-band / ADS-B / DME"),
    (1164e6, 1240e6, "GPS L5 / Galileo"),
    (1559e6, 1610e6, "GPS L1 / GLONASS / Galileo"),
    (121.475e6, 121.525e6, "Aviation emergency"),
    (156.7625e6, 156.8375e6, "Marine Ch. 16 distress"),
    (406.0e6, 406.1e6, "COSPAS-SARSAT emergency"),
    (1544e6, 1545e6, "INMARSAT distress"),
]

# ---------------------------------------------------------------------------
# Default allowed bands (ISM — advisory, not enforced)
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_BANDS: list[tuple[float, float, str]] = [
    (433.05e6, 434.79e6, "ISM 433 MHz"),
    (902e6, 928e6, "ISM 915 MHz"),
    (2400e6, 2483.5e6, "ISM 2.4 GHz"),
    (5725e6, 5875e6, "ISM 5.8 GHz"),
]

# ---------------------------------------------------------------------------
# TX limits
# ---------------------------------------------------------------------------

MAX_TX_GAIN_HARD: int = 40  # Absolute max — never overridable
MAX_TX_GAIN_DEFAULT: int = 20  # Env: BRIDGE_FUZZ_MAX_TX_GAIN
MAX_TX_DURATION_HARD: float = 300.0  # Absolute max in seconds
MAX_TX_DURATION_DEFAULT: float = 60.0  # Env: BRIDGE_FUZZ_MAX_DURATION

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FuzzSafetyError(Exception):
    """Base exception for fuzz TX safety violations."""


class BandViolationError(FuzzSafetyError):
    """Transmission frequency overlaps a forbidden band."""


class PowerViolationError(FuzzSafetyError):
    """Transmission gain exceeds the allowed maximum."""


# ---------------------------------------------------------------------------
# Validation functions
# ---------------------------------------------------------------------------


def validate_tx_frequency(freq_hz: float, bandwidth_hz: float = 0.0) -> None:
    """Validate that a TX frequency does not overlap any forbidden band.

    Checks whether the transmission footprint (center +/- bandwidth/2)
    overlaps any entry in FORBIDDEN_BANDS.  Raises BandViolationError on
    overlap.  Also logs a warning if the frequency is outside all
    DEFAULT_ALLOWED_BANDS (advisory only — does not raise).

    Parameters
    ----------
    freq_hz : float
        Center frequency in Hz.
    bandwidth_hz : float
        Signal bandwidth in Hz (default 0 for CW / narrowband).

    Raises
    ------
    BandViolationError
        If the TX footprint overlaps a forbidden band.
    """
    if (
        not isinstance(freq_hz, (int, float))
        or math.isnan(freq_hz)
        or math.isinf(freq_hz)
    ):
        raise BandViolationError(f"Invalid frequency value: {freq_hz}")
    if (
        not isinstance(bandwidth_hz, (int, float))
        or math.isnan(bandwidth_hz)
        or math.isinf(bandwidth_hz)
    ):
        raise BandViolationError(f"Invalid bandwidth value: {bandwidth_hz}")

    half_bw = abs(bandwidth_hz) / 2.0
    tx_low = freq_hz - half_bw
    tx_high = freq_hz + half_bw

    for band_low, band_high, description in FORBIDDEN_BANDS:
        if tx_low <= band_high and tx_high >= band_low:
            raise BandViolationError(
                f"TX at {freq_hz / 1e6:.4f} MHz (BW {bandwidth_hz / 1e3:.1f} kHz) "
                f"overlaps forbidden band: {description} "
                f"({band_low / 1e6:.4f}–{band_high / 1e6:.4f} MHz)"
            )

    if not is_allowed_band(freq_hz, bandwidth_hz):
        logger.warning(
            "TX at %.4f MHz (BW %.1f kHz) is outside all default allowed ISM bands",
            freq_hz / 1e6,
            bandwidth_hz / 1e3,
        )


def validate_tx_gain(gain: float) -> None:
    """Validate that TX gain does not exceed the hard cap.

    Parameters
    ----------
    gain : float
        Requested TX gain in dB.

    Raises
    ------
    PowerViolationError
        If gain exceeds MAX_TX_GAIN_HARD.
    """
    if (
        not isinstance(gain, (int, float))
        or math.isnan(float(gain))
        or math.isinf(float(gain))
    ):
        raise PowerViolationError(f"Invalid gain value: {gain}")

    if gain > MAX_TX_GAIN_HARD:
        raise PowerViolationError(
            f"TX gain {gain} dB exceeds hard cap of {MAX_TX_GAIN_HARD} dB"
        )

    max_allowed = get_max_tx_gain()
    if gain > max_allowed:
        raise PowerViolationError(
            f"TX gain {gain} dB exceeds configured max of {max_allowed} dB"
        )


def get_max_tx_gain() -> int:
    """Return the effective maximum TX gain.

    Uses the BRIDGE_FUZZ_MAX_TX_GAIN environment variable if set,
    clamped to MAX_TX_GAIN_HARD.

    Returns
    -------
    int
        Maximum allowed TX gain in dB.
    """
    env_val = os.environ.get("BRIDGE_FUZZ_MAX_TX_GAIN")
    if env_val is not None:
        try:
            configured = int(env_val)
        except ValueError:
            logger.warning(
                "Invalid BRIDGE_FUZZ_MAX_TX_GAIN=%r, using default %d",
                env_val,
                MAX_TX_GAIN_DEFAULT,
            )
            return min(MAX_TX_GAIN_DEFAULT, MAX_TX_GAIN_HARD)
        return min(configured, MAX_TX_GAIN_HARD)
    return min(MAX_TX_GAIN_DEFAULT, MAX_TX_GAIN_HARD)


def get_max_tx_duration() -> float:
    """Return the effective maximum TX duration in seconds.

    Uses the BRIDGE_FUZZ_MAX_DURATION environment variable if set,
    clamped to MAX_TX_DURATION_HARD.  A non-finite value (nan, inf) is
    malformed: NaN would slip past min() and every duration comparison.

    Returns
    -------
    float
        Maximum allowed TX duration in seconds.
    """
    env_val = os.environ.get("BRIDGE_FUZZ_MAX_DURATION")
    if env_val is not None:
        try:
            configured = float(env_val)
            if not math.isfinite(configured):
                raise ValueError(env_val)
        except ValueError:
            logger.warning(
                "Invalid BRIDGE_FUZZ_MAX_DURATION=%r, using default %.1f",
                env_val,
                MAX_TX_DURATION_DEFAULT,
            )
            return min(MAX_TX_DURATION_DEFAULT, MAX_TX_DURATION_HARD)
        return min(configured, MAX_TX_DURATION_HARD)
    return min(MAX_TX_DURATION_DEFAULT, MAX_TX_DURATION_HARD)


def validate_tx_request(
    freq_hz: float,
    bandwidth_hz: float,
    gain: float,
    duration_s: float,
) -> None:
    """Run all TX safety validations.

    Parameters
    ----------
    freq_hz : float
        Center frequency in Hz.
    bandwidth_hz : float
        Signal bandwidth in Hz.
    gain : float
        TX gain in dB.
    duration_s : float
        Requested TX duration in seconds.

    Raises
    ------
    BandViolationError
        If the frequency overlaps a forbidden band.
    PowerViolationError
        If gain exceeds the allowed maximum.
    FuzzSafetyError
        If duration exceeds the allowed maximum.
    """
    if (
        not isinstance(duration_s, (int, float))
        or math.isnan(duration_s)
        or math.isinf(duration_s)
    ):
        raise FuzzSafetyError(f"Invalid duration value: {duration_s}")

    validate_tx_frequency(freq_hz, bandwidth_hz)
    validate_tx_gain(gain)

    max_duration = get_max_tx_duration()
    if duration_s > max_duration:
        raise FuzzSafetyError(
            f"TX duration {duration_s:.1f}s exceeds max of {max_duration:.1f}s"
        )

    if duration_s <= 0:
        raise FuzzSafetyError(f"TX duration must be positive, got {duration_s:.1f}s")

    logger.info(
        "TX request validated: %.4f MHz, BW %.1f kHz, gain %d dB, %.1fs",
        freq_hz / 1e6,
        bandwidth_hz / 1e3,
        gain,
        duration_s,
    )


def is_allowed_band(freq_hz: float, bandwidth_hz: float = 0.0) -> bool:
    """Check if a frequency is within any default allowed ISM band.

    Parameters
    ----------
    freq_hz : float
        Center frequency in Hz.
    bandwidth_hz : float
        Signal bandwidth in Hz (default 0).

    Returns
    -------
    bool
        True if the entire TX footprint is within an allowed band.
    """
    half_bw = abs(bandwidth_hz) / 2.0
    tx_low = freq_hz - half_bw
    tx_high = freq_hz + half_bw

    for band_low, band_high, _ in DEFAULT_ALLOWED_BANDS:
        if tx_low >= band_low and tx_high <= band_high:
            return True
    return False
