"""BPSK/QPSK/8PSK bitstream extraction from IQ captures.

Demodulates PSK signals to recover the transmitted bit sequence.
Supports automatic symbol rate and CFO detection using the
cyclostationary estimators from modulation_params.

Algorithm pipeline for each modulation:
1. CFO correction (phase de-rotation)
2. Matched filter (root-raised-cosine, rolloff=0.35)
3. Symbol timing recovery (Mueller-Muller TED)
4. Decision slicer (nearest constellation point)
5. Gray-coded bit mapping
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

from sigrift.lib.dsp.modulation_params import estimate_cfo, estimate_symbol_rate

logger = logging.getLogger(__name__)

# Supported modulation types and their constellation orders
_SUPPORTED = {"bpsk": 2, "qpsk": 4, "8psk": 8}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class BitStreamResult:
    """Result of bitstream extraction from an IQ capture."""

    bits: list[int]
    symbols: np.ndarray
    modulation: str
    symbol_rate: float
    snr_estimate: float
    confidence: float
    n_symbols: int
    bit_error_rate: float | None
    constellation: list[complex]


# ---------------------------------------------------------------------------
# Constellation definitions
# ---------------------------------------------------------------------------


def _bpsk_constellation() -> np.ndarray:
    """BPSK: {+1, -1}."""
    return np.array([1.0 + 0j, -1.0 + 0j])


def _qpsk_constellation() -> np.ndarray:
    """QPSK: exp(j*pi/4 * (2k+1)) for k=0..3, Gray coded."""
    return np.array(
        [
            np.exp(1j * np.pi / 4),  # 00
            np.exp(1j * 3 * np.pi / 4),  # 01
            np.exp(1j * -np.pi / 4),  # 10
            np.exp(1j * -3 * np.pi / 4),  # 11
        ]
    )


def _8psk_constellation() -> np.ndarray:
    """8PSK: exp(j*2*pi*k/8) for k=0..7, Gray coded."""
    # Gray code order: 000,001,011,010,110,111,101,100
    gray_order = [0, 1, 3, 2, 6, 7, 5, 4]
    points = np.array([np.exp(1j * 2 * np.pi * k / 8) for k in range(8)])
    # Reorder so index = Gray code value
    result = np.zeros(8, dtype=complex)
    for gray_val, phase_idx in enumerate(gray_order):
        result[gray_val] = points[phase_idx]
    return result


_CONSTELLATIONS = {
    "bpsk": _bpsk_constellation,
    "qpsk": _qpsk_constellation,
    "8psk": _8psk_constellation,
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _rrc_filter(n_taps: int, rolloff: float, sps: int) -> np.ndarray:
    """Root-raised-cosine filter.

    Parameters
    ----------
    n_taps : int
        Number of filter taps (should be odd for symmetry).
    rolloff : float
        Roll-off factor in (0, 1].
    sps : int
        Samples per symbol.

    Returns
    -------
    np.ndarray
        Filter coefficients normalised to unit energy.
    """
    if n_taps < 1:
        return np.array([1.0])

    # Ensure odd length for symmetry
    if n_taps % 2 == 0:
        n_taps += 1

    t = (np.arange(n_taps) - (n_taps - 1) / 2) / sps

    h = np.zeros(n_taps)
    for i, ti in enumerate(t):
        if abs(ti) < 1e-10:
            h[i] = 1.0 - rolloff + 4.0 * rolloff / np.pi
        elif rolloff > 0 and abs(abs(ti) - 1.0 / (4.0 * rolloff)) < 1e-8:
            h[i] = (rolloff / np.sqrt(2.0)) * (
                (1.0 + 2.0 / np.pi) * np.sin(np.pi / (4.0 * rolloff))
                + (1.0 - 2.0 / np.pi) * np.cos(np.pi / (4.0 * rolloff))
            )
        else:
            num = np.sin(np.pi * ti * (1 - rolloff)) + 4 * rolloff * ti * np.cos(
                np.pi * ti * (1 + rolloff)
            )
            den = np.pi * ti * (1 - (4 * rolloff * ti) ** 2)
            if abs(den) > 1e-12:
                h[i] = num / den
            else:
                h[i] = 0.0

    # Normalise to unit energy
    energy = np.sqrt(np.sum(h**2))
    if energy > 0:
        h = h / energy

    return h


def _mueller_muller_ted(signal: np.ndarray, sps: float) -> np.ndarray:
    """Mueller-Muller timing error detector with linear interpolation.

    Recovers symbol-spaced samples from an oversampled signal using
    the Mueller-Muller timing error detector and a first-order loop
    filter.

    Parameters
    ----------
    signal : np.ndarray
        Oversampled complex signal (after matched filter).
    sps : float
        Samples per symbol (can be fractional).

    Returns
    -------
    np.ndarray
        Symbol-spaced complex samples.
    """
    n = len(signal)
    if n < 4:
        return signal

    # Loop filter parameters (conservative for robustness)
    # Normalised loop bandwidth ~0.01 of symbol rate
    bn_ts = 0.01
    damping = 1.0
    theta = bn_ts / (damping + 1.0 / (4.0 * damping))
    kp = 2.0 * damping * theta
    ki = theta**2

    symbols = []
    mu = 0.0  # fractional timing offset
    idx = int(sps)  # start one symbol in
    prev_symbol = 0.0 + 0j
    prev_sample = 0.0 + 0j
    loop_filter_state = 0.0

    while idx < n - 1:
        # Linear interpolation at fractional index
        base = int(idx)
        frac = idx - base
        if base + 1 < n:
            current_sample = signal[base] * (1 - frac) + signal[base + 1] * frac
        else:
            current_sample = signal[base]

        symbols.append(current_sample)

        # Mueller-Muller TED: e(n) = Re{a*(n-1)*x(n) - a*(n)*x(n-1)}
        # where a* is the decision (hard sliced previous symbol)
        if len(symbols) >= 2:
            # Use hard decisions for TED
            curr_decision = np.sign(current_sample.real) + 1j * np.sign(
                current_sample.imag
            )
            prev_decision = np.sign(prev_symbol.real) + 1j * np.sign(prev_symbol.imag)

            timing_error = np.real(
                np.conj(prev_decision) * current_sample
                - np.conj(curr_decision) * prev_sample
            )

            # Clamp timing error
            timing_error = max(-1.0, min(1.0, timing_error))

            # Loop filter (proportional + integral)
            loop_filter_state += ki * timing_error
            timing_adjust = kp * timing_error + loop_filter_state

            # Adjust sampling point
            mu += timing_adjust
        else:
            mu = 0.0

        prev_symbol = current_sample
        prev_sample = current_sample

        # Advance by sps +/- timing adjustment
        idx += sps + mu
        mu = 0.0  # reset fractional accumulator after applying

    return np.array(symbols, dtype=complex) if symbols else np.array([], dtype=complex)


def _estimate_snr(symbols: np.ndarray, constellation: np.ndarray) -> float:
    """Estimate SNR from EVM (Error Vector Magnitude).

    Maps each received symbol to its nearest constellation point,
    computes mean squared error, and derives SNR.

    Parameters
    ----------
    symbols : np.ndarray
        Received symbol-spaced samples.
    constellation : np.ndarray
        Ideal constellation points.

    Returns
    -------
    float
        Estimated SNR in dB.
    """
    if len(symbols) == 0 or len(constellation) == 0:
        return 0.0

    # Normalise symbols to match constellation power
    sym_power = np.mean(np.abs(symbols) ** 2)
    const_power = np.mean(np.abs(constellation) ** 2)
    if sym_power > 1e-12:
        symbols_norm = symbols * np.sqrt(const_power / sym_power)
    else:
        return 0.0

    # Find nearest constellation point for each symbol
    errors = np.zeros(len(symbols_norm))
    for i, s in enumerate(symbols_norm):
        dists = np.abs(s - constellation) ** 2
        errors[i] = np.min(dists)

    mse = np.mean(errors)
    if mse < 1e-12:
        return 40.0  # Effectively perfect

    evm_sq = mse / const_power
    snr_linear = 1.0 / evm_sq
    snr_db = float(10.0 * np.log10(max(snr_linear, 1e-6)))

    return max(-10.0, min(40.0, snr_db))


def _slice_symbols(
    symbols: np.ndarray,
    constellation: np.ndarray,
    bits_per_symbol: int,
) -> list[int]:
    """Map received symbols to nearest constellation point and extract bits.

    Parameters
    ----------
    symbols : np.ndarray
        Received complex symbols.
    constellation : np.ndarray
        Ideal constellation points (indexed by Gray code value).
    bits_per_symbol : int
        Number of bits per symbol (1 for BPSK, 2 for QPSK, 3 for 8PSK).

    Returns
    -------
    list[int]
        Extracted bit sequence.
    """
    bits = []

    # Normalise symbols to match constellation power
    sym_power = np.mean(np.abs(symbols) ** 2)
    const_power = np.mean(np.abs(constellation) ** 2)
    if sym_power > 1e-12:
        scale = np.sqrt(const_power / sym_power)
    else:
        scale = 1.0

    for s in symbols:
        s_scaled = s * scale
        dists = np.abs(s_scaled - constellation)
        idx = int(np.argmin(dists))
        # Convert index to bits (MSB first)
        for b in range(bits_per_symbol - 1, -1, -1):
            bits.append((idx >> b) & 1)

    return bits


# ---------------------------------------------------------------------------
# Per-modulation demodulators
# ---------------------------------------------------------------------------


def demod_bpsk(
    iq: np.ndarray,
    symbol_rate: float,
    sample_rate: float,
) -> np.ndarray:
    """Demodulate BPSK signal to symbol-spaced samples.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples (CFO already corrected).
    symbol_rate : float
        Symbol rate in Hz.
    sample_rate : float
        Sample rate in Hz.

    Returns
    -------
    np.ndarray
        Complex symbol-spaced samples.
    """
    sps = sample_rate / symbol_rate if symbol_rate > 0 else 8.0

    # Matched filter
    n_taps = max(int(6 * sps) | 1, 11)
    rrc = _rrc_filter(n_taps, rolloff=0.35, sps=max(1, int(round(sps))))
    filtered = np.convolve(iq, rrc, mode="same")

    # Timing recovery
    symbols = _mueller_muller_ted(filtered, sps)

    return symbols


def demod_qpsk(
    iq: np.ndarray,
    symbol_rate: float,
    sample_rate: float,
) -> np.ndarray:
    """Demodulate QPSK signal to symbol-spaced samples.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples (CFO already corrected).
    symbol_rate : float
        Symbol rate in Hz.
    sample_rate : float
        Sample rate in Hz.

    Returns
    -------
    np.ndarray
        Complex symbol-spaced samples.
    """
    sps = sample_rate / symbol_rate if symbol_rate > 0 else 8.0

    # Matched filter
    n_taps = max(int(6 * sps) | 1, 11)
    rrc = _rrc_filter(n_taps, rolloff=0.35, sps=max(1, int(round(sps))))
    filtered = np.convolve(iq, rrc, mode="same")

    # Timing recovery
    symbols = _mueller_muller_ted(filtered, sps)

    return symbols


def demod_8psk(
    iq: np.ndarray,
    symbol_rate: float,
    sample_rate: float,
) -> np.ndarray:
    """Demodulate 8PSK signal to symbol-spaced samples.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples (CFO already corrected).
    symbol_rate : float
        Symbol rate in Hz.
    sample_rate : float
        Sample rate in Hz.

    Returns
    -------
    np.ndarray
        Complex symbol-spaced samples.
    """
    sps = sample_rate / symbol_rate if symbol_rate > 0 else 8.0

    # Matched filter
    n_taps = max(int(6 * sps) | 1, 11)
    rrc = _rrc_filter(n_taps, rolloff=0.35, sps=max(1, int(round(sps))))
    filtered = np.convolve(iq, rrc, mode="same")

    # Timing recovery
    symbols = _mueller_muller_ted(filtered, sps)

    return symbols


# ---------------------------------------------------------------------------
# Main extraction function
# ---------------------------------------------------------------------------


_DEMODULATORS = {
    "bpsk": demod_bpsk,
    "qpsk": demod_qpsk,
    "8psk": demod_8psk,
}


def extract_bitstream(
    iq: np.ndarray,
    modulation: str,
    sample_rate: float = 1.0,
    symbol_rate: float | None = None,
) -> BitStreamResult:
    """Extract bitstream from a PSK-modulated IQ capture.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples.
    modulation : str
        Modulation type: "bpsk", "qpsk", or "8psk".
    sample_rate : float
        Sample rate in Hz (default 1.0 for normalised frequency).
    symbol_rate : float or None
        Symbol rate in Hz.  If None, auto-detected using
        cyclostationary analysis.

    Returns
    -------
    BitStreamResult
        Extracted bitstream and metadata.

    Raises
    ------
    ValueError
        If the modulation type is not supported.
    """
    mod_lower = modulation.lower()
    if mod_lower not in _SUPPORTED:
        raise ValueError(
            f"Unsupported modulation: {modulation!r}. "
            f"Supported: {sorted(_SUPPORTED.keys())}"
        )

    order = _SUPPORTED[mod_lower]
    bits_per_symbol = {2: 1, 4: 2, 8: 3}[order]

    # --- Auto-detect symbol rate ---
    if symbol_rate is None or symbol_rate <= 0:
        sr_result = estimate_symbol_rate(iq, sample_rate)
        symbol_rate = sr_result["symbol_rate_hz"]
        if symbol_rate <= 0:
            # Fallback: assume 8 samples per symbol
            symbol_rate = sample_rate / 8.0
            logger.warning(
                "Symbol rate auto-detection failed; using fallback %.1f Hz",
                symbol_rate,
            )

    # --- CFO correction ---
    cfo_result = estimate_cfo(iq, sample_rate)
    cfo_hz = cfo_result["cfo_hz"]
    if abs(cfo_hz) > 0:
        t = np.arange(len(iq)) / sample_rate
        iq = iq * np.exp(-1j * 2 * np.pi * cfo_hz * t)

    # --- Demodulate ---
    demod_fn = _DEMODULATORS[mod_lower]
    symbols = demod_fn(iq, symbol_rate, sample_rate)

    if len(symbols) == 0:
        return BitStreamResult(
            bits=[],
            symbols=np.array([], dtype=complex),
            modulation=mod_lower,
            symbol_rate=symbol_rate,
            snr_estimate=0.0,
            confidence=0.0,
            n_symbols=0,
            bit_error_rate=None,
            constellation=[],
        )

    # --- Get constellation ---
    constellation = _CONSTELLATIONS[mod_lower]()

    # --- SNR estimation ---
    snr_db = _estimate_snr(symbols, constellation)

    # --- Decision slicing ---
    bits = _slice_symbols(symbols, constellation, bits_per_symbol)

    # --- Confidence estimation ---
    # Based on SNR: sigmoid mapping
    # At 15 dB SNR -> ~0.85 confidence, at 0 dB -> ~0.3
    confidence = float(1.0 / (1.0 + np.exp(-0.2 * (snr_db - 5.0))))
    confidence = max(0.0, min(1.0, confidence))

    return BitStreamResult(
        bits=bits,
        symbols=symbols,
        modulation=mod_lower,
        symbol_rate=symbol_rate,
        snr_estimate=round(snr_db, 2),
        confidence=round(confidence, 4),
        n_symbols=len(symbols),
        bit_error_rate=None,
        constellation=constellation.tolist(),
    )
