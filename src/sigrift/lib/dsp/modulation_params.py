"""Modulation parameter extraction from IQ captures.

Extracts symbol rate, occupied bandwidth, and carrier frequency offset
from raw IQ data. All functions are numpy-based and run on any platform.
"""

import numpy as np
from typing import Any


def estimate_symbol_rate(iq: np.ndarray, sample_rate: float = 1.0) -> dict[str, Any]:
    """Estimate symbol rate using cyclostationary analysis.

    Uses the squared-magnitude of the IQ signal -- the envelope has
    a spectral line at the symbol rate for most modulations.

    Algorithm:
    1. Compute |x(t)|^2 (envelope squared)
    2. FFT of the envelope
    3. Find peaks in the magnitude spectrum (above noise floor)
    4. The lowest strong peak = estimated symbol rate

    Returns dict with:
    - symbol_rate_hz: estimated symbol rate (relative to sample_rate)
    - confidence: 0-1 confidence in the estimate
    - spectral_peaks: list of (freq, magnitude) for top peaks
    """
    n = len(iq)
    if n < 64:
        return {"symbol_rate_hz": 0.0, "confidence": 0.0, "spectral_peaks": []}

    # Envelope squared (removes carrier, reveals symbol rate)
    envelope_sq = np.abs(iq) ** 2
    envelope_sq -= np.mean(envelope_sq)  # remove DC

    # FFT of envelope
    fft = np.fft.rfft(envelope_sq)
    mag = np.abs(fft)
    freqs = np.fft.rfftfreq(n, d=1.0 / sample_rate)

    # Skip DC bin and very low frequencies
    min_bin = max(1, int(n * 0.001))  # skip below 0.1% of sample rate
    mag[:min_bin] = 0

    # Find peaks above noise floor
    noise_floor = np.median(mag[min_bin:])
    threshold = noise_floor * 3.0  # ~5 dB above noise

    peak_indices = []
    for i in range(min_bin + 1, len(mag) - 1):
        if mag[i] > mag[i - 1] and mag[i] > mag[i + 1] and mag[i] > threshold:
            peak_indices.append(i)

    if not peak_indices:
        return {"symbol_rate_hz": 0.0, "confidence": 0.0, "spectral_peaks": []}

    # Sort by magnitude
    peak_indices.sort(key=lambda i: mag[i], reverse=True)

    # Top peaks
    spectral_peaks = [(float(freqs[i]), float(mag[i])) for i in peak_indices[:5]]

    # Best estimate = strongest peak
    best_idx = peak_indices[0]
    symbol_rate = float(freqs[best_idx])

    # Confidence = peak-to-noise ratio (normalized)
    confidence = min(1.0, float(mag[best_idx] / noise_floor) / 20.0)

    return {
        "symbol_rate_hz": symbol_rate,
        "confidence": round(confidence, 3),
        "spectral_peaks": spectral_peaks[:5],
    }


def estimate_occupied_bandwidth(
    iq: np.ndarray, sample_rate: float = 1.0, threshold_db: float = -20.0
) -> dict[str, Any]:
    """Estimate occupied bandwidth using PSD analysis.

    Computes PSD, finds the -20dB bandwidth (default) relative to peak.

    Returns dict with:
    - bandwidth_hz: occupied bandwidth
    - bandwidth_3db_hz: -3dB bandwidth
    - bandwidth_20db_hz: -20dB bandwidth
    - center_offset_hz: offset of spectral center from DC
    """
    n = len(iq)
    if n < 64:
        return {
            "bandwidth_hz": 0.0,
            "bandwidth_3db_hz": 0.0,
            "bandwidth_20db_hz": 0.0,
            "center_offset_hz": 0.0,
        }

    # PSD via Welch-like averaging
    nfft = min(n, 1024)
    window = np.hanning(nfft)
    n_segments = max(1, n // nfft)

    psd_sum = np.zeros(nfft)
    for i in range(n_segments):
        seg = iq[i * nfft : (i + 1) * nfft]
        if len(seg) < nfft:
            break
        windowed = seg * window
        fft_vals = np.fft.fftshift(np.fft.fft(windowed))
        psd_sum += np.abs(fft_vals) ** 2

    psd = psd_sum / n_segments
    psd_db = 10 * np.log10(np.maximum(psd, 1e-12))
    peak_db = float(np.max(psd_db))

    freqs = np.fft.fftshift(np.fft.fftfreq(nfft, d=1.0 / sample_rate))

    # Find bandwidths at different thresholds
    def _bandwidth_at_threshold(threshold: float) -> tuple[float, float]:
        mask = psd_db >= (peak_db + threshold)
        if not np.any(mask):
            return 0.0, 0.0
        indices = np.where(mask)[0]
        low_freq = float(freqs[indices[0]])
        high_freq = float(freqs[indices[-1]])
        bw = high_freq - low_freq
        center = (high_freq + low_freq) / 2.0
        return bw, center

    bw_3db, center_3db = _bandwidth_at_threshold(-3.0)
    bw_20db, center_20db = _bandwidth_at_threshold(threshold_db)

    return {
        "bandwidth_hz": round(bw_20db, 2),
        "bandwidth_3db_hz": round(bw_3db, 2),
        "bandwidth_20db_hz": round(bw_20db, 2),
        "center_offset_hz": round(center_20db, 2),
    }


def estimate_cfo(iq: np.ndarray, sample_rate: float = 1.0) -> dict[str, Any]:
    """Estimate carrier frequency offset (CFO) using phase regression.

    Uses the instantaneous phase slope over a short window.

    Returns dict with:
    - cfo_hz: estimated CFO in Hz
    - cfo_normalized: CFO normalized to sample rate
    """
    n = len(iq)
    if n < 32:
        return {"cfo_hz": 0.0, "cfo_normalized": 0.0}

    # Instantaneous phase
    phase = np.unwrap(np.angle(iq))

    # Linear regression on phase vs sample index
    t = np.arange(n, dtype=np.float64)
    # Use only first 1024 samples for efficiency
    t_sub = t[: min(n, 1024)]
    phase_sub = phase[: min(n, 1024)]

    # Least squares fit: phase = slope * t + intercept
    t_mean = np.mean(t_sub)
    p_mean = np.mean(phase_sub)
    slope = float(
        np.sum((t_sub - t_mean) * (phase_sub - p_mean)) / np.sum((t_sub - t_mean) ** 2)
    )

    # slope = 2 * pi * f_offset / sample_rate per sample
    cfo_normalized = slope / (2 * np.pi)
    cfo_hz = cfo_normalized * sample_rate

    return {
        "cfo_hz": round(cfo_hz, 4),
        "cfo_normalized": round(cfo_normalized, 6),
    }


def extract_modulation_params(
    iq: np.ndarray, sample_rate: float = 1.0
) -> dict[str, Any]:
    """Extract all modulation parameters from IQ data.

    Convenience function that calls all estimators and returns combined results.
    """
    return {
        "symbol_rate": estimate_symbol_rate(iq, sample_rate),
        "bandwidth": estimate_occupied_bandwidth(iq, sample_rate),
        "cfo": estimate_cfo(iq, sample_rate),
        "n_samples": len(iq),
        "sample_rate_hz": sample_rate,
    }
