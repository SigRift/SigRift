"""SNR estimation methods for IQ signals.

Provides three estimators of increasing sophistication:

- **M2M4** (moment-based): fast, no FFT required.
- **Percentile** (spectral): improved with windowing and median-of-segments
  for robustness against transients.
- **Eigenvalue** (covariance-based): uses eigenvalue spread of the sample
  covariance matrix as an SNR proxy.

All estimators return SNR in dB, clipped to [-20, 50].
"""

import logging

import numpy as np

from sigrift.lib.dsp.windowing import windowed_psd

logger = logging.getLogger(__name__)

# Kurtosis (kappa_s) lookup by modulation family or specific modulation.
# PSK and FSK are constant-envelope (kappa_s = 1.0).
# QAM, APSK, ASK, PAM have non-constant envelopes.
# OFDM is approximately Gaussian by CLT (kappa_s ~ 1.0).
# Per-order QAM/APSK values derived from constellation statistics:
#   kappa_s = E[|s|^4] / E[|s|^2]^2
KAPPA_S: dict[str, float] = {
    # Families (fallback when specific order not matched)
    "PSK": 1.0,
    "FSK": 1.0,
    "QAM": 1.32,
    "APSK": 1.25,
    "ASK": 1.8,
    "PAM": 1.8,
    "OFDM": 1.0,
    "ANALOG": 1.0,
    "SPREAD_SPECTRUM": 1.0,
    "NOISE": 1.0,
    # Per-order PSK (all constant-envelope)
    "BPSK": 1.0,
    "QPSK": 1.0,
    "8PSK": 1.0,
    "16PSK": 1.0,
    "32PSK": 1.0,
    # Per-order QAM
    "16QAM": 1.32,
    "32QAM": 1.35,
    "64QAM": 1.381,
    "128QAM": 1.39,
    "256QAM": 1.397,
    # Per-order APSK (ring-based, slightly less than rectangular QAM)
    "16APSK": 1.21,
    "32APSK": 1.25,
    "64APSK": 1.30,
    "128APSK": 1.33,
}


def _resolve_kappa_s(
    kappa_s: float | None,
    signal_class: str | None,
) -> float:
    """Resolve kappa_s from explicit value or signal class lookup.

    Parameters
    ----------
    kappa_s : float or None
        Explicit kappa_s value. If provided, used directly.
    signal_class : str or None
        Signal family name (e.g. "QAM", "PSK") for lookup.

    Returns
    -------
    float
        Resolved kappa_s value.
    """
    if kappa_s is not None:
        return kappa_s

    if signal_class is not None:
        key = signal_class.upper()
        if key in KAPPA_S:
            return KAPPA_S[key]
        # Try matching prefix (e.g. "16qam" -> "QAM")
        for family, val in KAPPA_S.items():
            if key.endswith(family):
                return val

    logger.warning(
        "estimate_snr_m2m4: no signal_class provided and kappa_s not set; "
        "defaulting to kappa_s=1.0 (constant-envelope assumption). "
        "Pass signal_class= for accurate QAM/APSK/ASK estimation."
    )
    return 1.0


def estimate_snr_m2m4(
    iq_data: np.ndarray,
    kappa_s: float | None = None,
    signal_class: str | None = None,
) -> float:
    """Estimate SNR using the standard M2M4 quadratic method.

    The M2M4 estimator uses the second and fourth moments of the signal
    envelope to separate signal and noise power without spectral analysis.

    For a signal s[n] + w[n] with signal power S and noise power N::

        M2 = E[|x|^2] = S + N
        M4 = E[|x|^4] = kappa_s * S^2 + 4*S*N + 2*N^2

    where ``kappa_s`` is the signal kurtosis (1.0 for constant-envelope like
    PSK, ~1.32 for 16-QAM, ~1.38 for 64-QAM, 2.0 for Gaussian).

    Solving the quadratic gives::

        N = M2 - sqrt(max(0, (2*M2^2 - M4) / (2 - kappa_s)))

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array with at least 64 samples.
    kappa_s : float or None
        Signal kurtosis. If ``None``, looked up from ``signal_class``.
        Common values: 1.0 (PSK), 1.32 (16-QAM), 1.38 (64-QAM).
    signal_class : str or None
        Signal family or modulation name (e.g. "QAM", "PSK", "16qam").
        Used to look up kappa_s when not explicitly provided.

    Returns
    -------
    float
        Estimated SNR in dB, clipped to [-20, 50].
    """
    kappa_s = _resolve_kappa_s(kappa_s, signal_class)
    if len(iq_data) < 64:
        return 0.0

    x = iq_data.astype(np.complex128)
    mag_sq = np.abs(x) ** 2

    m2 = np.mean(mag_sq)
    m4 = np.mean(mag_sq**2)

    if m2 <= 0:
        return 0.0

    # Standard M2M4 quadratic solution
    denom = 2.0 - kappa_s
    if abs(denom) < 1e-10:
        # kappa_s close to 2 (Gaussian signal), fall back to kurtosis ratio
        kappa = m4 / (m2**2)
        if kappa >= 2.0:
            return -20.0  # Noise-dominated
        return 50.0  # Signal-dominated

    discriminant = (2.0 * m2**2 - m4) / denom
    if discriminant < 0:
        discriminant = 0.0

    noise_power = m2 - np.sqrt(discriminant)
    signal_power = m2 - noise_power

    if signal_power <= 0 or noise_power <= 0:
        if noise_power <= 0:
            return 50.0  # Very high SNR (no noise detected)
        return -20.0

    snr_db = 10.0 * np.log10(signal_power / noise_power)
    return float(np.clip(snr_db, -20.0, 50.0))


def estimate_snr_percentile(
    iq_data: np.ndarray,
    window: str = "hann",
    num_segments: int = 8,
) -> float:
    """Estimate SNR using windowed spectral percentile method.

    Splits data into ``num_segments`` segments, computes the percentile-based
    SNR per segment, and returns the median (robust to transients).

    For each segment:

    1. Compute windowed PSD.
    2. Sort power values.
    3. Noise estimate = mean of lower 25th percentile.
    4. Signal estimate = mean of upper 25th percentile.
    5. SNR = 10 * log10(signal / noise).

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    window : str
        Window for PSD computation.
    num_segments : int
        Number of segments for median-of-segments.

    Returns
    -------
    float
        Estimated SNR in dB, clipped to [-20, 50].
    """
    if len(iq_data) < 256:
        return 0.0

    # Ensure enough samples per segment
    seg_len = len(iq_data) // num_segments
    if seg_len < 64:
        num_segments = max(1, len(iq_data) // 64)
        seg_len = len(iq_data) // num_segments

    snr_estimates = []

    for i in range(num_segments):
        start = i * seg_len
        end = start + seg_len
        segment = iq_data[start:end]

        psd = windowed_psd(segment, window=window)
        sorted_power = np.sort(psd)

        n = len(sorted_power)
        noise_estimate = np.mean(sorted_power[: n // 4])
        signal_estimate = np.mean(sorted_power[-(n // 4) :])

        if noise_estimate > 0:
            snr_linear = signal_estimate / noise_estimate
            snr_db = 10.0 * np.log10(snr_linear)
            snr_estimates.append(float(np.clip(snr_db, -20.0, 50.0)))

    if not snr_estimates:
        return 0.0

    return float(np.median(snr_estimates))


def estimate_snr_eigenvalue(
    iq_data: np.ndarray,
    segment_length: int = 256,
    num_segments: int = 16,
) -> float:
    """Estimate SNR using covariance matrix eigenvalue decomposition.

    Splits data into overlapping segments, forms a sample covariance matrix,
    and uses the ratio of the largest to smallest eigenvalues as an SNR proxy.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    segment_length : int
        Length of each segment for covariance estimation.
    num_segments : int
        Number of segments to use.

    Returns
    -------
    float
        Estimated SNR in dB, clipped to [-20, 50].
    """
    n = len(iq_data)
    if n < segment_length:
        return 0.0

    # Collect segments
    step = max(1, (n - segment_length) // num_segments)
    segments = []
    for i in range(num_segments):
        start = i * step
        if start + segment_length > n:
            break
        segments.append(iq_data[start : start + segment_length])

    if len(segments) < 2:
        return 0.0

    # Form data matrix and compute covariance
    data_matrix = np.array(segments, dtype=np.complex128)
    cov = data_matrix.T.conj() @ data_matrix / len(segments)

    # Eigenvalue decomposition
    eigenvalues = np.sort(np.abs(np.linalg.eigvalsh(cov)))

    # SNR estimate from eigenvalue spread
    noise_floor = np.mean(eigenvalues[: len(eigenvalues) // 4])
    signal_peak = np.mean(eigenvalues[-(len(eigenvalues) // 4) :])

    if noise_floor <= 0:
        return 50.0

    snr_db = 10.0 * np.log10(signal_peak / noise_floor)
    return float(np.clip(snr_db, -20.0, 50.0))
