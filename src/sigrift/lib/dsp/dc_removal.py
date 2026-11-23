"""DC offset removal for IQ data.

Provides IIR high-pass filtering (preferred) and mean subtraction (fallback).
The IIR filter includes optional warm-up transient handling via settle_samples,
which prepends mirrored data so the filter state settles before the actual
signal begins.
"""

import numpy as np
from scipy.signal import lfilter


def dc_removal_alpha_from_cutoff(cutoff_hz: float, sample_rate_hz: float) -> float:
    """Compute IIR alpha coefficient from a desired -3 dB cutoff frequency.

    The single-pole high-pass filter has the transfer function::

        H(z) = ((1 + alpha) / 2) * (1 - z^-1) / (1 - alpha * z^-1)

    The -3 dB cutoff relates to alpha via the exact relation::

        alpha = exp(-2 * pi * fc / fs)

    Parameters
    ----------
    cutoff_hz : float
        Desired -3 dB cutoff frequency in Hz.
    sample_rate_hz : float
        Sample rate in Hz.

    Returns
    -------
    float
        Alpha coefficient in (0, 1).

    Raises
    ------
    ValueError
        If frequencies are non-positive or cutoff exceeds Nyquist.
    """
    if cutoff_hz <= 0 or sample_rate_hz <= 0:
        raise ValueError("cutoff_hz and sample_rate_hz must be positive")
    if cutoff_hz >= sample_rate_hz / 2:
        raise ValueError("cutoff_hz must be less than Nyquist (sample_rate_hz / 2)")
    return float(np.exp(-2.0 * np.pi * cutoff_hz / sample_rate_hz))


def remove_dc_iir(
    iq_data: np.ndarray,
    alpha: float = 0.9999,
    settle_samples: int = 0,
) -> np.ndarray:
    """Remove DC offset using a single-pole IIR high-pass filter.

    Implements the standard first-order DC-blocking filter::

        gain = (1 + alpha) / 2
        b = [gain, -gain]
        a = [1, -alpha]
        y = lfilter(b, a, x)

    When ``settle_samples > 0``, the filter is "warmed up" by prepending
    mirrored data so the IIR transient decays before the real signal begins.
    The mirrored prefix is discarded from the output.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    alpha : float
        Pole location in (0, 1). Closer to 1 means a narrower DC notch.
        Default 0.9999 gives approximately 0.03 Hz notch at 2.048 MHz.
    settle_samples : int
        Number of mirrored samples to prepend for transient warm-up.
        0 disables (default). Typical value: 256--1024.

    Returns
    -------
    np.ndarray
        DC-removed complex IQ array, same length and dtype as input.

    Raises
    ------
    ValueError
        If alpha is not in (0, 1).
    """
    if len(iq_data) == 0:
        return iq_data.copy()

    if not 0 < alpha < 1:
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")

    # Standard single-pole high-pass coefficients
    gain = (1.0 + alpha) / 2.0
    b = np.array([gain, -gain], dtype=np.float64)
    a = np.array([1.0, -alpha], dtype=np.float64)

    if settle_samples > 0:
        # Prepend mirrored data so the IIR state settles before the real data
        n_settle = min(settle_samples, len(iq_data))
        prefix = iq_data[:n_settle][::-1]
        extended = np.concatenate([prefix, iq_data])
        filtered = lfilter(b, a, extended)
        return filtered[n_settle:].astype(iq_data.dtype)
    else:
        return lfilter(b, a, iq_data).astype(iq_data.dtype)


def remove_dc_mean(iq_data: np.ndarray) -> np.ndarray:
    """Remove DC offset by subtracting the mean.

    Simple fallback method. Suitable for short, stationary segments where
    the IIR approach is unnecessary.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.

    Returns
    -------
    np.ndarray
        DC-removed complex IQ array, same dtype as input.
    """
    if len(iq_data) == 0:
        return iq_data.copy()
    return (iq_data - np.mean(iq_data)).astype(iq_data.dtype)
