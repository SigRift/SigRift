"""IQ imbalance estimation, correction, and augmentation.

Implements Gram-Schmidt orthogonalization for estimation and correction,
plus a physically correct augmentation formula for training data generation
using the direct-conversion receiver model.

The ``estimate_iq_imbalance`` function returns identity (1.0, 0.0) when
the estimated SNR is below ``min_snr_db`` to avoid noise-corrupted estimates.
"""

import numpy as np


def _quick_snr_db(iq_data: np.ndarray) -> float:
    """Quick SNR estimate for gating purposes (M2M4 moment method).

    Uses the standard M2M4 quadratic solution for constant-envelope signals
    (kappa_s=1). Returns SNR in dB clipped to [-20, 50].

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.

    Returns
    -------
    float
        Estimated SNR in dB.
    """
    if len(iq_data) < 64:
        return 0.0
    x = iq_data.astype(np.complex128)
    mag_sq = np.abs(x) ** 2
    m2 = np.mean(mag_sq)
    m4 = np.mean(mag_sq**2)
    if m2 <= 0:
        return 0.0
    # Standard M2M4 quadratic: N = M2 - sqrt(max(0, 2*M2^2 - M4))
    discriminant = 2.0 * m2**2 - m4
    if discriminant < 0:
        discriminant = 0.0
    noise_power = m2 - np.sqrt(discriminant)
    signal_power = m2 - noise_power
    if signal_power <= 0 or noise_power <= 0:
        if noise_power <= 0:
            return 50.0  # Very high SNR (no noise detected)
        return 0.0
    snr_db = 10.0 * np.log10(signal_power / noise_power)
    return float(np.clip(snr_db, -20.0, 50.0))


def estimate_iq_imbalance(
    iq_data: np.ndarray,
    min_snr_db: float = 5.0,
) -> tuple:
    """Estimate IQ amplitude and phase imbalance using Gram-Schmidt.

    Gram-Schmidt method::

        P_I  = mean(I^2)
        P_Q  = mean(Q^2)
        C_IQ = mean(I * Q)

        amplitude = sqrt(P_Q / P_I)
        phase     = arcsin(C_IQ / sqrt(P_I * P_Q))

    Returns (1.0, 0.0) when estimated SNR < ``min_snr_db`` to avoid
    noise-corrupted estimates.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array.
    min_snr_db : float
        Minimum SNR threshold below which no correction is applied.

    Returns
    -------
    tuple of (float, float)
        ``(amplitude, phase)`` where amplitude=1.0 and phase=0.0 mean
        no imbalance.
    """
    if len(iq_data) == 0:
        return (1.0, 0.0)

    # SNR guard
    snr = _quick_snr_db(iq_data)
    if snr < min_snr_db:
        return (1.0, 0.0)

    i_data = iq_data.real.astype(np.float64)
    q_data = iq_data.imag.astype(np.float64)

    p_i = np.mean(i_data**2)
    p_q = np.mean(q_data**2)
    c_iq = np.mean(i_data * q_data)

    if p_i <= 0 or p_q <= 0:
        return (1.0, 0.0)

    amplitude = float(np.sqrt(p_q / p_i))
    sin_arg = np.clip(c_iq / np.sqrt(p_i * p_q), -1.0, 1.0)
    phase = float(np.arcsin(sin_arg))

    return (amplitude, phase)


def correct_iq_imbalance(
    iq_data: np.ndarray,
    amplitude: float,
    phase: float,
) -> np.ndarray:
    """Correct IQ imbalance using Gram-Schmidt inverse.

    Applies the inverse of the estimated imbalance to restore balance::

        I_corr = I
        Q_corr = (Q - amplitude * I * sin(phase)) / (amplitude * cos(phase))

    This is the Gram-Schmidt step matching :func:`estimate_iq_imbalance`:
    ``amplitude * sin(phase)`` equals ``C_IQ / P_I``, so subtracting that
    multiple of I removes the I/Q correlation, and dividing by
    ``amplitude * cos(phase)`` restores ``P_Q == P_I``.

    Parameters
    ----------
    iq_data : np.ndarray
        Complex IQ array with imbalance.
    amplitude : float
        Estimated amplitude imbalance (Q/I gain ratio).
    phase : float
        Estimated phase imbalance in radians.

    Returns
    -------
    np.ndarray
        Corrected complex IQ array, same dtype as input.
    """
    if len(iq_data) == 0:
        return iq_data.copy()

    i_data = iq_data.real.astype(np.float64)
    q_data = iq_data.imag.astype(np.float64)

    cos_phase = np.cos(phase)
    sin_phase = np.sin(phase)

    if abs(amplitude * cos_phase) < 1e-10:
        return iq_data.copy()

    i_corr = i_data
    q_corr = (q_data - amplitude * i_data * sin_phase) / (amplitude * cos_phase)

    return (i_corr + 1j * q_corr).astype(iq_data.dtype)


def apply_iq_imbalance(
    iq_data: np.ndarray,
    amplitude_imb: float,
    phase_imb: float,
) -> np.ndarray:
    """Apply IQ imbalance to a signal for data augmentation.

    Uses a direct-conversion receiver with symmetric LO phase errors::

        g_i = 1 + amplitude_imb / 2
        g_q = 1 - amplitude_imb / 2

        I_out = g_i * (I * cos(phase/2) + Q * sin(phase/2))
        Q_out = g_q * (I * sin(phase/2) + Q * cos(phase/2))

    Both cross terms have the same sign: the LO quadrature separation is
    ``pi/2 - phase_imb``. For a complex tone ``exp(j*theta)``, the rails are
    ``g_i*cos(theta - phase_imb/2)`` and ``g_q*sin(theta + phase_imb/2)``.
    Opposite cross-term signs would produce a common phase rotation, not a
    quadrature error.

    This models:

    - ``amplitude_imb``: fractional gain difference between I and Q paths
      (e.g. 0.05 means 5% imbalance, g_i=1.025, g_q=0.975).
    - ``phase_imb``: phase error in radians between I and Q LO signals.
      Positive error gives positive I/Q correlation for balanced input,
      matching :func:`estimate_iq_imbalance`. With I as the reference, this
      is the receiver model ``Q_out = Q*cos(phase) + I*sin(phase)`` up to a
      common input rotation and the separate path gains.

    Parameters
    ----------
    iq_data : np.ndarray
        Clean complex IQ array.
    amplitude_imb : float
        Fractional amplitude imbalance (e.g. 0.05 for 5%).
    phase_imb : float
        Phase imbalance in radians (e.g. 0.05 for about 3 degrees).

    Returns
    -------
    np.ndarray
        Complex IQ array with imbalance applied, same dtype as input.
    """
    if len(iq_data) == 0:
        return iq_data.copy()

    i_in = iq_data.real.astype(np.float64)
    q_in = iq_data.imag.astype(np.float64)

    g_i = 1.0 + amplitude_imb / 2.0
    g_q = 1.0 - amplitude_imb / 2.0

    cos_half = np.cos(phase_imb / 2.0)
    sin_half = np.sin(phase_imb / 2.0)

    i_out = g_i * (i_in * cos_half + q_in * sin_half)
    q_out = g_q * (i_in * sin_half + q_in * cos_half)

    return (i_out + 1j * q_out).astype(iq_data.dtype)
