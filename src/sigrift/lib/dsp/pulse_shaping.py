"""Consolidated Root Raised Cosine (RRC) pulse shaping.

Provides a single, well-tested implementation of the RRC filter and
pulse shaping, replacing 8+ duplicated implementations scattered across
the gen2 codebase.

The RRC filter uses the standard time-domain formula with proper handling
of the singularities at t=0 and t=+/-1/(4*rolloff).
"""

import numpy as np


def rrc_filter(
    num_taps: int,
    samples_per_symbol: int,
    rolloff: float,
) -> np.ndarray:
    """Generate Root Raised Cosine (RRC) filter coefficients.

    Uses the standard time-domain formula::

        h(t) = [sin(pi*t*(1-r)) + 4*r*t*cos(pi*t*(1+r))]
               / [pi*t*(1-(4*r*t)^2)]

    with proper handling of singularities:

    - At t=0: h(0) = (1 - r + 4*r/pi)
    - At t=+/-1/(4*r): h = (r/sqrt(2)) * [(1+2/pi)*sin(pi/(4*r))
      + (1-2/pi)*cos(pi/(4*r))]

    The filter is normalised to unit energy.

    Parameters
    ----------
    num_taps : int
        Number of filter taps (should be odd for symmetric filter).
    samples_per_symbol : int
        Oversampling factor (samples per symbol period).
    rolloff : float
        Roll-off factor in [0, 1]. Common values: 0.2, 0.25, 0.35.

    Returns
    -------
    np.ndarray
        Filter coefficients of length ``num_taps``, normalised to unit energy.

    Raises
    ------
    ValueError
        If ``rolloff`` is outside [0, 1] or ``num_taps < 1``.
    """
    if not 0.0 <= rolloff <= 1.0:
        raise ValueError(f"rolloff must be in [0, 1], got {rolloff}")
    if num_taps < 1:
        raise ValueError(f"num_taps must be >= 1, got {num_taps}")

    sps = float(samples_per_symbol)
    r = float(rolloff)

    # Time indices centred around 0
    center = (num_taps - 1) / 2.0
    n = np.arange(num_taps, dtype=np.float64)
    t = (n - center) / sps  # Time in symbol periods

    h = np.zeros(num_taps, dtype=np.float64)

    for k in range(num_taps):
        tk = t[k]

        if abs(tk) < 1e-12:
            # Singularity at t = 0
            h[k] = 1.0 - r + 4.0 * r / np.pi

        elif r > 0 and abs(abs(tk) - 1.0 / (4.0 * r)) < 1e-12:
            # Singularity at t = +/-1/(4*rolloff)
            h[k] = (r / np.sqrt(2.0)) * (
                (1.0 + 2.0 / np.pi) * np.sin(np.pi / (4.0 * r))
                + (1.0 - 2.0 / np.pi) * np.cos(np.pi / (4.0 * r))
            )

        else:
            # General formula
            pi_t = np.pi * tk
            numerator = np.sin(pi_t * (1.0 - r)) + 4.0 * r * tk * np.cos(
                pi_t * (1.0 + r)
            )
            denominator = pi_t * (1.0 - (4.0 * r * tk) ** 2)

            if abs(denominator) < 1e-30:
                # Fallback for near-zero denominator (should not normally happen)
                h[k] = 0.0
            else:
                h[k] = numerator / denominator

    # Normalise to unit energy
    energy = np.sum(h**2)
    if energy > 0:
        h = h / np.sqrt(energy)

    return h


def apply_rrc_pulse_shaping(
    symbols: np.ndarray,
    samples_per_symbol: int,
    rolloff: float = 0.35,
    num_taps: int = 101,
) -> np.ndarray:
    """Upsample symbols and apply RRC pulse shaping.

    1. Upsample by inserting zeros between symbols.
    2. Convolve with the RRC filter.
    3. Normalise output power to match input symbol power.

    Parameters
    ----------
    symbols : np.ndarray
        Complex symbol array (e.g. QPSK constellation points).
    samples_per_symbol : int
        Oversampling factor.
    rolloff : float
        RRC roll-off factor (default 0.35).
    num_taps : int
        Number of RRC filter taps (default 101).

    Returns
    -------
    np.ndarray
        Pulse-shaped signal. Length is approximately
        ``len(symbols) * samples_per_symbol + num_taps - 1``.
    """
    sps = int(samples_per_symbol)

    # Upsample: insert zeros between symbols
    upsampled = np.zeros(len(symbols) * sps, dtype=np.complex128)
    upsampled[::sps] = symbols

    # Generate and apply RRC filter
    h = rrc_filter(num_taps, sps, rolloff)
    shaped = np.convolve(upsampled, h, mode="full")

    # Normalise output power to match input symbol power
    input_power = np.mean(np.abs(symbols) ** 2) if len(symbols) > 0 else 1.0
    output_power = np.mean(np.abs(shaped) ** 2) if len(shaped) > 0 else 1.0

    if output_power > 0 and input_power > 0:
        shaped = shaped * np.sqrt(input_power / output_power)

    return shaped
