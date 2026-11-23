"""OFDM signal generation with correct subcarrier allocation.

Properly nulls DC, Nyquist, and guard band subcarriers before inserting
pilot tones.  Fixes the gen2 bug where pilot insertion could overwrite
null positions: pilots are now only inserted on non-null subcarriers,
determined by building an explicit set of null indices (DC + Nyquist +
guard bands) and skipping any pilot that falls in that set.
"""

import numpy as np

# WiFi 802.11a/n pilot indices (FFT-index convention)
# 64-subcarrier OFDM: standard positions -21, -7, +7, +21 -> FFT indices 7, 21, 43, 57
WIFI_64_PILOTS = [7, 21, 43, 57]
# 256-subcarrier OFDM (802.11ac/ax)
WIFI_256_PILOTS = [11, 39, 75, 103, 153, 181, 217, 245]


def generate_ofdm_symbol(
    num_subcarriers: int,
    modulation: str = "qpsk",
    guard_fraction: float = 0.0625,
    pilot_indices: list | None = None,
    pilot_value: complex = 1.0 + 0j,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Generate a single OFDM symbol in the frequency domain.

    Allocates data subcarriers with proper nulling:

    1. Generate random data on all subcarriers.
    2. Null the DC subcarrier (index 0).
    3. Null the Nyquist subcarrier (index N/2).
    4. Null guard bands at both edges.
    5. Insert pilots *only* on non-null subcarriers (the key fix).

    The null_indices set is built from DC + Nyquist + guard band indices.
    Any pilot whose index falls in null_indices is silently skipped.

    Parameters
    ----------
    num_subcarriers : int
        FFT size / number of subcarriers (must be >= 4).
    modulation : str
        Subcarrier modulation: ``'bpsk'``, ``'qpsk'``, ``'16qam'``,
        ``'64qam'``.
    guard_fraction : float
        Fraction of subcarriers used as guard bands on each side.
    pilot_indices : list of int or None
        Subcarrier indices for pilot tones. ``None`` auto-detects from
        WiFi defaults for 64/256 subcarriers.
    pilot_value : complex
        Complex value for pilot subcarriers (default +1).
    rng : np.random.RandomState or None
        Random state for reproducibility.

    Returns
    -------
    np.ndarray
        Complex frequency-domain array of length ``num_subcarriers``.

    Raises
    ------
    ValueError
        If ``num_subcarriers < 4`` or unknown modulation.
    """
    if num_subcarriers < 4:
        raise ValueError(f"num_subcarriers must be >= 4, got {num_subcarriers}")

    if rng is None:
        rng = np.random.RandomState()

    symbols = np.zeros(num_subcarriers, dtype=np.complex128)

    # Step 1: Generate modulated data symbols for all subcarriers
    if modulation == "bpsk":
        data = rng.choice([1.0, -1.0], num_subcarriers).astype(np.complex128)
    elif modulation == "qpsk":
        phases = rng.choice(
            [np.pi / 4, 3 * np.pi / 4, 5 * np.pi / 4, 7 * np.pi / 4],
            num_subcarriers,
        )
        data = np.exp(1j * phases)
    elif modulation == "16qam":
        levels = np.array([-3, -1, 1, 3]) / np.sqrt(10.0)
        real = rng.choice(levels, num_subcarriers)
        imag = rng.choice(levels, num_subcarriers)
        data = (real + 1j * imag).astype(np.complex128)
    elif modulation == "64qam":
        levels = np.array([-7, -5, -3, -1, 1, 3, 5, 7]) / np.sqrt(42.0)
        real = rng.choice(levels, num_subcarriers)
        imag = rng.choice(levels, num_subcarriers)
        data = (real + 1j * imag).astype(np.complex128)
    else:
        raise ValueError(f"Unknown modulation: {modulation}")

    symbols[:] = data

    # Step 2--4: Build the complete set of null indices, then null them
    null_indices = set()

    # DC subcarrier (index 0)
    null_indices.add(0)

    # Nyquist subcarrier (index N/2)
    if num_subcarriers >= 2:
        null_indices.add(num_subcarriers // 2)

    # Guard bands
    guard = int(num_subcarriers * guard_fraction)
    if guard > 0:
        # Lower guard band: indices 1..guard (index 0 is already DC-null)
        for idx in range(1, guard + 1):
            null_indices.add(idx)
        # Upper guard band: indices (N-guard)...(N-1)
        for idx in range(num_subcarriers - guard, num_subcarriers):
            null_indices.add(idx)

    # Apply nulling
    for idx in null_indices:
        symbols[idx] = 0.0

    # Step 5: Insert pilots ONLY on non-null subcarriers
    if pilot_indices is None:
        if num_subcarriers == 64:
            pilot_indices = WIFI_64_PILOTS
        elif num_subcarriers == 256:
            pilot_indices = WIFI_256_PILOTS
        else:
            pilot_indices = []

    for idx in pilot_indices:
        if 0 <= idx < num_subcarriers and idx not in null_indices:
            symbols[idx] = pilot_value

    return symbols


def generate_ofdm_signal(
    n_samples: int,
    num_subcarriers: int,
    cp_fraction: float = 0.25,
    modulation: str = "qpsk",
    guard_fraction: float = 0.0625,
    pilot_indices: list | None = None,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Generate a multi-symbol OFDM signal with cyclic prefix.

    Parameters
    ----------
    n_samples : int
        Total number of output time-domain samples.
    num_subcarriers : int
        FFT size / number of subcarriers.
    cp_fraction : float
        Cyclic prefix length as fraction of FFT size.
    modulation : str
        Subcarrier modulation type.
    guard_fraction : float
        Guard band fraction on each side.
    pilot_indices : list of int or None
        Pilot subcarrier indices (``None`` = auto-detect).
    rng : np.random.RandomState or None
        Random state for reproducibility.

    Returns
    -------
    np.ndarray
        Complex time-domain signal of length ``n_samples`` (complex64).
    """
    if rng is None:
        rng = np.random.RandomState()

    cp_length = int(num_subcarriers * cp_fraction)
    symbol_length = num_subcarriers + cp_length
    num_symbols = n_samples // symbol_length + 1

    signal = np.zeros(n_samples, dtype=np.complex64)
    pos = 0

    for _ in range(num_symbols):
        if pos >= n_samples:
            break

        # Generate frequency-domain symbol
        freq_domain = generate_ofdm_symbol(
            num_subcarriers,
            modulation,
            guard_fraction,
            pilot_indices=pilot_indices,
            rng=rng,
        )

        # IFFT to time domain
        time_domain = np.fft.ifft(freq_domain)

        # Add cyclic prefix
        ofdm_symbol = np.concatenate([time_domain[-cp_length:], time_domain])

        # Copy to output
        end_pos = min(pos + len(ofdm_symbol), n_samples)
        signal[pos:end_pos] = ofdm_symbol[: end_pos - pos]
        pos = end_pos

    return signal
