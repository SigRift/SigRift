"""Channel impairment models for training data augmentation.

Provides physically realistic channel effects:

- Phase noise (Wiener process with periodic modulo-2pi wrapping)
- Multipath fading (sparse FIR)
- Carrier frequency offset (CFO)
- 1/f (flicker / pink) noise
- Sample rate offset (SRO) via linear interpolation
- ADC quantization (uniform, configurable bit depth)
- Frequency drift (linear ramp over signal duration)
- AGC transient modeling (gain steps with exponential settling)
- Convenience function to apply all with configurable probabilities

**Bug fix from gen2**: Phase noise now wraps the accumulated phase modulo
2*pi in chunks of 4096 samples to prevent unbounded float64 accumulation
that degrades precision for long signals.
"""

from dataclasses import dataclass

import numpy as np
from scipy.signal import lfilter


@dataclass
class ChannelConfig:
    """Configuration for channel impairment application.

    Each impairment has an enable flag and parameter range.
    ``apply_channel`` draws random parameters from these ranges.
    """

    # Overall probability of applying any channel effects
    apply_probability: float = 0.7

    # Per-impairment enable/probability
    multipath_enabled: bool = True
    multipath_probability: float = 0.5
    multipath_num_taps: tuple = (2, 6)
    multipath_max_delay: tuple = (5, 50)
    multipath_power_decay_db: tuple = (3.0, 15.0)

    cfo_enabled: bool = True
    cfo_probability: float = 0.5
    cfo_hz_range: tuple = (-500.0, 500.0)
    cfo_sample_rate: float = 2048000.0

    phase_noise_enabled: bool = True
    phase_noise_probability: float = 0.5
    phase_noise_linewidth_range: tuple = (10.0, 500.0)

    sro_enabled: bool = True
    sro_probability: float = 0.5
    sro_ppm_range: tuple = (-20.0, 20.0)

    adc_bits: int = 8  # 8-bit for RTL-SDR; 0 disables quantization
    freq_drift_ppm_range: tuple = (0.0, 0.0)  # (0,0) means disabled

    agc_enabled: bool = True
    agc_probability: float = 0.3
    agc_step_range_db: tuple = (1.0, 6.0)
    agc_settle_samples: int = 256

    dc_offset_enabled: bool = True
    dc_offset_probability: float = 0.5
    dc_offset_magnitude_range: tuple = (0.005, 0.05)

    flicker_noise_enabled: bool = False
    flicker_noise_probability: float = 0.3
    flicker_noise_corner_freq_hz_range: tuple = (1.0, 100.0)
    flicker_noise_magnitude_range: tuple = (0.01, 0.1)


def apply_dc_offset(
    signal: np.ndarray,
    magnitude: float = 0.02,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Add DC offset to model direct-conversion receiver LO leakage.

    RTL-SDR and similar zero-IF receivers have LO self-mixing that creates
    a DC spike in the baseband signal.  The magnitude varies with temperature
    and individual receiver characteristics (typically 0.5-5% of full scale).

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    magnitude : float
        Maximum absolute DC offset per channel (I and Q offsets are drawn
        independently from [-magnitude, +magnitude]).
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal with DC offset added, same dtype as input.
    """
    if rng is None:
        rng = np.random.RandomState()
    dc_i = rng.uniform(-magnitude, magnitude)
    dc_q = rng.uniform(-magnitude, magnitude)
    return (signal + complex(dc_i, dc_q)).astype(signal.dtype)


def apply_adc_quantization(
    signal: np.ndarray,
    bits: int = 8,
) -> np.ndarray:
    """Apply uniform ADC quantization to a complex signal.

    Clips real and imaginary parts to [-1, 1] and quantizes to 2^bits
    uniform levels.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    bits : int
        Number of ADC bits (e.g. 8 for RTL-SDR).

    Returns
    -------
    np.ndarray
        Quantized signal with same dtype as input.
    """
    levels = 2**bits
    # Clip to [-1, 1]
    real = np.clip(signal.real, -1.0, 1.0)
    imag = np.clip(signal.imag, -1.0, 1.0)
    # Uniform quantization: map [-1,1] to integer levels then back
    real = np.round(real * (levels / 2 - 1)) / (levels / 2 - 1)
    imag = np.round(imag * (levels / 2 - 1)) / (levels / 2 - 1)
    return (real + 1j * imag).astype(signal.dtype)


def apply_frequency_drift(
    signal: np.ndarray,
    ppm: float,
    sample_rate_hz: float,
) -> np.ndarray:
    """Apply a linear frequency drift over the signal duration.

    Models slow oscillator drift where instantaneous frequency ramps
    linearly from 0 to ``drift_hz`` over the signal length.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    ppm : float
        Drift magnitude in parts per million.
    sample_rate_hz : float
        Sample rate in Hz.

    Returns
    -------
    np.ndarray
        Signal with frequency drift applied, same dtype as input.
    """
    n = len(signal)
    drift_hz = ppm * 1e-6 * sample_rate_hz
    t = np.arange(n) / sample_rate_hz
    # Phase is the cumulative integral of linearly-ramping instantaneous freq:
    #   inst_freq(t) = drift_hz * t / T
    #   phase(t) = 2*pi * drift_hz * t^2 / (2*T)
    duration = n / sample_rate_hz
    phase_ramp = 2.0 * np.pi * drift_hz * t * t / (2.0 * duration)
    return (signal * np.exp(1j * phase_ramp)).astype(signal.dtype)


def apply_agc_transient(
    signal: np.ndarray,
    step_db: float = 3.0,
    settle_samples: int = 256,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply AGC gain-step transients to a signal.

    Models an automatic gain control circuit that periodically adjusts
    gain in discrete steps, with exponential settling between steps.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    step_db : float
        Magnitude of each gain step in dB.
    settle_samples : int
        Number of samples for exponential settling
        (time constant = settle_samples / 3).
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal with AGC transients applied, same dtype as input.
    """
    if rng is None:
        rng = np.random.RandomState()

    n = len(signal)
    gain_envelope = np.ones(n, dtype=np.float64)

    # Place 1-3 random gain steps throughout the signal
    num_steps = rng.randint(1, 4)
    step_positions = np.sort(rng.randint(0, max(n - settle_samples, 1), num_steps))

    tau = max(settle_samples / 3.0, 1.0)  # time constant

    for pos in step_positions:
        direction = rng.choice([-1, 1])
        delta_linear = 10.0 ** (direction * step_db / 20.0) - 1.0

        remaining = n - pos
        t = np.arange(remaining)
        transient = delta_linear * np.exp(-t / tau)
        gain_envelope[pos:] *= 1.0 + transient

    return (signal * gain_envelope).astype(signal.dtype)


def apply_phase_noise(
    signal: np.ndarray,
    linewidth_hz: float,
    sample_rate_hz: float,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply phase noise modeled as a Wiener process (random walk).

    The phase increment variance per sample is::

        var = 2 * pi * linewidth / sample_rate

    **SigRift fix**: The accumulated phase is wrapped modulo 2*pi periodically
    (every 4096 samples) to prevent unbounded growth that degrades float64
    precision for long signals.  Wrapping is done by processing the cumulative
    sum in chunks: each chunk starts from the carry-over phase of the previous
    chunk (reduced modulo 2*pi), preserving continuity.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    linewidth_hz : float
        3-dB linewidth of the oscillator in Hz.
    sample_rate_hz : float
        Sample rate in Hz.
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal with phase noise applied, same dtype as input.
    """
    if rng is None:
        rng = np.random.RandomState()

    n = len(signal)
    phase_var = 2.0 * np.pi * linewidth_hz / sample_rate_hz
    phase_std = np.sqrt(phase_var)
    phase_increments = rng.randn(n) * phase_std

    # Chunked cumsum with periodic modulo-2pi wrapping to prevent
    # unbounded float64 accumulation.
    chunk_size = 4096
    phase_walk = np.empty(n, dtype=np.float64)
    carry = 0.0

    for start in range(0, n, chunk_size):
        end = min(start + chunk_size, n)
        chunk = phase_increments[start:end]
        # Cumsum within this chunk, offset by carry from previous chunk
        chunk_cumsum = np.cumsum(chunk) + carry
        # Store the result
        phase_walk[start:end] = chunk_cumsum
        # Wrap the carry phase modulo 2*pi for the next chunk
        carry = chunk_cumsum[-1] % (2.0 * np.pi)

    return (signal * np.exp(1j * phase_walk)).astype(signal.dtype)


def apply_flicker_noise(
    signal: np.ndarray,
    corner_freq_hz: float = 10.0,
    magnitude: float = 0.05,
    sample_rate_hz: float = 2_048_000.0,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Add 1/f (flicker / pink) noise to a complex signal.

    Models low-frequency gain fluctuations caused by semiconductor
    flicker noise in oscillators and amplifiers.  The noise spectrum
    rolls off as ~1/f below *corner_freq_hz*.

    Implementation:
        1. Generate white noise.
        2. Cumulative-sum to produce a ~1/f characteristic.
        3. High-pass filter at *corner_freq_hz* to limit DC energy.
        4. Normalise and scale to *magnitude* relative to signal RMS.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    corner_freq_hz : float
        Corner frequency in Hz that controls the low-frequency rolloff.
    magnitude : float
        Noise amplitude as a fraction of the signal RMS.
    sample_rate_hz : float
        Sample rate in Hz.
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal with 1/f noise added, same dtype as input.
    """
    if rng is None:
        rng = np.random.RandomState()

    n = len(signal)

    # Generate 1/f-like noise via cumulative sum of white noise
    white_i = rng.randn(n)
    white_q = rng.randn(n)
    pink_i = np.cumsum(white_i)
    pink_q = np.cumsum(white_q)

    # High-pass filter: single-pole IIR to remove energy below corner_freq_hz
    # alpha = 1 / (1 + fs / (2*pi*fc))  -- larger alpha keeps more low freq
    alpha = 1.0 / (1.0 + sample_rate_hz / (2.0 * np.pi * corner_freq_hz))
    # First-order high-pass: y[n] = (1-alpha)*(y[n-1] + x[n] - x[n-1])
    # Transfer function: H(z) = (1-alpha)(1 - z^-1) / (1 - (1-alpha)z^-1)
    coeff = 1.0 - alpha
    b_hp = np.array([coeff, -coeff])
    a_hp = np.array([1.0, -coeff])
    hp_i = lfilter(b_hp, a_hp, pink_i)
    hp_q = lfilter(b_hp, a_hp, pink_q)

    # Normalise to unit RMS
    noise = hp_i + 1j * hp_q
    noise_rms = np.sqrt(np.mean(np.abs(noise) ** 2))
    if noise_rms > 0:
        noise = noise / noise_rms

    # Scale relative to signal RMS
    sig_rms = np.sqrt(np.mean(np.abs(signal) ** 2))
    noise = noise * (magnitude * sig_rms)

    return (signal + noise).astype(signal.dtype)


def apply_multipath(
    signal: np.ndarray,
    num_taps: int = 4,
    max_delay_samples: int = 20,
    power_decay_db: float = 10.0,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply multipath channel using a sparse FIR filter.

    Creates a tap-delay-line channel with an exponentially decaying
    power profile.  The output is normalized to preserve total power.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    num_taps : int
        Number of multipath taps (including direct path).
    max_delay_samples : int
        Maximum delay spread in samples.
    power_decay_db : float
        Total power decay from first to last tap in dB.
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal after multipath (same length as input, power preserved).
    """
    if rng is None:
        rng = np.random.RandomState()

    # Generate random tap delays (sorted, first tap at 0)
    delays = np.sort(rng.randint(0, max_delay_samples + 1, num_taps))
    delays[0] = 0  # Direct path

    # Exponentially decaying power profile
    decay_per_tap = power_decay_db / max(num_taps - 1, 1)
    tap_powers = 10.0 ** (-decay_per_tap * np.arange(num_taps) / 10.0)

    # Random phase per tap
    tap_phases = rng.uniform(0, 2 * np.pi, num_taps)
    taps = np.sqrt(tap_powers) * np.exp(1j * tap_phases)

    # Build sparse FIR
    fir_len = int(delays[-1]) + 1
    h = np.zeros(fir_len, dtype=np.complex128)
    for delay, tap in zip(delays.astype(int), taps):
        h[delay] += tap

    # Normalize to preserve power
    h_power = np.sum(np.abs(h) ** 2)
    if h_power > 0:
        h = h / np.sqrt(h_power)

    # Apply via convolution, keep same length
    output = np.convolve(signal, h, mode="full")[: len(signal)]
    return output.astype(signal.dtype)


def apply_cfo(
    signal: np.ndarray,
    cfo_hz: float,
    sample_rate_hz: float,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply carrier frequency offset.

    Multiplies the signal by ``exp(j * 2*pi * cfo * t)``.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    cfo_hz : float
        Frequency offset in Hz.
    sample_rate_hz : float
        Sample rate in Hz.
    rng : np.random.RandomState or None
        Random state (unused, for API consistency).

    Returns
    -------
    np.ndarray
        Signal with frequency offset applied, same dtype as input.
    """
    n = len(signal)
    t = np.arange(n) / sample_rate_hz
    return (signal * np.exp(1j * 2.0 * np.pi * cfo_hz * t)).astype(signal.dtype)


def apply_sro(
    signal: np.ndarray,
    sro_ppm: float,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply sample rate offset via linear interpolation.

    SRO causes the sample clock to run slightly fast or slow, effectively
    resampling the signal at a different rate.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    sro_ppm : float
        Sample rate offset in parts per million.
    rng : np.random.RandomState or None
        Random state (unused, for API consistency).

    Returns
    -------
    np.ndarray
        Signal with SRO applied (same length as input).
    """
    n = len(signal)
    # New sample indices at the offset rate
    rate_ratio = 1.0 + sro_ppm * 1e-6
    new_indices = np.arange(n) * rate_ratio

    # Clip to valid range
    new_indices = np.clip(new_indices, 0, n - 1)

    # Linear interpolation for real and imag separately
    old_indices = np.arange(n).astype(np.float64)
    i_resampled = np.interp(new_indices, old_indices, signal.real.astype(np.float64))
    q_resampled = np.interp(new_indices, old_indices, signal.imag.astype(np.float64))

    return (i_resampled + 1j * q_resampled).astype(signal.dtype)


def apply_channel_fast(
    signal: np.ndarray,
    config: ChannelConfig,
    rng: np.random.RandomState,
) -> np.ndarray:
    """Optimized channel impairment chain — fuses phase operations.

    Combines CFO, phase noise, and frequency drift into a single complex
    multiply instead of 3 separate np.exp(1j*...) calls. ~2-3x faster than
    apply_channel() for long signals (16384+).
    """
    if rng.rand() > config.apply_probability:
        return signal

    n = len(signal)
    result = signal  # In-place where possible

    # Multipath (FIR — must be separate)
    if config.multipath_enabled and rng.rand() < config.multipath_probability:
        num_taps = rng.randint(
            config.multipath_num_taps[0], config.multipath_num_taps[1] + 1
        )
        max_delay = rng.randint(
            config.multipath_max_delay[0], config.multipath_max_delay[1] + 1
        )
        decay = rng.uniform(
            config.multipath_power_decay_db[0], config.multipath_power_decay_db[1]
        )
        result = apply_multipath(result, num_taps, max_delay, decay, rng)

    # DC offset
    if config.dc_offset_enabled and rng.rand() < config.dc_offset_probability:
        mag = rng.uniform(
            config.dc_offset_magnitude_range[0], config.dc_offset_magnitude_range[1]
        )
        dc_i = rng.uniform(-mag, mag)
        dc_q = rng.uniform(-mag, mag)
        result = result + complex(dc_i, dc_q)

    # AGC transient
    if config.agc_enabled and rng.rand() < config.agc_probability:
        step_db = rng.uniform(config.agc_step_range_db[0], config.agc_step_range_db[1])
        result = apply_agc_transient(result, step_db, config.agc_settle_samples, rng)

    # --- Fused phase operations: freq_drift + CFO + phase_noise ---
    # Accumulate total phase offset, apply as single complex multiply
    phase = np.zeros(n, dtype=np.float64)
    t = np.arange(n, dtype=np.float64)
    sr = config.cfo_sample_rate

    # Frequency drift (quadratic phase)
    if config.freq_drift_ppm_range != (0.0, 0.0):
        drift_ppm = rng.uniform(
            config.freq_drift_ppm_range[0], config.freq_drift_ppm_range[1]
        )
        drift_hz = drift_ppm * 1e-6 * sr
        duration = n / sr
        phase += 2.0 * np.pi * drift_hz * (t / sr) ** 2 / (2.0 * duration)

    # CFO (linear phase)
    if config.cfo_enabled and rng.rand() < config.cfo_probability:
        cfo = rng.uniform(config.cfo_hz_range[0], config.cfo_hz_range[1])
        phase += 2.0 * np.pi * cfo * t / sr

    # Phase noise (Wiener walk — can't avoid cumsum but skip separate exp)
    if config.phase_noise_enabled and rng.rand() < config.phase_noise_probability:
        linewidth = rng.uniform(
            config.phase_noise_linewidth_range[0], config.phase_noise_linewidth_range[1]
        )
        phase_std = np.sqrt(2.0 * np.pi * linewidth / sr)
        phase += np.cumsum(rng.randn(n) * phase_std)

    # Single complex multiply for all phase effects
    if np.any(phase != 0):
        result = (result * np.exp(1j * phase)).astype(signal.dtype)

    # Flicker noise (additive, not phase — stays separate)
    if config.flicker_noise_enabled and rng.rand() < config.flicker_noise_probability:
        corner = rng.uniform(
            config.flicker_noise_corner_freq_hz_range[0],
            config.flicker_noise_corner_freq_hz_range[1],
        )
        mag = rng.uniform(
            config.flicker_noise_magnitude_range[0],
            config.flicker_noise_magnitude_range[1],
        )
        result = apply_flicker_noise(result, corner, mag, sr, rng)

    # SRO (resampling — must be separate)
    if config.sro_enabled and rng.rand() < config.sro_probability:
        sro = rng.uniform(config.sro_ppm_range[0], config.sro_ppm_range[1])
        result = apply_sro(result, sro, rng)

    # ADC quantization (last)
    if config.adc_bits > 0:
        result = apply_adc_quantization(result, config.adc_bits)

    return np.asarray(result, dtype=signal.dtype)


def apply_channel(
    signal: np.ndarray,
    config: ChannelConfig | None = None,
    rng: np.random.RandomState | None = None,
) -> np.ndarray:
    """Apply a chain of channel impairments with random parameters.

    Order: multipath -> DC offset -> AGC -> freq_drift -> CFO -> phase noise -> flicker noise -> SRO -> ADC.
    Each impairment is applied with its configured probability.

    Parameters
    ----------
    signal : np.ndarray
        Complex input signal.
    config : ChannelConfig or None
        Channel configuration (uses defaults if ``None``).
    rng : np.random.RandomState or None
        Random state.

    Returns
    -------
    np.ndarray
        Signal with channel impairments applied.
    """
    if config is None:
        config = ChannelConfig()
    if rng is None:
        rng = np.random.RandomState()

    # Overall gate
    if rng.rand() > config.apply_probability:
        return signal.copy()

    result = signal.copy()

    # Multipath
    if config.multipath_enabled and rng.rand() < config.multipath_probability:
        num_taps = rng.randint(
            config.multipath_num_taps[0], config.multipath_num_taps[1] + 1
        )
        max_delay = rng.randint(
            config.multipath_max_delay[0], config.multipath_max_delay[1] + 1
        )
        decay = rng.uniform(
            config.multipath_power_decay_db[0], config.multipath_power_decay_db[1]
        )
        result = apply_multipath(result, num_taps, max_delay, decay, rng)

    # DC offset (LO leakage in direct-conversion receivers, after multipath)
    if config.dc_offset_enabled and rng.rand() < config.dc_offset_probability:
        mag = rng.uniform(
            config.dc_offset_magnitude_range[0], config.dc_offset_magnitude_range[1]
        )
        result = apply_dc_offset(result, mag, rng)

    # AGC transient (after multipath, before frequency effects)
    if config.agc_enabled and rng.rand() < config.agc_probability:
        step_db = rng.uniform(config.agc_step_range_db[0], config.agc_step_range_db[1])
        result = apply_agc_transient(result, step_db, config.agc_settle_samples, rng)

    # Frequency drift
    if config.freq_drift_ppm_range != (0.0, 0.0):
        drift_ppm = rng.uniform(
            config.freq_drift_ppm_range[0], config.freq_drift_ppm_range[1]
        )
        result = apply_frequency_drift(result, drift_ppm, config.cfo_sample_rate)

    # CFO
    if config.cfo_enabled and rng.rand() < config.cfo_probability:
        cfo = rng.uniform(config.cfo_hz_range[0], config.cfo_hz_range[1])
        result = apply_cfo(result, cfo, config.cfo_sample_rate, rng)

    # Phase noise
    if config.phase_noise_enabled and rng.rand() < config.phase_noise_probability:
        linewidth = rng.uniform(
            config.phase_noise_linewidth_range[0],
            config.phase_noise_linewidth_range[1],
        )
        result = apply_phase_noise(result, linewidth, config.cfo_sample_rate, rng)

    # Flicker (1/f) noise
    if config.flicker_noise_enabled and rng.rand() < config.flicker_noise_probability:
        corner = rng.uniform(
            config.flicker_noise_corner_freq_hz_range[0],
            config.flicker_noise_corner_freq_hz_range[1],
        )
        mag = rng.uniform(
            config.flicker_noise_magnitude_range[0],
            config.flicker_noise_magnitude_range[1],
        )
        result = apply_flicker_noise(result, corner, mag, config.cfo_sample_rate, rng)

    # SRO
    if config.sro_enabled and rng.rand() < config.sro_probability:
        sro = rng.uniform(config.sro_ppm_range[0], config.sro_ppm_range[1])
        result = apply_sro(result, sro, rng)

    # ADC quantization (last in the chain)
    if config.adc_bits > 0:
        result = apply_adc_quantization(result, config.adc_bits)

    return result


# ---------------------------------------------------------------------------
# Preset configurations
# ---------------------------------------------------------------------------

RTL_SDR_REALISTIC = ChannelConfig(
    apply_probability=1.0,
    multipath_enabled=True,
    multipath_probability=1.0,
    multipath_num_taps=(2, 6),
    multipath_max_delay=(5, 50),
    multipath_power_decay_db=(3.0, 15.0),
    cfo_enabled=True,
    cfo_probability=1.0,
    cfo_hz_range=(-500.0, 500.0),
    phase_noise_enabled=True,
    phase_noise_probability=1.0,
    phase_noise_linewidth_range=(10.0, 500.0),
    sro_enabled=True,
    sro_probability=1.0,
    sro_ppm_range=(-20.0, 20.0),
    adc_bits=8,
    agc_enabled=True,
    agc_probability=1.0,
    agc_step_range_db=(1.0, 6.0),
    agc_settle_samples=256,
    dc_offset_enabled=True,
    dc_offset_probability=1.0,
    dc_offset_magnitude_range=(0.005, 0.05),
    flicker_noise_enabled=True,
    flicker_noise_probability=0.5,
    flicker_noise_corner_freq_hz_range=(5.0, 50.0),
    flicker_noise_magnitude_range=(0.02, 0.08),
)
