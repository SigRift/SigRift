"""Signal augmentation for training data generation.

Applies randomised impairments to synthetic IQ signals to improve model
generalisation to real-world conditions:

- Frequency offset (tuning error)
- Phase offset
- Time shift (circular)
- Amplitude scaling
- IQ imbalance (amplitude and phase)
- SpecAugment-style frequency masking
- Channel impairments (multipath, CFO, phase noise, SRO)

Uses sigrift.lib.dsp.iq_correction.apply_iq_imbalance for IQ imbalance and
sigrift.lib.dsp.channel_models.apply_channel for channel impairments.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class AugmentationConfig:
    """Configuration for signal augmentation.

    Each tuple specifies a (min, max) range from which a random value is
    drawn uniformly.  Probabilities control how often optional augmentations
    are applied.

    Parameters
    ----------
    freq_offset_hz : tuple[float, float]
        Range of random frequency offset in Hz (normalised to sample rate
        at application time).
    phase_offset_rad : tuple[float, float]
        Range of random initial phase offset in radians.
    time_shift_samples : tuple[int, int]
        Range of random circular time shift in samples.
    amplitude_scale : tuple[float, float]
        Range of random amplitude scaling factor.
    iq_imbalance_amp : tuple[float, float]
        Range of IQ amplitude imbalance (fractional).
    iq_imbalance_phase : tuple[float, float]
        Range of IQ phase imbalance (radians).
    spec_augment_prob : float
        Probability of applying SpecAugment-style frequency masking.
    channel_prob : float
        Probability of applying channel impairments (multipath, CFO, etc.).
    """

    freq_offset_hz: tuple[float, float] = (-1000.0, 1000.0)
    phase_offset_rad: tuple[float, float] = (0.0, 2 * np.pi)
    time_shift_samples: tuple[int, int] = (0, 256)
    amplitude_scale: tuple[float, float] = (0.8, 1.2)
    iq_imbalance_amp: tuple[float, float] = (0.0, 0.05)
    iq_imbalance_phase: tuple[float, float] = (0.0, 0.05)
    spec_augment_prob: float = 0.3
    channel_prob: float = 0.7


# Lighter config for OFDM signals (preserve subcarrier structure)
OFDM_AUGMENTATION_CONFIG = AugmentationConfig(
    freq_offset_hz=(-200.0, 200.0),
    phase_offset_rad=(0.0, 2 * np.pi),
    time_shift_samples=(0, 64),
    amplitude_scale=(0.9, 1.1),
    iq_imbalance_amp=(0.0, 0.03),
    iq_imbalance_phase=(0.0, 0.03),
    spec_augment_prob=0.0,  # don't mask OFDM subcarriers
    channel_prob=0.5,
)


def _apply_freq_mask(
    signal: np.ndarray,
    rng: np.random.RandomState,
) -> np.ndarray:
    """SpecAugment-style frequency masking.

    Transforms to frequency domain, zeros out 1-3 random bands, then
    transforms back.  Helps the model generalise to partial-band
    interference.
    """
    n = len(signal)
    spec = np.fft.fft(signal)
    num_masks = rng.randint(1, 4)
    for _ in range(num_masks):
        mask_width = rng.randint(max(n // 50, 1), max(n // 12, 2))
        start = rng.randint(0, n)
        end = min(start + mask_width, n)
        spec[start:end] = 0.0
    return np.fft.ifft(spec).astype(signal.dtype)


def apply_augmentation(
    signal: np.ndarray,
    config: AugmentationConfig | None = None,
    rng: np.random.RandomState | None = None,
    sample_rate: float = 2_048_000.0,
    is_ofdm: bool = False,
) -> np.ndarray:
    """Apply random augmentations to a signal.

    Parameters
    ----------
    signal : np.ndarray
        Complex IQ signal to augment.
    config : AugmentationConfig or None
        Augmentation configuration.  ``None`` uses the default config, or
        ``OFDM_AUGMENTATION_CONFIG`` when ``is_ofdm`` is True.
    rng : np.random.RandomState or None
        Random state.  ``None`` creates a new unseeded state.
    sample_rate : float
        Sample rate in Hz (used to normalise frequency offset).
    is_ofdm : bool
        If True and config is None, use the gentler OFDM-specific config.

    Returns
    -------
    np.ndarray
        Augmented complex64 signal (same length as input).
    """
    if rng is None:
        rng = np.random.RandomState()

    if config is None:
        config = OFDM_AUGMENTATION_CONFIG if is_ofdm else AugmentationConfig()

    n = len(signal)

    # 1. Frequency offset (simulates tuning error)
    freq_offset_norm = rng.uniform(*config.freq_offset_hz) / sample_rate
    t = np.arange(n)
    signal = signal * np.exp(1j * 2 * np.pi * freq_offset_norm * t)

    # 2. Phase offset
    phase_offset = rng.uniform(*config.phase_offset_rad)
    signal = signal * np.exp(1j * phase_offset)

    # 3. Time shift (zero-pad, not circular — np.roll wraps end-to-start
    #    creating unrealistic discontinuities at the boundary)
    lo, hi = config.time_shift_samples
    if hi > lo:
        shift = rng.randint(lo, max(hi, lo + 1))
        if shift > 0:
            signal = np.concatenate(
                [np.zeros(shift, dtype=signal.dtype), signal[:-shift]]
            )

    # 4. Amplitude scaling
    amp_scale = rng.uniform(*config.amplitude_scale)
    signal = signal * amp_scale

    # 5. IQ imbalance
    if rng.rand() > 0.5:
        amp_imb = rng.uniform(*config.iq_imbalance_amp)
        phase_imb = rng.uniform(*config.iq_imbalance_phase)
        try:
            from sigrift.lib.dsp.iq_correction import apply_iq_imbalance

            signal = apply_iq_imbalance(signal, amp_imb, phase_imb)
        except ImportError:
            # Fallback if DSP module not available yet
            g_i = 1 + amp_imb / 2
            g_q = 1 - amp_imb / 2
            i_part = g_i * signal.real
            q_part = g_q * (
                signal.real * np.sin(phase_imb) + signal.imag * np.cos(phase_imb)
            )
            signal = (i_part + 1j * q_part).astype(np.complex64)

    # 6. SpecAugment-style frequency masking
    if rng.rand() < config.spec_augment_prob:
        signal = _apply_freq_mask(signal, rng)

    # 7. Channel impairments (multipath, CFO, phase noise, SRO)
    if rng.rand() < config.channel_prob:
        try:
            from sigrift.lib.dsp.channel_models import ChannelConfig, apply_channel

            if is_ofdm:
                cfg = ChannelConfig(
                    cfo_hz_range=(-100.0, 100.0),
                    sro_enabled=False,
                    multipath_num_taps=(2, 3),
                    multipath_max_delay=(5, 20),
                )
            else:
                cfg = ChannelConfig()

            signal = apply_channel(signal, config=cfg, rng=rng)
        except ImportError:
            logger.debug(
                "sigrift.lib.dsp.channel_models not available; skipping channel augmentation"
            )

    return signal.astype(np.complex64)
