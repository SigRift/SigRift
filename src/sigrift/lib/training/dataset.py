"""On-the-fly signal generation dataset.

Generates synthetic IQ samples per epoch using
``sigrift.lib.training.signal_factory.generate_signal`` exclusively.  Supports
SNR-weighted class distribution to handle class imbalance.

FIX: gen2's val SNR range (0--20) was different from training (-5--25),
which caused misleading validation metrics.  This dataset uses the same
configurable SNR range for both.
"""

from __future__ import annotations

import logging
from typing import Iterator

import numpy as np
import torch
from torch.utils.data import IterableDataset

from sigrift.lib.dsp.channel_models import ChannelConfig, apply_channel
from sigrift.lib.taxonomy import CLASS_TO_FAMILY
from sigrift.lib.training.augmentation import (
    AugmentationConfig,
    OFDM_AUGMENTATION_CONFIG,
    apply_augmentation,
)
from sigrift.lib.training.signal_factory import generate_signal

logger = logging.getLogger(__name__)


class OnTheFlySignalDataset(IterableDataset):
    """Generates synthetic IQ samples on-the-fly per epoch.

    Each iteration yields ``(tensor[2, input_samples], class_idx)`` pairs
    where the 2 channels are I and Q components.

    Parameters
    ----------
    classes : list[str]
        List of modulation class names.
    samples_per_epoch : int
        Total number of samples per full iteration.
    input_samples : int
        Number of IQ samples per signal.
    snr_range : tuple[float, float]
        SNR range in dB.  Uses weighted sampling: 30% low, 40% mid, 30% high.
    augmentation_config : AugmentationConfig or None
        Augmentation config.  ``None`` uses the default.
    seed : int or None
        Random seed.  ``None`` for non-deterministic.
    sample_rate : float
        Nominal sample rate in Hz (passed to signal generator and augmentation).
    """

    def __init__(
        self,
        classes: list[str],
        samples_per_epoch: int = 100_000,
        input_samples: int = 4096,
        snr_range: tuple[float, float] = (-5.0, 25.0),
        augmentation_config: AugmentationConfig | None = None,
        seed: int | None = None,
        sample_rate: float = 2_048_000.0,
        channel_config: ChannelConfig | None = None,
    ) -> None:
        super().__init__()
        self.classes = classes
        self.samples_per_epoch = samples_per_epoch
        self.input_samples = input_samples
        self.snr_range = snr_range
        self.augmentation_config = augmentation_config
        self.seed = seed
        self.sample_rate = sample_rate
        self.channel_config = channel_config
        self.class_to_idx = {c: i for i, c in enumerate(classes)}

    def _sample_snr(self, rng: np.random.RandomState) -> float:
        """SNR-weighted sampling: 30% low (<0 dB), 40% mid (0-10 dB), 30% high (>10 dB).

        This distribution ensures the model sees enough challenging low-SNR
        examples while still training on clean signals.
        """
        snr_lo, snr_hi = self.snr_range
        roll = rng.rand()
        if roll < 0.3:
            # Low SNR band
            return rng.uniform(snr_lo, min(0.0, snr_hi))
        elif roll < 0.7:
            # Mid SNR band
            return rng.uniform(max(0.0, snr_lo), min(10.0, snr_hi))
        else:
            # High SNR band
            return rng.uniform(max(10.0, snr_lo), snr_hi)

    def __iter__(self) -> Iterator[tuple[torch.Tensor, int]]:
        worker_info = torch.utils.data.get_worker_info()
        if worker_info is None:
            start = 0
            end = self.samples_per_epoch
            seed = self.seed
        else:
            per_worker = self.samples_per_epoch // worker_info.num_workers
            start = worker_info.id * per_worker
            end = start + per_worker
            seed = (self.seed + worker_info.id) if self.seed is not None else None

        rng = np.random.RandomState(seed)
        num_classes = len(self.classes)

        for _ in range(end - start):
            class_idx = rng.randint(num_classes)
            class_name = self.classes[class_idx]
            snr_db = self._sample_snr(rng)

            # Generate signal using the single authoritative generator
            signal = generate_signal(
                class_name=class_name,
                n_samples=self.input_samples,
                sample_rate=self.sample_rate,
                snr_db=snr_db,
                rng=rng,
            )

            # Per-family augmentation: OFDM family uses gentler config
            family = CLASS_TO_FAMILY.get(class_name, "")
            is_ofdm = family == "OFDM"
            if is_ofdm and self.augmentation_config is None:
                aug_config = OFDM_AUGMENTATION_CONFIG
            else:
                aug_config = self.augmentation_config
            signal = apply_augmentation(
                signal,
                config=aug_config,
                rng=rng,
                sample_rate=self.sample_rate,
                is_ofdm=is_ofdm,
            )

            # Apply explicit channel model when configured
            if self.channel_config is not None:
                signal = apply_channel(
                    signal,
                    config=self.channel_config,
                    rng=rng,
                )

            # Final safety check -- replace non-finite with noise
            if not np.isfinite(signal).all():
                signal = (
                    rng.randn(self.input_samples) + 1j * rng.randn(self.input_samples)
                ).astype(np.complex64)
                power = np.mean(np.abs(signal) ** 2)
                if power > 0:
                    signal = signal / np.sqrt(power)

            # Normalize final power
            power = np.mean(np.abs(signal) ** 2)
            if power > 0:
                signal = signal / np.sqrt(power)

            # Convert to [2, N] real tensor (I and Q channels)
            tensor = torch.tensor(
                np.stack([signal.real, signal.imag], axis=0),
                dtype=torch.float32,
            )

            yield tensor, class_idx
