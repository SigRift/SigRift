#!/usr/bin/env python3
"""Pre-generate training data to memory-mapped file for fast GPU training.

Generates IQ signals for all training classes and saves to a numpy memmap
file on /dev/shm (RAM disk) for near-zero I/O latency during training.

Usage:
    # Generate 200K training + 30K validation samples at 16384 length
    python3 sigrift/tools/pregen_training_data.py \
        --train-samples 200000 --val-samples 30000 \
        --input-samples 16384 --output-dir /dev/shm/mlrf_train

    # Then train from pre-generated data:
    python3 sigrift/train.py --pregen /dev/shm/mlrf_train --model full ...
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))

from sigrift.lib.dsp.channel_models import RTL_SDR_REALISTIC, apply_channel  # noqa: E402
from sigrift.lib.taxonomy import CLASSES  # noqa: E402
from sigrift.lib.training.augmentation import (  # noqa: E402
    AugmentationConfig,
    apply_augmentation,
)
from sigrift.lib.training.signal_factory import generate_signal  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger("pregen")

# Same as train.py
_PROTOCOL_ONLY_CLASSES = frozenset(
    {
        "lora-meshtastic",
        "lora-meshcore",
        "lora-lorawan",
        "analog-video-24",
        "wireless-hart",
        "isa100",
        "elrs",
    }
)

TRAIN_CLASSES = [c for c in CLASSES if c not in _PROTOCOL_ONLY_CLASSES]


def generate_dataset(
    output_dir: Path,
    n_samples: int,
    input_samples: int,
    snr_range: tuple[float, float],
    channel_realistic: bool,
    seed: int,
    prefix: str,
    num_workers: int = 8,
):
    """Generate dataset and save as memmap + labels."""
    num_classes = len(TRAIN_CLASSES)

    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Memory-mapped arrays
    iq_path = output_dir / f"{prefix}_iq.dat"
    labels_path = output_dir / f"{prefix}_labels.dat"

    logger.info(
        "Generating %d samples (%d classes, %d IQ samples each)",
        n_samples,
        num_classes,
        input_samples,
    )
    logger.info("Output: %s", output_dir)

    # Create memmap files
    iq_mm = np.memmap(
        str(iq_path), dtype=np.float32, mode="w+", shape=(n_samples, 2, input_samples)
    )
    labels_mm = np.memmap(
        str(labels_path), dtype=np.int32, mode="w+", shape=(n_samples,)
    )

    channel_config = RTL_SDR_REALISTIC if channel_realistic else None
    aug_default = AugmentationConfig(channel_prob=0.0)
    aug_ofdm = AugmentationConfig(channel_prob=0.0)  # Simplified

    rng = np.random.RandomState(seed)
    t0 = time.time()

    for i in range(n_samples):
        class_idx = rng.randint(num_classes)
        class_name = TRAIN_CLASSES[class_idx]

        # SNR sampling: 30% low, 40% mid, 30% high
        roll = rng.rand()
        if roll < 0.3:
            snr_db = rng.uniform(snr_range[0], min(0.0, snr_range[1]))
        elif roll < 0.7:
            snr_db = rng.uniform(max(0.0, snr_range[0]), min(10.0, snr_range[1]))
        else:
            snr_db = rng.uniform(max(10.0, snr_range[0]), snr_range[1])

        # Generate signal
        signal = generate_signal(
            class_name=class_name,
            n_samples=input_samples,
            sample_rate=2_048_000.0,
            snr_db=snr_db,
            rng=rng,
        )

        # Augmentation
        is_ofdm = "ofdm" in class_name
        aug = aug_ofdm if is_ofdm else aug_default
        signal = apply_augmentation(
            signal, config=aug, rng=rng, sample_rate=2_048_000.0, is_ofdm=is_ofdm
        )

        # Channel model
        if channel_config:
            signal = apply_channel(signal, config=channel_config, rng=rng)

        # Safety
        if not np.isfinite(signal).all() or np.max(np.abs(signal)) > 1e6:
            signal = (rng.randn(input_samples) + 1j * rng.randn(input_samples)).astype(
                np.complex64
            ) * 0.01

        # Normalize
        power = np.mean(np.abs(signal) ** 2)
        if power > 1e-20:
            signal = signal / np.sqrt(power)
        else:
            signal = (rng.randn(input_samples) + 1j * rng.randn(input_samples)).astype(
                np.complex64
            ) * 0.01

        signal = np.clip(signal.real, -10, 10) + 1j * np.clip(signal.imag, -10, 10)

        # Store
        iq_mm[i, 0, :] = signal.real
        iq_mm[i, 1, :] = signal.imag
        labels_mm[i] = class_idx

        if (i + 1) % 10000 == 0:
            elapsed = time.time() - t0
            rate = (i + 1) / elapsed
            eta = (n_samples - i - 1) / rate
            logger.info("  %d/%d (%.0f/s, ETA %.0fs)", i + 1, n_samples, rate, eta)

    # Flush
    iq_mm.flush()
    labels_mm.flush()

    elapsed = time.time() - t0
    size_gb = os.path.getsize(str(iq_path)) / 1e9
    logger.info(
        "Done: %d samples in %.1f min (%.1f GB)", n_samples, elapsed / 60, size_gb
    )

    return iq_path, labels_path


def main():
    parser = argparse.ArgumentParser(description="Pre-generate training data")
    parser.add_argument("--train-samples", type=int, default=200_000)
    parser.add_argument("--val-samples", type=int, default=30_000)
    parser.add_argument("--input-samples", type=int, default=16384)
    parser.add_argument("--output-dir", type=str, default="/dev/shm/mlrf_train")
    parser.add_argument("--snr-min", type=float, default=-5.0)
    parser.add_argument("--snr-max", type=float, default=25.0)
    parser.add_argument("--realistic", action="store_true", default=True)
    parser.add_argument(
        "--num-workers",
        type=int,
        default=1,
        help="Single-process for now (numpy RNG not fork-safe)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    snr_range = (args.snr_min, args.snr_max)

    # Save metadata
    output_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "classes": TRAIN_CLASSES,
        "num_classes": len(TRAIN_CLASSES),
        "input_samples": args.input_samples,
        "snr_range": list(snr_range),
        "train_samples": args.train_samples,
        "val_samples": args.val_samples,
        "realistic_channel": args.realistic,
        "sample_rate": 2_048_000.0,
    }
    with open(output_dir / "meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    logger.info("=== Training data ===")
    generate_dataset(
        output_dir,
        args.train_samples,
        args.input_samples,
        snr_range,
        args.realistic,
        seed=42,
        prefix="train",
    )

    logger.info("=== Validation data ===")
    generate_dataset(
        output_dir,
        args.val_samples,
        args.input_samples,
        snr_range,
        args.realistic,
        seed=123,
        prefix="val",
    )

    logger.info("Pre-generation complete: %s", output_dir)
    logger.info("Train with: python3 sigrift/train.py --pregen %s", output_dir)


if __name__ == "__main__":
    main()
