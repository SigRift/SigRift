#!/usr/bin/env python3
"""Train the 16-class open-default community classifier.

Wraps ``sigrift.lib.training.trainer.Trainer`` with DDP across both
local GPUs and the open-default taxonomy collapse from
``sigrift.lib.taxonomy_open``.

Launch:
    torchrun --standalone --nproc_per_node=2 \\
        training/train_open_default.py \\
            --epochs 200 --batch-size 256 \\
            --train-samples 100000 --val-samples 20000

Single-GPU debug launch:
    python training/train_open_default.py --single-gpu --epochs 5

Outputs go to ``training/{logs,models}/<run-name>_<timestamp>.*``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch
import torch.distributed as dist
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data import IterableDataset

# Make the repo importable without installing.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from sigrift.lib.config import TrainingConfig  # noqa: E402
from sigrift.lib.models.edge import EdgeRFClassifier  # noqa: E402
from sigrift.lib.taxonomy_open import (  # noqa: E402
    OPEN_DEFAULT_CLASSES,
    OPEN_DEFAULT_TO_IDX,
    OPEN_DEFAULT_TO_SOURCES,
    SOURCE_TO_OPEN_DEFAULT,
    register_open_default_classes,
)

# Patch the global taxonomy with our family-collapsed class names so
# that Trainer's hierarchical-loss helper can resolve every class →
# family lookup even when we run in flat mode.
register_open_default_classes()
from sigrift.lib.training.dataset import OnTheFlySignalDataset  # noqa: E402
from sigrift.lib.training.trainer import Trainer  # noqa: E402

logger = logging.getLogger("sigrift.train.open_default")

DEFAULT_OUTPUT_DIR = _REPO_ROOT / "training" / "models"
DEFAULT_LOG_DIR = _REPO_ROOT / "training" / "logs"
DEFAULT_TMP_DIR = _REPO_ROOT / "training" / "tmp"


# ---------------------------------------------------------------------------
# Collapse-aware dataset wrapper
# ---------------------------------------------------------------------------


class CollapsedDataset(IterableDataset):
    """Wraps OnTheFlySignalDataset to emit collapsed open-default labels.

    The underlying generator renders signals across the full 76-class
    catalogue; we sample only sources that have a collapse-map entry
    and rewrite their integer label to the open-default index.
    """

    def __init__(
        self,
        samples_per_epoch: int,
        input_samples: int,
        snr_range: tuple[float, float],
    ) -> None:
        # Source classes are the union of every value in OPEN_DEFAULT_TO_SOURCES.
        source_classes = sorted(SOURCE_TO_OPEN_DEFAULT.keys())
        self._source_classes = source_classes
        self._source_to_open_idx = {
            src: OPEN_DEFAULT_TO_IDX[SOURCE_TO_OPEN_DEFAULT[src]]
            for src in source_classes
        }
        self._inner = OnTheFlySignalDataset(
            classes=source_classes,
            samples_per_epoch=samples_per_epoch,
            input_samples=input_samples,
            snr_range=snr_range,
        )

    def __iter__(self):
        for tensor, src_idx in self._inner:
            src_name = self._source_classes[int(src_idx)]
            yield tensor, self._source_to_open_idx[src_name]


# ---------------------------------------------------------------------------
# DDP helpers
# ---------------------------------------------------------------------------


def _setup_ddp() -> tuple[int, int, int]:
    """Initialise the default process group from torchrun env vars.

    Returns ``(rank, local_rank, world_size)``. Falls back to single-process
    mode (rank 0, world 1) if torchrun env vars are absent.
    """
    if "RANK" not in os.environ:
        return 0, 0, 1
    rank = int(os.environ["RANK"])
    local_rank = int(os.environ.get("LOCAL_RANK", rank))
    world_size = int(os.environ["WORLD_SIZE"])
    dist.init_process_group(backend="nccl", init_method="env://")
    torch.cuda.set_device(local_rank)
    return rank, local_rank, world_size


def _is_rank0(rank: int) -> bool:
    return rank == 0


def _cleanup_ddp() -> None:
    if dist.is_available() and dist.is_initialized():
        dist.destroy_process_group()


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def _git_sha() -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT, stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--epochs", type=int, default=200)
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--train-samples", type=int, default=100_000)
    p.add_argument("--val-samples", type=int, default=20_000)
    p.add_argument(
        "--input-samples",
        type=int,
        default=8192,
        help="IQ samples per signal (default: 8192 — 4ms @ 2.048 Msps)",
    )
    p.add_argument("--num-workers", type=int, default=4)
    p.add_argument("--patience", type=int, default=30)
    p.add_argument(
        "--snr-min", type=float, default=-5.0, help="Training SNR range lower bound (dB)"
    )
    p.add_argument(
        "--snr-max", type=float, default=25.0, help="Training SNR range upper bound (dB)"
    )
    p.add_argument(
        "--single-gpu",
        action="store_true",
        help="Skip DDP init even if torchrun env vars are present (debug)",
    )
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    p.add_argument(
        "--run-name",
        default="open_default",
        help="Prefix for output files (default: open_default)",
    )
    p.add_argument(
        "--resume",
        type=Path,
        default=None,
        help="Resume from a previous .pth checkpoint",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()

    # ── DDP init ─────────────────────────────────────────────────────
    if args.single_gpu:
        rank, local_rank, world_size = 0, 0, 1
    else:
        rank, local_rank, world_size = _setup_ddp()

    # ── Logging — rank 0 to file + stderr; others stderr only ────────
    args.log_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    DEFAULT_TMP_DIR.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_name = f"{args.run_name}_{ts}"
    log_path = args.log_dir / f"{run_name}.log" if _is_rank0(rank) else None

    fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_path is not None:
        handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        datefmt="%Y-%m-%dT%H:%M:%S%z",
        handlers=handlers,
    )

    if _is_rank0(rank):
        logger.info("=" * 70)
        logger.info("SigRift open-default training run")
        logger.info("  git SHA          : %s", _git_sha())
        logger.info("  run name         : %s", run_name)
        logger.info("  world size       : %d", world_size)
        logger.info("  classes (%d)     : %s", len(OPEN_DEFAULT_CLASSES), OPEN_DEFAULT_CLASSES)
        logger.info(
            "  source pool      : %d classes from the 76-class taxonomy",
            len(SOURCE_TO_OPEN_DEFAULT),
        )
        logger.info("  output dir       : %s", args.output_dir)
        logger.info("  log file         : %s", log_path)
        logger.info("  epochs / patience: %d / %d", args.epochs, args.patience)
        logger.info("  batch size       : %d (global %d)", args.batch_size, args.batch_size * world_size)
        logger.info("  samples train/val: %d / %d", args.train_samples, args.val_samples)
        logger.info("  SNR range (dB)   : [%g, %g]", args.snr_min, args.snr_max)
        logger.info("=" * 70)

    # ── Reproducibility seed (per-rank offset so workers diverge) ────
    base_seed = 1337
    torch.manual_seed(base_seed + rank)
    np.random.seed(base_seed + rank)

    # ── Datasets ─────────────────────────────────────────────────────
    # Each rank generates samples_per_epoch / world_size on the fly.
    per_rank_train = max(args.train_samples // world_size, 1)
    per_rank_val = max(args.val_samples // world_size, 1)
    train_ds = CollapsedDataset(
        samples_per_epoch=per_rank_train,
        input_samples=args.input_samples,
        snr_range=(args.snr_min, args.snr_max),
    )
    val_ds = CollapsedDataset(
        samples_per_epoch=per_rank_val,
        input_samples=args.input_samples,
        snr_range=(args.snr_min, args.snr_max),
    )

    # ── Model ────────────────────────────────────────────────────────
    device = torch.device(f"cuda:{local_rank}" if torch.cuda.is_available() else "cpu")
    model = EdgeRFClassifier(num_classes=len(OPEN_DEFAULT_CLASSES))

    # Load checkpoint up front so model weights are populated before
    # we wrap in DDP (DDP buffers/gradients tie to the model on
    # init). Optimizer / scheduler / scaler are restored further down
    # once Trainer has built them.
    resume_ckpt: dict | None = None
    if args.resume is not None:
        # weights_only=True: a checkpoint is data, not code. Without it an
        # older torch (< 2.6, where the default was False) unpickles
        # arbitrary objects, so a tampered .pth would run code on load.
        # Both checkpoint shapes this script resumes from (Trainer's
        # periodic save and the final save below) hold only tensors,
        # containers and primitives, which the safe loader accepts.
        resume_ckpt = torch.load(args.resume, map_location="cpu", weights_only=True)
        model_state = resume_ckpt.get("model_state_dict", resume_ckpt)
        model.load_state_dict(model_state)
        if _is_rank0(rank):
            logger.info(
                "Resumed model weights from %s (saved at epoch %s, best_val_acc=%s)",
                args.resume,
                resume_ckpt.get("epoch", "?"),
                resume_ckpt.get("best_val_acc", "?"),
            )

    model.to(device)
    if world_size > 1:
        model = DDP(model, device_ids=[local_rank], output_device=local_rank)

    # ── Training config ──────────────────────────────────────────────
    config = TrainingConfig(
        epochs=args.epochs,
        batch_size=args.batch_size,
        learning_rate=args.lr,
        early_stopping_patience=args.patience,
        snr_range_db=(args.snr_min, args.snr_max),
        val_snr_range_db=(args.snr_min, args.snr_max),
        input_samples=args.input_samples,
        num_workers=args.num_workers,
    )

    # ── Train ────────────────────────────────────────────────────────
    trainer = Trainer(
        model=model,
        train_dataset=train_ds,
        val_dataset=val_ds,
        config=config,
        device=device,
        classes=OPEN_DEFAULT_CLASSES,
        hierarchical=False,
    )

    # Restore optimizer / scheduler / scaler / best_val_acc state if
    # we're resuming. After this the LR schedule, AdamW momentum, and
    # mixed-precision scale all continue from where the saved run
    # left off. The epoch loop still restarts at 1 — to compensate we
    # subtract the elapsed-epochs count from num_epochs so total
    # epochs trained (across both runs) lands near the original
    # config.epochs cap. Doesn't affect early-stopping (patience
    # counter resets) — that's a wart we accept for now.
    resume_epoch = 0
    if resume_ckpt is not None:
        if "optimizer_state_dict" in resume_ckpt:
            trainer.optimizer.load_state_dict(resume_ckpt["optimizer_state_dict"])
        if "scheduler_state_dict" in resume_ckpt:
            trainer.scheduler.load_state_dict(resume_ckpt["scheduler_state_dict"])
        if "scaler_state_dict" in resume_ckpt and hasattr(trainer, "scaler"):
            trainer.scaler.load_state_dict(resume_ckpt["scaler_state_dict"])
        if "best_val_acc" in resume_ckpt:
            trainer._best_val_acc = resume_ckpt["best_val_acc"]
        resume_epoch = int(resume_ckpt.get("epoch", 0))
        if _is_rank0(rank):
            logger.info(
                "Restored optimizer / scheduler / scaler state (continuing from epoch %d)",
                resume_epoch,
            )

    remaining_epochs = max(args.epochs - resume_epoch, 1)

    # Pass checkpoint_dir so Trainer writes a periodic "last good"
    # checkpoint every 5 epochs into training/models/sigrift_best.pth.
    # If this run is killed mid-flight, --resume <that path> picks
    # up the work.
    t0 = time.time()
    history = trainer.fit(
        num_epochs=remaining_epochs,
        checkpoint_dir=args.output_dir if _is_rank0(rank) else None,
        checkpoint_every=5,
    )
    elapsed = time.time() - t0

    if _is_rank0(rank):
        logger.info("Training complete in %.1f s (%.1f h)", elapsed, elapsed / 3600.0)

        # Save final checkpoint
        ckpt_path = args.output_dir / f"{run_name}.pth"
        state_dict = (
            model.module.state_dict() if isinstance(model, DDP) else model.state_dict()
        )
        torch.save(
            {
                "model_state_dict": state_dict,
                "classes": OPEN_DEFAULT_CLASSES,
                "input_samples": args.input_samples,
                "git_sha": _git_sha(),
                "config": config.__dict__,
                "history": history,
            },
            ckpt_path,
        )
        logger.info("Checkpoint → %s", ckpt_path)

        # Export ONNX
        onnx_path = args.output_dir / f"{run_name}.onnx"
        _export_onnx(
            model.module if isinstance(model, DDP) else model,
            onnx_path,
            input_samples=args.input_samples,
        )
        logger.info("ONNX export → %s", onnx_path)

        # Metadata
        meta_path = args.output_dir / f"{run_name}_metadata.json"
        meta_path.write_text(
            json.dumps(
                {
                    "run_name": run_name,
                    "timestamp_utc": ts,
                    "license": "MIT",
                    "git_sha": _git_sha(),
                    "classes": OPEN_DEFAULT_CLASSES,
                    "input_samples": args.input_samples,
                    "channels": 2,  # I/Q
                    "model_arch": "EdgeRFClassifier",
                    "world_size": world_size,
                    "epochs_completed": len(history.get("train_loss", [])),
                    "training_seconds": elapsed,
                    "config": config.__dict__,
                    "source_classes": sorted(SOURCE_TO_OPEN_DEFAULT.keys()),
                    "collapse_map": SOURCE_TO_OPEN_DEFAULT,
                },
                indent=2,
                sort_keys=True,
            )
        )
        logger.info("Metadata → %s", meta_path)

    _cleanup_ddp()
    return 0


def _export_onnx(model: torch.nn.Module, path: Path, *, input_samples: int) -> None:
    """Export the trained EdgeRFClassifier to ONNX for edge inference."""
    model.eval()
    dummy = torch.zeros(1, 2, input_samples, device=next(model.parameters()).device)
    torch.onnx.export(
        model,
        dummy,
        str(path),
        input_names=["iq"],
        output_names=["logits"],
        dynamic_axes={"iq": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=17,
        dynamo=False,
        do_constant_folding=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
