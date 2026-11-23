"""Production training loop with all gen2 fixes applied.

Fixes from gen2:
- **Early stopping** with configurable patience (gen2 had NONE in production)
- **Val SNR range** matches training SNR range (was 0--20 vs -5--25 in gen2)
- **Mixed precision** training with GradScaler
- **Gradient clipping** to prevent exploding gradients
- **Family-aware mixup** to preserve QAM/APSK constellation geometry
- **Comprehensive logging** with per-epoch metrics
- **Checkpoint provenance** (git hash, timestamp, config)
"""

from __future__ import annotations

import copy
import logging
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
from torch.amp import GradScaler, autocast
from torch.utils.data import DataLoader

from sigrift.lib.config import TrainingConfig
from sigrift.lib.taxonomy import CLASSES
from sigrift.lib.training.losses import (
    FocalLoss,
    HierarchicalFocalLoss,
    compute_class_weights,
)
from sigrift.lib.training.mixup import family_aware_mixup
from sigrift.lib.training.scheduler import build_optimizer, build_scheduler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Early stopping
# ---------------------------------------------------------------------------


class EarlyStopping:
    """Early stopping monitor.

    FIX: gen2 had NO early stopping in production training, leading to
    overfitting and wasted compute.

    Parameters
    ----------
    patience : int
        Number of epochs without improvement before stopping.
    min_delta : float
        Minimum improvement to count as an improvement.
    mode : str
        ``'max'`` for metrics where higher is better (accuracy),
        ``'min'`` for metrics where lower is better (loss).
    """

    def __init__(
        self,
        patience: int = 30,
        min_delta: float = 1e-4,
        mode: str = "max",
    ) -> None:
        self.patience = patience
        self.min_delta = min_delta
        self.mode = mode
        self._best: float | None = None
        self._counter: int = 0
        self._best_epoch: int = 0
        self._call_count: int = 0

    def __call__(self, metric: float) -> bool:
        """Check if training should stop.

        Parameters
        ----------
        metric : float
            Current epoch's monitored metric.

        Returns
        -------
        bool
            ``True`` if training should stop (patience exhausted).
        """
        self._call_count += 1

        if self._best is None:
            self._best = metric
            self._best_epoch = self._call_count
            return False

        if self.mode == "max":
            improved = metric > self._best + self.min_delta
        else:
            improved = metric < self._best - self.min_delta

        if improved:
            self._best = metric
            self._best_epoch = self._call_count
            self._counter = 0
        else:
            self._counter += 1

        return self._counter >= self.patience

    @property
    def best_score(self) -> float | None:
        """Best metric value seen so far."""
        return self._best

    @property
    def best_epoch(self) -> int:
        """Epoch number that achieved the best score."""
        return self._best_epoch

    @property
    def epochs_without_improvement(self) -> int:
        """Number of consecutive epochs without improvement."""
        return self._counter


# ---------------------------------------------------------------------------
# Provenance metadata
# ---------------------------------------------------------------------------


def _get_provenance() -> dict[str, str]:
    """Return checkpoint provenance metadata (git hash, timestamp)."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        git_hash = result.stdout.strip() if result.returncode == 0 else "unknown"
    except Exception:
        git_hash = "unknown"

    return {
        "git_hash": git_hash,
        "timestamp": datetime.now().isoformat(),
        "framework": "sigrift",
    }


# ---------------------------------------------------------------------------
# Trainer
# ---------------------------------------------------------------------------


class Trainer:
    """Production training loop with all gen2 fixes.

    Supports both flat classifiers (single logit output) and hierarchical
    models (tuple of class/mt/fam/sf logits).  Auto-detects which mode
    to use based on the model's forward output.

    Parameters
    ----------
    model : nn.Module
        Model to train.
    train_dataset : IterableDataset
        Training dataset (e.g. ``OnTheFlySignalDataset``).
    val_dataset : IterableDataset
        Validation dataset with the same SNR range as training.
    config : TrainingConfig or None
        Training hyperparameters.  ``None`` uses defaults.
    device : torch.device or None
        Device for training.  ``None`` auto-detects CUDA.
    classes : list[str] or None
        Class name list.  ``None`` defaults to ``CLASSES``.
    hierarchical : bool or None
        Whether the model uses hierarchical output.  ``None`` auto-detects
        on the first forward pass.
    """

    def __init__(
        self,
        model: nn.Module,
        train_dataset: torch.utils.data.IterableDataset,
        val_dataset: torch.utils.data.IterableDataset,
        config: TrainingConfig | None = None,
        device: torch.device | None = None,
        classes: list[str] | None = None,
        hierarchical: bool | None = None,
    ) -> None:
        self.config = config or TrainingConfig()
        self.classes = classes or CLASSES
        self.hierarchical = hierarchical

        # Device
        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = device
        logger.info("Training device: %s", self.device)

        # Model
        self.model = model.to(self.device)
        param_count = sum(p.numel() for p in self.model.parameters())
        logger.info("Model parameters: %s", f"{param_count:,}")

        # Data loaders
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=self.config.batch_size,
            num_workers=self.config.num_workers,
            pin_memory=self.config.pin_memory,
        )
        self.val_loader = DataLoader(
            val_dataset,
            batch_size=self.config.batch_size,
            num_workers=max(self.config.num_workers // 2, 1),
            pin_memory=self.config.pin_memory,
        )

        # Optimizer and scheduler
        self.optimizer = build_optimizer(self.model, self.config)
        self.scheduler = build_scheduler(self.optimizer, self.config)

        # Loss function
        class_weights = compute_class_weights(
            self.classes,
            ofdm_boost=self.config.ofdm_boost,
        ).to(self.device)

        self._hierarchical_loss = HierarchicalFocalLoss(
            gamma=self.config.gamma,
            class_weights=class_weights,
            label_smoothing=self.config.label_smoothing,
            classes=self.classes,
        ).to(self.device)

        self._flat_loss = FocalLoss(
            gamma=self.config.gamma,
            alpha=class_weights,
            label_smoothing=self.config.label_smoothing,
        ).to(self.device)

        # Mixed precision
        self.scaler = GradScaler("cuda", enabled=self.config.mixed_precision)

        # Early stopping
        self.early_stopping = EarlyStopping(
            patience=self.config.early_stopping_patience,
            min_delta=self.config.early_stopping_min_delta,
            mode="max",
        )

        # Training state
        self._best_val_acc: float = 0.0
        self._best_model_state: dict | None = None
        self._history: dict[str, list] = defaultdict(list)

    def _is_hierarchical(self, output: Any) -> bool:
        """Detect if model output is hierarchical (tuple of 4 logit tensors)."""
        return isinstance(output, (tuple, list)) and len(output) >= 4

    def train_epoch(self, epoch: int) -> dict[str, float]:
        """Run one training epoch with mixup and mixed precision.

        Parameters
        ----------
        epoch : int
            Current epoch number (for logging).

        Returns
        -------
        dict[str, float]
            Metrics: ``loss``, ``accuracy``, ``lr``.
        """
        self.model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        num_batches = 0

        for batch_x, batch_y in self.train_loader:
            batch_x = batch_x.to(self.device, non_blocking=True)
            batch_y = batch_y.to(self.device, non_blocking=True)

            # Family-aware mixup
            mixed_x, y_a, y_b, lam = family_aware_mixup(
                batch_x,
                batch_y,
                classes=self.classes,
                alpha=self.config.mixup_alpha,
                qam_apsk_alpha=self.config.mixup_qam_alpha,
            )

            self.optimizer.zero_grad(set_to_none=True)

            with autocast("cuda", enabled=self.config.mixed_precision):
                output = self.model(mixed_x)

                # Auto-detect hierarchical mode on first batch
                if self.hierarchical is None:
                    self.hierarchical = self._is_hierarchical(output)
                    logger.info(
                        "Auto-detected %s model output",
                        "hierarchical" if self.hierarchical else "flat",
                    )

                if self.hierarchical:
                    cls_logits, mt_logits, fam_logits, sf_logits = output[:4]
                    loss = self._hierarchical_loss.mixup_forward(
                        cls_logits,
                        mt_logits,
                        fam_logits,
                        sf_logits,
                        y_a,
                        y_b,
                        lam,
                    )
                    preds = cls_logits.argmax(dim=1)
                else:
                    loss = self._flat_loss.mixup_forward(output, y_a, y_b, lam)
                    preds = output.argmax(dim=1)

            # Backward with mixed precision
            self.scaler.scale(loss).backward()

            # Gradient clipping
            self.scaler.unscale_(self.optimizer)
            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)

            self.scaler.step(self.optimizer)
            self.scaler.update()

            total_loss += loss.item()
            # Accuracy vs original (non-mixed) labels for monitoring
            correct += (preds == batch_y).sum().item()
            total += batch_y.size(0)
            num_batches += 1

        self.scheduler.step(epoch)

        avg_loss = total_loss / max(num_batches, 1)
        accuracy = correct / max(total, 1)
        current_lr = self.optimizer.param_groups[0]["lr"]

        return {
            "loss": avg_loss,
            "accuracy": accuracy,
            "lr": current_lr,
        }

    @torch.no_grad()
    def validate(self) -> dict[str, float]:
        """Run validation with same SNR range as training.

        Returns
        -------
        dict[str, float]
            Metrics: ``loss``, ``accuracy``, ``per_class_correct``,
            ``per_class_total``.
        """
        self.model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        num_batches = 0
        per_class_correct = defaultdict(int)
        per_class_total = defaultdict(int)

        for batch_x, batch_y in self.val_loader:
            batch_x = batch_x.to(self.device, non_blocking=True)
            batch_y = batch_y.to(self.device, non_blocking=True)

            with autocast("cuda", enabled=self.config.mixed_precision):
                output = self.model(batch_x)

                if self.hierarchical:
                    cls_logits, mt_logits, fam_logits, sf_logits = output[:4]
                    loss = self._hierarchical_loss.forward(
                        cls_logits,
                        mt_logits,
                        fam_logits,
                        sf_logits,
                        batch_y,
                    )
                    preds = cls_logits.argmax(dim=1)
                else:
                    loss = self._flat_loss.forward(output, batch_y)
                    preds = output.argmax(dim=1)

            total_loss += loss.item()
            correct += (preds == batch_y).sum().item()
            total += batch_y.size(0)
            num_batches += 1

            # Per-class tracking
            for pred, target in zip(preds.cpu().tolist(), batch_y.cpu().tolist()):
                per_class_total[target] += 1
                if pred == target:
                    per_class_correct[target] += 1

        avg_loss = total_loss / max(num_batches, 1)
        accuracy = correct / max(total, 1)

        # Compute per-class accuracy
        per_class_acc = {}
        for idx in range(len(self.classes)):
            t = per_class_total.get(idx, 0)
            c = per_class_correct.get(idx, 0)
            per_class_acc[self.classes[idx]] = c / t if t > 0 else 0.0

        return {
            "loss": avg_loss,
            "accuracy": accuracy,
            "per_class_accuracy": per_class_acc,
        }

    def fit(
        self,
        num_epochs: int = 200,
        checkpoint_dir: str | Path | None = None,
        checkpoint_every: int = 5,
    ) -> dict[str, list]:
        """Full training loop with early stopping.

        Parameters
        ----------
        num_epochs : int
            Maximum number of training epochs.
        checkpoint_dir : str or Path or None
            If set, save a checkpoint every ``checkpoint_every`` epochs.
        checkpoint_every : int
            Save checkpoint every N epochs (default 5).

        Returns
        -------
        dict[str, list]
            Training history with keys: ``train_loss``, ``train_acc``,
            ``val_loss``, ``val_acc``, ``lr``.
        """
        logger.info(
            "Starting training: %d epochs, batch_size=%d, lr=%.1e, device=%s",
            num_epochs,
            self.config.batch_size,
            self.config.learning_rate,
            self.device,
        )

        start_time = time.time()

        for epoch in range(1, num_epochs + 1):
            epoch_start = time.time()

            # Train
            train_metrics = self.train_epoch(epoch)

            # Validate
            val_metrics = self.validate()

            epoch_time = time.time() - epoch_start

            # Record history
            self._history["train_loss"].append(train_metrics["loss"])
            self._history["train_acc"].append(train_metrics["accuracy"])
            self._history["val_loss"].append(val_metrics["loss"])
            self._history["val_acc"].append(val_metrics["accuracy"])
            self._history["lr"].append(train_metrics["lr"])

            # Log progress
            logger.info(
                "Epoch %3d/%d | train_loss=%.4f train_acc=%.4f | "
                "val_loss=%.4f val_acc=%.4f | lr=%.2e | %.1fs",
                epoch,
                num_epochs,
                train_metrics["loss"],
                train_metrics["accuracy"],
                val_metrics["loss"],
                val_metrics["accuracy"],
                train_metrics["lr"],
                epoch_time,
            )

            # Track best model
            if val_metrics["accuracy"] > self._best_val_acc:
                self._best_val_acc = val_metrics["accuracy"]
                self._best_model_state = copy.deepcopy(self.model.state_dict())
                logger.info(
                    "  New best val_acc=%.4f at epoch %d",
                    self._best_val_acc,
                    epoch,
                )

            # Periodic checkpoint saving
            if checkpoint_dir is not None and epoch % checkpoint_every == 0:
                ckpt_path = Path(checkpoint_dir) / "sigrift_best.pth"
                self.save_checkpoint(
                    path=ckpt_path,
                    epoch=epoch,
                    metrics={"best_val_acc": self._best_val_acc},
                )

            # Early stopping
            if self.early_stopping(val_metrics["accuracy"]):
                logger.info(
                    "Early stopping triggered at epoch %d "
                    "(best=%.4f at epoch %d, %d epochs without improvement)",
                    epoch,
                    self.early_stopping.best_score,
                    self.early_stopping.best_epoch,
                    self.early_stopping.epochs_without_improvement,
                )
                break

        total_time = time.time() - start_time
        logger.info(
            "Training complete: %.1f minutes, best val_acc=%.4f",
            total_time / 60,
            self._best_val_acc,
        )

        # Restore best model
        if self._best_model_state is not None:
            self.model.load_state_dict(self._best_model_state)
            logger.info("Restored best model weights")

        return dict(self._history)

    def save_checkpoint(
        self,
        path: str | Path,
        epoch: int,
        metrics: dict[str, float],
    ) -> None:
        """Save a training checkpoint.

        Parameters
        ----------
        path : str or Path
            Output file path.
        epoch : int
            Current epoch number.
        metrics : dict[str, float]
            Metrics to include in the checkpoint.
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "epoch": epoch,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "scheduler_state_dict": self.scheduler.state_dict(),
            "scaler_state_dict": self.scaler.state_dict(),
            "metrics": metrics,
            "best_val_acc": self._best_val_acc,
            "classes": self.classes,
            "config": {
                "epochs": self.config.epochs,
                "batch_size": self.config.batch_size,
                "learning_rate": self.config.learning_rate,
                "weight_decay": self.config.weight_decay,
                "gamma": self.config.gamma,
                "label_smoothing": self.config.label_smoothing,
                "ofdm_boost": self.config.ofdm_boost,
                "snr_range_db": list(self.config.snr_range_db),
                "val_snr_range_db": list(self.config.val_snr_range_db),
                "input_samples": self.config.input_samples,
                "mixup_alpha": self.config.mixup_alpha,
                "mixup_qam_alpha": self.config.mixup_qam_alpha,
            },
            "provenance": _get_provenance(),
        }

        torch.save(checkpoint, path)
        logger.info("Saved checkpoint to %s", path)

    def load_checkpoint(self, path: str | Path) -> dict[str, Any]:
        """Load a training checkpoint and restore state.

        Parameters
        ----------
        path : str or Path
            Checkpoint file path.

        Returns
        -------
        dict
            Loaded checkpoint dict (contains epoch, metrics, etc.).
        """
        path = Path(path)
        checkpoint = torch.load(path, map_location=self.device, weights_only=True)

        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self.scheduler.load_state_dict(checkpoint["scheduler_state_dict"])

        if "scaler_state_dict" in checkpoint:
            self.scaler.load_state_dict(checkpoint["scaler_state_dict"])

        self._best_val_acc = checkpoint.get("best_val_acc", 0.0)

        logger.info(
            "Loaded checkpoint from %s (epoch %d, best_val_acc=%.4f)",
            path,
            checkpoint.get("epoch", -1),
            self._best_val_acc,
        )

        return checkpoint
