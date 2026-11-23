"""Training pipeline for RF signal classification.

- Consolidated signal generation (single authoritative implementation)
- On-the-fly dataset with correct SNR ranges
- Early stopping (was missing in gen2)
- Focal loss, hierarchical loss, knowledge distillation
- Family-aware mixup
"""

from sigrift.lib.training.signal_factory import generate_signal, list_classes
from sigrift.lib.training.augmentation import AugmentationConfig, apply_augmentation
from sigrift.lib.training.dataset import OnTheFlySignalDataset
from sigrift.lib.training.losses import (
    FocalLoss,
    DistillationLoss,
    HierarchicalFocalLoss,
    HierarchicalDistillationLoss,
    calibrate_temperature,
    compute_class_weights,
)
from sigrift.lib.training.mixup import family_aware_mixup
from sigrift.lib.training.trainer import EarlyStopping, Trainer
from sigrift.lib.training.scheduler import build_optimizer, build_scheduler

__all__ = [
    # Signal factory
    "generate_signal",
    "list_classes",
    # Augmentation
    "AugmentationConfig",
    "apply_augmentation",
    # Dataset
    "OnTheFlySignalDataset",
    # Losses
    "FocalLoss",
    "DistillationLoss",
    "HierarchicalFocalLoss",
    "HierarchicalDistillationLoss",
    "calibrate_temperature",
    "compute_class_weights",
    # Mixup
    "family_aware_mixup",
    # Trainer
    "EarlyStopping",
    "Trainer",
    # Scheduler / optimizer
    "build_optimizer",
    "build_scheduler",
]
