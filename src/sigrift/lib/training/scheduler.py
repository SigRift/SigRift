"""Learning rate scheduling and optimizer utilities.

Provides factory functions to build the optimizer and scheduler from a
``sigrift.lib.config.TrainingConfig`` dataclass, ensuring consistent hyperparameter
sourcing across training scripts.
"""

from __future__ import annotations

import logging

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingWarmRestarts

from sigrift.lib.config import TrainingConfig

logger = logging.getLogger(__name__)


def build_optimizer(
    model: nn.Module,
    config: TrainingConfig,
) -> AdamW:
    """Build AdamW optimizer from config.

    Parameters
    ----------
    model : nn.Module
        Model whose parameters will be optimised.
    config : TrainingConfig
        Training configuration containing ``learning_rate`` and ``weight_decay``.

    Returns
    -------
    AdamW
        Configured AdamW optimizer.
    """
    optimizer = AdamW(
        model.parameters(),
        lr=config.learning_rate,
        weight_decay=config.weight_decay,
    )
    logger.info(
        "Built AdamW optimizer: lr=%.1e, weight_decay=%.1e",
        config.learning_rate,
        config.weight_decay,
    )
    return optimizer


def build_scheduler(
    optimizer: torch.optim.Optimizer,
    config: TrainingConfig,
) -> CosineAnnealingWarmRestarts:
    """Build CosineAnnealingWarmRestarts scheduler from config.

    The cosine annealing schedule with warm restarts periodically resets
    the learning rate, which helps escape local minima and improve final
    accuracy.

    Parameters
    ----------
    optimizer : torch.optim.Optimizer
        Optimizer to schedule.
    config : TrainingConfig
        Training configuration containing ``scheduler_t0`` and
        ``scheduler_t_mult``.

    Returns
    -------
    CosineAnnealingWarmRestarts
        Configured scheduler.
    """
    scheduler = CosineAnnealingWarmRestarts(
        optimizer,
        T_0=config.scheduler_t0,
        T_mult=config.scheduler_t_mult,
    )
    logger.info(
        "Built CosineAnnealingWarmRestarts: T_0=%d, T_mult=%d",
        config.scheduler_t0,
        config.scheduler_t_mult,
    )
    return scheduler
