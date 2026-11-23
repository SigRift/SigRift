"""Family-aware mixup for RF signal classification.

QAM and APSK constellations are more sensitive to mixup since the
constellation geometry matters more for classification.  Lower alpha
preserves geometry better.  This module provides a family-aware mixup
implementation that automatically reduces alpha for QAM/APSK-dominated
batches.
"""

from __future__ import annotations

import numpy as np
import torch

from sigrift.lib.taxonomy import CLASSES, CLASS_TO_FAMILY


def family_aware_mixup(
    x: torch.Tensor,
    y: torch.Tensor,
    classes: list[str] | None = None,
    alpha: float = 0.4,
    qam_apsk_alpha: float = 0.2,
    rng: np.random.RandomState | None = None,
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, float]:
    """Family-aware mixup that uses lower alpha for QAM/APSK families.

    QAM and APSK constellations are more sensitive to mixup since the
    constellation geometry matters more.  Lower alpha preserves geometry
    better.

    Parameters
    ----------
    x : torch.Tensor
        Input batch ``[B, 2, N]`` (I/Q channels).
    y : torch.Tensor
        Target labels ``[B]`` (class indices).
    classes : list[str] or None
        Class name list for family lookup.  Defaults to ``CLASSES``.
    alpha : float
        Default mixup alpha for non-QAM/APSK families.
    qam_apsk_alpha : float
        Reduced alpha for batches dominated by QAM/APSK.
    rng : np.random.RandomState or None
        Random state.  ``None`` creates a new unseeded state.

    Returns
    -------
    mixed_x : torch.Tensor
        Mixed input batch ``[B, 2, N]``.
    y_a : torch.Tensor
        Original targets ``[B]``.
    y_b : torch.Tensor
        Permuted targets ``[B]``.
    lam : float
        Mixup interpolation coefficient.
    """
    if rng is None:
        rng = np.random.RandomState()

    classes = classes or CLASSES

    # Check if batch is predominantly QAM/APSK -> use lower alpha
    effective_alpha = alpha
    if alpha > 0 and len(classes) > 0:
        qam_apsk_count = 0
        for idx in y.cpu().tolist():
            if idx < len(classes):
                family = CLASS_TO_FAMILY.get(classes[idx], "")
                if family in ("QAM", "APSK"):
                    qam_apsk_count += 1
        if qam_apsk_count > len(y) * 0.5:
            effective_alpha = qam_apsk_alpha

    if effective_alpha > 0:
        lam = float(rng.beta(effective_alpha, effective_alpha))
    else:
        lam = 1.0

    batch_size = x.size(0)
    # Use torch for the permutation to keep it on the same device
    index = torch.randperm(batch_size, device=x.device)

    mixed_x = lam * x + (1 - lam) * x[index]
    y_a = y
    y_b = y[index]

    return mixed_x, y_a, y_b, lam
