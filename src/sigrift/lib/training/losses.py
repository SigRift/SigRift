"""Consolidated loss functions for RF signal classification training.

All loss functions in one place:

- ``compute_class_weights``: per-class weight tensor with OFDM boost.
- ``FocalLoss``: focal loss with optional per-class weights and label smoothing.
- ``DistillationLoss``: knowledge distillation (alpha * T^2 * KL + (1-alpha) * CE).
- ``HierarchicalFocalLoss``: combined focal loss across all 4 hierarchy levels
  + KL consistency between class-level and modulation-type.
- ``HierarchicalDistillationLoss``: knowledge distillation at all 4 hierarchy levels.
- ``calibrate_temperature``: post-hoc temperature calibration via LBFGS.

Uses taxonomy mappings from ``sigrift.lib.taxonomy`` for building class-to-family/mt/sf
tensors.
"""

from __future__ import annotations

import logging

import torch
import torch.nn as nn
import torch.nn.functional as F

from sigrift.lib.taxonomy import (
    CLASSES,
    build_class_family_tensor,
    build_class_mt_tensor,
    build_class_sf_tensor,
    build_family_class_mask,
    build_mt_class_mask,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Class weights
# ---------------------------------------------------------------------------


def compute_class_weights(
    classes: list[str],
    ofdm_boost: float = 1.5,
) -> torch.Tensor:
    """Return per-class weight tensor with OFDM boost multiplier.

    OFDM variants are harder to distinguish from each other (the main
    difference is subcarrier count), so they get a higher loss weight.

    Parameters
    ----------
    classes : list[str]
        Class name list.
    ofdm_boost : float
        Multiplier applied to OFDM class weights.

    Returns
    -------
    torch.Tensor
        Float tensor of shape ``[len(classes)]``.
    """
    weights = torch.ones(len(classes))
    for i, cls in enumerate(classes):
        if "ofdm" in cls.lower():
            weights[i] = ofdm_boost
    return weights


# ---------------------------------------------------------------------------
# Focal Loss
# ---------------------------------------------------------------------------


class FocalLoss(nn.Module):
    """Focal loss with optional per-class weights and label smoothing.

    ``(1 - p_t)^gamma * CE(inputs, targets)``

    Parameters
    ----------
    gamma : float
        Focusing parameter.  0 = standard cross-entropy.
    alpha : torch.Tensor or None
        Per-class weights (length = num_classes).
    label_smoothing : float
        Label smoothing for the underlying CE term.
    """

    def __init__(
        self,
        gamma: float = 1.5,
        alpha: torch.Tensor | None = None,
        label_smoothing: float = 0.1,
    ) -> None:
        super().__init__()
        self.gamma = gamma
        self.label_smoothing = label_smoothing
        if alpha is not None:
            self.register_buffer("alpha", alpha)
        else:
            self.alpha = None

    def forward(
        self,
        inputs: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """Standard forward: inputs [B, C], targets [B] (class indices)."""
        ce_loss = F.cross_entropy(
            inputs,
            targets,
            weight=self.alpha,
            reduction="none",
            label_smoothing=self.label_smoothing,
        )
        # p_t = model confidence on the true class (without smoothing)
        pt = torch.exp(-F.cross_entropy(inputs, targets, reduction="none"))
        focal = ((1 - pt) ** self.gamma) * ce_loss
        return focal.mean()

    def mixup_forward(
        self,
        inputs: torch.Tensor,
        y_a: torch.Tensor,
        y_b: torch.Tensor,
        lam: float,
    ) -> torch.Tensor:
        """Mixup-compatible forward: weighted sum of focal losses for both targets."""
        return lam * self.forward(inputs, y_a) + (1 - lam) * self.forward(inputs, y_b)


# ---------------------------------------------------------------------------
# Knowledge Distillation Loss
# ---------------------------------------------------------------------------


class DistillationLoss(nn.Module):
    """Knowledge distillation loss.

    ``alpha * T^2 * KL(soft_student || soft_teacher) + (1-alpha) * CE(student, labels)``

    Parameters
    ----------
    temperature : float
        Softmax temperature for softening logits.
    alpha : float
        Weight for distillation term (1-alpha for hard label CE).
    """

    def __init__(
        self,
        temperature: float = 4.0,
        alpha: float = 0.7,
    ) -> None:
        super().__init__()
        self.temperature = temperature
        self.alpha = alpha

    def forward(
        self,
        student_logits: torch.Tensor,
        teacher_logits: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """
        Parameters
        ----------
        student_logits : torch.Tensor
            ``[B, C]`` raw student outputs.
        teacher_logits : torch.Tensor
            ``[B, C]`` raw teacher outputs (should be detached by caller).
        targets : torch.Tensor
            ``[B]`` class indices.
        """
        T = self.temperature
        soft_student = F.log_softmax(student_logits / T, dim=1)
        soft_teacher = F.softmax(teacher_logits / T, dim=1)
        kl = F.kl_div(soft_student, soft_teacher, reduction="batchmean") * (T * T)
        ce = F.cross_entropy(student_logits, targets)
        return self.alpha * kl + (1 - self.alpha) * ce


# ---------------------------------------------------------------------------
# Hierarchical Focal Loss
# ---------------------------------------------------------------------------


class HierarchicalFocalLoss(nn.Module):
    """Combined focal loss across all 4 hierarchy levels + KL consistency.

    ``L = w_cls*Focal(class) + w_mt*Focal(mt) + w_fam*Focal(family)
         + w_sf*Focal(sf) + w_cons*KL(mt_induced || mt_probs)``

    *mt_induced*: aggregate class probs to MT space via
    ``class_probs @ mt_class_mask.T``, then compare to ``softmax(mt_logits)``
    with KL divergence.

    Consistency direction: ``KL(mt_probs || mt_induced)`` -- the MT head is
    authoritative and the class head's implied MT distribution is pulled to
    match.  This enforces strictly top-down hierarchy.

    Parameters
    ----------
    gamma : float
        Focal loss focusing parameter.
    w_cls, w_mt, w_fam, w_sf, w_cons : float
        Weights for class, modulation-type, family, super-family, and
        consistency terms.
    class_weights : torch.Tensor or None
        Per-class weights (e.g. OFDM boost), shape ``[num_classes]``.
    label_smoothing : float
        Label smoothing for the CE component of focal loss.
    classes : list[str] or None
        Class name list (defaults to ``sigrift.lib.taxonomy.CLASSES``).
    """

    def __init__(
        self,
        gamma: float = 1.5,
        w_cls: float = 1.0,
        w_mt: float = 0.4,
        w_fam: float = 0.5,
        w_sf: float = 0.25,
        w_cons: float = 0.2,
        class_weights: torch.Tensor | None = None,
        label_smoothing: float = 0.1,
        classes: list[str] | None = None,
    ) -> None:
        super().__init__()
        self.gamma = gamma
        self.w_cls = w_cls
        self.w_mt = w_mt
        self.w_fam = w_fam
        self.w_sf = w_sf
        self.w_cons = w_cons
        self.label_smoothing = label_smoothing

        classes = classes or CLASSES

        # Registered buffers move with .to(device)
        self.register_buffer("class_to_fam", build_class_family_tensor(classes))
        self.register_buffer("class_to_mt", build_class_mt_tensor(classes))
        self.register_buffer("class_to_sf", build_class_sf_tensor(classes))
        self.register_buffer("fam_class_mask", build_family_class_mask(classes))
        self.register_buffer("mt_class_mask", build_mt_class_mask(classes))

        if class_weights is not None:
            self.register_buffer("class_weights", class_weights)
        else:
            self.class_weights = None

    def _focal(
        self,
        logits: torch.Tensor,
        targets: torch.Tensor,
        weight: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """Focal loss on a single hierarchy level."""
        logits = logits.float().clamp(-30, 30)  # prevent overflow
        log_probs = F.log_softmax(logits, dim=1)
        pt = torch.exp(log_probs.gather(1, targets.unsqueeze(1)).squeeze(1))
        ce = F.cross_entropy(
            logits,
            targets,
            weight=weight,
            reduction="none",
            label_smoothing=self.label_smoothing,
        )
        return (((1 - pt) ** self.gamma) * ce).mean()

    def forward(
        self,
        class_logits: torch.Tensor,
        mt_logits: torch.Tensor,
        fam_logits: torch.Tensor,
        sf_logits: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """
        Parameters
        ----------
        class_logits : torch.Tensor
            ``[B, num_classes]``
        mt_logits : torch.Tensor
            ``[B, num_mt]``
        fam_logits : torch.Tensor
            ``[B, num_families]``
        sf_logits : torch.Tensor
            ``[B, num_sf]``
        targets : torch.Tensor
            ``[B]`` class indices
        """
        fam_targets = self.class_to_fam[targets]
        mt_targets = self.class_to_mt[targets]
        sf_targets = self.class_to_sf[targets]

        loss_cls = self._focal(class_logits, targets, weight=self.class_weights)
        loss_mt = self._focal(mt_logits, mt_targets)
        loss_fam = self._focal(fam_logits, fam_targets)
        loss_sf = self._focal(sf_logits, sf_targets)

        # Consistency: MT head is authoritative. Pull class-induced MT
        # distribution toward MT head's prediction. MT probs are detached
        # so gradients only flow through the class head's implied distribution.
        class_probs = F.softmax(class_logits.float(), dim=1)  # [B, C]
        mt_induced = class_probs @ self.mt_class_mask.float().T  # [B, MT]
        mt_induced = mt_induced.clamp(min=1e-8)
        mt_probs = F.softmax(mt_logits.float(), dim=1).detach()  # [B, MT]
        loss_cons = F.kl_div(
            mt_induced.log(),
            mt_probs,
            reduction="batchmean",
        )

        return (
            self.w_cls * loss_cls
            + self.w_mt * loss_mt
            + self.w_fam * loss_fam
            + self.w_sf * loss_sf
            + self.w_cons * loss_cons
        )

    def mixup_forward(
        self,
        class_logits: torch.Tensor,
        mt_logits: torch.Tensor,
        fam_logits: torch.Tensor,
        sf_logits: torch.Tensor,
        y_a: torch.Tensor,
        y_b: torch.Tensor,
        lam: float,
    ) -> torch.Tensor:
        """Mixup-compatible forward: weighted sum for both targets."""
        return lam * self.forward(
            class_logits, mt_logits, fam_logits, sf_logits, y_a
        ) + (1 - lam) * self.forward(
            class_logits, mt_logits, fam_logits, sf_logits, y_b
        )


# ---------------------------------------------------------------------------
# Hierarchical Distillation Loss
# ---------------------------------------------------------------------------


class HierarchicalDistillationLoss(nn.Module):
    """Knowledge distillation at all 4 hierarchy levels.

    ``L = alpha * T^2 * (w_cls*KL_class + w_mt*KL_mt + w_fam*KL_family + w_sf*KL_sf)
         + (1 - alpha) * FocalLoss(student_cls, targets)``

    Level weights mirror ``HierarchicalFocalLoss``: class-level KL dominates,
    SF-level (only 6 classes, trivially matched) gets lowest weight.

    The hard-label term uses focal loss (gamma) to focus on hard examples
    (QAM/PSK/APSK confusion), matching the loss used in direct training.

    Parameters
    ----------
    temperature : float
        Softmax temperature for KD soft labels.
    alpha : float
        Distillation weight (1-alpha for hard-label focal loss).
    gamma : float
        Focal loss focusing parameter for the hard-label term.
    w_cls, w_mt, w_fam, w_sf : float
        Weights for class, modulation-type, family, and super-family KL terms.
    """

    def __init__(
        self,
        temperature: float = 2.0,
        alpha: float = 0.4,
        gamma: float = 1.5,
        w_cls: float = 1.0,
        w_mt: float = 0.4,
        w_fam: float = 0.5,
        w_sf: float = 0.25,
    ) -> None:
        super().__init__()
        self.temperature = temperature
        self.alpha = alpha
        self.gamma = gamma
        self.w_cls = w_cls
        self.w_mt = w_mt
        self.w_fam = w_fam
        self.w_sf = w_sf

    def _kl_at_level(
        self,
        student_logits: torch.Tensor,
        teacher_logits: torch.Tensor,
    ) -> torch.Tensor:
        T = self.temperature
        s = F.log_softmax(student_logits.float() / T, dim=1)
        t = F.softmax(teacher_logits.float() / T, dim=1)
        return F.kl_div(s, t, reduction="batchmean") * (T * T)

    def _focal(
        self,
        logits: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """Focal loss for the hard-label term."""
        logits = logits.float().clamp(-30, 30)
        log_probs = F.log_softmax(logits, dim=1)
        pt = torch.exp(log_probs.gather(1, targets.unsqueeze(1)).squeeze(1))
        ce = F.cross_entropy(logits, targets, reduction="none")
        return (((1 - pt) ** self.gamma) * ce).mean()

    def forward(
        self,
        student_cls: torch.Tensor,
        student_mt: torch.Tensor,
        student_fam: torch.Tensor,
        student_sf: torch.Tensor,
        teacher_cls: torch.Tensor,
        teacher_mt: torch.Tensor,
        teacher_fam: torch.Tensor,
        teacher_sf: torch.Tensor,
        targets: torch.Tensor,
    ) -> torch.Tensor:
        """
        Parameters
        ----------
        student_cls, student_mt, student_fam, student_sf : torch.Tensor
            Student logits at each hierarchy level.
        teacher_cls, teacher_mt, teacher_fam, teacher_sf : torch.Tensor
            Teacher logits (should be detached by caller).
        targets : torch.Tensor
            ``[B]`` class indices.
        """
        kl_cls = self._kl_at_level(student_cls, teacher_cls)
        kl_mt = self._kl_at_level(student_mt, teacher_mt)
        kl_fam = self._kl_at_level(student_fam, teacher_fam)
        kl_sf = self._kl_at_level(student_sf, teacher_sf)

        focal = self._focal(student_cls, targets)

        kd_loss = (
            self.w_cls * kl_cls
            + self.w_mt * kl_mt
            + self.w_fam * kl_fam
            + self.w_sf * kl_sf
        )
        return self.alpha * kd_loss + (1 - self.alpha) * focal


# ---------------------------------------------------------------------------
# Temperature calibration
# ---------------------------------------------------------------------------


def calibrate_temperature(
    model: nn.Module,
    val_loader: torch.utils.data.DataLoader,
    device: torch.device,
    max_iter: int = 50,
) -> float:
    """Post-hoc temperature calibration via LBFGS on validation set.

    After training, logits can be poorly calibrated (over/under-confident).
    This finds a scalar T such that ``softmax(logits / T)`` minimises NLL
    on the held-out validation data.

    Parameters
    ----------
    model : nn.Module
        Trained model (must return class logits as first output or as a
        single tensor).
    val_loader : DataLoader
        Validation data loader.
    device : torch.device
        Device for computation.
    max_iter : int
        Maximum LBFGS iterations.

    Returns
    -------
    float
        Optimal calibration temperature.
    """
    all_logits: list[torch.Tensor] = []
    all_labels: list[torch.Tensor] = []

    model.eval()
    with torch.no_grad():
        for bx, by in val_loader:
            bx = bx.to(device)
            output = model(bx)
            # Support both hierarchical (tuple) and flat (tensor) models
            cls_logits = output[0] if isinstance(output, tuple) else output
            all_logits.append(cls_logits.cpu())
            all_labels.append(by)

    logits = torch.cat(all_logits, dim=0).to(device)
    labels = torch.cat(all_labels, dim=0).to(device)

    # Learnable temperature in log-space (ensures positivity)
    log_temp = nn.Parameter(torch.zeros(1, device=device))
    optimizer = torch.optim.LBFGS([log_temp], lr=0.01, max_iter=max_iter)

    def _closure() -> torch.Tensor:
        optimizer.zero_grad()
        t = log_temp.exp()
        loss = F.cross_entropy(logits / t, labels)
        loss.backward()
        return loss

    optimizer.step(_closure)

    t_cal = float(log_temp.exp().item())
    logger.info("Calibrated temperature: %.4f", t_cal)
    return t_cal
