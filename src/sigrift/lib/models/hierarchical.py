"""Hierarchical RF signal classifiers with 4-level taxonomy and MT-gated class masking.

Two model variants:

- **HierarchicalClassifier** -- full-size (~23M params), uses SignalBackbone
- **HierarchicalEdgeClassifier** -- edge (~500K params), uses EdgeRFClassifier

Both produce four outputs via ``HierarchicalOutput``:
``(class_logits, mt_logits, fam_logits, sf_logits)``.

Cascade::

    backbone -> sf_head -> fam_head(+sf) -> mt_head(+fam+kurtosis+dsp) -> class_head(+dsp, MT-gated)

Additive log-domain MT gating::

    gated = class_logits + gate_weight * log(soft_mask + eps)

Zero-probability classes receive -inf logits (correctly suppressed) while
non-zero classes are not amplified by the mask magnitude.  ``gate_weight``
is a learnable scalar (initial value 1.0).

Consolidated from gen2; imports now use sigrift.* paths,
architecture_version bumped to 8 for v4.15.0 taxonomy restructure, and backbone uses the consolidated
SignalBackbone instead of SignalClassifierCNN.
"""

from __future__ import annotations

import logging
from typing import NamedTuple

import torch
import torch.nn as nn
import torch.nn.functional as F

from sigrift.lib.dsp.spectral_features import NUM_DSP_FEATURES, compute_dsp_features
from sigrift.lib.models.backbone import SignalBackbone
from sigrift.lib.models.edge import EdgeRFClassifier
from sigrift.lib.taxonomy import (
    CLASSES,
    NUM_CLASSES,
    NUM_FAMILIES,
    NUM_MODULATION_TYPES,
    NUM_SUPER_FAMILIES,
    build_family_class_mask,
    build_mt_class_mask,
)

logger = logging.getLogger(__name__)

# Backbone key prefixes used by load_backbone_from_flat for explicit filtering
_FULL_BACKBONE_PREFIXES = ("stem.", "blocks.", "global_pool.")
_EDGE_BACKBONE_PREFIXES = ("features.", "pool.")


class HierarchicalOutput(NamedTuple):
    """4-level hierarchical model output.

    Fields
    ------
    class_logits : torch.Tensor
        ``[B, num_classes]`` MT-gated class logits.
    mt_logits : torch.Tensor
        ``[B, num_mt]`` modulation-type logits.
    fam_logits : torch.Tensor
        ``[B, num_families]`` family logits.
    sf_logits : torch.Tensor
        ``[B, num_sf]`` super-family logits.
    """

    class_logits: torch.Tensor
    mt_logits: torch.Tensor
    fam_logits: torch.Tensor
    sf_logits: torch.Tensor


# ---------------------------------------------------------------------------
# Security validation for checkpoint loading
# ---------------------------------------------------------------------------


def _validate_tensor(key: str, tensor: torch.Tensor) -> bool:
    """Validate a tensor from a checkpoint for security.

    Checks for:
    - Non-floating-point dtype
    - NaN or Inf values
    - Magnitude exceeding 1e6

    Returns True if the tensor is safe to load.
    """
    if not tensor.is_floating_point():
        logger.warning("Skipping key %s: not floating point", key)
        return False
    if torch.isnan(tensor).any() or torch.isinf(tensor).any():
        logger.warning("Skipping key %s: contains NaN/Inf", key)
        return False
    if tensor.abs().max() > 1e6:
        logger.warning("Skipping key %s: magnitude exceeds 1e6", key)
        return False
    return True


# ---------------------------------------------------------------------------
# Full-size hierarchical classifier
# ---------------------------------------------------------------------------


class HierarchicalClassifier(nn.Module):
    """Full hierarchical classifier (~12M params).

    Shared backbone = SignalBackbone (multi-scale stem + ResBlocks with SE).
    Four classification heads:

    - **Super-family head:** ``Linear(feat_dim -> 128 -> 9)``
    - **Family head:** ``Linear(feat_dim + 9 -> 256 -> 16)``
    - **MT head:** ``Linear(feat_dim + 16 + 1 + 16 -> 128 -> 13)``
      (features + family logits + kurtosis + DSP features)
    - **Class head:** ``Linear(feat_dim + 16 -> 512 -> 76)``,
      **gated** by MT probabilities

    Additive log-domain MT gating with learnable weight::

        gated = class_logits_raw + gate_weight * log(soft_mask + eps)

    Parameters
    ----------
    num_classes : int
        Number of fine-grained modulation classes.
    num_families : int
        Number of modulation families.
    num_mt : int
        Number of modulation types.
    num_sf : int
        Number of super-families.
    input_samples : int
        Expected input sample length.
    base_channels : int
        Base channel width for the backbone.
    """

    architecture_version: int = 8  # v4.15.0: 76 classes, 16 families, 13 MT, 9 SF

    def __init__(
        self,
        num_classes: int = NUM_CLASSES,
        num_families: int = NUM_FAMILIES,
        num_mt: int = NUM_MODULATION_TYPES,
        num_sf: int = NUM_SUPER_FAMILIES,
        input_samples: int = 4096,
        base_channels: int = 64,
    ) -> None:
        super().__init__()
        self.num_classes = num_classes
        self.num_families = num_families
        self.num_mt = num_mt
        self.num_sf = num_sf
        self.num_dsp_features = NUM_DSP_FEATURES

        # Shared backbone
        backbone = SignalBackbone(
            input_channels=2,
            base_channels=base_channels,
            input_samples=input_samples,
        )
        self.stem = backbone.stem
        self.blocks = backbone.blocks
        self.global_pool = backbone.global_pool

        feat_dim = base_channels * 16  # 1024 for base_channels=64
        self.feat_dim = feat_dim

        # Super-family head
        self.sf_head = nn.Sequential(
            nn.Linear(feat_dim, 128),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(128, num_sf),
        )

        # Family head -- gets sf logits concatenated
        self.family_head = nn.Sequential(
            nn.Linear(feat_dim + num_sf, 256),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(256, num_families),
        )

        # Modulation-type head -- gets family logits + kurtosis + DSP features
        # Kurtosis helps discriminate PSK (~1.0) vs QAM/APSK (>1.5)
        # DSP features (16): spectral peaks (3) + CP autocorrelation (5) + cumulants (8)
        self.mt_head = nn.Sequential(
            nn.Linear(feat_dim + num_families + 1 + NUM_DSP_FEATURES, 128),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(128, num_mt),
        )

        # Class head -- gets DSP features concatenated; gating applied in forward()
        self.class_head = nn.Sequential(
            nn.Linear(feat_dim + NUM_DSP_FEATURES, 512),
            nn.SiLU(),
            nn.Dropout(0.3),
            nn.Linear(512, num_classes),
        )

        # MT -> class mask [NUM_MODULATION_TYPES, num_classes]
        self.register_buffer(
            "mt_class_mask",
            build_mt_class_mask(CLASSES[:num_classes]),
        )

        # Family -> class mask for backward compat and consistency checks
        self.register_buffer(
            "family_class_mask",
            build_family_class_mask(CLASSES[:num_classes]),
        )

        # Learnable gate weight for additive log-domain gating (default 1.0)
        self.gate_weight = nn.Parameter(torch.tensor(1.0))

        self._init_heads()

    def _init_heads(self) -> None:
        """Initialize head weights with small normal for stability."""
        for module in [self.sf_head, self.family_head, self.mt_head, self.class_head]:
            for m in module.modules():
                if isinstance(m, nn.Linear):
                    nn.init.normal_(m.weight, 0, 0.01)
                    if m.bias is not None:
                        nn.init.constant_(m.bias, 0)

    def get_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract backbone features ``[B, feat_dim]``.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        torch.Tensor
            Feature vector ``[B, feat_dim]``.
        """
        x = self.stem(x)
        x = self.blocks(x)
        x = self.global_pool(x)
        return x.squeeze(-1)

    @staticmethod
    def _feature_kurtosis(features: torch.Tensor) -> torch.Tensor:
        """Compute excess kurtosis of feature vector: E[x^4]/E[x^2]^2 - 3.

        Returns ``[B, 1]`` tensor. PSK features tend to have kurtosis ~1.0,
        QAM/APSK > 1.5, providing a cheap discriminative signal for the MT head.

        Parameters
        ----------
        features : torch.Tensor
            Feature vector ``[B, D]``.

        Returns
        -------
        torch.Tensor
            Excess kurtosis ``[B, 1]``.
        """
        m2 = (features**2).mean(dim=1, keepdim=True)  # [B, 1]
        m4 = (features**4).mean(dim=1, keepdim=True)  # [B, 1]
        # Guard against zero variance (e.g. all-zero features)
        kurtosis = m4 / (m2**2 + 1e-8) - 3.0
        return kurtosis

    def forward(self, x: torch.Tensor) -> HierarchicalOutput:
        """Forward pass through the hierarchical cascade.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        HierarchicalOutput
            Named tuple of ``(class_logits, mt_logits, fam_logits, sf_logits)``.
        """
        features = self.get_features(x)  # [B, feat_dim]

        # DSP features from raw IQ input (normalised internally)
        dsp_feats = compute_dsp_features(x)  # [B, NUM_DSP_FEATURES]

        # Super-family
        sf_logits = self.sf_head(features)  # [B, num_sf]

        # Family (conditioned on sf)
        fam_logits = self.family_head(
            torch.cat([features, sf_logits], dim=1),
        )  # [B, num_families]

        # Kurtosis of features as auxiliary input for MT head
        kurtosis = self._feature_kurtosis(features)  # [B, 1]

        # Modulation-type (conditioned on family + kurtosis + DSP features)
        mt_logits = self.mt_head(
            torch.cat([features, fam_logits, kurtosis, dsp_feats], dim=1),
        )  # [B, num_mt]

        # Class (with DSP features + additive log-domain MT gating)
        class_logits_raw = self.class_head(
            torch.cat([features, dsp_feats], dim=1),
        )  # [B, num_classes]
        mt_probs = F.softmax(mt_logits, dim=1)  # [B, num_mt]
        soft_mask = mt_probs @ self.mt_class_mask  # [B, num_classes]
        class_logits = class_logits_raw + self.gate_weight * torch.log(soft_mask + 1e-8)

        return HierarchicalOutput(class_logits, mt_logits, fam_logits, sf_logits)

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Return gated class predictions ``[B]``.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        torch.Tensor
            Predicted class indices ``[B]``.
        """
        output = self.forward(x)
        return output.class_logits.argmax(dim=1)

    def load_backbone_from_flat(self, path: str, device: str = "cpu") -> int:
        """Load backbone weights from a flat SignalBackbone checkpoint.

        Copies only keys with ``stem.``, ``blocks.``, ``global_pool.``
        prefixes. All other keys (``classifier.*``, head weights) are
        explicitly skipped. Each tensor is validated for NaN/Inf, magnitude,
        and dtype before loading.

        Parameters
        ----------
        path : str
            Path to checkpoint file.
        device : str
            Device to load tensors onto.

        Returns
        -------
        int
            Number of keys successfully loaded.
        """
        ckpt = torch.load(path, map_location=device, weights_only=True)
        state = ckpt["model_state_dict"] if "model_state_dict" in ckpt else ckpt
        own = self.state_dict()
        loaded = 0
        for k, v in state.items():
            if not any(k.startswith(p) for p in _FULL_BACKBONE_PREFIXES):
                continue
            if k in own and own[k].shape == v.shape:
                if not _validate_tensor(k, v):
                    continue
                own[k] = v
                loaded += 1
        self.load_state_dict(own)
        if loaded == 0:
            logger.warning("load_backbone_from_flat: 0 keys loaded from %s", path)
        return loaded


# ---------------------------------------------------------------------------
# Edge hierarchical classifier
# ---------------------------------------------------------------------------


class HierarchicalEdgeClassifier(nn.Module):
    """Lightweight hierarchical classifier for edge deployment (~500K params).

    Backbone reuses EdgeRFClassifier's ``features`` + ``pool`` layers,
    followed by a bottleneck and four classification heads with additive
    log-domain MT-gated class masking.

    ONNX-exportable (4 output tensors, opset 17).

    Parameters
    ----------
    num_classes : int
        Number of fine-grained modulation classes.
    num_families : int
        Number of modulation families.
    num_mt : int
        Number of modulation types.
    num_sf : int
        Number of super-families.
    input_samples : int
        Expected input sample length.
    """

    architecture_version: int = 8  # v4.15.0: 76 classes, 16 families, 13 MT, 9 SF

    def __init__(
        self,
        num_classes: int = NUM_CLASSES,
        num_families: int = NUM_FAMILIES,
        num_mt: int = NUM_MODULATION_TYPES,
        num_sf: int = NUM_SUPER_FAMILIES,
        input_samples: int = 4096,
    ) -> None:
        super().__init__()
        self.num_classes = num_classes
        self.num_families = num_families
        self.num_mt = num_mt
        self.num_sf = num_sf
        self.num_dsp_features = NUM_DSP_FEATURES

        # Backbone (same as EdgeRFClassifier)
        edge = EdgeRFClassifier(num_classes=num_classes, input_samples=input_samples)
        self.features = edge.features
        self.pool = edge.pool

        feat_dim = 256  # EdgeRFClassifier output channels
        self.feat_dim = feat_dim

        # Bottleneck
        self.bottleneck = nn.Sequential(
            nn.Flatten(),
            nn.Linear(feat_dim, feat_dim),
            nn.BatchNorm1d(feat_dim),
            nn.SiLU(),
            nn.Dropout(0.3),
        )

        # Super-family head
        self.sf_head = nn.Sequential(
            nn.Linear(feat_dim, num_sf),
        )

        # Family head
        self.family_head = nn.Sequential(
            nn.Linear(feat_dim + num_sf, 128),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(128, num_families),
        )

        # Modulation-type head (includes kurtosis + DSP features)
        self.mt_head = nn.Sequential(
            nn.Linear(feat_dim + num_families + 1 + NUM_DSP_FEATURES, 64),
            nn.SiLU(),
            nn.Dropout(0.2),
            nn.Linear(64, num_mt),
        )

        # Class head (includes DSP features)
        self.class_head = nn.Sequential(
            nn.Linear(feat_dim + NUM_DSP_FEATURES, 128),
            nn.SiLU(),
            nn.Dropout(0.3),
            nn.Linear(128, num_classes),
        )

        # MT -> class mask
        self.register_buffer(
            "mt_class_mask",
            build_mt_class_mask(CLASSES[:num_classes]),
        )

        # Family -> class mask for backward compat
        self.register_buffer(
            "family_class_mask",
            build_family_class_mask(CLASSES[:num_classes]),
        )

        # Learnable gate weight for additive log-domain gating (default 1.0)
        self.gate_weight = nn.Parameter(torch.tensor(1.0))

        self._init_heads()

    def _init_heads(self) -> None:
        """Initialize head and bottleneck weights."""
        # Head layers: small init to avoid disturbing pretrained backbone features
        for module in [self.sf_head, self.family_head, self.mt_head, self.class_head]:
            for m in module.modules():
                if isinstance(m, nn.Linear):
                    nn.init.normal_(m.weight, 0, 0.01)
                    if m.bias is not None:
                        nn.init.constant_(m.bias, 0)
        # Bottleneck: Kaiming init preserves backbone feature magnitude.
        # Use nonlinearity="linear" (gain=1) since SiLU is approximately
        # identity for small inputs and Kaiming-linear is a closer match.
        for m in self.bottleneck.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(m.weight, nonlinearity="linear")
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.constant_(m.weight, 1)
                nn.init.constant_(m.bias, 0)

    def get_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract backbone features ``[B, 256]``.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        torch.Tensor
            Feature vector ``[B, 256]``.
        """
        x = self.features(x)
        x = self.pool(x)
        x = self.bottleneck(x)
        return x

    def forward(self, x: torch.Tensor) -> HierarchicalOutput:
        """Forward pass through the hierarchical cascade.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        HierarchicalOutput
            Named tuple of ``(class_logits, mt_logits, fam_logits, sf_logits)``.
        """
        features = self.get_features(x)  # [B, 256]

        # DSP features from raw IQ input (normalised internally)
        dsp_feats = compute_dsp_features(x)  # [B, NUM_DSP_FEATURES]

        sf_logits = self.sf_head(features)  # [B, num_sf]

        fam_logits = self.family_head(
            torch.cat([features, sf_logits], dim=1),
        )  # [B, num_families]

        # Kurtosis feature for MT head
        kurtosis = HierarchicalClassifier._feature_kurtosis(features)  # [B, 1]

        mt_logits = self.mt_head(
            torch.cat([features, fam_logits, kurtosis, dsp_feats], dim=1),
        )  # [B, num_mt]

        class_logits_raw = self.class_head(
            torch.cat([features, dsp_feats], dim=1),
        )  # [B, num_classes]
        mt_probs = F.softmax(mt_logits, dim=1)
        soft_mask = mt_probs @ self.mt_class_mask  # [B, num_classes]
        class_logits = class_logits_raw + self.gate_weight * torch.log(soft_mask + 1e-8)

        return HierarchicalOutput(class_logits, mt_logits, fam_logits, sf_logits)

    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Return gated class predictions ``[B]``.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        torch.Tensor
            Predicted class indices ``[B]``.
        """
        output = self.forward(x)
        return output.class_logits.argmax(dim=1)

    def load_backbone_from_flat(self, path: str, device: str = "cpu") -> int:
        """Load backbone weights from a flat EdgeRFClassifier checkpoint.

        Copies only keys with ``features.`` or ``pool.`` prefixes.
        All other keys (``classifier.*``, head weights) are explicitly
        skipped. Each tensor is validated for NaN/Inf, magnitude,
        and dtype before loading.

        Parameters
        ----------
        path : str
            Path to checkpoint file.
        device : str
            Device to load tensors onto.

        Returns
        -------
        int
            Number of keys successfully loaded.
        """
        ckpt = torch.load(path, map_location=device, weights_only=True)
        state = ckpt["model_state_dict"] if "model_state_dict" in ckpt else ckpt
        own = self.state_dict()
        loaded = 0
        for k, v in state.items():
            if not any(k.startswith(p) for p in _EDGE_BACKBONE_PREFIXES):
                continue
            if k in own and own[k].shape == v.shape:
                if not _validate_tensor(k, v):
                    continue
                own[k] = v
                loaded += 1
        self.load_state_dict(own)
        if loaded == 0:
            logger.warning("load_backbone_from_flat: 0 keys loaded from %s", path)
        return loaded
