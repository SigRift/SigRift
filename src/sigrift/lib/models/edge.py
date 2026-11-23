"""Lightweight 1D CNN classifier for edge deployment on constrained devices.

Designed for Raspberry Pi 5 with ONNX Runtime inference. ~420K parameters
(419,972 with a 16-class head, 426,397 with the default 41),
ONNX-exportable, uses CBAM attention for efficient feature recalibration.

Architecture::

    Conv(2 -> 64, k=7, s=2)   + BN + SiLU
    Conv(64 -> 128, k=5, s=2) + BN + SiLU + CBAM(128)
    Conv(128 -> 256, k=3, s=2)+ BN + SiLU + CBAM(256)
    Conv(256 -> 256, k=3, s=2)+ BN + SiLU
    AdaptiveAvgPool1d(1) -> FC(256, 256) + BN + SiLU + Dropout(0.3) -> FC(256, num_classes)

Consolidated from gen2/edge_model.py: removed the inline CBAM duplicate
(now imported from sigrift.lib.models.attention) and the inline export_to_onnx
(now in sigrift.lib.models.onnx_export).
"""

from __future__ import annotations

import torch
import torch.nn as nn

from sigrift.lib.models.attention import CBAM


class EdgeRFClassifier(nn.Module):
    """Lightweight 1D CNN for edge deployment (~420K params).

    Parameters
    ----------
    num_classes : int
        Number of output classes.
    input_samples : int
        Expected input length (for documentation; not enforced at runtime).
    """

    # Feature output dimension (before classifier head)
    feat_dim: int = 256

    def __init__(
        self,
        num_classes: int = 41,
        input_samples: int = 4096,
    ) -> None:
        super().__init__()
        self.num_classes = num_classes
        self.input_samples = input_samples

        self.features = nn.Sequential(
            # Block 1: 2 -> 64
            nn.Conv1d(2, 64, kernel_size=7, stride=2, padding=3),
            nn.BatchNorm1d(64),
            nn.SiLU(),
            # Block 2: 64 -> 128 + CBAM
            nn.Conv1d(64, 128, kernel_size=5, stride=2, padding=2),
            nn.BatchNorm1d(128),
            nn.SiLU(),
            CBAM(128),
            # Block 3: 128 -> 256 + CBAM
            nn.Conv1d(128, 256, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(256),
            nn.SiLU(),
            CBAM(256),
            # Block 4: 256 -> 256
            nn.Conv1d(256, 256, kernel_size=3, stride=2, padding=1),
            nn.BatchNorm1d(256),
            nn.SiLU(),
        )

        self.pool = nn.AdaptiveAvgPool1d(1)

        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(256, 256),
            nn.BatchNorm1d(256),
            nn.SiLU(),
            nn.Dropout(0.3),
            nn.Linear(256, num_classes),
        )

        self._init_weights()

    def _init_weights(self) -> None:
        """Initialize weights: Kaiming for conv, normal(0, 0.01) for linear, constant for BN."""
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(m.weight, mode="fan_out", nonlinearity="linear")
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.BatchNorm1d):
                nn.init.constant_(m.weight, 1)
                nn.init.constant_(m.bias, 0)
            elif isinstance(m, nn.Linear):
                nn.init.normal_(m.weight, 0, 0.01)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Parameters
        ----------
        x : torch.Tensor
            IQ input ``[B, 2, N]``.

        Returns
        -------
        torch.Tensor
            Class logits ``[B, num_classes]``.
        """
        x = self.features(x)
        x = self.pool(x)
        x = self.classifier(x)
        return x

    def get_features(self, x: torch.Tensor) -> torch.Tensor:
        """Extract feature vector before classifier head.

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
        return x.squeeze(-1)
