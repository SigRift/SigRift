"""Consolidated attention modules for RF signal classification.

Squeeze-and-Excitation (SE) and Convolutional Block Attention Module (CBAM)
for 1D signal processing. These were duplicated 3+ times across gen2 files
(edge_model.py, rf_signal_identifier.py, train_enhanced.py); now unified here.

Both modules are ONNX-safe (no complex ops, no in-place mutations).
"""

from __future__ import annotations

import torch
import torch.nn as nn


class SEBlock(nn.Module):
    """Squeeze-and-Excitation block for 1D signals.

    Applies channel-wise recalibration via global average pooling followed by
    a two-layer bottleneck FC network with sigmoid gating.

    Architecture::

        AdaptiveAvgPool1d(1) -> Linear(C, mid) -> SiLU -> Linear(mid, C) -> Sigmoid

    Parameters
    ----------
    channels : int
        Number of input/output channels.
    reduction : int
        Channel reduction factor for the bottleneck (min 8 channels).
    """

    def __init__(self, channels: int, reduction: int = 16) -> None:
        super().__init__()
        mid = max(channels // reduction, 8)
        self.pool = nn.AdaptiveAvgPool1d(1)
        self.fc = nn.Sequential(
            nn.Linear(channels, mid),
            nn.SiLU(),
            nn.Linear(mid, channels),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply SE attention.

        Parameters
        ----------
        x : torch.Tensor
            Input tensor ``[B, C, L]``.

        Returns
        -------
        torch.Tensor
            Recalibrated tensor ``[B, C, L]``.
        """
        b, c, _ = x.shape
        scale = self.pool(x).view(b, c)  # [B, C]
        scale = self.fc(scale).view(b, c, 1)  # [B, C, 1]
        return x * scale


class CBAM(nn.Module):
    """Convolutional Block Attention Module for 1D signals (ONNX-safe).

    Applies sequential channel and spatial attention:

    **Channel attention:** shared FC applied to both avg-pooled and max-pooled
    features, summed before sigmoid gating.

    **Spatial attention:** concatenate channel-wise mean and max, apply
    Conv1d(2, 1, kernel_size=7) with sigmoid gating.

    Parameters
    ----------
    channels : int
        Number of input/output channels.
    reduction : int
        Channel reduction factor for the shared FC (min 8 channels).
    """

    def __init__(self, channels: int, reduction: int = 16) -> None:
        super().__init__()
        mid = max(channels // reduction, 8)
        self.channel_fc = nn.Sequential(
            nn.Linear(channels, mid),
            nn.SiLU(),
            nn.Linear(mid, channels),
        )
        self.spatial_conv = nn.Conv1d(
            2,
            1,
            kernel_size=7,
            padding=3,
            bias=False,
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Apply CBAM attention.

        Parameters
        ----------
        x : torch.Tensor
            Input tensor ``[B, C, L]``.

        Returns
        -------
        torch.Tensor
            Attended tensor ``[B, C, L]``.
        """
        # --- Channel attention ---
        avg = x.mean(dim=2)  # [B, C]
        mx = x.amax(dim=2)  # [B, C]
        ca = torch.sigmoid(self.channel_fc(avg) + self.channel_fc(mx))  # [B, C]
        x = x * ca.unsqueeze(2)

        # --- Spatial attention ---
        avg_s = x.mean(dim=1, keepdim=True)  # [B, 1, L]
        mx_s = x.amax(dim=1, keepdim=True)  # [B, 1, L]
        sa = torch.sigmoid(
            self.spatial_conv(torch.cat([avg_s, mx_s], dim=1)),
        )  # [B, 1, L]
        x = x * sa

        return x
