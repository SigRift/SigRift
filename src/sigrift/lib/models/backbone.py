"""Shared ResNet-style 1D CNN backbone for RF signal classification.

Consolidates the ConvBlock/ResBlock/backbone definitions that were duplicated
across gen2's rf_signal_identifier.py, edge_model.py, and train_enhanced.py
into a single, well-tested implementation.

Architecture (for default base_channels=64)::

    Stem:   MultiScaleStem(2 -> 64) with kernel sizes [3, 7, 15]
    Block1: ConvBlock(64 -> 128, stride=2)  + ResBlock(128)
    Block2: ConvBlock(128 -> 256, stride=2) + ResBlock(256)
    Block3: ConvBlock(256 -> 512, stride=2) + ResBlock(512)
    Block4: ConvBlock(512 -> 1024, stride=2) + ResBlock(1024)
    GlobalAvgPool1d -> [B, 1024]
"""

from __future__ import annotations

import torch
import torch.nn as nn

from sigrift.lib.models.attention import SEBlock


class ConvBlock(nn.Module):
    """Conv1d + BatchNorm1d + SiLU.

    Parameters
    ----------
    in_ch : int
        Number of input channels.
    out_ch : int
        Number of output channels.
    kernel_size : int
        Convolution kernel size.
    stride : int
        Convolution stride.
    """

    def __init__(
        self,
        in_ch: int,
        out_ch: int,
        kernel_size: int = 3,
        stride: int = 1,
    ) -> None:
        super().__init__()
        self.conv = nn.Conv1d(
            in_ch,
            out_ch,
            kernel_size,
            stride=stride,
            padding=kernel_size // 2,
        )
        self.bn = nn.BatchNorm1d(out_ch)
        self.act = nn.SiLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.act(self.bn(self.conv(x)))


class ResBlock(nn.Module):
    """Residual block with SE attention and optional downsampling.

    Two Conv1d layers with BatchNorm and SiLU, followed by an SEBlock,
    then added to the skip connection.

    Architecture::

        x -> conv1(C, C, k=3) -> BN -> SiLU -> conv2(C, C, k=3) -> BN -> SE -> + skip -> SiLU

    Parameters
    ----------
    channels : int
        Number of input and output channels.
    use_se : bool
        Whether to apply Squeeze-and-Excitation attention after the
        second convolution.
    """

    def __init__(self, channels: int, use_se: bool = True) -> None:
        super().__init__()
        self.conv1 = nn.Conv1d(channels, channels, 3, padding=1)
        self.bn1 = nn.BatchNorm1d(channels)
        self.conv2 = nn.Conv1d(channels, channels, 3, padding=1)
        self.bn2 = nn.BatchNorm1d(channels)
        self.act = nn.SiLU()
        self.se = SEBlock(channels) if use_se else nn.Identity()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        out = self.act(self.bn1(self.conv1(x)))
        out = self.bn2(self.conv2(out))
        out = self.se(out)
        return self.act(out + residual)


class MultiScaleStem(nn.Module):
    """Multi-scale stem that captures features at different temporal resolutions.

    Three parallel Conv1d branches with kernel sizes [3, 7, 15], each producing
    ``out_channels`` feature maps, concatenated and projected back to
    ``out_channels`` via a 1x1 convolution.

    Parameters
    ----------
    in_channels : int
        Number of input channels (typically 2 for I/Q).
    out_channels : int
        Number of output channels per branch (and final output).
    """

    def __init__(self, in_channels: int, out_channels: int) -> None:
        super().__init__()
        kernel_sizes = [3, 7, 15]
        self.branches = nn.ModuleList(
            [
                nn.Sequential(
                    nn.Conv1d(
                        in_channels,
                        out_channels,
                        k,
                        stride=2,
                        padding=k // 2,
                    ),
                    nn.BatchNorm1d(out_channels),
                    nn.SiLU(),
                )
                for k in kernel_sizes
            ]
        )
        # 1x1 projection from concatenated branches back to out_channels
        self.project = nn.Sequential(
            nn.Conv1d(out_channels * len(kernel_sizes), out_channels, 1),
            nn.BatchNorm1d(out_channels),
            nn.SiLU(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        branch_outputs = [branch(x) for branch in self.branches]
        # All branches have same spatial size due to same stride and auto-padding
        out = torch.cat(branch_outputs, dim=1)
        return self.project(out)


class SignalBackbone(nn.Module):
    """Shared ResNet-style 1D CNN backbone for RF signals.

    Multi-scale stem followed by residual blocks with SE attention.
    Output: ``[B, feat_dim]`` feature vector.

    Architecture (for base_channels=64)::

        Stem: MultiScaleStem(2 -> 64) with kernel sizes [3, 7, 15]
        Block1: ConvBlock(64 -> 128, stride=2)  + ResBlock(128)
        Block2: ConvBlock(128 -> 256, stride=2) + ResBlock(256)
        Block3: ConvBlock(256 -> 512, stride=2) + ResBlock(512)
        Block4: ConvBlock(512 -> 1024, stride=2) + ResBlock(1024)
        GlobalAvgPool1d -> [B, 1024]

    Parameters
    ----------
    input_channels : int
        Number of input channels (2 for I/Q data).
    base_channels : int
        Base channel width (scaled by 2/4/8/16 in each block).
    input_samples : int
        Expected input length (for documentation; not enforced).
    """

    def __init__(
        self,
        input_channels: int = 2,
        base_channels: int = 64,
        input_samples: int = 4096,
    ) -> None:
        super().__init__()
        self.input_channels = input_channels
        self.base_channels = base_channels
        self.input_samples = input_samples
        self.feat_dim = base_channels * 16  # 1024 for default

        # Multi-scale stem
        self.stem = MultiScaleStem(input_channels, base_channels)

        # Residual blocks with increasing channel counts
        c = base_channels
        self.blocks = nn.Sequential(
            # Block 1: base -> 2x
            ConvBlock(c, c * 2, stride=2),
            ResBlock(c * 2),
            # Block 2: 2x -> 4x
            ConvBlock(c * 2, c * 4, stride=2),
            ResBlock(c * 4),
            # Block 3: 4x -> 8x
            ConvBlock(c * 4, c * 8, stride=2),
            ResBlock(c * 8),
            # Block 4: 8x -> 16x
            ConvBlock(c * 8, c * 16, stride=2),
            ResBlock(c * 16),
        )

        self.global_pool = nn.AdaptiveAvgPool1d(1)

        self._init_weights()

    def _init_weights(self) -> None:
        """Initialize weights: Kaiming for conv, constant for BN, normal for linear."""
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
        """Extract backbone features.

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
        return x.squeeze(-1)  # [B, feat_dim]
