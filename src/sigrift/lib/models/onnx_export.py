"""Consolidated ONNX export utilities for flat and hierarchical models.

Eliminates the duplication between gen2/edge_model.py (inline export_to_onnx)
and gen2/hierarchical_model.py (export_hierarchical_to_onnx) by providing
both in a single module.

Usage::

    from sigrift.lib.models.onnx_export import export_to_onnx, export_hierarchical_to_onnx

    # Flat model (single logits output)
    export_to_onnx(model, "model.onnx")

    # Hierarchical model (4 named outputs)
    export_hierarchical_to_onnx(model, "hierarchical.onnx")
"""

from __future__ import annotations

import logging

import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


def export_to_onnx(
    model: nn.Module,
    path: str,
    input_size: int = 4096,
    opset_version: int = 13,
) -> None:
    """Export a flat model to ONNX with a single logits output.

    The model is temporarily moved to CPU and set to eval mode for export,
    then restored to its original device and training state, including on failure.
    The legacy exporter preserves the requested opset and ``dynamic_axes`` contract.

    Parameters
    ----------
    model : nn.Module
        Model to export (must accept ``[B, 2, N]`` input and return
        ``[B, num_classes]`` logits).
    path : str
        Output ONNX file path.
    input_size : int
        Number of input samples (N dimension).
    opset_version : int
        ONNX opset version. 13 is sufficient for basic Conv1d/Linear models.
    """
    params = list(model.parameters())
    original_device = params[0].device if params else torch.device("cpu")
    was_training = model.training

    try:
        model.cpu().eval()
        dummy = torch.randn(1, 2, input_size)

        torch.onnx.export(
            model,
            dummy,
            path,
            opset_version=opset_version,
            dynamo=False,
            input_names=["iq_input"],
            output_names=["logits"],
            dynamic_axes={
                "iq_input": {0: "batch"},
                "logits": {0: "batch"},
            },
        )
    finally:
        try:
            model.to(original_device)
        finally:
            model.train(was_training)

    logger.info("Exported flat model to %s (opset %d)", path, opset_version)


def export_hierarchical_to_onnx(
    model: nn.Module,
    path: str,
    input_size: int = 4096,
    opset_version: int = 17,
) -> None:
    """Export a hierarchical model to ONNX with 4 named outputs.

    Output names: ``class_logits``, ``mt_logits``, ``family_logits``, ``sf_logits``.

    Uses opset 17 by default for the hierarchical models and their real-valued
    DSP features. The model is temporarily moved to CPU and
    set to eval mode for export, then restored to its original device and
    training state, including on failure. The legacy exporter preserves the
    requested opset and ``dynamic_axes`` contract.

    Parameters
    ----------
    model : nn.Module
        Hierarchical model to export (must accept ``[B, 2, N]`` input and
        return a 4-tuple of tensors).
    path : str
        Output ONNX file path.
    input_size : int
        Number of input samples (N dimension).
    opset_version : int
        ONNX opset version (default 17).
    """
    params = list(model.parameters())
    original_device = params[0].device if params else torch.device("cpu")
    was_training = model.training

    try:
        model.cpu().eval()
        dummy = torch.randn(1, 2, input_size)

        torch.onnx.export(
            model,
            dummy,
            path,
            opset_version=opset_version,
            dynamo=False,
            input_names=["iq_input"],
            output_names=["class_logits", "mt_logits", "family_logits", "sf_logits"],
            dynamic_axes={
                "iq_input": {0: "batch"},
                "class_logits": {0: "batch"},
                "mt_logits": {0: "batch"},
                "family_logits": {0: "batch"},
                "sf_logits": {0: "batch"},
            },
        )
    finally:
        try:
            model.to(original_device)
        finally:
            model.train(was_training)

    logger.info(
        "Exported hierarchical model to %s (opset %d)",
        path,
        opset_version,
    )
