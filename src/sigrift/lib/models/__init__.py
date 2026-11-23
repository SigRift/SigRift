"""Model architectures for RF signal classification.

- Shared ResNet-style 1D CNN backbone (consolidated from duplicated definitions)
- SE and CBAM attention modules (consolidated)
- Full hierarchical classifier (~23M params, 4-level taxonomy)
- Edge hierarchical classifier (~500K params, ONNX-exportable)
- ONNX export utilities
"""

from sigrift.lib.models.attention import SEBlock, CBAM
from sigrift.lib.models.backbone import ResBlock, SignalBackbone
from sigrift.lib.models.hierarchical import (
    HierarchicalClassifier,
    HierarchicalEdgeClassifier,
    HierarchicalOutput,
)
from sigrift.lib.models.edge import EdgeRFClassifier
from sigrift.lib.models.onnx_export import export_to_onnx, export_hierarchical_to_onnx

__all__ = [
    "SEBlock",
    "CBAM",
    "ResBlock",
    "SignalBackbone",
    "HierarchicalClassifier",
    "HierarchicalEdgeClassifier",
    "HierarchicalOutput",
    "EdgeRFClassifier",
    "export_to_onnx",
    "export_hierarchical_to_onnx",
]
