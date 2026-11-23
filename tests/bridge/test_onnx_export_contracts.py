"""Real serialized ONNX contracts and export-failure model ownership."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import numpy as np
import onnx
import onnxruntime as ort
import pytest
import torch
from torch import nn

from sigrift.lib.dsp.family_classifier import FamilyTrainer
from sigrift.lib.models.edge import EdgeRFClassifier
from sigrift.lib.models.hierarchical import HierarchicalEdgeClassifier
from sigrift.lib.models.onnx_export import (
    export_hierarchical_to_onnx,
    export_to_onnx,
)


@pytest.fixture(autouse=True)
def bounded_torch_runtime():
    previous = torch.get_num_threads()
    with torch.random.fork_rng(devices=[]):
        torch.manual_seed(173)
        torch.set_num_threads(1)
        try:
            yield
        finally:
            torch.set_num_threads(previous)


def load_export(path, opset, input_name, output_names, batch_symbol):
    graph = onnx.load(path)
    onnx.checker.check_model(graph, full_check=True)
    assert {item.domain: item.version for item in graph.opset_import} == {"": opset}
    assert [item.name for item in graph.graph.input] == [input_name]
    assert [item.name for item in graph.graph.output] == output_names
    for value in [*graph.graph.input, *graph.graph.output]:
        assert value.type.tensor_type.shape.dim[0].dim_param == batch_symbol
    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    session = ort.InferenceSession(
        str(path), sess_options=options, providers=["CPUExecutionProvider"]
    )
    assert session.get_providers() == ["CPUExecutionProvider"]
    return session


@pytest.mark.parametrize("opset", [None, 13])
def test_family_export_matches_independent_affine_relu_oracle(tmp_path, opset):
    trainer = FamilyTrainer(epochs=1)
    first = np.linspace(-0.2, 0.3, 32 * 54, dtype=np.float32).reshape(32, 54)
    first_bias = np.linspace(-0.5, 0.5, 32, dtype=np.float32)
    second = np.linspace(-0.3, 0.4, 16 * 32, dtype=np.float32).reshape(16, 32)
    second_bias = np.linspace(-0.1, 0.1, 16, dtype=np.float32)
    with torch.no_grad():
        trainer.model.fc1.weight.copy_(torch.from_numpy(first))
        trainer.model.fc1.bias.copy_(torch.from_numpy(first_bias))
        trainer.model.fc2.weight.copy_(torch.from_numpy(second))
        trainer.model.fc2.bias.copy_(torch.from_numpy(second_bias))
    path = tmp_path / "nested" / "family.onnx"
    options = {} if opset is None else {"opset_version": opset}
    assert trainer.export_onnx(path, **options) == path
    session = load_export(path, opset or 11, "features", ["logits"], "batch_size")
    for batch in (1, 3):
        values = np.linspace(-1.0, 0.9, batch * 54, dtype=np.float32).reshape(batch, 54)
        expected = np.maximum(values @ first.T + first_bias, 0) @ second.T + second_bias
        actual = session.run(None, {"features": values})[0]
        np.testing.assert_allclose(actual, expected, rtol=2e-5, atol=2e-5)
    assert (
        not trainer.model.training
    )  # Existing trainer export leaves its model in eval.


@pytest.mark.parametrize("hierarchical", [False, True])
@pytest.mark.parametrize("training", [False, True])
def test_actual_edge_models_export_dynamic_batches_and_restore_mode(
    tmp_path, hierarchical, training
):
    samples = 512
    if hierarchical:
        model = HierarchicalEdgeClassifier(input_samples=samples)
        exporter = export_hierarchical_to_onnx
        outputs = ["class_logits", "mt_logits", "family_logits", "sf_logits"]
        opset = 17
    else:
        model = EdgeRFClassifier(num_classes=5, input_samples=samples)
        exporter = export_to_onnx
        outputs = ["logits"]
        opset = 13
    model.train(training)
    saved = {name: value.clone() for name, value in model.state_dict().items()}
    path = tmp_path / "edge.onnx"
    assert exporter(model, str(path), input_size=samples) is None
    assert model.training is training
    assert all(value.device.type == "cpu" for value in model.parameters())
    for name, value in model.state_dict().items():
        torch.testing.assert_close(value, saved[name], rtol=0, atol=0)
    session = load_export(path, opset, "iq_input", outputs, "batch")
    model.eval()
    for batch in (1, 3):
        values = (
            np.random.default_rng(batch)
            .normal(size=(batch, 2, samples))
            .astype(np.float32)
        )
        with torch.no_grad():
            expected = model(torch.from_numpy(values))
        if not hierarchical:
            expected = (expected,)
        actual = session.run(None, {"iq_input": values})
        assert len(actual) == len(expected)
        for exported, reference in zip(actual, expected, strict=True):
            assert exported.shape == tuple(reference.shape)
            assert np.isfinite(exported).all()
            np.testing.assert_allclose(
                exported, reference.numpy(), rtol=2e-4, atol=2e-4
            )


class ChannelMeans(nn.Module):
    def forward(self, values):
        return values.mean(dim=2)


class FourChannelMeans(nn.Module):
    def forward(self, values):
        means = values.mean(dim=2)
        return means, means + 1, means * 2, means - 3


@pytest.mark.parametrize("hierarchical", [False, True])
def test_parameterless_models_and_explicit_opset_are_supported(tmp_path, hierarchical):
    model = FourChannelMeans() if hierarchical else ChannelMeans()
    exporter = export_hierarchical_to_onnx if hierarchical else export_to_onnx
    outputs = (
        ["class_logits", "mt_logits", "family_logits", "sf_logits"]
        if hierarchical
        else ["logits"]
    )
    path = tmp_path / "parameterless.onnx"
    exporter(model, str(path), input_size=4, opset_version=17)
    assert model.training
    session = load_export(path, 17, "iq_input", outputs, "batch")
    values = np.arange(24, dtype=np.float32).reshape(3, 2, 4)
    means = np.array([[1.5, 5.5], [9.5, 13.5], [17.5, 21.5]], dtype=np.float32)
    expected = (means, means + 1, means * 2, means - 3) if hierarchical else (means,)
    for actual, reference in zip(
        session.run(None, {"iq_input": values}), expected, strict=True
    ):
        np.testing.assert_array_equal(actual, reference)


class UnexportableEigenvalues(nn.Module):
    def __init__(self):
        super().__init__()
        self.scale = nn.Parameter(torch.tensor(1.0))

    def forward(self, values):
        return torch.linalg.eigvals(values[:, :, :2] * self.scale).real


@pytest.mark.parametrize("hierarchical", [False, True])
@pytest.mark.parametrize("training", [False, True])
@pytest.mark.parametrize("failure", ["directory", "unsupported_operator"])
def test_failed_export_restores_original_model_state(
    tmp_path, hierarchical, training, failure
):
    exporter = export_hierarchical_to_onnx if hierarchical else export_to_onnx
    if failure == "unsupported_operator":
        model = UnexportableEigenvalues()
        error = torch.onnx.errors.UnsupportedOperatorError
    else:
        model = nn.Sequential(nn.Conv1d(2, 2, 1), nn.AdaptiveAvgPool1d(1), nn.Flatten())
        if hierarchical:
            # A genuine four-output callable with registered parameters.
            class FourOutputs(nn.Module):
                def __init__(self, inner):
                    super().__init__()
                    self.inner = inner

                def forward(self, values):
                    result = self.inner(values)
                    return result, result + 1, result + 2, result + 3

            model = FourOutputs(model)
        error = OSError
    model.train(training)
    before = {name: value.clone() for name, value in model.state_dict().items()}
    path = tmp_path if failure == "directory" else tmp_path / "unsupported.onnx"
    with pytest.raises(error):
        exporter(model, str(path), input_size=4)
    assert model.training is training
    for name, value in model.state_dict().items():
        assert value.device.type == "cpu"
        torch.testing.assert_close(value, before[name], rtol=0, atol=0)
    assert not (tmp_path / "unsupported.onnx").exists()


def test_training_export_in_isolated_process_preserves_its_public_graph_contract(
    tmp_path,
):
    # Import registers the open taxonomy globally; isolate that intentional side effect.
    root = Path(__file__).resolve().parents[2]
    code = r"""
import runpy, sys
from pathlib import Path
import numpy as np
import onnx
import onnxruntime as ort
import torch
root, destination = map(Path, sys.argv[1:])
torch.set_num_threads(1)
torch.manual_seed(173)
scope = runpy.run_path(str(root / "training/train_open_default.py"))
model = scope["EdgeRFClassifier"](num_classes=16, input_samples=128)
scope["_export_onnx"](model, destination, input_samples=128)
graph = onnx.load(destination)
onnx.checker.check_model(graph, full_check=True)
assert [(x.domain, x.version) for x in graph.opset_import] == [("", 17)]
assert [x.name for x in graph.graph.input] == ["iq"]
assert [x.name for x in graph.graph.output] == ["logits"]
assert graph.graph.input[0].type.tensor_type.shape.dim[0].dim_param == "batch"
assert graph.graph.output[0].type.tensor_type.shape.dim[0].dim_param == "batch"
options = ort.SessionOptions()
options.intra_op_num_threads = 1
options.inter_op_num_threads = 1
session = ort.InferenceSession(str(destination), sess_options=options, providers=["CPUExecutionProvider"])
for batch in (1, 3):
    values = np.random.default_rng(batch).normal(size=(batch, 2, 128)).astype(np.float32)
    with torch.no_grad():
        expected = model(torch.from_numpy(values)).numpy()
    actual = session.run(None, {"iq": values})[0]
    assert actual.shape == (batch, 16)
    np.testing.assert_allclose(actual, expected, rtol=2e-4, atol=2e-4)
assert not model.training
"""
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    result = subprocess.run(
        [sys.executable, "-c", code, str(root), str(tmp_path / "training.onnx")],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        # Keep child termination inside the repository default 30-second test budget.
        timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
