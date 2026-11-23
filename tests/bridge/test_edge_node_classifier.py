"""Actual ONNX CPU integration for the alternate node/legacy monitor classifier.

The tiny graph computes I/Q channel means. It verifies the loader, numerical
contract and label mapping, not trained RF model accuracy or Hailo execution.
This module requires the explicit ONNX test runtime; inference is never mocked.
"""

from __future__ import annotations

import json
import math

import numpy as np
import onnx
from onnx import TensorProto, helper
import onnxruntime as ort
import pytest

from sigrift.edge.node import HailoClassifier


def make_graph(path, *, samples=4, shape=None, dtype=TensorProto.FLOAT, bias=None):
    shape = [1, 2, samples] if shape is None else shape
    nodes = [helper.make_node("ReduceMean", ["iq"], ["means"], axes=[2], keepdims=0)]
    initializers = []
    output = "means"
    if bias is not None:
        initializers.append(helper.make_tensor("bias", dtype, [1], [bias]))
        nodes.append(helper.make_node("Add", ["means", "bias"], ["logits"]))
        output = "logits"
    graph = helper.make_graph(
        nodes,
        "known_channel_means",
        [helper.make_tensor_value_info("iq", dtype, shape)],
        [helper.make_tensor_value_info(output, dtype, [1, shape[1]])],
        initializers,
    )
    # A stable old IR/opset supported by the pinned real ORT, not its defaults.
    model = helper.make_model(graph, opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model, full_check=True)
    onnx.save(model, path)


@pytest.fixture
def model_files(tmp_path):
    model = tmp_path / "fixture.onnx"
    metadata = tmp_path / "fixture_metadata.json"
    make_graph(model)
    metadata.write_text(
        json.dumps({"input_samples": 4, "class_names": ["bpsk", "gfsk"]})
    )
    return model, metadata


def load_classifier(model_files):
    model, metadata = model_files
    # The public loader derives .onnx from a missing .hef; no fake session.
    classifier = HailoClassifier(str(model.with_suffix(".hef")), str(metadata))
    assert classifier.available and classifier.use_onnx
    assert isinstance(classifier.onnx_session, ort.InferenceSession)
    assert classifier.onnx_session.get_providers() == ["CPUExecutionProvider"]
    assert classifier.onnx_session.get_inputs()[0].name == "iq"
    return classifier


@pytest.mark.parametrize(
    "samples,expected,means",
    [
        ([1 + 0j] * 4, [[1, 1, 1, 1], [0, 0, 0, 0]], (1, 0)),
        ([0 + 1j] * 4, [[0, 0, 0, 0], [1, 1, 1, 1]], (0, 1)),
        ([0j] * 4, [[0, 0, 0, 0], [0, 0, 0, 0]], (0, 0)),
        (
            [2 + 0j] * 2,
            [[math.sqrt(2), math.sqrt(2), 0, 0], [0, 0, 0, 0]],
            (1 / math.sqrt(2), 0),
        ),
        (
            [999 + 999j] + [3 + 4j] * 4 + [-999 - 999j],
            [[0.6] * 4, [0.8] * 4],
            (0.6, 0.8),
        ),
        (
            [1 + 2j, -1 + 2j, 1 - 2j, -1 - 2j],
            [
                [1 / math.sqrt(5), -1 / math.sqrt(5)] * 2,
                [
                    2 / math.sqrt(5),
                    2 / math.sqrt(5),
                    -2 / math.sqrt(5),
                    -2 / math.sqrt(5),
                ],
            ],
            (0, 0),
        ),
    ],
    ids=[
        "real-channel",
        "imag-channel",
        "zero-power",
        "right-padding",
        "center-crop",
        "both-channels",
    ],
)
def test_real_loader_and_inference_match_independent_iq_oracle(
    model_files, samples, expected, means
):
    classifier = load_classifier(model_files)
    # Noncontiguous caller-owned input catches accidental shape/mutation assumptions.
    backing = np.empty(len(samples) * 2, dtype=np.complex64)
    backing[::2] = samples
    backing[1::2] = 91 - 19j
    before = backing.copy()
    iq = backing[::2]
    tensor = classifier.preprocess(iq)
    assert tensor.dtype == np.float32 and tensor.shape == (1, 2, 4)
    np.testing.assert_allclose(tensor, np.array([expected]), rtol=0, atol=1e-7)
    name, confidence, family, probabilities = classifier.classify(iq)
    # Closed-form two-logit logistic oracle, independent of production softmax.
    first = 1 / (1 + math.exp(means[1] - means[0]))
    np.testing.assert_allclose(
        list(probabilities.values()), [first, 1 - first], rtol=0, atol=1e-7
    )
    assert list(probabilities) == ["bpsk", "gfsk"]
    assert name == ("bpsk" if first >= 0.5 else "gfsk")
    assert family == ("psk" if first >= 0.5 else "fsk")
    assert confidence == pytest.approx(max(first, 1 - first), abs=1e-7)
    np.testing.assert_array_equal(backing, before)


@pytest.mark.parametrize("names", [[], ["bpsk"], ["bpsk", "gfsk"]])
def test_metadata_labels_and_missing_label_fallback_use_real_output(model_files, names):
    model, metadata = model_files
    metadata.write_text(json.dumps({"input_samples": 4, "class_names": names}))
    classifier = load_classifier(model_files)
    name, confidence, family, probabilities = classifier.classify(
        np.full(4, 1j, dtype=np.complex64)
    )
    assert name == ("gfsk" if len(names) == 2 else "class_1")
    assert family == ("fsk" if len(names) == 2 else "unknown")
    assert confidence == pytest.approx(math.e / (1 + math.e), abs=1e-7)
    assert list(probabilities) == [
        names[0] if names else "class_0",
        names[1] if len(names) == 2 else "class_1",
    ]


def test_large_real_graph_logits_still_produce_finite_probabilities(model_files):
    model, _ = model_files
    make_graph(model, bias=1000)
    classifier = load_classifier(model_files)
    _, confidence, _, probabilities = classifier.classify(
        np.ones(4, dtype=np.complex64)
    )
    assert all(math.isfinite(value) for value in probabilities.values())
    assert sum(probabilities.values()) == pytest.approx(1)
    assert confidence == pytest.approx(math.e / (1 + math.e), abs=1e-7)


@pytest.mark.parametrize("metadata_exists", [False, True])
def test_absent_or_optional_metadata_defaults_are_used_by_actual_runtime(
    tmp_path, metadata_exists
):
    model, metadata = tmp_path / "default.onnx", tmp_path / "metadata.json"
    make_graph(model, samples=8192)
    if metadata_exists:
        metadata.write_text("{}")
    classifier = HailoClassifier(str(model.with_suffix(".hef")), str(metadata))
    assert classifier.available and classifier.input_samples == 8192
    name, confidence, family, probabilities = classifier.classify(
        np.ones(8192, dtype=np.complex64)
    )
    assert name == "class_0" and family == "unknown"
    assert confidence == pytest.approx(math.e / (1 + math.e), abs=1e-7)
    assert list(probabilities) == ["class_0", "class_1"]


@pytest.mark.parametrize("payload", [None, b"not an ONNX protobuf", b"\x08"])
def test_missing_or_corrupt_model_never_reports_available_or_fake_classification(
    tmp_path, payload
):
    model = tmp_path / "broken.onnx"
    if payload is not None:
        model.write_bytes(payload)
    classifier = HailoClassifier(str(model.with_suffix(".hef")))
    assert not classifier.available
    assert classifier.classify(np.ones(4, dtype=np.complex64)) == (
        "unknown",
        0.0,
        "unknown",
        {},
    )


def test_malformed_real_metadata_fails_before_model_can_be_reported_ready(model_files):
    model, metadata = model_files
    metadata.write_text('{"class_names":[')
    with pytest.raises(json.JSONDecodeError):
        HailoClassifier(str(model.with_suffix(".hef")), str(metadata))


@pytest.mark.parametrize("incompatibility", ["shape", "dtype"])
def test_incompatible_real_model_rejects_input_instead_of_fabricating_detection(
    model_files, incompatibility
):
    model, _ = model_files
    if incompatibility == "shape":
        make_graph(model, shape=[1, 4, 2])
    else:
        make_graph(model, dtype=TensorProto.DOUBLE)
    classifier = load_classifier(model_files)
    with pytest.raises(
        ort.capi.onnxruntime_pybind11_state.InvalidArgument,
        match="dimensions|data type",
    ):
        classifier.classify(np.ones(4, dtype=np.complex64))


@pytest.mark.parametrize(
    "label,family",
    [
        ("64QAM", "qam"),
        ("OFDM", "ofdm"),
        ("WBFM", "analog"),
        ("OOK", "ask"),
        ("unmapped", "unknown"),
    ],
)
def test_real_output_preserves_metadata_label_and_known_family_mapping(
    model_files, label, family
):
    model, metadata = model_files
    metadata.write_text(
        json.dumps({"input_samples": 4, "class_names": [label, "other"]})
    )
    classifier = load_classifier(model_files)
    name, confidence, actual_family, probabilities = classifier.classify(
        np.ones(4, dtype=np.complex64)
    )
    assert name == label and actual_family == family
    assert confidence == pytest.approx(math.e / (1 + math.e), abs=1e-7)
    assert probabilities[label] == confidence


def test_direct_onnx_path_loads_real_model_without_requiring_hef_artifact(model_files):
    model, metadata = model_files
    classifier = HailoClassifier(str(model), str(metadata))
    assert classifier.available and classifier.use_onnx
    name, confidence, family, _ = classifier.classify(np.ones(4, dtype=np.complex64))
    assert (name, family) == ("bpsk", "psk")
    assert confidence == pytest.approx(math.e / (1 + math.e), abs=1e-7)
    assert not model.with_suffix(".hef").exists()
