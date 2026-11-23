"""Both stdin runners must preserve interleaved float32 IQ channel order."""

import importlib
import io
import logging
import struct
import sys
from types import SimpleNamespace

import numpy as np
import pytest


@pytest.fixture(
    params=["sigrift.edge.edge_inference", "sigrift.lib.shiny.edge_inference"]
)
def runner(request):
    return importlib.import_module(request.param)


def run_stdin(runner, monkeypatch, raw):
    frames = []

    class RecordingEngine:
        avg_cls_per_sec = 10.0
        # The edge runner takes its frame length from the engine (the model).
        input_samples = runner.INPUT_SAMPLES

        def __init__(self, model_path, backend):
            assert model_path == "synthetic-contract.onnx"
            assert backend == "onnx"

        def classify(self, frame):
            frames.append(frame.copy())
            return {"class": "tone", "confidence": 1.0, "family": "ANALOG"}

    monkeypatch.setattr(runner, "InferenceEngine", RecordingEngine)
    monkeypatch.setattr(
        sys, "argv", ["edge_inference.py", "--model", "synthetic-contract.onnx"]
    )
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    runner.main()
    return frames


def samples(frame_number, count):
    # Encode each pair independently of numpy reshape/transposition. Distinct
    # signs and ranges make a swapped channel or half-frame split observable.
    pairs = [
        (frame_number + index / 8.0, -1000.0 - index / 4.0) for index in range(count)
    ]
    raw = b"".join(struct.pack("=ff", i, q) for i, q in pairs)
    return (
        raw,
        np.array([pair[0] for pair in pairs], dtype=np.float32),
        np.array([pair[1] for pair in pairs], dtype=np.float32),
    )


def test_interleaved_stream_keeps_channels_and_frame_boundaries(
    runner, monkeypatch, caplog
):
    encoded = [samples(index, runner.INPUT_SAMPLES) for index in range(10)]
    with caplog.at_level(logging.INFO, logger="edge_inference"):
        frames = run_stdin(runner, monkeypatch, b"".join(item[0] for item in encoded))
    assert len(frames) == 10
    for actual, (_, expected_i, expected_q) in zip(frames, encoded, strict=True):
        assert actual.shape == (2, runner.INPUT_SAMPLES)
        assert actual.dtype == np.float32
        np.testing.assert_array_equal(actual[0], expected_i)
        np.testing.assert_array_equal(actual[1], expected_q)
    assert "[10] tone (100.0%) family=ANALOG" in caplog.text
    assert "Processed 10 frames" in caplog.text


@pytest.mark.parametrize("trailing", [b"", b"\x00", struct.pack("=ff", 17.0, -23.0)])
def test_incomplete_tail_never_becomes_an_extra_frame(runner, monkeypatch, trailing):
    raw, expected_i, expected_q = samples(12, runner.INPUT_SAMPLES)
    frames = run_stdin(runner, monkeypatch, raw + trailing)
    assert len(frames) == 1
    np.testing.assert_array_equal(frames[0][0], expected_i)
    np.testing.assert_array_equal(frames[0][1], expected_q)


def test_empty_stream_does_not_classify(runner, monkeypatch, caplog):
    with caplog.at_level(logging.INFO, logger="edge_inference"):
        assert run_stdin(runner, monkeypatch, b"") == []
    assert "Processed 0 frames" in caplog.text
