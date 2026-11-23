#!/usr/bin/env python3
"""SigRift edge inference runner.

Runs RF signal classification on edge nodes using ONNX Runtime.

Usage:
    # Benchmark mode (synthetic data)
    python3 edge_inference.py --model model.onnx --benchmark

    # Continuous inference from native-endian float32 I/Q pairs
    python3 edge_inference.py --model model.onnx < capture-iq.f32

Input order is I0, Q0, I1, Q1, ... . Convert unsigned 8-bit SDR output to
normalized float32 pairs before using this runner.

Each frame is scaled to unit average power before inference, as in
training, so the absolute receiver scale does not matter.

Environment variables:
    MLRF_MODEL_PATH
    MLRF_INPUT_SAMPLES  frame length, used only when the model's input
                        length is not fixed (default 4096)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("edge_inference")

VERSION = "4.1.0"
# IQ samples per frame when neither the model nor MLRF_INPUT_SAMPLES says.
INPUT_SAMPLES = 4096


class ModelContractError(RuntimeError):
    """The model and its class names (or frame size) do not agree.

    Running anyway would label every detection wrongly, so callers treat
    this like a model that cannot be loaded.
    """


# ---------------------------------------------------------------------------
# Model metadata / class labels
# ---------------------------------------------------------------------------

DEFAULT_CLASSES = [
    "ook",
    "4ask",
    "8ask",
    "16ask",
    "4pam",
    "8pam",
    "16pam",
    "bpsk",
    "qpsk",
    "8psk",
    "16psk",
    "32psk",
    "16qam",
    "32qam",
    "64qam",
    "128qam",
    "256qam",
    "16apsk",
    "32apsk",
    "64apsk",
    "128apsk",
    "2fsk",
    "4fsk",
    "2gfsk",
    "4gfsk",
    "2msk",
    "4msk",
    "2gmsk",
    "4gmsk",
    "ofdm-64",
    "ofdm-128",
    "ofdm-256",
    "ofdm-512",
    "ofdm-1024",
    "ofdm-2048",
    "lora-css",
    "am-dsb",
    "am-ssb",
    "fm",
    "tone",
    "noise",
]

FAMILIES = {
    # The bare names (ask, psk, ..., pocsag) are the open-default model's
    # classes; they must not fall through to UNKNOWN, which the default
    # "Novel Signal Detected" rule treats as a novel signal.
    "ASK": ["ook", "4ask", "8ask", "16ask", "ask"],
    "PAM": ["4pam", "8pam", "16pam"],
    "PSK": ["bpsk", "qpsk", "8psk", "16psk", "32psk", "psk"],
    "QAM": ["16qam", "32qam", "64qam", "128qam", "256qam", "qam"],
    "APSK": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "FSK": [
        "2fsk",
        "4fsk",
        "2gfsk",
        "4gfsk",
        "2msk",
        "4msk",
        "2gmsk",
        "4gmsk",
        "fsk",
        "gfsk",
        "msk",
        "pocsag",
    ],
    "OFDM": [
        "ofdm-64",
        "ofdm-128",
        "ofdm-256",
        "ofdm-512",
        "ofdm-1024",
        "ofdm-2048",
        "ofdm",
    ],
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone", "am", "fpv-analog"],
    "SPREAD_SPECTRUM": ["lora-css", "dsss"],
    "NOISE": ["noise"],
    "PULSED": ["adsb"],
}


def _class_to_family(cls_name: str) -> str:
    for fam, members in FAMILIES.items():
        if cls_name in members:
            return fam
    return "UNKNOWN"


def load_metadata(model_path: str) -> list[str]:
    return _load_metadata(model_path)[0]


def _load_metadata(model_path: str) -> tuple[list[str], Path | None]:
    """Load class names from metadata JSON sibling of the model.

    Tries in order:
      1. ``<model_stem>_metadata.json`` — what training/train_open_default.py
         writes alongside each ONNX export.
      2. The same for the file the model path links to, when it is an
         alias (``open-default.onnx`` -> ``<release>.onnx``).
      3. ``gen4_edge_metadata.json`` — legacy fixed filename used by older
         training runs.
      4. Falls back to ``DEFAULT_CLASSES`` if nothing is found or parseable.

    Another model's ``*_metadata.json`` in the same directory is never
    used: a list of the right length for the wrong model would mislabel
    every detection without tripping the class-count check.

    Returns the names and the metadata file they came from (``None`` for
    the built-in fallback).

    Accepts either ``class_names`` (legacy) or ``classes`` (current
    train_open_default.py output) as the JSON key.
    """
    p = Path(model_path)
    candidates = [p.parent / f"{p.stem}_metadata.json"]
    try:
        target = p.resolve()
    except OSError:
        target = p
    candidates.append(target.parent / f"{target.stem}_metadata.json")
    candidates.append(p.parent / "gen4_edge_metadata.json")

    seen: set[Path] = set()
    for meta_path in candidates:
        if meta_path in seen or not meta_path.exists():
            seen.add(meta_path)
            continue
        seen.add(meta_path)
        try:
            meta = json.loads(meta_path.read_text())
            names = meta.get("classes") or meta.get("class_names")
            if names:
                logger.info("Loaded %d classes from %s", len(names), meta_path)
                return names, meta_path
        except Exception as e:
            logger.warning("Failed to load metadata from %s: %s", meta_path, e)
    # WARNING, not INFO: the built-in list belongs to an older model, so the
    # labels are only right if this model happens to share it.
    logger.warning(
        "No class-name metadata found for %s (expected %s); using the built-in"
        " class list",
        model_path,
        p.parent / f"{p.stem}_metadata.json",
    )
    return DEFAULT_CLASSES, None


def _fixed_dim(shape, axis: int) -> int | None:
    """The size of *axis* in an ONNX shape, or None if it is symbolic."""
    try:
        dim = shape[axis]
    except (IndexError, TypeError):
        return None
    return dim if isinstance(dim, int) and dim > 0 else None


def resolve_input_samples(declared: int | None) -> int:
    """Frame length: the model's fixed input length, else the env, else 4096."""
    if declared is not None:
        return declared
    raw = os.environ.get("MLRF_INPUT_SAMPLES", "").strip()
    if not raw:
        return INPUT_SAMPLES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise ModelContractError(
            f"MLRF_INPUT_SAMPLES must be a positive integer, got {raw!r}"
        )
    return value


# ---------------------------------------------------------------------------
# ONNX Runtime backend
# ---------------------------------------------------------------------------


class ONNXBackend:
    """ONNX Runtime inference backend."""

    def __init__(self, model_path: str) -> None:
        import onnxruntime as ort

        opts = ort.SessionOptions()
        opts.inter_op_num_threads = int(os.environ.get("MLRF_INTER_THREADS", "2"))
        opts.intra_op_num_threads = int(os.environ.get("MLRF_INTRA_THREADS", "4"))
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        # Prefer CUDA when the GPU runtime is present (onnxruntime-gpu
        # build), always fall back to CPU. On the default CPU build only
        # CPUExecutionProvider is available, so this is a no-op there.
        available = ort.get_available_providers()
        providers = [
            p
            for p in ("CUDAExecutionProvider", "CPUExecutionProvider")
            if p in available
        ]
        self.session = ort.InferenceSession(
            model_path, sess_options=opts, providers=providers
        )
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]
        # Dims are ints when fixed, strings/None when symbolic (dynamic).
        self.input_shape = list(self.session.get_inputs()[0].shape)
        self.output_shape = list(self.session.get_outputs()[0].shape)
        logger.info(
            "ONNX model loaded: %s (inputs=%s, outputs=%s, providers=%s)",
            model_path,
            self.input_name,
            self.output_names,
            self.session.get_providers(),
        )

    def infer(self, iq: np.ndarray) -> np.ndarray:
        """Run inference on IQ data [1, 2, N]. Returns class logits [1, C]."""
        results = self.session.run(None, {self.input_name: iq})
        return results[0]  # class_logits


# ---------------------------------------------------------------------------
# Inference engine
# ---------------------------------------------------------------------------


class InferenceEngine:
    """Wraps backend + class labels for end-to-end classification."""

    def __init__(self, model_path: str, backend: str = "onnx") -> None:
        self.model_path = model_path
        self.class_names, self.metadata_path = _load_metadata(model_path)
        self.backend_name = backend
        self.backend = ONNXBackend(model_path)
        self.total_inferences = 0
        self.total_time = 0.0
        self.input_samples = resolve_input_samples(
            _fixed_dim(getattr(self.backend, "input_shape", None), -1)
        )
        # A symbolic class dimension is checked on the first inference.
        self._classes_checked = False
        n_out = _fixed_dim(getattr(self.backend, "output_shape", None), -1)
        if n_out is not None:
            self._check_class_count(n_out)

    def _check_class_count(self, n_out: int) -> None:
        """Refuse to label outputs with a class list of a different length."""
        self._classes_checked = True
        n_names = len(self.class_names)
        if n_names == n_out:
            return
        if self.metadata_path is not None:
            raise ModelContractError(
                f"Model {self.model_path} outputs {n_out} classes but its"
                f" metadata {self.metadata_path} lists {n_names} class names;"
                " install the model and its metadata file from the same release"
            )
        p = Path(self.model_path)
        raise ModelContractError(
            f"Model {self.model_path} outputs {n_out} classes and has no usable"
            " class-name metadata: expected"
            f' {p.parent / (p.stem + "_metadata.json")} with a "classes" list'
            f" (the built-in list has {n_names} names, so every label would be"
            " wrong)"
        )

    def classify(self, iq: np.ndarray) -> dict:
        """Classify IQ frame [2, N] -> result dict."""
        if iq.ndim == 2:
            iq = iq[np.newaxis, :, :]  # add batch dim [1, 2, N]
        iq = _unit_power(iq.astype(np.float32))

        t0 = time.perf_counter()
        logits = self.backend.infer(iq)
        dt = time.perf_counter() - t0
        if not self._classes_checked:
            self._check_class_count(int(np.shape(logits)[-1]))

        self.total_inferences += 1
        self.total_time += dt

        probs = _softmax(logits[0])
        top_idx = int(np.argmax(probs))
        top_class = (
            self.class_names[top_idx]
            if top_idx < len(self.class_names)
            else f"class_{top_idx}"
        )
        top_conf = float(probs[top_idx])
        family = _class_to_family(top_class)

        return {
            "class": top_class,
            "confidence": round(top_conf, 4),
            "family": family,
            "inference_ms": round(dt * 1000, 2),
            "cls_per_sec": round(1.0 / dt, 1) if dt > 0 else 0,
        }

    @property
    def avg_cls_per_sec(self) -> float:
        if self.total_time == 0:
            return 0.0
        return self.total_inferences / self.total_time


def _unit_power(iq: np.ndarray) -> np.ndarray:
    """Scale each [2, N] window of *iq* [B, 2, N] to mean(I^2 + Q^2) == 1.

    Training normalises every window this way, so feeding receiver-scaled
    samples skews the classes. A window with zero or non-finite power is
    returned unchanged rather than divided by zero. Returns a new array.
    """
    power = np.mean(np.sum(np.square(iq, dtype=np.float64), axis=1), axis=-1)
    ok = np.isfinite(power) & (power > 0)
    scale = np.ones_like(power)
    scale[ok] = 1.0 / np.sqrt(power[ok])
    return (iq * scale[:, np.newaxis, np.newaxis]).astype(np.float32)


def _softmax(x: np.ndarray) -> np.ndarray:
    e = np.exp(x - np.max(x))
    return e / e.sum()


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------


def run_benchmark(engine: InferenceEngine, num_iters: int = 200) -> dict:
    """Run benchmark with random IQ data."""
    logger.info("Running benchmark (%d iterations)...", num_iters)

    # Warmup
    n = engine.input_samples
    dummy = np.random.randn(1, 2, n).astype(np.float32)
    for _ in range(10):
        engine.backend.infer(dummy)

    # Reset counters
    engine.total_inferences = 0
    engine.total_time = 0.0

    latencies = []
    for _ in range(num_iters):
        iq = np.random.randn(2, n).astype(np.float32)
        t0 = time.perf_counter()
        engine.classify(iq)
        latencies.append(time.perf_counter() - t0)

    latencies_ms = [lat * 1000 for lat in latencies]
    result = {
        "iterations": num_iters,
        "total_time_s": round(engine.total_time, 3),
        "avg_cls_per_sec": round(engine.avg_cls_per_sec, 1),
        "avg_latency_ms": round(np.mean(latencies_ms), 2),
        "p50_latency_ms": round(np.percentile(latencies_ms, 50), 2),
        "p95_latency_ms": round(np.percentile(latencies_ms, 95), 2),
        "p99_latency_ms": round(np.percentile(latencies_ms, 99), 2),
    }
    logger.info("Benchmark results: %s", json.dumps(result, indent=2))
    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="SigRift edge inference runner")
    parser.add_argument(
        "--model",
        default=os.environ.get("MLRF_MODEL_PATH", ""),
        help="Path to .onnx model file",
    )
    parser.add_argument(
        "--backend", default="onnx", choices=["onnx"], help="Inference backend"
    )
    parser.add_argument(
        "--benchmark", action="store_true", help="Run benchmark with synthetic data"
    )
    parser.add_argument(
        "--benchmark-iters",
        type=int,
        default=200,
        help="Number of benchmark iterations",
    )
    args = parser.parse_args()

    if not args.model:
        logger.error("--model or MLRF_MODEL_PATH required")
        sys.exit(1)

    backend = args.backend

    logger.info("SigRift edge inference v%s (backend=%s)", VERSION, backend)

    try:
        engine = InferenceEngine(args.model, backend=backend)
    except ModelContractError as e:
        logger.error("Cannot use the model: %s", e)
        sys.exit(1)

    if args.benchmark:
        try:
            results = run_benchmark(engine, args.benchmark_iters)
        except ModelContractError as e:  # a symbolic class dim, checked late
            logger.error("Cannot use the model: %s", e)
            sys.exit(1)
        print(json.dumps(results, indent=2))
        return

    # Continuous inference from stdin (raw IQ float32 interleaved)
    n = engine.input_samples
    logger.info("Reading IQ data from stdin (float32, %d samples/frame)...", n)
    frame_bytes = n * 2 * 4  # 2 channels * 4 bytes per float32
    frame_count = 0

    try:
        while True:
            raw = sys.stdin.buffer.read(frame_bytes)
            if len(raw) < frame_bytes:
                break

            iq = np.frombuffer(raw, dtype=np.float32).reshape(n, 2).T
            result = engine.classify(iq)
            frame_count += 1

            if frame_count % 10 == 0:
                logger.info(
                    "[%d] %s (%.1f%%) family=%s  %.1f cls/sec",
                    frame_count,
                    result["class"],
                    result["confidence"] * 100,
                    result["family"],
                    engine.avg_cls_per_sec,
                )
    except KeyboardInterrupt:
        pass
    except ModelContractError as e:  # a symbolic class dim, checked late
        logger.error("Cannot use the model: %s", e)
        sys.exit(1)

    logger.info(
        "Processed %d frames, avg %.1f cls/sec", frame_count, engine.avg_cls_per_sec
    )


if __name__ == "__main__":
    main()
