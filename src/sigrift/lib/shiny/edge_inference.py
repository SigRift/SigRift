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

Environment variables:
    MLRF_MODEL_PATH
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
INPUT_SAMPLES = 4096  # IQ samples per frame


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
    "ASK": ["ook", "4ask", "8ask", "16ask"],
    "PAM": ["4pam", "8pam", "16pam"],
    "PSK": ["bpsk", "qpsk", "8psk", "16psk", "32psk"],
    "QAM": ["16qam", "32qam", "64qam", "128qam", "256qam"],
    "APSK": ["16apsk", "32apsk", "64apsk", "128apsk"],
    "FSK": ["2fsk", "4fsk", "2gfsk", "4gfsk", "2msk", "4msk", "2gmsk", "4gmsk"],
    "OFDM": ["ofdm-64", "ofdm-128", "ofdm-256", "ofdm-512", "ofdm-1024", "ofdm-2048"],
    "ANALOG": ["am-dsb", "am-ssb", "fm", "tone"],
    "SPREAD_SPECTRUM": ["lora-css"],
    "NOISE": ["noise"],
}


def _class_to_family(cls_name: str) -> str:
    for fam, members in FAMILIES.items():
        if cls_name in members:
            return fam
    return "UNKNOWN"


def load_metadata(model_path: str) -> list[str]:
    """Load class names from metadata JSON if present next to model."""
    meta_path = Path(model_path).parent / "sigrift_edge_metadata.json"
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text())
            names = meta.get("class_names", DEFAULT_CLASSES)
            logger.info("Loaded %d classes from %s", len(names), meta_path)
            return names
        except Exception as e:
            logger.warning("Failed to load metadata: %s", e)
    return DEFAULT_CLASSES


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
        self.session = ort.InferenceSession(model_path, sess_options=opts)
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]
        logger.info(
            "ONNX model loaded: %s (inputs=%s, outputs=%s)",
            model_path,
            self.input_name,
            self.output_names,
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
        self.class_names = load_metadata(model_path)
        self.backend_name = backend
        self.backend = ONNXBackend(model_path)
        self.total_inferences = 0
        self.total_time = 0.0

    def classify(self, iq: np.ndarray) -> dict:
        """Classify IQ frame [2, N] -> result dict."""
        if iq.ndim == 2:
            iq = iq[np.newaxis, :, :]  # add batch dim [1, 2, N]
        iq = iq.astype(np.float32)

        t0 = time.perf_counter()
        logits = self.backend.infer(iq)
        dt = time.perf_counter() - t0

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
    dummy = np.random.randn(1, 2, INPUT_SAMPLES).astype(np.float32)
    for _ in range(10):
        engine.backend.infer(dummy)

    # Reset counters
    engine.total_inferences = 0
    engine.total_time = 0.0

    latencies = []
    for _ in range(num_iters):
        iq = np.random.randn(2, INPUT_SAMPLES).astype(np.float32)
        t0 = time.perf_counter()
        engine.classify(iq)
        latencies.append(time.perf_counter() - t0)

    latencies_ms = [l * 1000 for l in latencies]  # noqa: E741
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

    engine = InferenceEngine(args.model, backend=backend)

    if args.benchmark:
        results = run_benchmark(engine, args.benchmark_iters)
        print(json.dumps(results, indent=2))
        return

    # Continuous inference from stdin (raw IQ float32 interleaved)
    logger.info(
        "Reading IQ data from stdin (float32, %d samples/frame)...", INPUT_SAMPLES
    )
    frame_bytes = INPUT_SAMPLES * 2 * 4  # 2 channels * 4 bytes per float32
    frame_count = 0

    try:
        while True:
            raw = sys.stdin.buffer.read(frame_bytes)
            if len(raw) < frame_bytes:
                break

            iq = np.frombuffer(raw, dtype=np.float32).reshape(INPUT_SAMPLES, 2).T
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

    logger.info(
        "Processed %d frames, avg %.1f cls/sec", frame_count, engine.avg_cls_per_sec
    )


if __name__ == "__main__":
    main()
