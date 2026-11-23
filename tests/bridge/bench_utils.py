"""Benchmarking utilities for The Bridge performance tests.

Provides:
  - BenchmarkTimer: context manager for measuring operation latency
  - LatencyStats: statistical summary of latency measurements
  - LoadGenerator: configurable concurrent load driver
  - ReportFormatter: output results as structured dict and human-readable table
"""

from __future__ import annotations

import math
import os
import platform
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Performance scale configuration
# ---------------------------------------------------------------------------

def get_perf_scale() -> str:
    """Return the performance scale from PERF_SCALE env var.

    Values: 'small' (default), 'medium', 'large'.
    """
    return os.environ.get("PERF_SCALE", "small").lower()


def scale_value(small: int, medium: int, large: int) -> int:
    """Return the appropriate value for the current scale."""
    scale = get_perf_scale()
    if scale == "large":
        return large
    if scale == "medium":
        return medium
    return small


# ---------------------------------------------------------------------------
# BenchmarkTimer
# ---------------------------------------------------------------------------

class BenchmarkTimer:
    """Context manager that records elapsed time with high precision.

    Usage::

        with BenchmarkTimer() as t:
            do_work()
        print(f"Took {t.elapsed:.3f}s")
    """

    def __init__(self) -> None:
        self.start: float = 0.0
        self.end: float = 0.0
        self.elapsed: float = 0.0

    def __enter__(self) -> BenchmarkTimer:
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.end = time.perf_counter()
        self.elapsed = self.end - self.start


# ---------------------------------------------------------------------------
# LatencyStats
# ---------------------------------------------------------------------------

@dataclass
class LatencyStats:
    """Statistical summary of a collection of latency samples (in seconds)."""

    samples: list[float] = field(default_factory=list, repr=False)

    @property
    def count(self) -> int:
        return len(self.samples)

    @property
    def min(self) -> float:
        return builtins_min(self.samples) if self.samples else 0.0

    @property
    def max(self) -> float:
        return builtins_max(self.samples) if self.samples else 0.0

    @property
    def avg(self) -> float:
        return statistics.mean(self.samples) if self.samples else 0.0

    @property
    def p50(self) -> float:
        return self._percentile(50)

    @property
    def p95(self) -> float:
        return self._percentile(95)

    @property
    def p99(self) -> float:
        return self._percentile(99)

    @property
    def std_dev(self) -> float:
        if len(self.samples) < 2:
            return 0.0
        return statistics.stdev(self.samples)

    @property
    def total(self) -> float:
        return sum(self.samples)

    def add(self, sample: float) -> None:
        """Record a single latency sample."""
        self.samples.append(sample)

    def _percentile(self, pct: int) -> float:
        if not self.samples:
            return 0.0
        sorted_s = sorted(self.samples)
        idx = int(math.ceil(pct / 100.0 * len(sorted_s))) - 1
        return sorted_s[max(0, idx)]

    def as_dict(self) -> dict[str, Any]:
        """Return stats as a plain dict."""
        return {
            "count": self.count,
            "min_s": round(self.min, 6),
            "max_s": round(self.max, 6),
            "avg_s": round(self.avg, 6),
            "p50_s": round(self.p50, 6),
            "p95_s": round(self.p95, 6),
            "p99_s": round(self.p99, 6),
            "std_dev_s": round(self.std_dev, 6),
            "total_s": round(self.total, 6),
        }

    def summary_line(self, label: str = "") -> str:
        """One-line summary for console output."""
        prefix = f"{label}: " if label else ""
        return (
            f"{prefix}n={self.count}  "
            f"avg={self.avg * 1000:.1f}ms  "
            f"p50={self.p50 * 1000:.1f}ms  "
            f"p95={self.p95 * 1000:.1f}ms  "
            f"p99={self.p99 * 1000:.1f}ms  "
            f"min={self.min * 1000:.1f}ms  "
            f"max={self.max * 1000:.1f}ms"
        )


# Use builtins to avoid name collision with LatencyStats.min/max
import builtins
builtins_min = builtins.min
builtins_max = builtins.max


# ---------------------------------------------------------------------------
# LoadGenerator
# ---------------------------------------------------------------------------

@dataclass
class LoadResult:
    """Outcome of a single load generator invocation."""

    latency_stats: LatencyStats
    total_requests: int
    successful: int
    failed: int
    errors: list[str]
    elapsed_wall: float
    requests_per_sec: float


class LoadGenerator:
    """Drive concurrent load against a callable target.

    Parameters
    ----------
    concurrency : int
        Number of threads to run in parallel.
    duration_seconds : float
        Maximum wall-clock time to run (0 = run all iterations).
    iterations : int
        Total number of requests to issue (across all threads).
        If duration_seconds > 0, iterations is ignored and the generator
        runs until time expires.
    """

    def __init__(
        self,
        concurrency: int = 1,
        duration_seconds: float = 0,
        iterations: int = 100,
    ) -> None:
        self.concurrency = concurrency
        self.duration_seconds = duration_seconds
        self.iterations = iterations

    def run(self, request_fn: Callable[[], Any]) -> LoadResult:
        """Execute the load test.

        Parameters
        ----------
        request_fn : callable
            A zero-argument function that performs one request.
            Should raise on failure.

        Returns
        -------
        LoadResult
        """
        stats = LatencyStats()
        errors: list[str] = []
        lock = threading.Lock()
        counter = {"done": 0}
        stop_event = threading.Event()

        def _worker() -> None:
            while not stop_event.is_set():
                with lock:
                    if self.duration_seconds <= 0 and counter["done"] >= self.iterations:
                        return
                    counter["done"] += 1

                t0 = time.perf_counter()
                try:
                    request_fn()
                    elapsed = time.perf_counter() - t0
                    with lock:
                        stats.add(elapsed)
                except Exception as exc:
                    elapsed = time.perf_counter() - t0
                    with lock:
                        stats.add(elapsed)
                        errors.append(str(exc)[:200])

        wall_start = time.perf_counter()

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = [pool.submit(_worker) for _ in range(self.concurrency)]

            if self.duration_seconds > 0:
                time.sleep(self.duration_seconds)
                stop_event.set()

            for f in as_completed(futures):
                f.result()  # propagate exceptions

        wall_elapsed = time.perf_counter() - wall_start
        total = stats.count
        rps = total / wall_elapsed if wall_elapsed > 0 else 0

        return LoadResult(
            latency_stats=stats,
            total_requests=total,
            successful=total - len(errors),
            failed=len(errors),
            errors=errors[:20],  # cap stored errors
            elapsed_wall=wall_elapsed,
            requests_per_sec=rps,
        )


# ---------------------------------------------------------------------------
# ReportFormatter
# ---------------------------------------------------------------------------

class ReportFormatter:
    """Accumulates benchmark results and formats them."""

    def __init__(self) -> None:
        self._results: list[dict[str, Any]] = []

    def add_result(
        self,
        test_name: str,
        stats: LatencyStats | None = None,
        load_result: LoadResult | None = None,
        extra: dict[str, Any] | None = None,
        passed: bool = True,
        threshold_label: str = "",
    ) -> None:
        """Record a single test result."""
        entry: dict[str, Any] = {
            "test": test_name,
            "passed": passed,
            "threshold": threshold_label,
        }
        if stats is not None:
            entry["latency"] = stats.as_dict()
        if load_result is not None:
            entry["load"] = {
                "total_requests": load_result.total_requests,
                "successful": load_result.successful,
                "failed": load_result.failed,
                "rps": round(load_result.requests_per_sec, 2),
                "wall_time_s": round(load_result.elapsed_wall, 3),
            }
            entry["latency"] = load_result.latency_stats.as_dict()
        if extra:
            entry["extra"] = extra
        self._results.append(entry)

    def as_dict(self) -> dict[str, Any]:
        """Return full report as structured dict."""
        return {
            "system": _system_info(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "perf_scale": get_perf_scale(),
            "results": self._results,
            "summary": {
                "total": len(self._results),
                "passed": sum(1 for r in self._results if r["passed"]),
                "failed": sum(1 for r in self._results if not r["passed"]),
            },
        }

    def format_table(self) -> str:
        """Format results as a human-readable table."""
        lines = [
            "",
            "=" * 100,
            "PERFORMANCE TEST RESULTS",
            f"Scale: {get_perf_scale()}  |  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "=" * 100,
            f"{'Test':<45} {'Status':<8} {'Avg':>8} {'P95':>8} {'P99':>8} {'RPS':>8} {'Threshold':<20}",
            "-" * 100,
        ]

        for r in self._results:
            status = "PASS" if r["passed"] else "FAIL"
            lat = r.get("latency", {})
            load = r.get("load", {})
            avg_ms = f"{lat.get('avg_s', 0) * 1000:.1f}ms" if lat else "-"
            p95_ms = f"{lat.get('p95_s', 0) * 1000:.1f}ms" if lat else "-"
            p99_ms = f"{lat.get('p99_s', 0) * 1000:.1f}ms" if lat else "-"
            rps = f"{load.get('rps', 0):.1f}" if load else "-"
            lines.append(
                f"{r['test']:<45} {status:<8} {avg_ms:>8} {p95_ms:>8} {p99_ms:>8} {rps:>8} {r.get('threshold', ''):<20}"
            )

        lines.append("=" * 100)
        summary = self.as_dict()["summary"]
        lines.append(
            f"Total: {summary['total']}  |  Passed: {summary['passed']}  |  Failed: {summary['failed']}"
        )
        lines.append("=" * 100)
        return "\n".join(lines)


def _system_info() -> dict[str, Any]:
    """Gather basic system info for the report."""
    return {
        "platform": platform.platform(),
        "python": sys.version,
        "cpu_count": os.cpu_count(),
    }
