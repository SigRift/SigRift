"""Behavioral checks for the authored benchmark helper (without a server)."""

from datetime import datetime, timezone
import math
import os
import platform
import sys
import threading
import time

import pytest

from tests.bridge.bench_utils import (
    BenchmarkTimer,
    LatencyStats,
    LoadGenerator,
    LoadResult,
    ReportFormatter,
    get_perf_scale,
    scale_value,
)


@pytest.mark.parametrize(
    ("setting", "scale", "value"),
    [
        (None, "small", 10),
        ("MeDiUm", "medium", 100),
        ("LARGE", "large", 1000),
        ("unknown", "unknown", 10),
    ],
)
def test_scale_uses_environment_with_small_default(monkeypatch, setting, scale, value):
    if setting is None:
        monkeypatch.delenv("PERF_SCALE", raising=False)
    else:
        monkeypatch.setenv("PERF_SCALE", setting)
    assert get_perf_scale() == scale
    assert scale_value(10, 100, 1000) == value


@pytest.mark.parametrize("raises", [False, True])
def test_timer_measures_real_work_and_preserves_exceptions(raises):
    timer = BenchmarkTimer()
    assert (timer.start, timer.end, timer.elapsed) == (0, 0, 0)
    failure = ValueError("operation failed")
    before = time.perf_counter()
    try:
        with timer as active:
            assert active is timer
            threading.Event().wait(0.005)
            if raises:
                raise failure
    except ValueError as caught:
        assert raises and caught is failure
    else:
        assert not raises
    after = time.perf_counter()
    assert before <= timer.start < timer.end <= after
    assert timer.elapsed == timer.end - timer.start
    assert timer.elapsed >= 0.005


def test_empty_and_single_latency_sample_have_defined_statistics():
    stats = LatencyStats()
    assert stats.as_dict() == {
        "count": 0,
        "min_s": 0,
        "max_s": 0,
        "avg_s": 0,
        "p50_s": 0,
        "p95_s": 0,
        "p99_s": 0,
        "std_dev_s": 0,
        "total_s": 0,
    }
    assert stats.summary_line() == (
        "n=0  avg=0.0ms  p50=0.0ms  p95=0.0ms  p99=0.0ms  min=0.0ms  max=0.0ms"
    )
    stats.add(0.01234567)
    assert stats.count == 1
    assert stats.min == stats.max == stats.avg == stats.p50 == stats.p95 == stats.p99
    assert stats.total == 0.01234567
    assert stats.std_dev == 0
    assert stats.as_dict()["avg_s"] == 0.012346
    # Each instance owns its sample list.
    assert LatencyStats().samples == []


def test_nearest_rank_percentiles_and_sample_deviation_use_independent_oracles():
    # Each value 1..100 milliseconds occurs once, deliberately out of order.
    # Nearest rank gives 50,95,99ms; the sample variance is n*(n+1)/12 ms².
    samples = [n / 1000 for n in range(100, 0, -1)]
    original_order = samples.copy()
    stats = LatencyStats(samples)
    assert stats.count == 100
    assert stats.min == 0.001 and stats.max == 0.1
    assert stats.avg == pytest.approx(0.0505)
    assert (stats.p50, stats.p95, stats.p99) == (0.050, 0.095, 0.099)
    assert stats.std_dev == pytest.approx(math.sqrt(100 * 101 / 12) / 1000)
    assert stats.total == pytest.approx(5.05)
    assert stats.samples == original_order  # Queries do not sort caller data.
    assert stats.summary_line("read") == (
        "read: n=100  avg=50.5ms  p50=50.0ms  p95=95.0ms  p99=99.0ms  min=1.0ms  max=100.0ms"
    )
    assert stats.as_dict() == {
        "count": 100,
        "min_s": 0.001,
        "max_s": 0.1,
        "avg_s": 0.0505,
        "p50_s": 0.05,
        "p95_s": 0.095,
        "p99_s": 0.099,
        "std_dev_s": 0.029011,
        "total_s": 5.05,
    }


def check_load_accounting(result, count, failed):
    assert isinstance(result, LoadResult)
    assert result.total_requests == result.latency_stats.count == count
    assert result.failed == failed
    assert result.successful == count - failed
    assert result.elapsed_wall > 0
    assert result.requests_per_sec == pytest.approx(count / result.elapsed_wall)
    assert all(sample > 0 for sample in result.latency_stats.samples)


@pytest.mark.parametrize("workers", [1, 4])
def test_fixed_load_runs_each_request_once_and_joins_real_workers(workers):
    lock = threading.Lock()
    barrier = threading.Barrier(workers, timeout=3)
    worker_threads = set()
    calls, completed = [], []
    active = peak = 0

    def operation():
        nonlocal active, peak
        with lock:
            index = len(calls)
            calls.append(index)
            worker_threads.add(threading.current_thread())
            active += 1
            peak = max(peak, active)
        try:
            if index < workers:
                barrier.wait()
            threading.Event().wait(0.002)
            if index % 3 == 0:
                raise ValueError(f"rejected-{index}")
        finally:
            with lock:
                active -= 1
                completed.append(index)

    result = LoadGenerator(concurrency=workers, iterations=12).run(operation)
    check_load_accounting(result, 12, 4)
    assert calls == list(range(12)) and sorted(completed) == calls
    assert set(result.errors) == {f"rejected-{n}" for n in (0, 3, 6, 9)}
    assert active == 0 and peak == workers
    assert len(worker_threads) == workers
    assert all(not thread.is_alive() for thread in worker_threads)


def test_error_report_caps_details_without_losing_failed_request_count():
    detail = "denied:" + "x" * 250

    def fail():
        raise RuntimeError(detail)

    result = LoadGenerator(concurrency=3, iterations=27).run(fail)
    check_load_accounting(result, 27, 27)
    assert result.errors == [detail[:200]] * 20


def test_zero_iterations_never_calls_target():
    def forbidden():
        pytest.fail("A zero-iteration load called the target")

    result = LoadGenerator(concurrency=2, iterations=0).run(forbidden)
    check_load_accounting(result, 0, 0)
    assert result.errors == [] and result.requests_per_sec == 0


def test_duration_load_ignores_iterations_and_joins_inflight_requests():
    lock = threading.Lock()
    threads = set()
    calls = completed = 0

    def operation():
        nonlocal calls, completed
        with lock:
            calls += 1
            threads.add(threading.current_thread())
        threading.Event().wait(0.004)
        with lock:
            completed += 1

    before = time.perf_counter()
    result = LoadGenerator(concurrency=2, duration_seconds=0.06, iterations=1).run(
        operation
    )
    after = time.perf_counter()
    check_load_accounting(result, calls, 0)
    assert completed == calls and calls > 1
    assert result.errors == []
    assert 0.06 <= result.elapsed_wall <= after - before
    assert threads and all(not thread.is_alive() for thread in threads)


def test_uncaught_worker_failure_propagates_after_other_workers_join():
    class WorkerAbort(BaseException):
        pass

    lock = threading.Lock()
    barrier = threading.Barrier(2, timeout=3)
    threads = set()
    calls, completed = [], []
    failure = WorkerAbort("stop worker")

    def operation():
        with lock:
            index = len(calls)
            calls.append(index)
            threads.add(threading.current_thread())
        try:
            if index < 2:
                barrier.wait()
            if index == 0:
                raise failure
            threading.Event().wait(0.002)
        finally:
            with lock:
                completed.append(index)

    with pytest.raises(WorkerAbort) as caught:
        LoadGenerator(concurrency=2, iterations=6).run(operation)
    assert caught.value is failure
    assert calls == list(range(6)) and sorted(completed) == calls
    assert len(threads) == 2 and all(not thread.is_alive() for thread in threads)


def test_invalid_worker_count_fails_without_calling_target():
    def forbidden():
        pytest.fail("Invalid executor configuration called the target")

    with pytest.raises(ValueError, match="max_workers"):
        LoadGenerator(concurrency=0).run(forbidden)


def test_report_formats_mixed_outcomes_and_real_system_metadata(monkeypatch):
    monkeypatch.setenv("PERF_SCALE", "medium")
    report = ReportFormatter()
    empty = report.as_dict()
    assert empty["summary"] == {"total": 0, "passed": 0, "failed": 0}
    assert empty["results"] == []
    assert "Total: 0  |  Passed: 0  |  Failed: 0" in report.format_table()

    stats = LatencyStats([0.001, 0.003])
    load_stats = LatencyStats([0.002, 0.004, 0.006])
    load = LoadResult(load_stats, 3, 2, 1, ["denied"], 0.123456, 24.300156)
    report.add_result("metadata-only", extra={}, threshold_label="configuration")
    report.add_result("read", stats=stats, threshold_label="p95 < 5ms")
    report.add_result(
        "load",
        stats=stats,
        load_result=load,
        extra={"workers": 2},
        passed=False,
        threshold_label="no errors",
    )
    before = datetime.now(timezone.utc)
    data = report.as_dict()
    after = datetime.now(timezone.utc)
    assert before <= datetime.fromisoformat(data["timestamp"]) <= after
    assert data["system"] == {
        "platform": platform.platform(),
        "python": sys.version,
        "cpu_count": os.cpu_count(),
    }
    assert data["perf_scale"] == "medium"
    assert data["summary"] == {"total": 3, "passed": 2, "failed": 1}
    assert data["results"] == [
        {"test": "metadata-only", "passed": True, "threshold": "configuration"},
        {
            "test": "read",
            "passed": True,
            "threshold": "p95 < 5ms",
            "latency": stats.as_dict(),
        },
        {
            "test": "load",
            "passed": False,
            "threshold": "no errors",
            "latency": load_stats.as_dict(),
            "extra": {"workers": 2},
            "load": {
                "total_requests": 3,
                "successful": 2,
                "failed": 1,
                "rps": 24.3,
                "wall_time_s": 0.123,
            },
        },
    ]
    lines = report.format_table().splitlines()
    assert "PERFORMANCE TEST RESULTS" in lines
    assert any(
        line.startswith("Scale: medium  |  ") and line.endswith(" UTC")
        for line in lines
    )
    rows = {
        line.split()[0]: line.split()[1:]
        for line in lines
        if line.split() and line.split()[0] in {"metadata-only", "read", "load"}
    }
    assert rows == {
        "metadata-only": ["PASS", "-", "-", "-", "-", "configuration"],
        "read": ["PASS", "2.0ms", "3.0ms", "3.0ms", "-", "p95", "<", "5ms"],
        "load": ["FAIL", "4.0ms", "6.0ms", "6.0ms", "24.3", "no", "errors"],
    }
    assert "Total: 3  |  Passed: 2  |  Failed: 1" in lines
