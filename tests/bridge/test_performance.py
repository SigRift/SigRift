"""Performance and load tests for The Bridge.

Run with::

    pytest -m performance sigrift/bridge/tests/test_performance.py -v
    PERF_SCALE=medium pytest -m performance sigrift/bridge/tests/test_performance.py -v
    PERF_SCALE=large pytest -m performance sigrift/bridge/tests/test_performance.py -v

Scale levels:
  - small (default): quick smoke tests (~seconds)
  - medium: moderate load (~30s)
  - large: full stress test (~minutes)

Tests PASS/FAIL based on latency and throughput thresholds.
"""

from __future__ import annotations

import asyncio
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.cache import TTLCache
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionQuery
from sigrift.bridge.state import AppState, WebSocketClientSet
from sigrift.bridge.tests.bench_utils import (
    BenchmarkTimer,
    LatencyStats,
    LoadGenerator,
    ReportFormatter,
    get_perf_scale,
    scale_value,
)
from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_report = ReportFormatter()

def _batch_payload(node_id: str, n: int, offset: int = 0) -> dict:
    """Build a batch ingest payload with *n* detections."""
    now = datetime.now(timezone.utc)
    return {
        "node_id": node_id,
        "period_start": (now - timedelta(minutes=10)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "node_id": node_id,
                "signal_class": "bpsk",
                "confidence": 0.90 + (i % 10) * 0.01,
                "family": "psk",
                "freq_hz": 433.92e6 + (offset + i) * 1000,
                "snr_db": 12.0 + i % 20,
            }
            for i in range(n)
        ],
    }

def _seed_detections(client: TestClient, node_id: str, count: int, batch_size: int = 500) -> int:
    """Seed the database with *count* detections. Returns actual inserted count."""
    inserted = 0
    offset = 0
    while inserted < count:
        n = min(batch_size, count - inserted)
        payload = _batch_payload(node_id, n, offset=offset)
        resp = client.post("/api/detections/batch", json=payload)
        if resp.status_code == 201:
            inserted += resp.json().get("inserted", 0)
        offset += n
    return inserted

# ---------------------------------------------------------------------------
# Session-scoped report printer
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _print_report():
    """Print the performance report after all tests in this module."""
    yield
    table = _report.format_table()
    print(table)

# ---------------------------------------------------------------------------
# Detection Ingestion Throughput
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestBatchIngestThroughput:
    """Batch detection ingest throughput at various batch sizes."""

    @pytest.mark.parametrize("batch_size", [10, 100, 500, 1000])
    def test_batch_ingest_sizes(self, client: TestClient, registered_node: str, batch_size: int) -> None:
        """Ingesting a batch should complete within time proportional to size."""
        # Skip large batches on small scale
        if batch_size > 100 and get_perf_scale() == "small":
            pytest.skip("Large batch sizes skipped on small scale")

        payload = _batch_payload(registered_node, batch_size)
        stats = LatencyStats()
        iterations = scale_value(3, 10, 30)

        for _ in range(iterations):
            with BenchmarkTimer() as t:
                resp = client.post("/api/detections/batch", json=payload)
            assert resp.status_code == 201
            assert resp.json()["inserted"] == batch_size
            stats.add(t.elapsed)

        # Threshold: avg < 50ms per detection
        max_avg = batch_size * 0.05
        passed = stats.avg < max_avg
        _report.add_result(
            f"batch_ingest_{batch_size}",
            stats=stats,
            passed=passed,
            threshold_label=f"avg < {max_avg:.1f}s",
        )
        assert passed, (
            f"Batch ingest {batch_size}: avg {stats.avg:.3f}s exceeds {max_avg:.1f}s\n"
            f"{stats.summary_line()}"
        )

    @pytest.mark.parametrize("concurrency", [1, 3, 5])
    def test_concurrent_ingest(self, client: TestClient, bridge_app: FastAPI, master_key: str, registered_node: str, concurrency: int) -> None:
        """Multiple edge nodes ingesting concurrently."""
        if concurrency > 3 and get_perf_scale() == "small":
            pytest.skip("High concurrency skipped on small scale")

        batch_size = 50
        iterations = scale_value(10, 50, 200)

        def _do_request() -> None:
            # Each thread needs its own TestClient
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            payload = _batch_payload(registered_node, batch_size)
            resp = tc.post("/api/detections/batch", json=payload)
            if resp.status_code != 201:
                raise RuntimeError(f"Status {resp.status_code}: {resp.text[:200]}")

        gen = LoadGenerator(concurrency=concurrency, iterations=iterations)
        result = gen.run(_do_request)

        # No errors allowed
        error_rate = result.failed / result.total_requests if result.total_requests else 0
        passed = error_rate < 0.01  # <1% error rate

        _report.add_result(
            f"concurrent_ingest_c{concurrency}",
            load_result=result,
            passed=passed,
            threshold_label="error_rate < 1%",
            extra={"concurrency": concurrency, "batch_size": batch_size},
        )
        assert passed, (
            f"Concurrent ingest c={concurrency}: {result.failed}/{result.total_requests} failures "
            f"({error_rate * 100:.1f}%)\nErrors: {result.errors[:5]}"
        )

    def test_sustained_throughput(self, client: TestClient, bridge_app: FastAPI, master_key: str, registered_node: str) -> None:
        """Sustain 100 detections/sec for a configurable duration without errors."""
        duration = scale_value(5, 30, 60)
        batch_size = 100  # 1 batch/sec = 100 det/sec
        errors: list[str] = []
        stats = LatencyStats()
        batches_sent = 0

        t_end = time.perf_counter() + duration
        while time.perf_counter() < t_end:
            payload = _batch_payload(registered_node, batch_size, offset=batches_sent * batch_size)
            with BenchmarkTimer() as t:
                resp = client.post("/api/detections/batch", json=payload)
            stats.add(t.elapsed)
            if resp.status_code != 201:
                errors.append(f"Status {resp.status_code}")
            batches_sent += 1

            # Pace to roughly 1 batch/sec
            sleep_time = 1.0 - t.elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

        total_det = batches_sent * batch_size
        det_per_sec = total_det / duration if duration > 0 else 0
        passed = len(errors) == 0 and det_per_sec >= 80  # allow some slack

        _report.add_result(
            "sustained_100det_per_sec",
            stats=stats,
            passed=passed,
            threshold_label=">= 80 det/s, 0 errors",
            extra={
                "duration_s": duration,
                "batches_sent": batches_sent,
                "total_detections": total_det,
                "det_per_sec": round(det_per_sec, 1),
                "errors": len(errors),
            },
        )
        assert passed, (
            f"Sustained throughput: {det_per_sec:.1f} det/s (target >= 80), "
            f"{len(errors)} errors over {duration}s"
        )

# ---------------------------------------------------------------------------
# Query Latency Under Load
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestQueryLatency:
    """Query latency with pre-populated database."""

    @pytest.fixture(autouse=True)
    def _seed_data(self, client: TestClient, registered_node: str) -> None:
        """Pre-populate database for query tests."""
        count = scale_value(1_000, 10_000, 50_000)
        _seed_detections(client, registered_node, count)

    @pytest.mark.parametrize("endpoint,method,payload", [
        ("/api/detections/recent?minutes=60&limit=100", "GET", None),
        ("/api/detections/query", "POST", {"limit": 100}),
        ("/api/detections/timeline?hours=24", "GET", None),
        ("/api/detections/stats?hours=24", "GET", None),
        ("/api/detections/heatmap?hours=24", "GET", None),
        ("/api/detections/count", "GET", None),
        ("/api/detections/distribution?hours=24", "GET", None),
    ])
    def test_query_latency(
        self, client: TestClient, endpoint: str, method: str, payload: dict | None,
    ) -> None:
        """Individual query endpoint latency."""
        stats = LatencyStats()
        iterations = scale_value(5, 20, 50)

        for _ in range(iterations):
            with BenchmarkTimer() as t:
                if method == "GET":
                    resp = client.get(endpoint)
                else:
                    resp = client.post(endpoint, json=payload or {})
            assert resp.status_code == 200, f"{endpoint} returned {resp.status_code}"
            stats.add(t.elapsed)

        # p95 < 500ms for all query endpoints
        threshold_s = 0.5
        passed = stats.p95 < threshold_s
        short_name = endpoint.split("?")[0].split("/")[-1]

        _report.add_result(
            f"query_{short_name}",
            stats=stats,
            passed=passed,
            threshold_label=f"p95 < {threshold_s * 1000:.0f}ms",
        )
        assert passed, (
            f"Query {short_name}: p95={stats.p95 * 1000:.1f}ms exceeds {threshold_s * 1000:.0f}ms\n"
            f"{stats.summary_line()}"
        )

    def test_query_during_active_ingest(
        self, client: TestClient, bridge_app: FastAPI, master_key: str, registered_node: str,
    ) -> None:
        """Query latency while ingestion is happening concurrently."""
        duration = scale_value(3, 10, 30)
        ingest_errors: list[str] = []
        query_stats = LatencyStats()
        stop_event = threading.Event()

        def _ingest_loop() -> None:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            i = 0
            while not stop_event.is_set():
                payload = _batch_payload(registered_node, 50, offset=100_000 + i * 50)
                resp = tc.post("/api/detections/batch", json=payload)
                if resp.status_code != 201:
                    ingest_errors.append(f"Status {resp.status_code}")
                i += 1
                time.sleep(0.1)

        # Start background ingest
        ingest_thread = threading.Thread(target=_ingest_loop, daemon=True)
        ingest_thread.start()

        try:
            t_end = time.perf_counter() + duration
            while time.perf_counter() < t_end:
                with BenchmarkTimer() as t:
                    resp = client.get("/api/detections/recent?minutes=60&limit=100")
                if resp.status_code == 200:
                    query_stats.add(t.elapsed)
                time.sleep(0.2)
        finally:
            stop_event.set()
            ingest_thread.join(timeout=5)

        threshold_s = 1.0  # More lenient during concurrent writes
        passed = query_stats.p95 < threshold_s and len(ingest_errors) == 0

        _report.add_result(
            "query_during_ingest",
            stats=query_stats,
            passed=passed,
            threshold_label=f"p95 < {threshold_s * 1000:.0f}ms",
            extra={"ingest_errors": len(ingest_errors)},
        )
        assert passed, (
            f"Query during ingest: p95={query_stats.p95 * 1000:.1f}ms, "
            f"ingest_errors={len(ingest_errors)}\n{query_stats.summary_line()}"
        )

# ---------------------------------------------------------------------------
# WebSocket Broadcast Latency
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestWebSocketBroadcast:
    """WebSocket broadcast latency tests.

    Uses the async _broadcast_detections helper directly (same pattern as
    the existing test_ws_broadcast.py) because the synchronous TestClient
    cannot mix HTTP POST and WS receive across threads reliably.
    """

    def test_ws_broadcast_latency_single(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Measure broadcast latency for a single WS client (baseline)."""
        from sigrift.bridge.routers.detections import _broadcast_detections

        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "type": "batch",
            "node_id": "node-test-01",
            "batch_id": "perf-test",
            "count": 10,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        stats = LatencyStats()
        iterations = scale_value(10, 50, 100)

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                for _ in range(iterations):
                    send_time = time.perf_counter()

                    future = tc.portal.start_task_soon(
                        _broadcast_detections, app_state, broadcast_payload,
                    )

                    data = ws.receive_json()
                    recv_time = time.perf_counter()
                    future.result(timeout=5.0)

                    stats.add(recv_time - send_time)
                    assert data["type"] == "batch"

        threshold_s = 0.1  # 100ms
        passed = stats.p95 < threshold_s

        _report.add_result(
            "ws_broadcast_1client",
            stats=stats,
            passed=passed,
            threshold_label="p95 < 100ms",
        )
        assert passed, (
            f"WS broadcast 1 client: p95={stats.p95 * 1000:.1f}ms\n"
            f"{stats.summary_line()}"
        )

    def test_ws_broadcast_repeated(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Measure broadcast latency over multiple sends to a single client.

        Uses a moderate iteration count to avoid hitting internal TestClient
        buffering limits with the synchronous WS transport.
        """
        from sigrift.bridge.routers.detections import _broadcast_detections

        app_state: AppState = bridge_app.state.app_state
        # Keep iteration count modest -- the synchronous TestClient WS transport
        # can stall on high-volume sends (not a server-side issue).
        iterations = scale_value(10, 25, 50)
        stats = LatencyStats()

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                for i in range(iterations):
                    payload = {
                        "type": "batch",
                        "node_id": "node-test-01",
                        "batch_id": f"perf-{i}",
                        "count": 10,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                    send_time = time.perf_counter()

                    future = tc.portal.start_task_soon(
                        _broadcast_detections, app_state, payload,
                    )
                    data = ws.receive_json()
                    recv_time = time.perf_counter()
                    future.result(timeout=5.0)

                    stats.add(recv_time - send_time)
                    assert data["batch_id"] == f"perf-{i}"

        # p95 broadcast latency < 100ms
        threshold_s = 0.1
        passed = stats.p95 < threshold_s

        _report.add_result(
            f"ws_broadcast_repeated_{iterations}msgs",
            stats=stats,
            passed=passed,
            threshold_label="p95 < 100ms",
            extra={
                "messages": iterations,
                "msgs_per_sec": round(iterations / stats.total, 1) if stats.total > 0 else 0,
            },
        )
        assert passed, (
            f"WS broadcast repeated: p95={stats.p95 * 1000:.1f}ms\n"
            f"{stats.summary_line()}"
        )

# ---------------------------------------------------------------------------
# SQLite Contention
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestSQLiteContention:
    """Concurrent reader/writer contention tests."""

    def test_no_database_locked_errors(
        self, bridge_app: FastAPI, master_key: str, registered_node: str,
    ) -> None:
        """Concurrent writers + readers should not produce database locked errors."""
        duration = scale_value(3, 15, 60)
        writer_count = scale_value(2, 5, 10)
        reader_count = scale_value(2, 5, 10)

        write_errors: list[str] = []
        read_errors: list[str] = []
        write_stats = LatencyStats()
        read_stats = LatencyStats()
        stop_event = threading.Event()
        lock = threading.Lock()

        def _writer(idx: int) -> None:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            i = 0
            while not stop_event.is_set():
                payload = _batch_payload(registered_node, 20, offset=idx * 100_000 + i * 20)
                t0 = time.perf_counter()
                resp = tc.post("/api/detections/batch", json=payload)
                elapsed = time.perf_counter() - t0
                with lock:
                    write_stats.add(elapsed)
                    if resp.status_code != 201:
                        write_errors.append(f"w{idx}: status={resp.status_code} {resp.text[:100]}")
                i += 1
                time.sleep(0.05)

        def _reader(idx: int) -> None:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            while not stop_event.is_set():
                t0 = time.perf_counter()
                resp = tc.get("/api/detections/recent?minutes=60&limit=50")
                elapsed = time.perf_counter() - t0
                with lock:
                    read_stats.add(elapsed)
                    if resp.status_code != 200:
                        read_errors.append(f"r{idx}: status={resp.status_code} {resp.text[:100]}")
                time.sleep(0.1)

        threads = []
        for i in range(writer_count):
            t = threading.Thread(target=_writer, args=(i,), daemon=True)
            t.start()
            threads.append(t)
        for i in range(reader_count):
            t = threading.Thread(target=_reader, args=(i,), daemon=True)
            t.start()
            threads.append(t)

        time.sleep(duration)
        stop_event.set()
        for t in threads:
            t.join(timeout=5)

        # Check for "database is locked" errors specifically
        locked_errors = [e for e in write_errors + read_errors if "locked" in e.lower()]
        passed = len(locked_errors) == 0

        _report.add_result(
            f"sqlite_contention_w{writer_count}_r{reader_count}",
            passed=passed,
            threshold_label="0 locked errors",
            extra={
                "writers": writer_count,
                "readers": reader_count,
                "duration_s": duration,
                "write_requests": write_stats.count,
                "read_requests": read_stats.count,
                "write_errors": len(write_errors),
                "read_errors": len(read_errors),
                "locked_errors": len(locked_errors),
                "write_avg_ms": round(write_stats.avg * 1000, 1),
                "read_avg_ms": round(read_stats.avg * 1000, 1),
            },
        )
        assert passed, (
            f"SQLite contention: {len(locked_errors)} locked errors out of "
            f"{write_stats.count} writes + {read_stats.count} reads\n"
            f"Write errors: {write_errors[:5]}\n"
            f"Read errors: {read_errors[:5]}"
        )

# ---------------------------------------------------------------------------
# API Endpoint Stress
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestEndpointStress:
    """Stress test all major endpoints with increasing concurrency."""

    @pytest.fixture(autouse=True)
    def _seed(self, client: TestClient, registered_node: str) -> None:
        _seed_detections(client, registered_node, scale_value(200, 2000, 10000))

    ENDPOINTS = [
        ("GET", "/api/detections/recent?minutes=60&limit=50"),
        ("POST", "/api/detections/query"),
        ("GET", "/api/detections/stats?hours=24"),
        ("GET", "/api/detections/timeline?hours=24"),
        ("GET", "/api/detections/heatmap?hours=24"),
        ("GET", "/api/detections/count"),
        ("GET", "/api/detections/distribution?hours=24"),
    ]

    @pytest.mark.parametrize("concurrency", [1, 5, 10, 20])
    def test_stress_sweep(
        self, bridge_app: FastAPI, master_key: str, concurrency: int,
    ) -> None:
        """Hit all endpoints at increasing concurrency levels."""
        if concurrency > 10 and get_perf_scale() == "small":
            pytest.skip("High concurrency skipped on small scale")

        iterations = scale_value(20, 100, 500)
        endpoint_idx = {"i": 0}
        lock = threading.Lock()

        def _do_request() -> None:
            with lock:
                idx = endpoint_idx["i"] % len(self.ENDPOINTS)
                endpoint_idx["i"] += 1
            method, url = self.ENDPOINTS[idx]
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            if method == "GET":
                resp = tc.get(url)
            else:
                resp = tc.post(url, json={})
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"{method} {url} -> {resp.status_code}")

        gen = LoadGenerator(concurrency=concurrency, iterations=iterations)
        result = gen.run(_do_request)

        error_rate = result.failed / result.total_requests if result.total_requests else 0
        passed = error_rate < 0.05  # < 5% error rate

        _report.add_result(
            f"stress_c{concurrency}",
            load_result=result,
            passed=passed,
            threshold_label="error_rate < 5%",
            extra={
                "concurrency": concurrency,
                "error_rate_pct": round(error_rate * 100, 2),
            },
        )
        assert passed, (
            f"Stress c={concurrency}: error_rate={error_rate * 100:.1f}%  "
            f"({result.failed}/{result.total_requests})\nErrors: {result.errors[:5]}"
        )

# ---------------------------------------------------------------------------
# Anomaly Scoring Performance
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestAnomalyScoring:
    """Anomaly scoring latency."""

    def test_score_single_detection(self) -> None:
        """Scoring a single detection should complete in under 1 second."""
        baseline_mgr = BaselineManager()
        scorer = AnomalyScorer(baseline_mgr)

        det = {
            "signal_class": "bpsk",
            "confidence": 0.95,
            "freq_hz": 433.92e6,
            "snr_db": 15.0,
        }

        stats = LatencyStats()
        for _ in range(100):
            with BenchmarkTimer() as t:
                scorer.score(det)
            stats.add(t.elapsed)

        passed = stats.p95 < 0.01  # 10ms per score
        _report.add_result(
            "anomaly_score_single",
            stats=stats,
            passed=passed,
            threshold_label="p95 < 10ms",
        )
        assert passed, f"Anomaly scoring: {stats.summary_line()}"

# ---------------------------------------------------------------------------
# Cache Performance
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestCachePerformance:
    """Cache get/set throughput."""

    def test_cache_throughput(self) -> None:
        """1000 get/set operations should complete in under 2 seconds."""
        cache = TTLCache(max_entries=512)

        stats = LatencyStats()
        for i in range(1000):
            key = f"test_key_{i}"
            with BenchmarkTimer() as t:
                cache.put(key, {"data": i}, ttl=60.0)
                cache.get(key)
            stats.add(t.elapsed)

        passed = stats.total < 2.0
        _report.add_result(
            "cache_1000_ops",
            stats=stats,
            passed=passed,
            threshold_label="total < 2s",
            extra={"ops": 1000, "ops_per_sec": round(1000 / stats.total, 1) if stats.total > 0 else 0},
        )
        assert passed, f"Cache ops: total={stats.total:.2f}s (limit 2s)"

# ===========================================================================
# Sprint 8 Phase 3 — Direct-store performance benchmarks
# ===========================================================================

@pytest.fixture
def perf_store(tmp_path: Path) -> DetectionStore:
    """On-disk DetectionStore for direct-store performance benchmarks."""
    return DetectionStore(db_path=tmp_path / "perf_direct.db")

# ---------------------------------------------------------------------------
# S8P3-1. Detection insert throughput (direct store, target >5000/sec)
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
@pytest.mark.performance
class TestDirectInsertThroughput:
    """Benchmark insert_batch called directly on DetectionStore."""

    def test_insert_10k_via_store(self, perf_store: DetectionStore) -> None:
        """Insert 10,000 detections via insert_batch; target > 5000/sec."""
        now = datetime.now(timezone.utc)
        detections = [
            make_detection(
                node_id=f"node-{i % 10:02d}",
                signal_class=["bpsk", "qpsk", "ofdm", "gmsk", "fsk"][i % 5],
                confidence=0.7 + (i % 30) * 0.01,
                family=["psk", "psk", "ofdm", "fsk", "fsk"][i % 5],
                freq_hz=[433.92e6, 915e6, 2.4e9, 868e6, 162.4e6][i % 5],
                snr_db=10.0 + (i % 20),
                anomaly_score=min(1.0, (i % 100) / 200.0),
                timestamp=now - timedelta(seconds=i),
            )
            for i in range(10_000)
        ]

        start = time.perf_counter()
        inserted = perf_store.insert_batch(detections)
        elapsed = time.perf_counter() - start

        throughput = inserted / elapsed if elapsed > 0 else float("inf")
        print(f"\n[S8P3] Direct insert throughput: {throughput:,.0f} detections/sec "
              f"({inserted} in {elapsed:.3f}s)")

        assert inserted == 10_000
        assert throughput > 5_000, (
            f"Insert throughput {throughput:.0f}/sec below 5000/sec target"
        )

# ---------------------------------------------------------------------------
# S8P3-2. Query latency (direct store, target <50ms per query on 100K rows)
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
@pytest.mark.performance
class TestDirectQueryLatency:
    """Benchmark query performance against DetectionStore directly."""

    @pytest.fixture(autouse=True)
    def _populate(self, perf_store: DetectionStore) -> None:
        """Pre-populate with 100K rows for direct query benchmarks."""
        now = datetime.now(timezone.utc)
        batch_size = 10_000
        total = 100_000
        for batch_start in range(0, total, batch_size):
            detections = [
                make_detection(
                    node_id=f"node-{i % 20:02d}",
                    signal_class=["bpsk", "qpsk", "ofdm", "gmsk", "fsk",
                                  "qam16", "8psk", "fm", "am", "ook"][i % 10],
                    confidence=0.6 + (i % 40) * 0.01,
                    family=["psk", "psk", "ofdm", "fsk", "fsk",
                            "qam", "psk", "analog", "analog", "digital"][i % 10],
                    freq_hz=[433.92e6, 915e6, 2.4e9, 868e6, 162.4e6,
                             5.8e9, 1.09e9, 88.1e6, 1.0e6, 315e6][i % 10],
                    snr_db=5.0 + (i % 30),
                    anomaly_score=min(1.0, (i % 100) / 200.0),
                    timestamp=now - timedelta(seconds=i),
                )
                for i in range(batch_start, batch_start + batch_size)
            ]
            perf_store.insert_batch(detections)
        self.store = perf_store

    def test_get_recent_latency(self) -> None:
        """get_recent < 50ms on 100K rows."""
        self.store._cache.invalidate()

        start = time.perf_counter()
        results = self.store.get_recent(minutes=5, limit=100)
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(f"\n[S8P3] get_recent: {elapsed_ms:.1f}ms ({len(results)} rows)")
        assert elapsed_ms < 50, (
            f"get_recent took {elapsed_ms:.1f}ms, exceeds 50ms target"
        )

    def test_query_by_signal_class_latency(self) -> None:
        """Query by signal_class < 50ms on 100K rows."""
        self.store._cache.invalidate()

        start = time.perf_counter()
        results = self.store.query(DetectionQuery(signal_class="ofdm", limit=100))
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(f"\n[S8P3] query(signal_class=ofdm): {elapsed_ms:.1f}ms ({len(results)} rows)")
        assert elapsed_ms < 50, (
            f"Query by signal_class took {elapsed_ms:.1f}ms, exceeds 50ms target"
        )

    def test_query_by_node_id_latency(self) -> None:
        """Query by node_id < 50ms on 100K rows."""
        self.store._cache.invalidate()

        start = time.perf_counter()
        results = self.store.query(DetectionQuery(node_id="node-05", limit=100))
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(f"\n[S8P3] query(node_id=node-05): {elapsed_ms:.1f}ms ({len(results)} rows)")
        assert elapsed_ms < 50, (
            f"Query by node_id took {elapsed_ms:.1f}ms, exceeds 50ms target"
        )

    def test_row_count_latency(self) -> None:
        """row_count < 50ms on 100K rows."""
        start = time.perf_counter()
        count = self.store.row_count()
        elapsed_ms = (time.perf_counter() - start) * 1000

        print(f"\n[S8P3] row_count: {elapsed_ms:.1f}ms (total={count})")
        assert count == 100_000
        assert elapsed_ms < 50, (
            f"row_count took {elapsed_ms:.1f}ms, exceeds 50ms target"
        )

# ---------------------------------------------------------------------------
# S8P3-3. Anomaly scoring throughput (target >500/sec on 1000 detections)
# ---------------------------------------------------------------------------

@pytest.mark.timeout(120)
@pytest.mark.performance
class TestDirectAnomalyScoringThroughput:
    """Benchmark anomaly scorer at scale via direct invocation."""

    def test_score_1000_detections(self) -> None:
        """Score 1000 detections; target > 500/sec."""
        baseline_mgr = BaselineManager()
        scorer = AnomalyScorer(baseline_mgr)

        # Seed baselines to exercise the full scoring code path
        for freq in [433.92e6, 915e6, 2.4e9, 868e6, 162.4e6]:
            for _ in range(200):
                baseline_mgr.update(
                    freq_hz=freq,
                    class_name="bpsk",
                    confidence=0.9,
                    power_dbm=-60.0,
                    snr_db=15.0,
                    hour=12,
                )

        detections = [
            {
                "signal_class": ["bpsk", "qpsk", "ofdm", "gmsk", "fsk"][i % 5],
                "confidence": 0.5 + (i % 50) * 0.01,
                "freq_hz": [433.92e6, 915e6, 2.4e9, 868e6, 162.4e6][i % 5],
                "power_dbm": -80.0 + (i % 40),
                "snr_db": 5.0 + (i % 25),
                "timestamp": datetime.now(timezone.utc) - timedelta(seconds=i),
            }
            for i in range(1_000)
        ]

        start = time.perf_counter()
        results = [scorer.score(d) for d in detections]
        elapsed = time.perf_counter() - start

        throughput = len(results) / elapsed if elapsed > 0 else float("inf")
        print(f"\n[S8P3] Anomaly scoring: {throughput:,.0f} detections/sec "
              f"({len(results)} in {elapsed:.3f}s)")

        assert len(results) == 1_000
        assert all(0.0 <= r.score <= 1.0 for r in results)
        assert throughput > 500, (
            f"Scoring throughput {throughput:.0f}/sec below 500/sec target"
        )

# ---------------------------------------------------------------------------
# S8P3-4. WebSocket broadcast to 50 mock clients (target <100ms)
# ---------------------------------------------------------------------------

class _MockWS:
    """Lightweight mock WebSocket for broadcast benchmarking."""

    __slots__ = ("messages",)

    def __init__(self) -> None:
        self.messages: list = []

    async def send_json(self, data: dict) -> None:
        self.messages.append(data)

    async def send_text(self, data: str) -> None:
        self.messages.append(data)

@pytest.mark.timeout(120)
@pytest.mark.performance
class TestDirectWebSocketBroadcast:
    """Benchmark WebSocket broadcast using mock clients."""

    def test_broadcast_to_50_clients(self) -> None:
        """Broadcast to 50 mock WS clients; target < 100ms."""
        client_set = WebSocketClientSet()
        clients = [_MockWS() for _ in range(50)]

        async def _run() -> float:
            for c in clients:
                await client_set.add(c)

            payload = {
                "type": "batch",
                "node_id": "node-perf-01",
                "batch_id": "perf-batch-001",
                "count": 100,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            start = time.perf_counter()
            await client_set.broadcast(payload)
            return (time.perf_counter() - start) * 1000

        loop = asyncio.new_event_loop()
        try:
            elapsed_ms = loop.run_until_complete(_run())
        finally:
            loop.close()

        # Verify all clients received the message
        for i, c in enumerate(clients):
            assert len(c.messages) == 1, f"Client {i} got {len(c.messages)} messages"
            assert c.messages[0]["type"] == "batch"

        print(f"\n[S8P3] Broadcast to 50 clients: {elapsed_ms:.1f}ms")
        assert elapsed_ms < 100, (
            f"Broadcast took {elapsed_ms:.1f}ms, exceeds 100ms target"
        )

    def test_broadcast_to_50_clients_repeated(self) -> None:
        """10 consecutive broadcasts to 50 clients; average < 100ms."""
        client_set = WebSocketClientSet()
        clients = [_MockWS() for _ in range(50)]

        async def _run() -> float:
            for c in clients:
                await client_set.add(c)

            total_ms = 0.0
            for iteration in range(10):
                payload = {
                    "type": "batch",
                    "node_id": "node-perf-01",
                    "batch_id": f"perf-batch-{iteration:03d}",
                    "count": 100,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                start = time.perf_counter()
                await client_set.broadcast(payload)
                total_ms += (time.perf_counter() - start) * 1000

            return total_ms / 10

        loop = asyncio.new_event_loop()
        try:
            avg_ms = loop.run_until_complete(_run())
        finally:
            loop.close()

        print(f"\n[S8P3] Average broadcast (10 rounds, 50 clients): {avg_ms:.1f}ms")
        assert avg_ms < 100, (
            f"Average broadcast took {avg_ms:.1f}ms, exceeds 100ms target"
        )
