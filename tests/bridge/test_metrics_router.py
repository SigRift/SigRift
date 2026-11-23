"""Tests for the Prometheus metrics router (/metrics).

Verifies the Prometheus text exposition format endpoint returns
correct content type and includes expected metric metadata lines.
Mounted at root /metrics (Prometheus convention), separate from
the JSON /api/metrics endpoint.
"""

from __future__ import annotations

import threading

from fastapi.testclient import TestClient

import sigrift.bridge.routers.metrics as metrics_mod
from sigrift.bridge.routers.metrics import (
    _metrics_lock,
    record_detection,
    record_request,
)


class TestPrometheusMetrics:
    """Test the Prometheus /metrics endpoint."""

    def test_metrics_returns_200(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type_plain_text(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_contains_help_lines(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        body = resp.text
        assert "# HELP" in body

    def test_metrics_contains_type_lines(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        body = resp.text
        assert "# TYPE" in body

    def test_metrics_contains_uptime(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        body = resp.text
        assert "sigrift_uptime_seconds" in body

    def test_metrics_contains_detections_total(self, client: TestClient) -> None:
        resp = client.get("/metrics")
        body = resp.text
        assert "sigrift_detections_total" in body


class TestMetricsConcurrency:
    """Verify thread-safety of module-level metric counters."""

    def _reset_counters(self) -> None:
        with _metrics_lock:
            metrics_mod._request_counts.clear()
            metrics_mod._detection_count = 0

    def test_concurrent_record_request(self) -> None:
        self._reset_counters()
        n_threads = 10
        calls_per_thread = 100
        barrier = threading.Barrier(n_threads)

        def worker() -> None:
            barrier.wait()
            for _ in range(calls_per_thread):
                record_request("GET", "/api/test")

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with _metrics_lock:
            total = metrics_mod._request_counts[("GET", "/api/test")]
        assert total == n_threads * calls_per_thread

    def test_concurrent_record_detection(self) -> None:
        self._reset_counters()
        n_threads = 10
        calls_per_thread = 100
        barrier = threading.Barrier(n_threads)

        def worker() -> None:
            barrier.wait()
            for _ in range(calls_per_thread):
                record_detection(1)

        threads = [threading.Thread(target=worker) for _ in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with _metrics_lock:
            total = metrics_mod._detection_count
        assert total == n_threads * calls_per_thread
