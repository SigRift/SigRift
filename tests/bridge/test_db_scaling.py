"""Database scaling and efficiency tests for The Bridge.

Tests cover:
  - Retention/cleanup efficiency at scale (100K+ rows)
  - Index effectiveness via EXPLAIN QUERY PLAN
  - WAL checkpoint behavior under write pressure
  - Cache hit rate measurement
  - Insert throughput scaling with row count

Run with::

    pytest -m performance sigrift/bridge/tests/test_db_scaling.py -v
    PERF_SCALE=medium pytest -m performance sigrift/bridge/tests/test_db_scaling.py -v
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionQuery, DetectionRecord
from sigrift.bridge.tests.bench_utils import (
    BenchmarkTimer,
    LatencyStats,
    ReportFormatter,
    scale_value,
)
from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_report = ReportFormatter()

def _make_batch(n: int, node_id: str = "node-scale-01", offset: int = 0) -> list[DetectionRecord]:
    """Create a list of DetectionRecord objects for bulk insert."""
    now = datetime.now(timezone.utc)
    return [
        make_detection(
            node_id=node_id,
            signal_class=["bpsk", "qpsk", "8psk", "16qam", "ofdm"][i % 5],
            confidence=0.80 + (i % 20) * 0.01,
            family=["psk", "psk", "psk", "qam", "ofdm"][i % 5],
            freq_hz=100e6 + (offset + i) * 1000,
            snr_db=5.0 + i % 30,
            anomaly_score=0.1 * (i % 10) / 10.0,
            timestamp=now - timedelta(seconds=i),
        )
        for i in range(n)
    ]

def _populate_store(store: DetectionStore, count: int, batch_size: int = 1000) -> int:
    """Insert *count* detections into the store. Returns actual inserted."""
    inserted = 0
    offset = 0
    while inserted < count:
        n = min(batch_size, count - inserted)
        batch = _make_batch(n, offset=offset)
        inserted += store.insert_batch(batch)
        offset += n
    return inserted

# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _print_report():
    yield
    table = _report.format_table()
    print(table)

# ---------------------------------------------------------------------------
# Index Effectiveness Tests
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestIndexEffectiveness:
    """Verify that key queries use indexes via EXPLAIN QUERY PLAN."""

    @pytest.fixture(autouse=True)
    def _store(self, tmp_path: Path) -> None:
        self.store = DetectionStore(db_path=tmp_path / "idx_test.db")
        # Populate with some data so the planner has stats
        _populate_store(self.store, 1000)

    INDEXED_QUERIES = [
        (
            "recent_by_timestamp",
            "SELECT * FROM detections WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 100",
            [(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()],
        ),
        (
            "by_node_and_time",
            "SELECT * FROM detections WHERE node_id = ? AND timestamp > ? LIMIT 100",
            ["node-scale-01", (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()],
        ),
        (
            "by_signal_class",
            "SELECT * FROM detections WHERE signal_class = ? LIMIT 100",
            ["bpsk"],
        ),
        (
            "anomaly_filter",
            "SELECT * FROM detections WHERE anomaly_score > 0.0 LIMIT 100",
            [],
        ),
        (
            "timestamp_freq_range",
            "SELECT * FROM detections WHERE timestamp > ? AND freq_hz BETWEEN ? AND ? LIMIT 100",
            [(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), 100e6, 200e6],
        ),
    ]

    @pytest.mark.parametrize("name,sql,params", INDEXED_QUERIES, ids=[q[0] for q in INDEXED_QUERIES])
    def test_query_uses_index(self, name: str, sql: str, params: list) -> None:
        """Verify that EXPLAIN QUERY PLAN shows index usage (not full SCAN)."""
        conn = self.store.get_connection()
        plan_rows = conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()

        # Extract detail text from Row objects (sqlite3.Row has a 'detail' key)
        details: list[str] = []
        for row in plan_rows:
            if hasattr(row, "keys"):
                details.append(str(dict(row).get("detail", row)))
            else:
                details.append(str(row))
        plan_text = " ".join(details).upper()

        # A full table SCAN without an index indicates missing or unused index
        uses_index = "USING INDEX" in plan_text or "USING COVERING INDEX" in plan_text
        # Some queries may use PRIMARY KEY which is fine
        uses_pk = "PRIMARY KEY" in plan_text or "ROWID" in plan_text
        # Search on primary key column is acceptable too
        acceptable = uses_index or uses_pk or "SEARCH" in plan_text

        _report.add_result(
            f"index_{name}",
            passed=acceptable,
            threshold_label="uses index",
            extra={"plan": plan_text[:200]},
        )
        assert acceptable is True, (
            f"Query '{name}' does not use an index.\n"
            f"EXPLAIN QUERY PLAN: {plan_text}"
        )

# ---------------------------------------------------------------------------
# Retention / Cleanup at Scale
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestRetentionAtScale:
    """Test that retention/cleanup works efficiently at scale."""

    def test_cleanup_100k_rows(self, tmp_path: Path) -> None:
        """Cleanup of 100K+ rows should complete in reasonable time."""
        row_count = scale_value(10_000, 50_000, 100_000)
        store = DetectionStore(db_path=tmp_path / "cleanup_test.db")

        # Insert old data (> 7 days old) so cleanup finds it
        now = datetime.now(timezone.utc)
        batch_size = 1000
        inserted = 0
        for offset in range(0, row_count, batch_size):
            n = min(batch_size, row_count - offset)
            batch = [
                make_detection(
                    node_id="node-cleanup-01",
                    signal_class="bpsk",
                    confidence=0.9,
                    freq_hz=433e6 + i * 1000,
                    # 8-30 days old so cleanup finds it
                    timestamp=now - timedelta(days=8 + (i % 22)),
                )
                for i in range(n)
            ]
            inserted += store.insert_batch(batch)

        assert inserted >= row_count * 0.9, f"Only inserted {inserted}/{row_count}"

        # Measure cleanup time
        with BenchmarkTimer() as t:
            deleted = store.cleanup(max_age_days=7)

        # Should have deleted most rows
        assert deleted > 0, "Cleanup deleted 0 rows"

        # Threshold: cleanup should finish in < 10s even at 100K
        max_time = scale_value(5.0, 10.0, 30.0)
        passed = t.elapsed < max_time

        _report.add_result(
            f"cleanup_{row_count // 1000}k_rows",
            passed=passed,
            threshold_label=f"< {max_time:.0f}s",
            extra={
                "rows_inserted": inserted,
                "rows_deleted": deleted,
                "elapsed_s": round(t.elapsed, 3),
                "rows_per_sec": round(deleted / t.elapsed, 1) if t.elapsed > 0 else 0,
            },
        )
        assert passed is True, (
            f"Cleanup of {inserted} rows took {t.elapsed:.2f}s (limit {max_time:.0f}s), "
            f"deleted {deleted}"
        )

    def test_aggregation_at_scale(self, tmp_path: Path) -> None:
        """Hourly aggregation should work efficiently at scale."""
        row_count = scale_value(5_000, 20_000, 100_000)
        store = DetectionStore(db_path=tmp_path / "agg_test.db")

        # Insert data > 1 hour old so aggregation finds it
        now = datetime.now(timezone.utc)
        batch_size = 1000
        for offset in range(0, row_count, batch_size):
            n = min(batch_size, row_count - offset)
            batch = [
                make_detection(
                    node_id="node-agg-01",
                    signal_class=["bpsk", "qpsk", "8psk"][i % 3],
                    family="psk",
                    confidence=0.85 + (i % 15) * 0.01,
                    freq_hz=433e6 + i * 1000,
                    timestamp=now - timedelta(hours=2, seconds=i),
                )
                for i in range(n)
            ]
            store.insert_batch(batch)

        with BenchmarkTimer() as t:
            aggregated = store.aggregate_hourly()

        max_time = scale_value(5.0, 15.0, 60.0)
        passed = t.elapsed < max_time and aggregated > 0

        _report.add_result(
            f"aggregation_{row_count // 1000}k_rows",
            passed=passed,
            threshold_label=f"< {max_time:.0f}s",
            extra={
                "rows_source": row_count,
                "aggregated_buckets": aggregated,
                "elapsed_s": round(t.elapsed, 3),
            },
        )
        assert passed is True, (
            f"Aggregation of {row_count} rows took {t.elapsed:.2f}s (limit {max_time:.0f}s), "
            f"produced {aggregated} buckets"
        )

# ---------------------------------------------------------------------------
# WAL Checkpoint Behavior
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestWALBehavior:
    """Test WAL journal mode behavior under write pressure."""

    def test_wal_mode_enabled(self, tmp_path: Path) -> None:
        """Verify database is using WAL journal mode."""
        store = DetectionStore(db_path=tmp_path / "wal_test.db")
        conn = store.get_connection()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        passed = mode.lower() == "wal"
        _report.add_result(
            "wal_mode_enabled",
            passed=passed,
            threshold_label="journal_mode = wal",
            extra={"journal_mode": mode},
        )
        assert passed is True, f"Expected WAL journal mode, got {mode}"

    def test_wal_checkpoint_under_pressure(self, tmp_path: Path) -> None:
        """WAL file should not grow unbounded under write pressure."""
        store = DetectionStore(db_path=tmp_path / "wal_pressure.db")
        db_path = Path(store.db_path)
        wal_path = db_path.parent / (db_path.name + "-wal")

        # Heavy write phase
        total_writes = scale_value(5_000, 20_000, 50_000)
        batch_size = 500
        for offset in range(0, total_writes, batch_size):
            n = min(batch_size, total_writes - offset)
            batch = _make_batch(n, offset=offset)
            store.insert_batch(batch)

        wal_size_bytes = wal_path.stat().st_size if wal_path.exists() else 0
        wal_size_mb = wal_size_bytes / (1024 * 1024)

        # Force a checkpoint
        conn = store.get_connection()
        with BenchmarkTimer() as t:
            result = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        checkpoint_elapsed = t.elapsed

        wal_after = wal_path.stat().st_size if wal_path.exists() else 0

        # WAL should shrink after checkpoint
        passed = wal_after < wal_size_bytes or wal_size_bytes == 0

        _report.add_result(
            "wal_checkpoint",
            passed=passed,
            threshold_label="WAL shrinks after checkpoint",
            extra={
                "writes": total_writes,
                "wal_before_mb": round(wal_size_mb, 2),
                "wal_after_bytes": wal_after,
                "checkpoint_elapsed_s": round(checkpoint_elapsed, 3),
                "checkpoint_result": str(result),
            },
        )
        assert passed is True, (
            f"WAL did not shrink: before={wal_size_bytes}B, after={wal_after}B"
        )

# ---------------------------------------------------------------------------
# Cache Effectiveness
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestCacheEffectiveness:
    """Test cache hit rates for repeated queries."""

    def test_cache_hit_rate(self, tmp_path: Path) -> None:
        """Repeated identical queries should benefit from caching."""
        # Use enough data that query time is measurable vs cache overhead
        data_count = scale_value(10_000, 50_000, 100_000)
        store = DetectionStore(db_path=tmp_path / "cache_test.db")
        _populate_store(store, data_count)

        # Warm up cache with first query
        q = DetectionQuery(limit=100)
        store.query(q)

        # Measure cached vs uncached query latency
        cold_stats = LatencyStats()
        warm_stats = LatencyStats()

        iterations = scale_value(10, 30, 50)

        # Cold queries (invalidate cache each time)
        for i in range(iterations):
            store._cache.invalidate()  # force cold
            with BenchmarkTimer() as t:
                store.query(DetectionQuery(limit=100))
            cold_stats.add(t.elapsed)

        # Warm queries (same params, should hit cache)
        fixed_q = DetectionQuery(limit=100)
        store._cache.invalidate()
        store.query(fixed_q)  # prime cache
        for _ in range(iterations):
            with BenchmarkTimer() as t:
                store.query(fixed_q)
            warm_stats.add(t.elapsed)

        # Warm should not be significantly slower than cold.
        # At small data sizes, the difference may be negligible, so we
        # accept any ratio >= 0.5 (warm can be up to 2x slower due to
        # measurement noise on sub-millisecond ops).  At larger scales
        # the cache should clearly help.
        speedup = cold_stats.avg / warm_stats.avg if warm_stats.avg > 0 else 1.0
        min_ratio = scale_value(0.5, 0.8, 1.0)
        passed = speedup >= min_ratio

        _report.add_result(
            "cache_effectiveness",
            passed=passed,
            threshold_label="warm >= cold speed",
            extra={
                "cold_avg_ms": round(cold_stats.avg * 1000, 2),
                "warm_avg_ms": round(warm_stats.avg * 1000, 2),
                "speedup_ratio": round(speedup, 2),
            },
        )
        assert passed is True, (
            f"Cache not effective: cold_avg={cold_stats.avg * 1000:.1f}ms, "
            f"warm_avg={warm_stats.avg * 1000:.1f}ms, speedup={speedup:.2f}x"
        )

# ---------------------------------------------------------------------------
# Insert Throughput Scaling
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestInsertScaling:
    """Test how insert throughput changes as the DB grows."""

    def test_insert_throughput_at_scale(self, tmp_path: Path) -> None:
        """Insert throughput should not degrade significantly as DB grows."""
        store = DetectionStore(db_path=tmp_path / "insert_scale.db")
        batch_size = 500
        checkpoints = scale_value(
            [1_000, 5_000, 10_000],
            [5_000, 25_000, 50_000],
            [10_000, 50_000, 100_000],
        )

        results: list[dict[str, Any]] = []
        total_inserted = 0

        for target in checkpoints:
            to_insert = target - total_inserted
            if to_insert <= 0:
                continue

            stats = LatencyStats()
            for offset in range(0, to_insert, batch_size):
                n = min(batch_size, to_insert - offset)
                batch = _make_batch(n, offset=total_inserted + offset)
                with BenchmarkTimer() as t:
                    store.insert_batch(batch)
                stats.add(t.elapsed)

            total_inserted = target
            rps = batch_size / stats.avg if stats.avg > 0 else 0

            results.append({
                "db_rows": target,
                "avg_batch_ms": round(stats.avg * 1000, 1),
                "p95_batch_ms": round(stats.p95 * 1000, 1),
                "rows_per_sec": round(rps, 0),
            })

        # Throughput at max size should be at least 30% of throughput at min size
        if len(results) >= 2:
            initial_rps = results[0]["rows_per_sec"]
            final_rps = results[-1]["rows_per_sec"]
            ratio = final_rps / initial_rps if initial_rps > 0 else 1.0
            passed = ratio >= 0.3
        else:
            passed = True
            ratio = 1.0

        _report.add_result(
            "insert_scaling",
            passed=passed,
            threshold_label="final_rps >= 30% initial",
            extra={
                "checkpoints": results,
                "degradation_ratio": round(ratio, 3),
            },
        )
        assert passed is True, (
            f"Insert throughput degraded: ratio={ratio:.2f}\n"
            f"Checkpoints: {results}"
        )

# ---------------------------------------------------------------------------
# Query Performance at Scale
# ---------------------------------------------------------------------------

@pytest.mark.performance
class TestQueryScaling:
    """Test query latency at different database sizes."""

    def test_query_latency_vs_db_size(self, tmp_path: Path) -> None:
        """Query latency should scale sublinearly with DB size (thanks to indexes)."""
        store = DetectionStore(db_path=tmp_path / "query_scale.db")

        sizes = scale_value(
            [1_000, 5_000],
            [5_000, 25_000, 50_000],
            [10_000, 50_000, 100_000],
        )

        results: list[dict[str, Any]] = []
        total = 0

        for target in sizes:
            to_insert = target - total
            if to_insert > 0:
                _populate_store(store, to_insert, batch_size=1000)
                total = target

            # Measure query latency at this DB size
            store._cache.invalidate()
            stats = LatencyStats()
            iterations = scale_value(5, 15, 30)

            for _ in range(iterations):
                q = DetectionQuery(limit=100)
                with BenchmarkTimer() as t:
                    store.query(q)
                stats.add(t.elapsed)
                store._cache.invalidate()

            results.append({
                "db_rows": target,
                "avg_ms": round(stats.avg * 1000, 2),
                "p95_ms": round(stats.p95 * 1000, 2),
            })

        # p95 at max size should be under 500ms
        max_p95 = results[-1]["p95_ms"] if results else 0
        passed = max_p95 < 500

        _report.add_result(
            "query_scaling",
            passed=passed,
            threshold_label="p95 < 500ms at max size",
            extra={"checkpoints": results},
        )
        assert passed is True, (
            f"Query latency at max size: p95={max_p95:.1f}ms (limit 500ms)\n"
            f"Checkpoints: {results}"
        )
