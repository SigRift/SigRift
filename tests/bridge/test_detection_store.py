"""Comprehensive tests for the DetectionStore (SQLite backend).

Tests cover:
  - Batch insert (including duplicates)
  - Filtered queries
  - Recent detection retrieval
  - Statistics computation
  - Distribution
  - Anomaly retrieval
  - Aggregation and cleanup
  - Row count
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionQuery

from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Insert tests
# ---------------------------------------------------------------------------

class TestInsertBatch:
    """Tests for DetectionStore.insert_batch."""

    def test_insert_empty(self, detection_store: DetectionStore) -> None:
        """Inserting an empty list returns 0."""
        assert detection_store.insert_batch([]) == 0

    def test_insert_single(self, detection_store: DetectionStore) -> None:
        """Insert a single detection."""
        det = make_detection()
        inserted = detection_store.insert_batch([det])
        assert inserted == 1
        assert detection_store.row_count() == 1

    def test_insert_multiple(self, detection_store: DetectionStore) -> None:
        """Insert multiple detections in one batch."""
        dets = [make_detection(signal_class=f"sig{i}") for i in range(5)]
        inserted = detection_store.insert_batch(dets)
        assert inserted == 5
        assert detection_store.row_count() == 5

    def test_insert_duplicates_ignored(self, detection_store: DetectionStore) -> None:
        """Duplicate detection_ids are silently ignored."""
        det = make_detection()
        detection_store.insert_batch([det])
        # Insert same detection again
        inserted = detection_store.insert_batch([det])
        # INSERT OR IGNORE — duplicate is skipped
        assert detection_store.row_count() == 1

    def test_insert_preserves_fields(self, detection_store: DetectionStore) -> None:
        """All fields are stored and retrievable."""
        det = make_detection(
            node_id="node-42",
            signal_class="qpsk",
            confidence=0.88,
            family="psk",
            freq_hz=915e6,
            snr_db=20.0,
            anomaly_score=0.7,
            baseline_status="learning",
            backend="onnx",
        )
        detection_store.insert_batch([det])

        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        row = results[0]
        assert row["node_id"] == "node-42"
        assert row["signal_class"] == "qpsk"
        assert row["confidence"] == 0.88
        assert row["family"] == "psk"
        assert row["freq_hz"] == 915e6
        assert row["snr_db"] == 20.0
        assert row["anomaly_score"] == 0.7
        assert row["baseline_status"] == "learning"
        assert row["backend"] == "onnx"

# ---------------------------------------------------------------------------
# Query tests
# ---------------------------------------------------------------------------

class TestQuery:
    """Tests for DetectionStore.query."""

    def test_query_empty_db(self, detection_store: DetectionStore) -> None:
        """Query on empty database returns empty list."""
        results = detection_store.query(DetectionQuery())
        assert results == []

    def test_query_filter_by_node(self, detection_store: DetectionStore) -> None:
        """Filter by node_id."""
        detection_store.insert_batch([
            make_detection(node_id="node-a"),
            make_detection(node_id="node-b"),
            make_detection(node_id="node-a"),
        ])
        results = detection_store.query(DetectionQuery(node_id="node-a"))
        assert len(results) == 2
        assert all(r["node_id"] == "node-a" for r in results)

    def test_query_filter_by_class(self, detection_store: DetectionStore) -> None:
        """Filter by signal_class."""
        detection_store.insert_batch([
            make_detection(signal_class="bpsk"),
            make_detection(signal_class="qpsk"),
            make_detection(signal_class="bpsk"),
        ])
        results = detection_store.query(DetectionQuery(signal_class="qpsk"))
        assert len(results) == 1
        assert results[0]["signal_class"] == "qpsk"

    def test_query_filter_by_family(self, detection_store: DetectionStore) -> None:
        """Filter by family."""
        detection_store.insert_batch([
            make_detection(family="psk"),
            make_detection(family="qam"),
            make_detection(family="psk"),
        ])
        results = detection_store.query(DetectionQuery(family="qam"))
        assert len(results) == 1

    def test_query_filter_by_confidence(self, detection_store: DetectionStore) -> None:
        """Filter by min_confidence."""
        detection_store.insert_batch([
            make_detection(confidence=0.5),
            make_detection(confidence=0.8),
            make_detection(confidence=0.95),
        ])
        results = detection_store.query(DetectionQuery(min_confidence=0.7))
        assert len(results) == 2

    def test_query_limit_and_offset(self, detection_store: DetectionStore) -> None:
        """Limit and offset work correctly."""
        now = datetime.now(timezone.utc)
        dets = [
            make_detection(
                signal_class=f"sig{i}",
                timestamp=now - timedelta(minutes=i),
            )
            for i in range(10)
        ]
        detection_store.insert_batch(dets)

        results = detection_store.query(DetectionQuery(limit=3, offset=0))
        assert len(results) == 3

        results2 = detection_store.query(DetectionQuery(limit=3, offset=3))
        assert len(results2) == 3
        # No overlap
        ids1 = {r["detection_id"] for r in results}
        ids2 = {r["detection_id"] for r in results2}
        assert ids1.isdisjoint(ids2)

    def test_query_time_range(self, detection_store: DetectionStore) -> None:
        """Filter by start/end time range."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(timestamp=now - timedelta(hours=3)),
            make_detection(timestamp=now - timedelta(hours=1)),
            make_detection(timestamp=now),
        ])
        results = detection_store.query(DetectionQuery(
            start=now - timedelta(hours=2),
            end=now,
        ))
        assert len(results) == 2

# ---------------------------------------------------------------------------
# Recent detections tests
# ---------------------------------------------------------------------------

class TestGetRecent:
    """Tests for DetectionStore.get_recent."""

    def test_recent_empty(self, detection_store: DetectionStore) -> None:
        """No results on empty DB."""
        assert detection_store.get_recent() == []

    def test_recent_within_window(self, detection_store: DetectionStore) -> None:
        """Only returns detections within the time window."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(timestamp=now - timedelta(minutes=2)),  # within 5min
            make_detection(timestamp=now - timedelta(minutes=10)),  # outside 5min
        ])
        results = detection_store.get_recent(minutes=5)
        assert len(results) == 1

    def test_recent_node_filter(self, detection_store: DetectionStore) -> None:
        """Node filter works in get_recent."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(node_id="node-a", timestamp=now),
            make_detection(node_id="node-b", timestamp=now),
        ])
        results = detection_store.get_recent(minutes=5, node_id="node-a")
        assert len(results) == 1
        assert results[0]["node_id"] == "node-a"

# ---------------------------------------------------------------------------
# Statistics tests
# ---------------------------------------------------------------------------

class TestGetStats:
    """Tests for DetectionStore.get_stats."""

    def test_stats_empty(self, detection_store: DetectionStore) -> None:
        """Stats on empty DB return zeroes."""
        stats = detection_store.get_stats()
        assert stats.total_detections == 0
        assert stats.unique_classes == 0
        assert stats.unique_nodes == 0
        assert stats.avg_confidence == 0.0

    def test_stats_with_data(self, detection_store: DetectionStore) -> None:
        """Stats reflect inserted data."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(
                node_id="node-a", signal_class="bpsk",
                confidence=0.9, family="psk", timestamp=now,
            ),
            make_detection(
                node_id="node-b", signal_class="qam16",
                confidence=0.8, family="qam", timestamp=now,
            ),
            make_detection(
                node_id="node-a", signal_class="bpsk",
                confidence=1.0, family="psk", timestamp=now,
            ),
        ])
        stats = detection_store.get_stats(hours=1)
        assert stats.total_detections == 3
        assert stats.unique_classes == 2
        assert stats.unique_nodes == 2
        assert 0.8 <= stats.avg_confidence <= 1.0
        assert "bpsk" in stats.class_distribution
        assert stats.class_distribution["bpsk"] == 2
        assert stats.family_distribution["psk"] == 2

    def test_stats_node_filter(self, detection_store: DetectionStore) -> None:
        """Stats can filter by node_id."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(node_id="node-a", timestamp=now),
            make_detection(node_id="node-b", timestamp=now),
        ])
        stats = detection_store.get_stats(hours=1, node_id="node-a")
        assert stats.total_detections == 1
        assert stats.unique_nodes == 1

# ---------------------------------------------------------------------------
# Distribution tests
# ---------------------------------------------------------------------------

class TestGetDistribution:
    """Tests for DetectionStore.get_distribution."""

    def test_distribution_empty(self, detection_store: DetectionStore) -> None:
        """Empty DB returns empty list."""
        assert detection_store.get_distribution() == []

    def test_distribution_groups(self, detection_store: DetectionStore) -> None:
        """Distribution groups by signal_class and family."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(signal_class="bpsk", family="psk", timestamp=now),
            make_detection(signal_class="bpsk", family="psk", timestamp=now),
            make_detection(signal_class="qam16", family="qam", timestamp=now),
        ])
        dist = detection_store.get_distribution(range_hours=1)
        assert len(dist) == 2
        bpsk_entry = next(d for d in dist if d["signal_class"] == "bpsk")
        assert bpsk_entry["count"] == 2
        assert bpsk_entry["family"] == "psk"

# ---------------------------------------------------------------------------
# Anomaly tests
# ---------------------------------------------------------------------------

class TestGetAnomalies:
    """Tests for DetectionStore.get_anomalies."""

    def test_anomalies_empty(self, detection_store: DetectionStore) -> None:
        """No anomalies in empty DB."""
        assert detection_store.get_anomalies() == []

    def test_anomalies_threshold(self, detection_store: DetectionStore) -> None:
        """Only returns detections above the min_score threshold."""
        detection_store.insert_batch([
            make_detection(anomaly_score=0.1),
            make_detection(anomaly_score=0.5),
            make_detection(anomaly_score=0.8),
        ])
        results = detection_store.get_anomalies(min_score=0.3)
        assert len(results) == 2
        # Sorted by score descending
        assert results[0]["anomaly_score"] >= results[1]["anomaly_score"]

    def test_anomalies_node_filter(self, detection_store: DetectionStore) -> None:
        """Node filter works in get_anomalies."""
        detection_store.insert_batch([
            make_detection(node_id="node-a", anomaly_score=0.9),
            make_detection(node_id="node-b", anomaly_score=0.8),
        ])
        results = detection_store.get_anomalies(min_score=0.3, node_id="node-a")
        assert len(results) == 1
        assert results[0]["node_id"] == "node-a"

# ---------------------------------------------------------------------------
# Aggregation and cleanup tests
# ---------------------------------------------------------------------------

class TestAggregation:
    """Tests for aggregation and cleanup."""

    def test_aggregate_hourly(self, detection_store: DetectionStore) -> None:
        """aggregate_hourly runs without error."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(
                signal_class="bpsk",
                timestamp=now - timedelta(hours=2),
            ),
        ])
        count = detection_store.aggregate_hourly()
        assert isinstance(count, int)

    def test_cleanup(self, detection_store: DetectionStore) -> None:
        """cleanup removes old detections."""
        old = datetime.now(timezone.utc) - timedelta(days=10)
        detection_store.insert_batch([
            make_detection(timestamp=old),
        ])
        assert detection_store.row_count() == 1
        deleted = detection_store.cleanup(max_age_days=7)
        assert deleted == 1
        assert detection_store.row_count() == 0

    def test_cleanup_preserves_recent(self, detection_store: DetectionStore) -> None:
        """cleanup does not remove recent detections."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(timestamp=now),
        ])
        deleted = detection_store.cleanup(max_age_days=7)
        assert deleted == 0
        assert detection_store.row_count() == 1

# ---------------------------------------------------------------------------
# Row count and close
# ---------------------------------------------------------------------------

class TestRowCount:
    """Tests for row_count and close."""

    def test_row_count(self, detection_store: DetectionStore) -> None:
        """row_count returns correct count."""
        assert detection_store.row_count() == 0
        detection_store.insert_batch([make_detection()])
        assert detection_store.row_count() == 1

    def test_close(self, detection_store: DetectionStore) -> None:
        """close does not raise."""
        detection_store.close()

# ---------------------------------------------------------------------------
# Cache integration tests
# ---------------------------------------------------------------------------

class TestCacheIntegration:
    """Tests verifying the TTL cache layer in DetectionStore."""

    def test_cached_read_returns_same_result(
        self, detection_store: DetectionStore,
    ) -> None:
        """Repeated reads return cached data; hit count increases."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(timestamp=now),
            make_detection(timestamp=now),
        ])
        # First call — cache miss
        result1 = detection_store.get_stats(hours=1)
        stats1 = detection_store.cache_stats()
        assert stats1["misses"] >= 1

        # Second call — cache hit
        result2 = detection_store.get_stats(hours=1)
        stats2 = detection_store.cache_stats()
        assert stats2["hits"] >= 1
        assert result1.total_detections == result2.total_detections

    def test_cache_invalidated_on_write(
        self, detection_store: DetectionStore,
    ) -> None:
        """Writing data invalidates the cache so fresh data is returned."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([make_detection(timestamp=now)])

        stats_before = detection_store.get_stats(hours=1)
        assert stats_before.total_detections == 1

        # Insert more data — should invalidate cache
        detection_store.insert_batch([make_detection(timestamp=now)])

        stats_after = detection_store.get_stats(hours=1)
        assert stats_after.total_detections == 2

    def test_different_params_different_cache_keys(
        self, detection_store: DetectionStore,
    ) -> None:
        """Calls with different parameters are cached independently."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(node_id="node-a", timestamp=now),
            make_detection(node_id="node-b", timestamp=now),
        ])

        stats_a = detection_store.get_stats(hours=1, node_id="node-a")
        stats_all = detection_store.get_stats(hours=1)
        assert stats_a.total_detections == 1
        assert stats_all.total_detections == 2

    def test_cache_stats_method(
        self, detection_store: DetectionStore,
    ) -> None:
        """cache_stats() returns expected keys."""
        cs = detection_store.cache_stats()
        assert isinstance(cs["hits"], int)
        assert isinstance(cs["misses"], int)
        assert isinstance(cs["entries"], int)
        assert isinstance(cs["hit_ratio"], float)

    def test_active_anomaly_count_cached(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_active_anomaly_count returns correct result and caches."""
        detection_store.insert_batch([
            make_detection(anomaly_score=0.5),
            make_detection(anomaly_score=0.1),
        ])
        count = detection_store.get_active_anomaly_count(threshold=0.3)
        assert count == 1
        # Second call should be cached
        count2 = detection_store.get_active_anomaly_count(threshold=0.3)
        assert count2 == 1
        assert detection_store.cache_stats()["hits"] >= 1

    def test_active_frequency_count(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_active_frequency_count returns correct count."""
        now = datetime.now(timezone.utc)
        detection_store.insert_batch([
            make_detection(freq_hz=433.92e6, timestamp=now),
            make_detection(freq_hz=915.0e6, timestamp=now),
        ])
        count = detection_store.get_active_frequency_count(hours=1)
        assert count >= 2

# ---------------------------------------------------------------------------
# Public facade API tests (get_connection, db_path)
# ---------------------------------------------------------------------------

class TestFacadePublicAPI:
    """Tests for the public accessors added to DetectionStore facade."""

    def test_get_connection_returns_sqlite_connection(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_connection() returns a usable sqlite3.Connection."""
        import sqlite3
        conn = detection_store.get_connection()
        assert isinstance(conn, sqlite3.Connection)

    def test_get_connection_is_functional(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_connection() returns a connection that can execute queries."""
        conn = detection_store.get_connection()
        row = conn.execute("SELECT COUNT(*) as cnt FROM detections").fetchone()
        assert row["cnt"] == 0

    def test_get_connection_returns_same_thread_local_conn(
        self, detection_store: DetectionStore,
    ) -> None:
        """Repeated calls return the same thread-local connection."""
        conn1 = detection_store.get_connection()
        conn2 = detection_store.get_connection()
        assert conn1 is conn2

    def test_db_path_returns_string(
        self, detection_store: DetectionStore,
    ) -> None:
        """db_path property returns a string path."""
        assert isinstance(detection_store.db_path, str)
        assert len(detection_store.db_path) > 0

    def test_db_path_matches_actual_database(
        self, detection_store: DetectionStore,
    ) -> None:
        """db_path points to the database file used by get_connection()."""
        db_path = detection_store.db_path
        assert Path(db_path).exists()

    def test_deprecated_shims_still_work(
        self, detection_store: DetectionStore,
    ) -> None:
        """Deprecated _get_conn() and _db_path still function for back-compat."""
        import sqlite3
        conn = detection_store._get_conn()
        assert isinstance(conn, sqlite3.Connection)
        assert detection_store._db_path == detection_store.db_path

    def test_get_connection_matches_deprecated_get_conn(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_connection() returns same object as deprecated _get_conn()."""
        assert detection_store.get_connection() is detection_store._get_conn()
