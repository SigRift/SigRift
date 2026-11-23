"""Detection analytics, aggregation, and cleanup.

Sub-store extracted from the monolithic DetectionStore.  Provides
time-series, heatmap, distribution, anomaly queries, hourly
roll-ups, and aged-data cleanup.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, TTLCache
from sigrift.bridge.models import DetectionStats

logger = logging.getLogger(__name__)


class DetectionAnalyticsStore:
    """Analytics, aggregation, and cleanup operations on detections.

    Parameters
    ----------
    ctx : SharedContext
        Shared storage infrastructure (connection, lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def _spectrum_table(self) -> str:
        """Return the best available spectrum source table.

        Prefers ``spectrum_materialized`` over the ``spectrum_all``
        view.  Falls back to the view when the materialized table
        doesn't exist or is empty.
        """
        try:
            conn = self._ctx.get_conn()
            row = conn.execute("SELECT COUNT(*) FROM spectrum_materialized").fetchone()
            if row and row[0] > 0:
                return "spectrum_materialized"
        except Exception:
            pass
        return "spectrum_all"

    # -- Stats --------------------------------------------------------------

    def get_stats(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> DetectionStats:
        """Compute aggregated statistics over the last *hours*.

        ``active_frequencies`` always counts positive 100 kHz bins in raw
        detections from the last hour, matching the native gateway contract.
        It describes observed/tuned frequencies, not confirmed occupancy.

        Parameters
        ----------
        hours : int
            Lookback window in hours.
        node_id : str or None
            Optional node filter.

        Returns
        -------
        DetectionStats
            Aggregated statistics.
        """
        cache_key = TTLCache.make_key("get_stats", hours=hours, node_id=node_id)
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        conn = self._ctx.get_conn()

        # Single query: totals + unique counts + class/family distributions
        row = conn.execute(
            f"SELECT COUNT(*) as cnt, AVG(confidence) as avg_conf, "
            f"COUNT(DISTINCT signal_class) as ucls, "
            f"COUNT(DISTINCT node_id) as unodes "
            f"FROM detections WHERE {where}",
            params,
        ).fetchone()
        total = row["cnt"]
        avg_conf = row["avg_conf"] or 0.0
        unique_cls = row["ucls"]
        unique_nodes = row["unodes"]

        # Class + family distribution (single query)
        dist_rows = conn.execute(
            f"SELECT signal_class, family, COUNT(*) as cnt "
            f"FROM detections WHERE {where} "
            f"GROUP BY signal_class, family ORDER BY cnt DESC",
            params,
        ).fetchall()
        class_dist: dict[str, int] = {}
        fam_dist: dict[str, int] = {}
        for r in dist_rows:
            sc = r["signal_class"]
            class_dist[sc] = class_dist.get(sc, 0) + r["cnt"]
            fam = r["family"]
            if fam:
                fam_dist[fam] = fam_dist.get(fam, 0) + r["cnt"]

        # Keep the frequency KPI's fixed one-hour window separate from the
        # selected chart window. Tenant and optional node scope still apply.
        freq_clauses = [tf_clause, "timestamp >= ?", "freq_hz > 0"]
        freq_params: list[Any] = list(tf_params) + [
            (now - timedelta(hours=1)).isoformat()
        ]
        if node_id is not None:
            freq_clauses.append("node_id = ?")
            freq_params.append(node_id)
        active_frequencies = conn.execute(
            "SELECT COUNT(DISTINCT CAST(freq_hz / 100000 AS INTEGER)) "
            f"FROM detections WHERE {' AND '.join(freq_clauses)}",
            freq_params,
        ).fetchone()[0]

        # Detections per second
        dps = total / (hours * 3600) if hours > 0 else 0.0

        result = DetectionStats(
            total_detections=total,
            unique_classes=unique_cls,
            unique_nodes=unique_nodes,
            avg_confidence=round(avg_conf, 4),
            class_distribution=class_dist,
            family_distribution=fam_dist,
            detections_per_second=round(dps, 4),
            active_frequencies=active_frequencies,
        )
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    # -- Timeline (time series) --------------------------------------------

    def get_timeline(
        self,
        range_hours: int = 24,
        resolution_seconds: int = 300,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return time-bucketed detection counts for time-series charts.

        Parameters
        ----------
        range_hours : int
            Lookback window.
        resolution_seconds : int
            Bucket size in seconds.
        node_id : str or None
            Optional node filter.

        Returns
        -------
        list[dict]
            Each entry: ``{bucket, count, avg_confidence, classes}``.
        """
        cache_key = TTLCache.make_key(
            "get_timeline",
            range_hours=range_hours,
            resolution_seconds=resolution_seconds,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=range_hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff]
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        where = " AND ".join(clauses)

        # Use strftime to bucket by resolution
        # SQLite strftime gives us seconds since epoch-ish via julianday
        sql = f"""
            SELECT
                CAST((julianday(timestamp) - julianday(?)) * 86400 / ? AS INTEGER) as bucket_idx,
                COUNT(*) as count,
                AVG(confidence) as avg_confidence,
                GROUP_CONCAT(DISTINCT signal_class) as classes
            FROM detections
            WHERE {where}
            GROUP BY bucket_idx
            ORDER BY bucket_idx
        """
        params_full = [cutoff, resolution_seconds] + params

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params_full).fetchall()

        result = []
        for r in rows:
            bucket_offset = r["bucket_idx"] * resolution_seconds
            bucket_time = datetime.fromisoformat(cutoff) + timedelta(
                seconds=bucket_offset
            )
            result.append(
                {
                    "bucket": bucket_time.isoformat(),
                    "count": r["count"],
                    "avg_confidence": round(r["avg_confidence"] or 0.0, 4),
                    "classes": (r["classes"] or "").split(","),
                }
            )
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    # -- Heatmap (freq x time) ---------------------------------------------

    def get_heatmap(
        self,
        date: str = "",
        resolution_minutes: int = 15,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return frequency x time heatmap data.

        Parameters
        ----------
        date : str
            ISO date string (YYYY-MM-DD).  Defaults to today UTC.
            Ignored when *hours* is provided.
        resolution_minutes : int
            Time bucket size in minutes.
        hours : int or None
            If provided, return data for the last *hours* instead of
            a full calendar day.  Overrides *date*.

        Returns
        -------
        list[dict]
            Each entry: ``{time_bucket, freq_bucket_mhz, count, dominant_class}``.
        """
        if hours is not None:
            now = datetime.now(timezone.utc)
            start = (now - timedelta(hours=hours)).isoformat()
            end = now.isoformat()
            cache_key = TTLCache.make_key(
                "get_heatmap",
                hours=hours,
                resolution_minutes=resolution_minutes,
            )
        else:
            if not date:
                date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            start = f"{date}T00:00:00+00:00"
            end = f"{date}T23:59:59+00:00"
            cache_key = TTLCache.make_key(
                "get_heatmap",
                date=date,
                resolution_minutes=resolution_minutes,
            )

        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = f"""
            SELECT time_bucket, freq_bucket_mhz, SUM(cnt) as count,
                   SUBSTR(MAX(PRINTF('%010d', cnt) || sc), 11) as dominant_class
            FROM (
                SELECT
                    CAST((julianday(timestamp) - julianday(?)) * 1440 / ? AS INTEGER) as time_bucket,
                    CAST(freq_hz / 1000000.0 AS INTEGER) as freq_bucket_mhz,
                    signal_class as sc,
                    COUNT(*) as cnt
                FROM detections
                WHERE {tf_clause} AND timestamp >= ? AND timestamp <= ? AND freq_hz > 0
                GROUP BY time_bucket, freq_bucket_mhz, signal_class
            ) sub
            GROUP BY time_bucket, freq_bucket_mhz
            ORDER BY time_bucket, freq_bucket_mhz
        """
        params = [start, resolution_minutes] + tf_params + [start, end]

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        result = [dict(r) for r in rows]
        # Shorter TTL for hours-based ranges (live data); longer for date-based
        ttl = 12.0 if hours is not None else 300.0
        self._ctx.cache.put(cache_key, result, ttl=ttl)
        return result

    # -- Distribution -------------------------------------------------------

    def get_distribution(
        self,
        range_hours: int = 24,
        min_confidence: float = 0.0,
    ) -> list[dict[str, Any]]:
        """Return signal class distribution data.

        Parameters
        ----------
        range_hours : int
            Lookback window.
        min_confidence : float
            Minimum confidence filter.

        Returns
        -------
        list[dict]
            Each entry: ``{signal_class, family, count, avg_confidence}``.
        """
        cache_key = TTLCache.make_key(
            "get_distribution",
            range_hours=range_hours,
            min_confidence=min_confidence,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=range_hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = f"""
            SELECT
                signal_class,
                family,
                COUNT(*) as count,
                AVG(confidence) as avg_confidence
            FROM detections INDEXED BY idx_detections_tenant_ts_class
            WHERE {tf_clause} AND timestamp >= ? AND confidence >= ?
            GROUP BY signal_class, family
            ORDER BY count DESC
        """
        conn = self._ctx.get_conn()
        rows = conn.execute(sql, tf_params + [cutoff, min_confidence]).fetchall()
        result = [
            {
                "signal_class": r["signal_class"],
                "family": r["family"],
                "count": r["count"],
                "avg_confidence": round(r["avg_confidence"] or 0.0, 4),
            }
            for r in rows
        ]
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    # -- Anomalies ----------------------------------------------------------

    def get_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        hours: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return detections with anomaly scores above threshold.

        Parameters
        ----------
        min_score : float
            Minimum anomaly score.
        limit : int
            Maximum results.
        node_id : str or None
            Optional node filter.
        hours : int or None
            Optional time window in hours.

        Returns
        -------
        list[dict]
            Anomalous detection records sorted by score descending.
        """
        cache_key = TTLCache.make_key(
            "get_anomalies",
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            hours=hours,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        if hours is not None:
            # Bind a Python-computed cutoff in the stored format
            # (isoformat, 'T' separator): text-comparing the column with
            # SQLite's datetime('now', ...) (' ' separator) made every row
            # since UTC midnight match.  Plain column comparison keeps the
            # timestamp index usable.
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            clauses.append("timestamp >= ?")
            params.append(cutoff)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM detections
            WHERE {where}
            ORDER BY anomaly_score DESC, timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        result = [dict(r) for r in rows]
        self._ctx.cache.put(cache_key, result, ttl=3.0)
        return result

    # -- Cached count helpers -----------------------------------------------

    def get_active_anomaly_count(self, threshold: float = 0.3) -> int:
        """Count detections with anomaly_score >= *threshold*.

        Parameters
        ----------
        threshold : float
            Minimum anomaly score.

        Returns
        -------
        int
            Number of matching detections.
        """
        cache_key = TTLCache.make_key(
            "get_active_anomaly_count",
            threshold=threshold,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM detections WHERE {tf_clause} AND anomaly_score >= ?",
            tf_params + [threshold],
        ).fetchone()
        result = row["cnt"] if row else 0
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    def get_active_frequency_count(self, hours: int = 1) -> int:
        """Count distinct frequency buckets active in the last *hours*.

        Parameters
        ----------
        hours : int
            Lookback window.

        Returns
        -------
        int
            Number of distinct 100 kHz frequency buckets.
        """
        cache_key = TTLCache.make_key(
            "get_active_frequency_count",
            hours=hours,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(DISTINCT CAST(freq_hz / 100000 AS INTEGER)) as cnt "
            f"FROM detections WHERE {tf_clause} AND timestamp >= ? AND freq_hz > 0",
            tf_params + [cutoff],
        ).fetchone()
        result = row["cnt"] if row else 0
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    def get_active_frequencies(self, hours: int = 1) -> list[dict]:
        """Return active frequency buckets with detection counts.

        Returns list of dicts with keys: freq_mhz, count, classes.
        """
        cache_key = TTLCache.make_key(
            "get_active_frequencies",
            hours=hours,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT CAST(freq_hz / 100000 AS INTEGER) AS bucket, "
            f"COUNT(*) AS cnt, "
            f"GROUP_CONCAT(DISTINCT signal_class) AS classes, "
            f"GROUP_CONCAT(DISTINCT node_id) AS nodes, "
            f"ROUND(AVG(power_dbm), 1) AS avg_power "
            f"FROM detections WHERE {tf_clause} AND timestamp >= ? AND freq_hz > 0 "
            f"GROUP BY bucket ORDER BY cnt DESC",
            tf_params + [cutoff],
        ).fetchall()
        result = []
        for r in rows:
            bucket_val = r["bucket"]
            result.append(
                {
                    "freq_mhz": round(bucket_val * 0.1, 1),
                    "count": r["cnt"],
                    "classes": r["classes"] or "",
                    "nodes": r["nodes"] or "",
                    "avg_power_dbm": r["avg_power"],
                }
            )
        self._ctx.cache.put(cache_key, result, ttl=30.0)
        return result

    def get_threat_ribbon(
        self,
        hours: int = 1,
        threshold: float = 0.5,
        limit: int = 50,
    ) -> list[dict]:
        """Return recent high-anomaly events across all protocols.

        Queries the spectrum_all unified view to include RF detections,
        WiFi, Bluetooth, and Zigbee events with anomaly scores above
        the threshold.
        """
        cache_key = TTLCache.make_key(
            "get_threat_ribbon",
            hours=hours,
            threshold=threshold,
            limit=limit,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        # Prefer materialized table, fall back to view, then detections
        table = self._spectrum_table()
        try:
            rows = conn.execute(
                f"SELECT signal_class, freq_hz, power_dbm, timestamp, node_id, "
                f"anomaly_score "
                f"FROM {table} WHERE {tf_clause} AND timestamp >= ? "
                f"AND anomaly_score >= ? "
                f"ORDER BY anomaly_score DESC LIMIT ?",
                tf_params + [cutoff, threshold, limit],
            ).fetchall()
        except Exception:
            # Fallback to detections table only
            rows = conn.execute(
                f"SELECT signal_class, freq_hz, power_dbm, timestamp, node_id, "
                f"anomaly_score "
                f"FROM detections WHERE {tf_clause} AND timestamp >= ? "
                f"AND anomaly_score >= ? "
                f"ORDER BY anomaly_score DESC LIMIT ?",
                tf_params + [cutoff, threshold, limit],
            ).fetchall()

        result = [
            {
                "signal_class": r["signal_class"],
                "freq_hz": r["freq_hz"],
                "power_dbm": r["power_dbm"],
                "timestamp": r["timestamp"],
                "node_id": r["node_id"],
                "anomaly_score": r["anomaly_score"],
            }
            for r in rows
        ]
        self._ctx.cache.put(cache_key, result, ttl=15.0)
        return result

    # -- Aggregation --------------------------------------------------------

    def aggregate_hourly(self, tenant_id: str) -> int:
        """Roll up raw detections into hourly aggregates.

        Aggregates detections older than 1 hour into the
        ``detection_aggregates`` table.  Uses INSERT OR REPLACE
        to update existing aggregates.

        Parameters
        ----------
        tenant_id : str
            Tenant whose detections to aggregate.

        Returns
        -------
        int
            Number of aggregate rows written.
        """
        one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        sql = """
            INSERT OR REPLACE INTO detection_aggregates
                (hour, node_id, signal_class, family, detection_count,
                 avg_confidence, avg_snr_db, avg_power_dbm, avg_anomaly,
                 min_freq_hz, max_freq_hz, tenant_id, max_anomaly_score)
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                node_id,
                signal_class,
                family,
                COUNT(*) as detection_count,
                AVG(confidence) as avg_confidence,
                AVG(snr_db) as avg_snr_db,
                AVG(power_dbm) as avg_power_dbm,
                AVG(anomaly_score) as avg_anomaly,
                MIN(freq_hz) as min_freq_hz,
                MAX(freq_hz) as max_freq_hz,
                tenant_id,
                MAX(anomaly_score) as max_anomaly_score
            FROM detections
            WHERE tenant_id = ? AND timestamp < ?
            GROUP BY hour, node_id, signal_class, family
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, [tenant_id, one_hour_ago])
        self._ctx.cache.invalidate()  # aggregation reshapes data broadly
        count = cursor.rowcount
        logger.info("Aggregated %d hourly buckets for tenant %s", count, tenant_id)
        return count

    # -- Cleanup ------------------------------------------------------------

    def cleanup(self, tenant_id: str, max_age_days: int = 7) -> int:
        """Delete raw detections older than *max_age_days*.

        Should be called after ``aggregate_hourly()`` to ensure
        data is preserved in aggregates before deletion.

        Parameters
        ----------
        tenant_id : str
            Tenant whose detections to clean up.
        max_age_days : int
            Maximum age for raw detections.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()

        total_deleted = 0
        _BATCH_SIZE = 10_000
        while True:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM detections WHERE rowid IN ("
                    "  SELECT rowid FROM detections"
                    "  WHERE tenant_id = ? AND timestamp < ?"
                    "  LIMIT ?"
                    ")",
                    [tenant_id, cutoff, _BATCH_SIZE],
                )
            batch_deleted = cursor.rowcount
            total_deleted += batch_deleted
            if batch_deleted < _BATCH_SIZE:
                break

        if total_deleted > 0:
            self._ctx.cache.invalidate()
            logger.info(
                "Cleaned up %d detections older than %d days for tenant %s",
                total_deleted,
                max_age_days,
                tenant_id,
            )
        return total_deleted
