"""FHSS event storage sub-store.

Handles insert, query, and get-by-id operations for the ``fhss_events``
table.  Extracted to follow the same sub-store pattern used by other
domain stores (detection_crud, rf_anomalies, etc.).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any


logger = logging.getLogger(__name__)


class FHSSStore:
    """FHSS event CRUD operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------

    def insert_fhss_events(self, events: list[dict[str, Any]]) -> list[str]:
        """Bulk insert FHSS events.

        Parameters
        ----------
        events : list[dict]
            Each dict should contain keys matching the fhss_events schema.

        Returns
        -------
        list[str]
            The fhss_id values of inserted events.
        """
        if not events:
            return []

        tenant_id = self._ctx.tenant_id
        inserted_ids: list[str] = []

        rows = []
        for evt in events:
            fhss_id = evt.get("fhss_id", "")
            if not fhss_id:
                continue

            hop_set = evt.get("hop_set", [])
            hop_set_json = (
                json.dumps(hop_set) if isinstance(hop_set, list) else str(hop_set)
            )

            rows.append(
                (
                    fhss_id,
                    evt.get("node_id", ""),
                    evt.get("timestamp", ""),
                    evt.get("hop_rate_hz", 0.0),
                    hop_set_json,
                    evt.get("bandwidth_hz", 0.0),
                    evt.get("dwell_time_ms", 0.0),
                    evt.get("duration_sec", 0.0),
                    evt.get("signal_class", ""),
                    evt.get("detection_count", 0),
                    evt.get("confidence", 0.0),
                    tenant_id,
                )
            )
            inserted_ids.append(fhss_id)

        if not rows:
            return []

        sql = """
            INSERT INTO fhss_events (
                fhss_id, node_id, timestamp, hop_rate_hz,
                hop_set, bandwidth_hz, dwell_time_ms,
                duration_sec, signal_class, detection_count,
                confidence, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fhss_id) DO NOTHING
        """

        with self._ctx.write_transaction() as conn:
            conn.executemany(sql, rows)
        logger.debug("Inserted %d FHSS events", len(rows))

        return inserted_ids

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_fhss_events(
        self,
        hours: int = 24,
        node_id: str | None = None,
        min_hop_rate: float | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query FHSS events with filters.

        Parameters
        ----------
        hours : int
            Lookback window in hours.
        node_id : str or None
            Optional node filter.
        min_hop_rate : float or None
            Minimum hop rate filter.
        limit : int
            Maximum results.
        offset : int
            Pagination offset.

        Returns
        -------
        list[dict]
            Matching FHSS event records.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        if min_hop_rate is not None:
            clauses.append("hop_rate_hz >= ?")
            params.append(min_hop_rate)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM fhss_events
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Single record
    # ------------------------------------------------------------------

    def get_fhss_event_by_id(self, fhss_id: str) -> dict[str, Any] | None:
        """Get a single FHSS event by its ID.

        Parameters
        ----------
        fhss_id : str
            FHSS event ID.

        Returns
        -------
        dict or None
            FHSS event record, or None if not found.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "fhss_id = ?"]
        params: list[Any] = list(tf_params) + [fhss_id]

        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT * FROM fhss_events WHERE {where}",
            params,
        ).fetchone()
        return self._row_to_dict(row) if row is not None else None

    # ------------------------------------------------------------------
    # Count
    # ------------------------------------------------------------------

    def count_fhss_events(
        self,
        hours: int = 24,
        node_id: str | None = None,
    ) -> int:
        """Count FHSS events matching filters.

        Parameters
        ----------
        hours : int
            Lookback window in hours.
        node_id : str or None
            Optional node filter.

        Returns
        -------
        int
            Number of matching events.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM fhss_events WHERE {where}",
            params,
        ).fetchone()
        return row["cnt"]

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_fhss_events(self, max_age_days: int = 30) -> int:
        """Delete FHSS events older than *max_age_days*.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM fhss_events WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Dedup / summarization
    # ------------------------------------------------------------------

    def dedup_to_summaries(self, window_hours: int = 1) -> int:
        """Group FHSS events into hourly summary bins."""
        import hashlib as _hashlib
        import json as _json

        conn = self._ctx.get_conn()
        rows = conn.execute("""
            SELECT
                strftime('%Y-%m-%dT%H:00:00Z', timestamp) AS window_start,
                node_id,
                hop_set,
                signal_class,
                AVG(hop_rate_hz) AS hop_rate_hz,
                AVG(bandwidth_hz) AS bandwidth_hz,
                COUNT(*) AS occurrence_count,
                AVG(confidence) AS avg_confidence,
                MAX(confidence) AS max_confidence,
                AVG(dwell_time_ms) AS avg_dwell_time_ms,
                SUM(duration_sec) AS total_duration_sec,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen
            FROM fhss_events
            GROUP BY window_start, node_id, hop_set, signal_class
        """).fetchall()

        if not rows:
            return 0

        insert_sql = """
            INSERT OR REPLACE INTO fhss_event_summaries
                (window_start, node_id, hop_rate_hz, hop_set_hash, bandwidth_hz,
                 signal_class, occurrence_count, avg_confidence, max_confidence,
                 avg_dwell_time_ms, total_duration_sec, first_seen, last_seen, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        insert_rows = []
        for r in rows:
            hop_set_str = r[2] or "[]"
            try:
                hop_set_hash = _hashlib.sha256(
                    _json.dumps(sorted(_json.loads(hop_set_str))).encode()
                ).hexdigest()[:16]
            except (ValueError, TypeError):
                hop_set_hash = _hashlib.sha256(hop_set_str.encode()).hexdigest()[:16]

            insert_rows.append(
                (
                    r[0],  # window_start
                    r[1],  # node_id
                    r[4],  # hop_rate_hz
                    hop_set_hash,
                    r[5],  # bandwidth_hz
                    r[3],  # signal_class
                    r[6],  # occurrence_count
                    r[7],  # avg_confidence
                    r[8],  # max_confidence
                    r[9],  # avg_dwell_time_ms
                    r[10],  # total_duration_sec
                    r[11],  # first_seen
                    r[12],  # last_seen
                    self._ctx.tenant_id,
                )
            )

        with self._ctx.write_transaction() as conn:
            conn.executemany(insert_sql, insert_rows)

        logger.info("FHSS dedup: %d summary rows from raw events", len(insert_rows))
        return len(insert_rows)

    def cleanup_raw_fhss(self, max_age_days: int = 7) -> int:
        """Delete raw FHSS events older than threshold (already summarized)."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM fhss_events WHERE timestamp < ?", (cutoff,)
            )
            count = cursor.rowcount

        if count > 0:
            logger.info("Cleaned up %d old raw FHSS events", count)
        return count

    def cleanup_fhss_summaries(self, max_age_days: int = 90) -> int:
        """Delete old FHSS summary rows."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM fhss_event_summaries WHERE window_start < ?",
                (cutoff,),
            )
            count = cursor.rowcount

        if count > 0:
            logger.info("Cleaned up %d old FHSS summary rows", count)
        return count

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row) -> dict[str, Any]:
        """Convert a sqlite3.Row to a dict, parsing JSON fields."""
        d = dict(row)
        # Parse hop_set from JSON string
        hop_set_raw = d.get("hop_set", "[]")
        if isinstance(hop_set_raw, str):
            try:
                d["hop_set"] = json.loads(hop_set_raw)
            except (json.JSONDecodeError, TypeError):
                d["hop_set"] = []
        return d
