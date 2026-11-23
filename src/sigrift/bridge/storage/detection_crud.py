"""Detection CRUD operations sub-store.

Handles insert, query, get-by-id, recent lookups, IQ-capture flagging,
and row counting for the ``detections`` table.  Extracted from the
monolithic ``DetectionStore`` to keep modules focused.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag, TTLCache
from sigrift.bridge.models import DetectionQuery, DetectionRecord

logger = logging.getLogger(__name__)

#: Signal class of the stub detection ``PUT /api/detections/{id}/iq``
#: records for a capture whose detection is not stored (yet).
IQ_STUB_SIGNAL_CLASS = "iq_capture"


class DetectionCrudStore:
    """Detection CRUD operations backed by a :class:`SharedContext`.

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

    def insert_batch(self, detections: list[DetectionRecord]) -> int:
        """Bulk insert detection records.

        Parameters
        ----------
        detections : list[DetectionRecord]
            Records to insert.  Duplicate ``detection_id`` values are
            silently ignored (ON CONFLICT DO NOTHING) — except that a real
            detection replaces the IQ route's stub row for its id (see
            :meth:`_insert`).

        Returns
        -------
        int
            Number of rows actually inserted (stubs replaced included).
        """
        if not detections:
            return 0
        return self._insert(detections, None)

    def insert_batch_new_ids(self, detections: list[DetectionRecord]) -> set[str]:
        """Insert like :meth:`insert_batch`; return the ids that were new.

        A detection whose id is stored already (by this or any other
        process, or earlier in *detections*) is not in the result: callers
        run once-per-detection work (alerts) for the result only.  A
        detection that replaced the IQ route's stub for its id is new: the
        stub was never ingested as a detection.
        """
        new_ids: set[str] = set()
        if detections:
            self._insert(detections, new_ids)
        return new_ids

    def _insert(
        self, detections: list[DetectionRecord], new_ids: set[str] | None
    ) -> int:
        """Insert *detections*; with *new_ids*, collect the ids inserted.

        An edge may upload a detection's IQ before the detection reaches
        the bridge (the IQ of a detection reported while the previous
        flush was in flight).  The IQ route then stores a stub row for the
        id (class :data:`IQ_STUB_SIGNAL_CLASS`, confidence and anomaly
        score 0, the uploader's node).  The real detection, from the same
        node, takes that row over — counted as inserted — instead of
        being dropped as a duplicate, so its alerts, rules and decode
        still run.  The row's ``has_iq_capture`` flag is kept.
        """

        def _ts(v):
            if isinstance(v, (int, float)):
                return datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
            return v.isoformat()

        tenant_id = self._ctx.tenant_id
        rows = [
            (
                d.detection_id,
                d.node_id,
                _ts(d.timestamp),
                d.signal_class,
                d.confidence,
                d.family,
                d.freq_hz,
                d.snr_db,
                d.power_dbm,
                d.inference_ms,
                d.backend,
                d.anomaly_score,
                d.baseline_status,
                d.gain_db,
                d.lna_state,
                d.bandwidth_hz,
                getattr(d, "refined_class", ""),
                tenant_id,
            )
            for d in detections
        ]

        sql = f"""
            INSERT INTO detections (
                detection_id, node_id, timestamp, signal_class,
                confidence, family, freq_hz, snr_db, power_dbm,
                inference_ms, backend, anomaly_score, baseline_status,
                gain_db, lna_state, bandwidth_hz, refined_class, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(detection_id) DO UPDATE SET
                timestamp = excluded.timestamp,
                signal_class = excluded.signal_class,
                confidence = excluded.confidence,
                family = excluded.family,
                freq_hz = excluded.freq_hz,
                snr_db = excluded.snr_db,
                power_dbm = excluded.power_dbm,
                inference_ms = excluded.inference_ms,
                backend = excluded.backend,
                anomaly_score = excluded.anomaly_score,
                baseline_status = excluded.baseline_status,
                gain_db = excluded.gain_db,
                lna_state = excluded.lna_state,
                bandwidth_hz = excluded.bandwidth_hz,
                refined_class = excluded.refined_class
            WHERE detections.signal_class = '{IQ_STUB_SIGNAL_CLASS}'
              AND excluded.signal_class != '{IQ_STUB_SIGNAL_CLASS}'
              AND detections.confidence = 0
              AND detections.anomaly_score = 0
              AND detections.node_id = excluded.node_id
              AND detections.tenant_id = excluded.tenant_id
        """

        with self._ctx.write_transaction() as conn:
            if new_ids is None:
                inserted = conn.executemany(sql, rows).rowcount
            else:
                # Row by row: rowcount says which rows were new.
                inserted = 0
                for row in rows:
                    if conn.execute(sql, row).rowcount == 1:
                        new_ids.add(row[0])
                        inserted += 1
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RECENT,
            CacheTag.GET_STATS,
            CacheTag.GET_TIMELINE,
            CacheTag.GET_ANOMALIES,
        )
        logger.debug("Inserted %d/%d detections", inserted, len(rows))
        return inserted

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query(self, q: DetectionQuery) -> list[dict[str, Any]]:
        """Query detections with filters.

        Parameters
        ----------
        q : DetectionQuery
            Filter parameters.

        Returns
        -------
        list[dict]
            Matching detection records.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause]
        params: list[Any] = list(tf_params)

        if q.start is not None:
            clauses.append("timestamp >= ?")
            params.append(q.start.isoformat())
        if q.end is not None:
            clauses.append("timestamp <= ?")
            params.append(q.end.isoformat())
        if q.node_id is not None:
            clauses.append("node_id = ?")
            params.append(q.node_id)
        if q.signal_class is not None:
            clauses.append("signal_class = ?")
            params.append(q.signal_class)
        if q.family is not None:
            clauses.append("family = ?")
            params.append(q.family)
        if q.min_confidence > 0.0:
            clauses.append("confidence >= ?")
            params.append(q.min_confidence)

        where = " AND ".join(clauses) if clauses else "1=1"
        sql = f"""
            SELECT * FROM detections
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([q.limit, q.offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Recent
    # ------------------------------------------------------------------

    def get_recent(
        self,
        minutes: int = 5,
        node_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return recent detections within the last *minutes*.

        Parameters
        ----------
        minutes : int
            Lookback window in minutes.
        node_id : str or None
            Optional node filter.
        limit : int
            Maximum results.

        Returns
        -------
        list[dict]
            Recent detection records.
        """
        cache_key = TTLCache.make_key(
            "get_recent",
            minutes=minutes,
            node_id=node_id,
            limit=limit,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "timestamp >= ?"]
        params: list[Any] = list(tf_params) + [cutoff.isoformat()]

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM detections
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        result = [dict(r) for r in rows]
        self._ctx.cache.put(cache_key, result, ttl=3.0)
        return result

    # ------------------------------------------------------------------
    # Single record
    # ------------------------------------------------------------------

    def get_detection_by_id(self, detection_id: str) -> dict[str, Any] | None:
        """Get a single detection by its ID.

        Parameters
        ----------
        detection_id : str
            Detection ID.

        Returns
        -------
        dict or None
            Detection record, or None if not found.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "detection_id = ?"]
        params: list[Any] = list(tf_params) + [detection_id]

        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT * FROM detections WHERE {where}",
            params,
        ).fetchone()
        return dict(row) if row is not None else None

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def set_has_iq_capture(self, detection_id: str, value: bool = True) -> None:
        """Set the has_iq_capture flag for a detection.

        Parameters
        ----------
        detection_id : str
            Detection ID.
        value : bool
            Flag value (default True).
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE detections SET has_iq_capture = ? WHERE detection_id = ? AND {tf_clause}",
                [1 if value else 0, detection_id] + tf_params,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_RECENT, CacheTag.GET_ANOMALIES)

    # ------------------------------------------------------------------
    # Counts
    # ------------------------------------------------------------------

    def row_count(self) -> int:
        """Return total number of raw detection rows."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM detections WHERE {tf_clause}",
            tf_params,
        ).fetchone()
        return row["cnt"]
