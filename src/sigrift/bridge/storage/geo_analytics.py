"""Geolocation analytics queries.

Sub-store that provides geo-scoped detection queries for map summaries,
heatmaps, coverage areas, and activity feeds.  All queries run against
the existing ``detections`` table with proper tenant isolation.
"""

from __future__ import annotations

import logging
from typing import Any


logger = logging.getLogger(__name__)


class GeoAnalyticsStore:
    """Geo-scoped detection queries on the detections table.

    Parameters
    ----------
    ctx : SharedContext
        Shared storage infrastructure (connection, lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # -- Node map summary ---------------------------------------------------

    def get_node_detection_summary(
        self,
        node_id: str,
        cutoff_iso: str,
    ) -> dict[str, Any]:
        """Return detection count, top signals, and anomaly count for a node.

        Parameters
        ----------
        node_id : str
            The node to query.
        cutoff_iso : str
            ISO timestamp cutoff (only detections >= this are counted).

        Returns
        -------
        dict with keys: detection_count, top_signals, anomaly_count
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        # Detection count
        where = f"{tf_clause} AND node_id = ? AND timestamp >= ?"
        params: list[Any] = tf_params + [node_id, cutoff_iso]

        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM detections WHERE {where}",
            params,
        ).fetchone()
        det_count = row["cnt"] if row else 0

        # Top signal classes
        top_rows = conn.execute(
            f"SELECT signal_class, COUNT(*) as cnt FROM detections "
            f"WHERE {where} "
            f"GROUP BY signal_class ORDER BY cnt DESC LIMIT 5",
            params,
        ).fetchall()
        top_signals = [r["signal_class"] for r in top_rows]

        # Anomaly count
        anom_row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM detections "
            f"WHERE {where} AND anomaly_score >= 0.3",
            params,
        ).fetchone()
        anomaly_count = anom_row["cnt"] if anom_row else 0

        return {
            "detection_count": det_count,
            "top_signals": top_signals,
            "anomaly_count": anomaly_count,
        }

    # -- Heatmap ------------------------------------------------------------

    def get_heatmap_weight(
        self,
        node_id: str,
        cutoff_iso: str,
        signal_class: str | None = None,
    ) -> int:
        """Return detection count for a node within the time window.

        Parameters
        ----------
        node_id : str
            The node to query.
        cutoff_iso : str
            ISO timestamp cutoff.
        signal_class : str or None
            Optional signal class filter.

        Returns
        -------
        int
            Number of matching detections.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        clauses = [tf_clause, "node_id = ?", "timestamp >= ?"]
        params: list[Any] = tf_params + [node_id, cutoff_iso]

        if signal_class:
            clauses.append("signal_class = ?")
            params.append(signal_class)

        where = " AND ".join(clauses)
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM detections WHERE {where}",
            params,
        ).fetchone()
        return row["cnt"] if row else 0

    # -- Coverage -----------------------------------------------------------

    def get_coverage_stats(
        self,
        node_id: str,
    ) -> dict[str, Any]:
        """Return distinct signal classes and average SNR for a node.

        Parameters
        ----------
        node_id : str
            The node to query.

        Returns
        -------
        dict with keys: detection_classes, avg_snr_db
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        where = f"{tf_clause} AND node_id = ?"
        params: list[Any] = tf_params + [node_id]

        class_rows = conn.execute(
            f"SELECT DISTINCT signal_class FROM detections WHERE {where}",
            params,
        ).fetchall()
        detection_classes = [r["signal_class"] for r in class_rows]

        snr_row = conn.execute(
            f"SELECT AVG(snr_db) as avg_snr FROM detections "
            f"WHERE {where} AND snr_db IS NOT NULL",
            params,
        ).fetchone()
        avg_snr = (
            snr_row["avg_snr"] if snr_row and snr_row["avg_snr"] is not None else 0.0
        )

        return {
            "detection_classes": detection_classes,
            "avg_snr_db": round(avg_snr, 2),
        }

    # -- Activity feed ------------------------------------------------------

    def get_activity_feed(
        self,
        node_ids: list[str],
        cutoff_iso: str,
        min_anomaly_score: float | None = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return recent detections for located nodes.

        Parameters
        ----------
        node_ids : list[str]
            Node IDs to include.
        cutoff_iso : str
            ISO timestamp cutoff.
        min_anomaly_score : float or None
            Optional minimum anomaly score filter.
        limit : int
            Maximum results to return.

        Returns
        -------
        list[dict]
            Raw detection rows as dicts.
        """
        if not node_ids:
            return []

        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        placeholders = ",".join("?" for _ in node_ids)
        clauses = [tf_clause, f"node_id IN ({placeholders})", "timestamp >= ?"]
        params: list[Any] = tf_params + list(node_ids) + [cutoff_iso]

        if min_anomaly_score is not None:
            clauses.append("anomaly_score >= ?")
            params.append(min_anomaly_score)

        where = " AND ".join(clauses)
        sql = (
            "SELECT detection_id, node_id, signal_class, confidence, freq_hz, "
            "snr_db, power_dbm, anomaly_score, timestamp "
            f"FROM detections WHERE {where} "
            "ORDER BY timestamp DESC LIMIT ?"
        )
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
