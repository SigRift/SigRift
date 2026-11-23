"""Emitter persistence sub-store.

Stores discovered emitter associations in SQLite. Each emitter record
captures the clustering result (primary frequency, bandwidth, signal
class, power profile, activity pattern, associated nodes, detection
count, and time range).

The table is created via a numbered migration in ``base.py``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any


logger = logging.getLogger(__name__)


class EmitterStore:
    """CRUD operations for the ``emitters`` table.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # Upsert (replace-on-conflict by emitter_id + tenant)
    # ------------------------------------------------------------------

    def upsert_emitters(self, emitters: list[dict[str, Any]]) -> int:
        """Insert or replace emitter records.

        Parameters
        ----------
        emitters : list[dict]
            Emitter dicts as produced by ``Emitter.model_dump()``.

        Returns
        -------
        int
            Number of rows upserted.
        """
        if not emitters:
            return 0

        tenant_id = self._ctx.tenant_id
        now = datetime.now(timezone.utc).isoformat()

        rows = []
        for e in emitters:
            rows.append(
                (
                    e.get("emitter_id", ""),
                    e.get("primary_freq_hz", 0.0),
                    e.get("bandwidth_hz", 0.0),
                    e.get("signal_class", ""),
                    json.dumps(e.get("power_profile", {})),
                    json.dumps(e.get("activity_pattern", {})),
                    json.dumps(e.get("associated_nodes", [])),
                    e.get("first_seen", now),
                    e.get("last_seen", now),
                    e.get("detection_count", 0),
                    json.dumps(e.get("detection_ids", [])[:500]),
                    now,
                    tenant_id,
                )
            )

        sql = """
            INSERT OR REPLACE INTO emitters (
                emitter_id, primary_freq_hz, bandwidth_hz, signal_class,
                power_profile, activity_pattern, associated_nodes,
                first_seen, last_seen, detection_count,
                detection_ids, updated_at, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self._ctx.write_transaction() as conn:
            conn.executemany(sql, rows)
        logger.debug("Upserted %d emitters", len(rows))
        return len(rows)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_emitters(
        self,
        limit: int = 100,
        offset: int = 0,
        signal_class: str | None = None,
        min_detections: int = 0,
    ) -> list[dict[str, Any]]:
        """List discovered emitters.

        Parameters
        ----------
        limit : int
            Maximum results (default 100).
        offset : int
            Pagination offset.
        signal_class : str or None
            Optional filter by signal class.
        min_detections : int
            Minimum detection count filter.

        Returns
        -------
        list[dict]
            Emitter records with JSON fields parsed.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause]
        params: list[Any] = list(tf_params)

        if signal_class:
            clauses.append("signal_class = ?")
            params.append(signal_class)
        if min_detections > 0:
            clauses.append("detection_count >= ?")
            params.append(min_detections)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM emitters
            WHERE {where}
            ORDER BY detection_count DESC, last_seen DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        return [self._parse_row(r) for r in rows]

    def get_emitter(self, emitter_id: str) -> dict[str, Any] | None:
        """Get a single emitter by ID.

        Parameters
        ----------
        emitter_id : str
            Emitter identifier.

        Returns
        -------
        dict or None
            Emitter record with parsed JSON fields, or None.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = f"""
            SELECT * FROM emitters
            WHERE emitter_id = ? AND {tf_clause}
        """
        params = [emitter_id] + tf_params

        conn = self._ctx.get_conn()
        row = conn.execute(sql, params).fetchone()
        return self._parse_row(row) if row else None

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_all(self) -> int:
        """Delete all emitters for the current tenant.

        Returns
        -------
        int
            Number of rows deleted.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM emitters WHERE {tf_clause}",
                tf_params,
            )
        return cursor.rowcount

    def count(self) -> int:
        """Return total number of emitter records for the current tenant."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM emitters WHERE {tf_clause}",
            tf_params,
        ).fetchone()
        return row["cnt"]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_row(row: Any) -> dict[str, Any]:
        """Convert a sqlite3.Row to a dict, parsing JSON fields."""
        d = dict(row)
        for key in (
            "power_profile",
            "activity_pattern",
            "associated_nodes",
            "detection_ids",
        ):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d
