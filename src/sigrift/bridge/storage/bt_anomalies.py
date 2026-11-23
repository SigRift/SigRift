"""Bluetooth anomaly CRUD and management sub-store.

Handles insert, query, dismiss, snooze, and cleanup for the
``bt_anomalies`` table.  Follows the same architecture as
``WiFiAnomalyStore``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag, TTLCache
from sigrift.bridge.storage.base import ACTIVE_FILTER as _BASE_ACTIVE_FILTER

logger = logging.getLogger(__name__)


class BtAnomalyStore:
    """Bluetooth anomaly operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    # Filter clause for "active" anomalies: not dismissed AND not snoozed
    # (one definition, see storage.base.ACTIVE_FILTER).
    ACTIVE_FILTER = _BASE_ACTIVE_FILTER

    _BT_ANOMALY_BASE_COLS = (
        "id, device_addr, device_name, device_type, device_class, "
        "device_class_name, manufacturer, vendor, rssi_dbm, "
        "anomaly_score, priority, dimensions, reasons, baseline_status, "
        "node_id, timestamp, dismissed, snoozed_until, "
        "seen_count, first_seen, device_count_nearby, "
        "service_uuids, adv_data, "
        "expected_rssi, rssi_zscore, baseline_observations, node_ids"
    )

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # Insert / upsert
    # ------------------------------------------------------------------

    def insert_bt_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
    ) -> list[int]:
        """Upsert Bluetooth anomaly records, deduplicating by device_addr.

        Dedup includes dismissed rows: finds the most recent row per
        device_addr regardless of dismissed/snoozed status.  If the most
        recent row is dismissed, it is un-dismissed and updated.  Snoozed
        rows are updated (seen_count incremented) but remain snoozed.

        Parameters
        ----------
        anomalies : list[dict]
            Anomaly dicts with keys matching bt_anomalies columns.

        Returns
        -------
        list[int]
            Row IDs of upserted anomalies (same order as input).
        """
        if not anomalies:
            return []

        insert_sql = """
            INSERT INTO bt_anomalies (
                device_addr, device_name, device_type, device_class,
                device_class_name, manufacturer, vendor, rssi_dbm,
                anomaly_score, priority, dimensions, reasons,
                baseline_status, node_id, timestamp, first_seen,
                device_count_nearby, service_uuids, adv_data,
                expected_rssi, rssi_zscore, baseline_observations,
                node_ids, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?)
        """

        update_sql = """
            UPDATE bt_anomalies SET
                device_name = ?, device_type = ?, device_class = ?,
                device_class_name = ?, manufacturer = ?, vendor = ?,
                rssi_dbm = ?, anomaly_score = ?, priority = ?,
                dimensions = ?, reasons = ?, baseline_status = ?,
                node_id = ?, timestamp = ?,
                device_count_nearby = ?, service_uuids = ?, adv_data = ?,
                expected_rssi = ?, rssi_zscore = ?, baseline_observations = ?,
                node_ids = ?,
                seen_count = seen_count + 1,
                dismissed = 0
            WHERE id = ?
        """

        update_snoozed_sql = """
            UPDATE bt_anomalies SET
                device_name = ?, device_type = ?, device_class = ?,
                device_class_name = ?, manufacturer = ?, vendor = ?,
                rssi_dbm = ?, anomaly_score = ?, priority = ?,
                dimensions = ?, reasons = ?, baseline_status = ?,
                node_id = ?, timestamp = ?,
                device_count_nearby = ?, service_uuids = ?, adv_data = ?,
                expected_rssi = ?, rssi_zscore = ?, baseline_observations = ?,
                node_ids = ?,
                seen_count = seen_count + 1
            WHERE id = ?
        """

        row_ids: list[int] = []
        with self._ctx.write_transaction() as conn:
            # Batch dedup lookup
            addrs = list(
                {a.get("device_addr", "") for a in anomalies if a.get("device_addr")}
            )
            existing_map: dict[str, tuple[int, bool, int, dict]] = {}
            tf_clause, tf_params = self._ctx.tenant_filter()
            if addrs:
                ph = ",".join("?" for _ in addrs)
                for row in conn.execute(
                    f"SELECT w.id, w.device_addr, w.snoozed_until, w.seen_count, w.node_ids "
                    f"FROM bt_anomalies w "
                    f"INNER JOIN (SELECT MAX(id) as max_id FROM bt_anomalies "
                    f"  WHERE {tf_clause} AND device_addr IN ({ph}) GROUP BY device_addr) sub "
                    f"ON w.id = sub.max_id",
                    tf_params + addrs,
                ).fetchall():
                    is_snoozed = (
                        row["snoozed_until"] is not None
                        and row["snoozed_until"]
                        > datetime.now(timezone.utc).isoformat()
                    )
                    try:
                        prev_nodes = json.loads(row["node_ids"] or "{}")
                    except (json.JSONDecodeError, TypeError):
                        prev_nodes = {}
                    existing_map[row["device_addr"]] = (
                        row["id"],
                        is_snoozed,
                        row["seen_count"] or 0,
                        prev_nodes,
                    )

            for a in anomalies:
                device_addr = a.get("device_addr", "")
                ts = a.get("timestamp", datetime.now(timezone.utc).isoformat())

                dims = json.dumps(a.get("dimensions", {}))
                reasons = json.dumps(a.get("reasons", []))
                svc_uuids = json.dumps(a.get("service_uuids", []))
                adv = json.dumps(a.get("adv_data", {}))

                # Build merged node_ids map: {node_id: rssi_dbm}
                cur_node = a.get("node_id", "")
                cur_rssi = a.get("rssi_dbm", 0.0)

                existing = existing_map.get(device_addr)
                if existing is not None:
                    existing_id, is_snoozed, seen_count, prev_nodes = existing
                    # Merge: keep strongest RSSI per node
                    merged_nodes = dict(prev_nodes)
                    if cur_node:
                        prev_rssi = merged_nodes.get(cur_node)
                        if prev_rssi is None or cur_rssi > prev_rssi:
                            merged_nodes[cur_node] = cur_rssi
                    merged_json = json.dumps(merged_nodes)

                    update_params = (
                        a.get("device_name", ""),
                        a.get("device_type", "unknown"),
                        a.get("device_class", 0),
                        a.get("device_class_name", ""),
                        a.get("manufacturer", ""),
                        a.get("vendor", ""),
                        a.get("rssi_dbm", 0.0),
                        a.get("anomaly_score", 0.0),
                        a.get("priority", "normal"),
                        dims,
                        reasons,
                        a.get("baseline_status", "stable"),
                        a.get("node_id", ""),
                        ts,
                        a.get("device_count_nearby", 0),
                        svc_uuids,
                        adv,
                        a.get("expected_rssi"),
                        a.get("rssi_zscore", 0.0),
                        a.get("baseline_observations", 0),
                        merged_json,
                        existing_id,
                    )
                    if is_snoozed:
                        conn.execute(update_snoozed_sql, update_params)
                    else:
                        conn.execute(update_sql, update_params)

                    row_ids.append(existing_id)
                    existing_map[device_addr] = (
                        existing_id,
                        is_snoozed,
                        seen_count + 1,
                        merged_nodes,
                    )
                else:
                    new_nodes = {cur_node: cur_rssi} if cur_node else {}
                    new_nodes_json = json.dumps(new_nodes)
                    cursor = conn.execute(
                        insert_sql,
                        (
                            device_addr,
                            a.get("device_name", ""),
                            a.get("device_type", "unknown"),
                            a.get("device_class", 0),
                            a.get("device_class_name", ""),
                            a.get("manufacturer", ""),
                            a.get("vendor", ""),
                            a.get("rssi_dbm", 0.0),
                            a.get("anomaly_score", 0.0),
                            a.get("priority", "normal"),
                            dims,
                            reasons,
                            a.get("baseline_status", "stable"),
                            a.get("node_id", ""),
                            ts,
                            ts,
                            a.get("device_count_nearby", 0),
                            svc_uuids,
                            adv,
                            a.get("expected_rssi"),
                            a.get("rssi_zscore", 0.0),
                            a.get("baseline_observations", 0),
                            new_nodes_json,
                            self._ctx.tenant_id,
                        ),
                    )
                    new_id = cursor.lastrowid
                    row_ids.append(new_id)
                    existing_map[device_addr] = (new_id, False, 1, new_nodes)
        self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)
        logger.debug("Upserted %d bt anomaly records", len(row_ids))
        return row_ids

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_bt_anomalies(
        self,
        min_score: float = 0.0,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
    ) -> list[dict[str, Any]]:
        """Return Bluetooth anomalies above threshold.

        Parameters
        ----------
        min_score : float
            Minimum anomaly score.
        limit : int
            Maximum results.
        node_id : str or None
            Optional node filter.
        include_dismissed : bool
            Whether to include dismissed anomalies.

        Returns
        -------
        list[dict]
            Anomaly records sorted by score descending.
        """
        cache_key = TTLCache.make_key(
            "get_bt_anomalies",
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]

        if not include_dismissed:
            clauses.append(self.ACTIVE_FILTER)

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT {self._BT_ANOMALY_BASE_COLS} FROM bt_anomalies
            WHERE {where}
            ORDER BY anomaly_score DESC, timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            for key, default in (
                ("dimensions", {}),
                ("reasons", []),
                ("service_uuids", []),
                ("adv_data", {}),
                ("node_ids", {}),
            ):
                if key in entry and entry[key]:
                    try:
                        entry[key] = json.loads(entry[key])
                    except (json.JSONDecodeError, TypeError):
                        entry[key] = default
                elif key in entry:
                    entry[key] = default
            results.append(entry)
        self._ctx.cache.put(cache_key, results, ttl=3.0)
        return results

    def count_bt_anomalies(
        self,
        min_score: float = 0.0,
        include_dismissed: bool = False,
    ) -> int:
        """Return total count of Bluetooth anomalies matching filters."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]
        if not include_dismissed:
            clauses.append(self.ACTIVE_FILTER)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM bt_anomalies WHERE {where}", params
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Dismiss / snooze
    # ------------------------------------------------------------------

    def dismiss_bt_anomaly(self, anomaly_id: int) -> None:
        """Mark a Bluetooth anomaly as dismissed."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE bt_anomalies SET dismissed = 1 WHERE {tf_clause} AND id = ?",
                tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)

    def dismiss_bt_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        """Bulk dismiss Bluetooth anomalies.

        Parameters
        ----------
        anomaly_ids : list[int]
            Row IDs of anomalies to dismiss.

        Returns
        -------
        int
            Number of rows updated.
        """
        if not anomaly_ids:
            return 0
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in anomaly_ids)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE bt_anomalies SET dismissed = 1 WHERE {tf_clause} AND id IN ({placeholders})",
                tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)
        return cursor.rowcount

    def snooze_bt_anomaly(self, anomaly_id: int, until: str) -> None:
        """Snooze a Bluetooth anomaly until the given ISO timestamp."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE bt_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id = ?",
                [until] + tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)

    def snooze_bt_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        """Bulk snooze Bluetooth anomalies until the given ISO timestamp."""
        if not anomaly_ids:
            return 0
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in anomaly_ids)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE bt_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id IN ({placeholders})",
                [until] + tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def compact_dismissed_bt_anomalies(self) -> int:
        """Keep only the most recent row per device_addr among dismissed records.

        Returns
        -------
        int
            Number of rows deleted.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = f"""
            DELETE FROM bt_anomalies WHERE {tf_clause} AND dismissed = 1
            AND id NOT IN (
                SELECT MAX(id) FROM bt_anomalies
                WHERE {tf_clause} AND dismissed = 1 GROUP BY device_addr
            )
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, tf_params + tf_params)
        deleted = cursor.rowcount
        if deleted > 0:
            self._ctx.cache.invalidate_prefix(CacheTag.GET_BT_ANOMAL, CacheTag.COUNT_BT)
            logger.info(
                "Compacted %d duplicate dismissed bt anomaly rows",
                deleted,
            )
        return deleted

    def cleanup_bt_anomalies(self, max_age_days: int = 30) -> int:
        """Delete Bluetooth anomalies older than *max_age_days*.

        Parameters
        ----------
        max_age_days : int
            Maximum age for Bluetooth anomaly records.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM bt_anomalies WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d bt anomalies older than %d days",
                deleted,
                max_age_days,
            )
        return deleted
