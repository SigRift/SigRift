"""RF anomaly CRUD and management sub-store.

Handles insert (upsert), query, count, summary, dismiss, snooze,
and cleanup operations for the ``rf_anomalies`` table.  Extracted from
the monolithic ``DetectionStore`` to keep modules focused.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag, TTLCache
from sigrift.bridge.storage.base import ACTIVE_FILTER

logger = logging.getLogger(__name__)

# RF-specific active filter: extends the base filter to exclude stale-resolved
# anomalies.  The ``status`` column is added by migration 35; the
# ``status IS NULL`` guard keeps queries working on pre-migration databases.
_RF_ACTIVE_FILTER = ACTIVE_FILTER + " AND (status IS NULL OR status = 'active')"


class RFAnomalyStore:
    """RF anomaly operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _rf_dedup_key(signal_class: str, freq_hz: float) -> str:
        """Build dedup key for RF anomalies: signal_class|freq_100kHz_bucket."""
        return f"{signal_class}|{int(freq_hz / 100000)}"

    @staticmethod
    def _rf_priority(score: float) -> str:
        """Map anomaly score to priority label."""
        if score >= 0.7:
            return "critical"
        if score >= 0.5:
            return "anomalous"
        if score >= 0.3:
            return "interesting"
        return "normal"

    @staticmethod
    def _bucket_to_band_label(freq_hz: float) -> str:
        """Convert a frequency in Hz to a human-readable RF band label."""
        mhz = freq_hz / 1e6
        if 0.1 <= mhz < 0.5:
            return "LF"
        if 0.5 <= mhz < 1.7:
            return "MF/AM"
        if 1.7 <= mhz < 30:
            return "HF"
        if 30 <= mhz < 88:
            return "VHF Low"
        if 88 <= mhz < 108:
            return "FM Broadcast"
        if 108 <= mhz < 137:
            return "Airband"
        if 137 <= mhz < 174:
            return "VHF High"
        if 174 <= mhz < 216:
            return "VHF TV"
        if 216 <= mhz < 400:
            return "UHF Low"
        if 400 <= mhz < 470:
            return "ISM 433 MHz"
        if 470 <= mhz < 698:
            return "UHF TV"
        if 698 <= mhz < 960:
            return "Cellular 700-900"
        if 860 <= mhz < 930:
            return "ISM 900 MHz"
        if 960 <= mhz < 1800:
            return "L-Band"
        if 1800 <= mhz < 2200:
            return "Cellular 1800-2100"
        if 2200 <= mhz < 2500:
            return "ISM 2.4 GHz"
        if 2500 <= mhz < 4000:
            return "S-Band"
        if 4000 <= mhz < 8000:
            return "C-Band"
        if 5000 <= mhz < 6000:
            return "ISM 5 GHz"
        return f"{mhz:.0f} MHz"

    # ------------------------------------------------------------------
    # Insert / upsert
    # ------------------------------------------------------------------

    def insert_rf_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
        *,
        auto_snooze_seen_count: int = 0,
        auto_snooze_max_score: float = 0.0,
        auto_snooze_hours: int = 0,
    ) -> list[int]:
        """Upsert RF anomaly records, deduplicating by signal_class + freq_bucket.

        If an active (non-dismissed) anomaly already exists for the same
        dedup_key, updates it with the latest data and increments ``seen_count``.
        Otherwise inserts a new row.

        Parameters
        ----------
        anomalies : list[dict]
            Anomaly dicts with keys matching rf_anomalies columns.
        auto_snooze_seen_count : int
            If > 0, auto-snooze when seen_count reaches this threshold.
        auto_snooze_max_score : float
            Only auto-snooze if anomaly_score is below this value.
        auto_snooze_hours : int
            Duration of auto-snooze in hours.

        Returns
        -------
        list[int]
            Row IDs of upserted anomalies (same order as input).
        """
        if not anomalies:
            return []

        insert_sql = """
            INSERT INTO rf_anomalies (
                detection_id, signal_class, family, freq_hz, dedup_key,
                node_id, timestamp, confidence, snr_db, power_dbm,
                anomaly_score, priority, dimensions, reasons,
                baseline_status, has_iq_capture, first_seen, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        update_sql = """
            UPDATE rf_anomalies SET
                detection_id = ?, signal_class = ?, family = ?,
                freq_hz = ?, node_id = ?, timestamp = ?,
                confidence = ?, snr_db = ?, power_dbm = ?,
                anomaly_score = ?, priority = ?, dimensions = ?,
                reasons = ?, baseline_status = ?, has_iq_capture = ?,
                seen_count = seen_count + 1
            WHERE id = ?
        """

        row_ids: list[int] = []
        with self._ctx.write_transaction() as conn:
            # Batch dedup lookup: fetch all active RF anomalies for the dedup keys
            dedup_keys = list(
                {
                    self._rf_dedup_key(a.get("signal_class", ""), a.get("freq_hz", 0.0))
                    for a in anomalies
                }
            )
            # Maps dedup_key -> (id, seen_count)
            existing_map: dict[str, tuple[int, int]] = {}
            tf_clause, tf_params = self._ctx.tenant_filter()
            if dedup_keys:
                ph = ",".join("?" for _ in dedup_keys)
                try:
                    for row in conn.execute(
                        f"SELECT id, dedup_key, seen_count FROM rf_anomalies "
                        f"WHERE {tf_clause} AND dedup_key IN ({ph}) AND {_RF_ACTIVE_FILTER}",
                        tf_params + dedup_keys,
                    ).fetchall():
                        existing_map[row["dedup_key"]] = (
                            row["id"],
                            row["seen_count"] or 0,
                        )
                except sqlite3.OperationalError:
                    self._ctx.ensure_rf_anomalies_table(conn)

            for a in anomalies:
                signal_class = a.get("signal_class", "")
                freq_hz = a.get("freq_hz", 0.0)
                dedup_key = self._rf_dedup_key(signal_class, freq_hz)
                ts = a.get("timestamp", datetime.now(timezone.utc).isoformat())
                if isinstance(ts, (int, float)):
                    ts = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                elif hasattr(ts, "isoformat"):
                    ts = ts.isoformat()

                dims = json.dumps(a.get("dimensions", {}))
                reasons = json.dumps(a.get("reasons", []))
                priority = a.get("priority") or self._rf_priority(
                    a.get("anomaly_score", 0.0)
                )

                existing = existing_map.get(dedup_key)
                if existing is not None:
                    existing_id, seen_count = existing
                    conn.execute(
                        update_sql,
                        (
                            a.get("detection_id", ""),
                            signal_class,
                            a.get("family", ""),
                            freq_hz,
                            a.get("node_id", ""),
                            ts,
                            a.get("confidence", 0.0),
                            a.get("snr_db"),
                            a.get("power_dbm"),
                            a.get("anomaly_score", 0.0),
                            priority,
                            dims,
                            reasons,
                            a.get("baseline_status", "stable"),
                            1 if a.get("has_iq_capture") else 0,
                            existing_id,
                        ),
                    )

                    # Auto-snooze: check if seen_count threshold reached
                    new_seen = seen_count + 1
                    score = a.get("anomaly_score", 0.0)
                    if (
                        auto_snooze_seen_count > 0
                        and new_seen >= auto_snooze_seen_count
                        and score < auto_snooze_max_score
                        and auto_snooze_hours > 0
                    ):
                        snooze_until = (
                            datetime.now(timezone.utc)
                            + timedelta(hours=auto_snooze_hours)
                        ).isoformat()
                        conn.execute(
                            "UPDATE rf_anomalies SET snoozed_until = ? WHERE id = ?",
                            (snooze_until, existing_id),
                        )
                        logger.info(
                            "Auto-snoozed RF anomaly %d (key=%s, seen=%d, score=%.2f)",
                            existing_id,
                            dedup_key,
                            new_seen,
                            score,
                        )

                    row_ids.append(existing_id)
                    existing_map[dedup_key] = (existing_id, new_seen)
                else:
                    cursor = conn.execute(
                        insert_sql,
                        (
                            a.get("detection_id", ""),
                            signal_class,
                            a.get("family", ""),
                            freq_hz,
                            dedup_key,
                            a.get("node_id", ""),
                            ts,
                            a.get("confidence", 0.0),
                            a.get("snr_db"),
                            a.get("power_dbm"),
                            a.get("anomaly_score", 0.0),
                            priority,
                            dims,
                            reasons,
                            a.get("baseline_status", "stable"),
                            1 if a.get("has_iq_capture") else 0,
                            ts,  # first_seen
                            self._ctx.tenant_id,
                        ),
                    )
                    new_id = cursor.lastrowid
                    row_ids.append(new_id)
                    existing_map[dedup_key] = (new_id, 1)
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RF_ANOMAL,
            CacheTag.COUNT_RF,
            CacheTag.GET_RF_ANOMALY_SUMMARY,
        )
        logger.debug("Upserted %d RF anomaly records", len(row_ids))
        return row_ids

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_rf_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
        family: str | None = None,
        signal_class: str | None = None,
        priority: str | None = None,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
        sort_by: str = "score",
        sort_order: str = "desc",
    ) -> list[dict[str, Any]]:
        """Return RF anomalies above threshold from dedicated table.

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
        family : str or None
            Filter by signal family (e.g. "PSK", "QAM").
        signal_class : str or None
            Filter by signal class (e.g. "bpsk", "qpsk").
        priority : str or None
            Filter by priority ("critical", "anomalous", "interesting").
        freq_min_hz : float or None
            Minimum frequency in Hz.
        freq_max_hz : float or None
            Maximum frequency in Hz.
        sort_by : str
            Sort field: "score", "time", "freq", or "seen".
        sort_order : str
            Sort direction: "asc" or "desc".

        Returns
        -------
        list[dict]
            Anomaly records sorted by requested field.
        """
        _SORT_COLS = {
            "score": "anomaly_score",
            "time": "timestamp",
            "freq": "freq_hz",
            "seen": "seen_count",
        }
        sort_col = _SORT_COLS.get(sort_by, "anomaly_score")
        order = "DESC" if sort_order.lower() != "asc" else "ASC"

        cache_key = TTLCache.make_key(
            "get_rf_anomalies",
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
            family=family,
            signal_class=signal_class,
            priority=priority,
            freq_min_hz=freq_min_hz,
            freq_max_hz=freq_max_hz,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]

        if not include_dismissed:
            clauses.append(_RF_ACTIVE_FILTER)

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        if family is not None:
            clauses.append("family = ?")
            params.append(family)

        if signal_class is not None:
            clauses.append("signal_class = ?")
            params.append(signal_class)

        if priority is not None:
            clauses.append("priority = ?")
            params.append(priority)

        if freq_min_hz is not None:
            clauses.append("freq_hz >= ?")
            params.append(freq_min_hz)

        if freq_max_hz is not None:
            clauses.append("freq_hz <= ?")
            params.append(freq_max_hz)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM rf_anomalies
            WHERE {where}
            ORDER BY {sort_col} {order}, timestamp DESC
            LIMIT ?
        """
        params.append(limit)

        conn = self._ctx.get_conn()
        try:
            rows = conn.execute(sql, params).fetchall()
        except sqlite3.OperationalError:
            # Table may not exist yet — run migration and retry
            self._ctx.ensure_rf_anomalies_table(conn)
            rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            for key, default in (("dimensions", {}), ("reasons", [])):
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

    # ------------------------------------------------------------------
    # Count
    # ------------------------------------------------------------------

    def count_rf_anomalies(
        self,
        min_score: float = 0.3,
        include_dismissed: bool = False,
        node_id: str | None = None,
        family: str | None = None,
        signal_class: str | None = None,
        priority: str | None = None,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
    ) -> int:
        """Return total count of RF anomalies matching filters."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]
        if not include_dismissed:
            clauses.append(_RF_ACTIVE_FILTER)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if family is not None:
            clauses.append("family = ?")
            params.append(family)
        if signal_class is not None:
            clauses.append("signal_class = ?")
            params.append(signal_class)
        if priority is not None:
            clauses.append("priority = ?")
            params.append(priority)
        if freq_min_hz is not None:
            clauses.append("freq_hz >= ?")
            params.append(freq_min_hz)
        if freq_max_hz is not None:
            clauses.append("freq_hz <= ?")
            params.append(freq_max_hz)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        try:
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM rf_anomalies WHERE {where}", params
            ).fetchone()
        except sqlite3.OperationalError:
            self._ctx.ensure_rf_anomalies_table(conn)
            row = conn.execute(
                f"SELECT COUNT(*) as cnt FROM rf_anomalies WHERE {where}", params
            ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_rf_anomaly_summary(
        self,
        min_score: float = 0.3,
    ) -> dict[str, Any]:
        """Return aggregate breakdown of active RF anomalies.

        Returns counts by priority, family, frequency band, and node,
        plus lists of unique signal classes, families, and nodes.
        """
        cache_key = TTLCache.make_key("get_rf_anomaly_summary", min_score=min_score)
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        base_where = f"{tf_clause} AND {_RF_ACTIVE_FILTER} AND anomaly_score >= ?"
        base_params: list[Any] = list(tf_params) + [min_score]
        conn = self._ctx.get_conn()

        def _query(sql: str, params: list[Any] | None = None) -> list[sqlite3.Row]:
            try:
                return conn.execute(sql, params or base_params).fetchall()
            except sqlite3.OperationalError:
                self._ctx.ensure_rf_anomalies_table(conn)
                return conn.execute(sql, params or base_params).fetchall()

        # Total count
        total_row = _query(
            f"SELECT COUNT(*) as cnt FROM rf_anomalies WHERE {base_where}"
        )
        total = total_row[0]["cnt"] if total_row else 0

        # By priority
        priority_rows = _query(
            f"SELECT priority, COUNT(*) as count FROM rf_anomalies "
            f"WHERE {base_where} GROUP BY priority"
        )
        by_priority = {
            r["priority"]: r["count"] for r in priority_rows if r["priority"]
        }

        # By family
        family_rows = _query(
            f"SELECT family, COUNT(*) as count FROM rf_anomalies "
            f"WHERE {base_where} GROUP BY family ORDER BY count DESC LIMIT 10"
        )
        by_family = [
            {"family": r["family"], "count": r["count"]}
            for r in family_rows
            if r["family"]
        ]

        # By frequency band (100kHz buckets)
        band_rows = _query(
            f"SELECT CAST(freq_hz/100000 AS INT) as bucket, COUNT(*) as count "
            f"FROM rf_anomalies WHERE {base_where} GROUP BY bucket "
            f"ORDER BY count DESC LIMIT 10"
        )
        by_band = []
        for r in band_rows:
            bucket = r["bucket"]
            if bucket is not None and bucket > 0:
                freq_hz = bucket * 100000
                by_band.append(
                    {"band": self._bucket_to_band_label(freq_hz), "count": r["count"]}
                )

        # By node
        node_rows = _query(
            f"SELECT node_id, COUNT(*) as count FROM rf_anomalies "
            f"WHERE {base_where} GROUP BY node_id ORDER BY count DESC"
        )
        by_node = [
            {"node_id": r["node_id"], "count": r["count"]}
            for r in node_rows
            if r["node_id"]
        ]

        # Unique values for filter dropdowns
        class_rows = _query(
            f"SELECT DISTINCT signal_class FROM rf_anomalies WHERE {base_where}"
        )
        unique_classes = sorted(
            [r["signal_class"] for r in class_rows if r["signal_class"]]
        )

        fam_rows = _query(
            f"SELECT DISTINCT family FROM rf_anomalies WHERE {base_where}"
        )
        unique_families = sorted([r["family"] for r in fam_rows if r["family"]])

        node_uniq_rows = _query(
            f"SELECT DISTINCT node_id FROM rf_anomalies WHERE {base_where}"
        )
        unique_nodes = sorted([r["node_id"] for r in node_uniq_rows if r["node_id"]])

        result = {
            "total": total,
            "by_priority": by_priority,
            "by_family": by_family,
            "by_band": by_band,
            "by_node": by_node,
            "unique_classes": unique_classes,
            "unique_families": unique_families,
            "unique_nodes": unique_nodes,
        }
        self._ctx.cache.put(cache_key, result, ttl=5.0)
        return result

    def get_rf_anomalies_by_ids(self, ids: list[int]) -> list[dict[str, Any]]:
        """Return the RF anomalies with these row IDs, dismissed or not.

        Parameters
        ----------
        ids : list[int]
            Row IDs to fetch.

        Returns
        -------
        list[dict]
            The tenant-visible rows among *ids* (unknown IDs are absent),
            with ``dimensions`` and ``reasons`` decoded.
        """
        if not ids:
            return []
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in ids)
        sql = f"SELECT * FROM rf_anomalies WHERE {tf_clause} AND id IN ({placeholders})"
        conn = self._ctx.get_conn()
        try:
            rows = conn.execute(sql, tf_params + list(ids)).fetchall()
        except sqlite3.OperationalError:
            # Table may not exist yet — run migration and retry
            self._ctx.ensure_rf_anomalies_table(conn)
            rows = conn.execute(sql, tf_params + list(ids)).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            for key, default in (("dimensions", {}), ("reasons", [])):
                if key in entry and entry[key]:
                    try:
                        entry[key] = json.loads(entry[key])
                    except (json.JSONDecodeError, TypeError):
                        entry[key] = default
                elif key in entry:
                    entry[key] = default
            results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Dismiss
    # ------------------------------------------------------------------

    def dismiss_rf_anomaly(self, anomaly_id: int) -> None:
        """Mark an RF anomaly as dismissed.

        Parameters
        ----------
        anomaly_id : int
            Row ID of the anomaly to dismiss.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE rf_anomalies SET dismissed = 1 WHERE {tf_clause} AND id = ?",
                tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RF_ANOMAL,
            CacheTag.COUNT_RF,
            CacheTag.GET_RF_ANOMALY_SUMMARY,
        )

    def dismiss_rf_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        """Bulk dismiss RF anomalies.

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
                f"UPDATE rf_anomalies SET dismissed = 1 WHERE {tf_clause} AND id IN ({placeholders})",
                tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RF_ANOMAL,
            CacheTag.COUNT_RF,
            CacheTag.GET_RF_ANOMALY_SUMMARY,
        )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Snooze
    # ------------------------------------------------------------------

    def snooze_rf_anomaly(self, anomaly_id: int, until: str) -> None:
        """Snooze an RF anomaly until the given ISO timestamp."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE rf_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id = ?",
                [until] + tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RF_ANOMAL,
            CacheTag.COUNT_RF,
            CacheTag.GET_RF_ANOMALY_SUMMARY,
        )

    def snooze_rf_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        """Bulk snooze RF anomalies until the given ISO timestamp."""
        if not anomaly_ids:
            return 0
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in anomaly_ids)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE rf_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id IN ({placeholders})",
                [until] + tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_RF_ANOMAL,
            CacheTag.COUNT_RF,
            CacheTag.GET_RF_ANOMALY_SUMMARY,
        )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Stale auto-resolution
    # ------------------------------------------------------------------

    def resolve_stale_anomalies(
        self,
        max_age_hours: float = 1.0,
        max_score: float = 1.0,
        min_seen_count: int = 1,
    ) -> int:
        """Mark active anomalies as ``stale-resolved`` if not updated recently.

        Only anomalies whose ``timestamp`` is older than *max_age_hours*,
        whose ``anomaly_score`` is at or below *max_score*, and whose
        ``seen_count`` meets *min_seen_count* are resolved.  This preserves
        the record for audit/history while removing it from the active queue.

        Parameters
        ----------
        max_age_hours : float
            Decay period — anomalies not updated within this window are stale.
        max_score : float
            Only auto-resolve anomalies with score <= this threshold.
        min_seen_count : int
            Minimum ``seen_count`` before eligible for auto-resolve.

        Returns
        -------
        int
            Number of anomalies marked as stale-resolved.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        try:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    f"UPDATE rf_anomalies SET status = 'stale-resolved' "
                    f"WHERE {tf_clause} "
                    f"  AND dismissed = 0 "
                    f"  AND (status IS NULL OR status = 'active') "
                    f"  AND timestamp < ? "
                    f"  AND anomaly_score <= ? "
                    f"  AND seen_count >= ?",
                    tf_params + [cutoff, max_score, min_seen_count],
                )
        except sqlite3.OperationalError as exc:
            # status column may not exist yet (pre-migration 35)
            logger.debug("resolve_stale_anomalies skipped: %s", exc)
            return 0
        count = cursor.rowcount
        if count:
            self._ctx.cache.invalidate_prefix(
                CacheTag.GET_RF_ANOMAL,
                CacheTag.COUNT_RF,
                CacheTag.GET_RF_ANOMALY_SUMMARY,
            )
        return count

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_rf_anomalies(self, max_age_days: int = 7) -> int:
        """Delete RF anomalies older than *max_age_days*.

        Parameters
        ----------
        max_age_days : int
            Maximum age for RF anomaly records.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM rf_anomalies WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d RF anomalies older than %d days",
                deleted,
                max_age_days,
            )
        return deleted

    def auto_resolve_baseline_anomalies(
        self,
        max_score: float = 0.4,
        min_seen_count: int = 5,
    ) -> int:
        """Auto-resolve anomalies that have been absorbed into baseline.

        When a signal was flagged during the learning phase but has since
        settled into the baseline (anomaly_score dropped below max_score
        after being seen min_seen_count times), mark it as resolved.

        Returns the number of anomalies resolved.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"""UPDATE rf_anomalies
                    SET status = 'resolved', dismissed = 1
                    WHERE {tf_clause}
                      AND {_RF_ACTIVE_FILTER}
                      AND anomaly_score <= ?
                      AND seen_count >= ?
                      AND baseline_status = 'stable'
                """,
                tf_params + [max_score, min_seen_count],
            )
        count = cursor.rowcount
        if count > 0:
            self._ctx.cache.invalidate()
            logger.info(
                "Auto-resolved %d baseline-absorbed RF anomalies "
                "(score<=%.2f, seen>=%d)",
                count,
                max_score,
                min_seen_count,
            )
        return count
