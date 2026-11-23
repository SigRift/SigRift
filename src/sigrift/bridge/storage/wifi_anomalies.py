"""WiFi anomaly CRUD and management sub-store.

Handles insert, query, dismiss, snooze, pcap flagging, and cleanup
for the ``wifi_anomalies`` table.  Extracted from the monolithic
``DetectionStore`` for maintainability.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag, TTLCache
from sigrift.bridge.storage.base import ACTIVE_FILTER as _BASE_ACTIVE_FILTER

logger = logging.getLogger(__name__)


class WiFiAnomalyStore:
    """WiFi anomaly operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    # Filter clause for "active" anomalies: not dismissed AND not snoozed
    # (one definition, see storage.base.ACTIVE_FILTER).
    ACTIVE_FILTER = _BASE_ACTIVE_FILTER

    _WIFI_ATTACK_LABELS: dict[str, str] = {
        "evil_twin": "Evil Twin AP",
        "security_downgrade": "Security Downgrade",
        "signal_anomaly": "Signal Anomaly",
        "new_network": "Rogue AP",
        "channel_change": "Channel Manipulation",
        "client_surge": "Client Flood",
        "deauth_indicator": "Deauth Attack",
    }

    _WIFI_ANOMALY_BASE_COLS = (
        "id, bssid, ssid, channel, band, security, signal_dbm, "
        "anomaly_score, priority, dimensions, reasons, baseline_status, "
        "node_id, timestamp, dismissed, "
        "client_count, retry_rate, noise_dbm_max, data_rate_min, data_rate_max, "
        "channel_width, frame_count, deauth_count, frame_type_counts, "
        "expected_signal, signal_zscore, expected_channel, expected_security, "
        "expected_client_count, expected_retry_rate, baseline_observations, "
        "has_pcap_capture, pcap_frame_count, "
        "seen_count, first_seen, snoozed_until, vendor"
    )
    # Heavy columns excluded from default list query
    _WIFI_ANOMALY_FRAME_COLS = ", client_macs, frame_capture"

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # Attack type derivation
    # ------------------------------------------------------------------

    @staticmethod
    def _wifi_attack_type(dimensions: dict[str, float]) -> str:
        """Derive human-readable attack type label from dimension scores."""
        if not dimensions:
            return ""
        top = max(dimensions, key=dimensions.get)
        if dimensions[top] < 0.3:
            return ""
        return WiFiAnomalyStore._WIFI_ATTACK_LABELS.get(top, top)

    # ------------------------------------------------------------------
    # Insert / upsert
    # ------------------------------------------------------------------

    def insert_wifi_anomalies_batch(
        self,
        anomalies: list[dict[str, Any]],
        *,
        auto_snooze_seen_count: int = 0,
        auto_snooze_max_score: float = 0.0,
        auto_snooze_hours: int = 0,
    ) -> list[int]:
        """Upsert WiFi anomaly records, deduplicating by BSSID.

        Dedup includes dismissed rows: finds the **most recent** row per
        BSSID regardless of dismissed/snoozed status.  If the most recent
        row is dismissed, it is un-dismissed and updated.  Snoozed rows
        are updated (seen_count incremented) but remain snoozed.

        Parameters
        ----------
        anomalies : list[dict]
            Anomaly dicts with keys matching wifi_anomalies columns.
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
            INSERT INTO wifi_anomalies (
                bssid, ssid, channel, band, security, signal_dbm,
                anomaly_score, priority, dimensions, reasons,
                baseline_status, node_id, timestamp, first_seen,
                client_count, retry_rate, noise_dbm_max,
                data_rate_min, data_rate_max, channel_width,
                frame_count, deauth_count, frame_type_counts,
                expected_signal, signal_zscore, expected_channel,
                expected_security, expected_client_count, expected_retry_rate,
                baseline_observations, client_macs, frame_capture, tenant_id,
                vendor
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?)
        """

        # Update SQL: also un-dismiss (dismissed=0) but preserve snoozed_until
        update_sql = """
            UPDATE wifi_anomalies SET
                ssid = ?, channel = ?, band = ?, security = ?,
                signal_dbm = ?, anomaly_score = ?, priority = ?,
                dimensions = ?, reasons = ?, baseline_status = ?,
                node_id = ?, timestamp = ?,
                client_count = ?, retry_rate = ?, noise_dbm_max = ?,
                data_rate_min = ?, data_rate_max = ?, channel_width = ?,
                frame_count = ?, deauth_count = ?, frame_type_counts = ?,
                expected_signal = ?, signal_zscore = ?, expected_channel = ?,
                expected_security = ?, expected_client_count = ?,
                expected_retry_rate = ?, baseline_observations = ?,
                client_macs = ?, frame_capture = ?,
                vendor = ?,
                seen_count = seen_count + 1,
                dismissed = 0
            WHERE id = ?
        """

        # Snoozed rows: update data + increment seen_count but don't un-snooze
        update_snoozed_sql = """
            UPDATE wifi_anomalies SET
                ssid = ?, channel = ?, band = ?, security = ?,
                signal_dbm = ?, anomaly_score = ?, priority = ?,
                dimensions = ?, reasons = ?, baseline_status = ?,
                node_id = ?, timestamp = ?,
                client_count = ?, retry_rate = ?, noise_dbm_max = ?,
                data_rate_min = ?, data_rate_max = ?, channel_width = ?,
                frame_count = ?, deauth_count = ?, frame_type_counts = ?,
                expected_signal = ?, signal_zscore = ?, expected_channel = ?,
                expected_security = ?, expected_client_count = ?,
                expected_retry_rate = ?, baseline_observations = ?,
                client_macs = ?, frame_capture = ?,
                vendor = ?,
                seen_count = seen_count + 1
            WHERE id = ?
        """

        row_ids: list[int] = []
        with self._ctx.write_transaction() as conn:
            # Batch dedup lookup: find the most recent row per BSSID
            # regardless of dismissed/snoozed status
            bssids = list({a.get("bssid", "") for a in anomalies if a.get("bssid")})
            # Maps bssid -> (id, is_snoozed, seen_count)
            existing_map: dict[str, tuple[int, bool, int]] = {}
            tf_clause, tf_params = self._ctx.tenant_filter()
            if bssids:
                ph = ",".join("?" for _ in bssids)
                for row in conn.execute(
                    f"SELECT w.id, w.bssid, w.snoozed_until, w.seen_count "
                    f"FROM wifi_anomalies w "
                    f"INNER JOIN (SELECT MAX(id) as max_id FROM wifi_anomalies "
                    f"  WHERE {tf_clause} AND bssid IN ({ph}) GROUP BY bssid) sub "
                    f"ON w.id = sub.max_id",
                    tf_params + bssids,
                ).fetchall():
                    is_snoozed = (
                        row["snoozed_until"] is not None
                        and row["snoozed_until"]
                        > datetime.now(timezone.utc).isoformat()
                    )
                    existing_map[row["bssid"]] = (
                        row["id"],
                        is_snoozed,
                        row["seen_count"] or 0,
                    )

            for a in anomalies:
                bssid = a.get("bssid", "")
                ts = a.get("timestamp", datetime.now(timezone.utc).isoformat())

                dims = json.dumps(a.get("dimensions", {}))
                reasons = json.dumps(a.get("reasons", []))
                ftc = json.dumps(a.get("frame_type_counts", {}))
                macs = json.dumps(a.get("client_macs", []))
                frames = json.dumps(a.get("frame_capture", []))

                existing = existing_map.get(bssid)
                if existing is not None:
                    existing_id, is_snoozed, seen_count = existing
                    update_params = (
                        a.get("ssid", ""),
                        a.get("channel", 0),
                        a.get("band", "2.4GHz"),
                        a.get("security", ""),
                        a.get("signal_dbm", 0.0),
                        a.get("anomaly_score", 0.0),
                        a.get("priority", "normal"),
                        dims,
                        reasons,
                        a.get("baseline_status", "stable"),
                        a.get("node_id", ""),
                        ts,
                        a.get("client_count", 0),
                        a.get("retry_rate", 0.0),
                        a.get("noise_dbm_max", 0.0),
                        a.get("data_rate_min", 0.0),
                        a.get("data_rate_max", 0.0),
                        a.get("channel_width", 0),
                        a.get("frame_count", 0),
                        a.get("deauth_count", 0),
                        ftc,
                        a.get("expected_signal"),
                        a.get("signal_zscore", 0.0),
                        a.get("expected_channel"),
                        a.get("expected_security", ""),
                        a.get("expected_client_count", 0.0),
                        a.get("expected_retry_rate", 0.0),
                        a.get("baseline_observations", 0),
                        macs,
                        frames,
                        a.get("vendor", ""),
                        existing_id,
                    )
                    if is_snoozed:
                        conn.execute(update_snoozed_sql, update_params)
                    else:
                        conn.execute(update_sql, update_params)

                    # Auto-snooze: check if seen_count threshold reached
                    new_seen = seen_count + 1
                    score = a.get("anomaly_score", 0.0)
                    if (
                        auto_snooze_seen_count > 0
                        and new_seen >= auto_snooze_seen_count
                        and score < auto_snooze_max_score
                        and auto_snooze_hours > 0
                        and not is_snoozed
                    ):
                        snooze_until = (
                            datetime.now(timezone.utc)
                            + timedelta(hours=auto_snooze_hours)
                        ).isoformat()
                        conn.execute(
                            "UPDATE wifi_anomalies SET snoozed_until = ? WHERE id = ?",
                            (snooze_until, existing_id),
                        )
                        logger.info(
                            "Auto-snoozed WiFi anomaly %d (bssid=%s, seen=%d, score=%.2f)",
                            existing_id,
                            bssid,
                            new_seen,
                            score,
                        )

                    row_ids.append(existing_id)
                    existing_map[bssid] = (existing_id, is_snoozed, seen_count + 1)
                else:
                    # Insert new row
                    cursor = conn.execute(
                        insert_sql,
                        (
                            bssid,
                            a.get("ssid", ""),
                            a.get("channel", 0),
                            a.get("band", "2.4GHz"),
                            a.get("security", ""),
                            a.get("signal_dbm", 0.0),
                            a.get("anomaly_score", 0.0),
                            a.get("priority", "normal"),
                            dims,
                            reasons,
                            a.get("baseline_status", "stable"),
                            a.get("node_id", ""),
                            ts,
                            ts,
                            a.get("client_count", 0),
                            a.get("retry_rate", 0.0),
                            a.get("noise_dbm_max", 0.0),
                            a.get("data_rate_min", 0.0),
                            a.get("data_rate_max", 0.0),
                            a.get("channel_width", 0),
                            a.get("frame_count", 0),
                            a.get("deauth_count", 0),
                            ftc,
                            a.get("expected_signal"),
                            a.get("signal_zscore", 0.0),
                            a.get("expected_channel"),
                            a.get("expected_security", ""),
                            a.get("expected_client_count", 0.0),
                            a.get("expected_retry_rate", 0.0),
                            a.get("baseline_observations", 0),
                            macs,
                            frames,
                            self._ctx.tenant_id,
                            a.get("vendor", ""),
                        ),
                    )
                    new_id = cursor.lastrowid
                    row_ids.append(new_id)
                    existing_map[bssid] = (new_id, False, 1)
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)
        logger.debug("Upserted %d wifi anomaly records", len(row_ids))
        return row_ids

    def insert_wifi_anomaly(self, anomaly: dict[str, Any]) -> int:
        """Insert a single WiFi anomaly record.

        Parameters
        ----------
        anomaly : dict
            Anomaly data with keys matching wifi_anomalies columns.

        Returns
        -------
        int
            Row ID of the inserted anomaly.
        """
        sql = """
            INSERT INTO wifi_anomalies (
                bssid, ssid, channel, band, security, signal_dbm,
                anomaly_score, priority, dimensions, reasons,
                baseline_status, node_id, timestamp,
                client_count, retry_rate, noise_dbm_max,
                data_rate_min, data_rate_max, channel_width,
                frame_count, deauth_count, frame_type_counts,
                expected_signal, signal_zscore, expected_channel,
                expected_security, expected_client_count, expected_retry_rate,
                baseline_observations, client_macs, frame_capture, tenant_id,
                vendor
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      ?)
        """
        row = (
            anomaly.get("bssid", ""),
            anomaly.get("ssid", ""),
            anomaly.get("channel", 0),
            anomaly.get("band", "2.4GHz"),
            anomaly.get("security", ""),
            anomaly.get("signal_dbm", 0.0),
            anomaly.get("anomaly_score", 0.0),
            anomaly.get("priority", "normal"),
            json.dumps(anomaly.get("dimensions", {})),
            json.dumps(anomaly.get("reasons", [])),
            anomaly.get("baseline_status", "stable"),
            anomaly.get("node_id", ""),
            anomaly.get("timestamp", datetime.now(timezone.utc).isoformat()),
            anomaly.get("client_count", 0),
            anomaly.get("retry_rate", 0.0),
            anomaly.get("noise_dbm_max", 0.0),
            anomaly.get("data_rate_min", 0.0),
            anomaly.get("data_rate_max", 0.0),
            anomaly.get("channel_width", 0),
            anomaly.get("frame_count", 0),
            anomaly.get("deauth_count", 0),
            json.dumps(anomaly.get("frame_type_counts", {})),
            anomaly.get("expected_signal"),
            anomaly.get("signal_zscore", 0.0),
            anomaly.get("expected_channel"),
            anomaly.get("expected_security", ""),
            anomaly.get("expected_client_count", 0.0),
            anomaly.get("expected_retry_rate", 0.0),
            anomaly.get("baseline_observations", 0),
            json.dumps(anomaly.get("client_macs", [])),
            json.dumps(anomaly.get("frame_capture", [])),
            self._ctx.tenant_id,
            anomaly.get("vendor", ""),
        )
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, row)
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)
        return cursor.lastrowid

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_wifi_anomalies(
        self,
        min_score: float = 0.3,
        limit: int = 50,
        node_id: str | None = None,
        include_dismissed: bool = False,
        include_frames: bool = False,
    ) -> list[dict[str, Any]]:
        """Return WiFi anomalies above threshold.

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
        include_frames : bool
            Whether to include frame_capture and client_macs (heavy).

        Returns
        -------
        list[dict]
            Anomaly records sorted by score descending.
        """
        cache_key = TTLCache.make_key(
            "get_wifi_anomalies",
            min_score=min_score,
            limit=limit,
            node_id=node_id,
            include_dismissed=include_dismissed,
            include_frames=include_frames,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cols = self._WIFI_ANOMALY_BASE_COLS
        if include_frames:
            cols += self._WIFI_ANOMALY_FRAME_COLS

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
            SELECT {cols} FROM wifi_anomalies
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
            # Deserialize JSON fields
            for key, default in (
                ("dimensions", {}),
                ("reasons", []),
                ("frame_type_counts", {}),
            ):
                if key in entry and entry[key]:
                    try:
                        entry[key] = json.loads(entry[key])
                    except (json.JSONDecodeError, TypeError):
                        entry[key] = default
                elif key in entry:
                    entry[key] = default
            # Derive attack type label from dimensions
            entry["attack_type"] = self._wifi_attack_type(entry.get("dimensions", {}))
            if include_frames:
                for key in ("client_macs", "frame_capture"):
                    if key in entry and entry[key]:
                        try:
                            entry[key] = json.loads(entry[key])
                        except (json.JSONDecodeError, TypeError):
                            entry[key] = []
                    elif key in entry:
                        entry[key] = []
            results.append(entry)
        self._ctx.cache.put(cache_key, results, ttl=3.0)
        return results

    def count_wifi_anomalies(
        self,
        min_score: float = 0.3,
        include_dismissed: bool = False,
    ) -> int:
        """Return total count of WiFi anomalies matching filters."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause, "anomaly_score >= ?"]
        params: list[Any] = list(tf_params) + [min_score]
        if not include_dismissed:
            clauses.append(self.ACTIVE_FILTER)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM wifi_anomalies WHERE {where}", params
        ).fetchone()
        return row["cnt"] if row else 0

    def get_wifi_anomalies_by_ids(self, ids: list[int]) -> list[dict[str, Any]]:
        """Return WiFi anomalies by their IDs (for re-evaluation).

        Parameters
        ----------
        ids : list[int]
            Row IDs to fetch.

        Returns
        -------
        list[dict]
            Anomaly records with all columns including frame data.
        """
        if not ids:
            return []
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in ids)
        cols = self._WIFI_ANOMALY_BASE_COLS + self._WIFI_ANOMALY_FRAME_COLS
        sql = f"SELECT {cols} FROM wifi_anomalies WHERE {tf_clause} AND id IN ({placeholders})"
        conn = self._ctx.get_conn()
        rows = conn.execute(sql, tf_params + ids).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            for key, default in (
                ("dimensions", {}),
                ("reasons", []),
                ("frame_type_counts", {}),
                ("client_macs", []),
                ("frame_capture", []),
            ):
                if key in entry and entry[key]:
                    try:
                        entry[key] = json.loads(entry[key])
                    except (json.JSONDecodeError, TypeError):
                        entry[key] = default
                elif key in entry:
                    entry[key] = default
            entry["attack_type"] = self._wifi_attack_type(entry.get("dimensions", {}))
            results.append(entry)
        return results

    # ------------------------------------------------------------------
    # Dismiss / snooze
    # ------------------------------------------------------------------

    def dismiss_wifi_anomaly(self, anomaly_id: int) -> None:
        """Mark a WiFi anomaly as dismissed.

        Parameters
        ----------
        anomaly_id : int
            Row ID of the anomaly to dismiss.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE wifi_anomalies SET dismissed = 1 WHERE {tf_clause} AND id = ?",
                tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)

    def dismiss_wifi_anomalies_bulk(self, anomaly_ids: list[int]) -> int:
        """Bulk dismiss WiFi anomalies.

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
                f"UPDATE wifi_anomalies SET dismissed = 1 WHERE {tf_clause} AND id IN ({placeholders})",
                tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)
        return cursor.rowcount

    def snooze_wifi_anomaly(self, anomaly_id: int, until: str) -> None:
        """Snooze a WiFi anomaly until the given ISO timestamp."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE wifi_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id = ?",
                [until] + tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)

    def snooze_wifi_anomalies_bulk(self, anomaly_ids: list[int], until: str) -> int:
        """Bulk snooze WiFi anomalies until the given ISO timestamp."""
        if not anomaly_ids:
            return 0
        tf_clause, tf_params = self._ctx.tenant_filter()
        placeholders = ",".join("?" for _ in anomaly_ids)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE wifi_anomalies SET snoozed_until = ? WHERE {tf_clause} AND id IN ({placeholders})",
                [until] + tf_params + anomaly_ids,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI)
        return cursor.rowcount

    # ------------------------------------------------------------------
    # PCAP flagging
    # ------------------------------------------------------------------

    def set_wifi_anomaly_pcap(
        self,
        anomaly_id: int,
        has_pcap: bool = True,
        frame_count: int = 0,
    ) -> bool:
        """Set the pcap capture flag and frame count for a WiFi anomaly.

        Parameters
        ----------
        anomaly_id : int
            Row ID of the WiFi anomaly.
        has_pcap : bool
            Whether a pcap capture is stored.
        frame_count : int
            Number of frames in the pcap capture.

        Returns
        -------
        bool
            True if anomaly was found and updated, False otherwise.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE wifi_anomalies SET has_pcap_capture = ?, pcap_frame_count = ? WHERE {tf_clause} AND id = ?",
                [1 if has_pcap else 0, frame_count] + tf_params + [anomaly_id],
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_WIFI_ANOMAL)
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def compact_dismissed_wifi_anomalies(self) -> int:
        """Keep only the most recent row per BSSID among dismissed records.

        Removes duplicate dismissed rows, keeping the one with the highest
        ``id`` (most recent) for each BSSID.

        Returns
        -------
        int
            Number of rows deleted.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = f"""
            DELETE FROM wifi_anomalies WHERE {tf_clause} AND dismissed = 1
            AND id NOT IN (
                SELECT MAX(id) FROM wifi_anomalies
                WHERE {tf_clause} AND dismissed = 1 GROUP BY bssid
            )
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, tf_params + tf_params)
        deleted = cursor.rowcount
        if deleted > 0:
            self._ctx.cache.invalidate_prefix(
                CacheTag.GET_WIFI_ANOMAL, CacheTag.COUNT_WIFI
            )
            logger.info(
                "Compacted %d duplicate dismissed wifi anomaly rows",
                deleted,
            )
        return deleted

    def cleanup_wifi_anomalies(self, max_age_days: int = 7) -> int:
        """Delete WiFi anomalies older than *max_age_days*.

        Parameters
        ----------
        max_age_days : int
            Maximum age for WiFi anomaly records.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM wifi_anomalies WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d wifi anomalies older than %d days",
                deleted,
                max_age_days,
            )
        return deleted
