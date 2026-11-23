"""Bluetooth device metadata storage and queries sub-store.

Handles Bluetooth device insertion, device aggregation, timeline queries,
hourly roll-up, and cleanup.  Follows the same architecture as
``WiFiMetadataStore`` with raw + hourly merging.

All queries merge data from both ``bt_devices`` (raw recent rows)
and ``bt_devices_hourly`` (rolled-up historical summaries) using
weighted averages for RSSI.  Raw data takes precedence for attribute
columns.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag, TTLCache

logger = logging.getLogger(__name__)


class BtMetadataStore:
    """Bluetooth device metadata storage backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    # ------------------------------------------------------------------
    # MAC anonymization
    # ------------------------------------------------------------------

    @staticmethod
    def _anonymize_mac(mac: str, secret: bytes) -> str:
        """Pseudonymize a MAC/device address using HMAC-SHA256.

        Preserves the OUI (first 3 octets) for vendor identification
        and replaces the device portion with HMAC-derived hex.
        """
        if not mac:
            return mac
        clean = mac.replace(":", "").replace("-", "").replace(".", "").lower()
        if len(clean) < 6:
            return mac
        oui = clean[:6]
        device = clean[6:]
        h = hmac.new(secret, clean.encode(), hashlib.sha256).hexdigest()
        anon_device = h[: len(device)] if device else ""
        result = oui + anon_device
        return ":".join(result[i : i + 2] for i in range(0, len(result), 2))

    # ------------------------------------------------------------------
    # Insert
    # ------------------------------------------------------------------

    def insert_bt_devices(
        self,
        records: list[dict],
        mac_secret: str | None = None,
    ) -> int:
        """Bulk insert Bluetooth device records.

        Parameters
        ----------
        records : list[dict]
            Bluetooth device records to insert.
        mac_secret : str or None
            If provided, anonymize device_addr fields.

        Returns
        -------
        int
            Number of rows inserted.
        """
        if not records:
            return 0

        secret_bytes = mac_secret.encode() if mac_secret else None

        rows = []
        for r in records:
            device_addr = r.get("device_addr", "")
            if secret_bytes and device_addr:
                device_addr = self._anonymize_mac(device_addr, secret_bytes)
            rows.append(
                (
                    device_addr,
                    r.get("device_name", ""),
                    r.get("device_type", "unknown"),
                    r.get("device_class", 0),
                    r.get("device_class_name", ""),
                    r.get("appearance", 0),
                    r.get("rssi_dbm", 0.0),
                    r.get("tx_power_dbm"),
                    r.get("manufacturer_id"),
                    r.get("manufacturer", ""),
                    r.get("vendor", ""),
                    json.dumps(r.get("service_uuids", [])),
                    json.dumps(r.get("adv_data", {})),
                    r.get("connectable", 1),
                    r.get("bonded", 0),
                    r.get("channel", 0),
                    r.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    r.get("node_id", ""),
                    self._ctx.tenant_id,
                )
            )

        sql = """
            INSERT INTO bt_devices (
                device_addr, device_name, device_type, device_class,
                device_class_name, appearance, rssi_dbm, tx_power_dbm,
                manufacturer_id, manufacturer, vendor, service_uuids,
                adv_data, connectable, bonded, channel, timestamp,
                node_id, tenant_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.executemany(sql, rows)
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_BT_DEVICES,
            CacheTag.GET_BT_STATS,
            CacheTag.GET_BT_TIMELINE,
        )
        inserted = cursor.rowcount
        logger.debug("Inserted %d bt device records", inserted)
        return inserted

    # ------------------------------------------------------------------
    # Device queries
    # ------------------------------------------------------------------

    def get_bt_devices(
        self,
        limit: int = 100,
        device_type: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Aggregate Bluetooth devices by device_addr (raw + hourly).

        Returns
        -------
        list[dict]
            Each entry: device_addr, device_name, device_type, avg RSSI,
            observation count, last seen, node IDs.
        """
        cache_key = TTLCache.make_key(
            "get_bt_devices",
            limit=limit,
            device_type=device_type,
            node_id=node_id,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause, "device_addr != ''"]
        params: list[Any] = list(tf_params)

        if device_type is not None:
            clauses.append("device_type = ?")
            params.append(device_type)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)

        where = " AND ".join(clauses)

        # -- Raw query (recent data) --
        raw_sql = f"""
            SELECT
                device_addr,
                MAX(device_name) as device_name,
                MAX(device_type) as device_type,
                MAX(device_class) as device_class,
                MAX(device_class_name) as device_class_name,
                MAX(manufacturer) as manufacturer,
                MAX(vendor) as vendor,
                AVG(rssi_dbm) as avg_rssi_dbm,
                COUNT(*) as observation_count,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM bt_devices
            WHERE {where}
            GROUP BY device_addr
        """

        # -- Hourly aggregate query (historical) --
        hourly_sql = f"""
            SELECT
                device_addr,
                MAX(device_name) as device_name,
                MAX(device_type) as device_type,
                MAX(device_class) as device_class,
                MAX(manufacturer) as manufacturer,
                MAX(vendor) as vendor,
                SUM(observation_count * avg_rssi_dbm) / SUM(observation_count) as avg_rssi_dbm,
                SUM(observation_count) as observation_count,
                MAX(hour) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM bt_devices_hourly
            WHERE {where}
            GROUP BY device_addr
        """

        conn = self._ctx.get_conn()
        raw_rows = conn.execute(raw_sql, params).fetchall()
        hourly_rows = conn.execute(hourly_sql, params).fetchall()

        # -- Merge by device_addr --
        merged: dict[str, dict[str, Any]] = {}
        for r in raw_rows:
            d = dict(r)
            d["_raw_obs"] = d["observation_count"]
            d["_raw_rssi_sum"] = (d.get("avg_rssi_dbm") or 0.0) * d["observation_count"]
            node_str = d.get("node_ids", "")
            d["node_ids"] = {n for n in (node_str or "").split(",") if n}
            merged[d["device_addr"]] = d

        for r in hourly_rows:
            h = dict(r)
            addr = h["device_addr"]
            h_obs = h["observation_count"] or 0
            h_rssi_sum = (h.get("avg_rssi_dbm") or 0.0) * h_obs
            h_nodes = {n for n in (h.get("node_ids") or "").split(",") if n}

            if addr in merged:
                m = merged[addr]
                total_obs = m["_raw_obs"] + h_obs
                m["observation_count"] = total_obs
                if total_obs > 0:
                    m["avg_rssi_dbm"] = (m["_raw_rssi_sum"] + h_rssi_sum) / total_obs
                m["node_ids"] |= h_nodes
            else:
                h["_raw_obs"] = 0
                h["_raw_rssi_sum"] = 0.0
                h["avg_rssi_dbm"] = h.get("avg_rssi_dbm") or 0.0
                h["node_ids"] = h_nodes
                merged[addr] = h

        # Sort by observation_count DESC, apply limit
        sorted_entries = sorted(
            merged.values(), key=lambda x: x["observation_count"], reverse=True
        )[:limit]
        results = []
        for entry in sorted_entries:
            entry.pop("_raw_obs", None)
            entry.pop("_raw_rssi_sum", None)
            entry["avg_rssi_dbm"] = round(entry.get("avg_rssi_dbm") or 0.0, 1)
            entry["node_ids"] = (
                sorted(entry["node_ids"])
                if isinstance(entry["node_ids"], set)
                else entry["node_ids"]
            )
            results.append(entry)
        self._ctx.cache.put(cache_key, results, ttl=4.0)
        return results

    def get_bt_device_detail(self, device_addr: str) -> dict[str, Any] | None:
        """Return aggregated detail for a single Bluetooth device (raw + hourly).

        Parameters
        ----------
        device_addr : str
            Device address to look up.

        Returns
        -------
        dict or None
            Device info dict, or None if not found in either source.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()

        raw_row = conn.execute(
            f"""
            SELECT
                device_addr,
                MAX(device_name) as device_name,
                MAX(device_type) as device_type,
                MAX(device_class) as device_class,
                MAX(device_class_name) as device_class_name,
                MAX(manufacturer) as manufacturer,
                MAX(vendor) as vendor,
                AVG(rssi_dbm) as avg_rssi_dbm,
                COUNT(*) as observation_count,
                MAX(timestamp) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM bt_devices
            WHERE {tf_clause} AND device_addr = ?
            GROUP BY device_addr
            """,
            tf_params + [device_addr],
        ).fetchone()

        hourly_row = conn.execute(
            f"""
            SELECT
                device_addr,
                MAX(device_name) as device_name,
                MAX(device_type) as device_type,
                MAX(device_class) as device_class,
                MAX(manufacturer) as manufacturer,
                MAX(vendor) as vendor,
                SUM(observation_count * avg_rssi_dbm) / SUM(observation_count) as avg_rssi_dbm,
                SUM(observation_count) as observation_count,
                MAX(hour) as last_seen,
                GROUP_CONCAT(DISTINCT node_id) as node_ids
            FROM bt_devices_hourly
            WHERE {tf_clause} AND device_addr = ?
            GROUP BY device_addr
            """,
            tf_params + [device_addr],
        ).fetchone()

        if raw_row is None and hourly_row is None:
            return None

        if raw_row is not None and hourly_row is not None:
            raw = dict(raw_row)
            hourly = dict(hourly_row)
            raw_obs = raw["observation_count"]
            h_obs = hourly["observation_count"] or 0
            total = raw_obs + h_obs
            raw_rssi = (raw.get("avg_rssi_dbm") or 0.0) * raw_obs
            h_rssi = (hourly.get("avg_rssi_dbm") or 0.0) * h_obs

            device = raw  # Prefer raw for attribute columns
            device["observation_count"] = total
            if total > 0:
                device["avg_rssi_dbm"] = (raw_rssi + h_rssi) / total
            raw_nodes = {n for n in (raw.get("node_ids") or "").split(",") if n}
            h_nodes = {n for n in (hourly.get("node_ids") or "").split(",") if n}
            device["node_ids"] = sorted(raw_nodes | h_nodes)
        elif raw_row is not None:
            device = dict(raw_row)
            node_str = device.get("node_ids", "")
            device["node_ids"] = [n for n in (node_str or "").split(",") if n]
        else:
            device = dict(hourly_row)
            node_str = device.get("node_ids", "")
            device["node_ids"] = [n for n in (node_str or "").split(",") if n]

        device["avg_rssi_dbm"] = round(device.get("avg_rssi_dbm") or 0.0, 1)
        return device

    # ------------------------------------------------------------------
    # Summary stats
    # ------------------------------------------------------------------

    def get_bt_stats(self) -> dict[str, Any]:
        """Summary Bluetooth statistics (bounded to recent data).

        Returns
        -------
        dict
            total_devices, type_breakdown, top_manufacturers, active_bt_nodes.
        """
        cache_key = TTLCache.make_key("get_bt_stats")
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        ts_clause = "timestamp >= ?"

        # Total unique devices
        row = conn.execute(
            f"SELECT COUNT(DISTINCT device_addr) as cnt "
            f"FROM bt_devices WHERE {tf_clause} AND device_addr != '' AND {ts_clause}",
            tf_params + [cutoff],
        ).fetchone()
        total_devices = row["cnt"] if row else 0

        # Type breakdown
        type_rows = conn.execute(
            f"SELECT device_type, COUNT(DISTINCT device_addr) as device_count "
            f"FROM bt_devices WHERE {tf_clause} AND device_addr != '' AND {ts_clause} "
            f"GROUP BY device_type",
            tf_params + [cutoff],
        ).fetchall()
        type_breakdown = {r["device_type"]: r["device_count"] for r in type_rows}

        # Top manufacturers
        mfr_rows = conn.execute(
            f"SELECT manufacturer, COUNT(DISTINCT device_addr) as device_count "
            f"FROM bt_devices WHERE {tf_clause} AND manufacturer != '' AND {ts_clause} "
            f"GROUP BY manufacturer ORDER BY device_count DESC LIMIT 10",
            tf_params + [cutoff],
        ).fetchall()
        top_manufacturers = [
            {"manufacturer": r["manufacturer"], "device_count": r["device_count"]}
            for r in mfr_rows
        ]

        # Active BT node IDs (last 1 hour)
        node_cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        bt_nodes = conn.execute(
            f"SELECT DISTINCT node_id FROM bt_devices "
            f"WHERE {tf_clause} AND node_id != '' AND timestamp >= ?",
            tf_params + [node_cutoff],
        ).fetchall()
        active_bt_nodes = [r["node_id"] for r in bt_nodes]

        result = {
            "total_devices": total_devices,
            "type_breakdown": type_breakdown,
            "top_manufacturers": top_manufacturers,
            "active_bt_nodes": active_bt_nodes,
        }
        self._ctx.cache.put(cache_key, result, ttl=18.0)
        return result

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def get_bt_timeline(
        self,
        device_addr: str,
        hours: int = 24,
    ) -> list[dict[str, Any]]:
        """RSSI over time for a Bluetooth device (raw + hourly).

        Parameters
        ----------
        device_addr : str
            Device address filter.
        hours : int
            Lookback window.
        """
        cache_key = TTLCache.make_key(
            "get_bt_timeline",
            device_addr=device_addr,
            hours=hours,
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cutoff_hour = cutoff[:19]

        tf_clause, tf_params = self._ctx.tenant_filter()

        # -- Raw query --
        raw_sql = f"""
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                AVG(rssi_dbm) as avg_rssi_dbm,
                COUNT(*) as observation_count
            FROM bt_devices
            WHERE {tf_clause} AND timestamp >= ? AND device_addr = ?
            GROUP BY hour
        """
        raw_params: list[Any] = list(tf_params) + [cutoff, device_addr]

        # -- Hourly aggregate query --
        hourly_sql = f"""
            SELECT
                hour,
                SUM(observation_count * avg_rssi_dbm) / SUM(observation_count) as avg_rssi_dbm,
                SUM(observation_count) as observation_count
            FROM bt_devices_hourly
            WHERE {tf_clause} AND hour >= ? AND device_addr = ?
            GROUP BY hour
        """
        h_params: list[Any] = list(tf_params) + [cutoff_hour, device_addr]

        conn = self._ctx.get_conn()
        raw_rows = conn.execute(raw_sql, raw_params).fetchall()
        hourly_rows = conn.execute(hourly_sql, h_params).fetchall()

        # Merge by hour -- hourly first so raw can override
        merged: dict[str, dict[str, Any]] = {}

        for r in hourly_rows:
            h = dict(r)
            hour = h["hour"]
            merged[hour] = {
                "hour": hour,
                "avg_rssi_dbm": h.get("avg_rssi_dbm") or 0.0,
                "observation_count": h["observation_count"] or 0,
                "_h_obs": h["observation_count"] or 0,
                "_h_rssi_sum": (h.get("avg_rssi_dbm") or 0.0)
                * (h["observation_count"] or 0),
            }

        for r in raw_rows:
            d = dict(r)
            hour = d["hour"]
            if hour in merged:
                m = merged[hour]
                raw_obs = d["observation_count"]
                raw_rssi = (d.get("avg_rssi_dbm") or 0.0) * raw_obs
                total = raw_obs + m["_h_obs"]
                m["observation_count"] = total
                if total > 0:
                    m["avg_rssi_dbm"] = (raw_rssi + m["_h_rssi_sum"]) / total
            else:
                merged[hour] = {
                    "hour": hour,
                    "avg_rssi_dbm": d.get("avg_rssi_dbm") or 0.0,
                    "observation_count": d["observation_count"],
                }

        result = []
        for hour in sorted(merged):
            entry = merged[hour]
            entry.pop("_h_obs", None)
            entry.pop("_h_rssi_sum", None)
            entry["avg_rssi_dbm"] = round(entry["avg_rssi_dbm"], 1)
            result.append(entry)

        self._ctx.cache.put(cache_key, result, ttl=12.0)
        return result

    # ------------------------------------------------------------------
    # Hourly aggregation
    # ------------------------------------------------------------------

    def aggregate_bt_hourly(self, cutoff_hours: int = 2) -> int:
        """Roll up raw bt_devices into hourly summaries.

        Aggregates bt_devices rows older than *cutoff_hours* into
        ``bt_devices_hourly``.  Uses INSERT OR REPLACE on the unique
        ``(hour, device_addr, node_id)`` index so re-runs are idempotent.

        Parameters
        ----------
        cutoff_hours : int
            Only aggregate rows whose timestamp is older than this
            many hours ago.  Default 2 provides a safety margin before
            the raw purge.

        Returns
        -------
        int
            Number of aggregate rows written.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
        ).isoformat()

        sql = """
            INSERT OR REPLACE INTO bt_devices_hourly
                (hour, device_addr, device_name, device_type, device_class,
                 manufacturer, vendor, node_id,
                 avg_rssi_dbm, min_rssi_dbm, max_rssi_dbm,
                 observation_count, service_uuids_json, tenant_id)
            SELECT
                strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                device_addr,
                MAX(device_name) as device_name,
                MAX(device_type) as device_type,
                MAX(device_class) as device_class,
                MAX(manufacturer) as manufacturer,
                MAX(vendor) as vendor,
                node_id,
                AVG(rssi_dbm) as avg_rssi_dbm,
                MIN(rssi_dbm) as min_rssi_dbm,
                MAX(rssi_dbm) as max_rssi_dbm,
                COUNT(*) as observation_count,
                '[' || COALESCE(
                    GROUP_CONCAT(DISTINCT CASE WHEN service_uuids != '[]' THEN service_uuids END),
                    ''
                ) || ']' as service_uuids_json,
                tenant_id
            FROM bt_devices
            WHERE timestamp < ? AND tenant_id = ?
            GROUP BY hour, device_addr, node_id
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(sql, [cutoff, self._ctx.tenant_id])
        self._ctx.cache.invalidate()
        count = cursor.rowcount
        if count > 0:
            logger.info("Aggregated %d bt hourly buckets", count)
        return count

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_bt_devices(self, max_age_hours: int = 4) -> int:
        """Delete Bluetooth device rows older than *max_age_hours*.

        Parameters
        ----------
        max_age_hours : int
            Maximum age in hours for raw device rows.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM bt_devices WHERE {tf_clause} AND timestamp < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d bt device rows older than %d hours",
                deleted,
                max_age_hours,
            )
        return deleted

    def cleanup_bt_hourly(self, max_age_days: int = 30) -> int:
        """Delete hourly Bluetooth summaries older than *max_age_days*.

        Parameters
        ----------
        max_age_days : int
            Maximum age in days for hourly summary rows.

        Returns
        -------
        int
            Number of rows deleted.
        """
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=max_age_days)
        ).isoformat()[:19]  # Truncate to match hour format YYYY-MM-DDTHH:00:00

        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"DELETE FROM bt_devices_hourly WHERE {tf_clause} AND hour < ?",
                tf_params + [cutoff],
            )
        self._ctx.cache.invalidate()
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info(
                "Cleaned up %d bt hourly summaries older than %d days",
                deleted,
                max_age_days,
            )
        return deleted
