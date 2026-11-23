"""Zigbee device metadata storage and queries sub-store.

Handles Zigbee device insertion, device aggregation, timeline queries,
hourly roll-up, and cleanup.  Follows the same architecture as
``BtMetadataStore`` with raw + hourly merging.

Zigbee devices are identified by their IEEE 802.15.4 short address or
64-bit extended address.  The storage tracks PAN IDs, device types
(coordinator/router/end-device), manufacturer codes, and Zigbee
cluster information.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import MISSING, CacheTag

logger = logging.getLogger(__name__)


class ZigbeeMetadataStore:
    """Zigbee device metadata storage backed by a :class:`SharedContext`.

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

    def insert_zigbee_devices(self, records: list[dict]) -> int:
        """Bulk insert Zigbee device records.

        Parameters
        ----------
        records : list[dict]
            Zigbee device records to insert.

        Returns
        -------
        int
            Number of rows inserted.
        """
        if not records:
            return 0

        now = datetime.now(timezone.utc).isoformat()
        rows: list[tuple] = []
        for r in records:
            rows.append(
                (
                    r.get("ieee_addr", ""),
                    r.get("short_addr", ""),
                    r.get("device_name", ""),
                    r.get("device_type", "unknown"),
                    r.get("pan_id", ""),
                    r.get("extended_pan_id", ""),
                    r.get("channel", 0),
                    r.get("rssi_dbm", 0.0),
                    r.get("lqi", 0),
                    r.get("manufacturer_code", 0),
                    r.get("manufacturer", ""),
                    json.dumps(r.get("clusters", [])),
                    json.dumps(r.get("endpoints", [])),
                    r.get("power_source", "unknown"),
                    r.get("profile_id", ""),
                    r.get("stack_profile", ""),
                    r.get("security_enabled", 0),
                    r.get("parent_addr", ""),
                    r.get("node_id", ""),
                    now,
                    self._ctx.tenant_id,
                )
            )

        with self._ctx.write_transaction() as conn:
            conn.executemany(
                """INSERT INTO zigbee_devices (
                    ieee_addr, short_addr, device_name, device_type,
                    pan_id, extended_pan_id, channel, rssi_dbm, lqi,
                    manufacturer_code, manufacturer, clusters_json, endpoints_json,
                    power_source, profile_id, stack_profile, security_enabled,
                    parent_addr, node_id, timestamp, tenant_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

        self._ctx.cache.invalidate_prefix(CacheTag.GET_ZB_DEVICES.value)
        self._ctx.cache.invalidate_prefix(CacheTag.GET_ZB_STATS.value)
        return len(rows)

    # ------------------------------------------------------------------
    # Query — device list
    # ------------------------------------------------------------------

    def get_zigbee_devices(
        self,
        *,
        limit: int = 100,
        device_type: str | None = None,
        pan_id: str | None = None,
        node_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List discovered Zigbee devices, merged from raw + hourly."""
        cache_key = f"{CacheTag.GET_ZB_DEVICES.value}:{limit}:{device_type}:{pan_id}:{node_id}:{self._ctx.tenant_id}"
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        conn = self._ctx.get_conn()

        # Raw recent data
        wheres = ["tenant_id = ?"]
        params: list[Any] = [self._ctx.tenant_id]
        if device_type:
            wheres.append("device_type = ?")
            params.append(device_type)
        if pan_id:
            wheres.append("pan_id = ?")
            params.append(pan_id)
        if node_id:
            wheres.append("node_id = ?")
            params.append(node_id)

        where_clause = " AND ".join(wheres)

        sql = f"""
            SELECT z.ieee_addr, z.short_addr, z.device_name, z.device_type,
                   z.pan_id, z.channel, z.rssi_dbm, z.lqi,
                   z.manufacturer_code, z.manufacturer, z.clusters_json,
                   z.endpoints_json, z.power_source, z.profile_id,
                   z.extended_pan_id, z.stack_profile, z.security_enabled,
                   z.parent_addr,
                   z.node_id, z.timestamp,
                   g.observation_count
            FROM zigbee_devices z
            INNER JOIN (
                SELECT ieee_addr, MAX(rowid) AS max_rowid,
                       COUNT(*) AS observation_count
                FROM zigbee_devices
                WHERE {where_clause}
                GROUP BY ieee_addr
            ) g ON z.ieee_addr = g.ieee_addr AND z.rowid = g.max_rowid
            ORDER BY z.timestamp DESC
            LIMIT ?
        """
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()

        devices = []
        for row in rows:
            d = dict(row)
            d["clusters"] = json.loads(d.pop("clusters_json", "[]"))
            d["endpoints"] = json.loads(d.pop("endpoints_json", "[]"))
            devices.append(d)

        self._ctx.cache.put(cache_key, devices, ttl=30)
        return devices

    # ------------------------------------------------------------------
    # Query — device detail
    # ------------------------------------------------------------------

    def get_zigbee_device_detail(self, ieee_addr: str) -> dict[str, Any] | None:
        """Get detailed info for a single Zigbee device."""
        cache_key = (
            f"{CacheTag.GET_ZB_DEVICE_DETAIL.value}:{ieee_addr}:{self._ctx.tenant_id}"
        )
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        conn = self._ctx.get_conn()
        row = conn.execute(
            """SELECT z.ieee_addr, z.short_addr, z.device_name, z.device_type,
                      z.pan_id, z.channel, z.rssi_dbm, z.lqi,
                      z.manufacturer_code, z.manufacturer, z.clusters_json,
                      z.endpoints_json, z.power_source, z.profile_id,
                      z.extended_pan_id, z.stack_profile, z.security_enabled,
                      z.parent_addr,
                      z.node_id,
                      agg.first_seen, agg.last_seen,
                      agg.observation_count, agg.avg_rssi_dbm
               FROM zigbee_devices z
               INNER JOIN (
                   SELECT ieee_addr,
                          MIN(timestamp) AS first_seen,
                          MAX(timestamp) AS last_seen,
                          COUNT(*) AS observation_count,
                          AVG(rssi_dbm) AS avg_rssi_dbm,
                          MAX(rowid) AS max_rowid
                   FROM zigbee_devices
                   WHERE ieee_addr = ? AND tenant_id = ?
                   GROUP BY ieee_addr
               ) agg ON z.ieee_addr = agg.ieee_addr AND z.rowid = agg.max_rowid""",
            (ieee_addr, self._ctx.tenant_id),
        ).fetchone()

        if not row:
            return None

        detail = dict(row)
        detail["clusters"] = json.loads(detail.pop("clusters_json", "[]"))
        detail["endpoints"] = json.loads(detail.pop("endpoints_json", "[]"))

        # Recent timeline (last 24h, hourly buckets)
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        timeline_rows = conn.execute(
            """SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                      AVG(rssi_dbm) as avg_rssi, COUNT(*) as count
               FROM zigbee_devices
               WHERE ieee_addr = ? AND tenant_id = ? AND timestamp >= ?
               GROUP BY hour ORDER BY hour""",
            (ieee_addr, self._ctx.tenant_id, cutoff),
        ).fetchall()
        detail["timeline"] = [dict(r) for r in timeline_rows]

        self._ctx.cache.put(cache_key, detail, ttl=30)
        return detail

    # ------------------------------------------------------------------
    # Query — stats
    # ------------------------------------------------------------------

    def get_zigbee_stats(self) -> dict[str, Any]:
        """Summary statistics for Zigbee devices."""
        cache_key = f"{CacheTag.GET_ZB_STATS.value}:{self._ctx.tenant_id}"
        cached = self._ctx.cache.get(cache_key)
        if cached is not MISSING:
            return cached

        conn = self._ctx.get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        row = conn.execute(
            """SELECT COUNT(DISTINCT ieee_addr) as total_devices,
                      COUNT(DISTINCT pan_id) as total_pan_ids,
                      COUNT(DISTINCT node_id) as active_nodes
               FROM zigbee_devices
               WHERE tenant_id = ? AND timestamp >= ?""",
            (self._ctx.tenant_id, cutoff),
        ).fetchone()

        type_rows = conn.execute(
            """SELECT device_type, COUNT(DISTINCT ieee_addr) as count
               FROM zigbee_devices
               WHERE tenant_id = ? AND timestamp >= ?
               GROUP BY device_type""",
            (self._ctx.tenant_id, cutoff),
        ).fetchall()

        stats = {
            "total_devices": row["total_devices"] if row else 0,
            "total_pan_ids": row["total_pan_ids"] if row else 0,
            "active_nodes": row["active_nodes"] if row else 0,
            "type_breakdown": {r["device_type"]: r["count"] for r in type_rows},
        }
        self._ctx.cache.put(cache_key, stats, ttl=30)
        return stats

    # ------------------------------------------------------------------
    # Hourly aggregation
    # ------------------------------------------------------------------

    def aggregate_zigbee_hourly(self, cutoff_hours: int = 2) -> int:
        """Roll up raw zigbee_devices older than *cutoff_hours* into hourly buckets."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
        ).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """INSERT OR REPLACE INTO zigbee_devices_hourly (
                       hour, ieee_addr, short_addr, device_name, device_type,
                       pan_id, extended_pan_id, channel, manufacturer, node_id,
                       avg_rssi_dbm, min_rssi_dbm, max_rssi_dbm, avg_lqi,
                       observation_count, clusters_json,
                       stack_profile, security_enabled, parent_addr,
                       tenant_id
                   )
                   SELECT strftime('%Y-%m-%dT%H:00:00', timestamp) as hour,
                          ieee_addr, short_addr, device_name, device_type,
                          pan_id, extended_pan_id, channel, manufacturer, node_id,
                          AVG(rssi_dbm), MIN(rssi_dbm), MAX(rssi_dbm), AVG(lqi),
                          COUNT(*), clusters_json,
                          stack_profile, MAX(security_enabled), parent_addr,
                          tenant_id
                   FROM zigbee_devices
                   WHERE tenant_id = ? AND timestamp < ?
                   GROUP BY strftime('%Y-%m-%dT%H:00:00', timestamp), ieee_addr, node_id""",
                (self._ctx.tenant_id, cutoff),
            )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def cleanup_zigbee_devices(self, max_age_hours: int = 24) -> int:
        """Delete raw zigbee_devices rows older than *max_age_hours*."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()
        total_deleted = 0
        batch_size = 50_000
        while True:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    """DELETE FROM zigbee_devices WHERE rowid IN (
                       SELECT rowid FROM zigbee_devices
                       WHERE tenant_id = ? AND timestamp < ? LIMIT ?)""",
                    (self._ctx.tenant_id, cutoff, batch_size),
                )
            deleted = cursor.rowcount
            total_deleted += deleted
            if deleted < batch_size:
                break
        if total_deleted:
            self._ctx.cache.invalidate_prefix(CacheTag.GET_ZB_DEVICES.value)
            self._ctx.cache.invalidate_prefix(CacheTag.GET_ZB_STATS.value)
            logger.info(
                "Cleaned up %d zigbee_devices rows older than %dh",
                total_deleted,
                max_age_hours,
            )
        return total_deleted

    def cleanup_zigbee_hourly(self, max_age_days: int = 90) -> int:
        """Delete hourly rollup rows older than *max_age_days*."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM zigbee_devices_hourly WHERE tenant_id = ? AND hour < ?",
                (self._ctx.tenant_id, cutoff),
            )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Channel energy
    # ------------------------------------------------------------------

    def insert_channel_energy(self, records: list[dict]) -> int:
        """Insert channel energy scan results."""
        if not records:
            return 0
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                r["channel"],
                r["rssi_dbm"],
                r.get("node_id", ""),
                now,
                self._ctx.tenant_id,
            )
            for r in records
        ]
        with self._ctx.write_transaction() as conn:
            conn.executemany(
                """INSERT INTO zigbee_channel_energy
                   (channel, rssi_dbm, node_id, timestamp, tenant_id)
                   VALUES (?, ?, ?, ?, ?)""",
                rows,
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_ZB_STATS.value)
        return len(rows)

    def get_channel_energy(
        self, hours: int = 1, node_id: str | None = None
    ) -> list[dict]:
        """Return recent channel energy readings."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        conn = self._ctx.get_conn()
        wheres = ["tenant_id = ?", "timestamp >= ?"]
        params: list[Any] = [self._ctx.tenant_id, cutoff]
        if node_id:
            wheres.append("node_id = ?")
            params.append(node_id)
        rows = conn.execute(
            f"""SELECT channel, AVG(rssi_dbm) as avg_rssi,
                       MIN(rssi_dbm) as min_rssi, MAX(rssi_dbm) as max_rssi,
                       COUNT(*) as sample_count
                FROM zigbee_channel_energy
                WHERE {" AND ".join(wheres)}
                GROUP BY channel ORDER BY channel""",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def cleanup_channel_energy(self, max_age_hours: int = 24) -> int:
        """Delete channel energy rows older than *max_age_hours*."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM zigbee_channel_energy WHERE tenant_id = ? AND timestamp < ?",
                (self._ctx.tenant_id, cutoff),
            )
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Network topology
    # ------------------------------------------------------------------

    def get_network_topology(self) -> list[dict]:
        """Return devices grouped by PAN ID for topology view.

        Groups devices hierarchically: coordinator → router → end_device
        within each PAN.
        """
        conn = self._ctx.get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        rows = conn.execute(
            """SELECT ieee_addr, short_addr, device_name, device_type,
                      pan_id, extended_pan_id, channel, rssi_dbm, lqi,
                      manufacturer, parent_addr, security_enabled,
                      stack_profile, node_id, MAX(timestamp) as last_seen
               FROM zigbee_devices
               WHERE tenant_id = ? AND timestamp >= ?
               GROUP BY ieee_addr
               ORDER BY pan_id, CASE device_type
                   WHEN 'coordinator' THEN 0
                   WHEN 'router' THEN 1
                   WHEN 'end_device' THEN 2
                   ELSE 3 END,
               ieee_addr""",
            (self._ctx.tenant_id, cutoff),
        ).fetchall()

        pans: dict[str, dict] = {}
        for row in rows:
            d = dict(row)
            pid = d["pan_id"] or "unknown"
            if pid not in pans:
                pans[pid] = {
                    "pan_id": pid,
                    "extended_pan_id": d.get("extended_pan_id", ""),
                    "channel": d["channel"],
                    "security_enabled": d.get("security_enabled", 0),
                    "stack_profile": d.get("stack_profile", ""),
                    "devices": [],
                }
            pans[pid]["devices"].append(d)

        return list(pans.values())
