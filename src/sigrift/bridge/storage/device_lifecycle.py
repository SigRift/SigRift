"""Device lifecycle daily rollup for BT and Zigbee devices.

Aggregates per-scan device discoveries into daily summaries,
reducing storage by ~6x while preserving first/last seen and signal stats.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


class DeviceLifecycleStore:
    """Daily rollup of BT and Zigbee device discoveries."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def rollup_bt_daily(self) -> int:
        """Roll up bt_devices into device_lifecycles_daily."""
        sql = """
            INSERT OR REPLACE INTO device_lifecycles_daily
                (date, node_id, device_type, device_id, device_name,
                 manufacturer, discovery_count, avg_signal_dbm,
                 min_signal_dbm, max_signal_dbm, first_seen, last_seen,
                 status, tenant_id)
            SELECT
                date(timestamp) AS date,
                node_id,
                'bt' AS device_type,
                device_addr AS device_id,
                COALESCE(MAX(device_name), '') AS device_name,
                COALESCE(MAX(manufacturer), '') AS manufacturer,
                COUNT(*) AS discovery_count,
                AVG(rssi_dbm) AS avg_signal_dbm,
                MIN(rssi_dbm) AS min_signal_dbm,
                MAX(rssi_dbm) AS max_signal_dbm,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                'active' AS status,
                ? AS tenant_id
            FROM bt_devices
            GROUP BY date(timestamp), node_id, device_addr
        """
        try:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(sql, (self._ctx.tenant_id,))
                count = cursor.rowcount
        except Exception as e:
            logger.debug("BT daily rollup skipped: %s", e)
            return 0

        if count > 0:
            logger.info("BT daily rollup: %d lifecycle rows", count)
        return count

    def rollup_zigbee_daily(self) -> int:
        """Roll up zigbee_devices into device_lifecycles_daily."""
        sql = """
            INSERT OR REPLACE INTO device_lifecycles_daily
                (date, node_id, device_type, device_id, device_name,
                 manufacturer, discovery_count, avg_signal_dbm,
                 min_signal_dbm, max_signal_dbm, first_seen, last_seen,
                 status, tenant_id)
            SELECT
                date(timestamp) AS date,
                node_id,
                'zigbee' AS device_type,
                ieee_addr AS device_id,
                COALESCE(MAX(device_type), '') AS device_name,
                COALESCE(MAX(manufacturer), '') AS manufacturer,
                COUNT(*) AS discovery_count,
                AVG(lqi) AS avg_signal_dbm,
                MIN(lqi) AS min_signal_dbm,
                MAX(lqi) AS max_signal_dbm,
                MIN(timestamp) AS first_seen,
                MAX(timestamp) AS last_seen,
                'active' AS status,
                ? AS tenant_id
            FROM zigbee_devices
            GROUP BY date(timestamp), node_id, ieee_addr
        """
        try:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(sql, (self._ctx.tenant_id,))
                count = cursor.rowcount
        except Exception as e:
            logger.debug("Zigbee daily rollup skipped: %s", e)
            return 0

        if count > 0:
            logger.info("Zigbee daily rollup: %d lifecycle rows", count)
        return count

    def archive_old_devices(
        self, bt_max_age_days: int = 7, zb_max_age_days: int = 7
    ) -> dict[str, int]:
        """Delete raw device rows older than threshold (already rolled up)."""
        results = {}
        cutoff_bt = (
            datetime.now(timezone.utc) - timedelta(days=bt_max_age_days)
        ).isoformat()
        cutoff_zb = (
            datetime.now(timezone.utc) - timedelta(days=zb_max_age_days)
        ).isoformat()

        with self._ctx.write_transaction() as conn:
            try:
                c = conn.execute(
                    "DELETE FROM bt_devices WHERE timestamp < ?", (cutoff_bt,)
                )
                results["archived_bt"] = c.rowcount
            except Exception as e:
                logger.debug("BT archive skipped: %s", e)
                results["archived_bt"] = 0
            try:
                c = conn.execute(
                    "DELETE FROM zigbee_devices WHERE timestamp < ?", (cutoff_zb,)
                )
                results["archived_zigbee"] = c.rowcount
            except Exception as e:
                logger.debug("Zigbee archive skipped: %s", e)
                results["archived_zigbee"] = 0

        total = sum(results.values())
        if total > 0:
            logger.info("Device archive: %s", results)
        return results

    def cleanup_lifecycles(self, max_age_days: int = 90) -> int:
        """Delete lifecycle summaries older than threshold."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).strftime(
            "%Y-%m-%d"
        )
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM device_lifecycles_daily WHERE date < ?",
                (cutoff,),
            )
            count = cursor.rowcount

        if count > 0:
            logger.info("Cleaned up %d old device lifecycle rows", count)
        return count

    def get_lifecycles(
        self,
        days: int = 7,
        device_type: str | None = None,
        node_id: str | None = None,
    ) -> list[dict]:
        """Query device lifecycles."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime(
            "%Y-%m-%d"
        )
        sql = "SELECT * FROM device_lifecycles_daily WHERE date >= ?"
        params: list[Any] = [cutoff]
        if device_type:
            sql += " AND device_type = ?"
            params.append(device_type)
        if node_id:
            sql += " AND node_id = ?"
            params.append(node_id)
        sql += " ORDER BY date DESC, last_seen DESC LIMIT 10000"

        conn = self._ctx.get_conn()
        conn.row_factory = _dict_factory
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.row_factory = None

    def run_daily_rollup(self) -> dict[str, int]:
        """Run all daily rollup operations."""
        return {
            "bt_lifecycles": self.rollup_bt_daily(),
            "zigbee_lifecycles": self.rollup_zigbee_daily(),
        }


def _dict_factory(cursor, row):
    return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
