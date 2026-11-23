"""Aircraft tracking sub-store for ADS-B and UAT detections."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


class AircraftStore:
    """Sub-store for aircraft position tracking.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx

    def insert_position(self, track_data: dict) -> int:
        """Insert an aircraft position report.

        Parameters
        ----------
        track_data : dict
            Keys: icao_address, callsign, source, lat, lon, altitude_ft,
            velocity_kts, heading_deg, squawk, rssi_dbm, node_id,
            timestamp.  The row's tenant is the store's own (its
            ``SharedContext``); a ``tenant_id`` in *track_data* is ignored,
            since positions come from edge nodes.

        Returns
        -------
        int
            Row ID of the inserted record.
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO aircraft_tracks
                   (icao_address, callsign, source, lat, lon, altitude_ft,
                    velocity_kts, heading_deg, squawk, rssi_dbm, node_id,
                    timestamp, tenant_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    track_data.get("icao_address"),
                    track_data.get("callsign"),
                    track_data.get("source", "adsb"),
                    track_data.get("lat"),
                    track_data.get("lon"),
                    track_data.get("altitude_ft"),
                    track_data.get("velocity_kts"),
                    track_data.get("heading_deg"),
                    track_data.get("squawk"),
                    track_data.get("rssi_dbm"),
                    track_data.get("node_id", ""),
                    track_data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    self._ctx.tenant_id,
                ),
            )
        return cursor.lastrowid

    def get_active_aircraft(
        self,
        max_age_seconds: int = 300,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Get aircraft with recent position updates.

        Parameters
        ----------
        max_age_seconds : int
            Maximum age of position updates to include.
        tenant_id : str or None
            Tenant filter; defaults to context tenant.
        """
        tid = tenant_id or self._ctx.tenant_id
        conn = self._ctx.get_conn()
        cutoff = (
            datetime.now(timezone.utc) - timedelta(seconds=max_age_seconds)
        ).isoformat()
        rows = conn.execute(
            """SELECT icao_address, callsign, source, lat, lon, altitude_ft,
                      velocity_kts, heading_deg, squawk, rssi_dbm, node_id,
                      MAX(timestamp) as last_seen
               FROM aircraft_tracks
               WHERE tenant_id = ? AND timestamp >= ?
               GROUP BY icao_address
               ORDER BY last_seen DESC""",
            (tid, cutoff),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_aircraft_history(
        self,
        icao_address: str,
        hours: int = 1,
        tenant_id: str | None = None,
    ) -> list[dict]:
        """Get position trail for a single aircraft.

        Parameters
        ----------
        icao_address : str
            ICAO 24-bit hex address.
        hours : int
            Lookback window in hours.
        tenant_id : str or None
            Tenant filter; defaults to context tenant.
        """
        tid = tenant_id or self._ctx.tenant_id
        conn = self._ctx.get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        rows = conn.execute(
            """SELECT lat, lon, altitude_ft, velocity_kts, heading_deg,
                      rssi_dbm, timestamp
               FROM aircraft_tracks
               WHERE icao_address = ? AND tenant_id = ? AND timestamp >= ?
               ORDER BY timestamp ASC""",
            (icao_address, tid, cutoff),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self, tenant_id: str | None = None) -> dict:
        """Get aircraft tracking statistics for the last 5 minutes."""
        tid = tenant_id or self._ctx.tenant_id
        conn = self._ctx.get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()

        by_source = conn.execute(
            """SELECT source, COUNT(DISTINCT icao_address)
               FROM aircraft_tracks
               WHERE tenant_id = ? AND timestamp >= ?
               GROUP BY source""",
            (tid, cutoff),
        ).fetchall()

        total = conn.execute(
            "SELECT COUNT(DISTINCT icao_address) FROM aircraft_tracks WHERE tenant_id = ? AND timestamp >= ?",
            (tid, cutoff),
        ).fetchone()[0]

        return {
            "total_active": total,
            "by_source": {r[0]: r[1] for r in by_source},
        }

    def cleanup_stale(
        self,
        max_age_hours: int = 24,
        tenant_id: str | None = None,
    ) -> int:
        """Remove old aircraft tracks.

        Parameters
        ----------
        max_age_hours : int
            Maximum age before deletion.
        tenant_id : str or None
            Tenant filter; defaults to context tenant.

        Returns
        -------
        int
            Number of rows deleted.
        """
        tid = tenant_id or self._ctx.tenant_id
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM aircraft_tracks WHERE tenant_id = ? AND timestamp < ?",
                (tid, cutoff),
            )
        return cursor.rowcount
