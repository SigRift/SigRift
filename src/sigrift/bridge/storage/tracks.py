"""Emitter track storage sub-store.

SQLite-backed storage for Kalman-filtered emitter tracks and
individual track points.  Uses the SharedContext pattern for
thread-safe access.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_TRACKS_SCHEMA = """
CREATE TABLE IF NOT EXISTS emitter_tracks (
    track_id TEXT PRIMARY KEY,
    emitter_id TEXT,
    status TEXT DEFAULT 'active',
    first_seen REAL,
    last_seen REAL,
    total_distance_m REAL DEFAULT 0,
    mean_velocity_mps REAL DEFAULT 0,
    is_stationary INTEGER DEFAULT 1,
    classification TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS track_points (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    track_id TEXT NOT NULL REFERENCES emitter_tracks(track_id),
    x REAL NOT NULL,
    y REAL NOT NULL,
    vx REAL DEFAULT 0,
    vy REAL DEFAULT 0,
    confidence REAL,
    timestamp REAL NOT NULL,
    source_estimate_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_track_points_track_id
    ON track_points (track_id);
CREATE INDEX IF NOT EXISTS idx_track_points_timestamp
    ON track_points (timestamp);
CREATE INDEX IF NOT EXISTS idx_emitter_tracks_status
    ON emitter_tracks (status);
CREATE INDEX IF NOT EXISTS idx_emitter_tracks_emitter_id
    ON emitter_tracks (emitter_id);
"""


class TrackStore:
    """Emitter track persistence backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        from sigrift.bridge.storage.base import SharedContext

        self._ctx: SharedContext = ctx
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        """Create tables if they do not exist."""
        with self._ctx.transaction() as conn:
            conn.executescript(_TRACKS_SCHEMA)

    # ------------------------------------------------------------------
    # Create / insert
    # ------------------------------------------------------------------

    def create_track(
        self,
        track_id: str,
        emitter_id: str | None = None,
        first_seen: float = 0.0,
        last_seen: float = 0.0,
        status: str = "active",
        classification: str | None = None,
    ) -> dict[str, Any]:
        """Create a new emitter track record.

        Returns the created track as a dict.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO emitter_tracks
                   (track_id, emitter_id, status, first_seen, last_seen,
                    classification, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    track_id,
                    emitter_id,
                    status,
                    first_seen,
                    last_seen,
                    classification,
                    now,
                    now,
                ),
            )
        return self.get_track(track_id) or {}

    def add_point(
        self,
        track_id: str,
        x: float,
        y: float,
        timestamp: float,
        vx: float = 0.0,
        vy: float = 0.0,
        confidence: float | None = None,
        source_estimate_id: str | None = None,
    ) -> int:
        """Add a track point to an existing track.

        Returns the row ID of the inserted point.
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """INSERT INTO track_points
                   (track_id, x, y, vx, vy, confidence, timestamp,
                    source_estimate_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (track_id, x, y, vx, vy, confidence, timestamp, source_estimate_id),
            )
        return cursor.lastrowid or 0

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_track(self, track_id: str) -> dict[str, Any] | None:
        """Retrieve a single track by ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM emitter_tracks WHERE track_id = ?",
            (track_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_track_points(
        self,
        track_id: str,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Retrieve track points ordered by timestamp ascending."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            """SELECT id, track_id, x, y, vx, vy, confidence,
                      timestamp, source_estimate_id, created_at
               FROM track_points
               WHERE track_id = ?
               ORDER BY timestamp ASC
               LIMIT ?""",
            (track_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_tracks(
        self,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List tracks, optionally filtered by status."""
        conn = self._ctx.get_conn()
        if status:
            rows = conn.execute(
                """SELECT * FROM emitter_tracks
                   WHERE status = ?
                   ORDER BY last_seen DESC
                   LIMIT ?""",
                (status, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM emitter_tracks
                   ORDER BY last_seen DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_active_tracks(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return only active tracks."""
        return self.list_tracks(status="active", limit=limit)

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_track_status(self, track_id: str, status: str) -> bool:
        """Update the status of a track. Returns True if updated."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """UPDATE emitter_tracks
                   SET status = ?, updated_at = ?
                   WHERE track_id = ?""",
                (status, now, track_id),
            )
        return cursor.rowcount > 0

    def update_track_summary(
        self,
        track_id: str,
        last_seen: float,
        total_distance_m: float,
        mean_velocity_mps: float,
        is_stationary: bool,
        classification: str | None,
    ) -> bool:
        """Update the summary statistics of a track."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """UPDATE emitter_tracks
                   SET last_seen = ?, total_distance_m = ?,
                       mean_velocity_mps = ?, is_stationary = ?,
                       classification = ?, updated_at = ?
                   WHERE track_id = ?""",
                (
                    last_seen,
                    total_distance_m,
                    mean_velocity_mps,
                    1 if is_stationary else 0,
                    classification,
                    now,
                    track_id,
                ),
            )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_track(self, track_id: str) -> bool:
        """Delete a track and all its points. Returns True if deleted."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "DELETE FROM track_points WHERE track_id = ?",
                (track_id,),
            )
            cursor = conn.execute(
                "DELETE FROM emitter_tracks WHERE track_id = ?",
                (track_id,),
            )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return aggregate statistics about tracks."""
        conn = self._ctx.get_conn()
        track_row = conn.execute(
            "SELECT COUNT(*) as total FROM emitter_tracks"
        ).fetchone()
        active_row = conn.execute(
            "SELECT COUNT(*) as total FROM emitter_tracks WHERE status = 'active'"
        ).fetchone()
        lost_row = conn.execute(
            "SELECT COUNT(*) as total FROM emitter_tracks WHERE status = 'lost'"
        ).fetchone()
        point_row = conn.execute(
            "SELECT COUNT(*) as total FROM track_points"
        ).fetchone()
        return {
            "total_tracks": track_row["total"] if track_row else 0,
            "active_tracks": active_row["total"] if active_row else 0,
            "lost_tracks": lost_row["total"] if lost_row else 0,
            "total_points": point_row["total"] if point_row else 0,
        }
