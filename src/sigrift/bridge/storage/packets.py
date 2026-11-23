"""Packet detection storage sub-store.

SQLite-backed storage for packet boundary detections and timing analyses,
following the SharedContext pattern used by FingerprintStore.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_PACKET_SCHEMA = """
CREATE TABLE IF NOT EXISTS packet_detections (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    packet_index INTEGER NOT NULL,
    start_sample INTEGER NOT NULL,
    end_sample INTEGER NOT NULL,
    duration_samples INTEGER NOT NULL,
    duration_seconds REAL,
    peak_energy_db REAL,
    mean_energy_db REAL,
    mean_entropy REAL,
    snr_estimate_db REAL,
    confidence REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pkt_detection_id
    ON packet_detections (detection_id) WHERE detection_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pkt_created_at
    ON packet_detections (created_at);

CREATE TABLE IF NOT EXISTS packet_timing_analyses (
    id TEXT PRIMARY KEY,
    detection_id TEXT UNIQUE,
    n_packets INTEGER NOT NULL,
    mean_gap_seconds REAL,
    std_gap_seconds REAL,
    is_periodic INTEGER DEFAULT 0,
    estimated_period_seconds REAL,
    duty_cycle REAL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pkt_timing_detection_id
    ON packet_timing_analyses (detection_id) WHERE detection_id IS NOT NULL;
"""


class PacketStore:
    """Packet detection operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create packet tables if they do not exist."""
        with self._ctx.transaction() as conn:
            conn.executescript(_PACKET_SCHEMA)

    # -- Write operations ---------------------------------------------------

    def store_packets(
        self,
        detection_id: str | None,
        packets: list[dict[str, Any]],
    ) -> list[str]:
        """Store packet boundary detections.

        Parameters
        ----------
        detection_id : str or None
            Associated detection ID.
        packets : list[dict]
            List of packet dicts with keys matching PacketBoundary fields,
            plus ``packet_index``.

        Returns
        -------
        list[str]
            IDs of stored packet records.
        """
        now = datetime.now(timezone.utc).isoformat()
        ids: list[str] = []
        with self._ctx.write_transaction() as conn:
            for pkt in packets:
                pkt_id = str(uuid.uuid4())
                conn.execute(
                    """
                    INSERT INTO packet_detections
                        (id, detection_id, packet_index, start_sample, end_sample,
                         duration_samples, duration_seconds, peak_energy_db,
                         mean_energy_db, mean_entropy, snr_estimate_db,
                         confidence, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        pkt_id,
                        detection_id,
                        pkt.get("packet_index", 0),
                        pkt["start_sample"],
                        pkt["end_sample"],
                        pkt["duration_samples"],
                        pkt.get("duration_seconds"),
                        pkt.get("peak_energy_db"),
                        pkt.get("mean_energy_db"),
                        pkt.get("mean_entropy"),
                        pkt.get("snr_estimate_db"),
                        pkt.get("confidence"),
                        now,
                    ),
                )
                ids.append(pkt_id)
        logger.debug("Stored %d packets for detection %s", len(ids), detection_id)
        return ids

    def store_timing(
        self,
        detection_id: str | None,
        timing: dict[str, Any],
    ) -> str:
        """Store a timing analysis result.

        Parameters
        ----------
        detection_id : str or None
            Associated detection ID.
        timing : dict
            TimingAnalysis fields as dict.

        Returns
        -------
        str
            ID of stored timing record.
        """
        now = datetime.now(timezone.utc).isoformat()
        timing_id = str(uuid.uuid4())
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO packet_timing_analyses
                    (id, detection_id, n_packets, mean_gap_seconds,
                     std_gap_seconds, is_periodic, estimated_period_seconds,
                     duty_cycle, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?,
                        COALESCE(
                            (SELECT created_at FROM packet_timing_analyses WHERE detection_id = ?),
                            ?
                        ))
                """,
                (
                    timing_id,
                    detection_id,
                    timing["n_packets"],
                    timing.get("mean_gap_seconds"),
                    timing.get("std_gap_seconds"),
                    1 if timing.get("is_periodic") else 0,
                    timing.get("estimated_period_seconds"),
                    timing.get("duty_cycle"),
                    detection_id,
                    now,
                ),
            )
        logger.debug("Stored timing analysis for detection %s", detection_id)
        return timing_id

    # -- Read operations ----------------------------------------------------

    def get_packets_for(self, detection_id: str) -> list[dict[str, Any]]:
        """Get all packet detections for a detection ID."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM packet_detections WHERE detection_id = ? "
            "ORDER BY packet_index",
            (detection_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_timing_for(self, detection_id: str) -> dict[str, Any] | None:
        """Get timing analysis for a detection ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM packet_timing_analyses WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["is_periodic"] = bool(d.get("is_periodic", 0))
        return d

    def list_analyses(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """List all packet timing analyses.

        Returns timing analyses with packet counts, ordered by created_at DESC.
        """
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM packet_timing_analyses "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["is_periodic"] = bool(d.get("is_periodic", 0))
            results.append(d)
        return results

    def delete_analysis(self, detection_id: str) -> bool:
        """Delete packet detections and timing for a detection_id.

        Returns
        -------
        bool
            True if any rows were deleted.
        """
        with self._ctx.write_transaction() as conn:
            c1 = conn.execute(
                "DELETE FROM packet_detections WHERE detection_id = ?",
                (detection_id,),
            )
            c2 = conn.execute(
                "DELETE FROM packet_timing_analyses WHERE detection_id = ?",
                (detection_id,),
            )
        return (c1.rowcount + c2.rowcount) > 0

    # -- Stats --------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return packet detection statistics."""
        conn = self._ctx.get_conn()

        total_packets = conn.execute(
            "SELECT COUNT(*) as cnt FROM packet_detections"
        ).fetchone()["cnt"]

        total_analyses = conn.execute(
            "SELECT COUNT(*) as cnt FROM packet_timing_analyses"
        ).fetchone()["cnt"]

        periodic_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM packet_timing_analyses WHERE is_periodic = 1"
        ).fetchone()["cnt"]

        return {
            "total_packets": total_packets,
            "total_analyses": total_analyses,
            "periodic_count": periodic_count,
        }
