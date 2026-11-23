"""Sweep session lifecycle storage sub-store.

SQLite-backed storage for TSCM sweep sessions with zone management,
detection/incident linking, and phase state machine.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Valid sweep phases (lifecycle)
SWEEP_PHASES = (
    "pre_assessment",
    "active",
    "analysis",
    "reporting",
    "closed",
)

# Valid zone statuses
ZONE_STATUSES = ("pending", "sweeping", "cleared", "flagged")


class SweepStore:
    """Sweep session lifecycle management backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_sweep(
        self,
        name: str,
        location: str = "",
        scope_description: str = "",
        threat_profile: str = "",
        notes: str = "",
        created_by: str = "",
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Create a new sweep session in pre_assessment phase."""
        sweep_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO sweeps
                   (sweep_id, name, location, phase, status, start_time,
                    end_time, scope_description, threat_profile, notes,
                    created_by, tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sweep_id,
                    name,
                    location,
                    "pre_assessment",
                    "active",
                    now,
                    None,
                    scope_description,
                    threat_profile,
                    notes,
                    created_by,
                    tenant_id,
                ),
            )

        logger.info("Sweep created: %s (%s)", sweep_id, name)
        return self.get_sweep(sweep_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_sweep(self, sweep_id: str) -> dict[str, Any] | None:
        """Return a single sweep by ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM sweeps WHERE sweep_id = ?",
            (sweep_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_sweeps(
        self,
        phase: str | None = None,
        status: str | None = None,
        tenant_id: str = "default",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List sweeps with optional filters."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if phase:
            clauses.append("phase = ?")
            params.append(phase)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = " AND ".join(clauses)
        params.extend([limit, offset])
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM sweeps WHERE {where} "
            f"ORDER BY start_time DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def count_sweeps(
        self,
        phase: str | None = None,
        tenant_id: str = "default",
    ) -> int:
        """Count sweeps with optional phase filter."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if phase:
            clauses.append("phase = ?")
            params.append(phase)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM sweeps WHERE {where}",
            params,
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Phase transitions
    # ------------------------------------------------------------------

    def update_phase(
        self,
        sweep_id: str,
        new_phase: str,
    ) -> dict[str, Any] | None:
        """Transition sweep to a new phase."""
        if new_phase not in SWEEP_PHASES:
            return None

        now = datetime.now(timezone.utc).isoformat()
        updates: dict[str, Any] = {"phase": new_phase}
        if new_phase == "closed":
            updates["end_time"] = now
            updates["status"] = "completed"

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [sweep_id]

        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE sweeps SET {set_clause} WHERE sweep_id = ?",
                params,
            )
        return self.get_sweep(sweep_id)

    # ------------------------------------------------------------------
    # Zone management
    # ------------------------------------------------------------------

    def add_zone(
        self,
        sweep_id: str,
        zone_name: str,
    ) -> dict[str, Any]:
        """Add a zone to a sweep."""
        zone_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO sweep_zones
                   (zone_id, sweep_id, zone_name, status, entered_at,
                    cleared_at, anomaly_count, flagged_reason)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (zone_id, sweep_id, zone_name, "pending", now, None, 0, ""),
            )
        return {
            "zone_id": zone_id,
            "sweep_id": sweep_id,
            "zone_name": zone_name,
            "status": "pending",
        }

    def update_zone_status(
        self,
        zone_id: str,
        new_status: str,
        flagged_reason: str = "",
    ) -> dict[str, Any] | None:
        """Update zone status (pending → sweeping → cleared/flagged)."""
        if new_status not in ZONE_STATUSES:
            return None

        now = datetime.now(timezone.utc).isoformat()
        updates: dict[str, Any] = {"status": new_status}
        if new_status == "cleared":
            updates["cleared_at"] = now
        if new_status == "flagged":
            updates["flagged_reason"] = flagged_reason

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [zone_id]

        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE sweep_zones SET {set_clause} WHERE zone_id = ?",
                params,
            )

        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM sweep_zones WHERE zone_id = ?",
            (zone_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_zones(self, sweep_id: str) -> list[dict[str, Any]]:
        """Return all zones for a sweep."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM sweep_zones WHERE sweep_id = ? ORDER BY entered_at",
            (sweep_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Detection / incident linking
    # ------------------------------------------------------------------

    def link_detection(
        self,
        sweep_id: str,
        detection_id: str,
        zone_id: str = "",
    ) -> bool:
        """Link a detection to a sweep (optionally to a zone)."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO sweep_detections
                       (sweep_id, detection_id, zone_id, linked_at)
                       VALUES (?,?,?,?)""",
                    (sweep_id, detection_id, zone_id, now),
                )
                # Increment zone anomaly count if zone specified
                if zone_id:
                    conn.execute(
                        "UPDATE sweep_zones SET anomaly_count = anomaly_count + 1 "
                        "WHERE zone_id = ?",
                        (zone_id,),
                    )
            return True
        except Exception:
            return False

    def link_incident(
        self,
        sweep_id: str,
        incident_id: str,
        zone_id: str = "",
    ) -> bool:
        """Link an incident to a sweep (optionally to a zone)."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO sweep_incidents
                       (sweep_id, incident_id, zone_id, linked_at)
                       VALUES (?,?,?,?)""",
                    (sweep_id, incident_id, zone_id, now),
                )
            return True
        except Exception:
            return False

    def get_linked_detections(self, sweep_id: str) -> list[str]:
        """Return detection IDs linked to a sweep."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT detection_id FROM sweep_detections "
            "WHERE sweep_id = ? ORDER BY linked_at",
            (sweep_id,),
        ).fetchall()
        return [r["detection_id"] for r in rows]

    def get_linked_incidents(self, sweep_id: str) -> list[str]:
        """Return incident IDs linked to a sweep."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT incident_id FROM sweep_incidents "
            "WHERE sweep_id = ? ORDER BY linked_at",
            (sweep_id,),
        ).fetchall()
        return [r["incident_id"] for r in rows]

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_sweep_summary(self, sweep_id: str) -> dict[str, Any] | None:
        """Return aggregated summary for a sweep."""
        sweep = self.get_sweep(sweep_id)
        if not sweep:
            return None

        conn = self._ctx.get_conn()

        zones = self.get_zones(sweep_id)
        zone_counts = {
            "total": len(zones),
            "pending": sum(1 for z in zones if z["status"] == "pending"),
            "sweeping": sum(1 for z in zones if z["status"] == "sweeping"),
            "cleared": sum(1 for z in zones if z["status"] == "cleared"),
            "flagged": sum(1 for z in zones if z["status"] == "flagged"),
        }

        det_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sweep_detections WHERE sweep_id = ?",
            (sweep_id,),
        ).fetchone()["cnt"]

        inc_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sweep_incidents WHERE sweep_id = ?",
            (sweep_id,),
        ).fetchone()["cnt"]

        return {
            **sweep,
            "zone_summary": zone_counts,
            "detection_count": det_count,
            "incident_count": inc_count,
        }
