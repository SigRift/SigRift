"""Incident lifecycle management storage sub-store.

SQLite-backed storage for security incidents with state machine,
operator assignment, evidence linking, timeline events, and
resolution tracking.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Valid incident states (lifecycle)
INCIDENT_STATES = ("open", "investigating", "escalated", "resolved", "closed")

# Valid resolution classifications
RESOLUTION_TYPES = (
    "confirmed_threat",
    "false_alarm",
    "inconclusive",
    "known_device",
    "benign",
)

# Valid event types for the timeline
EVENT_TYPES = (
    "created",
    "assigned",
    "state_change",
    "note",
    "evidence",
    "detection_linked",
    "escalated",
    "resolved",
    "closed",
    "reopened",
)


class IncidentStore:
    """Incident lifecycle management backed by a :class:`SharedContext`.

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

    def create_incident(
        self,
        title: str,
        severity: str = "warning",
        description: str = "",
        node_id: str = "",
        freq_hz: float = 0.0,
        signal_class: str = "",
        anomaly_score: float = 0.0,
        alert_id: str = "",
        created_by: str = "",
        tenant_id: str = "default",
    ) -> dict[str, Any]:
        """Create a new incident.

        Returns the created incident dict.
        """
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (incident_id, title, severity, description, status,
                    node_id, freq_hz, signal_class, anomaly_score,
                    alert_id, assigned_to, resolution, resolution_note,
                    created_by, created_at, updated_at, resolved_at,
                    tenant_id)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    incident_id,
                    title,
                    severity,
                    description,
                    "open",
                    node_id,
                    freq_hz,
                    signal_class,
                    anomaly_score,
                    alert_id,
                    "",
                    "",
                    "",
                    created_by,
                    now,
                    now,
                    None,
                    tenant_id,
                ),
            )
            # Record creation event
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    "created",
                    created_by,
                    f"Incident created: {title}",
                    now,
                ),
            )

        logger.info("Incident created: %s (%s)", incident_id, title)
        return self.get_incident(incident_id)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> dict[str, Any] | None:
        """Return a single incident by ID."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_incidents(
        self,
        status: str | None = None,
        severity: str | None = None,
        assigned_to: str | None = None,
        tenant_id: str = "default",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List incidents with optional filters."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]

        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if assigned_to:
            clauses.append("assigned_to = ?")
            params.append(assigned_to)

        where = " AND ".join(clauses)
        params.extend([limit, offset])
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM incidents WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def count_incidents(
        self,
        status: str | None = None,
        tenant_id: str = "default",
    ) -> int:
        """Count incidents with optional status filter."""
        clauses = ["tenant_id = ?"]
        params: list[Any] = [tenant_id]
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses)
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM incidents WHERE {where}",
            params,
        ).fetchone()
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    def assign_incident(
        self,
        incident_id: str,
        assigned_to: str,
        actor: str = "",
    ) -> dict[str, Any] | None:
        """Assign an incident to an operator."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "UPDATE incidents SET assigned_to = ?, updated_at = ? "
                "WHERE incident_id = ?",
                (assigned_to, now, incident_id),
            )
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    "assigned",
                    actor,
                    f"Assigned to {assigned_to}",
                    now,
                ),
            )
        return self.get_incident(incident_id)

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        actor: str = "",
        note: str = "",
    ) -> dict[str, Any] | None:
        """Transition incident to a new status."""
        if new_status not in INCIDENT_STATES:
            return None

        now = datetime.now(timezone.utc).isoformat()
        updates = {"status": new_status, "updated_at": now}
        if new_status == "resolved":
            updates["resolved_at"] = now

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        params = list(updates.values()) + [incident_id]

        event_type = (
            new_status
            if new_status in ("escalated", "resolved", "closed")
            else "state_change"
        )

        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE incidents SET {set_clause} WHERE incident_id = ?",
                params,
            )
            detail = f"Status changed to {new_status}"
            if note:
                detail += f": {note}"
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (str(uuid.uuid4()), incident_id, event_type, actor, detail, now),
            )
        return self.get_incident(incident_id)

    def resolve_incident(
        self,
        incident_id: str,
        resolution: str,
        resolution_note: str = "",
        actor: str = "",
    ) -> dict[str, Any] | None:
        """Resolve an incident with a classification."""
        if resolution not in RESOLUTION_TYPES:
            return None

        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "UPDATE incidents SET status = 'resolved', resolution = ?, "
                "resolution_note = ?, resolved_at = ?, updated_at = ? "
                "WHERE incident_id = ?",
                (resolution, resolution_note, now, now, incident_id),
            )
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (
                    str(uuid.uuid4()),
                    incident_id,
                    "resolved",
                    actor,
                    f"Resolved as {resolution}: {resolution_note}"
                    if resolution_note
                    else f"Resolved as {resolution}",
                    now,
                ),
            )
        return self.get_incident(incident_id)

    # ------------------------------------------------------------------
    # Evidence & notes
    # ------------------------------------------------------------------

    def add_note(
        self,
        incident_id: str,
        note: str,
        actor: str = "",
    ) -> dict[str, Any]:
        """Add a text note to the incident timeline."""
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (event_id, incident_id, "note", actor, note, now),
            )
            conn.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now, incident_id),
            )
        return {"event_id": event_id, "event_type": "note", "detail": note}

    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        reference: str,
        description: str = "",
        actor: str = "",
    ) -> dict[str, Any]:
        """Add an evidence reference (IQ capture, photo, etc.)."""
        now = datetime.now(timezone.utc).isoformat()
        event_id = str(uuid.uuid4())
        detail = json.dumps(
            {
                "evidence_type": evidence_type,
                "reference": reference,
                "description": description,
            }
        )
        with self._ctx.write_transaction() as conn:
            conn.execute(
                """INSERT INTO incident_events
                   (event_id, incident_id, event_type, actor, detail, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (event_id, incident_id, "evidence", actor, detail, now),
            )
            conn.execute(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now, incident_id),
            )
        return {
            "event_id": event_id,
            "evidence_type": evidence_type,
            "reference": reference,
        }

    # ------------------------------------------------------------------
    # Detection linking
    # ------------------------------------------------------------------

    def link_detection(
        self,
        incident_id: str,
        detection_id: str,
        actor: str = "",
    ) -> bool:
        """Link a detection to an incident."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    """INSERT OR IGNORE INTO incident_detections
                       (incident_id, detection_id, linked_at)
                       VALUES (?,?,?)""",
                    (incident_id, detection_id, now),
                )
                conn.execute(
                    """INSERT INTO incident_events
                       (event_id, incident_id, event_type, actor, detail, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        incident_id,
                        "detection_linked",
                        actor,
                        f"Linked detection {detection_id}",
                        now,
                    ),
                )
                conn.execute(
                    "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                    (now, incident_id),
                )
            return True
        except Exception:
            # The partial link (if any) was rolled back with the transaction.
            return False

    def get_linked_detections(self, incident_id: str) -> list[str]:
        """Return detection IDs linked to an incident."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT detection_id FROM incident_detections "
            "WHERE incident_id = ? ORDER BY linked_at",
            (incident_id,),
        ).fetchall()
        return [r["detection_id"] for r in rows]

    # ------------------------------------------------------------------
    # Timeline
    # ------------------------------------------------------------------

    def get_timeline(
        self,
        incident_id: str,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Return the full event timeline for an incident."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM incident_events WHERE incident_id = ? "
            "ORDER BY created_at ASC LIMIT ?",
            (incident_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # SLA metrics
    # ------------------------------------------------------------------

    def get_sla_metrics(self, tenant_id: str = "default") -> dict[str, Any]:
        """Compute SLA metrics: MTTA, MTTR, open/resolved counts."""
        conn = self._ctx.get_conn()

        open_count = self.count_incidents(status="open", tenant_id=tenant_id)
        investigating = self.count_incidents(
            status="investigating", tenant_id=tenant_id
        )
        resolved = self.count_incidents(status="resolved", tenant_id=tenant_id)
        closed = self.count_incidents(status="closed", tenant_id=tenant_id)

        # Mean time to resolve (for resolved/closed incidents)
        row = conn.execute(
            "SELECT AVG(JULIANDAY(resolved_at) - JULIANDAY(created_at)) * 24 as avg_hours "
            "FROM incidents WHERE resolved_at IS NOT NULL AND tenant_id = ?",
            (tenant_id,),
        ).fetchone()
        mttr_hours = round(row["avg_hours"], 2) if row and row["avg_hours"] else None

        return {
            "open": open_count,
            "investigating": investigating,
            "resolved": resolved,
            "closed": closed,
            "total": open_count + investigating + resolved + closed,
            "mttr_hours": mttr_hours,
        }
