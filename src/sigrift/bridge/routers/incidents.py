"""Incident lifecycle management API endpoints for The Bridge.

Provides CRUD, state transitions, assignment, evidence attachment,
detection linking, timeline reconstruction, and SLA metrics.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.storage.incidents import (
    INCIDENT_STATES,
    RESOLUTION_TYPES,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_incident_store(request: Request) -> Any:
    store = getattr(request.app.state, "incident_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Incident store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateIncidentRequest(BaseModel):
    model_config = {"extra": "forbid"}

    title: str = Field(..., min_length=1, max_length=500)
    severity: str = Field("warning")
    description: str = Field("")
    node_id: str = Field("")
    freq_hz: float = Field(0.0)
    signal_class: str = Field("")
    anomaly_score: float = Field(0.0, ge=0.0, le=1.0)
    alert_id: str = Field("")


class AssignRequest(BaseModel):
    model_config = {"extra": "forbid"}

    assigned_to: str = Field(..., min_length=1)


class StatusUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}

    status: str = Field(...)
    note: str = Field("")


class ResolveRequest(BaseModel):
    model_config = {"extra": "forbid"}

    resolution: str = Field(...)
    resolution_note: str = Field("")


class NoteRequest(BaseModel):
    model_config = {"extra": "forbid"}

    note: str = Field(..., min_length=1)


class EvidenceRequest(BaseModel):
    model_config = {"extra": "forbid"}

    evidence_type: str = Field(
        ..., min_length=1, description="iq_capture, photo, spectrum, document"
    )
    reference: str = Field(..., min_length=1, description="ID or path to evidence")
    description: str = Field("")


class LinkDetectionRequest(BaseModel):
    model_config = {"extra": "forbid"}

    detection_id: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_incident(
    body: CreateIncidentRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a new incident."""
    store = _get_incident_store(request)
    return store.create_incident(
        title=body.title,
        severity=body.severity,
        description=body.description,
        node_id=body.node_id,
        freq_hz=body.freq_hz,
        signal_class=body.signal_class,
        anomaly_score=body.anomaly_score,
        alert_id=body.alert_id,
        created_by=_key_id,
    )


@router.get("/")
def list_incidents(
    request: Request,
    incident_status: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    assigned_to: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List incidents with optional filters."""
    store = _get_incident_store(request)
    incidents = store.list_incidents(
        status=incident_status,
        severity=severity,
        assigned_to=assigned_to,
        limit=limit,
        offset=offset,
    )
    total = store.count_incidents(status=incident_status)
    return {"incidents": incidents, "count": len(incidents), "total": total}


@router.get("/metrics")
def get_sla_metrics(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get SLA metrics (MTTA, MTTR, counts by status)."""
    store = _get_incident_store(request)
    return store.get_sla_metrics()


@router.get("/{incident_id}")
def get_incident(
    incident_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get a single incident by ID."""
    store = _get_incident_store(request)
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.put("/{incident_id}/assign")
def assign_incident(
    incident_id: str,
    body: AssignRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Assign an incident to an operator."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    result = store.assign_incident(incident_id, body.assigned_to, actor=_key_id)
    return result


@router.put("/{incident_id}/status")
def update_status(
    incident_id: str,
    body: StatusUpdateRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update incident status."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.status not in INCIDENT_STATES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status. Must be one of: {', '.join(INCIDENT_STATES)}",
        )
    result = store.update_status(
        incident_id, body.status, actor=_key_id, note=body.note
    )
    return result


@router.put("/{incident_id}/resolve")
def resolve_incident(
    incident_id: str,
    body: ResolveRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Resolve an incident with a classification."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    if body.resolution not in RESOLUTION_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid resolution. Must be one of: {', '.join(RESOLUTION_TYPES)}",
        )
    result = store.resolve_incident(
        incident_id,
        body.resolution,
        body.resolution_note,
        actor=_key_id,
    )
    return result


@router.post("/{incident_id}/notes")
def add_note(
    incident_id: str,
    body: NoteRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Add a note to the incident timeline."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return store.add_note(incident_id, body.note, actor=_key_id)


@router.post("/{incident_id}/evidence")
def add_evidence(
    incident_id: str,
    body: EvidenceRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Add evidence to the incident."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return store.add_evidence(
        incident_id,
        evidence_type=body.evidence_type,
        reference=body.reference,
        description=body.description,
        actor=_key_id,
    )


@router.post("/{incident_id}/detections")
def link_detection(
    incident_id: str,
    body: LinkDetectionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Link a detection to an incident."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    store.link_detection(incident_id, body.detection_id, actor=_key_id)
    return {"ok": True, "detection_id": body.detection_id}


@router.get("/{incident_id}/detections")
def get_linked_detections(
    incident_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get detection IDs linked to an incident."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    ids = store.get_linked_detections(incident_id)
    return {"detection_ids": ids, "count": len(ids)}


@router.get("/{incident_id}/timeline")
def get_timeline(
    incident_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get the full event timeline for an incident."""
    store = _get_incident_store(request)
    if store.get_incident(incident_id) is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    events = store.get_timeline(incident_id)
    return {"events": events, "count": len(events)}
