"""Sweep session management API endpoints.

Provides CRUD, phase transitions, zone management, and detection/incident
linking for TSCM sweep sessions.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.storage.sweeps import SWEEP_PHASES, ZONE_STATUSES

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateSweepRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(min_length=1, max_length=500)
    location: str = ""
    scope_description: str = ""
    threat_profile: str = ""
    notes: str = ""


class PhaseUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    phase: str = Field(min_length=1)


class AddZoneRequest(BaseModel):
    model_config = {"extra": "forbid"}
    zone_name: str = Field(min_length=1, max_length=200)


class ZoneStatusRequest(BaseModel):
    model_config = {"extra": "forbid"}
    status: str = Field(min_length=1)
    flagged_reason: str = ""


class LinkDetectionRequest(BaseModel):
    model_config = {"extra": "forbid"}
    detection_id: str = Field(min_length=1)
    zone_id: str = ""


class LinkIncidentRequest(BaseModel):
    model_config = {"extra": "forbid"}
    incident_id: str = Field(min_length=1)
    zone_id: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_sweep_store(request: Request) -> Any:
    store = getattr(request.app.state, "sweep_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Sweep store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_sweep(
    body: CreateSweepRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a new sweep session."""
    store = _get_sweep_store(request)
    return store.create_sweep(
        name=body.name,
        location=body.location,
        scope_description=body.scope_description,
        threat_profile=body.threat_profile,
        notes=body.notes,
        created_by=_key_id,
    )


@router.get("/")
def list_sweeps(
    request: Request,
    phase: str | None = None,
    sweep_status: str | None = None,
    limit: int = 100,
    offset: int = 0,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List sweep sessions with optional filters."""
    store = _get_sweep_store(request)
    sweeps = store.list_sweeps(
        phase=phase,
        status=sweep_status,
        limit=limit,
        offset=offset,
    )
    total = store.count_sweeps(phase=phase)
    return {"sweeps": sweeps, "count": len(sweeps), "total": total}


@router.get("/{sweep_id}")
def get_sweep(
    sweep_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get a sweep session by ID."""
    store = _get_sweep_store(request)
    sweep = store.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    return sweep


@router.put("/{sweep_id}/phase")
def update_phase(
    sweep_id: str,
    body: PhaseUpdateRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Transition sweep to a new phase."""
    store = _get_sweep_store(request)
    if body.phase not in SWEEP_PHASES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid phase: {body.phase}. Must be one of {SWEEP_PHASES}",
        )
    sweep = store.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    result = store.update_phase(sweep_id, body.phase)
    return result  # type: ignore[return-value]


@router.post("/{sweep_id}/zones", status_code=status.HTTP_201_CREATED)
def add_zone(
    sweep_id: str,
    body: AddZoneRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Add a zone to a sweep."""
    store = _get_sweep_store(request)
    sweep = store.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    return store.add_zone(sweep_id, body.zone_name)


@router.put("/{sweep_id}/zones/{zone_id}/status")
def update_zone_status(
    sweep_id: str,
    zone_id: str,
    body: ZoneStatusRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update zone status (pending → sweeping → cleared/flagged)."""
    store = _get_sweep_store(request)
    if body.status not in ZONE_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid status: {body.status}. Must be one of {ZONE_STATUSES}",
        )
    result = store.update_zone_status(
        zone_id,
        body.status,
        flagged_reason=body.flagged_reason,
    )
    if not result:
        raise HTTPException(status_code=404, detail="Zone not found")
    return result


@router.get("/{sweep_id}/zones")
def get_zones(
    sweep_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List zones for a sweep."""
    store = _get_sweep_store(request)
    zones = store.get_zones(sweep_id)
    return {"zones": zones, "count": len(zones)}


@router.post("/{sweep_id}/detections")
def link_detection(
    sweep_id: str,
    body: LinkDetectionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Link a detection to a sweep."""
    store = _get_sweep_store(request)
    sweep = store.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    ok = store.link_detection(sweep_id, body.detection_id, zone_id=body.zone_id)
    return {"ok": ok, "detection_id": body.detection_id}


@router.post("/{sweep_id}/incidents")
def link_incident(
    sweep_id: str,
    body: LinkIncidentRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Link an incident to a sweep."""
    store = _get_sweep_store(request)
    sweep = store.get_sweep(sweep_id)
    if not sweep:
        raise HTTPException(status_code=404, detail="Sweep not found")
    ok = store.link_incident(sweep_id, body.incident_id, zone_id=body.zone_id)
    return {"ok": ok, "incident_id": body.incident_id}


@router.get("/{sweep_id}/summary")
def get_sweep_summary(
    sweep_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get aggregated summary for a sweep."""
    store = _get_sweep_store(request)
    summary = store.get_sweep_summary(sweep_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Sweep not found")
    return summary


@router.get("/{sweep_id}/report", response_class=HTMLResponse)
def get_sweep_report(
    sweep_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> HTMLResponse:
    """Generate a self-contained HTML report for a sweep."""
    from sigrift.bridge.sweep_report import SweepReportGenerator

    sweep_store = _get_sweep_store(request)
    incident_store = getattr(request.app.state, "incident_store", None)
    detection_store = getattr(request.app.state, "detection_store", None)

    if not incident_store or not detection_store:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Required stores not initialised",
        )

    generator = SweepReportGenerator(sweep_store, incident_store, detection_store)
    html_content = generator.render_html(sweep_id)
    if not html_content:
        raise HTTPException(status_code=404, detail="Sweep not found")
    return HTMLResponse(content=html_content)
