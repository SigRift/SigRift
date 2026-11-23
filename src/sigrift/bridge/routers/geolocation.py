"""RSSI-based multilateration geolocation API endpoints.

Provides endpoints for managing node positions, estimating emitter
positions from RSSI measurements, and querying stored estimates.
All endpoints are gated behind the ``BRIDGE_GEOLOCATION_ENABLED``
feature flag.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from starlette import status as http_status

from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature flag — same pattern as TDOA router
# ---------------------------------------------------------------------------

GEOLOCATION_ENABLED = os.environ.get("BRIDGE_GEOLOCATION_ENABLED", "false").lower() in (
    "true",
    "1",
    "yes",
)


def _require_geolocation_enabled():
    """Dependency that gates all geolocation endpoints behind the feature flag."""
    if not GEOLOCATION_ENABLED:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Geolocation feature is disabled",
        )


router = APIRouter(
    dependencies=[
        Depends(_require_geolocation_enabled),
    ]
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_geolocation_store(request: Request) -> Any:
    """Retrieve the GeolocationStore from app state."""
    store = getattr(request.app.state, "geolocation_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Geolocation store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class NodePositionRequest(BaseModel):
    """Request body for setting a node position."""

    model_config = {"extra": "forbid"}

    x: float = Field(..., description="X coordinate in metres")
    y: float = Field(..., description="Y coordinate in metres")
    z: float = Field(0.0, description="Z coordinate in metres (height)")
    label: str = Field("", description="Human-readable label")
    floor: str = Field("", description="Floor identifier")


class RSSIMeasurementInput(BaseModel):
    """Single RSSI measurement from a node."""

    model_config = {"extra": "forbid"}

    node_id: str = Field(..., min_length=1, description="Receiver node ID")
    rssi_dbm: float = Field(..., description="RSSI in dBm")
    frequency_hz: float = Field(..., gt=0, description="Carrier frequency in Hz")
    timestamp: float = Field(..., description="Unix timestamp")


class EstimateRequest(BaseModel):
    """Request body for RSSI-based position estimation."""

    model_config = {"extra": "forbid"}

    measurements: list[RSSIMeasurementInput] = Field(
        ..., min_length=2, description="RSSI measurements from nodes"
    )
    path_loss_exponent: float = Field(
        2.5, ge=1.0, le=6.0, description="Path loss exponent"
    )
    reference_rssi_dbm: float = Field(-30.0, description="RSSI at reference distance")
    reference_distance_m: float = Field(
        1.0, gt=0, description="Reference distance in metres"
    )
    detection_id: str | None = Field(
        None, description="Optional associated detection ID"
    )
    emitter_id: str | None = Field(None, description="Optional emitter ID")


class PathLossConfigRequest(BaseModel):
    """Request body for updating path loss model configuration."""

    model_config = {"extra": "forbid"}

    path_loss_exponent: float = Field(2.5, ge=1.0, le=6.0)
    reference_rssi_dbm: float = Field(-30.0)
    reference_distance_m: float = Field(1.0, gt=0)


# ---------------------------------------------------------------------------
# In-memory path loss configuration (persisted per-request via app state)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG = {
    "path_loss_exponent": 2.5,
    "reference_rssi_dbm": -30.0,
    "reference_distance_m": 1.0,
}


def _get_config(request: Request) -> dict[str, Any]:
    """Get path loss config from app state, with defaults."""
    return getattr(request.app.state, "geolocation_config", dict(_DEFAULT_CONFIG))


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/nodes")
def list_node_positions(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List all node positions."""
    store = _get_geolocation_store(request)
    return store.get_all_positions()


@router.put("/nodes/{node_id}")
def set_node_position(
    node_id: str,
    body: NodePositionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Set or update a node's position (ADMIN only)."""
    store = _get_geolocation_store(request)
    return store.set_node_position(
        node_id=node_id,
        x=body.x,
        y=body.y,
        z=body.z,
        label=body.label,
        floor=body.floor,
    )


@router.delete("/nodes/{node_id}")
def delete_node_position(
    node_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Remove a node position (ADMIN only)."""
    store = _get_geolocation_store(request)
    deleted = store.delete_node_position(node_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node position {node_id!r} not found",
        )
    return {"ok": True, "deleted": node_id}


@router.post("/estimate")
def estimate_position(
    body: EstimateRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Estimate emitter position from RSSI measurements."""
    from sigrift.lib.dsp.multilateration import (
        NodePosition,
        RSSIMeasurement,
        estimate_position as do_estimate,
    )

    store = _get_geolocation_store(request)

    # Load node positions from DB
    all_positions = store.get_all_positions()
    node_positions: dict[str, NodePosition] = {}
    for pos in all_positions:
        node_positions[pos["node_id"]] = NodePosition(
            node_id=pos["node_id"],
            x=pos["x"],
            y=pos["y"],
            z=pos.get("z", 0.0),
        )

    # Convert input measurements
    measurements = [
        RSSIMeasurement(
            node_id=m.node_id,
            rssi_dbm=m.rssi_dbm,
            frequency_hz=m.frequency_hz,
            timestamp=m.timestamp,
        )
        for m in body.measurements
    ]

    try:
        result = do_estimate(
            measurements=measurements,
            node_positions=node_positions,
            path_loss_exponent=body.path_loss_exponent,
            reference_distance_m=body.reference_distance_m,
            reference_rssi_dbm=body.reference_rssi_dbm,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    # Store the result
    estimate_id = str(uuid.uuid4())
    store.store_estimate(
        estimate_id=estimate_id,
        detection_id=body.detection_id,
        x=result.x,
        y=result.y,
        z=result.z,
        confidence=result.confidence,
        error_radius_m=result.error_radius_m,
        method=result.method,
        n_nodes=result.n_nodes,
        path_loss_model=result.path_loss_model,
        measurements=result.measurements,
        emitter_id=body.emitter_id,
    )

    return {
        "estimate_id": estimate_id,
        "x": result.x,
        "y": result.y,
        "z": result.z,
        "confidence": result.confidence,
        "error_radius_m": result.error_radius_m,
        "method": result.method,
        "n_nodes": result.n_nodes,
        "path_loss_model": result.path_loss_model,
        "measurements": result.measurements,
    }


@router.post("/estimate/detection/{detection_id}")
def estimate_from_detection(
    detection_id: str,
    request: Request,
    path_loss_exponent: float = Query(2.5, ge=1.0, le=6.0),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Estimate position from a detection's RSSI across nodes.

    Placeholder -- requires detection RSSI data from multiple nodes.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Detection-based estimation not yet implemented",
    )


@router.get("/estimates")
def list_estimates(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List position estimates."""
    store = _get_geolocation_store(request)
    estimates = store.list_estimates(limit=limit, offset=offset)
    return {
        "count": len(estimates),
        "estimates": estimates,
    }


@router.get("/estimates/{estimate_id}")
def get_estimate(
    estimate_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get a single position estimate."""
    store = _get_geolocation_store(request)
    est = store.get_estimate(estimate_id)
    if est is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Estimate {estimate_id!r} not found",
        )
    return est


@router.get("/estimates/detection/{detection_id}")
def get_estimates_for_detection(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Get all estimates for a given detection."""
    store = _get_geolocation_store(request)
    return store.get_estimates_for_detection(detection_id)


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return geolocation statistics."""
    store = _get_geolocation_store(request)
    return store.get_stats()


@router.get("/config")
def get_config(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get current path loss model configuration."""
    return _get_config(request)


@router.put("/config")
def update_config(
    body: PathLossConfigRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Update path loss model configuration (ADMIN only)."""
    config = {
        "path_loss_exponent": body.path_loss_exponent,
        "reference_rssi_dbm": body.reference_rssi_dbm,
        "reference_distance_m": body.reference_distance_m,
    }
    request.app.state.geolocation_config = config
    return config
