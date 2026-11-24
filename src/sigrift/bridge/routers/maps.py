"""Map / floor plan REST API endpoints.

Provides endpoints for managing floor plans, zones, and map overlays
for both indoor floor plan views and outdoor Leaflet maps.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    UploadFile,
    File,
    Form,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.routers.nodes import stored_location
from sigrift.lib.shiny.node_metrics import stored_metric

logger = logging.getLogger(__name__)

router = APIRouter()

_FLOOR_PLAN_DIR = Path(__file__).resolve().parent.parent / "data" / "floor_plans"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_map_store(request: Request) -> Any:
    """Retrieve the MapStore from app state."""
    store = getattr(request.app.state, "map_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Map store not initialised",
        )
    return store


def _get_geolocation_store(request: Request) -> Any:
    """Retrieve the GeolocationStore from app state (optional)."""
    return getattr(request.app.state, "geolocation_store", None)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class FloorPlanUpdate(BaseModel):
    """Request body for updating floor plan metadata."""

    model_config = {"extra": "forbid"}

    name: str | None = None
    building: str | None = None
    floor: str | None = None
    description: str | None = None
    origin_x: float | None = None
    origin_y: float | None = None
    scale_x: float | None = None
    scale_y: float | None = None
    rotation_deg: float | None = None
    geo_lat: float | None = None
    geo_lon: float | None = None
    geo_bearing: float | None = None
    width_px: int | None = None
    height_px: int | None = None


class ZoneCreate(BaseModel):
    """Request body for creating a zone."""

    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=1, description="Zone name")
    polygon: list[list[float]] = Field(
        ..., min_length=3, description="Polygon as list of [x, y] points"
    )
    zone_type: str = Field("area", description="Zone type")
    color: str = Field("#3388ff", description="Zone display color")


# ---------------------------------------------------------------------------
# Floor plan endpoints
# ---------------------------------------------------------------------------


@router.get("/floor-plans")
def list_floor_plans(
    request: Request,
    building: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List all floor plans."""
    store = _get_map_store(request)
    return store.list_floor_plans(building=building)


@router.get("/floor-plans/{plan_id}")
def get_floor_plan(
    plan_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get floor plan metadata."""
    store = _get_map_store(request)
    plan = store.get_floor_plan(plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )
    return plan


_ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp"}
_EXTENSION_CONTENT_TYPES: dict[str, set[str]] = {
    ".png": {"image/png"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".gif": {"image/gif"},
    ".webp": {"image/webp"},
}


@router.post("/floor-plans", status_code=201)
async def create_floor_plan(
    request: Request,
    image: UploadFile = File(...),
    name: str = Form(...),
    building: str = Form(""),
    floor: str = Form(""),
    description: str = Form(""),
    origin_x: float = Form(0.0),
    origin_y: float = Form(0.0),
    scale_x: float = Form(1.0),
    scale_y: float = Form(1.0),
    rotation_deg: float = Form(0.0),
    geo_lat: float | None = Form(None),
    geo_lon: float | None = Form(None),
    geo_bearing: float | None = Form(None),
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Upload a floor plan image with metadata (ADMIN only)."""
    store = _get_map_store(request)

    # --- Validate file extension (block SVG / HTML / XML to prevent stored XSS) ---
    ext = (Path(image.filename or "plan.png").suffix or ".png").lower()
    if ext not in _ALLOWED_IMAGE_EXTENSIONS:
        allowed = ", ".join(sorted(_ALLOWED_IMAGE_EXTENSIONS))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported image format '{ext}'. Allowed: {allowed}",
        )

    # --- Validate Content-Type matches the extension ---
    content_type = (image.content_type or "").lower()
    expected_types = _EXTENSION_CONTENT_TYPES.get(ext, set())
    if content_type and expected_types and content_type not in expected_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Content-Type '{content_type}' does not match file extension '{ext}'"
            ),
        )

    plan_id = uuid.uuid4().hex[:12]

    # Ensure floor plan directory exists
    floor_plan_dir = getattr(request.app.state, "floor_plan_dir", _FLOOR_PLAN_DIR)
    floor_plan_dir = Path(floor_plan_dir)
    floor_plan_dir.mkdir(parents=True, exist_ok=True)

    # Save image file
    image_filename = f"{plan_id}{ext}"
    image_path = floor_plan_dir / image_filename

    content = await image.read()
    image_path.write_bytes(content)

    # Try to determine image dimensions
    width_px = None
    height_px = None
    try:
        # Minimal PNG dimension parsing
        if content[:4] == b"\x89PNG":
            import struct

            width_px = struct.unpack(">I", content[16:20])[0]
            height_px = struct.unpack(">I", content[20:24])[0]
    except (struct.error, IndexError):
        pass

    result = store.add_floor_plan(
        plan_id=plan_id,
        name=name,
        image_path=str(image_path),
        building=building,
        floor=floor,
        description=description,
        origin_x=origin_x,
        origin_y=origin_y,
        scale_x=scale_x,
        scale_y=scale_y,
        rotation_deg=rotation_deg,
        geo_lat=geo_lat,
        geo_lon=geo_lon,
        geo_bearing=geo_bearing,
        width_px=width_px,
        height_px=height_px,
    )
    return result


@router.put("/floor-plans/{plan_id}")
def update_floor_plan(
    plan_id: str,
    body: FloorPlanUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Update floor plan metadata/calibration (ADMIN only)."""
    store = _get_map_store(request)
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    result = store.update_floor_plan(plan_id, **updates)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )
    return result


@router.delete("/floor-plans/{plan_id}")
def delete_floor_plan(
    plan_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Delete a floor plan and its zones (ADMIN only)."""
    store = _get_map_store(request)

    # Try to delete the image file
    plan = store.get_floor_plan(plan_id)
    if plan and plan.get("image_path"):
        try:
            Path(plan["image_path"]).unlink(missing_ok=True)
        except OSError as exc:
            # The plan is still deleted below; say which file stays behind.
            logger.warning(
                "Floor plan %r: could not remove its image %s: %s",
                plan_id,
                plan["image_path"],
                exc,
            )

    deleted = store.delete_floor_plan(plan_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )
    return {"ok": True, "deleted": plan_id}


@router.get("/floor-plans/{plan_id}/image")
def serve_floor_plan_image(
    plan_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Serve floor plan image file."""
    from fastapi.responses import FileResponse

    store = _get_map_store(request)
    plan = store.get_floor_plan(plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )

    image_path = Path(plan["image_path"])
    if not image_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Floor plan image file not found",
        )

    # Determine media type (SVG intentionally excluded -- stored XSS risk)
    suffix = image_path.suffix.lower()
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }
    media_type = media_types.get(suffix, "application/octet-stream")

    return FileResponse(str(image_path), media_type=media_type)


# ---------------------------------------------------------------------------
# Zone endpoints
# ---------------------------------------------------------------------------


@router.post("/floor-plans/{plan_id}/zones", status_code=201)
def add_zone(
    plan_id: str,
    body: ZoneCreate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Add a zone to a floor plan (ANALYST only)."""
    store = _get_map_store(request)

    # Verify floor plan exists
    plan = store.get_floor_plan(plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )

    zone_id = uuid.uuid4().hex[:12]
    return store.add_zone(
        zone_id=zone_id,
        floor_plan_id=plan_id,
        name=body.name,
        polygon=body.polygon,
        zone_type=body.zone_type,
        color=body.color,
    )


@router.get("/floor-plans/{plan_id}/zones")
def get_zones(
    plan_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Get zones for a floor plan."""
    store = _get_map_store(request)
    return store.get_zones(plan_id)


@router.delete("/zones/{zone_id}")
def delete_zone(
    zone_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Delete a zone (ANALYST only)."""
    store = _get_map_store(request)
    deleted = store.delete_zone(zone_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Zone {zone_id!r} not found",
        )
    return {"ok": True, "deleted": zone_id}


# ---------------------------------------------------------------------------
# Combined view endpoints
# ---------------------------------------------------------------------------


@router.get("/view/{plan_id}")
def get_combined_view(
    plan_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get combined view: floor plan + node positions + emitter positions."""
    store = _get_map_store(request)

    plan = store.get_floor_plan(plan_id)
    if plan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Floor plan {plan_id!r} not found",
        )

    # Build image URL
    plan_data = dict(plan)
    plan_data["image_url"] = f"/api/maps/floor-plans/{plan_id}/image"

    # Get zones
    zones = store.get_zones(plan_id)

    # Get node positions from geolocation store (if available)
    nodes: list[dict[str, Any]] = []
    geo_store = _get_geolocation_store(request)
    if geo_store is not None:
        try:
            all_positions = geo_store.get_all_positions()
            for pos in all_positions:
                node_entry: dict[str, Any] = {
                    "node_id": pos["node_id"],
                    "x": pos["x"],
                    "y": pos["y"],
                    "status": "online",
                }
                # Convert to pixel coords
                px_result = store.local_to_pixel(plan_id, pos["x"], pos["y"])
                if px_result is not None:
                    node_entry["px"] = round(px_result[0], 1)
                    node_entry["py"] = round(px_result[1], 1)
                nodes.append(node_entry)
        except Exception as exc:
            logger.debug("Failed to fetch node positions: %s", exc)

    # Get emitter positions from geolocation store estimates (if available)
    emitters: list[dict[str, Any]] = []
    if geo_store is not None:
        try:
            estimates = geo_store.list_estimates(limit=50)
            for est in estimates:
                emitter_entry: dict[str, Any] = {
                    "emitter_id": est.get("emitter_id") or est.get("id", ""),
                    "x": est["x"],
                    "y": est["y"],
                    "confidence": est.get("confidence", 0.0),
                    "classification": "estimated",
                }
                px_result = store.local_to_pixel(plan_id, est["x"], est["y"])
                if px_result is not None:
                    emitter_entry["px"] = round(px_result[0], 1)
                    emitter_entry["py"] = round(px_result[1], 1)
                emitters.append(emitter_entry)
        except Exception as exc:
            logger.debug("Failed to fetch emitter positions: %s", exc)

    return {
        "floor_plan": plan_data,
        "nodes": nodes,
        "emitters": emitters,
        "zones": zones,
    }


@router.get("/overlay")
def get_overlay(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get outdoor map overlay data (all nodes + recent positions)."""
    store = _get_map_store(request)

    # Get nodes with geo coords from persistence
    nodes: list[dict[str, Any]] = []
    persistence = getattr(request.app.state, "persistence", None)
    if persistence is not None:
        try:
            nodes_data = persistence.get_nodes()
            for nid, data in nodes_data.items():
                # A record with a bad location (saved before heartbeat
                # metrics were checked) is left out, not every node.
                location = stored_location(data)
                if location is not None:
                    nodes.append(
                        {
                            "node_id": nid,
                            "lat": float(location["latitude"]),
                            "lon": float(location["longitude"]),
                            "status": stored_metric(data, "status") or "unknown",
                        }
                    )
        except Exception as exc:
            logger.debug("Failed to fetch node geo data: %s", exc)

    # Get emitters with geo positions
    emitters: list[dict[str, Any]] = []

    # Get geo-referenced floor plans
    floor_plans: list[dict[str, Any]] = []
    all_plans = store.list_floor_plans()
    for plan in all_plans:
        if plan.get("geo_lat") is not None and plan.get("geo_lon") is not None:
            floor_plans.append(
                {
                    "id": plan["id"],
                    "name": plan["name"],
                    "bounds": _compute_geo_bounds(plan),
                }
            )

    return {
        "nodes": nodes,
        "emitters": emitters,
        "floor_plans": floor_plans,
    }


def _compute_geo_bounds(plan: dict[str, Any]) -> list[list[float]]:
    """Compute geographic bounds for a geo-referenced floor plan."""
    lat = plan.get("geo_lat") or 0.0
    lon = plan.get("geo_lon") or 0.0
    width_px = plan.get("width_px") or 100
    height_px = plan.get("height_px") or 100
    scale_x = plan.get("scale_x") or 1.0
    scale_y = plan.get("scale_y") or 1.0

    # Convert pixel dimensions to meters
    width_m = width_px * scale_x
    height_m = height_px * scale_y

    # Approximate degree offsets (at given latitude)
    m_per_deg_lat = 111_320.0
    m_per_deg_lon = m_per_deg_lat * abs(
        __import__("math").cos(__import__("math").radians(lat))
    )
    if m_per_deg_lon < 1:
        m_per_deg_lon = m_per_deg_lat

    dlat = height_m / m_per_deg_lat
    dlon = width_m / m_per_deg_lon

    return [
        [lat, lon],
        [lat + dlat, lon + dlon],
    ]


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return map statistics."""
    store = _get_map_store(request)
    return store.get_stats()
