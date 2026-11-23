"""Emitter association API endpoints for The Bridge.

Provides endpoints to list discovered emitters, view emitter detail
with associated detections, and trigger re-computation of emitter
associations from recent detection data.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from sigrift.bridge.anomaly.emitter import EmitterAssociator
from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.utils import get_detection_store

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# GET /emitters -- list discovered emitters
# ---------------------------------------------------------------------------


@router.get("/emitters")
async def list_emitters(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    signal_class: str | None = Query(None),
    min_detections: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List discovered emitters.

    Parameters
    ----------
    limit : int
        Maximum results (default 100).
    offset : int
        Pagination offset.
    signal_class : str or None
        Optional filter by signal class.
    min_detections : int
        Minimum detection count filter.
    """
    store = get_detection_store(request)
    emitters = await asyncio.to_thread(
        store.list_emitters,
        limit=limit,
        offset=offset,
        signal_class=signal_class,
        min_detections=min_detections,
    )
    total = await asyncio.to_thread(store.count_emitters)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(emitters),
        "emitters": emitters,
    }


# ---------------------------------------------------------------------------
# GET /emitters/{emitter_id} -- emitter detail with associated detections
# ---------------------------------------------------------------------------


@router.get("/emitters/{emitter_id}")
async def get_emitter_detail(
    request: Request,
    emitter_id: str,
    include_detections: bool = Query(False),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get emitter detail, optionally including associated detections.

    Parameters
    ----------
    emitter_id : str
        Emitter identifier.
    include_detections : bool
        If True, fetch the associated detection records (up to 200).
    """
    store = get_detection_store(request)
    emitter = await asyncio.to_thread(store.get_emitter, emitter_id)

    if emitter is None:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Emitter {emitter_id!r} not found",
        )

    result: dict[str, Any] = {"emitter": emitter}

    if include_detections:
        det_ids = emitter.get("detection_ids", [])[:200]
        detections = []
        for did in det_ids:
            det = await asyncio.to_thread(store.get_detection_by_id, did)
            if det:
                detections.append(det)
        result["detections"] = detections
        result["detections_returned"] = len(detections)

    return result


# ---------------------------------------------------------------------------
# POST /emitters/recompute -- re-run association on recent data
# ---------------------------------------------------------------------------


@router.post("/emitters/recompute")
async def recompute_emitters(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    min_detections: int = Query(3, ge=1, le=100),
    freq_tolerance_hz: float = Query(50_000, ge=1_000, le=10_000_000),
    power_tolerance_db: float = Query(10.0, ge=1.0, le=30.0),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Re-run emitter association on recent detection data.

    Clears existing emitter records and rebuilds from scratch
    using detections from the specified lookback window.

    Parameters
    ----------
    hours : int
        Lookback window in hours (default 24, max 168 = 7 days).
    min_detections : int
        Minimum detections to form an emitter (default 3).
    freq_tolerance_hz : float
        Frequency tolerance for clustering (default 50 kHz).
    power_tolerance_db : float
        Power tolerance for clustering (default 10 dB).
    """
    store = get_detection_store(request)

    # Fetch recent detections
    minutes = hours * 60
    detections = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=50000,
    )

    # Run associator
    associator = EmitterAssociator(
        freq_tolerance_hz=freq_tolerance_hz,
        power_tolerance_db=power_tolerance_db,
        min_detections=min_detections,
    )
    emitters = associator.associate(detections)

    # Clear old emitters and store new ones
    deleted = await asyncio.to_thread(store.delete_all_emitters)
    emitter_dicts = [e.model_dump() for e in emitters]
    upserted = await asyncio.to_thread(store.upsert_emitters, emitter_dicts)

    logger.info(
        "Emitter recompute: %d detections -> %d emitters (deleted %d old)",
        len(detections),
        len(emitters),
        deleted,
    )

    return {
        "detections_analysed": len(detections),
        "hours": hours,
        "emitters_discovered": len(emitters),
        "emitters_stored": upserted,
        "previous_deleted": deleted,
        "parameters": {
            "freq_tolerance_hz": freq_tolerance_hz,
            "power_tolerance_db": power_tolerance_db,
            "min_detections": min_detections,
        },
    }
