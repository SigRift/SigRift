"""Aircraft tracking API endpoints (ADS-B / UAT)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.utils import get_detection_store

logger = logging.getLogger(__name__)

router = APIRouter()

_get_detection_store = get_detection_store


@router.get("/")
async def list_active_aircraft(
    request: Request,
    max_age: int = Query(300, description="Max age in seconds"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List currently active aircraft."""
    store = _get_detection_store(request)
    aircraft_store = getattr(store, "_aircraft", None)
    if aircraft_store is None:
        return {"aircraft": [], "count": 0}

    aircraft = await asyncio.to_thread(
        aircraft_store.get_active_aircraft,
        max_age_seconds=max_age,
    )
    return {"aircraft": aircraft, "count": len(aircraft)}


@router.post("/")
async def ingest_aircraft(
    request: Request,
    body: dict,
    _key_id: str = Depends(require_role(Role.NODE)),
) -> dict[str, Any]:
    """Insert aircraft position(s) from edge decoder."""
    store = _get_detection_store(request)
    aircraft_store = getattr(store, "_aircraft", None)
    if aircraft_store is None:
        return {"inserted": 0}

    positions = body.get("positions", [body] if "icao_address" in body else [])
    count = 0
    for pos in positions:
        await asyncio.to_thread(aircraft_store.insert_position, pos)
        count += 1
    return {"inserted": count}


@router.get("/stats")
async def get_aircraft_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get aircraft tracking statistics."""
    store = _get_detection_store(request)
    aircraft_store = getattr(store, "_aircraft", None)
    if aircraft_store is None:
        return {"total_active": 0, "by_source": {}}

    return await asyncio.to_thread(aircraft_store.get_stats)


@router.get("/{icao}/trail")
async def get_aircraft_trail(
    request: Request,
    icao: str,
    hours: int = Query(1, description="Hours of trail history"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get position history for a single aircraft."""
    store = _get_detection_store(request)
    aircraft_store = getattr(store, "_aircraft", None)
    if aircraft_store is None:
        return {"trail": []}

    trail = await asyncio.to_thread(
        aircraft_store.get_aircraft_history,
        icao,
        hours=hours,
    )
    return {"icao_address": icao, "trail": trail, "count": len(trail)}
