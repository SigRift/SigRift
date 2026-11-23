"""Geolocation and mapping endpoints for The Bridge.

Provides geographic map data, detection heatmaps, coverage estimates,
and geospatial activity feeds for edge nodes with location data.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.models import (
    GeoActivityItem,
    GeoCoverageArea,
    GeoHeatmapPoint,
    GeoNodeSummary,
)
from sigrift.bridge.routers.nodes import stored_location
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow
from sigrift.lib.shiny.node_metrics import isoformat

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow

# Default coverage radius in km for RTL-SDR type receivers
_DEFAULT_RADIUS_KM = 1.0


def _nodes_with_location(
    persistence: Any,
) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Return (node_id, node_data, location) for nodes with a valid location.

    The location is read through ``stored_location``: a record saved with a
    latitude or longitude that is not a number in range has none, so one
    bad record cannot fail a map endpoint for every viewer.
    """
    nodes = persistence.get_nodes()
    located = []
    for nid, data in nodes.items():
        location = stored_location(data)
        if location is not None:
            located.append((nid, data, location))
    return located


@router.get("/map")
async def geo_map(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[GeoNodeSummary]:
    """All nodes with locations and recent detection summary per node."""
    persistence = request.app.state.persistence
    store = get_detection_store(request)

    now = _utcnow()
    one_hour_ago = (now - timedelta(hours=1)).isoformat()

    result = []
    for nid, data, location in _nodes_with_location(persistence):
        summary = await asyncio.to_thread(
            store.get_geo_node_summary,
            node_id=nid,
            cutoff_iso=one_hour_ago,
        )

        result.append(
            GeoNodeSummary(
                node_id=nid,
                **location,
                status=AppState.get_node_status(data).value,
                detection_count_1h=summary["detection_count"],
                top_signals=summary["top_signals"],
                last_heartbeat=isoformat(data.get("last_seen")),
                anomaly_count_1h=summary["anomaly_count"],
            )
        )

    return result


@router.get("/heatmap")
async def geo_heatmap(
    request: Request,
    hours: int = Query(default=24, ge=1, le=168),
    signal_class: str | None = Query(default=None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[GeoHeatmapPoint]:
    """Detection density heatmap data. Only includes nodes with location."""
    persistence = request.app.state.persistence
    store = get_detection_store(request)

    now = _utcnow()
    cutoff = (now - timedelta(hours=hours)).isoformat()

    located_nodes = {nid: loc for nid, _, loc in _nodes_with_location(persistence)}
    if not located_nodes:
        return []

    result = []
    for nid, location in located_nodes.items():
        weight = await asyncio.to_thread(
            store.get_geo_heatmap_weight,
            node_id=nid,
            cutoff_iso=cutoff,
            signal_class=signal_class,
        )

        if weight > 0:
            result.append(
                GeoHeatmapPoint(
                    latitude=location["latitude"],
                    longitude=location["longitude"],
                    weight=weight,
                )
            )

    return result


@router.get("/coverage")
async def geo_coverage(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[GeoCoverageArea]:
    """Estimated coverage area per node with location data."""
    persistence = request.app.state.persistence
    store = get_detection_store(request)

    result = []
    for nid, _, location in _nodes_with_location(persistence):
        stats = await asyncio.to_thread(
            store.get_geo_coverage_stats,
            node_id=nid,
        )

        result.append(
            GeoCoverageArea(
                node_id=nid,
                latitude=location["latitude"],
                longitude=location["longitude"],
                radius_km=_DEFAULT_RADIUS_KM,
                detection_classes=stats["detection_classes"],
                avg_snr_db=stats["avg_snr_db"],
            )
        )

    return result


@router.get("/activity")
async def geo_activity(
    request: Request,
    hours: int = Query(default=4, ge=1, le=48),
    min_anomaly_score: float | None = Query(default=None, ge=0.0, le=1.0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[GeoActivityItem]:
    """Geospatial activity feed — recent detections enriched with location."""
    persistence = request.app.state.persistence
    store = get_detection_store(request)

    now = _utcnow()
    cutoff = (now - timedelta(hours=hours)).isoformat()

    located_nodes = {nid: loc for nid, _, loc in _nodes_with_location(persistence)}
    if not located_nodes:
        return []

    rows = await asyncio.to_thread(
        store.get_geo_activity_feed,
        node_ids=list(located_nodes.keys()),
        cutoff_iso=cutoff,
        min_anomaly_score=min_anomaly_score,
    )

    result = []
    for r in rows:
        location = located_nodes.get(r["node_id"])
        if location is None:
            continue
        ts = r["timestamp"]
        if isinstance(ts, datetime):
            ts = ts.isoformat()
        result.append(
            GeoActivityItem(
                detection_id=r["detection_id"],
                node_id=r["node_id"],
                latitude=location["latitude"],
                longitude=location["longitude"],
                location_name=location["location_name"],
                signal_class=r["signal_class"],
                confidence=r["confidence"],
                freq_hz=r["freq_hz"],
                snr_db=r["snr_db"],
                power_dbm=r["power_dbm"],
                anomaly_score=r["anomaly_score"],
                timestamp=str(ts),
            )
        )

    return result
