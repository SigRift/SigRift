"""Detection analytics endpoints for The Bridge.

Provides time-series timeline, frequency heatmap, signal class distribution,
cross-node comparison, and hourly aggregation trigger endpoints.
"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    Query,
    Request,
)

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.models import DetectionQuery, DetectionStats
from sigrift.bridge.utils import get_detection_store, utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow
_get_detection_store = get_detection_store

# Threshold reused from the core detections module
_ANOMALY_ALERT_THRESHOLD = 0.7


# ---------------------------------------------------------------------------
# GET /stats -- aggregated statistics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_stats(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> DetectionStats:
    """Return aggregated detection statistics."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(store.get_stats, hours=hours, node_id=node_id)


# ---------------------------------------------------------------------------
# GET /timeline -- time-series data
# ---------------------------------------------------------------------------


@router.get("/timeline")
async def get_timeline(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    resolution: int = Query(300, ge=60, le=3600),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return time-bucketed detection counts for time-series charts."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(
        store.get_timeline,
        range_hours=hours,
        resolution_seconds=resolution,
        node_id=node_id,
    )


# ---------------------------------------------------------------------------
# GET /heatmap -- frequency x time heatmap
# ---------------------------------------------------------------------------


@router.get("/heatmap")
async def get_heatmap(
    request: Request,
    date: str = Query("", description="ISO date YYYY-MM-DD, defaults to today"),
    resolution: int = Query(15, ge=1, le=60),
    hours: int | None = Query(
        None, ge=1, le=168, description="Lookback window; overrides date"
    ),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return frequency x time heatmap data."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(
        store.get_heatmap, date=date, resolution_minutes=resolution, hours=hours
    )


# ---------------------------------------------------------------------------
# GET /distribution -- signal class distribution
# ---------------------------------------------------------------------------


@router.get("/distribution")
async def get_distribution(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return signal class distribution data."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(
        store.get_distribution,
        range_hours=hours,
        min_confidence=min_confidence,
    )


# ---------------------------------------------------------------------------
# POST /aggregate -- trigger hourly aggregation
# ---------------------------------------------------------------------------


@router.post("/aggregate")
async def trigger_aggregation(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Trigger hourly aggregation of raw detections."""
    store = _get_detection_store(request)
    count = await asyncio.to_thread(store.aggregate_hourly)
    iq_store = getattr(request.app.state, "iq_store", None)
    iq_cleaned = 0
    if iq_store is not None:
        iq_cleaned = await asyncio.to_thread(iq_store.cleanup, max_age_days=7)
    wifi_cleaned = await asyncio.to_thread(store.cleanup_wifi_anomalies, max_age_days=7)
    return {
        "aggregated_rows": count,
        "iq_files_cleaned": iq_cleaned,
        "wifi_anomalies_cleaned": wifi_cleaned,
    }


# ---------------------------------------------------------------------------
# GET /nodes/compare -- cross-node detection profile comparison
# ---------------------------------------------------------------------------


@router.get("/nodes/compare")
async def compare_nodes(
    request: Request,
    hours: int = Query(24, ge=1, le=168),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Compare detection profiles across all active nodes.

    Returns per-node detection statistics including class/family
    distributions, average confidence, anomaly counts, and a
    cross-correlation matrix using Jaccard similarity on signal
    class sets.
    """
    store = _get_detection_store(request)
    persistence = request.app.state.persistence

    nodes = persistence.get_nodes()
    node_ids = list(nodes.keys())

    if not node_ids:
        return {"nodes": [], "cross_correlation": {}}

    now = _utcnow()
    start = now - timedelta(hours=hours)

    profiles: dict[str, dict[str, Any]] = {}
    node_classes: dict[str, set[str]] = {}

    for nid in node_ids:
        q = DetectionQuery(
            start=start,
            end=now,
            node_id=nid,
            limit=10000,
        )
        rows = await asyncio.to_thread(store.query, q)

        if not rows:
            profiles[nid] = {
                "node_id": nid,
                "total_detections": 0,
                "unique_classes": 0,
                "class_distribution": {},
                "family_distribution": {},
                "avg_confidence": 0.0,
                "anomaly_count": 0,
                "top_class": None,
            }
            node_classes[nid] = set()
            continue

        class_counts: dict[str, int] = defaultdict(int)
        family_counts: dict[str, int] = defaultdict(int)
        total_conf = 0.0
        anomaly_count = 0

        for r in rows:
            sc = r.get("signal_class", "unknown")
            class_counts[sc] += 1
            fam = r.get("family", "")
            if fam:
                family_counts[fam] += 1
            total_conf += r.get("confidence", 0.0)
            if r.get("anomaly_score", 0.0) >= _ANOMALY_ALERT_THRESHOLD:
                anomaly_count += 1

        top_class = max(class_counts, key=class_counts.get) if class_counts else None

        profiles[nid] = {
            "node_id": nid,
            "total_detections": len(rows),
            "unique_classes": len(class_counts),
            "class_distribution": dict(class_counts),
            "family_distribution": dict(family_counts),
            "avg_confidence": round(total_conf / len(rows), 4) if rows else 0.0,
            "anomaly_count": anomaly_count,
            "top_class": top_class,
        }
        node_classes[nid] = set(class_counts.keys())

    # Jaccard similarity cross-correlation
    cross_correlation: dict[str, dict[str, float]] = {}
    for a in node_ids:
        cross_correlation[a] = {}
        for b in node_ids:
            set_a = node_classes.get(a, set())
            set_b = node_classes.get(b, set())
            union = set_a | set_b
            if not union:
                cross_correlation[a][b] = 0.0
            else:
                cross_correlation[a][b] = round(
                    len(set_a & set_b) / len(union),
                    4,
                )

    return {
        "hours": hours,
        "nodes": list(profiles.values()),
        "cross_correlation": cross_correlation,
    }


# ---------------------------------------------------------------------------
# GET /threat-ribbon -- cross-protocol threat ribbon (UX-R1)
# ---------------------------------------------------------------------------


@router.get("/threat-ribbon")
async def threat_ribbon(
    request: Request,
    hours: int = Query(default=1, ge=1, le=168),
    threshold: float = Query(default=0.5, ge=0.0, le=1.0),
    limit: int = Query(default=50, ge=1, le=200),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return recent high-anomaly events across all protocols for the threat ribbon.

    Combines RF detections, WiFi, Bluetooth, and Zigbee events
    that exceed the anomaly threshold.
    """
    store = _get_detection_store(request)

    events = await asyncio.to_thread(
        store.get_threat_ribbon,
        hours=hours,
        threshold=threshold,
        limit=limit,
    )

    # Group by protocol for frontend ribbon rendering
    by_protocol: dict[str, int] = defaultdict(int)
    for evt in events:
        by_protocol[evt.get("signal_class", "unknown")] += 1

    return {
        "hours": hours,
        "threshold": threshold,
        "total": len(events),
        "events": events,
        "by_protocol": dict(by_protocol),
    }
