"""Emitter position tracking API endpoints.

Provides endpoints for managing Kalman-filtered emitter tracks,
including position updates, predictions, pruning, and configuration.

All endpoints are gated behind the ``BRIDGE_GEOLOCATION_ENABLED``
feature flag (same as TDOA endpoints).
"""

from __future__ import annotations

import asyncio
import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from starlette import status

from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature flag: re-use the same geolocation gate as TDOA
# ---------------------------------------------------------------------------

GEOLOCATION_ENABLED = os.environ.get("BRIDGE_GEOLOCATION_ENABLED", "false").lower() in (
    "true",
    "1",
    "yes",
)


def _require_geolocation_enabled():
    """Dependency that gates all tracking endpoints behind the feature flag."""
    if not GEOLOCATION_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Geolocation feature is disabled. Set BRIDGE_GEOLOCATION_ENABLED=true to enable.",
        )


router = APIRouter(
    dependencies=[
        Depends(_require_geolocation_enabled),
    ]
)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class TrackUpdateRequest(BaseModel):
    """Submit a position update for an emitter."""

    emitter_id: str = Field(..., description="Emitter identifier")
    x: float = Field(..., description="X position in metres")
    y: float = Field(..., description="Y position in metres")
    timestamp: float = Field(..., description="Unix timestamp")
    measurement_noise: float | None = Field(
        None, description="Optional measurement noise (m)"
    )
    estimate_id: str | None = Field(None, description="Source position estimate ID")


class TrackPointResponse(BaseModel):
    """Filtered track point returned from update/predict."""

    x: float
    y: float
    vx: float
    vy: float
    timestamp: float
    confidence: float
    source_estimate_id: str | None = None


class TrackSummaryResponse(BaseModel):
    """Summary of an emitter track."""

    track_id: str
    emitter_id: str | None
    status: str
    first_seen: float
    last_seen: float
    total_distance_m: float
    mean_velocity_mps: float
    is_stationary: bool
    classification: str | None
    point_count: int


class TrackDetailResponse(BaseModel):
    """Full track with all points."""

    track_id: str
    emitter_id: str | None
    status: str
    first_seen: float
    last_seen: float
    total_distance_m: float
    mean_velocity_mps: float
    is_stationary: bool
    classification: str | None
    points: list[TrackPointResponse]


class PruneResponse(BaseModel):
    """Result of pruning lost tracks."""

    pruned_count: int
    pruned_ids: list[str]


class TrackerConfigResponse(BaseModel):
    """Current tracker configuration."""

    process_noise: float
    measurement_noise: float
    lost_timeout_s: float
    stationary_threshold_mps: float
    min_points_for_track: int


class TrackerConfigUpdate(BaseModel):
    """Update tracker configuration."""

    process_noise: float | None = None
    measurement_noise: float | None = None
    lost_timeout_s: float | None = None
    stationary_threshold_mps: float | None = None
    min_points_for_track: int | None = None


class TrackStatsResponse(BaseModel):
    """Track statistics."""

    total_tracks: int
    active_tracks: int
    lost_tracks: int
    total_points: int


# ---------------------------------------------------------------------------
# Helper to get tracker + store from app state
# ---------------------------------------------------------------------------


def _get_tracker(request: Request):
    """Get EmitterTracker from app state."""
    tracker = getattr(request.app.state, "emitter_tracker", None)
    if tracker is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Emitter tracker not initialised",
        )
    return tracker


def _get_track_store(request: Request):
    """Get TrackStore from app state."""
    store = getattr(request.app.state, "track_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Track store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/update", response_model=TrackPointResponse)
async def update_track(
    request: Request,
    body: TrackUpdateRequest,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> TrackPointResponse:
    """Submit a position update for an emitter.

    Creates a new track if the emitter has not been seen before.
    Returns the Kalman-filtered (smoothed) position.
    """
    tracker = _get_tracker(request)
    store = _get_track_store(request)

    point = await asyncio.to_thread(
        tracker.update,
        emitter_id=body.emitter_id,
        x=body.x,
        y=body.y,
        timestamp=body.timestamp,
        measurement_noise=body.measurement_noise,
        estimate_id=body.estimate_id,
    )

    # Persist to storage
    track = tracker.get_track(body.emitter_id)
    if track is not None:
        # Ensure track record exists in DB
        existing = await asyncio.to_thread(store.get_track, track.track_id)
        if existing is None:
            await asyncio.to_thread(
                store.create_track,
                track_id=track.track_id,
                emitter_id=body.emitter_id,
                first_seen=track.first_seen,
                last_seen=track.last_seen,
                status=track.status,
                classification=track.classification,
            )

        # Add point
        await asyncio.to_thread(
            store.add_point,
            track_id=track.track_id,
            x=point.x,
            y=point.y,
            timestamp=point.timestamp,
            vx=point.vx,
            vy=point.vy,
            confidence=point.confidence,
            source_estimate_id=point.source_estimate_id,
        )

        # Update summary
        await asyncio.to_thread(
            store.update_track_summary,
            track_id=track.track_id,
            last_seen=track.last_seen,
            total_distance_m=track.total_distance_m,
            mean_velocity_mps=track.mean_velocity_mps,
            is_stationary=track.is_stationary,
            classification=track.classification,
        )

    return TrackPointResponse(
        x=point.x,
        y=point.y,
        vx=point.vx,
        vy=point.vy,
        timestamp=point.timestamp,
        confidence=point.confidence,
        source_estimate_id=point.source_estimate_id,
    )


@router.get("/tracks", response_model=list[TrackSummaryResponse])
async def list_tracks(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[TrackSummaryResponse]:
    """List all tracks."""
    store = _get_track_store(request)
    tracks = await asyncio.to_thread(store.list_tracks, status=None, limit=limit)
    result = []
    for t in tracks:
        points = await asyncio.to_thread(store.get_track_points, t["track_id"])
        result.append(
            TrackSummaryResponse(
                track_id=t["track_id"],
                emitter_id=t.get("emitter_id"),
                status=t.get("status", "active"),
                first_seen=t.get("first_seen", 0.0),
                last_seen=t.get("last_seen", 0.0),
                total_distance_m=t.get("total_distance_m", 0.0),
                mean_velocity_mps=t.get("mean_velocity_mps", 0.0),
                is_stationary=bool(t.get("is_stationary", True)),
                classification=t.get("classification"),
                point_count=len(points),
            )
        )
    return result


@router.get("/tracks/active", response_model=list[TrackSummaryResponse])
async def list_active_tracks(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[TrackSummaryResponse]:
    """List active tracks only."""
    store = _get_track_store(request)
    tracks = await asyncio.to_thread(store.get_active_tracks, limit=limit)
    result = []
    for t in tracks:
        points = await asyncio.to_thread(store.get_track_points, t["track_id"])
        result.append(
            TrackSummaryResponse(
                track_id=t["track_id"],
                emitter_id=t.get("emitter_id"),
                status=t.get("status", "active"),
                first_seen=t.get("first_seen", 0.0),
                last_seen=t.get("last_seen", 0.0),
                total_distance_m=t.get("total_distance_m", 0.0),
                mean_velocity_mps=t.get("mean_velocity_mps", 0.0),
                is_stationary=bool(t.get("is_stationary", True)),
                classification=t.get("classification"),
                point_count=len(points),
            )
        )
    return result


@router.get("/tracks/{track_id}", response_model=TrackDetailResponse)
async def get_track(
    request: Request,
    track_id: str,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> TrackDetailResponse:
    """Get a track with all points."""
    store = _get_track_store(request)
    track = await asyncio.to_thread(store.get_track, track_id)
    if track is None:
        raise HTTPException(status_code=404, detail="Track not found")

    points_raw = await asyncio.to_thread(store.get_track_points, track_id)
    points = [
        TrackPointResponse(
            x=p["x"],
            y=p["y"],
            vx=p.get("vx", 0.0),
            vy=p.get("vy", 0.0),
            timestamp=p["timestamp"],
            confidence=p.get("confidence", 0.0),
            source_estimate_id=p.get("source_estimate_id"),
        )
        for p in points_raw
    ]

    return TrackDetailResponse(
        track_id=track["track_id"],
        emitter_id=track.get("emitter_id"),
        status=track.get("status", "active"),
        first_seen=track.get("first_seen", 0.0),
        last_seen=track.get("last_seen", 0.0),
        total_distance_m=track.get("total_distance_m", 0.0),
        mean_velocity_mps=track.get("mean_velocity_mps", 0.0),
        is_stationary=bool(track.get("is_stationary", True)),
        classification=track.get("classification"),
        points=points,
    )


@router.get("/tracks/{track_id}/predict", response_model=TrackPointResponse)
async def predict_track(
    request: Request,
    track_id: str,
    timestamp: float | None = Query(
        default=None, description="Prediction timestamp (unix)"
    ),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> TrackPointResponse:
    """Predict emitter position at given timestamp."""
    import time as _time

    tracker = _get_tracker(request)
    store = _get_track_store(request)

    # Find which emitter this track belongs to
    track_data = await asyncio.to_thread(store.get_track, track_id)
    if track_data is None:
        raise HTTPException(status_code=404, detail="Track not found")

    emitter_id = track_data.get("emitter_id")
    if emitter_id is None:
        raise HTTPException(status_code=404, detail="Track has no emitter_id")

    ts = timestamp if timestamp is not None else _time.time()
    point = tracker.predict(emitter_id, ts)
    if point is None:
        raise HTTPException(status_code=404, detail="No track data for prediction")

    return TrackPointResponse(
        x=point.x,
        y=point.y,
        vx=point.vx,
        vy=point.vy,
        timestamp=point.timestamp,
        confidence=point.confidence,
        source_estimate_id=point.source_estimate_id,
    )


@router.delete("/tracks/{track_id}")
async def delete_track(
    request: Request,
    track_id: str,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, str]:
    """Delete a track and all its points."""
    store = _get_track_store(request)
    deleted = await asyncio.to_thread(store.delete_track, track_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Track not found")
    return {"status": "deleted", "track_id": track_id}


@router.post("/prune", response_model=PruneResponse)
async def prune_tracks(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> PruneResponse:
    """Prune lost tracks (mark as lost if not updated within timeout)."""
    import time as _time

    tracker = _get_tracker(request)
    store = _get_track_store(request)

    pruned_ids = tracker.prune_lost_tracks(_time.time())

    # Update status in storage
    for eid in pruned_ids:
        track = tracker.get_track(eid)
        if track is not None:
            await asyncio.to_thread(store.update_track_status, track.track_id, "lost")

    return PruneResponse(
        pruned_count=len(pruned_ids),
        pruned_ids=pruned_ids,
    )


@router.get("/stats", response_model=TrackStatsResponse)
async def track_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> TrackStatsResponse:
    """Get track statistics."""
    store = _get_track_store(request)
    stats = await asyncio.to_thread(store.get_stats)
    return TrackStatsResponse(**stats)


@router.get("/config", response_model=TrackerConfigResponse)
async def get_config(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> TrackerConfigResponse:
    """Get current tracker configuration."""
    tracker = _get_tracker(request)
    return TrackerConfigResponse(
        process_noise=tracker.process_noise,
        measurement_noise=tracker.measurement_noise,
        lost_timeout_s=tracker.lost_timeout_s,
        stationary_threshold_mps=tracker.stationary_threshold_mps,
        min_points_for_track=tracker.min_points_for_track,
    )


@router.put("/config", response_model=TrackerConfigResponse)
async def update_config(
    request: Request,
    body: TrackerConfigUpdate,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> TrackerConfigResponse:
    """Update tracker configuration."""
    tracker = _get_tracker(request)
    if body.process_noise is not None:
        tracker.process_noise = body.process_noise
    if body.measurement_noise is not None:
        tracker.measurement_noise = body.measurement_noise
    if body.lost_timeout_s is not None:
        tracker.lost_timeout_s = body.lost_timeout_s
    if body.stationary_threshold_mps is not None:
        tracker.stationary_threshold_mps = body.stationary_threshold_mps
    if body.min_points_for_track is not None:
        tracker.min_points_for_track = body.min_points_for_track
    return TrackerConfigResponse(
        process_noise=tracker.process_noise,
        measurement_noise=tracker.measurement_noise,
        lost_timeout_s=tracker.lost_timeout_s,
        stationary_threshold_mps=tracker.stationary_threshold_mps,
        min_points_for_track=tracker.min_points_for_track,
    )
