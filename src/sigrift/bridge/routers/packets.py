"""Packet boundary detection API endpoints for The Bridge.

Provides endpoints for detecting packet boundaries in IQ captures
using energy, entropy, and timing analysis.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import asdict
from typing import Any

import numpy as np
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_packet_store(request: Request) -> Any:
    """Retrieve the PacketStore from app state."""
    store = getattr(request.app.state, "packet_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Packet store not initialised",
        )
    return store


def _get_iq_store(request: Request) -> Any:
    """Retrieve the IQStore from app state."""
    store = getattr(request.app.state, "iq_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class DetectRequest(BaseModel):
    """Request body for packet detection from a stored detection."""

    model_config = {"extra": "forbid"}

    detection_id: str = Field(..., description="Detection ID with IQ data")
    energy_threshold_db: float = Field(
        -20.0, description="Energy threshold in dB above noise"
    )
    min_packet_samples: int = Field(
        64, ge=1, description="Minimum packet length in samples"
    )
    min_gap_samples: int = Field(32, ge=1, description="Minimum gap between packets")
    entropy_window: int = Field(64, ge=2, description="Entropy window size")
    sample_rate: float = Field(1.0, gt=0, description="Sample rate in Hz")


class DetectRawRequest(BaseModel):
    """Request body for packet detection from raw IQ data."""

    model_config = {"extra": "forbid"}

    iq_base64: str = Field(..., description="Base64-encoded complex64 IQ data")
    energy_threshold_db: float = Field(
        -20.0, description="Energy threshold in dB above noise"
    )
    min_packet_samples: int = Field(
        64, ge=1, description="Minimum packet length in samples"
    )
    min_gap_samples: int = Field(32, ge=1, description="Minimum gap between packets")
    entropy_window: int = Field(64, ge=2, description="Entropy window size")
    sample_rate: float = Field(1.0, gt=0, description="Sample rate in Hz")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/detect")
def detect_packets(
    body: DetectRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Detect packets in a stored detection's IQ data."""
    from sigrift.lib.dsp.packet_detector import PacketDetector

    packet_store = _get_packet_store(request)
    iq_store = _get_iq_store(request)

    # Load IQ data
    iq_data = iq_store.load(body.detection_id)
    if iq_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ data for detection {body.detection_id!r}",
        )

    iq = iq_data if isinstance(iq_data, np.ndarray) else np.array(iq_data)

    detector = PacketDetector(
        energy_threshold_db=body.energy_threshold_db,
        min_packet_samples=body.min_packet_samples,
        min_gap_samples=body.min_gap_samples,
        entropy_window=body.entropy_window,
    )

    packets = detector.detect_packets(iq, sample_rate=body.sample_rate)
    timing = detector.analyze_timing(packets, sample_rate=body.sample_rate)

    # Store results
    pkt_dicts = []
    for i, p in enumerate(packets):
        d = asdict(p)
        d["packet_index"] = i
        pkt_dicts.append(d)

    packet_store.store_packets(body.detection_id, pkt_dicts)
    packet_store.store_timing(body.detection_id, asdict(timing))

    return {
        "detection_id": body.detection_id,
        "packets": pkt_dicts,
        "timing": asdict(timing),
    }


@router.post("/detect/raw")
def detect_packets_raw(
    body: DetectRawRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Detect packets in uploaded raw IQ data (base64-encoded complex64)."""
    from sigrift.lib.dsp.packet_detector import PacketDetector

    try:
        raw = base64.b64decode(body.iq_base64)
        iq = np.frombuffer(raw, dtype=np.complex64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IQ data: {exc}",
        )

    if len(iq) < body.min_packet_samples:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IQ data too short for packet detection",
        )

    detector = PacketDetector(
        energy_threshold_db=body.energy_threshold_db,
        min_packet_samples=body.min_packet_samples,
        min_gap_samples=body.min_gap_samples,
        entropy_window=body.entropy_window,
    )

    packets = detector.detect_packets(iq, sample_rate=body.sample_rate)
    timing = detector.analyze_timing(packets, sample_rate=body.sample_rate)

    pkt_dicts = []
    for i, p in enumerate(packets):
        d = asdict(p)
        d["packet_index"] = i
        pkt_dicts.append(d)

    return {
        "packets": pkt_dicts,
        "timing": asdict(timing),
    }


@router.get("/detection/{detection_id}")
def get_packets_for_detection(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Get detected packets for a detection."""
    store = _get_packet_store(request)
    return store.get_packets_for(detection_id)


@router.get("/detection/{detection_id}/timing")
def get_timing_for_detection(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get timing analysis for a detection."""
    store = _get_packet_store(request)
    timing = store.get_timing_for(detection_id)
    if timing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No timing analysis for detection {detection_id!r}",
        )
    return timing


@router.get("/")
def list_analyses(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List all packet timing analyses."""
    store = _get_packet_store(request)
    return store.list_analyses(limit=limit, offset=offset)


@router.delete("/{detection_id}")
def delete_analysis(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Delete packet analysis for a detection."""
    store = _get_packet_store(request)
    deleted = store.delete_analysis(detection_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No packet analysis for {detection_id!r}",
        )
    return {"ok": True, "deleted": detection_id}


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return packet detection statistics."""
    store = _get_packet_store(request)
    return store.get_stats()
