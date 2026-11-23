"""Preamble / sync-word detection API endpoints for The Bridge.

Provides pattern management, IQ scanning for known preambles,
and detection result queries.
"""

from __future__ import annotations

import logging
import uuid
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


def _get_preamble_store(request: Request) -> Any:
    store = getattr(request.app.state, "preamble_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Preamble store not initialised",
        )
    return store


def _get_iq_store(request: Request) -> Any:
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


class CreatePatternRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=1, description="Pattern name")
    bits: list[int] = Field(..., min_length=1, description="Bit sequence (0/1 values)")
    protocol: str = Field(..., min_length=1, description="Protocol name")
    modulation: str = Field("bpsk", description="Modulation type")
    description: str = Field("", description="Human-readable description")
    chip_rate: float | None = Field(None, description="Chip rate in Hz")


class DetectRequest(BaseModel):
    model_config = {"extra": "forbid"}

    detection_id: str = Field(..., min_length=1, description="Detection ID to scan")
    threshold: float = Field(0.7, ge=0.0, le=1.0, description="Correlation threshold")


class DetectRawRequest(BaseModel):
    model_config = {"extra": "forbid"}

    iq_real: list[float] = Field(..., min_length=1, description="I (real) samples")
    iq_imag: list[float] = Field(..., min_length=1, description="Q (imag) samples")
    sample_rate: float = Field(1.0, gt=0, description="Sample rate in Hz")
    threshold: float = Field(0.7, ge=0.0, le=1.0, description="Correlation threshold")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/patterns")
def list_patterns(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List all sync patterns (built-in + custom)."""
    from sigrift.lib.dsp.preamble_detector import _builtin_patterns

    store = _get_preamble_store(request)
    custom = store.list_patterns()

    builtin = []
    for p in _builtin_patterns():
        builtin.append(
            {
                "name": p.name,
                "bits": p.bits,
                "protocol": p.protocol,
                "modulation": p.modulation,
                "description": p.description,
                "chip_rate": p.chip_rate,
                "source": "builtin",
            }
        )

    for c in custom:
        c["source"] = "custom"

    return {"builtin": builtin, "custom": custom}


@router.post("/patterns", status_code=status.HTTP_201_CREATED)
def add_pattern(
    body: CreatePatternRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Add a custom sync pattern."""
    store = _get_preamble_store(request)
    pattern_id = str(uuid.uuid4())
    store.add_pattern(
        pattern_id=pattern_id,
        name=body.name,
        bits=body.bits,
        protocol=body.protocol,
        modulation=body.modulation,
        description=body.description,
        chip_rate=body.chip_rate,
    )
    return store.get_pattern(pattern_id)


@router.delete("/patterns/{pattern_id}")
def delete_pattern(
    pattern_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Delete a custom pattern."""
    store = _get_preamble_store(request)
    deleted = store.delete_pattern(pattern_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pattern {pattern_id!r} not found",
        )
    return {"ok": True, "deleted": pattern_id}


@router.post("/detect")
def detect_preambles(
    body: DetectRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Scan a detection's IQ capture for preambles."""
    from sigrift.lib.dsp.preamble_detector import PreambleDetector, SyncPattern

    store = _get_preamble_store(request)
    iq_store = _get_iq_store(request)

    # Load IQ data
    iq_data = iq_store.load(body.detection_id)
    if iq_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ data for detection {body.detection_id!r}",
        )

    iq = iq_data["iq"]
    sample_rate = iq_data.get("sample_rate", 1.0)

    # Build detector with built-in + custom patterns
    detector = PreambleDetector()
    for custom in store.list_patterns():
        detector.add_pattern(
            SyncPattern(
                name=custom["name"],
                bits=custom["bits"],
                protocol=custom["protocol"],
                modulation=custom["modulation"],
                description=custom.get("description", ""),
                chip_rate=custom.get("chip_rate"),
            )
        )

    matches = detector.detect(iq, sample_rate=sample_rate, threshold=body.threshold)

    # Store results
    results = []
    for m in matches:
        det_id = str(uuid.uuid4())
        store.store_detection(
            det_id=det_id,
            detection_id=body.detection_id,
            pattern_name=m.pattern_name,
            protocol=m.protocol,
            sample_offset=m.sample_offset,
            correlation_peak=m.correlation_peak,
            confidence=m.confidence,
            estimated_symbol_rate=m.estimated_symbol_rate,
        )
        results.append(
            {
                "id": det_id,
                "pattern_name": m.pattern_name,
                "protocol": m.protocol,
                "sample_offset": m.sample_offset,
                "correlation_peak": m.correlation_peak,
                "confidence": m.confidence,
                "estimated_symbol_rate": m.estimated_symbol_rate,
                "bit_sequence": m.bit_sequence,
            }
        )

    return {
        "detection_id": body.detection_id,
        "matches": results,
        "count": len(results),
    }


@router.post("/detect/raw")
def detect_preambles_raw(
    body: DetectRawRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Scan uploaded IQ data for preambles."""
    from sigrift.lib.dsp.preamble_detector import PreambleDetector, SyncPattern

    store = _get_preamble_store(request)

    iq = np.array(body.iq_real, dtype=np.float64) + 1j * np.array(
        body.iq_imag, dtype=np.float64
    )

    detector = PreambleDetector()
    for custom in store.list_patterns():
        detector.add_pattern(
            SyncPattern(
                name=custom["name"],
                bits=custom["bits"],
                protocol=custom["protocol"],
                modulation=custom["modulation"],
                description=custom.get("description", ""),
                chip_rate=custom.get("chip_rate"),
            )
        )

    matches = detector.detect(
        iq, sample_rate=body.sample_rate, threshold=body.threshold
    )

    results = []
    for m in matches:
        results.append(
            {
                "pattern_name": m.pattern_name,
                "protocol": m.protocol,
                "sample_offset": m.sample_offset,
                "correlation_peak": m.correlation_peak,
                "confidence": m.confidence,
                "estimated_symbol_rate": m.estimated_symbol_rate,
                "bit_sequence": m.bit_sequence,
            }
        )

    return {
        "matches": results,
        "count": len(results),
    }


@router.get("/detections")
def list_detections(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List preamble detections."""
    store = _get_preamble_store(request)
    return store.list_detections(limit=limit, offset=offset)


@router.get("/detections/{detection_id}")
def get_detections_for(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Get preamble detections for a specific signal detection."""
    store = _get_preamble_store(request)
    return store.get_detections_for(detection_id)


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return preamble detection statistics."""
    store = _get_preamble_store(request)
    return store.get_stats()
