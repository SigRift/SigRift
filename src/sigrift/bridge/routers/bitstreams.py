"""Bitstream extraction API endpoints for The Bridge.

Provides endpoints for extracting bitstreams from PSK-modulated
IQ captures, managing extraction results, and querying statistics.
"""

from __future__ import annotations

import base64
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


def _get_bitstream_store(request: Request) -> Any:
    """Retrieve the BitstreamStore from app state."""
    store = getattr(request.app.state, "bitstream_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bitstream store not initialised",
        )
    return store


def _get_iq_store(request: Request) -> Any:
    """Retrieve the IQStore from app state."""
    iq_store = getattr(request.app.state, "iq_store", None)
    if iq_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ store not initialised",
        )
    return iq_store


def _get_detection_store(request: Request) -> Any:
    """Retrieve the DetectionStore from app state."""
    store = getattr(request.app.state, "detection_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not initialised",
        )
    return store


def _bits_to_hex(bits: list[int]) -> str:
    """Convert a bit list to a hex string."""
    if not bits:
        return ""
    # Pad to multiple of 8
    padded = bits + [0] * ((8 - len(bits) % 8) % 8)
    hex_str = ""
    for i in range(0, len(padded), 8):
        byte = 0
        for b in range(8):
            byte = (byte << 1) | padded[i + b]
        hex_str += f"{byte:02x}"
    return hex_str


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ExtractRequest(BaseModel):
    """Request body for extracting bitstream from a detection's IQ."""

    model_config = {"extra": "forbid"}

    detection_id: str = Field(..., description="Detection ID with stored IQ")
    modulation: str | None = Field(
        None,
        description="Override modulation type (bpsk/qpsk/8psk). Auto-detected from signal_class if omitted.",
    )
    sample_rate: float = Field(2.048e6, gt=0, description="Sample rate in Hz")
    symbol_rate: float | None = Field(
        None, gt=0, description="Symbol rate in Hz (auto-detected if omitted)"
    )


class ExtractRawRequest(BaseModel):
    """Request body for extracting bitstream from uploaded raw IQ data."""

    model_config = {"extra": "forbid"}

    iq_base64: str = Field(
        ..., description="Base64-encoded float32 interleaved IQ data"
    )
    modulation: str = Field(..., description="Modulation type: bpsk, qpsk, or 8psk")
    sample_rate: float = Field(1.0, gt=0, description="Sample rate in Hz")
    symbol_rate: float | None = Field(
        None, gt=0, description="Symbol rate in Hz (auto-detected if omitted)"
    )


# ---------------------------------------------------------------------------
# Modulation type inference
# ---------------------------------------------------------------------------

_PSK_MAP = {
    "bpsk": "bpsk",
    "qpsk": "qpsk",
    "8psk": "8psk",
}


def _infer_modulation(signal_class: str) -> str | None:
    """Infer PSK modulation type from a signal class label."""
    lower = signal_class.lower().strip()
    return _PSK_MAP.get(lower)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return bitstream extraction statistics."""
    store = _get_bitstream_store(request)
    return store.get_stats()


@router.post("/extract", status_code=status.HTTP_201_CREATED)
def extract_from_detection(
    body: ExtractRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Extract bitstream from a detection's stored IQ capture.

    Loads IQ data from IQStore, determines modulation type from the
    detection's signal_class (or uses the override), runs the DSP
    extraction pipeline, stores the result, and returns it.
    """
    from sigrift.lib.dsp.bitstream_extractor import extract_bitstream

    iq_store = _get_iq_store(request)
    det_store = _get_detection_store(request)
    bs_store = _get_bitstream_store(request)

    # Load detection record
    detection = det_store.get_detection_by_id(body.detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {body.detection_id!r} not found",
        )

    # Load IQ data
    if not iq_store.exists(body.detection_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ capture for detection {body.detection_id!r}",
        )

    # The analysis prefix of the capture (at most
    # BRIDGE_IQ_ANALYSIS_MAX_SAMPLES samples): a highly compressible upload
    # can hold far more, and the extraction over all of it costs gigabytes.
    iq = iq_store.load_iq_for_analysis(body.detection_id)
    if iq is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decompress IQ data",
        )

    # Determine modulation
    modulation = body.modulation
    if modulation is None:
        signal_class = detection.get("signal_class", "")
        modulation = _infer_modulation(signal_class)
        if modulation is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Cannot infer PSK modulation from signal_class "
                    f"{signal_class!r}. Provide modulation parameter."
                ),
            )

    # Extract bitstream
    try:
        result = extract_bitstream(
            iq=iq,
            modulation=modulation,
            sample_rate=body.sample_rate,
            symbol_rate=body.symbol_rate,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # Store result
    extraction_id = uuid.uuid4().hex
    bits_hex = _bits_to_hex(result.bits)
    signal_class = detection.get("signal_class", modulation)

    bs_store.store_extraction(
        extraction_id=extraction_id,
        detection_id=body.detection_id,
        signal_class=signal_class,
        bits_hex=bits_hex,
        n_bits=len(result.bits),
        modulation=result.modulation,
        symbol_rate=result.symbol_rate,
        snr_estimate=result.snr_estimate,
        confidence=result.confidence,
    )

    return bs_store.get_extraction(extraction_id)


@router.post("/extract/raw", status_code=status.HTTP_201_CREATED)
def extract_from_raw(
    body: ExtractRawRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Extract bitstream from uploaded raw IQ data.

    Accepts base64-encoded float32 interleaved IQ samples.
    """
    from sigrift.lib.dsp.bitstream_extractor import extract_bitstream

    bs_store = _get_bitstream_store(request)

    # Decode IQ data
    try:
        raw_bytes = base64.b64decode(body.iq_base64)
        floats = np.frombuffer(raw_bytes, dtype=np.float32)
        i_vals = floats[0::2]
        q_vals = floats[1::2]
        iq = (i_vals + 1j * q_vals).astype(np.complex64)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to decode IQ data: {exc}",
        )

    if len(iq) < 32:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="IQ data too short (minimum 32 samples)",
        )

    # Extract bitstream
    try:
        result = extract_bitstream(
            iq=iq,
            modulation=body.modulation,
            sample_rate=body.sample_rate,
            symbol_rate=body.symbol_rate,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )

    # Store result
    extraction_id = uuid.uuid4().hex
    bits_hex = _bits_to_hex(result.bits)

    bs_store.store_extraction(
        extraction_id=extraction_id,
        detection_id=None,
        signal_class=body.modulation,
        bits_hex=bits_hex,
        n_bits=len(result.bits),
        modulation=result.modulation,
        symbol_rate=result.symbol_rate,
        snr_estimate=result.snr_estimate,
        confidence=result.confidence,
    )

    return bs_store.get_extraction(extraction_id)


@router.get("/detection/{detection_id}")
def get_by_detection(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Get all bitstream extractions for a detection."""
    store = _get_bitstream_store(request)
    return store.get_by_detection(detection_id)


@router.get("/{extraction_id}")
def get_extraction(
    extraction_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get a single bitstream extraction by ID."""
    store = _get_bitstream_store(request)
    extraction = store.get_extraction(extraction_id)
    if extraction is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Extraction {extraction_id!r} not found",
        )
    return extraction


@router.get("/")
def list_extractions(
    request: Request,
    modulation: str | None = Query(None, description="Filter by modulation type"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List bitstream extractions with optional filters."""
    store = _get_bitstream_store(request)
    return store.list_extractions(
        modulation=modulation,
        limit=limit,
        offset=offset,
    )


@router.delete("/{extraction_id}")
def delete_extraction(
    extraction_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Delete a bitstream extraction."""
    store = _get_bitstream_store(request)
    deleted = store.delete_extraction(extraction_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Extraction {extraction_id!r} not found",
        )
    return {"ok": True, "deleted": extraction_id}
