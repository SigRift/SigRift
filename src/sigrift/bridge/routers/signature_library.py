"""Reference IQ Signature Library API endpoints for The Bridge.

Provides CRUD operations for curated reference IQ signatures,
similarity search, signal matching, and import/export.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import uuid
from typing import Any

import numpy as np
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge import iq_store as _iq_store_module
from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_signature_store(request: Request) -> Any:
    """Retrieve the SignatureLibraryStore from app state."""
    store = getattr(request.app.state, "signature_library_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Signature library store not initialised",
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


def _get_detection_store(request: Request) -> Any:
    """Retrieve the DetectionStore from app state."""
    store = getattr(request.app.state, "detection_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not initialised",
        )
    return store


def _load_iq_for_analysis(
    iq_store: Any, capture_id: str
) -> tuple[np.ndarray | None, int | None]:
    """The analysis prefix of a capture and the capture's sample count.

    Features and embeddings are computed over at most
    :func:`sigrift.bridge.iq_store.analysis_max_samples` samples (the start
    of the capture): a highly compressible upload holds up to
    ``BRIDGE_IQ_MAX_SAMPLES`` samples, and the DSP features over all of
    them cost gigabytes.  The count of a longer capture is taken while
    inflating, without holding the samples.
    """
    iq = iq_store.load_iq_for_analysis(capture_id)
    if iq is None:
        return None, None
    n_samples = len(iq)
    if n_samples >= _iq_store_module.analysis_max_samples():
        n_samples = iq_store.sample_count(capture_id) or n_samples
    return iq, n_samples


def _compute_embedding_from_iq(iq: np.ndarray) -> tuple[list[float], list[float]]:
    """Compute 49-dim features and 32-dim embedding from IQ samples.

    Uses compute_dsp_features if available, with fallback to simple
    L2-normalized truncation.

    Returns
    -------
    tuple[list[float], list[float]]
        (embedding_32, features_49)
    """
    import torch

    # Prepare IQ tensor [1, 2, N]
    i_vals = iq.real.astype(np.float32)
    q_vals = iq.imag.astype(np.float32)
    iq_tensor = torch.tensor(
        np.stack([i_vals, q_vals])[np.newaxis, :, :],
        dtype=torch.float32,
    )

    # Compute 49-dim DSP features (3 spectral + 6 CP + 8 cumulants + 32 extended)
    try:
        from sigrift.lib.dsp.spectral_features import compute_dsp_features

        with torch.no_grad():
            feats = compute_dsp_features(iq_tensor)
        features_49 = feats.squeeze(0).tolist()
    except Exception:
        # Fallback: simple statistical features
        features_49 = _fallback_features(iq)

    # Compute 32-dim embedding.
    # The learned SignalEncoder lives in the sigrift_sentinel enterprise
    # plugin; community installs use the L2-normalised statistical
    # fallback below. If the sentinel package is installed, its
    # SignalEncoder becomes importable and we use it; otherwise the
    # ImportError is silently swallowed.
    try:
        from sigrift_sentinel.fingerprint.encoder import SignalEncoder

        encoder = SignalEncoder(input_dim=54, embedding_dim=32)
        encoder.eval()
        with torch.no_grad():
            feat_tensor = torch.tensor([features_49], dtype=torch.float32)
            emb = encoder(feat_tensor)
        embedding_32 = emb.squeeze(0).tolist()
    except Exception:
        # Fallback: L2-normalize first 32 features.
        vec = np.array(features_49[:32], dtype=np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec = vec / norm
        embedding_32 = vec.tolist()

    return embedding_32, features_49


def _fallback_features(iq: np.ndarray) -> list[float]:
    """Compute simple fallback features when DSP module is unavailable."""
    n = len(iq)
    feats = [0.0] * 49
    if n == 0:
        return feats
    mag = np.abs(iq)
    feats[0] = float(np.mean(mag))
    feats[1] = float(np.std(mag))
    feats[2] = float(np.max(mag))
    feats[3] = float(np.mean(iq.real))
    feats[4] = float(np.mean(iq.imag))
    feats[5] = float(np.std(iq.real))
    feats[6] = float(np.std(iq.imag))
    return feats


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class MatchRequest(BaseModel):
    """Request body for matching an unknown signal."""

    model_config = {"extra": "forbid"}

    embedding: list[float] | None = Field(None, description="32-dim embedding vector")
    detection_id: str | None = Field(
        None, description="Detection ID to look up IQ data"
    )
    threshold: float = Field(
        0.8, ge=0.0, le=1.0, description="Minimum similarity threshold"
    )


class SearchRequest(BaseModel):
    """Request body for similarity search."""

    model_config = {"extra": "forbid"}

    embedding: list[float] = Field(
        ..., min_length=1, description="Query embedding vector"
    )
    top_k: int = Field(10, ge=1, le=100, description="Max results")
    threshold: float = Field(0.5, ge=0.0, le=1.0, description="Min cosine similarity")


class UpdateSignatureRequest(BaseModel):
    """Request body for updating a signature."""

    model_config = {"extra": "forbid"}

    name: str | None = Field(None, description="New name")
    protocol: str | None = Field(None, description="New protocol")
    signal_class: str | None = Field(None, description="New signal class")
    description: str | None = Field(None, description="New description")
    center_freq_hz: float | None = Field(None, description="Center frequency")
    bandwidth_hz: float | None = Field(None, description="Bandwidth")
    sample_rate_hz: float | None = Field(None, description="Sample rate")
    source: str | None = Field(None, description="Source")


class CreateFromDetectionRequest(BaseModel):
    """Request body for creating a signature from a detection."""

    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=1, description="Signature name")
    protocol: str = Field(..., min_length=1, description="Protocol type")
    description: str = Field("", description="Description")
    tags: list[str] = Field(default_factory=list, description="Tags")


class ExportRequest(BaseModel):
    """Request body for export."""

    model_config = {"extra": "forbid"}

    sig_ids: list[str] | None = Field(None, description="IDs to export; None for all")


class ImportRequest(BaseModel):
    """Request body for import."""

    model_config = {"extra": "forbid"}

    signatures: list[dict[str, Any]] = Field(
        ..., description="Signature records to import"
    )


class TagsRequest(BaseModel):
    """Request body for updating tags."""

    model_config = {"extra": "forbid"}

    tags: list[str] = Field(..., description="New tags list")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


_GZIP_MAGIC = b"\x1f\x8b"


async def _gzip_reference_iq(raw_data: bytes) -> bytes:
    """Return *raw_data* as a gzip IQ payload, bounded like edge uploads.

    A gzip upload must decompress (with the same sample cap as
    :func:`sigrift.bridge.iq_store.decompress_iq`) to whole complex64
    samples; anything else that starts with the gzip magic is rejected
    rather than double-compressed.  A raw upload must be whole complex64
    samples within the cap and is compressed in a worker thread.
    """
    if raw_data[:2] == _GZIP_MAGIC:
        try:
            await asyncio.to_thread(_iq_store_module.decompress_iq, raw_data)
        except _iq_store_module.IQSampleLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
            ) from exc
        except _iq_store_module.IQDecompressionError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid gzip IQ file: {exc}",
            ) from exc
        return raw_data
    if not raw_data or len(raw_data) % 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="IQ file must be gzip or raw interleaved float32 I/Q "
            "(a whole number of 8-byte complex64 samples)",
        )
    if len(raw_data) // 8 > _iq_store_module.max_iq_samples():
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"IQ file exceeds {_iq_store_module.max_iq_samples()} samples",
        )
    return await asyncio.to_thread(gzip.compress, raw_data)


@router.get("/stats")
def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return library statistics."""
    store = _get_signature_store(request)
    return store.get_stats()


@router.get("/")
def list_signatures(
    request: Request,
    protocol: str | None = Query(None, description="Filter by protocol"),
    signal_class: str | None = Query(None, description="Filter by signal class"),
    verified: bool | None = Query(None, description="Filter by verified flag"),
    tags: str | None = Query(None, description="Comma-separated tags filter"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List reference signatures with optional filters."""
    store = _get_signature_store(request)
    tag_list = tags.split(",") if tags else None
    return store.list_signatures(
        protocol=protocol,
        signal_class=signal_class,
        verified=verified,
        tags=tag_list,
        limit=limit,
        offset=offset,
    )


@router.get("/{sig_id}")
def get_signature(
    sig_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get a single reference signature by ID."""
    store = _get_signature_store(request)
    sig = store.get_signature(sig_id)
    if sig is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature {sig_id!r} not found",
        )
    return sig


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_signature(
    request: Request,
    name: str = Form(...),
    protocol: str = Form(...),
    signal_class: str = Form(...),
    description: str = Form(""),
    center_freq_hz: float | None = Form(None),
    bandwidth_hz: float | None = Form(None),
    sample_rate_hz: float | None = Form(None),
    tags: str = Form("[]"),
    source: str = Form(""),
    iq_file: UploadFile | None = File(None),
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Upload a new reference signature with optional IQ file."""
    store = _get_signature_store(request)
    iq_store = _get_iq_store(request)

    sig_id = str(uuid.uuid4())
    embedding = None
    features = None
    iq_file_path = None
    iq_samples = None
    sigmf_metadata = None

    # Parse tags
    try:
        tag_list = json.loads(tags)
    except (json.JSONDecodeError, TypeError):
        tag_list = []

    # Process IQ file if provided
    if iq_file is not None:
        raw_data = await iq_file.read()
        iq_file_path = sig_id
        compressed = await _gzip_reference_iq(raw_data)
        try:
            await asyncio.to_thread(iq_store.store, sig_id, compressed)
        except _iq_store_module.IQSampleLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
            ) from exc

        # Load IQ and compute features/embedding (CPU-bound: off the loop)
        iq, iq_samples = await asyncio.to_thread(
            _load_iq_for_analysis, iq_store, sig_id
        )
        if iq is not None:
            embedding, features = await asyncio.to_thread(
                _compute_embedding_from_iq, iq
            )

            # Generate SigMF metadata
            try:
                from sigrift.bridge.sigmf import generate_sigmf_meta

                detection_record = {
                    "freq_hz": center_freq_hz or 0.0,
                    "signal_class": signal_class,
                    "node_id": "",
                    "bandwidth_hz": bandwidth_hz,
                    "sample_count": iq_samples,
                }
                sr = sample_rate_hz or 1.0
                sigmf_metadata = generate_sigmf_meta(
                    detection_id=sig_id,
                    detection_record=detection_record,
                    sample_rate=sr,
                )
            except Exception as exc:
                logger.warning("Failed to generate SigMF metadata: %s", exc)

    store.add_signature(
        sig_id=sig_id,
        name=name,
        protocol=protocol,
        signal_class=signal_class,
        description=description,
        center_freq_hz=center_freq_hz,
        bandwidth_hz=bandwidth_hz,
        sample_rate_hz=sample_rate_hz,
        embedding=embedding,
        features=features,
        iq_file_path=iq_file_path,
        iq_samples=iq_samples,
        sigmf_metadata=sigmf_metadata,
        tags=tag_list,
        source=source,
    )

    return store.get_signature(sig_id)


@router.post("/from-detection/{detection_id}", status_code=status.HTTP_201_CREATED)
def create_from_detection(
    detection_id: str,
    body: CreateFromDetectionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a reference signature from an existing detection."""
    store = _get_signature_store(request)
    det_store = _get_detection_store(request)
    iq_store = _get_iq_store(request)

    # Look up detection
    conn = det_store.get_connection()
    row = conn.execute(
        "SELECT * FROM detections WHERE detection_id = ?",
        (detection_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id!r} not found",
        )
    detection = dict(row)

    sig_id = str(uuid.uuid4())
    embedding = None
    features = None
    iq_file_path = None
    iq_samples = None

    # Try to get existing fingerprint
    fp_store = getattr(request.app.state, "fingerprint_store", None)
    if fp_store:
        fp = fp_store.get_by_detection(detection_id)
        if fp:
            embedding = fp.get("embedding")
            features = fp.get("features_48dim")

    # Try to load IQ data
    if iq_store.exists(detection_id):
        iq_file_path = detection_id
        iq, iq_samples = _load_iq_for_analysis(iq_store, detection_id)
        if iq is not None:
            if embedding is None:
                embedding, features = _compute_embedding_from_iq(iq)

    store.add_signature(
        sig_id=sig_id,
        name=body.name,
        protocol=body.protocol,
        signal_class=detection.get("signal_class", "unknown"),
        description=body.description,
        center_freq_hz=detection.get("freq_hz"),
        bandwidth_hz=detection.get("bandwidth_hz"),
        embedding=embedding,
        features=features,
        iq_file_path=iq_file_path,
        iq_samples=iq_samples,
        tags=body.tags,
        source=f"detection:{detection_id}",
    )

    result = store.get_signature(sig_id)
    return result


@router.put("/{sig_id}")
def update_signature(
    sig_id: str,
    body: UpdateSignatureRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update signature metadata."""
    store = _get_signature_store(request)
    sig = store.get_signature(sig_id)
    if sig is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature {sig_id!r} not found",
        )
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if updates:
        store.update_signature(sig_id, **updates)
    return store.get_signature(sig_id)


@router.delete("/{sig_id}")
def delete_signature(
    sig_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Delete a reference signature."""
    store = _get_signature_store(request)
    deleted = store.delete_signature(sig_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature {sig_id!r} not found",
        )
    return {"ok": True, "deleted": sig_id}


@router.post("/match")
def match_signal(
    body: MatchRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Match an unknown signal against the reference library."""
    store = _get_signature_store(request)
    iq_store = _get_iq_store(request)

    embedding = body.embedding

    if embedding is None and body.detection_id:
        # Try to compute embedding from detection IQ (its analysis prefix)
        iq = iq_store.load_iq_for_analysis(body.detection_id)
        if iq is not None:
            embedding, _ = _compute_embedding_from_iq(iq)
        else:
            # Try fingerprint store
            fp_store = getattr(request.app.state, "fingerprint_store", None)
            if fp_store:
                fp = fp_store.get_by_detection(body.detection_id)
                if fp:
                    embedding = fp.get("embedding")

    if embedding is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide embedding or detection_id with available IQ data",
        )

    match = store.match_signal(embedding, threshold=body.threshold)
    if match is None:
        return {"matched": False, "match": None}
    return {"matched": True, "match": match}


@router.post("/search")
def search_similar(
    body: SearchRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Search for similar signatures in the library."""
    store = _get_signature_store(request)
    return store.search_similar(
        embedding=body.embedding,
        top_k=body.top_k,
        threshold=body.threshold,
    )


@router.post("/export")
def export_signatures(
    body: ExportRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Export signatures as JSON."""
    store = _get_signature_store(request)
    signatures = store.export_signatures(sig_ids=body.sig_ids)
    return {"signatures": signatures, "count": len(signatures)}


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_signatures(
    body: ImportRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Import signatures from JSON."""
    store = _get_signature_store(request)
    count = store.import_signatures(body.signatures)
    return {"imported": count}


@router.put("/{sig_id}/verify")
def verify_signature(
    sig_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Mark a signature as verified."""
    store = _get_signature_store(request)
    sig = store.get_signature(sig_id)
    if sig is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature {sig_id!r} not found",
        )
    store.verify_signature(sig_id)
    return store.get_signature(sig_id)


@router.put("/{sig_id}/tags")
def update_tags(
    sig_id: str,
    body: TagsRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update tags on a signature (replace all tags)."""
    store = _get_signature_store(request)
    sig = store.get_signature(sig_id)
    if sig is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Signature {sig_id!r} not found",
        )
    # Replace all tags
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()
    with store._ctx.write_transaction() as conn:
        conn.execute(
            "UPDATE reference_signatures SET tags = ?, updated_at = ? WHERE id = ?",
            (json.dumps(body.tags), now, sig_id),
        )
    return store.get_signature(sig_id)


# ---------------------------------------------------------------------------
# Threat signature endpoints
# ---------------------------------------------------------------------------


@router.get("/threats/list")
def list_threats(
    request: Request,
    threat_category: str | None = None,
    threat_level: str | None = None,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List threat signatures with optional category/level filters."""
    store = _get_signature_store(request)
    return store.get_threat_signatures(
        threat_category=threat_category,
        threat_level=threat_level,
    )


class ThreatMatchRequest(BaseModel):
    model_config = {"extra": "forbid"}
    freq_hz: float | None = None
    signal_class: str | None = None
    power_dbm: float | None = None
    bandwidth_hz: float | None = None


@router.post("/threats/match")
def match_threats(
    body: ThreatMatchRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Match observed signal parameters against threat signatures."""
    store = _get_signature_store(request)
    matches = store.match_by_parameters(
        freq_hz=body.freq_hz,
        signal_class=body.signal_class,
        power_dbm=body.power_dbm,
        bandwidth_hz=body.bandwidth_hz,
    )
    return {
        "matched": len(matches) > 0,
        "count": len(matches),
        "matches": matches,
    }


@router.post("/threats/seed")
def seed_threats(
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Seed the threat signature library with curated TSCM signatures."""
    store = _get_signature_store(request)
    count = store.seed_threat_signatures()
    return {"seeded": count}
