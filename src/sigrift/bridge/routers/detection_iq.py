"""IQ capture upload, download, and investigation endpoints for The Bridge.

Provides endpoints for edge nodes to upload IQ waveform captures
associated with anomalous detections, for analysts to retrieve
them as visualization JSON or raw binary data, and to trigger
high-resolution investigation captures on edge nodes.
"""

from __future__ import annotations

import asyncio
import logging
import math
import re
import uuid
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge import iq_store as _iq_store_module
from sigrift.bridge.dependencies import Role, enforce_node_binding, require_role
from sigrift.bridge.routers.nodes import _check_command_queue, command_queue_limit
from sigrift.bridge.state import AppState
from sigrift.bridge.storage.detection_crud import IQ_STUB_SIGNAL_CLASS
from sigrift.bridge.utils import get_detection_store, utcnow
from sigrift.lib.shiny.models import _validate_id

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow
_get_detection_store = get_detection_store


def _get_iq_store(request: Request) -> Any:
    """Retrieve the IQStore from app state."""
    iq_store = getattr(request.app.state, "iq_store", None)
    if iq_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ store not initialised",
        )
    return iq_store


# Import broadcast helper from core detections module
def _get_broadcast_anomalies():
    from sigrift.bridge.routers.detections import _broadcast_anomalies

    return _broadcast_anomalies


# ---------------------------------------------------------------------------
# PUT /{detection_id}/iq -- upload IQ capture from edge node
# ---------------------------------------------------------------------------

#: Detection ids an IQ upload may use: ``[A-Za-z0-9_-]{1,128}`` — every id
#: the edge agents generate (hex, UUIDs, ``iq_<command>_<node>_<ts>``).
#: Checked before anything is written, so an id can neither be refused by
#: the IQ store after a stub detection was inserted nor map to the same
#: capture file as another id (the store derives file names from ids).
_IQ_DETECTION_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
_IQ_MAX_UPLOAD_BYTES = 10_485_760  # 10 MB
#: The id an edge gives a manual capture's upload
#: (``rf_scan.execute_iq_capture``): ``iq_<command_id>_<node_id>_<unix
#: time>``, where the command id is the uuid4 the bridge generated for the
#: ``iq_capture`` command (``POST /api/nodes/{node_id}/capture``).
_MANUAL_CAPTURE_ID_RE = re.compile(
    r"iq_(?P<command_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{12})_(?P<node_id>[A-Za-z0-9_-]+)_[0-9]+"
)
#: Signal classes an uploader may name for its capture (``X-Signal-Class``;
#: the detection models' pattern).
_SIGNAL_CLASS_RE = re.compile(r"[a-zA-Z0-9_/.-]{1,128}")
#: The class of a stub detection whose capture names none.  A real
#: detection that arrives later for the same id (and node) replaces such
#: a stub and is ingested as new (``DetectionCrudStore._insert``).
_STUB_SIGNAL_CLASS = IQ_STUB_SIGNAL_CLASS


def _float_header(request: Request, name: str, default: float) -> float:
    """Parse a numeric request header; 400 when it is not a finite number."""
    raw = request.headers.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} must be a non-negative number, got {raw[:32]!r}",
        )
    return value


def _int_header(request: Request, name: str, default: int) -> int:
    """Parse an integer request header; 400 when it is not one."""
    raw = request.headers.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = -1
    if value < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} must be a non-negative integer, got {raw[:32]!r}",
        )
    return value


def _signal_class_header(request: Request) -> str | None:
    """``X-Signal-Class`` (normalized), ``None`` when absent; 400 when malformed."""
    raw = request.headers.get("x-signal-class", "").strip()
    if not raw:
        return None
    if not _SIGNAL_CLASS_RE.fullmatch(raw):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Signal-Class must match [a-zA-Z0-9_/.-]{1,128}",
        )
    from sigrift.bridge.class_map import normalize_class

    return normalize_class(raw)


def _requested_capture_class(
    claims: Any, detection_id: str, node_id: str
) -> str | None:
    """The class an operator named when tasking this manual capture, if any.

    Blocking (SQLite).  The upload's id carries the ``iq_capture``
    command's id (:data:`_MANUAL_CAPTURE_ID_RE`); the class was recorded
    for that command and node by ``POST /api/nodes/{node_id}/capture``.
    """
    match = _MANUAL_CAPTURE_ID_RE.fullmatch(detection_id)
    if match is None or match["node_id"] != node_id or claims is None:
        return None
    try:
        return claims.capture_request_class(match["command_id"], node_id)
    except Exception:
        logger.warning(
            "Could not look up the capture request of %s", detection_id, exc_info=True
        )
        return None


def _upload_node_id(request: Request, principal: str) -> str:
    """Node a new (stub) detection is recorded for: ``X-Node-Id``.

    Without the header a key bound to a node uploads for that node, an
    admin for ``unknown`` (as before); anyone else must name the node.
    """
    node_id = request.headers.get("x-node-id", "").strip()
    if not node_id:
        persistence = request.app.state.persistence
        bound = persistence.get_key_meta().get(principal, {}).get("node_id")
        if isinstance(bound, str) and bound:
            node_id = bound
        elif getattr(request.state, "key_role", Role.SENSOR) >= Role.ADMIN:
            node_id = "unknown"
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-Node-Id header required",
            )
    try:
        return _validate_id(node_id, "X-Node-Id")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from None


@router.put("/{detection_id}/iq", status_code=status.HTTP_201_CREATED)
async def upload_iq_capture(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Upload IQ waveform capture for an anomalous detection.

    Accepts gzip-compressed float32 interleaved IQ data (max 10 MB).
    The caller must be allowed to act for the detection's node (contract
    K4) — for an unknown detection, the node in ``X-Node-Id``, for which
    a stub detection is created once the capture is stored.  Malformed
    ids and headers are rejected (400) before anything is written.

    A stub detection's signal class is ``X-Signal-Class`` when the
    uploader names one, else the class an operator gave when tasking the
    capture (``POST /api/nodes/{node_id}/capture`` with ``signal_class``
    or ``detection_id``), else ``iq_capture``.  A capture of a decodable
    class is queued for protocol decoding once (contract K8b) when it can
    hold a frame; otherwise the response says why not
    (``protocol_decode_skipped``).
    """
    import gzip as _gzip

    if not _IQ_DETECTION_ID_RE.fullmatch(detection_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="detection_id must match [A-Za-z0-9_-]{1,128}",
        )
    named_class = _signal_class_header(request)
    freq_hz = _float_header(request, "x-freq-hz", 0.0)
    sample_rate = _float_header(request, "x-sample-rate", 2.048e6) or 2.048e6
    if not (
        _iq_store_module.MIN_IQ_SAMPLE_RATE_HZ
        <= sample_rate
        <= _iq_store_module.MAX_IQ_SAMPLE_RATE_HZ
    ):
        # The rate sizes later work on the capture (protocol decoding
        # resamples by it): an absurd one must not get that far.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "x-sample-rate must be between "
                f"{_iq_store_module.MIN_IQ_SAMPLE_RATE_HZ:g} and "
                f"{_iq_store_module.MAX_IQ_SAMPLE_RATE_HZ:g} Hz"
            ),
        )
    n_samples_hdr = _int_header(request, "x-iq-samples", 0)

    store = _get_detection_store(request)
    iq_store = _get_iq_store(request)
    app_state: AppState = request.app.state.app_state

    # The node this capture belongs to: the detection's, or (for a
    # standalone capture) the one the uploader names.
    detection = store.get_detection_by_id(detection_id)
    if detection is not None:
        node_id = detection.get("node_id") or ""
        if not node_id and getattr(request.state, "key_role", Role.SENSOR) < (
            Role.ADMIN
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Detection has no node; only an admin may attach IQ to it",
            )
    else:
        node_id = _upload_node_id(request, _key_id)
    if node_id:
        await enforce_node_binding(request, _key_id, node_id)

    # Read body
    raw_body = await request.body()
    if len(raw_body) > _IQ_MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="IQ upload exceeds 10MB limit",
        )

    # If the body isn't already gzip-compressed, compress it
    content_encoding = request.headers.get("content-encoding", "")
    if content_encoding == "gzip":
        compressed = raw_body
    else:
        # Assume raw float32 data, compress it
        compressed = _gzip.compress(raw_body)

    # Store on disk (decompression + quality FFT: off the event loop)
    try:
        await asyncio.to_thread(iq_store.store, detection_id, compressed)
    except ValueError as exc:
        limit_error = getattr(_iq_store_module, "IQSampleLimitError", None)
        if limit_error is not None and isinstance(exc, limit_error):
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=str(exc),
            ) from None
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"IQ capture rejected: {exc}",
        ) from None

    from sigrift.bridge.storage.ingest_claims import get_ingest_claims

    claims = get_ingest_claims(request.app.state)
    if detection is None:
        # Standalone capture from an edge node (manual / investigate):
        # record a stub detection for it, with the class the uploader or
        # the operator who tasked the capture named.
        from sigrift.bridge.models import DetectionRecord

        stub_class = named_class or await asyncio.to_thread(
            _requested_capture_class, claims, detection_id, node_id
        )
        stub = DetectionRecord(
            id=detection_id,
            freq_hz=freq_hz,
            signal_class=stub_class or _STUB_SIGNAL_CLASS,
            confidence=0.0,
            snr_db=0.0,
            power_dbm=-100.0,
            node_id=node_id,
            anomaly_score=0.0,
        )
        await asyncio.to_thread(store.insert_batch, [stub])
        detection = store.get_detection_by_id(detection_id)
        logger.info(
            "Auto-created stub detection for IQ capture: %s (node=%s, freq=%.3f MHz)",
            detection_id,
            node_id,
            freq_hz / 1e6 if freq_hz else 0,
        )

    # Update detection flag
    store.set_has_iq_capture(detection_id)

    from sigrift.bridge.decode_pipeline import is_decodable, queue_protocol_decode_once

    det_class = (detection or {}).get("signal_class")
    n_samples = n_samples_hdr
    if is_decodable(det_class):
        # Whether a decode can find a frame depends on the real length,
        # not on what X-IQ-Samples claims.
        counted = await asyncio.to_thread(iq_store.sample_count, detection_id)
        if counted is not None:
            n_samples = counted

    # Index in IQ metadata store so it appears in /api/iq/index and /stats.
    # Before the decode is queued below: post-ingest takes the capture's
    # sample rate from here when it queues the decode first.
    iq_meta_store = getattr(request.app.state, "iq_metadata_store", None)
    if iq_meta_store is not None:
        iq_meta_store.index_capture(
            detection_id,
            {
                "node_id": detection.get("node_id", "") if detection else "",
                "freq_hz": detection.get("freq_hz", 0.0) if detection else 0.0,
                "signal_class": detection.get("signal_class", "") if detection else "",
                "sample_rate": sample_rate,
                "n_samples": n_samples,
                "file_size_bytes": len(compressed),
                "tier": "standard",
            },
        )
        # Evict oldest captures if over budget (1 GB default)
        iq_meta_store.evict_to_budget(iq_store)

    # Broadcast iq_available event to anomaly WS clients
    _broadcast_anomalies = _get_broadcast_anomalies()
    await _broadcast_anomalies(
        app_state,
        {
            "type": "iq_available",
            "detection_id": detection_id,
            "timestamp": _utcnow().isoformat(),
        },
    )

    # Queue fingerprint computation (non-blocking)
    fingerprint_service = getattr(request.app.state, "fingerprint_service", None)
    job_queue = getattr(request.app.state, "job_queue", None)
    fingerprint_job_id = None
    if fingerprint_service and job_queue:
        try:
            fingerprint_job_id = await job_queue.submit(
                job_type="fingerprint",
                params={
                    "detection_id": detection_id,
                    "detection": detection,
                    "sample_rate": sample_rate,
                },
            )
            logger.debug(
                "Fingerprint job %s queued for %s", fingerprint_job_id, detection_id
            )
        except Exception as exc:
            logger.warning(
                "Failed to queue fingerprint job for %s: %s", detection_id, exc
            )

    logger.info(
        "IQ capture stored: %s (%d bytes, samples=%s)",
        detection_id,
        len(compressed),
        n_samples or "unknown",
    )

    result: dict[str, Any] = {
        "stored": True,
        "detection_id": detection_id,
        "size_bytes": len(compressed),
    }
    if fingerprint_job_id:
        result["fingerprint_job_id"] = fingerprint_job_id
    # Protocol-decode the capture now that it is stored (edges upload IQ
    # after the detection batch, so this is usually where a decodable
    # detection and its IQ first meet).  Once per detection, whichever of
    # this route and post-ingest gets there first (contract K8b).
    decode = await queue_protocol_decode_once(
        getattr(request.app.state, "job_queue", None),
        claims,
        detection_id=detection_id,
        signal_class=det_class,
        freq_hz=(detection or {}).get("freq_hz"),
        node_id=(detection or {}).get("node_id"),
        sample_rate=sample_rate,
        n_samples=n_samples,
        source="iq_upload",
    )
    if decode.job_id:
        result["protocol_decode_job_id"] = decode.job_id
    elif decode.skipped:
        # Logged at debug by queue_protocol_decode_once: every classifier
        # window an edge uploads is too short to decode.
        result["protocol_decode_skipped"] = decode.skipped
    return result


# ---------------------------------------------------------------------------
# GET /{detection_id}/iq -- retrieve IQ capture visualization or raw data
# ---------------------------------------------------------------------------


@router.get("/{detection_id}/iq")
def get_iq_capture(
    detection_id: str,
    request: Request,
    format: str = Query("json", pattern="^(json|raw)$"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Retrieve IQ capture as visualization JSON or raw gzip binary.

    Parameters
    ----------
    format : str
        ``json`` (default) returns constellation/PSD/features dict.
        ``raw`` returns gzip binary with ``application/octet-stream``.
    """
    # P0-3: Raw IQ download contains interceptable communications —
    # require ANALYST role or higher.
    if format == "raw":
        key_role = getattr(request.state, "key_role", Role.VIEWER)
        if key_role < Role.ANALYST:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Raw IQ download requires ANALYST role or higher",
            )

    iq_store = _get_iq_store(request)

    if not iq_store.exists(detection_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ capture for detection {detection_id!r}",
        )

    store = _get_detection_store(request)

    if format == "raw":
        raw = iq_store.load_raw(detection_id)
        # P0-5: Audit log for raw IQ download
        store.log_audit(
            action="iq_download",
            target_id=detection_id,
            operator=_key_id,
            details={"format": "raw", "detection_id": detection_id},
        )
        return Response(
            content=raw,
            media_type="application/octet-stream",
            headers={
                "Content-Encoding": "gzip",
                "Content-Disposition": f'attachment; filename="{detection_id}.iq.gz"',
            },
        )

    # JSON visualization
    viz = iq_store.compute_visualization(detection_id)
    if viz is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute IQ visualization",
        )
    # P0-5: Audit log for JSON visualization download
    store.log_audit(
        action="iq_download",
        target_id=detection_id,
        operator=_key_id,
        details={"format": "json", "detection_id": detection_id},
    )
    return viz


# ---------------------------------------------------------------------------
# GET /{detection_id}/spectrogram -- compute spectrogram / waterfall data
# ---------------------------------------------------------------------------


@router.get("/{detection_id}/spectrogram")
def get_iq_spectrogram(
    detection_id: str,
    request: Request,
    nfft: int = Query(256, ge=64, le=4096),
    overlap: int = Query(128, ge=0),
    window: str = Query("hann"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Compute and return spectrogram/waterfall data for an IQ capture.

    Bounded whatever the capture and parameters (see
    :meth:`IQStore.compute_spectrogram`): at most
    ``BRIDGE_IQ_ANALYSIS_MAX_SAMPLES`` samples are analysed, the STFT work
    is capped (a very high overlap is lowered; ``overlap`` in the result
    is the one used) and consecutive segments are averaged down to at
    most ``SPECTROGRAM_MAX_CELLS`` cells.  dB values are rounded to 0.1 dB
    (the viewer shows one decimal).
    """
    if overlap >= nfft:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="overlap must be less than nfft",
        )

    iq_store = _get_iq_store(request)

    if not iq_store.exists(detection_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ capture for detection {detection_id!r}",
        )

    try:
        result = iq_store.compute_spectrogram(
            detection_id,
            nfft=nfft,
            overlap=overlap,
            window=window,
            db_decimals=1,
        )
    except ValueError as exc:  # unknown window name
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to compute spectrogram",
        )
    return result


# ---------------------------------------------------------------------------
# GET /{detection_id}/modulation -- extract modulation parameters
# ---------------------------------------------------------------------------


@router.get("/{detection_id}/modulation")
def get_modulation_params(
    detection_id: str,
    request: Request,
    sample_rate: float = Query(2.048e6, gt=0, description="Sample rate in Hz"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Extract modulation parameters from an IQ capture.

    Returns symbol rate, occupied bandwidth, and carrier frequency offset
    estimated from the stored IQ data.
    """
    from sigrift.lib.dsp.modulation_params import extract_modulation_params

    iq_store = _get_iq_store(request)

    if not iq_store.exists(detection_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ capture for detection {detection_id!r}",
        )

    # Full-length FFTs: bounded to the analysis window like the other
    # IQ consumers (a highly compressible upload can hold 32 Mi samples).
    iq = iq_store.load_iq_for_analysis(detection_id)
    if iq is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decompress IQ data",
        )

    return extract_modulation_params(iq, sample_rate=sample_rate)


# ---------------------------------------------------------------------------
# POST /{detection_id}/investigate -- P1-3: investigate command channel
# ---------------------------------------------------------------------------


class InvestigateRequest(BaseModel):
    """Parameters for a high-resolution investigation capture."""

    model_config = {"extra": "forbid"}

    sample_rate: float = Field(2.4e6, gt=0, le=20e6, description="Sample rate in Hz")
    duration_ms: int = Field(
        2000, ge=100, le=30000, description="Capture duration in ms"
    )
    gain_db: float = Field(40.0, ge=0, le=70, description="Receiver gain in dB")


@router.post("/{detection_id}/investigate")
async def investigate_detection(
    detection_id: str,
    request: Request,
    body: InvestigateRequest = InvestigateRequest(),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Trigger a high-resolution IQ investigation capture on the edge node
    that produced the given detection.

    Looks up the detection to find its node, frequency, and signal class,
    then queues an ``investigate`` command with higher sample count (65536),
    configurable sample rate, duration, and gain.  Requires ANALYST role.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state
    persistence = request.app.state.persistence

    # Look up the detection
    detection = store.get_detection_by_id(detection_id)
    if detection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection {detection_id!r} not found",
        )

    node_id = detection.get("node_id", "")
    if not node_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Detection has no associated node_id",
        )

    # Verify the node exists
    if node_id not in persistence.get_nodes():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    now = _utcnow()
    command_id = str(uuid.uuid4())

    cmd = {
        "command": "investigate",
        "command_id": command_id,
        "params": {
            "freq_hz": detection.get("freq_hz", 0.0),
            "sample_rate": body.sample_rate,
            "sample_count": 65536,
            "duration_ms": body.duration_ms,
            "gain_db": body.gain_db,
            "detection_id": detection_id,
            "signal_class": detection.get("signal_class", ""),
        },
        "queued_at": now.isoformat(),
    }

    # Queue command for delivery on next heartbeat (bounded like every
    # other non-admin command, see routers/nodes.py)
    _check_command_queue(request, app_state, node_id)
    if node_id not in app_state.pending_commands:
        app_state.pending_commands[node_id] = []
    app_state.pending_commands[node_id].append(cmd)

    # Audit log
    store.log_audit(
        action="investigate_queued",
        target_id=detection_id,
        node_id=node_id,
        operator=_key_id,
        details={
            "command_id": command_id,
            "freq_hz": detection.get("freq_hz", 0.0),
            "signal_class": detection.get("signal_class", ""),
            "sample_rate": body.sample_rate,
            "duration_ms": body.duration_ms,
            "gain_db": body.gain_db,
        },
    )

    # Activity log
    app_state.log_activity(
        event_type="investigate_queued",
        node_id=node_id,
        message=(
            f"Investigation queued for detection {detection_id} on {node_id}: "
            f"{detection.get('freq_hz', 0) / 1e6:.3f} MHz, "
            f"{body.duration_ms}ms, gain {body.gain_db} dB"
        ),
    )

    logger.info(
        "Investigation %s queued for node %s (detection %s, %.3f MHz)",
        command_id,
        node_id,
        detection_id,
        detection.get("freq_hz", 0) / 1e6,
    )

    return {
        "ok": True,
        "command_id": command_id,
        "node_id": node_id,
        "detection_id": detection_id,
        "command": cmd,
    }


# ---------------------------------------------------------------------------
# GET /{detection_id}/sigmf -- P1-5: SigMF metadata for IQ capture
# ---------------------------------------------------------------------------


@router.get("/{detection_id}/sigmf")
def get_sigmf_metadata(
    detection_id: str,
    request: Request,
    sample_rate: float = Query(2.048e6, gt=0, description="Sample rate in Hz"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Return SigMF metadata JSON for a detection's IQ capture.

    Requires VIEWER role (metadata only, no raw data access).
    Returns 404 if no IQ capture exists for the detection.
    """
    from sigrift.bridge.sigmf import generate_sigmf_meta

    iq_store = _get_iq_store(request)

    if not iq_store.exists(detection_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ capture for detection {detection_id!r}",
        )

    store = _get_detection_store(request)
    detection = store.get_detection_by_id(detection_id)

    # Build detection record dict for SigMF generator
    if detection is None:
        # IQ exists but detection record is gone — use minimal defaults
        detection = {}

    # Sample count, counted while inflating (the samples are not kept)
    sample_count = iq_store.sample_count(detection_id)
    if sample_count is not None:
        detection["sample_count"] = sample_count

    meta = generate_sigmf_meta(
        detection_id=detection_id,
        detection_record=detection,
        sample_rate=sample_rate,
    )
    return meta


# ---------------------------------------------------------------------------
# PUT /{detection_id}/iq/tier -- set IQ retention tier (P1-9)
# ---------------------------------------------------------------------------


class SetTierRequest(BaseModel):
    """Request body for setting IQ capture retention tier."""

    model_config = {"extra": "forbid"}

    tier: str = Field(..., pattern="^(critical|standard|temporary)$")
    ttl_hours: int | None = Field(None, ge=0, description="Override TTL in hours")


def _get_iq_metadata_store(request: Request) -> Any:
    """Retrieve the IQMetadataStore from app state."""
    store = getattr(request.app.state, "iq_metadata_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ metadata store not initialised",
        )
    return store


@router.put("/{detection_id}/iq/tier")
def set_iq_tier(
    detection_id: str,
    body: SetTierRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Set the retention tier for an IQ capture. Requires ADMIN role."""
    meta_store = _get_iq_metadata_store(request)

    updated = meta_store.set_tier(
        detection_id,
        tier=body.tier,
        ttl_hours=body.ttl_hours,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No IQ metadata for detection {detection_id!r}",
        )

    meta = meta_store.get_metadata(detection_id)
    return {
        "ok": True,
        "detection_id": detection_id,
        "tier": body.tier,
        "expires_at": meta["expires_at"] if meta else None,
    }


# ---------------------------------------------------------------------------
# P1-4: Auto-rescan helper
# ---------------------------------------------------------------------------

# In-memory retry tracking: {(node_id, freq_bucket_mhz): retry_count}
_auto_rescan_retries: dict[tuple[str, int], int] = {}


def check_auto_rescan(
    detection: dict[str, Any],
    app_state: AppState,
    persistence: Any,
) -> bool:
    """Check whether a low-confidence detection should trigger an automatic rescan.

    Reads the auto-rescan config from persistence.  If enabled and the
    detection confidence is below the threshold, queues a rescan command
    to the originating node.  Tracks retry counts per (node_id, freq_bucket)
    to prevent infinite loops.

    Parameters
    ----------
    detection : dict
        Detection record dict (must have node_id, confidence, freq_hz, signal_class).
    app_state : AppState
        The app state (for pending_commands).
    persistence : PersistenceManager
        For reading auto-rescan config and verifying node existence.

    Returns
    -------
    bool
        True if a rescan command was queued, False otherwise.
    """
    config = persistence.get_detection_config()
    auto_rescan = config.get("auto_rescan", {})

    if not auto_rescan.get("enabled", False):
        return False

    threshold = auto_rescan.get("confidence_threshold", 0.5)
    max_retries = auto_rescan.get("max_retries", 2)

    confidence = detection.get("confidence", 1.0)
    if confidence >= threshold:
        return False

    node_id = detection.get("node_id", "")
    if not node_id:
        return False

    # Verify node exists
    if node_id not in persistence.get_nodes():
        return False

    # Check retry count (bucket frequency to nearest MHz)
    freq_hz = detection.get("freq_hz", 0.0)
    freq_bucket = int(freq_hz / 1e6)
    retry_key = (node_id, freq_bucket)

    current_retries = _auto_rescan_retries.get(retry_key, 0)
    if current_retries >= max_retries:
        logger.debug(
            "Auto-rescan: max retries (%d) reached for %s @ %d MHz",
            max_retries,
            node_id,
            freq_bucket,
        )
        return False

    # Never fill the queue slots reserved for admin commands
    if len(app_state.pending_commands.get(node_id, [])) >= command_queue_limit(
        Role.SENSOR
    ):
        return False

    # Queue rescan command
    command_id = str(uuid.uuid4())
    now = _utcnow()

    cmd = {
        "command": "rescan",
        "command_id": command_id,
        "params": {
            "freq_hz": freq_hz,
            "sample_rate": 2.4e6,
            "duration_ms": 1000,
            "gain_db": 40.0,
            "reason": "low_confidence_auto_rescan",
            "original_confidence": confidence,
            "signal_class": detection.get("signal_class", ""),
            "retry_number": current_retries + 1,
        },
        "queued_at": now.isoformat(),
    }

    if node_id not in app_state.pending_commands:
        app_state.pending_commands[node_id] = []
    app_state.pending_commands[node_id].append(cmd)

    _auto_rescan_retries[retry_key] = current_retries + 1

    app_state.log_activity(
        event_type="auto_rescan_queued",
        node_id=node_id,
        message=(
            f"Auto-rescan queued for {node_id} @ {freq_hz / 1e6:.3f} MHz "
            f"(confidence={confidence:.2f} < threshold={threshold:.2f}, "
            f"retry {current_retries + 1}/{max_retries})"
        ),
    )

    logger.info(
        "Auto-rescan %s queued for node %s @ %.3f MHz (confidence=%.2f, retry %d/%d)",
        command_id,
        node_id,
        freq_hz / 1e6,
        confidence,
        current_retries + 1,
        max_retries,
    )

    return True
