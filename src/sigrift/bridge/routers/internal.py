"""Gateway-only internal endpoints (contracts K7, K8, K9), under ``/api/internal``.

* ``POST /api/internal/bind-node-key`` — the gateway's ingest asks the
  bridge to bind an unbound node API key to the node it posts for (K7,
  K7b), with the same trust-on-first-use routine the bridge's own
  node-scoped routes use (:func:`sigrift.bridge.dependencies.bind_node_key`).
* ``POST /api/internal/ingest-hook`` — the gateway hands over each batch
  it ingested natively, after committing it, so the bridge runs the
  post-ingest work (alert rules, watch bands, anomaly alerts, webhooks,
  edge-decoded messages, protocol_decode jobs; K8, K8b).  It never
  inserts or re-broadcasts the detections themselves; detections are
  claimed in ``detections.db`` (shared by every worker process) so a
  re-delivered batch is processed once; webhooks run in the background.

Every route requires the ``X-Rust-Proxy`` secret and accepts no other
credential (:func:`sigrift.bridge.dependencies.require_rust_proxy`); the
middleware refuses the whole prefix without it too.  The gateway answers
``/api/internal/*`` with 404 for clients and never proxies it (K9).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from sigrift.bridge.dependencies import (
    NODE_ALREADY_BOUND,
    NODE_KEY_REQUIRED,
    NodeBindOutcome,
    Role,
    bind_node_key,
    read_json_body,
    require_rust_proxy,
    stored_key_role,
    valid_node_id,
)
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.routers.detections import _edge_decoded_from_hook, post_ingest
from sigrift.bridge.storage.ingest_claims import get_ingest_claims

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_rust_proxy)])

#: Longest key id accepted by bind-node-key.
_MAX_KEY_ID_LEN = 256
#: Largest ingest-hook body (the gateway accepts batches of up to 50 MB
#: decompressed; the hook carries the accepted part of one batch).
INGEST_HOOK_MAX_BODY = 64 * 1024 * 1024
#: Detections processed per hook; the rest are skipped (and logged).
_HOOK_MAX_DETECTIONS = 20_000
#: Hooked ``(node_id, detection_id)`` pairs are claimed in ``detections.db``
#: (:class:`~sigrift.bridge.storage.ingest_claims.IngestClaimStore`), which
#: every bridge worker process shares, so a batch the gateway sends again —
#: a retry after a lost or slow response, possibly answered by another
#: worker, or a redelivery of what it spooled across a restart (contract
#: K8b) — does not fire its alerts twice.  A claim expires after
#: ``_HOOK_SEEN_TTL`` seconds, which covers the gateway's retries of a
#: chunk (3 attempts of up to 10 s, 0.5 s and 1 s apart) and a gateway
#: that is down for hours before it re-sends its spool; about
#: ``_HOOK_SEEN_MAX`` claims are kept whatever the ingest rate (oldest
#: dropped first; roughly 130 bytes each on disk).  The cap must hold one
#: whole hook (``_HOOK_MAX_DETECTIONS``), so that hook's own retry is
#: still caught.
_HOOK_SEEN_TTL = 86_400.0
_HOOK_SEEN_MAX = 200_000
#: Wall clock for the claims (shared by processes; a seam for tests).
_clock = time.time


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail
    )


def _persistence(request: Request) -> Any:
    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )
    return persistence


# ---------------------------------------------------------------------------
# K7: POST /api/internal/bind-node-key
# ---------------------------------------------------------------------------


@router.post("/bind-node-key")
async def bind_node_key_route(request: Request) -> JSONResponse:
    """Bind node API key ``key_id`` to ``node_id`` unless it is bound already.

    Answers (contracts K7, K7b):

    * 200 ``{"node_id": <node>, "bound": true}`` — the key is bound to that
      node (now, or it already was);
    * 409 ``{"node_id": <other node>}`` — it is bound to a different node;
    * 409 ``{"node_id": <node>, "detail": "node already has a bound key"}``
      — an unbound node key, but another key is already bound to that
      node (first key wins; an admin binds extra keys explicitly);
    * 409 ``{"node_id": <node>, "detail": "Node endpoints require a node
      API key"}`` — an unbound key whose role is neither a node role
      (SENSOR, NODE) nor ANALYST-or-above (i.e. VIEWER): never bound;
    * 404 — no such key;
    * 403 — wrong or missing ``X-Rust-Proxy`` (the router dependency).

    Only SENSOR / NODE keys are bound on first use.  An admin (or higher)
    key is never bound — admins act for any node — and neither is an
    unbound ANALYST key (operator tooling): both get 200
    ``{"node_id": <node>, "bound": false}``.
    """
    payload = await read_json_body(
        request, max_body_bytes=4096, max_decompressed_bytes=4096
    )
    key_id = payload.get("key_id")
    node_id = payload.get("node_id")
    if not isinstance(key_id, str) or not key_id or len(key_id) > _MAX_KEY_ID_LEN:
        raise _unprocessable("key_id must be a non-empty string")
    if not valid_node_id(node_id):
        raise _unprocessable("node_id must match [a-zA-Z0-9_-]{1,64}")

    persistence = _persistence(request)
    if key_id not in persistence.get_key_store():
        return JSONResponse(status_code=404, content={"detail": "Unknown API key"})
    if stored_key_role(key_id, persistence.get_key_meta().get(key_id)) >= Role.ADMIN:
        return JSONResponse(content={"node_id": node_id, "bound": False})

    binding = await bind_node_key(persistence, key_id, node_id)
    if binding.outcome is NodeBindOutcome.UNKNOWN_KEY:
        # Revoked between the lookup and the bind.
        return JSONResponse(status_code=404, content={"detail": "Unknown API key"})
    if binding.outcome is NodeBindOutcome.OPERATOR_KEY:
        # K7b: an unbound ANALYST key is operator tooling, never bound.
        return JSONResponse(content={"node_id": node_id, "bound": False})
    if binding.outcome is NodeBindOutcome.NOT_NODE_KEY:
        # K7b: never bound automatically.  409, which the gateway turns
        # into a 403 (a 403 here would read as a wrong proxy secret).
        logger.warning(
            "Gateway ingest: API key %r is not a node key (role below "
            "ANALYST, not SENSOR/NODE) and posted for node %r",
            key_id,
            node_id,
        )
        return JSONResponse(
            status_code=409,
            content={"node_id": node_id, "detail": NODE_KEY_REQUIRED},
        )
    if binding.outcome is NodeBindOutcome.NODE_CLAIMED:
        return JSONResponse(
            status_code=409,
            content={"node_id": node_id, "detail": NODE_ALREADY_BOUND},
        )
    bound = binding.node_id
    if bound != node_id:
        logger.warning(
            "Gateway ingest: API key %r is bound to node %r but posted for %r",
            key_id,
            bound,
            node_id,
        )
        return JSONResponse(status_code=409, content={"node_id": bound})
    return JSONResponse(content={"node_id": bound, "bound": True})


# ---------------------------------------------------------------------------
# K8: POST /api/internal/ingest-hook
# ---------------------------------------------------------------------------


def _parse_hook_detections(
    node_id: str, raw_dets: list[Any]
) -> tuple[list[DetectionRecord], int]:
    """Validate the hooked detections; return ``(records, invalid_count)``."""
    records: list[DetectionRecord] = []
    invalid = 0
    for raw in raw_dets:
        if not isinstance(raw, dict):
            invalid += 1
            continue
        det_id = raw.get("detection_id") or raw.get("id")
        if not isinstance(det_id, str) or not det_id:
            invalid += 1
            continue
        item = dict(raw)
        item.pop("id", None)
        item["detection_id"] = det_id
        det_node = item.get("node_id") or node_id
        if det_node != node_id:
            # The gateway forces every detection onto the batch's node
            # (K4); anything else is not this node's to attribute.
            invalid += 1
            continue
        item["node_id"] = node_id
        try:
            records.append(DetectionRecord(**item))
        except (ValidationError, TypeError, ValueError):
            invalid += 1
    return records, invalid


@router.post("/ingest-hook")
async def ingest_hook(request: Request) -> dict[str, Any]:
    """Run the post-ingest work for a batch the gateway already stored.

    Body (contract K8)::

        {"node_id": "...", "batch_id": "..." (optional),
         "detections": [<detection as inserted, with detection_id>, ...],
         "decoded_messages": [...] (optional, see _edge_decoded_from_hook),
         "received_at": "<ISO UTC>"}

    Calls only :func:`~sigrift.bridge.routers.detections.post_ingest` (with
    ``native_analysis``: the gateway already ran FHSS, correlation and the
    rf_anomalies upsert).  A detection already claimed — by this or any
    other worker process, within ``_HOOK_SEEN_TTL`` — is skipped, so a
    batch delivered twice fires its alerts once.  Webhooks and syslog for
    the alerts created are delivered in the background (K8b), so the
    answer never waits for a third-party endpoint.  Answers 200 with
    counts; 422 for a malformed body (the gateway drops it); 503 before
    start-up finished (the gateway retries).
    """
    payload = await read_json_body(
        request,
        max_body_bytes=INGEST_HOOK_MAX_BODY,
        max_decompressed_bytes=INGEST_HOOK_MAX_BODY,
    )
    node_id = payload.get("node_id")
    if not valid_node_id(node_id):
        raise _unprocessable("node_id must match [a-zA-Z0-9_-]{1,64}")
    raw_dets = payload.get("detections")
    if not isinstance(raw_dets, list):
        raise _unprocessable("detections must be a list")
    batch_id = payload.get("batch_id")
    batch_id = batch_id[:128] if isinstance(batch_id, str) else ""

    state = request.app.state
    if getattr(state, "persistence", None) is None or (
        getattr(state, "app_state", None) is None
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )

    skipped = max(0, len(raw_dets) - _HOOK_MAX_DETECTIONS)
    if skipped:
        logger.warning(
            "Ingest hook for node %s: %d detections, processing the first %d",
            node_id,
            len(raw_dets),
            _HOOK_MAX_DETECTIONS,
        )
        raw_dets = raw_dets[:_HOOK_MAX_DETECTIONS]
    records, invalid = _parse_hook_detections(node_id, raw_dets)
    if invalid:
        logger.warning(
            "Ingest hook for node %s: %d invalid detections ignored", node_id, invalid
        )

    # Idempotence (K8b): claim each detection in detections.db, which every
    # worker process shares, before any alert stage runs, so a concurrent
    # or repeated delivery of the same batch — to this process or another
    # — finds it taken.  At most once: a detection is not processed again
    # even if this delivery fails.
    claims = get_ingest_claims(state)
    if claims is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )
    claimed = await asyncio.to_thread(
        claims.claim_hook_detections,
        node_id,
        [det.detection_id for det in records],
        now=_clock(),
        ttl=_HOOK_SEEN_TTL,
        max_rows=_HOOK_SEEN_MAX,
    )
    fresh: list[DetectionRecord] = []
    duplicates = 0
    for det in records:
        if det.detection_id not in claimed:
            duplicates += 1
            continue
        claimed.discard(det.detection_id)  # a repeat inside one batch
        fresh.append(det)

    response: dict[str, Any] = {
        "accepted": len(fresh),
        "duplicates": duplicates,
        "invalid": invalid,
        "skipped": skipped,
        "alerts_created": 0,
        "decoded_stored": 0,
        "decode_jobs": 0,
    }
    if not fresh:
        return response

    edge_decoded = _edge_decoded_from_hook(
        payload, only={det.detection_id for det in fresh}
    )
    result = await post_ingest(
        request.app,
        fresh,
        node_id,
        edge_decoded,
        batch_id=batch_id,
        native_analysis=True,
    )
    for key in ("alerts_created", "decoded_stored", "decode_jobs"):
        response[key] = result[key]
    logger.info(
        "Ingest hook for node %s: %d detections, %d duplicates, %d alerts",
        node_id,
        len(fresh),
        duplicates,
        result["alerts_created"],
    )
    return response
