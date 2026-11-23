"""Detection audit, feedback, and anomaly management endpoints for The Bridge.

Provides anomaly listing, dismiss/snooze (single and bulk), baseline operations,
operator feedback, and audit log query endpoints.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.known_signals import authorized_store, detection_target
from sigrift.bridge.storage.known_signals import KnownSignalPattern, matches
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store

logger = logging.getLogger(__name__)

router = APIRouter()

_get_detection_store = get_detection_store


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class FeedbackRequest(BaseModel):
    """Operator feedback on an anomaly detection."""

    model_config = {"extra": "forbid"}

    label: str = Field(
        ...,
        description="One of: true_positive, false_positive, expected, interesting",
    )
    note: str | None = Field(
        default=None,
        description="Optional operator note",
    )


class BulkActionRequest(BaseModel):
    """Bulk dismiss or baseline request (legacy, detection_id strings)."""

    model_config = {"extra": "forbid"}

    detection_ids: list[str] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of detection IDs to act on (max 100)",
    )


class BulkRfDismissRequest(BaseModel):
    """Bulk dismiss RF anomalies by row ID."""

    model_config = {"extra": "forbid"}

    ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of rf_anomalies row IDs to dismiss",
    )


class BulkRfSnoozeRequest(BaseModel):
    """Bulk snooze RF anomalies by row ID."""

    model_config = {"extra": "forbid"}

    ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="List of rf_anomalies row IDs to snooze",
    )
    hours: int = Field(ge=1, le=168, description="Snooze duration in hours")


class BulkRfEscalateRequest(BaseModel):
    """Escalate RF anomalies by row ID: each raises a critical alert."""

    model_config = {"extra": "forbid"}

    ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=100,
        description="List of rf_anomalies row IDs to escalate (max 100)",
    )


class _RfSnoozeBody(BaseModel):
    model_config = {"extra": "forbid"}
    hours: int = Field(ge=1, le=168, description="Snooze duration in hours")


# ---------------------------------------------------------------------------
# GET /anomalies/summary -- aggregate anomaly breakdown
# ---------------------------------------------------------------------------


@router.get("/anomalies/summary")
async def get_anomaly_summary(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Aggregate RF anomaly breakdown by priority, family, band, node.

    Returns counts and unique values for populating filter dropdowns
    and the summary statistics bar.
    """
    store = _get_detection_store(request)
    return await asyncio.to_thread(store.get_rf_anomaly_summary, min_score=min_score)


# ---------------------------------------------------------------------------
# GET /anomalies -- high anomaly score detections
# ---------------------------------------------------------------------------


@router.get("/anomalies")
async def get_anomalies(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=1000),
    node_id: str | None = Query(None),
    reevaluate: bool = Query(
        False, description="Re-evaluate each anomaly against current baselines"
    ),
    family: str | None = Query(None),
    signal_class: str | None = Query(None),
    priority: str | None = Query(None),
    freq_min: float | None = Query(None, ge=0),
    freq_max: float | None = Query(None, ge=0),
    sort: str = Query("score"),
    order: str = Query("desc"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return RF anomalies above threshold from dedicated rf_anomalies table.

    Uses DB-level ``dismissed`` column (no in-memory set). Supports
    BSSID-style dedup by signal_class + freq_bucket with ``seen_count``.

    When *reevaluate=true*, each anomaly is re-scored against current
    RF baselines and an inline ``reeval`` dict is appended.
    """
    # Whitelist sort/order to prevent injection
    if sort not in ("score", "time", "freq", "seen"):
        sort = "score"
    if order not in ("asc", "desc"):
        order = "desc"

    store = _get_detection_store(request)

    results = await asyncio.to_thread(
        store.get_rf_anomalies,
        min_score=min_score,
        limit=limit,
        node_id=node_id,
        family=family,
        signal_class=signal_class,
        priority=priority,
        freq_min_hz=freq_min,
        freq_max_hz=freq_max,
        sort_by=sort,
        sort_order=order,
    )

    total = await asyncio.to_thread(
        store.count_rf_anomalies,
        min_score=min_score,
        node_id=node_id,
        family=family,
        signal_class=signal_class,
        priority=priority,
        freq_min_hz=freq_min,
        freq_max_hz=freq_max,
    )

    # Inline re-evaluation against current baselines
    reeval_summary: dict[str, int] | None = None
    if reevaluate:
        rf_scorer = getattr(request.app.state, "rf_scorer", None)
        signal_whitelist = getattr(request.app.state, "signal_whitelist", None)
        if rf_scorer is not None:
            still_count = 0
            resolved_count = 0
            for anomaly in results:
                try:
                    original_score = anomaly.get("anomaly_score", 0.0) or 0.0
                    new_result = rf_scorer.score(anomaly)
                    new_score = new_result.score
                    if signal_whitelist is not None:
                        new_score = signal_whitelist.apply_reduction(
                            new_score,
                            anomaly.get("freq_hz", 0.0),
                            anomaly.get("signal_class", ""),
                            node_id=anomaly.get("node_id"),
                        )
                    still = new_score >= min_score
                    anomaly["reeval"] = {
                        "still_anomalous": still,
                        "new_score": new_score,
                        "score_delta": round(new_score - original_score, 4),
                        "new_priority": new_result.priority,
                        "new_dimensions": new_result.dimensions,
                        "new_reasons": new_result.reasons,
                        "baseline_status": new_result.baseline_status,
                    }
                    if still:
                        still_count += 1
                    else:
                        resolved_count += 1
                except Exception as exc:
                    logger.warning(
                        "RF reevaluate failed for %s: %s",
                        anomaly.get("detection_id"),
                        exc,
                    )
            reeval_summary = {
                "still_anomalous": still_count,
                "resolved": resolved_count,
            }

    resp: dict[str, Any] = {
        "count": len(results),
        "total": total,
        "min_score": min_score,
        "anomalies": results,
    }
    if reeval_summary is not None:
        resp["reeval_summary"] = reeval_summary
    return resp


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/dismiss -- bulk dismiss anomalies
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/dismiss")
async def bulk_dismiss_anomalies(
    body: BulkRfDismissRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Bulk dismiss RF anomalies by row ID.

    Accepts up to 1000 rf_anomalies row IDs. Uses DB-level dismissed column.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    count = await asyncio.to_thread(store.dismiss_rf_anomalies_bulk, body.ids)

    store.log_audit(
        action="bulk_dismiss_rf",
        target_id=str(body.ids[0]),
        operator=_key_id,
        target_ids=[str(i) for i in body.ids],
    )

    app_state.log_activity(
        event_type="rf_anomaly_bulk_dismissed",
        message=f"Bulk dismissed {count} RF anomalies",
        details={"ids": body.ids[:20]},
    )

    logger.info("Bulk dismissed %d RF anomalies", count)

    return {
        "ok": True,
        "dismissed_count": count,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/snooze -- bulk snooze RF anomalies
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/snooze")
async def bulk_snooze_anomalies(
    body: BulkRfSnoozeRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Bulk snooze RF anomalies for a specified duration.

    Accepts up to 1000 rf_anomalies row IDs. Snoozed anomalies are hidden
    from active queries until the snooze period expires.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    count = await asyncio.to_thread(store.snooze_rf_anomalies_bulk, body.ids, until)

    store.log_audit(
        action="bulk_snooze_rf",
        target_id=str(body.ids[0]),
        operator=_key_id,
        target_ids=[str(i) for i in body.ids],
        note=f"Snoozed for {body.hours}h until {until}",
    )

    app_state.log_activity(
        event_type="rf_anomaly_bulk_snoozed",
        message=f"Bulk snoozed {count} RF anomalies for {body.hours}h",
        details={"ids": body.ids[:20], "snoozed_until": until},
    )

    logger.info("Bulk snoozed %d RF anomalies for %dh", count, body.hours)

    return {
        "ok": True,
        "snoozed_count": count,
        "snoozed_until": until,
    }


# ---------------------------------------------------------------------------
# POST /anomalies/bulk/escalate -- one critical alert naming the RF anomalies
# ---------------------------------------------------------------------------


def _describe_rf_anomaly(row: dict[str, Any]) -> str:
    freq = float(row.get("freq_hz") or 0.0)
    score = float(row.get("anomaly_score") or 0.0)
    return (
        f"{row.get('signal_class') or 'unknown'} score {score:.2f} at "
        f"{freq / 1e6:.2f} MHz on {row.get('node_id') or 'an unknown node'}"
    )


def _rf_escalation_details(
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """The alert's RF fields: a frequency or class only when all share it."""
    from sigrift.bridge.routers.detections import shared_value

    fields: dict[str, Any] = {
        "detection_ids": [row.get("detection_id") or "" for row in rows]
    }
    syslog_fields: dict[str, Any] = {}
    freq = shared_value(rows, "freq_hz")
    if freq is not None:
        fields["freq_hz"] = float(freq)
    signal_class = shared_value(rows, "signal_class")
    if signal_class:
        syslog_fields["signal_class"] = signal_class
    return fields, syslog_fields


@router.post("/anomalies/bulk/escalate")
async def bulk_escalate_anomalies(
    body: BulkRfEscalateRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Escalate RF anomalies: one critical alert names them, none dismissed.

    Accepts up to 100 rf_anomalies row IDs.  The anomalies stay in the
    queue.  Those no unacknowledged ``anomaly_escalated`` alert names yet
    share one new critical ``anomaly_escalated`` alert (stored, sent to the
    live alert feed, webhooks and syslog) whose ``alert_id`` the answer
    gives; the others are listed in ``already_escalated``.  IDs that match
    no anomaly are reported in ``not_found``.
    """
    # Imported here: detections.py imports this module.
    from sigrift.bridge.routers.detections import escalate_anomalies

    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state
    rows = await asyncio.to_thread(store.get_rf_anomalies_by_ids, body.ids)
    result = await escalate_anomalies(
        request,
        rows={row["id"]: row for row in rows},
        ids=body.ids,
        alert_name="anomaly_escalated",
        kind="RF",
        describe=_describe_rf_anomaly,
        details=_rf_escalation_details,
        operator=_key_id,
    )

    escalated = [str(anomaly_id) for anomaly_id in result["escalated"]]
    if escalated:
        store.log_audit(
            action="bulk_escalate_rf",
            target_id=escalated[0],
            operator=_key_id,
            target_ids=escalated,
            note=(
                f"Raised critical alert {result['alert_id']} for "
                f"{len(escalated)} RF anomalies"
            ),
        )
        app_state.log_activity(
            event_type="rf_anomaly_bulk_escalated",
            message=f"Escalated {len(escalated)} RF anomalies",
            details={
                "ids": result["escalated"][:20],
                "alert_id": result["alert_id"],
            },
        )
        logger.info("Escalated %d RF anomalies", len(escalated))
    return result


# ---------------------------------------------------------------------------
# POST /anomalies/bulk/reeval-dismiss -- server-side purge of resolved RF anomalies
# ---------------------------------------------------------------------------


@router.post("/anomalies/bulk/reeval-dismiss")
async def reeval_and_dismiss_all_rf(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Re-evaluate all active RF anomalies and auto-dismiss resolved ones.

    Processes the entire queue server-side (up to 100k), re-scores each
    against current baselines, and bulk-dismisses any that no longer meet
    the anomaly threshold.
    """
    store = _get_detection_store(request)
    rf_scorer = getattr(request.app.state, "rf_scorer", None)
    if rf_scorer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="RF scorer not initialised",
        )

    all_anomalies = await asyncio.to_thread(
        store.get_rf_anomalies,
        min_score=min_score,
        limit=100_000,
    )

    resolved_ids: list[int] = []
    still_count = 0
    errors = 0

    for anomaly in all_anomalies:
        try:
            result = rf_scorer.score(anomaly)
            if result.score < min_score:
                aid = anomaly.get("id")
                if aid is not None:
                    resolved_ids.append(aid)
            else:
                still_count += 1
        except Exception:
            errors += 1

    dismissed_count = 0
    for i in range(0, len(resolved_ids), 500):
        batch = resolved_ids[i : i + 500]
        dismissed_count += await asyncio.to_thread(
            store.dismiss_rf_anomalies_bulk,
            batch,
        )

    new_total = await asyncio.to_thread(
        store.count_rf_anomalies,
        min_score=min_score,
    )

    logger.info(
        "RF reeval-dismiss: %d processed, %d still anomalous, %d dismissed, %d errors",
        len(all_anomalies),
        still_count,
        dismissed_count,
        errors,
    )

    return {
        "ok": True,
        "processed": len(all_anomalies),
        "still_anomalous": still_count,
        "dismissed": dismissed_count,
        "errors": errors,
        "remaining_total": new_total,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/baseline -- bulk baseline anomalies
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/baseline")
def bulk_baseline_anomalies(
    body: BulkActionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Atomically save default node-scoped patterns for all supplied RF detections.

    An unknown or unusable detection refuses the entire batch. No records are
    dismissed, rescored, or deleted. Identical retries return the same patterns.
    Plain ``def`` (threadpool): the per-detection reads and the IMMEDIATE write
    transaction, which can wait up to the busy timeout, must not run on the
    event loop.
    """
    store = authorized_store(request, _key_id)
    items = [
        (det_id, KnownSignalPattern(**detection_target(store, det_id)["defaults"]))
        for det_id in dict.fromkeys(body.detection_ids)
    ]
    patterns = _save_patterns(store, items, _key_id)
    return {
        "baselined": True,
        "count": len(patterns),
        "patterns": patterns,
        "effect": "suppress_matching_rf_alerts",
    }


# ---------------------------------------------------------------------------
# GET /anomalies/audit -- audit log query
# ---------------------------------------------------------------------------


@router.get("/anomalies/audit")
async def get_audit_log(
    request: Request,
    limit: int = Query(200, ge=1, le=1000),
    action: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return audit log entries for anomaly operations."""
    store = _get_detection_store(request)
    entries = await asyncio.to_thread(store.get_audit_log, limit=limit, action=action)
    return {
        "count": len(entries),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/{anomaly_id}/dismiss -- dismiss an anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/dismiss")
async def dismiss_anomaly(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Mark an RF anomaly as dismissed using its rf_anomalies row ID.

    Uses DB-level ``dismissed`` column in rf_anomalies table.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    await asyncio.to_thread(store.dismiss_rf_anomaly, anomaly_id)

    store.log_audit(
        action="dismiss_rf",
        target_id=str(anomaly_id),
        operator=_key_id,
    )

    app_state.log_activity(
        event_type="rf_anomaly_dismissed",
        message=f"RF anomaly {anomaly_id} dismissed",
        details={"anomaly_id": anomaly_id},
    )

    logger.info("RF anomaly dismissed: %d", anomaly_id)

    return {
        "ok": True,
        "dismissed_id": anomaly_id,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/{anomaly_id}/snooze -- snooze single RF anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/snooze")
async def snooze_anomaly(
    anomaly_id: int,
    body: _RfSnoozeBody,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Snooze an RF anomaly for a specified duration.

    The anomaly will be hidden from active queries until the snooze
    period expires, then automatically reappear.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    await asyncio.to_thread(store.snooze_rf_anomaly, anomaly_id, until)

    store.log_audit(
        action="snooze_rf",
        target_id=str(anomaly_id),
        operator=_key_id,
        note=f"Snoozed for {body.hours}h until {until}",
    )

    app_state.log_activity(
        event_type="rf_anomaly_snoozed",
        message=f"RF anomaly {anomaly_id} snoozed for {body.hours}h",
        details={"anomaly_id": anomaly_id, "snoozed_until": until},
    )

    logger.info("RF anomaly snoozed: %d for %dh", anomaly_id, body.hours)

    return {
        "ok": True,
        "snoozed_id": anomaly_id,
        "snoozed_until": until,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/{detection_id}/baseline -- add to baseline/whitelist
# ---------------------------------------------------------------------------


def _save_patterns(store, items, operator):
    try:
        return store.known_signals.create_many(items, operator)
    except sqlite3.Error as exc:
        logger.warning("Known RF pattern save failed: %s", type(exc).__name__)
        raise HTTPException(
            503, "Could not save the known RF pattern. Nothing was changed; retry."
        ) from exc


@router.get("/known-signals")
def list_known_signals(
    request: Request, _key_id: str = Depends(require_role(Role.VIEWER))
):
    store = authorized_store(request, _key_id)
    return {
        "patterns": store.known_signals.list(),
        "can_manage": getattr(request.state, "key_role", Role.VIEWER) >= Role.ANALYST,
        "effect": "suppress_matching_rf_alerts",
    }


class KnownSignalCreate(KnownSignalPattern):
    # Require an explicit node or null (all nodes); omission must not silently
    # broaden a new operator rule across receivers.
    node_id: str | None = Field(..., min_length=1, max_length=128)


@router.post("/known-signals", status_code=201)
def create_known_signal(
    body: KnownSignalCreate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
):
    """Save an operator-reviewed range without requiring an existing alert."""
    store = authorized_store(request, _key_id)
    try:
        return store.known_signals.create(
            KnownSignalPattern(**body.model_dump()), _key_id
        )
    except sqlite3.Error as exc:
        raise HTTPException(
            503, "Could not save the known RF pattern. Nothing was changed; retry."
        ) from exc


class KnownSignalUpdate(KnownSignalPattern):
    revision: int = Field(ge=1)


@router.put("/known-signals/{pattern_id}")
def update_known_signal(
    pattern_id: str,
    body: KnownSignalUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
):
    store = authorized_store(request, _key_id)
    pattern = KnownSignalPattern(**body.model_dump(exclude={"revision"}))
    try:
        return store.known_signals.update(pattern_id, pattern, body.revision, _key_id)
    except KeyError as exc:
        raise HTTPException(404, "Known RF pattern not found") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except sqlite3.Error as exc:
        if getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_CONSTRAINT_UNIQUE:
            raise HTTPException(
                409, "That matching pattern already exists; refresh the list."
            ) from exc
        raise HTTPException(
            503, "Could not save the pattern. Nothing was changed; retry."
        ) from exc


@router.delete("/known-signals/{pattern_id}")
def remove_known_signal(
    pattern_id: str,
    request: Request,
    revision: int = Query(ge=1),
    _key_id: str = Depends(require_role(Role.ANALYST)),
):
    try:
        removed = authorized_store(request, _key_id).known_signals.remove(
            pattern_id, revision, _key_id
        )
    except KeyError as exc:
        raise HTTPException(404, "Known RF pattern not found") from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except sqlite3.Error as exc:
        raise HTTPException(
            503, "Could not remove the pattern. Nothing was changed; retry."
        ) from exc
    return {"removed": True, "pattern": removed}


@router.get("/anomalies/{detection_id}/baseline")
def preview_baseline(
    detection_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
):
    store = authorized_store(request, _key_id)
    target = detection_target(store, detection_id)
    detection = {
        "freq_hz": target["freq_hz"],
        **{key: target["defaults"][key] for key in ("signal_class", "node_id")},
    }
    return {
        **target,
        "matching_patterns": [
            p for p in store.known_signals.list() if matches(p, detection)
        ],
        "can_manage": getattr(request.state, "key_role", Role.VIEWER) >= Role.ANALYST,
    }


@router.put("/anomalies/{detection_id}/baseline")
def add_to_baseline(
    detection_id: str,
    request: Request,
    body: KnownSignalPattern | None = Body(default=None),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Save a known RF pattern durably, without changing scores or history."""
    store = authorized_store(request, _key_id)
    target = detection_target(store, detection_id)
    pattern = body or KnownSignalPattern(**target["defaults"])
    detection = {
        "freq_hz": target["freq_hz"],
        **{key: target["defaults"][key] for key in ("signal_class", "node_id")},
    }
    if not matches(pattern.model_dump(), detection):
        raise HTTPException(
            422,
            "The reviewed pattern must match this detection's class, frequency and node.",
        )
    saved = _save_patterns(store, [(detection_id, pattern)], _key_id)[0]
    request.app.state.app_state.log_activity(
        event_type="anomaly_baselined",
        message="Known RF pattern saved; matching alerts suppressed",
        details={"detection_id": detection_id, "pattern_id": saved["pattern_id"]},
    )
    return {
        "baselined": True,
        "detection_id": detection_id,
        "pattern": saved,
        "effect": "suppress_matching_rf_alerts",
        "freq_mhz": target["freq_hz"] / 1e6,
        "signal_class": pattern.signal_class,
    }


# ---------------------------------------------------------------------------
# POST /anomalies/{detection_id}/feedback -- operator feedback
# ---------------------------------------------------------------------------


@router.post("/anomalies/{detection_id}/feedback")
def submit_feedback(
    detection_id: str,
    body: FeedbackRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Submit operator feedback on an anomaly detection.

    Labels:
      - true_positive: confirmed real anomaly
      - false_positive: not actually anomalous
      - expected: known/expected signal
      - interesting: worth further investigation

    If false_positive or expected, the detection is automatically
    added to the whitelist/dismissed set for future filtering.
    """
    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    # Validate label
    allowed_labels = {"true_positive", "false_positive", "expected", "interesting"}
    if body.label not in allowed_labels:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"label must be one of {sorted(allowed_labels)}",
        )

    # Store feedback
    feedback = store.add_feedback(
        detection_id=detection_id,
        label=body.label,
        note=body.note or "",
    )

    # Auto-dismiss if false positive or expected
    if body.label in ("false_positive", "expected"):
        if not hasattr(app_state, "dismissed_anomalies"):
            app_state.dismissed_anomalies = set()
        app_state.dismissed_anomalies.add(detection_id)

    # Retrieve the detection record for the response
    detection = store.get_detection_by_id(detection_id)

    # Feed feedback to score calibrator for Platt scaling
    score_calibrator = getattr(request.app.state, "score_calibrator", None)
    if score_calibrator is not None and detection is not None:
        is_anomaly = body.label in ("true_positive", "interesting")
        score_calibrator.add_feedback(
            score=detection.get("anomaly_score", 0.0),
            is_anomaly=is_anomaly,
            freq_hz=detection.get("freq_hz", 0.0),
        )
        band = score_calibrator.get_band(detection.get("freq_hz", 0.0))
        score_calibrator.fit_band(band)

    # Persistent audit log
    store.log_audit(
        action="feedback",
        target_id=detection_id,
        signal_class=detection.get("signal_class", "") if detection else "",
        freq_hz=detection.get("freq_hz", 0.0) if detection else 0.0,
        node_id=detection.get("node_id", "") if detection else "",
        operator=_key_id,
        note=body.note or "",
        details={"label": body.label},
    )

    app_state.log_activity(
        event_type="anomaly_feedback",
        message=f"Feedback on {detection_id}: {body.label}",
        details={
            "detection_id": detection_id,
            "label": body.label,
            "note": body.note or "",
        },
    )

    logger.info("Feedback on %s: %s", detection_id, body.label)

    return {
        "detection_id": detection_id,
        "label": body.label,
        "note": body.note or "",
        "auto_dismissed": body.label in ("false_positive", "expected"),
        "detection": detection,
        "feedback": feedback,
    }
