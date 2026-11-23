"""Alert system endpoints and WebSocket stream for The Bridge.

Provides CRUD for alert rules, acknowledgement, history browsing,
and a real-time WebSocket stream that pushes new alerts to connected
clients.

Includes condition-based alert rule endpoints that support multi-condition
rules with AND logic, cooldown tracking, and dry-run testing.

Adapted from sigrift.lib.shiny.routers.alerts for The Bridge.
"""

from __future__ import annotations

import asyncio
import html
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge.alert_analysis import (
    MAX_ACK_IDS_RETURNED,
    RFTargets,
    analyse,
    covered_open_alerts,
)
from sigrift.bridge.known_signals import alert_detection_id, authorized_store
from sigrift.bridge.storage.known_signals import KnownSignalPattern
from sigrift.bridge.alert_engine import evaluate_rule
from sigrift.bridge.dependencies import (
    Role,
    get_ws_limiter,
    require_master_key,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.models import (
    AlertCreate,
    AlertResponse,
    AlertRuleCreate,
    AlertRuleResponse,
    AlertRuleTestRequest,
    AlertRuleUpdate,
    AlertSeverity,
)
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import utcnow

logger = logging.getLogger(__name__)
router = APIRouter()

_utcnow = utcnow


def _to_response(a: dict[str, Any]) -> AlertResponse:
    """Convert a raw alert dict to an AlertResponse model."""
    raw_sev = a.get("severity", "warning")
    if isinstance(raw_sev, str):
        raw_sev = raw_sev.lower()
    return AlertResponse(
        alert_id=a.get("alert_id", ""),
        name=a.get("name", ""),
        severity=raw_sev,
        message=a.get("message", ""),
        node_id=a.get("node_id"),
        triggered_at=a.get("triggered_at", _utcnow().isoformat()),
        acknowledged=a.get("acknowledged", False),
        acknowledged_at=a.get("acknowledged_at"),
        acknowledged_by=a.get("acknowledged_by"),
        ack_note=a.get("ack_note"),
        escalated=a.get("escalated", False),
    )


def _to_rule_response(r: dict[str, Any]) -> AlertRuleResponse:
    """Convert a raw rule dict to an AlertRuleResponse model."""
    return AlertRuleResponse(
        rule_id=r.get("rule_id", ""),
        name=r.get("name", ""),
        severity=r.get("severity", "warning"),
        conditions=r.get("conditions", []),
        logic=r.get("logic", "AND"),
        enabled=r.get("enabled", True),
        cooldown_seconds=r.get("cooldown_seconds", 300),
        notify_webhook=r.get("notify_webhook", True),
        created_at=r.get("created_at", ""),
        last_triggered_at=r.get("last_triggered_at"),
        trigger_count=r.get("trigger_count", 0),
    )


def _parse_ts(value: Any) -> datetime:
    """Parse an ISO timestamp string, returning epoch on failure."""
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


class AlertWithBaselineResponse(AlertResponse):
    """A linked RF detection is the only eligible baseline entry point."""

    rf_detection_id: str | None = None


# -- GET / -- list alerts ---------------------------------------------------


@router.get("/")
async def list_alerts(
    request: Request,
    severity: AlertSeverity | None = None,
    node_id: str | None = None,
    acknowledged: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[AlertWithBaselineResponse]:
    """List alerts with optional filters."""
    persistence: PersistenceManager = request.app.state.persistence
    alerts = persistence.get_alerts()

    if severity is not None:
        alerts = [a for a in alerts if a.get("severity") == severity.value]
    if node_id is not None:
        safe_node = html.escape(node_id)
        alerts = [a for a in alerts if a.get("node_id") == safe_node]
    if acknowledged is not None:
        alerts = [a for a in alerts if a.get("acknowledged") is acknowledged]

    try:
        store = authorized_store(request, _key_id)
    except HTTPException:
        # Preserve the existing alert list while withholding an ineligible RF link.
        store = None
    return [
        AlertWithBaselineResponse(
            **_to_response(a).model_dump(), rf_detection_id=alert_detection_id(a, store)
        )
        for a in alerts[-limit:]
    ]


# -- GET /analysis -- most common alert types and RF frequencies --------------


@router.get("/analysis")
def alert_analysis(
    request: Request,
    hours: int | None = Query(24, ge=1, le=24 * 365),
    include_acknowledged: bool = False,
    limit: int = Query(10, ge=1, le=50),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Group retained alerts by type and by RF frequency, most frequent first.

    Plain ``def``: the per-detection SQLite lookups run in the threadpool,
    not on the event loop. ``hours`` bounds the window by trigger time; pass
    a large value to cover every retained alert.
    """
    persistence: PersistenceManager = request.app.state.persistence
    try:
        store = authorized_store(request, _key_id)
    except HTTPException:
        # Types still list; RF grouping and suggestions need the tenant store.
        store = None
    patterns = store.known_signals.list() if store is not None else []
    result = analyse(
        persistence.get_alerts(),
        RFTargets(store),
        patterns,
        hours=hours,
        include_acknowledged=include_acknowledged,
        limit=limit,
    )
    result["can_manage"] = (
        store is not None
        and getattr(request.state, "key_role", Role.VIEWER) >= Role.ANALYST
    )
    return result


class KnownFromAnalysis(KnownSignalPattern):
    # As for direct known-signal creation: an explicit node or null (all
    # nodes) is required, so omission never silently broadens the scope.
    node_id: str | None = Field(..., min_length=1, max_length=128)
    acknowledge_covered: bool = True


@router.post("/analysis/known")
def mark_known_from_analysis(
    request: Request,
    body: KnownFromAnalysis,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Save a known RF pattern, then optionally acknowledge the open alerts it covers.

    The pattern save is idempotent (an identical pattern is returned as is).
    Acknowledgement happens only after the pattern is saved, and only for
    unacknowledged RF alerts whose linked detection the saved pattern matches.
    """
    store = authorized_store(request, _key_id)
    pattern = KnownSignalPattern(**body.model_dump(exclude={"acknowledge_covered"}))
    try:
        saved = store.known_signals.create(pattern, _key_id)
    except sqlite3.Error as exc:
        logger.warning("Known RF pattern save failed: %s", type(exc).__name__)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Could not save the known RF pattern. Nothing was changed; retry.",
        ) from exc

    persistence: PersistenceManager = request.app.state.persistence
    acknowledged: list[str] = []
    if body.acknowledge_covered:
        now = _utcnow().isoformat()
        note = html.escape(f"Covered by known RF pattern {saved['pattern_id']}")
        for alert_id in covered_open_alerts(
            persistence.get_alerts(), RFTargets(store), saved
        ):
            result = persistence.update_alert(
                alert_id,
                {
                    "acknowledged": True,
                    "acknowledged_at": now,
                    "acknowledged_by": _key_id,
                    "ack_note": note,
                },
            )
            if result is not None:
                acknowledged.append(alert_id)

    app_state: AppState = request.app.state.app_state
    app_state.log_activity(
        "known_pattern_from_alert_analysis",
        message=(
            f"Known RF pattern {saved['pattern_id']} saved from alert analysis; "
            f"{len(acknowledged)} covered open alert(s) acknowledged by {_key_id}"
        ),
    )
    return {
        "pattern": saved,
        "effect": "suppress_matching_rf_alerts",
        "acknowledged_count": len(acknowledged),
        "acknowledged_alert_ids": acknowledged[:MAX_ACK_IDS_RETURNED],
    }


# -- POST /rules -- create alert rule (legacy, threshold-based) ---------------


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    request: Request,
    body: AlertCreate,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertResponse:
    """Create a new alert rule and persist it (legacy threshold-based)."""
    persistence: PersistenceManager = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    alert_id = app_state.next_alert_id()
    now = _utcnow()
    safe_name = html.escape(body.name)
    safe_node = html.escape(body.node_id) if body.node_id else None

    alert_dict: dict[str, Any] = {
        "alert_id": alert_id,
        "name": safe_name,
        "severity": body.severity.value,
        "message": html.escape(f"Alert rule '{body.name}' created"),
        "node_id": safe_node,
        "triggered_at": now.isoformat(),
        "acknowledged": False,
        "acknowledged_at": None,
        "thresholds": body.thresholds.model_dump(),
        "is_rule": True,
    }

    persistence.add_alert(alert_dict)
    app_state.log_activity(
        "alert_rule_created",
        node_id=safe_node,
        message=f"Alert rule '{safe_name}' created",
    )
    await _broadcast_alert(app_state, alert_dict)

    return AlertResponse(
        alert_id=alert_id,
        name=safe_name,
        severity=body.severity,
        message=alert_dict["message"],
        node_id=safe_node,
        triggered_at=now,
        acknowledged=False,
        acknowledged_at=None,
    )


# -- PUT /{alert_id}/ack -- acknowledge alert --------------------------------


class AckBody(BaseModel):
    note: str = ""
    escalated: bool = False


@router.put("/{alert_id}/ack")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    body: AckBody | None = None,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertResponse:
    """Acknowledge an alert by its ID."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(alert_id)
    ack_body = body or AckBody()

    now = _utcnow()
    changes: dict[str, Any] = {
        "acknowledged": True,
        "acknowledged_at": now.isoformat(),
        "acknowledged_by": _key_id,
    }
    if ack_body.note:
        changes["ack_note"] = html.escape(ack_body.note[:500])
    if ack_body.escalated:
        changes["escalated"] = True
    result = persistence.update_alert(safe_id, changes)
    if result is not None:
        alert, _changes = result
        app_state: AppState = request.app.state.app_state
        app_state.log_activity(
            "alert_acknowledged",
            node_id=alert.get("node_id"),
            message=f"Alert {safe_id} acknowledged by {_key_id}",
        )
        return _to_response(alert)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {safe_id} not found"
    )


# -- DELETE /rules/{rule_id} -- delete alert rule (legacy, master key) -------


@router.delete("/rules/{rule_id}", status_code=status.HTTP_200_OK)
async def delete_alert_rule(
    rule_id: str,
    request: Request,
    _key_id: str = Depends(require_master_key),
) -> dict[str, str]:
    """Delete an alert rule. Requires master key.

    Checks both the legacy alerts list and the new condition-based rules.
    """
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)
    app_state: AppState = request.app.state.app_state

    if persistence.delete_alert(safe_id):
        app_state.log_activity(
            "alert_rule_deleted", message=f"Alert rule {safe_id} deleted"
        )
        return {"status": "ok", "deleted": safe_id}

    if persistence.delete_alert_rule(safe_id):
        app_state.log_activity(
            "condition_rule_deleted", message=f"Condition rule {safe_id} deleted"
        )
        return {"status": "ok", "deleted": safe_id}

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert rule {safe_id} not found"
    )


# -- GET /history -- full alert history with optional date range -------------


@router.get("/history")
async def alert_history(
    request: Request,
    start: str | None = Query(None, description="ISO 8601 start datetime"),
    end: str | None = Query(None, description="ISO 8601 end datetime"),
    limit: int = Query(200, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[AlertResponse]:
    """Return full alert history with optional date range filter."""
    persistence: PersistenceManager = request.app.state.persistence
    alerts = persistence.get_alerts()

    if start is not None:
        try:
            start_dt = datetime.fromisoformat(start)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid start datetime (use ISO 8601)",
            )
        alerts = [a for a in alerts if _parse_ts(a.get("triggered_at")) >= start_dt]

    if end is not None:
        try:
            end_dt = datetime.fromisoformat(end)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid end datetime (use ISO 8601)",
            )
        alerts = [a for a in alerts if _parse_ts(a.get("triggered_at")) <= end_dt]

    return [_to_response(a) for a in alerts[-limit:]]


# ===========================================================================
# Condition-based alert rule CRUD
# ===========================================================================


@router.post("/rules/conditions", status_code=status.HTTP_201_CREATED)
async def create_condition_rule(
    request: Request,
    body: AlertRuleCreate,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertRuleResponse:
    """Create a condition-based alert rule."""
    persistence: PersistenceManager = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    rule_id = f"rule_{uuid.uuid4().hex[:12]}"
    now = _utcnow()

    rule_dict: dict[str, Any] = {
        "rule_id": rule_id,
        "name": html.escape(body.name),
        "severity": body.severity,
        "conditions": [c.model_dump() for c in body.conditions],
        "logic": body.logic,
        "enabled": body.enabled,
        "cooldown_seconds": body.cooldown_seconds,
        "notify_webhook": body.notify_webhook,
        "created_at": now.isoformat(),
        "last_triggered_at": None,
        "trigger_count": 0,
    }

    persistence.add_alert_rule(rule_dict)
    app_state.log_activity(
        "condition_rule_created",
        message=f"Condition rule '{body.name}' created with {len(body.conditions)} conditions",
    )

    return _to_rule_response(rule_dict)


@router.get("/rules/conditions")
async def list_condition_rules(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[AlertRuleResponse]:
    """List all condition-based alert rules."""
    persistence: PersistenceManager = request.app.state.persistence
    rules = persistence.get_alert_rules()
    return [_to_rule_response(r) for r in rules]


@router.get("/rules/conditions/{rule_id}")
async def get_condition_rule(
    rule_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> AlertRuleResponse:
    """Get a single condition-based alert rule."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)

    for rule in persistence.get_alert_rules():
        if rule.get("rule_id") == safe_id:
            return _to_rule_response(rule)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {safe_id} not found"
    )


@router.put("/rules/conditions/{rule_id}")
async def update_condition_rule(
    rule_id: str,
    body: AlertRuleUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertRuleResponse:
    """Update a condition-based alert rule."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)

    changes = body.model_dump(exclude_none=True)
    if "name" in changes:
        changes["name"] = html.escape(changes["name"])
    rule = persistence.update_alert_rule(safe_id, changes)
    if rule is not None:
        app_state: AppState = request.app.state.app_state
        app_state.log_activity(
            "condition_rule_updated",
            message=f"Condition rule {safe_id} updated",
        )
        return _to_rule_response(rule)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {safe_id} not found"
    )


@router.delete("/rules/conditions/{rule_id}")
async def delete_condition_rule(
    rule_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, str]:
    """Delete a condition-based alert rule."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)

    if persistence.delete_alert_rule(safe_id):
        app_state: AppState = request.app.state.app_state
        app_state.log_activity(
            "condition_rule_deleted", message=f"Condition rule {safe_id} deleted"
        )
        return {"status": "ok", "deleted": safe_id}

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {safe_id} not found"
    )


@router.post("/rules/conditions/{rule_id}/test")
async def test_condition_rule(
    rule_id: str,
    request: Request,
    body: AlertRuleTestRequest | None = None,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Dry-run test: evaluate a rule against recent detections.

    Returns the list of detections that would have triggered the rule,
    without actually creating alerts or firing webhooks.
    """
    from sigrift.bridge.utils import get_detection_store

    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)
    store = get_detection_store(request)

    # Find the rule
    target_rule = None
    for rule in persistence.get_alert_rules():
        if rule.get("rule_id") == safe_id:
            target_rule = rule
            break

    if target_rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule {safe_id} not found"
        )

    minutes = 60
    limit = 1000
    if body is not None:
        minutes = body.minutes
        limit = body.limit

    # Fetch recent detections
    recent = await asyncio.to_thread(
        store.get_recent,
        minutes=minutes,
        limit=limit,
    )

    # Evaluate each detection against the rule (ignoring cooldown)
    matches: list[dict[str, Any]] = []
    # Temporarily force enabled for testing
    test_rule = dict(target_rule)
    test_rule["enabled"] = True

    for det in recent:
        det_dict = det if isinstance(det, dict) else det.__dict__
        if evaluate_rule(det_dict, test_rule):
            matches.append(det_dict)

    return {
        "rule_id": safe_id,
        "rule_name": target_rule.get("name", ""),
        "detections_scanned": len(recent),
        "matches": len(matches),
        "sample_matches": matches[:50],  # Return at most 50 examples
    }


# -- WebSocket /ws/alerts -- real-time alert stream --------------------------


@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket) -> None:
    """Stream new alerts over WebSocket."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_alert_clients.add(websocket)
    logger.info("Alert WS client connected: %s", key_id)
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await app_state.ws_alert_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Alert WS client disconnected: %s", key_id)


# -- Broadcast helper -------------------------------------------------------


async def _broadcast_alert(app_state: AppState, alert: dict[str, Any]) -> None:
    """Push an alert to all connected WebSocket alert clients."""
    await app_state.ws_alert_clients.broadcast(alert)
