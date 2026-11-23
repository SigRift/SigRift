"""Alert system endpoints and WebSocket stream.

Provides CRUD for alert rules, acknowledgement, history browsing,
and a real-time WebSocket stream that pushes new alerts to connected
clients.

Any valid key reads alerts and their history.  Creating an alert rule and
acknowledging an alert need an ``analyst`` key (an ``admin`` key or the
master key is one), as on the bridge; deleting a rule needs the master key.
A ``viewer`` key -- the default, and every key stored before roles
existed -- gets 403 for them.
"""

from __future__ import annotations

import html
import logging
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

from sigrift.lib.shiny.dependencies import (
    Role,
    rate_limit,
    require_master_key,
    require_role,
    accept_ws,
    require_ws_auth,
)
from sigrift.lib.shiny.models import AlertCreate, AlertResponse, AlertSeverity
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.state import AppState

logger = logging.getLogger(__name__)
router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_response(a: dict[str, Any]) -> AlertResponse:
    """Convert a raw alert dict to an AlertResponse model."""
    return AlertResponse(
        alert_id=a.get("alert_id", ""),
        name=a.get("name", ""),
        severity=a.get("severity", AlertSeverity.warning),
        message=a.get("message", ""),
        node_id=a.get("node_id"),
        triggered_at=a.get("triggered_at", _utcnow().isoformat()),
        acknowledged=a.get("acknowledged", False),
        acknowledged_at=a.get("acknowledged_at"),
    )


def _as_utc(dt: datetime) -> datetime:
    """*dt* with a UTC offset: a value without one is read as UTC."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_ts(value: Any) -> datetime:
    """Parse a stored ISO timestamp (UTC-aware), returning epoch on failure."""
    if isinstance(value, datetime):
        return _as_utc(value)
    if isinstance(value, str):
        try:
            return _as_utc(datetime.fromisoformat(value))
        except ValueError:
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _parse_bound(value: str, label: str) -> datetime:
    """A history range bound (UTC-aware); 400 if it is not ISO 8601.

    A bound without a UTC offset (``2026-03-01``) is read as UTC, as
    ``/api/export/alerts`` reads its date bounds.
    """
    try:
        return _as_utc(datetime.fromisoformat(value))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid {label} datetime (use ISO 8601)",
        ) from None


# -- GET / — list alerts ----------------------------------------------------


@router.get("/")
async def list_alerts(
    request: Request,
    severity: AlertSeverity | None = None,
    node_id: str | None = None,
    acknowledged: bool | None = None,
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(rate_limit),
) -> list[AlertResponse]:
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

    return [_to_response(a) for a in alerts[-limit:]]


# -- POST /rules — create alert rule ---------------------------------------


@router.post("/rules", status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    request: Request,
    body: AlertCreate,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertResponse:
    """Create a new alert rule and persist it. Requires an analyst key."""
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


# -- PUT /{alert_id}/ack — acknowledge alert --------------------------------


@router.put("/{alert_id}/ack")
async def acknowledge_alert(
    alert_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> AlertResponse:
    """Acknowledge an alert by its ID. Requires an analyst key."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(alert_id)

    if not persistence.acknowledge_alert(safe_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Alert {safe_id} not found"
        )

    # Re-read the acknowledged alert for the response
    now = _utcnow()
    alert: dict[str, Any] = {}
    for a in persistence.get_alerts():
        if a.get("alert_id") == safe_id:
            alert = a
            break

    app_state: AppState = request.app.state.app_state
    app_state.log_activity(
        "alert_acknowledged",
        node_id=alert.get("node_id"),
        message=f"Alert {safe_id} acknowledged",
    )
    return AlertResponse(
        alert_id=safe_id,
        name=alert.get("name", ""),
        severity=alert.get("severity", AlertSeverity.warning),
        message=alert.get("message", ""),
        node_id=alert.get("node_id"),
        triggered_at=alert.get("triggered_at", now.isoformat()),
        acknowledged=True,
        acknowledged_at=alert.get("acknowledged_at", now),
    )


# -- DELETE /rules/{rule_id} — delete alert rule (master key) ---------------


@router.delete("/rules/{rule_id}", status_code=status.HTTP_200_OK)
async def delete_alert_rule(
    rule_id: str,
    request: Request,
    _key_id: str = Depends(require_master_key),
) -> dict[str, str]:
    """Delete an alert rule. Requires master key."""
    persistence: PersistenceManager = request.app.state.persistence
    safe_id = html.escape(rule_id)

    if not persistence.remove_alert(safe_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert rule {safe_id} not found",
        )

    app_state: AppState = request.app.state.app_state
    app_state.log_activity(
        "alert_rule_deleted", message=f"Alert rule {safe_id} deleted"
    )
    return {"status": "ok", "deleted": safe_id}


# -- GET /history — full alert history with optional date range -------------


@router.get("/history")
async def alert_history(
    request: Request,
    start: str | None = Query(None, description="ISO 8601 start datetime"),
    end: str | None = Query(None, description="ISO 8601 end datetime"),
    limit: int = Query(200, ge=1, le=500),
    _key_id: str = Depends(rate_limit),
) -> list[AlertResponse]:
    """Return full alert history with optional date range filter.

    Bounds and stored timestamps without a UTC offset are read as UTC.
    """
    persistence: PersistenceManager = request.app.state.persistence
    alerts = persistence.get_alerts()

    if start is not None:
        start_dt = _parse_bound(start, "start")
        alerts = [a for a in alerts if _parse_ts(a.get("triggered_at")) >= start_dt]

    if end is not None:
        end_dt = _parse_bound(end, "end")
        alerts = [a for a in alerts if _parse_ts(a.get("triggered_at")) <= end_dt]

    return [_to_response(a) for a in alerts[-limit:]]


# -- WebSocket /ws/alerts — real-time alert stream --------------------------


@router.websocket("/ws/alerts")
async def ws_alerts(
    websocket: WebSocket,
    key_id: str = Depends(require_ws_auth),
) -> None:
    """Stream new alerts over WebSocket.

    Auth is validated BEFORE accept (SigRift fix for gen2 bug).
    """
    await accept_ws(websocket)
    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_alert_clients.add(websocket)
    logger.info("Alert WS client connected: %s", key_id)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        await app_state.ws_alert_clients.remove(websocket)
        logger.info("Alert WS client disconnected: %s", key_id)


# -- Broadcast helper -------------------------------------------------------


async def _broadcast_alert(app_state: AppState, alert: dict[str, Any]) -> None:
    """Push an alert to all connected WebSocket alert clients."""
    await app_state.ws_alert_clients.broadcast(alert)
