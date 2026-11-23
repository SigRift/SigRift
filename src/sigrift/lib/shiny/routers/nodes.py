"""Node management endpoints and WebSocket status stream.

Provides CRUD for edge nodes, heartbeat processing, command queuing,
activity log retrieval, and a real-time WebSocket status stream.

Registering a node and queueing node commands need an ``admin`` key (the
``master`` key is one); removing a node needs the master key.

Node heartbeats (which hand out the node's queued commands and overwrite its
metrics) are accepted from an admin key, or from a key bound to that node:

* A key with a ``node_id`` (created with one, or bound later with
  ``PATCH /api/keys/{key_id}``) is bound to that node and can heartbeat
  only as that node.
* An unbound ``node`` key (``purpose: "node"``) is bound to the node it
  first heartbeats for ("trust on first use"), unless another key is
  already bound to that node: then it is refused with 403, the node's
  queued commands stay queued and its metrics are untouched.
* Every other unbound key is refused with 403 and never bound: ``dashboard``
  keys (the default for a key created without ``node_id``), ``analyst``
  keys, and keys from before key purposes existed (no ``purpose`` stored).
  Such an old key cannot be told apart from a dashboard viewer key, so
  binding it on first use would let any dashboard user claim a node that
  has not heartbeated yet, take its commands and lock the real node out.
  Bind each old node key to its node with ``PATCH /api/keys/{key_id}``
  ``{"node_id": "<node>"}`` (master key; the startup warning lists the
  keys), or set ``SHINY_LEGACY_KEY_TOFU`` for the migration (see
  :func:`legacy_key_tofu`): old keys then claim nodes on first use again,
  and each such claim is logged as a warning.

``PATCH /api/keys/{key_id}`` with ``{"node_id": null}`` unbinds a key, so a
wrong claim can be undone without revoking the key.

Upgrade note: one key shared by several nodes now works for the first node
that heartbeats with it; the others get 403 ("API key is bound to node
...").  Give each node its own key (``POST /api/keys/`` with ``node_id``),
bind further keys to a node explicitly with ``PATCH /api/keys/{key_id}``,
or set ``BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`` to restore the old behaviour in
which any unbound key may heartbeat as any node (insecure: any key holder
can then take a node's commands).
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
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
    accept_ws,
    rate_limit,
    require_master_key,
    require_role,
    require_ws_auth,
)
from sigrift.lib.shiny.models import (
    CommandRequest,
    CommandResponse,
    CommandStatus,
    HeartbeatRequest,
    HeartbeatResponse,
    NodeRegistration,
    NodeResponse,
)
from sigrift.lib.shiny.node_metrics import accept_metrics, stored_node_fields
from sigrift.lib.shiny.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _allow_unbound_node_keys() -> bool:
    """True if ``BRIDGE_ALLOW_UNBOUND_NODE_KEYS`` restores unbound node keys.

    Same opt-out flag the bridge uses (contract K4): with it set, an unbound
    non-admin key may heartbeat as any node, as before.
    """
    return os.environ.get("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


# Migration opt-in: lets keys from before key purposes existed claim a node
# on first use again (see the module docstring).
LEGACY_KEY_TOFU_ENV = "SHINY_LEGACY_KEY_TOFU"


@dataclass(frozen=True)
class LegacyKeyTofu:
    """State of the ``SHINY_LEGACY_KEY_TOFU`` migration opt-in."""

    active: bool
    until: datetime | None = None  # deadline, when time-limited
    invalid: str | None = None  # an unparseable value (treated as off)


def legacy_key_tofu(now: datetime | None = None) -> LegacyKeyTofu:
    """Whether keys with no ``purpose`` may claim a node on first use.

    ``SHINY_LEGACY_KEY_TOFU`` is off when unset (the default).  ``1`` /
    ``true`` / ``yes`` / ``on`` turn it on until it is unset; an ISO 8601
    date or date-time (``2026-12-01``, ``2026-12-01T12:00:00Z``; no zone
    means UTC, a bare date means 00:00 UTC that day) turns it on until that
    moment, so the migration window closes by itself.  Any other value is
    invalid and leaves it off.
    """
    raw = os.environ.get(LEGACY_KEY_TOFU_ENV, "").strip()
    flag = raw.lower()
    if flag in ("", "0", "false", "no", "off"):
        return LegacyKeyTofu(active=False)
    if flag in ("1", "true", "yes", "on"):
        return LegacyKeyTofu(active=True)
    try:
        until = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return LegacyKeyTofu(active=False, invalid=raw)
    if until.tzinfo is None:
        until = until.replace(tzinfo=timezone.utc)
    return LegacyKeyTofu(active=until > (now or _utcnow()), until=until)


def _bind_on_first_use(
    persistence: Any,
    app_state: AppState,
    key_id: str,
    meta: dict[str, Any],
    role: Role,
    node_id: str,
) -> None:
    """Bind an unbound non-admin key to *node_id* on its first heartbeat.

    Only ``node``-purpose keys are bound this way (and keys with no purpose
    while :func:`legacy_key_tofu` is on).  Raises 403 for every other key
    (``dashboard`` keys, ``analyst`` keys, keys with no purpose) and for a
    node another key is already bound to.  Without these checks any
    dashboard viewer key could claim a node, take its admin-queued
    commands, spoof its metrics and lock the real node out.
    """

    def _refuse(detail: str) -> None:
        logger.warning(
            "Heartbeat for node %r refused for API key %r: %s", node_id, key_id, detail
        )
        app_state.log_activity(
            event_type="heartbeat_refused",
            node_id=node_id,
            message=f"Heartbeat for {node_id} refused for API key {key_id}: {detail}",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    purpose = meta.get("purpose")
    if purpose == "dashboard":
        _refuse(
            "API key is a dashboard key, not a node key (create node keys with node_id)"
        )
    if role >= Role.ANALYST:
        _refuse("analyst keys cannot act as a node unless created with node_id")
    # (Details end up in the activity feed, which HTML-escapes them: no quotes.)
    legacy = not purpose
    if legacy:
        if not legacy_key_tofu().active:
            _refuse(
                "API key has no purpose and no node binding (it was created "
                "before key purposes existed), so it cannot heartbeat as a "
                f"node: an admin binds it to its node with PATCH /api/keys/{key_id} "
                f"and a node_id (master key), or sets {LEGACY_KEY_TOFU_ENV} "
                "for the migration"
            )
    elif purpose != "node":
        _refuse(f"API key is not a node key (purpose {purpose})")

    outcome = persistence.bind_key_to_node(key_id, node_id)
    if outcome == "node_claimed":
        _refuse(f"node {node_id!r} is bound to another API key")
    if outcome == "bound_elsewhere":
        _refuse("API key is bound to a different node")
    if outcome != "bound":
        _refuse("API key cannot be bound to a node")

    if legacy:
        # Could be the node's own key or a shared dashboard key: say so loudly.
        message = (
            f"API key {key_id} (no purpose: created before key purposes "
            f"existed) claimed node {node_id} on its first heartbeat under "
            f"{LEGACY_KEY_TOFU_ENV}. If it is not the own key of {node_id}, "
            f"unbind it (PATCH /api/keys/{key_id} with node_id null) or revoke it"
        )
        logger.warning("%s", message)
        app_state.log_activity(
            event_type="legacy_key_bound",
            node_id=node_id,
            message=message,
            details={"level": "warning", "key_id": key_id},
        )
        return
    logger.info(
        "API key %r bound to node %r on first heartbeat (trust on first use)",
        key_id,
        node_id,
    )
    app_state.log_activity(
        event_type="node_key_bound",
        node_id=node_id,
        message=f"API key {key_id} bound to node {node_id} on first heartbeat",
    )


def _node_to_response(node_id: str, data: dict[str, Any]) -> NodeResponse:
    """Build a ``NodeResponse`` from raw persistence data.

    A stored value of the wrong type (a record saved before heartbeat
    metrics were checked, or edited by hand) reads as the field's default,
    so one bad record cannot fail the node listing.
    """
    return NodeResponse(
        node_id=node_id,
        status=AppState.get_node_status(data),
        **stored_node_fields(data),
    )


#: Heartbeat metrics also shown in the node's capabilities (the first five of
#: node_metrics.CAPABILITY_METRICS, which the bridge copies in full).
_CAPABILITY_METRICS = (
    "agent_version",
    "disk_percent",
    "cpu_temp",
    "load_1m",
    "uptime_seconds",
)


@router.post("/register")
async def register_node(
    body: NodeRegistration,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> NodeResponse:
    """Register a new edge node (or re-register an existing one). Admin only."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    now = _utcnow()
    node_data: dict[str, Any] = {
        "host": body.host,
        "port": body.port,
        "capabilities": body.capabilities,
        "registered_at": now.isoformat(),
        "last_seen": now.isoformat(),
    }
    persistence.set_node(body.node_id, node_data)

    app_state.log_activity(
        event_type="node_registered",
        node_id=body.node_id,
        message=f"Node {body.node_id} registered from {body.host}:{body.port}",
    )
    logger.info("Node registered: %s", body.node_id)
    return _node_to_response(body.node_id, node_data)


@router.post("/heartbeat")
async def heartbeat(
    body: HeartbeatRequest,
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> HeartbeatResponse:
    """Process a node heartbeat, updating metrics and checking alerts.

    The heartbeat hands out the node's queued commands and overwrites its
    metrics, so only a credential bound to the node (or an admin) may send
    it: an unbound non-admin key would otherwise be able to impersonate any
    registered node.  An unbound ``node`` key is bound to the node it first
    reports for ("trust on first use", mirroring the bridge's contracts K4
    and K7b) unless another key already holds that node; other unbound keys
    are refused.  See the module docstring.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    nodes = persistence.get_nodes()

    node_data = nodes.get(body.node_id)
    if node_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {body.node_id!r} not registered",
        )

    meta = getattr(request.state, "api_key_meta", None) or {}
    bound_node = meta.get("node_id")
    role = getattr(request.state, "api_key_role", Role.VIEWER)
    if role < Role.ADMIN:
        if bound_node:
            if bound_node != body.node_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"API key is bound to node {bound_node!r}",
                )
        elif not _allow_unbound_node_keys():
            # Every refusal happens before any state changes: the node's
            # queued commands stay queued and its metrics are untouched.
            _bind_on_first_use(
                persistence, app_state, _key_id, meta, role, body.node_id
            )

    now = _utcnow()
    node_data["last_seen"] = now.isoformat()
    # Only known metrics with valid values are stored (node_metrics): the
    # extra fields NodeMetrics allows never rewrite the admin's record
    # (host, port, registered_at) or the server's last_seen, and of the
    # capabilities only the monitor fields below.
    metrics, invalid = accept_metrics(body.metrics.model_dump())
    for name in invalid:
        node_data.pop(name, None)
    node_data.update(metrics)

    # Sync monitor agent info into capabilities so it's visible in responses
    # (a bad value clears the entry, whoever wrote it)
    caps = node_data.get("capabilities")
    if not isinstance(caps, dict):
        caps = node_data["capabilities"] = {}
    for name in _CAPABILITY_METRICS:
        if name in metrics:
            caps[name] = metrics[name]
        elif name in invalid:
            caps.pop(name, None)

    persistence.set_node(body.node_id, node_data)

    app_state.check_node_alerts(body.node_id, node_data, persistence)

    pending = app_state.pending_commands.pop(body.node_id, [])
    return HeartbeatResponse(
        accepted=True,
        node_id=body.node_id,
        server_time=now,
        pending_commands=pending,
    )


@router.get("/")
async def list_nodes(
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> list[NodeResponse]:
    """Return all registered nodes with computed status."""
    nodes = request.app.state.persistence.get_nodes()
    return [_node_to_response(nid, d) for nid, d in nodes.items()]


@router.get("/activity")
async def get_activity(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    _key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """Return recent activity log entries."""
    app_state: AppState = request.app.state.app_state
    return list(app_state.activity_log)[-limit:]


@router.get("/{node_id}")
async def get_node(
    node_id: str,
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> NodeResponse:
    """Return a single node by ID, or 404 if not found."""
    nodes = request.app.state.persistence.get_nodes()
    node_data = nodes.get(node_id)
    if node_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )
    return _node_to_response(node_id, node_data)


@router.delete("/{node_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_node(
    node_id: str,
    request: Request,
    _key_id: str = Depends(require_master_key),
) -> None:
    """Remove a node (requires master key)."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    if not persistence.remove_node(node_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    app_state.log_activity(
        event_type="node_removed",
        node_id=node_id,
        message=f"Node {node_id} removed",
    )
    logger.info("Node removed: %s", node_id)


@router.post("/{node_id}/command")
async def queue_command(
    node_id: str,
    body: CommandRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> CommandResponse:
    """Queue a command for delivery on the node's next heartbeat. Admin only."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    if node_id not in persistence.get_nodes():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    command_id = str(uuid.uuid4())
    now = _utcnow()

    cmd_entry: dict[str, Any] = {
        "command_id": command_id,
        "command": body.command,
        "params": body.params,
        "status": CommandStatus.queued,
        "queued_at": now.isoformat(),
    }

    if node_id not in app_state.pending_commands:
        app_state.pending_commands[node_id] = []
    app_state.pending_commands[node_id].append(cmd_entry)

    app_state.log_activity(
        event_type="command_queued",
        node_id=node_id,
        message=f"Command '{body.command}' queued for {node_id}",
    )
    logger.info(
        "Command %s queued for node %s: %s",
        command_id,
        node_id,
        body.command,
    )
    return CommandResponse(
        command_id=command_id,
        node_id=node_id,
        command=body.command,
        status=CommandStatus.queued,
        queued_at=now,
    )


# ---------------------------------------------------------------------------
# WebSocket: real-time node status stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/status")
async def ws_status(websocket: WebSocket) -> None:
    """Stream node status to authenticated WebSocket clients.

    Auth is validated *before* accept() (gen2 bug fix).
    """
    key_id = await require_ws_auth(websocket)
    await accept_ws(websocket)

    app_state: AppState = websocket.app.state.app_state
    persistence = websocket.app.state.persistence
    await app_state.ws_status_clients.add(websocket)
    logger.info("WebSocket status client connected: %s", key_id)

    try:
        # Send current node snapshot on connect
        nodes = persistence.get_nodes()
        node_list = [
            _node_to_response(nid, data).model_dump(mode="json")
            for nid, data in nodes.items()
        ]
        await websocket.send_json({"type": "snapshot", "nodes": node_list})

        # Keep alive, listening for client close
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("WebSocket status client disconnected: %s", key_id)
    except RuntimeError as exc:
        logger.debug("WebSocket runtime error for %s: %s", key_id, exc)
    finally:
        await app_state.ws_status_clients.remove(websocket)
