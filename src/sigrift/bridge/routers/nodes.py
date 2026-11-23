"""Node management endpoints and WebSocket status stream.

Provides CRUD for edge nodes, heartbeat processing (with detection
summary support), command queuing, activity log retrieval, and a
real-time WebSocket status stream.

Adapted from sigrift.lib.shiny.routers.nodes for The Bridge.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from functools import partial
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

from pydantic import BaseModel, Field, ValidationError, field_validator

from sigrift.bridge.dependencies import (
    Role,
    enforce_node_binding,
    get_ws_limiter,
    require_master_key,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.models import (
    BridgeHeartbeatRequest,
    BridgeHeartbeatResponse,
    BridgeNodeResponse,
    CommandRequest,
    CommandResponse,
    CommandStatus,
    DetectionSummary,
    IQCaptureRequest,
    NodeLocationUpdate,
    ScannerStatusRequest,
    ScannerStatusResponse,
)
from sigrift.bridge.scanner_status import SCANNER_REPORTS_FIELD, scanner_status_snapshot
from sigrift.bridge.known_signals import authorized_store
from sigrift.bridge.setup_readiness import (
    READINESS_FIELD,
    SetupReadinessRequest,
    readiness_snapshot,
)
from sigrift.bridge.setup_checklist import (
    MAX_NODES,
    build_checklist,
    collect_observations,
)
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow
from sigrift.lib.shiny.node_metrics import (
    CAPABILITY_METRICS,
    MAX_TEXT_LENGTH,
    accept_metrics,
    isoformat,
    stored_node_fields,
    stored_number,
)

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow

_COMMAND_LEASE_MINUTES = 5
_MAX_PENDING_COMMANDS_PER_NODE = 100
#: Queue slots per node only admin credentials may fill: commands queued by
#: analysts (IQ captures) stop this many short of the limit, so they can
#: never crowd out an admin's commands.
_ADMIN_RESERVED_COMMAND_SLOTS = 20


def command_queue_limit(role: Role) -> int:
    """Pending commands per node a caller with *role* may queue up to."""
    if role >= Role.ADMIN:
        return _MAX_PENDING_COMMANDS_PER_NODE
    return _MAX_PENDING_COMMANDS_PER_NODE - _ADMIN_RESERVED_COMMAND_SLOTS


def _check_command_queue(request: Request, app_state: AppState, node_id: str) -> None:
    """Raise 429 if *node_id*'s pending-command queue is full for this caller."""
    limit = command_queue_limit(getattr(request.state, "key_role", Role.SENSOR))
    pending_count = len(app_state.pending_commands.get(node_id, []))
    if pending_count >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Node {node_id!r} already has {pending_count} pending commands (limit {limit})",
        )


def _enqueue_command(
    app_state: AppState,
    node_id: str,
    command: str,
    params: dict[str, Any],
    now: datetime,
) -> dict[str, Any]:
    """Queue *command* for *node_id*'s next heartbeat and record it in history.

    The caller has checked that the node is registered and that its queue
    has room (``_check_command_queue``).  The command carries a lease: a
    node that has not collected it within ``_COMMAND_LEASE_MINUTES`` never
    gets it (``_reap_expired_commands``), so an offline node does not run a
    restart or update whenever it next comes back.  Returns the queued entry.
    """
    command_id = str(uuid.uuid4())
    lease_expires_at = (now + timedelta(minutes=_COMMAND_LEASE_MINUTES)).isoformat()
    cmd_entry: dict[str, Any] = {
        "command_id": command_id,
        "command": command,
        "params": params,
        "status": CommandStatus.queued,
        "queued_at": now.isoformat(),
        "lease_expires_at": lease_expires_at,
    }
    app_state.pending_commands.setdefault(node_id, []).append(cmd_entry)
    app_state.command_history.append(
        {
            "command_id": command_id,
            "node_id": node_id,
            "command": command,
            "status": "queued",
            "params": params,
            "queued_at": now.isoformat(),
            "lease_expires_at": lease_expires_at,
            "dispatched_at": None,
            "acked_at": None,
            "completed_at": None,
        }
    )
    return cmd_entry


def _drop_pending_commands(app_state: AppState, node_id: str) -> int:
    """Discard every command still queued for a node that is being removed.

    A node registering again under the same id must not run commands queued
    for the node that was removed.  Their history entries become
    ``cancelled``.  Returns the number of commands dropped.
    """
    dropped = app_state.pending_commands.pop(node_id, [])
    ids = {c["command_id"] for c in dropped if c.get("command_id")}
    for entry in app_state.command_history:
        if entry.get("command_id") in ids and entry.get("status") == "queued":
            entry["status"] = "cancelled"
    return len(dropped)


def _reap_expired_commands(app_state: AppState) -> int:
    """Remove pending commands whose lease has expired.

    Returns the number of commands reaped.
    """
    now = _utcnow()
    reaped = 0
    for node_id in list(app_state.pending_commands):
        cmds = app_state.pending_commands[node_id]
        remaining: list[dict[str, Any]] = []
        for cmd in cmds:
            lease_str = cmd.get("lease_expires_at")
            if lease_str:
                lease_dt = datetime.fromisoformat(lease_str)
                if lease_dt < now:
                    logger.info(
                        "Reaping expired command %s for node %s (expired %s)",
                        cmd.get("command_id"),
                        node_id,
                        lease_str,
                    )
                    # Update command history status
                    for entry in app_state.command_history:
                        if entry.get("command_id") == cmd.get("command_id") and entry[
                            "status"
                        ] in ("queued", "dispatched"):
                            entry["status"] = "expired"
                    reaped += 1
                    continue
            remaining.append(cmd)
        if remaining:
            app_state.pending_commands[node_id] = remaining
        else:
            app_state.pending_commands.pop(node_id, None)
    return reaped


def _compute_config_hash(
    node_data: dict[str, Any], detection_config: dict[str, Any]
) -> str:
    """Return a short hash of the node's expected configuration.

    The edge node can compare this against its local config to detect
    staleness without transferring the full config blob.
    """
    caps = node_data.get("capabilities")
    if not isinstance(caps, dict):
        caps = {}
    config_dict = {
        "model_version": caps.get("model_version", ""),
        "scan_ranges": caps.get("scan_ranges", []),
        "anomaly_enabled": caps.get("anomaly_enabled", False),
        "iq_capture_enabled": detection_config.get("iq_capture_enabled", False),
    }
    return hashlib.sha256(json.dumps(config_dict, sort_keys=True).encode()).hexdigest()[
        :16
    ]


def stored_detection_summary(value: Any) -> dict[str, Any] | None:
    """A stored ``detection_summary`` as a valid summary, or None."""
    if value is None:
        return None
    try:
        return DetectionSummary.model_validate(value).model_dump()
    except ValidationError:
        return None


def stored_floor_label(value: Any) -> str:
    """A stored ``floor_label``, or "" when it is not text."""
    return value if isinstance(value, str) else ""


def stored_location(record: dict[str, Any]) -> dict[str, Any] | None:
    """A node record's stored location, or None when it has no valid one.

    ``latitude`` and ``longitude`` must be finite numbers in range (as
    ``NodeLocationUpdate`` accepts them), else the node has no location.  A
    bad ``altitude_m`` reads as None and a bad ``location_name`` as "", so a
    record saved before heartbeat metrics were checked (or edited by hand)
    cannot fail the map, geo or TDOA readers.
    """
    latitude = stored_number(record.get("latitude"))
    longitude = stored_number(record.get("longitude"))
    if latitude is None or longitude is None:
        return None
    if not (-90.0 <= latitude <= 90.0 and -180.0 <= longitude <= 180.0):
        return None
    name = record.get("location_name")
    return {
        "latitude": latitude,
        "longitude": longitude,
        "altitude_m": stored_number(record.get("altitude_m")),
        "location_name": (
            name if isinstance(name, str) and len(name) <= MAX_TEXT_LENGTH else ""
        ),
    }


def _node_to_response(node_id: str, data: dict[str, Any]) -> BridgeNodeResponse:
    """Build a ``BridgeNodeResponse`` from raw persistence data.

    A stored value of the wrong type (a record saved before heartbeat
    metrics were checked, or edited by hand) reads as the field's default,
    so one bad record cannot fail a node listing or status broadcast.
    """
    return BridgeNodeResponse(
        node_id=node_id,
        status=AppState.get_node_status(data),
        **stored_node_fields(data),
        position_x=stored_number(data.get("position_x")),
        position_y=stored_number(data.get("position_y")),
        floor_label=stored_floor_label(data.get("floor_label")),
        detection_summary=stored_detection_summary(data.get("detection_summary")),
        scanner_status=scanner_status_snapshot(
            data.get(SCANNER_REPORTS_FIELD), _utcnow()
        ),
    )


class NodeRegistrationWithLocation(BaseModel):
    """Extended registration request with optional geolocation."""

    model_config = {"extra": "forbid"}

    node_id: str
    host: str = ""
    port: int = 0
    capabilities: dict[str, Any] = Field(default_factory=dict)
    latitude: float | None = Field(default=None, ge=-90.0, le=90.0)
    longitude: float | None = Field(default=None, ge=-180.0, le=180.0)
    altitude_m: float | None = None
    location_name: str = Field(default="", max_length=256)

    @field_validator("node_id")
    @classmethod
    def _check_node_id(cls, v: str) -> str:
        from sigrift.lib.shiny.models import _validate_id

        return _validate_id(v, "node_id")


@router.post("/register")
async def register_node(
    body: NodeRegistrationWithLocation,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> BridgeNodeResponse:
    """Register a new edge node (or re-register an existing one)."""
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
    # Store optional geolocation fields
    if body.latitude is not None and body.longitude is not None:
        node_data["latitude"] = body.latitude
        node_data["longitude"] = body.longitude
        if body.altitude_m is not None:
            node_data["altitude_m"] = body.altitude_m
        if body.location_name:
            node_data["location_name"] = body.location_name
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
    body: BridgeHeartbeatRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> BridgeHeartbeatResponse:
    """Process a node heartbeat with optional detection summary.

    The heartbeat also hands out the node's queued commands, so only a
    credential bound to the node may send it (contract K4).  An unbound
    key is bound only to a registered node (checked first).
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

    await enforce_node_binding(request, _key_id, body.node_id)
    # Binding performs asynchronous persistence work. Re-read after it so a
    # concurrent scanner report/heartbeat is not replaced by a stale snapshot.
    node_data = persistence.get_nodes().get(body.node_id)
    if node_data is None:
        raise HTTPException(status_code=404, detail="Node not registered")

    now = _utcnow()
    node_data["last_seen"] = now.isoformat()
    # NodeMetrics allows extra fields for legacy agents, but only known
    # metrics with valid values are stored (sigrift.lib.shiny.node_metrics):
    # a heartbeat never rewrites the server's last_seen, the admin's host or
    # port, or the scanner leases and setup readiness that only their
    # node-bound routes write, and of the capabilities only the monitor
    # fields below.  A known metric with a bad value is cleared; the
    # heartbeat is still accepted and still collects commands.
    reported = body.metrics.model_dump()
    metrics, invalid = accept_metrics(reported)
    for name in invalid:
        node_data.pop(name, None)
    node_data.update(metrics)
    ignored = reported.keys() - metrics.keys() - invalid
    if invalid or ignored:
        logger.debug(
            "Heartbeat from %s: cleared %d invalid metric(s), ignored %d unknown",
            body.node_id,
            len(invalid),
            len(ignored),
        )

    # Sync monitor agent info into capabilities (a bad value clears the
    # entry, whoever wrote it: the stale value is not shown as current)
    caps = node_data.get("capabilities")
    if not isinstance(caps, dict):
        caps = node_data["capabilities"] = {}
    for field in CAPABILITY_METRICS:
        if field in metrics:
            caps[field] = metrics[field]
        elif field in invalid:
            caps.pop(field, None)

    # Store detection summary in node data if provided
    if body.detection_summary is not None:
        node_data["detection_summary"] = body.detection_summary.model_dump()

    persistence.set_node(body.node_id, node_data)

    app_state.check_node_alerts(body.node_id, node_data, persistence)

    # Broadcast updated node list to all WebSocket status clients
    if app_state.ws_status_clients:
        all_nodes = persistence.get_nodes()
        node_list = [
            _node_to_response(nid, d).model_dump(mode="json")
            for nid, d in all_nodes.items()
        ]
        msg = {"type": "snapshot", "nodes": node_list}
        await app_state.ws_status_clients.broadcast(msg)

    pending = app_state.pending_commands.pop(body.node_id, [])

    # Mark dispatched commands in history
    if pending:
        dispatched_ids = {c.get("command_id") for c in pending}
        for entry in app_state.command_history:
            if entry["command_id"] in dispatched_ids and entry["status"] == "queued":
                entry["status"] = "dispatched"
                entry["dispatched_at"] = now.isoformat()

    # Compute config hash so edge nodes can detect stale config
    detection_config = getattr(request.app.state, "detection_config", {})
    config_hash = _compute_config_hash(node_data, detection_config)

    return BridgeHeartbeatResponse(
        accepted=True,
        node_id=body.node_id,
        server_time=now,
        pending_commands=pending,
        config_hash=config_hash,
    )


@router.post("/{node_id}/scanner-status")
async def report_scanner_status(
    node_id: str,
    body: ScannerStatusRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> ScannerStatusResponse:
    """Renew only this scanner's lease after a real capture-health check.

    Workers report at least every 30 seconds while capture is healthy, including
    quiet air with no detections. Shutdown/error reports invalidate immediately;
    a crashed or disconnected worker expires after 120 seconds. Generic node
    heartbeats and configured hardware never imply an active scanner.
    """
    persistence = request.app.state.persistence
    node_data = persistence.get_nodes().get(node_id)
    if node_data is None:
        raise HTTPException(status_code=404, detail="Node not registered")
    await enforce_node_binding(request, _key_id, node_id)
    # Binding performs asynchronous persistence work. Re-read after it so a
    # concurrent scanner report/heartbeat is not replaced by a stale snapshot.
    node_data = persistence.get_nodes().get(node_id)
    if node_data is None:
        raise HTTPException(status_code=404, detail="Node not registered")
    now = _utcnow()
    reports = node_data.get(SCANNER_REPORTS_FIELD)
    if not isinstance(reports, dict):
        reports = {}
    record = {"state": body.state, "reported_at": now.isoformat()}
    # Replacing the whole record clears an earlier reason the scanner dropped.
    if body.reason is not None:
        record["reason"] = body.reason
    reports[body.protocol] = record
    node_data[SCANNER_REPORTS_FIELD] = reports
    # A real scanner report is node contact, but does not overwrite host metrics.
    node_data["last_seen"] = now.isoformat()
    persistence.set_node(node_id, node_data)
    clients = request.app.state.app_state.ws_status_clients
    if clients:
        await clients.broadcast(
            {
                "type": "snapshot",
                "nodes": [
                    _node_to_response(nid, data).model_dump(mode="json")
                    for nid, data in persistence.get_nodes().items()
                ],
            }
        )
    return ScannerStatusResponse(**scanner_status_snapshot(reports, now)[body.protocol])


@router.post("/{node_id}/setup-readiness")
async def report_setup_readiness(
    node_id: str,
    body: SetupReadinessRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
):
    """Record a host's last setup check, not evidence of ongoing capture.

    Unlike legacy ingest, this endpoint requires an already bound scanner API
    key. Neither permissive unbound-key mode nor operator credentials can
    manufacture an association with a host. No timestamp or hardware identity
    is accepted from the client; the server limits freshness to five minutes.
    """
    authorized_store(request, _key_id)
    persistence = request.app.state.persistence
    meta = persistence.get_key_meta().get(_key_id, {})
    if (
        getattr(request.state, "key_role", None) not in {Role.SENSOR, Role.NODE}
        or getattr(request.state, "session_token", None)
        or meta.get("node_id") != node_id
        or _key_id not in persistence.get_key_store()
    ):
        raise HTTPException(
            403, "Setup readiness requires this node's bound scanner API key"
        )
    # There is no await between the current metadata read and persistence write.
    node_data = persistence.get_nodes().get(node_id)
    if node_data is None:
        raise HTTPException(404, "Node not registered")
    now = _utcnow()
    value = body.model_dump() | {"checked_at": now.isoformat()}
    node_data[READINESS_FIELD] = value
    persistence.set_node(node_id, node_data)
    return readiness_snapshot(value, now)


@router.get("/")
async def list_nodes(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[BridgeNodeResponse]:
    """Return all registered nodes with computed status."""
    nodes = request.app.state.persistence.get_nodes()
    return [_node_to_response(nid, d) for nid, d in nodes.items()]


@router.get("/setup-checklist")
async def setup_checklist(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
):
    """Read fixed-instance capture/data evidence without host privileges or PII."""
    store = authorized_store(request, _key_id)
    nodes = request.app.state.persistence.get_nodes()
    ids = sorted(nodes)[:MAX_NODES]
    observations = await asyncio.to_thread(collect_observations, store, ids)
    # Take the lease snapshot after database work, so elapsed query time cannot
    # renew or extend a scanner's server-issued lifetime.
    current = request.app.state.persistence.get_nodes()
    # A node removed while querying must not reappear in this response.
    retained = {node_id: current[node_id] for node_id in ids if node_id in current}
    result = build_checklist(retained, observations, _utcnow())
    result["truncated"] = len(current) > MAX_NODES
    return result


@router.get("/commands")
async def list_commands(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict]:
    """Return recent command history (queued, dispatched, completed)."""
    app_state: AppState = request.app.state.app_state
    # Return newest first
    return list(reversed(app_state.command_history))


@router.post("/{node_id}/commands/{command_id}/ack")
async def ack_command(
    node_id: str,
    command_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.NODE)),
) -> dict[str, Any]:
    """Acknowledge receipt of a dispatched command.

    The edge node calls this after it picks up a command from the
    heartbeat response, confirming it will execute the command before
    the lease expires.
    """
    await enforce_node_binding(request, _key_id, node_id)

    app_state: AppState = request.app.state.app_state
    now = _utcnow()

    for entry in app_state.command_history:
        if entry["command_id"] == command_id and entry["node_id"] == node_id:
            if entry["status"] not in ("dispatched", "queued"):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Command {command_id!r} is in state {entry['status']!r}, cannot ack",
                )
            entry["status"] = "acked"
            entry["acked_at"] = now.isoformat()
            logger.info("Command %s acked by node %s", command_id, node_id)
            return {"ok": True, "command_id": command_id, "status": "acked"}

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Command {command_id!r} not found for node {node_id!r}",
    )


@router.get("/activity")
async def get_activity(
    request: Request,
    limit: int = Query(default=100, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return recent activity log entries."""
    app_state: AppState = request.app.state.app_state
    return list(app_state.activity_log)[-limit:]


@router.get("/locations")
async def get_node_locations(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return all nodes that have a valid geographic location."""
    nodes = request.app.state.persistence.get_nodes()
    result = []
    for nid, data in nodes.items():
        location = stored_location(data)
        if location is not None:
            result.append(
                {
                    "node_id": nid,
                    **location,
                    "status": AppState.get_node_status(data).value,
                    "last_seen": isoformat(data.get("last_seen")),
                }
            )
    return result


@router.get("/{node_id}")
async def get_node(
    node_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> BridgeNodeResponse:
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
    _drop_pending_commands(app_state, node_id)

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
    """Queue a command for delivery on the node's next heartbeat."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    if node_id not in persistence.get_nodes():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    _check_command_queue(request, app_state, node_id)

    now = _utcnow()
    cmd_entry = _enqueue_command(app_state, node_id, body.command, body.params, now)
    command_id = cmd_entry["command_id"]

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
# POST /{node_id}/capture — trigger manual IQ capture
# ---------------------------------------------------------------------------


@router.post("/{node_id}/capture")
async def trigger_iq_capture(
    node_id: str,
    body: IQCaptureRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> CommandResponse:
    """Trigger a manual IQ capture on a specific edge node.

    Queues an ``iq_capture`` command with the specified frequency,
    duration, sample rate, and gain.  The edge node picks it up via
    its next heartbeat poll.  Needs ANALYST or above (tasking a node's
    radio is an operator action, not something a sensor key may do), and
    non-admin callers cannot fill the node's queue slots reserved for
    admin commands.

    ``signal_class`` (or ``detection_id``, a detection of this node whose
    class is used) says what the capture is of.  It is recorded for the
    command, and the stub detection the node's upload creates gets that
    class: a capture of a decodable channel (DMR, P25, LoRa) is then
    protocol-decoded like a detection's own IQ.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    if node_id not in persistence.get_nodes():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    signal_class = body.signal_class
    if body.detection_id:
        store = get_detection_store(request)
        source = await asyncio.to_thread(store.get_detection_by_id, body.detection_id)
        if source is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection {body.detection_id!r} not found",
            )
        if source.get("node_id") != node_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Detection {body.detection_id!r} is not from node {node_id!r}",
            )
        signal_class = signal_class or source.get("signal_class") or None
    if signal_class:
        from sigrift.bridge.class_map import normalize_class

        signal_class = normalize_class(signal_class)

    _check_command_queue(request, app_state, node_id)

    command_id = str(uuid.uuid4())
    now = _utcnow()
    lease_expires_at = now + timedelta(minutes=_COMMAND_LEASE_MINUTES)

    params: dict[str, Any] = {
        "freq_hz": body.freq_hz,
        "duration_ms": body.duration_ms,
        "sample_rate": body.sample_rate,
    }
    # Only task a gain when the operator set one; otherwise the node keeps
    # its configured scan gain (an always-present 40 dB cut HackRF captures
    # ~48 dB below the scan gain -- see IQCaptureRequest).
    if body.gain_db is not None:
        params["gain_db"] = body.gain_db
    if signal_class:
        # Informational for the node (it ignores fields it does not know);
        # the bridge tags the upload's stub detection from the record below.
        params["signal_class"] = signal_class
        if body.detection_id:
            params["detection_id"] = body.detection_id
        from sigrift.bridge.storage.ingest_claims import get_ingest_claims

        claims = get_ingest_claims(request.app.state)
        if claims is not None:
            await asyncio.to_thread(
                partial(
                    claims.record_capture_request,
                    command_id,
                    node_id,
                    signal_class,
                    now=time.time(),
                )
            )

    cmd_entry: dict[str, Any] = {
        "command_id": command_id,
        "command": "iq_capture",
        "params": params,
        "status": CommandStatus.queued,
        "queued_at": now.isoformat(),
        "lease_expires_at": lease_expires_at.isoformat(),
    }

    if node_id not in app_state.pending_commands:
        app_state.pending_commands[node_id] = []
    app_state.pending_commands[node_id].append(cmd_entry)

    # Track in command history
    app_state.command_history.append(
        {
            "command_id": command_id,
            "node_id": node_id,
            "command": "iq_capture",
            "status": "queued",
            "params": cmd_entry["params"],
            "queued_at": now.isoformat(),
            "lease_expires_at": lease_expires_at.isoformat(),
            "dispatched_at": None,
            "acked_at": None,
            "completed_at": None,
        }
    )

    app_state.log_activity(
        event_type="iq_capture_queued",
        node_id=node_id,
        message=(
            f"IQ capture queued for {node_id}: "
            f"{body.freq_hz / 1e6:.3f} MHz, {body.duration_ms}ms, "
            f"gain {'node default' if body.gain_db is None else f'{body.gain_db} dB'}"
        ),
    )
    logger.info(
        "IQ capture %s queued for node %s: %.3f MHz, %d ms",
        command_id,
        node_id,
        body.freq_hz / 1e6,
        body.duration_ms,
    )
    return CommandResponse(
        command_id=command_id,
        node_id=node_id,
        command="iq_capture",
        status=CommandStatus.queued,
        queued_at=now,
    )


# ---------------------------------------------------------------------------
# PUT /{node_id}/location — update node geographic location
# ---------------------------------------------------------------------------


@router.put("/{node_id}/location")
async def update_node_location(
    node_id: str,
    body: NodeLocationUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Update a node's geographic location (lat/lon/alt/name)."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    store = get_detection_store(request)

    nodes = persistence.get_nodes()
    node_data = nodes.get(node_id)
    if node_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    node_data["latitude"] = body.latitude
    node_data["longitude"] = body.longitude
    node_data["altitude_m"] = body.altitude_m
    node_data["location_name"] = body.location_name
    persistence.set_node(node_id, node_data)

    store.log_audit(
        action="admin_update_node_location",
        target_id=node_id,
        operator=_key_id,
        details={
            "latitude": body.latitude,
            "longitude": body.longitude,
            "altitude_m": body.altitude_m,
            "location_name": body.location_name,
        },
    )

    app_state.log_activity(
        event_type="node_location_updated",
        node_id=node_id,
        message=f"Node {node_id} location set to ({body.latitude}, {body.longitude}) name={body.location_name!r}",
    )

    logger.info(
        "Node location updated: %s -> (%.6f, %.6f) name=%s",
        node_id,
        body.latitude,
        body.longitude,
        body.location_name,
    )

    return {
        "ok": True,
        "node_id": node_id,
        "latitude": body.latitude,
        "longitude": body.longitude,
        "altitude_m": body.altitude_m,
        "location_name": body.location_name,
    }


# ---------------------------------------------------------------------------
# PATCH /{node_id}/position — update node geolocation
# ---------------------------------------------------------------------------


class NodePositionRequest(BaseModel):
    """Request body for updating a node's position on the floor plan."""

    model_config = {"extra": "forbid"}

    x: float = Field(ge=0.0, le=100.0, description="X coordinate (0-100)")
    y: float = Field(ge=0.0, le=100.0, description="Y coordinate (0-100)")
    floor_label: str = Field(
        default="",
        max_length=64,
        description="Floor/area label (e.g. 'Floor 2', 'Rooftop')",
    )


@router.patch("/{node_id}/position")
async def update_node_position(
    node_id: str,
    body: NodePositionRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Update a node's position on the floor plan map.

    Stores position_x, position_y (0-100 coordinate space) and
    floor_label in the node's persistent metadata.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    store = get_detection_store(request)

    nodes = persistence.get_nodes()
    node_data = nodes.get(node_id)
    if node_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    node_data["position_x"] = body.x
    node_data["position_y"] = body.y
    node_data["floor_label"] = body.floor_label
    persistence.set_node(node_id, node_data)

    store.log_audit(
        action="admin_update_node_position",
        target_id=node_id,
        operator=_key_id,
        details={
            "position_x": body.x,
            "position_y": body.y,
            "floor_label": body.floor_label,
        },
    )

    app_state.log_activity(
        event_type="node_position_updated",
        node_id=node_id,
        message=f"Node {node_id} position updated to ({body.x}, {body.y}) floor={body.floor_label!r}",
    )

    logger.info(
        "Node position updated: %s -> (%.1f, %.1f) floor=%s",
        node_id,
        body.x,
        body.y,
        body.floor_label,
    )

    return {
        "ok": True,
        "node_id": node_id,
        "position_x": body.x,
        "position_y": body.y,
        "floor_label": body.floor_label,
    }


# ---------------------------------------------------------------------------
# WebSocket: real-time node status stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/status")
async def ws_status(websocket: WebSocket) -> None:
    """Stream node status to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    persistence = websocket.app.state.persistence
    await app_state.ws_status_clients.add(websocket)
    logger.info("WebSocket status client connected: %s", key_id)

    try:
        nodes = persistence.get_nodes()
        node_list = [
            _node_to_response(nid, data).model_dump(mode="json")
            for nid, data in nodes.items()
        ]
        await websocket.send_json({"type": "snapshot", "nodes": node_list})

        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        logger.info("WebSocket status client disconnected: %s", key_id)
    except RuntimeError as exc:
        logger.debug("WebSocket runtime error for %s: %s", key_id, exc)
    finally:
        await app_state.ws_status_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
