"""Zigbee SIGINT API router for The Bridge.

Provides endpoints for Zigbee device discovery, batch ingest from
edge sensor nodes, and real-time event streaming via WebSocket.

Zigbee operates on IEEE 802.15.4 in the 2.4 GHz ISM band (channels
11-26, 2405-2480 MHz) and optionally sub-GHz bands.  Common dongles:
CC2652, CC2531, ConBee II, HUSBZB-1.
"""

from __future__ import annotations

import asyncio
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

from pydantic import BaseModel as _BaseModel, Field

from sigrift.bridge.dependencies import (
    Role,
    enforce_node_binding,
    get_ws_limiter,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.correlation_engine import PerNodeThrottle
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store


class ZigbeeDeviceRecord(_BaseModel):
    ieee_addr: str = ""  # 64-bit extended address (00:11:22:33:44:55:66:77)
    short_addr: str = ""  # 16-bit network address (0x1234)
    device_name: str = ""
    device_type: str = "unknown"  # coordinator, router, end_device, unknown
    pan_id: str = ""  # 16-bit PAN ID
    extended_pan_id: str = ""  # 64-bit Extended PAN ID
    channel: int = Field(default=0, ge=0, le=26)
    rssi_dbm: float = 0.0
    lqi: int = Field(default=0, ge=0, le=255)  # Link Quality Indicator
    manufacturer_code: int = 0
    manufacturer: str = ""
    clusters: list[str] = Field(default_factory=list)
    endpoints: list[int] = Field(default_factory=list)
    power_source: str = "unknown"  # mains, battery, unknown
    profile_id: str = ""  # ZHA (0x0104), ZLL (0xC05E), etc.
    stack_profile: str = ""  # zigbee, zigbee_pro, zigbee_3_0
    security_enabled: int = 0  # 1 if network uses encryption
    parent_addr: str = ""  # parent router/coordinator IEEE addr


class ZigbeeChannelEnergy(_BaseModel):
    channel: int = Field(ge=11, le=26)
    rssi_dbm: float = 0.0


class ZigbeeScanBatch(_BaseModel):
    node_id: str
    records: list[ZigbeeDeviceRecord] = Field(default_factory=list)
    channel_energy: list[ZigbeeChannelEnergy] = Field(default_factory=list)


logger = logging.getLogger(__name__)

# Per-uvicorn-worker throttle on cross-correlation: see routers/wifi.py
# for rationale.
_corr_throttle = PerNodeThrottle(every_n=5)

router = APIRouter()

_ZB_MAX_BATCH = 500

_get_detection_store = get_detection_store


# ---------------------------------------------------------------------------
# GET /devices — list discovered Zigbee devices
# ---------------------------------------------------------------------------


@router.get("/devices")
async def get_zigbee_devices(
    request: Request,
    device_type: str | None = Query(
        None, description="Filter: coordinator, router, end_device, unknown"
    ),
    pan_id: str | None = Query(None),
    node_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List discovered Zigbee devices."""
    store = _get_detection_store(request)
    devices = await asyncio.to_thread(
        store.get_zigbee_devices,
        limit=limit,
        device_type=device_type,
        pan_id=pan_id,
        node_id=node_id,
    )
    return {
        "count": len(devices),
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# GET /devices/{ieee_addr} — device detail with timeline
# ---------------------------------------------------------------------------


@router.get("/devices/{ieee_addr}")
async def get_zigbee_device_detail(
    ieee_addr: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get detailed info for a Zigbee device by IEEE address."""
    store = _get_detection_store(request)
    detail = await asyncio.to_thread(store.get_zigbee_device_detail, ieee_addr)
    if not detail:
        raise HTTPException(status_code=404, detail="Device not found")
    return detail


# ---------------------------------------------------------------------------
# GET /stats — summary statistics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_zigbee_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Zigbee network summary statistics."""
    store = _get_detection_store(request)
    stats = await asyncio.to_thread(store.get_zigbee_stats)
    # Include channel energy in stats
    energy = await asyncio.to_thread(store.get_channel_energy, 1)
    stats["channel_energy"] = energy
    return stats


# ---------------------------------------------------------------------------
# GET /topology — network topology grouped by PAN
# ---------------------------------------------------------------------------


@router.get("/topology")
async def get_zigbee_topology(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Zigbee network topology grouped by PAN ID."""
    store = _get_detection_store(request)
    networks = await asyncio.to_thread(store.get_network_topology)
    return {"networks": networks, "count": len(networks)}


# ---------------------------------------------------------------------------
# GET /energy — channel energy heatmap data
# ---------------------------------------------------------------------------


@router.get("/energy")
async def get_zigbee_energy(
    request: Request,
    hours: int = Query(1, ge=1, le=24),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Channel energy scan results."""
    store = _get_detection_store(request)
    energy = await asyncio.to_thread(store.get_channel_energy, hours, node_id)
    return {"channels": energy}


# ---------------------------------------------------------------------------
# POST /ingest — batch ingest Zigbee scan data from edge nodes
# ---------------------------------------------------------------------------


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_zigbee_scan(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Batch ingest Zigbee scan data from an edge node.

    Supports gzip-compressed request bodies (Content-Encoding: gzip).
    Accepts up to 500 device records per batch.
    """
    import gzip as _gzip
    import json as _json
    import zlib as _zlib

    raw_body = await request.body()
    if len(raw_body) > 1_048_576:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds 1MB limit",
        )

    if request.headers.get("content-encoding") == "gzip":
        try:
            from io import BytesIO as _BytesIO

            _MAX_DECOMPRESSED = 10 * 1024 * 1024
            dec = _gzip.GzipFile(fileobj=_BytesIO(raw_body))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = dec.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DECOMPRESSED:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Decompressed payload exceeds 10MB limit",
                    )
                chunks.append(chunk)
            raw_body = b"".join(chunks)
        except HTTPException:
            raise
        except (OSError, ValueError, EOFError, _zlib.error):
            # EOFError: truncated stream; zlib.error: corrupt deflate
            # behind a valid header — client garbage, 400 not 500.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decompress gzip body",
            )

    try:
        payload = _json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {exc}",
        )

    try:
        body = ZigbeeScanBatch(**payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload: {exc}",
        )
    await enforce_node_binding(request, _key_id, body.node_id)

    if len(body.records) > _ZB_MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(body.records)} exceeds maximum {_ZB_MAX_BATCH}",
        )

    store = _get_detection_store(request)

    # Bound device names; they are stored as received and pages escape
    # them on output.
    safe_records: list[dict] = []
    for rec in body.records:
        d = rec.model_dump()
        d["node_id"] = body.node_id
        if d.get("device_name"):
            d["device_name"] = d["device_name"][:64]
        safe_records.append(d)

    inserted = await asyncio.to_thread(store.insert_zigbee_devices, safe_records)

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(request.app.state, "cross_correlator", None)
    if cross_correlator and _corr_throttle.should_run(body.node_id):
        try:
            zb_events = [
                {
                    "channel": r["channel"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "id": r.get("ieee_addr", ""),
                }
                for r in safe_records
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "zigbee", zb_events, body.node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    # Insert channel energy if present
    energy_inserted = 0
    if body.channel_energy:
        energy_records = [
            {"channel": e.channel, "rssi_dbm": e.rssi_dbm, "node_id": body.node_id}
            for e in body.channel_energy
        ]
        energy_inserted = await asyncio.to_thread(
            store.insert_channel_energy, energy_records
        )

    # Broadcast via WebSocket
    app_state: AppState = request.app.state.app_state
    ws_clients = getattr(app_state, "zigbee_ws_clients", set())
    if ws_clients:
        event = {
            "type": "zigbee_ingest",
            "node_id": body.node_id,
            "count": inserted,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        dead: set = set()
        for ws in ws_clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.add(ws)
        ws_clients -= dead

    logger.info(
        "Zigbee ingest: %d devices from node %s",
        inserted,
        body.node_id,
    )
    return {
        "accepted": inserted,
        "energy_channels": energy_inserted,
        "node_id": body.node_id,
    }


# ---------------------------------------------------------------------------
# WebSocket /ws/zigbee — real-time Zigbee events
# ---------------------------------------------------------------------------


@router.websocket("/ws/zigbee")
async def zigbee_websocket(websocket: WebSocket) -> None:
    """Real-time Zigbee event stream."""
    # require_ws_auth authenticates (VIEWER+) and takes this client's
    # connection slot; it is released in the finally below.
    _key_id, subprotocol = await require_ws_auth(websocket)
    client_ip = getattr(websocket.state, "ws_client_ip", None)
    ws_limiter = get_ws_limiter()

    app_state: AppState = websocket.app.state.app_state
    if not hasattr(app_state, "zigbee_ws_clients"):
        app_state.zigbee_ws_clients = set()

    try:
        if subprotocol:
            await websocket.accept(subprotocol=subprotocol)
        else:
            await websocket.accept()
        app_state.zigbee_ws_clients.add(websocket)
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        ws_limiter.release(client_ip)
        clients = getattr(app_state, "zigbee_ws_clients", set())
        clients.discard(websocket)
