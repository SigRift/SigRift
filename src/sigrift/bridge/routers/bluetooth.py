"""Bluetooth SIGINT API router for The Bridge.

Provides endpoints for Bluetooth device discovery, anomaly detection,
real-time BT event streaming via WebSocket, and batch ingest from
edge sensor nodes.

Bluetooth metadata enriches RF detections in the 2.4 GHz ISM band
for Classic, BLE, and Dual-mode devices.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
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

from sigrift.bridge.bt_vuln_scanner import BtVulnScanner
from sigrift.bridge.dependencies import (
    Role,
    enforce_node_binding,
    get_ws_limiter,
    read_json_body,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.correlation_engine import PerNodeThrottle
from sigrift.bridge.models import BtSummaryBatch
from sigrift.bridge.oui_lookup import lookup_vendor
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store


class BtDeviceRecord(_BaseModel):
    device_addr: str = ""
    device_name: str = ""
    device_type: str = "unknown"  # classic, ble, dual, unknown
    device_class: int = 0
    device_class_name: str = ""
    appearance: int = 0
    rssi_dbm: float = 0.0
    tx_power_dbm: float | None = None
    manufacturer_id: int | None = None
    manufacturer: str = ""
    service_uuids: list[str] = Field(default_factory=list)
    adv_data: dict = Field(default_factory=dict)
    connectable: bool = True
    bonded: bool = False
    channel: int = 0


class BtScanBatch(_BaseModel):
    node_id: str
    records: list[BtDeviceRecord] = Field(default_factory=list)


class _BulkDismissBody(_BaseModel):
    ids: list[int]


class _SnoozeBody(_BaseModel):
    hours: int = Field(ge=1, le=168, description="Snooze duration in hours (1-168)")


class _BulkSnoozeBody(_BaseModel):
    ids: list[int]
    hours: int = Field(ge=1, le=168)


logger = logging.getLogger(__name__)

# Per-uvicorn-worker throttle on cross-correlation: see routers/wifi.py
# for rationale.
_corr_throttle = PerNodeThrottle(every_n=5)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BT_MAX_BATCH = 500
_BT_ANOMALY_INSERT_THRESHOLD = 0.4

_get_detection_store = get_detection_store


# ---------------------------------------------------------------------------
# GET /devices — list discovered Bluetooth devices
# ---------------------------------------------------------------------------


@router.get("/devices")
async def get_bt_devices(
    request: Request,
    device_type: str | None = Query(
        None, description="Filter: classic, ble, dual, unknown"
    ),
    node_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List discovered Bluetooth devices."""
    store = _get_detection_store(request)
    devices = await asyncio.to_thread(
        store.get_bt_devices,
        limit=limit,
        device_type=device_type,
        node_id=node_id,
    )
    return {
        "count": len(devices),
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# GET /devices/{device_addr} — device detail with timeline
# ---------------------------------------------------------------------------


@router.get("/devices/{device_addr}")
async def get_bt_device_detail(
    device_addr: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return detail for a specific Bluetooth device including signal timeline."""
    store = _get_detection_store(request)

    device = await asyncio.to_thread(store.get_bt_device_detail, device_addr)

    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device {device_addr!r} not found",
        )

    timeline = await asyncio.to_thread(
        store.get_bt_timeline,
        device_addr=device_addr,
        hours=24,
    )

    return {
        "device": device,
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# GET /stats — Bluetooth summary statistics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_bt_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return Bluetooth summary statistics."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(store.get_bt_stats)


# ---------------------------------------------------------------------------
# POST /ingest — batch ingest BT scan data from edge nodes
# ---------------------------------------------------------------------------


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_bt_scan(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Batch ingest Bluetooth scan data from an edge node.

    Supports gzip-compressed request bodies (Content-Encoding: gzip)
    from the edge BT scanner.  Accepts up to 500 device records per
    batch, stores them, runs anomaly scoring, and broadcasts updates
    via WebSocket.
    """
    import gzip as _gzip
    import json as _json
    import zlib as _zlib

    # Read raw body (max 1 MB compressed)
    raw_body = await request.body()
    if len(raw_body) > 1_048_576:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Request body exceeds 1MB limit",
        )

    # Decompress gzip if needed (bomb protection: 10 MB limit)
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
            # Truncated streams raise EOFError and corrupt deflate data
            # raises zlib.error — same client-garbage class as a bad
            # gzip magic (OSError/BadGzipFile).
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
        body = BtScanBatch(**payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload: {exc}",
        )
    await enforce_node_binding(request, _key_id, body.node_id)

    if len(body.records) > _BT_MAX_BATCH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(body.records)} exceeds maximum {_BT_MAX_BATCH}",
        )

    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state

    now = datetime.now(timezone.utc).isoformat()

    records = []
    for rec in body.records:
        # OUI vendor lookup from MAC address when manufacturer not provided
        mfr = rec.manufacturer or ""
        vendor = lookup_vendor(rec.device_addr) if rec.device_addr else ""
        if not mfr and vendor:
            mfr = vendor
        records.append(
            {
                # Names are stored as received, like /ingest-summary does;
                # pages escape them on output.
                "device_addr": rec.device_addr,
                "device_name": rec.device_name or "",
                "device_type": rec.device_type,
                "device_class": rec.device_class,
                "device_class_name": rec.device_class_name or "",
                "appearance": rec.appearance,
                "rssi_dbm": rec.rssi_dbm,
                "tx_power_dbm": rec.tx_power_dbm,
                "manufacturer_id": rec.manufacturer_id,
                "manufacturer": mfr,
                "vendor": vendor,
                "service_uuids": rec.service_uuids,
                "adv_data": rec.adv_data,
                "connectable": rec.connectable,
                "bonded": rec.bonded,
                "channel": rec.channel,
                "timestamp": now,
                "node_id": body.node_id,
            }
        )

    inserted = await asyncio.to_thread(store.insert_bt_devices, records)

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(request.app.state, "cross_correlator", None)
    if cross_correlator and _corr_throttle.should_run(body.node_id):
        try:
            bt_events = [
                {"freq_hz": 2441e6, "timestamp": r["timestamp"], "id": r["device_addr"]}
                for r in records
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "bt", bt_events, body.node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    # -- Anomaly scoring ---------------------------------------------------
    anomaly_count = 0
    bt_scorer = getattr(request.app.state, "bt_scorer", None)
    if bt_scorer is not None:
        try:
            anomaly_results = await asyncio.to_thread(
                bt_scorer.score_batch,
                records,
                body.node_id,
            )

            anomaly_rows: list[dict[str, Any]] = []
            for result in anomaly_results:
                if result.anomaly_score >= _BT_ANOMALY_INSERT_THRESHOLD:
                    anomaly_count += 1
                    anomaly_rows.append(
                        {
                            "device_addr": result.device_addr,
                            "device_name": result.device_name,
                            "device_type": result.device_type,
                            "manufacturer": result.manufacturer,
                            "rssi_dbm": result.rssi_dbm,
                            "anomaly_score": result.anomaly_score,
                            "priority": result.priority,
                            "dimensions": result.dimensions,
                            "reasons": result.reasons,
                            "baseline_status": result.baseline_status,
                            "node_id": body.node_id,
                            "timestamp": now,
                        }
                    )

            if anomaly_rows:
                await asyncio.to_thread(
                    store.insert_bt_anomalies_batch,
                    anomaly_rows,
                )

            if anomaly_count > 0:
                await _broadcast_bt(
                    app_state,
                    {
                        "type": "bt_anomaly",
                        "count": anomaly_count,
                        "timestamp": now,
                    },
                )

        except Exception as exc:
            logger.warning("Bluetooth anomaly scoring failed: %s", exc)

    app_state.log_activity(
        event_type="bt_ingest",
        node_id=body.node_id,
        message=f"Bluetooth scan: {inserted}/{len(body.records)} devices stored, {anomaly_count} anomalies",
    )

    # Broadcast to BT WebSocket clients
    await _broadcast_bt(
        app_state,
        {
            "type": "bt_ingest",
            "node_id": body.node_id,
            "count": inserted,
            "timestamp": now,
        },
    )

    logger.info(
        "Bluetooth scan from %s: %d/%d inserted, %d anomalies",
        body.node_id,
        inserted,
        len(body.records),
        anomaly_count,
    )

    return {
        "accepted": True,
        "inserted": inserted,
        "total": len(body.records),
        "anomalies": anomaly_count,
    }


# ---------------------------------------------------------------------------
# POST /ingest-summary — edge-aggregated BT summary ingest
# ---------------------------------------------------------------------------

_BT_SUMMARY_MAX_DEVICES = int(os.environ.get("BRIDGE_BT_SUMMARY_MAX_DEVICES", "500"))


@router.post("/ingest-summary", status_code=status.HTTP_201_CREATED)
async def ingest_bt_summary(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Ingest an edge-aggregated BT summary.

    Mirrors ``POST /ingest-summary`` for WiFi: collapses N observations
    per unique ``device_addr`` per scan window into a single aggregate
    row, replacing per-observation raw uploads. Each summary device is
    written to ``bt_devices`` as a single row with ``rssi_avg_dbm``
    mapped to the row's ``rssi_dbm`` column; the periodic cleanup loop
    then rolls these into ``bt_devices_hourly`` the same as raw rows.

    The body is read via ``read_json_body`` because the edge scanner
    gzips this POST (Content-Encoding: gzip) — a declared Pydantic body
    parameter would reject the compressed bytes with a 400 before the
    handler runs.
    """
    payload = await read_json_body(request)
    try:
        body = BtSummaryBatch(**payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload: {exc}",
        )
    await enforce_node_binding(request, _key_id, body.node_id)

    # Truncate oversized summaries.
    if len(body.devices) > _BT_SUMMARY_MAX_DEVICES:
        body.devices = body.devices[:_BT_SUMMARY_MAX_DEVICES]

    store = _get_detection_store(request)
    now = datetime.now(timezone.utc).isoformat()

    records: list[dict[str, Any]] = []
    for dev in body.devices:
        vendor = lookup_vendor(dev.device_addr) if dev.device_addr else ""
        manufacturer = dev.manufacturer or vendor
        records.append(
            {
                "device_addr": dev.device_addr,
                "device_name": dev.device_name,
                "device_type": dev.device_type,
                "device_class": 0,
                "device_class_name": "",
                "appearance": 0,
                "rssi_dbm": dev.rssi_avg_dbm,
                "tx_power_dbm": None,
                "manufacturer_id": dev.manufacturer_id,
                "manufacturer": manufacturer,
                "vendor": vendor,
                "service_uuids": dev.service_uuids,
                "adv_data": {},
                "connectable": True,
                "bonded": False,
                "channel": dev.channel,
                "timestamp": now,
                "node_id": body.node_id,
            }
        )

    inserted = await asyncio.to_thread(store.insert_bt_devices, records)

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(request.app.state, "cross_correlator", None)
    if cross_correlator:
        try:
            bt_events = [
                {"freq_hz": 2441e6, "timestamp": r["timestamp"], "id": r["device_addr"]}
                for r in records
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "bt", bt_events, body.node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    return {
        "accepted": True,
        "inserted": inserted,
        "devices": len(body.devices),
        "total_observations": body.total_observations,
    }


# ---------------------------------------------------------------------------
# GET /anomalies — query BT anomalies
# ---------------------------------------------------------------------------


@router.get("/anomalies")
async def get_bt_anomalies(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return Bluetooth anomalies above score threshold."""
    store = _get_detection_store(request)
    anomalies = await asyncio.to_thread(
        store.get_bt_anomalies,
        min_score=min_score,
        limit=limit,
        node_id=node_id,
    )
    total = await asyncio.to_thread(store.count_bt_anomalies, min_score=min_score)
    return {
        "count": len(anomalies),
        "total": total,
        "anomalies": anomalies,
    }


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/dismiss — bulk dismiss BT anomalies
# (must be registered before the {anomaly_id} path param route)
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/dismiss")
async def dismiss_bt_anomalies_bulk(
    request: Request,
    body: _BulkDismissBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Bulk dismiss up to 100 Bluetooth anomalies."""
    ids = body.ids
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ids must be a non-empty list",
        )
    ids = ids[:100]
    store = _get_detection_store(request)
    count = await asyncio.to_thread(store.dismiss_bt_anomalies_bulk, ids)

    def _audit_bulk_dismiss():
        for aid in ids:
            store.log_audit(action="bt_anomaly_bulk_dismiss", target_id=str(aid))

    await asyncio.to_thread(_audit_bulk_dismiss)
    return {"ok": True, "dismissed_count": count}


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/snooze — snooze up to 100 BT anomalies
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/snooze")
async def snooze_bt_anomalies_bulk(
    request: Request,
    body: _BulkSnoozeBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Snooze up to 100 Bluetooth anomalies for a specified duration."""
    ids = body.ids
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ids must be a non-empty list",
        )
    ids = ids[:100]
    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    store = _get_detection_store(request)
    count = await asyncio.to_thread(store.snooze_bt_anomalies_bulk, ids, until)

    def _audit_bulk_snooze():
        for aid in ids:
            store.log_audit(
                action="bt_anomaly_snooze",
                target_id=str(aid),
                note=f"Snoozed for {body.hours}h until {until}",
            )

    await asyncio.to_thread(_audit_bulk_snooze)
    return {"ok": True, "snoozed_count": count, "snoozed_until": until}


# ---------------------------------------------------------------------------
# PUT /anomalies/{anomaly_id}/dismiss — dismiss single BT anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/dismiss")
async def dismiss_bt_anomaly(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Dismiss a single Bluetooth anomaly."""
    store = _get_detection_store(request)
    await asyncio.to_thread(store.dismiss_bt_anomaly, anomaly_id)
    await asyncio.to_thread(
        store.log_audit,
        action="bt_anomaly_dismiss",
        target_id=str(anomaly_id),
    )
    return {"ok": True, "dismissed": anomaly_id}


# ---------------------------------------------------------------------------
# PUT /anomalies/{anomaly_id}/snooze — snooze single BT anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/snooze")
async def snooze_bt_anomaly(
    anomaly_id: int,
    request: Request,
    body: _SnoozeBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Snooze a single Bluetooth anomaly for a specified duration."""
    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    store = _get_detection_store(request)
    await asyncio.to_thread(store.snooze_bt_anomaly, anomaly_id, until)
    await asyncio.to_thread(
        store.log_audit,
        action="bt_anomaly_snooze",
        target_id=str(anomaly_id),
        note=f"Snoozed for {body.hours}h until {until}",
    )
    return {"ok": True, "snoozed": anomaly_id, "snoozed_until": until}


# ---------------------------------------------------------------------------
# WebSocket: real-time Bluetooth event stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/bluetooth")
async def ws_bluetooth(websocket: WebSocket) -> None:
    """Stream Bluetooth events to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_bluetooth_clients.add(websocket)
    logger.info("Bluetooth WS client connected: %s", key_id)

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
        await app_state.ws_bluetooth_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("Bluetooth WS client disconnected: %s", key_id)


# ---------------------------------------------------------------------------
# Shared vuln scanner instance (stateless, safe to reuse)
# ---------------------------------------------------------------------------

_vuln_scanner = BtVulnScanner()


# ---------------------------------------------------------------------------
# GET /vulnerabilities — vulnerability assessment for known BT devices
# ---------------------------------------------------------------------------


@router.get("/vulnerabilities")
async def get_bt_vulnerabilities(
    request: Request,
    device_type: str | None = Query(
        None, description="Filter: classic, ble, dual, unknown"
    ),
    node_id: str | None = Query(None),
    min_risk: float = Query(
        0.0, ge=0.0, le=1.0, description="Minimum risk score filter"
    ),
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Assess known Bluetooth devices for vulnerabilities.

    Fetches the latest device records from the store, runs each through
    the BtVulnScanner, and returns per-device risk assessments sorted
    by risk score descending.  Use ``min_risk`` to filter out low-risk
    devices.
    """
    store = _get_detection_store(request)
    devices = await asyncio.to_thread(
        store.get_bt_devices,
        limit=limit,
        device_type=device_type,
        node_id=node_id,
    )

    assessments = _vuln_scanner.assess_batch(devices)

    if min_risk > 0.0:
        assessments = [a for a in assessments if a["risk_score"] >= min_risk]

    return {
        "count": len(assessments),
        "assessments": assessments,
    }


# ---------------------------------------------------------------------------
# GET /vulnerabilities/summary — aggregate risk summary
# ---------------------------------------------------------------------------


@router.get("/vulnerabilities/summary")
async def get_bt_vuln_summary(
    request: Request,
    device_type: str | None = Query(None),
    node_id: str | None = Query(None),
    limit: int = Query(500, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return an aggregate risk summary for all known Bluetooth devices.

    Fetches devices, runs vulnerability assessment on each, and returns
    risk distribution, CVE frequency, critical device list, and top flags.
    """
    store = _get_detection_store(request)
    devices = await asyncio.to_thread(
        store.get_bt_devices,
        limit=limit,
        device_type=device_type,
        node_id=node_id,
    )

    assessments = _vuln_scanner.assess_batch(devices)
    summary = _vuln_scanner.get_risk_summary(assessments)

    return summary


# ---------------------------------------------------------------------------
# Broadcast helper
# ---------------------------------------------------------------------------


async def _broadcast_bt(
    app_state: AppState,
    data: dict[str, Any],
) -> None:
    """Push Bluetooth event to all connected BT WS clients."""
    await app_state.ws_bluetooth_clients.broadcast(data)
