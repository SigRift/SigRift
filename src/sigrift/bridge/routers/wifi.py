"""WiFi SIGINT API router for The Bridge.

Provides endpoints for WiFi network discovery, client association
tracking, channel utilization heatmaps, signal timelines, and
real-time WiFi event streaming via WebSocket.

WiFi metadata enriches existing RF detections classified as OFDM
variants in the 2.4/5/6 GHz bands.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
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
from fastapi.responses import Response as RawResponse

from pydantic import BaseModel as _BaseModel, Field

from sigrift.bridge.dependencies import (
    Role,
    enforce_node_binding,
    get_ws_limiter,
    read_json_body,
    require_role,
    require_ws_auth,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import WifiMetadataBatch, WifiSummaryBatch
from sigrift.bridge.oui_lookup import lookup_vendor
from sigrift.bridge.correlation_engine import PerNodeThrottle
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store


class _BulkDismissBody(_BaseModel):
    ids: list[int]


class _BulkReevaluateBody(_BaseModel):
    ids: list[int]


class _SnoozeBody(_BaseModel):
    hours: int = Field(ge=1, le=168, description="Snooze duration in hours (1-168)")


class _BulkSnoozeBody(_BaseModel):
    ids: list[int]
    hours: int = Field(ge=1, le=168)


class _BulkEscalateBody(_BaseModel):
    model_config = {"extra": "forbid"}

    ids: list[int] = Field(..., min_length=1, max_length=100)


logger = logging.getLogger(__name__)

# Per-uvicorn-worker throttle on cross-correlation: a chatty wifi scanner
# was firing _query_nearby_detections on every ingest, pegging an executor
# thread. Mirrors the SDR throttle in routers/detections.py (every Nth
# batch per node_id).
_corr_throttle = PerNodeThrottle(every_n=5)

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SSID_MAX_BYTES = 32
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")

_WIFI_ANOMALY_ALERT_THRESHOLD = 0.7
_WIFI_ANOMALY_CRITICAL_THRESHOLD = 0.85
_WIFI_ANOMALY_COOLDOWN_SECONDS = 300  # 5 minutes per BSSID

# MAC anonymization secret — generated on first use, persisted to disk
_mac_secret: bytes | None = None

# Well-known path next to .master_key
_MAC_SECRET_PATH = Path(__file__).resolve().parent.parent / "data" / ".mac_secret"


def _get_mac_secret(request: Request) -> bytes:
    """Get or load/generate the MAC anonymization secret.

    On first call the secret is loaded from disk if the file exists,
    otherwise a new 32-byte secret is generated and persisted so that
    MAC anonymization remains stable across restarts.
    """
    global _mac_secret
    if _mac_secret is not None:
        return _mac_secret

    import os

    secret_path = _MAC_SECRET_PATH
    if secret_path.is_file():
        _mac_secret = secret_path.read_bytes()
        logger.info("Loaded MAC anonymization secret from %s", secret_path)
    else:
        _mac_secret = os.urandom(32)
        try:
            secret_path.parent.mkdir(parents=True, exist_ok=True)
            secret_path.write_bytes(_mac_secret)
            os.chmod(str(secret_path), 0o600)
            logger.info(
                "Generated and persisted MAC anonymization secret to %s", secret_path
            )
        except OSError as exc:
            logger.warning("Failed to persist MAC secret to %s: %s", secret_path, exc)

    return _mac_secret


def _sanitize_ssid(ssid: str) -> str:
    """Normalize an SSID for storage.

    - Strip control characters (0x00-0x1F, 0x7F)
    - Truncate to 32 bytes (802.11 max)

    The SSID is stored as heard, not HTML-escaped: every page escapes it
    where it renders it, so escaping here too showed entities such as
    ``&#x27;`` in place of the text.
    """
    # Strip control characters
    cleaned = _CONTROL_CHAR_RE.sub("", ssid)
    # Truncate to 32 bytes
    encoded = cleaned.encode("utf-8")[:_SSID_MAX_BYTES]
    return encoded.decode("utf-8", errors="ignore")


_get_detection_store = get_detection_store


async def _maybe_create_wifi_alert(
    app_state: Any,
    persistence: Any,
    result: Any,
    node_id: str,
    notifier: Any = None,
) -> bool:
    """Create an alert for a critical WiFi anomaly with rate limiting.

    Returns True if an alert was created.
    """
    # Read thresholds from detection config (app.state) with fallbacks
    det_cfg = getattr(app_state, "_detection_config", None) or {}
    alert_threshold = det_cfg.get(
        "wifi_anomaly_alert_threshold",
        _WIFI_ANOMALY_ALERT_THRESHOLD,
    )
    critical_threshold = det_cfg.get(
        "wifi_anomaly_critical_threshold",
        _WIFI_ANOMALY_CRITICAL_THRESHOLD,
    )
    cooldown_seconds = det_cfg.get(
        "wifi_anomaly_cooldown_seconds",
        _WIFI_ANOMALY_COOLDOWN_SECONDS,
    )

    if result.score < alert_threshold:
        return False

    now = time.monotonic()
    cooldown_key = ("wifi", result.bssid)

    # A BSSID that never alerted has no cooldown (a 0.0 default would mean
    # "alerted at monotonic 0", i.e. at host boot, and suppress its first
    # alert for the first cooldown period after a reboot).
    last_alert = app_state.anomaly_alert_cooldowns.get(cooldown_key)
    if last_alert is not None and now - last_alert < cooldown_seconds:
        return False

    severity = "critical" if result.score >= critical_threshold else "warning"

    # Determine dominant attack dimension for context
    dims = result.dimensions if hasattr(result, "dimensions") else {}
    from sigrift.bridge.detection_store import DetectionStore

    attack_type = DetectionStore._wifi_attack_type(dims)

    alert = {
        "alert_id": app_state.next_alert_id(),
        "name": "wifi_anomaly_detected",
        "severity": severity,
        "message": html.escape(
            f"WiFi anomaly score {result.score:.2f} for "
            f"{result.ssid or result.bssid} on {node_id}"
        ),
        "node_id": node_id,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "acknowledged": False,
        "acknowledged_at": None,
        "bssid": result.bssid,
        "anomaly_score": result.score,
        "attack_type": attack_type,
    }

    persistence.add_alert(alert)
    app_state.anomaly_alert_cooldowns[cooldown_key] = now

    # Webhooks and syslog, in the background (never awaited here: an
    # unreachable endpoint must not hold up the ingest request)
    from sigrift.bridge.routers.detections import _dispatch_alert

    _dispatch_alert(app_state, notifier, alert, syslog_fields={"signal_class": "wifi"})

    app_state.log_activity(
        event_type="wifi_anomaly_alert",
        node_id=node_id,
        message=f"WiFi auto-alert: anomaly score {result.score:.2f} for {result.ssid or result.bssid}",
        details={
            "bssid": result.bssid,
            "anomaly_score": result.score,
            "severity": severity,
            "dimensions": result.dimensions,
            "attack_type": attack_type,
        },
    )

    logger.info(
        "WiFi auto-alert: %s score=%.2f bssid=%s node=%s",
        severity,
        result.score,
        result.bssid,
        node_id,
    )
    return True


# ---------------------------------------------------------------------------
# GET /networks — list discovered WiFi networks
# ---------------------------------------------------------------------------


@router.get("/networks")
async def get_networks(
    request: Request,
    band: str | None = Query(None, description="Band filter: 2.4GHz, 5GHz, 6GHz"),
    node_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List discovered WiFi networks aggregated by BSSID."""
    store = _get_detection_store(request)
    networks = await asyncio.to_thread(
        store.get_wifi_networks, limit=limit, band=band, node_id=node_id
    )
    return {
        "count": len(networks),
        "networks": networks,
    }


# ---------------------------------------------------------------------------
# GET /networks/{bssid} — detail for a specific network
# ---------------------------------------------------------------------------


@router.get("/networks/{bssid}")
async def get_network_detail(
    bssid: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return detail for a specific WiFi network including clients and signal history."""
    store = _get_detection_store(request)

    network = await asyncio.to_thread(store.get_wifi_network_detail, bssid)

    if network is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Network {bssid!r} not found",
        )

    clients, timeline = await asyncio.gather(
        asyncio.to_thread(store.get_wifi_clients, bssid=bssid, limit=200),
        asyncio.to_thread(store.get_wifi_timeline, bssid=bssid, hours=24),
    )

    return {
        "network": network,
        "clients": clients,
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# GET /clients — all observed client associations
# ---------------------------------------------------------------------------


@router.get("/clients")
async def get_clients(
    request: Request,
    bssid: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return all observed WiFi client associations."""
    store = _get_detection_store(request)
    clients = await asyncio.to_thread(store.get_wifi_clients, bssid=bssid, limit=limit)
    return {
        "count": len(clients),
        "clients": clients,
    }


# ---------------------------------------------------------------------------
# GET /channels — channel utilization heatmap data
# ---------------------------------------------------------------------------


@router.get("/channels")
async def get_channels(
    request: Request,
    band: str = Query("2.4GHz", description="Band: 2.4GHz, 5GHz, 6GHz"),
    node_id: str | None = Query(None),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return per-channel utilization data for heatmap rendering."""
    store = _get_detection_store(request)
    channels = await asyncio.to_thread(
        store.get_wifi_channel_utilization, band=band, node_id=node_id
    )
    return {
        "band": band,
        "count": len(channels),
        "channels": channels,
    }


# ---------------------------------------------------------------------------
# GET /timeline — signal strength timeline
# ---------------------------------------------------------------------------


@router.get("/timeline")
async def get_timeline(
    request: Request,
    bssid: str | None = Query(None),
    hours: int = Query(24, ge=1, le=168),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return signal strength timeline for a WiFi network."""
    store = _get_detection_store(request)
    timeline = await asyncio.to_thread(
        store.get_wifi_timeline, bssid=bssid, hours=hours
    )
    return {
        "hours": hours,
        "bssid": bssid,
        "count": len(timeline),
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# GET /stats — WiFi summary statistics
# ---------------------------------------------------------------------------


@router.get("/stats")
async def get_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return WiFi summary statistics."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(store.get_wifi_stats)


# ---------------------------------------------------------------------------
# POST /ingest — batch ingest WiFi metadata from edge nodes
# ---------------------------------------------------------------------------


_wifi_ingest_cooldown: dict[str, float] = {}  # node_id -> last ingest timestamp
_WIFI_INGEST_MIN_INTERVAL = float(
    os.environ.get("BRIDGE_WIFI_INGEST_INTERVAL", "5")
)  # seconds
_WIFI_INGEST_MAX_RECORDS = int(os.environ.get("BRIDGE_WIFI_INGEST_MAX_RECORDS", "500"))


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_wifi_metadata(
    body: WifiMetadataBatch,
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Batch ingest WiFi metadata from an edge node.

    Rate-limited per node (BRIDGE_WIFI_INGEST_INTERVAL, default 5s).
    Truncates batches to BRIDGE_WIFI_INGEST_MAX_RECORDS (default 500).
    """
    import time as _time

    await enforce_node_binding(request, _key_id, body.node_id)

    # Per-node rate limiting
    now_ts = _time.monotonic()
    last = _wifi_ingest_cooldown.get(body.node_id)
    if last is not None and now_ts - last < _WIFI_INGEST_MIN_INTERVAL:
        return {"status": "throttled", "inserted": 0, "reason": "rate limited"}
    _wifi_ingest_cooldown[body.node_id] = now_ts

    # Truncate oversized batches
    if len(body.records) > _WIFI_INGEST_MAX_RECORDS:
        body.records = body.records[:_WIFI_INGEST_MAX_RECORDS]

    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state
    mac_secret = _get_mac_secret(request)

    now = datetime.now(timezone.utc).isoformat()

    records = []
    bssid_vendor: dict[str, str] = {}
    for rec in body.records:
        # Resolve vendors BEFORE anonymization (needs original MACs)
        vendor = lookup_vendor(rec.bssid)
        client_vendor = lookup_vendor(rec.client_mac)
        if vendor:
            bssid_vendor[rec.bssid] = vendor
        # Anonymize client_mac BEFORE records reach scorer or store
        client_mac = rec.client_mac
        if mac_secret and client_mac:
            client_mac = DetectionStore._anonymize_mac(client_mac, mac_secret)
        records.append(
            {
                "detection_id": uuid.uuid4().hex[:16],
                "bssid": rec.bssid,
                "ssid": _sanitize_ssid(rec.ssid),
                "channel": rec.channel,
                "channel_width": rec.channel_width,
                "band": rec.band,
                # Radio text is stored as received; pages escape on output.
                "security": rec.security,
                "signal_dbm": rec.signal_dbm,
                "noise_dbm": rec.noise_dbm,
                "frame_type": rec.frame_type,
                "client_mac": client_mac,
                "data_rate_mbps": rec.data_rate_mbps,
                "retry_flag": rec.retry_flag,
                "timestamp": now,
                "node_id": body.node_id,
                "vendor": vendor,
                "client_vendor": client_vendor,
            }
        )

    # MACs already anonymized — skip re-anonymization in store
    inserted = await asyncio.to_thread(
        store.insert_wifi_metadata,
        records,
    )

    logger.info(
        "Raw WiFi ingest from node %s — consider enabling MLRF_WIFI_SUMMARIZE=1",
        body.node_id,
    )

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(request.app.state, "cross_correlator", None)
    if cross_correlator and _corr_throttle.should_run(body.node_id):
        try:
            wifi_events = [
                {
                    "channel": r["channel"],
                    "timestamp": r["timestamp"],
                    "id": r["detection_id"],
                }
                for r in records
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "wifi", wifi_events, body.node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    # -- Anomaly scoring (offloaded to thread to avoid blocking) -----------
    anomaly_count = 0
    anomaly_ids: list[int] = []
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is not None:
        try:
            anomaly_results = await asyncio.to_thread(
                wifi_scorer.score_batch,
                records,
                body.node_id,
            )
            persistence = request.app.state.persistence
            alerts_created = 0

            # Read configurable insert threshold
            det_cfg = getattr(request.app.state, "detection_config", None) or {}
            insert_threshold = det_cfg.get("wifi_anomaly_insert_threshold", 0.4)

            # Collect anomalies for batch insert
            anomaly_rows: list[dict[str, Any]] = []
            for result in anomaly_results:
                if result.score >= insert_threshold:
                    anomaly_count += 1
                    # Frame text is stored as received; pages escape on output.
                    safe_frames = [dict(fr) for fr in result.frame_capture]

                    anomaly_rows.append(
                        {
                            "bssid": result.bssid,
                            "ssid": result.ssid,
                            "channel": result.channel,
                            "band": result.band,
                            "security": result.security,
                            "signal_dbm": result.signal_dbm,
                            "anomaly_score": result.score,
                            "priority": result.priority,
                            "dimensions": result.dimensions,
                            "reasons": result.reasons,
                            "baseline_status": result.baseline_status,
                            "node_id": body.node_id,
                            "timestamp": now,
                            "vendor": bssid_vendor.get(result.bssid, ""),
                            "client_count": result.client_count,
                            "retry_rate": result.retry_rate,
                            "noise_dbm_max": result.noise_dbm_max,
                            "data_rate_min": result.data_rate_min,
                            "data_rate_max": result.data_rate_max,
                            "channel_width": result.channel_width,
                            "frame_count": result.frame_count,
                            "deauth_count": result.deauth_count,
                            "frame_type_counts": result.frame_type_counts,
                            "expected_signal": result.expected_signal,
                            "signal_zscore": result.signal_zscore,
                            "expected_channel": result.expected_channel,
                            "expected_security": result.expected_security,
                            "expected_client_count": result.expected_client_count,
                            "expected_retry_rate": result.expected_retry_rate,
                            "baseline_observations": result.baseline_observations,
                            "client_macs": result.client_macs,
                            "frame_capture": safe_frames,
                        }
                    )

                    alert_thresh = det_cfg.get(
                        "wifi_anomaly_alert_threshold",
                        _WIFI_ANOMALY_ALERT_THRESHOLD,
                    )
                    if result.score >= alert_thresh:
                        notifier = getattr(request.app.state, "notifier", None)
                        created = await _maybe_create_wifi_alert(
                            app_state,
                            persistence,
                            result,
                            body.node_id,
                            notifier=notifier,
                        )
                        if created:
                            alerts_created += 1

            if anomaly_rows:
                anomaly_ids = await asyncio.to_thread(
                    store.insert_wifi_anomalies_batch,
                    anomaly_rows,
                    auto_snooze_seen_count=int(
                        det_cfg.get("wifi_auto_snooze_seen_count", 0)
                    ),
                    auto_snooze_max_score=float(
                        det_cfg.get("wifi_auto_snooze_max_score", 0)
                    ),
                    auto_snooze_hours=int(det_cfg.get("wifi_auto_snooze_hours", 0)),
                )

            if anomaly_count > 0:
                await _broadcast_wifi(
                    app_state,
                    {
                        "type": "wifi_anomaly",
                        "count": anomaly_count,
                        "timestamp": now,
                    },
                )

        except Exception as exc:
            logger.warning("WiFi anomaly scoring failed: %s", exc)

    app_state.log_activity(
        event_type="wifi_ingest",
        node_id=body.node_id,
        message=f"WiFi metadata: {inserted}/{len(body.records)} records stored, {anomaly_count} anomalies",
    )

    # Broadcast to WiFi WebSocket clients
    await _broadcast_wifi(
        app_state,
        {
            "type": "wifi_ingest",
            "node_id": body.node_id,
            "count": inserted,
            "timestamp": now,
        },
    )

    logger.info(
        "WiFi metadata from %s: %d/%d inserted, %d anomalies",
        body.node_id,
        inserted,
        len(body.records),
        anomaly_count,
    )

    resp: dict[str, Any] = {
        "accepted": True,
        "inserted": inserted,
        "total": len(body.records),
        "anomalies": anomaly_count,
    }
    # Include anomaly IDs so edge nodes can upload pcap captures
    if anomaly_count > 0:
        resp["anomaly_ids"] = anomaly_ids
    return resp


# ---------------------------------------------------------------------------
# POST /ingest-summary — edge-aggregated WiFi summary ingest
# ---------------------------------------------------------------------------

_WIFI_SUMMARY_MAX_NETWORKS = int(
    os.environ.get("BRIDGE_WIFI_SUMMARY_MAX_NETWORKS", "500")
)


@router.post("/ingest-summary", status_code=status.HTTP_201_CREATED)
async def ingest_wifi_summary(
    request: Request,
    _key_id: str = Depends(require_role(Role.SENSOR)),
) -> dict[str, Any]:
    """Ingest an edge-aggregated WiFi summary.

    Accepts compact per-BSSID summaries instead of raw per-frame records,
    reducing SQLite write pressure from high-frame-rate edge nodes.

    Reads the body via ``read_json_body`` so gzipped scanner uploads
    (Content-Encoding: gzip) are accepted — same contract as the BT
    summary route.
    """
    import time as _time

    payload = await read_json_body(request)
    try:
        body = WifiSummaryBatch(**payload)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload: {exc}",
        )
    await enforce_node_binding(request, _key_id, body.node_id)

    # Per-node rate limiting (reuse raw ingest cooldown)
    now_ts = _time.monotonic()
    last = _wifi_ingest_cooldown.get(body.node_id)
    if last is not None and now_ts - last < _WIFI_INGEST_MIN_INTERVAL:
        return {"status": "throttled", "inserted": 0, "reason": "rate limited"}
    _wifi_ingest_cooldown[body.node_id] = now_ts

    # Truncate oversized summaries
    if len(body.networks) > _WIFI_SUMMARY_MAX_NETWORKS:
        body.networks = body.networks[:_WIFI_SUMMARY_MAX_NETWORKS]

    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state
    _get_mac_secret(request)
    now = datetime.now(timezone.utc).isoformat()

    records = []
    bssid_vendor: dict[str, str] = {}
    for net in body.networks:
        vendor = lookup_vendor(net.bssid)
        if vendor:
            bssid_vendor[net.bssid] = vendor
        records.append(
            {
                "detection_id": uuid.uuid4().hex[:16],
                "bssid": net.bssid,
                "ssid": _sanitize_ssid(net.ssid),
                "channel": net.channel or 0,
                "channel_width": net.channel_width or 20,
                "band": net.band or "2.4GHz",
                "security": net.security,
                "signal_dbm": net.signal_avg_dbm,
                "noise_dbm": 0.0,
                "frame_type": "summary",
                "client_mac": "",
                "data_rate_mbps": 0.0,
                "retry_flag": 0,
                "timestamp": now,
                "node_id": body.node_id,
                "vendor": vendor,
                "client_vendor": "",
            }
        )

    inserted = await asyncio.to_thread(store.insert_wifi_metadata, records)

    # -- Cross-correlation (fire-and-forget) --------------------------------
    cross_correlator = getattr(request.app.state, "cross_correlator", None)
    if cross_correlator and _corr_throttle.should_run(body.node_id):
        try:
            wifi_events = [
                {
                    "channel": r["channel"],
                    "timestamp": r["timestamp"],
                    "id": r["detection_id"],
                }
                for r in records
            ]
            await asyncio.to_thread(
                cross_correlator.correlate, "wifi", wifi_events, body.node_id
            )
        except Exception as e:
            logger.debug("Cross-correlation error: %s", e)

    # -- Anomaly scoring on summary data ------------------------------------
    anomaly_count = 0
    anomaly_ids: list[int] = []
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is not None:
        try:
            # Inject summary-level indicators into records for the scorer
            summary_hints = []
            for rec, net in zip(records, body.networks):
                rec_copy = dict(rec)
                # Deauth indicator: any deauths in this summary window
                if body.deauth_count > 0:
                    rec_copy["_deauth_indicator"] = True
                # Frame weight for scorer context
                rec_copy["_frame_count"] = net.frame_count
                rec_copy["_client_count"] = net.client_count
                rec_copy["_signal_max_dbm"] = net.signal_max_dbm
                summary_hints.append(rec_copy)

            anomaly_results = await asyncio.to_thread(
                wifi_scorer.score_batch,
                summary_hints,
                body.node_id,
            )
            persistence = request.app.state.persistence

            det_cfg = getattr(request.app.state, "detection_config", None) or {}
            insert_threshold = det_cfg.get("wifi_anomaly_insert_threshold", 0.4)

            anomaly_rows: list[dict[str, Any]] = []
            for result in anomaly_results:
                if result.score >= insert_threshold:
                    anomaly_count += 1
                    safe_frames = [dict(fr) for fr in result.frame_capture]

                    anomaly_rows.append(
                        {
                            "bssid": result.bssid,
                            "ssid": result.ssid,
                            "channel": result.channel,
                            "band": result.band,
                            "security": result.security,
                            "signal_dbm": result.signal_dbm,
                            "anomaly_score": result.score,
                            "priority": result.priority,
                            "dimensions": result.dimensions,
                            "reasons": result.reasons,
                            "baseline_status": result.baseline_status,
                            "node_id": body.node_id,
                            "timestamp": now,
                            "vendor": bssid_vendor.get(result.bssid, ""),
                            "client_count": result.client_count,
                            "retry_rate": result.retry_rate,
                            "noise_dbm_max": result.noise_dbm_max,
                            "data_rate_min": result.data_rate_min,
                            "data_rate_max": result.data_rate_max,
                            "channel_width": result.channel_width,
                            "frame_count": result.frame_count,
                            "deauth_count": result.deauth_count,
                            "frame_type_counts": result.frame_type_counts,
                            "expected_signal": result.expected_signal,
                            "signal_zscore": result.signal_zscore,
                            "expected_channel": result.expected_channel,
                            "expected_security": result.expected_security,
                            "expected_client_count": result.expected_client_count,
                            "expected_retry_rate": result.expected_retry_rate,
                            "baseline_observations": result.baseline_observations,
                            "client_macs": result.client_macs,
                            "frame_capture": safe_frames,
                        }
                    )

                    alert_thresh = det_cfg.get(
                        "wifi_anomaly_alert_threshold",
                        _WIFI_ANOMALY_ALERT_THRESHOLD,
                    )
                    if result.score >= alert_thresh:
                        notifier = getattr(request.app.state, "notifier", None)
                        await _maybe_create_wifi_alert(
                            app_state,
                            persistence,
                            result,
                            body.node_id,
                            notifier=notifier,
                        )

            if anomaly_rows:
                anomaly_ids = await asyncio.to_thread(
                    store.insert_wifi_anomalies_batch,
                    anomaly_rows,
                    auto_snooze_seen_count=int(
                        det_cfg.get("wifi_auto_snooze_seen_count", 0)
                    ),
                    auto_snooze_max_score=float(
                        det_cfg.get("wifi_auto_snooze_max_score", 0)
                    ),
                    auto_snooze_hours=int(det_cfg.get("wifi_auto_snooze_hours", 0)),
                )

            if anomaly_count > 0:
                await _broadcast_wifi(
                    app_state,
                    {
                        "type": "wifi_anomaly",
                        "count": anomaly_count,
                        "timestamp": now,
                    },
                )

        except Exception as exc:
            logger.warning("WiFi summary anomaly scoring failed: %s", exc)

    app_state.log_activity(
        event_type="wifi_ingest_summary",
        node_id=body.node_id,
        message=(
            f"WiFi summary: {inserted} networks from {body.total_frames} frames, "
            f"{anomaly_count} anomalies, {body.deauth_count} deauths"
        ),
    )

    await _broadcast_wifi(
        app_state,
        {
            "type": "wifi_ingest_summary",
            "node_id": body.node_id,
            "networks": inserted,
            "total_frames": body.total_frames,
            "timestamp": now,
        },
    )

    logger.info(
        "WiFi summary from %s: %d networks from %d frames, %d anomalies",
        body.node_id,
        inserted,
        body.total_frames,
        anomaly_count,
    )

    resp: dict[str, Any] = {
        "accepted": True,
        "inserted": inserted,
        "networks": len(body.networks),
        "total_frames": body.total_frames,
        "anomalies": anomaly_count,
    }
    if anomaly_count > 0:
        resp["anomaly_ids"] = anomaly_ids
    return resp


# ---------------------------------------------------------------------------
# GET /anomalies — query WiFi anomalies
# ---------------------------------------------------------------------------


@router.get("/anomalies")
async def get_wifi_anomalies(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
    node_id: str | None = Query(None),
    include_frames: bool = Query(False),
    reevaluate: bool = Query(
        False, description="Re-evaluate each anomaly against current baselines"
    ),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return WiFi anomalies above score threshold.

    When *reevaluate=true*, each anomaly is re-scored against current
    baselines and an inline ``reeval`` dict is appended with
    ``still_anomalous``, ``new_score``, ``score_delta``, etc.
    """
    store = _get_detection_store(request)
    anomalies = await asyncio.to_thread(
        store.get_wifi_anomalies,
        min_score=min_score,
        limit=limit,
        node_id=node_id,
        include_frames=include_frames,
    )

    reeval_summary: dict[str, int] | None = None
    if reevaluate:
        wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
        if wifi_scorer is not None:
            still_count = 0
            resolved_count = 0
            for anomaly in anomalies:
                try:
                    result = wifi_scorer.reevaluate(anomaly)
                    anomaly["reeval"] = result
                    if result["still_anomalous"]:
                        still_count += 1
                    else:
                        resolved_count += 1
                except Exception as exc:
                    logger.warning(
                        "Inline reevaluate failed for anomaly %s: %s",
                        anomaly.get("id"),
                        exc,
                    )
            reeval_summary = {
                "still_anomalous": still_count,
                "resolved": resolved_count,
            }

    total = await asyncio.to_thread(store.count_wifi_anomalies, min_score=min_score)

    resp: dict[str, Any] = {
        "count": len(anomalies),
        "total": total,
        "anomalies": anomalies,
    }
    if reeval_summary is not None:
        resp["reeval_summary"] = reeval_summary
    return resp


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/dismiss — bulk dismiss WiFi anomalies
# (must be registered before the {anomaly_id} path param route)
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/dismiss")
async def dismiss_wifi_anomalies_bulk(
    request: Request,
    body: _BulkDismissBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Bulk dismiss up to 100 WiFi anomalies."""
    ids = body.ids
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ids must be a non-empty list",
        )
    ids = ids[:100]
    store = _get_detection_store(request)
    count = await asyncio.to_thread(store.dismiss_wifi_anomalies_bulk, ids)

    def _audit_bulk_dismiss():
        for aid in ids:
            store.log_audit(action="wifi_anomaly_bulk_dismiss", target_id=str(aid))

    await asyncio.to_thread(_audit_bulk_dismiss)
    return {"ok": True, "dismissed_count": count}


# ---------------------------------------------------------------------------
# PUT /anomalies/bulk/snooze — snooze up to 100 WiFi anomalies
# ---------------------------------------------------------------------------


@router.put("/anomalies/bulk/snooze")
async def snooze_wifi_anomalies_bulk(
    request: Request,
    body: _BulkSnoozeBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Snooze up to 100 WiFi anomalies for a specified duration."""
    ids = body.ids
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ids must be a non-empty list",
        )
    ids = ids[:100]
    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    store = _get_detection_store(request)
    count = await asyncio.to_thread(store.snooze_wifi_anomalies_bulk, ids, until)

    def _audit_bulk_snooze():
        for aid in ids:
            store.log_audit(
                action="wifi_anomaly_snooze",
                target_id=str(aid),
                note=f"Snoozed for {body.hours}h until {until}",
            )

    await asyncio.to_thread(_audit_bulk_snooze)
    return {"ok": True, "snoozed_count": count, "snoozed_until": until}


# ---------------------------------------------------------------------------
# POST /anomalies/bulk/escalate — one critical alert naming the WiFi anomalies
# (must be registered before the {anomaly_id} path param route)
# ---------------------------------------------------------------------------


def _describe_wifi_anomaly(row: dict[str, Any]) -> str:
    score = float(row.get("anomaly_score") or 0.0)
    network = row.get("ssid") or row.get("bssid") or "an unknown network"
    return (
        f"score {score:.2f} for {network} on {row.get('node_id') or 'an unknown node'}"
    )


def _wifi_escalation_details(
    rows: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    return {"bssids": [row.get("bssid") or "" for row in rows]}, {
        "signal_class": "wifi"
    }


@router.post("/anomalies/bulk/escalate")
async def escalate_wifi_anomalies_bulk(
    request: Request,
    body: _BulkEscalateBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Escalate up to 100 WiFi anomalies: one critical alert, none dismissed.

    Those no unacknowledged ``wifi_anomaly_escalated`` alert names yet
    share one new critical ``wifi_anomaly_escalated`` alert (stored, sent
    to the live alert feed, webhooks and syslog) whose ``alert_id`` the
    answer gives; the others are listed in ``already_escalated``.  IDs
    that match no anomaly are reported in ``not_found``.  Each escalated
    anomaly gets a ``wifi_anomaly_escalate`` audit entry.
    """
    from sigrift.bridge.routers.detections import escalate_anomalies

    store = _get_detection_store(request)
    rows = await asyncio.to_thread(store.get_wifi_anomalies_by_ids, body.ids)
    result = await escalate_anomalies(
        request,
        rows={row["id"]: row for row in rows},
        ids=body.ids,
        alert_name="wifi_anomaly_escalated",
        kind="WiFi",
        describe=_describe_wifi_anomaly,
        details=_wifi_escalation_details,
        operator=_key_id,
    )

    escalated = result["escalated"]

    def _audit_bulk_escalate():
        for anomaly_id in escalated:
            store.log_audit(
                action="wifi_anomaly_escalate",
                target_id=str(anomaly_id),
                operator=_key_id,
                note=f"Raised critical alert {result['alert_id']}",
            )

    await asyncio.to_thread(_audit_bulk_escalate)
    if escalated:
        app_state: AppState = request.app.state.app_state
        app_state.log_activity(
            event_type="wifi_anomaly_bulk_escalated",
            message=f"Escalated {len(escalated)} WiFi anomalies",
            details={"ids": escalated[:20], "alert_id": result["alert_id"]},
        )
    return result


# ---------------------------------------------------------------------------
# POST /anomalies/bulk/reeval-dismiss — re-evaluate ALL and dismiss resolved
# (must be registered before the {anomaly_id} path param route)
# ---------------------------------------------------------------------------


@router.post("/anomalies/bulk/reeval-dismiss")
async def reeval_and_dismiss_all(
    request: Request,
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Re-evaluate the entire WiFi anomaly queue and dismiss resolved ones.

    Processes all active (non-dismissed) anomalies server-side in batches,
    re-scores each against current baselines, and auto-dismisses any that
    no longer meet the anomaly threshold.

    Returns a summary of what was processed.
    """
    store = _get_detection_store(request)
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WiFi scorer not initialized",
        )

    # Fetch all active anomalies (no limit)
    all_anomalies = await asyncio.to_thread(
        store.get_wifi_anomalies,
        min_score=min_score,
        limit=100_000,
        include_frames=False,
    )

    still_count = 0
    resolved_ids: list[int] = []
    errors = 0

    for anomaly in all_anomalies:
        try:
            result = wifi_scorer.reevaluate(anomaly)
            if result["still_anomalous"]:
                still_count += 1
            else:
                aid = anomaly.get("id")
                if aid is not None:
                    resolved_ids.append(aid)
        except Exception:
            errors += 1

    # Bulk dismiss resolved in batches of 500
    dismissed_count = 0
    for i in range(0, len(resolved_ids), 500):
        batch = resolved_ids[i : i + 500]
        dismissed_count += await asyncio.to_thread(
            store.dismiss_wifi_anomalies_bulk, batch
        )

    if resolved_ids:
        await asyncio.to_thread(
            store.log_audit,
            action="wifi_anomaly_reeval_dismiss",
            target_id=f"batch:{len(resolved_ids)}",
        )
        logger.info(
            "Reeval-dismiss: %d processed, %d still anomalous, %d dismissed, %d errors",
            len(all_anomalies),
            still_count,
            dismissed_count,
            errors,
        )

    new_total = await asyncio.to_thread(
        store.count_wifi_anomalies,
        min_score=min_score,
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
# PUT /anomalies/{anomaly_id}/dismiss — dismiss single WiFi anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/dismiss")
async def dismiss_wifi_anomaly(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Dismiss a single WiFi anomaly."""
    store = _get_detection_store(request)
    await asyncio.to_thread(store.dismiss_wifi_anomaly, anomaly_id)
    await asyncio.to_thread(
        store.log_audit,
        action="wifi_anomaly_dismiss",
        target_id=str(anomaly_id),
    )
    return {"ok": True, "dismissed": anomaly_id}


# ---------------------------------------------------------------------------
# PUT /anomalies/{anomaly_id}/snooze — snooze single WiFi anomaly
# ---------------------------------------------------------------------------


@router.put("/anomalies/{anomaly_id}/snooze")
async def snooze_wifi_anomaly(
    anomaly_id: int,
    request: Request,
    body: _SnoozeBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Snooze a single WiFi anomaly for a specified duration."""
    until = (datetime.now(timezone.utc) + timedelta(hours=body.hours)).isoformat()
    store = _get_detection_store(request)
    await asyncio.to_thread(store.snooze_wifi_anomaly, anomaly_id, until)
    await asyncio.to_thread(
        store.log_audit,
        action="wifi_anomaly_snooze",
        target_id=str(anomaly_id),
        note=f"Snoozed for {body.hours}h until {until}",
    )
    return {"ok": True, "snoozed": anomaly_id, "snoozed_until": until}


# ---------------------------------------------------------------------------
# POST /anomalies/bulk/reevaluate — bulk re-evaluate WiFi anomalies
# (must be registered before the {anomaly_id} path param route)
# ---------------------------------------------------------------------------


@router.post("/anomalies/bulk/reevaluate")
async def reevaluate_wifi_anomalies_bulk(
    request: Request,
    body: _BulkReevaluateBody,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Re-evaluate up to 50 WiFi anomalies against current baselines."""
    ids = body.ids[:50]
    if not ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ids must be a non-empty list",
        )
    store = _get_detection_store(request)
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WiFi scorer not initialised",
        )

    # Fetch anomaly records
    anomalies = await asyncio.to_thread(
        store.get_wifi_anomalies_by_ids,
        ids,
    )
    results = {}
    errors = 0
    for anomaly in anomalies:
        aid = anomaly.get("id")
        try:
            result = wifi_scorer.reevaluate(anomaly)
            results[str(aid)] = result
        except Exception as exc:
            logger.warning("Re-evaluate anomaly %s failed: %s", aid, exc)
            errors += 1

    resp: dict[str, Any] = {"count": len(results), "results": results}
    if errors:
        resp["errors"] = errors
    return resp


# ---------------------------------------------------------------------------
# POST /anomalies/{anomaly_id}/reevaluate — re-evaluate single anomaly
# ---------------------------------------------------------------------------


@router.post("/anomalies/{anomaly_id}/reevaluate")
async def reevaluate_wifi_anomaly(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Re-evaluate a WiFi anomaly against current baselines."""
    store = _get_detection_store(request)
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WiFi scorer not initialised",
        )

    anomalies = await asyncio.to_thread(
        store.get_wifi_anomalies_by_ids,
        [anomaly_id],
    )
    if not anomalies:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anomaly {anomaly_id} not found",
        )

    try:
        result = wifi_scorer.reevaluate(anomalies[0])
    except Exception as exc:
        logger.warning("Re-evaluate anomaly %d failed: %s", anomaly_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Re-evaluation error: {exc}",
        )
    return {"anomaly_id": anomaly_id, **result}


# ---------------------------------------------------------------------------
# POST /anomalies/{anomaly_id}/pcap — upload pcap capture
# ---------------------------------------------------------------------------


@router.post("/anomalies/{anomaly_id}/pcap", status_code=status.HTTP_201_CREATED)
async def upload_pcap(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Upload a gzip-compressed pcap capture for a WiFi anomaly.

    The request body must be the raw gzip-compressed pcap bytes
    (Content-Type: application/octet-stream).
    """
    pcap_store = getattr(request.app.state, "pcap_store", None)
    if pcap_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pcap store not initialised",
        )

    # Cap upload size (10 MB compressed) — reject early via Content-Length
    max_size = 10 * 1024 * 1024
    content_length = request.headers.get("content-length")
    if content_length is not None and int(content_length) > max_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Pcap upload exceeds {max_size} byte limit",
        )

    # Stream body with size enforcement
    chunks = []
    received = 0
    async for chunk in request.stream():
        received += len(chunk)
        if received > max_size:
            raise HTTPException(
                status_code=413, detail=f"Pcap upload exceeds {max_size} byte limit"
            )
        chunks.append(chunk)
    body = b"".join(chunks)

    if not body:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty request body",
        )

    store = _get_detection_store(request)
    # Verify anomaly exists before storing pcap
    matches = await asyncio.to_thread(store.get_wifi_anomalies_by_ids, [anomaly_id])
    if not matches:
        raise HTTPException(
            status_code=404, detail=f"WiFi anomaly {anomaly_id} not found"
        )

    # Inflate once, bounded and off the event loop: a capture that inflates
    # past the limit (a gzip bomb within the 10 MB upload cap) is refused
    # before anything is stored.
    from sigrift.bridge.anomaly.pcap_store import (
        PcapDecompressionError,
        PcapSizeLimitError,
        decompress_pcap,
    )

    pcap_data: bytes | None
    try:
        pcap_data = await asyncio.to_thread(decompress_pcap, body)
    except PcapSizeLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(exc)
        )
    except PcapDecompressionError as exc:
        # Stored as before (frame count 0), so a capture the bridge cannot
        # read can still be downloaded for inspection.
        logger.warning(
            "Pcap upload for anomaly %d is not valid gzip: %s", anomaly_id, exc
        )
        pcap_data = None

    await asyncio.to_thread(pcap_store.store, anomaly_id, body)

    # Parse frame count from the pcap for metadata
    frame_count = 0
    if pcap_data is not None:
        summary = await asyncio.to_thread(pcap_store.summarize, pcap_data, len(body))
        frame_count = summary["total_frames"]

    # Update the database record
    await asyncio.to_thread(
        store.set_wifi_anomaly_pcap,
        anomaly_id,
        True,
        frame_count,
    )

    logger.info(
        "Pcap uploaded for anomaly %d: %d bytes, %d frames",
        anomaly_id,
        len(body),
        frame_count,
    )

    return {
        "ok": True,
        "anomaly_id": anomaly_id,
        "size_bytes": len(body),
        "frame_count": frame_count,
    }


# ---------------------------------------------------------------------------
# GET /anomalies/{anomaly_id}/pcap — download raw pcap
# ---------------------------------------------------------------------------


@router.get("/anomalies/{anomaly_id}/pcap")
async def download_pcap(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> RawResponse:
    """Download the raw pcap capture for a WiFi anomaly.

    Returns gzip-compressed pcap suitable for Wireshark import.
    """
    pcap_store = getattr(request.app.state, "pcap_store", None)
    if pcap_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pcap store not initialised",
        )

    data = pcap_store.load_raw(anomaly_id)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No pcap capture for anomaly {anomaly_id}",
        )

    return RawResponse(
        content=data,
        media_type="application/vnd.tcpdump.pcap",
        headers={
            "Content-Disposition": f'attachment; filename="anomaly_{anomaly_id}.pcap.gz"',
            "Content-Encoding": "gzip",
        },
    )


# ---------------------------------------------------------------------------
# GET /anomalies/{anomaly_id}/pcap/summary — parsed frame summary
# ---------------------------------------------------------------------------


@router.get("/anomalies/{anomaly_id}/pcap/summary")
async def pcap_summary(
    anomaly_id: int,
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return a parsed summary of the pcap capture for dashboard display.

    Includes frame count, duration, frame type breakdown, and
    per-frame metadata (timestamps, sizes, types).
    """
    pcap_store = getattr(request.app.state, "pcap_store", None)
    if pcap_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pcap store not initialised",
        )

    summary = await asyncio.to_thread(pcap_store.parse_summary, anomaly_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No pcap capture for anomaly {anomaly_id}",
        )

    return {"anomaly_id": anomaly_id, **summary}


# ---------------------------------------------------------------------------
# WebSocket: real-time WiFi event stream
# ---------------------------------------------------------------------------


@router.websocket("/ws/wifi")
async def ws_wifi(websocket: WebSocket) -> None:
    """Stream WiFi events to authenticated WebSocket clients."""
    key_id, subprotocol = await require_ws_auth(websocket)
    if subprotocol:
        await websocket.accept(subprotocol=subprotocol)
    else:
        await websocket.accept()

    app_state: AppState = websocket.app.state.app_state
    await app_state.ws_wifi_clients.add(websocket)
    logger.info("WiFi WS client connected: %s", key_id)

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
        await app_state.ws_wifi_clients.remove(websocket)
        client_ip = getattr(websocket.state, "ws_client_ip", None)
        if client_ip:
            get_ws_limiter().release(client_ip)
        logger.info("WiFi WS client disconnected: %s", key_id)


# ---------------------------------------------------------------------------
# Broadcast helper
# ---------------------------------------------------------------------------


async def _broadcast_wifi(
    app_state: AppState,
    data: dict[str, Any],
) -> None:
    """Push WiFi event to all connected WiFi WS clients."""
    await app_state.ws_wifi_clients.broadcast(data)
