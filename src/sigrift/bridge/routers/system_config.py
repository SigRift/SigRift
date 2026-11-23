"""System configuration router for The Bridge admin panel.

Provides endpoints for detection config, anomaly thresholds, scorer settings,
and WiFi AP whitelist management. All endpoints require master key authentication.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge import __version__
from sigrift.bridge.constants import BRIDGE_RETENTION_DAYS
from sigrift.bridge.dependencies import admin_rate_limit as _admin_rate_limit
from sigrift.bridge.detection_config import (
    MERGED_KEYS,
    PROTOCOL_KEY,
    AutoRescanConfig,
    DetectionConfigError,
    check_detection_config,
)
from sigrift.bridge.routers.admin import _config_diff
from sigrift.bridge.state import AppState
from sigrift.bridge.storage.base import sqlite_transaction
from sigrift.bridge.utils import get_detection_store, utcnow

logger = logging.getLogger(__name__)

_utcnow = utcnow
_get_detection_store = get_detection_store

router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class WhitelistAPRequest(BaseModel):
    model_config = {"extra": "forbid"}
    bssid: str
    ssid: str = ""
    notes: str = ""


# ---------------------------------------------------------------------------
# Detection Config
# ---------------------------------------------------------------------------


@router.get("/detection-config")
async def get_detection_config(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return current detection thresholds, weights, and auto-snooze config."""
    persistence = request.app.state.persistence
    config = persistence.get_detection_config()
    defaults = persistence.get_detection_config_defaults()
    return {"config": config, "defaults": defaults}


@router.put("/detection-config")
async def update_detection_config(
    request: Request,
    body: dict[str, Any],
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update detection thresholds and weights.

    Every value is checked first (``detection_config.check_detection_config``):
    a wrong type, a value out of range, an unknown key, or weights / toggles
    that merged into the stored ones would break their bounds (64 entries,
    a weight sum of 2.0) is a 422 that changes nothing.  Persists to JSON,
    then updates live scorers and app.state thresholds.
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    # Snapshot old config for audit diff
    old_config = persistence.get_detection_config()
    try:
        body = check_detection_config(body, old_config)
    except DetectionConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    # Merge with current config.  Weights and protocol toggles merge into
    # the stored ones (as get_detection_config reads them), so a partial
    # dict never resets the entries it leaves out.
    current = dict(old_config)
    for key, val in body.items():
        if key in MERGED_KEYS:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            else:
                current[key] = dict(current[key])
            current[key].update(val)
        else:
            current[key] = val

    # Auto-snapshot before applying config change
    try:
        store_snap = _get_detection_store(request)
        conn_snap = store_snap.get_connection()
        persistence.create_config_snapshot(
            "config_change",
            "before: PUT /detection-config",
            db_conn=conn_snap,
        )
    except Exception as exc:
        logger.warning("Auto-snapshot before detection-config update failed: %s", exc)

    persistence.set_detection_config(current)

    # Propagate to live scorers (shared with the bundle-apply path)
    from sigrift.bridge import bundles

    bundles.apply_detection_config_to_scorers(
        getattr(request.app.state, "rf_scorer", None),
        getattr(request.app.state, "wifi_scorer", None),
        current,
    )

    # Store config on app.state for routers to read
    request.app.state.detection_config = current
    # Also sync to app_state for _maybe_create_wifi_alert compatibility
    app_state = request.app.state.app_state
    if app_state is not None:
        app_state._detection_config = current

    # Build audit diff: only include keys that actually changed
    changes = _config_diff(old_config, current, list(body.keys()))

    store.log_audit(
        action="admin_update_detection_config",
        target_id="detection_config",
        operator=_key_id,
        details={"changes": changes},
    )

    logger.info("Detection config updated by %s: %s", _key_id, list(body.keys()))
    return {"status": "ok", "config": current}


# ---------------------------------------------------------------------------
# Rescore RF anomalies
# ---------------------------------------------------------------------------


@router.post("/rescore-rf-anomalies")
async def rescore_rf_anomalies(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Re-evaluate all RF anomalies using the current scoring engine.

    Reads every row from rf_anomalies, re-runs the scorer, and updates
    anomaly_score, priority, dimensions, and reasons in place.
    """
    import json as _json

    store = _get_detection_store(request)
    rf_scorer = getattr(request.app.state, "rf_scorer", None)
    if rf_scorer is None:
        raise HTTPException(status_code=503, detail="RF scorer not available")

    conn = store.get_connection()

    rows = conn.execute(
        "SELECT id, signal_class, confidence, freq_hz, power_dbm, snr_db, "
        "timestamp, anomaly_score FROM rf_anomalies"
    ).fetchall()

    updated = 0
    removed = 0
    det_cfg = getattr(request.app.state, "detection_config", None) or {}
    insert_threshold = det_cfg.get("rf_anomaly_insert_threshold", 0.3)
    conf_floor = det_cfg.get("rf_min_confidence_floor", 0.0)

    # One transaction: a failure part-way rolls back every rescored row.
    with sqlite_transaction(conn):
        for row in rows:
            row_id = row[0]
            confidence = row[2] or 0.0

            # Apply confidence floor — remove anomalies below it
            if confidence < conf_floor:
                conn.execute("DELETE FROM rf_anomalies WHERE id = ?", (row_id,))
                removed += 1
                continue

            det = {
                "signal_class": row[1] or "",
                "confidence": confidence,
                "freq_hz": row[3] or 0.0,
                "power_dbm": row[4],
                "snr_db": row[5],
                "timestamp": row[6],
            }

            result = rf_scorer.score(det)

            # Remove if below insert threshold
            if result.score < insert_threshold:
                conn.execute("DELETE FROM rf_anomalies WHERE id = ?", (row_id,))
                removed += 1
                continue

            conn.execute(
                "UPDATE rf_anomalies SET anomaly_score = ?, priority = ?, "
                "dimensions = ?, reasons = ? WHERE id = ?",
                (
                    round(result.score, 4),
                    result.priority,
                    _json.dumps({k: round(v, 4) for k, v in result.dimensions.items()}),
                    _json.dumps(result.reasons),
                    row_id,
                ),
            )
            updated += 1

    store.log_audit(
        action="admin_rescore_rf_anomalies",
        target_id="rf_anomalies",
        operator=_key_id,
        details={
            "severity": "critical",
            "total": len(rows),
            "updated": updated,
            "removed": removed,
        },
        note=f"CRITICAL: Rescored {len(rows)} RF anomalies — {updated} updated, {removed} removed",
    )

    logger.info(
        "RF anomalies rescored by %s: %d updated, %d removed out of %d",
        _key_id,
        updated,
        removed,
        len(rows),
    )
    return {
        "status": "ok",
        "total": len(rows),
        "updated": updated,
        "removed": removed,
    }


@router.post("/simulate-rescore-rf")
async def simulate_rescore_rf(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Dry-run rescore: predict changes without modifying the database."""
    store = _get_detection_store(request)
    rf_scorer = getattr(request.app.state, "rf_scorer", None)
    if rf_scorer is None:
        raise HTTPException(status_code=503, detail="RF scorer not available")

    conn = store.get_connection()
    rows = conn.execute(
        "SELECT id, signal_class, confidence, freq_hz, power_dbm, snr_db, "
        "timestamp, anomaly_score, priority FROM rf_anomalies"
    ).fetchall()

    det_cfg = getattr(request.app.state, "detection_config", None) or {}
    insert_threshold = det_cfg.get("rf_anomaly_insert_threshold", 0.3)
    conf_floor = det_cfg.get("rf_min_confidence_floor", 0.0)

    would_remove = 0
    would_update = 0
    unchanged = 0
    priority_before: dict[str, int] = {}
    priority_after: dict[str, int] = {}

    for row in rows:
        confidence = row[2] or 0.0
        old_score = row[7] or 0.0
        old_priority = row[8] or "normal"
        priority_before[old_priority] = priority_before.get(old_priority, 0) + 1

        if confidence < conf_floor:
            would_remove += 1
            continue

        det = {
            "signal_class": row[1] or "",
            "confidence": confidence,
            "freq_hz": row[3] or 0.0,
            "power_dbm": row[4],
            "snr_db": row[5],
            "timestamp": row[6],
        }
        result = rf_scorer.score(det)

        if result.score < insert_threshold:
            would_remove += 1
            continue

        priority_after[result.priority] = priority_after.get(result.priority, 0) + 1
        if result.priority != old_priority or abs(result.score - old_score) > 0.005:
            would_update += 1
        else:
            unchanged += 1

    store.log_audit(
        action="admin_simulate_rescore_rf",
        target_id="rf_anomalies",
        operator=_key_id,
        details={
            "severity": "warning",
            "total": len(rows),
            "would_remove": would_remove,
            "would_update": would_update,
            "remaining": len(rows) - would_remove,
        },
        note=f"Simulated rescore of {len(rows)} RF anomalies — {would_remove} would be removed",
    )

    return {
        "total": len(rows),
        "would_remove": would_remove,
        "would_update": would_update,
        "unchanged": unchanged,
        "remaining": len(rows) - would_remove,
        "priority_before": priority_before,
        "priority_after": priority_after,
    }


# ---------------------------------------------------------------------------
# System Config / Stats
# ---------------------------------------------------------------------------


@router.get("/config")
async def get_config(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Current system configuration (sanitized, no secrets)."""
    from sigrift.bridge.dependencies import get_config

    config = get_config()
    # Return sanitized config -- no secrets
    return {
        "security": {
            "rate_limit_per_minute": config.security.rate_limit_per_minute,
        },
        "retention": {
            "retention_days": BRIDGE_RETENTION_DAYS,
            "source": "env" if os.environ.get("BRIDGE_RETENTION_DAYS") else "default",
        },
        "version": __version__,
    }


@router.get("/stats")
async def get_db_stats(
    request: Request,
    period_hours: int = Query(
        0, ge=0, le=8760, description="Custom period in hours for rows_period column"
    ),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Database statistics: per-table rows, size, hourly volume, DB totals."""
    store = _get_detection_store(request)
    return await asyncio.to_thread(_collect_db_stats, store, period_hours)


def _collect_db_stats(store: Any, period_hours: int) -> dict[str, Any]:
    """Blocking helper -- runs SQLite queries in a worker thread."""
    conn = store.get_connection()

    all_tables = [
        "detections",
        "detection_aggregates",
        "detection_feedback",
        "audit_log",
        "wifi_metadata",
        "wifi_metadata_hourly",
        "wifi_anomalies",
        "rf_anomalies",
        "bt_devices",
        "bt_anomalies",
        "bt_devices_hourly",
        "fhss_events",
        "emitters",
        "tdoa_estimates",
        "spectrum_snapshots",
        "users",
        "sessions",
        "mfa_tokens",
        "mfa_backup_codes",
        "tenant_settings",
        "schema_version",
    ]

    from datetime import timedelta as _td

    # Per-table detailed stats
    table_stats = []
    one_hour_ago = (datetime.now(timezone.utc) - _td(hours=1)).isoformat()
    twenty_four_hours_ago = (datetime.now(timezone.utc) - _td(hours=24)).isoformat()
    period_cutoff = (
        (datetime.now(timezone.utc) - _td(hours=period_hours)).isoformat()
        if period_hours > 0
        else None
    )

    ts_tables = (
        "detections",
        "detection_aggregates",
        "audit_log",
        "wifi_metadata",
        "wifi_metadata_hourly",
        "wifi_anomalies",
        "rf_anomalies",
        "bt_devices",
        "bt_anomalies",
        "bt_devices_hourly",
        "fhss_events",
        "emitters",
        "tdoa_estimates",
        "spectrum_snapshots",
        "users",
        "sessions",
        "mfa_tokens",
        "mfa_backup_codes",
    )

    for table in all_tables:
        info: dict[str, Any] = {"name": table, "rows": 0, "size_bytes": 0}
        if table in (
            "wifi_metadata_hourly",
            "detection_aggregates",
            "bt_devices_hourly",
        ):
            ts_col = "hour"
        elif table in ("users", "sessions", "mfa_tokens", "mfa_backup_codes"):
            ts_col = "created_at"
        elif table == "emitters":
            ts_col = "last_seen"
        else:
            ts_col = "timestamp"

        if table in ts_tables:
            # Single-pass query: count, 1h, 24h, period, oldest, newest
            try:
                parts = [
                    "SELECT COUNT(*) as cnt",
                    f"SUM(CASE WHEN {ts_col} >= ? THEN 1 ELSE 0 END) as r1h",
                    f"SUM(CASE WHEN {ts_col} >= ? THEN 1 ELSE 0 END) as r24h",
                ]
                params: list[str] = [one_hour_ago, twenty_four_hours_ago]
                if period_cutoff:
                    parts.append(
                        f"SUM(CASE WHEN {ts_col} >= ? THEN 1 ELSE 0 END) as rp"
                    )
                    params.append(period_cutoff)
                parts.append(f"MIN({ts_col}) as oldest")
                parts.append(f"MAX({ts_col}) as newest")
                sql = ", ".join(parts) + f" FROM {table}"
                row = conn.execute(sql, params).fetchone()
                if row:
                    info["rows"] = row["cnt"] or 0
                    info["rows_1h"] = row["r1h"] or 0
                    info["rows_24h"] = row["r24h"] or 0
                    if period_cutoff:
                        info["rows_period"] = row["rp"] or 0
                    info["oldest"] = row["oldest"]
                    info["newest"] = row["newest"]
            except Exception:
                pass
        else:
            try:
                row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
                info["rows"] = row["cnt"] if row else 0
            except Exception:
                pass

        table_stats.append(info)

    # Sort by row count descending (largest first)
    table_stats.sort(key=lambda t: t.get("rows", 0), reverse=True)

    # Legacy compat: flat rows dict
    tables = {t["name"]: t["rows"] for t in table_stats}

    # DB file size
    db_path = Path(store.db_path)
    db_size = db_path.stat().st_size if db_path.exists() else 0
    wal_path = db_path.with_suffix(".db-wal")
    wal_size = wal_path.stat().st_size if wal_path.exists() else 0

    return {
        "tables": tables,
        "table_stats": table_stats,
        "db_size_bytes": db_size,
        "wal_size_bytes": wal_size,
        "db_path": str(db_path),
    }


@router.get("/sessions")
async def get_sessions(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Active sessions list (from SQLite)."""
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        return {"count": 0, "sessions": []}

    conn = detection_store.get_connection()
    rows = conn.execute(
        "SELECT session_token, user_id, created_at, expires_at, ip_address "
        "FROM sessions ORDER BY created_at DESC LIMIT 200"
    ).fetchall()

    sessions = []
    for row in rows:
        r = dict(row)
        sessions.append(
            {
                "token_prefix": r["session_token"][:8] + "...",
                "user_id": r.get("user_id", ""),
                "created": r.get("created_at", ""),
                "expires": r.get("expires_at", ""),
                "ip_address": r.get("ip_address", ""),
            }
        )

    return {
        "count": len(sessions),
        "sessions": sessions,
    }


# ---------------------------------------------------------------------------
# WiFi AP Whitelist
# ---------------------------------------------------------------------------


@router.get("/wifi-whitelist")
async def list_wifi_whitelist(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List all whitelisted (authorized) WiFi access points."""
    persistence = request.app.state.persistence
    return {"whitelist": persistence.get_wifi_whitelist()}


@router.post("/wifi-whitelist", status_code=status.HTTP_201_CREATED)
async def add_wifi_whitelist(
    request: Request,
    body: WhitelistAPRequest,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Add a BSSID to the authorized AP whitelist."""
    import html as _html
    import re
    import secrets as _secrets

    bssid = body.bssid.strip().upper()
    # Basic BSSID format validation (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
    if not re.match(r"^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$", bssid):
        raise HTTPException(
            status_code=400, detail="Invalid BSSID format (expected AA:BB:CC:DD:EE:FF)"
        )
    bssid = bssid.replace("-", ":")

    persistence = request.app.state.persistence
    whitelist = persistence.get_wifi_whitelist()

    # Check for duplicates
    for entry in whitelist:
        if entry.get("bssid", "").upper() == bssid:
            raise HTTPException(
                status_code=409, detail=f"BSSID {bssid} already whitelisted"
            )

    entry = {
        "id": _secrets.token_hex(6),
        "bssid": bssid,
        # The SSID is stored as given, like the networks it names.
        "ssid": body.ssid.strip() if body.ssid else "",
        "notes": _html.escape(body.notes.strip())[:200] if body.notes else "",
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    whitelist.append(entry)
    persistence.set_wifi_whitelist(whitelist)

    # Sync scorer whitelist
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is not None:
        wifi_scorer.set_whitelist(whitelist)

    # Audit
    store = request.app.state.detection_store
    store.log_audit(
        action="admin_whitelist_add",
        target_id=bssid,
        operator=_key_id,
        note=f"Whitelisted AP {bssid} ({entry['ssid'] or 'no SSID'})",
    )

    return {"status": "created", "entry": entry}


@router.delete("/wifi-whitelist/{entry_id}")
async def remove_wifi_whitelist(
    entry_id: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Remove a BSSID from the authorized AP whitelist."""
    persistence = request.app.state.persistence
    whitelist = persistence.get_wifi_whitelist()

    removed = None
    for i, entry in enumerate(whitelist):
        if entry.get("id") == entry_id:
            removed = whitelist.pop(i)
            break

    if removed is None:
        raise HTTPException(
            status_code=404, detail=f"Whitelist entry {entry_id} not found"
        )

    persistence.set_wifi_whitelist(whitelist)

    # Sync scorer whitelist
    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    if wifi_scorer is not None:
        wifi_scorer.set_whitelist(whitelist)

    # Audit
    store = request.app.state.detection_store
    store.log_audit(
        action="admin_whitelist_remove",
        target_id=removed["bssid"],
        operator=_key_id,
        note=f"Removed AP {removed['bssid']} from whitelist",
    )

    return {"status": "deleted", "entry_id": entry_id, "bssid": removed["bssid"]}


# ---------------------------------------------------------------------------
# Bluetooth Device Whitelist
# ---------------------------------------------------------------------------


class WhitelistBTRequest(BaseModel):
    model_config = {"extra": "forbid"}
    device_addr: str
    device_name: str = ""
    notes: str = ""


@router.get("/bt-whitelist")
async def list_bt_whitelist(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List all whitelisted (authorized) Bluetooth devices."""
    persistence = request.app.state.persistence
    return {"whitelist": persistence.get_bt_whitelist()}


@router.post("/bt-whitelist", status_code=status.HTTP_201_CREATED)
async def add_bt_whitelist(
    request: Request,
    body: WhitelistBTRequest,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Add a device address to the authorized BT whitelist."""
    import html as _html
    import re
    import secrets as _secrets

    addr = body.device_addr.strip().upper()
    if not re.match(r"^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$", addr):
        raise HTTPException(
            status_code=400,
            detail="Invalid device address format (expected AA:BB:CC:DD:EE:FF)",
        )
    addr = addr.replace("-", ":")

    persistence = request.app.state.persistence
    whitelist = persistence.get_bt_whitelist()

    for entry in whitelist:
        if entry.get("device_addr", "").upper() == addr:
            raise HTTPException(
                status_code=409, detail=f"Device {addr} already whitelisted"
            )

    entry = {
        "id": _secrets.token_hex(6),
        "device_addr": addr,
        # The name is stored as given, like the devices it names.
        "device_name": body.device_name.strip() if body.device_name else "",
        "notes": _html.escape(body.notes.strip())[:200] if body.notes else "",
        "added_at": datetime.now(timezone.utc).isoformat(),
    }
    whitelist.append(entry)
    persistence.set_bt_whitelist(whitelist)

    store = request.app.state.detection_store
    store.log_audit(
        action="admin_bt_whitelist_add",
        target_id=addr,
        operator=_key_id,
        note=f"Whitelisted BT device {addr} ({entry['device_name'] or 'unnamed'})",
    )

    return {"status": "created", "entry": entry}


@router.delete("/bt-whitelist/{entry_id}")
async def remove_bt_whitelist(
    entry_id: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Remove a device address from the authorized BT whitelist."""
    persistence = request.app.state.persistence
    whitelist = persistence.get_bt_whitelist()

    removed = None
    for i, entry in enumerate(whitelist):
        if entry.get("id") == entry_id:
            removed = whitelist.pop(i)
            break

    if removed is None:
        raise HTTPException(
            status_code=404, detail=f"Whitelist entry {entry_id} not found"
        )

    persistence.set_bt_whitelist(whitelist)

    store = request.app.state.detection_store
    store.log_audit(
        action="admin_bt_whitelist_remove",
        target_id=removed["device_addr"],
        operator=_key_id,
        note=f"Removed BT device {removed['device_addr']} from whitelist",
    )

    return {
        "status": "deleted",
        "entry_id": entry_id,
        "device_addr": removed["device_addr"],
    }


# ---------------------------------------------------------------------------
# Config Snapshots (Versioning)
# ---------------------------------------------------------------------------


@router.get("/config-snapshots")
async def list_config_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List config snapshots (newest first)."""
    from sigrift.bridge.persistence import PersistenceManager

    store = _get_detection_store(request)
    conn = store.get_connection()
    snapshots = PersistenceManager.list_config_snapshots(conn, limit=limit)
    return {"snapshots": snapshots}


@router.post("/config-snapshots", status_code=status.HTTP_201_CREATED)
async def create_config_snapshot(
    request: Request,
    body: dict[str, Any] | None = None,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Create a manual config snapshot."""
    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    conn = store.get_connection()
    description = ""
    if body and isinstance(body.get("description"), str):
        import html as _html

        description = _html.escape(body["description"].strip())[:200]
    snap_id = persistence.create_config_snapshot(
        "manual",
        description,
        db_conn=conn,
    )
    if snap_id is None:
        raise HTTPException(status_code=500, detail="Failed to create snapshot")

    store.log_audit(
        action="admin_config_snapshot_create",
        target_id=str(snap_id),
        operator=_key_id,
        note=f"Manual config snapshot #{snap_id}",
    )
    return {"status": "created", "snapshot_id": snap_id}


@router.get("/config-snapshots/{snapshot_id}")
async def get_config_snapshot(
    snapshot_id: int,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Get snapshot detail with file contents."""
    from sigrift.bridge.persistence import PersistenceManager

    store = _get_detection_store(request)
    conn = store.get_connection()
    snap = PersistenceManager.get_config_snapshot(conn, snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")
    return {"snapshot": snap}


@router.post("/config-snapshots/{snapshot_id}/restore")
async def restore_config_snapshot(
    snapshot_id: int,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Restore config from a snapshot. Creates a pre-restore snapshot first."""
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is None:
        return await _restore_config_snapshot(snapshot_id, request, _key_id)
    async with notifier.configuration_lock:
        return await _restore_config_snapshot(snapshot_id, request, _key_id)


async def _restore_config_snapshot(
    snapshot_id: int, request: Request, _key_id: str
) -> dict[str, Any]:
    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    conn = store.get_connection()

    from sigrift.bridge.persistence import (
        ConfigSnapshotRejected,
        ConfigSnapshotRestoreError,
        PersistenceManager,
    )

    # Verify snapshot exists
    snap = PersistenceManager.get_config_snapshot(conn, snapshot_id)
    if snap is None:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")

    def rejected(exc: ConfigSnapshotRejected) -> HTTPException:
        # A tampered row (keys.json, a path): nothing was written.
        return HTTPException(
            status_code=422,
            detail=f"Snapshot {snapshot_id} cannot be restored. {exc}. "
            "Nothing was restored.",
        )

    # Refuse a tampered row before the pre-restore backup, which it would
    # otherwise leave behind for nothing (restore checks again).
    try:
        PersistenceManager.config_snapshot_files(snap)
    except ConfigSnapshotRejected as exc:
        raise rejected(exc) from exc

    # Create pre-restore snapshot
    backup_id = persistence.create_config_snapshot(
        "config_change",
        f"pre-restore backup (before restoring #{snapshot_id})",
        db_conn=conn,
        require_complete=True,
    )
    if backup_id is None:
        raise HTTPException(
            status_code=500, detail="Failed to create pre-restore backup"
        )

    # Restore
    incomplete = False
    try:
        restored = persistence.restore_config_snapshot(conn, snapshot_id)
    except ConfigSnapshotRejected as exc:
        raise rejected(exc) from exc
    except ConfigSnapshotRestoreError as exc:
        restored = exc.restored_files
        incomplete = True
    if not restored and not incomplete:
        raise HTTPException(status_code=500, detail="No files restored")

    # Propagate detection config to live scorers
    detection_config = persistence.get_detection_config()
    request.app.state.detection_config = detection_config
    app_state = request.app.state.app_state
    if app_state is not None:
        app_state._detection_config = detection_config
    from sigrift.bridge import bundles

    wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
    rf_scorer = getattr(request.app.state, "rf_scorer", None)
    bundles.apply_detection_config_to_scorers(rf_scorer, wifi_scorer, detection_config)
    if wifi_scorer is not None:
        wifi_scorer.set_whitelist(persistence.get_wifi_whitelist())

    # Reload webhooks and syslog
    notifier = getattr(request.app.state, "notifier", None)
    if notifier is not None:
        notifier.load(persistence.get_webhooks())
    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is not None:
        syslog_fwd.load(persistence.get_syslog_targets())

    if incomplete:
        raise HTTPException(
            status_code=500,
            detail="Config restore incomplete; some files could not be written. "
            "Completed writes remain applied; fix the destination and retry.",
        )

    store.log_audit(
        action="admin_config_snapshot_restore",
        target_id=str(snapshot_id),
        operator=_key_id,
        note=f"Restored config from snapshot #{snapshot_id} ({len(restored)} files)",
        details={"restored_files": restored},
    )

    return {
        "status": "restored",
        "snapshot_id": snapshot_id,
        "restored_files": restored,
    }


@router.delete("/config-snapshots/{snapshot_id}")
async def delete_config_snapshot(
    snapshot_id: int,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Delete a config snapshot."""
    from sigrift.bridge.persistence import PersistenceManager

    store = _get_detection_store(request)
    conn = store.get_connection()
    deleted = PersistenceManager.delete_config_snapshot(conn, snapshot_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Snapshot {snapshot_id} not found")

    store.log_audit(
        action="admin_config_snapshot_delete",
        target_id=str(snapshot_id),
        operator=_key_id,
    )
    return {"status": "deleted", "snapshot_id": snapshot_id}


# ---------------------------------------------------------------------------
# P1-4: Auto-Rescan Configuration (body model: detection_config.AutoRescanConfig)
# ---------------------------------------------------------------------------


@router.get("/auto-rescan")
async def get_auto_rescan_config(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return the current auto-rescan configuration."""
    persistence = request.app.state.persistence
    config = persistence.get_detection_config()
    auto_rescan = config.get(
        "auto_rescan",
        {
            "enabled": False,
            "confidence_threshold": 0.5,
            "max_retries": 2,
        },
    )
    return {"auto_rescan": auto_rescan}


@router.post("/auto-rescan")
async def set_auto_rescan_config(
    request: Request,
    body: AutoRescanConfig,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Set the auto-rescan configuration.

    When enabled, detections with confidence below the threshold will
    automatically trigger a rescan command to the originating edge node.
    The body is checked strictly (:class:`AutoRescanConfig`, as the
    ``auto_rescan`` key of ``PUT /detection-config``): a string or a
    boolean where a number belongs is a 422, not converted.
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    config = persistence.get_detection_config()
    old_auto_rescan = config.get("auto_rescan", {})

    new_auto_rescan = {
        "enabled": body.enabled,
        "confidence_threshold": body.confidence_threshold,
        "max_retries": body.max_retries,
    }
    config["auto_rescan"] = new_auto_rescan
    persistence.set_detection_config(config)

    # Propagate to app state
    request.app.state.detection_config = config
    app_state: AppState = request.app.state.app_state
    if app_state is not None:
        app_state._detection_config = config

    # Audit log
    store.log_audit(
        action="admin_auto_rescan_config",
        target_id="auto_rescan",
        operator=_key_id,
        details={"old": old_auto_rescan, "new": new_auto_rescan},
    )

    logger.info(
        "Auto-rescan config updated by %s: enabled=%s, threshold=%.2f, max_retries=%d",
        _key_id,
        body.enabled,
        body.confidence_threshold,
        body.max_retries,
    )

    return {"status": "ok", "auto_rescan": new_auto_rescan}


# ---------------------------------------------------------------------------
# Scoring Thresholds (QuantileTracker) & Evaluation (ScoringEvaluator)
# ---------------------------------------------------------------------------


@router.get("/scoring/thresholds")
async def get_scoring_thresholds(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return QuantileTracker status for all bands."""
    qt = getattr(request.app.state, "quantile_tracker", None)
    if qt is None:
        return {"status": "not_configured", "bands": {}}
    return qt.status()


@router.get("/scoring/evaluation")
async def get_scoring_evaluation(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return ScoringEvaluator ROC evaluation results."""
    ev = getattr(request.app.state, "scoring_evaluator", None)
    if ev is None:
        return {
            "status": "not_configured",
            "auc": 0.0,
            "n_positive": 0,
            "n_negative": 0,
        }
    result = ev.compute_roc()
    return {
        "auc": result.auc,
        "n_positive": result.n_positive,
        "n_negative": result.n_negative,
        "optimal_threshold": result.optimal_threshold,
        "optimal_f1": result.optimal_f1,
        "sample_count": ev.sample_count,
    }


# ---------------------------------------------------------------------------
# Protocol Detection Configuration
# ---------------------------------------------------------------------------


@router.get("/protocols")
async def get_protocol_config(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Get protocol detection configuration."""
    persistence = request.app.state.persistence
    config = persistence.get_detection_config()
    protocol_config = config.get("protocol_detection", {})

    # Community build: every protocol is unconditionally available; the
    # `licensed` field is kept for response-shape compatibility and is
    # always True.
    result: dict[str, dict[str, Any]] = {}
    for proto, enabled in protocol_config.items():
        result[proto] = {"enabled": enabled, "licensed": True}

    return {"protocols": result}


@router.put("/protocols")
async def update_protocol_config(
    request: Request,
    body: dict[str, Any],
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Toggle individual protocols on/off (admin only).

    A name the bridge does not list is ignored; every other value must be
    ``true`` or ``false`` (the rule ``protocol_detection`` has in ``PUT
    /detection-config``), or the request is a 422 that changes nothing.
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    config = persistence.get_detection_config()
    if PROTOCOL_KEY not in config:
        config[PROTOCOL_KEY] = {}
    toggles = config[PROTOCOL_KEY]
    try:
        body = check_detection_config(
            {PROTOCOL_KEY: {k: v for k, v in body.items() if k in toggles}}, config
        )[PROTOCOL_KEY]
    except DetectionConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    changed: dict[str, bool] = {}
    for proto, enabled in body.items():
        if toggles[proto] != enabled:
            changed[proto] = enabled
        toggles[proto] = enabled

    persistence.set_detection_config(config)

    # Propagate to app state
    request.app.state.detection_config = config
    app_state = request.app.state.app_state
    if app_state is not None:
        app_state._detection_config = config

    if changed:
        store.log_audit(
            action="admin_update_protocol_config",
            target_id="protocol_detection",
            operator=_key_id,
            details={"changed": changed},
        )
        logger.info("Protocol config updated by %s: %s", _key_id, changed)

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Session binding (admin-toggleable, gateway reads env var at startup)
# ---------------------------------------------------------------------------


class SessionBindingRequest(BaseModel):
    model_config = {"extra": "forbid"}
    mode: str = Field(..., description="strict | ip | warn | none")


_VALID_BINDING_MODES = ("strict", "ip", "warn", "none")


@router.get("/session-binding")
async def get_session_binding(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return the admin-configured session binding mode + the current
    gateway env var value so the UI can show any drift between what's
    saved and what's actually being enforced until the next restart.
    """
    persistence = request.app.state.persistence
    saved = persistence.get_session_binding()
    gateway_env = os.environ.get("BRIDGE_SESSION_BINDING", "").strip().lower()
    if gateway_env not in _VALID_BINDING_MODES:
        gateway_env = ""
    return {
        "saved": saved,
        "gateway_active": gateway_env or "unset",
        "restart_required": bool(gateway_env) and saved != gateway_env,
        "valid_modes": list(_VALID_BINDING_MODES),
        "default": "none",
    }


@router.put("/session-binding")
async def update_session_binding(
    request: Request,
    body: SessionBindingRequest,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Persist the admin-configured session binding mode. The gateway
    reads BRIDGE_SESSION_BINDING from env at startup, so a stack restart
    is required for the change to take effect — the response flags
    this so the UI can surface a banner.
    """
    mode = body.mode.strip().lower()
    if mode not in _VALID_BINDING_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"mode must be one of: {', '.join(_VALID_BINDING_MODES)}",
        )

    persistence = request.app.state.persistence
    previous = persistence.get_session_binding()
    persistence.set_session_binding(mode)

    gateway_env = os.environ.get("BRIDGE_SESSION_BINDING", "").strip().lower()
    restart_required = bool(gateway_env) and mode != gateway_env

    if mode != previous:
        store = _get_detection_store(request)
        store.log_audit(
            action="admin_update_session_binding",
            target_id="session_binding",
            operator=_key_id,
            details={"old": previous, "new": mode},
        )
        logger.info(
            "Session binding mode updated by %s: %s → %s", _key_id, previous, mode
        )

    return {
        "status": "ok",
        "saved": mode,
        "gateway_active": gateway_env or "unset",
        "restart_required": restart_required,
    }
