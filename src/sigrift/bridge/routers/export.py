"""Report export endpoints for The Bridge.

CSV and JSON export of node data, training history, alert history,
and detection data.  In JSON every string of a stored record is
HTML-escaped, dict keys and strings inside lists included, at any depth
(the Shiny export's rule).

Adapted from sigrift.lib.shiny.routers.export for The Bridge.
"""

from __future__ import annotations

import csv
import html
import io
import logging
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.models import ExportFormat, ExportReport
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow

logger = logging.getLogger(__name__)
router = APIRouter()

_utcnow = utcnow


def _ts_filename(prefix: str, ext: str) -> str:
    return f"{prefix}_{_utcnow().strftime('%Y%m%d_%H%M%S')}.{ext}"


def _escape_value(v: Any) -> Any:
    """*v* with every string in it HTML-escaped: dict keys, list items, any depth."""
    if isinstance(v, str):
        return html.escape(v)
    if isinstance(v, dict):
        return {_escape_value(k): _escape_value(item) for k, item in v.items()}
    if isinstance(v, (list, tuple)):
        return [_escape_value(item) for item in v]
    return v


def _escape_dict(d: dict[str, Any]) -> dict[str, Any]:
    """HTML-escape every string in *d*: keys and values, lists and dicts within."""
    return _escape_value(d)


def _stored_runs_by_node(history: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Each node's stored training runs, oldest first.

    A value that is not a list, or an entry that is not an object (a
    hand-edited ``history.json``), is left out and not counted.
    """
    return {
        node_id: [entry for entry in entries if isinstance(entry, dict)]
        for node_id, entries in history.items()
        if isinstance(entries, list)
    }


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


#: Leading characters a spreadsheet may treat as the start of a formula.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
#: A plain number ("-85.5", "+3", "1e-3") is data, not a formula.
_CSV_NUMBER_RE = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")


def _csv_safe(value: Any) -> Any:
    """Neutralise CSV formula injection in one cell (OWASP).

    Text that starts with ``= + - @``, TAB or CR is prefixed with a single
    quote so Excel / LibreOffice / Sheets show it instead of evaluating it
    — SSIDs, device names and alert messages come from over the air (an
    SSID of ``=HYPERLINK(...)`` would otherwise run in the analyst's
    spreadsheet).  Non-string values and plain numbers are unchanged.
    """
    if (
        isinstance(value, str)
        and value.startswith(_CSV_FORMULA_PREFIXES)
        and not _CSV_NUMBER_RE.fullmatch(value)
    ):
        return "'" + value
    return value


def _build_csv(rows: list[dict[str, Any]], fields: list[str]) -> io.StringIO:
    """Build a CSV of *fields* from *rows*; every cell goes through :func:`_csv_safe`."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _csv_safe(row.get(k)) for k in fields if k in row})
    buf.seek(0)
    return buf


def _csv_response(buf: io.StringIO, filename: str) -> StreamingResponse:
    return StreamingResponse(
        buf,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _json_response(payload: dict[str, Any], filename: str) -> JSONResponse:
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# -- Field definitions for CSV export --------------------------------------

_NODE_FIELDS = [
    "node_id",
    "host",
    "port",
    "status",
    "cpu_percent",
    "memory_mb",
    "classifications_per_sec",
    "current_frequency_hz",
    "last_seen",
    "registered_at",
]

_ALERT_FIELDS = [
    "alert_id",
    "name",
    "severity",
    "message",
    "node_id",
    "triggered_at",
    "acknowledged",
    "acknowledged_at",
]

_HISTORY_FIELDS = [
    "node_id",
    "run_id",
    "started_at",
    "finished_at",
    "total_epochs",
    "best_epoch",
    "best_val_acc",
    "final_acc_cls",
]

_DETECTION_FIELDS = [
    "detection_id",
    "node_id",
    "timestamp",
    "signal_class",
    "confidence",
    "family",
    "freq_hz",
    "snr_db",
    "power_dbm",
    "inference_ms",
    "backend",
    "anomaly_score",
    "baseline_status",
]

_ANOMALY_FIELDS = [
    "detection_id",
    "node_id",
    "timestamp",
    "signal_class",
    "confidence",
    "family",
    "freq_hz",
    "anomaly_score",
    "baseline_status",
    "snr_db",
    "power_dbm",
]

_WIFI_NETWORK_FIELDS = [
    "bssid",
    "ssid",
    "channel",
    "channel_width",
    "band",
    "security",
    "avg_signal_dbm",
    "client_count",
    "frame_count",
    "last_seen",
]

_WIFI_ANOMALY_FIELDS = [
    "id",
    "bssid",
    "ssid",
    "channel",
    "band",
    "security",
    "signal_dbm",
    "anomaly_score",
    "priority",
    "baseline_status",
    "node_id",
    "timestamp",
    "dismissed",
    "seen_count",
    "first_seen",
]

_RF_ANOMALY_FIELDS = [
    "id",
    "detection_id",
    "signal_class",
    "family",
    "freq_hz",
    "node_id",
    "timestamp",
    "confidence",
    "snr_db",
    "power_dbm",
    "anomaly_score",
    "priority",
    "baseline_status",
    "dismissed",
    "seen_count",
    "first_seen",
]


def _flatten_node(nid: str, d: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": _esc(nid),
        "host": _esc(d.get("host")),
        "port": d.get("port", 0),
        "status": _esc(d.get("status")),
        "cpu_percent": d.get("cpu_percent", 0.0),
        "memory_mb": d.get("memory_mb", 0.0),
        "classifications_per_sec": d.get("classifications_per_sec", 0.0),
        "current_frequency_hz": d.get("current_frequency_hz", 0.0),
        "last_seen": _esc(d.get("last_seen")),
        "registered_at": _esc(d.get("registered_at")),
    }


def _flatten_alert(a: dict[str, Any]) -> dict[str, Any]:
    return {
        "alert_id": _esc(a.get("alert_id")),
        "name": _esc(a.get("name")),
        "severity": _esc(a.get("severity")),
        "message": _esc(a.get("message")),
        "node_id": _esc(a.get("node_id")),
        "triggered_at": _esc(a.get("triggered_at")),
        "acknowledged": a.get("acknowledged", False),
        "acknowledged_at": _esc(a.get("acknowledged_at")),
    }


def _flatten_history(nid: str, e: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": _esc(nid),
        "run_id": _esc(e.get("run_id")),
        "started_at": _esc(e.get("started_at")),
        "finished_at": _esc(e.get("finished_at")),
        "total_epochs": e.get("total_epochs", 0),
        "best_epoch": e.get("best_epoch", 0),
        "best_val_acc": e.get("best_val_acc", 0.0),
        "final_acc_cls": e.get("final_acc_cls", 0.0),
    }


# -- Date filter helper -----------------------------------------------------


def _parse_iso_date(value: str, label: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Invalid {label}: {value!r}")


# -- GET /nodes -------------------------------------------------------------


@router.get("/nodes")
async def export_nodes(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export node data as JSON or CSV."""
    nodes = request.app.state.persistence.get_nodes()

    if format == ExportFormat.csv:
        rows = [_flatten_node(nid, nd) for nid, nd in nodes.items()]
        return _csv_response(
            _build_csv(rows, _NODE_FIELDS), _ts_filename("nodes_export", "csv")
        )

    escaped = {_esc(nid): _escape_dict(nd) for nid, nd in nodes.items()}
    meta = ExportReport(
        format=ExportFormat.json, record_count=len(escaped), generated_at=_utcnow()
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "nodes": escaped},
        _ts_filename("nodes_export", "json"),
    )


# -- GET /training ----------------------------------------------------------


@router.get("/training")
async def export_training(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export training history as JSON or CSV.

    A stored entry that is not a run (a hand-edited ``history.json``) is
    left out and not counted.
    """
    history = _stored_runs_by_node(request.app.state.persistence.get_history())

    if format == ExportFormat.csv:
        rows = [
            _flatten_history(nid, e)
            for nid, entries in history.items()
            for e in entries
        ]
        return _csv_response(
            _build_csv(rows, _HISTORY_FIELDS), _ts_filename("training_export", "csv")
        )

    escaped: dict[str, Any] = {}
    total = 0
    for nid, entries in history.items():
        escaped[_esc(nid)] = [_escape_dict(e) for e in entries]
        total += len(entries)

    meta = ExportReport(
        format=ExportFormat.json, record_count=total, generated_at=_utcnow()
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "history": escaped},
        _ts_filename("training_export", "json"),
    )


# -- GET /alerts ------------------------------------------------------------


@router.get("/alerts")
async def export_alerts(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    start_date: str | None = Query(None, description="ISO 8601 start"),
    end_date: str | None = Query(None, description="ISO 8601 end"),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export alert history with optional date range filter."""
    alerts = request.app.state.persistence.get_alerts()

    start_dt = _parse_iso_date(start_date, "start_date") if start_date else None
    end_dt = _parse_iso_date(end_date, "end_date") if end_date else None

    filtered: list[dict[str, Any]] = []
    for alert in alerts:
        triggered = alert.get("triggered_at")
        if triggered and (start_dt or end_dt):
            try:
                alert_dt = (
                    datetime.fromisoformat(triggered)
                    if isinstance(triggered, str)
                    else triggered
                )
                if alert_dt.tzinfo is None:
                    alert_dt = alert_dt.replace(tzinfo=timezone.utc)
                if start_dt and alert_dt < start_dt:
                    continue
                if end_dt and alert_dt > end_dt:
                    continue
            except (ValueError, TypeError):
                pass
        filtered.append(alert)

    if format == ExportFormat.csv:
        rows = [_flatten_alert(a) for a in filtered]
        return _csv_response(
            _build_csv(rows, _ALERT_FIELDS), _ts_filename("alerts_export", "csv")
        )

    escaped = [_escape_dict(a) for a in filtered]
    filters: dict[str, Any] = {}
    if start_date:
        filters["start_date"] = start_date
    if end_date:
        filters["end_date"] = end_date

    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(escaped),
        generated_at=_utcnow(),
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "alerts": escaped},
        _ts_filename("alerts_export", "json"),
    )


# -- GET /detections --------------------------------------------------------


@router.get("/detections")
async def export_detections(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    hours: int = Query(24, ge=1, le=168),
    node_id: str | None = Query(None),
    signal_class: str | None = Query(None),
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    min_anomaly_score: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(10000, ge=1, le=50000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export detection data as JSON or CSV.

    Supports filtering by node, signal class, minimum confidence,
    and minimum anomaly score.
    """
    from sigrift.bridge.models import DetectionQuery
    from datetime import timedelta

    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not available",
        )

    now = _utcnow()
    q = DetectionQuery(
        start=now - timedelta(hours=hours),
        end=now,
        node_id=node_id,
        signal_class=signal_class,
        min_confidence=min_confidence,
        limit=limit,
    )
    rows = detection_store.query(q)

    # Post-filter by anomaly score (not in DetectionQuery)
    if min_anomaly_score > 0.0:
        rows = [r for r in rows if r.get("anomaly_score", 0.0) >= min_anomaly_score]

    if format == ExportFormat.csv:
        return _csv_response(
            _build_csv(rows, _DETECTION_FIELDS),
            _ts_filename("detections_export", "csv"),
        )

    filters: dict[str, Any] = {
        "hours": hours,
        "node_id": node_id,
        "signal_class": signal_class,
    }
    if min_confidence > 0.0:
        filters["min_confidence"] = min_confidence
    if min_anomaly_score > 0.0:
        filters["min_anomaly_score"] = min_anomaly_score

    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(rows),
        generated_at=now,
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "detections": rows},
        _ts_filename("detections_export", "json"),
    )


# -- GET /anomalies --------------------------------------------------------


@router.get("/anomalies")
async def export_anomalies(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    hours: int = Query(24, ge=1, le=168),
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    node_id: str | None = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export anomaly detections as JSON or CSV.

    Exports detections with anomaly scores above the threshold,
    sorted by score descending.
    """
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not available",
        )

    rows = detection_store.get_anomalies(
        min_score=min_score,
        limit=limit,
        node_id=node_id,
    )

    if format == ExportFormat.csv:
        return _csv_response(
            _build_csv(rows, _ANOMALY_FIELDS),
            _ts_filename("anomalies_export", "csv"),
        )

    filters: dict[str, Any] = {
        "hours": hours,
        "min_score": min_score,
        "node_id": node_id,
    }
    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(rows),
        generated_at=_utcnow(),
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "anomalies": rows},
        _ts_filename("anomalies_export", "json"),
    )


# -- GET /wifi_networks ------------------------------------------------


@router.get("/wifi_networks")
async def export_wifi_networks(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    band: str | None = Query(None),
    node_id: str | None = Query(None),
    limit: int = Query(500, ge=1, le=10000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export WiFi network summary (aggregated by BSSID)."""
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not available",
        )

    rows = detection_store.get_wifi_networks(
        limit=limit,
        band=band,
        node_id=node_id,
    )

    if format == ExportFormat.csv:
        return _csv_response(
            _build_csv(rows, _WIFI_NETWORK_FIELDS),
            _ts_filename("wifi_networks_export", "csv"),
        )

    filters: dict[str, Any] = {"band": band, "node_id": node_id}
    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(rows),
        generated_at=_utcnow(),
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "wifi_networks": rows},
        _ts_filename("wifi_networks_export", "json"),
    )


# -- GET /wifi_anomalies ------------------------------------------------


@router.get("/wifi_anomalies")
async def export_wifi_anomalies(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    include_dismissed: bool = Query(False),
    limit: int = Query(5000, ge=1, le=50000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export WiFi anomalies."""
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not available",
        )

    rows = detection_store.get_wifi_anomalies(
        min_score=min_score,
        limit=limit,
        include_dismissed=include_dismissed,
    )

    if format == ExportFormat.csv:
        return _csv_response(
            _build_csv(rows, _WIFI_ANOMALY_FIELDS),
            _ts_filename("wifi_anomalies_export", "csv"),
        )

    filters: dict[str, Any] = {
        "min_score": min_score,
        "include_dismissed": include_dismissed,
    }
    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(rows),
        generated_at=_utcnow(),
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "wifi_anomalies": rows},
        _ts_filename("wifi_anomalies_export", "json"),
    )


# -- GET /rf_anomalies ------------------------------------------------


@router.get("/rf_anomalies")
async def export_rf_anomalies(
    request: Request,
    format: ExportFormat = Query(ExportFormat.json),
    min_score: float = Query(0.3, ge=0.0, le=1.0),
    include_dismissed: bool = Query(False),
    family: str | None = Query(None),
    signal_class: str | None = Query(None),
    limit: int = Query(5000, ge=1, le=50000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Export RF anomalies with optional filtering."""
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not available",
        )

    rows = detection_store.get_rf_anomalies(
        min_score=min_score,
        limit=limit,
        include_dismissed=include_dismissed,
        family=family,
        signal_class=signal_class,
    )

    if format == ExportFormat.csv:
        return _csv_response(
            _build_csv(rows, _RF_ANOMALY_FIELDS),
            _ts_filename("rf_anomalies_export", "csv"),
        )

    filters: dict[str, Any] = {
        "min_score": min_score,
        "include_dismissed": include_dismissed,
        "family": family,
        "signal_class": signal_class,
    }
    meta = ExportReport(
        format=ExportFormat.json,
        record_count=len(rows),
        generated_at=_utcnow(),
        filters=filters,
    )
    return _json_response(
        {"meta": meta.model_dump(mode="json"), "rf_anomalies": rows},
        _ts_filename("rf_anomalies_export", "json"),
    )


# -- GET /report --------------------------------------------------------


def _collect_report_data(
    request: Request,
    start_dt: datetime,
    end_dt: datetime,
) -> dict[str, Any]:
    """Gather all report sections from stores and persistence."""

    store = get_detection_store(request)
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    start_iso = start_dt.isoformat()
    end_iso = end_dt.isoformat()

    # --- Anomaly summary (counts by priority/severity) ---
    wifi_anomalies = store.get_wifi_anomalies(
        min_score=0.0, limit=50000, include_dismissed=True
    )
    rf_anomalies = store.get_rf_anomalies(
        min_score=0.0, limit=50000, include_dismissed=True
    )

    def _in_range(ts: Any) -> bool:
        if not ts:
            return False
        try:
            dt = datetime.fromisoformat(str(ts)) if isinstance(ts, str) else ts
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return start_dt <= dt <= end_dt
        except (ValueError, TypeError):
            return False

    wifi_in_range = [a for a in wifi_anomalies if _in_range(a.get("timestamp"))]
    rf_in_range = [a for a in rf_anomalies if _in_range(a.get("timestamp"))]

    severity_counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0}
    for a in wifi_in_range:
        p = a.get("priority", "warning")
        severity_counts[p] = severity_counts.get(p, 0) + 1
    for a in rf_in_range:
        p = a.get("priority", "warning")
        severity_counts[p] = severity_counts.get(p, 0) + 1

    anomaly_summary = {
        "wifi_total": len(wifi_in_range),
        "rf_total": len(rf_in_range),
        "by_severity": severity_counts,
    }

    # --- Top signals detected ---
    from sigrift.bridge.models import DetectionQuery

    detections = store.query(
        DetectionQuery(
            start=start_dt,
            end=end_dt,
            limit=10000,
        )
    )
    signal_counts: dict[str, int] = {}
    for d in detections:
        sc = d.get("signal_class", "unknown")
        signal_counts[sc] = signal_counts.get(sc, 0) + 1
    top_signals = sorted(signal_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # --- Operator actions (audit log) ---
    audit_entries = store.get_audit_log(limit=5000)
    audit_in_range = [e for e in audit_entries if _in_range(e.get("timestamp"))]
    # Count by action type
    action_counts: dict[str, int] = {}
    for e in audit_in_range:
        act = e.get("action", "unknown")
        action_counts[act] = action_counts.get(act, 0) + 1
    operator_actions = {
        "total": len(audit_in_range),
        "by_action": dict(
            sorted(action_counts.items(), key=lambda x: x[1], reverse=True)
        ),
        "recent": audit_in_range[:20],
    }

    # --- Alert history ---
    alerts = persistence.get_alerts()
    alerts_in_range = [a for a in alerts if _in_range(a.get("triggered_at"))]

    # --- Node status summary ---
    nodes_data = persistence.get_nodes()
    node_summary = []
    for nid, ndata in nodes_data.items():
        node_status = app_state.get_node_status(ndata)
        node_summary.append(
            {
                "node_id": nid,
                "status": node_status.value,
                "host": ndata.get("host", ""),
                "last_seen": ndata.get("last_seen"),
                "cpu_percent": ndata.get("cpu_percent"),
                "memory_mb": ndata.get("memory_mb"),
            }
        )

    return {
        "period": {"start": start_iso, "end": end_iso},
        "generated_at": _utcnow().isoformat(),
        "anomaly_summary": anomaly_summary,
        "top_signals": [{"signal_class": s, "count": c} for s, c in top_signals],
        "detection_count": len(detections),
        "operator_actions": operator_actions,
        "alerts": [_escape_dict(a) for a in alerts_in_range],
        "node_summary": node_summary,
    }


def _render_report_html(data: dict[str, Any]) -> str:
    """Render report data as a self-contained HTML document with inline CSS."""
    period = data["period"]
    anomaly = data["anomaly_summary"]
    sev = anomaly["by_severity"]

    def _h(v: Any) -> str:
        return html.escape(str(v)) if v is not None else ""

    lines = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="UTF-8">',
        "<title>Compliance Report</title>",
        "<style>",
        "body{font-family:Arial,Helvetica,sans-serif;margin:40px;color:#222;line-height:1.5;}",
        "h1{border-bottom:2px solid #333;padding-bottom:8px;}",
        "h2{color:#444;margin-top:28px;border-bottom:1px solid #ccc;padding-bottom:4px;}",
        "table{border-collapse:collapse;width:100%;margin:12px 0;}",
        "th,td{border:1px solid #ccc;padding:6px 10px;text-align:left;font-size:13px;}",
        "th{background:#f0f0f0;font-weight:600;}",
        ".badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:12px;font-weight:600;color:#fff;}",
        ".critical{background:#d32f2f;}.warning{background:#f57c00;}.info{background:#1976d2;}",
        ".active{background:#2e7d32;}.offline{background:#757575;}.degraded{background:#f57c00;}",
        ".footer{margin-top:40px;padding-top:12px;border-top:1px solid #ccc;font-size:11px;color:#888;}",
        "@media print{body{margin:20px;}}",
        "</style></head><body>",
        "<h1>RF Monitoring — Compliance Report</h1>",
        f"<p><strong>Period:</strong> {_h(period['start'])} &mdash; {_h(period['end'])}<br>",
        f"<strong>Generated:</strong> {_h(data['generated_at'])}</p>",
    ]

    # -- Anomaly Summary --
    lines.append("<h2>Anomaly Summary</h2>")
    lines.append("<table><tr><th>Category</th><th>Count</th></tr>")
    lines.append(f"<tr><td>WiFi Anomalies</td><td>{anomaly['wifi_total']}</td></tr>")
    lines.append(f"<tr><td>RF Anomalies</td><td>{anomaly['rf_total']}</td></tr>")
    lines.append(
        f'<tr><td><span class="badge critical">Critical</span></td><td>{sev.get("critical", 0)}</td></tr>'
    )
    lines.append(
        f'<tr><td><span class="badge warning">Warning</span></td><td>{sev.get("warning", 0)}</td></tr>'
    )
    lines.append(
        f'<tr><td><span class="badge info">Info</span></td><td>{sev.get("info", 0)}</td></tr>'
    )
    lines.append("</table>")

    # -- Top Signals --
    lines.append("<h2>Top Signals Detected</h2>")
    if data["top_signals"]:
        lines.append(
            f"<p>Total detections in period: <strong>{data['detection_count']}</strong></p>"
        )
        lines.append("<table><tr><th>Signal Class</th><th>Count</th></tr>")
        for s in data["top_signals"]:
            lines.append(
                f"<tr><td>{_h(s['signal_class'])}</td><td>{s['count']}</td></tr>"
            )
        lines.append("</table>")
    else:
        lines.append("<p>No detections in this period.</p>")

    # -- Operator Actions --
    ops = data["operator_actions"]
    lines.append("<h2>Operator Actions</h2>")
    lines.append(f"<p>Total audit events: <strong>{ops['total']}</strong></p>")
    if ops["by_action"]:
        lines.append("<table><tr><th>Action</th><th>Count</th></tr>")
        for act, cnt in ops["by_action"].items():
            lines.append(f"<tr><td><code>{_h(act)}</code></td><td>{cnt}</td></tr>")
        lines.append("</table>")

    # Recent actions table
    if ops["recent"]:
        lines.append("<h3>Recent Actions</h3>")
        lines.append(
            "<table><tr><th>Timestamp</th><th>Action</th><th>Target</th><th>Operator</th><th>Note</th></tr>"
        )
        for e in ops["recent"]:
            lines.append(
                f"<tr><td>{_h(e.get('timestamp'))}</td>"
                f"<td><code>{_h(e.get('action'))}</code></td>"
                f"<td>{_h(e.get('target_id'))}</td>"
                f"<td>{_h(e.get('operator'))}</td>"
                f"<td>{_h(e.get('note'))}</td></tr>"
            )
        lines.append("</table>")

    # -- Alert History --
    lines.append("<h2>Alert History</h2>")
    if data["alerts"]:
        lines.append(
            "<table><tr><th>Alert ID</th><th>Name</th><th>Severity</th><th>Message</th><th>Triggered</th><th>Ack</th></tr>"
        )
        for a in data["alerts"]:
            sev_cls = _h(a.get("severity", "info"))
            lines.append(
                f"<tr><td>{_h(a.get('alert_id'))}</td>"
                f"<td>{_h(a.get('name'))}</td>"
                f'<td><span class="badge {sev_cls}">{sev_cls}</span></td>'
                f"<td>{_h(a.get('message'))}</td>"
                f"<td>{_h(a.get('triggered_at'))}</td>"
                f"<td>{'Yes' if a.get('acknowledged') else 'No'}</td></tr>"
            )
        lines.append("</table>")
    else:
        lines.append("<p>No alerts in this period.</p>")

    # -- Node Status --
    lines.append("<h2>Node Status</h2>")
    if data["node_summary"]:
        lines.append(
            "<table><tr><th>Node ID</th><th>Host</th><th>Status</th><th>CPU %</th><th>Mem MB</th><th>Last Seen</th></tr>"
        )
        for n in data["node_summary"]:
            st = _h(n.get("status", "unknown"))
            lines.append(
                f"<tr><td>{_h(n['node_id'])}</td>"
                f"<td>{_h(n.get('host'))}</td>"
                f'<td><span class="badge {st}">{st}</span></td>'
                f"<td>{_h(n.get('cpu_percent'))}</td>"
                f"<td>{_h(n.get('memory_mb'))}</td>"
                f"<td>{_h(n.get('last_seen'))}</td></tr>"
            )
        lines.append("</table>")
    else:
        lines.append("<p>No nodes registered.</p>")

    lines.append(
        '<div class="footer">Generated by The Bridge — RF Monitoring Platform</div>'
    )
    lines.append("</body></html>")

    return "\n".join(lines)


@router.get("/report")
async def export_compliance_report(
    request: Request,
    start: str = Query(..., description="ISO 8601 start of report period"),
    end: str = Query(..., description="ISO 8601 end of report period"),
    format: ExportFormat = Query(ExportFormat.html),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Generate a compliance/incident report for a time range.

    Includes anomaly summary, top signals, operator actions,
    alert history, and node status.
    """
    import asyncio

    start_dt = _parse_iso_date(start, "start")
    end_dt = _parse_iso_date(end, "end")

    if end_dt <= start_dt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end must be after start",
        )

    data = await asyncio.to_thread(_collect_report_data, request, start_dt, end_dt)

    if format == ExportFormat.html:
        html_content = _render_report_html(data)
        return StreamingResponse(
            io.StringIO(html_content),
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{_ts_filename("compliance_report", "html")}"'
            },
        )

    # JSON format
    return _json_response(data, _ts_filename("compliance_report", "json"))
