"""Report export endpoints.

CSV and JSON export of node data, training history, and alert history.
All user-supplied data is HTML-escaped: in JSON every string, including
dict keys and strings inside lists, at any depth.  A CSV cell that a
spreadsheet would read as a formula is prefixed with ``'`` (see
:func:`_csv_safe`, the bridge export's rule).  CSV uses
``StreamingResponse``.
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

from sigrift.lib.shiny.dependencies import rate_limit
from sigrift.lib.shiny.models import ExportFormat, ExportReport
from sigrift.lib.shiny.routers.training import stored_runs_by_node

logger = logging.getLogger(__name__)
router = APIRouter()

_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731


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


def _esc(val: Any) -> str:
    return html.escape(str(val)) if val is not None else ""


#: Leading characters a spreadsheet may treat as the start of a formula
#: (the bridge export's ``_CSV_FORMULA_PREFIXES``).
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")
#: A plain number ("-85.5", "+3", "1e-3") is data, not a formula.
_CSV_NUMBER_RE = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")


def _csv_safe(value: Any) -> Any:
    """Neutralise CSV formula injection in one cell (OWASP), as the bridge does.

    Text that starts with ``= + - @``, TAB or CR is prefixed with a single
    quote so Excel / LibreOffice / Sheets show it instead of evaluating it:
    alert rule names, node hosts and training run ids are user-supplied (an
    alert rule named ``=HYPERLINK(...)`` would otherwise run in the
    spreadsheet of whoever opens the export).  Non-string values and plain
    numbers are unchanged.
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
        writer.writerow({k: _csv_safe(v) for k, v in row.items()})
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
    _key_id: str = Depends(rate_limit),
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
    _key_id: str = Depends(rate_limit),
) -> Any:
    """Export training history as JSON or CSV.

    The runs the history routes serve: a stored entry that is not a run
    (a hand-edited ``history.json``) is left out and not counted.
    """
    history = stored_runs_by_node(request.app.state.persistence.get_history())

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
    _key_id: str = Depends(rate_limit),
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
                pass  # Include alerts with unparseable timestamps
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
