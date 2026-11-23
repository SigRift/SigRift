"""Prometheus-compatible metrics endpoint for The Bridge.

Exposes ``/api/metrics`` in Prometheus text exposition format with basic
counters and gauges.  Does NOT require the ``prometheus_client`` library —
metric lines are generated as plain text.

Already mounted in app.py (at root, no prefix) for ``/metrics``.
``record_request()`` is called from ``CombinedMiddleware`` in ``app.py``.
"""

from __future__ import annotations

import logging
import threading
import time

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()

# Module-level counters — updated by middleware (see app.py CombinedMiddleware)
_metrics_lock = threading.Lock()
_request_counts: dict[tuple[str, str], int] = {}
_detection_count: int = 0
_start_time: float = time.monotonic()


def record_request(method: str, path: str) -> None:
    """Increment the per-(method, path) request counter.

    Call this from ASGI middleware on every request.
    """
    with _metrics_lock:
        key = (method, path)
        _request_counts[key] = _request_counts.get(key, 0) + 1


def record_detection(n: int = 1) -> None:
    """Increment the detection counter by *n*."""
    global _detection_count
    with _metrics_lock:
        _detection_count += n


def _prom_line(
    name: str, help_text: str, type_: str, value: float, labels: str = ""
) -> str:
    """Format a single Prometheus metric block."""
    lines = [
        f"# HELP {name} {help_text}",
        f"# TYPE {name} {type_}",
    ]
    if labels:
        lines.append(f"{name}{{{labels}}} {value}")
    else:
        lines.append(f"{name} {value}")
    return "\n".join(lines)


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> str:
    """Return metrics in Prometheus text exposition format."""
    app_state: AppState = request.app.state.app_state

    # -- Uptime ---------------------------------------------------------------
    uptime = time.monotonic() - _start_time
    blocks: list[str] = [
        _prom_line(
            "sigrift_uptime_seconds",
            "Time since server start in seconds",
            "gauge",
            round(uptime, 1),
        ),
    ]

    # -- Request counter (labeled by method + path) ---------------------------
    blocks.append("# HELP sigrift_requests_total Total HTTP requests")
    blocks.append("# TYPE sigrift_requests_total counter")
    with _metrics_lock:
        items = sorted(_request_counts.items())
    for (method, path), count in items:
        blocks.append(
            f'sigrift_requests_total{{method="{method}",path="{path}"}} {count}'
        )

    # -- Detection counter ----------------------------------------------------
    with _metrics_lock:
        det_count = _detection_count
    blocks.append(
        _prom_line(
            "sigrift_detections_total",
            "Total detections ingested",
            "counter",
            det_count,
        )
    )

    # -- Active WebSocket connections (gauge) ---------------------------------
    ws_total = (
        len(getattr(app_state, "ws_detection_clients", []))
        + len(getattr(app_state, "ws_anomaly_clients", []))
        + len(getattr(app_state, "ws_spectrum_clients", []))
        + len(getattr(app_state, "ws_wifi_clients", []))
        + len(getattr(app_state, "ws_status_clients", []))
        + len(getattr(app_state, "ws_alert_clients", []))
        + len(getattr(app_state, "ws_activity_clients", []))
        + len(getattr(app_state, "ws_training_clients", []))
    )
    blocks.append(
        _prom_line(
            "sigrift_active_websockets",
            "Number of active WebSocket connections",
            "gauge",
            ws_total,
        )
    )

    return "\n\n".join(blocks) + "\n"
