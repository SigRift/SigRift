"""Report generation endpoints for The Bridge.

Generates downloadable HTML (and JSON) reports summarizing detections,
anomalies, spectrum activity, node status, and alerts over a configurable
time window.

HTML reports are self-contained with inline CSS and SVG bar charts,
styled for both screen and print.  PDF generation is supported when
weasyprint is installed, but HTML is the primary format.
"""

from __future__ import annotations

import html
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.models import DetectionQuery
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow

logger = logging.getLogger(__name__)
router = APIRouter()

_utcnow = utcnow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _h(val: Any) -> str:
    """HTML-escape a value, returning empty string for None."""
    return html.escape(str(val)) if val is not None else ""


def _ts_filename(prefix: str, ext: str) -> str:
    return f"{prefix}_{_utcnow().strftime('%Y%m%d_%H%M%S')}.{ext}"


def _fmt_freq(freq_hz: float) -> str:
    """Human-readable frequency label."""
    if freq_hz >= 1e9:
        return f"{freq_hz / 1e9:.3f} GHz"
    if freq_hz >= 1e6:
        return f"{freq_hz / 1e6:.3f} MHz"
    if freq_hz >= 1e3:
        return f"{freq_hz / 1e3:.1f} kHz"
    return f"{freq_hz:.0f} Hz"


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------


def _collect_report_data(
    request: Request,
    hours: int,
    sections: set[str],
) -> dict[str, Any]:
    """Gather report data from stores and persistence layer."""
    store = get_detection_store(request)
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    now = _utcnow()
    start_dt = now - timedelta(hours=hours)

    data: dict[str, Any] = {
        "period": {
            "start": start_dt.isoformat(),
            "end": now.isoformat(),
            "hours": hours,
        },
        "generated_at": now.isoformat(),
        "sections": sorted(sections),
    }

    # --- Executive summary (always included) ---
    summary: dict[str, Any] = {
        "total_detections": 0,
        "total_anomalies": 0,
        "total_alerts": 0,
        "active_nodes": 0,
        "total_nodes": 0,
    }

    # --- Detections ---
    detections: list[dict[str, Any]] = []
    if "detections" in sections or "spectrum" in sections:
        detections = store.query(
            DetectionQuery(
                start=start_dt,
                end=now,
                limit=10000,
            )
        )
        summary["total_detections"] = len(detections)

    if "detections" in sections:
        # Breakdown by signal class
        class_counts: dict[str, int] = {}
        family_counts: dict[str, int] = {}
        for d in detections:
            sc = d.get("signal_class", "unknown")
            fam = d.get("family", "unknown")
            class_counts[sc] = class_counts.get(sc, 0) + 1
            family_counts[fam] = family_counts.get(fam, 0) + 1

        sorted_classes = sorted(class_counts.items(), key=lambda x: x[1], reverse=True)
        data["detections"] = {
            "total": len(detections),
            "by_class": [{"signal_class": s, "count": c} for s, c in sorted_classes],
            "by_family": [
                {"family": f, "count": c}
                for f, c in sorted(
                    family_counts.items(), key=lambda x: x[1], reverse=True
                )
            ],
        }

    # --- Anomalies ---
    if "anomalies" in sections:
        rf_anomalies = store.get_rf_anomalies(
            min_score=0.0,
            limit=10000,
            include_dismissed=False,
        )
        wifi_anomalies = store.get_wifi_anomalies(
            min_score=0.0,
            limit=10000,
            include_dismissed=False,
        )

        def _in_range(ts: Any) -> bool:
            if not ts:
                return False
            try:
                dt = datetime.fromisoformat(str(ts)) if isinstance(ts, str) else ts
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return start_dt <= dt <= now
            except (ValueError, TypeError):
                return False

        rf_in_range = [a for a in rf_anomalies if _in_range(a.get("timestamp"))]
        wifi_in_range = [a for a in wifi_anomalies if _in_range(a.get("timestamp"))]

        severity_counts: dict[str, int] = {"critical": 0, "warning": 0, "info": 0}
        for a in rf_in_range + wifi_in_range:
            p = a.get("priority", "warning")
            severity_counts[p] = severity_counts.get(p, 0) + 1

        # Top anomalies by score
        all_anomalies = rf_in_range + wifi_in_range
        all_anomalies.sort(key=lambda x: x.get("anomaly_score", 0), reverse=True)
        top_anomalies = all_anomalies[:20]

        total_anomalies = len(rf_in_range) + len(wifi_in_range)
        summary["total_anomalies"] = total_anomalies

        data["anomalies"] = {
            "rf_total": len(rf_in_range),
            "wifi_total": len(wifi_in_range),
            "total": total_anomalies,
            "by_severity": severity_counts,
            "top": [
                {
                    "signal_class": a.get("signal_class", a.get("ssid", "N/A")),
                    "anomaly_score": round(a.get("anomaly_score", 0), 3),
                    "priority": a.get("priority", "warning"),
                    "freq_hz": a.get("freq_hz", 0),
                    "node_id": a.get("node_id", ""),
                    "timestamp": a.get("timestamp", ""),
                }
                for a in top_anomalies
            ],
        }

    # --- Spectrum ---
    if "spectrum" in sections:
        bands = store.get_spectrum_bands(hours=hours)
        active_freqs = store.get_active_frequency_count(hours=min(hours, 24))

        # Frequency distribution from detections
        freq_buckets: dict[str, int] = {}
        for d in detections:
            fhz = d.get("freq_hz", 0)
            if fhz > 0:
                label = _fmt_freq(fhz)
                freq_buckets[label] = freq_buckets.get(label, 0) + 1

        data["spectrum"] = {
            "active_frequencies": active_freqs,
            "bands": bands[:20] if bands else [],
            "freq_distribution": [
                {"frequency": f, "count": c}
                for f, c in sorted(
                    freq_buckets.items(), key=lambda x: x[1], reverse=True
                )[:15]
            ],
        }

    # --- Nodes ---
    if "nodes" in sections:
        nodes_data = persistence.get_nodes()
        node_list = []
        active_count = 0
        for nid, ndata in nodes_data.items():
            node_status = app_state.get_node_status(ndata)
            if node_status.value == "active":
                active_count += 1
            node_list.append(
                {
                    "node_id": nid,
                    "status": node_status.value,
                    "host": ndata.get("host", ""),
                    "last_seen": ndata.get("last_seen"),
                    "cpu_percent": ndata.get("cpu_percent"),
                    "memory_mb": ndata.get("memory_mb"),
                    "classifications_per_sec": ndata.get("classifications_per_sec", 0),
                }
            )
        summary["active_nodes"] = active_count
        summary["total_nodes"] = len(nodes_data)
        data["nodes"] = node_list

    # --- Alerts ---
    if "alerts" in sections:
        alerts = persistence.get_alerts()

        def _alert_in_range(a: dict) -> bool:
            triggered = a.get("triggered_at")
            if not triggered:
                return False
            try:
                dt = (
                    datetime.fromisoformat(str(triggered))
                    if isinstance(triggered, str)
                    else triggered
                )
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return start_dt <= dt <= now
            except (ValueError, TypeError):
                return False

        alerts_in_range = [a for a in alerts if _alert_in_range(a)]
        summary["total_alerts"] = len(alerts_in_range)

        data["alerts"] = [
            {
                "alert_id": a.get("alert_id", ""),
                "name": a.get("name", ""),
                "severity": a.get("severity", "info"),
                "message": a.get("message", ""),
                "triggered_at": a.get("triggered_at", ""),
                "acknowledged": a.get("acknowledged", False),
            }
            for a in alerts_in_range
        ]

    data["summary"] = summary
    return data


# ---------------------------------------------------------------------------
# HTML report renderer
# ---------------------------------------------------------------------------


def _render_svg_bar_chart(
    items: list[tuple[str, int]],
    title: str = "",
    max_bar_width: int = 400,
    bar_height: int = 22,
    gap: int = 4,
) -> str:
    """Render a simple horizontal bar chart as inline SVG."""
    if not items:
        return ""

    max_val = max(c for _, c in items) or 1
    chart_height = len(items) * (bar_height + gap) + 30
    label_width = 140

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{label_width + max_bar_width + 80}" '
        f'height="{chart_height}" style="font-family:Arial,sans-serif;font-size:12px;">',
    ]
    if title:
        lines.append(
            f'<text x="0" y="14" font-weight="600" font-size="13" fill="#333">{_h(title)}</text>'
        )

    y_offset = 24 if title else 4
    for i, (label, count) in enumerate(items):
        y = y_offset + i * (bar_height + gap)
        bar_w = max(2, int((count / max_val) * max_bar_width))
        color = "#1976d2" if i % 2 == 0 else "#2196f3"
        lines.append(
            f'<text x="{label_width - 4}" y="{y + bar_height - 6}" '
            f'text-anchor="end" fill="#444">{_h(label[:20])}</text>'
        )
        lines.append(
            f'<rect x="{label_width}" y="{y}" width="{bar_w}" '
            f'height="{bar_height - 2}" fill="{color}" rx="2"/>'
        )
        lines.append(
            f'<text x="{label_width + bar_w + 6}" y="{y + bar_height - 6}" '
            f'fill="#666">{count}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def _render_report_html(data: dict[str, Any]) -> str:
    """Render report data as a self-contained HTML document."""
    period = data["period"]
    summary = data.get("summary", {})
    sections = set(data.get("sections", []))

    lines = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="UTF-8">',
        "<title>RF SIGINT Report</title>",
        "<style>",
        "* { box-sizing: border-box; }",
        "body { font-family: Arial, Helvetica, sans-serif; margin: 40px; color: #222; line-height: 1.5; max-width: 1100px; }",
        "h1 { border-bottom: 3px solid #1a237e; padding-bottom: 10px; color: #1a237e; }",
        "h2 { color: #333; margin-top: 32px; border-bottom: 1px solid #ccc; padding-bottom: 6px; }",
        "h3 { color: #555; margin-top: 20px; }",
        "table { border-collapse: collapse; width: 100%; margin: 12px 0; }",
        "th, td { border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 13px; }",
        "th { background: #f0f0f0; font-weight: 600; }",
        "tr:nth-child(even) { background: #fafafa; }",
        ".badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; color: #fff; }",
        ".critical { background: #d32f2f; }",
        ".warning { background: #f57c00; }",
        ".info { background: #1976d2; }",
        ".active { background: #2e7d32; }",
        ".offline { background: #757575; }",
        ".degraded { background: #f57c00; }",
        ".stale { background: #9e9e9e; }",
        ".summary-grid { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0; }",
        ".summary-card { background: #f5f7fa; border: 1px solid #ddd; border-radius: 6px; padding: 16px 24px; min-width: 160px; text-align: center; }",
        ".summary-card .value { font-size: 28px; font-weight: 700; color: #1a237e; }",
        ".summary-card .label { font-size: 12px; color: #666; margin-top: 4px; }",
        ".chart-container { margin: 16px 0; }",
        ".footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #ccc; font-size: 11px; color: #888; }",
        "@media print { body { margin: 20px; } .summary-card { break-inside: avoid; } table { page-break-inside: auto; } tr { page-break-inside: avoid; } }",
        "</style></head><body>",
        "<h1>RF SIGINT Activity Report</h1>",
        f"<p><strong>Period:</strong> {_h(period['start'])} &mdash; {_h(period['end'])} ({period['hours']}h)<br>",
        f"<strong>Generated:</strong> {_h(data['generated_at'])}</p>",
    ]

    # -- Executive summary --
    lines.append("<h2>Executive Summary</h2>")
    lines.append('<div class="summary-grid">')
    lines.append(
        f'<div class="summary-card"><div class="value">{summary.get("total_detections", 0)}</div><div class="label">Total Detections</div></div>'
    )
    lines.append(
        f'<div class="summary-card"><div class="value">{summary.get("total_anomalies", 0)}</div><div class="label">Anomalies</div></div>'
    )
    lines.append(
        f'<div class="summary-card"><div class="value">{summary.get("total_alerts", 0)}</div><div class="label">Alerts</div></div>'
    )
    lines.append(
        f'<div class="summary-card"><div class="value">{summary.get("active_nodes", 0)}/{summary.get("total_nodes", 0)}</div><div class="label">Active Nodes</div></div>'
    )
    lines.append("</div>")

    # -- Detections section --
    if "detections" in sections and "detections" in data:
        det = data["detections"]
        lines.append("<h2>Detection Breakdown</h2>")
        lines.append(
            f"<p>Total detections in period: <strong>{det['total']}</strong></p>"
        )

        if det["by_class"]:
            # SVG bar chart
            chart_items = [
                (s["signal_class"], s["count"]) for s in det["by_class"][:15]
            ]
            lines.append('<div class="chart-container">')
            lines.append(
                _render_svg_bar_chart(chart_items, title="Detections by Signal Class")
            )
            lines.append("</div>")

            # Table
            lines.append(
                "<table><tr><th>Signal Class</th><th>Family</th><th>Count</th><th>Percentage</th></tr>"
            )
            # No direct class->family mapping in summary; use em-dash below
            for s in det["by_class"]:
                pct = (s["count"] / det["total"] * 100) if det["total"] > 0 else 0
                lines.append(
                    f"<tr><td>{_h(s['signal_class'])}</td><td>&mdash;</td><td>{s['count']}</td><td>{pct:.1f}%</td></tr>"
                )
            lines.append("</table>")

        if det.get("by_family"):
            lines.append("<h3>By Signal Family</h3>")
            lines.append("<table><tr><th>Family</th><th>Count</th></tr>")
            for f in det["by_family"]:
                lines.append(
                    f"<tr><td>{_h(f['family'])}</td><td>{f['count']}</td></tr>"
                )
            lines.append("</table>")

    # -- Anomalies section --
    if "anomalies" in sections and "anomalies" in data:
        anom = data["anomalies"]
        sev = anom["by_severity"]
        lines.append("<h2>Anomaly Summary</h2>")
        lines.append(
            f"<p>Total anomalies: <strong>{anom['total']}</strong> (RF: {anom['rf_total']}, WiFi: {anom['wifi_total']})</p>"
        )

        lines.append("<table><tr><th>Severity</th><th>Count</th></tr>")
        for sev_name in ("critical", "warning", "info"):
            cnt = sev.get(sev_name, 0)
            lines.append(
                f'<tr><td><span class="badge {sev_name}">{sev_name.title()}</span></td><td>{cnt}</td></tr>'
            )
        lines.append("</table>")

        if anom.get("top"):
            lines.append("<h3>Top Anomalies by Score</h3>")
            lines.append(
                "<table><tr><th>Signal/SSID</th><th>Score</th><th>Priority</th><th>Frequency</th><th>Node</th><th>Time</th></tr>"
            )
            for a in anom["top"][:10]:
                freq_label = _fmt_freq(a["freq_hz"]) if a.get("freq_hz") else "&mdash;"
                pri = a.get("priority", "warning")
                lines.append(
                    f"<tr><td>{_h(a['signal_class'])}</td>"
                    f"<td>{a['anomaly_score']:.3f}</td>"
                    f'<td><span class="badge {_h(pri)}">{_h(pri)}</span></td>'
                    f"<td>{freq_label}</td>"
                    f"<td>{_h(a['node_id'])}</td>"
                    f"<td>{_h(a['timestamp'])}</td></tr>"
                )
            lines.append("</table>")

    # -- Spectrum section --
    if "spectrum" in sections and "spectrum" in data:
        spec = data["spectrum"]
        lines.append("<h2>Spectrum Activity</h2>")
        lines.append(
            f"<p>Active frequencies: <strong>{spec.get('active_frequencies', 0)}</strong></p>"
        )

        if spec.get("freq_distribution"):
            chart_items = [
                (f["frequency"], f["count"]) for f in spec["freq_distribution"][:12]
            ]
            lines.append('<div class="chart-container">')
            lines.append(
                _render_svg_bar_chart(chart_items, title="Activity by Frequency")
            )
            lines.append("</div>")

        if spec.get("bands"):
            lines.append("<h3>Active Bands</h3>")
            lines.append(
                "<table><tr><th>Band</th><th>Detections</th><th>Avg SNR (dB)</th><th>Avg Power (dBm)</th></tr>"
            )
            for b in spec["bands"][:15]:
                avg_snr = b.get("avg_snr_db") or 0
                avg_pwr = b.get("avg_power_dbm") or 0
                lines.append(
                    f"<tr><td>{_h(b.get('band', b.get('label', '')))}</td>"
                    f"<td>{b.get('count', b.get('detection_count', 0))}</td>"
                    f"<td>{avg_snr:.1f}</td>"
                    f"<td>{avg_pwr:.1f}</td></tr>"
                )
            lines.append("</table>")

    # -- Nodes section --
    if "nodes" in sections and "nodes" in data:
        nodes = data["nodes"]
        lines.append("<h2>Node Status</h2>")
        if nodes:
            lines.append(
                "<table><tr><th>Node ID</th><th>Host</th><th>Status</th><th>CPU %</th><th>Memory MB</th><th>Last Seen</th></tr>"
            )
            for n in nodes:
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

    # -- Alerts section --
    if "alerts" in sections and "alerts" in data:
        alerts_list = data["alerts"]
        lines.append("<h2>Alert History</h2>")
        if alerts_list:
            lines.append(
                "<table><tr><th>Alert ID</th><th>Name</th><th>Severity</th><th>Message</th><th>Triggered</th><th>Ack</th></tr>"
            )
            for a in alerts_list:
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

    # -- Footer --
    lines.append(
        '<div class="footer">Generated by The Bridge &mdash; RF SIGINT Monitoring Platform</div>'
    )
    lines.append("</body></html>")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

_VALID_SECTIONS = {"detections", "anomalies", "spectrum", "nodes", "alerts"}
_DEFAULT_SECTIONS = "detections,anomalies,spectrum,nodes,alerts"


@router.get("/generate")
async def generate_report(
    request: Request,
    format: str = Query("html", description="Output format: html or json"),
    hours: int = Query(24, ge=1, le=720, description="Time window in hours"),
    sections: str = Query(
        _DEFAULT_SECTIONS,
        description="Comma-separated sections: detections, anomalies, spectrum, nodes, alerts",
    ),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> Any:
    """Generate a comprehensive report for a time window.

    Returns a self-contained HTML document (default) or JSON data.
    The HTML report includes executive summary, detection breakdown
    with SVG bar charts, anomaly summary, spectrum activity, node
    status, and alert history.  Styled for both screen and print.
    """
    import asyncio

    # Parse and validate sections
    requested = {s.strip().lower() for s in sections.split(",") if s.strip()}
    invalid = requested - _VALID_SECTIONS
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sections: {', '.join(sorted(invalid))}. "
            f"Valid: {', '.join(sorted(_VALID_SECTIONS))}",
        )
    if not requested:
        requested = _VALID_SECTIONS.copy()

    # Validate format
    fmt = format.lower()
    if fmt not in ("html", "json"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {format!r}. Must be 'html' or 'json'.",
        )

    data = await asyncio.to_thread(
        _collect_report_data,
        request,
        hours,
        requested,
    )

    if fmt == "html":
        html_content = _render_report_html(data)
        filename = _ts_filename("rf_sigint_report", "html")
        return StreamingResponse(
            io.StringIO(html_content),
            media_type="text/html; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )

    # JSON format
    filename = _ts_filename("rf_sigint_report", "json")
    return JSONResponse(
        content=data,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )
