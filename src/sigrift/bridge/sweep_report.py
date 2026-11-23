"""Sweep report generator for TSCM engagements.

Collects data from multiple stores and renders a self-contained HTML
report covering executive summary, findings, device inventory,
coverage verification, and recommendations.
"""

from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class SweepReportGenerator:
    """Generates HTML reports from sweep session data.

    Parameters
    ----------
    sweep_store : SweepStore
        Sweep session storage.
    incident_store : IncidentStore
        Incident lifecycle storage.
    detection_store : DetectionStore
        Detection and analytics storage.
    """

    def __init__(
        self,
        sweep_store: Any,
        incident_store: Any,
        detection_store: Any,
    ) -> None:
        self._sweeps = sweep_store
        self._incidents = incident_store
        self._detections = detection_store

    def collect_data(self, sweep_id: str) -> dict[str, Any] | None:
        """Collect all report data for a sweep."""
        summary = self._sweeps.get_sweep_summary(sweep_id)
        if not summary:
            return None

        zones = self._sweeps.get_zones(sweep_id)
        linked_det_ids = self._sweeps.get_linked_detections(sweep_id)
        linked_inc_ids = self._sweeps.get_linked_incidents(sweep_id)

        # Fetch incident details
        incidents = []
        for inc_id in linked_inc_ids:
            inc = self._incidents.get_incident(inc_id)
            if inc:
                timeline = self._incidents.get_timeline(inc_id)
                incidents.append({**inc, "timeline": timeline})

        # Fetch detection details from DB
        detections = []
        if linked_det_ids:
            conn = self._detections.get_connection()
            for det_id in linked_det_ids:
                row = conn.execute(
                    "SELECT * FROM detections WHERE detection_id = ?",
                    (det_id,),
                ).fetchone()
                if row:
                    detections.append(dict(row))

        return {
            "sweep": summary,
            "zones": zones,
            "incidents": incidents,
            "detections": detections,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def render_html(self, sweep_id: str) -> str | None:
        """Render a self-contained HTML report for a sweep."""
        data = self.collect_data(sweep_id)
        if not data:
            return None

        sweep = data["sweep"]
        zones = data["zones"]
        incidents = data["incidents"]
        detections = data["detections"]

        # Zone summary stats
        cleared = sum(1 for z in zones if z["status"] == "cleared")
        flagged = sum(1 for z in zones if z["status"] == "flagged")
        pending = sum(1 for z in zones if z["status"] == "pending")

        # Executive summary
        finding_level = "CLEAR" if flagged == 0 else "FINDINGS PRESENT"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TSCM Sweep Report — {_esc(sweep["name"])}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; }}
  h1 {{ border-bottom: 3px solid #1a1a1a; padding-bottom: 8px; }}
  h2 {{ color: #2d3748; margin-top: 2em; }}
  .meta {{ color: #666; font-size: 0.9em; }}
  .badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
            font-weight: bold; font-size: 0.85em; }}
  .badge-clear {{ background: #c6f6d5; color: #22543d; }}
  .badge-findings {{ background: #fed7d7; color: #742a2a; }}
  .badge-pending {{ background: #fefcbf; color: #744210; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1em 0; }}
  th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
  th {{ background: #f7fafc; font-weight: 600; }}
  .flagged {{ color: #c53030; font-weight: bold; }}
  .cleared {{ color: #276749; }}
  .section {{ margin-bottom: 2em; }}
  @media print {{ body {{ max-width: 100%; margin: 0; }} }}
  @media (max-width: 768px) {{ body {{ padding: 0 10px; }}
    table {{ font-size: 0.85em; }} }}
</style>
</head>
<body>

<h1>TSCM Sweep Report</h1>
<div class="meta">
  <p><strong>Engagement:</strong> {_esc(sweep["name"])}</p>
  <p><strong>Location:</strong> {_esc(sweep.get("location", "N/A"))}</p>
  <p><strong>Phase:</strong> {_esc(sweep["phase"])}</p>
  <p><strong>Start:</strong> {_esc(sweep.get("start_time", "N/A"))}
     | <strong>End:</strong> {_esc(sweep.get("end_time", "In progress"))}</p>
  <p><strong>Generated:</strong> {_esc(data["generated_at"])}</p>
</div>

<h2>1. Executive Summary</h2>
<div class="section">
  <p>Overall status:
    <span class="badge {"badge-clear" if flagged == 0 else "badge-findings"}">{finding_level}</span>
  </p>
  <p>Zones surveyed: <strong>{len(zones)}</strong>
     (Cleared: {cleared}, Flagged: {flagged}, Pending: {pending})</p>
  <p>Detections linked: <strong>{len(detections)}</strong></p>
  <p>Incidents created: <strong>{len(incidents)}</strong></p>
  {"<p><strong>Scope:</strong> " + _esc(sweep.get("scope_description", "")) + "</p>" if sweep.get("scope_description") else ""}  # noqa: invalid-syntax
  {"<p><strong>Threat profile:</strong> " + _esc(sweep.get("threat_profile", "")) + "</p>" if sweep.get("threat_profile") else ""}  # noqa: invalid-syntax
</div>

<h2>2. Zone Coverage</h2>
<div class="section">
{_render_zone_table(zones)}
</div>

<h2>3. Findings</h2>
<div class="section">
{_render_incidents(incidents) if incidents else "<p>No incidents recorded during this sweep.</p>"}
</div>

<h2>4. Detection Inventory</h2>
<div class="section">
{_render_detections(detections) if detections else "<p>No detections linked to this sweep.</p>"}
</div>

<h2>5. Recommendations</h2>
<div class="section">
{_render_recommendations(flagged, incidents)}
</div>

<hr>
<p class="meta">Generated by SigRift TSCM Module</p>
</body>
</html>"""


def _esc(val: Any) -> str:
    """HTML-escape a value, handling None."""
    return html.escape(str(val)) if val is not None else "N/A"


def _render_zone_table(zones: list[dict]) -> str:
    if not zones:
        return "<p>No zones defined.</p>"

    rows = ""
    for z in zones:
        status_class = (
            "flagged"
            if z["status"] == "flagged"
            else ("cleared" if z["status"] == "cleared" else "")
        )
        rows += (
            f"<tr><td>{_esc(z['zone_name'])}</td>"
            f"<td class='{status_class}'>{_esc(z['status'])}</td>"
            f"<td>{z.get('anomaly_count', 0)}</td>"
            f"<td>{_esc(z.get('flagged_reason', ''))}</td></tr>\n"
        )

    return f"""<table>
<thead><tr><th>Zone</th><th>Status</th><th>Anomalies</th><th>Notes</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _render_incidents(incidents: list[dict]) -> str:
    parts = []
    for inc in incidents:
        parts.append(
            f"<h3>{_esc(inc['title'])} "
            f"<span class='badge badge-findings'>{_esc(inc['severity'])}</span></h3>"
            f"<p>Status: {_esc(inc['status'])} | "
            f"Resolution: {_esc(inc.get('resolution', 'pending'))}</p>"
            f"<p>{_esc(inc.get('description', ''))}</p>"
        )
        if inc.get("resolution_note"):
            parts.append(f"<p><em>{_esc(inc['resolution_note'])}</em></p>")
    return "\n".join(parts)


def _render_detections(detections: list[dict]) -> str:
    if not detections:
        return "<p>No detections.</p>"

    rows = ""
    for d in detections:
        freq_mhz = d.get("freq_hz", 0) / 1e6 if d.get("freq_hz") else 0
        rows += (
            f"<tr><td>{_esc(d.get('detection_id', ''))}</td>"
            f"<td>{_esc(d.get('signal_class', ''))}</td>"
            f"<td>{freq_mhz:.3f} MHz</td>"
            f"<td>{_esc(d.get('power_dbm', ''))}</td>"
            f"<td>{d.get('anomaly_score', 0):.2f}</td></tr>\n"
        )

    return f"""<table>
<thead><tr><th>Detection ID</th><th>Signal Class</th><th>Frequency</th><th>Power (dBm)</th><th>Anomaly Score</th></tr></thead>
<tbody>{rows}</tbody>
</table>"""


def _render_recommendations(flagged_count: int, incidents: list[dict]) -> str:
    recs = []
    if flagged_count > 0:
        recs.append("Flagged zones require follow-up physical inspection")
    if any(i.get("severity") == "critical" for i in incidents):
        recs.append("Critical incidents should be escalated to security leadership")
    if any(i.get("resolution") == "confirmed_threat" for i in incidents):
        recs.append("Confirmed threats require device seizure and forensic analysis")
    if not recs:
        recs.append("No immediate action required — maintain regular sweep schedule")

    items = "\n".join(f"<li>{r}</li>" for r in recs)
    return f"<ul>{items}</ul>"
