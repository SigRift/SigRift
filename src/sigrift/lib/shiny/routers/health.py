"""Health and system status endpoints.

Provides ``/health`` for uptime probes and ``/status`` for a live
system-wide summary including node counts, alert counts, and job counts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from sigrift.lib.shiny.dependencies import rate_limit
from sigrift.lib.shiny.models import HealthResponse, JobState, NodeStatus, SystemStatus
from sigrift.lib.shiny.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()


def _utcnow() -> datetime:
    """Return the current UTC-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get("/health")
async def health_check(
    _key_id: str = Depends(rate_limit),
) -> HealthResponse:
    """Basic health probe.

    Returns a simple ``ok`` response with the server version and
    current UTC timestamp.
    """
    return HealthResponse(
        status="ok",
        version="4.0.0",
        timestamp=_utcnow(),
    )


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------


@router.get("/status")
async def system_status(
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> SystemStatus:
    """Live system-wide status summary.

    Counts nodes by state (active/stale/offline), tallies alerts and
    jobs, and reports spectrum/training subsystem states.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    # -- Node counts --------------------------------------------------------
    nodes = persistence.get_nodes()
    active = stale = offline = 0
    for node_data in nodes.values():
        status = AppState.get_node_status(node_data)
        if status == NodeStatus.active:
            active += 1
        elif status == NodeStatus.stale:
            stale += 1
        elif status == NodeStatus.offline:
            offline += 1

    # -- Alert count --------------------------------------------------------
    alert_count = len(persistence.get_alerts())

    # -- Job counts ---------------------------------------------------------
    # A stored record that is not an object (a hand-edited jobs.json) is no
    # job in any state; the job routes leave it out too.
    states = [
        j.get("state") for j in persistence.get_jobs().values() if isinstance(j, dict)
    ]
    pending_jobs = sum(1 for s in states if s == JobState.queued)
    running_jobs = sum(1 for s in states if s == JobState.running)

    # -- Spectrum / training flags ------------------------------------------
    spectrum_connected = bool(app_state.ws_spectrum_clients)
    training_running = getattr(app_state, "training_running", False)

    # -- Uptime -------------------------------------------------------------
    uptime_seconds = (_utcnow() - app_state.started_at).total_seconds()

    return SystemStatus(
        node_count=len(nodes),
        active_nodes=active,
        stale_nodes=stale,
        offline_nodes=offline,
        alert_count=alert_count,
        pending_jobs=pending_jobs,
        running_jobs=running_jobs,
        spectrum_connected=spectrum_connected,
        training_running=training_running,
        uptime_seconds=uptime_seconds,
    )
