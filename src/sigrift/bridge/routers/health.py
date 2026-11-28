"""Health and system status endpoints for The Bridge.

Provides ``/health`` for uptime probes and ``/status`` for a live
system-wide summary including node counts, alert counts, job counts,
and detection metrics.

Adapted from sigrift.lib.shiny.routers.health for The Bridge.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, Query, Request

from sigrift.bridge import API_VERSION, SUPPORTED_API_VERSIONS, WS_PROTOCOL, __version__
from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.release_info import current_release
from sigrift.bridge.models import (
    BridgeHealthResponse,
    BridgeSystemStatus,
    NodeStatus,
    TenantUsage,
)
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import utcnow

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow


# ---------------------------------------------------------------------------
# GET /version  (unauthenticated)
# ---------------------------------------------------------------------------


@router.get("/version")
def api_version() -> dict:
    """Version discovery endpoint (no authentication required).

    ``server_version`` is the API server's version (unchanged across
    releases); ``release`` is the image's release tag (``main-<sha12>``
    or ``dev`` for other builds).
    """
    return {
        "api_version": API_VERSION,
        "server_version": __version__,
        "release": current_release(),
        "ws_protocol": WS_PROTOCOL,
        "supported_versions": SUPPORTED_API_VERSIONS,
    }


# ---------------------------------------------------------------------------
# GET /healthz  (unauthenticated liveness probe)
# ---------------------------------------------------------------------------


@router.get("/healthz")
def healthz() -> dict:
    """Kubernetes-style liveness probe (no authentication required)."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# GET /ready  (unauthenticated readiness probe)
# ---------------------------------------------------------------------------


@router.get("/ready")
def readiness(request: Request) -> dict:
    """Kubernetes-style readiness probe (no authentication required).

    Returns 200 if the database is reachable, 503 otherwise.
    """
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        from starlette.responses import JSONResponse

        return JSONResponse(  # type: ignore[return-value]
            {"status": "not_ready", "reason": "detection_store not initialised"},
            status_code=503,
        )
    try:
        ctx = getattr(detection_store, "_ctx", None)
        if ctx is not None:
            conn = ctx.get_conn()
            conn.execute("SELECT 1").fetchone()
    except Exception as exc:
        from starlette.responses import JSONResponse

        logger.warning("Readiness probe failed: %s", exc)
        return JSONResponse(  # type: ignore[return-value]
            {"status": "not_ready", "reason": "database unreachable"},
            status_code=503,
        )
    return {"status": "ready"}


@router.get("/integrity-status")
def integrity_status(request: Request) -> dict:
    """Return database integrity check status (no auth required).

    Used by the startup progress page to show check progress.
    """
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is None:
        return {"state": "not_started", "db_size_mb": 0}
    ctx = getattr(detection_store, "_ctx", None)
    if ctx is None:
        return {"state": "not_started", "db_size_mb": 0}
    status = getattr(ctx, "_integrity_status", {"state": "unknown"})
    # Add elapsed time for running checks
    if status.get("state") == "running" and "started_at" in status:
        import time as _time

        status = dict(status)
        status["elapsed_s"] = round(_time.time() - status["started_at"], 1)
    return status


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get("/health")
def health_check(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> BridgeHealthResponse:
    """Basic health probe with Bridge version and security warnings."""
    warnings = _collect_security_warnings()

    # DB-P13: Disk space monitoring
    disk_usage_pct: float | None = None
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store is not None:
        ctx = getattr(detection_store, "_ctx", None)
        if ctx is not None and hasattr(ctx, "check_disk_space"):
            disk_usage_pct = ctx.check_disk_space()
            if disk_usage_pct is not None and disk_usage_pct >= 90.0:
                warnings.append(
                    f"Disk usage CRITICAL: {disk_usage_pct:.0f}% used. "
                    "Database writes may fail soon."
                )
            elif disk_usage_pct is not None and disk_usage_pct >= 80.0:
                warnings.append(
                    f"Disk usage HIGH: {disk_usage_pct:.0f}% used. "
                    "Consider freeing space or archiving old data."
                )

        # WAL bloat watchdog — a WAL above 256 MB usually means a long
        # write transaction is open or a reader is pinning a snapshot.
        # Surface as a warning rather than wait for the bridge to OOM.
        try:
            from pathlib import Path as _Path

            db_path = getattr(detection_store, "_db_path", None)
            if db_path is not None:
                wal_path = _Path(str(db_path) + "-wal")
                if wal_path.exists():
                    wal_mb = wal_path.stat().st_size / 1e6
                    if wal_mb > 1024:
                        warnings.append(
                            f"WAL file CRITICAL: {wal_mb:.0f} MB. "
                            "Bridge may be unable to checkpoint — "
                            "long-running transaction or stuck reader."
                        )
                    elif wal_mb > 256:
                        warnings.append(
                            f"WAL file HIGH: {wal_mb:.0f} MB. "
                            "Expect autocheckpoint to clear; investigate "
                            "if it persists."
                        )
        except OSError:
            pass

        # Integrity-check status — if the startup quick_check failed (or
        # the deferred background check did), surface it loudly. The
        # bridge will still be serving reads even on a corrupt DB, but
        # operators need to know the recovery path is open.
        ctx = getattr(detection_store, "_ctx", None)
        if ctx is not None:
            integrity = getattr(ctx, "_integrity_status", None) or {}
            if integrity.get("state") in ("failed", "error"):
                warnings.append(
                    "Database integrity check FAILED: "
                    f"{integrity.get('error', 'unknown error')}. "
                    "Migrations blocked. Run `sqlite3 detections.db .recover` "
                    "to repair."
                )

    # Saved protocol decryption keys: a missing, invalid or wrong
    # BRIDGE_KEYSTORE_KEY, unreadable rows, or imports that a restart loses.
    crypto_key_persistence = "unknown"
    vault = getattr(request.app.state, "crypto_key_vault", None)
    key_store = getattr(request.app.state, "crypto_key_store", None)
    if vault is not None and key_store is not None:
        warnings.extend(vault.health_warnings(key_store))
        crypto_key_persistence = vault.state.value

    # Collect nodes still using raw (non-aggregated) ingest endpoints
    raw_ingest_node_ids: list[str] = []
    try:
        from sigrift.bridge.routers.detections import get_raw_ingest_nodes

        raw_ingest_node_ids = sorted(get_raw_ingest_nodes().keys())
    except Exception:
        pass

    resp = BridgeHealthResponse(
        status="ok",
        version=__version__,
        release=current_release(),
        crypto_key_persistence=crypto_key_persistence,
        timestamp=_utcnow(),
        security_warnings=warnings,
        raw_ingest_nodes=raw_ingest_node_ids,
    )
    if disk_usage_pct is not None:
        resp.disk_usage_pct = disk_usage_pct
    return resp


def _collect_security_warnings() -> list[str]:
    """Check for security configuration issues and return warning strings."""
    import os

    warnings: list[str] = []

    # SEC-H2: TOTP secrets not encrypted (base64 only).  An unset key and a
    # key that is not a valid Fernet key both fall back to base64.
    from sigrift.bridge.storage.users import mfa_key_problem, mfa_key_remedy

    mfa_problem = mfa_key_problem()
    if mfa_problem:
        warnings.append(
            "TOTP secrets stored with base64 encoding only (NOT encrypted): "
            f"{mfa_problem}. To fix it, {mfa_key_remedy()}."
        )

    # SEC-H6 / P0-1: Data-at-rest encryption check.
    # If SQLCipher is active, no warning needed.  Otherwise check for the
    # filesystem-level encryption acknowledgement flag.
    from sigrift.bridge.storage.encryption import encryption_status

    # The pre-migration copy guard is off: meant for one upgrade only.
    from sigrift.bridge.storage.base import allow_migration_without_backup

    if allow_migration_without_backup():
        warnings.append(
            "Pre-migration copy guard disabled: BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP "
            "is set, so the next upgrade migrates the database without its "
            "detections.db.pre-migration recovery copy when that copy cannot be "
            "made. Remove it once the upgrade it was set for is done."
        )

    enc = encryption_status()
    if not enc["enabled"]:
        dar_key = os.environ.get("BRIDGE_ENCRYPTION_KEY", "").strip()
        if not dar_key:
            warnings.append(
                "No data-at-rest encryption configured. Either install pysqlcipher3 "
                "and set BRIDGE_DB_ENCRYPTION_KEY, or use filesystem-level encryption "
                "(LUKS/dm-crypt) and set BRIDGE_ENCRYPTION_KEY to acknowledge."
            )

    return warnings


# ---------------------------------------------------------------------------
# GET /status
# ---------------------------------------------------------------------------


@router.get("/status")
async def system_status(
    request: Request,
    freq_hours: int = Query(default=1, ge=1, le=168),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> BridgeSystemStatus:
    """Live system-wide status summary with detection metrics."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    # -- Node counts --------------------------------------------------------
    nodes = persistence.get_nodes()
    active = stale = offline = 0
    for node_data in nodes.values():
        st = AppState.get_node_status(node_data)
        if st == NodeStatus.active:
            active += 1
        elif st == NodeStatus.stale:
            stale += 1
        elif st == NodeStatus.offline:
            offline += 1

    # -- Alert count --------------------------------------------------------
    alerts = persistence.get_alerts()
    alert_count = len(alerts)
    unacked_alerts = sum(1 for a in alerts if not a.get("acknowledged", False))

    # -- Job counts ---------------------------------------------------------
    jobs = persistence.get_jobs()
    pending_jobs = sum(1 for j in jobs.values() if j.get("state") == "queued")
    running_jobs = sum(1 for j in jobs.values() if j.get("state") == "running")

    # -- Spectrum / training flags ------------------------------------------
    spectrum_connected = bool(app_state.ws_spectrum_clients)
    training_running = getattr(app_state, "training_running", False)

    # -- Uptime -------------------------------------------------------------
    uptime_seconds = (_utcnow() - app_state.started_at).total_seconds()

    # -- Onboarding: is the in-stack scanner key pre-registered? -----------
    # PR-6 (cog review §1.3): exposes whether the docker-compose stack
    # registered a NODE-role API key for the bundled wifi-scan/bt-scan
    # containers via BRIDGE_LOCAL_NODE_KEY. The dashboard banner uses
    # this to suppress the "mint a NODE key" prompt for operators on
    # the quickstart path where the work is already done. Only the
    # boolean is exposed — never the raw key.
    local_scanner_key_registered = persistence.has_key(LOCAL_SCANNER_KEY_ID)

    # -- Detection metrics --------------------------------------------------
    detection_store = getattr(request.app.state, "detection_store", None)
    total_detections_24h = 0
    detections_per_second = 0.0
    active_anomalies = 0
    active_frequencies = 0
    freq_list = []
    if detection_store is not None:
        # Run all three DB queries in parallel threads
        async def _get_stats():
            try:
                s = await asyncio.to_thread(detection_store.get_stats, hours=24)
                return s.total_detections, s.detections_per_second
            except Exception:
                return 0, 0.0

        async def _get_anomalies():
            try:
                return await asyncio.to_thread(
                    detection_store.get_active_anomaly_count,
                    threshold=0.3,
                )
            except Exception:
                return 0

        async def _get_freqs():
            try:
                return await asyncio.to_thread(
                    detection_store.get_active_frequency_count,
                    hours=freq_hours,
                )
            except Exception:
                return 0

        async def _get_freq_list():
            try:
                return await asyncio.to_thread(
                    detection_store.get_active_frequencies,
                    hours=freq_hours,
                )
            except Exception:
                return []

        (det_24h, det_ps), anom, freqs, freq_list = await asyncio.gather(
            _get_stats(),
            _get_anomalies(),
            _get_freqs(),
            _get_freq_list(),
        )
        total_detections_24h = det_24h
        detections_per_second = det_ps
        active_anomalies = anom
        active_frequencies = freqs

    # -- Tenant usage -------------------------------------------------------
    tenant_usage: TenantUsage | None = None
    if detection_store is not None:
        ctx = getattr(detection_store, "_ctx", None)
        if ctx is not None:
            try:
                usage_dict = await asyncio.to_thread(ctx.get_tenant_usage)
                total_rows = sum(usage_dict.values())
                limit = ctx.row_limit
                tenant_usage = TenantUsage(
                    tables=usage_dict,
                    total_rows=total_rows,
                    row_limit=limit,
                    usage_pct=round(total_rows / limit * 100, 2) if limit > 0 else 0.0,
                )
            except Exception:
                logger.warning("Failed to compute tenant usage", exc_info=True)

    return BridgeSystemStatus(
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
        total_detections_24h=total_detections_24h,
        detections_per_second=detections_per_second,
        active_anomalies=active_anomalies,
        unacked_alerts=unacked_alerts,
        active_frequencies=active_frequencies,
        active_frequency_list=freq_list,
        tenant_usage=tenant_usage,
        local_scanner_key_registered=local_scanner_key_registered,
    )


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------


@router.get("/metrics")
async def get_metrics(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict:
    """Operational metrics: ingest rate, latency, WS clients, DB size, cache stats."""
    from pathlib import Path

    app_state: AppState = request.app.state.app_state
    detection_store = getattr(request.app.state, "detection_store", None)

    uptime = (_utcnow() - app_state.started_at).total_seconds()

    # WebSocket client counts
    ws_detection_clients = len(getattr(app_state, "ws_detection_clients", []))
    ws_anomaly_clients = len(getattr(app_state, "ws_anomaly_clients", []))
    ws_spectrum_clients = len(getattr(app_state, "ws_spectrum_clients", []))
    ws_wifi_clients = len(getattr(app_state, "ws_wifi_clients", []))

    metrics: dict = {
        "uptime_seconds": round(uptime, 1),
        "ws_clients": {
            "detections": ws_detection_clients,
            "anomalies": ws_anomaly_clients,
            "spectrum": ws_spectrum_clients,
            "wifi": ws_wifi_clients,
            "total": ws_detection_clients
            + ws_anomaly_clients
            + ws_spectrum_clients
            + ws_wifi_clients,
        },
    }

    if detection_store is not None:
        try:
            stats = await asyncio.to_thread(detection_store.get_stats, hours=1)
            metrics["ingest"] = {
                "detections_1h": stats.total_detections,
                "detections_per_second": stats.detections_per_second,
            }
        except Exception:
            metrics["ingest"] = {"detections_1h": 0, "detections_per_second": 0.0}

        try:
            db_path = Path(detection_store.db_path)
            db_size = db_path.stat().st_size if db_path.exists() else 0
            wal_path = db_path.with_suffix(".db-wal")
            wal_size = wal_path.stat().st_size if wal_path.exists() else 0
            metrics["database"] = {
                "db_size_mb": round(db_size / 1048576, 2),
                "wal_size_mb": round(wal_size / 1048576, 2),
                "row_count": await asyncio.to_thread(detection_store.row_count),
            }
        except Exception:
            pass

        cache_stats = getattr(detection_store, "cache_stats", None)
        if cache_stats is not None:
            try:
                metrics["cache"] = cache_stats()
            except Exception:
                pass

    write_queue = getattr(request.app.state, "write_queue", None)
    if write_queue is not None:
        metrics["write_queue"] = write_queue.stats

    return metrics
