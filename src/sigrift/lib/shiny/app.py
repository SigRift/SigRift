"""FastAPI application for the SigRift Shiny dashboard.

Creates the application instance, configures lifespan (startup/shutdown),
CSP middleware, and mounts all routers and static files.
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from fastapi import FastAPI, Request

from sigrift.lib.config import load_config
from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny.dependencies import (
    MASTER_KEY_ID,
    RateLimiter,
    install_log_redaction,
    set_config,
    set_rate_limiter,
)
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.routers import (
    alerts,
    export,
    health,
    jobs,
    keys,
    nodes,
    signals,
    spectrum,
    training,
)
from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer
from sigrift.lib.shiny.state import AppState
from sigrift.lib.validation_errors import install_validation_handler

logger = logging.getLogger(__name__)

# Keep API keys passed in query strings (?api_key=...) out of uvicorn's
# access and WebSocket handshake logs.
install_log_redaction()

# Where the first start writes the generated master key (in the data dir).
INITIAL_MASTER_KEY_FILE = "initial-master-key.txt"

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# ---------------------------------------------------------------------------
# Content Security Policy middleware
# ---------------------------------------------------------------------------

_CSP_VALUE = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "connect-src 'self' wss:; "
    "img-src 'self' data:"
)


_CSP_ENCODED = _CSP_VALUE.encode()

_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", _CSP_ENCODED),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
]


class CSPMiddleware:
    """Pure ASGI middleware that adds CSP and security headers to HTTP responses."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":

            async def send_with_headers(message: dict) -> None:
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.extend(_SECURITY_HEADERS)
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, send_with_headers)
        else:
            await self.app(scope, receive, send)


# ---------------------------------------------------------------------------
# Initial master key
# ---------------------------------------------------------------------------


def _write_private_file(path: Path, text: str) -> None:
    """Atomically write *text* to *path*, created mode 0600 from the start."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def bootstrap_master_key(persistence: PersistenceManager) -> Path | None:
    """Create the ``master`` key; return the file holding it.

    Run at startup when the store has no master key: on first start, and
    on an install whose master key was revoked before the API refused that
    (only the master key can manage keys, so no one could any more).  The
    other keys are kept.

    The raw key is never logged: it is written to a 0600 file in the data
    directory and only that path is logged. If the file cannot be written
    no key is created (a key nobody can read would lock everyone out), and
    the next start tries again.
    """
    reason = (
        "The master key is missing from the key store"
        if persistence.get_key_store()
        else "No API keys found"
    )
    raw_key = generate_api_key()
    path = persistence.data_dir / INITIAL_MASTER_KEY_FILE
    try:
        _write_private_file(
            path,
            "# SigRift dashboard initial master key. Store it safely, then\n"
            "# delete this file.\n"
            f"{raw_key}\n",
        )
    except OSError as exc:
        logger.error(
            "%s, and the initial master key could not be written to %s "
            "(%s); no key was created",
            reason,
            path,
            exc,
        )
        return None
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(
        MASTER_KEY_ID,
        hash_hex,
        salt,
        meta={
            "role": "admin",
            "description": "initial master key",
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    logger.warning(
        "%s. Generated the initial master key and wrote it to %s (mode "
        "0600): store it safely, then delete that file.",
        reason,
        path,
    )
    return path


_LEGACY_KEYS_LISTED = 20


def warn_legacy_viewer_keys(persistence: PersistenceManager) -> list[str]:
    """Log once at startup which keys predate roles (they are now viewers).

    Keys stored before roles existed have no ``role`` in ``keys.json`` and
    load as ``viewer``: they can still read, but creating alert rules,
    acknowledging alerts, creating or changing jobs, schedules and model
    evaluations, and connecting, disconnecting or retuning the spectrum
    source now need ``analyst``, registering nodes and queueing node
    commands need ``admin``, and rotation keeps a key's role. Returns the
    affected key IDs (the master key is always admin and never listed).
    """
    legacy = sorted(
        kid
        for kid in persistence.get_key_store()
        if kid != MASTER_KEY_ID and "role" not in persistence.get_key_meta(kid)
    )
    if legacy:
        shown = legacy[:_LEGACY_KEYS_LISTED]
        more = len(legacy) - len(shown)
        logger.warning(
            "%d API key(s) in %s have no stored role (created before roles "
            "existed) and are now viewers (read-only): %s%s. Creating alert "
            "rules, acknowledging alerts, creating or changing jobs, "
            "schedules and model evaluations, and connecting, disconnecting "
            "or retuning the spectrum source need an analyst key; "
            "registering nodes and queueing node commands need an admin "
            "key: use the master key, or create a key with role 'analyst' "
            "or role 'admin' (the dashboard's API Keys panel, or POST "
            "/api/keys/, with the master key) and deploy it where it is "
            'needed; or stop the dashboard and add "role": "analyst" (or '
            '"admin") to that key\'s entry in keys.json.',
            len(legacy),
            persistence.data_dir / "keys.json",
            shown,
            f" and {more} more" if more else "",
        )
    return legacy


def warn_unclassified_node_keys(persistence: PersistenceManager) -> list[str]:
    """Log once at startup which keys cannot heartbeat until classified.

    A non-admin key with neither ``node_id`` nor ``purpose`` in ``keys.json``
    (created before key purposes existed) cannot be told apart from a
    dashboard viewer key, so it is no longer bound to the first node it
    heartbeats for: its heartbeats are refused (403) until the operator binds
    it to its node or marks it as a dashboard key, unless the
    ``SHINY_LEGACY_KEY_TOFU`` migration opt-in is on.  Returns the affected
    key IDs.
    """
    tofu = nodes.legacy_key_tofu()
    if tofu.invalid is not None:
        logger.error(
            "%s=%r is not 1/true/yes/on or an ISO 8601 date/date-time; the "
            "legacy-key migration opt-in is OFF",
            nodes.LEGACY_KEY_TOFU_ENV,
            tofu.invalid,
        )
    unclassified = []
    for kid in sorted(persistence.get_key_store()):
        meta = persistence.get_key_meta(kid)
        if kid == MASTER_KEY_ID or meta.get("node_id") or meta.get("purpose"):
            continue
        if str(meta.get("role", "viewer")).lower() in ("admin", "analyst"):
            continue  # never bound by first use
        unclassified.append(kid)
    if unclassified:
        shown = unclassified[:_LEGACY_KEYS_LISTED]
        more = len(unclassified) - len(shown)
        if tofu.active:
            until = (
                f"until {tofu.until.isoformat()}"
                if tofu.until
                else "until it is unset (set it to an ISO date to end it by itself)"
            )
            effect = (
                f"{nodes.LEGACY_KEY_TOFU_ENV} is on {until}: each is bound to "
                "the first node it heartbeats for, unless another key already "
                "holds that node, and every such claim is logged as a warning "
                "(a dashboard key can claim a node this way)."
            )
        else:
            effect = (
                "Their heartbeats are refused (403) until they are classified: "
                "they could be a node's own key or a shared dashboard key."
            )
        logger.warning(
            "%d API key(s) in %s have no node_id and no purpose (created "
            "before key purposes existed): %s%s. %s With the master key, bind "
            "each node key to its node with PATCH /api/keys/<key_id> "
            '{"node_id": "<node>"} and mark dashboard keys with PATCH '
            '/api/keys/<key_id> {"purpose": "dashboard"}. For a one-off '
            "migration, %s=1 (or an ISO date, after which it turns itself "
            "off) lets each such key claim the first unclaimed node it "
            "heartbeats for.",
            len(unclassified),
            persistence.data_dir / "keys.json",
            shown,
            f" and {more} more" if more else "",
            effect,
            nodes.LEGACY_KEY_TOFU_ENV,
        )
    return unclassified


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and shutdown of the dashboard application.

    Startup:
      - Load configuration
      - Create and load PersistenceManager
      - Start background auto-save
      - Create AppState and restore alert counter
      - Initialize rate limiter
      - Generate initial master key if none exist

    Shutdown:
      - Stop auto-save (performs final save)
    """
    # -- Configuration ------------------------------------------------------
    config = load_config()
    set_config(config)

    # -- Rate limiter -------------------------------------------------------
    limiter = RateLimiter(
        max_requests=config.security.rate_limit_per_minute,
        window_seconds=60.0,
    )
    set_rate_limiter(limiter)

    # -- Persistence --------------------------------------------------------
    persistence = PersistenceManager()
    persistence.load_all()
    await persistence.start_auto_save()

    # -- App state ----------------------------------------------------------
    app_state = AppState()
    app_state.restore_alert_counter(persistence)

    # -- Spectrum streamer --------------------------------------------------
    spectrum_streamer = SpectrumStreamer()

    # -- Store on app.state for dependency injection ------------------------
    app.state.persistence = persistence
    app.state.app_state = app_state
    app.state.spectrum_streamer = spectrum_streamer

    # -- Generate the master key if there is none ---------------------------
    # On first start, or after the master key was revoked (older versions
    # allowed that, leaving no key that can manage keys).
    had_keys = bool(persistence.get_key_store())
    if MASTER_KEY_ID not in persistence.get_key_store():
        try:
            await asyncio.to_thread(bootstrap_master_key, persistence)
        except (ValueError, OSError) as exc:
            logger.error("Failed to generate initial master key: %s", exc)
    if had_keys:
        warn_legacy_viewer_keys(persistence)
        warn_unclassified_node_keys(persistence)

    logger.info("SigRift Dashboard started")

    yield

    # -- Shutdown -----------------------------------------------------------
    await spectrum_streamer.disconnect()
    await persistence.stop_auto_save()
    logger.info("SigRift Dashboard stopped")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SigRift Dashboard",
    version="4.0.0",
    lifespan=lifespan,
)

# -- Middleware -------------------------------------------------------------
app.add_middleware(CSPMiddleware)
# A 422 that echoes a NaN / Infinity input is not a 500.
install_validation_handler(app)

# -- Routers ---------------------------------------------------------------
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])
app.include_router(spectrum.router, prefix="/api/spectrum", tags=["spectrum"])
app.include_router(training.router, prefix="/api/training", tags=["training"])
app.include_router(signals.router, prefix="/api/signals", tags=["signals"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
app.include_router(keys.router, prefix="/api/keys", tags=["keys"])
app.include_router(jobs.router, prefix="/api/jobs", tags=["jobs"])
app.include_router(export.router, prefix="/api/export", tags=["export"])

# -- Static files -----------------------------------------------------------
if _STATIC_DIR.is_dir():
    from fastapi.staticfiles import StaticFiles

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    logger.info("Static files mounted from %s", _STATIC_DIR)

# -- Templates / root route -------------------------------------------------
if _TEMPLATES_DIR.is_dir():
    from fastapi.responses import HTMLResponse
    from fastapi.templating import Jinja2Templates

    _templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index(request: Request) -> HTMLResponse:
        """Serve the dashboard index page."""
        return _templates.TemplateResponse(request, "index.html")
