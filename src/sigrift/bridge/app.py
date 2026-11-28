"""FastAPI application for the SigRift bridge — RF signal detection backend.

Creates the application instance, configures lifespan (startup/shutdown),
CSP middleware, and mounts all routers.  Extends the Shiny dashboard
pattern with detection-specific routers and DetectionStore.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import random
import re
import sys
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketClose
# BaseHTTPMiddleware replaced by pure-ASGI CombinedMiddleware for performance

from sigrift.bridge import API_VERSION, SUPPORTED_API_VERSIONS, __version__
from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
from sigrift.bridge.utils import utcnow
from sigrift.lib.config import load_config
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.bridge.dependencies import (
    ALLOW_UNBOUND_NODE_KEYS_ENV,
    RateLimiter,
    Role,
    WSConnectionLimiter,
    _extract_session_token,
    _authenticate_api_key,
    _scope_denied_detail,
    allow_unbound_node_keys,
    forwarding_headers_trusted,
    reload_trusted_proxies,
    resolve_session,
    rust_proxy_header_valid,
    set_config,
    set_rate_limiter,
    set_ws_limiter,
    trusted_forwarded_proto,
)
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.calibrator import ScoreCalibrator
from sigrift.bridge.anomaly.correlator import NodeCorrelator
from sigrift.bridge.anomaly.drift_detector import DriftDetector
from sigrift.bridge.anomaly.evaluation import ScoringEvaluator
from sigrift.bridge.anomaly.pcap_store import PcapStore
from sigrift.bridge.anomaly.quantile_tracker import QuantileTracker
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.anomaly.bt_scorer import BtAnomalyScorer, BtBaselineManager
from sigrift.bridge.anomaly.wifi_scorer import WifiAnomalyScorer, WifiBaselineManager
from sigrift.bridge.anomaly.whitelist import SignalWhitelist
from sigrift.bridge.instrumentation import get_tracer, setup_tracing, trace_span
from sigrift.bridge.storage.spectrum_materializer import SpectrumMaterializer
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.log_buffer import init_log_buffer
from sigrift.bridge.notifications import NotificationManager, _retry_queue_max
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore
from sigrift.bridge.iq_store import IQStore
from sigrift.bridge.write_queue import WriteQueue
from sigrift.bridge.persistence import KeyStoreWriteError, PersistenceManager
from sigrift.bridge.routers import (
    admin,
    aircraft,
    alerts,
    auth,
    bitstreams,
    bluetooth,
    ca,
    clusters,
    correlation,
    crypto,
    deployment,
    detection_analytics,
    detection_audit,
    detection_iq,
    detections,
    edge,
    edge_models,
    emitters,
    export,
    geo,
    geolocation,
    health,
    incidents,
    internal,
    iq_metadata,
    jobs,
    keys,
    maintenance,
    maps,
    mbtiles,
    metrics,
    nodes,
    packets,
    preambles,
    reports,
    signature_library,
    signals,
    spectrum,
    sweeps,
    system_config,
    tracking,
    training,
    webhook_management,
    wifi,
    wifi_fingerprint,
    zigbee,
)
from sigrift.bridge.routers.nodes import stored_location
from sigrift.bridge.state import AppState
from sigrift.lib.shiny.models import NodeStatus
from sigrift.lib.shiny.node_metrics import stored_number
from sigrift.lib.validation_errors import install_validation_handler

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).resolve().parent / "static"
_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

# ---------------------------------------------------------------------------
# Content Security Policy middleware
# ---------------------------------------------------------------------------

#: The gateway's reviewed policy (``CSP_DIRECTIVES`` in the gateway's
#: ``middleware/security.rs``). Behind the gateway it replaces this header;
#: a bridge run without one sends this, so the two must be the same. The
#: shared table ``testdata/security_headers_parity.json`` in the gateway
#: crate pins both (``tests/bridge/test_security_headers_parity.py``).
_CSP_VALUE = (
    "default-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://*.tile.openstreetmap.org; "
    "connect-src 'self' wss: ws:; "
    "font-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)
_PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=(), payment=()"


_MAX_REQUEST_BODY = 10 * 1024 * 1024  # 10 MB global limit
_TOO_LARGE_BODY = "Request body too large"


class _BodyTooLarge(Exception):
    """A request body went past the middleware's size limit while being read."""


class _LimitedReceive:
    """ASGI ``receive`` that counts the request body against *limit*.

    The declared ``Content-Length`` is checked first, but a chunked body
    declares no length: the bytes are counted here as the app reads them.
    The call that crosses the limit, and every later one, raises
    ``_BodyTooLarge`` (that chunk is never handed on), and the middleware
    answers 413 in place of whatever the app does with the error (the
    gateway's ``RequestBodyLimitLayer`` also counts streamed bytes).
    """

    __slots__ = ("_receive", "_limit", "_read", "exceeded")

    def __init__(self, receive, limit: int) -> None:
        self._receive = receive
        self._limit = limit
        self._read = 0
        self.exceeded = False

    async def __call__(self):
        if self.exceeded:
            raise _BodyTooLarge
        message = await self._receive()
        if message.get("type") == "http.request":
            self._read += len(message.get("body", b""))
            if self._read > self._limit:
                self.exceeded = True
                raise _BodyTooLarge
        return message


# Security + version + size-limit + logging headers as a single pure-ASGI
# middleware.  ``BaseHTTPMiddleware`` spawns a new asyncio.Task per request
# per layer which is a major throughput bottleneck under load.  This
# combined middleware avoids that overhead entirely.

_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"content-security-policy", _CSP_VALUE.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"strict-origin-when-cross-origin"),
    (b"permissions-policy", _PERMISSIONS_POLICY.encode()),
]
_HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")
_API_VERSION_BYTES = API_VERSION.encode()
_CORR_ID_RE = re.compile(r"[^a-zA-Z0-9_\-]")


# --- Rust gateway trust header (contract K2) ---
# When BRIDGE_REQUIRE_PROXY=true, Python rejects every HTTP request and
# WebSocket upgrade that didn't come through the Rust gateway (missing or
# wrong X-Rust-Proxy header), except GET /api/healthz and GET /api/ready
# from a loopback peer (container health checks).
_REQUIRE_PROXY = os.environ.get("BRIDGE_REQUIRE_PROXY", "").lower() in (
    "true",
    "1",
    "yes",
)
_PROXY_SECRET = os.environ.get("UC_PROXY_SECRET", "").encode()
#: The value older releases shipped as a default; it is public, so it
#: proves nothing.
_INSECURE_PROXY_SECRETS = frozenset({b"", b"uppercrust-internal"})
_PROXY_EXEMPT_PATHS = frozenset({"/api/healthz", "/api/ready"})
_PROXY_DENIED_BODY = '{"detail":"Direct access denied — use the Rust gateway"}'


def _proxy_secret_usable() -> bool:
    """True if UC_PROXY_SECRET can prove a request came through the gateway."""
    return _PROXY_SECRET not in _INSECURE_PROXY_SECRETS


def _log_gateway_trust_status() -> None:
    """Say at start-up what an unusable UC_PROXY_SECRET does (K2, K10).

    Production refuses to start without a strong secret before this runs.
    Elsewhere the message must describe what actually happens:

    * with ``BRIDGE_REQUIRE_PROXY`` on, every request except the loopback
      health checks is refused with 403 (CRITICAL);
    * with it off, nothing is restricted, but the bridge cannot recognise
      the gateway: ``/api/internal/*`` (node-key binding, ingest hooks)
      refuses it with 403 and forwarded client-certificate identities are
      not trusted (WARNING).
    """
    if _proxy_secret_usable():
        return
    if _REQUIRE_PROXY:
        logger.critical(
            "BRIDGE_REQUIRE_PROXY is on but UC_PROXY_SECRET is unset or the "
            "public default — every request except loopback GET /api/healthz "
            "and /api/ready will be refused with 403. Set UC_PROXY_SECRET to "
            "the gateway's value."
        )
        return
    logger.warning(
        "UC_PROXY_SECRET unset or the public default — the bridge cannot "
        "recognise gateway-proxied requests: /api/internal/* (node-key "
        "binding, post-ingest hooks: alert rules, watch bands, webhooks and "
        "decode jobs for gateway-ingested batches) refuses the gateway with "
        "403 and client-certificate identities forwarded by the gateway are "
        "not trusted, while direct access to the bridge is not restricted. "
        "Run scripts/quickstart.sh or set the same strong value on the "
        "gateway and the bridge."
    )


def _is_loopback_peer(scope: dict) -> bool:
    client = scope.get("client")
    if not client:
        return False
    try:
        return ipaddress.ip_address(str(client[0]).split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _proxy_check_passes(scope: dict, headers_raw: dict[bytes, bytes]) -> bool:
    """BRIDGE_REQUIRE_PROXY check for one HTTP request or WebSocket upgrade.

    Passes when the ``x-rust-proxy`` header equals UC_PROXY_SECRET
    (constant-time compare; an empty or default secret never matches) or
    for the loopback health-check exemptions.
    """
    if (
        scope["type"] == "http"
        and scope.get("method") == "GET"
        and scope.get("path", "") in _PROXY_EXEMPT_PATHS
        and _is_loopback_peer(scope)
    ):
        return True
    if not _proxy_secret_usable():
        return False
    return hmac.compare_digest(headers_raw.get(b"x-rust-proxy", b""), _PROXY_SECRET)


#: Gateway-only routes (contracts K7 / K8 / K9).  The middleware refuses
#: them without a valid X-Rust-Proxy — whatever BRIDGE_REQUIRE_PROXY says —
#: and the routes themselves accept no other credential.
_INTERNAL_PREFIX = "/api/internal"
_INTERNAL_DENIED_BODY = '{"detail":"Internal endpoint: only the gateway may call it"}'
_SLASH_RUN_RE = re.compile(r"/{2,}")


def _is_internal_path(path: str) -> bool:
    """True for ``/api/internal`` and everything under it (any case)."""
    canon = _SLASH_RUN_RE.sub("/", path).lower().rstrip("/")
    return canon == _INTERNAL_PREFIX or canon.startswith(_INTERNAL_PREFIX + "/")


_UPPERCRUST_URL = os.environ.get("UPPERCRUST_URL", "http://127.0.0.1:3001")
_UPPERCRUST_PROXY_PATHS = frozenset(
    {
        "/api/detections/recent",
        "/api/detections/timeline",
        "/api/detections/distribution",
        "/api/detections/heatmap",
        "/api/detections/stats",
        "/api/detections/summary",
        "/api/detections/anomalies/summary",
    }
)


def _sync_fetch_uppercrust(url: str, api_key: str = "") -> tuple[int, bytes]:
    """Blocking HTTP GET to upperCrust — run in a thread."""
    import urllib.request

    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.status, resp.read()


# Minimum role required for proxy read endpoints (dashboard queries)
_PROXY_READ_MIN_ROLE = Role.VIEWER
# Minimum role required for proxy write endpoints (batch ingest)
_PROXY_WRITE_MIN_ROLE = Role.SENSOR


async def _verify_proxy_auth(
    scope: dict,
    *,
    min_role: Role = _PROXY_READ_MIN_ROLE,
) -> tuple[str | None, Role | None, str]:
    """Validate API key or session token from ASGI headers for proxy requests.

    Uses the same ``_lookup_key_async`` logic as FastAPI dependencies to ensure
    expiry and RBAC checks are applied consistently.

    Returns
    -------
    tuple[str | None, Role | None, str]
        ``(key_id, role, "")`` on success,
        ``(None, None, "missing")`` when no credentials are provided,
        ``(None, None, "invalid")`` when credentials are invalid/expired,
        ``(None, None, "forbidden")`` when role is insufficient,
        ``(None, None, "scope:<scope>")`` for a restricted session.
    """
    app = scope.get("app")
    if not app:
        return None, None, "missing"
    conn = HTTPConnection(scope)
    # Match normal HTTP/WS precedence. A valid foreign or restricted session
    # cannot fall through to a secondary key, including on the proxy fast path.
    token = _extract_session_token(conn)
    if token:
        try:
            resolved = resolve_session(conn, token)
        except HTTPException:
            return None, None, "tenant"
        if resolved is not None:
            session, role, session_scope = resolved
            if session_scope:
                return None, None, f"scope:{session_scope}"
            if role < min_role:
                return None, None, "forbidden"
            return f"user:{session.get('username', 'unknown')}", role, ""

    api_key = conn.headers.get("x-api-key") or conn.query_params.get("api_key", "")
    if api_key:
        persistence = getattr(app.state, "persistence", None)
        if persistence is not None:
            try:
                key_id, role = await _authenticate_api_key(
                    api_key, persistence, conn, upgrade_legacy=False
                )
            except HTTPException:
                return None, None, "tenant"
            if key_id is None:
                return None, None, "invalid"
            if role < min_role:
                return None, None, "forbidden"
            return key_id, role, ""
    return None, None, "missing"


async def _proxy_post_to_uppercrust(scope, receive, send) -> tuple[bool, bytes]:
    """Forward POST ingest requests to upperCrust, streaming the request body.

    Returns
    -------
    tuple[bool, bytes]
        ``(True, b"")`` when upperCrust handled the request (2xx or 4xx --
        the response has already been sent to *send*).
        ``(False, buffered_body)`` when the proxy is unreachable, so the
        caller can replay the already-consumed body to the downstream app.
    """
    import urllib.request

    path = scope.get("path", "")
    qs = scope.get("query_string", b"").decode()
    url = f"{_UPPERCRUST_URL}{path}"
    if qs:
        url += f"?{qs}"

    # Collect request body
    body = b""
    while True:
        msg = await receive()
        body += msg.get("body", b"")
        if not msg.get("more_body", False):
            break

    # Forward headers (API key, content-type, content-encoding)
    headers_raw = dict(scope.get("headers", []))
    fwd_headers = {"Accept": "application/json"}
    for hname in (b"content-type", b"content-encoding", b"x-api-key", b"authorization"):
        val = headers_raw.get(hname)
        if val:
            fwd_headers[hname.decode()] = val.decode()

    try:

        def _do_post():
            req = urllib.request.Request(
                url, data=body, headers=fwd_headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                return (
                    resp.status,
                    resp.read(),
                    resp.headers.get("Content-Type", "application/json"),
                )

        status_code, resp_body, ct = await asyncio.to_thread(_do_post)
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [(b"content-type", ct.encode())],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": resp_body,
            }
        )
        return True, b""
    except Exception as exc:
        # On 4xx errors, urllib raises — extract the status code
        status_code = getattr(exc, "code", None)
        if status_code:
            resp_body = getattr(exc, "read", lambda: b"")()
            await send(
                {
                    "type": "http.response.start",
                    "status": status_code,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": resp_body,
                }
            )
            return True, b""
        else:
            logger.debug("upperCrust POST proxy failed (%s), falling back", exc)
            return False, body


async def _proxy_to_uppercrust(scope, receive, send, *, api_key: str = ""):
    """Forward a GET request to upperCrust and stream the response back."""
    path = scope.get("path", "")
    qs = scope.get("query_string", b"").decode()
    url = f"{_UPPERCRUST_URL}{path}"
    if qs:
        url += f"?{qs}"
    try:
        status_code, body = await asyncio.to_thread(
            _sync_fetch_uppercrust, url, api_key
        )
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
    except Exception as exc:
        logger.debug("upperCrust proxy failed (%s), falling back", exc)
        return False
    return True


_middleware_tracer = get_tracer("sigrift.bridge.middleware")


def _csrf_setting() -> str:
    """``BRIDGE_CSRF`` as the CSRF check reads it: trimmed, lower case.

    Empty means the default for ``BRIDGE_ENV``; ``enabled`` turns the check
    on, and any other value turns it off.
    """
    return os.environ.get("BRIDGE_CSRF", "").strip().lower()


def _csrf_setting_problem() -> str | None:
    """Why ``BRIDGE_CSRF`` is refused in production, or ``None``.

    Production refuses to start with CSRF protection turned off (owner
    decision, 2026-11-10). Any value other than empty or ``enabled`` turns
    it off here, not only ``disabled``, so all of them are refused; the
    gateway refuses the same values.
    """
    if _csrf_setting() in ("", "enabled"):
        return None
    return (
        f"BRIDGE_CSRF={os.environ.get('BRIDGE_CSRF', '')!r} turns CSRF "
        "protection off (any value other than enabled does), which production "
        "refuses: unset BRIDGE_CSRF or set it to enabled"
    )


class CombinedMiddleware:
    """Single pure-ASGI middleware replacing SecurityHeaders, RequestSizeLimit,
    APIVersion, and RequestLogging middlewares."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "websocket":
            # --- Rust gateway trust header check (WebSocket upgrades) ---
            if _REQUIRE_PROXY and not _proxy_check_passes(
                scope, dict(scope.get("headers", []))
            ):
                # Closing before accept makes the server answer the
                # upgrade with 403.
                await WebSocketClose(code=1008, reason="Direct access denied")(
                    scope, receive, send
                )
                return
            if _is_internal_path(scope.get("path", "")) and not (
                rust_proxy_header_valid(HTTPConnection(scope))
            ):
                await WebSocketClose(code=1008, reason="Internal endpoint")(
                    scope, receive, send
                )
                return
            await self.app(scope, receive, send)
            return
        if scope["type"] not in ("http",):
            await self.app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        headers_raw = dict(scope.get("headers", []))

        # --- Rust gateway trust header check ---
        # When BRIDGE_REQUIRE_PROXY is enabled, reject requests that didn't
        # come through the Rust gateway (fail-closed).
        if _REQUIRE_PROXY and not _proxy_check_passes(scope, headers_raw):
            resp = Response(
                _PROXY_DENIED_BODY,
                status_code=403,
                media_type="application/json",
            )
            await resp(scope, receive, send)
            return

        # --- Gateway-only internal routes (K9, bridge half) ---
        is_internal = _is_internal_path(path)
        if is_internal and not rust_proxy_header_valid(HTTPConnection(scope)):
            resp = Response(
                _INTERNAL_DENIED_BODY,
                status_code=403,
                media_type="application/json",
            )
            await resp(scope, receive, send)
            return

        # --- Fix server scope for proxied requests ---
        # When behind the Rust gateway, X-Forwarded-Host tells us the real
        # external host:port. Override scope["server"] so Starlette's
        # url_for() generates correct URLs (not http://127.0.0.1:8001/...).
        # Only the gateway or a trusted proxy is believed: from a direct
        # client these headers would let it pick its own scheme (claiming
        # TLS for key rotation) and the host in generated links.
        fwd_host = headers_raw.get(b"x-forwarded-host", b"").decode("latin-1")
        if fwd_host and forwarding_headers_trusted(HTTPConnection(scope)):
            if ":" in fwd_host:
                fwd_hostname, fwd_port = fwd_host.rsplit(":", 1)
                try:
                    scope["server"] = (fwd_hostname, int(fwd_port))
                except (ValueError, TypeError):
                    scope["server"] = (fwd_host, 443)
            else:
                scope["server"] = (fwd_host, 443)
            # Also fix scheme if X-Forwarded-Proto is present (http/https only)
            fwd_proto = trusted_forwarded_proto(HTTPConnection(scope))
            if fwd_proto:
                scope["scheme"] = fwd_proto

        # --- Timing + request ID + correlation ID for logging ---
        # Before the size limit, so its 413 is a logged bridge response with
        # the security headers too (the gateway's SecurityHeadersLayer also
        # wraps its RequestBodyLimitLayer).
        is_api = path.startswith("/api/")
        is_ws = headers_raw.get(b"upgrade", b"").lower() == b"websocket"
        should_log = is_api and not is_ws
        request_id = uuid.uuid4().hex[:12] if should_log else ""
        start = time.monotonic() if should_log else 0.0

        # Correlation ID: accept from caller or generate from request_id
        # Sanitize to prevent header injection (alphanumeric, dash, underscore only)
        incoming_corr = headers_raw.get(b"x-correlation-id")
        if incoming_corr:
            decoded = incoming_corr.decode(errors="replace")[:64]
            correlation_id = _CORR_ID_RE.sub("", decoded) or (
                request_id or uuid.uuid4().hex[:12]
            )
        else:
            correlation_id = request_id or uuid.uuid4().hex[:12]
        scope.setdefault("state", {})["correlation_id"] = correlation_id

        scheme = scope.get("scheme", "http")
        status_code = 0

        async def send_with_headers(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
                extra_headers = list(_SECURITY_HEADERS)
                if scheme == "https":
                    extra_headers.append(_HSTS_HEADER)
                if is_api:
                    extra_headers.append((b"x-api-version", _API_VERSION_BYTES))
                if request_id:
                    extra_headers.append((b"x-request-id", request_id.encode()))
                extra_headers.append((b"x-correlation-id", correlation_id.encode()))
                message = dict(message)
                message["headers"] = list(message.get("headers", [])) + extra_headers
            await send(message)

        def log_request() -> None:
            if not should_log:
                return
            duration_ms = round((time.monotonic() - start) * 1000, 1)
            req_method = scope.get("method", "?")
            logger.info(
                "%s %s %d %.1fms",
                req_method,
                path,
                status_code,
                duration_ms,
                extra={
                    "request_id": request_id,
                    "correlation_id": correlation_id,
                    "method": req_method,
                    "path": path,
                    "status_code": status_code,
                    "duration_ms": duration_ms,
                },
            )
            # Record request for Prometheus metrics
            from sigrift.bridge.routers.metrics import record_request

            record_request(req_method, path)

        async def send_too_large() -> None:
            response = Response(_TOO_LARGE_BODY, status_code=413)
            await response(scope, receive, send_with_headers)

        # --- Request size limit ---
        # Before the upperCrust proxy, which buffers the whole body too.
        cl = headers_raw.get(b"content-length")
        try:
            cl_int = int(cl) if cl else 0
        except (ValueError, TypeError):
            cl_int = 0
        # The gateway's ingest hook carries a whole accepted batch (the
        # gateway takes batches of up to 50 MB decompressed); the route
        # enforces its own limit.
        max_body = internal.INGEST_HOOK_MAX_BODY if is_internal else _MAX_REQUEST_BODY
        if cl_int > max_body:
            await send_too_large()
            log_request()
            return
        # A chunked body declares no length: count what is read.
        body_limit = _LimitedReceive(receive, max_body)
        receive = body_limit

        # --- Proxy to upperCrust (Rust) ---
        method = scope.get("method", "GET")
        _is_post_proxy = method == "POST" and path in (
            "/api/detections/batch",
            "/batch",
        )
        _is_get_proxy = method == "GET" and path in _UPPERCRUST_PROXY_PATHS
        _is_proxy_path = _is_get_proxy or _is_post_proxy
        _proxy_api_key = ""
        if _is_proxy_path:
            _min_role = (
                _PROXY_WRITE_MIN_ROLE if _is_post_proxy else _PROXY_READ_MIN_ROLE
            )
            _key_id, _role, _reason = await _verify_proxy_auth(
                scope, min_role=_min_role
            )
            if _reason == "tenant":
                response = Response(
                    '{"detail":"Credential belongs to another tenant"}',
                    status_code=403,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return
            if _reason == "forbidden":
                response = Response(
                    '{"detail":"Insufficient role for this endpoint"}',
                    status_code=403,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return
            if _reason.startswith("scope:"):
                response = Response(
                    json.dumps({"detail": _scope_denied_detail(_reason[6:])}),
                    status_code=403,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return
            if _key_id is None:
                response = Response(
                    '{"detail":"API key or session token required"}',
                    status_code=401,
                    media_type="application/json",
                )
                await response(scope, receive, send)
                return
            # Forward the original API key header to upperCrust (not key_id)
            _proxy_api_key = headers_raw.get(b"x-api-key", b"").decode()

        # Proxy read-heavy dashboard queries
        if method == "GET" and path in _UPPERCRUST_PROXY_PATHS:
            if await _proxy_to_uppercrust(scope, receive, send, api_key=_proxy_api_key):
                return
        # Redirect batch ingest to upperCrust (biggest CPU saver)
        if method == "POST" and path in ("/api/detections/batch", "/batch"):
            try:
                result = await _proxy_post_to_uppercrust(scope, receive, send)
            except _BodyTooLarge:
                # Raised while the body is buffered, before any response.
                await send_too_large()
                log_request()
                return
            if result[0]:
                return
            # Proxy failed — replay the already-consumed body for the
            # downstream ASGI handler so it can read request.body().
            _consumed_body = result[1]
            _orig_receive = receive

            async def _replay_receive():
                nonlocal _consumed_body
                if _consumed_body is not None:
                    body = _consumed_body
                    _consumed_body = None
                    return {"type": "http.request", "body": body, "more_body": False}
                return await _orig_receive()

            receive = _replay_receive

        # --- API version check ---
        if is_api:
            req_ver = headers_raw.get(b"x-api-version")
            if req_ver and req_ver.decode() not in SUPPORTED_API_VERSIONS:
                response = Response(
                    content=f"Unsupported API version: {req_ver.decode()}",
                    status_code=400,
                )
                await response(scope, receive, send)
                return

        # --- CSRF Double Submit Cookie (SEC-H5) ---
        # Only enforce for session-authenticated mutating requests.
        # Controlled by BRIDGE_CSRF env var: "enabled" (default in production),
        # "disabled" to skip. In non-production, defaults to "disabled".
        # Production refuses to start with it off (_csrf_setting_problem).
        _csrf_mode = _csrf_setting()
        if not _csrf_mode:
            _bridge_env = os.environ.get("BRIDGE_ENV", "").lower()
            _csrf_mode = (
                "disabled"
                if _bridge_env in ("development", "dev", "test")
                else "enabled"
            )
        if (
            _csrf_mode == "enabled"
            and is_api
            and method in ("POST", "PUT", "DELETE", "PATCH")
        ):
            _csrf_exempt = (
                "/api/auth/login",
                "/api/auth/logout",
                "/api/auth/mfa/verify",
                "/api/version",
                "/api/health",
                "/api/detections/batch",
                "/batch",
            )
            has_api_key = b"x-api-key" in headers_raw
            is_ws_upgrade = headers_raw.get(b"upgrade", b"").lower() == b"websocket"
            # Check if session token is present (Bearer or X-Session-Token)
            has_session = False
            auth_hdr = headers_raw.get(b"authorization", b"").decode(errors="replace")
            if auth_hdr.lower().startswith("bearer "):
                has_session = True
            if headers_raw.get(b"x-session-token", b""):
                has_session = True
            if HTTPConnection(scope).cookies.get("session_token"):
                has_session = True
            if (
                has_session
                and has_api_key
                and path not in _csrf_exempt
                and not is_ws_upgrade
            ):
                conn = HTTPConnection(scope)
                token = _extract_session_token(conn)
                if token:
                    try:
                        resolved = await asyncio.to_thread(
                            resolve_session, conn, token, touch=False
                        )
                    except HTTPException:
                        response = Response(
                            '{"detail":"Credential belongs to another tenant"}',
                            status_code=403,
                            media_type="application/json",
                        )
                        await response(scope, receive, send)
                        return
                    # A valid session wins over a secondary API-key header.
                    # Only an invalid/expired session may fall through to key
                    # auth and retain the non-cookie client's CSRF exemption.
                    has_api_key = resolved is None
            if (
                has_session
                and not has_api_key
                and not is_ws_upgrade
                and path not in _csrf_exempt
            ):
                csrf_cookie = ""
                cookie_raw = headers_raw.get(b"cookie", b"").decode(errors="replace")
                for part in cookie_raw.split(";"):
                    part = part.strip()
                    if part.startswith("csrf_token="):
                        csrf_cookie = part[len("csrf_token=") :]
                        break
                csrf_header = headers_raw.get(b"x-csrf-token", b"").decode(
                    errors="replace"
                )
                # Constant time, as the gateway compares: `!=` stops at the
                # first differing character.
                if (
                    not csrf_cookie
                    or not csrf_header
                    or not hmac.compare_digest(
                        csrf_cookie.encode(), csrf_header.encode()
                    )
                ):
                    response = Response(
                        '{"detail":"CSRF token missing or mismatch"}',
                        status_code=403,
                        media_type="application/json",
                    )
                    await response(scope, receive, send)
                    return

        # The app's own response has started (before any body limit hit).
        response_started = False
        # 413 sent for a body that went past the limit while it was read.
        refused = False

        async def refuse_body():
            nonlocal refused
            refused = True
            await send_too_large()

        async def send_wrapper(message):
            nonlocal response_started
            if refused:
                # The app's answer to a body it was refused: already 413.
                return
            if message["type"] == "http.response.start":
                if body_limit.exceeded:
                    # Whatever the route made of the refused read (a 400
                    # parse error, a 422, a 500), the answer is 413.
                    await refuse_body()
                    return
                response_started = True
            await send_with_headers(message)

        with trace_span(
            _middleware_tracer,
            "http_request",
            attributes={
                "http.method": method,
                "http.path": path,
                "http.correlation_id": correlation_id,
            },
        ) as _req_span:
            try:
                await self.app(scope, receive, send_wrapper)
            except Exception:
                # A route that let the refused read escape: answered below.
                if not body_limit.exceeded or response_started:
                    raise
            if body_limit.exceeded and not response_started and not refused:
                await refuse_body()
            _req_span.set_attribute("http.status_code", status_code)

        log_request()


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


#: Control characters a log line must not carry raw: C0 except tab, DEL,
#: C1, and the Unicode line and paragraph separators.  Any of them can
#: start what a terminal or a line-splitting tool shows as a new record.
_LOG_CONTROL_CHARS = re.compile("[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")


class SingleLineFormatter(logging.Formatter):
    """Text formatter that keeps each log record's message on one line.

    Log messages often include values from requests, edge nodes or radio
    payloads.  A CR or LF in such a value would start a new line in
    stdout/journald that looks like a separate, forged record (CWE-117),
    and an ESC sequence could rewrite the previous line in a terminal.
    This formatter writes such characters as escapes (``\\n``, ``\\x1b``,
    ...).  A traceback (``exc_info``/``stack_info``) is appended after the
    message and keeps its own lines.
    """

    def formatMessage(self, record: logging.LogRecord) -> str:  # noqa: N802
        line = super().formatMessage(record)
        return _LOG_CONTROL_CHARS.sub(lambda m: repr(m.group())[1:-1], line)


def _ensure_root_log_handler(log_level: str) -> None:
    """Attach a stdout handler to the root logger if none exists.

    The root logger had its *level* set to INFO but no *handler*, so
    application ``logger.info``/``debug`` records were silently dropped —
    only WARNING+ reached stderr via Python's last-resort handler. That
    hid the WAL-checkpoint diagnostics (busy/log/checkpointed) for days
    during the 2026-06 WAL-bloat incident. Uvicorn configures its own
    loggers (propagate=False), so this only surfaces ``sigrift.bridge.*``
    logs and won't double-log uvicorn's output.

    Idempotent: tagged so repeated calls (or multiple workers in one
    process) don't stack handlers.  The handler uses
    :class:`SingleLineFormatter`, so a logged value cannot forge extra
    log lines.
    """
    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level, logging.INFO))
    if any(getattr(h, "_sigrift_app_handler", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(
        SingleLineFormatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler._sigrift_app_handler = True  # type: ignore[attr-defined]
    root.addHandler(handler)


#: Shortest BRIDGE_MASTER_KEY / BRIDGE_LOCAL_NODE_KEY that starts without a
#: warning.  The installers generate 43 characters (secrets.token_urlsafe(32)).
_MIN_ENV_KEY_LENGTH = 32


def _warn_if_short_env_key(name: str, value: str) -> None:
    """Warn at startup when an operator-set API key is short.

    keys.json keeps a fast, unsalted SHA-256 lookup hash of every API key
    next to its PBKDF2 hash.  That is fine for long random keys, but a
    short or hand-picked key could be guessed from a leaked keys.json.
    Only the length is logged, never the key.
    """
    if value and len(value) < _MIN_ENV_KEY_LENGTH:
        logger.warning(
            "%s is only %d characters long. Use at least %d random characters, "
            'for example python3 -c "import secrets; '
            'print(secrets.token_urlsafe(32))": a short key can be guessed '
            "from its lookup hash if keys.json leaks.",
            name,
            len(value),
            _MIN_ENV_KEY_LENGTH,
        )


#: Key id under which releases before 2026-11 *also* stored
#: BRIDGE_LOCAL_NODE_KEY, next to LOCAL_SCANNER_KEY_ID.  Two key_ids for one
#: credential left this one without a lookup hash in keys.json, so every
#: unknown API key cost a PBKDF2 against it (bridge and gateway).
_LEGACY_LOCAL_EDGE_KEY_ID = "node_local_edge"
_LEGACY_LOCAL_EDGE_DESCRIPTION = "Auto-seeded local edge agent (BRIDGE_LOCAL_NODE_KEY)"


def _drop_legacy_local_edge_key(persistence: PersistenceManager, raw_key: str) -> None:
    """Remove the duplicate ``node_local_edge`` entry older releases seeded.

    It is removed when it is the auto-seeded copy (its description says so)
    or holds the current BRIDGE_LOCAL_NODE_KEY; that credential keeps
    working as LOCAL_SCANNER_KEY_ID, which the fast index already resolved
    it to.  An operator-created key that merely reuses the id is kept.

    Does not refuse startup when keys.json cannot be written: the entry
    only duplicates a credential that stays valid, its removal stays in
    effect here and the next save retries it.
    """
    from sigrift.lib.security.credentials import verify_credential

    stored = persistence.get_key_store().get(_LEGACY_LOCAL_EDGE_KEY_ID)
    if stored is None:
        return
    meta = persistence.get_key_meta().get(_LEGACY_LOCAL_EDGE_KEY_ID, {})
    if meta.get("description") != _LEGACY_LOCAL_EDGE_DESCRIPTION and not (
        raw_key and verify_credential(raw_key, *stored)
    ):
        return
    try:
        persistence.remove_key(_LEGACY_LOCAL_EDGE_KEY_ID)
    except KeyStoreWriteError as exc:
        logger.warning(
            "Duplicate API key '%s' %s (%s)",
            _LEGACY_LOCAL_EDGE_KEY_ID,
            "removed in memory only; the next save retries writing keys.json"
            if exc.applied_here
            else "not removed; the next start retries",
            exc,
        )
        return
    logger.info(
        "Removed duplicate API key '%s' (BRIDGE_LOCAL_NODE_KEY is registered "
        "as '%s' only)",
        _LEGACY_LOCAL_EDGE_KEY_ID,
        LOCAL_SCANNER_KEY_ID,
    )


def _seed_local_scanner_key(
    persistence: PersistenceManager, raw_key: str, node_id: str | None = None
) -> None:
    """Register BRIDGE_LOCAL_NODE_KEY as LOCAL_SCANNER_KEY_ID (NODE role).

    One key_id per credential: the key is stored once, with its lookup
    hash, so it is always indexed and unknown keys never PBKDF2-scan it.
    Re-hashes only when the entry is missing, out of sync with the env var
    or not indexed, and rewrites the metadata only when the role is not
    NODE — the in-stack scanners must never hold an analyst/admin key —
    or the key is not bound to *node_id* (BRIDGE_LOCAL_NODE_ID, the node
    the in-stack scanners report as; contract K4).  A key bound to that
    node can heartbeat, take commands and submit data for it only.

    Raises ``RuntimeError`` when the value is already registered under
    another key_id (one credential cannot be two keys), and
    :class:`KeyStoreWriteError` (startup is refused) when keys.json cannot
    be written.
    """
    from sigrift.lib.security.credentials import verify_credential

    lookup_hash = compute_lookup_hash(raw_key)
    stored = persistence.get_key_store().get(LOCAL_SCANNER_KEY_ID)
    in_sync = (
        stored is not None
        and persistence.get_key_fast_index().get(lookup_hash) == LOCAL_SCANNER_KEY_ID
        and verify_credential(raw_key, *stored)
    )
    if not in_sync:
        if stored is not None:
            logger.warning(
                "BRIDGE_LOCAL_NODE_KEY out of sync with API key '%s' — re-hashing",
                LOCAL_SCANNER_KEY_ID,
            )
        hash_hex, salt = hash_credential(raw_key)
        try:
            persistence.set_key(
                LOCAL_SCANNER_KEY_ID, hash_hex, salt, lookup_hash=lookup_hash
            )
        except ValueError as exc:
            raise RuntimeError(
                f"BRIDGE_LOCAL_NODE_KEY cannot be registered: {exc}. The "
                "in-stack scanner key must be its own credential — set "
                "BRIDGE_LOCAL_NODE_KEY to a new random value (python3 -c "
                "'import secrets; print(secrets.token_urlsafe(32))')."
            ) from exc
        logger.info(
            "Pre-registered in-stack scanner key '%s' from BRIDGE_LOCAL_NODE_KEY",
            LOCAL_SCANNER_KEY_ID,
        )

    node_id = node_id or None
    meta = persistence.get_key_meta().get(LOCAL_SCANNER_KEY_ID) or {}
    if meta.get("role") != "node" or (meta.get("node_id") or None) != node_id:
        # No expires_at: the env-var-supplied key is operator-managed.
        persistence.set_key_meta(
            LOCAL_SCANNER_KEY_ID,
            {
                "description": "In-stack scanner key (BRIDGE_LOCAL_NODE_KEY)",
                "created_at": meta.get("created_at") or utcnow().isoformat(),
                "expires_at": None,
                "node_id": node_id,
                "role": "node",
                "revoked": False,
            },
        )


def _log_unwritable_key_store(
    persistence: PersistenceManager, what: str, exc: KeyStoreWriteError
) -> None:
    """Log why startup is refused: *what* must be saved, keys.json cannot be."""
    logger.critical(
        "Refusing to start: %s must be saved to %s, which cannot be written "
        "(%s). Free disk space or make the data directory writable, then "
        "restart.",
        what,
        persistence.data_dir / "keys.json",
        exc,
    )


#: Key ids the lifespan seeds from BRIDGE_LOCAL_NODE_KEY (current and legacy).
_IN_STACK_KEY_IDS = (LOCAL_SCANNER_KEY_ID, _LEGACY_LOCAL_EDGE_KEY_ID)


def _index_master_key(
    persistence: PersistenceManager, env_key: str, local_node_key: str
) -> None:
    """Sync the stored master key with BRIDGE_MASTER_KEY and index it.

    A master entry written before lookup hashes existed is re-hashed with
    one, so unknown keys are rejected without a PBKDF2 scan against it.

    Releases that allowed BRIDGE_LOCAL_NODE_KEY to equal BRIDGE_MASTER_KEY
    left the in-stack scanner entry holding the master credential (and its
    lookup hash).  Once BRIDGE_LOCAL_NODE_KEY is a different value — or
    unset — that entry is stale: it is removed here so the master key can
    be indexed, and re-seeded from BRIDGE_LOCAL_NODE_KEY afterwards.

    Raises :class:`KeyStoreWriteError` (startup is refused) when keys.json
    cannot be written: BRIDGE_MASTER_KEY would not be the stored master
    key for the gateway, other workers or the next start.
    """
    from sigrift.lib.security.credentials import verify_credential

    stored = persistence.get_key_store().get("master")
    if stored is None:
        return
    lookup_hash = compute_lookup_hash(env_key)
    owner = persistence.get_key_fast_index().get(lookup_hash)
    if verify_credential(env_key, *stored):
        if owner == "master":
            return
        logger.info("Adding a lookup hash to the master key")
    else:
        logger.warning(
            "BRIDGE_MASTER_KEY env var out of sync with key store — re-hashing"
        )
    hash_hex, salt = hash_credential(env_key)
    if owner in _IN_STACK_KEY_IDS and env_key != local_node_key:
        persistence.remove_key(owner)
        logger.warning(
            "Removed stale API key '%s': it held BRIDGE_MASTER_KEY's value, "
            "which is no longer BRIDGE_LOCAL_NODE_KEY",
            owner,
        )
    try:
        persistence.set_key("master", hash_hex, salt, lookup_hash=lookup_hash)
    except ValueError as exc:
        raise RuntimeError(
            f"BRIDGE_MASTER_KEY cannot be registered: {exc}. Use a distinct "
            "random value for BRIDGE_MASTER_KEY."
        ) from exc


class _RefuseToStart(RuntimeError):
    """A start-up check that stops the bridge (never only logged)."""


def _write_owner_only_file(path: Path, text: str) -> None:
    """Write *text* to a new owner-only (0600) file at *path*.

    The admin password file has a fixed, documented name in the temp dir,
    so something may already be there: a symlink or file another user
    planted, or a file an earlier run left behind.  It is removed, never
    written through: the file is created with ``O_EXCL`` (which does not
    follow a symlink) and ``O_NOFOLLOW``, mode 0600 from the start.

    Raises :class:`OSError` when the file cannot be created, also when the
    entry at *path* cannot be removed (another user's file in a sticky
    ``/tmp``, a directory) or is planted again right after removal.
    """
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        # unlink() removes a symlink itself, never its target.
        path.unlink()
        fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            # The umask may only have narrowed it; make it exactly 0600.
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(text)
    except BaseException:
        if fd != -1:
            os.close(fd)
        # No partial password file is left behind (nothing deletes it).
        try:
            path.unlink()
        except OSError:
            pass
        raise


async def _sweep_migration_leftovers(detection_store: object) -> None:
    """One periodic sweep of migration leftovers; never raises.

    Startup sweeps them too (``SharedContext._init_db``), but a bridge can
    run for weeks: this removes what is older than 7 days, including the
    ``.pre-migration`` copy a successful upgrade keeps, and that copy
    earlier once the volume has no room for it
    (``SharedContext.sweep_migration_leftovers``).
    """
    ctx = getattr(detection_store, "_ctx", None)
    if ctx is None:
        return
    try:
        await asyncio.to_thread(ctx.sweep_migration_leftovers)
    except Exception as exc:
        logger.warning("Migration leftover sweep failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage startup and shutdown of the bridge application.

    Startup:
      - Refuse to start while a restore marker
        (``.sigrift-restore-incomplete``) exists in bridge_data or
        bridge_secrets, before anything touches the volumes
      - Log the release (``SIGRIFT_RELEASE``) next to server_version
      - Load configuration
      - Create and load PersistenceManager
      - Start background auto-save
      - Create AppState and restore alert counter
      - Initialize rate limiter
      - Initialize DetectionStore (migrations under the pre-migration
        copy policy of storage/base.py)
      - Load the protocol decryption keys: built-in defaults, then the
        keys saved in crypto_keys (storage/crypto_keys.py), before any
        decode job runs
      - Generate initial master key if none exist

    Shutdown:
      - Cancel background tasks, then stop auto-save (performs the final
        save) before anything that waits
      - Stop the job queue (waiting, bounded, for its handler threads) and
        drain the write queue
      - Save again (state changed meanwhile), wait (bounded) for worker
        threads still running, then close DetectionStore
    """
    # -- Logging: root level + stdout handler so app INFO actually emits -----
    log_level = os.environ.get("BRIDGE_LOG_LEVEL", "INFO").upper()
    _ensure_root_log_handler(log_level)

    # -- Restore marker: a restore of the volumes that did not finish -------
    # Before anything reads or writes bridge_data / bridge_secrets (the
    # data-dir chmod, keys.json, the database and its .pre-migration copy).
    # Raises like the production guards: uvicorn exits, and the healthcheck
    # never passes, so the gateway never starts.
    from sigrift.bridge.restore_marker import check_restore_markers

    check_restore_markers()

    # -- Worker threads: a default executor shutdown can wait on ------------
    # (asyncio.to_thread work outlives the cancellation of its task; the
    # database must not be closed under it, see the shutdown block.)
    from sigrift.bridge.worker_threads import install_default_executor

    worker_executor = install_default_executor()

    # -- Access log → file (keeps uvicorn access logs out of stderr) --------
    _access_log_dir = Path(__file__).resolve().parent.parent / "logs" / "access"
    _access_log_dir.mkdir(parents=True, exist_ok=True)
    _access_ts = time.strftime("%Y%m%d_%H%M%S")
    _access_handler = logging.handlers.TimedRotatingFileHandler(
        _access_log_dir / f"access_{_access_ts}.log",
        when="midnight",
        backupCount=30,
        encoding="utf-8",
    )
    _access_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    _uvicorn_access = logging.getLogger("uvicorn.access")
    _uvicorn_access.addHandler(_access_handler)
    _uvicorn_access.propagate = False  # don't duplicate to stderr

    # -- Memory limit (RSS cap, auto-restart if exceeded) --------------------
    _mem_limit_mb = int(os.environ.get("BRIDGE_MEMORY_LIMIT_MB", "0"))  # 0 = no limit
    if _mem_limit_mb > 0:
        try:
            import resource

            _mem_limit_bytes = _mem_limit_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (_mem_limit_bytes, _mem_limit_bytes))
            logger.info(
                "Memory limit set: %d MB (BRIDGE_MEMORY_LIMIT_MB)", _mem_limit_mb
            )
        except (ImportError, ValueError, OSError) as _mem_exc:
            logger.debug("Could not set memory limit: %s", _mem_exc)
    else:
        logger.info("No memory limit set (BRIDGE_MEMORY_LIMIT_MB=0)")

    # -- Log buffer (must be early so it captures all startup logs) ----------
    init_log_buffer()

    from sigrift.bridge.release_info import log_release

    log_release(logger)

    from sigrift.bridge.storage.base import allow_migration_without_backup

    if allow_migration_without_backup():
        logger.warning(
            "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP is set: new database "
            "migrations are applied without their detections.db.pre-migration "
            "recovery copy when it cannot be made. Remove it once the upgrade "
            "it was set for is done."
        )

    # -- OpenTelemetry tracing (P3-13, no-op if opentelemetry not installed) -
    setup_tracing()
    logger.info("OTel tracing initialized")

    # -- Data directory permissions hardening --------------------------------
    _data_dir = Path(__file__).resolve().parent / "data"
    if _data_dir.exists():
        try:
            _data_dir.chmod(0o700)
            # webhooks.json holds webhook signing secrets; releases up to
            # v0.1.0 wrote it with the umask mode.
            for _secret in ("keys.json", ".mac_secret", "webhooks.json"):
                _sf = _data_dir / _secret
                if _sf.exists():
                    _sf.chmod(0o600)
            logger.info("Data directory permissions hardened: %s", _data_dir)
        except OSError as _perm_err:
            logger.warning("Could not harden data dir permissions: %s", _perm_err)

    # -- Production security guards -----------------------------------------
    # Production is detected the same way the MFA/audit key stores detect
    # it (BRIDGE_ENV or BRIDGE_MODE = production/prod), so the startup
    # guard and the runtime fail-closed paths agree.
    from sigrift.bridge.storage.users import (
        _is_production as _is_production_mode,
        mfa_key_problem,
        mfa_key_remedy,
    )

    _bridge_env = os.environ.get("BRIDGE_ENV", "").strip().lower()
    _mfa_problem = mfa_key_problem()
    if _is_production_mode():
        _key_errors = []
        if _mfa_problem:
            # Validates the format, not just presence: an invalid key
            # would otherwise leave TOTP secrets stored as base64.
            # A 43-character key is repaired by appending '=' (keeps
            # existing encrypted TOTP secrets readable), anything else by
            # generating a new key.
            _key_errors.append(f"{_mfa_problem} — to fix it, {mfa_key_remedy()}")
        if not os.environ.get("BRIDGE_AUDIT_KEY", "").strip():
            _key_errors.append(
                "BRIDGE_AUDIT_KEY is not set — generate one with: "
                "python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
            )
        _csrf_problem = _csrf_setting_problem()
        if _csrf_problem:
            _key_errors.append(_csrf_problem)
        if _key_errors:
            logger.critical(
                "FATAL: production mode — refusing to start: %s",
                "; ".join(_key_errors),
            )
            raise RuntimeError("Production requires: " + "; ".join(_key_errors))
        _proxy_secret = os.environ.get("UC_PROXY_SECRET", "")
        # The proxy-secret guard keeps its original BRIDGE_ENV=production
        # trigger; only the MFA/audit key checks follow _is_production().
        if _bridge_env == "production" and (
            not _proxy_secret or _proxy_secret == "uppercrust-internal"
        ):
            logger.critical(
                "FATAL: production mode requires a strong UC_PROXY_SECRET — "
                "refusing to start with default value"
            )
            raise RuntimeError("Production requires strong UC_PROXY_SECRET")
        logger.info("Production security guards passed")
    elif _bridge_env in ("development", "dev", "test"):
        if _mfa_problem:
            logger.warning(
                "%s — MFA secrets stored as base64 (insecure). To fix it, %s",
                _mfa_problem,
                mfa_key_remedy(),
            )
        if not os.environ.get("BRIDGE_AUDIT_KEY"):
            logger.warning(
                "BRIDGE_AUDIT_KEY not set — audit HMAC chain uses weak default"
            )
    else:
        logger.warning("BRIDGE_ENV not set — defaulting to development mode")
    if not _is_production_mode() and _csrf_setting_problem():
        logger.warning(
            "%s. Allowed outside production: CSRF protection is OFF, and only "
            "SameSite protects session requests; production refuses to start.",
            _csrf_setting_problem(),
        )

    # -- Gateway trust (contract K2) and node binding (K4) ------------------
    reload_trusted_proxies()
    _log_gateway_trust_status()
    if allow_unbound_node_keys():
        logger.warning(
            "%s is set: sensor/node API keys that are not bound to a node may "
            "act for any node (heartbeats, commands, ingest). Bind node keys "
            "(node_id) and unset it.",
            ALLOW_UNBOUND_NODE_KEYS_ENV,
        )

    # -- Configuration ------------------------------------------------------
    config = load_config()
    set_config(config)

    # -- Rate limiter -------------------------------------------------------
    limiter = RateLimiter(
        max_requests=config.security.rate_limit_per_minute,
        window_seconds=60.0,
    )
    set_rate_limiter(limiter)

    # -- WebSocket connection limiter ---------------------------------------
    ws_limiter = WSConnectionLimiter()
    set_ws_limiter(ws_limiter)

    # -- Persistence --------------------------------------------------------
    persistence = PersistenceManager()
    persistence.load_all()
    await persistence.start_auto_save()

    # -- App state ----------------------------------------------------------
    app_state = AppState()
    app_state.restore_alert_counter(persistence)

    # -- Detection store ----------------------------------------------------
    detection_store = DetectionStore()

    # -- Write queue (batched detection inserts) ----------------------------
    write_queue = WriteQueue(
        detection_store,
        batch_size=int(os.environ.get("BRIDGE_WQ_BATCH_SIZE", "100")),
        flush_interval_ms=int(os.environ.get("BRIDGE_WQ_FLUSH_MS", "500")),
    )
    await write_queue.start()

    # -- IQ capture store ---------------------------------------------------
    iq_store = IQStore()

    # -- IQ metadata index --------------------------------------------------
    from sigrift.bridge.storage.iq_metadata import IQMetadataStore

    iq_metadata_store = IQMetadataStore(detection_store._ctx)

    # -- Fingerprint store (sentinel plugin) -----------------------------
    # The FingerprintStore lives in the `sigrift-sentinel` package.
    # Community builds do not ship sentinel; the ImportError is caught and
    # fingerprint features are disabled.
    fingerprint_store = None
    try:
        from sigrift_sentinel.storage.fingerprints import FingerprintStore

        fingerprint_store = FingerprintStore(detection_store._ctx)
        logger.info("Fingerprint store enabled (sentinel installed)")
    except ImportError:
        logger.info("Fingerprint store disabled (sentinel package not installed)")

    # -- Signature library store --------------------------------------------
    from sigrift.bridge.storage.signature_library import SignatureLibraryStore

    signature_library_store = SignatureLibraryStore(detection_store._ctx)
    if os.environ.get("BRIDGE_SEED_THREATS", "true").lower() in ("true", "1", "yes"):
        if hasattr(signature_library_store, "seed_threat_signatures"):
            signature_library_store.seed_threat_signatures()

    # -- Incident store -----------------------------------------------------
    from sigrift.bridge.storage.incidents import IncidentStore

    incident_store = IncidentStore(detection_store._ctx)

    # -- Aircraft store -----------------------------------------------------
    from sigrift.bridge.storage.aircraft import AircraftStore

    aircraft_store = AircraftStore(detection_store._ctx)
    detection_store._aircraft = aircraft_store

    # -- Sweep store --------------------------------------------------------
    from sigrift.bridge.storage.sweeps import SweepStore

    sweep_store = SweepStore(detection_store._ctx)

    # -- WiFi device cluster store ------------------------------------------
    from sigrift.bridge.storage.wifi_device_clusters import WiFiDeviceClusterStore

    wifi_cluster_store = WiFiDeviceClusterStore(detection_store._ctx)

    # -- Bitstream store ----------------------------------------------------
    from sigrift.bridge.storage.bitstreams import BitstreamStore

    bitstream_store = BitstreamStore(detection_store._ctx)

    # -- Preamble store -----------------------------------------------------
    from sigrift.bridge.storage.preambles import PreambleStore

    preamble_store = PreambleStore(detection_store._ctx)

    # -- Packet store -------------------------------------------------------
    from sigrift.bridge.storage.packets import PacketStore

    packet_store = PacketStore(detection_store._ctx)

    # -- Fuzz session store (sentinel plugin) ----------------------------
    # FuzzSessionStore lives in sigrift-sentinel. Community builds don't
    # ship it; ImportError is the graceful-degradation signal.
    fuzz_session_store = None
    try:
        from sigrift_sentinel.storage.fuzz_sessions import FuzzSessionStore

        fuzz_session_store = FuzzSessionStore(detection_store._ctx)
        logger.info("Fuzz session store enabled (sentinel installed)")
    except ImportError:
        logger.info("Fuzz session store disabled (sentinel package not installed)")

    # -- Geolocation store --------------------------------------------------
    from sigrift.bridge.storage.geolocation import GeolocationStore

    geolocation_store = GeolocationStore(detection_store._ctx)

    # -- Map / floor plan store ---------------------------------------------
    from sigrift.bridge.storage.maps import MapStore

    map_store = MapStore(detection_store._ctx)

    # -- Emitter tracking (Kalman filter) -----------------------------------
    from sigrift.lib.dsp.emitter_tracker import EmitterTracker
    from sigrift.bridge.storage.tracks import TrackStore

    emitter_tracker = EmitterTracker()
    track_store = TrackStore(detection_store._ctx)

    # -- Analysis job queue -------------------------------------------------
    from sigrift.bridge.job_queue import AnalysisJobQueue

    job_queue = AnalysisJobQueue(max_workers=2, max_queue_size=100)

    if iq_store is not None:
        from sigrift.bridge.iq_store import spectrogram_job_handler

        # Runs in a worker thread; the result is bounded for every nfft
        # (see spectrogram_job_handler), since results stay in memory
        # until the job is evicted.
        job_queue.register_handler(
            "spectrogram",
            spectrogram_job_handler(
                iq_store, max_result_bytes=job_queue.max_result_bytes
            ),
        )

    # -- Fingerprint computation service (sentinel plugin) ---------------
    # Depends on FingerprintStore above. If the store failed to load
    # (community build, no sentinel), the service stays None.
    data_dir = Path(__file__).resolve().parent / "data"
    fingerprint_service = None
    if fingerprint_store is not None:
        try:
            from sigrift_sentinel.fingerprint.service import FingerprintService

            fp_model_path = os.environ.get(
                "BRIDGE_FINGERPRINT_MODEL",
                str(data_dir / "fingerprint_encoder.pth"),
            )
            fingerprint_service = FingerprintService(
                fingerprint_store=fingerprint_store,
                iq_store=iq_store,
                model_path=fp_model_path,
            )
            job_queue.register_handler(
                "fingerprint",
                fingerprint_service.compute_fingerprint_handler,
            )
            logger.info("Fingerprint service enabled (sentinel installed)")
        except ImportError:
            logger.info(
                "Fingerprint service disabled — sentinel.fingerprint.service not importable"
            )
    else:
        logger.info("Fingerprint service disabled (no store)")

    # -- Protocol decode job handler ----------------------------------------
    from sigrift.bridge.decode_pipeline import (
        ProtocolDecodePipeline,
        protocol_decode_job_handler,
    )
    from sigrift.bridge.storage.crypto_keys import init_crypto_keys

    from sigrift.bridge.storage.decoded_messages import DecodedMessageStore

    # Built-in defaults, then the keys saved in crypto_keys (when
    # BRIDGE_KEYSTORE_KEY is set): before the decode pipeline and the job
    # queue start, so no decode job runs without them.
    crypto_key_store, crypto_key_vault = init_crypto_keys(detection_store._ctx)
    # Decoded protocol messages are persisted (also used by the ingest path
    # for edge-decoded messages via app.state.decoded_message_store).
    decoded_message_store = DecodedMessageStore(detection_store._ctx)
    decode_pipeline = ProtocolDecodePipeline(
        decoded_message_store, crypto_key_store=crypto_key_store
    )
    # Jobs are queued once a decodable detection's IQ is stored (IQ upload
    # route, decode_pipeline.queue_protocol_decode).
    job_queue.register_handler(
        "protocol_decode", protocol_decode_job_handler(decode_pipeline, iq_store)
    )

    await job_queue.start()

    # -- Family classifier for edge deployment ------------------------------
    family_model_path = os.environ.get(
        "BRIDGE_FAMILY_MODEL",
        str(data_dir / "family_classifier.pth"),
    )
    try:
        from sigrift.lib.dsp.family_classifier import load_family_classifier

        if Path(family_model_path).exists():
            app.state.family_classifier = load_family_classifier(family_model_path)
            logger.info("Family classifier loaded from %s", family_model_path)
        else:
            app.state.family_classifier = None
            logger.info(
                "No family classifier model at %s (will be available after training)",
                family_model_path,
            )
    except Exception as exc:
        app.state.family_classifier = None
        logger.warning("Failed to load family classifier: %s", exc)

    # -- Pcap capture store -------------------------------------------------
    pcap_store = PcapStore()

    # -- Seed dismissed anomalies from persistent audit log ----------------
    try:
        dismissed_from_db = detection_store.get_dismissed_ids()
        app_state.dismissed_anomalies = dismissed_from_db
        if dismissed_from_db:
            logger.info(
                "Seeded %d dismissed anomalies from audit log", len(dismissed_from_db)
            )
    except Exception as exc:
        logger.warning("Failed to seed dismissed anomalies: %s", exc)

    # -- WiFi anomaly baseline + scorer ------------------------------------
    wifi_baseline_mgr = WifiBaselineManager()
    wifi_baselines_path = str(
        Path(__file__).resolve().parent / "data" / "wifi_baselines.json"
    )
    try:
        wifi_baseline_mgr.load(wifi_baselines_path)
    except Exception as exc:
        logger.warning("Failed to load WiFi baselines: %s", exc)
    max_frame_capture = int(os.environ.get("MLRF_WIFI_FRAME_CAPTURE_MAX", "50"))
    wifi_scorer = WifiAnomalyScorer(
        wifi_baseline_mgr, max_frame_capture=max_frame_capture
    )
    wifi_scorer.set_whitelist(persistence.get_wifi_whitelist())

    # -- Bluetooth anomaly baseline + scorer -----------------------------------
    bt_baseline_mgr = BtBaselineManager()
    bt_baselines_path = str(
        Path(__file__).resolve().parent / "data" / "bt_baselines.json"
    )
    try:
        bt_baseline_mgr.load(bt_baselines_path)
    except Exception as exc:
        logger.warning("Failed to load BT baselines: %s", exc)
    bt_scorer = BtAnomalyScorer(bt_baseline_mgr)

    # -- RF anomaly baseline + scorer ----------------------------------------
    rf_baseline_mgr = BaselineManager()
    rf_baselines_path = str(Path(__file__).resolve().parent / "data" / "baselines.json")
    try:
        rf_baseline_mgr.load(rf_baselines_path)
    except Exception as exc:
        logger.warning("Failed to load RF baselines: %s", exc)
    rf_scorer = AnomalyScorer(rf_baseline_mgr)
    # Wire threat signature library into scorer for SIGNATURE_MATCH dimension
    rf_scorer._sig_store = signature_library_store

    # -- First-boot preset seeding (SIGRIFT_PRESET) -------------------------
    # A fresh install can start warm instead of spending ~300 detections/bin in
    # learning mode. Only seeds when RF baselines are empty AND no bundle has
    # been applied before (provenance marker) — idempotent, never overwrites
    # learned state. A bad preset logs and continues cold; it must never block
    # the bridge from starting.
    _preset = os.environ.get("SIGRIFT_PRESET", "").strip()
    _data_dir = Path(rf_baselines_path).parent
    _prov = _data_dir / "bundle_provenance.json"
    if _preset and _preset.lower() != "none":
        if rf_baseline_mgr.baselines or _prov.exists():
            logger.info(
                "SIGRIFT_PRESET=%s ignored: learned baselines already present "
                "(%d bins) or a bundle was already applied",
                _preset,
                len(rf_baseline_mgr.baselines),
            )
        else:
            try:
                from sigrift.bridge import bundles as _bundles

                _preset_path = _bundles.resolve_preset(_preset)
                if _preset_path is None:
                    logger.error("SIGRIFT_PRESET=%s: no such packaged preset", _preset)
                else:
                    _rep, _man, _members = _bundles.validate_bundle(
                        _preset_path, expect_kind="preset"
                    )
                    if not _rep.valid:
                        logger.error(
                            "SIGRIFT_PRESET=%s failed validation; starting cold",
                            _preset,
                        )
                    else:
                        _rf_bytes = _members.get("rf_baselines.json")
                        if _rf_bytes is not None:
                            _bl, _alpha = _bundles.load_rf_baselines_from_bytes(
                                _rf_bytes
                            )
                            rf_baseline_mgr.replace_state(_bl, _alpha)
                            rf_baseline_mgr.save(rf_baselines_path)
                        # Provenance marker: gates re-seeding on subsequent boots
                        # and surfaces in GET /api/admin/baselines/status.
                        _prov.write_text(
                            json.dumps(
                                {
                                    "bundle_name": _man.name,
                                    "kind": _man.kind,
                                    "profile": _man.profile,
                                    "git_sha": _man.generator.git_sha,
                                    "components": ["rf"],
                                    "source": "SIGRIFT_PRESET",
                                },
                                indent=2,
                            )
                        )
                        logger.info(
                            "Applied preset '%s' (%d RF bins) — anomaly scoring "
                            "warm; timing patterns refine locally",
                            _preset,
                            len(rf_baseline_mgr.baselines),
                        )
            except Exception as exc:
                logger.error("SIGRIFT_PRESET=%s seeding failed: %s", _preset, exc)

    # -- Build RF baselines from existing detections if empty ---------------
    if not rf_baseline_mgr.baselines:
        try:
            conn = detection_store.get_connection()
            rows = conn.execute(
                "SELECT signal_class, confidence, freq_hz, power_dbm, timestamp "
                "FROM detections WHERE freq_hz > 0 ORDER BY timestamp LIMIT 50000"
            ).fetchall()
            for r in rows:
                rf_baseline_mgr.update(
                    r["freq_hz"],
                    r["signal_class"],
                    r["confidence"],
                    r["power_dbm"],
                    AnomalyScorer._extract_hour(r["timestamp"]),
                )
            if rows:
                logger.info(
                    "Built RF baselines from %d existing detections (%d freq bins)",
                    len(rows),
                    len(rf_baseline_mgr.baselines),
                )
                # Persist immediately: the rebuild is lossy (it replays only
                # class/confidence/power/hour, dropping SNR/bandwidth/inter-arrival)
                # and would otherwise repeat on every crash-restart. One save here
                # caps the loss to a single rebuild ever.
                try:
                    rf_baseline_mgr.save(rf_baselines_path)
                except Exception as save_exc:
                    logger.warning(
                        "Failed to persist rebuilt RF baselines: %s", save_exc
                    )
        except Exception as exc:
            logger.warning("Failed to build RF baselines from detections: %s", exc)

    # -- Backfill rf_anomalies from existing detections (one-time) -----------
    try:
        conn = detection_store.get_connection()
        rf_count = conn.execute("SELECT COUNT(*) as cnt FROM rf_anomalies").fetchone()[
            "cnt"
        ]
        if rf_count == 0:
            rows = conn.execute(
                "SELECT detection_id, signal_class, family, freq_hz, node_id, "
                "timestamp, confidence, snr_db, power_dbm, anomaly_score, "
                "baseline_status, has_iq_capture "
                "FROM detections WHERE anomaly_score >= 0.3 "
                "ORDER BY timestamp DESC LIMIT 100000"
            ).fetchall()
            if rows:
                anomaly_dicts = []
                for r in rows:
                    d = dict(r)
                    d["priority"] = AnomalyScorer._priority_label(
                        d.get("anomaly_score", 0)
                    )
                    if rf_scorer:
                        try:
                            result = rf_scorer.score(d)
                            d["dimensions"] = result.dimensions
                            d["reasons"] = result.reasons
                            d["priority"] = result.priority
                        except Exception:
                            pass
                    anomaly_dicts.append(d)
                detection_store.insert_rf_anomalies_batch(anomaly_dicts)
                logger.info(
                    "Backfilled %d RF anomalies from detections table",
                    len(rows),
                )
    except Exception as exc:
        logger.warning("Failed to backfill RF anomalies: %s", exc)

    # -- Notification manager (webhooks) ------------------------------------
    retry_store = WebhookRetryStore(
        detection_store._ctx, max_entries=_retry_queue_max()
    )
    notifier = NotificationManager(
        retry_store=retry_store,
        current_webhooks=persistence.current_webhooks,
    )
    notifier.load(
        persistence.initialize_webhooks(
            allow_empty=not retry_store.snapshot()["entries"]
        )
    )

    # -- Syslog forwarder ---------------------------------------------------
    from sigrift.bridge.syslog_forwarder import SyslogForwarder

    syslog_forwarder = SyslogForwarder()
    syslog_forwarder.load(persistence.get_syslog_targets())

    # -- Load detection config and apply to scorers -------------------------
    detection_config = persistence.get_detection_config()
    wifi_weights = detection_config.get("wifi_dimension_weights")
    if wifi_weights and isinstance(wifi_weights, dict):
        wifi_scorer.update_weights(wifi_weights)
    rf_weights = detection_config.get("rf_dimension_weights")
    if rf_weights and isinstance(rf_weights, dict):
        rf_scorer.update_weights(rf_weights)

    # -- Seed default alert rules if none exist ------------------------------
    from sigrift.bridge.alert_engine import seed_default_rules

    seeded = seed_default_rules(persistence)
    if seeded:
        logger.info("Seeded %d default alert rules", seeded)

    # -- Store on app.state for dependency injection ------------------------
    app.state.persistence = persistence
    app.state.app_state = app_state
    app.state.ws_limiter = ws_limiter
    app_state.ws_limiter = ws_limiter
    app.state.detection_store = detection_store
    app.state.write_queue = write_queue
    app.state.iq_store = iq_store
    app.state.iq_metadata_store = iq_metadata_store
    # Cross-process claims for post-ingest work (ingest hook, decode jobs,
    # manual capture classes; contract K8b), in detections.db.
    from sigrift.bridge.storage.ingest_claims import IngestClaimStore

    app.state.ingest_claims = IngestClaimStore(detection_store._ctx)
    app.state.fingerprint_store = fingerprint_store
    app.state.signature_library_store = signature_library_store
    app.state.incident_store = incident_store
    app.state.sweep_store = sweep_store
    app.state.wifi_cluster_store = wifi_cluster_store
    app.state.bitstream_store = bitstream_store
    app.state.preamble_store = preamble_store
    app.state.packet_store = packet_store
    app.state.fuzz_session_store = fuzz_session_store
    app.state.crypto_key_store = crypto_key_store
    app.state.crypto_key_vault = crypto_key_vault
    app.state.geolocation_store = geolocation_store
    app.state.map_store = map_store
    app.state.emitter_tracker = emitter_tracker
    app.state.track_store = track_store
    app.state.fingerprint_service = fingerprint_service
    app.state.job_queue = job_queue
    app.state.decoded_message_store = decoded_message_store
    app.state.pcap_store = pcap_store
    app.state.wifi_scorer = wifi_scorer
    app.state.wifi_baseline_mgr = wifi_baseline_mgr
    app.state.bt_scorer = bt_scorer
    app.state.bt_baseline_mgr = bt_baseline_mgr
    app.state.rf_scorer = rf_scorer
    app.state.rf_baseline_mgr = rf_baseline_mgr
    # Baseline file paths (consumed by the bundle export/import endpoints so
    # they read/write exactly the files the lifespan loads and autosaves).
    app.state.rf_baselines_path = rf_baselines_path
    app.state.wifi_baselines_path = wifi_baselines_path
    app.state.bt_baselines_path = bt_baselines_path

    # -- Spectrum materializer (P3-11, periodic refresh of materialized view) -
    materializer = SpectrumMaterializer(detection_store._ctx)
    materializer.create_table()
    _bg_tasks_enabled = os.environ.get(
        "BRIDGE_BACKGROUND_TASKS", "true"
    ).lower() not in ("0", "false", "no", "disabled")
    # Each periodic task exists only when background tasks are enabled;
    # shutdown cancels the ones that do.
    materializer_task: asyncio.Task | None = None
    cleanup_task: asyncio.Task | None = None
    stale_resolve_task: asyncio.Task | None = None
    daily_snap_task: asyncio.Task | None = None
    wal_task: asyncio.Task | None = None
    reaper_task: asyncio.Task | None = None
    _materializer_interval = int(
        os.environ.get("BRIDGE_MATERIALIZER_INTERVAL", "300")
    )  # default 5min (was 60s)
    if _bg_tasks_enabled:
        materializer._interval = _materializer_interval
        materializer_task = asyncio.create_task(materializer.start_periodic())
        materializer._task = materializer_task
        logger.info(
            "Spectrum materializer started (interval=%ds)", _materializer_interval
        )
    else:
        logger.info("Spectrum materializer DISABLED (BRIDGE_BACKGROUND_TASKS=disabled)")
    app.state.materializer = materializer

    # -- Drift detector (P3-6) ---------------------------------------------
    drift_detector = DriftDetector()
    app.state.drift_detector = drift_detector
    logger.info("Drift detector initialized")

    # -- Score calibrator (P3-9) -------------------------------------------
    score_calibrator = ScoreCalibrator()
    app.state.score_calibrator = score_calibrator
    logger.info("Score calibrator initialized")

    # -- Quantile tracker (P0-2) -------------------------------------------
    app.state.quantile_tracker = QuantileTracker()
    logger.info("Quantile tracker initialized")

    # -- Scoring evaluator (P0-2) ------------------------------------------
    app.state.scoring_evaluator = ScoringEvaluator()
    logger.info("Scoring evaluator initialized")

    # -- RF signal whitelist (known-signal false-positive reduction) ----------
    signal_whitelist = SignalWhitelist()
    _wl_path = str(Path(__file__).resolve().parent / "data" / "signal_whitelist.json")
    try:
        signal_whitelist.load(_wl_path)
    except Exception as exc:
        logger.warning("Failed to load signal whitelist: %s", exc)
    app.state.signal_whitelist = signal_whitelist
    app.state.signal_whitelist_path = _wl_path

    correlator = NodeCorrelator()
    # Set initial active node count from persisted nodes
    all_nodes = persistence.get_nodes()
    active_count = sum(
        1
        for n in all_nodes.values()
        if AppState.get_node_status(n) in (NodeStatus.active, NodeStatus.stale)
    )
    correlator.set_active_node_count(max(1, active_count))
    app.state.correlator = correlator
    app.state.notifier = notifier
    # Failed webhook deliveries are retried in the background with
    # exponential backoff (stopped on shutdown below).
    notifier.start_retry_loop()

    # -- Cross-correlator (SDR <-> protocol scanner correlation) ------------
    from sigrift.bridge.correlation_engine import CrossCorrelator

    cross_correlator = CrossCorrelator(detection_store._ctx)
    app.state.cross_correlator = cross_correlator
    logger.info("Cross-correlator initialized")

    # -- TDOA engine + correlator integration --------------------------------
    from sigrift.providers.registry import get_geo_provider
    from sigrift.providers.adapters import (
        detections_to_observations,
        geo_estimate_to_tdoa_dict,
    )

    geo_provider = get_geo_provider("tdoa", config={"coordinate_mode": "2d"})
    app.state.geo_provider = geo_provider
    app.state.tdoa_engine = geo_provider  # backward compat

    def _tdoa_callback(cluster_detections: list) -> None:
        """Called by correlator when 3+ nodes detect same signal within 100ms."""
        try:
            nodes_data = persistence.get_nodes()
            positions: dict[str, dict[str, float]] = {}
            has_geo = False
            for nid, data in nodes_data.items():
                if isinstance(data, dict):
                    # Read through the stored-value checks: one record saved
                    # with a bad position must not stop TDOA for every node.
                    location = stored_location(data)
                    x_m = stored_number(data.get("position_x"))
                    y_m = stored_number(data.get("position_y"))
                    if location is not None:
                        positions[nid] = {
                            "lat": float(location["latitude"]),
                            "lon": float(location["longitude"]),
                        }
                        has_geo = True
                    elif (
                        not ("latitude" in data and "longitude" in data)
                        and x_m is not None
                        and y_m is not None
                    ):
                        positions[nid] = {"x_m": float(x_m), "y_m": float(y_m)}

            if len(positions) < 3:
                return

            config = {"coordinate_mode": "geo" if has_geo else "2d"}
            provider = get_geo_provider("tdoa", config=config)
            observations = detections_to_observations(cluster_detections, positions)
            estimate = provider.estimate(observations)

            if estimate.confidence > 0:
                tdoa_dict = geo_estimate_to_tdoa_dict(estimate)
                detection_store.store_tdoa_estimate(tdoa_dict)
                logger.info(
                    "TDOA estimate stored: %s (confidence=%.2f)",
                    tdoa_dict.get("estimate_id", "?"),
                    estimate.confidence,
                )
        except Exception as exc:
            logger.warning("Geo auto-callback error: %s", exc)

    correlator.set_tdoa_callback(_tdoa_callback)
    # -- Spectrum streamer (rtl_tcp proxy) -----------------------------------
    from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer

    spectrum_streamer = SpectrumStreamer()
    app.state.spectrum_streamer = spectrum_streamer
    from sigrift.bridge.routers.spectrum import _NodeSpectrumPoller

    app.state.spectrum_poller = _NodeSpectrumPoller()

    app.state.syslog_forwarder = syslog_forwarder
    # Also store on app_state so detection alert dispatch can access it
    app_state._syslog_forwarder = syslog_forwarder
    app.state.detection_config = detection_config
    # Also store on app_state for _maybe_create_wifi_alert compatibility
    app_state._detection_config = detection_config

    # -- Ensure master key is present and synced ------------------------------
    key_store = persistence.get_key_store()
    env_key = os.environ.get("BRIDGE_MASTER_KEY", "").strip()
    _is_production = os.environ.get("BRIDGE_ENV", "").strip().lower() == "production"

    if _is_production and not env_key:
        raise RuntimeError(
            "BRIDGE_MASTER_KEY env var is required when BRIDGE_ENV=production. "
            "Set it to a strong random string (e.g. python -c "
            '"import secrets; print(secrets.token_urlsafe(32))")'
        )
    _warn_if_short_env_key("BRIDGE_MASTER_KEY", env_key)

    local_node_key = os.environ.get("BRIDGE_LOCAL_NODE_KEY", "").strip()
    _warn_if_short_env_key("BRIDGE_LOCAL_NODE_KEY", local_node_key)
    if local_node_key and env_key and local_node_key == env_key:
        # The privileged in-stack scanner containers would hold the admin
        # key, and one credential cannot be registered as two keys.
        raise RuntimeError(
            "BRIDGE_LOCAL_NODE_KEY must differ from BRIDGE_MASTER_KEY — set "
            "it to a new random value (python3 -c 'import secrets; "
            "print(secrets.token_urlsafe(32))')"
        )

    if not key_store:
        # First run: no keys at all — generate or use env var
        try:
            raw_key = env_key if env_key else generate_api_key()
            hash_hex, salt = hash_credential(raw_key)
            persistence.set_key(
                "master", hash_hex, salt, lookup_hash=compute_lookup_hash(raw_key)
            )
            if env_key:
                logger.info("Master key loaded from BRIDGE_MASTER_KEY env var")
            else:
                key_file = Path(__file__).parent / "data" / "master_key.txt"
                key_file.parent.mkdir(parents=True, exist_ok=True)
                key_file.write_text(raw_key)
                key_file.chmod(0o600)
                logger.warning(
                    "No API keys found. Generated initial master key written to %s. "
                    "Set BRIDGE_MASTER_KEY env var in production.",
                    key_file,
                )
        except KeyStoreWriteError as exc:
            # keys.json cannot be written: refuse to start rather than run
            # with a master key no other worker, the gateway or the next
            # start knows.
            _log_unwritable_key_store(persistence, "the initial master key", exc)
            raise
        except (ValueError, OSError) as exc:
            logger.error("Failed to generate initial master key: %s", exc)
    elif "master" in key_store and env_key:
        # Verify env var is in sync with key store (and indexed)
        try:
            _index_master_key(persistence, env_key, local_node_key)
        except KeyStoreWriteError as exc:
            _log_unwritable_key_store(persistence, "BRIDGE_MASTER_KEY", exc)
            raise

    # -- In-stack edge / scanner key (BRIDGE_LOCAL_NODE_KEY) ----------------
    # Lets the edge and scanner containers in the same compose stack
    # authenticate to the bridge without an out-of-band API-key minting
    # step: the same value is passed to them via env, so their heartbeats
    # land on first boot.  Registered once, under LOCAL_SCANNER_KEY_ID
    # ("local-edge"), with role NODE (cannot perform admin or analyst
    # operations).  The dashboard onboarding banner uses the presence of
    # this key (via /api/status's local_scanner_key_registered flag) to
    # distinguish "no scanners present" from "scanners registered but no
    # heartbeat yet".
    _drop_legacy_local_edge_key(persistence, local_node_key)
    if local_node_key:
        # The compose `edge` service ships with MLRF_NODE_ID defaulting
        # to "local-edge"; same default here, overridable via
        # BRIDGE_LOCAL_NODE_ID. The key is bound to this node (K4).
        local_node_id = os.environ.get("BRIDGE_LOCAL_NODE_ID", "local-edge").strip()
        try:
            _seed_local_scanner_key(persistence, local_node_key, local_node_id)
        except KeyStoreWriteError as exc:
            _log_unwritable_key_store(persistence, "BRIDGE_LOCAL_NODE_KEY", exc)
            raise

        # Pre-register the matching node entry so the edge agent's
        # first heartbeat is accepted (the /api/nodes/heartbeat handler
        # 404s on unregistered nodes). Idempotent — only creates the row
        # if absent, never overwrites an operator-edited entry.
        if local_node_id and local_node_id not in persistence.get_nodes():
            now_iso = datetime.now(timezone.utc).isoformat()
            persistence.set_node(
                local_node_id,
                {
                    "host": "edge",
                    "port": 0,
                    "capabilities": {"source": "in-stack edge container"},
                    "registered_at": now_iso,
                    "last_seen": now_iso,
                },
            )
            logger.info("Pre-registered in-stack edge node: %s", local_node_id)

    # -- Seed default admin user if users table is empty --------------------
    _admin_pw_file: Path | None = None
    try:
        if detection_store.users.user_count() == 0:
            admin_user = os.environ.get("BRIDGE_ADMIN_USER", "admin").strip()
            admin_pass = os.environ.get("BRIDGE_ADMIN_PASSWORD", "").strip()
            # When the operator explicitly supplied a password via env
            # var, we trust it: no forced rotation on first login. When
            # the bridge auto-generates one (dev installs that didn't
            # set the env var), we write it to a 0600 file and flag
            # the account so the next login is scoped to change-password
            # only — picking the password out of the file once doesn't
            # mean the operator has rotated it into their own memory.
            must_change_on_first_login = False
            if not admin_pass:
                if _is_production:
                    # Not logged and swallowed below: refuse to start.
                    raise _RefuseToStart(
                        "BRIDGE_ADMIN_PASSWORD env var is required when "
                        "BRIDGE_ENV=production and no users exist."
                    )
                admin_pass = generate_api_key(length=16)
                must_change_on_first_login = True
                # SEC-M18: Write password to temp file, auto-deleted after 60s.
                # Intentionally written to /tmp (container-local tmpfs), NOT
                # to _data_dir — the data dir is a shared docker volume that
                # the gateway container also mounts. Putting the admin
                # password there creates a cross-container read path if the
                # gateway process is ever compromised. /tmp is per-container.
                import tempfile as _tempfile

                _admin_pw_file = Path(_tempfile.gettempdir()) / "sigrift-admin-pw"
                try:
                    _write_owner_only_file(
                        _admin_pw_file,
                        f"username: {admin_user}\npassword: {admin_pass}\n",
                    )
                except OSError as _pw_err:
                    logger.warning("Could not write admin password file: %s", _pw_err)
                    _admin_pw_file = None
                logger.warning(
                    "No users found. Created default admin user '%s'. "
                    "Password written to %s inside the bridge container "
                    "(auto-deletes in 60s; run `docker compose exec bridge cat %s` "
                    "to read it). First login will be forced to change the "
                    "password. Set BRIDGE_ADMIN_PASSWORD env var to skip this "
                    "flow entirely.",
                    admin_user,
                    _admin_pw_file,
                    _admin_pw_file,
                )
            else:
                logger.info(
                    "Created default admin user '%s' from env vars.",
                    admin_user,
                )
            detection_store.create_user(
                username=admin_user,
                password=admin_pass,
                role="admin",
                display_name="Administrator",
                must_change_password=must_change_on_first_login,
            )
    except _RefuseToStart:
        raise
    except Exception as exc:
        logger.warning("Failed to seed default admin user: %s", exc)

    # -- MFA encryption key check (fail-fast in production) -----------------
    from sigrift.bridge.storage.users import _get_fernet

    try:
        _get_fernet()
    except RuntimeError:
        # _get_fernet raises RuntimeError in production when BRIDGE_MFA_KEY
        # is missing.  Re-raise so the service refuses to start.
        raise

    # -- Background cleanup task --------------------------------------------
    retention_days = int(os.environ.get("BRIDGE_RETENTION_DAYS", "90"))
    logger.info(
        "Data retention policy: %d days (BRIDGE_RETENTION_DAYS)", retention_days
    )

    _cleanup_interval = int(
        os.environ.get("BRIDGE_CLEANUP_INTERVAL", "1800")
    )  # default 30min (was 15min)

    async def _periodic_cleanup():
        """Run DB cleanup periodically to prevent WAL bloat.

        Interval controlled by BRIDGE_CLEANUP_INTERVAL env (seconds, default 1800).
        """
        while True:
            await asyncio.sleep(_cleanup_interval)
            # First, and on its own: a failing cleanup step below never
            # skips it (a kept .pre-migration copy is database-sized).
            await _sweep_migration_leftovers(detection_store)
            job = app_state.start_job("scheduled_full_cleanup", trigger="scheduled")
            try:
                # 1. Aggregate wifi_metadata rows >30min old into hourly buckets
                aggregated = await asyncio.to_thread(
                    detection_store.aggregate_wifi_hourly, 1
                )
                # 2. Purge raw wifi_metadata >1h (safe — already aggregated)
                deleted_meta = await asyncio.to_thread(
                    detection_store.cleanup_wifi_metadata, 1
                )
                deleted_anomalies = await asyncio.to_thread(
                    detection_store.cleanup_wifi_anomalies, retention_days
                )
                deleted_detections = await asyncio.to_thread(
                    detection_store.cleanup, retention_days
                )
                deleted_rf_anomalies = await asyncio.to_thread(
                    detection_store.cleanup_rf_anomalies, retention_days
                )
                # 2b. Auto-resolve RF anomalies absorbed into baseline
                try:
                    resolved_rf = await asyncio.to_thread(
                        detection_store.auto_resolve_baseline_anomalies, 0.4, 5
                    )
                    if resolved_rf:
                        logger.info(
                            "Auto-resolved %d baseline RF anomalies", resolved_rf
                        )
                except Exception as exc:
                    logger.debug("RF auto-resolve skipped: %s", exc)
                # 3. Purge hourly summaries >retention_days
                deleted_hourly = await asyncio.to_thread(
                    detection_store.cleanup_wifi_hourly, retention_days
                )
                # 3b. Prune spectrum_materialized (the largest table on disk;
                # it grows unbounded without this — staging accumulated 26M
                # rows / ~7GB before the first manual cleanup, 2026-06-10).
                _spec_max_age = int(
                    os.environ.get(
                        "BRIDGE_SPECTRUM_RETENTION_DAYS",
                        os.environ.get("BRIDGE_RETENTION_DAYS", "90"),
                    )
                )
                deleted_spec_mat = 0
                try:
                    deleted_spec_mat = await materializer.cleanup_old(_spec_max_age)
                except Exception as spec_exc:
                    logger.debug("spectrum_materialized cleanup skipped: %s", spec_exc)
                # 4. Compact dismissed WiFi anomalies (keep only most recent per BSSID)
                compacted_wifi = await asyncio.to_thread(
                    detection_store.compact_dismissed_wifi_anomalies
                )
                # 5. BT: aggregate raw -> hourly summaries, then purge raw
                # (mirrors WiFi at #1+#2). Without aggregate_bt_hourly the
                # bt_devices_hourly table never gets populated, raw rows
                # are deleted at 4h via cleanup_bt_devices, and read
                # queries that merge raw + hourly see only the raw side.
                aggregated_bt = 0
                deleted_bt_devices = 0
                deleted_bt_hourly = 0
                deleted_bt_anomalies = 0
                try:
                    aggregated_bt = await asyncio.to_thread(
                        detection_store.aggregate_bt_hourly, 2
                    )
                    deleted_bt_devices = await asyncio.to_thread(
                        detection_store.cleanup_bt_devices, 4
                    )
                    deleted_bt_hourly = await asyncio.to_thread(
                        detection_store.cleanup_bt_hourly, retention_days
                    )
                    deleted_bt_anomalies = await asyncio.to_thread(
                        detection_store.cleanup_bt_anomalies, retention_days
                    )
                except Exception as bt_exc:
                    logger.debug(
                        "BT cleanup skipped (tables may not exist): %s", bt_exc
                    )
                # 6. Zigbee: aggregate raw -> hourly summaries, then purge raw
                # (same fix as BT — both stores have aggregate methods that
                # were never wired into the periodic cleanup loop).
                aggregated_zb = 0
                deleted_zb_devices = 0
                deleted_zb_hourly = 0
                try:
                    aggregated_zb = await asyncio.to_thread(
                        detection_store.aggregate_zigbee_hourly, 2
                    )
                    deleted_zb_devices = await asyncio.to_thread(
                        detection_store.cleanup_zigbee_devices, 4
                    )
                    deleted_zb_hourly = await asyncio.to_thread(
                        detection_store.cleanup_zigbee_hourly, retention_days
                    )
                except Exception as zb_exc:
                    logger.debug(
                        "Zigbee cleanup skipped (tables may not exist): %s", zb_exc
                    )
                # 7. Cleanup old config snapshots
                deleted_config_snapshots = 0
                try:
                    from sigrift.bridge.persistence import PersistenceManager

                    conn_snap = detection_store.get_connection()
                    deleted_config_snapshots = PersistenceManager.cleanup_old_snapshots(
                        conn_snap, retention_days=retention_days
                    )
                except Exception as snap_exc:
                    logger.debug("Config snapshot cleanup skipped: %s", snap_exc)
                # 8. Cleanup security state (rate limits, lockouts, OIDC, TOTP)
                security_cleanup = {}
                try:
                    security_cleanup = await asyncio.to_thread(
                        detection_store.security_state.cleanup_all
                    )
                    logger.info(
                        "Security state cleanup: %s",
                        ", ".join(f"{k}={v}" for k, v in security_cleanup.items()),
                    )
                except Exception as sec_exc:
                    logger.debug("Security state cleanup skipped: %s", sec_exc)
                # 9. Detection summary rollup from raw (for non-summarizing nodes)
                det_summary_rollup = 0
                try:
                    _det_summary_store = getattr(
                        detection_store, "_detection_summaries", None
                    )
                    if _det_summary_store is not None:
                        det_summary_rollup = await asyncio.to_thread(
                            _det_summary_store.rollup_from_raw, 2
                        )
                except Exception as exc:
                    logger.debug("Detection summary rollup skipped: %s", exc)
                # 10. IQ session rollup
                iq_session_rollup = 0
                try:
                    _iq_store = iq_metadata_store
                    if _iq_store is not None:
                        iq_session_rollup = await asyncio.to_thread(
                            _iq_store.rollup_to_sessions, 1
                        )
                        await asyncio.to_thread(
                            _iq_store.cleanup_sessioned_metadata, 24
                        )
                except Exception as exc:
                    logger.debug("IQ session rollup skipped: %s", exc)
                # 11. FHSS dedup
                fhss_dedup_count = 0
                try:
                    _fhss_store = getattr(detection_store, "_fhss", None)
                    if _fhss_store is not None:
                        fhss_dedup_count = await asyncio.to_thread(
                            _fhss_store.dedup_to_summaries, 1
                        )
                        await asyncio.to_thread(_fhss_store.cleanup_raw_fhss, 7)
                        await asyncio.to_thread(_fhss_store.cleanup_fhss_summaries, 90)
                except Exception as exc:
                    logger.debug("FHSS dedup skipped: %s", exc)
                # 12. Device lifecycle daily rollup
                device_lifecycle_count = 0
                try:
                    _lifecycle_store = getattr(
                        detection_store, "_device_lifecycle", None
                    )
                    if _lifecycle_store is not None:
                        rollup = await asyncio.to_thread(
                            _lifecycle_store.run_daily_rollup
                        )
                        device_lifecycle_count = sum(rollup.values())
                        await asyncio.to_thread(
                            _lifecycle_store.archive_old_devices, 7, 7
                        )
                        await asyncio.to_thread(_lifecycle_store.cleanup_lifecycles, 90)
                except Exception as exc:
                    logger.debug("Device lifecycle rollup skipped: %s", exc)
                result = {
                    "aggregated_wifi_hourly": aggregated,
                    "deleted_wifi_metadata": deleted_meta,
                    "deleted_wifi_anomalies": deleted_anomalies,
                    "deleted_detections": deleted_detections,
                    "deleted_rf_anomalies": deleted_rf_anomalies,
                    "deleted_wifi_hourly": deleted_hourly,
                    "deleted_spectrum_materialized": deleted_spec_mat,
                    "compacted_wifi_dismissed": compacted_wifi,
                    "aggregated_bt_hourly": aggregated_bt,
                    "deleted_bt_devices": deleted_bt_devices,
                    "deleted_bt_hourly": deleted_bt_hourly,
                    "deleted_bt_anomalies": deleted_bt_anomalies,
                    "aggregated_zb_hourly": aggregated_zb,
                    "deleted_zb_devices": deleted_zb_devices,
                    "deleted_zb_hourly": deleted_zb_hourly,
                    "deleted_config_snapshots": deleted_config_snapshots,
                    "security_state": security_cleanup,
                    "det_summary_rollup": det_summary_rollup,
                    "iq_session_rollup": iq_session_rollup,
                    "fhss_dedup": fhss_dedup_count,
                    "device_lifecycle": device_lifecycle_count,
                }
                app_state.finish_job(job, result=result)
                logger.info(
                    "Periodic cleanup: aggregated %d wifi hourly, "
                    "%d wifi_metadata, %d wifi_anomalies, "
                    "%d rf_anomalies, %d detections, "
                    "%d wifi_hourly removed, %d wifi dismissed compacted",
                    aggregated,
                    deleted_meta,
                    deleted_anomalies,
                    deleted_rf_anomalies,
                    deleted_detections,
                    deleted_hourly,
                    compacted_wifi,
                )
            except Exception as exc:
                app_state.finish_job(job, error=str(exc))
                logger.warning("Periodic cleanup failed: %s", exc)

    if _bg_tasks_enabled:
        cleanup_task = asyncio.create_task(_periodic_cleanup())
        app.state._cleanup_task = cleanup_task
        logger.info("Periodic cleanup started (interval=%ds)", _cleanup_interval)
    else:
        logger.info("Periodic cleanup DISABLED")

    # -- Cross-correlation maintenance (every 6 hours) ---------------------
    async def _periodic_correlation_maintenance():
        """Prune cross-correlations every 6 hours."""
        while True:
            await asyncio.sleep(6 * 3600)
            try:
                _corr_store = getattr(detection_store, "_correlation_maintenance", None)
                if _corr_store is not None:
                    result = await asyncio.to_thread(
                        _corr_store.run_maintenance, 30, 0.3
                    )
                    logger.info("Correlation maintenance: %s", result)
            except Exception as exc:
                logger.debug("Correlation maintenance failed: %s", exc)

    if _bg_tasks_enabled:
        corr_maint_task = asyncio.create_task(_periodic_correlation_maintenance())
        app.state._corr_maint_task = corr_maint_task

    # -- Stale RF anomaly auto-resolution -----------------------------------
    _stale_resolve_interval = int(
        os.environ.get("BRIDGE_STALE_RESOLVE_INTERVAL", "600")
    )  # default 10min (was 5min)

    async def _resolve_stale_rf_anomalies():
        """Mark stale RF anomalies as 'stale-resolved' based on config."""
        while True:
            await asyncio.sleep(_stale_resolve_interval)
            try:
                det_cfg = persistence.get_detection_config()
                max_hours = float(det_cfg.get("rf_auto_snooze_hours", 24))
                max_score = float(det_cfg.get("rf_auto_snooze_max_score", 0.5))
                min_seen = int(det_cfg.get("rf_auto_snooze_seen_count", 100))
                count = await asyncio.to_thread(
                    detection_store.resolve_stale_anomalies,
                    max_age_hours=max_hours,
                    max_score=max_score,
                    min_seen_count=min_seen,
                )
                if count:
                    logger.info("Auto-resolved %d stale RF anomalies", count)
            except Exception as exc:
                logger.warning("Stale RF anomaly resolution failed: %s", exc)

    if _bg_tasks_enabled:
        stale_resolve_task = asyncio.create_task(_resolve_stale_rf_anomalies())
        app.state._stale_resolve_task = stale_resolve_task

    # -- Daily config snapshot ------------------------------------------------
    async def _daily_config_snapshot():
        """Create a daily config snapshot every 24 hours."""
        while True:
            await asyncio.sleep(86400)  # 24 hours
            try:
                conn = detection_store.get_connection()
                persistence.create_config_snapshot(
                    "daily",
                    "automatic daily snapshot",
                    db_conn=conn,
                )
            except Exception as exc:
                logger.warning("Daily config snapshot failed: %s", exc)

    if _bg_tasks_enabled:
        daily_snap_task = asyncio.create_task(_daily_config_snapshot())
        app.state._daily_snap_task = daily_snap_task

    # -- Periodic baseline autosave (crash safety) ---------------------------
    # The bridge otherwise saves learned baselines only at graceful shutdown
    # (see the shutdown block below), so a SIGKILL/OOM/power-loss drops all
    # learning since boot. A dirty-flag autosave bounds that loss to one
    # interval. The edge-side DetectionReporter already does this at 300s.
    _baseline_save_interval = int(
        os.environ.get("BRIDGE_BASELINE_SAVE_INTERVAL", "900")
    )  # 15 min; 0 disables

    async def _periodic_baseline_save():
        """Persist dirty baseline managers every BRIDGE_BASELINE_SAVE_INTERVAL."""
        # Jitter the first tick so this never phase-locks with the daily
        # snapshot or the WAL checkpoint loop.
        await asyncio.sleep(_baseline_save_interval * random.uniform(0.9, 1.1))
        while True:
            try:
                if rf_baseline_mgr.dirty:
                    await asyncio.to_thread(rf_baseline_mgr.save, rf_baselines_path)
                if wifi_baseline_mgr.dirty:
                    await asyncio.to_thread(wifi_baseline_mgr.save, wifi_baselines_path)
                if bt_baseline_mgr.dirty:
                    # prune() was previously never called anywhere, so the BT
                    # baseline file grew unbounded with transient (often
                    # randomized) MACs. Prune stale devices before each save.
                    pruned = await asyncio.to_thread(bt_baseline_mgr.prune)
                    if pruned:
                        logger.info(
                            "BT baseline prune removed %d stale devices", pruned
                        )
                    await asyncio.to_thread(bt_baseline_mgr.save, bt_baselines_path)
            except Exception as exc:
                logger.warning("Periodic baseline save failed: %s", exc)
            await asyncio.sleep(_baseline_save_interval)

    baseline_save_task = None
    if _bg_tasks_enabled and _baseline_save_interval > 0:
        baseline_save_task = asyncio.create_task(_periodic_baseline_save())
        app.state._baseline_save_task = baseline_save_task

    # -- WAL checkpoint (TRUNCATE mode) -------------------------------------
    # Delegated to SharedContext.schedule_wal_checkpoint, which runs
    # PRAGMA wal_checkpoint(TRUNCATE) on the interval. The previous
    # inline implementation here ran PASSIVE — that mode merges WAL
    # frames into the main DB but never truncates the file, so the WAL
    # grew unbounded once any reader pinned a snapshot. A 2026-06-02
    # production WAL hit 18.8 GB before we noticed because the inline
    # task also logged failures at DEBUG (silent in INFO logs).
    _wal_interval = float(
        os.environ.get("BRIDGE_WAL_CHECKPOINT_INTERVAL", "300")
    )  # default 5min

    if _bg_tasks_enabled:
        wal_task = detection_store._ctx.schedule_wal_checkpoint(
            interval_seconds=_wal_interval
        )
        app.state._wal_task = wal_task

    # -- Command lease reaper -----------------------------------------------
    async def _periodic_command_reaper():
        """Remove pending commands whose lease has expired."""
        while True:
            await asyncio.sleep(60)
            try:
                reaped = nodes._reap_expired_commands(app_state)
                if reaped:
                    logger.info("Command reaper: removed %d expired commands", reaped)
            except Exception as exc:
                logger.warning("Command reaper failed: %s", exc)

    if _bg_tasks_enabled:
        reaper_task = asyncio.create_task(_periodic_command_reaper())
        app.state._reaper_task = reaper_task

    # SEC-H2: CRITICAL log on startup if TOTP secrets unencrypted
    if mfa_key_problem():
        logger.critical(
            "TOTP secrets stored with base64 encoding only (NOT encrypted). "
            "Set BRIDGE_MFA_KEY to a valid Fernet key for production use."
        )
    # SEC-H6 / P0-1: DAR status
    from sigrift.bridge.storage.encryption import encryption_status

    _enc = encryption_status()
    if _enc["enabled"]:
        logger.info(
            "SQLCipher encryption ACTIVE (version=%s, kdf_iter=%s)",
            _enc.get("sqlcipher_version", "unknown"),
            _enc.get("kdf_iter"),
        )
    elif not os.environ.get("BRIDGE_ENCRYPTION_KEY", "").strip():
        logger.warning(
            "No data-at-rest encryption configured. Set BRIDGE_DB_ENCRYPTION_KEY "
            "for SQLCipher, or use LUKS/dm-crypt and set BRIDGE_ENCRYPTION_KEY."
        )

    # SEC-M18: Schedule auto-deletion of admin password file after 60 seconds
    _admin_pw_task: asyncio.Task | None = None
    if _admin_pw_file is not None:

        async def _delete_admin_pw_file() -> None:
            await asyncio.sleep(60)
            try:
                pw_path = _admin_pw_file  # type: ignore[union-attr]
                if pw_path.exists():
                    pw_path.unlink()
                    logger.info("SEC-M18: Admin password file auto-deleted after 60s")
            except OSError as exc:
                logger.warning("Failed to auto-delete admin password file: %s", exc)

        _admin_pw_task = asyncio.create_task(_delete_admin_pw_file())
        logger.warning(
            "SEC-M18: Admin password file %s will be auto-deleted in 60 seconds",
            _admin_pw_file,
        )

    logger.info("SigRift bridge started")

    yield

    # Cancel admin password cleanup task if still running
    if _admin_pw_task is not None:
        _admin_pw_task.cancel()
        try:
            await _admin_pw_task
        except asyncio.CancelledError:
            pass
        # Ensure file is removed on shutdown regardless
        if _admin_pw_file is not None and _admin_pw_file.exists():
            try:
                _admin_pw_file.unlink()
                logger.info("SEC-M18: Admin password file removed on shutdown")
            except OSError:
                pass

    # Stop spectrum materializer
    materializer.stop()

    # None for the tasks BRIDGE_BACKGROUND_TASKS=false never started.
    _all_bg_tasks = [
        _task
        for _task in (
            cleanup_task,
            stale_resolve_task,
            wal_task,
            daily_snap_task,
            reaper_task,
            materializer_task,
            getattr(app.state, "_corr_maint_task", None),
            baseline_save_task,
        )
        if _task is not None
    ]
    for _task in _all_bg_tasks:
        _task.cancel()
    await asyncio.gather(*_all_bg_tasks, return_exceptions=True)

    # -- Shutdown -----------------------------------------------------------
    # The final persistence save (nodes, alerts, history) comes before
    # every bounded wait below (job threads up to BRIDGE_JOB_STOP_TIMEOUT_S,
    # the write-queue flush up to 10 s, worker threads up to
    # BRIDGE_SHUTDOWN_THREAD_WAIT_S): a container runtime's stop grace
    # period (Docker: 10 s by default) may run out during them.
    try:
        await persistence.stop_auto_save()
    except Exception as exc:
        logger.warning("Failed to stop persistence auto-save: %s", exc)

    try:
        await notifier.stop_retry_loop()
    except Exception as exc:
        logger.warning("Failed to stop webhook retry loop: %s", exc)
    # Webhook / syslog deliveries of alerts created by requests run in the
    # background (contract K8b): give them a moment, then cancel the rest.
    try:
        await notifier.stop_deliveries()
        await syslog_forwarder.stop_forwards()
    except Exception as exc:
        logger.warning("Failed to stop background alert deliveries: %s", exc)

    # Stop analysis job queue
    try:
        await job_queue.stop()
    except Exception as exc:
        logger.warning("Failed to stop job queue: %s", exc)

    # Disconnect spectrum streamer + poller
    try:
        await spectrum_streamer.disconnect()
    except Exception as exc:
        logger.warning("Failed to disconnect spectrum streamer: %s", exc)
    try:
        await app.state.spectrum_poller.disconnect()
    except Exception as exc:
        logger.warning("Failed to disconnect spectrum poller: %s", exc)

    # Close syslog connections
    try:
        syslog_forwarder.close_all()
    except Exception as exc:
        logger.warning("Failed to close syslog connections: %s", exc)

    try:
        wifi_baseline_mgr.save(wifi_baselines_path)
    except Exception as exc:
        logger.warning("Failed to save WiFi baselines: %s", exc)
    try:
        bt_baseline_mgr.save(bt_baselines_path)
    except Exception as exc:
        logger.warning("Failed to save BT baselines: %s", exc)
    try:
        rf_baseline_mgr.save(rf_baselines_path)
    except Exception as exc:
        logger.warning("Failed to save RF baselines: %s", exc)
    try:
        signal_whitelist.save(_wl_path)
    except Exception as exc:
        logger.warning("Failed to save signal whitelist: %s", exc)

    # Drain write queue before closing store.
    try:
        await write_queue.stop()
    except Exception as exc:
        logger.warning("Failed to stop write queue: %s", exc)

    # Core resources — always close, even if earlier cleanup steps failed.
    # Save what job handlers and the write-queue flush changed since the
    # final save (only changed files are written).
    try:
        await persistence.async_save_all()
    except Exception as exc:
        logger.warning("Failed to save persistence state: %s", exc)
    # Cancelled background tasks may still have a worker thread stepping a
    # statement: give them a bounded moment.  (close() never closes a
    # connection a live thread owns, so a thread still running afterwards
    # is safe; it only keeps its connection until it exits.)
    from sigrift.bridge.job_queue import env_int
    from sigrift.bridge.worker_threads import wait_until_idle

    try:
        await wait_until_idle(
            worker_executor,
            float(env_int("BRIDGE_SHUTDOWN_THREAD_WAIT_S", 5, minimum=0)),
        )
    except Exception as exc:
        logger.warning("Failed to wait for worker threads: %s", exc)
    try:
        detection_store.close()
    except Exception as exc:
        logger.warning("Failed to close detection store: %s", exc)
    logger.info("SigRift bridge stopped")


# ---------------------------------------------------------------------------
# Application assembly helpers
# ---------------------------------------------------------------------------


def _register_middleware(app: FastAPI) -> None:
    """Register all middleware layers on the application.

    Order matters: middleware added last runs first (outermost).
    GZip is outermost so it compresses after all other processing.
    CombinedMiddleware handles security headers, request size limits,
    API version checks, request logging, and upperCrust proxying.
    CORS is added only when BRIDGE_CORS_ORIGINS is configured.
    """
    from starlette.middleware.gzip import GZipMiddleware

    app.add_middleware(CombinedMiddleware)
    app.add_middleware(GZipMiddleware, minimum_size=500)

    cors_origins = os.environ.get("BRIDGE_CORS_ORIGINS", "")
    if cors_origins:
        from starlette.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=[o.strip() for o in cors_origins.split(",")],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )


def _mount_routers(app: FastAPI) -> None:
    """Mount API routers onto the application.

    Routers are grouped by domain.  Within the detections group,
    ``detections.router`` is mounted last because its ``/{detection_id}``
    catch-all must not shadow named routes above it.
    """

    def _include(router_module, module_name: str, **kwargs) -> None:
        app.include_router(router_module.router, **kwargs)

    # Prometheus metrics at /metrics (root, standard convention — separate from /api/metrics JSON)
    _include(metrics, "metrics", tags=["metrics"])

    # Gateway-only internal routes (contracts K7 / K8): X-Rust-Proxy only.
    _include(
        internal,
        "internal",
        prefix="/api/internal",
        tags=["internal"],
        include_in_schema=False,
    )

    # Health
    _include(health, "health", prefix="/api", tags=["health"])

    # Nodes
    _include(deployment, "deployment", prefix="/api/nodes", tags=["nodes"])
    _include(nodes, "nodes", prefix="/api/nodes", tags=["nodes"])

    # Edge-agent onboarding — serves the host install script at
    # /api/edge/install.sh unauthenticated (script itself has no
    # secrets; caller must supply --api-key at runtime).
    _include(edge, "edge", prefix="/api/edge", tags=["edge"])

    # Detections (named routes first, catch-all last)
    _include(
        detection_analytics,
        "detection_analytics",
        prefix="/api/detections",
        tags=["detections"],
    )
    _include(
        detection_audit,
        "detection_audit",
        prefix="/api/detections",
        tags=["detections"],
    )
    _include(
        detection_iq, "detection_iq", prefix="/api/detections", tags=["detections"]
    )
    _include(correlation, "correlation", prefix="/api/detections", tags=["detections"])
    _include(detections, "detections", prefix="/api/detections", tags=["detections"])

    # Auth and keys
    _include(auth, "auth", prefix="/api", tags=["auth"])
    # MFA is served by the Rust gateway only.  routers/mfa.py is NOT
    # mounted, and must not be: its verify / disable / regenerate handlers
    # lack the gateway's per-user attempt limit and atomic TOTP replay
    # claim, and a request the gateway routes past its own handlers (e.g. a
    # percent-encoded path) would reach them.
    # tests/bridge/test_round4_br1.py checks that no /api/auth/mfa/* route
    # is served here.
    # OIDC/SSO router lives in sigrift-sentinel; community builds expose
    # local password/MFA auth only.
    try:
        from sigrift_sentinel.routers import oidc as _oidc_router

        _include(_oidc_router, "oidc", prefix="/api", tags=["auth", "oidc"])
    except ImportError:
        logger.debug("sigrift-sentinel not installed — /api/oidc not mounted")
    _include(keys, "keys", prefix="/api/keys", tags=["keys"])
    _include(ca, "ca", prefix="/api/ca", tags=["ca"])

    # Export and reports
    _include(export, "export", prefix="/api/export", tags=["export"])
    _include(reports, "reports", prefix="/api/reports", tags=["reports"])

    # Protocol-specific
    _include(wifi, "wifi", prefix="/api/wifi", tags=["wifi"])
    _include(
        wifi_fingerprint,
        "wifi_fingerprint",
        prefix="/api/wifi",
        tags=["wifi", "fingerprint"],
    )
    _include(bluetooth, "bluetooth", prefix="/api/bluetooth", tags=["bluetooth"])
    _include(zigbee, "zigbee", prefix="/api/zigbee", tags=["zigbee"])
    _include(aircraft, "aircraft", prefix="/api/aircraft", tags=["aircraft"])
    _include(signals, "signals", prefix="/api/signals", tags=["signals"])
    _include(alerts, "alerts", prefix="/api/alerts", tags=["alerts"])
    _include(incidents, "incidents", prefix="/api/incidents", tags=["incidents"])
    _include(sweeps, "sweeps", prefix="/api/sweeps", tags=["sweeps"])

    # Admin
    _include(admin, "admin", prefix="/api/admin", tags=["admin"])
    _include(maintenance, "maintenance", prefix="/api/admin", tags=["admin"])
    _include(system_config, "system_config", prefix="/api/admin", tags=["admin"])
    _include(
        webhook_management, "webhook_management", prefix="/api/admin", tags=["admin"]
    )

    # Spectrum and training
    _include(spectrum, "spectrum", prefix="/api/spectrum", tags=["spectrum"])
    _include(training, "training", prefix="/api/training", tags=["training"])

    # Geolocation and mapping
    _include(geo, "geo", prefix="/api/geo", tags=["geo"])
    _include(emitters, "emitters", prefix="/api", tags=["emitters"])
    # TDOA router hasn't been ported to the community tree yet; mount
    # only if the module is present. Community builds return 404 on
    # /api/tdoa until then.
    try:
        from sigrift.bridge.routers import tdoa as _tdoa_router

        _include(_tdoa_router, "tdoa", prefix="/api/tdoa", tags=["tdoa"])
    except ImportError:
        logger.debug("tdoa router not available — /api/tdoa not mounted")
    _include(
        geolocation, "geolocation", prefix="/api/geolocation", tags=["geolocation"]
    )
    _include(maps, "maps", prefix="/api/maps", tags=["maps"])
    _include(mbtiles, "mbtiles", prefix="/api/maps", tags=["maps", "mbtiles"])

    # IQ data and analysis
    _include(iq_metadata, "iq_metadata", prefix="/api/iq", tags=["iq"])
    _include(jobs, "jobs", prefix="/api/jobs", tags=["jobs"])
    # Fingerprints router lives in sigrift-sentinel; mount only when the
    # package is installed. Community builds return 404 on /api/fingerprints.
    try:
        from sigrift_sentinel.routers import fingerprints as _fp_router

        _include(
            _fp_router,
            "fingerprints",
            prefix="/api/fingerprints",
            tags=["fingerprints"],
        )
    except ImportError:
        logger.debug("sigrift-sentinel not installed — /api/fingerprints not mounted")
    _include(
        signature_library,
        "signature_library",
        prefix="/api/signatures",
        tags=["signatures"],
    )

    # RF reversing
    _include(bitstreams, "bitstreams", prefix="/api/bitstreams", tags=["bitstreams"])
    _include(preambles, "preambles", prefix="/api/preambles", tags=["preambles"])
    _include(packets, "packets", prefix="/api/packets", tags=["packets"])

    # Crypto
    _include(crypto, "crypto", prefix="/api/crypto", tags=["crypto"])
    # Fuzzing router lives in sigrift-sentinel; mount only when the
    # package is installed. Community builds return 404 on /api/fuzzing.
    try:
        from sigrift_sentinel.routers import fuzzing as _fuzz_router

        _include(_fuzz_router, "fuzzing", prefix="/api/fuzzing", tags=["fuzzing"])
    except ImportError:
        logger.debug("sigrift-sentinel not installed — /api/fuzzing not mounted")

    # Edge and tracking
    _include(clusters, "clusters", prefix="/api/clusters", tags=["clusters"])
    _include(
        edge_models, "edge_models", prefix="/api/edge-models", tags=["edge-models"]
    )
    _include(tracking, "tracking", prefix="/api/tracking", tags=["tracking"])

    # STIX/TAXII router lives in sigrift-sentinel; community builds
    # do not expose /api/stix. Threat-intel consumers can still export
    # signatures via /api/signatures.
    try:
        from sigrift_sentinel.routers import stix as _stix_router

        _include(_stix_router, "stix", prefix="/api/stix", tags=["stix"])
    except ImportError:
        logger.debug("sigrift-sentinel not installed — /api/stix not mounted")


def _mount_static_and_templates(app: FastAPI) -> None:
    """Mount static file serving and register HTML template routes.

    Static files are served from ``/static`` and templates provide the
    dashboard UI at ``/``, ``/login``, ``/admin``, and ``/documentation/``.
    """
    if _STATIC_DIR.is_dir():
        from fastapi.staticfiles import StaticFiles

        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
        logger.info("Static files mounted from %s", _STATIC_DIR)

    if _TEMPLATES_DIR.is_dir():
        from fastapi.responses import HTMLResponse
        from fastapi.templating import Jinja2Templates

        _templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

        @app.get("/login", response_class=HTMLResponse, include_in_schema=False)
        async def login_page(request: Request) -> HTMLResponse:
            """Serve the standalone login page."""
            return _templates.TemplateResponse(request, "login.html")

        @app.get("/", include_in_schema=False)
        async def index(request: Request) -> RedirectResponse:
            """Redirect root: /dashboard if authenticated, /login otherwise.

            Without this check the dashboard's "home" links bounce the
            user back to the login page even with a valid session — see
            the `_try_session_auth` helper in `dependencies.py` for the
            auth lookup it shares with the FastAPI deps.
            """
            from sigrift.bridge.dependencies import _try_session_auth

            username, _ = _try_session_auth(request)
            return RedirectResponse(url="/dashboard" if username else "/login")

        @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard(request: Request) -> HTMLResponse:
            """Serve the Bridge dashboard index page."""
            return _templates.TemplateResponse(request, "index.html")

        @app.get("/admin", response_class=HTMLResponse, include_in_schema=False)
        async def admin_page(request: Request) -> HTMLResponse:
            """Serve the admin panel page."""
            return _templates.TemplateResponse(request, "admin.html")

        @app.get(
            "/documentation/", response_class=HTMLResponse, include_in_schema=False
        )
        async def docs_index(request: Request) -> HTMLResponse:
            """Serve the operator documentation index page."""
            return HTMLResponse(
                "<!DOCTYPE html><html lang=en><head><meta charset=UTF-8>"
                "<meta name=viewport content='width=device-width,initial-scale=1'>"
                "<title>Documentation — SigRift</title>"
                "<style>"
                ":root{--bg:#0d1117;--bg-card:#161b22;--border:#30363d;--text:#c9d1d9;"
                "--text-secondary:#8b949e;--accent:#58a6ff;--accent-hover:#79c0ff}"
                "*{margin:0;padding:0;box-sizing:border-box}"
                "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;"
                "background:var(--bg);color:var(--text);line-height:1.6;display:flex;"
                "justify-content:center;padding:80px 20px}"
                "a{color:var(--accent);text-decoration:none}"
                "a:hover{color:var(--accent-hover);text-decoration:underline}"
                ".container{max-width:640px;width:100%}"
                "h1{font-size:28px;margin-bottom:8px}"
                ".subtitle{color:var(--text-secondary);margin-bottom:32px;font-size:15px}"
                ".card{background:var(--bg-card);border:1px solid var(--border);"
                "border-radius:8px;padding:20px 24px;margin-bottom:16px;display:block;"
                "text-decoration:none!important;transition:border-color .15s}"
                ".card:hover{border-color:var(--accent)}"
                ".card h2{font-size:18px;color:var(--text);margin-bottom:6px}"
                ".card p{font-size:13px;color:var(--text-secondary);margin:0}"
                ".back{display:inline-block;margin-top:24px;font-size:13px;"
                "color:var(--text-secondary)}"
                "</style></head><body><div class=container>"
                "<h1>SigRift Documentation</h1>"
                "<p class=subtitle>v4.0.0 — Operator reference and guides</p>"
                "<a href='/static/docs/operations_guide.html' class=card>"
                "<h2>Operations Guide</h2>"
                "<p>System architecture, detection workflows, background tasks, "
                "security configuration, troubleshooting, and maintenance.</p></a>"
                "<a href='/static/docs/api_reference.html' class=card>"
                "<h2>API Reference</h2>"
                "<p>Complete REST and WebSocket API documentation with endpoint details, "
                "parameters, authentication, and examples.</p></a>"
                "<a href='/static/docs/deployment_guide.html' class=card>"
                "<h2>Deployment Guide</h2>"
                "<p>Installation, environment configuration, TLS setup, reverse proxy, "
                "systemd service, and upgrade procedures.</p></a>"
                "<a href='/' class=back>&larr; Back to Dashboard</a>"
                "</div></body></html>"
            )

        @app.get(
            "/documentation/{page}",
            response_class=HTMLResponse,
            include_in_schema=False,
        )
        async def docs_page(page: str) -> HTMLResponse:
            """Serve a specific documentation page."""
            from fastapi.responses import RedirectResponse

            allowed = {
                "api_reference.html",
                "deployment_guide.html",
                "operations_guide.html",
            }
            if page not in allowed:
                from fastapi.responses import PlainTextResponse

                return PlainTextResponse("Not found", status_code=404)
            return RedirectResponse(url=f"/static/docs/{page}")


# ---------------------------------------------------------------------------
# Test app factory
# ---------------------------------------------------------------------------


def create_test_app(
    tmp_path: Path,
    detection_store: DetectionStore | None = None,
    persistence: PersistenceManager | None = None,
    app_state: AppState | None = None,
    master_key: str | None = None,
) -> FastAPI:
    """Build a fully wired Bridge app for testing without lifespan side effects.

    Uses the same ``_register_middleware`` and ``_mount_routers`` helpers as the
    production app so routers, middleware, and mount order stay in sync.
    """
    # Fingerprint service + store live in sigrift-sentinel. Community
    # installs don't have sentinel, so the test-app factory skips the
    # fingerprint wiring cleanly.
    try:
        from sigrift_sentinel.fingerprint.service import FingerprintService
        from sigrift_sentinel.storage.fingerprints import FingerprintStore

        _sentinel_fingerprint_available = True
    except ImportError:
        FingerprintService = None  # type: ignore[assignment]
        FingerprintStore = None  # type: ignore[assignment]
        _sentinel_fingerprint_available = False

    from sigrift.bridge.job_queue import AnalysisJobQueue
    from sigrift.bridge.syslog_forwarder import SyslogForwarder
    from sigrift.bridge.storage.bitstreams import BitstreamStore
    from sigrift.bridge.storage.geolocation import GeolocationStore
    from sigrift.bridge.storage.iq_metadata import IQMetadataStore
    from sigrift.bridge.storage.maps import MapStore
    from sigrift.bridge.storage.packets import PacketStore
    from sigrift.bridge.storage.preambles import PreambleStore
    from sigrift.bridge.storage.signature_library import SignatureLibraryStore
    from sigrift.bridge.storage.tracks import TrackStore
    from sigrift.providers.registry import get_geo_provider
    from sigrift.lib.dsp.emitter_tracker import EmitterTracker
    from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer
    from sigrift.bridge.routers.spectrum import _NodeSpectrumPoller

    # -- Defaults for optional arguments ------------------------------------
    if detection_store is None:
        detection_store = DetectionStore(db_path=tmp_path / "test_detections.db")
    if persistence is None:
        persistence = PersistenceManager(
            data_dir=tmp_path / "data", auto_save_interval=0
        )
        persistence.load_all()
    if app_state is None:
        app_state = AppState()
    if master_key is None:
        master_key = generate_api_key(length=32)

    # Register master key
    hash_hex, salt = hash_credential(master_key)
    persistence.set_key("master", hash_hex, salt)

    # -- Build the FastAPI app (no lifespan — tests manage lifecycle) --------
    test_app = FastAPI()

    _register_middleware(test_app)
    install_validation_handler(test_app)
    _mount_routers(test_app)
    # Skip _mount_static_and_templates — tests don't need static files

    # -- Rate limiter (permissive for tests) --------------------------------
    limiter = RateLimiter(max_requests=1000, window_seconds=60.0)
    set_rate_limiter(limiter)

    ws_limiter = WSConnectionLimiter(max_concurrent=10, max_per_minute=30)
    set_ws_limiter(ws_limiter)

    # -- Wire up app.state identically to production lifespan ---------------
    test_app.state.persistence = persistence
    test_app.state.app_state = app_state
    test_app.state.detection_store = detection_store
    test_app.state.write_queue = WriteQueue(
        detection_store, batch_size=10, flush_interval_ms=100
    )
    test_app.state.ws_limiter = ws_limiter
    app_state.ws_limiter = ws_limiter

    # Stores backed by the same SharedContext as detection_store
    ctx = detection_store._ctx
    iq_store = IQStore(base_dir=tmp_path / "iq_captures")
    iq_metadata_store = IQMetadataStore(ctx)
    fingerprint_store = (
        FingerprintStore(ctx) if _sentinel_fingerprint_available else None
    )
    bitstream_store = BitstreamStore(ctx)
    preamble_store = PreambleStore(ctx)
    signature_library_store = SignatureLibraryStore(ctx)
    if hasattr(signature_library_store, "seed_threat_signatures"):
        signature_library_store.seed_threat_signatures()

    from sigrift.bridge.storage.incidents import IncidentStore

    incident_store = IncidentStore(ctx)

    from sigrift.bridge.storage.sweeps import SweepStore

    sweep_store = SweepStore(ctx)

    from sigrift.bridge.storage.wifi_device_clusters import WiFiDeviceClusterStore

    wifi_cluster_store = WiFiDeviceClusterStore(ctx)

    packet_store = PacketStore(ctx)

    # FuzzSessionStore lives in sigrift-sentinel. Community test-apps
    # (no sentinel installed) run without it.
    try:
        from sigrift_sentinel.storage.fuzz_sessions import FuzzSessionStore

        fuzz_session_store = FuzzSessionStore(ctx)
    except ImportError:
        fuzz_session_store = None

    geolocation_store = GeolocationStore(ctx)
    map_store = MapStore(ctx)
    track_store = TrackStore(ctx)

    test_app.state.iq_store = iq_store
    from sigrift.bridge.storage.decoded_messages import DecodedMessageStore

    test_app.state.decoded_message_store = DecodedMessageStore(ctx)
    test_app.state.iq_metadata_store = iq_metadata_store
    from sigrift.bridge.storage.ingest_claims import IngestClaimStore

    test_app.state.ingest_claims = IngestClaimStore(ctx)
    test_app.state.fingerprint_store = fingerprint_store
    test_app.state.bitstream_store = bitstream_store
    test_app.state.preamble_store = preamble_store
    test_app.state.signature_library_store = signature_library_store
    test_app.state.incident_store = incident_store
    test_app.state.sweep_store = sweep_store
    test_app.state.wifi_cluster_store = wifi_cluster_store
    test_app.state.packet_store = packet_store
    test_app.state.fuzz_session_store = fuzz_session_store
    from sigrift.bridge.storage.crypto_keys import init_crypto_keys

    # The test app keeps imported keys in memory only, as before, whatever
    # the developer's shell exports (tests that persist pass their own env).
    _crypto_key_store, _crypto_key_vault = init_crypto_keys(ctx, {})
    test_app.state.crypto_key_store = _crypto_key_store
    test_app.state.crypto_key_vault = _crypto_key_vault
    test_app.state.geolocation_store = geolocation_store
    test_app.state.map_store = map_store
    test_app.state.floor_plan_dir = str(tmp_path / "floor_plans")
    test_app.state.emitter_tracker = EmitterTracker()
    test_app.state.track_store = track_store
    test_app.state.pcap_store = PcapStore(base_dir=tmp_path / "pcap_captures")

    # Anomaly scorers and baselines
    wifi_baseline_mgr = WifiBaselineManager()
    test_app.state.wifi_scorer = WifiAnomalyScorer(wifi_baseline_mgr)
    test_app.state.wifi_baseline_mgr = wifi_baseline_mgr

    rf_baseline_mgr = BaselineManager()
    test_app.state.rf_scorer = AnomalyScorer(rf_baseline_mgr)
    test_app.state.rf_baseline_mgr = rf_baseline_mgr

    bt_baseline_mgr = BtBaselineManager()
    test_app.state.bt_scorer = BtAnomalyScorer(bt_baseline_mgr)
    test_app.state.bt_baseline_mgr = bt_baseline_mgr

    # Baseline paths + signal whitelist under the test data dir so the bundle
    # export/import endpoints read/write into tmp_path, never the package dir.
    from sigrift.bridge.anomaly.whitelist import SignalWhitelist

    _test_data = tmp_path / "data"
    _test_data.mkdir(parents=True, exist_ok=True)
    test_app.state.rf_baselines_path = str(_test_data / "baselines.json")
    test_app.state.wifi_baselines_path = str(_test_data / "wifi_baselines.json")
    test_app.state.bt_baselines_path = str(_test_data / "bt_baselines.json")
    test_app.state.signal_whitelist = SignalWhitelist()
    test_app.state.signal_whitelist_path = str(_test_data / "signal_whitelist.json")

    test_app.state.correlator = NodeCorrelator()

    # Cross-correlator (SDR <-> protocol scanner correlation)
    from sigrift.bridge.correlation_engine import CrossCorrelator

    test_app.state.cross_correlator = CrossCorrelator(ctx)

    # Drift detector and score calibrator (wired into ingest + feedback paths)
    test_app.state.drift_detector = DriftDetector()
    test_app.state.score_calibrator = ScoreCalibrator()
    test_app.state.quantile_tracker = QuantileTracker()
    test_app.state.scoring_evaluator = ScoringEvaluator()

    # Spectrum materializer (table only, no periodic task in tests)
    test_materializer = SpectrumMaterializer(ctx)
    test_materializer.create_table()
    test_app.state.materializer = test_materializer

    # Notification manager
    retry_store = WebhookRetryStore(
        detection_store._ctx, max_entries=_retry_queue_max()
    )
    notifier = NotificationManager(
        retry_store=retry_store,
        current_webhooks=persistence.current_webhooks,
    )
    notifier.load(
        persistence.initialize_webhooks(
            allow_empty=not retry_store.snapshot()["entries"]
        )
    )
    test_app.state.notifier = notifier

    # Syslog forwarder
    syslog_forwarder = SyslogForwarder()
    syslog_forwarder.load(persistence.get_syslog_targets())
    test_app.state.syslog_forwarder = syslog_forwarder
    app_state._syslog_forwarder = syslog_forwarder

    # Detection config
    detection_config = persistence.get_detection_config()
    test_app.state.detection_config = detection_config
    app_state._detection_config = detection_config

    # Fingerprint service (sentinel plugin) — only wired when sentinel
    # is installed. Community test-app instances have no fingerprint
    # service; tests that need it should install sigrift-sentinel.
    if _sentinel_fingerprint_available:
        fingerprint_service = FingerprintService(
            fingerprint_store=fingerprint_store,
            iq_store=iq_store,
            model_path=None,
        )
    else:
        fingerprint_service = None
    test_app.state.fingerprint_service = fingerprint_service

    # TDOA engine (via provider registry)
    test_app.state.geo_provider = get_geo_provider(
        "tdoa", config={"coordinate_mode": "2d"}
    )
    test_app.state.tdoa_engine = test_app.state.geo_provider

    # Family classifier (not loaded in tests)
    test_app.state.family_classifier = None

    # Job queue (not started — tests that need it manage lifecycle)
    job_queue = AnalysisJobQueue(max_workers=2, max_queue_size=100)
    test_app.state.job_queue = job_queue

    # Spectrum streamer + HTTP poller
    test_app.state.spectrum_streamer = SpectrumStreamer()
    test_app.state.spectrum_poller = _NodeSpectrumPoller()

    return test_app


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SigRift Bridge — Detection Backend",
    version=__version__,
    lifespan=lifespan,
    # No generated documentation pages: Swagger UI and ReDoc load their
    # script from a CDN (and /docs runs an inline one), which the CSP
    # (script-src 'self') refuses, so they rendered blank. /openapi.json
    # stays; static/docs/api_reference.html documents the API.
    docs_url=None,
    redoc_url=None,
)

_register_middleware(app)
# A 422 that echoes a NaN / Infinity input is not a 500.
install_validation_handler(app)
_mount_routers(app)
_mount_static_and_templates(app)
