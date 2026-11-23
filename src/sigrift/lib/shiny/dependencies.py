"""FastAPI dependency injection for the Shiny dashboard.

Provides authentication, roles, rate limiting, configuration injection,
and WebSocket auth helpers.  All auth flows use
``sigrift.lib.security.credentials`` for constant-time credential
verification.

Keys carry a role (``viewer`` < ``analyst`` < ``admin``, the bridge's
:class:`~sigrift.bridge.dependencies.Role` names and values) and an
optional ``expires_at``, both stored with the key in ``keys.json``. The
``master`` key is always ``admin``; a key stored without a role (created
before roles existed) is a ``viewer``. Expired keys -- and keys whose
expiry cannot be parsed -- are rejected everywhere.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any
from urllib.parse import unquote_plus

from fastapi import (
    Depends,
    Header,
    HTTPException,
    Request,
    WebSocket,
    WebSocketException,
    status,
)

from sigrift.lib.config import MLRFConfig, load_config
from sigrift.lib.security.credentials import verify_credential

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Roles and key validity
# ---------------------------------------------------------------------------


class Role(IntEnum):
    """Key roles, ascending. Same names/values as the bridge's Role."""

    VIEWER = 2
    ANALYST = 3
    ADMIN = 4


MASTER_KEY_ID = "master"
# Role of a key stored without one (keys.json from before roles existed).
DEFAULT_ROLE = Role.VIEWER


class KeyRejected(Exception):
    """A known key that must not be accepted (expired, unknown role)."""


def key_role(key_id: str, meta: dict[str, Any]) -> Role:
    """Role of *key_id* from its stored metadata.

    Raises KeyRejected for a role name this service does not know: failing
    closed beats guessing a privilege level.
    """
    if key_id == MASTER_KEY_ID:
        return Role.ADMIN
    name = meta.get("role")
    if name is None:
        return DEFAULT_ROLE
    try:
        return Role[str(name).upper()]
    except KeyError:
        raise KeyRejected(f"API key has an unknown role {name!r}") from None


def key_expired(meta: dict[str, Any], now: datetime | None = None) -> bool:
    """True when *meta* has an ``expires_at`` in the past or unparseable."""
    raw = meta.get("expires_at")
    if raw in (None, ""):
        return False
    try:
        expires = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires <= (now or datetime.now(timezone.utc))


def check_key(persistence: Any, key_id: str) -> tuple[Role, dict[str, Any]]:
    """Validate an authenticated *key_id*: (role, metadata) or KeyRejected."""
    meta = persistence.get_key_meta(key_id)
    if key_expired(meta):
        raise KeyRejected("API key expired")
    return key_role(key_id, meta), meta


# ---------------------------------------------------------------------------
# Configuration dependency
# ---------------------------------------------------------------------------

_config_singleton: MLRFConfig | None = None


def get_config() -> MLRFConfig:
    """Return the shared ``MLRFConfig`` instance.

    Loads from YAML on first call, then returns the cached instance.

    Returns
    -------
    MLRFConfig
        Application configuration.
    """
    global _config_singleton
    if _config_singleton is None:
        _config_singleton = load_config()
    return _config_singleton


def set_config(config: MLRFConfig) -> None:
    """Override the cached config (useful for testing).

    Parameters
    ----------
    config : MLRFConfig
        Config to inject.
    """
    global _config_singleton
    _config_singleton = config


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Sliding-window rate limiter with per-client tracking.

    Parameters
    ----------
    max_requests : int
        Maximum requests allowed within ``window_seconds``.
    window_seconds : float
        Length of the sliding window in seconds.
    max_keys : int
        Maximum number of tracked client keys.  Prevents unbounded
        memory growth from a large number of distinct clients.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60.0,
        max_keys: int = 10_000,
    ) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300.0

    # -- internal helpers ---------------------------------------------------

    def _cleanup_stale(self) -> None:
        """Remove client keys with no recent activity."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self.window_seconds
        stale = [k for k, ts in self._requests.items() if not ts or ts[-1] < cutoff]
        for k in stale:
            del self._requests[k]

        # If still over budget, evict oldest
        if len(self._requests) > self.max_keys:
            by_recency = sorted(
                self._requests,
                key=lambda k: self._requests[k][-1] if self._requests[k] else 0.0,
            )
            for k in by_recency[: len(self._requests) - self.max_keys]:
                del self._requests[k]

        self._last_cleanup = now

    def _prune_window(self, key: str) -> None:
        """Remove timestamps outside the current window for *key*."""
        cutoff = time.monotonic() - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    # -- public API ---------------------------------------------------------

    def check(self, key: str) -> tuple[bool, int]:
        """Check whether *key* is within its rate limit.

        Does **not** record a request.

        Parameters
        ----------
        key : str
            Client identifier (e.g. key_id or IP).

        Returns
        -------
        tuple of (bool, int)
            ``(allowed, retry_after_seconds)``.  If allowed is ``False``,
            ``retry_after_seconds`` indicates how long the client should
            wait.
        """
        self._cleanup_stale()
        self._prune_window(key)

        if len(self._requests[key]) >= self.max_requests:
            oldest = min(self._requests[key])
            retry = int(oldest + self.window_seconds - time.monotonic()) + 1
            return False, max(retry, 1)

        return True, 0

    def record(self, key: str) -> None:
        """Record a request for *key*.

        Parameters
        ----------
        key : str
            Client identifier.
        """
        self._requests[key].append(time.monotonic())

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """Check **and** record a request for *key*.

        Parameters
        ----------
        key : str
            Client identifier.

        Returns
        -------
        tuple of (bool, int)
            ``(allowed, retry_after_seconds)``.
        """
        allowed, retry = self.check(key)
        if allowed:
            self.record(key)
        return allowed, retry

    def reset(self, key: str | None = None) -> None:
        """Clear rate-limit state.

        Parameters
        ----------
        key : str or None
            If given, clear only that client.  Otherwise clear everything.
        """
        if key is None:
            self._requests.clear()
        else:
            self._requests.pop(key, None)


# Module-level default rate limiter (replaced at app startup)
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the module-level rate limiter instance.

    Returns
    -------
    RateLimiter
        The active rate limiter.
    """
    global _rate_limiter
    if _rate_limiter is None:
        cfg = get_config()
        _rate_limiter = RateLimiter(
            max_requests=cfg.security.rate_limit_per_minute,
            window_seconds=60.0,
        )
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Override the module-level rate limiter (useful for testing).

    Parameters
    ----------
    limiter : RateLimiter
        Rate limiter to use.
    """
    global _rate_limiter
    _rate_limiter = limiter


# ---------------------------------------------------------------------------
# Fast-hash index for O(1) key candidate lookup
# ---------------------------------------------------------------------------

# Maps sha256(raw_key) -> key_id.  Populated on first successful PBKDF2
# verification so subsequent requests skip the full key-store scan.
_fast_hash_index: dict[str, str] = {}


def _compute_fast_hash(raw_key: str) -> str:
    """Return SHA-256 hex digest of *raw_key* for fast-hash indexing."""
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def clear_fast_hash_index() -> None:
    """Clear the fast-hash index (call on key add/remove/rotate)."""
    _fast_hash_index.clear()


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


def _lookup_key(
    api_key: str,
    key_store: dict[str, tuple[str, bytes]],
) -> str | None:
    """Find the key_id matching *api_key* in *key_store*.

    First checks the fast-hash index for an O(1) candidate.  If found,
    only runs PBKDF2 against that single candidate.  On miss, falls back
    to a full scan and populates the index on success.

    Parameters
    ----------
    api_key : str
        Raw API key from the client.
    key_store : dict
        Mapping of ``{key_id: (hash_hex, salt_bytes)}``.

    Returns
    -------
    str or None
        The matching ``key_id``, or ``None`` if no match.
    """
    fast_hash = _compute_fast_hash(api_key)

    # O(1) candidate from fast-hash index
    candidate_id = _fast_hash_index.get(fast_hash)
    if candidate_id is not None and candidate_id in key_store:
        expected_hash, salt = key_store[candidate_id]
        if verify_credential(api_key, expected_hash, salt):
            return candidate_id
        # Index entry stale (key was rotated); remove it
        _fast_hash_index.pop(fast_hash, None)

    # Full scan fallback
    for key_id, (expected_hash, salt) in key_store.items():
        if verify_credential(api_key, expected_hash, salt):
            _fast_hash_index[fast_hash] = key_id
            return key_id
    return None


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


async def require_api_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Dependency: extract and validate an API key.

    Accepts the key from the ``X-API-Key`` header or the ``api_key``
    query parameter.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    x_api_key : str or None
        Value of the ``X-API-Key`` header.

    Returns
    -------
    str
        Authenticated ``key_id``.

    Raises
    ------
    HTTPException
        401 if the key is missing or invalid.
    """
    api_key = x_api_key or request.query_params.get("api_key", "")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
        )

    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )

    key_store = persistence.get_key_store()
    key_id = await asyncio.to_thread(_lookup_key, api_key, key_store)
    if key_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    try:
        role, meta = check_key(persistence, key_id)
    except KeyRejected as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from None

    request.state.api_key_role = role
    request.state.api_key_meta = meta
    return key_id


async def require_master_key(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Dependency: require a master-level API key for admin endpoints.

    Checks that the key exists **and** has the ``key_id`` equal to
    ``"master"``.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    x_api_key : str or None
        Value of the ``X-API-Key`` header.

    Returns
    -------
    str
        The ``key_id`` (always ``"master"``).

    Raises
    ------
    HTTPException
        401 if missing/invalid, 403 if not master.
    """
    key_id = await require_api_key(request, x_api_key)
    if key_id != "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Master key required",
        )
    return key_id


def require_role(min_role: Role):
    """Dependency factory: rate-limited API key with at least *min_role*.

    Usage: ``_key_id: str = Depends(require_role(Role.ADMIN))``.
    """

    async def _require_role(
        request: Request,
        key_id: str = Depends(rate_limit),
    ) -> str:
        role = getattr(request.state, "api_key_role", DEFAULT_ROLE)
        if role < min_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{min_role.name.lower()} role required",
            )
        return key_id

    return _require_role


async def rate_limit(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> str:
    """Dependency: enforce sliding-window rate limiting per key.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    key_id : str
        Authenticated key id (injected by ``require_api_key``).

    Returns
    -------
    str
        The ``key_id`` (pass-through).

    Raises
    ------
    HTTPException
        429 if the client has exceeded its rate limit.
    """
    limiter = get_rate_limiter()
    allowed, retry_after = limiter.is_allowed(key_id)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )
    return key_id


async def rate_limit_sensitive(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> str:
    """Dependency: stricter rate limit for sensitive endpoints.

    Allows 10 requests per minute (vs the global default).

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    key_id : str
        Authenticated key id.

    Returns
    -------
    str
        The ``key_id`` (pass-through).

    Raises
    ------
    HTTPException
        429 if rate limit exceeded.
    """
    limiter = get_rate_limiter()
    # Use a prefixed key for the stricter bucket
    bucket = f"sensitive:{key_id}"
    # Manually check with a tighter limit
    limiter._cleanup_stale()
    limiter._prune_window(bucket)
    if len(limiter._requests[bucket]) >= 10:
        oldest = min(limiter._requests[bucket])
        retry = int(oldest + limiter.window_seconds - time.monotonic()) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for sensitive endpoint",
            headers={"Retry-After": str(max(retry, 1))},
        )
    limiter.record(bucket)
    return key_id


# ---------------------------------------------------------------------------
# WebSocket auth
# ---------------------------------------------------------------------------


WS_SUBPROTOCOL = "bridge-v1"

_ws_query_warned = False


def _ws_api_key(websocket: WebSocket) -> tuple[str, str | None]:
    """(API key, subprotocol to echo) from a WebSocket handshake.

    Sources, in order: ``Sec-WebSocket-Protocol: bridge-v1, <key>`` (what
    browsers can send; ``bridge-v1`` is echoed back), the ``X-API-Key``
    header (non-browser clients), and -- deprecated, because URLs end up in
    access logs, proxy logs and browser history -- the ``api_key`` query
    parameter.
    """
    global _ws_query_warned
    offered = websocket.headers.get("sec-websocket-protocol", "")
    if offered:
        parts = [p.strip() for p in offered.split(",")]
        for i, part in enumerate(parts[:-1]):
            if part == WS_SUBPROTOCOL and parts[i + 1]:
                return parts[i + 1], WS_SUBPROTOCOL
    header_key = websocket.headers.get("x-api-key", "")
    if header_key:
        return header_key, None
    query_key = websocket.query_params.get("api_key", "")
    if query_key and not _ws_query_warned:
        _ws_query_warned = True
        logger.warning(
            "WebSocket auth via the api_key query parameter is deprecated "
            "(URLs are logged); send 'Sec-WebSocket-Protocol: %s, <key>' or "
            "an X-API-Key header instead",
            WS_SUBPROTOCOL,
        )
    return query_key, None


async def require_ws_auth(websocket: WebSocket) -> str:
    """Validate WebSocket auth **before** ``accept()``.

    Gen2 bug: accepted the WebSocket first, then never checked auth.
    The key is taken from the ``bridge-v1`` subprotocol, the ``X-API-Key``
    header or (deprecated) the ``api_key`` query parameter, then checked
    like an HTTP key (expiry, role). On failure the handshake is refused
    with close code 4001. Accept with :func:`accept_ws` so the chosen
    subprotocol is echoed.

    Parameters
    ----------
    websocket : WebSocket
        Incoming WebSocket connection.

    Returns
    -------
    str
        Authenticated ``key_id``.

    Raises
    ------
    WebSocketException
        Code 4001 if auth fails.
    """
    api_key, subprotocol = _ws_api_key(websocket)
    if not api_key:
        raise WebSocketException(code=4001, reason="API key required")

    persistence = getattr(websocket.app.state, "persistence", None)
    if persistence is None:
        raise WebSocketException(code=4001, reason="Service not ready")

    key_store = persistence.get_key_store()
    key_id = await asyncio.to_thread(_lookup_key, api_key, key_store)
    if key_id is None:
        raise WebSocketException(code=4001, reason="Invalid API key")
    try:
        role, _meta = check_key(persistence, key_id)
    except KeyRejected as exc:
        raise WebSocketException(code=4001, reason=str(exc)) from None

    websocket.state.ws_subprotocol = subprotocol
    websocket.state.api_key_role = role
    return key_id


async def accept_ws(websocket: WebSocket) -> None:
    """Accept a WebSocket authenticated by :func:`require_ws_auth`.

    Echoes ``bridge-v1`` when the client authenticated with it; a browser
    drops a connection whose server picks none of the offered protocols.
    """
    await websocket.accept(subprotocol=getattr(websocket.state, "ws_subprotocol", None))


# ---------------------------------------------------------------------------
# Log redaction
# ---------------------------------------------------------------------------

# Match raw query fields, then decode only the name as the request parser does.
# Decoding the whole URL first would turn encoded value delimiters into fields.
_QUERY_PARAM_RE = re.compile(r"([?&]([^=&#\s\"']+)=)[^&#\s\"']*")
_QUERY_SECRET_NAMES = {"api_key", "apikey", "api-key", "key", "token", "access_token"}


def redact_query_secrets(text: str) -> str:
    """Replace credential values in URL query strings with ``[REDACTED]``."""
    return _QUERY_PARAM_RE.sub(
        lambda match: f"{match[1]}[REDACTED]"
        if unquote_plus(match[2]).lower() in _QUERY_SECRET_NAMES
        else match[0],
        text,
    )


class RedactQuerySecretsFilter(logging.Filter):
    """Logging filter that scrubs query-string credentials from records.

    uvicorn's access log (``uvicorn.access``) and its WebSocket handshake
    lines (``uvicorn.error``) include the full path with query string.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_query_secrets(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_query_secrets(a) if isinstance(a, str) else a
                for a in record.args
            )
        elif isinstance(record.args, dict):
            record.args = {
                k: redact_query_secrets(v) if isinstance(v, str) else v
                for k, v in record.args.items()
            }
        return True


_REDACTED_LOGGERS = ("uvicorn.access", "uvicorn.error", "uvicorn")


def install_log_redaction() -> None:
    """Attach :class:`RedactQuerySecretsFilter` to uvicorn's loggers (idempotent).

    Logger filters survive uvicorn's ``dictConfig`` (it replaces handlers,
    not filters), so installing this at import time is enough.
    """
    for name in _REDACTED_LOGGERS:
        lg = logging.getLogger(name)
        if not any(isinstance(f, RedactQuerySecretsFilter) for f in lg.filters):
            lg.addFilter(RedactQuerySecretsFilter())
