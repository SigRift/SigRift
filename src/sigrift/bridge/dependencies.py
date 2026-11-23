"""FastAPI dependency injection for The Bridge.

Provides authentication, rate limiting, configuration injection,
and WebSocket auth helpers.  All auth flows use
``sigrift.lib.security.credentials`` for constant-time credential verification.

Adapted from sigrift.lib.shiny.dependencies for the Bridge application.
"""

from __future__ import annotations

import asyncio
import gzip
import hmac
import ipaddress
import json
import logging
import os
import re
import socket
import threading
import time
import zlib
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, IntEnum
from functools import partial
from io import BytesIO
from typing import Any

from fastapi import (
    Depends,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketException,
    status,
)
from starlette.requests import HTTPConnection
from starlette.websockets import WebSocketDisconnect

from sigrift.bridge import WS_PROTOCOL
from sigrift.bridge.storage.encryption import database_errors
from sigrift.lib.config import MLRFConfig, load_config
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    upgrade_legacy_credential,
    verify_credential,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Request-body helpers
# ---------------------------------------------------------------------------


async def read_json_body(
    request: Request,
    *,
    max_body_bytes: int = 1_048_576,
    max_decompressed_bytes: int = 10 * 1024 * 1024,
) -> dict[str, Any]:
    """Read a JSON request body, transparently handling gzip.

    Edge scanners send ``Content-Encoding: gzip`` on their ingest POSTs.
    Starlette does not decompress request bodies (GZipMiddleware only
    compresses responses), so a route that declares a Pydantic body
    parameter hands the compressed bytes to the JSON parser and rejects
    them with a 400. Routes that accept scanner traffic must read the
    body through this helper instead. Limits and error mapping mirror
    ``POST /api/bluetooth/ingest``.
    """
    raw_body = await request.body()
    if len(raw_body) > max_body_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Request body exceeds {max_body_bytes} byte limit",
        )

    if request.headers.get("content-encoding") == "gzip":
        try:
            dec = gzip.GzipFile(fileobj=BytesIO(raw_body))
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = dec.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_decompressed_bytes:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Decompressed payload exceeds size limit",
                    )
                chunks.append(chunk)
            raw_body = b"".join(chunks)
        except HTTPException:
            raise
        except (OSError, ValueError, EOFError, zlib.error):
            # OSError covers BadGzipFile (bad magic); EOFError is a
            # truncated stream; zlib.error is corrupt deflate data after
            # a valid header. All are client-side garbage — 400, not 500.
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to decompress gzip body",
            )

    try:
        payload = json.loads(raw_body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON: {exc}",
        )
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="JSON body must be an object",
        )
    return payload


# ---------------------------------------------------------------------------
# RBAC roles
# ---------------------------------------------------------------------------


class Role(IntEnum):
    """Hierarchical roles for API key access control.

    Higher values include all permissions of lower values.
    SENSOR keys can only submit data (detections, heartbeats, IQ uploads).
    NODE keys can ingest data and read their own node status.
    VIEWER and above can read the dashboard.

    Hierarchy (ascending): SENSOR < NODE < VIEWER < ANALYST < ADMIN < KEYMASTER
    """

    SENSOR = 0
    NODE = 1
    VIEWER = 2
    ANALYST = 3
    ADMIN = 4
    KEYMASTER = 5  # reserved highest role; not used in the community build


# ---------------------------------------------------------------------------
# Configuration dependency
# ---------------------------------------------------------------------------

_config_singleton: MLRFConfig | None = None


def get_config() -> MLRFConfig:
    """Return the shared ``MLRFConfig`` instance.

    Loads from YAML on first call, then returns the cached instance.
    """
    global _config_singleton
    if _config_singleton is None:
        _config_singleton = load_config()
    return _config_singleton


def set_config(config: MLRFConfig) -> None:
    """Override the cached config (useful for testing)."""
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
        Maximum number of tracked client keys.
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

    def _cleanup_stale(self) -> None:
        """Remove client keys with no recent activity."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        cutoff = now - self.window_seconds
        stale = [k for k, ts in self._requests.items() if not ts or ts[-1] < cutoff]
        for k in stale:
            del self._requests[k]

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

    def check(self, key: str) -> tuple[bool, int]:
        """Check whether *key* is within its rate limit (does not record)."""
        self._cleanup_stale()
        self._prune_window(key)

        if len(self._requests[key]) >= self.max_requests:
            oldest = min(self._requests[key])
            retry = int(oldest + self.window_seconds - time.monotonic()) + 1
            return False, max(retry, 1)

        return True, 0

    def record(self, key: str) -> None:
        """Record a request for *key*."""
        self._requests[key].append(time.monotonic())

    def is_allowed(self, key: str) -> tuple[bool, int]:
        """Check **and** record a request for *key*."""
        allowed, retry = self.check(key)
        if allowed:
            self.record(key)
        return allowed, retry

    def reset(self, key: str | None = None) -> None:
        """Clear rate-limit state."""
        if key is None:
            self._requests.clear()
        else:
            self._requests.pop(key, None)


# Module-level default rate limiter (replaced at app startup)
_rate_limiter: RateLimiter | None = None


def get_rate_limiter() -> RateLimiter:
    """Return the module-level rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        cfg = get_config()
        _rate_limiter = RateLimiter(
            max_requests=cfg.security.rate_limit_per_minute,
            window_seconds=60.0,
        )
    return _rate_limiter


def set_rate_limiter(limiter: RateLimiter) -> None:
    """Override the module-level rate limiter (useful for testing)."""
    global _rate_limiter
    _rate_limiter = limiter


# ---------------------------------------------------------------------------
# WebSocket connection rate limiter
# ---------------------------------------------------------------------------


class WSConnectionLimiter:
    """Per-IP WebSocket connection rate limiter.

    Enforces two limits:
    - Max concurrent connections per IP
    - Max connections per minute per IP (sliding window)
    """

    def __init__(
        self,
        max_concurrent: int = 10,
        max_per_minute: int = 30,
    ) -> None:
        self.max_concurrent = max_concurrent
        self.max_per_minute = max_per_minute
        self._active: dict[str, int] = defaultdict(int)
        self._recent: dict[str, list[float]] = defaultdict(list)

    def _prune_window(self, ip: str) -> None:
        """Remove connection timestamps older than 60 seconds."""
        cutoff = time.monotonic() - 60.0
        self._recent[ip] = [t for t in self._recent[ip] if t > cutoff]

    def try_acquire(self, ip: str) -> tuple[bool, str]:
        """Attempt to acquire a WS connection slot for *ip*.

        Returns (allowed, reason). If allowed, the caller MUST call
        ``release(ip)`` when the connection closes.
        """
        # Check concurrent limit
        if self._active[ip] >= self.max_concurrent:
            return False, "Too many concurrent WebSocket connections"

        # Check per-minute limit
        self._prune_window(ip)
        if len(self._recent[ip]) >= self.max_per_minute:
            return False, "WebSocket connection rate limit exceeded"

        # Acquire
        self._active[ip] += 1
        self._recent[ip].append(time.monotonic())
        return True, ""

    def release(self, ip: str) -> None:
        """Release a WS connection slot for *ip*."""
        if self._active[ip] > 0:
            self._active[ip] -= 1
        if self._active[ip] == 0:
            self._active.pop(ip, None)


# Module-level WS connection limiter
_ws_limiter: WSConnectionLimiter | None = None


def get_ws_limiter() -> WSConnectionLimiter:
    """Return the module-level WS connection limiter instance."""
    global _ws_limiter
    if _ws_limiter is None:
        _ws_limiter = WSConnectionLimiter()
    return _ws_limiter


def set_ws_limiter(limiter: WSConnectionLimiter | None) -> None:
    """Override the module-level WS limiter (useful for testing)."""
    global _ws_limiter
    _ws_limiter = limiter


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


def key_expiry(meta: dict[str, Any]) -> datetime | None:
    """The explicit expiry auth applies to a key: aware, naive read as UTC.

    ``None`` when there is none: a missing, null or blank ``expires_at``
    is the legacy non-expiring policy.  Surrounding whitespace is ignored.
    Raises :class:`ValueError` for any other value that is not an ISO
    date-time (also a non-string), which :func:`key_expired` treats as
    expired.  The one parser for a stored expiry on the bridge: bridge auth
    and both key listings use it, so a listing cannot disagree with bridge
    auth.

    The gateway reads ``expires_at`` with its own parser (``parse_expiry``
    in ``sigrift-gateway-core/src/auth/api_key.rs``), which accepts a
    different set of shapes.  The two agree on what the bridge writes
    (``datetime.isoformat()``) but can disagree on a hand-edited value:
    ``2999-01-01T00:00`` (no seconds) or a basic-format date is accepted
    here and refused by the gateway, ``2999-01-01t00:00:00z`` (lower case)
    or a leap second the other way round.
    """
    expires_at = meta.get("expires_at")
    if expires_at is None:
        return None
    if isinstance(expires_at, str):
        expires_at = expires_at.strip()
        if not expires_at:
            return None
    try:
        exp_dt = datetime.fromisoformat(expires_at)
    except (ValueError, TypeError):
        raise ValueError("expires_at is not an ISO date-time") from None
    if exp_dt.tzinfo is None:
        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
    return exp_dt


def key_expired(meta: dict[str, Any], now: datetime | None = None) -> bool:
    """Return True for an expired or malformed explicit expiry.

    Missing/empty expiry is the legacy non-expiring policy. A non-empty
    value that cannot be parsed must fail closed, as on the gateway.
    The key stays usable up to and including its expiry instant and is
    expired once *now* (default: the current time) is past it, as on the
    gateway (``now <= expires_at`` is usable).  The key listings report
    this verdict as ``expired``; it is bridge auth's, see
    :func:`key_expiry` for where the gateway's parser differs.
    """
    try:
        exp_dt = key_expiry(meta)
    except ValueError:
        return True
    if exp_dt is None:
        return False
    return (now or datetime.now(timezone.utc)) > exp_dt


def _key_usable(meta: dict[str, Any]) -> bool:
    """Apply the persisted revocation, enabled and expiry checks on every use.

    The gateway forwards API keys to bridge-owned routes even when its
    own auth check refused them, so the bridge must independently enforce
    these flags. Missing flags retain the legacy enabled/not-revoked policy.
    """
    return (
        meta.get("revoked") is not True
        and meta.get("enabled") is not False
        and not key_expired(meta)
    )


def _resolve_key_role(
    key_id: str,
    key_meta: dict[str, dict[str, Any]] | None,
) -> tuple[str | None, Role | None]:
    """Resolve role and check usability for a matched key_id, including cache hits."""
    meta = (key_meta or {}).get(key_id, {})
    if not _key_usable(meta):
        return None, None
    # Default to viewer (least privilege); master is always admin.  The one
    # resolution role ceilings and the admin key listing use as well.
    return key_id, stored_key_role(key_id, meta)


class _VerifiedKeyCache:
    """Short-lived memo of successful PBKDF2 API-key verifications.

    Keyed by the key's SHA-256 lookup hash (the same value the fast index
    uses, so it adds no new way to match a key).  An entry only counts while
    the key store still holds the *same* ``(hash, salt)`` for that key_id:
    rotating a key (new salt) or removing it invalidates the entry on the
    next lookup, independent of the TTL. Revocation, enabled state,
    expiry and role are still re-checked from ``key_meta`` on every request.

    TTL comes from ``BRIDGE_KEY_VERIFY_CACHE_TTL`` (seconds, default 60;
    ``0`` disables the cache).
    """

    _MAX_ENTRIES = 1024

    def __init__(self) -> None:
        self._entries: dict[str, tuple[str, str, bytes, float]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _ttl() -> float:
        raw = os.environ.get("BRIDGE_KEY_VERIFY_CACHE_TTL", "").strip()
        if not raw:
            return 60.0
        try:
            return max(0.0, float(raw))
        except ValueError:
            return 60.0

    def get(
        self,
        lookup_hash: str,
        key_store: dict[str, tuple[str, bytes]],
        fast_index: dict[str, str],
    ) -> str | None:
        """Return the cached key_id for *lookup_hash* if still valid."""
        with self._lock:
            entry = self._entries.get(lookup_hash)
            if entry is None:
                return None
            key_id, expected_hash, salt, expires = entry
            # Plain equality is fine here: both sides are stored values
            # (the cached and the current key-store hash/salt); nothing the
            # client sent is compared.
            valid = (
                time.monotonic() < expires
                and fast_index.get(lookup_hash) == key_id
                and tuple(key_store.get(key_id) or ()) == (expected_hash, salt)
            )
            if not valid:
                del self._entries[lookup_hash]
                return None
            return key_id

    def put(
        self, lookup_hash: str, key_id: str, expected_hash: str, salt: bytes
    ) -> None:
        ttl = self._ttl()
        if ttl <= 0:
            return
        with self._lock:
            if len(self._entries) >= self._MAX_ENTRIES:
                self._entries.clear()
            self._entries[lookup_hash] = (
                key_id,
                expected_hash,
                salt,
                time.monotonic() + ttl,
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_verified_key_cache = _VerifiedKeyCache()


#: Most legacy keys (stored without a lookup hash) PBKDF2-checked for one
#: presented key — the gateway's ``MAX_LEGACY_SCAN``.  Keys beyond the cap
#: cannot authenticate until they are rotated (which gives them a lookup
#: hash); a warning names the problem.
MAX_LEGACY_SCAN = 16
#: Threads that run legacy scans.  They are not the default executor, so a
#: flood of unknown keys cannot starve other ``to_thread`` work (API-key
#: checks of indexed keys, logins, the detection write queue).
_LEGACY_SCAN_WORKERS = 2
#: Legacy scans running or queued at once; beyond this an unknown key is
#: rejected without PBKDF2 instead of waiting in an unbounded queue.
_LEGACY_SCAN_MAX_PENDING = 8


def _legacy_candidates(
    key_store: dict[str, tuple[str, bytes]],
    key_meta: dict[str, dict[str, Any]] | None,
    fast_index: dict[str, str],
    indexed_ids: Iterable[str] | None,
) -> list[str]:
    """Return the unindexed, usable key_ids a legacy scan may try.

    A key that has a lookup hash can only match through it, so it is never
    scanned — whether or not it currently owns the fast-index entry.  At
    most :data:`MAX_LEGACY_SCAN` ids are returned.
    """
    indexed = set(fast_index.values())
    if indexed_ids is not None:
        indexed.update(indexed_ids)
    meta = key_meta or {}
    usable = [
        kid
        for kid in key_store
        if kid not in indexed and _key_usable(meta.get(kid, {}))
    ]
    if len(usable) > MAX_LEGACY_SCAN:
        _warn_legacy_overflow(len(usable))
    return usable[:MAX_LEGACY_SCAN]


_legacy_overflow_warned = False


def _warn_legacy_overflow(count: int) -> None:
    global _legacy_overflow_warned
    if not _legacy_overflow_warned:
        _legacy_overflow_warned = True
        logger.warning(
            "%d API keys have no lookup hash; only %d are checked per "
            "request, so the rest cannot authenticate. Rotate them.",
            count,
            MAX_LEGACY_SCAN,
        )


def _scan_legacy_keys(
    api_key: str,
    key_store: dict[str, tuple[str, bytes]],
    candidates: list[str],
) -> str | None:
    """PBKDF2-check *api_key* against *candidates*; return the match."""
    for key_id in candidates:
        expected_hash, salt = key_store[key_id]
        if verify_credential(api_key, expected_hash, salt):
            return key_id
    return None


class _LegacyScanPool:
    """Bounded, dedicated thread pool for legacy-key PBKDF2 scans.

    At most :data:`_LEGACY_SCAN_WORKERS` scans run at once and at most
    :data:`_LEGACY_SCAN_MAX_PENDING` are running or queued.  A slot is
    released when the scan's future completes or is cancelled, not when
    the awaiting request goes away, so clients that disconnect cannot
    queue unbounded work.
    """

    def __init__(self, workers: int, max_pending: int) -> None:
        self._workers = workers
        self._max_pending = max_pending
        self._executor: ThreadPoolExecutor | None = None
        self._lock = threading.Lock()
        self._pending = 0
        self._last_shed_log = 0.0

    def _release(self, _future: object = None) -> None:
        with self._lock:
            self._pending -= 1

    def try_submit(self, fn: Any, *args: Any) -> Future | None:
        """Submit *fn(*args)*, or return ``None`` when the pool is full."""
        with self._lock:
            if self._pending >= self._max_pending:
                now = time.monotonic()
                if now - self._last_shed_log > 60.0:
                    self._last_shed_log = now
                    logger.warning(
                        "Legacy API-key scans saturated (%d pending): "
                        "rejecting unknown keys without PBKDF2. Rotate keys "
                        "that have no lookup hash.",
                        self._pending,
                    )
                return None
            self._pending += 1
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._workers,
                    thread_name_prefix="bridge-legacy-key-scan",
                )
            executor = self._executor
        try:
            future = executor.submit(fn, *args)
        except BaseException:
            self._release()
            raise
        future.add_done_callback(self._release)
        return future


_legacy_scan_pool = _LegacyScanPool(_LEGACY_SCAN_WORKERS, _LEGACY_SCAN_MAX_PENDING)


def _lookup_key(
    api_key: str,
    key_store: dict[str, tuple[str, bytes]],
    key_meta: dict[str, dict[str, Any]] | None = None,
    fast_index: dict[str, str] | None = None,
    indexed_ids: Iterable[str] | None = None,
) -> tuple[str | None, Role | None]:
    """Find the key_id and role matching *api_key* in *key_store*.

    Synchronous reference implementation, blocking (PBKDF2, ~600k
    iterations).  Request handlers use :func:`_lookup_key_async`, which
    applies the same steps without blocking the event loop.

    1. A recent successful verification of the same key (see
       :class:`_VerifiedKeyCache`) skips PBKDF2.
    2. The SHA-256 fast index gives the single candidate key, verified
       with PBKDF2.
    3. Only keys that have **no** lookup hash (legacy keys; *indexed_ids*
       lists the key_ids that have one, in addition to the fast index's
       values) are scanned with PBKDF2, at most :data:`MAX_LEGACY_SCAN`.
       When every key is indexed an unknown key is rejected without
       running PBKDF2 at all.

    Returns ``(key_id, role)`` or ``(None, None)`` if not found or inactive.
    """
    fast_index = fast_index or {}
    lookup_hash = compute_lookup_hash(api_key)

    cached_id = _verified_key_cache.get(lookup_hash, key_store, fast_index)
    if cached_id is not None:
        return _resolve_key_role(cached_id, key_meta)

    # Fast path: O(1) lookup via SHA-256 index
    candidate_id = fast_index.get(lookup_hash)
    if candidate_id and candidate_id in key_store:
        if not _key_usable((key_meta or {}).get(candidate_id, {})):
            return None, None
        expected_hash, salt = key_store[candidate_id]
        if verify_credential(api_key, expected_hash, salt):
            _verified_key_cache.put(lookup_hash, candidate_id, expected_hash, salt)
            return _resolve_key_role(candidate_id, key_meta)
        # Fast-hash matched but PBKDF2 didn't: the stored hash belongs to a
        # different credential (stale index entry).  The key it indexes
        # cannot match, so only the unindexed keys below remain.

    # Slow path: scan only the keys without a lookup hash.
    candidates = _legacy_candidates(key_store, key_meta, fast_index, indexed_ids)
    matched = _scan_legacy_keys(api_key, key_store, candidates)
    if matched is not None:
        return _resolve_key_role(matched, key_meta)
    return None, None


async def _lookup_key_async(
    api_key: str,
    key_store: dict[str, tuple[str, bytes]],
    key_meta: dict[str, dict[str, Any]] | None = None,
    fast_index: dict[str, str] | None = None,
    indexed_ids: Iterable[str] | None = None,
) -> tuple[str | None, Role | None]:
    """Async :func:`_lookup_key` for request handlers.

    Pass snapshots taken on the event loop.  The cache and fast-index
    checks are dict lookups and run inline, so an unknown key (no
    fast-index entry, no legacy keys) costs no PBKDF2 and no thread hop.
    PBKDF2 for an indexed candidate runs via ``asyncio.to_thread``; a
    legacy scan runs on :data:`_legacy_scan_pool` and is rejected outright
    when that pool is saturated.
    """
    fast_index = fast_index or {}
    lookup_hash = compute_lookup_hash(api_key)

    cached_id = _verified_key_cache.get(lookup_hash, key_store, fast_index)
    if cached_id is not None:
        return _resolve_key_role(cached_id, key_meta)

    candidate_id = fast_index.get(lookup_hash)
    if candidate_id and candidate_id in key_store:
        if not _key_usable((key_meta or {}).get(candidate_id, {})):
            return None, None
        expected_hash, salt = key_store[candidate_id]
        if await asyncio.to_thread(verify_credential, api_key, expected_hash, salt):
            _verified_key_cache.put(lookup_hash, candidate_id, expected_hash, salt)
            return _resolve_key_role(candidate_id, key_meta)

    candidates = _legacy_candidates(key_store, key_meta, fast_index, indexed_ids)
    if not candidates:
        return None, None
    future = _legacy_scan_pool.try_submit(
        _scan_legacy_keys, api_key, key_store, candidates
    )
    if future is None:
        return None, None
    matched = await asyncio.wrap_future(future)
    if matched is not None:
        return _resolve_key_role(matched, key_meta)
    return None, None


def _upgrade_legacy_key(
    persistence: Any, key_id: str, api_key: str, matched: tuple[str, bytes]
) -> tuple[str, bytes]:
    """Re-hash a legacy key with PBKDF2 and give it a lookup hash (blocking).

    Only replaces the credential that was matched: if the key was rotated
    or revoked meanwhile, nothing changes (a revoked key is not re-created
    and a rotated one keeps its new credential).
    """
    try:
        new_hash, new_salt, new_lookup = upgrade_legacy_credential(api_key)
        if (
            persistence.replace_key_credential(
                key_id,
                new_hash,
                new_salt,
                lookup_hash=new_lookup,
                expected=matched,
            )
            is not None
        ):
            logger.info("Auto-upgraded credential for key %s to PBKDF2", key_id)
            return new_hash, new_salt
    except Exception:
        logger.warning(
            "Failed to auto-upgrade credential for key %s", key_id, exc_info=True
        )

    return matched


def instance_tenant(conn: HTTPConnection) -> str:
    """Return the fixed store boundary, never a tenant supplied by the caller.

    Auth-only applications without a detection store use the deployment default.
    A configured store must expose a valid tenant; invalid configuration fails
    closed rather than widening access to shared instance state.
    """
    store = getattr(conn.app.state, "detection_store", None)
    tenant = "default" if store is None else getattr(store, "tenant_id", None)
    if not isinstance(tenant, str) or not tenant:
        raise RuntimeError("Invalid configured store tenant")
    return tenant


def require_instance_tenant(conn: HTTPConnection, tenant: Any) -> None:
    if not isinstance(tenant, str) or not tenant or tenant != instance_tenant(conn):
        detail = "Credential belongs to another tenant"
        if conn.scope["type"] == "websocket":
            raise WebSocketException(code=4003, reason=detail)
        raise HTTPException(status_code=403, detail=detail)


def bind_key_tenant(conn: HTTPConnection, key_id: str, key_meta: dict) -> None:
    """Bind the authenticated key's persisted scope, preserving legacy absence."""
    meta = key_meta.get(key_id, {})
    tenant = meta["tenant_id"] if "tenant_id" in meta else instance_tenant(conn)
    require_instance_tenant(conn, tenant)
    conn.state.key_tenant = tenant


async def _authenticate_api_key(
    api_key: str,
    persistence: Any,
    conn: HTTPConnection | None = None,
    *,
    upgrade_legacy: bool = True,
) -> tuple[str | None, Role | None]:
    """Authenticate against coherent snapshots before and after awaited work.

    PBKDF2 and legacy upgrades may overlap a rotation, revocation, or role/tenant
    edit. The final snapshot must still contain the exact verified credential;
    its current metadata decides authorization. No stale verdict is reused.
    """
    key_store, key_meta, fast_index, indexed_ids = await asyncio.to_thread(
        persistence.get_key_auth_snapshot
    )
    key_id, _role = await _lookup_key_async(
        api_key, key_store, key_meta, fast_index, indexed_ids
    )
    if key_id is None:
        return None, None

    async def current_role(expected: tuple[str, bytes]) -> Role | None:
        current, metadata, index, indexed = await asyncio.to_thread(
            persistence.get_key_auth_snapshot
        )
        if tuple(current.get(key_id) or ()) != expected:
            return None
        if key_id in indexed and index.get(compute_lookup_hash(api_key)) != key_id:
            return None
        current_id, role = _resolve_key_role(key_id, metadata)
        if current_id is None:
            return None
        if conn is not None:
            bind_key_tenant(conn, key_id, metadata)
        return role

    matched = tuple(key_store[key_id])
    role = await current_role(matched)
    if role is None:
        return None, None
    if upgrade_legacy and key_id not in indexed_ids:
        matched = await asyncio.to_thread(
            _upgrade_legacy_key, persistence, key_id, api_key, matched
        )
        role = await current_role(matched)
        if role is None:
            return None, None
    return key_id, role


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def _extract_session_token(request: HTTPConnection) -> str | None:
    """Extract session token from Authorization header, X-Session-Token header, or cookie.

    Works for HTTP requests and WebSocket handshakes alike.  A source that
    carries only whitespace is skipped, as the gateway skips it
    (``session_token_from_headers`` in its ``middleware/auth.rs``): an
    empty ``Authorization: Bearer`` used to hide a session in
    ``X-Session-Token`` or the cookie here while the gateway read it.  The
    shared table ``testdata/session_token_parity.json`` in the gateway
    crate pins both sides (``tests/bridge/test_session_token_parity.py``).
    """
    # Check Authorization: Bearer <token> (the scheme in any letter case)
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        bearer = auth_header[7:].strip()
        if bearer:
            return bearer
    # Check X-Session-Token header
    session_header = request.headers.get("x-session-token", "").strip()
    if session_header:
        return session_header
    # Check session_token cookie (set by the gateway; forwarded on
    # WebSocket upgrades, see contract K1)
    cookie_token = request.cookies.get("session_token", "").strip()
    if cookie_token:
        return cookie_token
    return None


# -- Session scopes ------------------------------------------------------------
#
# A session row's ``scope`` is empty for a full session.  Any other value
# restricts it (contract K3, same rules as the gateway):
#   mfa_setup_only       — MFA setup endpoints only (tenant requires MFA)
#   password_change_only — change-password only (must_change_password)
# plus, for every restricted session, "who am I" and logout.  A scope this
# code does not know fails closed the same way.

SCOPE_MFA_SETUP_ONLY = "mfa_setup_only"
SCOPE_PASSWORD_CHANGE_ONLY = "password_change_only"

#: The 403 body for a ``password_change_only`` session (contract K3).
PASSWORD_CHANGE_REQUIRED_DETAIL = "password change required"

_RESTRICTED_SESSION_PATHS = frozenset({"/api/auth/me", "/api/auth/logout"})
_PASSWORD_CHANGE_PATHS = _RESTRICTED_SESSION_PATHS | {"/api/auth/change-password"}


def session_scope_allows(scope: str, path: str) -> bool:
    """True if a session with *scope* may call the HTTP endpoint at *path*."""
    if not scope:
        return True
    if scope == SCOPE_PASSWORD_CHANGE_ONLY:
        return path in _PASSWORD_CHANGE_PATHS
    if scope == SCOPE_MFA_SETUP_ONLY:
        return path.startswith("/api/auth/mfa/") or path in _RESTRICTED_SESSION_PATHS
    return path in _RESTRICTED_SESSION_PATHS


def _scope_denied_detail(scope: str) -> str:
    if scope == SCOPE_PASSWORD_CHANGE_ONLY:
        return PASSWORD_CHANGE_REQUIRED_DETAIL
    if scope == SCOPE_MFA_SETUP_ONLY:
        return "MFA setup required before accessing other endpoints"
    return "Session is restricted and cannot access this endpoint"


def _role_from_name(name: Any) -> Role:
    """Map a stored role name to :class:`Role` (unknown → VIEWER)."""
    try:
        return Role[str(name).upper()]
    except KeyError:
        return Role.VIEWER


def _session_binding_ok(
    conn: HTTPConnection, session: dict[str, Any], token: str
) -> bool:
    """Check the session's IP / User-Agent binding for this connection.

    Session binding modes (BRIDGE_SESSION_BINDING env var):
      - "strict"  — reject if IP or User-Agent changes (strongest)
      - "ip"      — reject only on IP mismatch (UA changes allowed; default)
      - "warn"    — log warning on mismatch but allow
      - "none"    — no binding check
    """
    binding_mode = os.environ.get("BRIDGE_SESSION_BINDING", "ip").lower()
    if binding_mode == "none":
        return True
    current_ip = get_client_ip(conn)
    current_ua = conn.headers.get("user-agent", "")
    session_ip = session.get("ip_address", "")
    session_ua = session.get("user_agent", "")

    ip_mismatch = bool(session_ip) and current_ip != session_ip
    ua_mismatch = bool(session_ua) and current_ua != session_ua
    if not (ip_mismatch or ua_mismatch):
        return True

    details = []
    if ip_mismatch:
        details.append(f"IP {session_ip!r}->{current_ip!r}")
    if ua_mismatch:
        details.append("UA changed")

    if binding_mode == "strict":
        logger.warning(
            "Session %s rejected: binding mismatch (%s) for user %s",
            token[:8],
            ", ".join(details),
            session.get("username", "?"),
        )
        return False
    if binding_mode == "ip" and ip_mismatch:
        logger.warning(
            "Session %s rejected: IP mismatch (%s) for user %s",
            token[:8],
            details[0],
            session.get("username", "?"),
        )
        return False
    # "warn" mode (or a UA-only change in "ip" mode) — log but allow
    logger.info(
        "Session binding mismatch (%s) for user %s (mode=%s, allowed)",
        ", ".join(details),
        session.get("username", "?"),
        binding_mode,
    )
    return True


def resolve_session(
    conn: HTTPConnection, token: str, *, touch: bool = True
) -> tuple[dict[str, Any], Role, str] | None:
    """Look up session *token* for *conn*: ``(session, role, scope)`` or None.

    The one session check shared by HTTP auth, WebSocket auth and the
    middleware's proxied read paths: the session must exist, be unexpired
    and pass the IP / User-Agent binding check.  *scope* is the session's
    restriction ("" for a full session); callers enforce it.
    """
    detection_store = getattr(conn.app.state, "detection_store", None)
    if detection_store is None:
        return None
    tenant = detection_store.users.session_tenant(token)
    if tenant is not None:
        require_instance_tenant(conn, tenant)
    session = (
        detection_store.get_session(token)
        if touch
        else detection_store.users.get_session(token, touch=False)
    )
    if session is None:
        return None
    if not _session_binding_ok(conn, session, token):
        return None
    scope = session.get("scope") or ""
    if not isinstance(scope, str):
        scope = str(scope)
    return session, _role_from_name(session.get("role", "viewer")), scope


def _try_session_auth(request: Request) -> tuple[str | None, Role | None]:
    """Attempt session-based authentication.

    Returns (username, role) if a valid session is found, or (None, None).
    Sets request.state.auth_user with the username for audit trails, and
    ``request.state.session_scope`` (plus the ``mfa_restricted`` /
    ``password_change_restricted`` flags) for :func:`require_api_key`,
    which enforces the scope.  See :func:`_session_binding_ok` for the
    binding modes.
    """
    token = _extract_session_token(request)
    if not token:
        return None, None

    resolved = resolve_session(request, token)
    if resolved is None:
        return None, None
    session, role, scope = resolved

    # Store user info on request state for audit trails
    request.state.auth_user = session["username"]
    request.state.key_tenant = session["tenant_id"]
    request.state.session_token = token
    request.state.session_expires_at = session.get("expires_at")
    request.state.session_scope = scope
    request.state.mfa_restricted = scope == SCOPE_MFA_SETUP_ONLY
    request.state.password_change_restricted = scope == SCOPE_PASSWORD_CHANGE_ONLY

    return session["username"], role


#: ``UC_PROXY_SECRET`` values that prove nothing: unset, or the public
#: default older releases shipped.
INSECURE_PROXY_SECRETS = frozenset({"", "uppercrust-internal"})


def rust_proxy_header_valid(conn: HTTPConnection) -> bool:
    """True if *conn* carries the gateway's ``X-Rust-Proxy`` secret.

    Constant-time comparison against ``UC_PROXY_SECRET`` (read per call);
    an unset or default secret never matches.  This is the only credential
    the ``/api/internal/*`` routes accept (contracts K7 / K8 / K9).

    The comparison is on bytes, as the proxy middleware's is, so any header
    value (non-ASCII included) gives a plain False rather than a TypeError.
    Every copy of a repeated header must match: the middleware reads the
    last copy and ``headers.get`` the first, so copies that disagree fail.
    """
    secret = os.environ.get("UC_PROXY_SECRET", "")
    if secret in INSECURE_PROXY_SECRETS:
        return False
    expected = secret.encode()
    # Starlette decodes header bytes as latin-1, so this recovers them.
    matches = [
        hmac.compare_digest(v.encode("latin-1"), expected)
        for v in conn.headers.getlist("x-rust-proxy")
    ]
    # all([]) is True: no header at all must be refused explicitly, or a
    # client-cert assertion without one would be trusted.
    return bool(matches) and all(matches)


async def require_rust_proxy(request: Request) -> None:
    """Dependency for gateway-only internal routes: 403 without the proxy secret.

    API keys, sessions and client-certificate assertions are not accepted
    here — only the ``X-Rust-Proxy`` header (:func:`rust_proxy_header_valid`).
    """
    if not rust_proxy_header_valid(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Internal endpoint: only the gateway may call it",
        )


def _gateway_cert_auth(request: HTTPConnection) -> tuple[str, Role] | None:
    """Resolve a client-cert identity asserted by the Rust gateway.

    PKI Phase A: the gateway terminates mTLS, verifies the client
    certificate against the CA, resolves it to an identity + role, and
    forwards them as ``x-auth-key-id`` / ``x-auth-role`` with
    ``x-auth-method: client-cert``. The certificate never reaches the
    bridge, so this assertion is trusted **only** when the request
    provably came through the gateway — the ``x-rust-proxy`` header must
    carry the shared ``UC_PROXY_SECRET``. Returns ``(identity, role)`` or
    ``None`` to fall through to API-key auth.
    """
    if request.headers.get("x-auth-method") != "client-cert":
        return None
    secret = os.environ.get("UC_PROXY_SECRET", "")
    # Fail safe: with no secret (or the insecure built-in default) the
    # x-rust-proxy check is meaningless, so refuse to trust forwarded
    # auth headers. API-key auth is unaffected.
    if secret in INSECURE_PROXY_SECRETS:
        logger.warning(
            "client-cert auth header present but UC_PROXY_SECRET is unset "
            "or default — refusing to trust gateway assertion"
        )
        return None
    # The same bytes check as the middleware and the internal routes, so a
    # non-ASCII header is a mismatch (fall through to 401 / 4001), not a 500.
    if not rust_proxy_header_valid(request):
        logger.warning("client-cert auth header present but x-rust-proxy mismatch")
        return None
    identity = request.headers.get("x-auth-key-id", "").strip()
    role_name = request.headers.get("x-auth-role", "").strip().upper()
    if not identity or not role_name:
        return None
    try:
        role = Role[role_name]
    except KeyError:
        logger.warning("client-cert auth: unknown role %r", role_name)
        return None
    # KEYMASTER (license authority) is never delegated to a certificate:
    # the CA refuses to issue it (ca.VALID_CERT_ROLES) and the gateway
    # refuses a registry entry that carries it. Refused here too, so a
    # gateway or proxy path that ever forwarded it is not honoured.
    if role is Role.KEYMASTER:
        logger.warning(
            "client-cert auth: refusing role KEYMASTER, which is never "
            "delegated to a certificate"
        )
        return None
    return identity, role


async def require_api_key(
    request: Request,
    response: Response,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Dependency: extract and validate an API key or session token.

    Accepts authentication from:
    1. Session token via ``Authorization: Bearer <token>`` or ``X-Session-Token`` header
    2. API key via ``X-API-Key`` header or ``api_key`` query parameter

    Stores the resolved role on ``request.state.key_role``.
    For session auth, also stores ``request.state.auth_user`` with the username.
    """
    # Try session-based auth first
    username, role = _try_session_auth(request)
    if username is not None and role is not None:
        # Enforce restricted sessions (contract K3): mfa_setup_only may
        # only reach /api/auth/mfa/*, password_change_only only
        # change-password; both (and any scope unknown here) may also ask
        # who they are and log out.
        scope = getattr(request.state, "session_scope", "")
        if not session_scope_allows(scope, request.url.path):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_scope_denied_detail(scope),
            )
        request.state.key_role = role

        # Add session expiry headers
        expires_at_str = getattr(request.state, "session_expires_at", None)
        if expires_at_str:
            try:
                exp = datetime.fromisoformat(expires_at_str)
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                remaining = int((exp - datetime.now(timezone.utc)).total_seconds())
                if remaining < 0:
                    remaining = 0
                response.headers["X-Session-Expires-In"] = str(remaining)
                if remaining < 300:
                    response.headers["X-Session-Warning"] = "expiring-soon"
            except (ValueError, TypeError):
                pass

        return f"user:{username}"

    # Gateway-authenticated client certificate (PKI mTLS, Phase A).
    # Checked after sessions and before API keys: a request carrying an
    # X-API-Key has no x-auth-method header and falls through unchanged,
    # so API-key auth keeps working exactly as before.
    cert_auth = _gateway_cert_auth(request)
    if cert_auth is not None:
        identity, role = cert_auth
        request.state.key_role = role
        request.state.key_tenant = instance_tenant(request)
        return f"cert:{identity}"

    # Fall back to API key auth
    api_key = x_api_key or ""
    query_param_used = False
    if not api_key:
        api_key = request.query_params.get("api_key", "")
        if api_key:
            query_param_used = True
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key or session token required",
        )

    # SEC-L2: Deprecate query parameter auth — configurable behavior
    # BRIDGE_QUERY_PARAM_AUTH: "deprecated" (warn), "disabled" (reject), "enabled" (silent)
    # Default: "disabled" in production, "deprecated" otherwise
    if query_param_used:
        qp_mode = os.environ.get("BRIDGE_QUERY_PARAM_AUTH", "").lower()
        if not qp_mode:
            bridge_env = os.environ.get("BRIDGE_ENV", "").lower()
            qp_mode = (
                "disabled" if bridge_env in ("production", "prod") else "deprecated"
            )
        if qp_mode == "disabled":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Query parameter authentication is disabled. Use X-API-Key header instead.",
            )
        elif qp_mode != "enabled":
            response.headers["X-Deprecated"] = (
                "api_key query parameter; use X-API-Key header"
            )
            logger.info(
                "Deprecated api_key query param used from %s",
                get_client_ip(request),
            )

    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )

    # PBKDF2 (and a possible legacy re-hash) runs off the event loop so a
    # burst of API-key requests cannot stall it.
    key_id, role = await _authenticate_api_key(api_key, persistence, request)
    if key_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    request.state.key_role = role
    return key_id


async def require_master_key(
    request: Request,
    response: Response,
    x_api_key: str | None = Header(None, alias="X-API-Key"),
) -> str:
    """Dependency: require admin role for admin endpoints."""
    key_id = await require_api_key(request, response, x_api_key)
    role = getattr(request.state, "key_role", Role.VIEWER)
    if role < Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )
    return key_id


def require_role(min_role: Role):
    """Dependency factory: require at least *min_role* with rate limiting."""

    async def _check(
        request: Request,
        key_id: str = Depends(rate_limit),
    ) -> str:
        role = getattr(request.state, "key_role", Role.VIEWER)
        if role < min_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"{min_role.name.capitalize()} role required",
            )
        return key_id

    return _check


async def rate_limit(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> str:
    """Dependency: enforce sliding-window rate limiting per key."""
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
    """Dependency: stricter rate limit for sensitive endpoints (10/min)."""
    limiter = get_rate_limiter()
    bucket = f"sensitive:{key_id}"
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
# Convenience role dependencies
# ---------------------------------------------------------------------------

# Sensor: submit data only (all roles accepted)
require_sensor = require_role(Role.SENSOR)

# Operator: dashboard read + alert management (viewer and above)
require_operator = require_role(Role.VIEWER)

# Admin: full access
require_admin = require_role(Role.ADMIN)


# ---------------------------------------------------------------------------
# Role ceilings (contract K5)
# ---------------------------------------------------------------------------


def stored_key_role(key_id: str, meta: dict[str, Any] | None) -> Role:
    """The role stored key *key_id* authenticates with (master is ADMIN).

    A missing or unknown role is VIEWER.  The gateway resolves keys.json
    roles itself (``effective_role`` in ``auth/api_key.rs``) and must agree:
    both are pinned to the table in
    ``src/gateway/crates/sigrift-gateway-core/testdata/key_role_parity.json``
    (``tests/bridge/test_key_role_parity.py`` on this side).
    """
    if key_id == "master":
        return Role.ADMIN
    return _role_from_name((meta or {}).get("role", "viewer"))


def highest_key_role(persistence: Any, key_id: str) -> Role:
    """The highest role stored key *key_id* holds: here or in keys.json.

    The two differ only while a revocation or downgrade made by this
    worker is not saved yet: other workers and the gateway still grant the
    saved role.  The role ceiling (K5) is checked against the higher one,
    so finishing (or overriding) such a change needs the role the saved
    key has.
    """
    here = stored_key_role(key_id, persistence.get_key_meta().get(key_id))
    saved = persistence.get_saved_key_meta(key_id)
    if not isinstance(saved, dict):
        return here
    return max(here, stored_key_role(key_id, saved))


def enforce_role_ceiling(request: Request, target: Role, what: str) -> None:
    """403 unless the caller's role is at least *target*.

    No caller may create, re-role, rotate or revoke a key — or create or
    assign a user — above its own role; in particular only KEYMASTER can
    hand out (or touch) KEYMASTER.  *what* names the action for the error.
    """
    caller = getattr(request.state, "key_role", Role.VIEWER)
    if target > caller:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Cannot {what} with role {target.name.lower()}: above your "
                f"own role ({caller.name.lower()})"
            ),
        )


def enforce_master_rotation(request: Request, principal: str) -> None:
    """403 unless *principal* may rotate the master key.

    Only the master key itself or a KEYMASTER may: rotating returns the
    new raw master credential and invalidates the old one for everyone
    (keys.json is shared with the gateway), so another admin key or user
    must not be able to take it over.
    """
    if principal == "master":
        return
    if getattr(request.state, "key_role", Role.VIEWER) >= Role.KEYMASTER:
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Only the master key itself or a keymaster may rotate the master key",
    )


# ---------------------------------------------------------------------------
# Admin rate limit
# ---------------------------------------------------------------------------


async def admin_rate_limit(
    request: Request,
    key_id: str = Depends(require_master_key),
) -> str:
    """Dependency: require master key AND apply sensitive rate limiting (10/min)."""
    limiter = get_rate_limiter()
    bucket = f"sensitive:{key_id}"
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


# Backward compat alias
_admin_rate_limit = admin_rate_limit


# ---------------------------------------------------------------------------
# Tenant extraction
# ---------------------------------------------------------------------------


async def get_tenant_id(
    request: Request,
    tenant_id: str | None = Query(default=None),
    _key_id: str = Depends(require_api_key),
) -> str:
    """Resolve a fixed-instance tenant, rejecting caller-selected alternatives."""
    configured = instance_tenant(request)
    if tenant_id is not None:
        require_instance_tenant(request, tenant_id)
    return configured


# ---------------------------------------------------------------------------
# Client IP and trusted proxies
# ---------------------------------------------------------------------------

_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
_LOOPBACK_PROXIES = frozenset({"127.0.0.1", "::1"})


def _normalize_ip(value: str) -> str | None:
    """Return *value* as a canonical IP string, or None if it is not an IP.

    IPv4-mapped IPv6 addresses (``::ffff:10.0.0.5``) become their IPv4
    form and an IPv6 zone id (``%eth0``) is dropped, so the same peer
    always compares equal.
    """
    try:
        ip = ipaddress.ip_address(value.strip().split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _resolve_proxy_host(name: str) -> frozenset[str] | None:
    """Resolve host name *name* to its addresses; ``None`` if it does not resolve."""
    try:
        infos = socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)
    except (OSError, UnicodeError) as exc:
        logger.debug("BRIDGE_TRUSTED_PROXIES: cannot resolve %r (%s)", name, exc)
        return None
    addrs = {_normalize_ip(str(info[4][0])) for info in infos}
    return frozenset(a for a in addrs if a) or None


class _ProxyHostResolver:
    """Host names listed in ``BRIDGE_TRUSTED_PROXIES``, resolved and kept fresh.

    A name is resolved when the list is loaded, and again later, because a
    name can resolve differently over time: in docker compose the gateway
    starts only after the bridge is healthy, so ``gateway`` does not
    resolve when the bridge starts, and without a static IP the gateway's
    address can change when its container is recreated.

    * a peer that is not trusted triggers a re-resolution in a background
      thread (at most every :attr:`RETRY_SECONDS`), so the first requests
      the gateway sends (its readiness probe) make it trusted;
    * trusted addresses are re-resolved every :attr:`REFRESH_SECONDS`, so
      an address the name no longer has stops being trusted.

    A name that fails to resolve keeps its last addresses (a transient DNS
    failure does not make every client look like the gateway).  Request
    paths never wait for DNS: they read the current set.
    """

    RETRY_SECONDS = 5.0
    REFRESH_SECONDS = 60.0

    def __init__(self, hosts: Iterable[str]) -> None:
        self.hosts = tuple(dict.fromkeys(hosts))
        self._by_host: dict[str, frozenset[str]] = {}
        self._addrs: frozenset[str] = frozenset()
        self._lock = threading.Lock()
        self._refreshing = False
        self._attempted_at: float | None = None
        self._resolved_at = 0.0
        self._failure_logged: set[str] = set()

    @property
    def addresses(self) -> frozenset[str]:
        return self._addrs

    def resolve(self, *, startup: bool = False) -> frozenset[str]:
        """Resolve every host name now (blocking); return the trusted addresses."""
        by_host = dict(self._by_host)
        for name in self.hosts:
            addrs = _resolve_proxy_host(name)
            if addrs is None:
                if startup:
                    logger.error(
                        "BRIDGE_TRUSTED_PROXIES: host name %r does not resolve "
                        "yet. Until it does, X-Forwarded-For from it is ignored: "
                        "every client appears with the proxy's address, so they "
                        "share per-IP rate and WebSocket limits, audit entries "
                        "record that address, and IP-bound sessions fail. It is "
                        "resolved again when a request arrives from an untrusted "
                        "peer (at most every %.0f s). List the proxy's IP "
                        "address or subnet to avoid this.",
                        name,
                        self.RETRY_SECONDS,
                    )
                    self._failure_logged.add(name)
                elif name not in self._failure_logged:
                    logger.warning(
                        "BRIDGE_TRUSTED_PROXIES: cannot resolve %r; keeping %s",
                        name,
                        sorted(by_host.get(name, ())) or "nothing trusted for it",
                    )
                    self._failure_logged.add(name)
                continue
            if by_host.get(name) != addrs:
                logger.info(
                    "BRIDGE_TRUSTED_PROXIES: %r resolves to %s", name, sorted(addrs)
                )
            by_host[name] = addrs
            self._failure_logged.discard(name)
        with self._lock:
            self._by_host = by_host
            self._addrs = frozenset().union(*by_host.values())
            self._resolved_at = time.monotonic()
            return self._addrs

    def _refresh_in_background(self, min_age: float) -> threading.Thread | None:
        """Start a background :meth:`resolve` unless one ran within *min_age* s."""
        now = time.monotonic()
        with self._lock:
            recent = (
                self._attempted_at is not None and now - self._attempted_at < min_age
            )
            if self._refreshing or recent:
                return None
            self._refreshing = True
            self._attempted_at = now

        def _run() -> None:
            try:
                self.resolve()
            except Exception:
                logger.warning("BRIDGE_TRUSTED_PROXIES refresh failed", exc_info=True)
            finally:
                with self._lock:
                    self._refreshing = False

        thread = threading.Thread(
            target=_run, name="bridge-trusted-proxy-resolver", daemon=True
        )
        thread.start()
        return thread

    def is_trusted(self, ip: str, *, refresh_on_miss: bool) -> bool:
        """True if *ip* is a current address of a listed name (non-blocking)."""
        if ip in self._addrs:
            if time.monotonic() - self._resolved_at >= self.REFRESH_SECONDS:
                self._refresh_in_background(self.REFRESH_SECONDS)
            return True
        if refresh_on_miss:
            self._refresh_in_background(self.RETRY_SECONDS)
        return False


def _load_trusted_proxies(
    env_val: str | None = None,
    *,
    startup: bool = True,
) -> tuple[set[str], list[_IPNetwork], _ProxyHostResolver | None]:
    """Load the peers whose ``X-Forwarded-For`` is honoured.

    ``BRIDGE_TRUSTED_PROXIES`` is a comma-separated list of IPs
    (``10.0.0.5``), CIDR networks (``172.29.84.0/28``) and host names
    (``gateway``; resolved now and kept fresh afterwards, see
    :class:`_ProxyHostResolver`).  Loopback is always trusted; nothing
    else is unless listed (contract K2: list exactly the gateway, not a
    whole docker address range).  *startup*: a name that does not resolve
    is logged as an error (with its consequences), not just a warning.
    """
    if env_val is None:
        env_val = os.environ.get("BRIDGE_TRUSTED_PROXIES", "")
    plain: set[str] = set(_LOOPBACK_PROXIES)
    nets: list[_IPNetwork] = []
    hosts: list[str] = []
    for entry in (e.strip() for e in env_val.split(",") if e.strip()):
        if "/" in entry:
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                logger.warning(
                    "BRIDGE_TRUSTED_PROXIES: ignoring invalid CIDR %r", entry
                )
            continue
        ip = _normalize_ip(entry)
        if ip is not None:
            plain.add(ip)
        else:
            hosts.append(entry)
    resolver = None
    if hosts:
        resolver = _ProxyHostResolver(hosts)
        resolver.resolve(startup=startup)
    return plain, nets, resolver


# Loaded again (and reported) by the lifespan: reload_trusted_proxies().
_TRUSTED_PROXIES, _TRUSTED_PROXY_NETS, _TRUSTED_PROXY_HOSTS = _load_trusted_proxies(
    startup=False
)


def reload_trusted_proxies() -> None:
    """Re-read ``BRIDGE_TRUSTED_PROXIES`` (re-resolving host names).

    Called by the application lifespan, so the list in force is the one
    the service started with, not only the one this module was first
    imported with.
    """
    global _TRUSTED_PROXIES, _TRUSTED_PROXY_NETS, _TRUSTED_PROXY_HOSTS
    (
        _TRUSTED_PROXIES,
        _TRUSTED_PROXY_NETS,
        _TRUSTED_PROXY_HOSTS,
    ) = _load_trusted_proxies()


def _peer_is_trusted(direct_ip: str, *, refresh_on_miss: bool = False) -> bool:
    """True if *direct_ip* is a configured trusted proxy (IP, CIDR or host name).

    *refresh_on_miss*: an untrusted address re-resolves the listed host
    names in the background (see :class:`_ProxyHostResolver`); set for the
    TCP peer only, not for the ``X-Forwarded-For`` hops.
    """
    ip = _normalize_ip(direct_ip)
    if ip is None:
        return False
    if ip in _TRUSTED_PROXIES:
        return True
    if _TRUSTED_PROXY_NETS:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in _TRUSTED_PROXY_NETS):
            return True
    resolver = _TRUSTED_PROXY_HOSTS
    if resolver is None:
        return False
    return resolver.is_trusted(ip, refresh_on_miss=refresh_on_miss)


def get_client_ip(conn: HTTPConnection) -> str:
    """Extract client IP, only trusting X-Forwarded-For from known proxies.

    Works with both :class:`~fastapi.Request` and :class:`~fastapi.WebSocket`
    objects.  This is the single canonical implementation used by both
    HTTP request handlers and WebSocket auth.

    ``X-Forwarded-For`` is read only when the TCP peer is a trusted proxy,
    and then from the right: every hop added by a trusted proxy is
    skipped and the first address that is not a trusted proxy is the
    client.  The left end of the header is whatever the client sent, so
    it is used only when every hop is trusted.  An entry that is not an
    IP address ends the walk (the peer's address is used).
    """
    direct_ip = conn.client.host if conn.client else "unknown"
    if not _peer_is_trusted(direct_ip, refresh_on_miss=True):
        return direct_ip
    forwarded = conn.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    if not hops:
        return direct_ip
    # The address is returned as the proxy wrote it (it is compared with
    # the IP the gateway recorded for a session); only trust decisions use
    # the normalised form.
    for hop in reversed(hops):
        if _normalize_ip(hop) is None:
            return direct_ip
        if not _peer_is_trusted(hop):
            return hop
    return hops[0]


# Keep the old name as a private alias for internal WS usage
_get_client_ip = get_client_ip


def forwarding_headers_trusted(conn: HTTPConnection) -> bool:
    """True if *conn*'s ``X-Forwarded-Host`` / ``X-Forwarded-Proto`` are believed.

    Only the gateway (a valid ``X-Rust-Proxy``; it replaces every client
    copy of those headers) or a TCP peer listed in
    ``BRIDGE_TRUSTED_PROXIES`` (loopback always) is believed, the same
    rule as ``X-Forwarded-For``.  From anyone else they are whatever the
    client typed, so a direct plaintext client could claim TLS.
    """
    if rust_proxy_header_valid(conn):
        return True
    return _peer_is_trusted(conn.client.host if conn.client else "")


def trusted_forwarded_proto(conn: HTTPConnection) -> str:
    """The ``X-Forwarded-Proto`` scheme (lower case) when it is believed, else ``""``.

    See :func:`forwarding_headers_trusted`.  Only ``http`` and ``https``
    are returned; any other value counts as absent.
    """
    if not forwarding_headers_trusted(conn):
        return ""
    proto = conn.headers.get("x-forwarded-proto", "").strip().lower()
    return proto if proto in ("http", "https") else ""


# ---------------------------------------------------------------------------
# Node binding (contract K4)
# ---------------------------------------------------------------------------

#: Set to ``1`` to let a SENSOR / NODE API key that is not bound to a node
#: act for any node (the behaviour before keys were bound on first use);
#: other unbound keys below ANALYST (VIEWER) are refused on node routes
#: either way.  Logged as a WARNING at start-up.
ALLOW_UNBOUND_NODE_KEYS_ENV = "BRIDGE_ALLOW_UNBOUND_NODE_KEYS"
#: A node id a key may be bound to (the node models' ``_validate_id``).
_NODE_ID_RE = re.compile(r"[a-zA-Z0-9_-]{1,64}")


def allow_unbound_node_keys() -> bool:
    """True if ``BRIDGE_ALLOW_UNBOUND_NODE_KEYS`` restores unbound node keys."""
    return os.environ.get(ALLOW_UNBOUND_NODE_KEYS_ENV, "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _node_forbidden(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


#: A refused (certificate identity, node) pair is logged at most once per
#: this many seconds: an agent with a mismatched certificate retries every
#: few seconds, forever.
_CERT_MISMATCH_LOG_INTERVAL = 600.0
#: Pairs remembered for that (the map is cleared when it grows past this).
_CERT_MISMATCH_LOG_MAX = 1024
_cert_mismatch_logged: dict[tuple[str, str], float] = {}


def _cert_identity_possible(node_id: str) -> bool:
    """True if the bridge CA can issue a certificate whose identity is *node_id*."""
    from sigrift.bridge.ca import CAError, validate_identity

    try:
        validate_identity(node_id)
    except CAError:
        return False
    return True


def cert_node_mismatch_detail(identity: str, node_id: str) -> str:
    """The 403 detail for client certificate *identity* acting for *node_id*.

    Says how to fix it: a node certificate's identity is the node id
    (contract K7), so the usual cause is a certificate minted for an agent
    or service name (e.g. the old shared ``local-edge`` one) on a node
    whose ``MLRF_NODE_ID`` is something else.
    """
    detail = (
        f"Client certificate {identity!r} may only act for node {identity!r}, "
        f"not {node_id!r}: a node certificate's identity must be the node id "
        "its agents report as. "
    )
    if _cert_identity_possible(node_id):
        detail += (
            f"Issue this node a certificate with identity {node_id!r} (all of "
            "a node's agents share it), or set the agents' MLRF_NODE_ID to "
            f"{identity!r}, or authenticate them with the node's API key."
        )
    else:
        detail += (
            f"Node id {node_id!r} cannot be a certificate identity (it must "
            "start and end with a letter or digit), so this node must "
            "authenticate with an API key, or be renamed."
        )
    return detail


def _log_cert_node_mismatch(identity: str, node_id: str) -> None:
    key = (identity, node_id)
    now = time.monotonic()
    last = _cert_mismatch_logged.get(key)
    if last is not None and now - last < _CERT_MISMATCH_LOG_INTERVAL:
        return
    if len(_cert_mismatch_logged) >= _CERT_MISMATCH_LOG_MAX:
        _cert_mismatch_logged.clear()
    _cert_mismatch_logged[key] = now
    logger.error(
        "Refused client certificate %r acting for node %r (refused on every "
        "node route; this pair is not logged again for %d s). %s",
        identity,
        node_id,
        int(_CERT_MISMATCH_LOG_INTERVAL),
        cert_node_mismatch_detail(identity, node_id),
    )


def valid_node_id(node_id: Any) -> bool:
    """True if *node_id* is a node id a key may be bound to."""
    return isinstance(node_id, str) and _NODE_ID_RE.fullmatch(node_id) is not None


def _stored_binding(meta: dict[str, Any] | None) -> str | None:
    bound = (meta or {}).get("node_id")
    return bound if isinstance(bound, str) and bound else None


async def existing_node_binding(persistence: Any, key_id: str) -> str | None:
    """The node API key *key_id* is already bound to, or ``None``.

    * a key with ``node_id`` in keys.json is bound to that node;
    * a key whose id is a registered node's id (the legacy convention) is
      bound to that node, and the binding is written to keys.json now so
      the gateway, which only reads keys.json, enforces it too.

    ``None`` means unbound (or not a stored key).
    """
    bound = _stored_binding(persistence.get_key_meta().get(key_id))
    if bound is not None:
        return bound
    if key_id not in persistence.get_nodes():
        return None
    if key_id not in persistence.get_key_store():
        # Not a stored key (cannot have authenticated): the convention
        # still applies, there is just nothing to write.
        return key_id
    bound = await asyncio.to_thread(persistence.bind_key_to_node, key_id, key_id)
    if bound == key_id:
        logger.info(
            "API key %r bound to node %r (key named after the node)", key_id, key_id
        )
    return bound


#: Roles whose unbound API keys are bound to a node on first use (K7b).
NODE_KEY_ROLES = frozenset({Role.SENSOR, Role.NODE})
#: 403 detail for a credential that is not a node credential (K7b).
NODE_KEY_REQUIRED = "Node endpoints require a node API key"
#: Detail when another key is already bound to the node (K7b).
NODE_ALREADY_BOUND = "node already has a bound key"


class NodeBindOutcome(str, Enum):
    """What :func:`bind_node_key` found or did."""

    #: The key is bound (now or before) to ``NodeKeyBinding.node_id``.
    BOUND = "bound"
    #: No such stored key.
    UNKNOWN_KEY = "unknown_key"
    #: An ANALYST (or higher) key: operator tooling, never bound; it may
    #: act for any node.
    OPERATOR_KEY = "operator_key"
    #: A VIEWER (or other non-node role) key: never bound, not a node
    #: credential.
    NOT_NODE_KEY = "not_node_key"
    #: Another key is already bound to the node: first key wins.
    NODE_CLAIMED = "node_claimed"


@dataclass(frozen=True)
class NodeKeyBinding:
    outcome: NodeBindOutcome
    #: The node the key is bound to (``BOUND`` only).
    node_id: str | None = None


def _holds_node(node_id: str) -> Callable[[str, dict[str, Any]], bool]:
    """Does another stored key hold *node_id*? (K7b; for ``bind_key_to_node``).

    A usable (enabled, not revoked or expired) key holds the node it is
    bound to (``node_id`` in its metadata), and a key named like the node
    is that node's key (the legacy convention, :func:`existing_node_binding`). The
    master key holds no node.
    """

    def holds(other_key_id: str, meta: dict[str, Any]) -> bool:
        if other_key_id == "master" or not _key_usable(meta):
            return False
        return other_key_id == node_id or _stored_binding(meta) == node_id

    return holds


async def bind_node_key(persistence: Any, key_id: str, node_id: str) -> NodeKeyBinding:
    """Bind API key *key_id* for *node_id* by the K4 / K7b rules (I/O offloaded).

    The one binding routine behind every node-scoped bridge route
    (:func:`enforce_node_binding`) and the gateway's ingest
    (``POST /api/internal/bind-node-key``, contract K7):

    * an already bound key keeps its node (:func:`existing_node_binding`),
      whatever its role — an admin binds extra keys explicitly;
    * an unbound ANALYST-or-above key is operator tooling: never bound;
    * an unbound key of any other role that is not a node role
      (:data:`NODE_KEY_ROLES`: SENSOR, NODE), e.g. VIEWER, is never bound;
    * an unbound SENSOR / NODE key is bound to *node_id* now ("trust on
      first use") — unless another live key is already bound to that node
      (:func:`_holds_node`): the first key to claim a node wins.

    The caller validates *node_id* (:func:`valid_node_id`).  Writes go
    through :meth:`PersistenceManager.bind_key_to_node`, which checks and
    binds in one step under the key lock (and the inter-process lock), so
    concurrent first requests cannot both win.
    """
    if key_id not in persistence.get_key_store():
        return NodeKeyBinding(NodeBindOutcome.UNKNOWN_KEY)
    bound = await existing_node_binding(persistence, key_id)
    if bound is not None:
        return NodeKeyBinding(NodeBindOutcome.BOUND, bound)
    role = stored_key_role(key_id, persistence.get_key_meta().get(key_id))
    if role >= Role.ANALYST:
        return NodeKeyBinding(NodeBindOutcome.OPERATOR_KEY)
    if role not in NODE_KEY_ROLES:
        return NodeKeyBinding(NodeBindOutcome.NOT_NODE_KEY)
    from sigrift.bridge.persistence import NodeAlreadyBound

    try:
        bound = await asyncio.to_thread(
            partial(
                persistence.bind_key_to_node,
                key_id,
                node_id,
                holds_node=_holds_node(node_id),
            )
        )
    except NodeAlreadyBound as exc:
        logger.warning(
            "API key %r not bound to node %r: the node already has a bound key "
            "(%r). Bind extra keys for a node explicitly (key node_id).",
            key_id,
            node_id,
            exc.owner_key_id,
        )
        return NodeKeyBinding(NodeBindOutcome.NODE_CLAIMED)
    if bound is None:
        return NodeKeyBinding(NodeBindOutcome.UNKNOWN_KEY)
    if bound == node_id:
        logger.info(
            "API key %r bound to node %r on first use (trust on first use)",
            key_id,
            node_id,
        )
    return NodeKeyBinding(NodeBindOutcome.BOUND, bound)


async def enforce_node_binding(request: Request, principal: str, node_id: str) -> None:
    """Allow *principal* to act as edge node *node_id*, or raise 403.

    Used by every node-scoped route (heartbeat and the commands it hands
    out, command acks, detection / WiFi / BT / Zigbee / spectrum ingest,
    IQ uploads).

    * Admin (and above) credentials may act for any node.
    * An API key bound to a node (``node_id`` in its metadata, or a key
      whose id is the node's id) may act only for that node, whatever its
      role.
    * An unbound SENSOR / NODE API key is bound to *node_id* on its first
      node-scoped request ("trust on first use"); the binding is written
      to keys.json, which the gateway also enforces.  If another key is
      already bound to that node, the request is refused (403; contract
      K7b: first key wins, an admin binds extra keys explicitly).
    * An unbound ANALYST key is operator tooling: it is never bound and
      may act for any node (K7b).  An unbound key of any other role
      (VIEWER) is not a node credential: 403 ``Node endpoints require a
      node API key``.
    * With ``BRIDGE_ALLOW_UNBOUND_NODE_KEYS=1`` unbound SENSOR / NODE keys
      are left unbound and may act for any node, as before; an unbound
      VIEWER key is still refused (it is not a node key).  See
      :func:`bind_node_key`.
    * A non-admin user session is not a node credential: 403.
    * A gateway-verified client certificate (``cert:<identity>``) below
      ADMIN acts only for the node its identity names: a node certificate
      is issued with the node id as identity (contract K7; no trust on
      first use, the identity is fixed by the CA).  A certificate minted
      for an agent or service name instead (``local-edge`` on a node
      called something else, ``wifi-scan``) is refused with a 403 that
      says how to fix it, logged once per 10 minutes per pair.
    """
    role = getattr(request.state, "key_role", Role.SENSOR)
    if role >= Role.ADMIN:
        return
    if principal.startswith("user:"):
        raise _node_forbidden(NODE_KEY_REQUIRED)
    if principal.startswith("cert:"):
        identity = principal[len("cert:") :]
        if identity != node_id:
            _log_cert_node_mismatch(identity, node_id)
            raise _node_forbidden(cert_node_mismatch_detail(identity, node_id))
        return

    persistence = getattr(request.app.state, "persistence", None)
    if persistence is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )
    bound = await existing_node_binding(persistence, principal)
    if bound is None:
        if role >= Role.ANALYST:
            return  # operator tooling: never bound (K7b)
        if role not in NODE_KEY_ROLES:
            # Not a node credential, BRIDGE_ALLOW_UNBOUND_NODE_KEYS or not
            # (it concerns node keys only; the gateway refuses the same).
            raise _node_forbidden(NODE_KEY_REQUIRED)
        if allow_unbound_node_keys():
            return
        if not valid_node_id(node_id):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="node_id must match [a-zA-Z0-9_-]{1,64}",
            )
        binding = await bind_node_key(persistence, principal, node_id)
        if binding.outcome is NodeBindOutcome.OPERATOR_KEY:
            return  # re-roled meanwhile
        if binding.outcome is NodeBindOutcome.NOT_NODE_KEY:
            raise _node_forbidden(NODE_KEY_REQUIRED)
        if binding.outcome is NodeBindOutcome.NODE_CLAIMED:
            raise _node_forbidden(
                f"API key {principal!r} cannot be bound to node {node_id!r}: "
                f"{NODE_ALREADY_BOUND} (an admin binds more keys to a node "
                "explicitly: create the key with that node_id, or set it with "
                "PUT /api/admin/keys/{key_id}/permissions)"
            )
        if binding.node_id is None:
            # Removed meanwhile (or not a stored key): nothing to bind.
            raise _node_forbidden(
                f"API key {principal!r} cannot be bound to node {node_id!r}"
            )
        bound = binding.node_id
    if bound != node_id:
        logger.warning(
            "API key %r is bound to node %r but was used for node %r",
            principal,
            bound,
            node_id,
        )
        raise _node_forbidden(
            f"API key {principal!r} is bound to node {bound!r}, "
            f"not authorized for node {node_id!r}"
        )


# ---------------------------------------------------------------------------
# WebSocket auth (contract K1)
# ---------------------------------------------------------------------------

#: Lowest role that may open a WebSocket feed.
WS_MIN_ROLE = Role.VIEWER


def _ws_reject(code: int, reason: str) -> WebSocketException:
    return WebSocketException(code=code, reason=reason)


def _ws_subprotocol_credential(websocket: WebSocket) -> tuple[str, str | None]:
    """Return ``(credential, subprotocol)`` from ``Sec-WebSocket-Protocol``.

    Format: ``bridge-v1, <credential>``.  *subprotocol* is ``bridge-v1``
    whenever the client offered it (the handshake must then select it,
    even when the credential comes from a cookie instead), else None.
    """
    offered = [
        p.strip()
        for p in websocket.headers.get("sec-websocket-protocol", "").split(",")
        if p.strip()
    ]
    if WS_PROTOCOL not in offered:
        return "", None
    idx = offered.index(WS_PROTOCOL)
    credential = offered[idx + 1] if idx + 1 < len(offered) else ""
    return credential, WS_PROTOCOL


def _ws_session(websocket: WebSocket, token: str) -> tuple[str, Role] | None:
    """Session auth for a WebSocket: like HTTP, but only full sessions.

    A restricted session (MFA setup or password change pending, or a
    scope unknown here) may not stream any feed.

    A session that cannot be read (a storage error) fails closed with
    1011, as the gateway answers 503 and the payload re-check closes with
    1011: an unknown answer is neither "no session" (to be tried as
    another credential and refused as invalid) nor an unhandled error.
    """
    try:
        resolved = resolve_session(websocket, token)
    except database_errors():
        # No raw exception, credential, or request headers in diagnostics.
        logger.warning("WebSocket refused: the session store cannot be read")
        raise _ws_reject(1011, "Authentication unavailable") from None
    if resolved is None:
        return None
    session, role, scope = resolved
    if scope:
        raise _ws_reject(4003, _scope_denied_detail(scope))
    websocket.state.auth_user = session["username"]
    websocket.state.key_tenant = session["tenant_id"]
    websocket.state.session_token = token
    websocket.state.ws_winning_credential = (
        "session",
        token,
        f"user:{session['username']}",
    )
    return f"user:{session['username']}", role


async def _ws_api_key(websocket: WebSocket, api_key: str) -> tuple[str, Role] | None:
    persistence = getattr(websocket.app.state, "persistence", None)
    if persistence is None:
        raise _ws_reject(4001, "Service not ready")
    key_id, role = await _authenticate_api_key(api_key, persistence, websocket)
    if key_id is None or role is None:
        return None
    websocket.state.ws_winning_credential = ("api_key", api_key, key_id)
    return key_id, role


async def _ws_request_credential(
    websocket: WebSocket,
) -> tuple[tuple[str, Role] | None, WebSocketException | None]:
    """Check the upgrade request's own credentials as HTTP auth does.

    Same sources and order as :func:`require_api_key`: a session token
    (``Authorization: Bearer``, ``X-Session-Token`` or the
    ``session_token`` cookie), then a gateway-verified client certificate
    (``x-auth-method: client-cert`` with a valid ``x-rust-proxy``), then
    ``X-API-Key``, then ``?api_key=`` (only with
    ``BRIDGE_WS_QUERY_AUTH=enabled``).  As for HTTP, a token that is not a
    valid session falls through to the other sources.

    Returns ``((principal, role), None)`` for the first valid credential,
    else ``(None, refusal)``: why the credential presented was refused, or
    ``None`` when there was none.  A valid session restricted to MFA setup
    or a password change is refused (4003) at once, as for HTTP.
    """
    refusal: WebSocketException | None = None
    token = _extract_session_token(websocket)
    if token:
        found = _ws_session(websocket, token)
        if found is not None:
            return found, None
        refusal = _ws_reject(4001, "Invalid or expired session")

    cert_auth = _gateway_cert_auth(websocket)
    if cert_auth is not None:
        identity, role = cert_auth
        websocket.state.ws_winning_credential = ("cert", "", f"cert:{identity}")
        return (f"cert:{identity}", role), None

    api_key = websocket.headers.get("x-api-key", "")
    if not api_key:
        api_key = websocket.query_params.get("api_key", "")
        if api_key:
            ws_query_auth = (
                os.environ.get("BRIDGE_WS_QUERY_AUTH", "disabled").strip().lower()
            )
            if ws_query_auth != "enabled":
                return None, _ws_reject(
                    4003,
                    "Query parameter auth disabled. Use Sec-WebSocket-Protocol header.",
                )
            logger.warning(
                "WebSocket auth via query parameter is deprecated. "
                "Use Sec-WebSocket-Protocol header instead. "
                "Query params leak to server logs, proxy logs, and browser history.",
            )
    if not api_key:
        return None, refusal
    found = await _ws_api_key(websocket, api_key)
    if found is None:
        return None, _ws_reject(4001, "Invalid API key")
    return found, None


async def _authenticate_ws(websocket: WebSocket) -> tuple[str, Role, str | None]:
    """Resolve the WebSocket's principal exactly like HTTP auth does.

    The rule is the gateway's (contract K1), so both layers accept and
    refuse the same upgrades and identify the same principal:

    1. the upgrade request is authenticated as an HTTP request would be
       (:func:`_ws_request_credential`: session token, client
       certificate, ``X-API-Key``, ``?api_key=`` when enabled).  On a
       proxied upgrade the gateway sends the credential it verified this
       way (a session as the ``session_token`` cookie, an API key as
       ``X-API-Key``), so the bridge checks that credential first;
    2. only when that finds no valid credential, the one in
       ``Sec-WebSocket-Protocol: bridge-v1, <credential>`` (an API key or
       a session token).

    So a stale or bogus credential in the subprotocol list does not get
    a socket refused that the session cookie (or key, or certificate)
    authenticates, and a stale cookie does not get one refused that a
    valid subprotocol credential authenticates.

    Returns ``(principal, role, subprotocol)``; raises
    :class:`WebSocketException` (4001 unauthenticated, 4003 refused).
    """
    credential, subprotocol = _ws_subprotocol_credential(websocket)
    found, refusal = await _ws_request_credential(websocket)
    if found is None and credential:
        found = await _ws_api_key(websocket, credential)
        if found is None:
            found = _ws_session(websocket, credential)
        if found is None:
            refusal = _ws_reject(4001, "Invalid API key")
    if found is None:
        raise refusal or _ws_reject(4001, "API key required")
    return found[0], found[1], subprotocol


async def _revalidate_ws_principal(
    websocket: WebSocket, winning, min_role: Role
) -> None:
    """Check only the credential that won the upgrade, never a fallback identity."""
    method, credential, principal = winning
    if method == "session":
        resolved = await asyncio.to_thread(
            resolve_session, websocket, credential, touch=False
        )
        if resolved is None:
            raise _ws_reject(4001, "Session is no longer valid")
        session, role, scope = resolved
        if scope or principal != f"user:{session['username']}":
            raise _ws_reject(4003, "Session is no longer permitted")
    elif method == "api_key":
        persistence = getattr(websocket.app.state, "persistence", None)
        if persistence is None:
            raise _ws_reject(4001, "Service not ready")
        key_id, role = await _authenticate_api_key(credential, persistence, websocket)
        if key_id is None or key_id != principal:
            raise _ws_reject(4001, "API key is no longer valid")
    else:
        # The gateway owns certificate-chain/CRL validation. The Bridge still
        # requires its authenticated assertion and unchanged principal/role.
        found = _gateway_cert_auth(websocket)
        if found is None or f"cert:{found[0]}" != principal:
            raise _ws_reject(4001, "Certificate assertion is no longer valid")
        role = found[1]
    if role is None or role < min_role:
        raise _ws_reject(4003, "Role is no longer permitted")
    websocket.state.key_role = role


def _ws_revalidate_interval() -> float:
    """Seconds a successful WebSocket credential check is reused (0 = every payload)."""
    raw = os.environ.get("BRIDGE_WS_REVALIDATE_SECONDS", "1").strip()
    try:
        value = float(raw)
    except ValueError:
        return 1.0
    # Bound the reuse window: revocation must still close streams promptly.
    return min(max(value, 0.0), 30.0) if value == value else 1.0


def _guard_ws_payloads(websocket: WebSocket, min_role: Role) -> None:
    """Revalidate outgoing text/bytes/JSON payloads, not idle time.

    Wrapping the ASGI send boundary covers both broadcast client sets and direct
    spectrum senders. Accept/close messages retain Starlette's state machine;
    denial uses the original bound method, so closing cannot recurse.

    A successful check is reused for ``BRIDGE_WS_REVALIDATE_SECONDS`` (default
    1 s, max 30 s, 0 = before every payload) so a high-rate spectrum stream does
    not repeat the credential lookup for every frame. A revoked, expired or
    downgraded credential therefore stops receiving within one interval.
    """
    winning = websocket.state.ws_winning_credential
    original_send = websocket.send
    lock = asyncio.Lock()
    refused = False
    interval = _ws_revalidate_interval()
    checked_at: float | None = None

    async def guarded_send(message):
        nonlocal refused, checked_at
        if message["type"] != "websocket.send":
            return await original_send(message)
        async with lock:
            if refused:
                raise WebSocketDisconnect(code=4003)
            if (
                interval > 0
                and checked_at is not None
                and time.monotonic() - checked_at < interval
            ):
                return await original_send(message)
            try:
                await asyncio.wait_for(
                    _revalidate_ws_principal(websocket, winning, min_role), timeout=5.0
                )
            except WebSocketException as error:
                code, reason = error.code, "Credential no longer permitted"
            except Exception:
                # No raw exception, credential, or request headers in diagnostics.
                code, reason = 1011, "Credential validation unavailable"
            else:
                checked_at = time.monotonic()
                return await original_send(message)
            refused = True
            try:
                await original_send(
                    {"type": "websocket.close", "code": code, "reason": reason}
                )
            except (RuntimeError, OSError):
                pass  # Receiver already disconnected; never send the payload.
            raise WebSocketDisconnect(code=code)

    websocket.send = guarded_send


async def require_ws_auth(websocket: WebSocket) -> tuple[str, str | None]:
    """Validate WebSocket auth **before** ``accept()``.

    Authenticates exactly like HTTP auth (contract K1): the same API-key
    lookup, the same session checks (binding, expiry) — and a session
    restricted to MFA setup or a password change is refused — and the
    caller needs at least VIEWER (SENSOR/NODE keys cannot stream feeds).
    See :func:`_authenticate_ws` for the credential sources.

    Also enforces per-IP connection rate limiting via WSConnectionLimiter.
    On success the slot is held (released on disconnect via
    ``websocket.state.ws_client_ip``), and ``websocket.state.key_role``
    holds the role.

    Returns
    -------
    tuple[str, str | None]
        (principal, subprotocol) where subprotocol is "bridge-v1" if the
        client offered it (pass it to ``accept``), else None.
    """
    # -- Per-IP WS connection rate limiting --------------------------------
    # On rejection we raise WebSocketException rather than HTTPException +
    # manual close(). HTTPException in a WS handler triggers Starlette's
    # HTTP exception handler, which sends a second "response.start"
    # message after our close() already sent one — uvicorn then raises
    # "RuntimeError: Expected ASGI message 'websocket.http.response.body'
    # but got 'websocket.http.response.start'" and prints ~100 lines of
    # stack trace per rejection. WebSocketException is the FastAPI-native
    # path: the framework closes the socket with the given code and the
    # handler aborts cleanly, no double-send, no traceback.
    client_ip = _get_client_ip(websocket)
    ws_limiter = get_ws_limiter()
    allowed, reason = ws_limiter.try_acquire(client_ip)
    if not allowed:
        logger.warning("WS connection rejected for %s: %s", client_ip, reason)
        raise WebSocketException(code=1008, reason=reason)

    try:
        principal, role, subprotocol = await _authenticate_ws(websocket)
        if role < WS_MIN_ROLE:
            raise _ws_reject(4003, f"{WS_MIN_ROLE.name.capitalize()} role required")
    except BaseException:
        ws_limiter.release(client_ip)
        raise

    websocket.state.key_role = role
    # Store client_ip on websocket state for release on disconnect
    websocket.state.ws_client_ip = client_ip
    _guard_ws_payloads(websocket, WS_MIN_ROLE)

    return principal, subprotocol
