"""Webhook notification delivery for The Bridge.

Fires HTTP POST to configured webhook URLs when alerts are created.
Supports filtering by severity (critical, warning, info). Alert source and
other event details are preserved in the payload context.

Webhook configs are stored in PersistenceManager alongside other
JSON-persisted data.

SSRF protection (shared with ``routers/webhook_management``):

* A webhook target must resolve only to **globally routable** addresses
  (``ipaddress.is_global``): loopback, private, link-local, CGNAT
  (100.64/10), unspecified (0.0.0.0, ::), reserved and multicast addresses
  are refused.  IPv4-mapped (``::ffff:0:0/96``) and well-known NAT64
  (``64:ff9b::/96``) addresses are judged by the IPv4 address they reach;
  6to4 / Teredo addresses must pass for the IPv4 addresses they embed too.
* The name is resolved **once** per delivery, off the event loop, and the
  connection goes to that checked address (the URL's host name is still
  sent as ``Host`` and as the TLS SNI / certificate name), so a DNS answer
  that changes between check and connect (rebinding) cannot redirect it.
* Redirects are never followed.
* ``BRIDGE_WEBHOOK_ALLOW_HOSTS`` (comma-separated host names, IPs or CIDRs)
  exempts operator-approved internal targets from the address check.
* An environment egress proxy (``https_proxy`` / ``http_proxy`` /
  ``no_proxy``, as ``urllib`` reads them) is used only as a ``CONNECT``
  tunnel to the already-checked address.

Operator documentation: ``src/sigrift/bridge/DEPLOYMENT.md`` (Webhooks).
"""

from __future__ import annotations

import asyncio
import base64
import collections
import functools
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import secrets
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Callable
import urllib.request
from urllib.parse import unquote, urlparse

from sigrift.bridge.storage.webhook_retries import WebhookRetryStore

logger = logging.getLogger(__name__)


async def settle_task(task: asyncio.Task, *, cancelled: bool = False):
    """Settle owned work despite repeated caller cancellation.

    The caller must complete synchronous publication/ownership cleanup before
    propagating the returned cancellation flag. A cancelled caller still waits
    for a failed callback; its error is retrieved without replacing cancellation.
    This is settlement, not a hard deadline for a running blocking operation.
    """
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    try:
        result = task.result()
    except Exception:
        if cancelled:
            logger.error("Webhook owned operation failed while cancellation settled")
            raise asyncio.CancelledError from None
        raise
    return result, cancelled


# Maximum concurrent webhook deliveries (HTTP posts and DNS lookups); also
# the size of the manager's own worker-thread pool (see NotificationManager).
_MAX_CONCURRENT = 5

# Delivery timeout per webhook
_TIMEOUT_SECONDS = 10

# Retry config
_MAX_RETRIES = 2
_RETRY_DELAY_SECONDS = 5

# Persistent retry queue config
_MAX_RETRY_QUEUE_ATTEMPTS = 5
_MAX_RETRY_DELAY = 300  # seconds
#: Durable capacity rejects new work; transient staging drops oldest unreserved.
_DEFAULT_RETRY_QUEUE_MAX = 1000
#: How often the background retry loop looks for due entries.
_RETRY_LOOP_INTERVAL = 5.0
#: Background deliveries (:meth:`NotificationManager.submit`) in flight at
#: most. Durable intents wait in bounded intake; standalone overflow retries.
_DEFAULT_MAX_PENDING_DELIVERIES = 256
# Durable-mode initial dispatch is bounded but is not an outbox. These caps
# bound retained intake/direct-event serialized bytes, not total manager heap.
# Scheduled deliveries release intake reservations but remain capped separately
# by _DEFAULT_MAX_PENDING_DELIVERIES and the per-event serialized limit.
_DEFAULT_MAX_INITIAL_INTENTS = 256
_DEFAULT_MAX_INITIAL_BYTES = 8 * 1024 * 1024
_DEFAULT_MAX_INITIAL_PAYLOAD = 256 * 1024
#: How long shutdown waits for background deliveries before cancelling them.
_DELIVERY_STOP_GRACE_SECONDS = 2.0
_RETRY_LEASE_SECONDS = 90.0
_RETRY_LEASE_RENEW_SECONDS = 20.0
_HEALTH_FIELDS = {
    "last_delivery",
    "delivery_count",
    "failure_count",
    "last_error",
    "last_success",
    "last_failure",
    "consecutive_failures",
}


class _ConfigurationUnavailable(Exception):
    """Current endpoint authority cannot be read; retain work without sending."""


#: Env var: comma-separated host names, IP addresses or CIDRs that may be
#: webhook targets even though they are not globally routable.
ALLOW_HOSTS_ENV = "BRIDGE_WEBHOOK_ALLOW_HOSTS"

# Port validation: blocked internal service ports
BLOCKED_PORTS = {6379, 27017, 3306, 5432, 11211, 9200, 2379, 8500}
_ALLOWED_STANDARD_PORTS = {80, 443, 8080, 8443}

#: RFC 6052 well-known NAT64 prefix: the address is the embedded IPv4
#: address as seen through the site's NAT64 gateway (IPv6-only / DNS64
#: networks), so it is judged by that IPv4 address alone.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")
#: RFC 8215 local-use NAT64 prefix: site-specific, never vetted as public.
_NAT64_LOCAL_PREFIX = ipaddress.ip_network("64:ff9b:1::/48")


def _is_port_allowed(port: int | None) -> bool:
    """Check if a port is allowed for webhook delivery.

    Allows ports 80, 443, 8080, 8443, or 1024-65535 minus blocked set.
    """
    if port is None:
        return True  # default port for scheme
    if port in _ALLOWED_STANDARD_PORTS:
        return True
    if 1024 <= port <= 65535 and port not in BLOCKED_PORTS:
        return True
    return False


def _translated_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """The IPv4 address a connection to *ip* actually reaches, if any.

    IPv4-mapped (``::ffff:a.b.c.d``) and well-known-prefix NAT64
    (``64:ff9b::a.b.c.d``) addresses are just another spelling of an IPv4
    destination.
    """
    if ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> list[ipaddress.IPv4Address]:
    """IPv4 addresses a 6to4 or Teredo IPv6 address carries."""
    found: list[ipaddress.IPv4Address] = []
    if ip.sixtofour is not None:
        found.append(ip.sixtofour)
    if ip.teredo is not None:
        found.extend(ip.teredo)
    return found


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for a globally routable unicast address.

    IPv4-mapped and well-known-prefix NAT64 addresses are judged by the
    IPv4 address they translate to (so IPv6-only sites behind DNS64/NAT64
    can reach public webhooks, and ``::ffff:127.0.0.1`` is still
    loopback); 6to4 / Teredo addresses must pass both as IPv6 and for
    every IPv4 address they embed.
    """
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id or ip in _NAT64_LOCAL_PREFIX:
            return False
        translated = _translated_ipv4(ip)
        if translated is not None:
            return _is_public_ip(translated)
        candidates.extend(_embedded_ipv4(ip))
    for addr in candidates:
        if (
            not addr.is_global
            or addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False
    return True


def _webhook_allowlist() -> tuple[frozenset[str], tuple[Any, ...]]:
    """Parse ``BRIDGE_WEBHOOK_ALLOW_HOSTS`` into (host names, networks)."""
    names: set[str] = set()
    networks: list[Any] = []
    for raw in os.environ.get(ALLOW_HOSTS_ENV, "").split(","):
        entry = raw.strip().lower().rstrip(".")
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry.strip("[]"), strict=False))
        except ValueError:
            names.add(entry)
    return frozenset(names), tuple(networks)


def _host_allowlisted(hostname: str) -> bool:
    names, _networks = _webhook_allowlist()
    return hostname.strip().lower().rstrip(".") in names


def _ip_allowlisted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    _names, networks = _webhook_allowlist()
    candidates: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        translated = _translated_ipv4(ip)
        if translated is not None:
            candidates.append(translated)
    return any(c.version == n.version and c in n for c in candidates for n in networks)


def _resolve_and_check_ip(hostname: str) -> list[str]:
    """Resolve *hostname* and check every address it resolves to.

    Returns the vetted addresses (deduplicated, resolver order).  Raises
    ``ValueError`` if any address is not globally routable (and not
    allow-listed via ``BRIDGE_WEBHOOK_ALLOW_HOSTS``) — every address must
    pass, since a client may connect to any of them.  Raises
    ``socket.gaierror`` if the name cannot be resolved.  Blocking: call it
    with ``asyncio.to_thread`` from async code.
    """
    host = hostname.strip().strip("[]")
    host_allowed = _host_allowlisted(host)
    resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    addresses: list[str] = []
    for _fam, _type, _proto, _canon, addr in resolved:
        ip = ip_address(addr[0].split("%", 1)[0])
        if not host_allowed and not _is_public_ip(ip) and not _ip_allowlisted(ip):
            raise ValueError(
                f"Webhook target resolves to blocked network: {ip} (only "
                f"globally routable addresses are allowed; add the host to "
                f"{ALLOW_HOSTS_ENV} to permit an internal target)"
            )
        if str(ip) not in addresses:
            addresses.append(str(ip))
    if not addresses:
        raise socket.gaierror(f"{hostname!r} did not resolve to any address")
    return addresses


#: (proxy host, proxy port, extra CONNECT headers)
_Proxy = tuple[str, int, dict[str, str]]

# Longest CONNECT response head accepted from a proxy.
_MAX_PROXY_RESPONSE_HEAD = 16 * 1024


def _webhook_proxy(scheme: str, host: str) -> _Proxy | None:
    """The egress proxy for a webhook to *host*, from the environment.

    Honours ``https_proxy`` / ``http_proxy`` (either case) and ``no_proxy``
    the way ``urllib`` does.  The proxy is only ever asked to ``CONNECT``
    to an address this module already vetted (see :func:`_open_pinned`),
    so it cannot be used to reach a different, unchecked destination.
    Credentials in the proxy URL are sent as ``Proxy-Authorization``.
    Raises ``ValueError`` for a proxy URL that is not ``http(s)://``.
    """
    proxies = urllib.request.getproxies_environment()
    proxy_url = proxies.get(scheme)
    if not proxy_url or urllib.request.proxy_bypass_environment(host, proxies):
        return None
    if "://" not in proxy_url:
        proxy_url = f"http://{proxy_url}"
    parsed = urlparse(proxy_url)
    proxy_scheme = (parsed.scheme or "").lower()
    if proxy_scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            f"Unsupported {scheme}_proxy for webhooks: only http:// proxies "
            "(spoken to with CONNECT) are supported"
        )
    headers: dict[str, str] = {}
    if parsed.username is not None:
        creds = f"{unquote(parsed.username)}:{unquote(parsed.password or '')}"
        token = base64.b64encode(creds.encode("utf-8")).decode("ascii")
        headers["Proxy-Authorization"] = f"Basic {token}"
    port = parsed.port or (443 if proxy_scheme == "https" else 80)
    return parsed.hostname, port, headers


def _open_pinned(
    address: str,
    port: int,
    timeout: float | None,
    source_address: Any,
    proxy: _Proxy | None,
) -> socket.socket:
    """Open a TCP stream to the vetted *address*, directly or via *proxy*.

    Through a proxy the stream is a ``CONNECT`` tunnel to the IP address
    itself (never to a host name the proxy would resolve again).
    """
    if proxy is None:
        return socket.create_connection((address, port), timeout, source_address)
    proxy_host, proxy_port, proxy_headers = proxy
    target = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
    sock = socket.create_connection((proxy_host, proxy_port), timeout, source_address)
    try:
        head = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        head += [f"{name}: {value}" for name, value in proxy_headers.items()]
        sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode("latin-1"))
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            byte = sock.recv(1)  # byte-wise: nothing past the head is consumed
            if not byte:
                raise OSError("proxy closed the connection during CONNECT")
            response += byte
            if len(response) > _MAX_PROXY_RESPONSE_HEAD:
                raise OSError("proxy CONNECT response too long")
        status_line = bytes(response).split(b"\r\n", 1)[0].decode("latin-1")
        parts = status_line.split(None, 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/") or parts[1] != "200":
            raise OSError(f"proxy refused CONNECT to {target}: {status_line[:100]}")
    except BaseException:
        sock.close()
        raise
    return sock


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection to a fixed, pre-checked IP; ``Host`` stays the URL host."""

    def __init__(
        self,
        host: str,
        port: int,
        address: str,
        timeout: float,
        proxy: _Proxy | None = None,
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_address = address
        self._pinned_proxy = proxy
        self._create_connection = self._connect_pinned

    def _connect_pinned(self, addr, timeout=None, source_address=None):  # noqa: ANN001
        return _open_pinned(
            self._pinned_address, addr[1], timeout, source_address, self._pinned_proxy
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS to a fixed IP; SNI and certificate checks use the URL host."""

    def __init__(
        self,
        host: str,
        port: int,
        address: str,
        timeout: float,
        context: ssl.SSLContext,
        proxy: _Proxy | None = None,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_address = address
        self._pinned_proxy = proxy
        self._create_connection = self._connect_pinned

    def _connect_pinned(self, addr, timeout=None, source_address=None):  # noqa: ANN001
        return _open_pinned(
            self._pinned_address, addr[1], timeout, source_address, self._pinned_proxy
        )


class WebhookHTTPError(Exception):
    """The webhook answered with a non-2xx status (redirects included)."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(f"HTTP {status} {reason}".strip())
        self.status = status


def _retry_queue_max() -> int:
    raw = os.environ.get("BRIDGE_WEBHOOK_RETRY_QUEUE_MAX", "").strip()
    if not raw:
        return _DEFAULT_RETRY_QUEUE_MAX
    try:
        return max(1, int(raw))
    except ValueError:
        return _DEFAULT_RETRY_QUEUE_MAX


class NotificationManager:
    """Manages webhook endpoints and delivers alert notifications.

    Webhook configs are a list of dicts stored in persistence:
    [
        {
            "id": "abc123",
            "url": "https://example.com/webhook",
            "name": "Slack #alerts",
            "enabled": true,
            "severity_filter": ["critical", "warning"],
            "created_at": "2026-02-13T...",
            "last_delivery": null,
            "delivery_count": 0,
            "failure_count": 0,
            "last_error": null,
            "last_success": null,
            "last_failure": null,
            "consecutive_failures": 0,
        }
    ]

    The application commits failed deliveries to a bounded SQLite retry queue
    (``BRIDGE_WEBHOOK_RETRY_QUEUE_MAX``, default 1000; new excess is rejected
    and counted), retried by :meth:`start_retry_loop`. Standalone managers without
    a retry store retain the legacy in-memory queue. Initial intents/tasks are
    transient until a failed-queue INSERT commits; intake refusal is counted.

    Alerts created while handling a request (ingest, the gateway's ingest
    hook) are handed over with :meth:`submit`, which delivers them in
    background tasks: a slow or unreachable webhook never delays the
    request (contract K8b).  At most ``_MAX_CONCURRENT`` HTTP posts (and
    DNS lookups) run at once, at most ``_DEFAULT_MAX_PENDING_DELIVERIES``
    deliveries are in flight. Durable initial intents wait for those slots in a
    bounded queue; count/serialized-byte overflow is refused, never converted
    into retries using an obsolete endpoint snapshot. Standalone compatibility
    mode retains its previous saturated-delivery retry behavior.

    The blocking calls (DNS lookups, HTTP posts) run in the manager's own
    pool of ``_MAX_CONCURRENT`` threads, never in the event loop's default
    executor: that pool (``min(32, cpus + 4)`` threads, 5 on one vCPU) runs
    every ``asyncio.to_thread`` call of the bridge, the ingest hook's
    claims and inserts included, and endpoints that do not answer must not
    be able to take all of its threads.
    """

    def __init__(
        self,
        *,
        retry_store: WebhookRetryStore | None = None,
        current_webhooks: Callable[[], list[dict[str, Any]]] | None = None,
    ) -> None:
        if (retry_store is None) != (current_webhooks is None):
            raise ValueError("Durable retries require current configuration authority")
        self._retry_store = retry_store
        self._current_webhooks = current_webhooks
        self._durable_retry_lock = asyncio.Lock()
        self.configuration_lock = asyncio.Lock()
        self._retry_storage_failures = 0
        self._webhooks: list[dict[str, Any]] = []
        self._delivery_log: list[dict[str, Any]] = []
        self._failed_queue: collections.deque[dict[str, Any]] = collections.deque()
        self._staging_entry: dict | None = None
        self._retry_queue_max = _retry_queue_max()
        self._retry_dropped = 0
        self._retry_task: asyncio.Task[None] | None = None
        self._semaphore = asyncio.Semaphore(_MAX_CONCURRENT)
        self._pending: set[asyncio.Task[Any]] = set()
        self._max_pending = _DEFAULT_MAX_PENDING_DELIVERIES
        self._backlog_deferred = 0
        self._io_executor: ThreadPoolExecutor | None = None
        self._io_executor_lock = threading.Lock()
        self._authority_executor: ThreadPoolExecutor | None = None
        self._authority_lock = asyncio.Lock()
        self._intake: collections.deque[bytes] = collections.deque()
        self._intake_current: bytes | None = None
        self._intake_bytes = 0
        self._intake_task: asyncio.Task | None = None
        self._direct_pending: set[asyncio.Task] = set()
        self._direct_bytes = 0
        self._active_requests: set[asyncio.Task] = set()
        self._intake_max = _DEFAULT_MAX_INITIAL_INTENTS
        self._intake_max_bytes = _DEFAULT_MAX_INITIAL_BYTES
        self._intake_max_payload = _DEFAULT_MAX_INITIAL_PAYLOAD
        self._deliveries_closed = False
        self._initial_stats = collections.Counter()

    def _executor(self) -> ThreadPoolExecutor:
        """The pool the blocking webhook I/O runs in (created on first use)."""
        with self._io_executor_lock:
            if self._io_executor is None:
                self._io_executor = ThreadPoolExecutor(
                    max_workers=_MAX_CONCURRENT, thread_name_prefix="webhook-io"
                )
            return self._io_executor

    async def _run_blocking(self, fn: Callable[..., Any], /, *args: Any) -> Any:
        """Run ``fn(*args)`` in the webhook pool, not the default executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor(), functools.partial(fn, *args)
        )

    def _shutdown_executor(self) -> None:
        """Stop the webhook pool: queued calls are dropped, running ones finish.

        A later delivery starts a new pool.
        """
        with self._io_executor_lock:
            executor, self._io_executor = self._io_executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)
        with self._io_executor_lock:
            authority, self._authority_executor = self._authority_executor, None
        if authority is not None:
            authority.shutdown(wait=False, cancel_futures=True)

    async def _initial_configuration(self) -> list[dict]:
        """One owned off-loop read at a time; no I/O in synchronous submit.

        Cancellation settles the read because legacy revision initialization
        can write. A blocked filesystem lock can exceed shutdown's grace; this
        is settlement, not a hard wall-clock deadline for blocking file I/O.
        """
        async with self._authority_lock:
            with self._io_executor_lock:
                if self._authority_executor is None:
                    self._authority_executor = ThreadPoolExecutor(
                        max_workers=1, thread_name_prefix="webhook-authority"
                    )
                executor = self._authority_executor

            async def read():
                return await asyncio.get_running_loop().run_in_executor(
                    executor, self._current_webhooks
                )

            try:
                values, cancelled = await settle_task(asyncio.create_task(read()))
                if cancelled:
                    raise asyncio.CancelledError
                if any(
                    not isinstance(
                        value.get("severity_filter", ["critical", "warning"]), list
                    )
                    or any(
                        not isinstance(item, str)
                        for item in value.get(
                            "severity_filter", ["critical", "warning"]
                        )
                    )
                    for value in values
                ):
                    raise ValueError("Invalid webhook severity policy")
                return values
            except asyncio.CancelledError:
                raise
            except Exception:
                self._initial_stats["authority_failures"] += 1
                logger.warning(
                    "Initial webhook authority unavailable; no send admitted"
                )
                raise _ConfigurationUnavailable from None

    @property
    def initial_dispatch(self) -> dict[str, int | bool]:
        """Worker-local intent diagnostics; accepted is neither sent nor durable."""
        return {
            name: self._initial_stats[name]
            for name in (
                "accepted",
                "dispatched",
                "no_matching",
                "capacity_rejected",
                "invalid_rejected",
                "closed_rejected",
                "authority_failures",
                "policy_cancelled",
                "shutdown_discarded",
                "deliveries_cancelled",
            )
        } | {
            "queued": len(self._intake) + int(self._intake_current is not None),
            "serialized_bytes": self._intake_bytes,
            "direct_active": len(self._direct_pending),
            "direct_serialized_bytes": self._direct_bytes,
            "closed": self._deliveries_closed,
        }

    def load(
        self, webhooks: list[dict[str, Any]], *, preserve_metrics: bool = False
    ) -> None:
        """Load webhook configs from persistence."""
        self._webhooks = (
            self._with_local_health(webhooks) if preserve_metrics else list(webhooks)
        )

    def _with_local_health(self, webhooks: list[dict]) -> list[dict]:
        """Worker-local diagnostics never overwrite endpoint authority on disk."""
        old = {value["id"]: value for value in self._webhooks}
        result = []
        for webhook in webhooks:
            current = dict(webhook)
            previous = old.get(webhook["id"])
            if previous is not None and self._target_binding(
                previous
            ) == self._target_binding(webhook):
                current.update(
                    {key: previous[key] for key in _HEALTH_FIELDS if key in previous}
                )
            result.append(current)
        return result

    @property
    def webhooks(self) -> list[dict[str, Any]]:
        return self._webhooks

    @property
    def delivery_log(self) -> list[dict[str, Any]]:
        return self._delivery_log[-100:]

    @property
    def failed_queue(self) -> list[dict[str, Any]]:
        """Transient queue only; use async retry_snapshot for the durable app."""
        return list(self._failed_queue)

    async def _retry_db(self, function, *args, **kwargs):
        # SQLite work settles before propagating cancellation. This avoids a
        # cancelled enqueue racing shutdown/close or silently losing its commit.
        task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
        result, cancelled = await settle_task(task)
        if cancelled:
            raise asyncio.CancelledError
        return result

    async def retry_snapshot(self) -> tuple[list[dict], int]:
        if self._retry_store is None:
            return self.failed_queue, 0
        state = await self._retry_db(self._retry_store.snapshot)
        wall, monotonic = time.time(), time.monotonic()
        entries = [
            {**entry, "next_retry": monotonic + max(0, entry["due_at"] - wall)}
            for entry in state["entries"]
        ]
        return entries + self.failed_queue, state["dropped"]

    async def configuration_snapshot(self) -> list[dict]:
        """Fresh admin read; never publish an awaited stale snapshot as authority."""
        if self._current_webhooks is None:
            return self.webhooks
        return self._with_local_health(await self._retry_db(self._current_webhooks))

    @staticmethod
    def _target_binding(webhook: dict) -> str:
        # No raw destination or signing credentials are stored in the queue.
        fields = [
            webhook.get("url"),
            webhook.get("signing_secret"),
            webhook.get("delivery_revision"),
        ]
        return hashlib.sha256(json.dumps(fields).encode("utf-8")).hexdigest()

    async def _queue_failed(self, webhook: dict, payload: dict, error: str) -> None:
        if self._retry_store is None:
            self._enqueue_failed(webhook, payload, error)
            return
        try:
            accepted = await self._retry_db(
                self._retry_store.enqueue,
                payload["delivery_id"],
                webhook["id"],
                self._target_binding(webhook),
                json.dumps(payload).encode("utf-8"),
                now=time.time(),
                delay=_RETRY_DELAY_SECONDS,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            self._retry_storage_failures += 1
            logger.error(
                "Webhook failed-delivery persistence unavailable (%d failures)",
                self._retry_storage_failures,
            )
            raise RuntimeError("Webhook retry persistence unavailable") from None
        if not accepted:
            logger.warning(
                "Webhook retry durable capacity exhausted; failed delivery dropped"
            )

    @property
    def retry_dropped(self) -> int:
        """Failed deliveries dropped from the retry queue (full or out of attempts)."""
        return self._retry_dropped

    @property
    def pending_deliveries(self) -> int:
        """Background deliveries (:meth:`submit`) still in flight."""
        return len(self._pending)

    @property
    def backlog_deferred(self) -> int:
        """Deliveries sent to the retry queue because too many were in flight."""
        return self._backlog_deferred

    def add_webhook(
        self,
        url: str,
        name: str = "",
        severity_filter: list[str] | None = None,
    ) -> dict[str, Any]:
        """Add a new webhook endpoint. Returns the config dict.

        A ``signing_secret`` is generated automatically and stored in the
        webhook config.  It is used to compute an HMAC-SHA256 signature
        (``X-Bridge-Signature`` header) on every delivery so receivers can
        verify payload authenticity.
        """
        webhook = {
            "id": secrets.token_hex(6),
            "url": url,
            "name": name or url,
            "enabled": True,
            "severity_filter": severity_filter or ["critical", "warning"],
            "signing_secret": secrets.token_hex(32),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_delivery": None,
            "delivery_count": 0,
            "failure_count": 0,
            "last_error": None,
            "last_success": None,
            "last_failure": None,
            "consecutive_failures": 0,
        }
        self._webhooks.append(webhook)
        return webhook

    def remove_webhook(self, webhook_id: str) -> bool:
        """Remove a webhook by ID. Returns True if found."""
        for i, wh in enumerate(self._webhooks):
            if wh["id"] == webhook_id:
                self._webhooks.pop(i)
                return True
        return False

    def update_webhook(
        self, webhook_id: str, updates: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Update a webhook's config. Returns updated config or None."""
        for wh in self._webhooks:
            if wh["id"] == webhook_id:
                allowed = {"url", "name", "enabled", "severity_filter"}
                for k, v in updates.items():
                    if k in allowed:
                        wh[k] = v
                return wh
        return None

    def test_webhook(self, webhook_id: str) -> dict[str, Any] | None:
        """Find a webhook by ID for testing."""
        for wh in self._webhooks:
            if wh["id"] == webhook_id:
                return wh
        return None

    def _matching_webhooks(
        self, alert: dict[str, Any], webhooks: list[dict] | None = None
    ) -> list[dict[str, Any]]:
        """The enabled webhooks whose severity filter accepts *alert*."""
        severity = alert.get("severity", "warning")
        return [
            wh
            for wh in (self._webhooks if webhooks is None else webhooks)
            if wh.get("enabled", True)
            and severity in wh.get("severity_filter", ["critical", "warning"])
        ]

    async def notify(self, alert: dict[str, Any]) -> int:
        """Send alert to all matching webhooks and wait. Returns delivery count.

        Waits for every delivery, retries included. Blocking DNS/filesystem
        work can exceed the HTTP socket timeouts. Request handlers use
        :meth:`submit` instead, which never waits for I/O. Durable direct calls
        share its event/count/byte admission limits; refusal returns zero.
        """
        if self._retry_store is not None:
            if self._deliveries_closed:
                self._initial_stats["closed_rejected"] += 1
                return 0
            # Direct calls share submit's event/count/byte admission budget.
            # Keep their reservation until all child deliveries settle.
            encoded = self._encode_initial(alert)
            if encoded is None:
                return 0
            if len(self._direct_pending) >= self._max_pending:
                self._initial_stats["capacity_rejected"] += 1
                return 0
            task = asyncio.create_task(
                self._notify_current(json.loads(encoded)), name="webhook-notify"
            )
            self._direct_bytes += len(encoded)
            self._direct_pending.add(task)
            task.add_done_callback(self._direct_pending.discard)
            try:
                return await task
            finally:
                self._direct_bytes -= len(encoded)
        tasks = [self._deliver(wh, alert) for wh in self._matching_webhooks(alert)]
        if not tasks:
            return 0

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return sum(1 for r in results if r is True)

    async def _notify_current(self, alert: dict) -> int:
        deliveries = []
        try:
            webhooks = self._matching_webhooks(
                alert, await self._initial_configuration()
            )
            for webhook in webhooks:
                while len(self._pending) >= self._max_pending:
                    await asyncio.wait(
                        self._pending, return_when=asyncio.FIRST_COMPLETED
                    )
                task = asyncio.create_task(
                    self._deliver(webhook, alert, initial_policy=True)
                )
                self._pending.add(task)
                task.add_done_callback(self._delivery_done)
                deliveries.append(task)
            results = await asyncio.gather(*deliveries, return_exceptions=True)
            return sum(value is True for value in results)
        except _ConfigurationUnavailable:
            return 0
        finally:

            async def settle_deliveries():
                for task in deliveries:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*deliveries, return_exceptions=True)

            _result, cancelled = await settle_task(
                asyncio.create_task(settle_deliveries()),
                cancelled=isinstance(sys.exception(), asyncio.CancelledError),
            )
            if cancelled:
                raise asyncio.CancelledError

    def submit(self, alert: dict[str, Any]) -> int:
        """Deliver *alert* to every matching webhook in the background.

        In the durable app, returns 1 for a bounded accepted intent, 0 when
        refused. Accepted does not mean matched, delivered or durable. Fresh
        endpoint discovery runs asynchronously even if this worker's cache is
        empty; an unavailable authority sends nothing and increments a counter.

        Standalone compatibility mode returns the number handed over. Each
        runs as a task (with the inline retries of :meth:`_deliver`, then
        the retry queue); when ``_DEFAULT_MAX_PENDING_DELIVERIES`` are
        already in flight, the delivery is put on the retry queue instead
        (counted in :attr:`backlog_deferred`).  Must be called from the
        running event loop.
        """
        if self._retry_store is not None:
            return self._submit_intent(alert)
        webhooks = self._matching_webhooks(alert)
        if not webhooks:
            return 0
        loop = asyncio.get_running_loop()
        for webhook in webhooks:
            if len(self._pending) >= self._max_pending:
                self._backlog_deferred += 1
                if self._backlog_deferred == 1 or self._backlog_deferred % 100 == 0:
                    logger.warning(
                        "Webhook delivery backlog full (%d in flight): alert %s "
                        "for %s goes to the retry queue (%d deferred so far)",
                        self._max_pending,
                        alert.get("alert_id", ""),
                        webhook.get("name", webhook.get("id")),
                        self._backlog_deferred,
                    )
                self._enqueue_failed(
                    webhook, self._build_payload(alert), "delivery backlog full"
                )
                continue
            task = loop.create_task(
                self._deliver_in_background(webhook, alert), name="webhook-delivery"
            )
            self._pending.add(task)
            task.add_done_callback(self._delivery_done)
        return len(webhooks)

    def _submit_intent(self, alert: dict[str, Any]) -> int:
        if self._deliveries_closed:
            self._initial_stats["closed_rejected"] += 1
            return 0
        loop = asyncio.get_running_loop()
        encoded = self._encode_initial(alert)
        if encoded is None:
            return 0
        self._intake.append(encoded)
        self._intake_bytes += len(encoded)
        self._initial_stats["accepted"] += 1
        if self._intake_task is None or self._intake_task.done():
            self._intake_task = loop.create_task(
                self._dispatch_intents(), name="webhook-initial-dispatch"
            )
        return 1

    def _encode_initial(self, alert: dict) -> bytes | None:
        """Admit bounded immutable events for queued submit and direct notify."""
        try:
            if not isinstance(alert, dict):
                raise ValueError("An alert must be an object")
            encoded = json.dumps(alert, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            self._initial_stats["invalid_rejected"] += 1
            logger.warning("Initial webhook intent rejected: invalid alert")
            return None
        if (
            len(self._intake)
            + int(self._intake_current is not None)
            + len(self._direct_pending)
            >= self._intake_max
            or len(encoded) > self._intake_max_payload
            or self._intake_bytes + self._direct_bytes + len(encoded)
            > self._intake_max_bytes
        ):
            self._initial_stats["capacity_rejected"] += 1
            logger.warning("Initial webhook intent capacity exhausted; intent refused")
            return None
        return encoded

    async def _dispatch_intents(self) -> None:
        while self._intake:
            encoded = self._intake.popleft()
            self._intake_current = encoded
            try:
                alert = json.loads(encoded)
                webhooks = self._matching_webhooks(
                    alert, await self._initial_configuration()
                )
                if not webhooks:
                    self._initial_stats["no_matching"] += 1
                for webhook in webhooks:
                    while len(self._pending) >= self._max_pending:
                        await asyncio.wait(
                            self._pending, return_when=asyncio.FIRST_COMPLETED
                        )
                    task = asyncio.create_task(
                        self._deliver_in_background(webhook, alert),
                        name="webhook-delivery",
                    )
                    self._pending.add(task)
                    task.add_done_callback(self._delivery_done)
                self._initial_stats["dispatched"] += 1
            except _ConfigurationUnavailable:
                # No endpoint-bound retry can be constructed from stale authority.
                pass
            except asyncio.CancelledError:
                self._initial_stats["shutdown_discarded"] += 1
                raise
            finally:
                self._intake_current = None
                self._intake_bytes -= len(encoded)

    async def _deliver_in_background(
        self, webhook: dict[str, Any], alert: dict[str, Any]
    ) -> None:
        try:
            if self._retry_store is None:
                await self._deliver(webhook, alert)
            else:
                await self._deliver(webhook, alert, initial_policy=True)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(
                "Webhook delivery to %s failed", webhook.get("name", webhook.get("id"))
            )

    def _delivery_done(self, task: asyncio.Task) -> None:
        self._pending.discard(task)
        if self._retry_store is not None and task.cancelled():
            self._initial_stats["deliveries_cancelled"] += 1

    async def stop_deliveries(
        self, grace_seconds: float = _DELIVERY_STOP_GRACE_SECONDS
    ) -> None:
        """Wait up to *grace_seconds* for background deliveries, then cancel them.

        Then stops the webhook thread pool. A post already running may finish
        after cancellation; socket timeouts are not total wall deadlines.
        Durable authority reads settle before return and can exceed the grace
        period when blocked on the filesystem.
        """
        if self._retry_store is not None:
            self._deliveries_closed = True
            _result, cancelled = await settle_task(
                asyncio.create_task(self._stop_initial_dispatch(grace_seconds))
            )
            if cancelled:
                raise asyncio.CancelledError
            return
        pending = list(self._pending)
        if pending:
            _done, still = await asyncio.wait(pending, timeout=max(0.0, grace_seconds))
            for task in still:
                task.cancel()
            if still:
                await asyncio.gather(*still, return_exceptions=True)
                logger.warning(
                    "Shutdown: cancelled %d webhook deliveries still in flight",
                    len(still),
                )
        self._shutdown_executor()

    async def _stop_initial_dispatch(self, grace_seconds: float) -> None:
        async def drained():
            if self._intake_task is not None:
                await self._intake_task
            if self._direct_pending:
                await asyncio.gather(*self._direct_pending, return_exceptions=True)
            if self._pending:
                await asyncio.gather(*self._pending, return_exceptions=True)
            if self._active_requests:
                await asyncio.gather(*self._active_requests, return_exceptions=True)

        drain = asyncio.create_task(drained())
        try:
            await asyncio.wait({drain}, timeout=max(0.0, grace_seconds))
        finally:
            owned = {
                drain,
                *self._pending,
                *self._direct_pending,
                *self._active_requests,
            }
            if self._intake_task is not None:
                owned.add(self._intake_task)
            for task in owned:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*owned, return_exceptions=True)
            self._initial_stats["shutdown_discarded"] += len(self._intake)
            self._intake.clear()
            self._intake_bytes = 0
            self._shutdown_executor()

    async def _vet_target(self, url: str) -> list[str] | None:
        """Check *url*'s port and resolve + vet its host once, off the loop.

        Returns the addresses to connect to (``None`` when the URL has no
        host, which ``_http_post`` then rejects).  Raises ``ValueError``
        for a blocked port or address, ``OSError`` when resolution fails.
        """
        parsed = urlparse(url)
        if not _is_port_allowed(parsed.port):
            raise ValueError(f"Port {parsed.port} is blocked for webhook delivery")
        if not parsed.hostname:
            return None
        return await self._run_blocking(_resolve_and_check_ip, parsed.hostname)

    def _health_targets(self, webhook: dict):
        yield webhook
        local = self.test_webhook(webhook["id"])
        if (
            local is not None
            and local is not webhook
            and self._target_binding(local) == self._target_binding(webhook)
        ):
            yield local

    def _record_success(self, webhook: dict[str, Any]) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        for target in self._health_targets(webhook):
            target["last_delivery"] = now_iso
            target["delivery_count"] = target.get("delivery_count", 0) + 1
            target["last_error"] = None
            target["last_success"] = now_iso
            target["consecutive_failures"] = 0

    def _record_failure(self, webhook: dict[str, Any], exc: BaseException) -> None:
        for target in self._health_targets(webhook):
            target["failure_count"] = target.get("failure_count", 0) + 1
            target["last_error"] = str(exc)[:200]
            target["last_failure"] = datetime.now(timezone.utc).isoformat()
            target["consecutive_failures"] = target.get("consecutive_failures", 0) + 1

    async def _deliver(
        self,
        webhook: dict[str, Any],
        alert: dict[str, Any],
        *,
        initial_policy: bool = False,
    ) -> bool:
        """Own even an explicit admin test through manager shutdown."""
        if self._retry_store is None:
            return await self._deliver_current(
                webhook, alert, initial_policy=initial_policy
            )
        if self._deliveries_closed and not initial_policy:
            self._initial_stats["closed_rejected"] += 1
            return False
        while len(self._active_requests) >= self._max_pending:
            if not initial_policy:
                self._initial_stats["capacity_rejected"] += 1
                return False
            # Accepted intents already own a bounded delivery slot. An admin
            # test can occupy the request budget too; wait rather than discard
            # that accepted work. Manager shutdown owns and cancels this waiter.
            await asyncio.wait(
                self._active_requests, return_when=asyncio.FIRST_COMPLETED
            )
        task = asyncio.create_task(
            self._deliver_current(webhook, alert, initial_policy=initial_policy),
            name="webhook-request",
        )
        self._active_requests.add(task)
        task.add_done_callback(self._active_requests.discard)
        return await task

    async def _deliver_current(
        self, webhook: dict[str, Any], alert: dict[str, Any], *, initial_policy: bool
    ) -> bool:
        """Deliver a single alert to a single webhook with retries."""

        url = webhook["url"]
        payload = self._build_payload(alert)
        if self._retry_store is not None:
            payload["delivery_id"] = secrets.token_hex(16)
        data = json.dumps(payload).encode("utf-8")

        # Compute HMAC signature if webhook has a signing secret
        signing_secret = webhook.get("signing_secret")
        signature = (
            self.compute_signature(signing_secret, data) if signing_secret else None
        )

        # Resolve and vet the target once; every attempt below connects to
        # these checked addresses (no second lookup an attacker could flip).
        try:
            if not await self._initial_target_current(webhook, alert, initial_policy):
                return False
            # Under the semaphore like the posts: a resolver that hangs
            # must not take more than _MAX_CONCURRENT worker threads.
            async with self._semaphore:
                addresses = await self._vet_target(url)
        except _ConfigurationUnavailable:
            return False
        except Exception as exc:
            self._record_failure(webhook, exc)
            self._log_delivery(webhook, alert, success=False, error=str(exc))
            logger.warning(
                "Webhook DNS/port check failed: %s → %s: %s",
                webhook["name"],
                url,
                exc,
            )
            await self._queue_current_initial_failure(
                webhook, alert, payload, exc, initial_policy
            )
            return False

        for attempt in range(_MAX_RETRIES + 1):
            try:
                async with self._semaphore:
                    # The endpoint and filtering decision can change while DNS,
                    # another post, or the previous retry delay was pending.
                    if not await self._initial_target_current(
                        webhook, alert, initial_policy
                    ):
                        return False
                    await self._run_blocking(
                        self._http_post,
                        url,
                        data,
                        signature,
                        addresses,
                    )
                self._record_success(webhook)
                self._log_delivery(webhook, alert, success=True)
                return True
            except _ConfigurationUnavailable:
                return False
            except Exception as exc:
                if attempt < _MAX_RETRIES:
                    await asyncio.sleep(_RETRY_DELAY_SECONDS)
                    continue
                self._record_failure(webhook, exc)
                self._log_delivery(webhook, alert, success=False, error=str(exc))
                logger.warning(
                    "Webhook delivery failed: %s → %s: %s",
                    webhook["name"],
                    url,
                    exc,
                )
                await self._queue_current_initial_failure(
                    webhook, alert, payload, exc, initial_policy
                )
                return False
        return False

    async def _initial_target_current(
        self, webhook: dict, alert: dict, policy: bool
    ) -> bool:
        if self._current_webhooks is None:
            return True
        # URL/signing/enabled/restore revisions reject an old A→B→A target.
        # Severity filters use current eligibility, not a historical revision.
        # An HTTP call admitted after this check may complete during a later edit.
        configs = await self._initial_configuration()
        current = next(
            (value for value in configs if value["id"] == webhook["id"]), None
        )
        valid = (
            current is not None
            and self._target_binding(current) == self._target_binding(webhook)
            and (not policy or bool(self._matching_webhooks(alert, [current])))
        )
        if not valid:
            self._initial_stats["policy_cancelled"] += 1
        return valid

    async def _queue_current_initial_failure(
        self, webhook, alert, payload, error, policy
    ):
        try:
            if await self._initial_target_current(webhook, alert, policy):
                await self._queue_failed(webhook, payload, str(error))
        except _ConfigurationUnavailable:
            # Unknown authority cannot authorize a retry bound to an old target.
            # The explicit authority-failure counter records this non-durable loss.
            pass

    def _enqueue_failed(
        self,
        webhook: dict[str, Any],
        payload: dict[str, Any],
        error: str,
    ) -> None:
        """Add a failed delivery to the retry queue."""
        delay = min(_MAX_RETRY_DELAY, _RETRY_DELAY_SECONDS * (2**0))
        entry = {
            "webhook_id": webhook["id"],
            "payload": payload,
            "attempts": 1,
            "last_error": error[:200],
            "next_retry": time.monotonic() + delay,
        }
        if self._retry_store is not None:
            # submit() is synchronous/nonblocking. Overflow is bounded transient
            # staging until the retry loop commits it; submit is not a durable
            # acceptance acknowledgement, just like initial in-flight tasks.
            entry["payload"] = {**payload, "delivery_id": secrets.token_hex(16)}
            entry["target_binding"] = self._target_binding(webhook)
        self._append_failed(entry)

    def _append_failed(self, entry: dict[str, Any]) -> None:
        """Queue *entry* for retry, dropping the oldest entry when full."""
        self._failed_queue.append(entry)
        while len(self._failed_queue) > self._retry_queue_max:
            # A durable INSERT may already be committing this reserved entry.
            # Drop the oldest unreserved entry, never claim that commit was lost.
            index = next(
                i
                for i, pending in enumerate(self._failed_queue)
                if pending is not self._staging_entry
            )
            dropped = self._failed_queue[index]
            del self._failed_queue[index]
            self._retry_dropped += 1
            if self._retry_dropped == 1 or self._retry_dropped % 100 == 0:
                logger.warning(
                    "Webhook retry queue full (%d): dropped the oldest failed "
                    "delivery for %s (%d dropped so far)",
                    self._retry_queue_max,
                    dropped.get("webhook_id"),
                    self._retry_dropped,
                )

    async def retry_failed(self) -> int:
        """Retry the due deliveries in the failed queue.

        Returns the count of successful retries.  Due entries are taken off
        the queue first, so failures queued meanwhile (by ``notify``) are
        kept, and a failed retry is re-queued with exponential backoff
        until ``_MAX_RETRY_QUEUE_ATTEMPTS`` attempts. Cancellation restores the
        current and unstarted entries without consuming another attempt, subject
        to the same bounded queue policy. Recorded successes stay completed.

        A cancelled executor HTTP call may still reach its receiver. Retrying
        that uncertain delivery repeats the same payload/signature (at least
        once, not exactly once). The app uses the durable failed queue; a
        standalone manager without a store uses the legacy memory queue.
        """
        if self._retry_store is not None:
            return await self._retry_durable()
        now = time.monotonic()
        due = [e for e in self._failed_queue if now >= e["next_retry"]]
        if not due:
            return 0
        due_ids = {id(e) for e in due}
        self._failed_queue = collections.deque(
            e for e in self._failed_queue if id(e) not in due_ids
        )
        successes = 0

        for index, entry in enumerate(due):
            # Find the webhook config
            webhook = None
            for wh in self._webhooks:
                if wh["id"] == entry["webhook_id"]:
                    webhook = wh
                    break

            if webhook is None:
                # Webhook was deleted, drop from queue
                continue

            url = webhook["url"]
            data = json.dumps(entry["payload"]).encode("utf-8")

            # Compute HMAC signature for retry
            retry_secret = webhook.get("signing_secret")
            retry_sig = (
                self.compute_signature(retry_secret, data) if retry_secret else None
            )

            try:
                # Re-vet the target (DNS may have changed) and pin it.
                async with self._semaphore:
                    addresses = await self._vet_target(url)
                async with self._semaphore:
                    await self._run_blocking(
                        self._http_post, url, data, retry_sig, addresses
                    )
                self._record_success(webhook)
                successes += 1
            except asyncio.CancelledError:
                # Taking the batch off the queue reserves it from concurrent
                # retry passes. Return only work this pass has not completed;
                # notify() may have appended other failures while we awaited I/O.
                for pending in due[index:]:
                    self._append_failed(pending)
                raise
            except Exception as exc:
                entry["attempts"] += 1
                entry["last_error"] = str(exc)[:200]
                if entry["attempts"] >= _MAX_RETRY_QUEUE_ATTEMPTS:
                    # Drop after max attempts
                    self._retry_dropped += 1
                    logger.warning(
                        "Webhook retry queue: dropping entry for %s after %d attempts",
                        entry["webhook_id"],
                        entry["attempts"],
                    )
                    continue
                delay = min(
                    _MAX_RETRY_DELAY, _RETRY_DELAY_SECONDS * (2 ** entry["attempts"])
                )
                entry["next_retry"] = time.monotonic() + delay
                self._append_failed(entry)

        return successes

    async def _retry_configuration(self, entry: dict) -> dict | None:
        try:
            configs = await self._retry_db(self._current_webhooks)
        except asyncio.CancelledError:
            raise
        except Exception:
            raise _ConfigurationUnavailable from None
        webhook = next(
            (item for item in configs if item["id"] == entry["webhook_id"]), None
        )
        if (
            webhook is None
            or not webhook.get("enabled", True)
            or self._target_binding(webhook) != entry["target_binding"]
        ):
            return None
        return webhook

    async def _retry_request(self, entry: dict) -> dict | None:
        webhook = await self._retry_configuration(entry)
        if webhook is None:
            return None
        async with self._semaphore:
            addresses = await self._vet_target(webhook["url"])
            # DNS can be slow: honor an admin change completed while it waited.
            webhook = await self._retry_configuration(entry)
            if webhook is None:
                return None
            secret = webhook.get("signing_secret")
            signature = (
                self.compute_signature(secret, entry["payload"]) if secret else None
            )
            await self._run_blocking(
                self._http_post, webhook["url"], entry["payload"], signature, addresses
            )
        return webhook

    async def _renew_retry(self, entry: dict) -> None:
        while True:
            await asyncio.sleep(_RETRY_LEASE_RENEW_SECONDS)
            owned = await self._retry_db(
                self._retry_store.renew,
                entry,
                now=time.time(),
                lease_seconds=_RETRY_LEASE_SECONDS,
            )
            if not owned:
                raise RuntimeError("Webhook retry lease lost")

    async def _retry_durable(self) -> int:
        """Serialize this worker; cross-worker ownership is fenced in SQLite.

        Cancellation releases a claim without incrementing its attempt. An
        already-running executor HTTP call may still complete; receivers can
        deduplicate the stable delivery_id in the exact repeated JSON payload.
        """
        async with self._durable_retry_lock:
            # Initial backlog saturation remains non-durable until this commit.
            while self._failed_queue:
                entry = self._failed_queue[0]
                self._staging_entry = entry
                try:
                    _accepted, cancelled = await settle_task(
                        asyncio.create_task(
                            asyncio.to_thread(
                                self._retry_store.enqueue,
                                entry["payload"]["delivery_id"],
                                entry["webhook_id"],
                                entry["target_binding"],
                                json.dumps(entry["payload"]).encode("utf-8"),
                                now=time.time(),
                                delay=max(0, entry["next_retry"] - time.monotonic()),
                            )
                        )
                    )
                    # False means an explicit, counted durable capacity refusal.
                    # A failed INSERT instead leaves this exact entry staged.
                    self._failed_queue.remove(entry)
                    if cancelled:
                        raise asyncio.CancelledError
                finally:
                    self._staging_entry = None
            successes = 0
            for _ in range(self._retry_queue_max):
                claim = asyncio.create_task(
                    asyncio.to_thread(
                        self._retry_store.claim,
                        now=time.time(),
                        lease_seconds=_RETRY_LEASE_SECONDS,
                    )
                )
                entry, cancelled = await settle_task(claim)
                if cancelled:
                    if entry is not None:
                        await settle_task(
                            asyncio.create_task(
                                self._retry_db(self._retry_store.release, entry)
                            ),
                            cancelled=True,
                        )
                    raise asyncio.CancelledError
                if entry is None:
                    break
                request = asyncio.create_task(self._retry_request(entry))
                renewal = asyncio.create_task(self._renew_retry(entry))
                try:
                    done, _pending = await asyncio.wait(
                        (request, renewal), return_when=asyncio.FIRST_COMPLETED
                    )
                    if renewal in done:
                        await renewal  # failure; never acknowledge an unowned row
                    webhook = await request
                    if (
                        await self._retry_db(
                            self._retry_store.ack,
                            entry,
                            now=time.time(),
                            dropped=webhook is None,
                        )
                        and webhook is not None
                    ):
                        self._record_success(webhook)
                        successes += 1
                except _ConfigurationUnavailable:
                    logger.warning(
                        "Webhook retry authority unavailable; delivery retained"
                    )
                    break
                except asyncio.CancelledError:
                    raise
                except Exception as error:
                    await self._retry_db(
                        self._retry_store.fail,
                        entry,
                        now=time.time(),
                        delay=min(
                            _MAX_RETRY_DELAY,
                            _RETRY_DELAY_SECONDS * (2 ** (entry["attempts"] + 1)),
                        ),
                        max_attempts=_MAX_RETRY_QUEUE_ATTEMPTS,
                        category="http_error"
                        if isinstance(error, WebhookHTTPError)
                        else "transport_error",
                    )
                finally:
                    _result, cancelled = await settle_task(
                        asyncio.create_task(
                            self._release_retry(entry, request, renewal)
                        ),
                        cancelled=isinstance(sys.exception(), asyncio.CancelledError),
                    )
                    if cancelled:
                        raise asyncio.CancelledError
            return successes

    async def _release_retry(self, entry, request, renewal):
        request.cancel()
        renewal.cancel()
        await asyncio.gather(request, renewal, return_exceptions=True)
        await self._retry_db(self._retry_store.release, entry)

    # -- Background retry loop ----------------------------------------------

    def start_retry_loop(self, interval: float = _RETRY_LOOP_INTERVAL) -> None:
        """Start the background task that retries failed deliveries.

        Must be called from a running event loop (the app lifespan).
        Idempotent while the loop is running.
        """
        if self._retry_task is not None and not self._retry_task.done():
            return
        self._retry_task = asyncio.get_running_loop().create_task(
            self._retry_loop(interval), name="webhook-retry-loop"
        )

    async def stop_retry_loop(self) -> None:
        """Stop the background retry task (pending entries stay queued)."""
        task, self._retry_task = self._retry_task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    async def _retry_loop(self, interval: float) -> None:
        while True:
            await asyncio.sleep(interval)
            if not self._failed_queue and self._retry_store is None:
                continue
            try:
                await self.retry_failed()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Webhook retry pass failed")

    @staticmethod
    def compute_signature(signing_secret: str, body: bytes) -> str:
        """Compute HMAC-SHA256 signature for a webhook payload.

        Returns the signature in the format ``sha256=<hex_digest>``.
        """
        mac = hmac.new(signing_secret.encode("utf-8"), body, hashlib.sha256)
        return f"sha256={mac.hexdigest()}"

    @staticmethod
    def _http_post(
        url: str,
        data: bytes,
        signature: str | None = None,
        addresses: list[str] | None = None,
    ) -> int:
        """Synchronous HTTP POST with timeout, to a vetted address.

        *addresses* are the checked IPs for the URL's host (from
        :func:`_resolve_and_check_ip`); when omitted they are resolved
        and checked here.  The connection goes to one of those addresses
        while ``Host`` and TLS SNI/certificate verification use the URL's
        host name.  Redirects are not followed (a 3xx is a failure).  An
        environment proxy (``https_proxy`` / ``http_proxy``, minus
        ``no_proxy``) is used as a ``CONNECT`` tunnel to that same vetted
        address, for http and https webhooks alike.

        TLS certificates are always verified. Set the ``BRIDGE_CA_BUNDLE``
        environment variable to a CA bundle path for custom/internal PKI.

        If *signature* is provided it is sent as the ``X-Bridge-Signature``
        header so that receivers can verify payload authenticity.
        """
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError("Webhook URL must use http or https")
        host = parsed.hostname
        if not host:
            raise ValueError("Webhook URL has no host")
        if not _is_port_allowed(parsed.port):
            raise ValueError(f"Port {parsed.port} is blocked for webhook delivery")
        port = parsed.port or (443 if scheme == "https" else 80)
        if addresses is None:
            addresses = _resolve_and_check_ip(host)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SigRift-Webhook/1.0",
        }
        if signature:
            headers["X-Bridge-Signature"] = signature

        ctx: ssl.SSLContext | None = None
        if scheme == "https":
            ctx = ssl.create_default_context()
            ca_bundle = os.environ.get("BRIDGE_CA_BUNDLE")
            if ca_bundle:
                ctx.load_verify_locations(ca_bundle)

        proxy = _webhook_proxy(scheme, host)
        last_error: OSError | None = None
        for address in addresses:
            if ctx is not None:
                conn: http.client.HTTPConnection = _PinnedHTTPSConnection(
                    host, port, address, _TIMEOUT_SECONDS, ctx, proxy
                )
            else:
                conn = _PinnedHTTPConnection(
                    host, port, address, _TIMEOUT_SECONDS, proxy
                )
            try:
                try:
                    conn.connect()
                except OSError as exc:
                    last_error = exc  # try the next vetted address
                    continue
                conn.request("POST", path, body=data, headers=headers)
                resp = conn.getresponse()
                resp.read(64 * 1024)
                if 200 <= resp.status < 300:
                    return resp.status
                if 300 <= resp.status < 400:
                    raise WebhookHTTPError(
                        resp.status, f"{resp.reason} (redirects are not followed)"
                    )
                raise WebhookHTTPError(resp.status, resp.reason)
            finally:
                conn.close()
        raise last_error or OSError(f"could not connect to {host}")

    @staticmethod
    def _build_payload(alert: dict[str, Any]) -> dict[str, Any]:
        """Build the webhook JSON payload from an alert dict."""
        return {
            "event": "alert",
            "source": "sigrift",
            "timestamp": alert.get(
                "triggered_at", datetime.now(timezone.utc).isoformat()
            ),
            "alert": {
                "id": alert.get("alert_id", ""),
                "name": alert.get("name", ""),
                "severity": alert.get("severity", "warning"),
                "message": alert.get("message", ""),
                "node_id": alert.get("node_id"),
            },
            "context": {
                k: v
                for k, v in alert.items()
                if k
                not in {
                    "alert_id",
                    "name",
                    "severity",
                    "message",
                    "node_id",
                    "triggered_at",
                    "acknowledged",
                    "acknowledged_at",
                    "is_rule",
                    "thresholds",
                }
            },
        }

    def _log_delivery(
        self,
        webhook: dict[str, Any],
        alert: dict[str, Any],
        success: bool,
        error: str | None = None,
    ) -> None:
        """Record a delivery attempt in the in-memory log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "webhook_id": webhook["id"],
            "webhook_name": webhook["name"],
            "alert_id": alert.get("alert_id", ""),
            "severity": alert.get("severity", ""),
            "success": success,
        }
        if error:
            entry["error"] = error[:200]
        self._delivery_log.append(entry)
        # Keep bounded
        if len(self._delivery_log) > 200:
            self._delivery_log = self._delivery_log[-200:]
