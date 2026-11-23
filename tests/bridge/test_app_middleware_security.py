"""Security paths of the bridge's ``CombinedMiddleware`` and middleware stack.

Covers what the other suites leave out (``test_round3_bridge_auth``,
``test_round4_br1``, ``test_proxy_auth`` and ``test_admin_router_security``
cover the proxy check, the HTTP side of ``/api/internal/*`` and the TLS
check of key rotation):

* response security headers on content and error responses, and HSTS only
  for TLS requests: a direct TLS connection or a trusted proxy that vouches
  for TLS, never a direct client that claims it;
* ``X-Forwarded-Host`` / ``X-Forwarded-Proto``: believed only from a trusted
  proxy peer or the gateway, ``host[:port]`` parsing;
* the request-size limit: a declared body over 10 MB is refused before any
  route (or auth) runs, ``/api/internal/*`` gets the ingest hook's limit;
  a chunked body is counted as it is read (413 whatever the route makes
  of the refused read, nothing more read from the client), the limit
  applies before the upperCrust proxy, and every 413 is a logged bridge
  response with the security headers;
* WebSocket upgrades to ``/api/internal/*`` without the gateway secret;
* ``BRIDGE_REQUIRE_PROXY``'s loopback exemption needs a peer address;
* the CSRF check with a session of another tenant;
* the upperCrust ingest proxy: an upstream 4xx is the answer, the batch is
  not replayed to the local handler;
* CORS only for the configured origins.
"""

from __future__ import annotations

import asyncio
import email.message
import io
import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import sigrift.bridge.app as app_module
import sigrift.bridge.dependencies as deps
from sigrift.bridge import API_VERSION
from sigrift.bridge.app import CombinedMiddleware, create_test_app
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.routers.internal import INGEST_HOOK_MAX_BODY
from sigrift.lib.security import credentials

_SECRET = "p-app-middleware-proxy-secret-0123456789abcdef"
#: The documented global request-body limit (10 MB), spelled out so a
#: change of the constant is noticed here.
_LIMIT = 10 * 1024 * 1024
_UNTRUSTED_PEER = "203.0.113.7"

_SECURITY_HEADERS = {
    "content-security-policy": "frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture(scope="module")
def shared_app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[FastAPI]:
    """One bridge app for the tests that only send requests (no state)."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)
        app = create_test_app(tmp_path_factory.mktemp("p-app-middleware"))
    yield app
    app.state.detection_store.close()


@pytest.fixture
def proxy_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    """UC_PROXY_SECRET as the gateway and bridge share it."""
    monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
    return _SECRET


def _request(
    app,
    method: str,
    path: str,
    *,
    peer: str = _UNTRUSTED_PEER,
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
) -> httpx.Response:
    """One request to *app* from TCP peer *peer* (TestClient's is fixed)."""

    async def _go() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, client=(peer, 40000))
        async with httpx.AsyncClient(
            transport=transport, base_url="http://bridge:8001"
        ) as ac:
            return await ac.request(method, path, headers=headers, content=content)

    return asyncio.run(_go())


async def _echo_scope(scope, receive, send) -> None:
    """Inner ASGI app: answers with the scope fields the middleware rewrites."""
    body = json.dumps(
        {"server": list(scope["server"]), "scheme": scope["scheme"]}
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body})


_probe = CombinedMiddleware(_echo_scope)


# ---------------------------------------------------------------------------
# Security headers and HSTS
# ---------------------------------------------------------------------------


class TestSecurityHeaders:
    @pytest.mark.parametrize(
        ("path", "status"),
        [
            ("/api/version", 200),  # API content
            ("/api/nodes", 401),  # API error (no credential)
            ("/no-such-page", 404),  # non-API error
        ],
    )
    def test_every_response_carries_them(self, shared_app, path, status):
        resp = TestClient(shared_app).get(path)
        assert resp.status_code == status
        for name, expected in _SECURITY_HEADERS.items():
            assert expected in resp.headers.get(name, ""), (name, resp.headers)
        # Plain HTTP: no HSTS (a browser would ignore it, and it must not be
        # sent for a connection that is not TLS).
        assert "strict-transport-security" not in resp.headers

    def test_csp_forbids_inline_script_and_plugins(self, shared_app):
        csp = (
            TestClient(shared_app)
            .get("/api/version")
            .headers["content-security-policy"]
        )
        directives = {
            name: sources.split()
            for name, _, sources in (
                d.strip().partition(" ") for d in csp.split(";") if d.strip()
            )
        }
        # Sources that would let injected markup run script (a nonce, a hash
        # or 'strict-dynamic' would be a tightening, and pass).
        unsafe = {"'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:", "https:"}
        for name in ("default-src", "script-src"):
            assert directives.get(name), (name, csp)
            assert unsafe.isdisjoint(directives[name]), (name, csp)
        assert directives["object-src"] == ["'none'"]

    def test_direct_tls_connection_gets_hsts(self, shared_app):
        resp = TestClient(shared_app, base_url="https://testserver").get("/api/version")
        assert resp.headers["strict-transport-security"] == (
            "max-age=31536000; includeSubDomains"
        )

    def test_a_direct_client_cannot_claim_tls(self, shared_app):
        resp = _request(
            shared_app,
            "GET",
            "/api/version",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "bridge.example",
            },
        )
        assert resp.status_code == 200
        assert "strict-transport-security" not in resp.headers

    def test_a_trusted_proxy_vouches_for_tls(self, shared_app):
        # Loopback is always a trusted proxy (nginx in front of the bridge).
        resp = _request(
            shared_app,
            "GET",
            "/api/version",
            peer="127.0.0.1",
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "bridge.example",
            },
        )
        assert resp.status_code == 200
        assert "strict-transport-security" in resp.headers


# ---------------------------------------------------------------------------
# X-Forwarded-Host / X-Forwarded-Proto trust
# ---------------------------------------------------------------------------


class TestForwardedHostAndProto:
    @pytest.mark.parametrize(
        ("forwarded_host", "server"),
        [
            ("bridge.example:8443", ["bridge.example", 8443]),
            ("bridge.example", ["bridge.example", 443]),
            # Not a port: the whole value is the host, on the TLS port.
            ("bridge.example:https", ["bridge.example:https", 443]),
        ],
    )
    def test_trusted_proxy_sets_host_port_and_scheme(self, forwarded_host, server):
        resp = _request(
            _probe,
            "GET",
            "/probe",
            peer="127.0.0.1",
            headers={"X-Forwarded-Host": forwarded_host, "X-Forwarded-Proto": "https"},
        )
        assert resp.json() == {"server": server, "scheme": "https"}

    def test_direct_client_headers_are_ignored(self):
        resp = _request(
            _probe,
            "GET",
            "/probe",
            headers={
                "X-Forwarded-Host": "attacker.example:443",
                "X-Forwarded-Proto": "https",
            },
        )
        # The connection's own values (host "bridge", port 8001).
        assert resp.json() == {"server": ["bridge", 8001], "scheme": "http"}

    def test_the_gateway_secret_makes_a_peer_trusted(self, proxy_secret):
        headers = {
            "X-Forwarded-Host": "bridge.example:8443",
            "X-Forwarded-Proto": "https",
        }
        resp = _request(
            _probe,
            "GET",
            "/probe",
            headers={**headers, "X-Rust-Proxy": proxy_secret},
        )
        assert resp.json() == {"server": ["bridge.example", 8443], "scheme": "https"}
        wrong = _request(
            _probe,
            "GET",
            "/probe",
            headers={**headers, "X-Rust-Proxy": proxy_secret[:-1] + "x"},
        )
        assert wrong.json() == {"server": ["bridge", 8001], "scheme": "http"}

    @pytest.mark.parametrize("proto", ["javascript", "ftp", "https;x", ""])
    def test_only_http_or_https_becomes_the_scheme(self, proto):
        resp = _request(
            _probe,
            "GET",
            "/probe",
            peer="127.0.0.1",
            headers={"X-Forwarded-Host": "bridge.example", "X-Forwarded-Proto": proto},
        )
        assert resp.json()["scheme"] == "http"


# ---------------------------------------------------------------------------
# Request size limit
# ---------------------------------------------------------------------------


def _declared(length: int) -> dict[str, str]:
    """Headers declaring a body of *length* bytes (the body sent is tiny)."""
    return {"Content-Length": str(length), "Content-Type": "application/json"}


def _assert_bridge_refusal(resp: httpx.Response) -> None:
    """*resp* is the middleware's 413, sent as any bridge API response."""
    assert (resp.status_code, resp.text) == (413, "Request body too large")
    for name, expected in _SECURITY_HEADERS.items():
        assert expected in resp.headers.get(name, ""), (name, resp.headers)
    assert resp.headers.get("x-api-version") == API_VERSION
    assert resp.headers.get("x-correlation-id")
    assert resp.headers.get("x-request-id")


class TestRequestSizeLimit:
    def test_declared_body_over_the_limit_is_refused_before_any_route(
        self, shared_app, caplog
    ):
        caplog.set_level("INFO", logger="sigrift.bridge.app")
        # Unauthenticated: the 413 comes before auth or the body is read.
        resp = TestClient(shared_app).post(
            "/api/nodes/register", content=b"{}", headers=_declared(_LIMIT + 1)
        )
        _assert_bridge_refusal(resp)
        (logged,) = [
            r
            for r in caplog.records
            if getattr(r, "request_id", None) == resp.headers["x-request-id"]
        ]
        assert (logged.method, logged.path, logged.status_code) == (
            "POST",
            "/api/nodes/register",
            413,
        )

    def test_declared_body_at_the_limit_reaches_the_route(self, shared_app):
        resp = TestClient(shared_app).post(
            "/api/nodes/register", content=b"{}", headers=_declared(_LIMIT)
        )
        # The route's own auth answers.
        assert resp.status_code == 401

    def test_internal_routes_get_the_ingest_hook_limit(self, shared_app, proxy_secret):
        gw = TestClient(shared_app, headers={"X-Rust-Proxy": proxy_secret})
        # Above the global limit, below the hook's: the route reads the body
        # (an empty object → 422), the middleware does not refuse it.
        resp = gw.post(
            "/api/internal/ingest-hook", content=b"{}", headers=_declared(_LIMIT + 1)
        )
        assert resp.status_code == 422, resp.text
        over = gw.post(
            "/api/internal/ingest-hook",
            content=b"{}",
            headers=_declared(INGEST_HOOK_MAX_BODY + 1),
        )
        _assert_bridge_refusal(over)

    def test_the_larger_internal_limit_needs_the_gateway(
        self, shared_app, proxy_secret
    ):
        # Without the secret the prefix is refused before the size check.
        resp = TestClient(shared_app).post(
            "/api/internal/ingest-hook", content=b"{}", headers=_declared(_LIMIT + 1)
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "detail": "Internal endpoint: only the gateway may call it"
        }

    def test_chunked_body_over_the_limit_is_refused(self, shared_app):
        def _chunks() -> Iterator[bytes]:
            chunk = b" " * (1024 * 1024)
            for _ in range(_LIMIT // len(chunk)):
                yield chunk
            yield b" "

        resp = TestClient(shared_app).post(
            "/api/nodes/register",
            content=_chunks(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.request.headers.get("transfer-encoding") == "chunked"
        assert resp.status_code == 413
        assert resp.text == "Request body too large"
        # The 413 replaces the route's answer: it is still a bridge response.
        for name, expected in _SECURITY_HEADERS.items():
            assert expected in resp.headers.get(name, ""), (name, resp.headers)

    def test_chunked_body_at_the_limit_reaches_the_route(self, shared_app):
        resp = TestClient(shared_app).post(
            "/api/nodes/register",
            content=_chunked(b" " * _LIMIT, 1024 * 1024),
            headers={"Content-Type": "application/json"},
        )
        assert resp.request.headers.get("transfer-encoding") == "chunked"
        # Whitespace is not JSON: the route parsed the whole body.
        assert resp.status_code == 422, resp.text


def _chunked(body: bytes, size: int) -> Iterator[bytes]:
    """*body* as a chunked request body of *size*-byte chunks."""
    for i in range(0, len(body), size):
        yield body[i : i + size]


#: The global limit in the chunked tests below (a small one keeps them fast).
_SMALL_LIMIT = 64


@pytest.fixture
def small_limit(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(app_module, "_MAX_REQUEST_BODY", _SMALL_LIMIT)
    return _SMALL_LIMIT


def _body_reader(*, swallow: bool):
    """Inner ASGI app: reads the whole body, answers 200 with its length.

    *swallow*: catch any error of the read and answer 200 anyway (a route
    that maps it to its own status), instead of letting it escape.
    """

    async def app(scope, receive, send) -> None:
        body = b""
        try:
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
        except Exception:
            if not swallow:
                raise
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": str(len(body)).encode()})

    return app


class TestChunkedBodyLimit:
    """The counted limit, whatever the app does with the refused read."""

    @pytest.mark.parametrize("swallow", [True, False])
    def test_the_answer_is_413_whatever_the_app_does(self, small_limit, swallow):
        app = CombinedMiddleware(_body_reader(swallow=swallow))
        resp = TestClient(app).post(
            "/api/upload", content=_chunked(b"x" * (small_limit + 1), 16)
        )
        assert resp.request.headers.get("transfer-encoding") == "chunked"
        assert (resp.status_code, resp.text) == (413, "Request body too large")
        assert resp.headers["x-content-type-options"] == "nosniff"

    def test_a_body_at_the_limit_is_delivered_whole(self, small_limit):
        app = CombinedMiddleware(_body_reader(swallow=False))
        resp = TestClient(app).post(
            "/api/upload", content=_chunked(b"x" * small_limit, 16)
        )
        assert (resp.status_code, resp.text) == (200, str(small_limit))

    def test_internal_routes_count_against_the_ingest_hook_limit(
        self, shared_app, proxy_secret, small_limit, monkeypatch
    ):
        hook_limit = 4 * small_limit
        monkeypatch.setattr(
            "sigrift.bridge.routers.internal.INGEST_HOOK_MAX_BODY", hook_limit
        )
        gw = TestClient(shared_app, headers={"X-Rust-Proxy": proxy_secret})
        # Above the global limit, within the hook's: the route parses it.
        within = b"{}".ljust(hook_limit)
        resp = gw.post("/api/internal/ingest-hook", content=_chunked(within, 16))
        assert resp.status_code == 422, resp.text
        over = b"{}".ljust(hook_limit + 1)
        resp = gw.post("/api/internal/ingest-hook", content=_chunked(over, 16))
        # The middleware's refusal, not the route's own JSON 413.
        assert (resp.status_code, resp.text) == (413, "Request body too large")

    @pytest.mark.parametrize("chunked", [True, False])
    def test_an_over_limit_batch_is_not_proxied_to_uppercrust(
        self, client, small_limit, monkeypatch, caplog, chunked
    ):
        caplog.set_level("INFO", logger="sigrift.bridge.app")
        # The proxy buffers the whole body: the limit applies before it.
        upstream = _Upstream(201, b"{}")
        monkeypatch.setattr(urllib.request, "urlopen", upstream)
        body = b"{}".ljust(small_limit + 1)
        resp = client.post(
            "/api/detections/batch",
            content=_chunked(body, 16) if chunked else body,
            headers={"Content-Type": "application/json"},
        )
        assert ("transfer-encoding" in resp.request.headers) is chunked
        _assert_bridge_refusal(resp)
        assert upstream.requests == []
        # Logged like any other API request.
        (logged,) = [
            r
            for r in caplog.records
            if getattr(r, "request_id", None) == resp.headers["x-request-id"]
        ]
        assert (logged.path, logged.status_code) == ("/api/detections/batch", 413)

    def test_nothing_more_is_read_from_the_client_after_the_limit(self, small_limit):
        # A route that catches the refused read and keeps calling receive():
        # every later call is refused too, without reading on from the
        # client (neither the rest of the body nor its disconnect).
        retries: list[str] = []

        async def keeps_reading(scope, receive, send) -> None:
            while len(retries) < 3:
                try:
                    message = await receive()
                except Exception as exc:
                    retries.append(type(exc).__name__)
                    continue
                if not message.get("more_body", False):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        # 16-byte chunks (TestClient would send one message): the 5th
        # crosses the limit, then one more chunk and the client's disconnect.
        crossing = small_limit // 16 + 1
        from_client = [
            {"type": "http.request", "body": b"x" * 16, "more_body": True}
            for _ in range(crossing + 1)
        ] + [{"type": "http.disconnect"}]
        client_reads = 0

        async def receive() -> dict:
            nonlocal client_reads
            client_reads += 1
            return from_client.pop(0)

        sent: list[dict] = []

        async def send(message: dict) -> None:
            sent.append(message)

        scope = _http_scope(
            "/api/upload",
            method="POST",
            headers=[(b"transfer-encoding", b"chunked")],
        )
        asyncio.run(CombinedMiddleware(keeps_reading)(scope, receive, send))
        assert sent[0]["status"] == 413
        assert b"".join(m.get("body", b"") for m in sent[1:]) == (
            b"Request body too large"
        )
        assert retries == ["_BodyTooLarge"] * 3
        assert client_reads == crossing


# ---------------------------------------------------------------------------
# WebSocket upgrades to /api/internal/*
# ---------------------------------------------------------------------------


class TestInternalWebSocket:
    @pytest.mark.parametrize(
        "path", ["/api/internal/feed", "/api//Internal/feed", "/API/INTERNAL"]
    )
    def test_upgrade_without_the_secret_is_refused(self, shared_app, path):
        with pytest.raises(WebSocketDisconnect) as refused:
            with TestClient(shared_app).websocket_connect(path):
                pytest.fail("internal WebSocket accepted without the gateway")
        assert (refused.value.code, refused.value.reason) == (
            1008,
            "Internal endpoint",
        )

    @pytest.mark.parametrize("secret", ["", "uppercrust-internal"])
    def test_an_insecure_secret_never_matches(self, shared_app, monkeypatch, secret):
        monkeypatch.setenv("UC_PROXY_SECRET", secret)
        with pytest.raises(WebSocketDisconnect) as refused:
            with TestClient(shared_app).websocket_connect(
                "/api/internal/feed", headers={"X-Rust-Proxy": secret}
            ):
                pass
        assert refused.value.code == 1008

    def test_the_gateway_passes_the_middleware(self, shared_app, proxy_secret):
        # No internal WebSocket route exists: the router (not the
        # middleware's 1008) answers the gateway.
        with pytest.raises(WebSocketDisconnect) as closed:
            with TestClient(shared_app).websocket_connect(
                "/api/internal/feed", headers={"X-Rust-Proxy": proxy_secret}
            ):
                pass
        assert closed.value.code != 1008


# ---------------------------------------------------------------------------
# BRIDGE_REQUIRE_PROXY: loopback health-check exemption
# ---------------------------------------------------------------------------


def _call(app, scope: dict) -> list[dict]:
    """Drive *app* with a hand-built ASGI scope; return the sent messages."""
    sent: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent


def _http_scope(path: str, **extra) -> dict:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [],
        "server": ("bridge", 80),
    }
    scope.update(extra)
    return scope


class TestLoopbackExemption:
    @pytest.fixture
    def require_proxy(self, monkeypatch):
        monkeypatch.setattr(app_module, "_REQUIRE_PROXY", True)
        monkeypatch.setattr(app_module, "_PROXY_SECRET", _SECRET.encode())

    def test_a_scope_without_a_peer_is_not_loopback(self, require_proxy):
        sent = _call(_probe, _http_scope("/api/healthz"))
        assert sent[0]["status"] == 403

    # "::1%lo0": an IPv6 peer may carry a zone id.
    @pytest.mark.parametrize("peer", ["127.0.0.1", "::1", "127.8.9.10", "::1%lo0"])
    def test_a_loopback_peer_is_exempt(self, require_proxy, peer):
        sent = _call(_probe, _http_scope("/api/healthz", client=(peer, 5000)))
        assert sent[0]["status"] == 200

    @pytest.mark.parametrize("peer", ["localhost", "", "0.0.0.0", "10.0.0.1"])
    def test_other_peers_are_not(self, require_proxy, peer):
        sent = _call(_probe, _http_scope("/api/healthz", client=(peer, 5000)))
        assert sent[0]["status"] == 403


# ---------------------------------------------------------------------------
# CSRF check with a foreign-tenant session
# ---------------------------------------------------------------------------


def test_csrf_check_refuses_a_session_of_another_tenant(
    bridge_app, detection_store, persistence, master_key, monkeypatch
):
    # A session plus an API key: the middleware resolves the session to
    # decide whether the CSRF exemption of key clients applies.  A session
    # of another tenant is refused there (403), not a server error, and the
    # request does not go on to the router with the key's CSRF exemption.
    monkeypatch.setenv("BRIDGE_CSRF", "enabled")
    other = DetectionStore(detection_store.db_path, tenant_id="other")
    try:
        other.create_user("csrf-other", "fixture-password-long", role="admin")
        token = other.create_session(other.get_user("csrf-other")["id"])[
            "session_token"
        ]
    finally:
        other.close()
    actor = TestClient(
        bridge_app,
        headers={"Authorization": "Bearer " + token, "X-API-Key": master_key},
    )
    refused = (403, {"detail": "Credential belongs to another tenant"})
    resp = actor.post("/api/nodes/register", json={"node_id": "csrf-node"})
    assert (resp.status_code, resp.json()) == refused
    assert "csrf-node" not in persistence.get_nodes()
    # The route's own session auth would refuse that request the same way.
    # These two never reach an auth check of a route: a body FastAPI
    # cannot parse (answered 422 before route auth) and a path with no
    # route (404).  Only the middleware answers them with the tenant 403.
    malformed = actor.post(
        "/api/nodes/register",
        content=b"{",
        headers={"Content-Type": "application/json"},
    )
    assert (malformed.status_code, malformed.json()) == refused
    unrouted = actor.post("/api/no-such-route", json={})
    assert (unrouted.status_code, unrouted.json()) == refused


# ---------------------------------------------------------------------------
# upperCrust ingest proxy
# ---------------------------------------------------------------------------


class _UpstreamResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body
        self.headers = {"Content-Type": "application/json"}

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> bool:
        return False


class _Upstream:
    """upperCrust at the HTTP-client boundary (``urllib.request.urlopen``)."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body
        self.requests: list[urllib.request.Request] = []

    def __call__(self, req, timeout=None):
        self.requests.append(req)
        if self.status >= 400:
            raise urllib.error.HTTPError(
                req.full_url,
                self.status,
                "upstream",
                email.message.Message(),
                io.BytesIO(self.body),
            )
        return _UpstreamResponse(self.status, self.body)


def _batch(node_id: str) -> dict:
    ts = "2026-03-04T12:00:00"
    return {
        "node_id": node_id,
        "batch_id": "p-app-proxy",
        "period_start": ts,
        "period_end": ts,
        "detections": [
            {
                "node_id": node_id,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433920000.0,
                "timestamp": ts,
            }
        ],
    }


def _detection_count(store: DetectionStore) -> int:
    return (
        store.get_connection().execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    )


class TestUpperCrustProxy:
    @pytest.fixture
    def registered(self, client) -> str:
        assert (
            client.post(
                "/api/nodes/register", json={"node_id": "proxy-node"}
            ).status_code
            == 200
        )
        return "proxy-node"

    def test_an_upstream_refusal_is_the_answer(
        self, client, registered, detection_store, monkeypatch, master_key
    ):
        for status in (401, 403, 413):
            upstream = _Upstream(status, b'{"detail":"refused upstream"}')
            monkeypatch.setattr(urllib.request, "urlopen", upstream)
            resp = client.post(
                "/api/detections/batch?source=edge", json=_batch(registered)
            )
            assert resp.status_code == status
            assert resp.json() == {"detail": "refused upstream"}
            # The refused batch is not replayed to the local ingest handler.
            assert _detection_count(detection_store) == 0
            (req,) = upstream.requests
            assert req.full_url.endswith("/api/detections/batch?source=edge")
            # upperCrust authenticates the caller itself.
            assert req.get_header("X-api-key") == master_key
            assert json.loads(req.data) == _batch(registered)

    def test_a_dashboard_query_carries_the_callers_key_upstream(
        self, client, monkeypatch, master_key
    ):
        upstream = _Upstream(200, b'{"from":"uppercrust"}')
        monkeypatch.setattr(urllib.request, "urlopen", upstream)
        resp = client.get("/api/detections/stats?hours=1")
        assert (resp.status_code, resp.json()) == (200, {"from": "uppercrust"})
        (req,) = upstream.requests
        assert req.full_url.endswith("/api/detections/stats?hours=1")
        # The caller's own key (not its key id): upperCrust checks it again.
        assert req.get_header("X-api-key") == master_key

    def test_an_upstream_success_is_the_answer(
        self, client, registered, detection_store, monkeypatch
    ):
        upstream = _Upstream(201, b'{"accepted":1}')
        monkeypatch.setattr(urllib.request, "urlopen", upstream)
        resp = client.post("/api/detections/batch", json=_batch(registered))
        assert (resp.status_code, resp.json()) == (201, {"accepted": 1})
        assert _detection_count(detection_store) == 0
        assert len(upstream.requests) == 1

    def test_unauthenticated_batches_never_reach_upstream(
        self, bridge_app, registered, monkeypatch
    ):
        upstream = _Upstream(201, b"{}")
        monkeypatch.setattr(urllib.request, "urlopen", upstream)
        resp = TestClient(bridge_app).post(
            "/api/detections/batch", json=_batch(registered)
        )
        assert resp.status_code == 401
        assert upstream.requests == []


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


def _cors_app(tmp_path: Path, monkeypatch, origins: str | None) -> FastAPI:
    if origins is None:
        monkeypatch.delenv("BRIDGE_CORS_ORIGINS", raising=False)
    else:
        monkeypatch.setenv("BRIDGE_CORS_ORIGINS", origins)
    return create_test_app(tmp_path)


def _preflight(app: FastAPI, origin: str) -> httpx.Response:
    return TestClient(app).options(
        "/api/nodes",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )


class TestCors:
    def test_only_configured_origins_are_allowed(self, tmp_path, monkeypatch):
        app = _cors_app(
            tmp_path, monkeypatch, "https://ops.example, https://soc.example"
        )
        ok = _preflight(app, "https://soc.example")
        assert ok.status_code == 200
        assert ok.headers["access-control-allow-origin"] == "https://soc.example"
        assert ok.headers["access-control-allow-credentials"] == "true"

        bad = _preflight(app, "https://evil.example")
        assert bad.status_code == 400
        assert "access-control-allow-origin" not in bad.headers
        simple = TestClient(app).get(
            "/api/version", headers={"Origin": "https://evil.example"}
        )
        assert "access-control-allow-origin" not in simple.headers

    def test_no_cors_without_configuration(self, tmp_path, monkeypatch):
        app = _cors_app(tmp_path, monkeypatch, None)
        resp = TestClient(app).get(
            "/api/version", headers={"Origin": "https://ops.example"}
        )
        assert "access-control-allow-origin" not in resp.headers
        assert (
            "access-control-allow-origin"
            not in _preflight(app, "https://ops.example").headers
        )


# ---------------------------------------------------------------------------
# The production app object (no lifespan: these routes need no state)
# ---------------------------------------------------------------------------


class TestProductionApp:
    @pytest.fixture
    def prod(self) -> TestClient:
        return TestClient(app_module.app, follow_redirects=False)

    @pytest.mark.parametrize(
        "page", ["api_reference.html", "deployment_guide.html", "operations_guide.html"]
    )
    def test_documentation_redirects_only_to_the_listed_pages(self, prod, page):
        resp = prod.get(f"/documentation/{page}")
        assert resp.status_code == 307
        assert resp.headers["location"] == f"/static/docs/{page}"

    @pytest.mark.parametrize(
        "page",
        ["admin.html", "keys.json", "%2E%2E", "..%2F..%2Fadmin", "api_reference"],
    )
    def test_other_documentation_pages_are_404(self, prod, page):
        resp = prod.get(f"/documentation/{page}")
        assert resp.status_code == 404
        assert "location" not in resp.headers
        # The production assembly runs CombinedMiddleware too.
        for name, expected in _SECURITY_HEADERS.items():
            assert expected in resp.headers.get(name, ""), name
