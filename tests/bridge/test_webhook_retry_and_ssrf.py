"""Regression tests for webhook delivery hardening (review B6 and C4).

B6 (SSRF): only globally routable targets, IPv4-mapped / embedded forms
unwrapped, resolution once per delivery off the event loop, the connection
pinned to the checked address, no redirects, operator allow-list.

C4: the failed-delivery queue is bounded and retried by a background loop.
"""

from __future__ import annotations

import asyncio
import http.server
import socket
import threading
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import notifications as notif
from sigrift.bridge.notifications import (
    NotificationManager,
    WebhookHTTPError,
    _is_public_ip,
    _resolve_and_check_ip,
)


_PROXY_ENV = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
)


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Deliveries honour proxy env vars: keep the host's out of these tests."""
    for name in _PROXY_ENV:
        monkeypatch.delenv(name, raising=False)


def _gai(*addresses: str):
    """getaddrinfo stand-in returning *addresses*."""

    def fake(host, port, family=0, type=0, *args, **kwargs):  # noqa: A002
        out = []
        for addr in addresses:
            fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
            sockaddr = (addr, 0, 0, 0) if fam == socket.AF_INET6 else (addr, 0)
            out.append((fam, socket.SOCK_STREAM, 6, "", sockaddr))
        return out

    return fake


BLOCKED = [
    "0.0.0.0",  # reaches the bridge itself on Linux
    "127.0.0.1",
    "10.1.2.3",
    "172.20.0.5",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",  # CGNAT / Tailscale
    "198.18.0.1",
    "192.0.2.10",
    "224.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "fe80::1",
    "fc00::1",
    "2002:7f00:1::1",  # 6to4 of 127.0.0.1
    "64:ff9b::7f00:1",  # NAT64 of 127.0.0.1
    "64:ff9b::a00:1",  # NAT64 of 10.0.0.1
    "64:ff9b::6440:1",  # NAT64 of 100.64.0.1
    "64:ff9b::",  # NAT64 of 0.0.0.0
    "64:ff9b:1::808:808",  # local-use NAT64 prefix (RFC 8215)
    "::8.8.8.8",  # deprecated IPv4-compatible form
    "ff02::1",
]
ALLOWED = [
    "8.8.8.8",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "::ffff:8.8.8.8",
    "64:ff9b::808:808",  # NAT64 of 8.8.8.8 (IPv6-only / DNS64 sites)
    "64:ff9b::5db8:d822",  # NAT64 of 93.184.216.34
]


class TestAddressPolicy:
    @pytest.mark.parametrize("addr", BLOCKED)
    def test_non_global_addresses_blocked(self, addr: str) -> None:
        with patch.object(notif.socket, "getaddrinfo", _gai(addr)):
            with pytest.raises(ValueError, match="blocked network"):
                _resolve_and_check_ip("hook.example.com")

    @pytest.mark.parametrize("addr", ALLOWED)
    def test_global_addresses_allowed(self, addr: str) -> None:
        with patch.object(notif.socket, "getaddrinfo", _gai(addr)):
            assert _resolve_and_check_ip("hook.example.com")

    def test_one_bad_address_blocks_the_name(self) -> None:
        with patch.object(notif.socket, "getaddrinfo", _gai("8.8.8.8", "127.0.0.1")):
            with pytest.raises(ValueError):
                _resolve_and_check_ip("hook.example.com")

    def test_scoped_ipv6_is_not_public(self) -> None:
        import ipaddress

        assert not _is_public_ip(ipaddress.ip_address("fe80::1%eth0"))

    def test_allowlist_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "BRIDGE_WEBHOOK_ALLOW_HOSTS", "hooks.internal, 10.9.0.0/16 ,192.168.5.5"
        )
        with patch.object(notif.socket, "getaddrinfo", _gai("10.0.0.7")):
            assert _resolve_and_check_ip("hooks.internal.") == ["10.0.0.7"]
            with pytest.raises(ValueError):
                _resolve_and_check_ip("other.internal")
        with patch.object(notif.socket, "getaddrinfo", _gai("10.9.3.4")):
            assert _resolve_and_check_ip("x.internal") == ["10.9.3.4"]
        with patch.object(notif.socket, "getaddrinfo", _gai("192.168.5.5")):
            assert _resolve_and_check_ip("y.internal") == ["192.168.5.5"]
        # A NAT64 spelling of an allow-listed IPv4 address is allowed too.
        with patch.object(notif.socket, "getaddrinfo", _gai("64:ff9b::a09:304")):
            assert _resolve_and_check_ip("z.internal") == ["64:ff9b::a09:304"]


class _Recorder(http.server.BaseHTTPRequestHandler):
    requests: list[tuple[str, str]] = []
    status = 302

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        type(self).requests.append((self.path, self.headers.get("Host", "")))
        self.send_response(type(self).status)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST  # noqa: N815

    def log_message(self, *args) -> None:
        pass


@pytest.fixture
def local_server():
    _Recorder.requests = []
    server = http.server.HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


class TestPinnedConnection:
    def test_connects_to_pinned_address_with_original_host(self, local_server) -> None:
        port = local_server.server_address[1]
        _Recorder.status = 204
        status = NotificationManager._http_post(
            f"http://hook.example.test:{port}/in?x=1", b"{}", None, ["127.0.0.1"]
        )
        assert status == 204
        assert _Recorder.requests == [("/in?x=1", f"hook.example.test:{port}")]

    def test_redirect_is_not_followed(self, local_server) -> None:
        port = local_server.server_address[1]
        _Recorder.status = 302
        with pytest.raises(WebhookHTTPError, match="302"):
            NotificationManager._http_post(
                f"http://hook.example.test:{port}/in", b"{}", None, ["127.0.0.1"]
            )
        # Only the original request; the Location was never fetched.
        assert len(_Recorder.requests) == 1

    def test_error_status_raises(self, local_server) -> None:
        port = local_server.server_address[1]
        _Recorder.status = 500
        with pytest.raises(WebhookHTTPError, match="500"):
            NotificationManager._http_post(
                f"http://hook.example.test:{port}/in", b"{}", None, ["127.0.0.1"]
            )

    def test_without_addresses_the_url_host_is_vetted(self) -> None:
        with patch.object(notif.socket, "getaddrinfo", _gai("127.0.0.1")):
            with pytest.raises(ValueError, match="blocked network"):
                NotificationManager._http_post("http://hook.example.test/x", b"{}")

    @pytest.mark.asyncio
    async def test_dns_rebinding_cannot_redirect_the_connection(self) -> None:
        """The name is resolved once; the connect goes to the vetted address.

        The resolver answers public first and loopback afterwards.  Before
        the fix urllib resolved the name again when connecting.
        """
        answers = iter(["93.184.216.34"] + ["127.0.0.1"] * 20)
        calls: list[str] = []

        def rebinding(host, port, family=0, type=0, *a, **k):  # noqa: A002
            calls.append(host)
            return _gai(next(answers))(host, port)

        connected: list[tuple] = []

        def fake_connect(address, timeout=None, source_address=None):
            connected.append(address)
            raise ConnectionRefusedError("test: no network")

        mgr = NotificationManager()
        wh = mgr.add_webhook("http://rebind.example.test:8080/hook", ["critical"])
        with (
            patch.object(notif.socket, "getaddrinfo", rebinding),
            patch.object(notif.socket, "create_connection", fake_connect),
            patch("sigrift.bridge.notifications.asyncio.sleep", return_value=None),
        ):
            delivered = await mgr.notify({"severity": "critical", "alert_id": "r1"})
        assert delivered == 0
        assert calls == ["rebind.example.test"]
        assert connected and all(a == ("93.184.216.34", 8080) for a in connected)
        assert wh["failure_count"] == 1

    @pytest.mark.asyncio
    async def test_resolution_runs_off_the_event_loop(self) -> None:
        loop_thread = threading.get_ident()
        threads: list[int] = []

        def recording(host, port, family=0, type=0, *a, **k):  # noqa: A002
            threads.append(threading.get_ident())
            return _gai("93.184.216.34")(host, port)

        mgr = NotificationManager()
        mgr.add_webhook("https://hook.example.com/x", ["critical"])
        with (
            patch.object(notif.socket, "getaddrinfo", recording),
            patch.object(mgr, "_http_post", return_value=200),
        ):
            assert await mgr.notify({"severity": "critical"}) == 1
        assert threads and loop_thread not in threads


class TestAdminValidation:
    @pytest.mark.parametrize(
        "url",
        [
            "http://0.0.0.0:8001/",
            "http://[::ffff:127.0.0.1]:8001/",
            "http://100.64.0.1/hook",
            "http://[::]:8001/",
        ],
    )
    def test_create_webhook_refuses_internal_targets(
        self, client: TestClient, url: str
    ) -> None:
        resp = client.post("/api/admin/webhooks", json={"url": url, "name": "x"})
        assert resp.status_code == 400, resp.text
        assert "private" in resp.json()["detail"].lower()

    def test_allowlisted_internal_target_accepted(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_WEBHOOK_ALLOW_HOSTS", "10.20.30.40")
        resp = client.post(
            "/api/admin/webhooks",
            json={"url": "http://10.20.30.40:8080/h", "name": "x"},
        )
        assert resp.status_code == 201, resp.text

    def test_retry_queue_endpoint_reports_dropped(
        self, client: TestClient, bridge_app
    ) -> None:
        notifier = bridge_app.state.notifier
        notifier._retry_dropped = 3
        resp = client.get("/api/admin/webhooks/retry-queue")
        assert resp.status_code == 200
        assert resp.json()["dropped"] == 3


class TestRetryQueue:
    def test_queue_is_bounded_and_drops_oldest(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_WEBHOOK_RETRY_QUEUE_MAX", "3")
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook")
        for i in range(5):
            mgr._enqueue_failed(wh, {"n": i}, "down")
        assert [e["payload"]["n"] for e in mgr.failed_queue] == [2, 3, 4]
        assert mgr.retry_dropped == 2

    @pytest.mark.asyncio
    async def test_background_loop_retries_and_stops(self) -> None:
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", ["critical"])
        mgr._enqueue_failed(wh, {"event": "alert"}, "down")
        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1
        with (
            patch.object(
                notif, "_resolve_and_check_ip", return_value=["93.184.216.34"]
            ),
            patch.object(mgr, "_http_post", return_value=200) as post,
        ):
            mgr.start_retry_loop(interval=0.02)
            mgr.start_retry_loop(interval=0.02)  # idempotent
            task = mgr._retry_task
            try:
                deadline = time.monotonic() + 5
                # A retry removes its batch before DNS/HTTP completes. Wait
                # for the delivery result, not the temporarily empty queue.
                while wh["delivery_count"] != 1 and time.monotonic() < deadline:
                    await asyncio.sleep(0.02)
            finally:
                await mgr.stop_retry_loop()
                await mgr.stop_deliveries()
        assert mgr.failed_queue == []
        assert wh["delivery_count"] == 1
        assert post.call_args.args[3] == ["93.184.216.34"]
        assert task is not None and task.done()
        assert mgr._retry_task is None

    @pytest.mark.asyncio
    async def test_failed_retry_is_requeued_with_backoff(self) -> None:
        mgr = NotificationManager()
        wh = mgr.add_webhook("https://example.com/hook", ["critical"])
        mgr._enqueue_failed(wh, {"event": "alert"}, "down")
        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1
        with (
            patch.object(
                notif, "_resolve_and_check_ip", return_value=["93.184.216.34"]
            ),
            patch.object(mgr, "_http_post", side_effect=OSError("still down")),
        ):
            assert await mgr.retry_failed() == 0
        [entry] = mgr.failed_queue
        assert entry["attempts"] == 2
        assert entry["next_retry"] - time.monotonic() > 15


# ---------------------------------------------------------------------------
# Egress proxy: CONNECT tunnel to the vetted address
# ---------------------------------------------------------------------------


class _FakeConnectProxy:
    """A CONNECT proxy that answers the tunnelled request itself.

    Records each CONNECT target and its headers, then (optionally over TLS,
    as the webhook receiver) reads the request and answers 204.
    """

    def __init__(self, connect_status: int = 200, tls_context=None) -> None:
        self.connect_status = connect_status
        self.tls_context = tls_context
        self.connects: list[tuple[str, dict[str, str]]] = []
        self.requests: list[tuple[str, str]] = []
        self.errors: list[BaseException] = []
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @staticmethod
    def _read_head(conn) -> tuple[str, dict[str, str]]:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(1)
            if not chunk:
                raise ConnectionError("client closed")
            data += chunk
        lines = data.decode("latin-1").split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return lines[0], headers

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                with conn:
                    line, headers = self._read_head(conn)
                    self.connects.append((line, headers))
                    if self.connect_status != 200:
                        conn.sendall(
                            f"HTTP/1.1 {self.connect_status} Nope\r\n"
                            "Content-Length: 0\r\n\r\n".encode()
                        )
                        continue
                    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    stream = conn
                    if self.tls_context is not None:
                        stream = self.tls_context.wrap_socket(conn, server_side=True)
                    line, headers = self._read_head(stream)
                    body_len = int(headers.get("content-length", "0"))
                    while body_len > 0:
                        body_len -= len(stream.recv(body_len))
                    self.requests.append((line, headers.get("host", "")))
                    stream.sendall(
                        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"
                    )
            except BaseException as exc:  # recorded for the test to inspect
                self.errors.append(exc)

    def close(self) -> None:
        self._sock.close()


@pytest.fixture
def connect_proxy():
    proxies: list[_FakeConnectProxy] = []

    def make(**kwargs) -> _FakeConnectProxy:
        proxy = _FakeConnectProxy(**kwargs)
        proxies.append(proxy)
        return proxy

    yield make
    for proxy in proxies:
        proxy.close()


def _self_signed(tmp_path, hostname: str):
    """(server SSLContext, CA file) for a self-signed *hostname* cert."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )
    cert_file = tmp_path / "hook.pem"
    key_file = tmp_path / "hook.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_file, key_file)
    return server_ctx, cert_file


class TestEgressProxy:
    """Deliveries used to honour HTTP(S)_PROXY via urllib; they still do,
    but only as a CONNECT tunnel to the address that was vetted."""

    def test_http_webhook_tunnels_to_the_vetted_ip(
        self, connect_proxy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import base64

        proxy = connect_proxy()
        monkeypatch.setenv("http_proxy", f"http://alice:p%40ss@127.0.0.1:{proxy.port}")
        status = NotificationManager._http_post(
            "http://hook.example.test/in?x=1", b"{}", None, ["93.184.216.34"]
        )
        assert status == 204
        [(line, headers)] = proxy.connects
        assert line == "CONNECT 93.184.216.34:80 HTTP/1.1"
        assert headers["proxy-authorization"] == (
            "Basic " + base64.b64encode(b"alice:p@ss").decode()
        )
        assert proxy.requests == [("POST /in?x=1 HTTP/1.1", "hook.example.test")]

    def test_ipv6_target_is_bracketed(
        self, connect_proxy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proxy = connect_proxy()
        monkeypatch.setenv("HTTP_PROXY", f"127.0.0.1:{proxy.port}")  # no scheme
        NotificationManager._http_post(
            "http://hook.example.test:8080/in", b"{}", None, ["2606:4700::1111"]
        )
        assert proxy.connects[0][0] == "CONNECT [2606:4700::1111]:8080 HTTP/1.1"
        assert proxy.requests[0][1] == "hook.example.test:8080"

    def test_https_through_proxy_verifies_the_url_host(
        self, connect_proxy, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        server_ctx, ca_file = _self_signed(tmp_path, "hook.example.test")
        proxy = connect_proxy(tls_context=server_ctx)
        monkeypatch.setenv("https_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("BRIDGE_CA_BUNDLE", str(ca_file))
        status = NotificationManager._http_post(
            "https://hook.example.test/in", b"{}", None, ["93.184.216.34"]
        )
        assert status == 204, proxy.errors
        assert proxy.connects[0][0] == "CONNECT 93.184.216.34:443 HTTP/1.1"
        assert proxy.requests == [("POST /in HTTP/1.1", "hook.example.test")]

    def test_no_proxy_connects_directly(
        self, connect_proxy, local_server, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proxy = connect_proxy()
        port = local_server.server_address[1]
        _Recorder.status = 204
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        monkeypatch.setenv("no_proxy", ".example.test")
        NotificationManager._http_post(
            f"http://hook.example.test:{port}/in", b"{}", None, ["127.0.0.1"]
        )
        assert proxy.connects == []
        assert _Recorder.requests == [("/in", f"hook.example.test:{port}")]

    def test_refused_connect_is_a_failed_delivery(
        self, connect_proxy, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        proxy = connect_proxy(connect_status=407)
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        with pytest.raises(OSError, match="proxy refused CONNECT"):
            NotificationManager._http_post(
                "http://hook.example.test/in", b"{}", None, ["93.184.216.34"]
            )
        assert proxy.requests == []

    def test_unsupported_proxy_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("https_proxy", "socks5://127.0.0.1:1080")
        with pytest.raises(ValueError, match="only http:// proxies"):
            NotificationManager._http_post(
                "https://hook.example.test/in", b"{}", None, ["93.184.216.34"]
            )


class _OneShotProxy:
    """Accepts one ``CONNECT``, answers *reply* and closes the connection."""

    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.received = b""
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        with self._sock:
            conn, _ = self._sock.accept()
            with conn:
                while b"\r\n\r\n" not in self.received:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    self.received += chunk
                conn.sendall(self.reply)

    def join(self) -> None:
        self._thread.join(5)
        assert not self._thread.is_alive()


class TestProxyConnectBounds:
    """A proxy that never finishes its ``CONNECT`` answer fails the delivery
    (the answer is read with a bound); nothing is sent through it."""

    @pytest.mark.parametrize(
        ("reply", "error"),
        [
            (b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 17_000, "too long"),
            (b"HTTP/1.1 200 OK\r\n", "closed the connection"),
        ],
        ids=["endless-head", "closed-mid-head"],
    )
    def test_unfinished_connect_answer_fails_the_delivery(
        self, monkeypatch: pytest.MonkeyPatch, reply: bytes, error: str
    ) -> None:
        proxy = _OneShotProxy(reply)
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.port}")
        with pytest.raises(OSError, match=error):
            NotificationManager._http_post(
                "http://hook.example.test/in", b"{}", None, ["93.184.216.34"]
            )
        proxy.join()
        assert proxy.received.startswith(b"CONNECT 93.184.216.34:80 HTTP/1.1\r\n")
        assert b"POST" not in proxy.received


class TestDeliveryTimeUrlChecks:
    """The URL is checked again when a webhook is delivered to: a stored URL
    that skipped the admin API's validation (a hand-edited webhooks.json, a
    restored snapshot) is never connected to."""

    @staticmethod
    def _no_connections(monkeypatch: pytest.MonkeyPatch) -> list:
        connected: list = []

        def connect(address, *args, **kwargs):
            connected.append(address)
            raise ConnectionRefusedError("test: no network")

        monkeypatch.setattr(notif.socket, "getaddrinfo", _gai("93.184.216.34"))
        monkeypatch.setattr(notif.socket, "create_connection", connect)
        return connected

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("url", "error"),
        [
            ("ftp://hook.example.test/in", "must use http or https"),
            ("file://hook.example.test/etc/passwd", "must use http or https"),
            ("http:///in", "has no host"),
            ("http://hook.example.test:6379/in", "Port 6379 is blocked"),
        ],
    )
    async def test_stored_url_failing_the_checks_reaches_no_host(
        self, monkeypatch: pytest.MonkeyPatch, url: str, error: str
    ) -> None:
        connected = self._no_connections(monkeypatch)
        monkeypatch.setattr(notif, "_RETRY_DELAY_SECONDS", 0)
        mgr = NotificationManager()
        wh = mgr.add_webhook(url, severity_filter=["critical"])
        assert await mgr.notify({"severity": "critical", "alert_id": "u1"}) == 0
        assert connected == []
        assert wh["failure_count"] == 1
        [entry] = mgr.delivery_log
        assert entry["success"] is False
        assert error in entry["error"]

    @pytest.mark.parametrize(
        ("url", "error"),
        [
            ("ftp://hook.example.test/in", "must use http or https"),
            ("http:///in", "has no host"),
            ("http://hook.example.test:6379/in", "Port 6379 is blocked"),
        ],
    )
    def test_vetted_addresses_do_not_bypass_the_url_checks(
        self, monkeypatch: pytest.MonkeyPatch, url: str, error: str
    ) -> None:
        connected = self._no_connections(monkeypatch)
        with pytest.raises(ValueError, match=error):
            NotificationManager._http_post(url, b"{}", None, ["93.184.216.34"])
        assert connected == []
