"""Syslog egress over real local transports (edge_syslog, syslog_forwarder).

The edge client and the bridge forwarder send RFC 5424 messages over UDP,
TCP and TLS.  These tests run them against collectors on 127.0.0.1 and
check what actually reaches the wire: octet-counted framing (RFC 5425),
structured-data escaping of untrusted RF fields, TLS certificate and host
name verification (fail closed), reconnect backoff, and the accounting of
messages that could not be sent.
"""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import queue
import re
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sigrift.bridge import edge_syslog
from sigrift.bridge import syslog_forwarder as sf
from sigrift.bridge.edge_syslog import EdgeSyslogClient
from sigrift.bridge.syslog_forwarder import (
    CEFFormatter,
    SyslogForwarder,
    _matches_filter,
    _SyslogConnection,
    format_rfc5424,
)

#: Bounds a hang only; every wait below ends as soon as its condition holds.
_WAIT = 20.0


# ---------------------------------------------------------------------------
# Local collectors and fakes
# ---------------------------------------------------------------------------


class _StreamCollector:
    """A TCP (optionally TLS) syslog collector on 127.0.0.1."""

    def __init__(self, tls: ssl.SSLContext | None) -> None:
        self._tls = tls
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._cond = threading.Condition()
        self.streams: list[bytearray] = []
        self.peer_certs: list = []
        self.eofs = 0
        self.failures = 0
        self._conns: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        self._stopping = False
        self._sock.listen()
        self._accepter = threading.Thread(target=self._accept, daemon=True)
        self._accepter.start()

    def _accept(self) -> None:
        while True:
            conn, _addr = self._sock.accept()
            if self._stopping:
                conn.close()
                return
            conn.settimeout(_WAIT)
            reader = threading.Thread(target=self._read, args=(conn,), daemon=True)
            self._conns.append(conn)
            self._threads.append(reader)
            reader.start()

    def _read(self, conn: socket.socket) -> None:
        buf = bytearray()
        with self._cond:
            self.streams.append(buf)
        try:
            if self._tls is not None:
                conn = self._tls.wrap_socket(conn, server_side=True)
                self._conns.append(conn)
                self.peer_certs.append(conn.getpeercert())
            while chunk := conn.recv(65536):
                with self._cond:
                    buf += chunk
                    self._cond.notify_all()
            with self._cond:
                self.eofs += 1
                self._cond.notify_all()
        except OSError:
            with self._cond:
                self.failures += 1
                self._cond.notify_all()
        finally:
            conn.close()

    def data(self) -> bytes:
        with self._cond:
            return b"".join(self.streams)

    def wait_until(self, predicate) -> None:
        with self._cond:
            assert self._cond.wait_for(predicate, timeout=_WAIT), "collector timeout"

    def close(self) -> None:
        self._stopping = True
        socket.create_connection(("127.0.0.1", self.port), timeout=_WAIT).close()
        self._accepter.join(_WAIT)
        for conn in self._conns:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for thread in self._threads:
            thread.join(_WAIT)
        self._sock.close()


@pytest.fixture
def stream_collector():
    collectors: list[_StreamCollector] = []

    def make(tls: ssl.SSLContext | None = None) -> _StreamCollector:
        collector = _StreamCollector(tls)
        collectors.append(collector)
        return collector

    yield make
    for collector in collectors:
        collector.close()


class _RefusingSocket(socket.socket):
    def connect(self, address) -> None:
        raise ConnectionRefusedError(111, "Connection refused")


class _Network:
    """Stands in for the ``socket`` module: connections are refused while down.

    (A bound port that does not listen is refused at once on Linux but
    only times out on macOS, so the outage is simulated here.)
    """

    def __init__(self, *, up: bool) -> None:
        self.up = up
        self.refused = 0

    def __getattr__(self, name: str):
        return getattr(socket, name)

    def socket(self, *args) -> socket.socket:
        if self.up:
            return socket.socket(*args)
        self.refused += 1
        return _RefusingSocket(*args)


@pytest.fixture
def udp_collector():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(_WAIT)
    yield sock
    sock.close()


class _Clock:
    """Stands in for the ``time`` module of the code under test."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class _FakeSocket:
    """Records what is sent; can fail sends and/or close."""

    def __init__(
        self,
        send_error: OSError | None = None,
        close_error: OSError | None = None,
    ) -> None:
        self.sent: list[bytes] = []
        self.closed = False
        self._send_error = send_error
        self._close_error = close_error

    def sendall(self, data: bytes) -> None:
        self._send(data)

    def sendto(self, data: bytes, address: tuple) -> None:
        self._send(data)

    def _send(self, data: bytes) -> None:
        if self._send_error is not None:
            raise self._send_error
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
        if self._close_error is not None:
            raise self._close_error


class _UnstartableThread(threading.Thread):
    """A thread the system cannot start (e.g. an edge node out of threads)."""

    def start(self) -> None:
        raise RuntimeError("can't start new thread")


class _IdleOnceQueue(queue.Queue):
    """A queue whose first ``get`` reports an idle poll (``queue.Empty``)."""

    def __init__(self) -> None:
        super().__init__()
        self.idle_polls = 0

    def get(self, block: bool = True, timeout: float | None = None):
        if not self.idle_polls:
            self.idle_polls += 1
            raise queue.Empty
        return super().get(block, timeout)


def _frames(data: bytes) -> list[bytes]:
    """Split an RFC 5425 octet-counted stream into its messages."""
    frames = []
    while data:
        length, _, data = data.partition(b" ")
        frames.append(data[: int(length)])
        data = data[int(length) :]
    return frames


#: RFC 5424 section 6.3: SD-ELEMENTs, whose PARAM-VALUEs escape ``"``, ``\``
#: and ``]``, then one space and the MSG.
_SD_AND_MSG = re.compile(
    r'((?:\[[^ \]"=]+(?: [^ \]"=]+="(?:[^"\\]|\\.)*")*\])+) (.*)', re.S
)


def _split_sd(rest: str) -> tuple[str, str]:
    """Split ``STRUCTURED-DATA SP MSG`` where the SD-ELEMENTs end."""
    match = _SD_AND_MSG.fullmatch(rest)
    assert match, rest
    return match.group(1), match.group(2)


def _queued(client: EdgeSyslogClient) -> list[str]:
    messages = []
    while not client._queue.empty():
        messages.append(client._queue.get_nowait())
    return messages


def _stuck_sender(client: EdgeSyslogClient):
    """Make the sender block in its first send until ``release`` is set."""
    entered, release = threading.Event(), threading.Event()
    sent: list[str] = []

    def send_message(msg: str) -> None:
        entered.set()
        release.wait(_WAIT)
        sent.append(msg)

    client._send_message = send_message  # type: ignore[method-assign]
    return entered, release, sent


# ---------------------------------------------------------------------------
# PKI: private CA, server certificate for 127.0.0.1, client certificate
# ---------------------------------------------------------------------------


def _key_usage(*, ca: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not ca,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=ca,
        crl_sign=ca,
        encipher_only=False,
        decipher_only=False,
    )


def _issue(directory: Path, name: str, ca_key, ca_cert, san, eku) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(_key_usage(ca=False), critical=True)
        .add_extension(x509.SubjectAlternativeName([san]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_ski.value
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / f"{name}.pem").write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    (directory / f"{name}.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture(scope="module")
def pki(tmp_path_factory) -> SimpleNamespace:
    directory = tmp_path_factory.mktemp("syslog-pki")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "syslog-test-ca")])
    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(_key_usage(ca=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    loopback = x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
    _issue(
        directory, "server", ca_key, ca_cert, loopback, ExtendedKeyUsageOID.SERVER_AUTH
    )
    _issue(
        directory,
        "edge-client",
        ca_key,
        ca_cert,
        x509.DNSName("edge-client"),
        ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    return SimpleNamespace(
        ca=str(directory / "ca.pem"),
        server_cert=str(directory / "server.pem"),
        server_key=str(directory / "server.key"),
        client_cert=str(directory / "edge-client.pem"),
        client_key=str(directory / "edge-client.key"),
    )


def _server_context(pki: SimpleNamespace, *, client_cert: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pki.server_cert, pki.server_key)
    ctx.load_verify_locations(pki.ca)
    ctx.verify_mode = ssl.CERT_REQUIRED if client_cert else ssl.CERT_NONE
    # No session tickets: the client then never has unread data at close.
    ctx.num_tickets = 0
    return ctx


# ---------------------------------------------------------------------------
# edge_syslog: message content
# ---------------------------------------------------------------------------


def test_edge_udp_detection_reaches_collector_with_escaped_fields(
    udp_collector: socket.socket,
) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1",
        port=udp_collector.getsockname()[1],
        protocol="udp",
        node_id="edge-01",
        facility="local3",
    )
    client.start()
    assert client.forward_detection(
        {
            "signal_class": 'ofdm"] [forged@0 x="1',
            "confidence": 0.91234,
            "freq_hz": 5.8e9,
            "snr_db": 21.5,
            "power_dbm": -40.5,
            "anomaly_score": 0.85,
            "family": "ofdm\\wifi",
            "bandwidth_hz": 2e7,
            "id": "det-7]",
        }
    )
    client.stop()
    data, _addr = udp_collector.recvfrom(65535)

    head = data.decode().split(" ", 6)
    # local3 (19) * 8 + warning (4): anomaly >= 0.8 is a warning.
    assert head[0] == "<156>1"
    assert head[2:6] == ["edge-01", "mlrf-edge", "-", "detection"]
    sd, msg = _split_sd(head[6])
    # The quote/bracket in the RF fields cannot close the element early.
    assert sd == (
        '[mlrf@0 class="ofdm\\"\\] [forged@0 x=\\"1" conf="0.9123" '
        'freq_hz="5800000000" snr_db="21.50" power_dbm="-40.50" '
        'anomaly="0.8500" node="edge-01" family="ofdm\\\\wifi" '
        'bw_hz="20000000" det_id="det-7\\]"]'
    )
    assert msg.startswith("RF detection: ")
    assert msg.endswith("at 5800.000 MHz conf=0.91 snr=21.5dB power=-40.5dBm")
    assert client.stats()["sent"] == 1


def test_edge_severity_follows_the_anomaly_score() -> None:
    client = EdgeSyslogClient(host="127.0.0.1", node_id="edge-01")
    assert client.forward_detection({"anomaly_score": 0.6})
    assert client.forward_detection({"anomaly_score": 0.2})
    assert client.forward_anomaly(
        {
            "score": 0.95,
            "signal_class": "fhss",
            "freq_hz": 915e6,
            "baseline_status": 'drift"]',
        }
    )
    assert client.forward_anomaly({"anomaly_score": 0.55})
    assert client.forward_anomaly({})
    messages = _queued(client)
    # local0 (16) * 8 + notice 5 / info 6 / warning 4
    assert [m.split(" ", 1)[0] for m in messages] == [
        "<133>1",
        "<134>1",
        "<132>1",
        "<133>1",
        "<134>1",
    ]
    head = messages[2].split(" ", 6)
    assert head[5] == "anomaly"
    sd, msg = _split_sd(head[6])
    assert sd == (
        '[mlrf@0 type="anomaly" score="0.9500" class="fhss" '
        'freq_hz="915000000" baseline="drift\\"\\]" node="edge-01"]'
    )
    assert msg == 'Anomaly score=0.9500 for fhss at 915.000 MHz baseline=drift"]'
    assert messages[4].endswith(
        "Anomaly score=0.0000 for unknown at 0.000 MHz baseline=unknown"
    )

    strict = EdgeSyslogClient(host="127.0.0.1", severity_threshold="warning")
    assert strict.forward_anomaly({"score": 0.6}) is False
    assert strict.forward_detection({"anomaly_score": 0.5}) is False
    assert strict.forward_anomaly({"score": 0.8}) is True
    assert len(_queued(strict)) == 1


def test_edge_health_report_fields_and_threshold() -> None:
    client = EdgeSyslogClient(host="127.0.0.1", node_id="edge-02")
    assert client.forward_health(
        {
            "total_received": 10,
            "total_uploaded": 7,
            "total_filtered": 2,
            "total_dropped": 1,
            "total_anomalies": 3,
            "buffer_size": 4,
        }
    )
    assert client.forward_health({})
    first, empty = _queued(client)
    head = first.split(" ", 6)
    assert head[0] == "<134>1"
    assert head[5] == "health"
    sd, msg = _split_sd(head[6])
    assert sd == (
        '[mlrf@0 type="health" node="edge-02" received="10" uploaded="7" '
        'filtered="2" dropped="1" anomalies="3" buffer="4"]'
    )
    assert msg == "Node health: received=10 uploaded=7 anomalies=3 buffer=4"
    assert empty.endswith("Node health: received=0 uploaded=0 anomalies=0 buffer=0")

    quiet = EdgeSyslogClient(host="127.0.0.1", severity_threshold="warning")
    assert quiet.forward_health({"total_received": 1}) is False
    assert quiet.stats()["queue_size"] == 0


def test_edge_unknown_severity_is_sent_as_info(caplog) -> None:
    client = EdgeSyslogClient(host="127.0.0.1")
    with caplog.at_level(logging.WARNING, logger=edge_syslog.__name__):
        assert client.send("verbose", "odd level") is True
    assert "Unknown severity 'verbose'" in caplog.text
    [message] = _queued(client)
    assert message.startswith("<134>1 ")

    # As "info", it is below a "notice" threshold.
    strict = EdgeSyslogClient(host="127.0.0.1", severity_threshold="notice")
    assert strict.send("verbose", "odd level") is False
    assert strict.stats()["queue_size"] == 0


def test_edge_full_queue_refuses_and_counts_the_drop() -> None:
    client = EdgeSyslogClient(host="127.0.0.1", max_queue_size=1)
    assert client.send("warning", "first") is True
    assert client.send("warning", "second") is False
    assert client.stats()["dropped"] == 1
    [kept] = _queued(client)
    assert kept.endswith(" first")


# ---------------------------------------------------------------------------
# edge_syslog: transports
# ---------------------------------------------------------------------------


def test_edge_start_and_stop_are_idempotent(udp_collector, caplog) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1", port=udp_collector.getsockname()[1], protocol="udp"
    )
    with caplog.at_level(logging.INFO, logger=edge_syslog.__name__):
        client.stop()  # never started: nothing to stop
        client.start()
        sender = client._sender_thread
        client.start()
        assert client._sender_thread is sender
        client.stop()
        client.stop()
    assert not sender.is_alive()
    messages = [r.getMessage() for r in caplog.records]
    started = [m for m in messages if "sender thread started" in m]
    stopped = [m for m in messages if "Syslog client stopped" in m]
    assert len(started) == 1
    assert len(stopped) == 1


def test_edge_stop_cleans_up_after_the_sender_failed_to_start(
    udp_collector, monkeypatch, caplog
) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1", port=udp_collector.getsockname()[1], protocol="udp"
    )
    with monkeypatch.context() as patch:
        patch.setattr(
            edge_syslog, "threading", SimpleNamespace(Thread=_UnstartableThread)
        )
        with pytest.raises(RuntimeError, match="can't start new thread"):
            client.start()
    sock = client._socket
    assert sock is not None  # the transport was opened before the thread failed
    with caplog.at_level(logging.INFO, logger=edge_syslog.__name__):
        # No sender to drain for: stop() neither waits for nor joins it
        # (joining a thread that never started raises) and queues nothing.
        client.stop(drain_timeout=_WAIT)
    assert client.stats()["queue_size"] == 0
    assert client._sender_thread is None
    assert client._socket is None
    assert sock.fileno() == -1
    assert "Syslog client stopped" in caplog.text

    # Once threads are available again the same client starts and delivers.
    client.start()
    assert client.send("warning", "after restart")
    data, _addr = udp_collector.recvfrom(65535)
    client.stop()
    assert data.endswith(b" after restart")
    assert client.stats()["sent"] == 1


def test_edge_tcp_frames_each_message_with_its_octet_count(stream_collector) -> None:
    collector = stream_collector()
    client = EdgeSyslogClient(
        host="127.0.0.1", port=collector.port, protocol="tcp", node_id="edge-01"
    )
    client.start()
    assert client.send("warning", "burst at 433.92 MHz: µ-sweep ✓", msg_id="rf")
    assert client.send("err", "second")
    collector.wait_until(lambda: collector.data().endswith(b" second"))
    client.stop()

    data = collector.data()
    first, second = _frames(data)
    assert data == b"".join(b"%d %s" % (len(f), f) for f in (first, second))
    # The count is in octets, not characters.
    assert len(first) > len(first.decode())
    assert first.startswith(b"<132>1 ")
    assert first.decode().endswith(
        " edge-01 mlrf-edge - rf - burst at 433.92 MHz: µ-sweep ✓"
    )
    assert second.startswith(b"<131>1 ")
    assert client.stats()["sent"] == 2
    assert client.stats()["errors"] == 0


def test_edge_tls_delivers_to_a_verified_collector(stream_collector, pki) -> None:
    collector = stream_collector(tls=_server_context(pki, client_cert=False))
    client = EdgeSyslogClient(
        host="127.0.0.1",
        port=collector.port,
        protocol="tls",
        tls_ca_bundle=pki.ca,
    )
    client.start()
    assert client.send("crit", "jammer")
    collector.wait_until(lambda: collector.data().endswith(b" jammer"))
    client.stop()
    [frame] = _frames(collector.data())
    assert frame.startswith(b"<130>1 ")
    assert client.stats()["sent"] == 1


@pytest.mark.parametrize(
    ("host", "trust_ca"),
    [
        ("127.0.0.1", False),  # issuer not trusted
        ("localhost", True),  # trusted issuer, but not issued for this name
    ],
)
def test_edge_tls_refuses_unverified_collectors(
    stream_collector, pki, caplog, host: str, trust_ca: bool
) -> None:
    collector = stream_collector(tls=_server_context(pki, client_cert=False))
    client = EdgeSyslogClient(
        host=host,
        port=collector.port,
        protocol="tls",
        tls_ca_bundle=pki.ca if trust_ca else None,
    )
    with caplog.at_level(logging.WARNING, logger=edge_syslog.__name__):
        client._connect()
    assert client._socket is None
    assert "Syslog connect failed" in caplog.text
    assert "CERTIFICATE_VERIFY_FAILED" in caplog.text
    collector.wait_until(lambda: collector.failures == 1)
    assert collector.data() == b""


def test_edge_stream_client_reconnects_when_collector_comes_up(
    stream_collector, monkeypatch
) -> None:
    collector = stream_collector()
    network = _Network(up=False)
    monkeypatch.setattr(edge_syslog, "socket", network)
    client = EdgeSyslogClient(
        host="127.0.0.1",
        port=collector.port,
        protocol="tcp",
        reconnect_base_delay=0.01,
        reconnect_max_delay=0.05,
    )
    client.start()  # collector unreachable: the connection is refused
    assert network.refused == 1
    assert client.send("warning", "queued while down")
    network.up = True
    collector.wait_until(lambda: collector.data().endswith(b"queued while down"))
    client.stop()
    assert client.stats() == {
        "sent": 1,
        "dropped": 0,
        "errors": 0,
        "reconnects": 1,
        "queue_size": 0,
    }


def test_edge_broken_stream_is_reconnected_and_resent_once(stream_collector) -> None:
    collector = stream_collector()
    client = EdgeSyslogClient(host="127.0.0.1", port=collector.port, protocol="tcp")
    client.start()
    original = client._socket
    broken = _FakeSocket(
        send_error=BrokenPipeError(32, "Broken pipe"), close_error=OSError("EBADF")
    )
    client._socket = broken
    original.close()
    assert client.send("warning", "resent once")
    collector.wait_until(lambda: collector.data().endswith(b" resent once"))
    client.stop()
    assert broken.closed
    assert broken.sent == []
    assert len(collector.streams) == 2
    assert len(_frames(collector.data())) == 1
    assert client.stats() == {
        "sent": 1,
        "dropped": 0,
        "errors": 1,
        "reconnects": 1,
        "queue_size": 0,
    }


def test_edge_failed_resend_is_counted_as_dropped(monkeypatch) -> None:
    client = EdgeSyslogClient(host="127.0.0.1", protocol="tls")
    first = _FakeSocket(send_error=ConnectionResetError(54, "reset"))
    second = _FakeSocket(send_error=OSError("still down"))
    monkeypatch.setattr(client, "_connect", lambda: setattr(client, "_socket", second))
    client._running = True
    client._socket = first
    client._send_message("<132>1 - edge - - - - lost")
    assert first.closed
    assert client._socket is second
    assert client.stats() == {
        "sent": 0,
        "dropped": 1,
        "errors": 1,
        "reconnects": 1,
        "queue_size": 0,
    }


def test_edge_stopped_stream_client_drops_without_reconnecting(monkeypatch) -> None:
    client = EdgeSyslogClient(host="127.0.0.1", protocol="tcp")
    attempts: list[int] = []
    monkeypatch.setattr(client, "_connect", lambda: attempts.append(1))
    client._send_message("<132>1 - edge - - - - no socket")
    client._socket = _FakeSocket(send_error=BrokenPipeError(32, "Broken pipe"))
    client._send_message("<132>1 - edge - - - - broken")
    assert attempts == []
    assert client.stats()["dropped"] == 2
    assert client.stats()["errors"] == 1
    assert client.stats()["sent"] == 0


def test_edge_udp_send_error_is_not_retried(monkeypatch) -> None:
    client = EdgeSyslogClient(host="127.0.0.1", protocol="udp")
    attempts: list[int] = []
    monkeypatch.setattr(client, "_connect", lambda: attempts.append(1))
    failing = _FakeSocket(send_error=OSError("network unreachable"))
    client._socket = failing
    client._send_message("<134>1 - edge - - - - udp")
    assert attempts == []
    assert client._socket is failing
    assert client.stats()["errors"] == 1
    assert client.stats()["dropped"] == 1


def test_edge_udp_socket_is_created_on_demand(udp_collector, monkeypatch) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1", port=udp_collector.getsockname()[1], protocol="udp"
    )
    client._send_message("<134>1 - edge - - - - lazily")
    data, _addr = udp_collector.recvfrom(65535)
    assert data == b"<134>1 - edge - - - - lazily"
    client._disconnect()

    # No socket can be made: the message is dropped, not raised.
    monkeypatch.setattr(client, "_connect", lambda: None)
    client._send_message("<134>1 - edge - - - - nowhere")
    assert client.stats()["sent"] == 1
    assert client.stats()["dropped"] == 1


# ---------------------------------------------------------------------------
# edge_syslog: reconnect backoff and shutdown
# ---------------------------------------------------------------------------


def test_edge_reconnect_backoff_doubles_up_to_the_cap(monkeypatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(edge_syslog, "time", clock)
    client = EdgeSyslogClient(
        host="127.0.0.1",
        protocol="tcp",
        reconnect_base_delay=1.0,
        reconnect_max_delay=4.0,
    )
    attempts: list[float] = []
    connected = _FakeSocket()

    def connect() -> None:
        attempts.append(clock.now)
        if len(attempts) == 1:
            raise OSError("resolver failure")
        if len(attempts) == 5:
            client._socket = connected

    monkeypatch.setattr(client, "_connect", connect)
    client._running = True
    client._reconnect()
    assert clock.sleeps == [1.0, 2.0, 4.0, 4.0]
    assert attempts == [1000.0, 1001.0, 1003.0, 1007.0, 1011.0]
    assert client._socket is connected
    assert client.stats()["reconnects"] == 1
    msg = "<132>1 - edge - - - - after backoff"
    client._send_message(msg)
    assert connected.sent == [f"{len(msg)} {msg}".encode()]


def test_edge_reconnect_while_draining_stops_at_the_deadline(monkeypatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(edge_syslog, "time", clock)
    client = EdgeSyslogClient(
        host="127.0.0.1", protocol="tls", reconnect_base_delay=1.0
    )
    attempts: list[float] = []
    monkeypatch.setattr(client, "_connect", lambda: attempts.append(clock.now))
    client._drain_deadline = clock.now + 2.5  # stop() is draining
    client._reconnect()
    assert clock.sleeps == [1.0, 1.5]
    assert attempts == [1000.0, 1001.0]
    assert clock.now == 1002.5
    assert client._socket is None
    assert client.stats()["reconnects"] == 0


def test_edge_sending_window_closes_at_the_drain_deadline(monkeypatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(edge_syslog, "time", clock)
    client = EdgeSyslogClient(host="127.0.0.1", protocol="tcp")
    # Never started (or fully stopped): nothing may be sent.
    assert client._drain_remaining() == float("inf")
    assert client._sending_allowed() is False
    client._running = True
    assert client._sending_allowed() is True
    # stop() draining: sending (and reconnecting) only before the deadline.
    client._running = False
    client._drain_deadline = clock.now + 3.0
    assert client._drain_remaining() == 3.0
    assert client._sending_allowed() is True
    clock.now += 3.0
    assert client._drain_remaining() == 0.0
    assert client._sending_allowed() is False


def test_edge_stop_with_full_queue_drops_the_backlog(caplog) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1", port=9, protocol="udp", max_queue_size=2
    )
    entered, release, sent = _stuck_sender(client)
    client.start()
    sender = client._sender_thread
    assert client.send("warning", "m0")
    assert entered.wait(_WAIT)
    assert client.send("warning", "m1")
    assert client.send("warning", "m2")
    assert client.send("warning", "m3") is False  # queue full
    with caplog.at_level(logging.WARNING, logger=edge_syslog.__name__):
        client.stop(drain_timeout=0)  # no room for the shutdown sentinel
        assert sender.is_alive()
        release.set()
        sender.join(_WAIT)
    assert not sender.is_alive()
    assert [m.rsplit(" ", 1)[1] for m in sent] == ["m0"]
    assert client.stats()["dropped"] == 3
    assert client.stats()["queue_size"] == 0
    assert "2 queued message(s) dropped" in caplog.text


def test_edge_drain_timeout_does_not_count_the_sentinel(caplog) -> None:
    client = EdgeSyslogClient(host="127.0.0.1", port=9, protocol="udp")
    entered, release, sent = _stuck_sender(client)
    client.start()
    sender = client._sender_thread
    assert client.send("warning", "m0")
    assert entered.wait(_WAIT)
    with caplog.at_level(logging.WARNING, logger=edge_syslog.__name__):
        client.stop(drain_timeout=0)
        release.set()
        sender.join(_WAIT)
    assert not sender.is_alive()
    assert len(sent) == 1
    assert client.stats()["dropped"] == 0
    assert client.stats()["queue_size"] == 0
    assert "drain timed out" not in caplog.text


def test_edge_idle_sender_keeps_waiting_for_messages(udp_collector) -> None:
    client = EdgeSyslogClient(
        host="127.0.0.1", port=udp_collector.getsockname()[1], protocol="udp"
    )
    client._queue = _IdleOnceQueue()
    client.start()
    assert client.send("warning", "after idle")
    data, _addr = udp_collector.recvfrom(65535)
    client.stop()
    assert data.endswith(b" after idle")
    assert client._queue.idle_polls == 1
    assert client.stats()["sent"] == 1


# ---------------------------------------------------------------------------
# syslog_forwarder: formatting and filters
# ---------------------------------------------------------------------------


def test_rfc5424_header_normalisation_and_nil_values(monkeypatch) -> None:
    msg = format_rfc5424(
        {"severity": "", "triggered_at": "2026-11-18 10:00:00+00:00"},
        hostname="bridge-1",
    )
    assert msg == (
        b"<134>1 2026-11-18T10:00:00+00:00 bridge-1 SigRift - - - "
        b"alert:  alert on unknown"
    )

    def no_hostname() -> str:
        raise OSError("hostname unavailable")

    monkeypatch.setattr(sf, "socket", SimpleNamespace(gethostname=no_hostname))
    assert SyslogForwarder()._hostname == "sigrift"
    head = format_rfc5424({"severity": "critical", "alert_id": "a1"}).split(b" ")
    assert head[0] == b"<130>1"
    assert head[2] == b"-"  # RFC 5424 NILVALUE
    assert head[5] == b"a1"


def test_cef_reason_text_and_timestamp_forms() -> None:
    base = {"node_id": "n1"}
    assert CEFFormatter.format({**base, "reasons": "jammer burst"}).endswith(
        "src=n1 msg=jammer burst"
    )
    epoch = 1_763_460_000
    assert f"rt={epoch * 1000}" in CEFFormatter.format({**base, "timestamp": epoch})
    assert f"rt={epoch * 1000 + 500}" in CEFFormatter.format(
        {**base, "timestamp": epoch + 0.5}
    )
    when = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)
    assert f"rt={int(when.timestamp() * 1000)}" in CEFFormatter.format(
        {**base, "triggered_at": when}
    )
    unparsable = CEFFormatter.format({**base, "triggered_at": "not-a-date"})
    assert "rt=" not in unparsable
    assert unparsable.endswith("|src=n1")


def test_filters_exclude_only_alerts_placed_outside_the_target() -> None:
    target = {
        "signal_class_filter": ["lora"],
        "freq_min_hz": 400e6,
        "freq_max_hz": 500e6,
        "rule_name_filter": ["jammer"],
    }
    alert = {
        "severity": "warning",
        "signal_class": "lora",
        "freq_hz": 433.92e6,
        "name": "jammer",
    }
    assert _matches_filter(alert, target)
    assert not _matches_filter({**alert, "signal_class": "fsk"}, target)
    assert not _matches_filter({**alert, "freq_hz": 315e6}, target)
    assert not _matches_filter({**alert, "freq_hz": 868e6}, target)
    assert not _matches_filter({**alert, "name": "drone"}, target)
    # Alerts without a usable frequency (Wi-Fi/BT, malformed) are not lost.
    assert _matches_filter({**alert, "freq_hz": None}, target)
    assert _matches_filter({**alert, "freq_hz": "n/a"}, target)


# ---------------------------------------------------------------------------
# syslog_forwarder: delivery
# ---------------------------------------------------------------------------


def test_udp_forward_delivers_to_matching_targets_only(udp_collector) -> None:
    port = udp_collector.getsockname()[1]
    fwd = SyslogForwarder()
    hit = fwd.add_target(
        "127.0.0.1", port=port, facility="local4", severity_filter=["critical"]
    )
    miss = fwd.add_target(
        "127.0.0.1",
        port=port,
        severity_filter=["critical"],
        signal_class_filter=["fsk"],
    )
    alert = {
        "severity": "critical",
        "alert_id": "al-1",
        "name": 'rule "x"]',
        "signal_class": "lora",
        "node_id": "edge-01",
        "freq_hz": 433920000,
        "message": "Jammer suspected",
    }
    assert fwd.forward(alert) == 1
    data, _addr = udp_collector.recvfrom(65535)
    head = data.decode().split(" ", 6)
    # local4 (20) * 8 + critical (2)
    assert head[0] == "<162>1"
    assert head[2:6] == [socket.gethostname(), "SigRift", "-", "al-1"]
    sd, msg = _split_sd(head[6])
    assert sd == (
        '[sigrift@0 signal_class="lora" freq_hz="433920000" node_id="edge-01" '
        'severity="critical" alert_id="al-1" rule_name="rule \\"x\\"\\]"]'
    )
    assert msg == "Jammer suspected"
    assert hit["delivery_count"] == 1
    assert hit["last_error"] is None
    assert hit["last_delivery"] is not None
    assert miss["delivery_count"] == 0
    assert miss["failure_count"] == 0
    # UDP is connectionless: no persistent connection is kept for it.
    assert fwd._get_connection(hit) is None
    assert fwd._connections == {}


def test_udp_send_error_is_recorded_as_a_failure(caplog) -> None:
    fwd = SyslogForwarder()
    target = fwd.add_target("127.0.0.1", port=70000, severity_filter=["warning"])
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert fwd.forward({"severity": "warning", "message": "x"}) == 0
    assert target["failure_count"] == 1
    assert target["delivery_count"] == 0
    assert target["last_error"].startswith("Send failed at ")
    assert "Syslog UDP send to 127.0.0.1:70000 failed" in caplog.text


def test_tcp_forward_frames_messages_on_one_connection(stream_collector) -> None:
    collector = stream_collector()
    fwd = SyslogForwarder()
    target = fwd.add_target(
        "127.0.0.1", port=collector.port, protocol="TCP", severity_filter=["warning"]
    )
    assert target["protocol"] == "tcp"
    for n in (1, 2):
        alert = {"severity": "warning", "alert_id": f"al-{n}", "message": f"µs {n}"}
        assert fwd.forward(alert) == 1
    collector.wait_until(lambda: collector.data().endswith(" µs 2".encode()))
    assert len(collector.streams) == 1
    frames = _frames(collector.data())
    assert [f.decode().rsplit(" ", 2)[1:] for f in frames] == [["µs", "1"], ["µs", "2"]]
    assert all(f.startswith(b"<132>1 ") for f in frames)
    assert target["delivery_count"] == 2

    conn = fwd._connections[target["id"]]
    assert conn.connected
    fwd.close_all()
    collector.wait_until(lambda: collector.eofs == 1)
    assert fwd._connections == {}
    assert not conn.connected


def test_tcp_connect_failures_back_off_then_recover(
    monkeypatch, caplog, stream_collector
) -> None:
    clock = _Clock()
    monkeypatch.setattr(sf, "time", clock)
    network = _Network(up=False)
    monkeypatch.setattr(sf, "socket", network)
    collector = stream_collector()
    port = collector.port
    fwd = SyslogForwarder()
    target = fwd.add_target(
        "127.0.0.1", port=port, protocol="tcp", severity_filter=["warning"]
    )
    alert = {"severity": "warning", "message": "after outage"}
    failed = f"Syslog connection to 127.0.0.1:{port} failed"
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert fwd.forward(alert) == 0  # refused: next attempt in 2 s
        assert caplog.text.count(failed) == 1
        clock.now += 1.5
        assert fwd.forward(alert) == 0  # too early: not even attempted
        assert caplog.text.count(failed) == 1
        assert network.refused == 1
        network.up = True
        clock.now += 0.5
        assert fwd.forward(alert) == 1
    assert target["failure_count"] == 2
    assert target["delivery_count"] == 1
    assert target["last_error"] is None
    collector.wait_until(lambda: collector.data().endswith(b" after outage"))
    fwd.close_all()


def test_tcp_reconnect_delay_doubles_up_to_five_minutes(monkeypatch) -> None:
    clock = _Clock()
    monkeypatch.setattr(sf, "time", clock)
    network = _Network(up=False)
    monkeypatch.setattr(sf, "socket", network)
    conn = _SyslogConnection("127.0.0.1", 6514)
    delays = []
    for _attempt in range(10):
        assert conn.connect() is False
        delays.append(conn._reconnect_delay)
        clock.now += conn._reconnect_delay
    assert delays == [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]
    assert network.refused == 10
    assert not conn.connected


def test_tcp_send_failure_drops_the_socket_and_reconnects(
    monkeypatch, caplog, stream_collector
) -> None:
    clock = _Clock()
    monkeypatch.setattr(sf, "time", clock)
    collector = stream_collector()
    conn = _SyslogConnection("127.0.0.1", collector.port, protocol="tcp")
    assert conn.connect()
    original = conn._sock
    broken = _FakeSocket(
        send_error=BrokenPipeError(32, "Broken pipe"), close_error=OSError("EBADF")
    )
    conn._sock = broken
    original.close()
    clock.now += 1.0
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert conn.send(b"<134>1 lost") is False
    assert f"Syslog send to 127.0.0.1:{collector.port} failed" in caplog.text
    assert broken.closed
    assert broken.sent == []
    assert conn.connected  # reconnected at once
    assert conn.send(b"<134>1 next") is True
    collector.wait_until(lambda: collector.data().endswith(b"next"))
    assert _frames(collector.data()) == [b"<134>1 next"]
    assert len(collector.streams) == 2
    conn.close()
    assert not conn.connected


def test_tls_target_refuses_an_untrusted_collector(
    stream_collector, pki, caplog
) -> None:
    collector = stream_collector(tls=_server_context(pki, client_cert=False))
    fwd = SyslogForwarder()
    target = fwd.add_target(
        "127.0.0.1", port=collector.port, protocol="tls", severity_filter=["warning"]
    )
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert fwd.forward({"severity": "warning", "message": "secret"}) == 0
    assert "CERTIFICATE_VERIFY_FAILED" in caplog.text
    assert target["failure_count"] == 1
    collector.wait_until(lambda: collector.failures == 1)
    assert collector.data() == b""
    fwd.close_all()


def test_tls_target_presents_its_client_certificate(stream_collector, pki) -> None:
    collector = stream_collector(tls=_server_context(pki, client_cert=True))
    fwd = SyslogForwarder()
    target = fwd.add_target(
        "127.0.0.1",
        port=collector.port,
        protocol="tls",
        severity_filter=["critical"],
        tls_ca_bundle=pki.ca,
        tls_client_cert=pki.client_cert,
        tls_client_key=pki.client_key,
    )
    assert fwd.forward({"severity": "critical", "message": "mutual"}) == 1
    collector.wait_until(lambda: collector.data().endswith(b" mutual"))
    [peer] = collector.peer_certs
    assert peer["subject"] == ((("commonName", "edge-client"),),)
    assert target["delivery_count"] == 1
    fwd.close_all()


# ---------------------------------------------------------------------------
# syslog_forwarder: target management
# ---------------------------------------------------------------------------


def test_update_target_protects_identity_and_rebinds_on_endpoint_change(
    stream_collector,
) -> None:
    first, second = stream_collector(), stream_collector()
    fwd = SyslogForwarder()
    target = fwd.add_target(
        "127.0.0.1", port=first.port, protocol="tcp", severity_filter=["warning"]
    )
    tid, created_at = target["id"], target["created_at"]
    assert fwd.forward({"severity": "warning", "message": "to-first"}) == 1
    conn = fwd._connections[tid]

    updated = fwd.update_target(
        tid,
        {
            "id": "forged",
            "delivery_count": 999,
            "created_at": "1970-01-01T00:00:00+00:00",
            "host": "127.0.0.1",
            "severity_filter": ["warning", "critical"],
        },
    )
    assert updated["id"] == tid
    assert updated["delivery_count"] == 1
    assert updated["created_at"] == created_at
    assert updated["severity_filter"] == ["warning", "critical"]
    assert fwd._connections[tid] is conn  # same endpoint: connection kept

    fwd.update_target(tid, {"port": second.port})
    assert tid not in fwd._connections
    first.wait_until(lambda: first.eofs == 1)
    assert fwd.forward({"severity": "critical", "message": "to-second"}) == 1
    second.wait_until(lambda: second.data().endswith(b" to-second"))
    assert b"to-second" not in first.data()
    fwd.close_all()


def test_reload_and_remove_close_connections_of_dropped_targets(
    stream_collector,
) -> None:
    first, second = stream_collector(), stream_collector()
    fwd = SyslogForwarder()
    kept = fwd.add_target(
        "127.0.0.1", port=second.port, protocol="tcp", severity_filter=["warning"]
    )
    fwd.add_target(
        "127.0.0.1", port=first.port, protocol="tcp", severity_filter=["warning"]
    )
    assert fwd.forward({"severity": "warning", "message": "both"}) == 2

    fwd.load([kept])  # configuration reloaded without the first target
    first.wait_until(lambda: first.eofs == 1)
    assert list(fwd._connections) == [kept["id"]]

    assert fwd.remove_target(kept["id"]) is True
    second.wait_until(lambda: second.eofs == 1)
    assert fwd._connections == {}
    assert fwd.forward({"severity": "warning", "message": "none"}) == 0


def test_send_test_reports_delivery_and_each_failure(
    stream_collector, monkeypatch
) -> None:
    collector = stream_collector()
    fwd = SyslogForwarder()
    ok = fwd.add_target("127.0.0.1", port=collector.port, protocol="tcp")
    down = fwd.add_target("127.0.0.1", port=6514, protocol="tcp")
    assert fwd.send_test("nope") == {"status": "failed", "error": "Target not found"}

    assert fwd.send_test(ok["id"]) == {"status": "delivered"}
    assert ok["delivery_count"] == 1
    test_message = b"SigRift syslog forwarding test message"
    collector.wait_until(lambda: collector.data().endswith(test_message))
    [frame] = _frames(collector.data())
    assert b'rule_name="syslog_test"' in frame

    monkeypatch.setattr(sf, "socket", _Network(up=False))
    assert fwd.send_test(down["id"]) == {
        "status": "failed",
        "error": "Connection or send failed",
    }
    assert down["delivery_count"] == 0

    fwd.load([{"id": "corrupt", "protocol": "udp", "port": 514}])  # no host
    assert fwd.send_test("corrupt") == {"status": "failed", "error": "'host'"}
    fwd.close_all()


# ---------------------------------------------------------------------------
# syslog_forwarder: background forwarding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_submit_drops_alerts_beyond_the_backlog_cap(monkeypatch, caplog) -> None:
    monkeypatch.setattr(sf, "_MAX_PENDING_FORWARDS", 1)
    fwd = SyslogForwarder()
    fwd.add_target("127.0.0.1", port=514)
    release = threading.Event()
    forwarded: list[str] = []

    def blocking_forward(alert: dict) -> int:
        release.wait(_WAIT)
        forwarded.append(alert["alert_id"])
        return 1

    monkeypatch.setattr(fwd, "forward", blocking_forward)
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert fwd.submit({"alert_id": "a0"}) is True
        assert fwd.pending_forwards == 1
        for n in range(1, 101):
            assert fwd.submit({"alert_id": f"a{n}"}) is False
    assert fwd.dropped == 100
    warned = [m for m in caplog.messages if "backlog full" in m]
    # The first drop and every 100th are logged.
    assert len(warned) == 2
    assert "alert a1 dropped (1 dropped so far)" in warned[0]
    assert "alert a100 dropped (100 dropped so far)" in warned[1]

    release.set()
    await fwd.stop_forwards(grace_seconds=_WAIT)
    assert forwarded == ["a0"]
    assert fwd.pending_forwards == 0


@pytest.mark.asyncio
async def test_background_forward_errors_are_logged_not_raised(
    monkeypatch, caplog
) -> None:
    fwd = SyslogForwarder()
    fwd.add_target("127.0.0.1", port=514)

    def failing_forward(alert: dict) -> int:
        raise RuntimeError("collector config corrupt")

    monkeypatch.setattr(fwd, "forward", failing_forward)
    with caplog.at_level(logging.WARNING, logger=sf.__name__):
        assert fwd.submit({"alert_id": "a0"}) is True
        [task] = list(fwd._pending)
        await fwd.stop_forwards(grace_seconds=_WAIT)
    assert task.done() and task.exception() is None
    assert "Syslog forwarding failed: collector config corrupt" in caplog.text
    assert fwd.pending_forwards == 0
    assert fwd.dropped == 0
