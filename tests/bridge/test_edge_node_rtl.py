"""Alternate edge/node.py RTL protocol checks using real loopback TCP.

The owner scanner uses rf_scan.py; these exercise the separate MQTT node daemon.
The upstream rtl_tcp server sends RTL0 + two network-order u32 values before IQ:
https://github.com/osmocom/rtl-sdr/blob/master/src/rtl_tcp.c
"""

from __future__ import annotations

from contextlib import contextmanager
import socket
import struct
import threading

import numpy as np
import pytest

from sigrift.edge.node import RTLSDRCapture

HEADER = b"RTL0" + struct.pack(">II", 5, 29)
# Independent unsigned interleaved I/Q fixture; eight exact complex samples.
PAYLOAD = bytes([0, 255, 255, 0, 0, 0, 255, 255, 128, 127, 127, 128, 64, 192, 192, 64])
EXPECTED = np.array(
    [
        -1 + 1j,
        1 - 1j,
        -1 - 1j,
        1 + 1j,
        1 / 255 - 1j / 255,
        -1 / 255 + 1j / 255,
        -127 / 255 + 129j / 255,
        129 / 255 - 127j / 255,
    ],
    dtype=np.complex64,
)


@contextmanager
def rtl_peer(header=HEADER, payload=PAYLOAD, *, fragment=False):
    """A finite server with bounded sockets/joins and explicit command bytes."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    seen = bytearray()
    errors = []
    closed = threading.Event()

    def serve():
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(3)
                if fragment:
                    for byte in header:
                        peer.sendall(bytes([byte]))
                else:
                    peer.sendall(header)
                if len(header) < 12:
                    peer.shutdown(socket.SHUT_WR)
                while len(seen) < 15:
                    data = peer.recv(15 - len(seen))
                    if not data:
                        # A rejected header/probe closes without commands. EOF
                        # ends this finite peer; never write after that close.
                        closed.set()
                        return
                    seen.extend(data)
                if len(header) == 12:
                    if fragment:
                        for byte in payload:
                            peer.sendall(bytes([byte]))
                    else:
                        peer.sendall(payload)
                    peer.shutdown(socket.SHUT_WR)
                while peer.recv(4096):
                    pass
                closed.set()
        except (BrokenPipeError, ConnectionResetError):
            # Rejection can close before the finite peer finishes its response.
            closed.set()
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=serve, name="test-rtl-peer", daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], seen, closed
    finally:
        thread.join(4)
        listener.close()
        assert not thread.is_alive(), "Owned RTL peer did not exit"
        assert not errors, errors


@pytest.mark.parametrize("fragment", [False, True])
def test_rtl_header_never_becomes_iq_and_wire_commands_match(fragment):
    with rtl_peer(fragment=fragment) as (port, commands, closed):
        capture = RTLSDRCapture("127.0.0.1", port, 2_400_000)
        capture.available = True
        actual = capture.capture(433_920_000, 8)
        assert (
            actual is not None and actual.shape == (8,) and actual.dtype == np.complex64
        )
        np.testing.assert_allclose(actual, EXPECTED, rtol=0, atol=1e-7)
        assert (
            bytes(commands)
            == b"\x01\x19\xdd\x18\x00\x02\x00\x24\x9f\x00\x03\x00\x00\x00\x00"
        )
        assert closed.wait(1)


@pytest.mark.parametrize(
    "header,payload",
    [
        (b"NOT0" + HEADER[4:], PAYLOAD),
        (HEADER[:8], b""),
        (HEADER, PAYLOAD[:4]),
        (HEADER, PAYLOAD[:5]),
    ],
    ids=["bad-magic", "short-header", "short-even-iq", "short-odd-iq"],
)
def test_rtl_rejects_wrong_protocol_or_incomplete_capture(header, payload):
    with rtl_peer(header, payload) as (port, _commands, closed):
        capture = RTLSDRCapture("127.0.0.1", port)
        capture.available = True
        assert capture.capture(433_920_000, 8) is None
        assert closed.wait(1)


def test_unavailable_capture_does_not_open_socket(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("No connection when unavailable")

    monkeypatch.setattr(socket, "socket", unexpected)
    assert RTLSDRCapture().capture(433_920_000, 8) is None


@pytest.mark.parametrize(
    "header,available",
    [(HEADER, True), (b"WRNG" + HEADER[4:], False), (HEADER[:5], False)],
)
def test_probe_validates_protocol_and_closes_owned_connection(header, available):
    with rtl_peer(header, b"") as (port, commands, closed):
        capture = RTLSDRCapture("127.0.0.1", port)
        assert capture.check_connection() is available
        assert capture.available is available
        assert not commands
        assert closed.wait(1)


@pytest.mark.parametrize("operation", ["check_connection", "capture"])
def test_refused_real_connection_is_explicitly_closed(operation, monkeypatch):
    from types import SimpleNamespace
    import sigrift.edge.node as node

    opened = []

    def tracked(*args, **kwargs):
        sock = socket.socket(*args, **kwargs)
        opened.append(sock)
        return sock

    # Bound but not listening: genuine local ECONNREFUSED, with no port race.
    with socket.socket() as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        monkeypatch.setattr(
            node,
            "socket",
            SimpleNamespace(
                socket=tracked, AF_INET=socket.AF_INET, SOCK_STREAM=socket.SOCK_STREAM
            ),
        )
        capture = RTLSDRCapture("127.0.0.1", unavailable.getsockname()[1])
        capture.available = True
        try:
            if operation == "capture":
                assert capture.capture(433_920_000, 8) is None
            else:
                assert capture.check_connection() is False
            assert len(opened) == 1 and opened[0].fileno() == -1
        finally:
            for sock in opened:
                sock.close()


def test_failed_capture_can_reconnect_on_next_attempt_without_reusing_partial_iq():
    capture = RTLSDRCapture("127.0.0.1", 0)
    capture.available = True
    with rtl_peer(HEADER, PAYLOAD[:3]) as (port, _commands, closed):
        capture.port = port
        assert capture.capture(433_920_000, 8) is None
        assert closed.wait(1)
    with rtl_peer() as (port, _commands, closed):
        capture.port = port
        np.testing.assert_allclose(
            capture.capture(433_920_000, 8), EXPECTED, rtol=0, atol=1e-7
        )
        assert closed.wait(1)
