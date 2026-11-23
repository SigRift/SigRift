"""Verify the challenge/response protocol over real bounded socket pairs."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import hmac
import socket
import struct

import pytest

from sigrift.lib.security.auth import _recv_exact, authenticate_client, send_auth


@pytest.mark.parametrize("client_key,success", [("secret-α", True), ("wrong", False)])
def test_protocol_interoperability_and_timeout_restoration(client_key, success):
    with _socket_pair() as (server, client):
        server.settimeout(3.0)
        client.settimeout(None)
        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(authenticate_client, server, "secret-α", 2.0)
            assert send_auth(client, client_key, timeout=2.0) is success
            assert accepted.result(timeout=5) is success
        assert server.gettimeout() == 3.0
        assert client.gettimeout() is None


@contextmanager
def _socket_pair():
    first, second = socket.socketpair()
    with first, second:
        yield first, second


def test_previous_challenge_response_cannot_be_replayed():
    previous_response = None
    for expected in (True, False):
        with _socket_pair() as (server, client):
            client.settimeout(2.0)
            with ThreadPoolExecutor(max_workers=1) as pool:
                accepted = pool.submit(authenticate_client, server, "replay-test", 2.0)
                size = struct.unpack("!I", _recv_exact(client, 4))[0]
                assert size == 32
                challenge = _recv_exact(client, size)
                response = (
                    previous_response
                    or hmac.new(b"replay-test", challenge, hashlib.sha256).digest()
                )
                client.sendall(response)
                assert _recv_exact(client, 1) == (b"\x01" if expected else b"\x00")
                assert accepted.result(timeout=5) is expected
                previous_response = response


def test_partial_frame_eof_reports_received_size():
    with _socket_pair() as (receiver, sender):
        receiver.settimeout(2.0)
        sender.sendall(b"ab")
        sender.shutdown(socket.SHUT_WR)
        with pytest.raises(ConnectionError, match=r"received 2/4 bytes"):
            _recv_exact(receiver, 4)


@pytest.mark.parametrize("size", [0, 31, 33, 2**32 - 1])
def test_client_rejects_wrong_challenge_length_without_responding(size):
    with _socket_pair() as (server, client):
        server.sendall(struct.pack("!I", size))
        assert send_auth(client, "key", timeout=2.0) is False
        assert client.gettimeout() is None
        server.settimeout(0.01)
        with pytest.raises(TimeoutError):
            server.recv(1)


def test_client_requires_exact_success_byte():
    with _socket_pair() as (server, client):
        server.settimeout(2.0)
        challenge = bytes(range(32))
        server.sendall(struct.pack("!I", 32) + challenge)
        with ThreadPoolExecutor(max_workers=1) as pool:
            accepted = pool.submit(send_auth, client, "key", 2.0)
            response = _recv_exact(server, 32)
            assert response == hmac.new(b"key", challenge, hashlib.sha256).digest()
            server.sendall(b"\x02")
            assert accepted.result(timeout=5) is False


@pytest.mark.parametrize("operation", [authenticate_client, send_auth])
def test_unresponsive_peer_times_out_and_restores_timeout(operation):
    with _socket_pair() as (active, silent):
        active.settimeout(3.0)
        assert operation(active, "key", timeout=0.01) is False
        assert active.gettimeout() == 3.0


@pytest.mark.parametrize("operation", [authenticate_client, send_auth])
def test_disconnected_peer_fails_closed(operation):
    with _socket_pair() as (active, disconnected):
        disconnected.close()
        assert operation(active, "key", timeout=2.0) is False
        assert active.gettimeout() is None


@pytest.mark.parametrize("operation", [authenticate_client, send_auth])
def test_closed_local_socket_does_not_mask_auth_failure(operation):
    with _socket_pair() as (closed, peer):
        closed.close()
        assert operation(closed, "key", timeout=2.0) is False
