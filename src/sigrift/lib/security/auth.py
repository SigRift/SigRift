"""Socket-based authentication with constant-time comparison.

Implements a simple challenge-response authentication protocol:
1. Server sends a random 32-byte challenge.
2. Client computes HMAC-SHA256(key, challenge) and sends the 32-byte digest.
3. Server independently computes the expected digest and uses constant-time
   comparison (hmac.compare_digest) to verify.

All operations have timeouts to prevent resource exhaustion.
"""

from __future__ import annotations

import hmac
import hashlib
import logging
import secrets
import socket
import struct

logger = logging.getLogger(__name__)

_CHALLENGE_SIZE = 32
_DIGEST_SIZE = 32  # SHA-256 output


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from a socket.

    Parameters
    ----------
    sock : socket.socket
        Connected socket.
    n : int
        Number of bytes to receive.

    Returns
    -------
    bytes
        Exactly n bytes.

    Raises
    ------
    ConnectionError
        If the connection is closed before n bytes are received.
    """
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(f"Connection closed (received {len(data)}/{n} bytes)")
        data.extend(chunk)
    return bytes(data)


def authenticate_client(
    sock: socket.socket,
    expected_key: str,
    timeout: float = 5.0,
) -> bool:
    """Authenticate a client connection using challenge-response.

    Server side of the protocol:
    1. Generate and send a random challenge.
    2. Receive the client's HMAC response.
    3. Verify using constant-time comparison.

    Parameters
    ----------
    sock : socket.socket
        Connected client socket.
    expected_key : str
        Expected authentication key.
    timeout : float
        Timeout in seconds for the authentication exchange.

    Returns
    -------
    bool
        True if authentication succeeded, False otherwise.
    """
    original_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)

        # Step 1: Send challenge
        challenge = secrets.token_bytes(_CHALLENGE_SIZE)
        sock.sendall(struct.pack(f"!I{_CHALLENGE_SIZE}s", _CHALLENGE_SIZE, challenge))

        # Step 2: Receive client's HMAC response
        response = _recv_exact(sock, _DIGEST_SIZE)

        # Step 3: Compute expected response and verify (constant-time)
        expected = hmac.new(
            expected_key.encode("utf-8"),
            challenge,
            hashlib.sha256,
        ).digest()

        if hmac.compare_digest(response, expected):
            # Send success (1 byte: 0x01)
            sock.sendall(b"\x01")
            logger.debug("Client authenticated successfully")
            return True
        else:
            # Send failure (1 byte: 0x00)
            sock.sendall(b"\x00")
            logger.warning("Client authentication failed")
            return False

    except (OSError, ConnectionError) as exc:
        logger.warning("Authentication error: %s", exc)
        return False
    finally:
        try:
            sock.settimeout(original_timeout)
        except OSError:
            pass


def send_auth(
    sock: socket.socket,
    key: str,
    timeout: float = 5.0,
) -> bool:
    """Send authentication to server (client side).

    Client side of the protocol:
    1. Receive challenge from server.
    2. Compute HMAC-SHA256(key, challenge).
    3. Send the digest.
    4. Receive success/failure byte.

    Parameters
    ----------
    sock : socket.socket
        Connected socket to server.
    key : str
        Authentication key.
    timeout : float
        Timeout in seconds.

    Returns
    -------
    bool
        True if authentication succeeded, False otherwise.
    """
    original_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)

        # Step 1: Receive challenge header (4 bytes length + challenge)
        header = _recv_exact(sock, 4)
        challenge_len = struct.unpack("!I", header)[0]
        if challenge_len != _CHALLENGE_SIZE:
            logger.warning("Unexpected challenge size: %d", challenge_len)
            return False
        challenge = _recv_exact(sock, challenge_len)

        # Step 2: Compute HMAC response
        response = hmac.new(
            key.encode("utf-8"),
            challenge,
            hashlib.sha256,
        ).digest()

        # Step 3: Send response
        sock.sendall(response)

        # Step 4: Receive result
        result = _recv_exact(sock, 1)
        if result == b"\x01":
            logger.debug("Authentication succeeded")
            return True
        else:
            logger.warning("Authentication rejected by server")
            return False

    except (OSError, ConnectionError) as exc:
        logger.warning("Authentication error: %s", exc)
        return False
    finally:
        try:
            sock.settimeout(original_timeout)
        except OSError:
            pass
