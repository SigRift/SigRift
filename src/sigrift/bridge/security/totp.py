"""TOTP (RFC 6238) implementation using only Python stdlib.

Provides generation, computation, and verification of Time-based One-Time
Passwords without any external dependency (no pyotp).  Uses HMAC-SHA1 as
specified in the RFC.

References:
    - RFC 4226 (HOTP): https://datatracker.ietf.org/doc/html/rfc4226
    - RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import urllib.parse

_ASCII_DIGITS = frozenset("0123456789")


def generate_secret(nbytes: int = 20) -> str:
    """Generate a random base32-encoded secret.

    Parameters
    ----------
    nbytes : int
        Number of random bytes (default 20 = 160 bits, per RFC recommendation).

    Returns
    -------
    str
        Base32-encoded secret string (no padding).
    """
    raw = os.urandom(nbytes)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _decode_secret(secret: str) -> bytes:
    """Decode a base32 secret, adding padding if necessary."""
    # Add padding to make length a multiple of 8
    padded = secret.upper() + "=" * (-len(secret) % 8)
    return base64.b32decode(padded)


def compute_hotp(secret: str, counter: int, digits: int = 6) -> str:
    """Compute an HOTP value per RFC 4226.

    Parameters
    ----------
    secret : str
        Base32-encoded shared secret.
    counter : int
        Moving factor (counter value).
    digits : int
        Number of digits in the OTP (default 6).

    Returns
    -------
    str
        Zero-padded OTP string.
    """
    key = _decode_secret(secret)
    # Pack counter as 8-byte big-endian
    msg = struct.pack(">Q", counter)
    # HMAC-SHA1
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    # Dynamic truncation (RFC 4226 section 5.4)
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0]
    code_int &= 0x7FFFFFFF  # mask sign bit
    code_int %= 10**digits
    return str(code_int).zfill(digits)


def compute_totp(
    secret: str,
    timestamp: int | None = None,
    period: int = 30,
    digits: int = 6,
) -> str:
    """Compute a TOTP value per RFC 6238.

    Parameters
    ----------
    secret : str
        Base32-encoded shared secret.
    timestamp : int or None
        Unix timestamp.  Defaults to current time.
    period : int
        Time step in seconds (default 30).
    digits : int
        Number of digits in the OTP (default 6).

    Returns
    -------
    str
        Zero-padded TOTP string.
    """
    if timestamp is None:
        timestamp = int(time.time())
    counter = timestamp // period
    return compute_hotp(secret, counter, digits)


def verify_totp(
    secret: str,
    code: str,
    window: int = 1,
    timestamp: int | None = None,
    period: int = 30,
    digits: int = 6,
) -> bool:
    """Verify a TOTP code with a configurable time window.

    Parameters
    ----------
    secret : str
        Base32-encoded shared secret.
    code : str
        The OTP code to verify.
    window : int
        Number of time steps to check on either side of current
        (default 1 = check T-1, T, T+1).
    timestamp : int or None
        Unix timestamp to verify against.  Defaults to current time.
    period : int
        Time step in seconds (default 30).
    digits : int
        Number of digits in the OTP (default 6).

    Returns
    -------
    bool
        True if the code matches any time step within the window.
    """
    # compute_totp only yields ASCII digits, so nothing else can match, and
    # hmac.compare_digest raises TypeError on a non-ASCII str.  Refuse it up
    # front (str.isdigit() alone would let Arabic-Indic digits through).
    if not code or not set(code) <= _ASCII_DIGITS:
        return False

    if timestamp is None:
        timestamp = int(time.time())

    for offset in range(-window, window + 1):
        ts = timestamp + (offset * period)
        expected = compute_totp(secret, ts, period, digits)
        # Use constant-time comparison to prevent timing attacks
        if hmac.compare_digest(expected, code):
            return True
    return False


def get_provisioning_uri(
    secret: str,
    username: str,
    issuer: str = "SigRift",
    period: int = 30,
    digits: int = 6,
    algorithm: str = "SHA1",
) -> str:
    """Generate an otpauth:// URI for QR code scanning.

    Compatible with Google Authenticator, Authy, and other TOTP apps.

    Parameters
    ----------
    secret : str
        Base32-encoded shared secret.
    username : str
        The account name / username.
    issuer : str
        Issuer label (default "SigRift").
    period : int
        Time step in seconds.
    digits : int
        Number of digits.
    algorithm : str
        Hash algorithm name.

    Returns
    -------
    str
        otpauth://totp/ URI.
    """
    label = urllib.parse.quote(f"{issuer}:{username}", safe=":")
    params = urllib.parse.urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": algorithm,
            "digits": str(digits),
            "period": str(period),
        }
    )
    return f"otpauth://totp/{label}?{params}"


def generate_backup_codes(count: int = 10, length: int = 8) -> list[str]:
    """Generate a list of one-time backup codes.

    Parameters
    ----------
    count : int
        Number of codes to generate (default 10).
    length : int
        Length of each hex code (default 8 chars = 32 bits).

    Returns
    -------
    list[str]
        List of lowercase hex backup codes.
    """
    return [secrets.token_hex(length // 2) for _ in range(count)]


def hash_backup_code(code: str) -> str:
    """Hash a backup code for storage using SHA-256.

    Parameters
    ----------
    code : str
        Raw backup code.

    Returns
    -------
    str
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()
