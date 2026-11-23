"""Credential management: generation, hashing, verification.

Uses PBKDF2-HMAC-SHA256 with 600,000 iterations for password hashing
and HMAC constant-time comparison for verification to prevent timing
attacks.  Falls back gracefully when verifying legacy salted-SHA-256
hashes (64-char hex digests).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

logger = logging.getLogger(__name__)

# PBKDF2 iteration count — OWASP 2023 recommends >= 600,000 for SHA-256
_PBKDF2_ITERATIONS = 600_000
_PBKDF2_HASH = "sha256"
_PBKDF2_DKLEN = 32  # 256 bits


def generate_api_key(length: int = 32) -> str:
    """Generate a cryptographically secure API key.

    Uses ``secrets.token_urlsafe`` which produces URL-safe base64-encoded
    random bytes. The resulting string length will be approximately
    4/3 * length characters.

    Parameters
    ----------
    length : int
        Number of random bytes (not characters). Default 32 gives
        approximately 43 characters of base64 output.

    Returns
    -------
    str
        URL-safe API key string.

    Raises
    ------
    ValueError
        If length is less than 16 (minimum for security).
    """
    if length < 16:
        raise ValueError(
            f"API key length must be at least 16 bytes for security, got {length}"
        )
    return secrets.token_urlsafe(length)


def compute_lookup_hash(credential: str) -> str:
    """Compute a fast SHA-256 hash for O(1) key lookup.

    This is NOT a substitute for PBKDF2 — it is used only to index
    keys so that authentication avoids iterating all stored keys.
    The actual credential verification still uses PBKDF2.
    """
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


def hash_credential(
    credential: str,
    salt: bytes | None = None,
) -> tuple[str, bytes]:
    """Hash credential with PBKDF2-HMAC-SHA256.

    If no salt is provided, a cryptographically random 32-byte salt is
    generated.  The derived key is 256 bits with 600,000 iterations per
    OWASP recommendations.

    Parameters
    ----------
    credential : str
        The credential to hash.
    salt : bytes or None
        Salt bytes. If None, generates 32 random bytes.

    Returns
    -------
    tuple of (str, bytes)
        (hex_hash, salt) where hex_hash is the hex-encoded derived key.
    """
    if salt is None:
        salt = os.urandom(32)

    dk = hashlib.pbkdf2_hmac(
        _PBKDF2_HASH,
        credential.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
        dklen=_PBKDF2_DKLEN,
    )
    return (dk.hex(), salt)


def _verify_legacy_sha256(
    credential: str,
    expected_hash: str,
    salt: bytes,
) -> bool:
    """Verify a legacy salted-SHA-256 hash (pre-PBKDF2 migration).

    Legacy hashes are exactly 64 hex characters (SHA-256 output) and
    were computed as SHA-256(salt + credential_bytes).
    """
    h = hashlib.sha256()
    h.update(salt)
    h.update(credential.encode("utf-8"))
    return hmac.compare_digest(h.hexdigest(), expected_hash)


def verify_credential(
    credential: str,
    expected_hash: str,
    salt: bytes,
) -> bool:
    """Verify credential using constant-time comparison.

    Supports both PBKDF2-HMAC-SHA256 hashes (current) and legacy
    salted-SHA-256 hashes for backward compatibility.  Uses
    ``hmac.compare_digest`` for constant-time comparison to prevent
    timing attacks.

    Parameters
    ----------
    credential : str
        The credential to verify.
    expected_hash : str
        The expected hex-encoded hash.
    salt : bytes
        The salt used when the hash was computed.

    Returns
    -------
    bool
        True if the credential matches, False otherwise.
    """
    # Try PBKDF2 first (current format)
    computed_hash, _ = hash_credential(credential, salt=salt)
    if hmac.compare_digest(computed_hash, expected_hash):
        return True

    # Fall back to legacy salted-SHA-256 for pre-migration credentials.
    # Legacy hashes are exactly 64 hex chars (SHA-256 digest length).
    if len(expected_hash) == 64:
        if _verify_legacy_sha256(credential, expected_hash, salt):
            logger.warning(
                "Legacy SHA-256 credential matched — should be rehashed "
                "with PBKDF2 via upgrade_legacy_credential()"
            )
            return True

    return False


def upgrade_legacy_credential(
    credential: str,
) -> tuple[str, bytes, str]:
    """Rehash a legacy credential with PBKDF2 and generate a lookup hash.

    Call this after ``verify_credential`` returns True for a legacy hash.
    The caller is responsible for persisting the new hash and salt.

    Returns
    -------
    tuple of (str, bytes, str)
        (pbkdf2_hash_hex, new_salt, lookup_hash)
    """
    new_hash, new_salt = hash_credential(credential)
    lookup = compute_lookup_hash(credential)
    return new_hash, new_salt, lookup
