"""Cryptographic key management for RF protocol decryption.

In-memory key store for managing protocol-specific encryption keys
used during signal analysis.  Keys are stored as mutable bytearrays
so they can be securely zeroed when no longer needed.

Supported protocols: Meshtastic, DMR, P25, generic AES/DES.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known default keys
# ---------------------------------------------------------------------------

# Meshtastic "AQ==" — single byte 0x01, meaning "use default channel key"
_MESHTASTIC_DEFAULT_AQ = base64.b64decode("AQ==")

# Meshtastic LongFast default PSK (16 bytes)
_MESHTASTIC_LONGFAST_PSK = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class CryptoKey:
    """A single cryptographic key with metadata."""

    key_id: str
    protocol: str
    algorithm: str
    key_material: bytearray
    label: str
    source: str  # "builtin", "import", or "derived"
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"CryptoKey(key_id={self.key_id!r}, protocol={self.protocol!r}, "
            f"algorithm={self.algorithm!r}, label={self.label!r}, "
            f"source={self.source!r}, key_len={len(self.key_material)})"
        )


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------


class KeyStore:
    """In-memory cryptographic key store.

    Keys are held as mutable ``bytearray`` objects so material can be
    securely zeroed on removal.  This class does NOT persist to disk:
    imported keys are saved, encrypted, by
    ``sigrift.bridge.storage.crypto_keys`` when ``BRIDGE_KEYSTORE_KEY`` is
    set (and loaded back under the same ``key_id`` at startup); built-in
    and derived keys never are.
    """

    def __init__(self) -> None:
        self._keys: dict[str, CryptoKey] = {}

    # -- public API --------------------------------------------------------

    def add_key(
        self,
        protocol: str,
        algorithm: str,
        key_material: bytes | bytearray,
        label: str,
        source: str = "import",
        metadata: dict[str, Any] | None = None,
        *,
        key_id: str | None = None,
        created_at: str | None = None,
    ) -> str:
        """Add a key to the store.  Returns its key_id.

        Without *key_id* a new uuid4 is minted, and without *created_at*
        the time is now (UTC).  A key loaded back from the database passes
        both, so it keeps the id and time it was imported with.  A given
        *key_id* must be a non-empty string of at most 128 characters that
        is not in the store yet (``ValueError`` otherwise; the key already
        there is left alone).
        """
        if key_id is None:
            key_id = str(uuid.uuid4())
        elif not isinstance(key_id, str) or not key_id or len(key_id) > 128:
            raise ValueError(
                "key_id must be a non-empty string of at most 128 characters"
            )
        elif key_id in self._keys:
            raise ValueError(f"key_id {key_id!r} is already in the store")
        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()
        elif not isinstance(created_at, str) or not created_at:
            raise ValueError("created_at must be a non-empty string")
        key = CryptoKey(
            key_id=key_id,
            protocol=protocol,
            algorithm=algorithm,
            key_material=bytearray(key_material),
            label=label,
            source=source,
            created_at=created_at,
            metadata=metadata or {},
        )
        self._keys[key_id] = key
        logger.info(
            "Added key %s for protocol=%s algorithm=%s label=%r",
            key_id,
            protocol,
            algorithm,
            label,
        )
        return key_id

    def remove_key(self, key_id: str) -> bool:
        """Remove a key, securely zeroing material first."""
        key = self._keys.pop(key_id, None)
        if key is None:
            return False
        self._zero_bytes(key.key_material)
        logger.info("Removed and zeroed key %s", key_id)
        return True

    def list_keys(self, protocol: str | None = None) -> list[dict[str, Any]]:
        """Return metadata for stored keys.  NEVER includes key_material."""
        results = []
        # A copy: an import or revoke on a request thread may change the
        # dict while a decode job iterates it.
        for key in list(self._keys.values()):
            if protocol is not None and key.protocol != protocol:
                continue
            results.append(
                {
                    "key_id": key.key_id,
                    "protocol": key.protocol,
                    "algorithm": key.algorithm,
                    "label": key.label,
                    "source": key.source,
                    "created_at": key.created_at,
                    "key_len": len(key.key_material),
                    "metadata": key.metadata,
                }
            )
        return results

    def lookup_key(self, key_id: str) -> CryptoKey | None:
        return self._keys.get(key_id)

    def lookup_by_protocol(self, protocol: str) -> list[CryptoKey]:
        return [k for k in list(self._keys.values()) if k.protocol == protocol]

    # -- import helpers ----------------------------------------------------

    def import_hex(
        self,
        hex_str: str,
        protocol: str,
        algorithm: str,
        label: str,
    ) -> str:
        """Import a key from a hex string."""
        try:
            raw = bytearray(bytes.fromhex(hex_str.replace(" ", "").replace(":", "")))
        except ValueError as exc:
            raise ValueError(
                f"Invalid hex key string for label={label!r}: {exc}"
            ) from exc
        try:
            return self.add_key(protocol, algorithm, raw, label, source="import")
        finally:
            self._zero_bytes(raw)

    def import_base64(
        self,
        b64_str: str,
        protocol: str,
        algorithm: str,
        label: str,
    ) -> str:
        """Import a key from a base64 string."""
        try:
            raw = bytearray(base64.b64decode(b64_str))
        except Exception as exc:
            raise ValueError(
                f"Invalid base64 key string for label={label!r}: {exc}"
            ) from exc
        try:
            return self.add_key(protocol, algorithm, raw, label, source="import")
        finally:
            self._zero_bytes(raw)

    # -- protocol-specific derivation --------------------------------------

    def derive_meshtastic_psk(self, channel_name: str, key_size: int = 16) -> bytes:
        """Derive a Meshtastic PSK from a channel name.

        Returns the derived key bytes and also stores it.

        Parameters
        ----------
        channel_name : str
            Channel name to derive the key from.
        key_size : int
            Key size in bytes (16 or 32).
        """
        if key_size not in (16, 32):
            raise ValueError(f"key_size must be 16 or 32, got {key_size}")
        digest = hashlib.sha256(channel_name.encode()).digest()
        psk = digest[:key_size]
        self.add_key(
            protocol="meshtastic",
            algorithm=f"aes-{key_size * 8}-ctr",
            key_material=psk,
            label=f"derived:{channel_name}",
            source="derived",
            metadata={"channel_name": channel_name},
        )
        return psk

    def load_builtin_defaults(self) -> int:
        """Load well-known default keys.  Returns count loaded."""
        count = 0

        self.add_key(
            protocol="meshtastic",
            algorithm="none",
            key_material=_MESHTASTIC_DEFAULT_AQ,
            label="meshtastic-default-AQ",
            source="builtin",
            metadata={"description": "AQ== single-byte default marker"},
        )
        count += 1

        self.add_key(
            protocol="meshtastic",
            algorithm="aes-128-ctr",
            key_material=_MESHTASTIC_LONGFAST_PSK,
            label="meshtastic-LongFast",
            source="builtin",
            metadata={"description": "LongFast channel default PSK"},
        )
        count += 1

        logger.info("Loaded %d builtin default keys", count)
        return count

    # -- internal ----------------------------------------------------------

    @staticmethod
    def _zero_bytes(b: bytearray) -> None:
        """In-place zero fill of a bytearray."""
        try:
            import ctypes

            ctypes.memset((ctypes.c_char * len(b)).from_buffer(b), 0, len(b))
        except Exception:
            b[:] = b"\x00" * len(b)

    def __len__(self) -> int:
        return len(self._keys)
