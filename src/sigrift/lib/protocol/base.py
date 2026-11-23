"""Base abstractions for RF protocol decoders.

Defines the common dataclasses (DecodedPacket, DecodedMessage) and the
ProtocolDecoder ABC that all protocol-specific decoders implement.
Custom exception hierarchy for decode failures: CRCError, FECError,
FrameSyncError all inherit from DecodeError.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class DecodeError(Exception):
    """Base exception for all protocol decode failures."""


class CRCError(DecodeError):
    """CRC verification failed on decoded data."""


class FECError(DecodeError):
    """Forward error correction could not recover data."""


class FrameSyncError(DecodeError):
    """Frame synchronisation pattern not found or invalid."""


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DecodedPacket:
    """A single decoded packet at the PHY/MAC layer."""

    protocol: str
    raw_bytes: bytes
    payload: bytes
    metadata: dict = field(default_factory=dict)
    timestamp: str = ""
    confidence: float = 0.0
    errors: list[str] = field(default_factory=list)


@dataclass
class DecodedMessage:
    """A higher-level decoded message extracted from one or more packets."""

    protocol: str
    source_id: str
    dest_id: str
    message_type: str
    payload: bytes
    decrypted: bool = False
    decrypted_payload: bytes | None = None
    gps_lat: float | None = None
    gps_lon: float | None = None
    gps_alt: float | None = None
    text: str | None = None
    metadata: dict = field(default_factory=dict)
    key_id: str | None = None
    confidence: float = 0.0


# ---------------------------------------------------------------------------
# Abstract base decoder
# ---------------------------------------------------------------------------


class ProtocolDecoder(ABC):
    """Abstract base class for protocol-specific decoders.

    Subclasses must implement ``protocol_name``, ``decode_packet``, and
    ``extract_messages``.
    """

    @abstractmethod
    def protocol_name(self) -> str:
        """Return the canonical protocol name string."""

    @abstractmethod
    def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
        """Decode raw bytes into a DecodedPacket.

        Parameters
        ----------
        raw : bytes
            Raw captured bytes (may include PHY-layer framing).
        **kwargs
            Protocol-specific decode options.

        Returns
        -------
        DecodedPacket

        Raises
        ------
        DecodeError
            On unrecoverable decode failure.
        """

    @abstractmethod
    def extract_messages(self, packet: DecodedPacket) -> list[DecodedMessage]:
        """Extract higher-level messages from a decoded packet.

        Parameters
        ----------
        packet : DecodedPacket
            A previously decoded packet.

        Returns
        -------
        list[DecodedMessage]
            Zero or more extracted messages.
        """
