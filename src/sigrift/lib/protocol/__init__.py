"""RF protocol decoder package.

Re-exports base abstractions, exception types, and all concrete decoder
classes.  The ``DECODERS`` registry maps protocol name strings to their
decoder classes for dynamic dispatch.
"""

from sigrift.lib.protocol.base import (
    CRCError,
    DecodeError,
    DecodedMessage,
    DecodedPacket,
    FECError,
    FrameSyncError,
    ProtocolDecoder,
)
from sigrift.lib.protocol.dmr import DMRDecoder
from sigrift.lib.protocol.lora_phy import LoRaPhyDecoder
from sigrift.lib.protocol.meshtastic import MeshtasticDecoder

# Registry mapping canonical protocol name to decoder class
DECODERS: dict[str, type[ProtocolDecoder]] = {
    "lora": LoRaPhyDecoder,
    "meshtastic": MeshtasticDecoder,
    "dmr": DMRDecoder,
}

__all__ = [
    # Base abstractions
    "ProtocolDecoder",
    "DecodedPacket",
    "DecodedMessage",
    # Exceptions
    "DecodeError",
    "CRCError",
    "FECError",
    "FrameSyncError",
    # Decoders
    "LoRaPhyDecoder",
    "MeshtasticDecoder",
    "DMRDecoder",
    # Registry
    "DECODERS",
]
