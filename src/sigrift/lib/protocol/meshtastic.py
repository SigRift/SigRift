"""Meshtastic mesh protocol decoder.

Decodes Meshtastic packets including MAC header parsing, manual protobuf
field extraction (no protobuf dependency), AES-CTR decryption with known
keys, and extraction of position, text, telemetry, and node-info payloads.

Reference: Meshtastic protocol specification
https://meshtastic.org/docs/overview/mesh-algo
"""

from __future__ import annotations

import logging
import struct
from datetime import datetime, timezone

from sigrift.lib.crypto.aes_decrypt import build_meshtastic_nonce
from sigrift.lib.protocol.base import (
    DecodeError,
    DecodedMessage,
    DecodedPacket,
    ProtocolDecoder,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# MAC header: 16 bytes total
#   dest       (4 bytes, LE uint32)
#   source     (4 bytes, LE uint32)
#   packet_id  (4 bytes, LE uint32)
#   flags      (1 byte)
#   channel_hash (1 byte)
#   padding    (2 bytes)
_MAC_HEADER_SIZE = 16
_MAC_HEADER_FMT = "<III B B 2x"

# Portnum values (subset — most commonly seen on air)
PORTNUM_TEXT = 1
PORTNUM_POSITION = 3
PORTNUM_NODEINFO = 4
PORTNUM_TELEMETRY = 67

_PORTNUM_NAMES = {
    PORTNUM_TEXT: "TEXT_MESSAGE",
    PORTNUM_POSITION: "POSITION",
    PORTNUM_NODEINFO: "NODEINFO",
    PORTNUM_TELEMETRY: "TELEMETRY",
}

# PortNum enum values are 0..511 (PortNum.MAX = 511); 0 is UNKNOWN_APP.
_PORTNUM_MAX = 511

# ``Data`` message (meshtastic/mesh.proto): field number -> wire type.
#   1 portnum (PortNum enum, varint)   2 payload (bytes)
#   3 want_response (bool, varint)     4 dest (fixed32)
#   5 source (fixed32)                 6 request_id (fixed32)
#   7 reply_id (fixed32)               8 emoji (fixed32)
#   9 bitfield (uint32, varint)
_WT_VARINT = 0
_WT_FIXED64 = 1
_WT_LEN = 2
_WT_FIXED32 = 5
_DATA_FIELD_WIRE_TYPES = {
    1: _WT_VARINT,
    2: _WT_LEN,
    3: _WT_VARINT,
    4: _WT_FIXED32,
    5: _WT_FIXED32,
    6: _WT_FIXED32,
    7: _WT_FIXED32,
    8: _WT_FIXED32,
    9: _WT_VARINT,
}

_crypto_missing_warned = False


# ---------------------------------------------------------------------------
# Protobuf helpers (manual — no external dependency)
# ---------------------------------------------------------------------------


def _decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a protobuf varint starting at *offset*.

    Returns
    -------
    tuple[int, int]
        (value, new_offset)

    Raises
    ------
    DecodeError
        If the varint is truncated or longer than 10 bytes.
    """
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, offset
        shift += 7
        if shift > 63:
            raise DecodeError("varint too long")
    raise DecodeError("truncated varint")


def _to_int32(n: int) -> int:
    """Reinterpret a varint/fixed32 value as a two's-complement int32.

    Negative ``int32`` values travel as 10-byte sign-extended varints and
    ``sfixed32`` values as raw 32-bit words; both reduce to the low 32 bits.
    """
    n &= 0xFFFFFFFF
    return n - (1 << 32) if n & 0x80000000 else n


def _parse_protobuf_fields(
    data: bytes, *, strict: bool = False
) -> list[tuple[int, int, bytes | int]]:
    """Parse raw protobuf fields into (field_number, wire_type, value) tuples.

    Handles wire types 0 (varint), 1 (64-bit fixed), 2 (length-delimited)
    and 5 (32-bit fixed).

    Parameters
    ----------
    data : bytes
        Serialized protobuf message.
    strict : bool
        When False (default) parsing stops quietly at the first malformed
        field and the fields decoded so far are returned -- this never
        raises.  When True any malformation (truncated or over-long varint,
        field number 0, unknown wire type, length running past the buffer)
        raises :class:`DecodeError`, so a successful return means the whole
        buffer was consumed exactly.

    Returns
    -------
    list[tuple[int, int, bytes | int]]
        Each entry is (field_number, wire_type, value).
        Varint values are ints; length-delimited values are bytes;
        fixed values are unsigned ints.
    """
    fields: list[tuple[int, int, bytes | int]] = []
    offset = 0

    try:
        while offset < len(data):
            tag, offset = _decode_varint(data, offset)
            field_number = tag >> 3
            wire_type = tag & 0x07
            if field_number == 0:
                raise DecodeError("protobuf field number 0")

            if wire_type == _WT_VARINT:
                val, offset = _decode_varint(data, offset)
                fields.append((field_number, wire_type, val))

            elif wire_type == _WT_LEN:
                length, offset = _decode_varint(data, offset)
                if offset + length > len(data):
                    raise DecodeError("length-delimited field overruns buffer")
                fields.append((field_number, wire_type, data[offset : offset + length]))
                offset += length

            elif wire_type == _WT_FIXED32:
                if offset + 4 > len(data):
                    raise DecodeError("truncated fixed32")
                val = struct.unpack_from("<I", data, offset)[0]
                fields.append((field_number, wire_type, val))
                offset += 4

            elif wire_type == _WT_FIXED64:
                if offset + 8 > len(data):
                    raise DecodeError("truncated fixed64")
                val = struct.unpack_from("<Q", data, offset)[0]
                fields.append((field_number, wire_type, val))
                offset += 8

            else:
                # Groups (3/4) and 6/7: cannot determine the length.
                raise DecodeError(f"unsupported protobuf wire type {wire_type}")
    except DecodeError as exc:
        if strict:
            raise
        logger.debug("Protobuf parse stopped at offset %d: %s", offset, exc)

    return fields


def parse_data_message(plaintext: bytes) -> dict | None:
    """Strictly parse a Meshtastic ``Data`` protobuf.

    This is the acceptance test for trial decryption: AES-CTR "decrypts"
    with any key, so a key is only considered correct when the *whole*
    plaintext is a well-formed ``Data`` message -- every field is a known
    ``Data`` field with its declared wire type, the field lengths consume
    the buffer exactly, and ``portnum`` (field 1) is present and in range.

    Parameters
    ----------
    plaintext : bytes
        Candidate decrypted payload (the bytes after the 16-byte header).

    Returns
    -------
    dict or None
        Keys ``portnum``, ``portnum_name``, ``payload``, ``want_response``,
        ``dest``, ``source``, ``request_id``, ``reply_id``, ``emoji``,
        ``bitfield`` -- or None if *plaintext* is not a valid ``Data``.
    """
    if not plaintext:
        return None
    try:
        fields = _parse_protobuf_fields(plaintext, strict=True)
    except DecodeError:
        return None

    portnum: int | None = None
    for field_num, wire_type, value in fields:
        if _DATA_FIELD_WIRE_TYPES.get(field_num) != wire_type:
            return None
        if field_num == 1:
            portnum = value  # type: ignore[assignment]

    if portnum is None or not (1 <= portnum <= _PORTNUM_MAX):
        return None
    return _data_fields_to_dict(fields)


def _data_fields_to_dict(fields: list[tuple[int, int, bytes | int]]) -> dict:
    """Map parsed ``Data`` fields onto a result dict (last value wins)."""
    result: dict = {
        "portnum": 0,
        "portnum_name": "UNKNOWN",
        "payload": b"",
        "want_response": False,
        "dest": None,
        "source": None,
        "request_id": None,
        "reply_id": None,
        "emoji": None,
        "bitfield": None,
    }
    fixed32_names = {4: "dest", 5: "source", 6: "request_id", 7: "reply_id", 8: "emoji"}
    for field_num, wire_type, value in fields:
        if _DATA_FIELD_WIRE_TYPES.get(field_num) != wire_type:
            continue
        if field_num == 1:
            result["portnum"] = value
            result["portnum_name"] = _PORTNUM_NAMES.get(value, f"UNKNOWN_{value}")
        elif field_num == 2:
            result["payload"] = value
        elif field_num == 3:
            result["want_response"] = bool(value)
        elif field_num in fixed32_names:
            result[fixed32_names[field_num]] = value
        elif field_num == 9:
            result["bitfield"] = value
    return result


# ---------------------------------------------------------------------------
# MeshtasticDecoder
# ---------------------------------------------------------------------------


class MeshtasticDecoder(ProtocolDecoder):
    """Meshtastic protocol decoder."""

    def __init__(self, keys: list[bytes] | None = None) -> None:
        """
        Parameters
        ----------
        keys : list[bytes] or None
            AES-128 or AES-256 keys to attempt for decryption.
            Default key is the well-known Meshtastic default channel key.
        """
        if keys is not None:
            self._keys = list(keys)
        else:
            # Default Meshtastic channel key (AES-128, base64 "1PG7OiApB1nwvP+rz05pAQ==")
            self._keys = [
                b"\xd4\xf1\xbb\x3a\x20\x29\x07\x59\xf0\xbc\xff\xab\xcf\x4e\x69\x01"
            ]

    def protocol_name(self) -> str:
        return "meshtastic"

    # -- MAC header ---------------------------------------------------------

    @staticmethod
    def decode_mac_header(payload: bytes) -> dict:
        """Parse the 16-byte Meshtastic MAC header.

        Parameters
        ----------
        payload : bytes
            At least 16 bytes of packet data.

        Returns
        -------
        dict
            Keys: ``dest``, ``source``, ``packet_id``, ``flags``,
            ``channel_hash``, ``hop_limit``, ``want_ack``.
        """
        if len(payload) < _MAC_HEADER_SIZE:
            raise DecodeError(
                f"MAC header requires {_MAC_HEADER_SIZE} bytes, got {len(payload)}"
            )

        dest, source, packet_id, flags, channel_hash = struct.unpack_from(
            _MAC_HEADER_FMT, payload
        )

        # Flags byte: bits 0-2 = hop_limit, bit 3 = want_ack
        hop_limit = flags & 0x07
        want_ack = bool(flags & 0x08)

        return {
            "dest": dest,
            "source": source,
            "packet_id": packet_id,
            "flags": flags,
            "channel_hash": channel_hash,
            "hop_limit": hop_limit,
            "want_ack": want_ack,
        }

    # -- Protobuf decode (MeshPacket.decoded fields) ------------------------

    @staticmethod
    def decode_protobuf(payload: bytes) -> dict:
        """Leniently parse the inner protobuf payload (Data message).

        Extracts the ``Data`` fields from a Meshtastic Data protobuf without
        requiring the protobuf library.  Malformed trailing bytes are
        ignored; use :func:`parse_data_message` for a strict validity check.

        Field mapping (from meshtastic.mesh.proto Data message):
          1: portnum (varint)        2: payload (bytes)
          3: want_response (bool)    4: dest (fixed32)
          5: source (fixed32)        6: request_id (fixed32)
          7: reply_id (fixed32)      8: emoji (fixed32)
          9: bitfield (uint32)

        The hop limit is not part of ``Data``; it lives in the cleartext
        radio header (see :meth:`decode_mac_header`).

        Parameters
        ----------
        payload : bytes
            Protobuf-encoded Data message.

        Returns
        -------
        dict
            Keys: ``portnum``, ``portnum_name``, ``payload``,
            ``want_response``, ``dest``, ``source``, ``request_id``,
            ``reply_id``, ``emoji``, ``bitfield``.
        """
        return _data_fields_to_dict(_parse_protobuf_fields(payload))

    # -- Position extraction ------------------------------------------------

    @staticmethod
    def extract_position(data: bytes) -> dict:
        """Extract GPS position from a Position protobuf.

        Field mapping (Position message, meshtastic/mesh.proto):
          1: latitude_i  (sfixed32, degrees * 1e7)
          2: longitude_i (sfixed32, degrees * 1e7)
          3: altitude    (int32 varint, metres MSL)
          4: time        (fixed32, unix epoch seconds)

        Parameters
        ----------
        data : bytes
            Protobuf-encoded Position message.

        Returns
        -------
        dict
            Keys: ``latitude``, ``longitude``, ``altitude``, ``time``.
            Lat/lon are in decimal degrees (divided by 1e7).
        """
        fields = _parse_protobuf_fields(data)
        result: dict = {
            "latitude": None,
            "longitude": None,
            "altitude": None,
            "time": None,
        }

        for field_num, wire_type, value in fields:
            if field_num == 1 and wire_type == _WT_FIXED32:
                result["latitude"] = _to_int32(value) / 1e7  # type: ignore[arg-type]
            elif field_num == 2 and wire_type == _WT_FIXED32:
                result["longitude"] = _to_int32(value) / 1e7  # type: ignore[arg-type]
            elif field_num == 3 and wire_type == _WT_VARINT:
                result["altitude"] = _to_int32(value)  # type: ignore[arg-type]
            elif field_num == 4 and wire_type == _WT_FIXED32:
                result["time"] = value

        return result

    # -- Text extraction ----------------------------------------------------

    @staticmethod
    def extract_text(data: bytes) -> str:
        """Decode a text message payload.

        Parameters
        ----------
        data : bytes
            Raw text payload (UTF-8).

        Returns
        -------
        str
        """
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return data.hex()

    # -- Telemetry extraction -----------------------------------------------

    @staticmethod
    def extract_telemetry(data: bytes) -> dict:
        """Extract device telemetry from a Telemetry protobuf.

        Field mapping (DeviceMetrics, nested in Telemetry field 2):
          1: battery_level (uint32, percent)
          2: voltage (float, fixed32)
          3: channel_utilization (float, fixed32)

        Parameters
        ----------
        data : bytes
            Protobuf-encoded Telemetry message.

        Returns
        -------
        dict
            Keys: ``battery``, ``voltage``, ``channel_utilization``.
        """
        result: dict = {
            "battery": None,
            "voltage": None,
            "channel_utilization": None,
        }

        fields = _parse_protobuf_fields(data)

        # Telemetry wraps DeviceMetrics in field 2 (length-delimited)
        metrics_data = None
        for field_num, wire_type, value in fields:
            if field_num == 2 and wire_type == 2:
                metrics_data = value
                break

        if metrics_data is None:
            # Maybe the data IS the DeviceMetrics directly
            metrics_data = data

        metrics_fields = _parse_protobuf_fields(metrics_data)
        for field_num, wire_type, value in metrics_fields:
            if field_num == 1 and wire_type == 0:
                result["battery"] = value
            elif field_num == 2 and wire_type == 5:
                # Fixed32 float
                result["voltage"] = struct.unpack("<f", struct.pack("<I", value))[0]
            elif field_num == 3 and wire_type == 5:
                result["channel_utilization"] = struct.unpack(
                    "<f", struct.pack("<I", value)
                )[0]

        return result

    # -- NodeInfo extraction ------------------------------------------------

    @staticmethod
    def extract_nodeinfo(data: bytes) -> dict:
        """Extract node information from a User protobuf.

        Field mapping (User message, meshtastic/mesh.proto):
          1: id (string)
          2: long_name (string)
          3: short_name (string)
          5: hw_model (varint enum)

        Parameters
        ----------
        data : bytes
            Protobuf-encoded User message.

        Returns
        -------
        dict
            Keys: ``id``, ``long_name``, ``short_name``, ``hw_model``.
        """
        fields = _parse_protobuf_fields(data)
        result: dict = {
            "id": None,
            "long_name": None,
            "short_name": None,
            "hw_model": None,
        }

        for field_num, wire_type, value in fields:
            if field_num == 1 and wire_type == 2:
                result["id"] = value.decode("utf-8", errors="replace")
            elif field_num == 2 and wire_type == 2:
                result["long_name"] = value.decode("utf-8", errors="replace")
            elif field_num == 3 and wire_type == 2:
                result["short_name"] = value.decode("utf-8", errors="replace")
            elif field_num == 5 and wire_type == _WT_VARINT:
                result["hw_model"] = value

        return result

    # -- AES-CTR decryption -------------------------------------------------

    @staticmethod
    def decrypt_payload(
        encrypted: bytes,
        packet_id: int,
        source_node: int,
        keys: list[bytes],
    ) -> bytes | None:
        """Attempt AES-CTR decryption with each key.

        Nonce construction follows firmware ``CryptoEngine::initNonce``
        (see :func:`sigrift.lib.crypto.aes_decrypt.build_meshtastic_nonce`):
        packet_id as LE uint64 in bytes 0-7, source node as LE uint32 in
        bytes 8-11, bytes 12-15 zero.  AES-128 or AES-256 is selected by
        key length.

        A key is accepted only when the plaintext parses as a complete,
        well-formed ``Data`` protobuf (:func:`parse_data_message`); CTR mode
        never "fails", so anything weaker accepts wrong keys.

        Parameters
        ----------
        encrypted : bytes
            Encrypted payload.
        packet_id : int
            Packet ID from MAC header.
        source_node : int
            Source node ID from MAC header.
        keys : list[bytes]
            AES keys to try (128 or 256 bit).

        Returns
        -------
        bytes or None
            Decrypted payload, or None if no key succeeded.
        """
        if not encrypted:
            return None
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            global _crypto_missing_warned
            if not _crypto_missing_warned:  # once: the edge image lacks it
                _crypto_missing_warned = True
                logger.warning(
                    "cryptography library not available; cannot decrypt "
                    "Meshtastic payloads"
                )
            return None

        nonce = build_meshtastic_nonce(packet_id, source_node)

        for key in keys:
            try:
                cipher = Cipher(algorithms.AES(bytes(key)), modes.CTR(nonce))
                decryptor = cipher.decryptor()
                plaintext = decryptor.update(encrypted) + decryptor.finalize()
            except Exception as exc:
                logger.debug("Decryption attempt failed: %s", exc)
                continue
            if parse_data_message(plaintext) is not None:
                return plaintext

        return None

    # -- Packet decode ------------------------------------------------------

    def decode_packet(self, raw: bytes, **kwargs) -> DecodedPacket:
        """Decode a raw Meshtastic packet.

        Parameters
        ----------
        raw : bytes
            Raw packet bytes (MAC header + encrypted/plaintext payload).
        **kwargs
            Optional: ``keys`` (list[bytes]) to override instance keys.

        Returns
        -------
        DecodedPacket
        """
        errors: list[str] = []
        now = datetime.now(timezone.utc).isoformat()

        if len(raw) < _MAC_HEADER_SIZE:
            errors.append(f"packet too short: {len(raw)} bytes")
            return DecodedPacket(
                protocol="meshtastic",
                raw_bytes=raw,
                payload=b"",
                metadata={},
                timestamp=now,
                confidence=0.0,
                errors=errors,
            )

        try:
            mac = self.decode_mac_header(raw)
        except DecodeError as exc:
            errors.append(str(exc))
            return DecodedPacket(
                protocol="meshtastic",
                raw_bytes=raw,
                payload=b"",
                metadata={},
                timestamp=now,
                confidence=0.0,
                errors=errors,
            )

        encrypted_payload = raw[_MAC_HEADER_SIZE:]
        metadata = {
            "mac": mac,
            "encrypted_size": len(encrypted_payload),
        }

        # Attempt decryption
        keys = kwargs.get("keys", self._keys)
        payload = self.decrypt_payload(
            encrypted_payload,
            mac["packet_id"],
            mac["source"],
            keys,
        )

        if payload is not None:
            metadata["decrypted"] = True
        else:
            metadata["decrypted"] = False
            payload = encrypted_payload
            errors.append("decryption failed or no matching key")

        confidence = 0.85 if metadata["decrypted"] else 0.4

        return DecodedPacket(
            protocol="meshtastic",
            raw_bytes=raw,
            payload=payload,
            metadata=metadata,
            timestamp=now,
            confidence=round(confidence, 4),
            errors=errors,
        )

    # -- Message extraction -------------------------------------------------

    def extract_messages(self, packet: DecodedPacket) -> list[DecodedMessage]:
        """Extract messages from a decoded Meshtastic packet.

        Parses the protobuf Data message and dispatches to the
        appropriate extractor based on portnum.  Malformed input never
        raises: a payload that is not a valid ``Data`` message (e.g. it is
        still encrypted) yields a single ``raw`` message, and a malformed
        inner payload leaves the extracted fields unset.

        Parameters
        ----------
        packet : DecodedPacket
            A decoded Meshtastic packet.

        Returns
        -------
        list[DecodedMessage]
        """
        if not packet.payload:
            return []

        mac = packet.metadata.get("mac", {})
        source = mac.get("source", 0)
        dest = mac.get("dest", 0)
        is_decrypted = packet.metadata.get("decrypted", False)

        # Strict parse: ciphertext (or garbage) must not be misread as Data.
        pb = parse_data_message(packet.payload)
        if pb is None:
            return [
                DecodedMessage(
                    protocol="meshtastic",
                    source_id=f"!{source:08x}",
                    dest_id=f"!{dest:08x}",
                    message_type="raw",
                    payload=packet.payload,
                    decrypted=is_decrypted,
                    metadata={
                        **packet.metadata,
                        # Lets downstream trial decryption rebuild the nonce.
                        "packet_id": mac.get("packet_id", 0),
                        "source_node": source,
                    },
                    confidence=packet.confidence * 0.5,
                )
            ]

        portnum = pb["portnum"]
        inner_payload = pb["payload"]
        msg_type = pb["portnum_name"]

        msg = DecodedMessage(
            protocol="meshtastic",
            source_id=f"!{source:08x}",
            dest_id=f"!{dest:08x}",
            message_type=msg_type,
            payload=inner_payload,
            decrypted=is_decrypted,
            decrypted_payload=inner_payload if is_decrypted else None,
            metadata={
                "portnum": portnum,
                "want_response": pb["want_response"],
                "hop_limit": mac.get("hop_limit", 0),
                "packet_id": mac.get("packet_id", 0),
                "source_node": source,
                "channel_hash": mac.get("channel_hash", 0),
            },
            confidence=packet.confidence,
        )

        # Dispatch to extractors for known portnums.  The extractors parse
        # leniently, but guard anyway: malformed input must never crash.
        try:
            if portnum == PORTNUM_TEXT:
                msg.text = self.extract_text(inner_payload)

            elif portnum == PORTNUM_POSITION:
                pos = self.extract_position(inner_payload)
                msg.gps_lat = pos.get("latitude")
                msg.gps_lon = pos.get("longitude")
                msg.gps_alt = pos.get("altitude")
                msg.metadata["gps_time"] = pos.get("time")

            elif portnum == PORTNUM_NODEINFO:
                info = self.extract_nodeinfo(inner_payload)
                msg.metadata["nodeinfo"] = info
                if info.get("long_name"):
                    msg.text = info["long_name"]

            elif portnum == PORTNUM_TELEMETRY:
                telemetry = self.extract_telemetry(inner_payload)
                msg.metadata["telemetry"] = telemetry
        except Exception as exc:  # defensive: never let one packet crash
            logger.debug("Meshtastic portnum %d payload parse failed: %s", portnum, exc)
            msg.metadata["payload_error"] = str(exc)

        return [msg]
