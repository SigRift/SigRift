"""LoRa PHY demodulator with Meshtastic/MeshCore protocol decode.

Provides FFT-based CSS (chirp spread spectrum) demodulation, LoRa header
extraction, sync word classification (Meshtastic/LoRaWAN/generic), and
Meshtastic MAC header parsing with default-key payload decryption.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field

import numpy as np

from sigrift.lib.protocol.meshtastic import MeshtasticDecoder, parse_data_message

logger = logging.getLogger(__name__)

# Meshtastic default channel PSK: the expansion of the one-byte PSK "AQ=="
# (base64 "1PG7OiApB1nwvP+rz05pAQ==").  Every modem preset uses this same
# key on its default (unnamed) channel -- only the channel *name*, and so the
# channel hash, differs per preset.
_MESHTASTIC_DEFAULT_PSK = bytes.fromhex("d4f1bb3a20290759f0bcffabcf4e6901")

# Firmware default channel names (DisplayFormatters::getModemPresetDisplayName).
_MESHTASTIC_PRESET_CHANNEL_NAMES = (
    "ShortTurbo",
    "ShortFast",
    "ShortSlow",
    "MediumFast",
    "MediumSlow",
    "LongFast",
    "LongMod",
    "LongSlow",
    "LongTurbo",
    "VLongSlow",
)


def _meshtastic_channel_hash(name: str, key: bytes) -> int:
    """Firmware ``Channels::generateHash``: xor(name bytes) ^ xor(key bytes)."""
    h = 0
    for b in name.encode("utf-8") + key:
        h ^= b
    return h


# Channel hash -> AES key for the default-key channel of every modem preset
# (LongFast -> 0x08, MediumFast -> 0x1f, ...).
_MESHTASTIC_DEFAULT_KEYS: dict[int, bytes] = {
    _meshtastic_channel_hash(name, _MESHTASTIC_DEFAULT_PSK): _MESHTASTIC_DEFAULT_PSK
    for name in _MESHTASTIC_PRESET_CHANNEL_NAMES
}

# Meshtastic port numbers
PORT_TEXT_MESSAGE = 1
PORT_POSITION = 3
PORT_NODEINFO = 4
PORT_TELEMETRY = 67


@dataclass
class MeshNetworkIntelligence:
    """Decoded LoRa/Meshtastic packet intelligence."""

    protocol: str
    source_node_id: str | None
    dest_node_id: str | None
    packet_id: int | None
    hop_limit: int | None
    channel_hash: int | None
    port_num: int | None
    encryption_status: str
    decoded_position: dict | None
    decoded_text: str | None
    decoded_telemetry: dict | None
    rf_params: dict = field(default_factory=dict)


def _generate_chirp(
    n_fft: int, bw: float, fs: float, upchirp: bool = True
) -> np.ndarray:
    """Generate a base chirp signal for LoRa modulation.

    Parameters
    ----------
    n_fft : int
        FFT size (2^SF).
    bw : float
        Bandwidth in Hz.
    fs : float
        Sample rate in Hz.
    upchirp : bool
        True for upchirp (reference), False for downchirp.

    Returns
    -------
    np.ndarray
        Complex chirp signal of length n_fft.
    """
    t = np.arange(n_fft) / fs
    sign = 1.0 if upchirp else -1.0
    chirp_rate = sign * bw / (n_fft / fs)
    phase = 2.0 * np.pi * (chirp_rate / 2.0 * t * t)
    return np.exp(1j * phase)


def dechirp(iq: np.ndarray, sf: int, bw: float, fs: float) -> np.ndarray:
    """Dechirp LoRa symbols using FFT peak detection.

    Multiplies each symbol-length chunk by the conjugate of a base
    upchirp (i.e., a downchirp), then finds the FFT bin with maximum
    energy.  The bin index encodes the symbol value.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples.
    sf : int
        Spreading factor (5-12).
    bw : float
        Bandwidth in Hz.
    fs : float
        Sample rate in Hz.

    Returns
    -------
    np.ndarray
        Array of symbol values (0 to 2^SF - 1), dtype int32.
    """
    n_fft = 2**sf
    samples_per_symbol = int(fs / bw * n_fft)

    # Generate base downchirp (conjugate of upchirp)
    downchirp = _generate_chirp(n_fft, bw, fs, upchirp=False)

    symbols = []
    pos = 0
    while pos + samples_per_symbol <= len(iq):
        chunk = iq[pos : pos + samples_per_symbol]

        # Resample to n_fft samples if needed
        if len(chunk) != n_fft:
            indices = np.linspace(0, len(chunk) - 1, n_fft).astype(int)
            chunk = chunk[indices]

        # Dechirp: multiply by downchirp
        dechirped = chunk * downchirp

        # FFT and find peak
        spectrum = np.abs(np.fft.fft(dechirped))
        symbol = int(np.argmax(spectrum))
        symbols.append(symbol)

        pos += samples_per_symbol

    return np.array(symbols, dtype=np.int32)


def extract_header(symbols: np.ndarray) -> dict:
    """Extract LoRa header from demodulated symbols.

    The LoRa header is encoded in the first symbols after the preamble.
    Layout (simplified):
    - Symbols 0-1 (high nibbles): sync word
    - Symbol 2: payload length (upper)
    - Symbol 3: payload length (lower) + coding rate + CRC flag

    Parameters
    ----------
    symbols : np.ndarray
        Demodulated symbol values.

    Returns
    -------
    dict
        Header fields: sync_word, cr, has_crc, payload_len.
    """
    if len(symbols) < 8:
        return {"sync_word": 0, "cr": 1, "has_crc": False, "payload_len": 0}

    # Sync word from first two symbols (high nibble each)
    sync_word = ((symbols[0] & 0xF0) >> 4) | (symbols[1] & 0xF0)

    # Payload length from symbols 2-3
    payload_len = ((symbols[2] & 0xFF) << 4) | ((symbols[3] >> 4) & 0x0F)
    payload_len = min(payload_len, 255)

    # Coding rate: symbols[3] bits 3-2
    cr = ((symbols[3] >> 1) & 0x03) + 1  # CR 1-4 (= 4/5 to 4/8)

    # CRC flag: symbols[3] bit 0
    has_crc = bool(symbols[3] & 0x01)

    return {
        "sync_word": int(sync_word),
        "cr": int(cr),
        "has_crc": has_crc,
        "payload_len": int(payload_len),
    }


def classify_protocol(sync_word: int) -> str:
    """Classify LoRa protocol variant by sync word.

    Parameters
    ----------
    sync_word : int
        8-bit sync word extracted from header.

    Returns
    -------
    str
        Protocol name: "meshtastic", "lorawan", or "generic".
    """
    sync_map = {
        0x12: "meshtastic",
        0x34: "lorawan",
    }
    return sync_map.get(sync_word, "generic")


def _hamming_decode_nibble(bits_7: int) -> int:
    """Decode a Hamming(7,4) codeword to a 4-bit nibble.

    Parameters
    ----------
    bits_7 : int
        7-bit Hamming codeword.

    Returns
    -------
    int
        Decoded 4-bit value (single-error corrected).
    """
    # Syndrome calculation for Hamming(7,4)
    # Parity check matrix H positions: p1=bit6, p2=bit5, p3=bit3
    d = [0] * 7
    for i in range(7):
        d[i] = (bits_7 >> (6 - i)) & 1

    s1 = d[0] ^ d[2] ^ d[4] ^ d[6]
    s2 = d[1] ^ d[2] ^ d[5] ^ d[6]
    s3 = d[3] ^ d[4] ^ d[5] ^ d[6]

    syndrome = (s1 << 2) | (s2 << 1) | s3
    if syndrome:
        # Single bit error correction
        error_pos = syndrome - 1
        if 0 <= error_pos < 7:
            d[error_pos] ^= 1

    # Data bits at positions 2, 4, 5, 6 (0-indexed)
    return (d[2] << 3) | (d[4] << 2) | (d[5] << 1) | d[6]


def decode_payload(symbols: np.ndarray, cr: int) -> bytes:
    """Decode LoRa payload from symbols.

    Performs de-interleaving, Hamming FEC decoding, and de-whitening.

    Parameters
    ----------
    symbols : np.ndarray
        Symbol values after header (symbols[4:] typically).
    cr : int
        Coding rate (1-4, meaning 4/5 to 4/8).

    Returns
    -------
    bytes
        Decoded payload bytes.
    """
    if len(symbols) < 5:
        return b""

    # Skip header symbols (first 4 after preamble sync)
    data_symbols = symbols[4:]

    # Extract nibbles from symbols using low bits
    nibbles = []
    for sym in data_symbols:
        # Each symbol carries data in its lower bits
        # For CR=1 (4/5): 4 data bits per symbol
        # For CR=4 (4/8): 4 data bits per symbol (extra parity)
        if cr >= 3:
            # Hamming decode: treat low 7 bits as Hamming(7,4)
            nibble = _hamming_decode_nibble(sym & 0x7F)
        else:
            nibble = sym & 0x0F
        nibbles.append(nibble)

    # Combine nibbles into bytes
    payload = bytearray()
    for i in range(0, len(nibbles) - 1, 2):
        byte_val = (nibbles[i] << 4) | (nibbles[i + 1] & 0x0F)
        payload.append(byte_val)

    # De-whiten with LoRa whitening sequence (LFSR x^8 + x^6 + x^5 + x^4 + 1)
    lfsr = 0xFF
    for i in range(len(payload)):
        payload[i] ^= lfsr
        # LFSR feedback
        feedback = ((lfsr >> 7) ^ (lfsr >> 5) ^ (lfsr >> 4) ^ (lfsr >> 3)) & 1
        lfsr = ((lfsr << 1) | feedback) & 0xFF

    return bytes(payload)


# ---------------------------------------------------------------------------
# Meshtastic protocol layer
# ---------------------------------------------------------------------------


def decode_meshtastic_header(payload: bytes) -> dict:
    """Decode Meshtastic MAC header (always cleartext).

    Header layout (first 16 bytes, firmware ``PacketHeader``):
    - [0:4]  dest_node_id   (uint32 LE)
    - [4:8]  source_node_id (uint32 LE)
    - [8:12] packet_id      (uint32 LE)
    - [12]   flags          (hop_limit bits 0-2, want_ack bit 3,
                             via_mqtt bit 4, hop_start bits 5-7)
    - [13]   channel_hash   (uint8)
    - [14]   next_hop       (uint8)
    - [15]   relay_node     (uint8)

    The port number is *not* in the header: it is field 1 of the
    encrypted ``Data`` protobuf that follows (see :func:`demodulate_and_decode`).

    Parameters
    ----------
    payload : bytes
        Raw payload starting at Meshtastic MAC header.

    Returns
    -------
    dict
        Header fields, or empty dict if payload too short.
    """
    if len(payload) < 16:
        return {}

    dest, source, pkt_id = struct.unpack_from("<III", payload, 0)
    flags = payload[12]

    return {
        "source_node_id": f"!{source:08x}",
        "dest_node_id": f"!{dest:08x}",
        "source_node": source,
        "packet_id": pkt_id,
        "hop_limit": flags & 0x07,
        "want_ack": bool(flags & 0x08),
        "hop_start": (flags >> 5) & 0x07,
        "channel_hash": payload[13],
        "next_hop": payload[14],
        "relay_node": payload[15],
    }


def try_decrypt_meshtastic(
    encrypted: bytes,
    channel_hash: int,
    packet_id: int = 0,
    source_node: int = 0,
) -> bytes | None:
    """Try to decrypt Meshtastic payload using the well-known default key.

    Only attempts decryption when the channel hash is that of a modem
    preset's default channel (default PSK).  Returns None for
    custom-encrypted channels -- no brute force is attempted.

    The nonce follows firmware ``CryptoEngine::initNonce`` (packet_id as
    LE uint64, source node as LE uint32, zero padding), and the result is
    only returned if it parses as a complete Meshtastic ``Data`` protobuf.

    Parameters
    ----------
    encrypted : bytes
        Encrypted payload (after 16-byte MAC header).
    channel_hash : int
        Channel hash byte from MAC header.
    packet_id : int
        Packet ID for nonce construction.
    source_node : int
        Source node ID for nonce construction.

    Returns
    -------
    bytes or None
        Decrypted ``Data`` protobuf, or None if the key is unknown or the
        plaintext is not a valid ``Data`` message.
    """
    key = _MESHTASTIC_DEFAULT_KEYS.get(channel_hash)
    if key is None or not encrypted:
        return None

    try:
        return MeshtasticDecoder.decrypt_payload(
            encrypted, packet_id, source_node, [key]
        )
    except Exception:
        logger.debug("Meshtastic decryption failed", exc_info=True)
        return None


def decode_meshtastic_protobuf(plaintext: bytes, port_num: int) -> dict:
    """Decode the inner payload of a Meshtastic ``Data`` message.

    *plaintext* is ``Data.payload`` (not the whole ``Data`` message) and
    *port_num* is ``Data.portnum``.  Parsing is delegated to
    :class:`sigrift.lib.protocol.meshtastic.MeshtasticDecoder` and never
    raises on malformed input:

    - TEXT_MESSAGE (1): UTF-8 text
    - POSITION (3): lat, lon, altitude, time
    - NODEINFO (4): id, long_name, short_name, hw_model
    - TELEMETRY (67): battery_level, voltage, channel_util

    Parameters
    ----------
    plaintext : bytes
        Inner payload bytes.
    port_num : int
        Meshtastic port number.

    Returns
    -------
    dict
        Decoded fields keyed by type (e.g., "text", "position", "telemetry").
    """
    result: dict = {}

    try:
        if port_num == PORT_TEXT_MESSAGE:
            result["text"] = MeshtasticDecoder.extract_text(plaintext)

        elif port_num == PORT_POSITION:
            pos = MeshtasticDecoder.extract_position(plaintext)
            position = {
                "lat": pos["latitude"],
                "lon": pos["longitude"],
                "altitude": pos["altitude"],
                "time": pos["time"],
            }
            position = {k: v for k, v in position.items() if v is not None}
            if position:
                result["position"] = position

        elif port_num == PORT_NODEINFO:
            info = MeshtasticDecoder.extract_nodeinfo(plaintext)
            nodeinfo = {k: v for k, v in info.items() if v is not None}
            if nodeinfo:
                result["nodeinfo"] = nodeinfo

        elif port_num == PORT_TELEMETRY:
            tel = MeshtasticDecoder.extract_telemetry(plaintext)
            telemetry: dict = {}
            if tel["battery"] is not None:
                telemetry["battery_level"] = tel["battery"]
            if tel["voltage"] is not None:
                telemetry["voltage"] = round(tel["voltage"], 2)
            if tel["channel_utilization"] is not None:
                telemetry["channel_util"] = round(tel["channel_utilization"], 1)
            if telemetry:
                result["telemetry"] = telemetry
    except Exception:
        logger.debug(
            "Meshtastic payload decode failed (port %s)", port_num, exc_info=True
        )

    return result


def _frame_payload(
    decoded: bytes, payload_len: int, has_crc: bool
) -> tuple[bytes, bool | None]:
    """Cut the PHY payload to the header's length and check its CRC-16.

    ``decode_payload`` returns every byte the symbols carry, including the
    payload CRC and the zero padding of the last interleaver block, so the
    header's ``payload_len`` decides where the payload ends.  When
    ``has_crc`` is set, the two bytes after the payload are the CRC-16/CCITT
    (big-endian, same as :class:`sigrift.lib.protocol.lora_phy.LoRaPhyDecoder`).

    Returns ``(payload, crc_ok)``: ``crc_ok`` is True/False when a CRC was
    checked and None when the frame carries none.  A truncated frame or a
    CRC mismatch returns an empty payload, so nothing downstream decodes it.
    """
    from sigrift.lib.protocol.lora_phy import _crc16_ccitt

    if payload_len <= 0:
        return b"", None
    needed = payload_len + (2 if has_crc else 0)
    if len(decoded) < needed:
        return b"", False if has_crc else None
    payload = bytes(decoded[:payload_len])
    if not has_crc:
        return payload, None
    received = (decoded[payload_len] << 8) | decoded[payload_len + 1]
    if _crc16_ccitt(payload) != received:
        return b"", False
    return payload, True


def demodulate_and_decode(
    iq: np.ndarray,
    sf: int,
    bw: float,
    fs: float,
) -> MeshNetworkIntelligence | None:
    """Full pipeline: dechirp -> header -> classify -> decode.

    Parameters
    ----------
    iq : np.ndarray
        Complex IQ samples.
    sf : int
        Spreading factor (5-12).
    bw : float
        Bandwidth in Hz.
    fs : float
        Sample rate in Hz.

    Returns
    -------
    MeshNetworkIntelligence or None
        Decoded packet intelligence, or None if too few symbols.
    """
    symbols = dechirp(iq, sf, bw, fs)
    if len(symbols) < 8:
        return None

    header = extract_header(symbols)
    protocol = classify_protocol(header.get("sync_word", 0))
    decoded = decode_payload(symbols, header.get("cr", 1))
    payload, crc_ok = _frame_payload(
        decoded, header.get("payload_len", 0), header.get("has_crc", False)
    )

    result = MeshNetworkIntelligence(
        protocol=protocol,
        source_node_id=None,
        dest_node_id=None,
        packet_id=None,
        hop_limit=None,
        channel_hash=None,
        port_num=None,
        encryption_status="unknown",
        decoded_position=None,
        decoded_text=None,
        decoded_telemetry=None,
        rf_params={
            "payload_len": header.get("payload_len", 0),
            "has_crc": header.get("has_crc", False),
            "crc_ok": crc_ok,
        },
    )

    if protocol == "meshtastic" and payload:
        hdr = decode_meshtastic_header(payload)
        if not hdr:
            return result

        result.source_node_id = hdr.get("source_node_id")
        result.dest_node_id = hdr.get("dest_node_id")
        result.packet_id = hdr.get("packet_id")
        result.hop_limit = hdr.get("hop_limit")
        result.channel_hash = hdr.get("channel_hash")

        # The portnum lives inside the encrypted Data protobuf: decrypt with
        # the default key (if the channel hash is a preset's), parse Data,
        # then dispatch on Data.portnum.
        body = payload[16:]
        if body:
            decrypted = try_decrypt_meshtastic(
                body,
                hdr["channel_hash"],
                packet_id=hdr["packet_id"],
                source_node=hdr["source_node"],
            )
            if decrypted is not None:
                result.encryption_status = "default_key"
                data = parse_data_message(decrypted)
            else:
                # Unencrypted channel (empty PSK): the body is the Data itself.
                data = parse_data_message(body)
                result.encryption_status = (
                    "cleartext" if data is not None else "custom_encrypted"
                )

            if data is not None:
                result.port_num = data["portnum"]
                decoded = decode_meshtastic_protobuf(data["payload"], data["portnum"])
                result.decoded_position = decoded.get("position")
                result.decoded_text = decoded.get("text")
                result.decoded_telemetry = decoded.get("telemetry")
    elif protocol == "lorawan" and payload:
        result.encryption_status = "custom_encrypted"
    elif payload:
        result.encryption_status = "cleartext"

    return result
