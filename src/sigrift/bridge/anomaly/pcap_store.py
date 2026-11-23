"""Filesystem-backed pcap capture storage for WiFi anomalies.

Stores gzip-compressed pcap files on disk at ``data/pcap_captures/``
following the same pattern as :class:`~sigrift.bridge.iq_store.IQStore`.

Each file is named ``{anomaly_id}.pcap.gz`` and contains a standard
libpcap file (magic + header + packet records) with 802.11 link type,
suitable for direct import into Wireshark or tshark.

The pcap format uses:
    - Magic: 0xa1b2c3d4 (microsecond resolution)
    - Link type: 127 (LINKTYPE_IEEE802_11_RADIOTAP)
    - Snap length: 65535
"""

from __future__ import annotations

import gzip
import zlib
import logging
import os
import re
import struct
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Largest decompressed pcap accepted (``BRIDGE_PCAP_MAX_BYTES``, default
#: 64 MiB).  A capture is gzip-compressed, so a small upload can inflate to
#: gigabytes; inflation stops at this size.
DEFAULT_MAX_PCAP_BYTES = 64 * 1024 * 1024
_MAX_PCAP_BYTES_ENV = "BRIDGE_PCAP_MAX_BYTES"
# Inflation work bounds: input fed to zlib per call, output per call, and
# concatenated gzip members accepted (the edge sends one).
_INFLATE_INPUT_CHUNK = 64 * 1024
_INFLATE_OUTPUT_STEP = 1024 * 1024
_MAX_GZIP_MEMBERS = 64


class PcapDecompressionError(ValueError):
    """The capture is not a valid gzip stream."""


class PcapSizeLimitError(PcapDecompressionError):
    """The capture decompresses to more than the configured limit."""


def max_pcap_bytes() -> int:
    """Return the decompressed pcap size limit (``BRIDGE_PCAP_MAX_BYTES``)."""
    raw = os.environ.get(_MAX_PCAP_BYTES_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_PCAP_BYTES
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        logger.warning(
            "Invalid %s=%r (must be a positive integer); using %d",
            _MAX_PCAP_BYTES_ENV,
            raw,
            DEFAULT_MAX_PCAP_BYTES,
        )
        return DEFAULT_MAX_PCAP_BYTES
    return value


def _skip_zero_padding(view: memoryview, pos: int) -> int:
    """Return the offset of the first non-zero byte at or after *pos*."""
    total = len(view)
    while pos < total and view[pos] == 0:
        chunk = bytes(view[pos : pos + _INFLATE_INPUT_CHUNK])
        stripped = len(chunk) - len(chunk.lstrip(b"\x00"))
        pos += stripped
        if stripped < len(chunk):
            break
    return pos


def decompress_pcap(data: bytes, max_bytes: int | None = None) -> bytes:
    """Inflate a gzip-compressed capture, refusing more than *max_bytes*.

    Like ``gzip.decompress`` (concatenated members and zero padding after
    them are accepted, empty input gives ``b""``) but bounded: output is produced at most
    ``_INFLATE_OUTPUT_STEP`` bytes per call and inflation stops as soon as
    it would exceed *max_bytes* (default :func:`max_pcap_bytes`), so a
    gzip bomb costs about the limit, not its decompressed size.

    Raises
    ------
    PcapSizeLimitError
        The capture decompresses to more than *max_bytes*.
    PcapDecompressionError
        Not gzip, truncated, or too many gzip members.
    """
    limit = max_pcap_bytes() if max_bytes is None else int(max_bytes)
    view = memoryview(data).cast("B")
    total = len(view)
    out = bytearray()
    pos = 0
    members = 0
    try:
        while True:
            pos = _skip_zero_padding(view, pos)
            if pos >= total:
                break
            members += 1
            if members > _MAX_GZIP_MEMBERS:
                raise PcapDecompressionError(
                    f"pcap payload has more than {_MAX_GZIP_MEMBERS} gzip members"
                )
            inflater = zlib.decompressobj(wbits=31)  # gzip container only
            while not inflater.eof:
                if pos >= total:
                    raise PcapDecompressionError("truncated gzip stream")
                end = min(pos + _INFLATE_INPUT_CHUNK, total)
                pending: bytes | memoryview = view[pos:end]
                while True:
                    want = min(_INFLATE_OUTPUT_STEP, limit - len(out) + 1)
                    produced = inflater.decompress(pending, want)
                    out += produced
                    if len(out) > limit:
                        raise PcapSizeLimitError(
                            f"pcap decompresses to more than {limit} bytes; "
                            f"raise {_MAX_PCAP_BYTES_ENV} to accept larger "
                            "captures"
                        )
                    if inflater.eof:
                        pos = end - len(inflater.unused_data)
                        break
                    pending = inflater.unconsumed_tail
                    if not pending and len(produced) < want:
                        pos = end
                        break
    except zlib.error as exc:
        raise PcapDecompressionError(f"invalid gzip data: {exc}") from exc
    return bytes(out)


_DEFAULT_BASE_DIR = Path(__file__).resolve().parent.parent / "data" / "pcap_captures"

# Pcap file format constants
_PCAP_MAGIC = 0xA1B2C3D4
_PCAP_VERSION_MAJOR = 2
_PCAP_VERSION_MINOR = 4
_PCAP_SNAPLEN = 65535
_PCAP_LINKTYPE_RADIOTAP = 127  # IEEE 802.11 with radiotap header


class PcapStore:
    """Filesystem storage for WiFi anomaly pcap captures.

    Parameters
    ----------
    base_dir : str or Path or None
        Directory for ``.pcap.gz`` files.  Created if it does not exist.
        Defaults to ``sigrift/bridge/data/pcap_captures/``.
    """

    def __init__(self, base_dir: str | Path | None = None) -> None:
        self._base_dir = Path(base_dir or _DEFAULT_BASE_DIR)
        self._base_dir.mkdir(parents=True, exist_ok=True)
        logger.info("PcapStore initialised: %s", self._base_dir)

    # -- Write --------------------------------------------------------------

    def store(self, anomaly_id: int | str, data: bytes) -> Path:
        """Write compressed pcap data to disk.

        Parameters
        ----------
        anomaly_id : int or str
            WiFi anomaly row ID (used as filename).
        data : bytes
            Gzip-compressed pcap file data.

        Returns
        -------
        Path
            Path to the stored file.
        """
        path = self._path_for(anomaly_id)
        path.write_bytes(data)
        logger.debug("Pcap stored: anomaly %s (%d bytes)", anomaly_id, len(data))
        return path

    def store_frames(
        self,
        anomaly_id: int | str,
        frames: list[dict[str, Any]],
    ) -> Path:
        """Build a pcap file from parsed frame dicts and store it.

        Each frame dict should have:
            - timestamp_us (int): microseconds since epoch
            - data (bytes): raw frame bytes (radiotap + 802.11)

        If frames lack raw ``data``, a minimal synthetic pcap is
        built from the metadata fields for forensic reference.

        Parameters
        ----------
        anomaly_id : int or str
            WiFi anomaly row ID.
        frames : list[dict]
            Frame records with raw bytes or metadata.

        Returns
        -------
        Path
            Path to the stored file.
        """
        pcap_bytes = self._build_pcap(frames)
        compressed = gzip.compress(pcap_bytes, compresslevel=6)
        return self.store(anomaly_id, compressed)

    # -- Read ---------------------------------------------------------------

    def load_raw(self, anomaly_id: int | str) -> bytes | None:
        """Return compressed bytes, or None if not found."""
        path = self._path_for(anomaly_id)
        if not path.exists():
            return None
        return path.read_bytes()

    def load_pcap(self, anomaly_id: int | str) -> bytes | None:
        """Decompress and return raw pcap bytes, or None.

        None also when the capture inflates past :func:`max_pcap_bytes`
        (inflation stops there; see :func:`decompress_pcap`).
        """
        raw = self.load_raw(anomaly_id)
        if raw is None:
            return None
        try:
            return decompress_pcap(raw)
        except PcapDecompressionError as e:
            logger.warning(
                "Failed to decompress pcap for anomaly %s: %s", anomaly_id, e
            )
            return None

    # -- Query --------------------------------------------------------------

    def exists(self, anomaly_id: int | str) -> bool:
        """Check if a pcap capture exists for this anomaly."""
        return self._path_for(anomaly_id).exists()

    def delete(self, anomaly_id: int | str) -> bool:
        """Delete a pcap capture file.  Returns True if deleted."""
        path = self._path_for(anomaly_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_captures(self) -> list[str]:
        """Return anomaly IDs that have pcap captures on disk."""
        return [p.stem.replace(".pcap", "") for p in self._base_dir.glob("*.pcap.gz")]

    # -- Cleanup ------------------------------------------------------------

    def cleanup(self, max_age_days: int = 7) -> int:
        """Delete pcap files older than *max_age_days*.

        Returns
        -------
        int
            Number of files deleted.
        """
        cutoff = time.time() - (max_age_days * 86400)
        deleted = 0
        for path in self._base_dir.glob("*.pcap.gz"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
                    deleted += 1
            except OSError:
                pass
        if deleted > 0:
            logger.info(
                "Pcap cleanup: removed %d files older than %d days",
                deleted,
                max_age_days,
            )
        return deleted

    # -- Parse / Summary ----------------------------------------------------

    def parse_summary(self, anomaly_id: int | str) -> dict[str, Any] | None:
        """Parse pcap and return a frame summary for the API.

        Returns
        -------
        dict or None
            Keys: total_frames, duration_ms, frame_types, size_bytes.
            None if pcap not found.
        """
        pcap_data = self.load_pcap(anomaly_id)
        if pcap_data is None:
            return None

        compressed = self.load_raw(anomaly_id)
        size_bytes = len(compressed) if compressed else 0
        return self.summarize(pcap_data, size_bytes)

    @classmethod
    def summarize(cls, pcap_data: bytes, size_bytes: int) -> dict[str, Any]:
        """Frame summary of decompressed *pcap_data* (see :meth:`parse_summary`)."""
        frames = cls._parse_pcap_frames(pcap_data)
        if not frames:
            return {
                "total_frames": 0,
                "duration_ms": 0,
                "frame_types": {},
                "size_bytes": size_bytes,
                "frames": [],
            }

        timestamps = [f["timestamp_us"] for f in frames]
        duration_ms = (
            (max(timestamps) - min(timestamps)) / 1000.0 if len(timestamps) > 1 else 0
        )

        # Count frame types from metadata
        type_counts: dict[str, int] = {}
        for f in frames:
            ft = f.get("frame_type", "unknown")
            type_counts[ft] = type_counts.get(ft, 0) + 1

        return {
            "total_frames": len(frames),
            "duration_ms": round(duration_ms, 1),
            "frame_types": type_counts,
            "size_bytes": size_bytes,
            "frames": frames[:100],  # cap detail frames for API response
        }

    # -- Internal -----------------------------------------------------------

    def _path_for(self, anomaly_id: int | str) -> Path:
        """Return filesystem path for an anomaly's pcap capture."""
        safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", str(anomaly_id))
        if not safe_id:
            raise ValueError("Invalid anomaly_id")
        path = (self._base_dir / f"{safe_id}.pcap.gz").resolve()
        if not path.is_relative_to(self._base_dir.resolve()):
            raise ValueError("Path traversal detected")
        return path

    @staticmethod
    def _build_pcap(frames: list[dict[str, Any]]) -> bytes:
        """Build a libpcap file from frame records.

        Parameters
        ----------
        frames : list[dict]
            Each must have ``timestamp_us`` (int) and ``data`` (bytes).
            If ``data`` is missing, a minimal placeholder frame is used.

        Returns
        -------
        bytes
            Complete pcap file.
        """
        # Global header: magic, version major/minor, thiszone, sigfigs,
        #                snaplen, network (link type)
        header = struct.pack(
            "<IHHiIII",
            _PCAP_MAGIC,
            _PCAP_VERSION_MAJOR,
            _PCAP_VERSION_MINOR,
            0,  # thiszone
            0,  # sigfigs
            _PCAP_SNAPLEN,
            _PCAP_LINKTYPE_RADIOTAP,
        )

        packets = bytearray()
        for frame in frames:
            ts_us = frame.get("timestamp_us", 0)
            ts_sec = ts_us // 1_000_000
            ts_usec = ts_us % 1_000_000
            data = frame.get("data", b"")
            if not data:
                # Build minimal placeholder if no raw data
                data = b"\x00" * 4  # minimal radiotap stub
            incl_len = min(len(data), _PCAP_SNAPLEN)
            orig_len = len(data)
            # Packet record header: ts_sec, ts_usec, incl_len, orig_len
            pkt_header = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
            packets.extend(pkt_header)
            packets.extend(data[:incl_len])

        return header + bytes(packets)

    @staticmethod
    def _parse_pcap_frames(pcap_data: bytes) -> list[dict[str, Any]]:
        """Parse a libpcap file and extract frame metadata.

        Returns a list of frame summaries with timestamps and sizes.
        Does NOT attempt full 802.11 dissection — that belongs in
        Wireshark.  Extracts enough for the dashboard summary view.
        """
        if len(pcap_data) < 24:
            return []

        # Verify magic and determine byte order
        magic = struct.unpack_from("<I", pcap_data, 0)[0]
        if magic == _PCAP_MAGIC:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            logger.warning("Invalid pcap magic: 0x%08X", magic)
            return []

        # Skip global header (24 bytes)
        offset = 24
        frames: list[dict[str, Any]] = []

        while offset + 16 <= len(pcap_data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(
                f"{endian}IIII",
                pcap_data,
                offset,
            )
            offset += 16

            if offset + incl_len > len(pcap_data):
                break  # truncated file

            timestamp_us = ts_sec * 1_000_000 + ts_usec
            pkt_data = pcap_data[offset : offset + incl_len]
            offset += incl_len

            frame_info: dict[str, Any] = {
                "timestamp_us": timestamp_us,
                "length": orig_len,
                "captured_length": incl_len,
            }

            # Try to extract radiotap header length and basic 802.11 type
            frame_type = _extract_frame_type(pkt_data)
            if frame_type:
                frame_info["frame_type"] = frame_type

            frames.append(frame_info)

        return frames


_FRAME_TYPE_MAP: dict[tuple[int, int], str] = {
    (0, 0): "association_request",
    (0, 1): "association_response",
    (0, 2): "reassociation_request",
    (0, 3): "reassociation_response",
    (0, 4): "probe_request",
    (0, 5): "probe_response",
    (0, 8): "beacon",
    (0, 10): "disassociation",
    (0, 11): "authentication",
    (0, 12): "deauth",
    (1, 11): "rts",
    (1, 12): "cts",
    (1, 13): "ack",
    (2, 0): "data",
    (2, 4): "null_data",
    (2, 8): "qos_data",
}


def _extract_frame_type(pkt_data: bytes) -> str:
    """Try to extract 802.11 frame type from radiotap + MAC header.

    Returns a human-readable frame type string, or "unknown".
    """
    if len(pkt_data) < 4:
        return "unknown"

    # Radiotap header: version (1), pad (1), length (2, LE)
    rt_version = pkt_data[0]
    if rt_version != 0:
        return "unknown"

    rt_len = struct.unpack_from("<H", pkt_data, 2)[0]
    if rt_len > len(pkt_data) or rt_len < 8:
        return "unknown"

    # 802.11 MAC header starts after radiotap
    mac_offset = rt_len
    if mac_offset + 2 > len(pkt_data):
        return "unknown"

    fc = struct.unpack_from("<H", pkt_data, mac_offset)[0]
    frame_type = (fc >> 2) & 0x03
    frame_subtype = (fc >> 4) & 0x0F

    return _FRAME_TYPE_MAP.get(
        (frame_type, frame_subtype), f"type{frame_type}_sub{frame_subtype}"
    )
