"""Tests for PcapStore — filesystem storage, pcap building, and parsing."""

from __future__ import annotations

import gzip
import struct
import time
from pathlib import Path


from sigrift.bridge.anomaly.pcap_store import (
    PcapStore,
    _PCAP_LINKTYPE_RADIOTAP,
    _PCAP_MAGIC,
    _extract_frame_type,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_radiotap_frame(frame_type: int, frame_subtype: int) -> bytes:
    """Build a minimal radiotap + 802.11 frame for testing.

    Parameters
    ----------
    frame_type : int
        802.11 frame type (0=mgmt, 1=ctrl, 2=data).
    frame_subtype : int
        802.11 frame subtype.
    """
    # Minimal radiotap header: version=0, pad=0, length=8, present=0
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    # 802.11 frame control: type and subtype encoded in bits 2-7
    fc = (frame_subtype << 4) | (frame_type << 2)
    mac_header = struct.pack("<H", fc) + b"\x00" * 22  # FC + minimal MAC header
    return radiotap + mac_header


def _build_test_pcap(frames: list[tuple[int, bytes]]) -> bytes:
    """Build a pcap file from (timestamp_us, frame_data) tuples."""
    header = struct.pack(
        "<IHHiIII",
        _PCAP_MAGIC, 2, 4, 0, 0, 65535, _PCAP_LINKTYPE_RADIOTAP,
    )
    packets = bytearray()
    for ts_us, data in frames:
        ts_sec = ts_us // 1_000_000
        ts_usec = ts_us % 1_000_000
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(data), len(data))
        packets.extend(pkt_hdr)
        packets.extend(data)
    return header + bytes(packets)


# ---------------------------------------------------------------------------
# PcapStore basic operations
# ---------------------------------------------------------------------------


class TestPcapStoreBasic:
    def test_store_and_load(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        data = gzip.compress(b"test pcap data")
        store.store(42, data)
        assert store.exists(42)
        loaded = store.load_raw(42)
        assert loaded == data

    def test_load_nonexistent(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        assert store.load_raw(999) is None
        assert store.load_pcap(999) is None
        assert not store.exists(999)

    def test_delete(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        data = gzip.compress(b"test")
        store.store(1, data)
        assert store.exists(1)
        assert store.delete(1)
        assert not store.exists(1)
        assert not store.delete(1)  # Already deleted

    def test_list_captures(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        store.store(10, gzip.compress(b"a"))
        store.store(20, gzip.compress(b"b"))
        captures = store.list_captures()
        assert isinstance(captures, (list, set, dict))
        assert "10" in captures
        assert "20" in captures

    def test_cleanup(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        # Create a file and backdate its mtime
        data = gzip.compress(b"old data")
        store.store(1, data)
        path = store._path_for(1)
        old_time = time.time() - (10 * 86400)  # 10 days ago
        import os
        os.utime(path, (old_time, old_time))

        # Store a recent one
        store.store(2, gzip.compress(b"new data"))

        deleted = store.cleanup(max_age_days=7)
        assert deleted == 1
        assert not store.exists(1)
        assert store.exists(2)

    def test_path_sanitization(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        # Ensure path traversal characters are sanitized
        path = store._path_for("../../etc/passwd")
        assert ".." not in str(path.name)


# ---------------------------------------------------------------------------
# Pcap building from frame dicts
# ---------------------------------------------------------------------------


class TestPcapBuild:
    def test_store_frames(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        beacon = _build_radiotap_frame(0, 8)
        data_frame = _build_radiotap_frame(2, 0)
        frames = [
            {"timestamp_us": 1000000, "data": beacon},
            {"timestamp_us": 1001000, "data": data_frame},
        ]
        path = store.store_frames(42, frames)
        assert path.exists()
        assert store.exists(42)

        # Verify it decompresses to valid pcap
        pcap_data = store.load_pcap(42)
        assert pcap_data is not None
        assert isinstance(pcap_data, bytes)
        magic = struct.unpack_from("<I", pcap_data, 0)[0]
        assert magic == _PCAP_MAGIC

    def test_store_frames_empty(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        path = store.store_frames(99, [])
        assert path.exists()
        # Should still be a valid (empty) pcap
        pcap_data = store.load_pcap(99)
        assert pcap_data is not None
        assert isinstance(pcap_data, bytes)
        assert len(pcap_data) == 24  # Just the global header

    def test_store_frames_no_raw_data(self, tmp_path: Path):
        """Frames without raw data should get placeholder bytes."""
        store = PcapStore(base_dir=tmp_path)
        frames = [
            {"timestamp_us": 1000000},
            {"timestamp_us": 2000000},
        ]
        store.store_frames(50, frames)
        pcap_data = store.load_pcap(50)
        assert pcap_data is not None
        assert isinstance(pcap_data, bytes)
        # Should have header + 2 packet records
        assert len(pcap_data) > 24


# ---------------------------------------------------------------------------
# Pcap parsing
# ---------------------------------------------------------------------------


class TestPcapParse:
    def test_parse_summary(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        beacon = _build_radiotap_frame(0, 8)
        deauth = _build_radiotap_frame(0, 12)
        data_frame = _build_radiotap_frame(2, 0)

        frames = [
            {"timestamp_us": 1000000, "data": beacon},
            {"timestamp_us": 1500000, "data": deauth},
            {"timestamp_us": 2000000, "data": data_frame},
        ]
        store.store_frames(1, frames)

        summary = store.parse_summary(1)
        assert summary is not None
        assert isinstance(summary, dict)
        assert summary["total_frames"] == 3
        assert summary["duration_ms"] == 1000.0  # 1s
        assert isinstance(summary["frame_types"], dict)
        assert "beacon" in summary["frame_types"]
        assert "deauth" in summary["frame_types"]
        assert "data" in summary["frame_types"]
        assert isinstance(summary["size_bytes"], int)
        assert summary["size_bytes"] > 0

    def test_parse_summary_nonexistent(self, tmp_path: Path):
        store = PcapStore(base_dir=tmp_path)
        assert store.parse_summary(999) is None

    def test_parse_big_endian_pcap(self, tmp_path: Path):
        """Test parsing big-endian pcap (swapped magic)."""
        store = PcapStore(base_dir=tmp_path)
        frame = _build_radiotap_frame(2, 0)
        # Build a big-endian pcap
        header = struct.pack(
            ">IHHiIII",
            _PCAP_MAGIC, 2, 4, 0, 0, 65535, _PCAP_LINKTYPE_RADIOTAP,
        )
        pkt_hdr = struct.pack(">IIII", 1, 0, len(frame), len(frame))
        pcap_data = header + pkt_hdr + frame
        compressed = gzip.compress(pcap_data)
        store.store(1, compressed)

        summary = store.parse_summary(1)
        assert summary is not None
        assert isinstance(summary, dict)
        assert summary["total_frames"] == 1


# ---------------------------------------------------------------------------
# Frame type extraction
# ---------------------------------------------------------------------------


class TestExtractFrameType:
    def test_beacon(self):
        frame = _build_radiotap_frame(0, 8)
        assert _extract_frame_type(frame) == "beacon"

    def test_deauth(self):
        frame = _build_radiotap_frame(0, 12)
        assert _extract_frame_type(frame) == "deauth"

    def test_data(self):
        frame = _build_radiotap_frame(2, 0)
        assert _extract_frame_type(frame) == "data"

    def test_qos_data(self):
        frame = _build_radiotap_frame(2, 8)
        assert _extract_frame_type(frame) == "qos_data"

    def test_probe_response(self):
        frame = _build_radiotap_frame(0, 5)
        assert _extract_frame_type(frame) == "probe_response"

    def test_ack(self):
        frame = _build_radiotap_frame(1, 13)
        assert _extract_frame_type(frame) == "ack"

    def test_unknown_subtype(self):
        frame = _build_radiotap_frame(2, 15)
        result = _extract_frame_type(frame)
        assert result.startswith("type2_sub15")

    def test_too_short(self):
        assert _extract_frame_type(b"\x00\x01") == "unknown"

    def test_invalid_radiotap(self):
        # Radiotap version != 0
        bad = b"\x01\x00\x08\x00" + b"\x00" * 20
        assert _extract_frame_type(bad) == "unknown"


# ---------------------------------------------------------------------------
# DB integration
# ---------------------------------------------------------------------------


class TestPcapDBIntegration:
    def test_migration_adds_columns(self, tmp_path: Path):
        """Verify the migration adds has_pcap_capture and pcap_frame_count columns."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=str(tmp_path / "test.db"))
        conn = store.get_connection()

        # Check columns exist
        cols = [row[1] for row in conn.execute("PRAGMA table_info(wifi_anomalies)").fetchall()]
        assert isinstance(cols, list)
        assert "has_pcap_capture" in cols
        assert "pcap_frame_count" in cols
        store.close()

    def test_set_wifi_anomaly_pcap(self, tmp_path: Path):
        """Test setting pcap metadata on a WiFi anomaly."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=str(tmp_path / "test.db"))

        # Insert an anomaly
        row_id = store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.6,
            "priority": "anomalous",
            "baseline_status": "stable",
            "timestamp": "2025-01-01T00:00:00+00:00",
        })

        # Set pcap metadata
        store.set_wifi_anomaly_pcap(row_id, True, 42)

        # Verify
        rows = store.get_wifi_anomalies(min_score=0.3)
        assert len(rows) == 1
        assert isinstance(rows[0], dict)
        assert rows[0]["has_pcap_capture"] == 1
        assert rows[0]["pcap_frame_count"] == 42

        store.close()

    def test_pcap_fields_default_zero(self, tmp_path: Path):
        """Verify new anomalies default to no pcap capture."""
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=str(tmp_path / "test.db"))

        store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.5,
            "priority": "anomalous",
            "baseline_status": "new",
            "timestamp": "2025-01-01T00:00:00+00:00",
        })

        rows = store.get_wifi_anomalies(min_score=0.3)
        assert len(rows) == 1
        assert rows[0]["has_pcap_capture"] == 0
        assert rows[0]["pcap_frame_count"] == 0

        store.close()
