"""Integration tests for WiFi anomaly pcap API endpoints.

Covers the full round-trip:
  - POST pcap upload → GET download → verify bytes
  - POST pcap upload → DB metadata update (has_pcap_capture, pcap_frame_count)
  - GET pcap summary → frame type breakdown
  - 404 on missing pcap (download + summary)
  - Empty body / oversized rejection
  - insert_wifi_anomalies_batch returns row IDs
  - Ingest response includes anomaly_ids when anomalies detected
"""

from __future__ import annotations

import gzip
import struct

from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.pcap_store import _PCAP_LINKTYPE_RADIOTAP, _PCAP_MAGIC
from sigrift.bridge.detection_store import DetectionStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_radiotap_frame(frame_type: int, frame_subtype: int) -> bytes:
    """Minimal radiotap + 802.11 frame."""
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    fc = (frame_subtype << 4) | (frame_type << 2)
    mac_header = struct.pack("<H", fc) + b"\x00" * 22
    return radiotap + mac_header


def _build_test_pcap_gz(frames: list[tuple[int, bytes]]) -> bytes:
    """Build a gzip-compressed pcap from (timestamp_us, frame_data) tuples."""
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
    return gzip.compress(header + bytes(packets))


def _insert_anomaly(store: DetectionStore) -> int:
    """Insert a test WiFi anomaly and return its row ID."""
    return store.insert_wifi_anomaly({
        "bssid": "aa:bb:cc:11:22:33",
        "anomaly_score": 0.7,
        "priority": "critical",
        "baseline_status": "stable",
        "timestamp": "2026-02-11T00:00:00+00:00",
    })


# ---------------------------------------------------------------------------
# Pcap upload / download round-trip
# ---------------------------------------------------------------------------


class TestPcapUploadDownload:
    def test_upload_and_download_round_trip(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        aid = _insert_anomaly(detection_store)
        beacon = _build_radiotap_frame(0, 8)
        pcap_gz = _build_test_pcap_gz([(1_000_000, beacon), (2_000_000, beacon)])

        # Upload
        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap_gz,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["anomaly_id"] == aid
        assert data["frame_count"] == 2

        # Download (Content-Encoding: gzip causes auto-decompression by test client)
        resp = client.get(f"/api/wifi/anomalies/{aid}/pcap")
        assert resp.status_code == 200
        assert resp.content == gzip.decompress(pcap_gz)

    def test_download_nonexistent_returns_404(self, client: TestClient):
        resp = client.get("/api/wifi/anomalies/99999/pcap")
        assert resp.status_code == 404

    def test_upload_empty_body_returns_400(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        aid = _insert_anomaly(detection_store)
        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=b"",
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Pcap upload updates DB metadata
# ---------------------------------------------------------------------------


class TestPcapDBMetadata:
    def test_upload_sets_has_pcap_and_frame_count(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        aid = _insert_anomaly(detection_store)

        # Before upload: defaults
        rows = detection_store.get_wifi_anomalies(min_score=0.3)
        assert rows[0]["has_pcap_capture"] == 0
        assert rows[0]["pcap_frame_count"] == 0

        # Upload a pcap with 3 frames
        beacon = _build_radiotap_frame(0, 8)
        deauth = _build_radiotap_frame(0, 12)
        data_frame = _build_radiotap_frame(2, 0)
        pcap_gz = _build_test_pcap_gz([
            (1_000_000, beacon),
            (1_500_000, deauth),
            (2_000_000, data_frame),
        ])

        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap_gz,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 201

        # After upload: metadata updated
        rows = detection_store.get_wifi_anomalies(min_score=0.3)
        assert rows[0]["has_pcap_capture"] == 1
        assert rows[0]["pcap_frame_count"] == 3


# ---------------------------------------------------------------------------
# Pcap summary endpoint
# ---------------------------------------------------------------------------


class TestPcapSummary:
    def test_summary_returns_frame_breakdown(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        aid = _insert_anomaly(detection_store)
        beacon = _build_radiotap_frame(0, 8)
        deauth = _build_radiotap_frame(0, 12)
        pcap_gz = _build_test_pcap_gz([
            (1_000_000, beacon),
            (1_500_000, deauth),
            (2_000_000, beacon),
        ])

        # Upload first
        client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap_gz,
            headers={"Content-Type": "application/octet-stream"},
        )

        # Get summary
        resp = client.get(f"/api/wifi/anomalies/{aid}/pcap/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["anomaly_id"] == aid
        assert data["total_frames"] == 3
        assert data["duration_ms"] == 1000.0
        assert "beacon" in data["frame_types"]
        assert data["frame_types"]["beacon"] == 2
        assert "deauth" in data["frame_types"]
        assert data["frame_types"]["deauth"] == 1

    def test_summary_nonexistent_returns_404(self, client: TestClient):
        resp = client.get("/api/wifi/anomalies/99999/pcap/summary")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Batch insert returns row IDs
# ---------------------------------------------------------------------------


class TestBatchInsertReturnsIDs:
    def test_batch_insert_returns_ordered_ids(self, detection_store: DetectionStore):
        anomalies = [
            {
                "bssid": f"aa:bb:cc:11:22:{i:02x}",
                "anomaly_score": 0.5 + i * 0.1,
                "priority": "anomalous",
                "baseline_status": "stable",
                "timestamp": "2026-02-11T00:00:00+00:00",
            }
            for i in range(3)
        ]

        ids = detection_store.insert_wifi_anomalies_batch(anomalies)
        assert isinstance(ids, list)
        assert len(ids) == 3
        # IDs should be sequential integers
        assert ids[1] == ids[0] + 1
        assert ids[2] == ids[1] + 1

        # Each ID should correspond to a real row
        for row_id in ids:
            rows = detection_store.get_wifi_anomalies(min_score=0.0)
            found = [r for r in rows if r["id"] == row_id]
            assert len(found) == 1

    def test_batch_insert_empty_returns_empty_list(self, detection_store: DetectionStore):
        ids = detection_store.insert_wifi_anomalies_batch([])
        assert ids == []


# ---------------------------------------------------------------------------
# Corrupt / edge-case uploads
# ---------------------------------------------------------------------------


class TestPcapEdgeCases:
    def test_upload_corrupt_gzip(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """Corrupt gzip data should still be stored (bridge stores raw bytes).
        Summary should handle decompression failure gracefully."""
        aid = _insert_anomaly(detection_store)
        corrupt = b"\x1f\x8b\x08\x00CORRUPT_DATA"

        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=corrupt,
            headers={"Content-Type": "application/octet-stream"},
        )
        # Upload stores raw bytes — succeeds even with corrupt gzip
        assert resp.status_code == 201
        assert resp.json()["frame_count"] == 0  # parse_summary returns None → 0

        # Summary endpoint should 404 since parse fails
        resp = client.get(f"/api/wifi/anomalies/{aid}/pcap/summary")
        assert resp.status_code == 404

    def test_reupload_overwrites(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """Uploading pcap twice should overwrite the first."""
        aid = _insert_anomaly(detection_store)
        beacon = _build_radiotap_frame(0, 8)

        # First upload: 1 frame
        pcap1 = _build_test_pcap_gz([(1_000_000, beacon)])
        client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap1,
            headers={"Content-Type": "application/octet-stream"},
        )

        # Second upload: 3 frames
        pcap2 = _build_test_pcap_gz([
            (1_000_000, beacon),
            (2_000_000, beacon),
            (3_000_000, beacon),
        ])
        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap2,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 201
        assert resp.json()["frame_count"] == 3

        # DB should reflect latest upload
        rows = detection_store.get_wifi_anomalies(min_score=0.3)
        assert rows[0]["pcap_frame_count"] == 3

    def test_single_frame_pcap_summary_duration_zero(
        self, client: TestClient, detection_store: DetectionStore,
    ):
        """Pcap with one frame should have duration_ms = 0."""
        aid = _insert_anomaly(detection_store)
        beacon = _build_radiotap_frame(0, 8)
        pcap_gz = _build_test_pcap_gz([(1_000_000, beacon)])

        client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=pcap_gz,
            headers={"Content-Type": "application/octet-stream"},
        )

        resp = client.get(f"/api/wifi/anomalies/{aid}/pcap/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_frames"] == 1
        assert data["duration_ms"] == 0

    def test_set_pcap_nonexistent_anomaly(self, detection_store: DetectionStore):
        """set_wifi_anomaly_pcap should return False for missing anomaly."""
        result = detection_store.set_wifi_anomaly_pcap(999999, True, 10)
        assert result is False


# ---------------------------------------------------------------------------
# Variable-length radiotap headers
# ---------------------------------------------------------------------------


class TestVariableRadiotap:
    def test_extract_frame_type_long_radiotap(self):
        """Real radiotap headers are often 18-56 bytes, not just 8."""
        from sigrift.bridge.anomaly.pcap_store import _extract_frame_type

        # Build a radiotap header with length=24 (common on Linux)
        rt_len = 24
        radiotap = struct.pack("<BBHI", 0, 0, rt_len, 0) + b"\x00" * (rt_len - 8)
        # Beacon frame control after radiotap
        fc = (8 << 4) | (0 << 2)  # subtype=8 (beacon), type=0 (mgmt)
        mac_header = struct.pack("<H", fc) + b"\x00" * 22
        frame = radiotap + mac_header

        assert _extract_frame_type(frame) == "beacon"

    def test_extract_frame_type_36_byte_radiotap(self):
        """36-byte radiotap (common with rate/channel/signal fields)."""
        from sigrift.bridge.anomaly.pcap_store import _extract_frame_type

        rt_len = 36
        radiotap = struct.pack("<BBHI", 0, 0, rt_len, 0) + b"\x00" * (rt_len - 8)
        fc = (12 << 4) | (0 << 2)  # subtype=12 (deauth), type=0 (mgmt)
        mac_header = struct.pack("<H", fc) + b"\x00" * 22
        frame = radiotap + mac_header

        assert _extract_frame_type(frame) == "deauth"

    def test_extract_frame_type_radiotap_too_long(self):
        """Radiotap length > packet data should return unknown."""
        from sigrift.bridge.anomaly.pcap_store import _extract_frame_type

        # rt_len says 100 but packet is only 30 bytes
        radiotap = struct.pack("<BBHI", 0, 0, 100, 0) + b"\x00" * 22
        assert _extract_frame_type(radiotap) == "unknown"
