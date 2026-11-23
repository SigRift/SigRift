"""Tests for packet boundary detection (DSP, storage, API).

Covers:
  - PacketDetector DSP algorithms (energy, entropy, timing)
  - PacketStore SQLite storage
  - /api/packets/* endpoints with RBAC
"""

from __future__ import annotations

import base64
import uuid

import numpy as np
import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_burst_signal(
    n_samples: int = 8192,
    n_bursts: int = 3,
    burst_len: int = 512,
    gap_len: int = 1024,
    snr_db: float = 20.0,
) -> tuple[np.ndarray, list[int]]:
    """Create a test signal with *n_bursts* sine bursts in noise."""
    rng = np.random.default_rng(42)
    noise = (
        rng.standard_normal(n_samples) + 1j * rng.standard_normal(n_samples)
    ) * 0.01
    signal = noise.copy().astype(np.complex64)
    burst_starts: list[int] = []
    for i in range(n_bursts):
        start = 256 + i * (burst_len + gap_len)
        if start + burst_len > n_samples:
            break
        burst = np.exp(2j * np.pi * 0.1 * np.arange(burst_len)).astype(
            np.complex64
        )
        signal[start : start + burst_len] += burst * (10 ** (snr_db / 20))
        burst_starts.append(start)
    return signal, burst_starts


def _make_periodic_signal(
    n_bursts: int = 5,
    burst_len: int = 256,
    gap_len: int = 512,
    snr_db: float = 25.0,
) -> tuple[np.ndarray, list[int]]:
    """Create a periodic burst signal with equal gaps."""
    total = 256 + n_bursts * (burst_len + gap_len)
    return _make_burst_signal(
        n_samples=total,
        n_bursts=n_bursts,
        burst_len=burst_len,
        gap_len=gap_len,
        snr_db=snr_db,
    )


def _iq_to_base64(iq: np.ndarray) -> str:
    """Encode complex64 IQ as base64 string."""
    return base64.b64encode(iq.astype(np.complex64).tobytes()).decode()


# ===========================================================================
# DSP tests
# ===========================================================================


class TestPacketDetectorDSP:
    """Tests for sigrift.lib.dsp.packet_detector."""

    def test_detect_single_burst(self):
        """Single burst in noise is detected."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, starts = _make_burst_signal(n_bursts=1, snr_db=25)
        det = PacketDetector(min_packet_samples=32, min_gap_samples=16)
        packets = det.detect_packets(sig, sample_rate=1e6)
        assert len(packets) == 1
        p = packets[0]
        # Start should be near expected
        assert abs(p.start_sample - starts[0]) < 128

    def test_detect_multiple_bursts(self):
        """Three bursts are found."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, starts = _make_burst_signal(n_bursts=3, snr_db=25)
        det = PacketDetector(min_packet_samples=32, min_gap_samples=16)
        packets = det.detect_packets(sig, sample_rate=1e6)
        assert len(packets) == 3

    def test_no_packets_in_noise(self):
        """Pure noise returns empty list."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        rng = np.random.default_rng(42)
        noise = (
            rng.standard_normal(4096) + 1j * rng.standard_normal(4096)
        ).astype(np.complex64) * 0.01
        det = PacketDetector()
        packets = det.detect_packets(noise)
        assert len(packets) == 0

    def test_energy_profile_shape(self):
        """Energy profile has correct output shape."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_burst_signal()
        det = PacketDetector()
        profile = det.compute_energy_profile(sig, window=64)
        assert len(profile) == len(sig) - 64 + 1

    def test_entropy_profile_shape(self):
        """Entropy profile has correct output shape."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_burst_signal()
        det = PacketDetector()
        profile = det.compute_entropy_profile(sig, window=64)
        assert len(profile) == len(sig) - 64 + 1

    def test_noise_floor_estimation(self):
        """Noise floor estimate is reasonable for known noise level."""
        from sigrift.lib.dsp.packet_detector import _estimate_noise_floor, _sliding_power_db

        rng = np.random.default_rng(42)
        noise = (
            rng.standard_normal(4096) + 1j * rng.standard_normal(4096)
        ).astype(np.complex64) * 0.01
        energy = _sliding_power_db(noise, 64)
        nf = _estimate_noise_floor(energy)
        # 0.01 amplitude -> power ~1e-4 -> ~-40 dB
        assert -50 < nf < -30

    def test_packet_boundaries_accurate(self):
        """Detected start/end are within tolerance of true boundaries."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, starts = _make_burst_signal(
            n_bursts=1, burst_len=512, snr_db=30
        )
        det = PacketDetector(min_packet_samples=32, min_gap_samples=16, entropy_window=32)
        packets = det.detect_packets(sig)
        assert len(packets) >= 1
        assert hasattr(packets[0], 'start_sample')
        p = packets[0]
        # Within 128 samples of true start
        assert abs(p.start_sample - starts[0]) < 128
        # End should be near start + 512
        assert abs(p.end_sample - (starts[0] + 512)) < 128

    def test_min_packet_filter(self):
        """Short bursts are filtered out by min_packet_samples."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        # Create a very short burst
        sig, _ = _make_burst_signal(
            n_bursts=1, burst_len=32, snr_db=30, n_samples=4096
        )
        # With min_packet=256, the 32-sample burst should be filtered
        det = PacketDetector(min_packet_samples=256)
        packets = det.detect_packets(sig)
        assert len(packets) == 0

    def test_merge_close_segments(self):
        """Segments close together are merged when gap < min_gap_samples."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        # Two bursts very close together (gap=16) with min_gap=64
        sig, starts = _make_burst_signal(
            n_bursts=2, burst_len=256, gap_len=16, snr_db=30, n_samples=4096
        )
        det = PacketDetector(
            min_packet_samples=32, min_gap_samples=64, entropy_window=32
        )
        packets = det.detect_packets(sig)
        # Should be merged into 1 packet
        assert len(packets) == 1

    def test_timing_analysis_periodic(self):
        """Periodic signal gaps are detected as periodic."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_periodic_signal(n_bursts=5, gap_len=512, snr_db=30)
        det = PacketDetector(min_packet_samples=32, min_gap_samples=16, entropy_window=32)
        packets = det.detect_packets(sig, sample_rate=1e6)
        assert len(packets) >= 4
        timing = det.analyze_timing(packets, sample_rate=1e6)
        assert timing.is_periodic is True
        assert timing.estimated_period_seconds is not None
        assert isinstance(timing.estimated_period_seconds, float)

    def test_timing_analysis_aperiodic(self):
        """Random gaps are detected as not periodic."""
        from sigrift.lib.dsp.packet_detector import PacketDetector, PacketBoundary

        # Create packets with highly variable gaps to ensure CV > 0.25
        gap_values = [200, 5000, 300, 8000, 100]
        packets = []
        pos = 0
        for gap in gap_values:
            start = pos + gap
            end = start + 256
            packets.append(
                PacketBoundary(
                    start_sample=start,
                    end_sample=end,
                    duration_samples=256,
                    duration_seconds=256 / 1e6,
                    peak_energy_db=0.0,
                    mean_energy_db=-5.0,
                    mean_entropy=1.0,
                    snr_estimate_db=20.0,
                    confidence=0.9,
                )
            )
            pos = end

        det = PacketDetector()
        timing = det.analyze_timing(packets, sample_rate=1e6)
        assert timing.is_periodic is False

    def test_duty_cycle_calculation(self):
        """Duty cycle is correctly computed."""
        from sigrift.lib.dsp.packet_detector import PacketDetector, PacketBoundary

        # 2 packets, each 500 samples long, total span 2000 samples
        packets = [
            PacketBoundary(
                start_sample=0, end_sample=500,
                duration_samples=500, duration_seconds=500.0,
                peak_energy_db=0.0, mean_energy_db=0.0,
                mean_entropy=1.0, snr_estimate_db=20.0, confidence=0.9,
            ),
            PacketBoundary(
                start_sample=1500, end_sample=2000,
                duration_samples=500, duration_seconds=500.0,
                peak_energy_db=0.0, mean_energy_db=0.0,
                mean_entropy=1.0, snr_estimate_db=20.0, confidence=0.9,
            ),
        ]
        det = PacketDetector()
        timing = det.analyze_timing(packets, sample_rate=1.0)
        # total_tx = 1000, total_duration = 2000, duty_cycle = 0.5
        assert abs(timing.duty_cycle - 0.5) < 0.01

    def test_snr_estimation(self):
        """SNR estimate is positive for strong signals."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_burst_signal(n_bursts=1, snr_db=25)
        det = PacketDetector(min_packet_samples=32)
        packets = det.detect_packets(sig)
        assert len(packets) >= 1
        assert isinstance(packets[0].snr_estimate_db, float)
        assert packets[0].snr_estimate_db > 5.0

    def test_confidence_high_snr(self):
        """High SNR produces high confidence."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_burst_signal(n_bursts=1, snr_db=40)
        det = PacketDetector(min_packet_samples=32)
        packets = det.detect_packets(sig)
        assert len(packets) >= 1
        assert isinstance(packets[0].confidence, float)
        assert packets[0].confidence > 0.5

    def test_high_energy_threshold(self):
        """Higher threshold detects fewer packets."""
        from sigrift.lib.dsp.packet_detector import PacketDetector

        sig, _ = _make_burst_signal(n_bursts=3, snr_db=15)
        det_low = PacketDetector(
            energy_threshold_db=-30.0, min_packet_samples=32
        )
        det_high = PacketDetector(
            energy_threshold_db=-5.0, min_packet_samples=32
        )
        pkts_low = det_low.detect_packets(sig)
        pkts_high = det_high.detect_packets(sig)
        assert len(pkts_high) <= len(pkts_low)


# ===========================================================================
# Storage tests
# ===========================================================================


class TestPacketStore:
    """Tests for sigrift.bridge.storage.packets.PacketStore."""

    @pytest.fixture
    def store(self, detection_store):
        from sigrift.bridge.storage.packets import PacketStore

        return PacketStore(detection_store._ctx)

    def test_store_packets(self, store):
        """Stores and retrieves packet records."""
        det_id = str(uuid.uuid4())
        pkts = [
            {
                "packet_index": 0,
                "start_sample": 100,
                "end_sample": 600,
                "duration_samples": 500,
                "duration_seconds": 0.0005,
                "peak_energy_db": -10.0,
                "mean_energy_db": -15.0,
                "mean_entropy": 1.5,
                "snr_estimate_db": 20.0,
                "confidence": 0.9,
            },
            {
                "packet_index": 1,
                "start_sample": 1200,
                "end_sample": 1700,
                "duration_samples": 500,
                "duration_seconds": 0.0005,
                "peak_energy_db": -12.0,
                "mean_energy_db": -17.0,
                "mean_entropy": 1.4,
                "snr_estimate_db": 18.0,
                "confidence": 0.85,
            },
        ]
        ids = store.store_packets(det_id, pkts)
        assert len(ids) == 2

        retrieved = store.get_packets_for(det_id)
        assert len(retrieved) == 2
        assert retrieved[0]["start_sample"] == 100
        assert retrieved[1]["start_sample"] == 1200

    def test_store_timing(self, store):
        """Stores and retrieves timing analysis."""
        det_id = str(uuid.uuid4())
        timing = {
            "n_packets": 3,
            "mean_gap_seconds": 0.001,
            "std_gap_seconds": 0.0001,
            "is_periodic": True,
            "estimated_period_seconds": 0.001,
            "duty_cycle": 0.33,
        }
        tid = store.store_timing(det_id, timing)
        assert isinstance(tid, str) and len(tid) > 0

        retrieved = store.get_timing_for(det_id)
        assert retrieved is not None
        assert isinstance(retrieved, dict)
        assert retrieved["n_packets"] == 3
        assert retrieved["is_periodic"] is True

    def test_get_packets_for(self, store):
        """Filter by detection_id returns only matching records."""
        det_a = str(uuid.uuid4())
        det_b = str(uuid.uuid4())
        store.store_packets(det_a, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100},
        ])
        store.store_packets(det_b, [
            {"packet_index": 0, "start_sample": 200, "end_sample": 300,
             "duration_samples": 100},
        ])
        assert len(store.get_packets_for(det_a)) == 1
        assert len(store.get_packets_for(det_b)) == 1
        assert store.get_packets_for(det_a)[0]["start_sample"] == 0

    def test_delete_analysis(self, store):
        """Delete removes packets and timing for detection_id."""
        det_id = str(uuid.uuid4())
        store.store_packets(det_id, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100},
        ])
        store.store_timing(det_id, {"n_packets": 1, "duty_cycle": 0.5})

        assert store.delete_analysis(det_id) is True
        assert len(store.get_packets_for(det_id)) == 0
        assert store.get_timing_for(det_id) is None

    def test_stats(self, store):
        """Stats returns correct counts."""
        det_id = str(uuid.uuid4())
        store.store_packets(det_id, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100},
            {"packet_index": 1, "start_sample": 200, "end_sample": 300,
             "duration_samples": 100},
        ])
        store.store_timing(det_id, {
            "n_packets": 2, "is_periodic": True, "duty_cycle": 0.5,
        })

        stats = store.get_stats()
        assert stats["total_packets"] == 2
        assert stats["total_analyses"] == 1
        assert stats["periodic_count"] == 1

    def test_list_analyses(self, store):
        """list_analyses returns timing records."""
        for _ in range(3):
            det_id = str(uuid.uuid4())
            store.store_timing(det_id, {"n_packets": 2, "duty_cycle": 0.5})

        analyses = store.list_analyses(limit=10)
        assert len(analyses) == 3


# ===========================================================================
# API tests
# ===========================================================================


class TestPacketsAPI:
    """Tests for /api/packets/* endpoints."""

    def test_detect_requires_analyst(self, bridge_app, master_key):
        """VIEWER role cannot run detection (requires ANALYST)."""
        from sigrift.lib.security.credentials import hash_credential

        viewer_key = "viewer-key-12345678"
        h, s = hash_credential(viewer_key)
        bridge_app.state.persistence.set_key("viewer_pkt", h, s)
        bridge_app.state.persistence.set_key_meta(
            "viewer_pkt", {"role": "viewer"}
        )
        viewer_client = TestClient(
            bridge_app, headers={"X-API-Key": viewer_key}
        )
        resp = viewer_client.post(
            "/api/packets/detect",
            json={"detection_id": "det-1"},
        )
        assert resp.status_code == 403

    def test_detect_raw_returns_packets(self, client):
        """POST /detect/raw with burst signal returns detected packets."""
        sig, starts = _make_burst_signal(n_bursts=2, snr_db=25)
        payload = {
            "iq_base64": _iq_to_base64(sig),
            "sample_rate": 1e6,
            "min_packet_samples": 32,
            "min_gap_samples": 16,
            "entropy_window": 32,
        }
        resp = client.post("/api/packets/detect/raw", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "packets" in data
        assert isinstance(data["packets"], list)
        assert len(data["packets"]) >= 1
        assert "timing" in data
        assert isinstance(data["timing"], dict)

    def test_get_packets(self, client, bridge_app):
        """GET /detection/{id} returns stored packets."""
        det_id = str(uuid.uuid4())
        store = bridge_app.state.packet_store
        store.store_packets(det_id, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100, "confidence": 0.9},
        ])
        resp = client.get(f"/api/packets/detection/{det_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1

    def test_get_timing(self, client, bridge_app):
        """GET /detection/{id}/timing returns timing analysis."""
        det_id = str(uuid.uuid4())
        store = bridge_app.state.packet_store
        store.store_timing(det_id, {"n_packets": 3, "duty_cycle": 0.5})
        resp = client.get(f"/api/packets/detection/{det_id}/timing")
        assert resp.status_code == 200
        data = resp.json()
        assert data["n_packets"] == 3

    def test_get_timing_404(self, client):
        """GET /detection/{id}/timing returns 404 for missing."""
        resp = client.get("/api/packets/detection/nonexistent/timing")
        assert resp.status_code == 404

    def test_list_analyses(self, client, bridge_app):
        """GET / returns list of analyses."""
        store = bridge_app.state.packet_store
        for _ in range(2):
            store.store_timing(
                str(uuid.uuid4()), {"n_packets": 1, "duty_cycle": 0.1}
            )
        resp = client.get("/api/packets/")
        assert resp.status_code == 200
        result = resp.json()
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_delete_analysis(self, client, bridge_app):
        """DELETE /{detection_id} removes analysis."""
        det_id = str(uuid.uuid4())
        store = bridge_app.state.packet_store
        store.store_packets(det_id, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100},
        ])
        store.store_timing(det_id, {"n_packets": 1, "duty_cycle": 0.5})

        resp = client.delete(f"/api/packets/{det_id}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_analysis_404(self, client):
        """DELETE with unknown ID returns 404."""
        resp = client.delete("/api/packets/nonexistent")
        assert resp.status_code == 404

    def test_stats(self, client, bridge_app):
        """GET /stats returns counts."""
        store = bridge_app.state.packet_store
        det_id = str(uuid.uuid4())
        store.store_packets(det_id, [
            {"packet_index": 0, "start_sample": 0, "end_sample": 100,
             "duration_samples": 100},
        ])
        store.store_timing(det_id, {"n_packets": 1, "duty_cycle": 0.5})

        resp = client.get("/api/packets/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_packets" in data
        assert isinstance(data["total_packets"], int)
        assert "total_analyses" in data
        assert isinstance(data["total_analyses"], int)

    def test_detect_raw_noise_only(self, client):
        """POST /detect/raw with pure noise returns empty packets."""
        rng = np.random.default_rng(42)
        noise = (
            rng.standard_normal(4096) + 1j * rng.standard_normal(4096)
        ).astype(np.complex64) * 0.01
        resp = client.post(
            "/api/packets/detect/raw",
            json={
                "iq_base64": _iq_to_base64(noise),
                "sample_rate": 1e6,
            },
        )
        assert resp.status_code == 200
        assert len(resp.json()["packets"]) == 0
