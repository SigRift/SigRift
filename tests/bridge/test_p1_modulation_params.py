"""Tests for P1-2: Modulation parameter extraction (symbol rate, bandwidth, CFO).

Tests cover:
  - Symbol rate estimation (BPSK signal vs pure noise)
  - Occupied bandwidth estimation (narrowband vs wideband)
  - CFO estimation (zero offset vs known offset)
  - Combined parameter extraction
  - HTTP endpoint integration (200 and 404 cases)
"""

from __future__ import annotations

import gzip

import numpy as np

from sigrift.lib.dsp.modulation_params import (
    estimate_cfo,
    estimate_occupied_bandwidth,
    estimate_symbol_rate,
    extract_modulation_params,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bpsk(n_symbols: int = 200, samples_per_symbol: int = 10, seed: int = 42,
               noise_std: float = 0.1) -> np.ndarray:
    """Generate a BPSK signal with known symbol rate and additive noise.

    Adding noise breaks the constant-envelope property of pure rectangular
    BPSK, which is necessary for the cyclostationary symbol-rate estimator
    to detect spectral lines in |x(t)|^2.
    """
    rng = np.random.default_rng(seed)
    symbols = rng.choice([-1.0, 1.0], size=n_symbols)
    upsampled = np.repeat(symbols, samples_per_symbol)
    noise = noise_std * (rng.standard_normal(len(upsampled)) + 1j * rng.standard_normal(len(upsampled)))
    return (upsampled + noise).astype(np.complex64)


def _make_tone(n: int = 1000, freq: float = 0.0) -> np.ndarray:
    """Generate a pure complex tone -- ideal for CFO testing."""
    t = np.arange(n)
    return np.exp(1j * 2 * np.pi * freq * t).astype(np.complex64)


def _apply_cfo(iq: np.ndarray, cfo_normalized: float) -> np.ndarray:
    """Apply a carrier frequency offset to IQ data."""
    t = np.arange(len(iq))
    return (iq * np.exp(1j * 2 * np.pi * cfo_normalized * t)).astype(np.complex64)


def _make_noise(n: int = 2000, seed: int = 99) -> np.ndarray:
    """Generate complex Gaussian noise."""
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)


def _iq_to_gzip_bytes(iq: np.ndarray) -> bytes:
    """Convert complex64 IQ array to gzip-compressed interleaved float32 bytes."""
    interleaved = np.empty(len(iq) * 2, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return gzip.compress(interleaved.tobytes())


# ---------------------------------------------------------------------------
# Symbol rate tests
# ---------------------------------------------------------------------------

class TestSymbolRate:
    def test_symbol_rate_bpsk(self):
        """BPSK signal at 0.1 symbols/sample should produce a detectable symbol rate."""
        iq = _make_bpsk(n_symbols=200, samples_per_symbol=10, noise_std=0.3)
        result = estimate_symbol_rate(iq, sample_rate=1.0)

        assert isinstance(result["symbol_rate_hz"], float)
        assert result["symbol_rate_hz"] > 0.0
        assert isinstance(result["confidence"], float)
        assert result["confidence"] > 0.0
        assert isinstance(result["spectral_peaks"], list)
        assert len(result["spectral_peaks"]) > 0
        assert all(isinstance(p, (list, tuple)) and len(p) == 2 for p in result["spectral_peaks"])

    def test_symbol_rate_noise(self):
        """Pure noise should return low confidence."""
        iq = _make_noise(n=2000)
        result = estimate_symbol_rate(iq, sample_rate=1.0)

        # Noise may find spurious peaks but confidence should be low
        assert result["confidence"] < 0.5

    def test_symbol_rate_short_signal(self):
        """Signal shorter than 64 samples returns zeros."""
        iq = np.ones(32, dtype=np.complex64)
        result = estimate_symbol_rate(iq)

        assert result["symbol_rate_hz"] == 0.0
        assert result["confidence"] == 0.0
        assert result["spectral_peaks"] == []


# ---------------------------------------------------------------------------
# Bandwidth tests
# ---------------------------------------------------------------------------

class TestBandwidth:
    def test_bandwidth_narrowband(self):
        """A narrowband signal (single tone) has small bandwidth."""
        iq = _make_tone(n=2048, freq=0.01)
        result = estimate_occupied_bandwidth(iq, sample_rate=1.0)

        assert result["bandwidth_hz"] >= 0.0
        assert result["bandwidth_3db_hz"] >= 0.0
        # Narrowband: -3dB BW should be much less than Nyquist
        assert result["bandwidth_3db_hz"] < 0.1

    def test_bandwidth_wideband(self):
        """A wideband signal (noise) occupies a larger bandwidth."""
        iq = _make_noise(n=4096)
        result = estimate_occupied_bandwidth(iq, sample_rate=1.0)

        # White noise should have broad bandwidth
        assert result["bandwidth_hz"] > 0.3
        assert result["bandwidth_20db_hz"] > 0.3

    def test_bandwidth_short_signal(self):
        """Signal shorter than 64 samples returns zeros."""
        iq = np.ones(32, dtype=np.complex64)
        result = estimate_occupied_bandwidth(iq)

        assert result["bandwidth_hz"] == 0.0
        assert result["bandwidth_3db_hz"] == 0.0

    def test_bandwidth_keys(self):
        """Verify all expected keys are present."""
        iq = _make_noise(n=512)
        result = estimate_occupied_bandwidth(iq)
        assert "bandwidth_hz" in result
        assert isinstance(result["bandwidth_hz"], float)
        assert "bandwidth_3db_hz" in result
        assert isinstance(result["bandwidth_3db_hz"], float)
        assert "bandwidth_20db_hz" in result
        assert isinstance(result["bandwidth_20db_hz"], float)
        assert "center_offset_hz" in result
        assert isinstance(result["center_offset_hz"], float)


# ---------------------------------------------------------------------------
# CFO tests
# ---------------------------------------------------------------------------

class TestCFO:
    def test_cfo_zero(self):
        """Signal with no CFO returns approximately zero."""
        iq = _make_tone(n=1000, freq=0.0)
        result = estimate_cfo(iq, sample_rate=1.0)

        assert abs(result["cfo_hz"]) < 0.001
        assert abs(result["cfo_normalized"]) < 0.001

    def test_cfo_offset(self):
        """Signal with a known CFO is estimated correctly."""
        cfo_true = 0.05  # normalized frequency offset
        iq = _make_tone(n=1000, freq=cfo_true)

        result = estimate_cfo(iq, sample_rate=1.0)

        # Should be within 1% of the true CFO
        assert abs(result["cfo_normalized"] - cfo_true) < 0.005
        assert abs(result["cfo_hz"] - cfo_true) < 0.005

    def test_cfo_negative_offset(self):
        """Negative CFO is estimated correctly."""
        cfo_true = -0.03
        iq = _make_tone(n=1000, freq=cfo_true)

        result = estimate_cfo(iq, sample_rate=1.0)
        assert abs(result["cfo_normalized"] - cfo_true) < 0.005

    def test_cfo_short_signal(self):
        """Signal shorter than 32 samples returns zeros."""
        iq = np.ones(16, dtype=np.complex64)
        result = estimate_cfo(iq)

        assert result["cfo_hz"] == 0.0
        assert result["cfo_normalized"] == 0.0


# ---------------------------------------------------------------------------
# Combined extraction
# ---------------------------------------------------------------------------

class TestExtractAll:
    def test_extract_all_params(self):
        """Combined function returns all expected fields."""
        iq = _make_bpsk(n_symbols=200, samples_per_symbol=10)
        result = extract_modulation_params(iq, sample_rate=2.048e6)

        assert "symbol_rate" in result
        assert isinstance(result["symbol_rate"], dict)
        assert "bandwidth" in result
        assert isinstance(result["bandwidth"], dict)
        assert "cfo" in result
        assert isinstance(result["cfo"], dict)
        assert result["n_samples"] == len(iq)
        assert result["sample_rate_hz"] == 2.048e6

        # Sub-dicts have expected keys
        assert "symbol_rate_hz" in result["symbol_rate"]
        assert isinstance(result["symbol_rate"]["symbol_rate_hz"], float)
        assert "confidence" in result["symbol_rate"]
        assert isinstance(result["symbol_rate"]["confidence"], float)
        assert "bandwidth_hz" in result["bandwidth"]
        assert isinstance(result["bandwidth"]["bandwidth_hz"], float)
        assert "cfo_hz" in result["cfo"]
        assert isinstance(result["cfo"]["cfo_hz"], float)


# ---------------------------------------------------------------------------
# Endpoint integration tests
# ---------------------------------------------------------------------------

class TestModulationEndpoint:
    def test_modulation_endpoint_200(self, client, detection_store, bridge_app):
        """GET /api/detections/{id}/modulation returns 200 with IQ data present."""
        from sigrift.bridge.iq_store import IQStore
        from sigrift.bridge.tests.conftest import make_detection
        import tempfile

        # Create a detection and insert it
        det = make_detection(signal_class="bpsk")
        detection_store.insert_batch([det])
        det_id = det.detection_id

        # Set up IQ store with temp dir
        with tempfile.TemporaryDirectory() as tmpdir:
            iq_store = IQStore(base_dir=tmpdir)
            bridge_app.state.iq_store = iq_store

            # Store synthetic IQ data
            iq = _make_bpsk(n_symbols=100, samples_per_symbol=10)
            compressed = _iq_to_gzip_bytes(iq)
            iq_store.store(det_id, compressed)

            resp = client.get(f"/api/detections/{det_id}/modulation")
            assert resp.status_code == 200

            data = resp.json()
            assert "symbol_rate" in data
            assert isinstance(data["symbol_rate"], dict)
            assert "bandwidth" in data
            assert isinstance(data["bandwidth"], dict)
            assert "cfo" in data
            assert isinstance(data["cfo"], dict)
            assert data["n_samples"] == len(iq)

    def test_modulation_endpoint_404(self, client):
        """GET /api/detections/{id}/modulation returns 404 for missing IQ data."""
        resp = client.get("/api/detections/nonexistent-id/modulation")
        # Should be 404 (no IQ capture) or 503 (no IQ store)
        assert resp.status_code in (404, 503)
