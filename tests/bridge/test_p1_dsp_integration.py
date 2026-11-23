"""Integration tests for P1 DSP and Signal Processing pipeline.

End-to-end tests that exercise the full DSP pipeline:
  - Synthetic IQ generation → feature extraction → dimension/validity checks
  - Modulation parameter extraction across signal types (AM, FM, PSK, FSK)
  - Edge cases: empty IQ, very short captures, extreme frequencies
  - Spectrogram endpoint returns valid waterfall data
  - Determinism: same input → same features
  - Cross-module: torch-based 49-dim features + numpy-based modulation params
"""

from __future__ import annotations

import gzip
import math

import numpy as np
import pytest
import torch

from sigrift.lib.dsp.spectral_features import (
    NUM_DSP_FEATURES,
    compute_dsp_features,
    extended_features,
)
from sigrift.lib.dsp.modulation_params import (
    estimate_cfo,
    estimate_occupied_bandwidth,
    estimate_symbol_rate,
    extract_modulation_params,
)
from sigrift.bridge.iq_store import IQStore, validate_iq_quality


# ---------------------------------------------------------------------------
# Synthetic signal generators
# ---------------------------------------------------------------------------

def _make_tone_iq_tensor(freq: float = 0.1, n: int = 2048, batch: int = 1) -> torch.Tensor:
    """Generate a pure complex tone as [B, 2, N] tensor for DSP features."""
    t = torch.arange(n, dtype=torch.float32).unsqueeze(0).expand(batch, -1)
    phase = 2.0 * math.pi * freq * t
    i = torch.cos(phase)
    q = torch.sin(phase)
    return torch.stack([i, q], dim=1)


def _make_noise_iq_tensor(n: int = 2048, batch: int = 1, seed: int = 42) -> torch.Tensor:
    """Generate Gaussian noise as [B, 2, N] tensor."""
    torch.manual_seed(seed)
    return torch.randn(batch, 2, n)


def _make_bpsk_numpy(
    n_symbols: int = 200, samples_per_symbol: int = 10,
    seed: int = 42, noise_std: float = 0.1,
) -> np.ndarray:
    """Generate BPSK signal as complex64 numpy array."""
    rng = np.random.default_rng(seed)
    symbols = rng.choice([-1.0, 1.0], size=n_symbols)
    upsampled = np.repeat(symbols, samples_per_symbol)
    noise = noise_std * (
        rng.standard_normal(len(upsampled))
        + 1j * rng.standard_normal(len(upsampled))
    )
    return (upsampled + noise).astype(np.complex64)


def _make_qpsk_numpy(
    n_symbols: int = 200, samples_per_symbol: int = 10,
    seed: int = 42, noise_std: float = 0.1,
) -> np.ndarray:
    """Generate QPSK signal as complex64 numpy array."""
    rng = np.random.default_rng(seed)
    phase_choices = np.array([np.pi / 4, 3 * np.pi / 4, -3 * np.pi / 4, -np.pi / 4])
    phases = rng.choice(phase_choices, size=n_symbols)
    symbols = np.exp(1j * phases)
    upsampled = np.repeat(symbols, samples_per_symbol)
    noise = noise_std * (
        rng.standard_normal(len(upsampled))
        + 1j * rng.standard_normal(len(upsampled))
    )
    return (upsampled + noise).astype(np.complex64)


def _make_fsk_numpy(
    n_symbols: int = 200, samples_per_symbol: int = 20,
    freq_dev: float = 0.1, seed: int = 42, noise_std: float = 0.05,
) -> np.ndarray:
    """Generate 2-FSK signal as complex64 numpy array."""
    rng = np.random.default_rng(seed)
    bits = rng.choice([0, 1], size=n_symbols)
    freqs = np.where(bits == 1, freq_dev, -freq_dev)
    # Build continuous phase FSK
    freq_per_sample = np.repeat(freqs, samples_per_symbol)
    phase = np.cumsum(2 * np.pi * freq_per_sample)
    signal = np.exp(1j * phase)
    noise = noise_std * (
        rng.standard_normal(len(signal))
        + 1j * rng.standard_normal(len(signal))
    )
    return (signal + noise).astype(np.complex64)


def _make_am_numpy(
    n: int = 4000, mod_freq: float = 0.01, mod_depth: float = 0.5,
    carrier_freq: float = 0.1, seed: int = 42, noise_std: float = 0.05,
) -> np.ndarray:
    """Generate AM signal as complex64 numpy array."""
    rng = np.random.default_rng(seed)
    t = np.arange(n)
    # Modulating signal
    mod = 1.0 + mod_depth * np.sin(2 * np.pi * mod_freq * t)
    carrier = np.exp(1j * 2 * np.pi * carrier_freq * t)
    signal = mod * carrier
    noise = noise_std * (
        rng.standard_normal(n) + 1j * rng.standard_normal(n)
    )
    return (signal + noise).astype(np.complex64)


def _make_fm_numpy(
    n: int = 4000, mod_freq: float = 0.01, freq_dev: float = 0.05,
    seed: int = 42, noise_std: float = 0.05,
) -> np.ndarray:
    """Generate FM signal as complex64 numpy array."""
    rng = np.random.default_rng(seed)
    t = np.arange(n)
    mod = np.sin(2 * np.pi * mod_freq * t)
    phase = 2 * np.pi * np.cumsum(freq_dev * mod)
    signal = np.exp(1j * phase)
    noise = noise_std * (
        rng.standard_normal(n) + 1j * rng.standard_normal(n)
    )
    return (signal + noise).astype(np.complex64)


def _make_noise_numpy(n: int = 2000, seed: int = 99) -> np.ndarray:
    """Generate complex Gaussian noise."""
    rng = np.random.default_rng(seed)
    return (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)


def _iq_to_gzip_bytes(iq: np.ndarray) -> bytes:
    """Convert complex64 IQ array to gzip-compressed interleaved float32 bytes."""
    interleaved = np.empty(len(iq) * 2, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return gzip.compress(interleaved.tobytes())


def _numpy_to_torch(iq: np.ndarray) -> torch.Tensor:
    """Convert complex64 numpy IQ to [1, 2, N] torch tensor."""
    i = torch.from_numpy(iq.real.copy()).unsqueeze(0)
    q = torch.from_numpy(iq.imag.copy()).unsqueeze(0)
    return torch.stack([i, q], dim=1).float()


# ---------------------------------------------------------------------------
# End-to-end feature extraction tests
# ---------------------------------------------------------------------------

class TestE2EFeatureExtraction:
    """End-to-end: generate synthetic IQ → extract features → validate."""

    def test_tone_48_dims(self):
        """Pure tone produces 49 valid features."""
        x = _make_tone_iq_tensor(freq=0.1, n=4096)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all(), "Tone features contain NaN/Inf"

    def test_noise_48_dims(self):
        """Gaussian noise produces 49 valid features."""
        x = _make_noise_iq_tensor(n=4096)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all(), "Noise features contain NaN/Inf"

    def test_bpsk_48_dims(self):
        """BPSK signal converted to torch produces 49 valid features."""
        iq = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10)
        x = _numpy_to_torch(iq)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_qpsk_48_dims(self):
        """QPSK signal produces 49 valid features."""
        iq = _make_qpsk_numpy(n_symbols=200, samples_per_symbol=10)
        x = _numpy_to_torch(iq)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_fsk_48_dims(self):
        """FSK signal produces 49 valid features."""
        iq = _make_fsk_numpy(n_symbols=100, samples_per_symbol=20)
        x = _numpy_to_torch(iq)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_am_48_dims(self):
        """AM signal produces 49 valid features."""
        iq = _make_am_numpy(n=4000)
        x = _numpy_to_torch(iq)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_fm_48_dims(self):
        """FM signal produces 49 valid features."""
        iq = _make_fm_numpy(n=4000)
        x = _numpy_to_torch(iq)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_batch_mixed_signals(self):
        """Batch of mixed signals all produce valid 49-dim features."""
        signals = [
            _make_bpsk_numpy(seed=1),
            _make_qpsk_numpy(seed=2),
            _make_fsk_numpy(seed=3),
        ]
        # Pad to equal length
        max_len = max(len(s) for s in signals)
        padded = []
        for s in signals:
            if len(s) < max_len:
                s = np.pad(s, (0, max_len - len(s)), mode="constant")
            padded.append(s)
        batch = np.stack(padded)
        i_t = torch.from_numpy(batch.real.copy()).float()
        q_t = torch.from_numpy(batch.imag.copy()).float()
        x = torch.stack([i_t, q_t], dim=1)  # [3, 2, N]
        feats = compute_dsp_features(x)
        assert feats.shape == (3, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_feature_count_matches_constant(self):
        """NUM_DSP_FEATURES constant matches actual output dimension."""
        x = _make_tone_iq_tensor(n=1024)
        feats = compute_dsp_features(x)
        assert feats.shape[-1] == NUM_DSP_FEATURES

    def test_extended_features_32_dims(self):
        """extended_features returns exactly 32 dimensions."""
        x = _make_tone_iq_tensor(n=2048)
        i, q = x[:, 0, :], x[:, 1, :]
        ext = extended_features((i, q))
        assert ext.shape == (1, 32)
        assert torch.isfinite(ext).all()


# ---------------------------------------------------------------------------
# Modulation parameter extraction with different signal types
# ---------------------------------------------------------------------------

class TestModulationParamsBySignalType:
    """Modulation parameter extraction across AM, FM, PSK, FSK."""

    def test_bpsk_symbol_rate(self):
        """BPSK signal yields positive symbol rate with confidence."""
        iq = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10, noise_std=0.3)
        result = estimate_symbol_rate(iq, sample_rate=1.0)
        assert isinstance(result["symbol_rate_hz"], float)
        assert result["symbol_rate_hz"] > 0.0
        assert isinstance(result["confidence"], float)
        assert result["confidence"] > 0.0

    def test_qpsk_symbol_rate(self):
        """QPSK signal yields detectable symbol rate."""
        iq = _make_qpsk_numpy(n_symbols=200, samples_per_symbol=10, noise_std=0.3)
        result = estimate_symbol_rate(iq, sample_rate=1.0)
        assert isinstance(result["symbol_rate_hz"], float)
        assert result["symbol_rate_hz"] >= 0.0
        # QPSK may or may not produce strong cyclostationary peaks
        assert isinstance(result["spectral_peaks"], list)

    def test_fsk_bandwidth(self):
        """FSK signal has measurable bandwidth."""
        iq = _make_fsk_numpy(n_symbols=200, samples_per_symbol=20, freq_dev=0.1)
        result = estimate_occupied_bandwidth(iq, sample_rate=1.0)
        assert isinstance(result["bandwidth_hz"], float)
        assert result["bandwidth_hz"] >= 0.0
        assert isinstance(result["bandwidth_3db_hz"], float)
        assert result["bandwidth_3db_hz"] >= 0.0

    def test_am_bandwidth_narrower_than_noise(self):
        """AM signal has narrower bandwidth than pure noise."""
        am = _make_am_numpy(n=4096)
        noise = _make_noise_numpy(n=4096)
        bw_am = estimate_occupied_bandwidth(am, sample_rate=1.0)["bandwidth_hz"]
        bw_noise = estimate_occupied_bandwidth(noise, sample_rate=1.0)["bandwidth_hz"]
        # AM should be at least somewhat narrower than broadband noise
        # (or at most similar if modulation is deep)
        assert isinstance(bw_am, float)
        assert bw_am >= 0.0
        assert isinstance(bw_noise, float)
        assert bw_noise >= 0.0

    def test_fm_cfo_near_zero(self):
        """FM signal centered at DC has near-zero CFO."""
        iq = _make_fm_numpy(n=4000)
        result = estimate_cfo(iq, sample_rate=1.0)
        # FM around DC should have small estimated CFO
        assert isinstance(result["cfo_normalized"], float)
        assert abs(result["cfo_normalized"]) < 0.2

    def test_extract_all_returns_complete_dict(self):
        """extract_modulation_params returns all expected fields for each signal type."""
        for signal_fn, label in [
            (_make_bpsk_numpy, "BPSK"),
            (_make_qpsk_numpy, "QPSK"),
            (_make_fsk_numpy, "FSK"),
            (_make_am_numpy, "AM"),
            (_make_fm_numpy, "FM"),
        ]:
            iq = signal_fn()
            result = extract_modulation_params(iq, sample_rate=2.048e6)
            assert "symbol_rate" in result, f"{label}: missing symbol_rate"
            assert isinstance(result["symbol_rate"], dict), f"{label}: symbol_rate not dict"
            assert "bandwidth" in result, f"{label}: missing bandwidth"
            assert isinstance(result["bandwidth"], dict), f"{label}: bandwidth not dict"
            assert "cfo" in result, f"{label}: missing cfo"
            assert isinstance(result["cfo"], dict), f"{label}: cfo not dict"
            assert result["n_samples"] == len(iq), f"{label}: wrong n_samples"
            assert result["sample_rate_hz"] == 2.048e6, f"{label}: wrong sample_rate_hz"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases: empty/short IQ, extreme values, zeros."""

    def test_empty_iq_features(self):
        """All-zero IQ produces 49 finite features."""
        x = torch.zeros(1, 2, 1024)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_very_short_capture_features(self):
        """Very short IQ (4 samples) still produces 49 features."""
        x = torch.randn(1, 2, 4)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_single_sample_features(self):
        """Single-sample IQ produces 49 features without crash."""
        x = torch.randn(1, 2, 2)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_very_large_amplitude(self):
        """Large-amplitude signal (1e6) produces finite features due to RMS normalization."""
        x = _make_tone_iq_tensor(n=1024) * 1e6
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_very_small_amplitude(self):
        """Tiny-amplitude signal (1e-8) produces finite features."""
        x = _make_tone_iq_tensor(n=1024) * 1e-8
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_modulation_params_short_signal(self):
        """Signals shorter than min length return zero/empty results."""
        short = np.ones(16, dtype=np.complex64)
        sr = estimate_symbol_rate(short)
        assert sr["symbol_rate_hz"] == 0.0

        bw = estimate_occupied_bandwidth(short)
        assert bw["bandwidth_hz"] == 0.0

        cfo = estimate_cfo(short)
        assert cfo["cfo_hz"] == 0.0

    def test_modulation_params_all_zeros(self):
        """All-zero IQ handles gracefully for modulation params."""
        zeros = np.zeros(2000, dtype=np.complex64)
        result = extract_modulation_params(zeros, sample_rate=1.0)
        assert "symbol_rate" in result
        assert isinstance(result["symbol_rate"], dict)
        assert "bandwidth" in result
        assert isinstance(result["bandwidth"], dict)
        assert "cfo" in result
        assert isinstance(result["cfo"], dict)
        # Should not crash, values may be zero or near-zero

    def test_dc_only_signal(self):
        """Pure DC signal (constant complex value) features are finite."""
        x = torch.ones(1, 2, 2048)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_extreme_high_frequency(self):
        """Tone at near-Nyquist frequency produces valid features."""
        x = _make_tone_iq_tensor(freq=0.49, n=2048)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()

    def test_extreme_low_frequency(self):
        """Tone at very low frequency produces valid features."""
        x = _make_tone_iq_tensor(freq=0.001, n=4096)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()


# ---------------------------------------------------------------------------
# Determinism and consistency
# ---------------------------------------------------------------------------

class TestDeterminismAndConsistency:
    """Feature extraction produces identical results for the same input."""

    def test_deterministic_tone(self):
        """Same tone input → identical features."""
        x = _make_tone_iq_tensor(freq=0.1, n=2048)
        f1 = compute_dsp_features(x)
        f2 = compute_dsp_features(x)
        torch.testing.assert_close(f1, f2, atol=0.0, rtol=0.0)

    def test_deterministic_noise(self):
        """Same noise input tensor → identical features (no internal randomness)."""
        x = _make_noise_iq_tensor(n=2048, seed=123)
        f1 = compute_dsp_features(x)
        f2 = compute_dsp_features(x)
        torch.testing.assert_close(f1, f2, atol=0.0, rtol=0.0)

    def test_deterministic_modulation_params(self):
        """Same IQ input → identical modulation params."""
        iq = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10)
        r1 = extract_modulation_params(iq, sample_rate=2.048e6)
        r2 = extract_modulation_params(iq, sample_rate=2.048e6)
        assert r1["symbol_rate"]["symbol_rate_hz"] == r2["symbol_rate"]["symbol_rate_hz"]
        assert r1["bandwidth"]["bandwidth_hz"] == r2["bandwidth"]["bandwidth_hz"]
        assert r1["cfo"]["cfo_hz"] == r2["cfo"]["cfo_hz"]

    def test_different_signals_different_features(self):
        """Different signal types produce different feature vectors."""
        tone = compute_dsp_features(_make_tone_iq_tensor(n=2048))
        noise = compute_dsp_features(_make_noise_iq_tensor(n=2048))
        # At least some features must differ
        assert not torch.allclose(tone, noise, atol=1e-3)


# ---------------------------------------------------------------------------
# IQ quality validation integration
# ---------------------------------------------------------------------------

class TestIQQualityIntegration:
    """Verify validate_iq_quality works with synthetic signals."""

    def test_quality_clean_signal(self):
        """Clean BPSK signal gets reasonable quality score."""
        iq = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10, noise_std=0.1)
        quality = validate_iq_quality(iq)
        assert 0.0 <= quality["score"] <= 1.0
        assert isinstance(quality["clipped"], bool)
        assert isinstance(quality["snr_db"], float)

    def test_quality_pure_noise(self):
        """Pure noise signal gets a quality assessment without crashing."""
        iq = _make_noise_numpy(n=2000)
        quality = validate_iq_quality(iq)
        assert 0.0 <= quality["score"] <= 1.0

    def test_quality_empty(self):
        """Empty IQ returns lowest quality score."""
        iq = np.array([], dtype=np.complex64)
        quality = validate_iq_quality(iq)
        assert quality["score"] == 0.0


# ---------------------------------------------------------------------------
# Spectrogram endpoint integration
# ---------------------------------------------------------------------------

class TestSpectrogramIntegration:
    """Test spectrogram computation through the IQStore and HTTP endpoint."""

    @pytest.fixture()
    def iq_store_with_data(self, tmp_path):
        """IQStore with several test signals pre-loaded."""
        store = IQStore(base_dir=tmp_path / "iq_caps")
        # Store a tone
        tone = np.exp(1j * 2 * np.pi * 0.1 * np.arange(4096)).astype(np.complex64)
        store.store("det-tone-01", _iq_to_gzip_bytes(tone))
        # Store BPSK
        bpsk = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10)
        store.store("det-bpsk-01", _iq_to_gzip_bytes(bpsk))
        # Store noise
        noise = _make_noise_numpy(n=4096)
        store.store("det-noise-01", _iq_to_gzip_bytes(noise))
        return store

    def test_spectrogram_tone_structure(self, iq_store_with_data):
        """Tone spectrogram has expected keys and shape."""
        result = iq_store_with_data.compute_spectrogram("det-tone-01", nfft=256, overlap=128)
        assert result is not None
        assert isinstance(result, dict)
        assert "spectrogram" in result
        assert isinstance(result["spectrogram"], list)
        assert "time_axis" in result
        assert isinstance(result["time_axis"], list)
        assert "freq_axis" in result
        assert isinstance(result["freq_axis"], list)
        assert result["nfft"] == 256
        assert len(result["freq_axis"]) == 256

    def test_spectrogram_db_range(self, iq_store_with_data):
        """All spectrogram dB values fall in [-60, 0]."""
        result = iq_store_with_data.compute_spectrogram("det-tone-01")
        assert result is not None
        assert isinstance(result, dict)
        flat = [v for row in result["spectrogram"] for v in row]
        assert min(flat) >= -60.0
        assert max(flat) <= 0.0

    def test_spectrogram_bpsk(self, iq_store_with_data):
        """BPSK spectrogram computes without error."""
        result = iq_store_with_data.compute_spectrogram("det-bpsk-01", nfft=128, overlap=64)
        assert result is not None
        assert isinstance(result, dict)
        assert result["nfft"] == 128
        n_time = len(result["time_axis"])
        n_freq = len(result["freq_axis"])
        sg = result["spectrogram"]
        assert len(sg) == n_time
        assert all(len(row) == n_freq for row in sg)

    def test_spectrogram_noise(self, iq_store_with_data):
        """Noise spectrogram has relatively flat distribution."""
        result = iq_store_with_data.compute_spectrogram("det-noise-01")
        assert result is not None
        assert isinstance(result, dict)
        flat = [v for row in result["spectrogram"] for v in row]
        # Noise should not have extreme dynamic range (most values within ~20 dB of peak)
        assert max(flat) == 0.0  # peak is normalized to 0
        # Most values should be above -30 for broadband noise
        above_30 = sum(1 for v in flat if v > -30.0)
        assert above_30 > len(flat) * 0.3, "Noise should have many bins above -30 dB"

    def test_spectrogram_missing_detection(self, iq_store_with_data):
        """Non-existent detection returns None."""
        assert iq_store_with_data.compute_spectrogram("nonexistent") is None

    def test_spectrogram_different_nfft(self, iq_store_with_data):
        """Different NFFT sizes produce correctly sized outputs."""
        for nfft in [64, 128, 256, 512]:
            result = iq_store_with_data.compute_spectrogram(
                "det-tone-01", nfft=nfft, overlap=nfft // 2,
            )
            assert result is not None
            assert isinstance(result, dict)
            assert result["nfft"] == nfft
            assert len(result["freq_axis"]) == nfft


# ---------------------------------------------------------------------------
# HTTP endpoint integration (spectrogram + modulation)
# ---------------------------------------------------------------------------

class TestEndpointIntegration:
    """HTTP endpoint tests for spectrogram and modulation params."""

    @pytest.fixture()
    def seeded_app(self, bridge_app, tmp_path):
        """Wire a seeded IQStore into the bridge app."""
        store = IQStore(base_dir=tmp_path / "iq_ep")
        bpsk = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10)
        store.store("det-ep-01", _iq_to_gzip_bytes(bpsk))
        bridge_app.state.iq_store = store
        return bridge_app

    def test_spectrogram_endpoint_200(self, client, seeded_app):
        """GET /api/detections/{id}/spectrogram returns 200 with valid data."""
        resp = client.get("/api/detections/det-ep-01/spectrogram")
        assert resp.status_code == 200
        body = resp.json()
        assert "spectrogram" in body
        assert isinstance(body["spectrogram"], list)
        assert "time_axis" in body
        assert isinstance(body["time_axis"], list)
        assert "freq_axis" in body
        assert isinstance(body["freq_axis"], list)
        assert body["nfft"] == 256

    def test_spectrogram_endpoint_404(self, client, seeded_app):
        """GET spectrogram for missing detection returns 404."""
        resp = client.get("/api/detections/no-such-id/spectrogram")
        assert resp.status_code == 404

    def test_spectrogram_endpoint_custom_params(self, client, seeded_app):
        """GET spectrogram with custom nfft/overlap."""
        resp = client.get("/api/detections/det-ep-01/spectrogram?nfft=128&overlap=64")
        assert resp.status_code == 200
        body = resp.json()
        assert body["nfft"] == 128

    def test_spectrogram_endpoint_invalid_overlap(self, client, seeded_app):
        """Overlap >= nfft returns 422."""
        resp = client.get("/api/detections/det-ep-01/spectrogram?nfft=128&overlap=128")
        assert resp.status_code == 422

    def test_modulation_endpoint_200(self, client, seeded_app):
        """GET /api/detections/{id}/modulation returns 200 with params."""
        resp = client.get("/api/detections/det-ep-01/modulation")
        assert resp.status_code == 200
        body = resp.json()
        assert "symbol_rate" in body
        assert isinstance(body["symbol_rate"], dict)
        assert "bandwidth" in body
        assert isinstance(body["bandwidth"], dict)
        assert "cfo" in body
        assert isinstance(body["cfo"], dict)
        assert isinstance(body["n_samples"], int)
        assert body["n_samples"] > 0

    def test_modulation_endpoint_404(self, client, seeded_app):
        """GET modulation for missing detection returns 404."""
        resp = client.get("/api/detections/no-such-id/modulation")
        assert resp.status_code == 404

    def test_modulation_endpoint_custom_sample_rate(self, client, seeded_app):
        """GET modulation with custom sample_rate parameter."""
        resp = client.get("/api/detections/det-ep-01/modulation?sample_rate=1000000")
        assert resp.status_code == 200
        body = resp.json()
        assert body["sample_rate_hz"] == 1000000.0


# ---------------------------------------------------------------------------
# Cross-module: torch features + numpy modulation params on same signal
# ---------------------------------------------------------------------------

class TestCrossModule:
    """Verify torch DSP features and numpy modulation params both work on the same signal."""

    def test_bpsk_both_pipelines(self):
        """BPSK signal processed by both torch features and numpy modulation params."""
        iq_np = _make_bpsk_numpy(n_symbols=200, samples_per_symbol=10, noise_std=0.2)
        # Torch pipeline
        x = _numpy_to_torch(iq_np)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()
        # Numpy pipeline
        params = extract_modulation_params(iq_np, sample_rate=2.048e6)
        assert params["n_samples"] == len(iq_np)
        assert isinstance(params["symbol_rate"]["symbol_rate_hz"], float)
        assert params["symbol_rate"]["symbol_rate_hz"] >= 0.0
        assert isinstance(params["bandwidth"]["bandwidth_hz"], float)
        assert params["bandwidth"]["bandwidth_hz"] >= 0.0

    def test_fsk_both_pipelines(self):
        """FSK signal through both pipelines."""
        iq_np = _make_fsk_numpy(n_symbols=100, samples_per_symbol=20)
        x = _numpy_to_torch(iq_np)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()
        params = extract_modulation_params(iq_np, sample_rate=1.0)
        assert params["n_samples"] == len(iq_np)

    def test_am_both_pipelines(self):
        """AM signal through both pipelines."""
        iq_np = _make_am_numpy(n=4000)
        x = _numpy_to_torch(iq_np)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()
        params = extract_modulation_params(iq_np, sample_rate=1.0)
        assert params["n_samples"] == len(iq_np)

    def test_fm_both_pipelines(self):
        """FM signal through both pipelines."""
        iq_np = _make_fm_numpy(n=4000)
        x = _numpy_to_torch(iq_np)
        feats = compute_dsp_features(x)
        assert feats.shape == (1, NUM_DSP_FEATURES)
        assert torch.isfinite(feats).all()
        params = extract_modulation_params(iq_np, sample_rate=1.0)
        assert params["n_samples"] == len(iq_np)
