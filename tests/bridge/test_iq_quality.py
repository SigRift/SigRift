"""Tests for IQ capture quality validation."""

from __future__ import annotations

import gzip
from pathlib import Path

import numpy as np
import pytest

from sigrift.bridge.iq_store import IQStore, validate_iq_quality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_iq_gz(iq: np.ndarray) -> bytes:
    """Convert complex IQ array to gzip-compressed float32 interleaved bytes."""
    i_vals = iq.real.astype(np.float32)
    q_vals = iq.imag.astype(np.float32)
    interleaved = np.empty(len(iq) * 2, dtype=np.float32)
    interleaved[0::2] = i_vals
    interleaved[1::2] = q_vals
    return gzip.compress(interleaved.tobytes())


def _clean_signal(n: int = 1024, snr_linear: float = 100.0) -> np.ndarray:
    """Generate a clean BPSK-like signal with high SNR."""
    rng = np.random.default_rng(42)
    t = np.arange(n)
    signal = np.exp(1j * 2 * np.pi * 0.1 * t).astype(np.complex64)
    noise_power = 1.0 / snr_linear
    noise = (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64) * np.sqrt(noise_power / 2)
    return signal + noise


def _clipped_signal(n: int = 1024) -> np.ndarray:
    """Generate a signal that clips (>5% at max magnitude)."""
    rng = np.random.default_rng(42)
    signal = _clean_signal(n)
    # Set 10% of samples to max magnitude
    clip_count = n // 10
    max_mag = float(np.max(np.abs(signal)))
    clip_val = max_mag * 1.0
    indices = rng.choice(n, clip_count, replace=False)
    for idx in indices:
        phase = np.angle(signal[idx])
        signal[idx] = clip_val * np.exp(1j * phase)
    return signal


def _noisy_signal(n: int = 1024) -> np.ndarray:
    """Generate a noise-dominated signal (SNR < -5 dB)."""
    rng = np.random.default_rng(42)
    noise = (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)
    return noise * 0.1


def _dc_offset_signal(n: int = 1024) -> np.ndarray:
    """Generate a signal with significant DC offset."""
    signal = _clean_signal(n) * 0.1
    # Add large DC component
    signal += (0.5 + 0.5j)
    return signal.astype(np.complex64)


# ---------------------------------------------------------------------------
# validate_iq_quality() unit tests
# ---------------------------------------------------------------------------


class TestValidateIqQuality:
    def test_clean_signal(self):
        """Clean signal should score high with no issues."""
        iq = _clean_signal(2048)
        quality = validate_iq_quality(iq)
        assert quality["score"] >= 0.8
        assert quality["clipped"] is False
        assert quality["snr_db"] > 0
        assert quality["phase_coherent"] is True

    def test_clipped_signal(self):
        """Clipped signal should be detected."""
        iq = _clipped_signal(2048)
        quality = validate_iq_quality(iq)
        assert quality["clipped"] is True
        assert quality["score"] < 1.0

    def test_noisy_signal(self):
        """Noise-dominated signal should have low SNR (peak-to-median)."""
        iq = _noisy_signal(4096)
        quality = validate_iq_quality(iq)
        # Pure noise: peak/median ratio is modest (typically 10-15 dB)
        assert quality["snr_db"] < 20

    def test_dc_offset_signal(self):
        """Signal with DC offset should be flagged."""
        iq = _dc_offset_signal(2048)
        quality = validate_iq_quality(iq)
        assert quality["dc_offset"] is True
        assert quality["score"] < 1.0

    def test_empty_signal(self):
        """Empty array should return worst-case quality."""
        iq = np.array([], dtype=np.complex64)
        quality = validate_iq_quality(iq)
        assert quality["score"] == 0.0
        assert quality["phase_coherent"] is False

    def test_score_bounds(self):
        """Score should always be between 0 and 1."""
        for signal_fn in [_clean_signal, _clipped_signal, _noisy_signal, _dc_offset_signal]:
            quality = validate_iq_quality(signal_fn(1024))
            assert 0.0 <= quality["score"] <= 1.0

    def test_all_keys_present(self):
        """Quality dict should have all required keys."""
        quality = validate_iq_quality(_clean_signal(512))
        assert "score" in quality
        assert isinstance(quality["score"], float)
        assert "clipped" in quality
        assert isinstance(quality["clipped"], bool)
        assert "snr_db" in quality
        assert isinstance(quality["snr_db"], (int, float))
        assert "dc_offset" in quality
        assert isinstance(quality["dc_offset"], bool)
        assert "phase_coherent" in quality
        assert isinstance(quality["phase_coherent"], bool)

    def test_incoherent_signal(self):
        """Signal where I == Q (perfect correlation) should flag incoherent."""
        n = 1024
        rng = np.random.default_rng(42)
        real_part = rng.standard_normal(n).astype(np.float32)
        # I == Q → correlation = 1.0 → not phase coherent
        iq = (real_part + 1j * real_part).astype(np.complex64)
        quality = validate_iq_quality(iq)
        assert quality["phase_coherent"] is False


# ---------------------------------------------------------------------------
# IQStore integration: quality metadata saved on store()
# ---------------------------------------------------------------------------


class TestIQStoreQualityIntegration:
    @pytest.fixture
    def iq_store(self, tmp_path: Path) -> IQStore:
        return IQStore(base_dir=tmp_path / "iq_captures")

    def test_store_saves_quality(self, iq_store: IQStore):
        """store() should save quality metadata sidecar file."""
        iq = _clean_signal(1024)
        data = _make_iq_gz(iq)
        iq_store.store("det001", data)

        quality = iq_store.get_quality("det001")
        assert quality is not None
        assert isinstance(quality, dict)
        assert "score" in quality
        assert isinstance(quality["score"], float)
        assert quality["score"] > 0.5

    def test_get_quality_nonexistent(self, iq_store: IQStore):
        """get_quality() returns None for non-existent detection."""
        assert iq_store.get_quality("no_such_id") is None

    def test_quality_persisted_as_json(self, iq_store: IQStore, tmp_path: Path):
        """Quality file should be valid JSON on disk."""
        iq = _clean_signal(512)
        data = _make_iq_gz(iq)
        iq_store.store("det002", data)

        import json
        quality_path = tmp_path / "iq_captures" / "det002.quality.json"
        assert quality_path.exists()
        parsed = json.loads(quality_path.read_text())
        assert isinstance(parsed["score"], float)
        assert isinstance(parsed["clipped"], bool)

    def test_store_with_bad_data_still_stores_file(self, iq_store: IQStore):
        """Even if quality validation fails, the IQ file should be stored."""
        bad_data = gzip.compress(b"not float32 data")
        iq_store.store("det003", bad_data)
        assert iq_store.exists("det003")
        # Quality may be None since data is invalid
        # But the file itself should exist
        raw = iq_store.load_raw("det003")
        assert raw is not None
        assert isinstance(raw, bytes)
