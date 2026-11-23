"""Tests for P2-5 (adaptive frequency binning) and P2-17 (Welford's variance).

P2-5: Adaptive frequency binning — 25 kHz for sub-GHz, 500 kHz for >= 1 GHz.
P2-17: Welford's online variance during learning phase (first 300 samples),
       then smooth transition to EWMA.
"""

from __future__ import annotations

import math
import random

import pytest

from sigrift.bridge.anomaly.baseline import (
    BaselineManager,
    FrequencyBaseline,
    _MIN_LEARNING_DETECTIONS,
    _adaptive_bin_hz,
)


# ---------------------------------------------------------------------------
# P2-5: Adaptive Frequency Binning
# ---------------------------------------------------------------------------


class TestAdaptiveFrequencyBinning:
    """Tests for adaptive bin width based on frequency range."""

    def test_sub_ghz_bins_to_25khz(self):
        """433.92 MHz ISM band should use 25 kHz bins."""
        assert _adaptive_bin_hz(433_920_000) == 25_000
        binned = BaselineManager.freq_bin(433_920_000)
        # 433_920_000 / 25_000 = 17356.8 → round → 17357 * 25_000 = 433_925_000
        assert binned == 433_925_000

    def test_above_ghz_bins_to_500khz(self):
        """2.4 GHz Wi-Fi/BLE/Zigbee should use 500 kHz bins."""
        assert _adaptive_bin_hz(2_400_000_000) == 500_000
        binned = BaselineManager.freq_bin(2_400_000_000)
        assert binned == 2_400_000_000

    def test_5ghz_bins_to_500khz(self):
        """5 GHz Wi-Fi should use 500 kHz bins."""
        assert _adaptive_bin_hz(5_800_000_000) == 500_000
        binned = BaselineManager.freq_bin(5_800_000_000)
        assert binned == 5_800_000_000

    def test_boundary_at_1ghz(self):
        """Exact 1 GHz boundary uses 500 kHz bins."""
        assert _adaptive_bin_hz(1_000_000_000) == 500_000
        binned = BaselineManager.freq_bin(1_000_000_000)
        assert binned == 1_000_000_000

    def test_baseline_update_creates_correct_bin(self):
        """BaselineManager.update() bins to the correct adaptive width."""
        mgr = BaselineManager()
        # Sub-GHz: 868.1 MHz → 25 kHz bin
        mgr.update(868_100_000, "lora", 0.9, -60.0, 10)
        bl = mgr.get_baseline(868_100_000)
        assert bl is not None
        assert isinstance(bl, FrequencyBaseline)
        assert bl.total_detections == 1
        # The key in the dict should be binned to 25 kHz
        assert 868_100_000 in mgr.baselines

        # Above GHz: 2.412 GHz → 500 kHz bin
        mgr.update(2_412_000_000, "wifi", 0.8, -45.0, 10)
        bl2 = mgr.get_baseline(2_412_000_000)
        assert bl2 is not None
        assert isinstance(bl2, FrequencyBaseline)
        assert 2_412_000_000 in mgr.baselines  # 2412 / 0.5 = 4824 exact

    def test_zero_frequency_handled(self):
        """Zero Hz should not crash and should use sub-GHz (25 kHz) bin."""
        assert _adaptive_bin_hz(0) == 25_000
        binned = BaselineManager.freq_bin(0)
        assert binned == 0

    def test_freq_bin_idempotent(self):
        """Binning an already-binned frequency should return the same value."""
        test_freqs = [
            433_920_000,
            868_000_000,
            915_000_000,
            2_400_000_000,
            5_800_000_000,
            0,
        ]
        for freq in test_freqs:
            once = BaselineManager.freq_bin(freq)
            twice = BaselineManager.freq_bin(once)
            assert once == twice, f"freq_bin not idempotent for {freq}: {once} != {twice}"

    def test_nearby_freqs_same_bin(self):
        """Two frequencies within the same bin width should map to the same bin."""
        # Sub-GHz: 433.920 and 433.930 MHz are both within 25 kHz of 433.925 MHz
        bin_a = BaselineManager.freq_bin(433_920_000)
        bin_b = BaselineManager.freq_bin(433_930_000)
        assert bin_a == bin_b

        # Above GHz: 2.400050 and 2.400200 GHz are both within 500 kHz of 2.400 GHz
        bin_c = BaselineManager.freq_bin(2_400_050_000)
        bin_d = BaselineManager.freq_bin(2_400_200_000)
        assert bin_c == bin_d


# ---------------------------------------------------------------------------
# P2-17: Welford's Online Variance
# ---------------------------------------------------------------------------


class TestWelfordVariance:
    """Tests for Welford's algorithm during learning phase."""

    def test_welford_variance_accuracy(self):
        """Welford variance should match population variance for 100 samples."""
        random.seed(42)
        samples = [random.gauss(-50, 5) for _ in range(100)]

        fb = FrequencyBaseline()
        for s in samples:
            fb.update("fm", 0.9, s, 10)

        # Compute population variance directly
        mean_ref = sum(samples) / len(samples)
        var_ref = sum((x - mean_ref) ** 2 for x in samples) / len(samples)

        assert fb.power_ewma == pytest.approx(mean_ref, abs=1e-9)
        assert fb.power_var == pytest.approx(var_ref, abs=1e-9)

    def test_welford_to_ewma_transition_smooth(self):
        """No large discontinuity in mean/var at the Welford→EWMA boundary."""
        fb = FrequencyBaseline(alpha=0.01)
        # Feed 300 samples at -50 dBm (fills Welford)
        for _ in range(_MIN_LEARNING_DETECTIONS):
            fb.update("fm", 0.9, -50.0, 10)

        mean_before = fb.power_ewma
        var_before = fb.power_var

        # Sample 301 — first EWMA sample, same value
        fb.update("fm", 0.9, -50.0, 10)

        mean_after = fb.power_ewma
        var_after = fb.power_var

        # With identical input, mean should barely move
        assert abs(mean_after - mean_before) < 0.5
        # Variance should not jump wildly
        assert abs(var_after - var_before) < 1.0

    def test_single_sample_variance_zero(self):
        """Welford variance with 1 sample should be 0."""
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        assert fb.power_var == 0.0
        assert fb.power_ewma == -50.0

    def test_two_samples_correct_variance(self):
        """Welford variance with 2 samples should equal population variance."""
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("fm", 0.9, -40.0, 10)

        # Population mean = (-50 + -40) / 2 = -45
        # Population var = ((−50−(−45))² + (−40−(−45))²) / 2 = (25 + 25) / 2 = 25
        assert fb.power_ewma == pytest.approx(-45.0)
        assert fb.power_var == pytest.approx(25.0)

    def test_300th_uses_welford_301st_uses_ewma(self):
        """Sample 300 uses Welford; sample 301 switches to EWMA."""
        fb = FrequencyBaseline(alpha=0.01)
        for _ in range(299):
            fb.update("fm", 0.9, -50.0, 10)

        # Sample 300 — still Welford
        assert fb._welford_power_count == 299
        fb.update("fm", 0.9, -50.0, 10)
        assert fb._welford_power_count == 300

        # Welford mean should be exact
        assert fb.power_ewma == pytest.approx(-50.0, abs=1e-9)

        # Sample 301 — transitions to EWMA
        fb.update("fm", 0.9, -48.0, 10)
        assert fb._welford_power_count == 301
        # EWMA: 0.01 * -48 + 0.99 * -50 = -0.48 + -49.5 = -49.98
        assert fb.power_ewma == pytest.approx(-49.98, abs=0.01)

    def test_serialization_roundtrip_welford(self):
        """Welford state should survive to_dict/from_dict roundtrip."""
        fb = FrequencyBaseline()
        for i in range(50):
            fb.update("fm", 0.9, -50.0 + i * 0.1, 10, snr_db=20.0 + i * 0.05)

        data = fb.to_dict()
        restored = FrequencyBaseline.from_dict(data)

        assert restored._welford_power_count == fb._welford_power_count
        assert restored._welford_power_mean == pytest.approx(fb._welford_power_mean)
        assert restored._welford_power_m2 == pytest.approx(fb._welford_power_m2)
        assert restored._welford_snr_count == fb._welford_snr_count
        assert restored._welford_snr_mean == pytest.approx(fb._welford_snr_mean)
        assert restored._welford_snr_m2 == pytest.approx(fb._welford_snr_m2)
        assert restored.power_ewma == pytest.approx(fb.power_ewma)
        assert restored.power_var == pytest.approx(fb.power_var)
        assert restored.snr_ewma == pytest.approx(fb.snr_ewma)
        assert restored.snr_var == pytest.approx(fb.snr_var)

    def test_snr_welford_independent(self):
        """SNR Welford state should be independent of power Welford state."""
        fb = FrequencyBaseline()
        # Feed power only for first 10
        for _ in range(10):
            fb.update("fm", 0.9, -50.0, 10, snr_db=None)
        # Feed SNR only for next 10
        for _ in range(10):
            fb.update("fm", 0.9, None, 10, snr_db=20.0)

        assert fb._welford_power_count == 10
        assert fb._welford_snr_count == 10
        assert fb.power_ewma == pytest.approx(-50.0)
        assert fb.snr_ewma == pytest.approx(20.0)

    def test_zscore_during_learning(self):
        """power_zscore should work correctly during Welford learning phase."""
        fb = FrequencyBaseline()
        # Build 50-sample baseline at -50 with some noise
        random.seed(123)
        for _ in range(50):
            fb.update("fm", 0.9, random.gauss(-50, 3), 10)

        # Welford should have non-zero variance
        assert fb.power_var > 0
        assert fb._welford_power_count == 50

        # Z-score of a value near the mean should be small
        z_near = fb.power_zscore(-50.0)
        assert abs(z_near) < 2.0

        # Z-score of an outlier should be large
        z_far = fb.power_zscore(-30.0)
        assert abs(z_far) > 3.0
