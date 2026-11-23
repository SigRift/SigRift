"""Tests for sigrift.bridge.anomaly.baseline."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline


# ---------------------------------------------------------------------------
# FrequencyBaseline
# ---------------------------------------------------------------------------


class TestFrequencyBaseline:
    """Tests for the per-frequency baseline tracker."""

    def test_initial_state(self):
        fb = FrequencyBaseline()
        assert fb.total_detections == 0
        assert fb.is_learning() is True
        assert fb.class_counts == {}
        assert fb.class_ewma == {}
        assert fb.power_ewma == 0.0
        assert fb.power_var == 0.0

    def test_cold_start_detection(self):
        fb = FrequencyBaseline()
        assert fb.is_learning() is True
        for i in range(300):
            fb.update("fm", 0.9, -50.0, 10)
        assert fb.is_learning() is False

    def test_class_counts(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("fm", 0.85, -48.0, 10)
        fb.update("bpsk", 0.7, -55.0, 10)
        assert fb.class_counts == {"fm": 2, "bpsk": 1}
        assert fb.total_detections == 3

    def test_class_probability(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("fm", 0.85, -48.0, 10)
        fb.update("bpsk", 0.7, -55.0, 10)
        assert fb.class_probability("fm") == pytest.approx(2 / 3)
        assert fb.class_probability("bpsk") == pytest.approx(1 / 3)
        assert fb.class_probability("qpsk") == 0.0

    def test_class_probability_empty(self):
        fb = FrequencyBaseline()
        assert fb.class_probability("fm") == 0.0

    def test_novel_class(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        assert fb.is_novel_class("fm") is False
        assert fb.is_novel_class("bpsk") is True

    def test_hourly_counts(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("fm", 0.85, -48.0, 10)
        fb.update("bpsk", 0.7, -55.0, 22)
        assert fb.hourly_counts[10] == {"fm": 2}
        assert fb.hourly_counts[22] == {"bpsk": 1}

    def test_hourly_probability(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("fm", 0.85, -48.0, 10)
        fb.update("bpsk", 0.7, -55.0, 10)
        assert fb.hourly_probability("fm", 10) == pytest.approx(2 / 3)
        assert fb.hourly_probability("bpsk", 10) == pytest.approx(1 / 3)
        assert fb.hourly_probability("fm", 22) == 0.0  # No data at hour 22

    def test_hourly_probability_empty(self):
        fb = FrequencyBaseline()
        assert fb.hourly_probability("fm", 10) == 0.0

    def test_hour_wrapping(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 25)  # Should wrap to hour 1
        assert 1 in fb.hourly_counts

    def test_power_ewma_first_detection(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10)
        assert fb.power_ewma == -50.0
        assert fb.power_var == 0.0

    def test_power_ewma_convergence(self):
        fb = FrequencyBaseline(alpha=0.1)
        # Feed 200 detections at -50 dBm
        for _ in range(200):
            fb.update("fm", 0.9, -50.0, 10)
        assert fb.power_ewma == pytest.approx(-50.0, abs=0.1)

        # Feed 200 more at -40 dBm — EWMA should shift toward -40
        for _ in range(200):
            fb.update("fm", 0.9, -40.0, 10)
        assert fb.power_ewma == pytest.approx(-40.0, abs=0.5)

    def test_power_zscore(self):
        fb = FrequencyBaseline(alpha=0.1)
        # Build baseline at -50 dBm with some variance
        for _ in range(200):
            fb.update("fm", 0.9, -50.0, 10)
        # Power at baseline should have z-score near 0
        z = fb.power_zscore(-50.0)
        assert abs(z) < 1.0

    def test_power_zscore_insufficient_data(self):
        fb = FrequencyBaseline()
        assert fb.power_zscore(-50.0) == 0.0  # Only 0 detections
        fb.update("fm", 0.9, -50.0, 10)
        assert fb.power_zscore(-50.0) == 0.0  # Only 1 detection

    def test_power_none_skips_update(self):
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, None, 10)
        assert fb.power_ewma == 0.0
        assert fb.power_var == 0.0

    def test_ewma_class_tracking(self):
        fb = FrequencyBaseline(alpha=0.5)
        # Class "fm" should have high EWMA after consecutive updates
        for _ in range(10):
            fb.update("fm", 0.9, -50.0, 10)
        assert fb.class_ewma["fm"] > 0.5

    def test_serialization_roundtrip(self):
        fb = FrequencyBaseline(alpha=0.05)
        fb.update("fm", 0.9, -50.0, 10)
        fb.update("bpsk", 0.7, -55.0, 22)

        data = fb.to_dict()
        restored = FrequencyBaseline.from_dict(data)

        assert restored.alpha == 0.05
        assert restored.class_counts == fb.class_counts
        assert restored.class_ewma == fb.class_ewma
        assert restored.hourly_counts == fb.hourly_counts
        assert restored.power_ewma == fb.power_ewma
        assert restored.power_var == fb.power_var
        assert restored.total_detections == fb.total_detections


# ---------------------------------------------------------------------------
# BaselineManager
# ---------------------------------------------------------------------------


class TestBaselineManager:
    """Tests for the multi-frequency baseline manager."""

    def test_freq_bin_rounding(self):
        # P2-5: Sub-GHz uses 25 kHz bins
        assert BaselineManager.freq_bin(433_920_000) == 433_925_000  # rounds up
        assert BaselineManager.freq_bin(433_910_000) == 433_900_000  # rounds down
        assert BaselineManager.freq_bin(433_850_000) == 433_850_000  # exact
        assert BaselineManager.freq_bin(100_000_000) == 100_000_000  # exact
        assert BaselineManager.freq_bin(0) == 0
        # >= 1 GHz uses 500 kHz bins
        assert BaselineManager.freq_bin(2_400_000_000) == 2_400_000_000
        assert BaselineManager.freq_bin(2_400_200_000) == 2_400_000_000

    def test_update_creates_baseline(self):
        mgr = BaselineManager()
        assert mgr.get_baseline(433_920_000) is None
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
        baseline = mgr.get_baseline(433_920_000)
        assert baseline is not None
        assert isinstance(baseline, FrequencyBaseline)
        assert baseline.total_detections == 1

    def test_same_bin_shares_baseline(self):
        mgr = BaselineManager()
        # P2-5: 25 kHz bins for sub-GHz
        # 433_920_000 and 433_930_000 both round to 433_925_000
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
        mgr.update(433_930_000, "bpsk", 0.7, -55.0, 10)
        baseline = mgr.get_baseline(433_925_000)
        assert baseline is not None
        assert isinstance(baseline, FrequencyBaseline)
        assert baseline.total_detections == 2

    def test_different_bins_separate(self):
        mgr = BaselineManager()
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
        mgr.update(915_000_000, "lora-css", 0.95, -60.0, 10)
        assert len(mgr.baselines) == 2

    def test_get_baseline_not_found(self):
        mgr = BaselineManager()
        assert mgr.get_baseline(100_000_000) is None

    def test_save_load_roundtrip(self):
        mgr = BaselineManager(alpha=0.05)
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
        mgr.update(433_920_000, "bpsk", 0.7, -55.0, 22)
        mgr.update(915_000_000, "lora-css", 0.95, -60.0, 14)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "baselines.json")
            mgr.save(path)

            # Verify file exists and is valid JSON
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert "baselines" in data
            assert isinstance(data["baselines"], dict)
            assert "alpha" in data
            assert isinstance(data["alpha"], float)
            assert len(data["baselines"]) == 2

            # Load into new manager
            mgr2 = BaselineManager()
            mgr2.load(path)
            assert mgr2.alpha == 0.05
            assert len(mgr2.baselines) == 2

            # Verify data integrity
            bl = mgr2.get_baseline(433_920_000)
            assert bl is not None
            assert isinstance(bl, FrequencyBaseline)
            assert bl.total_detections == 2
            assert "fm" in bl.class_counts
            assert bl.class_counts["fm"] == 1
            assert "bpsk" in bl.class_counts
            assert bl.class_counts["bpsk"] == 1

    def test_load_missing_file(self):
        mgr = BaselineManager()
        mgr.load("/nonexistent/path/baselines.json")
        assert len(mgr.baselines) == 0

    def test_update_returns_baseline(self):
        mgr = BaselineManager()
        bl = mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
        assert isinstance(bl, FrequencyBaseline)
        assert bl.total_detections == 1

    def test_update_auto_hour(self):
        """Update without explicit hour should use current UTC hour."""
        mgr = BaselineManager()
        bl = mgr.update(433_920_000, "fm", 0.9, -50.0)
        assert bl.total_detections == 1
        # Should have exactly one hour entry
        assert len(bl.hourly_counts) == 1
