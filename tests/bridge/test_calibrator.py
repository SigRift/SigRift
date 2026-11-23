"""Tests for sigrift.bridge.anomaly.calibrator — Platt scaling."""

from __future__ import annotations

import math

import pytest

from sigrift.bridge.anomaly.calibrator import ScoreCalibrator, _sigmoid


# ---------------------------------------------------------------------------
# Band mapping
# ---------------------------------------------------------------------------


class TestBandMapping:
    def test_sub_1ghz(self):
        cal = ScoreCalibrator()
        assert cal.get_band(433_920_000) == "sub_1ghz"
        assert cal.get_band(915_000_000) == "sub_1ghz"

    def test_ism_2_4ghz(self):
        cal = ScoreCalibrator()
        assert cal.get_band(2_437_000_000) == "ism_2_4ghz"
        assert cal.get_band(2_400_000_000) == "ism_2_4ghz"

    def test_ism_5ghz(self):
        cal = ScoreCalibrator()
        assert cal.get_band(5_200_000_000) == "ism_5ghz"
        assert cal.get_band(5_800_000_000) == "ism_5ghz"

    def test_l_band(self):
        cal = ScoreCalibrator()
        assert cal.get_band(1_500_000_000) == "l_band"
        assert cal.get_band(1_000_000_000) == "l_band"

    def test_s_band(self):
        cal = ScoreCalibrator()
        assert cal.get_band(2_100_000_000) == "s_band"
        assert cal.get_band(3_000_000_000) == "s_band_upper"

    def test_c_band(self):
        cal = ScoreCalibrator()
        assert cal.get_band(4_500_000_000) == "c_band"

    def test_other_band(self):
        cal = ScoreCalibrator()
        # Above 5.9 GHz
        assert cal.get_band(6_000_000_000) == "other"


# ---------------------------------------------------------------------------
# Feedback collection
# ---------------------------------------------------------------------------


class TestFeedback:
    def test_add_feedback(self):
        cal = ScoreCalibrator()
        cal.add_feedback(0.7, True, 433_920_000)
        cal.add_feedback(0.3, False, 433_920_000)
        status = cal.status()
        assert status["total_feedback"] == 2
        assert status["bands"]["sub_1ghz"]["samples"] == 2
        assert status["bands"]["sub_1ghz"]["positives"] == 1
        assert status["bands"]["sub_1ghz"]["negatives"] == 1

    def test_feedback_multiple_bands(self):
        cal = ScoreCalibrator()
        cal.add_feedback(0.8, True, 433_920_000)
        cal.add_feedback(0.2, False, 2_437_000_000)
        status = cal.status()
        assert status["total_feedback"] == 2
        assert "sub_1ghz" in status["bands"]
        assert isinstance(status["bands"]["sub_1ghz"], dict)
        assert "ism_2_4ghz" in status["bands"]
        assert isinstance(status["bands"]["ism_2_4ghz"], dict)


# ---------------------------------------------------------------------------
# Calibration (uncalibrated fallback)
# ---------------------------------------------------------------------------


class TestUncalibrated:
    def test_uncalibrated_returns_raw_score(self):
        cal = ScoreCalibrator()
        assert cal.calibrate(0.75, 433_920_000) == 0.75

    def test_is_calibrated_false_initially(self):
        cal = ScoreCalibrator()
        assert cal.is_calibrated(433_920_000) is False


# ---------------------------------------------------------------------------
# Fitting
# ---------------------------------------------------------------------------


class TestFitting:
    def test_fit_insufficient_samples_returns_false(self):
        cal = ScoreCalibrator(min_samples=30)
        for i in range(10):
            cal.add_feedback(0.5, True, 433_920_000)
        assert cal.fit_band("sub_1ghz") is False

    def test_fit_all_same_label_returns_false(self):
        cal = ScoreCalibrator(min_samples=10)
        for _ in range(20):
            cal.add_feedback(0.5, True, 433_920_000)
        assert cal.fit_band("sub_1ghz") is False

    def test_fit_sufficient_samples_returns_true(self):
        cal = ScoreCalibrator(min_samples=10)
        # High scores -> anomaly, low scores -> not anomaly
        for i in range(20):
            cal.add_feedback(0.8 + i * 0.005, True, 433_920_000)
        for i in range(20):
            cal.add_feedback(0.1 + i * 0.005, False, 433_920_000)
        assert cal.fit_band("sub_1ghz") is True
        assert cal.is_calibrated(433_920_000) is True

    def test_fitted_curve_monotonic(self):
        """Calibrated scores should be monotonically increasing."""
        cal = ScoreCalibrator(min_samples=10)
        # Strong positive correlation: high score -> anomaly
        for i in range(30):
            cal.add_feedback(0.7 + i * 0.01, True, 433_920_000)
        for i in range(30):
            cal.add_feedback(0.1 + i * 0.01, False, 433_920_000)
        assert cal.fit_band("sub_1ghz") is True

        scores = [cal.calibrate(s / 10.0, 433_920_000) for s in range(11)]
        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1] - 1e-6

    def test_high_raw_score_yields_high_calibrated(self):
        """Raw score of 0.9 with clear separation should calibrate > 0.5."""
        cal = ScoreCalibrator(min_samples=10)
        for _ in range(30):
            cal.add_feedback(0.85, True, 433_920_000)
        for _ in range(30):
            cal.add_feedback(0.15, False, 433_920_000)
        cal.fit_band("sub_1ghz")

        p = cal.calibrate(0.9, 433_920_000)
        assert p > 0.5

    def test_low_raw_score_yields_low_calibrated(self):
        """Raw score of 0.1 with clear separation should calibrate < 0.5."""
        cal = ScoreCalibrator(min_samples=10)
        for _ in range(30):
            cal.add_feedback(0.85, True, 433_920_000)
        for _ in range(30):
            cal.add_feedback(0.15, False, 433_920_000)
        cal.fit_band("sub_1ghz")

        p = cal.calibrate(0.1, 433_920_000)
        assert p < 0.5


# ---------------------------------------------------------------------------
# fit_all
# ---------------------------------------------------------------------------


class TestFitAll:
    def test_fit_all_multiple_bands(self):
        cal = ScoreCalibrator(min_samples=10)
        # sub_1ghz: enough data
        for _ in range(20):
            cal.add_feedback(0.8, True, 433_920_000)
        for _ in range(20):
            cal.add_feedback(0.2, False, 433_920_000)
        # ism_2_4ghz: not enough data
        for _ in range(5):
            cal.add_feedback(0.5, True, 2_437_000_000)

        results = cal.fit_all()
        assert results["sub_1ghz"] is True
        assert results["ism_2_4ghz"] is False


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_empty(self):
        cal = ScoreCalibrator()
        status = cal.status()
        assert status["total_feedback"] == 0
        assert status["bands"] == {}

    def test_status_after_fit(self):
        cal = ScoreCalibrator(min_samples=10)
        for _ in range(15):
            cal.add_feedback(0.8, True, 433_920_000)
        for _ in range(15):
            cal.add_feedback(0.2, False, 433_920_000)
        cal.fit_band("sub_1ghz")

        status = cal.status()
        band = status["bands"]["sub_1ghz"]
        assert band["calibrated"] is True
        assert "a" in band
        assert isinstance(band["a"], float)
        assert "b" in band
        assert isinstance(band["b"], float)
        assert band["samples"] == 30


# ---------------------------------------------------------------------------
# Sigmoid helper
# ---------------------------------------------------------------------------


class TestSigmoid:
    def test_sigmoid_zero(self):
        assert _sigmoid(0.0) == pytest.approx(0.5)

    def test_sigmoid_large_positive(self):
        assert _sigmoid(10.0) > 0.999

    def test_sigmoid_large_negative(self):
        assert _sigmoid(-10.0) < 0.001

    def test_sigmoid_symmetry(self):
        assert _sigmoid(2.0) + _sigmoid(-2.0) == pytest.approx(1.0)
