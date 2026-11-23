"""Tests for sigrift.bridge.anomaly.drift_detector."""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import pytest

from sigrift.bridge.anomaly.drift_detector import DriftDetector


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------


class TestBasicLifecycle:
    def test_no_drift_initially(self):
        dd = DriftDetector()
        assert dd.has_drift() is False

    def test_no_drift_insufficient_data(self):
        dd = DriftDetector(min_reference_samples=50)
        for _ in range(10):
            dd.add_score(0.5)
        assert dd.has_drift() is False

    def test_auto_reference_established(self):
        """Reference is auto-set once min_reference_samples reached."""
        dd = DriftDetector(min_reference_samples=20, window_size=100)
        for _ in range(25):
            dd.add_score(0.3)
        assert dd._reference_mean is not None
        assert dd._reference_mean == pytest.approx(0.3, abs=0.01)


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------


class TestDriftDetection:
    def test_no_drift_stable_distribution(self):
        dd = DriftDetector(
            window_size=200, sigma_threshold=2.0, min_reference_samples=50,
        )
        # Establish reference with mean~0.3, some variance
        import random
        random.seed(99)
        for _ in range(100):
            dd.add_score(0.3 + random.gauss(0, 0.03))
        dd.update_reference()

        # Feed more at similar values — no drift
        for _ in range(100):
            dd.add_score(0.31 + random.gauss(0, 0.03))
        assert dd.has_drift() is False

    def test_drift_detected_on_shift(self):
        dd = DriftDetector(
            window_size=200, sigma_threshold=2.0, min_reference_samples=50,
        )
        # Establish reference: mean=0.3, small variance
        for _ in range(100):
            dd.add_score(0.3)
        dd.update_reference()

        # Feed a clearly shifted distribution (mean=0.8)
        # The rolling window is size 200, so feed 200 to fully replace
        for _ in range(200):
            dd.add_score(0.8)
        assert dd.has_drift() is True

    def test_drift_with_zero_variance_reference(self):
        """If reference has zero variance, any shift should trigger drift."""
        dd = DriftDetector(
            window_size=50, sigma_threshold=2.0, min_reference_samples=20,
        )
        for _ in range(50):
            dd.add_score(0.5)
        dd.update_reference()

        # Shift to a slightly different value
        for _ in range(50):
            dd.add_score(0.6)
        assert dd.has_drift() is True

    def test_no_drift_within_threshold(self):
        """Small shift within sigma_threshold should not trigger drift."""
        dd = DriftDetector(
            window_size=200, sigma_threshold=3.0, min_reference_samples=50,
        )
        # Reference with some variance
        import random
        random.seed(42)
        for _ in range(200):
            dd.add_score(0.3 + random.gauss(0, 0.05))
        dd.update_reference()

        # Small shift within bounds
        for _ in range(200):
            dd.add_score(0.35 + random.gauss(0, 0.05))

        # With sigma=3 and std ~0.05, a 0.05 shift (1 sigma) shouldn't trigger
        ref_std = math.sqrt(dd._reference_var)
        current_mean = sum(dd._current_scores) / len(dd._current_scores)
        z = abs(current_mean - dd._reference_mean) / ref_std
        if z <= 3.0:
            assert dd.has_drift() is False


# ---------------------------------------------------------------------------
# Reference update and retrain
# ---------------------------------------------------------------------------


class TestReferenceUpdate:
    def test_update_reference(self):
        dd = DriftDetector(min_reference_samples=10, window_size=50)
        for _ in range(30):
            dd.add_score(0.4)
        dd.update_reference()

        assert dd._reference_mean == pytest.approx(0.4, abs=0.01)
        assert dd._reference_var is not None
        assert dd._last_retrain is not None

    def test_mark_retrained_resets_reference(self):
        dd = DriftDetector(min_reference_samples=10, window_size=50)
        for _ in range(30):
            dd.add_score(0.3)
        dd.update_reference()
        old_mean = dd._reference_mean

        # Shift scores, then mark retrained
        for _ in range(50):
            dd.add_score(0.7)
        dd.mark_retrained()

        assert dd._reference_mean != old_mean
        assert dd._reference_mean == pytest.approx(0.7, abs=0.05)

    def test_should_retrain_respects_cooldown(self):
        dd = DriftDetector(
            min_reference_samples=10, window_size=50, cooldown_sec=3600,
        )
        for _ in range(30):
            dd.add_score(0.3)
        dd.update_reference()

        # Shift to trigger drift
        for _ in range(50):
            dd.add_score(0.9)

        # Retrain was just done via update_reference, cooldown not elapsed
        assert dd.has_drift() is True
        assert dd.should_retrain() is False

    def test_should_retrain_after_cooldown(self):
        dd = DriftDetector(
            min_reference_samples=10, window_size=50, cooldown_sec=0,
        )
        for _ in range(30):
            dd.add_score(0.3)
        dd.update_reference()

        # Shift to trigger drift
        for _ in range(50):
            dd.add_score(0.9)

        # With cooldown=0, should_retrain should be True
        assert dd.should_retrain() is True


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_empty(self):
        dd = DriftDetector()
        status = dd.status()
        assert status["reference_mean"] is None
        assert status["current_window_size"] == 0
        assert status["has_drift"] is False

    def test_status_with_data(self):
        dd = DriftDetector(min_reference_samples=10, window_size=50)
        for _ in range(20):
            dd.add_score(0.5)

        status = dd.status()
        assert status["reference_mean"] is not None
        assert status["current_window_size"] == 20
        assert status["window_capacity"] == 50
        assert status["current_mean"] is not None

    def test_status_drift_count(self):
        dd = DriftDetector(
            min_reference_samples=10, window_size=30, cooldown_sec=0,
        )
        for _ in range(20):
            dd.add_score(0.3)
        dd.update_reference()

        # Trigger drift and retrain
        for _ in range(30):
            dd.add_score(0.9)
        dd.mark_retrained()

        status = dd.status()
        assert status["drift_count"] == 1


# ---------------------------------------------------------------------------
# Window behavior
# ---------------------------------------------------------------------------


class TestWindowBehavior:
    def test_window_caps_at_max_size(self):
        dd = DriftDetector(window_size=10)
        for i in range(20):
            dd.add_score(float(i))
        assert len(dd._current_scores) == 10
        # Should contain the last 10 values (10-19)
        assert list(dd._current_scores) == [float(i) for i in range(10, 20)]
