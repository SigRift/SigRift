"""Tests for P2-16: smooth exponential decay in _quiet_frequency_score."""

from __future__ import annotations

import math

import pytest

from sigrift.bridge.anomaly.baseline import FrequencyBaseline
from sigrift.bridge.anomaly.scorer import AnomalyScorer


def _make_baseline(total_detections: int) -> FrequencyBaseline:
    """Create a FrequencyBaseline stub with a given total_detections count."""
    bl = FrequencyBaseline()
    bl.total_detections = total_detections
    return bl


class TestQuietFrequencyScore:
    """Verify exponential decay behaviour of _quiet_frequency_score."""

    def test_none_baseline_returns_one(self) -> None:
        assert AnomalyScorer._quiet_frequency_score(None) == 1.0

    def test_zero_detections_returns_one(self) -> None:
        bl = _make_baseline(0)
        assert AnomalyScorer._quiet_frequency_score(bl) == 1.0

    def test_score_at_10_detections(self) -> None:
        bl = _make_baseline(10)
        score = AnomalyScorer._quiet_frequency_score(bl)
        expected = math.exp(-10 / 20.0)  # ~0.6065
        assert score == pytest.approx(expected, abs=1e-6)

    def test_score_at_20_detections(self) -> None:
        bl = _make_baseline(20)
        score = AnomalyScorer._quiet_frequency_score(bl)
        expected = math.exp(-1.0)  # ~0.3679
        assert score == pytest.approx(expected, abs=1e-6)

    def test_score_at_50_detections(self) -> None:
        bl = _make_baseline(50)
        score = AnomalyScorer._quiet_frequency_score(bl)
        assert score < 0.1

    def test_score_at_100_detections(self) -> None:
        bl = _make_baseline(100)
        score = AnomalyScorer._quiet_frequency_score(bl)
        assert score < 0.01

    def test_monotonically_decreasing(self) -> None:
        counts = [0, 1, 5, 10, 20, 50, 100, 200, 500]
        scores = [
            AnomalyScorer._quiet_frequency_score(_make_baseline(n))
            for n in counts
        ]
        for i in range(1, len(scores)):
            assert scores[i] < scores[i - 1], (
                f"Score at n={counts[i]} ({scores[i]:.6f}) >= "
                f"score at n={counts[i-1]} ({scores[i-1]:.6f})"
            )

    def test_no_discontinuities(self) -> None:
        """Adjacent integer counts should produce small score changes."""
        max_jump = 0.0
        for n in range(0, 200):
            s1 = AnomalyScorer._quiet_frequency_score(_make_baseline(n))
            s2 = AnomalyScorer._quiet_frequency_score(_make_baseline(n + 1))
            jump = abs(s1 - s2)
            if jump > max_jump:
                max_jump = jump
        # Exponential decay with tau=20: max step is at n=0->1,
        # which is 1.0 - exp(-1/20) ~ 0.0488.  No step should exceed 0.05.
        assert max_jump < 0.05, f"Max jump between adjacent counts: {max_jump:.6f}"
