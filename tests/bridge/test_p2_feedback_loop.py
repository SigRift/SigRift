"""Tests for P2-15: Operator feedback loop — TP/FP labels adjust scoring.

Covers FeedbackStore.get_feedback_stats / get_fp_rate and
FeedbackCalibrator integration with AnomalyScorer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import AnomalyScorer, FeedbackCalibrator
from sigrift.bridge.detection_store import DetectionStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> DetectionStore:
    """DetectionStore backed by a temp SQLite file."""
    return DetectionStore(db_path=tmp_path / "feedback_loop.db")


@pytest.fixture
def baseline_mgr() -> BaselineManager:
    return BaselineManager()


# ---------------------------------------------------------------------------
# FeedbackStore.get_feedback_stats
# ---------------------------------------------------------------------------


class TestFeedbackStats:

    def test_feedback_stats_empty(self, store: DetectionStore):
        stats = store.get_feedback_stats()
        assert stats == {}

    def test_feedback_stats_with_data(self, store: DetectionStore):
        store.add_feedback("d1", "true_positive")
        store.add_feedback("d2", "true_positive")
        store.add_feedback("d3", "false_positive")
        store.add_feedback("d4", "expected")

        stats = store.get_feedback_stats()
        assert stats["true_positive"] == 2
        assert stats["false_positive"] == 1
        assert stats["expected"] == 1


# ---------------------------------------------------------------------------
# FeedbackStore.get_fp_rate
# ---------------------------------------------------------------------------


class TestFPRate:

    def test_fp_rate_calculation(self, store: DetectionStore):
        # 3 FP + 7 TP = 0.3 rate
        for i in range(7):
            store.add_feedback(f"tp-{i}", "true_positive")
        for i in range(3):
            store.add_feedback(f"fp-{i}", "false_positive")

        rate = store.get_fp_rate()
        assert rate == pytest.approx(0.3)

    def test_fp_rate_no_feedback(self, store: DetectionStore):
        assert store.get_fp_rate() == 0.0


# ---------------------------------------------------------------------------
# FeedbackCalibrator
# ---------------------------------------------------------------------------


class TestFeedbackCalibrator:

    def test_calibrator_high_fp_rate(self):
        cal = FeedbackCalibrator(target_fp_rate=0.15, min_samples=10)
        # 50% FP rate is way above 15% target
        offset = cal.calibrate(fp_count=10, tp_count=10)
        assert offset > 0.0
        assert cal.offset == offset

    def test_calibrator_low_fp_rate(self):
        cal = FeedbackCalibrator(target_fp_rate=0.15, min_samples=10)
        # 5% FP rate is below 15% target → negative offset
        offset = cal.calibrate(fp_count=1, tp_count=19)
        assert offset < 0.0

    def test_calibrator_insufficient_samples(self):
        cal = FeedbackCalibrator(target_fp_rate=0.15, min_samples=20)
        offset = cal.calibrate(fp_count=5, tp_count=5)
        assert offset == 0.0
        assert cal.offset == 0.0


# ---------------------------------------------------------------------------
# AnomalyScorer + FeedbackCalibrator integration
# ---------------------------------------------------------------------------


class TestScorerCalibration:

    @staticmethod
    def _make_detection(**overrides) -> dict:
        base = {
            "signal_class": "wifi",
            "confidence": 0.9,
            "freq_hz": 2_437_000_000,
        }
        base.update(overrides)
        return base

    def test_calibrator_offset_applied_to_score(self, baseline_mgr: BaselineManager):
        """A positive calibrator offset should lower the composite score."""
        cal = FeedbackCalibrator(target_fp_rate=0.15, min_samples=5)
        cal.calibrate(fp_count=10, tp_count=10)  # 50% FP → positive offset

        scorer_with = AnomalyScorer(baseline_mgr, calibrator=cal)
        scorer_without = AnomalyScorer(baseline_mgr)

        det = self._make_detection()
        result_with = scorer_with.score(det)
        result_without = scorer_without.score(det)

        assert result_with.score <= result_without.score

    def test_score_clamped_after_offset(self, baseline_mgr: BaselineManager):
        """Score must stay in [0, 1] even with large negative offset."""
        cal = FeedbackCalibrator(target_fp_rate=0.99, min_samples=5)
        # 0% FP rate vs 99% target → very large negative offset
        cal.calibrate(fp_count=0, tp_count=100)
        assert cal.offset < 0.0

        scorer = AnomalyScorer(baseline_mgr, calibrator=cal)
        det = self._make_detection()
        result = scorer.score(det)
        assert 0.0 <= result.score <= 1.0

    def test_no_calibrator_backward_compat(self, baseline_mgr: BaselineManager):
        """calibrator=None (default) does not change scoring."""
        scorer = AnomalyScorer(baseline_mgr)
        det = self._make_detection()
        result = scorer.score(det)
        # Just verify it runs and returns a valid result
        assert 0.0 <= result.score <= 1.0
        assert result.priority in {"normal", "interesting", "anomalous", "critical"}
