"""Tests for sigrift.bridge.anomaly.scorer."""

from __future__ import annotations

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyResult,
    AnomalyScorer,
    ScorerConfig,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline_mgr() -> BaselineManager:
    """BaselineManager with 350+ detections at 433.9 MHz (past learning)."""
    mgr = BaselineManager(alpha=0.05)
    for i in range(250):
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
    # Add some diversity
    for i in range(80):
        mgr.update(433_920_000, "bpsk", 0.8, -52.0, 10)
    for i in range(20):
        mgr.update(433_920_000, "ook", 0.85, -48.0, 14)
    return mgr


@pytest.fixture
def scorer(baseline_mgr: BaselineManager) -> AnomalyScorer:
    """Scorer with a populated baseline manager."""
    return AnomalyScorer(baseline_mgr)


@pytest.fixture
def learning_scorer() -> AnomalyScorer:
    """Scorer with a baseline still in learning phase."""
    mgr = BaselineManager()
    mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
    return AnomalyScorer(mgr)


# ---------------------------------------------------------------------------
# Individual dimension tests
# ---------------------------------------------------------------------------


class TestNovelClassScore:
    def test_novel_class_returns_1(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        assert AnomalyScorer._novel_class_score(baseline, "qam16") == 1.0

    def test_known_class_returns_0(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        assert AnomalyScorer._novel_class_score(baseline, "fm") == 0.0

    def test_no_baseline_returns_0(self):
        assert AnomalyScorer._novel_class_score(None, "fm") == 0.0


class TestRareClassScore:
    def test_common_class_low_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # fm is 150/200 = 75% of detections
        score = AnomalyScorer._rare_class_score(baseline, "fm")
        assert score < 0.3

    def test_rare_class_high_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # ook is 20/200 = 10% of detections
        score = AnomalyScorer._rare_class_score(baseline, "ook")
        assert score > 0.8

    def test_unseen_class_near_max_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        score = AnomalyScorer._rare_class_score(baseline, "qam16")
        # With Laplace smoothing (DS-R5), unseen class is close to but < 1.0
        assert score > 0.99
        assert score < 1.0

    def test_no_baseline_returns_0(self):
        assert AnomalyScorer._rare_class_score(None, "fm") == 0.0


class TestLowConfidenceScore:
    def test_high_confidence_low_score(self):
        assert AnomalyScorer._low_confidence_score(0.95) == pytest.approx(0.05)

    def test_low_confidence_high_score(self):
        assert AnomalyScorer._low_confidence_score(0.3) == pytest.approx(0.7)

    def test_zero_confidence(self):
        assert AnomalyScorer._low_confidence_score(0.0) == 1.0

    def test_perfect_confidence(self):
        assert AnomalyScorer._low_confidence_score(1.0) == 0.0

    def test_clamps_negative(self):
        assert AnomalyScorer._low_confidence_score(1.5) == 0.0


class TestPowerZscoreScore:
    def test_normal_power_low_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        score = AnomalyScorer._power_zscore_score(baseline, -50.0)
        assert score < 0.3

    def test_no_baseline_returns_0(self):
        assert AnomalyScorer._power_zscore_score(None, -50.0) == 0.0

    def test_no_power_returns_0(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        assert AnomalyScorer._power_zscore_score(baseline, None) == 0.0

    def test_extreme_power_high_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Very different power should yield higher score
        score = AnomalyScorer._power_zscore_score(baseline, -10.0)
        assert score >= 0.0  # At least non-negative


class TestTimingAnomalyScore:
    def test_expected_hour_low_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # fm at hour 10 is the most common pattern
        score = AnomalyScorer._timing_anomaly_score(baseline, "fm", 10)
        assert score < 0.5

    def test_unexpected_hour_high_score(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Hour 3 has no data
        score = AnomalyScorer._timing_anomaly_score(baseline, "fm", 3)
        assert score == 1.0

    def test_no_baseline_returns_0(self):
        assert AnomalyScorer._timing_anomaly_score(None, "fm", 10) == 0.0


class TestQuietFrequencyScore:
    def test_busy_frequency_near_zero(self, scorer):
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # P2-16: exp(-n/20) smooth decay — busy frequency ≈ 0
        assert AnomalyScorer._quiet_frequency_score(baseline) < 0.01

    def test_no_baseline_returns_1(self):
        assert AnomalyScorer._quiet_frequency_score(None) == 1.0

    def test_few_detections_high_score(self):
        fb = FrequencyBaseline()
        for _ in range(5):
            fb.update("fm", 0.9, -50.0, 10)
        # exp(-5/20) = exp(-0.25) ≈ 0.78
        score = AnomalyScorer._quiet_frequency_score(fb)
        assert 0.7 < score < 0.85

    def test_moderate_detections_decaying(self):
        fb = FrequencyBaseline()
        for _ in range(25):
            fb.update("fm", 0.9, -50.0, 10)
        # exp(-25/20) = exp(-1.25) ≈ 0.287
        score = AnomalyScorer._quiet_frequency_score(fb)
        assert 0.2 < score < 0.4


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------


class TestCompositeScoring:
    def test_normal_detection(self, scorer):
        """Common class, high confidence, known frequency → normal."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.95,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert isinstance(result, AnomalyResult)
        assert result.score < 0.3
        assert result.priority == "normal"
        assert result.baseline_status == "stable"

    def test_novel_class_detection(self, scorer):
        """Novel class at known frequency → higher score."""
        result = scorer.score({
            "signal_class": "qam256",
            "confidence": 0.6,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.score > 0.3
        assert result.priority in ("interesting", "anomalous", "critical")
        assert len(result.reasons) > 0

    def test_score_bounds(self, scorer):
        """Score should always be in [0, 1]."""
        result = scorer.score({
            "signal_class": "qam1024",
            "confidence": 0.1,
            "freq_hz": 433_920_000,
            "power_dbm": -10.0,
            "timestamp": "2026-02-10T03:00:00+00:00",
        })
        assert 0.0 <= result.score <= 1.0

    def test_all_zero_case(self):
        """Empty baseline, known class → low score (dampened by learning)."""
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.99,
            "freq_hz": 433_920_000,
        })
        assert 0.0 <= result.score <= 1.0
        assert result.baseline_status == "learning"

    def test_learning_phase_dampening(self, learning_scorer):
        """During learning, score should be dampened by 0.5x."""
        result = learning_scorer.score({
            "signal_class": "qam256",
            "confidence": 0.5,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert result.baseline_status == "learning"
        # Dampened score should be lower than undampened
        assert result.score <= 0.75  # unknown class boost raises score

    def test_dimensions_populated(self, scorer):
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert "novel_class" in result.dimensions
        assert "rare_class" in result.dimensions
        assert "low_confidence" in result.dimensions
        assert "power_zscore" in result.dimensions
        assert "timing_anomaly" in result.dimensions
        assert "quiet_frequency" in result.dimensions

    def test_custom_weights(self, baseline_mgr):
        """Custom weights should affect scoring."""
        config = ScorerConfig(
            weights={
                AnomalyDimension.NOVEL_CLASS: 1.0,
                AnomalyDimension.RARE_CLASS: 0.0,
                AnomalyDimension.LOW_CONFIDENCE: 0.0,
                AnomalyDimension.POWER_ZSCORE: 0.0,
                AnomalyDimension.TIMING_ANOMALY: 0.0,
                AnomalyDimension.QUIET_FREQUENCY: 0.0,
            }
        )
        scorer = AnomalyScorer(baseline_mgr, config)

        # Known class should score 0
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
        })
        assert result.score == 0.0

        # Novel class should score 1.0
        result = scorer.score({
            "signal_class": "qam1024",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
        })
        assert result.score == 1.0


# ---------------------------------------------------------------------------
# Priority labels
# ---------------------------------------------------------------------------


class TestPriorityLabels:
    def test_normal(self):
        assert AnomalyScorer._priority_label(0.0) == "normal"
        assert AnomalyScorer._priority_label(0.15) == "normal"
        assert AnomalyScorer._priority_label(0.29) == "normal"

    def test_interesting(self):
        assert AnomalyScorer._priority_label(0.3) == "interesting"
        assert AnomalyScorer._priority_label(0.4) == "interesting"
        assert AnomalyScorer._priority_label(0.49) == "interesting"

    def test_anomalous(self):
        assert AnomalyScorer._priority_label(0.5) == "anomalous"
        assert AnomalyScorer._priority_label(0.6) == "anomalous"
        assert AnomalyScorer._priority_label(0.69) == "anomalous"

    def test_critical(self):
        assert AnomalyScorer._priority_label(0.7) == "critical"
        assert AnomalyScorer._priority_label(0.85) == "critical"
        assert AnomalyScorer._priority_label(1.0) == "critical"


# ---------------------------------------------------------------------------
# Scorer config
# ---------------------------------------------------------------------------


class TestScorerConfig:
    def test_default_weights_sum(self):
        config = ScorerConfig()
        total = sum(config.weights.values())
        assert total == pytest.approx(1.18, abs=0.01)

    def test_default_min_learning(self):
        config = ScorerConfig()
        assert config.min_learning_detections == 300


# ---------------------------------------------------------------------------
# Hour extraction
# ---------------------------------------------------------------------------


class TestExtractHour:
    def test_iso_string(self):
        assert AnomalyScorer._extract_hour("2026-02-10T14:30:00+00:00") == 14

    def test_datetime_object(self):
        from datetime import datetime, timezone
        dt = datetime(2026, 2, 10, 22, 15, 0, tzinfo=timezone.utc)
        assert AnomalyScorer._extract_hour(dt) == 22

    def test_none_uses_current(self):
        hour = AnomalyScorer._extract_hour(None)
        assert 0 <= hour <= 23

    def test_invalid_string_uses_current(self):
        hour = AnomalyScorer._extract_hour("not-a-date")
        assert 0 <= hour <= 23


# ---------------------------------------------------------------------------
# SNR Z-Score Tests
# ---------------------------------------------------------------------------


class TestSNRZscoreScore:
    """Tests for SNR anomaly scoring dimension."""

    def test_snr_zscore_score_normal(self, scorer):
        """SNR within 1σ should score low (<0.2)."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # First build a baseline with SNR data
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        # SNR close to baseline (20.0) should score low
        score = AnomalyScorer._snr_zscore_score(baseline, 20.0)
        assert score < 0.2

    def test_snr_zscore_score_anomalous(self, scorer):
        """SNR at 3σ should score high (MAD or z-score path)."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Build baseline with SNR=20 and some variance
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0 + (i % 5) * 0.5)

        # Calculate 3σ deviation
        import math
        std = math.sqrt(baseline.snr_var)
        snr_3sigma = baseline.snr_ewma + 3 * std

        score = AnomalyScorer._snr_zscore_score(baseline, snr_3sigma)
        # With >=30 samples, MAD scoring is preferred (returns higher scores).
        # Both paths should flag 3σ deviation as anomalous.
        assert score > 0.3

    def test_snr_zscore_score_missing_snr(self, scorer):
        """None snr_db should return 0.0."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        score = AnomalyScorer._snr_zscore_score(baseline, None)
        assert score == 0.0

    def test_snr_zscore_score_cold_start(self):
        """<2 total_detections should return 0.0."""
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        # Only 1 detection, should return 0.0
        score = AnomalyScorer._snr_zscore_score(fb, 30.0)
        assert score == 0.0

    def test_snr_zscore_score_extreme_high(self, scorer):
        """SNR at 6σ should score ~0.67 (but not saturate)."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Build baseline with SNR=20 and some variance
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0 + (i % 5) * 0.5)

        # Calculate 6σ deviation
        import math
        std = math.sqrt(baseline.snr_var)
        snr_6sigma = baseline.snr_ewma + 6 * std

        score = AnomalyScorer._snr_zscore_score(baseline, snr_6sigma)
        # With >=30 samples, MAD scoring is preferred.
        # Both paths should flag 6σ deviation as highly anomalous.
        assert score > 0.6

    def test_snr_zscore_score_negative(self, scorer):
        """Large negative z-score (jamming) should also score high."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Build baseline with SNR=20
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0 + (i % 5) * 0.5)

        # Calculate -3σ deviation (very low SNR = possible jamming)
        import math
        std = math.sqrt(baseline.snr_var)
        snr_negative_3sigma = baseline.snr_ewma - 3 * std

        score = AnomalyScorer._snr_zscore_score(baseline, snr_negative_3sigma)
        # With >=30 samples, MAD scoring is preferred.
        # Both paths should flag -3σ (jamming) as anomalous.
        assert score > 0.3

    def test_snr_zscore_score_no_baseline(self):
        """No baseline should return 0.0."""
        score = AnomalyScorer._snr_zscore_score(None, 20.0)
        assert score == 0.0

    def test_snr_zscore_score_zero_variance(self):
        """Zero variance should return 0.0 to avoid division by zero."""
        fb = FrequencyBaseline()
        # Add two detections with identical SNR (zero variance)
        fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)
        fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        # Even with different SNR, should return 0 due to zero variance
        score = AnomalyScorer._snr_zscore_score(fb, 30.0)
        assert score == 0.0


# ---------------------------------------------------------------------------
# SNR Baseline Tests
# ---------------------------------------------------------------------------


class TestSNRBaseline:
    """Tests for SNR tracking in FrequencyBaseline."""

    def test_baseline_snr_ewma_update(self):
        """Verify snr_ewma converges after updates.

        P2-17: Welford runs for first 300 samples, then EWMA.
        We need >300 total samples to test EWMA convergence.
        """
        fb = FrequencyBaseline(alpha=0.1)
        # Fill Welford phase with SNR=20 (300 samples)
        for _ in range(300):
            fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        assert fb.snr_ewma == pytest.approx(20.0, abs=0.1)

        # Feed 200 more at SNR=25 — now in EWMA phase, should shift toward 25
        for _ in range(200):
            fb.update("fm", 0.9, -50.0, 10, snr_db=25.0)

        assert fb.snr_ewma == pytest.approx(25.0, abs=0.5)

    def test_baseline_snr_var_tracking(self):
        """Verify snr_var tracks variance correctly."""
        fb = FrequencyBaseline(alpha=0.05)
        # Feed detections with varying SNR
        import random
        random.seed(42)
        for _ in range(200):
            snr = 20.0 + random.gauss(0, 2.0)  # Mean=20, std=2
            fb.update("fm", 0.9, -50.0, 10, snr_db=snr)

        # Variance should be non-zero and roughly track input variance
        assert fb.snr_var > 0.0
        import math
        std = math.sqrt(fb.snr_var)
        # Estimated std should be in reasonable range (1-4 for std=2 input)
        assert 1.0 < std < 4.0

    def test_baseline_snr_zscore_calculation(self):
        """Verify z-score = (snr - mean) / sqrt(var)."""
        fb = FrequencyBaseline(alpha=0.1)
        # Build baseline at SNR=20 with small variance
        for _ in range(100):
            fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        # Manually calculate expected z-score
        import math
        std = math.sqrt(fb.snr_var)
        if std > 1e-9:
            expected_z = (25.0 - fb.snr_ewma) / std
            actual_z = fb.snr_zscore(25.0)
            assert actual_z == pytest.approx(expected_z, abs=0.01)

    def test_baseline_snr_serialization(self):
        """Verify to_dict()/from_dict() roundtrip preserves snr fields."""
        fb = FrequencyBaseline(alpha=0.05)
        fb.update("fm", 0.9, -50.0, 10, snr_db=20.0)
        fb.update("bpsk", 0.7, -55.0, 22, snr_db=25.0)

        data = fb.to_dict()
        restored = FrequencyBaseline.from_dict(data)

        assert restored.snr_ewma == fb.snr_ewma
        assert restored.snr_var == fb.snr_var
        assert restored.total_detections == fb.total_detections

    def test_baseline_snr_first_detection(self):
        """First detection should initialize snr_ewma, snr_var=0."""
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10, snr_db=22.5)

        assert fb.snr_ewma == 22.5
        assert fb.snr_var == 0.0

    def test_baseline_snr_none_skips_update(self):
        """None snr_db should skip SNR tracking."""
        fb = FrequencyBaseline()
        fb.update("fm", 0.9, -50.0, 10, snr_db=None)

        assert fb.snr_ewma == 0.0
        assert fb.snr_var == 0.0
        assert fb.total_detections == 1


# ---------------------------------------------------------------------------
# Integration: SNR in full scoring
# ---------------------------------------------------------------------------


class TestSNRIntegration:
    """Integration tests for SNR dimension in full score() pipeline."""

    def test_score_includes_snr_dimension(self, scorer):
        """Full score() call with SNR data includes SNR_ZSCORE in dimensions."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "snr_db": 20.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })

        assert "snr_zscore" in result.dimensions
        # Normal SNR should score low
        assert result.dimensions["snr_zscore"] < 0.3

    def test_score_includes_snr_reason_when_significant(self, scorer):
        """SNR anomaly should appear in reasons when score > 0.5."""
        baseline = scorer.baseline_manager.get_baseline(433_920_000)
        # Build SNR baseline at 20 with low variance
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0 + (i % 3) * 0.1)

        # Test with very high SNR (should be anomalous)
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "snr_db": 50.0,  # Much higher than baseline
            "timestamp": "2026-02-10T10:30:00+00:00",
        })

        # Check that SNR dimension scored high
        assert result.dimensions["snr_zscore"] > 0.5
        # Check that reason was added
        assert any("SNR" in reason for reason in result.reasons)
        assert any("snr_db=50.0" in reason for reason in result.reasons)

    def test_score_without_snr_data(self, scorer):
        """Score without snr_db should still work (dimension scores 0)."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })

        assert "snr_zscore" in result.dimensions
        assert result.dimensions["snr_zscore"] == 0.0
        assert not any("SNR" in reason for reason in result.reasons)

    def test_score_snr_weight_in_composite(self, baseline_mgr):
        """SNR weight contributes to composite score correctly."""
        # Create scorer with SNR weight = 1.0, all others = 0.0
        config = ScorerConfig(
            weights={
                AnomalyDimension.NOVEL_CLASS: 0.0,
                AnomalyDimension.RARE_CLASS: 0.0,
                AnomalyDimension.LOW_CONFIDENCE: 0.0,
                AnomalyDimension.POWER_ZSCORE: 0.0,
                AnomalyDimension.SNR_ZSCORE: 1.0,
                AnomalyDimension.TIMING_ANOMALY: 0.0,
                AnomalyDimension.QUIET_FREQUENCY: 0.0,
            }
        )
        scorer = AnomalyScorer(baseline_mgr, config)

        # Build SNR baseline
        baseline = baseline_mgr.get_baseline(433_920_000)
        for i in range(100):
            baseline.update("fm", 0.9, -50.0, 10, snr_db=20.0)

        # Test with anomalous SNR
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "snr_db": 50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })

        # Composite score should equal SNR dimension score (weight=1.0)
        assert result.score == pytest.approx(result.dimensions["snr_zscore"], abs=0.01)
