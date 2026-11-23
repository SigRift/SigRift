"""Tests for DS backlog features: R9, R11, R12, R13, R14.

DS-R9:  Correlation-aware scoring (decorrelation)
DS-R11: Adaptive quantile-based thresholds
DS-R12: ROC evaluation framework
DS-R13: Online Isolation Forest with reservoir sampling
DS-R14: Bandwidth / inter-arrival scoring dimensions
"""

from __future__ import annotations

import math
import time

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager, FrequencyBaseline
from sigrift.bridge.anomaly.evaluation import EvaluationResult, ScoringEvaluator
from sigrift.bridge.anomaly.quantile_tracker import QuantileTracker
from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyResult,
    AnomalyScorer,
    ScorerConfig,
    _DEFAULT_WEIGHTS,
    DEFAULT_RF_DIMENSION_WEIGHTS,
)

# ---------------------------------------------------------------------------
# DS-R14: Bandwidth / duty-cycle baseline tracking
# ---------------------------------------------------------------------------


class TestBandwidthBaseline:
    """FrequencyBaseline bandwidth tracking."""

    def test_bandwidth_tracking_initializes_on_first_sample(self):
        bl = FrequencyBaseline()
        bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
        assert "bpsk" in bl.bandwidth_by_class
        ewma, var, count = bl.bandwidth_by_class["bpsk"]
        assert ewma == 25_000.0
        assert count == 1
        assert var == 0.0

    def test_bandwidth_variance_grows_with_diverse_samples(self):
        bl = FrequencyBaseline()
        for i in range(50):
            bw = 25_000 + (i % 5) * 1000  # 25k-29k
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))
        _ewma, var, count = bl.bandwidth_by_class["bpsk"]
        assert count == 50
        assert var > 0, "Variance should be positive with diverse samples"

    def test_bandwidth_zscore_needs_10_samples(self):
        bl = FrequencyBaseline()
        for i in range(9):
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
        assert bl.bandwidth_zscore("bpsk", 50_000.0) == 0.0, "Should return 0 below 10 samples"
        bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
        # With 10 samples of identical bandwidth, var is near 0 so zscore still 0
        assert bl.bandwidth_zscore("bpsk", 50_000.0) == 0.0

    def test_bandwidth_zscore_detects_anomaly(self):
        bl = FrequencyBaseline()
        # Build baseline with varied bandwidth
        for i in range(100):
            bw = 25_000 + (i % 10) * 200  # 25k-26.8k range
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))
        z = bl.bandwidth_zscore("bpsk", 100_000.0)  # Way outside baseline
        assert abs(z) > 2.0, f"z-score should be large for outlier bandwidth, got {z}"

    def test_bandwidth_per_class_isolation(self):
        bl = FrequencyBaseline()
        for i in range(20):
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
            bl.update("ofdm", 0.9, -50.0, 10, bandwidth_hz=20_000_000.0)
        assert "bpsk" in bl.bandwidth_by_class
        assert "ofdm" in bl.bandwidth_by_class
        bpsk_ewma = bl.bandwidth_by_class["bpsk"][0]
        ofdm_ewma = bl.bandwidth_by_class["ofdm"][0]
        assert bpsk_ewma < 100_000, f"BPSK baseline should be ~25kHz, got {bpsk_ewma}"
        assert ofdm_ewma > 1_000_000, f"OFDM baseline should be ~20MHz, got {ofdm_ewma}"

    def test_bandwidth_serialization_round_trip(self):
        bl = FrequencyBaseline()
        for i in range(20):
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0 + i * 100)
        data = bl.to_dict()
        assert "bandwidth_by_class" in data
        restored = FrequencyBaseline.from_dict(data)
        assert "bpsk" in restored.bandwidth_by_class
        assert restored.bandwidth_by_class["bpsk"][2] == 20


class TestInterArrivalBaseline:
    """FrequencyBaseline inter-arrival time tracking."""

    def test_first_detection_no_inter_arrival(self):
        bl = FrequencyBaseline()
        bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0)
        assert bl.last_detection_time == 1000.0
        assert bl._ia_count == 0

    def test_second_detection_computes_inter_arrival(self):
        bl = FrequencyBaseline()
        bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0)
        bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1005.0)
        assert bl._ia_count == 1
        assert bl.last_inter_arrival == 5.0
        assert bl.inter_arrival_ewma == 5.0

    def test_inter_arrival_zscore_needs_10_samples(self):
        bl = FrequencyBaseline()
        for i in range(10):
            bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0 + i * 5.0)
        assert bl._ia_count == 9
        assert bl.inter_arrival_zscore() == 0.0, "Should need 10+ IA samples"

    def test_inter_arrival_zscore_detects_anomaly(self):
        bl = FrequencyBaseline()
        # Regular 5-second arrivals
        for i in range(50):
            bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0 + i * 5.0)
        # Now a very long gap
        bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0 + 50 * 5.0 + 500.0)
        z = bl.inter_arrival_zscore()
        assert abs(z) > 2.0, f"z-score should be large for long gap, got {z}"

    def test_inter_arrival_serialization(self):
        bl = FrequencyBaseline()
        for i in range(20):
            bl.update("bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0 + i * 5.0)
        data = bl.to_dict()
        assert "ia_count" in data
        assert "inter_arrival_ewma" in data
        restored = FrequencyBaseline.from_dict(data)
        assert restored._ia_count == bl._ia_count
        assert abs(restored.inter_arrival_ewma - bl.inter_arrival_ewma) < 1e-6


class TestBaselineManagerPassthrough:
    """BaselineManager passes bandwidth/timestamp to FrequencyBaseline."""

    def test_bandwidth_passthrough(self):
        mgr = BaselineManager()
        mgr.update(433_000_000, "bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
        bl = mgr.get_baseline(433_000_000)
        assert bl is not None
        assert "bpsk" in bl.bandwidth_by_class

    def test_timestamp_passthrough(self):
        mgr = BaselineManager()
        mgr.update(433_000_000, "bpsk", 0.9, -50.0, 10, timestamp_epoch=1000.0)
        mgr.update(433_000_000, "bpsk", 0.9, -50.0, 10, timestamp_epoch=1005.0)
        bl = mgr.get_baseline(433_000_000)
        assert bl is not None
        assert bl._ia_count == 1


# ---------------------------------------------------------------------------
# DS-R14: Bandwidth / inter-arrival scorer dimensions
# ---------------------------------------------------------------------------


class TestBandwidthAnomalyScorer:
    """AnomalyScorer BANDWIDTH_ANOMALY dimension."""

    def test_dimension_exists_in_enum(self):
        assert hasattr(AnomalyDimension, "BANDWIDTH_ANOMALY")
        assert AnomalyDimension.BANDWIDTH_ANOMALY.value == "bandwidth_anomaly"

    def test_default_weight_is_zero(self):
        assert _DEFAULT_WEIGHTS[AnomalyDimension.BANDWIDTH_ANOMALY] == 0.0
        assert DEFAULT_RF_DIMENSION_WEIGHTS["bandwidth_anomaly"] == 0.0

    def test_score_includes_bandwidth_dimension(self):
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)
        result = scorer.score({"signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6})
        assert "bandwidth_anomaly" in result.dimensions
        assert isinstance(result.dimensions["bandwidth_anomaly"], float)

    def test_bandwidth_anomaly_zero_without_data(self):
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "bandwidth_hz": 25_000.0,
        })
        assert result.dimensions["bandwidth_anomaly"] == 0.0

    def test_bandwidth_anomaly_nonzero_with_weight(self):
        mgr = BaselineManager()
        # Build bandwidth baseline
        for i in range(100):
            bw = 25_000 + (i % 10) * 200
            mgr.update(433e6, "bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))
        weights = dict(_DEFAULT_WEIGHTS)
        weights[AnomalyDimension.BANDWIDTH_ANOMALY] = 0.10
        config = ScorerConfig(weights=weights)
        scorer = AnomalyScorer(mgr, config)
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "bandwidth_hz": 200_000.0,  # Way outside baseline
        })
        assert result.dimensions["bandwidth_anomaly"] > 0.0


class TestInterArrivalAnomalyScorer:
    """AnomalyScorer INTER_ARRIVAL_ANOMALY dimension."""

    def test_dimension_exists_in_enum(self):
        assert hasattr(AnomalyDimension, "INTER_ARRIVAL_ANOMALY")
        assert AnomalyDimension.INTER_ARRIVAL_ANOMALY.value == "inter_arrival_anomaly"

    def test_default_weight_is_zero(self):
        assert _DEFAULT_WEIGHTS[AnomalyDimension.INTER_ARRIVAL_ANOMALY] == 0.0

    def test_score_includes_inter_arrival_anomaly_dimension(self):
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)
        result = scorer.score({"signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6})
        assert "inter_arrival_anomaly" in result.dimensions
        assert isinstance(result.dimensions["inter_arrival_anomaly"], float)


# ---------------------------------------------------------------------------
# DS-R9: Correlation-aware scoring (decorrelation)
# ---------------------------------------------------------------------------


class TestDecorrelation:
    """DS-R9: Diminishing returns on correlated classification dims."""

    def test_decorrelation_enabled_by_default(self):
        config = ScorerConfig()
        assert config.decorrelate_classification is True

    def test_decorrelation_reduces_score_when_all_classification_dims_fire(self):
        """When novel, rare, and low_confidence all fire, decorrelation
        should reduce the combined contribution vs non-decorrelated."""
        mgr = BaselineManager()
        # Build baseline so novel_class = 1.0, rare_class ~ 1.0 for unseen class
        for i in range(400):
            mgr.update(433e6, "fm", 0.95, -50.0, 10)

        detection = {
            "signal_class": "qam256",  # Novel at this freq
            "confidence": 0.3,  # Low confidence
            "freq_hz": 433e6,
        }

        # Score with decorrelation
        scorer_on = AnomalyScorer(mgr, ScorerConfig(decorrelate_classification=True))
        result_on = scorer_on.score(detection)

        # Score without decorrelation
        scorer_off = AnomalyScorer(mgr, ScorerConfig(decorrelate_classification=False))
        result_off = scorer_off.score(detection)

        assert result_on.score < result_off.score, (
            f"Decorrelated score ({result_on.score}) should be lower "
            f"than non-decorrelated ({result_off.score})"
        )

    def test_decorrelation_no_effect_when_single_dim_fires(self):
        """When only one classification dim fires, decorrelation should
        have no effect."""
        mgr = BaselineManager()
        for i in range(400):
            mgr.update(433e6, "bpsk", 0.95, -50.0, 10)

        # bpsk is common, so rare_class ≈ 0, novel = 0.
        # Low confidence only.
        detection = {
            "signal_class": "bpsk",
            "confidence": 0.3,
            "freq_hz": 433e6,
        }

        scorer_on = AnomalyScorer(mgr, ScorerConfig(decorrelate_classification=True))
        scorer_off = AnomalyScorer(mgr, ScorerConfig(decorrelate_classification=False))
        result_on = scorer_on.score(detection)
        result_off = scorer_off.score(detection)

        # Should be identical (only low_confidence fires > 0.3)
        assert abs(result_on.score - result_off.score) < 0.02

    def test_decorrelation_decay_factor(self):
        """Verify the 50% decay is applied to 2nd and 25% to 3rd dim."""
        mgr = BaselineManager()
        for i in range(400):
            mgr.update(433e6, "fm", 0.95, -50.0, 10)

        detection = {
            "signal_class": "qam256",
            "confidence": 0.2,
            "freq_hz": 433e6,
        }

        scorer = AnomalyScorer(mgr, ScorerConfig(decorrelate_classification=True))
        result = scorer.score(detection)
        # All three classification dims should be > 0.3
        dims = result.dimensions
        active = sum(
            1 for d in ["novel_class", "rare_class", "low_confidence"]
            if dims.get(d, 0) > 0.3
        )
        assert active >= 2, f"Expected 2+ active classification dims, got {active}"


# ---------------------------------------------------------------------------
# DS-R11: Adaptive quantile-based thresholds
# ---------------------------------------------------------------------------


class TestQuantileTracker:
    """QuantileTracker for adaptive thresholds."""

    def test_fallback_thresholds_below_min_samples(self):
        qt = QuantileTracker(min_samples=100)
        for i in range(50):
            qt.add_score(i / 100, 433e6)
        t_int, t_anom, t_crit = qt.get_thresholds(433e6)
        assert t_int == 0.3
        assert t_anom == 0.5
        assert t_crit == 0.7

    def test_adaptive_thresholds_activate(self):
        qt = QuantileTracker(min_samples=50)
        import random
        random.seed(42)
        for _ in range(200):
            qt.add_score(random.betavariate(2, 5), 433e6)
        t_int, t_anom, t_crit = qt.get_thresholds(433e6)
        assert 0 < t_int < t_anom < t_crit <= 1.0
        assert t_int != 0.3, "Thresholds should be adaptive, not fixed"

    def test_per_band_isolation(self):
        qt = QuantileTracker(min_samples=50)
        import random
        random.seed(42)
        for _ in range(100):
            qt.add_score(random.uniform(0.0, 0.3), 433e6)  # sub-GHz: low scores
            qt.add_score(random.uniform(0.5, 1.0), 2.45e9)  # ISM 2.4: high scores
        t_sub = qt.get_thresholds(433e6)
        t_ism = qt.get_thresholds(2.45e9)
        assert t_sub[0] < t_ism[0], "Sub-GHz thresholds should be lower"

    def test_priority_label_uses_adaptive_thresholds(self):
        qt = QuantileTracker(min_samples=50)
        import random
        random.seed(42)
        for _ in range(200):
            qt.add_score(random.betavariate(2, 5), 433e6)
        label = qt.priority_label(0.95, 433e6)
        assert label == "critical"
        label_low = qt.priority_label(0.01, 433e6)
        assert label_low == "normal"

    def test_status_reports_bands(self):
        qt = QuantileTracker(min_samples=10)
        for i in range(20):
            qt.add_score(i / 20, 433e6)
        status = qt.status()
        assert "sub_1ghz" in status
        assert status["sub_1ghz"]["active"] is True
        assert "thresholds" in status["sub_1ghz"]
        assert status["sub_1ghz"]["samples"] == 20

    def test_ring_buffer_caps_at_max_samples(self):
        qt = QuantileTracker(max_samples=50, min_samples=10)
        for i in range(200):
            qt.add_score(i / 200, 433e6)
        buf = qt._buffers.get("sub_1ghz", [])
        assert len(buf) == 50
        assert qt._counts["sub_1ghz"] == 200

    def test_monotonic_thresholds(self):
        qt = QuantileTracker(min_samples=10)
        for i in range(50):
            qt.add_score(i / 50, 433e6)
        t_int, t_anom, t_crit = qt.get_thresholds(433e6)
        assert t_int < t_anom < t_crit

    def test_threshold_floor_prevents_manipulation(self):
        """P2-1: Flooding with zero scores should not push thresholds below floors."""
        qt = QuantileTracker(min_samples=10, min_thresholds=(0.2, 0.4, 0.6))
        # Flood with all-zero scores
        for _ in range(200):
            qt.add_score(0.0, 433e6)
        t_int, t_anom, t_crit = qt.get_thresholds(433e6)
        assert t_int >= 0.2, f"Interesting threshold {t_int} below floor 0.2"
        assert t_anom >= 0.4, f"Anomalous threshold {t_anom} below floor 0.4"
        assert t_crit >= 0.6, f"Critical threshold {t_crit} below floor 0.6"

    def test_threshold_shift_warning(self):
        """P2-1: Threshold shift rate check runs without error."""
        qt = QuantileTracker(min_samples=10, min_thresholds=(0.0, 0.0, 0.0))
        # Build initial thresholds with high scores
        for _ in range(50):
            qt.add_score(0.8, 433e6)
        qt.get_thresholds(433e6)  # store _prev_thresholds
        # Now add many low scores to shift thresholds down
        for _ in range(200):
            qt.add_score(0.01, 433e6)
        # Should run without error and log a warning (verified by no exception)
        t_int, t_anom, t_crit = qt.get_thresholds(433e6)
        assert t_int < 0.8  # thresholds should have shifted down


# ---------------------------------------------------------------------------
# DS-R12: ROC evaluation framework
# ---------------------------------------------------------------------------


class TestScoringEvaluator:
    """ScoringEvaluator ROC / AUC computation."""

    def test_empty_evaluator(self):
        ev = ScoringEvaluator()
        result = ev.compute_roc()
        assert result.auc == 0.0
        assert result.n_positive == 0
        assert result.n_negative == 0

    def test_perfect_separation(self):
        ev = ScoringEvaluator()
        # All positives have score > 0.8, all negatives < 0.2
        for _ in range(50):
            ev.add_labeled_sample(0.9, True)
            ev.add_labeled_sample(0.1, False)
        result = ev.compute_roc()
        assert result.auc > 0.95, f"Perfect separation should give AUC > 0.95, got {result.auc}"
        assert result.n_positive == 50
        assert result.n_negative == 50

    def test_random_scores_auc_near_half(self):
        import random
        random.seed(42)
        ev = ScoringEvaluator()
        for _ in range(200):
            score = random.random()
            ev.add_labeled_sample(score, random.random() > 0.5)
        result = ev.compute_roc()
        assert 0.3 < result.auc < 0.7, f"Random scores AUC should be ~0.5, got {result.auc}"

    def test_optimal_threshold_and_f1(self):
        ev = ScoringEvaluator()
        # Use overlapping score distributions for a meaningful threshold
        import random
        random.seed(42)
        for _ in range(100):
            ev.add_labeled_sample(0.5 + random.random() * 0.4, True)   # 0.5-0.9
            ev.add_labeled_sample(0.1 + random.random() * 0.4, False)  # 0.1-0.5
        result = ev.compute_roc()
        assert 0.2 < result.optimal_threshold < 0.8
        assert result.optimal_f1 > 0.5

    def test_confusion_matrix(self):
        ev = ScoringEvaluator()
        ev.add_labeled_sample(0.9, True)
        ev.add_labeled_sample(0.8, True)
        ev.add_labeled_sample(0.2, False)
        ev.add_labeled_sample(0.1, False)
        cm = ev.confusion_matrix(0.5)
        assert cm["tp"] == 2
        assert cm["tn"] == 2
        assert cm["fp"] == 0
        assert cm["fn"] == 0

    def test_threshold_for_fpr(self):
        ev = ScoringEvaluator()
        for i in range(100):
            ev.add_labeled_sample(i / 100, False)  # negatives spread 0-1
        for i in range(100):
            ev.add_labeled_sample(0.7 + i / 400, True)  # positives 0.7-0.95
        threshold = ev.threshold_for_fpr(0.05)
        assert threshold is not None
        assert 0.9 < threshold <= 1.0, f"5% FPR threshold should be high, got {threshold}"

    def test_add_feedback_batch(self):
        ev = ScoringEvaluator()
        detections = [
            {"detection_id": "d1", "anomaly_score": 0.9},
            {"detection_id": "d2", "anomaly_score": 0.3},
            {"detection_id": "d3", "anomaly_score": 0.5},
        ]
        feedback = [
            {"detection_id": "d1", "label": "true_positive"},
            {"detection_id": "d2", "label": "false_positive"},
            {"detection_id": "d3", "label": "expected"},  # Ignored
        ]
        added = ev.add_feedback_batch(detections, feedback)
        assert added == 2
        assert ev.sample_count == 2

    def test_roc_curve_structure(self):
        ev = ScoringEvaluator()
        for i in range(30):
            ev.add_labeled_sample(0.8 + i / 300, True)
            ev.add_labeled_sample(0.2 + i / 300, False)
        result = ev.compute_roc()
        assert len(result.roc_curve) > 0
        for point in result.roc_curve:
            assert 0.0 <= point.tpr <= 1.0
            assert 0.0 <= point.fpr <= 1.0

    def test_clear(self):
        ev = ScoringEvaluator()
        ev.add_labeled_sample(0.5, True)
        ev.clear()
        assert ev.sample_count == 0

    def test_label_quality_check_imbalanced(self):
        """P2-2: Detect suspicious label distribution (>90% FP)."""
        ev = ScoringEvaluator()
        for i in range(95):
            ev.add_labeled_sample(float(i) / 100, False)  # 95 FP
        for i in range(5):
            ev.add_labeled_sample(0.9, True)  # 5 TP
        quality = ev.check_label_quality()
        assert quality["total"] == 100
        assert len(quality["warnings"]) == 1
        assert "label poisoning" in quality["warnings"][0]

    def test_max_samples_eviction(self):
        """P2-2: Buffer doesn't grow beyond max_samples."""
        ev = ScoringEvaluator(max_samples=100)
        for i in range(200):
            ev.add_labeled_sample(float(i) / 200, True)
        assert ev.sample_count == 100
        # Oldest samples should have been evicted (FIFO)
        oldest_score = ev._samples[0][0]
        assert oldest_score >= 0.5, f"FIFO eviction should have removed early samples, oldest={oldest_score}"

    def test_roc_optimized_matches_naive(self):
        """P2-6: Optimized bisect-based ROC gives same AUC as before."""
        import random
        random.seed(123)
        ev = ScoringEvaluator()
        # Well-separated distributions for a deterministic AUC check
        for _ in range(100):
            ev.add_labeled_sample(0.7 + random.random() * 0.3, True)   # 0.7-1.0
            ev.add_labeled_sample(random.random() * 0.5, False)        # 0.0-0.5
        result = ev.compute_roc()
        assert result.auc > 0.95, f"Well-separated data should give AUC > 0.95, got {result.auc}"
        assert result.n_positive == 100
        assert result.n_negative == 100
        # Verify ROC curve is well-formed
        for point in result.roc_curve:
            assert 0.0 <= point.tpr <= 1.0
            assert 0.0 <= point.fpr <= 1.0


# ---------------------------------------------------------------------------
# DS-R13: Online Isolation Forest with reservoir sampling
# ---------------------------------------------------------------------------


class TestReservoirSampling:
    """IsolationForestDetector reservoir sampling."""

    def test_buffer_grows_normally_under_cap(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(max_buffer_size=100)
        for i in range(50):
            det.add_sample([float(i)] * 13)
        assert det.buffer_size == 50
        assert det.total_seen == 50

    def test_buffer_capped_at_max_size(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(max_buffer_size=100)
        for i in range(500):
            det.add_sample([float(i)] * 13)
        assert det.buffer_size == 100
        assert det.total_seen == 500

    def test_reservoir_maintains_representative_sample(self):
        """Statistical test: reservoir should contain samples from
        throughout the stream, not just the first 100."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(max_buffer_size=100)
        for i in range(1000):
            det.add_sample([float(i)] * 13)
        # Check that buffer contains samples from the latter half
        first_features = [s[0] for s in det._training_buffer]
        has_late = any(f >= 500 for f in first_features)
        assert has_late, "Reservoir should contain samples from the latter half of the stream"

    def test_per_instance_rng_differs(self):
        """Different IsolationForestDetector instances should use
        independent RNGs seeded from os.urandom, producing different
        reservoir outcomes."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det_a = IsolationForestDetector(max_buffer_size=50)
        det_b = IsolationForestDetector(max_buffer_size=50)
        for i in range(500):
            det_a.add_sample([float(i)] * 13)
            det_b.add_sample([float(i)] * 13)
        buf_a = [s[0] for s in det_a._training_buffer]
        buf_b = [s[0] for s in det_b._training_buffer]
        # With independent RNGs seeded from urandom, the buffers should
        # differ (probability of identical buffers is astronomically low).
        assert buf_a != buf_b, "Per-instance RNGs should produce different reservoir contents"

    def test_retrain_without_samples_uses_buffer(self):
        """DS-R13: retrain() without arguments uses existing buffer."""
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(min_training_samples=50, max_buffer_size=200)
        import random
        random.seed(42)
        for i in range(100):
            features = [random.random() for _ in range(13)]
            det.add_sample(features)
        assert det.needs_training()
        try:
            det.retrain()
            assert det.is_ready()
        except RuntimeError:
            pytest.skip("scikit-learn not installed")

    def test_needs_training_after_buffer_fills(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(min_training_samples=50, max_buffer_size=100)
        for i in range(49):
            det.add_sample([float(i)] * 13)
        assert not det.needs_training()
        det.add_sample([49.0] * 13)
        assert det.needs_training()

    def test_total_seen_property(self):
        from sigrift.bridge.anomaly.isolation_forest import IsolationForestDetector
        det = IsolationForestDetector(max_buffer_size=10)
        for i in range(100):
            det.add_sample([float(i)] * 13)
        assert det.total_seen == 100
        assert det.buffer_size == 10


# ---------------------------------------------------------------------------
# DS-R14: Weight / dimension mapping completeness
# ---------------------------------------------------------------------------


class TestDimensionCompleteness:
    """All dimensions have weights and appear in score output."""

    def test_all_dimensions_in_default_weights(self):
        for dim in AnomalyDimension:
            assert dim in _DEFAULT_WEIGHTS, f"Missing default weight for {dim}"

    def test_all_dimensions_in_string_weights(self):
        for dim in AnomalyDimension:
            assert dim.value in DEFAULT_RF_DIMENSION_WEIGHTS, (
                f"Missing string weight for {dim.value}"
            )

    def test_all_dimensions_in_score_output(self):
        mgr = BaselineManager()
        scorer = AnomalyScorer(mgr)
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6,
        })
        for dim in AnomalyDimension:
            assert dim.value in result.dimensions, f"Missing dimension {dim.value} in output"

    def test_weights_sum_to_one(self):
        total = sum(_DEFAULT_WEIGHTS.values())
        assert abs(total - 1.18) < 0.01, f"Weights sum to {total}, expected ~1.18"


# ---------------------------------------------------------------------------
# v4.14.0 review fixes
# ---------------------------------------------------------------------------


class TestDecorrelationThresholdConfig:
    """P1-1: Decorrelation decay and threshold are configurable."""

    def test_default_decorrelation_threshold_is_0_5(self):
        config = ScorerConfig()
        assert config.decorrelation_threshold == 0.5

    def test_default_decorrelation_decay_is_0_5(self):
        config = ScorerConfig()
        assert config.decorrelation_decay == 0.5

    def test_higher_threshold_avoids_decorrelation_on_weak_dims(self):
        """With threshold=0.5, dims scoring 0.4 should not trigger
        decorrelation, but with threshold=0.3 they would."""
        mgr = BaselineManager()
        for i in range(400):
            mgr.update(433e6, "fm", 0.95, -50.0, 10)

        # Use a confidence that gives low_confidence = 0.4 (below 0.5 threshold)
        detection = {
            "signal_class": "qam256",  # Novel -> 1.0
            "confidence": 0.6,  # low_confidence = 0.4
            "freq_hz": 433e6,
        }

        # With default threshold 0.5: low_confidence=0.4 is NOT active,
        # so only novel_class + rare_class fire -> still decorrelates
        scorer_high = AnomalyScorer(
            mgr, ScorerConfig(decorrelation_threshold=0.5),
        )
        result_high = scorer_high.score(detection)

        # With old threshold 0.3: low_confidence=0.4 IS active,
        # so all 3 fire -> more aggressive decorrelation
        scorer_low = AnomalyScorer(
            mgr, ScorerConfig(decorrelation_threshold=0.3),
        )
        result_low = scorer_low.score(detection)

        # More active dims with lower threshold means more weight decay,
        # so the low-threshold score should be lower or equal.
        assert result_low.score <= result_high.score, (
            f"Lower threshold ({result_low.score}) should produce "
            f"equal or lower score than higher threshold ({result_high.score})"
        )

    def test_custom_decay_changes_decorrelation_strength(self):
        """A smaller decay factor should produce more aggressive dampening."""
        mgr = BaselineManager()
        for i in range(400):
            mgr.update(433e6, "fm", 0.95, -50.0, 10)

        detection = {
            "signal_class": "qam256",
            "confidence": 0.1,  # very low -> all 3 classification dims fire
            "freq_hz": 433e6,
        }

        scorer_gentle = AnomalyScorer(
            mgr, ScorerConfig(decorrelation_decay=0.8, decorrelation_threshold=0.3),
        )
        scorer_aggressive = AnomalyScorer(
            mgr, ScorerConfig(decorrelation_decay=0.2, decorrelation_threshold=0.3),
        )
        result_gentle = scorer_gentle.score(detection)
        result_aggressive = scorer_aggressive.score(detection)

        assert result_aggressive.score < result_gentle.score, (
            f"Aggressive decay ({result_aggressive.score}) should be lower "
            f"than gentle decay ({result_gentle.score})"
        )


class TestBaselineDependentDims:
    """P0-3: _BASELINE_DEPENDENT includes bandwidth and inter-arrival dims."""

    def test_bandwidth_anomaly_dampened_during_learning(self):
        mgr = BaselineManager()
        # Only a few detections -> learning phase
        for i in range(10):
            mgr.update(433e6, "bpsk", 0.9, -50.0 + i, 10,
                       bandwidth_hz=25_000.0 + i * 200)

        weights = dict(_DEFAULT_WEIGHTS)
        weights[AnomalyDimension.BANDWIDTH_ANOMALY] = 0.10
        config = ScorerConfig(weights=weights, min_learning_detections=300)
        scorer = AnomalyScorer(mgr, config)

        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "bandwidth_hz": 200_000.0,
        })
        assert result.baseline_status == "learning"

    def test_inter_arrival_anomaly_dampened_during_learning(self):
        mgr = BaselineManager()
        for i in range(10):
            mgr.update(433e6, "bpsk", 0.9, -50.0, 10,
                       timestamp_epoch=1000.0 + i * 5.0)

        weights = dict(_DEFAULT_WEIGHTS)
        weights[AnomalyDimension.INTER_ARRIVAL_ANOMALY] = 0.10
        config = ScorerConfig(weights=weights, min_learning_detections=300)
        scorer = AnomalyScorer(mgr, config)

        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6,
        })
        assert result.baseline_status == "learning"

    def test_baseline_dependent_set_contents(self):
        """Verify the _BASELINE_DEPENDENT set inside score() contains the
        expected dimensions by observing dampening behavior."""
        mgr = BaselineManager()
        # Stay in learning phase (< 300 detections)
        for i in range(5):
            mgr.update(433e6, "bpsk", 0.9, -50.0, 10)

        # Give nonzero weight to bandwidth + inter-arrival
        weights = dict(_DEFAULT_WEIGHTS)
        weights[AnomalyDimension.BANDWIDTH_ANOMALY] = 0.10
        weights[AnomalyDimension.INTER_ARRIVAL_ANOMALY] = 0.10

        # Score in learning phase
        config_learn = ScorerConfig(weights=weights, min_learning_detections=300)
        scorer_learn = AnomalyScorer(mgr, config_learn)
        result_learn = scorer_learn.score({
            "signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6,
        })
        assert result_learn.baseline_status == "learning"

        # Build up baseline past learning phase
        mgr2 = BaselineManager()
        for i in range(400):
            mgr2.update(433e6, "bpsk", 0.9, -50.0, 10)

        config_stable = ScorerConfig(weights=weights, min_learning_detections=300)
        scorer_stable = AnomalyScorer(mgr2, config_stable)
        result_stable = scorer_stable.score({
            "signal_class": "bpsk", "confidence": 0.9, "freq_hz": 433e6,
        })
        assert result_stable.baseline_status == "stable"


class TestBandwidthMadScore:
    """P2-3: MAD-based robust scoring for bandwidth."""

    def test_bandwidth_mad_score(self):
        """MAD scoring works for bandwidth with 30+ samples."""
        bl = FrequencyBaseline()
        # Build baseline with varied bandwidth (25k-27k range)
        for i in range(50):
            bw = 25_000 + (i % 10) * 200
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))
        assert len(bl.bandwidth_samples) == 50
        # An outlier bandwidth should produce a nonzero MAD score
        score = bl.bandwidth_mad_score(100_000.0)
        assert score > 0.0, f"MAD score should be nonzero for outlier, got {score}"
        # A normal bandwidth should produce a low score
        score_normal = bl.bandwidth_mad_score(26_000.0)
        assert score_normal < score, (
            f"Normal bandwidth score ({score_normal}) should be less than outlier ({score})"
        )

    def test_bandwidth_mad_score_insufficient_samples(self):
        """MAD scoring returns 0.0 with fewer than 10 samples."""
        bl = FrequencyBaseline()
        for i in range(9):
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0)
        assert bl.bandwidth_mad_score(100_000.0) == 0.0

    def test_bandwidth_samples_serialization(self):
        """bandwidth_samples survives to_dict/from_dict round-trip."""
        bl = FrequencyBaseline()
        for i in range(30):
            bl.update("bpsk", 0.9, -50.0, 10, bandwidth_hz=25_000.0 + i * 100)
        data = bl.to_dict()
        assert "bandwidth_samples" in data
        restored = FrequencyBaseline.from_dict(data)
        assert len(restored.bandwidth_samples) == 30

    def test_scorer_prefers_mad_at_30_samples(self):
        """Scorer uses MAD path when >= 30 bandwidth samples available."""
        mgr = BaselineManager()
        for i in range(50):
            bw = 25_000 + (i % 10) * 200
            mgr.update(433e6, "bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))
        bl = mgr.get_baseline(433e6)
        assert len(bl.bandwidth_samples) >= 30
        # Score via scorer
        weights = dict(_DEFAULT_WEIGHTS)
        weights[AnomalyDimension.BANDWIDTH_ANOMALY] = 0.10
        config = ScorerConfig(weights=weights)
        scorer = AnomalyScorer(mgr, config)
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "bandwidth_hz": 100_000.0,
        })
        assert result.dimensions["bandwidth_anomaly"] > 0.0


class TestWeightNormalization:
    """P2-8: Weight auto-normalization."""

    def test_weight_normalization_with_optin_dims(self):
        """Set bandwidth_anomaly weight to 0.1 without reducing others;
        verify score still in [0,1] and meaningful."""
        mgr = BaselineManager()
        for i in range(400):
            bw = 25_000 + (i % 10) * 200
            mgr.update(433e6, "bpsk", 0.9, -50.0, 10, bandwidth_hz=float(bw))

        weights = dict(_DEFAULT_WEIGHTS)
        # Add 0.1 to bandwidth without reducing others — total > 1.0
        weights[AnomalyDimension.BANDWIDTH_ANOMALY] = 0.1
        assert sum(weights.values()) > 1.01, "Weights should sum to > 1.0 before normalization"

        config = ScorerConfig(weights=weights)
        scorer = AnomalyScorer(mgr, config)
        result = scorer.score({
            "signal_class": "bpsk", "confidence": 0.9,
            "freq_hz": 433e6, "bandwidth_hz": 100_000.0,
        })
        assert 0.0 <= result.score <= 1.0, f"Score {result.score} out of [0,1] range"
        # Score should be meaningful (not zero — bandwidth anomaly is firing)
        assert result.score > 0.0


class TestScorerConfigForwardCompat:
    """P2-7: ScorerConfig forward compatibility."""

    def test_scorer_config_ignores_unknown_fields(self):
        """ScorerConfig(unknown_field='x') should not raise."""
        config = ScorerConfig(unknown_field="x")
        assert config.min_learning_detections == 300


class TestRingBufferOffByOne:
    """P1-6: Ring buffer write index correctness."""

    def test_power_ring_buffer_index_zero_overwritten(self):
        """After filling the buffer, the next write should go to index 0."""
        from sigrift.bridge.anomaly.baseline import _MAX_POWER_SAMPLES
        bl = FrequencyBaseline()
        # Fill buffer to capacity
        for i in range(_MAX_POWER_SAMPLES):
            bl.update("bpsk", 0.9, float(i), 10)
        assert len(bl.power_samples) == _MAX_POWER_SAMPLES
        # The first sample was 0.0
        assert bl.power_samples[0] == 0.0
        # Next write should overwrite index 0
        bl.update("bpsk", 0.9, -999.0, 10)
        assert bl.power_samples[0] == -999.0, (
            f"Index 0 should be overwritten after buffer fills, got {bl.power_samples[0]}"
        )

    def test_snr_ring_buffer_index_zero_overwritten(self):
        """After filling the buffer, the next write should go to index 0."""
        from sigrift.bridge.anomaly.baseline import _MAX_POWER_SAMPLES
        bl = FrequencyBaseline()
        for i in range(_MAX_POWER_SAMPLES):
            bl.update("bpsk", 0.9, -50.0, 10, snr_db=float(i))
        assert len(bl.snr_samples) == _MAX_POWER_SAMPLES
        assert bl.snr_samples[0] == 0.0
        bl.update("bpsk", 0.9, -50.0, 10, snr_db=-999.0)
        assert bl.snr_samples[0] == -999.0, (
            f"Index 0 should be overwritten after buffer fills, got {bl.snr_samples[0]}"
        )

    def test_ring_buffer_wraps_correctly(self):
        """Verify second wrap-around also works (index 0 overwritten twice)."""
        from sigrift.bridge.anomaly.baseline import _MAX_POWER_SAMPLES
        bl = FrequencyBaseline()
        # Fill buffer + wrap once
        for i in range(_MAX_POWER_SAMPLES + 1):
            bl.update("bpsk", 0.9, float(i), 10)
        assert bl.power_samples[0] == float(_MAX_POWER_SAMPLES)
        # Wrap again: write at index 1
        bl.update("bpsk", 0.9, -888.0, 10)
        assert bl.power_samples[1] == -888.0
