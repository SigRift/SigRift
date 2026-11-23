"""Tests for the Isolation Forest (Tier 2) anomaly detector.

Tests cover:
  - Readiness before/after training
  - Training with sufficient samples
  - Scoring after training
  - Score range [0, 1]
  - Feature extraction (12-dim vector)
  - Save/load persistence
  - Graceful degradation without sklearn
  - Retrain
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.isolation_forest import (
    HAS_SKLEARN,
    IsolationForestDetector,
)


# Skip entire module if sklearn not available
pytestmark = pytest.mark.skipif(not HAS_SKLEARN, reason="scikit-learn not installed")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_normal_samples(n: int = 3000) -> list[list[float]]:
    """Generate n normal (non-anomalous) 12-dim feature vectors."""
    import numpy as np
    rng = np.random.RandomState(42)
    # Cluster around typical values
    samples = []
    for _ in range(n):
        samples.append([
            rng.uniform(0.7, 1.0),    # confidence
            rng.uniform(0.0, 0.3),    # entropy
            rng.uniform(0.2, 0.4),    # class_index
            rng.uniform(0.1, 0.3),    # family_index
            rng.uniform(0.0, 0.2),    # sf_index
            rng.uniform(0.3, 0.9),    # hour/24
            rng.uniform(0.0, 1.0),    # dow/7
            rng.uniform(0.1, 0.4),    # freq_mhz/3000
            rng.uniform(0.3, 0.7),    # power_norm
            rng.uniform(0.0, 0.3),    # tier1_score
            rng.uniform(0.5, 1.0),    # class_baseline_freq
            rng.uniform(0.0, 0.1),    # seconds_since_last
        ])
    return samples


def _make_anomalous_sample() -> list[float]:
    """Generate a clearly anomalous feature vector."""
    return [
        0.1,   # very low confidence
        0.95,  # very high entropy
        0.95,  # unusual class
        0.9,   # unusual family
        0.9,   # unusual super-family
        0.1,   # unusual hour
        0.5,   # typical day
        0.95,  # unusual frequency
        0.05,  # unusual power
        0.9,   # high tier1 score
        0.01,  # very rare class
        0.99,  # long time since last
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestReadiness:
    """Tests for is_ready and needs_training."""

    def test_not_ready_before_training(self) -> None:
        """Detector is not ready before training."""
        det = IsolationForestDetector(min_training_samples=100)
        assert not det.is_ready()

    def test_needs_training_when_enough_samples(self) -> None:
        """needs_training returns True when enough samples collected."""
        det = IsolationForestDetector(min_training_samples=10)
        for s in _make_normal_samples(10):
            det.add_sample(s)
        assert det.needs_training()

    def test_not_needs_training_when_few_samples(self) -> None:
        """needs_training returns False with insufficient samples."""
        det = IsolationForestDetector(min_training_samples=100)
        for s in _make_normal_samples(5):
            det.add_sample(s)
        assert not det.needs_training()


class TestTraining:
    """Tests for training the Isolation Forest."""

    def test_training_with_sufficient_samples(self) -> None:
        """Training succeeds with enough samples."""
        det = IsolationForestDetector(min_training_samples=100, n_estimators=10)
        for s in _make_normal_samples(200):
            det.add_sample(s)
        det.train()
        assert det.is_ready()

    def test_training_insufficient_samples_raises(self) -> None:
        """Training with too few samples raises RuntimeError."""
        det = IsolationForestDetector(min_training_samples=1000)
        for s in _make_normal_samples(10):
            det.add_sample(s)
        with pytest.raises(RuntimeError, match="Need"):
            det.train()


class TestScoring:
    """Tests for scoring after training."""

    @pytest.fixture
    def trained_detector(self) -> IsolationForestDetector:
        det = IsolationForestDetector(min_training_samples=100, n_estimators=20)
        for s in _make_normal_samples(500):
            det.add_sample(s)
        det.train()
        return det

    def test_scoring_after_training(self, trained_detector: IsolationForestDetector) -> None:
        """Scoring produces a float value after training."""
        normal = _make_normal_samples(1)[0]
        score = trained_detector.score(normal)
        assert isinstance(score, float)

    def test_score_range(self, trained_detector: IsolationForestDetector) -> None:
        """Score is always in [0, 1]."""
        for sample in _make_normal_samples(50):
            score = trained_detector.score(sample)
            assert 0.0 <= score <= 1.0, f"Score {score} out of range"

        anomalous = _make_anomalous_sample()
        score = trained_detector.score(anomalous)
        assert 0.0 <= score <= 1.0

    def test_anomalous_scores_higher(self, trained_detector: IsolationForestDetector) -> None:
        """Anomalous samples should generally score higher than normal ones."""
        normal_scores = [trained_detector.score(s) for s in _make_normal_samples(50)]
        anomalous_score = trained_detector.score(_make_anomalous_sample())

        avg_normal = sum(normal_scores) / len(normal_scores)
        # Anomalous should score higher than average normal
        assert anomalous_score > avg_normal

    def test_score_before_training_returns_zero(self) -> None:
        """Scoring before training returns 0.0."""
        det = IsolationForestDetector()
        score = det.score([0.5] * 12)
        assert score == 0.0


class TestFeatureExtraction:
    """Tests for extract_features."""

    def test_feature_extraction(self) -> None:
        """Feature extraction produces 11-dim vector (DS-R7: tier1 removed)."""
        det = IsolationForestDetector()
        detection = {
            "signal_class": "bpsk",
            "confidence": 0.95,
            "freq_hz": 433.92e6,
            "power_dbm": -80.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "family": "psk",
        }
        features = det.extract_features(detection)
        assert len(features) == 13  # P2-4: 11→13 with sin/cos pairs

    def test_feature_values_range(self) -> None:
        """All features should be in valid ranges (sin/cos in [-1,1], rest in [0,1])."""
        det = IsolationForestDetector()
        detection = {
            "signal_class": "qpsk",
            "confidence": 0.8,
            "freq_hz": 915e6,
            "power_dbm": -60.0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        tier1 = {"score": 0.3, "dimensions": {"rare_class": 0.2}}
        features = det.extract_features(detection, tier1)
        # Features 5-8 are sin/cos (range [-1, 1])
        for i, f in enumerate(features):
            if i in (5, 6, 7, 8):
                assert -1.0 <= f <= 1.0, f"Feature {i} = {f} out of [-1,1]"
            else:
                assert 0.0 <= f <= 1.0, f"Feature {i} = {f} out of [0,1]"

    def test_feature_with_class_probs(self) -> None:
        """Feature extraction handles class_probs for entropy."""
        det = IsolationForestDetector()
        detection = {
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433e6,
            "class_probs": {"bpsk": 0.9, "qpsk": 0.05, "noise": 0.05},
        }
        features = det.extract_features(detection)
        # entropy should be > 0 since distribution is not uniform
        assert features[1] > 0.0

    def test_feature_without_power(self) -> None:
        """Feature extraction handles missing power_dbm."""
        det = IsolationForestDetector()
        detection = {
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433e6,
        }
        features = det.extract_features(detection)
        assert features[10] == 0.5  # neutral default (index shifted by P2-4)


class TestSaveLoad:
    """Tests for save/load persistence."""

    def test_save_load(self, tmp_path: Path) -> None:
        """Model can be saved and loaded."""
        det = IsolationForestDetector(min_training_samples=100, n_estimators=10)
        for s in _make_normal_samples(200):
            det.add_sample(s)
        det.train()

        model_path = str(tmp_path / "if_model.pkl")
        det.save(model_path)

        # Load into new detector
        det2 = IsolationForestDetector()
        det2.load(model_path)
        assert det2.is_ready()

        # Scores should be similar
        sample = _make_normal_samples(1)[0]
        score1 = det.score(sample)
        score2 = det2.score(sample)
        assert abs(score1 - score2) < 1e-6

    def test_load_missing_file(self, tmp_path: Path) -> None:
        """Loading missing file does not crash."""
        det = IsolationForestDetector()
        det.load(str(tmp_path / "nonexistent.pkl"))
        assert not det.is_ready()

    def test_save_untrained_warns(self, tmp_path: Path) -> None:
        """Saving untrained model logs warning and does nothing."""
        det = IsolationForestDetector()
        model_path = str(tmp_path / "if_model.pkl")
        det.save(model_path)
        assert not Path(model_path).exists()


class TestRetrain:
    """Tests for retraining."""

    def test_retrain(self) -> None:
        """Retrain resets and retrains the model."""
        det = IsolationForestDetector(min_training_samples=100, n_estimators=10)
        for s in _make_normal_samples(200):
            det.add_sample(s)
        det.train()
        assert det.is_ready()

        # Retrain with new data
        new_samples = _make_normal_samples(200)
        det.retrain(new_samples)
        assert det.is_ready()


class TestGracefulDegradation:
    """Tests for graceful degradation without sklearn."""

    def test_graceful_without_sklearn(self) -> None:
        """When sklearn is not available, detector degrades gracefully."""
        import sigrift.bridge.anomaly.isolation_forest as mod
        original = mod.HAS_SKLEARN
        try:
            mod.HAS_SKLEARN = False
            det = IsolationForestDetector()
            assert not det.is_ready()
            assert det.score([0.5] * 12) == 0.0
        finally:
            mod.HAS_SKLEARN = original
