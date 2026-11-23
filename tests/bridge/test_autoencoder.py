"""Tests for the Autoencoder (Tier 3) anomaly detector.

Tests cover:
  - Model building
  - Training
  - Scoring
  - Score range
  - Threshold update
  - Anomaly detection
  - Save/load persistence
  - Graceful degradation without torch
"""

from __future__ import annotations

from pathlib import Path

import pytest

from sigrift.bridge.anomaly.autoencoder import AnomalyAutoencoder, HAS_TORCH

pytestmark = [
    # Skip entire module if torch not available
    pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed"),
    # Every test here trains or scores a real torch model. ~seconds on
    # an idle machine, but the global 30 s pytest-timeout flakes under
    # shard contention on the shared self-hosted runner — and torch
    # 2.7's heavier first-use init pushed even fixture setup over the
    # line (dependabot #131). Per-test hangs still die at 120 s.
    pytest.mark.timeout(120),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_normal_data(n: int = 500, dim: int = 32) -> "numpy.ndarray":
    """Generate normal training data."""
    import numpy as np
    rng = np.random.RandomState(42)
    # Generate data clustered around 0.5 with small variance
    return rng.normal(0.5, 0.1, size=(n, dim)).clip(0, 1).astype(np.float32)


def _make_anomalous_data(n: int = 10, dim: int = 32) -> "numpy.ndarray":
    """Generate anomalous data (far from normal distribution)."""
    import numpy as np
    rng = np.random.RandomState(99)
    # Generate data far from the normal cluster
    return rng.uniform(0.8, 1.0, size=(n, dim)).astype(np.float32)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBuildModel:
    """Tests for model building."""

    def test_build_model(self) -> None:
        """Build creates a model."""
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        ae.build_model()
        assert ae._model is not None

    def test_not_ready_after_build(self) -> None:
        """Model is not ready right after building (not trained)."""
        ae = AnomalyAutoencoder(input_dim=32)
        ae.build_model()
        assert ae.is_ready() is False


class TestTraining:
    """Tests for autoencoder training."""

    def test_training(self) -> None:
        """Training succeeds and model becomes ready."""
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(200, 32)
        losses = ae.train_model(data, epochs=5, batch_size=64)
        assert ae.is_ready() is True
        assert len(losses) == 5

    def test_loss_decreases(self) -> None:
        """Training loss generally decreases over epochs."""
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(500, 32)
        losses = ae.train_model(data, epochs=20, lr=1e-3, batch_size=64)
        # Last loss should be less than first loss
        assert losses[-1] < losses[0]

    def test_threshold_set_after_training(self) -> None:
        """Threshold is automatically set after training."""
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(200, 32)
        ae.train_model(data, epochs=5)
        assert ae._threshold > 0.0


class TestScoring:
    """Tests for scoring."""

    @pytest.fixture
    def trained_ae(self) -> AnomalyAutoencoder:
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(500, 32)
        ae.train_model(data, epochs=20, batch_size=64)
        return ae

    def test_scoring(self, trained_ae: AnomalyAutoencoder) -> None:
        """Scoring produces a non-negative float."""
        sample = _make_normal_data(1, 32)[0]
        score = trained_ae.score(sample)
        assert isinstance(score, float)
        assert score >= 0.0

    def test_score_range(self, trained_ae: AnomalyAutoencoder) -> None:
        """Normal data should have lower scores than anomalous data."""
        normal_scores = [trained_ae.score(s) for s in _make_normal_data(50, 32)]
        anomalous_scores = [trained_ae.score(s) for s in _make_anomalous_data(10, 32)]

        avg_normal = sum(normal_scores) / len(normal_scores)
        avg_anomalous = sum(anomalous_scores) / len(anomalous_scores)
        # Anomalous data should have higher reconstruction error
        assert avg_anomalous > avg_normal

    def test_score_batch(self, trained_ae: AnomalyAutoencoder) -> None:
        """Batch scoring produces correct number of scores."""
        data = _make_normal_data(10, 32)
        scores = trained_ae.score_batch(data)
        assert len(scores) == 10
        assert all(s >= 0.0 for s in scores)

    def test_score_before_training_returns_zero(self) -> None:
        """Scoring before training returns 0.0."""
        ae = AnomalyAutoencoder(input_dim=32)
        import numpy as np
        sample = np.zeros(32, dtype=np.float32)
        assert ae.score(sample) == 0.0


class TestThreshold:
    """Tests for threshold update and anomaly detection."""

    @pytest.fixture
    def trained_ae(self) -> AnomalyAutoencoder:
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(500, 32)
        ae.train_model(data, epochs=20, batch_size=64)
        return ae

    def test_threshold_update(self, trained_ae: AnomalyAutoencoder) -> None:
        """update_threshold sets a new threshold."""
        normal_data = _make_normal_data(100, 32)
        scores = trained_ae.score_batch(normal_data)
        old_threshold = trained_ae._threshold
        trained_ae.update_threshold(scores)
        # Threshold should be set (may be same or different)
        assert trained_ae._threshold >= 0.0

    def test_anomaly_detection(self, trained_ae: AnomalyAutoencoder) -> None:
        """is_anomaly returns bool based on threshold."""
        normal = _make_normal_data(1, 32)[0]
        anomalous = _make_anomalous_data(1, 32)[0]

        # Normal data should not be anomalous (usually)
        normal_result = trained_ae.is_anomaly(normal)
        assert isinstance(normal_result, bool)

        # We can at least verify that anomalous data is more likely to trigger
        normal_score = trained_ae.score(normal)
        anomalous_score = trained_ae.score(anomalous)
        assert anomalous_score > normal_score


class TestSaveLoad:
    """Tests for save/load persistence."""

    def test_save_load(self, tmp_path: Path) -> None:
        """Model can be saved and loaded."""
        ae = AnomalyAutoencoder(input_dim=32, latent_dim=8, hidden_dim=16)
        data = _make_normal_data(200, 32)
        ae.train_model(data, epochs=5)

        model_path = str(tmp_path / "ae_model.pt")
        ae.save(model_path)

        # Load into new autoencoder
        ae2 = AnomalyAutoencoder()
        ae2.load(model_path)
        assert ae2.is_ready() is True
        assert ae2.input_dim == 32
        assert ae2.latent_dim == 8
        assert ae2.hidden_dim == 16

        # Scores should be similar
        sample = _make_normal_data(1, 32)[0]
        score1 = ae.score(sample)
        score2 = ae2.score(sample)
        assert abs(score1 - score2) < 1e-4

    def test_load_missing_file(self, tmp_path: Path) -> None:
        """Loading missing file does not crash."""
        ae = AnomalyAutoencoder()
        ae.load(str(tmp_path / "nonexistent.pt"))
        assert ae.is_ready() is False

    def test_save_untrained_warns(self, tmp_path: Path) -> None:
        """Saving untrained model does nothing."""
        ae = AnomalyAutoencoder()
        model_path = str(tmp_path / "ae_model.pt")
        ae.save(model_path)
        assert not Path(model_path).exists()


class TestGracefulDegradation:
    """Tests for graceful degradation without torch."""

    def test_graceful_without_torch(self) -> None:
        """When torch is not available, autoencoder degrades gracefully."""
        import sigrift.bridge.anomaly.autoencoder as mod
        original = mod.HAS_TORCH
        try:
            mod.HAS_TORCH = False
            ae = AnomalyAutoencoder()
            assert ae.is_ready() is False
            # score should return 0.0
            assert ae.score([0.5] * 32) == 0.0
        finally:
            mod.HAS_TORCH = original
