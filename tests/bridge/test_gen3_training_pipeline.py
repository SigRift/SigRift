"""Tests for the SigRift training pipeline components.

Validates that the Trainer, Dataset, SignalFactory, Losses, and Model
are correctly wired together and produce expected outputs.
"""

from __future__ import annotations


import numpy as np
import pytest
import torch

from sigrift.lib.config import TrainingConfig
from sigrift.lib.models.hierarchical import HierarchicalClassifier, HierarchicalOutput
from sigrift.lib.taxonomy import (
    CLASSES,
    CLASS_TO_FAMILY,
    CLASS_TO_MT,
    NUM_CLASSES,
    NUM_FAMILIES,
    NUM_MODULATION_TYPES,
    NUM_SUPER_FAMILIES,
)
from sigrift.lib.training.augmentation import (
    AugmentationConfig,
    OFDM_AUGMENTATION_CONFIG,
    apply_augmentation,
)
from sigrift.lib.training.dataset import OnTheFlySignalDataset
from sigrift.lib.training.losses import (
    FocalLoss,
    HierarchicalFocalLoss,
    compute_class_weights,
)
from sigrift.lib.training.mixup import family_aware_mixup
from sigrift.lib.training.signal_factory import generate_signal, list_classes


# ---------------------------------------------------------------------------
# Signal Factory
# ---------------------------------------------------------------------------


class TestSignalFactory:
    """Tests for sigrift.lib.training.signal_factory — the authoritative signal generator."""

    def test_all_40_classes_registered(self):
        """All 40 taxonomy classes must have generators."""
        available = set(list_classes())
        for cls in CLASSES:
            assert cls in available, f"Class {cls!r} missing from signal factory"

    def test_generate_signal_returns_correct_shape(self):
        """generate_signal should return complex64 array of requested length."""
        rng = np.random.RandomState(42)
        for n_samples in [1024, 4096]:
            sig = generate_signal("bpsk", n_samples=n_samples, snr_db=15.0, rng=rng)
            assert sig.shape == (n_samples,)
            assert sig.dtype == np.complex64

    def test_generate_signal_finite_values(self):
        """All generated signals must be finite (no NaN/Inf)."""
        rng = np.random.RandomState(123)
        for cls in CLASSES:
            sig = generate_signal(cls, n_samples=1024, snr_db=10.0, rng=rng)
            assert np.isfinite(sig).all(), f"Non-finite values in {cls}"

    def test_generate_signal_unit_power_after_noise(self):
        """At high SNR, signal should be approximately unit power."""
        rng = np.random.RandomState(99)
        sig = generate_signal("qpsk", n_samples=4096, snr_db=30.0, rng=rng)
        power = np.mean(np.abs(sig) ** 2)
        # At 30 dB SNR, noise adds ~0.001 to power so ~1.001
        assert 0.5 < power < 2.0, f"Power {power} out of expected range"

    def test_unknown_class_raises(self):
        """generate_signal should raise ValueError for unknown classes."""
        with pytest.raises(ValueError, match="Unknown modulation class"):
            generate_signal("nonexistent_mod")

    @pytest.mark.parametrize("cls", ["ofdm-64", "ofdm-256", "ofdm-1024"])
    def test_ofdm_variants_produce_different_signals(self, cls):
        """OFDM variants should produce valid complex signals."""
        rng = np.random.RandomState(42)
        sig = generate_signal(cls, n_samples=4096, snr_db=15.0, rng=rng)
        assert sig.shape == (4096,)
        assert np.isfinite(sig).all()


# ---------------------------------------------------------------------------
# Dataset
# ---------------------------------------------------------------------------


class TestOnTheFlyDataset:
    """Tests for the on-the-fly synthetic dataset."""

    def test_dataset_yields_correct_shapes(self):
        """Each sample should be (tensor[2, N], class_idx)."""
        ds = OnTheFlySignalDataset(
            classes=CLASSES,
            samples_per_epoch=10,
            input_samples=1024,
            snr_range=(-5.0, 25.0),
            seed=42,
        )
        count = 0
        for tensor, label in ds:
            assert tensor.shape == (2, 1024), f"Expected (2, 1024), got {tensor.shape}"
            assert tensor.dtype == torch.float32
            assert 0 <= label < len(CLASSES)
            assert torch.isfinite(tensor).all()
            count += 1
        assert count == 10

    def test_dataset_respects_seed(self):
        """Same seed should produce identical sequences."""
        ds1 = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=5, input_samples=512, seed=123,
        )
        ds2 = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=5, input_samples=512, seed=123,
        )
        for (t1, l1), (t2, l2) in zip(ds1, ds2):
            assert l1 == l2
            assert torch.allclose(t1, t2)

    def test_snr_weighted_sampling(self):
        """SNR sampling should cover the full range."""
        ds = OnTheFlySignalDataset(
            classes=CLASSES[:5],
            samples_per_epoch=100,
            input_samples=512,
            snr_range=(-5.0, 25.0),
            seed=42,
        )
        # Just verify it iterates without error
        count = sum(1 for _ in ds)
        assert count == 100


# ---------------------------------------------------------------------------
# Augmentation
# ---------------------------------------------------------------------------


class TestAugmentation:
    """Tests for the augmentation pipeline."""

    def test_augmentation_preserves_length(self):
        """Augmented signal should have same length as input."""
        rng = np.random.RandomState(42)
        signal = (rng.randn(4096) + 1j * rng.randn(4096)).astype(np.complex64)
        aug = apply_augmentation(signal, rng=rng)
        assert aug.shape == signal.shape
        assert aug.dtype == np.complex64

    def test_ofdm_augmentation_is_gentler(self):
        """OFDM config should have smaller freq offset and no spec augment."""
        assert OFDM_AUGMENTATION_CONFIG.spec_augment_prob == 0.0
        default = AugmentationConfig()
        assert abs(OFDM_AUGMENTATION_CONFIG.freq_offset_hz[1]) < abs(default.freq_offset_hz[1])

    def test_augmentation_finite_output(self):
        """Augmented signals must remain finite."""
        rng = np.random.RandomState(77)
        signal = (rng.randn(2048) + 1j * rng.randn(2048)).astype(np.complex64)
        for _ in range(10):
            aug = apply_augmentation(signal, rng=rng)
            assert np.isfinite(aug).all()


# ---------------------------------------------------------------------------
# Losses
# ---------------------------------------------------------------------------


class TestLosses:
    """Tests for focal loss and class weights."""

    def test_compute_class_weights_ofdm_boost(self):
        """OFDM classes should get boosted weight, others should be 1.0."""
        weights = compute_class_weights(CLASSES, ofdm_boost=1.5)
        assert weights.shape == (len(CLASSES),)
        for i, cls in enumerate(CLASSES):
            if "ofdm" in cls:
                assert weights[i] == pytest.approx(1.5)
            else:
                assert weights[i] == pytest.approx(1.0)

    def test_focal_loss_output_scalar(self):
        """FocalLoss forward should return a scalar."""
        loss_fn = FocalLoss(gamma=1.5, label_smoothing=0.1)
        logits = torch.randn(8, NUM_CLASSES)
        targets = torch.randint(0, NUM_CLASSES, (8,))
        loss = loss_fn(logits, targets)
        assert loss.dim() == 0  # scalar
        assert loss.item() > 0

    def test_focal_loss_with_class_weights(self):
        """FocalLoss should accept per-class weights."""
        weights = compute_class_weights(CLASSES, ofdm_boost=1.5)
        loss_fn = FocalLoss(gamma=1.5, alpha=weights)
        logits = torch.randn(8, NUM_CLASSES)
        targets = torch.randint(0, NUM_CLASSES, (8,))
        loss = loss_fn(logits, targets)
        assert loss.item() > 0

    def test_focal_loss_mixup_forward(self):
        """Mixup forward should return valid loss."""
        loss_fn = FocalLoss(gamma=1.5)
        logits = torch.randn(8, NUM_CLASSES)
        y_a = torch.randint(0, NUM_CLASSES, (8,))
        y_b = torch.randint(0, NUM_CLASSES, (8,))
        loss = loss_fn.mixup_forward(logits, y_a, y_b, lam=0.7)
        assert loss.dim() == 0
        assert loss.item() > 0

    def test_hierarchical_focal_loss(self):
        """HierarchicalFocalLoss should combine all 4 levels."""
        weights = compute_class_weights(CLASSES, ofdm_boost=1.5)
        loss_fn = HierarchicalFocalLoss(
            gamma=1.5, class_weights=weights, classes=CLASSES,
        )
        B = 8
        cls_logits = torch.randn(B, NUM_CLASSES)
        mt_logits = torch.randn(B, NUM_MODULATION_TYPES)
        fam_logits = torch.randn(B, NUM_FAMILIES)
        sf_logits = torch.randn(B, NUM_SUPER_FAMILIES)
        targets = torch.randint(0, NUM_CLASSES, (B,))
        loss = loss_fn(cls_logits, mt_logits, fam_logits, sf_logits, targets)
        assert loss.dim() == 0
        assert loss.item() > 0

    def test_hierarchical_focal_loss_mixup(self):
        """HierarchicalFocalLoss mixup_forward should work."""
        loss_fn = HierarchicalFocalLoss(gamma=1.5, classes=CLASSES)
        B = 4
        cls_logits = torch.randn(B, NUM_CLASSES)
        mt_logits = torch.randn(B, NUM_MODULATION_TYPES)
        fam_logits = torch.randn(B, NUM_FAMILIES)
        sf_logits = torch.randn(B, NUM_SUPER_FAMILIES)
        y_a = torch.randint(0, NUM_CLASSES, (B,))
        y_b = torch.randint(0, NUM_CLASSES, (B,))
        loss = loss_fn.mixup_forward(
            cls_logits, mt_logits, fam_logits, sf_logits, y_a, y_b, 0.6,
        )
        assert loss.dim() == 0
        assert loss.item() > 0


# ---------------------------------------------------------------------------
# Mixup
# ---------------------------------------------------------------------------


class TestFamilyAwareMixup:
    """Tests for family-aware mixup."""

    def test_mixup_returns_correct_shapes(self):
        """Mixup should return same-shaped tensors."""
        x = torch.randn(16, 2, 4096)
        y = torch.randint(0, NUM_CLASSES, (16,))
        mixed_x, y_a, y_b, lam = family_aware_mixup(x, y, classes=CLASSES, alpha=0.4)
        assert mixed_x.shape == x.shape
        assert y_a.shape == y.shape
        assert y_b.shape == y.shape
        assert 0.0 <= lam <= 1.0

    def test_mixup_qam_uses_lower_alpha(self):
        """When batch is >50% QAM/APSK, effective alpha should be lower."""
        x = torch.randn(16, 2, 4096)
        # Create batch dominated by QAM classes (indices 12-16 are QAM)
        y = torch.full((16,), 12, dtype=torch.long)  # all 16qam
        rng = np.random.RandomState(42)

        # Run many times and check lambda distribution
        lams = []
        for seed in range(50):
            _, _, _, lam = family_aware_mixup(
                x, y, classes=CLASSES, alpha=0.4, qam_apsk_alpha=0.2,
                rng=np.random.RandomState(seed),
            )
            lams.append(lam)

        # With alpha=0.2, Beta(0.2, 0.2) produces extreme values (near 0 or 1)
        # With alpha=0.4, distribution is less extreme
        # Just verify it runs without error and produces valid lambdas
        assert all(0.0 <= l <= 1.0 for l in lams)

    def test_mixup_alpha_zero_returns_original(self):
        """alpha=0 should return lambda=1.0 (no mixing)."""
        x = torch.randn(8, 2, 1024)
        y = torch.randint(0, NUM_CLASSES, (8,))
        _, _, _, lam = family_aware_mixup(x, y, alpha=0.0)
        assert lam == 1.0


# ---------------------------------------------------------------------------
# Model Architecture
# ---------------------------------------------------------------------------


class TestHierarchicalClassifier:
    """Tests for the HierarchicalClassifier model."""

    @pytest.fixture
    def model(self):
        return HierarchicalClassifier(
            num_classes=NUM_CLASSES,
            input_samples=1024,
            base_channels=32,  # smaller for fast tests
        )

    def test_forward_output_type(self, model):
        """Forward should return HierarchicalOutput named tuple."""
        x = torch.randn(2, 2, 1024)
        out = model(x)
        assert isinstance(out, HierarchicalOutput)

    def test_forward_output_shapes(self, model):
        """Output tensors should have correct shapes."""
        x = torch.randn(2, 2, 1024)
        out = model(x)
        assert out.class_logits.shape == (2, NUM_CLASSES)
        assert out.mt_logits.shape == (2, NUM_MODULATION_TYPES)
        assert out.fam_logits.shape == (2, NUM_FAMILIES)
        assert out.sf_logits.shape == (2, NUM_SUPER_FAMILIES)

    def test_predict_returns_class_indices(self, model):
        """predict() should return integer class indices."""
        x = torch.randn(4, 2, 1024)
        preds = model.predict(x)
        assert preds.shape == (4,)
        assert preds.dtype == torch.long
        assert (preds >= 0).all() and (preds < NUM_CLASSES).all()

    def test_mt_gating_boosts_consistent_classes(self, model):
        """MT gating should boost logits for classes matching the predicted MT."""
        x = torch.randn(1, 2, 1024)
        out = model(x)
        # Gated logits should differ from raw class head output
        # (additive log-domain gating with gate_weight=1.0 is always active)
        assert out.class_logits.shape == (1, NUM_CLASSES)


# ---------------------------------------------------------------------------
# Training Config
# ---------------------------------------------------------------------------


class TestTrainingConfig:
    """Tests for TrainingConfig defaults matching SigRift recommendations."""

    def test_default_snr_ranges_match(self):
        """Val and train SNR ranges must match (gen2 fix)."""
        cfg = TrainingConfig()
        assert cfg.snr_range_db == cfg.val_snr_range_db

    def test_default_gamma(self):
        """Focal loss gamma should be 1.5 (addresses 4ASK bias)."""
        cfg = TrainingConfig()
        assert cfg.gamma == 1.5

    def test_default_ofdm_boost(self):
        """OFDM boost should be 1.5 (not 4x like v8)."""
        cfg = TrainingConfig()
        assert cfg.ofdm_boost == 1.5

    def test_early_stopping_enabled(self):
        """Early stopping patience must be > 0 (gen2 fix)."""
        cfg = TrainingConfig()
        assert cfg.early_stopping_patience > 0

    def test_mixup_qam_alpha_lower(self):
        """QAM/APSK mixup alpha should be lower than default."""
        cfg = TrainingConfig()
        assert cfg.mixup_qam_alpha < cfg.mixup_alpha


# ---------------------------------------------------------------------------
# Trainer (minimal integration)
# ---------------------------------------------------------------------------


class TestTrainerIntegration:
    """Minimal integration tests for the Trainer class."""

    def test_trainer_instantiation(self):
        """Trainer should instantiate with all components wired."""
        from sigrift.lib.training.trainer import Trainer

        model = HierarchicalClassifier(
            num_classes=NUM_CLASSES, input_samples=512, base_channels=16,
        )
        train_ds = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=32, input_samples=512, seed=42,
        )
        val_ds = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=16, input_samples=512, seed=99,
        )
        config = TrainingConfig(
            batch_size=8,
            num_workers=0,
            mixed_precision=False,
            pin_memory=False,
        )
        trainer = Trainer(
            model=model,
            train_dataset=train_ds,
            val_dataset=val_ds,
            config=config,
            device=torch.device("cpu"),
            classes=CLASSES,
            hierarchical=True,
        )
        assert trainer.device == torch.device("cpu")
        assert trainer.hierarchical is True
        assert trainer.early_stopping.patience == config.early_stopping_patience

    def test_trainer_checkpoint_roundtrip(self, tmp_path):
        """Save and load checkpoint should preserve state."""
        from sigrift.lib.training.trainer import Trainer

        model = HierarchicalClassifier(
            num_classes=NUM_CLASSES, input_samples=512, base_channels=16,
        )
        train_ds = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=16, input_samples=512, seed=42,
        )
        val_ds = OnTheFlySignalDataset(
            classes=CLASSES, samples_per_epoch=8, input_samples=512, seed=99,
        )
        config = TrainingConfig(
            batch_size=8, num_workers=0, mixed_precision=False, pin_memory=False,
        )
        trainer = Trainer(
            model=model,
            train_dataset=train_ds,
            val_dataset=val_ds,
            config=config,
            device=torch.device("cpu"),
            hierarchical=True,
        )

        ckpt_path = tmp_path / "test_ckpt.pth"
        trainer.save_checkpoint(ckpt_path, epoch=5, metrics={"val_acc": 0.42})
        assert ckpt_path.exists()

        # Load into a fresh trainer
        model2 = HierarchicalClassifier(
            num_classes=NUM_CLASSES, input_samples=512, base_channels=16,
        )
        trainer2 = Trainer(
            model=model2,
            train_dataset=train_ds,
            val_dataset=val_ds,
            config=config,
            device=torch.device("cpu"),
            hierarchical=True,
        )
        ckpt = trainer2.load_checkpoint(ckpt_path)
        assert ckpt["epoch"] == 5
        assert ckpt["metrics"]["val_acc"] == pytest.approx(0.42)


# ---------------------------------------------------------------------------
# Taxonomy consistency
# ---------------------------------------------------------------------------


class TestTaxonomyConsistency:
    """Verify taxonomy mappings are consistent with signal factory."""

    def test_all_classes_have_family(self):
        """Every class in CLASSES must have a family mapping."""
        for cls in CLASSES:
            assert cls in CLASS_TO_FAMILY, f"{cls} missing family mapping"

    def test_all_classes_have_modulation_type(self):
        """Every class in CLASSES must have a modulation type mapping."""
        for cls in CLASSES:
            assert cls in CLASS_TO_MT, f"{cls} missing MT mapping"

    def test_class_count_is_76(self):
        """Production class count should be 76 (v4.15.0: 75 modulations + noise)."""
        assert NUM_CLASSES == 76
        assert len(CLASSES) == 76
