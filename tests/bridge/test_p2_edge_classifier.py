"""Tests for Phase 2 Item 8: LightweightClassifier family classifier.

Tests cover:
- Family mapping (class -> family)
- Model architecture and forward pass
- Training pipeline
- ONNX export
- API endpoints
"""

from __future__ import annotations

import numpy as np
import pytest
import torch

from sigrift.lib.dsp.family_classifier import (
    SIGNAL_FAMILIES,
    FamilyTrainer,
    LightweightClassifier,
    get_family,
    get_family_index,
    get_family_names,
    load_family_classifier,
)


# ===========================================================================
# Family mapping tests
# ===========================================================================


class TestFamilyMapping:
    """Tests for the signal family mapping functions."""

    def test_all_classes_have_family(self):
        """Every class in list_classes() maps to a family."""
        from sigrift.lib.training.signal_factory import list_classes

        for cls_name in list_classes():
            family = get_family(cls_name)
            assert family in SIGNAL_FAMILIES, f"{cls_name} -> {family} not in families"

    def test_family_names_unique(self):
        """No duplicate family names."""
        names = get_family_names()
        assert len(names) == len(set(names))

    def test_get_family_bpsk(self):
        """'bpsk' maps to 'PSK'."""
        assert get_family("bpsk") == "PSK"

    def test_get_family_ofdm(self):
        """'ofdm-256' maps to 'OFDM'."""
        assert get_family("ofdm-256") == "OFDM"

    def test_get_family_unknown(self):
        """Unknown class raises KeyError."""
        with pytest.raises(KeyError):
            get_family("nonexistent_mod")

    def test_family_count(self):
        """16 families total."""
        assert len(get_family_names()) == 16

    def test_no_class_in_multiple_families(self):
        """Each class appears in exactly one family."""
        seen: dict[str, str] = {}
        for family, classes in SIGNAL_FAMILIES.items():
            for cls in classes:
                assert cls not in seen, f"{cls} in both {seen[cls]} and {family}"
                seen[cls] = family

    def test_get_family_index_range(self):
        """Family indices are in [0, n_families)."""
        names = get_family_names()
        for name in names:
            idx = get_family_index(name)
            assert 0 <= idx < len(names)

    def test_get_family_qam(self):
        """'64qam' maps to 'QAM'."""
        assert get_family("64qam") == "QAM"

    def test_get_family_lora(self):
        """'lora-css' maps to 'SPREAD_SPECTRUM'."""
        assert get_family("lora-css") == "SPREAD_SPECTRUM"

    def test_get_family_fm(self):
        """'fm' maps to 'ANALOG'."""
        assert get_family("fm") == "ANALOG"

    def test_get_family_ook(self):
        """'ook' maps to 'ASK'."""
        assert get_family("ook") == "ASK"


# ===========================================================================
# Model tests
# ===========================================================================


class TestLightweightClassifier:
    """Tests for the LightweightClassifier model."""

    def test_model_forward_shape(self):
        """[B, 54] -> [B, 16] logits."""
        model = LightweightClassifier()
        x = torch.randn(16, 54)
        logits = model(x)
        assert logits.shape == (16, 16)

    def test_model_output_valid(self):
        """Outputs sum to ~1 after softmax."""
        model = LightweightClassifier()
        x = torch.randn(4, 54)
        logits = model(x)
        probs = torch.softmax(logits, dim=-1)
        sums = probs.sum(dim=-1)
        assert torch.allclose(sums, torch.ones(4), atol=1e-5)

    def test_model_single_sample(self):
        """Batch size 1 works."""
        model = LightweightClassifier()
        x = torch.randn(1, 54)
        logits = model(x)
        assert logits.shape == (1, 16)

    def test_model_parameter_count(self):
        """<5000 parameters (lightweight)."""
        model = LightweightClassifier()
        param_count = sum(p.numel() for p in model.parameters())
        assert param_count < 5000, f"Model has {param_count} params, expected <5000"

    def test_predict_returns_family_and_confidence(self):
        """predict() returns (str, float) tuple."""
        model = LightweightClassifier()
        x = torch.randn(1, 54)
        family, confidence = model.predict(x)
        assert isinstance(family, str)
        assert isinstance(confidence, float)
        assert family in get_family_names()
        assert 0.0 <= confidence <= 1.0

    def test_predict_1d_input(self):
        """predict() works with 1D input tensor."""
        model = LightweightClassifier()
        x = torch.randn(54)
        family, confidence = model.predict(x)
        assert isinstance(family, str)
        assert 0.0 <= confidence <= 1.0

    def test_predict_batch(self):
        """Batch prediction works."""
        model = LightweightClassifier()
        x = torch.randn(8, 54)
        results = model.predict_batch(x)
        assert len(results) == 8
        for family, confidence in results:
            assert isinstance(family, str)
            assert family in get_family_names()
            assert 0.0 <= confidence <= 1.0

    def test_model_save_load(self, tmp_path):
        """Save and reload produces same predictions."""
        model = LightweightClassifier()
        x = torch.randn(4, 54)

        # Get predictions before save
        model.eval()
        with torch.no_grad():
            logits_before = model(x)

        # Save
        path = tmp_path / "test_model.pth"
        torch.save({
            "model_state_dict": model.state_dict(),
            "input_dim": model.input_dim,
            "hidden_dim": model.hidden_dim,
            "n_families": model.n_families,
            "family_names": get_family_names(),
        }, path)

        # Load
        loaded = load_family_classifier(path)
        with torch.no_grad():
            logits_after = loaded(x)

        assert torch.allclose(logits_before, logits_after, atol=1e-6)

    def test_model_custom_dims(self):
        """Custom input/hidden/output dimensions work."""
        model = LightweightClassifier(input_dim=32, hidden_dim=16, n_families=5)
        x = torch.randn(4, 32)
        logits = model(x)
        assert logits.shape == (4, 5)


# ===========================================================================
# Training tests
# ===========================================================================


class TestFamilyTrainer:
    """Tests for the FamilyTrainer training pipeline."""

    def test_prepare_data(self):
        """Generates data with correct family labels."""
        trainer = FamilyTrainer(epochs=1, batch_size=32)
        total = trainer.prepare_data(samples_per_class=2, input_samples=512)
        assert total > 0
        assert trainer._features is not None
        assert trainer._labels is not None
        assert trainer._features.shape[0] == total
        assert trainer._labels.shape[0] == total
        assert trainer._features.shape[1] == 54

        # Labels should be valid family indices
        n_families = len(get_family_names())
        assert trainer._labels.min() >= 0
        assert trainer._labels.max() < n_families

    def test_train_one_epoch(self):
        """Completes without error."""
        trainer = FamilyTrainer(epochs=1, batch_size=32)
        trainer.prepare_data(samples_per_class=4, input_samples=512)
        history = trainer.train(verbose=False)
        assert len(history) == 1
        assert isinstance(history[0]["loss"], float)
        assert history[0]["epoch"] == 1

    @pytest.mark.timeout(120)
    def test_train_loss_decreases(self):
        """Loss goes down over epochs.

        Five-epoch real-train on a small CNN — runs near the 30s
        default timeout under shared CI runner load and has been
        flaking on shard 3 with `Timeout (>30.0s)`. Same 120s budget
        as the long-running ML tests in test_performance.py.
        """
        trainer = FamilyTrainer(epochs=5, batch_size=32, lr=1e-2)
        trainer.prepare_data(samples_per_class=16, input_samples=512)
        history = trainer.train(verbose=False)
        assert len(history) == 5
        # First epoch loss should be higher than last
        assert history[0]["loss"] > history[-1]["loss"], (
            f"Loss did not decrease: {history[0]['loss']:.4f} -> {history[-1]['loss']:.4f}"
        )

    def test_evaluate_returns_accuracy(self):
        """Evaluation returns per-family accuracy."""
        trainer = FamilyTrainer(epochs=2, batch_size=32)
        trainer.prepare_data(samples_per_class=8, input_samples=512)
        trainer.train(verbose=False)
        results = trainer.evaluate(n_test=2)
        assert isinstance(results["overall_accuracy"], float)
        assert isinstance(results["per_family_accuracy"], dict)
        assert isinstance(results["confusion_matrix"], list)
        assert isinstance(results["family_names"], list)
        assert 0.0 <= results["overall_accuracy"] <= 1.0
        # Check per-family accuracy has all families
        for family in get_family_names():
            assert family in results["per_family_accuracy"]

    def test_train_without_prepare_raises(self):
        """Training without prepare_data raises RuntimeError."""
        trainer = FamilyTrainer(epochs=1)
        with pytest.raises(RuntimeError, match="prepare_data"):
            trainer.train()

    def test_export_onnx(self, tmp_path):
        """Creates valid ONNX file."""
        pytest.importorskip("onnx")
        trainer = FamilyTrainer(epochs=1, batch_size=32)
        trainer.prepare_data(samples_per_class=4, input_samples=512)
        trainer.train(verbose=False)
        onnx_path = trainer.export_onnx(tmp_path / "family.onnx")
        assert onnx_path.exists()
        assert onnx_path.stat().st_size > 0
        # Optional: validate with onnxruntime if available
        try:
            import onnxruntime as ort
            sess = ort.InferenceSession(str(onnx_path))
            input_name = sess.get_inputs()[0].name
            result = sess.run(
                None, {input_name: np.random.randn(1, 54).astype(np.float32)}
            )
            assert result[0].shape == (1, 16)
        except ImportError:
            pass  # onnxruntime not required

    def test_save_model(self, tmp_path):
        """Save creates a .pth file that can be loaded."""
        trainer = FamilyTrainer(epochs=1, batch_size=32)
        trainer.prepare_data(samples_per_class=4, input_samples=512)
        trainer.train(verbose=False)
        pth_path = trainer.save_model(tmp_path / "family.pth")
        assert pth_path.exists()
        assert pth_path.stat().st_size > 0

        # Load and verify
        loaded = load_family_classifier(pth_path)
        assert isinstance(loaded, LightweightClassifier)
        x = torch.randn(1, 54)
        family, conf = loaded.predict(x)
        assert family in get_family_names()


# ===========================================================================
# API tests
# ===========================================================================


class TestEdgeModelsAPI:
    """Tests for the /api/edge-models endpoints."""

    def test_list_families(self, client):
        """GET /families returns family definitions."""
        resp = client.get("/api/edge-models/families")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["families"], dict)
        assert isinstance(data["family_names"], list)
        assert data["total_families"] == 16
        assert "PSK" in data["families"]
        assert "bpsk" in data["families"]["PSK"]

    def test_get_family(self, client):
        """GET /family/bpsk returns 'psk'."""
        resp = client.get("/api/edge-models/family/bpsk")
        assert resp.status_code == 200
        data = resp.json()
        assert data["family"] == "PSK"
        assert data["class_name"] == "bpsk"

    def test_get_family_unknown(self, client):
        """GET /family/unknown_class returns 404."""
        resp = client.get("/api/edge-models/family/unknown_class")
        assert resp.status_code == 404

    def test_classify_no_model(self, client):
        """POST /classify returns 503 if no model loaded."""
        resp = client.post(
            "/api/edge-models/classify",
            json={"features": [0.1] * 54},
        )
        assert resp.status_code == 503

    def test_classify_features(self, client, bridge_app):
        """POST /classify returns family prediction when model is loaded."""
        # Load a model into app state
        model = LightweightClassifier()
        bridge_app.state.family_classifier = model

        resp = client.post(
            "/api/edge-models/classify",
            json={"features": [0.1] * 54},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["family"] in get_family_names()
        assert 0.0 <= data["confidence"] <= 1.0
        assert isinstance(data["all_families"], dict)

    def test_classify_wrong_dim(self, client, bridge_app):
        """POST /classify with wrong feature length returns 400."""
        bridge_app.state.family_classifier = LightweightClassifier()
        resp = client.post(
            "/api/edge-models/classify",
            json={"features": [0.1] * 32},  # wrong dim
        )
        assert resp.status_code == 400

    def test_model_info(self, client):
        """GET /model/info returns model metadata."""
        resp = client.get("/api/edge-models/model/info")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["loaded"], bool)
        assert isinstance(data["families"], list)
        assert isinstance(data["n_families"], int)

    def test_model_info_with_model(self, client, bridge_app):
        """GET /model/info with loaded model returns full metadata."""
        bridge_app.state.family_classifier = LightweightClassifier()
        resp = client.get("/api/edge-models/model/info")
        assert resp.status_code == 200
        data = resp.json()
        assert data["loaded"] is True
        assert data["param_count"] > 0
        assert data["input_dim"] == 54

    def test_model_download_requires_analyst(self, client, bridge_app, tmp_path, persistence, master_key):
        """VIEWER gets 403 on model download (requires ANALYST)."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        # Create a VIEWER key using the correct pattern
        viewer_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(viewer_key)
        persistence.set_key("viewer_test", hash_hex, salt)
        persistence.set_key_meta("viewer_test", {"role": "viewer", "description": "test viewer"})

        from fastapi.testclient import TestClient
        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )
        resp = viewer_client.get("/api/edge-models/model/download")
        assert resp.status_code in (403, 404)  # 403 if role blocked, 404 if no file

    def test_train_requires_admin(self, client, bridge_app, persistence, master_key):
        """Non-ADMIN gets 403 on training."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        viewer_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(viewer_key)
        persistence.set_key("viewer_train", hash_hex, salt)
        persistence.set_key_meta("viewer_train", {"role": "viewer", "description": "test viewer"})

        from fastapi.testclient import TestClient
        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )
        resp = viewer_client.post(
            "/api/edge-models/model/train",
            json={"epochs": 1, "samples_per_class": 2},
        )
        assert resp.status_code == 403

    def test_model_status(self, client):
        """GET /model/status returns status."""
        resp = client.get("/api/edge-models/model/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["status"], str)

    def test_classify_iq_no_model(self, client):
        """POST /classify/iq returns 503 if no model loaded."""
        resp = client.post(
            "/api/edge-models/classify/iq",
            json={"iq_real": [0.1] * 256, "iq_imag": [0.1] * 256},
        )
        assert resp.status_code == 503

    def test_classify_iq_with_model(self, client, bridge_app):
        """POST /classify/iq returns prediction when model loaded."""
        bridge_app.state.family_classifier = LightweightClassifier()
        resp = client.post(
            "/api/edge-models/classify/iq",
            json={"iq_real": [0.1] * 256, "iq_imag": [0.1] * 256},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["family"], str)
        assert isinstance(data["confidence"], float)
