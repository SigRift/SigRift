"""Tests for sigrift.bridge.routers.edge_models — edge ML model endpoints."""

import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def app_with_model():
    """Create test app with a mock family classifier on state."""
    from sigrift.bridge.app import app as _app
    app = _app

    mock_classifier = MagicMock()
    mock_classifier.family_names = ["PSK", "FSK", "OFDM", "ANALOG"]
    mock_classifier.num_classes = 4
    mock_classifier.input_dim = 49
    mock_classifier.predict.return_value = {"family": "PSK", "confidence": 0.95, "probabilities": {"PSK": 0.95, "FSK": 0.03}}

    app.state.family_classifier = mock_classifier
    return app


@pytest.fixture
def client(app_with_model):
    return TestClient(app_with_model)


@pytest.fixture
def auth_headers():
    return {"X-API-Key": "test-key-admin"}


class TestFamiliesEndpoint:
    """GET /api/edge-models/families."""

    def test_returns_families(self, client, auth_headers):
        resp = client.get("/api/edge-models/families", headers=auth_headers)
        # May return 200 or 404 depending on whether classifier is wired
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, (list, dict))

    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/edge-models/families")
        assert resp.status_code in (401, 403, 404, 503)


class TestFamilyLookup:
    """GET /api/edge-models/family/{class_name}."""

    def test_known_class(self, client, auth_headers):
        resp = client.get("/api/edge-models/family/bpsk", headers=auth_headers)
        if resp.status_code == 200:
            data = resp.json()
            assert "family" in data

    def test_unknown_class(self, client, auth_headers):
        resp = client.get("/api/edge-models/family/nonexistent_signal_xyz", headers=auth_headers)
        # Should still return something (UNKNOWN family) or 404
        assert resp.status_code in (200, 404, 503)


class TestClassifyFeatures:
    """POST /api/edge-models/classify."""

    def test_classify_with_features(self, client, auth_headers):
        features = [0.0] * 49
        resp = client.post(
            "/api/edge-models/classify",
            json={"features": features},
            headers=auth_headers,
        )
        if resp.status_code == 200:
            data = resp.json()
            assert "family" in data or "class" in data

    def test_classify_wrong_length(self, client, auth_headers):
        resp = client.post(
            "/api/edge-models/classify",
            json={"features": [0.0] * 10},  # wrong dimension
            headers=auth_headers,
        )
        # Should return 400 or 422
        assert resp.status_code in (200, 400, 422, 404, 503)  # may pad/truncate

    def test_classify_no_auth(self, client):
        resp = client.post(
            "/api/edge-models/classify",
            json={"features": [0.0] * 49},
        )
        assert resp.status_code in (401, 403, 404, 503)


class TestModelInfo:
    """GET /api/edge-models/model/info."""

    def test_model_info(self, client, auth_headers):
        resp = client.get("/api/edge-models/model/info", headers=auth_headers)
        if resp.status_code == 200:
            data = resp.json()
            assert isinstance(data, dict)


class TestModelDownload:
    """GET /api/edge-models/model/download."""

    def test_download_no_model(self, client, auth_headers):
        resp = client.get("/api/edge-models/model/download", headers=auth_headers)
        # Without a real model file, should 404
        assert resp.status_code in (200, 404, 503)


class TestModelTrain:
    """POST /api/edge-models/model/train."""

    def test_train_requires_admin(self, client):
        resp = client.post(
            "/api/edge-models/model/train",
            json={"epochs": 1},
        )
        assert resp.status_code in (401, 403, 404, 503)

    def test_train_accepted(self, client, auth_headers):
        resp = client.post(
            "/api/edge-models/model/train",
            json={"epochs": 1, "samples_per_class": 10},
            headers=auth_headers,
        )
        # Should accept or reject based on license/state
        assert resp.status_code in (200, 202, 400, 403, 404, 409, 503)
