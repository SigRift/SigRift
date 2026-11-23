"""Query-key policy with real credential persistence and normal-app controls."""

import os
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.dependencies import require_api_key
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture
def key_client(persistence):
    """Exercise the public auth dependency with a real hashed, persisted key."""
    raw = generate_api_key()
    hashed, salt = hash_credential(raw)
    assert persistence.add_key(
        "test-key",
        hashed,
        salt,
        lookup_hash=compute_lookup_hash(raw),
        meta={"role": "admin", "tenant_id": "default"},
    )
    app = FastAPI()
    app.state.persistence = persistence
    app.state.detection_store = None  # Auth-only application uses its fixed default.

    @app.get("/test")
    async def endpoint(key_id: str = Depends(require_api_key)):
        return {"key_id": key_id}

    with TestClient(app) as client:
        yield client, raw


def test_query_param_deprecated_mode_returns_header(key_client, monkeypatch):
    """Deprecated query auth still validates the actual key and warns."""
    client, raw = key_client
    monkeypatch.setenv("BRIDGE_QUERY_PARAM_AUTH", "deprecated")
    resp = client.get("/test", params={"api_key": raw})
    assert resp.status_code == 200
    assert resp.json() == {"key_id": "test-key"}
    assert "X-API-Key" in resp.headers["X-Deprecated"]


def test_query_param_disabled_mode_rejects(key_client, monkeypatch):
    """Disabled query auth refuses even a valid persisted key."""
    client, raw = key_client
    monkeypatch.setenv("BRIDGE_QUERY_PARAM_AUTH", "disabled")
    resp = client.get("/test", params={"api_key": raw})
    assert resp.status_code == 400
    assert "disabled" in resp.json()["detail"].lower()


def test_query_param_enabled_mode_no_warning(key_client, monkeypatch):
    client, raw = key_client
    monkeypatch.setenv("BRIDGE_QUERY_PARAM_AUTH", "enabled")
    resp = client.get("/test", params={"api_key": raw})
    assert resp.status_code == 200
    assert resp.json() == {"key_id": "test-key"}
    assert "X-Deprecated" not in resp.headers


def test_header_auth_not_affected(key_client, monkeypatch):
    client, raw = key_client
    monkeypatch.setenv("BRIDGE_QUERY_PARAM_AUTH", "disabled")
    resp = client.get("/test", headers={"X-API-Key": raw})
    assert resp.status_code == 200
    assert resp.json() == {"key_id": "test-key"}
    assert "X-Deprecated" not in resp.headers


def test_default_mode_is_deprecated(key_client, monkeypatch):
    client, raw = key_client
    monkeypatch.delenv("BRIDGE_QUERY_PARAM_AUTH", raising=False)
    resp = client.get("/test", params={"api_key": raw})
    assert resp.status_code == 200
    assert "X-Deprecated" in resp.headers


def test_wrong_key_cannot_pass_real_lookup(key_client, monkeypatch):
    client, _ = key_client
    monkeypatch.setenv("BRIDGE_QUERY_PARAM_AUTH", "enabled")
    assert (
        client.get("/test", params={"api_key": generate_api_key()}).status_code == 401
    )


# ---------------------------------------------------------------------------
# Integration: query param deprecation through the real app
# ---------------------------------------------------------------------------


class TestQueryParamDeprecationIntegration:
    """Test query param deprecation through the full bridge_app stack."""

    def test_deprecated_mode_header_on_real_endpoint(
        self,
        client: TestClient,
        master_key: str,
    ):
        """Real endpoint returns X-Deprecated header for query param auth."""
        plain = TestClient(client.app)
        with patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "deprecated"}):
            resp = plain.get(f"/api/health?api_key={master_key}")
        assert resp.status_code == 200
        assert "X-Deprecated" in resp.headers

    def test_disabled_mode_rejects_on_real_endpoint(
        self,
        client: TestClient,
        master_key: str,
    ):
        """Real endpoint rejects query param auth when disabled."""
        plain = TestClient(client.app)
        with patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "disabled"}):
            resp = plain.get(f"/api/health?api_key={master_key}")
        assert resp.status_code == 400

    def test_header_auth_unaffected_when_disabled(
        self,
        client: TestClient,
        master_key: str,
    ):
        """Header auth works fine even when query param is disabled."""
        with patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "disabled"}):
            resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "X-Deprecated" not in resp.headers

    def test_enabled_mode_silent_on_real_endpoint(
        self,
        client: TestClient,
        master_key: str,
    ):
        """Real endpoint allows query param silently when enabled."""
        plain = TestClient(client.app)
        with patch.dict(os.environ, {"BRIDGE_QUERY_PARAM_AUTH": "enabled"}):
            resp = plain.get(f"/api/health?api_key={master_key}")
        assert resp.status_code == 200
        assert "X-Deprecated" not in resp.headers
