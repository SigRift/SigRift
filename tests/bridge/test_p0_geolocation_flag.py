"""Tests for P0-4: geolocation_enabled feature flag.

Verifies that:
  - All TDOA endpoints return 403 when the feature flag is disabled (default)
  - Endpoints work normally when the feature flag is enabled
  - TDOA read endpoints require ANALYST role (not VIEWER)
  - TDOA compute endpoint requires ANALYST role
"""

from __future__ import annotations

import pytest

pytest.importorskip(
    "sigrift.bridge.routers.tdoa",
    reason="TDOA router is enterprise-only and not shipped in community",
)

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager

import sigrift.bridge.routers.tdoa as tdoa_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict = {"role": role, "description": f"test {role}"}
    persistence.set_key_meta(key_id, meta)
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    """Create a viewer-role API key and return the raw key."""
    return _make_key_and_store(persistence, "viewer_key_tdoa", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    """Create an analyst-role API key and return the raw key."""
    return _make_key_and_store(persistence, "analyst_key_tdoa", role="analyst")


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    """TestClient authenticated with a viewer-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    """TestClient authenticated with an analyst-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


# ---------------------------------------------------------------------------
# TDOA endpoints (all under /api/tdoa)
# ---------------------------------------------------------------------------

TDOA_GET_ENDPOINTS = [
    "/api/tdoa/estimates",
    "/api/tdoa/estimates/fake-id-123",
    "/api/tdoa/heatmap",
]


# ---------------------------------------------------------------------------
# Test 1: TDOA disabled by default — all endpoints return 403
# ---------------------------------------------------------------------------


class TestTDOADisabledByDefault:
    """When GEOLOCATION_ENABLED is False (the default), all TDOA endpoints
    must return 403 Forbidden regardless of the caller's role."""

    def test_tdoa_disabled_by_default_get_endpoints(
        self, monkeypatch, client: TestClient,
    ):
        monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", False)
        for endpoint in TDOA_GET_ENDPOINTS:
            resp = client.get(endpoint)
            assert resp.status_code == 403, (
                f"{endpoint} should return 403 when geolocation is disabled, "
                f"got {resp.status_code}"
            )
            assert "BRIDGE_GEOLOCATION_ENABLED" in resp.json()["detail"]

    def test_tdoa_disabled_by_default_compute(
        self, monkeypatch, client: TestClient,
    ):
        monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", False)
        resp = client.post(
            "/api/tdoa/compute",
            json={"detection_ids": ["a", "b", "c"]},
        )
        assert resp.status_code == 403
        assert "BRIDGE_GEOLOCATION_ENABLED" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Test 2: TDOA enabled when flag is set — endpoints respond normally
# ---------------------------------------------------------------------------


class TestTDOAEnabledWhenFlagSet:
    """When GEOLOCATION_ENABLED is True, endpoints should NOT return 403
    from the feature gate (they may return other codes based on data)."""

    def test_tdoa_enabled_estimates(
        self, monkeypatch, client: TestClient,
    ):
        monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
        resp = client.get("/api/tdoa/estimates")
        # Should not be 403 from the feature gate
        assert resp.status_code == 200

    def test_tdoa_enabled_estimate_detail(
        self, monkeypatch, client: TestClient,
    ):
        monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
        resp = client.get("/api/tdoa/estimates/nonexistent")
        # 404 because the estimate doesn't exist, but NOT 403 from the gate
        assert resp.status_code == 404

    def test_tdoa_enabled_heatmap(
        self, monkeypatch, client: TestClient,
    ):
        monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
        resp = client.get("/api/tdoa/heatmap")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Test 3: TDOA estimates requires ANALYST (not VIEWER)
# ---------------------------------------------------------------------------


def test_tdoa_estimates_requires_analyst(
    monkeypatch, viewer_client: TestClient,
):
    """VIEWER role should get 403 on /estimates even when geolocation is enabled."""
    monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
    resp = viewer_client.get("/api/tdoa/estimates")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test 4: TDOA heatmap requires ANALYST (not VIEWER)
# ---------------------------------------------------------------------------


def test_tdoa_heatmap_requires_analyst(
    monkeypatch, viewer_client: TestClient,
):
    """VIEWER role should get 403 on /heatmap even when geolocation is enabled."""
    monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
    resp = viewer_client.get("/api/tdoa/heatmap")
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Test 5: TDOA compute requires ANALYST and works when enabled
# ---------------------------------------------------------------------------


def test_tdoa_compute_requires_analyst(
    monkeypatch, analyst_client: TestClient,
):
    """ANALYST role should be able to POST /compute when geolocation is enabled.

    The request will fail with 400 (not enough nodes) but it must NOT be
    rejected by RBAC or the feature gate.
    """
    monkeypatch.setattr(tdoa_module, "GEOLOCATION_ENABLED", True)
    resp = analyst_client.post(
        "/api/tdoa/compute",
        json={"detection_ids": ["det-1", "det-2", "det-3"]},
    )
    # 400 because there are no nodes with positions configured, but the
    # important thing is it's NOT 403 (i.e., RBAC and feature gate passed).
    assert resp.status_code == 400
    assert "nodes" in resp.json()["detail"].lower()
