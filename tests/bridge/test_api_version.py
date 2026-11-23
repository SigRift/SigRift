"""Tests for API versioning infrastructure."""

from __future__ import annotations

from fastapi.testclient import TestClient

from sigrift.bridge import (
    API_VERSION,
    SUPPORTED_API_VERSIONS,
    WS_PROTOCOL,
    __version__,
)


# ---------------------------------------------------------------------------
# X-API-Version response header
# ---------------------------------------------------------------------------


class TestAPIVersionHeader:
    """X-API-Version header is set on API responses."""

    def test_health_has_version_header(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.headers["X-API-Version"] == API_VERSION

    def test_status_has_version_header(self, client: TestClient) -> None:
        resp = client.get("/api/status")
        assert resp.headers["X-API-Version"] == API_VERSION

    def test_version_endpoint_has_version_header(self, client: TestClient) -> None:
        resp = client.get("/api/version")
        assert resp.headers["X-API-Version"] == API_VERSION


# ---------------------------------------------------------------------------
# Unsupported version rejection
# ---------------------------------------------------------------------------


class TestUnsupportedVersionRejection:
    """Requests with unsupported X-API-Version are rejected."""

    def test_unsupported_version_returns_400(self, client: TestClient) -> None:
        resp = client.get(
            "/api/health",
            headers={"X-API-Version": "99"},
        )
        assert resp.status_code == 400

    def test_supported_version_passes(self, client: TestClient) -> None:
        resp = client.get(
            "/api/health",
            headers={"X-API-Version": API_VERSION},
        )
        assert resp.status_code == 200

    def test_no_version_header_passes(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# GET /api/version discovery endpoint
# ---------------------------------------------------------------------------


class TestVersionEndpoint:
    """The /api/version endpoint returns version metadata without auth."""

    def test_returns_200_without_auth(self, bridge_app) -> None:
        """Version endpoint requires no authentication."""
        unauthenticated = TestClient(bridge_app)
        resp = unauthenticated.get("/api/version")
        assert resp.status_code == 200

    def test_response_structure(self, client: TestClient) -> None:
        resp = client.get("/api/version")
        data = resp.json()
        assert data["api_version"] == API_VERSION
        assert data["server_version"] == __version__
        assert data["ws_protocol"] == WS_PROTOCOL
        assert data["supported_versions"] == SUPPORTED_API_VERSIONS


# ---------------------------------------------------------------------------
# Health endpoint uses centralized version
# ---------------------------------------------------------------------------


class TestHealthVersion:
    """Health endpoint version matches the centralized constant."""

    def test_health_version_matches_constant(self, client: TestClient) -> None:
        resp = client.get("/api/health")
        assert resp.json()["version"] == __version__


# ---------------------------------------------------------------------------
# WebSocket subprotocol matches centralized constant
# ---------------------------------------------------------------------------


class TestWSProtocol:
    """WS_PROTOCOL constant is the expected value."""

    def test_ws_protocol_value(self) -> None:
        assert WS_PROTOCOL == "bridge-v1"
