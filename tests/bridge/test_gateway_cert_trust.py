"""Tests for the bridge trusting gateway-asserted client-cert auth.

PKI Phase A: the Rust gateway terminates mTLS, verifies the client
certificate, and forwards the resolved identity + role as trust
headers. The bridge honours them only when the request provably came
through the gateway — ``x-rust-proxy`` must carry ``UC_PROXY_SECRET``.
A client cannot reach this path directly because the gateway strips
any client-supplied trust headers before proxying.
"""

from __future__ import annotations

import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from sigrift.bridge.ca import VALID_CERT_ROLES
from sigrift.bridge.dependencies import Role, _gateway_cert_auth

_SECRET = "test-proxy-secret-xyz"


def _gw_headers(
    role: str = "viewer",
    identity: str = "viewer-agent",
    proxy_secret: str = _SECRET,
) -> dict[str, str]:
    """The trust headers the Rust gateway sets for a cert-authed request."""
    return {
        "x-auth-method": "client-cert",
        "x-auth-role": role,
        "x-auth-key-id": identity,
        "x-rust-proxy": proxy_secret,
    }


def _request(headers: dict[str, str]) -> Request:
    """Build a minimal Starlette Request carrying *headers*."""
    raw = [(k.lower().encode(), v.encode()) for k, v in headers.items()]
    return Request({"type": "http", "method": "GET", "path": "/", "headers": raw})


# ---------------------------------------------------------------------------
# _gateway_cert_auth unit tests
# ---------------------------------------------------------------------------


class TestGatewayCertAuthHelper:
    def test_resolves_identity_and_role(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        result = _gateway_cert_auth(_request(_gw_headers("viewer")))
        assert result == ("viewer-agent", Role.VIEWER)

    def test_no_cert_method_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        # A plain API-key request has no x-auth-method — must fall through.
        assert _gateway_cert_auth(_request({"x-api-key": "abc"})) is None

    def test_wrong_proxy_secret_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        assert _gateway_cert_auth(_request(_gw_headers(proxy_secret="forged"))) is None

    def test_unset_proxy_secret_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("UC_PROXY_SECRET", raising=False)
        assert _gateway_cert_auth(_request(_gw_headers())) is None

    def test_default_proxy_secret_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The insecure built-in default must not enable the trust path.
        monkeypatch.setenv("UC_PROXY_SECRET", "uppercrust-internal")
        headers = _gw_headers(proxy_secret="uppercrust-internal")
        assert _gateway_cert_auth(_request(headers)) is None

    def test_unknown_role_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        assert _gateway_cert_auth(_request(_gw_headers("wizard"))) is None

    @pytest.mark.parametrize(
        "role", ["keymaster", "KEYMASTER", "KeyMaster", " keymaster "]
    )
    def test_keymaster_is_never_honoured(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
        role: str,
    ) -> None:
        # KEYMASTER is never delegated to a certificate (ca.VALID_CERT_ROLES).
        # The gateway refuses a registry entry carrying it; the bridge does
        # not rely on that alone.
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.dependencies"):
            assert _gateway_cert_auth(_request(_gw_headers(role))) is None
        assert "refusing role KEYMASTER" in caplog.text

    def test_honours_exactly_the_roles_the_ca_issues(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Every role the gateway may forward for a certificate, and no other.
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        honoured = set()
        for role in Role:
            result = _gateway_cert_auth(_request(_gw_headers(role.name.lower())))
            if result is not None:
                assert result == ("viewer-agent", role)
                honoured.add(role.name.lower())
        assert honoured == VALID_CERT_ROLES


# ---------------------------------------------------------------------------
# Route-level: gateway cert headers flow through require_api_key + RBAC
# ---------------------------------------------------------------------------


class TestGatewayCertTrustRoutes:
    def test_viewer_cert_reaches_viewer_endpoint(
        self, bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        client = TestClient(bridge_app)
        resp = client.get("/api/ca/certs", headers=_gw_headers("viewer"))
        assert resp.status_code == 200

    def test_sensor_cert_denied_viewer_endpoint(
        self, bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        client = TestClient(bridge_app)
        # Authenticated as sensor, but sensor < viewer — RBAC still applies.
        resp = client.get("/api/ca/certs", headers=_gw_headers("sensor"))
        assert resp.status_code == 403

    def test_keymaster_cert_assertion_is_not_authenticated(
        self, bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        client = TestClient(bridge_app)
        # Refused as a credential (401), not authenticated as KEYMASTER, even
        # with a valid x-rust-proxy.
        resp = client.get("/api/ca/certs", headers=_gw_headers("keymaster"))
        assert resp.status_code == 401

    def test_forged_trust_headers_without_secret_rejected(
        self, bridge_app: FastAPI, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        client = TestClient(bridge_app)
        resp = client.get("/api/ca/certs", headers=_gw_headers(proxy_secret="forged"))
        assert resp.status_code == 401

    def test_api_key_auth_still_works(
        self,
        bridge_app: FastAPI,
        master_key: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        # A plain API-key request (no cert headers) is unaffected.
        client = TestClient(bridge_app, headers={"X-API-Key": master_key})
        assert client.get("/api/ca/certs").status_code == 200
