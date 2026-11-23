"""Tests for _get_client_ip (trusted proxy handling) and X-Tenant-ID header rejection.

Covers:
  - _get_client_ip returns peer IP for direct connections
  - _get_client_ip ignores X-Forwarded-For from untrusted peers
  - _get_client_ip trusts X-Forwarded-For from trusted proxies
  - X-Tenant-ID header is ignored (tenant derived from key metadata only)
  - Requests without X-Tenant-ID pass through normally
"""

from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from sigrift.bridge.routers.auth import _get_client_ip


# ---------------------------------------------------------------------------
# _get_client_ip tests
# ---------------------------------------------------------------------------


def _make_request(
    *,
    client_host: str = "10.0.0.1",
    headers: dict[str, str] | None = None,
) -> Request:
    """Build a minimal mock Request with client info and headers."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "client": (client_host, 0),
    }
    request = Request(scope)
    return request


class TestGetClientIpFromPeer:
    def test_client_ip_from_peer(self):
        """Direct connection returns the TCP peer IP."""
        request = _make_request(client_host="192.168.1.50")
        assert _get_client_ip(request) == "192.168.1.50"

    def test_client_ip_from_peer_no_xff(self):
        """Peer IP returned when no X-Forwarded-For header is present."""
        request = _make_request(client_host="10.10.10.10")
        assert _get_client_ip(request) == "10.10.10.10"


class TestGetClientIpIgnoresXffWithoutTrustedProxy:
    def test_client_ip_ignores_xff_without_trusted_proxy(self):
        """X-Forwarded-For header is ignored when not from a trusted proxy."""
        request = _make_request(
            client_host="203.0.113.50",
            headers={"X-Forwarded-For": "10.0.0.1, 172.16.0.1"},
        )
        # 203.0.113.50 is not in the default trusted proxies (127.0.0.1, ::1)
        assert _get_client_ip(request) == "203.0.113.50"


class TestGetClientIpUsesXffFromTrustedProxy:
    def test_client_ip_uses_xff_from_trusted_proxy(self):
        """X-Forwarded-For header is trusted when connection is from localhost.

        It is read from the right: the trusted proxy appended the last hop
        (10.0.0.1, its own peer); everything left of it was sent by that
        peer and can be forged, so it must not be taken as the client.
        """
        request = _make_request(
            client_host="127.0.0.1",
            headers={"X-Forwarded-For": "198.51.100.42, 10.0.0.1"},
        )
        assert _get_client_ip(request) == "10.0.0.1"

    def test_client_ip_skips_trusted_hops_in_xff(self):
        """Hops added by trusted proxies are skipped, right to left."""
        request = _make_request(
            client_host="127.0.0.1",
            headers={"X-Forwarded-For": "198.51.100.42, ::1, 127.0.0.1"},
        )
        assert _get_client_ip(request) == "198.51.100.42"

    def test_client_ip_ignores_non_ip_xff(self):
        """A hop that is not an IP address is not used as the client IP."""
        request = _make_request(
            client_host="127.0.0.1",
            headers={"X-Forwarded-For": "evil<script>"},
        )
        assert _get_client_ip(request) == "127.0.0.1"

    def test_client_ip_uses_xff_from_ipv6_loopback(self):
        """X-Forwarded-For header is trusted from ::1 (IPv6 loopback)."""
        request = _make_request(
            client_host="::1",
            headers={"X-Forwarded-For": "203.0.113.99"},
        )
        assert _get_client_ip(request) == "203.0.113.99"


# ---------------------------------------------------------------------------
# X-Tenant-ID header rejection tests
#
# The SigRift fix (FIX-006) removed the X-Tenant-ID header parameter from
# get_tenant_id(). Tenant is now derived exclusively from
# request.state.key_tenant. These tests verify that sending an
# X-Tenant-ID header does NOT change the resolved tenant.
# ---------------------------------------------------------------------------


class TestTenantHeaderRejected:
    def test_tenant_header_rejected(self, client: TestClient):
        """Request with X-Tenant-ID header does not override tenant context.

        The health endpoint returns 200 regardless, and the header is
        silently ignored — tenant resolution uses key metadata only.
        """
        resp = client.get(
            "/api/health",
            headers={"X-Tenant-ID": "attacker-tenant"},
        )
        # The request should succeed (header is ignored, not rejected with 400)
        assert resp.status_code == 200

    def test_tenant_header_does_not_change_tenant(
        self, bridge_app: FastAPI, master_key: str
    ):
        """Sending X-Tenant-ID header must not change the resolved tenant.

        We add a test endpoint that returns the tenant and verify the header
        has no effect.
        """
        from sigrift.bridge.dependencies import get_tenant_id, require_api_key

        @bridge_app.get("/test/tenant")
        async def _get_tenant(
            request: Request,
            key_id: str = Depends(require_api_key),
            tenant: str = Depends(get_tenant_id),
        ):
            return {"tenant": tenant}

        test_client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key},
        )

        # Without the attack header
        resp_normal = test_client.get("/test/tenant")
        assert resp_normal.status_code == 200
        normal_tenant = resp_normal.json()["tenant"]

        # With the attack header — tenant must be the same
        resp_attack = test_client.get(
            "/test/tenant",
            headers={"X-Tenant-ID": "victim-tenant"},
        )
        assert resp_attack.status_code == 200
        assert resp_attack.json()["tenant"] == normal_tenant


class TestRequestWithoutTenantHeaderSucceeds:
    def test_request_without_tenant_header_succeeds(self, client: TestClient):
        """Normal request without X-Tenant-ID passes through fine."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
