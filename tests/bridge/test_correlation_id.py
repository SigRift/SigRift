"""Tests for Sprint 8 correlation ID tracing (X-Correlation-ID header).

Verifies that:
  - Response includes X-Correlation-ID even when not sent in request
  - When X-Correlation-ID is sent, the same value is echoed back
  - Malicious correlation IDs are sanitized (alphanumeric, dash, underscore only)
  - Long correlation IDs are truncated to 64 characters
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Correlation ID generation
# ---------------------------------------------------------------------------


class TestCorrelationIDGeneration:
    """Response includes X-Correlation-ID even when not sent in request."""

    def test_response_has_correlation_id_without_sending(
        self, client: TestClient,
    ) -> None:
        """Every API response includes X-Correlation-ID header."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert "x-correlation-id" in resp.headers
        corr_id = resp.headers["x-correlation-id"]
        assert isinstance(corr_id, str)
        assert len(corr_id) > 0

    def test_generated_id_is_alphanumeric_hex(
        self, client: TestClient,
    ) -> None:
        """Auto-generated correlation ID is a hex string (from uuid4)."""
        resp = client.get("/api/health")
        corr_id = resp.headers["x-correlation-id"]
        # Should be alphanumeric (hex chars from uuid4().hex[:12])
        assert re.fullmatch(r"[a-f0-9]+", corr_id) is not None, f"Unexpected format: {corr_id}"

    def test_different_requests_get_different_ids(
        self, client: TestClient,
    ) -> None:
        """Each request gets a unique correlation ID."""
        ids = set()
        for _ in range(5):
            resp = client.get("/api/health")
            ids.add(resp.headers["x-correlation-id"])
        assert len(ids) == 5


# ---------------------------------------------------------------------------
# Echo-back
# ---------------------------------------------------------------------------


class TestCorrelationIDEcho:
    """When X-Correlation-ID is sent in request, same value is echoed in response."""

    def test_echo_simple_id(self, client: TestClient) -> None:
        """Simple alphanumeric correlation ID is echoed verbatim."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "abc123"},
        )
        assert resp.status_code == 200
        assert resp.headers["x-correlation-id"] == "abc123"

    def test_echo_uuid_format(self, client: TestClient) -> None:
        """UUID-like ID with dashes is echoed verbatim."""
        test_id = "550e8400-e29b-41d4-a716-446655440000"
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": test_id},
        )
        assert resp.headers["x-correlation-id"] == test_id

    def test_echo_with_underscores(self, client: TestClient) -> None:
        """ID with underscores is echoed verbatim."""
        test_id = "req_12345_node_01"
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": test_id},
        )
        assert resp.headers["x-correlation-id"] == test_id

    def test_echo_mixed_case(self, client: TestClient) -> None:
        """Mixed-case ID is preserved."""
        test_id = "MyRequest-ABC-123"
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": test_id},
        )
        assert resp.headers["x-correlation-id"] == test_id


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------


class TestCorrelationIDSanitization:
    """Malicious correlation IDs are sanitized (only alphanumeric, dash, underscore)."""

    def test_removes_spaces(self, client: TestClient) -> None:
        """Spaces are stripped from correlation ID."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "hello world"},
        )
        assert resp.headers["x-correlation-id"] == "helloworld"

    def test_removes_newlines(self, client: TestClient) -> None:
        r"""Newline characters are stripped (prevents header injection)."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "id\r\nX-Evil: injected"},
        )
        corr_id = resp.headers["x-correlation-id"]
        assert "\r" not in corr_id
        assert "\n" not in corr_id
        # Only safe chars remain
        assert re.fullmatch(r"[a-zA-Z0-9_\-]+", corr_id) is not None

    def test_removes_special_chars(self, client: TestClient) -> None:
        """Special characters like <, >, ;, etc. are removed."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "id<script>alert(1)</script>"},
        )
        corr_id = resp.headers["x-correlation-id"]
        assert "<" not in corr_id
        assert ">" not in corr_id
        assert "(" not in corr_id
        assert ")" not in corr_id
        # Should contain the safe parts
        assert re.fullmatch(r"[a-zA-Z0-9_\-]+", corr_id) is not None

    def test_removes_null_bytes(self, client: TestClient) -> None:
        """Null bytes are removed from correlation ID."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "test\x00id"},
        )
        corr_id = resp.headers["x-correlation-id"]
        assert "\x00" not in corr_id
        assert re.fullmatch(r"[a-zA-Z0-9_\-]+", corr_id) is not None

    def test_fully_malicious_id_generates_new(self, client: TestClient) -> None:
        """If sanitization removes ALL characters, a fresh ID is generated."""
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": "!!@@##$$%%"},
        )
        corr_id = resp.headers["x-correlation-id"]
        # Should fall back to a generated request_id
        assert isinstance(corr_id, str)
        assert len(corr_id) > 0
        assert re.fullmatch(r"[a-zA-Z0-9_\-]+", corr_id) is not None


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


class TestCorrelationIDTruncation:
    """Long correlation IDs are truncated to 64 characters."""

    def test_long_id_truncated_to_64(self, client: TestClient) -> None:
        """A correlation ID longer than 64 chars is truncated."""
        long_id = "a" * 100
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": long_id},
        )
        corr_id = resp.headers["x-correlation-id"]
        assert len(corr_id) <= 64

    def test_exactly_64_chars_preserved(self, client: TestClient) -> None:
        """A correlation ID of exactly 64 chars is not truncated."""
        exact_id = "b" * 64
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": exact_id},
        )
        assert resp.headers["x-correlation-id"] == exact_id

    def test_under_64_chars_preserved(self, client: TestClient) -> None:
        """A correlation ID under 64 chars is preserved as-is."""
        short_id = "c" * 30
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": short_id},
        )
        assert resp.headers["x-correlation-id"] == short_id

    def test_long_id_with_special_chars_truncated_then_sanitized(
        self, client: TestClient,
    ) -> None:
        """Truncation happens before sanitization, so result <= 64 chars."""
        # 80 chars, some invalid
        long_mixed = "valid-" + "!" * 20 + "a" * 60
        resp = client.get(
            "/api/health",
            headers={"X-Correlation-ID": long_mixed},
        )
        corr_id = resp.headers["x-correlation-id"]
        assert len(corr_id) <= 64
        assert re.fullmatch(r"[a-zA-Z0-9_\-]+", corr_id) is not None
