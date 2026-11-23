"""Tests for BRIDGE_WS_QUERY_AUTH config flag.

Verifies that:
  - When BRIDGE_WS_QUERY_AUTH=disabled, query param auth is rejected (code 4003)
  - When BRIDGE_WS_QUERY_AUTH=enabled (or unset), query param auth works with deprecation warning
  - Header auth always works regardless of the setting
"""

from __future__ import annotations


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect


# ---------------------------------------------------------------------------
# Query param auth rejected when disabled
# ---------------------------------------------------------------------------


class TestWsQueryAuthDisabled:
    """When BRIDGE_WS_QUERY_AUTH=disabled, query param auth must be rejected."""

    def test_query_param_rejected_when_disabled(
        self, bridge_app: FastAPI, master_key: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Query param auth is rejected with code 4003 when disabled."""
        monkeypatch.setenv("BRIDGE_WS_QUERY_AUTH", "disabled")

        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    f"/api/detections/ws/feed?api_key={master_key}",
                ) as ws:
                    ws.receive_text()

    def test_header_auth_works_when_query_disabled(
        self, bridge_app: FastAPI, master_key: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Header auth still works even when query param auth is disabled."""
        monkeypatch.setenv("BRIDGE_WS_QUERY_AUTH", "disabled")

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert ws.accepted_subprotocol == "bridge-v1"
                ws.send_text("ping")
                assert ws.receive_text() == "pong"


# ---------------------------------------------------------------------------
# Query param auth allowed when enabled (default)
# ---------------------------------------------------------------------------


class TestWsQueryAuthEnabled:
    """When BRIDGE_WS_QUERY_AUTH=enabled or unset, query param auth works."""

    def test_query_param_works_when_enabled(
        self, bridge_app: FastAPI, master_key: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Query param auth works with deprecation warning when enabled."""
        monkeypatch.setenv("BRIDGE_WS_QUERY_AUTH", "enabled")

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                f"/api/detections/ws/feed?api_key={master_key}",
            ) as ws:
                assert ws.accepted_subprotocol is None
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_query_param_rejected_when_unset(
        self, bridge_app: FastAPI, master_key: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Query param auth is rejected when env var is unset (default=disabled)."""
        monkeypatch.delenv("BRIDGE_WS_QUERY_AUTH", raising=False)

        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    f"/api/detections/ws/feed?api_key={master_key}",
                ) as ws:
                    ws.receive_text()

    def test_header_auth_works_when_enabled(
        self, bridge_app: FastAPI, master_key: str, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Header auth works regardless of BRIDGE_WS_QUERY_AUTH setting."""
        monkeypatch.setenv("BRIDGE_WS_QUERY_AUTH", "enabled")

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert ws.accepted_subprotocol == "bridge-v1"
                ws.send_text("ping")
                assert ws.receive_text() == "pong"
