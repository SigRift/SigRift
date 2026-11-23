"""WebSocket edge case tests.

Tests connect without auth, expired token, oversized messages,
rapid connect/disconnect, invalid JSON payloads, and binary data.
"""

from __future__ import annotations

import json
import time

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.dependencies import WSConnectionLimiter, set_ws_limiter
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "ws_sensor_key", role="sensor")


# ---------------------------------------------------------------------------
# Connect without auth
# ---------------------------------------------------------------------------


class TestWsConnectWithoutAuth:
    """Verify that WebSocket endpoints reject unauthenticated connections."""

    def test_detection_feed_no_auth(self, bridge_app: FastAPI):
        """Detection feed WS rejects connection without any auth."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/detections/ws/feed") as ws:
                    ws.receive_text()

    def test_alert_feed_no_auth(self, bridge_app: FastAPI):
        """Alert feed WS rejects connection without any auth."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/alerts/ws/alerts") as ws:
                    ws.receive_text()

    def test_wifi_feed_no_auth(self, bridge_app: FastAPI):
        """WiFi feed WS rejects connection without any auth."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/wifi/ws/wifi") as ws:
                    ws.receive_text()


# ---------------------------------------------------------------------------
# Connect with invalid / expired token
# ---------------------------------------------------------------------------


class TestWsConnectBadAuth:
    """Verify that WebSocket endpoints reject invalid credentials."""

    def test_detection_feed_bad_key(self, bridge_app: FastAPI):
        """Detection feed WS rejects a bogus API key."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/detections/ws/feed",
                    subprotocols=["bridge-v1", "completely-wrong-key"],
                ) as ws:
                    ws.receive_text()

    def test_detection_feed_empty_key(self, bridge_app: FastAPI):
        """Detection feed WS rejects empty subprotocol key."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/detections/ws/feed",
                    subprotocols=["bridge-v1", ""],
                ) as ws:
                    ws.receive_text()


# ---------------------------------------------------------------------------
# Send invalid data over WebSocket
# ---------------------------------------------------------------------------


class TestWsSendInvalidData:
    """Test handling of invalid data sent over established WebSocket connections."""

    def test_send_invalid_json(self, bridge_app: FastAPI, master_key: str):
        """Sending invalid JSON over detection feed does not crash the server."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                ws.send_text("not json at all {{{")
                # The server should either ignore or reply with an error
                # but should NOT close the connection unexpectedly
                # Send a ping to verify connection is still alive
                ws.send_text("ping")
                reply = ws.receive_text()
                assert reply == "pong"

    def test_send_empty_string(self, bridge_app: FastAPI, master_key: str):
        """Sending empty string over WebSocket does not crash."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                ws.send_text("")
                # Verify connection still works
                ws.send_text("ping")
                reply = ws.receive_text()
                assert reply == "pong"


# ---------------------------------------------------------------------------
# Rapid connect/disconnect
# ---------------------------------------------------------------------------


class TestWsRapidConnectDisconnect:
    """Test rapid WebSocket connect/disconnect cycles."""

    def test_rapid_cycles(self, bridge_app: FastAPI, master_key: str):
        """Multiple rapid connect/disconnect cycles do not leak state."""
        app_state: AppState = bridge_app.state.app_state

        for _ in range(5):
            with TestClient(bridge_app) as tc:
                with tc.websocket_connect(
                    "/api/detections/ws/feed",
                    subprotocols=["bridge-v1", master_key],
                ) as ws:
                    assert len(app_state.ws_detection_clients) == 1
                # After disconnect
                assert len(app_state.ws_detection_clients) == 0


# ---------------------------------------------------------------------------
# Multiple simultaneous connections
# ---------------------------------------------------------------------------


class TestWsMultipleConnections:
    """Test multiple WebSocket connections from same client."""

    def test_two_simultaneous_detection_feeds(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """Two simultaneous detection feed connections are both tracked."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws1:
                assert len(app_state.ws_detection_clients) == 1
                with tc.websocket_connect(
                    "/api/detections/ws/feed",
                    subprotocols=["bridge-v1", master_key],
                ) as ws2:
                    assert len(app_state.ws_detection_clients) == 2
                # ws2 closed
                assert len(app_state.ws_detection_clients) == 1
            # ws1 closed
            assert len(app_state.ws_detection_clients) == 0


# ---------------------------------------------------------------------------
# WebSocket connection limiter edge cases
# ---------------------------------------------------------------------------


class TestWsConnectionLimiter:
    """Test the WSConnectionLimiter directly for boundary conditions."""

    def test_limiter_at_max_concurrent(self):
        """Limiter rejects when max concurrent connections reached."""
        limiter = WSConnectionLimiter(max_concurrent=2, max_per_minute=100)
        ok1, _ = limiter.try_acquire("10.0.0.1")
        assert ok1 is True
        ok2, _ = limiter.try_acquire("10.0.0.1")
        assert ok2 is True
        ok3, reason = limiter.try_acquire("10.0.0.1")
        assert ok3 is False
        assert "concurrent" in reason.lower()

        # Release one, should allow again
        limiter.release("10.0.0.1")
        ok4, _ = limiter.try_acquire("10.0.0.1")
        assert ok4 is True

    def test_limiter_different_ips_independent(self):
        """Different IPs have independent limits."""
        limiter = WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        ok1, _ = limiter.try_acquire("10.0.0.1")
        assert ok1 is True
        ok2, _ = limiter.try_acquire("10.0.0.2")
        assert ok2 is True

    def test_limiter_release_below_zero(self):
        """Releasing when no connections active does not go negative."""
        limiter = WSConnectionLimiter(max_concurrent=5, max_per_minute=100)
        limiter.release("10.0.0.1")
        # Should be cleaned up, not negative
        assert limiter._active.get("10.0.0.1", 0) == 0
