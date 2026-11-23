"""Tests for WebSocket broadcast functionality.

Tests cover:
  - Detection feed WS connect with valid auth
  - Detection feed WS rejection without auth
  - Detection feed WS ping/pong
  - Anomaly WS connect with valid auth
  - Detection broadcast delivery via WS
  - Anomaly broadcast delivery via WS
  - Client cleanup on disconnect
  - Multiple WS clients receiving broadcasts
  - Alert WS connect with valid auth
  - Alert WS rejection without auth
  - Alert broadcast delivery via WS
  - Status WS connect with valid auth
  - Status WS rejection without auth
  - Status WS sends snapshot on connect
  - WiFi WS connect with valid auth
  - WiFi WS rejection without auth
  - WiFi broadcast delivery via WS
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.bridge.dependencies import WSConnectionLimiter, set_ws_limiter
from sigrift.bridge.routers.alerts import _broadcast_alert
from sigrift.bridge.routers.detections import _broadcast_anomalies, _broadcast_detections
from sigrift.bridge.routers.wifi import _broadcast_wifi
from sigrift.bridge.state import AppState

# ---------------------------------------------------------------------------
# 1. Detection feed WS connect with valid auth
# ---------------------------------------------------------------------------

class TestWsFeedConnectAuth:
    """Test that a WebSocket client can connect to /ws/feed with a valid api_key."""

    def test_ws_feed_connect_auth_header(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to detection feed WS with Sec-WebSocket-Protocol header; verify accepted."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                # Connection accepted -- client should be tracked
                assert len(app_state.ws_detection_clients) == 1
                # Server should accept with bridge-v1 subprotocol
                assert ws.accepted_subprotocol == "bridge-v1"

            # After context manager exit, client should be cleaned up
            assert len(app_state.ws_detection_clients) == 0

    def test_ws_feed_connect_auth_query_param_deprecated(
        self, bridge_app: FastAPI, master_key: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Connect to detection feed WS with query param (deprecated); verify accepted with warning."""
        # Query param auth is disabled by default; explicitly enable for this test
        monkeypatch.setenv("BRIDGE_WS_QUERY_AUTH", "enabled")
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                f"/api/detections/ws/feed?api_key={master_key}",
            ) as ws:
                # Connection accepted -- client should be tracked
                assert len(app_state.ws_detection_clients) == 1
                # No subprotocol when using query param
                assert ws.accepted_subprotocol is None

            # After context manager exit, client should be cleaned up
            assert len(app_state.ws_detection_clients) == 0

# ---------------------------------------------------------------------------
# 2. Detection feed WS rejection without auth
# ---------------------------------------------------------------------------

class TestWsFeedNoAuthRejected:
    """Test that connecting without api_key is rejected."""

    def test_ws_feed_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to detection feed WS without api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            # Starlette TestClient raises an exception on WS handshake failure
            # when the server closes before accept().  The require_ws_auth
            # dependency closes with code 4001 if no api_key is provided.
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/detections/ws/feed") as ws:
                    # Should not reach here
                    ws.receive_text()

    def test_ws_feed_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """Connect with an invalid api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/detections/ws/feed?api_key=totally-wrong-key",
                ) as ws:
                    ws.receive_text()

# ---------------------------------------------------------------------------
# 3. Detection feed WS ping/pong
# ---------------------------------------------------------------------------

class TestWsFeedPingPong:
    """Test the in-protocol ping/pong on the detection feed WS."""

    def test_ws_feed_ping_pong(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Send 'ping' text frame, receive 'pong' reply."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                ws.send_text("ping")
                reply = ws.receive_text()
                assert reply == "pong"

# ---------------------------------------------------------------------------
# 4. Anomaly WS connect with valid auth
# ---------------------------------------------------------------------------

class TestWsAnomalyConnect:
    """Test that a WebSocket client can connect to /ws/anomalies."""

    def test_ws_anomaly_connect(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to anomaly WS with valid api_key; verify tracked."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/anomalies",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_anomaly_clients) == 1
                assert ws.accepted_subprotocol == "bridge-v1"
                # Ping/pong should work on anomaly WS too
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_anomaly_clients) == 0

# ---------------------------------------------------------------------------
# 5. Detection broadcast — connect WS, call broadcast helper, verify receipt
# ---------------------------------------------------------------------------

class TestDetectionBroadcast:
    """Test that _broadcast_detections delivers data to connected WS clients."""

    def test_detection_broadcast(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to detection WS, call broadcast helper, read the message."""
        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "type": "batch",
            "node_id": "node-test-01",
            "batch_id": "test-batch-001",
            "count": 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1

                # Schedule the broadcast on the TestClient's event loop so the
                # WebSocket send goes through the correct ASGI channel.
                future = tc.portal.start_task_soon(
                    _broadcast_detections, app_state, broadcast_payload,
                )
                data = ws.receive_json()
                future.result(timeout=5.0)

                assert data["type"] == "batch"
                assert data["node_id"] == "node-test-01"
                assert data["batch_id"] == "test-batch-001"
                assert data["count"] == 1

# ---------------------------------------------------------------------------
# 6. Anomaly broadcast — connect anomaly WS, broadcast, verify receipt
# ---------------------------------------------------------------------------

class TestAnomalyBroadcast:
    """Test that _broadcast_anomalies delivers data to connected WS clients."""

    def test_anomaly_broadcast(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to anomaly WS, call broadcast helper, read the message."""
        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "type": "iq_available",
            "detection_id": "det-abc-123",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/anomalies",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_anomaly_clients) == 1

                future = tc.portal.start_task_soon(
                    _broadcast_anomalies, app_state, broadcast_payload,
                )
                data = ws.receive_json()
                future.result(timeout=5.0)

                assert data["type"] == "iq_available"
                assert data["detection_id"] == "det-abc-123"

# ---------------------------------------------------------------------------
# 7. Client cleanup on disconnect
# ---------------------------------------------------------------------------

class TestWsClientCleanupOnDisconnect:
    """Test that WS clients are removed from the tracking list on disconnect."""

    def test_ws_client_cleanup_on_disconnect(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect; verify client removed from list."""
        app_state: AppState = bridge_app.state.app_state

        assert len(app_state.ws_detection_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                # Send a ping to confirm connection is alive
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            # Exiting the context manager closes the WS
            assert len(app_state.ws_detection_clients) == 0

        # Also verify anomaly client cleanup
        assert len(app_state.ws_anomaly_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/anomalies",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_anomaly_clients) == 1

            assert len(app_state.ws_anomaly_clients) == 0

# ---------------------------------------------------------------------------
# 8. Multiple WS clients receive broadcast
# ---------------------------------------------------------------------------

class TestMultipleWsClients:
    """Test that multiple connected clients all receive the same broadcast."""

    def test_multiple_ws_clients(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect two detection WS clients; verify both receive broadcast."""
        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "type": "batch",
            "node_id": "node-multi-01",
            "batch_id": "multi-batch-001",
            "count": 5,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws1, tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws2:
                assert len(app_state.ws_detection_clients) == 2

                future = tc.portal.start_task_soon(
                    _broadcast_detections, app_state, broadcast_payload,
                )

                # Both clients should receive the broadcast
                data1 = ws1.receive_json()
                data2 = ws2.receive_json()
                future.result(timeout=5.0)

                assert data1["type"] == "batch"
                assert data1["batch_id"] == "multi-batch-001"
                assert data1["count"] == 5

                assert data2["type"] == "batch"
                assert data2["batch_id"] == "multi-batch-001"
                assert data2["count"] == 5

            # Both should be cleaned up
            assert len(app_state.ws_detection_clients) == 0

# ---------------------------------------------------------------------------
# 9. WS rate limiter — connections up to limit are accepted
# ---------------------------------------------------------------------------

class TestWsRateLimiterAcceptsUpToLimit:
    """Test that WebSocket connections up to the concurrent limit are accepted."""

    def test_ws_connections_up_to_limit_accepted(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect sequentially with max_concurrent=2; each connection is accepted."""
        ws_limiter = WSConnectionLimiter(max_concurrent=2, max_per_minute=100)
        set_ws_limiter(ws_limiter)
        bridge_app.state.ws_limiter = ws_limiter

        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            # First connection
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            # Disconnected, slot released
            assert len(app_state.ws_detection_clients) == 0

            # Second connection (still under limit)
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_detection_clients) == 0

    def test_ws_limiter_unit_accepts_up_to_limit(self) -> None:
        """Unit test: try_acquire succeeds up to max_concurrent times."""
        limiter = WSConnectionLimiter(max_concurrent=3, max_per_minute=100)
        ip = "10.0.0.1"

        ok1, _ = limiter.try_acquire(ip)
        ok2, _ = limiter.try_acquire(ip)
        ok3, _ = limiter.try_acquire(ip)
        assert ok1 is True
        assert ok2 is True
        assert ok3 is True

        # 4th should be denied
        ok4, reason = limiter.try_acquire(ip)
        assert ok4 is False
        assert "concurrent" in reason.lower()

# ---------------------------------------------------------------------------
# 10. WS rate limiter — connections beyond limit are rejected with code 1008
# ---------------------------------------------------------------------------

class TestWsRateLimiterRejectsBeyondLimit:
    """Test that connections exceeding the concurrent limit are rejected."""

    def test_ws_connection_rejected_when_over_limit(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Exhaust the limiter externally, then attempt WS connect; expect rejection."""
        ws_limiter = WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        set_ws_limiter(ws_limiter)
        bridge_app.state.ws_limiter = ws_limiter

        # Pre-acquire the single slot so the next WS connect is denied.
        # TestClient connections appear as "testclient" IP.
        ok, _ = ws_limiter.try_acquire("testclient")
        assert ok is True

        with TestClient(bridge_app) as tc:
            # Connection should be rejected because the slot is taken
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/detections/ws/feed",
                    subprotocols=["bridge-v1", master_key],
                ) as ws:
                    ws.receive_text()

        # Clean up the pre-acquired slot
        ws_limiter.release("testclient")

    def test_ws_limiter_unit_rejects_over_limit(self) -> None:
        """Unit test: try_acquire returns False when max_concurrent exceeded."""
        limiter = WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        ip = "10.0.0.1"

        ok1, _ = limiter.try_acquire(ip)
        assert ok1 is True

        ok2, reason = limiter.try_acquire(ip)
        assert ok2 is False
        assert "concurrent" in reason.lower()

# ---------------------------------------------------------------------------
# 11. WS rate limiter — release allows reconnection
# ---------------------------------------------------------------------------

class TestWsRateLimiterReleaseAllowsReconnect:
    """Test that after disconnect, the slot is released and reconnection works."""

    def test_ws_release_allows_reconnect(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Set max_concurrent=1; connect, disconnect, then reconnect successfully."""
        ws_limiter = WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        set_ws_limiter(ws_limiter)
        bridge_app.state.ws_limiter = ws_limiter

        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            # First connection
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            # After disconnect, slot should be released
            assert len(app_state.ws_detection_clients) == 0

            # Second connection should succeed (slot was released)
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_detection_clients) == 0

    def test_ws_limiter_unit_release_frees_slot(self) -> None:
        """Unit test: releasing a slot allows re-acquisition."""
        limiter = WSConnectionLimiter(max_concurrent=1, max_per_minute=100)
        ip = "10.0.0.1"

        ok1, _ = limiter.try_acquire(ip)
        assert ok1 is True

        # Over limit
        ok2, _ = limiter.try_acquire(ip)
        assert ok2 is False

        # Release
        limiter.release(ip)

        # Should be allowed again
        ok3, _ = limiter.try_acquire(ip)
        assert ok3 is True

# ===========================================================================
# Alert WS channel tests (/api/alerts/ws/alerts)
# ===========================================================================

# ---------------------------------------------------------------------------
# 12. Alert WS connect with valid auth
# ---------------------------------------------------------------------------

class TestWsAlertConnect:
    """Test that a WebSocket client can connect to /ws/alerts with a valid api_key."""

    def test_ws_alert_connect_auth_header(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to alert WS with Sec-WebSocket-Protocol header; verify accepted."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/alerts/ws/alerts",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                # Connection accepted -- client should be tracked
                assert len(app_state.ws_alert_clients) == 1
                # Server should accept with bridge-v1 subprotocol
                assert ws.accepted_subprotocol == "bridge-v1"

            # After context manager exit, client should be cleaned up
            assert len(app_state.ws_alert_clients) == 0

    def test_ws_alert_ping_pong(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Send 'ping' text frame on alert WS, receive 'pong' reply."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/alerts/ws/alerts",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                ws.send_text("ping")
                reply = ws.receive_text()
                assert reply == "pong"

# ---------------------------------------------------------------------------
# 13. Alert WS rejection without auth
# ---------------------------------------------------------------------------

class TestWsAlertNoAuthRejected:
    """Test that connecting to alert WS without api_key is rejected."""

    def test_ws_alert_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to alert WS without api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/alerts/ws/alerts") as ws:
                    ws.receive_text()

    def test_ws_alert_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to alert WS with an invalid api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/alerts/ws/alerts?api_key=totally-wrong-key",
                ) as ws:
                    ws.receive_text()

# ---------------------------------------------------------------------------
# 14. Alert broadcast delivery via WS
# ---------------------------------------------------------------------------

class TestAlertBroadcast:
    """Test that _broadcast_alert delivers data to connected WS clients."""

    def test_alert_broadcast(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to alert WS, call broadcast helper, read the message."""
        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "alert_id": "alert-test-001",
            "name": "test_alert",
            "severity": "warning",
            "message": "Test alert message",
            "node_id": "node-test-01",
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "acknowledged": False,
            "acknowledged_at": None,
        }

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/alerts/ws/alerts",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_alert_clients) == 1

                future = tc.portal.start_task_soon(
                    _broadcast_alert, app_state, broadcast_payload,
                )
                data = ws.receive_json()
                future.result(timeout=5.0)

                assert data["alert_id"] == "alert-test-001"
                assert data["name"] == "test_alert"
                assert data["severity"] == "warning"

# ===========================================================================
# Status WS channel tests (/api/nodes/ws/status)
# ===========================================================================

# ---------------------------------------------------------------------------
# 15. Status WS connect with valid auth
# ---------------------------------------------------------------------------

class TestWsStatusConnect:
    """Test that a WebSocket client can connect to /ws/status with a valid api_key."""

    def test_ws_status_connect_auth_header(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to status WS with Sec-WebSocket-Protocol header; verify accepted and snapshot received."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/nodes/ws/status",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                # Connection accepted -- client should be tracked
                assert len(app_state.ws_status_clients) == 1
                # Server should accept with bridge-v1 subprotocol
                assert ws.accepted_subprotocol == "bridge-v1"

                # Status WS sends a snapshot on connect
                data = ws.receive_json()
                assert data["type"] == "snapshot"
                assert "nodes" in data
                assert isinstance(data["nodes"], list)
                assert all(isinstance(n, dict) for n in data["nodes"])

            # After context manager exit, client should be cleaned up
            assert len(app_state.ws_status_clients) == 0

    def test_ws_status_snapshot_reflects_registered_nodes(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """After registering a node, the status WS snapshot includes it."""
        with TestClient(bridge_app, headers={"X-API-Key": master_key}) as tc:
            # Register a node first
            resp = tc.post("/api/nodes/register", json={
                "node_id": "node-snapshot-01",
                "host": "10.0.0.50",
                "port": 8080,
            })
            assert resp.status_code == 200

            # Now connect to the status WS
            with tc.websocket_connect(
                "/api/nodes/ws/status",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                data = ws.receive_json()
                assert data["type"] == "snapshot"
                assert len(data["nodes"]) >= 1
                assert isinstance(data["nodes"][0], dict)
                node_ids = [n["node_id"] for n in data["nodes"]]
                assert "node-snapshot-01" in node_ids

# ---------------------------------------------------------------------------
# 16. Status WS rejection without auth
# ---------------------------------------------------------------------------

class TestWsStatusNoAuthRejected:
    """Test that connecting to status WS without api_key is rejected."""

    def test_ws_status_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to status WS without api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/nodes/ws/status") as ws:
                    ws.receive_text()

    def test_ws_status_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to status WS with an invalid api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/nodes/ws/status?api_key=totally-wrong-key",
                ) as ws:
                    ws.receive_text()

# ===========================================================================
# WiFi WS channel tests (/api/wifi/ws/wifi)
# ===========================================================================

# ---------------------------------------------------------------------------
# 17. WiFi WS connect with valid auth
# ---------------------------------------------------------------------------

class TestWsWifiConnect:
    """Test that a WebSocket client can connect to /ws/wifi with a valid api_key."""

    def test_ws_wifi_connect_auth_header(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to WiFi WS with Sec-WebSocket-Protocol header; verify accepted."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/wifi/ws/wifi",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                # Connection accepted -- client should be tracked
                clients = getattr(app_state, "ws_wifi_clients", [])
                assert len(clients) == 1
                # Server should accept with bridge-v1 subprotocol
                assert ws.accepted_subprotocol == "bridge-v1"

            # After context manager exit, client should be cleaned up
            clients = getattr(app_state, "ws_wifi_clients", [])
            assert len(clients) == 0

    def test_ws_wifi_ping_pong(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Send 'ping' text frame on WiFi WS, receive 'pong' reply."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/wifi/ws/wifi",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                ws.send_text("ping")
                reply = ws.receive_text()
                assert reply == "pong"

# ---------------------------------------------------------------------------
# 18. WiFi WS rejection without auth
# ---------------------------------------------------------------------------

class TestWsWifiNoAuthRejected:
    """Test that connecting to WiFi WS without api_key is rejected."""

    def test_ws_wifi_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to WiFi WS without api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/wifi/ws/wifi") as ws:
                    ws.receive_text()

    def test_ws_wifi_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """Connect to WiFi WS with an invalid api_key; expect close/error."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/wifi/ws/wifi?api_key=totally-wrong-key",
                ) as ws:
                    ws.receive_text()

# ---------------------------------------------------------------------------
# 19. WiFi broadcast delivery via WS
# ---------------------------------------------------------------------------

class TestWifiBroadcast:
    """Test that _broadcast_wifi delivers data to connected WS clients."""

    def test_wifi_broadcast(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to WiFi WS, call broadcast helper, read the message."""
        app_state: AppState = bridge_app.state.app_state
        broadcast_payload = {
            "type": "wifi_ingest",
            "node_id": "node-wifi-01",
            "count": 10,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/wifi/ws/wifi",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                clients = getattr(app_state, "ws_wifi_clients", [])
                assert len(clients) == 1

                future = tc.portal.start_task_soon(
                    _broadcast_wifi, app_state, broadcast_payload,
                )
                data = ws.receive_json()
                future.result(timeout=5.0)

                assert data["type"] == "wifi_ingest"
                assert data["node_id"] == "node-wifi-01"
                assert data["count"] == 10

# ---------------------------------------------------------------------------
# 20. WiFi WS client cleanup on disconnect
# ---------------------------------------------------------------------------

class TestWsWifiClientCleanup:
    """Test that WiFi WS clients are removed from tracking on disconnect."""

    def test_ws_wifi_client_cleanup(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect WiFi WS; verify client removed from list."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/wifi/ws/wifi",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                clients = getattr(app_state, "ws_wifi_clients", [])
                assert len(clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            # After disconnect, client should be cleaned up
            clients = getattr(app_state, "ws_wifi_clients", [])
            assert len(clients) == 0

# ---------------------------------------------------------------------------
# 21. Status WS client cleanup on disconnect
# ---------------------------------------------------------------------------

class TestWsStatusClientCleanup:
    """Test that Status WS clients are removed from tracking on disconnect."""

    def test_ws_status_client_cleanup(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect Status WS; verify client removed from list."""
        app_state: AppState = bridge_app.state.app_state

        assert len(app_state.ws_status_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/nodes/ws/status",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_status_clients) == 1
                # Consume the initial snapshot
                ws.receive_json()

            # After disconnect, client should be cleaned up
            assert len(app_state.ws_status_clients) == 0

# ---------------------------------------------------------------------------
# 22. Alert WS client cleanup on disconnect
# ---------------------------------------------------------------------------

class TestWsAlertClientCleanup:
    """Test that Alert WS clients are removed from tracking on disconnect."""

    def test_ws_alert_client_cleanup(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect Alert WS; verify client removed from list."""
        app_state: AppState = bridge_app.state.app_state

        assert len(app_state.ws_alert_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/alerts/ws/alerts",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_alert_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            # After disconnect, client should be cleaned up
            assert len(app_state.ws_alert_clients) == 0
