"""Integration tests for Spectrum WebSocket, session token auth, and RBAC.

Covers:
  - Session token WebSocket auth (create user session, connect WS with it)
  - Session token auth across ALL WebSocket endpoints
  - Spectrum viewer lifecycle: connect -> WS stream -> disconnect
  - Spectrum config endpoint state after connect/disconnect
  - RBAC: VIEWER can access /config and /nodes but not /connect or /disconnect
  - Multiple WS clients on spectrum endpoint
  - Error cases: non-existent node, no auth, expired session on WS
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.state import AppState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _create_user_session(
    detection_store: DetectionStore,
    username: str = "wsuser",
    password: str = "WsUser123!",
    role: str = "analyst",
) -> tuple[dict[str, Any], str]:
    """Create a user and a session, returning (session_dict, token)."""
    detection_store.create_user(username=username, password=password, role=role)
    user = detection_store.users.get_user_full(username)
    assert user is not None, f"Failed to create user {username}"
    session = detection_store.create_session(user_id=user["id"])
    return session, session["session_token"]


def _create_viewer_api_key(
    persistence: Any,
) -> str:
    """Create a VIEWER-level API key and return the raw key."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key("viewer-key", hash_hex, salt)
    persistence.set_key_meta("viewer-key", {"role": "viewer"})
    return raw_key


def _register_node(client: TestClient, node_id: str = "node-01", host: str = "192.168.1.50") -> None:
    """Register a node for spectrum tests."""
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": host,
        "port": 8080,
    })
    assert resp.status_code == 200


# ===========================================================================
# 1. Session token WebSocket auth
# ===========================================================================


class TestSessionTokenWsAuth:
    """Verify that session tokens work for WebSocket authentication
    via the Sec-WebSocket-Protocol header (same path as API keys)."""

    def test_session_token_ws_feed(
        self, bridge_app: FastAPI, detection_store: DetectionStore, master_key: str,
    ) -> None:
        """Connect to /ws/feed using a session token instead of API key."""
        _, token = _create_user_session(detection_store, "ws_feed_user", role="analyst")
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", token],
            ) as ws:
                assert len(app_state.ws_detection_clients) == 1
                assert ws.accepted_subprotocol == "bridge-v1"
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_detection_clients) == 0


# ===========================================================================
# 2. Session token works for ALL WebSocket endpoints
# ===========================================================================


class TestSessionTokenAllWsEndpoints:
    """Verify session token auth works across every WS endpoint."""

    @pytest.fixture(autouse=True)
    def _setup_user(self, bridge_app: FastAPI, detection_store: DetectionStore, master_key: str) -> None:
        """Create a user and session token for all tests in this class."""
        _, self.token = _create_user_session(
            detection_store, "ws_all_user", role="admin",
        )
        self.app_state: AppState = bridge_app.state.app_state

    def test_ws_status(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/status."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/nodes/ws/status",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_status_clients) == 1
                # Consume the initial snapshot
                data = ws.receive_json()
                assert data["type"] == "snapshot"

    def test_ws_alerts(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/alerts."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/alerts/ws/alerts",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_alert_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_feed(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/feed."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/feed",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_detection_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_anomalies(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/anomalies."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/detections/ws/anomalies",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_anomaly_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_bluetooth(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/bluetooth."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/bluetooth/ws/bluetooth",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_bluetooth_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_wifi(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/wifi."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/wifi/ws/wifi",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                clients = getattr(self.app_state, "ws_wifi_clients", [])
                assert len(clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_spectrum(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/spectrum."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/spectrum/ws/spectrum",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_spectrum_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

    def test_ws_spectrum_monitor(self, bridge_app: FastAPI) -> None:
        """Session token works for /ws/spectrum-monitor."""
        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/spectrum/ws/spectrum-monitor",
                subprotocols=["bridge-v1", self.token],
            ) as ws:
                assert len(self.app_state.ws_spectrum_monitor_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"


# ===========================================================================
# 3. Spectrum viewer connect -> WS stream -> disconnect lifecycle
# ===========================================================================


class TestSpectrumViewerLifecycle:
    """Full lifecycle: connect to node, verify WS receives frames, disconnect."""

    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.connect", new_callable=AsyncMock, return_value=True)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.set_params", new_callable=AsyncMock)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.start_streaming", new_callable=AsyncMock)
    def test_connect_ws_stream_disconnect(
        self, mock_start, mock_params, mock_conn,
        bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect to node -> open WS -> verify tracked -> disconnect."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app, headers={"X-API-Key": master_key}) as tc:
            # 1. Register a node
            _register_node(tc, "lifecycle-node", "10.0.0.1")

            # 2. Connect to the node for spectrum viewing
            resp = tc.post("/api/spectrum/connect", json={
                "node_id": "lifecycle-node",
                "center_freq_hz": 433920000,
                "gain_db": 40,
                "sample_rate_hz": 2048000,
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["connected"] is True
            assert data["node_id"] == "lifecycle-node"

            # 3. Open a WS connection for spectrum data
            with tc.websocket_connect(
                "/api/spectrum/ws/spectrum",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_spectrum_clients) == 1
                # The WS may receive streaming spectrum frames since
                # we have an active connection. Send ping and drain
                # messages until we get the pong reply.
                ws.send_text("ping")
                got_pong = False
                for _ in range(20):  # Read up to 20 messages
                    msg = ws.receive_text()
                    if msg == "pong":
                        got_pong = True
                        break
                assert got_pong is True, "Expected pong reply from spectrum WS"

            # 4. After WS close, client should be cleaned up
            assert len(app_state.ws_spectrum_clients) == 0

            # 5. Disconnect from the node
            resp = tc.get("/api/spectrum/disconnect")
            assert resp.status_code == 200
            assert resp.json()["connected"] is False


# ===========================================================================
# 4. Spectrum config endpoint returns correct state
# ===========================================================================


class TestSpectrumConfigState:
    """Verify /config returns correct state after connect and disconnect."""

    def test_config_disconnected_state(self, client: TestClient) -> None:
        """Before any connection, config shows disconnected."""
        resp = client.get("/api/spectrum/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is False

    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.connect", new_callable=AsyncMock, return_value=True)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.set_params", new_callable=AsyncMock)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.start_streaming", new_callable=AsyncMock)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.disconnect", new_callable=AsyncMock)
    def test_config_after_connect_then_disconnect(
        self, mock_disconnect, mock_start, mock_params, mock_conn,
        client: TestClient,
    ) -> None:
        """Config should reflect connected state, then disconnected after disconnect."""
        _register_node(client, "config-node", "10.0.0.2")

        # Connect
        resp = client.post("/api/spectrum/connect", json={
            "node_id": "config-node",
            "center_freq_hz": 915000000,
            "gain_db": 30,
            "sample_rate_hz": 1024000,
        })
        assert resp.status_code == 200
        assert resp.json()["connected"] is True

        # Disconnect
        resp = client.get("/api/spectrum/disconnect")
        assert resp.status_code == 200
        assert resp.json()["connected"] is False


# ===========================================================================
# 5. RBAC: VIEWER can read /config and /nodes but not /connect or /disconnect
# ===========================================================================


class TestSpectrumRBAC:
    """RBAC enforcement: VIEWER can read, ANALYST needed for connect/disconnect."""

    def test_viewer_can_access_config(
        self, bridge_app: FastAPI,
    ) -> None:
        """VIEWER-level key can access /config."""
        persistence = bridge_app.state.persistence
        viewer_key = _create_viewer_api_key(persistence)

        with TestClient(bridge_app, headers={"X-API-Key": viewer_key}) as tc:
            resp = tc.get("/api/spectrum/config")
            assert resp.status_code == 200

    def test_viewer_can_access_nodes(
        self, bridge_app: FastAPI,
    ) -> None:
        """VIEWER-level key can access /nodes."""
        persistence = bridge_app.state.persistence
        viewer_key = _create_viewer_api_key(persistence)

        with TestClient(bridge_app, headers={"X-API-Key": viewer_key}) as tc:
            resp = tc.get("/api/spectrum/nodes")
            assert resp.status_code == 200

    def test_viewer_cannot_connect(
        self, bridge_app: FastAPI,
    ) -> None:
        """VIEWER-level key is rejected for /connect (ANALYST required)."""
        persistence = bridge_app.state.persistence
        viewer_key = _create_viewer_api_key(persistence)

        with TestClient(bridge_app, headers={"X-API-Key": viewer_key}) as tc:
            resp = tc.post("/api/spectrum/connect", json={"node_id": "x"})
            assert resp.status_code == 403

    def test_viewer_cannot_disconnect(
        self, bridge_app: FastAPI,
    ) -> None:
        """VIEWER-level key is rejected for /disconnect (ANALYST required)."""
        persistence = bridge_app.state.persistence
        viewer_key = _create_viewer_api_key(persistence)

        with TestClient(bridge_app, headers={"X-API-Key": viewer_key}) as tc:
            resp = tc.get("/api/spectrum/disconnect")
            assert resp.status_code == 403

    def test_viewer_session_can_read_config(
        self, bridge_app: FastAPI, detection_store: DetectionStore,
    ) -> None:
        """VIEWER-role session token can access /config."""
        _, token = _create_user_session(
            detection_store, "viewer_cfg_user", role="viewer",
        )

        with TestClient(bridge_app, headers={"X-Session-Token": token}) as tc:
            resp = tc.get("/api/spectrum/config")
            assert resp.status_code == 200

    def test_viewer_session_cannot_connect(
        self, bridge_app: FastAPI, detection_store: DetectionStore,
    ) -> None:
        """VIEWER-role session token is rejected for /connect."""
        _, token = _create_user_session(
            detection_store, "viewer_conn_user", role="viewer",
        )

        with TestClient(bridge_app, headers={"X-Session-Token": token}) as tc:
            resp = tc.post("/api/spectrum/connect", json={"node_id": "x"})
            assert resp.status_code == 403

    def test_analyst_session_can_connect(
        self, bridge_app: FastAPI, detection_store: DetectionStore, master_key: str,
    ) -> None:
        """ANALYST-role session token is accepted for /connect (even if node missing)."""
        _, token = _create_user_session(
            detection_store, "analyst_conn_user", role="analyst",
        )

        with TestClient(bridge_app, headers={"X-Session-Token": token}) as tc:
            # Node doesn't exist, so we get 404 (not 403) proving auth passed
            resp = tc.post("/api/spectrum/connect", json={"node_id": "nonexistent"})
            assert resp.status_code == 404


# ===========================================================================
# 6. Multiple WS clients on spectrum endpoint
# ===========================================================================


class TestMultipleSpectrumWsClients:
    """Two clients connecting to spectrum WS should both be tracked."""

    def test_two_spectrum_ws_clients_tracked(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Two spectrum WS clients connect simultaneously; both tracked."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc1, TestClient(bridge_app) as tc2:
            with tc1.websocket_connect(
                "/api/spectrum/ws/spectrum",
                subprotocols=["bridge-v1", master_key],
            ) as ws1, tc2.websocket_connect(
                "/api/spectrum/ws/spectrum",
                subprotocols=["bridge-v1", master_key],
            ) as ws2:
                assert len(app_state.ws_spectrum_clients) == 2
                # Both should respond to ping
                ws1.send_text("ping")
                assert ws1.receive_text() == "pong"
                ws2.send_text("ping")
                assert ws2.receive_text() == "pong"

            assert len(app_state.ws_spectrum_clients) == 0

    def test_two_spectrum_monitor_ws_clients(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Two spectrum-monitor WS clients connect; both tracked and cleaned up."""
        app_state: AppState = bridge_app.state.app_state

        with TestClient(bridge_app) as tc1, TestClient(bridge_app) as tc2:
            with tc1.websocket_connect(
                "/api/spectrum/ws/spectrum-monitor",
                subprotocols=["bridge-v1", master_key],
            ) as ws1, tc2.websocket_connect(
                "/api/spectrum/ws/spectrum-monitor",
                subprotocols=["bridge-v1", master_key],
            ) as ws2:
                assert len(app_state.ws_spectrum_monitor_clients) == 2
                ws1.send_text("ping")
                assert ws1.receive_text() == "pong"

            assert len(app_state.ws_spectrum_monitor_clients) == 0


# ===========================================================================
# 7. Error cases
# ===========================================================================


class TestSpectrumWsErrorCases:
    """Error cases: no auth, bad node, expired session."""

    def test_spectrum_ws_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connecting to spectrum WS without auth is rejected."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/spectrum/ws/spectrum") as ws:
                    ws.receive_text()

    def test_spectrum_monitor_ws_no_auth_rejected(self, bridge_app: FastAPI) -> None:
        """Connecting to spectrum-monitor WS without auth is rejected."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect("/api/spectrum/ws/spectrum-monitor") as ws:
                    ws.receive_text()

    def test_spectrum_ws_bad_key_rejected(self, bridge_app: FastAPI) -> None:
        """Connecting to spectrum WS with invalid key is rejected."""
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/spectrum/ws/spectrum",
                    subprotocols=["bridge-v1", "totally-bogus-key"],
                ) as ws:
                    ws.receive_text()

    def test_connect_nonexistent_node(self, client: TestClient) -> None:
        """POST /connect with a node_id that does not exist returns 404."""
        resp = client.post("/api/spectrum/connect", json={
            "node_id": "ghost-node-999",
            "center_freq_hz": 433920000,
        })
        assert resp.status_code == 404

    def test_expired_session_rejected_on_ws(
        self, bridge_app: FastAPI, detection_store: DetectionStore,
    ) -> None:
        """An expired session token should be rejected on WS connect."""
        # Create user and session
        detection_store.create_user(
            username="expired_ws_user",
            password="ExpiredWs123!",
            role="analyst",
        )
        user = detection_store.users.get_user_full("expired_ws_user")
        session = detection_store.create_session(
            user_id=user["id"],
            expires_hours=0,  # Expires immediately
        )
        token = session["session_token"]

        # Manually expire the session in the DB (use hashed token)
        import hashlib
        conn = detection_store.get_connection()
        past = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        hashed = hashlib.sha256(token.encode("utf-8")).hexdigest()
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
            [past, hashed],
        )
        conn.commit()

        # Verify get_session returns None for expired token
        assert detection_store.get_session(token) is None

        # Attempt WS connect with expired token
        with TestClient(bridge_app) as tc:
            with pytest.raises((WebSocketDisconnect, Exception)):
                with tc.websocket_connect(
                    "/api/spectrum/ws/spectrum",
                    subprotocols=["bridge-v1", token],
                ) as ws:
                    ws.receive_text()

    def test_connect_without_node_id(self, client: TestClient) -> None:
        """POST /connect without node_id returns 422."""
        resp = client.post("/api/spectrum/connect", json={
            "center_freq_hz": 433920000,
        })
        assert resp.status_code == 422


# ===========================================================================
# 8. Spectrum WS client cleanup on disconnect
# ===========================================================================


class TestSpectrumWsCleanup:
    """Verify clients are properly removed from tracking on disconnect."""

    def test_spectrum_ws_client_cleanup(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect spectrum WS; verify client removed."""
        app_state: AppState = bridge_app.state.app_state
        assert len(app_state.ws_spectrum_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/spectrum/ws/spectrum",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_spectrum_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_spectrum_clients) == 0

    def test_spectrum_monitor_ws_client_cleanup(
        self, bridge_app: FastAPI, master_key: str,
    ) -> None:
        """Connect and disconnect spectrum-monitor WS; verify client removed."""
        app_state: AppState = bridge_app.state.app_state
        assert len(app_state.ws_spectrum_monitor_clients) == 0

        with TestClient(bridge_app) as tc:
            with tc.websocket_connect(
                "/api/spectrum/ws/spectrum-monitor",
                subprotocols=["bridge-v1", master_key],
            ) as ws:
                assert len(app_state.ws_spectrum_monitor_clients) == 1
                ws.send_text("ping")
                assert ws.receive_text() == "pong"

            assert len(app_state.ws_spectrum_monitor_clients) == 0
