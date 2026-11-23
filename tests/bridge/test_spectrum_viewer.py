"""Tests for spectrum viewer endpoints: nodes, connect, disconnect, config.

Validates the rtl_tcp proxy endpoints added to routers/spectrum.py
including RBAC, node lookup, and streamer config reporting.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security.credentials import generate_api_key, hash_credential


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register_node(client: TestClient, node_id: str = "node-01", host: str = "192.168.1.50") -> None:
    """Register a node for spectrum tests."""
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": host,
        "port": 8080,
    })
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# TestSpectrumNodes
# ---------------------------------------------------------------------------


class TestSpectrumNodes:
    """GET /api/spectrum/nodes — list registered nodes."""

    def test_list_nodes_returns_registered(self, client: TestClient) -> None:
        _register_node(client, "spec-node-01", "10.0.0.1")
        resp = client.get("/api/spectrum/nodes")
        assert resp.status_code == 200
        nodes = resp.json()
        assert isinstance(nodes, list)
        ids = [n["node_id"] for n in nodes]
        assert "spec-node-01" in ids
        node = next(n for n in nodes if n["node_id"] == "spec-node-01")
        assert node["host"] == "10.0.0.1"

    def test_list_nodes_empty(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/nodes")
        assert resp.status_code == 200
        # May have nodes from other fixtures, but should be a list
        assert isinstance(resp.json(), list)

    def test_list_nodes_requires_auth(self, bridge_app: FastAPI) -> None:
        unauth_client = TestClient(bridge_app)
        resp = unauth_client.get("/api/spectrum/nodes")
        assert resp.status_code in (401, 403)

    def test_list_nodes_includes_rtl_tcp_port(self, client: TestClient) -> None:
        _register_node(client, "spec-node-02")
        resp = client.get("/api/spectrum/nodes")
        nodes = resp.json()
        node = next((n for n in nodes if n["node_id"] == "spec-node-02"), None)
        assert isinstance(node, dict)
        assert isinstance(node["rtl_tcp_port"], int)


# ---------------------------------------------------------------------------
# TestSpectrumConnect
# ---------------------------------------------------------------------------


class TestSpectrumConnect:
    """POST /api/spectrum/connect and GET /disconnect, /config."""

    def test_connect_unknown_node(self, client: TestClient) -> None:
        resp = client.post("/api/spectrum/connect", json={
            "node_id": "nonexistent-node",
            "center_freq_hz": 433920000,
            "gain_db": 40,
            "sample_rate_hz": 2048000,
        })
        assert resp.status_code == 404

    def test_connect_missing_node_id(self, client: TestClient) -> None:
        resp = client.post("/api/spectrum/connect", json={
            "center_freq_hz": 433920000,
        })
        assert resp.status_code == 422

    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.connect", new_callable=AsyncMock, return_value=True)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.set_params", new_callable=AsyncMock)
    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.start_streaming", new_callable=AsyncMock)
    def test_connect_valid_node(self, mock_start, mock_params, mock_conn, client: TestClient) -> None:
        _register_node(client, "spec-conn-01", "10.0.0.5")
        resp = client.post("/api/spectrum/connect", json={
            "node_id": "spec-conn-01",
            "center_freq_hz": 433920000,
            "gain_db": 40,
            "sample_rate_hz": 2048000,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["connected"] is True
        assert data["node_id"] == "spec-conn-01"
        assert data["host"] == "10.0.0.5"

    @patch("sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer.connect", new_callable=AsyncMock, return_value=False)
    def test_connect_rtl_tcp_failure(self, mock_conn, client: TestClient) -> None:
        _register_node(client, "spec-fail-01", "10.0.0.99")
        resp = client.post("/api/spectrum/connect", json={
            "node_id": "spec-fail-01",
            "center_freq_hz": 433920000,
        })
        assert resp.status_code == 502

    def test_disconnect_returns_false(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/disconnect")
        assert resp.status_code == 200
        assert resp.json()["connected"] is False

    def test_config_returns_status(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/config")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["connected"], bool)
        assert isinstance(data["host"], str)
        assert isinstance(data["port"], int)


# ---------------------------------------------------------------------------
# TestSpectrumConnectRBAC
# ---------------------------------------------------------------------------


class TestSpectrumConnectRBAC:
    """RBAC checks for spectrum connect/disconnect/config."""

    def test_connect_requires_auth(self, bridge_app: FastAPI) -> None:
        unauth = TestClient(bridge_app)
        resp = unauth.post("/api/spectrum/connect", json={"node_id": "x"})
        assert resp.status_code in (401, 403)

    def test_disconnect_requires_auth(self, bridge_app: FastAPI) -> None:
        unauth = TestClient(bridge_app)
        resp = unauth.get("/api/spectrum/disconnect")
        assert resp.status_code in (401, 403)

    def test_config_requires_auth(self, bridge_app: FastAPI) -> None:
        unauth = TestClient(bridge_app)
        resp = unauth.get("/api/spectrum/config")
        assert resp.status_code in (401, 403)

    def test_viewer_key_reads_but_cannot_connect_or_disconnect(
        self, bridge_app: FastAPI, persistence: PersistenceManager
    ) -> None:
        """Connecting and disconnecting need an analyst key (as on Shiny).

        The streamer is never reached: the 403 comes before the handler.
        """
        raw = generate_api_key(length=32)
        hash_hex, salt = hash_credential(raw)
        persistence.set_key("spec-viewer", hash_hex, salt)
        persistence.set_key_meta("spec-viewer", {"role": "viewer"})
        viewer = TestClient(bridge_app, headers={"X-API-Key": raw})

        streamer = "sigrift.lib.shiny.spectrum_streamer.SpectrumStreamer"
        with (
            patch(f"{streamer}.connect", new_callable=AsyncMock) as connect,
            patch(f"{streamer}.disconnect", new_callable=AsyncMock) as disconnect,
        ):
            resp = viewer.post("/api/spectrum/connect", json={"node_id": "x"})
            assert (resp.status_code, resp.json()["detail"]) == (
                403,
                "Analyst role required",
            )
            resp = viewer.get("/api/spectrum/disconnect")
            assert (resp.status_code, resp.json()["detail"]) == (
                403,
                "Analyst role required",
            )
            connect.assert_not_called()
            disconnect.assert_not_called()
        assert viewer.get("/api/spectrum/config").status_code == 200
