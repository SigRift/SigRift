"""Tests for POST /api/nodes/{node_id}/capture — manual IQ capture trigger."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestIQCaptureEndpoint:
    """Tests for the IQ capture trigger endpoint."""

    def test_capture_queues_command(self, client: TestClient, registered_node: str):
        """Valid capture request returns 200 with command details."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433.92e6},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["command"] == "iq_capture"
        assert data["node_id"] == registered_node
        assert data["status"] == "queued"
        assert "command_id" in data
        assert isinstance(data["command_id"], str)
        assert data["queued_at"] is not None
        assert isinstance(data["queued_at"], str)

    def test_capture_with_all_params(self, client: TestClient, registered_node: str):
        """Capture with all optional parameters should succeed."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={
                "freq_hz": 915e6,
                "duration_ms": 2000,
                "sample_rate": 4.8e6,
                "gain_db": 30.0,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["command"] == "iq_capture"

    def test_capture_defaults(
        self, client: TestClient, registered_node: str, app_state
    ):
        """Capture with only freq_hz should use defaults for other params."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 100e6},
        )
        assert resp.status_code == 200

        # Verify the queued command has defaults
        pending = app_state.pending_commands.get(registered_node, [])
        assert len(pending) >= 1
        assert isinstance(pending[-1], dict)
        cmd = pending[-1]
        assert cmd["command"] == "iq_capture"
        assert cmd["params"]["freq_hz"] == 100e6
        assert cmd["params"]["duration_ms"] == 1000
        assert cmd["params"]["sample_rate"] == 2.4e6
        # No gain field means "use the node's scan gain" -- an always-present
        # 40 dB cut HackRF captures ~48 dB below the scan gain (Q14).
        assert "gain_db" not in cmd["params"]

    def test_capture_explicit_gain_is_forwarded(
        self, client: TestClient, registered_node: str, app_state
    ):
        """An operator-set gain is still passed through unchanged."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 100e6, "gain_db": 88.0},
        )
        assert resp.status_code == 200
        cmd = app_state.pending_commands[registered_node][-1]
        assert cmd["params"]["gain_db"] == 88.0

    def test_capture_nonexistent_node(self, client: TestClient):
        """Capture on a nonexistent node should return 404."""
        resp = client.post(
            "/api/nodes/node-does-not-exist/capture",
            json={"freq_hz": 433.92e6},
        )
        assert resp.status_code == 404

    def test_capture_invalid_freq_zero(self, client: TestClient, registered_node: str):
        """freq_hz must be > 0."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 0},
        )
        assert resp.status_code == 422

    def test_capture_invalid_freq_negative(
        self, client: TestClient, registered_node: str
    ):
        """freq_hz must be positive."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": -100e6},
        )
        assert resp.status_code == 422

    def test_capture_duration_too_short(self, client: TestClient, registered_node: str):
        """duration_ms below 10 should be rejected."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "duration_ms": 5},
        )
        assert resp.status_code == 422

    def test_capture_duration_too_long(self, client: TestClient, registered_node: str):
        """duration_ms above 30000 should be rejected."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "duration_ms": 60000},
        )
        assert resp.status_code == 422

    def test_capture_gain_too_high(self, client: TestClient, registered_node: str):
        """gain_db above the HackRF LNA+VGA ceiling (102 dB) is rejected."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "gain_db": 120},
        )
        assert resp.status_code == 422

    def test_capture_scan_equivalent_gain_accepted(
        self, client: TestClient, registered_node: str
    ):
        """88 dB (HackRF scan LNA 40 + VGA 48) is within range now."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "gain_db": 88},
        )
        assert resp.status_code == 200

    def test_capture_sample_rate_too_high(
        self, client: TestClient, registered_node: str
    ):
        """sample_rate above 20 MHz should be rejected."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "sample_rate": 25e6},
        )
        assert resp.status_code == 422

    def test_capture_extra_fields_rejected(
        self, client: TestClient, registered_node: str
    ):
        """Extra fields should be rejected (extra=forbid)."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433e6, "unknown_field": "x"},
        )
        assert resp.status_code == 422

    def test_capture_queued_for_heartbeat(
        self, client: TestClient, registered_node: str
    ):
        """Captured command should appear in heartbeat response."""
        # Queue capture
        client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 915e6, "duration_ms": 500, "gain_db": 25.0},
        )

        # Simulate heartbeat
        hb_resp = client.post(
            "/api/nodes/heartbeat",
            json={
                "node_id": registered_node,
                "metrics": {},
            },
        )
        assert hb_resp.status_code == 200
        data = hb_resp.json()
        assert data["accepted"] is True
        pending = data.get("pending_commands", [])
        assert len(pending) >= 1
        assert isinstance(pending[0], dict)

        iq_cmds = [c for c in pending if c["command"] == "iq_capture"]
        assert len(iq_cmds) == 1
        assert iq_cmds[0]["params"]["freq_hz"] == 915e6
        assert iq_cmds[0]["params"]["duration_ms"] == 500
        assert iq_cmds[0]["params"]["gain_db"] == 25.0

    def test_capture_activity_logged(self, client: TestClient, registered_node: str):
        """Capture should create an activity log entry."""
        client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"freq_hz": 433.92e6},
        )
        resp = client.get("/api/nodes/activity?limit=10")
        assert resp.status_code == 200
        entries = resp.json()
        assert isinstance(entries, list)
        assert len(entries) >= 1
        assert any(
            e["event_type"] == "iq_capture_queued" and e["node_id"] == registered_node
            for e in entries
        )

    def test_capture_requires_auth(self, bridge_app):
        """Capture endpoint should require authentication."""
        from fastapi.testclient import TestClient as TC

        no_auth = TC(bridge_app)
        resp = no_auth.post(
            "/api/nodes/some-node/capture",
            json={"freq_hz": 433e6},
        )
        assert resp.status_code == 401

    def test_capture_multiple_queued(
        self, client: TestClient, registered_node: str, app_state
    ):
        """Multiple captures should all be queued."""
        for freq in [433e6, 868e6, 915e6]:
            resp = client.post(
                f"/api/nodes/{registered_node}/capture",
                json={"freq_hz": freq},
            )
            assert resp.status_code == 200

        pending = app_state.pending_commands.get(registered_node, [])
        iq_cmds = [c for c in pending if c["command"] == "iq_capture"]
        assert len(iq_cmds) == 3
        freqs = {c["params"]["freq_hz"] for c in iq_cmds}
        assert freqs == {433e6, 868e6, 915e6}

    def test_capture_missing_freq_rejected(
        self, client: TestClient, registered_node: str
    ):
        """Missing freq_hz should be rejected."""
        resp = client.post(
            f"/api/nodes/{registered_node}/capture",
            json={"duration_ms": 1000},
        )
        assert resp.status_code == 422
