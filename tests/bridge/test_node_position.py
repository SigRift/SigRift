"""Tests for PATCH /api/nodes/{node_id}/position — node geolocation."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


class TestNodePositionEndpoint:
    """Tests for the node position update endpoint."""

    def test_update_position_success(self, client: TestClient, registered_node: str):
        """Valid position update returns 200 with coordinates."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 25.5, "y": 75.0, "floor_label": "Floor 2"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["node_id"] == registered_node
        assert data["position_x"] == pytest.approx(25.5)
        assert data["position_y"] == pytest.approx(75.0)
        assert data["floor_label"] == "Floor 2"

    def test_position_persisted_in_single_node(self, client: TestClient, registered_node: str):
        """Position should be retrievable from GET /api/nodes/{id}."""
        client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 10.0, "y": 90.0, "floor_label": "Rooftop"},
        )
        resp = client.get(f"/api/nodes/{registered_node}")
        assert resp.status_code == 200
        node = resp.json()
        assert node["position_x"] == 10.0
        assert node["position_y"] == 90.0
        assert node["floor_label"] == "Rooftop"

    def test_position_persisted_in_node_list(self, client: TestClient, registered_node: str):
        """Position should be retrievable from GET /api/nodes/."""
        client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 42.0, "y": 58.0, "floor_label": "Basement"},
        )
        resp = client.get("/api/nodes/")
        assert resp.status_code == 200
        nodes = resp.json()
        node = next(n for n in nodes if n["node_id"] == registered_node)
        assert node["position_x"] == 42.0
        assert node["position_y"] == 58.0
        assert node["floor_label"] == "Basement"

    def test_unpositioned_node_returns_null(self, client: TestClient, registered_node: str):
        """Nodes without a position set should return null for position fields."""
        resp = client.get(f"/api/nodes/{registered_node}")
        assert resp.status_code == 200
        node = resp.json()
        assert node["position_x"] is None
        assert node["position_y"] is None
        assert node["floor_label"] == ""

    def test_position_boundary_zero(self, client: TestClient, registered_node: str):
        """Coordinates at (0, 0) should be accepted."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 0.0, "y": 0.0, "floor_label": ""},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["position_x"] == 0.0
        assert data["position_y"] == 0.0

    def test_position_boundary_max(self, client: TestClient, registered_node: str):
        """Coordinates at (100, 100) should be accepted."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 100.0, "y": 100.0, "floor_label": "Max"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["position_x"] == 100.0
        assert data["position_y"] == 100.0

    def test_position_x_out_of_range_high(self, client: TestClient, registered_node: str):
        """x > 100 should be rejected with 422."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 101.0, "y": 50.0, "floor_label": ""},
        )
        assert resp.status_code == 422

    def test_position_x_out_of_range_low(self, client: TestClient, registered_node: str):
        """x < 0 should be rejected with 422."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": -1.0, "y": 50.0, "floor_label": ""},
        )
        assert resp.status_code == 422

    def test_position_y_out_of_range_high(self, client: TestClient, registered_node: str):
        """y > 100 should be rejected with 422."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 50.0, "y": 150.0, "floor_label": ""},
        )
        assert resp.status_code == 422

    def test_position_y_out_of_range_low(self, client: TestClient, registered_node: str):
        """y < 0 should be rejected with 422."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 50.0, "y": -0.1, "floor_label": ""},
        )
        assert resp.status_code == 422

    def test_position_nonexistent_node(self, client: TestClient):
        """Position update on a nonexistent node should return 404."""
        resp = client.patch(
            "/api/nodes/node-does-not-exist/position",
            json={"x": 50.0, "y": 50.0, "floor_label": ""},
        )
        assert resp.status_code == 404

    def test_position_missing_fields(self, client: TestClient, registered_node: str):
        """Missing required x/y fields should return 422."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"floor_label": "Floor 1"},
        )
        assert resp.status_code == 422

    def test_position_floor_label_default_empty(self, client: TestClient, registered_node: str):
        """floor_label should default to empty string if omitted."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 50.0, "y": 50.0},
        )
        assert resp.status_code == 200
        assert resp.json()["floor_label"] == ""

    def test_position_extra_fields_rejected(self, client: TestClient, registered_node: str):
        """Extra fields should be rejected (extra=forbid)."""
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 50.0, "y": 50.0, "floor_label": "", "z": 10.0},
        )
        assert resp.status_code == 422

    def test_position_audit_logged(self, client: TestClient, registered_node: str):
        """Position update should create an audit log entry."""
        client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 33.3, "y": 66.6, "floor_label": "Lab"},
        )
        # Check audit log for the entry
        resp = client.get("/api/detections/anomalies/audit", params={"action": "admin_update_node_position"})
        assert resp.status_code == 200
        entries = resp.json()["entries"]
        assert any(
            e["action"] == "admin_update_node_position" and e["target_id"] == registered_node
            for e in entries
        )

    def test_position_update_overwrite(self, client: TestClient, registered_node: str):
        """Second position update should overwrite the first."""
        client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 10.0, "y": 20.0, "floor_label": "A"},
        )
        resp = client.patch(
            f"/api/nodes/{registered_node}/position",
            json={"x": 80.0, "y": 90.0, "floor_label": "B"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["position_x"] == pytest.approx(80.0)
        assert data["position_y"] == pytest.approx(90.0)
        assert data["floor_label"] == "B"

    def test_position_requires_auth(self, bridge_app):
        """Position endpoint should require authentication."""
        from fastapi.testclient import TestClient as TC
        no_auth = TC(bridge_app)
        resp = no_auth.patch(
            "/api/nodes/some-node/position",
            json={"x": 50.0, "y": 50.0},
        )
        assert resp.status_code == 401
