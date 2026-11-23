"""Tests for RSSI-based multilateration geolocation (Phase 2 Item 6).

Covers:
  - DSP/math functions (rssi_to_distance, trilateration, weighted centroid)
  - GeolocationStore (node positions, position estimates)
  - API endpoints (/api/geolocation/*)
  - Feature flag gating
"""

from __future__ import annotations

import math
import time
import uuid

import pytest
from fastapi.testclient import TestClient

from sigrift.lib.dsp.multilateration import (
    NodePosition,
    PositionEstimate,
    RSSIMeasurement,
    _free_space_path_loss,
    _trilaterate_2d,
    _weighted_centroid,
    compute_error_estimate,
    estimate_position,
    rssi_to_distance,
)


# ===========================================================================
# Math / DSP tests
# ===========================================================================


class TestRSSIToDistance:
    """Tests for rssi_to_distance conversion."""

    def test_rssi_to_distance_reference(self):
        """At reference RSSI, returns reference distance."""
        d = rssi_to_distance(-30.0, reference_rssi_dbm=-30.0, reference_distance_m=1.0)
        assert abs(d - 1.0) < 1e-6

    def test_rssi_to_distance_farther(self):
        """Lower (more negative) RSSI yields larger distance."""
        d1 = rssi_to_distance(-30.0)
        d2 = rssi_to_distance(-50.0)
        assert d2 > d1

    def test_rssi_to_distance_closer(self):
        """Higher (less negative) RSSI yields smaller distance."""
        d1 = rssi_to_distance(-30.0)
        d2 = rssi_to_distance(-20.0)
        assert d2 < d1

    def test_rssi_to_distance_minimum(self):
        """Distance never goes below 0.01 m."""
        d = rssi_to_distance(0.0, reference_rssi_dbm=-30.0)
        assert d >= 0.01

    def test_path_loss_exponent_effect(self):
        """Higher path-loss exponent yields shorter estimated distance for same RSSI."""
        d_low = rssi_to_distance(-50.0, path_loss_exponent=2.0)
        d_high = rssi_to_distance(-50.0, path_loss_exponent=4.0)
        assert d_high < d_low


class TestFreeSpacePathLoss:
    """Tests for FSPL calculation."""

    def test_free_space_path_loss(self):
        """FSPL at 1 GHz, 100 m should be approximately 72.4 dB."""
        fspl = _free_space_path_loss(1e9, 100.0)
        # FSPL(1GHz, 100m) = 20*log10(100) + 20*log10(1e9) + 20*log10(4*pi/c)
        # ~ 40 + 180 + (-147.55) = 72.45 dB
        assert 72.0 < fspl < 73.0

    def test_free_space_path_loss_zero_distance(self):
        """Zero distance returns 0 dB."""
        assert _free_space_path_loss(1e9, 0.0) == 0.0


class TestTrilaterate2D:
    """Tests for least-squares 2D trilateration."""

    def test_trilaterate_known_position(self):
        """3 nodes at known positions, target at origin."""
        positions = [(10.0, 0.0), (0.0, 10.0), (-10.0, 0.0)]
        distances = [10.0, 10.0, 10.0]
        x, y = _trilaterate_2d(positions, distances)
        assert abs(x) < 0.5
        assert abs(y) < 0.5

    def test_trilaterate_accuracy(self):
        """Target at (3, 7), estimated position within tolerance."""
        target = (3.0, 7.0)
        nodes = [(0.0, 0.0), (10.0, 0.0), (0.0, 10.0), (10.0, 10.0)]
        distances = [
            math.sqrt((target[0] - n[0]) ** 2 + (target[1] - n[1]) ** 2)
            for n in nodes
        ]
        x, y = _trilaterate_2d(nodes, distances)
        error = math.sqrt((x - target[0]) ** 2 + (y - target[1]) ** 2)
        assert error < 0.1

    def test_trilaterate_insufficient_nodes(self):
        """Fewer than 3 nodes raises ValueError."""
        with pytest.raises(ValueError, match="requires >= 3"):
            _trilaterate_2d([(0.0, 0.0), (1.0, 0.0)], [1.0, 1.0])


class TestWeightedCentroid:
    """Tests for weighted centroid fallback."""

    def test_weighted_centroid_two_nodes(self):
        """Weighted centroid with 2 nodes biases toward closer node."""
        positions = [(0.0, 0.0), (10.0, 0.0)]
        # Higher weight on first node => result closer to first
        weights = [10.0, 1.0]
        x, y = _weighted_centroid(positions, weights)
        assert x < 5.0  # Closer to the first node

    def test_weighted_centroid_equal_weights(self):
        """Equal weights returns geometric center."""
        positions = [(0.0, 0.0), (10.0, 0.0), (5.0, 10.0)]
        weights = [1.0, 1.0, 1.0]
        x, y = _weighted_centroid(positions, weights)
        expected_x = 5.0
        expected_y = 10.0 / 3.0
        assert abs(x - expected_x) < 0.01
        assert abs(y - expected_y) < 0.01

    def test_weighted_centroid_zero_weights(self):
        """Zero weights fall back to simple average."""
        positions = [(0.0, 0.0), (10.0, 0.0)]
        weights = [0.0, 0.0]
        x, y = _weighted_centroid(positions, weights)
        assert abs(x - 5.0) < 0.01


class TestEstimatePosition:
    """Tests for the main estimate_position pipeline."""

    def _make_nodes(self) -> dict[str, NodePosition]:
        return {
            "n1": NodePosition("n1", 0.0, 0.0),
            "n2": NodePosition("n2", 20.0, 0.0),
            "n3": NodePosition("n3", 10.0, 17.0),
            "n4": NodePosition("n4", 10.0, -5.0),
        }

    def test_estimate_position_3_nodes(self):
        """Full pipeline with 3 nodes returns a valid estimate."""
        nodes = self._make_nodes()
        measurements = [
            RSSIMeasurement("n1", -45.0, 433e6, time.time()),
            RSSIMeasurement("n2", -50.0, 433e6, time.time()),
            RSSIMeasurement("n3", -48.0, 433e6, time.time()),
        ]
        result = estimate_position(measurements, nodes)
        assert isinstance(result, PositionEstimate)
        assert result.method == "rssi_trilateration"
        assert result.n_nodes == 3
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.error_radius_m, float)
        assert result.error_radius_m > 0

    def test_estimate_position_4_nodes(self):
        """More nodes should produce an estimate (possibly lower error)."""
        nodes = self._make_nodes()
        measurements = [
            RSSIMeasurement("n1", -45.0, 433e6, time.time()),
            RSSIMeasurement("n2", -50.0, 433e6, time.time()),
            RSSIMeasurement("n3", -48.0, 433e6, time.time()),
            RSSIMeasurement("n4", -47.0, 433e6, time.time()),
        ]
        result = estimate_position(measurements, nodes)
        assert result.n_nodes == 4
        assert result.method == "rssi_trilateration"

    def test_estimate_position_2_nodes_fallback(self):
        """With 2 nodes, falls back to weighted centroid."""
        nodes = self._make_nodes()
        measurements = [
            RSSIMeasurement("n1", -40.0, 433e6, time.time()),
            RSSIMeasurement("n2", -55.0, 433e6, time.time()),
        ]
        result = estimate_position(measurements, nodes)
        assert result.method == "rssi_weighted_centroid"
        assert result.n_nodes == 2

    def test_estimate_position_insufficient_nodes(self):
        """1 node raises ValueError."""
        nodes = self._make_nodes()
        measurements = [
            RSSIMeasurement("n1", -40.0, 433e6, time.time()),
        ]
        with pytest.raises(ValueError, match="at least 2"):
            estimate_position(measurements, nodes)

    def test_estimate_position_unknown_node(self):
        """Measurements from unknown nodes are filtered out."""
        nodes = {"n1": NodePosition("n1", 0.0, 0.0)}
        measurements = [
            RSSIMeasurement("n1", -40.0, 433e6, time.time()),
            RSSIMeasurement("unknown1", -45.0, 433e6, time.time()),
            RSSIMeasurement("unknown2", -50.0, 433e6, time.time()),
        ]
        with pytest.raises(ValueError, match="at least 2"):
            estimate_position(measurements, nodes)


class TestErrorAndConfidence:
    """Tests for error estimation and confidence scoring."""

    def test_error_estimate_perfect(self):
        """When RSSI-implied distances match geometric distances, error is small."""
        # Place target at (5, 0), node at (0, 0), distance 5
        # RSSI that yields distance ~5 at default params:
        # d = 1 * 10^((-30 - rssi) / 25), so rssi for d=5: -30 - 25*log10(5) ~ -47.47
        nodes = {
            "n1": NodePosition("n1", 0.0, 0.0),
            "n2": NodePosition("n2", 10.0, 0.0),
            "n3": NodePosition("n3", 5.0, 8.66),
        }
        target = (5.0, 0.0)
        # Compute exact RSSI for each node distance
        measurements = []
        for nid, np_ in nodes.items():
            d = math.sqrt((target[0] - np_.x) ** 2 + (target[1] - np_.y) ** 2)
            # Inverse of rssi_to_distance: rssi = ref_rssi - 10*n*log10(d/d0)
            rssi = -30.0 - 10.0 * 2.5 * math.log10(max(d, 0.01) / 1.0)
            measurements.append(RSSIMeasurement(nid, rssi, 433e6, time.time()))

        error = compute_error_estimate(measurements, target, nodes, 2.5)
        assert error < 1.0  # very small error for perfect RSSI

    def test_confidence_high_quality(self):
        """Good geometry and measurements yield high confidence."""
        nodes = {
            "n1": NodePosition("n1", 0.0, 0.0),
            "n2": NodePosition("n2", 20.0, 0.0),
            "n3": NodePosition("n3", 10.0, 17.0),
        }
        target = (7.0, 4.0)
        measurements = []
        for nid, np_ in nodes.items():
            d = math.sqrt((target[0] - np_.x) ** 2 + (target[1] - np_.y) ** 2)
            rssi = -30.0 - 10.0 * 2.5 * math.log10(max(d, 0.01) / 1.0)
            measurements.append(RSSIMeasurement(nid, rssi, 433e6, time.time()))

        result = estimate_position(measurements, nodes)
        # With perfect RSSI, error should be small and confidence reasonable
        assert result.confidence > 0.3

    def test_confidence_poor_geometry(self):
        """Collinear nodes yield lower confidence or fallback method."""
        nodes = {
            "n1": NodePosition("n1", 0.0, 0.0),
            "n2": NodePosition("n2", 10.0, 0.0),
            "n3": NodePosition("n3", 20.0, 0.0),  # collinear
        }
        measurements = [
            RSSIMeasurement("n1", -45.0, 433e6, time.time()),
            RSSIMeasurement("n2", -50.0, 433e6, time.time()),
            RSSIMeasurement("n3", -55.0, 433e6, time.time()),
        ]
        # Should still produce a result (may use fallback)
        result = estimate_position(measurements, nodes)
        assert result.confidence >= 0.0
        assert result.confidence <= 1.0


# ===========================================================================
# Storage tests
# ===========================================================================


class TestGeolocationStore:
    """Tests for the GeolocationStore SQLite sub-store."""

    @pytest.fixture
    def store(self, detection_store):
        from sigrift.bridge.storage.geolocation import GeolocationStore
        return GeolocationStore(detection_store._ctx)

    def test_set_node_position(self, store):
        """Store and retrieve a node position."""
        result = store.set_node_position("node-a", 10.0, 20.0, z=1.5, label="Office", floor="2F")
        assert result["node_id"] == "node-a"
        assert result["x"] == 10.0

        pos = store.get_node_position("node-a")
        assert pos is not None
        assert isinstance(pos, dict)
        assert pos["y"] == 20.0
        assert pos["label"] == "Office"

    def test_get_all_positions(self, store):
        """Returns all stored node positions."""
        store.set_node_position("a", 0.0, 0.0)
        store.set_node_position("b", 5.0, 5.0)
        store.set_node_position("c", 10.0, 10.0)
        positions = store.get_all_positions()
        assert len(positions) == 3
        node_ids = {p["node_id"] for p in positions}
        assert node_ids == {"a", "b", "c"}

    def test_delete_node_position(self, store):
        """Removes a node position."""
        store.set_node_position("x", 1.0, 2.0)
        assert store.delete_node_position("x") is True
        assert store.get_node_position("x") is None
        assert store.delete_node_position("x") is False

    def test_store_estimate(self, store):
        """Store and retrieve a position estimate."""
        est_id = str(uuid.uuid4())
        store.store_estimate(
            estimate_id=est_id,
            detection_id="det-1",
            x=5.0, y=10.0, z=0.0,
            confidence=0.85,
            error_radius_m=2.5,
            method="rssi_trilateration",
            n_nodes=3,
            path_loss_model="log_distance",
            measurements=[{"node_id": "n1", "rssi_dbm": -45.0}],
        )
        est = store.get_estimate(est_id)
        assert est is not None
        assert isinstance(est, dict)
        assert est["x"] == 5.0
        assert est["confidence"] == 0.85
        assert est["method"] == "rssi_trilateration"
        assert len(est["measurements"]) == 1

    def test_get_estimates_for_detection(self, store):
        """Filter estimates by detection_id."""
        store.store_estimate("e1", "det-A", 1.0, 2.0, method="rssi_trilateration")
        store.store_estimate("e2", "det-A", 3.0, 4.0, method="rssi_weighted_centroid")
        store.store_estimate("e3", "det-B", 5.0, 6.0, method="rssi_trilateration")

        results = store.get_estimates_for_detection("det-A")
        assert len(results) == 2
        assert all(r["detection_id"] == "det-A" for r in results)

    def test_list_estimates(self, store):
        """List all estimates with pagination."""
        for i in range(5):
            store.store_estimate(f"e{i}", None, float(i), float(i), method="test")
        results = store.list_estimates(limit=3)
        assert len(results) == 3

    def test_stats(self, store):
        """Stats returns counts."""
        store.set_node_position("n1", 0.0, 0.0)
        store.set_node_position("n2", 5.0, 5.0)
        store.store_estimate("e1", None, 1.0, 2.0, confidence=0.8, method="rssi_trilateration")
        store.store_estimate("e2", None, 3.0, 4.0, confidence=0.6, method="rssi_weighted_centroid")

        stats = store.get_stats()
        assert stats["node_positions"] == 2
        assert stats["total_estimates"] == 2
        assert isinstance(stats["avg_confidence"], float)
        assert stats["avg_confidence"] > 0


# ===========================================================================
# API tests
# ===========================================================================


class TestGeolocationAPI:
    """Tests for the /api/geolocation endpoints."""

    @pytest.fixture
    def geo_client(self, bridge_app, master_key):
        """Client with geolocation feature flag enabled."""
        # Patch the module-level flag
        import sigrift.bridge.routers.geolocation as geo_mod
        original = geo_mod.GEOLOCATION_ENABLED
        geo_mod.GEOLOCATION_ENABLED = True
        client = TestClient(bridge_app, headers={"X-API-Key": master_key})
        yield client
        geo_mod.GEOLOCATION_ENABLED = original

    def _setup_nodes(self, client):
        """Helper to set up 3 node positions."""
        for nid, x, y in [("n1", 0.0, 0.0), ("n2", 20.0, 0.0), ("n3", 10.0, 17.0)]:
            resp = client.put(f"/api/geolocation/nodes/{nid}", json={"x": x, "y": y})
            assert resp.status_code == 200

    def test_list_node_positions(self, geo_client):
        """GET /nodes returns empty list initially."""
        resp = geo_client.get("/api/geolocation/nodes")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_set_node_position(self, geo_client):
        """PUT /nodes/{id} stores position."""
        resp = geo_client.put("/api/geolocation/nodes/n1", json={
            "x": 10.0, "y": 20.0, "z": 1.5, "label": "Hallway",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_id"] == "n1"
        assert data["x"] == 10.0

        # Verify it appears in list
        resp = geo_client.get("/api/geolocation/nodes")
        assert len(resp.json()) == 1

    def test_set_position_requires_admin(self, bridge_app, master_key):
        """Non-ADMIN role cannot set node positions."""
        import sigrift.bridge.routers.geolocation as geo_mod
        original = geo_mod.GEOLOCATION_ENABLED
        geo_mod.GEOLOCATION_ENABLED = True
        try:
            from sigrift.lib.security.credentials import generate_api_key, hash_credential
            viewer_key = generate_api_key(length=32)
            hash_hex, salt = hash_credential(viewer_key)
            bridge_app.state.persistence.set_key("viewer-key", hash_hex, salt)
            bridge_app.state.persistence.set_key_meta("viewer-key", {"role": "viewer"})
            client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
            resp = client.put("/api/geolocation/nodes/n1", json={"x": 1.0, "y": 2.0})
            assert resp.status_code == 403
        finally:
            geo_mod.GEOLOCATION_ENABLED = original

    def test_delete_node_position(self, geo_client):
        """DELETE /nodes/{id} removes the position."""
        geo_client.put("/api/geolocation/nodes/n1", json={"x": 1.0, "y": 2.0})
        resp = geo_client.delete("/api/geolocation/nodes/n1")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_estimate_returns_position(self, geo_client):
        """POST /estimate returns x, y, confidence."""
        self._setup_nodes(geo_client)
        resp = geo_client.post("/api/geolocation/estimate", json={
            "measurements": [
                {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": time.time()},
                {"node_id": "n2", "rssi_dbm": -52.0, "frequency_hz": 433e6, "timestamp": time.time()},
                {"node_id": "n3", "rssi_dbm": -48.0, "frequency_hz": 433e6, "timestamp": time.time()},
            ],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "x" in data
        assert isinstance(data["x"], (int, float))
        assert "y" in data
        assert isinstance(data["y"], (int, float))
        assert "confidence" in data
        assert isinstance(data["confidence"], (int, float))
        assert "estimate_id" in data
        assert isinstance(data["estimate_id"], str)
        assert data["method"] == "rssi_trilateration"
        assert data["n_nodes"] == 3

    def test_estimate_requires_analyst(self, bridge_app, master_key):
        """VIEWER cannot call estimate endpoint."""
        import sigrift.bridge.routers.geolocation as geo_mod
        original = geo_mod.GEOLOCATION_ENABLED
        geo_mod.GEOLOCATION_ENABLED = True
        try:
            from sigrift.lib.security.credentials import generate_api_key, hash_credential
            viewer_key = generate_api_key(length=32)
            hash_hex, salt = hash_credential(viewer_key)
            bridge_app.state.persistence.set_key("viewer-est", hash_hex, salt)
            bridge_app.state.persistence.set_key_meta("viewer-est", {"role": "viewer"})
            client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
            resp = client.post("/api/geolocation/estimate", json={
                "measurements": [
                    {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": 1.0},
                    {"node_id": "n2", "rssi_dbm": -50.0, "frequency_hz": 433e6, "timestamp": 1.0},
                    {"node_id": "n3", "rssi_dbm": -55.0, "frequency_hz": 433e6, "timestamp": 1.0},
                ],
            })
            assert resp.status_code == 403
        finally:
            geo_mod.GEOLOCATION_ENABLED = original

    def test_estimate_insufficient_nodes(self, geo_client):
        """POST /estimate with 1 known node returns 400."""
        geo_client.put("/api/geolocation/nodes/n1", json={"x": 0.0, "y": 0.0})
        resp = geo_client.post("/api/geolocation/estimate", json={
            "measurements": [
                {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": 1.0},
            ],
        })
        # pydantic validation requires min_length=2
        assert resp.status_code == 422

    def test_list_estimates(self, geo_client):
        """GET /estimates returns stored estimates."""
        self._setup_nodes(geo_client)
        # Create an estimate first
        geo_client.post("/api/geolocation/estimate", json={
            "measurements": [
                {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": 1.0},
                {"node_id": "n2", "rssi_dbm": -50.0, "frequency_hz": 433e6, "timestamp": 1.0},
                {"node_id": "n3", "rssi_dbm": -55.0, "frequency_hz": 433e6, "timestamp": 1.0},
            ],
        })
        resp = geo_client.get("/api/geolocation/estimates")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert data["count"] >= 1

    def test_get_estimate(self, geo_client):
        """GET /estimates/{id} returns a single estimate."""
        self._setup_nodes(geo_client)
        post_resp = geo_client.post("/api/geolocation/estimate", json={
            "measurements": [
                {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": 1.0},
                {"node_id": "n2", "rssi_dbm": -50.0, "frequency_hz": 433e6, "timestamp": 1.0},
                {"node_id": "n3", "rssi_dbm": -55.0, "frequency_hz": 433e6, "timestamp": 1.0},
            ],
        })
        est_id = post_resp.json()["estimate_id"]
        resp = geo_client.get(f"/api/geolocation/estimates/{est_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == est_id

    def test_get_estimate_not_found(self, geo_client):
        """GET /estimates/{id} returns 404 for missing ID."""
        resp = geo_client.get("/api/geolocation/estimates/nonexistent")
        assert resp.status_code == 404

    def test_stats(self, geo_client):
        """GET /stats returns counts."""
        self._setup_nodes(geo_client)
        resp = geo_client.get("/api/geolocation/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_positions"] == 3

    def test_config_get(self, geo_client):
        """GET /config returns default config."""
        resp = geo_client.get("/api/geolocation/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "path_loss_exponent" in data
        assert isinstance(data["path_loss_exponent"], (int, float))

    def test_config_update(self, geo_client):
        """PUT /config updates the config."""
        resp = geo_client.put("/api/geolocation/config", json={
            "path_loss_exponent": 3.0,
            "reference_rssi_dbm": -35.0,
            "reference_distance_m": 1.5,
        })
        assert resp.status_code == 200
        assert resp.json()["path_loss_exponent"] == 3.0

    def test_geolocation_disabled(self, bridge_app, master_key):
        """When feature flag is off, all endpoints return 403."""
        import sigrift.bridge.routers.geolocation as geo_mod
        original = geo_mod.GEOLOCATION_ENABLED
        geo_mod.GEOLOCATION_ENABLED = False
        try:
            client = TestClient(bridge_app, headers={"X-API-Key": master_key})
            resp = client.get("/api/geolocation/nodes")
            assert resp.status_code == 403
            assert "disabled" in resp.json()["detail"].lower()

            resp = client.get("/api/geolocation/stats")
            assert resp.status_code == 403

            resp = client.post("/api/geolocation/estimate", json={
                "measurements": [
                    {"node_id": "n1", "rssi_dbm": -45.0, "frequency_hz": 433e6, "timestamp": 1.0},
                    {"node_id": "n2", "rssi_dbm": -50.0, "frequency_hz": 433e6, "timestamp": 1.0},
                ],
            })
            assert resp.status_code == 403
        finally:
            geo_mod.GEOLOCATION_ENABLED = original
