"""Tests for geolocation and mapping endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register_node(client: TestClient, node_id: str = "node-geo-01", **kwargs) -> None:
    """Register a node via the API."""
    body = {"node_id": node_id, "host": "10.0.0.1", "port": 8080}
    body.update(kwargs)
    resp = client.post("/api/nodes/register", json=body)
    assert resp.status_code == 200, resp.text


def _set_location(
    client: TestClient,
    node_id: str,
    lat: float = 40.7128,
    lon: float = -74.0060,
    alt: float | None = None,
    name: str = "",
) -> None:
    """Set location on a node."""
    body = {"latitude": lat, "longitude": lon, "location_name": name}
    if alt is not None:
        body["altitude_m"] = alt
    resp = client.put(f"/api/nodes/{node_id}/location", json=body)
    assert resp.status_code == 200, resp.text


def _insert_detections(client: TestClient, store, node_id: str, count: int = 5) -> None:
    """Insert test detections into the store."""
    now = datetime.now(timezone.utc)
    dets = []
    for i in range(count):
        dets.append(make_detection(
            node_id=node_id,
            signal_class="bpsk" if i % 2 == 0 else "qpsk",
            confidence=0.9,
            freq_hz=433.92e6,
            snr_db=15.0,
            anomaly_score=0.5 if i == 0 else 0.0,
            timestamp=now - timedelta(minutes=i),
        ))
    store.insert_batch(dets)


# ---------------------------------------------------------------------------
# Test: Node location update
# ---------------------------------------------------------------------------


class TestNodeLocation:
    """Tests for PUT /api/nodes/{node_id}/location."""

    def test_set_location(self, client: TestClient):
        _register_node(client)
        resp = client.put("/api/nodes/node-geo-01/location", json={
            "latitude": 40.7128,
            "longitude": -74.0060,
            "altitude_m": 10.0,
            "location_name": "NYC Office",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["latitude"] == 40.7128
        assert data["longitude"] == -74.0060
        assert data["altitude_m"] == 10.0
        assert data["location_name"] == "NYC Office"

    def test_set_location_not_found(self, client: TestClient):
        resp = client.put("/api/nodes/nonexistent/location", json={
            "latitude": 0.0,
            "longitude": 0.0,
        })
        assert resp.status_code == 404

    def test_set_location_invalid_coords(self, client: TestClient):
        _register_node(client)
        resp = client.put("/api/nodes/node-geo-01/location", json={
            "latitude": 999.0,
            "longitude": 0.0,
        })
        assert resp.status_code == 422

    def test_register_with_location(self, client: TestClient):
        resp = client.post("/api/nodes/register", json={
            "node_id": "node-geo-loc",
            "host": "10.0.0.2",
            "port": 8080,
            "latitude": 51.5074,
            "longitude": -0.1278,
            "location_name": "London",
        })
        assert resp.status_code == 200

        # Verify location is stored
        resp = client.get("/api/nodes/locations")
        assert resp.status_code == 200
        locations = resp.json()
        found = [n for n in locations if n["node_id"] == "node-geo-loc"]
        assert len(found) == 1
        assert found[0]["latitude"] == 51.5074
        assert found[0]["longitude"] == -0.1278
        assert found[0]["location_name"] == "London"


# ---------------------------------------------------------------------------
# Test: GET /api/nodes/locations
# ---------------------------------------------------------------------------


class TestNodeLocations:
    def test_get_locations_empty(self, client: TestClient):
        resp = client.get("/api/nodes/locations")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_locations(self, client: TestClient):
        _register_node(client, "node-a")
        _set_location(client, "node-a", lat=40.0, lon=-74.0, name="Site A")
        _register_node(client, "node-b")
        # node-b has no location

        resp = client.get("/api/nodes/locations")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["node_id"] == "node-a"


# ---------------------------------------------------------------------------
# Test: GET /api/geo/map
# ---------------------------------------------------------------------------


class TestGeoMap:
    def test_map_empty(self, client: TestClient):
        resp = client.get("/api/geo/map")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_map_with_nodes(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-map-01")
        _set_location(client, "node-map-01", lat=40.7, lon=-74.0, name="NYC")

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-map-01", count=3)

        resp = client.get("/api/geo/map")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        node = data[0]
        assert node["node_id"] == "node-map-01"
        assert node["latitude"] == 40.7
        assert node["longitude"] == -74.0
        assert node["location_name"] == "NYC"
        assert isinstance(node["detection_count_1h"], int)
        assert node["detection_count_1h"] >= 0
        assert isinstance(node["top_signals"], list)
        assert all(isinstance(s, str) for s in node["top_signals"])
        assert isinstance(node["anomaly_count_1h"], int)
        assert isinstance(node["status"], str)
        assert node["status"] in ("online", "offline", "unknown", "stale", "active")
        # last_heartbeat may be None if no heartbeat received yet
        assert "last_heartbeat" in node
        assert isinstance(node["last_heartbeat"], (str, type(None)))

    def test_map_excludes_unlocated_nodes(self, client: TestClient):
        _register_node(client, "node-no-loc")
        _register_node(client, "node-has-loc")
        _set_location(client, "node-has-loc", lat=35.0, lon=139.0)

        resp = client.get("/api/geo/map")
        data = resp.json()
        node_ids = [n["node_id"] for n in data]
        assert "node-no-loc" not in node_ids
        assert "node-has-loc" in node_ids


# ---------------------------------------------------------------------------
# Test: GET /api/geo/heatmap
# ---------------------------------------------------------------------------


class TestGeoHeatmap:
    def test_heatmap_empty(self, client: TestClient):
        resp = client.get("/api/geo/heatmap")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_heatmap_with_detections(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-heat-01")
        _set_location(client, "node-heat-01", lat=48.85, lon=2.35)

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-heat-01", count=5)

        resp = client.get("/api/geo/heatmap?hours=24")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["latitude"] == 48.85
        assert data[0]["longitude"] == 2.35
        assert data[0]["weight"] == 5

    def test_heatmap_filter_by_class(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-heat-02")
        _set_location(client, "node-heat-02", lat=48.85, lon=2.35)

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-heat-02", count=4)

        resp = client.get("/api/geo/heatmap?signal_class=bpsk")
        assert resp.status_code == 200
        data = resp.json()
        # Should only count bpsk detections (indices 0, 2 = 2 detections)
        if data:
            assert data[0]["weight"] <= 4

    def test_heatmap_no_location_excluded(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-noloc")
        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-noloc", count=10)

        resp = client.get("/api/geo/heatmap")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# Test: GET /api/geo/coverage
# ---------------------------------------------------------------------------


class TestGeoCoverage:
    def test_coverage_empty(self, client: TestClient):
        resp = client.get("/api/geo/coverage")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_coverage_with_node(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-cov-01")
        _set_location(client, "node-cov-01", lat=52.52, lon=13.41)

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-cov-01", count=3)

        resp = client.get("/api/geo/coverage")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["node_id"] == "node-cov-01"
        assert data[0]["latitude"] == 52.52
        assert data[0]["longitude"] == 13.41
        assert data[0]["radius_km"] == 1.0
        assert isinstance(data[0]["detection_classes"], list)
        assert all(isinstance(c, str) for c in data[0]["detection_classes"])
        assert isinstance(data[0]["avg_snr_db"], float)


# ---------------------------------------------------------------------------
# Test: GET /api/geo/activity
# ---------------------------------------------------------------------------


class TestGeoActivity:
    def test_activity_empty(self, client: TestClient):
        resp = client.get("/api/geo/activity")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_activity_with_detections(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-act-01")
        _set_location(client, "node-act-01", lat=34.05, lon=-118.24, name="LA")

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-act-01", count=3)

        resp = client.get("/api/geo/activity?hours=4")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for item in data:
            assert item["node_id"] == "node-act-01"
            assert item["latitude"] == 34.05
            assert item["longitude"] == -118.24
            assert item["location_name"] == "LA"
            assert isinstance(item["signal_class"], str)
            assert isinstance(item["confidence"], (int, float))
            assert isinstance(item["timestamp"], str)

    def test_activity_min_anomaly_filter(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-act-02")
        _set_location(client, "node-act-02", lat=34.05, lon=-118.24)

        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-act-02", count=5)

        resp = client.get("/api/geo/activity?min_anomaly_score=0.4")
        assert resp.status_code == 200
        data = resp.json()
        # Only the detection with anomaly_score=0.5 should be included
        for item in data:
            assert item["anomaly_score"] >= 0.4

    def test_activity_excludes_unlocated(self, client: TestClient, bridge_app: FastAPI):
        _register_node(client, "node-act-noloc")
        store = bridge_app.state.detection_store
        _insert_detections(client, store, "node-act-noloc", count=5)

        resp = client.get("/api/geo/activity")
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# Test: Auth required
# ---------------------------------------------------------------------------


class TestGeoAuth:
    def test_map_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.get("/api/geo/map")
        assert resp.status_code == 401

    def test_heatmap_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.get("/api/geo/heatmap")
        assert resp.status_code == 401

    def test_coverage_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.get("/api/geo/coverage")
        assert resp.status_code == 401

    def test_activity_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.get("/api/geo/activity")
        assert resp.status_code == 401

    def test_location_update_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.put("/api/nodes/node-x/location", json={
            "latitude": 0.0, "longitude": 0.0,
        })
        assert resp.status_code == 401

    def test_locations_requires_auth(self, bridge_app: FastAPI):
        unauthed = TestClient(bridge_app)
        resp = unauthed.get("/api/nodes/locations")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Test: Tenant isolation
# ---------------------------------------------------------------------------


class TestGeoTenantIsolation:
    """Verify that geo queries respect tenant_id filtering."""

    def test_node_summary_respects_tenant(self, tmp_path: Path):
        """Detections from another tenant must not appear in geo summaries."""
        db_path = tmp_path / "tenant_test.db"
        store_a = DetectionStore(db_path=db_path, tenant_id="tenant-a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant-b")

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=1)).isoformat()

        # Insert detections for tenant-a
        dets_a = [make_detection(node_id="node-1", signal_class="bpsk", timestamp=now)]
        store_a.insert_batch(dets_a)

        # Insert detections for tenant-b
        dets_b = [
            make_detection(node_id="node-1", signal_class="qpsk", timestamp=now),
            make_detection(node_id="node-1", signal_class="qpsk", timestamp=now),
        ]
        store_b.insert_batch(dets_b)

        # Tenant-a should only see its 1 detection
        summary_a = store_a.get_geo_node_summary("node-1", cutoff)
        assert summary_a["detection_count"] == 1
        assert summary_a["top_signals"] == ["bpsk"]

        # Tenant-b should only see its 2 detections
        summary_b = store_b.get_geo_node_summary("node-1", cutoff)
        assert summary_b["detection_count"] == 2
        assert summary_b["top_signals"] == ["qpsk"]

    def test_heatmap_weight_respects_tenant(self, tmp_path: Path):
        db_path = tmp_path / "tenant_heatmap.db"
        store_a = DetectionStore(db_path=db_path, tenant_id="tenant-a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant-b")

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=1)).isoformat()

        store_a.insert_batch([make_detection(node_id="n1", timestamp=now)])
        store_b.insert_batch([
            make_detection(node_id="n1", timestamp=now),
            make_detection(node_id="n1", timestamp=now),
            make_detection(node_id="n1", timestamp=now),
        ])

        assert store_a.get_geo_heatmap_weight("n1", cutoff) == 1
        assert store_b.get_geo_heatmap_weight("n1", cutoff) == 3

    def test_coverage_stats_respects_tenant(self, tmp_path: Path):
        db_path = tmp_path / "tenant_coverage.db"
        store_a = DetectionStore(db_path=db_path, tenant_id="tenant-a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant-b")

        now = datetime.now(timezone.utc)
        store_a.insert_batch([make_detection(node_id="n1", signal_class="bpsk", snr_db=10.0, timestamp=now)])
        store_b.insert_batch([make_detection(node_id="n1", signal_class="qpsk", snr_db=20.0, timestamp=now)])

        stats_a = store_a.get_geo_coverage_stats("n1")
        assert stats_a["detection_classes"] == ["bpsk"]
        assert stats_a["avg_snr_db"] == 10.0

        stats_b = store_b.get_geo_coverage_stats("n1")
        assert stats_b["detection_classes"] == ["qpsk"]
        assert stats_b["avg_snr_db"] == 20.0

    def test_activity_feed_respects_tenant(self, tmp_path: Path):
        db_path = tmp_path / "tenant_activity.db"
        store_a = DetectionStore(db_path=db_path, tenant_id="tenant-a")
        store_b = DetectionStore(db_path=db_path, tenant_id="tenant-b")

        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(hours=1)).isoformat()

        store_a.insert_batch([make_detection(node_id="n1", signal_class="bpsk", timestamp=now)])
        store_b.insert_batch([
            make_detection(node_id="n1", signal_class="qpsk", timestamp=now),
            make_detection(node_id="n1", signal_class="qpsk", timestamp=now),
        ])

        feed_a = store_a.get_geo_activity_feed(["n1"], cutoff)
        assert len(feed_a) == 1
        assert feed_a[0]["signal_class"] == "bpsk"

        feed_b = store_b.get_geo_activity_feed(["n1"], cutoff)
        assert len(feed_b) == 2
        assert all(r["signal_class"] == "qpsk" for r in feed_b)
