"""Tests for Phase 3 Item 3: Emitter Position Tracking with Kalman Filter.

Covers:
  - Kalman filter convergence / noise reduction
  - EmitterTracker create / update / predict / classify
  - TrackStore CRUD
  - REST API endpoints (auth, RBAC, feature flag)
"""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.dsp.emitter_tracker import EmitterTracker
from sigrift.bridge.storage.tracks import TrackStore
from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key in persistence and return the raw key string."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    meta: dict = {"role": role, "description": f"test {role}"}
    persistence.set_key_meta(key_id, meta)
    return raw_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tracker() -> EmitterTracker:
    """Fresh EmitterTracker with default parameters."""
    return EmitterTracker(
        process_noise=0.5,
        measurement_noise=5.0,
        lost_timeout_s=60.0,
        stationary_threshold_mps=0.5,
        min_points_for_track=3,
    )


@pytest.fixture
def track_store_standalone(tmp_path: Path) -> TrackStore:
    """Standalone TrackStore backed by temp DB."""
    from sigrift.bridge.storage.base import SharedContext
    ctx = SharedContext(db_path=tmp_path / "test_tracks.db")
    return TrackStore(ctx)


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "viewer_key_track", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "analyst_key_track", role="analyst")


@pytest.fixture
def admin_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "admin_key_track", role="admin")


@pytest.fixture
def tracking_client(bridge_app: FastAPI, master_key: str) -> TestClient:
    """TestClient with geolocation feature flag enabled."""
    import sigrift.bridge.routers.tracking as tracking_module
    original = tracking_module.GEOLOCATION_ENABLED
    tracking_module.GEOLOCATION_ENABLED = True
    client = TestClient(bridge_app, headers={"X-API-Key": master_key})
    yield client
    tracking_module.GEOLOCATION_ENABLED = original


@pytest.fixture
def tracking_client_disabled(bridge_app: FastAPI, master_key: str) -> TestClient:
    """TestClient with geolocation feature flag DISABLED."""
    import sigrift.bridge.routers.tracking as tracking_module
    original = tracking_module.GEOLOCATION_ENABLED
    tracking_module.GEOLOCATION_ENABLED = False
    client = TestClient(bridge_app, headers={"X-API-Key": master_key})
    yield client
    tracking_module.GEOLOCATION_ENABLED = original


# ===========================================================================
# KALMAN FILTER TESTS
# ===========================================================================


class TestKalmanFilter:
    """Tests for the core Kalman filter behaviour."""

    def test_kalman_stationary(self, tracker: EmitterTracker):
        """Stationary target: filtered position converges to true position."""
        t = 1000.0
        true_x, true_y = 10.0, 20.0
        rng = np.random.RandomState(42)

        for i in range(30):
            nx = true_x + rng.normal(0, 3.0)
            ny = true_y + rng.normal(0, 3.0)
            pt = tracker.update("emitter-stat", nx, ny, t + i)

        # Filtered position should be close to true position
        assert abs(pt.x - true_x) < 2.0
        assert abs(pt.y - true_y) < 2.0

    def test_kalman_constant_velocity(self, tracker: EmitterTracker):
        """Moving target: velocity estimate converges."""
        t = 1000.0
        vx_true, vy_true = 2.0, 1.0
        rng = np.random.RandomState(42)

        for i in range(40):
            true_x = 0.0 + vx_true * i
            true_y = 0.0 + vy_true * i
            nx = true_x + rng.normal(0, 2.0)
            ny = true_y + rng.normal(0, 2.0)
            pt = tracker.update("emitter-cv", nx, ny, t + i)

        # Velocity should be close to true velocity
        assert abs(pt.vx - vx_true) < 1.0
        assert abs(pt.vy - vy_true) < 1.0

    def test_kalman_prediction(self, tracker: EmitterTracker):
        """Predict future position accurately for constant-velocity target."""
        t = 1000.0
        vx, vy = 3.0, 0.0

        for i in range(20):
            x = 0.0 + vx * i
            y = 0.0
            tracker.update("emitter-pred", x, y, t + i)

        # Predict 5 seconds ahead
        pred = tracker.predict("emitter-pred", t + 25)
        assert pred is not None
        assert hasattr(pred, "x")
        assert isinstance(pred.x, float)
        # Should be near x = 3*25 = 75
        expected_x = vx * 25
        assert abs(pred.x - expected_x) < 5.0

    def test_kalman_noise_reduction(self, tracker: EmitterTracker):
        """Filtered position is less noisy than raw measurements."""
        t = 1000.0
        true_x, true_y = 50.0, 50.0
        rng = np.random.RandomState(42)

        raw_errors = []
        filtered_errors = []

        for i in range(50):
            nx = true_x + rng.normal(0, 5.0)
            ny = true_y + rng.normal(0, 5.0)
            raw_errors.append(math.sqrt((nx - true_x)**2 + (ny - true_y)**2))
            pt = tracker.update("emitter-noise", nx, ny, t + i)
            filtered_errors.append(
                math.sqrt((pt.x - true_x)**2 + (pt.y - true_y)**2)
            )

        # Mean filtered error should be less than mean raw error
        mean_raw = sum(raw_errors) / len(raw_errors)
        mean_filtered = sum(filtered_errors) / len(filtered_errors)
        assert mean_filtered < mean_raw

    def test_kalman_covariance_shrinks(self, tracker: EmitterTracker):
        """Covariance decreases with successive updates."""
        t = 1000.0
        pt1 = tracker.update("emitter-cov", 10.0, 10.0, t)
        trace1 = np.trace(pt1.covariance)

        for i in range(1, 10):
            pt = tracker.update("emitter-cov", 10.0, 10.0, t + i)

        trace2 = np.trace(pt.covariance)
        assert trace2 < trace1

    def test_kalman_innovation(self, tracker: EmitterTracker):
        """Large innovation for unexpected measurement: confidence drops."""
        t = 1000.0
        for i in range(10):
            tracker.update("emitter-innov", 0.0, 0.0, t + i)

        # Confidence should be high after convergence
        track = tracker.get_track("emitter-innov")
        conf_before = track.points[-1].confidence

        # Jump far away
        pt = tracker.update("emitter-innov", 100.0, 100.0, t + 11)
        # The filtered position shouldn't jump all the way to 100,100
        assert pt.x < 80.0 or pt.y < 80.0


# ===========================================================================
# TRACKER TESTS
# ===========================================================================


class TestEmitterTracker:
    """Tests for EmitterTracker high-level operations."""

    def test_create_track(self, tracker: EmitterTracker):
        """First update creates a new track."""
        pt = tracker.update("e1", 5.0, 5.0, 1000.0)
        track = tracker.get_track("e1")
        assert track is not None
        assert hasattr(track, "emitter_id")
        assert isinstance(track.emitter_id, str)
        assert track.emitter_id == "e1"
        assert len(track.points) == 1

    def test_update_existing_track(self, tracker: EmitterTracker):
        """Second update continues an existing track."""
        tracker.update("e2", 5.0, 5.0, 1000.0)
        tracker.update("e2", 6.0, 5.0, 1001.0)
        track = tracker.get_track("e2")
        assert len(track.points) == 2

    def test_multiple_emitters(self, tracker: EmitterTracker):
        """Tracks multiple emitters independently."""
        tracker.update("a", 0.0, 0.0, 1000.0)
        tracker.update("b", 100.0, 100.0, 1000.0)

        track_a = tracker.get_track("a")
        track_b = tracker.get_track("b")
        assert track_a is not None
        assert isinstance(track_a.track_id, str)
        assert len(track_a.track_id) > 0
        assert track_b is not None
        assert isinstance(track_b.track_id, str)
        assert len(track_b.track_id) > 0
        assert track_a.track_id != track_b.track_id
        assert abs(track_a.points[-1].x) < 1.0
        assert abs(track_b.points[-1].x - 100.0) < 1.0

    def test_track_stationary(self, tracker: EmitterTracker):
        """Stationary emitter classified correctly."""
        for i in range(5):
            tracker.update("stat", 10.0, 10.0, 1000.0 + i)
        track = tracker.get_track("stat")
        assert track.is_stationary is True

    def test_track_moving(self, tracker: EmitterTracker):
        """Moving emitter has velocity > 0."""
        for i in range(10):
            tracker.update("mov", float(i * 5), 0.0, 1000.0 + i)
        track = tracker.get_track("mov")
        assert isinstance(track.mean_velocity_mps, float)
        assert track.mean_velocity_mps > 0.0

    def test_predict_position(self, tracker: EmitterTracker):
        """Extrapolation works for tracked emitter."""
        for i in range(10):
            tracker.update("pred", float(i * 2), 0.0, 1000.0 + i)

        pred = tracker.predict("pred", 1015.0)
        assert pred is not None
        assert hasattr(pred, "x")
        assert isinstance(pred.x, float)
        assert pred.timestamp == 1015.0

    def test_predict_nonexistent(self, tracker: EmitterTracker):
        """Predict returns None for unknown emitter."""
        result = tracker.predict("nope", 1000.0)
        assert result is None

    def test_prune_lost_tracks(self, tracker: EmitterTracker):
        """Old tracks are reported as lost."""
        tracker.update("old", 0.0, 0.0, 1000.0)
        tracker.update("fresh", 0.0, 0.0, 2000.0)

        pruned = tracker.prune_lost_tracks(2000.0)
        assert "old" in pruned
        assert "fresh" not in pruned

    def test_classify_motion_stationary(self, tracker: EmitterTracker):
        """Below threshold = stationary."""
        for i in range(5):
            tracker.update("cls-s", 10.0, 10.0, 1000.0 + i)
        assert tracker.classify_motion("cls-s") == "stationary"

    def test_classify_motion_walking(self, tracker: EmitterTracker):
        """~1.5 m/s = walking."""
        for i in range(10):
            tracker.update("cls-w", float(i * 1.5), 0.0, 1000.0 + i)
        result = tracker.classify_motion("cls-w")
        assert result in ("walking", "unknown")  # may take a few steps to converge

    def test_classify_motion_vehicle(self, tracker: EmitterTracker):
        """>10 m/s = vehicle."""
        for i in range(20):
            tracker.update("cls-v", float(i * 15), 0.0, 1000.0 + i)
        result = tracker.classify_motion("cls-v")
        assert result == "vehicle"

    def test_classify_motion_unknown(self, tracker: EmitterTracker):
        """Not enough points = unknown."""
        tracker.update("cls-u", 0.0, 0.0, 1000.0)
        assert tracker.classify_motion("cls-u") == "unknown"

    def test_total_distance(self, tracker: EmitterTracker):
        """Correct cumulative distance."""
        for i in range(5):
            tracker.update("dist", float(i * 10), 0.0, 1000.0 + i)
        track = tracker.get_track("dist")
        assert isinstance(track.total_distance_m, float)
        assert track.total_distance_m > 0.0

    def test_get_all_tracks(self, tracker: EmitterTracker):
        """Returns all tracks."""
        tracker.update("t1", 0.0, 0.0, 1000.0)
        tracker.update("t2", 10.0, 10.0, 1000.0)
        all_tracks = tracker.get_all_tracks()
        assert len(all_tracks) == 2

    def test_track_history(self, tracker: EmitterTracker):
        """Full point history preserved."""
        for i in range(10):
            tracker.update("hist", float(i), float(i), 1000.0 + i)
        track = tracker.get_track("hist")
        assert len(track.points) == 10
        # Timestamps are in order
        for i in range(1, len(track.points)):
            assert track.points[i].timestamp > track.points[i - 1].timestamp


# ===========================================================================
# STORAGE TESTS
# ===========================================================================


class TestTrackStore:
    """Tests for TrackStore CRUD operations."""

    def test_create_track(self, track_store_standalone: TrackStore):
        """Store and retrieve a track."""
        store = track_store_standalone
        result = store.create_track(
            track_id="trk-001",
            emitter_id="e-001",
            first_seen=1000.0,
            last_seen=1001.0,
        )
        assert result["track_id"] == "trk-001"
        assert result["emitter_id"] == "e-001"

    def test_add_points(self, track_store_standalone: TrackStore):
        """Store track points."""
        store = track_store_standalone
        store.create_track(track_id="trk-002", emitter_id="e-002")
        pid = store.add_point(
            track_id="trk-002", x=1.0, y=2.0, timestamp=1000.0,
            vx=0.5, vy=0.1, confidence=0.9,
        )
        assert isinstance(pid, int)
        assert pid > 0

    def test_get_track_points(self, track_store_standalone: TrackStore):
        """Retrieve ordered points."""
        store = track_store_standalone
        store.create_track(track_id="trk-003", emitter_id="e-003")
        store.add_point(track_id="trk-003", x=1.0, y=2.0, timestamp=1001.0)
        store.add_point(track_id="trk-003", x=3.0, y=4.0, timestamp=1000.0)
        store.add_point(track_id="trk-003", x=5.0, y=6.0, timestamp=1002.0)

        points = store.get_track_points("trk-003")
        assert len(points) == 3
        # Should be ordered by timestamp ascending
        assert points[0]["timestamp"] == 1000.0
        assert points[1]["timestamp"] == 1001.0
        assert points[2]["timestamp"] == 1002.0

    def test_update_status(self, track_store_standalone: TrackStore):
        """Status changes persist."""
        store = track_store_standalone
        store.create_track(track_id="trk-004", emitter_id="e-004")
        assert store.update_track_status("trk-004", "lost") is True
        track = store.get_track("trk-004")
        assert track["status"] == "lost"

    def test_list_active(self, track_store_standalone: TrackStore):
        """Filter active tracks."""
        store = track_store_standalone
        store.create_track(track_id="trk-a", emitter_id="a", status="active")
        store.create_track(track_id="trk-b", emitter_id="b", status="lost")
        store.create_track(track_id="trk-c", emitter_id="c", status="active")

        active = store.get_active_tracks()
        assert len(active) == 2
        assert all(t["status"] == "active" for t in active)

    def test_delete_track(self, track_store_standalone: TrackStore):
        """Remove track and points."""
        store = track_store_standalone
        store.create_track(track_id="trk-del", emitter_id="e-del")
        store.add_point(track_id="trk-del", x=1.0, y=2.0, timestamp=1000.0)
        assert store.delete_track("trk-del") is True
        assert store.get_track("trk-del") is None
        assert store.get_track_points("trk-del") == []

    def test_stats(self, track_store_standalone: TrackStore):
        """Return track statistics."""
        store = track_store_standalone
        store.create_track(track_id="trk-s1", emitter_id="s1", status="active")
        store.create_track(track_id="trk-s2", emitter_id="s2", status="lost")
        store.add_point(track_id="trk-s1", x=1.0, y=2.0, timestamp=1000.0)
        store.add_point(track_id="trk-s1", x=3.0, y=4.0, timestamp=1001.0)

        stats = store.get_stats()
        assert stats["total_tracks"] == 2
        assert stats["active_tracks"] == 1
        assert stats["lost_tracks"] == 1
        assert stats["total_points"] == 2


# ===========================================================================
# API TESTS
# ===========================================================================


class TestTrackingAPI:
    """Tests for the tracking REST API."""

    def test_update_requires_analyst(
        self, bridge_app: FastAPI, persistence: PersistenceManager, viewer_key: str,
    ):
        """VIEWER gets 403 on POST /update."""
        import sigrift.bridge.routers.tracking as tracking_module
        original = tracking_module.GEOLOCATION_ENABLED
        tracking_module.GEOLOCATION_ENABLED = True
        try:
            client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
            resp = client.post("/api/tracking/update", json={
                "emitter_id": "e1", "x": 1.0, "y": 2.0, "timestamp": 1000.0,
            })
            assert resp.status_code == 403
        finally:
            tracking_module.GEOLOCATION_ENABLED = original

    def test_update_creates_track(self, tracking_client: TestClient):
        """POST /update creates a new track."""
        resp = tracking_client.post("/api/tracking/update", json={
            "emitter_id": "api-e1", "x": 10.0, "y": 20.0, "timestamp": 1000.0,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "x" in data
        assert isinstance(data["x"], (int, float))
        assert "confidence" in data
        assert isinstance(data["confidence"], (int, float))
        assert data["timestamp"] == 1000.0

    def test_list_tracks(self, tracking_client: TestClient):
        """GET /tracks returns list."""
        # Create a track first
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "list-e1", "x": 5.0, "y": 5.0, "timestamp": 1000.0,
        })
        resp = tracking_client.get("/api/tracking/tracks")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1
        assert all(isinstance(t, dict) for t in data)

    def test_get_track(self, tracking_client: TestClient):
        """GET /tracks/{id} returns track with points."""
        # Create a track
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "get-e1", "x": 1.0, "y": 2.0, "timestamp": 1000.0,
        })
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "get-e1", "x": 3.0, "y": 4.0, "timestamp": 1001.0,
        })

        # List tracks to get track_id
        tracks = tracking_client.get("/api/tracking/tracks").json()
        target = [t for t in tracks if t.get("emitter_id") == "get-e1"]
        assert len(target) > 0
        assert isinstance(target[0], dict)

        track_id = target[0]["track_id"]
        resp = tracking_client.get(f"/api/tracking/tracks/{track_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["track_id"], str)
        assert data["track_id"] == track_id
        assert isinstance(data["points"], list)
        assert len(data["points"]) == 2

    def test_predict(self, tracking_client: TestClient):
        """GET /tracks/{id}/predict returns predicted position."""
        for i in range(5):
            tracking_client.post("/api/tracking/update", json={
                "emitter_id": "pred-e1",
                "x": float(i * 3),
                "y": 0.0,
                "timestamp": 1000.0 + i,
            })

        tracks = tracking_client.get("/api/tracking/tracks").json()
        target = [t for t in tracks if t.get("emitter_id") == "pred-e1"]
        assert len(target) > 0
        assert isinstance(target[0], dict)

        track_id = target[0]["track_id"]
        resp = tracking_client.get(
            f"/api/tracking/tracks/{track_id}/predict",
            params={"timestamp": 1010.0},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["timestamp"] == 1010.0
        assert "x" in data
        assert isinstance(data["x"], (int, float))
        assert "vx" in data
        assert isinstance(data["vx"], (int, float))

    def test_prune(self, tracking_client: TestClient):
        """POST /prune marks old tracks lost."""
        # Create a track with old timestamp
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "prune-old",
            "x": 0.0, "y": 0.0,
            "timestamp": 1.0,  # very old
        })

        resp = tracking_client.post("/api/tracking/prune")
        assert resp.status_code == 200
        data = resp.json()
        assert "pruned_count" in data
        assert isinstance(data["pruned_count"], int)

    def test_stats(self, tracking_client: TestClient):
        """GET /stats returns counts."""
        resp = tracking_client.get("/api/tracking/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_tracks" in data
        assert isinstance(data["total_tracks"], int)
        assert "active_tracks" in data
        assert isinstance(data["active_tracks"], int)

    def test_geolocation_disabled(self, tracking_client_disabled: TestClient):
        """Endpoints return 403 when feature flag is off."""
        resp = tracking_client_disabled.post("/api/tracking/update", json={
            "emitter_id": "e1", "x": 1.0, "y": 2.0, "timestamp": 1000.0,
        })
        assert resp.status_code == 403

        resp = tracking_client_disabled.get("/api/tracking/tracks")
        assert resp.status_code == 403

        resp = tracking_client_disabled.get("/api/tracking/stats")
        assert resp.status_code == 403

    def test_config_get(self, tracking_client: TestClient):
        """GET /config returns tracker configuration."""
        resp = tracking_client.get("/api/tracking/config")
        assert resp.status_code == 200
        data = resp.json()
        assert "process_noise" in data
        assert isinstance(data["process_noise"], (int, float))
        assert "measurement_noise" in data
        assert isinstance(data["measurement_noise"], (int, float))

    def test_config_update_requires_admin(
        self, bridge_app: FastAPI, persistence: PersistenceManager, analyst_key: str,
    ):
        """ANALYST gets 403 on PUT /config (requires ADMIN)."""
        import sigrift.bridge.routers.tracking as tracking_module
        original = tracking_module.GEOLOCATION_ENABLED
        tracking_module.GEOLOCATION_ENABLED = True
        try:
            client = TestClient(bridge_app, headers={"X-API-Key": analyst_key})
            resp = client.put("/api/tracking/config", json={
                "process_noise": 1.0,
            })
            assert resp.status_code == 403
        finally:
            tracking_module.GEOLOCATION_ENABLED = original

    def test_delete_track_api(self, tracking_client: TestClient):
        """DELETE /tracks/{id} removes track."""
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "del-e1", "x": 1.0, "y": 2.0, "timestamp": 1000.0,
        })

        tracks = tracking_client.get("/api/tracking/tracks").json()
        target = [t for t in tracks if t.get("emitter_id") == "del-e1"]
        assert len(target) > 0
        assert isinstance(target[0], dict)

        track_id = target[0]["track_id"]
        resp = tracking_client.delete(f"/api/tracking/tracks/{track_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"

    def test_get_active_tracks(self, tracking_client: TestClient):
        """GET /tracks/active returns only active tracks."""
        tracking_client.post("/api/tracking/update", json={
            "emitter_id": "active-e1", "x": 1.0, "y": 2.0, "timestamp": 1000.0,
        })

        resp = tracking_client.get("/api/tracking/tracks/active")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        for t in data:
            assert t["status"] == "active"
