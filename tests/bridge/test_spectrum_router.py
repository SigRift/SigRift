"""Tests for spectrum occupancy analysis endpoints.

Covers all four /api/spectrum/* endpoints: occupancy, waterfall,
bands, and activity.  Tests response structure, frequency binning,
time bucketing, empty database, node_id filtering, and auth.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_sample_detections(
    store: DetectionStore,
    *,
    node_id: str = "node-test-01",
    count: int = 20,
    freq_hz: float = 433.92e6,
    signal_class: str = "bpsk",
    power_dbm: float = -45.0,
) -> list[DetectionRecord]:
    """Insert sample detections spread over the last hour."""
    now = datetime.now(timezone.utc)
    dets = []
    for i in range(count):
        det = make_detection(
            node_id=node_id,
            signal_class=signal_class,
            freq_hz=freq_hz,
            power_dbm=power_dbm,
            timestamp=now - timedelta(minutes=i * 2),
        )
        dets.append(det)
    store.insert_batch(dets)
    return dets

# ---------------------------------------------------------------------------
# Occupancy endpoint
# ---------------------------------------------------------------------------

class TestOccupancy:
    """Tests for GET /api/spectrum/occupancy."""

    def test_empty_database(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/occupancy")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 24
        assert data["bin_width_hz"] == 1_000_000
        assert data["bins"] == []

    def test_returns_bins(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/occupancy?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["bins"]) > 0
        b = data["bins"][0]
        assert isinstance(b["center_freq_hz"], (int, float))
        assert isinstance(b["bin_width_hz"], int)
        assert isinstance(b["occupancy_pct"], (int, float))
        assert isinstance(b["avg_power_dbm"], (int, float))
        assert isinstance(b["peak_power_dbm"], (int, float))
        assert isinstance(b["signal_count"], int)
        assert isinstance(b["dominant_class"], str)
        assert isinstance(b["first_seen"], str)
        assert isinstance(b["last_seen"], str)

    def test_custom_bin_width(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/occupancy?bin_width_hz=5000000")
        assert resp.status_code == 200
        data = resp.json()
        assert data["bin_width_hz"] == 5_000_000

    def test_node_id_filter(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(
            detection_store, node_id=registered_node, freq_hz=433.92e6,
        )
        resp = client.get("/api/spectrum/occupancy?node_id=nonexistent-node")
        assert resp.status_code == 200
        assert resp.json()["bins"] == []

    def test_frequency_binning(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Detections at different frequencies should land in different bins."""
        _insert_sample_detections(
            detection_store, node_id=registered_node,
            freq_hz=433.92e6, count=5, signal_class="bpsk",
        )
        _insert_sample_detections(
            detection_store, node_id=registered_node,
            freq_hz=915.0e6, count=5, signal_class="qam16",
        )
        resp = client.get("/api/spectrum/occupancy?hours=2&bin_width_hz=1000000")
        assert resp.status_code == 200
        bins = resp.json()["bins"]
        freq_centers = [b["center_freq_hz"] for b in bins]
        assert len(set(freq_centers)) >= 2

# ---------------------------------------------------------------------------
# Waterfall endpoint
# ---------------------------------------------------------------------------

class TestWaterfall:
    """Tests for GET /api/spectrum/waterfall."""

    def test_empty_database(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/waterfall")
        assert resp.status_code == 200
        data = resp.json()
        assert data["time_bins"] == []
        assert data["freq_bins"] == []
        assert data["power_matrix"] == []
        assert data["signal_matrix"] == []

    def test_returns_matrix(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/waterfall?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["time_bins"]) > 0
        assert len(data["freq_bins"]) > 0
        assert len(data["power_matrix"]) == len(data["time_bins"])
        if data["power_matrix"]:
            assert len(data["power_matrix"][0]) == len(data["freq_bins"])

    def test_freq_range_filter(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(
            detection_store, node_id=registered_node, freq_hz=433.92e6,
        )
        resp = client.get(
            "/api/spectrum/waterfall?hours=2&freq_min_hz=900000000&freq_max_hz=1000000000"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["time_bins"] == []

    def test_time_bucketing(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Multiple detections in the same time bucket should be aggregated."""
        _insert_sample_detections(
            detection_store, node_id=registered_node, count=10,
        )
        resp = client.get(
            "/api/spectrum/waterfall?hours=2&time_resolution_sec=600"
        )
        assert resp.status_code == 200
        data = resp.json()
        # With 600s resolution and detections every 2 min, we should have
        # fewer time bins than detections
        assert len(data["time_bins"]) <= 10

    def test_node_id_filter(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/waterfall?node_id=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["time_bins"] == []

# ---------------------------------------------------------------------------
# Bands endpoint
# ---------------------------------------------------------------------------

class TestBands:
    """Tests for GET /api/spectrum/bands."""

    def test_empty_database(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/bands")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["bands"], list)
        assert len(data["bands"]) > 0
        b = data["bands"][0]
        assert isinstance(b["band"], str)
        assert isinstance(b["min_hz"], (int, float))
        assert isinstance(b["max_hz"], (int, float))
        assert isinstance(b["signal_count"], int)
        assert isinstance(b["occupancy_pct"], (int, float))

    def test_matching_band(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Detections at 433.92 MHz should appear in the UHF 433 ISM band."""
        _insert_sample_detections(
            detection_store, node_id=registered_node, freq_hz=433.92e6,
        )
        resp = client.get("/api/spectrum/bands?hours=2")
        assert resp.status_code == 200
        bands = resp.json()["bands"]
        ism_band = next(
            (b for b in bands if b["band"] == "UHF 433 ISM"), None,
        )
        assert isinstance(ism_band, dict)
        assert ism_band["signal_count"] > 0
        assert ism_band["occupancy_pct"] > 0

    def test_node_id_filter(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/bands?node_id=nonexistent")
        assert resp.status_code == 200
        bands = resp.json()["bands"]
        assert all(b["signal_count"] == 0 for b in bands)

# ---------------------------------------------------------------------------
# Activity endpoint
# ---------------------------------------------------------------------------

class TestActivity:
    """Tests for GET /api/spectrum/activity."""

    def test_empty_database(self, client: TestClient) -> None:
        resp = client.get("/api/spectrum/activity")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["activity"] == []

    def test_returns_detections(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(
            detection_store, node_id=registered_node, count=5,
        )
        resp = client.get("/api/spectrum/activity?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 5
        a = data["activity"][0]
        assert isinstance(a["timestamp"], str)
        assert isinstance(a["freq_hz"], (int, float))
        assert isinstance(a["signal_class"], str)
        assert isinstance(a["power_dbm"], (int, float))
        assert isinstance(a["node_id"], str)

    def test_limit(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(
            detection_store, node_id=registered_node, count=20,
        )
        resp = client.get("/api/spectrum/activity?hours=2&limit=5")
        assert resp.status_code == 200
        assert resp.json()["count"] == 5

    def test_node_id_filter(
        self, client: TestClient, detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        _insert_sample_detections(detection_store, node_id=registered_node)
        resp = client.get("/api/spectrum/activity?node_id=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    """All spectrum endpoints require VIEWER auth."""

    @pytest.fixture
    def no_auth_client(self, bridge_app: FastAPI) -> TestClient:
        return TestClient(bridge_app)

    def test_occupancy_requires_auth(self, no_auth_client: TestClient) -> None:
        resp = no_auth_client.get("/api/spectrum/occupancy")
        assert resp.status_code == 401

    def test_waterfall_requires_auth(self, no_auth_client: TestClient) -> None:
        resp = no_auth_client.get("/api/spectrum/waterfall")
        assert resp.status_code == 401

    def test_bands_requires_auth(self, no_auth_client: TestClient) -> None:
        resp = no_auth_client.get("/api/spectrum/bands")
        assert resp.status_code == 401

    def test_activity_requires_auth(self, no_auth_client: TestClient) -> None:
        resp = no_auth_client.get("/api/spectrum/activity")
        assert resp.status_code == 401
