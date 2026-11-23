"""Tests for /api/status freq_hours query parameter and active_frequency_list.

Covers the new freq_hours parameter on GET /api/status:
  - Default freq_hours=1 works
  - Custom freq_hours values (4, 24, 168) work
  - Validation rejects out-of-range values (0, 169, negative)
  - Response includes active_frequency_list field
  - active_frequency_list structure matches expected format
  - Graceful handling when detection_store is None
  - Graceful handling when detection_store methods raise exceptions
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStatusFreqHoursDefault:
    """Default freq_hours=1 behaviour."""

    def test_status_default_freq_hours(self, client: TestClient):
        """GET /api/status with no freq_hours param defaults to 1 and succeeds."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_frequencies" in data
        assert isinstance(data["active_frequencies"], int)
        assert "active_frequency_list" in data
        assert isinstance(data["active_frequency_list"], list)

    def test_status_explicit_freq_hours_1(self, client: TestClient):
        """GET /api/status?freq_hours=1 behaves the same as the default."""
        resp = client.get("/api/status?freq_hours=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_frequency_list" in data
        assert isinstance(data["active_frequency_list"], list)


class TestStatusFreqHoursCustom:
    """Custom freq_hours values within the valid range."""

    @pytest.mark.parametrize("hours", [4, 24, 168])
    def test_status_custom_freq_hours(self, client: TestClient, hours: int):
        """Valid freq_hours values (4, 24, 168) are accepted."""
        resp = client.get(f"/api/status?freq_hours={hours}")
        assert resp.status_code == 200
        data = resp.json()
        assert "active_frequencies" in data
        assert isinstance(data["active_frequencies"], int)
        assert "active_frequency_list" in data
        assert isinstance(data["active_frequency_list"], list)

    def test_status_freq_hours_min_boundary(self, client: TestClient):
        """freq_hours=1 (minimum) is accepted."""
        resp = client.get("/api/status?freq_hours=1")
        assert resp.status_code == 200

    def test_status_freq_hours_max_boundary(self, client: TestClient):
        """freq_hours=168 (maximum, 1 week) is accepted."""
        resp = client.get("/api/status?freq_hours=168")
        assert resp.status_code == 200


class TestStatusFreqHoursValidation:
    """Validation: reject out-of-range freq_hours values."""

    def test_status_freq_hours_zero_rejected(self, client: TestClient):
        """freq_hours=0 is below the minimum (ge=1) and returns 422."""
        resp = client.get("/api/status?freq_hours=0")
        assert resp.status_code == 422

    def test_status_freq_hours_negative_rejected(self, client: TestClient):
        """Negative freq_hours returns 422."""
        resp = client.get("/api/status?freq_hours=-1")
        assert resp.status_code == 422

    def test_status_freq_hours_too_large_rejected(self, client: TestClient):
        """freq_hours=169 exceeds maximum (le=168) and returns 422."""
        resp = client.get("/api/status?freq_hours=169")
        assert resp.status_code == 422

    def test_status_freq_hours_non_integer_rejected(self, client: TestClient):
        """Non-integer freq_hours returns 422."""
        resp = client.get("/api/status?freq_hours=abc")
        assert resp.status_code == 422

    def test_status_freq_hours_float_rejected(self, client: TestClient):
        """Float freq_hours returns 422."""
        resp = client.get("/api/status?freq_hours=2.5")
        assert resp.status_code == 422


class TestStatusFrequencyList:
    """active_frequency_list field presence and structure."""

    def test_active_frequency_list_is_list(self, client: TestClient):
        """active_frequency_list is always a list."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["active_frequency_list"], list)

    def test_active_frequency_list_empty_when_no_detections(self, client: TestClient):
        """With no detections, active_frequency_list is empty."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["active_frequency_list"] == []
        assert data["active_frequencies"] == 0


class TestStatusDetectionStoreNone:
    """Graceful handling when detection_store is None."""

    def test_status_without_detection_store(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """When detection_store is not set, status still returns defaults."""
        original = bridge_app.state.detection_store
        bridge_app.state.detection_store = None
        try:
            no_store_client = TestClient(
                bridge_app, headers={"X-API-Key": master_key},
            )
            resp = no_store_client.get("/api/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_detections_24h"] == 0
            assert data["detections_per_second"] == 0.0
            assert data["active_anomalies"] == 0
            assert data["active_frequencies"] == 0
            assert data["active_frequency_list"] == []
        finally:
            bridge_app.state.detection_store = original


class TestStatusDetectionStoreExceptions:
    """Graceful handling when detection_store methods raise exceptions."""

    def test_status_get_stats_raises(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """If get_stats raises, status still returns with zeroed metrics."""
        store = bridge_app.state.detection_store
        original_get_stats = store.get_stats
        store.get_stats = MagicMock(side_effect=RuntimeError("db locked"))
        try:
            err_client = TestClient(
                bridge_app, headers={"X-API-Key": master_key},
            )
            resp = err_client.get("/api/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_detections_24h"] == 0
            assert data["detections_per_second"] == 0.0
        finally:
            store.get_stats = original_get_stats

    def test_status_get_active_frequencies_raises(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """If get_active_frequencies raises, freq_list defaults to []."""
        store = bridge_app.state.detection_store
        original_fn = getattr(store, "get_active_frequencies", None)
        store.get_active_frequencies = MagicMock(
            side_effect=RuntimeError("db locked"),
        )
        try:
            err_client = TestClient(
                bridge_app, headers={"X-API-Key": master_key},
            )
            resp = err_client.get("/api/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["active_frequency_list"] == []
        finally:
            if original_fn is not None:
                store.get_active_frequencies = original_fn

    def test_status_all_detection_methods_raise(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """If all detection_store methods raise, status still returns cleanly."""
        store = bridge_app.state.detection_store
        originals = {}
        error = RuntimeError("total failure")
        for name in ("get_stats", "get_active_anomaly_count",
                      "get_active_frequency_count", "get_active_frequencies"):
            originals[name] = getattr(store, name, None)
            setattr(store, name, MagicMock(side_effect=error))
        try:
            err_client = TestClient(
                bridge_app, headers={"X-API-Key": master_key},
            )
            resp = err_client.get("/api/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_detections_24h"] == 0
            assert data["detections_per_second"] == 0.0
            assert data["active_anomalies"] == 0
            assert data["active_frequencies"] == 0
            assert data["active_frequency_list"] == []
        finally:
            for name, fn in originals.items():
                if fn is not None:
                    setattr(store, name, fn)


class TestStatusFreqHoursPassthrough:
    """Verify freq_hours is passed through to the detection_store methods."""

    def test_freq_hours_passed_to_frequency_count(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """get_active_frequency_count receives the freq_hours value."""
        store = bridge_app.state.detection_store
        original_fn = store.get_active_frequency_count
        mock_fn = MagicMock(return_value=5)
        store.get_active_frequency_count = mock_fn
        try:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            resp = tc.get("/api/status?freq_hours=24")
            assert resp.status_code == 200
            mock_fn.assert_called_once_with(hours=24)
        finally:
            store.get_active_frequency_count = original_fn

    def test_freq_hours_passed_to_active_frequencies(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """get_active_frequencies receives the freq_hours value."""
        store = bridge_app.state.detection_store
        original_fn = getattr(store, "get_active_frequencies", None)
        mock_fn = MagicMock(return_value=[{"freq_hz": 433.92e6, "count": 3}])
        store.get_active_frequencies = mock_fn
        try:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            resp = tc.get("/api/status?freq_hours=48")
            assert resp.status_code == 200
            mock_fn.assert_called_once_with(hours=48)
            data = resp.json()
            assert len(data["active_frequency_list"]) == 1
        finally:
            if original_fn is not None:
                store.get_active_frequencies = original_fn

    def test_default_freq_hours_passed_as_1(
        self, bridge_app: FastAPI, master_key: str,
    ):
        """When freq_hours is omitted, detection_store methods receive hours=1."""
        store = bridge_app.state.detection_store
        original_count = store.get_active_frequency_count
        original_list = getattr(store, "get_active_frequencies", None)
        mock_count = MagicMock(return_value=0)
        mock_list = MagicMock(return_value=[])
        store.get_active_frequency_count = mock_count
        store.get_active_frequencies = mock_list
        try:
            tc = TestClient(bridge_app, headers={"X-API-Key": master_key})
            resp = tc.get("/api/status")
            assert resp.status_code == 200
            mock_count.assert_called_once_with(hours=1)
            mock_list.assert_called_once_with(hours=1)
        finally:
            store.get_active_frequency_count = original_count
            if original_list is not None:
                store.get_active_frequencies = original_list
