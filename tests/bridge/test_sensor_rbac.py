"""Tests for the SENSOR RBAC role.

Verifies that:
  - SENSOR keys can submit detections (ingest batch)
  - SENSOR keys cannot read dashboard endpoints
  - VIEWER/ANALYST/ADMIN keys can still read and operate as before
  - The role hierarchy SENSOR < VIEWER < ANALYST < ADMIN is enforced
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.pcap_store import PcapStore
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.anomaly.wifi_scorer import WifiAnomalyScorer, WifiBaselineManager
from sigrift.bridge.dependencies import (
    RateLimiter,
    Role,
    WSConnectionLimiter,
    set_rate_limiter,
    set_ws_limiter,
)
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.notifications import NotificationManager
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState


def _make_app(tmp_path: Path) -> tuple[FastAPI, PersistenceManager, str, str, str, str]:
    """Build a test app and return (app, persistence, admin_key, analyst_key, viewer_key, sensor_key)."""
    from sigrift.bridge.app import CombinedMiddleware
    from sigrift.bridge.routers import (
        admin, alerts, detection_analytics, detection_audit, detection_iq,
        detections, export, health, keys,
        maintenance, nodes, signals, system_config, webhook_management, wifi,
    )

    app = FastAPI()
    app.add_middleware(CombinedMiddleware)

    persistence = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    persistence.load_all()

    # Create keys with different roles
    keys_data = {}
    for name, role in [("admin", "admin"), ("analyst", "analyst"), ("viewer", "viewer"), ("sensor", "sensor")]:
        raw = generate_api_key(length=32)
        h, s = hash_credential(raw)
        persistence.set_key(name, h, s)
        persistence.set_key_meta(name, {"role": role})
        keys_data[name] = raw

    detection_store = DetectionStore(db_path=tmp_path / "test.db")
    app_state = AppState()

    app.state.persistence = persistence
    app.state.app_state = app_state
    app.state.detection_store = detection_store
    app.state.pcap_store = PcapStore(base_dir=tmp_path / "pcap")
    wifi_baseline_mgr = WifiBaselineManager()
    app.state.wifi_scorer = WifiAnomalyScorer(wifi_baseline_mgr)
    app.state.wifi_baseline_mgr = wifi_baseline_mgr
    rf_baseline_mgr = BaselineManager()
    app.state.rf_scorer = AnomalyScorer(rf_baseline_mgr)
    app.state.rf_baseline_mgr = rf_baseline_mgr
    notifier = NotificationManager()
    app.state.notifier = notifier

    limiter = RateLimiter(max_requests=1000, window_seconds=60.0)
    set_rate_limiter(limiter)
    ws_limiter = WSConnectionLimiter(max_concurrent=10, max_per_minute=30)
    set_ws_limiter(ws_limiter)
    app.state.ws_limiter = ws_limiter
    app_state.ws_limiter = ws_limiter

    app.include_router(health.router, prefix="/api", tags=["health"])
    app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])
    # Specific detection sub-routers MUST come before the catch-all
    # detections router (which has /{detection_id}) to avoid shadowing.
    app.include_router(detection_analytics.router, prefix="/api/detections", tags=["detections"])
    app.include_router(detection_audit.router, prefix="/api/detections", tags=["detections"])
    app.include_router(detection_iq.router, prefix="/api/detections", tags=["detections"])
    app.include_router(detections.router, prefix="/api/detections", tags=["detections"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(keys.router, prefix="/api/keys", tags=["keys"])
    app.include_router(export.router, prefix="/api/export", tags=["export"])
    app.include_router(wifi.router, prefix="/api/wifi", tags=["wifi"])
    app.include_router(signals.router, prefix="/api/signals", tags=["signals"])
    app.include_router(admin.router, prefix="/api/admin", tags=["admin"])
    app.include_router(maintenance.router, prefix="/api/admin", tags=["admin"])
    app.include_router(system_config.router, prefix="/api/admin", tags=["admin"])
    app.include_router(webhook_management.router, prefix="/api/admin", tags=["admin"])

    return (
        app, persistence,
        keys_data["admin"], keys_data["analyst"],
        keys_data["viewer"], keys_data["sensor"],
    )


@pytest.fixture
def sensor_setup(tmp_path):
    app, persistence, admin_key, analyst_key, viewer_key, sensor_key = _make_app(tmp_path)

    # Register a node so ingest works
    c = TestClient(app, headers={"X-API-Key": admin_key})
    c.post("/api/nodes/register", json={
        "node_id": "node-sensor-01",
        "host": "10.0.0.1",
        "port": 8080,
    })

    return {
        "app": app,
        "admin_key": admin_key,
        "analyst_key": analyst_key,
        "viewer_key": viewer_key,
        "sensor_key": sensor_key,
    }


# -----------------------------------------------------------------------
# Role enum
# -----------------------------------------------------------------------

class TestRoleHierarchy:
    def test_sensor_is_lowest(self):
        assert Role.SENSOR < Role.NODE < Role.VIEWER < Role.ANALYST < Role.ADMIN

    def test_sensor_value(self):
        assert Role.SENSOR == 0
        assert Role.NODE == 1
        assert Role.VIEWER == 2


# -----------------------------------------------------------------------
# Sensor key can ingest
# -----------------------------------------------------------------------

class TestSensorCanIngest:
    def test_sensor_can_submit_detections(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        import time
        now = time.time()
        resp = c.post("/api/detections/batch", json={
            "node_id": "node-sensor-01",
            "period_start": now - 60,
            "period_end": now,
            "detections": [{
                "node_id": "node-sensor-01",
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
            }],
        })
        assert resp.status_code in (200, 201), f"Sensor ingest failed: {resp.status_code} {resp.text}"

    def test_sensor_can_send_heartbeat(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.post("/api/nodes/heartbeat", json={
            "node_id": "node-sensor-01",
            "metrics": {
                "cpu_percent": 25.0,
                "memory_mb": 512.0,
            },
        })
        assert resp.status_code == 200


# -----------------------------------------------------------------------
# Sensor key cannot read dashboard
# -----------------------------------------------------------------------

class TestSensorCannotRead:
    def test_sensor_cannot_get_detections_recent(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.get("/api/detections/recent")
        assert resp.status_code == 403

    def test_sensor_cannot_get_stats(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.get("/api/detections/stats")
        assert resp.status_code == 403

    def test_sensor_cannot_list_alerts(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.get("/api/alerts/")
        assert resp.status_code == 403

    def test_sensor_cannot_list_nodes(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.get("/api/nodes/")
        assert resp.status_code == 403

    def test_sensor_cannot_export(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["sensor_key"]})
        resp = c.get("/api/export/detections")
        assert resp.status_code == 403


# -----------------------------------------------------------------------
# Viewer key can read but not write (except what was already allowed)
# -----------------------------------------------------------------------

class TestViewerAccess:
    def test_viewer_can_get_recent(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["viewer_key"]})
        resp = c.get("/api/detections/recent")
        assert resp.status_code == 200

    def test_viewer_can_get_stats(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["viewer_key"]})
        resp = c.get("/api/detections/stats")
        assert resp.status_code == 200


# -----------------------------------------------------------------------
# Admin key has full access
# -----------------------------------------------------------------------

class TestAdminAccess:
    def test_admin_can_ingest(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["admin_key"]})
        import time
        now = time.time()
        resp = c.post("/api/detections/batch", json={
            "node_id": "node-sensor-01",
            "period_start": now - 60,
            "period_end": now,
            "detections": [{
                "node_id": "node-sensor-01",
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433.92e6,
            }],
        })
        assert resp.status_code in (200, 201)

    def test_admin_can_read(self, sensor_setup):
        c = TestClient(sensor_setup["app"], headers={"X-API-Key": sensor_setup["admin_key"]})
        resp = c.get("/api/detections/recent")
        assert resp.status_code == 200
