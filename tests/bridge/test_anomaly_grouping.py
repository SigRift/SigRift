"""Tests for anomaly grouping and startup seed behavior.

Covers:
  - Startup dismissed seed from audit log
  - Combined in-memory + DB dismissed filtering
  - Audit log operator tracking
  - Audit log signal metadata recording
  - Bulk dismiss/baseline with nonexistent detection IDs
  - Feedback auto-dismiss audit trail
  - Multiple actions on same detection
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.state import AppState
from sigrift.bridge.tests.conftest import make_detection

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

if HAS_FASTAPI:
    from sigrift.bridge.routers.detections import router
    from sigrift.bridge.routers.detection_audit import router as audit_router
    from sigrift.bridge.dependencies import rate_limit

def _make_app(tmp_path: Path) -> "FastAPI":
    """Create a FastAPI app with real DetectionStore and sample data."""
    app = FastAPI()

    store = DetectionStore(db_path=tmp_path / "test.db")
    app_state = AppState()

    # Insert diverse anomalies into both detections and rf_anomalies tables
    dets = [
        # Group 1: bpsk @ 433.92 MHz (3 detections)
        make_detection(signal_class="bpsk", freq_hz=433.92e6, anomaly_score=0.8, node_id="node-01"),
        make_detection(signal_class="bpsk", freq_hz=433.95e6, anomaly_score=0.6, node_id="node-01"),
        make_detection(signal_class="bpsk", freq_hz=433.90e6, anomaly_score=0.5, node_id="node-02"),
        # Group 2: ofdm @ 868 MHz (2 detections)
        make_detection(signal_class="ofdm-256", freq_hz=868e6, anomaly_score=0.75, node_id="node-02"),
        make_detection(signal_class="ofdm-256", freq_hz=868.05e6, anomaly_score=0.65, node_id="node-03"),
        # Group 3: qam16 @ 915 MHz (1 detection)
        make_detection(signal_class="qam16", freq_hz=915e6, anomaly_score=0.9, node_id="node-01"),
    ]
    store.insert_batch(dets)

    # Also populate rf_anomalies (the table now used by GET /anomalies)
    rows = store.get_anomalies(min_score=0.3, limit=20)
    rf_anomaly_dicts = []
    for r in rows:
        rf_anomaly_dicts.append({
            "detection_id": r["detection_id"],
            "signal_class": r["signal_class"],
            "family": r.get("family", ""),
            "freq_hz": r["freq_hz"],
            "node_id": r["node_id"],
            "timestamp": r["timestamp"],
            "confidence": r.get("confidence", 0.0),
            "snr_db": r.get("snr_db"),
            "power_dbm": r.get("power_dbm"),
            "anomaly_score": r["anomaly_score"],
            "baseline_status": r.get("baseline_status", ""),
        })
    rf_ids = store.insert_rf_anomalies_batch(rf_anomaly_dicts)

    app._test_detection_ids = [r["detection_id"] for r in rows]
    app._test_rf_ids = rf_ids
    app._test_detections = rows

    app.state.detection_store = store
    app.state.app_state = app_state

    mock_persistence = MagicMock()
    mock_persistence.get_key_meta.return_value = {}
    mock_persistence.get_nodes.return_value = {"node-01": {}, "node-02": {}, "node-03": {}}
    app.state.persistence = mock_persistence

    from starlette.middleware.base import BaseHTTPMiddleware
    from sigrift.bridge.dependencies import Role

    class _SetRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_SetRoleMiddleware)

    async def _fake_rate_limit():
        return "operator-alpha"

    app.dependency_overrides[rate_limit] = _fake_rate_limit
    app.include_router(audit_router, prefix="/api/detections")
    app.include_router(router, prefix="/api/detections")
    return app

@pytest.fixture
def grp_app(tmp_path: Path):
    if not HAS_FASTAPI:
        pytest.skip("FastAPI not installed")
    return _make_app(tmp_path)

@pytest.fixture
def grp_client(grp_app):
    return TestClient(grp_app)

# ---------------------------------------------------------------------------
# Startup seed tests
# ---------------------------------------------------------------------------

class TestStartupSeed:
    """Test that dismissed anomalies are seeded from DB on startup."""

    def test_seed_dismissed_from_audit(self, tmp_path: Path) -> None:
        """AppState should be seedable from audit log on startup."""
        db_path = tmp_path / "seed_test.db"
        store = DetectionStore(db_path=db_path)
        store.insert_batch([
            make_detection(anomaly_score=0.8),
        ])
        rows = store.get_anomalies(min_score=0.3)
        det_id = rows[0]["detection_id"]

        # Simulate a previous dismiss
        store.log_audit(action="dismiss", target_id=det_id)
        store.close()

        # Re-open and seed
        store2 = DetectionStore(db_path=db_path)
        dismissed = store2.get_dismissed_ids()
        assert isinstance(dismissed, set)
        assert det_id in dismissed

        # Seed into AppState (same as app.py startup logic)
        app_state = AppState()
        app_state.dismissed_anomalies = dismissed
        assert det_id in app_state.dismissed_anomalies
        store2.close()

# ---------------------------------------------------------------------------
# Combined filtering (in-memory + DB)
# ---------------------------------------------------------------------------

class TestRfAnomalyDismissFiltering:
    """Test that GET /anomalies filters by DB-level dismissed column."""

    def test_dismiss_via_api(self, grp_app, grp_client) -> None:
        """Anomalies dismissed via API are filtered from results."""
        rf_id = grp_app._test_rf_ids[0]
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")

        resp = grp_client.get("/api/detections/anomalies")
        returned_ids = [a["id"] for a in resp.json()["anomalies"]]
        assert rf_id not in returned_ids

    def test_bulk_dismiss_via_api(self, grp_app, grp_client) -> None:
        """Bulk dismissed anomalies are filtered from results."""
        rf_ids = grp_app._test_rf_ids[:2]
        grp_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": rf_ids},
        )

        resp = grp_client.get("/api/detections/anomalies")
        returned_ids = [a["id"] for a in resp.json()["anomalies"]]
        for rid in rf_ids:
            assert rid not in returned_ids

# ---------------------------------------------------------------------------
# Audit metadata recording
# ---------------------------------------------------------------------------

class TestAuditMetadata:
    """Test that audit entries capture correct metadata."""

    def test_dismiss_records_operator(self, grp_app, grp_client) -> None:
        """Dismiss records the operator (API key ID)."""
        rf_id = grp_app._test_rf_ids[0]
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        store = grp_app.state.detection_store
        entries = store.get_audit_log(action="dismiss_rf")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["operator"] == "operator-alpha"

    def test_dismiss_records_target_id(self, grp_app, grp_client) -> None:
        """Dismiss records the rf_anomalies row ID as target."""
        rf_id = grp_app._test_rf_ids[0]
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")

        store = grp_app.state.detection_store
        entries = store.get_audit_log(action="dismiss_rf")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == str(rf_id)

    def test_baseline_records_metadata(self, grp_app, grp_client) -> None:
        """Baseline records correct metadata."""
        det_id = grp_app._test_detection_ids[0]
        grp_client.put(f"/api/detections/anomalies/{det_id}/baseline")
        store = grp_app.state.detection_store
        entries = store.get_audit_log(action="baseline")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == det_id
        assert entries[0]["operator"] == "operator-alpha"

    def test_feedback_records_label_in_details(self, grp_app, grp_client) -> None:
        """Feedback records the label in details."""
        det_id = grp_app._test_detection_ids[0]
        grp_client.post(
            f"/api/detections/anomalies/{det_id}/feedback",
            json={"label": "false_positive", "note": "known signal"},
        )
        store = grp_app.state.detection_store
        entries = store.get_audit_log(action="feedback")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert isinstance(entries[0]["details"], dict)
        assert entries[0]["details"]["label"] == "false_positive"
        assert entries[0]["note"] == "known signal"

# ---------------------------------------------------------------------------
# Bulk with nonexistent IDs
# ---------------------------------------------------------------------------

class TestBulkEdgeCases:
    """Test bulk operations edge cases."""

    def test_bulk_dismiss_nonexistent_ids(self, grp_client) -> None:
        """Bulk dismiss with nonexistent integer IDs still succeeds (0 dismissed)."""
        resp = grp_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": [99999, 99998]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["dismissed_count"] == 0

    def test_bulk_baseline_nonexistent_ids(self, grp_client) -> None:
        """A nonexistent detection cannot be reported as durably baselined."""
        resp = grp_client.put(
            "/api/detections/anomalies/bulk/baseline",
            json={"detection_ids": ["nonexistent_001"]},
        )
        assert resp.status_code == 404

    def test_bulk_dismiss_mixed_ids(self, grp_app, grp_client) -> None:
        """Bulk dismiss with mix of real and nonexistent IDs."""
        real_rf_id = grp_app._test_rf_ids[0]
        resp = grp_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": [real_rf_id, 99999]},
        )
        assert resp.status_code == 200
        # Only the real ID gets dismissed
        assert resp.json()["dismissed_count"] == 1

# ---------------------------------------------------------------------------
# Multiple actions on same detection
# ---------------------------------------------------------------------------

class TestMultipleActions:
    """Test that multiple actions on the same detection are all recorded."""

    def test_dismiss_then_baseline(self, grp_app, grp_client) -> None:
        """Both RF dismiss and baseline are recorded."""
        rf_id = grp_app._test_rf_ids[0]
        det_id = grp_app._test_detection_ids[0]
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        grp_client.put(f"/api/detections/anomalies/{det_id}/baseline")
        store = grp_app.state.detection_store
        entries = store.get_audit_log()
        assert len(entries) >= 2
        actions = [e["action"] for e in entries]
        assert "dismiss_rf" in actions
        assert "baseline" in actions

    def test_feedback_then_dismiss(self, grp_app, grp_client) -> None:
        """Feedback then dismiss creates two audit entries."""
        det_id = grp_app._test_detection_ids[0]
        rf_id = grp_app._test_rf_ids[0]
        grp_client.post(
            f"/api/detections/anomalies/{det_id}/feedback",
            json={"label": "interesting"},
        )
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        store = grp_app.state.detection_store
        # At least 2 entries total (feedback + dismiss_rf)
        entries = store.get_audit_log()
        assert len(entries) >= 2
        actions = [e["action"] for e in entries]
        assert "feedback" in actions
        assert "dismiss_rf" in actions

    def test_false_positive_feedback_records_audit(self, grp_app, grp_client) -> None:
        """false_positive feedback creates audit trail."""
        det_id = grp_app._test_detection_ids[0]
        grp_client.post(
            f"/api/detections/anomalies/{det_id}/feedback",
            json={"label": "false_positive"},
        )

        # Audit trail should have feedback entry
        store = grp_app.state.detection_store
        entries = store.get_audit_log(action="feedback", target_id=det_id)
        assert len(entries) == 1

# ---------------------------------------------------------------------------
# Audit log query edge cases
# ---------------------------------------------------------------------------

class TestAuditQueryEdgeCases:
    """Test audit log query edge cases."""

    def test_audit_combined_filters(self, grp_app, grp_client) -> None:
        """Filter by both action and target_id."""
        rf_id = grp_app._test_rf_ids[0]
        det_id = grp_app._test_detection_ids[0]
        grp_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        grp_client.put(f"/api/detections/anomalies/{det_id}/baseline")

        resp = grp_client.get(
            "/api/detections/anomalies/audit?action=dismiss_rf"
        )
        data = resp.json()
        assert isinstance(data["entries"], list)
        assert len(data["entries"]) >= 1
        assert all(e["action"] == "dismiss_rf" for e in data["entries"])

    def test_audit_returns_json_details(self, grp_app, grp_client) -> None:
        """Audit entries with JSON details are properly returned."""
        det_id = grp_app._test_detection_ids[0]
        grp_client.post(
            f"/api/detections/anomalies/{det_id}/feedback",
            json={"label": "true_positive", "note": "confirmed threat"},
        )
        resp = grp_client.get("/api/detections/anomalies/audit?action=feedback")
        data = resp.json()
        assert isinstance(data["entries"], list)
        assert len(data["entries"]) >= 1
        assert isinstance(data["entries"][0]["details"], dict)
        assert data["entries"][0]["details"]["label"] == "true_positive"

    def test_audit_timestamp_ordering(self, grp_app, grp_client) -> None:
        """Audit entries are ordered by timestamp DESC."""
        ids = grp_app._test_rf_ids[:3]
        for rid in ids:
            grp_client.put(f"/api/detections/anomalies/{rid}/dismiss")

        resp = grp_client.get("/api/detections/anomalies/audit")
        entries = resp.json()["entries"]
        timestamps = [e["timestamp"] for e in entries]
        assert timestamps == sorted(timestamps, reverse=True)
