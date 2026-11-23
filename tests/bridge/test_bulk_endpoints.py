"""Tests for bulk anomaly endpoints and audit integration.

Covers:
  - PUT /anomalies/bulk/dismiss
  - PUT /anomalies/bulk/baseline
  - GET /anomalies/audit
  - Audit log writes on dismiss, baseline, and feedback
  - Dismissed anomaly persistence via audit log
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
    """Create a FastAPI app with a real DetectionStore for audit tests."""
    app = FastAPI()

    store = DetectionStore(db_path=tmp_path / "test.db")
    app_state = AppState()

    # Insert some detections for tests
    dets = [
        make_detection(
            signal_class="bpsk",
            freq_hz=433.92e6,
            anomaly_score=0.8,
            node_id="node-01",
        ),
        make_detection(
            signal_class="bpsk",
            freq_hz=433.92e6,
            anomaly_score=0.6,
            node_id="node-01",
        ),
        make_detection(
            signal_class="ofdm-256",
            freq_hz=868e6,
            anomaly_score=0.75,
            node_id="node-02",
        ),
    ]
    store.insert_batch(dets)

    # Get the actual detection IDs
    rows = store.get_anomalies(min_score=0.3, limit=10)
    app._test_detection_ids = [r["detection_id"] for r in rows]

    # Also populate rf_anomalies (used by dismiss endpoints)
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
    app._test_rf_ids = rf_ids

    app.state.detection_store = store
    app.state.app_state = app_state

    # Mock persistence (needed by some deps)
    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {"node-01": {}, "node-02": {}}
    # This fixture represents a legacy local key without an explicit tenant.
    # A MagicMock is not valid credential metadata for the tenant guard.
    mock_persistence.get_key_meta.return_value = {}
    app.state.persistence = mock_persistence

    # Override auth
    from starlette.middleware.base import BaseHTTPMiddleware
    from sigrift.bridge.dependencies import Role

    class _SetRoleMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            request.state.key_role = Role.ADMIN
            return await call_next(request)

    app.add_middleware(_SetRoleMiddleware)

    async def _fake_rate_limit():
        return "test-key-id"

    app.dependency_overrides[rate_limit] = _fake_rate_limit
    app.include_router(audit_router, prefix="/api/detections")
    app.include_router(router, prefix="/api/detections")
    return app

@pytest.fixture
def bulk_app(tmp_path: Path):
    """Fixture that creates a test app with real DetectionStore."""
    if not HAS_FASTAPI:
        pytest.skip("FastAPI not installed")
    app = _make_app(tmp_path)
    try:
        yield app
    finally:
        app.state.detection_store.close()

@pytest.fixture
def bulk_client(bulk_app):
    """TestClient for the bulk endpoints."""
    with TestClient(bulk_app) as client:
        yield client

# ---------------------------------------------------------------------------
# Bulk dismiss tests
# ---------------------------------------------------------------------------

class TestBulkDismiss:
    """Tests for PUT /api/detections/anomalies/bulk/dismiss."""

    def test_bulk_dismiss_success(self, bulk_app, bulk_client) -> None:
        """Bulk dismiss returns success with correct count."""
        rf_ids = bulk_app._test_rf_ids[:2]
        resp = bulk_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": rf_ids},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["dismissed_count"] == 2

    def test_bulk_dismiss_writes_audit(self, bulk_app, bulk_client) -> None:
        """Bulk dismiss writes audit entry."""
        rf_ids = bulk_app._test_rf_ids[:2]
        bulk_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": rf_ids},
        )
        store = bulk_app.state.detection_store
        entries = store.get_audit_log(action="bulk_dismiss_rf")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)

    def test_bulk_dismiss_filters_anomalies(self, bulk_app, bulk_client) -> None:
        """Bulk dismissed IDs are excluded from GET /anomalies."""
        rf_ids = bulk_app._test_rf_ids[:2]
        bulk_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": rf_ids},
        )
        resp = bulk_client.get("/api/detections/anomalies")
        data = resp.json()
        returned_ids = [a["id"] for a in data["anomalies"]]
        for rid in rf_ids:
            assert rid not in returned_ids

    def test_bulk_dismiss_empty_list_fails(self, bulk_client) -> None:
        """Empty ids list returns 422."""
        resp = bulk_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": []},
        )
        assert resp.status_code == 422

    def test_bulk_dismiss_too_many_fails(self, bulk_client) -> None:
        """More than 1000 IDs returns 422."""
        resp = bulk_client.put(
            "/api/detections/anomalies/bulk/dismiss",
            json={"ids": list(range(1001))},
        )
        assert resp.status_code == 422

# ---------------------------------------------------------------------------
# Bulk baseline tests
# ---------------------------------------------------------------------------

class TestBulkBaseline:
    """Tests for PUT /api/detections/anomalies/bulk/baseline."""

    def test_bulk_baseline_success(self, bulk_app, bulk_client) -> None:
        """Bulk baseline returns success with correct count."""
        ids = bulk_app._test_detection_ids[:2]
        resp = bulk_client.put(
            "/api/detections/anomalies/bulk/baseline",
            json={"detection_ids": ids},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["baselined"] is True
        assert data["count"] == 2
        store = bulk_app.state.detection_store
        patterns = data["patterns"]
        assert len(patterns) == 2
        assert {p["source_detection_id"] for p in patterns} == set(ids)
        for pattern in patterns:
            detection = store.get_detection_by_id(pattern["source_detection_id"])
            assert pattern["node_id"] == detection["node_id"]
            assert pattern["signal_class"] == detection["signal_class"]
            assert pattern["freq_min_hz"] == detection["freq_hz"] - 50_000
            assert pattern["freq_max_hz"] == detection["freq_hz"] + 50_000
        assert {p["pattern_id"] for p in store.known_signals.list()} == {
            p["pattern_id"] for p in patterns
        }

    def test_bulk_baseline_writes_audit(self, bulk_app, bulk_client) -> None:
        """Bulk baseline writes audit entries."""
        ids = bulk_app._test_detection_ids[:1]
        response = bulk_client.put(
            "/api/detections/anomalies/bulk/baseline",
            json={"detection_ids": ids},
        )
        assert response.status_code == 200
        store = bulk_app.state.detection_store
        entries = store.get_audit_log(action="baseline")
        assert len(entries) == 1
        assert entries[0]["target_id"] == ids[0]
        pattern = response.json()["patterns"][0]
        assert entries[0]["details"]["pattern_id"] == pattern["pattern_id"]
        assert entries[0]["details"]["pattern"]["node_id"] == pattern["node_id"]
        assert entries[0]["details"]["effect"] == "suppress_matching_rf_alerts"

    def test_bulk_baseline_preserves_detections_and_anomalies(self, bulk_app, bulk_client) -> None:
        """Known patterns do not rewrite scores or dismiss existing anomalies."""
        ids = bulk_app._test_detection_ids[:2]
        store = bulk_app.state.detection_store
        detections = [store.get_detection_by_id(did) for did in ids]
        anomalies = store.get_rf_anomalies(min_score=0)
        assert anomalies
        response = bulk_client.put(
            "/api/detections/anomalies/bulk/baseline",
            json={"detection_ids": ids},
        )
        assert response.status_code == 200
        assert len(store.known_signals.list()) == 2
        assert [store.get_detection_by_id(did) for did in ids] == detections
        assert store.get_rf_anomalies(min_score=0) == anomalies
        app_state = bulk_app.state.app_state
        for did in ids:
            assert did not in app_state.dismissed_anomalies
            assert not store.is_dismissed(did)

    def test_bulk_baseline_retry_preserves_durable_rules_and_audit(self, bulk_app, bulk_client) -> None:
        """A lost response can be retried without duplicate rules or audit events."""
        url = "/api/detections/anomalies/bulk/baseline"
        ids = bulk_app._test_detection_ids[:2]
        first = bulk_client.put(url, json={"detection_ids": ids})
        assert first.status_code == 200
        store = bulk_app.state.detection_store
        saved = store.known_signals.list()
        audit = store.get_audit_log(action="baseline")
        assert len(saved) == len(audit) == 2
        fresh = DetectionStore(store.db_path)
        try:
            assert fresh.known_signals.list() == saved
            assert fresh.get_audit_log(action="baseline") == audit
            retry = bulk_client.put(url, json={"detection_ids": ids})
            assert retry.status_code == 200
            assert retry.json() == first.json()
            assert fresh.known_signals.list() == saved
            assert fresh.get_audit_log(action="baseline") == audit
        finally:
            fresh.close()

# ---------------------------------------------------------------------------
# Audit endpoint tests
# ---------------------------------------------------------------------------

class TestAuditEndpoint:
    """Tests for GET /api/detections/anomalies/audit."""

    def test_audit_empty(self, bulk_client) -> None:
        """Empty audit log returns empty entries."""
        resp = bulk_client.get("/api/detections/anomalies/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["entries"] == []

    def test_audit_after_dismiss(self, bulk_app, bulk_client) -> None:
        """Audit shows entries after dismiss action."""
        rf_id = bulk_app._test_rf_ids[0]
        bulk_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        resp = bulk_client.get("/api/detections/anomalies/audit")
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)
        actions = [e["action"] for e in data["entries"]]
        assert "dismiss_rf" in actions

    def test_audit_after_baseline(self, bulk_app, bulk_client) -> None:
        """Audit shows entries after baseline action."""
        det_id = bulk_app._test_detection_ids[0]
        mutation = bulk_client.put(f"/api/detections/anomalies/{det_id}/baseline")
        assert mutation.status_code == 200
        resp = bulk_client.get("/api/detections/anomalies/audit")
        assert resp.status_code == 200
        data = resp.json()
        actions = [e["action"] for e in data["entries"]]
        assert "baseline" in actions

    def test_audit_filter_action(self, bulk_app, bulk_client) -> None:
        """Filter audit by action type."""
        rf_id = bulk_app._test_rf_ids[0]
        det_id = bulk_app._test_detection_ids[0]
        assert bulk_client.put(f"/api/detections/anomalies/{rf_id}/dismiss").status_code == 200
        assert bulk_client.put(f"/api/detections/anomalies/{det_id}/baseline").status_code == 200

        resp = bulk_client.get("/api/detections/anomalies/audit?action=dismiss_rf")
        data = resp.json()
        assert data["count"] == 1
        assert all(e["action"] == "dismiss_rf" for e in data["entries"])

    def test_audit_limit(self, bulk_app, bulk_client) -> None:
        """Limit parameter works."""
        rf_ids = bulk_app._test_rf_ids
        for rid in rf_ids:
            bulk_client.put(f"/api/detections/anomalies/{rid}/dismiss")

        resp = bulk_client.get("/api/detections/anomalies/audit?limit=1")
        data = resp.json()
        assert data["count"] == 1

# ---------------------------------------------------------------------------
# Audit integration on existing endpoints
# ---------------------------------------------------------------------------

class TestAuditIntegration:
    """Test that existing endpoints write audit entries."""

    def test_dismiss_writes_audit(self, bulk_app, bulk_client) -> None:
        """Single dismiss writes audit entry."""
        rf_id = bulk_app._test_rf_ids[0]
        bulk_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        store = bulk_app.state.detection_store
        entries = store.get_audit_log(action="dismiss_rf")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == str(rf_id)

    def test_baseline_writes_audit(self, bulk_app, bulk_client) -> None:
        """Single baseline writes audit entry."""
        det_id = bulk_app._test_detection_ids[0]
        mutation = bulk_client.put(f"/api/detections/anomalies/{det_id}/baseline")
        assert mutation.status_code == 200
        store = bulk_app.state.detection_store
        entries = store.get_audit_log(action="baseline")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == det_id

    def test_feedback_writes_audit(self, bulk_app, bulk_client) -> None:
        """Feedback writes audit entry."""
        det_id = bulk_app._test_detection_ids[0]
        bulk_client.post(
            f"/api/detections/anomalies/{det_id}/feedback",
            json={"label": "true_positive", "note": "confirmed"},
        )
        store = bulk_app.state.detection_store
        entries = store.get_audit_log(action="feedback")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == det_id
        assert entries[0]["details"]["label"] == "true_positive"

    def test_dismissed_persists_via_audit(self, bulk_app, bulk_client) -> None:
        """Dismissed IDs are queryable from audit log."""
        rf_id = bulk_app._test_rf_ids[0]
        bulk_client.put(f"/api/detections/anomalies/{rf_id}/dismiss")
        store = bulk_app.state.detection_store
        # dismiss_rf writes audit entry with target_id
        entries = store.get_audit_log(action="dismiss_rf")
        assert len(entries) >= 1
        assert isinstance(entries[0], dict)
        assert entries[0]["target_id"] == str(rf_id)
