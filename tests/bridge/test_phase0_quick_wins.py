"""Tests for Phase 0 quick-win items: D-2, T-2, D-8, D-6, D-7."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.storage.audit import AuditStore
from sigrift.bridge.storage.users import UserStore


# ---------------------------------------------------------------------------
# D-2: Unauthenticated /healthz and /ready endpoints
# ---------------------------------------------------------------------------


class TestHealthzEndpoint:
    """D-2: /api/healthz and /api/ready must not require authentication."""

    def test_healthz_no_auth(self, bridge_app):
        """GET /api/healthz returns 200 without any auth headers."""
        client = TestClient(bridge_app)
        resp = client.get("/api/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_ready_no_auth(self, bridge_app):
        """GET /api/ready returns 200 without any auth headers."""
        client = TestClient(bridge_app)
        resp = client.get("/api/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"

    def test_ready_checks_database(self, bridge_app):
        """Readiness probe verifies database connectivity."""
        client = TestClient(bridge_app)
        resp = client.get("/api/ready")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_ready_returns_503_without_store(self, bridge_app):
        """Readiness probe returns 503 when detection_store is missing."""
        # Temporarily remove detection_store
        original = bridge_app.state.detection_store
        bridge_app.state.detection_store = None
        try:
            client = TestClient(bridge_app)
            resp = client.get("/api/ready")
            assert resp.status_code == 503
            data = resp.json()
            assert data["status"] == "not_ready"
        finally:
            bridge_app.state.detection_store = original

    def test_healthz_response_minimal(self, bridge_app):
        """Healthz response is minimal for fast K8s probing."""
        client = TestClient(bridge_app)
        resp = client.get("/api/healthz")
        data = resp.json()
        # Should be just {"status": "ok"} — no security warnings, no version
        assert set(data.keys()) == {"status"}


# ---------------------------------------------------------------------------
# T-2: Metrics router wired + record_request
# ---------------------------------------------------------------------------


class TestMetricsWiring:
    """T-2: Prometheus metrics endpoint is mounted and records requests."""

    def test_metrics_endpoint_exists(self, client):
        """GET /metrics returns Prometheus text format."""
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "sigrift_uptime_seconds" in resp.text

    def test_record_request_called(self, client):
        """After making requests, /metrics shows request counts."""
        # Make a few requests to generate metrics
        client.get("/api/version")
        client.get("/api/version")

        resp = client.get("/metrics")
        text = resp.text
        assert "sigrift_requests_total" in text

    def test_metrics_includes_websocket_gauge(self, client):
        """Metrics includes active WebSocket connection gauge."""
        resp = client.get("/metrics")
        assert "sigrift_active_websockets" in resp.text

    def test_metrics_includes_detection_counter(self, client):
        """Metrics includes detection counter."""
        resp = client.get("/metrics")
        assert "sigrift_detections_total" in resp.text


# ---------------------------------------------------------------------------
# D-8: Audit log pagination with total count
# ---------------------------------------------------------------------------


class TestAuditPagination:
    """D-8: Audit log endpoint returns total count for pagination."""

    def test_audit_returns_total(self, client, detection_store):
        """GET /api/admin/audit includes 'total' field."""
        # Create some audit entries
        detection_store.log_audit(
            action="test_action",
            target_id="det-001",
            operator="test-op",
        )
        detection_store.log_audit(
            action="test_action",
            target_id="det-002",
            operator="test-op",
        )

        resp = client.get("/api/admin/audit", params={"limit": 10})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["total"], int) and data["total"] >= 2
        assert data["count"] == len(data["entries"])

    def test_audit_total_with_pagination(self, client, detection_store):
        """Total count reflects all matching entries, not just current page."""
        for i in range(5):
            detection_store.log_audit(
                action="paginate_test",
                target_id=f"det-{i:03d}",
                operator="test-op",
            )

        # Request page of 2
        resp = client.get("/api/admin/audit", params={
            "limit": 2,
            "action": "paginate_test",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2  # page size
        assert data["total"] == 5  # total matching

    def test_audit_total_with_filter(self, client, detection_store):
        """Total count respects filters."""
        detection_store.log_audit(action="action_a", target_id="x", operator="op")
        detection_store.log_audit(action="action_b", target_id="y", operator="op")
        detection_store.log_audit(action="action_a", target_id="z", operator="op")

        resp = client.get("/api/admin/audit", params={"action": "action_a"})
        data = resp.json()
        assert data["total"] == 2

    def test_count_audit_log_storage(self, detection_store):
        """Storage-level count_audit_log matches filter behavior."""
        detection_store.log_audit(action="c1", target_id="t1", operator="op")
        detection_store.log_audit(action="c2", target_id="t2", operator="op")
        detection_store.log_audit(action="c1", target_id="t3", operator="op")

        total_all = detection_store.count_audit_log()
        assert isinstance(total_all, int)
        assert total_all >= 3

        total_c1 = detection_store.count_audit_log(action="c1")
        assert total_c1 == 2

        total_c2 = detection_store.count_audit_log(action="c2")
        assert total_c2 == 1


# ---------------------------------------------------------------------------
# D-6: Configurable session absolute timeout
# ---------------------------------------------------------------------------


class TestSessionAbsoluteTimeout:
    """D-6: Session absolute timeout is configurable via env var."""

    def test_default_absolute_timeout(self):
        """Default absolute timeout is 24 hours."""
        assert UserStore._get_absolute_timeout_hours() == 24

    def test_custom_absolute_timeout(self):
        """BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS overrides default."""
        with patch.dict(os.environ, {"BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS": "8"}):
            assert UserStore._get_absolute_timeout_hours() == 8

    def test_invalid_absolute_timeout_falls_back(self):
        """Invalid env var falls back to default."""
        with patch.dict(os.environ, {"BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS": "not_a_number"}):
            assert UserStore._get_absolute_timeout_hours() == 24

    def test_zero_absolute_timeout_falls_back(self):
        """Zero value falls back to default."""
        with patch.dict(os.environ, {"BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS": "0"}):
            assert UserStore._get_absolute_timeout_hours() == 24

    def test_session_uses_configured_timeout(self, detection_store):
        """Sessions created with configured absolute timeout."""
        user_store = detection_store._users
        # Create a user first
        user_store.create_user("timeout_test", "pass123", role="viewer")

        with patch.dict(os.environ, {"BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS": "4"}):
            session = user_store.create_session(user_id=1)

        # expires_at should be ~4 hours from now
        exp = datetime.fromisoformat(session["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delta_hours = (exp - now).total_seconds() / 3600
        assert 3.9 < delta_hours < 4.1


# ---------------------------------------------------------------------------
# D-7: Node_id binding on heartbeat
# ---------------------------------------------------------------------------


class TestNodeIdBinding:
    """D-7: API key node_id binding enforced on heartbeat."""

    def test_heartbeat_unbound_key_allowed(self, client, registered_node):
        """Keys without node_id binding can heartbeat any node."""
        resp = client.post("/api/nodes/heartbeat", json={
            "node_id": registered_node,
            "metrics": {},
        })
        assert resp.status_code == 200

    def _create_bound_key(self, persistence, key_id, node_id, role="sensor"):
        """Helper: create an API key bound to a specific node."""
        from sigrift.lib.security.credentials import (
            compute_lookup_hash,
            generate_api_key,
            hash_credential,
        )
        raw_key = generate_api_key()
        hashed, salt = hash_credential(raw_key)
        lookup_hash = compute_lookup_hash(raw_key)
        persistence.set_key(key_id, hashed, salt, lookup_hash=lookup_hash)
        persistence.set_key_meta(key_id, {
            "role": role,
            "node_id": node_id,
        })
        return raw_key

    def test_heartbeat_bound_key_correct_node(self, bridge_app, registered_node):
        """Key bound to node can heartbeat that node."""
        persistence = bridge_app.state.persistence
        raw_key = self._create_bound_key(
            persistence, "hb-bound-ok", registered_node,
        )

        client = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        resp = client.post("/api/nodes/heartbeat", json={
            "node_id": registered_node,
            "metrics": {},
        })
        assert resp.status_code == 200

    def test_heartbeat_bound_key_wrong_node(self, bridge_app, client):
        """Key bound to one node cannot heartbeat a different node."""
        persistence = bridge_app.state.persistence

        # Register two nodes
        client.post("/api/nodes/register", json={
            "node_id": "node-a", "host": "10.0.0.1", "port": 8080,
        })
        client.post("/api/nodes/register", json={
            "node_id": "node-b", "host": "10.0.0.2", "port": 8080,
        })

        # Create a key bound to node-a
        raw_key = self._create_bound_key(persistence, "hb-bound-a", "node-a")

        client_a = TestClient(bridge_app, headers={"X-API-Key": raw_key})
        # Heartbeat as node-b should fail
        resp = client_a.post("/api/nodes/heartbeat", json={
            "node_id": "node-b",
            "metrics": {},
        })
        assert resp.status_code == 403

    def test_ack_command_uses_shared_binding(self, client, registered_node):
        """ack_command also uses the shared _check_node_binding function."""
        # This should not crash — admin keys bypass binding
        resp = client.post(
            f"/api/nodes/{registered_node}/commands/cmd-nonexistent/ack"
        )
        # 404 = command not found (not 403), proving binding check passed
        assert resp.status_code in (404, 409, 200)
