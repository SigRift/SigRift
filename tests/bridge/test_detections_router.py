"""Comprehensive tests for the detections router.

Tests cover:
  - Batch ingestion (success, missing node, empty batch)
  - Query endpoint
  - Recent detections
  - Statistics
  - Timeline
  - Heatmap
  - Distribution
  - Anomalies
  - Aggregation trigger
  - Row count
  - Authentication requirement
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Batch ingestion tests
# ---------------------------------------------------------------------------

class TestBatchIngestion:
    """Tests for POST /api/detections/batch."""

    def test_ingest_batch_success(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Successful batch ingestion."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                },
                {
                    "node_id": registered_node,
                    "signal_class": "qam16",
                    "confidence": 0.85,
                    "family": "qam",
                    "freq_hz": 915e6,
                },
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 2
        assert data["total"] == 2

    def test_ingest_batch_unregistered_node(self, client: TestClient) -> None:
        """Batch from unregistered node returns 404."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": "unknown-node",
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [],
        })
        assert resp.status_code == 404

    def test_ingest_batch_empty(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Empty batch is accepted with 0 insertions."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [],
        })
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 0

    def test_ingest_batch_mismatched_node_id(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detections with mismatched node_id are corrected."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": "wrong-node",
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                },
            ],
        })
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 1

# ---------------------------------------------------------------------------
# Query endpoint tests
# ---------------------------------------------------------------------------

class TestQueryEndpoint:
    """Tests for POST /api/detections/query."""

    def test_query_empty(self, client: TestClient) -> None:
        """Query on empty store returns empty list."""
        resp = client.post("/api/detections/query", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["detections"] == []

    def test_query_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Query returns ingested detections."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                },
            ],
        })
        resp = client.post("/api/detections/query", json={
            "signal_class": "bpsk",
        })
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

    def test_query_with_filters(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Query respects filters."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
                {"node_id": registered_node, "signal_class": "qpsk", "confidence": 0.5},
            ],
        })
        resp = client.post("/api/detections/query", json={
            "min_confidence": 0.7,
        })
        assert resp.status_code == 200
        assert resp.json()["count"] == 1

# ---------------------------------------------------------------------------
# Recent detections tests
# ---------------------------------------------------------------------------

class TestRecentEndpoint:
    """Tests for GET /api/detections/recent."""

    def test_recent_empty(self, client: TestClient) -> None:
        """Recent on empty store returns empty."""
        resp = client.get("/api/detections/recent")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_recent_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Recent returns recently ingested detections."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
            ],
        })
        resp = client.get("/api/detections/recent", params={"minutes": 10})
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

# ---------------------------------------------------------------------------
# Stats endpoint tests
# ---------------------------------------------------------------------------

class TestStatsEndpoint:
    """Tests for GET /api/detections/stats."""

    def test_stats_empty(self, client: TestClient) -> None:
        """Stats on empty store return zeroes."""
        resp = client.get("/api/detections/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_detections"] == 0

    def test_stats_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Stats reflect ingested data."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
                {"node_id": registered_node, "signal_class": "qam16", "confidence": 0.8},
            ],
        })
        resp = client.get("/api/detections/stats", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_detections"] == 2
        assert data["unique_classes"] == 2

# ---------------------------------------------------------------------------
# Timeline endpoint tests
# ---------------------------------------------------------------------------

class TestTimelineEndpoint:
    """Tests for GET /api/detections/timeline."""

    def test_timeline_empty(self, client: TestClient) -> None:
        """Timeline on empty store returns empty list."""
        resp = client.get("/api/detections/timeline")
        assert resp.status_code == 200
        assert resp.json() == []

# ---------------------------------------------------------------------------
# Heatmap endpoint tests
# ---------------------------------------------------------------------------

class TestHeatmapEndpoint:
    """Tests for GET /api/detections/heatmap."""

    def test_heatmap_empty(self, client: TestClient) -> None:
        """Heatmap on empty store returns empty list."""
        resp = client.get("/api/detections/heatmap")
        assert resp.status_code == 200
        assert resp.json() == []

# ---------------------------------------------------------------------------
# Distribution endpoint tests
# ---------------------------------------------------------------------------

class TestDistributionEndpoint:
    """Tests for GET /api/detections/distribution."""

    def test_distribution_empty(self, client: TestClient) -> None:
        """Distribution on empty store returns empty list."""
        resp = client.get("/api/detections/distribution")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_distribution_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Distribution groups correctly."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9, "family": "psk"},
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.85, "family": "psk"},
                {"node_id": registered_node, "signal_class": "qam16", "confidence": 0.7, "family": "qam"},
            ],
        })
        resp = client.get("/api/detections/distribution", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 2

# ---------------------------------------------------------------------------
# Anomalies endpoint tests
# ---------------------------------------------------------------------------

class TestAnomaliesEndpoint:
    """Tests for GET /api/detections/anomalies."""

    def test_anomalies_empty(self, client: TestClient) -> None:
        """Anomalies on empty store returns empty."""
        resp = client.get("/api/detections/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0

    def test_anomalies_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Anomalies returns high-score detections."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9, "anomaly_score": 0.1},
                {"node_id": registered_node, "signal_class": "unknown", "confidence": 0.3, "anomaly_score": 0.8},
            ],
        })
        resp = client.get("/api/detections/anomalies", params={"min_score": 0.5})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["anomalies"][0]["anomaly_score"] == 0.8

    def test_reevaluate_inline(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """GET /anomalies?reevaluate=true includes reeval data."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "unknown",
                    "confidence": 0.3,
                    "anomaly_score": 0.7,
                    "freq_hz": 433920000,
                },
            ],
        })

        # Without reevaluate — no reeval field
        resp = client.get("/api/detections/anomalies", params={"min_score": 0.3})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert "reeval_summary" not in data
        assert "reeval" not in data["anomalies"][0]

        # With reevaluate=true — includes reeval on each anomaly
        resp = client.get("/api/detections/anomalies", params={
            "min_score": 0.3, "reevaluate": "true",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["reeval_summary"], dict)
        summary = data["reeval_summary"]
        assert summary["still_anomalous"] + summary["resolved"] == 1
        anomaly = data["anomalies"][0]
        assert isinstance(anomaly["reeval"], dict)
        reeval = anomaly["reeval"]
        assert isinstance(reeval["still_anomalous"], bool)
        assert isinstance(reeval["new_score"], float)
        assert isinstance(reeval["score_delta"], float)

# ---------------------------------------------------------------------------
# Aggregation and count tests
# ---------------------------------------------------------------------------

class TestAggregationAndCount:
    """Tests for POST /api/detections/aggregate and GET /api/detections/count."""

    def test_aggregate_empty(self, client: TestClient) -> None:
        """Aggregate on empty store succeeds."""
        resp = client.post("/api/detections/aggregate")
        assert resp.status_code == 200
        assert isinstance(resp.json()["aggregated_rows"], int)

    def test_count_empty(self, client: TestClient) -> None:
        """Count on empty store returns 0."""
        resp = client.get("/api/detections/count")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_count_after_insert(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Count reflects insertions."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {"node_id": registered_node, "signal_class": "bpsk", "confidence": 0.9},
                {"node_id": registered_node, "signal_class": "qpsk", "confidence": 0.8},
            ],
        })
        resp = client.get("/api/detections/count")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    """Tests for authentication requirements."""

    def test_no_api_key(self, bridge_app) -> None:
        """Requests without API key return 401."""
        from fastapi.testclient import TestClient
        unauth_client = TestClient(bridge_app)
        resp = unauth_client.get("/api/detections/stats")
        assert resp.status_code == 401

    def test_invalid_api_key(self, bridge_app) -> None:
        """Requests with invalid API key return 401."""
        from fastapi.testclient import TestClient
        bad_client = TestClient(bridge_app, headers={"X-API-Key": "invalid-key"})
        resp = bad_client.get("/api/detections/stats")
        assert resp.status_code == 401

# ---------------------------------------------------------------------------
# Health and status endpoint tests
# ---------------------------------------------------------------------------

class TestHealthAndStatus:
    """Tests for GET /api/health and GET /api/status."""

    def test_health(self, client: TestClient) -> None:
        """Health check returns ok."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "4.0.0"

    def test_status(self, client: TestClient) -> None:
        """System status returns expected fields."""
        resp = client.get("/api/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["node_count"], int)
        assert isinstance(data["total_detections_24h"], int)
        assert isinstance(data["active_anomalies"], int)

# ---------------------------------------------------------------------------
# Node management tests
# ---------------------------------------------------------------------------

class TestNodeManagement:
    """Tests for node registration and heartbeat."""

    def test_register_node(self, client: TestClient) -> None:
        """Register a node."""
        resp = client.post("/api/nodes/register", json={
            "node_id": "test-node",
            "host": "10.0.0.1",
            "port": 8080,
        })
        assert resp.status_code == 200
        assert resp.json()["node_id"] == "test-node"

    def test_list_nodes(self, client: TestClient, registered_node: str) -> None:
        """List nodes after registration."""
        resp = client.get("/api/nodes/")
        assert resp.status_code == 200
        nodes = resp.json()
        assert len(nodes) >= 1

    def test_get_node(self, client: TestClient, registered_node: str) -> None:
        """Get a specific node."""
        resp = client.get(f"/api/nodes/{registered_node}")
        assert resp.status_code == 200
        assert resp.json()["node_id"] == registered_node

    def test_get_node_not_found(self, client: TestClient) -> None:
        """Get non-existent node returns 404."""
        resp = client.get("/api/nodes/nonexistent")
        assert resp.status_code == 404

    def test_heartbeat(self, client: TestClient, registered_node: str) -> None:
        """Heartbeat from registered node is accepted."""
        resp = client.post("/api/nodes/heartbeat", json={
            "node_id": registered_node,
            "metrics": {},
        })
        assert resp.status_code == 200
        assert resp.json()["accepted"] is True

    def test_heartbeat_with_detection_summary(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Heartbeat with detection summary is accepted."""
        resp = client.post("/api/nodes/heartbeat", json={
            "node_id": registered_node,
            "metrics": {},
            "detection_summary": {
                "period_seconds": 60.0,
                "total_frames": 100,
                "class_counts": {"bpsk": 50, "qpsk": 30},
                "avg_confidence": 0.87,
                "dominant_class": "bpsk",
                "dominant_family": "psk",
            },
        })
        assert resp.status_code == 200
        assert resp.json()["accepted"] is True

    def test_heartbeat_unregistered_node(self, client: TestClient) -> None:
        """Heartbeat from unregistered node returns 404."""
        resp = client.post("/api/nodes/heartbeat", json={
            "node_id": "ghost-node",
            "metrics": {},
        })
        assert resp.status_code == 404

# ---------------------------------------------------------------------------
# Feedback endpoint tests
# ---------------------------------------------------------------------------

class TestFeedbackEndpoint:
    """Tests for POST /api/detections/anomalies/{detection_id}/feedback."""

    def _ingest_detection(
        self, client: TestClient, registered_node: str, detection_id: str = "det-001",
    ) -> None:
        """Helper: ingest a detection with a known detection_id."""
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "unknown",
                    "confidence": 0.3,
                    "anomaly_score": 0.85,
                    "detection_id": detection_id,
                },
            ],
        })

    def test_feedback_true_positive(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Submit true_positive feedback."""
        self._ingest_detection(client, registered_node, "det-tp")
        resp = client.post("/api/detections/anomalies/det-tp/feedback", json={
            "label": "true_positive",
            "note": "Confirmed anomaly",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["detection_id"] == "det-tp"
        assert data["label"] == "true_positive"
        assert data["auto_dismissed"] is False

    def test_feedback_false_positive_auto_dismisses(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """false_positive feedback auto-dismisses the anomaly."""
        self._ingest_detection(client, registered_node, "det-fp")
        resp = client.post("/api/detections/anomalies/det-fp/feedback", json={
            "label": "false_positive",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["auto_dismissed"] is True

    def test_feedback_expected_auto_dismisses(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """expected feedback auto-dismisses the anomaly."""
        self._ingest_detection(client, registered_node, "det-exp")
        resp = client.post("/api/detections/anomalies/det-exp/feedback", json={
            "label": "expected",
            "note": "Known WiFi beacon",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["auto_dismissed"] is True
        assert data["note"] == "Known WiFi beacon"

    def test_feedback_interesting(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """interesting feedback does not auto-dismiss."""
        self._ingest_detection(client, registered_node, "det-int")
        resp = client.post("/api/detections/anomalies/det-int/feedback", json={
            "label": "interesting",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["auto_dismissed"] is False

    def test_feedback_invalid_label(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Invalid label returns 422."""
        self._ingest_detection(client, registered_node, "det-bad")
        resp = client.post("/api/detections/anomalies/det-bad/feedback", json={
            "label": "invalid_label",
        })
        assert resp.status_code == 422

    def test_feedback_stored_in_db(
        self, client: TestClient, registered_node: str, detection_store,
    ) -> None:
        """Feedback is persisted in the detection store."""
        self._ingest_detection(client, registered_node, "det-db")
        client.post("/api/detections/anomalies/det-db/feedback", json={
            "label": "true_positive",
            "note": "Stored check",
        })
        feedbacks = detection_store.get_feedback("det-db")
        assert len(feedbacks) >= 1
        assert feedbacks[0]["label"] == "true_positive"
        assert feedbacks[0]["note"] == "Stored check"
