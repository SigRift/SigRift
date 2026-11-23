"""Tests for multi-node correlation in sigrift.bridge.anomaly.correlator.

Covers:
  - Single-node detection has no correlation
  - Two nodes detecting same signal within window -> correlated
  - Two nodes with different signals -> not correlated
  - Time window expiry
  - Frequency tolerance (within 100kHz = correlated)
  - Correlation API endpoints
  - Correlation summary
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.correlator import (
    NodeCorrelator,
    _freq_bin,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _det(
    node_id: str = "node-01",
    signal_class: str = "bpsk",
    family: str = "psk",
    freq_hz: float = 433.92e6,
    timestamp: datetime | None = None,
    confidence: float = 0.9,
    snr_db: float = 15.0,
) -> dict:
    """Build a detection dict for correlator tests."""
    return {
        "node_id": node_id,
        "signal_class": signal_class,
        "family": family,
        "freq_hz": freq_hz,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "confidence": confidence,
        "snr_db": snr_db,
    }

# ---------------------------------------------------------------------------
# Unit tests: NodeCorrelator
# ---------------------------------------------------------------------------

class TestNodeCorrelator:
    """Tests for the NodeCorrelator class."""

    def test_single_node_no_correlation(self) -> None:
        """A detection with only same-node recent detections is not correlated."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", timestamp=now)
        recent = [
            _det(node_id="node-01", timestamp=now - timedelta(seconds=5)),
            _det(node_id="node-01", timestamp=now - timedelta(seconds=10)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is False
        assert result.node_count == 1
        assert result.confidence_boost == 0.0

    def test_two_nodes_same_signal_correlated(self) -> None:
        """Two nodes detecting same signal class + freq within window -> correlated."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", timestamp=now)
        recent = [
            _det(node_id="node-02", timestamp=now - timedelta(seconds=3)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is True
        assert result.node_count == 2
        assert set(result.node_ids) == {"node-01", "node-02"}
        assert result.confidence_boost > 0.0

    def test_two_nodes_different_signal_not_correlated(self) -> None:
        """Two nodes detecting different signals are not correlated."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", signal_class="bpsk", family="psk", timestamp=now)
        recent = [
            _det(node_id="node-02", signal_class="fm", family="analog", timestamp=now - timedelta(seconds=5)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is False

    def test_time_window_expiry(self) -> None:
        """Detections outside the time window are not correlated."""
        correlator = NodeCorrelator(time_window_sec=30)
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", timestamp=now)
        recent = [
            _det(node_id="node-02", timestamp=now - timedelta(seconds=60)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is False

    def test_time_window_boundary(self) -> None:
        """Detection exactly at the window boundary is correlated."""
        correlator = NodeCorrelator(time_window_sec=30)
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", timestamp=now)
        recent = [
            _det(node_id="node-02", timestamp=now - timedelta(seconds=29)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is True

    def test_frequency_tolerance_within(self) -> None:
        """Detections within 100kHz bin -> correlated."""
        correlator = NodeCorrelator(freq_tolerance_hz=100_000)
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", freq_hz=433.92e6, timestamp=now)
        recent = [
            _det(node_id="node-02", freq_hz=433.95e6, timestamp=now - timedelta(seconds=5)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is True

    def test_frequency_tolerance_outside(self) -> None:
        """Detections in different 100kHz bins -> not correlated."""
        correlator = NodeCorrelator(freq_tolerance_hz=100_000)
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", freq_hz=433.92e6, timestamp=now)
        recent = [
            _det(node_id="node-02", freq_hz=434.15e6, timestamp=now - timedelta(seconds=5)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is False

    def test_three_nodes_higher_boost(self) -> None:
        """Three correlated nodes give higher boost than two."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detection = _det(node_id="node-01", timestamp=now)
        recent = [
            _det(node_id="node-02", timestamp=now - timedelta(seconds=2)),
            _det(node_id="node-03", timestamp=now - timedelta(seconds=4)),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is True
        assert result.node_count == 3
        assert result.confidence_boost > 0.1

    def test_same_family_different_class_correlated(self) -> None:
        """Same family but different class should still correlate."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detection = _det(
            node_id="node-01", signal_class="bpsk", family="psk", timestamp=now,
        )
        recent = [
            _det(
                node_id="node-02", signal_class="qpsk", family="psk",
                timestamp=now - timedelta(seconds=5),
            ),
        ]

        result = correlator.check_correlation(detection, recent)
        assert result.correlated is True

    def test_empty_recent_no_correlation(self) -> None:
        """No recent detections means no correlation."""
        correlator = NodeCorrelator()
        detection = _det(node_id="node-01")

        result = correlator.check_correlation(detection, [])
        assert result.correlated is False
        assert result.node_count == 1

# ---------------------------------------------------------------------------
# Correlation groups
# ---------------------------------------------------------------------------

class TestCorrelationGroups:
    """Tests for find_correlation_groups and correlation_summary."""

    def test_find_groups_basic(self) -> None:
        """Two nodes detecting same signal forms a group."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detections = [
            _det(node_id="node-01", timestamp=now),
            _det(node_id="node-02", timestamp=now - timedelta(seconds=3)),
        ]

        groups = correlator.find_correlation_groups(detections, min_nodes=2)
        assert len(groups) == 1
        assert len(groups[0].nodes) == 2
        assert groups[0].signal_class == "bpsk"

    def test_find_groups_min_nodes_filter(self) -> None:
        """Groups with fewer nodes than min_nodes are excluded."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detections = [
            _det(node_id="node-01", timestamp=now),
            _det(node_id="node-02", timestamp=now - timedelta(seconds=10)),
        ]

        groups = correlator.find_correlation_groups(detections, min_nodes=3)
        assert len(groups) == 0

    def test_summary_empty(self) -> None:
        """Summary with no correlations returns zeros."""
        correlator = NodeCorrelator()
        summary = correlator.correlation_summary([], min_nodes=2)

        assert summary["total_correlations_24h"] == 0
        assert summary["avg_nodes_per_correlation"] == 0.0
        assert summary["top_correlated_classes"] == []

    def test_summary_with_data(self) -> None:
        """Summary counts correlations and top classes."""
        correlator = NodeCorrelator()
        now = datetime.now(timezone.utc)

        detections = [
            _det(node_id="node-01", signal_class="bpsk", family="psk", timestamp=now),
            _det(node_id="node-02", signal_class="bpsk", family="psk", timestamp=now - timedelta(seconds=5)),
            _det(node_id="node-01", signal_class="fm", family="analog", freq_hz=100e6, timestamp=now),
            _det(node_id="node-02", signal_class="fm", family="analog", freq_hz=100e6, timestamp=now - timedelta(seconds=5)),
        ]

        summary = correlator.correlation_summary(detections, min_nodes=2)
        assert summary["total_correlations_24h"] >= 2
        assert summary["avg_nodes_per_correlation"] >= 2.0
        assert len(summary["top_correlated_classes"]) >= 1

# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

class TestFreqBin:
    """Tests for frequency binning."""

    def test_same_bin(self) -> None:
        """Frequencies within 100kHz share a bin."""
        assert _freq_bin(433.92e6) == _freq_bin(433.95e6)

    def test_different_bin(self) -> None:
        """Frequencies > 100kHz apart are in different bins."""
        assert _freq_bin(433.92e6) != _freq_bin(434.15e6)

class TestConfidenceBoost:
    """Tests for confidence boost calculation."""

    def test_single_node_no_boost(self) -> None:
        assert NodeCorrelator._compute_boost(1) == 0.0

    def test_two_nodes_boost(self) -> None:
        assert NodeCorrelator._compute_boost(2) == 0.1

    def test_three_nodes_boost(self) -> None:
        assert NodeCorrelator._compute_boost(3) == 0.15

    def test_four_plus_nodes_capped(self) -> None:
        assert NodeCorrelator._compute_boost(4) == 0.2
        assert NodeCorrelator._compute_boost(10) == 0.2

# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

class TestCorrelationEndpoints:
    """Tests for correlation API endpoints."""

    def test_correlations_empty(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Correlations endpoint with no data returns empty list."""
        resp = client.get("/api/detections/correlations")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["correlations"] == []

    def test_correlations_with_multi_node_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Correlations endpoint finds groups when multiple nodes report."""
        now = datetime.now(timezone.utc)

        # Register a second node
        resp = client.post("/api/nodes/register", json={
            "node_id": "node-test-02",
            "host": "192.168.1.101",
            "port": 8080,
        })
        assert resp.status_code == 200

        # Ingest from node 1
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                    "timestamp": now.isoformat(),
                },
            ],
        })
        assert resp.status_code == 201

        # Ingest from node 2
        resp = client.post("/api/detections/batch", json={
            "node_id": "node-test-02",
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": "node-test-02",
                    "signal_class": "bpsk",
                    "confidence": 0.88,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                    "timestamp": (now - timedelta(seconds=5)).isoformat(),
                },
            ],
        })
        assert resp.status_code == 201

        # Query correlations
        resp = client.get("/api/detections/correlations", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        group = data["correlations"][0]
        assert group["signal_class"] == "bpsk"
        assert len(group["nodes"]) >= 2

    def test_correlations_signal_class_filter(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Signal class filter narrows results."""
        resp = client.get(
            "/api/detections/correlations",
            params={"signal_class": "nonexistent_signal"},
        )
        assert resp.status_code == 200
        assert resp.json()["count"] == 0

    def test_correlation_summary_empty(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Summary endpoint with no data returns zeros."""
        resp = client.get("/api/detections/correlations/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_correlations_24h"] == 0
        assert data["avg_nodes_per_correlation"] == 0.0
        assert data["top_correlated_classes"] == []

    def test_correlation_summary_with_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Summary endpoint returns stats after multi-node ingestion."""
        now = datetime.now(timezone.utc)

        # Register second node
        client.post("/api/nodes/register", json={
            "node_id": "node-test-02",
            "host": "192.168.1.101",
            "port": 8080,
        })

        # Ingest from both nodes
        for node in [registered_node, "node-test-02"]:
            client.post("/api/detections/batch", json={
                "node_id": node,
                "period_start": (now - timedelta(minutes=1)).isoformat(),
                "period_end": now.isoformat(),
                "detections": [
                    {
                        "node_id": node,
                        "signal_class": "fm",
                        "confidence": 0.90,
                        "family": "analog",
                        "freq_hz": 100e6,
                        "timestamp": now.isoformat(),
                    },
                ],
            })

        resp = client.get("/api/detections/correlations/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_correlations_24h"] >= 1

    def test_correlations_requires_auth(
        self, bridge_app,
    ) -> None:
        """Correlations endpoint requires authentication."""
        unauth_client = TestClient(bridge_app)
        resp = unauth_client.get("/api/detections/correlations")
        assert resp.status_code in (401, 403)

    def test_correlation_summary_requires_auth(
        self, bridge_app,
    ) -> None:
        """Summary endpoint requires authentication."""
        unauth_client = TestClient(bridge_app)
        resp = unauth_client.get("/api/detections/correlations/summary")
        assert resp.status_code in (401, 403)
