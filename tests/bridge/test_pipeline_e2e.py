"""End-to-end pipeline tests for The Bridge.

Verifies the full detection lifecycle:
  - Submit detection batch via POST /api/detections/batch
  - Query back via GET /api/detections/recent
  - Verify appearance in timeline, distribution, stats
  - High anomaly_score detection triggers auto-alert creation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

class TestDetectionPipeline:
    """Full pipeline: ingest -> query -> timeline -> distribution -> stats."""

    def _ingest_batch(
        self,
        client: TestClient,
        node_id: str,
        detections: list[dict],
    ) -> dict:
        """Helper: ingest a batch and return the response body."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": node_id,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": detections,
        })
        assert resp.status_code == 201
        return resp.json()

    def test_ingest_and_query_recent(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Ingested detection appears in recent query."""
        data = self._ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.92,
                "family": "psk",
                "freq_hz": 433.92e6,
            },
        ])
        assert data["inserted"] == 1

        resp = client.get("/api/detections/recent", params={"minutes": 10})
        assert resp.status_code == 200
        recent = resp.json()
        assert isinstance(recent["count"], int)
        assert recent["count"] >= 1
        classes = [d["signal_class"] for d in recent["detections"]]
        assert "bpsk" in classes

    def test_ingest_and_query_timeline(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Ingested detection appears in timeline."""
        self._ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "qpsk",
                "confidence": 0.88,
                "family": "psk",
                "freq_hz": 915e6,
            },
        ])

        resp = client.get("/api/detections/timeline", params={"hours": 1})
        assert resp.status_code == 200
        timeline = resp.json()
        assert isinstance(timeline, list)
        assert len(timeline) >= 1
        # Timeline buckets should have counts > 0
        total_count = sum(b["count"] for b in timeline)
        assert total_count >= 1

    def test_ingest_and_query_distribution(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Ingested detections appear in distribution grouped by class."""
        self._ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.90,
                "family": "psk",
                "freq_hz": 433.92e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.85,
                "family": "psk",
                "freq_hz": 433.92e6,
            },
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.78,
                "family": "qam",
                "freq_hz": 915e6,
            },
        ])

        resp = client.get("/api/detections/distribution", params={"hours": 1})
        assert resp.status_code == 200
        dist = resp.json()
        assert isinstance(dist, list)
        assert len(dist) >= 2
        dist_classes = {d["signal_class"] for d in dist}
        assert "bpsk" in dist_classes
        assert "qam16" in dist_classes

    def test_ingest_updates_stats(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Stats reflect ingested data."""
        self._ingest_batch(client, registered_node, [
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
        ])

        resp = client.get("/api/detections/stats", params={"hours": 1})
        assert resp.status_code == 200
        stats = resp.json()
        assert isinstance(stats, dict)
        assert isinstance(stats["total_detections"], int)
        assert stats["total_detections"] >= 2
        assert isinstance(stats["unique_classes"], int)
        assert stats["unique_classes"] >= 2
        assert isinstance(stats["unique_nodes"], int)
        assert stats["unique_nodes"] >= 1
        assert isinstance(stats["avg_confidence"], (int, float))
        assert stats["avg_confidence"] > 0.0

    def test_full_pipeline_round_trip(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Complete round-trip: ingest -> recent -> timeline -> dist -> stats."""
        # Ingest
        batch = self._ingest_batch(client, registered_node, [
            {
                "node_id": registered_node,
                "signal_class": "8psk",
                "confidence": 0.91,
                "family": "psk",
                "freq_hz": 868.3e6,
                "snr_db": 18.5,
            },
        ])
        assert batch["accepted"] is True
        assert batch["inserted"] == 1

        # Recent
        resp = client.get("/api/detections/recent", params={"minutes": 10})
        assert resp.status_code == 200
        assert isinstance(resp.json()["count"], int)
        assert resp.json()["count"] >= 1

        # Timeline
        resp = client.get("/api/detections/timeline", params={"hours": 1})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

        # Distribution
        resp = client.get("/api/detections/distribution", params={"hours": 1})
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

        # Stats
        resp = client.get("/api/detections/stats", params={"hours": 1})
        assert resp.status_code == 200
        assert isinstance(resp.json()["total_detections"], int)
        assert resp.json()["total_detections"] >= 1

        # Count
        resp = client.get("/api/detections/count")
        assert resp.status_code == 200
        assert isinstance(resp.json()["total"], int)
        assert resp.json()["total"] >= 1

# ---------------------------------------------------------------------------
# Anomaly auto-alert pipeline
# ---------------------------------------------------------------------------

class TestAnomalyAutoAlert:
    """High anomaly_score detections auto-create alerts."""

    def test_high_anomaly_creates_alert(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score >= 0.7 triggers an alert."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "unknown",
                    "confidence": 0.35,
                    "family": "",
                    "freq_hz": 433.92e6,
                    "anomaly_score": 0.85,
                },
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert isinstance(data["alerts_created"], int)
        assert data["alerts_created"] >= 1

        # Verify alert exists in alerts list
        resp = client.get("/api/alerts/")
        assert resp.status_code == 200
        alerts = resp.json()
        assert isinstance(alerts, list)
        anomaly_alerts = [
            a for a in alerts if a["name"] == "anomaly_detected"
        ]
        assert len(anomaly_alerts) >= 1

    def test_low_anomaly_no_alert(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score < 0.7 does NOT trigger an alert."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.90,
                    "family": "psk",
                    "freq_hz": 915e6,
                    "anomaly_score": 0.3,
                },
            ],
        })
        assert resp.status_code == 201
        assert resp.json()["alerts_created"] == 0

    def test_critical_anomaly_severity(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Detection with anomaly_score >= 0.85 gets critical severity."""
        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "unknown",
                    "confidence": 0.2,
                    "freq_hz": 162.55e6,
                    "anomaly_score": 0.95,
                },
            ],
        })
        assert resp.status_code == 201
        assert isinstance(resp.json()["alerts_created"], int)
        assert resp.json()["alerts_created"] >= 1

        resp = client.get("/api/alerts/")
        alerts = resp.json()
        assert isinstance(alerts, list)
        critical_alerts = [
            a for a in alerts
            if a["name"] == "anomaly_detected" and a["severity"] == "critical"
        ]
        assert len(critical_alerts) >= 1
