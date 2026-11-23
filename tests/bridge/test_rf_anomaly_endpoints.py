"""Tests for RF anomaly API endpoints (dedicated rf_anomalies table)."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestRfAnomalyEndpoints:
    def test_get_anomalies_empty(self, client: TestClient):
        resp = client.get("/api/detections/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["total"] == 0
        assert data["anomalies"] == []

    def test_get_anomalies_after_insert(self, client: TestClient, detection_store):
        """Insert RF anomalies directly and verify query."""
        detection_store.insert_rf_anomalies_batch([
            {
                "detection_id": "det-001",
                "signal_class": "bpsk",
                "family": "psk",
                "freq_hz": 433.92e6,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
                "confidence": 0.92,
                "snr_db": 15.0,
                "power_dbm": -30.0,
                "anomaly_score": 0.75,
                "baseline_status": "stable",
                "dimensions": {"novel_class": 0.9, "rare_class": 0.5},
                "reasons": ["Novel signal class at this frequency"],
            },
            {
                "detection_id": "det-002",
                "signal_class": "16qam",
                "family": "qam",
                "freq_hz": 915e6,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:01:00+00:00",
                "confidence": 0.6,
                "anomaly_score": 0.4,
                "dimensions": {"low_confidence": 0.8},
                "reasons": ["Low confidence detection"],
            },
        ])

        resp = client.get("/api/detections/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        assert data["total"] == 2
        # Sorted by score desc
        assert data["anomalies"][0]["anomaly_score"] == 0.75

    def test_get_anomalies_min_score_filter(self, client: TestClient, detection_store):
        detection_store.insert_rf_anomalies_batch([
            {
                "signal_class": "bpsk",
                "freq_hz": 433.92e6,
                "anomaly_score": 0.8,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            },
            {
                "signal_class": "qpsk",
                "freq_hz": 915e6,
                "anomaly_score": 0.35,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:01:00+00:00",
            },
        ])

        # Default min_score=0.3 -> both
        resp = client.get("/api/detections/anomalies")
        assert resp.json()["count"] == 2

        # Higher min_score -> only critical
        resp = client.get("/api/detections/anomalies?min_score=0.5")
        assert resp.json()["count"] == 1
        assert resp.json()["anomalies"][0]["anomaly_score"] == 0.8

    def test_dismiss_single(self, client: TestClient, detection_store):
        ids = detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.6,
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        }])
        row_id = ids[0]

        # Dismiss it
        resp = client.put(f"/api/detections/anomalies/{row_id}/dismiss")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Should not appear in default query
        resp = client.get("/api/detections/anomalies")
        assert resp.json()["count"] == 0

    def test_bulk_dismiss(self, client: TestClient, detection_store):
        all_ids = []
        for i in range(3):
            ids = detection_store.insert_rf_anomalies_batch([{
                "signal_class": f"class{i}",
                "freq_hz": (433 + i) * 1e6,
                "anomaly_score": 0.5,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            }])
            all_ids.extend(ids)

        # Bulk dismiss first two
        resp = client.put("/api/detections/anomalies/bulk/dismiss",
                          json={"ids": all_ids[:2]})
        assert resp.status_code == 200
        assert resp.json()["dismissed_count"] == 2

        # Only one left
        resp = client.get("/api/detections/anomalies")
        assert resp.json()["count"] == 1

    def test_bulk_dismiss_empty_ids(self, client: TestClient):
        resp = client.put("/api/detections/anomalies/bulk/dismiss",
                          json={"ids": []})
        assert resp.status_code == 422  # validation error: min_length=1

    def test_dedup_by_signal_class_freq(self, client: TestClient, detection_store):
        """Batch insert deduplicates by signal_class + freq_bucket."""
        # First insert
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.5,
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        }])
        # Second insert — same class + freq bucket, higher score
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.8,
            "node_id": "node-01",
            "timestamp": "2026-02-11T01:00:00+00:00",
        }])
        # Third insert — same again
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.7,
            "node_id": "node-01",
            "timestamp": "2026-02-11T02:00:00+00:00",
        }])

        # Should be ONE row, not three
        resp = client.get("/api/detections/anomalies?min_score=0.3")
        data = resp.json()
        matching = [a for a in data["anomalies"] if a["signal_class"] == "bpsk"]
        assert len(matching) == 1
        assert matching[0]["anomaly_score"] == 0.7  # latest score
        assert matching[0]["seen_count"] == 3

    def test_dedup_dismissed_creates_new(self, client: TestClient, detection_store):
        """After dismissing, a new anomaly for same dedup key creates a new row."""
        ids = detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.6,
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        }])
        detection_store.dismiss_rf_anomaly(ids[0])

        # New insert after dismiss — should create new row
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.9,
            "node_id": "node-01",
            "timestamp": "2026-02-11T03:00:00+00:00",
        }])

        resp = client.get("/api/detections/anomalies?min_score=0.3")
        data = resp.json()
        matching = [a for a in data["anomalies"] if a["signal_class"] == "bpsk"]
        assert len(matching) == 1
        assert matching[0]["anomaly_score"] == 0.9
        assert matching[0]["seen_count"] == 1

    def test_reevaluate_inline(self, client: TestClient, detection_store):
        """GET /anomalies?reevaluate=true should include reeval data."""
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "family": "psk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.6,
            "confidence": 0.92,
            "snr_db": 15.0,
            "power_dbm": -30.0,
            "baseline_status": "new",
            "dimensions": {"novel_class": 1.0},
            "reasons": ["Novel signal class"],
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        }])

        # Without reevaluate — no reeval field
        resp = client.get("/api/detections/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert "reeval_summary" not in data
        assert "reeval" not in data["anomalies"][0]

        # With reevaluate=true — includes reeval on each anomaly
        resp = client.get("/api/detections/anomalies?reevaluate=true")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["reeval_summary"], dict)
        assert data["reeval_summary"]["still_anomalous"] + data["reeval_summary"]["resolved"] == 1
        anomaly = data["anomalies"][0]
        assert isinstance(anomaly["reeval"], dict)
        reeval = anomaly["reeval"]
        assert isinstance(reeval["still_anomalous"], bool)
        assert isinstance(reeval["new_score"], float)
        assert isinstance(reeval["score_delta"], float)

    def test_reeval_dismiss_all(self, client: TestClient, detection_store):
        """POST /anomalies/bulk/reeval-dismiss processes entire queue."""
        for i in range(5):
            detection_store.insert_rf_anomalies_batch([{
                "signal_class": f"class{i}",
                "freq_hz": (433 + i * 10) * 1e6,
                "anomaly_score": 0.6,
                "confidence": 0.92,
                "dimensions": {"novel_class": 1.0},
                "reasons": ["Test anomaly"],
                "baseline_status": "new",
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            }])

        resp = client.post("/api/detections/anomalies/bulk/reeval-dismiss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["processed"] == 5
        assert data["still_anomalous"] + data["dismissed"] == 5
        assert data["errors"] == 0
        assert isinstance(data["remaining_total"], int)

    def test_dimensions_parsed(self, client: TestClient, detection_store):
        detection_store.insert_rf_anomalies_batch([{
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "anomaly_score": 0.6,
            "dimensions": {"novel_class": 1.0, "rare_class": 0.5},
            "reasons": ["Novel class", "Rare at this frequency"],
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        }])

        resp = client.get("/api/detections/anomalies")
        anomaly = resp.json()["anomalies"][0]
        assert isinstance(anomaly["dimensions"], dict)
        assert anomaly["dimensions"]["novel_class"] == 1.0
        assert isinstance(anomaly["reasons"], list)
        assert len(anomaly["reasons"]) == 2

    def test_total_count_in_response(self, client: TestClient, detection_store):
        """Response includes total count even when limit truncates results."""
        for i in range(10):
            detection_store.insert_rf_anomalies_batch([{
                "signal_class": f"class{i}",
                "freq_hz": (400 + i * 10) * 1e6,
                "anomaly_score": 0.5 + i * 0.01,
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            }])

        resp = client.get("/api/detections/anomalies?limit=3")
        data = resp.json()
        assert data["count"] == 3
        assert data["total"] == 10
