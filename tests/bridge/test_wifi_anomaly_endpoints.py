"""Tests for WiFi anomaly API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


class TestWifiAnomalyEndpoints:
    def test_get_anomalies_empty(self, client: TestClient):
        resp = client.get("/api/wifi/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["anomalies"] == []

    def test_get_anomalies_after_insert(self, client: TestClient, detection_store):
        """Insert anomalies directly and verify query."""
        detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "ssid": "EvilNet",
            "channel": 6,
            "band": "2.4GHz",
            "security": "Open",
            "signal_dbm": -30.0,
            "anomaly_score": 0.75,
            "priority": "critical",
            "dimensions": {"evil_twin": 1.0, "security_downgrade": 1.0},
            "reasons": ["Possible evil twin"],
            "baseline_status": "stable",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })
        detection_store.insert_wifi_anomaly({
            "bssid": "dd:ee:ff:44:55:66",
            "ssid": "WeakNet",
            "channel": 11,
            "anomaly_score": 0.4,
            "priority": "interesting",
            "dimensions": {"signal_anomaly": 0.5},
            "reasons": ["Unusual signal"],
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })

        resp = client.get("/api/wifi/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 2
        # Sorted by score desc
        assert data["anomalies"][0]["anomaly_score"] == 0.75

    def test_get_anomalies_min_score_filter(self, client: TestClient, detection_store):
        detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.8,
            "priority": "critical",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })
        detection_store.insert_wifi_anomaly({
            "bssid": "dd:ee:ff:44:55:66",
            "anomaly_score": 0.35,
            "priority": "interesting",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })

        # Default min_score=0.3 → both
        resp = client.get("/api/wifi/anomalies")
        assert resp.json()["count"] == 2

        # Higher min_score → only critical
        resp = client.get("/api/wifi/anomalies?min_score=0.5")
        assert resp.json()["count"] == 1
        assert resp.json()["anomalies"][0]["anomaly_score"] == 0.8

    def test_dismiss_single(self, client: TestClient, detection_store):
        row_id = detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.6,
            "priority": "anomalous",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })

        # Dismiss it
        resp = client.put(f"/api/wifi/anomalies/{row_id}/dismiss")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        # Should not appear in default query (dismissed excluded)
        resp = client.get("/api/wifi/anomalies")
        assert resp.json()["count"] == 0

    def test_bulk_dismiss(self, client: TestClient, detection_store):
        ids = []
        for i in range(3):
            row_id = detection_store.insert_wifi_anomaly({
                "bssid": f"aa:bb:cc:11:22:{i:02x}",
                "anomaly_score": 0.5,
                "priority": "anomalous",
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            })
            ids.append(row_id)

        # Bulk dismiss first two
        resp = client.put("/api/wifi/anomalies/bulk/dismiss", json={"ids": ids[:2]})
        assert resp.status_code == 200
        assert resp.json()["dismissed_count"] == 2

        # Only one left
        resp = client.get("/api/wifi/anomalies")
        assert resp.json()["count"] == 1

    def test_bulk_dismiss_empty_ids(self, client: TestClient):
        resp = client.put("/api/wifi/anomalies/bulk/dismiss", json={"ids": []})
        assert resp.status_code == 400

    def test_dismissed_excluded_from_query(self, client: TestClient, detection_store):
        row_id = detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.5,
            "priority": "anomalous",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })
        detection_store.dismiss_wifi_anomaly(row_id)

        resp = client.get("/api/wifi/anomalies")
        assert resp.json()["count"] == 0

    def test_anomaly_dimensions_parsed(self, client: TestClient, detection_store):
        detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "anomaly_score": 0.6,
            "priority": "anomalous",
            "dimensions": {"evil_twin": 1.0, "new_network": 1.0},
            "reasons": ["Evil twin detected", "New BSSID"],
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
        })

        resp = client.get("/api/wifi/anomalies")
        anomaly = resp.json()["anomalies"][0]
        assert isinstance(anomaly["dimensions"], dict)
        assert anomaly["dimensions"]["evil_twin"] == 1.0
        assert isinstance(anomaly["reasons"], list)
        assert len(anomaly["reasons"]) == 2

    def test_reevaluate_inline(self, client: TestClient, detection_store):
        """GET /anomalies?reevaluate=true should include reeval data."""
        detection_store.insert_wifi_anomaly({
            "bssid": "aa:bb:cc:11:22:33",
            "ssid": "TestNet",
            "channel": 6,
            "band": "2.4GHz",
            "security": "WPA2",
            "signal_dbm": -50.0,
            "anomaly_score": 0.6,
            "priority": "anomalous",
            "dimensions": {"new_network": 1.0},
            "reasons": ["New network"],
            "baseline_status": "new",
            "node_id": "node-01",
            "timestamp": "2026-02-11T00:00:00+00:00",
            "client_count": 2,
            "retry_rate": 0.0,
            "frame_count": 10,
            "deauth_count": 0,
        })

        # Without reevaluate — no reeval field
        resp = client.get("/api/wifi/anomalies")
        assert resp.status_code == 200
        data = resp.json()
        assert "reeval_summary" not in data
        assert "reeval" not in data["anomalies"][0]

        # With reevaluate=true — includes reeval on each anomaly
        resp = client.get("/api/wifi/anomalies?reevaluate=true")
        assert resp.status_code == 200
        data = resp.json()
        assert "reeval_summary" in data
        assert isinstance(data["reeval_summary"], dict)
        assert data["reeval_summary"]["still_anomalous"] + data["reeval_summary"]["resolved"] == 1
        anomaly = data["anomalies"][0]
        assert "reeval" in anomaly
        reeval = anomaly["reeval"]
        assert isinstance(reeval, dict)
        assert "still_anomalous" in reeval
        assert isinstance(reeval["still_anomalous"], bool)
        assert "new_score" in reeval
        assert "score_delta" in reeval
        assert isinstance(reeval["score_delta"], float)
        assert isinstance(reeval["new_score"], float)

    def test_reeval_dismiss_all(self, client: TestClient, detection_store):
        """POST /anomalies/bulk/reeval-dismiss processes entire queue."""
        for i in range(5):
            detection_store.insert_wifi_anomaly({
                "bssid": f"aa:bb:cc:11:22:{i:02x}",
                "ssid": f"Net{i}",
                "channel": 6,
                "band": "2.4GHz",
                "security": "WPA2",
                "signal_dbm": -50.0,
                "anomaly_score": 0.6,
                "priority": "anomalous",
                "dimensions": {"new_network": 1.0},
                "reasons": ["New network"],
                "baseline_status": "new",
                "node_id": "node-01",
                "timestamp": "2026-02-11T00:00:00+00:00",
            })

        resp = client.post("/api/wifi/anomalies/bulk/reeval-dismiss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["processed"] == 5
        assert data["still_anomalous"] + data["dismissed"] == 5
        assert data["errors"] == 0
        assert "remaining_total" in data
        assert isinstance(data["remaining_total"], int)

    def test_batch_upsert_deduplicates(self, client: TestClient, detection_store):
        """Batch insert deduplicates by BSSID — updates existing active row."""
        bssid = "aa:bb:cc:de:du:p1"
        # First insert
        detection_store.insert_wifi_anomalies_batch([{
            "bssid": bssid, "anomaly_score": 0.5, "priority": "anomalous",
            "node_id": "node-01", "timestamp": "2026-02-11T00:00:00+00:00",
        }])
        # Second insert — same BSSID, higher score
        detection_store.insert_wifi_anomalies_batch([{
            "bssid": bssid, "anomaly_score": 0.8, "priority": "critical",
            "node_id": "node-01", "timestamp": "2026-02-11T01:00:00+00:00",
        }])
        # Third insert — same BSSID again
        detection_store.insert_wifi_anomalies_batch([{
            "bssid": bssid, "anomaly_score": 0.7, "priority": "critical",
            "node_id": "node-01", "timestamp": "2026-02-11T02:00:00+00:00",
        }])

        # Should be ONE row, not three
        resp = client.get("/api/wifi/anomalies?min_score=0.3")
        data = resp.json()
        matching = [a for a in data["anomalies"] if a["bssid"] == bssid]
        assert len(matching) == 1
        assert matching[0]["anomaly_score"] == 0.7  # latest score
        assert matching[0]["seen_count"] == 3

    def test_upsert_dismissed_reactivates(self, client: TestClient, detection_store):
        """After dismissing, a new anomaly for same BSSID reactivates the existing row."""
        bssid = "aa:bb:cc:de:du:p2"
        ids = detection_store.insert_wifi_anomalies_batch([{
            "bssid": bssid, "anomaly_score": 0.6, "priority": "anomalous",
            "node_id": "node-01", "timestamp": "2026-02-11T00:00:00+00:00",
        }])
        detection_store.dismiss_wifi_anomaly(ids[0])

        # New insert after dismiss — should reactivate existing row (not create new)
        detection_store.insert_wifi_anomalies_batch([{
            "bssid": bssid, "anomaly_score": 0.9, "priority": "critical",
            "node_id": "node-01", "timestamp": "2026-02-11T03:00:00+00:00",
        }])

        resp = client.get("/api/wifi/anomalies?min_score=0.3")
        data = resp.json()
        matching = [a for a in data["anomalies"] if a["bssid"] == bssid]
        assert len(matching) == 1
        assert matching[0]["anomaly_score"] == 0.9
        assert matching[0]["seen_count"] == 2  # reactivated, incremented
