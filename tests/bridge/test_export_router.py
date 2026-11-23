"""Tests for the export router endpoints (CSV and JSON export)."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager


def _seed_data(client: TestClient, registered_node: str) -> None:
    """Seed detection data and alerts for export tests."""
    now = datetime.now(timezone.utc)
    # Batch ingest some detections
    client.post("/api/detections/batch", json={
        "node_id": registered_node,
        "period_start": (now - timedelta(minutes=10)).isoformat(),
        "period_end": now.isoformat(),
        "detections": [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.92,
                "family": "psk",
                "freq_hz": 433.92e6,
                "snr_db": 15.0,
            },
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.85,
                "family": "qam",
                "freq_hz": 915e6,
                "anomaly_score": 0.75,
            },
        ],
    })
    # Create an alert
    client.post("/api/alerts/rules", json={
        "name": "Export Test Alert",
        "severity": "warning",
    })


class TestExportNodes:
    """GET /api/export/nodes — export node data."""

    def test_export_nodes_json(self, client: TestClient, registered_node: str):
        resp = client.get("/api/export/nodes", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["meta"], dict)
        assert isinstance(data["nodes"], dict)
        assert data["meta"]["format"] == "json"
        assert "record_count" in data["meta"]
        assert isinstance(data["meta"]["record_count"], int)

    def test_export_nodes_csv(self, client: TestClient, registered_node: str):
        resp = client.get("/api/export/nodes", params={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        content = resp.text
        assert isinstance(content, str)
        assert len(content) > 0
        assert "node_id" in content  # CSV header


class TestExportTraining:
    """GET /api/export/training — export training history."""

    def test_export_training_json(self, client: TestClient):
        resp = client.get("/api/export/training", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["meta"], dict)
        assert "format" in data["meta"]
        assert data["meta"]["format"] == "json"
        assert isinstance(data["history"], dict)

    def test_export_training_csv(self, client: TestClient):
        resp = client.get("/api/export/training", params={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]


class TestExportAlerts:
    """GET /api/export/alerts — export alert history."""

    def test_export_alerts_json(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/alerts", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["alerts"], list)
        assert len(data["alerts"]) >= 1
        assert isinstance(data["alerts"][0], dict)
        assert data["meta"]["record_count"] >= 1
        assert isinstance(data["meta"]["record_count"], int)

    def test_export_alerts_csv(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/alerts", params={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert isinstance(resp.text, str)
        assert len(resp.text) > 0
        assert "alert_id" in resp.text

    def test_export_alerts_with_date_filter(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/alerts", params={
            "format": "json",
            "start_date": "2020-01-01T00:00:00+00:00",
            "end_date": "2030-01-01T00:00:00+00:00",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["meta"]["record_count"], int)
        assert data["meta"]["record_count"] >= 1

    def test_export_alerts_invalid_start_date(self, client: TestClient):
        resp = client.get("/api/export/alerts", params={
            "format": "json",
            "start_date": "not-a-date",
        })
        assert resp.status_code == 400

    def test_export_alerts_invalid_end_date(self, client: TestClient):
        resp = client.get("/api/export/alerts", params={
            "format": "json",
            "end_date": "not-a-date",
        })
        assert resp.status_code == 400


class TestExportDetections:
    """GET /api/export/detections — export detection data."""

    def test_export_detections_json(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/detections", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["detections"], list)
        assert len(data["detections"]) >= 1
        assert isinstance(data["detections"][0], dict)
        assert isinstance(data["meta"], dict)
        assert "record_count" in data["meta"]
        assert isinstance(data["meta"]["record_count"], int)

    def test_export_detections_csv(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/detections", params={"format": "csv"})
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_export_detections_with_filters(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/detections", params={
            "format": "json",
            "hours": 1,
            "node_id": registered_node,
            "signal_class": "bpsk",
            "min_confidence": 0.5,
        })
        assert resp.status_code == 200

    def test_export_detections_anomaly_filter(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/detections", params={
            "format": "json",
            "min_anomaly_score": 0.5,
        })
        assert resp.status_code == 200


class TestExportAnomalies:
    """GET /api/export/anomalies — export anomaly detections."""

    def test_export_anomalies_json(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/anomalies", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["anomalies"], list)
        assert isinstance(data["meta"], dict)

    def test_export_anomalies_csv(self, client: TestClient, registered_node: str):
        _seed_data(client, registered_node)
        resp = client.get("/api/export/anomalies", params={"format": "csv"})
        assert resp.status_code == 200


class TestExportWifiNetworks:
    """GET /api/export/wifi_networks — export WiFi network data."""

    def test_export_wifi_networks_json(self, client: TestClient):
        # Seed some wifi data
        for i in range(3):
            client.post("/api/wifi/networks", json={
                "bssid": f"AA:BB:CC:DD:EE:{i:02X}",
                "ssid": f"TestNet-{i}",
                "channel": 1 + i,
                "signal_dbm": -50,
                "encryption": "WPA2",
            })
        resp = client.get("/api/export/wifi_networks", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["wifi_networks"], list)
        assert isinstance(data["meta"], dict)

    def test_export_wifi_networks_csv(self, client: TestClient):
        resp = client.get("/api/export/wifi_networks", params={"format": "csv"})
        assert resp.status_code == 200


class TestExportWifiAnomalies:
    """GET /api/export/wifi_anomalies — export WiFi anomalies."""

    def test_export_wifi_anomalies_json(self, client: TestClient):
        resp = client.get("/api/export/wifi_anomalies", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["wifi_anomalies"], list)
        assert isinstance(data["meta"], dict)

    def test_export_wifi_anomalies_csv(self, client: TestClient):
        resp = client.get("/api/export/wifi_anomalies", params={"format": "csv"})
        assert resp.status_code == 200


class TestExportRfAnomalies:
    """GET /api/export/rf_anomalies — export RF anomalies."""

    def test_export_rf_anomalies_json(self, client: TestClient):
        resp = client.get("/api/export/rf_anomalies", params={"format": "json"})
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["rf_anomalies"], list)
        assert isinstance(data["meta"], dict)

    def test_export_rf_anomalies_csv(self, client: TestClient):
        resp = client.get("/api/export/rf_anomalies", params={"format": "csv"})
        assert resp.status_code == 200

    def test_export_rf_anomalies_with_filters(self, client: TestClient):
        resp = client.get("/api/export/rf_anomalies", params={
            "format": "json",
            "min_score": 0.5,
            "include_dismissed": True,
            "family": "psk",
        })
        assert resp.status_code == 200


_XSS = "<img src=x onerror=alert(1)>"
_XSS_ESCAPED = "&lt;img src=x onerror=alert(1)&gt;"


class TestExportEscapingAndStoredShapes:
    """Every string is escaped; a hand-edited history entry is no run."""

    def test_json_exports_escape_every_string_at_any_depth(
        self, client: TestClient, persistence: PersistenceManager
    ) -> None:
        """Dict keys and strings in lists too (the Shiny export's rule)."""
        nested = {
            "<k>": [_XSS, {"<k2>": [[_XSS]], "n": 1}, ("<t>", None)],
            "ok": {"deep": {"<k3>": _XSS}},
        }
        escaped = {
            "&lt;k&gt;": [
                _XSS_ESCAPED,
                {"&lt;k2&gt;": [[_XSS_ESCAPED]], "n": 1},
                ["&lt;t&gt;", None],
            ],
            "ok": {"deep": {"&lt;k3&gt;": _XSS_ESCAPED}},
        }
        persistence.set_node("edge-01", {"capabilities": nested})
        persistence.add_alert({"alert_id": "a1", "thresholds": nested})
        persistence.add_history_entry("edge-01", {"run_id": "r", "cfg": nested})

        body = client.get("/api/export/nodes").json()
        assert body["nodes"]["edge-01"]["capabilities"] == escaped
        body = client.get("/api/export/alerts").json()
        assert body["alerts"][0]["thresholds"] == escaped
        resp = client.get("/api/export/training")
        assert resp.json()["history"]["edge-01"][0]["cfg"] == escaped
        assert "<" not in resp.text

    def test_escaping_rule_is_the_shiny_export_s(self) -> None:
        from sigrift.bridge.routers import export as bridge_export
        from sigrift.lib.shiny.routers import export as shiny_export

        for value in (
            {"<a>": ["<b>", ("<c>", {"<d>": "<e>"})], "n": 1.5, "t": True},
            ["<x>", None, 3],
            "<y>",
            7,
            None,
        ):
            assert bridge_export._escape_value(value) == (
                shiny_export._escape_value(value)
            )

    def test_training_export_skips_entries_that_are_not_runs(
        self, client: TestClient, persistence: PersistenceManager
    ) -> None:
        """history.json as hand-edited, loaded as at startup: no 500, no miscount."""
        persistence.save_all()  # keep the test keys across the reload
        (persistence.data_dir / "history.json").write_text(
            json.dumps(
                {
                    "history": {
                        "edge-01": [{"run_id": "r1"}, "junk", 5, None, {"run_id": "r2"}],
                        "edge-02": ["only junk"],
                        "edge-03": "not a list",
                    }
                }
            )
        )
        persistence.load_all()

        resp = client.get("/api/export/training", params={"format": "csv"})
        assert resp.status_code == 200
        rows = list(csv.DictReader(io.StringIO(resp.text)))
        assert [(r["node_id"], r["run_id"]) for r in rows] == [
            ("edge-01", "r1"),
            ("edge-01", "r2"),
        ]
        body = client.get("/api/export/training").json()
        assert body["meta"]["record_count"] == 2
        assert body["history"] == {
            "edge-01": [{"run_id": "r1"}, {"run_id": "r2"}],
            "edge-02": [],
        }
