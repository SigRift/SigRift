"""Tests for bandwidth estimation and the bandwidth_hz detection field.

Covers:
  - Migration adds bandwidth_hz column
  - estimate_bandwidth() for known signal classes
  - Bandwidth estimation with frequency-dependent adjustments
  - Ingest with and without bandwidth_hz field
  - Bandwidth appears in query results
  - Bandwidth analytics endpoint (GET /api/spectrum/bandwidth)
  - Bandwidth in spectrum activity responses
  - Bandwidth in occupancy responses
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionQuery
from sigrift.bridge.rf_utils import BANDWIDTH_BY_CLASS, estimate_bandwidth
from sigrift.bridge.tests.conftest import make_detection

# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------

class TestMigration:
    """Verify migration 12 adds the bandwidth_hz column."""

    def test_column_exists(self, detection_store: DetectionStore) -> None:
        """bandwidth_hz column exists in the detections table."""
        conn = detection_store.get_connection()
        info = conn.execute("PRAGMA table_info(detections)").fetchall()
        col_names = [row[1] for row in info]
        assert "bandwidth_hz" in col_names

    def test_column_allows_null(self, detection_store: DetectionStore) -> None:
        """bandwidth_hz column defaults to NULL."""
        det = make_detection()
        # Force bandwidth_hz to None explicitly
        det.bandwidth_hz = None
        detection_store.insert_batch([det])
        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        assert results[0]["bandwidth_hz"] is None

# ---------------------------------------------------------------------------
# estimate_bandwidth() tests
# ---------------------------------------------------------------------------

class TestEstimateBandwidth:
    """Tests for the bandwidth estimation function."""

    def test_known_classes_return_values(self) -> None:
        """All known canonical classes return a numeric bandwidth."""
        for cls_name, expected_bw in BANDWIDTH_BY_CLASS.items():
            bw = estimate_bandwidth(cls_name)
            assert bw is not None, f"Expected bandwidth for {cls_name}"
            assert isinstance(bw, (int, float))
            assert bw == expected_bw

    def test_unknown_class_returns_none(self) -> None:
        """Unknown signal classes return None."""
        assert estimate_bandwidth("completely-unknown-class") is None
        assert estimate_bandwidth("") is None

    def test_bpsk_bandwidth(self) -> None:
        """BPSK should have 25 kHz typical bandwidth."""
        bw = estimate_bandwidth("bpsk")
        assert bw == 25_000

    def test_ofdm_default(self) -> None:
        """OFDM at 2.4 GHz should default to 20 MHz."""
        bw = estimate_bandwidth("ofdm", freq_hz=2_450_000_000)
        assert bw == 20_000_000

    def test_ofdm_5ghz_adjustment(self) -> None:
        """OFDM at 5 GHz should use 40 MHz."""
        bw = estimate_bandwidth("ofdm", freq_hz=5_200_000_000)
        assert bw == 40_000_000

    def test_ofdm_subghz_adjustment(self) -> None:
        """OFDM below 1 GHz should use 1 MHz."""
        bw = estimate_bandwidth("ofdm", freq_hz=900_000_000)
        assert bw == 1_000_000

    def test_gfsk_bluetooth_adjustment(self) -> None:
        """GFSK at 2.4 GHz (Bluetooth) should use 1 MHz."""
        bw = estimate_bandwidth("gfsk", freq_hz=2_440_000_000)
        assert bw == 1_000_000

    def test_gfsk_generic(self) -> None:
        """GFSK outside 2.4 GHz should use default 50 kHz."""
        bw = estimate_bandwidth("gfsk", freq_hz=433_920_000)
        assert bw == 50_000

    def test_fm_bandwidth(self) -> None:
        """FM should have 200 kHz bandwidth."""
        bw = estimate_bandwidth("fm")
        assert bw == 200_000

    def test_lora_bandwidth(self) -> None:
        """LoRa-CSS should have 125 kHz bandwidth."""
        bw = estimate_bandwidth("lora-css")
        assert bw == 125_000

    def test_freq_zero_uses_default(self) -> None:
        """When freq_hz is 0, frequency adjustments are skipped."""
        bw = estimate_bandwidth("ofdm", freq_hz=0.0)
        assert bw == 20_000_000  # default OFDM value

# ---------------------------------------------------------------------------
# Ingest tests
# ---------------------------------------------------------------------------

class TestIngestBandwidth:
    """Tests for bandwidth_hz in detection insertion."""

    def test_insert_with_explicit_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """Explicit bandwidth_hz is preserved through insert/query."""
        det = make_detection(bandwidth_hz=500_000.0)
        detection_store.insert_batch([det])
        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        assert results[0]["bandwidth_hz"] == 500_000.0

    def test_insert_without_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """Detection without bandwidth_hz stores NULL."""
        det = make_detection()
        det.bandwidth_hz = None
        detection_store.insert_batch([det])
        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        assert results[0]["bandwidth_hz"] is None

    def test_batch_mixed_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """Batch with some detections having bandwidth and others not."""
        dets = [
            make_detection(signal_class="bpsk", bandwidth_hz=25_000.0),
            make_detection(signal_class="fm"),  # no bandwidth
        ]
        dets[1].bandwidth_hz = None
        detection_store.insert_batch(dets)
        results = detection_store.query(DetectionQuery(limit=10))
        bws = {r["signal_class"]: r["bandwidth_hz"] for r in results}
        assert bws["bpsk"] == 25_000.0
        assert bws["fm"] is None

# ---------------------------------------------------------------------------
# Query results tests
# ---------------------------------------------------------------------------

class TestQueryBandwidth:
    """Tests that bandwidth_hz appears in query results."""

    def test_query_includes_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """SELECT * queries include bandwidth_hz field."""
        det = make_detection(bandwidth_hz=100_000.0)
        detection_store.insert_batch([det])
        results = detection_store.query(DetectionQuery(limit=1))
        assert "bandwidth_hz" in results[0]
        assert results[0]["bandwidth_hz"] == 100_000.0

    def test_recent_includes_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_recent() results include bandwidth_hz."""
        now = datetime.now(timezone.utc)
        det = make_detection(bandwidth_hz=200_000.0, timestamp=now)
        detection_store.insert_batch([det])
        results = detection_store.get_recent(minutes=5)
        assert len(results) == 1
        assert results[0]["bandwidth_hz"] == 200_000.0

    def test_get_by_id_includes_bandwidth(
        self, detection_store: DetectionStore,
    ) -> None:
        """get_detection_by_id() includes bandwidth_hz."""
        det = make_detection(bandwidth_hz=1_000_000.0)
        detection_store.insert_batch([det])
        result = detection_store.get_detection_by_id(det.detection_id)
        assert result is not None
        assert isinstance(result, dict)
        assert result["bandwidth_hz"] == 1_000_000.0

# ---------------------------------------------------------------------------
# API endpoint tests (ingest with bandwidth estimation)
# ---------------------------------------------------------------------------

class TestIngestEndpointBandwidth:
    """Tests for bandwidth estimation in the batch ingest endpoint."""

    def test_ingest_estimates_bandwidth(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Ingest without bandwidth_hz estimates from signal class."""
        payload = {
            "node_id": registered_node,
            "period_start": datetime.now(timezone.utc).isoformat(),
            "period_end": datetime.now(timezone.utc).isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                },
            ],
        }
        resp = client.post("/api/detections/batch", json=payload)
        assert resp.status_code == 201

        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        # bpsk should get estimated bandwidth of 25 kHz
        assert results[0]["bandwidth_hz"] == 25_000.0

    def test_ingest_preserves_explicit_bandwidth(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Ingest with explicit bandwidth_hz preserves the value."""
        payload = {
            "node_id": registered_node,
            "period_start": datetime.now(timezone.utc).isoformat(),
            "period_end": datetime.now(timezone.utc).isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                    "bandwidth_hz": 50_000.0,
                },
            ],
        }
        resp = client.post("/api/detections/batch", json=payload)
        assert resp.status_code == 201

        results = detection_store.query(DetectionQuery(limit=1))
        assert len(results) == 1
        # Explicit value should be preserved, not overwritten
        assert results[0]["bandwidth_hz"] == 50_000.0

# ---------------------------------------------------------------------------
# Bandwidth analytics endpoint
# ---------------------------------------------------------------------------

class TestBandwidthEndpoint:
    """Tests for GET /api/spectrum/bandwidth."""

    def test_empty_database(self, client: TestClient) -> None:
        """Empty database returns empty classes list."""
        resp = client.get("/api/spectrum/bandwidth")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 24
        assert data["classes"] == []

    def test_returns_distribution(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Returns bandwidth stats grouped by signal class."""
        now = datetime.now(timezone.utc)
        dets = [
            make_detection(
                node_id=registered_node,
                signal_class="bpsk",
                bandwidth_hz=25_000.0,
                timestamp=now - timedelta(minutes=i),
            )
            for i in range(5)
        ] + [
            make_detection(
                node_id=registered_node,
                signal_class="fm",
                bandwidth_hz=200_000.0,
                timestamp=now - timedelta(minutes=i),
            )
            for i in range(3)
        ]
        detection_store.insert_batch(dets)

        resp = client.get("/api/spectrum/bandwidth?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["classes"]) == 2

        bpsk_entry = next(
            (c for c in data["classes"] if c["signal_class"] == "bpsk"), None,
        )
        assert bpsk_entry is not None
        assert isinstance(bpsk_entry, dict)
        assert bpsk_entry["detection_count"] == 5
        assert bpsk_entry["avg_bandwidth_hz"] == 25_000.0
        assert bpsk_entry["min_bandwidth_hz"] == 25_000.0
        assert bpsk_entry["max_bandwidth_hz"] == 25_000.0

    def test_node_id_filter(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        """Node filter limits results to that node."""
        now = datetime.now(timezone.utc)
        dets = [
            make_detection(
                node_id=registered_node,
                signal_class="bpsk",
                bandwidth_hz=25_000.0,
                timestamp=now,
            ),
        ]
        detection_store.insert_batch(dets)

        resp = client.get("/api/spectrum/bandwidth?node_id=nonexistent")
        assert resp.status_code == 200
        assert resp.json()["classes"] == []

    def test_requires_auth(self, bridge_app: FastAPI) -> None:
        """Bandwidth endpoint requires VIEWER auth."""
        no_auth = TestClient(bridge_app)
        resp = no_auth.get("/api/spectrum/bandwidth")
        assert resp.status_code == 401

# ---------------------------------------------------------------------------
# Spectrum activity includes bandwidth
# ---------------------------------------------------------------------------

class TestActivityIncludesBandwidth:
    """Tests that spectrum activity responses include bandwidth_hz."""

    def test_activity_includes_bandwidth(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        det = make_detection(
            node_id=registered_node,
            bandwidth_hz=200_000.0,
            timestamp=now,
        )
        detection_store.insert_batch([det])

        resp = client.get("/api/spectrum/activity?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert "bandwidth_hz" in data["activity"][0]
        assert isinstance(data["activity"][0]["bandwidth_hz"], (int, float))
        assert data["activity"][0]["bandwidth_hz"] == 200_000.0

# ---------------------------------------------------------------------------
# Occupancy includes bandwidth
# ---------------------------------------------------------------------------

class TestOccupancyIncludesBandwidth:
    """Tests that occupancy responses include avg_bandwidth_hz."""

    def test_occupancy_includes_bandwidth(
        self,
        client: TestClient,
        detection_store: DetectionStore,
        registered_node: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        dets = [
            make_detection(
                node_id=registered_node,
                signal_class="bpsk",
                freq_hz=433.92e6,
                bandwidth_hz=25_000.0,
                timestamp=now - timedelta(minutes=i),
            )
            for i in range(5)
        ]
        detection_store.insert_batch(dets)

        resp = client.get("/api/spectrum/occupancy?hours=2")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["bins"]) > 0
        assert isinstance(data["bins"][0], dict)
        assert "avg_bandwidth_hz" in data["bins"][0]
        assert isinstance(data["bins"][0]["avg_bandwidth_hz"], (int, float))
        assert data["bins"][0]["avg_bandwidth_hz"] == 25_000.0
