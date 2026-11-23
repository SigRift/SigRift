"""Tests for the wideband FFT spectrum monitor feature.

Covers snapshot ingestion, monitor endpoint, history query,
peak detection with classified/unclassified flagging, cleanup,
and auth requirements.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from sigrift.bridge.tests.conftest import make_detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_snapshot_payload(
    node_id: str = "node-test-01",
    center_freq_hz: float = 915e6,
    bandwidth_hz: float = 2e6,
    fft_size: int = 256,
    psd_dbm: list | None = None,
    timestamp: str | None = None,
) -> dict:
    """Build a valid snapshot payload for POST /api/spectrum/snapshots."""
    if psd_dbm is None:
        # Generate a PSD with a noise floor around -100 dBm and one peak at bin 128
        psd_dbm = [-100.0] * fft_size
        psd_dbm[128] = -40.0  # strong peak
        psd_dbm[64] = -80.0   # weak signal
    return {
        "node_id": node_id,
        "center_freq_hz": center_freq_hz,
        "bandwidth_hz": bandwidth_hz,
        "fft_size": fft_size,
        "psd_dbm": psd_dbm,
        **({"timestamp": timestamp} if timestamp else {}),
    }


# ---------------------------------------------------------------------------
# Test: Snapshot ingestion
# ---------------------------------------------------------------------------


class TestSnapshotIngestion:
    """POST /api/spectrum/snapshots"""

    def test_ingest_snapshot(self, client: TestClient, registered_node: str):
        payload = _make_snapshot_payload(node_id=registered_node)
        resp = client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["node_id"] == registered_node
        assert data["bins"] == 256
        assert isinstance(data["id"], int)

    def test_ingest_snapshot_gzipped(self, client: TestClient, registered_node: str):
        import gzip

        payload = _make_snapshot_payload(node_id=registered_node)
        body = gzip.compress(json.dumps(payload).encode())
        resp = client.post(
            "/api/spectrum/snapshots",
            content=body,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["accepted"] is True

    def test_ingest_missing_field(self, client: TestClient, registered_node: str):
        payload = {"node_id": registered_node}
        resp = client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422
        assert "Missing required field" in resp.json()["detail"]

    def test_ingest_empty_psd(self, client: TestClient, registered_node: str):
        payload = _make_snapshot_payload(node_id=registered_node, psd_dbm=[])
        resp = client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 422

    def test_ingest_requires_auth(self, client: TestClient):
        """Without API key, ingestion should fail."""
        payload = _make_snapshot_payload()
        # Create a new client without auth
        no_auth_client = TestClient(client.app)
        resp = no_auth_client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Test: Monitor endpoint
# ---------------------------------------------------------------------------


class TestMonitorEndpoint:
    """GET /api/spectrum/monitor"""

    def test_monitor_empty(self, client: TestClient):
        resp = client.get("/api/spectrum/monitor")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["snapshots"] == []

    def test_monitor_returns_latest(self, client: TestClient, registered_node: str):
        # Ingest two snapshots
        ts1 = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        ts2 = datetime.now(timezone.utc).isoformat()

        for ts in [ts1, ts2]:
            payload = _make_snapshot_payload(node_id=registered_node, timestamp=ts)
            resp = client.post(
                "/api/spectrum/snapshots",
                content=json.dumps(payload),
                headers={"Content-Type": "application/json"},
            )
            assert resp.status_code == 201

        resp = client.get("/api/spectrum/monitor")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        snap = data["snapshots"][0]
        assert snap["node_id"] == registered_node
        assert isinstance(snap["psd_dbm"], list)

    def test_monitor_filter_by_node(self, client: TestClient, registered_node: str):
        payload = _make_snapshot_payload(node_id=registered_node)
        client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

        resp = client.get(f"/api/spectrum/monitor?node_id={registered_node}")
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1

        resp = client.get("/api/spectrum/monitor?node_id=nonexistent-node")
        assert resp.status_code == 200
        assert resp.json()["count"] == 0


# ---------------------------------------------------------------------------
# Test: History query
# ---------------------------------------------------------------------------


class TestHistoryQuery:
    """GET /api/spectrum/monitor/history"""

    def test_history_requires_node_id(self, client: TestClient):
        resp = client.get("/api/spectrum/monitor/history")
        assert resp.status_code == 422  # Missing required param

    def test_history_returns_snapshots(self, client: TestClient, registered_node: str):
        # Ingest a snapshot
        payload = _make_snapshot_payload(node_id=registered_node)
        client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

        resp = client.get(
            f"/api/spectrum/monitor/history?node_id={registered_node}&hours=1"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["node_id"] == registered_node
        assert data["count"] >= 1
        assert len(data["snapshots"]) >= 1


# ---------------------------------------------------------------------------
# Test: Peak detection
# ---------------------------------------------------------------------------


class TestPeakDetection:
    """GET /api/spectrum/monitor/peaks"""

    def test_peaks_empty(self, client: TestClient):
        resp = client.get("/api/spectrum/monitor/peaks?hours=1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0

    def test_peaks_above_noise_floor(self, client: TestClient, registered_node: str):
        # PSD with clear peak at bin 128
        psd = [-100.0] * 256
        psd[128] = -40.0  # 60 dB above noise

        payload = _make_snapshot_payload(
            node_id=registered_node,
            psd_dbm=psd,
        )
        resp = client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 201

        resp = client.get("/api/spectrum/monitor/peaks?hours=1&threshold_db=10")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1

        # The strong peak should be found
        peak_powers = [p["power_dbm"] for p in data["peaks"]]
        assert -40.0 in peak_powers

    def test_classified_vs_unclassified_peaks(
        self, client: TestClient, registered_node: str, detection_store
    ):
        """Peaks matching a detection should be flagged as classified."""
        center_freq = 915e6
        bw = 2e6
        fft_size = 256
        bin_width = bw / fft_size

        # The peak at bin 128 => freq = 915e6 - 1e6 + 128 * bin_width
        peak_freq = center_freq - bw / 2 + 128 * bin_width

        # Insert a detection at the peak frequency
        det = make_detection(
            node_id=registered_node,
            signal_class="bpsk",
            freq_hz=peak_freq,
        )
        detection_store.insert_batch([det])

        # Ingest snapshot with peak at that frequency
        psd = [-100.0] * fft_size
        psd[128] = -40.0

        payload = _make_snapshot_payload(
            node_id=registered_node,
            center_freq_hz=center_freq,
            bandwidth_hz=bw,
            fft_size=fft_size,
            psd_dbm=psd,
        )
        client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

        resp = client.get("/api/spectrum/monitor/peaks?hours=1&threshold_db=10")
        data = resp.json()
        assert data["count"] >= 1

        # Find the peak near -40 dBm and check classification
        strong_peaks = [p for p in data["peaks"] if p["power_dbm"] == -40.0]
        assert len(strong_peaks) >= 1
        assert strong_peaks[0]["classified"] is True

    def test_unclassified_peak(self, client: TestClient, registered_node: str):
        """Peaks without matching detections should be unclassified."""
        psd = [-100.0] * 256
        psd[200] = -30.0  # peak with no matching detection

        payload = _make_snapshot_payload(
            node_id=registered_node,
            center_freq_hz=2400e6,  # different freq range, no detections here
            bandwidth_hz=5e6,
            psd_dbm=psd,
        )
        client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

        resp = client.get("/api/spectrum/monitor/peaks?hours=1&threshold_db=10")
        data = resp.json()
        unclassified = [p for p in data["peaks"] if not p["classified"]]
        assert len(unclassified) >= 1


# ---------------------------------------------------------------------------
# Test: Cleanup
# ---------------------------------------------------------------------------


class TestCleanup:
    """Spectrum snapshot cleanup via store method."""

    def test_cleanup_old_snapshots(
        self, client: TestClient, registered_node: str, detection_store
    ):
        # Ingest a current snapshot
        payload = _make_snapshot_payload(node_id=registered_node)
        client.post(
            "/api/spectrum/snapshots",
            content=json.dumps(payload),
            headers={"Content-Type": "application/json"},
        )

        # Directly insert an old snapshot via store
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        detection_store.insert_spectrum_snapshot({
            "node_id": registered_node,
            "timestamp": old_ts,
            "center_freq_hz": 915e6,
            "bandwidth_hz": 2e6,
            "fft_size": 256,
            "bin_width_hz": 2e6 / 256,
            "psd_dbm": [-100.0] * 256,
            "noise_floor_dbm": -100.0,
            "peak_freq_hz": 915e6,
            "peak_power_dbm": -100.0,
        })

        # Cleanup with 24h retention
        deleted = detection_store.cleanup_spectrum_snapshots(max_age_hours=24)
        assert deleted >= 1

        # Current snapshot should still exist
        resp = client.get("/api/spectrum/monitor")
        assert resp.json()["count"] >= 1


# ---------------------------------------------------------------------------
# Test: Auth required on all endpoints
# ---------------------------------------------------------------------------


class TestAuthRequired:
    """All spectrum monitor endpoints require authentication."""

    def test_monitor_requires_auth(self, client: TestClient):
        no_auth = TestClient(client.app)
        resp = no_auth.get("/api/spectrum/monitor")
        assert resp.status_code in (401, 403)

    def test_history_requires_auth(self, client: TestClient):
        no_auth = TestClient(client.app)
        resp = no_auth.get("/api/spectrum/monitor/history?node_id=x")
        assert resp.status_code in (401, 403)

    def test_peaks_requires_auth(self, client: TestClient):
        no_auth = TestClient(client.app)
        resp = no_auth.get("/api/spectrum/monitor/peaks")
        assert resp.status_code in (401, 403)
