"""End-to-end tests for the IQ capture pipeline.

Verifies the full lifecycle:
  1. Create a detection via POST /api/detections/batch
  2. Upload gzipped IQ data via PUT /api/detections/{id}/iq
  3. Retrieve IQ visualization via GET /api/detections/{id}/iq
  4. Verify metadata indexing via GET /api/iq/index
  5. Verify storage stats via GET /api/iq/stats
"""

from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone

import numpy as np
from fastapi.testclient import TestClient

def _make_iq_data(n_samples: int = 256) -> bytes:
    """Create gzip-compressed float32 interleaved IQ data."""
    t = np.linspace(0, 1, n_samples, dtype=np.float32)
    i_vals = np.cos(2 * np.pi * 10 * t).astype(np.float32)
    q_vals = np.sin(2 * np.pi * 10 * t).astype(np.float32)
    interleaved = np.empty(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = i_vals
    interleaved[1::2] = q_vals
    return gzip.compress(interleaved.tobytes())

class TestIQCaptureE2E:
    """Full IQ pipeline: ingest detection -> upload IQ -> retrieve -> index -> stats."""

    def _create_detection(
        self, client: TestClient, node_id: str, detection_id: str | None = None,
    ) -> str:
        """Ingest a detection and return its ID."""
        now = datetime.now(timezone.utc)
        det = {
            "node_id": node_id,
            "signal_class": "bpsk",
            "confidence": 0.90,
            "family": "psk",
            "freq_hz": 433.92e6,
            "snr_db": 15.0,
        }
        if detection_id:
            det["id"] = detection_id
        resp = client.post("/api/detections/batch", json={
            "node_id": node_id,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [det],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted"] == 1

        # Fetch the most recent detection to get its actual ID
        resp = client.get("/api/detections/recent", params={"minutes": 10})
        assert resp.status_code == 200
        detections = resp.json()["detections"]
        assert len(detections) >= 1
        return detections[0]["detection_id"]

    def test_full_iq_pipeline(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Complete round-trip: create detection -> upload IQ -> retrieve -> index -> stats."""
        det_id = self._create_detection(client, registered_node)

        # Upload IQ data
        iq_data = _make_iq_data(n_samples=512)
        resp = client.put(
            f"/api/detections/{det_id}/iq",
            content=iq_data,
            headers={
                "Content-Encoding": "gzip",
                "X-Sample-Rate": "2.048e6",
                "X-IQ-Samples": "512",
            },
        )
        assert resp.status_code == 201
        upload_data = resp.json()
        assert upload_data["stored"] is True
        assert upload_data["detection_id"] == det_id
        assert upload_data["size_bytes"] > 0

        # Retrieve IQ visualization (JSON format)
        resp = client.get(f"/api/detections/{det_id}/iq")
        assert resp.status_code == 200
        viz = resp.json()
        # Visualization should contain constellation or PSD data
        assert isinstance(viz, dict)

        # Verify metadata indexing
        resp = client.get("/api/iq/index")
        assert resp.status_code == 200
        index = resp.json()
        assert len(index) >= 1
        indexed_ids = [entry["detection_id"] for entry in index]
        assert det_id in indexed_ids

        # Verify stats
        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_captures"] >= 1
        assert stats["total_size_bytes"] > 0

    def test_iq_upload_without_detection_creates_stub(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Uploading IQ for a nonexistent detection auto-creates a stub."""
        fake_id = "stub-det-e2e-001"
        iq_data = _make_iq_data()
        resp = client.put(
            f"/api/detections/{fake_id}/iq",
            content=iq_data,
            headers={
                "Content-Encoding": "gzip",
                "X-Node-Id": registered_node,
                "X-Freq-Hz": "915e6",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["stored"] is True

        # Should be retrievable
        resp = client.get(f"/api/detections/{fake_id}/iq")
        assert resp.status_code == 200

    def test_iq_retrieval_404_when_missing(
        self, client: TestClient,
    ) -> None:
        """GET IQ for a detection with no capture returns 404."""
        resp = client.get("/api/detections/nonexistent-det/iq")
        assert resp.status_code == 404

    def test_iq_index_filter_by_node(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """IQ index can be filtered by node_id."""
        det_id = self._create_detection(client, registered_node)
        iq_data = _make_iq_data()
        resp = client.put(
            f"/api/detections/{det_id}/iq",
            content=iq_data,
            headers={"Content-Encoding": "gzip"},
        )
        assert resp.status_code == 201

        # Filter by the correct node
        resp = client.get("/api/iq/index", params={"node_id": registered_node})
        assert resp.status_code == 200
        entries = resp.json()
        assert len(entries) >= 1
        assert all(e["node_id"] == registered_node for e in entries)

        # Filter by a different node should return fewer (or none from this upload)
        resp = client.get("/api/iq/index", params={"node_id": "nonexistent-node"})
        assert resp.status_code == 200
        entries = resp.json()
        matching = [e for e in entries if e["detection_id"] == det_id]
        assert len(matching) == 0

    def test_multiple_iq_uploads_tracked(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Multiple IQ uploads are all reflected in index and stats."""
        det_ids = []
        for i in range(3):
            det_id = self._create_detection(client, registered_node)
            det_ids.append(det_id)
            iq_data = _make_iq_data(n_samples=128 * (i + 1))
            resp = client.put(
                f"/api/detections/{det_id}/iq",
                content=iq_data,
                headers={"Content-Encoding": "gzip"},
            )
            assert resp.status_code == 201

        # All should appear in index
        resp = client.get("/api/iq/index")
        assert resp.status_code == 200
        index = resp.json()
        indexed_ids = {entry["detection_id"] for entry in index}
        for det_id in det_ids:
            assert det_id in indexed_ids

        # Stats should reflect all uploads
        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_captures"] >= 3
