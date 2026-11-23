"""Tests for P1-1: Server-side spectrogram / waterfall viewer.

Covers:
  - IQStore.compute_spectrogram() logic (structure, shape, missing data)
  - GET /{detection_id}/spectrogram endpoint (200, custom nfft, 404, 422)
"""

from __future__ import annotations

import gzip
from pathlib import Path

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.iq_store import IQStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_iq_data(n_samples: int = 4096) -> bytes:
    """Create gzip-compressed IQ data with a tone at normalised freq 0.1."""
    iq = np.exp(1j * 2 * np.pi * 0.1 * np.arange(n_samples)).astype(np.complex64)
    interleaved = np.empty(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    return gzip.compress(interleaved.tobytes())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def iq_store(tmp_path: Path) -> IQStore:
    return IQStore(base_dir=tmp_path / "iq_captures")


@pytest.fixture()
def seeded_store(iq_store: IQStore) -> IQStore:
    """IQStore with a pre-loaded capture at detection_id='det-spec-01'."""
    iq_store.store("det-spec-01", _make_iq_data())
    return iq_store


# ---------------------------------------------------------------------------
# Unit tests: IQStore.compute_spectrogram
# ---------------------------------------------------------------------------

class TestComputeSpectrogramUnit:

    def test_compute_spectrogram_basic(self, seeded_store: IQStore):
        """Returns a dict with the expected top-level keys."""
        result = seeded_store.compute_spectrogram("det-spec-01")
        assert result is not None
        assert isinstance(result, dict)
        for key in ("spectrogram", "time_axis", "freq_axis", "nfft", "n_segments"):
            assert key in result, f"Missing key: {key}"
        assert isinstance(result["spectrogram"], list)
        assert isinstance(result["time_axis"], list)
        assert isinstance(result["freq_axis"], list)
        assert result["nfft"] == 256

    def test_compute_spectrogram_shape(self, seeded_store: IQStore):
        """spectrogram array dimensions match time_axis x freq_axis."""
        nfft = 128
        overlap = 64
        result = seeded_store.compute_spectrogram(
            "det-spec-01", nfft=nfft, overlap=overlap,
        )
        assert result is not None
        assert isinstance(result, dict)
        sg = result["spectrogram"]
        n_time = len(result["time_axis"])
        n_freq = len(result["freq_axis"])
        assert len(sg) == n_time
        assert all(len(row) == n_freq for row in sg)
        assert n_freq == nfft
        assert result["n_segments"] == n_time

    def test_compute_spectrogram_db_range(self, seeded_store: IQStore):
        """All dB values are in [-60, 0]."""
        result = seeded_store.compute_spectrogram("det-spec-01")
        assert result is not None
        assert isinstance(result, dict)
        flat = [v for row in result["spectrogram"] for v in row]
        assert min(flat) >= -60.0
        assert max(flat) <= 0.0

    def test_compute_spectrogram_missing(self, iq_store: IQStore):
        """Returns None for a non-existent detection."""
        assert iq_store.compute_spectrogram("no-such-id") is None


# ---------------------------------------------------------------------------
# Endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def det_id(bridge_app: FastAPI, seeded_store: IQStore) -> str:
    """Wire seeded IQ store into the bridge app, return detection ID."""
    bridge_app.state.iq_store = seeded_store
    return "det-spec-01"


class TestSpectrogramEndpoint:

    def test_spectrogram_endpoint_200(self, client: TestClient, det_id: str):
        resp = client.get(f"/api/detections/{det_id}/spectrogram")
        assert resp.status_code == 200
        body = resp.json()
        assert "spectrogram" in body
        assert isinstance(body["spectrogram"], list)
        assert "time_axis" in body
        assert isinstance(body["time_axis"], list)
        assert "freq_axis" in body
        assert isinstance(body["freq_axis"], list)
        assert body["nfft"] == 256

    def test_spectrogram_endpoint_custom_nfft(self, client: TestClient, det_id: str):
        resp = client.get(f"/api/detections/{det_id}/spectrogram?nfft=512&overlap=256")
        assert resp.status_code == 200
        body = resp.json()
        assert body["nfft"] == 512
        assert len(body["freq_axis"]) == 512

    def test_spectrogram_endpoint_404(self, client: TestClient, det_id: str):
        resp = client.get("/api/detections/nonexistent-id/spectrogram")
        assert resp.status_code == 404

    def test_spectrogram_endpoint_invalid_overlap(self, client: TestClient, det_id: str):
        resp = client.get(f"/api/detections/{det_id}/spectrogram?nfft=128&overlap=128")
        assert resp.status_code == 422

    def test_spectrogram_endpoint_overlap_greater_than_nfft(self, client: TestClient, det_id: str):
        resp = client.get(f"/api/detections/{det_id}/spectrogram?nfft=128&overlap=256")
        assert resp.status_code == 422
