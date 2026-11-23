"""Tests for P1-5: SigMF metadata format for IQ captures.

Covers:
  - SigMF metadata structure (global, captures, annotations)
  - Correct datatype field (cf32_le)
  - Frequency from detection record
  - Annotation label from signal_class
  - Sample rate propagation
  - Hardware field from node_id
  - Bandwidth edge annotations
  - save_sigmf_meta file creation
  - GET /{detection_id}/sigmf endpoint (200, 404)
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.iq_store import IQStore
from sigrift.bridge.sigmf import generate_sigmf_meta, save_sigmf_meta
from sigrift.bridge.tests.conftest import make_detection


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


def _sample_detection_record(**overrides: Any) -> dict[str, Any]:
    """Return a minimal detection record dict for SigMF tests."""
    rec = {
        "freq_hz": 433.92e6,
        "signal_class": "bpsk",
        "timestamp": "2026-02-16T12:00:00+00:00",
        "node_id": "node-test-01",
    }
    rec.update(overrides)
    return rec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def iq_store(tmp_path: Path) -> IQStore:
    return IQStore(base_dir=tmp_path / "iq_captures")


@pytest.fixture()
def seeded_store(iq_store: IQStore) -> IQStore:
    """IQStore with a pre-loaded capture at detection_id='det-sigmf-01'."""
    iq_store.store("det-sigmf-01", _make_iq_data())
    return iq_store


# ---------------------------------------------------------------------------
# Unit tests: generate_sigmf_meta
# ---------------------------------------------------------------------------


class TestGenerateSigmfMeta:
    def test_has_required_sections(self):
        """SigMF metadata must have global, captures, and annotations sections."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert "global" in meta
        assert isinstance(meta["global"], dict)
        assert "captures" in meta
        assert isinstance(meta["captures"], list)
        assert "annotations" in meta
        assert isinstance(meta["annotations"], list)

    def test_datatype_cf32_le(self):
        """Default datatype is cf32_le (complex float32 little-endian)."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert meta["global"]["core:datatype"] == "cf32_le"

    def test_custom_datatype(self):
        """Custom datatype is propagated."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
            data_type="ci16_le",
        )
        assert meta["global"]["core:datatype"] == "ci16_le"

    def test_sample_rate(self):
        """Sample rate from argument appears in global section."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=10e6,
        )
        assert meta["global"]["core:sample_rate"] == 10e6

    def test_version(self):
        """SigMF version is 1.0.0."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert meta["global"]["core:version"] == "1.0.0"

    def test_frequency_from_detection(self):
        """Capture frequency comes from detection record freq_hz."""
        rec = _sample_detection_record(freq_hz=915e6)
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        assert meta["captures"][0]["core:frequency"] == 915e6

    def test_capture_datetime(self):
        """Capture datetime comes from detection timestamp."""
        rec = _sample_detection_record(timestamp="2026-01-15T08:30:00+00:00")
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        assert meta["captures"][0]["core:datetime"] == "2026-01-15T08:30:00+00:00"

    def test_capture_sample_start_zero(self):
        """Capture sample_start is always 0."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert meta["captures"][0]["core:sample_start"] == 0

    def test_annotation_label_from_signal_class(self):
        """Annotation label comes from detection signal_class."""
        rec = _sample_detection_record(signal_class="qam16")
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        assert meta["annotations"][0]["core:label"] == "qam16"

    def test_annotation_sample_start_zero(self):
        """Annotation sample_start is 0."""
        meta = generate_sigmf_meta(
            "det-001",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert meta["annotations"][0]["core:sample_start"] == 0

    def test_hw_from_node_id(self):
        """Hardware field is derived from node_id when no explicit hw given."""
        rec = _sample_detection_record(node_id="sensor-alpha")
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        assert meta["global"]["core:hw"] == "node:sensor-alpha"

    def test_hw_explicit_override(self):
        """Explicit hw kwarg overrides node_id-based hw."""
        rec = _sample_detection_record(node_id="sensor-alpha")
        meta = generate_sigmf_meta(
            "det-001",
            rec,
            sample_rate=2.048e6,
            hw="RTL-SDR v3",
        )
        assert meta["global"]["core:hw"] == "RTL-SDR v3"

    def test_bandwidth_edges(self):
        """When bandwidth_hz is provided, freq_lower_edge and freq_upper_edge are set."""
        rec = _sample_detection_record(freq_hz=433.92e6, bandwidth_hz=200e3)
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        ann = meta["annotations"][0]
        assert ann["core:freq_lower_edge"] == 433.92e6 - 100e3
        assert ann["core:freq_upper_edge"] == 433.92e6 + 100e3

    def test_no_bandwidth_no_edges(self):
        """Without bandwidth_hz, no edge fields appear in annotations."""
        rec = _sample_detection_record()
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        ann = meta["annotations"][0]
        assert "core:freq_lower_edge" not in ann
        assert "core:freq_upper_edge" not in ann

    def test_sample_count_in_annotation(self):
        """When sample_count is in the detection record, it appears in annotation."""
        rec = _sample_detection_record(sample_count=8192)
        meta = generate_sigmf_meta("det-001", rec, sample_rate=2.048e6)
        assert meta["annotations"][0]["core:sample_count"] == 8192

    def test_description_contains_detection_id(self):
        """Description references the detection ID."""
        meta = generate_sigmf_meta(
            "det-xyz-99",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        assert "det-xyz-99" in meta["global"]["core:description"]


# ---------------------------------------------------------------------------
# Unit tests: save_sigmf_meta
# ---------------------------------------------------------------------------


class TestSaveSigmfMeta:
    def test_saves_json_file(self, tmp_path: Path):
        """Writes a .sigmf-meta file that can be parsed as JSON."""
        meta = generate_sigmf_meta(
            "det-save-01",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        path = save_sigmf_meta("det-save-01", meta, base_dir=tmp_path)
        assert path.exists()
        assert path.suffix == ".sigmf-meta"
        loaded = json.loads(path.read_text())
        assert loaded["global"]["core:version"] == "1.0.0"

    def test_invalid_detection_id(self, tmp_path: Path):
        """Empty detection_id raises ValueError."""
        meta = generate_sigmf_meta(
            "x",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        with pytest.raises(ValueError, match="Invalid"):
            save_sigmf_meta("", meta, base_dir=tmp_path)

    def test_special_character_id_is_encoded_not_stripped(self, tmp_path: Path):
        """Ids outside [A-Za-z0-9_-] get an injective, traversal-free name.

        The old sanitizer stripped such characters, so "///" was refused and
        "a.b" overwrote the sidecar of "ab".
        """
        meta = generate_sigmf_meta(
            "x",
            _sample_detection_record(),
            sample_rate=2.048e6,
        )
        slashes = save_sigmf_meta("///", meta, base_dir=tmp_path)
        dotted = save_sigmf_meta("a.b", meta, base_dir=tmp_path)
        plain = save_sigmf_meta("ab", meta, base_dir=tmp_path)
        assert len({slashes, dotted, plain}) == 3
        for path in (slashes, dotted, plain):
            assert path.parent == tmp_path.resolve()
        assert plain.name == "ab.sigmf-meta"


# ---------------------------------------------------------------------------
# Endpoint tests: GET /api/detections/{detection_id}/sigmf
# ---------------------------------------------------------------------------


@pytest.fixture()
def sigmf_det_id(
    bridge_app: FastAPI,
    seeded_store: IQStore,
    detection_store: Any,
) -> str:
    """Wire seeded IQ store into bridge app, insert a detection, return its ID."""
    bridge_app.state.iq_store = seeded_store

    det = make_detection(
        node_id="node-test-01",
        signal_class="bpsk",
        confidence=0.95,
        freq_hz=433.92e6,
    )
    detection_store.insert_batch([det])

    # Store IQ under the actual detection ID
    seeded_store.store(det.detection_id, _make_iq_data())
    return det.detection_id


class TestSigmfEndpoint:
    def test_sigmf_endpoint_200(self, client: TestClient, sigmf_det_id: str):
        """GET /sigmf returns 200 with valid SigMF structure."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        body = resp.json()
        assert "global" in body
        assert isinstance(body["global"], dict)
        assert "captures" in body
        assert isinstance(body["captures"], list)
        assert "annotations" in body
        assert isinstance(body["annotations"], list)

    def test_sigmf_endpoint_datatype(self, client: TestClient, sigmf_det_id: str):
        """Returned metadata has correct datatype."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        assert resp.json()["global"]["core:datatype"] == "cf32_le"

    def test_sigmf_endpoint_frequency(self, client: TestClient, sigmf_det_id: str):
        """Capture frequency matches detection freq_hz."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        assert resp.json()["captures"][0]["core:frequency"] == 433.92e6

    def test_sigmf_endpoint_label(self, client: TestClient, sigmf_det_id: str):
        """Annotation label matches detection signal_class."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        assert resp.json()["annotations"][0]["core:label"] == "bpsk"

    def test_sigmf_endpoint_sample_count(self, client: TestClient, sigmf_det_id: str):
        """Annotation includes sample_count derived from IQ data."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        # 4096 samples in _make_iq_data
        assert resp.json()["annotations"][0]["core:sample_count"] == 4096

    def test_sigmf_endpoint_custom_sample_rate(
        self, client: TestClient, sigmf_det_id: str
    ):
        """Custom sample_rate query param is reflected in metadata."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf?sample_rate=10000000")
        assert resp.status_code == 200
        assert resp.json()["global"]["core:sample_rate"] == 10e6

    def test_sigmf_endpoint_404_missing_iq(self, client: TestClient, sigmf_det_id: str):
        """Returns 404 for a detection with no IQ capture on disk."""
        resp = client.get("/api/detections/nonexistent-id/sigmf")
        assert resp.status_code == 404

    def test_sigmf_endpoint_version(self, client: TestClient, sigmf_det_id: str):
        """SigMF version in response is 1.0.0."""
        resp = client.get(f"/api/detections/{sigmf_det_id}/sigmf")
        assert resp.status_code == 200
        assert resp.json()["global"]["core:version"] == "1.0.0"
