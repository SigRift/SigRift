"""Tests for the /api/signals/* endpoints.

Covers:
  - GET  /api/signals/classes         (list 30 canonical signal classes)
  - GET  /api/signals/families        (list 9 families)
  - GET  /api/signals/super-families  (list 6 super-families)
  - GET  /api/signals/generate        (synthetic waveform generation)
  - GET  /api/signals/dsp-features    (DSP feature extraction)
  - POST /api/signals/compare         (multi-class side-by-side comparison)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from sigrift.bridge.class_map import CANONICAL_CLASSES


# ---------------------------------------------------------------------------
# Taxonomy browsing
# ---------------------------------------------------------------------------


class TestListClasses:
    """Tests for GET /api/signals/classes."""

    def test_list_classes_returns_57(self, client: TestClient) -> None:
        """GET /api/signals/classes returns 57 canonical items, each with name/family/super_family."""
        resp = client.get("/api/signals/classes")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 57
        for item in data:
            assert isinstance(item["name"], str)
            assert isinstance(item["family"], str)
            assert isinstance(item["super_family"], str)

    def test_class_names_match_canonical_taxonomy(self, client: TestClient) -> None:
        """All returned class names exist in the canonical 30-class taxonomy list."""
        resp = client.get("/api/signals/classes")
        assert resp.status_code == 200
        returned_names = {item["name"] for item in resp.json()}
        assert returned_names == set(CANONICAL_CLASSES)


class TestListFamilies:
    """Tests for GET /api/signals/families."""

    def test_list_families_returns_16(self, client: TestClient) -> None:
        """GET /api/signals/families returns 16 items (incl. NOISE), each with a classes list."""
        resp = client.get("/api/signals/families")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 16
        for item in data:
            assert isinstance(item["family"], str)
            assert isinstance(item["classes"], list)


class TestListSuperFamilies:
    """Tests for GET /api/signals/super-families."""

    def test_list_super_families_returns_9(self, client: TestClient) -> None:
        """GET /api/signals/super-families returns 9 items (incl. SPREAD_SPECTRUM, NOISE, PULSED, INTERFERENCE)."""
        resp = client.get("/api/signals/super-families")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 9
        for item in data:
            assert isinstance(item["super_family"], str)
            assert isinstance(item["families"], list)


# ---------------------------------------------------------------------------
# Waveform generation
# ---------------------------------------------------------------------------


class TestGenerateWaveform:
    """Tests for GET /api/signals/generate."""

    def test_generate_bpsk(self, client: TestClient) -> None:
        """Generating a BPSK waveform returns constellation, PSD, and DSP features."""
        resp = client.get("/api/signals/generate", params={"class": "bpsk"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["signal_class"] == "bpsk"
        assert isinstance(data["constellation_x"], list)
        assert isinstance(data["constellation_y"], list)
        assert isinstance(data["psd_db"], list)
        assert isinstance(data["dsp_features"], list)
        assert len(data["constellation_x"]) > 0
        assert len(data["constellation_y"]) > 0
        assert len(data["dsp_features"]) > 0

    def test_generate_qpsk(self, client: TestClient) -> None:
        """Generating a QPSK waveform returns valid response data."""
        resp = client.get("/api/signals/generate", params={"class": "qpsk"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["signal_class"] == "qpsk"
        assert isinstance(data["constellation_x"], list)
        assert isinstance(data["constellation_y"], list)
        assert isinstance(data["psd_db"], list)
        assert isinstance(data["dsp_features"], list)
        assert len(data["constellation_x"]) > 0

    def test_generate_invalid_class_400(self, client: TestClient) -> None:
        """An unknown signal class returns 400."""
        resp = client.get("/api/signals/generate", params={"class": "not_a_real_class"})
        assert resp.status_code == 400

    def test_generate_snr_bounds(self, client: TestClient) -> None:
        """SNR at both boundary values (-20 and 40) succeeds; 50 returns 422."""
        resp_low = client.get("/api/signals/generate", params={"class": "bpsk", "snr": -20})
        assert resp_low.status_code == 200

        resp_high = client.get("/api/signals/generate", params={"class": "bpsk", "snr": 40})
        assert resp_high.status_code == 200

        resp_over = client.get("/api/signals/generate", params={"class": "bpsk", "snr": 50})
        assert resp_over.status_code == 422

    def test_generate_sample_count_max(self, client: TestClient) -> None:
        """n=32768 succeeds; n=65536 exceeds the limit and returns 422."""
        resp_ok = client.get("/api/signals/generate", params={"class": "bpsk", "n": 32768})
        assert resp_ok.status_code == 200

        resp_over = client.get("/api/signals/generate", params={"class": "bpsk", "n": 65536})
        assert resp_over.status_code == 422

    def test_generate_psd_length(self, client: TestClient) -> None:
        """psd_db and psd_freq_hz arrays have the same length."""
        resp = client.get("/api/signals/generate", params={"class": "bpsk"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["psd_db"]) == len(data["psd_freq_hz"])
        assert len(data["psd_db"]) > 0


# ---------------------------------------------------------------------------
# DSP features
# ---------------------------------------------------------------------------


class TestDSPFeatures:
    """Tests for GET /api/signals/dsp-features."""

    def test_dsp_features_endpoint(self, client: TestClient) -> None:
        """GET /api/signals/dsp-features?class=bpsk returns features list."""
        resp = client.get("/api/signals/dsp-features", params={"class": "bpsk"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["signal_class"] == "bpsk"
        assert isinstance(data["features"], list)
        assert len(data["features"]) > 0
        assert data["feature_count"] == len(data["features"])


# ---------------------------------------------------------------------------
# Signal comparison
# ---------------------------------------------------------------------------


class TestCompareSignals:
    """Tests for POST /api/signals/compare."""

    def test_compare_two_classes(self, client: TestClient) -> None:
        """Comparing BPSK and QPSK returns 2 result entries."""
        resp = client.post(
            "/api/signals/compare",
            json=["bpsk", "qpsk"],
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        classes_returned = {item["signal_class"] for item in data}
        assert classes_returned == {"bpsk", "qpsk"}
        for item in data:
            assert isinstance(item["constellation_x"], list)
            assert isinstance(item["psd_db"], list)
            assert isinstance(item["dsp_features"], list)

    def test_compare_max_classes(self, client: TestClient) -> None:
        """Comparing 6 classes (the maximum) succeeds."""
        six_classes = ["bpsk", "qpsk", "8psk", "16qam", "2fsk", "fm"]
        resp = client.post("/api/signals/compare", json=six_classes)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 6

    def test_compare_exceeds_max_400(self, client: TestClient) -> None:
        """Comparing 7 classes exceeds the limit and returns 400."""
        seven_classes = ["bpsk", "qpsk", "8psk", "16qam", "2fsk", "fm", "ook"]
        resp = client.post("/api/signals/compare", json=seven_classes)
        assert resp.status_code == 400

    def test_compare_empty_400(self, client: TestClient) -> None:
        """An empty class list returns 400."""
        resp = client.post("/api/signals/compare", json=[])
        assert resp.status_code == 400
