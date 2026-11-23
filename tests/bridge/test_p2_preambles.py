"""Tests for Phase 2 Item 3: Preamble/Sync Word Detection + Pattern Database.

Covers:
  - DSP: Barker code generation, bit-to-symbol mapping, normalized xcorr,
    preamble detection in IQ, false-positive rejection, threshold filtering
  - Storage: PreambleStore CRUD, detection storage, stats
  - API: /api/preambles endpoints with RBAC
"""

from __future__ import annotations

import uuid
from pathlib import Path

import numpy as np
import pytest

from sigrift.lib.dsp.preamble_detector import (
    PreambleDetector,
    SyncPattern,
    _bits_to_symbols,
    _generate_barker,
    _normalized_xcorr,
)
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.preambles import PreambleStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    return SharedContext(db_path=tmp_path / "test_preambles.db")


@pytest.fixture
def store(ctx: SharedContext) -> PreambleStore:
    return PreambleStore(ctx)


@pytest.fixture
def detector() -> PreambleDetector:
    return PreambleDetector()


# ===================================================================
# DSP TESTS
# ===================================================================


class TestBarkerCodes:
    """Tests for Barker code generation."""

    def test_barker_codes_valid(self) -> None:
        """Barker-7, Barker-11, Barker-13 return correct length sequences."""
        for length in (7, 11, 13):
            code = _generate_barker(length)
            assert len(code) == length
            assert all(b in (0, 1) for b in code)

    def test_barker_11_autocorrelation(self) -> None:
        """Barker-11 has a sharp autocorrelation peak (sidelobe <= 1/N)."""
        code = _generate_barker(11)
        # Map to +1/-1
        bipolar = np.array([2 * b - 1 for b in code], dtype=np.float64)
        # Full autocorrelation
        acorr = np.correlate(bipolar, bipolar, mode="full")
        peak = np.max(np.abs(acorr))
        # Sidelobes should be <= 1 for Barker-11
        sidelobes = np.abs(acorr)
        center = len(bipolar) - 1
        sidelobes[center] = 0  # remove main peak
        assert peak == 11  # main lobe = N
        assert np.max(sidelobes) <= 1

    def test_barker_invalid_length(self) -> None:
        """Invalid Barker lengths raise ValueError."""
        with pytest.raises(ValueError, match="No Barker code"):
            _generate_barker(6)

    def test_barker_all_lengths(self) -> None:
        """All valid Barker lengths produce correct codes."""
        for length in (2, 3, 4, 5, 7, 11, 13):
            code = _generate_barker(length)
            assert len(code) == length


class TestBitsToSymbols:
    """Tests for bit-to-symbol mapping."""

    def test_bits_to_symbols_bpsk(self) -> None:
        """BPSK: 0 -> -1, 1 -> +1."""
        symbols = _bits_to_symbols([0, 1, 0, 1], "bpsk")
        assert len(symbols) == 4
        np.testing.assert_allclose(symbols.real, [-1, 1, -1, 1])
        np.testing.assert_allclose(symbols.imag, [0, 0, 0, 0])

    def test_bits_to_symbols_qpsk(self) -> None:
        """QPSK: pairs of bits map to 4 constellation points."""
        symbols = _bits_to_symbols([0, 0, 0, 1, 1, 0, 1, 1], "qpsk")
        assert len(symbols) == 4
        # All symbols should have magnitude 1
        mags = np.abs(symbols)
        np.testing.assert_allclose(mags, 1.0, atol=1e-10)

    def test_bits_to_symbols_empty(self) -> None:
        """Empty bit list produces empty symbol array."""
        symbols = _bits_to_symbols([], "bpsk")
        assert len(symbols) == 0

    def test_bits_to_symbols_default_is_bpsk(self) -> None:
        """Unknown modulation defaults to BPSK mapping."""
        symbols = _bits_to_symbols([1, 0], "unknown_mod")
        assert len(symbols) == 2
        np.testing.assert_allclose(symbols.real, [1, -1])


class TestNormalizedXcorr:
    """Tests for normalized cross-correlation."""

    def test_normalized_xcorr_range(self) -> None:
        """Correlation values are in [0, 1] for magnitude output."""
        np.random.seed(42)
        sig = np.random.randn(200) + 1j * np.random.randn(200)
        tmpl = np.random.randn(20) + 1j * np.random.randn(20)
        corr = _normalized_xcorr(sig, tmpl)
        assert len(corr) == 200 - 20 + 1
        assert np.all(corr >= -0.01)  # allow tiny float rounding
        assert np.all(corr <= 1.01)

    def test_perfect_match(self) -> None:
        """When template is embedded in signal, peak correlation is ~1."""
        template = np.array([1, -1, 1, 1, -1]) + 0j
        # Embed template at offset 50 with some noise around it
        sig = np.random.randn(200) * 0.01 + 1j * np.random.randn(200) * 0.01
        sig[50:55] = template
        corr = _normalized_xcorr(sig, template)
        assert corr[50] > 0.95

    def test_template_longer_than_signal(self) -> None:
        """Returns empty array when template is longer than signal."""
        sig = np.array([1, 2, 3]) + 0j
        tmpl = np.array([1, 2, 3, 4, 5]) + 0j
        corr = _normalized_xcorr(sig, tmpl)
        assert len(corr) == 0


class TestPreambleDetector:
    """Tests for the PreambleDetector class."""

    def test_pattern_database_populated(self, detector: PreambleDetector) -> None:
        """Built-in patterns exist and contain expected protocols."""
        patterns = detector.patterns
        assert len(patterns) >= 10
        assert isinstance(patterns, list)
        protocols = {p.protocol for p in patterns}
        assert "wifi" in protocols
        assert "bluetooth" in protocols
        assert "zigbee" in protocols
        assert "lora" in protocols
        assert "adsb" in protocols

    def test_detect_known_preamble(self) -> None:
        """Inject Barker-11 into noise and detect it."""
        barker = _generate_barker(11)
        template = _bits_to_symbols(barker, "bpsk")

        # Create noisy signal with embedded preamble
        np.random.seed(42)
        sig = np.random.randn(500) * 0.05 + 1j * np.random.randn(500) * 0.05
        offset = 100
        sig[offset : offset + len(template)] = template

        pattern = SyncPattern(
            name="test-barker-11",
            bits=barker,
            protocol="test",
            modulation="bpsk",
        )
        det = PreambleDetector(patterns=[pattern])
        matches = det.detect(sig, threshold=0.7)
        assert len(matches) >= 1
        assert isinstance(matches, list)
        # The best match should be near offset 100
        best = matches[0]
        assert best.pattern_name == "test-barker-11"
        assert abs(best.sample_offset - offset) <= 2
        assert best.correlation_peak >= 0.7

    def test_detect_multiple_preambles(self) -> None:
        """Inject two different patterns, find both."""
        np.random.seed(123)
        sig = np.random.randn(1000) * 0.02 + 1j * np.random.randn(1000) * 0.02

        barker7 = _generate_barker(7)
        barker13 = _generate_barker(13)
        tmpl7 = _bits_to_symbols(barker7, "bpsk")
        tmpl13 = _bits_to_symbols(barker13, "bpsk")

        sig[100 : 100 + len(tmpl7)] = tmpl7
        sig[500 : 500 + len(tmpl13)] = tmpl13

        patterns = [
            SyncPattern(name="B7", bits=barker7, protocol="test", modulation="bpsk"),
            SyncPattern(name="B13", bits=barker13, protocol="test", modulation="bpsk"),
        ]
        det = PreambleDetector(patterns=patterns)
        matches = det.detect(sig, threshold=0.7)
        names = {m.pattern_name for m in matches}
        assert "B7" in names
        assert "B13" in names

    def test_no_false_positive_noise(self) -> None:
        """Pure noise returns no detections at high threshold."""
        np.random.seed(99)
        sig = np.random.randn(2000) * 0.5 + 1j * np.random.randn(2000) * 0.5
        det = PreambleDetector()
        matches = det.detect(sig, threshold=0.95)
        assert len(matches) == 0

    def test_threshold_filters(self) -> None:
        """Higher threshold produces fewer or equal matches."""
        barker = _generate_barker(11)
        template = _bits_to_symbols(barker, "bpsk")

        np.random.seed(42)
        sig = np.random.randn(500) * 0.1 + 1j * np.random.randn(500) * 0.1
        sig[100 : 100 + len(template)] = template

        pattern = SyncPattern(
            name="B11", bits=barker, protocol="test", modulation="bpsk",
        )
        det = PreambleDetector(patterns=[pattern])
        low = det.detect(sig, threshold=0.5)
        high = det.detect(sig, threshold=0.9)
        assert len(high) <= len(low)

    def test_bluetooth_access_code(self) -> None:
        """Detect Bluetooth advertising access code embedded in IQ."""
        bt_sync = 0x8E89BED6
        bt_bits = [(bt_sync >> (31 - i)) & 1 for i in range(32)]
        template = _bits_to_symbols(bt_bits, "bpsk")

        np.random.seed(7)
        sig = np.random.randn(500) * 0.02 + 1j * np.random.randn(500) * 0.02
        sig[200 : 200 + len(template)] = template

        pattern = SyncPattern(
            name="BT-adv", bits=bt_bits, protocol="bluetooth", modulation="bpsk",
        )
        det = PreambleDetector(patterns=[pattern])
        matches = det.detect(sig, threshold=0.7)
        assert len(matches) >= 1
        assert isinstance(matches, list)
        assert matches[0].protocol == "bluetooth"

    def test_custom_pattern(self) -> None:
        """Add a custom pattern and detect it."""
        custom_bits = [1, 0, 1, 0, 1, 1, 0, 0]
        template = _bits_to_symbols(custom_bits, "bpsk")

        np.random.seed(55)
        sig = np.random.randn(300) * 0.02 + 1j * np.random.randn(300) * 0.02
        sig[50 : 50 + len(template)] = template

        det = PreambleDetector(patterns=[])
        det.add_pattern(SyncPattern(
            name="custom-8bit",
            bits=custom_bits,
            protocol="custom",
            modulation="bpsk",
        ))
        matches = det.detect(sig, threshold=0.7)
        assert len(matches) >= 1
        assert isinstance(matches, list)
        assert matches[0].pattern_name == "custom-8bit"

    def test_detect_empty_iq(self) -> None:
        """Empty IQ array returns no matches."""
        det = PreambleDetector()
        matches = det.detect(np.array([], dtype=np.complex128), threshold=0.5)
        assert matches == []

    def test_detect_pattern_short_iq(self) -> None:
        """IQ shorter than pattern returns empty."""
        pattern = SyncPattern(
            name="long-pat", bits=[1] * 100, protocol="test", modulation="bpsk",
        )
        det = PreambleDetector(patterns=[pattern])
        sig = np.ones(10, dtype=np.complex128)
        matches = det.detect(sig, threshold=0.5)
        assert matches == []


# ===================================================================
# STORAGE TESTS
# ===================================================================


class TestPreambleStore:
    """Tests for PreambleStore CRUD."""

    def test_add_pattern(self, store: PreambleStore) -> None:
        pid = str(uuid.uuid4())
        store.add_pattern(
            pattern_id=pid,
            name="test-pattern",
            bits=[1, 0, 1, 1],
            protocol="custom",
            modulation="bpsk",
            description="A test pattern",
        )
        pat = store.get_pattern(pid)
        assert isinstance(pat, dict)
        assert pat["name"] == "test-pattern"
        assert pat["protocol"] == "custom"
        # bits round-trip through hex encoding
        assert pat["bits"][:4] == [1, 0, 1, 1]

    def test_list_patterns(self, store: PreambleStore) -> None:
        for i in range(3):
            store.add_pattern(
                pattern_id=str(uuid.uuid4()),
                name=f"pat-{i}",
                bits=[1, 0],
                protocol="test",
            )
        patterns = store.list_patterns()
        assert len(patterns) == 3
        assert all(isinstance(p, dict) for p in patterns)

    def test_delete_pattern(self, store: PreambleStore) -> None:
        pid = str(uuid.uuid4())
        store.add_pattern(pid, "del-me", [1, 0], "test")
        assert store.delete_pattern(pid) is True
        assert store.get_pattern(pid) is None
        assert store.delete_pattern(pid) is False

    def test_store_detection(self, store: PreambleStore) -> None:
        det_id = str(uuid.uuid4())
        store.store_detection(
            det_id=det_id,
            detection_id="det-001",
            pattern_name="Barker-11",
            protocol="wifi",
            sample_offset=100,
            correlation_peak=0.95,
            confidence=0.95,
            estimated_symbol_rate=1e6,
        )
        results = store.get_detections_for("det-001")
        assert len(results) == 1
        assert isinstance(results[0], dict)
        assert results[0]["pattern_name"] == "Barker-11"
        assert results[0]["sample_offset"] == 100

    def test_get_detections_for(self, store: PreambleStore) -> None:
        for i in range(5):
            store.store_detection(
                det_id=str(uuid.uuid4()),
                detection_id="det-002",
                pattern_name=f"pat-{i}",
                protocol="test",
                sample_offset=i * 100,
                correlation_peak=0.8,
                confidence=0.8,
            )
        results = store.get_detections_for("det-002")
        assert len(results) == 5
        assert all(isinstance(r, dict) for r in results)

    def test_list_detections(self, store: PreambleStore) -> None:
        for i in range(3):
            store.store_detection(
                det_id=str(uuid.uuid4()),
                detection_id=f"det-{i}",
                pattern_name="test",
                protocol="test",
                sample_offset=0,
                correlation_peak=0.9,
                confidence=0.9,
            )
        detections = store.list_detections(limit=10)
        assert len(detections) == 3
        assert all(isinstance(d, dict) for d in detections)

    def test_stats(self, store: PreambleStore) -> None:
        store.add_pattern(str(uuid.uuid4()), "sp1", [1, 0], "wifi")
        store.store_detection(
            str(uuid.uuid4()), "d1", "pat-a", "wifi", 0, 0.9, 0.9,
        )
        store.store_detection(
            str(uuid.uuid4()), "d2", "pat-b", "bluetooth", 0, 0.8, 0.8,
        )
        stats = store.get_stats()
        assert stats["custom_patterns"] == 1
        assert stats["total_detections"] == 2
        assert "wifi" in stats["by_protocol"]
        assert isinstance(stats["by_protocol"]["wifi"], int)
        assert "bluetooth" in stats["by_protocol"]
        assert isinstance(stats["by_protocol"]["bluetooth"], int)

    def test_hex_roundtrip(self, store: PreambleStore) -> None:
        """Bits survive hex encoding/decoding round-trip."""
        bits = [1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0]
        hex_str = store._bits_to_hex(bits)
        recovered = store._hex_to_bits(hex_str)
        # Recovered may be padded to multiple of 4
        assert recovered[: len(bits)] == bits


# ===================================================================
# API TESTS
# ===================================================================


class TestPreambleAPI:
    """Tests for /api/preambles endpoints."""

    def test_list_patterns(self, client) -> None:
        resp = client.get("/api/preambles/patterns")
        assert resp.status_code == 200
        data = resp.json()
        assert "builtin" in data
        assert isinstance(data["builtin"], list)
        assert len(data["builtin"]) >= 10
        assert all(isinstance(p, dict) for p in data["builtin"])

    def test_add_pattern_requires_analyst(self, bridge_app, master_key) -> None:
        """Viewer-level key cannot add patterns (requires ANALYST)."""
        from sigrift.lib.security.credentials import hash_credential
        from fastapi.testclient import TestClient

        # Create a viewer-level key
        viewer_key = "viewer-key-test-preambles"
        h, s = hash_credential(viewer_key)
        bridge_app.state.persistence.set_key("viewer-test", h, s)
        bridge_app.state.persistence.set_key_meta("viewer-test", {"role": "viewer"})

        viewer_client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})
        resp = viewer_client.post("/api/preambles/patterns", json={
            "name": "test-viewer",
            "bits": [1, 0],
            "protocol": "test",
        })
        assert resp.status_code == 403

    def test_add_custom_pattern(self, client) -> None:
        resp = client.post("/api/preambles/patterns", json={
            "name": "my-custom-sync",
            "bits": [1, 0, 1, 1, 0, 0],
            "protocol": "custom",
            "modulation": "bpsk",
            "description": "Test custom pattern",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "my-custom-sync"
        assert data["protocol"] == "custom"

    def test_delete_pattern(self, client) -> None:
        # Create then delete
        resp = client.post("/api/preambles/patterns", json={
            "name": "to-delete",
            "bits": [1, 0],
            "protocol": "test",
        })
        assert resp.status_code == 201
        pid = resp.json()["id"]

        resp = client.delete(f"/api/preambles/patterns/{pid}")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_delete_nonexistent(self, client) -> None:
        resp = client.delete("/api/preambles/patterns/nonexistent-id")
        assert resp.status_code == 404

    def test_detect_requires_analyst(self, bridge_app, master_key) -> None:
        """Viewer cannot call /detect."""
        from sigrift.lib.security.credentials import hash_credential
        from fastapi.testclient import TestClient

        viewer_key = "viewer-key-detect-test"
        h, s = hash_credential(viewer_key)
        bridge_app.state.persistence.set_key("viewer-det", h, s)
        bridge_app.state.persistence.set_key_meta("viewer-det", {"role": "viewer"})
        viewer_client = TestClient(bridge_app, headers={"X-API-Key": viewer_key})

        resp = viewer_client.post("/api/preambles/detect/raw", json={
            "iq_real": [1.0, 0.0],
            "iq_imag": [0.0, 1.0],
            "sample_rate": 1.0,
        })
        assert resp.status_code == 403

    def test_detect_raw_returns_matches(self, client) -> None:
        """POST /detect/raw with embedded Barker-11 returns matches."""
        barker = _generate_barker(11)
        template = _bits_to_symbols(barker, "bpsk")

        np.random.seed(42)
        sig = np.random.randn(500) * 0.02 + 1j * np.random.randn(500) * 0.02
        sig[100 : 100 + len(template)] = template

        resp = client.post("/api/preambles/detect/raw", json={
            "iq_real": sig.real.tolist(),
            "iq_imag": sig.imag.tolist(),
            "sample_rate": 1e6,
            "threshold": 0.7,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert data["count"] >= 1
        assert isinstance(data["matches"], list)
        # Should find the Barker-11 pattern (built-in)
        names = [m["pattern_name"] for m in data["matches"]]
        assert any("Barker" in n and "11" in n for n in names)

    def test_detections_list(self, client) -> None:
        resp = client.get("/api/preambles/detections")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_detections_for_id(self, client) -> None:
        resp = client.get("/api/preambles/detections/nonexistent-det")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_stats(self, client) -> None:
        resp = client.get("/api/preambles/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "custom_patterns" in data
        assert isinstance(data["custom_patterns"], int)
        assert "total_detections" in data
        assert isinstance(data["total_detections"], int)
        assert "by_protocol" in data
        assert isinstance(data["by_protocol"], dict)
