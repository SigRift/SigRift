"""Tests for the demo data generator (P3-18).

Covers normal detection generation, all anomaly injection types,
multi-node distribution, frequency band coverage, and output schema.
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

from datetime import datetime

import pytest

from sigrift.bridge.demo_generator import (
    ANOMALY_TYPES,
    DEFAULT_NODES,
    ISM_BANDS,
    SIGNAL_CLASSES,
    DemoGenerator,
)


# ---------------------------------------------------------------------------
# Required fields for ingest-API compatibility
# ---------------------------------------------------------------------------

_REQUIRED_KEYS = {
    "detection_id",
    "node_id",
    "signal_class",
    "confidence",
    "freq_hz",
    "timestamp",
    "power_dbm",
    "snr_db",
    "bandwidth_hz",
    "family",
}


# ---------------------------------------------------------------------------
# Basic generation tests
# ---------------------------------------------------------------------------


class TestDemoGeneratorBasic:

    def test_generate_batch_default_size(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch()
        assert len(batch) == 10
        assert isinstance(batch, list)
        assert isinstance(batch[0], dict)

    def test_generate_batch_custom_size(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=25)
        assert len(batch) == 25

    def test_generate_batch_single(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=1)
        assert len(batch) == 1
        assert isinstance(batch[0], dict)

    def test_generate_batch_invalid_n(self):
        gen = DemoGenerator(seed=42)
        with pytest.raises(ValueError, match="n must be >= 1"):
            gen.generate_batch(n=0)

    def test_invalid_anomaly_rate(self):
        with pytest.raises(ValueError, match="anomaly_rate"):
            DemoGenerator(anomaly_rate=1.5)

    def test_invalid_anomaly_rate_negative(self):
        with pytest.raises(ValueError, match="anomaly_rate"):
            DemoGenerator(anomaly_rate=-0.1)


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


class TestSchemaValidation:

    def test_all_required_keys_present(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=20)
        for det in batch:
            missing = _REQUIRED_KEYS - set(det.keys())
            assert missing == set(), f"Missing keys: {missing}"

    def test_detection_id_is_string(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=5)
        for det in batch:
            assert isinstance(det["detection_id"], str)
            assert len(det["detection_id"]) == 16

    def test_confidence_range(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=50)
        for det in batch:
            assert 0.0 <= det["confidence"] <= 1.0

    def test_anomaly_score_present(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=10)
        for det in batch:
            assert "anomaly_score" in det
            assert isinstance(det["anomaly_score"], float)
            assert 0.0 <= det["anomaly_score"] <= 1.0

    def test_timestamp_is_iso_format(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=5)
        for det in batch:
            # Should parse without error
            datetime.fromisoformat(det["timestamp"])

    def test_signal_class_in_known_set(self):
        gen = DemoGenerator(seed=42)
        batch = gen.generate_batch(n=100)
        for det in batch:
            assert det["signal_class"] in SIGNAL_CLASSES


# ---------------------------------------------------------------------------
# Multi-node distribution
# ---------------------------------------------------------------------------


class TestMultiNodeDistribution:

    def test_default_nodes(self):
        gen = DemoGenerator(seed=42)
        assert gen.nodes == list(DEFAULT_NODES)

    def test_custom_nodes(self):
        custom = ["alpha", "beta"]
        gen = DemoGenerator(nodes=custom, seed=42)
        assert gen.nodes == custom

    def test_multiple_nodes_used(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=100)
        used_nodes = {det["node_id"] for det in batch}
        # With 100 detections and 3 nodes, all should appear
        assert len(used_nodes) >= 2
        for node in used_nodes:
            assert isinstance(node, str)
            assert node in DEFAULT_NODES

    def test_all_three_default_nodes_appear(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=200)
        used_nodes = {det["node_id"] for det in batch}
        assert used_nodes == set(DEFAULT_NODES)


# ---------------------------------------------------------------------------
# Frequency band coverage
# ---------------------------------------------------------------------------


class TestFrequencyBandCoverage:

    def test_multiple_bands_covered(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=200)
        freqs = [det["freq_hz"] for det in batch]
        assert all(isinstance(f, (int, float)) for f in freqs)
        # Check at least 3 distinct ISM bands are represented
        band_hits = set()
        for freq in freqs:
            for band_name, center in ISM_BANDS.items():
                # Within +/- 1 MHz of center counts as that band
                if abs(freq - center) < 1e6:
                    band_hits.add(band_name)
        assert len(band_hits) >= 3

    def test_freq_near_ism_center(self):
        gen = DemoGenerator(seed=42, anomaly_rate=0.0)
        batch = gen.generate_batch(n=50)
        for det in batch:
            freq = det["freq_hz"]
            # Each freq should be near an ISM band center
            near_band = any(
                abs(freq - center) < 1e6
                for center in ISM_BANDS.values()
            )
            assert near_band is True, f"freq {freq} not near any ISM band"


# ---------------------------------------------------------------------------
# Anomaly injection
# ---------------------------------------------------------------------------


class TestAnomalyInjection:

    def test_novel_class(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        result = gen.inject_anomaly(det, "novel_class")
        assert result["signal_class"] == "unknown"
        assert result["family"] == ""
        assert result["confidence"] <= 0.4
        assert result["anomaly_score"] >= 0.7

    def test_power_spike(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        original_power = det["power_dbm"]
        result = gen.inject_anomaly(det, "power_spike")
        assert result["power_dbm"] == pytest.approx(original_power + 20.0, abs=0.01)
        assert result["anomaly_score"] >= 0.6

    def test_evil_twin(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        result = gen.inject_anomaly(det, "evil_twin")
        assert result["signal_class"] == "wifi"
        assert result["family"] == "wifi"
        # Should be near 2.412 GHz
        assert 2.412e9 < result["freq_hz"] < 2.412e9 + 6e3
        assert result["anomaly_score"] >= 0.5

    def test_quiet_frequency(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        result = gen.inject_anomaly(det, "quiet_frequency")
        assert 400e6 <= result["freq_hz"] <= 410e6
        assert result["anomaly_score"] >= 0.5

    def test_unknown_anomaly_type_raises(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        with pytest.raises(ValueError, match="Unknown anomaly_type"):
            gen.inject_anomaly(det, "nonexistent")

    def test_inject_returns_same_dict(self):
        gen = DemoGenerator(seed=42)
        det = gen._generate_one()
        result = gen.inject_anomaly(det, "power_spike")
        assert result is det


# ---------------------------------------------------------------------------
# Anomaly rate
# ---------------------------------------------------------------------------


class TestAnomalyRate:

    def test_zero_anomaly_rate(self):
        gen = DemoGenerator(anomaly_rate=0.0, seed=42)
        batch = gen.generate_batch(n=100)
        anomalous = [d for d in batch if d["anomaly_score"] > 0.0]
        assert len(anomalous) == 0

    def test_full_anomaly_rate(self):
        gen = DemoGenerator(anomaly_rate=1.0, seed=42)
        batch = gen.generate_batch(n=50)
        anomalous = [d for d in batch if d["anomaly_score"] > 0.0]
        assert len(anomalous) == 50

    def test_partial_anomaly_rate(self):
        gen = DemoGenerator(anomaly_rate=0.5, seed=42)
        batch = gen.generate_batch(n=200)
        anomalous = [d for d in batch if d["anomaly_score"] > 0.0]
        # Expect roughly 50% +/- 15% margin
        ratio = len(anomalous) / 200
        assert 0.3 < ratio < 0.7


# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------


class TestReproducibility:

    def test_seeded_determinism(self):
        gen1 = DemoGenerator(seed=123, anomaly_rate=0.2)
        gen2 = DemoGenerator(seed=123, anomaly_rate=0.2)
        batch1 = gen1.generate_batch(n=20)
        batch2 = gen2.generate_batch(n=20)
        for d1, d2 in zip(batch1, batch2):
            assert d1["signal_class"] == d2["signal_class"]
            assert d1["freq_hz"] == d2["freq_hz"]
            assert d1["node_id"] == d2["node_id"]
            assert d1["anomaly_score"] == d2["anomaly_score"]
