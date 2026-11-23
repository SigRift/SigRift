"""Tests for sigrift.bridge.anomaly.feature_extractor."""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pytest

from sigrift.bridge.anomaly.feature_extractor import (
    FEATURE_DIM,
    FeatureExtractor,
)


@pytest.fixture
def extractor() -> FeatureExtractor:
    return FeatureExtractor()


# ---------------------------------------------------------------------------
# Basic extraction
# ---------------------------------------------------------------------------


class TestBasicExtraction:
    def test_output_length(self, extractor):
        features = extractor.extract({"freq_hz": 433_920_000})
        assert len(features) == FEATURE_DIM
        assert len(features) == 32

    def test_all_values_bounded(self, extractor):
        detection = {
            "freq_hz": 2_437_000_000,
            "power_dbm": -50.0,
            "snr_db": 20.0,
            "confidence": 0.9,
            "bandwidth_hz": 200_000,
            "signal_class": "fm",
            "timestamp": "2026-02-10T14:30:00+00:00",
        }
        features = extractor.extract(detection)
        for i, f in enumerate(features):
            assert 0.0 <= f <= 1.0, f"Feature {i} out of bounds: {f}"

    def test_empty_detection(self, extractor):
        features = extractor.extract({})
        assert len(features) == 32
        # Most features should be 0.0 or 0.5 (neutral)
        assert features[4] == 0.5  # power neutral
        assert features[5] == 0.5  # snr neutral


# ---------------------------------------------------------------------------
# Frequency features (0-3)
# ---------------------------------------------------------------------------


class TestFrequencyFeatures:
    def test_freq_log_normalized(self, extractor):
        features = extractor.extract({"freq_hz": 433_920_000})
        assert 0.0 < features[0] < 1.0

    def test_higher_freq_higher_value(self, extractor):
        f_low = extractor.extract({"freq_hz": 100_000_000})
        f_high = extractor.extract({"freq_hz": 2_400_000_000})
        assert f_high[0] > f_low[0]

    def test_zero_freq_yields_zero(self, extractor):
        features = extractor.extract({"freq_hz": 0})
        assert features[0] == 0.0
        assert features[1] == 0.0


# ---------------------------------------------------------------------------
# Power/SNR/confidence features (4-7)
# ---------------------------------------------------------------------------


class TestSignalFeatures:
    def test_power_normalized(self, extractor):
        features = extractor.extract({"freq_hz": 100e6, "power_dbm": -60.0})
        assert 0.0 < features[4] < 1.0

    def test_snr_normalized(self, extractor):
        features = extractor.extract({"freq_hz": 100e6, "snr_db": 20.0})
        assert features[5] == pytest.approx(0.5, abs=0.01)

    def test_confidence_passthrough(self, extractor):
        features = extractor.extract({"freq_hz": 100e6, "confidence": 0.85})
        assert features[6] == pytest.approx(0.85)

    def test_bandwidth_log_normalized(self, extractor):
        features = extractor.extract(
            {"freq_hz": 100e6, "bandwidth_hz": 200_000},
        )
        assert 0.0 < features[7] < 1.0


# ---------------------------------------------------------------------------
# Signal class one-hot (8-15)
# ---------------------------------------------------------------------------


class TestClassOneHot:
    def test_fm_sets_index_0(self, extractor):
        features = extractor.extract({"signal_class": "fm"})
        assert features[8] == 1.0
        for i in range(9, 16):
            assert features[i] == 0.0

    def test_qpsk_sets_index_3(self, extractor):
        features = extractor.extract({"signal_class": "qpsk"})
        assert features[11] == 1.0
        assert features[8] == 0.0

    def test_unknown_class_all_zeros(self, extractor):
        features = extractor.extract({"signal_class": "unknown_signal"})
        for i in range(8, 16):
            assert features[i] == 0.0

    def test_case_insensitive(self, extractor):
        features = extractor.extract({"signal_class": "FM"})
        assert features[8] == 1.0


# ---------------------------------------------------------------------------
# Time features (16-19)
# ---------------------------------------------------------------------------


class TestTimeFeatures:
    def test_time_features_bounded(self, extractor):
        features = extractor.extract(
            {"timestamp": "2026-02-10T14:30:00+00:00"},
        )
        for i in range(16, 20):
            assert 0.0 <= features[i] <= 1.0

    def test_time_features_vary_with_hour(self, extractor):
        f_morning = extractor.extract(
            {"timestamp": "2026-02-10T06:00:00+00:00"},
        )
        f_evening = extractor.extract(
            {"timestamp": "2026-02-10T18:00:00+00:00"},
        )
        # Hour sin/cos should differ between 6 AM and 6 PM
        assert f_morning[16] != pytest.approx(f_evening[16], abs=0.01)


# ---------------------------------------------------------------------------
# IQ features (20-23)
# ---------------------------------------------------------------------------


class TestIQFeatures:
    def test_iq_features_from_dict(self, extractor):
        detection = {
            "freq_hz": 100e6,
            "iq_data": {
                "spectral_flatness": 0.3,
                "dc_offset": 0.05,
                "iq_imbalance": 0.1,
                "cfo_hz": 500,
            },
        }
        features = extractor.extract(detection)
        assert features[20] == pytest.approx(0.3)
        assert features[21] == pytest.approx(0.05)
        assert features[22] == pytest.approx(0.2)  # 0.1/0.5
        assert features[23] == pytest.approx(0.1)  # 500/5000

    def test_no_iq_data_zeros(self, extractor):
        features = extractor.extract({"freq_hz": 100e6})
        for i in range(20, 24):
            assert features[i] == 0.0

    def test_iq_features_clamped(self, extractor):
        detection = {
            "iq_data": {
                "spectral_flatness": 2.0,  # above 1.0
                "cfo_hz": 10000,           # above 5000
            },
        }
        features = extractor.extract(detection)
        assert features[20] == 1.0
        assert features[23] == 1.0


# ---------------------------------------------------------------------------
# Reserved features (24-31)
# ---------------------------------------------------------------------------


class TestReservedFeatures:
    def test_reserved_are_zeros(self, extractor):
        features = extractor.extract({
            "freq_hz": 2_437_000_000,
            "power_dbm": -50.0,
            "signal_class": "ofdm",
        })
        for i in range(24, 32):
            assert features[i] == 0.0


# ---------------------------------------------------------------------------
# Batch extraction
# ---------------------------------------------------------------------------


class TestBatchExtraction:
    def test_batch_returns_correct_count(self, extractor):
        detections = [{"freq_hz": 100e6} for _ in range(5)]
        batch = extractor.extract_batch(detections)
        assert len(batch) == 5
        assert all(len(f) == 32 for f in batch)

    def test_batch_empty(self, extractor):
        assert extractor.extract_batch([]) == []

    def test_batch_consistency(self, extractor):
        detection = {"freq_hz": 433_920_000, "signal_class": "bpsk"}
        single = extractor.extract(detection)
        batch = extractor.extract_batch([detection])
        assert batch[0] == single
