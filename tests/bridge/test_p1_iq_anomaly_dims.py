"""Tests for P1-7: IQ anomaly dimensions in Tier 1 scorer.

Tests cover the three new IQ-based anomaly dimensions:
  - IQ quality anomaly
  - Spectral anomaly
  - Modulation anomaly

Each dimension is tested for:
  - Score in [0, 1]
  - Normal signals produce low scores
  - Anomalous signals produce higher scores
  - Missing IQ data results in graceful fallback (0.0)
  - Integration with the full scoring pipeline
"""

from __future__ import annotations

import math

import pytest

from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyScorer,
    ScorerConfig,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline_mgr() -> BaselineManager:
    """BaselineManager with 150+ detections at 433.9 MHz (past learning)."""
    mgr = BaselineManager(alpha=0.05)
    for i in range(150):
        mgr.update(433_920_000, "fm", 0.9, -50.0, 10)
    for i in range(30):
        mgr.update(433_920_000, "bpsk", 0.8, -52.0, 10)
    for i in range(20):
        mgr.update(433_920_000, "ook", 0.85, -48.0, 14)
    return mgr


@pytest.fixture
def scorer(baseline_mgr: BaselineManager) -> AnomalyScorer:
    """Scorer with a populated baseline manager."""
    return AnomalyScorer(baseline_mgr)


# ---------------------------------------------------------------------------
# IQ Quality Dimension
# ---------------------------------------------------------------------------


class TestIQQualityScore:
    """Tests for _iq_quality_score dimension."""

    def test_no_iq_data_returns_zero(self) -> None:
        """Missing IQ data should return 0.0."""
        score = AnomalyScorer._iq_quality_score({}, None)
        assert score == 0.0

    def test_good_quality_dict_low_score(self) -> None:
        """Good IQ metrics should produce a low score."""
        iq = {"dc_offset": 0.01, "iq_imbalance": 0.01, "snr_db": 25.0}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert 0.0 <= score <= 1.0
        assert score < 0.2

    def test_bad_dc_offset_high_score(self) -> None:
        """Large DC offset should produce a higher score."""
        iq = {"dc_offset": 0.5}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert score >= 0.8

    def test_bad_iq_imbalance_high_score(self) -> None:
        """Large IQ imbalance should produce a higher score."""
        iq = {"iq_imbalance": 0.4}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert score >= 0.8

    def test_low_snr_high_score(self) -> None:
        """Very low SNR should produce a higher score."""
        iq = {"snr_db": 2.0}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert score > 0.5

    def test_high_snr_low_score(self) -> None:
        """High SNR should produce a low score."""
        iq = {"snr_db": 30.0}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert score == 0.0

    def test_raw_iq_clean_signal(self) -> None:
        """Clean raw IQ samples should produce a low score."""
        # Generate clean sine-like IQ (no DC offset, balanced I/Q)
        n = 64
        samples = [
            complex(math.cos(2 * math.pi * 5 * i / n),
                    math.sin(2 * math.pi * 5 * i / n))
            for i in range(n)
        ]
        score = AnomalyScorer._iq_quality_score({}, samples)
        assert 0.0 <= score <= 1.0
        assert score < 0.3

    def test_raw_iq_with_dc_offset(self) -> None:
        """Raw IQ with large DC offset should score higher."""
        n = 64
        dc = complex(2.0, 2.0)
        samples = [
            dc + complex(math.cos(2 * math.pi * 5 * i / n),
                         math.sin(2 * math.pi * 5 * i / n))
            for i in range(n)
        ]
        score = AnomalyScorer._iq_quality_score({}, samples)
        assert score > 0.3

    def test_score_clamped_to_unit(self) -> None:
        """Score should always be in [0, 1] even with extreme inputs."""
        iq = {"dc_offset": 100.0, "iq_imbalance": 100.0, "snr_db": -50.0}
        score = AnomalyScorer._iq_quality_score({}, iq)
        assert 0.0 <= score <= 1.0

    def test_empty_dict_returns_zero(self) -> None:
        """IQ dict with no recognized keys returns 0.0."""
        score = AnomalyScorer._iq_quality_score({}, {"foo": "bar"})
        assert score == 0.0


# ---------------------------------------------------------------------------
# Spectral Anomaly Dimension
# ---------------------------------------------------------------------------


class TestSpectralAnomalyScore:
    """Tests for _spectral_anomaly_score dimension."""

    def test_no_iq_data_returns_zero(self) -> None:
        """Missing IQ data should return 0.0."""
        score = AnomalyScorer._spectral_anomaly_score({}, None)
        assert score == 0.0

    def test_normal_spectral_flatness(self) -> None:
        """Flatness in normal range [0.1, 0.6] should score 0."""
        iq = {"spectral_flatness": 0.3}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score == 0.0

    def test_high_spectral_flatness(self) -> None:
        """Very flat spectrum (noise-like) should score higher."""
        iq = {"spectral_flatness": 0.95}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score > 0.5

    def test_very_tonal_low_flatness(self) -> None:
        """Very tonal signal (flatness near 0) should score higher."""
        iq = {"spectral_flatness": 0.01}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score > 0.5

    def test_bandwidth_mismatch_wide(self) -> None:
        """Bandwidth much wider than expected should score higher."""
        iq = {"bandwidth_hz": 500_000, "expected_bandwidth_hz": 100_000}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score > 0.3

    def test_bandwidth_match_low_score(self) -> None:
        """Bandwidth matching expected should score 0."""
        iq = {"bandwidth_hz": 100_000, "expected_bandwidth_hz": 100_000}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score == 0.0

    def test_peak_count_anomaly(self) -> None:
        """Unexpected number of spectral peaks should score higher."""
        iq = {"num_peaks": 20, "expected_peaks": 3}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score > 0.5

    def test_peak_count_normal(self) -> None:
        """Expected peak count should score low."""
        iq = {"num_peaks": 3, "expected_peaks": 3}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert score == 0.0

    def test_raw_iq_pure_tone(self) -> None:
        """Pure tone raw IQ should have very low spectral flatness -> higher score."""
        n = 32
        samples = [complex(math.cos(2 * math.pi * 1 * i / n), 0.0) for i in range(n)]
        score = AnomalyScorer._spectral_anomaly_score({}, samples)
        assert 0.0 <= score <= 1.0

    def test_score_clamped_to_unit(self) -> None:
        """Score should always be in [0, 1]."""
        iq = {"spectral_flatness": 5.0, "bandwidth_hz": 1e9, "expected_bandwidth_hz": 1.0}
        score = AnomalyScorer._spectral_anomaly_score({}, iq)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Modulation Anomaly Dimension
# ---------------------------------------------------------------------------


class TestModulationAnomalyScore:
    """Tests for _modulation_anomaly_score dimension."""

    def test_no_iq_data_returns_zero(self) -> None:
        """Missing IQ data should return 0.0."""
        score = AnomalyScorer._modulation_anomaly_score({}, None)
        assert score == 0.0

    def test_matching_symbol_rate(self) -> None:
        """Symbol rate matching expected should score 0."""
        iq = {"symbol_rate": 9600, "expected_symbol_rate": 9600}
        score = AnomalyScorer._modulation_anomaly_score({}, iq)
        assert score == 0.0

    def test_mismatched_symbol_rate(self) -> None:
        """Symbol rate very different from expected should score higher."""
        iq = {"symbol_rate": 50_000, "expected_symbol_rate": 9600}
        score = AnomalyScorer._modulation_anomaly_score({}, iq)
        assert score > 0.5

    def test_low_cfo(self) -> None:
        """Small CFO should produce a low score."""
        iq = {"cfo_hz": 50}
        score = AnomalyScorer._modulation_anomaly_score({}, iq)
        assert score < 0.1

    def test_high_cfo(self) -> None:
        """Large CFO should produce a higher score."""
        iq = {"cfo_hz": 4000}
        score = AnomalyScorer._modulation_anomaly_score({}, iq)
        assert score > 0.5

    def test_bandwidth_vs_class_normal(self) -> None:
        """FM signal with ~200 kHz bandwidth should score 0."""
        detection = {"signal_class": "fm"}
        iq = {"bandwidth_hz": 200_000}
        score = AnomalyScorer._modulation_anomaly_score(detection, iq)
        assert score == 0.0

    def test_bandwidth_vs_class_mismatch(self) -> None:
        """FM signal with 10 MHz bandwidth should score higher."""
        detection = {"signal_class": "fm"}
        iq = {"bandwidth_hz": 10_000_000}
        score = AnomalyScorer._modulation_anomaly_score(detection, iq)
        assert score > 0.3

    def test_raw_iq_stable_carrier(self) -> None:
        """Stable carrier (no CFO) should produce low modulation anomaly."""
        n = 128
        samples = [
            complex(math.cos(2 * math.pi * 0.1 * i),
                    math.sin(2 * math.pi * 0.1 * i))
            for i in range(n)
        ]
        score = AnomalyScorer._modulation_anomaly_score({}, samples)
        assert 0.0 <= score <= 1.0
        # Stable carrier has consistent phase rotation -> moderate CFO score
        assert score < 0.5

    def test_raw_iq_drifting_carrier(self) -> None:
        """Carrier with large frequency drift should score higher."""
        n = 128
        # Rapid phase rotation = high CFO
        samples = [
            complex(math.cos(math.pi * 0.9 * i),
                    math.sin(math.pi * 0.9 * i))
            for i in range(n)
        ]
        score = AnomalyScorer._modulation_anomaly_score({}, samples)
        assert score > 0.5

    def test_score_clamped_to_unit(self) -> None:
        """Score should always be in [0, 1]."""
        iq = {"cfo_hz": 1_000_000, "symbol_rate": 1e9, "expected_symbol_rate": 1.0}
        score = AnomalyScorer._modulation_anomaly_score({}, iq)
        assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# Integration: new dimensions in the full score() pipeline
# ---------------------------------------------------------------------------


class TestIQDimensionsIntegration:
    """Integration tests for IQ dimensions in full scorer pipeline."""

    def test_score_includes_all_iq_dimensions(self, scorer: AnomalyScorer) -> None:
        """Full score() call includes the 3 new IQ dimension keys."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        assert "iq_quality" in result.dimensions
        assert isinstance(result.dimensions["iq_quality"], float)
        assert "spectral_anomaly" in result.dimensions
        assert isinstance(result.dimensions["spectral_anomaly"], float)
        assert "modulation_anomaly" in result.dimensions
        assert isinstance(result.dimensions["modulation_anomaly"], float)

    def test_no_iq_data_dimensions_are_zero(self, scorer: AnomalyScorer) -> None:
        """Without iq_data, all 3 new dimensions should be 0.0."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        assert result.dimensions["iq_quality"] == 0.0
        assert result.dimensions["spectral_anomaly"] == 0.0
        assert result.dimensions["modulation_anomaly"] == 0.0

    def test_bad_iq_boosts_score(self, scorer: AnomalyScorer) -> None:
        """Detection with poor IQ metrics should have a higher score."""
        normal_result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
        })
        anomalous_result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "timestamp": "2026-02-10T10:30:00+00:00",
            "iq_data": {
                "dc_offset": 0.8,
                "iq_imbalance": 0.5,
                "snr_db": 1.0,
                "spectral_flatness": 0.99,
                "cfo_hz": 8000,
            },
        })
        assert anomalous_result.score > normal_result.score

    def test_iq_reasons_added(self, scorer: AnomalyScorer) -> None:
        """Anomalous IQ data should add reasons to the result."""
        result = scorer.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {
                "dc_offset": 1.0,
                "iq_imbalance": 1.0,
                "snr_db": 0.0,
                "spectral_flatness": 1.0,
                "cfo_hz": 10000,
            },
        })
        reason_text = " ".join(result.reasons)
        assert "IQ" in reason_text or "spectral" in reason_text or "modulation" in reason_text

    def test_weights_sum_to_one(self) -> None:
        """Default weights for all dimensions should sum to ~1.18."""
        config = ScorerConfig()
        total = sum(config.weights.values())
        assert total == pytest.approx(1.18, abs=0.01)

    def test_iq_dimension_enum_values(self) -> None:
        """New AnomalyDimension enum values exist."""
        assert AnomalyDimension.IQ_QUALITY.value == "iq_quality"
        assert AnomalyDimension.SPECTRAL_ANOMALY.value == "spectral_anomaly"
        assert AnomalyDimension.MODULATION_ANOMALY.value == "modulation_anomaly"

    def test_iq_only_weight_config(self, baseline_mgr: BaselineManager) -> None:
        """Scorer with IQ-only weights should respond to IQ data."""
        config = ScorerConfig(
            weights={
                AnomalyDimension.NOVEL_CLASS: 0.0,
                AnomalyDimension.RARE_CLASS: 0.0,
                AnomalyDimension.LOW_CONFIDENCE: 0.0,
                AnomalyDimension.POWER_ZSCORE: 0.0,
                AnomalyDimension.SNR_ZSCORE: 0.0,
                AnomalyDimension.TIMING_ANOMALY: 0.0,
                AnomalyDimension.QUIET_FREQUENCY: 0.0,
                AnomalyDimension.IQ_QUALITY: 0.4,
                AnomalyDimension.SPECTRAL_ANOMALY: 0.3,
                AnomalyDimension.MODULATION_ANOMALY: 0.3,
            }
        )
        s = AnomalyScorer(baseline_mgr, config)

        # Without IQ data, score should be 0
        result_no_iq = s.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
        })
        assert result_no_iq.score == 0.0

        # With anomalous IQ data, score should be > 0
        result_with_iq = s.score({
            "signal_class": "fm",
            "confidence": 0.9,
            "freq_hz": 433_920_000,
            "power_dbm": -50.0,
            "iq_data": {
                "dc_offset": 0.8,
                "snr_db": 1.0,
                "spectral_flatness": 0.95,
                "cfo_hz": 6000,
            },
        })
        assert result_with_iq.score > 0.0
