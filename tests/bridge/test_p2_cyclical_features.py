"""Tests for P2-4: cyclical sin/cos feature encoding in Isolation Forest.

Validates that hour and day_of_week are encoded with sin/cos pairs
instead of linear normalization, ensuring cyclical adjacency
(e.g. hour 23 and hour 0 are close in feature space).
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pytest

from sigrift.bridge.anomaly.isolation_forest import (
    FEATURE_VERSION,
    NUM_IF_FEATURES,
    IsolationForestDetector,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _features_at_hour(hour: int) -> list[float]:
    """Extract features for a detection at a specific hour."""
    det = IsolationForestDetector()
    ts = datetime(2026, 3, 10, hour, 0, 0, tzinfo=timezone.utc)
    return det.extract_features({
        "signal_class": "bpsk",
        "confidence": 0.9,
        "freq_hz": 433e6,
        "power_dbm": -60.0,
        "timestamp": ts,
    })


def _features_at_dow(weekday: int) -> list[float]:
    """Extract features for a detection on a specific day of week.

    weekday 0 = Monday.  2026-03-09 is Monday, 2026-03-15 is Sunday.
    """
    det = IsolationForestDetector()
    # 2026-03-09 is a Monday (weekday=0)
    day = 9 + weekday
    ts = datetime(2026, 3, day, 12, 0, 0, tzinfo=timezone.utc)
    assert ts.weekday() == weekday, f"Expected weekday {weekday}, got {ts.weekday()}"
    return det.extract_features({
        "signal_class": "bpsk",
        "confidence": 0.9,
        "freq_hz": 433e6,
        "power_dbm": -60.0,
        "timestamp": ts,
    })


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCyclicalHourEncoding:
    """Verify sin/cos encoding for hour-of-day."""

    def test_hour_0_and_24_same_encoding(self) -> None:
        """Hour 0 and hour 24 produce identical sin/cos values.

        sin(0) == sin(2*pi) and cos(0) == cos(2*pi).
        """
        h0_sin = math.sin(2 * math.pi * 0 / 24.0)
        h24_sin = math.sin(2 * math.pi * 24 / 24.0)
        h0_cos = math.cos(2 * math.pi * 0 / 24.0)
        h24_cos = math.cos(2 * math.pi * 24 / 24.0)

        assert h0_sin == pytest.approx(h24_sin, abs=1e-10)
        assert h0_cos == pytest.approx(h24_cos, abs=1e-10)

        # Also verify via feature extraction: hour 0 features
        f0 = _features_at_hour(0)
        assert f0[5] == pytest.approx(0.0, abs=1e-10)  # sin(0) = 0
        assert f0[6] == pytest.approx(1.0, abs=1e-10)  # cos(0) = 1

    def test_hour_12_encoding(self) -> None:
        """Hour 12: sin(pi) ~ 0, cos(pi) ~ -1."""
        f = _features_at_hour(12)
        assert f[5] == pytest.approx(0.0, abs=1e-10)   # sin(pi)
        assert f[6] == pytest.approx(-1.0, abs=1e-10)  # cos(pi)

    def test_hour_6_encoding(self) -> None:
        """Hour 6: sin(pi/2) ~ 1, cos(pi/2) ~ 0."""
        f = _features_at_hour(6)
        assert f[5] == pytest.approx(1.0, abs=1e-10)   # sin(pi/2)
        assert f[6] == pytest.approx(0.0, abs=1e-10)   # cos(pi/2)

    def test_hour_23_close_to_hour_0(self) -> None:
        """Hour 23 and hour 0 should be close in Euclidean distance.

        With linear encoding (23/24 vs 0/24), distance = 0.958.
        With sin/cos, distance = 2*sin(pi/24) ~ 0.261.
        """
        f23 = _features_at_hour(23)
        f0 = _features_at_hour(0)
        dist = math.sqrt((f23[5] - f0[5]) ** 2 + (f23[6] - f0[6]) ** 2)
        # Should be small — approximately 2*sin(pi/24) ~ 0.261
        assert dist < 0.3


class TestCyclicalDowEncoding:
    """Verify sin/cos encoding for day-of-week."""

    def test_dow_monday_next_monday_same(self) -> None:
        """Day 0 and day 7 produce the same sin/cos encoding.

        sin(0) == sin(2*pi) and cos(0) == cos(2*pi).
        """
        d0_sin = math.sin(2 * math.pi * 0 / 7.0)
        d7_sin = math.sin(2 * math.pi * 7 / 7.0)
        d0_cos = math.cos(2 * math.pi * 0 / 7.0)
        d7_cos = math.cos(2 * math.pi * 7 / 7.0)

        assert d0_sin == pytest.approx(d7_sin, abs=1e-10)
        assert d0_cos == pytest.approx(d7_cos, abs=1e-10)

    def test_dow_monday_encoding(self) -> None:
        """Monday (day 0): sin(0) = 0, cos(0) = 1."""
        f = _features_at_dow(0)
        assert f[7] == pytest.approx(0.0, abs=1e-10)   # sin(0)
        assert f[8] == pytest.approx(1.0, abs=1e-10)   # cos(0)

    def test_dow_values_distinct(self) -> None:
        """Each day of the week produces a distinct (sin, cos) pair."""
        pairs = set()
        for dow in range(7):
            s = round(math.sin(2 * math.pi * dow / 7.0), 6)
            c = round(math.cos(2 * math.pi * dow / 7.0), 6)
            pairs.add((s, c))
        assert len(pairs) == 7


class TestFeatureVectorLength:
    """Verify the new feature vector length after adding sin/cos pairs."""

    def test_feature_vector_length(self) -> None:
        """Feature vector should be 13 dimensions (was 11 before P2-4)."""
        det = IsolationForestDetector()
        features = det.extract_features({
            "signal_class": "fm",
            "confidence": 0.7,
            "freq_hz": 88e6,
            "power_dbm": -80.0,
            "timestamp": datetime.now(timezone.utc),
        })
        assert len(features) == 13

    def test_num_if_features_constant(self) -> None:
        """NUM_IF_FEATURES constant matches actual output."""
        det = IsolationForestDetector()
        features = det.extract_features({
            "signal_class": "bpsk",
            "confidence": 0.9,
            "freq_hz": 433e6,
            "timestamp": datetime.now(timezone.utc),
        })
        assert len(features) == NUM_IF_FEATURES


class TestSinCosBounded:
    """Verify that sin/cos feature values are always in [-1, 1]."""

    def test_sin_cos_values_bounded(self) -> None:
        """All sin/cos features should be in [-1, 1] for every hour."""
        det = IsolationForestDetector()
        for hour in range(24):
            ts = datetime(2026, 3, 10, hour, 0, 0, tzinfo=timezone.utc)
            features = det.extract_features({
                "signal_class": "bpsk",
                "confidence": 0.9,
                "freq_hz": 433e6,
                "power_dbm": -60.0,
                "timestamp": ts,
            })
            # Features 5, 6 are hour sin/cos; 7, 8 are dow sin/cos
            for idx in (5, 6, 7, 8):
                assert -1.0 <= features[idx] <= 1.0, (
                    f"Feature {idx} = {features[idx]} out of [-1, 1] "
                    f"at hour {hour}"
                )

    def test_sin_cos_bounded_all_days(self) -> None:
        """All sin/cos features bounded for every day of the week."""
        for dow in range(7):
            day = 9 + dow  # 2026-03-09 is Monday
            ts = datetime(2026, 3, day, 15, 0, 0, tzinfo=timezone.utc)
            det = IsolationForestDetector()
            features = det.extract_features({
                "signal_class": "qpsk",
                "confidence": 0.85,
                "freq_hz": 915e6,
                "power_dbm": -50.0,
                "timestamp": ts,
            })
            for idx in (5, 6, 7, 8):
                assert -1.0 <= features[idx] <= 1.0, (
                    f"Feature {idx} = {features[idx]} out of [-1, 1] "
                    f"at dow {dow}"
                )


class TestFeatureVersion:
    """Verify FEATURE_VERSION constant."""

    def test_feature_version_constant(self) -> None:
        """FEATURE_VERSION should be 2 after P2-4 cyclical encoding."""
        assert FEATURE_VERSION == 2

    def test_feature_version_in_saved_model(self, tmp_path) -> None:
        """Saved model should contain the feature version."""
        try:
            import joblib
        except ImportError:
            pytest.skip("joblib not installed")

        from sigrift.bridge.anomaly.isolation_forest import HAS_SKLEARN
        if not HAS_SKLEARN:
            pytest.skip("scikit-learn not installed")

        det = IsolationForestDetector(min_training_samples=50, n_estimators=5)
        import numpy as np
        rng = np.random.RandomState(42)
        for _ in range(100):
            det.add_sample(rng.uniform(-1, 1, 13).tolist())
        det.train()

        model_path = str(tmp_path / "if_model.pkl")
        det.save(model_path)

        data = joblib.load(model_path)
        assert data["feature_version"] == FEATURE_VERSION

    def test_version_mismatch_warns_on_load(self, tmp_path) -> None:
        """Loading a model with wrong feature version logs a warning."""
        try:
            import joblib
        except ImportError:
            pytest.skip("joblib not installed")

        from sigrift.bridge.anomaly.isolation_forest import HAS_SKLEARN
        if not HAS_SKLEARN:
            pytest.skip("scikit-learn not installed")

        det = IsolationForestDetector(min_training_samples=50, n_estimators=5)
        import numpy as np
        rng = np.random.RandomState(42)
        for _ in range(100):
            det.add_sample(rng.uniform(-1, 1, 13).tolist())
        det.train()

        model_path = str(tmp_path / "if_model.pkl")
        det.save(model_path)

        # Tamper: change feature version in saved data
        data = joblib.load(model_path)
        data["feature_version"] = 1
        joblib.dump(data, model_path)
        # Rewrite checksum so load doesn't reject on checksum mismatch
        from sigrift.bridge.anomaly.isolation_forest import _write_checksum
        from pathlib import Path
        _write_checksum(Path(model_path))

        det2 = IsolationForestDetector()
        det2.load(model_path)
        assert det2.is_ready()
        assert det2._feature_version_stale is True
