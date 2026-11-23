"""Regression guard: scorer default weights must match persistence defaults.

The scorer.py _DEFAULT_WEIGHTS and persistence.py _DETECTION_CONFIG_DEFAULTS
rf_dimension_weights must stay in sync.  This test catches divergence before
deployment.
"""

from __future__ import annotations

import pytest

from sigrift.bridge.anomaly.scorer import _DEFAULT_WEIGHTS, AnomalyDimension
from sigrift.bridge.persistence import PersistenceManager


def _persistence_weights() -> dict[str, float]:
    """Extract canonical weights from persistence defaults (no disk I/O)."""
    return dict(PersistenceManager._DETECTION_CONFIG_DEFAULTS["rf_dimension_weights"])


class TestWeightParity:
    """Ensure scorer defaults match persistence defaults."""

    def test_all_dimensions_present(self) -> None:
        """Every AnomalyDimension has a weight in both sources."""
        scorer_keys = {d.value for d in _DEFAULT_WEIGHTS}
        persist_keys = set(_persistence_weights())
        assert scorer_keys == persist_keys, (
            f"Dimension mismatch: scorer has {scorer_keys - persist_keys}, "
            f"persistence has {persist_keys - scorer_keys}"
        )

    def test_weights_match(self) -> None:
        """Each dimension weight is identical in both sources."""
        persist = _persistence_weights()
        for dim, scorer_w in _DEFAULT_WEIGHTS.items():
            persist_w = persist[dim.value]
            assert scorer_w == pytest.approx(persist_w), (
                f"{dim.value}: scorer={scorer_w}, persistence={persist_w}"
            )

    def test_weights_sum_to_one(self) -> None:
        """Weights sum to 1.18 in both sources (SIGNATURE_MATCH=0.15 added)."""
        assert sum(_DEFAULT_WEIGHTS.values()) == pytest.approx(1.18, abs=0.01)
        assert sum(_persistence_weights().values()) == pytest.approx(1.18, abs=0.01)

    def test_no_negative_weights(self) -> None:
        """No weight is negative."""
        for dim, w in _DEFAULT_WEIGHTS.items():
            assert w >= 0, f"{dim.value} has negative weight {w}"

    def test_no_zero_weights_for_core_dimensions(self) -> None:
        """Core statistical dimensions must have non-zero weight."""
        core = {
            AnomalyDimension.NOVEL_CLASS,
            AnomalyDimension.POWER_ZSCORE,
            AnomalyDimension.SNR_ZSCORE,
        }
        for dim in core:
            assert _DEFAULT_WEIGHTS[dim] > 0, f"Core dimension {dim.value} has zero weight"
