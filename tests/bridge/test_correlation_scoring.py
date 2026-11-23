"""Tests for correlation scoring in CompositeScorer (P3-8)."""

from __future__ import annotations

import pytest

from sigrift.bridge.anomaly.scorer import (
    AnomalyDimension,
    AnomalyResult,
    CompositeScorer,
    _correlation_adjustment,
)


# ---------------------------------------------------------------------------
# _correlation_adjustment unit tests
# ---------------------------------------------------------------------------


class TestCorrelationAdjustment:
    def test_high_correlation_boost(self):
        """correlation_score=1.0 should give +0.15 boost."""
        adj = _correlation_adjustment(1.0)
        assert adj == pytest.approx(0.15)

    def test_mid_high_correlation_boost(self):
        """correlation_score=0.75 should give ~+0.075 boost."""
        adj = _correlation_adjustment(0.75)
        assert adj == pytest.approx(0.075)

    def test_threshold_correlation_zero(self):
        """correlation_score=0.5 should give 0.0 adjustment."""
        adj = _correlation_adjustment(0.5)
        assert adj == pytest.approx(0.0)

    def test_neutral_zone(self):
        """correlation_score in [0.2, 0.5] should give 0.0."""
        assert _correlation_adjustment(0.35) == pytest.approx(0.0)
        assert _correlation_adjustment(0.2) == pytest.approx(0.0)

    def test_single_node_dampen(self):
        """correlation_score=0.0 should give -0.05 dampening."""
        adj = _correlation_adjustment(0.0)
        assert adj == pytest.approx(-0.05)

    def test_low_correlation_partial_dampen(self):
        """correlation_score=0.1 should give half dampening."""
        adj = _correlation_adjustment(0.1)
        assert adj == pytest.approx(-0.025)


# ---------------------------------------------------------------------------
# CompositeScorer with correlation_score
# ---------------------------------------------------------------------------


class TestCompositeScorerCorrelation:
    @pytest.fixture
    def tier1_result(self) -> AnomalyResult:
        return AnomalyResult(
            score=0.5,
            priority="anomalous",
            dimensions={"novel_class": 0.5},
        )

    def test_no_correlation_score_unchanged(self, tier1_result):
        """Without correlation_score, score should be unaffected."""
        cs = CompositeScorer()
        score_without = cs.score(tier1_result)
        score_with_none = cs.score(tier1_result, correlation_score=None)
        assert score_without == score_with_none

    def test_high_correlation_boosts_score(self, tier1_result):
        cs = CompositeScorer()
        base_score = cs.score(tier1_result)
        boosted = cs.score(tier1_result, correlation_score=1.0)
        assert boosted > base_score
        assert boosted == pytest.approx(base_score + 0.15, abs=0.001)

    def test_zero_correlation_dampens_score(self, tier1_result):
        cs = CompositeScorer()
        base_score = cs.score(tier1_result)
        dampened = cs.score(tier1_result, correlation_score=0.0)
        assert dampened < base_score
        assert dampened == pytest.approx(base_score - 0.05, abs=0.001)

    def test_neutral_correlation_no_change(self, tier1_result):
        cs = CompositeScorer()
        base_score = cs.score(tier1_result)
        neutral = cs.score(tier1_result, correlation_score=0.35)
        assert neutral == pytest.approx(base_score, abs=0.001)

    def test_correlation_with_context_boosts(self, tier1_result):
        """Correlation boost stacks with context boosts."""
        cs = CompositeScorer()
        context = {"novel_class": True}
        with_ctx = cs.score(tier1_result, context=context)
        with_both = cs.score(
            tier1_result, context=context, correlation_score=0.8,
        )
        expected_corr_adj = 0.15 * (0.8 - 0.5) / 0.5  # 0.09
        assert with_both == pytest.approx(with_ctx + expected_corr_adj, abs=0.001)

    def test_correlation_clamped_to_1(self):
        """Score should not exceed 1.0 even with large boosts."""
        high_result = AnomalyResult(
            score=0.95,
            priority="critical",
            dimensions={},
        )
        cs = CompositeScorer()
        final = cs.score(
            high_result,
            context={"novel_class": True, "regulatory_band": True},
            correlation_score=1.0,
        )
        assert final <= 1.0

    def test_correlation_clamped_to_0(self):
        """Score should not go below 0.0 even with dampening."""
        low_result = AnomalyResult(
            score=0.02,
            priority="normal",
            dimensions={},
        )
        cs = CompositeScorer()
        final = cs.score(low_result, correlation_score=0.0)
        assert final >= 0.0

    def test_correlation_with_multi_tier(self, tier1_result):
        """Correlation score works with multi-tier scoring."""
        cs = CompositeScorer()
        score_t1_t2 = cs.score(tier1_result, tier2_score=0.6)
        score_t1_t2_corr = cs.score(
            tier1_result, tier2_score=0.6, correlation_score=0.8,
        )
        expected_adj = 0.15 * (0.8 - 0.5) / 0.5  # 0.09
        assert score_t1_t2_corr == pytest.approx(
            score_t1_t2 + expected_adj, abs=0.001,
        )


# ---------------------------------------------------------------------------
# AnomalyDimension enum
# ---------------------------------------------------------------------------


class TestCorrelationDimension:
    def test_correlation_in_enum(self):
        assert AnomalyDimension.CORRELATION.value == "correlation"

    def test_correlation_weight_003_default(self):
        from sigrift.bridge.anomaly.scorer import _DEFAULT_WEIGHTS
        assert _DEFAULT_WEIGHTS[AnomalyDimension.CORRELATION] == 0.03
