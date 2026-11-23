"""Tests for the CompositeScorer — multi-tier anomaly score combining.

Tests cover:
  - Single tier (tier 1 only)
  - Two tiers (tier1 + tier2, tier1 + tier3)
  - All three tiers
  - Context boosts (additive, capped)
  - Score clamping to [0, 1]
  - Custom weights
"""

from __future__ import annotations

import pytest

from sigrift.bridge.anomaly.scorer import AnomalyResult, CompositeScorer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(score: float) -> AnomalyResult:
    """Create a minimal AnomalyResult."""
    if score < 0.3:
        priority = "normal"
    elif score < 0.5:
        priority = "interesting"
    elif score < 0.7:
        priority = "anomalous"
    else:
        priority = "critical"
    return AnomalyResult(score=score, priority=priority)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSingleTier:
    """Tests with only Tier 1 available."""

    def test_tier1_only(self) -> None:
        """With only tier1, composite equals tier1 score."""
        cs = CompositeScorer()
        result = _make_result(0.5)
        composite = cs.score(result)
        assert composite == pytest.approx(0.5)

    def test_tier1_only_zero(self) -> None:
        """Tier 1 score of 0 gives composite of 0."""
        cs = CompositeScorer()
        result = _make_result(0.0)
        assert cs.score(result) == 0.0

    def test_tier1_only_max(self) -> None:
        """Tier 1 score of 1.0 gives composite of 1.0."""
        cs = CompositeScorer()
        result = _make_result(1.0)
        assert cs.score(result) == 1.0


class TestTwoTiers:
    """Tests with two tiers available."""

    def test_tier1_tier2(self) -> None:
        """Tier 1 + Tier 2 with default weights (0.5/0.5)."""
        cs = CompositeScorer()
        result = _make_result(0.4)
        composite = cs.score(result, tier2_score=0.6)
        expected = 0.5 * 0.4 + 0.5 * 0.6
        assert composite == pytest.approx(expected)

    def test_tier1_tier3(self) -> None:
        """Tier 1 + Tier 3 with default weights (0.5/0.5)."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        composite = cs.score(result, tier3_score=0.7)
        expected = 0.5 * 0.3 + 0.5 * 0.7
        assert composite == pytest.approx(expected)


class TestThreeTiers:
    """Tests with all three tiers available."""

    def test_all_three_tiers(self) -> None:
        """All 3 tiers with default weights (0.3/0.3/0.4)."""
        cs = CompositeScorer()
        result = _make_result(0.2)
        composite = cs.score(result, tier2_score=0.5, tier3_score=0.8)
        expected = 0.3 * 0.2 + 0.3 * 0.5 + 0.4 * 0.8
        assert composite == pytest.approx(expected)

    def test_all_zero(self) -> None:
        """All tiers scoring 0 gives 0."""
        cs = CompositeScorer()
        result = _make_result(0.0)
        assert cs.score(result, tier2_score=0.0, tier3_score=0.0) == 0.0

    def test_all_max(self) -> None:
        """All tiers scoring 1.0 gives 1.0 (clamped)."""
        cs = CompositeScorer()
        result = _make_result(1.0)
        composite = cs.score(result, tier2_score=1.0, tier3_score=1.0)
        assert composite == pytest.approx(1.0)


class TestContextBoosts:
    """Tests for context-based additive score boosting."""

    def test_novel_class_boost(self) -> None:
        """Novel class context adds +0.10."""
        cs = CompositeScorer()
        result = _make_result(0.4)
        base = cs.score(result)
        boosted = cs.score(result, context={"novel_class": True})
        assert boosted == pytest.approx(base + 0.10)

    def test_quiet_frequency_boost(self) -> None:
        """Quiet frequency context adds +0.08."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        base = cs.score(result)
        boosted = cs.score(result, context={"quiet_frequency": True})
        assert boosted == pytest.approx(base + 0.08)

    def test_multiple_nodes_boost(self) -> None:
        """Multiple nodes context adds +0.05."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        base = cs.score(result)
        boosted = cs.score(result, context={"multiple_nodes": True})
        assert boosted == pytest.approx(base + 0.05)

    def test_regulatory_band_boost(self) -> None:
        """Regulatory band context adds +0.10."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        base = cs.score(result)
        boosted = cs.score(result, context={"regulatory_band": True})
        assert boosted == pytest.approx(base + 0.10)

    def test_multiple_context_flags_additive(self) -> None:
        """Multiple context flags add together (capped at MAX_CONTEXT_BOOST)."""
        cs = CompositeScorer()
        result = _make_result(0.2)
        # novel_class(0.10) + quiet_frequency(0.08) = 0.18, under cap
        boosted = cs.score(result, context={
            "novel_class": True,
            "quiet_frequency": True,
        })
        expected = 0.2 + 0.10 + 0.08
        assert boosted == pytest.approx(expected)

    def test_all_flags_capped(self) -> None:
        """All four flags sum to 0.33 but are capped at MAX_CONTEXT_BOOST=0.25."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        boosted = cs.score(result, context={
            "novel_class": True,
            "quiet_frequency": True,
            "multiple_nodes": True,
            "regulatory_band": True,
        })
        # 0.3 + min(0.33, 0.25) = 0.55
        assert boosted == pytest.approx(0.3 + 0.25)

    def test_mid_score_not_inflated_to_max(self) -> None:
        """A 0.35 score with all flags should NOT reach 1.0 (the original bug)."""
        cs = CompositeScorer()
        result = _make_result(0.35)
        boosted = cs.score(result, context={
            "novel_class": True,
            "quiet_frequency": True,
            "multiple_nodes": True,
            "regulatory_band": True,
        })
        assert boosted == pytest.approx(0.35 + 0.25)
        assert boosted < 1.0

    def test_false_context_no_boost(self) -> None:
        """False context flags do not boost."""
        cs = CompositeScorer()
        result = _make_result(0.3)
        base = cs.score(result)
        same = cs.score(result, context={"novel_class": False})
        assert same == pytest.approx(base)

    def test_empty_context(self) -> None:
        """Empty context dict does not change score."""
        cs = CompositeScorer()
        result = _make_result(0.5)
        base = cs.score(result)
        same = cs.score(result, context={})
        assert same == pytest.approx(base)


class TestClamping:
    """Tests for score clamping to [0, 1]."""

    def test_clamp_to_one(self) -> None:
        """Score is clamped to 1.0 when boosts push it over."""
        cs = CompositeScorer()
        result = _make_result(0.9)
        # 0.9 + 0.25 (capped) = 1.15 → clamped to 1.0
        composite = cs.score(result, context={
            "novel_class": True,
            "quiet_frequency": True,
            "multiple_nodes": True,
            "regulatory_band": True,
        })
        assert composite == 1.0

    def test_never_negative(self) -> None:
        """Score never goes below 0."""
        cs = CompositeScorer()
        result = _make_result(0.0)
        composite = cs.score(result, tier2_score=0.0, tier3_score=0.0)
        assert composite >= 0.0


class TestCustomWeights:
    """Tests for custom weight configuration."""

    def test_custom_3tier_weights(self) -> None:
        """Custom 3-tier weights are applied."""
        cs = CompositeScorer(weights_3tier=(0.1, 0.2, 0.7))
        result = _make_result(0.5)
        composite = cs.score(result, tier2_score=0.5, tier3_score=0.5)
        expected = 0.1 * 0.5 + 0.2 * 0.5 + 0.7 * 0.5
        assert composite == pytest.approx(expected)

    def test_custom_2tier_weights(self) -> None:
        """Custom 2-tier weights are applied."""
        cs = CompositeScorer(weights_2tier=(0.3, 0.7))
        result = _make_result(0.4)
        composite = cs.score(result, tier2_score=0.6)
        expected = 0.3 * 0.4 + 0.7 * 0.6
        assert composite == pytest.approx(expected)

    def test_custom_context_boosts(self) -> None:
        """Custom context boosts override defaults."""
        cs = CompositeScorer(context_multipliers={"novel_class": 0.20})
        result = _make_result(0.3)
        boosted = cs.score(result, context={"novel_class": True})
        assert boosted == pytest.approx(0.3 + 0.20)
