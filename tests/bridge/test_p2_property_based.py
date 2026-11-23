"""Property-based tests using Hypothesis for scorer, baseline, cache, and SQL builders.

P2-18: Validates invariants that must hold for all valid inputs, catching
edge cases that hand-written examples miss.
"""

from __future__ import annotations

import math

import pytest

pytest.importorskip(
    "hypothesis",
    reason="hypothesis is a test-only dep for property-based tests",
)

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from sigrift.bridge.anomaly.scorer import (
    AnomalyScorer,
    CompositeScorer,
    AnomalyResult,
    FeedbackCalibrator,
)
from sigrift.bridge.anomaly.baseline import (
    FrequencyBaseline,
    BaselineManager,
)
from sigrift.bridge.cache import TTLCache

# ---------------------------------------------------------------------------
# Shared strategies
# ---------------------------------------------------------------------------

_SIGNAL_CLASSES = ["wifi", "fm", "bpsk", "ook", "qpsk", "8psk", "fsk", "ofdm"]

detection_strategy = st.fixed_dictionaries(
    {
        "signal_class": st.sampled_from(_SIGNAL_CLASSES),
        "confidence": st.floats(min_value=0.0, max_value=1.0),
        "freq_hz": st.floats(min_value=1e6, max_value=6e9),
    },
    optional={
        "power_dbm": st.one_of(st.none(), st.floats(min_value=-150.0, max_value=30.0)),
        "snr_db": st.one_of(st.none(), st.floats(min_value=-10.0, max_value=50.0)),
    },
)


def _make_scorer() -> AnomalyScorer:
    """Build a fresh scorer with empty baselines."""
    return AnomalyScorer(BaselineManager())


def _make_scorer_with_baseline(
    freq_hz: float, n: int = 50
) -> AnomalyScorer:
    """Build a scorer whose baseline has been primed with n detections."""
    mgr = BaselineManager()
    for i in range(n):
        mgr.update(
            freq_hz,
            class_name="wifi",
            confidence=0.9,
            power_dbm=-50.0 + (i % 5),
            hour=i % 24,
            snr_db=20.0 + (i % 3),
        )
    return AnomalyScorer(mgr)


# ===================================================================
# Scorer properties
# ===================================================================


class TestScorerProperties:
    """Property-based tests for AnomalyScorer."""

    @given(det=detection_strategy)
    @settings(max_examples=50)
    def test_all_dimension_scores_in_range(self, det: dict) -> None:
        """Every dimension score must be in [0, 1]."""
        scorer = _make_scorer_with_baseline(det["freq_hz"])
        result = scorer.score(det)
        for dim, value in result.dimensions.items():
            assert 0.0 <= value <= 1.0, f"dim {dim} = {value} out of [0,1]"

    @given(det=detection_strategy)
    @settings(max_examples=50)
    def test_composite_score_in_range(self, det: dict) -> None:
        """Composite score must always be in [0, 1]."""
        scorer = _make_scorer()
        result = scorer.score(det)
        assert 0.0 <= result.score <= 1.0

    @given(det=detection_strategy)
    @settings(max_examples=50)
    def test_priority_label_matches_range(self, det: dict) -> None:
        """Priority label must match the documented score thresholds."""
        scorer = _make_scorer()
        result = scorer.score(det)
        s = result.score
        if s < 0.3:
            assert result.priority == "normal"
        elif s < 0.5:
            assert result.priority == "interesting"
        elif s < 0.7:
            assert result.priority == "anomalous"
        else:
            assert result.priority == "critical"

    @given(
        t1_score=st.floats(min_value=0.0, max_value=1.0),
        t2_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
        t3_score=st.one_of(st.none(), st.floats(min_value=0.0, max_value=1.0)),
    )
    @settings(max_examples=50)
    def test_composite_scorer_bounded(
        self,
        t1_score: float,
        t2_score: float | None,
        t3_score: float | None,
    ) -> None:
        """CompositeScorer.score() always in [0, 1] for any tier inputs."""
        tier1 = AnomalyResult(
            score=t1_score,
            priority="normal",
            dimensions={},
            reasons=[],
        )
        cs = CompositeScorer()
        result = cs.score(tier1, tier2_score=t2_score, tier3_score=t3_score)
        assert 0.0 <= result <= 1.0

    @given(n=st.integers(min_value=0, max_value=500))
    @settings(max_examples=50)
    def test_quiet_frequency_monotonic(self, n: int) -> None:
        """_quiet_frequency_score(n) >= _quiet_frequency_score(n+1).

        More detections at a frequency -> lower quiet score.
        """
        bl_a = FrequencyBaseline()
        bl_a.total_detections = n
        bl_b = FrequencyBaseline()
        bl_b.total_detections = n + 1
        score_a = AnomalyScorer._quiet_frequency_score(bl_a)
        score_b = AnomalyScorer._quiet_frequency_score(bl_b)
        assert score_a >= score_b - 1e-12  # allow float rounding

    @given(
        fp=st.integers(min_value=0, max_value=1000),
        tp=st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=50)
    def test_feedback_calibrator_offset_bounded(
        self, fp: int, tp: int
    ) -> None:
        """Calibrator offset must always have small absolute value."""
        cal = FeedbackCalibrator()
        cal.calibrate(fp, tp)
        # Max possible: (1.0 - 0.15) * 0.1 = 0.085
        # Min possible: (0.0 - 0.15) * 0.1 = -0.015
        assert abs(cal.offset) < 0.1


# ===================================================================
# Baseline properties
# ===================================================================


class TestBaselineProperties:
    """Property-based tests for FrequencyBaseline and BaselineManager."""

    @given(
        classes=st.lists(
            st.sampled_from(_SIGNAL_CLASSES), min_size=1, max_size=30
        ),
        query_class=st.sampled_from(_SIGNAL_CLASSES),
    )
    @settings(max_examples=50)
    def test_class_probability_in_range(
        self, classes: list[str], query_class: str
    ) -> None:
        """After any sequence of updates, class_probability_smoothed in [0, 1]."""
        bl = FrequencyBaseline()
        for cls in classes:
            bl.update(cls, 0.9, -50.0, 12)
        prob = bl.class_probability_smoothed(query_class)
        assert 0.0 <= prob <= 1.0

    @given(power=st.floats(min_value=-150.0, max_value=30.0))
    @settings(max_examples=50)
    def test_power_zscore_zero_on_cold_start(self, power: float) -> None:
        """With fewer than 2 detections, power_zscore must return 0.0."""
        bl = FrequencyBaseline()
        assert bl.power_zscore(power) == 0.0
        bl.update("wifi", 0.9, power, 12)
        assert bl.power_zscore(power) == 0.0

    @given(freq=st.floats(min_value=1e6, max_value=6e9))
    @settings(max_examples=50)
    def test_freq_bin_idempotent(self, freq: float) -> None:
        """freq_bin(freq_bin(f)) == freq_bin(f)."""
        binned = BaselineManager.freq_bin(freq)
        assert BaselineManager.freq_bin(binned) == binned

    @given(
        samples=st.lists(
            st.floats(min_value=-150.0, max_value=30.0),
            min_size=15,
            max_size=50,
        ),
        query=st.floats(min_value=-150.0, max_value=30.0),
    )
    @settings(max_examples=50)
    def test_mad_score_bounded(
        self, samples: list[float], query: float
    ) -> None:
        """power_mad_score always in [0, 1]."""
        bl = FrequencyBaseline()
        for s in samples:
            bl.update("wifi", 0.9, s, 12)
        score = bl.power_mad_score(query)
        assert 0.0 <= score <= 1.0

    @given(
        powers=st.lists(
            st.floats(min_value=-150.0, max_value=30.0),
            min_size=2,
            max_size=100,
        ),
    )
    @settings(max_examples=50)
    def test_cusum_accumulators_non_negative(
        self, powers: list[float]
    ) -> None:
        """cusum_pos and cusum_neg >= 0 after any updates."""
        bl = FrequencyBaseline()
        for p in powers:
            bl.update("wifi", 0.9, p, 12)
        assert bl.cusum_pos >= 0.0
        assert bl.cusum_neg >= 0.0

    @given(
        powers=st.lists(
            st.floats(min_value=-150.0, max_value=30.0),
            min_size=1,
            max_size=100,
        ),
    )
    @settings(max_examples=50)
    def test_welford_variance_non_negative(
        self, powers: list[float]
    ) -> None:
        """power_var >= 0 after any sequence of updates."""
        bl = FrequencyBaseline()
        for p in powers:
            bl.update("wifi", 0.9, p, 12)
        assert bl.power_var >= -1e-15  # allow tiny float rounding


# ===================================================================
# Cache properties
# ===================================================================


class TestCacheProperties:
    """Property-based tests for TTLCache.make_key."""

    @given(
        method=st.text(min_size=1, max_size=20),
        limit=st.integers(min_value=0, max_value=1000),
        offset=st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=50)
    def test_cache_key_deterministic(
        self, method: str, limit: int, offset: int
    ) -> None:
        """Same inputs always produce same key."""
        k1 = TTLCache.make_key(method, limit=limit, offset=offset)
        k2 = TTLCache.make_key(method, limit=limit, offset=offset)
        assert k1 == k2

    @given(
        method_a=st.text(min_size=1, max_size=10, alphabet="abcdefghij"),
        method_b=st.text(min_size=1, max_size=10, alphabet="abcdefghij"),
        val_a=st.integers(min_value=0, max_value=999),
        val_b=st.integers(min_value=0, max_value=999),
    )
    @settings(max_examples=50)
    def test_cache_key_unique(
        self,
        method_a: str,
        method_b: str,
        val_a: int,
        val_b: int,
    ) -> None:
        """Different inputs produce different keys."""
        assume(method_a != method_b or val_a != val_b)
        k1 = TTLCache.make_key(method_a, x=val_a)
        k2 = TTLCache.make_key(method_b, x=val_b)
        assert k1 != k2


# ===================================================================
# SQL builder properties
# ===================================================================


class TestTenantFilterProperties:
    """Property-based tests for SharedContext.tenant_filter SQL generation."""

    @given(alias=st.text(min_size=0, max_size=10, alphabet="abcdefghijklmnop"))
    @settings(max_examples=50)
    def test_tenant_filter_produces_valid_sql(self, alias: str) -> None:
        """tenant_filter returns (clause, params) with exactly 1 param."""
        # Build a SharedContext without actually touching the DB
        from sigrift.bridge.storage.base import SharedContext

        ctx = SharedContext.__new__(SharedContext)
        ctx.tenant_id = "test_tenant"
        clause, params = ctx.tenant_filter(alias)
        assert len(params) == 1
        assert params[0] == "test_tenant"

    @given(alias=st.text(min_size=0, max_size=10, alphabet="abcdefghijklmnop"))
    @settings(max_examples=50)
    def test_tenant_filter_clause_has_placeholder(self, alias: str) -> None:
        """Clause must contain '?' placeholder for parameterized query."""
        from sigrift.bridge.storage.base import SharedContext

        ctx = SharedContext.__new__(SharedContext)
        ctx.tenant_id = "t"
        clause, _ = ctx.tenant_filter(alias)
        assert "?" in clause
        assert "tenant_id" in clause


# ===================================================================
# Additional properties
# ===================================================================


class TestAdditionalProperties:
    """Additional scorer/baseline property tests."""

    @given(confidence=st.floats(min_value=0.0, max_value=1.0))
    @settings(max_examples=50)
    def test_low_confidence_score_complement(self, confidence: float) -> None:
        """_low_confidence_score(c) == 1 - c for c in [0, 1]."""
        result = AnomalyScorer._low_confidence_score(confidence)
        assert abs(result - (1.0 - confidence)) < 1e-12

    @given(class_name=st.sampled_from(_SIGNAL_CLASSES + ["never_seen_xyz"]))
    @settings(max_examples=50)
    def test_novel_class_binary(self, class_name: str) -> None:
        """_novel_class_score returns exactly 0.0 or 1.0."""
        bl = FrequencyBaseline()
        bl.update("wifi", 0.9, -50.0, 12)
        score = AnomalyScorer._novel_class_score(bl, class_name)
        assert score == 0.0 or score == 1.0

    @given(
        classes=st.lists(
            st.sampled_from(_SIGNAL_CLASSES), min_size=1, max_size=20
        ),
    )
    @settings(max_examples=50)
    def test_baseline_update_increments_count(
        self, classes: list[str]
    ) -> None:
        """total_detections increases by 1 per update."""
        bl = FrequencyBaseline()
        for i, cls in enumerate(classes):
            assert bl.total_detections == i
            bl.update(cls, 0.9, -50.0, 12)
        assert bl.total_detections == len(classes)

    @given(
        power=st.sampled_from([float("nan"), float("inf"), float("-inf"), 0.0, -999.0, 999.0]),
        snr=st.sampled_from([float("nan"), float("inf"), float("-inf"), None, 0.0]),
        conf=st.sampled_from([float("nan"), float("inf"), 0.0, 1.0, -1.0, 2.0]),
    )
    @settings(max_examples=50)
    def test_scorer_no_crash_on_edge_cases(
        self, power: float, snr: float | None, conf: float
    ) -> None:
        """NaN, inf, and extreme values must not crash the scorer."""
        scorer = _make_scorer()
        det = {
            "signal_class": "wifi",
            "confidence": conf,
            "freq_hz": 2.4e9,
            "power_dbm": power,
            "snr_db": snr,
        }
        # Must not raise
        result = scorer.score(det)
        # Score must still be a finite float in [0, 1] despite bad inputs
        assert isinstance(result.score, float)
        assert math.isfinite(result.score)
        assert 0.0 <= result.score <= 1.0
