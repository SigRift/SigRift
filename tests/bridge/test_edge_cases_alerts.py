"""Alert engine edge case tests.

Tests empty conditions, contradictory conditions, cooldown boundary
timing, invalid field references, OR logic, disabled rules, and
missing rule IDs.
"""

from __future__ import annotations

import time

import pytest

from sigrift.bridge.alert_engine import evaluate_detection, evaluate_rule


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_detection(**overrides):
    d = {
        "signal_class": "bpsk",
        "freq_hz": 433.92e6,
        "snr_db": 15.0,
        "power_dbm": -40.0,
        "anomaly_score": 0.3,
        "node_id": "node-test-01",
        "family": "psk",
        "confidence": 0.95,
    }
    d.update(overrides)
    return d


def _make_rule(conditions, **overrides):
    r = {
        "rule_id": "test_rule_1",
        "name": "Test Rule",
        "severity": "warning",
        "conditions": conditions,
        "enabled": True,
        "cooldown_seconds": 300,
        "notify_webhook": True,
    }
    r.update(overrides)
    return r


# ---------------------------------------------------------------------------
# Rule with no conditions
# ---------------------------------------------------------------------------


class TestEmptyConditions:
    """A rule with no conditions should never trigger."""

    def test_rule_no_conditions(self):
        """Rule with empty conditions list never matches."""
        rule = _make_rule([])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_rule_conditions_key_missing(self):
        """Rule without conditions key never matches."""
        rule = {
            "rule_id": "no_cond",
            "name": "No Conditions",
            "severity": "warning",
            "enabled": True,
            "cooldown_seconds": 300,
        }
        assert evaluate_rule(_make_detection(), rule) is False

    def test_evaluate_detection_empty_conditions(self):
        """evaluate_detection with a no-condition rule returns empty."""
        rules = [_make_rule([])]
        triggered = evaluate_detection(_make_detection(), rules)
        assert triggered == []


# ---------------------------------------------------------------------------
# Contradictory AND conditions
# ---------------------------------------------------------------------------


class TestContradictoryConditions:
    """Rules with contradictory AND conditions should never trigger."""

    def test_impossible_and_conditions(self):
        """signal_class == bpsk AND signal_class == qpsk never matches."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            {"field": "signal_class", "operator": "eq", "value": "qpsk"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_contradictory_numeric_range(self):
        """snr_db > 100 AND snr_db < 5 is impossible for snr_db=15."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "gt", "value": 100.0},
            {"field": "snr_db", "operator": "lt", "value": 5.0},
        ])
        assert evaluate_rule(_make_detection(), rule) is False


# ---------------------------------------------------------------------------
# Invalid field references
# ---------------------------------------------------------------------------


class TestInvalidFieldReferences:
    """Rules with invalid or non-existent field names should not match."""

    def test_unknown_field(self):
        """Condition on a field not in VALID_FIELDS does not match."""
        rule = _make_rule([
            {"field": "nonexistent_field", "operator": "eq", "value": "foo"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_empty_field_name(self):
        """Condition with empty field name does not match."""
        rule = _make_rule([
            {"field": "", "operator": "eq", "value": "foo"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_invalid_operator(self):
        """Condition with unknown operator does not match."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "like", "value": "%foo%"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_empty_operator(self):
        """Condition with empty operator does not match."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "", "value": 10},
        ])
        assert evaluate_rule(_make_detection(), rule) is False


# ---------------------------------------------------------------------------
# Cooldown boundary conditions
# ---------------------------------------------------------------------------


class TestCooldownBoundary:
    """Test cooldown timing at exact boundaries."""

    def test_cooldown_prevents_second_trigger(self):
        """Same rule does not trigger twice within cooldown period."""
        rules = [_make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=300,
        )]
        cooldowns: dict[str, float] = {}
        now = 1000.0

        # First trigger succeeds
        triggered = evaluate_detection(_make_detection(), rules, cooldowns, now)
        assert len(triggered) == 1
        assert cooldowns["test_rule_1"] == 1000.0

        # Second trigger within cooldown fails
        triggered = evaluate_detection(_make_detection(), rules, cooldowns, now + 100)
        assert len(triggered) == 0

    def test_cooldown_at_exact_boundary(self):
        """Rule does not trigger when exactly at cooldown boundary."""
        rules = [_make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=300,
        )]
        cooldowns: dict[str, float] = {}
        now = 1000.0

        # First trigger
        evaluate_detection(_make_detection(), rules, cooldowns, now)

        # Exactly at cooldown boundary (now - last_trigger = 299.99... < 300)
        triggered = evaluate_detection(_make_detection(), rules, cooldowns, now + 299.99)
        assert len(triggered) == 0

    def test_cooldown_just_after_boundary(self):
        """Rule triggers again after cooldown period expires."""
        rules = [_make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=300,
        )]
        cooldowns: dict[str, float] = {}
        now = 1000.0

        # First trigger
        evaluate_detection(_make_detection(), rules, cooldowns, now)

        # Just past cooldown boundary
        triggered = evaluate_detection(_make_detection(), rules, cooldowns, now + 300.01)
        assert len(triggered) == 1

    def test_cooldown_zero_seconds(self):
        """Rule with cooldown_seconds=0 triggers every time."""
        rules = [_make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=0,
        )]
        cooldowns: dict[str, float] = {}
        now = 1000.0

        t1 = evaluate_detection(_make_detection(), rules, cooldowns, now)
        assert len(t1) == 1

        t2 = evaluate_detection(_make_detection(), rules, cooldowns, now + 0.001)
        assert len(t2) == 1


# ---------------------------------------------------------------------------
# Disabled rules
# ---------------------------------------------------------------------------


class TestDisabledRules:
    """Disabled rules should never trigger."""

    def test_disabled_rule_no_match(self):
        """Disabled rule with matching conditions does not trigger."""
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            enabled=False,
        )
        assert evaluate_rule(_make_detection(), rule) is False

    def test_evaluate_detection_disabled_rule(self):
        """evaluate_detection skips disabled rules."""
        rules = [_make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            enabled=False,
        )]
        triggered = evaluate_detection(_make_detection(), rules)
        assert triggered == []


# ---------------------------------------------------------------------------
# Missing rule_id
# ---------------------------------------------------------------------------


class TestMissingRuleId:
    """Rules without rule_id should be skipped by evaluate_detection."""

    def test_rule_without_id_skipped(self):
        """Rule with no rule_id or alert_id is skipped."""
        rules = [{
            "name": "No ID Rule",
            "severity": "warning",
            "conditions": [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            "enabled": True,
            "cooldown_seconds": 300,
        }]
        triggered = evaluate_detection(_make_detection(), rules)
        assert triggered == []


# ---------------------------------------------------------------------------
# OR logic
# ---------------------------------------------------------------------------


class TestORLogic:
    """Test OR logic in rule evaluation."""

    def test_or_one_match(self):
        """OR rule triggers when one condition matches."""
        rule = _make_rule(
            [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"},
                {"field": "signal_class", "operator": "eq", "value": "qpsk"},
            ],
            logic="OR",
        )
        assert evaluate_rule(_make_detection(), rule) is True

    def test_or_no_match(self):
        """OR rule does not trigger when no conditions match."""
        rule = _make_rule(
            [
                {"field": "signal_class", "operator": "eq", "value": "qpsk"},
                {"field": "signal_class", "operator": "eq", "value": "ofdm"},
            ],
            logic="OR",
        )
        assert evaluate_rule(_make_detection(), rule) is False


# ---------------------------------------------------------------------------
# Between operator edge cases
# ---------------------------------------------------------------------------


class TestBetweenOperator:
    """Test the between operator for boundary conditions."""

    def test_between_at_lower_bound(self):
        """Value exactly at lower bound matches between."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "between", "value": [15.0, 20.0]},
        ])
        assert evaluate_rule(_make_detection(snr_db=15.0), rule) is True

    def test_between_at_upper_bound(self):
        """Value exactly at upper bound matches between."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "between", "value": [10.0, 15.0]},
        ])
        assert evaluate_rule(_make_detection(snr_db=15.0), rule) is True

    def test_between_below_lower_bound(self):
        """Value below lower bound does not match between."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "between", "value": [20.0, 30.0]},
        ])
        assert evaluate_rule(_make_detection(snr_db=15.0), rule) is False

    def test_between_invalid_value_not_list(self):
        """Between with non-list value does not match."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "between", "value": 15.0},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_between_wrong_length(self):
        """Between with list of wrong length does not match."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "between", "value": [15.0]},
        ])
        assert evaluate_rule(_make_detection(), rule) is False


# ---------------------------------------------------------------------------
# In / not_in operator edge cases
# ---------------------------------------------------------------------------


class TestInNotInOperators:
    """Test the in/not_in operators with edge cases."""

    def test_in_with_empty_list(self):
        """'in' with empty list never matches."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "in", "value": []},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_not_in_with_empty_list(self):
        """'not_in' with empty list always matches."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "not_in", "value": []},
        ])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_in_non_list_value(self):
        """'in' with non-list value does not match."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "in", "value": "bpsk"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_not_in_non_list_value(self):
        """'not_in' with non-list value always returns True."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "not_in", "value": "bpsk"},
        ])
        assert evaluate_rule(_make_detection(), rule) is True


# ---------------------------------------------------------------------------
# Type coercion edge cases
# ---------------------------------------------------------------------------


class TestTypeCoercion:
    """Test numeric comparison with string/None values."""

    def test_gt_with_none_field(self):
        """Numeric comparison on None field does not match."""
        rule = _make_rule([
            {"field": "power_dbm", "operator": "gt", "value": -50.0},
        ])
        det = _make_detection()
        det["power_dbm"] = None
        assert evaluate_rule(det, rule) is False

    def test_gt_with_non_numeric_value(self):
        """Numeric comparison with string value does not crash."""
        rule = _make_rule([
            {"field": "snr_db", "operator": "gt", "value": "not_a_number"},
        ])
        assert evaluate_rule(_make_detection(), rule) is False


# ---------------------------------------------------------------------------
# Multiple rules evaluation
# ---------------------------------------------------------------------------


class TestMultipleRules:
    """Test evaluation with multiple rules, some matching and some not."""

    def test_multiple_rules_partial_match(self):
        """Only matching rules are returned in triggered list."""
        rules = [
            _make_rule(
                [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
                rule_id="r1",
            ),
            _make_rule(
                [{"field": "signal_class", "operator": "eq", "value": "qpsk"}],
                rule_id="r2",
            ),
            _make_rule(
                [{"field": "snr_db", "operator": "gt", "value": 10.0}],
                rule_id="r3",
            ),
        ]
        triggered = evaluate_detection(_make_detection(), rules)
        assert len(triggered) == 2
        rule_ids = [r["rule_id"] for r in triggered]
        assert "r1" in rule_ids
        assert "r2" not in rule_ids
        assert "r3" in rule_ids

    def test_empty_rules_list(self):
        """No rules means no triggers."""
        triggered = evaluate_detection(_make_detection(), [])
        assert triggered == []
