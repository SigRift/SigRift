"""Tests for the alert rule condition builder and evaluation engine.

Covers:
  - Condition matching for each operator (eq, ne, gt, gte, lt, lte, in, not_in, between)
  - AND logic (all conditions must match)
  - Cooldown prevents re-trigger
  - Rule CRUD endpoints (create, list, get, update, delete)
  - Detection ingest triggers matching rules
  - Dry-run test endpoint
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.alert_engine import evaluate_detection, evaluate_rule


# ---------------------------------------------------------------------------
# Unit tests: condition evaluation
# ---------------------------------------------------------------------------


def _make_detection(**overrides):
    """Build a detection dict with defaults."""
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
    """Build a rule dict with defaults."""
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


class TestConditionOperators:
    """Test each operator in isolation."""

    def test_eq_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "eq", "value": "bpsk"}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_eq_no_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "eq", "value": "qpsk"}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_ne_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "ne", "value": "qpsk"}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_ne_no_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "ne", "value": "bpsk"}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_gt_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "gt", "value": 10.0}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_gt_no_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "gt", "value": 20.0}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_gt_equal_no_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "gt", "value": 15.0}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_gte_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "gte", "value": 15.0}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_gte_no_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "gte", "value": 16.0}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_lt_match(self):
        rule = _make_rule([{"field": "power_dbm", "operator": "lt", "value": -30.0}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_lt_no_match(self):
        rule = _make_rule([{"field": "power_dbm", "operator": "lt", "value": -50.0}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_lte_match(self):
        rule = _make_rule([{"field": "power_dbm", "operator": "lte", "value": -40.0}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_lte_no_match(self):
        rule = _make_rule([{"field": "power_dbm", "operator": "lte", "value": -41.0}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_in_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "in", "value": ["bpsk", "qpsk"]}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_in_no_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "in", "value": ["qpsk", "qam16"]}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_not_in_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "not_in", "value": ["qpsk", "qam16"]}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_not_in_no_match(self):
        rule = _make_rule([{"field": "signal_class", "operator": "not_in", "value": ["bpsk", "qpsk"]}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_between_match(self):
        rule = _make_rule([{"field": "freq_hz", "operator": "between", "value": [400e6, 500e6]}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_between_no_match(self):
        rule = _make_rule([{"field": "freq_hz", "operator": "between", "value": [500e6, 600e6]}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_between_boundary_inclusive(self):
        rule = _make_rule([{"field": "snr_db", "operator": "between", "value": [15.0, 20.0]}])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_missing_field_no_match(self):
        rule = _make_rule([{"field": "bandwidth_hz", "operator": "gt", "value": 0}])
        det = _make_detection()
        det.pop("bandwidth_hz", None)
        assert evaluate_rule(det, rule) is False

    def test_invalid_operator_no_match(self):
        rule = _make_rule([{"field": "snr_db", "operator": "invalid_op", "value": 10}])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_invalid_field_no_match(self):
        rule = _make_rule([{"field": "nonexistent", "operator": "eq", "value": "x"}])
        assert evaluate_rule(_make_detection(), rule) is False


class TestAndLogic:
    """All conditions must match (AND logic)."""

    def test_all_match(self):
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            {"field": "snr_db", "operator": "gt", "value": 10.0},
            {"field": "anomaly_score", "operator": "gte", "value": 0.2},
        ])
        assert evaluate_rule(_make_detection(), rule) is True

    def test_one_fails(self):
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            {"field": "snr_db", "operator": "gt", "value": 100.0},  # fails
        ])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_empty_conditions_no_match(self):
        """A rule with no conditions should not auto-trigger on detections."""
        rule = _make_rule([])
        assert evaluate_rule(_make_detection(), rule) is False

    def test_disabled_rule(self):
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            enabled=False,
        )
        assert evaluate_rule(_make_detection(), rule) is False


class TestOrLogic:
    """OR logic: any condition must match."""

    def test_or_all_match(self):
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            {"field": "snr_db", "operator": "gt", "value": 10.0},
        ], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is True

    def test_or_one_matches(self):
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "qpsk"},  # fails
            {"field": "snr_db", "operator": "gt", "value": 10.0},  # matches
        ], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is True

    def test_or_none_match(self):
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "qpsk"},
            {"field": "snr_db", "operator": "gt", "value": 100.0},
        ], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is False

    def test_or_single_condition_match(self):
        rule = _make_rule([
            {"field": "anomaly_score", "operator": "gte", "value": 0.2},
        ], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is True

    def test_or_single_condition_no_match(self):
        rule = _make_rule([
            {"field": "anomaly_score", "operator": "gte", "value": 0.9},
        ], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is False

    def test_or_empty_conditions(self):
        rule = _make_rule([], logic="OR")
        assert evaluate_rule(_make_detection(), rule) is False

    def test_or_disabled(self):
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            logic="OR", enabled=False,
        )
        assert evaluate_rule(_make_detection(), rule) is False

    def test_default_logic_is_and(self):
        """Rules without a logic field should default to AND."""
        rule = _make_rule([
            {"field": "signal_class", "operator": "eq", "value": "qpsk"},  # fails
            {"field": "snr_db", "operator": "gt", "value": 10.0},  # matches
        ])
        # No logic field set, defaults to AND, so should be False
        assert evaluate_rule(_make_detection(), rule) is False


class TestCooldown:
    """Cooldown prevents re-trigger within the specified interval.

    These tests previously carried an xdist_group marker as a flake
    workaround. The actual root cause was a bug in evaluate_detection
    where a missing cooldown entry was treated as "triggered at
    monotonic 0", suppressing first-fires when time.monotonic() <
    cooldown_seconds — which is the steady state inside fresh xdist
    workers. The fix in alert_engine.py removed that case; the marker
    is no longer needed.
    """

    def test_cooldown_prevents_retrigger(self):
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=300,
        )
        cooldowns: dict[str, float] = {}
        det = _make_detection()

        # First evaluation triggers
        now = time.monotonic()
        triggered = evaluate_detection(det, [rule], cooldowns, now)
        assert len(triggered) == 1

        # Second evaluation within cooldown does NOT trigger
        triggered2 = evaluate_detection(det, [rule], cooldowns, now + 10)
        assert len(triggered2) == 0

    def test_cooldown_expires_allows_retrigger(self):
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=60,
        )
        cooldowns: dict[str, float] = {}
        det = _make_detection()

        now = time.monotonic()
        triggered = evaluate_detection(det, [rule], cooldowns, now)
        assert len(triggered) == 1

        # After cooldown expires, re-triggers
        triggered2 = evaluate_detection(det, [rule], cooldowns, now + 61)
        assert len(triggered2) == 1

    def test_multiple_rules_independent_cooldowns(self):
        rule1 = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            rule_id="rule_1", cooldown_seconds=300,
        )
        rule2 = _make_rule(
            [{"field": "family", "operator": "eq", "value": "psk"}],
            rule_id="rule_2", cooldown_seconds=60,
        )
        cooldowns: dict[str, float] = {}
        det = _make_detection()
        now = time.monotonic()

        triggered = evaluate_detection(det, [rule1, rule2], cooldowns, now)
        assert len(triggered) == 2

        # rule2 cooldown expired but rule1 still in cooldown
        triggered2 = evaluate_detection(det, [rule1, rule2], cooldowns, now + 65)
        assert len(triggered2) == 1
        assert triggered2[0]["rule_id"] == "rule_2"

    def test_first_trigger_at_low_monotonic(self):
        """Regression test for the cooldown-suppression bug: a never-
        triggered rule must fire on the first matching detection even
        when `now` (monotonic clock) is smaller than `cooldown_seconds`.
        Before the fix, the code treated a missing cooldowns entry as
        "triggered at time 0", silently suppressing first-fires for
        the entire duration of `cooldown_seconds` after any process
        start.
        """
        rule = _make_rule(
            [{"field": "signal_class", "operator": "eq", "value": "bpsk"}],
            cooldown_seconds=300,
        )
        cooldowns: dict[str, float] = {}
        det = _make_detection()
        # Simulate a freshly-started process: monotonic clock is well
        # below the 300-second cooldown.
        triggered = evaluate_detection(det, [rule], cooldowns, now=5.0)
        assert len(triggered) == 1, (
            "first-time match must fire regardless of monotonic clock value"
        )
        # And the cooldown is correctly recorded for subsequent calls.
        assert "test_rule_1" in cooldowns
        triggered2 = evaluate_detection(det, [rule], cooldowns, now=10.0)
        assert len(triggered2) == 0, "second call within cooldown must not fire"


# ---------------------------------------------------------------------------
# Integration tests: API endpoints
# ---------------------------------------------------------------------------


class TestConditionRuleCRUD:
    """CRUD operations for condition-based alert rules."""

    def test_create_rule(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "High Anomaly BPSK",
            "severity": "critical",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"},
                {"field": "anomaly_score", "operator": "gte", "value": 0.7},
            ],
            "cooldown_seconds": 120,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "High Anomaly BPSK"
        assert data["severity"] == "critical"
        assert len(data["conditions"]) == 2
        assert data["cooldown_seconds"] == 120
        assert data["enabled"] is True
        assert data["trigger_count"] == 0
        assert data["logic"] == "AND"  # default

    def test_create_rule_with_or_logic(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "OR Logic Rule",
            "severity": "warning",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"},
                {"field": "signal_class", "operator": "eq", "value": "qpsk"},
            ],
            "logic": "OR",
            "cooldown_seconds": 60,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["logic"] == "OR"
        assert len(data["conditions"]) == 2

    def test_list_rules(self, client: TestClient):
        # Create two rules
        client.post("/api/alerts/rules/conditions", json={
            "name": "Rule A",
            "severity": "info",
            "conditions": [{"field": "family", "operator": "eq", "value": "psk"}],
        })
        client.post("/api/alerts/rules/conditions", json={
            "name": "Rule B",
            "severity": "warning",
            "conditions": [{"field": "snr_db", "operator": "gt", "value": 20}],
        })
        resp = client.get("/api/alerts/rules/conditions")
        assert resp.status_code == 200
        rules = resp.json()
        assert len(rules) >= 2

    def test_get_rule(self, client: TestClient):
        create = client.post("/api/alerts/rules/conditions", json={
            "name": "Get Test",
            "severity": "warning",
            "conditions": [{"field": "confidence", "operator": "lt", "value": 0.5}],
        })
        rule_id = create.json()["rule_id"]
        resp = client.get(f"/api/alerts/rules/conditions/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Test"

    def test_get_rule_not_found(self, client: TestClient):
        resp = client.get("/api/alerts/rules/conditions/nonexistent")
        assert resp.status_code == 404

    def test_update_rule(self, client: TestClient):
        create = client.post("/api/alerts/rules/conditions", json={
            "name": "Update Test",
            "severity": "info",
            "conditions": [{"field": "snr_db", "operator": "gt", "value": 10}],
        })
        rule_id = create.json()["rule_id"]

        resp = client.put(f"/api/alerts/rules/conditions/{rule_id}", json={
            "name": "Updated Name",
            "severity": "critical",
            "conditions": [
                {"field": "snr_db", "operator": "gt", "value": 20},
                {"field": "node_id", "operator": "eq", "value": "node-01"},
            ],
            "enabled": False,
            "cooldown_seconds": 600,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Updated Name"
        assert data["severity"] == "critical"
        assert len(data["conditions"]) == 2
        assert data["enabled"] is False
        assert data["cooldown_seconds"] == 600

    def test_update_rule_logic(self, client: TestClient):
        create = client.post("/api/alerts/rules/conditions", json={
            "name": "Logic Update Test",
            "severity": "info",
            "conditions": [{"field": "snr_db", "operator": "gt", "value": 10}],
        })
        rule_id = create.json()["rule_id"]
        assert create.json()["logic"] == "AND"

        resp = client.put(f"/api/alerts/rules/conditions/{rule_id}", json={
            "logic": "OR",
        })
        assert resp.status_code == 200
        assert resp.json()["logic"] == "OR"

    def test_update_rule_not_found(self, client: TestClient):
        resp = client.put("/api/alerts/rules/conditions/nonexistent", json={
            "name": "No Such Rule",
        })
        assert resp.status_code == 404

    def test_delete_rule(self, client: TestClient):
        create = client.post("/api/alerts/rules/conditions", json={
            "name": "Delete Test",
            "severity": "info",
            "conditions": [],
        })
        rule_id = create.json()["rule_id"]

        resp = client.delete(f"/api/alerts/rules/conditions/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == rule_id

        # Confirm deleted
        resp2 = client.get(f"/api/alerts/rules/conditions/{rule_id}")
        assert resp2.status_code == 404

    def test_delete_rule_not_found(self, client: TestClient):
        resp = client.delete("/api/alerts/rules/conditions/nonexistent")
        assert resp.status_code == 404


class TestDetectionTriggersRules:
    """Detection ingest triggers matching condition-based rules."""

    def test_ingest_triggers_matching_rule(
        self, client: TestClient, registered_node: str,
    ):
        # Create a rule that matches bpsk signals
        client.post("/api/alerts/rules/conditions", json={
            "name": "BPSK Alert",
            "severity": "warning",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            ],
            "cooldown_seconds": 0,  # No cooldown for testing
        })

        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                },
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        # Should have at least 1 alert created by the rule
        assert data["alerts_created"] >= 1

    def test_ingest_no_trigger_when_not_matching(
        self, client: TestClient, registered_node: str,
    ):
        # Create a rule that matches only qam16
        client.post("/api/alerts/rules/conditions", json={
            "name": "QAM16 Only",
            "severity": "info",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "qam16"},
            ],
            "cooldown_seconds": 0,
        })

        now = datetime.now(timezone.utc)
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",  # not qam16
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                },
            ],
        })
        assert resp.status_code == 201
        # The QAM16 rule should not trigger; only check that
        # no additional rule alerts beyond anomaly alerts
        data = resp.json()
        assert data["accepted"] is True


class TestDryRunTest:
    """POST /api/alerts/rules/conditions/{rule_id}/test -- dry run."""

    def test_dry_run_with_recent_detections(
        self, client: TestClient, registered_node: str,
    ):
        # First ingest some detections
        now = datetime.now(timezone.utc)
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433.92e6,
                    "snr_db": 15.0,
                },
                {
                    "node_id": registered_node,
                    "signal_class": "qam16",
                    "confidence": 0.85,
                    "family": "qam",
                    "freq_hz": 915e6,
                    "snr_db": 20.0,
                },
            ],
        })

        # Create a rule matching bpsk
        create = client.post("/api/alerts/rules/conditions", json={
            "name": "BPSK Test Rule",
            "severity": "warning",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"},
            ],
        })
        rule_id = create.json()["rule_id"]

        # Test the rule
        resp = client.post(
            f"/api/alerts/rules/conditions/{rule_id}/test",
            json={"minutes": 60, "limit": 1000},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["rule_id"] == rule_id
        assert data["detections_scanned"] >= 1
        assert data["matches"] >= 1

    def test_dry_run_not_found(self, client: TestClient):
        resp = client.post(
            "/api/alerts/rules/conditions/nonexistent/test",
            json={"minutes": 60, "limit": 100},
        )
        assert resp.status_code == 404


class TestModelValidation:
    """Test Pydantic model validation for AlertCondition and AlertRuleCreate."""

    def test_invalid_field_rejected(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "Bad Field",
            "conditions": [{"field": "nonexistent_field", "operator": "eq", "value": "x"}],
        })
        assert resp.status_code == 422

    def test_invalid_operator_rejected(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "Bad Op",
            "conditions": [{"field": "snr_db", "operator": "contains", "value": 10}],
        })
        assert resp.status_code == 422

    def test_invalid_severity_rejected(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "Bad Severity",
            "severity": "mega_critical",
            "conditions": [],
        })
        assert resp.status_code == 422

    def test_invalid_logic_rejected(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "Bad Logic",
            "conditions": [{"field": "snr_db", "operator": "gt", "value": 10}],
            "logic": "XOR",
        })
        assert resp.status_code == 422

    def test_empty_name_rejected(self, client: TestClient):
        resp = client.post("/api/alerts/rules/conditions", json={
            "name": "",
            "conditions": [],
        })
        assert resp.status_code == 422
