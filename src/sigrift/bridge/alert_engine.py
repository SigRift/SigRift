"""Alert rule condition evaluation engine for The Bridge.

Evaluates detection records against user-defined alert rules with
multi-condition AND/OR logic, cooldown tracking, and optional webhook
notification.

Usage (function API -- backward compatible):
    from sigrift.bridge.alert_engine import evaluate_detection

    triggered = evaluate_detection(detection_dict, rules, cooldowns, now)

Usage (class API -- with notifications and audit):
    from sigrift.bridge.alert_engine import AlertEngine

    engine = AlertEngine(cooldowns=app_state.rule_cooldowns)
    triggered = engine.evaluate(detection_dict, rules)
"""

from __future__ import annotations

import html
import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)


_HTML_TEXT_ENTITIES = {
    "&amp;": "&",
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&#x27;": "'",
}


def decode_html_escaped_text(value: str) -> str:
    """Decode one layer only for a known html.escape-encoded text field.

    Re-escape when composing HTML-encoded messages; this is not safe HTML.
    Literal entity text and ambiguous legacy layers must not be decoded again.
    """
    return re.sub(
        r"&(?:amp|lt|gt|quot|#x27);",
        lambda match: _HTML_TEXT_ENTITIES[match.group()],
        value,
    )


# ---------------------------------------------------------------------------
# Valid fields and operators
# ---------------------------------------------------------------------------

VALID_FIELDS = frozenset(
    {
        "signal_class",
        "freq_hz",
        "snr_db",
        "power_dbm",
        "anomaly_score",
        "node_id",
        "family",
        "bandwidth_hz",
        "confidence",
    }
)

VALID_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "between",
    }
)


# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------


def _get_field(detection: dict[str, Any], field: str) -> Any:
    """Extract a field value from a detection dict."""
    return detection.get(field)


def _evaluate_condition(
    detection: dict[str, Any],
    condition: dict[str, Any],
) -> bool:
    """Evaluate a single condition against a detection.

    Returns True if the condition matches.
    """
    field = condition.get("field", "")
    operator = condition.get("operator", "")
    value = condition.get("value")

    if field not in VALID_FIELDS or operator not in VALID_OPERATORS:
        return False

    det_value = _get_field(detection, field)
    if det_value is None:
        # Field not present on detection -- condition cannot match
        return False

    try:
        if operator == "eq":
            return det_value == value
        elif operator == "ne":
            return det_value != value
        elif operator == "gt":
            return float(det_value) > float(value)
        elif operator == "gte":
            return float(det_value) >= float(value)
        elif operator == "lt":
            return float(det_value) < float(value)
        elif operator == "lte":
            return float(det_value) <= float(value)
        elif operator == "in":
            if not isinstance(value, list):
                return False
            return det_value in value
        elif operator == "not_in":
            if not isinstance(value, list):
                return True
            return det_value not in value
        elif operator == "between":
            if not isinstance(value, list) or len(value) != 2:
                return False
            lo, hi = float(value[0]), float(value[1])
            return lo <= float(det_value) <= hi
    except (TypeError, ValueError):
        return False

    return False


def evaluate_rule(
    detection: dict[str, Any],
    rule: dict[str, Any],
) -> bool:
    """Check if a detection matches the conditions of a rule.

    Supports AND (all conditions must match) and OR (any condition must
    match) logic controlled by the ``logic`` field on the rule.
    Defaults to AND when ``logic`` is not set.

    An enabled rule with no conditions never auto-triggers.
    """
    if not rule.get("enabled", True):
        return False

    conditions = rule.get("conditions", [])
    if not conditions:
        # A rule with no conditions never auto-triggers on detections
        return False

    logic = rule.get("logic", "AND").upper()
    if logic == "OR":
        return any(_evaluate_condition(detection, c) for c in conditions)
    return all(_evaluate_condition(detection, c) for c in conditions)


def evaluate_detection(
    detection: dict[str, Any],
    rules: list[dict[str, Any]],
    cooldowns: dict[str, float] | None = None,
    now: float | None = None,
) -> list[dict[str, Any]]:
    """Evaluate a detection against all enabled rules.

    Parameters
    ----------
    detection : dict
        A detection record as a dict with fields like signal_class,
        freq_hz, snr_db, etc.
    rules : list[dict]
        List of alert rule dicts, each with conditions, cooldown_seconds,
        enabled flag, etc.
    cooldowns : dict[str, float] or None
        Mutable dict tracking last trigger time (monotonic) per rule_id.
        Updated in place when a rule triggers.
    now : float or None
        Current monotonic timestamp.  Defaults to time.monotonic().

    Returns
    -------
    list[dict]
        List of rule dicts that were triggered (passed all conditions
        and are not within cooldown).
    """
    if cooldowns is None:
        cooldowns = {}
    if now is None:
        now = time.monotonic()

    triggered: list[dict[str, Any]] = []

    for rule in rules:
        if not rule.get("enabled", True):
            continue

        rule_id = rule.get("rule_id", rule.get("alert_id", ""))
        if not rule_id:
            continue

        # Check cooldown. Critically: a rule with no entry in `cooldowns`
        # has *never* been triggered, so it's eligible regardless of how
        # large `cooldown_seconds` is. The previous `.get(rule_id, 0.0)`
        # implementation treated absence as "triggered at monotonic 0",
        # which suppressed a rule's *first* match in any process where
        # time.monotonic() < cooldown_seconds (≈ first 5 minutes after
        # process start with the default 300s cooldown). Production
        # bridges that took an early detection saw real first-fire
        # losses; xdist workers see it deterministically.
        cooldown_seconds = rule.get("cooldown_seconds", 300)
        if rule_id in cooldowns:
            last_trigger = cooldowns[rule_id]
            if now - last_trigger < cooldown_seconds:
                continue

        # Evaluate conditions
        if evaluate_rule(detection, rule):
            cooldowns[rule_id] = now
            triggered.append(rule)

    return triggered


# ---------------------------------------------------------------------------
# Class-based engine with notification + audit integration
# ---------------------------------------------------------------------------


class AlertEngine:
    """Stateful alert evaluation engine with cooldown, notification, and audit.

    Wraps the module-level evaluation functions and adds:
    - Per-rule cooldown via a shared ``cooldowns`` dict (typically
      ``app_state.rule_cooldowns``)
    - Optional webhook delivery via ``NotificationManager``
    - Optional audit trail logging via a callable
    """

    def __init__(
        self,
        cooldowns: dict[str, float] | None = None,
        audit_log: Any | None = None,
    ) -> None:
        self._cooldowns: dict[str, float] = cooldowns if cooldowns is not None else {}
        self._audit_log = audit_log  # callable(action=, target_id=, details=)

    def _check_condition(
        self,
        detection: dict[str, Any],
        condition: dict[str, Any],
    ) -> bool:
        """Evaluate a single condition against a detection dict."""
        return _evaluate_condition(detection, condition)

    def evaluate(
        self,
        detection: dict[str, Any],
        rules: list[dict[str, Any]],
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate a detection against all rules, respecting cooldowns.

        Returns a list of result dicts for each triggered rule::

            {
                "rule_id": str,
                "rule_name": str,
                "severity": str,
                "matched_conditions": list[dict],
                "detection_summary": str,
            }
        """
        if now is None:
            now = time.monotonic()

        results: list[dict[str, Any]] = []

        for rule in rules:
            if not rule.get("enabled", True):
                continue

            rule_id = rule.get("rule_id", rule.get("alert_id", ""))
            if not rule_id:
                continue

            # Cooldown check.  A rule absent from the cooldowns has never
            # triggered (see evaluate_detection): treating absence as
            # "triggered at monotonic 0" suppressed first matches while
            # time.monotonic() < cooldown_seconds (early after boot).
            cooldown_seconds = rule.get("cooldown_seconds", 300)
            if rule_id in self._cooldowns:
                if now - self._cooldowns[rule_id] < cooldown_seconds:
                    continue

            if not evaluate_rule(detection, rule):
                continue

            # Collect matched conditions for the result summary
            conditions = rule.get("conditions", [])
            logic = rule.get("logic", "AND").upper()
            matched: list[dict[str, Any]] = [
                c for c in conditions if self._check_condition(detection, c)
            ]

            # Record cooldown
            self._cooldowns[rule_id] = now

            rule_name = rule.get("name", rule_id)
            severity = rule.get("severity", "warning")

            # Build condition summary
            cond_parts = []
            for c in matched:
                cond_parts.append(
                    f"{c.get('field')} {c.get('operator')} {c.get('value')}"
                )
            cond_str = f" {logic} ".join(cond_parts) if cond_parts else "no conditions"

            node_id = detection.get("node_id", "unknown")
            sig_class = detection.get("signal_class", "unknown")
            freq_mhz = detection.get("freq_hz", 0.0) / 1e6

            det_summary = (
                f"Rule '{decode_html_escaped_text(rule_name)}' triggered on {node_id}: "
                f"{sig_class} at {freq_mhz:.2f} MHz ({cond_str})"
            )

            result = {
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "matched_conditions": matched,
                "detection_summary": html.escape(det_summary),
            }
            results.append(result)

            # Flag whether caller should send webhook
            result["notify_webhook"] = rule.get("notify_webhook", True)

            logger.info(
                "Alert rule %s triggered: %s",
                rule_id,
                det_summary,
            )

            # Audit trail
            if self._audit_log is not None:
                try:
                    self._audit_log(
                        action="alert_rule_triggered",
                        target_id=rule_id,
                        details={
                            "rule_name": rule_name,
                            "severity": severity,
                            "node_id": node_id,
                            "signal_class": sig_class,
                            "matched_conditions": len(matched),
                        },
                    )
                except Exception:
                    logger.warning("Failed to write audit log for rule %s", rule_id)

        return results


# ---------------------------------------------------------------------------
# Watch band evaluation
# ---------------------------------------------------------------------------


def evaluate_watch_bands(
    detection: dict[str, Any],
    watch_bands: list[dict[str, Any]],
    cooldowns: dict[str, float],
    band_counts: dict[str, list[tuple[float, str]]],
    now: float | None = None,
) -> list[dict[str, Any]]:
    """Evaluate a detection against all enabled watch bands.

    Parameters
    ----------
    detection : dict
        Detection record with at least ``freq_hz`` and ``power_dbm``.
    watch_bands : list[dict]
        List of watch band dicts from persistence.
    cooldowns : dict[str, float]
        Mutable dict tracking last trigger time per watch_id.
    band_counts : dict[str, list]
        Mutable dict tracking recent detection timestamps per watch_id
        for count_threshold triggers.
    now : float or None
        Current monotonic timestamp.

    Returns
    -------
    list[dict]
        List of watch band dicts that triggered.
    """
    if now is None:
        now = time.monotonic()

    freq_hz = detection.get("freq_hz") or 0.0
    power_dbm = detection.get("power_dbm")

    triggered: list[dict[str, Any]] = []

    for band in watch_bands:
        if not band.get("enabled", True):
            continue

        watch_id = band.get("watch_id", "")
        if not watch_id:
            continue

        # Check frequency is within the watched band (a band with unusable
        # bounds never matches instead of breaking evaluation)
        try:
            freq_min = float(band.get("freq_min_hz") or 0.0)
            freq_max = float(band.get("freq_max_hz") or 0.0)
            in_band = freq_min <= float(freq_hz) <= freq_max
        except (TypeError, ValueError):
            continue
        if not in_band:
            continue

        # Check cooldown (a band absent from the cooldowns never fired;
        # see evaluate_detection for why absence must not mean "at 0").
        cooldown_seconds = band.get("cooldown_seconds", 300)
        if watch_id in cooldowns:
            if now - cooldowns[watch_id] < cooldown_seconds:
                continue

        trigger_type = band.get("trigger", "new_activity")

        if trigger_type == "new_activity":
            # Any detection in band triggers
            cooldowns[watch_id] = now
            triggered.append(band)

        elif trigger_type == "power_threshold":
            threshold = band.get("power_threshold_dbm")
            if threshold is not None and power_dbm is not None:
                try:
                    over = float(power_dbm) >= float(threshold)
                except (TypeError, ValueError):
                    over = False
                if over:
                    cooldowns[watch_id] = now
                    triggered.append(band)

        elif trigger_type == "count_threshold":
            count_threshold = band.get("count_threshold")
            time_window = band.get("time_window_seconds", 300)

            if not isinstance(time_window, (int, float)):
                time_window = 300
            if isinstance(count_threshold, (int, float)):
                # Add current detection to count tracking
                if watch_id not in band_counts:
                    band_counts[watch_id] = []

                det_id = detection.get("detection_id", "")
                band_counts[watch_id].append((now, det_id))

                # Prune old entries outside the time window
                cutoff = now - time_window
                band_counts[watch_id] = [
                    entry for entry in band_counts[watch_id] if entry[0] >= cutoff
                ]

                if len(band_counts[watch_id]) >= count_threshold:
                    cooldowns[watch_id] = now
                    band_counts[watch_id] = []  # Reset after trigger
                    triggered.append(band)

    return triggered


def build_watch_band_alert(
    band: dict[str, Any],
    detection: dict[str, Any],
    alert_id: str,
    triggered_at: str,
) -> dict[str, Any]:
    """Build the alert record for a triggered watch band."""
    watch_id = band.get("watch_id", "")
    band_name = band.get("name") or watch_id
    node_id = detection.get("node_id", "unknown")
    freq_mhz = (detection.get("freq_hz") or 0.0) / 1e6
    trigger_type = band.get("trigger", "new_activity")
    return {
        "alert_id": alert_id,
        "name": f"watch_band_{band_name}",
        "severity": band.get("severity", "warning"),
        "message": html.escape(
            f"Watch band '{band_name}' ({trigger_type}) triggered on {node_id}: "
            f"{detection.get('signal_class', 'unknown')} at {freq_mhz:.3f} MHz"
        ),
        "node_id": node_id,
        "triggered_at": triggered_at,
        "acknowledged": False,
        "acknowledged_at": None,
        "watch_id": watch_id,
        "detection_id": detection.get("detection_id", ""),
        "freq_hz": detection.get("freq_hz"),
        "power_dbm": detection.get("power_dbm"),
    }


# ---------------------------------------------------------------------------
# Default alert rules — seeded on first startup if no rules exist
# ---------------------------------------------------------------------------

import uuid  # noqa: E402


def seed_default_rules(persistence: Any) -> int:
    """Create default high-sensitivity alert rules if none exist.

    Returns the number of rules created (0 if rules already exist).
    Called at application startup.
    """
    existing = persistence.get_alert_rules()
    # Check if defaults already seeded (look for is_default flag)
    has_defaults = any(r.get("is_default") for r in existing)
    if has_defaults:
        return 0

    now_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime())
    defaults = [
        {
            "name": "Novel Signal Detected",
            "severity": "warning",
            "conditions": [
                {"field": "family", "operator": "eq", "value": "UNKNOWN"},
                {"field": "anomaly_score", "operator": "gte", "value": 0.3},
            ],
            "logic": "AND",
            "cooldown_seconds": 120,
        },
        {
            "name": "High Power Anomaly",
            "severity": "critical",
            "conditions": [
                {"field": "power_dbm", "operator": "gt", "value": -20},
            ],
            "logic": "AND",
            "cooldown_seconds": 60,
        },
        {
            "name": "GPS Jammer Detected",
            "severity": "critical",
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "gps-jammer"},
            ],
            "logic": "AND",
            "cooldown_seconds": 30,
        },
        {
            "name": "Drone Signal Detected",
            "severity": "warning",
            "conditions": [
                {
                    "field": "signal_class",
                    "operator": "in",
                    "value": ["dji-ofdm", "elrs", "fpv-analog"],
                },
            ],
            "logic": "OR",
            "cooldown_seconds": 120,
        },
        {
            "name": "Rare Frequency Activity",
            "severity": "warning",
            "conditions": [
                {"field": "anomaly_score", "operator": "gte", "value": 0.5},
            ],
            "logic": "AND",
            "cooldown_seconds": 300,
        },
        {
            "name": "Mesh Network Detected",
            "severity": "info",
            "conditions": [
                {
                    "field": "signal_class",
                    "operator": "in",
                    "value": ["lora-css", "oqpsk-dsss", "sidewalk"],
                },
            ],
            "logic": "OR",
            "cooldown_seconds": 600,
        },
        {
            "name": "Trunked Radio Activity",
            "severity": "info",
            "conditions": [
                {
                    "field": "signal_class",
                    "operator": "in",
                    "value": ["p25", "dmr", "tetra"],
                },
            ],
            "logic": "OR",
            "cooldown_seconds": 600,
        },
    ]

    for rule_def in defaults:
        rule_dict = {
            "rule_id": f"rule_{uuid.uuid4().hex[:12]}",
            "name": rule_def["name"],
            "severity": rule_def["severity"],
            "conditions": rule_def["conditions"],
            "logic": rule_def["logic"],
            "enabled": True,
            "cooldown_seconds": rule_def["cooldown_seconds"],
            "notify_webhook": True,
            "created_at": now_iso,
            "last_triggered_at": None,
            "trigger_count": 0,
            "is_default": True,
        }
        persistence.add_alert_rule(rule_dict)

    count = len(defaults)
    logger.info("Seeded %d default alert rules", count)
    return count
