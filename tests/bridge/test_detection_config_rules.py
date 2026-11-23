"""The value rules of ``sigrift.bridge.detection_config``.

``check_detection_config`` is shared by ``PUT /api/admin/detection-config``
and bundle validation / apply; the API and bundle tests cover those
callers, these the rules themselves.
"""

from __future__ import annotations

import copy
import functools
import math
import operator

import pytest

from sigrift.bridge import detection_config as rules
from sigrift.bridge.persistence import PersistenceManager


def _defaults() -> dict:
    return copy.deepcopy(PersistenceManager._DETECTION_CONFIG_DEFAULTS)


def test_every_factory_default_has_a_rule_and_passes_it():
    defaults = _defaults()
    assert set(defaults) <= rules.KNOWN_KEYS
    assert rules.check_detection_config(defaults, defaults) == defaults
    assert rules.check_detection_config(defaults) == defaults


@pytest.mark.parametrize("key", sorted(rules.UNIT_INTERVAL_KEYS))
@pytest.mark.parametrize(
    "value", ["0.5", None, True, False, -0.01, 1.01, math.nan, math.inf, [0.5]]
)
def test_unit_interval_values(key, value):
    with pytest.raises(rules.DetectionConfigError, match=key):
        rules.check_detection_config({key: value})


@pytest.mark.parametrize("key", sorted(rules.UNIT_INTERVAL_KEYS))
def test_unit_interval_bounds_are_inclusive(key):
    assert rules.check_detection_config({key: 0}) == {key: 0}
    assert rules.check_detection_config({key: 1.0}) == {key: 1.0}


@pytest.mark.parametrize("key", sorted(rules.INTEGER_LIMITS))
def test_integer_values(key):
    limit = rules.INTEGER_LIMITS[key]
    assert rules.check_detection_config({key: 0}) == {key: 0}
    checked = rules.check_detection_config({key: float(limit)})
    assert checked == {key: limit} and type(checked[key]) is int
    for bad in (-1, limit + 1, 1.5, "1", None, True, math.nan, math.inf):
        with pytest.raises(rules.DetectionConfigError, match=key):
            rules.check_detection_config({key: bad})


def test_hours_stay_within_the_datetime_range():
    from datetime import datetime, timedelta, timezone

    for key in ("rf_auto_snooze_hours", "wifi_auto_snooze_hours"):
        hours = rules.INTEGER_LIMITS[key]
        datetime.now(timezone.utc) + timedelta(hours=hours)  # no OverflowError


@pytest.mark.parametrize("key", sorted(rules.WEIGHT_KEYS))
def test_weight_values(key):
    weights = {"a": 0, "b": 0.5, "c": 1}
    assert rules.check_detection_config({key: weights}) == {key: weights}
    too_many = {f"w{i}": 0.01 for i in range(65)}
    for bad in (0.5, None, [0.5], too_many, {"": 0.1}, {"x" * 65: 0.1}):
        with pytest.raises(rules.DetectionConfigError, match=key):
            rules.check_detection_config({key: bad})
    for weight in ("0.5", None, True, -0.1, 1.1, math.nan, {"x": 1}):
        with pytest.raises(rules.DetectionConfigError, match=f"{key}.a"):
            rules.check_detection_config({key: {"a": weight}})
    # The bounds are inclusive: 64 weights, 64-character names.
    most = {f"w{i}": 0.01 for i in range(64)}
    assert rules.check_detection_config({key: most}) == {key: most}
    longest = {"x" * 64: 0.1}
    assert rules.check_detection_config({key: longest}) == {key: longest}


@pytest.mark.parametrize("key", sorted(rules.WEIGHT_KEYS))
def test_weights_sum_to_at_most_two(key):
    # Inclusive, and summed exactly (math.fsum): these six weights sum to
    # exactly 2.0, but adding them left to right, as Python 3.11's sum()
    # does, rounds up to 2.0000000000000004.
    u, w = 2.0**-52, 2.0**-53 + 2.0**-60
    exact = [1.0, 1.0 - 4 * u, w, w, w, 637 * 2.0**-60]
    assert math.fsum(exact) == 2.0
    assert functools.reduce(operator.add, exact) > 2.0
    for weights in (
        {"a": 1, "b": 1.0},
        {f"w{i}": 0.1 for i in range(20)},
        {f"x{i}": weight for i, weight in enumerate(exact)},
    ):
        assert rules.check_detection_config({key: weights}) == {key: weights}
    with pytest.raises(rules.DetectionConfigError, match="would sum to 2.01"):
        rules.check_detection_config({key: {"a": 1, "b": 1, "c": 0.01}})


def test_bounds_hold_for_the_object_as_stored():
    # Weights and toggles merge into the stored ones: the entry count and
    # the weights' sum are those of the merged object.
    current = {
        "rf_dimension_weights": {f"d{i}": 0.02 for i in range(14)},
        "protocol_detection": {"adsb": True},
    }
    fits = {"rf_dimension_weights": {f"n{i}": 0.0 for i in range(50)}}
    assert rules.check_detection_config(fits, current) == fits
    over = {"rf_dimension_weights": {f"n{i}": 0.0 for i in range(51)}}
    with pytest.raises(rules.DetectionConfigError) as caught:
        rules.check_detection_config(over, current)
    assert caught.value.problems == [
        "rf_dimension_weights: at most 64 entries in all, and with the ones "
        "already stored there would be 65"
    ]
    # Replacing a stored weight counts it once.
    renamed = {"rf_dimension_weights": {"d0": 0.0, **over["rf_dimension_weights"]}}
    del renamed["rf_dimension_weights"]["n50"]
    assert rules.check_detection_config(renamed, current) == renamed
    # 13 * 0.02 + 1.0 + 0.75 = 2.01 > 2.0; replacing d0 with 0.74 gives 2.0.
    heavy = {"rf_dimension_weights": {"d0": 1.0, "n": 0.75}}
    with pytest.raises(rules.DetectionConfigError, match="already stored they would"):
        rules.check_detection_config(heavy, current)
    heavy["rf_dimension_weights"]["n"] = 0.74
    assert rules.check_detection_config(heavy, current) == heavy
    # Without stored weights (a bundle on its own) only the object counts.
    assert rules.check_detection_config(heavy) == heavy


def test_protocol_toggle_bounds():
    most = {f"p{i}": True for i in range(64)}
    assert rules.check_detection_config({"protocol_detection": most}) == {
        "protocol_detection": most
    }
    with pytest.raises(rules.DetectionConfigError, match="at most 64 true / false"):
        rules.check_detection_config(
            {"protocol_detection": {**most, "one_more": False}}
        )
    # Merged (a bundle, whose protocol names are free): the stored count.
    current = {"protocol_detection": {f"s{i}": True for i in range(60)}}
    new = {"protocol_detection": {f"n{i}": False for i in range(4)}}
    assert rules.check_detection_config(new, current, allow_unknown=True) == new
    new["protocol_detection"]["n4"] = False
    with pytest.raises(rules.DetectionConfigError, match="there would be 65"):
        rules.check_detection_config(new, current, allow_unknown=True)


def test_protocol_toggles():
    current = {"protocol_detection": {"adsb": True, "dect": True}}
    toggles = {"protocol_detection": {"adsb": False}}
    assert rules.check_detection_config(toggles, current) == toggles
    for bad in ("false", 0, 1, None):
        with pytest.raises(rules.DetectionConfigError, match="protocol_detection.adsb"):
            rules.check_detection_config({"protocol_detection": {"adsb": bad}})
    # Known protocols only when the configuration in force is given.
    unknown = {"protocol_detection": {"bpsk": False}}
    with pytest.raises(rules.DetectionConfigError, match="unknown protocol"):
        rules.check_detection_config(unknown, current)
    assert rules.check_detection_config(unknown) == unknown
    # ... and free again for a bundle (allow_unknown), stored ones or not.
    assert rules.check_detection_config(unknown, current, allow_unknown=True) == unknown
    with pytest.raises(rules.DetectionConfigError, match="protocol_detection"):
        rules.check_detection_config({"protocol_detection": ["adsb"]}, current)


def test_auto_rescan_and_booleans():
    checked = rules.check_detection_config({"auto_rescan": {"enabled": True}})
    assert checked == {
        "auto_rescan": {"enabled": True, "confidence_threshold": 0.5, "max_retries": 2}
    }
    checked = rules.check_detection_config({"auto_rescan": {"confidence_threshold": 1}})
    assert checked["auto_rescan"]["confidence_threshold"] == 1.0
    for bad in (
        True,
        None,
        {"max_retries": 6},
        {"confidence_threshold": 2},
        {"x": 1},
        # Strict: strings and booleans are not converted.
        {"enabled": "false"},
        {"enabled": 0},
        {"confidence_threshold": "0.4"},
        {"confidence_threshold": True},
        {"max_retries": True},
        {"max_retries": "2"},
    ):
        with pytest.raises(rules.DetectionConfigError, match="auto_rescan"):
            rules.check_detection_config({"auto_rescan": bad})
    assert rules.check_detection_config({"iq_capture_enabled": False}) == {
        "iq_capture_enabled": False
    }
    for bad in (1, "true", None):
        with pytest.raises(rules.DetectionConfigError, match="iq_capture_enabled"):
            rules.check_detection_config({"iq_capture_enabled": bad})


def test_unknown_keys():
    with pytest.raises(rules.DetectionConfigError, match="mystery: unknown setting"):
        rules.check_detection_config({"mystery": 1})
    # Kept with allow_unknown (bundles), or when sent back unchanged.
    assert rules.check_detection_config({"mystery": 1}, allow_unknown=True) == {
        "mystery": 1
    }
    current = {"mystery": {"x": 1}}
    assert rules.check_detection_config({"mystery": {"x": 1}}, current) == current
    with pytest.raises(rules.DetectionConfigError, match="mystery"):
        rules.check_detection_config({"mystery": {"x": 2}}, current)
    with pytest.raises(rules.DetectionConfigError, match="mystery"):
        rules.check_detection_config({"mystery": None}, current)


def test_every_problem_is_listed_and_nothing_else_is_returned():
    with pytest.raises(rules.DetectionConfigError) as caught:
        rules.check_detection_config(
            {
                "rf_anomaly_insert_threshold": "abc",
                "rf_anomaly_alert_threshold": 0.5,
                "rf_auto_snooze_hours": -1,
            }
        )
    assert [p.split(":")[0] for p in caught.value.problems] == [
        "rf_anomaly_insert_threshold",
        "rf_auto_snooze_hours",
    ]
    assert str(caught.value) == "; ".join(caught.value.problems)


@pytest.mark.parametrize("values", [None, [], "config", 1])
def test_the_configuration_must_be_an_object(values):
    with pytest.raises(rules.DetectionConfigError, match="must be an object"):
        rules.check_detection_config(values)
    assert rules.usable_detection_config(values) == (
        {},
        ["the configuration must be an object"],
    )


def test_usable_detection_config_leaves_out_only_what_the_rules_refuse():
    # The reader's view of a stored configuration: each refused value is
    # left out (one weight or toggle of an object, else the whole key), and
    # what the rules accept is kept, normalised.
    stored = {
        "rf_anomaly_insert_threshold": "0.4",
        "rf_anomaly_alert_threshold": 0.6,
        "rf_auto_snooze_seen_count": 120.0,
        "rf_auto_snooze_hours": 0.5,
        "rf_dimension_weights": {"snr_zscore": "abc", "novel_class": 0.3},
        "wifi_dimension_weights": {f"w{i}": 0.0 for i in range(65)},
        "protocol_detection": {"adsb": "false", "dect": False, "future": True},
        "auto_rescan": {"enabled": "false"},
        "iq_capture_enabled": "yes",
        "legacy_setting": {"x": 1},
    }
    usable, problems = rules.usable_detection_config(stored)
    assert usable == {
        "rf_anomaly_alert_threshold": 0.6,
        "rf_auto_snooze_seen_count": 120,
        "rf_dimension_weights": {"novel_class": 0.3},
        "protocol_detection": {"dect": False, "future": True},
        "legacy_setting": {"x": 1},
    }
    assert type(usable["rf_auto_snooze_seen_count"]) is int
    assert [p.split(":")[0] for p in problems] == [
        "rf_anomaly_insert_threshold",
        "rf_auto_snooze_hours",
        "rf_dimension_weights.snr_zscore",
        "wifi_dimension_weights",
        "protocol_detection.adsb",
        "auto_rescan",
        "iq_capture_enabled",
    ]
    # The bounds of a whole object are the writers' to keep: the reader
    # does not drop weights a user set that sum past 2.0.
    heavy = {"wifi_dimension_weights": {"a": 1.0, "b": 1.0, "c": 1.0}}
    assert rules.usable_detection_config(heavy) == (heavy, [])
    defaults = _defaults()
    assert rules.usable_detection_config(defaults) == (defaults, [])
