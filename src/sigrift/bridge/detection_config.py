"""The values a detection configuration may hold.

The detection configuration (``detection_config.json``, read through
:meth:`PersistenceManager.get_detection_config`) is used on every ingest:
its thresholds are compared with anomaly scores, its counts and hours
become SQL parameters and time spans, its weights go into the live scorers
and its protocol toggles decide which detections are scored.  A value of
the wrong type there makes ingest fail after a batch's detections are
stored, so every writer that takes configuration values from outside
(``PUT /api/admin/detection-config``, ``PUT /api/admin/protocols``,
``POST /api/admin/auto-rescan``, bundle import) checks them here first
with :func:`check_detection_config`, and the reader leaves out a stored
value these rules refuse (:func:`usable_detection_config`): one an older
bridge stored, or a configuration snapshot restore brought back.
"""

from __future__ import annotations

import math
from typing import Any

from pydantic import BaseModel, Field, ValidationError


class AutoRescanConfig(BaseModel):
    """Configuration for automatic re-scan on low-confidence detections.

    Strict, like every other value of the configuration: a string, or a
    boolean where a number belongs, is refused, not converted.
    """

    model_config = {"extra": "forbid", "strict": True}

    enabled: bool = False
    confidence_threshold: float = Field(0.5, ge=0.0, le=1.0)
    max_retries: int = Field(2, ge=1, le=5)


#: Scores, thresholds and the confidence floor: a number in [0, 1].
UNIT_INTERVAL_KEYS = frozenset(
    {
        "wifi_anomaly_insert_threshold",
        "wifi_anomaly_alert_threshold",
        "wifi_anomaly_critical_threshold",
        "rf_anomaly_insert_threshold",
        "rf_anomaly_alert_threshold",
        "rf_anomaly_critical_threshold",
        "rf_min_confidence_floor",
        "wifi_auto_snooze_max_score",
        "rf_auto_snooze_max_score",
    }
)

_MAX_COUNT = 1_000_000_000
#: Ten years: "now + this many hours" is still a valid datetime.
_MAX_HOURS = 24 * 366 * 10

#: Counts and durations: a whole number in [0, limit].
INTEGER_LIMITS: dict[str, int] = {
    "wifi_anomaly_cooldown_seconds": _MAX_COUNT,
    "rf_min_learning_detections": _MAX_COUNT,
    "wifi_auto_snooze_seen_count": _MAX_COUNT,
    "rf_auto_snooze_seen_count": _MAX_COUNT,
    "wifi_auto_snooze_hours": _MAX_HOURS,
    "rf_auto_snooze_hours": _MAX_HOURS,
}

#: Dimension name -> weight, each a number in [0, 1].
WEIGHT_KEYS = frozenset({"wifi_dimension_weights", "rf_dimension_weights"})

#: Protocol name -> enabled.
PROTOCOL_KEY = "protocol_detection"

#: The objects every writer merges into the stored ones (the weights and
#: the protocol toggles).  Their bounds hold for the object as it would be
#: stored, after the merge, so merging writes cannot make one grow past
#: _MAX_ENTRIES entries.
MERGED_KEYS = WEIGHT_KEYS | {PROTOCOL_KEY}
_MAX_ENTRIES = 64
_MAX_NAME_LEN = 64
#: The weights of one weight object, as stored, sum to at most this.
_MAX_WEIGHT_SUM = 2.0

BOOLEAN_KEYS = frozenset({"iq_capture_enabled"})
AUTO_RESCAN_KEY = "auto_rescan"

KNOWN_KEYS = (
    UNIT_INTERVAL_KEYS
    | frozenset(INTEGER_LIMITS)
    | MERGED_KEYS
    | BOOLEAN_KEYS
    | {AUTO_RESCAN_KEY}
)

_MISSING = object()


class DetectionConfigError(ValueError):
    """Raised by :func:`check_detection_config`; ``problems`` lists each one."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _finite_number(value: Any) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _unit(value: Any) -> int | float | None:
    number = _finite_number(value)
    return number if number is not None and 0 <= number <= 1 else None


def _name_problem(where: str, name: Any) -> str | None:
    if not isinstance(name, str) or not name or len(name) > _MAX_NAME_LEN:
        return f"{where}: a name must be 1 to {_MAX_NAME_LEN} characters"
    return None


def _check_entries(
    key: str, value: Any, known: dict[str, Any] | None
) -> tuple[Any, list[str]]:
    """A weight object or the protocol toggles: ``(its good entries, problems)``.

    *known* (the toggles in force) restricts protocol names; ``None``
    leaves them free.  A value that is not an object, or one with more
    than _MAX_ENTRIES entries, is ``_MISSING`` as a whole.
    """
    weights = key in WEIGHT_KEYS
    if not isinstance(value, dict) or len(value) > _MAX_ENTRIES:
        what = "weights" if weights else "true / false toggles"
        return _MISSING, [f"{key}: must be an object of at most {_MAX_ENTRIES} {what}"]
    entries: dict[str, Any] = {}
    problems: list[str] = []
    for name, entry in value.items():
        problem = _name_problem(key, name)
        if problem is None and weights:
            if _unit(entry) is None:
                problem = f"{key}.{name}: must be a number from 0 to 1"
        elif problem is None:
            if known is not None and name not in known:
                problem = f"{key}.{name}: unknown protocol"
            elif not isinstance(entry, bool):
                problem = f"{key}.{name}: must be true or false"
        if problem is not None:
            problems.append(problem)
        else:
            entries[name] = entry
    return entries, problems


def _check_value(
    key: str,
    value: Any,
    current: dict[str, Any] | None,
    known: dict[str, Any] | None,
    allow_unknown: bool,
) -> tuple[Any, list[str]]:
    """One key: ``(its checked value, or _MISSING, and its problems)``."""
    if key in UNIT_INTERVAL_KEYS:
        number = _unit(value)
        if number is None:
            return _MISSING, [f"{key}: must be a number from 0 to 1"]
        return number, []
    if key in INTEGER_LIMITS:
        number = _finite_number(value)
        if isinstance(number, float) and number.is_integer():
            number = int(number)
        limit = INTEGER_LIMITS[key]
        if not isinstance(number, int) or not 0 <= number <= limit:
            return _MISSING, [f"{key}: must be a whole number from 0 to {limit}"]
        return number, []
    if key in MERGED_KEYS:
        return _check_entries(key, value, known if key == PROTOCOL_KEY else None)
    if key in BOOLEAN_KEYS:
        if not isinstance(value, bool):
            return _MISSING, [f"{key}: must be true or false"]
        return value, []
    if key == AUTO_RESCAN_KEY:
        try:
            return AutoRescanConfig.model_validate(value).model_dump(), []
        except ValidationError:
            return _MISSING, [
                f"{key}: must be an object of enabled (true / false), "
                "confidence_threshold (a number from 0 to 1) and max_retries "
                "(a whole number from 1 to 5)"
            ]
    if allow_unknown or (current is not None and current.get(key, _MISSING) == value):
        return value, []
    return _MISSING, [f"{key}: unknown setting"]


def _bounds_problems(key: str, entries: dict[str, Any], merged: bool) -> list[str]:
    """The bounds of one whole weight object, or the toggles, as stored."""
    problems: list[str] = []
    if len(entries) > _MAX_ENTRIES:
        problems.append(
            f"{key}: at most {_MAX_ENTRIES} entries in all, and with the ones "
            f"already stored there would be {len(entries)}"
        )
    if key in WEIGHT_KEYS:
        # The stored weights the reader returns are each in [0, 1]; anything
        # else (a caller's own *current*) cannot be summed and is not counted.
        total = math.fsum(w for w in entries.values() if _unit(w) is not None)
        if total > _MAX_WEIGHT_SUM:
            stored = " with the ones already stored" if merged else ""
            problems.append(
                f"{key}: the weights must sum to at most {_MAX_WEIGHT_SUM}, "
                f"and{stored} they would sum to {total:.2f}"
            )
    return problems


def check_detection_config(
    values: Any,
    current: dict[str, Any] | None = None,
    *,
    allow_unknown: bool = False,
) -> dict[str, Any]:
    """Return *values* checked and normalised, or raise :class:`DetectionConfigError`.

    Thresholds and scores must be numbers in [0, 1]; counts and durations
    whole numbers in [0, limit] (returned as ``int``); weights objects of
    numbers in [0, 1]; protocol toggles objects of booleans; ``auto_rescan``
    the ``POST /api/admin/auto-rescan`` body (:class:`AutoRescanConfig`).
    Booleans, strings, ``null``, NaN and infinities are not numbers.  A
    weight object and the protocol toggles hold at most 64 entries, each
    named by 1 to 64 characters, and one object's weights sum to at most
    2.0.

    *current* is the configuration in force.  The weights and protocol
    toggles merge into its objects (as every writer stores them), so their
    bounds are checked on the merged object.  Unless *allow_unknown*,
    *current* also restricts protocol toggles to the protocols it lists,
    and a key the bridge does not know is refused unless it is sent with
    the value *current* already holds, so a configuration read from
    ``GET`` can always be sent back.  *allow_unknown* (a bundle, which may
    come from another version) keeps unknown keys and protocol names.
    """
    if not isinstance(values, dict):
        raise DetectionConfigError(["the configuration must be an object"])
    known: dict[str, Any] | None = None
    if current is not None and not allow_unknown:
        in_force = current.get(PROTOCOL_KEY)
        known = in_force if isinstance(in_force, dict) else {}
    problems: list[str] = []
    checked: dict[str, Any] = {}
    for key, value in values.items():
        result, found = _check_value(key, value, current, known, allow_unknown)
        if found:
            problems.extend(found)
            continue
        checked[key] = result
        if key in MERGED_KEYS:
            stored = (current or {}).get(key)
            merged = isinstance(stored, dict)
            entries = {**stored, **result} if merged else result
            problems.extend(_bounds_problems(key, entries, merged))
    if problems:
        raise DetectionConfigError(problems)
    return checked


def usable_detection_config(values: Any) -> tuple[dict[str, Any], list[str]]:
    """``(the stored values the rules accept, a problem per value left out)``.

    For the reader: a stored configuration may hold a value an older bridge
    stored, or a configuration snapshot restore brought back, that the
    rules refuse.  Such a value is left out, so its default applies: a key
    as a whole, or one weight or protocol toggle of an object (the rest of
    the object is kept).  The rules are :func:`check_detection_config`'s
    for each value, with unknown keys and protocol names kept; the bounds
    of a whole object (its entries once merged, its weights' sum) are the
    writers' to keep.
    """
    if not isinstance(values, dict):
        return {}, ["the configuration must be an object"]
    usable: dict[str, Any] = {}
    problems: list[str] = []
    for key, value in values.items():
        result, found = _check_value(key, value, None, None, True)
        problems.extend(found)
        if result is not _MISSING:
            usable[key] = result
    return usable, problems
