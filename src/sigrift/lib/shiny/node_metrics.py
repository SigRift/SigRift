"""Heartbeat metrics: what a node may report, and how stored values are read.

A node record (``persistence.get_nodes()[node_id]``) mixes what an admin
registered (``host``, ``port``, ``capabilities``), what the server stamps
(``registered_at``, ``last_seen``) and what the node's heartbeat reports.
``NodeMetrics`` accepts extra fields so that older agents keep working, so a
heartbeat can carry any name with any value.  Only the metrics in
:data:`METRICS` are stored, each only when its value has the expected type
and range.  Every other name is ignored, so a heartbeat never rewrites the
rest of the record (``last_seen``, ``host``, ``port``, ``registered_at``,
...); of ``capabilities`` it updates only the monitor fields of
:data:`CAPABILITY_METRICS`.  A known metric with a bad value is cleared
rather than refused (in ``capabilities`` too): the heartbeat still counts as
contact and still collects the node's queued commands, and the stale value
is not shown as current.

Records saved before this check (or edited by hand) can still hold anything,
so readers use :func:`stored_metric`, :func:`stored_capabilities`,
:func:`parse_timestamp`, :func:`stored_node_fields` and :func:`stored_port`,
which read a bad value as absent instead of failing.

Shared by the bridge (``sigrift.bridge.routers.nodes``) and the Shiny
dashboard (``sigrift.lib.shiny.routers.nodes``), so both apply one rule.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from sigrift.lib.shiny.models import NodeStatus

#: Longest text metric stored (agent version, OS, platform, hardware, ...).
MAX_TEXT_LENGTH = 256

#: How far ahead of this server's clock a stored ``last_seen`` may be and
#: still count (the clock was stepped back).  The server stamps last_seen
#: itself, so a later one is not a time it wrote: the status is unknown.
CLOCK_SKEW_SECONDS = 60.0

#: A metric check returns the value to store, or None when it is not valid.
Check = Callable[[Any], Any]


def _number(
    low: float | None = None, high: float | None = None, *, integer: bool = False
) -> Check:
    """A check for a finite JSON number in ``[low, high]`` (never a bool)."""

    def check(value: Any) -> int | float | None:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None
        try:
            as_float = float(value)
        except OverflowError:  # an integer too large for a float
            return None
        if not math.isfinite(as_float):
            return None
        if (low is not None and as_float < low) or (
            high is not None and as_float > high
        ):
            return None
        if integer:
            return int(as_float) if as_float.is_integer() else None
        return value

    return check


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and len(value) <= MAX_TEXT_LENGTH else None


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _status(value: Any) -> str | None:
    try:
        return NodeStatus(value).value
    except (TypeError, ValueError):
        return None


_PERCENT = _number(0.0, 100.0)
_NON_NEGATIVE = _number(0.0)
_COUNT = _number(0, integer=True)
_TEMPERATURE = _number(-100.0, 200.0)  # degrees Celsius
_TEMPERATURE_TEXT = re.compile(r"-?[0-9]{1,3}°C")


def _gpu_temperature(value: Any) -> int | float | str | None:
    """A number, or the ``"91°C"`` text some GPU tools report."""
    if isinstance(value, str):
        if (
            _TEMPERATURE_TEXT.fullmatch(value)
            and _TEMPERATURE(int(value[:-2])) is not None
        ):
            return value
        return None
    return _TEMPERATURE(value)


#: Every metric a heartbeat may store, with its check.
METRICS: dict[str, Check] = {
    # NodeMetrics' own fields.
    "cpu_percent": _PERCENT,
    "memory_mb": _NON_NEGATIVE,
    "classifications_per_sec": _NON_NEGATIVE,
    "current_frequency_hz": _NON_NEGATIVE,
    "status": _status,
    # What the edge monitor agent reports (sigrift.edge.node_agent.collect_metrics).
    "agent_version": _text,
    "disk_percent": _PERCENT,
    "cpu_temp": _TEMPERATURE,
    "load_1m": _NON_NEGATIVE,
    "load_5m": _NON_NEGATIVE,
    "load_15m": _NON_NEGATIVE,
    "uptime_seconds": _NON_NEGATIVE,
    "platform": _text,
    "os": _text,
    "python_version": _text,
    "scan_count": _COUNT,
    "capture_mode": _text,
    "anomaly_enabled": _flag,
    "anomaly_count": _COUNT,
    "anomaly_baseline": _text,
    "hardware": _text,
    # Read by the built-in alert checks.
    "mem_percent": _PERCENT,
    "gpu_percent": _PERCENT,
    "gpu_temp": _gpu_temperature,
}


#: The metrics a heartbeat also copies into the node's ``capabilities``: the
#: bridge copies all of them, the Shiny dashboard the first five.  These are
#: the only ``capabilities`` entries checked on read; every other entry is
#: what the admin registered and is returned as stored.
CAPABILITY_METRICS: tuple[str, ...] = (
    "agent_version",
    "disk_percent",
    "cpu_temp",
    "load_1m",
    "uptime_seconds",
    "capture_mode",
    "scan_count",
    "anomaly_enabled",
    "anomaly_count",
    "anomaly_baseline",
    "platform",
    "os",
    "hardware",
    "python_version",
)

#: A TCP port the bridge connects to.
_PORT = _number(1, 65535, integer=True)


def accept_metrics(reported: Mapping[str, Any]) -> tuple[dict[str, Any], set[str]]:
    """Split a heartbeat's metrics into the values to store and those to clear.

    Returns ``(accepted, invalid)``: *accepted* maps each metric of
    :data:`METRICS` reported with a valid value to the value to store;
    *invalid* names the metrics of :data:`METRICS` reported with a bad value,
    which the caller clears.  Any other name is in neither: it is ignored.
    """
    accepted: dict[str, Any] = {}
    invalid: set[str] = set()
    for name, check in METRICS.items():
        if name not in reported:
            continue
        value = check(reported[name])
        if value is None:
            invalid.add(name)
        else:
            accepted[name] = value
    return accepted, invalid


def stored_metric(record: Mapping[str, Any], name: str) -> Any:
    """*record*'s value of metric *name*, or None when absent or not valid."""
    return METRICS[name](record.get(name))


def stored_number(value: Any) -> int | float | None:
    """A stored value as a finite number (never a bool), or None."""
    return _number()(value)


def stored_port(value: Any) -> int | None:
    """A stored TCP port (a whole number from 1 to 65535), or None."""
    return _PORT(value)


def stored_capabilities(value: Any) -> dict[str, Any]:
    """A stored ``capabilities`` value as a dict whose monitor fields are valid.

    Capabilities hold what the admin registered and the monitor fields a
    heartbeat copies into them (:data:`CAPABILITY_METRICS`).  A value that is
    not a dict reads as empty, and a monitor field with a bad value
    (``cpu_temp: "hot"``) is left out; every other entry is returned as
    stored, even one named like another metric (``status: "lab"``).
    """
    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, item in value.items()
        if key not in CAPABILITY_METRICS or METRICS[key](item) is not None
    }


def parse_timestamp(value: Any) -> datetime | None:
    """A stored ISO 8601 timestamp as an aware UTC datetime, or None.

    A timestamp without a UTC offset is read as UTC (as the gateway reads
    one); anything else that is not such a string or a datetime is None.
    """
    if isinstance(value, str):
        if len(value) > 64:
            return None
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    try:
        return value.astimezone(timezone.utc)
    except OverflowError:  # e.g. year 1 with a positive UTC offset
        return None


def isoformat(value: Any) -> str | None:
    """A stored timestamp in ISO 8601 (UTC), or None when it is not one."""
    parsed = parse_timestamp(value)
    return None if parsed is None else parsed.isoformat()


def status_from_last_seen(
    last_seen: Any, now: datetime, *, active_seconds: float, stale_seconds: float
) -> NodeStatus:
    """A node's status from its stored ``last_seen``, as of *now* (aware).

    Active while younger than *active_seconds*, stale while younger than
    *stale_seconds*, then offline.  A missing or unreadable value, or one
    more than :data:`CLOCK_SKEW_SECONDS` in the future, is unknown.
    """
    seen = parse_timestamp(last_seen)
    if seen is None:
        return NodeStatus.unknown
    elapsed = (now - seen).total_seconds()
    if elapsed < -CLOCK_SKEW_SECONDS:
        return NodeStatus.unknown
    if elapsed < active_seconds:
        return NodeStatus.active
    if elapsed < stale_seconds:
        return NodeStatus.stale
    return NodeStatus.offline


def _or(value: Any, default: Any) -> Any:
    return default if value is None else value


def stored_node_fields(record: Mapping[str, Any]) -> dict[str, Any]:
    """The ``NodeResponse`` fields of a stored record (status excepted).

    Each field is the stored value when it has the right type, else the
    field's default, so one bad record cannot fail a node listing.
    """
    host = record.get("host")
    port = record.get("port")
    return {
        "host": host if isinstance(host, str) else "",
        "port": port if isinstance(port, int) and not isinstance(port, bool) else 0,
        "cpu_percent": _or(stored_metric(record, "cpu_percent"), 0.0),
        "memory_mb": _or(stored_metric(record, "memory_mb"), 0.0),
        "classifications_per_sec": _or(
            stored_metric(record, "classifications_per_sec"), 0.0
        ),
        "current_frequency_hz": _or(stored_metric(record, "current_frequency_hz"), 0.0),
        "capabilities": stored_capabilities(record.get("capabilities")),
        "last_seen": parse_timestamp(record.get("last_seen")),
        "registered_at": parse_timestamp(record.get("registered_at")),
    }
