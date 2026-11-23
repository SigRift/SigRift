"""Heartbeat metric checks and stored-value readers (``node_metrics``).

The bridge and the Shiny dashboard both store a heartbeat through
``accept_metrics`` and read node records back through these helpers; the
router tests on each side cover the HTTP paths.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sigrift.lib.shiny.models import NodeStatus
from sigrift.lib.shiny.node_metrics import (
    CAPABILITY_METRICS,
    CLOCK_SKEW_SECONDS,
    MAX_TEXT_LENGTH,
    METRICS,
    accept_metrics,
    isoformat,
    parse_timestamp,
    status_from_last_seen,
    stored_capabilities,
    stored_metric,
    stored_node_fields,
    stored_number,
    stored_port,
)
from sigrift.lib.shiny.routers import nodes as shiny_nodes

_NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)


def _status(seconds_ago: float) -> NodeStatus:
    seen = (_NOW - timedelta(seconds=seconds_ago)).isoformat()
    return status_from_last_seen(seen, _NOW, active_seconds=120, stale_seconds=300)


def test_record_fields_are_never_heartbeat_metrics():
    # What an admin registers or the server stamps can never be reported.
    for name in (
        "last_seen",
        "registered_at",
        "host",
        "port",
        "capabilities",
        "detection_summary",
        "latitude",
        "position_x",
        "floor_label",
        "_scanner_reports",
        "_setup_readiness",
    ):
        assert name not in METRICS, name


def test_accept_metrics_stores_valid_values_and_clears_bad_ones():
    accepted, invalid = accept_metrics(
        {
            "cpu_percent": 12,
            "status": NodeStatus.stale,
            "scan_count": 4.0,
            "anomaly_enabled": False,
            "gpu_temp": "91°C",
            "cpu_temp": None,
            "disk_percent": 100.5,
            "last_seen": "never",
            "unknown": 1,
        }
    )
    assert accepted == {
        "cpu_percent": 12,
        "status": "stale",
        "scan_count": 4,
        "anomaly_enabled": False,
        "gpu_temp": "91°C",
    }
    assert invalid == {"cpu_temp", "disk_percent"}


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("cpu_percent", -0.1),
        ("cpu_percent", float("nan")),
        ("memory_mb", float("inf")),
        ("memory_mb", 10**400),  # too large for a float
        ("load_1m", True),
        ("load_1m", "0.5"),
        ("scan_count", 1.5),
        ("scan_count", -1),
        ("cpu_temp", 250),
        ("cpu_temp", -101),
        ("gpu_temp", "hot°C"),
        ("gpu_temp", "1000°C"),
        # The text form has the number's range too, not only 3 digits.
        ("gpu_temp", "201°C"),
        ("gpu_temp", "999°C"),
        ("gpu_temp", "-101°C"),
        ("gpu_temp", "٩١°C"),  # non-ASCII digits
        ("gpu_temp", [99]),
        ("status", "gone"),
        ("status", ["active"]),
        ("anomaly_enabled", 1),
        ("agent_version", "v" * (MAX_TEXT_LENGTH + 1)),
        ("hardware", {"model": "x"}),
    ],
)
def test_bad_values_are_not_valid(name, value):
    assert METRICS[name](value) is None
    assert stored_metric({name: value}, name) is None


def test_values_at_their_limits_are_valid():
    for name, value in (
        ("cpu_percent", 0),
        ("cpu_percent", 100.0),
        ("cpu_temp", -100),
        ("cpu_temp", 200),
        ("gpu_temp", "-5°C"),
        ("gpu_temp", "200°C"),
        ("gpu_temp", "-100°C"),
        ("agent_version", "v" * MAX_TEXT_LENGTH),
    ):
        assert METRICS[name](value) == value, (name, value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-11-10T12:00:00+00:00", _NOW),
        ("2026-11-10T12:00:00Z", _NOW),
        ("2026-11-10T13:00:00+01:00", _NOW),
        ("2026-11-10T12:00:00", _NOW),  # no offset: UTC, as the gateway reads it
        (_NOW, _NOW),
        (datetime(2026, 11, 10, 12, 0), _NOW),
        ("never", None),
        ("2026-11-10T12:00:00" + " " * 60, None),  # too long to be a timestamp
        # fromisoformat reads any number of fractional digits: the length
        # limit (64 characters) is what refuses the longer one.
        ("2026-11-10T12:00:00." + "0" * 38 + "+00:00", _NOW),
        ("2026-11-10T12:00:00." + "0" * 39 + "+00:00", None),
        ("0001-01-01T00:00:00+01:00", None),  # before year 1 in UTC
        (1_731_240_000, None),
        (None, None),
        (["2026-11-10T12:00:00Z"], None),
    ],
)
def test_parse_timestamp(value, expected):
    assert parse_timestamp(value) == expected
    assert isoformat(value) == (None if expected is None else expected.isoformat())


def test_status_from_last_seen():
    assert _status(0) == NodeStatus.active
    assert _status(119) == NodeStatus.active
    assert _status(120) == NodeStatus.stale
    assert _status(300) == NodeStatus.offline
    # A clock stepped back a little still counts; a time the clock has not
    # reached (a forged or hand-edited value) does not keep a node active.
    assert _status(-CLOCK_SKEW_SECONDS) == NodeStatus.active
    assert _status(-CLOCK_SKEW_SECONDS - 1) == NodeStatus.unknown
    for value in (None, "never", 5, {"at": "now"}):
        assert (
            status_from_last_seen(value, _NOW, active_seconds=1, stale_seconds=2)
            == NodeStatus.unknown
        )


def test_stored_capabilities_drop_only_bad_metrics():
    caps = {"cpu_temp": "hot", "uptime_seconds": 30, "sdr": {"any": "value"}}
    assert stored_capabilities(caps) == {"uptime_seconds": 30, "sdr": {"any": "value"}}
    for value in (None, "x", ["cpu_temp"]):
        assert stored_capabilities(value) == {}


def test_stored_capabilities_check_only_the_monitor_fields():
    # An admin-registered entry named like a metric that no heartbeat copies
    # into capabilities is returned as registered; a monitor field is checked.
    caps = {
        "status": "lab",
        "gpu_temp": "warm",
        "cpu_percent": "n/a",
        "load_5m": [1],
        "os": 11,
        "hardware": {"sdr": "hackrf"},
        "anomaly_enabled": "yes",
    }
    assert stored_capabilities(caps) == {
        "status": "lab",
        "gpu_temp": "warm",
        "cpu_percent": "n/a",
        "load_5m": [1],
    }


def test_capability_metrics_are_metrics_both_heartbeats_copy():
    assert set(CAPABILITY_METRICS) <= set(METRICS)
    assert len(set(CAPABILITY_METRICS)) == len(CAPABILITY_METRICS)
    # The Shiny dashboard copies the first five, the bridge all of them.
    assert shiny_nodes._CAPABILITY_METRICS == CAPABILITY_METRICS[:5]


def test_stored_port():
    for value, expected in ((1, 1), (8080, 8080), (65535, 65535), (1234.0, 1234)):
        assert stored_port(value) == expected
    for value in (0, 65536, -1, True, "22", 22.5, float("nan"), None, [22]):
        assert stored_port(value) is None, value


def test_stored_number():
    assert stored_number(12.5) == 12.5
    for value in (True, "1", float("nan"), None):
        assert stored_number(value) is None


def test_stored_node_fields_default_every_bad_value():
    assert stored_node_fields(
        {
            "host": 5,
            "port": True,
            "cpu_percent": "high",
            "memory_mb": -1,
            "classifications_per_sec": None,
            "current_frequency_hz": float("nan"),
            "capabilities": "x",
            "last_seen": "never",
            "registered_at": ["x"],
        }
    ) == {
        "host": "",
        "port": 0,
        "cpu_percent": 0.0,
        "memory_mb": 0.0,
        "classifications_per_sec": 0.0,
        "current_frequency_hz": 0.0,
        "capabilities": {},
        "last_seen": None,
        "registered_at": None,
    }
    good = stored_node_fields(
        {
            "host": "h",
            "port": 8080,
            "cpu_percent": 5,
            "last_seen": "2026-11-10T12:00:00Z",
        }
    )
    assert (good["host"], good["port"], good["cpu_percent"]) == ("h", 8080, 5)
    assert good["last_seen"] == _NOW
