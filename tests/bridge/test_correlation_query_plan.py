"""Regression: cross-correlator queries must use a (node_id, timestamp)
index, not full table scans.

The previous version of `CrossCorrelator._query_nearby_detections`
wrapped `timestamp` in `datetime()` on the column side, e.g.

    AND datetime(timestamp) >= datetime(?, '-' || ? || ' seconds')

That makes the expression non-constant per row, which prevents SQLite
from using any index on `timestamp` — every call became a full scan.
On staging this pegged an executor thread per ingest.

`EXPLAIN QUERY PLAN` exposes whether SQLite picked an index; this test
asserts each of the four queries hits one. If a future change reverts
to the function-wrapped form, this test fails.
"""

from __future__ import annotations

import sqlite3

import pytest


# The exact query templates emitted by CrossCorrelator._query_nearby_detections.
# Kept in sync with src/sigrift/bridge/correlation_engine.py.
QUERIES = {
    "sdr": (
        "SELECT detection_id, freq_hz, timestamp, signal_class "
        "FROM detections "
        "WHERE node_id = ? AND freq_hz BETWEEN ? AND ? "
        "AND timestamp >= ? AND timestamp <= ? "
        "LIMIT 10"
    ),
    "wifi": (
        "SELECT id, channel, timestamp FROM wifi_metadata "
        "WHERE node_id = ? AND timestamp >= ? AND timestamp <= ? LIMIT 10"
    ),
    "bt": (
        "SELECT id, channel, timestamp FROM bt_devices "
        "WHERE node_id = ? AND timestamp >= ? AND timestamp <= ? LIMIT 10"
    ),
    "zigbee": (
        "SELECT id, channel, timestamp FROM zigbee_devices "
        "WHERE node_id = ? AND timestamp >= ? AND timestamp <= ? LIMIT 10"
    ),
}


@pytest.fixture
def conn() -> sqlite3.Connection:
    """In-memory DB with minimal schemas + the indexes the queries rely on."""
    c = sqlite3.connect(":memory:")
    c.executescript(
        """
        CREATE TABLE detections (
            detection_id INTEGER PRIMARY KEY,
            node_id TEXT, freq_hz REAL, timestamp TEXT, signal_class TEXT
        );
        CREATE INDEX idx_detections_node_timestamp
            ON detections (node_id, timestamp);

        CREATE TABLE wifi_metadata (
            id INTEGER PRIMARY KEY,
            node_id TEXT, channel INTEGER, timestamp TEXT
        );
        CREATE INDEX idx_wifi_node_timestamp
            ON wifi_metadata (node_id, timestamp);

        CREATE TABLE bt_devices (
            id INTEGER PRIMARY KEY,
            node_id TEXT, channel INTEGER, timestamp TEXT
        );
        CREATE INDEX idx_bt_node_timestamp
            ON bt_devices (node_id, timestamp);

        CREATE TABLE zigbee_devices (
            id INTEGER PRIMARY KEY,
            node_id TEXT, channel INTEGER, timestamp TEXT
        );
        CREATE INDEX idx_zb_node_timestamp
            ON zigbee_devices (node_id, timestamp);
        """
    )
    yield c
    c.close()


def _bind_args(source: str) -> tuple:
    """Argument tuple shapes match _query_nearby_detections."""
    ts_low, ts_high = "2026-01-01T00:00:00+00:00", "2026-12-31T23:59:59+00:00"
    if source == "sdr":
        return ("node1", 0.0, 1e9, ts_low, ts_high)
    return ("node1", ts_low, ts_high)


@pytest.mark.parametrize("source", sorted(QUERIES))
def test_query_uses_node_timestamp_index(conn: sqlite3.Connection, source: str) -> None:
    plan = conn.execute(
        f"EXPLAIN QUERY PLAN {QUERIES[source]}", _bind_args(source)
    ).fetchall()
    # Plan rows: (id, parent, notused, detail). The detail string contains
    # "USING INDEX <name>" when an index is used, or a bare "SCAN" when
    # SQLite falls back to a full table scan.
    detail = " | ".join(row[3] for row in plan)
    assert "USING INDEX" in detail, (
        f"{source} query plan should use an index, got:\n  {detail}"
    )
