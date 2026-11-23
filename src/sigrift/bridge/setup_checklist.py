"""Read-only setup evidence: host inventory, capture leases and stored data differ."""

from datetime import datetime, timezone
import sqlite3
import time

from sigrift.bridge.scanner_status import SCANNER_REPORTS_FIELD, scanner_status_snapshot
from sigrift.bridge.setup_readiness import READINESS_FIELD, readiness_snapshot

MAX_NODES = 100
READ_BUDGET_SECONDS = 2.0
# Existing node indexes restrict each lookup to that node. The inner query
# walks the (node_id, timestamp) index newest-first and stops after a few
# rows, so cost no longer grows with the node's history (sorting every row by
# julianday() exhausted the VM budget past ~65k records). The outer query then
# applies SQL date ordering to those candidates, which handles stored timezone
# offsets; the shared VM budget still bounds the work.
LATEST_CANDIDATES = 64
LATEST_QUERIES = {
    "rf_record": "SELECT timestamp FROM (SELECT timestamp FROM detections INDEXED BY idx_detections_node_timestamp WHERE node_id=? AND tenant_id=? ORDER BY timestamp DESC LIMIT %d) ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT 1"
    % LATEST_CANDIDATES,
    "rf_summary": "SELECT hour,julianday(hour) AS sort_time FROM detection_summaries_hourly INDEXED BY idx_det_summary_node_ts WHERE node_id=?1 AND tenant_id=?2 AND detection_count>0 UNION ALL SELECT hour,julianday(hour) AS sort_time FROM rf_summary_components INDEXED BY idx_rf_summary_component_node_time WHERE node_id=?1 AND tenant_id=?2 AND detection_count>0 ORDER BY sort_time DESC,hour DESC LIMIT 1",
    "wifi_record": "SELECT timestamp FROM (SELECT timestamp FROM wifi_metadata INDEXED BY idx_wifi_node_timestamp WHERE node_id=? AND tenant_id=? ORDER BY timestamp DESC LIMIT %d) ORDER BY julianday(timestamp) DESC, timestamp DESC LIMIT 1"
    % LATEST_CANDIDATES,
}


def observation_time(value):
    """Only transmit normalized timestamps, never arbitrary stored strings."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        return None


def collect_observations(store, node_ids):
    """Cap nodes, result rows and SQLite work; unavailable is distinct from empty."""
    conn = store.get_connection()
    remaining = 1_000_000
    deadline = time.monotonic() + READ_BUDGET_SECONDS
    busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]

    def bounded_work():
        nonlocal remaining
        remaining -= 1000
        return remaining <= 0 or time.monotonic() >= deadline

    # Store connections are thread-local; this synchronous task owns this handler.
    conn.set_progress_handler(bounded_work, 1000)
    result = {}
    try:
        for node_id in node_ids[:MAX_NODES]:
            observations = {}
            for kind, query in LATEST_QUERIES.items():
                if remaining <= 0 or time.monotonic() >= deadline:
                    observations[kind] = {"status": "unavailable", "timestamp": None}
                    continue
                try:
                    # A lock wait does not execute VM instructions. Bound it
                    # separately so one busy database cannot stall every node.
                    wait_ms = min(
                        100, max(0, int((deadline - time.monotonic()) * 1000))
                    )
                    conn.execute(f"PRAGMA busy_timeout={wait_ms}")
                    row = conn.execute(query, (node_id, store.tenant_id)).fetchone()
                    stamp = observation_time(row[0]) if row else None
                    observations[kind] = {
                        "status": "available"
                        if stamp
                        else "invalid"
                        if row
                        else "empty",
                        "timestamp": stamp,
                    }
                except sqlite3.Error:
                    observations[kind] = {"status": "unavailable", "timestamp": None}
            result[node_id] = observations
    finally:
        conn.set_progress_handler(None, 0)
        conn.execute(f"PRAGMA busy_timeout={busy_timeout}")
    return result


def build_checklist(nodes, observations, now):
    ids = sorted(nodes)[:MAX_NODES]
    return {
        "generated_at": now.astimezone(timezone.utc).isoformat(),
        "host_inventory": "per_node",
        "truncated": len(nodes) > MAX_NODES,
        "nodes": [
            {
                "node_id": node_id,
                "setup_readiness": readiness_snapshot(
                    nodes[node_id].get(READINESS_FIELD), now
                ),
                "scanner_status": scanner_status_snapshot(
                    nodes[node_id].get(SCANNER_REPORTS_FIELD), now
                ),
                "observations": observations[node_id],
            }
            for node_id in ids
        ],
    }
