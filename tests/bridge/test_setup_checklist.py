"""Read actual SQLite and authenticated capture leases without inferring hardware."""

import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from sigrift.bridge import dependencies
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import nodes
from sigrift.bridge.setup_checklist import (
    LATEST_QUERIES,
    MAX_NODES,
    build_checklist,
    collect_observations,
    observation_time,
)
from sigrift.bridge.state import AppState
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture
def setup_api(tmp_path, monkeypatch):
    monkeypatch.setattr(dependencies, "_rate_limiter", dependencies.RateLimiter())
    monkeypatch.setenv("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "0")
    store = DetectionStore(tmp_path / "detections.db")
    persistence = PersistenceManager(tmp_path / "metadata", auto_save_interval=0)
    persistence.load_all()
    app = FastAPI()
    app.state.persistence = persistence
    app.state.app_state = AppState()
    app.state.detection_store = store
    app.include_router(nodes.router, prefix="/api/nodes")
    now = [datetime(2026, 11, 7, 15, tzinfo=timezone.utc)]
    monkeypatch.setattr(nodes, "_utcnow", lambda: now[0])

    def key(name, role="viewer", **meta):
        raw = generate_api_key()
        hashed, salt = hash_credential(raw)
        assert persistence.add_key(
            name,
            hashed,
            salt,
            lookup_hash=compute_lookup_hash(raw),
            meta={"role": role, **meta},
        )
        return {"X-API-Key": raw}

    headers = key("local-admin", "admin")
    with TestClient(app) as client:
        yield client, headers, store, persistence, now, key
    store.close()


def get(api, headers=None):
    client, admin, *_ = api
    response = client.get(
        "/api/nodes/setup-checklist", headers=admin if headers is None else headers
    )
    assert response.status_code == 200, response.text
    return response.json()


def register(api, name="quiet", **extra):
    client, headers, *_ = api
    assert (
        client.post(
            "/api/nodes/register", headers=headers, json={"node_id": name, **extra}
        ).status_code
        == 200
    )


def lease(api, state="running", protocol="wifi", name="quiet"):
    client, headers, *_ = api
    response = client.post(
        f"/api/nodes/{name}/scanner-status",
        headers=headers,
        json={"protocol": protocol, "state": state},
    )
    assert response.status_code == 200
    return response.json()


def test_empty_setup_and_adapter_claims_do_not_invent_capture(setup_api):
    assert get(setup_api)["nodes"] == []
    register(
        setup_api, capabilities={"hardware": "secret-serial", "capture_mode": "wifi"}
    )
    row = get(setup_api)["nodes"][0]
    assert row["scanner_status"] == {}
    assert all(
        item == {"status": "empty", "timestamp": None}
        for item in row["observations"].values()
    )
    assert get(setup_api)["host_inventory"] == "per_node"
    assert "secret-serial" not in json.dumps(get(setup_api))


def test_quiet_running_expiry_error_stop_and_recovery_are_independent_of_data(
    setup_api,
):
    register(setup_api)
    lease(setup_api)
    row = get(setup_api)["nodes"][0]
    assert row["scanner_status"]["wifi"]["active"]
    assert row["observations"]["wifi_record"]["status"] == "empty"
    setup_api[4][0] += timedelta(seconds=120)
    assert not get(setup_api)["nodes"][0]["scanner_status"]["wifi"]["active"]
    for state in ("error", "stopped", "running"):
        lease(setup_api, state)
        status = get(setup_api)["nodes"][0]["scanner_status"]["wifi"]
        assert status["state"] == state
        assert status["active"] is (state == "running")


def test_real_stored_protocols_tenants_and_summary_hour_are_separate(setup_api):
    register(setup_api)
    store = setup_api[2]
    store.insert_batch(
        [
            DetectionRecord(
                id="own",
                node_id="quiet",
                signal_class="bpsk",
                freq_hz=400e6,
                confidence=0.9,
                timestamp="2026-11-06T12:00:00Z",
            )
        ]
    )
    conn = store.get_connection()
    conn.execute(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp,ssid,bssid) VALUES(?,?,?,?,?)",
        ("wifi", "quiet", "2026-11-06T13:00:00Z", "private-ssid", "private-bssid"),
    )
    conn.execute(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp,tenant_id) VALUES(?,?,?,?)",
        ("foreign", "quiet", "2026-11-07T13:00:00Z", "foreign"),
    )
    conn.execute(
        "INSERT INTO detection_summaries_hourly(hour,node_id,signal_class,detection_count) VALUES(?,?,?,?)",
        ("2026-11-06T14:00:00+00:00", "quiet", "bpsk", 10),
    )
    conn.execute(
        "INSERT INTO detection_summaries_hourly(hour,node_id,signal_class,detection_count) VALUES(?,?,?,?)",
        ("2026-11-07T14:00:00+00:00", "quiet", "bpsk", 0),
    )
    conn.commit()
    result = get(setup_api)
    row = result["nodes"][0]
    assert row["scanner_status"] == {}
    assert row["observations"] == {
        "rf_record": {"status": "available", "timestamp": "2026-11-06T12:00:00+00:00"},
        "rf_summary": {"status": "available", "timestamp": "2026-11-06T14:00:00+00:00"},
        "wifi_record": {
            "status": "available",
            "timestamp": "2026-11-06T13:00:00+00:00",
        },
    }
    assert "private-" not in json.dumps(result) and "foreign" not in json.dumps(result)
    for query in LATEST_QUERIES.values():
        plan = conn.execute(
            "EXPLAIN QUERY PLAN " + query, ("quiet", "default")
        ).fetchall()
        assert any("USING INDEX" in item[3] for item in plan)
        # No table is scanned; only the bounded candidate subquery may be.
        assert all(
            not item[3].startswith("SCAN ") or item[3].startswith("SCAN (subquery-")
            for item in plan
        )


def test_missing_index_is_partial_failure_not_empty_or_capture_failure(setup_api):
    register(setup_api)
    lease(setup_api)
    conn = setup_api[2].get_connection()
    conn.execute("DROP INDEX idx_wifi_node_timestamp")
    conn.commit()
    row = get(setup_api)["nodes"][0]
    assert row["scanner_status"]["wifi"]["active"]
    assert row["observations"]["wifi_record"]["status"] == "unavailable"
    assert row["observations"]["rf_record"]["status"] == "empty"
    conn.execute(
        "CREATE INDEX idx_wifi_node_timestamp ON wifi_metadata(node_id,timestamp)"
    )
    conn.commit()
    assert (
        get(setup_api)["nodes"][0]["observations"]["wifi_record"]["status"] == "empty"
    )


@pytest.mark.parametrize(
    "value", [None, 42, "bad-secret", "2026-11-07T00:00:00", "2026-13-01T00:00:00Z"]
)
def test_unusable_timestamp_is_not_exposed(value):
    assert observation_time(value) is None


def test_valid_timestamp_normalizes_offset():
    assert observation_time("2026-11-07T09:00:00-06:00") == "2026-11-07T15:00:00+00:00"


def test_corrupt_stored_timestamp_is_distinct_from_no_data(setup_api):
    register(setup_api)
    conn = setup_api[2].get_connection()
    conn.execute(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp) VALUES('bad','quiet','private-invalid-value')"
    )
    conn.commit()
    result = get(setup_api)
    assert result["nodes"][0]["observations"]["wifi_record"] == {
        "status": "invalid",
        "timestamp": None,
    }
    assert "private-invalid-value" not in json.dumps(result)


def test_read_requires_viewer_and_fixed_instance(setup_api):
    client, _, _, _, _, key = setup_api
    assert client.get("/api/nodes/setup-checklist").status_code == 401
    assert (
        client.get(
            "/api/nodes/setup-checklist", headers=key("sensor", "sensor")
        ).status_code
        == 403
    )
    assert get(setup_api, key("viewer"))["host_inventory"] == "per_node"
    foreign = key("foreign", "admin", tenant_id="other")
    assert client.get("/api/nodes/setup-checklist", headers=foreign).status_code == 403


def test_node_limit_does_not_claim_complete_inventory(setup_api):
    persistence = setup_api[3]
    for index in range(MAX_NODES + 1):
        persistence.set_node(
            f"node-{index:03}", {"capabilities": {"serial": "private"}}
        )
    result = get(setup_api)
    assert result["truncated"] is True
    assert len(result["nodes"]) == MAX_NODES
    assert "private" not in json.dumps(result)


def test_database_budget_interrupts_real_index_scan_and_clears_handler(setup_api):
    store = setup_api[2]
    conn = store.get_connection()
    # Foreign rows sharing a node are filtered; an enormous node cannot monopolize reads.
    conn.executemany(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp,tenant_id) VALUES(?,?,?,?)",
        (
            (f"foreign-{i}", "crowded", f"2026-11-07T00:00:{i:07}Z", "other")
            for i in range(210000)
        ),
    )
    conn.commit()
    result = collect_observations(store, ["crowded"])
    assert result["crowded"]["wifi_record"]["status"] == "unavailable"
    # A separate legitimate long read still completes: no leaked progress callback.
    assert (
        conn.execute("SELECT SUM(length(timestamp)) FROM wifi_metadata").fetchone()[0]
        > 0
    )



def test_large_own_history_still_reports_latest_time(setup_api):
    """Soak UI-1: ~65k+ rows for one node used to exhaust the read budget."""
    store = setup_api[2]
    conn = store.get_connection()
    base = datetime(2026, 11, 1, tzinfo=timezone.utc)
    conn.executemany(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp,tenant_id) VALUES(?,?,?,?)",
        (
            (f"own-{i}", "busy", (base + timedelta(seconds=i)).isoformat(), store.tenant_id)
            for i in range(100_000)
        ),
    )
    # A later instant written with a non-UTC offset sorts lower as text; the
    # date-aware outer ordering must still pick it.
    conn.execute(
        "INSERT INTO wifi_metadata(detection_id,node_id,timestamp,tenant_id) VALUES(?,?,?,?)",
        ("own-offset", "busy", "2026-11-02T08:00:00+05:00", store.tenant_id),
    )
    conn.commit()
    result = collect_observations(store, ["busy"])
    assert result["busy"]["wifi_record"] == {
        "status": "available",
        "timestamp": "2026-11-02T03:46:39+00:00",
    }

def test_snapshot_does_not_expose_metadata_or_trust_forged_lease():
    now = datetime(2026, 11, 7, tzinfo=timezone.utc)
    rows = {
        "node": {
            "capabilities": {"usb_serial": "private"},
            "_scanner_reports": {
                "wifi": {"state": "running", "reported_at": "2099-01-01T00:00:00Z"}
            },
        }
    }
    result = build_checklist(rows, {"node": {}}, now)
    assert result["nodes"] == [
        {
            "node_id": "node",
            "setup_readiness": None,
            "scanner_status": {},
            "observations": {},
        }
    ]


def test_normal_application_mounts_checklist_with_its_actual_store(
    client, detection_store, registered_node
):
    detection_store.insert_batch(
        [
            DetectionRecord(
                id="full-app-checklist",
                node_id=registered_node,
                signal_class="bpsk",
                freq_hz=433e6,
                confidence=0.8,
                timestamp="2026-11-07T12:00:00Z",
            )
        ]
    )
    response = client.get("/api/nodes/setup-checklist")
    assert response.status_code == 200
    row = next(
        item for item in response.json()["nodes"] if item["node_id"] == registered_node
    )
    assert row["scanner_status"] == {}
    assert row["observations"]["rf_record"] == {
        "status": "available",
        "timestamp": "2026-11-07T12:00:00+00:00",
    }
    assert response.json()["host_inventory"] == "per_node"


def test_offset_order_and_equal_moment_use_actual_time_not_string_order(setup_api):
    register(setup_api)
    store = setup_api[2]
    records = [
        {
            "detection_id": "earlier-clock-later-text",
            "node_id": "quiet",
            "timestamp": "2026-11-07T18:00:00+10:00",
        },
        {
            "detection_id": "later-clock-earlier-text",
            "node_id": "quiet",
            "timestamp": "2026-11-07T09:00:00Z",
        },
        {
            "detection_id": "same-moment",
            "node_id": "quiet",
            "timestamp": "2026-11-07T03:00:00-06:00",
        },
    ]
    assert store.insert_wifi_metadata(records) == 3
    row = get(setup_api)["nodes"][0]
    assert row["observations"]["wifi_record"] == {
        "status": "available",
        "timestamp": "2026-11-07T09:00:00+00:00",
    }
    assert row["scanner_status"] == {}


def test_exclusive_database_lock_is_bounded_and_connection_settings_restored(setup_api):
    store = setup_api[2]
    conn = store.get_connection()
    # A real rollback-journal writer blocks readers; WAL readers ordinarily
    # remain available. This also covers an operator's non-WAL database.
    assert conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete"
    conn.execute("PRAGMA busy_timeout=2000")
    db_path = conn.execute("PRAGMA database_list").fetchone()[2]
    locker = sqlite3.connect(db_path)
    locker.execute("BEGIN EXCLUSIVE")
    try:
        started = time.monotonic()
        result = collect_observations(store, [f"locked-{i}" for i in range(100)])
        elapsed = time.monotonic() - started
        assert elapsed < 3.5, "Lock waits must share the bounded read budget"
        assert len(result) == 100
        assert all(
            value == {"status": "unavailable", "timestamp": None}
            for row in result.values()
            for value in row.values()
        )
    finally:
        locker.rollback()
        locker.close()
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 2000
    assert conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0] == 0
    assert collect_observations(store, ["quiet"])["quiet"]["rf_record"] == {
        "status": "empty",
        "timestamp": None,
    }
