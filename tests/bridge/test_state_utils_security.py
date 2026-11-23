"""Security paths of ``AppState`` (``sigrift.bridge.state``) and ``sigrift.bridge.utils``.

* The activity log escapes markup before the dashboard reads it back
  (``GET /api/nodes/activity``).
* The deprecated in-memory session API never authenticates: neither the
  methods nor a token placed in ``AppState.sessions``.
* Alert ids restored at start-up never reuse a persisted id, whatever the
  persisted ids look like.
* Heartbeat-driven node alerts: messages escaped, one open alert per name
  and node (a node cannot flood the alert store), rules scoped to their
  node, node-supplied values of an unexpected type are not a 500.
* Node status from ``last_seen``: a heartbeat metric never replaces the
  bridge's ``last_seen`` or the rest of the node record; values of the wrong
  type or range are not stored, and a record saved with such values before
  this check still lists, maps and connects (spectrum) with them read as
  absent.
* Cooldown maps are bounded (``BoundedDict``).
* ``get_detection_store`` answers 503 before start-up finished.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.routers.nodes import stored_location
from sigrift.bridge.routers.spectrum import _NodeSpectrumPoller
from sigrift.bridge.state import AppState
from sigrift.bridge.tests.conftest import make_detection
from sigrift.bridge.utils import BoundedDict
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer

_MARKUP = "<img src=x onerror=alert(1)>"


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------


def test_activity_log_escapes_markup_served_to_the_dashboard(client, app_state):
    app_state.log_activity("<script>x</script>", node_id='"><b>n</b>', message=_MARKUP)
    event = client.get("/api/nodes/activity").json()[-1]
    assert event["event_type"] == "&lt;script&gt;x&lt;/script&gt;"
    assert event["node_id"] == "&quot;&gt;&lt;b&gt;n&lt;/b&gt;"
    assert event["message"] == "&lt;img src=x onerror=alert(1)&gt;"


# ---------------------------------------------------------------------------
# Deprecated in-memory sessions
# ---------------------------------------------------------------------------


def test_the_deprecated_session_api_never_authenticates():
    # Nothing in src calls these stubs today (the route-level check is the
    # next test); this keeps them from being revived as a second session
    # store that skips the DetectionStore's tenant and binding checks.
    state = AppState()
    for token in ("", "master", "p-app-session-token-0123456789"):
        state.sessions[token] = {"key_id": "master", "expires": "2999-01-01T00:00:00"}
        assert state.validate_session(token) is None, token
        state.destroy_session(token)
        assert state.validate_session(token) is None, token


def test_a_token_in_app_state_sessions_is_not_a_credential(bridge_app, app_state):
    token = secrets.token_urlsafe(32)
    far = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    app_state.sessions[token] = {"key_id": "master", "expires": far}
    anon = TestClient(bridge_app)
    for headers in (
        {"Authorization": "Bearer " + token},
        {"X-Session-Token": token},
    ):
        assert anon.get("/api/nodes", headers=headers).status_code == 401


def test_the_deprecated_create_session_issues_no_token(caplog):
    state = AppState()
    assert state.create_session("master") == ""
    # Nothing was stored that a later check could mistake for a session.
    assert state.sessions == {}
    assert "AppState.create_session() called" in caplog.text


# ---------------------------------------------------------------------------
# Alert ids restored at start-up
# ---------------------------------------------------------------------------


def test_restored_alert_ids_never_collide(persistence):
    for alert_id in (
        "alert_7",
        "alert_41",
        "alert_9_suffix",
        "alert_",
        "alert_x",
        "legacy-99",
        "",
        12,
        None,
    ):
        persistence.add_alert({"alert_id": alert_id, "name": "restored"})
    existing = {a["alert_id"] for a in persistence.get_alerts()}

    state = AppState()
    state.restore_alert_counter(persistence)
    new_ids = [state.next_alert_id() for _ in range(3)]
    assert new_ids == ["alert_42", "alert_43", "alert_44"]
    assert existing.isdisjoint(new_ids)


def test_an_empty_alert_store_starts_at_one(persistence):
    state = AppState()
    state.restore_alert_counter(persistence)
    assert state.next_alert_id() == "alert_1"


# ---------------------------------------------------------------------------
# Heartbeat-driven node alerts
# ---------------------------------------------------------------------------


@pytest.fixture
def nodes(client) -> tuple[str, str]:
    for node_id in ("hb-node", "other-node"):
        resp = client.post("/api/nodes/register", json={"node_id": node_id})
        assert resp.status_code == 200, resp.text
    return "hb-node", "other-node"


def _heartbeat(client: TestClient, node_id: str, **metrics) -> int:
    return client.post(
        "/api/nodes/heartbeat", json={"node_id": node_id, "metrics": metrics}
    ).status_code


def _fired(persistence, prefix: str, node_id: str) -> list[dict]:
    return [
        a
        for a in persistence.get_alerts()
        if str(a.get("name", "")).startswith(prefix)
        and a.get("node_id") == node_id
        and not a.get("is_rule")
    ]


class TestNodeAlerts:
    def test_a_rule_named_with_markup_is_stored_escaped_and_fires_once(
        self, client, nodes, persistence
    ):
        # The alerts router escapes the name when the rule is created; the
        # escaping of the alert message itself (a raw persisted name) is
        # the next test.
        node, _ = nodes
        resp = client.post(
            "/api/alerts/rules",
            json={"name": _MARKUP, "thresholds": {"cpu_percent": 10}},
        )
        assert resp.status_code == 201, resp.text
        assert _heartbeat(client, node, cpu_percent=50.0) == 200
        assert _heartbeat(client, node, cpu_percent=60.0) == 200

        (alert,) = _fired(persistence, "rule_", node)
        assert "<" not in alert["message"] and "<" not in alert["name"]
        served = [
            a
            for a in client.get("/api/alerts/").json()
            if a["alert_id"] == alert["alert_id"]
        ]
        assert served and "<" not in served[0]["message"]

    def test_a_persisted_rule_name_is_escaped_in_the_alert_message(
        self, client, nodes, persistence
    ):
        # A rule written by an older release or restored from a file keeps
        # its raw name: the alert message is escaped when it fires.
        node, _ = nodes
        persistence.add_alert(
            {
                "alert_id": "alert_900",
                "name": _MARKUP,
                "severity": "warning",
                "is_rule": True,
                "thresholds": {"cpu_percent": 10},
            }
        )
        assert _heartbeat(client, node, cpu_percent=50.0) == 200
        (alert,) = _fired(persistence, "rule_", node)
        assert _MARKUP not in alert["message"]
        assert "&lt;img src=x onerror=alert(1)&gt;" in alert["message"]

    def test_a_rule_scoped_to_another_node_does_not_fire(
        self, client, nodes, persistence
    ):
        node, other = nodes
        resp = client.post(
            "/api/alerts/rules",
            json={"name": "cpu", "node_id": other, "thresholds": {"cpu_percent": 10}},
        )
        assert resp.status_code == 201, resp.text
        assert _heartbeat(client, node, cpu_percent=99.0) == 200
        assert _fired(persistence, "rule_", node) == []
        assert _heartbeat(client, other, cpu_percent=99.0) == 200
        assert len(_fired(persistence, "rule_", other)) == 1

    def test_built_in_resource_alerts_are_raised_once_per_node(
        self, client, nodes, persistence
    ):
        # A node reporting a full disk on every heartbeat gets one open
        # alert per limit, not one per heartbeat.
        node, other = nodes
        for _ in range(3):
            assert _heartbeat(client, node, disk_percent=97.5, mem_percent=99.0) == 200
        (disk,) = _fired(persistence, "disk_high", node)
        (mem,) = _fired(persistence, "memory_high", node)
        assert disk["severity"] == mem["severity"] == "critical"
        assert "97.5%" in disk["message"] and node in disk["message"]
        # At the limits: no alert.
        assert _heartbeat(client, other, disk_percent=90.0, mem_percent=95.0) == 200
        assert _fired(persistence, "disk_high", other) == []
        assert _fired(persistence, "memory_high", other) == []

    def test_node_supplied_gpu_temperature_is_parsed_safely(self, client, persistence):
        # One node per value: alerts are deduplicated per name and node.
        cases = {
            "gpu-a": ("91°C", True),
            "gpu-b": (92, True),
            "gpu-c": ("hot°C", False),
            "gpu-d": ("80°C", False),
            "gpu-e": ({"value": 99}, False),
            "gpu-f": ([99], False),
        }
        for node, (gpu_temp, fires) in cases.items():
            assert (
                client.post("/api/nodes/register", json={"node_id": node}).status_code
                == 200
            )
            assert _heartbeat(client, node, gpu_temp=gpu_temp) == 200, gpu_temp
            assert bool(_fired(persistence, "gpu_temp_high", node)) is fires, gpu_temp

    def test_node_supplied_percentages_of_another_type_are_not_a_500(
        self, bridge_app, master_key, nodes
    ):
        node, _ = nodes
        node_client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key},
            raise_server_exceptions=False,
        )
        for metrics in (
            {"disk_percent": "full"},
            {"mem_percent": "99"},
            {"disk_percent": [95]},
        ):
            resp = node_client.post(
                "/api/nodes/heartbeat", json={"node_id": node, "metrics": metrics}
            )
            assert resp.status_code < 500, metrics


# ---------------------------------------------------------------------------
# Node status from last_seen
# ---------------------------------------------------------------------------


def _node_key(persistence, key_id: str, node_id: str) -> str:
    """A NODE-role API key bound to *node_id* (the least a scanner holds)."""
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    persistence.set_key(key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw))
    persistence.set_key_meta(
        key_id,
        {"role": "node", "node_id": node_id, "description": "p-app node key"},
    )
    return raw


def _last_heard_long_ago(persistence, node_id: str) -> None:
    """Move *node_id*'s stored ``last_seen`` 10 minutes back (offline)."""
    data = persistence.get_nodes()[node_id]
    seen = datetime.fromisoformat(data["last_seen"]) - timedelta(minutes=10)
    data["last_seen"] = seen.isoformat()
    persistence.set_node(node_id, data)


def _statuses(client: TestClient) -> dict[str, str]:
    return {n["node_id"]: n["status"] for n in client.get("/api/nodes/").json()}


def test_node_status_follows_the_heartbeat(client, nodes, persistence):
    node, other = nodes
    # /register sets last_seen too: start from nodes not heard for a while,
    # so only the heartbeat can make one active again.
    for node_id in nodes:
        _last_heard_long_ago(persistence, node_id)
    assert _statuses(client) == {node: "offline", other: "offline"}

    key = _node_key(persistence, "hb-node-key", node)
    node_client = TestClient(client.app, headers={"X-API-Key": key})
    assert _heartbeat(node_client, node, cpu_percent=1.0) == 200
    # The key is bound to its node: it cannot refresh another one.
    assert _heartbeat(node_client, other, cpu_percent=1.0) == 403
    assert _statuses(client) == {node: "active", other: "offline"}


def test_a_node_cannot_forge_its_last_seen(bridge_app, master_key, nodes, persistence):
    node, _ = nodes
    key = _node_key(persistence, "hb-node-key", node)
    node_client = TestClient(bridge_app, headers={"X-API-Key": key})
    resp = node_client.post(
        "/api/nodes/heartbeat",
        json={"node_id": node, "metrics": {"last_seen": "not-a-timestamp"}},
    )
    assert resp.status_code == 200
    admin = TestClient(
        bridge_app,
        headers={"X-API-Key": master_key},
        raise_server_exceptions=False,
    )
    listing = admin.get("/api/nodes/")
    assert listing.status_code == 200, listing.text
    status = {n["node_id"]: n["status"] for n in listing.json()}
    assert status[node] == "active"


_REGISTERED = {
    "node_id": "hb-node",
    "host": "192.0.2.10",
    "port": 8080,
    "capabilities": {"sdr": "rtl-sdr"},
}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        # Future-dated: a node that stops would otherwise stay active.
        ("last_seen", "2036-01-01T00:00:00+00:00"),
        ("registered_at", "not-a-date"),
        ("host", "203.0.113.9"),
        ("port", 1),
        ("capabilities", "not-a-dict"),
        ("latitude", "x"),
        ("position_x", "x"),
        ("floor_label", 5),
        ("detection_summary", "x"),
        # Read by the spectrum connect route as the node's rtl_tcp port.
        ("rtl_tcp_port", 22),
    ],
)
def test_heartbeat_metrics_never_rewrite_the_node_record(
    bridge_app, master_key, persistence, field, value
):
    admin = TestClient(
        bridge_app, headers={"X-API-Key": master_key}, raise_server_exceptions=False
    )
    assert admin.post("/api/nodes/register", json=_REGISTERED).status_code == 200
    before = persistence.get_nodes()["hb-node"]
    key = _node_key(persistence, "hb-node-key", "hb-node")
    node_client = TestClient(
        bridge_app, headers={"X-API-Key": key}, raise_server_exceptions=False
    )
    resp = node_client.post(
        "/api/nodes/heartbeat", json={"node_id": "hb-node", "metrics": {field: value}}
    )
    assert resp.status_code == 200, resp.text
    after = persistence.get_nodes()["hb-node"]
    if field == "last_seen":  # the bridge's own time of this heartbeat
        seen = datetime.fromisoformat(after["last_seen"])
        assert abs((datetime.now(timezone.utc) - seen).total_seconds()) < 60
    else:
        assert after.get(field) == before.get(field)
    listing = admin.get("/api/nodes/")
    assert listing.status_code == 200, listing.text
    (node,) = listing.json()
    assert node["status"] == "active"
    assert (node["host"], node["port"], node["capabilities"]) == (
        "192.0.2.10",
        8080,
        {"sdr": "rtl-sdr"},
    )


def test_heartbeat_metrics_of_the_wrong_type_or_range_are_not_stored(
    client, nodes, persistence
):
    node, _ = nodes
    good = {"cpu_temp": 51.5, "disk_percent": 40.0, "hardware": "rtl-sdr"}
    assert _heartbeat(client, node, scan_count=3, **good) == 200
    assert persistence.get_nodes()[node]["capabilities"]["cpu_temp"] == 51.5
    bad = {
        "cpu_temp": "hot",
        "disk_percent": 101,
        "mem_percent": "99",
        "hardware": {"model": "x"},
        "scan_count": 1.5,
        "uptime_seconds": -1,
        "load_1m": True,
        "anomaly_enabled": "yes",
        "agent_version": "v" * 257,
    }
    # Python's JSON parser accepts NaN: it is not stored either.
    body = json.dumps(
        {"node_id": node, "metrics": {"cpu_percent": float("nan"), **bad}}
    )
    resp = client.post(
        "/api/nodes/heartbeat",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    # The heartbeat is accepted: each bad metric is cleared, not stored.
    assert resp.status_code == 200, resp.text
    stored = persistence.get_nodes()[node]
    assert not (set(bad) | {"cpu_percent"}) & set(stored)
    assert not set(bad) & set(stored["capabilities"])
    (listed,) = [n for n in client.get("/api/nodes/").json() if n["node_id"] == node]
    assert listed["cpu_percent"] == 0.0
    assert listed["status"] == "active"


def test_a_record_saved_with_bad_values_still_reads(client, persistence):
    # What a heartbeat could store before its metrics were checked.
    persistence.set_node(
        "old-node",
        {
            "host": 5,
            "port": "8080",
            "last_seen": "never",
            "registered_at": ["x"],
            "cpu_percent": "high",
            "memory_mb": float("inf"),
            "disk_percent": "full",
            "capabilities": {"cpu_temp": "hot", "scan_count": "<b>", "sdr": "rtl"},
            "detection_summary": {"class_counts": "x"},
            "position_x": "x",
            "floor_label": 5,
        },
    )
    persistence.set_node("future-node", {"last_seen": "2036-01-01T00:00:00+00:00"})
    listing = client.get("/api/nodes/")
    assert listing.status_code == 200, listing.text
    old, future = listing.json()
    assert (old["status"], future["status"]) == ("unknown", "unknown")
    assert (old["host"], old["port"], old["cpu_percent"]) == ("", 0, 0.0)
    assert (old["last_seen"], old["registered_at"]) == (None, None)
    assert old["capabilities"] == {"sdr": "rtl"}
    assert (old["detection_summary"], old["position_x"], old["floor_label"]) == (
        None,
        None,
        "",
    )
    status = client.get("/api/status")
    assert status.status_code == 200, status.text
    assert status.json()["active_nodes"] == 0

    admin_row = client.get("/api/admin/nodes").json()[0]
    assert {k: admin_row[k] for k in ("host", "port", "cpu_percent", "last_seen")} == {
        "host": "",
        "port": 0,
        "cpu_percent": None,
        "last_seen": None,
    }
    diagnostics = client.get("/api/admin/nodes/old-node/diagnostics")
    assert diagnostics.status_code == 200, diagnostics.text
    report = diagnostics.json()
    assert report["system_info"]["cpu_temp"] is None
    assert report["scanners"] == []
    assert report["health_issues"] == ["Node status: unknown"]

    # The alert checks read the saved disk_percent through the same checks.
    assert _heartbeat(client, "old-node") == 200
    assert _fired(persistence, "disk_high", "old-node") == []


def test_stored_location():
    assert stored_location(
        {
            "latitude": -90.0,
            "longitude": 180,
            "altitude_m": 12.5,
            "location_name": "roof",
        }
    ) == {
        "latitude": -90.0,
        "longitude": 180,
        "altitude_m": 12.5,
        "location_name": "roof",
    }
    assert stored_location(
        {
            "latitude": 90,
            "longitude": -180.0,
            "altitude_m": "high",
            "location_name": "x" * 257,
        }
    ) == {"latitude": 90, "longitude": -180.0, "altitude_m": None, "location_name": ""}
    for record in (
        {"latitude": 90.5, "longitude": 0},
        {"latitude": -90.5, "longitude": 0},
        {"latitude": 0, "longitude": 180.5},
        {"latitude": 0, "longitude": -180.5},
        {"latitude": True, "longitude": 0},
        {"latitude": 0, "longitude": float("nan")},
        {"latitude": "1", "longitude": 0},
        {"latitude": None, "longitude": None},
        {"latitude": 0},
    ):
        assert stored_location(record) is None, record


def test_a_record_saved_with_a_bad_location_or_port_still_reads(
    client, persistence, detection_store
):
    # The map, geo and spectrum readers of what a heartbeat could store
    # before its metrics were checked: a bad value reads as absent (no
    # location, the default port, no host), and the other nodes are served
    # as before.
    now = datetime.now(timezone.utc).isoformat()
    persistence.set_node(
        "old-node",
        {
            "host": 5,
            "port": "x",
            "rtl_tcp_port": "x",
            "latitude": "x",
            "longitude": 1.0,
            "status": ["active"],
            "hardware": {"model": "x"},
            "capabilities": ["capture_mode"],
        },
    )
    persistence.set_node("far-node", {"latitude": 91.0, "longitude": 0.0})
    persistence.set_node(
        "mapped-node",
        {
            "host": "192.0.2.20",
            "latitude": 10.5,
            "longitude": -20,
            "altitude_m": 12.5,
            "location_name": "roof",
            "last_seen": now,
            "status": "stale",
            "hardware": "rtl-sdr",
            "capabilities": {"capture_mode": "dual"},
        },
    )
    persistence.set_node(
        "odd-node",
        {
            "latitude": 0,
            "longitude": 0,
            "altitude_m": float("nan"),
            "location_name": ["roof"],
            "last_seen": 7,
            "status": "gone",
        },
    )
    persistence.set_node(
        "port-node", {"host": "192.0.2.30", "port": [8080], "rtl_tcp_port": 0}
    )
    detection_store.insert_batch(
        [
            make_detection(node_id=node_id, timestamp=datetime.now(timezone.utc))
            for node_id in ("old-node", "mapped-node", "mapped-node")
        ]
    )

    geo_map = {n["node_id"]: n for n in client.get("/api/geo/map").json()}
    assert set(geo_map) == {"mapped-node", "odd-node"}
    mapped, odd = geo_map["mapped-node"], geo_map["odd-node"]
    assert (mapped["latitude"], mapped["longitude"]) == (10.5, -20.0)
    assert (mapped["altitude_m"], mapped["location_name"]) == (12.5, "roof")
    assert (mapped["status"], mapped["last_heartbeat"]) == ("active", now)
    assert mapped["detection_count_1h"] == 2
    assert (odd["altitude_m"], odd["location_name"]) == (None, "")
    assert (odd["status"], odd["last_heartbeat"]) == ("unknown", None)
    assert client.get("/api/geo/heatmap").json() == [
        {"latitude": 10.5, "longitude": -20.0, "weight": 2}
    ]
    coverage = client.get("/api/geo/coverage").json()
    assert [c["node_id"] for c in coverage] == ["mapped-node", "odd-node"]
    activity = client.get("/api/geo/activity").json()
    assert [(a["node_id"], a["latitude"]) for a in activity] == [
        ("mapped-node", 10.5),
        ("mapped-node", 10.5),
    ]
    assert {a["location_name"] for a in activity} == {"roof"}
    assert client.get("/api/nodes/locations").json() == [
        {
            "node_id": "mapped-node",
            "latitude": 10.5,
            "longitude": -20,
            "altitude_m": 12.5,
            "location_name": "roof",
            "status": "active",
            "last_seen": now,
        },
        {
            "node_id": "odd-node",
            "latitude": 0,
            "longitude": 0,
            "altitude_m": None,
            "location_name": "",
            "status": "unknown",
            "last_seen": None,
        },
    ]
    assert client.get("/api/maps/overlay").json()["nodes"] == [
        {"node_id": "mapped-node", "lat": 10.5, "lon": -20.0, "status": "stale"},
        {"node_id": "odd-node", "lat": 0.0, "lon": 0.0, "status": "unknown"},
    ]

    spectrum_nodes = {n["node_id"]: n for n in client.get("/api/spectrum/nodes").json()}
    assert spectrum_nodes["old-node"] == {
        "node_id": "old-node",
        "host": "",
        "status": "unknown",
        "hardware": None,
        "rtl_tcp_port": 1234,
        "capture_mode": "",
    }
    assert spectrum_nodes["mapped-node"] == {
        "node_id": "mapped-node",
        "host": "192.0.2.20",
        "status": "stale",
        "hardware": "rtl-sdr",
        "rtl_tcp_port": 1234,
        "capture_mode": "dual",
    }
    assert spectrum_nodes["port-node"]["rtl_tcp_port"] == 1234

    # No valid host: refused, not a 500 or a connection to a coerced "5".
    resp = client.post("/api/spectrum/connect", json={"node_id": "old-node"})
    assert resp.status_code == 409, resp.text
    # Bad stored ports read as the defaults: rtl_tcp 1234, HTTP 8080.
    with (
        patch.object(SpectrumStreamer, "connect", new_callable=AsyncMock) as connect,
        patch.object(_NodeSpectrumPoller, "_fetch_node_status") as fetch,
    ):
        connect.return_value = False
        fetch.return_value = {"service": "rf-edge-monitor"}
        resp = client.post("/api/spectrum/connect", json={"node_id": "port-node"})
    assert resp.status_code == 200, resp.text
    connect.assert_awaited_once_with("192.0.2.30", 1234)
    fetch.assert_called_once_with("http://192.0.2.30:8080/")
    assert (resp.json()["source"], resp.json()["port"]) == ("node_poll", 8080)


def test_a_heartbeat_replaces_saved_capabilities_that_are_not_a_dict(
    client, nodes, persistence
):
    node, _ = nodes
    for saved in ("x", ["agent_version"]):
        data = persistence.get_nodes()[node]
        data["capabilities"] = saved
        persistence.set_node(node, data)
        resp = client.post(
            "/api/nodes/heartbeat",
            json={"node_id": node, "metrics": {"agent_version": "1.4"}},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["config_hash"]
        stored = persistence.get_nodes()[node]["capabilities"]
        assert stored == {"agent_version": "1.4"}, saved


def test_registered_capabilities_named_like_another_metric_are_listed(
    client, persistence
):
    # Only the monitor fields a heartbeat copies into capabilities are
    # checked on read; the admin's other entries are listed as registered.
    capabilities = {
        "status": "lab",
        "gpu_temp": "warm",
        "cpu_percent": "n/a",
        "hardware": {"sdr": "hackrf"},
        "os": 11,
        "sdr": "hackrf",
    }
    resp = client.post(
        "/api/nodes/register",
        json={"node_id": "lab-node", "capabilities": capabilities},
    )
    assert resp.status_code == 200, resp.text
    expected = {
        "status": "lab",
        "gpu_temp": "warm",
        "cpu_percent": "n/a",
        "sdr": "hackrf",
    }
    assert resp.json()["capabilities"] == expected
    (listed,) = client.get("/api/nodes/").json()
    assert listed["capabilities"] == expected
    assert client.get("/api/admin/nodes").json()[0]["capabilities"] == expected
    assert persistence.get_nodes()["lab-node"]["capabilities"] == capabilities


# ---------------------------------------------------------------------------
# Bounded cooldown maps
# ---------------------------------------------------------------------------


def test_bounded_dict_evicts_the_oldest_entry_only_for_new_keys():
    d = BoundedDict(max_size=3)
    for key in ("a", "b", "c"):
        d[key] = 0
    d["a"] = 1  # an update is not a new entry: nothing is evicted
    assert list(d) == ["a", "b", "c"]
    d["d"] = 2
    assert list(d) == ["b", "c", "d"]
    assert len(d) == 3


@pytest.mark.parametrize(
    ("field", "bound"),
    [
        ("anomaly_alert_cooldowns", 50_000),
        ("rule_cooldowns", 10_000),
        ("watch_band_cooldowns", 10_000),
        ("watch_band_counts", 10_000),
    ],
)
def test_app_state_cooldown_maps_are_bounded(field, bound):
    # *bound* is the most memory a map may take (a smaller bound is fine):
    # node- and rule-supplied keys cannot grow it without limit.
    cooldowns = getattr(AppState(), field)
    for i in range(bound + 5):
        cooldowns[f"k{i}"] = i
    assert len(cooldowns) <= bound
    assert "k0" not in cooldowns and f"k{bound + 4}" in cooldowns


# ---------------------------------------------------------------------------
# get_detection_store before start-up finished
# ---------------------------------------------------------------------------


def test_routes_answer_503_before_the_detection_store_exists(bridge_app, master_key):
    bridge_app.state.detection_store = None
    resp = TestClient(bridge_app, headers={"X-API-Key": master_key}).get("/api/geo/map")
    assert resp.status_code == 503
    assert resp.json() == {"detail": "Detection store not initialised"}
