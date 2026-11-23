"""Role checks on every node and alert route (``routers/nodes.py``,
``routers/alerts.py``).

For each HTTP route (the setup-readiness report has its own tests), every
role below the route's minimum is refused — 401 without credentials, 403
naming the required role otherwise — and a refused request changes nothing
(nodes, alerts, rules, queued commands and their history, the activity
log, known RF patterns, the audit log).  The minimum role then succeeds
(2xx).
Node-scoped keys are bound to the node, so the binding check is not what
refuses them.

Also: command acks honour the node binding; deleting or tasking an
unknown node changes nothing (a node registering under that id later
is handed no command); command history is newest first.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_LADDER = ["anonymous", "sensor", "node", "viewer", "analyst", "admin"]


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


def _add_key(
    persistence: PersistenceManager, key_id: str, role: str, node_id: str | None = None
) -> str:
    raw = generate_api_key(32)
    digest, salt = hash_credential(raw)
    meta: dict[str, Any] = {"role": role, "description": "", "created_at": ""}
    if node_id is not None:
        meta["node_id"] = node_id
    assert persistence.add_key(
        key_id, digest, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


@pytest.fixture
def world(bridge_app: FastAPI, client: TestClient, persistence: PersistenceManager):
    """A registered node with a queued command, an alert and a condition rule,
    and a client per role (scanner keys bound to the node)."""
    assert client.post("/api/nodes/register", json={"node_id": "n1"}).status_code == 200
    cmd = client.post("/api/nodes/n1/command", json={"command": "restart"})
    assert cmd.status_code == 200, cmd.text
    rule = client.post(
        "/api/alerts/rules/conditions",
        json={
            "name": "wide",
            "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
        },
    )
    assert rule.status_code == 201, rule.text
    persistence.add_alert(
        {
            "alert_id": "a1",
            "name": "anomaly_detected",
            "severity": "warning",
            "message": "m",
            "node_id": "n1",
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "acknowledged": False,
            "acknowledged_at": None,
        }
    )
    clients = {"anonymous": TestClient(bridge_app), "admin": client}
    for role in ("sensor", "node", "viewer", "analyst"):
        node_id = "n1" if role in ("sensor", "node") else None
        raw = _add_key(persistence, f"{role}_key", role, node_id)
        clients[role] = TestClient(bridge_app, headers={"X-API-Key": raw})
    observer = TestClient(
        bridge_app, headers={"X-API-Key": _add_key(persistence, "observer", "viewer")}
    )
    return {
        "clients": clients,
        "observer": observer,
        "cmd": cmd.json()["command_id"],
        "rule": rule.json()["rule_id"],
    }


def _commands(observer: TestClient) -> list[tuple[str, str]]:
    """Command history as the API reports it: (command_id, status)."""
    resp = observer.get("/api/nodes/commands")
    assert resp.status_code == 200, resp.text
    return [(c["command_id"], c["status"]) for c in resp.json()]


def _activity(observer: TestClient) -> list[dict[str, Any]]:
    resp = observer.get("/api/nodes/activity", params={"limit": 1000})
    assert resp.status_code == 200, resp.text
    return resp.json()


def _state(app: FastAPI, observer: TestClient) -> dict[str, Any]:
    persistence = app.state.persistence
    store = app.state.detection_store
    return {
        "nodes": copy.deepcopy(persistence.get_nodes()),
        "alerts": copy.deepcopy(persistence.get_alerts()),
        "rules": copy.deepcopy(persistence.get_alert_rules()),
        # Every queued, dispatched, acked or cancelled command shows here.
        "commands": _commands(observer),
        "activity": _activity(observer),
        "known": store.known_signals.list(),
        "audit": len(store.get_audit_log(limit=1000)),
    }


_KNOWN = {
    "freq_min_hz": 433.0e6,
    "freq_max_hz": 434.0e6,
    "signal_class": "bpsk",
    "node_id": "n1",
}

# (method, path, body, minimum role); {cmd} / {rule} are filled in by the
# test.  The minimum role's own calls run in this order on one app, so the
# routes that remove the node, the rule or the alert come last.
_ROUTES: list[tuple[str, str, Any, str]] = [
    # nodes
    ("POST", "/api/nodes/heartbeat", {"node_id": "n1"}, "sensor"),
    (
        "POST",
        "/api/nodes/n1/scanner-status",
        {"protocol": "sdr", "state": "running"},
        "sensor",
    ),
    ("POST", "/api/nodes/register", {"node_id": "n2"}, "admin"),
    ("POST", "/api/nodes/n1/command", {"command": "restart"}, "admin"),
    ("PUT", "/api/nodes/n1/location", {"latitude": 1.0, "longitude": 2.0}, "admin"),
    ("PATCH", "/api/nodes/n1/position", {"x": 1.0, "y": 2.0}, "admin"),
    ("POST", "/api/nodes/n1/capture", {"freq_hz": 433.92e6}, "analyst"),
    ("POST", "/api/nodes/n1/commands/{cmd}/ack", None, "node"),
    ("GET", "/api/nodes/", None, "viewer"),
    ("GET", "/api/nodes/n1", None, "viewer"),
    ("GET", "/api/nodes/commands", None, "viewer"),
    ("GET", "/api/nodes/activity", None, "viewer"),
    ("GET", "/api/nodes/locations", None, "viewer"),
    ("GET", "/api/nodes/setup-checklist", None, "viewer"),
    # alerts
    ("POST", "/api/alerts/rules", {"name": "legacy"}, "analyst"),
    ("PUT", "/api/alerts/a1/ack", {"note": "seen", "escalated": True}, "analyst"),
    (
        "POST",
        "/api/alerts/rules/conditions",
        {
            "name": "r",
            "conditions": [{"field": "snr_db", "operator": "gt", "value": 3}],
        },
        "analyst",
    ),
    ("PUT", "/api/alerts/rules/conditions/{rule}", {"enabled": False}, "analyst"),
    ("POST", "/api/alerts/rules/conditions/{rule}/test", None, "analyst"),
    ("POST", "/api/alerts/analysis/known", _KNOWN, "analyst"),
    ("GET", "/api/alerts/", None, "viewer"),
    ("GET", "/api/alerts/history", None, "viewer"),
    ("GET", "/api/alerts/analysis", None, "viewer"),
    ("GET", "/api/alerts/rules/conditions", None, "viewer"),
    ("GET", "/api/alerts/rules/conditions/{rule}", None, "viewer"),
    # removals
    ("DELETE", "/api/alerts/rules/conditions/{rule}", None, "analyst"),
    ("DELETE", "/api/alerts/rules/a1", None, "admin"),
    ("DELETE", "/api/nodes/n1", None, "admin"),
]


def test_roles_below_the_minimum_are_refused_and_change_nothing(bridge_app, world):
    # One app for every route (an app per route costs CI minutes).
    failures: list[str] = []
    for method, template, body, minimum in _ROUTES:
        path = template.format(cmd=world["cmd"], rule=world["rule"])
        before = _state(bridge_app, world["observer"])
        for role in _LADDER[: _LADDER.index(minimum)]:
            resp = world["clients"][role].request(method, path, json=body)
            if role == "anonymous":
                ok = resp.status_code == 401
            else:
                ok = resp.status_code == 403 and resp.json()["detail"] == (
                    f"{minimum.capitalize()} role required"
                )
            if not ok:
                failures.append(
                    f"{method} {path} as {role}: {resp.status_code} {resp.text}"
                )
            if _state(bridge_app, world["observer"]) != before:
                failures.append(f"{method} {path} as {role} changed the state")
        resp = world["clients"][minimum].request(method, path, json=body)
        if not 200 <= resp.status_code < 300:
            failures.append(
                f"{method} {path} as {minimum}: {resp.status_code} {resp.text}"
            )
    assert failures == []


# ---------------------------------------------------------------------------
# Node commands
# ---------------------------------------------------------------------------


def test_command_ack_is_bound_to_the_keys_node(bridge_app, client, persistence):
    for node_id in ("n1", "n2"):
        assert (
            client.post("/api/nodes/register", json={"node_id": node_id}).status_code
            == 200
        )
    cmd = client.post("/api/nodes/n2/command", json={"command": "status"}).json()
    other = TestClient(
        bridge_app, headers={"X-API-Key": _add_key(persistence, "k1", "node", "n1")}
    )
    resp = other.post(f"/api/nodes/n2/commands/{cmd['command_id']}/ack")
    assert resp.status_code == 403
    # Acking it as its own node id does not find another node's command.
    resp = other.post(f"/api/nodes/n1/commands/{cmd['command_id']}/ack")
    assert resp.status_code == 404
    assert _commands(client) == [(cmd["command_id"], "queued")]
    own = TestClient(
        bridge_app, headers={"X-API-Key": _add_key(persistence, "k2", "node", "n2")}
    )
    resp = own.post(f"/api/nodes/n2/commands/{cmd['command_id']}/ack")
    assert resp.status_code == 200
    assert resp.json()["status"] == "acked"
    assert _commands(client) == [(cmd["command_id"], "acked")]


def test_unknown_node_cannot_be_deleted_or_tasked(client):
    resp = client.delete("/api/nodes/ghost")
    assert resp.status_code == 404
    resp = client.post("/api/nodes/ghost/command", json={"command": "restart"})
    assert resp.status_code == 404
    assert _commands(client) == []
    assert not [e for e in _activity(client) if e.get("node_id") == "ghost"]
    # A node registering under that id later is handed nothing.
    assert (
        client.post("/api/nodes/register", json={"node_id": "ghost"}).status_code == 200
    )
    resp = client.post("/api/nodes/heartbeat", json={"node_id": "ghost"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["pending_commands"] == []


def test_command_history_is_newest_first(client):
    assert client.post("/api/nodes/register", json={"node_id": "n1"}).status_code == 200
    ids = [
        client.post("/api/nodes/n1/command", json={"command": c}).json()["command_id"]
        for c in ("status", "ping", "restart")
    ]
    history = client.get("/api/nodes/commands").json()
    assert [h["command_id"] for h in history] == ids[::-1]
    assert [h["command"] for h in history] == ["restart", "ping", "status"]
