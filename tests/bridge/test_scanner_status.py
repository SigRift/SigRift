"""Real node-authenticated scanner leases; host liveness is not capture health."""

from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import nodes
from sigrift.bridge.scanner_status import scanner_status_snapshot
from sigrift.bridge.state import AppState
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture
def scanner_api(tmp_path, monkeypatch):
    """Mount the shipped router with actual persistence, auth and node binding."""
    monkeypatch.setenv("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "0")
    persistence = PersistenceManager(tmp_path / "data", auto_save_interval=0)
    persistence.load_all()
    app = FastAPI()
    app.state.persistence = persistence
    app.state.app_state = AppState()
    app.include_router(nodes.router, prefix="/api/nodes")
    now = [datetime.now(timezone.utc)]
    monkeypatch.setattr(nodes, "_utcnow", lambda: now[0])
    keys = {}

    def key(name, role, node_id=None):
        raw = generate_api_key()
        hashed, salt = hash_credential(raw)
        meta = {"role": role}
        if node_id:
            meta["node_id"] = node_id
        assert persistence.add_key(
            name, hashed, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
        )
        keys[name] = {"X-API-Key": raw}
        return keys[name]

    key("admin", "admin")
    with TestClient(app) as client:
        for node_id in ("radio-one", "radio-two"):
            response = client.post(
                "/api/nodes/register",
                headers=keys["admin"],
                json={"node_id": node_id},
            )
            assert response.status_code == 200
        key("sensor", "sensor", "radio-one")
        yield client, persistence, now, keys, key


def report(api, protocol="wifi", state="running", *, node="radio-one", key="sensor"):
    client, _, _, keys, _ = api
    return client.post(
        f"/api/nodes/{node}/scanner-status",
        headers=keys[key],
        json={"protocol": protocol, "state": state},
    )


def node(api, name="radio-one"):
    client, _, _, keys, _ = api
    response = client.get(f"/api/nodes/{name}", headers=keys["admin"])
    assert response.status_code == 200
    return response.json()


def test_registration_and_generic_heartbeat_do_not_claim_scanning(scanner_api):
    client, _, _, keys, _ = scanner_api
    assert (
        client.post(
            "/api/nodes/register",
            headers=keys["admin"],
            json={
                "node_id": "radio-one",
                "capabilities": {"hardware": "USB SDR", "capture_mode": "wifi"},
            },
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/nodes/heartbeat",
            headers=keys["sensor"],
            json={"node_id": "radio-one", "metrics": {"classifications_per_sec": 20}},
        ).status_code
        == 200
    )
    current = node(scanner_api)
    assert current["status"] == "active"
    assert current["scanner_status"] == {}


def test_server_lease_is_not_renewed_or_forged_by_monitor_metrics(scanner_api):
    client, _, now, keys, _ = scanner_api
    response = report(scanner_api)
    assert response.status_code == 200
    original = response.json()
    assert original["active"] and original["expires_in_seconds"] == 120
    now[0] += timedelta(seconds=65)
    assert (
        client.post(
            "/api/nodes/heartbeat",
            headers=keys["sensor"],
            json={
                "node_id": "radio-one",
                "metrics": {
                    "scanner_status": {"zigbee": {"active": True}},
                    "_scanner_reports": {
                        "zigbee": {
                            "state": "running",
                            "reported_at": now[0].isoformat(),
                        }
                    },
                },
            },
        ).status_code
        == 200
    )
    current = node(scanner_api)["scanner_status"]
    assert set(current) == {"wifi"}
    assert current["wifi"]["reported_at"] == original["reported_at"]
    assert current["wifi"]["expires_in_seconds"] == 55
    now[0] += timedelta(seconds=55)
    current = node(scanner_api)["scanner_status"]["wifi"]
    assert current["active"] is False and current["expires_in_seconds"] == 0


@pytest.mark.parametrize("state", ["stopped", "error"])
def test_stop_or_error_invalidates_immediately_and_restart_renews(scanner_api, state):
    assert report(scanner_api).json()["active"]
    stopped = report(scanner_api, state=state).json()
    assert stopped["state"] == state and not stopped["active"]
    assert stopped["expires_in_seconds"] == 0
    assert node(scanner_api)["scanner_status"]["wifi"] == stopped
    assert report(scanner_api).json()["active"]


def test_protocol_and_node_leases_are_independent_and_visible_in_snapshot(scanner_api):
    client, _, now, keys, _ = scanner_api
    assert report(scanner_api, "sdr").status_code == 200
    now[0] += timedelta(seconds=40)
    assert report(scanner_api, "wifi").status_code == 200
    assert (
        report(scanner_api, "zigbee", node="radio-two", key="admin").status_code == 200
    )
    now[0] += timedelta(seconds=80)
    rows = client.get("/api/nodes/", headers=keys["admin"]).json()
    first, second = (
        next(row for row in rows if row["node_id"] == name)
        for name in ("radio-one", "radio-two")
    )
    assert not first["scanner_status"]["sdr"]["active"]
    assert first["scanner_status"]["wifi"]["active"]
    assert second["scanner_status"]["zigbee"]["active"]


def test_unauthenticated_wrong_node_and_dashboard_only_keys_cannot_write(scanner_api):
    client, _, _, keys, key = scanner_api
    path = "/api/nodes/radio-one/scanner-status"
    body = {"protocol": "wifi", "state": "running"}
    assert client.post(path, json=body).status_code == 401
    assert (
        client.post(path, json=body, headers={"X-API-Key": "invalid"}).status_code
        == 401
    )
    assert report(scanner_api, node="radio-two").status_code == 403
    key("viewer", "viewer")
    assert client.post(path, json=body, headers=keys["viewer"]).status_code == 403
    assert node(scanner_api)["scanner_status"] == {}
    assert node(scanner_api, "radio-two")["scanner_status"] == {}


def test_unknown_node_does_not_claim_unbound_sensor_key(scanner_api):
    client, persistence, _, _, key = scanner_api
    headers = key("unbound", "sensor")
    response = client.post(
        "/api/nodes/missing/scanner-status",
        headers=headers,
        json={"protocol": "wifi", "state": "running"},
    )
    assert response.status_code == 404
    assert not persistence.get_key_meta()["unbound"].get("node_id")
    response = client.post(
        "/api/nodes/radio-two/scanner-status",
        headers=headers,
        json={"protocol": "wifi", "state": "running"},
    )
    assert response.status_code == 200
    assert persistence.get_key_meta()["unbound"]["node_id"] == "radio-two"


@pytest.mark.parametrize(
    "body",
    [
        {"protocol": "usb", "state": "running"},
        {"protocol": "wifi", "state": True},
        {"protocol": "wifi", "state": "starting"},
        {"protocol": "wifi", "state": "running", "reported_at": "2099-01-01T00:00:00Z"},
        {"protocol": "wifi", "state": "running", "expires_in_seconds": 9999},
        {"protocol": "wifi"},
    ],
)
def test_invalid_status_or_client_expiry_cannot_enable_scanner(scanner_api, body):
    client, _, _, keys, _ = scanner_api
    response = client.post(
        "/api/nodes/radio-one/scanner-status", headers=keys["sensor"], json=body
    )
    assert response.status_code == 422
    assert node(scanner_api)["scanner_status"] == {}


def test_saved_lease_keeps_original_expiry_after_persistence_reload(scanner_api):
    _, persistence, now, _, _ = scanner_api
    assert report(scanner_api).json()["active"]
    persistence.save_all()
    loaded = PersistenceManager(persistence.data_dir, auto_save_interval=0)
    loaded.load_all()
    now[0] += timedelta(seconds=119)
    row = nodes._node_to_response("radio-one", loaded.get_nodes()["radio-one"])
    assert row.scanner_status["wifi"].expires_in_seconds == 1
    now[0] += timedelta(seconds=1)
    assert (
        not nodes._node_to_response("radio-one", loaded.get_nodes()["radio-one"])
        .scanner_status["wifi"]
        .active
    )


@pytest.mark.parametrize(
    "records",
    [
        None,
        [],
        {"wifi": []},
        {"wifi": {"state": "running"}},
        {"wifi": {"state": "running", "reported_at": "garbage"}},
        {"wifi": {"state": "running", "reported_at": 123}},
        {"wifi": {"state": "running", "reported_at": "2026-01-01T00:00:00"}},
        {"wifi": {"state": "running", "reported_at": "2099-01-01T00:00:00Z"}},
        {"wifi": {"state": "installed", "reported_at": "2026-01-01T00:00:00Z"}},
    ],
)
def test_invalid_or_future_saved_report_does_not_enable_any_scanner(records):
    assert (
        scanner_status_snapshot(records, datetime(2026, 1, 1, tzinfo=timezone.utc))
        == {}
    )


@pytest.mark.parametrize("role", ["sensor", "node"])
def test_node_bound_worker_roles_can_report_but_revocation_stops_renewal(
    scanner_api, role
):
    _, persistence, _, _, key = scanner_api
    key("worker", role, "radio-one")
    assert report(scanner_api, key="worker").status_code == 200
    assert persistence.remove_key("worker")
    assert report(scanner_api, key="worker").status_code == 401


def test_report_pushes_real_websocket_snapshot_without_waiting_for_heartbeat(
    scanner_api,
):
    client, _, _, keys, _ = scanner_api
    with client.websocket_connect(
        "/api/nodes/ws/status", subprotocols=["bridge-v1", keys["admin"]["X-API-Key"]]
    ) as ws:
        assert ws.receive_json()["type"] == "snapshot"
        assert report(scanner_api).status_code == 200
        current = next(
            row for row in ws.receive_json()["nodes"] if row["node_id"] == "radio-one"
        )
        assert current["scanner_status"]["wifi"]["active"] is True
        assert report(scanner_api, state="stopped").status_code == 200
        current = next(
            row for row in ws.receive_json()["nodes"] if row["node_id"] == "radio-one"
        )
        assert current["scanner_status"]["wifi"]["active"] is False


@pytest.mark.parametrize("slow_route", ["heartbeat", "scanner-status"])
@pytest.mark.parametrize("peer_operation", ["report", "delete"])
def test_overlapping_binding_checks_preserve_new_reports_and_deleted_nodes(
    scanner_api, monkeypatch, slow_route, peer_operation
):
    """Actual authenticated requests overlap at the existing async binding boundary."""
    import asyncio
    import threading

    client, _, _, keys, key = scanner_api
    key("slow-worker", "node", "radio-one")
    waiting, release = threading.Event(), threading.Event()
    original = nodes.enforce_node_binding

    async def paused_binding(request, principal, node_id):
        await original(request, principal, node_id)
        if principal == "slow-worker":
            waiting.set()
            assert await asyncio.to_thread(release.wait, 3)

    monkeypatch.setattr(nodes, "enforce_node_binding", paused_binding)
    responses = []
    errors = []

    def slow_request():
        try:
            if slow_route == "heartbeat":
                responses.append(
                    client.post(
                        "/api/nodes/heartbeat",
                        headers=keys["slow-worker"],
                        json={"node_id": "radio-one", "metrics": {"cpu_percent": 42}},
                    )
                )
            else:
                responses.append(report(scanner_api, "wifi", key="slow-worker"))
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=slow_request)
    thread.start()
    try:
        assert waiting.wait(2)
        if peer_operation == "report":
            assert report(scanner_api, "sdr").status_code == 200
        else:
            assert (
                client.delete("/api/nodes/radio-one", headers=keys["admin"]).status_code
                == 204
            )
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and not errors
    assert len(responses) == 1
    if peer_operation == "delete":
        assert responses[0].status_code == 404
        assert (
            client.get("/api/nodes/radio-one", headers=keys["admin"]).status_code == 404
        )
    else:
        assert responses[0].status_code == 200
        expected = {"sdr"} if slow_route == "heartbeat" else {"sdr", "wifi"}
        assert set(node(scanner_api)["scanner_status"]) == expected
