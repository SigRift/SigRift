"""A session seed can age out of recent results without losing stored history."""

import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from sigrift.lib.security.credentials import generate_api_key, hash_credential


E2E = Path(__file__).parents[1] / "e2e"


def case_body(name):
    module = ast.parse((E2E / "test_sdr_scanner.py").read_text())
    return next(
        n.body for n in module.body if isinstance(n, ast.FunctionDef) and n.name == name
    )


def execute(statements, namespace):
    exec(
        compile(
            ast.Module(body=statements, type_ignores=[]),
            str(E2E / "test_sdr_scanner.py"),
            "exec",
        ),
        namespace,
    )


@pytest.fixture(params=["node", "sensor"])
def aged_scanner(request, client, bridge_app, persistence):
    node_id = "freshness-real-" + request.param
    persistence.set_node(node_id, {"node_id": node_id, "host": "synthetic.invalid"})
    token = generate_api_key(length=32)
    digest, salt = hash_credential(token)
    persistence.set_key("freshness-key", digest, salt)
    persistence.set_key_meta(
        "freshness-key", {"role": request.param, "node_id": node_id}
    )
    old = datetime.now(timezone.utc) - timedelta(minutes=6)
    old_id = "aged-session-seed-" + request.param
    batch = {
        "node_id": node_id,
        "batch_id": old_id,
        "period_start": old.isoformat(),
        "period_end": old.isoformat(),
        "detections": [
            {
                "detection_id": old_id,
                "node_id": node_id,
                "timestamp": old.isoformat(),
                "signal_class": "bpsk",
                "confidence": 0.98,
                "freq_hz": 433920000,
                "snr_db": 24,
            }
        ],
    }
    with TestClient(bridge_app, headers={"X-API-Key": token}) as sensor:
        response = sensor.post("/api/detections/batch", json=batch)
        assert response.status_code == 201
        assert response.json()["inserted"] == 1
        recent = client.get("/api/detections/recent?limit=100").json()
        assert recent["minutes"] == 5
        assert old_id not in {r["detection_id"] for r in recent["detections"]}
        stored = client.get("/api/detections/" + old_id)
        assert stored.status_code == 200
        original = stored.json()
        assert datetime.fromisoformat(original["timestamp"]) == old
        calls = []

        def request_api(method, path, body=None, **kwargs):
            assert kwargs["key"] == token
            actual = sensor.request(
                method, path, json=body, headers={"X-API-Key": kwargs["key"]}
            )
            # Direct Bridge creates201; native gateway's batch contract is200.
            # Preserve the actual direct response and validate its own status.
            assert actual.status_code == (
                201 if method == "POST" and path == "/api/detections/batch" else 200
            )
            calls.append((method, path, body, actual.json()))
            return actual.json()

        def admin_request(method, path, body=None, **kwargs):
            actual = client.request(method, path, json=body)
            assert actual.status_code == 200
            return actual.json()

        def observe():
            # Use the shipped fixture helper, not a duplicate ingest algorithm.
            from tests.e2e.conftest import fresh_rf_observation

            return fresh_rf_observation(
                SimpleNamespace(request=request_api), {"raw_key": token}, node_id
            )

        yield {
            "node_id": node_id,
            "detection_id": old_id,
            "observe_rf": observe,
            "admin": SimpleNamespace(request=admin_request),
            "sensor": sensor,
            "original": original,
            "calls": calls,
        }


def test_feed_api_assertions_use_a_new_authenticated_observation(aged_scanner, client):
    body = case_body("test_synthetic_detection_reaches_api_and_visible_feed")
    end = next(
        i
        for i, n in enumerate(body)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "stats" for t in n.targets)
    )
    namespace = {"admin_api": aged_scanner["admin"], "synthetic_scanner": aged_scanner}
    execute(body[:end], namespace)
    calls = aged_scanner["calls"]
    assert len(calls) == 1
    batch = calls[0][2]
    assert calls[0][:2] == ("POST", "/api/detections/batch")
    assert len(batch["detections"]) == 1
    fresh = batch["detections"][0]
    assert "timestamp" not in fresh  # Actual server admission time, no aging rewrite.
    assert fresh["detection_id"] != aged_scanner["detection_id"]
    current = client.get("/api/detections/" + fresh["detection_id"]).json()
    assert datetime.now(timezone.utc) - datetime.fromisoformat(
        current["timestamp"]
    ) < timedelta(seconds=30)
    assert (
        client.get("/api/detections/" + aged_scanner["detection_id"]).json()
        == aged_scanner["original"]
    )


@pytest.mark.parametrize("loss", [None, "deleted", "changed"])
def test_history_assertions_survive_real_scanner_lifecycle_after_recent_expiry(
    aged_scanner, detection_store, loss
):
    body = case_body(
        "test_sdr_views_require_a_live_scanner_and_stop_without_losing_history"
    )
    namespace = {"admin_api": aged_scanner["admin"], "synthetic_scanner": aged_scanner}
    before_page = next(
        i
        for i, n in enumerate(body)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "page" for t in n.targets)
    )
    execute(body[:before_page], namespace)
    assert namespace["stored_before"] == aged_scanner["original"]
    sensor = aged_scanner["sensor"]
    path = f"/api/nodes/{aged_scanner['node_id']}/scanner-status"
    for state in ("running", "stopped"):
        response = sensor.post(path, json={"protocol": "sdr", "state": state})
        assert response.status_code == 200
        assert response.json()["active"] is (state == "running")
    if loss:
        # Deliberately remove/change a stored value to prove that the new
        # history oracle rejects actual loss, without changing its timestamp.
        conn = detection_store.get_connection()
        if loss == "deleted":
            conn.execute(
                "DELETE FROM detections WHERE detection_id = ?",
                (aged_scanner["detection_id"],),
            )
        else:
            conn.execute(
                "UPDATE detections SET confidence = .25 WHERE detection_id = ?",
                (aged_scanner["detection_id"],),
            )
        conn.commit()
        with pytest.raises(AssertionError):
            execute(body[-2:], namespace)
    else:
        execute(body[-2:], namespace)
