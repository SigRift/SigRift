"""Route reachability and integration tests.

These tests verify that EVERY endpoint in the mounted application is
reachable at its expected path, catching bugs like:
  - Double-prefix mounting (router path + mount prefix)
  - Route ordering conflicts (parameterized paths capturing literal paths)
  - Missing router mounts
  - Incorrect HTTP methods

Each test hits the actual mounted app via the httpx ASGI transport,
exactly as production requests would be routed.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sigrift.lib.taxonomy import CLASSES, CLASS_TO_SF, FAMILY_TO_CLASSES

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Health router (prefix=/api)
# ---------------------------------------------------------------------------


async def test_route_health(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/health", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_route_status(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/status", headers=api_key_header)
    assert resp.status_code == 200
    assert "node_count" in resp.json()


# ---------------------------------------------------------------------------
# Nodes router (prefix=/api/nodes)
# ---------------------------------------------------------------------------


async def test_route_nodes_register(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    resp = await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    assert resp.status_code == 200


async def test_route_nodes_heartbeat(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    node_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.post(
        "/api/nodes/heartbeat",
        headers=node_key_header,
        json={"node_id": "edge-01", "metrics": {"cpu_percent": 10.0}},
    )
    assert resp.status_code == 200


async def test_route_nodes_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/nodes/", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_nodes_activity(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Verify /activity is NOT captured by /{node_id}."""
    resp = await test_client.get("/api/nodes/activity", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_nodes_get_by_id(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.get("/api/nodes/edge-01", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json()["node_id"] == "edge-01"


async def test_route_nodes_command(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.post(
        "/api/nodes/edge-01/command",
        headers=admin_key_header,
        json={"command": "ping"},
    )
    assert resp.status_code == 200


async def test_route_nodes_delete(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    master_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.delete("/api/nodes/edge-01", headers=master_key_header)
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Training router (prefix=/api/training) — was broken by double prefix
# ---------------------------------------------------------------------------


async def test_route_training_current(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Must be /api/training/current, NOT /api/training/training/current."""
    resp = await test_client.get("/api/training/current", headers=api_key_header)
    assert resp.status_code == 200
    assert "running" in resp.json()


async def test_route_training_current_old_path_404(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """The old double-prefix path must NOT be reachable."""
    resp = await test_client.get(
        "/api/training/training/current", headers=api_key_header
    )
    # Should be 404 or 405 — the point is it's NOT 200
    assert resp.status_code != 200


async def test_route_training_history(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/training/history", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_training_runs_404(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/training/runs/nonexistent", headers=api_key_header
    )
    assert resp.status_code == 404


async def test_route_training_models_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/training/models", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_training_model_404(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/training/models/no-such-model", headers=api_key_header
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Jobs router (prefix=/api/jobs) — schedule routes vs {job_id} ordering
# ---------------------------------------------------------------------------


async def test_route_jobs_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/jobs/", headers=api_key_header)
    assert resp.status_code == 200


async def test_route_jobs_presets(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Verify /presets is NOT captured by /{job_id}."""
    resp = await test_client.get("/api/jobs/presets", headers=api_key_header)
    assert resp.status_code == 200
    presets = resp.json()
    assert isinstance(presets, list)
    assert any(p["name"] == "default" for p in presets)


async def test_route_jobs_schedules_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Verify /schedules is NOT captured by /{job_id}."""
    resp = await test_client.get("/api/jobs/schedules", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_jobs_schedules_list_is_not_job_lookup(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Regression: GET /schedules must NOT hit the job_id route and return 404."""
    resp = await test_client.get("/api/jobs/schedules", headers=api_key_header)
    # If route ordering is wrong, this would be 404 ("Job not found: schedules")
    assert resp.status_code == 200
    body = resp.json()
    # Should be a list, not a job object or error
    assert isinstance(body, list)


async def test_route_jobs_schedules_create(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/jobs/schedules",
        headers=analyst_key_header,
        json={
            "name": "test-sched",
            "node_id": "edge-01",
            "interval": "daily",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "test-sched"
    assert "schedule_id" in body


async def test_route_jobs_schedules_crud(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    master_key_header: dict[str, str],
) -> None:
    """Full CRUD on schedules — tests PUT and DELETE work at correct paths."""
    # Create
    create_resp = await test_client.post(
        "/api/jobs/schedules",
        headers=analyst_key_header,
        json={
            "name": "crud-sched",
            "node_id": "edge-01",
            "interval": "hourly",
        },
    )
    assert create_resp.status_code == 201
    sid = create_resp.json()["schedule_id"]

    # Update (PUT)
    put_resp = await test_client.put(
        f"/api/jobs/schedules/{sid}",
        headers=analyst_key_header,
        json={"enabled": False},
    )
    assert put_resp.status_code == 200
    assert put_resp.json()["enabled"] is False

    # Delete (master key required)
    del_resp = await test_client.delete(
        f"/api/jobs/schedules/{sid}", headers=master_key_header
    )
    assert del_resp.status_code == 200


async def test_route_jobs_create_and_get(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    # Create
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    assert create_resp.status_code == 201
    job_id = create_resp.json()["job_id"]

    # Get by ID
    get_resp = await test_client.get(f"/api/jobs/{job_id}", headers=api_key_header)
    assert get_resp.status_code == 200
    assert get_resp.json()["job_id"] == job_id


async def test_route_jobs_priority(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    job_id = create_resp.json()["job_id"]
    resp = await test_client.put(
        f"/api/jobs/{job_id}/priority",
        headers=analyst_key_header,
        json={"priority": 75},
    )
    assert resp.status_code == 200
    assert resp.json()["priority"] == 75


async def test_route_jobs_rerun(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    job_id = create_resp.json()["job_id"]
    resp = await test_client.post(
        f"/api/jobs/{job_id}/rerun", headers=analyst_key_header
    )
    assert resp.status_code == 201
    assert resp.json()["job_id"] != job_id


async def test_route_jobs_delete(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    master_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    job_id = create_resp.json()["job_id"]
    resp = await test_client.delete(f"/api/jobs/{job_id}", headers=master_key_header)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Signals router (prefix=/api/signals)
# ---------------------------------------------------------------------------


async def test_route_signals_classes(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/classes", headers=api_key_header)
    assert resp.status_code == 200
    assert len(resp.json()) == len(CLASSES)


async def test_route_signals_families(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/families", headers=api_key_header)
    assert resp.status_code == 200
    assert len(resp.json()) == len(FAMILY_TO_CLASSES)


async def test_route_signals_super_families(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/signals/super-families", headers=api_key_header)
    assert resp.status_code == 200
    assert len(resp.json()) == len(set(CLASS_TO_SF.values()))


async def test_route_signals_generate(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/signals/generate",
        headers=api_key_header,
        params={"class": "bpsk", "snr": 10.0, "n": 128},
    )
    assert resp.status_code == 200
    assert resp.json()["signal_class"] == "bpsk"


async def test_route_signals_dsp_features(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/signals/dsp-features",
        headers=api_key_header,
        params={"class": "qpsk"},
    )
    assert resp.status_code == 200
    assert "features" in resp.json()


# ---------------------------------------------------------------------------
# Alerts router (prefix=/api/alerts)
# ---------------------------------------------------------------------------


async def test_route_alerts_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/alerts/", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_alerts_history(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Verify /history is NOT captured by /{alert_id}/ack."""
    resp = await test_client.get("/api/alerts/history", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_alerts_create_rule(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Route Test", "severity": "info"},
    )
    assert resp.status_code == 201


async def test_route_alerts_ack(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    create = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Ack Test", "severity": "warning"},
    )
    alert_id = create.json()["alert_id"]
    resp = await test_client.put(
        f"/api/alerts/{alert_id}/ack", headers=analyst_key_header
    )
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] is True


async def test_route_alerts_delete_rule(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    master_key_header: dict[str, str],
) -> None:
    create = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Del Test", "severity": "info"},
    )
    alert_id = create.json()["alert_id"]
    resp = await test_client.delete(
        f"/api/alerts/rules/{alert_id}", headers=master_key_header
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Keys router (prefix=/api/keys)
# ---------------------------------------------------------------------------


async def test_route_keys_list(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/keys/", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_route_keys_create(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "route-test-key"},
    )
    assert resp.status_code == 201
    assert "raw_key" in resp.json()


async def test_route_keys_revoke(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "revoke-route-test"},
    )
    resp = await test_client.delete(
        "/api/keys/revoke-route-test", headers=master_key_header
    )
    assert resp.status_code == 200


async def test_route_keys_rotate(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "rotate-route-test"},
    )
    resp = await test_client.put(
        "/api/keys/rotate-route-test/rotate", headers=master_key_header
    )
    assert resp.status_code == 200
    assert "raw_key" in resp.json()


# ---------------------------------------------------------------------------
# Spectrum router (prefix=/api/spectrum)
# ---------------------------------------------------------------------------


async def test_route_spectrum_status(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/status", headers=api_key_header)
    assert resp.status_code == 200
    assert "connected" in resp.json()


async def test_route_spectrum_config_get(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/config", headers=api_key_header)
    assert resp.status_code == 200
    body = resp.json()
    assert "center_freq_hz" in body
    assert "fft_size" in body


async def test_route_spectrum_config_put(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.put(
        "/api/spectrum/config",
        headers=analyst_key_header,
        json={
            "center_freq_hz": 433920000.0,
            "sample_rate_hz": 2048000.0,
            "gain_db": 40.0,
            "fft_size": 1024,
        },
    )
    assert resp.status_code == 200


async def test_route_spectrum_disconnect(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/disconnect", headers=analyst_key_header)
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Export router (prefix=/api/export)
# ---------------------------------------------------------------------------


async def test_route_export_nodes_json(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/nodes", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body
    assert "nodes" in body


async def test_route_export_nodes_csv(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/nodes", headers=api_key_header, params={"format": "csv"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")


async def test_route_export_training(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/training", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body


async def test_route_export_alerts(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/alerts", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body
    assert "alerts" in body
