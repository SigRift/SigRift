"""Job queue and scheduling endpoint tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_list_jobs_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/jobs/", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_create_job(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "train-baseline"
    assert body["state"] == "queued"
    assert body["priority"] == 50


async def test_get_job_by_id(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    job_id = create_resp.json()["job_id"]

    resp = await test_client.get(f"/api/jobs/{job_id}", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json()["job_id"] == job_id


async def test_get_job_not_found(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/jobs/no-such-job", headers=api_key_header)
    assert resp.status_code == 404


async def test_delete_job_master_key(
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
    assert "removed" in resp.json()["detail"]


async def test_delete_job_regular_key_forbidden(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
    sample_job: dict[str, Any],
) -> None:
    create_resp = await test_client.post(
        "/api/jobs/", headers=analyst_key_header, json=sample_job
    )
    job_id = create_resp.json()["job_id"]

    resp = await test_client.delete(f"/api/jobs/{job_id}", headers=api_key_header)
    assert resp.status_code == 403


async def test_update_job_priority(
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
        json={"priority": 99},
    )
    assert resp.status_code == 200
    assert resp.json()["priority"] == 99


async def test_list_schedules_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/jobs/schedules", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_create_schedule(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/jobs/schedules",
        headers=analyst_key_header,
        json={
            "name": "nightly-capture",
            "node_id": "edge-01",
            "interval": "daily",
            "params": {"duration_s": 3600},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "nightly-capture"
    assert body["interval"] == "daily"
    assert body["enabled"] is True


async def test_list_presets(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/jobs/presets", headers=api_key_header)
    assert resp.status_code == 200
    presets = resp.json()
    assert isinstance(presets, list)
    names = [p["name"] for p in presets]
    assert "default" in names
    assert "fast" in names
    assert "thorough" in names


async def test_rerun_job(
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
    body = resp.json()
    assert body["job_id"] != job_id
    assert body["name"] == "train-baseline"
    assert body["state"] == "queued"
