"""Training and model management endpoint tests."""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_training_current(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/training/current", headers=api_key_header)
    assert resp.status_code == 200
    body = resp.json()
    assert "running" in body
    assert "run_id" in body
    assert "current_epoch" in body


async def test_training_history(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/training/history", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_training_run_not_found(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/training/runs/nonexistent-run", headers=api_key_header
    )
    assert resp.status_code == 404


async def test_list_models(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/training/models", headers=api_key_header)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_get_model_not_found(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/training/models/nonexistent-model", headers=api_key_header
    )
    assert resp.status_code == 404
