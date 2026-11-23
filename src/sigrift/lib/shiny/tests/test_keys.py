"""API key management endpoint tests."""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_create_key_returns_raw_key(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "node-01", "description": "Edge node key"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["key_id"] == "node-01"
    assert "raw_key" in body
    assert len(body["raw_key"]) > 16
    assert "Save this key now" in body["message"]


async def test_create_duplicate_key_returns_409(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "dup-key"},
    )
    resp = await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "dup-key"},
    )
    assert resp.status_code == 409


async def test_list_keys_masked(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    master_key_header: dict[str, str],
) -> None:
    # Create a key first
    await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "list-key"},
    )
    resp = await test_client.get("/api/keys/", headers=api_key_header)
    assert resp.status_code == 200
    keys = resp.json()
    assert isinstance(keys, list)
    # Ensure no raw keys are exposed
    for k in keys:
        assert "raw_key" not in k
        assert "hash" not in k
        assert "salt" not in k
        assert "key_id" in k


async def test_revoke_key_with_master(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "revoke-me"},
    )
    resp = await test_client.delete("/api/keys/revoke-me", headers=master_key_header)
    assert resp.status_code == 200
    assert resp.json()["revoked"] == "revoke-me"


async def test_revoke_nonexistent_key(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    resp = await test_client.delete("/api/keys/ghost-key", headers=master_key_header)
    assert resp.status_code == 404


async def test_rotate_key_returns_new_raw(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    # Create a key
    create_resp = await test_client.post(
        "/api/keys/",
        headers=master_key_header,
        json={"key_id": "rotate-me"},
    )
    original_raw = create_resp.json()["raw_key"]

    # Rotate it
    resp = await test_client.put(
        "/api/keys/rotate-me/rotate", headers=master_key_header
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "raw_key" in body
    assert body["raw_key"] != original_raw
    assert "Save this key now" in body["message"]


async def test_rotate_nonexistent_key(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
) -> None:
    resp = await test_client.put(
        "/api/keys/ghost-key/rotate", headers=master_key_header
    )
    assert resp.status_code == 404


async def test_create_key_requires_master(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/keys/",
        headers=api_key_header,
        json={"key_id": "should-fail"},
    )
    assert resp.status_code == 403
