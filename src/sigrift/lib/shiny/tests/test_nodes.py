"""Node management endpoint tests."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_register_node_valid(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    resp = await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_id"] == "edge-01"
    assert body["host"] == "192.168.1.100"


async def test_register_node_invalid_id(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/nodes/register",
        headers=admin_key_header,
        json={"node_id": "bad node id!!", "host": "x"},
    )
    assert resp.status_code == 422


async def test_heartbeat_updates_last_seen(
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
        json={"node_id": "edge-01", "metrics": {"cpu_percent": 42.0}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["accepted"] is True
    assert body["node_id"] == "edge-01"


async def test_list_nodes(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.get("/api/nodes/", headers=api_key_header)
    assert resp.status_code == 200
    nodes = resp.json()
    assert isinstance(nodes, list)
    assert len(nodes) >= 1


async def test_get_node_by_id(
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


async def test_get_node_not_found(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/nodes/nonexistent", headers=api_key_header)
    assert resp.status_code == 404


async def test_delete_node_with_master_key(
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


async def test_delete_node_with_regular_key_forbidden(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.delete("/api/nodes/edge-01", headers=api_key_header)
    assert resp.status_code == 403


async def test_queue_command_valid(
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
    body = resp.json()
    assert body["command"] == "ping"
    assert body["status"] == "queued"


@pytest.mark.parametrize(
    "command",
    # capture_start / capture_stop: the node agent has no handler for them.
    # PING / " ping" / "ping ": the agent matches names exactly, so a case or
    # whitespace variant of an allowlisted name is dropped on the node too.
    ["rm_rf_everything", "capture_start", "capture_stop", "PING", " ping", "ping "],
)
async def test_queue_command_disallowed(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
    command: str,
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.post(
        "/api/nodes/edge-01/command",
        headers=admin_key_header,
        json={"command": command},
    )
    assert resp.status_code == 422
    activity = await test_client.get("/api/nodes/activity", headers=admin_key_header)
    assert not any(e.get("event_type") == "command_queued" for e in activity.json())


async def test_get_activity(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    # Generate some activity
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.get("/api/nodes/activity", headers=api_key_header)
    assert resp.status_code == 200
    activity = resp.json()
    assert isinstance(activity, list)
    assert len(activity) >= 1
    assert activity[-1]["event_type"] == "node_registered"
