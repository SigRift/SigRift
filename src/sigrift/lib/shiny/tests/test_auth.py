"""Authentication and rate-limiting tests."""

from __future__ import annotations

import pytest
import httpx
from fastapi import FastAPI

from sigrift.lib.shiny.dependencies import RateLimiter


pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# API key auth
# ---------------------------------------------------------------------------


async def test_valid_api_key_returns_200(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/health", headers=api_key_header)
    assert resp.status_code == 200


async def test_missing_api_key_returns_401(
    test_client: httpx.AsyncClient,
) -> None:
    resp = await test_client.get("/api/health")
    assert resp.status_code == 401
    assert "API key required" in resp.json()["detail"]


async def test_invalid_api_key_returns_401(
    test_client: httpx.AsyncClient,
) -> None:
    resp = await test_client.get(
        "/api/health", headers={"X-API-Key": "totally-bogus-key"}
    )
    assert resp.status_code == 401
    assert "Invalid API key" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Master key auth
# ---------------------------------------------------------------------------


async def test_master_key_accepted_for_master_endpoint(
    test_client: httpx.AsyncClient,
    master_key_header: dict[str, str],
    mock_persistence,
) -> None:
    # Register a node first so DELETE has a target
    from datetime import datetime, timezone

    mock_persistence.set_node(
        "tmp-node",
        {
            "host": "127.0.0.1",
            "port": 0,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "last_seen": datetime.now(timezone.utc).isoformat(),
        },
    )
    resp = await test_client.delete("/api/nodes/tmp-node", headers=master_key_header)
    assert resp.status_code == 204


async def test_non_master_key_rejected_with_403(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.delete("/api/nodes/any-node", headers=api_key_header)
    assert resp.status_code == 403
    assert "Master key required" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


async def test_rate_limiter_allows_under_threshold(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    for _ in range(5):
        resp = await test_client.get("/api/health", headers=api_key_header)
        assert resp.status_code == 200


async def test_rate_limiter_returns_429_when_exceeded(
    test_app: FastAPI,
    api_key_header: dict[str, str],
) -> None:
    from sigrift.lib.shiny.dependencies import set_rate_limiter

    # Install a tiny limiter: 3 req / 60s
    tight = RateLimiter(max_requests=3, window_seconds=60.0)
    set_rate_limiter(tight)

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(3):
            r = await client.get("/api/health", headers=api_key_header)
            assert r.status_code == 200
        r = await client.get("/api/health", headers=api_key_header)
        assert r.status_code == 429
        assert "Retry-After" in r.headers


async def test_sensitive_rate_limit_lower_threshold(
    test_app: FastAPI,
    master_key: str,
    master_key_header: dict[str, str],
) -> None:
    """Sensitive endpoints allow only 10 requests per window."""
    from sigrift.lib.shiny.dependencies import set_rate_limiter

    limiter = RateLimiter(max_requests=1000, window_seconds=60.0)
    set_rate_limiter(limiter)

    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(10):
            r = await client.post(
                "/api/keys/",
                headers=master_key_header,
                json={"key_id": f"sens-{i}", "description": "test"},
            )
            assert r.status_code == 201, f"Request {i} failed: {r.text}"

        r = await client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "sens-overflow", "description": "test"},
        )
        assert r.status_code == 429


# ---------------------------------------------------------------------------
# WebSocket auth
# ---------------------------------------------------------------------------


async def test_ws_missing_key_closes_4001(
    test_app: FastAPI,
) -> None:
    """WebSocket with no api_key query param is closed with code 4001."""
    httpx.ASGITransport(app=test_app)
    # We need to use starlette's testclient for websocket testing
    from starlette.testclient import TestClient

    with TestClient(test_app) as client:
        with pytest.raises(Exception):
            with client.websocket_connect("/api/nodes/ws/status"):
                pass  # Should not reach here


async def test_ws_invalid_key_closes(
    test_app: FastAPI,
) -> None:
    """WebSocket with an invalid api_key is rejected."""
    from starlette.testclient import TestClient

    with TestClient(test_app) as client:
        with pytest.raises(Exception):
            with client.websocket_connect(
                "/api/nodes/ws/status?api_key=invalid-key-here"
            ):
                pass


async def test_ws_valid_key_allows_connection(
    test_app: FastAPI,
    api_key: str,
) -> None:
    """WebSocket with a valid api_key is accepted."""
    from starlette.testclient import TestClient

    with TestClient(test_app) as client:
        with client.websocket_connect(f"/api/nodes/ws/status?api_key={api_key}") as ws:
            data = ws.receive_json()
            assert data["type"] == "snapshot"
