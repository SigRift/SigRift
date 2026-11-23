"""Shared fixtures for the SigRift Shiny dashboard test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny.dependencies import RateLimiter, set_config, set_rate_limiter
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.routers import (
    alerts,
    export,
    health,
    jobs,
    keys,
    nodes,
    signals,
    spectrum,
    training,
)
from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer
from sigrift.lib.shiny.state import AppState
from sigrift.lib.config import MLRFConfig
from sigrift.lib.validation_errors import install_validation_handler


@pytest.fixture(autouse=True)
def _no_node_binding_opt_ins(monkeypatch: pytest.MonkeyPatch) -> None:
    """Node-key binding opt-ins come only from the test that sets them."""
    monkeypatch.delenv("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", raising=False)
    monkeypatch.delenv("SHINY_LEGACY_KEY_TOFU", raising=False)


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_persistence(tmp_path: Path) -> PersistenceManager:
    """PersistenceManager backed by a temp directory, auto-save disabled."""
    pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
    pm.load_all()
    return pm


# ---------------------------------------------------------------------------
# App state
# ---------------------------------------------------------------------------


@pytest.fixture()
def mock_app_state() -> AppState:
    return AppState()


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_key(mock_persistence: PersistenceManager) -> str:
    """A valid test API key (no stored role, so a viewer) in the key store."""
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    mock_persistence.set_key("test-user", hash_hex, salt)
    return raw


@pytest.fixture()
def api_key_header(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


@pytest.fixture()
def node_key(mock_persistence: PersistenceManager) -> str:
    """A viewer node key bound to ``edge-01`` (the ``sample_node``).

    Heartbeats need a key bound to the node (or an unbound ``node`` key):
    a key with no stored purpose, like ``api_key``, is refused.
    """
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    mock_persistence.set_key(
        "test-node", hash_hex, salt, meta={"purpose": "node", "node_id": "edge-01"}
    )
    return raw


@pytest.fixture()
def node_key_header(node_key: str) -> dict[str, str]:
    return {"X-API-Key": node_key}


@pytest.fixture()
def analyst_key(mock_persistence: PersistenceManager) -> str:
    """A key with the analyst role (may write alerts, jobs and schedules)."""
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    mock_persistence.set_key("test-analyst", hash_hex, salt, meta={"role": "analyst"})
    return raw


@pytest.fixture()
def analyst_key_header(analyst_key: str) -> dict[str, str]:
    return {"X-API-Key": analyst_key}


@pytest.fixture()
def admin_key(mock_persistence: PersistenceManager) -> str:
    """A non-master key with the admin role (may register nodes / queue commands)."""
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    mock_persistence.set_key("test-admin", hash_hex, salt, meta={"role": "admin"})
    return raw


@pytest.fixture()
def admin_key_header(admin_key: str) -> dict[str, str]:
    return {"X-API-Key": admin_key}


@pytest.fixture()
def master_key(mock_persistence: PersistenceManager) -> str:
    """Generate a master API key and register it."""
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    mock_persistence.set_key("master", hash_hex, salt)
    return raw


@pytest.fixture()
def master_key_header(master_key: str) -> dict[str, str]:
    return {"X-API-Key": master_key}


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


@pytest.fixture()
def rate_limiter() -> RateLimiter:
    """High-limit rate limiter for testing."""
    return RateLimiter(max_requests=1000, window_seconds=60.0)


# ---------------------------------------------------------------------------
# FastAPI test app
# ---------------------------------------------------------------------------


@pytest.fixture()
def test_app(
    mock_persistence: PersistenceManager,
    mock_app_state: AppState,
    rate_limiter: RateLimiter,
) -> FastAPI:
    """Create a FastAPI app with all routers and mock state."""
    app = FastAPI()
    install_validation_handler(app)  # as sigrift.lib.shiny.app does

    # Wire up dependency overrides
    config = MLRFConfig()
    set_config(config)
    set_rate_limiter(rate_limiter)

    # Mount routers with same prefixes as production
    app.include_router(health.router, prefix="/api", tags=["health"])
    app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])
    app.include_router(spectrum.router, prefix="/api/spectrum", tags=["spectrum"])
    app.include_router(training.router, prefix="/api/training", tags=["training"])
    app.include_router(signals.router, prefix="/api/signals", tags=["signals"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(keys.router, prefix="/api/keys", tags=["keys"])
    app.include_router(jobs.router, prefix="/api/jobs", tags=["jobs"])
    app.include_router(export.router, prefix="/api/export", tags=["export"])

    # Inject state
    app.state.persistence = mock_persistence
    app.state.app_state = mock_app_state
    app.state.spectrum_streamer = SpectrumStreamer()

    return app


@pytest_asyncio.fixture()
async def test_client(test_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    """httpx async client wired to the test app via ASGI transport."""
    transport = httpx.ASGITransport(app=test_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_node() -> dict[str, Any]:
    return {
        "node_id": "edge-01",
        "host": "192.168.1.100",
        "port": 8080,
        "capabilities": {"gpu": True, "sdr": "rtl-sdr"},
    }


@pytest.fixture()
def sample_job() -> dict[str, Any]:
    return {
        "name": "train-baseline",
        "priority": 50,
        "params": {"epochs": 100, "batch_size": 256},
    }
