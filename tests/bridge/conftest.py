"""Shared test fixtures for The Bridge test suite.

Provides:
  - In-memory DetectionStore (SQLite :memory:)
  - Temporary PersistenceManager
  - AppState with pre-configured master key
  - FastAPI TestClient with auth headers
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState

# Per-test timeout is provided by pytest-timeout (pinned in
# requirements.txt); --timeout=30 is configured via `addopts` in the
# root pyproject.toml. The hand-rolled SIGALRM handler that used to
# live here raced with pytest-timeout under pytest-xdist workers (both
# arm the process-wide alarm).
#
# Performance tests that legitimately need longer should mark with
# @pytest.mark.timeout(120) to override per-test.


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def make_detection(
    node_id: str = "node-test-01",
    signal_class: str = "bpsk",
    confidence: float = 0.95,
    family: str = "psk",
    freq_hz: float = 433.92e6,
    snr_db: float = 15.0,
    anomaly_score: float = 0.0,
    **kwargs: Any,
) -> DetectionRecord:
    """Create a DetectionRecord with sensible defaults for testing."""
    return DetectionRecord(
        node_id=node_id,
        signal_class=signal_class,
        confidence=confidence,
        family=family,
        freq_hz=freq_hz,
        snr_db=snr_db,
        anomaly_score=anomaly_score,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def detection_store(tmp_path: Path) -> DetectionStore:
    """In-memory DetectionStore for isolated tests."""
    return DetectionStore(db_path=tmp_path / "test_detections.db")


@pytest.fixture
def persistence(tmp_path: Path) -> PersistenceManager:
    """PersistenceManager backed by a temp directory."""
    pm = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    pm.load_all()
    return pm


@pytest.fixture
def app_state() -> AppState:
    """Fresh AppState instance."""
    return AppState()


@pytest.fixture
def master_key() -> str:
    """Generate a raw API key for test auth."""
    return generate_api_key(length=32)


@pytest.fixture
def bridge_app(
    tmp_path: Path,
    detection_store: DetectionStore,
    persistence: PersistenceManager,
    app_state: AppState,
    master_key: str,
) -> FastAPI:
    """Build a fully wired Bridge FastAPI app for testing.

    Delegates to the shared ``create_test_app`` factory in ``app.py`` so that
    routers, middleware, and app.state attributes stay in sync with production.
    """
    from sigrift.bridge.app import create_test_app

    return create_test_app(
        tmp_path=tmp_path,
        detection_store=detection_store,
        persistence=persistence,
        app_state=app_state,
        master_key=master_key,
    )


@pytest.fixture
def client(bridge_app: FastAPI, master_key: str) -> TestClient:
    """TestClient with master API key in headers."""
    return TestClient(
        bridge_app,
        headers={"X-API-Key": master_key},
    )


@pytest.fixture
def local_time_not_utc():
    """Run the test with the process's local time zone 7 hours west of UTC.

    A naive stored date read as local time instead of UTC then gives a
    different instant on every host, also a CI runner whose zone is UTC,
    where the two readings agree and such a regression would pass.
    """
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset() is not available on this platform")
    saved = os.environ.get("TZ")
    os.environ["TZ"] = "SRT+07"  # POSIX: 7 hours west of UTC, no DST
    time.tzset()
    try:
        offset = datetime(2999, 1, 1).astimezone().utcoffset()
        assert offset == timedelta(hours=-7), offset
        yield
    finally:
        if saved is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = saved
        time.tzset()


@pytest.fixture
def registered_node(client: TestClient) -> str:
    """Register a test node and return its ID."""
    node_id = "node-test-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": "192.168.1.100",
        "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


@pytest.fixture
def sample_detections() -> list[DetectionRecord]:
    """Create a list of sample detection records for testing."""
    now = _utcnow()
    return [
        make_detection(
            signal_class="bpsk",
            confidence=0.92,
            family="psk",
            freq_hz=433.92e6,
            timestamp=now - timedelta(minutes=i),
        )
        for i in range(10)
    ] + [
        make_detection(
            signal_class="qam16",
            confidence=0.85,
            family="qam",
            freq_hz=915e6,
            anomaly_score=0.5 if i % 3 == 0 else 0.0,
            timestamp=now - timedelta(minutes=i),
        )
        for i in range(5)
    ]
