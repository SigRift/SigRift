"""pytest-xdist readiness fixtures.

Provides fixtures for parallel test execution with pytest-xdist.
Import these via conftest.py or use directly in test modules.

Usage with xdist:
    pytest -n auto --dist=loadgroup sigrift/bridge/tests/

Tests needing sequential execution should use:
    @pytest.mark.xdist_group("sequential")
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore


@pytest.fixture
def worker_db(tmp_path: Path) -> str:
    """Create a unique database path per xdist worker.

    When running under pytest-xdist, each worker gets a distinct ID
    (gw0, gw1, ...). This fixture ensures each worker writes to its
    own database file, preventing SQLite locking conflicts.
    """
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    db_path = tmp_path / f"test_{worker_id}.db"
    return str(db_path)


@pytest.fixture
def worker_detection_store(worker_db: str) -> DetectionStore:
    """DetectionStore backed by a per-worker database."""
    return DetectionStore(db_path=worker_db)


@pytest.fixture
def worker_data_dir(tmp_path: Path) -> Path:
    """Per-worker data directory for persistence tests."""
    worker_id = os.environ.get("PYTEST_XDIST_WORKER", "gw0")
    data_dir = tmp_path / f"data_{worker_id}"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir
