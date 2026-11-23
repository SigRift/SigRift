"""Tests for P2-8: Online backup API via SQLite backup mechanism.

Validates:
- SharedContext.backup() creates valid SQLite databases
- Backup files are queryable and contain source data
- API endpoint returns correct metadata
- Retention policy prunes old backups
- Admin auth is required
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.base import SharedContext


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    """SharedContext backed by a temp on-disk database."""
    return SharedContext(db_path=tmp_path / "test.db")


@pytest.fixture
def backup_dir(tmp_path: Path) -> Path:
    d = tmp_path / "backups"
    d.mkdir()
    return d


# ---------------------------------------------------------------------------
# SharedContext.backup() unit tests
# ---------------------------------------------------------------------------

class TestBackupMethod:

    def test_backup_creates_valid_sqlite(self, ctx: SharedContext, backup_dir: Path):
        """Backup file must be a valid SQLite database."""
        dest = backup_dir / "backup.db"
        result = ctx.backup(dest)

        assert dest.exists()
        assert dest.stat().st_size > 0

        # Verify it's valid SQLite by reading the header magic
        with open(dest, "rb") as f:
            header = f.read(16)
        assert header.startswith(b"SQLite format 3")

    def test_backup_file_is_queryable(self, ctx: SharedContext, backup_dir: Path):
        """Can open the backup and run queries against schema tables."""
        dest = backup_dir / "backup.db"
        ctx.backup(dest)

        conn = sqlite3.connect(str(dest))
        conn.row_factory = sqlite3.Row
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            table_names = {r["name"] for r in tables}
            # The schema must include core tables
            assert "detections" in table_names
            assert "schema_version" in table_names
        finally:
            conn.close()

    def test_backup_returns_metadata(self, ctx: SharedContext, backup_dir: Path):
        """Return dict must contain path, size_bytes, elapsed_sec, status."""
        dest = backup_dir / "backup.db"
        result = ctx.backup(dest)

        assert result["path"] == str(dest)
        assert result["size_bytes"] > 0
        assert isinstance(result["elapsed_sec"], float)
        assert result["status"] == "complete"

    def test_backup_during_data(
        self, ctx: SharedContext, backup_dir: Path,
    ):
        """Data inserted before backup must appear in the backup file."""
        conn = ctx.get_conn()
        conn.execute(
            "INSERT INTO detections "
            "(detection_id, node_id, timestamp, signal_class, confidence, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("det-001", "node-1", "2026-01-01T00:00:00Z", "bpsk", 0.95,
             ctx.tenant_id),
        )
        conn.commit()

        dest = backup_dir / "backup_with_data.db"
        ctx.backup(dest)

        bk_conn = sqlite3.connect(str(dest))
        bk_conn.row_factory = sqlite3.Row
        try:
            row = bk_conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?",
                ("det-001",),
            ).fetchone()
            assert row is not None
            assert row["signal_class"] == "bpsk"
            assert row["node_id"] == "node-1"
        finally:
            bk_conn.close()

    def test_backup_retention(self, backup_dir: Path, tmp_path: Path):
        """With BRIDGE_BACKUP_RETENTION=5, creating 7 backups prunes the oldest 2."""
        from sigrift.bridge.routers.maintenance import _prune_old_backups

        # Create 7 fake backup files with staggered mtimes
        paths = []
        for i in range(7):
            p = backup_dir / f"detections_backup_{i:03d}.db"
            p.write_bytes(b"fake")
            # Ensure ordering: oldest first
            os.utime(p, (1000 + i, 1000 + i))
            paths.append(p)

        # Prune to 5
        _prune_old_backups(backup_dir, keep=5)

        remaining = sorted(backup_dir.glob("detections_backup_*.db"))
        assert len(remaining) == 5
        # The two oldest (000, 001) should be gone
        remaining_names = {p.name for p in remaining}
        assert "detections_backup_000.db" not in remaining_names
        assert "detections_backup_001.db" not in remaining_names


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

class TestBackupAPI:

    def test_backup_api_requires_admin(self, client, bridge_app):
        """POST /api/admin/backup without auth must fail."""
        from fastapi.testclient import TestClient

        unauth_client = TestClient(bridge_app)
        resp = unauth_client.post("/api/admin/backup")
        assert resp.status_code in (401, 403)

    def test_backup_api_returns_metadata(self, client):
        """POST /api/admin/backup returns status, backup_file, size_bytes."""
        resp = client.post("/api/admin/backup")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "complete"
        assert "backup_file" in data
        assert data["size_bytes"] > 0
        assert "elapsed_sec" in data
        assert "sha256" in data

    def test_backup_api_file_is_valid(self, client, detection_store):
        """The backup file created by the API must be valid SQLite."""
        resp = client.post("/api/admin/backup")
        assert resp.status_code == 200
        data = resp.json()

        backup_dir = Path(detection_store.db_path).parent / "backups"
        backup_path = backup_dir / data["backup_file"]
        assert backup_path.exists()

        conn = sqlite3.connect(str(backup_path))
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            assert len(tables) > 0
        finally:
            conn.close()

    def test_backup_api_retention_env(self, client, detection_store, monkeypatch):
        """BRIDGE_BACKUP_RETENTION controls how many backups are kept."""
        monkeypatch.setenv("BRIDGE_BACKUP_RETENTION", "3")

        # Create 5 backups (sleep briefly so timestamps differ)
        for _ in range(5):
            resp = client.post("/api/admin/backup")
            assert resp.status_code == 200
            time.sleep(0.05)

        backup_dir = Path(detection_store.db_path).parent / "backups"
        remaining = list(backup_dir.glob("detections_backup_*.db"))
        assert len(remaining) <= 3
