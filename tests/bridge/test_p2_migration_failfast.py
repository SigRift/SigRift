"""Tests for P2-14: migration fail-fast on first failure + pre-migration backup."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from sigrift.bridge.storage.base import SharedContext, _MIGRATIONS


def _seed_db(db_path: Path) -> None:
    """Create a minimal DB with schema_version marking all migrations applied."""
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)"
    )
    for version, desc, _ in _MIGRATIONS:
        conn.execute(
            "INSERT INTO schema_version (version, description, applied_at) "
            "VALUES (?, ?, '2026-01-01T00:00:00Z')",
            (version, desc),
        )
    conn.commit()
    conn.close()


class TestMigrationFailFast:
    """Fail-fast behaviour: RuntimeError on any migration failure."""

    def test_migration_failure_raises_runtime_error(self, tmp_path: Path) -> None:
        """A bad migration SQL raises RuntimeError with version info."""
        bad_migration = (9999, "broken migration", "INVALID SQL GARBAGE !!!")
        with patch(
            "sigrift.bridge.storage.base._MIGRATIONS",
            _MIGRATIONS + [bad_migration],
        ):
            with pytest.raises(
                RuntimeError, match=r"Migration 9999 \(broken migration\) failed"
            ):
                SharedContext(db_path=tmp_path / "fail.db")

    def test_successful_migrations_still_work(self, tmp_path: Path) -> None:
        """Normal migrations complete without error."""
        ctx = SharedContext(db_path=tmp_path / "ok.db")
        conn = ctx.get_conn()
        rows = conn.execute("SELECT version FROM schema_version").fetchall()
        applied = {r[0] for r in rows}
        for version, _, _ in _MIGRATIONS:
            assert version in applied, f"Migration {version} was not applied"


class TestPreMigrationBackup:
    """Pre-migration backup behaviour."""

    def test_pre_migration_backup_created_then_removed(
        self, tmp_path: Path, caplog
    ) -> None:
        """A .pre-migration backup is created during a migration run and
        removed when the run completes successfully. The on-disk artifact
        only persists when something fails (see test_backup_preserves_data)."""
        import logging

        db_path = tmp_path / "backup.db"
        # Create an empty DB file so the backup source exists
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version "
            "(version INTEGER PRIMARY KEY, description TEXT, applied_at TEXT)"
        )
        conn.commit()
        conn.close()

        with caplog.at_level(logging.INFO, logger="sigrift.bridge.storage.base"):
            SharedContext(db_path=db_path)

        assert any(
            "Pre-migration backup created" in r.getMessage() for r in caplog.records
        ), "Backup creation should be logged"
        assert any(
            "Pre-migration backup removed after successful run" in r.getMessage()
            for r in caplog.records
        ), "Backup should be cleaned up after success"
        backup = Path(str(db_path) + ".pre-migration")
        assert not backup.exists(), (
            "Backup should not survive a successful migration run"
        )

    def test_no_backup_for_memory_db(self, tmp_path: Path) -> None:
        """:memory: DB skips backup creation."""
        SharedContext(db_path=":memory:")
        backup = Path(":memory:.pre-migration")
        assert not backup.exists(), "Backup should not be created for :memory: DB"

    def test_no_backup_when_no_pending_migrations(self, tmp_path: Path) -> None:
        """Already up-to-date DB creates no .pre-migration file."""
        db_path = tmp_path / "uptodate.db"
        # First run: applies all migrations, creates backup
        SharedContext(db_path=db_path)
        backup = Path(str(db_path) + ".pre-migration")
        # Remove the backup from the first run
        if backup.exists():
            backup.unlink()

        # Second run: no pending migrations, no backup
        SharedContext(db_path=db_path)
        assert not backup.exists(), "No backup should be created when DB is up-to-date"

    def test_backup_preserves_data_on_failure(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """When a migration fails, the .pre-migration backup survives
        and contains the pre-run state — the whole point of the backup
        is forensic restore after a crash."""
        db_path = tmp_path / "preserve.db"
        # Build a fully-migrated DB with some user data, then synthesize
        # a "pending" migration by deleting the last schema_version row.
        ctx1 = SharedContext(db_path=db_path)
        conn = ctx1.get_conn()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS test_data (id INTEGER PRIMARY KEY, value TEXT)"
        )
        conn.execute("INSERT INTO test_data (id, value) VALUES (1, 'preserved')")
        last_version = _MIGRATIONS[-1][0]
        conn.execute("DELETE FROM schema_version WHERE version = ?", (last_version,))
        conn.commit()
        # Flush WAL so the backup captures all the test data.
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.close()
        del ctx1

        # Force the (synthesized) pending migration to fail. Append a
        # broken migration to the in-memory _MIGRATIONS list — the runner
        # raises RuntimeError on the first error; the backup must remain.
        from sigrift.bridge.storage import base

        bogus = (
            999_999,
            "synthetic failure",
            "SELECT * FROM definitely_not_a_real_table",
        )
        monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, bogus])

        with pytest.raises(RuntimeError, match="Migration"):
            SharedContext(db_path=db_path)

        # Backup must survive the failure.
        backup_path = str(db_path) + ".pre-migration"
        assert Path(backup_path).exists(), "Backup should survive a failed run"

        # And it should contain our pre-run data.
        bconn = sqlite3.connect(backup_path)
        row = bconn.execute("SELECT value FROM test_data WHERE id = 1").fetchone()
        assert row is not None
        assert isinstance(row, tuple)
        assert row[0] == "preserved"
        bconn.close()
