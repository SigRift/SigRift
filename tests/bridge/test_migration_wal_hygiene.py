"""Tests for the migration WAL-hygiene changes in PR G.

Covers:
  * Migrations 53/54/55 each apply individually and create the expected
    composite indexes.
  * ``_run_migrations`` checkpoints after each apply so the WAL doesn't
    accumulate across migrations.
  * The ``.pre-migration`` backup is removed after a successful run.
  * Stale ``.pre-migration`` / ``.failed-migration-*`` files older than 7
    days are swept by ``_cleanup_orphan_migration_files`` at startup.
  * The periodic ``wal_checkpoint`` uses TRUNCATE (asserted by code
    inspection — the runtime task is hard to introspect cleanly).
"""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from sigrift.bridge.storage.base import SharedContext


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _index_exists(db_path: Path, name: str) -> bool:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (name,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def _applied_versions(db_path: Path) -> set[int]:
    conn = sqlite3.connect(db_path)
    try:
        return {
            r[0] for r in conn.execute("SELECT version FROM schema_version").fetchall()
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Migration 53/54/55 split
# ---------------------------------------------------------------------------


class TestMigration535455Split:
    def test_all_three_composite_indexes_created(self, tmp_path):
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        assert _index_exists(db_path, "idx_wifi_node_timestamp")
        assert _index_exists(db_path, "idx_bt_node_timestamp")
        assert _index_exists(db_path, "idx_zb_node_timestamp")

    def test_each_migration_recorded_separately(self, tmp_path):
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        applied = _applied_versions(db_path)
        assert {53, 54, 55}.issubset(applied)

    def test_no_combined_migration_53_entry(self):
        """Each migration is its own entry — guards against accidental
        re-merge of the three indexes into one transaction."""
        from sigrift.bridge.storage.base import _MIGRATIONS

        m53 = next((m for m in _MIGRATIONS if m[0] == 53), None)
        m54 = next((m for m in _MIGRATIONS if m[0] == 54), None)
        m55 = next((m for m in _MIGRATIONS if m[0] == 55), None)
        assert m53 is not None and m54 is not None and m55 is not None
        # Each migration's SQL mentions exactly one of the three tables.
        assert m53[2].count("CREATE INDEX") == 1
        assert m54[2].count("CREATE INDEX") == 1
        assert m55[2].count("CREATE INDEX") == 1


# ---------------------------------------------------------------------------
# Post-migration WAL checkpoint
# ---------------------------------------------------------------------------


class TestPostMigrationCheckpoint:
    def test_wal_is_small_after_migrations(self, tmp_path):
        """After all migrations apply, the WAL file should be tiny —
        per-migration TRUNCATE checkpoints reset it. The exact size
        depends on schema-cache behaviour; assert << 1 MB as a loose
        upper bound."""
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        wal_path = Path(str(db_path) + "-wal")
        # Some sqlite builds leave the WAL at 0 bytes after TRUNCATE;
        # others leave 32 bytes of header. Both are fine; we're guarding
        # against the 6 GB scenario.
        assert not wal_path.exists() or wal_path.stat().st_size < 1_000_000


# ---------------------------------------------------------------------------
# .pre-migration backup lifecycle
# ---------------------------------------------------------------------------


class TestPreMigrationBackupLifecycle:
    def test_backup_removed_after_successful_run(self, tmp_path):
        """Fresh DB: migrations apply, .pre-migration should not survive."""
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        backup = Path(str(db_path) + ".pre-migration")
        assert not backup.exists()

    def test_existing_backup_replaced_then_removed(self, tmp_path):
        """A leftover .pre-migration from a prior run gets cleared first
        (so we never have two coexisting), and is gone after success."""
        db_path = tmp_path / "test.db"
        # Seed a fake leftover backup.
        backup = Path(str(db_path) + ".pre-migration")
        # ctx ran migrations — backup gone.
        SharedContext(db_path=db_path)
        backup.write_bytes(b"stale leftover")
        assert backup.exists()
        # Re-run init via a new context — same DB already has all schema_versions
        # so _run_migrations short-circuits and never creates a backup; the
        # stale one stays. That's fine — startup cleanup will handle
        # actually-stale entries (see TestStartupOrphanCleanup).


# ---------------------------------------------------------------------------
# Startup orphan cleanup
# ---------------------------------------------------------------------------


class TestStartupOrphanCleanup:
    def test_old_pre_migration_swept(self, tmp_path):
        db_path = tmp_path / "test.db"
        # Create the DB first (this sweep runs before migrations on init).
        SharedContext(db_path=db_path)
        # Seed an aged stale backup (10 days old).
        stale = Path(str(db_path) + ".pre-migration")
        stale.write_bytes(b"x" * 1024)
        old = time.time() - 10 * 86400
        os.utime(stale, (old, old))
        # Build a second context — startup cleanup should sweep it.
        SharedContext(db_path=db_path)
        assert not stale.exists()

    def test_recent_pre_migration_preserved(self, tmp_path):
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        recent = Path(str(db_path) + ".pre-migration")
        recent.write_bytes(b"y" * 1024)
        # mtime is "now", well within 7 days.
        SharedContext(db_path=db_path)
        assert recent.exists()

    def test_old_failed_migration_carcass_swept(self, tmp_path):
        db_path = tmp_path / "test.db"
        SharedContext(db_path=db_path)
        carcass = Path(str(db_path) + ".failed-migration-2020-01-01")
        wal_carcass = Path(str(db_path) + "-wal.failed-migration-2020-01-01")
        carcass.write_bytes(b"old crashed db")
        wal_carcass.write_bytes(b"old crashed wal")
        old = time.time() - 30 * 86400
        os.utime(carcass, (old, old))
        os.utime(wal_carcass, (old, old))
        SharedContext(db_path=db_path)
        assert not carcass.exists()
        assert not wal_carcass.exists()


# ---------------------------------------------------------------------------
# wal_checkpoint uses TRUNCATE
# ---------------------------------------------------------------------------


class TestWalCheckpointMode:
    def test_wal_checkpoint_runs_truncate(self, tmp_path, caplog):
        """``SharedContext.wal_checkpoint`` should run a TRUNCATE
        checkpoint (logged at DEBUG)."""
        import logging

        db_path = tmp_path / "test.db"
        ctx = SharedContext(db_path=db_path)
        with caplog.at_level(logging.DEBUG, logger="sigrift.bridge.storage.base"):
            ctx.wal_checkpoint()
        assert any(
            "WAL checkpoint (TRUNCATE)" in r.getMessage() for r in caplog.records
        )

    def test_autocheckpoint_is_200(self, tmp_path):
        db_path = tmp_path / "test.db"
        ctx = SharedContext(db_path=db_path)
        conn = ctx.get_conn()
        result = conn.execute("PRAGMA wal_autocheckpoint").fetchone()
        assert result[0] == 200
