"""Migration snapshots must preserve SQLite WAL content and process locks."""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from sigrift.bridge.storage import base


_WRITER = """
import sqlite3, sys
connection = sqlite3.connect(sys.argv[1])
connection.execute(
    "INSERT INTO schema_version VALUES (?, 'external writer', '2026-11-06')",
    (int(sys.argv[2]),),
)
connection.commit()
if len(sys.argv) > 3:
    print('committed', flush=True)
    sys.stdin.readline()
connection.close()
"""


def test_gateway_restart_preserves_bridge_visibility(tmp_path):
    """A second process closing/reopening must not orphan the bridge's WAL.

    Raw-copying the database during migrations closes a non-SQLite file
    descriptor and drops the bridge's POSIX locks. The first external
    writer then unlinks the WAL on close; writes by its replacement become
    invisible to the bridge's still-open connection (the observed 401).
    """
    ctx = base.SharedContext(tmp_path / "restart.db")
    child = None
    try:
        subprocess.run(
            [sys.executable, "-c", _WRITER, ctx.db_path, "50000"],
            check=True,
            capture_output=True,
            timeout=10,
        )
        child = subprocess.Popen(
            [sys.executable, "-c", _WRITER, ctx.db_path, "50001", "hold"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert child.stdout.readline().strip() == "committed"
        count = (
            ctx.get_conn()
            .execute(
                "SELECT COUNT(*) FROM schema_version WHERE version IN (50000, 50001)"
            )
            .fetchone()[0]
        )
        assert count == 2, "Bridge must see writes from the restarted gateway"
    finally:
        if child is not None:
            child.communicate("\n", timeout=10)
            assert child.returncode == 0
        ctx.close()


def test_failed_migration_backup_includes_uncheckpointed_wal(tmp_path, monkeypatch):
    ctx = base.SharedContext(tmp_path / "recovery.db")
    try:
        conn = ctx.get_conn()
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE recovery_data (value TEXT)")
        conn.execute("INSERT INTO recovery_data VALUES ('committed in WAL')")
        conn.commit()
        assert Path(ctx.db_path + "-wal").stat().st_size > 0
        os.chmod(ctx.db_path, 0o600)
        failed = (50000, "synthetic failed migration", "INVALID SQL")
        monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, failed])
        with pytest.raises(RuntimeError, match="Migration 50000"):
            ctx._run_migrations(conn)
        backup = Path(ctx.db_path + ".pre-migration")
        assert backup.stat().st_mode & 0o777 == 0o600
        restored = sqlite3.connect(backup)
        try:
            assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert restored.execute("SELECT value FROM recovery_data").fetchone() == (
                "committed in WAL",
            )
            assert restored.execute(
                "SELECT COUNT(*) FROM schema_version WHERE version = 50000"
            ).fetchone() == (0,)
        finally:
            restored.close()
    finally:
        ctx.close()


@pytest.mark.parametrize("failure", ["database", "replace"])
def test_snapshot_failure_preserves_prior_backup_and_cleans_temporary_file(
    tmp_path, monkeypatch, caplog, failure
):
    from sigrift.bridge.storage import encryption

    ctx = base.SharedContext(tmp_path / "snapshot.db")
    try:
        backup = Path(ctx.db_path + ".pre-migration")
        backup.write_bytes(b"prior recovery snapshot")
        pending = (50000, "harmless migration", "SELECT 1")
        monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, pending])

        def fail(*args, **kwargs):
            if failure == "database":
                raise sqlite3.OperationalError("snapshot destination unavailable")
            raise OSError("snapshot publication unavailable")

        if failure == "database":
            monkeypatch.setattr(encryption, "open_db", fail)
        else:
            monkeypatch.setattr(base.os, "replace", fail)
        ctx._run_migrations(ctx.get_conn())
        assert "Pre-migration backup failed" in caplog.text
        assert backup.read_bytes() == b"prior recovery snapshot"
        assert list(tmp_path.glob("snapshot.db.pre-migration.*")) == []
    finally:
        ctx.close()


def test_driver_without_online_backup_fails_closed_before_migration(
    tmp_path, monkeypatch
):
    ctx = base.SharedContext(tmp_path / "unsupported.db")
    try:
        conn = ctx.get_conn()
        pending = (50000, "must not execute", "CREATE TABLE unsafe_migration (id INT)")
        monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, pending])

        class DriverWithoutBackup:
            execute = conn.execute

        with pytest.raises(RuntimeError, match="driver lacks the online backup API"):
            ctx._run_migrations(DriverWithoutBackup())
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'unsafe_migration'"
            ).fetchone()[0]
            == 0
        )
        assert list(tmp_path.glob("unsupported.db.pre-migration*")) == []
    finally:
        ctx.close()
