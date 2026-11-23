"""PRE-68 follow-up: a bridge must refuse a database from a newer build.

``_run_migrations`` used to compute only *pending* migrations, so a build
started on a database that a newer build had already migrated (a rollback
onto live volumes) ran normally against a schema it does not understand.
The guard refuses before any schema statement runs, and it ignores
historical gaps in the migration list (versions below the newest known one).
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext, _MIGRATIONS, _SCHEMA

NEWEST = max(version for version, _, _ in _MIGRATIONS)
# Indexes the base schema (re)creates on every start, so running it is observable.
SCHEMA_INDEXES = set(re.findall(r"CREATE INDEX IF NOT EXISTS (\w+)", _SCHEMA))


def _migrated_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "detections.db"
    ctx = SharedContext(db_path=db_path)
    conn = ctx.get_conn()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()
    return db_path


def _add_version(db_path: Path, version: int) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO schema_version (version, description, applied_at) "
        "VALUES (?, 'from a newer build', datetime('now'))",
        (version,),
    )
    conn.commit()
    conn.close()


def _schema(db_path: Path) -> list[tuple]:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
    finally:
        conn.close()


def test_fresh_database_initialises(tmp_path):
    SharedContext(db_path=tmp_path / "fresh.db").get_conn()


def test_current_database_reopens(tmp_path):
    db_path = _migrated_db(tmp_path)
    SharedContext(db_path=db_path).get_conn()


@pytest.mark.parametrize("gap", [39, 44])
def test_historical_gap_versions_are_not_treated_as_newer(tmp_path, gap):
    assert gap not in {version for version, _, _ in _MIGRATIONS}
    db_path = _migrated_db(tmp_path)
    _add_version(db_path, gap)
    SharedContext(db_path=db_path).get_conn()


@pytest.mark.parametrize("offset", [1, 25])
def test_newer_schema_is_refused_before_any_schema_change(tmp_path, offset):
    db_path = _migrated_db(tmp_path)
    _add_version(db_path, NEWEST + offset)
    # Drop an index this build's base schema recreates on every start, so a
    # guard that ran only after executescript(_SCHEMA) would be visible.
    conn = sqlite3.connect(db_path)
    present = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
    }
    # One the migrations keep, so only a rerun of _SCHEMA could bring it back.
    index = sorted(SCHEMA_INDEXES & present)[0]
    conn.execute(f"DROP INDEX {index}")
    conn.commit()
    conn.close()
    before = _schema(db_path)
    with pytest.raises(RuntimeError, match=r"newer than this build") as info:
        SharedContext(db_path=db_path).get_conn()
    assert str(NEWEST + offset) in str(info.value)
    assert str(NEWEST) in str(info.value)
    assert _schema(db_path) == before


def test_unexpected_schema_version_shape_fails_closed(tmp_path):
    db_path = tmp_path / "odd.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE schema_version (applied_at TEXT)")
    conn.commit()
    conn.close()
    with pytest.raises(sqlite3.OperationalError, match="version"):
        SharedContext(db_path=db_path).get_conn()
