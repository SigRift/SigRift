"""Start-up integrity checks and migration failures of the SQLite store.

``SharedContext`` runs ``PRAGMA quick_check`` before it touches the schema:
a damaged database is refused at start-up, a large one (over 500 MB) is
checked in the background so start-up is not held up, and pending
migrations are never applied to a damaged file — the 2026-06-02 incident,
where a migration's ``CREATE INDEX`` walked into latent damage.  A
migration that fails on the rows it meets is never recorded as applied.

The damage is real: an index b-tree page of a populated table is
overwritten, so the file still opens and only ``quick_check`` notices.
"Large" files are sparse (``truncate``), so no disk space is used.
``test_migration_corruption_guard.py`` smashes the file header instead,
which fails on open, before either check runs.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.routers import health
from sigrift.bridge.storage import base as base_module
from sigrift.bridge.storage.base import _MIGRATIONS, SharedContext

LATEST = max(version for version, _, _ in _MIGRATIONS)
# The newest migration that is safe to run again on a fully migrated file
# (CREATE INDEX IF NOT EXISTS): left pending, only the guard can stop it.
REPEATABLE = max(
    version
    for version, _, sql in _MIGRATIONS
    if sql.lstrip().startswith("CREATE INDEX IF NOT EXISTS")
)
LARGE = 600_000_000  # above the 500 MB threshold for the background check


def _build_db(path: Path, *, pending: int | None = None) -> None:
    """A fully migrated store with a populated, indexed table (optionally
    with migration *pending* not applied yet), checkpointed and closed."""
    ctx = SharedContext(db_path=path)
    conn = ctx.get_conn()
    conn.execute("CREATE TABLE probe (id INTEGER PRIMARY KEY, v TEXT)")
    conn.execute("CREATE INDEX idx_probe_v ON probe (v)")
    conn.executemany(
        "INSERT INTO probe (v) VALUES (?)", [(f"value-{i:06d}",) for i in range(3000)]
    )
    if pending is not None:
        conn.execute("DELETE FROM schema_version WHERE version = ?", (pending,))
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    ctx.close()


def _sql(path: Path, *statements: str) -> None:
    conn = sqlite3.connect(path)
    try:
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


def _damage_index(path: Path) -> str:
    """Overwrite the start of the probe index's root page (file still opens).

    Returns what ``quick_check`` reports for the damaged file.
    """
    conn = sqlite3.connect(path)
    try:
        root = conn.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = 'idx_probe_v'"
        ).fetchone()[0]
        page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    finally:
        conn.close()
    with open(path, "r+b") as fh:
        fh.seek((root - 1) * page_size)
        fh.write(b"\xff" * 64)
    conn = sqlite3.connect(path)
    try:
        report = conn.execute("PRAGMA quick_check").fetchone()[0]
    finally:
        conn.close()
    assert report != "ok"
    return report


def _wal_size(path: Path) -> int:
    """Bytes in *path*'s write-ahead log (0 when there is none)."""
    wal = path.with_name(path.name + "-wal")
    return wal.stat().st_size if wal.exists() else 0


def _applied_versions(path: Path) -> set[int]:
    conn = sqlite3.connect(path)
    try:
        return {row[0] for row in conn.execute("SELECT version FROM schema_version")}
    finally:
        conn.close()


@contextlib.contextmanager
def _new_threads_joined():
    """Join the threads started inside the block (the deferred check), so its
    result is known and it never logs into another test."""
    before = set(threading.enumerate())
    try:
        yield
    finally:
        for thread in set(threading.enumerate()) - before:
            thread.join(timeout=20)
            assert not thread.is_alive()


def _integrity_status(store: DetectionStore) -> dict:
    """GET /integrity-status (unauthenticated) of an app using *store*."""
    app = FastAPI()
    app.include_router(health.router)
    app.state.detection_store = store
    with TestClient(app) as client:
        response = client.get("/integrity-status")
    assert response.status_code == 200
    return response.json()


def test_a_damaged_database_is_refused_before_anything_is_written(tmp_path, caplog):
    """No write of any kind, including the schema script: the file is from
    an older release that lacks one of the schema's indexes, which a schema
    script run before the check would create.

    The store is in WAL mode, so a committed write lands in ``-wal`` and the
    main file keeps its bytes until a checkpoint: both are compared.  The
    refused store's connection stays open meanwhile (``refused`` holds the
    traceback), as closing it would checkpoint such a write into the main
    file at whatever moment it is garbage-collected.
    """
    db = tmp_path / "detections.db"
    _build_db(db)
    _sql(db, "DROP INDEX idx_audit_target")
    _damage_index(db)
    before = db.read_bytes()
    assert _wal_size(db) == 0

    with pytest.raises(
        sqlite3.DatabaseError, match="Database corruption detected"
    ) as refused:
        SharedContext(db_path=db)

    assert "Database integrity check FAILED" in caplog.text
    assert _wal_size(db) == 0
    assert db.read_bytes() == before
    assert not (tmp_path / "detections.db.pre-migration").exists()
    del refused


def test_a_large_damaged_database_is_never_migrated(tmp_path, caplog):
    db = tmp_path / "detections.db"
    _build_db(db, pending=REPEATABLE)
    _damage_index(db)
    with open(db, "r+b") as fh:
        fh.truncate(LARGE)

    with _new_threads_joined():
        with pytest.raises(
            RuntimeError, match="Refusing to apply migrations on corrupt DB"
        ):
            SharedContext(db_path=db)

    assert REPEATABLE not in _applied_versions(db)
    assert not (tmp_path / "detections.db.pre-migration").exists()
    assert "Refusing to apply 1 pending migrations" in caplog.text


@pytest.mark.parametrize("damaged", [False, True], ids=["healthy", "damaged"])
def test_a_large_database_is_checked_in_the_background(tmp_path, damaged):
    """Start-up is not held up (even when damaged, unlike a small file); the
    result is reported by /integrity-status once the check ends."""
    db = tmp_path / "detections.db"
    _build_db(db)
    report = _damage_index(db) if damaged else None
    with open(db, "r+b") as fh:
        fh.truncate(LARGE)

    with _new_threads_joined():
        store = DetectionStore(db_path=db)

    try:
        status = _integrity_status(store)
        if damaged:
            assert status["state"] == "failed"
            assert status["error"] == report
        else:
            assert status["state"] == "passed"
            assert "error" not in status
        assert status["db_size_mb"] == round(LARGE / 1e6, 1)
    finally:
        store.close()


# New migrations (description, SQL) whose last one fails on a duplicate
# probe value.
_FAILING_MIGRATIONS = {
    # DDL runs in autocommit (sqlite3's default isolation level), so it
    # leaves no transaction open either way.
    "unique-index": [
        ("unique probe values", "CREATE UNIQUE INDEX uq_v ON probe (v)"),
    ],
    # DML opens a transaction (the implicit BEGIN) and takes the write lock
    # before it meets the duplicate: only a rollback releases the lock.
    "backfill": [
        ("unique probe values table", "CREATE TABLE probe_unique (v TEXT UNIQUE)"),
        ("backfill probe values", "INSERT INTO probe_unique (v) SELECT v FROM probe"),
    ],
    # A script in one explicit transaction stops inside it, with the table
    # already created: it must be undone, or the next start-up's CREATE
    # TABLE fails on it and the migration can never be applied.
    "transactional-script": [
        (
            "unique probe values table and backfill",
            "BEGIN;\n"
            "CREATE TABLE probe_unique (v TEXT UNIQUE);\n"
            "INSERT INTO probe_unique (v) SELECT v FROM probe;\n"
            "COMMIT;\n",
        ),
    ],
}


@pytest.mark.parametrize(
    "steps", _FAILING_MIGRATIONS.values(), ids=_FAILING_MIGRATIONS.keys()
)
def test_a_migration_that_fails_on_existing_rows_is_never_recorded(
    tmp_path, monkeypatch, steps
):
    """The duplicate fails the migration with an IntegrityError (not an
    OperationalError).  Start-up fails, the failed migration stays pending
    and its partial work is undone (one applied before it in the same run
    stays applied), the pre-migration snapshot is kept and the write lock
    is released, even though the refused store's connection is still open
    (``refused`` holds the traceback).  Once the rows are repaired the next
    start-up applies it."""
    db = tmp_path / "detections.db"
    backup = tmp_path / "detections.db.pre-migration"
    _build_db(db)
    _sql(db, "INSERT INTO probe (v) VALUES ('value-000001')")  # a duplicate
    versions = [LATEST + 1 + i for i in range(len(steps))]
    *earlier, failing = versions
    monkeypatch.setattr(
        base_module,
        "_MIGRATIONS",
        [*_MIGRATIONS, *((v, d, s) for v, (d, s) in zip(versions, steps))],
    )

    with pytest.raises(
        (RuntimeError, sqlite3.IntegrityError), match="UNIQUE constraint failed"
    ) as refused:
        SharedContext(db_path=db)

    applied = _applied_versions(db)
    assert failing not in applied
    assert set(earlier) <= applied
    assert backup.exists()
    other_writer = sqlite3.connect(db, timeout=0)  # fails at once if locked
    try:
        other_writer.execute("BEGIN IMMEDIATE")
        other_writer.rollback()
    finally:
        other_writer.close()
    del refused

    _sql(db, "DELETE FROM probe WHERE id = (SELECT MAX(id) FROM probe)")
    ctx = SharedContext(db_path=db)
    ctx.close()
    assert set(versions) <= _applied_versions(db)
    assert not backup.exists()
