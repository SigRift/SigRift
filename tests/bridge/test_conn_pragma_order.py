"""Guards the PRAGMA ordering fix in PR J.

``PRAGMA journal_mode=WAL`` takes a brief exclusive lock. Under
``uvicorn --workers 2`` both workers initialise their first connection
at startup and race for it. ``busy_timeout`` must already be in effect
so the loser waits instead of getting an immediate ``database is
locked`` — otherwise its lifespan crashes and its background tasks
(WAL checkpoint, materializer) never start, which is exactly how a
staging WAL grew to 21 GB.

These tests assert the ordering by source inspection (the live race is
timing-dependent and hard to reproduce deterministically) plus a
concurrency smoke test that opens many connections in parallel.
"""

from __future__ import annotations

import inspect
import sqlite3
import threading

from sigrift.bridge.storage.base import SharedContext


def test_busy_timeout_set_before_journal_mode_in_get_conn():
    source = inspect.getsource(SharedContext.get_conn)
    bt = source.index("busy_timeout")
    jm = source.index("journal_mode=WAL")
    assert bt < jm, (
        "busy_timeout must be set before journal_mode=WAL in get_conn so "
        "concurrent worker startup waits for the lock instead of crashing"
    )


def test_concurrent_connections_do_not_raise(tmp_path):
    """Open many connections to the same DB concurrently from threads —
    mimics the multi-worker startup race. With busy_timeout set first,
    none should raise 'database is locked'."""
    db_path = tmp_path / "race.db"
    # Prime the DB.
    SharedContext(db_path=db_path)

    errors: list[Exception] = []

    def _worker():
        try:
            ctx = SharedContext(db_path=db_path)
            conn = ctx.get_conn()
            conn.execute("SELECT 1").fetchone()
        except Exception as exc:  # noqa: BLE001 — we want to see any error
            errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    locked = [e for e in errors if isinstance(e, sqlite3.OperationalError)]
    assert not locked, f"Concurrent startup raised lock errors: {locked}"
    assert not errors, f"Concurrent startup raised: {errors}"


def test_bg_integrity_check_sets_busy_timeout_first():
    """The deferred background integrity-check thread opens its own
    connection and must follow the same ordering."""
    source = inspect.getsource(SharedContext._init_db)
    # Find the bg-check connection setup.
    assert "busy_timeout" in source, (
        "background integrity check should set busy_timeout"
    )
    bt = source.index("PRAGMA busy_timeout=30000")
    # The first journal_mode after that point should come later.
    jm = source.index("journal_mode=WAL", bt)
    assert bt < jm, "bg integrity check must set busy_timeout before journal_mode=WAL"
