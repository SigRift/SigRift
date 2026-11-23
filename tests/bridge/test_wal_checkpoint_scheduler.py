"""Tests for the WAL-checkpoint scheduler wiring fix in PR I.

PR G's ``schedule_wal_checkpoint`` used to be dead code — the bridge
lifespan ran its own inline ``_periodic_wal_checkpoint`` with
PRAGMA wal_checkpoint(PASSIVE), which merges frames but never shrinks
the WAL file. Production WAL hit 18.8 GB before we noticed because the
inline loop also logged failures at DEBUG.

These tests guard the wiring:

  * ``schedule_wal_checkpoint`` actually runs and triggers TRUNCATE.
  * Its interval is configurable.
  * Failures log at WARNING (loud enough to surface in INFO-level logs).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3

import pytest

from sigrift.bridge.storage.base import SharedContext


@pytest.mark.asyncio
async def test_schedule_wal_checkpoint_runs_truncate(tmp_path, monkeypatch):
    """A short-interval scheduler fires within seconds and runs TRUNCATE.

    We verify the contract by spying on the connection's ``execute``
    method — the loop should call ``PRAGMA wal_checkpoint(TRUNCATE)``
    at least once during a short test window. The log line is conditional
    (silenced when busy=0 and checkpointed=0) so we can't rely on it
    for this test."""
    db_path = tmp_path / "sched.db"
    ctx = SharedContext(db_path=db_path)

    seen_pragmas: list[str] = []
    real_get_conn = ctx.get_conn

    class _SpyConn:
        def __init__(self, wrapped):
            self._w = wrapped

        def execute(self, sql, *args, **kwargs):
            seen_pragmas.append(sql)
            return self._w.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._w, name)

    def _spy_get_conn():
        return _SpyConn(real_get_conn())

    monkeypatch.setattr(ctx, "get_conn", _spy_get_conn)

    task = ctx.schedule_wal_checkpoint(interval_seconds=0.3)
    await asyncio.sleep(1.0)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    truncate_calls = [s for s in seen_pragmas if "wal_checkpoint(TRUNCATE)" in s]
    assert truncate_calls, (
        f"Scheduler should have run TRUNCATE checkpoint at least once; "
        f"seen pragmas: {seen_pragmas}"
    )


@pytest.mark.asyncio
async def test_schedule_wal_checkpoint_warns_on_failure(tmp_path, caplog):
    """If the checkpoint pragma raises, the failure is logged at WARNING —
    not DEBUG. The DEBUG-only path is exactly what hid PR G's earlier
    silent dead-code situation."""
    db_path = tmp_path / "fail.db"
    ctx = SharedContext(db_path=db_path)

    # Monkeypatch get_conn to return a connection that raises.
    class _BadConn:
        def execute(self, *args, **kwargs):
            raise sqlite3.OperationalError("synthetic checkpoint failure")

    ctx.get_conn = lambda: _BadConn()  # type: ignore[assignment]

    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
        task = ctx.schedule_wal_checkpoint(interval_seconds=0.2)
        await asyncio.sleep(0.5)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    assert any(
        "WAL checkpoint failed" in r.getMessage() and r.levelno >= logging.WARNING
        for r in caplog.records
    ), "Checkpoint failures must surface at WARNING or above"


def test_lifespan_uses_schedule_wal_checkpoint_not_inline_passive():
    """Guards against the old bug returning: the lifespan must call
    ``schedule_wal_checkpoint`` (which is TRUNCATE) instead of having an
    inline ``wal_checkpoint(PASSIVE)`` loop."""
    import inspect

    from sigrift.bridge import app as bridge_app

    source = inspect.getsource(bridge_app)
    # The wiring must call the shared scheduler.
    assert "schedule_wal_checkpoint" in source, (
        "Lifespan should call detection_store._ctx.schedule_wal_checkpoint(...)"
    )
    # And must not silently retain the old PASSIVE-only inline loop —
    # if someone re-introduces it, this test fails. (We allow PASSIVE
    # to appear in comments — only the active code path is forbidden.)
    # The simplest contract: no top-level call to wal_checkpoint(PASSIVE)
    # in the lifespan path.
    assert "wal_checkpoint(PASSIVE)" not in source.replace(
        "# Delegated to SharedContext", ""
    ).replace("ran PASSIVE", ""), (
        "Lifespan must not run a PASSIVE-mode checkpoint loop in place of "
        "the TRUNCATE one"
    )
