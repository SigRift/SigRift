"""Tests for the checkpoint-under-write_lock + retry behavior (PR L).

On a busy 2-worker bridge, ``PRAGMA wal_checkpoint(TRUNCATE)`` merges
every frame but returns ``busy=1`` and skips truncating the file when a
reader is active during the truncate phase — so the WAL never shrinks on
disk. PR L holds the write lock and retries until ``busy=0`` (or attempts
run out) to catch a gap between short reader snapshots.
"""

from __future__ import annotations

import asyncio

import pytest

from sigrift.bridge.storage.base import SharedContext


def test_wal_checkpoint_holds_write_lock(tmp_path, monkeypatch):
    """wal_checkpoint must execute the pragma while holding write_lock."""
    ctx = SharedContext(db_path=tmp_path / "lk.db")

    held = {"during_execute": False}
    real_conn = ctx.get_conn()

    class _Conn:
        def execute(self, sql, *a, **k):
            if "wal_checkpoint" in sql:
                # The write lock must be held at this point.
                held["during_execute"] = not ctx._write_lock.acquire(blocking=False)
                if not held["during_execute"]:
                    ctx._write_lock.release()
                # Return a plausible checkpoint result.

                class _R:
                    def fetchone(self_inner):
                        return (0, 0, 0)

                return _R()
            return real_conn.execute(sql, *a, **k)

    monkeypatch.setattr(ctx, "get_conn", lambda: _Conn())
    ctx.wal_checkpoint()
    assert held["during_execute"], (
        "write_lock must be held during the checkpoint pragma"
    )


@pytest.mark.asyncio
async def test_scheduler_retries_until_not_busy(tmp_path, monkeypatch):
    """When wal_checkpoint returns busy=1, the loop retries; once it
    returns busy=0 it stops retrying that tick."""
    ctx = SharedContext(db_path=tmp_path / "retry.db")

    calls = {"n": 0}

    def _fake_checkpoint():
        calls["n"] += 1
        # busy=1 for the first two attempts, then clear.
        if calls["n"] < 3:
            return (1, 100, 100)
        return (0, 0, 100)

    monkeypatch.setattr(ctx, "wal_checkpoint", _fake_checkpoint)

    task = ctx.schedule_wal_checkpoint(
        interval_seconds=0.05, retry_attempts=5, retry_delay=0.01
    )
    await asyncio.sleep(0.5)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # At least 3 calls on the first tick (2 busy + 1 clear). Could be more
    # if a second tick fired, but must be >= 3.
    assert calls["n"] >= 3, f"expected retries until not-busy; got {calls['n']} calls"


@pytest.mark.asyncio
async def test_scheduler_caps_retries_when_always_busy(tmp_path, monkeypatch):
    """If every attempt is busy, the loop stops after retry_attempts and
    doesn't spin forever within one tick."""
    ctx = SharedContext(db_path=tmp_path / "busy.db")

    state = {"tick_calls": 0}

    def _always_busy():
        state["tick_calls"] += 1
        return (1, 50, 50)

    monkeypatch.setattr(ctx, "wal_checkpoint", _always_busy)

    # Slow retry relative to the window so a single tick can't make many
    # calls — if the per-tick cap were missing, an always-busy tick would
    # spin at the retry_delay rate without bound. With cap=4 and a 0.5s
    # window at 0.1s/retry, total stays small and bounded.
    task = ctx.schedule_wal_checkpoint(
        interval_seconds=0.02, retry_attempts=4, retry_delay=0.1
    )
    await asyncio.sleep(0.5)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    # At least one tick fired (>=1 call) and the per-tick cap kept the
    # total bounded — a missing cap would let one tick retry indefinitely.
    assert 1 <= state["tick_calls"] <= 8, (
        f"expected bounded, capped retries; got {state['tick_calls']}"
    )


@pytest.mark.asyncio
async def test_scheduler_does_not_block_event_loop(tmp_path, monkeypatch):
    """The checkpoint runs via asyncio.to_thread, so a slow checkpoint
    must not block the event loop — a concurrent coroutine keeps running."""
    ctx = SharedContext(db_path=tmp_path / "noblock.db")

    def _slow_checkpoint():
        # Simulate a multi-hundred-ms checkpoint.
        import time

        time.sleep(0.3)
        return (0, 0, 10)

    monkeypatch.setattr(ctx, "wal_checkpoint", _slow_checkpoint)

    ticks = {"beat": 0}

    async def _heartbeat():
        for _ in range(20):
            ticks["beat"] += 1
            await asyncio.sleep(0.02)

    task = ctx.schedule_wal_checkpoint(interval_seconds=0.01, retry_delay=0.01)
    hb = asyncio.create_task(_heartbeat())
    await asyncio.sleep(0.4)
    task.cancel()
    hb.cancel()
    for t in (task, hb):
        try:
            await t
        except asyncio.CancelledError:
            pass

    # If the loop were blocked during the 0.3s checkpoint, the heartbeat
    # (20ms cadence) would have far fewer than ~10 beats in 0.4s.
    assert ticks["beat"] >= 8, (
        f"event loop appears blocked during checkpoint; only {ticks['beat']} beats"
    )
