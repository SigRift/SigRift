"""Shutdown never closes the database under a running worker thread (review Q8).

Round 3 made ``SharedContext.close()`` close every thread's connection
(``check_same_thread=False``) and moved sync job handlers into
``asyncio.to_thread``.  Cancelling a task does not stop its thread, and
closing a sqlite3 connection while another thread steps a statement on it
crashes the interpreter — and shutdown closed the DB *before* the final
persistence save.  Now:

* ``close()`` closes only the caller's connection and those of threads
  that have exited; a live thread retires its own connection on next use;
* the job queue waits (bounded) for handler threads on ``stop()``;
* the write queue stops its flush loop gracefully;
* the lifespan saves persistence before any of those bounded waits (a
  container's stop grace period may end during them), saves again after
  them, waits (bounded) for the default executor's threads, then closes
  the DB.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.job_queue import AnalysisJobQueue
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.worker_threads import (
    TrackingThreadPoolExecutor,
    wait_until_idle,
)
from sigrift.bridge.write_queue import WriteQueue

# ---------------------------------------------------------------------------
# SharedContext.close()
# ---------------------------------------------------------------------------


class TestCloseLeavesLiveThreadsAlone:
    def test_live_threads_connection_stays_usable(self, tmp_path: Path) -> None:
        ctx = SharedContext(db_path=tmp_path / "c.db")
        opened, closed, done = threading.Event(), threading.Event(), threading.Event()
        result: list[object] = []

        def worker() -> None:
            conn = ctx.get_conn()
            conn.execute("CREATE TABLE IF NOT EXISTS t (x)")
            opened.set()
            closed.wait(10)
            # Still this thread's connection (a statement in flight would
            # be stepping it now): it must not have been closed under it.
            try:
                result.append(tuple(conn.execute("SELECT 1").fetchone()))
            except Exception as exc:  # pragma: no cover - the bug
                result.append(exc)
            done.set()

        t = threading.Thread(target=worker)
        t.start()
        assert opened.wait(10)
        ctx.close()
        closed.set()
        assert done.wait(10)
        t.join(10)
        assert result == [(1,)]
        # The thread has exited: a later close() closes its connection.
        assert len(ctx._conn_registry) == 1
        ctx.close()
        assert not ctx._conn_registry

    def test_callers_own_connection_is_closed(self, tmp_path: Path) -> None:
        ctx = SharedContext(db_path=tmp_path / "c.db")
        conn = ctx.get_conn()
        ctx.close()
        with pytest.raises(Exception, match="closed"):
            conn.execute("SELECT 1")
        assert tuple(ctx.get_conn().execute("SELECT 1").fetchone()) == (1,)

    def test_live_thread_retires_its_connection_on_next_use(
        self, tmp_path: Path
    ) -> None:
        ctx = SharedContext(db_path=tmp_path / "c.db")
        go, done = threading.Event(), threading.Event()
        conns: list[object] = []

        def worker() -> None:
            conns.append(ctx.get_conn())
            go.wait(10)
            conns.append(ctx.get_conn())
            done.set()

        t = threading.Thread(target=worker)
        t.start()
        while not conns:
            time.sleep(0.01)
        ctx.close()
        go.set()
        assert done.wait(10)
        t.join(10)
        old, new = conns
        assert old is not new
        with pytest.raises(Exception, match="closed"):
            old.execute("SELECT 1")
        assert list(ctx._conn_registry) == [new]

    def test_open_transaction_finishes_on_its_connection(self, tmp_path: Path) -> None:
        ctx = SharedContext(db_path=tmp_path / "c.db")
        ctx.get_conn().execute("CREATE TABLE t (x)")
        ctx.get_conn().commit()
        began, go, done = threading.Event(), threading.Event(), threading.Event()
        seen: list[object] = []

        def worker() -> None:
            with ctx.write_transaction() as conn:
                conn.execute("INSERT INTO t VALUES (1)")
                began.set()
                go.wait(10)
                # A nested store call mid-transaction gets the same connection.
                seen.append(ctx.get_conn() is conn)
                conn.execute("INSERT INTO t VALUES (2)")
            seen.append(ctx.get_conn() is conn)  # retired once committed
            done.set()

        t = threading.Thread(target=worker)
        t.start()
        assert began.wait(10)
        ctx.close()
        go.set()
        assert done.wait(10)
        t.join(10)
        assert seen == [True, False]
        rows = ctx.get_conn().execute("SELECT x FROM t ORDER BY x").fetchall()
        assert [tuple(r) for r in rows] == [(1,), (2,)]


# ---------------------------------------------------------------------------
# Job queue / write queue
# ---------------------------------------------------------------------------


class TestJobQueueWaitsForHandlerThreads:
    def test_stop_waits_for_a_running_handler(self) -> None:
        finished = threading.Event()

        def slow(job_id: str, params: dict) -> dict:
            time.sleep(0.5)
            finished.set()
            return {}

        async def run() -> tuple[bool, dict]:
            queue = AnalysisJobQueue(max_workers=1)  # default wait: 5 s
            queue.register_handler("slow", slow)
            await queue.start()
            job_id = await queue.submit("slow", {})
            while queue.get_job_status(job_id)["status"] != "running":
                await asyncio.sleep(0.01)
            await queue.stop()
            return finished.is_set(), queue.get_job_status(job_id)

        was_finished, job = asyncio.run(run())
        assert was_finished  # stop() returned only after the thread ended
        assert job["status"] == "failed"
        assert "stopped" in job["error"]

    def test_wait_is_bounded(self, caplog) -> None:
        release = threading.Event()

        def stuck(job_id: str, params: dict) -> dict:
            release.wait(10)
            return {}

        async def run() -> float:
            queue = AnalysisJobQueue(max_workers=1, stop_timeout=0.2)
            queue.register_handler("stuck", stuck)
            await queue.start()
            job_id = await queue.submit("stuck", {})
            while queue.get_job_status(job_id)["status"] != "running":
                await asyncio.sleep(0.01)
            started = time.monotonic()
            await queue.stop()
            return time.monotonic() - started

        try:
            with caplog.at_level("WARNING"):
                elapsed = asyncio.run(run())
        finally:
            release.set()
        assert elapsed < 2.0
        assert any("still running" in r.getMessage() for r in caplog.records)


class _RecordingStore:
    def __init__(self, delay: float = 0.0) -> None:
        self.batches: list[list[object]] = []
        self.delay = delay

    def insert_batch(self, batch: list[object]) -> int:
        time.sleep(self.delay)
        self.batches.append(list(batch))
        return len(batch)


class TestWriteQueueStop:
    def test_stop_is_prompt_and_flushes_everything(self) -> None:
        store = _RecordingStore()

        async def run() -> float:
            wq = WriteQueue(store, batch_size=1000, flush_interval_ms=60_000)
            await wq.start()
            await wq.enqueue_batch([object() for _ in range(7)])
            started = time.monotonic()
            await wq.stop()
            return time.monotonic() - started

        assert asyncio.run(run()) < 2.0
        assert sum(len(b) for b in store.batches) == 7

    def test_stop_lets_an_in_flight_flush_finish(self) -> None:
        # stop() used to cancel the loop mid-insert; its final drain then
        # inserted the in-flight batch a second time.
        store = _RecordingStore(delay=0.5)
        items = [object() for _ in range(5)]

        async def run() -> None:
            wq = WriteQueue(store, batch_size=5, flush_interval_ms=10)
            await wq.start()
            await wq.enqueue_batch(items)
            await asyncio.sleep(0.1)  # the flush of the 5 is in flight
            await wq.stop()
            await asyncio.sleep(0.7)

        asyncio.run(run())
        inserted = [item for batch in store.batches for item in batch]
        assert len(inserted) == len(set(map(id, inserted))) == 5

    def test_cancelled_flush_is_not_inserted_twice(self) -> None:
        store = _RecordingStore(delay=0.5)
        items = [object() for _ in range(5)]

        async def run() -> None:
            wq = WriteQueue(store, batch_size=5, flush_interval_ms=10)
            await wq.start()
            await wq.enqueue_batch(items)
            await asyncio.sleep(0.1)  # the flush of the 5 is in flight
            await wq.stop(timeout=0.05)  # too short: the loop is cancelled
            await asyncio.sleep(0.7)  # let the in-flight insert finish

        asyncio.run(run())
        inserted = [item for batch in store.batches for item in batch]
        assert len(inserted) == len(set(map(id, inserted))) == 5


# ---------------------------------------------------------------------------
# Default executor tracking
# ---------------------------------------------------------------------------


def test_wait_until_idle_waits_for_to_thread_work() -> None:
    finished = threading.Event()

    def work() -> None:
        time.sleep(0.4)
        finished.set()

    async def run() -> tuple[bool, bool]:
        executor = TrackingThreadPoolExecutor()
        asyncio.get_running_loop().set_default_executor(executor)
        task = asyncio.create_task(asyncio.to_thread(work))
        await asyncio.sleep(0.05)
        task.cancel()  # the thread keeps running, as in shutdown
        await asyncio.gather(task, return_exceptions=True)
        idle = await wait_until_idle(executor, timeout=5)
        return idle, finished.is_set()

    assert asyncio.run(run()) == (True, True)


def test_wait_until_idle_is_bounded() -> None:
    release = threading.Event()

    async def run() -> tuple[bool, float]:
        executor = TrackingThreadPoolExecutor()
        executor.submit(release.wait, 10)
        started = time.monotonic()
        idle = await wait_until_idle(executor, timeout=0.2)
        return idle, time.monotonic() - started

    try:
        idle, elapsed = asyncio.run(run())
    finally:
        release.set()
    assert idle is False and elapsed < 1.0


# ---------------------------------------------------------------------------
# Lifespan shutdown order
# ---------------------------------------------------------------------------


def _lifespan_patches(data: Path):
    from sigrift.bridge.anomaly.pcap_store import PcapStore
    from sigrift.bridge.detection_store import DetectionStore
    from sigrift.bridge.iq_store import IQStore
    from sigrift.bridge.persistence import PersistenceManager

    class _PM(PersistenceManager):
        def __init__(self, data_dir=None, auto_save_interval=60.0):
            super().__init__(data_dir=data_dir or data, auto_save_interval=60.0)

    class _DS(DetectionStore):
        def __init__(self, db_path=None):
            super().__init__(db_path=db_path or (data / "test.db"))

    class _IQ(IQStore):
        def __init__(self, base_dir=None):
            super().__init__(base_dir=base_dir or (data / "iq"))

    class _PC(PcapStore):
        def __init__(self, base_dir=None):
            super().__init__(base_dir=base_dir or (data / "pcap"))

    env = {
        "BRIDGE_LOG_LEVEL": "WARNING",
        "BRIDGE_FAMILY_MODEL": str(data / "none.pth"),
        "BRIDGE_FINGERPRINT_MODEL": str(data / "none_fp.pth"),
    }
    return [
        patch.dict(os.environ, env),
        patch.multiple(
            "sigrift.bridge.app",
            _STATIC_DIR=data / "static",
            _TEMPLATES_DIR=data / "templates",
        ),
        patch("sigrift.bridge.app.PersistenceManager", wraps=_PM),
        patch("sigrift.bridge.app.DetectionStore", wraps=_DS),
        patch("sigrift.bridge.app.IQStore", wraps=_IQ),
        patch("sigrift.bridge.app.PcapStore", wraps=_PC),
    ]


def test_lifespan_saves_before_waiting_and_again_before_closing_the_db(
    tmp_path: Path,
) -> None:
    """The final save precedes every bounded wait (BR2-V4).

    Docker sends SIGKILL 10 s after SIGTERM by default, and the job-thread
    wait (5 s), the write-queue flush (10 s) and the worker-thread wait
    (5 s) can use all of it: a save placed after them could be killed.
    What changed during the waits is saved once more before the database
    is closed.
    """
    import contextlib
    import json

    from sigrift.bridge.app import lifespan

    data = tmp_path / "data"
    data.mkdir()
    app = FastAPI(lifespan=lifespan)
    events: list[str] = []

    def slow_job(job_id: str, params: dict) -> dict:
        app.state.detection_store._ctx.get_conn().execute("SELECT 1").fetchone()
        time.sleep(0.5)
        app.state.persistence.set_node("node-from-job", {"node_id": "node-from-job"})
        events.append("job thread done")
        return {}

    with contextlib.ExitStack() as stack:
        for p in _lifespan_patches(data):
            stack.enter_context(p)
        with TestClient(app):
            store = app.state.detection_store
            pm = app.state.persistence
            real_close, real_save = store.close, pm.async_save_all

            def close() -> None:
                events.append("db close")
                real_close()

            async def async_save_all() -> None:
                events.append("save")
                await real_save()

            store.close = close
            pm.async_save_all = async_save_all
            queue = app.state.job_queue
            queue.register_handler("slow_job", slow_job)
            queue.submit_nowait("slow_job", {})
            deadline = time.monotonic() + 5
            while not [j for j in queue.list_jobs() if j["status"] == "running"]:
                assert time.monotonic() < deadline
                time.sleep(0.01)
    assert events == ["save", "job thread done", "save", "db close"]
    nodes = json.loads((data / "nodes.json").read_text())["nodes"]
    assert "node-from-job" in nodes
