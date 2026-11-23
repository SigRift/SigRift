"""Regression tests for AnalysisJobQueue resource bounds (review C2).

* sync handlers run in a worker thread, not on the event loop;
* finished jobs are evicted (TTL and count);
* oversized results fail the job; large results are kept compressed and
  their total is budgeted;
* ``submit_nowait`` queues from synchronous code (the ingest path called
  the coroutine ``submit`` without awaiting it, so no decode job ran).
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from sigrift.bridge.job_queue import AnalysisJobQueue


async def _wait_done(q: AnalysisJobQueue, job_id: str, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = q.get_job_status(job_id)
        if job is not None and job["status"] in ("completed", "failed", "cancelled"):
            return job
        await asyncio.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish")


@pytest.mark.asyncio
async def test_sync_handler_runs_off_the_event_loop() -> None:
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}

    def handler(job_id: str, params: dict) -> dict:
        seen["thread"] = threading.get_ident()
        time.sleep(0.3)  # a blocking FFT stand-in
        return {"ok": True}

    q = AnalysisJobQueue(max_workers=1)
    q.register_handler("slow", handler)
    await q.start()
    try:
        job_id = await q.submit("slow", {})
        # While the handler blocks, the loop keeps running other work.
        ticks = 0
        t_end = time.monotonic() + 0.2
        while time.monotonic() < t_end:
            await asyncio.sleep(0.01)
            ticks += 1
        assert ticks >= 5
        job = await _wait_done(q, job_id)
    finally:
        await q.stop()
    assert job["status"] == "completed"
    assert seen["thread"] != loop_thread


@pytest.mark.asyncio
async def test_async_handler_still_supported() -> None:
    async def handler(job_id: str, params: dict) -> dict:
        await asyncio.sleep(0)
        return {"v": params["v"]}

    q = AnalysisJobQueue(max_workers=1)
    q.register_handler("a", handler)
    await q.start()
    try:
        job = await _wait_done(q, await q.submit("a", {"v": 7}))
    finally:
        await q.stop()
    assert job["result"] == {"v": 7}


@pytest.mark.asyncio
async def test_finished_jobs_evicted_by_count() -> None:
    q = AnalysisJobQueue(max_workers=2, max_queue_size=100, max_finished_jobs=5)
    q.register_handler("echo", lambda job_id, params: {"i": params["i"]})
    await q.start()
    try:
        ids = [await q.submit("echo", {"i": i}) for i in range(20)]
        for job_id in ids[-2:]:
            await _wait_done(q, job_id)
        await asyncio.sleep(0.2)
        assert len(q._jobs) <= 5
        assert q.get_job_status(ids[-1]) is not None
        assert q.get_job_status(ids[0]) is None
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_finished_jobs_evicted_by_ttl() -> None:
    q = AnalysisJobQueue(max_workers=1, finished_job_ttl=0.2)
    q.register_handler("echo", lambda job_id, params: {})
    await q.start()
    try:
        job_id = await q.submit("echo", {})
        await _wait_done(q, job_id)
        await asyncio.sleep(0.3)
        assert q.get_job_status(job_id) is None
        assert job_id not in q._jobs
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_pending_and_running_jobs_are_never_evicted() -> None:
    release = threading.Event()

    def blocker(job_id: str, params: dict) -> dict:
        release.wait(5)
        return {}

    q = AnalysisJobQueue(max_workers=1, max_finished_jobs=1, finished_job_ttl=0.01)
    q.register_handler("block", blocker)
    await q.start()
    try:
        running = await q.submit("block", {})
        pending = await q.submit("block", {})
        await asyncio.sleep(0.1)
        q._evict_finished()
        assert q.get_job_status(running)["status"] == "running"
        assert q.get_job_status(pending)["status"] == "pending"
    finally:
        release.set()
        await q.stop()


@pytest.mark.asyncio
async def test_oversized_result_fails_the_job() -> None:
    q = AnalysisJobQueue(max_workers=1, max_result_bytes=10_000)
    q.register_handler("big", lambda job_id, params: {"data": [0.123456] * 10_000})
    await q.start()
    try:
        job = await _wait_done(q, await q.submit("big", {}))
    finally:
        await q.stop()
    assert job["status"] == "failed"
    assert "result too large" in job["error"]
    assert job["result"] is None


@pytest.mark.asyncio
async def test_large_result_kept_compressed_and_returned_intact() -> None:
    payload = {"spectrogram": [[float(i % 61) - 60.0] * 256 for i in range(512)]}
    q = AnalysisJobQueue(max_workers=1)
    q.register_handler("spec", lambda job_id, params: payload)
    await q.start()
    try:
        job_id = await q.submit("spec", {})
        job = await _wait_done(q, job_id)
        assert job["result"] == payload
        # Stored as compressed JSON, not as ~130k Python floats.
        assert q._jobs[job_id]["result"] is None
        assert len(q._result_blobs[job_id]) < 200_000
        listed = [j for j in q.list_jobs() if j["job_id"] == job_id][0]
        assert listed["result"] is None and listed["result_omitted"] is True
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_compressed_results_respect_the_budget() -> None:
    import random

    def noisy(job_id: str, params: dict) -> dict:
        rnd = random.Random(params["i"])
        return {"v": [rnd.random() for _ in range(20_000)]}

    q = AnalysisJobQueue(max_workers=1, result_budget_bytes=600_000)
    q.register_handler("noisy", noisy)
    await q.start()
    try:
        ids = [await q.submit("noisy", {"i": i}) for i in range(6)]
        await _wait_done(q, ids[-1])
        total = sum(len(b) for b in q._result_blobs.values())
        assert total <= 600_000
        assert q.get_job_status(ids[-1]) is not None
        assert q.get_job_status(ids[0]) is None
    finally:
        await q.stop()


@pytest.mark.asyncio
async def test_submit_nowait_from_sync_code() -> None:
    q = AnalysisJobQueue(max_workers=1)
    q.register_handler("echo", lambda job_id, params: {"x": params["x"]})
    await q.start()
    try:
        job_id = q.submit_nowait("echo", {"x": 1})
        job = await _wait_done(q, job_id)
    finally:
        await q.stop()
    assert job["result"] == {"x": 1}
    with pytest.raises(ValueError):
        q.submit_nowait("unknown", {})


def test_get_job_status_returns_a_copy() -> None:
    q = AnalysisJobQueue()
    q.register_handler("echo", lambda job_id, params: {})
    job_id = q.submit_nowait("echo", {})
    view = q.get_job_status(job_id)
    view["status"] = "tampered"
    assert q.get_job_status(job_id)["status"] == "pending"
