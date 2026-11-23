"""Cancellation of real executor I/O must not consume pending webhook retries.

Only DNS and the external HTTP boundary are controlled. The executor, semaphore,
retry scheduling, cancellation and shutdown are the shipped implementations.
"""

from __future__ import annotations

import asyncio
import copy
import json
import threading
import time

import pytest

from sigrift.bridge import notifications as notif
from sigrift.bridge.notifications import NotificationManager


async def _until(predicate) -> None:
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.005)


class _IOBarrier:
    def __init__(self, stage: str, call: int = 1) -> None:
        self.stage = stage
        self.call = call
        self.entered = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.resolutions = 0
        self.posts: list[tuple[bytes, str | None]] = []
        self.thread_ids: list[int] = []

    def _block(self, stage: str, call: int) -> None:
        self.thread_ids.append(threading.get_ident())
        if stage == self.stage and call == self.call:
            self.entered.set()
            try:
                if not self.release.wait(10):
                    raise TimeoutError("test I/O barrier was not released")
            finally:
                self.finished.set()

    def resolve(self, _host: str) -> list[str]:
        self.resolutions += 1
        self._block("dns", self.resolutions)
        return ["93.184.216.34"]

    def post(self, _url, data, signature, addresses) -> int:
        assert addresses == ["93.184.216.34"]
        self.posts.append((data, signature))
        self._block("http", len(self.posts))
        return 200


def _queue(mgr: NotificationManager, webhook, count: int) -> list[dict]:
    for index in range(count):
        mgr._enqueue_failed(webhook, {"id": f"event-{index}"}, "initial failure")
        mgr._failed_queue[-1]["next_retry"] = time.monotonic() - 1
    return copy.deepcopy(mgr.failed_queue)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["dns", "http"])
async def test_stop_retains_current_and_unstarted_retries_and_can_resume(
    monkeypatch, stage
):
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    original = _queue(mgr, webhook, 3)
    barrier = _IOBarrier(stage)
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)
    monkeypatch.setattr(mgr, "_http_post", barrier.post)
    try:
        mgr.start_retry_loop(interval=0.001)
        await _until(barrier.entered.is_set)
        task = mgr._retry_task
        assert mgr.failed_queue == []  # Dequeued does not mean delivered.
        assert webhook["delivery_count"] == 0
        await mgr.stop_retry_loop()
        assert task is not None and task.cancelled()
        assert mgr._retry_task is None
        assert mgr.failed_queue == original
        assert mgr.retry_dropped == 0
        # This is the real application shutdown order. Running executor I/O can
        # finish afterward; it must not erase the entries retained for retry.
        await mgr.stop_deliveries()
        assert mgr._io_executor is None
        assert mgr.failed_queue == original
        assert not barrier.finished.is_set()
        barrier.release.set()
        await _until(barrier.finished.is_set)
        mgr.start_retry_loop(interval=0.001)
        await _until(lambda: webhook["delivery_count"] == 3)
        await mgr.stop_retry_loop()
        assert mgr.failed_queue == []
        assert mgr.retry_dropped == 0
        bodies = [json.loads(body)["id"] for body, _ in barrier.posts]
        assert bodies == (["event-0"] if stage == "http" else []) + [
            "event-0",
            "event-1",
            "event-2",
        ]
        if stage == "http":
            # The first HTTP attempt may already have reached its receiver.
            # Repeating an uncertain delivery preserves body/signature identity.
            assert barrier.posts[0] == barrier.posts[1]
        assert all(t != threading.get_ident() for t in barrier.thread_ids)
    finally:
        barrier.release.set()
        await mgr.stop_retry_loop()
        await mgr.stop_deliveries()
        if barrier.entered.is_set():
            await _until(barrier.finished.is_set)


@pytest.mark.asyncio
async def test_cancel_keeps_completed_success_out_of_queue_and_preserves_new_entries(
    monkeypatch,
):
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    original = _queue(mgr, webhook, 3)
    barrier = _IOBarrier("http", call=2)
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)
    monkeypatch.setattr(mgr, "_http_post", barrier.post)
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(barrier.entered.is_set)
        assert webhook["delivery_count"] == 1
        mgr._enqueue_failed(webhook, {"id": "new-event"}, "new failure")
        new_entry = copy.deepcopy(mgr.failed_queue[0])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert mgr.failed_queue == [new_entry, *original[1:]]
        barrier.release.set()
        await _until(barrier.finished.is_set)
        assert await mgr.retry_failed() == 2
        assert mgr.failed_queue == [new_entry]  # Not yet due; no forced retry.
        assert webhook["delivery_count"] == 3
        assert [json.loads(body)["id"] for body, _ in barrier.posts].count(
            "event-0"
        ) == 1
    finally:
        barrier.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await mgr.stop_deliveries()
        await _until(barrier.finished.is_set)


@pytest.mark.asyncio
async def test_concurrent_retry_pass_cannot_claim_the_same_due_batch(monkeypatch):
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    _queue(mgr, webhook, 2)
    barrier = _IOBarrier("dns")
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)
    monkeypatch.setattr(mgr, "_http_post", barrier.post)
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(barrier.entered.is_set)
        assert await mgr.retry_failed() == 0
        mgr._enqueue_failed(webhook, {"id": "new-event"}, "new failure")
        mgr._failed_queue[0]["next_retry"] = time.monotonic() - 1
        assert await mgr.retry_failed() == 1
        barrier.release.set()
        assert await asyncio.wait_for(task, 5) == 2
        assert sorted(json.loads(body)["id"] for body, _ in barrier.posts) == [
            "event-0",
            "event-1",
            "new-event",
        ]
        assert webhook["delivery_count"] == 3
        assert mgr.failed_queue == []
    finally:
        barrier.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await mgr.stop_deliveries()


@pytest.mark.asyncio
async def test_cancel_does_not_consume_retry_budget_or_change_failure_backoff(
    monkeypatch,
):
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    original = _queue(mgr, webhook, 1)
    barrier = _IOBarrier("dns")
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(barrier.entered.is_set)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert mgr.failed_queue == original
        barrier.release.set()
        await _until(barrier.finished.is_set)

        def fail_post(*_args):
            raise OSError("receiver unavailable")

        monkeypatch.setattr(mgr, "_http_post", fail_post)
        before = time.monotonic()
        assert await mgr.retry_failed() == 0
        after = time.monotonic()
        [entry] = mgr.failed_queue
        assert entry["attempts"] == 2
        assert entry["last_error"] == "receiver unavailable"
        assert before + 20 <= entry["next_retry"] <= after + 20
        assert await mgr.retry_failed() == 0  # Backoff is honored.
        assert entry["attempts"] == 2
        # Only actual failed deliveries consume the remaining retry budget.
        for expected_attempts in (3, 4, 5):
            entry["next_retry"] = time.monotonic() - 1
            assert await mgr.retry_failed() == 0
            assert entry["attempts"] == expected_attempts
        assert mgr.failed_queue == []
        assert mgr.retry_dropped == 1
        assert webhook["delivery_count"] == 0
    finally:
        barrier.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await mgr.stop_deliveries()
        await _until(barrier.finished.is_set)


@pytest.mark.asyncio
async def test_cancel_requeue_obeys_capacity_and_accounts_for_overflow(monkeypatch):
    monkeypatch.setenv("BRIDGE_WEBHOOK_RETRY_QUEUE_MAX", "3")
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    original = _queue(mgr, webhook, 3)
    barrier = _IOBarrier("dns")
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(barrier.entered.is_set)
        mgr._enqueue_failed(webhook, {"id": "new-event"}, "new failure")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert mgr.failed_queue == original
        assert mgr.retry_dropped == 1
        assert len(mgr.failed_queue) == 3
    finally:
        barrier.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await mgr.stop_deliveries()
        await _until(barrier.finished.is_set)


@pytest.mark.asyncio
async def test_cancel_while_waiting_for_io_capacity_restores_batch():
    mgr = NotificationManager()
    webhook = mgr.add_webhook("https://example.com/hook")
    original = _queue(mgr, webhook, 2)
    for _ in range(notif._MAX_CONCURRENT):
        await mgr._semaphore.acquire()
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(lambda: not mgr.failed_queue)
        assert not task.done()
        assert mgr._io_executor is None
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert mgr.failed_queue == original
        assert mgr.retry_dropped == 0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        for _ in range(notif._MAX_CONCURRENT):
            mgr._semaphore.release()
        await mgr.stop_deliveries()


@pytest.mark.asyncio
@pytest.mark.parametrize("finalized", ["deleted", "exhausted"])
async def test_cancel_does_not_restore_previously_finalized_entries(
    monkeypatch, finalized
):
    mgr = NotificationManager()
    first = mgr.add_webhook("https://example.com/first")
    second = mgr.add_webhook("https://example.com/second")
    _queue(mgr, first, 1)
    mgr._failed_queue[0]["attempts"] = 4
    mgr._enqueue_failed(second, {"id": "remaining"}, "down")
    mgr._failed_queue[-1]["next_retry"] = time.monotonic() - 1
    remaining = copy.deepcopy(mgr.failed_queue[-1])
    if finalized == "deleted":
        assert mgr.remove_webhook(first["id"])
    barrier = _IOBarrier("dns", call=1 if finalized == "deleted" else 2)
    monkeypatch.setattr(notif, "_resolve_and_check_ip", barrier.resolve)

    def fail_first(*_args):
        raise OSError("receiver unavailable")

    monkeypatch.setattr(mgr, "_http_post", fail_first)
    task = asyncio.create_task(mgr.retry_failed())
    try:
        await _until(barrier.entered.is_set)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert mgr.failed_queue == [remaining]
        assert mgr.retry_dropped == (1 if finalized == "exhausted" else 0)
        assert first["delivery_count"] == second["delivery_count"] == 0
    finally:
        barrier.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await mgr.stop_deliveries()
        await _until(barrier.finished.is_set)
