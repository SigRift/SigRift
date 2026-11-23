"""Durable retry lifecycle with actual sockets, SQLite and executor cancellation."""

from __future__ import annotations

import asyncio
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import subprocess
import sys
import threading
import time

import pytest

from sigrift.bridge import notifications
from sigrift.bridge.notifications import NotificationManager
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore


@pytest.fixture
def durable(tmp_path, monkeypatch):
    state = {"status": 503, "requests": [], "lose_response": False, "hold": False}
    accepted, release = threading.Event(), threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state["requests"].append(body)
            accepted.set()
            if state["hold"]:
                assert release.wait(5)
            if state["lose_response"]:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(state["status"])
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("BRIDGE_WEBHOOK_ALLOW_HOSTS", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    monkeypatch.setattr(notifications, "_MAX_RETRIES", 0)
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 0)
    ctx = SharedContext(tmp_path / "deliveries.db")
    store = WebhookRetryStore(ctx)
    configs = [
        {
            "id": "hook",
            "url": f"http://127.0.0.1:{server.server_port}/hook",
            "name": "test receiver",
            "enabled": True,
            "signing_secret": "disposable",
            "delivery_revision": "a" * 32,
        }
    ]
    managers = []

    def factory():
        manager = NotificationManager(
            retry_store=store, current_webhooks=lambda: copy.deepcopy(configs)
        )
        manager.load(copy.deepcopy(configs))
        managers.append(manager)
        return manager

    try:
        yield state, accepted, release, configs, store, factory
    finally:
        release.set()
        for manager in managers:
            manager._shutdown_executor()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        ctx.close()


async def _fail(manager):
    assert await manager.notify({"severity": "critical", "alert_id": "real-alert"}) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("ambiguous", [False, True])
async def test_exact_payload_and_stable_identity_after_failed_or_lost_response(
    durable, ambiguous
):
    state, _accepted, _release, _configs, store, factory = durable
    first = factory()
    state["lose_response"] = ambiguous
    await _fail(first)
    assert len(store.snapshot()["entries"]) == 1
    original = state["requests"][0]
    ident = json.loads(original)["delivery_id"]
    assert ident == store.snapshot()["entries"][0]["delivery_id"]
    await first.stop_deliveries()
    second = factory()
    state.update(status=204, lose_response=False)
    assert await second.retry_failed() == 1
    assert state["requests"] == [original, original]
    assert store.snapshot()["entries"] == []


@pytest.mark.asyncio
async def test_cancel_real_http_releases_claim_without_attempt_increment(durable):
    state, accepted, release, _configs, store, factory = durable
    manager = factory()
    await _fail(manager)
    accepted.clear()
    state.update(status=204, hold=True)
    retry = asyncio.create_task(manager.retry_failed())
    try:
        assert await asyncio.to_thread(accepted.wait, 3)
        retry.cancel()
        with pytest.raises(asyncio.CancelledError):
            await retry
        row = store.snapshot()["entries"][0]
        assert row["attempts"] == 1 and row["lease_token"] is None
        release.set()
        state["hold"] = False
        assert await factory().retry_failed() == 1
        assert store.snapshot()["entries"] == []
        assert len(set(state["requests"])) == 1
    finally:
        release.set()
        retry.cancel()
        await asyncio.gather(retry, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["delete", "disable", "target", "revision"])
async def test_config_change_during_real_dns_prevents_post(
    durable, monkeypatch, change
):
    state, _accepted, _release, configs, store, factory = durable
    manager = factory()
    await _fail(manager)
    entered, resume = asyncio.Event(), asyncio.Event()
    original = manager._vet_target

    async def gated(url):
        result = await original(url)
        entered.set()
        await resume.wait()
        return result

    monkeypatch.setattr(manager, "_vet_target", gated)
    pending = asyncio.create_task(manager.retry_failed())
    try:
        await asyncio.wait_for(entered.wait(), 3)
        if change == "delete":
            configs.clear()
        elif change == "disable":
            configs[0]["enabled"] = False
        elif change == "target":
            configs[0]["url"] += "/new"
        else:
            configs[0]["delivery_revision"] = "b" * 32
        resume.set()
        assert await pending == 0
        assert len(state["requests"]) == 1
        assert store.snapshot()["entries"] == []
        assert store.snapshot()["dropped"] == 1
    finally:
        resume.set()
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_unreadable_authority_preserves_pending_and_attempts(durable):
    state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    await _fail(manager)

    def unavailable():
        raise OSError("private destination must not be logged")

    manager._current_webhooks = unavailable
    assert await manager.retry_failed() == 0
    row = store.snapshot()["entries"][0]
    assert row["attempts"] == 1 and row["lease_token"] is None
    assert len(state["requests"]) == 1


@pytest.mark.asyncio
async def test_retry_rechecks_real_dns_policy_without_contacting_private_receiver(
    durable, monkeypatch
):
    state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    await _fail(manager)
    monkeypatch.delenv("BRIDGE_WEBHOOK_ALLOW_HOSTS")
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 5)
    assert await manager.retry_failed() == 0
    assert len(state["requests"]) == 1
    row = store.snapshot()["entries"][0]
    assert row["attempts"] == 2 and row["lease_token"] is None
    assert row["due_at"] > time.time()


@pytest.mark.asyncio
async def test_long_http_renews_live_lease_and_other_worker_cannot_claim(
    durable, monkeypatch
):
    state, accepted, release, _configs, store, factory = durable
    monkeypatch.setattr(notifications, "_RETRY_LEASE_SECONDS", 0.3)
    monkeypatch.setattr(notifications, "_RETRY_LEASE_RENEW_SECONDS", 0.05)
    manager = factory()
    await _fail(manager)
    accepted.clear()
    state.update(status=204, hold=True)
    pending = asyncio.create_task(manager.retry_failed())
    try:
        assert await asyncio.to_thread(accepted.wait, 3)
        first_until = store.snapshot()["entries"][0]["lease_until"]
        deadline = time.monotonic() + 3
        while time.time() <= first_until:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.02)
        assert store.claim(now=time.time(), lease_seconds=1) is None
        release.set()
        assert await pending == 1
    finally:
        release.set()
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.asyncio
async def test_insert_failure_is_visible_and_never_memory_fallback(durable):
    state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    store._ctx.get_conn().executescript(
        "CREATE TRIGGER fail_retry BEFORE INSERT ON webhook_retries "
        "BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END;"
    )
    with pytest.raises(RuntimeError, match="retry persistence unavailable"):
        await manager._deliver(manager.webhooks[0], {"alert_id": "failed"})
    assert manager._retry_storage_failures == 1
    assert manager.failed_queue == [] and store.snapshot()["entries"] == []
    assert len(state["requests"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_repeated_cancellation_waits_for_real_sqlite_enqueue(
    durable, monkeypatch, fails
):
    _state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    entered, resume, finished = (threading.Event() for _ in range(3))
    original = store.enqueue
    if fails:
        store._ctx.get_conn().executescript(
            "CREATE TRIGGER refuse_enqueue BEFORE INSERT ON webhook_retries "
            "BEGIN SELECT RAISE(ABORT, 'failed commit'); END;"
        )

    def gated(*args, **kwargs):
        entered.set()
        try:
            assert resume.wait(5)
            return original(*args, **kwargs)
        finally:
            finished.set()

    monkeypatch.setattr(store, "enqueue", gated)
    task = asyncio.create_task(
        manager._queue_failed(manager.webhooks[0], {"delivery_id": "cancel"}, "failure")
    )
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0.02)
            assert not task.done(), "cancellation returned before the SQLite callback"
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert finished.is_set()
        assert len(store.snapshot()["entries"]) == (0 if fails else 1)
    finally:
        resume.set()
        await asyncio.gather(task, return_exceptions=True)
        assert await asyncio.to_thread(finished.wait, 3)


@pytest.mark.asyncio
async def test_staging_overflow_cannot_remove_an_unrelated_entry_after_commit(
    durable, monkeypatch
):
    _state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    manager._retry_queue_max = 2
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 60)
    for label in ("A", "B"):
        manager._enqueue_failed(manager.webhooks[0], {"label": label}, "failed")
    entered, resume = threading.Event(), threading.Event()
    original = store.enqueue

    def gated(*args, **kwargs):
        if not entered.is_set():
            entered.set()
            assert resume.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "enqueue", gated)
    task = asyncio.create_task(manager.retry_failed())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        manager._enqueue_failed(manager.webhooks[0], {"label": "C"}, "failed")
        pending = [entry["payload"]["label"] for entry in manager.failed_queue]
        assert pending == ["A", "C"]  # Reserved A survives; B is explicitly dropped.
        assert manager.retry_dropped == 1
        resume.set()
        assert await task == 0
        assert manager.failed_queue == []
        assert [
            json.loads(row["payload"])["label"] for row in store.snapshot()["entries"]
        ] == ["A", "C"]
    finally:
        resume.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["claim", "release"])
async def test_repeated_cancel_waits_for_claim_and_release(durable, monkeypatch, stage):
    state, accepted, release_http, _configs, store, factory = durable
    manager = factory()
    await _fail(manager)
    accepted.clear()
    state.update(status=204, hold=True)
    entered, resume = threading.Event(), threading.Event()
    original = getattr(store, stage)

    def gated(*args, **kwargs):
        entered.set()
        assert resume.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, stage, gated)
    task = asyncio.create_task(manager.retry_failed())
    try:
        if stage == "release":
            assert await asyncio.to_thread(accepted.wait, 3)
            task.cancel()
        assert await asyncio.to_thread(entered.wait, 3)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0.02)
            assert not task.done()
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        row = store.snapshot()["entries"][0]
        assert row["lease_token"] is None and row["attempts"] == 1
    finally:
        resume.set()
        release_http.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_staged_enqueue_cancellation_preserves_only_uncommitted_work(
    durable, monkeypatch, fails
):
    _state, _accepted, _release, _configs, store, factory = durable
    manager = factory()
    manager._enqueue_failed(manager.webhooks[0], {"label": "retained"}, "failed")
    entered, resume = threading.Event(), threading.Event()
    original = store.enqueue
    if fails:
        store._ctx.get_conn().executescript(
            "CREATE TRIGGER refuse_staging BEFORE INSERT ON webhook_retries "
            "BEGIN SELECT RAISE(ABORT, 'failed staging'); END;"
        )

    def gated(*args, **kwargs):
        entered.set()
        assert resume.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "enqueue", gated)
    task = asyncio.create_task(manager.retry_failed())
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        task.cancel()
        await asyncio.sleep(0.02)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done()
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert len(manager.failed_queue) == int(fails)
        assert len(store.snapshot()["entries"]) == int(not fails)
        assert manager._staging_entry is None
    finally:
        resume.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_killed_worker_after_receiver_acceptance_replays_same_delivery(durable):
    state, accepted, release, configs, store, factory = durable
    manager = factory()
    await _fail(manager)
    accepted.clear()
    state.update(status=204, hold=True)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import asyncio,json,sys
from sigrift.bridge import notifications
from sigrift.bridge.notifications import NotificationManager
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore
notifications._RETRY_LEASE_SECONDS=0.3
notifications._RETRY_LEASE_RENEW_SECONDS=0.05
configs=json.loads(sys.argv[2])
ctx=SharedContext(sys.argv[1])
manager=NotificationManager(retry_store=WebhookRetryStore(ctx),current_webhooks=lambda:configs)
manager.load(configs)
asyncio.run(manager.retry_failed())
""",
            str(store._ctx._db_path),
            json.dumps(configs),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert await asyncio.to_thread(accepted.wait, 5)
        assert child.poll() is None
        child.kill()
        await asyncio.to_thread(child.communicate, timeout=3)
        row = store.snapshot()["entries"][0]
        assert row["lease_token"] is not None and row["attempts"] == 1
        deadline = time.monotonic() + 3
        while time.time() <= row["lease_until"]:
            assert time.monotonic() < deadline
            await asyncio.sleep(0.02)
        release.set()
        state["hold"] = False
        assert await factory().retry_failed() == 1
        assert store.snapshot()["entries"] == []
        assert len(state["requests"]) == 3
        assert len(set(state["requests"])) == 1
    finally:
        release.set()
        if child.poll() is None:
            child.kill()
        await asyncio.to_thread(child.communicate, timeout=3)
