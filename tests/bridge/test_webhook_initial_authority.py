"""Initial deliveries must select and recheck shared endpoint authority."""

from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

import pytest

from sigrift.bridge import notifications
from sigrift.bridge.notifications import NotificationManager
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore


@pytest.fixture
def shared_receivers(tmp_path, monkeypatch):
    class Received(list):
        status = 204
        release = None

        def __init__(self):
            super().__init__()
            self.accepted = threading.Event()

    received = Received()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, body, self.headers.get("X-Bridge-Signature")))
            response_status = received.status
            received.accepted.set()
            if received.release is not None:
                assert received.release.wait(5)
            self.send_response(response_status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.01), daemon=True
    )
    thread.start()
    monkeypatch.setenv("BRIDGE_WEBHOOK_ALLOW_HOSTS", "127.0.0.1")
    for key in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(notifications, "_MAX_RETRIES", 0)
    contexts, managers = [], []
    base = f"http://127.0.0.1:{server.server_port}"
    original = {
        "id": "owned",
        "name": "synthetic receiver",
        "url": base + "/old",
        "enabled": True,
        "severity_filter": ["critical"],
        "signing_secret": "synthetic-old-secret",
    }

    def factory(*, disabled=False, empty=False):
        first_pm = PersistenceManager(tmp_path, auto_save_interval=0)
        first_pm.load_all()
        first_pm.set_webhooks([] if empty else [{**original, "enabled": not disabled}])
        second_pm = PersistenceManager(tmp_path, auto_save_interval=0)
        second_pm.load_all()
        result = []
        for pm in (first_pm, second_pm):
            ctx = SharedContext(tmp_path / "deliveries.db")
            contexts.append(ctx)
            notifier = NotificationManager(
                retry_store=WebhookRetryStore(ctx), current_webhooks=pm.current_webhooks
            )
            notifier.load(pm.current_webhooks())
            managers.append(notifier)
            result.append((pm, notifier))
        return result

    def change(pm, notifier, kind):
        if kind == "delete":
            pm.change_webhook("owned", delete=True)
        elif kind == "new":
            pm.change_webhook("owned", create=original)
        elif kind == "disable-cycle":
            pm.change_webhook("owned", updates={"enabled": False})
            pm.change_webhook("owned", updates={"enabled": True})
        elif kind == "url-cycle":
            pm.change_webhook("owned", updates={"url": base + "/new"})
            pm.change_webhook("owned", updates={"url": base + "/old"})
        elif kind != "unchanged":
            update = {
                "disable": {"enabled": False},
                "enable": {"enabled": True},
                "url": {"url": base + "/new"},
                "secret": {"signing_secret": "synthetic-new-secret"},
                "severity": {"severity_filter": ["warning"]},
            }[kind]
            pm.change_webhook("owned", updates=update)
        notifier.load(pm.current_webhooks())

    try:
        yield received, original, factory, change
    finally:
        if received.release is not None:
            received.release.set()
        for notifier in managers:
            notifier._shutdown_executor()
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        for ctx in contexts:
            ctx.close()


async def invoke(notifier, method):
    alert = {"severity": "critical", "alert_id": "synthetic-shared-authority"}
    if method == "notify":
        return await asyncio.wait_for(notifier.notify(alert), 5)
    accepted = notifier.submit(alert)
    await notifier.stop_deliveries(grace_seconds=5)
    return accepted


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["notify", "submit"])
@pytest.mark.parametrize(
    "change_kind",
    ["delete", "disable", "url", "secret", "enable", "new", "severity", "unchanged"],
)
async def test_initial_send_observes_completed_other_worker_configuration(
    shared_receivers, method, change_kind
):
    received, original, factory, change = shared_receivers
    (_first_pm, first), (second_pm, second) = factory(
        disabled=change_kind == "enable", empty=change_kind == "new"
    )
    change(second_pm, second, change_kind)
    await invoke(first, method)
    if change_kind in {"delete", "disable", "severity"}:
        assert received == [], (
            "A completed remote policy change must prevent initial delivery"
        )
    else:
        assert len(received) == 1, "Freshly enabled/new endpoints must be discovered"
        path, body, signature = received[0]
        assert path == ("/new" if change_kind == "url" else "/old")
        secret = (
            "synthetic-new-secret"
            if change_kind == "secret"
            else original["signing_secret"]
        )
        assert signature == NotificationManager.compute_signature(secret, body)
        assert json.loads(body)["delivery_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["notify", "submit"])
@pytest.mark.parametrize(
    "change_kind",
    [
        "delete",
        "disable",
        "url",
        "secret",
        "severity",
        "disable-cycle",
        "url-cycle",
        "unchanged",
    ],
)
async def test_initial_send_rechecks_authority_after_actual_dns(
    shared_receivers, monkeypatch, method, change_kind
):
    received, _original, factory, change = shared_receivers
    (_first_pm, first), (second_pm, second) = factory()
    entered, resume = asyncio.Event(), asyncio.Event()
    original_vet = first._vet_target

    async def pause_after_dns(url):
        checked = await original_vet(url)
        entered.set()
        await resume.wait()
        return checked

    monkeypatch.setattr(first, "_vet_target", pause_after_dns)
    task = asyncio.create_task(invoke(first, method))
    try:
        await asyncio.wait_for(entered.wait(), 3)
        change(second_pm, second, change_kind)
        resume.set()
        await task
        assert len(received) == int(change_kind == "unchanged"), (
            "Old admission must not survive a changed authority snapshot"
        )
    finally:
        resume.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await first.stop_deliveries(grace_seconds=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["notify", "submit"])
async def test_unreadable_initial_authority_never_uses_cached_endpoint(
    shared_receivers, tmp_path, method
):
    received, _original, factory, _change = shared_receivers
    (_first_pm, first), (_second_pm, _second) = factory()
    (tmp_path / "webhooks.json").write_text('{"webhooks": "invalid"}')
    await invoke(first, method)
    assert received == [], "Unreadable authority must fail closed, not use a cached URL"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change_kind",
    ["delete", "disable", "url", "secret", "severity", "disable-cycle", "url-cycle"],
)
@pytest.mark.parametrize("method", ["notify", "submit"])
async def test_every_inline_retry_rechecks_shared_policy_after_real_503(
    shared_receivers, monkeypatch, change_kind, method
):
    received, _original, factory, change = shared_receivers
    (_pm, first), (second_pm, second) = factory()
    monkeypatch.setattr(notifications, "_MAX_RETRIES", 1)
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 0)
    received.status = 503
    received.release = threading.Event()
    task = asyncio.create_task(invoke(first, method))
    try:
        assert await asyncio.to_thread(received.accepted.wait, 3)
        change(second_pm, second, change_kind)
        received.release.set()
        await task
        assert len(received) == 1
        assert first._retry_store.snapshot()["entries"] == []
        assert first.initial_dispatch["policy_cancelled"] == 1
    finally:
        received.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await first.stop_deliveries(grace_seconds=1)


@pytest.mark.asyncio
async def test_submit_remains_nonblocking_while_real_config_file_lock_is_held(
    shared_receivers,
):
    received, _original, factory, _change = shared_receivers
    (pm, first), (second_pm, _second) = factory()
    entered = threading.Event()
    original = first._current_webhooks

    def observed_read():
        entered.set()
        return original()

    first._current_webhooks = observed_read
    with second_pm._file_lock:
        alert = {"severity": "critical", "name": "immutable", "nested": {"value": 1}}
        started = time.monotonic()
        assert first.submit(alert) == 1
        assert time.monotonic() - started < 0.25
        assert await asyncio.to_thread(entered.wait, 2)
        # The dedicated authority thread may block; ordinary off-loop Bridge work must not.
        assert (
            await asyncio.wait_for(asyncio.to_thread(lambda: "default-pool-alive"), 1)
            == "default-pool-alive"
        )
        assert received == []
        assert first.initial_dispatch["queued"] == 1
        alert["nested"]["value"] = 999
        alert["name"] = "changed"
    await first.stop_deliveries(grace_seconds=3)
    assert len(received) == 1
    body = json.loads(received[0][1])
    assert body["alert"]["name"] == "immutable" and body["context"]["nested"] == {
        "value": 1
    }
    assert (
        first.initial_dispatch["queued"]
        == first.initial_dispatch["serialized_bytes"]
        == 0
    )
    assert first.submit({"severity": "critical"}) == 0
    assert first.initial_dispatch["closed_rejected"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("limit", ["count", "bytes", "payload"])
async def test_intake_limits_include_reserved_authority_read_and_refuse_without_retry_row(
    shared_receivers, limit
):
    _received, _original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    entered = threading.Event()
    original = first._current_webhooks

    def observed_read():
        entered.set()
        return original()

    first._current_webhooks = observed_read
    alert = {"severity": "critical", "message": "é" * 10}
    size = len(json.dumps(alert, allow_nan=False).encode())
    if limit == "count":
        first._intake_max = 1
    elif limit == "bytes":
        first._intake_max_bytes = size
    else:
        first._intake_max_payload = size
    with second_pm._file_lock:
        assert first.submit(alert) == 1
        assert await asyncio.to_thread(entered.wait, 2)
        rejected = {**alert, "message": "é" * 11} if limit == "payload" else alert
        assert first.submit(rejected) == 0
        assert first.initial_dispatch["queued"] == 1
        assert first.initial_dispatch["serialized_bytes"] == size
        assert first.initial_dispatch["capacity_rejected"] == 1
        assert first._retry_store.snapshot()["entries"] == []
    await first.stop_deliveries(grace_seconds=3)
    assert first.initial_dispatch["accepted"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad", [None, {"severity": float("nan")}, {"severity": object()}]
)
async def test_invalid_intent_is_refused_before_task_or_authority_read(
    shared_receivers, bad
):
    _received, _original, factory, _change = shared_receivers
    (_pm, first), _second = factory()
    assert first.submit(bad) == 0
    assert first._intake_task is None and first._authority_executor is None
    assert first.initial_dispatch["invalid_rejected"] == 1
    await first.stop_deliveries(grace_seconds=0)


@pytest.mark.asyncio
async def test_acceptance_is_one_intent_not_matching_count_and_fanout_is_bounded(
    shared_receivers,
):
    received, original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    second_pm.change_webhook(
        "second",
        create={**original, "id": "second", "url": original["url"] + "/second"},
    )
    first._max_pending = 1
    received.release = threading.Event()
    assert first.submit({"severity": "critical"}) == 1
    try:
        assert await asyncio.to_thread(received.accepted.wait, 3)
        assert first.pending_deliveries == 1
        assert first.initial_dispatch["queued"] == 1  # current fanout remains reserved
        assert len(received) == 1
    finally:
        received.release.set()
    await first.stop_deliveries(grace_seconds=3)
    assert len(received) == 2
    assert (
        first.initial_dispatch["accepted"] == first.initial_dispatch["dispatched"] == 1
    )
    assert first._retry_store.snapshot()["entries"] == []


@pytest.mark.asyncio
async def test_repeated_stop_cancellation_settles_actual_config_read_and_accounts_intents(
    shared_receivers,
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    entered = threading.Event()
    original = first._current_webhooks

    def observed_read():
        entered.set()
        return original()

    first._current_webhooks = observed_read
    with second_pm._file_lock:
        assert first.submit({"severity": "critical", "alert_id": "reserved"}) == 1
        assert first.submit({"severity": "critical", "alert_id": "queued"}) == 1
        assert await asyncio.to_thread(entered.wait, 2)
        stopping = asyncio.create_task(first.stop_deliveries(grace_seconds=0))
        # Give the owned closer a chance to cancel the blocked read, then repeat caller cancellation.
        await asyncio.sleep(0.02)
        stopping.cancel()
        await asyncio.sleep(0.02)
        stopping.cancel()
        await asyncio.sleep(0.02)
        assert not stopping.done() and received == []
        assert first.submit({"severity": "critical"}) == 0
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(stopping, 3)
    assert first.initial_dispatch["shutdown_discarded"] == 2
    assert (
        first.initial_dispatch["queued"]
        == first.initial_dispatch["serialized_bytes"]
        == 0
    )
    assert first._intake_task.done() and not first._pending
    assert first._authority_executor is first._io_executor is None
    assert received == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["notify", "admin-test"])
async def test_direct_initial_request_is_owned_by_stop_and_cannot_restart_pools(
    shared_receivers, method
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    entered = threading.Event()
    original = first._current_webhooks

    def observed_read():
        entered.set()
        return original()

    first._current_webhooks = observed_read
    alert = {"severity": "critical"}
    with second_pm._file_lock:
        request = asyncio.create_task(
            first.notify(alert)
            if method == "notify"
            else first._deliver(first.webhooks[0], alert)
        )
        assert await asyncio.to_thread(entered.wait, 2)
        stopping = asyncio.create_task(first.stop_deliveries(grace_seconds=0))
        await asyncio.sleep(0.03)
        assert not stopping.done()
    await asyncio.wait_for(stopping, 3)
    with pytest.raises(asyncio.CancelledError):
        await request
    assert received == []
    assert (
        not first._direct_pending and not first._active_requests and not first._pending
    )
    assert await first.notify(alert) == 0
    assert await first._deliver(first.webhooks[0], alert) is False
    assert first._authority_executor is first._io_executor is None


@pytest.mark.asyncio
async def test_authority_failure_and_zero_match_are_visible_without_old_target_retry(
    shared_receivers, tmp_path
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    second_pm.change_webhook("owned", updates={"enabled": False})
    assert first.submit({"severity": "critical"}) == 1
    await first._intake_task
    assert first.initial_dispatch["no_matching"] == 1
    (tmp_path / "webhooks.json").write_text('{"webhooks": "invalid"}')
    assert first.submit({"severity": "critical"}) == 1
    await first.stop_deliveries(grace_seconds=3)
    assert first.initial_dispatch["authority_failures"] == 1
    assert first.initial_dispatch["accepted"] == 2
    assert first._retry_store.snapshot()["entries"] == []
    assert received == []


@pytest.mark.asyncio
@pytest.mark.parametrize("filter_value", [None, "critical", [1]])
async def test_malformed_severity_authority_fails_closed(
    shared_receivers, filter_value
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (second_pm, _second) = factory()
    second_pm.change_webhook("owned", updates={"severity_filter": filter_value})
    assert first.submit({"severity": "critical"}) == 1
    await first.stop_deliveries(grace_seconds=3)
    assert received == [] and first.initial_dispatch["authority_failures"] == 1
    assert first._retry_store.snapshot()["entries"] == []


@pytest.mark.asyncio
async def test_accepted_intent_waits_for_owned_admin_request_slot(shared_receivers):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (_other_pm, _second) = factory()
    first._max_pending = 1
    received.release = threading.Event()
    testing = asyncio.create_task(
        first._deliver(first.webhooks[0], {"severity": "critical"})
    )
    try:
        assert await asyncio.to_thread(received.accepted.wait, 2)
        assert (
            first.submit({"severity": "critical", "alert_id": "after-admin-test"}) == 1
        )
        await first._intake_task
        await asyncio.sleep(0.03)
        assert len(received) == 1
        assert first.initial_dispatch["capacity_rejected"] == 0
        received.release.set()
        assert await asyncio.wait_for(testing, 3) is True
        await first.stop_deliveries(grace_seconds=3)
        assert len(received) == 2
        assert json.loads(received[-1][1])["alert"]["id"] == "after-admin-test"
    finally:
        received.release.set()
        await first.stop_deliveries(grace_seconds=0)
        await asyncio.gather(testing, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["bytes", "count"])
async def test_direct_notify_and_submit_share_reserved_admission_budget(
    shared_receivers, kind
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (other_pm, _second) = factory()
    event = {"severity": "critical", "message": "bounded"}
    size = len(json.dumps(event).encode())
    if kind == "bytes":
        first._intake_max_bytes = size
    else:
        first._intake_max = 1
    entered = threading.Event()
    original_read = first._current_webhooks

    def observed_read():
        entered.set()
        return original_read()

    first._current_webhooks = observed_read
    task = None
    try:
        with other_pm._file_lock:
            task = asyncio.create_task(first.notify(event))
            assert await asyncio.to_thread(entered.wait, 2)
            assert first.initial_dispatch["direct_serialized_bytes"] == size
            assert await first.notify(event) == 0
            assert first.submit(event) == 0
            assert first.initial_dispatch["capacity_rejected"] == 2
            assert received == []
        assert await asyncio.wait_for(task, 3) == 1
        assert first.initial_dispatch["direct_serialized_bytes"] == 0
        assert first.submit(event) == 1
        await first.stop_deliveries(grace_seconds=3)
        assert len(received) == 2
    finally:
        await first.stop_deliveries(grace_seconds=0)
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_direct_notify_refuses_oversized_event_without_authority_read(
    shared_receivers,
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (_other_pm, _second) = factory()
    first._intake_max_payload = 10
    assert await first.notify({"severity": "critical", "message": "too large"}) == 0
    assert first.initial_dispatch["capacity_rejected"] == 1
    assert first.initial_dispatch["direct_active"] == 0
    assert first._authority_executor is None and received == []


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["notify", "submit"])
async def test_unchanged_inline_retry_keeps_exact_payload_and_signature(
    shared_receivers, monkeypatch, method
):
    received, _original, factory, _change = shared_receivers
    (_pm, first), (_other_pm, _second) = factory()
    monkeypatch.setattr(notifications, "_MAX_RETRIES", 1)
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 0)
    received.status = 503
    received.release = threading.Event()
    task = asyncio.create_task(invoke(first, method))
    try:
        assert await asyncio.to_thread(received.accepted.wait, 3)
        received.status = 204
        received.release.set()
        assert await task == 1
        assert len(received) == 2
        assert received[0] == received[1]
        assert first._retry_store.snapshot()["entries"] == []
        assert first.initial_dispatch["policy_cancelled"] == 0
    finally:
        received.release.set()
        await first.stop_deliveries(grace_seconds=0)
        await asyncio.gather(task, return_exceptions=True)
