"""Failed webhook retries survive reopening the real application/database.

These tests use real loopback HTTP and the normal Bridge application factory.
Initial background task durability and ingest-to-analysis recovery are separate.
"""

from __future__ import annotations

import asyncio
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import sys
import threading

from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
import pytest
from starlette.requests import Request

from sigrift.bridge import notifications
from sigrift.bridge.app import create_test_app


@pytest.fixture
def receiver(monkeypatch):
    state = {"status": 503, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            state["requests"].append((body, dict(self.headers)))
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
    # Exercise one actual HTTP failure, without spending 10 seconds in inline
    # retry sleeps. Production defaults remain covered by existing tests.
    monkeypatch.setattr(notifications, "_MAX_RETRIES", 0)
    monkeypatch.setattr(notifications, "_RETRY_DELAY_SECONDS", 0)
    state["url"] = f"http://127.0.0.1:{server.server_port}/hook"
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def _close(app):
    async def stop():
        await app.state.notifier.stop_retry_loop()
        await app.state.notifier.stop_deliveries()

    asyncio.run(stop())
    app.state.persistence.save_all()
    app.state.detection_store.close()


def test_failed_delivery_reopens_with_same_payload_and_is_acknowledged(
    tmp_path, master_key, receiver
):
    first = create_test_app(tmp_path, master_key=master_key)
    try:
        with TestClient(first, headers={"X-API-Key": master_key}) as client:
            created = client.post(
                "/api/admin/webhooks", json={"url": receiver["url"], "name": "restart"}
            )
            assert created.status_code == 201, created.text
            webhook_id = created.json()["webhook"]["id"]
            failed = client.post(f"/api/admin/webhooks/{webhook_id}/test")
            assert failed.status_code == 200, failed.text
            assert failed.json()["status"] == "failed"
            queued = client.get("/api/admin/webhooks/retry-queue")
            assert queued.status_code == 200
            assert queued.json()["queue_size"] == 1
            assert len(receiver["requests"]) == 1
    finally:
        _close(first)

    receiver["status"] = 204
    second = create_test_app(tmp_path, master_key=master_key)
    try:
        with TestClient(second, headers={"X-API-Key": master_key}) as client:
            reopened = client.get("/api/admin/webhooks/retry-queue")
            assert reopened.status_code == 200
            assert reopened.json()["queue_size"] == 1
            assert asyncio.run(second.state.notifier.retry_failed()) == 1
            assert (
                client.get("/api/admin/webhooks/retry-queue").json()["queue_size"] == 0
            )
        assert len(receiver["requests"]) == 2
        assert receiver["requests"][0][0] == receiver["requests"][1][0]
        assert (
            receiver["requests"][0][1]["X-Bridge-Signature"]
            == receiver["requests"][1][1]["X-Bridge-Signature"]
        )
    finally:
        _close(second)


@pytest.mark.parametrize("edit", [{"enabled": False}, {"url": "target-change"}])
def test_pending_work_is_not_sent_after_endpoint_disable_or_target_change(
    tmp_path, master_key, receiver, edit
):
    app = create_test_app(tmp_path, master_key=master_key)
    try:
        with TestClient(app, headers={"X-API-Key": master_key}) as client:
            response = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
            assert response.status_code == 201
            ident = response.json()["webhook"]["id"]
            assert (
                client.post(f"/api/admin/webhooks/{ident}/test").json()["status"]
                == "failed"
            )
            update = {"url": receiver["url"] + "/changed"} if "url" in edit else edit
            assert (
                client.put(f"/api/admin/webhooks/{ident}", json=update).status_code
                == 200
            )
            receiver["status"] = 204
            assert asyncio.run(app.state.notifier.retry_failed()) == 0
            assert len(receiver["requests"]) == 1
            assert (
                client.get("/api/admin/webhooks/retry-queue").json()["queue_size"] == 0
            )
    finally:
        _close(app)


@pytest.mark.asyncio
@pytest.mark.parametrize("later", ["delete", "restore"])
async def test_late_crud_publication_cannot_revive_newer_delete_or_restore(
    bridge_app, master_key, receiver, monkeypatch, later
):
    async with AsyncClient(
        transport=ASGITransport(app=bridge_app),
        base_url="http://testserver",
        headers={"X-API-Key": master_key},
    ) as client:
        made = await client.post("/api/admin/webhooks", json={"url": receiver["url"]})
        assert made.status_code == 201
        ident = made.json()["webhook"]["id"]
        if later == "restore":
            assert (
                await client.put(
                    f"/api/admin/webhooks/{ident}", json={"enabled": False}
                )
            ).status_code == 200
            snapshot = await client.post(
                "/api/admin/config-snapshots", json={"description": "disabled"}
            )
            assert snapshot.status_code in {200, 201}, snapshot.text
            snapshot_id = snapshot.json()["snapshot_id"]
            assert (
                await client.put(f"/api/admin/webhooks/{ident}", json={"enabled": True})
            ).status_code == 200
        committed, resume = threading.Event(), threading.Event()
        persistence = bridge_app.state.persistence
        real_change = persistence.change_webhook

        def gated(*args, **kwargs):
            result = real_change(*args, **kwargs)
            if kwargs.get("updates", {}).get("name") == "paused publication":
                committed.set()
                assert resume.wait(5)
            return result

        monkeypatch.setattr(persistence, "change_webhook", gated)
        first = asyncio.create_task(
            client.put(
                f"/api/admin/webhooks/{ident}", json={"name": "paused publication"}
            )
        )
        second = None
        try:
            assert await asyncio.to_thread(committed.wait, 3)
            second = asyncio.create_task(
                client.delete(f"/api/admin/webhooks/{ident}")
                if later == "delete"
                else client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
            )
            # Allow the second public request to reach its lock/publication. A
            # serialized implementation waits here; the broken one publishes.
            await asyncio.sleep(0.1)
            resume.set()
            assert (await first).status_code == 200
            assert (await second).status_code == 200
            actual = (await client.get("/api/admin/webhooks")).json()["webhooks"]
            if later == "delete":
                assert actual == []
            else:
                assert len(actual) == 1 and actual[0]["enabled"] is False
            # GET reads disk authority; it cannot detect stale local publication.
            # Exercise the initial-send selector too, the original race's impact.
            before = len(receiver["requests"])
            assert await bridge_app.state.notifier.notify({"severity": "critical"}) == 0
            assert len(receiver["requests"]) == before
        finally:
            resume.set()
            await asyncio.gather(
                first, *([second] if second else []), return_exceptions=True
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("fails", [False, True])
async def test_cancelled_config_commit_settles_before_lock_release(
    bridge_app, receiver, monkeypatch, fails
):
    from sigrift.bridge.routers.webhook_management import _commit_webhook

    persistence = bridge_app.state.persistence
    persistence.change_webhook(
        "cancel",
        create={
            "id": "cancel",
            "url": receiver["url"],
            "enabled": True,
            "name": "original",
        },
    )
    notifier = bridge_app.state.notifier
    notifier.load(persistence.current_webhooks())
    entered, resume = threading.Event(), threading.Event()
    original = persistence.change_webhook

    def gated(*args, **kwargs):
        entered.set()
        assert resume.wait(5)
        if fails:
            # A real directory failure prevents the checked atomic JSON write.
            authority = persistence.data_dir / "webhooks.json"
            authority.unlink()
            authority.mkdir()
        return original(*args, **kwargs)

    monkeypatch.setattr(persistence, "change_webhook", gated)
    task = asyncio.create_task(
        _commit_webhook(
            Request({"type": "http", "app": bridge_app}),
            "cancel",
            updates={"name": "committed"},
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 3)
        for _ in range(3):
            task.cancel()
            await asyncio.sleep(0.02)
            assert not task.done()
            assert notifier.configuration_lock.locked()
        resume.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not notifier.configuration_lock.locked()
        assert notifier.webhooks[0]["name"] == ("original" if fails else "committed")
        if not fails:
            assert persistence.current_webhooks()[0]["name"] == "committed"
    finally:
        resume.set()
        await asyncio.gather(task, return_exceptions=True)
        authority = persistence.data_dir / "webhooks.json"
        if authority.is_dir():
            authority.rmdir()
            persistence.set_webhooks(notifier.webhooks)


def test_unrelated_crud_preserves_worker_health_but_does_not_persist_it(
    client, bridge_app, receiver
):
    made = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
    assert made.status_code == 201
    ident = made.json()["webhook"]["id"]
    assert client.post(f"/api/admin/webhooks/{ident}/test").json()["status"] == "failed"
    prior = next(w for w in bridge_app.state.notifier.webhooks if w["id"] == ident)
    failures = prior["failure_count"]
    assert failures > 0
    assert (
        client.post(
            "/api/admin/webhooks", json={"url": receiver["url"] + "/other"}
        ).status_code
        == 201
    )
    live = next(w for w in bridge_app.state.notifier.webhooks if w["id"] == ident)
    public = next(
        w
        for w in client.get("/api/admin/webhooks").json()["webhooks"]
        if w["id"] == ident
    )
    assert live["failure_count"] == public["failure_count"] == failures
    disk = next(
        w for w in bridge_app.state.persistence.current_webhooks() if w["id"] == ident
    )
    assert disk.get("failure_count", 0) == 0
    assert "delivery_revision" not in public and "signing_secret" not in public


@pytest.mark.parametrize("damage", ["malformed", "missing"])
def test_real_app_unavailable_config_keeps_durable_work_without_send(
    client, bridge_app, receiver, damage
):
    made = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
    assert made.status_code == 201
    ident = made.json()["webhook"]["id"]
    assert client.post(f"/api/admin/webhooks/{ident}/test").json()["status"] == "failed"
    notifier = bridge_app.state.notifier
    before = notifier._retry_store.snapshot()["entries"]
    assert len(before) == 1
    path = bridge_app.state.persistence.data_dir / "webhooks.json"
    saved = path.read_bytes()
    try:
        if damage == "malformed":
            path.write_text('{"webhooks":')
        else:
            path.unlink()
        assert client.get("/api/admin/webhooks").status_code == 503
        assert asyncio.run(notifier.retry_failed()) == 0
        assert notifier._retry_store.snapshot()["entries"] == before
        assert len(receiver["requests"]) == 1
    finally:
        path.write_bytes(saved)


@pytest.mark.parametrize("edit", ["delete", "disable"])
def test_admin_read_observes_checked_commit_by_another_real_process(
    client, bridge_app, receiver, edit
):
    made = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
    assert made.status_code == 201
    ident = made.json()["webhook"]["id"]
    assert "delivery_revision" not in made.json()["webhook"]
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from sigrift.bridge.persistence import PersistenceManager
pm=PersistenceManager(sys.argv[1],auto_save_interval=0)
pm.load_all()
if sys.argv[3]=='delete':
    pm.change_webhook(sys.argv[2],delete=True)
else:
    pm.change_webhook(sys.argv[2],updates={'enabled':False})
""",
            str(bridge_app.state.persistence.data_dir),
            ident,
            edit,
        ],
        capture_output=True,
        text=True,
        timeout=25,
    )
    assert child.returncode == 0, child.stderr
    # The local notifier intentionally still holds its old snapshot. The public
    # admin request must read disk authority without publishing another stale read.
    assert bridge_app.state.notifier.webhooks[0]["enabled"] is True
    result = client.get("/api/admin/webhooks")
    assert result.status_code == 200
    values = result.json()["webhooks"]
    if edit == "delete":
        assert values == []
    else:
        assert values[0]["enabled"] is False
        assert "delivery_revision" not in values[0]


@pytest.mark.parametrize("cycle", ["disable", "target", "restore"])
def test_revision_cycle_or_snapshot_restore_cannot_revive_pending_payload(
    client, bridge_app, receiver, cycle
):
    made = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
    assert made.status_code == 201
    ident = made.json()["webhook"]["id"]
    saved = client.post(
        "/api/admin/config-snapshots", json={"description": "old revision"}
    )
    assert saved.status_code in {200, 201}
    assert client.post(f"/api/admin/webhooks/{ident}/test").json()["status"] == "failed"
    first_id = json.loads(receiver["requests"][0][0])["delivery_id"]
    if cycle == "disable":
        for value in (False, True):
            assert (
                client.put(
                    f"/api/admin/webhooks/{ident}", json={"enabled": value}
                ).status_code
                == 200
            )
    elif cycle == "target":
        for value in (receiver["url"] + "/new", receiver["url"]):
            assert (
                client.put(
                    f"/api/admin/webhooks/{ident}", json={"url": value}
                ).status_code
                == 200
            )
    else:
        assert (
            client.post(
                f"/api/admin/config-snapshots/{saved.json()['snapshot_id']}/restore"
            ).status_code
            == 200
        )
    receiver["status"] = 204
    assert asyncio.run(bridge_app.state.notifier.retry_failed()) == 0
    assert len(receiver["requests"]) == 1
    assert client.get("/api/admin/webhooks/retry-queue").json()["queue_size"] == 0
    # New work is permitted at the current restored/reenabled destination.
    assert (
        client.post(f"/api/admin/webhooks/{ident}/test").json()["status"] == "delivered"
    )
    assert len(receiver["requests"]) == 2
    assert json.loads(receiver["requests"][1][0])["delivery_id"] != first_id


def test_failed_config_commit_preserves_disk_live_state_and_success_audit(
    client, bridge_app, receiver, detection_store
):
    made = client.post("/api/admin/webhooks", json={"url": receiver["url"]})
    assert made.status_code == 201
    ident = made.json()["webhook"]["id"]
    pm = bridge_app.state.persistence
    path = pm.data_dir / "webhooks.json"
    before = path.read_bytes()
    live = bridge_app.state.notifier.webhooks.copy()
    pm.data_dir.chmod(0o500)
    try:
        response = client.put(f"/api/admin/webhooks/{ident}", json={"enabled": False})
        assert response.status_code == 503
        assert path.read_bytes() == before
        assert bridge_app.state.notifier.webhooks == live
        assert (
            detection_store.get_connection()
            .execute(
                "SELECT COUNT(*) FROM audit_log WHERE action='admin_update_webhook'"
            )
            .fetchone()[0]
            == 0
        )
    finally:
        pm.data_dir.chmod(0o700)
