"""Initial webhook selection through two normal authenticated Bridge apps."""

from __future__ import annotations

import time

from httpx import ASGITransport, AsyncClient
import pytest

from sigrift.bridge.app import create_test_app
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from .test_round5_br5 import _RULE, _gateway_detection, _gw
from .test_round5_br5 import proxy_secret as _proxy_secret_fixture
from .test_webhook_initial_authority import (
    shared_receivers as _shared_receivers_fixture,
)


proxy_secret = _proxy_secret_fixture
shared_receivers = _shared_receivers_fixture


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["delete", "disable", "url", "enable", "new", "severity"]
)
async def test_ingest_initial_dispatch_observes_other_authenticated_worker(
    bridge_app, tmp_path, master_key, proxy_secret, shared_receivers, change
):
    received, original, _factory, _change = shared_receivers
    persistence = bridge_app.state.persistence
    persistence.set_alert_rules([dict(_RULE)])
    second = None
    first_notifier = bridge_app.state.notifier
    async with AsyncClient(
        transport=ASGITransport(app=bridge_app),
        base_url="http://bridge",
        headers={"X-API-Key": master_key},
    ) as first:
        if change != "new":
            made = await first.post(
                "/api/admin/webhooks",
                json={"url": original["url"], "name": "synthetic cross-worker"},
            )
            assert made.status_code == 201, made.text
            ident = made.json()["webhook"]["id"]
            if change == "enable":
                assert (
                    await first.put(
                        f"/api/admin/webhooks/{ident}", json={"enabled": False}
                    )
                ).status_code == 200
        other_persistence = PersistenceManager(
            persistence.data_dir, auto_save_interval=0
        )
        other_persistence.load_all()
        other_store = DetectionStore(bridge_app.state.detection_store.db_path)
        try:
            second = create_test_app(
                tmp_path,
                detection_store=other_store,
                persistence=other_persistence,
                master_key=master_key,
            )
            async with AsyncClient(
                transport=ASGITransport(app=second),
                base_url="http://other-bridge",
                headers={"X-API-Key": master_key},
            ) as editor:
                if change == "new":
                    response = await editor.post(
                        "/api/admin/webhooks", json={"url": original["url"]}
                    )
                    assert response.status_code == 201
                elif change == "delete":
                    assert (
                        await editor.delete(f"/api/admin/webhooks/{ident}")
                    ).status_code == 200
                else:
                    update = {
                        "disable": {"enabled": False},
                        "enable": {"enabled": True},
                        "url": {"url": original["url"] + "/edited"},
                        "severity": {"severity_filter": ["info"]},
                    }[change]
                    response = await editor.put(
                        f"/api/admin/webhooks/{ident}", json=update
                    )
                    assert response.status_code == 200, response.text
                started = time.monotonic()
                response = await first.post(
                    "/api/internal/ingest-hook",
                    headers=_gw(),
                    json={
                        "node_id": "edge-a",
                        "detections": [_gateway_detection("authority-" + change)],
                    },
                )
                elapsed = time.monotonic() - started
                assert response.status_code == 200, response.text
                assert (
                    response.json()["accepted"]
                    == response.json()["alerts_created"]
                    == 1
                )
                assert elapsed < 1.0
                await first_notifier.stop_deliveries(grace_seconds=3)
                expected = 0 if change in {"delete", "disable", "severity"} else 1
                assert len(received) == expected
                if expected:
                    assert received[0][0] == (
                        "/old/edited" if change == "url" else "/old"
                    )
                diagnostics = await first.get("/api/admin/webhooks/retry-queue")
                assert diagnostics.status_code == 200
                stats = diagnostics.json()["initial_dispatch"]
                assert (
                    stats["accepted"] == 1
                    and stats["queued"] == stats["serialized_bytes"] == 0
                )
                assert stats["no_matching"] == int(not expected)
                assert diagnostics.json()["queue_size"] == 0
                assert len(persistence.get_alerts()) == 1
        finally:
            await first_notifier.stop_deliveries(grace_seconds=0)
            await bridge_app.state.syslog_forwarder.stop_forwards(grace_seconds=0)
            if second is not None:
                await second.state.notifier.stop_deliveries(grace_seconds=0)
                await second.state.syslog_forwarder.stop_forwards(grace_seconds=0)
            other_store.close()
