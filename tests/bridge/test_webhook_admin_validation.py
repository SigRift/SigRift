"""Webhook admin API: URL validation, refusals and audit (webhook_management).

Every refusal must leave the persisted webhook authority untouched: a
rejected URL is never stored, an unknown webhook is a 404, and an update
that fails validation keeps the previous destination.
"""

from __future__ import annotations

import socket

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers.webhook_management import ALLOW_HOSTS_ENV

_PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def _no_operator_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host-level allowlist would let internal targets through: keep it out."""
    monkeypatch.delenv(ALLOW_HOSTS_ENV, raising=False)


def _fake_dns(address: str):
    """A getaddrinfo stand-in resolving every name to *address* (no network)."""

    def getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))]

    return getaddrinfo


@pytest.fixture
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns(_PUBLIC_IP))


def _create(client: TestClient, name: str = "SOC hook") -> dict:
    resp = client.post(
        "/api/admin/webhooks",
        json={"url": "https://hooks.example.com/in", "name": name},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["webhook"]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://hooks.example.com/in",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "//hooks.example.com/in",
    ],
)
def test_create_refuses_non_http_schemes(
    client: TestClient, persistence: PersistenceManager, url: str
) -> None:
    resp = client.post("/api/admin/webhooks", json={"url": url})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "URL must start with http:// or https://"
    assert persistence.current_webhooks() == []


@pytest.mark.parametrize(
    ("url", "detail"),
    [
        ("http://hooks.example.com:99999/in", "Invalid URL"),
        ("https://hooks.example.com:abc/in", "Invalid URL"),
        ("http://[::1/in", "Invalid URL"),
        ("http:///in", "Invalid URL: missing hostname"),
        ("https://:8443/in", "Invalid URL: missing hostname"),
    ],
)
def test_create_refuses_malformed_urls(
    client: TestClient, persistence: PersistenceManager, url: str, detail: str
) -> None:
    resp = client.post("/api/admin/webhooks", json={"url": url})
    assert resp.status_code == 400
    assert resp.json()["detail"] == detail
    assert persistence.current_webhooks() == []


@pytest.mark.parametrize(
    "error",
    [socket.gaierror(socket.EAI_NONAME, "no such host"), OSError("unreachable")],
)
def test_create_refuses_unresolvable_hosts(
    client: TestClient,
    persistence: PersistenceManager,
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
) -> None:
    def getaddrinfo(*args, **kwargs):
        raise error

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    resp = client.post(
        "/api/admin/webhooks", json={"url": "https://nowhere.example.com/in"}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Cannot resolve hostname"
    assert persistence.current_webhooks() == []


def test_create_refuses_unknown_severity(
    client: TestClient, persistence: PersistenceManager, public_dns: None
) -> None:
    resp = client.post(
        "/api/admin/webhooks",
        json={
            "url": "https://hooks.example.com/in",
            "severity_filter": ["critical", "debug"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid severity: debug"
    assert persistence.current_webhooks() == []


def test_update_refuses_bad_severity_and_internal_url(
    client: TestClient,
    persistence: PersistenceManager,
    monkeypatch: pytest.MonkeyPatch,
    public_dns: None,
) -> None:
    webhook = _create(client)
    before = persistence.current_webhooks()

    resp = client.put(
        f"/api/admin/webhooks/{webhook['id']}",
        json={"severity_filter": ["warning", "emerg"]},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid severity: emerg"

    # An update cannot re-point a vetted webhook at an internal address.
    monkeypatch.setattr(socket, "getaddrinfo", _fake_dns("10.0.0.5"))
    resp = client.put(
        f"/api/admin/webhooks/{webhook['id']}",
        json={"url": "https://intranet.example.com/in"},
    )
    assert resp.status_code == 400
    assert "private/internal" in resp.json()["detail"]

    assert persistence.current_webhooks() == before
    assert before[0]["url"] == "https://hooks.example.com/in"


def test_unknown_webhook_is_not_found(
    client: TestClient, persistence: PersistenceManager, public_dns: None
) -> None:
    webhook = _create(client)
    before = persistence.current_webhooks()

    resp = client.put("/api/admin/webhooks/missing", json={"enabled": False})
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Webhook not found"
    resp = client.delete("/api/admin/webhooks/missing")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Webhook not found"
    resp = client.post("/api/admin/webhooks/missing/test")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Webhook missing not found"

    assert persistence.current_webhooks() == before
    assert [value["id"] for value in before] == [webhook["id"]]


def test_update_audit_lists_only_changed_values(
    client: TestClient, bridge_app: FastAPI, public_dns: None
) -> None:
    webhook = _create(client, name="Ops & SOC")
    assert webhook["name"] == "Ops &amp; SOC"

    # The same (escaped) name again is not a change; ``enabled`` is.
    resp = client.put(
        f"/api/admin/webhooks/{webhook['id']}",
        json={"name": "Ops & SOC", "enabled": False},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "updated"
    assert body["webhook"]["enabled"] is False
    assert body["webhook"]["name"] == "Ops &amp; SOC"
    assert "delivery_revision" not in body["webhook"]

    [entry] = bridge_app.state.detection_store.get_audit_log(
        action="admin_update_webhook"
    )
    assert entry["target_id"] == webhook["id"]
    assert entry["details"] == {
        "changes": [{"key": "enabled", "old": True, "new": False}]
    }


def test_test_delivery_error_is_reported_and_truncated(
    client: TestClient,
    bridge_app: FastAPI,
    monkeypatch: pytest.MonkeyPatch,
    public_dns: None,
) -> None:
    webhook = _create(client)
    calls: list[tuple[str, str]] = []

    async def failing_deliver(target: dict, alert: dict) -> bool:
        calls.append((target["id"], alert["alert_id"]))
        raise RuntimeError("delivery exploded: " + "x" * 400)

    monkeypatch.setattr(bridge_app.state.notifier, "_deliver", failing_deliver)
    resp = client.post(f"/api/admin/webhooks/{webhook['id']}/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert body["webhook_id"] == webhook["id"]
    assert body["error"].startswith("delivery exploded: ")
    assert len(body["error"]) == 200
    assert calls == [(webhook["id"], "test-" + webhook["id"])]


def test_endpoints_without_notification_system(
    client: TestClient,
    bridge_app: FastAPI,
    persistence: PersistenceManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bridge_app.state, "notifier", None)

    assert client.get("/api/admin/webhooks").json() == {
        "webhooks": [],
        "delivery_log": [],
    }
    assert client.get("/api/admin/webhooks/retry-queue").json() == {
        "queue_size": 0,
        "entries": [],
        "dropped": 0,
    }
    refused = [
        client.post(
            "/api/admin/webhooks", json={"url": "https://hooks.example.com/in"}
        ),
        client.put("/api/admin/webhooks/abc", json={"enabled": False}),
        client.delete("/api/admin/webhooks/abc"),
        client.post("/api/admin/webhooks/abc/test"),
    ]
    for resp in refused:
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Notification system not initialized"
    assert persistence.current_webhooks() == []
