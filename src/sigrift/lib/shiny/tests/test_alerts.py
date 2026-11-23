"""Alert system endpoint tests."""

from __future__ import annotations

import httpx
import pytest

pytestmark = pytest.mark.asyncio


async def test_list_alerts_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/alerts/", headers=api_key_header)
    assert resp.status_code == 200
    assert resp.json() == []


async def test_create_alert_rule(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={
            "name": "High CPU",
            "severity": "critical",
            "thresholds": {"cpu_percent": 90.0},
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "High CPU"
    assert body["severity"] == "critical"
    assert body["acknowledged"] is False


async def test_acknowledge_alert(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    # Create an alert first
    create_resp = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Disk Full", "severity": "warning"},
    )
    alert_id = create_resp.json()["alert_id"]

    # Acknowledge it
    resp = await test_client.put(
        f"/api/alerts/{alert_id}/ack", headers=analyst_key_header
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["acknowledged"] is True
    assert body["acknowledged_at"] is not None


async def test_acknowledge_nonexistent_alert(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.put(
        "/api/alerts/no-such-alert/ack", headers=analyst_key_header
    )
    assert resp.status_code == 404


async def test_delete_alert_rule_master_key(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
    master_key_header: dict[str, str],
) -> None:
    # Create an alert rule
    create_resp = await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Test Rule", "severity": "info"},
    )
    alert_id = create_resp.json()["alert_id"]

    # Delete with master key
    resp = await test_client.delete(
        f"/api/alerts/rules/{alert_id}", headers=master_key_header
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_delete_alert_rule_regular_key_forbidden(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.delete("/api/alerts/rules/any-id", headers=api_key_header)
    assert resp.status_code == 403


async def test_alert_history(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
) -> None:
    # Create a couple of alerts
    for name in ["Alert A", "Alert B"]:
        await test_client.post(
            "/api/alerts/rules",
            headers=analyst_key_header,
            json={"name": name, "severity": "warning"},
        )
    resp = await test_client.get("/api/alerts/history", headers=api_key_header)
    assert resp.status_code == 200
    history = resp.json()
    assert isinstance(history, list)
    assert len(history) >= 2


async def test_list_alerts_with_severity_filter(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Info Alert", "severity": "info"},
    )
    await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Crit Alert", "severity": "critical"},
    )
    resp = await test_client.get(
        "/api/alerts/", headers=api_key_header, params={"severity": "critical"}
    )
    assert resp.status_code == 200
    alerts = resp.json()
    for a in alerts:
        assert a["severity"] == "critical"
