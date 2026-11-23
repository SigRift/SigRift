"""Export endpoint tests — JSON, CSV, and date filtering."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Node export
# ---------------------------------------------------------------------------


async def test_export_nodes_json_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/nodes", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body
    assert body["meta"]["record_count"] == 0
    assert body["meta"]["format"] == "json"


async def test_export_nodes_json_with_data(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.get(
        "/api/export/nodes", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["record_count"] == 1
    assert "nodes" in body


async def test_export_nodes_csv(
    test_client: httpx.AsyncClient,
    admin_key_header: dict[str, str],
    api_key_header: dict[str, str],
    sample_node: dict[str, Any],
) -> None:
    await test_client.post(
        "/api/nodes/register", headers=admin_key_header, json=sample_node
    )
    resp = await test_client.get(
        "/api/export/nodes", headers=api_key_header, params={"format": "csv"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert "Content-Disposition" in resp.headers
    text = resp.text
    assert "node_id" in text  # CSV header row


# ---------------------------------------------------------------------------
# Training history export
# ---------------------------------------------------------------------------


async def test_export_training_json_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/training", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body
    assert body["meta"]["record_count"] == 0


async def test_export_training_csv(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/training", headers=api_key_header, params={"format": "csv"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")


# ---------------------------------------------------------------------------
# Alert export
# ---------------------------------------------------------------------------


async def test_export_alerts_json_empty(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/alerts", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "meta" in body
    assert "alerts" in body


async def test_export_alerts_json_with_data(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
) -> None:
    # Create some alerts
    for name in ["Export Alert 1", "Export Alert 2"]:
        await test_client.post(
            "/api/alerts/rules",
            headers=analyst_key_header,
            json={"name": name, "severity": "info"},
        )
    resp = await test_client.get(
        "/api/export/alerts", headers=api_key_header, params={"format": "json"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["record_count"] >= 2


async def test_export_alerts_csv(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "CSV Alert", "severity": "warning"},
    )
    resp = await test_client.get(
        "/api/export/alerts", headers=api_key_header, params={"format": "csv"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers.get("content-type", "")
    assert "alert_id" in resp.text


async def test_export_alerts_date_filter_invalid_start(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/alerts",
        headers=api_key_header,
        params={"format": "json", "start_date": "not-a-date"},
    )
    assert resp.status_code == 400


async def test_export_alerts_date_filter_invalid_end(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get(
        "/api/export/alerts",
        headers=api_key_header,
        params={"format": "json", "end_date": "nope"},
    )
    assert resp.status_code == 400


async def test_export_alerts_date_filter_valid(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
    analyst_key_header: dict[str, str],
) -> None:
    await test_client.post(
        "/api/alerts/rules",
        headers=analyst_key_header,
        json={"name": "Date Filter Alert", "severity": "info"},
    )
    resp = await test_client.get(
        "/api/export/alerts",
        headers=api_key_header,
        params={
            "format": "json",
            "start_date": "2020-01-01T00:00:00+00:00",
            "end_date": "2030-01-01T00:00:00+00:00",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["record_count"] >= 1


# ---------------------------------------------------------------------------
# Default format (no format param)
# ---------------------------------------------------------------------------


async def test_export_nodes_default_format(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Default format should be JSON."""
    resp = await test_client.get("/api/export/nodes", headers=api_key_header)
    assert resp.status_code == 200
    body = resp.json()
    assert body["meta"]["format"] == "json"
