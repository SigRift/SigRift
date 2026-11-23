"""Spectrum streamer endpoint tests.

Connecting, disconnecting and retuning (``PUT /config``) need an analyst
key; any valid key reads the status and config.
"""

from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

pytestmark = pytest.mark.asyncio


async def test_spectrum_status(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/status", headers=api_key_header)
    assert resp.status_code == 200
    body = resp.json()
    assert "connected" in body
    assert body["connected"] is False


async def test_spectrum_connect_invalid_host(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    """Connection to a non-existent host returns 502 (connection fails)."""
    resp = await test_client.post(
        "/api/spectrum/connect",
        headers=analyst_key_header,
        json={
            "host": "127.0.0.1",
            "port": 19999,
            "center_freq_hz": 433920000.0,
            "sample_rate_hz": 2048000.0,
            "gain_db": 40.0,
        },
    )
    # Connection will fail since no rtl_tcp is running
    assert resp.status_code == 502


async def test_spectrum_connect_ssrf_rejected(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    """SSRF attempt with special characters in host is rejected."""
    resp = await test_client.post(
        "/api/spectrum/connect",
        headers=analyst_key_header,
        json={
            "host": "169.254.169.254/latest/meta-data",
            "port": 80,
        },
    )
    # validate_host rejects this format -> 422 or 500
    assert resp.status_code in (422, 500)


async def test_spectrum_get_config(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/config", headers=api_key_header)
    assert resp.status_code == 200
    body = resp.json()
    assert "center_freq_hz" in body
    assert "sample_rate_hz" in body
    assert "gain_db" in body
    assert "fft_size" in body


async def test_spectrum_update_config(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    """PUT /config with valid params returns updated config."""
    resp = await test_client.put(
        "/api/spectrum/config",
        headers=analyst_key_header,
        json={
            "center_freq_hz": 868000000.0,
            "sample_rate_hz": 2048000.0,
            "gain_db": 30.0,
            "fft_size": 1024,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["center_freq_hz"] == 868000000.0
    assert body["gain_db"] == 30.0


async def test_spectrum_disconnect(
    test_client: httpx.AsyncClient,
    analyst_key_header: dict[str, str],
) -> None:
    resp = await test_client.get("/api/spectrum/disconnect", headers=analyst_key_header)
    assert resp.status_code == 200
    assert resp.json()["status"] == "disconnected"


async def test_a_viewer_key_cannot_connect_disconnect_or_retune(
    test_client: httpx.AsyncClient,
    test_app: FastAPI,
    api_key_header: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """403 before the streamer is touched: no connect, no stop, no retune."""
    streamer = test_app.state.spectrum_streamer
    calls: list[str] = []

    async def record(name: str, *args: object, **kwargs: object) -> bool:
        calls.append(name)
        return True

    for name in ("connect", "disconnect", "set_params", "start_streaming"):
        monkeypatch.setattr(
            streamer, name, lambda *a, _n=name, **k: record(_n, *a, **k)
        )
    before = (
        await test_client.get("/api/spectrum/config", headers=api_key_header)
    ).json()

    for method, path, body in (
        ("POST", "/api/spectrum/connect", {"host": "127.0.0.1", "port": 9}),
        ("GET", "/api/spectrum/disconnect", None),
        (
            "PUT",
            "/api/spectrum/config",
            {"center_freq_hz": 868e6, "sample_rate_hz": 2048000.0, "gain_db": 1.0},
        ),
    ):
        resp = await test_client.request(
            method, path, headers=api_key_header, json=body
        )
        assert (resp.status_code, resp.json()["detail"]) == (
            403,
            "analyst role required",
        ), path
    assert calls == []
    after = (
        await test_client.get("/api/spectrum/config", headers=api_key_header)
    ).json()
    assert after == before
