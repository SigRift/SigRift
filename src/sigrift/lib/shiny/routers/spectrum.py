"""Spectrum router -- REST and WebSocket endpoints for rtl_tcp streaming.

Prefix: ``/api/spectrum`` (set when including the router in ``app.py``).
All endpoints require ``rate_limit`` dependency (auth + sliding window).
Connecting to an rtl_tcp source, disconnecting it and retuning it (``PUT
/config``) also need an ``analyst`` key (an ``admin`` key or the master key
is one), as the bridge's spectrum connect and disconnect do: a ``viewer``
key -- the default, and every key stored before roles existed -- reads the
status and config only.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, status

from sigrift.lib.security.validation import (
    validate_frequency,
    validate_gain,
    validate_sample_rate,
)
from sigrift.lib.shiny.dependencies import (
    Role,
    accept_ws,
    rate_limit,
    require_role,
    require_ws_auth,
)
from sigrift.lib.shiny.models import (
    SpectrumConnectRequest,
    SpectrumParams,
    SpectrumStatus,
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_streamer(request: Request) -> Any:
    """Retrieve the SpectrumStreamer from app state."""
    streamer = getattr(request.app.state, "spectrum_streamer", None)
    if streamer is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Spectrum streamer not initialised",
        )
    return streamer


# ---------------------------------------------------------------------------
# REST endpoints
# ---------------------------------------------------------------------------


@router.post("/connect")
async def spectrum_connect(
    body: SpectrumConnectRequest,
    request: Request,
    key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Connect to an rtl_tcp source. Requires an analyst key."""
    streamer = _get_streamer(request)
    app_state = request.app.state.app_state

    try:
        ok = await streamer.connect(body.host, body.port)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    if not ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to rtl_tcp at {body.host}:{body.port}",
        )

    # Apply requested params
    await streamer.set_params(
        freq_hz=body.center_freq_hz,
        gain_db=body.gain_db,
        sample_rate_hz=body.sample_rate_hz,
    )
    await streamer.start_streaming()

    app_state.log_activity(
        "spectrum_connect",
        message=f"Connected to rtl_tcp at {body.host}:{body.port}",
    )
    return {"status": "connected", "host": body.host, "port": body.port}


@router.get("/disconnect")
async def spectrum_disconnect(
    request: Request,
    key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, str]:
    """Disconnect from rtl_tcp. Requires an analyst key."""
    streamer = _get_streamer(request)
    await streamer.disconnect()
    request.app.state.app_state.log_activity(
        "spectrum_disconnect",
        message="Disconnected from rtl_tcp",
    )
    return {"status": "disconnected"}


@router.get("/config")
async def spectrum_get_config(
    request: Request,
    key_id: str = Depends(rate_limit),
) -> SpectrumParams:
    """Return current spectrum parameters."""
    streamer = _get_streamer(request)
    return SpectrumParams(
        center_freq_hz=streamer.center_freq,
        sample_rate_hz=streamer.sample_rate,
        gain_db=streamer.gain,
        fft_size=streamer.fft_size,
    )


@router.put("/config")
async def spectrum_update_config(
    body: SpectrumParams,
    request: Request,
    key_id: str = Depends(require_role(Role.ANALYST)),
) -> SpectrumParams:
    """Update spectrum parameters (frequency, gain, sample rate). Analyst key."""
    streamer = _get_streamer(request)

    # Validate all params upfront
    validate_frequency(body.center_freq_hz)
    validate_gain(body.gain_db)
    validate_sample_rate(body.sample_rate_hz)

    await streamer.set_params(
        freq_hz=body.center_freq_hz,
        gain_db=body.gain_db,
        sample_rate_hz=body.sample_rate_hz,
    )
    return SpectrumParams(
        center_freq_hz=streamer.center_freq,
        sample_rate_hz=streamer.sample_rate,
        gain_db=streamer.gain,
        fft_size=streamer.fft_size,
    )


@router.get("/status")
async def spectrum_status(
    request: Request,
    key_id: str = Depends(rate_limit),
) -> SpectrumStatus:
    """Return the current streamer status."""
    streamer = _get_streamer(request)
    return streamer.get_status()


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


@router.websocket("/ws/spectrum")
async def ws_spectrum(websocket: WebSocket) -> None:
    """Stream FFT data to authenticated WebSocket clients.

    Auth is validated BEFORE accept (SigRift SEC-2 fix).
    """
    await require_ws_auth(websocket)
    await accept_ws(websocket)

    app_state = websocket.app.state.app_state
    streamer = getattr(websocket.app.state, "spectrum_streamer", None)

    await app_state.ws_spectrum_clients.add(websocket)
    if streamer is not None:
        await streamer.clients.add(websocket)

    try:
        # Send current status on connect
        if streamer is not None:
            await websocket.send_json(streamer.get_status().model_dump(mode="json"))

        # Keep connection alive; data is pushed by the stream loop
        while True:
            _ = await websocket.receive_text()

    except Exception:
        pass
    finally:
        await app_state.ws_spectrum_clients.remove(websocket)
        if streamer is not None:
            await streamer.clients.remove(websocket)
