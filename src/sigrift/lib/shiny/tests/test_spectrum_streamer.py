"""I/Q alignment of ``SpectrumStreamer``'s stream reads (finding P13).

rtl_tcp streams unframed interleaved 8-bit I/Q, so a frame must start on an I
byte. The streamer throws bytes away in two places: the idle drain while no
client is watching (``sock_recv(65536)``, which can return an odd count) and a
partial frame abandoned when a read times out. Either would offset every later
frame by one and swap I/Q (a mirrored spectrum). The streamer tracks the
parity of every byte read and consumes one byte to realign before a frame.
"""

from __future__ import annotations

import asyncio

import numpy as np
import pytest

from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer

_I_BYTE, _Q_BYTE = 200, 50


class _Clients:
    """Minimal WebSocketClientSet stand-in: truthiness + broadcast."""

    def __init__(self, present: bool) -> None:
        self.present = present
        self.frames: list[dict] = []

    def __bool__(self) -> bool:
        return self.present

    async def broadcast(self, payload: dict) -> None:
        self.frames.append(payload)


@pytest.mark.asyncio
async def test_idle_odd_drain_realigns_before_frame(monkeypatch) -> None:
    streamer = SpectrumStreamer()
    streamer.fft_size = 4  # bytes-per-frame = 8
    streamer.display_bins = 2
    streamer.averaging = 1
    streamer.sample_rate = 8.0
    streamer.connected = True
    streamer.sock = object()  # sentinel; never touched directly

    # Stream after the header: I,Q,I,Q,...  (position 0 is an I byte).
    stream = bytes([_I_BYTE, _Q_BYTE] * 64)
    state = {"pos": 0, "clients_present": False}

    clients = _Clients(present=False)
    streamer.clients = clients

    recorded: dict[str, bytes] = {}

    def fake_compute_fft(raw, window, fft_size, display_bins):
        recorded["raw"] = bytes(raw)
        return np.zeros(display_bins, dtype=np.float32)

    monkeypatch.setattr(
        SpectrumStreamer, "_compute_fft", staticmethod(fake_compute_fft)
    )

    async def fake_sock_recv(sock, n):
        if not state["clients_present"]:
            # Idle drain: hand back exactly one (odd) byte, then a client joins.
            chunk = stream[state["pos"] : state["pos"] + 1]
            state["pos"] += len(chunk)
            state["clients_present"] = True
            clients.present = True
            return chunk
        chunk = stream[state["pos"] : state["pos"] + n]
        state["pos"] += len(chunk)
        return chunk

    # Stop the loop as soon as the first frame is broadcast.
    orig_broadcast = clients.broadcast

    async def stopping_broadcast(payload):
        await orig_broadcast(payload)
        streamer._running = False

    clients.broadcast = stopping_broadcast  # type: ignore[assignment]

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_recv", fake_sock_recv)

    streamer._running = True
    await asyncio.wait_for(streamer._stream_loop(), timeout=5.0)

    # One odd byte was drained while idle (position 0, an I byte); the realign
    # consumed position 1 (a Q byte), so the frame starts on an I byte at
    # position 2.  Without the realign it would have started on the Q at 1.
    assert clients.frames, "a spectrum frame should have been broadcast"
    assert recorded["raw"] == stream[2:10]
    assert recorded["raw"][0] == _I_BYTE


@pytest.mark.asyncio
async def test_partial_odd_frame_then_timeout_realigns(monkeypatch) -> None:
    # A frame read gets 3 bytes, then the next read times out: the loop
    # abandons the partial frame.  Those 3 bytes were consumed from the
    # stream, so the next frame must realign (one byte) and start on an I
    # byte; dropping them uncounted left every later frame starting on Q.
    streamer = SpectrumStreamer()
    streamer.fft_size = 4  # bytes-per-frame = 8
    streamer.display_bins = 2
    streamer.averaging = 1
    streamer.sample_rate = 8.0
    streamer.connected = True
    streamer.sock = object()

    stream = bytes([_I_BYTE, _Q_BYTE] * 64)
    state = {"pos": 0, "calls": 0}
    clients = _Clients(present=True)
    streamer.clients = clients
    recorded: dict[str, bytes] = {}

    def fake_compute_fft(raw, window, fft_size, display_bins):
        recorded["raw"] = bytes(raw)
        return np.zeros(display_bins, dtype=np.float32)

    monkeypatch.setattr(
        SpectrumStreamer, "_compute_fft", staticmethod(fake_compute_fft)
    )

    async def fake_sock_recv(sock, n):
        state["calls"] += 1
        if state["calls"] == 1:  # partial frame: 3 of 8 bytes arrive
            chunk = stream[0:3]
            state["pos"] = 3
            return chunk
        if state["calls"] == 2:  # then the read stalls past its timeout
            raise asyncio.TimeoutError
        chunk = stream[state["pos"] : state["pos"] + n]
        state["pos"] += len(chunk)
        return chunk

    async def stopping_broadcast(payload):
        clients.frames.append(payload)
        streamer._running = False

    clients.broadcast = stopping_broadcast  # type: ignore[assignment]
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "sock_recv", fake_sock_recv)

    streamer._running = True
    await asyncio.wait_for(streamer._stream_loop(), timeout=5.0)

    # Bytes 0-2 were abandoned, byte 3 (a Q) is consumed to realign, and the
    # frame is bytes 4-11, starting on an I byte.
    assert clients.frames
    assert recorded["raw"] == stream[4:12]
    assert recorded["raw"][0] == _I_BYTE


@pytest.mark.asyncio
async def test_connect_resets_stream_parity() -> None:
    # The parity is per connection: a reconnect starts at a fresh stream
    # (header + I/Q pairs), whatever the previous socket was left at.
    # The peer closes its side once the streamer hangs up.  (A handler that
    # just drops its writer leaves the server side open, and wait_closed()
    # then never returns whenever the accept ran before server.close().)
    async def rtl_tcp_peer(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            await reader.read()  # the tuning commands, then EOF
        finally:
            writer.close()

    server = await asyncio.start_server(rtl_tcp_peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    streamer = SpectrumStreamer()
    streamer._stream_odd = True
    try:
        assert await streamer.connect("127.0.0.1", port)
        assert streamer._stream_odd is False
    finally:
        await streamer.disconnect()
        server.close()
        await server.wait_closed()
