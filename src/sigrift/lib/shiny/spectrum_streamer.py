"""Spectrum streamer for rtl_tcp with FFT processing and signal ID.

Validates host/port on connect (SEC-4 SSRF fix), frequency/gain/rate on
set_params.  FFT pipeline: read IQ -> window -> FFT -> fftshift ->
downsample -> dB -> average -> send.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from datetime import datetime, timezone
from typing import Any

import numpy as np

from sigrift.lib.security.validation import (
    validate_frequency,
    validate_gain,
    validate_host,
    validate_port,
    validate_sample_rate,
)
from sigrift.lib.shiny.models import SpectrumParams, SpectrumStatus
from sigrift.lib.shiny.state import WebSocketClientSet

logger = logging.getLogger(__name__)

# Known signal database — SigRift taxonomy
KNOWN_SIGNALS: list[dict[str, Any]] = [
    {
        "name": "ISM 433 MHz",
        "center_hz": 433.92e6,
        "bw_hz": 1.74e6,
        "expected_classes": ["ook", "2fsk", "4fsk", "lora-css"],
    },
    {
        "name": "ISM 868 MHz",
        "center_hz": 868e6,
        "bw_hz": 2e6,
        "expected_classes": ["ook", "2fsk", "4fsk", "lora-css", "2gfsk"],
    },
    {
        "name": "ISM 915 MHz",
        "center_hz": 915e6,
        "bw_hz": 26e6,
        "expected_classes": ["lora-css", "2gfsk", "4gfsk"],
    },
    {
        "name": "2.4 GHz WiFi",
        "center_hz": 2.437e9,
        "bw_hz": 22e6,
        "expected_classes": ["ofdm-64", "ofdm-256"],
    },
    {
        "name": "5 GHz WiFi",
        "center_hz": 5.18e9,
        "bw_hz": 40e6,
        "expected_classes": ["ofdm-256", "ofdm-512", "ofdm-1024"],
    },
    {
        "name": "FM Broadcast",
        "center_hz": 100e6,
        "bw_hz": 200e3,
        "expected_classes": ["fm"],
    },
    {
        "name": "AM Broadcast",
        "center_hz": 1e6,
        "bw_hz": 10e3,
        "expected_classes": ["am-dsb"],
    },
    {
        "name": "DVB-S2",
        "center_hz": 12.0e9,
        "bw_hz": 36e6,
        "expected_classes": ["8psk", "16apsk", "32apsk", "qpsk"],
    },
    {
        "name": "LTE Downlink",
        "center_hz": 2.14e9,
        "bw_hz": 20e6,
        "expected_classes": ["ofdm-1024", "ofdm-2048", "16qam", "64qam", "256qam"],
    },
    {
        "name": "TETRA",
        "center_hz": 380e6,
        "bw_hz": 25e3,
        "expected_classes": ["qpsk", "4pam"],
    },
    {
        "name": "AIS Maritime",
        "center_hz": 161.975e6,
        "bw_hz": 25e3,
        "expected_classes": ["2gmsk"],
    },
    {
        "name": "DECT",
        "center_hz": 1.89e9,
        "bw_hz": 1.728e6,
        "expected_classes": ["2gfsk"],
    },
    {
        "name": "Bluetooth",
        "center_hz": 2.441e9,
        "bw_hz": 1e6,
        "expected_classes": ["2gfsk", "4gfsk", "8psk"],
    },
]

_SIGNAL_THRESHOLD_DB = -30.0


class SpectrumStreamer:
    """Manages an rtl_tcp connection and streams FFT data to WS clients."""

    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.connected = False
        self.host = ""
        self.port = 1234
        self.center_freq: float = 433_920_000.0
        self.sample_rate: float = 2_048_000.0
        self.gain: float = 40.0
        self.fft_size = 1024
        self.display_bins = 512
        self.averaging = 4
        self.target_fps = 15
        self.clients: WebSocketClientSet = WebSocketClientSet()
        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._window: np.ndarray | None = None
        self._connected_since: datetime | None = None
        self._frames_sent = 0
        # Parity of the bytes read from the rtl_tcp socket since it was
        # opened.  rtl_tcp has no framing: its 12-byte header and the I/Q
        # pairs that follow are even-sized, so an FFT frame starts on an I
        # byte exactly when an even number of bytes has been consumed.  Every
        # read updates this, including bytes that are thrown away.
        self._stream_odd = False

    async def connect(self, host: str, port: int = 1234) -> bool:
        """Connect to rtl_tcp after validating host/port (SEC-4)."""
        host = validate_host(host)
        port = validate_port(port)
        if self.connected:
            await self.disconnect()
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setblocking(False)
            self._stream_odd = False
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.sock_connect(self.sock, (host, port)),
                timeout=5.0,
            )
            self.host, self.port = host, port
            self.connected = True
            self._connected_since = datetime.now(timezone.utc)
            self._frames_sent = 0
            await self._send_command(0x01, int(self.center_freq))
            await self._send_command(0x02, int(self.sample_rate))
            await self._send_command(0x04, int(self.gain * 10))
            logger.info("Connected to rtl_tcp at %s:%d", host, port)
            return True
        except (ConnectionError, asyncio.TimeoutError, OSError) as exc:
            self.connected = False
            if self.sock:
                self.sock.close()
                self.sock = None
            logger.warning("Connect failed %s:%d: %s", host, port, exc)
            return False

    async def disconnect(self) -> None:
        """Disconnect from rtl_tcp and cancel the streaming task."""
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        if self.sock:
            self.sock.close()
            self.sock = None
        self.connected = False
        self._connected_since = None
        logger.info("Disconnected from rtl_tcp")

    async def _send_command(self, cmd: int, param: int) -> None:
        if not self.sock:
            return
        loop = asyncio.get_running_loop()
        await loop.sock_sendall(self.sock, struct.pack(">BI", cmd, param))

    async def set_params(
        self,
        freq_hz: float | None = None,
        gain_db: float | None = None,
        sample_rate_hz: float | None = None,
    ) -> None:
        """Update streaming parameters with validation."""
        if freq_hz is not None:
            freq_hz = validate_frequency(freq_hz)
            await self._send_command(0x01, int(freq_hz))
            self.center_freq = freq_hz
        if sample_rate_hz is not None:
            sample_rate_hz = validate_sample_rate(sample_rate_hz)
            await self._send_command(0x02, int(sample_rate_hz))
            self.sample_rate = sample_rate_hz
        if gain_db is not None:
            gain_db = validate_gain(gain_db)
            await self._send_command(0x04, int(gain_db * 10))
            self.gain = gain_db

    async def start_streaming(self) -> None:
        """Start the FFT streaming loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._stream_loop())

    async def stop_streaming(self) -> None:
        """Stop streaming (does not disconnect)."""
        self._running = False

    @staticmethod
    def _compute_fft(
        raw: bytes,
        window: np.ndarray,
        fft_size: int,
        display_bins: int,
    ) -> np.ndarray:
        """CPU-intensive FFT pipeline, safe to run in a worker thread.

        Converts raw IQ bytes -> windowed complex -> FFT -> fftshift ->
        downsample -> dB magnitudes.  All inputs are either immutable
        (bytes) or defensively copied before the call.
        """
        iq = (np.frombuffer(raw, np.uint8).astype(np.float32) - 127.5) / 127.5
        fft_r = np.fft.fftshift(np.fft.fft((iq[0::2] + 1j * iq[1::2]) * window))
        mag = np.abs(fft_r)
        bs = fft_size // display_bins
        return 20.0 * np.log10(mag.reshape(display_bins, bs).max(axis=1) + 1e-10)

    async def _stream_loop(self) -> None:
        """IQ -> window -> FFT -> fftshift -> downsample -> dB -> avg -> send."""
        if not self.sock:
            return
        loop = asyncio.get_running_loop()
        bpf = self.fft_size * 2  # bytes per frame (I+Q, 8-bit each)
        self._window = np.hanning(self.fft_size).astype(np.float32)
        # Snapshot the window so the thread gets an immutable copy
        window_copy = self._window.copy()
        avg_count = 0
        avg_mag = np.zeros(self.display_bins, dtype=np.float32)
        interval = 1.0 / self.target_fps
        last_t = 0.0
        fft_size = self.fft_size
        display_bins = self.display_bins
        # rtl_tcp has no framing, so a frame must start on an I byte.  Bytes
        # are discarded in two places -- the idle drain while no client is
        # watching, and a partial frame abandoned when a read times out --
        # and either can leave an odd count behind, which would offset every
        # later frame by one and swap I/Q (a mirrored spectrum).  Every read
        # folds its length into ``self._stream_odd``; before a frame is read
        # the stream is realigned to an even offset.
        try:
            while self._running and self.connected:
                if not self.clients:
                    try:
                        drained = await asyncio.wait_for(
                            loop.sock_recv(self.sock, 65536), timeout=0.1
                        )
                        self._stream_odd ^= bool(len(drained) % 2)
                    except (asyncio.TimeoutError, OSError):
                        pass
                    await asyncio.sleep(0.05)
                    continue
                try:
                    if self._stream_odd:
                        # Consume one byte so the next read starts on an I byte
                        # (sock_recv(.., 1) returns exactly 1 byte, or b"" on EOF).
                        extra = await asyncio.wait_for(
                            loop.sock_recv(self.sock, 1), timeout=2.0
                        )
                        if not extra:
                            raise ConnectionError("rtl_tcp closed")
                        self._stream_odd = False
                    raw = b""
                    while len(raw) < bpf:
                        # A timeout here abandons ``raw``; its bytes were
                        # already counted, so the next frame realigns.
                        chunk = await asyncio.wait_for(
                            loop.sock_recv(self.sock, min(65536, bpf - len(raw))),
                            timeout=2.0,
                        )
                        if not chunk:
                            raise ConnectionError("rtl_tcp closed")
                        raw += chunk
                        self._stream_odd ^= bool(len(chunk) % 2)
                    # Offload FFT to thread pool to avoid blocking event loop.
                    # ``raw`` is an immutable bytes object; ``window_copy`` is
                    # a dedicated copy not mutated by the main loop.
                    mag_db = await asyncio.to_thread(
                        self._compute_fft,
                        raw,
                        window_copy,
                        fft_size,
                        display_bins,
                    )
                    avg_mag += mag_db
                    avg_count += 1
                    now = time.time()
                    if avg_count >= self.averaging and (now - last_t) >= interval:
                        spec = avg_mag / avg_count
                        f0_hz = self.center_freq - self.sample_rate / 2
                        f1_hz = self.center_freq + self.sample_rate / 2
                        f0 = f0_hz / 1e6
                        f1 = f1_hz / 1e6
                        signals = self.identify_signals(f0_hz, f1_hz)
                        payload: dict[str, Any] = {
                            "type": "spectrum",
                            "magnitudes_db": [round(float(v), 1) for v in spec],
                            "f0": round(f0, 3),
                            "f1": round(f1, 3),
                            "fc": round(self.center_freq / 1e6, 3),
                            "bw": round(self.sample_rate / 1e6, 2),
                            "bins": self.display_bins,
                            "t": round(now, 3),
                            "signals": signals,
                        }
                        await self.clients.broadcast(payload)
                        avg_mag.fill(0)
                        avg_count = 0
                        last_t = now
                        self._frames_sent += 1
                except asyncio.TimeoutError:
                    continue
                except ConnectionError:
                    self.connected = False
                    break
        except asyncio.CancelledError:
            pass
        except (OSError, ConnectionError) as exc:
            logger.warning("Streaming error: %s", exc)
            self.connected = False

    def get_status(self) -> SpectrumStatus:
        """Return current streamer status."""
        params = (
            SpectrumParams(
                center_freq_hz=self.center_freq,
                sample_rate_hz=self.sample_rate,
                gain_db=self.gain,
                fft_size=self.fft_size,
            )
            if self.connected
            else None
        )
        return SpectrumStatus(
            connected=self.connected,
            host=self.host,
            port=self.port,
            params=params,
            connected_since=self._connected_since,
            frames_sent=self._frames_sent,
        )

    @staticmethod
    def identify_signals(
        freq_start_hz: float,
        freq_end_hz: float,
        magnitude_db: float = _SIGNAL_THRESHOLD_DB,
    ) -> list[dict[str, Any]]:
        """Return known signals whose bands overlap the given frequency range."""
        results: list[dict[str, Any]] = []
        for sig in KNOWN_SIGNALS:
            lo = sig["center_hz"] - sig["bw_hz"] / 2
            hi = sig["center_hz"] + sig["bw_hz"] / 2
            if (
                lo < freq_end_hz
                and hi > freq_start_hz
                and magnitude_db >= _SIGNAL_THRESHOLD_DB
            ):
                results.append(
                    {
                        "name": sig["name"],
                        "center_hz": sig["center_hz"],
                        "bw_hz": sig["bw_hz"],
                        "expected_classes": sig["expected_classes"],
                    }
                )
        return results
