"""I/Q alignment of edge ``monitor.RTLTCPClient`` captures (finding P13).

``monitor`` (run by ``rf-edge.service``) drained stale rtl_tcp data with
non-blocking ``recv(65536)`` calls without tracking parity, then read
``num_samples * 2`` bytes. TCP can hand those drains back in any sizes, so a
drain could stop on an odd byte count; the next read then started on a Q byte
and I/Q stayed swapped (a mirrored spectrum) for that and every later capture.
``connect()`` also read the 12-byte header with a bare ``recv(12)`` that can
return fewer bytes.
"""

from __future__ import annotations

import importlib
import struct
import sys
from types import ModuleType

import numpy as np
import pytest

_I_BYTE, _Q_BYTE = 200, 50  # rtl_tcp uint8 pattern: I high, Q low
_I_VAL = (_I_BYTE - 127.5) / 127.5
_Q_VAL = (_Q_BYTE - 127.5) / 127.5


@pytest.fixture(scope="module")
def monitor(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    tmp = tmp_path_factory.mktemp("monitor")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MLRF_LOG_DIR", str(tmp / "logs"))
        sys.modules.pop("sigrift.edge.monitor", None)
        return importlib.import_module("sigrift.edge.monitor")


class FakeRTLTCP:
    """rtl_tcp stand-in: a 12-byte header, then endless I/Q bytes."""

    HEADER = b"RTL0" + struct.pack(">II", 5, 29)

    def __init__(self, chunk: int = 777) -> None:
        self.pos = 0
        self.available = len(self.HEADER)
        self.blocking = True
        self.chunk = chunk

    def arrive(self, n: int) -> None:
        self.available = max(self.available, self.pos) + n

    def _wire(self, start: int, n: int) -> bytes:
        out = bytearray()
        for p in range(start, start + n):
            if p < len(self.HEADER):
                out.append(self.HEADER[p])
            else:
                out.append(_I_BYTE if (p - len(self.HEADER)) % 2 == 0 else _Q_BYTE)
        return bytes(out)

    def settimeout(self, _t: object) -> None:
        self.blocking = True

    def setblocking(self, flag: bool) -> None:
        self.blocking = flag

    def connect(self, _addr: object) -> None:
        pass

    def close(self) -> None:
        pass

    def send(self, data: bytes) -> None:
        pass

    def recv(self, n: int) -> bytes:
        if self.blocking:
            take = min(n, self.chunk)
            self.available = max(self.available, self.pos + take)
        else:
            take = min(n, self.chunk, self.available - self.pos)
            if take <= 0:
                raise BlockingIOError
        data = self._wire(self.pos, take)
        self.pos += take
        return data

    def recv_into(self, view: memoryview, n: int = 0) -> int:
        data = self.recv(n or len(view))
        view[: len(data)] = data
        return len(data)


@pytest.fixture()
def fake_rtl(monkeypatch: pytest.MonkeyPatch, monitor: ModuleType) -> FakeRTLTCP:
    fake = FakeRTLTCP()
    monkeypatch.setattr(monitor.socket, "socket", lambda *a, **k: fake)
    return fake


def _assert_aligned(iq: np.ndarray) -> None:
    assert iq is not None
    np.testing.assert_allclose(iq.real, _I_VAL, atol=1e-6)
    np.testing.assert_allclose(iq.imag, _Q_VAL, atol=1e-6)


def test_odd_stale_drain_does_not_swap_iq(
    monitor: ModuleType, fake_rtl: FakeRTLTCP
) -> None:
    client = monitor.RTLTCPClient()
    assert client.connect()
    fake_rtl.arrive(1001)  # odd number of stale bytes queued
    _assert_aligned(client.capture(64, dwell_time=0.0))


@pytest.mark.parametrize("stale", [0, 1, 2, 3, 65537, 131071])
def test_alignment_holds_across_captures(
    monitor: ModuleType, fake_rtl: FakeRTLTCP, stale: int
) -> None:
    client = monitor.RTLTCPClient()
    assert client.connect()
    for extra in (stale, 333, 0, 4097):
        fake_rtl.arrive(extra)
        _assert_aligned(client.capture(32, dwell_time=0.0))


def test_header_split_across_reads(monitor: ModuleType, monkeypatch) -> None:
    fake = FakeRTLTCP(chunk=5)  # header arrives as 5 + 5 + 2 bytes
    monkeypatch.setattr(monitor.socket, "socket", lambda *a, **k: fake)
    client = monitor.RTLTCPClient()
    assert client.connect()
    fake.arrive(7)
    _assert_aligned(client.capture(32, dwell_time=0.0))
