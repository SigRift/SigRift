"""rf_scan capture correctness (review findings D12 and D9).

D12: RTLTCPClient dropped stale rtl_tcp data with non-blocking
``recv(65536)`` calls. TCP can hand those back in any sizes, so the drop
could stop on an odd byte count; the next read then started on a Q byte and
I/Q stayed swapped (spectrum mirrored) for that and every later capture.
A closed connection also made the drop loop spin forever.

D9: a remote ``iq_capture`` ignored the command's ``sample_rate`` and
``gain_db``: rtl_tcp's rate was never set, HackRF always ran at 2 MHz, and
the upload's ``X-Sample-Rate`` reported the requested rate anyway.
"""

from __future__ import annotations

import gzip
import importlib
import json
import struct
import sys
from pathlib import Path
from types import ModuleType

import numpy as np
import pytest

_I_BYTE, _Q_BYTE = 200, 50  # rtl_tcp uint8 pattern: I high, Q low
_I_VAL = (_I_BYTE - 127.5) / 127.5
_Q_VAL = (_Q_BYTE - 127.5) / 127.5


@pytest.fixture(scope="module")
def rf_scan(tmp_path_factory: pytest.TempPathFactory) -> ModuleType:
    if "sigrift.edge.rf_scan" in sys.modules:
        return sys.modules["sigrift.edge.rf_scan"]
    tmp = tmp_path_factory.mktemp("rf_scan")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("MLRF_LOG_DIR", str(tmp / "logs"))
        mp.setenv("MLRF_AGENT_DIR", str(tmp / "agent"))
        return importlib.import_module("sigrift.edge.rf_scan")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch, rf_scan: ModuleType) -> None:
    for var in (
        "MLRF_RTL_SAMPLE_RATE",
        "MLRF_RTL_GAIN",
        "MLRF_CA_CERT",
        "MLRF_CA_BUNDLE",
        "MLRF_INSECURE_TLS",
        "MLRF_CLIENT_CERT",
        "MLRF_CLIENT_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(rf_scan, "DWELL_TIME", 0.0)


class _Spinning(BaseException):
    """Raised by the fake when the client keeps polling a dead socket.

    A BaseException so the client's ``except Exception`` cannot hide it.
    """


class FakeRTLTCP:
    """rtl_tcp stand-in: a 12-byte header, then endless I/Q bytes.

    ``arrive(n)`` queues *n* more stream bytes; non-blocking reads return
    only queued bytes (in awkward chunk sizes), blocking reads wait for
    "more" (the stream is endless). Commands the client sends are recorded.
    """

    HEADER = b"RTL0" + struct.pack(">II", 5, 29)  # R820T, 29 gains

    def __init__(self, chunk: int = 777) -> None:
        self.pos = 0  # wire bytes handed to the client (header + stream)
        self.available = len(self.HEADER)  # wire bytes that have "arrived"
        self.blocking = True
        self.chunk = chunk
        self.sent = bytearray()
        self.closed_by_peer = False
        self.empty_polls = 0

    # -- helpers for the test ------------------------------------------------
    def arrive(self, n: int) -> None:
        self.available = max(self.available, self.pos) + n

    def commands(self) -> list[tuple[int, int]]:
        out = []
        for i in range(0, len(self.sent), 5):
            out.append(struct.unpack(">BI", bytes(self.sent[i : i + 5])))
        return out

    def _wire(self, start: int, n: int) -> bytes:
        out = bytearray()
        for p in range(start, start + n):
            if p < len(self.HEADER):
                out.append(self.HEADER[p])
            else:
                out.append(_I_BYTE if (p - len(self.HEADER)) % 2 == 0 else _Q_BYTE)
        return bytes(out)

    # -- socket API used by RTLTCPClient ----------------------------------------
    def settimeout(self, _t: object) -> None:
        self.blocking = True

    def setblocking(self, flag: bool) -> None:
        self.blocking = flag

    def connect(self, _addr: object) -> None:
        pass

    def close(self) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        self.sent += data

    send = sendall

    def recv(self, n: int) -> bytes:
        if self.closed_by_peer:
            self.empty_polls += 1
            if self.empty_polls > 1000:
                raise _Spinning("client keeps polling a closed socket")
            return b""
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
def fake_rtl(monkeypatch: pytest.MonkeyPatch, rf_scan: ModuleType) -> FakeRTLTCP:
    fake = FakeRTLTCP()
    monkeypatch.setattr(rf_scan.socket, "socket", lambda *a, **k: fake)
    return fake


def _assert_aligned(iq: np.ndarray) -> None:
    assert iq is not None
    np.testing.assert_allclose(iq.real, _I_VAL, atol=1e-6)
    np.testing.assert_allclose(iq.imag, _Q_VAL, atol=1e-6)


# ---------------------------------------------------------------------------
# D12: I/Q alignment of rtl_tcp captures
# ---------------------------------------------------------------------------


class TestRTLAlignment:
    def test_odd_stale_drain_does_not_swap_iq(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        fake_rtl.arrive(1001)  # odd number of stale bytes queued
        _assert_aligned(client.capture(64))

    @pytest.mark.parametrize("stale", [0, 1, 2, 3, 65537, 131071])
    def test_alignment_holds_across_captures(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP, stale: int
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        for extra in (stale, 333, 0, 4097):
            fake_rtl.arrive(extra)
            _assert_aligned(client.capture(128))

    def test_header_split_across_reads(self, rf_scan: ModuleType, monkeypatch) -> None:
        fake = FakeRTLTCP(chunk=5)  # header arrives as 5 + 5 + 2 bytes
        monkeypatch.setattr(rf_scan.socket, "socket", lambda *a, **k: fake)
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        fake.arrive(7)
        _assert_aligned(client.capture(32))

    def test_closed_connection_during_drain_does_not_spin(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        fake_rtl.closed_by_peer = True
        assert client.capture(64) is None
        assert not client.connected


# ---------------------------------------------------------------------------
# D9: rtl_tcp rate/gain configuration
# ---------------------------------------------------------------------------


class TestRTLConfiguration:
    def test_connect_sets_the_scan_rate_explicitly(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        assert fake_rtl.commands() == [(0x02, 2_048_000)]
        assert client.sample_rate == 2_048_000.0

    def test_scan_rate_and_gain_from_env(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP, monkeypatch
    ) -> None:
        monkeypatch.setenv("MLRF_RTL_SAMPLE_RATE", "2400000")
        monkeypatch.setenv("MLRF_RTL_GAIN", "29.7")
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        assert fake_rtl.commands() == [(0x02, 2_400_000), (0x03, 1), (0x04, 297)]

    def test_unsupported_scan_rate_env_falls_back(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP, monkeypatch
    ) -> None:
        monkeypatch.setenv("MLRF_RTL_SAMPLE_RATE", "500000")  # RTL dead zone
        client = rf_scan.RTLTCPClient()
        assert client.scan_sample_rate == 2_048_000

    def test_capture_settings_applied_and_restored(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        del fake_rtl.sent[:]
        assert client.configure_capture(2.4e6, 40.0) == 2_400_000.0
        assert fake_rtl.commands() == [(0x02, 2_400_000), (0x03, 1), (0x04, 400)]
        assert client.sample_rate == 2_400_000.0
        del fake_rtl.sent[:]
        client.restore_scan_settings()
        # Back to the scan rate and to tuner AGC (rtl_tcp's default).
        assert fake_rtl.commands() == [(0x02, 2_048_000), (0x03, 0)]
        assert client.sample_rate == 2_048_000.0

    def test_unsupported_capture_rate_keeps_the_device_rate(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        del fake_rtl.sent[:]
        assert client.configure_capture(20e6, None) == 2_048_000.0
        assert fake_rtl.commands() == []
        client.restore_scan_settings()
        assert fake_rtl.commands() == []

    def test_reconnect_undoes_a_capture_gain(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        client.configure_capture(2.4e6, 20.0)
        client.disconnect()  # e.g. the capture failed mid-way
        del fake_rtl.sent[:]
        assert client.connect()
        assert fake_rtl.commands() == [(0x02, 2_048_000), (0x03, 0)]

    @pytest.mark.parametrize(
        "rate", [230_000, 250_000, 300_000, 960_000, 1_024_000, 2_048_000, 2_400_000]
    )
    def test_actual_rate_matches_librtlsdr(
        self, rf_scan: ModuleType, rate: int
    ) -> None:
        actual = rf_scan.rtl_actual_sample_rate(rate)
        assert actual == float(int(actual))
        assert abs(actual - rate) <= 1.0


# ---------------------------------------------------------------------------
# D9: HackRF rate/gain configuration
# ---------------------------------------------------------------------------


class FakeHackRF:
    """Patches subprocess.run: records argv, writes int8 I/Q to the -r file."""

    def __init__(self, extra_bytes: int = 0) -> None:
        self.argv: list[list[str]] = []
        self.timeouts: list[float] = []
        self.extra_bytes = extra_bytes

    def __call__(self, argv, capture_output=True, timeout=None):
        self.argv.append(list(argv))
        self.timeouts.append(timeout)
        n = int(argv[argv.index("-n") + 1])
        pattern = np.array([64, -64] * n, dtype=np.int8).tobytes()
        Path(argv[argv.index("-r") + 1]).write_bytes(pattern + bytes(self.extra_bytes))

        class _Done:
            returncode = 0

        return _Done()

    def arg(self, flag: str, call: int = -1) -> str:
        argv = self.argv[call]
        return argv[argv.index(flag) + 1]


@pytest.fixture()
def fake_hackrf(monkeypatch: pytest.MonkeyPatch, rf_scan: ModuleType) -> FakeHackRF:
    fake = FakeHackRF()
    monkeypatch.setattr(rf_scan.subprocess, "run", fake)
    return fake


class TestHackRF:
    def test_scan_capture_unchanged(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        cap = rf_scan.HackRFCapture()
        cap.set_frequency(915e6)
        iq = cap.capture(4096)
        assert len(iq) == 4096
        np.testing.assert_allclose(iq.real, 0.5)
        np.testing.assert_allclose(iq.imag, -0.5)
        assert fake_hackrf.arg("-s") == "2000000"
        assert fake_hackrf.arg("-l") == "40" and fake_hackrf.arg("-g") == "48"
        # -n counts samples: the request plus the discarded transient.
        assert fake_hackrf.arg("-n") == str(4096 + 4096)

    def test_capture_rate_and_gain(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        cap = rf_scan.HackRFCapture()
        assert cap.configure_capture(10e6, 30.0) == 10e6
        cap.capture(1_000_000)
        assert fake_hackrf.arg("-s") == "10000000"
        assert (fake_hackrf.arg("-l"), fake_hackrf.arg("-g")) == ("24", "6")
        # Timeout scales with the transfer (1 M samples at 10 MHz = 0.1 s+).
        assert fake_hackrf.timeouts[-1] >= 5.0
        cap.restore_scan_settings()
        cap.capture(4096)
        assert fake_hackrf.arg("-s") == "2000000"
        assert (fake_hackrf.arg("-l"), fake_hackrf.arg("-g")) == ("40", "48")

    def test_long_capture_gets_a_long_enough_timeout(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        cap = rf_scan.HackRFCapture()
        cap.capture(rf_scan.IQ_CAPTURE_MAX_SAMPLES)  # ~4.2 s at 2 MHz
        assert fake_hackrf.timeouts[-1] > rf_scan.IQ_CAPTURE_MAX_SAMPLES / 2e6

    def test_unsupported_rate_uses_the_scan_rate(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        cap = rf_scan.HackRFCapture()
        assert cap.configure_capture(1e6, None) == 2e6
        assert cap.configure_capture(25e6, None) == 2e6

    def test_odd_file_length_keeps_iq_aligned(
        self, rf_scan: ModuleType, monkeypatch
    ) -> None:
        def short_run(argv, capture_output=True, timeout=None):
            # hackrf_transfer wrote one byte more than requested and less
            # than the transient: the slice must still start on an I byte.
            n = 64
            data = np.array([64, -64] * n, dtype=np.int8).tobytes() + b"\x00"
            Path(argv[argv.index("-r") + 1]).write_bytes(data)

            class _Done:
                returncode = 0

            return _Done()

        monkeypatch.setattr(rf_scan.subprocess, "run", short_run)
        iq = rf_scan.HackRFCapture().capture(64)
        np.testing.assert_allclose(iq.real, 0.5)
        np.testing.assert_allclose(iq.imag, -0.5)

    @pytest.mark.parametrize(
        ("gain", "split"),
        [
            (0, (0, 0)),
            (7.9, (0, 6)),
            (10, (8, 2)),
            (40, (40, 0)),
            (73, (40, 32)),
            (102, (40, 62)),
            (200, (40, 62)),
        ],
    )
    def test_gain_split(self, rf_scan: ModuleType, gain: float, split) -> None:
        assert rf_scan.hackrf_split_gain(gain) == split


# ---------------------------------------------------------------------------
# D9: end to end -- the upload reports the rate the device used
# ---------------------------------------------------------------------------


class _Uploads:
    def __init__(self) -> None:
        self.requests = []

    def __call__(self, req, context=None, timeout=None):
        self.requests.append(req)
        uploads = self

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return json.dumps({"ok": True, "n": len(uploads.requests)}).encode()

        return _Resp()

    def header(self, name: str) -> str:
        return dict(self.requests[-1].header_items())[name.capitalize()]


@pytest.fixture()
def uploads(monkeypatch: pytest.MonkeyPatch, rf_scan: ModuleType) -> _Uploads:
    up = _Uploads()
    monkeypatch.setattr(rf_scan.urllib.request, "urlopen", up)
    return up


def _run(rf_scan, sdrs, **cmd):
    body = {"freq_hz": 915e6, "duration_ms": 100, "command_id": "c1", **cmd}
    return rf_scan.execute_iq_capture(body, sdrs, "https://bridge.test", "k", "n1")


class TestExecuteIQCapture:
    def test_hackrf_runs_and_reports_requested_supported_rate(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF, uploads: _Uploads
    ) -> None:
        cap = rf_scan.HackRFCapture()
        assert _run(rf_scan, [cap], sample_rate=2.4e6, gain_db=30)
        assert fake_hackrf.arg("-s") == "2400000"
        assert (fake_hackrf.arg("-l"), fake_hackrf.arg("-g")) == ("24", "6")
        assert float(uploads.header("X-Sample-Rate")) == 2.4e6
        assert uploads.header("X-IQ-Samples") == "240000"  # 100 ms at 2.4 MHz
        # Scan settings are back.
        assert cap.sample_rate == 2_000_000
        assert (cap.lna_gain, cap.vga_gain) == (40, 48)

    def test_hackrf_reports_the_rate_it_fell_back_to(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF, uploads: _Uploads
    ) -> None:
        assert _run(rf_scan, [rf_scan.HackRFCapture()], sample_rate=1e6)
        assert fake_hackrf.arg("-s") == "2000000"
        assert float(uploads.header("X-Sample-Rate")) == 2e6
        assert uploads.header("X-IQ-Samples") == "200000"  # 100 ms at 2 MHz

    def test_default_rate_is_applied_not_just_reported(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF, uploads: _Uploads
    ) -> None:
        assert _run(rf_scan, [rf_scan.HackRFCapture()])  # no sample_rate/gain
        assert fake_hackrf.arg("-s") == "2400000"
        assert float(uploads.header("X-Sample-Rate")) == 2.4e6
        assert (fake_hackrf.arg("-l"), fake_hackrf.arg("-g")) == ("40", "48")

    def test_rtl_tcp_rate_and_gain(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP, uploads: _Uploads
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        del fake_rtl.sent[:]
        fake_rtl.arrive(1001)
        assert _run(rf_scan, [client], sample_rate=2.4e6, gain_db=40)
        cmds = fake_rtl.commands()
        assert cmds[0] == (0x01, 915_000_000)
        assert cmds[1:4] == [(0x02, 2_400_000), (0x03, 1), (0x04, 400)]
        assert cmds[4:] == [(0x02, 2_048_000), (0x03, 0)]
        assert float(uploads.header("X-Sample-Rate")) == 2.4e6
        assert uploads.header("X-IQ-Samples") == "240000"
        data = np.frombuffer(
            gzip.decompress(uploads.requests[-1].data), dtype=np.float32
        )
        np.testing.assert_allclose(data[0::2], _I_VAL, atol=1e-6)
        np.testing.assert_allclose(data[1::2], _Q_VAL, atol=1e-6)

    def test_rtl_tcp_unsupported_rate_reports_device_rate(
        self, rf_scan: ModuleType, fake_rtl: FakeRTLTCP, uploads: _Uploads
    ) -> None:
        client = rf_scan.RTLTCPClient()
        assert client.connect()
        assert _run(rf_scan, [client], sample_rate=10e6)
        assert float(uploads.header("X-Sample-Rate")) == 2_048_000.0
        assert uploads.header("X-IQ-Samples") == "204800"

    def test_rejected_command_does_not_touch_the_device(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF, uploads: _Uploads
    ) -> None:
        assert not _run(rf_scan, [rf_scan.HackRFCapture()], gain_db=-3)
        assert fake_hackrf.argv == [] and uploads.requests == []


class TestParseGain:
    def test_gain_optional(self, rf_scan: ModuleType) -> None:
        assert rf_scan.parse_iq_capture_command({"freq_hz": 915e6})["gain_db"] is None
        p = rf_scan.parse_iq_capture_command({"freq_hz": 915e6, "gain_db": 40})
        assert p["gain_db"] == 40.0

    @pytest.mark.parametrize("gain", [-1, 103, float("nan"), "40", True, [1]])
    def test_bad_gain_rejected(self, rf_scan: ModuleType, gain: object) -> None:
        # 102 dB is the HackRF LNA+VGA ceiling; anything above it is rejected.
        with pytest.raises(ValueError):
            rf_scan.parse_iq_capture_command({"freq_hz": 915e6, "gain_db": gain})


# ---------------------------------------------------------------------------
# D9: anomaly / low-confidence IQ staged by the reporter carries the rate
# ---------------------------------------------------------------------------


class _Engine:
    avg_cls_per_sec = 1.0

    def classify(self, _iq):
        return {"class": "fm", "confidence": 0.3, "family": "analog"}


class _NewReporter:
    def __init__(self) -> None:
        self.kwargs: dict = {}

    def report(
        self,
        *,
        classification,
        freq_hz,
        snr_db,
        power_dbm,
        iq_data=None,
        decoded_messages=None,
        sample_rate=None,
    ):
        self.kwargs = {"sample_rate": sample_rate}
        return True


class _OldReporter:
    """A standalone detection_reporter.py from before sample_rate existed."""

    def __init__(self) -> None:
        self.called = False

    def report(
        self,
        *,
        classification,
        freq_hz,
        snr_db,
        power_dbm,
        iq_data=None,
        decoded_messages=None,
    ):
        self.called = True
        return True


class TestReporterSampleRate:
    def test_scan_passes_the_device_rate(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        rep = _NewReporter()
        rf_scan.scan_frequency(rf_scan.HackRFCapture(), 915_000_000, _Engine(), rep)
        assert rep.kwargs["sample_rate"] == 2e6

    def test_older_reporter_still_works(
        self, rf_scan: ModuleType, fake_hackrf: FakeHackRF
    ) -> None:
        rep = _OldReporter()
        rf_scan.scan_frequency(rf_scan.HackRFCapture(), 915_000_000, _Engine(), rep)
        assert rep.called

    def test_reporter_sends_x_sample_rate(self, monkeypatch) -> None:
        import sigrift.edge.detection_reporter as edge_reporter

        reporter = edge_reporter.DetectionReporter(
            server_url="https://bridge.test",
            api_key="k",
            node_id="n1",
            min_confidence=0.1,
            min_snr_db=0.0,
            iq_capture=True,
            iq_capture_low_confidence=0.5,
        )
        sent = []

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def fake_urlopen(req, context=None, timeout=None):
            sent.append(dict(req.header_items()))
            return _Resp()

        monkeypatch.setattr(edge_reporter.urllib.request, "urlopen", fake_urlopen)
        iq = np.ones(16, dtype=np.complex64)
        common = dict(snr_db=10.0, power_dbm=-50.0, iq_data=iq)
        cls = {"class": "fm", "confidence": 0.3}
        assert reporter.report(cls, 915e6, sample_rate=2e6, **common)
        assert reporter.report({**cls, "class": "am"}, 433e6, **common)  # rate unknown
        reporter._upload_iq_captures()
        assert sent[0]["X-sample-rate"] == "2000000.0"
        assert "X-sample-rate" not in sent[1]
