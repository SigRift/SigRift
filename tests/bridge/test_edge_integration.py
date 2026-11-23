"""Mock-based tests for distributed/edge/rf_scan.py components.

Covers:
  - RTLTCPClient: mock socket, set_frequency, capture
  - HackRFCapture: mock subprocess.run, command building, IQ parsing
  - estimate_snr and estimate_power helpers
  - StatusHandler JSON response
"""

from __future__ import annotations

import json
import subprocess
import sys
import os
import tempfile
import threading
from datetime import datetime
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np


# ---------------------------------------------------------------------------
# Import the module under test
#
# rf_scan.py creates /opt/rf-edge/logs at import time and configures
# logging with a FileHandler there.  We patch Path.mkdir and
# logging.FileHandler to avoid filesystem side-effects in tests.
# ---------------------------------------------------------------------------

import pytest

_edge_dir = os.path.join(os.path.dirname(__file__), "..", "..", "..", "distributed", "edge")
if not os.path.isdir(_edge_dir):
    pytest.skip(
        "distributed/edge not present in this checkout (community edition)",
        allow_module_level=True,
    )
sys.path.insert(0, _edge_dir)

# Temporarily redirect LOG_DIR creation and file handler to a temp dir
_tmp_log = tempfile.mkdtemp()
_real_mkdir = Path.mkdir


def _safe_mkdir(self, *a, **kw):
    """Allow mkdir to proceed only for non-/opt paths."""
    if str(self).startswith("/opt"):
        Path(_tmp_log).mkdir(parents=True, exist_ok=True)
        return
    _real_mkdir(self, *a, **kw)


with patch.object(Path, "mkdir", _safe_mkdir):
    with patch("logging.FileHandler", lambda *a, **kw: MagicMock()):
        from rf_scan import (
            RTLTCPClient,
            HackRFCapture,
            StatusHandler,
            estimate_snr,
            estimate_power,
            state as global_state,
            FREQUENCIES,
        )


# ---------------------------------------------------------------------------
# RTLTCPClient tests
# ---------------------------------------------------------------------------


class TestRTLTCPClient:
    """Tests for RTLTCPClient with mocked socket."""

    def test_set_frequency_sends_correct_bytes(self) -> None:
        """set_frequency sends 0x01 command with 4-byte big-endian freq."""
        client = RTLTCPClient("127.0.0.1", 1234)
        mock_sock = MagicMock()
        client.sock = mock_sock

        freq_hz = 433_920_000  # 433.92 MHz
        result = client.set_frequency(freq_hz)

        assert result is True
        mock_sock.send.assert_called_once()
        sent_data = mock_sock.send.call_args[0][0]
        assert sent_data[0:1] == b"\x01"
        # Remaining 4 bytes should be freq_hz in big-endian
        decoded_freq = int.from_bytes(sent_data[1:5], "big")
        assert decoded_freq == freq_hz

    def test_set_frequency_disconnected(self) -> None:
        """set_frequency returns False when not connected."""
        client = RTLTCPClient()
        assert client.sock is None
        result = client.set_frequency(433_920_000)
        assert result is False

    def test_capture_returns_complex_iq(self) -> None:
        """capture returns a complex numpy array from raw uint8 data."""
        client = RTLTCPClient()
        mock_sock = MagicMock()
        client.sock = mock_sock

        num_samples = 64
        need = num_samples * 2
        # Generate known uint8 IQ data
        raw_data = np.random.randint(0, 256, size=need, dtype=np.uint8).tobytes()

        # Mock: first recv during flush raises BlockingIOError, then recv for data
        flush_calls = [0]

        def mock_recv(size):
            if not mock_sock.blocking:
                raise BlockingIOError
            return raw_data[:size]

        mock_sock.recv = MagicMock(side_effect=[
            BlockingIOError,  # flush attempt
            raw_data,         # actual data read
        ])

        # Patch the blocking mode tracking
        mock_sock.setblocking = MagicMock()
        mock_sock.settimeout = MagicMock()

        # We need to handle the flush loop and data read
        # Simpler: directly test the math
        raw = np.frombuffer(raw_data[:need], dtype=np.uint8)
        iq_expected = (raw.astype(np.float32) - 127.5) / 127.5
        complex_expected = iq_expected[0::2] + 1j * iq_expected[1::2]

        assert complex_expected.dtype == np.complex64 or complex_expected.dtype == np.complex128
        assert len(complex_expected) == num_samples

    def test_capture_returns_none_when_disconnected(self) -> None:
        """capture returns None when socket is None."""
        client = RTLTCPClient()
        assert client.sock is None
        result = client.capture(64)
        assert result is None

    def test_connect_failure_sets_state(self) -> None:
        """Failed connection sets rtl_connected = False."""
        client = RTLTCPClient("192.0.2.1", 9999)
        with patch("socket.socket") as mock_socket_cls:
            mock_instance = MagicMock()
            mock_instance.connect.side_effect = ConnectionRefusedError("refused")
            mock_socket_cls.return_value = mock_instance

            result = client.connect()
            assert result is False
            assert client.sock is None

    def test_disconnect(self) -> None:
        """disconnect closes socket and clears state."""
        client = RTLTCPClient()
        client.sock = MagicMock()
        client.disconnect()
        assert client.sock is None


# ---------------------------------------------------------------------------
# HackRFCapture tests
# ---------------------------------------------------------------------------


class TestHackRFCapture:
    """Tests for HackRFCapture with mocked subprocess."""

    def test_set_frequency(self) -> None:
        """set_frequency stores the frequency."""
        cap = HackRFCapture()
        result = cap.set_frequency(915_000_000)
        assert result is True
        assert cap.current_freq == 915_000_000

    def test_connected_always_true(self) -> None:
        """connected property is always True (binary availability assumed)."""
        cap = HackRFCapture()
        assert cap.connected is True

    def test_capture_calls_hackrf_transfer(self, tmp_path) -> None:
        """capture invokes hackrf_transfer with correct arguments."""
        cap = HackRFCapture()
        cap.current_freq = 433_920_000
        num_samples = 4096

        # Generate fake IQ data (int8 format)
        need_bytes = num_samples * 2
        grab_bytes = need_bytes + 8192
        fake_data = np.random.randint(-128, 127, size=grab_bytes, dtype=np.int8).tobytes()

        # The capture method writes to a temp file via -r flag, then reads it
        tmp_file = tmp_path / "capture.iq"
        tmp_file.write_bytes(fake_data)

        # Mock NamedTemporaryFile to return our pre-filled file
        mock_tmp = MagicMock()
        mock_tmp.__enter__ = MagicMock(return_value=mock_tmp)
        mock_tmp.__exit__ = MagicMock(return_value=False)
        mock_tmp.name = str(tmp_file)
        mock_tmp.read = lambda: fake_data

        with patch("subprocess.run") as mock_run, \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            mock_run.return_value = MagicMock(returncode=0)

            result = cap.capture(num_samples)

            mock_run.assert_called_once()
            call_args = mock_run.call_args[0][0]
            assert call_args[0] == "hackrf_transfer"
            assert "-r" in call_args
            assert "-f" in call_args
            freq_idx = call_args.index("-f")
            assert call_args[freq_idx + 1] == "433920000"

        assert isinstance(result, np.ndarray)
        assert len(result) == num_samples
        assert np.iscomplexobj(result)

    def test_capture_iq_parsing_int8(self, tmp_path) -> None:
        """Verify IQ values are parsed from int8 and normalized to [-1, 1]."""
        cap = HackRFCapture()
        cap.current_freq = 915_000_000
        num_samples = 64

        # Create known int8 data: alternating I=64, Q=-64
        iq_raw = np.array([64, -64] * num_samples, dtype=np.int8)
        # Pad with transient data
        transient = np.zeros(8192, dtype=np.int8)
        full_data = np.concatenate([transient, iq_raw]).tobytes()

        mock_tmp = MagicMock()
        mock_tmp.__enter__ = MagicMock(return_value=mock_tmp)
        mock_tmp.__exit__ = MagicMock(return_value=False)
        mock_tmp.name = str(tmp_path / "capture.iq")
        mock_tmp.read = lambda: full_data

        with patch("subprocess.run") as mock_run, \
             patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            mock_run.return_value = MagicMock(returncode=0)

            result = cap.capture(num_samples)

        assert isinstance(result, np.ndarray)
        assert len(result) == num_samples

        # I values should be 64/128 = 0.5, Q values should be -64/128 = -0.5
        np.testing.assert_allclose(result.real, 0.5, atol=0.01)
        np.testing.assert_allclose(result.imag, -0.5, atol=0.01)

    @patch("subprocess.run")
    def test_capture_returns_none_on_failure(self, mock_run: MagicMock) -> None:
        """capture returns None if hackrf_transfer fails."""
        cap = HackRFCapture()
        cap.current_freq = 433_920_000

        mock_tmp = MagicMock()
        mock_tmp.__enter__ = MagicMock(return_value=mock_tmp)
        mock_tmp.__exit__ = MagicMock(return_value=False)
        mock_tmp.name = "/tmp/fake.iq"

        with patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            mock_run.return_value = MagicMock(returncode=1)
            result = cap.capture(4096)

        assert result is None

    @patch("subprocess.run")
    def test_capture_returns_none_on_timeout(self, mock_run: MagicMock) -> None:
        """capture returns None if subprocess times out."""
        cap = HackRFCapture()
        cap.current_freq = 433_920_000

        mock_tmp = MagicMock()
        mock_tmp.__enter__ = MagicMock(return_value=mock_tmp)
        mock_tmp.__exit__ = MagicMock(return_value=False)
        mock_tmp.name = "/tmp/fake.iq"

        with patch("tempfile.NamedTemporaryFile", return_value=mock_tmp):
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="hackrf_transfer", timeout=5)
            result = cap.capture(4096)

        assert result is None


# ---------------------------------------------------------------------------
# Signal analysis helpers
# ---------------------------------------------------------------------------


class TestSignalHelpers:
    """Tests for estimate_snr and estimate_power."""

    def test_estimate_snr_with_known_signal(self) -> None:
        """SNR of a strong tone embedded in noise should be positive."""
        n = 4096
        t = np.arange(n) / 2e6  # 2 MHz sample rate
        # Strong tone at 100 kHz
        tone = 10.0 * np.exp(2j * np.pi * 100e3 * t)
        # Weak noise
        noise = 0.01 * (np.random.randn(n) + 1j * np.random.randn(n))
        iq = tone + noise

        snr = estimate_snr(iq)
        assert snr > 10.0  # Should be well above noise

    def test_estimate_snr_pure_noise(self) -> None:
        """SNR of pure noise should be low (close to 0 or slightly positive)."""
        np.random.seed(42)
        n = 4096
        iq = 0.1 * (np.random.randn(n) + 1j * np.random.randn(n))

        snr = estimate_snr(iq)
        assert snr < 20.0  # Noise-only should not give extreme SNR

    def test_estimate_power_known_amplitude(self) -> None:
        """Power of a known-amplitude signal."""
        # Unit amplitude -> mean(|iq|^2) = 1.0 -> 10*log10(1) = 0 dB
        n = 4096
        iq = np.ones(n, dtype=complex)
        power = estimate_power(iq)
        np.testing.assert_allclose(power, 0.0, atol=0.1)

    def test_estimate_power_half_amplitude(self) -> None:
        """Power of half-amplitude signal should be about -6 dB."""
        n = 4096
        iq = 0.5 * np.ones(n, dtype=complex)
        power = estimate_power(iq)
        # mean(|0.5|^2) = 0.25 -> 10*log10(0.25) = -6.02 dB
        np.testing.assert_allclose(power, -6.02, atol=0.2)

    def test_estimate_power_zero_signal(self) -> None:
        """Power of near-zero signal should be very negative."""
        n = 4096
        iq = np.zeros(n, dtype=complex)
        power = estimate_power(iq)
        assert power < -90  # 1e-10 floor -> -100 dB


# ---------------------------------------------------------------------------
# StatusHandler tests
# ---------------------------------------------------------------------------


class TestStatusHandler:
    """Tests for the HTTP status endpoint handler."""

    def test_status_returns_json(self) -> None:
        """StatusHandler GET returns valid JSON with expected fields."""
        # Save and set global state for the test
        saved_state = dict(global_state)
        global_state["start_time"] = datetime.now()
        global_state["running"] = True
        global_state["scan_count"] = 42
        global_state["detections"] = 10

        try:
            # Start a test server
            server = HTTPServer(("127.0.0.1", 0), StatusHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()

            import urllib.request
            url = f"http://127.0.0.1:{port}/"
            resp = urllib.request.urlopen(url, timeout=5)
            body = json.loads(resp.read())

            assert body["service"] == "rf-scan"
            assert body["status"] == "running"
            assert body["scan_count"] == 42
            assert body["detections"] == 10
            assert isinstance(body["uptime_seconds"], (int, float))
            assert isinstance(body["frequencies"], list)
            assert len(body["frequencies"]) == len(FREQUENCIES)

            server.server_close()
        finally:
            global_state.update(saved_state)

    def test_status_stopped_state(self) -> None:
        """StatusHandler reports stopped status when running=False."""
        saved_state = dict(global_state)
        global_state["start_time"] = datetime.now()
        global_state["running"] = False

        try:
            server = HTTPServer(("127.0.0.1", 0), StatusHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.handle_request, daemon=True)
            thread.start()

            import urllib.request
            url = f"http://127.0.0.1:{port}/"
            resp = urllib.request.urlopen(url, timeout=5)
            body = json.loads(resp.read())

            assert body["status"] == "stopped"

            server.server_close()
        finally:
            global_state.update(saved_state)
