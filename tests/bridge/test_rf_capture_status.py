"""Real TCP reset/recovery and public status; no physical-radio claims."""

import importlib
import json
import logging
import socket
import struct
import threading
import time
import urllib.request
from datetime import datetime
from http.server import ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from sigrift.edge.scanner_status import CaptureActivity


@pytest.fixture
def rf(tmp_path, monkeypatch):
    monkeypatch.setenv("MLRF_LOG_DIR", str(tmp_path))
    value = importlib.import_module("sigrift.edge.rf_scan")
    monkeypatch.setattr(value, "state", dict(value.state))
    value.state.update(last_error=None, last_successful_capture=None, start_time=None)
    monkeypatch.setattr(value, "DWELL_TIME", 0)
    monkeypatch.setattr(value, "try_edge_decode", lambda *_: [])
    return value


@pytest.fixture
def status(rf):
    server = ThreadingHTTPServer(("127.0.0.1", 0), rf.StatusHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

    def read():
        with urllib.request.urlopen(
            f"http://127.0.0.1:{server.server_port}", timeout=2
        ) as response:
            return json.load(response)

    try:
        yield read
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def test_actual_rtl_reset_then_reconnect_never_claims_capture_until_valid_iq(
    rf, status
):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(3)
    done, errors = threading.Event(), []

    def peer():
        try:
            for attempt in range(2):
                with listener.accept()[0] as conn:
                    conn.settimeout(3)
                    conn.sendall(b"RTL0" + struct.pack(">II", 5, 29))
                    commands = b""
                    while len(commands) < 10:
                        chunk = conn.recv(10 - len(commands))
                        assert chunk, "client closed before actual rate/tune commands"
                        commands += chunk
                    assert struct.unpack(">BI", commands[:5]) == (2, 2048000)
                    assert struct.unpack(">BI", commands[5:]) == (1, 915000000)
                    if attempt == 0:
                        conn.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                        )
                    else:
                        # Keep producing samples across the real nonblocking
                        # stale-buffer drain; no socket or capture mocks.
                        while not done.is_set():
                            conn.sendall(bytes([200, 50]) * 8192)
                            done.wait(0.005)
        except (BrokenPipeError, ConnectionResetError):
            if not done.is_set():
                errors.append("unexpected peer disconnect")
        except Exception as error:
            if not done.is_set():
                errors.append(type(error).__name__)

    thread = threading.Thread(target=peer)
    thread.start()
    client = rf.RTLTCPClient("127.0.0.1", listener.getsockname()[1])
    activity = CaptureActivity()
    classified = []
    engine = SimpleNamespace(
        avg_cls_per_sec=1,
        classify=lambda iq: classified.append(iq) or {"class": "noise"},
    )
    reporter = SimpleNamespace(report=lambda **_: False)
    try:
        assert not rf.scan_frequency(client, 915000000, engine, reporter, activity)
        assert not client.connected and not classified
        failed = status()
        assert failed["last_error"] == "capture_failed"
        assert failed["last_successful_capture"] is None
        assert activity.state() == "error"
        assert client.connect()
        assert status()["rtl_connected"] is True
        assert status()["last_error"] == "capture_failed"
        assert activity.state() == "error", "TCP handshake is not successful capture"
        assert not rf.scan_frequency(client, 915000000, engine, reporter, activity)
        # Filtered/quiet capture still proves work, independently of an upload.
        assert len(classified) == 1 and classified[0].shape == (2, rf.INPUT_SAMPLES)
        healthy = status()
        assert healthy["last_error"] is None
        assert (
            datetime.fromisoformat(healthy["last_successful_capture"]).tzinfo
            is not None
        )
        assert activity.state() == "running"
    finally:
        done.set()
        client.disconnect()
        listener.close()
        thread.join(4)
        assert not thread.is_alive()
        assert not errors


def test_unavailable_connection_reports_category_and_keeps_last_capture(rf, status):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    previous = "2026-11-08T00:00:00+00:00"
    rf.state["last_successful_capture"] = previous
    activity = CaptureActivity()
    activity.succeeded()
    client = rf.RTLTCPClient("127.0.0.1", port)
    assert not rf.scan_frequency(client, 915000000, None, None, activity)
    current = status()
    assert current["last_error"] == "connection_failed"
    assert current["last_successful_capture"] == previous
    assert activity.state() == "error"


# --- receiver away: reason, one log line per transition, automatic resume ----


@pytest.fixture
def state_port():
    """A fake rtl-tcp supervisor state port; set ``answer[0]`` to change it."""
    answer = [b"sensor_absent\n"]
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    done = threading.Event()

    def serve():
        while not done.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.sendall(answer[0])

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], answer
    finally:
        done.set()
        thread.join(2)
        listener.close()


def closed_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@pytest.mark.parametrize(
    "answer, reason",
    [
        (b"sensor_absent\n", "sensor_absent"),
        (b"sensor_changed\n", "sensor_changed"),
        (b"sensor_unusable\n", "sensor_unusable"),
        (b"capture_failed\n", "capture_failed"),
        (b"starting\n", "capture_failed"),
        (b"running\n", "capture_failed"),
        (b"PRIVATE serial 1234\n", "capture_failed"),
        (b"", "capture_failed"),
    ],
)
def test_unreachable_rtl_tcp_reports_the_supervisor_reason(
    rf, state_port, answer, reason
):
    port, current = state_port
    current[0] = answer
    activity = CaptureActivity()
    assert activity.status() == ("error", "starting")
    client = rf.RTLTCPClient("127.0.0.1", closed_port(), status_port=port)
    assert not rf.scan_frequency(client, 915000000, None, None, activity)
    assert activity.status() == ("error", reason)


def test_no_supervisor_means_capture_failed(rf):
    activity = CaptureActivity()
    client = rf.RTLTCPClient("127.0.0.1", closed_port(), status_port=closed_port())
    assert not rf.scan_frequency(client, 915000000, None, None, activity)
    assert activity.status() == ("error", "capture_failed")


def test_reconnection_waits_instead_of_trying_every_frequency(rf, state_port):
    client = rf.RTLTCPClient("127.0.0.1", closed_port(), status_port=state_port[0])
    attempts = []
    connect = client.connect
    client.connect = lambda: attempts.append(1) or connect()
    activity = CaptureActivity()
    for _ in range(100):  # one sweep's worth of frequencies
        rf.scan_frequency(client, 915000000, None, None, activity)
    assert len(attempts) == 1
    assert 4 < client.retry_in() <= rf.RTL_RETRY_SECONDS
    assert activity.status() == ("error", "sensor_absent")


def test_outage_logs_once_and_capture_resumes_by_itself(rf, state_port, caplog):
    caplog.set_level(logging.INFO, logger="rf_scan")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        rtl_port = probe.getsockname()[1]
    client = rf.RTLTCPClient("127.0.0.1", rtl_port, status_port=state_port[0])
    client.retry_interval = 0.05
    activity = CaptureActivity()
    engine = SimpleNamespace(avg_cls_per_sec=1, classify=lambda iq: {"class": "noise"})
    reporter = SimpleNamespace(report=lambda **_: False)
    deadline = time.monotonic() + 0.6
    while time.monotonic() < deadline:  # many attempts, receiver away
        rf.scan_frequency(client, 915000000, engine, reporter, activity)
        time.sleep(0.01)
    assert activity.status() == ("error", "sensor_absent")
    state_port[1][0] = b"sensor_changed\n"  # a different receiver was plugged in
    time.sleep(0.06)
    rf.scan_frequency(client, 915000000, engine, reporter, activity)
    assert activity.status() == ("error", "sensor_changed")

    # rtl_tcp comes back on the same port: capture resumes, no operator action.
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", rtl_port))
    listener.listen(1)
    done = threading.Event()

    def peer():
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"RTL0" + struct.pack(">II", 5, 29))
            try:
                while not done.is_set():
                    conn.sendall(bytes([200, 50]) * 8192)
                    done.wait(0.005)
            except OSError:
                pass

    thread = threading.Thread(target=peer, daemon=True)
    thread.start()
    try:
        time.sleep(0.06)
        assert wait_until(
            lambda: rf.scan_frequency(client, 915000000, engine, reporter, activity)
            is False
            and activity.state() == "running"
        )
        assert client.unavailable_reason is None
    finally:
        done.set()
        client.disconnect()
        listener.close()
        thread.join(3)
    text = [r.getMessage() for r in caplog.records]
    assert len([m for m in text if " unavailable (connect failed" in m]) == 1
    assert (
        len([m for m in text if "still unavailable (receiver: sensor_changed)" in m])
        == 1
    )
    assert len([m for m in text if "capture resumed" in m]) == 1
    assert not [m for m in text if "connect failed" in m and "unavailable" not in m]


@pytest.fixture
def closing_rtl_tcp():
    """rtl_tcp that accepts, sends its header, then drops every client."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    done = threading.Event()

    def serve():
        while not done.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.settimeout(2)
                try:
                    conn.sendall(b"RTL0" + struct.pack(">II", 5, 29))
                    conn.recv(5)  # the rate command: connect() has finished
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        done.set()
        thread.join(2)
        listener.close()


@pytest.mark.parametrize("failure", ["connect", "capture"])
def test_outage_logs_again_only_when_the_reason_changes(
    rf, state_port, closing_rtl_tcp, caplog, failure
):
    caplog.set_level(logging.INFO, logger="rf_scan")
    rtl_port = closed_port() if failure == "connect" else closing_rtl_tcp
    client = rf.RTLTCPClient("127.0.0.1", rtl_port, status_port=state_port[0])
    client.retry_interval = 0  # every call tries again
    activity = CaptureActivity()
    attempts = []
    connect = client.connect
    client.connect = lambda: attempts.append(1) or connect()

    def fail_several_times():
        for _ in range(4):
            assert not rf.scan_frequency(client, 915000000, None, None, activity)

    def warnings():
        return [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.WARNING and "unavailable" in r.getMessage()
        ]

    fail_several_times()
    assert len(attempts) == 4
    assert len(warnings()) == 1
    assert activity.status() == ("error", "sensor_absent")
    state_port[1][0] = b"sensor_unusable\n"
    fail_several_times()
    assert len(attempts) == 8
    assert len(warnings()) == 2
    assert warnings()[1].endswith("still unavailable (receiver: sensor_unusable)")
    assert activity.status() == ("error", "sensor_unusable")


def wait_until(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False
