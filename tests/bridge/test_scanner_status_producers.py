"""Actual transport and capture-boundary checks; no physical-radio claims."""

import importlib
import json
import logging
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import numpy as np
import pytest

from sigrift.edge import scanner_status as edge_status
from sigrift.edge.scanner_status import CaptureActivity, ScannerStatusReporter

# Several tests wait for reporter threads, scan loops and helper processes with
# generous limits below. The project default of 30 s per test (pyproject.toml)
# is too short for them on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)
# A state that must be REACHED; the polls return as soon as it is.
WAIT = 60.0
# Waits for a helper process or thread to end; they return as soon as it has.
REAP = 30.0
# The product allows 3 s per status request. The test servers run in the test
# process and can take longer to answer on a loaded runner; tests that do not
# test that limit lengthen it.
REQUEST_TIMEOUT = 20.0
PRODUCT_REQUEST_TIMEOUT = edge_status._REQUEST_TIMEOUT


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(edge_status, "_REQUEST_TIMEOUT", REQUEST_TIMEOUT)
    observations = []
    status = [200]

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            observations.append(
                (
                    self.path,
                    self.headers.get("X-API-Key"),
                    json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                )
            )
            self.send_response(status[0])
            self.send_header("Location", "http://127.0.0.1:1/private-marker")
            self.end_headers()
            self.wfile.write(b"PRIVATE-RESPONSE-MARKER")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", observations, status
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=REAP)


def make_reporter(url, **kwargs):
    return ScannerStatusReporter(
        url,
        "owned-node",
        "wifi",
        ssl.create_default_context,
        lambda: {"X-API-Key": "PRIVATE-KEY-MARKER"},
        lambda: "running",
        **kwargs,
    )


@pytest.mark.parametrize("state", ["running", "stopped", "error"])
def test_actual_transport_only_fixed_body(endpoint, state):
    url, observed, _ = endpoint
    reporter = make_reporter(url)
    assert reporter.report(state)
    assert observed == [
        (
            "/api/nodes/owned-node/scanner-status",
            "PRIVATE-KEY-MARKER",
            {"protocol": "wifi", "state": state},
        )
    ]


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 404, 429, 500])
def test_errors_and_redirects_are_single_shot_and_private(endpoint, status, caplog):
    url, observed, statuses = endpoint
    statuses[0] = status
    with caplog.at_level(logging.WARNING):
        assert not make_reporter(url).report("running")
    assert len(observed) == 1
    assert "PRIVATE" not in caplog.text
    assert url not in caplog.text
    assert str(status) in caplog.text


def test_context_precedes_auth_and_failure_never_sends(endpoint, caplog):
    url, observed, _ = endpoint
    order = []

    def context():
        order.append("tls")
        raise ValueError("PRIVATE-CERT-MARKER")

    def headers():
        order.append("auth")
        return {}

    reporter = ScannerStatusReporter(
        url, "owned-node", "sdr", context, headers, lambda: "running"
    )
    assert not reporter.report("running")
    assert order == ["tls"]
    assert observed == []
    assert "PRIVATE" not in caplog.text


def test_transport_failure_is_private_and_not_retried(caplog):
    # Bind then close a real port so the request exercises urllib's connect failure.
    import socket

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    assert not make_reporter(f"http://127.0.0.1:{port}").report("running")
    assert "transport" in caplog.text
    assert "PRIVATE" not in caplog.text


def test_lifecycle_callback_and_final_state(endpoint):
    url, observed, _ = endpoint
    reporter = make_reporter(url, interval=0.02)
    reporter.start()
    reporter.start()  # Idempotent: no duplicate workers.
    deadline = time.monotonic() + WAIT
    while not observed and time.monotonic() < deadline:
        time.sleep(0.005)
    assert observed
    reporter.stop("error")
    count = len(observed)
    time.sleep(0.04)
    assert len(observed) == count
    assert observed[-1][2]["state"] == "error"
    assert not reporter._thread.is_alive()


def test_callback_exception_reports_only_error(endpoint, caplog):
    url, observed, _ = endpoint

    def broken():
        raise RuntimeError("PRIVATE-DEVICE-MARKER")

    reporter = ScannerStatusReporter(
        url,
        "owned-node",
        "wifi",
        ssl.create_default_context,
        lambda: {},
        broken,
        interval=0.02,
    )
    reporter.start()
    deadline = time.monotonic() + WAIT
    while not observed and time.monotonic() < deadline:
        time.sleep(0.005)
    assert observed  # Stopping earlier would test only the final report.
    reporter.stop()
    assert observed[0][2]["state"] == "error"
    assert observed[-1][2]["state"] == "stopped"
    assert "PRIVATE" not in caplog.text


def test_capture_activity_never_infers_work_from_startup_or_old_progress(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("sigrift.edge.scanner_status.time.monotonic", lambda: clock[0])
    activity = CaptureActivity()
    assert activity.state() == "error"
    activity.succeeded()
    assert activity.state() == "running"
    clock[0] += 60
    assert activity.state() == "error"
    activity.succeeded()
    activity.failed()
    assert activity.state() == "error"


@pytest.fixture
def rf(tmp_path, monkeypatch):
    monkeypatch.setenv("MLRF_LOG_DIR", str(tmp_path))
    module = importlib.import_module("sigrift.edge.rf_scan")
    monkeypatch.setattr(module, "try_edge_decode", lambda *_args: [])
    monkeypatch.setattr(module, "state", dict(module.state))
    return module


@pytest.mark.parametrize("accepted", [True, False])
def test_rf_valid_iq_classification_is_activity_even_without_detection(rf, accepted):
    activity = CaptureActivity()
    iq = np.exp(1j * np.arange(8192) * 0.3).astype(np.complex64)
    sdr = SimpleNamespace(
        connected=True, set_frequency=lambda _: True, capture=lambda _: iq
    )
    engine = SimpleNamespace(classify=lambda _: {"class": "noise"}, avg_cls_per_sec=1.0)
    reporter = SimpleNamespace(report=lambda **_: accepted)
    assert rf.scan_frequency(sdr, 915000000, engine, reporter, activity) is accepted
    assert activity.state() == "running"


@pytest.mark.parametrize("failure", ["disconnect", "capture"])
def test_rf_capture_failures_clear_previous_activity(rf, failure):
    activity = CaptureActivity()
    activity.succeeded()
    sdr = SimpleNamespace(
        connected=failure != "disconnect",
        connect=lambda: False,
        set_frequency=lambda _: True,
        capture=lambda _: None,
    )
    assert not rf.scan_frequency(sdr, 915000000, None, None, activity)
    assert activity.state() == "error"


@pytest.fixture
def wifi():
    return importlib.import_module("sigrift.edge.wifi_scan")


def test_wifi_empty_air_requires_real_pcap_reader_and_live_process(wifi):
    # A real child emits a radiotap pcap header, then blocks without packets.
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 512, 127)
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys,time;sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]));sys.stdout.buffer.flush();time.sleep(30)",
            header.hex(),
        ],
        stdout=subprocess.PIPE,
    )
    scanner = wifi.WifiScanner("unused-test-interface")
    scanner._proc = child
    scanner._running = True
    scanner._last_channel_success = time.monotonic()
    hop_done = threading.Event()
    scanner._hop_thread = threading.Thread(target=hop_done.wait, daemon=True)
    scanner._hop_thread.start()
    reader = threading.Thread(target=lambda: list(scanner.read_frames()), daemon=True)
    assert scanner.capture_state() == "error"
    reader.start()
    try:
        deadline = time.monotonic() + WAIT
        while scanner.capture_state() != "running" and time.monotonic() < deadline:
            # The stand-in hop thread keeps hopping successfully meanwhile.
            scanner._last_channel_success = time.monotonic()
            time.sleep(0.005)
        assert scanner.capture_state() == "running"
        assert len(scanner._pcap_ring) == 0
        child.terminate()
        child.wait(timeout=REAP)
        reader.join(timeout=REAP)
        assert not reader.is_alive()
        assert scanner.capture_state() == "error"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=REAP)
        child.stdout.close()
        hop_done.set()
        scanner._hop_thread.join(timeout=REAP)
        reader.join(timeout=REAP)


@pytest.mark.parametrize(
    "header",
    [b"", b"broken-header", struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 512, 1)],
)
def test_wifi_bad_or_wrong_format_never_reports_capture(wifi, header):
    import io

    scanner = wifi.WifiScanner("unused-test-interface")
    scanner._running = True
    scanner._proc = SimpleNamespace(stdout=io.BytesIO(header), poll=lambda: None)
    assert list(scanner.read_frames()) == []
    assert scanner.capture_state() == "error"


@pytest.mark.parametrize("status", [201, 202, 204])
def test_unexpected_success_status_is_not_acknowledgement(endpoint, status):
    url, observed, statuses = endpoint
    statuses[0] = status
    assert not make_reporter(url).report("running")
    assert len(observed) == 1


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/private",
        "https:///missing-host",
        "https://key:secret@example.invalid",
        "https://example.invalid?token=private",
        "https://example.invalid#private",
    ],
)
def test_unsafe_destination_rejected(url):
    with pytest.raises(ValueError, match="destination"):
        make_reporter(url)


@pytest.mark.parametrize(
    "protocol,interval",
    [("invented", 30), ("wifi", 0), ("wifi", 31), ("wifi", float("nan"))],
)
def test_invalid_reporter_configuration_rejected(protocol, interval):
    with pytest.raises(ValueError, match="configuration"):
        ScannerStatusReporter(
            "https://example.invalid",
            "node",
            protocol,
            ssl.create_default_context,
            lambda: {},
            lambda: "running",
            interval=interval,
        )


def test_empty_node_and_invalid_states_cannot_send(endpoint):
    url, observed, _ = endpoint
    with pytest.raises(ValueError, match="destination"):
        ScannerStatusReporter(
            url, "", "wifi", ssl.create_default_context, lambda: {}, lambda: "running"
        )
    reporter = make_reporter(url)
    with pytest.raises(ValueError, match="state"):
        reporter.report("invented")
    with pytest.raises(ValueError, match="final"):
        reporter.stop("running")
    reporter.stop()
    assert observed == []


def test_invalid_callback_value_is_not_transmitted(endpoint):
    url, observed, _ = endpoint
    reporter = ScannerStatusReporter(
        url,
        "owned-node",
        "wifi",
        ssl.create_default_context,
        lambda: {},
        lambda: "PRIVATE-INVALID",
        interval=0.02,
    )
    reporter.start()
    deadline = time.monotonic() + WAIT
    while not observed and time.monotonic() < deadline:
        time.sleep(0.005)
    assert observed  # Stopping earlier would test only the final report.
    reporter.stop()
    assert observed[0][2] == {"protocol": "wifi", "state": "error"}


def test_url_node_is_one_encoded_segment(endpoint):
    url, observed, _ = endpoint
    reporter = ScannerStatusReporter(
        url,
        "node/path?query",
        "wifi",
        ssl.create_default_context,
        lambda: {},
        lambda: "running",
    )
    assert reporter.report("running")
    assert observed[0][0] == "/api/nodes/node%2Fpath%3Fquery/scanner-status"


def test_real_tls_private_ca_and_hostname_are_required(tmp_path, caplog, monkeypatch):
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic scanner test")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    certfile = tmp_path / "ca.pem"
    keyfile = tmp_path / "private.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    keyfile.chmod(0o600)
    received = []
    monkeypatch.setattr(edge_status, "_REQUEST_TIMEOUT", REQUEST_TIMEOUT)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    order = []

    def trust():
        order.append("tls")
        return ssl.create_default_context(cafile=str(certfile))

    def auth():
        assert order[-1] == "tls"
        order.append("auth")
        return {"X-API-Key": "PRIVATE-TLS-KEY"}

    try:
        url = f"https://127.0.0.1:{server.server_port}"
        assert not make_reporter(url).report("running")
        valid = ScannerStatusReporter(
            url, "owned-node", "sdr", trust, auth, lambda: "running"
        )
        assert valid.report("running")
        wrong_host = ScannerStatusReporter(
            f"https://localhost:{server.server_port}",
            "owned-node",
            "sdr",
            trust,
            auth,
            lambda: "running",
        )
        assert not wrong_host.report("running")
        assert received == [{"protocol": "sdr", "state": "running"}]
        assert order == ["tls", "auth", "tls", "auth"]
        assert "PRIVATE" not in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=REAP)


def test_wifi_successful_channel_selection_and_stale_or_failed_hopping(
    wifi, monkeypatch
):
    scanner = wifi.WifiScanner("unused-test-interface")
    scanner._running = True
    scanner._reading_pcap = True
    scanner._proc = SimpleNamespace(poll=lambda: None)
    scanner._hop_thread = SimpleNamespace(is_alive=lambda: True)
    choices = []
    monkeypatch.setattr(
        scanner._monitor,
        "set_channel",
        lambda channel: choices.append(channel) or len(choices) == 1,
    )
    monkeypatch.setattr(
        wifi.time, "sleep", lambda _: setattr(scanner, "_running", False)
    )
    scanner._hop_channels()
    assert choices == [1]
    scanner._running = True
    assert scanner.capture_state() == "running"
    scanner._last_channel_success -= 31
    assert scanner.capture_state() == "error"
    scanner._hop_channels()  # Real failed set_channel must not refresh the timestamp.
    scanner._running = True
    assert scanner.capture_state() == "error"


def test_wifi_synthetic_mode_does_not_advertise_physical_scanner(wifi, monkeypatch):
    class SyntheticReporter:
        total_recorded = total_uploaded = total_batches = total_dropped = 0

        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    monkeypatch.setattr(wifi, "WifiReporter", SyntheticReporter)
    monkeypatch.setattr(wifi, "_check_tls_config", lambda: True)
    monkeypatch.setattr(wifi, "_generate_synthetic_frames", lambda *_args: None)
    monkeypatch.setattr(wifi.time, "sleep", lambda _: None)
    monkeypatch.setattr(wifi.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(wifi.sys, "argv", ["wifi_scan", "--test"])

    def unexpected(*_args, **_kwargs):
        pytest.fail("Synthetic capture constructed a physical scanner status reporter")

    monkeypatch.setattr(wifi, "ScannerStatusReporter", unexpected)
    assert wifi.main() == 0


@pytest.mark.parametrize(
    "outcome", ["shutdown", "startup_error", "classification_error"]
)
def test_rf_main_sends_real_lease_and_final_state(rf, endpoint, monkeypatch, outcome):
    url, observed, _ = endpoint
    monkeypatch.setenv("MLRF_BRIDGE_URL", url)
    monkeypatch.setenv("MLRF_BRIDGE_KEY", "PRIVATE-KEY-MARKER")
    monkeypatch.setenv("MLRF_NODE_ID", "owned-node")
    monkeypatch.setenv("MLRF_MODEL_PATH", "/unused-synthetic-model")
    monkeypatch.setenv("MLRF_ANOMALY", "0")
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "synthetic"})
    monkeypatch.setitem(rf.state, "running", True)
    iq = np.exp(1j * np.arange(8192) * 0.3).astype(np.complex64)
    cleanup = []

    class SDR:
        connected = True
        name = "synthetic-radio-boundary"

        def __init__(self, *_args):
            pass

        def connect(self):
            if outcome == "startup_error":
                raise OSError("Synthetic hardware unavailable")
            return True

        def set_frequency(self, _freq):
            return True

        def capture(self, _count):
            return iq

        def disconnect(self):
            cleanup.append("radio")

    class Engine:
        class_names = ["noise"]
        avg_cls_per_sec = 1

        def __init__(self, *_args, **_kwargs):
            pass

        def classify(self, samples):
            assert samples.shape == (2, 8192)
            if outcome == "classification_error":
                rf.state["running"] = False
                raise RuntimeError("PRIVATE-CLASSIFIER-DETAIL")
            return {"class": "noise"}

    class Reporter:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def report(self, **_kwargs):
            deadline = time.monotonic() + WAIT
            while (
                not any(item[2]["state"] == "running" for item in observed)
                and time.monotonic() < deadline
            ):
                time.sleep(0.005)
            assert any(item[2]["state"] == "running" for item in observed)
            rf.state["running"] = False
            return False  # Filtered noise still proves actual scanning.

        def stop(self):
            cleanup.append("uploader")

    monkeypatch.setattr(rf, "RTLTCPClient", SDR)
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.detection_reporter"),
        "DetectionReporter",
        Reporter,
    )

    class FastLease(ScannerStatusReporter):
        def __init__(self, *args):
            super().__init__(*args, interval=0.02)

    monkeypatch.setattr(rf, "ScannerStatusReporter", FastLease)
    if outcome == "startup_error":
        with pytest.raises(OSError, match="Synthetic hardware"):
            rf.main()
        assert all(item[2]["state"] == "error" for item in observed)
    else:
        assert rf.main() == 0
        if outcome == "classification_error":
            assert rf.state["last_error"] == "scan_failed"
            assert rf.state["last_successful_capture"] is not None
            assert not any(item[2]["state"] == "running" for item in observed)
        else:
            assert any(item[2]["state"] == "running" for item in observed)
        assert observed[-1][2]["state"] == "stopped"
    assert cleanup == ["uploader", "radio"]
    assert observed
    assert all(item[2]["protocol"] == "sdr" for item in observed)


def test_rf_main_waits_for_an_absent_receiver_and_resumes(
    rf, endpoint, monkeypatch, caplog
):
    """rtl_tcp away: reason sensor_absent, no exit, no flood; then it resumes."""
    import socket

    url, observed, _ = endpoint
    caplog.set_level(logging.INFO, logger="rf_scan")
    answer = socket.socket()
    answer.bind(("127.0.0.1", 0))
    answer.listen(8)
    answer.settimeout(0.2)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        rtl_port = probe.getsockname()[1]
    done = threading.Event()

    def supervisor_state_port():
        while not done.is_set():
            try:
                conn, _ = answer.accept()
            except (TimeoutError, OSError):
                continue
            with conn:
                conn.sendall(b"sensor_absent\n")

    for name, value in {
        "MLRF_BRIDGE_URL": url,
        "MLRF_BRIDGE_KEY": "PRIVATE-KEY-MARKER",
        "MLRF_NODE_ID": "owned-node",
        "MLRF_MODEL_PATH": "/unused-synthetic-model",
        "MLRF_ANOMALY": "0",
        "MLRF_CAPTURE_MODE": "rtltcp",
        "MLRF_RTL_HOST": "127.0.0.1",
        "MLRF_RTL_PORT": str(rtl_port),
        "MLRF_RTL_STATUS_PORT": str(answer.getsockname()[1]),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "a", 916: "b", 917: "c"})
    monkeypatch.setattr(rf, "DWELL_TIME", 0)
    monkeypatch.setattr(rf, "RTL_RETRY_SECONDS", 0.05)
    monkeypatch.setitem(rf.state, "running", True)
    captured = []

    class Engine:
        class_names = ["noise"]
        avg_cls_per_sec = 1
        input_samples = 8192

        def __init__(self, *_args, **_kwargs):
            pass

        def classify(self, _samples):
            captured.append(1)
            return {"class": "noise"}

    class Reporter:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def report(self, **_kwargs):
            if any(item[2]["state"] == "running" for item in observed):
                rf.state["running"] = False
            return False

        def stop(self):
            pass

    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.detection_reporter"),
        "DetectionReporter",
        Reporter,
    )

    class FastLease(ScannerStatusReporter):
        def __init__(self, *args):
            super().__init__(*args, interval=0.02)

    monkeypatch.setattr(rf, "ScannerStatusReporter", FastLease)
    result = []
    thread = threading.Thread(target=lambda: result.append(rf.main()), daemon=True)
    state_thread = threading.Thread(target=supervisor_state_port, daemon=True)
    state_thread.start()
    thread.start()
    listener = None
    try:
        deadline = time.monotonic() + WAIT
        while time.monotonic() < deadline and not any(
            item[2].get("reason") == "sensor_absent" for item in observed
        ):
            time.sleep(0.01)
        assert any(item[2].get("reason") == "sensor_absent" for item in observed)
        time.sleep(0.5)  # many retry intervals with the receiver away
        assert thread.is_alive(), "scan must not exit while the receiver is away"
        assert not captured
        # rtl_tcp is back: capture resumes without operator action.
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", rtl_port))
        listener.listen(1)
        listener.settimeout(WAIT)
        conn, _ = listener.accept()
        # Long enough for a starved scan loop to drain the socket; when the
        # scan ends and closes it, a send fails at once.
        conn.settimeout(REAP)
        with conn:
            conn.sendall(b"RTL0" + struct.pack(">II", 5, 29))
            while thread.is_alive():
                try:
                    conn.sendall(bytes([200, 50]) * 8192)
                except OSError:
                    break
                time.sleep(0.005)
        thread.join(WAIT)
    finally:
        rf.state["running"] = False
        done.set()
        thread.join(WAIT)
        state_thread.join(REAP)
        answer.close()
        if listener is not None:
            listener.close()
    assert result == [0]
    assert captured
    bodies = [item[2] for item in observed]
    reasons = [body.get("reason") for body in bodies if body["state"] == "error"]
    assert "sensor_absent" in reasons
    assert set(reasons) <= {"starting", "sensor_absent"}
    assert any(body["state"] == "running" for body in bodies)
    assert bodies[-1] == {"protocol": "sdr", "state": "stopped"}
    messages = [r.getMessage() for r in caplog.records]
    assert len([m for m in messages if " unavailable (" in m]) == 1
    assert len([m for m in messages if "capture resumed" in m]) == 1


def test_rf_main_pauses_one_retry_interval_per_sweep_while_rtl_tcp_is_away(
    rf, endpoint, monkeypatch
):
    """Every receiver away: each sweep ends with a wait, not a spin."""
    import socket

    url, _, _ = endpoint
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    for name, value in {
        "MLRF_BRIDGE_URL": url,
        "MLRF_BRIDGE_KEY": "PRIVATE-KEY-MARKER",
        "MLRF_NODE_ID": "owned-node",
        "MLRF_MODEL_PATH": "/unused-synthetic-model",
        "MLRF_ANOMALY": "0",
        "MLRF_CAPTURE_MODE": "rtltcp",
        "MLRF_RTL_HOST": "127.0.0.1",
        "MLRF_RTL_PORT": str(closed),
        "MLRF_RTL_STATUS_PORT": str(closed),
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "a", 916: "b", 917: "c"})
    monkeypatch.setattr(rf, "DWELL_TIME", 0)
    # Long enough that the time a sweep itself takes on a loaded CI runner
    # stays small beside it: the bounds below compare waits with the interval.
    interval = 5.0
    monkeypatch.setattr(rf, "RTL_RETRY_SECONDS", interval)
    monkeypatch.setitem(rf.state, "running", True)
    monkeypatch.setitem(rf.state, "scan_count", 0)
    attempts = []

    class AwayRTL(rf.RTLTCPClient):
        def connect(self):
            attempts.append(time.monotonic())
            if rf.state["scan_count"] > 100:
                rf.state["running"] = False  # spinning: end the test
            if len(attempts) == 1:
                # Connected at start; rtl_tcp then goes away (the unconnected
                # socket fails the first command).
                self.sock = socket.socket()
                return True
            return super().connect()

    class Engine:
        class_names = ["noise"]
        avg_cls_per_sec = 1

        def __init__(self, *_args, **_kwargs):
            pass

    class Reporter:
        summarize = False  # read every 10 sweeps

        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def stop(self):
            pass

    pauses = []
    real_pause = rf._pause

    def pause(seconds):
        pauses.append(seconds)
        if rf.state["scan_count"] >= 5:
            rf.state["running"] = False
        real_pause(seconds)

    monkeypatch.setattr(rf, "_pause", pause)
    monkeypatch.setattr(rf, "RTLTCPClient", AwayRTL)
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.detection_reporter"),
        "DetectionReporter",
        Reporter,
    )

    class QuietLease(ScannerStatusReporter):
        # Nothing here reads the lease; frequent reports would only take CPU
        # from the sweeps whose timing is measured.
        def __init__(self, *args):
            super().__init__(*args, interval=30)

    monkeypatch.setattr(rf, "ScannerStatusReporter", QuietLease)
    started = time.monotonic()
    assert rf.main() == 0
    elapsed = time.monotonic() - started
    assert rf.state["scan_count"] == 5
    # One wait per sweep, each about the rest of the retry interval.
    assert len(pauses) == 5
    assert all(interval / 2 <= seconds <= interval for seconds in pauses)
    assert elapsed >= 4 * interval
    # One reconnection attempt per sweep (plus the start), not one per frequency.
    assert len(attempts) == 5


@pytest.mark.parametrize(
    "outcome",
    [
        "shutdown",
        "startup_error",
        "enable_failed",
        "eof",
        "cleanup_error",
        "status_cleanup_error",
    ],
)
def test_wifi_main_lifecycle_uses_real_reporter(
    wifi, endpoint, monkeypatch, tmp_path, outcome
):
    url, observed, _ = endpoint
    monkeypatch.setenv("MLRF_BRIDGE_URL", url)
    monkeypatch.setenv("MLRF_BRIDGE_KEY", "PRIVATE-KEY-MARKER")
    monkeypatch.setenv("MLRF_NODE_ID", "owned-node")
    monkeypatch.delenv("MLRF_WIFI_IFACE", raising=False)
    monkeypatch.delenv("MLRF_WIFI_IDENTITY", raising=False)
    monkeypatch.setattr(wifi.sys, "argv", ["wifi_scan"])
    # The default interface is present in a fake sysfs.
    radio = tmp_path / "net/wlan1"
    radio.mkdir(parents=True)
    (radio / "ifindex").write_text("3\n")
    (radio / "type").write_text("803\n")
    monkeypatch.setattr(wifi, "NET_SYSFS", tmp_path / "net")
    monkeypatch.setattr(wifi, "RETRY_INTERVAL", 0.2)
    callbacks = {}
    monkeypatch.setattr(
        wifi.signal,
        "signal",
        lambda sig, callback: callbacks.__setitem__(sig, callback),
    )
    cleanup = []
    rounds = []

    class Uploader:
        total_uploaded = total_dropped = 0

        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def record(self, _obs):
            pass

        def stop(self):
            cleanup.append("uploader")

    class Scanner:
        captured = _running = False
        end_reason = None

        def __init__(self, **_kwargs):
            self.failures = wifi._FailureLog(wifi.logger)

        def start(self):
            rounds.append("round")
            # The first lease report must see the round not running yet.
            deadline = time.monotonic() + WAIT
            while not observed and time.monotonic() < deadline:
                time.sleep(0.005)
            if len(rounds) == 2:
                # The failed first round is reported until the next round
                # captures; wait for that report instead of relying on the
                # short back-off being long enough for one.
                deadline = time.monotonic() + WAIT
                while (
                    CAPTURE_FAILED not in [item[2] for item in observed]
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.005)
            if outcome == "startup_error":
                raise FileNotFoundError("Synthetic capture tool missing")
            if outcome == "enable_failed" and len(rounds) == 1:
                raise subprocess.CalledProcessError(2, ["ip"])

        def capture_state(self):
            return "error"  # Lifecycle seam is not physical-capture proof.

        def request_stop(self):
            pass

        def read_frames(self):
            if outcome == "eof" and len(rounds) == 1:
                # Let the lease report the failed round during the back-off.
                return
            callbacks[wifi.signal.SIGTERM](wifi.signal.SIGTERM, None)
            yield {"bssid": ""}

        def stop(self):
            cleanup.append("capture")
            if outcome == "cleanup_error":
                raise OSError("Synthetic capture cleanup failed")

    monkeypatch.setattr(wifi, "WifiReporter", Uploader)
    monkeypatch.setattr(wifi, "WifiScanner", Scanner)
    CAPTURE_FAILED = {"protocol": "wifi", "state": "error", "reason": "capture_failed"}

    class FastLease(ScannerStatusReporter):
        def __init__(self, *args):
            super().__init__(*args, interval=0.02)

        def stop(self, final_state, reason=None):
            super().stop(final_state, reason)
            if outcome == "status_cleanup_error":
                raise OSError("Synthetic status cleanup failed")

    monkeypatch.setattr(wifi, "ScannerStatusReporter", FastLease)
    if outcome == "status_cleanup_error":
        # The public lifecycle must still flush accepted uploads after a
        # status cleanup failure, while retaining that error for the caller.
        with pytest.raises(OSError, match="Synthetic status cleanup failed"):
            wifi.main()
    elif outcome == "startup_error":
        # Contract change: an error waiting cannot fix exits non-zero, and
        # the final report says why.
        assert wifi.main() == 1
    else:
        # Contract: SIGTERM exits 0 in every state, including a failed
        # restore of managed mode (it was re-raised before).
        assert wifi.main() == 0
    final = {"protocol": "wifi", "state": "stopped"}
    if outcome == "startup_error":
        final = {"protocol": "wifi", "state": "error", "reason": "capture_failed"}
    assert observed[-1][2] == final
    # Before the first capture round runs, the reason is "starting".
    assert observed[0][2] == {
        "protocol": "wifi",
        "state": "error",
        "reason": "starting",
    }
    if outcome in {"eof", "enable_failed"}:
        # A failed round is retried, and reported as capture_failed meanwhile.
        assert len(rounds) == 2
        assert CAPTURE_FAILED in [item[2] for item in observed]
    else:
        assert len(rounds) == 1
    assert cleanup == ["capture"] * len(rounds) + ["uploader"]


def test_wifi_round_that_captured_then_stalled_reports_capture_failed(
    wifi, monkeypatch, tmp_path
):
    monkeypatch.setenv("MLRF_BRIDGE_URL", "https://127.0.0.1:9")
    monkeypatch.setenv("MLRF_BRIDGE_KEY", "PRIVATE-KEY-MARKER")
    monkeypatch.setenv("MLRF_NODE_ID", "owned-node")
    monkeypatch.delenv("MLRF_WIFI_IFACE", raising=False)
    monkeypatch.delenv("MLRF_WIFI_IDENTITY", raising=False)
    monkeypatch.setattr(wifi.sys, "argv", ["wifi_scan"])
    radio = tmp_path / "net/wlan1"
    radio.mkdir(parents=True)
    (radio / "ifindex").write_text("3\n")
    (radio / "type").write_text("803\n")
    monkeypatch.setattr(wifi, "NET_SYSFS", tmp_path / "net")
    monkeypatch.setattr(wifi, "RETRY_INTERVAL", 0.01)
    callbacks = {}
    monkeypatch.setattr(
        wifi.signal, "signal", lambda sig, callback: callbacks.__setitem__(sig, callback)
    )
    seen = {}
    status = []

    class Status:
        def __init__(self, *args):
            status.append(args[-1])

        def start(self):
            pass

        def stop(self, *_args):
            pass

    class Uploader:
        total_uploaded = total_dropped = total_batches = total_pcap_uploads = 0

        def __init__(self, **_kwargs):
            pass

        def start(self):
            pass

        def record(self, _obs):
            pass

        def stop(self):
            pass

    class Scanner:
        _current_channel = 6

        def __init__(self, **_kwargs):
            self.failures = wifi._FailureLog(wifi.logger)
            self.rounds = 0
            self.state = "error"

        def start(self):
            self.rounds += 1
            self.end_reason = None
            self.captured = False
            self._running = True
            if self.rounds == 2:
                seen["next round"] = status[0]()
                callbacks[wifi.signal.SIGTERM](wifi.signal.SIGTERM, None)

        def capture_state(self):
            return self.state

        def request_stop(self):
            self._running = False

        def read_frames(self):
            if self.rounds > 1:
                return  # Stopping: SIGTERM arrived in start().
            self.state, self.captured = "running", True
            seen["capturing"] = status[0]()
            yield {"bssid": ""}
            self.state = "error"  # Hops fail or the type flips; not yet noticed.
            seen["stalled"] = status[0]()
            # What the watchdog does when it notices.
            self.end_reason = wifi.sensor_presence.CAPTURE_FAILED
            self.request_stop()
            seen["watchdog"] = status[0]()

        def stop(self):
            if self.rounds == 1:
                seen["teardown"] = status[0]()  # Stopping tcpdump takes seconds.
                (radio / "type").unlink()  # Then the adapter is unplugged.

    real_find = wifi.sensor_presence.find_wifi_sensor
    while_absent = []

    def find_wifi_sensor(*args, **kwargs):
        presence = real_find(*args, **kwargs)
        if presence.state == "absent":
            while_absent.append(status[0]())
            if len(while_absent) == 3:
                (radio / "type").write_text("1\n")  # Back for the next round.
        return presence

    monkeypatch.setattr(wifi.sensor_presence, "find_wifi_sensor", find_wifi_sensor)

    monkeypatch.setattr(wifi, "WifiReporter", Uploader)
    monkeypatch.setattr(wifi, "WifiScanner", Scanner)
    monkeypatch.setattr(wifi, "ScannerStatusReporter", Status)
    assert wifi.main() == 0
    failed = ("error", "capture_failed")
    assert seen == {
        "capturing": "running",
        "stalled": failed,
        "watchdog": failed,
        "teardown": failed,
        # A returning sensor keeps its reason until the new round captures.
        "next round": ("error", "sensor_absent"),
    }
    # A presence change after the failed round replaces its reason.
    assert while_absent[-1] == ("error", "sensor_absent")


@pytest.mark.parametrize("module", ["rf_scan", "wifi_scan"])
def test_legacy_standalone_module_can_import_shared_reporter(tmp_path, module):
    import os
    from pathlib import Path

    edge = Path(__file__).resolve().parents[2] / "src/sigrift/edge"
    env = {**os.environ, "PYTHONPATH": str(edge), "MLRF_LOG_DIR": str(tmp_path)}
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import {module}; assert {module}.ScannerStatusReporter.__module__ == 'scanner_status'",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=WAIT,
    )
    assert result.returncode == 0, result.stderr


def test_blocked_capture_callback_has_bounded_shutdown_and_visible_failure(
    endpoint, caplog, monkeypatch
):
    url, observed, _ = endpoint
    # This test measures the bound itself: the product's own request limit.
    monkeypatch.setattr(edge_status, "_REQUEST_TIMEOUT", PRODUCT_REQUEST_TIMEOUT)
    entered = threading.Event()
    release = threading.Event()

    def blocked_capture_state():
        entered.set()
        # Blocked far longer than stop() may wait (released below).
        release.wait(timeout=600)
        return "error"

    reporter = ScannerStatusReporter(
        url,
        "owned-node",
        "wifi",
        ssl.create_default_context,
        lambda: {},
        blocked_capture_state,
    )
    reporter.start()
    assert entered.wait(timeout=WAIT)
    started = time.monotonic()
    try:
        reporter.stop()
        elapsed = time.monotonic() - started
        # stop() waits for at most three request timeouts plus a margin. The
        # margin allowed here suits a loaded runner and is still far below
        # the 600 s an unbounded wait for the blocked callback would take.
        bound = 3 * edge_status._REQUEST_TIMEOUT + 0.5
        assert bound - 0.5 <= elapsed < bound + 30
        assert reporter._thread.is_alive()
        assert "shutdown did not finish" in caplog.text
    finally:
        release.set()
        reporter._thread.join(timeout=WAIT)
    assert not reporter._thread.is_alive()
    assert observed[-1][2]["state"] == "stopped"
