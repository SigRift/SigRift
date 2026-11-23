"""Real edge reporter and scanner-loop regressions for runtime mode changes."""

import gzip
import importlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import numpy as np
import pytest

from sigrift.edge.detection_reporter import DetectionReporter
from sigrift.edge.scanner_config import reload_summarize, write_config


@pytest.fixture
def uploads(tmp_path):
    from sigrift.bridge.storage.base import SharedContext
    from sigrift.bridge.storage.detection_summaries import DetectionSummaryStore

    context = SharedContext(tmp_path / "summary-receiver.db")
    summaries = DetectionSummaryStore(context)
    received = []
    scanner_states = []
    request_errors = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            response_body = {}
            try:
                assert self.headers["X-API-Key"] == "synthetic-key"
                data = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/api/nodes/synthetic-node/scanner-status":
                    body = json.loads(data)
                    # "reason" is optional and only goes with "error".
                    assert {"protocol", "state"} <= set(body) <= {
                        "protocol",
                        "state",
                        "reason",
                    }
                    if "reason" in body:
                        assert body["state"] == "error"
                        assert body["reason"] in {
                            "starting",
                            "sensor_absent",
                            "sensor_changed",
                            "sensor_unusable",
                            "capture_failed",
                        }
                    assert body["protocol"] == "sdr"
                    assert body["state"] in {"running", "stopped", "error"}
                    scanner_states.append(body["state"])
                else:
                    assert self.path in {
                        "/api/detections/batch",
                        "/api/detections/ingest-summary",
                    }
                    assert self.headers["X-Node-ID"] == "synthetic-node"
                    assert self.headers["Content-Encoding"] == "gzip"
                    body = json.loads(gzip.decompress(data))
                    received.append((self.path, body))
                    if self.path.endswith("ingest-summary"):
                        response_body = {
                            "summary_receipt": summaries.accept_snapshot(body)
                        }
                status = 200
            except Exception as exc:
                request_errors.append(type(exc).__name__)
                status = 400
            self.send_response(status)
            self.end_headers()
            self.wfile.write(json.dumps(response_body).encode())

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received, scanner_states
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        context.close()
        assert request_errors == []


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("MLRF_SCANNER_CONFIG_PATH", str(tmp_path / "scanner.json"))
    for name in (
        "MLRF_CA_CERT",
        "MLRF_CA_BUNDLE",
        "MLRF_INSECURE_TLS",
        "MLRF_CLIENT_CERT",
        "MLRF_CLIENT_KEY",
        "BRIDGE_CA_BUNDLE",
    ):
        monkeypatch.delenv(name, raising=False)


def make_reporter(url, data_dir, **kwargs):
    return DetectionReporter(
        url,
        "synthetic-key",
        "synthetic-node",
        data_dir=data_dir,
        batch_size=1000,
        dedup_window_seconds=0,
        repeat_report_interval=1,
        **kwargs,
    )


def record(reporter, index):
    assert reporter.report(
        {"class": "bpsk" if index % 2 else "qpsk", "confidence": 0.95, "family": "psk"},
        915000000,
        15.0,
        -55.0,
    )


def counts(received):
    raw = sum(
        len(body["detections"]) for path, body in received if path.endswith("/batch")
    )
    # Each snapshot replaces a prior partial count; use the last uploaded bins.
    summaries = [body for path, body in received if path.endswith("/ingest-summary")]
    summary = (
        sum(entry["detection_count"] for entry in summaries[-1]["summaries"])
        if summaries
        else 0
    )
    return raw, summary


@pytest.mark.parametrize("initial", [False, True])
def test_real_reporter_property_preserves_initial_mode_and_no_file(
    initial, uploads, tmp_path
):
    url, _, _states = uploads
    reporter = make_reporter(url, tmp_path / "edge-data", summarize=initial)
    assert reporter.summarize is initial
    reporter.summarize = reload_summarize(reporter.summarize)
    assert reporter.summarize is initial
    record(reporter, 1)
    if initial:
        assert reporter._accumulator.snapshot()["summaries"][0]["detection_count"] == 1
        assert len(reporter._buffer) == 0
    else:
        assert len(reporter._buffer) == 1
        assert reporter._accumulator is None


def test_enable_disable_enable_preserves_cumulative_hour_and_raw_pending(
    uploads, tmp_path
):
    url, received, _states = uploads
    reporter = make_reporter(url, tmp_path / "edge-data", summarize=False)
    record(reporter, 1)
    write_config({"summarize": True})
    reporter.summarize = reload_summarize(reporter.summarize)
    record(reporter, 2)
    accumulator = reporter._accumulator
    assert accumulator is not None
    reporter._flush_summaries()
    write_config({"summarize": False})
    reporter.summarize = reload_summarize(reporter.summarize)
    record(reporter, 3)
    assert reporter._accumulator is accumulator
    assert accumulator.snapshot()["summaries"][0]["detection_count"] == 1
    write_config({"summarize": True})
    reporter.summarize = reload_summarize(reporter.summarize)
    record(reporter, 4)
    reporter.stop()
    assert counts(received) == (2, 2)
    assert len(reporter._buffer) == 0
    assert accumulator.snapshot()["summaries"][0]["detection_count"] == 2
    assert reporter.get_stats()["summary_pending_hours"] == 0


@pytest.mark.parametrize("final_mode", [False, True])
def test_background_flush_drains_both_routes_after_toggle(
    uploads, final_mode, tmp_path
):
    url, received, _states = uploads
    reporter = make_reporter(
        url,
        tmp_path / "edge-data",
        summarize=not final_mode,
        flush_interval_seconds=0.01,
    )
    record(reporter, 1)
    reporter.summarize = final_mode
    record(reporter, 2)
    reporter.start()
    try:
        deadline = time.monotonic() + 3
        while counts(received) != (1, 1) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert counts(received) == (1, 1)
    finally:
        reporter.stop()
    assert counts(received) == (1, 1)


def test_late_enable_preserves_configured_anomaly_threshold(uploads, tmp_path):
    url, _, _states = uploads
    reporter = make_reporter(
        url, tmp_path / "edge-data", summarize=False, summary_anomaly_threshold=0.4
    )
    reporter.summarize = True
    assert reporter._accumulator.accumulate(
        {
            "id": "late-enable-high-anomaly",
            "node_id": "synthetic-node",
            "timestamp": time.time(),
            "signal_class": "bpsk",
            "freq_hz": 915000000,
            "anomaly_score": 0.5,
        }
    )
    payload = reporter._accumulator.snapshot()
    assert payload["summaries"] == []
    assert len(payload["high_anomaly_detections"]) == 1


@pytest.mark.parametrize("initial", [False, True])
def test_actual_rf_main_survives_25_sweeps_and_two_config_changes(
    tmp_path, monkeypatch, uploads, initial
):
    url, received, _states = uploads
    monkeypatch.setenv("MLRF_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("MLRF_BRIDGE_URL", url)
    monkeypatch.setenv("MLRF_BRIDGE_KEY", "synthetic-key")
    monkeypatch.setenv("MLRF_NODE_ID", "synthetic-node")
    monkeypatch.setenv("MLRF_MODEL_PATH", "/synthetic-model-boundary")
    monkeypatch.setenv("MLRF_DATA_DIR", str(tmp_path / "edge-data"))
    monkeypatch.setenv("MLRF_SUMMARIZE", str(initial).lower())
    monkeypatch.setenv("MLRF_ANOMALY", "0")
    monkeypatch.setenv("MLRF_IQ_CAPTURE", "0")
    rf = importlib.import_module("sigrift.edge.rf_scan")
    monkeypatch.setattr(
        rf, "state", {**rf.state, "running": True, "scan_count": 0, "detections": 0}
    )
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "synthetic"})
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rf, "try_edge_decode", lambda *_args: [])
    iq = np.exp(1j * np.arange(8192) * 0.3).astype(np.complex64)
    captures = []
    stopped = []

    class SDR:
        connected = True
        name = "synthetic-radio-boundary"

        def __init__(self, *_args):
            pass

        def connect(self):
            return True

        def set_frequency(self, _freq):
            return True

        def capture(self, _size):
            captures.append(1)
            if len(captures) == 10:
                write_config({"summarize": not initial})
            if len(captures) == 20:
                write_config({"summarize": initial})
            if len(captures) == 25:
                rf.state["running"] = False
            return iq

        def disconnect(self):
            stopped.append(True)

    class Engine:
        class_names = ["bpsk", "qpsk"]
        avg_cls_per_sec = 1

        def __init__(self, *_args, **_kwargs):
            pass

        def classify(self, samples):
            assert samples.shape == (2, 8192)
            return {
                "class": "bpsk" if len(captures) % 2 else "qpsk",
                "confidence": 0.95,
                "family": "psk",
            }

    instances = []

    class TrackedReporter(DetectionReporter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(rf, "RTLTCPClient", SDR)
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.detection_reporter"),
        "DetectionReporter",
        TrackedReporter,
    )
    write_config({"summarize": initial})
    try:
        assert rf.main() == 0
        assert len(captures) == rf.state["scan_count"] == 25
        assert stopped == [True]
        assert instances[0].summarize is initial
        assert instances[0].get_stats()["total_received"] == 25
        assert counts(received) == ((10, 15) if initial else (15, 10))
    finally:
        for instance in instances:
            if instance._running:
                instance.stop()


def test_inflight_summary_record_and_new_raw_record_each_uploaded_once(
    uploads, monkeypatch, tmp_path
):
    url, received, _states = uploads
    reporter = make_reporter(url, tmp_path / "edge-data", summarize=True)
    selected = threading.Event()
    release = threading.Event()
    accumulate = reporter._accumulator.accumulate

    def hold_selected_record(value):
        selected.set()
        assert release.wait(timeout=3)
        return accumulate(value)

    monkeypatch.setattr(reporter._accumulator, "accumulate", hold_selected_record)
    errors = []

    def in_flight():
        try:
            record(reporter, 1)
        except Exception as exc:
            errors.append(type(exc).__name__)

    thread = threading.Thread(target=in_flight, daemon=True)
    raw_thread = threading.Thread(target=lambda: record(reporter, 2), daemon=True)
    thread.start()
    try:
        assert selected.wait(timeout=2)
        reporter.summarize = False
        raw_thread.start()
    finally:
        release.set()
        thread.join(timeout=3)
        if raw_thread.ident is not None:
            raw_thread.join(timeout=3)
    assert not thread.is_alive()
    assert not raw_thread.is_alive()
    assert errors == []
    reporter.stop()
    assert counts(received) == (1, 1)
    batches = [body for path, body in received if path.endswith("/batch")]
    summaries = [body for path, body in received if path.endswith("/ingest-summary")]
    assert [item["signal_class"] for item in batches[0]["detections"]] == ["qpsk"]
    assert [item["signal_class"] for item in summaries[0]["summaries"]] == ["bpsk"]


@pytest.fixture(autouse=True)
def _close_summary_journal_resources(monkeypatch):
    # Track only resource ownership. Construction, SQLite and all behavior use
    # the real journal; tests explicitly exercise stop() independently of close.
    from sigrift.edge import summary_journal

    real_journal = summary_journal.SummaryJournal
    created = []

    def tracked(*args, **kwargs):
        journal = real_journal(*args, **kwargs)
        created.append(journal)
        return journal

    monkeypatch.setattr(summary_journal, "SummaryJournal", tracked)
    yield
    for journal in reversed(created):
        journal.close()


def test_stop_restart_and_final_close_preserve_identity_and_release_writer(
    uploads, tmp_path
):
    url, received, _ = uploads
    data_dir = tmp_path / "edge-data"
    reporter = make_reporter(url, data_dir, summarize=True)
    stream = reporter._summary_journal.stream_id
    try:
        for _ in range(2):
            reporter.start()
            assert reporter.report(
                {"class": "bpsk", "family": "PSK", "confidence": 0.8}, 915e6, 15, -55
            )
            reporter.stop()
        counts = [
            body["summaries"][0]["detection_count"]
            for path, body in received
            if path.endswith("ingest-summary")
        ]
        assert counts == [1, 2]
    finally:
        reporter.close()
    reporter.close()  # Idempotent disposal does not reupload.
    with pytest.raises(RuntimeError, match="closed"):
        reporter.start()
    with pytest.raises(RuntimeError, match="closed"):
        reporter.report({"class": "bpsk"}, 915e6, 15, -55)
    reopened = make_reporter(url, data_dir, summarize=False)
    try:
        assert reopened._summary_journal.stream_id == stream
        assert reopened.get_stats()["summary_pending_hours"] == 0
        assert reopened._accumulator.snapshot()["summaries"][0]["detection_count"] == 2
    finally:
        reopened.close()


def test_standalone_generator_failure_closes_real_journal_and_worker(
    uploads, tmp_path, monkeypatch
):
    from sigrift.edge import detection_reporter as module

    url, _, _ = uploads
    data_dir = tmp_path / "edge-data"
    monkeypatch.setattr(
        module.sys,
        "argv",
        [
            "detection_reporter",
            "--test",
            "--server-url",
            url,
            "--api-key",
            "synthetic-key",
            "--node-id",
            "synthetic-node",
            "--summarize",
            "--data-dir",
            str(data_dir),
        ],
    )
    monkeypatch.setattr(module.signal, "signal", lambda *_args: None)

    def failing_input(_reporter, *_args):
        raise RuntimeError("owned input failed")

    monkeypatch.setattr(module, "_generate_synthetic_detections", failing_input)
    with pytest.raises(RuntimeError, match="owned input failed"):
        module.main()
    reopened = make_reporter(url, data_dir, summarize=True)
    try:
        assert reopened.get_stats()["summary_pending_hours"] == 0
        assert not any(
            thread.name == "detection-flush" and thread.is_alive()
            for thread in threading.enumerate()
        )
    finally:
        reopened.close()


@pytest.mark.parametrize("failure", ["reporter_start", "lease_start", "lease_stop"])
def test_rf_main_exceptional_lifecycle_releases_real_journal_and_radio(
    uploads, tmp_path, monkeypatch, failure
):
    reporter_module = importlib.import_module("sigrift.edge.detection_reporter")
    url, _, _ = uploads
    for key, value in {
        "MLRF_LOG_DIR": str(tmp_path / "logs"),
        "MLRF_BRIDGE_URL": url,
        "MLRF_BRIDGE_KEY": "synthetic-key",
        "MLRF_NODE_ID": "synthetic-node",
        "MLRF_MODEL_PATH": "/synthetic-model-boundary",
        "MLRF_DATA_DIR": str(tmp_path / "edge-data"),
        "MLRF_SUMMARIZE": "1",
        "MLRF_ANOMALY": "0",
        "MLRF_IQ_CAPTURE": "0",
    }.items():
        monkeypatch.setenv(key, value)
    rf = importlib.import_module("sigrift.edge.rf_scan")
    monkeypatch.setattr(
        rf, "state", {**rf.state, "running": True, "scan_count": 0, "detections": 0}
    )
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "synthetic"})
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    disconnected = []

    class SDR:
        name = "owned-radio-boundary"

        def __init__(self, *_args):
            pass

        def connect(self):
            rf.state["running"] = False
            return True

        def disconnect(self):
            disconnected.append(True)

    class Engine:
        class_names = ["bpsk"]

        def __init__(self, *_args, **_kwargs):
            pass

    monkeypatch.setattr(rf, "RTLTCPClient", SDR)
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    instances = []

    class Tracked(DetectionReporter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(reporter_module, "DetectionReporter", Tracked)
    real_start = threading.Thread.start

    def thread_start(thread):
        if (failure == "reporter_start" and thread.name == "detection-flush") or (
            failure == "lease_start" and thread.name.startswith("scanner-status")
        ):
            raise OSError("owned thread startup failed")
        return real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", thread_start)
    original_lease = rf.ScannerStatusReporter

    class Lease(original_lease):
        def stop(self, *args):
            super().stop(*args)
            if failure == "lease_stop":
                raise OSError("owned status cleanup failed")

    monkeypatch.setattr(rf, "ScannerStatusReporter", Lease)
    try:
        with pytest.raises(OSError, match="owned"):
            rf.main()
        assert disconnected == [True]
        assert instances[0]._closed
        assert instances[0]._flush_thread is None
        replacement = make_reporter(url, tmp_path / "edge-data", summarize=True)
        replacement.close()
    finally:
        # If the regression fails, clean the test-owned original before exit.
        for item in instances:
            item._running = False
            thread = item._flush_thread
            if thread is not None and thread.ident is None:
                item._flush_thread = None
            item.close()


def test_bare_reporter_raw_cli_remains_supported_and_summary_fails_actionably(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    import sys
    from sigrift.edge import detection_reporter as module

    script = tmp_path / "detection_reporter.py"
    script.write_bytes(Path(module.__file__).read_bytes())
    environment = dict(os.environ)
    for name in tuple(environment):
        if name.startswith(("MLRF_", "BRIDGE_")) or name in {
            "PYTHONPATH",
            "SSLKEYLOGFILE",
        }:
            environment.pop(name, None)
    args = [
        sys.executable,
        "-I",
        str(script),
        "--test",
        "--test-count",
        "0",
        "--flush-interval",
        ".01",
        "--server-url",
        "http://127.0.0.1:1",
        "--node-id",
        "bare-node",
        "--data-dir",
        str(tmp_path / "data"),
    ]
    raw = subprocess.run(
        args, cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=10
    )
    assert raw.returncode == 0, raw.stderr
    assert not (tmp_path / "data" / "summary-journal").exists()
    summary = subprocess.run(
        [*args, "--summarize"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert summary.returncode != 0
    assert "Summary mode requires the installed sigrift package" in summary.stderr
    assert not (tmp_path / "data" / "summary-journal").exists()


def test_rf_main_keeps_scanning_when_runtime_summary_cannot_open_journal(
    tmp_path, monkeypatch, uploads, caplog
):
    """Turning summary on without MLRF_DATA_DIR logs and stays raw (soak RF-1)."""
    url, received, _states = uploads
    monkeypatch.setenv("MLRF_LOG_DIR", str(tmp_path / "logs"))
    monkeypatch.setenv("MLRF_BRIDGE_URL", url)
    monkeypatch.setenv("MLRF_BRIDGE_KEY", "synthetic-key")
    monkeypatch.setenv("MLRF_NODE_ID", "synthetic-node")
    monkeypatch.setenv("MLRF_MODEL_PATH", "/synthetic-model-boundary")
    monkeypatch.delenv("MLRF_DATA_DIR", raising=False)
    monkeypatch.setenv("MLRF_SUMMARIZE", "false")
    monkeypatch.setenv("MLRF_ANOMALY", "0")
    monkeypatch.setenv("MLRF_IQ_CAPTURE", "0")
    rf = importlib.import_module("sigrift.edge.rf_scan")
    monkeypatch.setattr(
        rf, "state", {**rf.state, "running": True, "scan_count": 0, "detections": 0}
    )
    monkeypatch.setattr(rf, "FREQUENCIES", {915: "synthetic"})
    monkeypatch.setattr(rf, "start_status_server", lambda: None)
    monkeypatch.setattr(rf.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(rf, "try_edge_decode", lambda *_args: [])
    iq = np.exp(1j * np.arange(8192) * 0.3).astype(np.complex64)
    captures = []

    class SDR:
        connected = True
        name = "synthetic-radio-boundary"

        def __init__(self, *_args):
            pass

        def connect(self):
            return True

        def set_frequency(self, _freq):
            return True

        def capture(self, _size):
            captures.append(1)
            if len(captures) == 5:
                write_config({"summarize": True})
            if len(captures) == 25:
                rf.state["running"] = False
            return iq

        def disconnect(self):
            pass

    class Engine:
        class_names = ["bpsk"]
        avg_cls_per_sec = 1

        def __init__(self, *_args, **_kwargs):
            pass

        def classify(self, _samples):
            return {"class": "bpsk", "confidence": 0.95, "family": "psk"}

    instances = []

    class TrackedReporter(DetectionReporter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)

    monkeypatch.setattr(rf, "RTLTCPClient", SDR)
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.edge_inference"),
        "InferenceEngine",
        Engine,
    )
    monkeypatch.setattr(
        importlib.import_module("sigrift.edge.detection_reporter"),
        "DetectionReporter",
        TrackedReporter,
    )
    write_config({"summarize": False})
    try:
        assert rf.main() == 0
        assert len(captures) == rf.state["scan_count"] == 25
        assert instances[0].summarize is False
        assert instances[0].get_stats()["total_received"] == 25
        assert any(
            "Cannot switch to summary mode" in r.getMessage() for r in caplog.records
        )
    finally:
        for instance in instances:
            if instance._running:
                instance.stop()
