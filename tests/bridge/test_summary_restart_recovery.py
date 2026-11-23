"""Fresh RF reporter processes must preserve accepted same-hour observations.

The loopback transport calls the shipped SQLite summary writer. This is a
reporter/storage integration proof, not a full Bridge or physical-radio test.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_summaries import (
    DetectionSummaryStore,
    SummaryConflict,
)


@contextmanager
def summary_receiver(tmp_path, *, legacy=False, receipt_generation=None):
    ctx = SharedContext(tmp_path / "receiver.db")
    store = DetectionSummaryStore(ctx)
    requests, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                assert self.path == "/api/detections/ingest-summary"
                assert self.headers["X-API-Key"] == "disposable-restart-key"
                assert self.headers["X-Node-ID"] == "restart-node"
                data = self.rfile.read(int(self.headers["Content-Length"]))
                body = json.loads(gzip.decompress(data))
                requests.append(body)
                try:
                    if legacy:
                        store.insert_summaries(body["node_id"], body["summaries"])
                        result = {"status": "ok"}
                    else:
                        result = {"summary_receipt": store.accept_snapshot(body)}
                        if receipt_generation is not None:
                            result["summary_receipt"]["generation"] = receipt_generation
                except SummaryConflict:
                    self.send_response(409)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                encoded = json.dumps(result).encode()
                self.send_response(201)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except BaseException as error:
                errors.append(type(error).__name__)
                raise

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", store, requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)
        ctx.close()
        assert not worker.is_alive()
        assert not errors


_CHILD = """
import json,sys,time
from types import SimpleNamespace
from sigrift.edge import detection_reporter as edge
# Only observation timestamps are fixed to the same hour; real socket waits,
# subprocess lifetime and HTTP deadlines retain their actual clocks.
observation_time=[float(sys.argv[3])]
edge.time=SimpleNamespace(time=lambda:observation_time[0],monotonic=time.monotonic,sleep=time.sleep)
reporter=edge.DetectionReporter(sys.argv[1], 'disposable-restart-key', 'restart-node',
    data_dir=sys.argv[2], summarize=True, min_confidence=0, min_snr_db=0,
    dedup_window_seconds=0, repeat_report_interval=1)
for confidence in json.loads(sys.argv[4]):
    assert reporter.report({'class':'bpsk','family':'PSK','confidence':confidence},
                           915000000, 15, -55)
    observation_time[0]+=.01
    if sys.argv[5] == "each": reporter.stop()
reporter.stop()
assert reporter.get_stats()['summary_pending_hours']==0
reporter.close()
"""


def run_reporter(url, data_dir, timestamp, confidences, *, flush_each=False):
    env = dict(os.environ)
    for name in (
        "MLRF_CA_CERT",
        "MLRF_CA_BUNDLE",
        "MLRF_INSECURE_TLS",
        "MLRF_CLIENT_CERT",
        "MLRF_CLIENT_KEY",
        "BRIDGE_CA_BUNDLE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        env.pop(name, None)
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1"
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _CHILD,
            url,
            str(data_dir),
            str(timestamp),
            json.dumps(confidences),
            "each" if flush_each else "final",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr


def test_fresh_process_retains_acknowledged_same_hour_state(tmp_path):
    data_dir = tmp_path / "edge-data"
    data_dir.mkdir()
    timestamp = int(time.time() // 3600) * 3600 + 60
    expected_hour = datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%dT%H:00:00Z"
    )
    with summary_receiver(tmp_path) as (url, store, requests):
        run_reporter(url, data_dir, timestamp, [0.7, 0.9])
        before = store.get_summaries(node_id="restart-node")
        assert len(before) == 1 and before[0]["hour"] == expected_hour
        assert before[0]["detection_count"] == 2
        assert before[0]["avg_confidence"] == 0.8
        run_reporter(url, data_dir, timestamp + 1, [0.8])
        after = store.get_summaries(node_id="restart-node")
        assert len(requests) == 2
        assert len(after) == 1
        assert after[0]["detection_count"] == 3, (
            "Fresh process overwrote acknowledged observations"
        )
        assert after[0]["avg_confidence"] == 0.8
        assert after[0]["min_confidence"] == 0.7
        assert after[0]["max_confidence"] == 0.9


def test_delayed_old_snapshot_cannot_overwrite_newer_accepted_generation(tmp_path):
    data_dir = tmp_path / "edge-data"
    data_dir.mkdir()
    timestamp = int(time.time() // 3600) * 3600 + 60
    with summary_receiver(tmp_path) as (url, store, requests):
        run_reporter(url, data_dir, timestamp, [0.7, 0.9], flush_each=True)
        assert [body["summaries"][0]["detection_count"] for body in requests] == [1, 2]
        assert store.get_summaries(node_id="restart-node")[0]["detection_count"] == 2
        # Replay exact earlier content, as an accepted-but-delayed network
        # request can arrive after a newer process sends its cumulative state.
        body = gzip.compress(json.dumps(requests[0]).encode())
        request = urllib.request.Request(
            url + "/api/detections/ingest-summary",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": "disposable-restart-key",
                "X-Node-ID": "restart-node",
            },
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with pytest.raises(urllib.error.HTTPError) as rejected:
            opener.open(request, timeout=3)
        assert rejected.value.code == 409
        assert store.get_summaries(node_id="restart-node")[0]["detection_count"] == 2, (
            "Delayed older snapshot regressed the accepted cumulative count"
        )


def test_process_exit_before_any_upload_replays_durable_observations(tmp_path):
    data_dir = tmp_path / "edge-data"
    data_dir.mkdir()
    timestamp = int(time.time() // 3600) * 3600 + 60
    with summary_receiver(tmp_path) as (url, store, requests):
        # os._exit bypasses destructors, stop(), close() and final HTTP upload.
        crash = (
            _CHILD[: _CHILD.index("reporter.stop()\nassert reporter.get_stats()")]
            + "\nimport os; os._exit(0)\n"
        )
        command = [
            sys.executable,
            "-c",
            crash,
            url,
            str(data_dir),
            str(timestamp),
            "[0.7,0.9]",
            "final",
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert completed.returncode == 0, completed.stderr
        assert requests == []
        run_reporter(url, data_dir, timestamp + 1, [0.8])
        assert len(requests) == 1
        assert store.get_summaries()[0]["detection_count"] == 3
        assert store.get_summaries()[0]["avg_confidence"] == 0.8


def test_old_receiver_success_is_not_acknowledgement_and_reopen_keeps_pending(tmp_path):
    from sigrift.edge.detection_reporter import DetectionReporter

    with summary_receiver(tmp_path, legacy=True) as (url, store, requests):
        arguments = dict(data_dir=tmp_path / "edge-data", summarize=True)
        reporter = DetectionReporter(
            url, "disposable-restart-key", "restart-node", **arguments
        )
        assert reporter.report({"class": "bpsk", "confidence": 0.9}, 915e6, 15, -55)
        reporter.stop()
        assert store.get_summaries()[0]["detection_count"] == 1
        assert reporter.get_stats()["summary_pending_hours"] == 1
        original = requests[0]
        reporter.close()
        reopened = DetectionReporter(
            url, "disposable-restart-key", "restart-node", **arguments
        )
        try:
            assert reopened.get_stats()["summary_pending_hours"] == 1
            reopened.stop()
            assert requests[-1] == original
            assert reopened.get_stats()["summary_pending_hours"] == 1
        finally:
            reopened.close()


def test_missing_journal_is_refused_by_receiver_and_original_can_recover(tmp_path):
    from sigrift.edge.detection_reporter import DetectionReporter

    data_dir = tmp_path / "edge-data"
    timestamp = int(time.time() // 3600) * 3600 + 60
    with summary_receiver(tmp_path) as (url, store, requests):
        run_reporter(url, data_dir, timestamp, [0.7, 0.9])
        old_stream = requests[0]["stream_id"]
        original = data_dir / "summary-journal"
        saved = data_dir / "original-journal"
        original.rename(saved)
        replacement = DetectionReporter(
            url,
            "disposable-restart-key",
            "restart-node",
            data_dir=data_dir,
            summarize=True,
        )
        try:
            assert replacement.report(
                {"class": "bpsk", "confidence": 0.8}, 915e6, 15, -55
            )
            replacement.stop()
            assert replacement.get_stats()["summary_pending_hours"] == 1
            assert requests[-1]["stream_id"] != old_stream
            assert store.get_summaries()[0]["detection_count"] == 2
        finally:
            replacement.close()
        # Preserve the refused replacement too; never erase accepted local data.
        original.rename(data_dir / "refused-journal")
        saved.rename(original)
        run_reporter(url, data_dir, timestamp + 1, [0.8])
        assert requests[-1]["stream_id"] == old_stream
        assert store.get_summaries()[0]["detection_count"] == 3
        assert (data_dir / "refused-journal" / "summary.sqlite3").is_file()


@pytest.mark.parametrize("generation", [True, 1.0, "1"])
def test_wrong_receipt_generation_type_does_not_discard_pending(tmp_path, generation):
    from sigrift.edge.detection_reporter import DetectionReporter

    with summary_receiver(tmp_path, receipt_generation=generation) as (url, store, _):
        reporter = DetectionReporter(
            url,
            "disposable-restart-key",
            "restart-node",
            data_dir=tmp_path / "edge-data",
            summarize=True,
        )
        try:
            assert reporter.report({"class": "bpsk", "confidence": 0.9}, 915e6, 15, -55)
            reporter.stop()
            assert store.get_summaries()[0]["detection_count"] == 1
            assert reporter.get_stats()["summary_pending_hours"] == 1
        finally:
            reporter.close()
