"""Real HTTP failures and SQLite summary upserts; no physical radio claims."""

from contextlib import contextmanager
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_summaries import DetectionSummaryStore
from sigrift.edge import detection_reporter as edge


@contextmanager
def summary_endpoint(
    tmp_path, first_outcome, *, gate=None, node_id="software-recovery-node", ingest=None
):
    context = SharedContext(tmp_path / "summaries.db")
    store = DetectionSummaryStore(context)
    received = []
    failures = []
    first_finished = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                assert self.path == "/api/detections/ingest-summary"
                assert self.headers["X-API-Key"] == "software-recovery-key"
                assert self.headers["X-Node-ID"] == node_id
                assert self.headers["Content-Encoding"] == "gzip"
                data = self.rfile.read(int(self.headers["Content-Length"]))
                payload = json.loads(gzip.decompress(data))
                assert payload["node_id"] == node_id
                received.append(payload)
                outcome = first_outcome if len(received) == 1 else "success"
                if gate is not None and len(received) == 1:
                    gate[0].set()
                    assert gate[1].wait(timeout=5)
                if outcome != "reject":
                    receipt = store.accept_snapshot(payload)
                    if ingest is not None:
                        ingest(data)
                if outcome == "lost-response":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                encoded = json.dumps(
                    {"summary_receipt": receipt} if outcome != "reject" else {}
                ).encode()
                self.send_response(503 if outcome == "reject" else 201)
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except BaseException as exc:
                failures.append(type(exc).__name__)
                raise
            finally:
                first_finished.set()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield (
            f"http://127.0.0.1:{server.server_port}",
            store,
            received,
            first_finished,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        context.close()
        assert not thread.is_alive()
        assert not failures


@pytest.fixture
def observation_clock(monkeypatch):
    now = [float(int(time.time() // 3600) * 3600 + 60)]
    # Only the reporter's observation clock is controlled; sockets, waits and
    # deadlines use real wall/monotonic time and server writes use real SQLite.
    monkeypatch.setattr(
        edge,
        "time",
        SimpleNamespace(
            time=lambda: now[0], monotonic=time.monotonic, sleep=time.sleep
        ),
    )
    for name in (
        "MLRF_CA_CERT",
        "MLRF_CA_BUNDLE",
        "MLRF_INSECURE_TLS",
        "MLRF_CLIENT_CERT",
        "MLRF_CLIENT_KEY",
        "BRIDGE_CA_BUNDLE",
    ):
        monkeypatch.delenv(name, raising=False)
    return now


def record(reporter, signal_class="bpsk"):
    assert reporter.report(
        {"class": signal_class, "confidence": 0.95, "family": "PSK"},
        915_000_000,
        15,
        -55,
    )


@pytest.mark.parametrize("first_outcome", ["reject", "lost-response"])
def test_closed_hour_survives_transport_failure_and_replay_is_replacement(
    tmp_path, observation_clock, first_outcome
):
    with summary_endpoint(tmp_path, first_outcome) as (url, store, received, first):
        reporter = edge.DetectionReporter(
            url,
            "software-recovery-key",
            "software-recovery-node",
            summarize=True,
            data_dir=tmp_path / "edge-data",
            min_confidence=0,
            min_snr_db=0,
            dedup_window_seconds=0,
            repeat_report_interval=1,
            flush_interval_seconds=0.01,
        )
        current_hour = observation_clock[0]
        observation_clock[0] -= 3600
        record(reporter)
        observation_clock[0] = current_hour
        record(reporter)  # Both cumulative hours must survive delivery failure.
        reporter.start()
        try:
            assert first.wait(timeout=2), "Closed hour must reach the real HTTP server"
            closed = received[0]["summaries"][0]["hour"]
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                retried = [p for p in received if p["summaries"][0]["hour"] == closed]
                rows = store.get_summaries()
                if len(retried) >= 2 and len(rows) == 2:
                    break
                time.sleep(0.01)
            assert len(retried) >= 2, (
                "Failed closed hour was discarded instead of retried"
            )
            assert retried[0] == retried[1], (
                "Ambiguous completion must retry identical data"
            )
            assert len(rows) == 2
            assert sorted(row["detection_count"] for row in rows) == [1, 1]
        finally:
            reporter.stop()
        assert sum(row["detection_count"] for row in store.get_summaries()) == 2


def test_late_hour_record_does_not_replace_the_previous_cumulative_count(
    tmp_path, observation_clock
):
    with summary_endpoint(tmp_path, "success") as (url, store, received, first):
        reporter = edge.DetectionReporter(
            url,
            "software-recovery-key",
            "software-recovery-node",
            summarize=True,
            data_dir=tmp_path / "edge-data",
            min_confidence=0,
            min_snr_db=0,
            dedup_window_seconds=0,
            repeat_report_interval=1,
            flush_interval_seconds=0.01,
        )
        current = observation_clock[0]
        observation_clock[0] = current - 3600
        record(reporter)
        observation_clock[0] += 0.01
        record(reporter)
        observation_clock[0] = current
        record(reporter, "qpsk")
        reporter.start()
        try:
            assert first.wait(timeout=2)
            old_hour = received[0]["summaries"][0]["hour"]
            initial = {
                row["hour"]: row["detection_count"] for row in store.get_summaries()
            }
            assert initial[old_hour] == 2
            # Observation timestamps can arrive in this order when report()
            # callers overlap an hour boundary, or the host clock moves back.
            observation_clock[0] = current - 61
            record(reporter)
            observation_clock[0] = current + 0.01
            record(reporter, "qpsk")
            deadline = time.monotonic() + 2
            while len(received) < 3 and time.monotonic() < deadline:
                time.sleep(0.01)
            reporter.stop()
            final = {
                row["hour"]: row["detection_count"] for row in store.get_summaries()
            }
            assert final[old_hour] == 3, (
                "A reopened hour replaced the earlier cumulative count"
            )
            assert sum(final.values()) == 5
        finally:
            reporter.stop()


def make_reporter(url, data_dir, **options):
    defaults = dict(
        summarize=True,
        data_dir=data_dir,
        min_confidence=0,
        min_snr_db=0,
        dedup_window_seconds=0,
        repeat_report_interval=1,
        flush_interval_seconds=0.01,
    )
    defaults.update(options)
    return edge.DetectionReporter(
        url, "software-recovery-key", "software-recovery-node", **defaults
    )


@pytest.mark.parametrize("first_outcome", ["success", "reject", "lost-response"])
def test_inflight_generation_never_overwrites_newer_data_during_concurrent_stop(
    tmp_path, observation_clock, first_outcome
):
    entered, release = threading.Event(), threading.Event()
    with summary_endpoint(tmp_path, first_outcome, gate=(entered, release)) as (
        url,
        store,
        received,
        _,
    ):
        reporter = make_reporter(url, tmp_path / "edge-data")
        record(reporter)
        reporter.start()
        errors = []

        def run(operation):
            try:
                operation()
            except BaseException as exc:
                errors.append(type(exc).__name__)

        admitted = threading.Event()

        def admit():
            observation_clock[0] += 0.01
            record(reporter)
            admitted.set()

        threads = []
        try:
            assert entered.wait(timeout=2)
            threads.append(threading.Thread(target=lambda: run(admit), daemon=True))
            threads[-1].start()
            # A real blocked HTTP request must not hold the report/admission lock.
            assert admitted.wait(timeout=1)
            threads.append(
                threading.Thread(target=lambda: run(reporter.stop), daemon=True)
            )
            threads[-1].start()
        finally:
            release.set()
            for thread in threads:
                thread.join(timeout=5)
            reporter.stop()
        assert not any(thread.is_alive() for thread in threads)
        assert errors == []
        counts = [p["summaries"][0]["detection_count"] for p in received]
        assert counts == [1, 2]
        assert store.get_summaries()[0]["detection_count"] == 2
        assert reporter.get_stats()["summary_pending_hours"] == 0


def test_twenty_four_contiguous_hours_retire_only_acknowledged_history(
    tmp_path, observation_clock
):
    with summary_endpoint(tmp_path, "success") as (url, store, received, _):
        reporter = make_reporter(url, tmp_path / "edge-data")
        first_hour = observation_clock[0]
        for hour in range(25):
            observation_clock[0] = first_hour + hour * 3600
            record(reporter)
            reporter.stop()
        stats = reporter.get_stats()
        assert stats["summary_retained_hours"] == 24
        assert stats["summary_pending_hours"] == 0
        assert len(received) == 25
        assert len(store.get_summaries()) == 25
        # Exactly the first hour is expired; it cannot reopen from an empty bin.
        observation_clock[0] = first_hour
        assert not reporter.report(
            {"class": "qpsk", "confidence": 0.95}, 915e6, 15, -55
        )
        assert reporter.get_stats()["summary_rejections"] == {"too_old": 1}
        observation_clock[0] = first_hour + 3600 + 1
        # A distinct class avoids the independent same-class sliding dedup
        # policy when observation time moves backward.
        record(reporter, "qpsk")
        reporter.stop()
        rows = store.get_summaries()
        assert len({row["hour"] for row in rows}) == 25
        assert sum(row["detection_count"] for row in rows) == 26


def test_unacknowledged_expired_hour_applies_backpressure_without_poisoning_retry(
    tmp_path, observation_clock, caplog
):
    with summary_endpoint(tmp_path, "reject") as (url, store, received, _):
        reporter = make_reporter(
            url,
            tmp_path / "edge-data",
            dedup_window_seconds=30,
            repeat_report_interval=30,
        )
        record(reporter)
        reporter.stop()
        assert reporter.get_stats()["summary_pending_hours"] == 1
        observation_clock[0] += 24 * 3600
        # Rejection must not mark this class/frequency delivered or repeated.
        assert not reporter.report(
            {"class": "qpsk", "confidence": 0.95}, 916e6, 15, -55
        )
        stats = reporter.get_stats()
        assert stats["summary_retained_hours"] == 1
        assert stats["summary_rejections"] == {"backpressure": 1}
        assert "backpressure" in caplog.text
        reporter.stop()  # Same immutable old hour is retried and acknowledged.
        assert received[0] == received[1]
        assert reporter.report({"class": "qpsk", "confidence": 0.95}, 916e6, 15, -55)
        reporter.stop()
        assert len(store.get_summaries()) == 2
        assert reporter.get_stats()["summary_retained_hours"] == 1


def test_capacity_rejection_preserves_accepted_state_and_dedup_admission(
    tmp_path, observation_clock, caplog
):
    with summary_endpoint(tmp_path, "success") as (url, store, received, _):
        reporter = make_reporter(
            url,
            tmp_path / "edge-data",
            summary_max_bytes=2048,
            summary_anomaly_threshold=0,
            dedup_window_seconds=30,
            repeat_report_interval=30,
        )
        record(reporter)
        before = reporter.get_stats()
        assert not reporter.report(
            {"class": "qpsk", "confidence": 0.95},
            916e6,
            15,
            -55,
            decoded_messages=[{"protocol": "test", "payload_hex": "ab" * 3000}],
        )
        rejected = reporter.get_stats()
        assert rejected["summary_retained_bytes"] == before["summary_retained_bytes"]
        assert rejected["total_buffered"] == before["total_buffered"]
        assert rejected["summary_rejections"] == {"capacity": 1}
        assert "capacity" in caplog.text
        assert reporter.report({"class": "qpsk", "confidence": 0.95}, 916e6, 15, -55)
        reporter.stop()
        raw = received[0]["high_anomaly_detections"]
        assert [r["signal_class"] for r in raw] == ["bpsk", "qpsk"]
        assert len({r["id"] for r in raw}) == 2
        assert store.get_summaries() == []


def test_per_hour_body_cap_is_below_bridge_compressed_ingress_limit(
    observation_clock, tmp_path
):
    reporter = make_reporter(
        "http://127.0.0.1:1", tmp_path / "edge-data", summary_anomaly_threshold=0
    )
    assert not reporter.report(
        {"class": "bpsk", "confidence": 0.95},
        915e6,
        15,
        -55,
        decoded_messages=[{"protocol": "test", "payload_hex": "ab" * (256 * 1024)}],
    )
    assert reporter.get_stats()["summary_retained_bytes"] == 0
    assert reporter.get_stats()["summary_rejections"] == {"capacity": 1}


def test_encoded_bound_counts_unicode_node_metadata_and_all_retained_bodies(
    observation_clock,
):
    accumulator = edge._HourlyAccumulator(node_id="software-λ-雪", anomaly_threshold=0)
    for hour in range(2):
        assert accumulator.accumulate(
            {
                "id": f"stable-{hour}",
                "timestamp": observation_clock[0] + hour * 3600,
                "anomaly_score": 0,
                "decoded_messages": [{"text": 'λ雪"'}],
            }
        )
    bodies = [
        accumulator.pending_snapshot(hour)[1] for hour in accumulator.pending_hours()
    ]
    assert accumulator.stats()["summary_retained_bytes"] == sum(map(len, bodies))
    for body in bodies:
        assert json.loads(body)["node_id"] == "software-λ-雪"
        assert len(body) <= 512 * 1024
        assert len(gzip.compress(body)) < 1024 * 1024


def test_total_encoded_byte_budget_rejects_new_hour_without_retiring_pending_state(
    observation_clock,
):
    accumulator = edge._HourlyAccumulator(node_id="budget-node", max_bytes=512)
    row = {
        "timestamp": observation_clock[0],
        "signal_class": "bpsk",
        "family": "PSK",
        "freq_hz": 915e6,
        "confidence": 0.9,
    }
    assert accumulator.accumulate(row)
    original = accumulator.snapshot()
    before = accumulator.stats()["summary_retained_bytes"]
    # Each individual hour fits, but their combined complete wire bodies do not.
    row["timestamp"] += 3600
    assert not accumulator.accumulate(row)
    assert accumulator.snapshot() == original
    assert accumulator.stats()["summary_retained_bytes"] == before
    assert accumulator.stats()["summary_rejections"] == {"capacity": 1}


def test_entry_count_limit_and_acknowledged_expiry_leave_pending_counts_intact(
    observation_clock,
):
    accumulator = edge._HourlyAccumulator(
        node_id="entry-bound-node", anomaly_threshold=0
    )
    for index in range(16_384):
        hour = index // 700
        assert accumulator.accumulate(
            {
                "id": str(index),
                "timestamp": observation_clock[0] + hour * 3600,
                "node_id": "entry-bound-node",
                "signal_class": "bpsk",
                "family": "PSK",
                "confidence": 0.9,
                "freq_hz": 915e6,
                "snr_db": 15,
                "power_dbm": -55,
            }
        )
    before = accumulator.stats()
    assert before["summary_retained_entries"] == 16_384
    assert before["summary_retained_bytes"] < 8 * 1024 * 1024
    assert not accumulator.accumulate(
        {"id": "overflow", "timestamp": observation_clock[0] + 23 * 3600}
    )
    assert accumulator.stats()["summary_retained_entries"] == 16_384
    first_hour = accumulator.pending_hours()[0]
    generation, body = accumulator.pending_snapshot(first_hour)
    accumulator.acknowledge(first_hour, generation)
    assert accumulator.accumulate(
        {"id": "after-expiry", "timestamp": observation_clock[0] + 24 * 3600}
    )
    assert accumulator.stats()["summary_retained_entries"] == 16_384 - 700 + 1
    assert len(json.loads(body)["high_anomaly_detections"]) == 700


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), "not-a-time", None])
def test_invalid_observation_does_not_corrupt_retained_hour(
    timestamp, observation_clock
):
    accumulator = edge._HourlyAccumulator(node_id="validation-node")
    assert accumulator.accumulate(
        {"timestamp": observation_clock[0], "confidence": 0.9}
    )
    before = accumulator.snapshot()
    assert not accumulator.accumulate({"timestamp": timestamp})
    assert accumulator.snapshot() == before
    assert accumulator.stats()["summary_rejections"] == {"invalid": 1}


def test_rejected_same_bin_update_cannot_partially_increment_prior_snapshot(
    observation_clock,
):
    row = {
        "timestamp": observation_clock[0],
        "signal_class": "bpsk",
        "family": "PSK",
        "freq_hz": 915e6,
        "confidence": 0.9,
    }
    reference = edge._HourlyAccumulator(node_id="exact-budget")
    assert reference.accumulate(row)
    exact_bytes = reference.stats()["summary_retained_bytes"]
    accumulator = edge._HourlyAccumulator(node_id="exact-budget", max_bytes=exact_bytes)
    assert accumulator.accumulate(row)
    before = accumulator.snapshot()
    row["confidence"] = 0.9876  # Same bin needs more encoded numeric digits.
    assert not accumulator.accumulate(row)
    assert accumulator.snapshot() == before
    assert accumulator.stats()["summary_retained_bytes"] == exact_bytes
    assert accumulator.stats()["summary_rejections"] == {"capacity": 1}


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
