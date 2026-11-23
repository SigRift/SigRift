"""Real filesystem/SQLite/process proofs for admitted RF summary state."""

import json
import sqlite3
import subprocess
import sys
import time

import pytest

from sigrift.edge.detection_reporter import _HourlyAccumulator
from sigrift.edge.summary_journal import SummaryJournal


def record(timestamp, confidence=0.75, **extra):
    return {
        "id": f"sample-{timestamp}",
        "node_id": "node-1",
        "timestamp": timestamp,
        "signal_class": "bpsk",
        "family": "PSK",
        "freq_hz": 915e6,
        "confidence": confidence,
        "snr_db": 12,
        "power_dbm": -50,
        "anomaly_score": 0.1,
        **extra,
    }


def opened(path, **kwargs):
    journal = SummaryJournal(path, "https://example.invalid:443/", "node-1")
    try:
        accumulator = _HourlyAccumulator(node_id="node-1", journal=journal, **kwargs)
    except BaseException:
        journal.close()
        raise
    return journal, accumulator


def test_acknowledged_exact_statistics_and_raw_bytes_survive_reopen(tmp_path):
    now = int(time.time() // 3600) * 3600 + 60
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.accumulate(record(now, 0.701234, snr_db=None))
        assert accumulator.accumulate(record(now + 1, 0.912345, power_dbm=None))
        assert accumulator.accumulate(record(now + 2, 0.8, anomaly_score=0.95))
        hour = accumulator.pending_hours()[0]
        gen, body = accumulator.pending_snapshot(hour)
        accumulator.acknowledge(hour, gen)
        stream = journal.stream_id
    finally:
        journal.close()
    journal, accumulator = opened(tmp_path)
    try:
        assert journal.stream_id == stream
        assert accumulator.pending_hours() == []
        assert accumulator._body(accumulator._hours[hour], hour) == body
        assert accumulator.accumulate(record(now + 3, 0.834567))
        _, updated = accumulator.pending_snapshot(hour)
        result = json.loads(updated)
        summary = result["summaries"][0]
        assert summary["detection_count"] == 3
        assert summary["avg_confidence"] == round(
            (0.701234 + 0.912345 + 0.834567) / 3, 4
        )
        assert summary["avg_snr_db"] == 12
        assert summary["avg_power_dbm"] == -50
        assert result["high_anomaly_detections"] == [
            record(now + 2, 0.8, anomaly_score=0.95)
        ]
        assert result["generation"] == 4
    finally:
        journal.close()


def test_observation_commit_failure_preserves_previous_state_and_can_retry(tmp_path):
    journal, accumulator = opened(tmp_path)
    now = time.time()
    try:
        assert accumulator.accumulate(record(now))
        previous = accumulator.snapshot()
        journal._conn.execute(
            "CREATE TRIGGER reject_write BEFORE UPDATE ON bins BEGIN SELECT RAISE(ABORT,'injected real storage failure'); END"
        )
        assert accumulator.accumulate(record(now + 0.01)) is False
        assert accumulator.snapshot() == previous
        assert accumulator.stats()["summary_rejections"] == {"storage": 1}
        journal._conn.execute("DROP TRIGGER reject_write")
        assert accumulator.accumulate(record(now + 0.01))
        assert accumulator.snapshot()["summaries"][0]["detection_count"] == 2
    finally:
        journal.close()
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.snapshot()["summaries"][0]["detection_count"] == 2
    finally:
        journal.close()


def test_ack_commit_failure_remains_pending_after_reopen(tmp_path):
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.accumulate(record(time.time()))
        hour = accumulator.pending_hours()[0]
        generation, body = accumulator.pending_snapshot(hour)
        journal._conn.execute(
            "CREATE TRIGGER reject_ack BEFORE UPDATE OF acknowledged ON hours BEGIN SELECT RAISE(ABORT,'failed ack'); END"
        )
        with pytest.raises(sqlite3.IntegrityError):
            accumulator.acknowledge(hour, generation)
        assert accumulator.pending_snapshot(hour) == (generation, body)
        journal._conn.execute("DROP TRIGGER reject_ack")
    finally:
        journal.close()
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.pending_snapshot(hour) == (generation, body)
        accumulator.acknowledge(hour, generation)
        assert not accumulator.pending_hours()
    finally:
        journal.close()


@pytest.mark.parametrize(
    "receiver,node",
    [("https://other.invalid", "node-1"), ("https://example.invalid", "node-2")],
)
def test_changed_identity_preserves_journal_and_fails(tmp_path, receiver, node):
    journal = SummaryJournal(tmp_path, "https://example.invalid", "node-1")
    stream = journal.stream_id
    journal.close()
    with pytest.raises(ValueError, match="identity mismatch"):
        SummaryJournal(tmp_path, receiver, node)
    journal = SummaryJournal(tmp_path, "https://example.invalid", "node-1")
    try:
        assert journal.stream_id == stream
    finally:
        journal.close()


def test_real_second_process_cannot_claim_live_journal_but_can_after_close(tmp_path):
    journal = SummaryJournal(tmp_path, "https://example.invalid", "node-1")
    code = "from sigrift.edge.summary_journal import SummaryJournal; import sys; j=SummaryJournal(sys.argv[1], 'https://example.invalid', 'node-1'); print(j.stream_id); j.close()"
    command = [sys.executable, "-c", code, str(tmp_path)]
    try:
        first = subprocess.run(command, capture_output=True, text=True, timeout=5)
        assert first.returncode != 0
        assert "BlockingIOError" in first.stderr
        stream = journal.stream_id
    finally:
        journal.close()
    second = subprocess.run(command, capture_output=True, text=True, timeout=5)
    assert second.returncode == 0, second.stderr
    assert second.stdout.strip() == stream


def test_corruption_and_symlink_are_not_silently_replaced(tmp_path):
    root = tmp_path / "summary-journal"
    root.mkdir(mode=0o700)
    target = tmp_path / "outside"
    target.write_bytes(b"preserve")
    path = root / "summary.sqlite3"
    path.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        SummaryJournal(tmp_path, "https://example.invalid", "node-1")
    assert target.read_bytes() == b"preserve"
    path.unlink()
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(sqlite3.DatabaseError):
        SummaryJournal(tmp_path, "https://example.invalid", "node-1")
    assert path.read_bytes() == b"not a sqlite database"


def test_pending_retention_cannot_be_evicted_and_acknowledged_history_can(tmp_path):
    journal, accumulator = opened(tmp_path, hours=2)
    now = int(time.time() // 3600) * 3600 + 60
    try:
        assert accumulator.accumulate(record(now))
        hour = accumulator.pending_hours()[0]
        assert accumulator.accumulate(record(now + 7200)) is False
        accumulator.acknowledge(hour, 1)
        assert accumulator.accumulate(record(now + 7200))
    finally:
        journal.close()

    journal, accumulator = opened(tmp_path, hours=2)
    try:
        assert accumulator.stats()["summary_retained_hours"] == 1
        assert accumulator.pending_hours() == [hour + 2]
    finally:
        journal.close()


def test_real_sqlite_capacity_failure_preserves_admission_and_can_retry(tmp_path):
    journal, accumulator = opened(tmp_path)
    now = time.time()
    try:
        assert accumulator.accumulate(record(now))
        before = accumulator.snapshot()
        # SQLite's actual page cap deterministically represents unavailable
        # storage; no replacement of execute/commit or the admission algorithm.
        journal._conn.execute("PRAGMA max_page_count=64")
        journal._conn.execute("CREATE TABLE filler (data BLOB)")
        with pytest.raises(sqlite3.OperationalError, match="full"):
            for _ in range(100):
                journal._conn.execute("INSERT INTO filler VALUES (zeroblob(4096))")
        large = record(
            now + 0.01,
            anomaly_score=0.99,
            decoded_messages=[{"payload_hex": "ab" * 16000}],
        )
        assert accumulator.accumulate(large) is False
        assert accumulator.snapshot() == before
        journal._conn.execute("DROP TABLE filler")
        assert accumulator.accumulate(large)
    finally:
        journal.close()
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.snapshot()["high_anomaly_detections"] == [large]
        assert accumulator.snapshot()["summaries"] == before["summaries"]
    finally:
        journal.close()


@pytest.mark.parametrize(
    "kind", ["empty", "unrelated", "missing_identity", "bad_stream"]
)
def test_existing_incomplete_database_cannot_silently_create_new_identity(
    tmp_path, kind
):
    root = tmp_path / "summary-journal"
    root.mkdir(mode=0o700)
    path = root / "summary.sqlite3"
    if kind in {"empty", "unrelated"}:
        with sqlite3.connect(path) as conn:
            if kind == "unrelated":
                conn.execute("CREATE TABLE owned_payload(value TEXT)")
                conn.execute("INSERT INTO owned_payload VALUES ('preserve')")
    else:
        journal, _ = opened(tmp_path)
        journal.close()
        with sqlite3.connect(path) as conn:
            if kind == "missing_identity":
                conn.execute("DELETE FROM metadata")
            else:
                conn.execute("UPDATE metadata SET stream=?", ("!" * 32,))
    with pytest.raises(ValueError, match="Incomplete|identity mismatch"):
        opened(tmp_path)
    with sqlite3.connect(path) as conn:
        if kind == "unrelated":
            assert conn.execute("SELECT value FROM owned_payload").fetchall() == [
                ("preserve",)
            ]
        elif kind == "missing_identity":
            assert conn.execute("SELECT * FROM metadata").fetchall() == []
        elif kind == "bad_stream":
            assert conn.execute("SELECT stream FROM metadata").fetchone()[0] == "!" * 32


def test_reported_retained_bytes_include_exact_wire_envelopes(tmp_path):
    journal, accumulator = opened(tmp_path)
    now = int(time.time() // 3600) * 3600 + 60
    try:
        for hour in range(3):
            assert accumulator.accumulate(record(now + hour * 3600))
        bodies = [
            accumulator.pending_snapshot(hour)[1]
            for hour in accumulator.pending_hours()
        ]
        assert accumulator.stats()["summary_retained_bytes"] == sum(map(len, bodies))
        accumulator.acknowledge(accumulator.pending_hours()[0], 1)
        assert accumulator.stats()["summary_retained_bytes"] == sum(map(len, bodies))
    finally:
        journal.close()


@pytest.mark.parametrize(
    "change",
    [
        {"confidence": 1.1},
        {"confidence": float("nan")},
        {"anomaly_score": -1},
        {"freq_hz": -1},
        {"signal_class": "x" * 129},
        {"power_dbm": float("inf")},
        {"anomaly_score": 0.99, "id": ""},
    ],
)
def test_invalid_observation_cannot_pin_a_durable_hour(tmp_path, change):
    journal, accumulator = opened(tmp_path)
    now = time.time()
    try:
        assert accumulator.accumulate(record(now))
        before = accumulator.snapshot()
        assert accumulator.accumulate(record(now + 0.01, **change)) is False
        assert accumulator.snapshot() == before
        assert accumulator.accumulate(record(now + 0.02))
        assert accumulator.snapshot()["summaries"][0]["detection_count"] == 2
    finally:
        journal.close()


def test_forked_object_refuses_use_before_inherited_lock(tmp_path):
    # The subprocess owns both the fork and its held thread lock. A hang is
    # bounded by subprocess.run; no clock or lock implementation is replaced.
    code = r"""
import os, sys, threading
from sigrift.edge.summary_journal import SummaryJournal
journal=SummaryJournal(sys.argv[1], 'https://example.invalid', 'node-1')
held=threading.Event(); release=threading.Event()
def hold():
    with journal._lock:
        held.set(); release.wait(4)
worker=threading.Thread(target=hold); worker.start(); assert held.wait(1)
child=os.fork()
if child == 0:
    try:
        for operation in (journal.load, journal.close):
            try: operation()
            except RuntimeError as error: assert 'inherited' in str(error)
            else: os._exit(2)
        os._exit(0)
    except BaseException: os._exit(3)
try:
    _, status=os.waitpid(child,0)
    assert os.waitstatus_to_exitcode(status)==0
finally:
    release.set(); worker.join(1); journal.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=6,
    )
    assert result.returncode == 0, result.stderr
    journal, accumulator = opened(tmp_path)
    try:
        assert accumulator.snapshot() is None
    finally:
        journal.close()


@pytest.mark.parametrize("corruption", ["missing_raw_id", "invalid_confidence"])
def test_reopen_rejects_receiver_incompatible_retained_data_without_reset(
    tmp_path, corruption
):
    journal, accumulator = opened(tmp_path)
    now = time.time()
    assert accumulator.accumulate(record(now, anomaly_score=0.95))
    stream = journal.stream_id
    if corruption == "missing_raw_id":
        raw = record(now, anomaly_score=0.95)
        raw.pop("id")
        encoded = accumulator._encode(raw)
        old_size = journal._conn.execute("SELECT length(encoded) FROM raw").fetchone()[
            0
        ]
        journal._conn.execute("UPDATE raw SET encoded=?", (encoded,))
        journal._conn.execute(
            "UPDATE hours SET size=size+?", (len(encoded) - old_size,)
        )
    else:
        assert accumulator.accumulate(record(now + 0.01))
        hour, key, stats, encoded = journal._conn.execute(
            "SELECT hour,bin_key,stats,encoded FROM bins"
        ).fetchone()
        stats = json.loads(stats)
        stats.update(conf_sum=1.5, conf_min=1.5, conf_max=1.5)
        body = json.loads(encoded)
        body.update(avg_confidence=1.5, min_confidence=1.5, max_confidence=1.5)
        changed = accumulator._encode(body)
        journal._conn.execute(
            "UPDATE bins SET stats=?,encoded=?", (json.dumps(stats), changed)
        )
        journal._conn.execute(
            "UPDATE hours SET size=size+?", (len(changed) - len(encoded),)
        )
    journal.close()
    with pytest.raises(ValueError, match="RF summary|RF raw"):
        opened(tmp_path)
    with sqlite3.connect(tmp_path / "summary-journal" / "summary.sqlite3") as conn:
        assert conn.execute("SELECT stream FROM metadata").fetchone()[0] == stream
        assert conn.execute("SELECT COUNT(*) FROM raw").fetchone()[0] == 1


@pytest.mark.parametrize("signal_class", ["", "invalid class", "bpsk!"])
def test_sender_refuses_actual_bridge_rejected_high_anomaly_class(
    tmp_path, signal_class
):
    from pydantic import ValidationError
    from sigrift.bridge.models import DetectionRecord

    row = record(time.time(), signal_class=signal_class, anomaly_score=0.95)
    # Use the actual public request model as an independent acceptance oracle.
    with pytest.raises(ValidationError):
        DetectionRecord.model_validate(row)
    journal, accumulator = opened(tmp_path)
    try:
        assert not accumulator.accumulate(row)
        assert accumulator.snapshot() is None
        assert accumulator.accumulate(record(time.time(), anomaly_score=0.95))
    finally:
        journal.close()


@pytest.mark.parametrize("node", ["", "node with spaces", "n" * 65, "../node"])
def test_sender_refuses_node_identity_rejected_by_actual_bridge_model(tmp_path, node):
    from pydantic import ValidationError
    from sigrift.bridge.models import DetectionSummaryBatch

    with pytest.raises(ValidationError):
        DetectionSummaryBatch.model_validate({"node_id": node})
    with pytest.raises(ValueError, match="node identity"):
        SummaryJournal(tmp_path, "https://example.invalid", node)
    assert not (tmp_path / "summary-journal").exists()
