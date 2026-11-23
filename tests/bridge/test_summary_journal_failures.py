"""Real path, SQLite and lifecycle failures preserve journal identity and contents."""

import json
import os

import pytest

from sigrift.edge.detection_reporter import _HourlyAccumulator
from sigrift.edge.summary_journal import SummaryJournal


RECEIVER = "https://example.invalid"
NODE = "synthetic-node"


def observation():
    return {
        "id": "synthetic-observation",
        "node_id": NODE,
        "timestamp": 1_794_052_860,
        "signal_class": "bpsk",
        "family": "PSK",
        "freq_hz": 915_000_000,
        "confidence": 0.8,
        "snr_db": 12,
        "power_dbm": -50,
        "anomaly_score": 0.1,
    }


@pytest.mark.parametrize("data_dir", [None, ""])
def test_missing_persistent_directory_is_refused(data_dir):
    with pytest.raises(ValueError, match="persistent data_dir"):
        SummaryJournal(data_dir, RECEIVER, NODE)


@pytest.mark.parametrize(
    "receiver",
    [
        "file:///tmp/receiver",
        "https:///missing-host",
        "https://user:synthetic-password@example.invalid",
        "https://example.invalid?credential=synthetic",
        "https://example.invalid#fragment",
    ],
)
def test_invalid_receiver_does_not_create_journal(tmp_path, receiver):
    with pytest.raises(ValueError, match=r"HTTP\(S\)"):
        SummaryJournal(tmp_path, receiver, NODE)
    assert list(tmp_path.iterdir()) == []


def test_ipv6_canonical_destination_reopens_same_identity(tmp_path):
    first = SummaryJournal(tmp_path, "https://[2001:db8::A]:443/bridge/", NODE)
    identity = first.stream_id
    first.close()
    same = SummaryJournal(tmp_path, "https://[2001:db8::a]/bridge", NODE)
    try:
        assert same.stream_id == identity
    finally:
        same.close()
    with pytest.raises(ValueError, match="identity mismatch"):
        SummaryJournal(tmp_path, "https://[2001:db8::a]:8443/bridge", NODE)
    recovered = SummaryJournal(tmp_path, "https://[2001:db8::a]/bridge/", NODE)
    try:
        assert recovered.stream_id == identity
    finally:
        recovered.close()


@pytest.mark.parametrize("target", ["directory", "lock", "database"])
def test_writable_paths_are_refused_without_replacing_retained_state(tmp_path, target):
    journal = SummaryJournal(tmp_path, RECEIVER, NODE)
    accumulator = _HourlyAccumulator(node_id=NODE, journal=journal)
    assert accumulator.accumulate(observation())
    expected = journal.load()
    identity = journal.stream_id
    journal.close()
    root = tmp_path / "summary-journal"
    path = {
        "directory": root,
        "lock": root / "writer.lock",
        "database": root / "summary.sqlite3",
    }[target]
    original_mode = path.stat().st_mode & 0o777
    original_bytes = None if path.is_dir() else path.read_bytes()
    path.chmod(original_mode | 0o020)
    try:
        with pytest.raises(ValueError, match="owned|Unsafe"):
            SummaryJournal(tmp_path, RECEIVER, NODE)
        assert path.stat().st_mode & 0o020
        if original_bytes is not None:
            assert path.read_bytes() == original_bytes
    finally:
        path.chmod(original_mode)
    reopened = SummaryJournal(tmp_path, RECEIVER, NODE)
    try:
        assert reopened.stream_id == identity
        assert reopened.load() == expected
    finally:
        reopened.close()


@pytest.mark.parametrize("target", ["writer.lock", "summary.sqlite3"])
def test_nonregular_file_is_refused_and_owned_lock_released(tmp_path, target):
    root = tmp_path / "summary-journal"
    root.mkdir(mode=0o700)
    path = root / target
    os.mkfifo(path, 0o600)
    try:
        with pytest.raises(ValueError, match="Unsafe"):
            SummaryJournal(tmp_path, RECEIVER, NODE)
        assert path.is_fifo()
    finally:
        path.unlink()
    repaired = SummaryJournal(tmp_path, RECEIVER, NODE)
    try:
        assert repaired.load() == (None, [], [], [])
    finally:
        repaired.close()


@pytest.mark.parametrize("invalid", ["missing_hour", "negative", "future"])
def test_invalid_acknowledgement_rolls_back_and_allows_valid_retry(tmp_path, invalid):
    journal = SummaryJournal(tmp_path, RECEIVER, NODE)
    accumulator = _HourlyAccumulator(node_id=NODE, journal=journal)
    try:
        assert accumulator.accumulate(observation())
        hour = accumulator.pending_hours()[0]
        generation, body = accumulator.pending_snapshot(hour)
        before = journal.load()
        wrong_hour = hour + 1 if invalid == "missing_hour" else hour
        wrong_generation = {
            "missing_hour": generation,
            "negative": -1,
            "future": generation + 1,
        }[invalid]
        with pytest.raises(ValueError, match="acknowledgement"):
            journal.acknowledge(wrong_hour, wrong_generation)
        assert journal.load() == before
        accumulator.acknowledge(hour, generation)
        assert accumulator.pending_hours() == []
    finally:
        journal.close()
    reopened = SummaryJournal(tmp_path, RECEIVER, NODE)
    try:
        restored = _HourlyAccumulator(node_id=NODE, journal=reopened)
        assert restored.pending_hours() == []
        assert restored.snapshot()["summaries"] == json.loads(body)["summaries"]
    finally:
        reopened.close()


def test_closed_journal_cannot_be_used_and_reopen_keeps_committed_observation(tmp_path):
    journal = SummaryJournal(tmp_path, RECEIVER, NODE)
    accumulator = _HourlyAccumulator(node_id=NODE, journal=journal)
    assert accumulator.accumulate(observation())
    before, identity = journal.load(), journal.stream_id
    journal.close()
    journal.close()  # Disposal is idempotent; operations after it are not allowed.
    with pytest.raises(RuntimeError, match="closed"):
        journal.load()
    with pytest.raises(RuntimeError, match="closed"):
        journal.acknowledge(0, 0)
    reopened = SummaryJournal(tmp_path, RECEIVER, NODE)
    try:
        assert reopened.stream_id == identity
        assert reopened.load() == before
    finally:
        reopened.close()
