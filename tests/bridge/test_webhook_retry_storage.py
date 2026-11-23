"""Real SQLite and separate-process ownership for durable failed deliveries."""

from __future__ import annotations

import json
import subprocess
import sys
import time

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore


@pytest.fixture
def queue(tmp_path):
    ctx = SharedContext(tmp_path / "queue.db")
    try:
        yield WebhookRetryStore(ctx, max_entries=3, max_bytes=1024, max_payload=512)
    finally:
        ctx.close()


def _put(queue, ident="delivery-1", *, now=1000, data=b'{"event":"one"}'):
    return queue.enqueue(ident, "hook-1", "binding-1", data, now=now, delay=5)


def test_additive_retry_schema_preserves_existing_records_and_reopens(tmp_path):
    path = tmp_path / "existing.db"
    ctx = SharedContext(path)
    try:
        with ctx.write_transaction(immediate=True) as conn:
            conn.execute(
                "INSERT INTO detections(detection_id,node_id,timestamp,signal_class,confidence) "
                "VALUES ('retained','node','2026-11-07T12:00:00Z','16qam',0.95)"
            )
            cursor = conn.execute(
                "INSERT INTO users(username,password_hash,salt,created_at) VALUES (?,?,?,?)",
                (
                    "existing",
                    b"synthetic-hash\x00",
                    b"synthetic-salt\xff",
                    "2026-11-07T12:00:00Z",
                ),
            )
            conn.execute(
                "INSERT INTO sessions(session_token,user_id,created_at,expires_at) VALUES (?,?,?,?)",
                (
                    "synthetic-existing-session",
                    cursor.lastrowid,
                    "2026-11-07T12:00:00Z",
                    "2026-11-08T12:00:00Z",
                ),
            )
        tables = ("detections", "users", "sessions")
        before = {
            table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table}")]
            for table in tables
        }
        assert not conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name='webhook_retries'"
        ).fetchall()
        queue = WebhookRetryStore(ctx)
        assert _put(queue)
        assert {
            table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table}")]
            for table in tables
        } == before
    finally:
        ctx.close()
    reopened = SharedContext(path)
    try:
        queue = WebhookRetryStore(reopened)
        assert len(queue.snapshot()["entries"]) == 1
        assert {
            table: [
                tuple(row)
                for row in reopened.get_conn().execute(f"SELECT * FROM {table}")
            ]
            for table in tables
        } == before
        assert reopened.get_conn().execute("PRAGMA foreign_key_check").fetchall() == []
        assert (
            reopened.get_conn().execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        )
    finally:
        reopened.close()


def test_reopen_retains_exact_payload_due_attempts_and_tenant(queue):
    assert _put(queue)
    ctx = SharedContext(queue._ctx._db_path)
    foreign_ctx = SharedContext(queue._ctx._db_path, tenant_id="other")
    try:
        again = WebhookRetryStore(ctx)
        row = again.snapshot()["entries"][0]
        assert row["payload"] == b'{"event":"one"}'
        assert row["delivery_id"] == "delivery-1"
        assert row["attempts"] == 1
        assert row["due_at"] == 1005
        assert again.claim(now=1004, lease_seconds=30) is None
        assert WebhookRetryStore(foreign_ctx).snapshot()["entries"] == []
    finally:
        ctx.close()
        foreign_ctx.close()


_CLAIM_CHILD = """
import json, pathlib, sys, time
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore
ctx = SharedContext(sys.argv[1])
marker = pathlib.Path(sys.argv[2])
start = pathlib.Path(sys.argv[3])
try:
    store = WebhookRetryStore(ctx)
    marker.with_suffix('.ready').touch()
    deadline = time.monotonic() + 15
    while not start.exists():
        assert time.monotonic() < deadline
        time.sleep(.01)
    row = store.claim(now=1005, lease_seconds=30)
    marker.write_text(json.dumps(None if row is None else {'delivery_id':row['delivery_id'],'lease_token':row['lease_token']}))
    if sys.argv[4] == 'hold':
        while time.monotonic() < deadline:
            time.sleep(.01)
finally:
    ctx.close()
"""


def _wait_path(path):
    deadline = time.monotonic() + 10
    while not path.exists():
        assert time.monotonic() < deadline, "Child did not reach its barrier"
        time.sleep(0.01)


def test_two_real_processes_cannot_claim_one_live_lease(queue, tmp_path):
    assert _put(queue)
    start = tmp_path / "start"
    markers = [tmp_path / f"claim-{index}.json" for index in range(2)]
    children = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                _CLAIM_CHILD,
                queue._ctx._db_path,
                str(marker),
                str(start),
                "exit",
            ]
        )
        for marker in markers
    ]
    try:
        for marker in markers:
            _wait_path(marker.with_suffix(".ready"))
        start.touch()
        for child in children:
            assert child.wait(timeout=10) == 0
        claims = [json.loads(marker.read_text()) for marker in markers]
        assert sum(row is not None for row in claims) == 1
        assert queue.claim(now=1034, lease_seconds=30) is None
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)


def test_killed_owner_lease_recovers_after_expiry_without_startup_reset(
    queue, tmp_path
):
    assert _put(queue)
    marker, start = tmp_path / "claimed.json", tmp_path / "start"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _CLAIM_CHILD,
            queue._ctx._db_path,
            str(marker),
            str(start),
            "hold",
        ]
    )
    try:
        _wait_path(marker.with_suffix(".ready"))
        start.touch()
        _wait_path(marker)
        old = json.loads(marker.read_text())
        assert old["delivery_id"] == "delivery-1"
        child.kill()
        assert child.wait(timeout=5) != 0
        reopened = WebhookRetryStore(queue._ctx)
        assert reopened.claim(now=1034, lease_seconds=30) is None
        new = reopened.claim(now=1035, lease_seconds=30)
        assert new["lease_token"] != old["lease_token"]
        assert new["attempts"] == 1
        assert not reopened.ack(old, now=1036)
        assert reopened.ack(new, now=1036)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)


def test_expired_owner_cannot_ack_or_fail_reclaimed_delivery(queue):
    assert _put(queue)
    old = queue.claim(now=1005, lease_seconds=30)
    new = queue.claim(now=1035, lease_seconds=30)
    assert old["lease_token"] != new["lease_token"]
    assert not queue.ack(old, now=1036)
    assert not queue.fail(
        old, now=1036, delay=20, max_attempts=5, category="http_error"
    )
    assert not queue.release(old)
    assert queue.snapshot()["entries"][0]["attempts"] == 1
    assert queue.ack(new, now=1036)
    assert not queue.fail(
        old, now=1037, delay=20, max_attempts=5, category="http_error"
    )
    assert queue.snapshot()["entries"] == []


def test_release_does_not_consume_attempt_or_due_and_startup_preserves_lease(queue):
    assert _put(queue)
    claim = queue.claim(now=1005, lease_seconds=30)
    same = WebhookRetryStore(queue._ctx)
    assert same.claim(now=1006, lease_seconds=30) is None
    assert same.renew(claim, now=1010, lease_seconds=30)
    assert same.claim(now=1039, lease_seconds=30) is None
    assert same.release(claim)
    retried = same.claim(now=1011, lease_seconds=30)
    assert retried["attempts"] == 1
    assert retried["due_at"] == 1005


def test_capacity_rejection_preserves_pending_and_is_counted(queue):
    for i in range(3):
        assert _put(queue, f"d-{i}")
    claim = queue.claim(now=1005, lease_seconds=30)
    assert not _put(queue, "excess")
    assert len(queue.snapshot()["entries"]) == 3
    assert queue.snapshot()["dropped"] == 1
    assert queue.ack(claim, now=1006)
    assert _put(queue, "excess")


def test_byte_limits_count_encoded_payload_not_characters(queue):
    assert not _put(queue, data=("é" * 257).encode())
    assert queue.snapshot()["dropped"] == 1
    assert _put(queue, "a", data=b"x" * 512)
    assert _put(queue, "b", data=b"x" * 512)
    assert not _put(queue, "c", data=b"x")
    assert queue.snapshot()["dropped"] == 2


def test_failed_insert_rolls_back_without_false_queued_state(queue):
    queue._ctx.get_conn().executescript(
        "CREATE TRIGGER fail_retry BEFORE INSERT ON webhook_retries "
        "BEGIN SELECT RAISE(ABORT, 'real injected failure'); END;"
    )
    with pytest.raises(Exception, match="real injected failure"):
        _put(queue)
    assert queue.snapshot()["entries"] == []
    queue._ctx.get_conn().execute("DROP TRIGGER fail_retry")
    assert _put(queue)


def test_failure_backoff_terminal_drop_and_stale_fencing(queue):
    assert _put(queue)
    claim = queue.claim(now=1005, lease_seconds=30)
    assert queue.fail(claim, now=1006, delay=20, max_attempts=3, category="http_error")
    assert queue.claim(now=1025, lease_seconds=30) is None
    row = queue.claim(now=1026, lease_seconds=30)
    assert row["attempts"] == 2
    assert queue.fail(
        row, now=1027, delay=40, max_attempts=3, category="transport_error"
    )
    assert queue.snapshot()["entries"] == []
    assert queue.snapshot()["dropped"] == 1


def test_clock_values_must_be_finite_and_due_survives_wall_clock_change(queue):
    with pytest.raises(ValueError):
        _put(queue, now=float("nan"))
    assert _put(queue, now=time.time())
    row = queue.snapshot()["entries"][0]
    assert queue.claim(now=row["due_at"] - 1000, lease_seconds=30) is None
    assert queue.claim(now=row["due_at"] + 1000, lease_seconds=30) is not None
