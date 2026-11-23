"""Queue admission failures preserve real SQLite state and caller ownership."""

from __future__ import annotations

import sqlite3

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.webhook_retries import WebhookRetryStore


PAYLOAD = b'{"delivery_id":"delivery","message":"synthetic"}'


@pytest.fixture
def context(tmp_path):
    ctx = SharedContext(tmp_path / "validation.db")
    try:
        yield ctx
    finally:
        ctx.close()


@pytest.fixture
def queue(context):
    return WebhookRetryStore(context, max_entries=1, max_bytes=len(PAYLOAD))


def admit(queue, **changes):
    values = {
        "delivery_id": "delivery",
        "webhook_id": "endpoint",
        "target_binding": "revision-binding",
        "payload": PAYLOAD,
        "now": 100,
        "delay": 5,
    }
    values.update(changes)
    return queue.enqueue(**values)


def test_schema_initialization_does_not_commit_or_rollback_callers_sql(context):
    conn = context.get_conn()
    conn.execute("CREATE TABLE caller_state (value TEXT)")
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("INSERT INTO caller_state VALUES ('uncommitted')")
    try:
        with pytest.raises(RuntimeError, match="existing transaction"):
            WebhookRetryStore(context)
        assert conn.in_transaction
        assert (
            conn.execute("SELECT value FROM caller_state").fetchone()[0]
            == "uncommitted"
        )
        with sqlite3.connect(context._db_path) as observer:
            assert observer.execute("SELECT * FROM caller_state").fetchall() == []
            assert (
                observer.execute(
                    "SELECT name FROM sqlite_master WHERE name='webhook_retries'"
                ).fetchall()
                == []
            )
    finally:
        conn.rollback()
    assert conn.execute("SELECT * FROM caller_state").fetchall() == []
    assert admit(WebhookRetryStore(context))


def test_schema_refuses_lazy_outer_scope_without_stealing_its_rollback(context):
    conn = context.get_conn()
    conn.execute("CREATE TABLE caller_state (value TEXT)")
    conn.commit()

    class CallerRollback(Exception):
        pass

    with pytest.raises(CallerRollback):
        with context.write_transaction() as owned:
            assert not owned.in_transaction
            with pytest.raises(RuntimeError, match="existing transaction"):
                WebhookRetryStore(context)
            owned.execute("INSERT INTO caller_state VALUES ('caller-owned')")
            raise CallerRollback
    assert not conn.in_transaction
    assert conn.execute("SELECT * FROM caller_state").fetchall() == []
    assert admit(WebhookRetryStore(context))


def test_exact_redelivery_at_full_capacity_preserves_attempt_due_and_live_owner(
    context, queue
):
    assert admit(queue)
    first = queue.claim(now=105, lease_seconds=20)
    assert queue.fail(first, now=106, delay=30, max_attempts=5, category="http_error")
    owner = queue.claim(now=136, lease_seconds=20)
    before = queue.snapshot()
    # A repeat enqueue must acknowledge the same work without resetting its
    # retry history, extending ownership or counting a capacity rejection.
    assert admit(queue, now=1000, delay=999)
    assert queue.snapshot() == before
    peer_context = SharedContext(context._db_path)
    try:
        peer = WebhookRetryStore(peer_context, max_entries=1, max_bytes=len(PAYLOAD))
        assert peer.snapshot() == before
        assert peer.claim(now=137, lease_seconds=20) is None
    finally:
        peer_context.close()
    assert queue.ack(owner, now=137)
    assert queue.snapshot() == {"entries": [], "dropped": 0}


@pytest.mark.parametrize(
    "change",
    [
        {"payload": b'{"message":"different"}'},
        {"target_binding": "different-revision"},
        {"webhook_id": "different-endpoint"},
    ],
    ids=["payload", "binding", "endpoint"],
)
def test_reused_delivery_id_cannot_overwrite_a_live_delivery(context, queue, change):
    assert admit(queue)
    owner = queue.claim(now=105, lease_seconds=20)
    before = queue.snapshot()
    with pytest.raises(ValueError, match="reused for different content"):
        admit(queue, **change)
    assert not context.get_conn().in_transaction
    assert queue.snapshot() == before
    assert queue.ack(owner, now=106)
    assert queue.snapshot() == {"entries": [], "dropped": 0}


@pytest.mark.parametrize(
    "payload",
    ["synthetic-secret", bytearray(PAYLOAD), memoryview(PAYLOAD), None],
    ids=["text", "mutable-bytes", "view", "absent"],
)
def test_nonbyte_payload_is_not_admitted_or_counted_as_capacity_loss(queue, payload):
    assert admit(queue)
    before = queue.snapshot()
    with pytest.raises(TypeError, match="must be bytes") as error:
        admit(queue, delivery_id="other", payload=payload)
    assert "synthetic-secret" not in str(error.value)
    assert queue.snapshot() == before


@pytest.mark.parametrize("field", ["delivery_id", "webhook_id", "target_binding"])
@pytest.mark.parametrize(
    "bad", ["", "x" * 129, None, 17], ids=["empty", "long", "null", "number"]
)
def test_invalid_identity_cannot_mutate_existing_queue(queue, field, bad):
    assert admit(queue)
    before = queue.snapshot()
    with pytest.raises(ValueError, match="Invalid bounded webhook delivery identity"):
        admit(queue, **{field: bad})
    assert queue.snapshot() == before


@pytest.mark.parametrize("length", [1, 128])
def test_identity_limits_accept_exact_boundary_and_survive_claim(queue, length):
    assert admit(
        queue,
        delivery_id="d" * length,
        webhook_id="h" * length,
        target_binding="b" * length,
    )
    owner = queue.claim(now=105, lease_seconds=20)
    assert owner["delivery_id"] == "d" * length
    assert owner["webhook_id"] == "h" * length
    assert owner["target_binding"] == "b" * length
    assert owner["payload"] == PAYLOAD
    assert queue.ack(owner, now=106)


@pytest.mark.parametrize(
    "lease",
    [0, -1, float("nan"), float("inf")],
    ids=["zero", "negative", "nan", "infinite"],
)
@pytest.mark.parametrize("operation", ["claim", "renew"])
def test_invalid_lease_does_not_acquire_or_change_ownership(queue, lease, operation):
    assert admit(queue)
    owner = queue.claim(now=105, lease_seconds=20) if operation == "renew" else None
    before = queue.snapshot()
    with pytest.raises(ValueError):
        if operation == "claim":
            queue.claim(now=110, lease_seconds=lease)
        else:
            queue.renew(owner, now=110, lease_seconds=lease)
    assert queue.snapshot() == before
    if owner is not None:
        assert queue.claim(now=124, lease_seconds=20) is None
        replacement = queue.claim(now=125, lease_seconds=20)
        assert replacement["lease_token"] != owner["lease_token"]
    else:
        replacement = queue.claim(now=110, lease_seconds=20)
    assert replacement["attempts"] == 1
    assert queue.ack(replacement, now=126 if owner else 111)


@pytest.mark.parametrize(
    "category",
    [
        "raw secret=synthetic-secret",
        "http_error\nAuthorization: synthetic-secret",
        "UNKNOWN",
    ],
    ids=["raw-message", "multiline", "unknown"],
)
def test_unapproved_diagnostic_does_not_release_or_record_attempt(
    queue, caplog, category
):
    assert admit(queue)
    owner = queue.claim(now=105, lease_seconds=20)
    before = queue.snapshot()
    with pytest.raises(ValueError, match="Unrecognized safe failure category") as error:
        queue.fail(owner, now=106, delay=30, max_attempts=5, category=category)
    assert queue.snapshot() == before
    assert "synthetic-secret" not in str(error.value) + caplog.text
    assert queue.ack(owner, now=107)


@pytest.mark.parametrize(
    "category", ["http_error", "transport_error", "configuration_unavailable"]
)
def test_approved_category_records_only_safe_diagnostic_and_preserves_payload(
    queue, category
):
    assert admit(queue)
    owner = queue.claim(now=105, lease_seconds=20)
    assert queue.fail(owner, now=106, delay=30, max_attempts=5, category=category)
    row = queue.snapshot()["entries"][0]
    assert row["payload"] == PAYLOAD
    assert row["last_error"] == category
    assert row["attempts"] == 2
    assert row["due_at"] == 136
    assert row["lease_token"] is None
    assert queue.claim(now=135, lease_seconds=20) is None
    assert queue.claim(now=136, lease_seconds=20) is not None


def test_policy_discard_is_counted_once_and_survives_reopen(context, queue):
    assert admit(queue)
    owner = queue.claim(now=105, lease_seconds=20)
    assert queue.ack(owner, now=106, dropped=True)
    assert not queue.ack(owner, now=107, dropped=True)
    assert queue.snapshot() == {"entries": [], "dropped": 1}
    reopened_context = SharedContext(context._db_path)
    try:
        assert WebhookRetryStore(reopened_context).snapshot() == {
            "entries": [],
            "dropped": 1,
        }
    finally:
        reopened_context.close()
