"""Tests for the async WriteQueue batching layer.

Validates:
- Items enqueued are flushed via insert_batch
- Batch-size trigger (flush at N items)
- Time-based trigger (flush after M ms)
- Graceful shutdown flushes remaining items
- Concurrent enqueue from multiple coroutines
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.write_queue import WriteQueue


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detection(idx: int = 0) -> DetectionRecord:
    return DetectionRecord(
        node_id="node-test-01",
        signal_class="bpsk",
        confidence=0.9,
        freq_hz=433.92e6,
    )


def _make_mock_store(inserted_batches: list | None = None):
    """Return a mock store whose insert_batch records calls."""
    store = MagicMock()
    if inserted_batches is None:
        inserted_batches = []

    def _insert_batch(detections):
        inserted_batches.append(list(detections))
        return len(detections)

    store.insert_batch = MagicMock(side_effect=_insert_batch)
    return store, inserted_batches


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enqueued_items_get_flushed():
    """Basic: items put in the queue end up flushed to the store."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=5, flush_interval_ms=50)
    await wq.start()

    for _ in range(3):
        await wq.enqueue_detection(_make_detection())

    # Wait for time-based flush
    await asyncio.sleep(0.15)
    await wq.stop()

    total_flushed = sum(len(b) for b in batches)
    assert total_flushed == 3
    assert wq.stats["total_enqueued"] == 3
    assert wq.stats["total_flushed"] == 3


@pytest.mark.asyncio
async def test_batch_size_trigger():
    """Flush triggers when batch_size items are buffered."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=5, flush_interval_ms=5000)
    await wq.start()

    # Enqueue exactly batch_size items
    for _ in range(5):
        await wq.enqueue_detection(_make_detection())

    # Give the loop time to process
    await asyncio.sleep(0.1)

    # Should have flushed without waiting for the long timer
    assert len(batches) >= 1
    total = sum(len(b) for b in batches)
    assert total == 5

    await wq.stop()


@pytest.mark.asyncio
async def test_time_based_trigger():
    """Flush triggers after flush_interval_ms even with partial batch."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=1000, flush_interval_ms=80)
    await wq.start()

    # Add fewer items than batch_size
    await wq.enqueue_detection(_make_detection())
    await wq.enqueue_detection(_make_detection())

    # Not flushed yet (batch_size=1000)
    assert wq.pending <= 2

    # Wait for time-based flush
    await asyncio.sleep(0.2)

    assert len(batches) >= 1
    total = sum(len(b) for b in batches)
    assert total == 2

    await wq.stop()


@pytest.mark.asyncio
async def test_graceful_shutdown_flushes_remaining():
    """stop() drains and flushes any remaining buffered items."""
    store, batches = _make_mock_store()
    # Very long interval so time trigger won't fire
    wq = WriteQueue(store, batch_size=1000, flush_interval_ms=60000)
    await wq.start()

    for _ in range(7):
        await wq.enqueue_detection(_make_detection())

    # Immediately stop — should flush the 7 remaining
    await wq.stop()

    total = sum(len(b) for b in batches)
    assert total == 7
    assert wq.stats["total_flushed"] == 7


@pytest.mark.asyncio
async def test_concurrent_enqueue():
    """Multiple coroutines can enqueue concurrently without data loss."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=50, flush_interval_ms=100)
    await wq.start()

    n_producers = 10
    items_per_producer = 20

    async def producer():
        for _ in range(items_per_producer):
            await wq.enqueue_detection(_make_detection())

    await asyncio.gather(*(producer() for _ in range(n_producers)))

    # Wait for flushes then stop
    await asyncio.sleep(0.3)
    await wq.stop()

    expected = n_producers * items_per_producer
    total = sum(len(b) for b in batches)
    assert total == expected
    assert wq.stats["total_enqueued"] == expected
    assert wq.stats["total_flushed"] == expected


@pytest.mark.asyncio
async def test_enqueue_batch_method():
    """enqueue_batch() adds multiple items at once."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=1000, flush_interval_ms=50)
    await wq.start()

    items = [_make_detection() for _ in range(12)]
    await wq.enqueue_batch(items)

    await asyncio.sleep(0.15)
    await wq.stop()

    total = sum(len(b) for b in batches)
    assert total == 12
    assert wq.stats["total_enqueued"] == 12


@pytest.mark.asyncio
async def test_empty_stop():
    """Stopping with nothing enqueued should not call insert_batch."""
    store, batches = _make_mock_store()
    wq = WriteQueue(store, batch_size=10, flush_interval_ms=50)
    await wq.start()
    await wq.stop()

    assert len(batches) == 0
    store.insert_batch.assert_not_called()


@pytest.mark.asyncio
async def test_stats():
    """stats property tracks enqueued/flushed/flush_count."""
    store, _ = _make_mock_store()
    wq = WriteQueue(store, batch_size=3, flush_interval_ms=50)
    await wq.start()

    for _ in range(6):
        await wq.enqueue_detection(_make_detection())

    await asyncio.sleep(0.2)
    await wq.stop()

    s = wq.stats
    assert s["total_enqueued"] == 6
    assert s["total_flushed"] == 6
    assert s["flush_count"] >= 1
    assert s["pending"] == 0


@pytest.mark.asyncio
async def test_flush_error_does_not_crash_loop():
    """If insert_batch raises, the flush loop continues."""
    store = MagicMock()
    call_count = 0

    def _failing_insert(detections):
        nonlocal call_count
        call_count += 1
        if call_count <= 3:  # fail all 3 retry attempts for first batch
            raise RuntimeError("simulated DB error")
        return len(detections)

    store.insert_batch = MagicMock(side_effect=_failing_insert)

    wq = WriteQueue(store, batch_size=2, flush_interval_ms=50)
    await wq.start()

    # First batch — will fail all retry attempts
    await wq.enqueue_detection(_make_detection())
    await wq.enqueue_detection(_make_detection())
    await asyncio.sleep(1.5)  # allow time for retries (0.1s + 0.5s backoff)

    # Second batch — should succeed
    await wq.enqueue_detection(_make_detection())
    await wq.enqueue_detection(_make_detection())
    await asyncio.sleep(0.15)
    await wq.stop()

    # The loop should have survived the first failure
    assert call_count >= 4
    assert wq.stats["total_flushed"] == 2  # only second batch succeeded
    assert wq.stats["total_dropped"] == 2  # first batch dropped after retries
