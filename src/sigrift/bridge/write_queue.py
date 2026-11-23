"""Async write-batching queue for SQLite detection inserts.

Buffers detection writes in memory and flushes them in batches to reduce
SQLite write-lock contention.  Flush triggers:

- **Batch size**: flush when >= ``batch_size`` items are queued (default 100).
- **Time interval**: flush after ``flush_interval_ms`` milliseconds since the
  last flush (default 500 ms), even if the batch is not full.
- **Shutdown**: ``stop()`` drains the remaining buffer before returning.

Usage::

    wq = WriteQueue(store, batch_size=100, flush_interval_ms=500)
    await wq.start()
    await wq.enqueue_detection(record)
    await wq.enqueue_batch(records)
    # ... on shutdown:
    await wq.stop()
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sigrift.bridge.detection_store import DetectionStore
    from sigrift.bridge.models import DetectionRecord

logger = logging.getLogger(__name__)

#: Put on the queue by stop() to wake the flush loop at once.
_WAKE = object()


class WriteQueue:
    """Async batching queue that coalesces detection writes.

    Parameters
    ----------
    store : DetectionStore
        The detection store whose ``insert_batch`` will be called on flush.
    batch_size : int
        Maximum number of detections to buffer before triggering a flush.
    flush_interval_ms : int
        Maximum milliseconds between flushes (time-based trigger).
    """

    def __init__(
        self,
        store: DetectionStore,
        batch_size: int = 100,
        flush_interval_ms: int = 500,
    ) -> None:
        self._store = store
        self._batch_size = max(1, batch_size)
        self._flush_interval_s = max(0.01, flush_interval_ms / 1000.0)
        self._queue: asyncio.Queue[DetectionRecord] = asyncio.Queue(maxsize=10_000)
        self._task: asyncio.Task | None = None
        self._running = False
        self._total_enqueued = 0
        self._total_flushed = 0
        self._total_dropped = 0
        self._flush_count = 0

    # -- Public API ---------------------------------------------------------

    async def start(self) -> None:
        """Start the background flush loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._flush_loop(), name="write-queue-flush")
        logger.info(
            "WriteQueue started (batch_size=%d, flush_interval=%.0fms)",
            self._batch_size,
            self._flush_interval_s * 1000,
        )

    async def stop(self, timeout: float = 10.0) -> None:
        """Stop the flush loop and drain any remaining items.

        The loop is asked to stop (it notices within one flush interval)
        and awaited for up to *timeout* seconds; it is cancelled only if it
        does not finish in time.  Cancelling it mid-flush would leave the
        ``insert_batch`` thread running while shutdown goes on to close the
        database (and used to make the final drain insert that batch again).
        """
        if not self._running:
            return
        self._running = False
        try:
            self._queue.put_nowait(_WAKE)  # type: ignore[arg-type]
        except asyncio.QueueFull:
            pass  # the loop is busy with items; it sees _running soon
        if self._task is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout)
            except (asyncio.TimeoutError, TimeoutError):
                logger.warning(
                    "WriteQueue flush loop did not stop within %.1fs; cancelling",
                    timeout,
                )
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None
        # Final drain
        remaining = self._drain_queue()
        if remaining:
            await self._flush(remaining)
        logger.info(
            "WriteQueue stopped (total_enqueued=%d, total_flushed=%d, flushes=%d)",
            self._total_enqueued,
            self._total_flushed,
            self._flush_count,
        )

    async def enqueue_detection(self, detection: DetectionRecord) -> None:
        """Add a single detection to the write buffer."""
        try:
            self._queue.put_nowait(detection)
            self._total_enqueued += 1
        except asyncio.QueueFull:
            self._total_dropped += 1
            logger.warning(
                "WriteQueue full (%d items), dropped detection",
                self._queue.qsize(),
            )

    async def enqueue_batch(self, detections: list[DetectionRecord]) -> None:
        """Add multiple detections to the write buffer."""
        dropped = 0
        for d in detections:
            try:
                self._queue.put_nowait(d)
                self._total_enqueued += 1
            except asyncio.QueueFull:
                dropped += 1
                self._total_dropped += 1
        if dropped:
            logger.warning(
                "WriteQueue full, dropped %d/%d detections from batch",
                dropped,
                len(detections),
            )

    @property
    def pending(self) -> int:
        """Number of items currently buffered."""
        return self._queue.qsize()

    @property
    def is_running(self) -> bool:
        """Whether the flush loop is active."""
        return self._running and self._task is not None and not self._task.done()

    @property
    def stats(self) -> dict:
        """Return queue statistics."""
        return {
            "pending": self._queue.qsize(),
            "total_enqueued": self._total_enqueued,
            "total_flushed": self._total_flushed,
            "total_dropped": self._total_dropped,
            "flush_count": self._flush_count,
        }

    # -- Internal -----------------------------------------------------------

    def _drain_queue(self) -> list[DetectionRecord]:
        """Non-blocking drain of all items currently in the queue."""
        items: list[DetectionRecord] = []
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break
            if item is not _WAKE:
                items.append(item)
        return items

    _RETRY_BACKOFFS = (0.1, 0.5)

    async def _flush(self, batch: list[DetectionRecord]) -> int:
        """Flush a batch to the store with retry (3 attempts max)."""
        if not batch:
            return 0
        last_exc: Exception | None = None
        for attempt in range(1 + len(self._RETRY_BACKOFFS)):
            try:
                inserted = await asyncio.to_thread(self._store.insert_batch, batch)
                self._total_flushed += inserted
                self._flush_count += 1
                if attempt > 0:
                    logger.info("WriteQueue flush succeeded on attempt %d", attempt + 1)
                logger.debug(
                    "WriteQueue flushed %d/%d detections", inserted, len(batch)
                )
                return inserted
            except Exception as exc:
                last_exc = exc
                if attempt < len(self._RETRY_BACKOFFS):
                    delay = self._RETRY_BACKOFFS[attempt]
                    logger.warning(
                        "WriteQueue flush attempt %d failed (%d items), retrying in %.1fs: %s",
                        attempt + 1,
                        len(batch),
                        delay,
                        exc,
                    )
                    await asyncio.sleep(delay)
        self._total_dropped += len(batch)
        logger.error(
            "WriteQueue flush failed after %d attempts, dropped %d items: %s",
            1 + len(self._RETRY_BACKOFFS),
            len(batch),
            last_exc,
        )
        return 0

    async def _flush_loop(self) -> None:
        """Background loop: wait for batch_size items or flush_interval."""
        batch: list[DetectionRecord] = []
        deadline = time.monotonic() + self._flush_interval_s
        logger.info("WriteQueue flush loop started")

        try:
            while self._running:
                # Calculate how long until the next time-based flush
                now = time.monotonic()
                timeout = max(0.0, deadline - now)

                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                    if item is not _WAKE:
                        batch.append(item)
                except (asyncio.TimeoutError, TimeoutError):
                    # Timer expired — flush whatever we have
                    pass

                # Check flush triggers
                now = time.monotonic()
                should_flush = len(batch) >= self._batch_size or (
                    batch and now >= deadline
                )

                if should_flush:
                    # Hand the batch over before awaiting: if the loop is
                    # cancelled mid-flush, the final drain must not insert
                    # it a second time.
                    pending, batch = batch, []
                    await self._flush(pending)
                    deadline = time.monotonic() + self._flush_interval_s
                elif now >= deadline:
                    # Idle path: deadline expired but nothing to flush.
                    # Without rolling the deadline forward here the next
                    # iteration computes timeout=max(0.0, deadline-now)=0.0
                    # and wait_for returns instantly — tight busy-loop
                    # that pegs one CPU core per worker.
                    deadline = now + self._flush_interval_s
        except asyncio.CancelledError:
            logger.info("WriteQueue flush loop cancelled")
        except Exception:
            logger.exception("WriteQueue flush loop crashed")
        finally:
            # Drain anything left
            batch.extend(self._drain_queue())
            if batch:
                await self._flush(batch)
