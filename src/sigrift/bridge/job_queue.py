"""In-process asyncio job queue for analysis tasks.

Provides an ``AnalysisJobQueue`` with configurable worker count that
processes analysis jobs (spectrogram computation, modulation parameter
extraction, etc.) without blocking API responses.

Zero infrastructure -- no Redis, no Celery.  Jobs are stored in an
in-memory dict with states: pending -> running -> completed/failed.

Resource bounds:

* Synchronous handlers (FFTs, protocol decoding) run in a worker thread
  (``asyncio.to_thread``), never on the event loop.  Cancelling a worker
  task does not stop its thread, so :meth:`AnalysisJobQueue.stop` waits
  (up to ``BRIDGE_JOB_STOP_TIMEOUT_S``, default 5 s) for handler threads
  still running before it returns: shutdown then does not close the
  database under a handler that is still using it.
* Finished jobs (completed / failed / cancelled) are evicted after
  ``BRIDGE_JOB_FINISHED_TTL_S`` seconds (default 3600) and beyond the
  newest ``BRIDGE_JOB_MAX_FINISHED`` (default 200).
* A result whose JSON form exceeds ``BRIDGE_JOB_MAX_RESULT_BYTES``
  (default 8 MiB) fails the job instead of being kept.  Results over
  64 KiB are kept as compressed JSON (decoded again by
  :meth:`AnalysisJobQueue.get_job_status`), and the compressed results of
  all finished jobs together stay under ``BRIDGE_JOB_RESULT_BUDGET_BYTES``
  (default 64 MiB) by evicting the oldest finished jobs.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
import uuid
import zlib
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)

_FINISHED_STATES = frozenset({"completed", "failed", "cancelled"})

# Results whose JSON is at most this size stay as Python objects; larger
# ones are kept as zlib-compressed JSON.
_INLINE_RESULT_BYTES = 64 * 1024


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_int(name: str, default: int, minimum: int = 0) -> int:
    """Integer env var *name*; *default* (logged) when unset, malformed or < *minimum*."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        logger.warning("Invalid %s=%r; using %d", name, raw, default)
        return default
    if value < minimum:
        logger.warning("%s must be >= %d; using %d", name, minimum, default)
        return default
    return value


class JobResultTooLarge(Exception):
    """A handler returned a result over the configured size cap."""


class AnalysisJobQueue:
    """Asyncio-based in-process job queue with configurable workers.

    Parameters
    ----------
    max_workers : int
        Number of concurrent worker tasks pulling from the queue.
    max_queue_size : int
        Maximum number of pending jobs.  ``submit()`` raises if full.
    max_finished_jobs, finished_job_ttl, max_result_bytes, result_budget_bytes
        Retention bounds (see the module docstring); ``None`` reads the
        environment variable / default.
    """

    def __init__(
        self,
        max_workers: int = 2,
        max_queue_size: int = 100,
        *,
        max_finished_jobs: int | None = None,
        finished_job_ttl: float | None = None,
        max_result_bytes: int | None = None,
        result_budget_bytes: int | None = None,
        stop_timeout: float | None = None,
    ) -> None:
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        self.max_finished_jobs = (
            max_finished_jobs
            if max_finished_jobs is not None
            else env_int("BRIDGE_JOB_MAX_FINISHED", 200, minimum=1)
        )
        self.finished_job_ttl = (
            finished_job_ttl
            if finished_job_ttl is not None
            else float(env_int("BRIDGE_JOB_FINISHED_TTL_S", 3600, minimum=1))
        )
        self.max_result_bytes = (
            max_result_bytes
            if max_result_bytes is not None
            else env_int("BRIDGE_JOB_MAX_RESULT_BYTES", 8 * 1024 * 1024, minimum=1)
        )
        self.result_budget_bytes = (
            result_budget_bytes
            if result_budget_bytes is not None
            else env_int("BRIDGE_JOB_RESULT_BUDGET_BYTES", 64 * 1024 * 1024, minimum=1)
        )

        self.stop_timeout = (
            stop_timeout
            if stop_timeout is not None
            else float(env_int("BRIDGE_JOB_STOP_TIMEOUT_S", 5, minimum=0))
        )

        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=max_queue_size)
        # Futures of handler work running in worker threads (see stop()).
        self._inflight: set[asyncio.Future[Any]] = set()
        self._jobs: dict[str, dict[str, Any]] = {}
        # job_id -> zlib-compressed JSON of a large result (see module doc)
        self._result_blobs: dict[str, bytes] = {}
        # job_id -> monotonic time it finished, oldest first (dict order)
        self._finished_at: dict[str, float] = {}
        self._handlers: dict[str, Callable] = {}
        self._workers: list[asyncio.Task] = []
        self._running = False

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def register_handler(
        self,
        job_type: str,
        handler: Callable[..., Any],
    ) -> None:
        """Register a handler for a job type.

        The handler receives ``(job_id: str, params: dict)`` and should
        return a JSON-serialisable result dict.  It may be a sync or async
        callable; a sync handler runs in a worker thread.
        """
        self._handlers[job_type] = handler

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start worker tasks."""
        if self._running:
            return
        self._running = True
        for i in range(self.max_workers):
            task = asyncio.create_task(self._worker_loop(i))
            self._workers.append(task)
        logger.info(
            "AnalysisJobQueue started with %d workers (max_queue=%d)",
            self.max_workers,
            self.max_queue_size,
        )

    async def stop(self, timeout: float | None = None) -> None:
        """Stop the workers, then wait for handler threads still running.

        Running jobs are marked failed ("cancelled: job queue stopped").
        Their handler threads cannot be interrupted; they are awaited for
        up to *timeout* seconds (default :attr:`stop_timeout`), and a
        warning names how many are still running after that.
        """
        if not self._running:
            return
        self._running = False

        # Send sentinel values to unblock workers
        for _ in self._workers:
            try:
                self._queue.put_nowait("")
            except asyncio.QueueFull:
                pass

        for task in self._workers:
            task.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()
        await self.wait_for_handler_threads(timeout)
        logger.info("AnalysisJobQueue stopped")

    async def wait_for_handler_threads(self, timeout: float | None = None) -> bool:
        """Wait up to *timeout* s for handler threads; True if none is left."""
        pending = {f for f in self._inflight if not f.done()}
        if not pending:
            return True
        limit = self.stop_timeout if timeout is None else timeout
        _done, still = await asyncio.wait(pending, timeout=max(0.0, limit))
        if still:
            logger.warning(
                "AnalysisJobQueue: %d job handler thread(s) still running after %.1fs",
                len(still),
                limit,
            )
            return False
        return True

    # ------------------------------------------------------------------
    # Job submission
    # ------------------------------------------------------------------

    def submit_nowait(self, job_type: str, params: dict) -> str:
        """Submit a job without awaiting (for synchronous callers).

        Same contract as :meth:`submit`.
        """
        if job_type not in self._handlers:
            raise ValueError(f"Unknown job type: {job_type}")

        self._evict_finished()
        job_id = uuid.uuid4().hex
        job = {
            "job_id": job_id,
            "job_type": job_type,
            "params": params,
            "status": "pending",
            "submitted_at": _utcnow(),
            "started_at": None,
            "completed_at": None,
            "result": None,
            "error": None,
        }
        self._jobs[job_id] = job

        try:
            self._queue.put_nowait(job_id)
        except asyncio.QueueFull:
            # Remove the job record and re-raise
            self._jobs.pop(job_id, None)
            raise

        logger.debug("Job %s (%s) submitted", job_id[:8], job_type)
        return job_id

    async def submit(self, job_type: str, params: dict) -> str:
        """Submit a job for processing.

        Parameters
        ----------
        job_type : str
            Must match a registered handler name.
        params : dict
            Arbitrary parameters passed to the handler.

        Returns
        -------
        str
            The job_id (UUID).

        Raises
        ------
        ValueError
            If the job_type has no registered handler.
        asyncio.QueueFull
            If the queue is at capacity.
        """
        return self.submit_nowait(job_type, params)

    # ------------------------------------------------------------------
    # Job status / listing
    # ------------------------------------------------------------------

    def get_job_status(self, job_id: str) -> dict | None:
        """Return a copy of the job dict for *job_id*, or ``None`` if not found.

        A large result kept compressed is decoded into ``result``.
        """
        self._evict_finished()
        job = self._jobs.get(job_id)
        if job is None:
            return None
        view = dict(job)
        blob = self._result_blobs.get(job_id)
        if blob is not None:
            view["result"] = json.loads(zlib.decompress(blob))
        return view

    def list_jobs(
        self,
        status_filter: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Return recent jobs, newest first, with optional status filter.

        Large results (kept compressed) are not inlined here: such a job
        has ``result`` None and ``result_omitted`` True; fetch it with
        :meth:`get_job_status`.
        """
        self._evict_finished()
        jobs = list(self._jobs.values())
        if status_filter:
            jobs = [j for j in jobs if j["status"] == status_filter]
        # Sort by submitted_at descending
        jobs.sort(key=lambda j: j["submitted_at"], reverse=True)
        views: list[dict] = []
        for job in jobs[:limit]:
            view = dict(job)
            if job["job_id"] in self._result_blobs:
                view["result_omitted"] = True
            views.append(view)
        return views

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending job.  Returns True if cancelled."""
        job = self._jobs.get(job_id)
        if job is None:
            return False
        if job["status"] != "pending":
            return False
        job["status"] = "cancelled"
        job["completed_at"] = _utcnow()
        self._mark_finished(job_id)
        return True

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def _mark_finished(self, job_id: str) -> None:
        self._finished_at.pop(job_id, None)
        self._finished_at[job_id] = time.monotonic()
        self._evict_finished()

    def _drop(self, job_id: str) -> None:
        self._finished_at.pop(job_id, None)
        self._result_blobs.pop(job_id, None)
        self._jobs.pop(job_id, None)

    def _evict_finished(self) -> None:
        """Evict finished jobs past the TTL, the count cap or the result budget."""
        if not self._finished_at:
            return
        cutoff = time.monotonic() - self.finished_job_ttl
        # _finished_at is in finishing order: the oldest come first.
        while self._finished_at:
            job_id, finished = next(iter(self._finished_at.items()))
            if finished >= cutoff and len(self._finished_at) <= self.max_finished_jobs:
                break
            self._drop(job_id)
        blob_bytes = sum(len(b) for b in self._result_blobs.values())
        while blob_bytes > self.result_budget_bytes and self._finished_at:
            job_id = next(iter(self._finished_at))
            blob_bytes -= len(self._result_blobs.get(job_id, b""))
            self._drop(job_id)

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    def _run_sync_handler(
        self, handler: Callable[..., Any], job_id: str, params: dict
    ) -> tuple[Any, bytes | None]:
        """Run a sync handler and size its result (in the worker thread)."""
        return self._encode_result(handler(job_id, params))

    def _encode_result(self, result: Any) -> tuple[Any, bytes | None]:
        """Return ``(inline_result, None)`` or ``(None, compressed_json)``.

        Raises :class:`JobResultTooLarge` past ``max_result_bytes``.
        """
        if result is None or isinstance(result, (bool, int, float, str)):
            if not isinstance(result, str) or len(result) <= _INLINE_RESULT_BYTES:
                return result, None
        try:
            encoded = json.dumps(result, default=str, separators=(",", ":"))
        except (TypeError, ValueError):
            # Not JSON-able as a whole (e.g. a cycle): keep it as it was.
            return result, None
        size = len(encoded)
        if size > self.max_result_bytes:
            raise JobResultTooLarge(
                f"result too large: {size} bytes of JSON exceeds the "
                f"{self.max_result_bytes}-byte limit (BRIDGE_JOB_MAX_RESULT_BYTES)"
            )
        if size <= _INLINE_RESULT_BYTES:
            return result, None
        return None, zlib.compress(encoded.encode("utf-8"), 6)

    async def _in_thread(self, func: Callable[..., Any], *args: Any) -> Any:
        """``asyncio.to_thread(func, *args)``, tracked for :meth:`stop`.

        The thread's future is shielded: cancelling the awaiting worker
        leaves it in :attr:`_inflight`, so :meth:`stop` can wait for it.
        """
        future = asyncio.ensure_future(asyncio.to_thread(func, *args))
        self._inflight.add(future)
        future.add_done_callback(self._forget_inflight)
        return await asyncio.shield(future)

    def _forget_inflight(self, future: asyncio.Future[Any]) -> None:
        self._inflight.discard(future)
        if not future.cancelled():
            future.exception()  # retrieved: an abandoned job's error is not re-logged

    async def _execute(self, handler: Callable[..., Any], job_id: str, params: dict):
        """Run *handler* off the event loop; return ``(inline, blob)``."""
        if inspect.iscoroutinefunction(handler):
            result = await handler(job_id, params)
            return await self._in_thread(self._encode_result, result)
        result, blob = await self._in_thread(
            self._run_sync_handler, handler, job_id, params
        )
        if asyncio.iscoroutine(result):
            # A sync callable that returned a coroutine (e.g. a wrapper).
            result = await result
            return await self._in_thread(self._encode_result, result)
        return result, blob

    async def _worker_loop(self, worker_id: int) -> None:
        """Continuously pull jobs from the queue and execute them."""
        logger.debug("Worker %d started", worker_id)
        while self._running:
            try:
                job_id = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break

            # Sentinel value or empty string means shutdown
            if not job_id:
                break

            job = self._jobs.get(job_id)
            if job is None or job["status"] != "pending":
                continue

            handler = self._handlers.get(job["job_type"])
            if handler is None:
                job["status"] = "failed"
                job["error"] = f"No handler for job type: {job['job_type']}"
                job["completed_at"] = _utcnow()
                self._mark_finished(job_id)
                continue

            # Execute
            job["status"] = "running"
            job["started_at"] = _utcnow()
            try:
                result, blob = await self._execute(handler, job_id, job["params"])
                job["status"] = "completed"
                job["result"] = result
                if blob is not None:
                    self._result_blobs[job_id] = blob
            except asyncio.CancelledError:
                job["status"] = "failed"
                job["error"] = "cancelled: job queue stopped"
                job["completed_at"] = _utcnow()
                self._mark_finished(job_id)
                raise
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = str(exc)
                logger.warning(
                    "Job %s (%s) failed: %s",
                    job_id[:8],
                    job["job_type"],
                    exc,
                )
            job["completed_at"] = _utcnow()
            self._mark_finished(job_id)

        logger.debug("Worker %d stopped", worker_id)
