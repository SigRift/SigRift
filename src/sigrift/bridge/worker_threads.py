"""Default executor that shutdown can wait on.

``asyncio.to_thread`` runs blocking work (database queries, retention,
VACUUM, file I/O) in the event loop's default executor.  Cancelling the
task that awaits it does not stop the thread, so after the lifespan
cancels its background tasks their threads may still be stepping SQLite
statements.  :class:`TrackingThreadPoolExecutor` counts the work items it
is running, and :func:`wait_until_idle` lets shutdown wait (bounded) for
them before it closes the database.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Callable

logger = logging.getLogger(__name__)


class TrackingThreadPoolExecutor(ThreadPoolExecutor):
    """A ``ThreadPoolExecutor`` that knows how many submitted items are unfinished."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._unfinished = 0
        self._count_lock = threading.Lock()

    def submit(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Future:
        with self._count_lock:
            self._unfinished += 1
        try:
            future = super().submit(fn, *args, **kwargs)
        except BaseException:
            self._finished(None)
            raise
        future.add_done_callback(self._finished)
        return future

    def _finished(self, _future: Future | None) -> None:
        with self._count_lock:
            self._unfinished -= 1

    @property
    def unfinished(self) -> int:
        """Submitted work items not finished yet (queued or running)."""
        with self._count_lock:
            return self._unfinished


def install_default_executor(
    loop: asyncio.AbstractEventLoop | None = None,
) -> TrackingThreadPoolExecutor:
    """Make a :class:`TrackingThreadPoolExecutor` *loop*'s default executor."""
    loop = loop or asyncio.get_running_loop()
    executor = TrackingThreadPoolExecutor(thread_name_prefix="bridge-worker")
    loop.set_default_executor(executor)
    return executor


async def wait_until_idle(
    executor: TrackingThreadPoolExecutor, timeout: float, poll: float = 0.05
) -> bool:
    """Wait up to *timeout* s until *executor* runs nothing; True if idle.

    Polls instead of waiting in a thread, which would itself be work of
    the executor.  Logs a warning when work is still running at the end.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while executor.unfinished:
        if time.monotonic() >= deadline:
            logger.warning(
                "%d worker thread task(s) still running after %.1fs; "
                "shutting down anyway",
                executor.unfinished,
                timeout,
            )
            return False
        await asyncio.sleep(poll)
    return True
