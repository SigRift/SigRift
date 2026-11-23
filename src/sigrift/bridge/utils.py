"""Shared utilities for The Bridge routers.

Centralises common helpers that were previously duplicated across
every router module.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request, status

from sigrift.bridge.persistence import KeyStoreWriteError

#: 503 detail for a key change keys.json could not record (nothing changed).
KEY_CHANGE_NOT_SAVED = "Key change could not be saved; try again"
#: 503 detail for a revocation or downgrade keys.json could not record:
#: in effect on this worker, not yet on the others or the gateway.
KEY_CHANGE_PENDING = (
    "Key change applied on this worker only: it could not be saved, so other "
    "workers and the gateway still use the previous key until a save "
    "succeeds (retried automatically); repeat the request to confirm it"
)


def utcnow() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


@contextlib.contextmanager
def key_change_saved(
    on_pending: Callable[[], None] | None = None,
) -> Iterator[None]:
    """Answer 503 for a key change whose keys.json write failed.

    Wraps a persistence key mutator: a :class:`KeyStoreWriteError` means
    the change is not durable (other workers and the gateway do not see
    it), so the route must not report success or audit it as done.

    A change that was undone gets :data:`KEY_CHANGE_NOT_SAVED`.  A
    revocation or downgrade that stays in effect here (``applied_here``)
    gets :data:`KEY_CHANGE_PENDING`, after *on_pending* runs: the route
    audits it as not yet saved, since the next save (or a repeat of the
    request) writes it.
    """
    try:
        yield
    except KeyStoreWriteError as exc:
        if exc.applied_here and on_pending is not None:
            on_pending()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=KEY_CHANGE_PENDING if exc.applied_here else KEY_CHANGE_NOT_SAVED,
        ) from exc


def get_detection_store(request: Request) -> Any:
    """Retrieve the DetectionStore from app state.

    Raises HTTP 503 if the store has not been initialised yet.
    """
    store = getattr(request.app.state, "detection_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection store not initialised",
        )
    return store


class BoundedDict(dict):
    """Dict subclass that evicts the oldest entry when max_size is exceeded.

    Uses insertion-order iteration (guaranteed in Python 3.7+) to identify
    the oldest key for eviction.
    """

    def __init__(self, max_size: int = 10000) -> None:
        super().__init__()
        self._max_size = max_size

    def __setitem__(self, key: Any, value: Any) -> None:
        if len(self) >= self._max_size and key not in self:
            oldest = next(iter(self))
            del self[oldest]
        super().__setitem__(key, value)
