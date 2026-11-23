"""IQ metadata index and tiered retention API endpoints.

Provides searchable IQ capture metadata, storage statistics,
retention tier management, and expired-capture cleanup.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_iq_metadata_store(request: Request) -> Any:
    """Retrieve the IQMetadataStore from app state."""
    store = getattr(request.app.state, "iq_metadata_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ metadata store not initialised",
        )
    return store


def _get_iq_store(request: Request) -> Any:
    """Retrieve the IQStore from app state."""
    store = getattr(request.app.state, "iq_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="IQ store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# GET /api/iq/index -- query IQ metadata with filters
# ---------------------------------------------------------------------------


@router.get("/index")
def query_iq_index(
    request: Request,
    node_id: str | None = Query(None),
    signal_class: str | None = Query(None),
    tier: str | None = Query(None),
    freq_min: float | None = Query(None, description="Min frequency in Hz"),
    freq_max: float | None = Query(None, description="Max frequency in Hz"),
    limit: int = Query(50, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Query IQ capture metadata with optional filters."""
    meta_store = _get_iq_metadata_store(request)

    freq_range = None
    if freq_min is not None and freq_max is not None:
        freq_range = (freq_min, freq_max)

    return meta_store.query(
        node_id=node_id,
        signal_class=signal_class,
        freq_range=freq_range,
        tier=tier,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# GET /api/iq/stats -- IQ storage statistics
# ---------------------------------------------------------------------------


@router.get("/stats")
def iq_stats(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return IQ storage statistics (counts by tier, total size, date range)."""
    meta_store = _get_iq_metadata_store(request)
    return meta_store.get_stats()


# ---------------------------------------------------------------------------
# POST /api/iq/cleanup -- trigger cleanup of expired captures
# ---------------------------------------------------------------------------


@router.post("/cleanup")
def cleanup_expired(
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Trigger cleanup of expired IQ captures. Requires ADMIN role."""
    meta_store = _get_iq_metadata_store(request)
    iq_store = _get_iq_store(request)

    removed = meta_store.cleanup_expired(iq_store)
    return {
        "ok": True,
        "removed": removed,
    }
