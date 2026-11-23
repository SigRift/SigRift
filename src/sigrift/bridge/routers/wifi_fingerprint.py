"""WiFi device fingerprint and clustering API router.

Provides endpoints for browsing device clusters produced by
protocol-layer fingerprinting (IE, timing, sequence number).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, get_tenant_id, require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class IdentifyRequest(BaseModel):
    ie_fingerprint: str = Field(..., min_length=1, max_length=32)
    timing_signature: dict[str, float] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_cluster_store(request: Request):
    store = getattr(request.app.state, "wifi_cluster_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WiFi device cluster store not initialised",
        )
    return store


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/device-clusters",
    dependencies=[Depends(require_role(Role.VIEWER))],
)
async def list_device_clusters(
    request: Request,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    min_observations: int = Query(0, ge=0),
    since: str = Query(""),
    limit: int = Query(200, ge=1, le=1000),
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, Any]:
    """List all active device clusters with optional filters."""
    store = _get_cluster_store(request)
    clusters = store.list_clusters(
        tenant_id=tenant_id,
        min_confidence=min_confidence,
        min_observations=min_observations,
        since=since,
        limit=limit,
    )
    return {"clusters": clusters, "total": len(clusters)}


@router.get(
    "/device-clusters/{cluster_id}",
    dependencies=[Depends(require_role(Role.VIEWER))],
)
async def get_device_cluster(
    request: Request,
    cluster_id: str,
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, Any]:
    """Get detailed information for a single device cluster."""
    store = _get_cluster_store(request)
    cluster = store.get_cluster(cluster_id, tenant_id=tenant_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Enrich with IE data
    ie_data = store.get_ie_data(cluster["ie_fingerprint"], tenant_id=tenant_id)

    # Enrich with PNL
    pnl = store.get_pnl(cluster_id, tenant_id=tenant_id)

    return {
        "cluster": cluster,
        "ie_data": ie_data,
        "pnl": pnl,
    }


@router.get(
    "/device-clusters/{cluster_id}/timeline",
    dependencies=[Depends(require_role(Role.VIEWER))],
)
async def get_device_cluster_timeline(
    request: Request,
    cluster_id: str,
    tenant_id: str = Depends(get_tenant_id),
    limit: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    """Get chronological appearance history for a cluster."""
    store = _get_cluster_store(request)
    # Verify cluster exists
    cluster = store.get_cluster(cluster_id, tenant_id=tenant_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")

    timeline = store.get_cluster_timeline(cluster_id, tenant_id=tenant_id, limit=limit)
    return {"cluster_id": cluster_id, "timeline": timeline}


@router.get(
    "/fingerprint-stats",
    dependencies=[Depends(require_role(Role.VIEWER))],
)
async def get_fingerprint_stats(
    request: Request,
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, Any]:
    """Return summary statistics for device fingerprinting."""
    store = _get_cluster_store(request)
    return store.get_stats(tenant_id=tenant_id)


@router.post(
    "/identify",
    dependencies=[Depends(require_role(Role.ANALYST))],
)
async def identify_device(
    request: Request,
    body: IdentifyRequest,
    tenant_id: str = Depends(get_tenant_id),
) -> dict[str, Any]:
    """Submit an IE fingerprint and return matching clusters."""
    store = _get_cluster_store(request)
    clusters = store.list_clusters(tenant_id=tenant_id, limit=1000)

    matches = []
    for cluster in clusters:
        if cluster.get("ie_fingerprint") == body.ie_fingerprint:
            matches.append(cluster)

    return {"matches": matches, "total": len(matches)}
