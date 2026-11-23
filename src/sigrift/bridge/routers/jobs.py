"""Job queue API router for analysis job submission and monitoring.

Provides endpoints for submitting, listing, inspecting, and cancelling
analysis jobs processed by the in-process ``AnalysisJobQueue``.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class JobSubmitRequest(BaseModel):
    model_config = {"extra": "forbid"}
    job_type: str = Field(..., description="Type of analysis job to run")
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters passed to the job handler",
    )


class JobResponse(BaseModel):
    job_id: str
    job_type: str
    params: dict[str, Any]
    status: str
    submitted_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    result: Any = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("")
async def list_jobs(
    request: Request,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """List recent analysis jobs with optional status filter."""
    job_queue = getattr(request.app.state, "job_queue", None)
    if job_queue is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job queue not available",
        )
    jobs = job_queue.list_jobs(status_filter=status_filter, limit=limit)
    return {"jobs": jobs, "count": len(jobs)}


@router.get("/{job_id}")
async def get_job(
    request: Request,
    job_id: str,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Get status and result of a specific job."""
    job_queue = getattr(request.app.state, "job_queue", None)
    if job_queue is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job queue not available",
        )
    job = job_queue.get_job_status(job_id)
    if job is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job {job_id} not found",
        )
    return {"job": job}


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def submit_job(
    request: Request,
    body: JobSubmitRequest,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Submit a new analysis job.  Requires ANALYST role."""
    job_queue = getattr(request.app.state, "job_queue", None)
    if job_queue is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job queue not available",
        )
    try:
        job_id = await job_queue.submit(body.job_type, body.params)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except asyncio.QueueFull:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Job queue is full, try again later",
        )
    return {"job_id": job_id, "status": "pending"}


@router.delete("/{job_id}")
async def cancel_job(
    request: Request,
    job_id: str,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Cancel a pending job.  Requires ADMIN role."""
    job_queue = getattr(request.app.state, "job_queue", None)
    if job_queue is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job queue not available",
        )
    cancelled = job_queue.cancel_job(job_id)
    if not cancelled:
        job = job_queue.get_job_status(job_id)
        if job is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} not found",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Job cannot be cancelled (status: {job['status']})",
        )
    return {"job_id": job_id, "status": "cancelled"}
