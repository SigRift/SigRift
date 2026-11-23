"""Job queue and scheduling endpoints.

CRUD for training jobs (create, list, cancel, rerun, priority update)
and capture schedules (create, list, update, delete).  Presets derive
from ``sigrift.lib.config.TrainingConfig`` defaults.

Any valid key lists jobs, presets and schedules.  Creating, rerunning and
reprioritising a job, and creating or changing a schedule, need an
``analyst`` key (an ``admin`` key or the master key is one), as creating a
job does on the bridge; removing a job or a schedule needs the master key.
A ``viewer`` key -- the default, and every key stored before roles
existed -- gets 403 for them.

A stored record that is not a valid job (a hand-edited ``jobs.json``) is
left out of the job list, answers 409 to the routes that serve or change
it, and can always be removed; it is logged once per defect, not on every
request.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, ValidationError

from sigrift.lib.config import TrainingConfig
from sigrift.lib.shiny.dependencies import (
    Role,
    rate_limit,
    require_master_key,
    require_role,
)
from sigrift.lib.shiny.models import (
    HyperparameterPreset,
    JobCreate,
    JobState,
    JobStatus,
    ScheduleInterval,
)
from sigrift.lib.shiny.state import AppState

logger = logging.getLogger(__name__)
router = APIRouter()

_utcnow = lambda: datetime.now(timezone.utc)  # noqa: E731


def _as_utc(dt: datetime) -> datetime:
    """*dt* with a stored time without an offset read as UTC (comparable)."""
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# -- Request models ---------------------------------------------------------


class PriorityUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    priority: int = Field(..., ge=0, le=100)


class ScheduleCreate(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(..., min_length=1, max_length=128)
    node_id: str = Field(..., min_length=1, max_length=64)
    interval: ScheduleInterval
    params: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    enabled: bool | None = None
    interval: ScheduleInterval | None = None
    params: dict[str, Any] | None = None


# -- Presets ----------------------------------------------------------------


def _build_presets() -> list[HyperparameterPreset]:
    tc = TrainingConfig()
    return [
        HyperparameterPreset(
            name="default",
            epochs=tc.epochs,
            batch_size=tc.batch_size,
            learning_rate=tc.learning_rate,
            weight_decay=tc.weight_decay,
            gamma=tc.gamma,
            label_smoothing=tc.label_smoothing,
            early_stopping_patience=tc.early_stopping_patience,
        ),
        HyperparameterPreset(
            name="fast",
            epochs=50,
            batch_size=256,
            learning_rate=3e-3,
            weight_decay=1e-4,
            gamma=1.5,
            label_smoothing=0.1,
            early_stopping_patience=15,
        ),
        HyperparameterPreset(
            name="thorough",
            epochs=400,
            batch_size=256,
            learning_rate=1e-3,
            weight_decay=1e-4,
            gamma=1.5,
            label_smoothing=0.1,
            early_stopping_patience=50,
        ),
    ]


_PRESETS: list[HyperparameterPreset] | None = None


def _get_presets() -> list[HyperparameterPreset]:
    global _PRESETS
    if _PRESETS is None:
        _PRESETS = _build_presets()
    return _PRESETS


# -- Helpers ----------------------------------------------------------------


def _get_job_or_404(persistence: Any, job_id: str) -> dict[str, Any]:
    jobs = persistence.get_jobs()
    if job_id not in jobs:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Job not found: {job_id}")
    return jobs[job_id]


def _job_name(job: dict[str, Any]) -> str:
    """The job's name; for a record stored without one, one derived from it.

    Model evaluations queued before they were stored with a name
    (``POST /api/training/models/{id}/evaluate``) have only ``type`` and
    ``model_id``: without a name they failed ``JobStatus`` and made the
    job list a 500 for everyone.
    """
    name = job.get("name")
    if isinstance(name, str) and name:
        return name
    kind = job.get("type") or "job"
    model_id = job.get("model_id")
    return f"{kind}-{model_id}" if model_id else str(kind)


def _job_view(job_id: str, job: dict[str, Any]) -> dict[str, Any]:
    """*job* as served (a copy): its id and name filled in when missing.

    The id is always the store key: every by-id route (detail, priority,
    rerun, delete) looks a job up by that key, so a stored ``job_id`` that
    differs from it (a hand-edited ``jobs.json``) would list the job under
    an id those routes answer 404 for.
    """
    return {**job, "job_id": job_id, "name": _job_name(job)}


def _defect(job_id: str, job: Any) -> JobStatus | str:
    """:func:`_job_view` of *job* as a ``JobStatus``, or what is wrong with it."""
    if not isinstance(job, dict):
        return f"not an object ({type(job).__name__})"
    try:
        return JobStatus.model_validate(_job_view(job_id, job))
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(part) for part in first.get("loc", ())) or "record"
        return f"{exc.error_count()} error(s), first: {where}: {first.get('msg', '')}"


def _logged_defects(request: Request) -> dict[str, str]:
    """This app's record of the defect last logged for each stored job."""
    state = request.app.state
    logged: dict[str, str] | None = getattr(state, "malformed_jobs_logged", None)
    if logged is None:
        logged = state.malformed_jobs_logged = {}
    return logged


def _servable(request: Request, job_id: str, job: Any) -> JobStatus | None:
    """:func:`_job_view` of *job* as a ``JobStatus``, or None if it is not one.

    A malformed stored record (a hand-edited ``jobs.json``) is logged as a
    warning the first time each defect is seen, not on every request.
    """
    found = _defect(job_id, job)
    logged = _logged_defects(request)
    if isinstance(found, JobStatus):
        logged.pop(job_id, None)
        return found
    if logged.get(job_id) != found:
        logged[job_id] = found
        logger.warning(
            "Stored job %r is malformed and is not served (fix it in "
            "jobs.json or remove it with the master key): %s",
            job_id,
            found,
        )
    return None


def _get_servable_or_error(
    request: Request, job_id: str
) -> tuple[dict[str, Any], JobStatus]:
    """The stored job and its ``JobStatus``: 404 if absent, 409 if malformed."""
    job = _get_job_or_404(request.app.state.persistence, job_id)
    model = _servable(request, job_id, job)
    if model is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Stored job record is malformed: fix it in jobs.json or remove it "
            "(DELETE /api/jobs/{job_id} with the master key)",
        )
    return job, model


# What a rerun copies besides name, priority and params: the fields that
# make a job a model evaluation (training.evaluate_model).
_RERUN_COPIED = ("type", "model_id", "model_path")


# -- Job endpoints ----------------------------------------------------------


@router.get("/presets")
async def list_presets(
    _key_id: str = Depends(rate_limit),
) -> list[HyperparameterPreset]:
    """Return available hyperparameter presets."""
    return _get_presets()


@router.get("/", response_model=list[JobStatus])
async def list_jobs(
    request: Request,
    state: JobState | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    _key_id: str = Depends(rate_limit),
) -> list[JobStatus]:
    """List jobs, optionally filtered by state. Sorted by priority desc.

    A stored record that is not a valid job is left out (and logged).
    """
    jobs = request.app.state.persistence.get_jobs()
    servable = [
        m for jid, j in jobs.items() if (m := _servable(request, jid, j)) is not None
    ]
    logged = _logged_defects(request)
    for gone in [jid for jid in logged if jid not in jobs]:
        del logged[gone]  # removed: logged again if a record returns under its id
    filtered = [m for m in servable if state is None or m.state == state]
    filtered.sort(key=lambda m: (-m.priority, _as_utc(m.created_at)))
    return filtered[:limit]


@router.post("/", response_model=JobStatus, status_code=status.HTTP_201_CREATED)
async def create_job(
    body: JobCreate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a training job. Merges preset params if specified. Analyst key."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    merged_params = dict(body.params)
    if body.preset:
        preset = next((p for p in _get_presets() if p.name == body.preset), None)
        if preset is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, f"Unknown preset: {body.preset!r}"
            )
        merged_params = {**preset.model_dump(exclude={"name"}), **merged_params}

    job_id = str(uuid4())
    job_data: dict[str, Any] = {
        "job_id": job_id,
        "name": body.name,
        "state": JobState.queued.value,
        "priority": body.priority,
        "params": merged_params,
        "created_at": _utcnow().isoformat(),
        "started_at": None,
        "finished_at": None,
        "result": None,
        "error": None,
    }
    persistence.set_job(job_id, job_data)
    app_state.log_activity(
        "job_created",
        message=f"Job {job_id} created: {body.name}",
        details={"job_id": job_id, "preset": body.preset},
    )
    return job_data


# -- Schedule endpoints (before {job_id} to avoid path capture) -------------


@router.get("/schedules")
async def list_schedules(
    request: Request,
    node_id: str | None = Query(None),
    _key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """List all schedules with optional node_id filter."""
    schedules = request.app.state.persistence.get_schedules()
    return [
        s for s in schedules.values() if node_id is None or s.get("node_id") == node_id
    ]


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
async def create_schedule(
    body: ScheduleCreate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a new capture schedule. Requires an analyst key."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    schedule_id = str(uuid4())

    sched_data: dict[str, Any] = {
        "schedule_id": schedule_id,
        "name": body.name,
        "node_id": body.node_id,
        "interval": body.interval.value,
        "params": body.params,
        "enabled": body.enabled,
        "created_at": _utcnow().isoformat(),
        "last_run": None,
        "run_count": 0,
    }
    persistence.set_schedule(schedule_id, sched_data)
    app_state.log_activity(
        "schedule_created",
        node_id=body.node_id,
        message=f"Schedule {schedule_id} created: {body.name}",
        details={"schedule_id": schedule_id, "interval": body.interval.value},
    )
    return sched_data


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    request: Request,
    _key_id: str = Depends(require_master_key),
) -> dict[str, str]:
    """Remove a schedule. Requires master key."""
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    if not persistence.remove_schedule(schedule_id):
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Schedule not found: {schedule_id}"
        )
    app_state.log_activity(
        "schedule_deleted",
        message=f"Schedule {schedule_id} removed",
        details={"schedule_id": schedule_id},
    )
    return {"detail": f"Schedule {schedule_id} removed"}


@router.put("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    body: ScheduleUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update a schedule (enable/disable, interval, params). Analyst key."""
    schedules = request.app.state.persistence.get_schedules()
    if schedule_id not in schedules:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"Schedule not found: {schedule_id}"
        )

    sched_data = schedules[schedule_id]
    if body.enabled is not None:
        sched_data["enabled"] = body.enabled
    if body.interval is not None:
        sched_data["interval"] = body.interval.value
    if body.params is not None:
        sched_data["params"] = body.params
    request.app.state.persistence.set_schedule(schedule_id, sched_data)
    return sched_data


# -- Job detail endpoints ---------------------------------------------------


@router.get("/{job_id}", response_model=JobStatus)
async def get_job(
    job_id: str,
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> JobStatus:
    """Get a specific job by ID. 404 if not found, 409 if its record is malformed."""
    return _get_servable_or_error(request, job_id)[1]


@router.delete("/{job_id}")
async def delete_job(
    job_id: str,
    request: Request,
    _key_id: str = Depends(require_master_key),
) -> dict[str, str]:
    """Remove a job (only if queued, failed, or cancelled).

    A stored record that is not a valid job can always be removed: that is
    how a malformed record (409 everywhere else) is cleaned up.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    job_data = _get_job_or_404(persistence, job_id)

    removable = {JobState.queued, JobState.failed, JobState.cancelled}
    model = _servable(request, job_id, job_data)
    if model is not None and model.state not in removable:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Cannot remove job in state: {model.state.value}",
        )

    persistence.remove_job(job_id)
    app_state.log_activity(
        "job_deleted", message=f"Job {job_id} removed", details={"job_id": job_id}
    )
    return {"detail": f"Job {job_id} removed"}


@router.put("/{job_id}/priority", response_model=JobStatus)
async def update_priority(
    job_id: str,
    body: PriorityUpdate,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Update job priority (0-100). Requires an analyst key.

    A malformed stored record answers 409 and is left as it is.
    """
    job, _model = _get_servable_or_error(request, job_id)
    job_data = {**job, "priority": body.priority}
    request.app.state.persistence.set_job(job_id, job_data)
    return _job_view(job_id, job_data)


@router.post(
    "/{job_id}/rerun", response_model=JobStatus, status_code=status.HTTP_201_CREATED
)
async def rerun_job(
    job_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Create a new job copying parameters from an existing one. Analyst key.

    A model evaluation is rerun as a model evaluation (its ``type``,
    ``model_id`` and ``model_path`` are copied too).  A malformed stored
    record answers 409.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    source, model = _get_servable_or_error(request, job_id)

    new_id = str(uuid4())
    new_job: dict[str, Any] = {
        **{k: source[k] for k in _RERUN_COPIED if k in source},
        "job_id": new_id,
        "name": model.name,
        "state": JobState.queued.value,
        "priority": model.priority,
        "params": dict(model.params),
        "created_at": _utcnow().isoformat(),
        "started_at": None,
        "finished_at": None,
        "result": None,
        "error": None,
    }
    persistence.set_job(new_id, new_job)
    app_state.log_activity(
        "job_rerun",
        message=f"Job {new_id} created (rerun of {job_id})",
        details={"job_id": new_id, "source_job_id": job_id},
    )
    return new_job
