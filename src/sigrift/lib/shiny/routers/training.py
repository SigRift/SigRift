"""Training and model management router.

Prefix: ``/api/training`` (set when including the router in ``app.py``).
All endpoints require ``rate_limit`` dependency (auth + sliding window);
queueing a model evaluation also needs an ``analyst`` key (an ``admin`` key
or the master key is one), as creating a job does.

The training history store (``history.json``) is keyed by node id, each
holding a list of run entries; the history routes serve the runs.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, status

from sigrift.lib.shiny.dependencies import (
    Role,
    accept_ws,
    rate_limit,
    require_role,
    require_ws_auth,
)
from sigrift.lib.shiny.models import JobState, TrainingStatus
from sigrift.lib.shiny.training_parser import parse_training_history, parse_training_log

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Search paths for training logs and model files
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[3]  # /mnt/z/mlrf

_LOG_SEARCH_DIRS = [
    _PROJECT_ROOT,
    _PROJECT_ROOT / "nightrun",
    _PROJECT_ROOT / "src" / "sigrift",
]

_MODEL_SEARCH_DIRS = [
    _PROJECT_ROOT / "src" / "sigrift" / "models",
    _PROJECT_ROOT / "models",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_training_logs() -> list[Path]:
    """Find *.log files that look like training logs."""
    results: list[Path] = []
    for d in _LOG_SEARCH_DIRS:
        if not d.is_dir():
            continue
        try:
            for f in d.iterdir():
                if f.suffix == ".log" and f.is_file():
                    results.append(f)
        except OSError:
            continue
    return sorted(results, key=lambda p: p.stat().st_mtime, reverse=True)


def _find_model_files() -> list[Path]:
    """Find *.pth model files."""
    results: list[Path] = []
    for d in _MODEL_SEARCH_DIRS:
        if not d.is_dir():
            continue
        try:
            for f in d.iterdir():
                if f.suffix == ".pth" and f.is_file():
                    results.append(f)
        except OSError:
            continue
    return sorted(results, key=lambda p: p.stat().st_mtime, reverse=True)


def stored_runs_by_node(history: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Each node's stored runs, oldest first (the history and export routes).

    The store maps a node id to that node's list of run entries; a value
    that is not a list, or an entry that is not an object (a hand-edited
    ``history.json``), is skipped.
    """
    return {
        node_id: [entry for entry in entries if isinstance(entry, dict)]
        for node_id, entries in history.items()
        if isinstance(entries, list)
    }


def _stored_runs(history: dict[str, Any]) -> list[dict[str, Any]]:
    """Every stored run, oldest first per node, each with its ``node_id``."""
    return [
        {**entry, "node_id": node_id}
        for node_id, entries in stored_runs_by_node(history).items()
        for entry in entries
    ]


def _model_meta(path: Path) -> dict[str, Any]:
    """Build metadata dict for a model file."""
    try:
        st = path.stat()
    except OSError:
        return {"name": path.name, "path": str(path), "error": "stat failed"}
    return {
        "model_id": path.stem,
        "name": path.name,
        "path": str(path),
        "size_bytes": st.st_size,
        "modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Training endpoints
# ---------------------------------------------------------------------------


@router.get("/current")
async def training_current(
    request: Request,
    key_id: str = Depends(rate_limit),
) -> TrainingStatus:
    """Scan for active training logs and return current status."""
    logs = _find_training_logs()
    if not logs:
        return TrainingStatus()

    # Use the most recently modified log
    latest = logs[0]
    data = parse_training_log(latest)
    return TrainingStatus(
        run_id=data.get("run_id", latest.stem),
        running=data.get("running", False),
        current_epoch=data.get("current_epoch", 0),
        total_epochs=data.get("total_epochs", 0),
        best_epoch=data.get("best_epoch", 0),
        best_val_acc=data.get("best_val_acc", 0.0),
        latest_epoch=data.get("latest_epoch"),
    )


@router.get("/history")
async def training_history(
    request: Request,
    key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """Return every stored training run (each with the ``node_id`` it ran on)."""
    return _stored_runs(request.app.state.persistence.get_history())


@router.get("/runs/{run_id}")
async def training_run_detail(
    run_id: str,
    request: Request,
    key_id: str = Depends(rate_limit),
) -> dict[str, Any]:
    """Get details for a specific training run.

    Looks in persistence first (the last stored run with this ``run_id``),
    then scans log files by name.
    """
    # Check persistence
    for run in reversed(_stored_runs(request.app.state.persistence.get_history())):
        if run.get("run_id") == run_id:
            return run

    # Fall back to scanning logs
    logs = _find_training_logs()
    for log in logs:
        if log.stem == run_id:
            epochs = parse_training_history(log)
            status_data = parse_training_log(log)
            return {
                "run_id": run_id,
                "log_path": str(log),
                "status": status_data,
                "epochs": epochs,
            }

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Training run {run_id!r} not found",
    )


# ---------------------------------------------------------------------------
# Model endpoints
# ---------------------------------------------------------------------------


@router.get("/models")
async def list_models(
    request: Request,
    key_id: str = Depends(rate_limit),
) -> list[dict[str, Any]]:
    """List model files (*.pth) with metadata."""
    return [_model_meta(p) for p in _find_model_files()]


@router.get("/models/{model_id}")
async def get_model(
    model_id: str,
    request: Request,
    key_id: str = Depends(rate_limit),
) -> dict[str, Any]:
    """Get metadata for a specific model."""
    for p in _find_model_files():
        if p.stem == model_id:
            return _model_meta(p)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Model {model_id!r} not found",
    )


@router.post("/models/{model_id}/evaluate")
async def evaluate_model(
    model_id: str,
    request: Request,
    key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Queue a model evaluation job. Requires an analyst key.

    The job is stored as a complete job record (name, priority, params ...)
    so the job list and job detail can serve it.
    """
    # Verify model exists
    model_path: Path | None = None
    for p in _find_model_files():
        if p.stem == model_id:
            model_path = p
            break

    if model_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model {model_id!r} not found",
        )

    persistence = request.app.state.persistence
    job_id = f"eval-{model_id}-{uuid.uuid4().hex[:8]}"
    job_data: dict[str, Any] = {
        "job_id": job_id,
        "name": f"evaluate-{model_id}",
        "type": "evaluate",
        "model_id": model_id,
        "model_path": str(model_path),
        "state": JobState.queued.value,
        "priority": 0,
        "params": {},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "finished_at": None,
        "result": None,
        "error": None,
    }
    persistence.set_job(job_id, job_data)
    persistence.mark_dirty()

    request.app.state.app_state.log_activity(
        "model_evaluate",
        message=f"Queued evaluation for model {model_id}",
    )
    return job_data


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------


@router.websocket("/ws/training")
async def ws_training(websocket: WebSocket) -> None:
    """Stream training progress to authenticated WebSocket clients."""
    await require_ws_auth(websocket)
    await accept_ws(websocket)
    app_state = websocket.app.state.app_state
    await app_state.ws_training_clients.add(websocket)

    try:
        while True:
            _ = await websocket.receive_text()
    except Exception:
        pass
    finally:
        await app_state.ws_training_clients.remove(websocket)
