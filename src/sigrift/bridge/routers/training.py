"""Training run viewer and operations endpoints.

Scans training log files from nightrun/checkpoints/ and serves
run metadata, live log tail, and parsed epoch metrics for the
dashboard training tab.  Logs training lifecycle events
(start/stop/resume/stalled/failed) to the persistent audit log.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from sigrift.bridge.dependencies import require_role, Role
from sigrift.bridge.utils import get_detection_store

logger = logging.getLogger(__name__)
router = APIRouter()

# Stale threshold: if a log file hasn't been modified in this many seconds,
# the run is considered stalled.
_STALE_THRESHOLD_S = 300  # 5 minutes

# Resolve checkpoints directory relative to project root
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_CHECKPOINTS_DIR = _PROJECT_ROOT / "nightrun" / "checkpoints"

_EPOCH_RE = re.compile(
    r"Epoch\s+(\d+)/(\d+)\s*\|"
    r"\s*train_loss=([\d.inf]+)\s+train_acc=([\d.]+)\s*\|"
    r"\s*val_loss=([\d.]+)\s+val_acc=([\d.]+)\s*\|"
    r"\s*lr=([\d.e+-]+)\s*\|"
    r"\s*([\d.]+)s"
)

_ARGS_RE = re.compile(r"Args:\s*(\{.*\})")
_GPU_RE = re.compile(r"GPU:\s*(.*)")
_VRAM_RE = re.compile(r"VRAM:\s*(.*)")
_BEST_RE = re.compile(r"New best val_acc=([\d.]+) at epoch (\d+)")


def _find_log_files() -> list[Path]:
    """Find all sigrift_train_*.log files under checkpoints."""
    if not _CHECKPOINTS_DIR.is_dir():
        return []
    logs = []
    for dirpath, _, filenames in os.walk(str(_CHECKPOINTS_DIR)):
        for fn in filenames:
            if fn.startswith("sigrift_train_") and fn.endswith(".log"):
                logs.append(Path(dirpath) / fn)
    logs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return logs


def _parse_run_metadata(log_path: Path) -> dict[str, Any]:
    """Parse a training log file header for run metadata."""
    run_id = log_path.parent.name + "/" + log_path.stem
    meta: dict[str, Any] = {
        "run_id": run_id,
        "log_file": str(log_path.relative_to(_PROJECT_ROOT)),
        "dir": log_path.parent.name,
        "filename": log_path.name,
        "size_bytes": log_path.stat().st_size,
        "modified": datetime.fromtimestamp(log_path.stat().st_mtime).isoformat(),
    }

    # Parse first 30 lines for header info
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            lines = []
            for i, line in enumerate(f):
                if i >= 40:
                    break
                lines.append(line)
    except OSError:
        return meta

    for line in lines:
        args_m = _ARGS_RE.search(line)
        if args_m:
            try:
                import ast

                args = ast.literal_eval(args_m.group(1))
                meta["epochs"] = args.get("epochs")
                meta["batch_size"] = args.get("batch_size")
                meta["lr"] = args.get("lr")
                meta["gamma"] = args.get("gamma")
                meta["seed"] = args.get("seed")
            except Exception:
                pass

        gpu_m = _GPU_RE.search(line)
        if gpu_m:
            meta["gpu"] = gpu_m.group(1).strip()

        vram_m = _VRAM_RE.search(line)
        if vram_m:
            meta["vram"] = vram_m.group(1).strip()

        if "Model parameters:" in line:
            parts = line.split("Model parameters:")
            if len(parts) > 1:
                meta["parameters"] = parts[1].strip()

    # Parse entire file for epoch data to get current state
    metrics = _parse_metrics(log_path)
    mtime = log_path.stat().st_mtime
    age_s = time.time() - mtime
    if metrics:
        last = metrics[-1]
        meta["current_epoch"] = last["epoch"]
        meta["total_epochs"] = last["total_epochs"]
        meta["val_acc"] = last["val_acc"]
        meta["val_loss"] = last["val_loss"]
        meta["best_val_acc"] = max(m["val_acc"] for m in metrics)
        if last["epoch"] >= last["total_epochs"]:
            meta["status"] = "completed"
        elif age_s > _STALE_THRESHOLD_S:
            meta["status"] = "stalled"
        else:
            meta["status"] = "active"
    else:
        meta["status"] = "starting" if age_s < _STALE_THRESHOLD_S else "failed"
    meta["last_activity_s"] = round(age_s, 1)

    # Check timestamps for elapsed time
    for line in lines:
        ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
        if ts_match:
            meta["start_time"] = ts_match.group(1)
            break

    return meta


def _parse_metrics(log_path: Path) -> list[dict[str, Any]]:
    """Parse epoch metrics from a training log."""
    metrics = []
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = _EPOCH_RE.search(line)
                if m:
                    train_loss = m.group(3)
                    metrics.append(
                        {
                            "epoch": int(m.group(1)),
                            "total_epochs": int(m.group(2)),
                            "train_loss": float(train_loss)
                            if train_loss != "inf"
                            else None,
                            "train_acc": float(m.group(4)),
                            "val_loss": float(m.group(5)),
                            "val_acc": float(m.group(6)),
                            "lr": float(m.group(7)),
                            "time_s": float(m.group(8)),
                        }
                    )
                best_m = _BEST_RE.search(line)
                if best_m and metrics:
                    metrics[-1]["is_best"] = True
    except OSError:
        pass
    return metrics


def _list_runs_sync() -> list[dict[str, Any]]:
    """Synchronous helper — runs in a thread to avoid blocking the event loop."""
    logs = _find_log_files()
    runs = []
    for log_path in logs:
        try:
            meta = _parse_run_metadata(log_path)
            runs.append(meta)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", log_path, exc)

    return runs


@router.get("/runs")
async def list_training_runs(
    _: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List all training runs with metadata."""
    return await asyncio.to_thread(_list_runs_sync)


@router.get("/runs/{run_dir}/{run_name}/log")
async def get_training_log(
    run_dir: str,
    run_name: str,
    lines: int = Query(200, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    _: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Return last N lines of a training log."""
    log_path = _validate_run_path(run_dir, run_name)

    def _read_log() -> dict[str, Any]:
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                all_lines = f.readlines()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        total = len(all_lines)
        if offset > 0:
            selected = all_lines[offset : offset + lines]
        else:
            selected = all_lines[-lines:] if len(all_lines) > lines else all_lines
        return {
            "total_lines": total,
            "offset": offset if offset > 0 else max(0, total - lines),
            "lines": [l.rstrip("\n") for l in selected],  # noqa: E741
        }

    return await asyncio.to_thread(_read_log)


@router.get("/runs/{run_dir}/{run_name}/metrics")
async def get_training_metrics(
    run_dir: str,
    run_name: str,
    _: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Parse and return epoch metrics from a training log."""
    log_path = _validate_run_path(run_dir, run_name)

    def _get_metrics() -> dict[str, Any]:
        metrics = _parse_metrics(log_path)
        best_acc = max((m["val_acc"] for m in metrics), default=0)
        return {
            "run_id": run_dir + "/" + run_name,
            "epochs": metrics,
            "best_val_acc": best_acc,
            "total_epochs": metrics[-1]["total_epochs"] if metrics else 0,
            "completed": len(metrics),
        }

    return await asyncio.to_thread(_get_metrics)


# ---------------------------------------------------------------------------
# Training operation audit helpers
# ---------------------------------------------------------------------------


async def _log_training_event(
    request: Request,
    action: str,
    run_id: str,
    operator: str = "system",
    note: str = "",
    details: dict | None = None,
) -> dict[str, Any] | None:
    """Write a training event to the persistent audit log (non-blocking)."""
    store = get_detection_store(request)
    try:
        entry = await asyncio.to_thread(
            store.log_audit,
            action=action,
            target_id=run_id,
            operator=operator,
            note=note,
            details=details or {},
        )
        app_state = getattr(request.app.state, "app_state", None)
        if app_state and hasattr(app_state, "log_activity"):
            app_state.log_activity(
                "training_operation",
                message=f"Training {action}: {run_id}" + (f" — {note}" if note else ""),
                details={"action": action, "run_id": run_id, **(details or {})},
            )
        return entry
    except Exception:
        logger.exception("Failed to log training event %s for %s", action, run_id)
        return None


def _health_scan_sync() -> list[dict[str, Any]]:
    """Synchronous helper for /health — scans all log files for metadata."""
    logs = _find_log_files()
    results = []
    for log_path in logs:
        try:
            results.append(_parse_run_metadata(log_path))
        except Exception:
            continue
    return results


def _validate_run_path(run_dir: str, run_name: str) -> Path:
    """Validate and resolve a run path, raising 400/404 on problems."""
    base = Path(_CHECKPOINTS_DIR).resolve()
    candidate = (base / run_dir / (run_name + ".log")).resolve()
    if not candidate.is_relative_to(base):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not candidate.is_file():
        raise HTTPException(status_code=404, detail="Log not found")
    return candidate


# ---------------------------------------------------------------------------
# Training operation endpoints
# ---------------------------------------------------------------------------


@router.get("/operations")
async def list_training_operations(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """Return training operation audit entries (start/stop/resume/stalled/failed)."""
    store = get_detection_store(request)
    all_entries = await asyncio.to_thread(store.get_audit_log, limit=limit * 5)
    training_actions = {
        "training_start",
        "training_stop",
        "training_resume",
        "training_stalled",
        "training_failed",
        "training_completed",
    }
    results = [e for e in all_entries if e.get("action") in training_actions]
    return results[:limit]


class TrainingActionBody(BaseModel):
    """Request body for manual training operation logging."""

    note: str = ""


@router.post("/runs/{run_dir}/{run_name}/start")
async def log_training_start(
    run_dir: str,
    run_name: str,
    body: TrainingActionBody,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Log a training run start event."""
    log_path = _validate_run_path(run_dir, run_name)
    run_id = f"{run_dir}/{run_name}"
    meta = await asyncio.to_thread(_parse_run_metadata, log_path)
    entry = await _log_training_event(
        request,
        "training_start",
        run_id,
        operator=_key_id,
        note=body.note or f"Training started: {meta.get('gpu', 'unknown GPU')}",
        details={
            "epochs": meta.get("epochs"),
            "batch_size": meta.get("batch_size"),
            "lr": meta.get("lr"),
            "gpu": meta.get("gpu"),
        },
    )
    return entry or {"status": "logged"}


@router.post("/runs/{run_dir}/{run_name}/stop")
async def log_training_stop(
    run_dir: str,
    run_name: str,
    body: TrainingActionBody,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Log a training run stop event."""
    log_path = _validate_run_path(run_dir, run_name)
    run_id = f"{run_dir}/{run_name}"
    meta = await asyncio.to_thread(_parse_run_metadata, log_path)
    entry = await _log_training_event(
        request,
        "training_stop",
        run_id,
        operator=_key_id,
        note=body.note or f"Stopped at epoch {meta.get('current_epoch', '?')}",
        details={
            "current_epoch": meta.get("current_epoch"),
            "best_val_acc": meta.get("best_val_acc"),
        },
    )
    return entry or {"status": "logged"}


@router.post("/runs/{run_dir}/{run_name}/resume")
async def log_training_resume(
    run_dir: str,
    run_name: str,
    body: TrainingActionBody,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Log a training run resume event."""
    log_path = _validate_run_path(run_dir, run_name)
    run_id = f"{run_dir}/{run_name}"
    meta = await asyncio.to_thread(_parse_run_metadata, log_path)
    entry = await _log_training_event(
        request,
        "training_resume",
        run_id,
        operator=_key_id,
        note=body.note or f"Resumed from epoch {meta.get('current_epoch', '?')}",
        details={
            "current_epoch": meta.get("current_epoch"),
            "best_val_acc": meta.get("best_val_acc"),
        },
    )
    return entry or {"status": "logged"}


@router.get("/health")
async def training_health(
    request: Request,
    _: str = Depends(require_role(Role.VIEWER)),
) -> dict[str, Any]:
    """Check training health: detect stalled/failed/completed runs and log events.

    Returns current status of all runs with auto-detected state transitions.
    """
    # Run file I/O in a thread to avoid blocking the event loop
    all_meta = await asyncio.to_thread(_health_scan_sync)
    store = get_detection_store(request)
    results = []

    for meta in all_meta:
        run_id = meta["run_id"]
        status = meta.get("status", "unknown")

        # Auto-log state transitions for stalled/failed/completed
        if status in ("stalled", "failed", "completed"):
            recent = await asyncio.to_thread(
                store.get_audit_log,
                limit=5,
                target_id=run_id,
            )
            action = f"training_{status}"
            already_logged = any(e.get("action") == action for e in recent)
            if not already_logged:
                details = {
                    "current_epoch": meta.get("current_epoch"),
                    "best_val_acc": meta.get("best_val_acc"),
                    "last_activity_s": meta.get("last_activity_s"),
                }
                await _log_training_event(
                    request,
                    action,
                    run_id,
                    operator="system",
                    note=f"Auto-detected: {status}",
                    details=details,
                )
                logger.info("Auto-logged training_%s for %s", status, run_id)

        results.append(
            {
                "run_id": run_id,
                "status": status,
                "current_epoch": meta.get("current_epoch"),
                "best_val_acc": meta.get("best_val_acc"),
                "last_activity_s": meta.get("last_activity_s"),
            }
        )

    return {"runs": results, "checked_at": datetime.now(timezone.utc).isoformat()}
