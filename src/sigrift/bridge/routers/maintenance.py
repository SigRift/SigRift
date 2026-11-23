"""Database maintenance router for The Bridge admin panel.

Provides endpoints for cleanup, backup, vacuum, WAL checkpoint,
optimize, and purge tasks. All endpoints require master key authentication.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from sigrift.bridge import bundles
from sigrift.bridge.constants import BRIDGE_RETENTION_DAYS
from sigrift.bridge.dependencies import admin_rate_limit as _admin_rate_limit
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, utcnow

logger = logging.getLogger(__name__)

_MAX_BACKUPS = 10

# Backup encryption
_BACKUP_ENC_MAGIC = b"BRIDGE_ENC_V1\n"
_BACKUP_CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB per chunk
_backup_fernet = None

_utcnow = utcnow
_get_detection_store = get_detection_store


class BackupKeyError(ValueError):
    """``BRIDGE_BACKUP_ENCRYPTION_KEY`` is set but is not a usable Fernet key."""


#: Why a backup was refused (never quotes the key).
_BACKUP_KEY_INVALID_DETAIL = (
    "BRIDGE_BACKUP_ENCRYPTION_KEY is set but is not a valid Fernet key "
    "(32 url-safe base64-encoded bytes), so backups cannot be encrypted. "
    "No backup was written. Set a valid key (generate one with: python3 -c "
    "'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    "), or unset it to write unencrypted backups, then restart the bridge."
)


def _get_backup_fernet():
    """Return a Fernet instance for backup encryption, or None if not configured.

    Reads a Fernet-compatible key from ``BRIDGE_BACKUP_ENCRYPTION_KEY``.
    Raises :class:`BackupKeyError` when the key is set but unusable: a
    configured key never falls back to plaintext (D-9).
    """
    global _backup_fernet
    if _backup_fernet is not None:
        return _backup_fernet
    key = os.environ.get("BRIDGE_BACKUP_ENCRYPTION_KEY", "").strip()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet

        _backup_fernet = Fernet(key.encode() if isinstance(key, str) else key)
        return _backup_fernet
    except Exception as exc:
        # Only the exception type: a decoding error can quote part of the key.
        logger.error(
            "BRIDGE_BACKUP_ENCRYPTION_KEY is unusable (%s); backups are refused",
            type(exc).__name__,
        )
        raise BackupKeyError(_BACKUP_KEY_INVALID_DETAIL) from None


def _encrypt_backup_file(src: Path) -> Path:
    """Encrypt *src* in chunked Fernet format, delete plaintext, return encrypted path.

    If no encryption key is configured, returns *src* unchanged; raises
    :class:`BackupKeyError` (leaving *src* as it is) for an unusable one.
    """
    fernet = _get_backup_fernet()
    if fernet is None:
        return src

    enc_path = src.with_suffix(".db.enc")
    with open(src, "rb") as fin, open(enc_path, "wb") as fout:
        fout.write(_BACKUP_ENC_MAGIC)
        while True:
            chunk = fin.read(_BACKUP_CHUNK_SIZE)
            if not chunk:
                break
            encrypted = fernet.encrypt(chunk)
            fout.write(len(encrypted).to_bytes(4, "big"))
            fout.write(encrypted)

    src.unlink()
    logger.info("Encrypted backup: %s -> %s", src.name, enc_path.name)
    return enc_path


def _decrypt_backup_file(src: Path, dest: Path) -> None:
    """Decrypt a chunked Fernet backup to *dest*.

    Raises ValueError if the key is missing or unusable (:class:`BackupKeyError`)
    or the file format is invalid.
    """
    fernet = _get_backup_fernet()
    if fernet is None:
        raise ValueError("BRIDGE_BACKUP_ENCRYPTION_KEY not set — cannot decrypt")

    with open(src, "rb") as fin, open(dest, "wb") as fout:
        magic = fin.read(len(_BACKUP_ENC_MAGIC))
        if magic != _BACKUP_ENC_MAGIC:
            raise ValueError("Not a Bridge encrypted backup file")
        while True:
            length_bytes = fin.read(4)
            if not length_bytes or len(length_bytes) < 4:
                break
            length = int.from_bytes(length_bytes, "big")
            encrypted_chunk = fin.read(length)
            if len(encrypted_chunk) != length:
                raise ValueError("Truncated encrypted backup chunk")
            fout.write(fernet.decrypt(encrypted_chunk))


router = APIRouter()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


#: Why the bridge never deletes audit entries itself.  The gateway's
#: archive moves the oldest verified, contiguous prefix of the chain into
#: ``audit_log_archive`` and records an anchor, so the remaining chain
#: still verifies; it refuses entries younger than
#: ``UC_AUDIT_MIN_RETENTION_DAYS`` (default 7); its purge only deletes
#: archived entries at or before the anchor.  A plain ``DELETE`` here
#: would bypass all three.
_AUDIT_RETENTION_DETAIL = (
    "The audit log is not purged by maintenance tasks. Archive old entries "
    'with POST /api/admin/audit/archive {"days": N}, then delete archived '
    "entries with DELETE /api/admin/audit?days=N (the gateway keeps the "
    "chain verifiable and enforces UC_AUDIT_MIN_RETENTION_DAYS)."
)


class MaintenanceRequest(BaseModel):
    model_config = {"extra": "forbid"}
    task: str
    retention_days: int = Field(default=7, ge=1, le=365)
    retention_hours: int | None = Field(default=None, ge=1, le=8760)


# ---------------------------------------------------------------------------
# Maintenance endpoint
# ---------------------------------------------------------------------------


@router.post("/maintenance")
async def run_maintenance(
    body: MaintenanceRequest,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Run a database maintenance task.

    Supported tasks:
    - ``purge_detections``  -- delete raw detections older than retention_days
    - ``purge_rf_anomalies`` -- delete RF anomalies older than retention_days
    - ``purge_wifi_anomalies`` -- delete WiFi anomalies older than retention_days
    - ``purge_wifi_metadata`` -- delete WiFi metadata (retention_days used as hours)
    - ``purge_wifi_hourly`` -- delete hourly WiFi summaries older than retention_days
    - ``purge_audit_log`` -- refused (409): the audit log is archived and
      purged only by the gateway (see ``_AUDIT_RETENTION_DETAIL``)
    - ``purge_iq_captures`` -- delete IQ capture files older than retention_days
    - ``purge_pcap_captures`` -- delete pcap files older than retention_days
    - ``aggregate_wifi`` -- roll up wifi_metadata into hourly summaries
    - ``aggregate_detections`` -- roll up raw detections into hourly aggregates
    - ``reeval_dismiss_rf`` -- re-evaluate RF anomalies, dismiss resolved
    - ``reeval_dismiss_wifi`` -- re-evaluate WiFi anomalies, dismiss resolved
    - ``dismiss_all_rf`` -- dismiss all active RF anomalies
    - ``dismiss_all_wifi`` -- dismiss all active WiFi anomalies
    - ``vacuum`` -- reclaim disk space (VACUUM)
    - ``wal_checkpoint`` -- force WAL checkpoint
    - ``optimize`` -- run PRAGMA optimize
    - ``full_cleanup`` -- run all purges + vacuum
    - ``purge_old_data`` -- run all purges using BRIDGE_RETENTION_DAYS (env
      default); the audit log is left to the gateway's anchored archive
    """

    store = _get_detection_store(request)
    app_state: AppState = request.app.state.app_state
    task = body.task
    days = body.retention_days
    result: dict[str, Any] = {"task": task, "retention_days": days}

    job = app_state.start_job(task, trigger="manual")

    try:
        result = await _execute_maintenance(
            store,
            request,
            task,
            days,
            result,
            retention_hours=body.retention_hours,
        )
    except HTTPException as exc:
        app_state.finish_job(job, error=exc.detail)
        raise
    except Exception as exc:
        logger.exception("Maintenance task '%s' failed", task)
        app_state.finish_job(job, error=str(exc))
        raise HTTPException(status_code=500, detail="Internal maintenance error")

    app_state.finish_job(job, result=result)

    store.log_audit(
        action="maintenance_" + task,
        target_id="system",
        operator=_key_id,
        note=f"retention={days}d",
    )

    return result


async def _execute_maintenance(
    store: Any,
    request: Request,
    task: str,
    days: int,
    result: dict[str, Any],
    *,
    retention_hours: int | None = None,
) -> dict[str, Any]:
    """Execute a single maintenance task. Returns the result dict."""
    import asyncio

    if task == "purge_detections":
        deleted = await asyncio.to_thread(store.cleanup, days)
        result["deleted"] = deleted

    elif task == "purge_rf_anomalies":
        deleted = await asyncio.to_thread(store.cleanup_rf_anomalies, days)
        result["deleted"] = deleted

    elif task == "purge_wifi_anomalies":
        deleted = await asyncio.to_thread(store.cleanup_wifi_anomalies, days)
        result["deleted"] = deleted

    elif task == "purge_wifi_metadata":
        # Use retention_hours if provided, otherwise retention_days * 24
        hours = retention_hours if retention_hours is not None else days * 24
        deleted = await asyncio.to_thread(store.cleanup_wifi_metadata, hours)
        result["deleted"] = deleted
        result["note"] = f"Used {hours}h retention"

    elif task == "purge_wifi_hourly":
        deleted = await asyncio.to_thread(store.cleanup_wifi_hourly, days)
        result["deleted"] = deleted

    elif task == "aggregate_wifi":
        # cutoff_hours defaults to 2; use retention_days as cutoff_hours
        aggregated = await asyncio.to_thread(store.aggregate_wifi_hourly, days)
        result["aggregated"] = aggregated
        result["note"] = f"Aggregated wifi rows older than {days}h"

    elif task == "purge_audit_log":
        # Deleting live audit rows breaks the HMAC chain and erases history
        # without an anchor (review P3); only the gateway's anchored
        # archive may remove audit entries.
        raise HTTPException(status_code=409, detail=_AUDIT_RETENTION_DETAIL)

    elif task == "purge_iq_captures":
        iq_store = getattr(request.app.state, "iq_store", None)
        if iq_store is None:
            raise HTTPException(status_code=404, detail="IQ store not available")
        deleted = await asyncio.to_thread(iq_store.cleanup, days)
        result["deleted"] = deleted

    elif task == "purge_pcap_captures":
        pcap_store = getattr(request.app.state, "pcap_store", None)
        if pcap_store is None:
            raise HTTPException(status_code=404, detail="Pcap store not available")
        deleted = await asyncio.to_thread(pcap_store.cleanup, days)
        result["deleted"] = deleted

    elif task == "vacuum":
        info = await asyncio.to_thread(store.vacuum)
        result["db_size_bytes"] = info["db_size_bytes"]
        result["reclaimed_bytes"] = info["reclaimed_bytes"]
        result["vacuumed"] = True

    elif task == "wal_checkpoint":
        info = await asyncio.to_thread(store.wal_checkpoint)
        result["wal_pages"] = info["wal_pages"]
        result["checkpointed"] = info["checkpointed"]

    elif task == "aggregate_detections":
        aggregated = await asyncio.to_thread(store.aggregate_hourly)
        result["aggregated"] = aggregated
        result["note"] = "Aggregated raw detections into hourly buckets"

    elif task == "reeval_dismiss_rf":
        # Server-side re-evaluate and auto-dismiss resolved RF anomalies
        rf_scorer = getattr(request.app.state, "rf_scorer", None)
        anomalies = await asyncio.to_thread(
            store.get_rf_anomalies,
            min_score=0.0,
            limit=100000,
        )
        dismissed_ids = []
        still_active = 0
        for a in anomalies:
            if rf_scorer:
                try:
                    res = rf_scorer.score(a)
                    if res.score < 0.3:
                        dismissed_ids.append(a["id"])
                        continue
                except Exception:
                    pass
            still_active += 1
        if dismissed_ids:
            await asyncio.to_thread(store.dismiss_rf_anomalies_bulk, dismissed_ids)
        result["processed"] = len(anomalies)
        result["dismissed"] = len(dismissed_ids)
        result["still_active"] = still_active

    elif task == "reeval_dismiss_wifi":
        # Server-side re-evaluate and auto-dismiss resolved WiFi anomalies
        wifi_scorer = getattr(request.app.state, "wifi_scorer", None)
        anomalies = await asyncio.to_thread(
            store.get_wifi_anomalies,
            min_score=0.0,
            limit=100000,
        )
        dismissed_ids = []
        still_active = 0
        for a in anomalies:
            if wifi_scorer:
                try:
                    res = wifi_scorer.reevaluate(a)
                    if not res.get("still_anomalous", True):
                        dismissed_ids.append(a["id"])
                        continue
                except Exception:
                    pass
            still_active += 1
        if dismissed_ids:
            await asyncio.to_thread(store.dismiss_wifi_anomalies_bulk, dismissed_ids)
        result["processed"] = len(anomalies)
        result["dismissed"] = len(dismissed_ids)
        result["still_active"] = still_active

    elif task == "dismiss_all_rf":
        anomalies = await asyncio.to_thread(
            store.get_rf_anomalies,
            min_score=0.0,
            limit=100000,
        )
        ids = [a["id"] for a in anomalies]
        if ids:
            await asyncio.to_thread(store.dismiss_rf_anomalies_bulk, ids)
        result["dismissed"] = len(ids)

    elif task == "dismiss_all_wifi":
        anomalies = await asyncio.to_thread(
            store.get_wifi_anomalies,
            min_score=0.0,
            limit=100000,
        )
        ids = [a["id"] for a in anomalies]
        if ids:
            await asyncio.to_thread(store.dismiss_wifi_anomalies_bulk, ids)
        result["dismissed"] = len(ids)

    elif task == "optimize":
        await asyncio.to_thread(store.optimize)
        result["status"] = "ok"

    elif task == "purge_old_data":
        # Use BRIDGE_RETENTION_DAYS as default, but allow body override
        policy_days = BRIDGE_RETENTION_DAYS
        aggregated = await asyncio.to_thread(store.aggregate_wifi_hourly, 2)
        deleted_det = await asyncio.to_thread(store.cleanup, policy_days)
        deleted_rf = await asyncio.to_thread(store.cleanup_rf_anomalies, policy_days)
        deleted_wifi = await asyncio.to_thread(
            store.cleanup_wifi_anomalies, policy_days
        )
        deleted_meta = await asyncio.to_thread(
            store.cleanup_wifi_metadata,
            policy_days * 24,
        )
        deleted_hourly = await asyncio.to_thread(
            store.cleanup_wifi_hourly,
            policy_days,
        )

        # The audit log is not purged here: entries leave it only through
        # the gateway's anchored archive (see _AUDIT_RETENTION_DETAIL).
        deleted_audit = 0

        iq_deleted = 0
        iq_store = getattr(request.app.state, "iq_store", None)
        if iq_store:
            iq_deleted = await asyncio.to_thread(iq_store.cleanup, policy_days)

        pcap_deleted = 0
        pcap_store = getattr(request.app.state, "pcap_store", None)
        if pcap_store:
            pcap_deleted = await asyncio.to_thread(pcap_store.cleanup, policy_days)

        result["retention_days"] = policy_days
        result["deleted"] = {
            "detections": deleted_det,
            "rf_anomalies": deleted_rf,
            "wifi_anomalies": deleted_wifi,
            "wifi_metadata": deleted_meta,
            "wifi_hourly": deleted_hourly,
            "audit_log": deleted_audit,
            "iq_captures": iq_deleted,
            "pcap_captures": pcap_deleted,
        }
        result["aggregated_wifi_hourly"] = aggregated
        result["audit_log_note"] = _AUDIT_RETENTION_DETAIL

    elif task == "full_cleanup":
        # Aggregate wifi hourly BEFORE purging raw data
        aggregated = await asyncio.to_thread(store.aggregate_wifi_hourly, 2)
        deleted_det = await asyncio.to_thread(store.cleanup, days)
        deleted_rf = await asyncio.to_thread(store.cleanup_rf_anomalies, days)
        deleted_wifi = await asyncio.to_thread(store.cleanup_wifi_anomalies, days)
        deleted_meta = await asyncio.to_thread(store.cleanup_wifi_metadata, days * 24)
        deleted_hourly = await asyncio.to_thread(store.cleanup_wifi_hourly, 90)

        iq_deleted = 0
        iq_store = getattr(request.app.state, "iq_store", None)
        if iq_store:
            iq_deleted = await asyncio.to_thread(iq_store.cleanup, days)

        pcap_deleted = 0
        pcap_store = getattr(request.app.state, "pcap_store", None)
        if pcap_store:
            pcap_deleted = await asyncio.to_thread(pcap_store.cleanup, days)

        await asyncio.to_thread(store.wal_checkpoint)
        await asyncio.to_thread(store.vacuum)

        result["deleted"] = {
            "detections": deleted_det,
            "rf_anomalies": deleted_rf,
            "wifi_anomalies": deleted_wifi,
            "wifi_metadata": deleted_meta,
            "wifi_hourly": deleted_hourly,
            "iq_captures": iq_deleted,
            "pcap_captures": pcap_deleted,
        }
        result["aggregated_wifi_hourly"] = aggregated
        result["vacuumed"] = True

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown maintenance task: {task}",
        )

    return result


# ---------------------------------------------------------------------------
# Database Backup
# ---------------------------------------------------------------------------


@router.post("/backup")
async def create_backup(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Create an online backup of the database.

    Uses SQLite's C-level backup API (``connection.backup()``) with
    ``pages=100, sleep=0.01`` so concurrent reads are not blocked.
    Stores the backup in the data/backups/ directory with a timestamped name.
    """
    store = _get_detection_store(request)
    # D-9: Optionally encrypt the backup at rest.  A key that is set but
    # unusable refuses the backup before anything is written: never a
    # plaintext copy in its place.
    try:
        encrypted = _get_backup_fernet() is not None
    except BackupKeyError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from None

    ctx = store._ctx
    db_path = Path(ctx.db_path)
    backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_path = backup_dir / f"detections_backup_{ts}.db"

    result = await asyncio.to_thread(ctx.backup, backup_path)

    final_path = await asyncio.to_thread(_encrypt_backup_file, backup_path)

    # Compute SHA-256 checksum of final (possibly encrypted) file
    sha256_hex = await asyncio.to_thread(_compute_sha256, final_path)
    sidecar_path = final_path.with_suffix(final_path.suffix + ".sha256")
    sidecar_path.write_text(f"{sha256_hex}  {final_path.name}\n")

    store.log_audit(
        action="admin_backup",
        target_id="system",
        operator=_key_id,
        note=f"backup={final_path.name} size={result['size_bytes']} encrypted={encrypted} sha256={sha256_hex[:16]}…",
    )

    # Prune old backups beyond configured retention
    max_backups = int(os.environ.get("BRIDGE_BACKUP_RETENTION", str(_MAX_BACKUPS)))
    _prune_old_backups(backup_dir, keep=max_backups)

    return {
        "status": result["status"],
        "backup_file": final_path.name,
        "size_bytes": final_path.stat().st_size,
        "elapsed_sec": result["elapsed_sec"],
        "sha256": sha256_hex,
        "encrypted": encrypted,
    }


@router.get("/backups")
async def list_backups(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List available database backups."""
    store = _get_detection_store(request)
    db_path = Path(store.db_path)
    backup_dir = db_path.parent / "backups"

    backups = []
    if backup_dir.exists():
        # List both plaintext (.db) and encrypted (.db.enc) backups
        files = sorted(
            list(backup_dir.glob("*.db")) + list(backup_dir.glob("*.db.enc")),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for f in files:
            backups.append(
                {
                    "name": f.name,
                    "size_bytes": f.stat().st_size,
                    "encrypted": f.suffix == ".enc",
                    "created": datetime.fromtimestamp(
                        f.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )

    return {"count": len(backups), "backups": backups}


# A backup file name (.db, or .db.enc when encrypted).  Matched with
# ``fullmatch``: with ``match`` and a ``$`` anchor a trailing newline passed
# ("x.db\n").
_BACKUP_NAME_RE = re.compile(r"[a-zA-Z0-9_.-]+\.db(\.enc)?")


@router.get("/backups/{filename}")
async def download_backup(
    filename: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> FileResponse:
    """Download a database backup file."""
    store = _get_detection_store(request)
    db_path = Path(store.db_path)
    backup_dir = db_path.parent / "backups"

    # Sanitize filename -- allow .db and .db.enc
    if not _BACKUP_NAME_RE.fullmatch(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    backup_path = backup_dir / filename
    if not backup_path.exists() or not backup_path.is_relative_to(backup_dir):
        raise HTTPException(status_code=404, detail="Backup not found")

    headers = {}
    if filename.endswith(".enc"):
        headers["X-Encrypted"] = "true"

    return FileResponse(
        str(backup_path),
        media_type="application/octet-stream",
        filename=filename,
        headers=headers,
    )


def _prune_old_backups(backup_dir: Path, keep: int = _MAX_BACKUPS) -> None:
    """Delete oldest backup files when count exceeds *keep*."""
    backups = sorted(
        list(backup_dir.glob("*.db")) + list(backup_dir.glob("*.db.enc")),
        key=lambda p: p.stat().st_mtime,
    )
    excess = backups[: len(backups) - keep]
    for old in excess:
        # Find sidecar regardless of .db or .db.enc extension
        sidecar = old.with_suffix(old.suffix + ".sha256")
        try:
            old.unlink()
            if sidecar.exists():
                sidecar.unlink()
            logger.info("Pruned old backup: %s", old.name)
        except OSError:
            logger.warning("Failed to prune backup: %s", old.name)


# ---------------------------------------------------------------------------
# Backup integrity helpers
# ---------------------------------------------------------------------------


def _compute_sha256(path: Path, chunk_size: int = 1 << 16) -> str:
    """Return hex SHA-256 digest of a file, reading in chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@router.get("/backups/{filename}/verify")
async def verify_backup(
    filename: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Verify integrity of a backup file by recomputing its SHA-256.

    Reads the backup, recomputes the hash, and compares it to the
    stored ``.sha256`` sidecar.  Returns ``"valid": true`` on match.
    """
    if not _BACKUP_NAME_RE.fullmatch(filename):
        raise HTTPException(status_code=400, detail="Invalid filename")

    store = _get_detection_store(request)
    db_path = Path(store.db_path)
    backup_dir = db_path.parent / "backups"
    backup_path = backup_dir / filename

    if not backup_path.exists() or not backup_path.is_relative_to(backup_dir):
        raise HTTPException(status_code=404, detail="Backup not found")

    sidecar_path = backup_path.with_suffix(backup_path.suffix + ".sha256")
    if not sidecar_path.exists():
        raise HTTPException(
            status_code=404,
            detail="No checksum sidecar found for this backup",
        )

    # Read stored hash (format: "<hash>  <filename>\n")
    sidecar_content = sidecar_path.read_text().strip()
    stored_hash = sidecar_content.split()[0] if sidecar_content else ""

    # Recompute
    actual_hash = await asyncio.to_thread(_compute_sha256, backup_path)
    valid = actual_hash == stored_hash

    store.log_audit(
        action="admin_backup_verify",
        target_id="system",
        operator=_key_id,
        note=f"backup={filename} valid={valid}",
    )

    return {
        "backup_file": filename,
        "stored_sha256": stored_hash,
        "computed_sha256": actual_hash,
        "valid": valid,
        "size_bytes": backup_path.stat().st_size,
    }


# ---------------------------------------------------------------------------
# Job Activity
# ---------------------------------------------------------------------------


def _fetch_maintenance_history(store: Any, limit: int) -> list[dict[str, Any]]:
    """Blocking helper -- query audit_log for maintenance history."""
    history: list[dict[str, Any]] = []
    try:
        conn = store.get_connection()
        rows = conn.execute(
            "SELECT timestamp, action, operator, note FROM audit_log "
            "WHERE action LIKE 'maintenance_%' "
            "ORDER BY timestamp DESC LIMIT ?",
            [limit],
        ).fetchall()
        for row in rows:
            action = row["action"].replace("maintenance_", "", 1)
            history.append(
                {
                    "task": action,
                    "trigger": "scheduled" if row["operator"] == "system" else "manual",
                    "status": "completed",
                    "started_at": row["timestamp"],
                    "finished_at": row["timestamp"],
                    "duration_s": None,
                    "note": row["note"],
                    "operator": row["operator"],
                }
            )
    except Exception:
        pass
    return history


@router.get("/jobs")
async def get_jobs(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Recent maintenance job activity (in-memory running + audit log history)."""
    app_state: AppState = request.app.state.app_state
    store = _get_detection_store(request)

    # Compute next scheduled cleanup time
    next_cleanup = None
    cleanup_task = getattr(request.app.state, "_cleanup_task", None)
    if cleanup_task and not cleanup_task.done():
        from datetime import timedelta as _td

        started = app_state.started_at
        now = _utcnow()
        elapsed = (now - started).total_seconds()
        cycle = 3600
        next_in = cycle - (elapsed % cycle)
        next_cleanup = (now + _td(seconds=next_in)).isoformat()

    # In-memory running/recent jobs (current session only)
    live_jobs = list(app_state.job_log)
    live_jobs.reverse()

    # Historical jobs from audit log (persisted across restarts)
    history: list[dict[str, Any]] = await asyncio.to_thread(
        _fetch_maintenance_history,
        store,
        limit,
    )

    # Merge: live jobs first (have richer detail), then history
    # Deduplicate by checking if a live job's started_at overlaps with audit
    live_timestamps = {j.get("started_at") for j in live_jobs}
    merged = list(live_jobs)
    for h in history:
        if h["started_at"] not in live_timestamps:
            merged.append(h)

    return {
        "jobs": merged[:limit],
        "next_scheduled_cleanup": next_cleanup,
    }


# ---------------------------------------------------------------------------
# POST /baselines/reset — reset anomaly baselines
# ---------------------------------------------------------------------------


@router.post("/baselines/reset")
async def reset_baselines(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
    target: str = Query(
        "all", description="Which baselines to reset: rf, wifi, bt, or all"
    ),
) -> dict[str, Any]:
    """Reset anomaly baselines, forcing the scorer back into learning mode.

    This clears accumulated frequency/power/class statistics so the anomaly
    scoring pipeline rebuilds its understanding of the RF environment.
    Useful after relocating sensors or changing the deployment environment.
    """
    reset_count = {}

    if target in ("rf", "all"):
        mgr = getattr(request.app.state, "rf_baseline_mgr", None)
        if mgr is not None:
            # Under the manager lock: ingest scores against these dicts
            # from worker threads.
            with mgr.lock:
                old_count = len(mgr.baselines)
                mgr.baselines.clear()
            reset_count["rf"] = old_count
            logger.info("RF baselines reset (%d bins cleared) by admin", old_count)

    if target in ("wifi", "all"):
        mgr = getattr(request.app.state, "wifi_baseline_mgr", None)
        if mgr is not None:
            # Under the manager lock: ingest scores against these dicts
            # from worker threads.
            with mgr.lock:
                old_count = len(mgr.baselines)
                mgr.baselines.clear()
            reset_count["wifi"] = old_count
            logger.info("WiFi baselines reset (%d bins cleared) by admin", old_count)

    if target in ("bt", "all"):
        mgr = getattr(request.app.state, "bt_baseline_mgr", None)
        if mgr is not None:
            # Under the manager lock: ingest scores against these dicts
            # from worker threads.
            with mgr.lock:
                old_count = len(mgr.baselines)
                mgr.baselines.clear()
            reset_count["bt"] = old_count
            logger.info("BT baselines reset (%d bins cleared) by admin", old_count)

    if not reset_count:
        return {
            "status": "error",
            "detail": f"No baselines found for target '{target}'",
        }

    return {
        "status": "ok",
        "reset": reset_count,
        "message": "Baselines cleared — scoring will re-enter learning mode",
    }


# ---------------------------------------------------------------------------
# Learned-state bundles: export / import / presets
# ---------------------------------------------------------------------------

_BUNDLE_SUFFIX = ".sigrift.tar.gz"
_MAX_EXPORTS = 5
# Matched with ``fullmatch``: with ``match`` and a ``$`` anchor a trailing
# newline passed ("x.sigrift.tar.gz\n").
_BUNDLE_NAME_RE = re.compile(r"[a-zA-Z0-9_.-]+\.sigrift\.tar\.gz")

# selector -> (app.state path attr, canonical data-dir filename)
_MGR_PATHS = {
    "rf": ("rf_baselines_path", "baselines.json"),
    "wifi": ("wifi_baselines_path", "wifi_baselines.json"),
    "bt": ("bt_baselines_path", "bt_baselines.json"),
}


def _data_dir(request: Request) -> Path:
    rf_path = getattr(request.app.state, "rf_baselines_path", None)
    if rf_path:
        return Path(rf_path).parent
    return Path(__file__).resolve().parent.parent / "data"


def _serialize_component(request: Request, selector: str) -> bytes | None:
    """Serialize one live component to its bundle JSON bytes, or None if absent."""
    state = request.app.state
    if selector == "rf":
        mgr = getattr(state, "rf_baseline_mgr", None)
        return bundles.serialize_rf_manager(mgr) if mgr is not None else None
    if selector == "wifi":
        mgr = getattr(state, "wifi_baseline_mgr", None)
        # Pure serializer: must NOT call mgr.save(), which clears the dirty
        # counter and would silently disable the crash-safety autosave for the
        # live wifi_baselines.json.
        return bundles.serialize_wifi_manager(mgr) if mgr is not None else None
    if selector == "bt":
        mgr = getattr(state, "bt_baseline_mgr", None)
        return bundles.serialize_bt_manager(mgr) if mgr is not None else None
    if selector == "whitelist":
        wl = getattr(state, "signal_whitelist", None)
        if wl is None:
            return None
        return json.dumps(
            {
                "entries": [e.model_dump() for e in wl.entries],
                "saved_at": _utcnow().isoformat(),
            },
            indent=2,
        ).encode()
    if selector == "detection_config":
        persistence = getattr(state, "persistence", None)
        if persistence is None:
            return None
        return json.dumps(
            {"config": persistence.get_detection_config()}, indent=2
        ).encode()
    return None


class ExportRequest(BaseModel):
    model_config = {"extra": "forbid"}
    components: list[str] | None = None


@router.post("/baselines/export")
async def export_baselines(
    request: Request,
    body: ExportRequest | None = None,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Export current learned state as a downloadable bundle (kind=export)."""
    selectors = (body.components if body else None) or [
        "rf",
        "wifi",
        "bt",
        "whitelist",
        "detection_config",
    ]
    invalid = [s for s in selectors if s not in bundles.COMPONENT_SELECTORS]
    if invalid:
        raise HTTPException(400, detail=f"Unknown components: {invalid}")

    component_bytes: dict[str, bytes] = {}
    for sel in selectors:
        data = await asyncio.to_thread(_serialize_component, request, sel)
        if data is not None:
            component_bytes[bundles.COMPONENT_SELECTORS[sel]] = data
    if not component_bytes:
        raise HTTPException(400, detail="No components available to export")

    exports_dir = _data_dir(request) / "exports"
    ts = _utcnow().strftime("%Y%m%d_%H%M%S")
    out = exports_dir / f"sigrift_export_{ts}{_BUNDLE_SUFFIX}"
    await asyncio.to_thread(
        bundles.build_bundle, out, kind="export", component_bytes=component_bytes
    )
    sha = await asyncio.to_thread(_compute_sha256, out)
    (out.with_suffix(out.suffix + ".sha256")).write_text(f"{sha}  {out.name}\n")
    _prune_old_backups(
        exports_dir,
        keep=int(os.environ.get("BRIDGE_EXPORT_RETENTION", str(_MAX_EXPORTS))),
    )

    store = _get_detection_store(request)
    store.log_audit(
        action="admin_baseline_export",
        target_id="system",
        operator=_key_id,
        note=f"export={out.name} sha256={sha[:16]}… components={sorted(component_bytes)}",
    )
    return {
        "status": "ok",
        "file": out.name,
        "size_bytes": out.stat().st_size,
        "sha256": sha,
        "components": sorted(component_bytes),
    }


@router.get("/baselines/exports")
async def list_exports(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List available export bundles."""
    exports_dir = _data_dir(request) / "exports"
    items = []
    if exports_dir.exists():
        for f in sorted(
            exports_dir.glob(f"*{_BUNDLE_SUFFIX}"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            items.append(
                {
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "created_at": datetime.fromtimestamp(
                        f.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
    return {"count": len(items), "exports": items}


@router.get("/baselines/exports/{filename}")
async def download_export(
    filename: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> FileResponse:
    """Download an export bundle."""
    if not _BUNDLE_NAME_RE.fullmatch(filename):
        raise HTTPException(400, detail="Invalid filename")
    exports_dir = (_data_dir(request) / "exports").resolve()
    path = (exports_dir / filename).resolve()
    if not path.is_relative_to(exports_dir) or not path.is_file():
        raise HTTPException(404, detail="Export not found")
    return FileResponse(path, filename=filename, media_type="application/gzip")


def _guard_learned_state(request: Request, manifest, force: bool) -> None:
    """409 if applying a preset would replace substantial learned RF state.

    Enforced for ANY preset apply (import endpoint or presets/apply) so learned
    state is never silently destroyed regardless of the path taken.
    """
    if manifest.kind != "preset" or force:
        return
    rf_mgr = getattr(request.app.state, "rf_baseline_mgr", None)
    learned = 0
    if rf_mgr is not None:
        with rf_mgr.lock:  # ingest updates baselines from worker threads
            learned = sum(b.total_detections for b in rf_mgr.baselines.values())
    if learned > 1000:
        raise HTTPException(
            409,
            detail={
                "error": f"{learned} learned RF detections would be replaced",
                "fix": "export current state via POST /api/admin/baselines/export, "
                "then retry with ?force=true (or POST /api/admin/baselines/reset first)",
            },
        )


def _parse_component_selectors(components: str | None) -> list[str] | None:
    """Parse a ``?components=rf,wifi`` selector list; 400 on an unknown one.

    None / empty means every component.  Validated before anything is
    applied (an unknown selector used to raise KeyError → 500).
    """
    if not components:
        return None
    selectors = [s.strip() for s in components.split(",") if s.strip()]
    invalid = [s for s in selectors if s not in bundles.COMPONENT_SELECTORS]
    if invalid:
        raise HTTPException(
            400,
            detail=f"Unknown components: {invalid}. "
            f"Valid: {sorted(bundles.COMPONENT_SELECTORS)}",
        )
    return selectors or None


def _plan_detection_config(
    request: Request,
    report: "bundles.ValidationReport",
    members: dict[str, bytes],
    manifest: "bundles.BundleManifest",
    selectors: list[str] | None,
) -> dict[str, Any] | None:
    """The configuration a validated bundle's ``detection_config`` would store.

    Validation checks a bundle on its own; merged into the configuration in
    force, its weights or protocol toggles can still break their bounds
    (more than 64 entries, weights summing past 2.0).  That fails here, as
    a check of *report*, so a dry run reports it and an apply is refused
    before any component is applied.  ``None`` when the bundle applies no
    detection config, or that check failed.
    """
    persistence = getattr(request.app.state, "persistence", None)
    fname = bundles.COMPONENT_SELECTORS["detection_config"]
    wanted = {bundles.COMPONENT_SELECTORS[s] for s in selectors} if selectors else None
    if persistence is None or fname not in members:
        return None
    if wanted is not None and fname not in wanted:
        return None
    try:
        return bundles.plan_detection_config(
            persistence.get_detection_config(),
            json.loads(members[fname]),
            manifest.kind == "preset",
        )
    except bundles.BundleError as exc:
        report.add(
            f"{fname} detection_config merge",
            "fail",
            str(exc),
            "fix these values in the bundle, or in the configuration in force "
            "(PUT /api/admin/detection-config), then retry",
        )
        return None


def _load_component(fname: str, data: bytes) -> Any:
    """Decode one bundle component for :func:`_apply_members`.

    ``None`` for the detection config (planned by :func:`_plan_detection_config`).
    """
    ctype = bundles.COMPONENT_FILES.get(fname)
    if ctype == "rf_baselines":
        return bundles.load_rf_baselines_from_bytes(data)
    if ctype == "wifi_baselines":
        return bundles.load_wifi_baselines_from_bytes(data)
    if ctype == "bt_baselines":
        return bundles.load_bt_baselines_from_bytes(data)
    if ctype == "signal_whitelist":
        return bundles.load_whitelist_entries_from_bytes(data)
    return None


def _apply_members(
    request: Request,
    members: dict[str, bytes],
    manifest: "bundles.BundleManifest",
    selectors: list[str] | None,
    planned_config: dict[str, Any] | None,
) -> list[str]:
    """Swap validated bundle components into the live managers + persist.

    *planned_config* is the detection config to store, from
    :func:`_plan_detection_config` (``None``: none is applied).
    """
    state = request.app.state
    data_dir = _data_dir(request)
    wanted = {bundles.COMPONENT_SELECTORS[s] for s in selectors} if selectors else None
    selected = [f for f in members if wanted is None or f in wanted]
    # Every component is decoded before the first is swapped in: one that
    # cannot be loaded fails the apply with no live state changed.
    loaded = {fname: _load_component(fname, members[fname]) for fname in selected}
    applied: list[str] = []

    for fname in selected:
        ctype = bundles.COMPONENT_FILES.get(fname)
        if ctype == "rf_baselines":
            mgr = getattr(state, "rf_baseline_mgr", None)
            if mgr is None:
                continue
            baselines, alpha = loaded[fname]
            mgr.replace_state(baselines, alpha)
            mgr.save(
                getattr(state, "rf_baselines_path", str(data_dir / "baselines.json"))
            )
            applied.append("rf")
        elif ctype == "wifi_baselines":
            mgr = getattr(state, "wifi_baseline_mgr", None)
            if mgr is None:
                continue
            bl, ssid_map, alpha = loaded[fname]
            mgr.replace_state(bl, ssid_map, alpha)
            mgr.save(
                getattr(
                    state, "wifi_baselines_path", str(data_dir / "wifi_baselines.json")
                )
            )
            applied.append("wifi")
        elif ctype == "bt_baselines":
            mgr = getattr(state, "bt_baseline_mgr", None)
            if mgr is None:
                continue
            bl, counts, alpha = loaded[fname]
            mgr.replace_state(bl, counts, alpha)
            mgr.save(
                Path(
                    getattr(state, "bt_baselines_path", data_dir / "bt_baselines.json")
                )
            )
            applied.append("bt")
        elif ctype == "signal_whitelist":
            wl = getattr(state, "signal_whitelist", None)
            if wl is None:
                continue
            wl.entries = loaded[fname]
            wl_path = getattr(
                state, "signal_whitelist_path", str(data_dir / "signal_whitelist.json")
            )
            wl.save(wl_path)
            applied.append("whitelist")
        elif ctype == "detection_config":
            persistence = getattr(state, "persistence", None)
            if persistence is None or planned_config is None:
                continue
            merged = planned_config
            persistence.set_detection_config(merged)
            bundles.apply_detection_config_to_scorers(
                getattr(state, "rf_scorer", None),
                getattr(state, "wifi_scorer", None),
                merged,
            )
            state.detection_config = merged
            applied.append("detection_config")

    # Provenance marker (also gates SIGRIFT_PRESET startup seeding).
    provenance = {
        "bundle_name": manifest.name,
        "kind": manifest.kind,
        "profile": manifest.profile,
        "applied_at": _utcnow().isoformat(),
        "git_sha": manifest.generator.git_sha,
        "components": applied,
    }
    (data_dir / "bundle_provenance.json").write_text(json.dumps(provenance, indent=2))
    logger.info(
        "Applied %s bundle '%s' (%d components: %s)",
        manifest.kind,
        manifest.name or manifest.profile or "?",
        len(applied),
        ", ".join(applied),
    )
    return applied


async def _validate_upload(request: Request, file: UploadFile, expect_kind: str | None):
    """Stream an upload to a 0600 temp file and validate it."""
    tmp_dir = _data_dir(request) / "tmp_bundles"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    max_bytes = int(
        os.environ.get("BRIDGE_BUNDLE_MAX_BYTES", str(bundles.MAX_BUNDLE_BYTES))
    )
    tmp_path = (
        tmp_dir / f"upload_{_utcnow().strftime('%Y%m%d_%H%M%S_%f')}{_BUNDLE_SUFFIX}"
    )
    total = 0
    try:
        with open(
            os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as fout:
            while True:
                chunk = await file.read(1 << 20)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(413, detail=f"Bundle exceeds {max_bytes} bytes")
                fout.write(chunk)
        report, manifest, members = await asyncio.to_thread(
            bundles.validate_bundle, tmp_path, expect_kind=expect_kind
        )
        return report, manifest, members
    finally:
        tmp_path.unlink(missing_ok=True)


@router.post("/baselines/import")
async def import_bundle(
    request: Request,
    file: UploadFile = File(...),
    dry_run: bool = Query(True),
    force: bool = Query(False),
    components: str | None = Query(None),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Import a learned-state bundle. Defaults to dry-run (validate only)."""
    selectors = _parse_component_selectors(components)
    report, manifest, members = await _validate_upload(request, file, expect_kind=None)

    # A taxonomy_overlap rejection is overridable with force=true.
    if not report.valid and force:
        fails = [c for c in report.checks if c.result == "fail"]
        if all(c.check == "taxonomy_overlap" for c in fails):
            report.valid = True
    # Not overridable: merged into the configuration in force.
    planned_config = None
    if report.valid:
        planned_config = _plan_detection_config(
            request, report, members, manifest, selectors
        )

    if dry_run or not report.valid:
        payload = report.model_dump()
        if not report.valid:
            raise HTTPException(422, detail=payload)
        return payload

    # Preset applies must never silently destroy learned state, regardless of
    # whether they come through here or /presets/{profile}/apply.
    _guard_learned_state(request, manifest, force)

    applied = await asyncio.to_thread(
        _apply_members, request, members, manifest, selectors, planned_config
    )
    store = _get_detection_store(request)
    store.log_audit(
        action="admin_bundle_import",
        target_id="system",
        operator=_key_id,
        note=f"kind={manifest.kind} applied={applied}",
    )
    return {
        "status": "applied",
        "kind": manifest.kind,
        "applied": applied,
        "next_steps": [
            "POST /api/admin/rescore-rf-anomalies to re-score history under new weights"
        ],
    }


@router.get("/presets")
async def list_presets(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List preset bundles packaged with this build."""
    presets = await asyncio.to_thread(bundles.list_packaged_presets)
    return {"count": len(presets), "presets": presets}


@router.post("/presets/{profile}/apply")
async def apply_preset(
    profile: str,
    request: Request,
    components: str | None = Query(None),
    force: bool = Query(False),
    dry_run: bool = Query(False),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Apply a packaged preset to the live scorers (validated, guarded)."""
    selectors = _parse_component_selectors(components)
    path = await asyncio.to_thread(bundles.resolve_preset, profile)
    if path is None:
        raise HTTPException(404, detail=f"Unknown preset: {profile}")

    report, manifest, members = await asyncio.to_thread(
        bundles.validate_bundle, path, expect_kind="preset"
    )
    # Guard: never silently destroy substantial learned state (dry_run skips it).
    if not dry_run:
        _guard_learned_state(request, manifest, force)
    if not report.valid:
        raise HTTPException(
            500,
            detail={
                "error": "packaged preset failed validation",
                **report.model_dump(),
            },
        )
    # Merged into the configuration in force (the preset itself is valid).
    planned_config = _plan_detection_config(
        request, report, members, manifest, selectors
    )
    if not report.valid:
        raise HTTPException(422, detail=report.model_dump())
    if dry_run:
        return report.model_dump()

    applied = await asyncio.to_thread(
        _apply_members, request, members, manifest, selectors, planned_config
    )
    store = _get_detection_store(request)
    store.log_audit(
        action="admin_preset_apply",
        target_id=profile,
        operator=_key_id,
        note=f"preset={profile} applied={applied}",
    )
    return {"status": "applied", "profile": profile, "applied": applied}


@router.get("/baselines/status")
async def baselines_status(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Summarize learned-baseline state, autosave, and last applied bundle."""
    state = request.app.state

    def _mgr_summary(mgr) -> dict[str, Any]:
        if mgr is None:
            return {"present": False}
        bins = getattr(mgr, "baselines", {})
        total = sum(getattr(b, "total_detections", 0) for b in bins.values())
        learning = sum(
            1 for b in bins.values() if getattr(b, "is_learning", lambda: False)()
        )
        return {
            "present": True,
            "count": len(bins),
            "learning": learning,
            "total_detections": total,
            "updates_since_save": getattr(mgr, "updates_since_save", 0),
        }

    provenance = None
    prov_path = _data_dir(request) / "bundle_provenance.json"
    if prov_path.exists():
        try:
            provenance = json.loads(prov_path.read_text())
        except (json.JSONDecodeError, OSError):
            provenance = None

    return {
        "rf": _mgr_summary(getattr(state, "rf_baseline_mgr", None)),
        "wifi": _mgr_summary(getattr(state, "wifi_baseline_mgr", None)),
        "bt": _mgr_summary(getattr(state, "bt_baseline_mgr", None)),
        "provenance": provenance,
        "autosave": {
            "interval_s": int(os.environ.get("BRIDGE_BASELINE_SAVE_INTERVAL", "900")),
        },
    }
