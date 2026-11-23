"""JSON file persistence for the Shiny dashboard.

Provides atomic read/write of dashboard state (nodes, keys, alerts,
history, jobs, schedules) as JSON files under a configurable data
directory.  Writes use atomic rename (write to ``.tmp``, then
``os.replace``) to prevent corruption on crash.

File locking is handled via ``fcntl.flock`` on Linux to guard against
concurrent access from multiple processes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"

MAX_HISTORY_PER_NODE = 100
MAX_ALERTS = 200
MAX_JOBS = 500

# Sentinel for "leave this stored value as it is" (``None`` is a real value).
KEEP: Any = object()

# Files managed by PersistenceManager
_FILES = {
    "nodes": "nodes.json",
    "keys": "keys.json",
    "alerts": "alerts.json",
    "history": "history.json",
    "jobs": "jobs.json",
    "schedules": "schedules.json",
}


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Write *data* as JSON to *path* atomically.

    Writes to a temporary file in the same directory, then uses
    ``os.replace`` for an atomic rename.

    Parameters
    ----------
    path : Path
        Destination file path.
    data : dict
        JSON-serialisable data.

    Raises
    ------
    OSError
        On I/O failure.
    """
    tmp_path = path.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    os.replace(tmp_path, path)


def _safe_load(path: Path) -> dict[str, Any]:
    """Load JSON from *path*, returning ``{}`` on any error.

    Parameters
    ----------
    path : Path
        JSON file to read.

    Returns
    -------
    dict
        Parsed JSON, or empty dict on failure.
    """
    if not path.exists():
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        logger.warning("Persistence file %s is not a JSON object", path)
        return {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return {}


# ---------------------------------------------------------------------------
# PersistenceManager
# ---------------------------------------------------------------------------


class PersistenceManager:
    """Manages JSON persistence for all dashboard state.

    Parameters
    ----------
    data_dir : str or Path or None
        Directory for data files.  Created if it does not exist.
        Defaults to ``sigrift/lib/shiny/data/``.
    auto_save_interval : float
        Seconds between automatic background saves.  Set to ``0``
        to disable.
    """

    def __init__(
        self,
        data_dir: str | Path | None = None,
        auto_save_interval: float = 60.0,
    ) -> None:
        self._data_dir = Path(data_dir) if data_dir else _DEFAULT_DATA_DIR
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._auto_save_interval = auto_save_interval
        self._lock = threading.Lock()
        self._auto_save_task: asyncio.Task[None] | None = None
        self._dirty = False

        # In-memory state
        self._nodes: dict[str, dict[str, Any]] = {}
        self._keys: dict[str, tuple[str, bytes]] = {}
        # Per-key metadata stored next to the hash in keys.json: role,
        # purpose, expires_at, node_id, description, created_at, rotated_at,
        # updated_at.
        self._key_meta: dict[str, dict[str, Any]] = {}
        self._alerts: list[dict[str, Any]] = []
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._jobs: dict[str, dict[str, Any]] = {}
        self._schedules: dict[str, dict[str, Any]] = {}

    # -- Path helpers -------------------------------------------------------

    @property
    def data_dir(self) -> Path:
        """Directory holding the JSON state files."""
        return self._data_dir

    def _path(self, name: str) -> Path:
        """Return the full path for a managed file.

        Parameters
        ----------
        name : str
            Logical name (one of the keys in ``_FILES``).

        Returns
        -------
        Path
            Absolute path.
        """
        return self._data_dir / _FILES[name]

    # -- Load ---------------------------------------------------------------

    def load_all(self) -> None:
        """Load all persisted data from disk.

        Called once at application startup.  Any file that is missing
        or corrupt is silently skipped (state defaults to empty).
        """
        with self._lock:
            self._load_nodes()
            self._load_keys()
            self._load_alerts()
            self._load_history()
            self._load_jobs()
            self._load_schedules()
        logger.info(
            "Persistence loaded: %d nodes, %d keys, %d alerts, "
            "%d history nodes, %d jobs, %d schedules",
            len(self._nodes),
            len(self._keys),
            len(self._alerts),
            len(self._history),
            len(self._jobs),
            len(self._schedules),
        )

    def _load_nodes(self) -> None:
        data = _safe_load(self._path("nodes"))
        self._nodes = data.get("nodes", {})

    def _load_keys(self) -> None:
        data = _safe_load(self._path("keys"))
        raw_keys = data.get("keys", {})
        self._keys = {}
        self._key_meta = {}
        for key_id, info in raw_keys.items():
            if isinstance(info, dict):
                hash_hex = info.get("hash", "")
                salt_hex = info.get("salt", "")
                try:
                    salt_bytes = bytes.fromhex(salt_hex)
                except (ValueError, TypeError):
                    logger.warning("Invalid salt for key %s, skipping", key_id)
                    continue
                self._keys[key_id] = (hash_hex, salt_bytes)
                meta = {k: v for k, v in info.items() if k not in ("hash", "salt")}
                if meta:
                    self._key_meta[key_id] = meta

    def _load_alerts(self) -> None:
        data = _safe_load(self._path("alerts"))
        alerts = data.get("alerts", [])
        if isinstance(alerts, list):
            self._alerts = alerts[-MAX_ALERTS:]
        else:
            self._alerts = []

    def _load_history(self) -> None:
        data = _safe_load(self._path("history"))
        raw = data.get("history", {})
        self._history = {}
        for node_id, entries in raw.items():
            if isinstance(entries, list):
                self._history[node_id] = entries[-MAX_HISTORY_PER_NODE:]

    def _load_jobs(self) -> None:
        data = _safe_load(self._path("jobs"))
        self._jobs = data.get("jobs", {})

    def _load_schedules(self) -> None:
        data = _safe_load(self._path("schedules"))
        self._schedules = data.get("schedules", {})

    # -- Save ---------------------------------------------------------------

    def save_all(self) -> None:
        """Persist all in-memory state to disk atomically.

        Each file is written independently so a failure in one does
        not block the others.
        """
        with self._lock:
            self._save_nodes()
            self._save_keys()
            self._save_alerts()
            self._save_history()
            self._save_jobs()
            self._save_schedules()
            self._dirty = False
        logger.debug("Persistence saved successfully")

    def _save_nodes(self) -> None:
        try:
            _atomic_write(
                self._path("nodes"),
                {
                    "nodes": self._nodes,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except OSError as exc:
            logger.error("Failed to save nodes: %s", exc)

    def _save_keys(self) -> None:
        serialisable: dict[str, dict[str, str]] = {}
        for key_id, (hash_hex, salt_bytes) in self._keys.items():
            serialisable[key_id] = {
                "hash": hash_hex,
                "salt": salt_bytes.hex(),
                **self._key_meta.get(key_id, {}),
            }
        try:
            path = self._path("keys")
            _atomic_write(
                path,
                {
                    "keys": serialisable,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
            # Restrict permissions on key file
            try:
                path.chmod(0o600)
            except OSError:
                pass
        except OSError as exc:
            logger.error("Failed to save keys: %s", exc)

    def _save_alerts(self) -> None:
        try:
            _atomic_write(
                self._path("alerts"),
                {
                    "alerts": self._alerts[-MAX_ALERTS:],
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except OSError as exc:
            logger.error("Failed to save alerts: %s", exc)

    def _save_history(self) -> None:
        trimmed: dict[str, list[dict[str, Any]]] = {}
        for node_id, entries in self._history.items():
            trimmed[node_id] = entries[-MAX_HISTORY_PER_NODE:]
        try:
            _atomic_write(
                self._path("history"),
                {
                    "history": trimmed,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except OSError as exc:
            logger.error("Failed to save history: %s", exc)

    def _save_jobs(self) -> None:
        try:
            _atomic_write(
                self._path("jobs"),
                {
                    "jobs": self._jobs,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except OSError as exc:
            logger.error("Failed to save jobs: %s", exc)

    def _save_schedules(self) -> None:
        try:
            _atomic_write(
                self._path("schedules"),
                {
                    "schedules": self._schedules,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        except OSError as exc:
            logger.error("Failed to save schedules: %s", exc)

    # -- Background auto-save -----------------------------------------------

    async def start_auto_save(self) -> None:
        """Start the background auto-save loop.

        Should be called during application startup (e.g. in the
        FastAPI lifespan).
        """
        if self._auto_save_interval <= 0:
            return
        self._auto_save_task = asyncio.create_task(self._auto_save_loop())
        logger.info("Auto-save started (interval=%ss)", self._auto_save_interval)

    async def stop_auto_save(self) -> None:
        """Stop the background auto-save and perform a final save.

        Should be called during application shutdown.
        """
        if self._auto_save_task is not None:
            self._auto_save_task.cancel()
            try:
                await self._auto_save_task
            except asyncio.CancelledError:
                pass
            self._auto_save_task = None
        # Final save on shutdown
        await asyncio.to_thread(self.save_all)
        logger.info("Auto-save stopped; final save complete")

    async def _auto_save_loop(self) -> None:
        """Periodically save state if dirty."""
        while True:
            await asyncio.sleep(self._auto_save_interval)
            if self._dirty:
                try:
                    await asyncio.to_thread(self.save_all)
                except Exception:
                    logger.exception("Auto-save failed")

    def mark_dirty(self) -> None:
        """Mark state as changed, triggering save on the next auto-save cycle."""
        self._dirty = True

    # -- Key store access ---------------------------------------------------

    def get_key_store(self) -> dict[str, tuple[str, bytes]]:
        """Return a shallow copy of the in-memory key store.

        Returns
        -------
        dict
            Mapping ``{key_id: (hash_hex, salt_bytes)}``.
        """
        return dict(self._keys)

    def set_key(
        self,
        key_id: str,
        hash_hex: str,
        salt: bytes,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Store a new (or replacement) API key hash.

        Parameters
        ----------
        key_id : str
            Key identifier.
        hash_hex : str
            Hex-encoded SHA-256 hash.
        salt : bytes
            Salt used for hashing.
        meta : dict or None
            Metadata to store with the key (role, expires_at, node_id, ...),
            replacing any it had. ``None`` keeps the existing metadata
            (e.g. on rotation).
        """
        with self._lock:
            self._keys[key_id] = (hash_hex, salt)
            if meta is not None:
                self._key_meta[key_id] = {
                    k: v for k, v in meta.items() if k not in ("hash", "salt")
                }
            self._dirty = True
            # Immediately persist key changes (security-sensitive).
            # Must be under lock to prevent races with concurrent key ops.
            self._save_keys()

    def remove_key(self, key_id: str) -> bool:
        """Remove an API key.

        Parameters
        ----------
        key_id : str
            Key to remove.

        Returns
        -------
        bool
            True if the key existed and was removed.
        """
        with self._lock:
            if key_id in self._keys:
                del self._keys[key_id]
                self._key_meta.pop(key_id, None)
                self._dirty = True
                self._save_keys()
                return True
        return False

    def get_key_meta(self, key_id: str) -> dict[str, Any]:
        """Return a copy of *key_id*'s stored metadata (``{}`` if none)."""
        return dict(self._key_meta.get(key_id, {}))

    def get_all_key_meta(self) -> dict[str, dict[str, Any]]:
        """Return a copy of every key's metadata, keyed by key_id."""
        return {kid: dict(meta) for kid, meta in self._key_meta.items()}

    def update_key_meta(self, key_id: str, **fields: Any) -> bool:
        """Merge *fields* into an existing key's metadata and persist it."""
        with self._lock:
            if key_id not in self._keys:
                return False
            self._key_meta.setdefault(key_id, {}).update(fields)
            self._dirty = True
            self._save_keys()
            return True

    def bind_key_to_node(self, key_id: str, node_id: str) -> str:
        """Bind *key_id* to *node_id* on first use, atomically.

        Returns one of:

        ``"bound"``
            *key_id* is now (or already was) bound to *node_id*.
        ``"bound_elsewhere"``
            *key_id* is already bound to a different node.
        ``"node_claimed"``
            another key is already bound to *node_id*; nothing is changed,
            so a node that has claimed its key cannot be taken over by a
            second key.
        ``"unknown_key"``
            *key_id* is not in the key store.

        The check and the write happen under one lock, so two unbound keys
        racing for the same node cannot both win.
        """
        with self._lock:
            if key_id not in self._keys:
                return "unknown_key"
            current = self._key_meta.get(key_id, {}).get("node_id")
            if current:
                return "bound" if current == node_id else "bound_elsewhere"
            for other_id, meta in self._key_meta.items():
                if (
                    other_id != key_id
                    and other_id in self._keys
                    and meta.get("node_id") == node_id
                ):
                    return "node_claimed"
            self._key_meta.setdefault(key_id, {})["node_id"] = node_id
            self._dirty = True
            self._save_keys()
            return "bound"

    def update_key_binding(
        self,
        key_id: str,
        *,
        purpose: Any = KEEP,
        node_id: Any = KEEP,
        updated_at: str | None = None,
    ) -> tuple[str, dict[str, Any], dict[str, Any]]:
        """Set *key_id*'s ``purpose`` and/or ``node_id`` (``None`` unbinds).

        An argument left at :data:`KEEP` keeps the stored value.  Returns
        ``(outcome, meta, previous)``: the key's metadata after and before
        the call.  *outcome* is one of:

        ``"updated"``
            the change was written.
        ``"dashboard_bound"``
            the result would be a ``dashboard`` key bound to a node; nothing
            is changed.
        ``"unknown_key"``
            *key_id* is not in the key store.

        The new values are worked out from the stored ones under the same
        lock :meth:`bind_key_to_node` takes, so an admin's change cannot be
        mixed with a concurrent first-use binding into an inconsistent key.
        """
        with self._lock:
            if key_id not in self._keys:
                return "unknown_key", {}, {}
            previous = dict(self._key_meta.get(key_id, {}))
            new_purpose = previous.get("purpose") if purpose is KEEP else purpose
            new_node = previous.get("node_id") if node_id is KEEP else node_id
            if new_purpose == "dashboard" and new_node:
                return "dashboard_bound", dict(previous), previous
            meta = self._key_meta.setdefault(key_id, {})
            meta["purpose"] = new_purpose
            meta["node_id"] = new_node
            if updated_at is not None:
                meta["updated_at"] = updated_at
            self._dirty = True
            self._save_keys()
            return "updated", dict(meta), previous

    # -- Node access --------------------------------------------------------

    def get_nodes(self) -> dict[str, dict[str, Any]]:
        """Return a shallow copy of the in-memory nodes dict."""
        return dict(self._nodes)

    def set_node(self, node_id: str, data: dict[str, Any]) -> None:
        """Create or update a node entry.

        Parameters
        ----------
        node_id : str
            Node identifier.
        data : dict
            Node data.
        """
        with self._lock:
            self._nodes[node_id] = data
            self._dirty = True

    def remove_node(self, node_id: str) -> bool:
        """Remove a node.

        Parameters
        ----------
        node_id : str
            Node identifier.

        Returns
        -------
        bool
            True if the node existed.
        """
        with self._lock:
            if node_id in self._nodes:
                del self._nodes[node_id]
                self._dirty = True
                return True
        return False

    # -- Alert access -------------------------------------------------------

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return a shallow copy of the in-memory alerts list."""
        return list(self._alerts)

    def add_alert(self, alert: dict[str, Any]) -> None:
        """Append an alert, trimming to ``MAX_ALERTS``.

        Parameters
        ----------
        alert : dict
            Alert data.
        """
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > MAX_ALERTS:
                self._alerts = self._alerts[-MAX_ALERTS:]
            self._dirty = True

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged.

        Parameters
        ----------
        alert_id : str
            The alert identifier to acknowledge.

        Returns
        -------
        bool
            True if the alert was found and acknowledged.
        """
        with self._lock:
            for alert in self._alerts:
                if alert.get("alert_id") == alert_id:
                    alert["acknowledged"] = True
                    alert["acknowledged_at"] = datetime.now(timezone.utc).isoformat()
                    self._dirty = True
                    return True
        return False

    def remove_alert(self, alert_id: str) -> bool:
        """Remove an alert by its ID.

        Parameters
        ----------
        alert_id : str
            The alert identifier to remove.

        Returns
        -------
        bool
            True if the alert was found and removed.
        """
        with self._lock:
            for i, alert in enumerate(self._alerts):
                if alert.get("alert_id") == alert_id:
                    self._alerts.pop(i)
                    self._dirty = True
                    return True
        return False

    # -- History access -----------------------------------------------------

    def get_history(self) -> dict[str, list[dict[str, Any]]]:
        """Return a shallow copy of the in-memory history dict."""
        return dict(self._history)

    def add_history_entry(self, node_id: str, entry: dict[str, Any]) -> None:
        """Append a history entry for *node_id*, trimming to max.

        Parameters
        ----------
        node_id : str
            Node identifier.
        entry : dict
            History entry.
        """
        with self._lock:
            if node_id not in self._history:
                self._history[node_id] = []
            self._history[node_id].append(entry)
            if len(self._history[node_id]) > MAX_HISTORY_PER_NODE:
                self._history[node_id] = self._history[node_id][-MAX_HISTORY_PER_NODE:]
            self._dirty = True

    # -- Job access ---------------------------------------------------------

    def get_jobs(self) -> dict[str, dict[str, Any]]:
        """Return a shallow copy of the in-memory jobs dict."""
        return dict(self._jobs)

    def set_job(self, job_id: str, data: dict[str, Any]) -> None:
        """Create or update a job entry.

        Parameters
        ----------
        job_id : str
            Job identifier.
        data : dict
            Job data.
        """
        with self._lock:
            self._jobs[job_id] = data
            self._dirty = True

    def remove_job(self, job_id: str) -> bool:
        """Remove a job.

        Parameters
        ----------
        job_id : str
            Job identifier.

        Returns
        -------
        bool
            True if the job existed.
        """
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                self._dirty = True
                return True
        return False

    # -- Schedule access ----------------------------------------------------

    def get_schedules(self) -> dict[str, dict[str, Any]]:
        """Return a shallow copy of the in-memory schedules dict."""
        return dict(self._schedules)

    def set_schedule(self, schedule_id: str, data: dict[str, Any]) -> None:
        """Create or update a schedule.

        Parameters
        ----------
        schedule_id : str
            Schedule identifier.
        data : dict
            Schedule data.
        """
        with self._lock:
            self._schedules[schedule_id] = data
            self._dirty = True

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule.

        Parameters
        ----------
        schedule_id : str
            Schedule identifier.

        Returns
        -------
        bool
            True if the schedule existed.
        """
        with self._lock:
            if schedule_id in self._schedules:
                del self._schedules[schedule_id]
                self._dirty = True
                return True
        return False
