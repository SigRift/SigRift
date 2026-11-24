"""JSON file persistence for The Bridge.

Provides durable read/write of dashboard state (nodes, keys, alerts,
history, jobs, schedules) as JSON files under a configurable data
directory.

Durability and concurrency rules:

* Every write goes to a uniquely named temp file in the same directory,
  is ``fsync``-ed, atomically renamed over the target and the directory
  is ``fsync``-ed, so a crash or power loss leaves either the old or the
  new file — never a truncated one.
* Several processes (``BRIDGE_WORKERS`` > 1) share the directory.  Writers
  take an advisory ``fcntl`` lock on ``.persistence.lock`` and merge before
  writing: each file remembers the version it last read or wrote (its
  *base*); entries this process changed since then win, every other entry
  is taken from the file on disk.  So one worker's periodic save cannot
  resurrect a key another worker revoked, or drop a node it registered.
  For keys.json, a key changed both here and on disk is merged field by
  field (:func:`_merge_key_entries`): a key removed on either side stays
  removed, a credential rotated on disk stays rotated, and a field both
  sides changed keeps the stricter value (lower role, revoked, disabled).
* Key changes are written immediately (the gateway reloads ``keys.json``
  when it changes).  Readers of key state re-read ``keys.json`` when it
  changed on disk (checked at most once a second), so a revocation made by
  another worker takes effect here too.  A key change that could not be
  written raises :class:`KeyStoreWriteError` instead of returning: a
  revocation or downgrade stays in effect in this process (fail closed)
  and is retried by the next save, any other change is undone in memory.
  Repeating an unsaved revocation retries the write (it is not "not
  found"); :meth:`PersistenceManager.get_saved_key_meta` tells what the
  other workers and the gateway still see.
* ``keys.json`` is never treated as empty because it is unreadable or
  missing: a copy of the last good version is kept in ``keys.json.bak``; at
  startup an unreadable ``keys.json`` is restored from it (a copy of the
  bad file is kept as ``keys.json.corrupt-<time>``; ``keys.json`` itself is
  replaced atomically, so a crash during recovery leaves the bad file to
  be recovered again, never no file), a missing ``keys.json`` is restored
  from a backup that holds keys, and without a usable backup startup is
  refused (:class:`KeyStoreCorruptError`).  To start with no API keys on
  purpose, move both ``keys.json`` and ``keys.json.bak`` aside.
* :meth:`PersistenceManager.save_all` snapshots state under the in-memory
  lock and does the file I/O after releasing it, so request handlers that
  update state (``set_node``, ``add_alert``) never wait for disk writes.
  Key changes do not take that lock at all: they are serialised by a
  separate key lock (then the inter-process file lock), and key state is
  copy-on-write, so a key write's fsyncs — or its wait for another
  worker's file lock — never hold up ``set_node`` / ``add_alert``.

Adapted from sigrift.lib.shiny.persistence for the Bridge application.
Detection data is stored separately in DetectionStore (SQLite).
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import json
import logging
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from sigrift.bridge.anomaly.scorer import DEFAULT_RF_DIMENSION_WEIGHTS
from sigrift.bridge.detection_config import usable_detection_config
from sigrift.bridge.storage.base import sqlite_transaction

try:  # POSIX advisory locks; absent on Windows (single process there)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"

MAX_HISTORY_PER_NODE = 100
MAX_ALERTS = 200
MAX_JOBS = 500
MAX_ALERT_RULES = 200
MAX_WATCH_BANDS = 100

_FILES = {
    "nodes": "nodes.json",
    "keys": "keys.json",
    "alerts": "alerts.json",
    "history": "history.json",
    "jobs": "jobs.json",
    "schedules": "schedules.json",
    "webhooks": "webhooks.json",
    "wifi_whitelist": "wifi_whitelist.json",
    "bt_whitelist": "bt_whitelist.json",
    "alert_rules": "alert_rules.json",
    "watch_bands": "watch_bands.json",
    "syslog_targets": "syslog_targets.json",
}

# Non-key state files: name -> (JSON field, attribute, merge key).  A merge
# key of None means "dict of entries" (merged per entry); a string names
# the identity field of the items of a list (merged per item).
_STATE_FILES: dict[str, tuple[str, str, str | None]] = {
    "nodes": ("nodes", "_nodes", None),
    "alerts": ("alerts", "_alerts", "alert_id"),
    "history": ("history", "_history", None),
    "jobs": ("jobs", "_jobs", None),
    "schedules": ("schedules", "_schedules", None),
    "webhooks": ("webhooks", "_webhooks", "id"),
    "wifi_whitelist": ("whitelist", "_wifi_whitelist", "bssid"),
    "bt_whitelist": ("whitelist", "_bt_whitelist", "device_addr"),
    "alert_rules": ("rules", "_alert_rules", "rule_id"),
    "watch_bands": ("watch_bands", "_watch_bands", "watch_id"),
    "syslog_targets": ("syslog_targets", "_syslog_targets", "id"),
}

_LOCK_FILE = ".persistence.lock"
_KEYS_BACKUP_SUFFIX = ".bak"
# keys.json entry fields that are the credential, not metadata.
_KEY_CREDENTIAL_FIELDS = frozenset({"hash", "salt", "lookup_hash"})
_KEY_STANDARD_META = ("role", "description", "created_at", "expires_at")
# Edge/sensor node keys must never have analyst-or-higher privileges: a key
# whose id starts with one of these is a node key (see edge_key_role).
_EDGE_PREFIXES = ("node_", "rtlsdr_", "hackrf_", "sensor_", "edge_", "sdr_")
# Role names in ascending privilege, as ``dependencies.Role`` (which auth
# looks up case-insensitively: ``Role[str(role).upper()]``).
_ROLE_ORDER = ("SENSOR", "NODE", "VIEWER", "ANALYST", "ADMIN", "KEYMASTER")
_ANALYST_RANK = _ROLE_ORDER.index("ANALYST")
_VIEWER_RANK = _ROLE_ORDER.index("VIEWER")
# How often key readers re-check keys.json for changes by other processes.
_KEYS_REFRESH_INTERVAL = 1.0

_MISSING = object()


class KeyStoreCorruptError(RuntimeError):
    """keys.json is unreadable and no usable keys.json.bak exists."""


class KeyStoreWriteError(OSError):
    """keys.json could not be written: the key change just made is not durable.

    Raised by the key mutators instead of reporting success — also when
    the inter-process lock (``.persistence.lock``) cannot be taken, before
    anything is changed.  Other workers, the gateway and a restart still
    see the previous key set.  A revocation or a downgrade stays in effect
    in this process (fail closed, :attr:`applied_here` is True) and is
    retried by the next save; any other change is undone in memory.
    """

    def __init__(self, message: str, *, applied_here: bool = False) -> None:
        super().__init__(message)
        #: True when the change stays in effect in this process (a
        #: revocation or downgrade) until a save writes it; False when it
        #: was undone (or never made): nothing changed anywhere.
        self.applied_here = applied_here


class NodeAlreadyBound(Exception):
    """Another API key is already bound to the node (contract K7b)."""

    def __init__(self, node_id: str, owner_key_id: str) -> None:
        super().__init__(f"node {node_id!r} already has a bound key")
        self.node_id = node_id
        self.owner_key_id = owner_key_id


class _UnreadableFile(Exception):
    """A state file exists but is not a readable JSON object."""


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------


def _fsync_dir(directory: Path) -> None:
    """fsync *directory* so a completed rename survives power loss."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _atomic_write(path: Path, data: Any, *, mode: int | None = None) -> None:
    """Write *data* as JSON to *path* durably and atomically.

    The JSON goes to a uniquely named temp file in the same directory
    (created with *mode*, default ``0o666`` minus the umask), which is
    flushed and fsync-ed, renamed over *path*, and the directory fsync-ed.
    Concurrent writers never share a temp file, and a crash leaves either
    the old or the new content.
    """
    payload = json.dumps(data, indent=2, default=str)
    tmp_path = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o666 if mode is None else mode,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _copy_file_durably(src: Path, dest: Path) -> None:
    """Copy *src* to *dest* (owner-only) and fsync the copy and the directory.

    Goes through a uniquely named temp file, so *dest* is either absent
    or complete.
    """
    data = src.read_bytes()
    tmp_path = dest.with_name(f".{dest.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, dest)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    _fsync_dir(dest.parent)


def _file_signature(path: Path) -> tuple[int, int, int, int] | None:
    """Identity of the file's current version (None if it does not exist)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _read_json_object(path: Path) -> dict[str, Any]:
    """Read a JSON object from *path*.

    Raises ``FileNotFoundError`` when it does not exist and
    :class:`_UnreadableFile` when it cannot be read or is not an object.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise
    except (OSError, ValueError) as exc:  # JSONDecodeError, UnicodeDecodeError
        raise _UnreadableFile(f"{path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise _UnreadableFile(f"{path.name}: not a JSON object")
    return data


def _build_fast_index(key_lookup: dict[str, str]) -> dict[str, str]:
    """Invert ``key_id → lookup_hash`` into ``lookup_hash → key_id``.

    Two key_ids can only share a lookup hash if keys.json was edited by
    hand (:meth:`PersistenceManager.set_key` refuses it); the first one in
    file order keeps the index entry.
    """
    index: dict[str, str] = {}
    for key_id, lookup_hash in key_lookup.items():
        index.setdefault(lookup_hash, key_id)
    return index


def _safe_load(path: Path) -> dict[str, Any]:
    """Load JSON from *path*, returning ``{}`` on any error.

    Not used for ``keys.json``, whose loss must never go unnoticed.
    """
    if not path.exists():
        return {}
    try:
        return _read_json_object(path)
    except FileNotFoundError:
        return {}
    except _UnreadableFile as exc:
        logger.warning("Failed to load %s: %s", path, exc)
        return {}


def _normalize(value: Any) -> Any:
    """JSON round-trip: the form the value has once written and read back."""
    return json.loads(json.dumps(value, default=str))


def _merge_dict(base: dict, ours: dict, theirs: dict) -> dict:
    """Three-way merge of dicts of entries.

    An entry this side changed (added, modified or removed) since *base*
    takes our value; every other entry is taken from *theirs*.
    """
    merged = dict(theirs)
    for key in set(base) | set(ours):
        mine = ours.get(key, _MISSING)
        if mine == base.get(key, _MISSING):
            continue
        if mine is _MISSING:
            merged.pop(key, None)
        else:
            merged[key] = mine
    return merged


def _keyed(items: Any, field: str) -> dict[Any, Any] | None:
    """Index list *items* by *field*, or None if that is not possible."""
    if not isinstance(items, list):
        return None
    index: dict[Any, Any] = {}
    for item in items:
        if not isinstance(item, dict):
            return None
        ident = item.get(field)
        if not isinstance(ident, (str, int)) or ident in index:
            return None
        index[ident] = item
    return index


def _merge_list(base: Any, ours: Any, theirs: Any, field: str) -> Any:
    """Three-way merge of lists of dicts identified by *field*.

    Keeps *theirs* order, applies our additions (appended), removals and
    modifications since *base*.  Falls back to whole-list resolution (ours
    if we changed the list, else theirs) when items lack unique ids.
    """
    b, o, t = _keyed(base, field), _keyed(ours, field), _keyed(theirs, field)
    if b is None or o is None or t is None:
        return ours if ours != base else theirs
    merged: list[Any] = []
    for ident, item in t.items():
        if o.get(ident, _MISSING) != b.get(ident, _MISSING):
            if ident in o:
                merged.append(o[ident])  # we modified it
            # else: we removed it
        else:
            merged.append(item)
    for ident, item in o.items():
        if ident not in t and item != b.get(ident, _MISSING):
            merged.append(item)  # we added it (or modified one they removed)
    return merged


class _InterProcessLock:
    """Re-entrant (per process) advisory lock on a lock file.

    Serialises read-merge-write cycles between bridge worker processes that
    share the data directory.  Without ``fcntl`` it only serialises threads.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._mutex = threading.RLock()
        self._depth = 0
        self._fd: int | None = None

    def __enter__(self) -> _InterProcessLock:
        self._mutex.acquire()
        try:
            if self._depth == 0 and _fcntl is not None:
                fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX)
                except BaseException:
                    os.close(fd)
                    raise
                self._fd = fd
            self._depth += 1
        except BaseException:
            self._mutex.release()
            raise
        return self

    def __exit__(self, *exc_info: Any) -> None:
        try:
            self._depth -= 1
            if self._depth == 0 and self._fd is not None:
                fd, self._fd = self._fd, None
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
                finally:
                    os.close(fd)
        finally:
            self._mutex.release()


def _role_rank(role: Any) -> int:
    """Privilege rank of a stored role, read as auth reads it.

    Case-insensitive, like ``dependencies.Role[str(role).upper()]``; an
    unknown role reads as VIEWER (the bridge's least-privilege default).
    """
    name = str(role).upper()
    return _ROLE_ORDER.index(name) if name in _ROLE_ORDER else _VIEWER_RANK


def is_edge_key_id(key_id: Any) -> bool:
    """Whether *key_id* names an edge/sensor node key (by its id prefix)."""
    return isinstance(key_id, str) and key_id.startswith(_EDGE_PREFIXES)


def edge_key_role(key_id: Any, role: Any) -> Any:
    """The role *key_id* may be stored with: *role*, or ``"node"`` for an edge key.

    One rule wherever a key's role is set (keys.json load, key creation,
    role and metadata changes): a key whose id starts with an edge prefix
    (case-sensitive) and whose role reads as ANALYST or higher — compared
    case-insensitively, as auth reads it, so ``ADMIN`` and ``KeyMaster``
    count — is a NODE key, whatever was stored or asked for.  Any other
    role is returned unchanged: VIEWER, NODE, SENSOR and unknown roles all
    authenticate at VIEWER or below.  The gateway applies the same rule
    (``effective_role`` in ``auth/api_key.rs``).
    """
    if is_edge_key_id(key_id) and _role_rank(role) >= _ANALYST_RANK:
        return "node"
    return role


def _edge_safe_meta(key_id: str, meta: dict[str, Any]) -> dict[str, Any]:
    """*meta* with its role passed through :func:`edge_key_role`.

    Returns *meta* itself when the role is allowed, else a new dict (meta
    dicts are copy-on-write) with role ``node``, and logs the downgrade.
    """
    if "role" not in meta:
        return meta
    role = meta["role"]
    safe = edge_key_role(key_id, role)
    if safe is role:
        return meta
    logger.warning("Downgrading edge key %s from %s to node role", key_id, role)
    return {**meta, "role": safe}


def _only_restricts(old: dict[str, Any] | None, new: dict[str, Any]) -> bool:
    """Whether changing a key's metadata from *old* to *new* only takes access away.

    True when every field that changed is a lower role, ``revoked`` set to
    True or ``enabled`` set to False.  Such a change stays in effect when
    keys.json cannot be written (fail closed); any other is undone.
    """
    old = old or {}
    for field in set(old) | set(new):
        before, after = old.get(field, _MISSING), new.get(field, _MISSING)
        if before == after:
            continue
        if field == "role":
            if _role_rank(new.get("role", "viewer")) >= _role_rank(
                old.get("role", "viewer")
            ):
                return False
        elif field == "revoked":
            if after is not True:
                return False
        elif field == "enabled":
            if after is not False:
                return False
        else:
            return False
    return True


def _stricter_key_field(field: str, ours: Any, theirs: Any) -> Any:
    """The value of key field *field* when both sides changed it differently.

    The one that grants less: the lower role, ``revoked`` True, ``enabled``
    False.  For any other field, *theirs* — the saved, newer value.
    """
    if field == "role":
        rank = {
            side: _role_rank("viewer" if value is _MISSING else value)
            for side, value in (("ours", ours), ("theirs", theirs))
        }
        return ours if rank["ours"] < rank["theirs"] else theirs
    if field == "revoked" and ours is True:
        return ours
    if field == "enabled" and ours is False:
        return ours
    return theirs


def _merge_key_entries(
    base: dict[str, dict[str, Any]],
    ours: dict[str, dict[str, Any]],
    theirs: dict[str, dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Three-way merge of ``keys.json`` entries; never undoes another worker's change.

    Like :func:`_merge_dict`, except for a key that both this process and
    the file changed since *base*.  This process's change to an existing
    key is then an unsaved revocation or restriction (any other unsaved
    change is undone, see :meth:`PersistenceManager._commit_key_change`):

    * removed on either side: removed.  A pending downgrade never brings
      back a key another worker revoked.
    * otherwise merged field by field: a field only we changed takes our
      value, a field both changed takes the stricter value
      (:func:`_stricter_key_field`), every other field — the credential
      included — is theirs.  A pending downgrade never brings back the old
      credential of a key another worker rotated; it applies to the new one.
    """
    merged = dict(theirs)
    for key_id in set(base) | set(ours):
        mine = ours.get(key_id, _MISSING)
        was = base.get(key_id, _MISSING)
        if mine == was:
            continue
        if mine is _MISSING:
            merged.pop(key_id, None)
            continue
        their = theirs.get(key_id, _MISSING)
        if was is _MISSING or their == was:
            merged[key_id] = mine
            continue
        if their is _MISSING:
            continue  # revoked by another worker: stays revoked
        entry = dict(their)
        for field in set(was) | set(mine):
            value = mine.get(field, _MISSING)
            if value == was.get(field, _MISSING):
                continue
            other = their.get(field, _MISSING)
            if other != was.get(field, _MISSING) and other != value:
                value = _stricter_key_field(field, value, other)
            if value is _MISSING:
                entry.pop(field, None)
            else:
                entry[field] = value
        merged[key_id] = entry
    return merged


def _parse_key_entries(
    raw_keys: Any,
) -> tuple[dict[str, tuple[str, bytes]], dict[str, dict[str, Any]], dict[str, str]]:
    """Parse ``keys.json``'s ``keys`` object into (keys, key_meta, key_lookup).

    Metadata fields beyond the standard ones (e.g. ``node_id``, ``revoked``,
    ``enabled``) are kept, so they survive a save/load round trip.
    """
    keys: dict[str, tuple[str, bytes]] = {}
    key_meta: dict[str, dict[str, Any]] = {}
    key_lookup: dict[str, str] = {}
    if not isinstance(raw_keys, dict):
        return keys, key_meta, key_lookup
    for key_id, info in raw_keys.items():
        if not isinstance(info, dict):
            continue
        hash_hex = info.get("hash", "")
        salt_hex = info.get("salt", "")
        try:
            salt_bytes = bytes.fromhex(salt_hex)
        except (ValueError, TypeError):
            logger.warning("Invalid salt for key %s, skipping", key_id)
            continue
        keys[key_id] = (hash_hex, salt_bytes)
        # SHA-256 of the raw key, kept per key_id so that saving
        # never drops it (the fast index is derived from this).
        lookup_hash = info.get("lookup_hash", "")
        if isinstance(lookup_hash, str) and lookup_hash:
            key_lookup[key_id] = lookup_hash
        meta: dict[str, Any] = {
            k: v
            for k, v in info.items()
            if k not in _KEY_CREDENTIAL_FIELDS and k not in _KEY_STANDARD_META
        }
        meta.update(
            {
                "role": info.get("role", "viewer"),
                "description": info.get("description", ""),
                "created_at": info.get("created_at", ""),
                "expires_at": info.get("expires_at"),
            }
        )
        # Edge/sensor node keys never hold analyst-or-higher privileges,
        # regardless of what was stored on disk (edge_key_role).
        key_meta[key_id] = _edge_safe_meta(key_id, meta)
    return keys, key_meta, key_lookup


def _read_key_store(path: Path) -> dict[str, Any]:
    """Read keys.json (or its backup) and check its ``keys`` section.

    Like :func:`_read_json_object`, plus :class:`_UnreadableFile` when the
    ``keys`` section is not an object, or holds entries of which none
    parses.  Read as an empty key store, such a file would drop every API
    key, and on startup it would also replace keys.json.bak, the copy
    that could restore them.  A missing ``keys`` section or an empty one
    is an empty key store.
    """
    data = _read_json_object(path)
    raw_keys = data.get("keys", {})
    if raw_keys is None:
        raw_keys = {}
    if not isinstance(raw_keys, dict):
        raise _UnreadableFile(
            f"{path.name}: 'keys' is a {type(raw_keys).__name__}, not an object"
        )
    if raw_keys and not _parse_key_entries(raw_keys)[0]:
        raise _UnreadableFile(
            f"{path.name}: none of its {len(raw_keys)} key entries is valid"
        )
    return data


def _serialize_key_state(
    keys: dict[str, tuple[str, bytes]],
    key_meta: dict[str, dict[str, Any]],
    key_lookup: dict[str, str],
) -> dict[str, dict[str, Any]]:
    """Build ``keys.json``'s ``keys`` object (inverse of :func:`_parse_key_entries`)."""
    serialisable: dict[str, dict[str, Any]] = {}
    for key_id, (hash_hex, salt_bytes) in keys.items():
        entry: dict[str, Any] = {
            "hash": hash_hex,
            "salt": salt_bytes.hex(),
        }
        lh = key_lookup.get(key_id)
        if lh:
            entry["lookup_hash"] = lh
        meta = key_meta.get(key_id, {})
        if meta:
            entry["role"] = meta.get("role", "viewer")
            entry["description"] = meta.get("description", "")
            entry["created_at"] = meta.get("created_at", "")
            entry["expires_at"] = meta.get("expires_at")
            for k, v in meta.items():
                if k not in _KEY_CREDENTIAL_FIELDS and k not in entry:
                    entry[k] = v
        serialisable[key_id] = entry
    return _normalize(serialisable)


# ---------------------------------------------------------------------------
# PersistenceManager
# ---------------------------------------------------------------------------


class ConfigSnapshotRestoreError(OSError):
    """Some snapshot files could not be restored; completed writes remain."""

    def __init__(self, restored_files: list[str], failed_files: list[str]) -> None:
        super().__init__("Configuration snapshot restore incomplete")
        self.restored_files = restored_files
        self.failed_files = failed_files


class ConfigSnapshotRejected(ValueError):
    """A snapshot names files that are not configuration snapshot files.

    Nothing was restored: every name is checked before anything is written.
    """

    def __init__(self, rejected_files: list[str]) -> None:
        super().__init__(
            "Configuration snapshot holds files that are not snapshot files: "
            + ", ".join(repr(name) for name in rejected_files)
        )
        self.rejected_files = rejected_files


class PersistenceManager:
    """Manages JSON persistence for all Bridge state (except detections).

    Detection data is stored in ``DetectionStore`` (SQLite).
    This class handles nodes, API keys, alerts, history, jobs, and
    schedules — same pattern as sigrift.lib.shiny.persistence.

    Parameters
    ----------
    data_dir : str or Path or None
        Directory for data files.  Created if it does not exist.
        Defaults to ``sigrift/bridge/data/``.
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
        # In-memory lock for the non-key state (nodes, alerts, history,
        # ...).  Held only for short in-memory steps, never across disk
        # I/O or the inter-process lock: request handlers on the event
        # loop take it.
        self._lock = threading.RLock()
        # Serialises key changes (and key refreshes from disk) in this
        # process.  Key writes fsync keys.json and its backup under it.
        # Re-entrant: key readers may refresh key state from disk while a
        # key mutation on the same thread holds it.
        self._key_lock = threading.RLock()
        # Serialises save_all() runs within this process (their snapshots
        # must reach disk in order).
        self._save_lock = threading.Lock()
        # Serialises read-merge-write between processes.  Lock order:
        # self._key_lock before self._file_lock, never the reverse; the
        # file lock is never awaited while self._lock is held.
        self._file_lock = _InterProcessLock(self._data_dir / _LOCK_FILE)
        self._auto_save_task: asyncio.Task[None] | None = None
        self._dirty = False
        # What get_detection_config last left out of detection_config.json
        # (logged when it changes).
        self._detection_config_left_out: list[str] = []

        # Per file: the content last read from / written to disk (JSON
        # normalised) and that file version's signature (see module doc).
        self._base: dict[str, Any] = {}
        self._sig: dict[str, tuple[int, int, int, int] | None] = {}
        self._keys_base: dict[str, dict[str, Any]] = {}
        self._keys_sig: tuple[int, int, int, int] | None = None
        self._keys_checked_at = 0.0
        self._keys_unreadable_logged = False
        # A key change is in memory but could not be written (I/O error).
        self._keys_write_pending = False

        # In-memory state
        self._nodes: dict[str, dict[str, Any]] = {}
        # Key state is copy-on-write: writers (under ``self._key_lock``) build
        # new dicts and swap them in, and never change a published dict
        # (or a meta dict inside ``_key_meta``) in place.  The getters can
        # therefore copy them from any thread without the lock — API-key
        # auth reads them from worker threads while the event loop creates
        # and revokes keys.
        self._keys: dict[str, tuple[str, bytes]] = {}
        self._key_meta: dict[str, dict[str, Any]] = {}
        # key_id → SHA-256(raw_key).  Source of truth for each key's lookup
        # hash; written to keys.json as the entry's ``lookup_hash``.
        self._key_lookup: dict[str, str] = {}
        # SHA-256(raw_key) → key_id, derived from ``_key_lookup``.
        self._key_fast_index: dict[str, str] = {}
        self._alerts: list[dict[str, Any]] = []
        self._history: dict[str, list[dict[str, Any]]] = {}
        self._jobs: dict[str, dict[str, Any]] = {}
        self._schedules: dict[str, dict[str, Any]] = {}
        self._webhooks: list[dict[str, Any]] = []
        self._wifi_whitelist: list[dict[str, Any]] = []
        self._bt_whitelist: list[dict[str, Any]] = []
        self._alert_rules: list[dict[str, Any]] = []
        self._watch_bands: list[dict[str, Any]] = []
        self._syslog_targets: list[dict[str, Any]] = []

    # -- Path helpers -------------------------------------------------------

    @property
    def data_dir(self) -> Path:
        """Directory holding all persisted state files."""
        return self._data_dir

    def _path(self, name: str) -> Path:
        return self._data_dir / _FILES[name]

    # -- Load ---------------------------------------------------------------

    def load_all(self) -> None:
        """Load all persisted data from disk (called at startup).

        Raises :class:`KeyStoreCorruptError` when ``keys.json`` is
        unreadable and cannot be restored from ``keys.json.bak``.
        """
        # Keys first, under the key lock (it waits for the inter-process
        # lock, which must not happen while self._lock is held).
        self._load_keys()
        with self._lock:
            loaders = {
                "nodes": self._load_nodes,
                "alerts": self._load_alerts,
                "history": self._load_history,
                "jobs": self._load_jobs,
                "schedules": self._load_schedules,
                "webhooks": self._load_webhooks,
                "wifi_whitelist": self._load_wifi_whitelist,
                "bt_whitelist": self._load_bt_whitelist,
                "alert_rules": self._load_alert_rules,
                "watch_bands": self._load_watch_bands,
                "syslog_targets": self._load_syslog_targets,
            }
            for name, loader in loaders.items():
                sig = _file_signature(self._path(name))
                loader()
                self._record_synced(name, sig)
        logger.info(
            "Persistence loaded: %d nodes, %d keys, %d alerts, "
            "%d history nodes, %d jobs, %d schedules, %d webhooks, "
            "%d whitelisted APs, %d alert rules, %d watch bands",
            len(self._nodes),
            len(self._keys),
            len(self._alerts),
            len(self._history),
            len(self._jobs),
            len(self._schedules),
            len(self._webhooks),
            len(self._wifi_whitelist),
            len(self._alert_rules),
            len(self._watch_bands),
        )

    def _record_synced(self, name: str, sig: Any) -> None:
        """Remember the just-loaded value of *name* as its base version."""
        _field, attr, _merge_key = _STATE_FILES[name]
        self._base[name] = _normalize(self._payload_value(name, getattr(self, attr)))
        self._sig[name] = sig

    def _load_nodes(self) -> None:
        data = _safe_load(self._path("nodes"))
        self._nodes = data.get("nodes", {})

    # -- Keys: load / refresh / save -----------------------------------------

    def _keys_backup_path(self) -> Path:
        path = self._path("keys")
        return path.with_name(path.name + _KEYS_BACKUP_SUFFIX)

    def _load_keys(self) -> None:
        """Load keys.json strictly (takes the key lock and the file lock).

        Neither an unreadable nor a missing keys.json is treated as an
        empty key store while ``keys.json.bak`` holds keys: it is restored
        from the backup (or, unreadable without a usable backup, startup
        is refused).  Only with neither file — a fresh install, or both
        moved aside on purpose — is the key store empty.
        """
        path = self._path("keys")
        with self._key_lock, self._file_lock:
            sig = _file_signature(path)
            try:
                data = _read_key_store(path)
            except FileNotFoundError:
                data, sig = self._restore_missing_keys(path)
            except _UnreadableFile as exc:
                data, sig = self._recover_keys_from_backup(path, exc)
            else:
                self._ensure_keys_backup(data)
            entries = data.get("keys", {})
            keys, key_meta, key_lookup = _parse_key_entries(entries)
            self._install_key_state(keys, key_meta, key_lookup)
            self._keys_base = _serialize_key_state(keys, key_meta, key_lookup)
            self._keys_sig = sig
            self._keys_checked_at = time.monotonic()
            self._keys_write_pending = False

    def _ensure_keys_backup(self, data: dict[str, Any]) -> None:
        """Make keys.json.bak a copy of the keys.json just read (if it is not)."""
        backup = self._keys_backup_path()
        try:
            if _read_json_object(backup) == data:
                return
        except (FileNotFoundError, _UnreadableFile):
            pass
        try:
            _atomic_write(backup, data, mode=0o600)
        except OSError as exc:
            logger.warning("Failed to write %s: %s", backup, exc)

    def _recover_keys_from_backup(
        self, path: Path, error: Exception
    ) -> tuple[dict[str, Any], Any]:
        """Restore an unreadable keys.json from keys.json.bak (or refuse).

        Crash-safe: the unreadable bytes are *copied* to
        ``keys.json.corrupt-<time>`` and keys.json is then replaced
        atomically with the backup, so at every instant keys.json is the
        unreadable file (recovered again on the next start) or the
        restored one — never missing, which would read as "no keys".
        """
        backup = self._keys_backup_path()
        try:
            data = _read_key_store(backup)
        except (FileNotFoundError, _UnreadableFile) as bak_exc:
            logger.critical(
                "API key store %s is unreadable (%s) and has no usable backup "
                "(%s: %s). Refusing to continue with an empty key store, "
                "which would drop every API key. Restore keys.json from a "
                "backup, or move it and %s aside to start with no API keys.",
                path,
                error,
                backup.name,
                bak_exc,
                backup.name,
            )
            raise KeyStoreCorruptError(
                f"{path} is unreadable ({error}) and {backup.name} is not "
                f"usable; restore keys.json, or move it and {backup.name} aside"
            ) from error
        aside: Path | None = path.with_name(
            f"{path.name}.corrupt-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
        )
        try:
            _copy_file_durably(path, aside)
        except OSError as exc:
            logger.error(
                "Could not keep a copy of the unreadable %s as %s (%s); "
                "restoring it from %s anyway",
                path.name,
                aside.name,
                exc,
                backup.name,
            )
            aside = None
        _atomic_write(path, data, mode=0o600)
        logger.critical(
            "API key store %s was unreadable (%s); restored %d key(s) from "
            "%s (the unreadable file was kept as %s)",
            path,
            error,
            len(data.get("keys", {}) or {}),
            backup.name,
            aside.name if aside is not None else "nothing: the copy failed",
        )
        return data, _file_signature(path)

    def _restore_missing_keys(self, path: Path) -> tuple[dict[str, Any], Any]:
        """keys.json does not exist: restore it from a backup that holds keys.

        A missing keys.json next to a backup with keys is not a fresh
        install — e.g. a release before recovery was crash-safe died
        between moving a corrupt keys.json aside and writing the restored
        one.  Starting empty would let the next key write (the master key
        at startup) overwrite the backup with a one-key store.  An
        unreadable backup refuses startup.  Without a backup, or with an
        empty one, the key store is empty (a fresh install).
        """
        backup = self._keys_backup_path()
        try:
            data = _read_key_store(backup)
        except FileNotFoundError:
            return {}, None
        except _UnreadableFile as exc:
            logger.critical(
                "API key store %s is missing and its backup %s is unreadable "
                "(%s). Refusing to start with an empty key store. Restore "
                "keys.json from a backup, or move %s aside to start with no "
                "API keys.",
                path,
                backup.name,
                exc,
                backup.name,
            )
            raise KeyStoreCorruptError(
                f"{path} is missing and {backup.name} is unreadable ({exc}); "
                f"restore keys.json, or move {backup.name} aside"
            ) from exc
        if not data.get("keys"):
            return {}, None
        _atomic_write(path, data, mode=0o600)
        logger.critical(
            "API key store %s was missing; restored %d key(s) from %s. To "
            "start with no API keys on purpose, stop the bridge and move "
            "both %s and %s aside.",
            path,
            len(data.get("keys", {}) or {}),
            backup.name,
            path.name,
            backup.name,
        )
        return data, _file_signature(path)

    def _install_key_state(
        self,
        keys: dict[str, tuple[str, bytes]],
        key_meta: dict[str, dict[str, Any]],
        key_lookup: dict[str, str],
    ) -> None:
        """Publish new key state (new dicts: copy-on-write)."""
        fast_index = _build_fast_index(key_lookup)
        for key_id, lookup_hash in key_lookup.items():
            owner = fast_index[lookup_hash]
            if owner != key_id:
                logger.warning(
                    "API keys %s and %s hold the same credential; it "
                    "authenticates as %s only. Revoke the duplicate.",
                    owner,
                    key_id,
                    owner,
                )
        self._keys = keys
        self._key_meta = key_meta
        self._key_lookup = key_lookup
        self._key_fast_index = fast_index

    def _current_key_entries(self) -> dict[str, dict[str, Any]]:
        return _serialize_key_state(self._keys, self._key_meta, self._key_lookup)

    def _refresh_keys_locked(self) -> None:
        """Merge in key changes another process wrote (caller holds the key lock).

        Three-way merge of keys.json entries (:func:`_merge_key_entries`):
        entries this process changed since its base version keep its
        changes, all others follow the file; a key the file revoked stays
        revoked and a rotated credential stays rotated.  An unreadable or
        missing file leaves the in-memory state alone.
        """
        path = self._path("keys")
        sig = _file_signature(path)
        self._keys_checked_at = time.monotonic()
        if sig == self._keys_sig or sig is None:
            return
        try:
            data = _read_key_store(path)
        except (FileNotFoundError, _UnreadableFile) as exc:
            if not self._keys_unreadable_logged:
                logger.error(
                    "keys.json changed on disk but cannot be read (%s); "
                    "keeping the last good key set",
                    exc,
                )
                self._keys_unreadable_logged = True
            return
        self._keys_unreadable_logged = False
        theirs_raw = data.get("keys", {})
        t_keys, t_meta, t_lookup = _parse_key_entries(theirs_raw)
        theirs = _serialize_key_state(t_keys, t_meta, t_lookup)
        ours = self._current_key_entries()
        merged = _merge_key_entries(self._keys_base, ours, theirs)
        if merged != ours:
            keys, key_meta, key_lookup = _parse_key_entries(merged)
            # Metadata recorded for ids that hold no key (e.g. the revoked
            # flag set after remove_key) lives in memory only; keep it.
            # (A removed key's own metadata is not kept.)
            for key_id, meta in self._key_meta.items():
                if key_id not in self._keys and key_id not in keys:
                    key_meta.setdefault(key_id, meta)
            self._install_key_state(keys, key_meta, key_lookup)
        self._keys_base = theirs
        self._keys_sig = sig

    def _maybe_refresh_keys(self) -> None:
        """Pick up key changes from other processes (at most once a second).

        Never waits: when a key change of this process holds the key lock
        (it may be fsyncing, or waiting for another worker's file lock),
        the reader keeps the current key state — that writer refreshes
        from disk itself and publishes the result.
        """
        if time.monotonic() - self._keys_checked_at < _KEYS_REFRESH_INTERVAL:
            return
        if _file_signature(self._path("keys")) == self._keys_sig:
            self._keys_checked_at = time.monotonic()
            return
        if not self._key_lock.acquire(blocking=False):
            return
        try:
            self._refresh_keys_locked()
        finally:
            self._key_lock.release()

    def _save_keys(self, *, raise_on_error: bool = False) -> None:
        """Merge-write keys.json (caller holds ``self._key_lock``).

        Under the inter-process lock: merge in what other processes wrote
        since our base, then write if our state differs from the file.
        Also refreshes ``keys.json.bak``.  A failure to write keys.json is
        logged and retried by the next save (``save_all``, the auto-save
        loop); with *raise_on_error* — the key mutators, whose change is
        then not durable — it is also raised as :class:`KeyStoreWriteError`.
        A failure to update ``keys.json.bak`` is only a warning.
        """
        path = self._path("keys")
        try:
            with self._file_lock:
                self._refresh_keys_locked()
                entries = self._current_key_entries()
                if entries == self._keys_base and self._keys_sig is not None:
                    self._keys_write_pending = False
                    return
                data = {
                    "keys": entries,
                    "saved_at": datetime.now(timezone.utc).isoformat(),
                }
                _atomic_write(path, data, mode=0o600)
                self._keys_base = entries
                self._keys_sig = _file_signature(path)
                self._keys_write_pending = False
                try:
                    _atomic_write(self._keys_backup_path(), data, mode=0o600)
                except OSError as exc:
                    logger.warning(
                        "Failed to update %s: %s", self._keys_backup_path(), exc
                    )
        except OSError as exc:
            self._keys_write_pending = True
            logger.error("Failed to save keys: %s", exc)
            if raise_on_error:
                raise KeyStoreWriteError(
                    f"API key change could not be saved to {path.name}: {exc}"
                ) from exc

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

    def _load_webhooks(self) -> None:
        data = _safe_load(self._path("webhooks"))
        webhooks = data.get("webhooks", [])
        self._webhooks = webhooks if isinstance(webhooks, list) else []

    def _load_wifi_whitelist(self) -> None:
        data = _safe_load(self._path("wifi_whitelist"))
        wl = data.get("whitelist", [])
        self._wifi_whitelist = wl if isinstance(wl, list) else []

    def _load_bt_whitelist(self) -> None:
        data = _safe_load(self._path("bt_whitelist"))
        wl = data.get("whitelist", [])
        self._bt_whitelist = wl if isinstance(wl, list) else []

    def _load_alert_rules(self) -> None:
        data = _safe_load(self._path("alert_rules"))
        rules = data.get("rules", [])
        self._alert_rules = rules if isinstance(rules, list) else []

    def _load_watch_bands(self) -> None:
        data = _safe_load(self._path("watch_bands"))
        bands = data.get("watch_bands", [])
        self._watch_bands = bands if isinstance(bands, list) else []

    def _load_syslog_targets(self) -> None:
        data = _safe_load(self._path("syslog_targets"))
        targets = data.get("syslog_targets", [])
        self._syslog_targets = targets if isinstance(targets, list) else []

    # -- Save ---------------------------------------------------------------

    @staticmethod
    def _payload_value(name: str, value: Any) -> Any:
        """The value written for state file *name* (trimmed as on disk)."""
        if name == "alerts" and isinstance(value, list):
            return value[-MAX_ALERTS:]
        if name == "history" and isinstance(value, dict):
            return {
                node_id: entries[-MAX_HISTORY_PER_NODE:]
                if isinstance(entries, list)
                else entries
                for node_id, entries in value.items()
            }
        return value

    @staticmethod
    def _merge(name: str, base: Any, ours: Any, theirs: Any) -> Any:
        merge_key = _STATE_FILES[name][2]
        if merge_key is None:
            if (
                isinstance(base, dict)
                and isinstance(ours, dict)
                and isinstance(theirs, dict)
            ):
                return _merge_dict(base, ours, theirs)
            return ours if ours != base else theirs
        return _merge_list(base, ours, theirs, merge_key)

    def save_all(self) -> None:
        """Persist in-memory state to disk (durably, merging with other workers).

        The state is snapshotted under the in-memory lock, which is then
        released: the merge and the file writes happen outside it, so
        callers of ``set_node`` / ``add_alert`` (on the event loop) never
        wait for disk I/O.  Only files whose content changed are written.
        Changes another process wrote meanwhile are merged in (see the
        module docstring) and adopted into memory.  Blocking: async callers
        should use :meth:`async_save_all`.
        """
        with self._save_lock:
            with self._lock:
                snapshot = {
                    name: copy.deepcopy(self._payload_value(name, getattr(self, attr)))
                    for name, (_field, attr, _mk) in _STATE_FILES.items()
                }
                self._dirty = False
                keys_pending = self._keys_write_pending
            if keys_pending:
                with self._key_lock:
                    self._save_keys()
            failed = False
            adopted: dict[str, tuple[Any, Any]] = {}
            for name, value in snapshot.items():
                try:
                    result = self._sync_state_file(name, value)
                except Exception as exc:
                    failed = True
                    logger.error("Failed to save %s: %s", _FILES[name], exc)
                    continue
                if result is not None:
                    adopted[name] = result
            if adopted:
                self._adopt_merged(adopted)
            if failed:
                self._dirty = True
        logger.debug("Persistence saved successfully")

    def _sync_state_file(self, name: str, value: Any) -> tuple[Any, Any] | None:
        """Merge-write one state file.

        Returns ``(ours, merged)`` when the merged content differs from our
        snapshot (another process contributed), else None.
        """
        field, _attr, _mk = _STATE_FILES[name]
        path = self._path(name)
        ours = _normalize(value)
        with self._file_lock:
            if name == "webhooks":
                # Endpoint security configuration has checked, immediate writes.
                # Generic stale snapshots/metrics must never resurrect a deleted
                # endpoint or undo another worker's disable/URL/secret change.
                try:
                    current = self._read_webhooks_authority()
                except FileNotFoundError:
                    if self._sig.get(name, _MISSING) is not None or ours:
                        raise
                    # First save of a new, empty installation only. A later
                    # removed/unreadable authority is not silently recreated.
                    _atomic_write(path, {"webhooks": []}, mode=0o600)
                    current = []
                self._base[name] = copy.deepcopy(current)
                self._sig[name] = _file_signature(path)
                return (ours, current) if current != ours else None
            base = self._base.get(name, _MISSING)
            sig = _file_signature(path)
            known_sig = self._sig.get(name, _MISSING)
            if base is _MISSING:
                # Never loaded (e.g. save without load_all): our state is
                # the whole truth, as before; write it.
                merged, must_write = ours, True
            else:
                if sig == known_sig:
                    theirs = base
                else:
                    try:
                        theirs = _read_json_object(path).get(field, base)
                    except (FileNotFoundError, _UnreadableFile):
                        theirs = base
                    theirs = _normalize(self._payload_value(name, theirs))
                merged = _normalize(
                    self._payload_value(name, self._merge(name, base, ours, theirs))
                )
                must_write = merged != theirs or sig is None
            if must_write:
                _atomic_write(
                    path,
                    {field: merged, "saved_at": datetime.now(timezone.utc).isoformat()},
                )
                sig = _file_signature(path)
            self._base[name] = merged
            self._sig[name] = sig
        return (ours, merged) if merged != ours else None

    def _adopt_merged(self, adopted: dict[str, tuple[Any, Any]]) -> None:
        """Bring other processes' changes into memory, keeping newer local edits."""
        with self._lock:
            for name, (snapshot, merged) in adopted.items():
                _field, attr, _mk = _STATE_FILES[name]
                if name == "webhooks":
                    setattr(self, attr, copy.deepcopy(merged))
                    continue
                current = _normalize(self._payload_value(name, getattr(self, attr)))
                setattr(self, attr, self._merge(name, snapshot, current, merged))
                if current != snapshot:
                    self._dirty = True

    async def async_save_all(self) -> None:
        """Async wrapper around :meth:`save_all`.

        Offloads the blocking file I/O to a thread so async handlers
        are not blocked while the lock is held.
        """
        await asyncio.to_thread(self.save_all)

    # -- Background auto-save -----------------------------------------------

    async def start_auto_save(self) -> None:
        """Start the background auto-save loop."""
        if self._auto_save_interval <= 0:
            return
        self._auto_save_task = asyncio.create_task(self._auto_save_loop())
        logger.info("Auto-save started (interval=%ss)", self._auto_save_interval)

    async def stop_auto_save(self) -> None:
        """Stop the background auto-save and perform a final save."""
        if self._auto_save_task is not None:
            self._auto_save_task.cancel()
            try:
                await self._auto_save_task
            except asyncio.CancelledError:
                pass
            self._auto_save_task = None
        await self.async_save_all()
        logger.info("Auto-save stopped; final save complete")

    async def _auto_save_loop(self) -> None:
        """Periodically save state if dirty."""
        while True:
            await asyncio.sleep(self._auto_save_interval)
            if self._dirty or self._keys_write_pending:
                try:
                    await self.async_save_all()
                except Exception:
                    logger.exception("Auto-save failed")

    def mark_dirty(self) -> None:
        """Mark state as changed, triggering save on the next cycle."""
        self._dirty = True

    # -- Key store access ---------------------------------------------------

    def get_key_auth_snapshot(
        self,
    ) -> tuple[
        dict[str, tuple[str, bytes]],
        dict[str, dict[str, Any]],
        dict[str, str],
        frozenset[str],
    ]:
        """Copy one coherent current credential/metadata/index state for auth.

        Run from a worker thread: a concurrent durable writer may hold the key
        lock while fsyncing. Refresh before copying so a completed external key
        edit is not hidden by the ordinary getters' refresh throttle.
        """
        with self._key_lock:
            self._refresh_keys_locked()
            return (
                dict(self._keys),
                copy.deepcopy(self._key_meta),
                dict(self._key_fast_index),
                frozenset(self._key_lookup),
            )

    def get_key_store(self) -> dict[str, tuple[str, bytes]]:
        """Return a shallow copy of the in-memory key store."""
        self._maybe_refresh_keys()
        return dict(self._keys)

    def get_key_fast_index(self) -> dict[str, str]:
        """Return a shallow copy of the fast-hash lookup index (SHA-256(raw_key) → key_id)."""
        self._maybe_refresh_keys()
        return dict(self._key_fast_index)

    def get_indexed_key_ids(self) -> frozenset[str]:
        """Return the key_ids that have a lookup hash.

        Authentication only PBKDF2-scans keys *outside* this set (legacy
        entries written before lookup hashes existed): an indexed key can
        only match through its own lookup hash.
        """
        self._maybe_refresh_keys()
        return frozenset(self._key_lookup)

    @contextlib.contextmanager
    def _key_transaction(self) -> Iterator[None]:
        """Hold the key lock and the inter-process lock for a key change.

        Re-reads keys.json first, so the change is validated against (and
        merged with) what other processes wrote.  Does not take
        ``self._lock``: the fsyncs of the write, and the wait for another
        worker's file lock, never block ``set_node`` / ``add_alert``.

        Raises :class:`KeyStoreWriteError` (nothing changed) when the
        inter-process lock cannot be taken or keys.json not re-read — a
        read-only or full data directory without ``.persistence.lock``, an
        I/O error — like a failed write, not as a bare ``OSError``.
        """
        with self._key_lock, contextlib.ExitStack() as stack:
            try:
                stack.enter_context(self._file_lock)
                self._refresh_keys_locked()
            except OSError as exc:
                logger.error("Failed to lock keys for a change: %s", exc)
                raise KeyStoreWriteError(
                    "API key change could not be made: the key store "
                    f"({self._data_dir / _LOCK_FILE}) cannot be locked: {exc}"
                ) from exc
            yield

    def _credential_update(
        self,
        key_id: str,
        hash_hex: str,
        salt: bytes,
        lookup_hash: str | None,
    ) -> tuple[dict[str, tuple[str, bytes]], dict[str, str]]:
        """Return new ``(_keys, _key_lookup)`` with *key_id*'s credential set.

        Caller holds ``self._key_lock``.  Raises ``ValueError`` when
        *lookup_hash* already belongs to a different key_id: one raw
        credential must map to one key_id, or the second id silently
        takes over (or loses) the fast-index entry of the first.
        """
        if lookup_hash:
            owner = self._key_fast_index.get(lookup_hash)
            if owner is not None and owner != key_id and owner in self._keys:
                raise ValueError(
                    f"this credential is already registered as API key {owner!r}"
                )
        keys = dict(self._keys)
        keys[key_id] = (hash_hex, salt)
        key_lookup = dict(self._key_lookup)
        # A replaced credential's old lookup hash described the old key:
        # drop it, and record the new one if given.
        key_lookup.pop(key_id, None)
        if lookup_hash:
            key_lookup[key_id] = lookup_hash
        return keys, key_lookup

    def _commit_key_change(
        self,
        key_id: str,
        *,
        keys: dict[str, tuple[str, bytes]] | None = None,
        key_lookup: dict[str, str] | None = None,
        key_meta: dict[str, dict[str, Any]] | None = None,
        keep_on_failure: bool = False,
    ) -> None:
        """Swap in new key state for a change to *key_id* and write keys.json.

        Caller holds the key transaction.  Raises :class:`KeyStoreWriteError`
        when keys.json could not be written: the change is then not durable
        (other workers, the gateway and a restart do not see it).  With
        *keep_on_failure* — a revocation or a downgrade — it stays in effect
        here (fail closed, ``applied_here``) and the next save retries it.
        Otherwise *key_id*'s entry is put back as it was, so this worker
        does not accept a key, credential, binding or privilege the caller
        was told was not saved.
        """
        before = (
            self._keys.get(key_id, _MISSING),
            self._key_lookup.get(key_id, _MISSING),
            self._key_meta.get(key_id, _MISSING),
        )
        if keys is not None:
            self._keys = keys
        if key_lookup is not None:
            self._key_lookup = key_lookup
            self._key_fast_index = _build_fast_index(key_lookup)
        if key_meta is not None:
            self._key_meta = key_meta
        self._dirty = True
        # Persist under lock to prevent races with concurrent key ops
        try:
            self._save_keys(raise_on_error=True)
        except KeyStoreWriteError as exc:
            if not keep_on_failure:
                self._restore_key_entry(key_id, *before)
                raise
            exc.applied_here = True
            raise

    def _restore_key_entry(
        self, key_id: str, key: Any, lookup_hash: Any, meta: Any
    ) -> None:
        """Put *key_id*'s in-memory entry back (``_MISSING`` removes a part).

        Copy-on-write.  The credential is put back first: undoing a new key
        removes it before its metadata, so it never authenticates with
        default metadata on the way out.
        """
        restored = []
        for current, value in (
            (self._keys, key),
            (self._key_lookup, lookup_hash),
            (self._key_meta, meta),
        ):
            new = dict(current)
            if value is _MISSING:
                new.pop(key_id, None)
            else:
                new[key_id] = value
            restored.append(new)
        keys, key_lookup, key_meta = restored
        self._keys = keys
        self._key_lookup = key_lookup
        self._key_fast_index = _build_fast_index(key_lookup)
        self._key_meta = key_meta

    def set_key(
        self,
        key_id: str,
        hash_hex: str,
        salt: bytes,
        lookup_hash: str | None = None,
    ) -> None:
        """Store a new (or replacement) API key hash.

        Parameters
        ----------
        lookup_hash : str or None
            SHA-256 hex digest of the raw key for O(1) lookup.
            When provided, enables fast-path authentication that
            avoids iterating all keys with PBKDF2.  When omitted, any
            previous lookup hash for *key_id* is dropped: it described
            the old credential, and authentication only scans keys that
            have no lookup hash.

        Raises
        ------
        ValueError
            If *lookup_hash* already belongs to another key_id (the same
            raw credential registered twice).
        KeyStoreWriteError
            If keys.json could not be written; the key is left as it was.
        """
        with self._key_transaction():
            keys, key_lookup = self._credential_update(
                key_id, hash_hex, salt, lookup_hash
            )
            self._commit_key_change(key_id, keys=keys, key_lookup=key_lookup)

    def add_key(
        self,
        key_id: str,
        hash_hex: str,
        salt: bytes,
        *,
        lookup_hash: str | None,
        meta: dict[str, Any],
    ) -> bool:
        """Create *key_id* with its metadata in one step, if it is absent.

        Returns ``False`` (and changes nothing) when *key_id* already
        exists.  The existence check, the key and the metadata are applied
        under one lock, so two concurrent creates of the same key_id cannot
        both succeed.  An edge key id is stored with role ``node`` instead
        of an analyst-or-higher one (:func:`edge_key_role`).  Raises
        ``ValueError`` like :meth:`set_key`, and :class:`KeyStoreWriteError`
        (the key is not created) when keys.json could not be written.
        """
        with self._key_transaction():
            if key_id in self._keys:
                return False
            keys, key_lookup = self._credential_update(
                key_id, hash_hex, salt, lookup_hash
            )
            key_meta = dict(self._key_meta)
            key_meta[key_id] = _edge_safe_meta(key_id, copy.deepcopy(meta))
            self._commit_key_change(
                key_id, keys=keys, key_lookup=key_lookup, key_meta=key_meta
            )
        return True

    def replace_key_credential(
        self,
        key_id: str,
        hash_hex: str,
        salt: bytes,
        *,
        lookup_hash: str | None,
        expected: tuple[str, bytes] | None = None,
        meta_update: dict[str, Any] | None = None,
        meta_default: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Replace the credential of an *existing* key in one step.

        Used by key rotation and the legacy-hash upgrade.  Returns a copy
        of the key's metadata after the change, or ``None`` (changing
        nothing) when *key_id* no longer exists — e.g. it was revoked
        while the caller was hashing the new credential — or, when
        *expected* is given, when its stored ``(hash, salt)`` is no longer
        *expected* (it was rotated meanwhile).  A revoked key is therefore
        never re-created by a rotation that raced with the revocation.

        *meta_update* is merged into the key's metadata (or into
        *meta_default* when the key has none); an edge key keeps role
        ``node`` (:func:`edge_key_role`).  Raises ``ValueError`` like
        :meth:`set_key`, and :class:`KeyStoreWriteError` (the old credential
        stays) when keys.json could not be written.
        """
        with self._key_transaction():
            current = self._keys.get(key_id)
            if current is None:
                return None
            if expected is not None and tuple(current) != tuple(expected):
                return None
            keys, key_lookup = self._credential_update(
                key_id, hash_hex, salt, lookup_hash
            )
            key_meta = None
            if meta_update is not None or meta_default is not None:
                key_meta = dict(self._key_meta)
                old = self._key_meta.get(key_id)
                new = copy.deepcopy(old) if old else copy.deepcopy(meta_default or {})
                new.update(copy.deepcopy(meta_update or {}))
                key_meta[key_id] = _edge_safe_meta(key_id, new)
            self._commit_key_change(
                key_id, keys=keys, key_lookup=key_lookup, key_meta=key_meta
            )
            return copy.deepcopy(self._key_meta.get(key_id, {}))

    def remove_key(self, key_id: str) -> bool:
        """Remove an API key.  Returns True if it existed.

        Raises :class:`KeyStoreWriteError` when keys.json could not be
        written: the revocation is not durable yet (other workers, the
        gateway and a restart still accept the key).  It stays in effect in
        this process (fail closed, ``applied_here``) and the next save
        retries it.

        Idempotent until saved: removing a key that this process already
        removed but keys.json still holds (an earlier call raised) retries
        the write, then returns True or raises again — it is not reported
        as missing while the other workers and the gateway still accept it.
        """
        with self._key_transaction():
            if key_id not in self._keys:
                if key_id not in self._keys_base:
                    return False
                # Removed here by an earlier call whose write failed.
                try:
                    self._save_keys(raise_on_error=True)
                except KeyStoreWriteError as exc:
                    exc.applied_here = True
                    raise
                return True
            keys = dict(self._keys)
            del keys[key_id]
            key_lookup = dict(self._key_lookup)
            key_lookup.pop(key_id, None)
            key_meta = dict(self._key_meta)
            key_meta.pop(key_id, None)
            self._commit_key_change(
                key_id,
                keys=keys,
                key_lookup=key_lookup,
                key_meta=key_meta,
                keep_on_failure=True,
            )
        return True

    def get_key_meta(self) -> dict[str, dict[str, Any]]:
        """Return a deep copy of the in-memory key metadata dict.

        Safe to call from any thread: the published dict is never changed
        in place (see ``__init__``), so the copy cannot see it resize.
        Picks up changes other worker processes wrote to keys.json.
        """
        self._maybe_refresh_keys()
        return copy.deepcopy(self._key_meta)

    def get_saved_key_meta(self, key_id: str) -> dict[str, Any] | None:
        """*key_id*'s metadata as keys.json holds it; None when it holds no such key.

        That is the version this process last read or wrote, and the one
        other workers, the gateway and a restart use.  It differs from
        :meth:`get_key_meta` only while a key change made here is not saved
        yet (:class:`KeyStoreWriteError` with ``applied_here``: a
        revocation or downgrade in effect here until a save writes it).  A
        key revoked that way is gone from :meth:`get_key_store` but still
        has saved metadata.
        """
        self._maybe_refresh_keys()
        entry = self._keys_base.get(key_id)
        if entry is None:
            return None
        _keys, key_meta, _lookup = _parse_key_entries({key_id: entry})
        meta = key_meta.get(key_id)
        return copy.deepcopy(meta) if meta is not None else None

    def set_key_meta(self, key_id: str, meta: dict[str, Any]) -> None:
        """Set or update metadata for a key.

        An edge key id is stored with role ``node`` instead of an
        analyst-or-higher one (:func:`edge_key_role`).  Raises
        :class:`KeyStoreWriteError` when keys.json could not be written; a
        change that only takes access away (lower role, revoked, disabled)
        then stays in effect here, any other is undone.
        """
        with self._key_transaction():
            old = self._key_meta.get(key_id)
            # Store a private copy: the caller may keep mutating *meta*.
            new = _edge_safe_meta(key_id, copy.deepcopy(meta))
            key_meta = dict(self._key_meta)
            key_meta[key_id] = new
            self._commit_key_change(
                key_id, key_meta=key_meta, keep_on_failure=_only_restricts(old, new)
            )

    def update_key_role(self, key_id: str, role: str) -> bool:
        """Update the role for a key. Returns True if key exists.

        An edge key keeps role ``node`` when given an analyst-or-higher
        role (:func:`edge_key_role`).  Raises :class:`KeyStoreWriteError`
        when keys.json could not be written; a downgrade then stays in
        effect here (fail closed), any other change is undone.
        """
        return self.update_key_access(key_id, role=role)

    def update_key_access(
        self,
        key_id: str,
        *,
        role: str | None = None,
        node_id: str | None = None,
        set_node: bool = False,
    ) -> bool:
        """Change a key's role and/or node binding in one write.

        *role* (unless None) as :meth:`update_key_role`; with *set_node*,
        *node_id* binds the key (``None`` / ``""`` unbinds it) as
        :meth:`set_key_node`.  Returns False when the key does not exist.

        All or nothing: one existence check and one keys.json write.
        Raises :class:`KeyStoreWriteError` when keys.json could not be
        written; a change that only lowers the role then stays in effect
        here (fail closed), any other — a binding included — is undone, so
        no part of it is saved without the rest.
        """
        with self._key_transaction():
            if key_id not in self._keys:
                return False
            old = self._key_meta.get(key_id) or {}
            new = copy.deepcopy(old)
            if role is not None:
                new["role"] = role
            if set_node:
                if node_id:
                    new["node_id"] = node_id
                else:
                    new.pop("node_id", None)
            new = _edge_safe_meta(key_id, new)
            key_meta = dict(self._key_meta)
            key_meta[key_id] = new
            self._commit_key_change(
                key_id, key_meta=key_meta, keep_on_failure=_only_restricts(old, new)
            )
        return True

    def has_key(self, key_id: str) -> bool:
        """Return True if a key with the given ``key_id`` is registered.

        Used by the dashboard onboarding banner (PR-6) to distinguish
        "no in-stack scanner key pre-registered" from "scanner key
        pre-registered but no heartbeat yet". Does not consult the
        revoked flag in key meta — the field is intentionally narrow:
        is the slot occupied at all?
        """
        self._maybe_refresh_keys()
        return key_id in self._keys

    # -- Key changes from async code -------------------------------------------
    #
    # Key changes are durable before they return (fsync of keys.json and its
    # backup, under the inter-process lock), or raise KeyStoreWriteError.
    # From the event loop use these wrappers, which run the change in a
    # worker thread.

    async def async_add_key(self, *args: Any, **kwargs: Any) -> bool:
        """:meth:`add_key` in a worker thread."""
        return await asyncio.to_thread(self.add_key, *args, **kwargs)

    async def async_set_key(self, *args: Any, **kwargs: Any) -> None:
        """:meth:`set_key` in a worker thread."""
        await asyncio.to_thread(self.set_key, *args, **kwargs)

    async def async_remove_key(self, key_id: str) -> bool:
        """:meth:`remove_key` in a worker thread."""
        return await asyncio.to_thread(self.remove_key, key_id)

    async def async_set_key_meta(self, key_id: str, meta: dict[str, Any]) -> None:
        """:meth:`set_key_meta` in a worker thread."""
        await asyncio.to_thread(self.set_key_meta, key_id, meta)

    async def async_update_key_role(self, key_id: str, role: str) -> bool:
        """:meth:`update_key_role` in a worker thread."""
        return await asyncio.to_thread(self.update_key_role, key_id, role)

    async def async_set_key_node(self, key_id: str, node_id: str | None) -> bool:
        """:meth:`set_key_node` in a worker thread."""
        return await asyncio.to_thread(self.set_key_node, key_id, node_id)

    async def async_update_key_access(self, key_id: str, **kwargs: Any) -> bool:
        """:meth:`update_key_access` in a worker thread."""
        return await asyncio.to_thread(self.update_key_access, key_id, **kwargs)

    async def async_replace_key_credential(
        self, *args: Any, **kwargs: Any
    ) -> dict[str, Any] | None:
        """:meth:`replace_key_credential` in a worker thread."""
        return await asyncio.to_thread(self.replace_key_credential, *args, **kwargs)

    # -- Node access --------------------------------------------------------

    def get_nodes(self) -> dict[str, dict[str, Any]]:
        """Return a deep copy of the in-memory nodes dict."""
        return copy.deepcopy(self._nodes)

    def set_node(self, node_id: str, data: dict[str, Any]) -> None:
        """Create or update a node entry."""
        with self._lock:
            self._nodes[node_id] = data
            self._dirty = True

    def remove_node(self, node_id: str) -> bool:
        """Remove a node.  Returns True if it existed."""
        with self._lock:
            if node_id in self._nodes:
                del self._nodes[node_id]
                self._dirty = True
                return True
        return False

    # -- Alert access -------------------------------------------------------

    def get_alerts(self) -> list[dict[str, Any]]:
        """Return a deep copy of the in-memory alerts list."""
        return copy.deepcopy(self._alerts)

    def add_alert(self, alert: dict[str, Any]) -> None:
        """Append an alert, trimming to ``MAX_ALERTS``."""
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > MAX_ALERTS:
                self._alerts = self._alerts[-MAX_ALERTS:]
            self._dirty = True

    def set_alerts(self, alerts: list[dict[str, Any]]) -> None:
        """Replace the alerts list (e.g. after deletion)."""
        with self._lock:
            self._alerts = alerts[-MAX_ALERTS:]
            self._dirty = True

    def update_alert(
        self, alert_id: str, changes: dict[str, Any]
    ) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
        """Patch one stored alert and capture its audit diff under the same lock.

        Readers return copies. Replacing a reader's entire list would lose
        alerts or acknowledgement fields written after that snapshot.
        """
        patch = copy.deepcopy(changes)
        with self._lock:
            for index, alert in enumerate(self._alerts):
                if alert.get("alert_id") != alert_id:
                    continue
                audit = [
                    {
                        "key": key,
                        "old": copy.deepcopy(alert.get(key)),
                        "new": copy.deepcopy(value),
                    }
                    for key, value in patch.items()
                    if alert.get(key) != value
                ]
                updated = {**alert, **patch}
                alerts = list(self._alerts)
                alerts[index] = updated
                self._alerts = alerts
                self._dirty = True
                return copy.deepcopy(updated), audit
        return None

    def delete_alert(self, alert_id: str) -> bool:
        """Remove one alert without replacing an earlier reader's snapshot."""
        with self._lock:
            alerts = [a for a in self._alerts if a.get("alert_id") != alert_id]
            if len(alerts) == len(self._alerts):
                return False
            self._alerts = alerts
            self._dirty = True
            return True

    # -- History access -----------------------------------------------------

    def get_history(self) -> dict[str, list[dict[str, Any]]]:
        """Return a deep copy of the in-memory history dict."""
        return copy.deepcopy(self._history)

    def add_history_entry(self, node_id: str, entry: dict[str, Any]) -> None:
        """Append a history entry for *node_id*, trimming to max."""
        with self._lock:
            if node_id not in self._history:
                self._history[node_id] = []
            self._history[node_id].append(entry)
            if len(self._history[node_id]) > MAX_HISTORY_PER_NODE:
                self._history[node_id] = self._history[node_id][-MAX_HISTORY_PER_NODE:]
            self._dirty = True

    # -- Job access ---------------------------------------------------------

    def get_jobs(self) -> dict[str, dict[str, Any]]:
        """Return a deep copy of the in-memory jobs dict."""
        return copy.deepcopy(self._jobs)

    def set_job(self, job_id: str, data: dict[str, Any]) -> None:
        """Create or update a job entry."""
        with self._lock:
            self._jobs[job_id] = data
            self._dirty = True

    def remove_job(self, job_id: str) -> bool:
        """Remove a job.  Returns True if it existed."""
        with self._lock:
            if job_id in self._jobs:
                del self._jobs[job_id]
                self._dirty = True
                return True
        return False

    # -- Schedule access ----------------------------------------------------

    def get_schedules(self) -> dict[str, dict[str, Any]]:
        """Return a deep copy of the in-memory schedules dict."""
        return copy.deepcopy(self._schedules)

    def set_schedule(self, schedule_id: str, data: dict[str, Any]) -> None:
        """Create or update a schedule."""
        with self._lock:
            self._schedules[schedule_id] = data
            self._dirty = True

    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a schedule.  Returns True if it existed."""
        with self._lock:
            if schedule_id in self._schedules:
                del self._schedules[schedule_id]
                self._dirty = True
                return True
        return False

    # -- Webhook access -----------------------------------------------------

    def get_webhooks(self) -> list[dict[str, Any]]:
        """Return a deep copy of the in-memory webhooks list."""
        return copy.deepcopy(self._webhooks)

    def set_webhooks(self, webhooks: list[dict[str, Any]]) -> None:
        """Explicit checked replacement (blocking); not delivery metric sync.

        HTTP CRUD uses ``change_webhook`` to update only its requested ID against
        fresh shared state. Async callers must offload this disk operation.
        """
        with self._save_lock, self._file_lock:
            values = copy.deepcopy(webhooks)
            for value in values:
                value["delivery_revision"] = secrets.token_hex(16)
            self._write_webhooks_authority(values)

    @staticmethod
    def _validate_webhooks_authority(value: Any) -> list[dict[str, Any]]:
        keyed = _keyed(value, "id")
        if keyed is None or any(
            not isinstance(ident, str)
            or not ident
            or not isinstance(entry.get("url"), str)
            or not entry["url"]
            or not isinstance(entry.get("enabled", True), bool)
            or (
                entry.get("signing_secret") is not None
                and not isinstance(entry["signing_secret"], str)
            )
            for ident, entry in keyed.items()
        ):
            raise ValueError("Invalid webhook configuration authority")
        return value

    def _read_webhooks_authority(self) -> list[dict[str, Any]]:
        raw = _read_json_object(self._path("webhooks"))
        if "webhooks" not in raw:
            raise ValueError("Missing webhook configuration authority")
        return self._validate_webhooks_authority(raw["webhooks"])

    def current_webhooks(self) -> list[dict[str, Any]]:
        """Fresh checked authority, including config restores; blocking read.

        Missing, unreadable and malformed configuration propagate to the caller.
        Retriers retain their work and send nothing on those failures.
        """
        with self._save_lock, self._file_lock:
            values = self._read_webhooks_authority()
            changed = False
            for value in values:
                revision = value.get("delivery_revision")
                if revision is None:
                    value["delivery_revision"] = secrets.token_hex(16)
                    changed = True
                elif (
                    not isinstance(revision, str)
                    or len(revision) != 32
                    or any(char not in "0123456789abcdef" for char in revision)
                ):
                    raise ValueError("Invalid webhook delivery revision")
            if changed:
                # Legacy configs get one durable revision before any work can
                # bind to it. A failed commit cannot mint in-memory authority.
                self._write_webhooks_authority(values)
            return values

    def initialize_webhooks(self, *, allow_empty: bool) -> list[dict[str, Any]]:
        """Initialize a genuinely new empty app; never erase pending authority."""
        with self._save_lock, self._file_lock:
            try:
                self._read_webhooks_authority()
            except FileNotFoundError:
                if not allow_empty or self._sig.get("webhooks", _MISSING) is not None:
                    raise
                self._write_webhooks_authority([])
        return self.current_webhooks()

    def _write_webhooks_authority(self, webhooks: list[dict[str, Any]]) -> None:
        self._validate_webhooks_authority(webhooks)
        path = self._path("webhooks")
        # Owner-only: the file holds each webhook's HMAC signing secret.
        _atomic_write(
            path,
            {"webhooks": webhooks, "saved_at": datetime.now(timezone.utc).isoformat()},
            mode=0o600,
        )
        with self._lock:
            self._webhooks = copy.deepcopy(webhooks)
            self._base["webhooks"] = copy.deepcopy(webhooks)
            self._sig["webhooks"] = _file_signature(path)

    def change_webhook(
        self,
        webhook_id: str,
        *,
        create: dict[str, Any] | None = None,
        updates: dict[str, Any] | None = None,
        delete: bool = False,
    ) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """Commit one admin mutation without stale whole-list overwrites.

        No DNS/HTTP runs under these locks. The returned prior record supports
        truthful audit diffs. Missing IDs raise KeyError; disk failures propagate.
        """
        with self._save_lock, self._file_lock:
            try:
                values = self._read_webhooks_authority()
            except FileNotFoundError:
                if self._sig.get("webhooks", _MISSING) is not None:
                    raise
                values = []  # first creation on a new installation
            previous = next((v for v in values if v["id"] == webhook_id), None)
            if create is not None:
                if previous is not None or create.get("id") != webhook_id:
                    raise ValueError("Webhook identity already exists or is invalid")
                created = copy.deepcopy(create)
                created["delivery_revision"] = secrets.token_hex(16)
                values.append(created)
            else:
                if previous is None:
                    raise KeyError(webhook_id)
                values = [
                    ({**v, **(updates or {})} if v["id"] == webhook_id else v)
                    for v in values
                    if not (delete and v["id"] == webhook_id)
                ]
                if not delete:
                    updated = next(v for v in values if v["id"] == webhook_id)
                    if any(
                        previous.get(key) != updated.get(key)
                        for key in ("url", "enabled", "signing_secret")
                    ):
                        updated["delivery_revision"] = secrets.token_hex(16)
                    elif updated.get("delivery_revision") is None:
                        updated["delivery_revision"] = secrets.token_hex(16)
            self._write_webhooks_authority(values)
            return copy.deepcopy(values), copy.deepcopy(previous)

    def get_wifi_whitelist(self) -> list[dict[str, Any]]:
        """Return a deep copy of the WiFi AP whitelist."""
        return copy.deepcopy(self._wifi_whitelist)

    def set_wifi_whitelist(self, whitelist: list[dict[str, Any]]) -> None:
        """Replace the WiFi whitelist."""
        with self._lock:
            self._wifi_whitelist = whitelist
            self._dirty = True

    def get_bt_whitelist(self) -> list[dict[str, Any]]:
        """Return a deep copy of the Bluetooth device whitelist."""
        return copy.deepcopy(self._bt_whitelist)

    def set_bt_whitelist(self, whitelist: list[dict[str, Any]]) -> None:
        """Replace the Bluetooth whitelist."""
        with self._lock:
            self._bt_whitelist = whitelist
            self._dirty = True

    # -- Alert rules access -------------------------------------------------

    def get_alert_rules(self) -> list[dict[str, Any]]:
        """Return a deep copy of the in-memory alert rules list."""
        return copy.deepcopy(self._alert_rules)

    def add_alert_rule(self, rule: dict[str, Any]) -> None:
        """Append an alert rule, trimming to ``MAX_ALERT_RULES``."""
        with self._lock:
            self._alert_rules.append(rule)
            if len(self._alert_rules) > MAX_ALERT_RULES:
                self._alert_rules = self._alert_rules[-MAX_ALERT_RULES:]
            self._dirty = True

    def set_alert_rules(self, rules: list[dict[str, Any]]) -> None:
        """Replace the alert rules list."""
        with self._lock:
            self._alert_rules = rules[-MAX_ALERT_RULES:]
            self._dirty = True

    def update_alert_rule(
        self, rule_id: str, changes: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Patch a rule while retaining concurrent trigger counts and peers."""
        patch = copy.deepcopy(changes)
        with self._lock:
            for index, rule in enumerate(self._alert_rules):
                if rule.get("rule_id") != rule_id:
                    continue
                updated = {**rule, **patch}
                rules = list(self._alert_rules)
                rules[index] = updated
                self._alert_rules = rules
                self._dirty = True
                return copy.deepcopy(updated)
        return None

    def delete_alert_rule(self, rule_id: str) -> bool:
        """Remove a rule without discarding concurrent changes to others."""
        with self._lock:
            rules = [r for r in self._alert_rules if r.get("rule_id") != rule_id]
            if len(rules) == len(self._alert_rules):
                return False
            self._alert_rules = rules
            self._dirty = True
            return True

    def record_alert_rule_trigger(
        self, rule_id: str, triggered_at: str
    ) -> dict[str, Any] | None:
        """Count one trigger of *rule_id* on the stored rule.

        Increments ``trigger_count`` and sets ``last_triggered_at`` on the
        persisted rule (``get_alert_rules`` returns copies, so updating
        those never reached disk).  Returns a copy of the updated rule, or
        None if no rule has that id.
        """
        with self._lock:
            for idx, rule in enumerate(self._alert_rules):
                if rule.get("rule_id") == rule_id:
                    updated = dict(rule)
                    updated["trigger_count"] = int(rule.get("trigger_count") or 0) + 1
                    updated["last_triggered_at"] = triggered_at
                    rules = list(self._alert_rules)
                    rules[idx] = updated
                    self._alert_rules = rules
                    self._dirty = True
                    return copy.deepcopy(updated)
        return None

    # -- Watch band access --------------------------------------------------

    def get_watch_bands(self) -> list[dict[str, Any]]:
        """Return a deep copy of the in-memory watch bands list."""
        return copy.deepcopy(self._watch_bands)

    def add_watch_band(self, band: dict[str, Any]) -> None:
        """Append a watch band, trimming to ``MAX_WATCH_BANDS``."""
        with self._lock:
            self._watch_bands.append(band)
            if len(self._watch_bands) > MAX_WATCH_BANDS:
                self._watch_bands = self._watch_bands[-MAX_WATCH_BANDS:]
            self._dirty = True

    def set_watch_bands(self, bands: list[dict[str, Any]]) -> None:
        """Replace the watch bands list."""
        with self._lock:
            self._watch_bands = bands[-MAX_WATCH_BANDS:]
            self._dirty = True

    # -- Syslog targets access ----------------------------------------------

    def get_syslog_targets(self) -> list[dict[str, Any]]:
        """Return a deep copy of the in-memory syslog targets list."""
        return copy.deepcopy(self._syslog_targets)

    def set_syslog_targets(self, targets: list[dict[str, Any]]) -> None:
        """Replace the syslog targets list."""
        with self._lock:
            self._syslog_targets = list(targets)
            self._dirty = True

    # -- Detection config access --------------------------------------------

    _DETECTION_CONFIG_DEFAULTS: dict[str, Any] = {
        "wifi_anomaly_insert_threshold": 0.4,
        "wifi_anomaly_alert_threshold": 0.7,
        "wifi_anomaly_critical_threshold": 0.85,
        "wifi_anomaly_cooldown_seconds": 300,
        "rf_anomaly_insert_threshold": 0.3,
        "rf_anomaly_alert_threshold": 0.7,
        "rf_anomaly_critical_threshold": 0.85,
        "rf_min_confidence_floor": 0.0,
        "rf_min_learning_detections": 300,
        "wifi_auto_snooze_seen_count": 50,
        "wifi_auto_snooze_max_score": 0.5,
        "wifi_auto_snooze_hours": 24,
        "rf_auto_snooze_seen_count": 100,
        "rf_auto_snooze_max_score": 0.5,
        "rf_auto_snooze_hours": 1,
        "wifi_dimension_weights": {
            "evil_twin": 0.25,
            "security_downgrade": 0.22,
            "signal_anomaly": 0.13,
            "deauth_indicator": 0.15,
            "new_network": 0.10,
            "channel_change": 0.08,
            "client_surge": 0.07,
        },
        "rf_dimension_weights": dict(DEFAULT_RF_DIMENSION_WEIGHTS),
        "protocol_detection": {
            "adsb": True,
            "dect": True,
            "p25": True,
            "scada_fsk": True,
            "zwave": True,
            "tpms": True,
            "ism433": True,
            "nrf24": True,
            "dji_ofdm": True,
            "fpv_analog": True,
            "elrs": True,
            "sigfox": True,
            "sidewalk": True,
            "nbiot": True,
            "wireless_hart": True,
            "isa100": True,
            "wisun": True,
            "pmr446": True,
            "lora_meshtastic": True,
            "lora_meshcore": True,
        },
    }

    _DEEP_MERGE_KEYS = (
        "wifi_dimension_weights",
        "rf_dimension_weights",
        "protocol_detection",
    )

    def get_detection_config(self) -> dict[str, Any]:
        """Return the detection configuration, merged with defaults.

        The result is the caller's own: the defaults are deep-copied, so a
        caller that changes a nested dict (``PUT /api/admin/protocols``
        sets a toggle in place) never changes the class-level defaults.

        A stored value the configuration rules refuse (one an older bridge
        stored, or a snapshot restore brought back) is left out, so its
        default applies, and logged once
        (:func:`~sigrift.bridge.detection_config.usable_detection_config`):
        no reader, ingest included, ever gets one.  The next write drops it
        from the file.
        """
        path = self._data_dir / "detection_config.json"
        saved, left_out = usable_detection_config(_safe_load(path).get("config", {}))
        if left_out != self._detection_config_left_out:
            self._detection_config_left_out = left_out
            if left_out:
                logger.warning(
                    "%s: stored values the configuration rules refuse are left out "
                    "(their defaults apply until they are set again): %s",
                    path.name,
                    "; ".join(left_out),
                )
        merged = copy.deepcopy(self._DETECTION_CONFIG_DEFAULTS)
        # Deep-merge dict-valued keys (weights, protocol toggles)
        for key in self._DEEP_MERGE_KEYS:
            if key in saved and isinstance(saved[key], dict):
                merged[key].update(saved[key])
        # Shallow-merge scalar keys
        for key, val in saved.items():
            if key not in self._DEEP_MERGE_KEYS:
                merged[key] = val
        return merged

    def set_detection_config(self, config: dict[str, Any]) -> None:
        """Persist detection configuration to JSON file."""
        path = self._data_dir / "detection_config.json"
        _atomic_write(
            path,
            {
                "config": config,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        logger.info("Detection config saved")

    def get_detection_config_defaults(self) -> dict[str, Any]:
        """Return factory default detection configuration."""
        return copy.deepcopy(self._DETECTION_CONFIG_DEFAULTS)

    # -- Key → node binding (contract K4) -----------------------------------

    def bind_key_to_node(
        self,
        key_id: str,
        node_id: str,
        *,
        holds_node: Callable[[str, dict[str, Any]], bool] | None = None,
    ) -> str | None:
        """Bind API key *key_id* to *node_id* unless it is already bound.

        Returns the node the key is bound to afterwards — *node_id* when
        this call bound it, the earlier binding otherwise — or ``None``
        when the key does not exist.  The check and the write are one
        step under the key lock (and, where key changes are coordinated
        between worker processes, inside that transaction), so two first
        requests for different nodes cannot both bind the key.  Blocking
        (writes keys.json): async callers use ``asyncio.to_thread``.

        *holds_node* ``(other_key_id, other_meta) -> bool``: when given, an
        unbound key is bound only if no *other* stored key holds *node_id*
        by that test, else :class:`NodeAlreadyBound` is raised — checked
        in the same locked step, so two keys racing to claim one node
        cannot both win (contract K7b).

        Raises :class:`KeyStoreWriteError` (the key stays unbound) when
        keys.json could not be written.
        """
        transaction = getattr(self, "_key_transaction", None)
        with transaction() if transaction is not None else self._key_lock:
            if key_id not in self._keys:
                return None
            meta = self._key_meta.get(key_id) or {}
            bound = meta.get("node_id")
            if isinstance(bound, str) and bound:
                return bound
            if holds_node is not None:
                for other in self._keys:
                    if other != key_id and holds_node(
                        other, self._key_meta.get(other) or {}
                    ):
                        raise NodeAlreadyBound(node_id, other)
            key_meta = dict(self._key_meta)
            key_meta[key_id] = {**copy.deepcopy(meta), "node_id": node_id}
            self._commit_key_change(key_id, key_meta=key_meta)
            return node_id

    def set_key_node(self, key_id: str, node_id: str | None) -> bool:
        """Bind API key *key_id* to *node_id*, or unbind it (``None``).

        The explicit, admin-made binding (contract K7b): unlike
        :meth:`bind_key_to_node` it replaces an earlier binding and does
        not care whether other keys are bound to that node — that is how
        a node gets a second key.  The caller validates *node_id*.
        Returns False when the key does not exist.  Blocking (writes
        keys.json).  Raises :class:`KeyStoreWriteError` (the binding stays
        as it was) when keys.json could not be written.
        """
        return self.update_key_access(key_id, node_id=node_id, set_node=True)

    # -- Session binding (admin-toggleable) ---------------------------------
    #
    # The gateway's binding mode is set via the BRIDGE_SESSION_BINDING env
    # var at startup (strict | ip | warn | none). This persistent setting
    # records the admin-preferred value and is surfaced in the admin UI so
    # operators can toggle it without editing compose/env files. The
    # gateway does NOT read this file directly — a stack restart is still
    # required to apply changes, and the admin UI shows that caveat.

    _VALID_SESSION_BINDING_MODES = ("strict", "ip", "warn", "none")
    _SESSION_BINDING_DEFAULT = "none"

    def get_session_binding(self) -> str:
        """Return the admin-configured session binding mode.

        Falls back to BRIDGE_SESSION_BINDING env var (what the gateway
        actually enforces), then to the safe default `none` when ambiguous.
        """
        path = self._data_dir / "session_binding.json"
        saved = _safe_load(path).get("mode")
        if saved in self._VALID_SESSION_BINDING_MODES:
            return saved
        # No saved pref → reflect whatever the gateway env is set to so
        # the UI shows the truth rather than a stale default.
        env = os.environ.get("BRIDGE_SESSION_BINDING", "").strip().lower()
        if env in self._VALID_SESSION_BINDING_MODES:
            return env
        return self._SESSION_BINDING_DEFAULT

    def set_session_binding(self, mode: str) -> None:
        """Persist the admin-configured session binding mode."""
        if mode not in self._VALID_SESSION_BINDING_MODES:
            raise ValueError(
                f"invalid session binding mode: {mode!r} "
                f"(expected one of {self._VALID_SESSION_BINDING_MODES})"
            )
        path = self._data_dir / "session_binding.json"
        _atomic_write(
            path,
            {
                "mode": mode,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            },
        )
        logger.info("Session binding mode saved: %s", mode)

    # -- Spectrum connection config ------------------------------------------

    def get_spectrum_connection(self) -> dict[str, Any]:
        """Return the active spectrum connection config (shared across workers)."""
        path = self._data_dir / "spectrum_connection.json"
        return _safe_load(path)

    def set_spectrum_connection(self, config: dict[str, Any]) -> None:
        """Store the active spectrum connection config."""
        path = self._data_dir / "spectrum_connection.json"
        _atomic_write(path, config)

    # -- Config snapshot access ----------------------------------------------

    # Files to include in config snapshots (user-configurable state only).
    # Excludes: keys.json (security), alerts.json/history.json/jobs.json
    # (transient event state), baselines (ML-derived, large).
    _SNAPSHOT_FILES = [
        "detection_config.json",
        "alert_rules.json",
        "watch_bands.json",
        "webhooks.json",
        "syslog_targets.json",
        "wifi_whitelist.json",
        "bt_whitelist.json",
        "nodes.json",
        "schedules.json",
    ]
    # Files older releases captured that are no longer snapshot files: a
    # restore of an older snapshot skips them (with a warning) and restores
    # the rest.  When a name leaves _SNAPSHOT_FILES, add it here — never a
    # key, lock or backup file, or a path.
    _RETIRED_SNAPSHOT_FILES: frozenset[str] = frozenset()

    def create_config_snapshot(
        self,
        trigger: str,
        description: str = "",
        *,
        db_conn: Any = None,
        require_complete: bool = False,
    ) -> int | None:
        """Read all config files from disk, store as JSON blob in DB.

        Parameters
        ----------
        trigger : str
            One of ``"manual"``, ``"daily"``, ``"config_change"``.
        description : str
            Human-readable note.
        db_conn : sqlite3.Connection or None
            If provided, use this connection instead of looking up the
            detection store via app state.
        require_complete : bool
            Refuse to save a partial backup if an existing config file cannot
            be read. Required before a restore overwrites current settings.

        Returns
        -------
        int or None
            The snapshot ID, or ``None`` if the store is unavailable.
        """
        files_dict: dict[str, Any] = {}
        for fname in self._SNAPSHOT_FILES:
            fpath = self._data_dir / fname
            if fpath.exists():
                try:
                    with open(fpath, encoding="utf-8") as f:
                        files_dict[fname] = json.load(f)
                except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
                    logger.warning("Snapshot: failed to read %s: %s", fname, exc)
                    if require_complete:
                        return None
            # Omit missing files (they just don't exist yet)

        if db_conn is None:
            return None

        now = datetime.now(timezone.utc).isoformat()
        try:
            with sqlite_transaction(db_conn):
                cur = db_conn.execute(
                    "INSERT INTO config_snapshots (timestamp, trigger, description, files, tenant_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        now,
                        trigger,
                        description,
                        json.dumps(files_dict, default=str),
                        "default",
                    ),
                )
            snap_id = cur.lastrowid
            logger.info(
                "Config snapshot #%d created (trigger=%s, %d files)",
                snap_id,
                trigger,
                len(files_dict),
            )
            return snap_id
        except Exception as exc:
            logger.warning("Failed to create config snapshot: %s", exc)
            return None

    @staticmethod
    def list_config_snapshots(db_conn: Any, limit: int = 50) -> list[dict[str, Any]]:
        """Return snapshot metadata (id, timestamp, trigger, description, file count)."""
        rows = db_conn.execute(
            "SELECT id, timestamp, trigger, description, files FROM config_snapshots "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        result = []
        for r in rows:
            try:
                file_count = len(json.loads(r["files"]))
            except (json.JSONDecodeError, TypeError):
                file_count = 0
            result.append(
                {
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "trigger": r["trigger"],
                    "description": r["description"],
                    "file_count": file_count,
                }
            )
        return result

    @staticmethod
    def get_config_snapshot(db_conn: Any, snapshot_id: int) -> dict[str, Any] | None:
        """Return full snapshot with file contents."""
        row = db_conn.execute(
            "SELECT id, timestamp, trigger, description, files FROM config_snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            files = json.loads(row["files"])
        except (json.JSONDecodeError, TypeError):
            files = {}
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "trigger": row["trigger"],
            "description": row["description"],
            "files": files,
        }

    @classmethod
    def config_snapshot_files(
        cls, snap: dict[str, Any]
    ) -> tuple[dict[str, Any], list[str]]:
        """``(files a restore of *snap* writes, retired names it skips)``.

        Raises :class:`ConfigSnapshotRejected` when the snapshot names any
        file that is neither a snapshot file (``_SNAPSHOT_FILES``, matched
        exactly) nor a retired one (``_RETIRED_SNAPSHOT_FILES``):
        ``keys.json``, a path, a name outside the data directory — such a
        row can only have been tampered with, and nothing of it is
        restored.  A ``files`` value that is not a JSON object (a
        malformed row) holds no files.
        """
        files = snap.get("files", {})
        if not isinstance(files, dict):
            files = {}
        rejected = [
            name
            for name in files
            if name not in cls._SNAPSHOT_FILES
            and name not in cls._RETIRED_SNAPSHOT_FILES
        ]
        if rejected:
            raise ConfigSnapshotRejected(rejected)
        retired = [name for name in files if name not in cls._SNAPSHOT_FILES]
        return {
            name: content
            for name, content in files.items()
            if name in cls._SNAPSHOT_FILES
        }, retired

    def restore_config_snapshot(self, db_conn: Any, snapshot_id: int) -> list[str]:
        """Write files back to disk from a snapshot, reload in-memory state.

        Returns list of restored file names. Writes are atomic per file, not
        across the snapshot. After a write failure, reload the resulting disk
        state and raise ConfigSnapshotRestoreError with completed/failed names
        so callers can synchronize live consumers without reporting success.

        Only the files a snapshot captures (``_SNAPSHOT_FILES``, matched
        exactly) are ever written; see :meth:`config_snapshot_files`.
        """
        snap = self.get_config_snapshot(db_conn, snapshot_id)
        if snap is None:
            return []

        try:
            files, retired = self.config_snapshot_files(snap)
        except ConfigSnapshotRejected as exc:
            logger.warning(
                "Restore: snapshot #%s refused, it names files that are not "
                "snapshot files: %s",
                snapshot_id,
                exc.rejected_files,
            )
            raise
        if retired:
            logger.warning(
                "Restore: snapshot #%s holds files this release no longer "
                "restores, skipped: %s",
                snapshot_id,
                retired,
            )
        restored: list[str] = []
        failed: list[str] = []
        for fname, content in files.items():
            fpath = self._data_dir / fname
            try:
                if fname == "webhooks.json":
                    # A restore is an explicit authority change, including
                    # A→B→A. Never restore an old queue's delivery revision.
                    values = self._validate_webhooks_authority(content["webhooks"])
                    self.set_webhooks(values)
                else:
                    _atomic_write(fpath, content)
                restored.append(fname)
            except (OSError, ValueError, KeyError, TypeError) as exc:
                logger.warning("Restore: failed to write %s: %s", fname, exc)
                failed.append(fname)

        # Reload in-memory state from the restored files
        self.load_all()
        if failed:
            raise ConfigSnapshotRestoreError(restored, failed)
        return restored

    @staticmethod
    def delete_config_snapshot(db_conn: Any, snapshot_id: int) -> bool:
        """Delete a snapshot by ID. Returns True if deleted."""
        with sqlite_transaction(db_conn):
            cur = db_conn.execute(
                "DELETE FROM config_snapshots WHERE id = ?", (snapshot_id,)
            )
        return cur.rowcount > 0

    @staticmethod
    def cleanup_old_snapshots(db_conn: Any, retention_days: int = 90) -> int:
        """Delete snapshots older than *retention_days*. Returns count deleted."""
        from datetime import timedelta

        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retention_days)
        ).isoformat()
        with sqlite_transaction(db_conn):
            cur = db_conn.execute(
                "DELETE FROM config_snapshots WHERE timestamp < ?", (cutoff,)
            )
        deleted = cur.rowcount
        if deleted:
            logger.info(
                "Cleaned up %d old config snapshots (>%d days)", deleted, retention_days
            )
        return deleted
