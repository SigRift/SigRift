"""Per-node API key management endpoints for The Bridge.

SECURITY: Raw API keys are returned ONLY at creation and rotation
time.  Hashes and salts are NEVER exposed in API responses.  All
user-supplied strings are sanitised with ``html.escape()``.

Adapted from sigrift.lib.shiny.routers.keys for The Bridge.
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.bridge.dependencies import (
    Role,
    enforce_master_rotation,
    enforce_role_ceiling,
    highest_key_role,
    key_expired,
    key_expiry,
    rate_limit_sensitive,
    require_master_key,
    require_role,
)
from sigrift.bridge.models import BridgeKeyResponse, KeyCreate
from sigrift.bridge.persistence import (
    KeyStoreWriteError,
    PersistenceManager,
    edge_key_role,
)
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import key_change_saved, utcnow
from sigrift.lib.shiny.models import MAX_KEY_EXPIRES_IN_HOURS

logger = logging.getLogger(__name__)

router = APIRouter()

_utcnow = utcnow

# SEC-M1: Maximum key lifetime (days). Keys without an explicit expiry
# get this as the default.  Configurable via env var.
_MAX_KEY_LIFETIME_DAYS = int(os.environ.get("BRIDGE_MAX_KEY_LIFETIME_DAYS", "365"))


def capped_key_expiry(now: datetime, hours: float | None) -> datetime:
    """SEC-M1: when a key created at *now* for *hours* expires.

    Omitted, zero or negative *hours* get the maximum lifetime
    (``BRIDGE_MAX_KEY_LIFETIME_DAYS``) and a longer request is capped to
    it, so every created key expires.  The cap is applied to the hours
    before they become a datetime, so no lifetime the request models accept
    (nor a huge ``BRIDGE_MAX_KEY_LIFETIME_DAYS``) can overflow it.  Shared
    by ``POST /api/keys/`` and ``POST /api/admin/keys``.
    """
    max_hours = min(_MAX_KEY_LIFETIME_DAYS * 24, MAX_KEY_EXPIRES_IN_HOURS)
    if hours is None or hours <= 0:
        hours = max_hours
    return now + timedelta(hours=min(hours, max_hours))


def _get_persistence(request: Request) -> PersistenceManager:
    return request.app.state.persistence


def _get_app_state(request: Request) -> AppState:
    return request.app.state.app_state


def _get_key_meta(persistence: PersistenceManager) -> dict[str, dict[str, Any]]:
    """Return key metadata from the persistence layer (survives restarts)."""
    return persistence.get_key_meta()


# ---------------------------------------------------------------------------
# POST / -- create new API key
# ---------------------------------------------------------------------------


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_key(
    request: Request,
    body: KeyCreate,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Create a new API key. Returns the raw key ONCE.

    Keys created here are ANALYST keys, except an edge/sensor node key id
    (``node_``, ``rtlsdr_``, ``hackrf_``, ``sensor_``, ``edge_``, ``sdr_``),
    which is always a NODE key (as the bridge and the gateway read it).
    The response's ``role`` says which.
    """
    persistence = _get_persistence(request)
    app_state = _get_app_state(request)

    safe_key_id = html.escape(body.key_id)
    safe_desc = html.escape(body.description)
    safe_node = html.escape(body.node_id) if body.node_id else None

    conflict = HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Key ID {safe_key_id} already exists",
    )
    # Cheap early answer; the authoritative check is add_key below.
    if safe_key_id in persistence.get_key_store():
        raise conflict

    raw_key = generate_api_key(length=32)
    hash_hex, salt = await asyncio.to_thread(hash_credential, raw_key)

    now = _utcnow()
    # SEC-M1: mandatory expiry, capped at the max lifetime.
    expires_at = capped_key_expiry(now, body.expires_in_hours)

    role = edge_key_role(safe_key_id, "analyst")
    meta = {
        "description": safe_desc,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "node_id": safe_node,
        "role": role,
        "revoked": False,
    }
    # Existence check, key and metadata in one locked step: another create
    # of the same key_id that ran while we were hashing wins, and this one
    # gets 409 instead of silently replacing the other caller's key.
    with key_change_saved():
        added = await persistence.async_add_key(
            safe_key_id,
            hash_hex,
            salt,
            lookup_hash=compute_lookup_hash(raw_key),
            meta=meta,
        )
    if not added:
        raise conflict

    app_state.log_activity(
        "key_created",
        node_id=safe_node,
        message=f"API key created: {safe_key_id}",
    )

    logger.info("API key created: %s", safe_key_id)

    return {
        "key_id": safe_key_id,
        "raw_key": raw_key,
        "role": role,
        "description": safe_desc,
        "node_id": safe_node,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "message": "Save this key now -- it will not be shown again",
    }


# ---------------------------------------------------------------------------
# GET / -- list all keys (masked)
# ---------------------------------------------------------------------------


@router.get("/")
async def list_keys(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[BridgeKeyResponse]:
    """List all managed keys. Raw keys and hashes are never returned.

    ``expires_at`` and ``expired`` are what bridge auth applies to the key
    (``dependencies.key_expiry`` / ``key_expired``): a stored expiry that
    cannot be parsed lists as ``expires_at`` null with ``expired`` true, as
    bridge auth rejects the key.  The gateway's own parser can disagree on
    a hand-edited value (see ``key_expiry``).
    """
    persistence = _get_persistence(request)
    key_store = persistence.get_key_store()
    all_meta = _get_key_meta(persistence)

    results: list[BridgeKeyResponse] = []
    for kid in key_store:
        meta = all_meta.get(kid, {})
        created_str = meta.get("created_at")

        # A stored value that is not an ISO string (malformed, or not a
        # string at all: TypeError) lists as unknown instead of failing
        # the whole listing.
        created_at = _utcnow()
        if created_str:
            try:
                created_at = datetime.fromisoformat(created_str)
            except (TypeError, ValueError):
                pass

        # The expiry auth applies, parsed the way auth parses it (padding
        # ignored, naive as UTC); unparseable lists as unknown.
        try:
            expires_at = key_expiry(meta)
        except ValueError:
            expires_at = None

        last_used_str = meta.get("last_used")
        last_used: datetime | None = None
        if last_used_str:
            try:
                last_used = datetime.fromisoformat(last_used_str)
            except (TypeError, ValueError):
                pass

        results.append(
            BridgeKeyResponse(
                key_id=kid,
                description=meta.get("description", ""),
                created_at=created_at,
                expires_at=expires_at,
                last_used=last_used,
                node_id=meta.get("node_id"),
                revoked=meta.get("revoked", False),
                # Auth's own verdict, so the listing never reads "never
                # expires" for a key every auth path rejects.
                expired=key_expired(meta),
            )
        )

    return results


# ---------------------------------------------------------------------------
# DELETE /{key_id} -- revoke key
# ---------------------------------------------------------------------------


@router.delete("/{key_id}")
async def revoke_key(
    key_id: str,
    request: Request,
    _master: str = Depends(require_master_key),
) -> dict[str, str]:
    """Revoke (delete) an API key. Requires admin; never the master key,
    nor a key above the caller's own role (K5).

    A revocation keys.json could not record is not reported as done (503):
    other workers and the gateway still accept the key.  It is in effect on
    this worker, logged as not yet saved, and repeating the request retries
    the write.
    """
    persistence = _get_persistence(request)
    safe_id = html.escape(key_id)

    if safe_id == "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot revoke master key",
        )
    # Also a key revoked here whose revocation is not saved yet: the other
    # workers and the gateway still accept it with its saved role.
    if (
        safe_id in persistence.get_key_store()
        or persistence.get_saved_key_meta(safe_id) is not None
    ):
        enforce_role_ceiling(
            request, highest_key_role(persistence, safe_id), "revoke a key"
        )

    def log_pending() -> None:
        _get_app_state(request).log_activity(
            "key_revoked",
            message=f"API key revoked on this worker, not yet saved: {safe_id}",
            details={"pending": "not yet saved"},
        )

    with key_change_saved(on_pending=log_pending):
        removed = await persistence.async_remove_key(safe_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {safe_id} not found",
        )

    # Mark as revoked in persistence metadata
    meta = persistence.get_key_meta().get(safe_id, {})
    if meta:
        meta["revoked"] = True
        try:
            await persistence.async_set_key_meta(safe_id, meta)
        except KeyStoreWriteError as exc:
            # The revocation itself is saved; only the flag is not.
            logger.warning("Revoked flag of key %s not saved: %s", safe_id, exc)

    app_state = _get_app_state(request)
    app_state.log_activity(
        "key_revoked",
        message=f"API key revoked: {safe_id}",
    )

    logger.info("API key revoked: %s", safe_id)
    return {"status": "ok", "revoked": safe_id}


# ---------------------------------------------------------------------------
# PUT /{key_id}/rotate -- rotate key
# ---------------------------------------------------------------------------


@router.put("/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    request: Request,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Rotate an existing key. Returns the new raw key ONCE.

    The master key can only be rotated by itself or a keymaster, and no
    caller may rotate (and so obtain) a key above its own role (K5).
    """
    persistence = _get_persistence(request)
    safe_id = html.escape(key_id)
    if safe_id == "master":
        enforce_master_rotation(request, _master)
    elif safe_id in persistence.get_key_store():
        enforce_role_ceiling(
            request, highest_key_role(persistence, safe_id), "rotate a key"
        )

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Key {safe_id} not found",
    )
    # Cheap early answer; the authoritative check is replace_key_credential.
    if safe_id not in persistence.get_key_store():
        raise not_found

    new_raw = generate_api_key(length=32)
    hash_hex, salt = await asyncio.to_thread(hash_credential, new_raw)

    now = _utcnow()

    # Existence check, new credential and metadata in one locked step: a
    # revocation that landed while we were hashing stays revoked (404).
    # An unsaved rotation (503) keeps the old credential.
    with key_change_saved():
        meta = await persistence.async_replace_key_credential(
            safe_id,
            hash_hex,
            salt,
            lookup_hash=compute_lookup_hash(new_raw),
            meta_update={"rotated_at": now.isoformat()},
            meta_default={
                "description": "",
                "created_at": now.isoformat(),
                "expires_at": None,
                "node_id": None,
                "revoked": False,
            },
        )
    if meta is None:
        raise not_found

    app_state = _get_app_state(request)
    app_state.log_activity(
        "key_rotated",
        message=f"API key rotated: {safe_id}",
    )

    logger.info("API key rotated: %s", safe_id)

    return {
        "key_id": safe_id,
        "raw_key": new_raw,
        "rotated_at": now.isoformat(),
        "message": "Save this key now -- it will not be shown again",
    }


# ---------------------------------------------------------------------------
# POST /rotate-master -- rotate the master key
# ---------------------------------------------------------------------------


@router.post("/rotate-master")
async def rotate_master_key(
    request: Request,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Rotate the master key. Requires the current master key (or KEYMASTER).

    Generates a new master key, replaces the hash in persistence,
    and returns the new raw key once.  The old key immediately
    stops working.  Update the ``BRIDGE_MASTER_KEY`` env var and
    restart in production.
    """
    enforce_master_rotation(request, _master)
    persistence = _get_persistence(request)
    app_state = _get_app_state(request)

    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Master key not found in key store",
    )
    # Ensure the master key entry exists (re-checked atomically below)
    if "master" not in persistence.get_key_store():
        raise not_found

    # Generate new master key
    new_raw = generate_api_key(length=32)
    hash_hex, salt = await asyncio.to_thread(hash_credential, new_raw)

    now = _utcnow()

    # New credential + metadata in one locked step, only if the master
    # entry still exists.  An unsaved rotation (503) keeps the old key.
    with key_change_saved():
        rotated = await persistence.async_replace_key_credential(
            "master",
            hash_hex,
            salt,
            lookup_hash=compute_lookup_hash(new_raw),
            meta_update={
                "role": "admin",
                "description": "Master key (rotated)",
                "created_at": now.isoformat(),
                "expires_at": None,
            },
        )
    if rotated is None:
        raise not_found

    # Note: the rotated key is returned in the response body once.
    # In production, update the BRIDGE_MASTER_KEY env var and restart.

    # Audit trail
    app_state.log_activity(
        "master_key_rotated",
        message="Master key rotated",
    )

    # Also log to detection store audit if available
    detection_store = getattr(request.app.state, "detection_store", None)
    if detection_store:
        detection_store.log_audit(
            action="master_key_rotated",
            target_id="master",
            operator=_master,
            note="Master key rotated via API",
        )

    logger.info("Master key rotated by %s", _master)

    return {
        "status": "rotated",
        "raw_key": new_raw,
        "rotated_at": now.isoformat(),
        "message": "Save this key now -- it will not be shown again. "
        "The old master key is no longer valid.",
    }
