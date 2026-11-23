"""Per-node API key management endpoints.

SECURITY: Raw API keys are returned ONLY at creation and rotation
time.  Hashes and salts are NEVER exposed in API responses.  All
user-supplied strings are sanitised with ``html.escape()``.

Each key's metadata -- role, purpose, expiry, bound node, description -- is stored
with its hash in ``keys.json`` (it used to live in process memory only and
was lost on restart), and the auth layer enforces role and expiry.

``PATCH /{key_id}`` changes a key's purpose and node binding: it classifies
keys created before key purposes existed (the startup warning lists them),
binds extra keys to a node, and unbinds a key (``{"node_id": null}``) after
a wrong first-use claim without revoking it.
"""

from __future__ import annotations

import html
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny.dependencies import (
    MASTER_KEY_ID,
    KeyRejected,
    key_expired,
    key_role,
    rate_limit,
    rate_limit_sensitive,
    require_master_key,
)
from sigrift.lib.shiny.models import (
    ManagedKeyCreate,
    ManagedKeyResponse,
    ManagedKeyUpdate,
)
from sigrift.lib.shiny.persistence import KEEP, PersistenceManager
from sigrift.lib.shiny.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _get_persistence(request: Request) -> PersistenceManager:
    return request.app.state.persistence


def _get_app_state(request: Request) -> AppState:
    return request.app.state.app_state


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _role_name(key_id: str, meta: dict[str, Any]) -> str:
    try:
        return key_role(key_id, meta).name.lower()
    except KeyRejected:
        return f"invalid:{meta.get('role')!s}"


def _key_response(key_id: str, meta: dict[str, Any]) -> ManagedKeyResponse:
    """Public view of one key (never the raw key, hash or salt)."""
    return ManagedKeyResponse(
        key_id=key_id,
        description=meta.get("description", ""),
        created_at=_parse_dt(meta.get("created_at")) or _utcnow(),
        expires_at=_parse_dt(meta.get("expires_at")),
        last_used=_parse_dt(meta.get("last_used")),
        node_id=meta.get("node_id"),
        revoked=False,
        role=_role_name(key_id, meta),
        purpose=meta.get("purpose"),
        # The auth layer's verdict: an unparseable expiry lists as
        # expires_at None but is rejected, so do not let it read as "never".
        expired=key_expired(meta),
    )


# ---------------------------------------------------------------------------
# POST / — create new API key
# ---------------------------------------------------------------------------


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_key(
    request: Request,
    body: ManagedKeyCreate,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Create a new API key.

    Returns the raw key ONCE.  It cannot be retrieved again.
    """
    persistence = _get_persistence(request)
    app_state = _get_app_state(request)

    safe_key_id = html.escape(body.key_id)
    safe_desc = html.escape(body.description)
    safe_node = body.node_id  # validated against the ID pattern

    # Check for duplicate key_id
    if safe_key_id in persistence.get_key_store():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Key ID {safe_key_id} already exists",
        )

    now = _utcnow()
    expires_at: datetime | None = None
    if body.expires_in_hours is not None and body.expires_in_hours > 0:
        expires_at = now + timedelta(hours=body.expires_in_hours)

    # Generate, hash, and store (with its metadata, in one write)
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(
        safe_key_id,
        hash_hex,
        salt,
        meta={
            "role": body.role,
            "description": safe_desc,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat() if expires_at else None,
            "node_id": safe_node,
            "purpose": body.purpose,
        },
    )

    app_state.log_activity(
        "key_created",
        node_id=safe_node,
        message=f"API key created: {safe_key_id} ({body.role})",
    )

    logger.info("API key created: %s (role %s)", safe_key_id, body.role)

    return {
        "key_id": safe_key_id,
        "raw_key": raw_key,
        "role": body.role,
        "description": safe_desc,
        "node_id": safe_node,
        "purpose": body.purpose,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "message": "Save this key now -- it will not be shown again",
    }


# ---------------------------------------------------------------------------
# GET / — list all keys (masked)
# ---------------------------------------------------------------------------


@router.get("/")
async def list_keys(
    request: Request,
    _key_id: str = Depends(rate_limit),
) -> list[ManagedKeyResponse]:
    """List all managed keys.  Raw keys and hashes are never returned."""
    persistence = _get_persistence(request)
    key_store = persistence.get_key_store()
    all_meta = persistence.get_all_key_meta()

    return [_key_response(kid, all_meta.get(kid, {})) for kid in key_store]


# ---------------------------------------------------------------------------
# PATCH /{key_id} — classify / bind / unbind a key
# ---------------------------------------------------------------------------


@router.patch("/{key_id}")
async def update_key(
    key_id: str,
    request: Request,
    body: ManagedKeyUpdate,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> ManagedKeyResponse:
    """Change a key's ``purpose`` and/or ``node_id``.  Requires master key.

    ``{"node_id": "<node>"}`` binds the key to that node (it becomes a
    ``node`` key unless ``purpose`` is sent too), even if other keys are
    already bound to it; ``{"node_id": null}`` unbinds it;
    ``{"purpose": "dashboard"}`` / ``{"purpose": "node"}`` classifies a key
    created before key purposes existed.  Fields not sent are kept.  409 if
    the result would be a ``dashboard`` key bound to a node.
    """
    persistence = _get_persistence(request)
    safe_id = html.escape(key_id)

    if safe_id not in persistence.get_key_store():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {safe_id} not found",
        )
    if safe_id == MASTER_KEY_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The master key is an admin key and is never bound to a node",
        )

    sent = body.model_fields_set
    purpose: Any = body.purpose if "purpose" in sent else KEEP
    node_id: Any = body.node_id if "node_id" in sent else KEEP
    if purpose is KEEP and node_id is not KEEP and node_id is not None:
        purpose = "node"  # binding a key to a node makes it a node key

    outcome, meta, previous = persistence.update_key_binding(
        safe_id, purpose=purpose, node_id=node_id, updated_at=_utcnow().isoformat()
    )
    if outcome == "unknown_key":  # revoked concurrently
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {safe_id} not found",
        )
    if outcome == "dashboard_bound":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Key {safe_id} is bound to node {meta.get('node_id')!r}; a "
                "dashboard key cannot be bound to a node (send node_id: null "
                "to unbind it)"
            ),
        )

    new_node = meta.get("node_id")
    previous_node = previous.get("node_id")
    message = (
        f"API key updated: {safe_id} (purpose {meta.get('purpose') or 'none'}, "
        f"node {new_node or 'none'})"
    )
    if previous_node and previous_node != new_node:
        message += f"; unbound from node {previous_node}"
    _get_app_state(request).log_activity(
        "key_updated",
        node_id=new_node or previous_node,
        message=message,
        details={
            "key_id": safe_id,
            "purpose": meta.get("purpose"),
            "node_id": new_node,
            "previous_node_id": previous_node,
        },
    )
    logger.info("%s", message)
    return _key_response(safe_id, meta)


# ---------------------------------------------------------------------------
# DELETE /{key_id} — revoke key
# ---------------------------------------------------------------------------


@router.delete("/{key_id}")
async def revoke_key(
    key_id: str,
    request: Request,
    _master: str = Depends(require_master_key),
) -> dict[str, str]:
    """Revoke (delete) an API key.  Requires master key; never the master key.

    The master key is the only key that can manage keys, and a new one is
    only generated at the next restart, so revoking it would lock everyone
    out of key management until then.  Rotate it instead.
    """
    persistence = _get_persistence(request)
    safe_id = html.escape(key_id)

    if safe_id == MASTER_KEY_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "The master key cannot be revoked; rotate it instead "
                "(PUT /api/keys/master/rotate)"
            ),
        )

    removed = persistence.remove_key(safe_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {safe_id} not found",
        )

    app_state = _get_app_state(request)
    app_state.log_activity(
        "key_revoked",
        message=f"API key revoked: {safe_id}",
    )

    logger.info("API key revoked: %s", safe_id)
    return {"status": "ok", "revoked": safe_id}


# ---------------------------------------------------------------------------
# PUT /{key_id}/rotate — rotate key
# ---------------------------------------------------------------------------


@router.put("/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    request: Request,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Rotate an existing key.  Returns the new raw key ONCE.

    The key keeps its role, expiry and node binding.
    """
    persistence = _get_persistence(request)
    safe_id = html.escape(key_id)

    if safe_id not in persistence.get_key_store():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {safe_id} not found",
        )

    # Generate new key and replace hash+salt (metadata is kept)
    new_raw = generate_api_key(length=32)
    hash_hex, salt = hash_credential(new_raw)
    persistence.set_key(safe_id, hash_hex, salt)

    now = _utcnow()
    persistence.update_key_meta(safe_id, rotated_at=now.isoformat())

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
