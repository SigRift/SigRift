"""Admin panel API router for The Bridge.

Provides master-key-only endpoints for API key management, node
management, alert rule management, audit log viewing, and log viewing.
All actions are logged to the audit trail.

Webhook management, maintenance/backup, and system config/stats endpoints
have been split into separate routers (webhook_management, maintenance,
system_config) for maintainability.
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Request,
    status,
)
from pydantic import BaseModel, Field

from sigrift.bridge.constants import BRIDGE_RETENTION_DAYS  # noqa: F401 — re-exported for backward compat
from sigrift.bridge.dependencies import admin_rate_limit as _admin_rate_limit
from sigrift.bridge.dependencies import (
    Role,
    enforce_role_ceiling,
    highest_key_role,
    key_expired,
    key_expiry,
    stored_key_role,
    trusted_forwarded_proto,
)
from sigrift.bridge.models import CommandRequest
from sigrift.bridge.routers.keys import capped_key_expiry
from sigrift.bridge.routers.nodes import (
    _check_command_queue,
    _drop_pending_commands,
    _enqueue_command,
    stored_detection_summary,
    stored_floor_label,
)
from sigrift.bridge.persistence import edge_key_role
from sigrift.bridge.state import AppState
from sigrift.bridge.utils import get_detection_store, key_change_saved, utcnow
from sigrift.lib.shiny.node_metrics import (
    isoformat,
    stored_capabilities,
    stored_metric,
    stored_node_fields,
    stored_number,
)

logger = logging.getLogger(__name__)


router = APIRouter()

_utcnow = utcnow
_get_detection_store = get_detection_store


# ---------------------------------------------------------------------------
# Audit diff helper (shared with system_config router)
# ---------------------------------------------------------------------------


def _config_diff(
    old: dict[str, Any],
    new: dict[str, Any],
    keys: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Build a list of {key, old, new} dicts for values that changed.

    For nested dicts (weights), produces per-sub-key entries.
    Only includes keys that actually differ.
    """
    check_keys = keys if keys else list(set(list(old.keys()) + list(new.keys())))
    changes: list[dict[str, Any]] = []
    for k in check_keys:
        old_v = old.get(k)
        new_v = new.get(k)
        if isinstance(old_v, dict) and isinstance(new_v, dict):
            # Per-sub-key diff for weight dicts
            all_sub = set(list(old_v.keys()) + list(new_v.keys()))
            for sk in sorted(all_sub):
                ov = old_v.get(sk)
                nv = new_v.get(sk)
                if ov != nv:
                    changes.append({"key": f"{k}.{sk}", "old": ov, "new": nv})
        elif old_v != new_v:
            changes.append({"key": k, "old": old_v, "new": new_v})
    return changes


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


#: Longest ``expires_days`` accepted (422 above it).  The key's lifetime is
#: then capped to BRIDGE_MAX_KEY_LIFETIME_DAYS, which an omitted
#: ``expires_days`` gets: every key expires (SEC-M1).
_MAX_KEY_EXPIRY_DAYS = 3650


class CreateKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}
    description: str = ""
    role: str = "analyst"
    node_id: str | None = None
    #: Lifetime in days.  Omitted or ``null`` gets the default lifetime,
    #: BRIDGE_MAX_KEY_LIFETIME_DAYS, which also caps a longer request, as on
    #: ``POST /api/keys/`` (SEC-M1: every key expires).  Zero or negative is
    #: refused (422), never taken as the default; so is anything above
    #: ``_MAX_KEY_EXPIRY_DAYS``.
    expires_days: int | None = Field(default=None, ge=1, le=_MAX_KEY_EXPIRY_DAYS)


def _validated_node_id(node_id: str | None) -> str | None:
    """Return *node_id* if it is a valid node id (or None/empty → None); else 400."""
    if not node_id:
        return None
    from sigrift.lib.shiny.models import _validate_id

    try:
        return _validate_id(node_id, "node_id")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from None


class UpdateKeyPermissionsRequest(BaseModel):
    model_config = {"extra": "forbid"}
    role: str | None = None
    permissions: list[str] = Field(default_factory=list)
    #: The node the key acts for (contract K7b: how an admin binds a key,
    #: e.g. a node's second key).  Omitted: unchanged; ``null`` or ``""``:
    #: unbound.
    node_id: str | None = None


class UpdateNodeConfigRequest(BaseModel):
    model_config = {"extra": "forbid"}
    config: dict[str, Any] = Field(default_factory=dict)


#: Same body and command allowlist (``ALLOWED_COMMANDS``) as
#: ``POST /api/nodes/{id}/command``.  The allowlist refuses names the edge
#: agent has no handler for, such as the ``restart_scanner`` and
#: ``run_diagnostics`` the admin UI used to queue, and ``capture_start`` and
#: ``capture_stop``, which the allowlist used to admit although the agent
#: ignores them.  It leaves out ``iq_capture``: IQ captures are queued
#: through ``POST /api/nodes/{id}/capture``.
NodeCommandRequest = CommandRequest


class CreateAlertRuleRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str
    severity: str = "warning"
    message: str = ""
    thresholds: dict[str, Any] = Field(default_factory=dict)
    node_id: str | None = None
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True
    cooldown_seconds: int = 300
    notify_webhook: bool = True


class UpdateAlertRuleRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str | None = None
    severity: str | None = None
    message: str | None = None
    thresholds: dict[str, Any] | None = None
    conditions: list[dict[str, Any]] | None = None
    enabled: bool | None = None
    cooldown_seconds: int | None = None
    notify_webhook: bool | None = None


# ---------------------------------------------------------------------------
# Key Management
# ---------------------------------------------------------------------------


@router.get("/keys")
async def list_keys(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> list[dict[str, Any]]:
    """List all API keys with metadata (no raw keys or hashes).

    ``expires_at`` is keys.json's value as stored; ``expired`` is bridge
    auth's verdict on it (``dependencies.key_expired``, as in
    ``GET /api/keys/``), also for a value that cannot be parsed.
    ``effective_expires_at`` is the instant bridge auth applies
    (``dependencies.key_expiry``: ISO 8601, always with an offset, a naive
    stored value read as UTC), or null when the key never expires or the
    stored value cannot be parsed (then ``expired`` is true).  The admin UI
    shows that, so it never reads the stored value with the browser's own
    date parser or time zone.  Both are bridge auth's reading: the
    gateway's parser can disagree on a hand-edited value (see
    ``key_expiry``).
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    key_store = persistence.get_key_store()
    key_meta = persistence.get_key_meta()

    keys = []
    for kid in key_store:
        meta = key_meta.get(kid, {})
        try:
            expiry = key_expiry(meta)
        except ValueError:
            expiry = None
        keys.append(
            {
                "key_id": kid,
                "is_master": kid == "master",
                # The role the key authenticates with (no stored role: viewer),
                # reported for keys that cannot authenticate too.
                "role": stored_key_role(kid, meta).name.lower(),
                # keys.json's value as stored (null: none): a value that is
                # not a lower-case role name, which "role" hides, shows here.
                "stored_role": meta.get("role"),
                "description": meta.get("description", ""),
                "created_at": meta.get("created_at", ""),
                "expires_at": meta.get("expires_at"),
                # The instant bridge auth applies (null: none, or the stored
                # value cannot be parsed), in its own offset: converting one
                # near year 1 or 9999 to UTC can overflow and fail the list.
                "effective_expires_at": (
                    expiry.isoformat() if expiry is not None else None
                ),
                # Rejected as expired by bridge auth: also an unparseable
                # expires_at (then effective_expires_at is null).
                "expired": key_expired(meta),
                "node_id": meta.get("node_id"),
            }
        )

    store.log_audit(
        action="admin_list_keys",
        target_id="keys",
        operator=_key_id,
    )

    return keys


@router.post("/keys", status_code=status.HTTP_201_CREATED)
async def create_key(
    body: CreateKeyRequest,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Create a new API key. Returns plaintext key once."""
    from sigrift.lib.security.credentials import (
        compute_lookup_hash,
        generate_api_key,
        hash_credential,
    )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    # Validate role
    role_str = body.role.lower()
    valid_roles = {r.name.lower() for r in Role}
    if role_str not in valid_roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role {body.role!r}. Must be one of: {', '.join(sorted(valid_roles))}",
        )
    # K5: never above the caller's own role (so keymaster only by keymaster)
    enforce_role_ceiling(request, Role[role_str.upper()], "create a key")
    node_id = _validated_node_id(body.node_id)

    raw_key = generate_api_key(length=32)
    hash_hex, salt = await asyncio.to_thread(hash_credential, raw_key)

    import uuid

    now = _utcnow()

    # SEC-M1: mandatory expiry (omitted: the default lifetime), capped at
    # the max lifetime.
    days = body.expires_days
    expires_at = capped_key_expiry(
        now, days * 24 if days is not None else None
    ).isoformat()

    meta = {
        "role": role_str,
        "description": body.description,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
        # K4: a key created for a node may act only for that node
        "node_id": node_id,
    }
    # Key and metadata in one locked step that never replaces an existing
    # key_id (a random id collision just draws a new one).
    for _attempt in range(8):
        key_id = f"key_{uuid.uuid4().hex[:8]}"
        with key_change_saved():
            added = await persistence.async_add_key(
                key_id,
                hash_hex,
                salt,
                lookup_hash=compute_lookup_hash(raw_key),
                meta=meta,
            )
        if added:
            break
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not allocate a unique key ID",
        )

    store.log_audit(
        action="admin_create_key",
        target_id=key_id,
        operator=_key_id,
        details={"description": body.description, "role": role_str, "node_id": node_id},
    )

    logger.info("Admin created key: %s (role=%s)", key_id, role_str)

    return {
        "key_id": key_id,
        "raw_key": raw_key,
        "role": role_str,
        "node_id": node_id,
        "description": body.description,
        "created_at": now.isoformat(),
        "expires_at": expires_at,
    }


@router.delete("/keys/{key_id}")
async def revoke_key(
    key_id: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Revoke an API key.

    A revocation keys.json could not record is not reported as done (503):
    other workers and the gateway still accept the key.  It is in effect on
    this worker, audited as not yet saved, and repeating the request
    retries the write (200 and the audit row once it is saved).
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    key_store = persistence.get_key_store()
    # A key revoked here whose revocation is not saved yet still exists
    # for the other workers and the gateway: not "not found".
    if key_id not in key_store and persistence.get_saved_key_meta(key_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id!r} not found",
        )

    if key_id == "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot revoke master key",
        )
    enforce_role_ceiling(request, highest_key_role(persistence, key_id), "revoke a key")

    def audit_pending() -> None:
        store.log_audit(
            action="admin_revoke_key",
            target_id=key_id,
            operator=_master,
            details={"pending": "not yet saved"},
        )

    with key_change_saved(on_pending=audit_pending):
        await persistence.async_remove_key(key_id)

    store.log_audit(
        action="admin_revoke_key",
        target_id=key_id,
        operator=_master,
    )

    logger.info("Admin revoked key: %s", key_id)

    return {"status": "ok", "revoked": key_id}


@router.put("/keys/{key_id}/permissions")
async def update_key_permissions(
    key_id: str,
    body: UpdateKeyPermissionsRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update a key's role, permissions and node binding.

    ``node_id`` (when present in the body) binds the key to that node, or
    unbinds it (``null`` / ``""``).  This explicit binding replaces an
    earlier one and may give a node more than one key; trust on first use
    never does (contract K7b).  A key named after a registered node stays
    bound to that node (the legacy convention).

    The role and the binding are saved together or not at all.  When
    keys.json cannot be written the answer is 503 and nothing is audited
    as done; only a downgrade stays in effect on this worker (audited as
    not yet saved, and saved by the next save or a repeat of the request).
    The audited ``old`` values are the saved ones.
    """
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    key_store = persistence.get_key_store()
    if key_id not in key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id!r} not found",
        )

    if key_id == "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change master key role",
        )

    result: dict[str, Any] = {"status": "ok", "key_id": key_id}
    # What keys.json holds (other workers and the gateway use it); it is
    # this worker's state too unless a downgrade made here is not saved.
    before = persistence.get_saved_key_meta(key_id)
    if before is None:
        before = persistence.get_key_meta().get(key_id) or {}
    # The role the saved key authenticates with (no stored role: viewer)
    old_role = stored_key_role(key_id, before).name.lower()
    # K5: a key above the caller's own role is out of its reach
    enforce_role_ceiling(request, highest_key_role(persistence, key_id), "change a key")

    set_node = "node_id" in body.model_fields_set
    new_node_id = _validated_node_id(body.node_id) if set_node else None
    old_node_id = before.get("node_id")

    role_str: str | None = None
    if body.role is not None:
        role_str = body.role.lower()
        valid_roles = {r.name.lower() for r in Role}
        if role_str not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role {body.role!r}. Must be one of: {', '.join(sorted(valid_roles))}",
            )
        # KEYMASTER role assignment requires the caller to already be KEYMASTER
        if role_str == "keymaster":
            caller_role = getattr(request.state, "key_role", Role.VIEWER)
            if caller_role < Role.KEYMASTER:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Only KEYMASTER can assign the keymaster role",
                )
        # K5: no role above the caller's own
        enforce_role_ceiling(request, Role[role_str.upper()], "assign a key role")
        # Edge/sensor node keys never hold analyst or above (the bridge and
        # the gateway would store and read them as NODE): refuse rather
        # than report a role the key does not get.
        if edge_key_role(key_id, role_str) != role_str:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"Key {key_id!r} is an edge/sensor node key (by its id) and "
                    f"cannot hold the {role_str} role; use node, sensor or viewer"
                ),
            )

    changes: list[dict[str, Any]] = []
    if role_str is not None and role_str != old_role:
        changes.append({"key": "role", "old": old_role, "new": role_str})
    raw_old_role = before.get("role")
    if role_str is not None and raw_old_role is not None and raw_old_role != old_role:
        # keys.json held something other than the role name the key
        # authenticated with ("Admin", "superuser", 4): the stored value is
        # rewritten even when the role itself does not change.
        changes.append({"key": "stored_role", "old": raw_old_role, "new": role_str})
    if set_node and new_node_id != old_node_id:
        changes.append({"key": "node_id", "old": old_node_id, "new": new_node_id})

    def audit_pending() -> None:
        store.log_audit(
            action="admin_update_key_permissions",
            target_id=key_id,
            operator=_master,
            details={"changes": changes, "pending": "not yet saved"},
        )

    if role_str is not None or set_node:
        # Role and binding in one locked step and one write: all or nothing.
        with key_change_saved(on_pending=audit_pending):
            found = await persistence.async_update_key_access(
                key_id, role=role_str, node_id=new_node_id, set_node=set_node
            )
        if not found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key {key_id!r} not found",
            )
    if role_str is not None:
        result["role"] = role_str
    if set_node:
        result["node_id"] = new_node_id
        logger.info("Admin set node binding of key %s: %r", key_id, new_node_id)

    store.log_audit(
        action="admin_update_key_permissions",
        target_id=key_id,
        operator=_master,
        details={"changes": changes}
        if changes
        else {"role": body.role, "permissions": body.permissions},
    )

    return result


# ---------------------------------------------------------------------------
# Key Rotation
# ---------------------------------------------------------------------------


class RotateKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}
    deploy_to_node: bool = False
    ssh_user: str = Field(
        default="pi",
        pattern=r"^[a-zA-Z0-9_\-]{1,32}$",
        description="SSH username for deployment (alphanumeric, hyphens, underscores only)",
    )


@router.post("/keys/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    body: RotateKeyRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Rotate an API key. Optionally deploy the new key to the node via SSH.

    The new raw key is only transmitted over TLS (the HTTPS connection this
    request arrived on).  If ``deploy_to_node`` is True the key is pushed to
    the edge node over SSH (encrypted transport) and the services are
    restarted so the old key is immediately invalidated.
    """
    import asyncio

    # ── TLS enforcement ──────────────────────────────────────────────
    # X-Forwarded-Proto counts only from the gateway or a trusted proxy;
    # a direct plaintext client could otherwise just claim https.
    if request.url.scheme != "https" and trusted_forwarded_proto(request) != "https":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Key rotation requires a TLS connection",
        )

    from sigrift.lib.security.credentials import (
        compute_lookup_hash,
        generate_api_key,
        hash_credential,
    )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    key_store = persistence.get_key_store()
    if key_id not in key_store:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id!r} not found",
        )

    if key_id == "master":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Use the dedicated master-rotate endpoint for the master key",
        )
    # K5: rotating hands out the key's new credential — never above the
    # caller's own role
    enforce_role_ceiling(request, highest_key_role(persistence, key_id), "rotate a key")

    # ── Generate new key ─────────────────────────────────────────────
    new_raw = generate_api_key(length=32)
    hash_hex, salt = await asyncio.to_thread(hash_credential, new_raw)

    now = _utcnow()
    # Existence check, new credential and metadata in one locked step: a
    # revocation that landed while we were hashing stays revoked (404).
    # An unsaved rotation (503) keeps the old credential.
    with key_change_saved():
        meta = await persistence.async_replace_key_credential(
            key_id,
            hash_hex,
            salt,
            lookup_hash=compute_lookup_hash(new_raw),
            meta_update={"rotated_at": now.isoformat()},
        )
    if meta is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id!r} not found",
        )

    result: dict[str, Any] = {
        "key_id": key_id,
        "raw_key": new_raw,
        "rotated_at": now.isoformat(),
        "deployed": False,
    }

    # ── Optional SSH deployment ──────────────────────────────────────
    if body.deploy_to_node:
        node_id = meta.get("node_id")
        if not node_id:
            # Fall back: key_id itself may be the node_id
            nodes = persistence.get_nodes()
            if key_id in nodes:
                node_id = key_id

        if not node_id:
            result["deploy_error"] = "No node_id associated with this key"
        else:
            nodes = persistence.get_nodes()
            node_data = nodes.get(node_id)
            # A record saved before heartbeat metrics were checked can hold
            # a host that is not text: no host, not a 500 that loses the
            # key this request has already rotated.
            host = stored_node_fields(node_data)["host"] if node_data else ""
            if not host:
                result["deploy_error"] = f"Node {node_id!r} has no host address"
            else:
                user = body.ssh_user
                # Validate host is an IP or simple hostname (no shell
                # metacharacters). fullmatch: '$' also matches before a
                # trailing newline.
                import re as _re

                if not _re.fullmatch(r"[a-zA-Z0-9._\-]+", host):
                    result["deploy_error"] = f"Invalid host address: {host!r}"
                elif not _re.fullmatch(r"[a-zA-Z0-9_\-]{1,32}", user):
                    result["deploy_error"] = f"Invalid SSH user: {user!r}"
                else:
                    # P0-2: Deploy key via SCP to avoid exposing it in
                    # /proc/*/cmdline.  Write the key to a local temp file,
                    # SCP it to the remote node, then SSH to read it from
                    # the file and update the service unit.
                    import tempfile

                    ssh_opts = [
                        "-o",
                        "ConnectTimeout=10",
                        "-o",
                        "StrictHostKeyChecking=accept-new",  # P0-1
                        "-o",
                        "BatchMode=yes",
                    ]
                    tmp = tempfile.NamedTemporaryFile(
                        mode="w",
                        prefix="mlrf_key_",
                        suffix=".tmp",
                        delete=False,
                    )
                    try:
                        os.chmod(tmp.name, 0o600)
                        tmp.write(new_raw)
                        tmp.close()

                        # Step 1: Create a secure temp file on the remote
                        # node with restrictive permissions (0600), then SCP
                        # the key into it.  This avoids the predictable
                        # /tmp/mlrf_key_deploy path that allows local race
                        # conditions.
                        mktemp_proc = await asyncio.create_subprocess_exec(
                            "ssh",
                            *ssh_opts,
                            f"{user}@{host}",
                            "mktemp /tmp/mlrf_key_XXXXXXXXXX",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        mktemp_out, mktemp_err = await asyncio.wait_for(
                            mktemp_proc.communicate(),
                            timeout=15,
                        )
                        if mktemp_proc.returncode != 0:
                            result["deploy_error"] = (
                                mktemp_err.decode(errors="replace").strip()
                                or "Failed to create temp file on remote node"
                            )
                            logger.warning(
                                "Remote mktemp failed for %s (%s): %s",
                                node_id,
                                host,
                                result["deploy_error"],
                            )
                        else:
                            remote_tmp = mktemp_out.decode().strip()
                            # Validate remote path (prevent injection)
                            import re as _re2

                            if not _re2.match(
                                r"^/tmp/mlrf_key_[A-Za-z0-9]{10}$", remote_tmp
                            ):
                                result["deploy_error"] = (
                                    f"Unexpected remote temp path: {remote_tmp!r}"
                                )
                            else:
                                # Step 1b: SCP key file to the secure
                                # remote temp path
                                scp_proc = await asyncio.create_subprocess_exec(
                                    "scp",
                                    *ssh_opts,
                                    tmp.name,
                                    f"{user}@{host}:{remote_tmp}",
                                    stdout=asyncio.subprocess.PIPE,
                                    stderr=asyncio.subprocess.PIPE,
                                )
                                scp_out, scp_err = await asyncio.wait_for(
                                    scp_proc.communicate(),
                                    timeout=30,
                                )
                                if scp_proc.returncode != 0:
                                    result["deploy_error"] = (
                                        scp_err.decode(errors="replace").strip()
                                        or "SCP transfer failed"
                                    )
                                    logger.warning(
                                        "SCP key deploy failed for %s (%s): %s",
                                        node_id,
                                        host,
                                        result["deploy_error"],
                                    )
                                else:
                                    # Step 2: SSH to read key from the secure
                                    # temp file and update the service unit —
                                    # key never appears in process command line.
                                    deploy_cmd = (
                                        "sudo bash -c '"
                                        f"chmod 600 {remote_tmp} && "
                                        f"KEY=$(cat {remote_tmp}) && "
                                        f"rm -f {remote_tmp} && "
                                        'sed -i "s|^Environment=MLRF_BRIDGE_KEY=.*'
                                        '|Environment=MLRF_BRIDGE_KEY=${KEY}|" '
                                        "/etc/systemd/system/rf-edge.service && "
                                        "systemctl daemon-reload && "
                                        "systemctl restart rf-edge.service'"
                                    )
                                    proc = await asyncio.create_subprocess_exec(
                                        "ssh",
                                        *ssh_opts,
                                        f"{user}@{host}",
                                        deploy_cmd,
                                        stdout=asyncio.subprocess.PIPE,
                                        stderr=asyncio.subprocess.PIPE,
                                    )
                                    stdout, stderr = await asyncio.wait_for(
                                        proc.communicate(),
                                        timeout=30,
                                    )
                                    if proc.returncode == 0:
                                        result["deployed"] = True
                                        result["deploy_host"] = host
                                        result["deploy_node_id"] = node_id
                                        logger.info(
                                            "Key rotated and deployed to node %s (%s)",
                                            node_id,
                                            host,
                                        )
                                    else:
                                        result["deploy_error"] = (
                                            stderr.decode(errors="replace").strip()
                                            or "SSH command failed"
                                        )
                                        logger.warning(
                                            "Key rotation deploy failed for %s (%s): %s",
                                            node_id,
                                            host,
                                            result["deploy_error"],
                                        )
                    except asyncio.TimeoutError:
                        result["deploy_error"] = "SSH connection timed out"
                    except Exception as exc:
                        result["deploy_error"] = str(exc)
                    finally:
                        # Always clean up the local temp file
                        try:
                            os.unlink(tmp.name)
                        except OSError:
                            pass

    store.log_audit(
        action="admin_rotate_key",
        target_id=key_id,
        operator=_master,
        details={
            "severity": "critical",
            "deployed": result.get("deployed", False),
            "deploy_node_id": result.get("deploy_node_id"),
        },
    )

    logger.info("Admin rotated key: %s (deployed=%s)", key_id, result.get("deployed"))

    return result


# ---------------------------------------------------------------------------
# Node Management
# ---------------------------------------------------------------------------


@router.get("/nodes")
async def list_nodes(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> list[dict[str, Any]]:
    """List all nodes with status, last heartbeat, detection stats.

    Stored values of the wrong type read as absent (see ``node_metrics``).
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    nodes_data = persistence.get_nodes()

    nodes = []
    for nid, ndata in nodes_data.items():
        node_status = app_state.get_node_status(ndata)
        fields = stored_node_fields(ndata)
        nodes.append(
            {
                "node_id": nid,
                "host": fields["host"],
                "port": fields["port"],
                "status": node_status.value,
                "last_seen": isoformat(fields["last_seen"]),
                "capabilities": fields["capabilities"],
                "cpu_percent": stored_metric(ndata, "cpu_percent"),
                "memory_mb": stored_metric(ndata, "memory_mb"),
                "detection_summary": stored_detection_summary(
                    ndata.get("detection_summary")
                ),
                "classifications_per_sec": stored_metric(
                    ndata, "classifications_per_sec"
                ),
                "position_x": stored_number(ndata.get("position_x")),
                "position_y": stored_number(ndata.get("position_y")),
                "floor_label": stored_floor_label(ndata.get("floor_label")),
            }
        )

    return nodes


@router.delete("/nodes/{node_id}")
async def deregister_node(
    node_id: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Deregister a node."""
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    nodes = persistence.get_nodes()
    if node_id not in nodes:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    persistence.remove_node(node_id)
    _drop_pending_commands(request.app.state.app_state, node_id)

    store.log_audit(
        action="admin_deregister_node",
        target_id=node_id,
        operator=_master,
    )

    logger.info("Admin deregistered node: %s", node_id)

    return {"status": "ok", "deregistered": node_id}


def _queue_for_registered_node(
    request: Request, node_id: str, command: str, params: dict[str, Any]
) -> None:
    """Queue *command* for *node_id*'s next heartbeat.

    Same guards as ``POST /api/nodes/{id}/command``, checked before anything
    is queued: 404 for a node that is not registered (it could never collect
    the command) and 429 once the node's queue is full for the caller.  Queued
    the same way too, with a command id, a history entry and a lease: a node
    that does not collect the command within the lease never runs it.
    """
    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state

    if node_id not in persistence.get_nodes():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )
    _check_command_queue(request, app_state, node_id)

    _enqueue_command(app_state, node_id, command, params, _utcnow())


@router.put("/nodes/{node_id}/config")
async def update_node_config(
    node_id: str,
    body: UpdateNodeConfigRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update node configuration (queued for next heartbeat)."""
    store = _get_detection_store(request)

    _queue_for_registered_node(request, node_id, "update_config", body.config)

    store.log_audit(
        action="admin_update_node_config",
        target_id=node_id,
        operator=_master,
        details={"config": body.config},
    )

    return {"status": "ok", "node_id": node_id, "config_queued": True}


@router.post("/nodes/{node_id}/command")
async def queue_node_command(
    node_id: str,
    body: NodeCommandRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Queue a command for a node."""
    store = _get_detection_store(request)

    _queue_for_registered_node(request, node_id, body.command, body.params)

    store.log_audit(
        action="admin_queue_command",
        target_id=node_id,
        operator=_master,
        details={"command": body.command},
    )

    return {"status": "queued", "node_id": node_id, "command": body.command}


@router.get("/nodes/{node_id}/diagnostics")
async def get_node_diagnostics(
    node_id: str,
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return detailed diagnostics for a single node.

    Combines heartbeat data, capabilities, detection statistics, and
    recent errors into a single introspection payload.
    """
    import asyncio

    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    store = _get_detection_store(request)

    nodes = persistence.get_nodes()
    node_data = nodes.get(node_id)
    if node_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node {node_id!r} not found",
        )

    node_status = app_state.get_node_status(node_data)
    # Stored values of the wrong type read as absent (see node_metrics).
    caps = stored_capabilities(node_data.get("capabilities"))
    det_summary = stored_detection_summary(node_data.get("detection_summary")) or {}

    # Compute uptime
    registered_at = isoformat(node_data.get("registered_at"))
    last_seen = isoformat(node_data.get("last_seen"))
    uptime_seconds = caps.get("uptime_seconds")

    # Detection statistics from summary
    total_detections = det_summary.get("total_detections", 0)
    period_seconds = det_summary.get("period_seconds", 0)
    det_rate_per_min = (
        (total_detections / period_seconds * 60) if period_seconds > 0 else 0
    )
    class_counts = det_summary.get("class_counts", {})
    avg_confidence = det_summary.get("avg_confidence", 0)
    dominant_class = det_summary.get("dominant_class", "")
    dominant_family = det_summary.get("dominant_family", "")

    # Top signal classes (sorted by count descending)
    sorted_classes = sorted(class_counts.items(), key=lambda x: x[1], reverse=True)
    top_classes = [{"class": c, "count": n} for c, n in sorted_classes[:10]]

    # SDR hardware info
    sdr_info = {
        "type": caps.get("hardware") or caps.get("device_type") or "Unknown",
        "capture_mode": caps.get("capture_mode", ""),
        "serial": caps.get("device_serial", ""),
        "firmware": caps.get("firmware_version", ""),
        "sample_rate": caps.get("sample_rate", 0),
        "freq_range_min": caps.get("freq_range_min", 0),
        "freq_range_max": caps.get("freq_range_max", 0),
    }

    # System info
    system_info = {
        "cpu_percent": stored_metric(node_data, "cpu_percent"),
        "memory_mb": stored_metric(node_data, "memory_mb"),
        "disk_percent": caps.get("disk_percent"),
        "cpu_temp": caps.get("cpu_temp"),
        "load_1m": caps.get("load_1m"),
        "os": caps.get("os", ""),
        "platform": caps.get("platform") or caps.get("board_model", ""),
        "python_version": caps.get("python_version", ""),
        "agent_version": caps.get("agent_version", ""),
        "model": caps.get("model", ""),
        "accelerator": caps.get("gpu") or caps.get("accelerator", ""),
    }

    # Active scanners
    scanners = []
    if caps.get("anomaly_enabled"):
        scanners.append(
            {
                "name": "RF Anomaly",
                "status": caps.get("anomaly_baseline", "active"),
                "count": caps.get("anomaly_count", 0),
            }
        )
    scan_count = caps.get("scan_count")
    if scan_count is not None:
        scanners.append(
            {
                "name": "RF Scanner",
                "status": "active" if node_status.value == "active" else "idle",
                "count": scan_count,
            }
        )

    # Recent errors from audit log (filter for this node)
    recent_errors: list[dict[str, Any]] = []
    try:
        errors = await asyncio.to_thread(
            store.get_audit_log,
            limit=20,
            node_id=node_id,
        )
        recent_errors = errors
    except Exception:
        pass

    # Pending commands
    pending = app_state.pending_commands.get(node_id, [])

    # Network latency placeholder (from heartbeat round-trip if tracked)
    latency_ms = stored_number(caps.get("heartbeat_latency_ms"))

    # Health assessment
    health = "green"
    health_issues: list[str] = []
    cpu = stored_metric(node_data, "cpu_percent")
    if cpu is not None and cpu > 90:
        health = "red"
        health_issues.append("CPU usage critical: " + str(round(cpu, 1)) + "%")
    elif cpu is not None and cpu > 75:
        if health != "red":
            health = "yellow"
        health_issues.append("CPU usage elevated: " + str(round(cpu, 1)) + "%")
    mem = stored_metric(node_data, "memory_mb")
    if mem is not None and mem > 3500:
        if health != "red":
            health = "yellow"
        health_issues.append("High memory usage: " + str(round(mem)) + " MB")
    temp = caps.get("cpu_temp")
    if temp is not None and temp > 80:
        health = "red"
        health_issues.append("CPU temperature critical: " + str(round(temp)) + " C")
    elif temp is not None and temp > 70:
        if health != "red":
            health = "yellow"
        health_issues.append("CPU temperature elevated: " + str(round(temp)) + " C")
    if node_status.value != "active":
        # Offline is red; stale/unknown is yellow but never hides a critical
        # metric (like every check above, it does not downgrade red).
        if node_status.value == "offline":
            health = "red"
        elif health != "red":
            health = "yellow"
        health_issues.append("Node status: " + node_status.value)

    return {
        "node_id": node_id,
        "status": node_status.value,
        "health": health,
        "health_issues": health_issues,
        "registered_at": registered_at,
        "last_seen": last_seen,
        "uptime_seconds": uptime_seconds,
        "system_info": system_info,
        "sdr_info": sdr_info,
        "detection_stats": {
            "total_detections": total_detections,
            "rate_per_min": round(det_rate_per_min, 2),
            "avg_confidence": round(avg_confidence, 3),
            "dominant_class": dominant_class,
            "dominant_family": dominant_family,
            "class_counts": class_counts,
            "top_classes": top_classes,
            "period_seconds": period_seconds,
        },
        "scanners": scanners,
        "recent_errors": recent_errors,
        "pending_commands": pending,
        "latency_ms": latency_ms,
        "capabilities": caps,
    }


# ---------------------------------------------------------------------------
# Alert Management
# ---------------------------------------------------------------------------


@router.get("/alerts")
async def list_alerts(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> list[dict[str, Any]]:
    """List all alert rules."""
    persistence = request.app.state.persistence
    return persistence.get_alerts()


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
async def create_alert_rule(
    body: CreateAlertRuleRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Create an alert rule."""
    import html as _html

    persistence = request.app.state.persistence
    app_state: AppState = request.app.state.app_state
    store = _get_detection_store(request)

    alert = {
        "alert_id": app_state.next_alert_id(),
        "name": _html.escape(body.name),
        "severity": body.severity,
        "message": _html.escape(body.message) if body.message else "",
        "node_id": body.node_id or "",
        "thresholds": body.thresholds,
        "conditions": body.conditions,
        "enabled": body.enabled,
        "cooldown_seconds": body.cooldown_seconds,
        "notify_webhook": body.notify_webhook,
        "triggered_at": _utcnow().isoformat(),
        "acknowledged": False,
        "acknowledged_at": None,
    }

    persistence.add_alert(alert)

    store.log_audit(
        action="admin_create_alert",
        target_id=alert["alert_id"],
        operator=_master,
        details={"name": body.name, "severity": body.severity},
    )

    return alert


@router.put("/alerts/{alert_id}")
async def update_alert_rule(
    alert_id: str,
    body: UpdateAlertRuleRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update an alert rule."""
    import html as _html

    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    patch = body.model_dump(exclude_none=True)
    for field in ("name", "message"):
        if field in patch:
            patch[field] = _html.escape(patch[field])
    result = persistence.update_alert(alert_id, patch)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id!r} not found",
        )
    target, changes = result

    store.log_audit(
        action="admin_update_alert",
        target_id=alert_id,
        operator=_master,
        details={"changes": changes} if changes else None,
    )

    return target


@router.delete("/alerts/{alert_id}")
async def delete_alert_rule(
    alert_id: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Delete an alert rule."""
    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    if not persistence.delete_alert(alert_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert {alert_id!r} not found",
        )

    store.log_audit(
        action="admin_delete_alert",
        target_id=alert_id,
        operator=_master,
    )

    return {"status": "ok", "deleted": alert_id}


# ---------------------------------------------------------------------------
# Audit Log
# ---------------------------------------------------------------------------


@router.get("/audit")
async def get_audit_log(
    request: Request,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    action: str | None = Query(None),
    operator: str | None = Query(None),
    node_id: str | None = Query(None),
    target_id: str | None = Query(None),
    search: str | None = Query(None, description="Search in note, target_id, action"),
    start: str | None = Query(None, description="ISO 8601 start datetime"),
    end: str | None = Query(None, description="ISO 8601 end datetime"),
    severity: str = Query(
        "", description="Filter by severity (info, warning, critical)"
    ),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Paginated audit log viewer with filtering."""
    store = _get_detection_store(request)
    import asyncio

    sev = severity if severity else None
    entries, total = await asyncio.gather(
        asyncio.to_thread(
            store.get_audit_log,
            limit=limit,
            offset=offset,
            action=action,
            operator=operator,
            node_id=node_id,
            target_id=target_id,
            search=search,
            start=start,
            end=end,
            severity=sev,
        ),
        asyncio.to_thread(
            store.count_audit_log,
            action=action,
            target_id=target_id,
            operator=operator,
            node_id=node_id,
            search=search,
            start=start,
            end=end,
            severity=sev,
        ),
    )

    return {
        "count": len(entries),
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": entries,
    }


@router.get("/audit/actions")
async def get_audit_actions(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> list[str]:
    """Return distinct action types for filter dropdown."""
    store = _get_detection_store(request)
    import asyncio

    return await asyncio.to_thread(store.get_audit_actions)


@router.get("/audit/filters")
async def get_audit_filters(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, list[str]]:
    """Return distinct values for audit filter dropdowns."""
    store = _get_detection_store(request)
    import asyncio

    actions, operators, node_ids = await asyncio.gather(
        asyncio.to_thread(store.get_audit_actions),
        asyncio.to_thread(store.get_audit_operators),
        asyncio.to_thread(store.get_audit_node_ids),
    )
    return {
        "actions": actions,
        "operators": operators,
        "node_ids": node_ids,
    }


@router.get("/audit/verify")
async def verify_audit_chain(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Verify the HMAC chain integrity of the audit log.

    Walks all audit entries in order and validates each entry's HMAC
    against its predecessor.  Returns ``valid: true`` when the chain
    is intact, or a list of errors identifying tampered/missing entries.
    """
    import asyncio

    store = _get_detection_store(request)
    result = await asyncio.to_thread(store.verify_audit_chain)
    return result


# ---------------------------------------------------------------------------
# Log Viewer
# ---------------------------------------------------------------------------


@router.get("/logs")
async def get_logs(
    request: Request,
    limit: int = Query(200, ge=1, le=2000),
    level: str | None = Query(
        None, description="Filter by level: DEBUG, INFO, WARNING, ERROR"
    ),
    logger_name: str | None = Query(
        None, alias="logger", description="Filter by logger name"
    ),
    search: str | None = Query(None, description="Search in log messages"),
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Return recent log entries from the in-memory ring buffer."""
    from sigrift.bridge.log_buffer import get_log_buffer

    buf = get_log_buffer()
    entries = buf.get_entries(
        limit=limit, level=level, search=search, logger_name=logger_name
    )
    return {
        "count": len(entries),
        "total_buffered": buf.size(),
        "loggers": buf.get_loggers(),
        "entries": entries,
    }


# ---------------------------------------------------------------------------
# Syslog Forwarding
# ---------------------------------------------------------------------------


class CreateSyslogTargetRequest(BaseModel):
    model_config = {"extra": "forbid"}
    host: str
    port: int = Field(default=514, ge=1, le=65535)
    protocol: str = "udp"
    facility: str = "local0"
    severity_filter: list[str] = Field(default_factory=lambda: ["critical", "warning"])
    signal_class_filter: list[str] = Field(default_factory=list)
    node_filter: list[str] = Field(default_factory=list)
    freq_min_hz: float | None = None
    freq_max_hz: float | None = None
    rule_name_filter: list[str] = Field(default_factory=list)
    tls_ca_bundle: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None


class UpdateSyslogTargetRequest(BaseModel):
    model_config = {"extra": "forbid"}
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = None
    facility: str | None = None
    enabled: bool | None = None
    severity_filter: list[str] | None = None
    signal_class_filter: list[str] | None = None
    node_filter: list[str] | None = None
    freq_min_hz: float | None = None
    freq_max_hz: float | None = None
    rule_name_filter: list[str] | None = None
    tls_ca_bundle: str | None = None
    tls_client_cert: str | None = None
    tls_client_key: str | None = None


@router.get("/syslog")
async def list_syslog_targets(
    request: Request,
    _key_id: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """List all configured syslog forwarding targets."""
    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is None:
        return {"targets": []}
    return {"targets": syslog_fwd.targets}


@router.post("/syslog", status_code=status.HTTP_201_CREATED)
async def create_syslog_target(
    body: CreateSyslogTargetRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Create a new syslog forwarding target."""

    from sigrift.bridge.syslog_forwarder import FACILITY_MAP

    # Validate protocol
    protocol = body.protocol.lower()
    if protocol not in ("udp", "tcp", "tls"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Protocol must be one of: udp, tcp, tls",
        )

    # Validate facility
    if body.facility not in FACILITY_MAP:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid syslog facility: {}".format(body.facility),
        )

    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Syslog forwarder not initialized",
        )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)

    target = syslog_fwd.add_target(
        host=body.host,
        port=body.port,
        protocol=protocol,
        facility=body.facility,
        severity_filter=body.severity_filter,
        signal_class_filter=body.signal_class_filter,
        node_filter=body.node_filter,
        freq_min_hz=body.freq_min_hz,
        freq_max_hz=body.freq_max_hz,
        rule_name_filter=body.rule_name_filter,
        tls_ca_bundle=body.tls_ca_bundle,
        tls_client_cert=body.tls_client_cert,
        tls_client_key=body.tls_client_key,
    )

    # Persist
    persistence.set_syslog_targets(syslog_fwd.targets)

    store.log_audit(
        action="admin_create_syslog_target",
        target_id=target["id"],
        operator=_master,
        details={"host": body.host, "port": body.port, "protocol": protocol},
    )

    logger.info(
        "Syslog target created: %s -> %s:%d/%s",
        target["id"],
        body.host,
        body.port,
        protocol,
    )

    return target


@router.put("/syslog/{target_id}")
async def update_syslog_target(
    target_id: str,
    body: UpdateSyslogTargetRequest,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Update a syslog forwarding target."""
    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Syslog forwarder not initialized",
        )

    # Build update dict from non-None fields
    updates: dict[str, Any] = {}
    for field_name in (
        "host",
        "port",
        "protocol",
        "facility",
        "enabled",
        "severity_filter",
        "signal_class_filter",
        "node_filter",
        "freq_min_hz",
        "freq_max_hz",
        "rule_name_filter",
        "tls_ca_bundle",
        "tls_client_cert",
        "tls_client_key",
    ):
        val = getattr(body, field_name, None)
        if val is not None:
            updates[field_name] = val

    # Validate protocol if provided
    if "protocol" in updates:
        updates["protocol"] = updates["protocol"].lower()
        if updates["protocol"] not in ("udp", "tcp", "tls"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Protocol must be one of: udp, tcp, tls",
            )

    result = syslog_fwd.update_target(target_id, updates)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Syslog target {} not found".format(target_id),
        )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    persistence.set_syslog_targets(syslog_fwd.targets)

    store.log_audit(
        action="admin_update_syslog_target",
        target_id=target_id,
        operator=_master,
        details={"updates": list(updates.keys())},
    )

    return result


@router.delete("/syslog/{target_id}")
async def delete_syslog_target(
    target_id: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Delete a syslog forwarding target."""
    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Syslog forwarder not initialized",
        )

    if not syslog_fwd.remove_target(target_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Syslog target {} not found".format(target_id),
        )

    persistence = request.app.state.persistence
    store = _get_detection_store(request)
    persistence.set_syslog_targets(syslog_fwd.targets)

    store.log_audit(
        action="admin_delete_syslog_target",
        target_id=target_id,
        operator=_master,
    )

    return {"status": "ok", "deleted": target_id}


@router.post("/syslog/{target_id}/test")
async def test_syslog_target(
    target_id: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict[str, Any]:
    """Send a test message to a syslog target."""
    import asyncio

    syslog_fwd = getattr(request.app.state, "syslog_forwarder", None)
    if syslog_fwd is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Syslog forwarder not initialized",
        )

    target = syslog_fwd.get_target(target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Syslog target {} not found".format(target_id),
        )

    result = await asyncio.to_thread(syslog_fwd.send_test, target_id)

    # Persist updated delivery counts
    persistence = request.app.state.persistence
    persistence.set_syslog_targets(syslog_fwd.targets)

    store = _get_detection_store(request)
    store.log_audit(
        action="admin_test_syslog_target",
        target_id=target_id,
        operator=_master,
        details={"result": result.get("status", "unknown")},
    )

    return result


# ---------------------------------------------------------------------------
# Runtime configuration toggles
# ---------------------------------------------------------------------------


@router.get("/runtime-config")
async def get_runtime_config(
    _master: str = Depends(_admin_rate_limit),
) -> dict:
    """Get runtime configuration flags."""
    import resource as _resource

    try:
        _soft, _hard = _resource.getrlimit(_resource.RLIMIT_AS)
        mem_limit = _soft // (1024 * 1024) if _soft > 0 else 0
    except Exception:
        mem_limit = 0

    # Current RSS
    try:
        import psutil

        proc = psutil.Process()
        rss_mb = proc.memory_info().rss // (1024 * 1024)
    except ImportError:
        rss_mb = 0

    return {
        "BRIDGE_SKIP_INTEGRITY_CHECK": os.environ.get(
            "BRIDGE_SKIP_INTEGRITY_CHECK", ""
        ),
        "BRIDGE_LOG_LEVEL": os.environ.get("BRIDGE_LOG_LEVEL", "INFO"),
        "BRIDGE_BACKGROUND_TASKS": os.environ.get("BRIDGE_BACKGROUND_TASKS", "true"),
        "BRIDGE_MEMORY_LIMIT_MB": os.environ.get("BRIDGE_MEMORY_LIMIT_MB", "4096"),
        "BRIDGE_CLEANUP_INTERVAL": os.environ.get("BRIDGE_CLEANUP_INTERVAL", "1800"),
        "BRIDGE_MATERIALIZER_INTERVAL": os.environ.get(
            "BRIDGE_MATERIALIZER_INTERVAL", "300"
        ),
        "BRIDGE_WAL_CHECKPOINT_INTERVAL": os.environ.get(
            "BRIDGE_WAL_CHECKPOINT_INTERVAL", "1800"
        ),
        "BRIDGE_STALE_RESOLVE_INTERVAL": os.environ.get(
            "BRIDGE_STALE_RESOLVE_INTERVAL", "600"
        ),
        "BRIDGE_BASELINE_SAVE_INTERVAL": os.environ.get(
            "BRIDGE_BASELINE_SAVE_INTERVAL", "900"
        ),
        # Read-only: applied once at first boot, not runtime-settable.
        "SIGRIFT_PRESET": os.environ.get("SIGRIFT_PRESET", ""),
        "_current_rss_mb": rss_mb,
        "_memory_limit_mb": mem_limit,
    }


@router.put("/runtime-config/{key}")
async def set_runtime_config(
    key: str,
    request: Request,
    _master: str = Depends(_admin_rate_limit),
) -> dict:
    """Set a configuration variable in this bridge process's environment.

    Not persisted: settings read at start-up keep their old value until a
    restart, and a restart goes back to the value from the deployment
    environment (``.env`` / compose).  The response says so; set the
    variable there to make a change permanent.
    """
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Body must be JSON: {"value": ...}',
        ) from None
    if not isinstance(body, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Body must be a JSON object: {"value": ...}',
        )
    raw_value = body.get("value", "")
    if isinstance(raw_value, bool):
        raw_value = "true" if raw_value else "false"
    if not isinstance(raw_value, (str, int, float)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="value must be a string, number or boolean",
        )
    value = str(raw_value)
    if len(value) > 256 or any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="value must be at most 256 printable characters",
        )

    allowed_keys = {
        "BRIDGE_SKIP_INTEGRITY_CHECK",
        "BRIDGE_LOG_LEVEL",
        "BRIDGE_BACKGROUND_TASKS",
        "BRIDGE_MEMORY_LIMIT_MB",
        "BRIDGE_CLEANUP_INTERVAL",
        "BRIDGE_MATERIALIZER_INTERVAL",
        "BRIDGE_WAL_CHECKPOINT_INTERVAL",
        "BRIDGE_STALE_RESOLVE_INTERVAL",
        "BRIDGE_BASELINE_SAVE_INTERVAL",
    }
    if key not in allowed_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Key {key!r} not configurable. Allowed: {sorted(allowed_keys)}",
        )

    os.environ[key] = value
    logger.info("Runtime config set: %s=%s by %s", key, value, _master)
    try:
        _get_detection_store(request).log_audit(
            action="admin_set_runtime_config",
            target_id=key,
            operator=_master,
            details={"value": value, "persisted": False},
        )
    except Exception:
        logger.warning("Failed to audit runtime config change of %s", key)
    return {
        "key": key,
        "value": value,
        "persisted": False,
        "note": (
            "Set in this bridge process only and not saved: values read at "
            "start-up are unaffected until a restart, and a restart reverts "
            "to the deployment environment (.env / docker compose). Set it "
            "there to make the change permanent."
        ),
    }
