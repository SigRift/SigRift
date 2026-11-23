"""MFA (Multi-Factor Authentication) router for The Bridge.

Provides TOTP MFA setup, verification, disable, and two-step login
endpoints.  Also includes admin endpoints for tenant MFA enforcement
and per-user MFA management.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from sigrift.lib.security.credentials import hash_credential
from sigrift.bridge.dependencies import (
    SCOPE_PASSWORD_CHANGE_ONLY,
    Role,
    require_api_key,
)
from sigrift.bridge.security.totp import (
    generate_backup_codes,
    generate_secret,
    get_provisioning_uri,
    verify_totp,
)
from sigrift.bridge.storage.users import CredentialChangedError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TOTP replay-prevention — DB-backed (TD-3)
# ---------------------------------------------------------------------------
# Moved from in-memory dict to SecurityStateStore for persistence across
# process restarts.

# Backward-compat stub: test files import this for cleanup.
# Real state is in SQLite — this is an inert dict kept to avoid import errors.
_used_totp_codes: dict = {}

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_backup_codes(codes: list[str]) -> list[tuple[str, bytes]]:
    """PBKDF2-hash each backup code (blocking: ~0.3 s per code).

    Called via ``asyncio.to_thread`` — ten codes would otherwise stall the
    event loop for seconds.
    """
    return [hash_credential(c.strip().lower()) for c in codes]


def _get_store(request: Request):
    """Retrieve DetectionStore from app state."""
    store = getattr(request.app.state, "detection_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )
    return store


def _require_session_user(request: Request) -> dict[str, Any]:
    """Require a session-authenticated user. Returns the full user record."""
    auth_user = getattr(request.state, "auth_user", None)
    if not auth_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session authentication required for MFA operations",
        )
    store = _get_store(request)
    user = store.users.get_user_full(auth_user)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


def _require_admin(request: Request) -> None:
    """Raise 403 if caller is not admin."""
    role = getattr(request.state, "key_role", Role.VIEWER)
    if role < Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    backup_codes: list[str]


class MFAVerifySetupRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)


class MFAVerifyLoginRequest(BaseModel):
    mfa_token: str = Field(..., min_length=1)
    totp_code: str = Field(..., min_length=1, max_length=8)


class MFADisableRequest(BaseModel):
    totp_code: str = Field(default="", max_length=8)
    backup_code: str = Field(default="", max_length=16)


class TenantMFARequest(BaseModel):
    mfa_required: bool


# ---------------------------------------------------------------------------
# MFA Setup endpoints
# ---------------------------------------------------------------------------


@router.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> MFASetupResponse:
    """Generate a TOTP secret for MFA setup.

    User must be logged in with a session.  Returns the secret,
    provisioning URI for QR codes, and backup codes.
    """
    user = _require_session_user(request)

    if user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled. Disable it first to re-setup.",
        )

    secret = generate_secret()
    uri = get_provisioning_uri(secret, user["username"])
    backup_codes = generate_backup_codes()

    store = _get_store(request)

    # Store secret temporarily (not yet enabled until verify-setup)
    store.users.set_totp_secret(user["id"], secret)

    # Store PBKDF2-hashed backup codes (hash, salt tuples)
    code_hashes = await asyncio.to_thread(_hash_backup_codes, backup_codes)
    store.users.store_backup_codes(user["id"], code_hashes)

    logger.info("MFA setup initiated for user: %s", user["username"])

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=uri,
        backup_codes=backup_codes,
    )


@router.post("/auth/mfa/verify-setup")
async def mfa_verify_setup(
    request: Request,
    body: MFAVerifySetupRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Confirm MFA setup by verifying the first TOTP code.

    If the code is valid, MFA is enabled on the user account.
    """
    user = _require_session_user(request)

    if user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enabled",
        )

    secret = user.get("totp_secret")
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No MFA setup in progress. Call /auth/mfa/setup first.",
        )

    if not verify_totp(secret, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code. Check your authenticator app and try again.",
        )

    # Note: verify-setup does not use the replay cache — it's a one-time
    # enrollment step, not a login.  Replay protection applies to login
    # verification and MFA disable only.

    store = _get_store(request)
    store.users.enable_mfa(user["id"])

    store.log_audit(
        action="mfa_enable",
        target_id=user["username"],
        operator=user["username"],
    )

    logger.info("MFA enabled for user: %s", user["username"])

    return {
        "status": "mfa_enabled",
        "backup_codes_remaining": store.users.get_backup_code_count(user["id"]),
    }


@router.post("/auth/mfa/disable")
async def mfa_disable(
    request: Request,
    body: MFADisableRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, str]:
    """Disable MFA on the current user's account.

    Requires either a valid TOTP code or a backup code.
    """
    user = _require_session_user(request)

    if not user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    store = _get_store(request)
    secret = user.get("totp_secret", "")
    sec = store.security_state

    # Verify via TOTP code
    verified = False
    if body.totp_code and secret:
        if sec.is_totp_reused(user["username"], body.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code already used. Wait for a new code.",
            )
        verified = verify_totp(secret, body.totp_code)
        if verified:
            sec.record_totp_use(user["username"], body.totp_code)

    # Verify via backup code
    if not verified and body.backup_code:
        verified = await asyncio.to_thread(
            store.users.verify_backup_code,
            user["id"],
            body.backup_code.strip().lower(),
        )

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code or backup code",
        )

    store.users.disable_mfa(user["id"])

    store.log_audit(
        action="mfa_disable",
        target_id=user["username"],
        operator=user["username"],
    )

    logger.info("MFA disabled for user: %s", user["username"])

    return {"status": "mfa_disabled"}


# ---------------------------------------------------------------------------
# Backup code regeneration
# ---------------------------------------------------------------------------


class MFARegenCodesRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)


@router.post("/auth/mfa/regenerate-backup-codes")
async def mfa_regenerate_backup_codes(
    request: Request,
    body: MFARegenCodesRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Regenerate backup codes for the current user.

    Requires MFA to be enabled and a valid TOTP code. Replaces all
    existing backup codes with fresh ones.
    """
    user = _require_session_user(request)

    if not user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    secret = user.get("totp_secret", "")
    store = _get_store(request)
    sec = store.security_state

    if sec.is_totp_reused(user["username"], body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOTP code already used. Wait for a new code.",
        )

    if not verify_totp(secret, body.totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code",
        )

    sec.record_totp_use(user["username"], body.totp_code)

    backup_codes = generate_backup_codes()
    code_hashes = await asyncio.to_thread(_hash_backup_codes, backup_codes)
    store.users.store_backup_codes(user["id"], code_hashes)

    store.log_audit(
        action="mfa_regenerate_backup_codes",
        target_id=user["username"],
        operator=user["username"],
    )

    logger.info("Backup codes regenerated for user: %s", user["username"])

    return {
        "status": "backup_codes_regenerated",
        "backup_codes": backup_codes,
        "backup_codes_remaining": len(backup_codes),
    }


# ---------------------------------------------------------------------------
# Two-step login MFA verification
# ---------------------------------------------------------------------------


@router.post("/auth/mfa/verify")
async def mfa_verify_login(
    request: Request,
    response: Response,
    body: MFAVerifyLoginRequest,
) -> dict[str, Any]:
    """Complete two-step MFA login by verifying a TOTP code.

    After initial password authentication returns ``mfa_required: true``,
    the client must call this endpoint with the ``mfa_token`` and a
    ``totp_code`` (or backup code) to receive a session token.
    """
    store = _get_store(request)

    # Claim the MFA token: the credential its password step verified, which
    # the session below is bound to.
    credential = store.users.claim_mfa_token(body.mfa_token)
    if credential is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )
    user_id = credential.user_id

    user = store.users.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    # Disabled after the password step: the challenge above is consumed, but
    # no code is checked (no backup code burnt), no session and no success
    # audit.  The detail is the gateway's, so it does not say "disabled".
    if not user.get("enabled"):
        logger.info("MFA login refused for disabled user id %s", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    secret = user.get("totp_secret", "")
    username = user.get("username", f"uid:{user_id}")
    sec = store.security_state

    # Try TOTP verification first
    verified = False
    if secret and len(body.totp_code) == 6:
        if sec.is_totp_reused(username, body.totp_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="TOTP code already used. Wait for a new code.",
            )
        verified = verify_totp(secret, body.totp_code)
        if verified:
            sec.record_totp_use(username, body.totp_code)

    # Try as backup code if TOTP didn't work
    if not verified:
        verified = await asyncio.to_thread(
            store.users.verify_backup_code,
            user_id,
            body.totp_code.strip().lower(),
        )

    if not verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code or backup code",
        )

    # Create session — restricted to the password change when the user
    # must change their password (contract K3), like the password login —
    # only while the password the challenge proved is still stored: a reset
    # or disable committed during the second-factor check refuses it.
    from sigrift.bridge.routers.auth import (
        _get_client_ip,
        _issue_session,
        _set_csrf_cookie,
    )

    ip = _get_client_ip(request)
    try:
        session, scope, _mfa_setup = _issue_session(
            request, store, credential, user["username"], ip
        )
    except CredentialChangedError:
        logger.warning(
            "MFA login refused for %s: the password changed or the account "
            "was disabled while it ran",
            user["username"],
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    store.log_audit(
        action="user_login_mfa",
        target_id=user["username"],
        operator=user["username"],
        note=f"MFA login from {ip}" + (f" (session scope {scope})" if scope else ""),
    )

    logger.info("MFA login completed for user: %s", user["username"])

    return {
        "session_token": session["session_token"],
        "expires_at": session["expires_at"],
        "csrf_token": _set_csrf_cookie(request, response),
        "user": {
            "username": user["username"],
            "role": user["role"],
            "display_name": user.get("display_name", ""),
        },
        "password_change_required": scope == SCOPE_PASSWORD_CHANGE_ONLY,
    }


# ---------------------------------------------------------------------------
# Admin MFA management
# ---------------------------------------------------------------------------


@router.put("/admin/settings/mfa")
async def set_tenant_mfa(
    request: Request,
    body: TenantMFARequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Set tenant-level MFA enforcement (admin only).

    When mfa_required is true, all users in the tenant must set up MFA
    before accessing other endpoints.
    """
    _require_admin(request)

    store = _get_store(request)
    tenant_id = store._ctx.tenant_id

    store.users.set_tenant_mfa_required(tenant_id, body.mfa_required)

    operator = getattr(request.state, "auth_user", key_id)
    store.log_audit(
        action="tenant_mfa_policy_change",
        target_id=tenant_id,
        operator=operator,
        note=f"MFA required: {body.mfa_required}",
    )

    logger.info(
        "Tenant %s MFA policy changed to %s by %s",
        tenant_id,
        body.mfa_required,
        operator,
    )

    return {
        "tenant_id": tenant_id,
        "mfa_required": body.mfa_required,
    }


@router.get("/admin/settings/mfa")
async def get_tenant_mfa(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get tenant-level MFA enforcement setting (admin only)."""
    _require_admin(request)

    store = _get_store(request)
    tenant_id = store._ctx.tenant_id
    required = store.users.get_tenant_mfa_required(tenant_id)

    return {
        "tenant_id": tenant_id,
        "mfa_required": required,
    }


@router.post("/admin/users/{username}/disable-mfa")
async def admin_disable_user_mfa(
    request: Request,
    username: str,
    key_id: str = Depends(require_api_key),
) -> dict[str, str]:
    """Admin disables MFA for a specific user (no TOTP code required)."""
    _require_admin(request)

    store = _get_store(request)
    user = store.users.get_user_full(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )

    if not user.get("mfa_enabled"):
        return {"status": "mfa_not_enabled", "username": username}

    store.users.disable_mfa(user["id"])

    operator = getattr(request.state, "auth_user", key_id)
    store.log_audit(
        action="admin_disable_mfa",
        target_id=username,
        operator=operator,
        note="MFA disabled by admin",
    )

    logger.info("Admin %s disabled MFA for user: %s", operator, username)

    return {"status": "mfa_disabled", "username": username}
