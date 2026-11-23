"""Authentication and user management router for The Bridge.

Provides login/logout endpoints with session tokens, user info,
password management, and admin user CRUD.  Session auth works
alongside existing API key auth (backward compatible).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import (
    SCOPE_MFA_SETUP_ONLY,
    SCOPE_PASSWORD_CHANGE_ONLY,
    Role,
    _extract_session_token,
    get_client_ip,
    require_api_key,
)
from sigrift.bridge.instrumentation import get_tracer, trace_span
from sigrift.bridge.storage.users import (
    CredentialChangedError,
    SessionEndedError,
    VerifiedCredential,
)

logger = logging.getLogger(__name__)
_tracer = get_tracer(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Login rate limiting & account lockout — DB-backed (D-10, TD-1)
# ---------------------------------------------------------------------------
# These now delegate to SecurityStateStore for persistence across restarts.
# The in-memory dicts were replaced in Phase 2 tech-debt work.

# Backward-compat stubs: many test files import these for cleanup.
# Real state is in SQLite — these are inert dicts kept to avoid import errors.
_login_attempts: dict = {}
_account_failures: dict = {}
_ACCOUNT_LOCKOUT_MAX = 10
_ACCOUNT_LOCKOUT_WINDOW = 1800.0
_ACCOUNT_MAX_TRACKED = 10_000


def _check_login_rate(ip: str, store) -> None:
    """Raise 429 if login rate limit exceeded for this IP."""
    sec = store.security_state
    count = sec.count_recent_login_attempts(ip)
    if count >= sec.RATE_LIMIT_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
            headers={"Retry-After": "60"},
        )
    sec.record_login_attempt(ip)


def _account_locked() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Account temporarily locked due to too many failed attempts.",
        headers={"Retry-After": "1800"},
    )


def _check_account_lockout(username: str, store) -> None:
    """Raise 429 if account has too many recent failed login attempts.

    Read-only check.  The login handler uses :func:`_reserve_login_attempt`
    instead, which also records the attempt.
    """
    sec = store.security_state
    count = sec.count_recent_failures(username)
    if count >= sec.LOCKOUT_MAX:
        raise _account_locked()


def _reserve_login_attempt(username: str, store) -> None:
    """Count this login attempt against *username* before checking it.

    Raise 429 if the account is locked; otherwise record the attempt as a
    failure up front, in the same atomic step as the lockout check.  The
    password check then runs in a worker thread, and parallel attempts
    arriving meanwhile already see this one counted — recording the
    failure only after the check would let any number of concurrent
    guesses past ``LOCKOUT_MAX``.  A successful login clears it.
    """
    if not store.security_state.reserve_account_attempt(username):
        raise _account_locked()


# Backward-compat alias: mfa.py imports _get_client_ip from this module
_get_client_ip = get_client_ip


def _get_store(request: Request):
    """Retrieve DetectionStore from app state."""
    store = getattr(request.app.state, "detection_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready",
        )
    return store


# ---------------------------------------------------------------------------
# Issuing sessions (password login, MFA login, password change) — K3
# ---------------------------------------------------------------------------


def _tenant_requires_mfa_setup(store, user: dict[str, Any]) -> bool:
    """True if the user's tenant requires MFA and the user has none yet."""
    if user.get("mfa_enabled"):
        return False
    try:
        return bool(
            store.users.get_tenant_mfa_required(user.get("tenant_id") or "default")
        )
    except Exception as exc:
        # No tenant_settings table: no MFA policy was ever set.  (Matched
        # by message: sqlite3 and SQLCipher raise different classes.)
        if "no such table" in str(exc).lower():
            return False
        raise


def _session_scope_for(store, username: str) -> tuple[str, bool]:
    """Return ``(scope, mfa_setup_required)`` for a new session of *username*.

    A user flagged ``must_change_password`` gets a ``password_change_only``
    session (this wins); otherwise a user whose tenant requires MFA they
    have not set up gets ``mfa_setup_only``; otherwise a full session
    (``""``).  Errors propagate: a session is never issued with a scope
    that could not be determined.
    """
    user = store.users.get_user(username)
    if user is None:
        raise LookupError(f"user {username!r} not found")
    mfa_setup_required = _tenant_requires_mfa_setup(store, user)
    if user.get("must_change_password"):
        return SCOPE_PASSWORD_CHANGE_ONLY, mfa_setup_required
    if mfa_setup_required:
        return SCOPE_MFA_SETUP_ONLY, True
    return "", False


def _issue_session(
    request: Request,
    store,
    credential: VerifiedCredential,
    username: str,
    ip: str,
) -> tuple[dict[str, Any], str, bool]:
    """Create a login session with the scope :func:`_session_scope_for` picks.

    Returns ``(session, scope, mfa_setup_required)``.  Fails closed: when
    the scope cannot be determined or does not stick, no session is left
    behind and the caller gets 503 instead of a full-access session.

    The session is bound to *credential*, the password the request proved
    (the password step, the MFA token's claim, or a password change): it
    is created only while that is still the stored password of an enabled
    account, else :class:`CredentialChangedError` propagates and nothing
    is created.  The earlier steps (PBKDF2, the second factor) may have
    overlapped a password reset or change, or a disable.
    """
    unavailable = HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Login temporarily unavailable",
    )
    try:
        scope, mfa_setup_required = _session_scope_for(store, username)
    except Exception:
        logger.exception("Cannot determine the session scope for %s", username)
        raise unavailable
    session = store.create_session(
        user_id=credential.user_id,
        ip_address=ip,
        user_agent=request.headers.get("user-agent", ""),
        credential=credential,
    )
    if scope:
        token = session["session_token"]
        store.users.set_session_scope(token, scope=scope)
        stored = store.get_session(token)
        if stored is None or (stored.get("scope") or "") != scope:
            logger.error(
                "Could not restrict the new session of %s to %r — refusing it",
                username,
                scope,
            )
            store.delete_session(token)
            raise unavailable
    return session, scope, mfa_setup_required


def _set_csrf_cookie(request: Request, response: Response) -> str:
    """Set the CSRF double-submit cookie (SEC-H5) and return its value."""
    csrf_token = secrets.token_hex(32)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,  # Must be readable by JS
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )
    return csrf_token


def _expire_csrf_cookie(request: Request, response: Response) -> None:
    """Expire the CSRF cookie, with the attributes ``_set_csrf_cookie`` uses."""
    response.delete_cookie(
        key="csrf_token",
        httponly=False,
        samesite="strict",
        secure=request.url.scheme == "https",
        path="/",
    )


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class LoginResponse(BaseModel):
    session_token: str = ""
    expires_at: str = ""
    user: dict[str, Any] = {}
    mfa_required: bool = False
    mfa_token: str = ""
    mfa_setup_required: bool = False


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=128)


class CreateUserRequest(BaseModel):
    username: str = Field(
        ..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-\.]+$"
    )
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(default="viewer", pattern=r"^(viewer|analyst|admin)$")
    display_name: str = Field(default="", max_length=128)
    email: str = Field(default="", max_length=256)


class UpdateUserRequest(BaseModel):
    role: str | None = Field(default=None, pattern=r"^(viewer|analyst|admin)$")
    display_name: str | None = Field(default=None, max_length=128)
    email: str | None = Field(default=None, max_length=256)
    enabled: bool | None = None


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)


# ---------------------------------------------------------------------------
# Auth endpoints (no auth required for login)
# ---------------------------------------------------------------------------


@router.post("/auth/login")
async def login(
    request: Request, response: Response, body: LoginRequest
) -> dict[str, Any]:
    """Authenticate with username and password, receive a session token.

    If the user has MFA enabled, returns ``mfa_required: true`` with
    a short-lived ``mfa_token`` instead of a session.  The client must
    then call ``POST /api/auth/mfa/verify`` to complete login.

    If the tenant requires MFA but the user has not set it up, returns
    ``mfa_setup_required: true`` along with a session token (the session
    only grants access to MFA setup endpoints until MFA is configured).
    """
    ip = get_client_ip(request)
    store = _get_store(request)
    _check_login_rate(ip, store)
    _reserve_login_attempt(body.username, store)

    with trace_span(
        _tracer,
        "auth_login",
        attributes={
            "auth.username": body.username,
            "auth.client_ip": ip,
        },
    ) as _span:
        return await _login_inner(request, response, body, store, ip, _span)


def _password_changed_during_login(username: str, span) -> HTTPException:
    """The refusal of a login whose verified password is no longer stored.

    Logged as a warning, as the gateway logs it; like the gateway, no audit
    entry is written for it.
    """
    logger.warning(
        "Login refused for %s: the password changed or the account was "
        "disabled while it ran",
        username,
    )
    span.set_attribute("auth.result", "failure")
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid username or password",
    )


async def _login_inner(request, response, body, store, ip, span):
    # PBKDF2 (600k iterations) — keep it off the event loop.  The session
    # or MFA challenge below is bound to the credential this verified, so a
    # reset or change committed after the check refuses the login.
    credential = await asyncio.to_thread(
        store.verify_password_credential, body.username, body.password
    )
    if credential is None:
        # SEC-M6: the per-account failure (DB-backed via TD-1) was already
        # recorded by _reserve_login_attempt before the check.

        # SEC-M9: Audit-log failed auth attempt
        try:
            store.log_audit(
                action="auth_failure",
                target_id=body.username,
                operator="",
                note=f"Failed login attempt from {ip}",
            )
        except Exception:
            logger.warning("Failed to audit-log auth failure for %s", body.username)

        span.set_attribute("auth.result", "failure")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user_data = store.users.get_user_full(body.username)
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Clear account lockout on successful auth (DB-backed)
    store.security_state.clear_account_failures(body.username)

    # -- MFA enabled: two-step login flow -----------------------------------
    if user_data.get("mfa_enabled"):
        try:
            mfa_token = store.users.create_mfa_token(
                credential.user_id, credential=credential
            )
        except CredentialChangedError:
            raise _password_changed_during_login(body.username, span)

        store.log_audit(
            action="user_login_mfa_pending",
            target_id=body.username,
            operator=body.username,
            note=f"MFA required, token issued from {ip}",
        )

        logger.info(
            "MFA login step 1 completed for user: %s from %s", body.username, ip
        )
        span.set_attribute("auth.result", "mfa_required")

        return {
            "mfa_required": True,
            "mfa_token": mfa_token,
            "session_token": "",
            "expires_at": "",
            "user": {
                "username": user_data["username"],
                "role": user_data["role"],
                "display_name": user_data.get("display_name", ""),
            },
            "mfa_setup_required": False,
        }

    # -- Normal login (no MFA on user) --------------------------------------
    # The session is restricted (contract K3) to the password change when
    # the user must change their password — set by create_user(...,
    # must_change_password=True) for the auto-bootstrapped admin whose
    # generated password was written to a file — or to MFA setup when the
    # tenant requires MFA the user has not set up.
    try:
        session, scope, mfa_setup_required = _issue_session(
            request, store, credential, body.username, ip
        )
    except CredentialChangedError:
        raise _password_changed_during_login(body.username, span)
    password_change_required = scope == SCOPE_PASSWORD_CHANGE_ONLY

    # Log to audit trail
    store.log_audit(
        action="user_login",
        target_id=body.username,
        operator=body.username,
        note=f"Login from {ip}" + (f" (session scope {scope})" if scope else ""),
    )

    logger.info("User logged in: %s from %s", body.username, ip)
    span.set_attribute("auth.result", "success")

    csrf_token = _set_csrf_cookie(request, response)

    return {
        "session_token": session["session_token"],
        "expires_at": session["expires_at"],
        "csrf_token": csrf_token,
        "user": {
            "username": user_data["username"],
            "role": user_data["role"],
            "display_name": user_data.get("display_name", ""),
        },
        "mfa_required": False,
        "mfa_token": "",
        "mfa_setup_required": mfa_setup_required,
        "password_change_required": password_change_required,
    }


#: The cookies whose presence lets a logout 401 expire the CSRF cookie.
_LOGOUT_COOKIES = ("session_token", "csrf_token")


@router.post("/auth/logout")
async def logout(request: Request) -> JSONResponse:
    """Invalidate the current session token.

    The outcomes that leave the caller signed out expire the CSRF cookie,
    whose presence is what the pages read as "signed in": the session
    ended (200), and a 401 (no token, or one that names no session) when
    the request carried the session or CSRF cookie. A storage error keeps
    it, so a retry can still end the session. (The gateway's logout does
    the same for its cookies.)

    A 401 for a request that carried neither sets no cookie. Logout is
    CSRF-exempt, and a cross-site form post carries no SameSite cookie, so
    it lands here; browsers apply a top-level navigation's ``Set-Cookie``
    whatever its SameSite, so expiring the cookie on that 401 would let any
    page sign a visitor's dashboard out.
    """

    def signed_out(status_code: int, body: dict[str, str]) -> JSONResponse:
        response = JSONResponse(body, status_code=status_code)
        if status_code == status.HTTP_200_OK or any(
            name in request.cookies for name in _LOGOUT_COOKIES
        ):
            _expire_csrf_cookie(request, response)
        return response

    token = _extract_session_token(request)
    if not token:
        return signed_out(
            status.HTTP_401_UNAUTHORIZED, {"detail": "No session token provided"}
        )

    store = _get_store(request)

    # The owner of a valid session, for the audit entry. Read-only: a
    # session past its time limits or with unreadable times must still be
    # found by the delete below, so the logout ends it (200, audited) as the
    # gateway's logout ends any session row the token names.
    session = store.users.get_session(token, touch=False)
    username = session["username"] if session else "unknown"

    deleted = store.delete_session(token)
    if not deleted:
        return signed_out(
            status.HTTP_401_UNAUTHORIZED, {"detail": "Invalid or expired session"}
        )

    store.log_audit(
        action="user_logout",
        target_id=username,
        operator=username,
    )

    return signed_out(status.HTTP_200_OK, {"status": "logged_out"})


@router.get("/auth/me")
async def get_me(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Get current user info from session or API key."""
    # If session-authenticated, return user details
    auth_user = getattr(request.state, "auth_user", None)
    if auth_user:
        store = _get_store(request)
        user = store.get_user(auth_user)
        if user:
            mfa_enabled = bool(user.get("mfa_enabled"))
            backup_codes_remaining = 0
            if mfa_enabled:
                try:
                    backup_codes_remaining = store.users.get_backup_code_count(
                        user["id"]
                    )
                except Exception:
                    pass
            return {
                "auth_type": "session",
                "username": user["username"],
                "role": user["role"],
                "display_name": user["display_name"],
                "email": user["email"],
                "last_login": user["last_login"],
                "mfa_enabled": mfa_enabled,
                "backup_codes_remaining": backup_codes_remaining,
            }

    # API key authenticated
    role = getattr(request.state, "key_role", Role.VIEWER)
    return {
        "auth_type": "api_key",
        "key_id": key_id,
        "role": role.name.lower(),
    }


@router.post("/auth/change-password")
async def change_password(
    request: Request,
    body: ChangePasswordRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Change the current user's password (requires current password).

    Every session of the user is invalidated, and the caller gets a new
    session in the response (``session_token`` / ``expires_at``): a full
    one, or ``mfa_setup_only`` when the tenant requires MFA the user has
    not set up.  This is how a ``password_change_only`` session (K3) is
    lifted. If replacement-session issuance fails after the password and
    revocation commit, the completed response requires a fresh sign-in;
    the caller must not retry the change using the old password.

    Each attempt counts against the account lockout the login uses
    (:func:`_reserve_login_attempt`), so a wrong current password is a
    failed guess like a failed login: audited as ``auth_failure``, and
    once the account is locked every attempt (login or change) gets 429
    until the window passes.  A correct current password clears the count.

    The change commits only while the password it verified is still the
    stored one (401 ``Current password is incorrect`` otherwise), and its
    session still exists and the account is enabled (401 ``Not
    authenticated``): a reset or revocation committed while it ran wins.
    """
    auth_user = getattr(request.state, "auth_user", None)
    if not auth_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change requires session authentication",
        )

    store = _get_store(request)
    ip = get_client_ip(request)
    incorrect = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Current password is incorrect",
    )

    # Counted before the check, as the login counts (429 when locked).
    _reserve_login_attempt(auth_user, store)

    # Verify current password (PBKDF2: off the event loop)
    credential = await asyncio.to_thread(
        store.verify_password_credential, auth_user, body.current_password
    )
    if credential is None:
        # The failure was already recorded by _reserve_login_attempt.
        try:
            store.log_audit(
                action="auth_failure",
                target_id=auth_user,
                operator=auth_user,
                note=f"Failed password change attempt from {ip}",
            )
        except Exception:
            logger.warning("Failed to audit-log auth failure for %s", auth_user)
        raise incorrect

    store.security_state.clear_account_failures(auth_user)

    # Commit password, revocation and success audit together, only for the
    # state verified above. A failed audit must not report an error after
    # changing the password behind the caller.
    try:
        new_credential = await asyncio.to_thread(
            store.change_password_with_audit,
            auth_user,
            body.new_password,
            credential=credential,
            session_token=getattr(request.state, "session_token", None),
            action="password_change",
            operator=auth_user,
        )
    except CredentialChangedError:
        logger.warning(
            "Password change refused for %s: the password changed while it ran",
            auth_user,
        )
        raise incorrect
    except SessionEndedError:
        logger.warning(
            "Password change refused for %s: its session or account was "
            "revoked while it ran",
            auth_user,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    if new_credential is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )

    # Clear the forced-reset flag, if it was set. This is the only way
    # out of a `password_change_only`-scoped session.  If it cannot be
    # cleared the reissued session below is still restricted.
    try:
        store.users.clear_must_change_password(auth_user)
    except Exception:
        logger.warning(
            "Failed to clear must_change_password for %s",
            auth_user,
            exc_info=True,
        )

    # All previous sessions were invalidated in the password transaction.
    # Reissue one for this client (K3: the new session has
    # the scope the user now qualifies for — full, unless MFA setup is
    # still required), bound to the new password: a reset committed since
    # the change refuses it, and the caller signs in again.
    result: dict[str, Any] = {
        "status": "password_changed",
        "reauthentication_required": True,
    }
    try:
        user_data = store.users.get_user(auth_user)
        if user_data:
            session, scope, mfa_setup_required = _issue_session(
                request, store, new_credential, auth_user, ip
            )
            result = {
                "status": "password_changed",
                "session_token": session["session_token"],
                "expires_at": session["expires_at"],
                "mfa_setup_required": mfa_setup_required,
                "password_change_required": scope == SCOPE_PASSWORD_CHANGE_ONLY,
            }
    except Exception:
        logger.warning(
            "Password changed for %s; replacement session unavailable",
            auth_user,
            exc_info=True,
        )

    return result


# ---------------------------------------------------------------------------
# Admin user management endpoints
# ---------------------------------------------------------------------------


def _require_admin_session_or_key(request: Request, key_id: str) -> None:
    """Raise 403 if the caller is not an admin."""
    role = getattr(request.state, "key_role", Role.VIEWER)
    if role < Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required",
        )


@router.post("/admin/users")
async def create_user(
    request: Request,
    body: CreateUserRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Create a new user account (admin only)."""
    _require_admin_session_or_key(request, key_id)

    store = _get_store(request)

    try:
        # create_user hashes the password with PBKDF2: run it in a thread.
        user = await asyncio.to_thread(
            store.create_user,
            username=body.username,
            password=body.password,
            role=body.role,
            display_name=body.display_name,
            email=body.email,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )

    operator = getattr(request.state, "auth_user", key_id)
    store.log_audit(
        action="user_create",
        target_id=body.username,
        operator=operator,
        note=f"Created user with role={body.role}",
    )

    return user


@router.get("/admin/users")
async def list_users(
    request: Request,
    key_id: str = Depends(require_api_key),
) -> list[dict[str, Any]]:
    """List all user accounts (admin only)."""
    _require_admin_session_or_key(request, key_id)

    store = _get_store(request)
    return store.list_users()


@router.put("/admin/users/{username}")
async def update_user(
    request: Request,
    username: str,
    body: UpdateUserRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, Any]:
    """Update a user's role, display_name, email, or enabled status (admin only)."""
    _require_admin_session_or_key(request, key_id)

    store = _get_store(request)

    update_kwargs: dict[str, Any] = {}
    if body.role is not None:
        update_kwargs["role"] = body.role
    if body.display_name is not None:
        update_kwargs["display_name"] = body.display_name
    if body.email is not None:
        update_kwargs["email"] = body.email
    if body.enabled is not None:
        update_kwargs["enabled"] = body.enabled

    operator = getattr(request.state, "auth_user", key_id)
    try:
        user = store.update_user_with_audit(
            username,
            **update_kwargs,
            revoke_sessions=body.enabled is False,
            action="user_update",
            operator=operator,
            note=f"Updated: {list(update_kwargs.keys())}",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )

    return user


@router.delete("/admin/users/{username}")
async def delete_user(
    request: Request,
    username: str,
    key_id: str = Depends(require_api_key),
) -> dict[str, str]:
    """Disable a user account (soft delete, admin only)."""
    _require_admin_session_or_key(request, key_id)

    store = _get_store(request)

    # The audit shares the field-update/revocation transaction; an audit
    # failure leaves both the account and its prior sessions unchanged.
    operator = getattr(request.state, "auth_user", key_id)
    if (
        store.update_user_with_audit(
            username,
            enabled=False,
            revoke_sessions=True,
            action="user_disable",
            operator=operator,
        )
        is None
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )

    return {"status": "disabled", "username": username}


@router.post("/admin/users/{username}/reset-password")
async def reset_password(
    request: Request,
    username: str,
    body: ResetPasswordRequest,
    key_id: str = Depends(require_api_key),
) -> dict[str, str]:
    """Admin resets a user's password."""
    _require_admin_session_or_key(request, key_id)

    store = _get_store(request)

    operator = getattr(request.state, "auth_user", key_id)
    if not await asyncio.to_thread(
        store.set_password_with_audit,
        username,
        body.new_password,
        action="password_reset",
        operator=operator,
        note="Password reset by admin",
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found",
        )

    return {"status": "password_reset", "username": username}
