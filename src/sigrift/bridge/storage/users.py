"""User account and session management sub-store.

Provides persistent storage for user accounts with salted password
hashing and session tokens for login-based authentication.  Designed
to work alongside (not replace) existing API key auth.

Uses ``sigrift.lib.security.credentials`` for password hashing -- the same
constant-time verification used for API keys.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from time import monotonic
from typing import Any

from sigrift.lib.security.credentials import hash_credential, verify_credential
from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TOTP secret encryption helpers
# ---------------------------------------------------------------------------

_fernet_instance = None
_mfa_encryption_warned = False
_mfa_invalid_key_warned = False

#: Shell command that prints a valid ``BRIDGE_MFA_KEY`` (a Fernet key).
MFA_KEYGEN_HINT = (
    "python3 -c 'from cryptography.fernet import Fernet; "
    "print(Fernet.generate_key().decode())'"
)


def _is_production() -> bool:
    """Return True if the bridge is running in production mode.

    Checks ``BRIDGE_ENV`` and ``BRIDGE_MODE`` environment variables for
    values ``"production"`` or ``"prod"`` (case-insensitive).
    """
    for var in ("BRIDGE_ENV", "BRIDGE_MODE"):
        val = os.environ.get(var, "").strip().lower()
        if val in ("production", "prod"):
            return True
    return False


_FERNET_KEY_RE = re.compile(r"[A-Za-z0-9\-_+/]{43}=")
_LEGACY_UNPADDED_KEY_RE = re.compile(r"[A-Za-z0-9\-_]{43}")


def _decode_fernet_key(key: str) -> bytes | None:
    """Return the 32 key bytes of *key* under the canonical rule, or ``None``.

    The rule is shared with the Rust gateway and the installers: after
    trimming surrounding whitespace the key is exactly 44 characters, the
    first 43 from ``[A-Za-z0-9-_+/]`` (URL-safe and standard alphabets are
    both accepted, as ``cryptography``'s Fernet accepts them) and the 44th
    ``=``; it decodes, mapping ``-`` to ``+`` and ``_`` to ``/``, to exactly
    32 bytes.  Non-zero trailing bits in the 43rd character are ignored, as
    ``cryptography``'s Fernet (``urlsafe_b64decode``) and the gateway ignore
    them, so such a key means the same 32 bytes in every service.
    """
    key = key.strip()
    if not _FERNET_KEY_RE.fullmatch(key):
        return None
    std = key.replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(std, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def is_valid_fernet_key(key: str) -> bool:
    """Return True if *key* is a valid ``BRIDGE_MFA_KEY`` (canonical rule)."""
    return _decode_fernet_key(key) is not None


def is_repairable_mfa_key(key: str) -> bool:
    """Return True for an unpadded 43-character key fixed by appending ``=``.

    ``secrets.token_urlsafe(32)`` (what older installers generated) writes
    such keys; the old gateway accepted them and may have encrypted TOTP
    secrets with them, so appending ``=`` — which keeps the same 32 bytes —
    is the lossless repair.  Generating a new key would orphan those secrets.
    """
    key = key.strip()
    return bool(_LEGACY_UNPADDED_KEY_RE.fullmatch(key)) and is_valid_fernet_key(
        key + "="
    )


def mfa_key_problem(key: str | None = None) -> str | None:
    """Return why ``BRIDGE_MFA_KEY`` is unusable, or ``None`` if it is valid.

    *key* defaults to the current ``BRIDGE_MFA_KEY`` environment value.
    Validity follows the canonical rule in :func:`_decode_fernet_key`, the
    same one the gateway applies, so the two services never disagree about
    a key.  :func:`mfa_key_remedy` says how to fix an unusable key.
    """
    if key is None:
        key = os.environ.get("BRIDGE_MFA_KEY", "")
    key = key.strip()
    if not key:
        return "BRIDGE_MFA_KEY is not set"
    try:
        import cryptography.fernet  # noqa: F401
    except ImportError:
        return (
            "BRIDGE_MFA_KEY is set but the 'cryptography' package is not "
            "installed, so it cannot be used"
        )
    if is_repairable_mfa_key(key):
        return (
            "BRIDGE_MFA_KEY is not a valid Fernet key: it is 43 characters "
            "long, missing the trailing '=' padding"
        )
    if not is_valid_fernet_key(key):
        return (
            "BRIDGE_MFA_KEY is not a valid Fernet key: it must be 44 base64 "
            "characters ending in '=' that decode to 32 bytes"
        )
    return None


def mfa_key_remedy(key: str | None = None) -> str:
    """Return how to fix an unusable ``BRIDGE_MFA_KEY`` (see :func:`mfa_key_problem`).

    A 43-character key is repaired by appending ``=``, which keeps TOTP
    secrets already encrypted with it readable; any other invalid key is
    replaced by a newly generated one.
    """
    if key is None:
        key = os.environ.get("BRIDGE_MFA_KEY", "")
    if is_repairable_mfa_key(key):
        return (
            "append '=' to BRIDGE_MFA_KEY (keep the existing 43 characters) "
            "to keep existing encrypted TOTP secrets readable"
        )
    return f"generate a new key with: {MFA_KEYGEN_HINT}"


def _get_fernet():
    """Return a Fernet instance for TOTP secret encryption.

    Reads a Fernet key (32 bytes, URL-safe base64) from the
    ``BRIDGE_MFA_KEY`` environment variable.  If the variable is unset, or
    set to something that is not a valid Fernet key:

    * In **production** mode (``BRIDGE_ENV`` or ``BRIDGE_MODE`` set to
      ``"production"`` or ``"prod"``): raises ``RuntimeError`` so the
      service fails closed rather than silently degrading to base64.
    * In **development** mode (default): returns ``None`` and callers
      fall back to base64 encoding with a logged warning.
    """
    global _fernet_instance, _mfa_encryption_warned, _mfa_invalid_key_warned
    if _fernet_instance is not None:
        return _fernet_instance

    key = os.environ.get("BRIDGE_MFA_KEY", "").strip()
    if not key:
        if _is_production():
            raise RuntimeError(
                "BRIDGE_MFA_KEY is not set but the service is running in "
                "production mode (BRIDGE_ENV/BRIDGE_MODE). TOTP secrets "
                "cannot be stored without encryption in production. "
                f"Generate a key with: {MFA_KEYGEN_HINT}"
            )
        if not _mfa_encryption_warned:
            logger.warning(
                "BRIDGE_MFA_KEY not set — TOTP secrets stored with base64 "
                "encoding only (NOT encrypted). Set a Fernet key for "
                "production: %s",
                MFA_KEYGEN_HINT,
            )
            _mfa_encryption_warned = True
        return None

    problem = mfa_key_problem(key)
    if problem is not None:
        # Never encrypt (or decrypt) with a key that fails the canonical
        # rule: the gateway would not accept it.
        remedy = mfa_key_remedy(key)
        if _is_production():
            raise RuntimeError(
                f"{problem}. The service is running in production mode "
                "(BRIDGE_ENV/BRIDGE_MODE) and will not store TOTP secrets "
                f"unencrypted. To fix it, {remedy}"
            )
        if not _mfa_invalid_key_warned:
            logger.warning(
                "%s — TOTP secrets stored with base64 encoding only (NOT "
                "encrypted). To fix it, %s",
                problem,
                remedy,
            )
            _mfa_invalid_key_warned = True
        return None

    from cryptography.fernet import Fernet

    # Build Fernet from exactly the 32 bytes the canonical rule decoded, so
    # a standard-alphabet key ('+', '/') means the same key as in Rust.
    raw = _decode_fernet_key(key)
    _fernet_instance = Fernet(base64.urlsafe_b64encode(raw))
    return _fernet_instance


def _encrypt_totp_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret for storage.

    With Fernet: returns ``fernet:<ciphertext>``.
    Without: returns ``b64:<base64-encoded>`` (backwards compatible).
    """
    if plaintext is None:
        return None
    fernet = _get_fernet()
    if fernet is not None:
        token = fernet.encrypt(plaintext.encode("utf-8"))
        return "fernet:" + token.decode("utf-8")
    # Fallback: base64 — NOT secure, but preserves compatibility
    return "b64:" + base64.b64encode(plaintext.encode("utf-8")).decode("utf-8")


def _decrypt_totp_secret(stored: str) -> str:
    """Decrypt a TOTP secret from storage.

    Handles three formats:
    - ``fernet:<token>`` — decrypt with Fernet
    - ``b64:<encoded>`` — decode base64
    - anything else — treat as legacy plaintext (pre-migration)
    """
    if stored is None:
        return None
    if stored.startswith("fernet:"):
        fernet = _get_fernet()
        if fernet is None:
            raise ValueError(
                "TOTP secret is Fernet-encrypted but BRIDGE_MFA_KEY is not "
                "set to a valid Fernet key"
            )
        return fernet.decrypt(stored[7:].encode("utf-8")).decode("utf-8")
    if stored.startswith("b64:"):
        return base64.b64decode(stored[4:]).decode("utf-8")
    # Legacy plaintext — return as-is
    return stored


# ---------------------------------------------------------------------------
# Session timestamps
# ---------------------------------------------------------------------------

#: The one layout of a stored session timestamp: ``YYYY-MM-DD``, ``T`` or
#: one space, ``HH:MM:SS``, an optional ``.`` with at least one fraction
#: digit, and an optional ``Z`` or ``+HH:MM`` / ``-HH:MM`` offset.
_SESSION_TIMESTAMP_RE = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})[T ]"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]+))?"
    r"(?:(?P<zulu>Z)|(?P<sign>[+-])(?P<off_hour>[0-9]{2}):(?P<off_minute>[0-9]{2}))?"
)


def _parse_session_timestamp(value: object) -> datetime | None:
    """Read a stored session timestamp as an aware datetime, or ``None``.

    Reads exactly what the gateway's ``parse_iso_datetime``
    (storage/sessions.rs) reads, so both services refuse the same rows.
    That layout is what every writer of the sessions table produces: the
    gateway's ``%Y-%m-%dT%H:%M:%S+00:00``, the bridge's ``isoformat()``
    (naive in legacy rows) and SQLite's ``datetime()``. A value without an
    offset is UTC. Fraction digits past microseconds are dropped.

    ``None`` for anything else: a value that is not text (a BLOB, a
    number), ``''``, field values out of range (month 13, a leap second
    ``:60``, an offset beyond ``23:59``) and the forms ``fromisoformat``
    reads although the gateway does not (``+0000`` or ``+02`` offsets,
    offset seconds, a comma fraction, a lowercase ``t`` or another
    separator, basic or date-only forms). Year 0000, which the gateway
    reads, is refused too: ``datetime`` cannot hold it. Callers treat
    ``None`` as a failed check, never as "no limit".
    """
    if not isinstance(value, str):
        return None
    match = _SESSION_TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return None
    tz = timezone.utc
    if match["sign"]:
        off_hour, off_minute = int(match["off_hour"]), int(match["off_minute"])
        if off_hour > 23 or off_minute > 59:
            return None
        offset = timedelta(hours=off_hour, minutes=off_minute)
        tz = timezone(-offset if match["sign"] == "-" else offset)
    fraction = match["fraction"] or ""
    try:
        return datetime(
            int(match["year"]),
            int(match["month"]),
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            int(fraction[:6].ljust(6, "0")),
            tzinfo=tz,
        )
    except ValueError:
        return None


def _session_time_limit(
    expires_at: object,
    last_active: object,
    idle_timeout_minutes: int,
    now: datetime,
) -> str | None:
    """Why a session's stored times end it at *now*, or ``None`` if they don't.

    ``"unreadable"``, ``"expired"`` or ``"idle"``, checked in the gateway's
    order (``session_time_limit`` in storage/sessions.rs): the absolute
    expiry first, then the idle timeout. A NULL *last_active* (a session
    from before the column) carries no idle information, so only the
    absolute limit applies. Any other value must be a timestamp, ``''``
    included: reading it as "never active" would let the touch revive an
    idle session with a fresh idle clock.

    The idle time counts whole seconds, as the gateway's ``num_seconds()``
    does: a session idle for 1800.5 s is still within a 30-minute limit.
    """
    expiry = _parse_session_timestamp(expires_at)
    if expiry is None:
        return "unreadable"
    if now > expiry:
        return "expired"
    if last_active is not None:
        active = _parse_session_timestamp(last_active)
        if active is None:
            return "unreadable"
        if (now - active) // timedelta(seconds=1) > idle_timeout_minutes * 60:
            return "idle"
    return None


#: Seconds a UserStore waits after a failed ``must_change_password`` ALTER
#: before it takes the write lock to try again.
MUST_CHANGE_COLUMN_RETRY_SECONDS = 5.0


# ---------------------------------------------------------------------------
# Verified credentials (the gateway's ``users::VerifiedCredential``)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VerifiedCredential:
    """The credential a password check verified.

    The account's id and the stored password hash the password matched.
    That hash identifies the password version: every password write stores
    a hash under a fresh salt (a reset to the same password included). A
    request that checked the password and then commits something on its
    strength (a login session, an MFA challenge, a password change)
    commits it only while that hash is still stored and the account is
    enabled, so a reset, change or disable committed in between refuses it
    (:class:`CredentialChangedError`). The hash stays out of ``repr``.
    """

    user_id: int
    password_hash: str = field(repr=False)


class CredentialChangedError(Exception):
    """The verified credential is no longer the account's; nothing was written.

    The password was reset or changed, or the account disabled or removed,
    after the request checked it.
    """


class SessionEndedError(Exception):
    """A password change's own session, or its account, ended meanwhile.

    The session was revoked or the account disabled after the change
    checked the current password; nothing was written.
    """


class SessionRowUnreadableError(sqlite3.DatabaseError):
    """A session or its user holds a value of the wrong type.

    A storage error, as the gateway's ``validate_session`` reports for the
    same row: not "no session" and not a guess (an unreadable role is not
    a viewer, an unreadable ``enabled`` is not enabled).
    """


def _session_row_unreadable(session: dict[str, Any]) -> str | None:
    """The first column of a joined session row that cannot be read, or None.

    The types the gateway's ``row_to_session`` requires of the columns the
    bridge acts on: text ``username``, ``role`` and ``tenant_id``, and an
    integer (or NULL) ``enabled``.  A non-text ``scope`` is left to the
    callers, which already fail closed on it as a restricted scope (no
    route but who-am-I and logout, no WebSocket).
    """
    for column in ("username", "role", "tenant_id"):
        if not isinstance(session.get(column), str):
            return column
    enabled = session.get("enabled")
    if enabled is not None and (
        isinstance(enabled, bool) or not isinstance(enabled, int)
    ):
        return "enabled"
    return None


class UserStore:
    """Manage user accounts and login sessions.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: SharedContext) -> None:
        self._ctx = ctx
        self._must_change_column_checked = False
        # monotonic() before which a failed ALTER is not attempted again.
        self._must_change_retry_at = 0.0
        # Secrets stored as ``b64:`` while no valid BRIDGE_MFA_KEY was set
        # are encrypted as soon as one is (startup constructs the store).
        try:
            self.reencrypt_legacy_totp_secrets()
        except Exception:
            logger.critical(
                "Could not encrypt base64-stored TOTP secrets; they stay "
                "unencrypted until the next start",
                exc_info=True,
            )

    def reencrypt_legacy_totp_secrets(self) -> int:
        """Encrypt TOTP secrets stored as ``b64:`` (or legacy plaintext).

        Runs only when ``BRIDGE_MFA_KEY`` is a valid Fernet key (in any
        mode).  All rows are rewritten in one transaction, each only if it
        still holds the value that was read (another worker may race).
        Returns the number of secrets encrypted.  Reading ``b64:`` stays
        supported as a fallback.
        """
        key = os.environ.get("BRIDGE_MFA_KEY", "").strip()
        if not key or mfa_key_problem(key) is not None:
            return 0
        if _get_fernet() is None:
            return 0
        conn = self._ctx.get_conn()
        try:
            rows = conn.execute(
                "SELECT id, totp_secret FROM users "
                "WHERE totp_secret IS NOT NULL AND totp_secret != '' "
                "AND totp_secret NOT LIKE 'fernet:%'"
            ).fetchall()
        except sqlite3.OperationalError as exc:
            if "no such table" in str(exc).lower():
                return 0
            raise
        if not rows:
            return 0
        updates: list[tuple[str, int, str]] = []
        for row in rows:
            stored = row["totp_secret"]
            try:
                plaintext = _decrypt_totp_secret(stored)
            except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
                logger.error(
                    "TOTP secret of user id %s is not decodable (%s); left as is",
                    row["id"],
                    exc,
                )
                continue
            updates.append((_encrypt_totp_secret(plaintext), row["id"], stored))
        if not updates:
            return 0
        count = 0
        with self._ctx.write_transaction() as wconn:
            for new_value, user_id, old_value in updates:
                cur = wconn.execute(
                    "UPDATE users SET totp_secret = ? WHERE id = ? AND totp_secret = ?",
                    (new_value, user_id, old_value),
                )
                count += cur.rowcount
        if count:
            logger.warning(
                "Encrypted %d TOTP secret(s) that were stored base64-encoded "
                "(written before a valid BRIDGE_MFA_KEY was set)",
                count,
            )
        return count

    def _ensure_must_change_column(self) -> None:
        """Add the ``must_change_password`` column to the users table
        if it isn't there yet. Idempotent; once the column is known to
        exist the result is cached, so the steady state costs nothing.

        Older databases created before this column existed get it added
        here; existing rows read as 0 (False) through its DEFAULT.  The
        SELECT and INSERT paths name the column, so it must exist before
        they run: a failed attempt is not cached.  The read-only check runs
        on every call until the column is found, but after a failed ALTER
        the next one waits ``MUST_CHANGE_COLUMN_RETRY_SECONDS``: each try
        can hold the process write lock for the whole busy_timeout, and a
        long outage would otherwise queue every login behind it and log a
        warning per call.
        """
        if self._must_change_column_checked:
            return
        # Read-only check first, so a database that already has the column
        # (the normal case) never takes the write lock here.
        try:
            columns = {
                row[1]
                for row in self._ctx.get_conn().execute("PRAGMA table_info(users)")
            }
        except Exception as exc:  # sqlite3 or SQLCipher (not a sqlite3.Error)
            logger.warning("must_change_password column check failed: %s", exc)
            return
        if "must_change_password" in columns:
            self._must_change_column_checked = True
            return
        if not columns:
            # No users table yet (first boot before the schema ran): there
            # is nothing to alter, so try again on a later call.
            return
        if self._ctx.transaction_active:
            # The caller owns this thread's transaction (and possibly the
            # non-reentrant write lock): adding the column here would
            # deadlock or commit inside its scope.  A later call retries.
            logger.warning(
                "must_change_password column missing inside a caller's "
                "transaction; adding it on a later call"
            )
            return
        if monotonic() < self._must_change_retry_at:
            return
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    "ALTER TABLE users ADD COLUMN must_change_password "
                    "INTEGER NOT NULL DEFAULT 0"
                )
        except Exception as exc:  # sqlite3 or SQLCipher (not a sqlite3.Error)
            msg = str(exc).lower()
            if "duplicate column" in msg or "already exists" in msg:
                # Another worker or thread added it between the check above
                # and the ALTER.
                self._must_change_column_checked = True
                return
            # Timed from the failure: the attempt may have waited out the
            # whole busy_timeout.
            self._must_change_retry_at = monotonic() + MUST_CHANGE_COLUMN_RETRY_SECONDS
            logger.warning(
                "Could not add must_change_password column (retrying in %gs): %s",
                MUST_CHANGE_COLUMN_RETRY_SECONDS,
                exc,
            )
            return
        self._must_change_column_checked = True
        logger.info("Added must_change_password column to users table")

    def clear_must_change_password(self, username: str) -> None:
        """Unset the must-change-password flag on a user. Called from
        the change-password handler after a successful reset.
        """
        self._ensure_must_change_column()
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                f"UPDATE users SET must_change_password = 0 "
                f"WHERE {tf_clause} AND username = ?",
                tf_params + [username],
            )

    # -- User CRUD ----------------------------------------------------------

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
        display_name: str = "",
        email: str = "",
        tenant_id: str | None = None,
        must_change_password: bool = False,
    ) -> dict[str, Any]:
        """Create a new user account.

        Returns the created user dict (without password_hash/salt).

        When ``must_change_password`` is True, the user is flagged
        such that their first login grants only a restricted session
        scoped to the change-password endpoint. This path is used
        for auto-bootstrapped admin accounts where a random password
        was written to a file and the operator may not have set it.

        Raises
        ------
        ValueError
            If username already exists or role is invalid.
        """
        valid_roles = ("viewer", "analyst", "admin")
        if role not in valid_roles:
            raise ValueError(f"Invalid role: {role}. Must be one of {valid_roles}")

        hash_hex, salt = hash_credential(password)
        now = datetime.now(timezone.utc).isoformat()
        tid = tenant_id or self._ctx.tenant_id
        must_change = 1 if must_change_password else 0

        # Ensure the must_change_password column exists (idempotent).
        self._ensure_must_change_column()

        sql = """
            INSERT INTO users
                (username, password_hash, salt, role, display_name, email,
                 enabled, created_at, tenant_id, must_change_password)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
        """
        try:
            # A duplicate username raises IntegrityError here; the
            # transaction is rolled back before the handler below runs, so
            # the connection does not keep the database write-locked.
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    sql,
                    [
                        username,
                        hash_hex,
                        salt,
                        role,
                        display_name,
                        email,
                        now,
                        tid,
                        must_change,
                    ],
                )
        except Exception as exc:
            if "UNIQUE" in str(exc).upper():
                raise ValueError(f"Username '{username}' already exists") from exc
            raise

        logger.info(
            "Created user: %s (role=%s, must_change_password=%s)",
            username,
            role,
            bool(must_change),
        )
        return {
            "username": username,
            "role": role,
            "display_name": display_name,
            "email": email,
            "enabled": True,
            "created_at": now,
            "last_login": None,
            "tenant_id": tid,
        }

    def get_user(self, username: str) -> dict[str, Any] | None:
        """Get user by username (excludes password_hash/salt)."""
        self._ensure_must_change_column()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT id, username, role, display_name, email, enabled, "
            f"created_at, last_login, tenant_id, mfa_enabled, "
            f"COALESCE(must_change_password, 0) AS must_change_password "
            f"FROM users WHERE {tf_clause} AND username = ?",
            tf_params + [username],
        ).fetchone()
        if row is None:
            return None
        user = dict(row)
        user["must_change_password"] = bool(user.get("must_change_password", 0))
        return user

    def get_user_full(self, username: str) -> dict[str, Any] | None:
        """Get user with password_hash and salt (for internal auth).

        TOTP secrets are decrypted transparently before being returned.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT * FROM users WHERE {tf_clause} AND username = ?",
            tf_params + [username],
        ).fetchone()
        if row is None:
            return None
        user = dict(row)
        if user.get("totp_secret"):
            try:
                user["totp_secret"] = _decrypt_totp_secret(user["totp_secret"])
            except Exception as exc:
                logger.error("Failed to decrypt TOTP secret for %s: %s", username, exc)
                user["totp_secret"] = None
        return user

    def list_users(self) -> list[dict[str, Any]]:
        """List all users (excludes password_hash/salt)."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT id, username, role, display_name, email, enabled, "
            f"created_at, last_login, tenant_id "
            f"FROM users WHERE {tf_clause} ORDER BY created_at",
            tf_params,
        ).fetchall()
        return [dict(r) for r in rows]

    def update_user(
        self,
        username: str,
        role: str | None = None,
        display_name: str | None = None,
        email: str | None = None,
        enabled: bool | None = None,
        *,
        revoke_sessions: bool = False,
        _after_write: Callable[[sqlite3.Connection], None] | None = None,
    ) -> dict[str, Any] | None:
        """Update user fields, optionally revoking sessions in the same commit.

        Public account-disable handlers request revocation; raw storage callers
        retain the historical field-update-only behavior by default.
        The facade's internal ``_after_write`` hook appends the mandatory audit
        on this transaction's connection, before commit and without re-locking.
        Returns updated user or None if not found.
        """
        updates: list[str] = []
        params: list[Any] = []

        if role is not None:
            valid_roles = ("viewer", "analyst", "admin")
            if role not in valid_roles:
                raise ValueError(f"Invalid role: {role}. Must be one of {valid_roles}")
            updates.append("role = ?")
            params.append(role)
        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if email is not None:
            updates.append("email = ?")
            params.append(email)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if not updates:
            if _after_write is None:
                return self.get_user(username)
            # A reopened store has not run this lazy schema check. Complete
            # its own write transaction before get_user reads under our lock.
            self._ensure_must_change_column()
            with self._ctx.write_transaction(immediate=True) as conn:
                user = self.get_user(username)
                if user is not None:
                    _after_write(conn)
            return user

        tf_clause, tf_params = self._ctx.tenant_filter()
        sql = (
            f"UPDATE users SET {', '.join(updates)} WHERE {tf_clause} AND username = ?"
        )
        params.extend(tf_params)
        params.append(username)

        with self._ctx.write_transaction(immediate=_after_write is not None) as conn:
            cursor = conn.execute(sql, params)
            if revoke_sessions and cursor.rowcount:
                conn.execute(
                    f"DELETE FROM sessions WHERE user_id IN "
                    f"(SELECT id FROM users WHERE {tf_clause} AND username = ?)",
                    tf_params + [username],
                )
            if cursor.rowcount and _after_write is not None:
                _after_write(conn)
        if cursor.rowcount == 0:
            return None

        logger.info("Updated user: %s", username)
        return self.get_user(username)

    def disable_user(self, username: str) -> bool:
        """Soft-delete a user by setting enabled=0. Returns True if found."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE users SET enabled = 0 WHERE {tf_clause} AND username = ?",
                tf_params + [username],
            )
        if cursor.rowcount > 0:
            logger.info("Disabled user: %s", username)
            return True
        return False

    def set_password(
        self,
        username: str,
        new_password: str,
        *,
        revoke_sessions: bool = False,
        _after_write: Callable[[sqlite3.Connection], None] | None = None,
    ) -> bool:
        """Set a password, optionally revoking sessions in the same commit.

        Hashing happens before the write transaction. Public password-change
        handlers request revocation so a deletion failure cannot commit only
        the new password. The facade may append its audit via ``_after_write``
        before the same commit. The user's pending MFA logins always end in
        that commit (see :meth:`_store_password_hash`). Returns True if the
        user was found.

        This write is unconditional (the admin reset). A change made on the
        strength of the current password uses :meth:`change_password`.
        """
        hash_hex, salt = hash_credential(new_password)
        with self._ctx.write_transaction(immediate=_after_write is not None) as conn:
            updated = self._store_password_hash(
                conn, username, hash_hex, salt, revoke_sessions=revoke_sessions
            )
            if updated and _after_write is not None:
                _after_write(conn)
        return updated

    def change_password(
        self,
        username: str,
        new_password: str,
        *,
        credential: VerifiedCredential,
        session_token: str | None,
        _after_write: Callable[[sqlite3.Connection], None] | None = None,
    ) -> VerifiedCredential | None:
        """Change a password on the strength of the verified current one.

        Commits only while the state the request was authorised against
        still holds, checked in the write transaction: *credential* (from
        :meth:`verify_password_credential`) is still the stored password,
        else :class:`CredentialChangedError`; the account is enabled and
        *session_token* (the session making the request, unless ``None``)
        still exists, else :class:`SessionEndedError`. Otherwise a reset,
        another change or a revocation committed while the request hashed
        the new password would be undone by it. On those errors nothing is
        written.

        The commit revokes every session of the user and ends the user's
        pending MFA logins; ``_after_write`` appends the facade's audit.
        Returns the new credential (for the replacement session), or
        ``None`` if the user is gone.
        """
        hash_hex, salt = hash_credential(new_password)
        tf_clause, tf_params = self._ctx.tenant_filter()
        # IMMEDIATE: the checks and the write see one state, also against
        # another process (the gateway) writing the same database.
        with self._ctx.write_transaction(immediate=True) as conn:
            row = conn.execute(
                f"SELECT id, password_hash, enabled FROM users "
                f"WHERE {tf_clause} AND username = ?",
                tf_params + [username],
            ).fetchone()
            if row is None:
                return None
            if (
                row["id"] != credential.user_id
                or row["password_hash"] != credential.password_hash
            ):
                raise CredentialChangedError(username)
            if not row["enabled"] or (
                session_token is not None
                and conn.execute(
                    "SELECT 1 FROM sessions WHERE session_token = ? AND user_id = ?",
                    [self._hash_token(session_token), row["id"]],
                ).fetchone()
                is None
            ):
                raise SessionEndedError(username)
            if not self._store_password_hash(
                conn, username, hash_hex, salt, revoke_sessions=True
            ):
                return None
            if _after_write is not None:
                _after_write(conn)
        return VerifiedCredential(user_id=row["id"], password_hash=hash_hex)

    def _store_password_hash(
        self,
        conn: sqlite3.Connection,
        username: str,
        hash_hex: str,
        salt: bytes,
        *,
        revoke_sessions: bool,
    ) -> bool:
        """Store a computed hash in the caller's write transaction.

        Every write of a new password (:meth:`set_password`,
        :meth:`change_password`) goes through here, and ends the user's
        pending MFA logins: an ``mfa_tokens`` challenge proves only the
        password it was issued for, so it must not complete a login under
        the new one. The gateway shares the table and redeems these tokens
        too; its ``users::set_password_hash`` deletes them the same way.
        Optionally revokes the user's sessions. Returns True if the user was
        found.

        The one other write of ``password_hash`` is the legacy SHA-256
        upgrade in :meth:`verify_password_credential`. It stores the same
        password under a PBKDF2 hash, so it leaves the pending logins (they
        proved that password) and the sessions alone. A new path that
        stores a different password must come through here instead:
        :meth:`claim_mfa_token` relies on it.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        user_ids = f"(SELECT id FROM users WHERE {tf_clause} AND username = ?)"
        updated = conn.execute(
            f"UPDATE users SET password_hash = ?, salt = ? "
            f"WHERE {tf_clause} AND username = ?",
            [hash_hex, salt] + tf_params + [username],
        ).rowcount
        if not updated:
            return False
        conn.execute(
            f"DELETE FROM mfa_tokens WHERE user_id IN {user_ids}",
            tf_params + [username],
        )
        if revoke_sessions:
            conn.execute(
                f"DELETE FROM sessions WHERE user_id IN {user_ids}",
                tf_params + [username],
            )
        return True

    def _credential_is_current(
        self, conn: sqlite3.Connection, credential: VerifiedCredential
    ) -> bool:
        """Whether *credential* is still the password of an enabled account."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        return (
            conn.execute(
                f"SELECT 1 FROM users WHERE {tf_clause} AND id = ? "
                f"AND password_hash = ? AND enabled = 1",
                tf_params + [credential.user_id, credential.password_hash],
            ).fetchone()
            is not None
        )

    def verify_password(self, username: str, password: str) -> bool:
        """Whether *password* is the current password of enabled *username*.

        See :meth:`verify_password_credential`, which also returns what it
        verified.
        """
        return self.verify_password_credential(username, password) is not None

    def verify_password_credential(
        self, username: str, password: str
    ) -> VerifiedCredential | None:
        """Verify against the current account, upgrading only actual legacy hashes.

        Both formats have 64 hex characters. A successful legacy SHA-256
        comparison identifies the old format; current PBKDF2 credentials stay
        byte-identical. Hashing occurs outside the write lock. A changed account
        refuses this attempt, and the conditional upgrade cannot overwrite a
        concurrent reset.

        Returns the credential verified (the upgraded hash after a legacy
        upgrade), or ``None``. This is not an atomic login: a caller that
        commits on the strength of the check (a session, an MFA challenge,
        a password change) passes the credential to that write, which
        refuses it if the password changed in between.
        """
        user = self.get_user_full(username)
        if user is None or not user.get("enabled"):
            return None
        if not verify_credential(password, user["password_hash"], user["salt"]):
            return None

        # Keep the verified identity and authentication policy, including the
        # lazily introduced password-change flag when that column exists.
        fields = (
            "id",
            "username",
            "password_hash",
            "salt",
            "tenant_id",
            "role",
            "enabled",
            "mfa_enabled",
            "must_change_password",
        )
        present = [field for field in fields if field in user]
        tf_clause, tf_params = self._ctx.tenant_filter()
        clause = (
            tf_clause + " AND " + " AND ".join(f"{field} IS ?" for field in present)
        )
        params = tf_params + [user[field] for field in present]
        legacy = hashlib.sha256(user["salt"] + password.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(legacy, user["password_hash"]):
            unchanged = (
                self._ctx.get_conn()
                .execute(f"SELECT 1 FROM users WHERE {clause}", params)
                .fetchone()
                is not None
            )
            if not unchanged:
                return None
            return VerifiedCredential(
                user_id=user["id"], password_hash=user["password_hash"]
            )

        # The same password under a new hash: not a new password, so not
        # through _store_password_hash. Pending MFA logins and sessions stay.
        new_hash, new_salt = hash_credential(password)
        with self._ctx.write_transaction() as conn:
            changed = conn.execute(
                f"UPDATE users SET password_hash = ?, salt = ? WHERE {clause}",
                [new_hash, new_salt] + params,
            ).rowcount
        if not changed:
            return None
        logger.info(
            "Upgraded legacy SHA-256 password hash to PBKDF2 for user: %s", username
        )
        return VerifiedCredential(user_id=user["id"], password_hash=new_hash)

    def user_count(self) -> int:
        """Return the number of users in the current tenant."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT COUNT(*) as cnt FROM users WHERE {tf_clause}",
            tf_params,
        ).fetchone()
        return row["cnt"] if row else 0

    # -- Session management -------------------------------------------------

    @staticmethod
    def _hash_token(token: str) -> str:
        """SHA-256 hash a high-entropy session token for storage."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    #: Default absolute session timeout in hours.
    #: Override via BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS env var.
    _ABSOLUTE_TIMEOUT_HOURS: int = 24

    #: Longest accepted absolute timeout: 10,000,000 hours (about 1141
    #: years), the ceiling API key lifetimes have too. The expiry it gives
    #: stays a four-digit year, which ``datetime`` holds and the gateway
    #: reads; a value from about 7e7 hours up overflowed ``create_session``.
    _MAX_ABSOLUTE_TIMEOUT_HOURS: int = 10_000_000

    @classmethod
    def _get_absolute_timeout_hours(cls) -> int:
        """``BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS``, or the default of 24.

        A value that is not an integer from 1 to
        :attr:`_MAX_ABSOLUTE_TIMEOUT_HOURS` is logged and ignored.
        """
        raw = os.environ.get("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", "").strip()
        if raw:
            try:
                val = int(raw)
            except ValueError:
                val = 0
            if 0 < val <= cls._MAX_ABSOLUTE_TIMEOUT_HOURS:
                return val
            logger.warning(
                "Invalid BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS=%r (expected an "
                "integer from 1 to %d), using default %d",
                raw[:64],
                cls._MAX_ABSOLUTE_TIMEOUT_HOURS,
                cls._ABSOLUTE_TIMEOUT_HOURS,
            )
        return cls._ABSOLUTE_TIMEOUT_HOURS

    def create_session(
        self,
        user_id: int,
        ip_address: str = "",
        user_agent: str = "",
        expires_hours: int | None = None,
        *,
        credential: VerifiedCredential | None = None,
    ) -> dict[str, Any]:
        """Create a login session. Returns session dict with token.

        With *credential* (what the login's password check verified, for
        *user_id*), the session is created only while it is still the
        account's password and the account is enabled, checked in the
        same transaction as the insert; otherwise
        :class:`CredentialChangedError` and nothing is written. A reset or
        disable committed after the check therefore refuses the login, and
        one committed after the insert revokes the session.
        """
        if credential is not None and credential.user_id != user_id:
            raise ValueError("credential is not for this user")
        if expires_hours is None:
            expires_hours = self._get_absolute_timeout_hours()
        token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=expires_hours)

        sql = """
            INSERT INTO sessions
                (session_token, user_id, created_at, expires_at,
                 ip_address, user_agent, last_active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        hashed = self._hash_token(token)
        with self._ctx.write_transaction(immediate=credential is not None) as conn:
            if credential is not None and not self._credential_is_current(
                conn, credential
            ):
                raise CredentialChangedError(user_id)
            conn.execute(
                sql,
                [
                    hashed,
                    user_id,
                    now.isoformat(),
                    expires_at.isoformat(),
                    ip_address,
                    user_agent,
                    now.isoformat(),
                ],
            )
            # Update last_login on the user
            conn.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                [now.isoformat(), user_id],
            )

        return {
            "session_token": token,
            "user_id": user_id,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "ip_address": ip_address,
        }

    #: Default idle timeout in minutes (NIST 800-63B recommends <= 30 min).
    #: Override via BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES env var.
    _IDLE_TIMEOUT_MINUTES: int = 30

    @classmethod
    def _get_idle_timeout_minutes(cls) -> int:
        raw = os.environ.get("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", "").strip()
        if raw:
            try:
                val = int(raw)
                if val > 0:
                    return val
            except ValueError:
                logger.warning(
                    "Invalid BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES=%r, using default %d",
                    raw,
                    cls._IDLE_TIMEOUT_MINUTES,
                )
        return cls._IDLE_TIMEOUT_MINUTES

    def session_tenant(self, session_token: str) -> str | None:
        """Read a credential's tenant for refusal, without touching foreign state."""
        row = (
            self._ctx.get_conn()
            .execute(
                "SELECT u.tenant_id FROM sessions s JOIN users u ON s.user_id=u.id "
                "WHERE s.session_token=?",
                [self._hash_token(session_token)],
            )
            .fetchone()
        )
        return row["tenant_id"] if row is not None else None

    def get_session(
        self, session_token: str, *, touch: bool = True
    ) -> dict[str, Any] | None:
        """Look up a session, rejecting foreign, disabled, expired or idle users.

        A session past its absolute expiry or its idle timeout, or whose
        ``expires_at`` or non-NULL ``last_active`` is unreadable (see
        :func:`_session_time_limit`), is refused and, with ``touch``,
        deleted, as the gateway's ``validate_session`` does. These checks
        come before the disabled-user refusal, which keeps the row.  A row
        whose user name, role, tenant or ``enabled`` has the wrong type
        raises :class:`SessionRowUnreadableError` (a storage error).

        ``touch=False`` is read-only validation for outgoing WebSocket data:
        receiving streamed data must not keep an otherwise idle session alive.
        It refuses the same sessions but never deletes or touches a row.
        """
        hashed = self._hash_token(session_token)
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT s.*, u.username, u.role, u.display_name, u.email, u.enabled, u.tenant_id "
            "FROM sessions s JOIN users u ON s.user_id = u.id "
            "WHERE s.session_token = ? AND u.tenant_id = ?",
            [hashed, self._ctx.tenant_id],
        ).fetchone()
        if row is None:
            return None

        session = dict(row)
        unreadable = _session_row_unreadable(session)
        if unreadable is not None:
            # Neither the value nor the token in diagnostics.
            logger.warning(
                "Refusing session %r: its %s cannot be read",
                session.get("id", -1),
                unreadable,
            )
            raise SessionRowUnreadableError(f"session {unreadable} cannot be read")
        now = datetime.now(timezone.utc)

        # Absolute expiry and idle timeout (NIST 800-63B). A session past
        # either, or whose times cannot be read, is never kept without a limit.
        idle_minutes = self._get_idle_timeout_minutes()
        limit = _session_time_limit(
            session.get("expires_at"), session.get("last_active"), idle_minutes, now
        )
        if limit is not None:
            if limit == "idle":
                logger.info(
                    "Session idle timeout for user %s (idle > %dm)",
                    session.get("username", "?"),
                    idle_minutes,
                )
            elif limit == "unreadable":
                logger.warning(
                    "Refusing session %d of user %s: its expires_at or "
                    "last_active is not a readable timestamp",
                    session.get("id", -1),
                    session.get("username", "?"),
                )
            if touch:
                self.delete_session(session_token)
            return None

        # Check user is still enabled
        if not session.get("enabled"):
            return None

        # Touch last_active timestamp
        if touch:
            self._touch_session(session_token, now)

        return session

    def _touch_session(self, session_token: str, now: datetime) -> None:
        """Update the last_active timestamp for a session."""
        hashed = self._hash_token(session_token)
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    "UPDATE sessions SET last_active = ? WHERE session_token = ?",
                    [now.isoformat(), hashed],
                )
        except Exception:
            # Graceful degradation if last_active column missing (pre-migration)
            pass

    def set_session_scope(self, session_token: str, scope: str) -> None:
        """Set a restricted scope on a session (e.g. 'mfa_setup_only').

        Adds a scope column if missing (graceful migration).
        """
        hashed = self._hash_token(session_token)
        with self._ctx.write_lock:
            try:
                with self._ctx.transaction() as conn:
                    conn.execute(
                        "UPDATE sessions SET scope = ? WHERE session_token = ?",
                        [scope, hashed],
                    )
            except Exception:
                # Column may not exist yet — add it
                try:
                    with self._ctx.transaction() as conn:
                        conn.execute(
                            "ALTER TABLE sessions ADD COLUMN scope TEXT DEFAULT ''"
                        )
                        conn.execute(
                            "UPDATE sessions SET scope = ? WHERE session_token = ?",
                            [scope, hashed],
                        )
                except Exception:
                    logger.warning(
                        "Failed to set session scope to %r: column migration failed",
                        scope,
                        exc_info=True,
                    )

    def delete_session(self, session_token: str) -> bool:
        """Delete a session (logout). Returns True if session existed."""
        hashed = self._hash_token(session_token)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE session_token = ? "
                "AND user_id IN (SELECT id FROM users WHERE tenant_id = ?)",
                [hashed, self._ctx.tenant_id],
            )
        return cursor.rowcount > 0

    def delete_user_sessions(self, user_id: int) -> int:
        """Delete all sessions for a user. Returns count deleted."""
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?",
                [user_id],
            )
        return cursor.rowcount

    def cleanup_expired_sessions(self) -> int:
        """Delete all expired sessions. Returns count deleted."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                [now],
            )
        deleted = cursor.rowcount
        if deleted > 0:
            logger.info("Cleaned up %d expired sessions", deleted)
        return deleted

    # -- MFA management -----------------------------------------------------

    def set_totp_secret(self, user_id: int, secret: str | None) -> bool:
        """Store or clear the TOTP secret for a user.

        The secret is encrypted via Fernet (if ``BRIDGE_MFA_KEY`` is set)
        or base64-encoded before being written to the database.
        """
        encrypted = _encrypt_totp_secret(secret) if secret else None
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET totp_secret = ? WHERE id = ?",
                [encrypted, user_id],
            )
        return cursor.rowcount > 0

    def enable_mfa(self, user_id: int) -> bool:
        """Set mfa_enabled = 1 on the user record."""
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET mfa_enabled = 1 WHERE id = ?",
                [user_id],
            )
        return cursor.rowcount > 0

    def disable_mfa(self, user_id: int) -> bool:
        """Disable MFA: clear totp_secret, set mfa_enabled = 0, remove backup codes."""
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "UPDATE users SET mfa_enabled = 0, totp_secret = NULL WHERE id = ?",
                [user_id],
            )
            conn.execute(
                "DELETE FROM mfa_backup_codes WHERE user_id = ?",
                [user_id],
            )
        return cursor.rowcount > 0

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        """Get user by id (all columns).

        TOTP secrets are decrypted transparently before being returned.
        """
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
        if row is None:
            return None
        user = dict(row)
        if user.get("totp_secret"):
            try:
                user["totp_secret"] = _decrypt_totp_secret(user["totp_secret"])
            except Exception as exc:
                logger.error(
                    "Failed to decrypt TOTP secret for user_id=%s: %s", user_id, exc
                )
                user["totp_secret"] = None
        return user

    # -- Backup codes -------------------------------------------------------

    def store_backup_codes(
        self,
        user_id: int,
        code_hashes: list[tuple[str, bytes]],
    ) -> None:
        """Store PBKDF2-hashed backup codes for a user, replacing existing ones.

        Parameters
        ----------
        user_id : int
            The user's database id.
        code_hashes : list[tuple[str, bytes]]
            Each element is ``(hex_hash, salt)`` from ``hash_credential()``.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "DELETE FROM mfa_backup_codes WHERE user_id = ?",
                [user_id],
            )
            for hash_hex, salt in code_hashes:
                conn.execute(
                    "INSERT INTO mfa_backup_codes "
                    "(user_id, code_hash, salt, used, created_at) "
                    "VALUES (?, ?, ?, 0, ?)",
                    [user_id, hash_hex, salt, now],
                )

    def verify_backup_code(self, user_id: int, code: str) -> bool:
        """Verify a raw backup code against stored PBKDF2 hashes.

        Iterates all unused codes for the user and checks each with
        ``verify_credential``.  If a match is found the code is marked
        used and True is returned.

        Also supports legacy unsalted SHA-256 rows (salt IS NULL) for
        backward compatibility during migration.

        The PBKDF2 checks (~0.3 s each, one per unused code) run *without*
        the global write lock, which every DB writer shares.  Single use is
        enforced by the consuming ``UPDATE ... WHERE used = 0``: of two
        concurrent requests presenting the same code, only one flips the
        row and gets True.
        """
        import hashlib as _hashlib
        import hmac as _hmac

        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT id, code_hash, salt FROM mfa_backup_codes "
            "WHERE user_id = ? AND used = 0",
            [user_id],
        ).fetchall()
        matched_id = None
        for row in rows:
            if row["salt"] is not None:
                # PBKDF2 path
                matched = verify_credential(code, row["code_hash"], row["salt"])
            else:
                # Legacy unsalted SHA-256 path
                legacy = _hashlib.sha256(code.encode()).hexdigest()
                matched = _hmac.compare_digest(legacy, row["code_hash"])
            if matched:
                matched_id = row["id"]
                break
        if matched_id is None:
            return False
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "UPDATE mfa_backup_codes SET used = 1 WHERE id = ? AND used = 0",
                [matched_id],
            )
        return cursor.rowcount == 1

    def get_backup_code_count(self, user_id: int) -> int:
        """Return the number of unused backup codes for a user."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM mfa_backup_codes "
            "WHERE user_id = ? AND used = 0",
            [user_id],
        ).fetchone()
        return row["cnt"] if row else 0

    # -- MFA tokens (short-lived proof of password) -------------------------

    def create_mfa_token(
        self,
        user_id: int,
        expires_minutes: int = 5,
        *,
        credential: VerifiedCredential | None = None,
    ) -> str:
        """Create a short-lived MFA token proving password was correct.

        With *credential* (what the login's password check verified, for
        *user_id*), the token is created only while it is still the
        account's password and the account is enabled, else
        :class:`CredentialChangedError` and nothing is written. Every write
        of a new password ends the user's tokens
        (:meth:`_store_password_hash`; the legacy upgrade re-hashes the same
        password and keeps them), so a token that exists was issued for the
        password stored now: the claim (:meth:`claim_mfa_token`, or the
        gateway's ``verify_mfa_token``) reads the credential it then binds
        the session to.
        """
        if credential is not None and credential.user_id != user_id:
            raise ValueError("credential is not for this user")
        token = secrets.token_urlsafe(32)
        hashed = self._hash_token(token)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expires_minutes)
        with self._ctx.write_transaction(immediate=credential is not None) as conn:
            if credential is not None and not self._credential_is_current(
                conn, credential
            ):
                raise CredentialChangedError(user_id)
            conn.execute(
                "INSERT INTO mfa_tokens (token, user_id, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                [hashed, user_id, now.isoformat(), expires_at.isoformat()],
            )
        return token

    def verify_mfa_token(self, token: str) -> int | None:
        """Verify an MFA token. Returns user_id if valid, None if invalid/expired.

        Consumes the token (deletes it) on success; see
        :meth:`claim_mfa_token`.
        """
        credential = self.claim_mfa_token(token)
        return None if credential is None else credential.user_id

    def claim_mfa_token(self, token: str) -> VerifiedCredential | None:
        """Consume an MFA token; return the credential its password step verified.

        ``None`` if the token is unknown, foreign, expired (it is deleted
        then too) or its expiry unreadable. The claim and the read of the
        user's stored password hash are one IMMEDIATE transaction under the
        write lock: of several requests presenting the token, also from
        another process sharing the database, exactly one gets it. A token
        still present was issued for the stored password, possibly since
        re-hashed by the legacy upgrade (:meth:`create_mfa_token`), so the
        hash read is the credential to bind the session to; the session is
        then created only while it is still current, which also refuses a
        reset committed during the second-factor check.
        """
        hashed = self._hash_token(token)
        with self._ctx.write_transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT m.id, m.user_id, m.expires_at, u.password_hash "
                "FROM mfa_tokens m JOIN users u ON u.id=m.user_id "
                "WHERE m.token = ? AND u.tenant_id = ?",
                [hashed, self._ctx.tenant_id],
            ).fetchone()
            if row is None:
                return None

            # Check expiration
            try:
                exp = datetime.fromisoformat(row["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > exp:
                    # Expired — clean up
                    conn.execute("DELETE FROM mfa_tokens WHERE id = ?", [row["id"]])
                    return None
            except (ValueError, TypeError):
                return None

            # Consume the token
            claimed = conn.execute(
                "DELETE FROM mfa_tokens WHERE id = ?", [row["id"]]
            ).rowcount
        if claimed != 1:
            return None
        return VerifiedCredential(
            user_id=row["user_id"], password_hash=row["password_hash"]
        )

    def cleanup_expired_mfa_tokens(self) -> int:
        """Delete all expired MFA tokens."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM mfa_tokens WHERE expires_at < ?",
                [now],
            )
        return cursor.rowcount

    # -- Tenant settings ----------------------------------------------------

    def get_tenant_mfa_required(self, tenant_id: str) -> bool:
        """Check if MFA is required for a tenant."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT mfa_required FROM tenant_settings WHERE tenant_id = ?",
            [tenant_id],
        ).fetchone()
        if row is None:
            return False
        return bool(row["mfa_required"])

    def set_tenant_mfa_required(self, tenant_id: str, required: bool) -> None:
        """Set the MFA requirement for a tenant."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT INTO tenant_settings (tenant_id, mfa_required, updated_at) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(tenant_id) DO UPDATE SET mfa_required = ?, updated_at = ?",
                [tenant_id, int(required), now, int(required), now],
            )
