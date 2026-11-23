"""DB-backed security state: rate limits, account lockout, OIDC states, TOTP replay.

Replaces in-memory dicts that were lost on process restart (D-10, TD-1–TD-3).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)


class SecurityStateStore:
    """Persistent security state backed by SQLite.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: SharedContext) -> None:
        self._ctx = ctx

    # -- D-10: Login rate limiting -------------------------------------------

    #: Max login attempts per IP within the window.
    RATE_LIMIT_MAX: int = 5
    #: Sliding window in seconds.
    RATE_LIMIT_WINDOW: float = 60.0

    def record_login_attempt(self, client_ip: str) -> None:
        """Record a login attempt from *client_ip*."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT INTO rate_limit_login (client_ip, attempt_at, tenant_id) "
                "VALUES (?, ?, ?)",
                [client_ip, time.time(), self._ctx.tenant_id],
            )

    def count_recent_login_attempts(self, client_ip: str) -> int:
        """Count login attempts from *client_ip* within the sliding window."""
        cutoff = time.time() - self.RATE_LIMIT_WINDOW
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM rate_limit_login "
            "WHERE client_ip = ? AND attempt_at > ? AND tenant_id = ?",
            [client_ip, cutoff, self._ctx.tenant_id],
        ).fetchone()
        return row["cnt"] if row else 0

    def cleanup_login_attempts(self) -> int:
        """Delete expired login rate-limit entries. Returns count deleted."""
        cutoff = time.time() - self.RATE_LIMIT_WINDOW
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM rate_limit_login WHERE attempt_at < ? AND tenant_id = ?",
                [cutoff, self._ctx.tenant_id],
            )
        return cursor.rowcount

    # -- TD-1: Account lockout -----------------------------------------------

    #: Max failed attempts per account within the lockout window.
    LOCKOUT_MAX: int = 10
    #: Lockout window in seconds (30 minutes).
    LOCKOUT_WINDOW: float = 1800.0
    #: How long :meth:`cleanup_account_lockout` keeps failures (24 hours).
    #: Longer than :attr:`LOCKOUT_WINDOW`: the gateway counts this table
    #: with its own ``UC_LOCKOUT_WINDOW``, up to its
    #: ``MAX_LOCKOUT_WINDOW_SECS`` (no longer than this), and prunes it to
    #: that window itself every 5 minutes.  Pruning at the bridge's window
    #: would delete failures a longer gateway window still counts and
    #: unlock the account at the next cleanup.
    LOCKOUT_RETENTION: float = 86400.0

    def record_account_failure(self, username: str) -> None:
        """Record a failed login attempt for *username*."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT INTO account_lockout (username, failure_at, tenant_id) "
                "VALUES (?, ?, ?)",
                [username, time.time(), self._ctx.tenant_id],
            )

    def reserve_account_attempt(self, username: str) -> bool:
        """Count a login attempt for *username* as a failure, if not locked.

        Returns ``False`` (recording nothing) when *username* already has
        :attr:`LOCKOUT_MAX` failures in the window, else records one and
        returns ``True``.  The count and the insert are a single INSERT …
        SELECT, so the check and the reservation are atomic even across
        processes sharing the database: N parallel attempts can never all
        see "below the limit".  A successful login clears the reservation
        with :meth:`clear_account_failures`.
        """
        now = time.time()
        cutoff = now - self.LOCKOUT_WINDOW
        tenant = self._ctx.tenant_id
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "INSERT INTO account_lockout (username, failure_at, tenant_id) "
                "SELECT ?, ?, ? WHERE ("
                "  SELECT COUNT(*) FROM account_lockout "
                "  WHERE username = ? AND failure_at > ? AND tenant_id = ?"
                ") < ?",
                [username, now, tenant, username, cutoff, tenant, self.LOCKOUT_MAX],
            )
        return cursor.rowcount == 1

    def count_recent_failures(self, username: str) -> int:
        """Count recent failures for *username* within the lockout window."""
        cutoff = time.time() - self.LOCKOUT_WINDOW
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM account_lockout "
            "WHERE username = ? AND failure_at > ? AND tenant_id = ?",
            [username, cutoff, self._ctx.tenant_id],
        ).fetchone()
        return row["cnt"] if row else 0

    def clear_account_failures(self, username: str) -> int:
        """Clear all failure records for *username* (on successful login)."""
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM account_lockout WHERE username = ? AND tenant_id = ?",
                [username, self._ctx.tenant_id],
            )
        return cursor.rowcount

    def cleanup_account_lockout(self) -> int:
        """Delete account lockout entries no window counts. Returns count deleted.

        Keeps them for :attr:`LOCKOUT_RETENTION`, not only the bridge's own
        :attr:`LOCKOUT_WINDOW`: the gateway shares the table.
        """
        cutoff = time.time() - max(self.LOCKOUT_WINDOW, self.LOCKOUT_RETENTION)
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM account_lockout WHERE failure_at < ? AND tenant_id = ?",
                [cutoff, self._ctx.tenant_id],
            )
        return cursor.rowcount

    # -- TD-2: OIDC states ---------------------------------------------------

    #: Max age for OIDC states in seconds.
    OIDC_STATE_MAX_AGE: float = 600.0
    #: Hard cap on stored states.
    OIDC_MAX_STATES: int = 1000

    def create_oidc_state(
        self,
        state: str,
        nonce: str,
        redirect_to: str = "/",
    ) -> None:
        """Store an OIDC authorization state."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO oidc_states "
                "(state, nonce, redirect_to, created_at, tenant_id) "
                "VALUES (?, ?, ?, ?, ?)",
                [state, nonce, redirect_to, time.time(), self._ctx.tenant_id],
            )

    def consume_oidc_state(self, state: str) -> dict[str, Any] | None:
        """Pop an OIDC state (atomic consume). Returns None if not found/expired."""
        with self._ctx.write_transaction() as conn:
            row = conn.execute(
                "SELECT nonce, redirect_to, created_at FROM oidc_states "
                "WHERE state = ? AND tenant_id = ?",
                [state, self._ctx.tenant_id],
            ).fetchone()
            if row is None:
                return None
            conn.execute(
                "DELETE FROM oidc_states WHERE state = ? AND tenant_id = ?",
                [state, self._ctx.tenant_id],
            )

        data = dict(row)
        # Check age
        if time.time() - data["created_at"] > self.OIDC_STATE_MAX_AGE:
            return None
        return data

    def cleanup_oidc_states(self) -> int:
        """Delete expired OIDC states and enforce hard cap."""
        cutoff = time.time() - self.OIDC_STATE_MAX_AGE
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM oidc_states WHERE created_at < ? AND tenant_id = ?",
                [cutoff, self._ctx.tenant_id],
            )
            deleted = cursor.rowcount

            # Hard cap
            count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM oidc_states WHERE tenant_id = ?",
                [self._ctx.tenant_id],
            ).fetchone()
            if count and count["cnt"] > self.OIDC_MAX_STATES:
                excess = count["cnt"] - self.OIDC_MAX_STATES
                conn.execute(
                    "DELETE FROM oidc_states WHERE state IN ("
                    "  SELECT state FROM oidc_states WHERE tenant_id = ? "
                    "  ORDER BY created_at LIMIT ?"
                    ")",
                    [self._ctx.tenant_id, excess],
                )
                deleted += excess

        return deleted

    # -- TD-3: TOTP replay cache ---------------------------------------------

    #: TOTP code reuse TTL in seconds (3 × 30s time steps).
    TOTP_REUSE_TTL: float = 90.0

    def is_totp_reused(self, username: str, code: str) -> bool:
        """Return True if *code* was already used by *username* recently."""
        cutoff = time.time() - self.TOTP_REUSE_TTL
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT 1 FROM totp_replay_cache "
            "WHERE username = ? AND totp_code = ? AND used_at > ? AND tenant_id = ?",
            [username, code, cutoff, self._ctx.tenant_id],
        ).fetchone()
        return row is not None

    def record_totp_use(self, username: str, code: str) -> None:
        """Record that *code* was successfully used by *username*."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT INTO totp_replay_cache "
                "(username, totp_code, used_at, tenant_id) VALUES (?, ?, ?, ?)",
                [username, code, time.time(), self._ctx.tenant_id],
            )

    def cleanup_totp_replay(self) -> int:
        """Delete expired TOTP replay entries. Returns count deleted."""
        cutoff = time.time() - self.TOTP_REUSE_TTL
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM totp_replay_cache WHERE used_at < ? AND tenant_id = ?",
                [cutoff, self._ctx.tenant_id],
            )
        return cursor.rowcount

    # -- Combined cleanup ----------------------------------------------------

    def cleanup_all(self) -> dict[str, int]:
        """Run all security state cleanup tasks. Returns counts by type."""
        return {
            "login_attempts": self.cleanup_login_attempts(),
            "account_lockout": self.cleanup_account_lockout(),
            "oidc_states": self.cleanup_oidc_states(),
            "totp_replay": self.cleanup_totp_replay(),
        }
