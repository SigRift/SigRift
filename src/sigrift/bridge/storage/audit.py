"""Audit log and dismissal tracking sub-store.

Provides persistent audit logging for operator actions (dismiss,
baseline, feedback, bulk operations) and efficient dismissal lookups.

Includes HMAC-SHA256 chain for tamper detection: each entry's HMAC
is computed over ``previous_hmac || action || target_id || operator
|| timestamp``, creating a hash chain that detects modifications,
deletions, and reordering.  The chain is scoped per-tenant so that
multi-tenant deployments have independent, non-interfering chains.

v2 HMAC entries additionally cover details, note, signal_class,
freq_hz, and node_id to prevent undetected tampering of those fields.

v3 (written for every new entry) also covers target_ids and tenant_id, and
length-prefixes every field.  v1 and v2 join fields with a bare ``|``, so
their encoding is not injective: text containing ``|`` can be moved between
adjacent fields of a v1/v2 row without changing its HMAC, and a v2 row's
target_ids can be rewritten.  Existing v1/v2 rows keep that weakness, since
stored rows are never rewritten; only v3 rows are protected against it.

No record version is stored: verification tries v3, then v2, then v1.  The
same versions are computed by the Rust gateway
(``sigrift-gateway-core/src/audit/chain.rs``), which shares this chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import sqlite3
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigrift.bridge.cache import CacheTag
from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)

# Sentinel used as previous_hmac when a legacy entry has no HMAC,
# preventing chain resets that could mask block-deletion attacks.
_LEGACY_NO_HMAC_SENTINEL = "LEGACY_NO_HMAC"

# The ``expected`` of a verification error for an entry whose HMAC does not
# match.  The computed digest is never reported (see ``verify_chain``); same
# text as the Rust gateway's ``HMAC_MISMATCH``.
_HMAC_MISMATCH = "HMAC of the entry's fields chained from its predecessor"

# The ``expected`` of a verification error for an entry without an HMAC that
# comes after a signed entry (its ``actual`` is the empty stored HMAC).  Both
# writers sign every entry, so only rows written before the chain existed,
# which come before its first signed entry, may have none.  Same text as the
# Rust gateway's ``HMAC_MISSING``.
_HMAC_MISSING = (
    "an HMAC: only entries before the chain's first signed entry may have none"
)

# Pin each development file's resolved key for this process. Re-reading a
# recovered/replaced file would otherwise silently change an active chain's key.
_DEV_AUDIT_SECRETS: dict[Path, bytes] = {}
_DEV_AUDIT_SECRET_LOCK = threading.Lock()


def _reset_dev_audit_lock_after_fork() -> None:
    # Other threads disappear in a child, potentially leaving their lock held.
    # Already resolved keys remain inherited, so existing chains still verify.
    global _DEV_AUDIT_SECRET_LOCK
    _DEV_AUDIT_SECRET_LOCK = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_dev_audit_lock_after_fork)


def _get_audit_secret() -> bytes:
    """Derive the HMAC secret for audit chain integrity.

    Resolution order:
    1. ``BRIDGE_AUDIT_KEY`` env var (preferred for production).
    2. Legacy ``BRIDGE_AUDIT_SECRET`` env var (backward compat).
    3. ``BRIDGE_MASTER_KEY`` env var (domain-separated derivation).
    4. Auto-generated key persisted to ``data/audit.key`` (created on
       first startup if none of the above are available).

    Development resolution is pinned per key-file path (derived from the resolved
    module location) until process restart, including when persistence fails.
    Filesystem recovery/replacement cannot change an active process's key.
    Configured credentials above retain precedence on every call. A deterministic
    hardcoded fallback is never used.
    """
    # 1. Preferred env var
    env_key = os.environ.get("BRIDGE_AUDIT_KEY", "").strip()
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()

    # 2. Legacy env var
    env_secret = os.environ.get("BRIDGE_AUDIT_SECRET", "").strip()
    if env_secret:
        return hashlib.sha256(env_secret.encode("utf-8")).digest()

    # 3. Master key from env var
    master_key = os.environ.get("BRIDGE_MASTER_KEY", "").strip()
    if master_key:
        return hashlib.sha256(
            b"bridge-audit-hmac:" + master_key.encode("utf-8")
        ).digest()

    # 4. Production mode: fail closed — no plaintext file fallback
    for _env_name in ("BRIDGE_ENV", "BRIDGE_MODE"):
        if os.environ.get(_env_name, "").strip().lower() in ("production", "prod"):
            raise RuntimeError(
                "No audit HMAC key configured and BRIDGE_ENV=production. "
                "Set BRIDGE_AUDIT_KEY or BRIDGE_MASTER_KEY env var."
            )

    # 5. Dev mode: auto-generated audit key file
    data_dir = Path(__file__).resolve().parent.parent / "data"
    audit_key_file = data_dir / "audit.key"
    with _DEV_AUDIT_SECRET_LOCK:
        if audit_key_file not in _DEV_AUDIT_SECRETS:
            _DEV_AUDIT_SECRETS[audit_key_file] = _load_dev_audit_secret(audit_key_file)
        return _DEV_AUDIT_SECRETS[audit_key_file]


def _load_dev_audit_secret(audit_key_file: Path) -> bytes:
    """Resolve once while the caller holds the development-key lock."""
    try:
        if audit_key_file.exists():
            stored = audit_key_file.read_text().strip()
            if stored:
                return hashlib.sha256(stored.encode("utf-8")).digest()
    except OSError:
        pass

    # Generate a new random key and persist it
    import secrets as _secrets

    try:
        audit_key_file.parent.mkdir(parents=True, exist_ok=True)
        random_key = _secrets.token_urlsafe(32)
        audit_key_file.write_text(random_key)
        os.chmod(str(audit_key_file), 0o600)
        logger.warning(
            "No audit HMAC key configured. Generated random key and saved "
            "to %s (mode 0600). Set BRIDGE_AUDIT_KEY env var in production.",
            audit_key_file,
        )
        return hashlib.sha256(random_key.encode("utf-8")).digest()
    except OSError as exc:
        logger.error(
            "Failed to write auto-generated audit key to %s: %s. "
            "Generating one ephemeral key for this path in this process "
            "(audit chain will NOT survive restarts). Filesystem recovery "
            "will not change this process's key.",
            audit_key_file,
            exc,
        )
        return hashlib.sha256(_secrets.token_bytes(32)).digest()


def _compute_hmac(
    secret: bytes,
    previous_hmac: str,
    action: str,
    target_id: str,
    operator: str,
    timestamp: str,
) -> str:
    """Compute v1 HMAC-SHA256 over the original chain fields."""
    payload = f"{previous_hmac}|{action}|{target_id}|{operator}|{timestamp}"
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _compute_hmac_v2(
    secret: bytes,
    previous_hmac: str,
    action: str,
    target_id: str,
    operator: str,
    timestamp: str,
    details: str,
    note: str,
    signal_class: str,
    freq_hz: str,
    node_id: str,
) -> str:
    """Compute v2 HMAC-SHA256 (verification of entries written before v3).

    v2 extends v1 by including details, note, signal_class, freq_hz,
    and node_id in the HMAC computation.  A ``v2`` version tag is embedded
    in the payload so that v1 and v2 digests never collide for the same
    row data.  It does not cover target_ids or tenant_id, and its ``|``
    join is ambiguous (see the module docstring); it must stay byte-for-byte
    unchanged so that existing v2 rows, and the Rust gateway's golden
    vectors, keep verifying.

    Returns:
        64-character hex digest (same length as v1 for storage compat).
    """
    payload = (
        f"v2|{previous_hmac}|{action}|{target_id}|{operator}|{timestamp}"
        f"|{details}|{note}|{signal_class}|{freq_hz}|{node_id}"
    )
    return hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def _hmac_v3_payload(*fields: str) -> bytes:
    """Encode the v3 HMAC input: ``v3`` then ``|<len>:<field>`` per field.

    ``<len>`` is the field's length in UTF-8 bytes (what Rust's ``str::len``
    returns), so the encoding is injective: no field's text can move into
    another one.  The ``v3|`` prefix cannot start a v2 payload (``v2|``) or a
    v1 payload, which starts with the previous HMAC (``""``, 64 hex digits
    or the legacy sentinel).
    """
    payload = bytearray(b"v3")
    for field in fields:
        # Fields are normally text, as stored.  str() runs on both paths: when
        # writing, it encodes any non-text value a caller passed (the entry
        # verifies only if the column reads it back as the same text); when
        # verifying, a column rewritten with another type makes that row fail
        # instead of breaking verification.
        data = str(field).encode("utf-8")
        payload += b"|%d:" % len(data)
        payload += data
    return bytes(payload)


def _compute_hmac_v3(
    secret: bytes,
    previous_hmac: str,
    action: str,
    target_id: str,
    operator: str,
    timestamp: str,
    details: str,
    note: str,
    signal_class: str,
    freq_hz: str,
    node_id: str,
    target_ids: str,
    tenant_id: str,
) -> str:
    """Compute the v3 HMAC-SHA256, the version written for new entries.

    Covers the v2 fields plus the stored ``target_ids`` text (bulk
    operations) and ``tenant_id``, with every field length-prefixed
    (:func:`_hmac_v3_payload`).

    Returns:
        64-character hex digest (same length as v1/v2 for storage compat).
    """
    payload = _hmac_v3_payload(
        previous_hmac,
        action,
        target_id,
        operator,
        timestamp,
        details,
        note,
        signal_class,
        freq_hz,
        node_id,
        target_ids,
        tenant_id,
    )
    return hmac.new(secret, payload, hashlib.sha256).hexdigest()


def _row_digests(
    secret: bytes, previous_hmac: str, row: sqlite3.Row, tenant_id: str
) -> Iterator[str]:
    """Yield the v3, v2 and v1 HMACs of a stored row chained from *previous_hmac*.

    NULL text columns read as ``""`` and NULL ``freq_hz`` as ``0.0``, exactly
    as every version has always been verified.
    """
    action = row["action"]
    target_id = row["target_id"]
    operator = row["operator"] or ""
    timestamp = row["timestamp"]
    details = row["details"] or ""
    note = row["note"] or ""
    signal_class = row["signal_class"] or ""
    freq_hz = str(row["freq_hz"] or 0.0)
    node_id = row["node_id"] or ""
    yield _compute_hmac_v3(
        secret,
        previous_hmac,
        action,
        target_id,
        operator,
        timestamp,
        details,
        note,
        signal_class,
        freq_hz,
        node_id,
        row["target_ids"] or "",
        tenant_id,
    )
    yield _compute_hmac_v2(
        secret,
        previous_hmac,
        action,
        target_id,
        operator,
        timestamp,
        details,
        note,
        signal_class,
        freq_hz,
        node_id,
    )
    yield _compute_hmac(secret, previous_hmac, action, target_id, operator, timestamp)


def _row_matches(
    secret: bytes, previous_hmac: str, row: sqlite3.Row, tenant_id: str, stored: str
) -> bool:
    """True if *stored* is the row's v3, v2 or v1 HMAC."""
    return any(
        hmac.compare_digest(digest, stored)
        for digest in _row_digests(secret, previous_hmac, row, tenant_id)
    )


def _stored_freq_hz(freq_hz: Any) -> float:
    """Return *freq_hz* as the ``REAL`` column will read it back.

    The HMAC is computed over ``str()`` of the value written and verified
    over ``str()`` of the value read back, so both must be the same float:
    ``0`` and ``433920000`` (ints) read back as ``0.0`` and ``433920000.0``,
    and ``-0.0`` as ``0.0``.  ``None`` and NaN, which used to be stored as
    NULL, are now stored (and returned) as ``0.0``, the value NULL verifies
    as; readers see ``0.0`` instead of ``None``.

    This fails closed: a value ``float()`` rejects (such as a non-numeric
    string, which used to be stored as TEXT) raises ``ValueError``, so the
    append and the caller's surrounding write transaction are rolled back.

    Rows that older code wrote with a non-float value (hashed as ``0``,
    ``None``, ``True``, ``nan``, ``-0.0``, ...) never verified and still do
    not; they need manual triage (``src/sigrift/bridge/UPGRADE.md``).
    """
    if freq_hz is None:
        return 0.0
    try:
        value = float(freq_hz)
    except (TypeError, ValueError) as exc:
        raise ValueError("audit freq_hz must be a number") from exc
    if math.isnan(value) or value == 0.0:
        return 0.0
    return value


def _stored_text(value: Any) -> Any:
    """Return a nullable text field as verification will read it back.

    A NULL text column is verified as ``""``, but ``None`` would be hashed as
    ``"None"``, so a genuine entry written with ``None`` would read as
    tampered.  ``None`` is therefore stored, hashed and returned as ``""``.
    """
    return "" if value is None else value


# The severity a details JSON object records, or NULL. Entries without details
# store '' (and older or tampered rows may hold NULL or invalid JSON), which
# json_extract rejects as malformed, so only valid JSON is read. CASE evaluates
# lazily; AND/OR are not guaranteed to short-circuit.
_DETAILS_SEVERITY = (
    "(CASE WHEN json_valid(details) THEN json_extract(details, '$.severity') END)"
)


def _severity_clause(severity: str) -> tuple[str, list[Any]]:
    """WHERE fragment and params for the audit severity filter.

    ``info`` matches entries without a severity (no details, no ``severity``
    key, or details that are not valid JSON) and those recording ``info``;
    any other value is an exact, bound match.
    """
    if severity == "info":
        return (
            f"({_DETAILS_SEVERITY} IS NULL OR {_DETAILS_SEVERITY} = 'info')",
            [],
        )
    return f"{_DETAILS_SEVERITY} = ?", [severity]


class AuditStore:
    """Manage the persistent audit log and dismissal state.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: SharedContext) -> None:
        self._ctx = ctx

    # -- Write --------------------------------------------------------------

    def log_audit(
        self,
        action: str,
        target_id: str,
        signal_class: str = "",
        freq_hz: float = 0.0,
        node_id: str = "",
        operator: str = "",
        note: str = "",
        details: dict | None = None,
        target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Write an entry to the persistent audit log.

        Parameters
        ----------
        action : str
            Action type (dismiss, baseline, feedback, bulk_dismiss, bulk_baseline).
        target_id : str
            Primary detection ID.
        signal_class : str
            Signal classification label.
        freq_hz : float
            Frequency in Hz.
        node_id : str
            Originating node identifier.
        operator : str
            Operator who performed the action.
        note : str
            Free-text note.
        details : dict or None
            Arbitrary metadata (stored as JSON).
        target_ids : list[str] or None
            Additional IDs for bulk operations (stored as JSON).

        Returns
        -------
        dict
            The audit entry.
        """
        with self._ctx.write_transaction(immediate=True) as conn:
            entry = self._log_audit_in_transaction(
                conn,
                action,
                target_id,
                signal_class,
                freq_hz,
                node_id,
                operator,
                note,
                details,
                target_ids,
            )
        self._after_commit(action, target_id)
        return entry

    def _after_commit(self, action: str, target_id: str) -> None:
        self._ctx.cache.invalidate_prefix(
            CacheTag.GET_AUDIT, CacheTag.GET_DISMISSED, CacheTag.IS_DISMISSED
        )
        logger.info("Audit: %s on %s", action, target_id)

    def _log_audit_in_transaction(
        self,
        conn: sqlite3.Connection,
        action: str,
        target_id: str,
        signal_class: str = "",
        freq_hz: float = 0.0,
        node_id: str = "",
        operator: str = "",
        note: str = "",
        details: dict | None = None,
        target_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """Append on this context's active, write-locked transaction.

        The caller owns commit/rollback and calls ``_after_commit`` only after
        success. No lock is reacquired: account changes and their audit event
        can share one transaction without deadlocking the non-reentrant lock.
        """
        if conn is not self._ctx.get_conn() or not conn.in_transaction:
            raise RuntimeError(
                "Audit append requires this context's active transaction"
            )
        now = datetime.now(timezone.utc).isoformat()
        ids_json = json.dumps(target_ids) if target_ids else ""
        details_json = json.dumps(details) if details else ""
        # Hash, store and return the values verification will read back.
        freq_hz = _stored_freq_hz(freq_hz)
        signal_class = _stored_text(signal_class)
        node_id = _stored_text(node_id)
        operator = _stored_text(operator)
        note = _stored_text(note)

        sql = """
            INSERT INTO audit_log
                (timestamp, action, target_id, target_ids, signal_class,
                 freq_hz, node_id, operator, note, details, tenant_id,
                 hmac_chain)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        # Fetch the previous HMAC to chain (scoped to this tenant
        # so multi-tenant deployments have independent chains).
        prev_row = conn.execute(
            "SELECT hmac_chain FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
            [self._ctx.tenant_id],
        ).fetchone()
        if prev_row is None:
            # First entry ever — no predecessor.
            previous_hmac = ""
        elif prev_row["hmac_chain"]:
            previous_hmac = prev_row["hmac_chain"]
        else:
            # Predecessor exists but has no HMAC (legacy pre-migration
            # row).  Use sentinel to prevent chain resets that could
            # mask block-deletion attacks.
            previous_hmac = _LEGACY_NO_HMAC_SENTINEL

        secret = _get_audit_secret()
        entry_hmac = _compute_hmac_v3(
            secret,
            previous_hmac,
            action,
            target_id,
            operator,
            now,
            details_json,
            note,
            signal_class,
            str(freq_hz),
            node_id,
            ids_json,
            self._ctx.tenant_id,
        )

        conn.execute(
            sql,
            [
                now,
                action,
                target_id,
                ids_json,
                signal_class,
                freq_hz,
                node_id,
                operator,
                note,
                details_json,
                self._ctx.tenant_id,
                entry_hmac,
            ],
        )
        return {
            "timestamp": now,
            "action": action,
            "target_id": target_id,
            "target_ids": target_ids or [],
            "signal_class": signal_class,
            "freq_hz": freq_hz,
            "node_id": node_id,
            "operator": operator,
            "note": note,
            "details": details or {},
        }

    # -- Read ---------------------------------------------------------------

    def get_audit_log(
        self,
        limit: int = 200,
        offset: int = 0,
        action: str | None = None,
        target_id: str | None = None,
        operator: str | None = None,
        node_id: str | None = None,
        search: str | None = None,
        start: str | None = None,
        end: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query the audit log with optional filters.

        Parameters
        ----------
        limit : int
            Maximum number of entries to return.
        offset : int
            Number of entries to skip (for pagination).
        action : str or None
            Filter by action type.
        target_id : str or None
            Filter by target detection ID.
        operator : str or None
            Filter by operator key ID.
        node_id : str or None
            Filter by node ID.
        search : str or None
            Search in note and target_id fields.
        start : str or None
            ISO timestamp lower bound (inclusive).
        end : str or None
            ISO timestamp upper bound (inclusive).

        Returns
        -------
        list[dict]
            Audit log entries, newest first.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause]
        params: list[Any] = list(tf_params)

        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if target_id is not None:
            clauses.append("target_id = ?")
            params.append(target_id)
        if operator is not None:
            clauses.append("operator = ?")
            params.append(operator)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if search is not None:
            # Escape SQL LIKE wildcards in user-provided search term
            escaped = (
                search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            clauses.append(
                "(note LIKE ? ESCAPE '\\' OR target_id LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\')"
            )
            pattern = f"%{escaped}%"
            params.extend([pattern, pattern, pattern])
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            params.append(end)
        if severity is not None:
            clause, values = _severity_clause(severity)
            clauses.append(clause)
            params.extend(values)

        where = " AND ".join(clauses)
        sql = f"""
            SELECT * FROM audit_log
            WHERE {where}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(sql, params).fetchall()
        results = []
        for r in rows:
            entry = dict(r)
            # Parse JSON fields
            if entry.get("target_ids"):
                try:
                    entry["target_ids"] = json.loads(entry["target_ids"])
                except (json.JSONDecodeError, TypeError):
                    entry["target_ids"] = []
            else:
                entry["target_ids"] = []
            if entry.get("details"):
                try:
                    entry["details"] = json.loads(entry["details"])
                except (json.JSONDecodeError, TypeError):
                    entry["details"] = {}
            else:
                entry["details"] = {}
            results.append(entry)
        return results

    def count_audit_log(
        self,
        action: str | None = None,
        target_id: str | None = None,
        operator: str | None = None,
        node_id: str | None = None,
        search: str | None = None,
        start: str | None = None,
        end: str | None = None,
        severity: str | None = None,
    ) -> int:
        """Return total count of audit entries matching the given filters."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses: list[str] = [tf_clause]
        params: list[Any] = list(tf_params)

        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if target_id is not None:
            clauses.append("target_id = ?")
            params.append(target_id)
        if operator is not None:
            clauses.append("operator = ?")
            params.append(operator)
        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if search is not None:
            escaped = (
                search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            clauses.append(
                "(note LIKE ? ESCAPE '\\' OR target_id LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\')"
            )
            pattern = f"%{escaped}%"
            params.extend([pattern, pattern, pattern])
        if start is not None:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end is not None:
            clauses.append("timestamp <= ?")
            params.append(end)
        if severity is not None:
            clause, values = _severity_clause(severity)
            clauses.append(clause)
            params.extend(values)

        where = " AND ".join(clauses)
        sql = f"SELECT COUNT(*) FROM audit_log WHERE {where}"
        conn = self._ctx.get_conn()
        row = conn.execute(sql, params).fetchone()
        return row[0] if row else 0

    def get_audit_actions(self) -> list[str]:
        """Return distinct action types in the audit log."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT DISTINCT action FROM audit_log WHERE {tf_clause} ORDER BY action",
            tf_params,
        ).fetchall()
        return [r["action"] for r in rows]

    def get_audit_operators(self) -> list[str]:
        """Return distinct operator key IDs in the audit log."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT DISTINCT operator FROM audit_log WHERE {tf_clause} AND operator != '' ORDER BY operator",
            tf_params,
        ).fetchall()
        return [r["operator"] for r in rows]

    def get_audit_node_ids(self) -> list[str]:
        """Return distinct node IDs in the audit log."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT DISTINCT node_id FROM audit_log WHERE {tf_clause} AND node_id != '' ORDER BY node_id",
            tf_params,
        ).fetchall()
        return [r["node_id"] for r in rows]

    def get_dismissed_ids(self) -> set[str]:
        """Return set of detection IDs that have been dismissed.

        Queries the audit log for dismiss and bulk_dismiss actions.

        Returns
        -------
        set[str]
            Dismissed detection IDs.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT DISTINCT target_id FROM audit_log WHERE {tf_clause} AND action IN ('dismiss', 'bulk_dismiss')",
            tf_params,
        ).fetchall()
        return {r["target_id"] for r in rows}

    def is_dismissed(self, detection_id: str) -> bool:
        """Check if a specific detection has been dismissed.

        Parameters
        ----------
        detection_id : str
            Detection ID to check.

        Returns
        -------
        bool
            True if the detection has a dismiss or bulk_dismiss audit entry.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        row = conn.execute(
            f"SELECT 1 FROM audit_log WHERE {tf_clause} AND target_id = ? AND action IN ('dismiss', 'bulk_dismiss') LIMIT 1",
            tf_params + [detection_id],
        ).fetchone()
        return row is not None

    # -- Archive ------------------------------------------------------------

    def archive_audit_log(self, max_age_days: int = 90) -> dict[str, Any]:
        """Archive old audit entries while preserving HMAC chain integrity.

        Entries older than *max_age_days* are deleted and replaced by
        an ``archive_marker`` row that records the terminal HMAC of the
        deleted block, keeping the chain verifiable.

        Archive markers are never deleted by subsequent archive calls.

        Returns
        -------
        dict
            ``{"archived_count": int, "terminal_hmac": str, "marker_id": int}``
        """
        cutoff = (
            datetime.now(timezone.utc)
            - __import__("datetime").timedelta(days=max_age_days)
        ).isoformat()

        with self._ctx.write_transaction(immediate=True) as conn:
            # Find old entries (exclude archive_marker so they survive)
            old_rows = conn.execute(
                "SELECT id, timestamp, hmac_chain FROM audit_log "
                "WHERE tenant_id = ? AND timestamp < ? AND action != 'archive_marker' "
                "ORDER BY id ASC",
                [self._ctx.tenant_id, cutoff],
            ).fetchall()

            if not old_rows:
                return {"archived_count": 0, "terminal_hmac": "", "marker_id": 0}

            # Terminal HMAC is the last entry's HMAC
            terminal_hmac = old_rows[-1]["hmac_chain"] or ""
            archived_count = len(old_rows)
            date_range = f"{old_rows[0]['timestamp']} — {old_rows[-1]['timestamp']}"
            old_ids = [r["id"] for r in old_rows]

            # Delete old entries
            placeholders = ",".join("?" * len(old_ids))
            conn.execute(
                f"DELETE FROM audit_log WHERE id IN ({placeholders})",
                old_ids,
            )

            # Insert archive marker with proper HMAC chain
            now = datetime.now(timezone.utc).isoformat()
            details_json = json.dumps(
                {
                    "archived_count": archived_count,
                    "terminal_hmac": terminal_hmac,
                    "date_range": date_range,
                }
            )

            # Find the predecessor HMAC for the marker
            prev_row = conn.execute(
                "SELECT hmac_chain FROM audit_log WHERE tenant_id = ? "
                "ORDER BY id DESC LIMIT 1",
                [self._ctx.tenant_id],
            ).fetchone()
            previous_hmac = ""
            if prev_row:
                previous_hmac = prev_row["hmac_chain"] or _LEGACY_NO_HMAC_SENTINEL

            secret = _get_audit_secret()
            marker_hmac = _compute_hmac_v3(
                secret,
                previous_hmac,
                "archive_marker",
                "",
                "",
                now,
                details_json,
                "",
                "",
                "0.0",
                "",
                "",
                self._ctx.tenant_id,
            )

            cursor = conn.execute(
                "INSERT INTO audit_log "
                "(timestamp, action, target_id, target_ids, signal_class, "
                "freq_hz, node_id, operator, note, details, tenant_id, hmac_chain) "
                "VALUES (?, 'archive_marker', '', '', '', 0.0, '', '', '', ?, ?, ?)",
                [now, details_json, self._ctx.tenant_id, marker_hmac],
            )
            marker_id = cursor.lastrowid
        self._ctx.cache.invalidate_prefix(CacheTag.GET_AUDIT)

        logger.info(
            "Audit archive: %d entries archived, marker id=%d",
            archived_count,
            marker_id,
        )
        return {
            "archived_count": archived_count,
            "terminal_hmac": terminal_hmac,
            "marker_id": marker_id,
        }

    # -- HMAC chain verification --------------------------------------------

    def verify_chain(self) -> dict[str, Any]:
        """Walk the current tenant's audit log and validate each entry's HMAC.

        The chain is scoped to the current tenant (``self._ctx.tenant_id``),
        so multi-tenant deployments have independent, non-interfering chains.

        Supports v1 (original fields only), v2 (adds details, note,
        signal_class, freq_hz and node_id) and v3 (adds target_ids and
        tenant_id, length-prefixed fields) entries.  No version is stored,
        so each entry is checked against v3, then v2, then v1, and chains
        holding older entries followed by newer ones still verify.

        An error's ``expected`` is a description (:data:`_HMAC_MISMATCH`),
        never a computed digest: that digest would be the valid HMAC of the
        entry's current, possibly tampered, content, and returning it from
        ``/api/admin/audit/verify`` would let anyone able to write the
        database re-sign the chain.

        Rows without an HMAC are accepted only before the chain's first
        signed entry: they were written before the chain existed.  Both
        writers sign every entry, so an unsigned entry after a signed one
        (or after an archived prefix that ended with a signed entry, whose
        terminal HMAC an ``archive_marker`` carries) was appended, or
        rewritten and its HMAC blanked, by someone without the key; it is
        reported with ``expected`` :data:`_HMAC_MISSING`.  The gateway's
        verifier applies the same rule.

        Also detects sequential ID gaps which may indicate deleted rows.

        Returns
        -------
        dict
            ``{"valid": bool, "total": int, "checked": int,
            "errors": list, "gaps": list}`` where each error is
            ``{"id": int, "expected": str, "actual": str}`` and each
            gap is ``{"after_id": int, "before_id": int,
            "missing": int}``.
        """
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT id, timestamp, action, target_id, operator, hmac_chain, "
            "details, note, signal_class, freq_hz, node_id, target_ids "
            "FROM audit_log WHERE tenant_id = ? ORDER BY id ASC",
            [self._ctx.tenant_id],
        ).fetchall()

        secret = _get_audit_secret()
        tenant_id = self._ctx.tenant_id
        errors: list[dict[str, Any]] = []
        gaps: list[dict[str, Any]] = []
        previous_hmac = ""
        checked = 0
        prev_id: int | None = None

        # Pre-scan for archive markers to collect terminal HMACs.
        # When entries were deleted by archive_audit_log, the surviving
        # entries' predecessors are gone.  The archive_marker stores the
        # terminal HMAC of the deleted block, which serves as a valid
        # chain root for the first surviving entry.
        archive_terminal_hmacs: set[str] = set()
        for row in rows:
            if row["action"] == "archive_marker":
                try:
                    details = json.loads(row["details"] or "{}")
                    th = details.get("terminal_hmac", "")
                    if th:
                        archive_terminal_hmacs.add(th)
                except (json.JSONDecodeError, TypeError):
                    pass

        # Whether the chain is signed by now: a signed entry was walked, or
        # an archived prefix ended with one (a marker's terminal HMAC that is
        # neither empty nor the sentinel a gateway archive of an unsigned
        # prefix hands on).
        signed = any(
            isinstance(th, str) and th != _LEGACY_NO_HMAC_SENTINEL
            for th in archive_terminal_hmacs
        )

        for row in rows:
            row_id = row["id"]

            # --- Gap detection: look for non-sequential IDs ---
            # SEC-M7: In multi-tenant mode, other tenants' rows occupy
            # intermediate IDs, so we only flag gaps when there are
            # genuinely missing rows for THIS tenant.  Check whether any
            # rows between prev_id and row_id belong to other tenants.
            if prev_id is not None and row_id != prev_id + 1:
                # Count rows in the gap belonging to OTHER tenants
                other_count = conn.execute(
                    "SELECT COUNT(*) FROM audit_log "
                    "WHERE id > ? AND id < ? AND tenant_id != ?",
                    [prev_id, row_id, self._ctx.tenant_id],
                ).fetchone()[0]
                expected_gap = row_id - prev_id - 1
                unexplained = expected_gap - other_count
                if unexplained > 0:
                    gaps.append(
                        {
                            "after_id": prev_id,
                            "before_id": row_id,
                            "missing": unexplained,
                        }
                    )
                    logger.warning(
                        "Audit chain gap detected: %d row(s) missing between "
                        "id %d and id %d",
                        unexplained,
                        prev_id,
                        row_id,
                    )
            prev_id = row_id

            stored_hmac = row["hmac_chain"] or ""
            # An entry without an HMAC: skipped before the chain's first
            # signed entry (a pre-chain row), reported after it.  Either way
            # the next entry chains from the sentinel (as log_audit chains
            # it), never from "", so a chain reset cannot mask a deletion.
            if not stored_hmac:
                if signed:
                    checked += 1
                    errors.append(
                        {"id": row_id, "expected": _HMAC_MISSING, "actual": ""}
                    )
                previous_hmac = _LEGACY_NO_HMAC_SENTINEL
                continue
            signed = True

            # No version is stored: accept the row's v3, v2 or v1 HMAC,
            # chained from its predecessor or, since that may have been
            # archived, from an archive marker's terminal HMAC.
            checked += 1
            if not any(
                _row_matches(secret, root, row, tenant_id, stored_hmac)
                for root in (previous_hmac, *archive_terminal_hmacs)
            ):
                errors.append(
                    {"id": row_id, "expected": _HMAC_MISMATCH, "actual": stored_hmac}
                )

            previous_hmac = stored_hmac

        if gaps:
            logger.warning(
                "Audit chain verification found %d ID gap(s) — possible row deletion",
                len(gaps),
            )

        return {
            "valid": len(errors) == 0 and len(gaps) == 0,
            "total": len(rows),
            "checked": checked,
            "errors": errors,
            "gaps": gaps,
        }
