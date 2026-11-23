"""Tenant-bound failed webhook deliveries in the existing Bridge database.

Blocking methods: callers offload them, and never perform network I/O inside
these transactions. A lease fences local acknowledgement, not the receiver:
an expired/cancelled HTTP call can still arrive and be repeated. SQLite commit
provides process-restart recovery, not an initial-delivery or analysis outbox.
"""

from __future__ import annotations

import math
import secrets

from sigrift.bridge.storage.base import SharedContext

_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_retries (
    tenant_id TEXT NOT NULL,
    delivery_id TEXT NOT NULL,
    webhook_id TEXT NOT NULL,
    target_binding TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at REAL NOT NULL,
    due_at REAL NOT NULL,
    attempts INTEGER NOT NULL,
    last_error TEXT NOT NULL,
    lease_token TEXT,
    lease_until REAL,
    PRIMARY KEY (tenant_id, delivery_id)
);
CREATE INDEX IF NOT EXISTS idx_webhook_retry_due
    ON webhook_retries(tenant_id, due_at, lease_until);
CREATE TABLE IF NOT EXISTS webhook_retry_stats (
    tenant_id TEXT PRIMARY KEY,
    dropped INTEGER NOT NULL DEFAULT 0
);
"""


def _finite(value: float) -> float:
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Webhook retry time must be finite")
    return value


class WebhookRetryStore:
    """Bounded durable queue. Capacity rejects new work, never evicts a lease.

    The byte cap counts serialized payload bytes; it is not a Python-RAM bound.
    UTC wall times survive restart; a mis-set system clock can delay due work or
    expire a lease early. Startup never resets another worker's live leases.
    """

    def __init__(
        self,
        ctx: SharedContext,
        *,
        max_entries: int = 1000,
        max_bytes: int = 8 * 1024 * 1024,
        max_payload: int = 256 * 1024,
    ) -> None:
        self._ctx = ctx
        self._tenant = ctx.tenant_id
        self._max_entries = max(1, max_entries)
        self._max_bytes = max(1, max_bytes)
        self._max_payload = max(1, max_payload)
        conn = ctx.get_conn()
        if ctx.transaction_active:
            raise RuntimeError(
                "Webhook retry schema cannot nest in an existing transaction"
            )
        with ctx.write_lock:
            conn.executescript(_SCHEMA)
            conn.commit()

    def _drop(self, conn) -> None:
        conn.execute(
            "INSERT INTO webhook_retry_stats(tenant_id,dropped) VALUES (?,1) "
            "ON CONFLICT(tenant_id) DO UPDATE SET dropped=dropped+1",
            (self._tenant,),
        )

    def enqueue(
        self,
        delivery_id: str,
        webhook_id: str,
        target_binding: str,
        payload: bytes,
        *,
        now: float,
        delay: float,
    ) -> bool:
        now, delay = _finite(now), max(0, _finite(delay))
        if not isinstance(payload, bytes):
            raise TypeError("Serialized webhook payload must be bytes")
        if any(
            not isinstance(value, str) or not 1 <= len(value) <= 128
            for value in (delivery_id, webhook_id, target_binding)
        ):
            raise ValueError("Invalid bounded webhook delivery identity")
        with self._ctx.write_transaction(immediate=True) as conn:
            old = conn.execute(
                "SELECT webhook_id,target_binding,payload FROM webhook_retries "
                "WHERE tenant_id=? AND delivery_id=?",
                (self._tenant, delivery_id),
            ).fetchone()
            if old is not None:
                if tuple(old) != (webhook_id, target_binding, payload):
                    raise ValueError(
                        "Delivery identity was reused for different content"
                    )
                return True
            count, size = conn.execute(
                "SELECT COUNT(*),COALESCE(SUM(length(payload)),0) FROM webhook_retries "
                "WHERE tenant_id=?",
                (self._tenant,),
            ).fetchone()
            if (
                count >= self._max_entries
                or len(payload) > self._max_payload
                or size + len(payload) > self._max_bytes
            ):
                self._drop(conn)
                return False
            conn.execute(
                "INSERT INTO webhook_retries "
                "(tenant_id,delivery_id,webhook_id,target_binding,payload,created_at,"
                "due_at,attempts,last_error) VALUES (?,?,?,?,?,?,?,1,'delivery_failed')",
                (
                    self._tenant,
                    delivery_id,
                    webhook_id,
                    target_binding,
                    payload,
                    now,
                    now + delay,
                ),
            )
            return True

    def snapshot(self) -> dict:
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM webhook_retries WHERE tenant_id=? ORDER BY due_at,created_at,delivery_id",
            (self._tenant,),
        ).fetchall()
        stats = conn.execute(
            "SELECT dropped FROM webhook_retry_stats WHERE tenant_id=?",
            (self._tenant,),
        ).fetchone()
        return {
            "entries": [dict(row) for row in rows],
            "dropped": stats[0] if stats else 0,
        }

    def claim(self, *, now: float, lease_seconds: float) -> dict | None:
        now, seconds = _finite(now), _finite(lease_seconds)
        if seconds <= 0:
            raise ValueError("Lease must be positive")
        with self._ctx.write_transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT * FROM webhook_retries WHERE tenant_id=? AND due_at<=? "
                "AND (lease_token IS NULL OR lease_until<=?) "
                "ORDER BY due_at,created_at,delivery_id LIMIT 1",
                (self._tenant, now, now),
            ).fetchone()
            if row is None:
                return None
            entry = dict(row)
            entry.update(lease_token=secrets.token_hex(24), lease_until=now + seconds)
            conn.execute(
                "UPDATE webhook_retries SET lease_token=?,lease_until=? "
                "WHERE tenant_id=? AND delivery_id=?",
                (
                    entry["lease_token"],
                    entry["lease_until"],
                    self._tenant,
                    entry["delivery_id"],
                ),
            )
            return entry

    def _identity(self, entry: dict) -> tuple:
        # Never accept a caller's tenant as the authority.
        return self._tenant, entry["delivery_id"], entry["lease_token"]

    def renew(self, entry: dict, *, now: float, lease_seconds: float) -> bool:
        now, seconds = _finite(now), _finite(lease_seconds)
        if seconds <= 0:
            raise ValueError("Lease must be positive")
        with self._ctx.write_transaction(immediate=True) as conn:
            return (
                conn.execute(
                    "UPDATE webhook_retries SET lease_until=? WHERE tenant_id=? "
                    "AND delivery_id=? AND lease_token=? AND lease_until>?",
                    (now + seconds, *self._identity(entry), now),
                ).rowcount
                == 1
            )

    def release(self, entry: dict) -> bool:
        with self._ctx.write_transaction(immediate=True) as conn:
            return (
                conn.execute(
                    "UPDATE webhook_retries SET lease_token=NULL,lease_until=NULL "
                    "WHERE tenant_id=? AND delivery_id=? AND lease_token=?",
                    self._identity(entry),
                ).rowcount
                == 1
            )

    def ack(self, entry: dict, *, now: float, dropped: bool = False) -> bool:
        with self._ctx.write_transaction(immediate=True) as conn:
            changed = (
                conn.execute(
                    "DELETE FROM webhook_retries WHERE tenant_id=? AND delivery_id=? "
                    "AND lease_token=? AND lease_until>?",
                    (*self._identity(entry), _finite(now)),
                ).rowcount
                == 1
            )
            if changed and dropped:
                self._drop(conn)
            return changed

    def fail(
        self,
        entry: dict,
        *,
        now: float,
        delay: float,
        max_attempts: int,
        category: str,
    ) -> bool:
        now, delay = _finite(now), max(0, _finite(delay))
        if category not in {
            "http_error",
            "transport_error",
            "configuration_unavailable",
        }:
            raise ValueError("Unrecognized safe failure category")
        with self._ctx.write_transaction(immediate=True) as conn:
            row = conn.execute(
                "SELECT attempts FROM webhook_retries WHERE tenant_id=? "
                "AND delivery_id=? AND lease_token=? AND lease_until>?",
                (*self._identity(entry), now),
            ).fetchone()
            if row is None:
                return False
            attempts = row[0] + 1
            if attempts >= max_attempts:
                conn.execute(
                    "DELETE FROM webhook_retries WHERE tenant_id=? AND delivery_id=?",
                    (self._tenant, entry["delivery_id"]),
                )
                self._drop(conn)
            else:
                conn.execute(
                    "UPDATE webhook_retries SET attempts=?,last_error=?,due_at=?,"
                    "lease_token=NULL,lease_until=NULL WHERE tenant_id=? AND delivery_id=?",
                    (
                        attempts,
                        category,
                        now + delay,
                        self._tenant,
                        entry["delivery_id"],
                    ),
                )
            return True
