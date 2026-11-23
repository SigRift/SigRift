"""Claims for post-ingest work, shared by every bridge process (contract K8b).

The post-ingest work for a detection (alert rules, watch bands, anomaly
alerts, webhooks, ``protocol_decode`` jobs) must run once, whichever
bridge worker process (``BRIDGE_WORKERS`` > 1) or restart sees it, and
however often the gateway delivers its ingest hook (it retries, and
re-sends what it spooled across a restart).  In-process memory cannot
promise that, so the claims live in ``detections.db``, which every worker
(and the gateway) shares.  A claim is one ``INSERT OR IGNORE`` into a
table with a unique key: the process whose insert changes a row owns the
work, every other one finds the row and skips it.

Tables (created here with ``CREATE TABLE IF NOT EXISTS``, not by a
numbered migration — they hold nothing that must survive a rebuild):

``ingest_hook_claims``
    one row per ``(node_id, detection_id)`` the ingest hook processed,
    kept for a TTL (see ``routers/internal.py``) and capped in count.
``protocol_decode_claims``
    one row per detection a ``protocol_decode`` job was queued for, by
    the IQ upload route or by post-ingest, whichever came first.
``iq_capture_requests``
    the signal class an operator named when tasking a node with a manual
    IQ capture, keyed by the capture command's id, so the capture's stub
    detection gets that class (and a decode) when the node uploads it.

Every method is blocking (SQLite): async callers use ``asyncio.to_thread``.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterable

from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ingest_hook_claims (
    node_id      TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    claimed_at   REAL NOT NULL,
    UNIQUE (node_id, detection_id)
);
CREATE INDEX IF NOT EXISTS idx_ingest_hook_claims_at
    ON ingest_hook_claims (claimed_at);

CREATE TABLE IF NOT EXISTS protocol_decode_claims (
    detection_id TEXT NOT NULL UNIQUE,
    claimed_at   REAL NOT NULL,
    source       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_protocol_decode_claims_at
    ON protocol_decode_claims (claimed_at);

CREATE TABLE IF NOT EXISTS iq_capture_requests (
    command_id   TEXT NOT NULL UNIQUE,
    node_id      TEXT NOT NULL,
    signal_class TEXT NOT NULL,
    created_at   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_iq_capture_requests_at
    ON iq_capture_requests (created_at);
"""

#: A protocol_decode claim is kept this long (seconds): longer than any
#: capture is kept (IQ cleanup defaults to 7 days), so a detection is
#: never decoded twice while its IQ exists.
DECODE_CLAIM_TTL = 8 * 86_400.0
DECODE_CLAIM_MAX = 200_000
#: A capture request outlives the command lease and the upload by far.
CAPTURE_REQUEST_TTL = 86_400.0
CAPTURE_REQUEST_MAX = 10_000

#: The count caps are enforced (one COUNT and one DELETE) every this many
#: new rows per process; the TTL deletes run on every claim.
_TRIM_EVERY = 1000


class IngestClaimStore:
    """Cross-process claims in ``detections.db`` (see the module docstring)."""

    def __init__(self, ctx: SharedContext) -> None:
        self._ctx = ctx
        self._new_rows: dict[str, int] = {}
        conn = ctx.get_conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    # -- Count caps ---------------------------------------------------------

    def _trim(
        self,
        conn: sqlite3.Connection,
        table: str,
        column: str,
        max_rows: int,
        added: int,
        force: bool = False,
    ) -> None:
        """Delete the oldest rows of *table* beyond *max_rows* (amortized)."""
        pending = self._new_rows.get(table, 0) + added
        if not force and pending < _TRIM_EVERY:
            self._new_rows[table] = pending
            return
        self._new_rows[table] = 0
        (count,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        excess = count - max(1, max_rows)
        if excess > 0:
            conn.execute(
                f"DELETE FROM {table} WHERE rowid IN ("
                f"SELECT rowid FROM {table} ORDER BY {column}, rowid LIMIT ?)",
                (excess,),
            )

    # -- Ingest hook (routers/internal.py) ------------------------------------

    def claim_hook_detections(
        self,
        node_id: str,
        detection_ids: Iterable[str],
        *,
        now: float,
        ttl: float,
        max_rows: int,
    ) -> set[str]:
        """Claim ``(node_id, id)`` for each id; return the ids claimed now.

        Claims older than *ttl* seconds are dropped first (so a detection
        can be claimed again once its claim expired), and at most about
        *max_rows* claims are kept (oldest dropped first).  One transaction
        that takes the write lock up front: another process claiming the
        same ids waits for it and then finds them taken.
        """
        fresh: set[str] = set()
        with self._ctx.write_transaction(immediate=True) as conn:
            conn.execute(
                "DELETE FROM ingest_hook_claims WHERE claimed_at <= ?", (now - ttl,)
            )
            for det_id in detection_ids:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ingest_hook_claims "
                    "(node_id, detection_id, claimed_at) VALUES (?, ?, ?)",
                    (node_id, det_id, now),
                )
                if cur.rowcount == 1:
                    fresh.add(det_id)
            self._trim(conn, "ingest_hook_claims", "claimed_at", max_rows, len(fresh))
        return fresh

    def hook_claim_count(self) -> int:
        """Number of ingest-hook claims currently kept."""
        conn = self._ctx.get_conn()
        (count,) = conn.execute("SELECT COUNT(*) FROM ingest_hook_claims").fetchone()
        return int(count)

    def trim_hook_claims(self, max_rows: int) -> None:
        """Enforce the ingest-hook claim cap now (tests, maintenance)."""
        with self._ctx.write_transaction(immediate=True) as conn:
            self._trim(
                conn, "ingest_hook_claims", "claimed_at", max_rows, 0, force=True
            )

    # -- protocol_decode jobs (decode_pipeline.queue_protocol_decode_once) ----

    def claim_decode(self, detection_id: str, *, now: float, source: str = "") -> bool:
        """Claim the protocol_decode of *detection_id*; False if claimed already."""
        with self._ctx.write_transaction(immediate=True) as conn:
            conn.execute(
                "DELETE FROM protocol_decode_claims WHERE claimed_at <= ?",
                (now - DECODE_CLAIM_TTL,),
            )
            cur = conn.execute(
                "INSERT OR IGNORE INTO protocol_decode_claims "
                "(detection_id, claimed_at, source) VALUES (?, ?, ?)",
                (detection_id, now, source[:32]),
            )
            claimed = cur.rowcount == 1
            self._trim(
                conn,
                "protocol_decode_claims",
                "claimed_at",
                DECODE_CLAIM_MAX,
                int(claimed),
            )
        return claimed

    def release_decode(self, detection_id: str) -> None:
        """Drop the decode claim of *detection_id* (its job could not be queued)."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "DELETE FROM protocol_decode_claims WHERE detection_id = ?",
                (detection_id,),
            )

    def decode_claimed(self, detection_id: str) -> bool:
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT 1 FROM protocol_decode_claims WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        return row is not None

    # -- Manual IQ capture requests (routers/nodes.py, routers/detection_iq.py)

    def record_capture_request(
        self, command_id: str, node_id: str, signal_class: str, *, now: float
    ) -> None:
        """Remember the signal class of the capture command *command_id*."""
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "DELETE FROM iq_capture_requests WHERE created_at <= ?",
                (now - CAPTURE_REQUEST_TTL,),
            )
            conn.execute(
                "INSERT OR REPLACE INTO iq_capture_requests "
                "(command_id, node_id, signal_class, created_at) VALUES (?, ?, ?, ?)",
                (command_id, node_id, signal_class, now),
            )
            self._trim(
                conn, "iq_capture_requests", "created_at", CAPTURE_REQUEST_MAX, 1
            )

    def capture_request_class(self, command_id: str, node_id: str) -> str | None:
        """The signal class capture *command_id* for *node_id* was tasked with."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT signal_class FROM iq_capture_requests "
            "WHERE command_id = ? AND node_id = ?",
            (command_id, node_id),
        ).fetchone()
        return str(row[0]) if row is not None else None


def get_ingest_claims(state: object) -> IngestClaimStore | None:
    """The app's :class:`IngestClaimStore`, created on first use.

    ``state`` is ``app.state``; the store shares the detection store's
    database.  ``None`` when the app has no detection store.
    """
    claims = getattr(state, "ingest_claims", None)
    if claims is not None:
        return claims
    store = getattr(state, "detection_store", None)
    ctx = getattr(store, "_ctx", None)
    if not isinstance(ctx, SharedContext):
        return None
    claims = IngestClaimStore(ctx)
    try:
        setattr(state, "ingest_claims", claims)
    except AttributeError:
        pass
    return claims
