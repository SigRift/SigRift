"""Decoded protocol message storage (``decoded_messages`` table).

Holds the messages produced by the bridge's protocol decode pipeline
(``decode_pipeline.ProtocolDecodePipeline``) and the edge-decoded messages
that nodes attach to detection batches.  Both producers emit the same
record shape, which is the column set below.

The table is created here (``CREATE TABLE IF NOT EXISTS``) rather than in
a numbered migration; an existing table with fewer columns (from an older
build) is used as-is, writing only the columns it has.  Records come from
edge nodes, so every field is type-checked and length-bounded, and the
table is capped at ``BRIDGE_DECODED_MAX_ROWS`` rows (default 200 000,
oldest removed first).  A row's ``tenant_id`` is always the store's own
(its ``SharedContext``), whatever the record names.
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import datetime, timezone
from typing import Any, Iterable

from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decoded_messages (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id      TEXT,
    protocol          TEXT NOT NULL,
    source_id         TEXT,
    dest_id           TEXT,
    message_type      TEXT,
    payload_hex       TEXT,
    payload_length    INTEGER,
    encrypted         INTEGER NOT NULL DEFAULT 0,
    decrypted_payload TEXT,
    key_id            TEXT,
    gps_lat           REAL,
    gps_lon           REAL,
    confidence        REAL,
    freq_hz           REAL,
    node_id           TEXT,
    text              TEXT,
    metadata          TEXT,
    timestamp         TEXT NOT NULL,
    tenant_id         TEXT NOT NULL DEFAULT 'default'
);
"""
# column -> index, created only when the (possibly older) table has it.
_INDEXES = {
    "detection_id": "CREATE INDEX IF NOT EXISTS idx_decoded_messages_detection "
    "ON decoded_messages (detection_id)",
    "timestamp": "CREATE INDEX IF NOT EXISTS idx_decoded_messages_timestamp "
    "ON decoded_messages (timestamp)",
}

# Column -> max length for text columns.
_TEXT_LIMITS: dict[str, int] = {
    "detection_id": 128,
    "protocol": 32,
    "source_id": 128,
    "dest_id": 128,
    "message_type": 64,
    "payload_hex": 16384,
    "decrypted_payload": 32768,
    "key_id": 128,
    "node_id": 128,
    "text": 2048,
    "metadata": 16384,
    "timestamp": 64,
}
_REAL_COLUMNS = ("gps_lat", "gps_lon", "confidence", "freq_hz")

_DEFAULT_MAX_ROWS = 200_000
# Enforce the row cap every this many inserts (one cheap DELETE).
_PRUNE_EVERY = 500


def _text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        if isinstance(value, (bytes, bytearray)):
            value = bytes(value).hex()
        elif isinstance(value, (dict, list)):
            value = json.dumps(value, default=str)
        else:
            value = str(value)
    return value[:limit]


def _real(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


class DecodedMessageStore:
    """Persist decoded protocol messages.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    max_rows : int or None
        Row cap; ``None`` reads ``BRIDGE_DECODED_MAX_ROWS``.
    """

    def __init__(self, ctx: SharedContext, max_rows: int | None = None) -> None:
        self._ctx = ctx
        if max_rows is None:
            try:
                max_rows = int(
                    os.environ.get("BRIDGE_DECODED_MAX_ROWS", _DEFAULT_MAX_ROWS)
                )
            except ValueError:
                max_rows = _DEFAULT_MAX_ROWS
        self._max_rows = max(1, max_rows)
        self._inserts_since_prune = 0
        conn = ctx.get_conn()
        conn.executescript(_SCHEMA)
        self._columns = frozenset(
            row[1] for row in conn.execute("PRAGMA table_info(decoded_messages)")
        )
        for column, ddl in _INDEXES.items():
            if column in self._columns:
                conn.execute(ddl)
        conn.commit()

    def _row(self, record: dict[str, Any]) -> dict[str, Any]:
        protocol = _text(record.get("protocol"), _TEXT_LIMITS["protocol"])
        if not protocol:
            raise ValueError("decoded message needs a protocol")
        row: dict[str, Any] = {}
        for column, limit in _TEXT_LIMITS.items():
            row[column] = _text(record.get(column), limit)
        row["protocol"] = protocol
        for column in _REAL_COLUMNS:
            row[column] = _real(record.get(column))
        length = record.get("payload_length")
        length = _real(length) if isinstance(length, (int, float)) else None
        row["payload_length"] = (
            int(length) if length is not None and abs(length) < 2**53 else None
        )
        row["encrypted"] = 1 if record.get("encrypted") else 0
        if not row["timestamp"]:
            row["timestamp"] = datetime.now(timezone.utc).isoformat()
        # The store's own tenant, never one the record names: records come
        # from edge nodes, and a row written under another tenant would land
        # in that tenant's view (and drop out of this one).
        row["tenant_id"] = self._ctx.tenant_id
        return {k: v for k, v in row.items() if k in self._columns}

    def store_message(self, record: dict[str, Any]) -> int:
        """Insert one decoded message; return its row id.

        Raises ``ValueError`` for a record without a protocol.
        """
        row = self._row(record)
        columns = ", ".join(row)
        placeholders = ", ".join("?" for _ in row)
        with self._ctx.write_transaction() as conn:
            cur = conn.execute(
                f"INSERT INTO decoded_messages ({columns}) VALUES ({placeholders})",
                list(row.values()),
            )
            msg_id = int(cur.lastrowid)
            self._inserts_since_prune += 1
            if self._inserts_since_prune >= _PRUNE_EVERY:
                self._inserts_since_prune = 0
                self._prune(conn)
        return msg_id

    def store_messages(self, records: Iterable[dict[str, Any]]) -> list[int | None]:
        """Insert many decoded messages in one write transaction.

        Returns one entry per record, in order: the new row id, or ``None``
        for a record that was skipped because it is not a valid message (no
        protocol, not a dict).  Blocking: async callers should run it with
        ``asyncio.to_thread``.
        """
        rows: list[dict[str, Any] | None] = []
        for record in records:
            try:
                rows.append(self._row(record) if isinstance(record, dict) else None)
            except (ValueError, TypeError, OverflowError):
                rows.append(None)
        ids: list[int | None] = []
        if not any(row is not None for row in rows):
            return [None] * len(rows)
        with self._ctx.write_transaction() as conn:
            for row in rows:
                if row is None:
                    ids.append(None)
                    continue
                cur = conn.execute(
                    f"INSERT INTO decoded_messages ({', '.join(row)}) "
                    f"VALUES ({', '.join('?' for _ in row)})",
                    list(row.values()),
                )
                ids.append(int(cur.lastrowid))
            self._inserts_since_prune += sum(1 for i in ids if i is not None)
            if self._inserts_since_prune >= _PRUNE_EVERY:
                self._inserts_since_prune = 0
                self._prune(conn)
        return ids

    def _prune(self, conn: Any) -> None:
        """Delete the oldest rows beyond the row cap (inside a transaction)."""
        cur = conn.execute(
            "DELETE FROM decoded_messages WHERE id <= ("
            "  SELECT id FROM decoded_messages ORDER BY id DESC LIMIT 1 OFFSET ?"
            ")",
            (self._max_rows,),
        )
        if cur.rowcount:
            logger.info(
                "Decoded messages: removed %d oldest rows (cap %d)",
                cur.rowcount,
                self._max_rows,
            )

    def get_messages(
        self,
        detection_id: str | None = None,
        protocol: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return the newest messages, optionally for one detection / protocol."""
        tf_clause, tf_params = self._ctx.tenant_filter()
        clauses = [tf_clause]
        params: list[Any] = list(tf_params)
        if detection_id is not None:
            clauses.append("detection_id = ?")
            params.append(detection_id)
        if protocol is not None:
            clauses.append("protocol = ?")
            params.append(protocol)
        params.append(max(1, min(int(limit), 1000)))
        rows = (
            self._ctx.get_conn()
            .execute(
                f"SELECT * FROM decoded_messages WHERE {' AND '.join(clauses)} "
                "ORDER BY id DESC LIMIT ?",
                params,
            )
            .fetchall()
        )
        return [dict(r) for r in rows]

    def count(self) -> int:
        """Return the number of stored messages (all tenants)."""
        row = (
            self._ctx.get_conn()
            .execute("SELECT COUNT(*) FROM decoded_messages")
            .fetchone()
        )
        return int(row[0])
