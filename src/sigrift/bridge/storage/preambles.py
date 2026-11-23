"""Preamble / sync-word storage sub-store.

SQLite-backed storage for user-defined sync patterns and preamble
detection results.  Uses the SharedContext pattern for thread-safe
database access.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_PREAMBLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sync_patterns (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    bits_hex    TEXT NOT NULL,
    protocol    TEXT NOT NULL,
    modulation  TEXT NOT NULL DEFAULT 'bpsk',
    description TEXT DEFAULT '',
    chip_rate   REAL,
    created_at  TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS preamble_detections (
    id                  TEXT PRIMARY KEY,
    detection_id        TEXT,
    pattern_name        TEXT NOT NULL,
    protocol            TEXT NOT NULL,
    sample_offset       INTEGER NOT NULL,
    correlation_peak    REAL NOT NULL,
    confidence          REAL NOT NULL,
    estimated_symbol_rate REAL,
    created_at          TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_preamble_det_detection_id
    ON preamble_detections (detection_id) WHERE detection_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_preamble_det_pattern
    ON preamble_detections (pattern_name);
CREATE INDEX IF NOT EXISTS idx_preamble_det_created
    ON preamble_detections (created_at);
"""


class PreambleStore:
    """Preamble / sync-word storage backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._ensure_table()

    def _ensure_table(self) -> None:
        with self._ctx.transaction() as conn:
            conn.executescript(_PREAMBLE_SCHEMA)

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _bits_to_hex(bits: list[int]) -> str:
        """Convert a list of 0/1 bits to a hex string."""
        # Pad to multiple of 4
        padded = list(bits)
        while len(padded) % 4 != 0:
            padded.append(0)
        hex_chars = []
        for i in range(0, len(padded), 4):
            nibble = (
                (padded[i] << 3)
                | (padded[i + 1] << 2)
                | (padded[i + 2] << 1)
                | padded[i + 3]
            )
            hex_chars.append(f"{nibble:x}")
        return "".join(hex_chars)

    @staticmethod
    def _hex_to_bits(hex_str: str) -> list[int]:
        """Convert a hex string back to a list of 0/1 bits."""
        bits: list[int] = []
        for ch in hex_str:
            val = int(ch, 16)
            bits.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
        return bits

    # -- Pattern CRUD -------------------------------------------------------

    def add_pattern(
        self,
        pattern_id: str,
        name: str,
        bits: list[int],
        protocol: str,
        modulation: str = "bpsk",
        description: str = "",
        chip_rate: float | None = None,
    ) -> None:
        """Store a user-defined sync pattern."""
        bits_hex = self._bits_to_hex(bits)
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sync_patterns "
                "(id, name, bits_hex, protocol, modulation, description, chip_rate, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pattern_id,
                    name,
                    bits_hex,
                    protocol,
                    modulation,
                    description,
                    chip_rate,
                    now,
                ),
            )

    def get_pattern(self, pattern_id: str) -> dict[str, Any] | None:
        """Return a single pattern by ID, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM sync_patterns WHERE id = ?", (pattern_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_pattern(row)

    def list_patterns(self) -> list[dict[str, Any]]:
        """Return all user-defined patterns."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM sync_patterns ORDER BY created_at DESC"
        ).fetchall()
        return [self._row_to_pattern(r) for r in rows]

    def delete_pattern(self, pattern_id: str) -> bool:
        """Delete a pattern by ID.  Returns True if deleted."""
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM sync_patterns WHERE id = ?", (pattern_id,)
            )
        return cursor.rowcount > 0

    def _row_to_pattern(self, row: Any) -> dict[str, Any]:
        d = dict(row)
        d["bits"] = self._hex_to_bits(d.pop("bits_hex"))
        return d

    # -- Detection results --------------------------------------------------

    def store_detection(
        self,
        det_id: str,
        detection_id: str | None,
        pattern_name: str,
        protocol: str,
        sample_offset: int,
        correlation_peak: float,
        confidence: float,
        estimated_symbol_rate: float | None = None,
    ) -> None:
        """Store a preamble detection result."""
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO preamble_detections "
                "(id, detection_id, pattern_name, protocol, sample_offset, "
                "correlation_peak, confidence, estimated_symbol_rate, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    det_id,
                    detection_id,
                    pattern_name,
                    protocol,
                    sample_offset,
                    correlation_peak,
                    confidence,
                    estimated_symbol_rate,
                    now,
                ),
            )

    def get_detections_for(self, detection_id: str) -> list[dict[str, Any]]:
        """Return all preamble detections for a given detection_id."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM preamble_detections WHERE detection_id = ? "
            "ORDER BY correlation_peak DESC",
            (detection_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_detections(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Return preamble detections with pagination."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM preamble_detections "
            "ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    # -- Stats --------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return preamble statistics."""
        conn = self._ctx.get_conn()

        pat_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM sync_patterns"
        ).fetchone()["cnt"]

        det_count = conn.execute(
            "SELECT COUNT(*) as cnt FROM preamble_detections"
        ).fetchone()["cnt"]

        by_protocol_rows = conn.execute(
            "SELECT protocol, COUNT(*) as cnt FROM preamble_detections GROUP BY protocol"
        ).fetchall()
        by_protocol = {r["protocol"]: r["cnt"] for r in by_protocol_rows}

        by_pattern_rows = conn.execute(
            "SELECT pattern_name, COUNT(*) as cnt FROM preamble_detections "
            "GROUP BY pattern_name ORDER BY cnt DESC LIMIT 20"
        ).fetchall()
        by_pattern = {r["pattern_name"]: r["cnt"] for r in by_pattern_rows}

        return {
            "custom_patterns": pat_count,
            "total_detections": det_count,
            "by_protocol": by_protocol,
            "by_pattern": by_pattern,
        }
