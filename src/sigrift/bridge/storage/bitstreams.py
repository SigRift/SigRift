"""Bitstream extraction storage sub-store.

SQLite-backed storage for PSK bitstream extraction results,
following the SharedContext pattern from fingerprints.py.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_BITSTREAM_SCHEMA = """
CREATE TABLE IF NOT EXISTS bitstream_extractions (
    id TEXT PRIMARY KEY,
    detection_id TEXT,
    signal_class TEXT NOT NULL,
    bits_hex TEXT NOT NULL,
    n_bits INTEGER NOT NULL,
    symbol_rate REAL,
    snr_estimate REAL,
    confidence REAL,
    modulation TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_bs_detection_id
    ON bitstream_extractions (detection_id) WHERE detection_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_bs_modulation
    ON bitstream_extractions (modulation);
CREATE INDEX IF NOT EXISTS idx_bs_created_at
    ON bitstream_extractions (created_at);
"""


class BitstreamStore:
    """Bitstream extraction operations backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create the bitstream_extractions table if it does not exist."""
        with self._ctx.transaction() as conn:
            conn.executescript(_BITSTREAM_SCHEMA)

    # -- Write operations ---------------------------------------------------

    def store_extraction(
        self,
        extraction_id: str,
        detection_id: str | None,
        signal_class: str,
        bits_hex: str,
        n_bits: int,
        modulation: str,
        symbol_rate: float | None = None,
        snr_estimate: float | None = None,
        confidence: float | None = None,
    ) -> None:
        """Insert a bitstream extraction result.

        Parameters
        ----------
        extraction_id : str
            Unique extraction ID (UUID hex).
        detection_id : str or None
            Associated detection ID (nullable for raw uploads).
        signal_class : str
            Signal classification label.
        bits_hex : str
            Hex-encoded bitstream.
        n_bits : int
            Number of bits extracted.
        modulation : str
            Modulation type used for extraction.
        symbol_rate : float or None
            Estimated or provided symbol rate.
        snr_estimate : float or None
            Estimated SNR in dB.
        confidence : float or None
            Extraction confidence 0-1.
        """
        now = datetime.now(timezone.utc).isoformat()

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO bitstream_extractions
                    (id, detection_id, signal_class, bits_hex, n_bits,
                     symbol_rate, snr_estimate, confidence, modulation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    extraction_id,
                    detection_id,
                    signal_class,
                    bits_hex,
                    n_bits,
                    symbol_rate,
                    snr_estimate,
                    confidence,
                    modulation,
                    now,
                ),
            )
        logger.debug(
            "Bitstream extraction stored: %s (mod=%s, %d bits)",
            extraction_id,
            modulation,
            n_bits,
        )

    # -- Read operations ----------------------------------------------------

    def get_extraction(self, extraction_id: str) -> dict[str, Any] | None:
        """Return a single extraction by ID, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM bitstream_extractions WHERE id = ?",
            (extraction_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_by_detection(self, detection_id: str) -> list[dict[str, Any]]:
        """Return all extractions for a given detection ID."""
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM bitstream_extractions WHERE detection_id = ? "
            "ORDER BY created_at DESC",
            (detection_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_extractions(
        self,
        modulation: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List extractions with optional filters.

        Parameters
        ----------
        modulation : str or None
            Filter by modulation type.
        limit : int
            Maximum results.
        offset : int
            Pagination offset.

        Returns
        -------
        list[dict]
            Matching extractions, ordered by created_at DESC.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if modulation is not None:
            clauses.append("modulation = ?")
            params.append(modulation)

        where = " AND ".join(clauses) if clauses else "1=1"
        params.extend([limit, offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM bitstream_extractions WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    # -- Delete -------------------------------------------------------------

    def delete_extraction(self, extraction_id: str) -> bool:
        """Delete an extraction by ID.

        Returns
        -------
        bool
            True if a row was deleted.
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM bitstream_extractions WHERE id = ?",
                (extraction_id,),
            )
        return cursor.rowcount > 0

    # -- Stats --------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return bitstream extraction statistics.

        Returns
        -------
        dict
            Keys: total, by_modulation (count per modulation type),
            avg_confidence, total_bits.
        """
        conn = self._ctx.get_conn()

        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM bitstream_extractions"
        ).fetchone()
        total = total_row["cnt"] if total_row else 0

        mod_rows = conn.execute(
            "SELECT modulation, COUNT(*) as cnt "
            "FROM bitstream_extractions GROUP BY modulation"
        ).fetchall()
        by_modulation = {r["modulation"]: r["cnt"] for r in mod_rows}

        avg_row = conn.execute(
            "SELECT AVG(confidence) as avg_conf, SUM(n_bits) as total_bits "
            "FROM bitstream_extractions"
        ).fetchone()
        avg_confidence = (
            round(avg_row["avg_conf"], 4)
            if avg_row and avg_row["avg_conf"] is not None
            else 0.0
        )
        total_bits = (
            avg_row["total_bits"]
            if avg_row and avg_row["total_bits"] is not None
            else 0
        )

        return {
            "total": total,
            "by_modulation": by_modulation,
            "avg_confidence": avg_confidence,
            "total_bits": total_bits,
        }
