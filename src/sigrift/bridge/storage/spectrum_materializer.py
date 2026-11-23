"""Periodic materialization of spectrum_all view into a real table.

The spectrum_all view (UNION ALL of wifi/bt/zigbee/generic detections) is
expensive for analytics queries. This materializer maintains a real table
``spectrum_materialized`` that is refreshed periodically.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS spectrum_materialized (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    freq_hz        REAL NOT NULL,
    power_dbm      REAL,
    signal_class   TEXT NOT NULL DEFAULT '',
    node_id        TEXT NOT NULL DEFAULT '',
    bandwidth_hz   REAL,
    confidence     REAL,
    tenant_id      TEXT NOT NULL DEFAULT 'default',
    anomaly_score  REAL,
    snr_db         REAL,
    materialized_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_spec_mat_ts
    ON spectrum_materialized (timestamp);
CREATE INDEX IF NOT EXISTS idx_spec_mat_tenant_ts
    ON spectrum_materialized (tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_spec_mat_freq
    ON spectrum_materialized (freq_hz);
CREATE INDEX IF NOT EXISTS idx_spec_mat_node
    ON spectrum_materialized (node_id);
"""

# Rows per batched transaction. Each batch commits separately so the WAL
# doesn't balloon: a single unbounded INSERT...SELECT over the whole
# spectrum_all view wrote ~1.9 GB into the WAL in one transaction, which
# the checkpointer couldn't reclaim under live read load (2026-06 WAL
# incident). Batched commits let autocheckpoint reclaim between batches.
_MATERIALIZE_BATCH_ROWS = 50_000

# Always cursors on ``timestamp > ?`` (the empty-string sentinel matches
# all rows), ordered, capped at one batch. Looped by the caller until a
# short batch signals the tail.
_INSERT_FROM_VIEW = """
INSERT INTO spectrum_materialized
    (timestamp, freq_hz, power_dbm, signal_class, node_id,
     bandwidth_hz, confidence, tenant_id, anomaly_score, snr_db,
     materialized_at)
SELECT
    timestamp, freq_hz, power_dbm, signal_class, node_id,
    bandwidth_hz, confidence, tenant_id, anomaly_score, snr_db,
    ?
FROM spectrum_all
WHERE timestamp > ?
ORDER BY timestamp
LIMIT ?
"""


class SpectrumMaterializer:
    """Manages periodic refresh of spectrum_materialized table.

    Parameters
    ----------
    shared_ctx : SharedContext
        Database context.
    refresh_interval_sec : int
        How often to refresh (default: 900 = 15 minutes).
    """

    def __init__(self, shared_ctx: Any, refresh_interval_sec: int = 900) -> None:
        self._ctx = shared_ctx
        self._interval = refresh_interval_sec
        self._last_watermark: str | None = None
        self._last_refresh_at: str | None = None
        self._total_rows_inserted: int = 0
        self._refresh_count: int = 0
        self._running = False
        self._task: asyncio.Task | None = None

    def create_table(self) -> None:
        """Create spectrum_materialized table if not exists."""
        with self._ctx.transaction() as conn:
            conn.executescript(_CREATE_TABLE)
        logger.info("spectrum_materialized table ensured")

    def refresh(self, batch_rows: int = _MATERIALIZE_BATCH_ROWS) -> int:
        """Incremental refresh: insert rows newer than the watermark.

        Recovers the watermark from the materialized table on first use so
        a process restart resumes incrementally instead of re-loading the
        entire ``spectrum_all`` view. The in-memory watermark resets to
        None on every restart; without recovery the first refresh inserted
        the whole view again — a ~1.9 GB single-transaction WAL burst that
        also duplicated rows into the table on every restart.

        Inserts in batches of ``batch_rows``, committing each, so the WAL
        never holds a giant transaction.

        Returns the count of new rows inserted across all batches.
        """
        conn = self._ctx.get_conn()
        now = datetime.now(timezone.utc).isoformat()

        # Recover watermark from the table (empty string => match all rows).
        if self._last_watermark is None:
            row = conn.execute(
                "SELECT MAX(timestamp) FROM spectrum_materialized"
            ).fetchone()
            self._last_watermark = row[0] if row and row[0] else ""

        total = 0
        while True:
            watermark = self._last_watermark or ""
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(_INSERT_FROM_VIEW, [now, watermark, batch_rows])
                count = cursor.rowcount
            if count <= 0:
                break
            total += count
            row = conn.execute(
                "SELECT MAX(timestamp) FROM spectrum_materialized"
            ).fetchone()
            new_watermark = row[0] if row and row[0] else watermark
            # Guard against an infinite loop if the watermark can't advance
            # (e.g. a full batch of rows sharing the boundary timestamp):
            # stop rather than re-select the same rows forever.
            if new_watermark == watermark:
                break
            self._last_watermark = new_watermark
            if count < batch_rows:
                break

        self._last_refresh_at = now
        self._total_rows_inserted += total
        self._refresh_count += 1

        logger.info(
            "Spectrum materialized incremental refresh: %d new rows (watermark=%s)",
            total,
            self._last_watermark,
        )
        return total

    async def cleanup_old(self, max_age_days: int, batch_size: int = 100_000) -> int:
        """Delete rows older than ``max_age_days`` in batches to avoid long
        write-lock holds. Releases ``write_lock`` between batches and yields
        via ``asyncio.sleep`` so other writers can interleave.

        Prunes globally by age (no tenant filter): a retention sweep should
        drop every row past the cutoff regardless of tenant. The
        ``idx_spec_mat_ts`` index on ``timestamp`` (ISO-8601 TEXT, whose
        lexicographic order matches chronological) serves the range scan.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        total = 0
        while True:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM spectrum_materialized WHERE rowid IN "
                    "(SELECT rowid FROM spectrum_materialized "
                    "WHERE timestamp < ? LIMIT ?)",
                    (cutoff, batch_size),
                )
                n = cursor.rowcount
            total += n
            if n < batch_size:
                break
            await asyncio.sleep(0.1)
        if total > 0:
            logger.info(
                "Pruned %d spectrum_materialized rows (>%dd, batched)",
                total,
                max_age_days,
            )
        return total

    def full_refresh(self, batch_rows: int = _MATERIALIZE_BATCH_ROWS) -> int:
        """Full refresh: truncate, then reload from the view in batches.

        The DELETE + reload is the only place a giant single transaction
        could still arise, so the reload reuses the same batched-commit
        path as ``refresh`` (after resetting the watermark to empty so it
        re-materializes everything).

        Returns count of rows inserted.
        """
        with self._ctx.write_transaction() as conn:
            conn.execute("DELETE FROM spectrum_materialized")
        # Reset watermark so refresh() reloads the whole view, batched.
        self._last_watermark = ""
        return self.refresh(batch_rows=batch_rows)

    async def start_periodic(self) -> None:
        """Start async periodic refresh loop."""
        self._running = True
        logger.info(
            "Starting periodic spectrum materialization (interval=%ds)",
            self._interval,
        )
        while self._running:
            try:
                await asyncio.sleep(self._interval)
                if not self._running:
                    break
                self.refresh()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Spectrum materialization refresh failed: %s", exc)

    def stop(self) -> None:
        """Stop periodic refresh."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        logger.info("Spectrum materialization stopped")

    def status(self) -> dict[str, Any]:
        """Return materialization status."""
        conn = self._ctx.get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM spectrum_materialized"
            ).fetchone()
            row_count = row[0] if row else 0
        except Exception:
            row_count = 0

        return {
            "running": self._running,
            "refresh_interval_sec": self._interval,
            "last_watermark": self._last_watermark,
            "last_refresh_at": self._last_refresh_at,
            "total_rows_inserted": self._total_rows_inserted,
            "refresh_count": self._refresh_count,
            "current_row_count": row_count,
        }
