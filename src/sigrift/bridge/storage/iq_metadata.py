"""IQ metadata index with tiered retention.

SQLite-backed searchable index for IQ captures, with configurable
retention tiers ('critical', 'standard', 'temporary') and automated
expiry cleanup.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Default TTLs per tier (in hours).  'critical' never expires.
DEFAULT_TIER_TTLS: dict[str, int | None] = {
    "critical": None,  # never expires
    "standard": 30 * 24,  # 30 days
    "temporary": 24,  # 24 hours
}

VALID_TIERS = frozenset(DEFAULT_TIER_TTLS.keys())

_IQ_METADATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS iq_metadata (
    detection_id    TEXT PRIMARY KEY,
    node_id         TEXT,
    freq_hz         REAL,
    signal_class    TEXT,
    sample_rate     REAL,
    n_samples       INTEGER,
    file_size_bytes INTEGER,
    quality_score   REAL,
    captured_at     TEXT,
    tier            TEXT DEFAULT 'standard',
    expires_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_iq_meta_node
    ON iq_metadata (node_id);
CREATE INDEX IF NOT EXISTS idx_iq_meta_signal_class
    ON iq_metadata (signal_class);
CREATE INDEX IF NOT EXISTS idx_iq_meta_tier
    ON iq_metadata (tier);
CREATE INDEX IF NOT EXISTS idx_iq_meta_expires
    ON iq_metadata (expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_iq_meta_freq
    ON iq_metadata (freq_hz);
CREATE INDEX IF NOT EXISTS idx_iq_meta_captured
    ON iq_metadata (captured_at);
"""


class IQMetadataStore:
    """SQLite-backed IQ metadata index with tiered retention.

    Parameters
    ----------
    ctx : SharedContext
        Shared storage infrastructure (connection, lock, cache).
    tier_ttls : dict or None
        Override default TTLs per tier.  Keys are tier names, values
        are hours (or None for never-expires).
    """

    def __init__(
        self,
        ctx: Any,
        tier_ttls: dict[str, int | None] | None = None,
        max_storage_bytes: int = 1_073_741_824,  # 1 GB
    ) -> None:
        self._ctx = ctx
        self._tier_ttls = dict(DEFAULT_TIER_TTLS)
        if tier_ttls:
            self._tier_ttls.update(tier_ttls)
        self._max_storage_bytes = max_storage_bytes
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create the iq_metadata table if it does not exist."""
        with self._ctx.transaction() as conn:
            conn.executescript(_IQ_METADATA_SCHEMA)

    # -- Write operations ---------------------------------------------------

    def index_capture(self, detection_id: str, metadata: dict[str, Any]) -> None:
        """Insert or update a metadata entry for an IQ capture.

        Parameters
        ----------
        detection_id : str
            Detection identifier (primary key).
        metadata : dict
            Keys may include: node_id, freq_hz, signal_class, sample_rate,
            n_samples, file_size_bytes, quality_score, captured_at, tier.
        """
        tier = metadata.get("tier", "standard")
        if tier not in VALID_TIERS:
            tier = "standard"

        captured_at = metadata.get(
            "captured_at", datetime.now(timezone.utc).isoformat()
        )

        # Compute expires_at based on tier
        expires_at = self._compute_expires_at(tier, captured_at)

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO iq_metadata
                    (detection_id, node_id, freq_hz, signal_class, sample_rate,
                     n_samples, file_size_bytes, quality_score, captured_at,
                     tier, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detection_id,
                    metadata.get("node_id"),
                    metadata.get("freq_hz"),
                    metadata.get("signal_class"),
                    metadata.get("sample_rate"),
                    metadata.get("n_samples"),
                    metadata.get("file_size_bytes"),
                    metadata.get("quality_score"),
                    captured_at,
                    tier,
                    expires_at,
                ),
            )
        logger.debug("IQ metadata indexed: %s (tier=%s)", detection_id, tier)

    def set_tier(
        self,
        detection_id: str,
        tier: str,
        ttl_hours: int | None = None,
    ) -> bool:
        """Set the retention tier for an IQ capture.

        Parameters
        ----------
        detection_id : str
            Detection identifier.
        tier : str
            One of 'critical', 'standard', 'temporary'.
        ttl_hours : int or None
            Override the default TTL for this tier.  None uses the
            tier default.

        Returns
        -------
        bool
            True if the entry was found and updated.
        """
        if tier not in VALID_TIERS:
            raise ValueError(
                f"Invalid tier {tier!r}; must be one of {sorted(VALID_TIERS)}"
            )

        if ttl_hours is not None:
            if ttl_hours <= 0:
                expires_at = None
            else:
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
                ).isoformat()
        else:
            ttl = self._tier_ttls.get(tier)
            if ttl is None:
                expires_at = None
            else:
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(hours=ttl)
                ).isoformat()

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "UPDATE iq_metadata SET tier = ?, expires_at = ? WHERE detection_id = ?",
                (tier, expires_at, detection_id),
            )
        updated = cursor.rowcount > 0

        if updated:
            logger.info(
                "IQ tier set: %s -> %s (expires=%s)", detection_id, tier, expires_at
            )
        return updated

    def delete_metadata(self, detection_id: str) -> bool:
        """Remove an index entry.

        Returns
        -------
        bool
            True if a row was deleted.
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM iq_metadata WHERE detection_id = ?",
                (detection_id,),
            )
        return cursor.rowcount > 0

    # -- Read operations ----------------------------------------------------

    def get_metadata(self, detection_id: str) -> dict[str, Any] | None:
        """Return metadata for a single detection, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM iq_metadata WHERE detection_id = ?",
            (detection_id,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def query(
        self,
        *,
        node_id: str | None = None,
        signal_class: str | None = None,
        freq_range: tuple[float, float] | None = None,
        tier: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query IQ metadata with optional filters.

        Parameters
        ----------
        node_id : str or None
            Filter by node.
        signal_class : str or None
            Filter by signal class.
        freq_range : tuple[float, float] or None
            Filter by frequency range (min_hz, max_hz).
        tier : str or None
            Filter by retention tier.
        limit : int
            Maximum results (default 50).

        Returns
        -------
        list[dict]
            Matching metadata entries, ordered by captured_at DESC.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if node_id is not None:
            clauses.append("node_id = ?")
            params.append(node_id)
        if signal_class is not None:
            clauses.append("signal_class = ?")
            params.append(signal_class)
        if freq_range is not None:
            clauses.append("freq_hz >= ? AND freq_hz <= ?")
            params.extend(freq_range)
        if tier is not None:
            clauses.append("tier = ?")
            params.append(tier)

        where = " AND ".join(clauses) if clauses else "1=1"
        params.append(limit)

        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM iq_metadata WHERE {where} ORDER BY captured_at DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]

    def get_expired(self) -> list[str]:
        """Return detection_ids whose expires_at is in the past.

        Returns
        -------
        list[str]
            Detection IDs that have expired.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT detection_id FROM iq_metadata WHERE expires_at IS NOT NULL AND expires_at <= ?",
            (now,),
        ).fetchall()
        return [r["detection_id"] for r in rows]

    def get_stats(self) -> dict[str, Any]:
        """Return IQ storage statistics.

        Returns
        -------
        dict
            Keys: total_captures, total_size_bytes, by_tier (count per tier),
            oldest_capture, newest_capture.
        """
        conn = self._ctx.get_conn()

        row = conn.execute(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(file_size_bytes), 0) as total_size, "
            "MIN(captured_at) as oldest, MAX(captured_at) as newest "
            "FROM iq_metadata"
        ).fetchone()

        tier_rows = conn.execute(
            "SELECT tier, COUNT(*) as cnt FROM iq_metadata GROUP BY tier"
        ).fetchall()
        by_tier = {r["tier"]: r["cnt"] for r in tier_rows}

        return {
            "total_captures": row["cnt"],
            "total_size_bytes": row["total_size"],
            "by_tier": by_tier,
            "oldest_capture": row["oldest"],
            "newest_capture": row["newest"],
        }

    def evict_to_budget(self, iq_store: Any) -> int:
        """Delete oldest non-critical captures until total size is under budget.

        Returns the number of captures evicted.
        """
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT COALESCE(SUM(file_size_bytes), 0) as total FROM iq_metadata"
        ).fetchone()
        total = row["total"]
        if total <= self._max_storage_bytes:
            return 0

        # Evict oldest temporary first, then standard — never critical
        candidates = conn.execute(
            "SELECT detection_id, file_size_bytes FROM iq_metadata "
            "WHERE tier != 'critical' "
            "ORDER BY CASE tier WHEN 'temporary' THEN 0 ELSE 1 END, captured_at ASC"
        ).fetchall()

        evicted = 0
        for row in candidates:
            if total <= self._max_storage_bytes:
                break
            iq_store.delete(row["detection_id"])
            self.delete_metadata(row["detection_id"])
            total -= row["file_size_bytes"] or 0
            evicted += 1

        if evicted:
            logger.info(
                "IQ budget eviction: removed %d captures (budget=%d MB)",
                evicted,
                self._max_storage_bytes // (1024 * 1024),
            )
        return evicted

    # -- Cleanup ------------------------------------------------------------

    def cleanup_expired(self, iq_store: Any) -> int:
        """Delete expired IQ files and their metadata entries.

        Parameters
        ----------
        iq_store : IQStore
            Filesystem IQ store instance, used to delete the actual files.

        Returns
        -------
        int
            Number of expired entries cleaned up.
        """
        expired_ids = self.get_expired()
        if not expired_ids:
            return 0

        deleted = 0
        for detection_id in expired_ids:
            # Delete the file
            iq_store.delete(detection_id)
            # Delete the metadata
            self.delete_metadata(detection_id)
            deleted += 1

        logger.info("IQ retention cleanup: removed %d expired captures", deleted)
        return deleted

    # -- Session rollup -----------------------------------------------------

    def rollup_to_sessions(self, cutoff_hours: int = 1) -> int:
        """Group iq_metadata rows by (node_id, hour) into capture sessions."""
        import json as _json

        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=cutoff_hours)
        ).isoformat()

        conn = self._ctx.get_conn()
        rows = conn.execute(
            """
            SELECT
                node_id,
                strftime('%Y-%m-%dT%H:00:00Z', captured_at) AS hour,
                MIN(freq_hz) AS freq_min_hz,
                MAX(freq_hz) AS freq_max_hz,
                COUNT(*) AS capture_count,
                SUM(CASE WHEN quality_score > 0.5 THEN 1 ELSE 0 END) AS anomaly_count,
                SUM(n_samples) AS total_samples,
                GROUP_CONCAT(DISTINCT signal_class) AS signal_classes,
                MIN(captured_at) AS start_time,
                MAX(captured_at) AS end_time
            FROM iq_metadata
            WHERE captured_at < ?
            GROUP BY node_id, hour
        """,
            (cutoff,),
        ).fetchall()

        if not rows:
            return 0

        insert_sql = """
            INSERT OR IGNORE INTO iq_capture_sessions
                (session_id, node_id, start_time, end_time, freq_min_hz,
                 freq_max_hz, capture_count, anomaly_count, total_samples,
                 total_size_bytes, signal_classes, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        insert_rows = []
        for r in rows:
            node_id = r[0]
            hour = r[1]
            session_id = f"{node_id}_{hour}"
            classes = r[7] or ""
            classes_json = _json.dumps(classes.split(",")) if classes else "[]"

            insert_rows.append(
                (
                    session_id,
                    node_id,
                    r[8],  # start_time
                    r[9],  # end_time
                    r[2],  # freq_min_hz
                    r[3],  # freq_max_hz
                    r[4],  # capture_count
                    r[5],  # anomaly_count
                    r[6] or 0,  # total_samples
                    0,  # total_size_bytes (not tracked at row level)
                    classes_json,
                    self._ctx.tenant_id,
                )
            )

        with self._ctx.write_transaction() as conn:
            conn.executemany(insert_sql, insert_rows)

        logger.info(
            "IQ session rollup: %d sessions from metadata rows", len(insert_rows)
        )
        return len(insert_rows)

    def cleanup_sessioned_metadata(self, max_age_hours: int = 24) -> int:
        """Delete raw iq_metadata rows that have been rolled up into sessions."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        ).isoformat()

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                """
                DELETE FROM iq_metadata
                WHERE captured_at < ?
                  AND quality_score <= 0.5
            """,
                (cutoff,),
            )
            count = cursor.rowcount

        if count > 0:
            logger.info("Cleaned up %d sessioned IQ metadata rows", count)
        return count

    # -- Internal -----------------------------------------------------------

    def _compute_expires_at(self, tier: str, captured_at: str) -> str | None:
        """Compute expiry timestamp for a given tier and capture time."""
        ttl_hours = self._tier_ttls.get(tier)
        if ttl_hours is None:
            return None
        try:
            base = datetime.fromisoformat(captured_at)
            # Ensure timezone-aware
            if base.tzinfo is None:
                base = base.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            base = datetime.now(timezone.utc)
        return (base + timedelta(hours=ttl_hours)).isoformat()
