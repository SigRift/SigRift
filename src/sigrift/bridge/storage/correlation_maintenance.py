"""Cross-correlation TTL pruning and sampling.

Runs periodically to prevent unbounded growth of the cross_correlations table.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)


class CorrelationMaintenanceStore:
    """Maintenance operations for the cross_correlations table."""

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx

    def prune_old(self, max_age_days: int = 30) -> int:
        """Delete cross-correlations older than max_age_days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        try:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM cross_correlations WHERE timestamp < ?",
                    (cutoff,),
                )
                count = cursor.rowcount
        except Exception as e:
            logger.debug("cross_correlations prune skipped: %s", e)
            return 0

        if count > 0:
            logger.info("Pruned %d old cross-correlations (>%dd)", count, max_age_days)
        return count

    def prune_low_score(self, min_score: float = 0.3) -> int:
        """Delete low-significance correlations."""
        try:
            with self._ctx.write_transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM cross_correlations WHERE score < ?",
                    (min_score,),
                )
                count = cursor.rowcount
        except Exception as e:
            logger.debug("cross_correlations low-score prune skipped: %s", e)
            return 0

        if count > 0:
            logger.info(
                "Pruned %d low-score cross-correlations (<%.2f)", count, min_score
            )
        return count

    def run_maintenance(
        self, max_age_days: int = 30, min_score: float = 0.3
    ) -> dict[str, int]:
        """Run all maintenance operations."""
        return {
            "pruned_old": self.prune_old(max_age_days),
            "pruned_low_score": self.prune_low_score(min_score),
        }
