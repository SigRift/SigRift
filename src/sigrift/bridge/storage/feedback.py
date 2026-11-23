"""Operator feedback and labelling sub-store.

Provides storage and retrieval of operator feedback labels attached
to individual detections.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sigrift.bridge.cache import CacheTag
from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)

# Valid feedback labels operators may assign to detections.
_ALLOWED_LABELS = {"true_positive", "false_positive", "expected", "interesting"}


class FeedbackStore:
    """Manage operator feedback records for detections.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: SharedContext) -> None:
        self._ctx = ctx

    # -- Write --------------------------------------------------------------

    def add_feedback(
        self,
        detection_id: str,
        label: str,
        note: str = "",
        operator: str = "",
    ) -> int:
        """Store operator feedback for a detection.

        Parameters
        ----------
        detection_id : str
            ID of the detection being labelled.
        label : str
            One of: true_positive, false_positive, expected, interesting.
        note : str
            Optional operator note.
        operator : str
            Operator identifier (for audit trail).

        Returns
        -------
        int
            Row ID of the inserted feedback record.

        Raises
        ------
        ValueError
            If *label* is not one of the allowed values.
        """
        if label not in _ALLOWED_LABELS:
            raise ValueError(f"label must be one of {_ALLOWED_LABELS}, got {label!r}")

        now = datetime.now(timezone.utc).isoformat()

        sql = """
            INSERT INTO detection_feedback (detection_id, label, note, created_at, tenant_id)
            VALUES (?, ?, ?, ?, ?)
        """

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                sql, [detection_id, label, note, now, self._ctx.tenant_id]
            )
        self._ctx.cache.invalidate_prefix(CacheTag.GET_FEEDBACK)

        logger.info("Feedback stored: %s → %s", detection_id, label)
        return cursor.lastrowid

    # -- Read ---------------------------------------------------------------

    def get_feedback(self, detection_id: str) -> list[dict[str, Any]]:
        """Get all feedback for a detection.

        Parameters
        ----------
        detection_id : str
            Detection ID.

        Returns
        -------
        list[dict]
            Feedback records, newest first.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM detection_feedback WHERE {tf_clause} AND detection_id = ? ORDER BY created_at DESC",
            tf_params + [detection_id],
        ).fetchall()
        return [dict(r) for r in rows]

    def get_feedback_by_label(
        self, label: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get feedback entries by label.

        Parameters
        ----------
        label : str
            Feedback label to filter by.
        limit : int
            Maximum results.

        Returns
        -------
        list[dict]
            Feedback records, newest first.
        """
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM detection_feedback WHERE {tf_clause} AND label = ? ORDER BY created_at DESC LIMIT ?",
            tf_params + [label, limit],
        ).fetchall()
        return [dict(r) for r in rows]

    # -- Aggregate stats ----------------------------------------------------

    def get_feedback_stats(self, days: int = 30) -> dict[str, int]:
        """Return counts of each label type in the last *days* days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        tf_clause, tf_params = self._ctx.tenant_filter()
        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT label, COUNT(*) AS cnt FROM detection_feedback "
            f"WHERE {tf_clause} AND created_at >= ? GROUP BY label",
            tf_params + [cutoff],
        ).fetchall()
        return {r["label"]: r["cnt"] for r in rows}

    def get_fp_rate(self, days: int = 30) -> float:
        """Return false positive rate: FP / (TP + FP).

        Recognises both long-form (``true_positive``) and short-form
        (``tp``) label strings.  Returns 0.0 when no TP or FP labels
        exist in the window.
        """
        stats = self.get_feedback_stats(days)
        tp = stats.get("true_positive", 0) + stats.get("tp", 0)
        fp = stats.get("false_positive", 0) + stats.get("fp", 0)
        total = tp + fp
        if total < 1:
            return 0.0
        return fp / total
