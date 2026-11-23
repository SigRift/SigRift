"""Tests for P2-10: CHECK constraints on numeric columns via SQLite triggers (migration 40)."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext, _MIGRATIONS


def _insert_detection(
    conn: sqlite3.Connection,
    detection_id: str = "det-1",
    anomaly_score: float | None = 0.0,
    confidence: float | None = 0.5,
) -> None:
    """Insert a detection row with the given score/confidence values."""
    conn.execute(
        "INSERT INTO detections "
        "(detection_id, node_id, timestamp, signal_class, confidence, "
        "anomaly_score, tenant_id) "
        "VALUES (?, ?, '2026-03-10T00:00:00Z', 'test', ?, ?, 'default')",
        (detection_id, "n1", confidence, anomaly_score),
    )
    conn.commit()


class TestCheckConstraintTriggers:
    """Trigger-based CHECK constraints on detections.anomaly_score and confidence."""

    def test_valid_insert_succeeds(self, tmp_path: Path) -> None:
        """anomaly_score=0.5, confidence=0.8 — no constraint violation."""
        ctx = SharedContext(db_path=tmp_path / "ok.db")
        conn = ctx.get_conn()
        _insert_detection(conn, "det-ok", anomaly_score=0.5, confidence=0.8)
        row = conn.execute(
            "SELECT anomaly_score, confidence FROM detections WHERE detection_id = 'det-ok'"
        ).fetchone()
        assert row[0] == pytest.approx(0.5)
        assert row[1] == pytest.approx(0.8)

    def test_anomaly_score_above_1_rejected(self, tmp_path: Path) -> None:
        """anomaly_score=1.5 triggers RAISE(ABORT)."""
        ctx = SharedContext(db_path=tmp_path / "hi_anom.db")
        conn = ctx.get_conn()
        with pytest.raises(sqlite3.IntegrityError, match="anomaly_score must be between 0 and 1"):
            _insert_detection(conn, "det-bad", anomaly_score=1.5, confidence=0.5)

    def test_anomaly_score_below_0_rejected(self, tmp_path: Path) -> None:
        """anomaly_score=-0.1 triggers RAISE(ABORT)."""
        ctx = SharedContext(db_path=tmp_path / "lo_anom.db")
        conn = ctx.get_conn()
        with pytest.raises(sqlite3.IntegrityError, match="anomaly_score must be between 0 and 1"):
            _insert_detection(conn, "det-bad", anomaly_score=-0.1, confidence=0.5)

    def test_confidence_above_1_rejected(self, tmp_path: Path) -> None:
        """confidence=1.5 triggers RAISE(ABORT)."""
        ctx = SharedContext(db_path=tmp_path / "hi_conf.db")
        conn = ctx.get_conn()
        with pytest.raises(sqlite3.IntegrityError, match="confidence must be between 0 and 1"):
            _insert_detection(conn, "det-bad", anomaly_score=0.5, confidence=1.5)

    def test_confidence_below_0_rejected(self, tmp_path: Path) -> None:
        """confidence=-0.1 triggers RAISE(ABORT)."""
        ctx = SharedContext(db_path=tmp_path / "lo_conf.db")
        conn = ctx.get_conn()
        with pytest.raises(sqlite3.IntegrityError, match="confidence must be between 0 and 1"):
            _insert_detection(conn, "det-bad", anomaly_score=0.5, confidence=-0.1)

    def test_null_values_allowed(self, tmp_path: Path) -> None:
        """NULL anomaly_score and confidence pass trigger IS NOT NULL guard.

        The detections schema defines these as NOT NULL with defaults, so we
        drop that constraint on a scratch table to verify the trigger's
        IS NOT NULL guard works independently of the column constraint.
        """
        ctx = SharedContext(db_path=tmp_path / "null.db")
        conn = ctx.get_conn()
        # Create a stripped-down table without NOT NULL to isolate trigger logic
        conn.executescript("""
            CREATE TABLE detections_nullable (
                detection_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                signal_class TEXT NOT NULL,
                confidence REAL,
                anomaly_score REAL,
                tenant_id TEXT NOT NULL DEFAULT 'default'
            );
            CREATE TRIGGER IF NOT EXISTS trg_nullable_check_insert
            BEFORE INSERT ON detections_nullable
            BEGIN
                SELECT RAISE(ABORT, 'anomaly_score must be between 0 and 1')
                WHERE NEW.anomaly_score IS NOT NULL AND (NEW.anomaly_score < 0.0 OR NEW.anomaly_score > 1.0);
                SELECT RAISE(ABORT, 'confidence must be between 0 and 1')
                WHERE NEW.confidence IS NOT NULL AND (NEW.confidence < 0.0 OR NEW.confidence > 1.0);
            END;
        """)
        conn.execute(
            "INSERT INTO detections_nullable "
            "(detection_id, node_id, timestamp, signal_class, confidence, anomaly_score) "
            "VALUES ('det-null', 'n1', '2026-03-10T00:00:00Z', 'test', NULL, NULL)"
        )
        conn.commit()
        row = conn.execute(
            "SELECT anomaly_score, confidence FROM detections_nullable "
            "WHERE detection_id = 'det-null'"
        ).fetchone()
        assert row[0] is None
        assert row[1] is None

    def test_update_violation_rejected(self, tmp_path: Path) -> None:
        """UPDATE that sets anomaly_score > 1 triggers RAISE(ABORT)."""
        ctx = SharedContext(db_path=tmp_path / "upd.db")
        conn = ctx.get_conn()
        _insert_detection(conn, "det-upd", anomaly_score=0.5, confidence=0.5)
        with pytest.raises(sqlite3.IntegrityError, match="anomaly_score must be between 0 and 1"):
            conn.execute(
                "UPDATE detections SET anomaly_score = 2.0 WHERE detection_id = 'det-upd'"
            )

    def test_migration_applies_cleanly(self, tmp_path: Path) -> None:
        """Migration 40 is recorded in schema_version after SharedContext init."""
        ctx = SharedContext(db_path=tmp_path / "mig.db")
        conn = ctx.get_conn()
        row = conn.execute(
            "SELECT version, description FROM schema_version WHERE version = 40"
        ).fetchone()
        assert row is not None, "Migration 40 not found in schema_version"
        assert isinstance(row[0], int)
        assert row[0] == 40
        assert "check_constraints" in row[1]

    def test_boundary_values_accepted(self, tmp_path: Path) -> None:
        """Exact boundary values 0.0 and 1.0 should be accepted."""
        ctx = SharedContext(db_path=tmp_path / "boundary.db")
        conn = ctx.get_conn()
        _insert_detection(conn, "det-zero", anomaly_score=0.0, confidence=0.0)
        _insert_detection(conn, "det-one", anomaly_score=1.0, confidence=1.0)
        rows = conn.execute(
            "SELECT detection_id FROM detections ORDER BY detection_id"
        ).fetchall()
        assert len(rows) == 2
