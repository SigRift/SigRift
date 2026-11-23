"""Tests for FK enforcement after migration 42.

Verifies that:
- PRAGMA foreign_keys=ON is active
- wifi_metadata INSERT works without a parent detection (FK removed)
- detection_feedback INSERT works without a parent detection (FK removed)
- Valid FKs (sessions→users) still enforced
- Basic CRUD operations remain functional
"""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    return SharedContext(db_path=tmp_path / "test_fk.db")


class TestForeignKeysEnabled:
    def test_pragma_foreign_keys_on(self, ctx):
        conn = ctx.get_conn()
        row = conn.execute("PRAGMA foreign_keys").fetchone()
        assert row[0] == 1, "PRAGMA foreign_keys should be ON"


class TestWifiMetadataNoFK:
    def test_insert_without_parent_detection(self, ctx):
        """wifi_metadata INSERT should succeed without a matching detection."""
        conn = ctx.get_conn()
        orphan_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO wifi_metadata (detection_id, bssid, ssid, channel, "
            "signal_dbm, timestamp, node_id, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (orphan_id, "aa:bb:cc:dd:ee:ff", "TestNet", 6,
             -50.0, _utcnow(), "n1", "default"),
        )
        conn.commit()

        row = conn.execute(
            "SELECT detection_id FROM wifi_metadata WHERE detection_id = ?",
            (orphan_id,),
        ).fetchone()
        assert row is not None
        assert isinstance(row["detection_id"], str)
        assert row["detection_id"] == orphan_id

    def test_wifi_metadata_table_has_no_fk(self, ctx):
        """Verify no FK constraint in the recreated wifi_metadata table."""
        conn = ctx.get_conn()
        fk_list = conn.execute("PRAGMA foreign_key_list(wifi_metadata)").fetchall()
        assert len(fk_list) == 0, f"Expected no FKs, got {len(fk_list)}"


class TestDetectionFeedbackNoFK:
    def test_insert_without_parent_detection(self, ctx):
        """detection_feedback INSERT should succeed without a matching detection."""
        conn = ctx.get_conn()
        orphan_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO detection_feedback (detection_id, label, note, "
            "created_at, tenant_id) VALUES (?, ?, ?, ?, ?)",
            (orphan_id, "false_positive", "test", _utcnow(), "default"),
        )
        conn.commit()

        row = conn.execute(
            "SELECT detection_id FROM detection_feedback WHERE detection_id = ?",
            (orphan_id,),
        ).fetchone()
        assert row is not None
        assert row["detection_id"] == orphan_id

    def test_feedback_table_has_no_fk(self, ctx):
        conn = ctx.get_conn()
        fk_list = conn.execute("PRAGMA foreign_key_list(detection_feedback)").fetchall()
        assert len(fk_list) == 0


class TestValidFKsStillWork:
    def test_sessions_fk_enforced(self, ctx):
        """sessions table FK to users should be enforced."""
        conn = ctx.get_conn()
        # Try to insert a session referencing a non-existent user
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO sessions (session_token, user_id, created_at, "
                "expires_at) VALUES (?, ?, ?, ?)",
                ("tok_abc", 99999, _utcnow(), _utcnow()),
            )

    def test_mfa_backup_codes_fk_enforced(self, ctx):
        """mfa_backup_codes FK to users should be enforced."""
        conn = ctx.get_conn()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO mfa_backup_codes (user_id, code_hash, created_at) "
                "VALUES (?, ?, ?)",
                (99999, "hashval", _utcnow()),
            )


class TestBasicCRUD:
    def test_detection_insert_and_query(self, ctx):
        conn = ctx.get_conn()
        det_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO detections (detection_id, node_id, timestamp, "
            "signal_class, confidence, freq_hz, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (det_id, "n1", _utcnow(), "bpsk", 0.9, 433.92e6, "default"),
        )
        conn.commit()

        row = conn.execute(
            "SELECT * FROM detections WHERE detection_id = ?", (det_id,)
        ).fetchone()
        assert row["signal_class"] == "bpsk"

    def test_wifi_with_matching_detection(self, ctx):
        """wifi_metadata with a valid detection parent still works."""
        conn = ctx.get_conn()
        det_id = str(uuid.uuid4())
        ts = _utcnow()
        conn.execute(
            "INSERT INTO detections (detection_id, node_id, timestamp, "
            "signal_class, confidence, freq_hz, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (det_id, "n1", ts, "wifi", 0.9, 2.437e9, "default"),
        )
        conn.execute(
            "INSERT INTO wifi_metadata (detection_id, bssid, ssid, channel, "
            "signal_dbm, timestamp, node_id, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (det_id, "aa:bb:cc:dd:ee:ff", "TestNet", 6,
             -50.0, ts, "n1", "default"),
        )
        conn.commit()

        row = conn.execute(
            "SELECT * FROM wifi_metadata WHERE detection_id = ?", (det_id,)
        ).fetchone()
        assert row["bssid"] == "aa:bb:cc:dd:ee:ff"

    def test_feedback_with_matching_detection(self, ctx):
        conn = ctx.get_conn()
        det_id = str(uuid.uuid4())
        ts = _utcnow()
        conn.execute(
            "INSERT INTO detections (detection_id, node_id, timestamp, "
            "signal_class, confidence, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (det_id, "n1", ts, "bpsk", 0.9, "default"),
        )
        conn.execute(
            "INSERT INTO detection_feedback (detection_id, label, note, "
            "created_at, tenant_id) VALUES (?, ?, ?, ?, ?)",
            (det_id, "confirmed", "good", ts, "default"),
        )
        conn.commit()

        row = conn.execute(
            "SELECT * FROM detection_feedback WHERE detection_id = ?", (det_id,)
        ).fetchone()
        assert row["label"] == "confirmed"

    def test_spectrum_all_view_still_works(self, ctx):
        """spectrum_all view is recreated and functional after migration."""
        conn = ctx.get_conn()
        det_id = str(uuid.uuid4())
        ts = _utcnow()
        conn.execute(
            "INSERT INTO detections (detection_id, node_id, timestamp, "
            "signal_class, confidence, freq_hz, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (det_id, "n1", ts, "bpsk", 0.9, 433.92e6, "default"),
        )
        conn.commit()

        rows = conn.execute("SELECT * FROM spectrum_all").fetchall()
        assert len(rows) >= 1
        assert isinstance(rows[0]["signal_class"], str)
        assert any(r["signal_class"] == "bpsk" for r in rows)
