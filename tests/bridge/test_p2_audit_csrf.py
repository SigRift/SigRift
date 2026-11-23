"""Tests for P2-7 (audit chain archive) and P2-3 (CSRF enabled by default).

P2-7: archive_audit_log() replaces destructive purge_audit_log() to
preserve the HMAC chain across retention cleanup.

P2-3: CSRF is now enabled by default (disabled only in dev/test mode
or when BRIDGE_CSRF=disabled is explicitly set).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _insert_old_audit_entry(
    store: DetectionStore,
    action: str,
    target_id: str,
    *,
    days_ago: int = 120,
    operator: str = "tester",
    note: str = "",
) -> dict:
    """Insert an audit entry backdated to *days_ago* days in the past.

    Inserts directly with the correct timestamp so the HMAC chain is
    computed correctly from the start.
    """
    from sigrift.bridge.storage.audit import (
        _compute_hmac_v2,
        _get_audit_secret,
    )

    old_ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    conn = store._ctx.get_conn()

    # Find predecessor HMAC.
    prev_row = conn.execute(
        "SELECT hmac_chain FROM audit_log WHERE tenant_id = ? "
        "ORDER BY id DESC LIMIT 1",
        [store._ctx.tenant_id],
    ).fetchone()
    previous_hmac = (prev_row["hmac_chain"] or "") if prev_row else ""

    secret = _get_audit_secret()
    entry_hmac = _compute_hmac_v2(
        secret, previous_hmac, action, target_id, operator, old_ts,
        "", note, "", "0.0", "",
    )

    conn.execute(
        "INSERT INTO audit_log "
        "(timestamp, action, target_id, target_ids, signal_class, "
        "freq_hz, node_id, operator, note, details, tenant_id, hmac_chain) "
        "VALUES (?, ?, ?, '', '', 0.0, '', ?, ?, '', ?, ?)",
        [old_ts, action, target_id, operator, note,
         store._ctx.tenant_id, entry_hmac],
    )
    conn.commit()
    return {
        "timestamp": old_ts,
        "action": action,
        "target_id": target_id,
        "operator": operator,
        "note": note,
    }


# ===========================================================================
# P2-7: Audit Chain Archive Tests
# ===========================================================================


class TestAuditArchive:
    """P2-7: archive_audit_log preserves HMAC chain integrity."""

    @pytest.fixture
    def store(self, tmp_path: Path) -> DetectionStore:
        return DetectionStore(db_path=tmp_path / "audit_archive.db")

    def test_archive_preserves_terminal_hmac(self, store: DetectionStore):
        """Archive creates a marker row whose details contain the terminal HMAC."""
        _insert_old_audit_entry(store, "dismiss", "det-001", days_ago=120)
        _insert_old_audit_entry(store, "dismiss", "det-002", days_ago=100)

        # Get the terminal HMAC before archiving
        conn = store._ctx.get_conn()
        terminal_row = conn.execute(
            "SELECT hmac_chain FROM audit_log WHERE target_id = 'det-002'"
        ).fetchone()
        expected_terminal = terminal_row["hmac_chain"]

        result = store._audit.archive_audit_log(max_age_days=90)
        assert result["terminal_hmac"] == expected_terminal
        assert result["archived_count"] == 2

        # Verify the marker row exists with a valid HMAC
        marker = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'archive_marker'"
        ).fetchone()
        assert marker is not None
        assert isinstance(marker["hmac_chain"], str)
        assert len(marker["hmac_chain"]) > 0
        details = json.loads(marker["details"])
        assert isinstance(details, dict)
        assert details["archived_count"] == 2
        assert "date_range" in details
        assert isinstance(details["date_range"], str)

    def test_archive_deletes_old_entries(self, store: DetectionStore):
        """Old entries are removed after archiving, but marker persists."""
        _insert_old_audit_entry(store, "dismiss", "det-old-1", days_ago=120)
        _insert_old_audit_entry(store, "dismiss", "det-old-2", days_ago=100)
        store.log_audit(action="dismiss", target_id="det-new-1")

        result = store._audit.archive_audit_log(max_age_days=90)
        assert result["archived_count"] == 2

        conn = store._ctx.get_conn()
        remaining = conn.execute("SELECT * FROM audit_log").fetchall()
        actions = [r["action"] for r in remaining]
        target_ids = [r["target_id"] for r in remaining]

        assert "archive_marker" in actions
        assert "det-new-1" in target_ids
        assert "det-old-1" not in target_ids
        assert "det-old-2" not in target_ids

    def test_chain_verification_across_archive(self, store: DetectionStore):
        """Chain verification passes after archive (no errors, no gaps)."""
        # Create old entries that will be archived
        _insert_old_audit_entry(store, "dismiss", "det-a1", days_ago=120)
        _insert_old_audit_entry(store, "dismiss", "det-a2", days_ago=110)

        # Create recent entries that will survive
        store.log_audit(action="dismiss", target_id="det-b1")
        store.log_audit(action="dismiss", target_id="det-b2")

        # Archive
        store._audit.archive_audit_log(max_age_days=90)

        # Verify chain integrity
        result = store._audit.verify_chain()
        assert result["valid"] is True, f"Chain errors: {result['errors']}, gaps: {result['gaps']}"
        assert result["errors"] == []
        assert result["gaps"] == []

    def test_archive_marker_recognized(self, store: DetectionStore):
        """The archive_marker entry has the correct action type."""
        _insert_old_audit_entry(store, "dismiss", "det-m1", days_ago=120)
        store._audit.archive_audit_log(max_age_days=90)

        conn = store._ctx.get_conn()
        marker = conn.execute(
            "SELECT * FROM audit_log WHERE action = 'archive_marker'"
        ).fetchone()
        assert marker is not None
        assert marker["action"] == "archive_marker"

        details = json.loads(marker["details"])
        assert isinstance(details, dict)
        assert isinstance(details["archived_count"], int)
        assert "date_range" in details
        assert isinstance(details["date_range"], str)

    def test_empty_audit_log_archive_noop(self, store: DetectionStore):
        """Archiving an empty audit log returns zero count."""
        result = store._audit.archive_audit_log(max_age_days=90)
        assert result["archived_count"] == 0
        assert result["terminal_hmac"] == ""
        assert result["marker_id"] == 0

    def test_multiple_archives_chain_integrity(self, store: DetectionStore):
        """Archiving twice still maintains a valid chain."""
        # First batch of old entries
        _insert_old_audit_entry(store, "dismiss", "det-r1-a", days_ago=200)
        _insert_old_audit_entry(store, "dismiss", "det-r1-b", days_ago=180)

        # Some mid-age entries
        _insert_old_audit_entry(store, "feedback", "det-r2-a", days_ago=120)
        _insert_old_audit_entry(store, "feedback", "det-r2-b", days_ago=100)

        # Recent entries
        store.log_audit(action="dismiss", target_id="det-r3-a")

        # First archive: remove > 150 days
        r1 = store._audit.archive_audit_log(max_age_days=150)
        assert r1["archived_count"] == 2

        # Verify chain after first archive
        v1 = store._audit.verify_chain()
        assert v1["valid"] is True, f"After first archive: {v1}"

        # Second archive: remove > 90 days
        r2 = store._audit.archive_audit_log(max_age_days=90)
        assert r2["archived_count"] == 2

        # Verify chain after second archive
        v2 = store._audit.verify_chain()
        assert v2["valid"] is True, f"After second archive: {v2}"

    def test_archive_returns_correct_count(self, store: DetectionStore):
        """Returned archived_count matches actual deletions."""
        for i in range(5):
            _insert_old_audit_entry(store, "dismiss", f"det-cnt-{i}", days_ago=120)
        # One recent entry that should NOT be archived
        store.log_audit(action="dismiss", target_id="det-cnt-recent")

        conn = store._ctx.get_conn()
        before_count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert before_count == 6

        result = store._audit.archive_audit_log(max_age_days=90)
        assert result["archived_count"] == 5

        after_count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        # 1 recent + 1 archive_marker = 2
        assert after_count == 2

    def test_marker_row_survives_subsequent_archive(self, store: DetectionStore):
        """Archive markers are never deleted by subsequent archive calls."""
        _insert_old_audit_entry(store, "dismiss", "det-surv-1", days_ago=200)
        store._audit.archive_audit_log(max_age_days=90)

        conn = store._ctx.get_conn()
        markers_before = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'archive_marker'"
        ).fetchone()[0]
        assert markers_before == 1

        # Backdate the marker to make it "old"
        conn.execute(
            "UPDATE audit_log SET timestamp = ? WHERE action = 'archive_marker'",
            [(datetime.now(timezone.utc) - timedelta(days=200)).isoformat()],
        )
        conn.commit()

        # Add and archive more entries
        _insert_old_audit_entry(store, "dismiss", "det-surv-2", days_ago=120)
        store._audit.archive_audit_log(max_age_days=90)

        markers_after = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'archive_marker'"
        ).fetchone()[0]
        # Both markers should survive
        assert markers_after == 2


# ===========================================================================
# P2-3: CSRF Enabled by Default Tests
# ===========================================================================


class TestCSRFDefaults:
    """P2-3: CSRF is enabled by default, disabled only in dev/test."""

    @pytest.fixture
    def _bridge_app(self, tmp_path: Path):
        """Build a fresh bridge app for CSRF testing."""
        ds = DetectionStore(db_path=tmp_path / "csrf.db")
        from sigrift.bridge.app import create_test_app
        from sigrift.bridge.persistence import PersistenceManager
        from sigrift.bridge.state import AppState
        from sigrift.lib.security.credentials import generate_api_key

        pm = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
        pm.load_all()
        key = generate_api_key(length=32)
        app = create_test_app(
            tmp_path=tmp_path,
            detection_store=ds,
            persistence=pm,
            app_state=AppState(),
            master_key=key,
        )
        return app

    @patch.dict(os.environ, {"BRIDGE_CSRF": "", "BRIDGE_ENV": ""}, clear=False)
    def test_csrf_enabled_by_default(self, _bridge_app):
        """No BRIDGE_CSRF or BRIDGE_ENV set: CSRF is active."""
        env_backup = {}
        for key in ("BRIDGE_CSRF", "BRIDGE_ENV"):
            env_backup[key] = os.environ.pop(key, None)
        try:
            with TestClient(_bridge_app) as c:
                resp = c.post(
                    "/api/auth/change-password",
                    json={"old_password": "x", "new_password": "y"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert resp.status_code == 403
                assert "CSRF" in resp.json()["detail"]
        finally:
            for key, val in env_backup.items():
                if val is not None:
                    os.environ[key] = val

    @patch.dict(os.environ, {"BRIDGE_ENV": "development"}, clear=False)
    def test_csrf_disabled_in_dev_mode(self, _bridge_app):
        """BRIDGE_ENV=development disables CSRF by default."""
        csrf_backup = os.environ.pop("BRIDGE_CSRF", None)
        try:
            with TestClient(_bridge_app) as c:
                resp = c.post(
                    "/api/auth/change-password",
                    json={"old_password": "x", "new_password": "y"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                # Should NOT be a CSRF 403
                if resp.status_code == 403:
                    assert "CSRF" not in resp.json().get("detail", "")
        finally:
            if csrf_backup is not None:
                os.environ["BRIDGE_CSRF"] = csrf_backup

    @patch.dict(os.environ, {"BRIDGE_CSRF": "disabled", "BRIDGE_ENV": "staging"}, clear=False)
    def test_csrf_explicit_disabled(self, _bridge_app):
        """BRIDGE_CSRF=disabled turns the check off outside production.

        In production (BRIDGE_ENV or BRIDGE_MODE production/prod) the bridge
        now refuses to start with it (test_mfa_key_validation.py,
        TestProductionStartupGuard); this app has no lifespan.
        """
        with TestClient(_bridge_app) as c:
            resp = c.post(
                "/api/auth/change-password",
                json={"old_password": "x", "new_password": "y"},
                headers={"Authorization": "Bearer fake_token"},
            )
            # Should NOT be CSRF 403
            if resp.status_code == 403:
                assert "CSRF" not in resp.json().get("detail", "")

    @patch.dict(os.environ, {"BRIDGE_CSRF": " Enabled ", "BRIDGE_ENV": "staging"}, clear=False)
    def test_csrf_setting_is_read_trimmed(self, _bridge_app):
        """" Enabled " is enabled, as the startup guard and the gateway read it.

        The middleware lowered the value but did not trim it, so " enabled "
        turned CSRF off while production's startup guard (which trims)
        accepted it.
        """
        with TestClient(_bridge_app) as c:
            resp = c.post(
                "/api/auth/change-password",
                json={"old_password": "x", "new_password": "y"},
                headers={"Authorization": "Bearer fake_token"},
            )
            assert resp.status_code == 403
            assert "CSRF" in resp.json()["detail"]

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"}, clear=False)
    def test_csrf_tokens_are_compared_in_constant_time(self, _bridge_app, monkeypatch):
        """The double-submit check compares with hmac.compare_digest.

        It compared the cookie and the header with ``!=``, whose early exit
        leaks how much of a guessed token matched; the gateway now uses
        ``constant_time_eq`` for the same check.
        """
        import sigrift.bridge.app as app_module

        real = app_module.hmac.compare_digest
        calls = []

        def spy(a, b):
            calls.append((a, b))
            return real(a, b)

        monkeypatch.setattr(app_module.hmac, "compare_digest", spy)
        with TestClient(_bridge_app) as c:
            for header, refused in [("c0ffee-guess", True), ("c0ffee-token", False)]:
                resp = c.post(
                    "/api/auth/change-password",
                    json={"old_password": "x", "new_password": "y"},
                    headers={
                        "Authorization": "Bearer fake_token",
                        "Cookie": "csrf_token=c0ffee-token",
                        "X-CSRF-Token": header,
                    },
                )
                csrf_refused = resp.status_code == 403 and "CSRF" in resp.text
                assert csrf_refused == refused, (header, resp.status_code, resp.text)
                assert (b"c0ffee-token", header.encode()) in calls, calls

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"}, clear=False)
    def test_csrf_enabled_explicit(self, _bridge_app):
        """BRIDGE_CSRF=enabled always enables CSRF protection."""
        with TestClient(_bridge_app) as c:
            resp = c.post(
                "/api/auth/change-password",
                json={"old_password": "x", "new_password": "y"},
                headers={"Authorization": "Bearer fake_token"},
            )
            assert resp.status_code == 403
            assert "CSRF" in resp.json()["detail"]
