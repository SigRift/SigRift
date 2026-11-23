"""Tests for backup integrity verification (Sprint 8).

Covers _compute_sha256() and GET /api/admin/backups/{filename}/verify.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.dependencies import admin_rate_limit as _admin_rate_limit
from sigrift.bridge.routers.maintenance import _compute_sha256, router
from sigrift.bridge.state import AppState


# ---------------------------------------------------------------------------
# Unit tests for _compute_sha256
# ---------------------------------------------------------------------------



class TestComputeSha256(unittest.TestCase):
    """Unit tests for _compute_sha256()."""

    def test_known_content(self):
        """SHA-256 of known bytes must match hashlib reference."""
        content = b"hello backup world"
        expected = hashlib.sha256(content).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = Path(f.name)
        try:
            self.assertEqual(_compute_sha256(tmp_path), expected)
        finally:
            tmp_path.unlink()

    def test_empty_file(self):
        """SHA-256 of an empty file is the well-known empty-digest."""
        expected = hashlib.sha256(b"").hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp_path = Path(f.name)
        try:
            self.assertEqual(_compute_sha256(tmp_path), expected)
        finally:
            tmp_path.unlink()

    def test_large_file_chunked(self):
        """Verify chunked reading produces the same result as whole-file hash."""
        content = os.urandom(256 * 1024)  # 256 KiB
        expected = hashlib.sha256(content).hexdigest()
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(content)
            f.flush()
            tmp_path = Path(f.name)
        try:
            self.assertEqual(_compute_sha256(tmp_path), expected)
        finally:
            tmp_path.unlink()


# ---------------------------------------------------------------------------
# Integration tests for GET /api/admin/backups/{filename}/verify
# ---------------------------------------------------------------------------


def _make_maintenance_app(tmp_dir: Path) -> "FastAPI":
    """Create a minimal FastAPI app with the maintenance router."""
    app = FastAPI()

    mock_persistence = MagicMock()
    mock_persistence.get_nodes.return_value = {}

    app_state = AppState()
    app.state.persistence = mock_persistence
    app.state.app_state = app_state

    # Mock detection store with db_path pointing to tmp_dir
    mock_store = MagicMock()
    mock_store.db_path = str(tmp_dir / "detections.db")
    mock_store.log_audit = MagicMock()
    app.state.detection_store = mock_store

    # Bypass admin auth
    async def _fake_admin_rate_limit():
        return "test-key-id"

    app.dependency_overrides[_admin_rate_limit] = _fake_admin_rate_limit

    # Patch _get_detection_store so it returns our mock_store
    import sigrift.bridge.routers.maintenance as maint_mod
    original_get = maint_mod._get_detection_store

    def _patched_get(request):
        return mock_store

    maint_mod._get_detection_store = _patched_get
    app._restore_get_detection_store = (maint_mod, original_get)

    app.include_router(router, prefix="/api/admin")
    return app



class TestVerifyBackupEndpoint(unittest.TestCase):
    """Integration tests for GET /api/admin/backups/{filename}/verify."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.tmp_dir = Path(self._tmpdir)
        self.app = _make_maintenance_app(self.tmp_dir)
        self.client = TestClient(self.app)

        # Create the backups directory structure
        self.backup_dir = self.tmp_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)

    def tearDown(self):
        # Restore patched function
        if hasattr(self.app, "_restore_get_detection_store"):
            mod, orig = self.app._restore_get_detection_store
            mod._get_detection_store = orig
        # Clean up temp dir
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_nonexistent_backup_returns_404(self):
        resp = self.client.get("/api/admin/backups/no_such_file.db/verify")
        self.assertEqual(resp.status_code, 404)

    def test_invalid_filename_returns_400(self):
        resp = self.client.get("/api/admin/backups/bad%20name!.db/verify")
        self.assertEqual(resp.status_code, 400)

    def test_trailing_newline_is_not_a_backup_name(self):
        """The whole name must match: "x.db\\n" is refused even if it exists.

        (``re.match`` with a ``$`` anchor let one trailing newline through.)
        """
        (self.backup_dir / "test_backup.db\n").write_bytes(b"not a backup")
        for path in (
            "/api/admin/backups/test_backup.db%0A",
            "/api/admin/backups/test_backup.db%0A/verify",
            "/api/admin/backups/test_backup.db.enc%0A",
        ):
            resp = self.client.get(path)
            self.assertEqual(
                (resp.status_code, resp.json()["detail"]),
                (400, "Invalid filename"),
                path,
            )
        # The names the route serves still match.
        (self.backup_dir / "test_backup.db").write_bytes(b"db")
        (self.backup_dir / "test_backup.db.enc").write_bytes(b"enc")
        resp = self.client.get("/api/admin/backups/test_backup.db")
        self.assertEqual((resp.status_code, resp.content), (200, b"db"))
        resp = self.client.get("/api/admin/backups/test_backup.db.enc")
        self.assertEqual(resp.headers.get("X-Encrypted"), "true")

    def test_missing_sidecar_returns_404(self):
        """Backup file exists but no .sha256 sidecar -> 404."""
        backup_file = self.backup_dir / "test_backup.db"
        backup_file.write_bytes(b"fake database content")

        resp = self.client.get("/api/admin/backups/test_backup.db/verify")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("sidecar", resp.json()["detail"].lower())

    def test_valid_backup_returns_success(self):
        """Backup + matching sidecar -> valid: true."""
        content = b"SQLite format 3 fake backup"
        backup_file = self.backup_dir / "detections_backup_20260304_120000.db"
        backup_file.write_bytes(content)

        sha256_hex = hashlib.sha256(content).hexdigest()
        sidecar = backup_file.with_suffix(".db.sha256")
        sidecar.write_text(f"{sha256_hex}  {backup_file.name}\n")

        resp = self.client.get(
            f"/api/admin/backups/{backup_file.name}/verify"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["valid"])
        self.assertEqual(data["stored_sha256"], sha256_hex)
        self.assertEqual(data["computed_sha256"], sha256_hex)
        self.assertEqual(data["backup_file"], backup_file.name)
        self.assertIn("size_bytes", data)

    def test_corrupted_backup_returns_invalid(self):
        """Backup content changed after sidecar was written -> valid: false."""
        original = b"original content"
        backup_file = self.backup_dir / "detections_backup_20260304_130000.db"
        backup_file.write_bytes(original)

        sha256_hex = hashlib.sha256(original).hexdigest()
        sidecar = backup_file.with_suffix(".db.sha256")
        sidecar.write_text(f"{sha256_hex}  {backup_file.name}\n")

        # Corrupt the backup
        backup_file.write_bytes(b"corrupted content")

        resp = self.client.get(
            f"/api/admin/backups/{backup_file.name}/verify"
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["valid"])
        self.assertEqual(data["stored_sha256"], sha256_hex)
        self.assertNotEqual(data["computed_sha256"], sha256_hex)


if __name__ == "__main__":
    unittest.main()
