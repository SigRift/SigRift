"""Tests for SQLCipher encryption layer (storage/encryption.py).

Most tests run with plain sqlite3 (no pysqlcipher3 required).
Tests that require pysqlcipher3 are skipped if it's not installed.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from sigrift.bridge.storage.encryption import (
    _HAS_SQLCIPHER,
    _SENTINEL,
    _escape_pragma_value,
    _resolve_encryption_key,
    encryption_status,
    is_plaintext_db,
    open_db,
    reset_cached_key,
)


@pytest.fixture(autouse=True)
def _reset_key_cache():
    """Reset the cached encryption key before and after each test."""
    reset_cached_key()
    yield
    reset_cached_key()


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------


class TestKeyResolution:
    def test_no_key_configured(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            assert _resolve_encryption_key() is None

    def test_key_from_env_var(self):
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": "my-secret-key"}):
            assert _resolve_encryption_key() == "my-secret-key"

    def test_key_from_file(self, tmp_path: Path):
        key_file = tmp_path / "db.key"
        key_file.write_text("file-based-key\n")
        key_file.chmod(0o600)
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY_FILE": str(key_file)}):
            assert _resolve_encryption_key() == "file-based-key"

    def test_env_var_takes_precedence_over_file(self, tmp_path: Path):
        key_file = tmp_path / "db.key"
        key_file.write_text("file-key")
        key_file.chmod(0o600)
        with patch.dict(os.environ, {
            "BRIDGE_DB_ENCRYPTION_KEY": "env-key",
            "BRIDGE_DB_ENCRYPTION_KEY_FILE": str(key_file),
        }):
            assert _resolve_encryption_key() == "env-key"

    def test_key_file_not_found(self):
        with patch.dict(os.environ, {
            "BRIDGE_DB_ENCRYPTION_KEY_FILE": "/nonexistent/path/key.txt",
        }):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            with pytest.raises(FileNotFoundError, match="not found"):
                _resolve_encryption_key()

    def test_key_file_empty(self, tmp_path: Path):
        key_file = tmp_path / "empty.key"
        key_file.write_text("")
        key_file.chmod(0o600)
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY_FILE": str(key_file)}):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            with pytest.raises(ValueError, match="empty"):
                _resolve_encryption_key()

    @pytest.mark.skipif(
        os.name == "nt", reason="Permission checks not reliable on Windows"
    )
    def test_key_file_bad_permissions(self, tmp_path: Path):
        key_file = tmp_path / "insecure.key"
        key_file.write_text("key-value")
        key_file.chmod(0o644)  # group/other readable
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY_FILE": str(key_file)}):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            with pytest.raises(PermissionError, match="group/other readable"):
                _resolve_encryption_key()

    def test_key_is_cached(self):
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": "cached-key"}):
            k1 = _resolve_encryption_key()
        # Even after env var is removed, cached value persists
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            k2 = _resolve_encryption_key()
        assert k1 == k2 == "cached-key"

    def test_reset_clears_cache(self):
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": "key1"}):
            assert _resolve_encryption_key() == "key1"
        reset_cached_key()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            assert _resolve_encryption_key() is None


# ---------------------------------------------------------------------------
# open_db (plain mode — no pysqlcipher3 needed)
# ---------------------------------------------------------------------------


class TestOpenDbPlain:
    def test_open_plain_db(self, tmp_path: Path):
        db = tmp_path / "test.db"
        conn = open_db(db, encryption_key=None)
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.execute("INSERT INTO t VALUES (1)")
        conn.commit()
        row = conn.execute("SELECT id FROM t").fetchone()
        assert row[0] == 1
        conn.close()

    def test_open_memory_db(self):
        conn = open_db(":memory:", encryption_key=None)
        conn.execute("CREATE TABLE t (x TEXT)")
        conn.close()

    def test_read_only_always_plain(self, tmp_path: Path):
        """read_only=True uses plain sqlite3 even if key is set."""
        db = tmp_path / "readonly.db"
        # Create a plain DB first
        c = sqlite3.connect(str(db))
        c.execute("CREATE TABLE t (id INTEGER)")
        c.close()
        # Open read-only with a key — should not try SQLCipher
        conn = open_db(db, encryption_key="some-key", read_only=True)
        conn.execute("SELECT count(*) FROM t")
        conn.close()

    def test_key_set_but_no_sqlcipher(self, tmp_path: Path):
        """If key is set but pysqlcipher3 not installed, raise RuntimeError."""
        if _HAS_SQLCIPHER:
            pytest.skip("pysqlcipher3 is installed — cannot test fallback")
        db = tmp_path / "test.db"
        with pytest.raises(RuntimeError, match="pysqlcipher3 is not installed"):
            open_db(db, encryption_key="my-key")

    def test_memory_db_skips_encryption(self):
        """In-memory DBs skip encryption even with a key."""
        conn = open_db(":memory:", encryption_key="key")
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.close()


# ---------------------------------------------------------------------------
# Escape utility
# ---------------------------------------------------------------------------


class TestEscapePragma:
    def test_no_quotes(self):
        assert _escape_pragma_value("abc123") == "abc123"

    def test_single_quotes(self):
        assert _escape_pragma_value("it's") == "it''s"

    def test_multiple_quotes(self):
        assert _escape_pragma_value("a'b'c") == "a''b''c"


# ---------------------------------------------------------------------------
# Encryption status
# ---------------------------------------------------------------------------


class TestEncryptionStatus:
    def test_no_key(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            status = encryption_status()
            assert status["enabled"] is False
            assert status["cipher"] == "none"

    def test_key_without_sqlcipher(self):
        if _HAS_SQLCIPHER:
            pytest.skip("pysqlcipher3 installed")
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": "key"}):
            status = encryption_status()
            assert status["enabled"] is False
            assert "error" in status
            assert isinstance(status["error"], str)


# ---------------------------------------------------------------------------
# Plaintext detection
# ---------------------------------------------------------------------------


class TestPlaintextDetection:
    def test_plaintext_db(self, tmp_path: Path):
        db = tmp_path / "plain.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.close()
        assert is_plaintext_db(db) is True

    def test_nonexistent_file(self, tmp_path: Path):
        assert is_plaintext_db(tmp_path / "nope.db") is False

    def test_corrupt_file(self, tmp_path: Path):
        bad = tmp_path / "corrupt.db"
        bad.write_bytes(b"this is not a database")
        assert is_plaintext_db(bad) is False


# ---------------------------------------------------------------------------
# Integration with SharedContext (plain mode)
# ---------------------------------------------------------------------------


class TestSharedContextIntegration:
    def test_shared_context_uses_open_db(self, tmp_path: Path):
        """SharedContext.get_conn() works without encryption configured."""
        from sigrift.bridge.storage.base import SharedContext

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            ctx = SharedContext(db_path=tmp_path / "test.db")
            conn = ctx.get_conn()
            # Should be a working connection
            row = conn.execute("SELECT 1").fetchone()
            assert row[0] == 1

    def test_is_encrypted_property_no_key(self, tmp_path: Path):
        from sigrift.bridge.storage.base import SharedContext

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            ctx = SharedContext(db_path=tmp_path / "test.db")
            assert ctx.is_encrypted is False


# ---------------------------------------------------------------------------
# SQLCipher-specific tests (skipped if not installed)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not _HAS_SQLCIPHER, reason="pysqlcipher3 not installed")
class TestSQLCipherEncryption:
    def test_encrypted_db_roundtrip(self, tmp_path: Path):
        """Create encrypted DB, write data, reopen and read."""
        db = tmp_path / "encrypted.db"
        key = "test-encryption-key-for-ci"

        conn = open_db(db, encryption_key=key)
        conn.execute("CREATE TABLE secrets (id INTEGER, value TEXT)")
        conn.execute("INSERT INTO secrets VALUES (1, 'classified')")
        conn.commit()
        conn.close()

        # Reopen with same key — should read data
        conn2 = open_db(db, encryption_key=key)
        row = conn2.execute("SELECT value FROM secrets WHERE id=1").fetchone()
        assert row[0] == "classified"
        conn2.close()

    def test_wrong_key_fails(self, tmp_path: Path):
        """Opening encrypted DB with wrong key raises error."""
        db = tmp_path / "encrypted.db"
        conn = open_db(db, encryption_key="correct-key")
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        conn2 = open_db(db, encryption_key="wrong-key")
        with pytest.raises(Exception):
            conn2.execute("SELECT count(*) FROM sqlite_master")

    def test_no_key_cannot_read_encrypted(self, tmp_path: Path):
        """Plain sqlite3 cannot read an encrypted database."""
        db = tmp_path / "encrypted.db"
        conn = open_db(db, encryption_key="secret")
        conn.execute("CREATE TABLE t (id INTEGER)")
        conn.commit()
        conn.close()

        # Plain sqlite3 should fail
        plain = sqlite3.connect(str(db))
        with pytest.raises(sqlite3.DatabaseError):
            plain.execute("SELECT count(*) FROM sqlite_master")
        plain.close()

    def test_encrypt_existing_db(self, tmp_path: Path):
        """Convert a plaintext DB to encrypted."""
        from sigrift.bridge.storage.encryption import encrypt_existing_db

        db = tmp_path / "plain.db"
        key = "migration-key"

        # Create plaintext DB with data
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE data (id INTEGER, val TEXT)")
        conn.execute("INSERT INTO data VALUES (1, 'hello')")
        conn.commit()
        conn.close()

        # Encrypt
        backup = encrypt_existing_db(db, key)
        assert backup.exists()
        assert backup.suffix == ".bak"

        # Original path now has encrypted DB
        conn2 = open_db(db, encryption_key=key)
        row = conn2.execute("SELECT val FROM data WHERE id=1").fetchone()
        assert row[0] == "hello"
        conn2.close()

        # Plain sqlite3 cannot read it
        plain = sqlite3.connect(str(db))
        with pytest.raises(sqlite3.DatabaseError):
            plain.execute("SELECT count(*) FROM sqlite_master")
        plain.close()

    def test_encryption_status_with_sqlcipher(self):
        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": "test"}):
            status = encryption_status()
            assert status["enabled"] is True
            assert status["cipher"] == "sqlcipher"
            assert status["sqlcipher_version"] is not None
            assert isinstance(status["sqlcipher_version"], str)
            assert isinstance(status["kdf_iter"], int)

    def test_backup_encrypted(self, tmp_path: Path):
        """Backup of encrypted DB is also encrypted."""
        from sigrift.bridge.storage.base import SharedContext

        db = tmp_path / "main.db"
        backup_path = tmp_path / "backup.db"
        key = "backup-test-key"

        with patch.dict(os.environ, {"BRIDGE_DB_ENCRYPTION_KEY": key}):
            ctx = SharedContext(db_path=db)
            conn = ctx.get_conn()
            conn.execute("INSERT INTO detections (detection_id, timestamp, freq_hz, signal_class, power_dbm, node_id, tenant_id) VALUES ('d1', '2026-01-01', 100e6, 'fm', -40, 'n1', 'default')")
            conn.commit()

            ctx.backup(backup_path)

        # Backup should be encrypted — plain sqlite3 fails
        plain = sqlite3.connect(str(backup_path))
        with pytest.raises(sqlite3.DatabaseError):
            plain.execute("SELECT count(*) FROM sqlite_master")
        plain.close()

        # But opening with key works
        conn2 = open_db(backup_path, encryption_key=key)
        count = conn2.execute("SELECT count(*) FROM detections").fetchone()[0]
        assert count >= 1
        conn2.close()
