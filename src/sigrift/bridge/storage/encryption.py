"""SQLCipher encryption layer for SigRift SQLite databases.

Provides ``open_db()`` as a drop-in replacement for ``sqlite3.connect()``
that optionally applies SQLCipher transparent encryption.  When
``pysqlcipher3`` is not installed the module falls back to plain
``sqlite3`` — encryption is fully optional.

Environment variables
---------------------
BRIDGE_DB_ENCRYPTION_KEY
    Raw passphrase for SQLCipher.  If set, every database opened through
    ``open_db()`` is encrypted (except ``:memory:`` and read-only opens).
BRIDGE_DB_ENCRYPTION_KEY_FILE
    Path to a file containing the passphrase (must be chmod 600).
    Checked only when BRIDGE_DB_ENCRYPTION_KEY is not set.
BRIDGE_SQLCIPHER_KDF_ITER
    PBKDF2 iterations (default 256000).  Lower = faster, less secure.
BRIDGE_SQLCIPHER_PAGE_SIZE
    Cipher page size (default 4096).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional pysqlcipher3 import
# ---------------------------------------------------------------------------

_HAS_SQLCIPHER = False
_sqlcipher_db: Any = None

try:
    from pysqlcipher3 import dbapi2 as _sqlcipher_db  # type: ignore[no-redef]

    _HAS_SQLCIPHER = True
except ImportError:
    pass


def database_errors() -> tuple[type[Exception], ...]:
    """The base exception classes a database from :func:`open_db` raises.

    ``pysqlcipher3``'s ``dbapi2`` errors do not inherit from
    :class:`sqlite3.Error`, so a handler for storage errors must catch
    both when encryption is available.
    """
    if _HAS_SQLCIPHER and _sqlcipher_db is not None:
        return (sqlite3.Error, _sqlcipher_db.Error)
    return (sqlite3.Error,)


# ---------------------------------------------------------------------------
# Key resolution (cached per-process)
# ---------------------------------------------------------------------------

_SENTINEL = object()
_cached_key: str | None = _SENTINEL  # type: ignore[assignment]


def _resolve_encryption_key() -> str | None:
    """Resolve the encryption key from env var or key file.

    Returns None if no key is configured (unencrypted mode).
    """
    global _cached_key
    if _cached_key is not _SENTINEL:
        return _cached_key

    # 1. Direct env var
    key = os.environ.get("BRIDGE_DB_ENCRYPTION_KEY", "").strip()
    if key:
        _cached_key = key
        return key

    # 2. Key file
    key_file = os.environ.get("BRIDGE_DB_ENCRYPTION_KEY_FILE", "").strip()
    if key_file:
        path = Path(key_file)
        if not path.exists():
            raise FileNotFoundError(
                f"BRIDGE_DB_ENCRYPTION_KEY_FILE not found: {key_file}"
            )
        # Validate permissions (Linux/macOS only)
        if hasattr(os, "stat"):
            st = path.stat()
            mode = st.st_mode
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
                raise PermissionError(
                    f"BRIDGE_DB_ENCRYPTION_KEY_FILE {key_file} is group/other "
                    f"readable (mode {oct(mode)}). Fix: chmod 600 {key_file}"
                )
        key = path.read_text().strip()
        if not key:
            raise ValueError(f"BRIDGE_DB_ENCRYPTION_KEY_FILE {key_file} is empty")
        _cached_key = key
        return key

    _cached_key = None
    return None


def reset_cached_key() -> None:
    """Reset the cached key (for testing)."""
    global _cached_key
    _cached_key = _SENTINEL  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Connection factory
# ---------------------------------------------------------------------------


def open_db(
    path: str | Path,
    *,
    encryption_key: str | None | object = _SENTINEL,
    read_only: bool = False,
    timeout: float = 5.0,
    check_same_thread: bool = True,
) -> sqlite3.Connection:
    """Open a SQLite/SQLCipher database connection.

    Parameters
    ----------
    path : str or Path
        Database file path, or ``:memory:`` for in-memory databases.
    encryption_key : str, None, or sentinel
        Explicit key override.  If not provided (sentinel), resolves
        from environment.  None = no encryption.
    read_only : bool
        If True, always use plain sqlite3 (for mbtiles, etc.).
    timeout : float
        Busy timeout in seconds (passed to connect()).
    check_same_thread : bool
        Passed to ``connect()``.  ``SharedContext`` opens its per-thread
        connections with ``False`` so that ``close()`` can close them from
        the shutdown thread; each one is still only *used* by the thread
        that opened it.
    """
    path_str = str(path)

    # Resolve key
    if encryption_key is _SENTINEL:
        key = _resolve_encryption_key()
    else:
        key = encryption_key  # type: ignore[assignment]

    # Skip encryption for :memory: or read-only opens
    if path_str == ":memory:" or read_only or not key:
        return sqlite3.connect(
            path_str, timeout=timeout, check_same_thread=check_same_thread
        )

    # Encryption requested
    if not _HAS_SQLCIPHER:
        raise RuntimeError(
            "BRIDGE_DB_ENCRYPTION_KEY is set but pysqlcipher3 is not installed. "
            "Install: apt-get install libsqlcipher-dev && pip install pysqlcipher3"
        )

    conn = _sqlcipher_db.connect(
        path_str, timeout=timeout, check_same_thread=check_same_thread
    )

    # PRAGMA key must be the FIRST statement on a new connection
    conn.execute(f"PRAGMA key='{_escape_pragma_value(key)}'")

    # Tuning
    kdf_iter = int(os.environ.get("BRIDGE_SQLCIPHER_KDF_ITER", "256000"))
    page_size = int(os.environ.get("BRIDGE_SQLCIPHER_PAGE_SIZE", "4096"))
    conn.execute(f"PRAGMA kdf_iter={kdf_iter}")
    conn.execute(f"PRAGMA cipher_page_size={page_size}")

    return conn


def _escape_pragma_value(value: str) -> str:
    """Escape single quotes in PRAGMA key values."""
    return value.replace("'", "''")


# ---------------------------------------------------------------------------
# Encryption status
# ---------------------------------------------------------------------------


def encryption_status() -> dict[str, Any]:
    """Return current encryption configuration status."""
    key = _resolve_encryption_key()
    result: dict[str, Any] = {
        "enabled": False,
        "cipher": "none",
        "sqlcipher_installed": _HAS_SQLCIPHER,
        "sqlcipher_version": None,
        "kdf_iter": None,
    }

    if not key:
        return result

    if not _HAS_SQLCIPHER:
        result["error"] = "key configured but pysqlcipher3 not installed"
        return result

    result["enabled"] = True
    result["cipher"] = "sqlcipher"
    result["kdf_iter"] = int(os.environ.get("BRIDGE_SQLCIPHER_KDF_ITER", "256000"))

    # Try to get SQLCipher version
    try:
        conn = _sqlcipher_db.connect(":memory:")
        conn.execute("PRAGMA key='probe'")
        ver = conn.execute("PRAGMA cipher_version").fetchone()
        if ver:
            result["sqlcipher_version"] = ver[0]
        conn.close()
    except Exception:
        pass

    return result


# ---------------------------------------------------------------------------
# Plaintext-to-encrypted migration
# ---------------------------------------------------------------------------


def is_encrypted_db(path: str | Path, key: str) -> bool:
    """Check whether a database file is already encrypted with the given key.

    Returns True if the file can be opened with the key and queried.
    Returns False if the file appears to be plaintext or uses a different key.
    """
    path_str = str(path)
    if not Path(path_str).exists() or path_str == ":memory:":
        return False

    if not _HAS_SQLCIPHER:
        return False

    try:
        conn = _sqlcipher_db.connect(path_str)
        conn.execute(f"PRAGMA key='{_escape_pragma_value(key)}'")
        kdf = int(os.environ.get("BRIDGE_SQLCIPHER_KDF_ITER", "256000"))
        ps = int(os.environ.get("BRIDGE_SQLCIPHER_PAGE_SIZE", "4096"))
        conn.execute(f"PRAGMA kdf_iter={kdf}")
        conn.execute(f"PRAGMA cipher_page_size={ps}")
        conn.execute("SELECT count(*) FROM sqlite_master")
        conn.close()
        return True
    except Exception:
        return False


def is_plaintext_db(path: str | Path) -> bool:
    """Check whether a database file is a plaintext (unencrypted) SQLite DB."""
    path_str = str(path)
    if not Path(path_str).exists():
        return False
    try:
        conn = sqlite3.connect(path_str)
        conn.execute("SELECT count(*) FROM sqlite_master")
        conn.close()
        return True
    except Exception:
        return False


def encrypt_existing_db(
    path: str | Path,
    key: str,
    *,
    kdf_iter: int | None = None,
    page_size: int | None = None,
) -> Path:
    """Convert a plaintext SQLite database to an encrypted SQLCipher database.

    The original file is renamed to ``<path>.unencrypted.bak`` and the
    encrypted version replaces it at the original path.

    Returns the path to the backup (unencrypted) file.
    """
    if not _HAS_SQLCIPHER:
        raise RuntimeError("pysqlcipher3 required for encryption migration")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Database not found: {path}")

    backup_path = path.with_suffix(path.suffix + ".unencrypted.bak")
    encrypted_path = path.with_suffix(path.suffix + ".encrypted")

    kdf = kdf_iter or int(os.environ.get("BRIDGE_SQLCIPHER_KDF_ITER", "256000"))
    ps = page_size or int(os.environ.get("BRIDGE_SQLCIPHER_PAGE_SIZE", "4096"))

    logger.warning("Encrypting existing database: %s", path)

    try:
        # Open the plaintext DB through SQLCipher: only it has
        # sqlcipher_export(), not the stdlib sqlite3 module.  Without a
        # key the connection reads the file as plain SQLite.
        plain_conn = _sqlcipher_db.connect(str(path))
        try:
            # Attach encrypted destination
            plain_conn.execute(
                f"ATTACH DATABASE '{_escape_pragma_value(str(encrypted_path))}' "
                f"AS encrypted KEY '{_escape_pragma_value(key)}'"
            )
            plain_conn.execute(f"PRAGMA encrypted.kdf_iter={kdf}")
            plain_conn.execute(f"PRAGMA encrypted.cipher_page_size={ps}")
            plain_conn.execute("SELECT sqlcipher_export('encrypted')")
            plain_conn.execute("DETACH DATABASE encrypted")
        finally:
            plain_conn.close()
    except BaseException:
        # The plaintext DB is untouched; leave no empty or partial copy.
        encrypted_path.unlink(missing_ok=True)
        raise

    # Swap files
    import shutil

    shutil.move(str(path), str(backup_path))
    # Also move WAL/SHM if they exist
    for ext in ("-wal", "-shm"):
        wal = Path(str(path) + ext)
        if wal.exists():
            wal.unlink()
    shutil.move(str(encrypted_path), str(path))

    logger.warning(
        "Database encrypted successfully. Unencrypted backup: %s",
        backup_path,
    )
    return backup_path
