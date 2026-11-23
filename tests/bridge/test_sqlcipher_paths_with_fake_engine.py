"""The SQLCipher paths of ``storage/encryption.py``, run against a fake engine.

``pysqlcipher3`` is not installed in CI, so ``test_sqlcipher_encryption.py``
skips everything that needs it. Here a small stand-in for
``pysqlcipher3.dbapi2`` records each statement and checks the key, so the
paths run anyway: the key reaches SQLCipher as one intact SQL literal and
before any other statement, malformed tuning settings are refused rather
than spliced into SQL, the status report never carries the key, a wrong key
or a plaintext file is not reported as encrypted, and a plaintext database
is migrated through SQLCipher (also where the stdlib ``sqlite3`` is stock
SQLite) with its data, a byte-identical backup and no stale WAL/SHM files,
or left untouched, with no partial encrypted copy, when the migration
cannot run.

The fake decodes every quoted value with the real SQLite parser, so an
unescaped quote fails the test with a syntax error.
"""

from __future__ import annotations

import importlib.util
import re
import sqlite3
import sys
import types
from contextlib import closing
from pathlib import Path

import pytest

from sigrift.bridge.storage import encryption
from sigrift.bridge.storage.base import SharedContext

_CIPHER_MAGIC = b"FAKE-SQLCIPHER\0"
# A key with a quote and a smuggled statement: it only survives intact when
# it is escaped as a single SQL string literal.
TRICKY_KEY = "o'brien'; ATTACH DATABASE 'x' AS y; --"


class FakeCipherError(Exception):
    """Like ``pysqlcipher3.dbapi2.Error``: not a ``sqlite3.Error`` subclass."""


def _cipher_header(key: str) -> bytes:
    """How the fake engine marks a file encrypted under *key*."""
    return _CIPHER_MAGIC + key.encode() + b"\0"


def _sql_values(*literals: str) -> tuple:
    """Evaluate SQL literals with the real SQLite parser."""
    with closing(sqlite3.connect(":memory:")) as probe:
        return probe.execute("SELECT " + ", ".join(literals)).fetchone()


class _FakeCursor:
    def __init__(self, row: tuple | None) -> None:
        self._row = row

    def fetchone(self) -> tuple | None:
        return self._row


class _FakeCipherConnection:
    def __init__(self, engine: _FakeSQLCipher, path: str, options: dict) -> None:
        self.engine = engine
        self.path = Path(path)
        self.options = options
        self.statements: list[str] = []
        self.key: str | None = None
        self.attached: tuple[str, str] | None = None
        self.closed = False

    def execute(self, sql: str) -> _FakeCursor:
        self.statements.append(sql)
        if self.engine.failing_statement and sql.startswith(
            self.engine.failing_statement
        ):
            raise FakeCipherError("disk I/O error")
        if sql.startswith("PRAGMA key="):
            (self.key,) = _sql_values(sql.removeprefix("PRAGMA key="))
        elif sql.startswith("ATTACH DATABASE "):
            match = re.fullmatch(r"ATTACH DATABASE (.+) AS encrypted KEY (.+)", sql)
            self.attached = _sql_values(match[1], match[2])
            # Like SQLite, ATTACH creates the (empty) database file.
            Path(self.attached[0]).touch()
        elif sql == "SELECT sqlcipher_export('encrypted')":
            self._export()
        elif sql == "SELECT count(*) FROM sqlite_master":
            self._check_key()
        elif sql == "PRAGMA cipher_version":
            return _FakeCursor(self.engine.version_row)
        return _FakeCursor(None)

    def _export(self) -> None:
        target, key = self.attached
        Path(target).write_bytes(_cipher_header(key) + self.path.read_bytes())

    def _check_key(self) -> None:
        if not self.path.read_bytes().startswith(_cipher_header(self.key)):
            raise FakeCipherError("file is not a database")

    def close(self) -> None:
        self.closed = True


class _FakeSQLCipher:
    """Stands in for the ``pysqlcipher3.dbapi2`` module."""

    Error = FakeCipherError

    def __init__(self) -> None:
        self.version_row: tuple | None = ("4.6.1 community",)
        # Statements starting with this fail with an engine error.
        self.failing_statement: str | None = None
        self.connections: list[_FakeCipherConnection] = []

    def connect(self, path: str, **options: object) -> _FakeCipherConnection:
        conn = _FakeCipherConnection(self, path, options)
        self.connections.append(conn)
        return conn


@pytest.fixture(autouse=True)
def _clean_encryption_env(monkeypatch: pytest.MonkeyPatch):
    for name in (
        "BRIDGE_DB_ENCRYPTION_KEY",
        "BRIDGE_DB_ENCRYPTION_KEY_FILE",
        "BRIDGE_SQLCIPHER_KDF_ITER",
        "BRIDGE_SQLCIPHER_PAGE_SIZE",
    ):
        monkeypatch.delenv(name, raising=False)
    encryption.reset_cached_key()
    yield
    encryption.reset_cached_key()


@pytest.fixture
def no_sqlcipher(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host without ``pysqlcipher3`` (as in CI), whatever this one has."""
    monkeypatch.setattr(encryption, "_HAS_SQLCIPHER", False)


@pytest.fixture
def sqlcipher(monkeypatch: pytest.MonkeyPatch) -> _FakeSQLCipher:
    """A host with ``pysqlcipher3`` installed."""
    engine = _FakeSQLCipher()
    monkeypatch.setattr(encryption, "_HAS_SQLCIPHER", True)
    monkeypatch.setattr(encryption, "_sqlcipher_db", engine)
    return engine


class _StockConnection(sqlite3.Connection):
    """A stdlib connection of a standard Python build: no SQLCipher in it."""

    def execute(self, sql: str, *args: object) -> sqlite3.Cursor:
        if "sqlcipher_export" in sql:
            raise sqlite3.OperationalError("no such function: sqlcipher_export")
        return super().execute(sql, *args)


@pytest.fixture
def stock_sqlite3(monkeypatch: pytest.MonkeyPatch) -> None:
    """The module's ``sqlite3`` links stock SQLite, without SQLCipher.

    As on Debian, Raspberry Pi OS, python.org builds and in CI, also with
    ``pysqlcipher3`` installed. Pinned here so the tests do not depend on
    how this host's Python was built.
    """

    def connect(path: str, **options: object) -> sqlite3.Connection:
        return sqlite3.connect(path, factory=_StockConnection, **options)

    monkeypatch.setattr(
        encryption,
        "sqlite3",
        types.SimpleNamespace(connect=connect, Error=sqlite3.Error),
    )


def _plaintext_db(path: Path) -> Path:
    with closing(sqlite3.connect(str(path))) as conn:
        conn.execute("CREATE TABLE secrets (id INTEGER, value TEXT)")
        conn.execute("INSERT INTO secrets VALUES (1, 'classified')")
        conn.commit()
    return path


def _rows(path: Path) -> list[tuple]:
    with closing(sqlite3.connect(str(path))) as conn:
        return conn.execute("SELECT id, value FROM secrets").fetchall()


# ---------------------------------------------------------------------------
# Import detection
# ---------------------------------------------------------------------------


def test_an_importable_pysqlcipher3_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Load a private copy of the module with ``pysqlcipher3`` importable.

    The copy is never put in ``sys.modules``, so the module every other test
    uses keeps its own state.
    """
    installed_here = encryption._HAS_SQLCIPHER
    engine = _FakeSQLCipher()
    package = types.ModuleType("pysqlcipher3")
    package.dbapi2 = engine
    monkeypatch.setitem(sys.modules, "pysqlcipher3", package)
    spec = importlib.util.spec_from_file_location(
        "_sigrift_encryption_copy", encryption.__file__
    )
    copy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(copy)

    assert copy._HAS_SQLCIPHER is True
    assert copy._sqlcipher_db is engine
    # A storage error handler has to catch the engine's own errors too.
    assert copy.database_errors() == (sqlite3.Error, FakeCipherError)
    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "copy-key")
    assert copy.encryption_status()["enabled"] is True
    assert encryption._HAS_SQLCIPHER is installed_here


# ---------------------------------------------------------------------------
# open_db
# ---------------------------------------------------------------------------


def test_open_db_keys_the_connection_first_with_one_intact_literal(
    sqlcipher: _FakeSQLCipher, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_SQLCIPHER_KDF_ITER", "64000")
    monkeypatch.setenv("BRIDGE_SQLCIPHER_PAGE_SIZE", "1024")
    conn = encryption.open_db(
        tmp_path / "s.db",
        encryption_key=TRICKY_KEY,
        timeout=2.5,
        check_same_thread=False,
    )
    assert sqlcipher.connections == [conn]
    assert conn.path == tmp_path / "s.db"
    assert conn.options == {"timeout": 2.5, "check_same_thread": False}
    assert conn.key == TRICKY_KEY
    assert conn.statements == [
        "PRAGMA key='o''brien''; ATTACH DATABASE ''x'' AS y; --'",
        "PRAGMA kdf_iter=64000",
        "PRAGMA cipher_page_size=1024",
    ]


def test_open_db_uses_the_configured_key_and_default_tuning(
    sqlcipher: _FakeSQLCipher, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "  env-key  ")
    conn = encryption.open_db(tmp_path / "s.db")
    assert conn.options == {"timeout": 5.0, "check_same_thread": True}
    assert conn.key == "env-key"
    assert conn.statements[1:] == [
        "PRAGMA kdf_iter=256000",
        "PRAGMA cipher_page_size=4096",
    ]


def test_memory_and_read_only_opens_bypass_sqlcipher(
    sqlcipher: _FakeSQLCipher, tmp_path: Path
) -> None:
    tiles = _plaintext_db(tmp_path / "tiles.mbtiles")
    for conn in (
        encryption.open_db(":memory:", encryption_key="k"),
        encryption.open_db(tiles, encryption_key="k", read_only=True),
    ):
        with closing(conn):
            assert isinstance(conn, sqlite3.Connection)
    assert sqlcipher.connections == []


@pytest.mark.parametrize(
    "setting", ["BRIDGE_SQLCIPHER_KDF_ITER", "BRIDGE_SQLCIPHER_PAGE_SIZE"]
)
def test_a_non_integer_tuning_setting_is_refused_not_spliced_into_sql(
    sqlcipher: _FakeSQLCipher,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
) -> None:
    monkeypatch.setenv(setting, "4096; PRAGMA cipher_plaintext_header_size=32")
    with pytest.raises(ValueError):
        encryption.open_db(tmp_path / "s.db", encryption_key="k")
    (conn,) = sqlcipher.connections
    assert not any("plaintext_header" in sql for sql in conn.statements)


# ---------------------------------------------------------------------------
# encryption_status
# ---------------------------------------------------------------------------


def test_status_reports_sqlcipher_without_exposing_the_key(
    sqlcipher: _FakeSQLCipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "status-secret")
    monkeypatch.setenv("BRIDGE_SQLCIPHER_KDF_ITER", "100000")
    status = encryption.encryption_status()
    assert status == {
        "enabled": True,
        "cipher": "sqlcipher",
        "sqlcipher_installed": True,
        "sqlcipher_version": "4.6.1 community",
        "kdf_iter": 100000,
    }
    assert "status-secret" not in repr(status)
    # The version probe keys an in-memory database with a throwaway key,
    # never the real one, and closes it.
    (probe,) = sqlcipher.connections
    assert probe.path == Path(":memory:")
    assert probe.key == "probe"
    assert not any("status-secret" in sql for sql in probe.statements)
    assert probe.closed is True


def test_status_without_a_version_row_leaves_the_version_unknown(
    sqlcipher: _FakeSQLCipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "k")
    sqlcipher.version_row = None
    status = encryption.encryption_status()
    assert status["enabled"] is True
    assert status["sqlcipher_version"] is None
    # An empty answer is handled, not swallowed as an error: the probe still
    # reaches close().
    (probe,) = sqlcipher.connections
    assert probe.closed is True


def test_status_survives_a_failing_version_probe(
    sqlcipher: _FakeSQLCipher, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: str, **options: object) -> None:
        raise FakeCipherError("unable to open database")

    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "k")
    monkeypatch.setattr(sqlcipher, "connect", refuse)
    status = encryption.encryption_status()
    assert status["enabled"] is True
    assert status["cipher"] == "sqlcipher"
    assert status["sqlcipher_version"] is None
    assert "error" not in status


# ---------------------------------------------------------------------------
# is_encrypted_db
# ---------------------------------------------------------------------------


def test_is_encrypted_db_accepts_only_the_right_key(
    sqlcipher: _FakeSQLCipher, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("BRIDGE_SQLCIPHER_KDF_ITER", "64000")
    db = tmp_path / "enc.db"
    db.write_bytes(_cipher_header(TRICKY_KEY) + b"pages")

    assert encryption.is_encrypted_db(db, TRICKY_KEY) is True
    (conn,) = sqlcipher.connections
    assert conn.key == TRICKY_KEY
    assert conn.statements[1:] == [
        "PRAGMA kdf_iter=64000",
        "PRAGMA cipher_page_size=4096",
        "SELECT count(*) FROM sqlite_master",
    ]
    assert conn.closed is True

    assert encryption.is_encrypted_db(db, "o'brien") is False


def test_a_plaintext_database_is_not_reported_encrypted(
    sqlcipher: _FakeSQLCipher, tmp_path: Path
) -> None:
    db = _plaintext_db(tmp_path / "plain.db")
    assert encryption.is_encrypted_db(db, "any-key") is False


def test_a_missing_or_memory_database_is_not_reported_encrypted(
    sqlcipher: _FakeSQLCipher, tmp_path: Path
) -> None:
    assert encryption.is_encrypted_db(tmp_path / "missing.db", "k") is False
    assert encryption.is_encrypted_db(":memory:", "k") is False
    assert sqlcipher.connections == []


def test_without_sqlcipher_nothing_is_reported_encrypted(
    sqlcipher: _FakeSQLCipher, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The engine would accept this key; without pysqlcipher3 it is never
    # asked.
    monkeypatch.setattr(encryption, "_HAS_SQLCIPHER", False)
    db = tmp_path / "enc.db"
    db.write_bytes(_cipher_header("k"))
    assert encryption.is_encrypted_db(db, "k") is False
    assert sqlcipher.connections == []


# ---------------------------------------------------------------------------
# encrypt_existing_db
# ---------------------------------------------------------------------------


def test_migration_without_sqlcipher_refuses_and_touches_nothing(
    no_sqlcipher: None, tmp_path: Path
) -> None:
    db = _plaintext_db(tmp_path / "plain.db")
    original = db.read_bytes()
    with pytest.raises(RuntimeError, match="pysqlcipher3 required"):
        encryption.encrypt_existing_db(db, "k")
    assert db.read_bytes() == original
    assert sorted(p.name for p in tmp_path.iterdir()) == ["plain.db"]


def test_migration_of_a_missing_database_creates_nothing(
    sqlcipher: _FakeSQLCipher, stock_sqlite3: None, tmp_path: Path
) -> None:
    with pytest.raises(FileNotFoundError, match="Database not found"):
        encryption.encrypt_existing_db(tmp_path / "missing.db", "k")
    assert list(tmp_path.iterdir()) == []
    assert sqlcipher.connections == []


@pytest.mark.parametrize(
    ("side_files", "tuning", "kdf_iter", "page_size"),
    [
        pytest.param((), {}, 256000, 4096, id="defaults"),
        pytest.param(
            ("-wal",),
            {"kdf_iter": 64000, "page_size": 1024},
            64000,
            1024,
            id="stale-wal",
        ),
        pytest.param(
            ("-wal", "-shm"),
            {"kdf_iter": 1000},
            1000,
            4096,
            id="stale-wal-and-shm",
        ),
    ],
)
def test_migration_encrypts_the_data_and_keeps_a_byte_identical_backup(
    sqlcipher: _FakeSQLCipher,
    stock_sqlite3: None,
    tmp_path: Path,
    side_files: tuple[str, ...],
    tuning: dict[str, int],
    kdf_iter: int,
    page_size: int,
) -> None:
    db = _plaintext_db(tmp_path / "bridge.db")
    original = db.read_bytes()
    for ext in side_files:
        Path(f"{db}{ext}").write_bytes(b"stale journal of the plaintext db")

    backup = encryption.encrypt_existing_db(db, TRICKY_KEY, **tuning)

    # No temporary copy is left, and no journal of the old plaintext file
    # sits beside the encrypted one, where SQLite would try to replay it.
    # Checked first: opening the file with sqlite3 below would itself clear
    # a stale -wal and hide one the migration left behind.
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "bridge.db",
        "bridge.db.unencrypted.bak",
    ]
    assert backup == tmp_path / "bridge.db.unencrypted.bak"
    assert backup.read_bytes() == original
    assert _rows(backup) == [(1, "classified")]
    # The original path now holds the export of the plaintext database,
    # under the key, and no longer reads as SQLite.
    assert db.read_bytes() == _cipher_header(TRICKY_KEY) + original
    with closing(sqlite3.connect(str(db))) as plain:
        with pytest.raises(sqlite3.DatabaseError):
            plain.execute("SELECT count(*) FROM sqlite_master")
    assert encryption.is_encrypted_db(db, TRICKY_KEY) is True

    # The export ran on a SQLCipher connection (the only kind that has
    # sqlcipher_export), opened without a key so it reads the plaintext.
    export = sqlcipher.connections[0]
    assert export.path == db
    assert export.key is None
    assert export.attached == (str(tmp_path / "bridge.db.encrypted"), TRICKY_KEY)
    assert export.statements[1:] == [
        f"PRAGMA encrypted.kdf_iter={kdf_iter}",
        f"PRAGMA encrypted.cipher_page_size={page_size}",
        "SELECT sqlcipher_export('encrypted')",
        "DETACH DATABASE encrypted",
    ]
    assert export.closed is True


def test_the_start_up_migration_works_on_a_stock_sqlite3_host(
    sqlcipher: _FakeSQLCipher,
    stock_sqlite3: None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``pysqlcipher3`` installed, a key configured, an old plaintext DB.

    The stdlib ``sqlite3`` has no ``sqlcipher_export`` there, so a migration
    run through it failed at every start-up.
    """
    with closing(encryption.sqlite3.connect(":memory:")) as stdlib:
        with pytest.raises(sqlite3.OperationalError, match="sqlcipher_export"):
            stdlib.execute("SELECT sqlcipher_export('encrypted')")
    db = _plaintext_db(tmp_path / "bridge.db")
    original = db.read_bytes()
    monkeypatch.setenv("BRIDGE_DB_ENCRYPTION_KEY", "start-up-key")

    # What SharedContext._init_db runs before it opens the database.
    SharedContext._maybe_encrypt_existing_db(types.SimpleNamespace(_db_path=str(db)))

    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "bridge.db",
        "bridge.db.unencrypted.bak",
    ]
    assert db.read_bytes() == _cipher_header("start-up-key") + original
    assert _rows(tmp_path / "bridge.db.unencrypted.bak") == [(1, "classified")]
    assert [conn.closed for conn in sqlcipher.connections] == [True]


def test_a_quote_in_the_data_directory_reaches_attach_as_one_literal(
    sqlcipher: _FakeSQLCipher, stock_sqlite3: None, tmp_path: Path
) -> None:
    data_dir = tmp_path / "o'brien"
    data_dir.mkdir()
    db = _plaintext_db(data_dir / "bridge.db")
    original = db.read_bytes()

    encryption.encrypt_existing_db(db, TRICKY_KEY)

    (export,) = sqlcipher.connections
    assert export.attached == (str(data_dir / "bridge.db.encrypted"), TRICKY_KEY)
    assert db.read_bytes() == _cipher_header(TRICKY_KEY) + original


@pytest.mark.parametrize(
    "failing_statement",
    [
        "ATTACH DATABASE",
        "PRAGMA encrypted.kdf_iter",
        "SELECT sqlcipher_export",
        "DETACH DATABASE",
    ],
)
def test_a_failed_export_leaves_only_the_plaintext_database(
    sqlcipher: _FakeSQLCipher,
    stock_sqlite3: None,
    tmp_path: Path,
    failing_statement: str,
) -> None:
    db = _plaintext_db(tmp_path / "bridge.db")
    original = db.read_bytes()
    sqlcipher.failing_statement = failing_statement

    with pytest.raises(FakeCipherError, match="disk I/O error"):
        encryption.encrypt_existing_db(db, "k")

    # No backup, and no empty or half-written encrypted copy beside it.
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bridge.db"]
    assert db.read_bytes() == original
    assert _rows(db) == [(1, "classified")]
    (export,) = sqlcipher.connections
    assert export.closed is True
