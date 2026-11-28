"""The pre-migration copy policy of ``SharedContext._run_migrations``.

Before it applies pending migrations to an existing database the bridge
copies it to ``<db>.pre-migration``.  A copy that cannot be made (usually a
full disk) now stops the upgrade before any migration, unless
``BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP`` is set.  After a successful
upgrade the copy is kept for the 7-day sweep while at least max(1 GiB, the
database's size) stays free and the disk stays below 80% used; otherwise,
and for a new database, it is removed at once, as before.  The sweep also
runs on every periodic cleanup, so a long-running bridge removes it too, and
there earlier once the volume has no room for it.  The free space is checked
before the copy is written, so a refused start writes nothing.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import logging
import tempfile
import os
import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.bridge import app as app_module
from sigrift.bridge.storage import base, encryption
from sigrift.bridge.storage.base import SharedContext

GB = 10**9
PROBE = (50000, "harmless", "CREATE TABLE IF NOT EXISTS policy_probe (id INTEGER)")
ALLOW = "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP"


def upgrade_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fully migrated database with one new migration pending."""
    db = tmp_path / "detections.db"
    SharedContext(db).close()
    monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, PROBE])
    return db


def fake_usage(
    monkeypatch: pytest.MonkeyPatch, total: float, used: float, free: float
) -> None:
    usage = SimpleNamespace(total=int(total), used=int(used), free=int(free))
    monkeypatch.setattr(base, "_disk_usage", lambda path: usage)


def ample(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_usage(monkeypatch, 1000 * GB, 100 * GB, 900 * GB)


def fail_the_copy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-migration snapshot cannot be written (live connections can)."""
    real = encryption.open_db

    def open_db(path, *args, **kwargs):
        if ".pre-migration." in Path(path).name:
            raise sqlite3.OperationalError("database or disk is full")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(encryption, "open_db", open_db)


def applied(db: Path) -> set[int]:
    conn = sqlite3.connect(db)
    try:
        return {v for (v,) in conn.execute("SELECT version FROM schema_version")}
    finally:
        conn.close()


def has_probe_table(db: Path) -> bool:
    conn = sqlite3.connect(db)
    try:
        return bool(
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'policy_probe'"
            ).fetchone()
        )
    finally:
        conn.close()



def logged(caplog: pytest.LogCaptureFixture) -> str:
    """The captured messages, independent of the handler's formatter.

    Another test can leave a JSON formatter on the handlers, which escapes
    non-ASCII text (the em dash) in caplog.text; the messages never change.
    """
    return "\n".join(r.getMessage() for r in caplog.records)

def test_a_failed_copy_stops_the_upgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv(ALLOW, raising=False)
    db = upgrade_db(tmp_path, monkeypatch)
    fail_the_copy(monkeypatch)
    with caplog.at_level(logging.INFO, logger="sigrift.bridge.storage.base"):
        with pytest.raises(RuntimeError, match="refusing to migrate without it"):
            SharedContext(db)
    assert PROBE[0] not in applied(db)
    assert not has_probe_table(db)
    (critical,) = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    text = critical.getMessage()
    assert text.startswith("Pre-migration backup failed: database or disk is full.")
    assert "Refusing to apply 1 pending migration(s)" in text
    assert f"set {ALLOW}=1" in text
    assert " MB next to the database and " in text and " MB are free there" in text
    assert "A copy from an earlier run" not in text
    assert not Path(str(db) + ".pre-migration").exists()
    assert list(tmp_path.glob("detections.db.pre-migration.*")) == []


@pytest.mark.parametrize("value", ["1", "true"])
def test_the_override_migrates_without_a_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    value: str,
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    fail_the_copy(monkeypatch)
    monkeypatch.setenv(ALLOW, value)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert PROBE[0] in applied(db) and has_probe_table(db)
    assert (
        "applying 1 pending migration(s) WITHOUT a recovery copy because "
        f"{ALLOW} is set"
    ) in logged(caplog)
    assert list(tmp_path.glob("detections.db.pre-migration*")) == []


class _WithoutBackup:
    """A connection whose driver has no online backup API."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __getattr__(self, name: str):
        if name == "backup":
            raise AttributeError(name)
        return getattr(self._conn, name)


def test_the_override_also_covers_a_driver_without_the_backup_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    ctx = SharedContext(tmp_path / "detections.db")
    try:
        monkeypatch.setattr(base, "_MIGRATIONS", [*base._MIGRATIONS, PROBE])
        monkeypatch.delenv(ALLOW, raising=False)
        with pytest.raises(RuntimeError, match="driver lacks the online backup API"):
            ctx._run_migrations(_WithoutBackup(ctx.get_conn()))
        monkeypatch.setenv(ALLOW, "1")
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
            ctx._run_migrations(_WithoutBackup(ctx.get_conn()))
        assert PROBE[0] in applied(Path(ctx.db_path))
        assert "lacks the online backup API — applying 1" in logged(caplog)
    finally:
        ctx.close()


def test_a_previous_copy_is_named_when_a_new_one_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv(ALLOW, raising=False)
    db = upgrade_db(tmp_path, monkeypatch)
    previous = Path(str(db) + ".pre-migration")
    previous.write_bytes(b"forensic copy of a crashed run")
    fail_the_copy(monkeypatch)
    with caplog.at_level(logging.CRITICAL, logger="sigrift.bridge.storage.base"):
        with pytest.raises(RuntimeError, match="refusing to migrate"):
            SharedContext(db)
    assert previous.read_bytes() == b"forensic copy of a crashed run"
    (critical,) = [r.getMessage() for r in caplog.records]
    assert f"A copy from an earlier run is still there: {previous} (0 MB, made " in critical
    assert "UTC); if the upgrade that made it went well, delete it and restart." in critical


def test_after_a_successful_upgrade_the_copy_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    os.chmod(db, 0o640)
    ample(monkeypatch)
    with caplog.at_level(logging.INFO, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert PROBE[0] in applied(db)
    copy = Path(str(db) + ".pre-migration")
    assert copy.exists()
    assert copy.stat().st_mode & 0o777 == 0o640
    restored = sqlite3.connect(copy)
    try:
        assert restored.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert restored.execute(
            "SELECT COUNT(*) FROM schema_version WHERE version = ?", (PROBE[0],)
        ).fetchone() == (0,)
    finally:
        restored.close()
    assert f"Pre-migration backup kept: {copy} (" in logged(caplog)
    assert "removed automatically 7 days after it was made" in logged(caplog)


def test_low_free_space_removes_the_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    fake_usage(monkeypatch, 100 * GB, 10 * GB, 0.5 * GB)
    with caplog.at_level(logging.INFO, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert PROBE[0] in applied(db)
    assert not Path(str(db) + ".pre-migration").exists()
    (record,) = [
        r
        for r in caplog.records
        if "Pre-migration backup removed after successful run" in r.getMessage()
    ]
    assert record.levelno == logging.WARNING
    assert "only 0.5 GB would stay free" in record.getMessage()


def test_a_disk_80_percent_used_removes_the_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    fake_usage(monkeypatch, 100 * GB, 80 * GB, 20 * GB)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert not Path(str(db) + ".pre-migration").exists()
    assert "the disk would be 80% used; it is kept only below 80%" in logged(caplog)


def test_a_database_larger_than_1_gb_needs_its_own_size_free(tmp_path: Path, monkeypatch) -> None:
    db = tmp_path / "detections.db"
    with open(db, "wb") as fh:
        fh.truncate(3 * GB)  # sparse: no disk space used
    fake_usage(monkeypatch, 1000 * GB, 100 * GB, 2 * GB)
    keep, reason = base._keep_pre_migration_copy(db, had_migrations=True)
    assert not keep
    assert "only 2.0 GB would stay free" in reason and "at least 3.0 GB" in reason
    fake_usage(monkeypatch, 1000 * GB, 100 * GB, 4 * GB)
    assert base._keep_pre_migration_copy(db, had_migrations=True) == (True, "")


def test_a_new_database_keeps_no_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    ample(monkeypatch)
    db = tmp_path / "detections.db"
    with caplog.at_level(logging.INFO, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert not Path(str(db) + ".pre-migration").exists()
    (record,) = [
        r
        for r in caplog.records
        if "Pre-migration backup removed after successful run" in r.getMessage()
    ]
    assert record.levelno == logging.INFO
    assert "a new database" in record.getMessage()


def test_a_kept_copy_is_swept_after_seven_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    ample(monkeypatch)
    ctx = SharedContext(db)
    try:
        copy = Path(str(db) + ".pre-migration")
        assert copy.exists()
        six_days = time.time() - 6 * 86400
        os.utime(copy, (six_days, six_days))
        ctx._cleanup_orphan_migration_files()
        assert copy.exists()
        eight_days = time.time() - 8 * 86400
        os.utime(copy, (eight_days, eight_days))
        ctx._cleanup_orphan_migration_files()
        assert not copy.exists()
    finally:
        ctx.close()


def test_the_periodic_cleanup_sweeps_first_and_on_its_own() -> None:
    # First in every cycle, outside the cycle's big try: a failing cleanup
    # step never skips it.
    tree = ast.parse(inspect.getsource(app_module.lifespan))
    (cleanup,) = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_periodic_cleanup"
    ]
    (loop,) = [node for node in cleanup.body if isinstance(node, ast.While)]
    sleep, sweep = loop.body[0], loop.body[1]
    assert ast.unparse(sleep) == "await asyncio.sleep(_cleanup_interval)"
    assert ast.unparse(sweep) == "await _sweep_migration_leftovers(detection_store)"


def _no_space(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_usage(monkeypatch, 100 * GB, 99.99 * GB, 10 * 10**6)  # 10 MB free


def test_a_copy_that_cannot_fit_is_refused_before_anything_is_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Compose restarts a bridge that refused: a copy tried at every start
    # would fill the volume again each time.
    monkeypatch.delenv(ALLOW, raising=False)
    db = upgrade_db(tmp_path, monkeypatch)
    _no_space(monkeypatch)
    made: list[str] = []
    real_mkstemp = tempfile.mkstemp

    def mkstemp(*args, **kwargs):
        made.append(str(kwargs.get("prefix", "")))
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    with caplog.at_level(logging.CRITICAL, logger="sigrift.bridge.storage.base"):
        with pytest.raises(RuntimeError, match="refusing to migrate without it"):
            SharedContext(db)
    assert not [prefix for prefix in made if ".pre-migration" in prefix]
    assert list(tmp_path.glob("detections.db.pre-migration*")) == []
    assert PROBE[0] not in applied(db)
    (critical,) = [r.getMessage() for r in caplog.records]
    assert "not enough free space for the copy" in critical
    assert "nothing was written" in critical
    assert " 10 MB are free there" in critical
    assert "docker-compose.override.yml" in critical


def test_the_override_also_covers_a_copy_that_cannot_fit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    _no_space(monkeypatch)
    monkeypatch.setenv(ALLOW, "1")
    SharedContext(db).close()
    assert PROBE[0] in applied(db)
    assert list(tmp_path.glob("detections.db.pre-migration*")) == []


def _unreadable_usage(monkeypatch: pytest.MonkeyPatch) -> None:
    def disk_usage(path):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(base, "_disk_usage", disk_usage)


def test_unreadable_free_space_still_tries_the_copy_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv(ALLOW, raising=False)
    db = upgrade_db(tmp_path, monkeypatch)
    _unreadable_usage(monkeypatch)
    fail_the_copy(monkeypatch)
    with caplog.at_level(logging.CRITICAL, logger="sigrift.bridge.storage.base"):
        with pytest.raises(RuntimeError, match="refusing to migrate"):
            SharedContext(db)
    (critical,) = [r.getMessage() for r in caplog.records]
    assert critical.startswith("Pre-migration backup failed: database or disk is full.")
    assert "the free space there could not be read" in critical


def test_unreadable_free_space_after_an_upgrade_removes_the_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    _unreadable_usage(monkeypatch)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
        SharedContext(db).close()
    assert PROBE[0] in applied(db)
    assert not Path(str(db) + ".pre-migration").exists()
    (record,) = [
        r
        for r in caplog.records
        if "Pre-migration backup removed after successful run" in r.getMessage()
    ]
    assert record.levelno == logging.WARNING
    assert "the free space could not be read" in record.getMessage()


def _age(path: Path, days: float) -> None:
    when = time.time() - days * 86400
    os.utime(path, (when, when))


def _sweep(ctx: SharedContext) -> None:
    asyncio.run(app_module._sweep_migration_leftovers(SimpleNamespace(_ctx=ctx)))


def test_the_periodic_sweep_removes_a_kept_copy_once_space_runs_low(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    ample(monkeypatch)
    ctx = SharedContext(db)
    try:
        copy = Path(str(db) + ".pre-migration")
        _age(copy, 1)
        _sweep(ctx)
        assert copy.exists(), "kept while there is room"
        _unreadable_usage(monkeypatch)
        _sweep(ctx)
        assert copy.exists(), "kept when the free space cannot be read"

        # Startup never deletes a younger copy to make room ...
        fake_usage(monkeypatch, 100 * GB, 95 * GB, 5 * GB)
        ctx._cleanup_orphan_migration_files()
        assert copy.exists()
        # ... the periodic sweep removes it once the disk is 80% used.
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.base"):
            _sweep(ctx)
        assert not copy.exists()
        (record,) = [
            r for r in caplog.records if "Removed the kept pre-migration copy" in r.getMessage()
        ]
        assert record.levelno == logging.WARNING
        assert "before its 7 days were up: the disk would be 95% used" in record.getMessage()
    finally:
        ctx.close()


def test_the_periodic_sweep_removes_copies_older_than_seven_days(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = upgrade_db(tmp_path, monkeypatch)
    ample(monkeypatch)
    ctx = SharedContext(db)
    try:
        copy = Path(str(db) + ".pre-migration")
        _age(copy, 8)
        _sweep(ctx)
        assert not copy.exists()
    finally:
        ctx.close()


def test_an_interrupted_copy_is_swept_after_seven_days(tmp_path: Path) -> None:
    # A copy killed while being written (SIGKILL, power loss) keeps its
    # mkstemp name; one being written now is never 7 days old.
    ctx = SharedContext(tmp_path / "detections.db")
    try:
        old = tmp_path / "detections.db.pre-migration.k3j9x0"
        young = tmp_path / "detections.db.pre-migration.p2m7q1"
        old.write_bytes(b"half a copy")
        young.write_bytes(b"a copy being written")
        _age(old, 8)
        ctx._cleanup_orphan_migration_files()
        assert not old.exists() and young.exists()
        old.write_bytes(b"half a copy")
        _age(old, 8)
        _sweep(ctx)
        assert not old.exists() and young.exists()
    finally:
        ctx.close()


def test_a_failing_sweep_never_stops_the_cleanup_loop(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken() -> None:
        raise sqlite3.OperationalError("disk I/O error")

    ctx = SimpleNamespace(sweep_migration_leftovers=broken)
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.app"):
        asyncio.run(app_module._sweep_migration_leftovers(SimpleNamespace(_ctx=ctx)))
    assert "Migration leftover sweep failed: disk I/O error" in logged(caplog)


def test_health_warns_while_the_override_is_set(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    def warnings() -> list[str]:
        body = client.get("/api/health").json()
        return [w for w in body["security_warnings"] if ALLOW in w]

    monkeypatch.delenv(ALLOW, raising=False)
    assert warnings() == []
    monkeypatch.setenv(ALLOW, "1")
    (warning,) = warnings()
    assert warning.startswith("Pre-migration copy guard disabled:")
    assert "Remove it once the upgrade it was set for is done." in warning
