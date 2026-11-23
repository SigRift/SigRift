"""Regression tests: storage writes commit on success and roll back on error.

Before ``SharedContext.transaction()`` existed, every write path did
``conn.execute(...); conn.commit()`` on Python sqlite3's implicit
transactions with no rollback anywhere.  A statement that failed after the
implicit ``BEGIN`` (e.g. the IntegrityError of a duplicate username) left
the thread-local connection inside an open write transaction:

* it kept holding the WAL write lock, so every other writer waited out the
  30 s busy_timeout (and the WriteQueue dropped batches), and
* the next unrelated ``commit()`` on that thread committed whatever half of
  the failed multi-statement block had already run.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext, sqlite_transaction
from sigrift.bridge.storage.users import UserStore


def _other_writer_can_lock(db_path: str) -> bool:
    """Return True if a fresh connection gets the write lock immediately."""
    other = sqlite3.connect(db_path, timeout=0)
    try:
        other.execute("PRAGMA busy_timeout=0")
        other.execute("BEGIN IMMEDIATE")
        other.execute("ROLLBACK")
        return True
    except sqlite3.OperationalError as exc:
        assert "locked" in str(exc) or "busy" in str(exc)
        return False
    finally:
        other.close()


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    c = SharedContext(db_path=tmp_path / "tx.db")
    yield c
    c.close()


class TestImplicitTransactionHazard:
    """Pins down the sqlite3 behaviour the fix guards against."""

    def test_failed_insert_leaves_raw_connection_in_transaction(self, tmp_path):
        db = str(tmp_path / "raw.db")
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE t (name TEXT UNIQUE)")
        conn.execute("INSERT INTO t VALUES ('a')")
        conn.commit()

        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO t VALUES ('a')")

        # Without a rollback the implicit BEGIN stays open and keeps the
        # database write-locked for everyone else.
        assert conn.in_transaction
        assert not _other_writer_can_lock(db)
        conn.rollback()
        assert _other_writer_can_lock(db)
        conn.close()


class TestDuplicateUsername:
    def test_duplicate_insert_rolls_back_and_releases_lock(self, ctx):
        users = UserStore(ctx)
        users.create_user("alice", "Password123!", role="viewer")

        with pytest.raises(ValueError, match="already exists"):
            users.create_user("alice", "Password456!", role="viewer")

        conn = ctx.get_conn()
        assert not conn.in_transaction
        # A second connection can take the write lock immediately instead
        # of waiting out busy_timeout behind the failed insert.
        assert _other_writer_can_lock(ctx.db_path)

        # And another writer on a different thread is not blocked either.
        errors: list[BaseException] = []

        def _write() -> None:
            try:
                users.create_user("bob", "Password789!", role="viewer")
            except BaseException as exc:  # pragma: no cover - failure path
                errors.append(exc)

        t = threading.Thread(target=_write)
        t.start()
        t.join(timeout=10)
        assert not t.is_alive()
        assert not errors
        assert users.get_user("bob") is not None


class TestTransactionContextManager:
    def test_commits_on_success(self, ctx):
        with ctx.write_transaction() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS t (v INTEGER)")
            conn.execute("INSERT INTO t VALUES (1)")
        assert not ctx.get_conn().in_transaction
        other = sqlite3.connect(ctx.db_path)
        assert other.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1
        other.close()

    def test_rolls_back_partial_multi_statement_block(self, ctx):
        conn = ctx.get_conn()
        conn.execute("CREATE TABLE t (v INTEGER UNIQUE)")

        with pytest.raises(sqlite3.IntegrityError):
            with ctx.write_transaction() as c:
                c.execute("INSERT INTO t VALUES (1)")
                c.execute("INSERT INTO t VALUES (2)")
                c.execute("INSERT INTO t VALUES (1)")  # duplicate -> raises

        assert not conn.in_transaction
        # A later, unrelated commit on this thread must not resurrect the
        # half-finished block.
        with ctx.write_transaction() as c:
            c.execute("INSERT INTO t VALUES (10)")
        rows = [r[0] for r in conn.execute("SELECT v FROM t ORDER BY v")]
        assert rows == [10]

    def test_rolls_back_on_non_sqlite_exception(self, ctx):
        conn = ctx.get_conn()
        conn.execute("CREATE TABLE t (v INTEGER)")
        with pytest.raises(KeyError):
            with ctx.transaction() as c:
                c.execute("INSERT INTO t VALUES (1)")
                raise KeyError("boom")
        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0

    def test_write_transaction_holds_write_lock(self, ctx):
        with ctx.write_transaction():
            assert not ctx.write_lock.acquire(blocking=False)
        assert ctx.write_lock.acquire(blocking=False)
        ctx.write_lock.release()

    def test_write_lock_released_after_error(self, ctx):
        with pytest.raises(RuntimeError):
            with ctx.write_transaction():
                raise RuntimeError("boom")
        assert ctx.write_lock.acquire(blocking=False)
        ctx.write_lock.release()

    def test_nested_failure_only_undoes_inner_block(self, ctx):
        conn = ctx.get_conn()
        conn.execute("CREATE TABLE t (v INTEGER)")
        with ctx.transaction() as outer:
            outer.execute("INSERT INTO t VALUES (1)")
            try:
                with ctx.transaction() as inner:
                    inner.execute("INSERT INTO t VALUES (2)")
                    raise ValueError("inner failure")
            except ValueError:
                pass
            outer.execute("INSERT INTO t VALUES (3)")
        assert not conn.in_transaction
        rows = [r[0] for r in conn.execute("SELECT v FROM t ORDER BY v")]
        assert rows == [1, 3]

    def test_nested_success_commits_with_outer(self, ctx):
        conn = ctx.get_conn()
        conn.execute("CREATE TABLE t (v INTEGER)")
        with pytest.raises(RuntimeError):
            with ctx.transaction() as outer:
                # The outer block has not written yet when the inner one
                # starts: the inner write must still belong to the outer
                # transaction and be undone with it.
                with ctx.transaction() as inner:
                    inner.execute("INSERT INTO t VALUES (1)")
                outer.execute("INSERT INTO t VALUES (2)")
                raise RuntimeError("outer failure")
        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0

    def test_module_helper_on_plain_connection(self, tmp_path):
        conn = sqlite3.connect(str(tmp_path / "plain.db"))
        conn.execute("CREATE TABLE t (v INTEGER UNIQUE)")
        with pytest.raises(sqlite3.IntegrityError):
            with sqlite_transaction(conn):
                conn.execute("INSERT INTO t VALUES (1)")
                conn.execute("INSERT INTO t VALUES (1)")
        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0
        conn.close()


class TestStoreWritePathsAreAtomic:
    def test_rf_anomaly_batch_failure_rolls_back_whole_batch(self, tmp_path):
        from sigrift.bridge.detection_store import DetectionStore

        store = DetectionStore(db_path=tmp_path / "rf.db")
        good = {
            "detection_id": "d1",
            "signal_class": "bpsk",
            "freq_hz": 433.92e6,
            "node_id": "n1",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "anomaly_score": 0.9,
        }
        bad = dict(good, signal_class="qpsk", freq_hz=915e6, detection_id=object())

        with pytest.raises(sqlite3.Error):
            store.insert_rf_anomalies_batch([good, bad])

        conn = store.get_connection()
        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM rf_anomalies").fetchone()[0] == 0
        assert _other_writer_can_lock(store.db_path)

        # The store keeps working afterwards.
        assert len(store.insert_rf_anomalies_batch([good])) == 1
        assert conn.execute("SELECT COUNT(*) FROM rf_anomalies").fetchone()[0] == 1

    def test_audit_archive_failure_keeps_rows(self, tmp_path, monkeypatch):
        from sigrift.bridge.detection_store import DetectionStore
        from sigrift.bridge.storage import audit as audit_mod

        store = DetectionStore(db_path=tmp_path / "audit.db")
        for i in range(3):
            store.log_audit(action="dismiss", target_id=f"det-{i}", operator="op")
        conn = store.get_connection()
        with sqlite_transaction(conn):
            conn.execute("UPDATE audit_log SET timestamp = '2000-01-01T00:00:00+00:00'")

        def _no_secret() -> bytes:
            raise RuntimeError("no audit key")

        # archive_audit_log DELETEs the old rows before it needs the HMAC
        # secret; the failure must not leave that DELETE pending.
        monkeypatch.setattr(audit_mod, "_get_audit_secret", _no_secret)
        with pytest.raises(RuntimeError, match="no audit key"):
            store._audit.archive_audit_log(max_age_days=1)

        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 3
        assert _other_writer_can_lock(store.db_path)

    def test_correlation_store_failure_leaves_no_open_transaction(self, tmp_path):
        from sigrift.bridge.correlation_engine import (
            CrossCorrelation,
            CrossCorrelator,
        )

        db = str(tmp_path / "corr.db")
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE cross_correlations ("
            " source_a TEXT NOT NULL CHECK (source_a != 'bad'),"
            " source_a_id TEXT, source_b TEXT, source_b_id TEXT,"
            " freq_hz REAL, time_delta_ms REAL, correlation_type TEXT,"
            " node_id TEXT, timestamp TEXT, tenant_id TEXT)"
        )
        conn.commit()

        def _corr(source: str) -> CrossCorrelation:
            return CrossCorrelation(
                source_a=source,
                source_a_id="1",
                source_b="",
                source_b_id=None,
                freq_hz=1.0,
                time_delta_ms=0,
                correlation_type="unmatched_sdr",
                node_id="n1",
                timestamp="2026-01-01T00:00:00+00:00",
            )

        correlator = CrossCorrelator(ctx=None)
        # The error is logged and swallowed, as before ...
        correlator._store_correlations(conn, [_corr("sdr"), _corr("bad")])
        # ... but no longer leaves the first row pending in an open
        # transaction that holds the write lock.
        assert not conn.in_transaction
        assert conn.execute("SELECT COUNT(*) FROM cross_correlations").fetchone()[0] == 0
        assert _other_writer_can_lock(db)
        conn.close()
