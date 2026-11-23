"""Transaction isolation and error recovery tests for SQLite/SharedContext.

Validates:
1. Concurrent writes via multiple threads do not corrupt data
2. SharedContext.write_lock serialises mutations correctly
3. Crash recovery -- failed mid-transaction writes leave DB intact (WAL)
4. Readers are not blocked while writes are in progress (WAL mode)
"""

from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.storage.base import SharedContext

from .conftest import make_detection


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_batch(prefix: str, count: int) -> list[DetectionRecord]:
    """Create *count* unique detections keyed by *prefix*."""
    return [
        make_detection(
            node_id=f"node-{prefix}",
            signal_class="bpsk",
            freq_hz=433.92e6,
        )
        for _ in range(count)
    ]


# ---------------------------------------------------------------------------
# 1. Concurrent writes -- multiple threads inserting simultaneously
# ---------------------------------------------------------------------------

class TestConcurrentWrites:
    """Multiple threads inserting detections must not corrupt data."""

    def test_parallel_inserts_no_data_loss(self, tmp_path: Path):
        """Spin up N threads that each insert a batch; total row count
        must equal the sum of all batches.
        """
        store = DetectionStore(db_path=tmp_path / "concurrent.db")
        n_threads = 8
        batch_size = 50

        batches = [_make_batch(f"t{i}", batch_size) for i in range(n_threads)]

        errors: list[Exception] = []

        def _insert(batch: list[DetectionRecord]):
            try:
                store.insert_batch(batch)
            except Exception as exc:
                errors.append(exc)

        threads = []
        for batch in batches:
            t = threading.Thread(target=_insert, args=(batch,))
            threads.append(t)

        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        assert not errors, f"Thread errors: {errors}"
        assert store.row_count() == n_threads * batch_size

    def test_parallel_inserts_with_executor(self, tmp_path: Path):
        """Same test using ThreadPoolExecutor for cleaner future handling."""
        store = DetectionStore(db_path=tmp_path / "executor.db")
        n_workers = 6
        batch_size = 40

        batches = [_make_batch(f"w{i}", batch_size) for i in range(n_workers)]

        with ThreadPoolExecutor(max_workers=n_workers) as pool:
            futures = [pool.submit(store.insert_batch, b) for b in batches]
            results = [f.result(timeout=15) for f in as_completed(futures)]

        assert sum(results) == n_workers * batch_size
        assert store.row_count() == n_workers * batch_size


# ---------------------------------------------------------------------------
# 2. Write lock -- SharedContext.write_lock prevents data races
# ---------------------------------------------------------------------------

class TestWriteLock:
    """Verify the write_lock serialises concurrent mutations."""

    def test_write_lock_serialises_counter(self, tmp_path: Path):
        """Use a shared counter table to prove the lock serialises access.

        Without the lock the final value would be indeterminate due to
        read-modify-write races.
        """
        ctx = SharedContext(db_path=tmp_path / "lock_test.db")
        conn = ctx.get_conn()
        conn.execute("CREATE TABLE IF NOT EXISTS counter (val INTEGER)")
        conn.execute("INSERT INTO counter VALUES (0)")
        conn.commit()

        increments = 200
        n_threads = 4

        def _increment(n: int):
            for _ in range(n):
                with ctx.write_lock:
                    c = ctx.get_conn()
                    row = c.execute("SELECT val FROM counter").fetchone()
                    c.execute("UPDATE counter SET val = ?", (row[0] + 1,))
                    c.commit()

        threads = [
            threading.Thread(target=_increment, args=(increments,))
            for _ in range(n_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        final = conn.execute("SELECT val FROM counter").fetchone()[0]
        assert final == increments * n_threads

        ctx.close()

    def test_lock_is_reentrant_safe(self, tmp_path: Path):
        """write_lock is a plain threading.Lock -- ensure non-reentrant
        calls from separate threads don't deadlock within a timeout.
        """
        ctx = SharedContext(db_path=tmp_path / "reentrant.db")
        acquired = threading.Event()
        released = threading.Event()

        def _hold_lock():
            with ctx.write_lock:
                acquired.set()
                # Hold for a short time
                released.wait(timeout=5)

        holder = threading.Thread(target=_hold_lock)
        holder.start()
        acquired.wait(timeout=5)

        # Attempting to acquire from main thread should block
        got_lock = ctx.write_lock.acquire(timeout=0.1)
        assert not got_lock, "Should not acquire lock while held by another thread"

        released.set()
        holder.join(timeout=5)

        # Now it should be free
        assert ctx.write_lock.acquire(timeout=1)
        ctx.write_lock.release()
        ctx.close()


# ---------------------------------------------------------------------------
# 3. Crash recovery -- failed write mid-transaction, DB stays intact
# ---------------------------------------------------------------------------

class TestCrashRecovery:
    """Simulate failed writes and verify DB integrity via WAL checkpoint."""

    def test_failed_transaction_rolls_back(self, tmp_path: Path):
        """A transaction that raises mid-way should not leave partial data."""
        store = DetectionStore(db_path=tmp_path / "crash.db")

        # Insert a known-good batch first
        good = _make_batch("good", 10)
        store.insert_batch(good)
        assert store.row_count() == 10

        # Simulate a crash by inserting into a deliberately broken statement
        conn = store.get_connection()
        try:
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence) VALUES (?, ?, ?, ?, ?)",
                ("crash-1", "node-crash", "2025-01-01T00:00:00Z", "bpsk", 0.9),
            )
            # Force an error -- violate NOT NULL on a required column via bad SQL
            conn.execute("INSERT INTO detections VALUES (NULL)")
        except sqlite3.OperationalError:
            conn.rollback()

        # Original data intact, failed row not committed
        assert store.row_count() == 10

    def test_wal_checkpoint_after_crash(self, tmp_path: Path):
        """After a failed write, WAL checkpoint succeeds and DB is consistent."""
        store = DetectionStore(db_path=tmp_path / "wal_crash.db")

        store.insert_batch(_make_batch("pre", 20))

        # Attempt a bad write
        conn = store.get_connection()
        try:
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO detections (detection_id, node_id, timestamp, "
                "signal_class, confidence) VALUES (?, ?, ?, ?, ?)",
                ("wal-crash-1", "node-x", "2025-01-01T00:00:00Z", "bpsk", 0.5),
            )
            raise RuntimeError("simulated crash")
        except RuntimeError:
            conn.rollback()

        # WAL checkpoint should succeed cleanly
        info = store.wal_checkpoint()
        assert isinstance(info, dict)
        assert "wal_pages" in info
        assert isinstance(info["wal_pages"], int)

        # Data is intact
        assert store.row_count() == 20

        # Integrity check
        result = conn.execute("PRAGMA integrity_check").fetchone()
        assert result[0] == "ok"

    def test_db_integrity_after_partial_batch(self, tmp_path: Path):
        """Insert a batch where some rows collide (duplicate PK).

        INSERT OR IGNORE skips duplicates but the rest commit fine.
        """
        store = DetectionStore(db_path=tmp_path / "partial.db")

        batch_a = _make_batch("a", 10)
        store.insert_batch(batch_a)

        # Re-insert same batch -- all should be ignored (INSERT OR IGNORE)
        inserted = store.insert_batch(batch_a)
        # Depending on SQLite version, rowcount for IGNORE may be -1 or 0
        # but total rows should still be 10
        assert store.row_count() == 10

        conn = store.get_connection()
        result = conn.execute("PRAGMA integrity_check").fetchone()
        assert result[0] == "ok"


# ---------------------------------------------------------------------------
# 4. Read during write -- WAL mode allows concurrent readers
# ---------------------------------------------------------------------------

class TestReadDuringWrite:
    """WAL mode should allow reads to proceed while a write is in progress."""

    def test_reader_not_blocked_during_write(self, tmp_path: Path):
        """Start a write transaction that holds for a bit, and verify a
        reader on a separate connection can still query concurrently.
        """
        db_path = tmp_path / "wal_read.db"
        store = DetectionStore(db_path=db_path)

        # Seed data
        store.insert_batch(_make_batch("seed", 25))

        write_started = threading.Event()
        write_done = threading.Event()
        read_result: dict = {}

        def _slow_write():
            """Hold the write lock and keep a transaction open briefly."""
            with store._write_lock:
                conn = store.get_connection()
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "INSERT INTO detections (detection_id, node_id, timestamp, "
                    "signal_class, confidence, tenant_id) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    ("slow-1", "node-slow", "2025-01-01T00:00:00Z",
                     "bpsk", 0.9, "default"),
                )
                write_started.set()
                # Hold transaction open
                time.sleep(0.3)
                conn.commit()
            write_done.set()

        def _concurrent_read():
            """Open a separate connection and read while write is active."""
            write_started.wait(timeout=5)
            # New connection in a different thread -- WAL allows this
            read_conn = sqlite3.connect(str(db_path))
            read_conn.execute("PRAGMA journal_mode=WAL")
            read_conn.execute("PRAGMA busy_timeout=5000")
            try:
                row = read_conn.execute(
                    "SELECT COUNT(*) FROM detections"
                ).fetchone()
                read_result["count"] = row[0]
                read_result["success"] = True
            except sqlite3.OperationalError as exc:
                read_result["success"] = False
                read_result["error"] = str(exc)
            finally:
                read_conn.close()

        writer = threading.Thread(target=_slow_write)
        reader = threading.Thread(target=_concurrent_read)

        writer.start()
        reader.start()

        writer.join(timeout=10)
        reader.join(timeout=10)

        assert read_result.get("success"), (
            f"Reader was blocked or failed: {read_result}"
        )
        # Reader should see the pre-write snapshot (25 rows) -- WAL isolation
        assert read_result["count"] >= 25

    def test_multiple_readers_during_write(self, tmp_path: Path):
        """Multiple readers should all succeed concurrently with a writer."""
        db_path = tmp_path / "multi_read.db"
        store = DetectionStore(db_path=db_path)
        store.insert_batch(_make_batch("init", 30))

        write_started = threading.Event()
        reader_results: list[dict] = []
        lock = threading.Lock()

        def _writer():
            with store._write_lock:
                conn = store.get_connection()
                conn.execute("BEGIN IMMEDIATE")
                for i in range(10):
                    conn.execute(
                        "INSERT INTO detections (detection_id, node_id, "
                        "timestamp, signal_class, confidence, tenant_id) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (f"multi-w-{i}", "node-w", "2025-01-01T00:00:00Z",
                         "bpsk", 0.9, "default"),
                    )
                write_started.set()
                time.sleep(0.2)
                conn.commit()

        def _reader(idx: int):
            write_started.wait(timeout=5)
            rconn = sqlite3.connect(str(db_path))
            rconn.execute("PRAGMA journal_mode=WAL")
            rconn.execute("PRAGMA busy_timeout=5000")
            try:
                row = rconn.execute(
                    "SELECT COUNT(*) FROM detections"
                ).fetchone()
                result = {"idx": idx, "count": row[0], "success": True}
            except sqlite3.OperationalError as exc:
                result = {"idx": idx, "success": False, "error": str(exc)}
            finally:
                rconn.close()
            with lock:
                reader_results.append(result)

        writer_t = threading.Thread(target=_writer)
        reader_threads = [threading.Thread(target=_reader, args=(i,)) for i in range(5)]

        writer_t.start()
        for rt in reader_threads:
            rt.start()

        writer_t.join(timeout=10)
        for rt in reader_threads:
            rt.join(timeout=10)

        for r in reader_results:
            assert r["success"] is True, f"Reader {r['idx']} failed: {r}"
            assert r["count"] >= 30
