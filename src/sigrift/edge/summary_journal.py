"""Single-writer durable RF summary state; not a raw-detection or alert outbox.

The caller commits each admitted observation before publishing its in-memory
state. Only the changed bin/raw record and hour metadata are written. A retained
acknowledged hour is needed for later observations in that same UTC hour.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
from urllib.parse import urlsplit, urlunsplit
import uuid


from sigrift.edge.summary_protocol import canonical_json, valid_node


class SummaryJournal:
    """One process owns a journal until close; never reset unreadable state."""

    def __init__(self, data_dir, receiver: str, node_id: str):
        if not data_dir:
            raise ValueError(
                "Summary mode requires a persistent data_dir / MLRF_DATA_DIR"
            )
        if not valid_node(node_id):
            raise ValueError("Summary journal requires a valid node identity")
        url = urlsplit(receiver)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
        ):
            raise ValueError(
                "Summary receiver must be an HTTP(S) URL without credentials/query"
            )
        host = url.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        port = url.port
        if port is not None and port != (443 if url.scheme == "https" else 80):
            host += f":{port}"
        identity = canonical_json(
            {
                "receiver": urlunsplit(
                    (url.scheme, host, url.path.rstrip("/"), "", "")
                ),
                "node_id": node_id,
            }
        ).decode()
        root = Path(data_dir) / "summary-journal"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = root.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o022
        ):
            raise ValueError(
                "Summary journal directory must be owned and not group/world writable"
            )
        self._lock = threading.RLock()
        self._pid = os.getpid()
        self._conn = None
        self._fd = None
        try:
            self._fd = os.open(
                root / "writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
            )
            info = os.fstat(self._fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o022
            ):
                raise ValueError("Unsafe summary journal lock file")
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = root / "summary.sqlite3"
            for candidate in (path, Path(str(path) + "-wal"), Path(str(path) + "-shm")):
                if candidate.is_symlink():
                    raise ValueError("Summary journal files must not be symlinks")
            try:
                fd = os.open(
                    path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600
                )
                new_file = True
            except FileExistsError:
                fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
                new_file = False
            try:
                info = os.fstat(fd)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o022
                ):
                    raise ValueError("Unsafe summary journal file")
            finally:
                os.close(fd)
            self._conn = sqlite3.connect(
                path, timeout=2, check_same_thread=False, isolation_level=None
            )
            if not new_file:
                # An existing empty/unrelated database is not permission to mint
                # a replacement stream and forget potentially accepted state.
                tables = {
                    row[0]
                    for row in self._conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                if (
                    not {"metadata", "hours", "bins", "raw"} <= tables
                    or not self._conn.execute(
                        "SELECT 1 FROM metadata WHERE id=1"
                    ).fetchone()
                ):
                    raise ValueError(
                        "Incomplete summary journal; preserve it for recovery"
                    )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            with self._transaction() as conn:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, identity TEXT NOT NULL, stream TEXT NOT NULL, latest_hour INTEGER)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS hours (hour INTEGER PRIMARY KEY, generation INTEGER NOT NULL, acknowledged INTEGER NOT NULL, size INTEGER NOT NULL)"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS bins (hour INTEGER NOT NULL, bin_key TEXT NOT NULL, stats TEXT NOT NULL, encoded BLOB NOT NULL, PRIMARY KEY(hour,bin_key))"
                )
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS raw (hour INTEGER NOT NULL, generation INTEGER NOT NULL, encoded BLOB NOT NULL, PRIMARY KEY(hour,generation))"
                )
                row = conn.execute(
                    "SELECT version,identity,stream FROM metadata WHERE id=1"
                ).fetchone()
                if row is None:
                    self.stream_id = uuid.uuid4().hex
                    conn.execute(
                        "INSERT INTO metadata VALUES (1,1,?,?,NULL)",
                        (identity, self.stream_id),
                    )
                else:
                    if (
                        row[0] != 1
                        or row[1] != identity
                        or not isinstance(row[2], str)
                        or not re.fullmatch("[0-9a-f]{32}", row[2])
                    ):
                        raise ValueError(
                            "Summary journal version/receiver/node identity mismatch; preserve it for recovery"
                        )
                    self.stream_id = row[2]
        except BaseException:
            self.close()
            raise

    @contextmanager
    def _transaction(self):
        # A fork may copy a lock owned by another parent thread. Refuse the
        # inherited object before touching that lock or its SQLite connection.
        if os.getpid() != self._pid:
            raise RuntimeError("Summary journal is inherited across fork")
        with self._lock:
            if os.getpid() != self._pid or self._conn is None:
                raise RuntimeError("Summary journal is closed or inherited across fork")
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    def load(self):
        """Return persisted rows; the accumulator validates its current limits."""
        with self._transaction() as conn:
            latest = conn.execute(
                "SELECT latest_hour FROM metadata WHERE id=1"
            ).fetchone()[0]
            hours = conn.execute(
                "SELECT hour,generation,acknowledged,size FROM hours ORDER BY hour"
            ).fetchall()
            bins = conn.execute(
                "SELECT hour,bin_key,stats,encoded FROM bins ORDER BY hour,bin_key"
            ).fetchall()
            raw = conn.execute(
                "SELECT hour,encoded FROM raw ORDER BY hour,generation"
            ).fetchall()
            return latest, hours, bins, raw

    def admit(self, hour, generation, size, latest, expired, key, stats, encoded):
        with self._transaction() as conn:
            for old in expired:
                conn.execute("DELETE FROM bins WHERE hour=?", (old,))
                conn.execute("DELETE FROM raw WHERE hour=?", (old,))
                conn.execute("DELETE FROM hours WHERE hour=?", (old,))
            conn.execute(
                "INSERT INTO hours VALUES (?,?,0,?) ON CONFLICT(hour) DO UPDATE SET generation=excluded.generation,size=excluded.size",
                (hour, generation, size),
            )
            if key is None:
                conn.execute(
                    "INSERT INTO raw VALUES (?,?,?)", (hour, generation, encoded)
                )
            else:
                conn.execute(
                    "INSERT INTO bins VALUES (?,?,?,?) ON CONFLICT(hour,bin_key) DO UPDATE SET stats=excluded.stats,encoded=excluded.encoded",
                    (
                        hour,
                        canonical_json(key).decode(),
                        canonical_json(stats).decode(),
                        encoded,
                    ),
                )
            conn.execute("UPDATE metadata SET latest_hour=? WHERE id=1", (latest,))

    def acknowledge(self, hour, generation):
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT generation,acknowledged FROM hours WHERE hour=?", (hour,)
            ).fetchone()
            if row is None or not 0 <= generation <= row[0]:
                raise ValueError("Invalid summary acknowledgement generation")
            conn.execute(
                "UPDATE hours SET acknowledged=? WHERE hour=?",
                (max(row[1], generation), hour),
            )

    def close(self):
        if os.getpid() != self._pid:
            raise RuntimeError("Summary journal is inherited across fork")
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
