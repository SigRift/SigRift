"""Tests for P2-1: thin DB abstraction layer in SharedContext."""

from __future__ import annotations

import sqlite3

import pytest

from sigrift.bridge.storage.base import SharedContext, SQLDialect


@pytest.fixture
def ctx(tmp_path):
    """Create a SharedContext backed by a temp database."""
    sc = SharedContext(db_path=tmp_path / "test_abstraction.db")
    yield sc
    sc.close()


class TestSQLDialect:
    def test_dialect_returns_sqlite(self, ctx: SharedContext) -> None:
        assert ctx.dialect == SQLDialect.SQLITE

    def test_dialect_is_string(self, ctx: SharedContext) -> None:
        assert ctx.dialect == "sqlite"

    def test_backend_returns_sqlite(self, ctx: SharedContext) -> None:
        assert ctx.backend == "sqlite"


class TestExecute:
    def test_execute_returns_cursor(self, ctx: SharedContext) -> None:
        cur = ctx.execute("SELECT 1")
        assert isinstance(cur, sqlite3.Cursor)
        assert cur.fetchone()[0] == 1

    def test_execute_with_params(self, ctx: SharedContext) -> None:
        cur = ctx.execute("SELECT ? + ?", (3, 4))
        assert cur.fetchone()[0] == 7

    def test_executemany_batch_insert(self, ctx: SharedContext) -> None:
        ctx.execute(
            "CREATE TABLE _test_batch (id INTEGER PRIMARY KEY, val TEXT)"
        )
        rows = [(1, "a"), (2, "b"), (3, "c")]
        ctx.executemany("INSERT INTO _test_batch VALUES (?, ?)", rows)
        ctx.commit()
        cur = ctx.execute("SELECT COUNT(*) FROM _test_batch")
        assert cur.fetchone()[0] == 3

    def test_commit_works(self, ctx: SharedContext) -> None:
        ctx.execute("CREATE TABLE _test_commit (x INTEGER)")
        ctx.execute("INSERT INTO _test_commit VALUES (?)", (42,))
        ctx.commit()
        # Verify data persists by re-querying
        cur = ctx.execute("SELECT x FROM _test_commit")
        assert cur.fetchone()[0] == 42
