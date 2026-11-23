"""Tests for the spectrum-materializer watermark recovery + chunking (PR M).

The materializer's ``refresh`` used to re-load the entire ``spectrum_all``
view in one transaction whenever the in-memory watermark was None (i.e.
on every process restart) — a ~1.9 GB single-transaction WAL burst that
the checkpointer couldn't reclaim under live load, and which also
duplicated rows into the table on every restart. PR M:

  * recovers the watermark from the materialized table on first refresh,
  * inserts in batched commits so no single transaction balloons.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.spectrum_materializer import SpectrumMaterializer


def _seed_detections(ctx, n: int, start: datetime) -> None:
    """Insert n rows into a base table that feeds spectrum_all.

    spectrum_all is a UNION ALL view; the generic detections table is one
    of its members. We insert into whichever table the view selects from
    for the 'generic' branch — discovered via the view definition.
    """
    conn = ctx.get_conn()
    # Use the detections table (always present) — the spectrum_all view's
    # first branch selects from it WHERE freq_hz > 0.
    rows = [
        (
            (start + timedelta(seconds=i)).isoformat(),
            433.92e6 + i,
            -50.0,
            "bpsk",
            0.9,
            "node-mat",
            "default",
        )
        for i in range(n)
    ]
    with ctx.write_lock:
        conn.executemany(
            "INSERT INTO detections "
            "(timestamp, freq_hz, power_dbm, signal_class, confidence, "
            " node_id, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()


def _mat_count(ctx) -> int:
    return (
        ctx.get_conn()
        .execute("SELECT COUNT(*) FROM spectrum_materialized")
        .fetchone()[0]
    )


@pytest.fixture
def ctx(tmp_path):
    return SharedContext(db_path=tmp_path / "mat.db")


def test_refresh_materializes_rows(ctx):
    _seed_detections(ctx, 100, datetime(2026, 1, 1, tzinfo=timezone.utc))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    inserted = mat.refresh()
    assert inserted == 100
    assert _mat_count(ctx) == 100


def test_restart_does_not_duplicate(ctx):
    """Simulate a restart: a fresh materializer (watermark=None) over an
    already-populated table must NOT re-insert everything."""
    _seed_detections(ctx, 100, datetime(2026, 1, 1, tzinfo=timezone.utc))
    mat1 = SpectrumMaterializer(ctx)
    mat1.create_table()
    assert mat1.refresh() == 100

    # New materializer instance = restarted process (in-memory watermark
    # is None again). It should recover the watermark and insert nothing.
    mat2 = SpectrumMaterializer(ctx)
    inserted = mat2.refresh()
    assert inserted == 0, "restart re-materialized rows (watermark not recovered)"
    assert _mat_count(ctx) == 100, "row count doubled on restart"


def test_only_new_rows_after_watermark(ctx):
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    _seed_detections(ctx, 50, base)
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    assert mat.refresh() == 50

    # Add 30 newer rows.
    _seed_detections(ctx, 30, base + timedelta(hours=1))
    assert mat.refresh() == 30
    assert _mat_count(ctx) == 80


def test_chunking_commits_in_batches(ctx):
    """With a small batch size, a load larger than one batch must still
    insert everything — across multiple committed batches."""
    _seed_detections(ctx, 250, datetime(2026, 1, 1, tzinfo=timezone.utc))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    inserted = mat.refresh(batch_rows=50)
    assert inserted == 250
    assert _mat_count(ctx) == 250


def test_full_refresh_rebuilds_without_duplicates(ctx):
    _seed_detections(ctx, 120, datetime(2026, 1, 1, tzinfo=timezone.utc))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    mat.refresh(batch_rows=40)
    assert _mat_count(ctx) == 120
    # Full refresh truncates + reloads; count stays the same (no dupes).
    rebuilt = mat.full_refresh(batch_rows=40)
    assert rebuilt == 120
    assert _mat_count(ctx) == 120


@pytest.mark.asyncio
async def test_cleanup_old_prunes_by_age(ctx):
    """cleanup_old deletes rows older than the cutoff and keeps newer ones."""
    now = datetime.now(timezone.utc)
    # 40 rows starting 100 days ago (well past a 90d cutoff) ...
    _seed_detections(ctx, 40, now - timedelta(days=100))
    # ... and 30 recent rows (within the window).
    _seed_detections(ctx, 30, now - timedelta(days=1))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    assert mat.refresh() == 70
    assert _mat_count(ctx) == 70

    deleted = await mat.cleanup_old(max_age_days=90)
    assert deleted == 40
    assert _mat_count(ctx) == 30
    # Every surviving row is newer than the cutoff.
    oldest = (
        ctx.get_conn()
        .execute("SELECT MIN(timestamp) FROM spectrum_materialized")
        .fetchone()[0]
    )
    assert oldest >= (now - timedelta(days=2)).isoformat()


@pytest.mark.asyncio
async def test_cleanup_old_batches(ctx):
    """A small batch_size still deletes everything past the cutoff."""
    now = datetime.now(timezone.utc)
    _seed_detections(ctx, 50, now - timedelta(days=100))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    assert mat.refresh() == 50
    deleted = await mat.cleanup_old(max_age_days=90, batch_size=7)
    assert deleted == 50
    assert _mat_count(ctx) == 0


@pytest.mark.asyncio
async def test_cleanup_old_noop_when_all_recent(ctx):
    """Nothing is deleted (and no log) when every row is within the window."""
    now = datetime.now(timezone.utc)
    _seed_detections(ctx, 25, now - timedelta(days=2))
    mat = SpectrumMaterializer(ctx)
    mat.create_table()
    mat.refresh()
    deleted = await mat.cleanup_old(max_age_days=90)
    assert deleted == 0
    assert _mat_count(ctx) == 25
