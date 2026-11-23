"""Regression test: aggregate_hourly must preserve distinct families.

Previously, the GROUP BY omitted `family`, causing INSERT OR REPLACE to
overwrite aggregates when the same (hour, node_id, signal_class) had
multiple families.  Migration 34 added family to the UNIQUE index.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.tests.conftest import make_detection

@pytest.fixture
def store(tmp_path: Path) -> DetectionStore:
    return DetectionStore(db_path=tmp_path / "test.db")

class TestAggregateFamily:
    """Verify aggregate_hourly preserves per-family data."""

    def test_two_families_same_class_both_preserved(self, store: DetectionStore) -> None:
        """Two families under the same signal_class produce separate aggregate rows."""
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        ts = old.isoformat()

        store.insert_batch([
            make_detection(signal_class="wifi", family="802.11n", timestamp=ts),
            make_detection(signal_class="wifi", family="802.11n", timestamp=ts),
            make_detection(signal_class="wifi", family="802.11ac", timestamp=ts),
        ])

        count = store.aggregate_hourly()
        assert count == 2, f"Expected 2 aggregate rows (one per family), got {count}"

        # Verify both rows exist in detection_aggregates
        conn = store._ctx.get_conn()
        rows = conn.execute(
            "SELECT family, detection_count FROM detection_aggregates ORDER BY family"
        ).fetchall()
        families = {r["family"]: r["detection_count"] for r in rows}
        assert "802.11n" in families, "802.11n family missing from aggregates"
        assert "802.11ac" in families, "802.11ac family missing from aggregates"
        assert families["802.11n"] == 2
        assert families["802.11ac"] == 1

    def test_single_family_still_works(self, store: DetectionStore) -> None:
        """Single family aggregation works as before."""
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        ts = old.isoformat()

        store.insert_batch([
            make_detection(signal_class="bpsk", family="psk", timestamp=ts),
            make_detection(signal_class="bpsk", family="psk", timestamp=ts),
        ])

        count = store.aggregate_hourly()
        assert count == 1

    def test_different_classes_different_families(self, store: DetectionStore) -> None:
        """Different signal classes with different families produce separate rows."""
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        ts = old.isoformat()

        store.insert_batch([
            make_detection(signal_class="wifi", family="802.11n", timestamp=ts),
            make_detection(signal_class="bpsk", family="psk", timestamp=ts),
            make_detection(signal_class="fm", family="analog", timestamp=ts),
        ])

        count = store.aggregate_hourly()
        assert count == 3

    def test_two_families_survive_a_restart(self, tmp_path: Path) -> None:
        """The same, on a store started before (as every deployed one is):
        the schema script runs again at each start-up (before the pending
        migrations, of which there are none by then), long after the
        migrations that replaced the family-less unique index."""
        db = tmp_path / "test.db"
        DetectionStore(db_path=db).close()
        store = DetectionStore(db_path=db)
        try:
            ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
            store.insert_batch(
                [
                    make_detection(signal_class="wifi", family="802.11n", timestamp=ts),
                    make_detection(signal_class="wifi", family="802.11n", timestamp=ts),
                    make_detection(signal_class="wifi", family="802.11ac", timestamp=ts),
                ]
            )
            store.aggregate_hourly()
        finally:
            store.close()

        conn = sqlite3.connect(db)
        try:
            rows = conn.execute(
                "SELECT family, detection_count FROM detection_aggregates "
                "ORDER BY family"
            ).fetchall()
        finally:
            conn.close()
        assert rows == [("802.11ac", 1), ("802.11n", 2)]


def _agg_indexes(db: Path) -> list[tuple[str, str]]:
    conn = sqlite3.connect(db)
    try:
        return conn.execute(
            "SELECT name, sql FROM sqlite_master WHERE type = 'index' "
            "AND tbl_name = 'detection_aggregates' AND sql IS NOT NULL "
            "ORDER BY name"
        ).fetchall()
    finally:
        conn.close()


class TestAggregateIndexAcrossStarts:
    """The aggregate unique index is created once; later starts are no-ops."""

    def test_second_and_third_start_leave_the_indexes_unchanged(
        self, tmp_path: Path
    ) -> None:
        db = tmp_path / "test.db"
        DetectionStore(db_path=db).close()
        first = _agg_indexes(db)
        names = [name for name, _ in first]
        assert "idx_agg_unique_v2" in names
        assert "idx_agg_unique" not in names
        for _ in range(2):
            DetectionStore(db_path=db).close()
            assert _agg_indexes(db) == first

    def test_start_up_drops_a_family_less_index_left_by_earlier_starts(
        self, tmp_path: Path
    ) -> None:
        """A database the old start-up already re-created the index on is
        repaired at the next start, and stays repaired after that."""
        db = tmp_path / "test.db"
        DetectionStore(db_path=db).close()
        conn = sqlite3.connect(db)
        try:
            conn.execute(
                "CREATE UNIQUE INDEX idx_agg_unique "
                "ON detection_aggregates (hour, node_id, signal_class)"
            )
            conn.commit()
        finally:
            conn.close()
        for _ in range(2):
            DetectionStore(db_path=db).close()
            names = [name for name, _ in _agg_indexes(db)]
            assert "idx_agg_unique" not in names
            assert "idx_agg_unique_v2" in names
