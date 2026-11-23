"""Regression tests: ISO timestamps vs SQLite ``datetime('now')`` (review C3).

Python stores ``datetime.isoformat()`` ("2026-11-05T10:00:00+00:00");
SQLite's ``datetime('now')`` is "2026-11-05 10:00:00".  Compared as text,
'T' sorts after ' ', so on the same UTC date every stored value looked
later than "now": an expired snooze stayed hidden until UTC midnight and
"last N hours" queries returned everything since midnight.

These tests use values on the current UTC date (seconds to a couple of
hours from now), which is the window where the text comparison was wrong.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.correlation_engine import CrossCorrelator
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.storage.base import ACTIVE_FILTER
from sigrift.bridge.storage.bt_anomalies import BtAnomalyStore
from sigrift.bridge.storage.wifi_anomalies import WiFiAnomalyStore


def _iso(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).isoformat()


def _same_utc_date(delta: timedelta) -> bool:
    now = datetime.now(timezone.utc)
    return (now + delta).date() == now.date()


class TestActiveFilter:
    def _active(self, snoozed_until: str | None) -> bool:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (dismissed INTEGER, snoozed_until TEXT)")
        conn.execute("INSERT INTO t VALUES (0, ?)", (snoozed_until,))
        return bool(
            conn.execute(f"SELECT COUNT(*) FROM t WHERE {ACTIVE_FILTER}").fetchone()[0]
        )

    def test_expired_snooze_is_active_again(self) -> None:
        assert self._active(_iso(timedelta(seconds=-2)))
        assert self._active(_iso(timedelta(minutes=-30)))

    def test_running_snooze_hides(self) -> None:
        assert not self._active(_iso(timedelta(hours=1)))
        assert not self._active(_iso(timedelta(seconds=30)))

    @pytest.mark.parametrize(
        "value",
        [None, "", "garbage"],
        ids=["null", "empty", "unparseable"],
    )
    def test_missing_or_unparseable_snooze_is_active(self, value: str | None) -> None:
        assert self._active(value)

    def test_other_formats_compare_by_instant(self) -> None:
        past = datetime.now(timezone.utc) - timedelta(minutes=5)
        assert self._active(past.strftime("%Y-%m-%d %H:%M:%S"))
        assert self._active(past.strftime("%Y-%m-%dT%H:%M:%SZ"))
        # +02:00 offset: 5 minutes ago in UTC terms.
        local = past.astimezone(timezone(timedelta(hours=2)))
        assert self._active(local.isoformat())
        future_local = (datetime.now(timezone.utc) + timedelta(hours=1)).astimezone(
            timezone(timedelta(hours=-5))
        )
        assert not self._active(future_local.isoformat())

    def test_wifi_and_bt_stores_use_the_shared_filter(self) -> None:
        assert WiFiAnomalyStore.ACTIVE_FILTER == ACTIVE_FILTER
        assert BtAnomalyStore.ACTIVE_FILTER == ACTIVE_FILTER


class TestRfSnooze:
    def test_expired_snooze_lists_the_anomaly_again(self, tmp_path: Path) -> None:
        store = DetectionStore(db_path=tmp_path / "snooze.db")
        [anomaly_id] = store.insert_rf_anomalies_batch(
            [
                {
                    "signal_class": "bpsk",
                    "family": "psk",
                    "freq_hz": 433.92e6,
                    "anomaly_score": 0.8,
                    "node_id": "n1",
                    "timestamp": _iso(timedelta(0)),
                }
            ]
        )
        store.snooze_rf_anomaly(anomaly_id, _iso(timedelta(hours=1)))
        assert store.get_rf_anomalies(min_score=0.0) == []

        store.snooze_rf_anomaly(anomaly_id, _iso(timedelta(seconds=-2)))
        ids = [a["id"] for a in store.get_rf_anomalies(min_score=0.0)]
        assert ids == [anomaly_id]


class TestHoursWindows:
    def test_get_anomalies_hours_window(self, tmp_path: Path) -> None:
        if not _same_utc_date(timedelta(hours=-2)):
            pytest.skip("needs two hours since UTC midnight")
        store = DetectionStore(db_path=tmp_path / "hours.db")
        now = datetime.now(timezone.utc)
        dets = [
            DetectionRecord(
                id=f"det-{label}",
                node_id="n1",
                timestamp=now - age,
                signal_class="bpsk",
                confidence=0.9,
                anomaly_score=0.9,
            )
            for label, age in (
                ("old", timedelta(hours=2)),
                ("new", timedelta(minutes=10)),
            )
        ]
        store.insert_batch(dets)
        got = {d["detection_id"] for d in store.get_anomalies(min_score=0.5, hours=1)}
        assert got == {"det-new"}

    def test_correlation_summary_hours_window(self, tmp_path: Path) -> None:
        if not _same_utc_date(timedelta(hours=-2)):
            pytest.skip("needs two hours since UTC midnight")
        store = DetectionStore(db_path=tmp_path / "xcorr.db")
        conn = store._ctx.get_conn()
        for age, ctype in ((timedelta(hours=2), "old"), (timedelta(minutes=5), "new")):
            conn.execute(
                "INSERT INTO cross_correlations (source_a, correlation_type, "
                "node_id, timestamp) VALUES ('sdr', ?, 'n1', ?)",
                (ctype, _iso(-age)),
            )
        conn.commit()
        summary = CrossCorrelator(store._ctx).get_correlation_summary("n1", hours=1)
        assert summary == {"new": 1}
