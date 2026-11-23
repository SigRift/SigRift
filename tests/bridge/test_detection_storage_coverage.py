"""Behavioural coverage for detection-domain storage sub-stores.

Targets:
  - storage/detection_crud.py     (DetectionCrudStore)
  - storage/detection_analytics.py (DetectionAnalyticsStore)
  - storage/emitter_store.py       (EmitterStore)
  - storage/fhss_store.py          (FHSSStore)

Each store is driven directly against a temp-file SQLite DB via a
``SharedContext`` (schema + migrations applied in its constructor).
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_crud import DetectionCrudStore
from sigrift.bridge.storage.detection_analytics import DetectionAnalyticsStore
from sigrift.bridge.storage.emitter_store import EmitterStore
from sigrift.bridge.storage.fhss_store import FHSSStore
from sigrift.bridge.models import DetectionQuery, DetectionRecord, DetectionStats


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _rec(**kwargs) -> DetectionRecord:
    defaults = dict(
        node_id="node-1",
        signal_class="bpsk",
        confidence=0.9,
        family="psk",
        freq_hz=433.92e6,
        snr_db=15.0,
        power_dbm=-40.0,
    )
    defaults.update(kwargs)
    return DetectionRecord(**defaults)


# ===========================================================================
# DetectionCrudStore
# ===========================================================================


class TestDetectionCrud:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "crud.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def store(self, ctx):
        return DetectionCrudStore(ctx)

    def test_insert_returns_inserted_count(self, store):
        recs = [_rec(node_id=f"n{i}") for i in range(4)]
        assert store.insert_batch(recs) == 4
        assert store.row_count() == 4

    def test_insert_empty(self, store):
        assert store.insert_batch([]) == 0
        assert store.row_count() == 0

    def test_dedup_on_conflicting_detection_id(self, store):
        rec = _rec()
        assert store.insert_batch([rec]) == 1
        # Same detection_id -> ON CONFLICT DO NOTHING, 0 rows inserted.
        assert store.insert_batch([rec]) == 0
        assert store.row_count() == 1

    def test_insert_accepts_float_epoch_timestamp(self, store):
        ts = _utcnow().timestamp()
        rec = _rec(timestamp=ts)
        store.insert_batch([rec])
        got = store.get_detection_by_id(rec.detection_id)
        assert got is not None
        assert got["timestamp"].startswith(
            datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()[:19]
        )

    def test_get_by_id_roundtrip(self, store):
        rec = _rec(signal_class="qam16", family="qam", confidence=0.77)
        store.insert_batch([rec])
        got = store.get_detection_by_id(rec.detection_id)
        assert got["signal_class"] == "qam16"
        assert got["family"] == "qam"
        assert got["confidence"] == 0.77

    def test_get_by_id_missing(self, store):
        assert store.get_detection_by_id("does-not-exist") is None

    def test_query_filter_by_node(self, store):
        store.insert_batch([_rec(node_id="a"), _rec(node_id="b"), _rec(node_id="a")])
        rows = store.query(DetectionQuery(node_id="a"))
        assert len(rows) == 2
        assert all(r["node_id"] == "a" for r in rows)

    def test_query_filter_by_signal_class_and_family(self, store):
        store.insert_batch(
            [
                _rec(signal_class="bpsk", family="psk"),
                _rec(signal_class="qam16", family="qam"),
            ]
        )
        rows = store.query(DetectionQuery(signal_class="qam16"))
        assert len(rows) == 1 and rows[0]["signal_class"] == "qam16"
        rows = store.query(DetectionQuery(family="psk"))
        assert len(rows) == 1 and rows[0]["family"] == "psk"

    def test_query_min_confidence(self, store):
        store.insert_batch(
            [
                _rec(confidence=0.2),
                _rec(confidence=0.6),
                _rec(confidence=0.95),
            ]
        )
        rows = store.query(DetectionQuery(min_confidence=0.5))
        assert len(rows) == 2
        assert all(r["confidence"] >= 0.5 for r in rows)

    def test_query_time_window(self, store):
        now = _utcnow()
        store.insert_batch(
            [
                _rec(timestamp=now - timedelta(hours=10)),
                _rec(timestamp=now - timedelta(minutes=1)),
            ]
        )
        rows = store.query(DetectionQuery(start=now - timedelta(hours=1)))
        assert len(rows) == 1

    def test_query_limit_offset_and_order(self, store):
        now = _utcnow()
        # 5 records, increasing recency
        recs = [
            _rec(node_id=f"n{i}", timestamp=now - timedelta(minutes=5 - i))
            for i in range(5)
        ]
        store.insert_batch(recs)
        first_two = store.query(DetectionQuery(limit=2, offset=0))
        assert len(first_two) == 2
        # ORDER BY timestamp DESC -> most recent first
        assert first_two[0]["node_id"] == "n4"
        next_two = store.query(DetectionQuery(limit=2, offset=2))
        assert [r["node_id"] for r in next_two] == ["n2", "n1"]

    def test_get_recent_window_excludes_old(self, store):
        now = _utcnow()
        store.insert_batch(
            [
                _rec(timestamp=now - timedelta(minutes=1)),
                _rec(timestamp=now - timedelta(minutes=30)),
            ]
        )
        recent = store.get_recent(minutes=5)
        assert len(recent) == 1

    def test_get_recent_node_filter(self, store):
        now = _utcnow()
        store.insert_batch(
            [
                _rec(node_id="a", timestamp=now),
                _rec(node_id="b", timestamp=now),
            ]
        )
        assert len(store.get_recent(minutes=5, node_id="a")) == 1

    def test_set_has_iq_capture(self, store):
        rec = _rec()
        store.insert_batch([rec])
        assert store.get_detection_by_id(rec.detection_id)["has_iq_capture"] == 0
        store.set_has_iq_capture(rec.detection_id, True)
        assert store.get_detection_by_id(rec.detection_id)["has_iq_capture"] == 1
        store.set_has_iq_capture(rec.detection_id, False)
        assert store.get_detection_by_id(rec.detection_id)["has_iq_capture"] == 0

    def test_tenant_isolation(self, tmp_path):
        db = tmp_path / "shared.db"
        with (
            closing(SharedContext(db_path=db, tenant_id="tenant-a")) as ctx_a,
            closing(SharedContext(db_path=db, tenant_id="tenant-b")) as ctx_b,
        ):
            a, b = DetectionCrudStore(ctx_a), DetectionCrudStore(ctx_b)
            a.insert_batch([_rec(), _rec(node_id="x")])
            b.insert_batch([_rec(node_id="y")])
            assert a.row_count() == 2
            assert b.row_count() == 1
            # b cannot read a's record
            arec = a.query(DetectionQuery(limit=1))[0]
            assert b.get_detection_by_id(arec["detection_id"]) is None


# ===========================================================================
# DetectionAnalyticsStore
# ===========================================================================


class TestDetectionAnalytics:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "analytics.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def crud(self, ctx):
        return DetectionCrudStore(ctx)

    @pytest.fixture
    def store(self, ctx):
        return DetectionAnalyticsStore(ctx)

    def test_stats_empty(self, store):
        s = store.get_stats(hours=24)
        assert isinstance(s, DetectionStats)
        assert s.total_detections == 0
        assert s.avg_confidence == 0.0

    def test_stats_totals_and_distributions(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(
                    signal_class="bpsk",
                    family="psk",
                    confidence=0.8,
                    node_id="n1",
                    timestamp=now,
                ),
                _rec(
                    signal_class="bpsk",
                    family="psk",
                    confidence=0.9,
                    node_id="n2",
                    timestamp=now,
                ),
                _rec(
                    signal_class="qam16",
                    family="qam",
                    confidence=1.0,
                    node_id="n1",
                    timestamp=now,
                ),
            ]
        )
        s = store.get_stats(hours=24)
        assert s.total_detections == 3
        assert s.unique_classes == 2
        assert s.unique_nodes == 2
        assert s.class_distribution["bpsk"] == 2
        assert s.class_distribution["qam16"] == 1
        assert s.family_distribution["psk"] == 2
        assert round(s.avg_confidence, 2) == 0.9

    def test_stats_node_filter(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(node_id="n1", timestamp=now),
                _rec(node_id="n2", timestamp=now),
            ]
        )
        assert store.get_stats(hours=24, node_id="n1").total_detections == 1

    def test_stats_respects_time_window(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(timestamp=now),
                _rec(timestamp=now - timedelta(hours=48)),
            ]
        )
        assert store.get_stats(hours=24).total_detections == 1

    def test_timeline_buckets(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [_rec(timestamp=now - timedelta(minutes=i)) for i in range(3)]
        )
        tl = store.get_timeline(range_hours=1, resolution_seconds=300)
        assert isinstance(tl, list)
        assert sum(b["count"] for b in tl) == 3
        for b in tl:
            assert "bucket" in b and "classes" in b

    def test_distribution(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(signal_class="bpsk", family="psk", timestamp=now),
                _rec(signal_class="bpsk", family="psk", timestamp=now),
                _rec(signal_class="fsk", family="fsk", confidence=0.3, timestamp=now),
            ]
        )
        dist = store.get_distribution(range_hours=24)
        top = dist[0]
        assert top["signal_class"] == "bpsk"
        assert top["count"] == 2
        # min_confidence filter drops the low-confidence fsk row
        filtered = store.get_distribution(range_hours=24, min_confidence=0.5)
        assert [d["signal_class"] for d in filtered] == ["bpsk"]
        assert filtered[0]["count"] == 2

    def test_anomalies_threshold_and_order(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(anomaly_score=0.1, timestamp=now),
                _rec(anomaly_score=0.5, timestamp=now),
                _rec(anomaly_score=0.9, timestamp=now),
            ]
        )
        res = store.get_anomalies(min_score=0.3)
        assert len(res) == 2
        # sorted by anomaly_score DESC
        assert res[0]["anomaly_score"] == 0.9
        assert res[1]["anomaly_score"] == 0.5

    def test_active_anomaly_count(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(anomaly_score=0.0, timestamp=now),
                _rec(anomaly_score=0.4, timestamp=now),
                _rec(anomaly_score=0.6, timestamp=now),
            ]
        )
        assert store.get_active_anomaly_count(threshold=0.3) == 2

    def test_active_frequency_count_and_list(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(freq_hz=433.0e6, timestamp=now),
                _rec(freq_hz=433.0e6, timestamp=now),
                _rec(freq_hz=915.0e6, timestamp=now),
            ]
        )
        # two distinct 100 kHz buckets
        assert store.get_active_frequency_count(hours=1) == 2
        freqs = store.get_active_frequencies(hours=1)
        assert len(freqs) == 2
        # ordered by count DESC -> the 433 bucket (2 hits) first
        assert freqs[0]["count"] == 2

    def test_aggregate_hourly_rolls_up_old_detections(self, ctx, crud, store):
        now = _utcnow()
        # Two old detections (older than 1h) in the same hour bucket + class.
        old = now - timedelta(hours=3)
        crud.insert_batch(
            [
                _rec(signal_class="bpsk", family="psk", confidence=0.8, timestamp=old),
                _rec(signal_class="bpsk", family="psk", confidence=0.6, timestamp=old),
                # a recent one that should NOT be aggregated
                _rec(signal_class="bpsk", timestamp=now),
            ]
        )
        written = store.aggregate_hourly(tenant_id="default")
        assert written == 1
        conn = ctx.get_conn()
        agg = conn.execute(
            "SELECT detection_count, avg_confidence FROM detection_aggregates"
        ).fetchone()
        assert agg["detection_count"] == 2
        assert round(agg["avg_confidence"], 2) == 0.7

    def test_cleanup_prunes_old_raw_rows(self, crud, store):
        now = _utcnow()
        crud.insert_batch(
            [
                _rec(timestamp=now - timedelta(days=30)),
                _rec(timestamp=now - timedelta(days=10)),
                _rec(timestamp=now),
            ]
        )
        deleted = store.cleanup(tenant_id="default", max_age_days=7)
        assert deleted == 2
        assert crud.row_count() == 1


# ===========================================================================
# EmitterStore
# ===========================================================================


class TestEmitterStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "emitter.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def store(self, ctx):
        return EmitterStore(ctx)

    def _emitter(self, emitter_id="em-1", **kwargs):
        base = dict(
            emitter_id=emitter_id,
            primary_freq_hz=433.92e6,
            bandwidth_hz=200e3,
            signal_class="bpsk",
            power_profile={"mean_dbm": -40.0},
            activity_pattern={"duty": 0.5},
            associated_nodes=["n1", "n2"],
            first_seen=_utcnow().isoformat(),
            last_seen=_utcnow().isoformat(),
            detection_count=12,
            detection_ids=["d1", "d2", "d3"],
        )
        base.update(kwargs)
        return base

    def test_upsert_empty(self, store):
        assert store.upsert_emitters([]) == 0
        assert store.count() == 0

    def test_upsert_and_get_parses_json(self, store):
        store.upsert_emitters([self._emitter()])
        got = store.get_emitter("em-1")
        assert got is not None
        assert got["signal_class"] == "bpsk"
        assert got["detection_count"] == 12
        # JSON columns parsed back into python structures
        assert got["associated_nodes"] == ["n1", "n2"]
        assert got["power_profile"] == {"mean_dbm": -40.0}
        assert got["detection_ids"] == ["d1", "d2", "d3"]

    def test_upsert_replaces_existing(self, store):
        store.upsert_emitters([self._emitter(detection_count=5)])
        store.upsert_emitters([self._emitter(detection_count=99)])
        assert store.count() == 1
        assert store.get_emitter("em-1")["detection_count"] == 99

    def test_get_missing_returns_none(self, store):
        assert store.get_emitter("nope") is None

    def test_list_signal_class_filter(self, store):
        store.upsert_emitters(
            [
                self._emitter("a", signal_class="bpsk"),
                self._emitter("b", signal_class="qam16"),
            ]
        )
        rows = store.list_emitters(signal_class="qam16")
        assert len(rows) == 1 and rows[0]["emitter_id"] == "b"

    def test_list_min_detections_filter(self, store):
        store.upsert_emitters(
            [
                self._emitter("a", detection_count=2),
                self._emitter("b", detection_count=50),
            ]
        )
        rows = store.list_emitters(min_detections=10)
        assert len(rows) == 1 and rows[0]["emitter_id"] == "b"

    def test_list_ordered_by_detection_count_desc(self, store):
        store.upsert_emitters(
            [
                self._emitter("low", detection_count=1),
                self._emitter("high", detection_count=100),
                self._emitter("mid", detection_count=50),
            ]
        )
        rows = store.list_emitters()
        assert [r["emitter_id"] for r in rows] == ["high", "mid", "low"]

    def test_list_limit_offset(self, store):
        store.upsert_emitters(
            [self._emitter(f"e{i}", detection_count=i) for i in range(5)]
        )
        page = store.list_emitters(limit=2, offset=0)
        assert [r["emitter_id"] for r in page] == ["e4", "e3"]
        next_page = store.list_emitters(limit=2, offset=2)
        assert [r["emitter_id"] for r in next_page] == ["e2", "e1"]

    def test_delete_all(self, store):
        store.upsert_emitters([self._emitter("a"), self._emitter("b")])
        assert store.count() == 2
        assert store.delete_all() == 2
        assert store.count() == 0

    def test_tenant_isolation(self, tmp_path):
        db = tmp_path / "em_shared.db"
        with (
            closing(SharedContext(db_path=db, tenant_id="a")) as ctx_a,
            closing(SharedContext(db_path=db, tenant_id="b")) as ctx_b,
        ):
            a, b = EmitterStore(ctx_a), EmitterStore(ctx_b)
            a.upsert_emitters([self._emitter("shared-id")])
            # Same emitter_id but different tenant -> distinct row, no clobber.
            b.upsert_emitters([self._emitter("shared-id", detection_count=7)])
            assert a.count() == 1
            assert b.count() == 1
            assert a.get_emitter("shared-id")["detection_count"] == 12
            assert b.get_emitter("shared-id")["detection_count"] == 7


# ===========================================================================
# FHSSStore
# ===========================================================================


class TestFHSSStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "fhss.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def store(self, ctx):
        return FHSSStore(ctx)

    def _event(self, fhss_id="f1", ts=None, **kwargs):
        ev = dict(
            fhss_id=fhss_id,
            node_id="n1",
            timestamp=(ts or _utcnow()).isoformat(),
            hop_rate_hz=1600.0,
            hop_set=[2402e6, 2426e6, 2480e6],
            bandwidth_hz=1e6,
            dwell_time_ms=0.625,
            duration_sec=5.0,
            signal_class="bluetooth",
            detection_count=8,
            confidence=0.9,
        )
        ev.update(kwargs)
        return ev

    def test_insert_returns_ids_and_parses_hop_set(self, store):
        assert store.insert_fhss_events([self._event()]) == ["f1"]
        got = store.get_fhss_event_by_id("f1")
        assert got["hop_set"] == [2402e6, 2426e6, 2480e6]
        assert got["hop_rate_hz"] == 1600.0

    def test_insert_skips_blank_id(self, store):
        assert store.insert_fhss_events([self._event(fhss_id="")]) == []
        assert store.count_fhss_events(hours=1) == 0

    def test_insert_dedup_on_conflict(self, store):
        store.insert_fhss_events([self._event("dup")])
        store.insert_fhss_events([self._event("dup", hop_rate_hz=999.0)])
        assert store.count_fhss_events(hours=1) == 1
        # ON CONFLICT DO NOTHING -> original value retained
        assert store.get_fhss_event_by_id("dup")["hop_rate_hz"] == 1600.0

    def test_query_min_hop_rate(self, store):
        store.insert_fhss_events(
            [
                self._event("slow", hop_rate_hz=100.0),
                self._event("fast", hop_rate_hz=2000.0),
            ]
        )
        rows = store.get_fhss_events(hours=1, min_hop_rate=1000.0)
        assert len(rows) == 1 and rows[0]["fhss_id"] == "fast"

    def test_query_node_filter(self, store):
        store.insert_fhss_events(
            [
                self._event("a", node_id="n1"),
                self._event("b", node_id="n2"),
            ]
        )
        rows = store.get_fhss_events(hours=1, node_id="n2")
        assert len(rows) == 1 and rows[0]["node_id"] == "n2"

    def test_query_time_window_excludes_old(self, store):
        store.insert_fhss_events(
            [
                self._event("recent", ts=_utcnow()),
                self._event("old", ts=_utcnow() - timedelta(hours=48)),
            ]
        )
        rows = store.get_fhss_events(hours=24)
        assert [r["fhss_id"] for r in rows] == ["recent"]

    def test_query_limit_offset(self, store):
        now = _utcnow()
        store.insert_fhss_events(
            [self._event(f"e{i}", ts=now - timedelta(minutes=i)) for i in range(4)]
        )
        page = store.get_fhss_events(hours=1, limit=2, offset=0)
        assert [r["fhss_id"] for r in page] == ["e0", "e1"]
        next_page = store.get_fhss_events(hours=1, limit=2, offset=2)
        assert [r["fhss_id"] for r in next_page] == ["e2", "e3"]

    def test_get_by_id_missing(self, store):
        assert store.get_fhss_event_by_id("nope") is None

    def test_cleanup_fhss_events_prunes_old(self, store):
        store.insert_fhss_events(
            [
                self._event("old", ts=_utcnow() - timedelta(days=40)),
                self._event("new", ts=_utcnow()),
            ]
        )
        assert store.cleanup_fhss_events(max_age_days=30) == 1
        assert store.get_fhss_event_by_id("old") is None
        assert store.get_fhss_event_by_id("new") is not None

    def test_dedup_to_summaries(self, ctx, store):
        now = _utcnow().replace(minute=5, second=0, microsecond=0)
        # Two events, same hour + node + hop_set + class -> one summary bin.
        store.insert_fhss_events(
            [
                self._event("s1", ts=now, confidence=0.8, duration_sec=2.0),
                self._event(
                    "s2",
                    ts=now + timedelta(minutes=10),
                    confidence=1.0,
                    duration_sec=3.0,
                ),
            ]
        )
        n = store.dedup_to_summaries()
        assert n == 1
        conn = ctx.get_conn()
        row = conn.execute(
            "SELECT occurrence_count, max_confidence, total_duration_sec, "
            "hop_set_hash FROM fhss_event_summaries"
        ).fetchone()
        assert row["occurrence_count"] == 2
        assert row["max_confidence"] == 1.0
        assert row["total_duration_sec"] == 5.0
        assert row["hop_set_hash"]  # non-empty hash

    def test_dedup_empty_returns_zero(self, store):
        assert store.dedup_to_summaries() == 0

    def test_cleanup_raw_fhss(self, store):
        store.insert_fhss_events(
            [
                self._event("old", ts=_utcnow() - timedelta(days=14)),
                self._event("fresh", ts=_utcnow()),
            ]
        )
        assert store.cleanup_raw_fhss(max_age_days=7) == 1
        assert store.get_fhss_event_by_id("fresh") is not None

    def test_cleanup_fhss_summaries(self, ctx, store):
        old_window = (_utcnow() - timedelta(days=120)).strftime("%Y-%m-%dT%H:00:00Z")
        conn = ctx.get_conn()
        conn.execute(
            "INSERT INTO fhss_event_summaries "
            "(window_start, node_id, hop_rate_hz, hop_set_hash, bandwidth_hz, "
            " signal_class, occurrence_count, avg_confidence, max_confidence, "
            " avg_dwell_time_ms, total_duration_sec, first_seen, last_seen, tenant_id) "
            "VALUES (?, 'n1', 1600.0, 'abc', 1e6, 'bt', 1, 0.5, 0.5, 0.6, 1.0, "
            " ?, ?, 'default')",
            (old_window, old_window, old_window),
        )
        conn.commit()
        assert store.cleanup_fhss_summaries(max_age_days=90) == 1
