"""Behavioural tests for Bluetooth storage sub-stores.

Covers:
  - storage/bt_anomalies.py (BtAnomalyStore): upsert/dedup, seen_count,
    snooze/dismiss (single + bulk), node_ids RSSI merge, query filters,
    active-filter, include_dismissed, count, compaction, retention cleanup.
  - storage/bt_metadata.py (BtMetadataStore): insert, MAC anonymization,
    device aggregation + filters, detail (raw + hourly merge), stats,
    timeline, hourly rollup (idempotent), and cleanup/retention.

All tests use a temp SQLite DB via SharedContext(tmp_path), mirroring
tests/bridge/test_wifi_metadata_store.py.
"""

from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.bt_anomalies import BtAnomalyStore
from sigrift.bridge.storage.bt_metadata import BtMetadataStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_anomaly(
    *,
    device_addr: str = "aa:bb:cc:11:22:33",
    device_name: str = "TestDev",
    device_type: str = "phone",
    anomaly_score: float = 0.6,
    rssi_dbm: float = -55.0,
    node_id: str = "n1",
    timestamp: str | None = None,
    priority: str = "normal",
    **kwargs: Any,
) -> dict[str, Any]:
    d = {
        "device_addr": device_addr,
        "device_name": device_name,
        "device_type": device_type,
        "device_class": 0,
        "device_class_name": "",
        "manufacturer": "Acme",
        "vendor": "AcmeVendor",
        "rssi_dbm": rssi_dbm,
        "anomaly_score": anomaly_score,
        "priority": priority,
        "dimensions": {"rssi": 1.2},
        "reasons": ["novel"],
        "baseline_status": "stable",
        "node_id": node_id,
        "timestamp": timestamp or _now_iso(),
        "device_count_nearby": 3,
        "service_uuids": ["180d"],
        "adv_data": {"flags": 6},
        "expected_rssi": -60.0,
        "rssi_zscore": 0.5,
        "baseline_observations": 10,
    }
    d.update(kwargs)
    return d


def _make_device(
    *,
    device_addr: str = "aa:bb:cc:11:22:33",
    device_name: str = "Dev",
    device_type: str = "phone",
    rssi_dbm: float = -50.0,
    manufacturer: str = "Acme",
    node_id: str = "n1",
    timestamp: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    d = {
        "device_addr": device_addr,
        "device_name": device_name,
        "device_type": device_type,
        "device_class": 0,
        "device_class_name": "",
        "appearance": 0,
        "rssi_dbm": rssi_dbm,
        "tx_power_dbm": None,
        "manufacturer_id": None,
        "manufacturer": manufacturer,
        "vendor": "AcmeVendor",
        "service_uuids": ["180d"],
        "adv_data": {"flags": 6},
        "connectable": 1,
        "bonded": 0,
        "channel": 37,
        "timestamp": timestamp or _now_iso(),
        "node_id": node_id,
    }
    d.update(kwargs)
    return d


# ===========================================================================
# BtAnomalyStore
# ===========================================================================


class TestBtAnomalyStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "bt_anom.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def store(self, ctx):
        return BtAnomalyStore(ctx)

    # -- Insert / upsert ----------------------------------------------------

    def test_insert_empty_returns_empty(self, store):
        assert store.insert_bt_anomalies_batch([]) == []

    def test_insert_single(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        assert len(ids) == 1
        assert isinstance(ids[0], int) and ids[0] > 0

    def test_insert_multiple_distinct(self, store):
        ids = store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        assert len(ids) == 2
        assert ids[0] != ids[1]
        assert store.count_bt_anomalies(min_score=0.0) == 2

    def test_upsert_dedup_same_addr_reuses_row(self, store):
        id1 = store.insert_bt_anomalies_batch([_make_anomaly()])[0]
        id2 = store.insert_bt_anomalies_batch([_make_anomaly()])[0]
        assert id1 == id2
        # Only one logical row exists for the device
        assert store.count_bt_anomalies(min_score=0.0) == 1

    def test_upsert_increments_seen_count(self, store):
        store.insert_bt_anomalies_batch([_make_anomaly()])
        store.insert_bt_anomalies_batch([_make_anomaly()])
        store.insert_bt_anomalies_batch([_make_anomaly()])
        rows = store.get_bt_anomalies(min_score=0.0)
        assert len(rows) == 1
        assert rows[0]["seen_count"] == 3

    def test_upsert_updates_mutable_fields(self, store):
        store.insert_bt_anomalies_batch([_make_anomaly(anomaly_score=0.3)])
        store.insert_bt_anomalies_batch(
            [_make_anomaly(anomaly_score=0.9, priority="critical")]
        )
        rows = store.get_bt_anomalies(min_score=0.0)
        assert rows[0]["anomaly_score"] == 0.9
        assert rows[0]["priority"] == "critical"

    def test_node_ids_merge_keeps_strongest_rssi(self, store):
        # Same device seen by two nodes; n1 seen twice with differing RSSI
        store.insert_bt_anomalies_batch([_make_anomaly(node_id="n1", rssi_dbm=-70.0)])
        store.insert_bt_anomalies_batch([_make_anomaly(node_id="n1", rssi_dbm=-40.0)])
        store.insert_bt_anomalies_batch([_make_anomaly(node_id="n2", rssi_dbm=-55.0)])
        rows = store.get_bt_anomalies(min_score=0.0)
        node_ids = rows[0]["node_ids"]
        assert isinstance(node_ids, dict)
        # Strongest (highest) RSSI retained per node
        assert node_ids["n1"] == -40.0
        assert node_ids["n2"] == -55.0

    def test_reinsert_undismisses(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        store.dismiss_bt_anomaly(ids[0])
        assert store.count_bt_anomalies(min_score=0.0) == 0
        # Re-observing the (non-snoozed) device un-dismisses it
        store.insert_bt_anomalies_batch([_make_anomaly()])
        assert store.count_bt_anomalies(min_score=0.0) == 1

    def test_reinsert_snoozed_stays_snoozed(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        future = (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat()
        store.snooze_bt_anomaly(ids[0], until=future)
        assert store.count_bt_anomalies(min_score=0.0) == 0
        # Re-observation bumps seen_count but does NOT clear the snooze
        store.insert_bt_anomalies_batch([_make_anomaly()])
        assert store.count_bt_anomalies(min_score=0.0) == 0
        rows = store.get_bt_anomalies(min_score=0.0, include_dismissed=True)
        assert rows[0]["seen_count"] == 2

    # -- Query filters ------------------------------------------------------

    def test_min_score_filter(self, store):
        store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01", anomaly_score=0.2),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02", anomaly_score=0.8),
            ]
        )
        rows = store.get_bt_anomalies(min_score=0.5)
        assert len(rows) == 1
        assert rows[0]["anomaly_score"] == 0.8

    def test_node_id_filter(self, store):
        store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01", node_id="na"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02", node_id="nb"),
            ]
        )
        rows = store.get_bt_anomalies(min_score=0.0, node_id="na")
        assert len(rows) == 1
        assert rows[0]["node_id"] == "na"

    def test_limit(self, store):
        for i in range(5):
            store.insert_bt_anomalies_batch(
                [_make_anomaly(device_addr=f"aa:bb:cc:00:00:0{i}")]
            )
        rows = store.get_bt_anomalies(min_score=0.0, limit=2)
        assert len(rows) == 2

    def test_sorted_by_score_desc(self, store):
        store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01", anomaly_score=0.4),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02", anomaly_score=0.9),
                _make_anomaly(device_addr="aa:bb:cc:00:00:03", anomaly_score=0.6),
            ]
        )
        rows = store.get_bt_anomalies(min_score=0.0)
        scores = [r["anomaly_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)

    def test_json_fields_deserialized(self, store):
        store.insert_bt_anomalies_batch([_make_anomaly()])
        row = store.get_bt_anomalies(min_score=0.0)[0]
        assert row["dimensions"] == {"rssi": 1.2}
        assert row["reasons"] == ["novel"]
        assert row["service_uuids"] == ["180d"]
        assert row["adv_data"] == {"flags": 6}
        assert isinstance(row["node_ids"], dict)

    def test_empty_query(self, store):
        assert store.get_bt_anomalies(min_score=0.0) == []

    def test_include_dismissed(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        store.dismiss_bt_anomaly(ids[0])
        assert len(store.get_bt_anomalies(min_score=0.0)) == 0
        assert len(store.get_bt_anomalies(min_score=0.0, include_dismissed=True)) == 1

    def test_active_filter_excludes_snoozed(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        future = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        store.snooze_bt_anomaly(ids[0], until=future)
        assert len(store.get_bt_anomalies(min_score=0.0)) == 0
        assert len(store.get_bt_anomalies(min_score=0.0, include_dismissed=True)) == 1

    def test_expired_snooze_reappears(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        store.snooze_bt_anomaly(ids[0], until=past)
        assert len(store.get_bt_anomalies(min_score=0.0)) == 1

    # -- Count --------------------------------------------------------------

    def test_count_basic(self, store):
        store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        assert store.count_bt_anomalies(min_score=0.0) == 2

    def test_count_min_score(self, store):
        store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01", anomaly_score=0.2),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02", anomaly_score=0.8),
            ]
        )
        assert store.count_bt_anomalies(min_score=0.5) == 1

    def test_count_include_dismissed(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        store.dismiss_bt_anomaly(ids[0])
        assert store.count_bt_anomalies(min_score=0.0) == 0
        assert store.count_bt_anomalies(min_score=0.0, include_dismissed=True) == 1

    # -- Dismiss / snooze ---------------------------------------------------

    def test_dismiss_single(self, store):
        ids = store.insert_bt_anomalies_batch([_make_anomaly()])
        store.dismiss_bt_anomaly(ids[0])
        assert store.count_bt_anomalies(min_score=0.0) == 0

    def test_dismiss_bulk(self, store):
        ids = store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        updated = store.dismiss_bt_anomalies_bulk(ids)
        assert updated == 2
        assert store.count_bt_anomalies(min_score=0.0) == 0

    def test_dismiss_bulk_empty(self, store):
        assert store.dismiss_bt_anomalies_bulk([]) == 0

    def test_snooze_bulk(self, store):
        ids = store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        future = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        updated = store.snooze_bt_anomalies_bulk(ids, until=future)
        assert updated == 2
        assert store.count_bt_anomalies(min_score=0.0) == 0

    def test_snooze_bulk_empty(self, store):
        assert store.snooze_bt_anomalies_bulk([], until="2030-01-01T00:00:00Z") == 0

    # -- Compaction ---------------------------------------------------------

    def test_compact_no_duplicates_returns_zero(self, store):
        ids = store.insert_bt_anomalies_batch(
            [
                _make_anomaly(device_addr="aa:bb:cc:00:00:01"),
                _make_anomaly(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        store.dismiss_bt_anomalies_bulk(ids)
        assert store.compact_dismissed_bt_anomalies() == 0

    def test_compact_removes_older_duplicate_dismissed(self, ctx, store):
        # Directly seed two dismissed rows for the same device_addr so the
        # store dedup (which reuses one row) is bypassed.
        conn = ctx.get_conn()
        for _ in range(3):
            conn.execute(
                "INSERT INTO bt_anomalies "
                "(device_addr, anomaly_score, dismissed, timestamp, tenant_id) "
                "VALUES (?, ?, 1, ?, ?)",
                ("aa:bb:cc:dd:ee:ff", 0.6, _now_iso(), "default"),
            )
        conn.commit()
        deleted = store.compact_dismissed_bt_anomalies()
        # 3 dismissed rows for one addr -> keep MAX(id), delete 2
        assert deleted == 2
        remaining = conn.execute(
            "SELECT COUNT(*) FROM bt_anomalies WHERE dismissed = 1"
        ).fetchone()[0]
        assert remaining == 1

    # -- Retention cleanup --------------------------------------------------

    def test_cleanup_removes_old(self, store):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
        store.insert_bt_anomalies_batch([_make_anomaly(timestamp=old_ts)])
        deleted = store.cleanup_bt_anomalies(max_age_days=30)
        assert deleted == 1
        assert store.count_bt_anomalies(min_score=0.0, include_dismissed=True) == 0

    def test_cleanup_keeps_recent(self, store):
        store.insert_bt_anomalies_batch([_make_anomaly(timestamp=_now_iso())])
        deleted = store.cleanup_bt_anomalies(max_age_days=30)
        assert deleted == 0
        assert store.count_bt_anomalies(min_score=0.0) == 1


# ===========================================================================
# BtMetadataStore
# ===========================================================================


class TestBtMetadataStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        with closing(
            SharedContext(db_path=tmp_path / "bt_meta.db", tenant_id="default")
        ) as ctx:
            yield ctx

    @pytest.fixture
    def store(self, ctx):
        return BtMetadataStore(ctx)

    # -- MAC anonymization --------------------------------------------------

    def test_anonymize_mac_preserves_oui(self):
        anon = BtMetadataStore._anonymize_mac("aa:bb:cc:11:22:33", b"secret")
        assert anon.startswith("aa:bb:cc")
        assert anon != "aa:bb:cc:11:22:33"

    def test_anonymize_mac_empty(self):
        assert BtMetadataStore._anonymize_mac("", b"s") == ""

    def test_anonymize_mac_short_unchanged(self):
        assert BtMetadataStore._anonymize_mac("ab:cd", b"s") == "ab:cd"

    def test_anonymize_mac_deterministic(self):
        a1 = BtMetadataStore._anonymize_mac("aa:bb:cc:11:22:33", b"k")
        a2 = BtMetadataStore._anonymize_mac("aa:bb:cc:11:22:33", b"k")
        assert a1 == a2

    # -- Insert -------------------------------------------------------------

    def test_insert_empty(self, store):
        assert store.insert_bt_devices([]) == 0

    def test_insert_single(self, store):
        assert store.insert_bt_devices([_make_device()]) == 1

    def test_insert_multiple(self, store):
        n = store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01"),
                _make_device(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        assert n == 2

    def test_insert_with_mac_anonymization(self, store):
        store.insert_bt_devices(
            [_make_device(device_addr="aa:bb:cc:dd:ee:ff")],
            mac_secret="secret-key",
        )
        devices = store.get_bt_devices()
        assert len(devices) == 1
        assert devices[0]["device_addr"].startswith("aa:bb:cc")
        assert devices[0]["device_addr"] != "aa:bb:cc:dd:ee:ff"

    # -- Device aggregation queries -----------------------------------------

    def test_get_bt_devices_empty(self, store):
        assert store.get_bt_devices() == []

    def test_get_bt_devices_aggregates(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-40.0),
                _make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-60.0),
                _make_device(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        devices = store.get_bt_devices()
        assert len(devices) == 2
        dev1 = next(d for d in devices if d["device_addr"] == "aa:bb:cc:00:00:01")
        assert dev1["observation_count"] == 2
        assert dev1["avg_rssi_dbm"] == -50.0  # (-40 + -60) / 2

    def test_get_bt_devices_type_filter(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", device_type="phone"),
                _make_device(device_addr="aa:bb:cc:00:00:02", device_type="wearable"),
            ]
        )
        result = store.get_bt_devices(device_type="wearable")
        assert len(result) == 1
        assert result[0]["device_addr"] == "aa:bb:cc:00:00:02"

    def test_get_bt_devices_node_filter(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", node_id="na"),
                _make_device(device_addr="aa:bb:cc:00:00:02", node_id="nb"),
            ]
        )
        result = store.get_bt_devices(node_id="na")
        assert len(result) == 1
        assert result[0]["node_ids"] == ["na"]

    def test_get_bt_devices_excludes_empty_addr(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr=""),
                _make_device(device_addr="aa:bb:cc:00:00:01"),
            ]
        )
        result = store.get_bt_devices()
        assert len(result) == 1
        assert result[0]["device_addr"] == "aa:bb:cc:00:00:01"

    def test_get_bt_devices_limit(self, store):
        for i in range(4):
            store.insert_bt_devices([_make_device(device_addr=f"aa:bb:cc:00:00:0{i}")])
        assert len(store.get_bt_devices(limit=2)) == 2

    # -- Device detail ------------------------------------------------------

    def test_get_bt_device_detail_not_found(self, store):
        assert store.get_bt_device_detail("ff:ff:ff:ff:ff:ff") is None

    def test_get_bt_device_detail_raw_only(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-45.0),
                _make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-55.0),
            ]
        )
        detail = store.get_bt_device_detail("aa:bb:cc:00:00:01")
        assert detail is not None
        assert detail["observation_count"] == 2
        assert detail["avg_rssi_dbm"] == -50.0

    def test_get_bt_device_detail_merges_raw_and_hourly(self, store):
        # After retention, historical summaries and new raw observations
        # represent distinct events and must both survive the detail query.
        old = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        store.insert_bt_devices(
            [
                _make_device(
                    device_addr="aa:bb:cc:00:00:09", timestamp=old, rssi_dbm=-60.0
                )
            ]
        )
        assert store.aggregate_bt_hourly(cutoff_hours=2) == 1
        assert store.cleanup_bt_devices(max_age_hours=4) == 1
        store.insert_bt_devices(
            [_make_device(device_addr="aa:bb:cc:00:00:09", rssi_dbm=-40.0)]
        )
        detail = store.get_bt_device_detail("aa:bb:cc:00:00:09")
        assert detail is not None
        assert detail["observation_count"] == 2
        assert detail["avg_rssi_dbm"] == -50.0

    # -- Stats --------------------------------------------------------------

    def test_get_bt_stats_empty(self, store):
        stats = store.get_bt_stats()
        assert stats["total_devices"] == 0
        assert stats["type_breakdown"] == {}
        assert stats["top_manufacturers"] == []
        assert stats["active_bt_nodes"] == []

    def test_get_bt_stats_with_data(self, store):
        store.insert_bt_devices(
            [
                _make_device(
                    device_addr="aa:bb:cc:00:00:01",
                    device_type="phone",
                    manufacturer="Acme",
                    node_id="na",
                ),
                _make_device(
                    device_addr="aa:bb:cc:00:00:02",
                    device_type="wearable",
                    manufacturer="Beta",
                    node_id="nb",
                ),
            ]
        )
        stats = store.get_bt_stats()
        assert stats["total_devices"] == 2
        assert stats["type_breakdown"] == {"phone": 1, "wearable": 1}
        mfrs = {m["manufacturer"] for m in stats["top_manufacturers"]}
        assert mfrs == {"Acme", "Beta"}
        assert set(stats["active_bt_nodes"]) == {"na", "nb"}

    def test_get_bt_stats_excludes_stale(self, store):
        stale = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", timestamp=stale),
            ]
        )
        # Stats window is 24h -> stale device not counted
        assert store.get_bt_stats()["total_devices"] == 0

    # -- Timeline -----------------------------------------------------------

    def test_get_bt_timeline_empty(self, store):
        assert store.get_bt_timeline("aa:bb:cc:00:00:01", hours=1) == []

    def test_get_bt_timeline_with_data(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-50.0),
            ]
        )
        result = store.get_bt_timeline("aa:bb:cc:00:00:01", hours=1)
        assert len(result) == 1
        entry = result[0]
        assert "hour" in entry and isinstance(entry["hour"], str)
        assert entry["avg_rssi_dbm"] == -50.0
        assert entry["observation_count"] == 1

    def test_get_bt_timeline_filters_by_device(self, store):
        store.insert_bt_devices(
            [
                _make_device(device_addr="aa:bb:cc:00:00:01"),
                _make_device(device_addr="aa:bb:cc:00:00:02"),
            ]
        )
        result = store.get_bt_timeline("aa:bb:cc:00:00:01", hours=1)
        total_obs = sum(e["observation_count"] for e in result)
        assert total_obs == 1

    # -- Hourly rollup ------------------------------------------------------

    def test_aggregate_bt_hourly(self, store):
        store.insert_bt_devices([_make_device()])
        count = store.aggregate_bt_hourly(cutoff_hours=0)
        assert count == 1

    def test_aggregate_bt_hourly_idempotent(self, ctx, store):
        store.insert_bt_devices([_make_device()])
        c1 = store.aggregate_bt_hourly(cutoff_hours=0)
        c2 = store.aggregate_bt_hourly(cutoff_hours=0)
        assert c1 == c2 == 1
        rows = (
            ctx.get_conn()
            .execute("SELECT observation_count FROM bt_devices_hourly")
            .fetchall()
        )
        assert len(rows) == 1
        assert rows[0]["observation_count"] == 1

    def test_get_bt_devices_merges_hourly(self, store):
        old = (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat()
        store.insert_bt_devices(
            [
                _make_device(
                    device_addr="aa:bb:cc:00:00:01", timestamp=old, rssi_dbm=-60.0
                )
            ]
        )
        assert store.aggregate_bt_hourly(cutoff_hours=2) == 1
        assert store.cleanup_bt_devices(max_age_hours=4) == 1
        store.insert_bt_devices(
            [_make_device(device_addr="aa:bb:cc:00:00:01", rssi_dbm=-40.0)]
        )
        devices = store.get_bt_devices()
        dev = next(d for d in devices if d["device_addr"] == "aa:bb:cc:00:00:01")
        assert dev["observation_count"] == 2
        assert dev["avg_rssi_dbm"] == -50.0

    # -- Cleanup / retention ------------------------------------------------

    def test_cleanup_bt_devices_deletes_old(self, store):
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=8)).isoformat()
        store.insert_bt_devices([_make_device(timestamp=old_ts)])
        store.insert_bt_devices([_make_device(timestamp=_now_iso())])
        deleted = store.cleanup_bt_devices(max_age_hours=4)
        assert deleted == 1

    def test_cleanup_bt_devices_no_op(self, store):
        store.insert_bt_devices([_make_device()])
        assert store.cleanup_bt_devices(max_age_hours=4) == 0

    def test_cleanup_bt_hourly_deletes_old(self, store):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        store.insert_bt_devices([_make_device(timestamp=old_ts)])
        store.aggregate_bt_hourly(cutoff_hours=0)
        deleted = store.cleanup_bt_hourly(max_age_days=90)
        assert deleted == 1

    def test_cleanup_bt_hourly_no_op(self, store):
        store.insert_bt_devices([_make_device()])
        store.aggregate_bt_hourly(cutoff_hours=0)
        assert store.cleanup_bt_hourly(max_age_days=90) == 0
