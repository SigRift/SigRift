"""Tests for RF anomaly storage sub-store (sigrift.bridge.storage.rf_anomalies).

Covers priority mapping, frequency band labels, summary aggregation,
snooze operations, cleanup, count with filters, and sort/order options
that are not exercised by the endpoint-level tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage.rf_anomalies import RFAnomalyStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path: Path) -> DetectionStore:
    """DetectionStore backed by a temp SQLite file."""
    return DetectionStore(db_path=tmp_path / "rf_test.db")


def _make_anomaly(
    signal_class: str = "bpsk",
    family: str = "psk",
    freq_hz: float = 433.92e6,
    anomaly_score: float = 0.6,
    node_id: str = "node-01",
    timestamp: str | None = None,
    **kwargs,
) -> dict:
    return {
        "signal_class": signal_class,
        "family": family,
        "freq_hz": freq_hz,
        "anomaly_score": anomaly_score,
        "node_id": node_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Static helper tests
# ---------------------------------------------------------------------------

class TestRfPriority:
    """RFAnomalyStore._rf_priority maps score to priority label."""

    def test_critical(self):
        assert RFAnomalyStore._rf_priority(0.7) == "critical"
        assert RFAnomalyStore._rf_priority(0.95) == "critical"

    def test_anomalous(self):
        assert RFAnomalyStore._rf_priority(0.5) == "anomalous"
        assert RFAnomalyStore._rf_priority(0.69) == "anomalous"

    def test_interesting(self):
        assert RFAnomalyStore._rf_priority(0.3) == "interesting"
        assert RFAnomalyStore._rf_priority(0.49) == "interesting"

    def test_normal(self):
        assert RFAnomalyStore._rf_priority(0.0) == "normal"
        assert RFAnomalyStore._rf_priority(0.29) == "normal"


class TestBucketToBandLabel:
    """RFAnomalyStore._bucket_to_band_label human-readable RF band labels."""

    def test_ism_433(self):
        assert "ISM 433" in RFAnomalyStore._bucket_to_band_label(433.92e6)

    def test_cellular_900(self):
        assert "Cellular 700-900" in RFAnomalyStore._bucket_to_band_label(915e6)

    def test_fm_broadcast(self):
        assert "FM Broadcast" in RFAnomalyStore._bucket_to_band_label(98.5e6)

    def test_airband(self):
        assert "Airband" in RFAnomalyStore._bucket_to_band_label(121.5e6)

    def test_vhf_low(self):
        assert "VHF Low" in RFAnomalyStore._bucket_to_band_label(50e6)

    def test_vhf_high(self):
        assert "VHF High" in RFAnomalyStore._bucket_to_band_label(150e6)

    def test_hf(self):
        assert "HF" in RFAnomalyStore._bucket_to_band_label(14.3e6)

    def test_lf(self):
        assert "LF" in RFAnomalyStore._bucket_to_band_label(200e3)

    def test_mf_am(self):
        assert "MF/AM" in RFAnomalyStore._bucket_to_band_label(1e6)

    def test_cellular_700_900(self):
        assert "Cellular" in RFAnomalyStore._bucket_to_band_label(750e6)

    def test_l_band(self):
        assert "L-Band" in RFAnomalyStore._bucket_to_band_label(1200e6)

    def test_cellular_1800(self):
        assert "Cellular" in RFAnomalyStore._bucket_to_band_label(1900e6)

    def test_ism_2_4ghz(self):
        assert "ISM 2.4 GHz" in RFAnomalyStore._bucket_to_band_label(2400e6)

    def test_s_band(self):
        assert "S-Band" in RFAnomalyStore._bucket_to_band_label(3000e6)

    def test_vhf_tv(self):
        assert "VHF TV" in RFAnomalyStore._bucket_to_band_label(180e6)

    def test_uhf_low(self):
        assert "UHF Low" in RFAnomalyStore._bucket_to_band_label(300e6)

    def test_uhf_tv(self):
        assert "UHF TV" in RFAnomalyStore._bucket_to_band_label(500e6)

    def test_fallback_mhz_label(self):
        # Very high frequency falls through to "NNN MHz" label
        label = RFAnomalyStore._bucket_to_band_label(12e9)
        assert isinstance(label, str)
        assert "MHz" in label


class TestDedupKey:
    """RFAnomalyStore._rf_dedup_key builds correct bucket keys."""

    def test_dedup_key_format(self):
        key = RFAnomalyStore._rf_dedup_key("bpsk", 433.92e6)
        assert key == "bpsk|4339"

    def test_different_freq_different_key(self):
        k1 = RFAnomalyStore._rf_dedup_key("bpsk", 433.92e6)
        k2 = RFAnomalyStore._rf_dedup_key("bpsk", 915e6)
        assert k1 != k2

    def test_different_class_different_key(self):
        k1 = RFAnomalyStore._rf_dedup_key("bpsk", 433.92e6)
        k2 = RFAnomalyStore._rf_dedup_key("qpsk", 433.92e6)
        assert k1 != k2


# ---------------------------------------------------------------------------
# Insert / query tests
# ---------------------------------------------------------------------------

class TestInsertAndQuery:
    """Batch insert and query with various filters."""

    def test_insert_empty_batch(self, store: DetectionStore):
        assert store.insert_rf_anomalies_batch([]) == []

    def test_insert_single(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([_make_anomaly()])
        assert len(ids) == 1
        assert isinstance(ids[0], int)
        assert ids[0] > 0

    def test_query_with_family_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(signal_class="bpsk", family="psk", freq_hz=433e6),
            _make_anomaly(signal_class="16qam", family="qam", freq_hz=915e6),
        ])
        results = store.get_rf_anomalies(min_score=0.0, family="psk")
        assert len(results) == 1
        assert results[0]["family"] == "psk"

    def test_query_with_signal_class_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(signal_class="bpsk", freq_hz=433e6),
            _make_anomaly(signal_class="qpsk", freq_hz=915e6),
        ])
        results = store.get_rf_anomalies(min_score=0.0, signal_class="qpsk")
        assert len(results) == 1
        assert results[0]["signal_class"] == "qpsk"

    def test_query_with_priority_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(anomaly_score=0.8, freq_hz=433e6),   # critical
            _make_anomaly(anomaly_score=0.4, freq_hz=915e6),   # interesting
        ])
        results = store.get_rf_anomalies(min_score=0.0, priority="critical")
        assert len(results) == 1
        assert results[0]["anomaly_score"] == 0.8

    def test_query_with_freq_range(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=100e6),
            _make_anomaly(signal_class="qpsk", freq_hz=500e6),
            _make_anomaly(signal_class="16qam", freq_hz=900e6),
        ])
        results = store.get_rf_anomalies(
            min_score=0.0, freq_min_hz=200e6, freq_max_hz=600e6,
        )
        assert len(results) == 1
        assert results[0]["signal_class"] == "qpsk"

    def test_query_sort_by_time_asc(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=433e6, timestamp="2026-02-10T00:00:00Z"),
            _make_anomaly(signal_class="qpsk", freq_hz=915e6, timestamp="2026-02-12T00:00:00Z"),
        ])
        results = store.get_rf_anomalies(min_score=0.0, sort_by="time", sort_order="asc")
        assert results[0]["timestamp"] <= results[1]["timestamp"]

    def test_query_sort_by_freq(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=915e6),
            _make_anomaly(signal_class="qpsk", freq_hz=100e6),
        ])
        results = store.get_rf_anomalies(min_score=0.0, sort_by="freq", sort_order="asc")
        assert results[0]["freq_hz"] <= results[1]["freq_hz"]

    def test_query_sort_by_seen(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=433e6),
        ])
        # Insert again to bump seen_count
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=433e6),
        ])
        store.insert_rf_anomalies_batch([
            _make_anomaly(signal_class="qpsk", freq_hz=915e6),
        ])
        results = store.get_rf_anomalies(min_score=0.0, sort_by="seen", sort_order="desc")
        assert results[0]["seen_count"] >= results[1]["seen_count"]

    def test_query_include_dismissed(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([_make_anomaly()])
        store.dismiss_rf_anomaly(ids[0])
        # Excluded by default
        assert len(store.get_rf_anomalies(min_score=0.0)) == 0
        # Included when requested
        assert len(store.get_rf_anomalies(min_score=0.0, include_dismissed=True)) == 1


# ---------------------------------------------------------------------------
# Count tests
# ---------------------------------------------------------------------------

class TestCountRfAnomalies:
    """count_rf_anomalies with various filters."""

    def test_count_basic(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=433e6),
            _make_anomaly(signal_class="qpsk", freq_hz=915e6),
        ])
        assert store.count_rf_anomalies(min_score=0.0) == 2

    def test_count_with_node_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(node_id="node-a", freq_hz=433e6),
            _make_anomaly(node_id="node-b", signal_class="qpsk", freq_hz=915e6),
        ])
        assert store.count_rf_anomalies(min_score=0.0, node_id="node-a") == 1

    def test_count_with_family_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(family="psk", freq_hz=433e6),
            _make_anomaly(family="qam", signal_class="16qam", freq_hz=915e6),
        ])
        assert store.count_rf_anomalies(min_score=0.0, family="qam") == 1

    def test_count_with_signal_class_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(signal_class="bpsk", freq_hz=433e6),
            _make_anomaly(signal_class="qpsk", freq_hz=915e6),
        ])
        assert store.count_rf_anomalies(min_score=0.0, signal_class="bpsk") == 1

    def test_count_with_priority_filter(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(anomaly_score=0.8, freq_hz=433e6),   # critical
            _make_anomaly(anomaly_score=0.4, signal_class="qpsk", freq_hz=915e6),   # interesting
        ])
        assert store.count_rf_anomalies(min_score=0.0, priority="critical") == 1

    def test_count_with_freq_range(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=100e6),
            _make_anomaly(signal_class="qpsk", freq_hz=500e6),
        ])
        assert store.count_rf_anomalies(min_score=0.0, freq_min_hz=400e6) == 1
        assert store.count_rf_anomalies(min_score=0.0, freq_max_hz=200e6) == 1

    def test_count_excludes_dismissed_by_default(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([_make_anomaly()])
        store.dismiss_rf_anomaly(ids[0])
        assert store.count_rf_anomalies(min_score=0.0) == 0
        assert store.count_rf_anomalies(min_score=0.0, include_dismissed=True) == 1


# ---------------------------------------------------------------------------
# Summary tests
# ---------------------------------------------------------------------------

class TestGetRfAnomalySummary:
    """get_rf_anomaly_summary returns correct aggregation."""

    def test_summary_empty(self, store: DetectionStore):
        summary = store.get_rf_anomaly_summary(min_score=0.0)
        assert summary["total"] == 0
        assert summary["by_priority"] == {}
        assert summary["by_family"] == []
        assert summary["by_band"] == []
        assert summary["by_node"] == []
        assert summary["unique_classes"] == []
        assert summary["unique_families"] == []
        assert summary["unique_nodes"] == []

    def test_summary_with_data(self, store: DetectionStore):
        store.insert_rf_anomalies_batch([
            _make_anomaly(signal_class="bpsk", family="psk", freq_hz=433.92e6,
                          anomaly_score=0.8, node_id="node-a"),
            _make_anomaly(signal_class="qpsk", family="psk", freq_hz=915e6,
                          anomaly_score=0.5, node_id="node-a"),
            _make_anomaly(signal_class="16qam", family="qam", freq_hz=2400e6,
                          anomaly_score=0.4, node_id="node-b"),
        ])
        summary = store.get_rf_anomaly_summary(min_score=0.0)
        assert summary["total"] == 3
        assert isinstance(summary["by_priority"], dict)
        assert summary["by_priority"]["critical"] >= 1
        assert len(summary["by_family"]) == 2
        assert all(isinstance(f, dict) for f in summary["by_family"])
        assert len(summary["by_node"]) == 2
        assert all(isinstance(n, dict) for n in summary["by_node"])
        assert "bpsk" in summary["unique_classes"]
        assert "psk" in summary["unique_families"]
        assert "node-a" in summary["unique_nodes"]


# ---------------------------------------------------------------------------
# Snooze tests
# ---------------------------------------------------------------------------

class TestSnooze:
    """Snooze operations on RF anomalies."""

    def test_snooze_single(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([_make_anomaly()])
        far_future = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        store.snooze_rf_anomaly(ids[0], until=far_future)
        # Snoozed anomalies should be excluded from default query
        results = store.get_rf_anomalies(min_score=0.0)
        assert len(results) == 0

    def test_snooze_bulk(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([
            _make_anomaly(freq_hz=433e6),
            _make_anomaly(signal_class="qpsk", freq_hz=915e6),
        ])
        far_future = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        updated = store.snooze_rf_anomalies_bulk(ids, until=far_future)
        assert updated == 2
        # Both snoozed, so neither in default query
        assert len(store.get_rf_anomalies(min_score=0.0)) == 0

    def test_snooze_bulk_empty(self, store: DetectionStore):
        assert store.snooze_rf_anomalies_bulk([], until="2030-01-01T00:00:00Z") == 0

    def test_expired_snooze_reappears(self, store: DetectionStore):
        ids = store.insert_rf_anomalies_batch([_make_anomaly()])
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
        store.snooze_rf_anomaly(ids[0], until=past)
        # Expired snooze => anomaly is active again
        results = store.get_rf_anomalies(min_score=0.0)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# Cleanup tests
# ---------------------------------------------------------------------------

class TestCleanup:
    """cleanup_rf_anomalies removes old records."""

    def test_cleanup_removes_old(self, store: DetectionStore):
        old_ts = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        store.insert_rf_anomalies_batch([
            _make_anomaly(timestamp=old_ts),
        ])
        deleted = store.cleanup_rf_anomalies(max_age_days=7)
        assert deleted == 1
        assert store.count_rf_anomalies(min_score=0.0, include_dismissed=True) == 0

    def test_cleanup_keeps_recent(self, store: DetectionStore):
        recent_ts = datetime.now(timezone.utc).isoformat()
        store.insert_rf_anomalies_batch([
            _make_anomaly(timestamp=recent_ts),
        ])
        deleted = store.cleanup_rf_anomalies(max_age_days=7)
        assert deleted == 0
        assert store.count_rf_anomalies(min_score=0.0) == 1


# ---------------------------------------------------------------------------
# Auto-snooze tests
# ---------------------------------------------------------------------------

class TestAutoSnooze:
    """Auto-snooze triggers when seen_count threshold is reached."""

    def test_auto_snooze_triggers(self, store: DetectionStore):
        # First insert: seen_count=1
        store.insert_rf_anomalies_batch(
            [_make_anomaly(anomaly_score=0.4)],
            auto_snooze_seen_count=3,
            auto_snooze_max_score=0.5,
            auto_snooze_hours=1,
        )
        assert store.count_rf_anomalies(min_score=0.0) == 1  # visible

        # Second insert: seen_count=2
        store.insert_rf_anomalies_batch(
            [_make_anomaly(anomaly_score=0.4)],
            auto_snooze_seen_count=3,
            auto_snooze_max_score=0.5,
            auto_snooze_hours=1,
        )
        assert store.count_rf_anomalies(min_score=0.0) == 1  # still visible

        # Third insert: seen_count=3 => auto-snoozed
        store.insert_rf_anomalies_batch(
            [_make_anomaly(anomaly_score=0.4)],
            auto_snooze_seen_count=3,
            auto_snooze_max_score=0.5,
            auto_snooze_hours=1,
        )
        # Should be snoozed and therefore excluded
        assert store.count_rf_anomalies(min_score=0.0) == 0

    def test_auto_snooze_skipped_high_score(self, store: DetectionStore):
        """High-scoring anomalies are NOT auto-snoozed."""
        for _ in range(3):
            store.insert_rf_anomalies_batch(
                [_make_anomaly(anomaly_score=0.8)],
                auto_snooze_seen_count=2,
                auto_snooze_max_score=0.5,
                auto_snooze_hours=1,
            )
        # score 0.8 > max_score 0.5 => no snooze
        assert store.count_rf_anomalies(min_score=0.0) == 1
