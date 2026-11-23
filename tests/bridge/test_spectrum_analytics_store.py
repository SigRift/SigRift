"""Unit tests for storage/spectrum_analytics.py (SpectrumAnalyticsStore).

Tests: occupancy, waterfall, band summary, activity timeline, bandwidth
distribution, empty inputs, node_id filtering, and cache bypass.
All use in-memory SQLite via SharedContext(tmp_path).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import uuid

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.spectrum_analytics import (
    KNOWN_BANDS,
    SpectrumAnalyticsStore,
)

def _insert_detection(
    ctx: SharedContext,
    *,
    freq_hz: float = 433.92e6,
    signal_class: str = "bpsk",
    power_dbm: float = -50.0,
    node_id: str = "n1",
    timestamp: str | None = None,
    bandwidth_hz: float | None = None,
) -> None:
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    conn = ctx.get_conn()
    conn.execute(
        """INSERT INTO detections
           (detection_id, node_id, timestamp, signal_class, confidence,
            freq_hz, power_dbm, bandwidth_hz, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            uuid.uuid4().hex[:16],
            node_id,
            ts,
            signal_class,
            0.9,
            freq_hz,
            power_dbm,
            bandwidth_hz,
            ctx.tenant_id,
        ),
    )
    conn.commit()

class TestSpectrumAnalyticsStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "spec_analytics.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return SpectrumAnalyticsStore(ctx)

    # -- Occupancy ----------------------------------------------------------

    def test_get_occupancy_empty(self, store):
        result = store.get_occupancy(hours=1)
        assert result == []

    def test_get_occupancy_single_detection(self, ctx, store):
        _insert_detection(ctx, freq_hz=433.92e6, power_dbm=-45.0)
        result = store.get_occupancy(hours=1, bin_width_hz=1_000_000)
        assert len(result) >= 1
        entry = result[0]
        assert isinstance(entry["center_freq_hz"], (int, float))
        assert isinstance(entry["occupancy_pct"], (int, float))
        assert entry["signal_count"] >= 1
        assert entry["dominant_class"] == "bpsk"

    def test_get_occupancy_node_filter(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, node_id="n1")
        _insert_detection(ctx, freq_hz=100e6, node_id="n2")
        result_all = store.get_occupancy(hours=1, bin_width_hz=1_000_000)
        # Need to clear cache to get fresh results
        ctx.cache.invalidate()
        result_n1 = store.get_occupancy(hours=1, bin_width_hz=1_000_000, node_id="n1")
        assert len(result_all) >= 1
        assert len(result_n1) >= 1
        assert result_n1[0]["signal_count"] <= result_all[0]["signal_count"]

    def test_get_occupancy_multiple_bins(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, signal_class="bpsk")
        _insert_detection(ctx, freq_hz=200e6, signal_class="qpsk")
        result = store.get_occupancy(hours=1, bin_width_hz=1_000_000)
        assert len(result) == 2
        classes = {r["dominant_class"] for r in result}
        assert classes == {"bpsk", "qpsk"}

    # -- Waterfall ----------------------------------------------------------

    def test_get_waterfall_empty(self, store):
        result = store.get_waterfall(hours=1)
        assert result["time_bins"] == []
        assert result["freq_bins"] == []
        assert result["power_matrix"] == []

    def test_get_waterfall_with_data(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, power_dbm=-40.0)
        result = store.get_waterfall(hours=1, bin_width_hz=1_000_000)
        assert len(result["time_bins"]) >= 1
        assert len(result["freq_bins"]) >= 1
        assert len(result["power_matrix"]) >= 1

    def test_get_waterfall_freq_filter(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6)
        _insert_detection(ctx, freq_hz=500e6)
        result = store.get_waterfall(
            hours=1, freq_min_hz=90e6, freq_max_hz=110e6, bin_width_hz=1_000_000,
        )
        # Only the 100 MHz detection should be included
        assert len(result["freq_bins"]) >= 1
        for fb in result["freq_bins"]:
            assert fb <= 110e6

    # -- Band summary -------------------------------------------------------

    def test_get_band_summary_empty(self, store):
        result = store.get_band_summary(hours=1)
        assert len(result) == len(KNOWN_BANDS)
        for band in result:
            assert band["signal_count"] == 0
            assert band["occupancy_pct"] == 0.0

    def test_get_band_summary_with_detection(self, ctx, store):
        # Insert in "UHF 433 ISM" band (433.05 MHz - 434.79 MHz)
        _insert_detection(ctx, freq_hz=433.92e6, signal_class="ook", power_dbm=-55.0)
        result = store.get_band_summary(hours=1)
        ism_band = next(b for b in result if b["band"] == "UHF 433 ISM")
        assert ism_band["signal_count"] == 1
        assert ism_band["dominant_class"] == "ook"
        assert ism_band["avg_power_dbm"] is not None

    def test_get_band_summary_no_double_count(self, ctx, store):
        # UHF 433 ISM is within UHF 70cm Ham -- detection should only count once
        _insert_detection(ctx, freq_hz=433.92e6, signal_class="ook")
        result = store.get_band_summary(hours=1)
        ism_band = next(b for b in result if b["band"] == "UHF 433 ISM")
        ham_band = next(b for b in result if b["band"] == "UHF 70cm Ham")
        assert ism_band["signal_count"] == 1
        # Ham band should exclude what ISM already claimed
        assert ham_band["signal_count"] == 0

    # -- Activity timeline --------------------------------------------------

    def test_get_activity_empty(self, store):
        result = store.get_activity(hours=1)
        assert result == []

    def test_get_activity_with_detections(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, signal_class="bpsk", power_dbm=-40.0)
        _insert_detection(ctx, freq_hz=200e6, signal_class="qpsk", power_dbm=-50.0)
        result = store.get_activity(hours=1)
        assert len(result) == 2
        assert all(isinstance(r["timestamp"], str) and isinstance(r["freq_hz"], (int, float)) for r in result)

    def test_get_activity_respects_limit(self, ctx, store):
        for i in range(10):
            _insert_detection(ctx, freq_hz=100e6 + i * 1e6)
        result = store.get_activity(hours=1, limit=3)
        assert len(result) == 3

    def test_get_activity_node_filter(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, node_id="n1")
        _insert_detection(ctx, freq_hz=200e6, node_id="n2")
        result = store.get_activity(hours=1, node_id="n1")
        assert len(result) == 1
        assert result[0]["node_id"] == "n1"

    # -- Bandwidth distribution ---------------------------------------------

    def test_get_bandwidth_distribution_empty(self, store):
        result = store.get_bandwidth_distribution(hours=1)
        assert result == []

    def test_get_bandwidth_distribution_with_data(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, signal_class="bpsk", bandwidth_hz=25000.0)
        _insert_detection(ctx, freq_hz=100e6, signal_class="bpsk", bandwidth_hz=50000.0)
        _insert_detection(ctx, freq_hz=200e6, signal_class="qpsk", bandwidth_hz=100000.0)
        result = store.get_bandwidth_distribution(hours=1)
        assert len(result) == 2
        bpsk_entry = next(r for r in result if r["signal_class"] == "bpsk")
        assert bpsk_entry["detection_count"] == 2
        assert bpsk_entry["min_bandwidth_hz"] == 25000.0
        assert bpsk_entry["max_bandwidth_hz"] == 50000.0

    def test_get_bandwidth_distribution_excludes_null_bandwidth(self, ctx, store):
        _insert_detection(ctx, freq_hz=100e6, bandwidth_hz=None)
        result = store.get_bandwidth_distribution(hours=1)
        assert result == []
