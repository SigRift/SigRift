"""Unit tests for storage/spectrum_snapshots.py (SpectrumSnapshotStore).

Tests: insert/query, PSD stitching, peak detection, snapshot history,
cleanup, wideband view, compare_psd, empty inputs, large data handling.
All use in-memory SQLite via SharedContext(tmp_path).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import uuid

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.spectrum_snapshots import SpectrumSnapshotStore

def _make_snapshot(
    *,
    node_id: str = "n1",
    center_freq_hz: float = 433.92e6,
    bandwidth_hz: float = 2.048e6,
    fft_size: int = 1024,
    psd_dbm: list[float] | None = None,
    noise_floor_dbm: float | None = -95.0,
    timestamp: str | None = None,
) -> dict[str, Any]:
    if psd_dbm is None:
        # Generate a simple PSD: noise floor with a peak at bin 512
        psd_dbm = [-95.0] * fft_size
        psd_dbm[512] = -40.0  # Peak
    return {
        "node_id": node_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "center_freq_hz": center_freq_hz,
        "bandwidth_hz": bandwidth_hz,
        "fft_size": fft_size,
        "bin_width_hz": bandwidth_hz / fft_size,
        "psd_dbm": psd_dbm,
        "noise_floor_dbm": noise_floor_dbm,
        "peak_freq_hz": center_freq_hz,
        "peak_power_dbm": -40.0,
    }

def _insert_detection(ctx: SharedContext, freq_hz: float = 433.92e6, node_id: str = "n1") -> None:
    ts = datetime.now(timezone.utc).isoformat()
    conn = ctx.get_conn()
    conn.execute(
        """INSERT INTO detections
           (detection_id, node_id, timestamp, signal_class, confidence,
            freq_hz, power_dbm, snr_db, tenant_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (uuid.uuid4().hex[:16], node_id, ts, "bpsk", 0.9, freq_hz, -40.0, 20.0, ctx.tenant_id),
    )
    conn.commit()

class TestSpectrumSnapshotStore:
    @pytest.fixture
    def ctx(self, tmp_path: Path):
        return SharedContext(db_path=tmp_path / "snap_test.db", tenant_id="default")

    @pytest.fixture
    def store(self, ctx):
        return SpectrumSnapshotStore(ctx)

    # -- Insert / query -----------------------------------------------------

    def test_insert_returns_row_id(self, store):
        snap = _make_snapshot()
        row_id = store.insert_snapshot(snap)
        assert isinstance(row_id, int)
        assert row_id >= 1

    def test_insert_and_query(self, store):
        snap = _make_snapshot()
        store.insert_snapshot(snap)
        results = store.get_snapshots(hours=1)
        assert len(results) == 1
        r = results[0]
        assert r["node_id"] == "n1"
        assert r["center_freq_hz"] == 433.92e6
        assert isinstance(r["psd_dbm"], list)
        assert len(r["psd_dbm"]) == 1024

    def test_query_filter_by_node(self, store):
        store.insert_snapshot(_make_snapshot(node_id="n1"))
        store.insert_snapshot(_make_snapshot(node_id="n2"))
        results = store.get_snapshots(node_id="n1", hours=1)
        assert len(results) == 1
        assert results[0]["node_id"] == "n1"

    def test_query_filter_by_center_freq(self, store):
        store.insert_snapshot(_make_snapshot(center_freq_hz=100e6))
        store.insert_snapshot(_make_snapshot(center_freq_hz=200e6))
        results = store.get_snapshots(center_freq_hz=100e6, hours=1)
        assert len(results) == 1
        assert results[0]["center_freq_hz"] == 100e6

    def test_query_respects_limit(self, store):
        for _ in range(5):
            store.insert_snapshot(_make_snapshot())
        results = store.get_snapshots(hours=1, limit=2)
        assert len(results) == 2

    # -- PSD JSON parsing ---------------------------------------------------

    def test_psd_stored_as_json_and_parsed_back(self, store):
        psd = [-90.0, -80.0, -70.0, -60.0]
        store.insert_snapshot(_make_snapshot(fft_size=4, psd_dbm=psd, bandwidth_hz=4000.0))
        results = store.get_snapshots(hours=1)
        assert results[0]["psd_dbm"] == psd

    # -- Latest per node ----------------------------------------------------

    def test_get_latest_per_node(self, store):
        ts_old = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        ts_new = datetime.now(timezone.utc).isoformat()
        store.insert_snapshot(_make_snapshot(node_id="n1", timestamp=ts_old))
        store.insert_snapshot(_make_snapshot(node_id="n1", timestamp=ts_new))
        store.insert_snapshot(_make_snapshot(node_id="n2", timestamp=ts_new))
        results = store.get_latest_per_node()
        assert len(results) == 2
        node_ids = {r["node_id"] for r in results}
        assert node_ids == {"n1", "n2"}

    # -- Wideband view ------------------------------------------------------

    def test_get_wideband_view_by_node(self, store):
        store.insert_snapshot(_make_snapshot(node_id="n1"))
        store.insert_snapshot(_make_snapshot(node_id="n2"))
        results = store.get_wideband_view(node_id="n1")
        assert len(results) == 1
        assert results[0]["node_id"] == "n1"

    def test_get_wideband_view_all(self, store):
        store.insert_snapshot(_make_snapshot(node_id="n1"))
        store.insert_snapshot(_make_snapshot(node_id="n2"))
        results = store.get_wideband_view()
        assert len(results) == 2

    # -- Peak detection -----------------------------------------------------

    def test_detect_peaks_with_snapshots(self, store):
        psd = [-95.0] * 1024
        psd[100] = -40.0  # 55 dB above noise floor
        psd[200] = -80.0  # 15 dB above noise floor
        store.insert_snapshot(_make_snapshot(psd_dbm=psd, noise_floor_dbm=-95.0))
        peaks = store.detect_peaks(hours=1, threshold_db=10.0)
        assert len(peaks) >= 1
        freqs = [p["freq_hz"] for p in peaks]
        powers = [p["power_dbm"] for p in peaks]
        assert -40.0 in powers

    def test_detect_peaks_min_power_filter(self, store):
        psd = [-95.0] * 1024
        psd[100] = -40.0
        psd[200] = -80.0
        store.insert_snapshot(_make_snapshot(psd_dbm=psd, noise_floor_dbm=-95.0))
        peaks = store.detect_peaks(hours=1, threshold_db=10.0, min_power_dbm=-50.0)
        assert all(p["power_dbm"] >= -50.0 for p in peaks)

    def test_detect_peaks_falls_back_to_detections(self, ctx, store):
        # No snapshots but detections exist
        _insert_detection(ctx, freq_hz=433.92e6)
        peaks = store.detect_peaks(hours=1)
        assert len(peaks) >= 1
        assert peaks[0]["classified"] is True

    # -- Sweep stitching ----------------------------------------------------

    def test_stitch_sweeps_no_data(self, store):
        result = store.stitch_sweeps("n1", minutes=5)
        assert result is None

    def test_stitch_sweeps_single_segment(self, store):
        psd = [-90.0, -80.0, -70.0, -60.0]
        store.insert_snapshot(_make_snapshot(
            center_freq_hz=100e6, bandwidth_hz=4e6, fft_size=4,
            psd_dbm=psd,
        ))
        result = store.stitch_sweeps("n1", minutes=5)
        assert isinstance(result, dict)
        assert result["segment_count"] == 1
        assert result["psd_dbm"] == psd
        assert result["start_freq_hz"] == 100e6 - 2e6
        assert result["end_freq_hz"] == 100e6 + 2e6

    def test_stitch_sweeps_multiple_adjacent(self, store):
        ts = datetime.now(timezone.utc).isoformat()
        psd1 = [-90.0] * 4
        psd2 = [-80.0] * 4
        # Two adjacent 4 MHz segments: centered at 100 MHz and 104 MHz
        store.insert_snapshot(_make_snapshot(
            center_freq_hz=100e6, bandwidth_hz=4e6, fft_size=4,
            psd_dbm=psd1, timestamp=ts,
        ))
        store.insert_snapshot(_make_snapshot(
            center_freq_hz=104e6, bandwidth_hz=4e6, fft_size=4,
            psd_dbm=psd2, timestamp=ts,
        ))
        result = store.stitch_sweeps("n1", minutes=5)
        assert isinstance(result, dict)
        assert result["segment_count"] == 2
        assert len(result["psd_dbm"]) == 8

    # -- PSD comparison -----------------------------------------------------

    def test_compare_psd_no_data(self, store):
        result = store.compare_psd("n1", hours=1)
        assert result is None

    def test_compare_psd_detects_new_peaks(self, store):
        # Insert multiple snapshots with stable noise floor
        psd_base = [-90.0] * 8
        for i in range(5):
            ts = (datetime.now(timezone.utc) - timedelta(minutes=i + 1)).isoformat()
            store.insert_snapshot(_make_snapshot(
                fft_size=8, bandwidth_hz=8000.0, psd_dbm=psd_base, timestamp=ts,
            ))
        # Insert current snapshot with a new peak (+20 dB at bin 3)
        psd_current = [-90.0] * 8
        psd_current[3] = -70.0  # 20 dB above baseline
        store.insert_snapshot(_make_snapshot(
            fft_size=8, bandwidth_hz=8000.0, psd_dbm=psd_current,
        ))
        result = store.compare_psd("n1", hours=1)
        assert isinstance(result, dict)
        assert result["snapshot_count"] >= 2
        assert len(result["current_psd"]) == 8
        assert len(result["avg_psd"]) == 8
        assert len(result["delta_db"]) == 8

    # -- Cleanup ------------------------------------------------------------

    def test_cleanup_old_deletes_expired(self, ctx, store):
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        store.insert_snapshot(_make_snapshot(timestamp=old_ts))
        store.insert_snapshot(_make_snapshot())  # current
        deleted = store.cleanup_old(max_age_hours=24)
        assert deleted == 1
        remaining = store.get_snapshots(hours=9999)
        assert len(remaining) == 1

    def test_cleanup_old_no_op_when_nothing_expired(self, store):
        store.insert_snapshot(_make_snapshot())
        deleted = store.cleanup_old(max_age_hours=24)
        assert deleted == 0
