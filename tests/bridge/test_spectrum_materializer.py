"""Tests for spectrum_materialized table and SpectrumMaterializer."""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.spectrum_materializer import SpectrumMaterializer


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    return SharedContext(db_path=tmp_path / "test_mat.db")


@pytest.fixture
def materializer(ctx: SharedContext) -> SpectrumMaterializer:
    mat = SpectrumMaterializer(ctx, refresh_interval_sec=60)
    mat.create_table()
    return mat


def _insert_detection(ctx: SharedContext, ts: str, freq: float = 433.92e6,
                       signal_class: str = "bpsk", node_id: str = "n1") -> str:
    import uuid
    det_id = str(uuid.uuid4())
    conn = ctx.get_conn()
    conn.execute(
        "INSERT INTO detections (detection_id, node_id, timestamp, signal_class, "
        "confidence, freq_hz, tenant_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (det_id, node_id, ts, signal_class, 0.9, freq, ctx.tenant_id),
    )
    conn.commit()
    return det_id


def _insert_wifi(ctx: SharedContext, ts: str, channel: int = 6,
                  signal_dbm: float = -50.0, node_id: str = "n1") -> None:
    import uuid
    conn = ctx.get_conn()
    conn.execute(
        "INSERT INTO wifi_metadata (detection_id, bssid, ssid, channel, "
        "signal_dbm, timestamp, node_id, tenant_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), "aa:bb:cc:dd:ee:ff", "TestNet", channel,
         signal_dbm, ts, node_id, ctx.tenant_id),
    )
    conn.commit()


class TestCreateTable:
    def test_table_created(self, ctx, materializer):
        conn = ctx.get_conn()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='spectrum_materialized'"
        ).fetchone()
        assert row is not None
        assert row["name"] == "spectrum_materialized"

    def test_idempotent(self, ctx, materializer):
        materializer.create_table()
        materializer.create_table()
        row = ctx.get_conn().execute(
            "SELECT COUNT(*) FROM spectrum_materialized"
        ).fetchone()
        assert row[0] == 0


class TestFullRefresh:
    def test_empty_source(self, ctx, materializer):
        count = materializer.full_refresh()
        assert count == 0

    def test_populates_from_detections(self, ctx, materializer):
        ts = _utcnow()
        _insert_detection(ctx, ts, freq=433.92e6)
        _insert_detection(ctx, ts, freq=915e6, signal_class="qam16")

        count = materializer.full_refresh()
        assert count == 2

        rows = ctx.get_conn().execute(
            "SELECT * FROM spectrum_materialized"
        ).fetchall()
        assert len(rows) == 2

    def test_includes_wifi(self, ctx, materializer):
        ts = _utcnow()
        _insert_wifi(ctx, ts, channel=6, signal_dbm=-45.0)

        count = materializer.full_refresh()
        assert count == 1

        row = ctx.get_conn().execute(
            "SELECT signal_class, power_dbm FROM spectrum_materialized"
        ).fetchone()
        assert row["signal_class"] == "wifi"
        assert row["power_dbm"] == -45.0

    def test_full_refresh_truncates(self, ctx, materializer):
        ts = _utcnow()
        _insert_detection(ctx, ts)
        materializer.full_refresh()

        _insert_detection(ctx, ts, freq=915e6, signal_class="qam16")
        count = materializer.full_refresh()
        # After full refresh, should have exactly 2 rows (not 3)
        total = ctx.get_conn().execute(
            "SELECT COUNT(*) FROM spectrum_materialized"
        ).fetchone()[0]
        assert total == 2


class TestIncrementalRefresh:
    def test_first_refresh_gets_all(self, ctx, materializer):
        ts = _utcnow()
        _insert_detection(ctx, ts)
        count = materializer.refresh()
        assert count == 1

    def test_second_refresh_only_new(self, ctx, materializer):
        ts1 = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        _insert_detection(ctx, ts1)
        materializer.refresh()

        ts2 = _utcnow()
        _insert_detection(ctx, ts2, freq=915e6, signal_class="qam16")
        count = materializer.refresh()
        assert count == 1

        total = ctx.get_conn().execute(
            "SELECT COUNT(*) FROM spectrum_materialized"
        ).fetchone()[0]
        assert total == 2

    def test_no_new_data(self, ctx, materializer):
        ts = _utcnow()
        _insert_detection(ctx, ts)
        materializer.refresh()

        count = materializer.refresh()
        assert count == 0


class TestWatermark:
    def test_watermark_updated_after_refresh(self, ctx, materializer):
        assert materializer._last_watermark is None
        ts = _utcnow()
        _insert_detection(ctx, ts)
        materializer.refresh()
        assert materializer._last_watermark is not None
        assert isinstance(materializer._last_watermark, str)

    def test_watermark_tracks_max_timestamp(self, ctx, materializer):
        ts_old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        ts_new = _utcnow()
        _insert_detection(ctx, ts_old)
        _insert_detection(ctx, ts_new, freq=915e6)
        materializer.refresh()
        # Watermark should be >= ts_new
        assert materializer._last_watermark >= ts_old


class TestStatus:
    def test_initial_status(self, ctx, materializer):
        status = materializer.status()
        assert status["running"] is False
        assert status["refresh_count"] == 0
        assert status["current_row_count"] == 0
        assert status["last_watermark"] is None

    def test_status_after_refresh(self, ctx, materializer):
        _insert_detection(ctx, _utcnow())
        materializer.refresh()

        status = materializer.status()
        assert status["refresh_count"] == 1
        assert status["total_rows_inserted"] == 1
        assert status["current_row_count"] == 1
        assert status["last_refresh_at"] is not None
        assert isinstance(status["last_refresh_at"], str)

    def test_status_after_full_refresh(self, ctx, materializer):
        _insert_detection(ctx, _utcnow())
        _insert_detection(ctx, _utcnow(), freq=915e6)
        materializer.full_refresh()

        status = materializer.status()
        assert status["refresh_count"] == 1
        assert status["total_rows_inserted"] == 2
        assert status["current_row_count"] == 2


class TestPeriodicControl:
    def test_stop_sets_flag(self, ctx, materializer):
        materializer._running = True
        materializer.stop()
        assert materializer._running is False
