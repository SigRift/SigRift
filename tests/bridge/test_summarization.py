"""Tests for server-side summarization: migration, endpoints, storage, background rollups."""

from __future__ import annotations

import os
os.environ.setdefault("BRIDGE_CSRF", "disabled")

import gzip
import hashlib
import json
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from sigrift.bridge.storage.base import SharedContext, _MIGRATIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hour(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:00:00Z")


# ---------------------------------------------------------------------------
# Migration 52
# ---------------------------------------------------------------------------


class TestMigration52:
    """Verify migration 52 creates summarization tables."""

    def test_migration_52_creates_tables(self, tmp_path: Path):
        ctx = SharedContext(tmp_path / "m52.db")
        conn = ctx.get_conn()
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        assert "detection_summaries_hourly" in tables
        assert "iq_capture_sessions" in tables
        assert "device_lifecycles_daily" in tables
        assert "fhss_event_summaries" in tables

    def test_migration_52_indexes(self, tmp_path: Path):
        ctx = SharedContext(tmp_path / "m52_idx.db")
        conn = ctx.get_conn()
        # The unique index should prevent duplicate (hour, node_id, signal_class, family, freq_bin)
        conn.execute(
            "INSERT INTO detection_summaries_hourly "
            "(hour, node_id, signal_class, family, freq_bin_hz, detection_count, tenant_id) "
            "VALUES ('2026-03-26T10:00:00Z', 'n1', 'bpsk', 'PSK', 433925000.0, 5, 'default')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO detection_summaries_hourly "
                "(hour, node_id, signal_class, family, freq_bin_hz, detection_count, tenant_id) "
                "VALUES ('2026-03-26T10:00:00Z', 'n1', 'bpsk', 'PSK', 433925000.0, 3, 'default')"
            )

    def test_migration_56_number(self):
        versions = [v for v, _d, _s in _MIGRATIONS]
        assert max(versions) == 56


# ---------------------------------------------------------------------------
# DetectionSummaryStore
# ---------------------------------------------------------------------------


class TestDetectionSummaryStore:
    """Tests for the DetectionSummaryStore sub-store."""

    @pytest.fixture
    def ctx(self, tmp_path: Path) -> SharedContext:
        return SharedContext(tmp_path / "summary.db")

    @pytest.fixture
    def store(self, ctx):
        from sigrift.bridge.storage.detection_summaries import DetectionSummaryStore
        return DetectionSummaryStore(ctx)

    def test_insert_summaries(self, store, ctx):
        now = _utcnow()
        summaries = [
            {
                "hour": _hour(now),
                "signal_class": "bpsk",
                "family": "PSK",
                "freq_bin_hz": 433925000.0,
                "detection_count": 10,
                "avg_confidence": 0.92,
                "min_confidence": 0.85,
                "max_confidence": 0.99,
                "avg_snr_db": 15.0,
                "avg_power_dbm": -65.0,
                "avg_anomaly": 0.1,
                "max_anomaly": 0.3,
            },
            {
                "hour": _hour(now),
                "signal_class": "qpsk",
                "family": "PSK",
                "freq_bin_hz": 915000000.0,
                "detection_count": 5,
                "avg_confidence": 0.88,
                "min_confidence": 0.80,
                "max_confidence": 0.95,
            },
        ]
        inserted = store.insert_summaries("node-1", summaries)
        assert inserted == 2

        conn = ctx.get_conn()
        rows = conn.execute("SELECT * FROM detection_summaries_hourly").fetchall()
        assert len(rows) == 2

    def test_insert_summaries_upsert(self, store, ctx):
        now = _utcnow()
        base = {
            "hour": _hour(now),
            "signal_class": "bpsk",
            "family": "PSK",
            "freq_bin_hz": 433925000.0,
            "detection_count": 5,
            "avg_confidence": 0.90,
            "min_confidence": 0.85,
            "max_confidence": 0.95,
        }
        store.insert_summaries("node-1", [base])

        updated = dict(base)
        updated["detection_count"] = 20
        updated["avg_confidence"] = 0.95
        store.insert_summaries("node-1", [updated])

        conn = ctx.get_conn()
        rows = conn.execute("SELECT * FROM detection_summaries_hourly").fetchall()
        assert len(rows) == 1
        assert dict(rows[0])["detection_count"] == 20

    def test_get_summaries_filters(self, store):
        now = _utcnow()
        summaries = [
            {
                "hour": _hour(now),
                "signal_class": "bpsk",
                "family": "PSK",
                "freq_bin_hz": 433925000.0,
                "detection_count": 10,
                "avg_confidence": 0.92,
                "min_confidence": 0.85,
                "max_confidence": 0.99,
            },
            {
                "hour": _hour(now),
                "signal_class": "qpsk",
                "family": "PSK",
                "freq_bin_hz": 915000000.0,
                "detection_count": 5,
                "avg_confidence": 0.88,
                "min_confidence": 0.80,
                "max_confidence": 0.95,
            },
            {
                "hour": _hour(now),
                "signal_class": "bpsk",
                "family": "PSK",
                "freq_bin_hz": 433925000.0,
                "detection_count": 3,
            },
        ]
        store.insert_summaries("node-1", summaries[:2])
        store.insert_summaries("node-2", summaries[2:])

        # Filter by node
        results = store.get_summaries(hours=24, node_id="node-1")
        assert len(results) == 2

        # Filter by signal_class
        results = store.get_summaries(hours=24, signal_class="qpsk")
        assert len(results) == 1
        assert results[0]["signal_class"] == "qpsk"

        # Filter by hours -- recent data should appear
        results = store.get_summaries(hours=1)
        assert len(results) >= 1

    def test_rollup_from_raw(self, ctx, store):
        conn = ctx.get_conn()
        # Insert raw detections directly
        now = _utcnow()
        past = now - timedelta(hours=2)
        for i in range(5):
            conn.execute(
                "INSERT INTO detections "
                "(detection_id, node_id, timestamp, signal_class, confidence, "
                " family, freq_hz, snr_db, power_dbm, anomaly_score, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"det-{i}", "node-1", _iso(past + timedelta(minutes=i)),
                    "bpsk", 0.9, "PSK", 433.92e6, 15.0, -65.0, 0.1, "default",
                ),
            )
        conn.commit()

        # Rollup with cutoff_hours=1 should capture detections older than 1 hour
        count = store.rollup_from_raw(cutoff_hours=1)
        assert count >= 1

        results = store.get_summaries(hours=48)
        assert len(results) >= 1
        assert results[0]["detection_count"] >= 1

    def test_cleanup_summaries(self, store, ctx):
        old_hour = (_utcnow() - timedelta(days=100)).strftime("%Y-%m-%dT%H:00:00Z")
        recent_hour = _hour(_utcnow())

        store.insert_summaries("node-1", [
            {"hour": old_hour, "signal_class": "bpsk", "family": "PSK",
             "freq_bin_hz": 433925000.0, "detection_count": 1},
            {"hour": recent_hour, "signal_class": "bpsk", "family": "PSK",
             "freq_bin_hz": 433925000.0, "detection_count": 5},
        ])

        deleted = store.cleanup_summaries(max_age_days=90)
        assert deleted >= 1

        conn = ctx.get_conn()
        remaining = conn.execute(
            "SELECT COUNT(*) FROM detection_summaries_hourly"
        ).fetchone()[0]
        assert remaining == 1

    def test_empty_insert(self, store):
        assert store.insert_summaries("node-1", []) == 0


# ---------------------------------------------------------------------------
# Detection summary endpoint tests (via TestClient)
# ---------------------------------------------------------------------------


class TestDetectionSummaryEndpoint:
    """API endpoint tests for /ingest-summary."""

    @pytest.fixture
    def client(self, bridge_app, master_key):
        from starlette.testclient import TestClient
        return TestClient(bridge_app, headers={"X-API-Key": master_key})

    @pytest.fixture
    def registered_node(self, client) -> str:
        node_id = "node-summary-01"
        resp = client.post("/api/nodes/register", json={
            "node_id": node_id, "host": "192.168.1.100", "port": 8080,
        })
        assert resp.status_code == 200
        return node_id

    def test_ingest_summary_happy_path(self, client, registered_node):
        now = _utcnow()
        payload = {
            "node_id": registered_node,
            "summaries": [
                {
                    "hour": _hour(now),
                    "signal_class": "bpsk",
                    "family": "PSK",
                    "freq_bin_hz": 433925000.0,
                    "detection_count": 10,
                    "avg_confidence": 0.92,
                    "min_confidence": 0.85,
                    "max_confidence": 0.99,
                },
            ],
        }
        resp = client.post("/api/detections/ingest-summary", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted_summaries"] == 1
        assert data["inserted_raw"] == 0

    def test_ingest_summary_with_high_anomaly(self, client, registered_node):
        now = _utcnow()
        payload = {
            "node_id": registered_node,
            "summaries": [
                {
                    "hour": _hour(now),
                    "signal_class": "bpsk",
                    "family": "PSK",
                    "freq_bin_hz": 433925000.0,
                    "detection_count": 10,
                    "avg_confidence": 0.92,
                    "min_confidence": 0.85,
                    "max_confidence": 0.99,
                },
            ],
            "high_anomaly_detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.95,
                    "anomaly_score": 0.9,
                    "freq_hz": 433.92e6,
                },
            ],
        }
        resp = client.post("/api/detections/ingest-summary", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted_summaries"] == 1
        assert data["inserted_raw"] >= 1

    def test_ingest_summary_unknown_node(self, client):
        payload = {
            "node_id": "nonexistent-node-xyz",
            "summaries": [
                {
                    "hour": _hour(_utcnow()),
                    "signal_class": "bpsk",
                    "family": "PSK",
                    "freq_bin_hz": 433925000.0,
                    "detection_count": 1,
                    "avg_confidence": 0.9,
                    "min_confidence": 0.9,
                    "max_confidence": 0.9,
                },
            ],
        }
        resp = client.post("/api/detections/ingest-summary", json=payload)
        assert resp.status_code == 404

    def test_ingest_summary_gzip(self, client, registered_node):
        now = _utcnow()
        payload = {
            "node_id": registered_node,
            "summaries": [
                {
                    "hour": _hour(now),
                    "signal_class": "ofdm",
                    "family": "OFDM",
                    "freq_bin_hz": 2437500000.0,
                    "detection_count": 20,
                    "avg_confidence": 0.88,
                    "min_confidence": 0.80,
                    "max_confidence": 0.95,
                },
            ],
        }
        compressed = gzip.compress(json.dumps(payload).encode())
        resp = client.post(
            "/api/detections/ingest-summary",
            content=compressed,
            headers={
                "X-API-Key": client.headers["X-API-Key"],
                "Content-Encoding": "gzip",
                "Content-Type": "application/json",
            },
        )
        assert resp.status_code == 201
        assert resp.json()["inserted_summaries"] == 1

    def test_ingest_summary_empty(self, client, registered_node):
        payload = {
            "node_id": registered_node,
            "summaries": [],
        }
        resp = client.post("/api/detections/ingest-summary", json=payload)
        assert resp.status_code == 201
        assert resp.json()["inserted_summaries"] == 0

    def test_raw_ingest_tracking(self, client, registered_node):
        from sigrift.bridge.routers.detections import get_raw_ingest_nodes

        now = _utcnow()
        batch = {
            "node_id": registered_node,
            "batch_id": "batch-track-01",
            "period_start": _iso(now - timedelta(minutes=5)),
            "period_end": _iso(now),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                },
            ],
        }
        resp = client.post("/api/detections/batch", json=batch)
        assert resp.status_code == 201

        raw_nodes = get_raw_ingest_nodes()
        assert registered_node in raw_nodes


# ---------------------------------------------------------------------------
# IQ Session Rollup
# ---------------------------------------------------------------------------


class TestIQSessionRollup:
    """Tests for IQ metadata session rollup."""

    @pytest.fixture
    def ctx(self, tmp_path: Path) -> SharedContext:
        return SharedContext(tmp_path / "iq_rollup.db")

    @pytest.fixture
    def iq_store(self, ctx):
        from sigrift.bridge.storage.iq_metadata import IQMetadataStore
        return IQMetadataStore(ctx)

    def _insert_iq_rows(self, ctx, node_id, count, hours_ago=2, quality_score=0.3):
        conn = ctx.get_conn()
        # Anchor to the start of the hour so the {hours_ago, hours_ago + count
        # minutes} span never straddles an hour boundary — sessions bucket by
        # hour, and a wall-clock-relative base flakes the rollup when "now"
        # is in the last `count` minutes of an hour.
        base = (_utcnow() - timedelta(hours=hours_ago)).replace(
            minute=0, second=0, microsecond=0
        )
        for i in range(count):
            ts = _iso(base + timedelta(minutes=i))
            conn.execute(
                "INSERT INTO iq_metadata "
                "(detection_id, node_id, freq_hz, signal_class, sample_rate, "
                " n_samples, file_size_bytes, quality_score, captured_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"iq-{uuid.uuid4().hex[:8]}", node_id, 433.92e6, "bpsk",
                 2.4e6, 1024, 8192, quality_score, ts),
            )
        conn.commit()

    def test_rollup_to_sessions(self, iq_store, ctx):
        self._insert_iq_rows(ctx, "node-1", 5, hours_ago=2)
        count = iq_store.rollup_to_sessions(cutoff_hours=1)
        assert count >= 1

        conn = ctx.get_conn()
        sessions = conn.execute("SELECT * FROM iq_capture_sessions").fetchall()
        assert len(sessions) >= 1
        s = dict(sessions[0])
        assert s["capture_count"] == 5
        assert s["node_id"] == "node-1"

    def test_cleanup_sessioned_metadata(self, iq_store, ctx):
        # Low quality -> should be cleaned
        self._insert_iq_rows(ctx, "node-1", 3, hours_ago=48, quality_score=0.3)
        # High quality -> should remain
        self._insert_iq_rows(ctx, "node-1", 2, hours_ago=48, quality_score=0.8)

        deleted = iq_store.cleanup_sessioned_metadata(max_age_hours=24)
        assert deleted == 3

        conn = ctx.get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM iq_metadata").fetchone()[0]
        assert remaining == 2

    def test_rollup_idempotent(self, iq_store, ctx):
        self._insert_iq_rows(ctx, "node-1", 5, hours_ago=2)
        count1 = iq_store.rollup_to_sessions(cutoff_hours=1)
        count2 = iq_store.rollup_to_sessions(cutoff_hours=1)
        # INSERT OR IGNORE means second run produces same or zero new rows
        assert count2 >= 0

        conn = ctx.get_conn()
        sessions = conn.execute("SELECT * FROM iq_capture_sessions").fetchall()
        # Should still be just one session, not duplicated
        assert len(sessions) == 1

    def test_session_id_format(self, iq_store, ctx):
        self._insert_iq_rows(ctx, "node-test", 3, hours_ago=2)
        iq_store.rollup_to_sessions(cutoff_hours=1)

        conn = ctx.get_conn()
        sessions = conn.execute("SELECT session_id FROM iq_capture_sessions").fetchall()
        assert len(sessions) >= 1
        session_id = sessions[0][0]
        assert session_id.startswith("node-test_")
        # Format: "{node_id}_{hour}"
        parts = session_id.split("_", 1)
        assert parts[0] == "node-test"


# ---------------------------------------------------------------------------
# Cross-correlation maintenance
# ---------------------------------------------------------------------------


class TestCorrelationMaintenance:
    """Tests for CorrelationMaintenanceStore."""

    @pytest.fixture
    def ctx(self, tmp_path: Path) -> SharedContext:
        return SharedContext(tmp_path / "corr_maint.db")

    @pytest.fixture
    def store(self, ctx):
        from sigrift.bridge.storage.correlation_maintenance import CorrelationMaintenanceStore
        return CorrelationMaintenanceStore(ctx)

    def _insert_correlations(self, ctx, count, days_ago=0):
        conn = ctx.get_conn()
        base = _utcnow() - timedelta(days=days_ago)
        for i in range(count):
            ts = _iso(base + timedelta(minutes=i))
            conn.execute(
                "INSERT INTO cross_correlations "
                "(source_a, source_a_id, source_b, source_b_id, "
                " freq_hz, time_delta_ms, correlation_type, node_id, timestamp, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("sdr", f"det-{i}", "wifi", f"wifi-{i}",
                 2.412e9, 50.0, "confirmed", "node-1", ts, "default"),
            )
        conn.commit()

    def test_prune_old(self, store, ctx):
        # Insert old correlations (>30 days ago)
        self._insert_correlations(ctx, 5, days_ago=40)
        # Insert recent correlations
        self._insert_correlations(ctx, 3, days_ago=0)

        pruned = store.prune_old(max_age_days=30)
        assert pruned == 5

        conn = ctx.get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM cross_correlations").fetchone()[0]
        assert remaining == 3

    def test_prune_low_score(self, store, ctx):
        # cross_correlations doesn't have a score column, so this should
        # silently return 0 (exception caught)
        self._insert_correlations(ctx, 3, days_ago=0)
        pruned = store.prune_low_score(min_score=0.3)
        assert pruned == 0

    def test_run_maintenance(self, store, ctx):
        self._insert_correlations(ctx, 5, days_ago=40)
        self._insert_correlations(ctx, 3, days_ago=0)

        results = store.run_maintenance(max_age_days=30, min_score=0.3)
        assert "pruned_old" in results
        assert "pruned_low_score" in results
        assert results["pruned_old"] == 5


# ---------------------------------------------------------------------------
# Device lifecycle
# ---------------------------------------------------------------------------


class TestDeviceLifecycle:
    """Tests for DeviceLifecycleStore."""

    @pytest.fixture
    def ctx(self, tmp_path: Path) -> SharedContext:
        return SharedContext(tmp_path / "lifecycle.db")

    @pytest.fixture
    def store(self, ctx):
        from sigrift.bridge.storage.device_lifecycle import DeviceLifecycleStore
        return DeviceLifecycleStore(ctx)

    def _insert_bt_devices(self, ctx, count, days_ago=0):
        conn = ctx.get_conn()
        base = _utcnow() - timedelta(days=days_ago)
        for i in range(count):
            ts = _iso(base + timedelta(minutes=i))
            conn.execute(
                "INSERT INTO bt_devices "
                "(device_addr, device_name, rssi_dbm, manufacturer, "
                " timestamp, node_id, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"AA:BB:CC:DD:EE:{i:02X}", f"Device-{i}", -65.0 + i,
                 "TestCorp", ts, "node-1", "default"),
            )
        conn.commit()

    def _insert_zigbee_devices(self, ctx, count, days_ago=0):
        conn = ctx.get_conn()
        base = _utcnow() - timedelta(days=days_ago)
        for i in range(count):
            ts = _iso(base + timedelta(minutes=i))
            conn.execute(
                "INSERT INTO zigbee_devices "
                "(ieee_addr, device_type, lqi, manufacturer, "
                " timestamp, node_id, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"0x00158D000{i:07X}", "router", 200 + i,
                 "Zigbee Corp", ts, "node-1", "default"),
            )
        conn.commit()

    def test_rollup_bt_daily(self, store, ctx):
        self._insert_bt_devices(ctx, 5)
        count = store.rollup_bt_daily()
        assert count >= 1

        conn = ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM device_lifecycles_daily WHERE device_type='bt'"
        ).fetchall()
        assert len(rows) >= 1

    def test_rollup_zigbee_daily(self, store, ctx):
        self._insert_zigbee_devices(ctx, 5)
        count = store.rollup_zigbee_daily()
        assert count >= 1

        conn = ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM device_lifecycles_daily WHERE device_type='zigbee'"
        ).fetchall()
        assert len(rows) >= 1

    def test_archive_old_devices(self, store, ctx):
        # Insert old + recent BT devices
        self._insert_bt_devices(ctx, 3, days_ago=10)
        self._insert_bt_devices(ctx, 2, days_ago=0)

        results = store.archive_old_devices(bt_max_age_days=7, zb_max_age_days=7)
        assert results["archived_bt"] == 3

        conn = ctx.get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM bt_devices").fetchone()[0]
        assert remaining == 2

    def test_cleanup_lifecycles(self, store, ctx):
        conn = ctx.get_conn()
        old_date = (_utcnow() - timedelta(days=100)).strftime("%Y-%m-%d")
        recent_date = _utcnow().strftime("%Y-%m-%d")

        conn.execute(
            "INSERT INTO device_lifecycles_daily "
            "(date, node_id, device_type, device_id, first_seen, last_seen, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (old_date, "node-1", "bt", "AA:BB:CC:DD:EE:00",
             "2025-01-01T00:00:00Z", "2025-01-01T01:00:00Z", "default"),
        )
        conn.execute(
            "INSERT INTO device_lifecycles_daily "
            "(date, node_id, device_type, device_id, first_seen, last_seen, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (recent_date, "node-1", "bt", "AA:BB:CC:DD:EE:01",
             _iso(_utcnow()), _iso(_utcnow()), "default"),
        )
        conn.commit()

        deleted = store.cleanup_lifecycles(max_age_days=90)
        assert deleted >= 1

        remaining = conn.execute(
            "SELECT COUNT(*) FROM device_lifecycles_daily"
        ).fetchone()[0]
        assert remaining == 1

    def test_run_daily_rollup(self, store, ctx):
        self._insert_bt_devices(ctx, 3)
        self._insert_zigbee_devices(ctx, 2)
        results = store.run_daily_rollup()
        assert "bt_lifecycles" in results
        assert "zigbee_lifecycles" in results
        assert results["bt_lifecycles"] >= 1
        assert results["zigbee_lifecycles"] >= 1


# ---------------------------------------------------------------------------
# FHSS dedup
# ---------------------------------------------------------------------------


class TestFHSSDedup:
    """Tests for FHSS event deduplication and summarization."""

    @pytest.fixture
    def ctx(self, tmp_path: Path) -> SharedContext:
        return SharedContext(tmp_path / "fhss_dedup.db")

    @pytest.fixture
    def store(self, ctx):
        from sigrift.bridge.storage.fhss_store import FHSSStore
        return FHSSStore(ctx)

    def _insert_fhss_events(self, ctx, count, days_ago=0, hop_set=None):
        if hop_set is None:
            hop_set = [433.0e6, 434.0e6, 435.0e6]
        conn = ctx.get_conn()
        base = _utcnow() - timedelta(days=days_ago)
        for i in range(count):
            ts = _iso(base + timedelta(minutes=i))
            conn.execute(
                "INSERT INTO fhss_events "
                "(fhss_id, node_id, timestamp, hop_rate_hz, hop_set, "
                " bandwidth_hz, dwell_time_ms, duration_sec, signal_class, "
                " detection_count, confidence, tenant_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (f"fhss-{uuid.uuid4().hex[:8]}", "node-1", ts, 50.0,
                 json.dumps(hop_set), 500000.0, 10.0, 30.0,
                 "2fsk", 5, 0.85, "default"),
            )
        conn.commit()

    def test_dedup_to_summaries(self, store, ctx):
        self._insert_fhss_events(ctx, 5)
        count = store.dedup_to_summaries()
        assert count >= 1

        conn = ctx.get_conn()
        summaries = conn.execute("SELECT * FROM fhss_event_summaries").fetchall()
        assert len(summaries) >= 1
        s = dict(summaries[0])
        assert s["occurrence_count"] >= 1
        assert s["hop_set_hash"] != ""
        assert len(s["hop_set_hash"]) == 16

    def test_cleanup_raw_fhss(self, store, ctx):
        self._insert_fhss_events(ctx, 5, days_ago=10)
        self._insert_fhss_events(ctx, 3, days_ago=0)

        deleted = store.cleanup_raw_fhss(max_age_days=7)
        assert deleted == 5

        conn = ctx.get_conn()
        remaining = conn.execute("SELECT COUNT(*) FROM fhss_events").fetchone()[0]
        assert remaining == 3

    def test_hop_set_hash(self, store, ctx):
        hop_set = [433.0e6, 434.0e6, 435.0e6]
        self._insert_fhss_events(ctx, 2, hop_set=hop_set)
        self._insert_fhss_events(ctx, 2, hop_set=hop_set)

        store.dedup_to_summaries()
        conn = ctx.get_conn()
        summaries = conn.execute("SELECT * FROM fhss_event_summaries").fetchall()
        # Same hop_set should produce same hash, resulting in one summary row
        hashes = {dict(s)["hop_set_hash"] for s in summaries}
        assert len(hashes) == 1

        # Verify the hash is deterministic
        expected = hashlib.sha256(
            json.dumps(sorted(hop_set)).encode()
        ).hexdigest()[:16]
        assert hashes.pop() == expected

    def test_cleanup_fhss_summaries(self, store, ctx):
        # Insert old summaries directly
        conn = ctx.get_conn()
        old_time = (_utcnow() - timedelta(days=100)).strftime("%Y-%m-%dT%H:00:00Z")
        conn.execute(
            "INSERT INTO fhss_event_summaries "
            "(window_start, node_id, hop_rate_hz, hop_set_hash, bandwidth_hz, "
            " signal_class, occurrence_count, first_seen, last_seen, tenant_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (old_time, "node-1", 50.0, "abc123", 500000.0,
             "2fsk", 5, old_time, old_time, "default"),
        )
        conn.commit()

        deleted = store.cleanup_fhss_summaries(max_age_days=90)
        assert deleted >= 1


# ---------------------------------------------------------------------------
# Ingest status endpoint
# ---------------------------------------------------------------------------


class TestIngestStatus:
    """Tests for the /ingest-status endpoint."""

    @pytest.fixture
    def client(self, bridge_app, master_key):
        from starlette.testclient import TestClient
        return TestClient(bridge_app, headers={"X-API-Key": master_key})

    @pytest.fixture
    def registered_node(self, client) -> str:
        node_id = "node-ingest-status-01"
        resp = client.post("/api/nodes/register", json={
            "node_id": node_id, "host": "192.168.1.200", "port": 8080,
        })
        assert resp.status_code == 200
        return node_id

    def test_ingest_status_endpoint(self, client):
        resp = client.get("/api/detections/ingest-status")
        assert resp.status_code == 200
        data = resp.json()
        assert "raw_ingest_nodes" in data
        assert "summary_ingest_nodes" in data

    def test_raw_ingest_warning(self, client, registered_node):
        from sigrift.bridge.routers.detections import get_raw_ingest_nodes

        now = _utcnow()
        batch = {
            "node_id": registered_node,
            "batch_id": "batch-status-01",
            "period_start": _iso(now - timedelta(minutes=5)),
            "period_end": _iso(now),
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                },
            ],
        }
        client.post("/api/detections/batch", json=batch)

        raw_nodes = get_raw_ingest_nodes()
        assert registered_node in raw_nodes

        resp = client.get("/api/detections/ingest-status")
        assert resp.status_code == 200
        data = resp.json()
        assert registered_node in data["raw_ingest_nodes"]
