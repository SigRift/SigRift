"""Tests for AircraftStore sub-store."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.aircraft import AircraftStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def ctx(tmp_path):
    """SharedContext with a fresh DB for each test."""
    return SharedContext(db_path=tmp_path / "test_stores.db", tenant_id="default")


@pytest.fixture()
def aircraft_store(ctx):
    return AircraftStore(ctx)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _past_iso(seconds: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()


# ---------------------------------------------------------------------------
# AircraftStore tests
# ---------------------------------------------------------------------------


class TestAircraftStore:
    def test_insert_position(self, aircraft_store):
        row_id = aircraft_store.insert_position({
            "icao_address": "A1B2C3",
            "callsign": "UAL123",
            "source": "adsb",
            "lat": 37.7749,
            "lon": -122.4194,
            "altitude_ft": 35000.0,
            "velocity_kts": 450.0,
            "heading_deg": 270.0,
            "squawk": "1200",
            "rssi_dbm": -85.0,
            "node_id": "node-1",
            "timestamp": _now_iso(),
        })
        assert row_id is not None and row_id > 0

    def test_get_active_aircraft(self, aircraft_store):
        now = _now_iso()
        aircraft_store.insert_position({
            "icao_address": "A1B2C3",
            "callsign": "UAL123",
            "source": "adsb",
            "lat": 37.7749,
            "lon": -122.4194,
            "node_id": "node-1",
            "timestamp": now,
        })
        aircraft_store.insert_position({
            "icao_address": "D4E5F6",
            "callsign": "DAL456",
            "source": "uat",
            "lat": 34.0522,
            "lon": -118.2437,
            "node_id": "node-1",
            "timestamp": now,
        })
        active = aircraft_store.get_active_aircraft(max_age_seconds=60)
        assert len(active) == 2
        icaos = {a["icao_address"] for a in active}
        assert icaos == {"A1B2C3", "D4E5F6"}

    def test_get_active_aircraft_filters_stale(self, aircraft_store):
        # Insert an old position (10 minutes ago)
        old_ts = _past_iso(600)
        aircraft_store.insert_position({
            "icao_address": "STALE1",
            "source": "adsb",
            "node_id": "node-1",
            "timestamp": old_ts,
        })
        # Insert a recent position
        aircraft_store.insert_position({
            "icao_address": "FRESH1",
            "source": "adsb",
            "node_id": "node-1",
            "timestamp": _now_iso(),
        })
        active = aircraft_store.get_active_aircraft(max_age_seconds=60)
        assert len(active) == 1
        assert active[0]["icao_address"] == "FRESH1"

    def test_get_aircraft_history(self, aircraft_store):
        now = datetime.now(timezone.utc)
        for i in range(5):
            ts = (now - timedelta(minutes=i)).isoformat()
            aircraft_store.insert_position({
                "icao_address": "TRAIL1",
                "source": "adsb",
                "lat": 37.0 + i * 0.01,
                "lon": -122.0,
                "altitude_ft": 30000.0 + i * 1000,
                "node_id": "node-1",
                "timestamp": ts,
            })
        history = aircraft_store.get_aircraft_history("TRAIL1", hours=1)
        assert len(history) == 5
        # Ordered ASC by timestamp — oldest (largest i, furthest in past) first
        timestamps = [h["timestamp"] for h in history]
        assert timestamps == sorted(timestamps)

    def test_get_stats(self, aircraft_store):
        now = _now_iso()
        aircraft_store.insert_position({
            "icao_address": "A1", "source": "adsb", "node_id": "n1", "timestamp": now,
        })
        aircraft_store.insert_position({
            "icao_address": "A2", "source": "adsb", "node_id": "n1", "timestamp": now,
        })
        aircraft_store.insert_position({
            "icao_address": "A3", "source": "uat", "node_id": "n1", "timestamp": now,
        })
        stats = aircraft_store.get_stats()
        assert stats["total_active"] == 3
        assert stats["by_source"]["adsb"] == 2
        assert stats["by_source"]["uat"] == 1

    def test_cleanup_stale(self, aircraft_store):
        # Insert old and recent tracks
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        aircraft_store.insert_position({
            "icao_address": "OLD1", "source": "adsb", "node_id": "n1", "timestamp": old_ts,
        })
        aircraft_store.insert_position({
            "icao_address": "NEW1", "source": "adsb", "node_id": "n1", "timestamp": _now_iso(),
        })
        deleted = aircraft_store.cleanup_stale(max_age_hours=24)
        assert deleted == 1
        # Only the recent one should remain
        active = aircraft_store.get_active_aircraft(max_age_seconds=60)
        assert len(active) == 1
        assert active[0]["icao_address"] == "NEW1"


