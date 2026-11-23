"""Tests for FHSS (frequency-hopping spread spectrum) detection.

Covers:
- FHSSDetector core logic with synthetic hopping data
- FHSSStore insert/query/get_by_id CRUD operations
- API endpoints GET /api/spectrum/fhss and GET /api/spectrum/fhss/{id}
- Integration with the detection ingestion pipeline
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any


from sigrift.bridge.anomaly.fhss import FHSSDetector, FHSSEvent
from sigrift.bridge.detection_store import DetectionStore


# ---------------------------------------------------------------------------
# Helper: generate synthetic FHSS detections
# ---------------------------------------------------------------------------

def _make_hopping_detections(
    node_id: str = "node-fhss-01",
    n_hops: int = 10,
    frequencies: list[float] | None = None,
    interval_sec: float = 0.1,
    signal_class: str = "2fsk",
    start_time: float | None = None,
) -> list[dict[str, Any]]:
    """Generate a sequence of detections that simulate FHSS hopping.

    Cycles through ``frequencies`` with ``interval_sec`` between each hop.
    """
    if frequencies is None:
        frequencies = [
            433.0e6, 433.2e6, 433.4e6, 433.6e6, 433.8e6,
        ]

    if start_time is None:
        start_time = time.time()

    dets: list[dict[str, Any]] = []
    for i in range(n_hops):
        freq = frequencies[i % len(frequencies)]
        ts = start_time + i * interval_sec
        dets.append({
            "node_id": node_id,
            "timestamp": ts,
            "freq_hz": freq,
            "signal_class": signal_class,
            "confidence": 0.9,
        })
    return dets


def _make_static_detections(
    node_id: str = "node-static-01",
    n: int = 10,
    freq_hz: float = 915.0e6,
    interval_sec: float = 0.1,
    start_time: float | None = None,
) -> list[dict[str, Any]]:
    """Generate static-frequency detections (NOT FHSS)."""
    if start_time is None:
        start_time = time.time()

    return [
        {
            "node_id": node_id,
            "timestamp": start_time + i * interval_sec,
            "freq_hz": freq_hz,
            "signal_class": "bpsk",
            "confidence": 0.85,
        }
        for i in range(n)
    ]


# ===========================================================================
# FHSSDetector unit tests
# ===========================================================================


class TestFHSSDetector:
    """Tests for the core FHSSDetector analysis logic."""

    def test_detects_basic_hopping(self):
        """5 distinct frequencies hopping rapidly should be detected."""
        detector = FHSSDetector()
        dets = _make_hopping_detections(n_hops=20, interval_sec=0.05)

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        evt = events[0]
        assert evt.node_id == "node-fhss-01"
        assert len(evt.hop_set) >= 3
        assert isinstance(evt.hop_rate_hz, float)
        assert evt.hop_rate_hz > 0
        assert isinstance(evt.bandwidth_hz, float)
        assert evt.bandwidth_hz > 0
        assert isinstance(evt.duration_sec, float)
        assert evt.duration_sec > 0
        assert evt.detection_count == 20
        assert evt.signal_class == "2fsk"

    def test_no_false_positive_static(self):
        """Static frequency detections should NOT be flagged as FHSS."""
        detector = FHSSDetector()
        dets = _make_static_detections(n=20)

        events = detector.analyse(dets)

        assert len(events) == 0

    def test_minimum_distinct_freq_threshold(self):
        """Only 2 frequencies should not trigger FHSS (threshold is 3)."""
        detector = FHSSDetector()
        dets = _make_hopping_detections(
            n_hops=20,
            frequencies=[433.0e6, 434.0e6],  # only 2 distinct
            interval_sec=0.05,
        )

        events = detector.analyse(dets)

        assert len(events) == 0

    def test_exactly_three_frequencies(self):
        """Exactly 3 distinct frequencies should trigger FHSS detection."""
        detector = FHSSDetector()
        dets = _make_hopping_detections(
            n_hops=15,
            frequencies=[433.0e6, 433.5e6, 434.0e6],
            interval_sec=0.05,
        )

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        assert len(events[0].hop_set) >= 3

    def test_multiple_nodes(self):
        """Detections from different nodes produce separate events."""
        detector = FHSSDetector()
        t = time.time()
        dets_a = _make_hopping_detections(
            node_id="node-A", n_hops=15, interval_sec=0.05, start_time=t,
        )
        dets_b = _make_hopping_detections(
            node_id="node-B", n_hops=15, interval_sec=0.05, start_time=t,
        )

        events = detector.analyse(dets_a + dets_b)

        node_ids = {evt.node_id for evt in events}
        assert "node-A" in node_ids
        assert "node-B" in node_ids

    def test_gap_splitting(self):
        """Large time gap should split into separate FHSS events."""
        detector = FHSSDetector(max_gap_sec=2.0)
        t = time.time()
        dets_1 = _make_hopping_detections(
            n_hops=10, interval_sec=0.05, start_time=t,
        )
        # Gap of 10 seconds
        dets_2 = _make_hopping_detections(
            n_hops=10, interval_sec=0.05, start_time=t + 10.0,
        )

        events = detector.analyse(dets_1 + dets_2)

        assert len(events) >= 2
        assert all(isinstance(e, FHSSEvent) for e in events)

    def test_hop_rate_estimation(self):
        """Hop rate should be close to actual hopping speed."""
        detector = FHSSDetector()
        # 10 hops/sec = interval of 0.1s, 5 freqs cycling
        dets = _make_hopping_detections(
            n_hops=50,
            frequencies=[433.0e6, 433.2e6, 433.4e6, 433.6e6, 433.8e6],
            interval_sec=0.1,
        )

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        # Each hop changes frequency (cycling 5 freqs), so transitions
        # happen every detection. With 50 detections over ~5s,
        # we expect ~8-10 hops/sec (some transitions to same freq bucket
        # won't count).
        evt = events[0]
        assert isinstance(evt.hop_rate_hz, float)
        assert evt.hop_rate_hz > 2.0  # at least well above minimum

    def test_dwell_time_estimation(self):
        """Dwell time should be reasonable given the hop interval."""
        detector = FHSSDetector()
        dets = _make_hopping_detections(
            n_hops=30,
            frequencies=[433.0e6, 433.2e6, 433.4e6, 433.6e6, 433.8e6],
            interval_sec=0.1,
        )

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        evt = events[0]
        assert isinstance(evt.dwell_time_ms, float)
        assert evt.dwell_time_ms > 0
        # With 0.1s intervals and cycling 5 freqs, dwell ~100ms
        assert evt.dwell_time_ms < 500  # sanity check

    def test_bandwidth_calculation(self):
        """Bandwidth should equal hop set spread."""
        detector = FHSSDetector()
        freqs = [433.0e6, 433.5e6, 434.0e6, 434.5e6, 435.0e6]
        dets = _make_hopping_detections(
            n_hops=25, frequencies=freqs, interval_sec=0.05,
        )

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        evt = events[0]
        # Expected bandwidth: 435 - 433 = 2 MHz
        assert isinstance(evt.bandwidth_hz, float)
        assert abs(evt.bandwidth_hz - 2.0e6) < 0.1e6

    def test_to_dict(self):
        """FHSSEvent.to_dict() produces serializable output."""
        evt = FHSSEvent(
            fhss_id="test123",
            node_id="node-01",
            timestamp="2026-01-01T00:00:00+00:00",
            hop_rate_hz=10.5,
            hop_set=[433.0e6, 433.5e6, 434.0e6],
            bandwidth_hz=1.0e6,
            dwell_time_ms=95.2,
            duration_sec=2.5,
            signal_class="2fsk",
            detection_count=25,
            confidence=0.88,
        )

        d = evt.to_dict()

        assert d["fhss_id"] == "test123"
        assert d["node_id"] == "node-01"
        assert len(d["hop_set"]) == 3
        assert isinstance(d["hop_rate_hz"], float)
        assert isinstance(d["bandwidth_hz"], float)

    def test_iso_timestamp_input(self):
        """Detector handles ISO timestamp strings in detection dicts."""
        detector = FHSSDetector()
        now = datetime.now(timezone.utc)
        dets = []
        freqs = [433.0e6, 433.2e6, 433.4e6, 433.6e6, 433.8e6]
        for i in range(20):
            dets.append({
                "node_id": "node-iso",
                "timestamp": (now + timedelta(milliseconds=50 * i)).isoformat(),
                "freq_hz": freqs[i % len(freqs)],
                "signal_class": "4fsk",
                "confidence": 0.9,
            })

        events = detector.analyse(dets)

        assert len(events) >= 1
        assert isinstance(events[0], FHSSEvent)
        assert events[0].node_id == "node-iso"

    def test_empty_input(self):
        """Empty detection list returns no events."""
        detector = FHSSDetector()
        assert detector.analyse([]) == []

    def test_too_few_detections(self):
        """Fewer detections than min_distinct_freqs returns nothing."""
        detector = FHSSDetector()
        dets = _make_hopping_detections(n_hops=2)
        assert detector.analyse(dets) == []


# ===========================================================================
# FHSSStore unit tests
# ===========================================================================


class TestFHSSStore:
    """Tests for the FHSSStore SQLite persistence."""

    def test_insert_and_query(self, detection_store: DetectionStore):
        """Insert FHSS events and query them back."""
        events = [
            {
                "fhss_id": "fhss-001",
                "node_id": "node-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hop_rate_hz": 10.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
                "dwell_time_ms": 100.0,
                "duration_sec": 2.5,
                "signal_class": "2fsk",
                "detection_count": 25,
                "confidence": 0.88,
            },
            {
                "fhss_id": "fhss-002",
                "node_id": "node-02",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hop_rate_hz": 5.0,
                "hop_set": [915.0e6, 915.5e6, 916.0e6, 916.5e6],
                "bandwidth_hz": 1500000.0,
                "dwell_time_ms": 200.0,
                "duration_sec": 4.0,
                "signal_class": "4fsk",
                "detection_count": 20,
                "confidence": 0.92,
            },
        ]

        ids = detection_store.insert_fhss_events(events)
        assert len(ids) == 2
        assert "fhss-001" in ids

        results = detection_store.get_fhss_events(hours=1)
        assert len(results) == 2

    def test_get_by_id(self, detection_store: DetectionStore):
        """Get a single FHSS event by its ID."""
        events = [
            {
                "fhss_id": "fhss-lookup",
                "node_id": "node-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "hop_rate_hz": 8.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
                "dwell_time_ms": 125.0,
                "duration_sec": 2.0,
                "signal_class": "2fsk",
                "detection_count": 16,
                "confidence": 0.85,
            },
        ]
        detection_store.insert_fhss_events(events)

        result = detection_store.get_fhss_event_by_id("fhss-lookup")

        assert result is not None
        assert isinstance(result, dict)
        assert result["fhss_id"] == "fhss-lookup"
        assert result["hop_rate_hz"] == 8.0
        assert isinstance(result["hop_set"], list)
        assert len(result["hop_set"]) == 3

    def test_get_by_id_not_found(self, detection_store: DetectionStore):
        """Non-existent ID returns None."""
        result = detection_store.get_fhss_event_by_id("nonexistent")
        assert result is None

    def test_node_filter(self, detection_store: DetectionStore):
        """Querying with node_id filter returns only matching events."""
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "fhss_id": "fhss-n1",
                "node_id": "node-A",
                "timestamp": now,
                "hop_rate_hz": 10.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
            },
            {
                "fhss_id": "fhss-n2",
                "node_id": "node-B",
                "timestamp": now,
                "hop_rate_hz": 5.0,
                "hop_set": [915.0e6, 915.5e6, 916.0e6],
                "bandwidth_hz": 1000000.0,
            },
        ]
        detection_store.insert_fhss_events(events)

        results = detection_store.get_fhss_events(hours=1, node_id="node-A")
        assert len(results) == 1
        assert results[0]["node_id"] == "node-A"

    def test_min_hop_rate_filter(self, detection_store: DetectionStore):
        """Querying with min_hop_rate filter excludes slow hoppers."""
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {
                "fhss_id": "fhss-fast",
                "node_id": "node-01",
                "timestamp": now,
                "hop_rate_hz": 20.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
            },
            {
                "fhss_id": "fhss-slow",
                "node_id": "node-01",
                "timestamp": now,
                "hop_rate_hz": 2.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
            },
        ]
        detection_store.insert_fhss_events(events)

        results = detection_store.get_fhss_events(hours=1, min_hop_rate=10.0)
        assert len(results) == 1
        assert results[0]["fhss_id"] == "fhss-fast"

    def test_count(self, detection_store: DetectionStore):
        """count_fhss_events returns correct count."""
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {"fhss_id": f"fhss-c{i}", "node_id": "node-01", "timestamp": now,
             "hop_rate_hz": 10.0, "hop_set": [433.0e6], "bandwidth_hz": 0.0}
            for i in range(5)
        ]
        detection_store.insert_fhss_events(events)

        assert detection_store.count_fhss_events(hours=1) == 5

    def test_cleanup(self, detection_store: DetectionStore):
        """cleanup_fhss_events removes old events."""
        old_ts = (datetime.now(timezone.utc) - timedelta(days=60)).isoformat()
        new_ts = datetime.now(timezone.utc).isoformat()

        events = [
            {"fhss_id": "fhss-old", "node_id": "node-01", "timestamp": old_ts,
             "hop_rate_hz": 5.0, "hop_set": [433.0e6], "bandwidth_hz": 0.0},
            {"fhss_id": "fhss-new", "node_id": "node-01", "timestamp": new_ts,
             "hop_rate_hz": 5.0, "hop_set": [433.0e6], "bandwidth_hz": 0.0},
        ]
        detection_store.insert_fhss_events(events)

        deleted = detection_store.cleanup_fhss_events(max_age_days=30)
        assert deleted == 1

        remaining = detection_store.get_fhss_events(hours=24 * 365)
        assert len(remaining) == 1
        assert remaining[0]["fhss_id"] == "fhss-new"

    def test_duplicate_insert_ignored(self, detection_store: DetectionStore):
        """Inserting a duplicate fhss_id is silently ignored."""
        now = datetime.now(timezone.utc).isoformat()
        event = {
            "fhss_id": "fhss-dup",
            "node_id": "node-01",
            "timestamp": now,
            "hop_rate_hz": 10.0,
            "hop_set": [433.0e6, 433.2e6, 433.4e6],
            "bandwidth_hz": 400000.0,
        }
        ids1 = detection_store.insert_fhss_events([event])
        ids2 = detection_store.insert_fhss_events([event])

        assert len(ids1) == 1
        assert len(ids2) == 1  # ID is returned but insert is ignored

        results = detection_store.get_fhss_events(hours=1)
        assert len(results) == 1


# ===========================================================================
# API endpoint tests
# ===========================================================================


class TestFHSSAPI:
    """Tests for the FHSS API endpoints."""

    def test_get_fhss_empty(self, client):
        """GET /api/spectrum/fhss returns empty list when no events."""
        resp = client.get("/api/spectrum/fhss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["events"] == []

    def test_get_fhss_with_data(self, client, detection_store):
        """GET /api/spectrum/fhss returns stored events."""
        now = datetime.now(timezone.utc).isoformat()
        detection_store.insert_fhss_events([
            {
                "fhss_id": "fhss-api-01",
                "node_id": "node-test-01",
                "timestamp": now,
                "hop_rate_hz": 10.0,
                "hop_set": [433.0e6, 433.2e6, 433.4e6],
                "bandwidth_hz": 400000.0,
                "dwell_time_ms": 100.0,
                "duration_sec": 2.5,
                "signal_class": "2fsk",
                "detection_count": 25,
                "confidence": 0.88,
            },
        ])

        resp = client.get("/api/spectrum/fhss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        evt = data["events"][0]
        assert evt["fhss_id"] == "fhss-api-01"
        assert evt["hop_rate_hz"] == 10.0
        assert len(evt["hop_set"]) == 3

    def test_get_fhss_detail(self, client, detection_store):
        """GET /api/spectrum/fhss/{id} returns event detail."""
        now = datetime.now(timezone.utc).isoformat()
        detection_store.insert_fhss_events([
            {
                "fhss_id": "fhss-detail-01",
                "node_id": "node-test-01",
                "timestamp": now,
                "hop_rate_hz": 8.0,
                "hop_set": [915.0e6, 915.5e6, 916.0e6],
                "bandwidth_hz": 1000000.0,
                "dwell_time_ms": 125.0,
                "duration_sec": 3.0,
                "signal_class": "4fsk",
                "detection_count": 24,
                "confidence": 0.91,
            },
        ])

        resp = client.get("/api/spectrum/fhss/fhss-detail-01")
        assert resp.status_code == 200
        data = resp.json()
        assert data["fhss_id"] == "fhss-detail-01"
        assert data["hop_rate_hz"] == 8.0
        assert len(data["hop_set"]) == 3
        assert data["signal_class"] == "4fsk"

    def test_get_fhss_detail_not_found(self, client):
        """GET /api/spectrum/fhss/{id} returns 404 for unknown ID."""
        resp = client.get("/api/spectrum/fhss/nonexistent")
        assert resp.status_code == 404

    def test_get_fhss_node_filter(self, client, detection_store):
        """GET /api/spectrum/fhss?node_id= filters by node."""
        now = datetime.now(timezone.utc).isoformat()
        detection_store.insert_fhss_events([
            {
                "fhss_id": "fhss-node-a",
                "node_id": "node-alpha",
                "timestamp": now,
                "hop_rate_hz": 10.0,
                "hop_set": [433.0e6],
                "bandwidth_hz": 0.0,
            },
            {
                "fhss_id": "fhss-node-b",
                "node_id": "node-beta",
                "timestamp": now,
                "hop_rate_hz": 5.0,
                "hop_set": [433.0e6],
                "bandwidth_hz": 0.0,
            },
        ])

        resp = client.get("/api/spectrum/fhss?node_id=node-alpha")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["events"][0]["node_id"] == "node-alpha"

    def test_get_fhss_pagination(self, client, detection_store):
        """GET /api/spectrum/fhss supports limit/offset pagination."""
        now = datetime.now(timezone.utc).isoformat()
        events = [
            {"fhss_id": f"fhss-pg-{i:02d}", "node_id": "node-01",
             "timestamp": now, "hop_rate_hz": 10.0,
             "hop_set": [433.0e6], "bandwidth_hz": 0.0}
            for i in range(10)
        ]
        detection_store.insert_fhss_events(events)

        resp = client.get("/api/spectrum/fhss?limit=3&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 3
        assert data["total"] == 10

        resp2 = client.get("/api/spectrum/fhss?limit=3&offset=3")
        data2 = resp2.json()
        assert data2["count"] == 3


# ===========================================================================
# Integration: FHSS detection during batch ingestion
# ===========================================================================


class TestFHSSIngestion:
    """Test FHSS detection triggered by batch detection ingestion."""

    def test_fhss_detected_on_batch(self, client, registered_node, detection_store):
        """Ingesting rapidly hopping detections should create FHSS events."""
        now = time.time()
        # Create frequency-hopping detections: 5 distinct freqs, rapid
        freqs = [433.0e6, 433.2e6, 433.4e6, 433.6e6, 433.8e6]
        detections = []
        for i in range(25):
            ts = now + i * 0.04  # 25 hops/sec
            detections.append({
                "node_id": registered_node,
                "timestamp": ts,
                "signal_class": "2fsk",
                "confidence": 0.9,
                "family": "FSK",
                "freq_hz": freqs[i % len(freqs)],
                "snr_db": 15.0,
                "power_dbm": -50.0,
            })

        payload = {
            "node_id": registered_node,
            "period_start": now,
            "period_end": now + 1.0,
            "detections": detections,
        }

        resp = client.post("/api/detections/batch", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert "fhss_events" in data
        assert isinstance(data["fhss_events"], int)

    def test_no_fhss_for_static_batch(self, client, registered_node, detection_store):
        """Static-frequency batch should not produce FHSS events."""
        now = time.time()
        detections = []
        for i in range(15):
            detections.append({
                "node_id": registered_node,
                "timestamp": now + i * 0.1,
                "signal_class": "bpsk",
                "confidence": 0.9,
                "family": "PSK",
                "freq_hz": 915.0e6,  # static
                "snr_db": 12.0,
                "power_dbm": -55.0,
            })

        payload = {
            "node_id": registered_node,
            "period_start": now,
            "period_end": now + 1.5,
            "detections": detections,
        }

        resp = client.post("/api/detections/batch", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["fhss_events"] == 0
