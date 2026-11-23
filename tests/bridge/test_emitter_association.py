"""Tests for the emitter association engine.

Covers:
  - EmitterAssociator frequency clustering
  - Power consistency refinement
  - Temporal regularity / activity pattern analysis
  - Emitter ID determinism
  - Minimum detection threshold
  - Multi-node association
  - EmitterStore CRUD (upsert, list, get, delete, count)
  - API endpoints: GET /emitters, GET /emitters/{id}, POST /emitters/recompute
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.emitter import Emitter, EmitterAssociator
from sigrift.bridge.detection_store import DetectionStore

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _det(
    node_id: str = "node-01",
    signal_class: str = "bpsk",
    freq_hz: float = 433.92e6,
    power_dbm: float = -40.0,
    timestamp: datetime | None = None,
    bandwidth_hz: float | None = None,
    detection_id: str = "",
) -> dict[str, Any]:
    """Build a detection dict for emitter tests."""
    import uuid
    return {
        "detection_id": detection_id or uuid.uuid4().hex[:16],
        "node_id": node_id,
        "signal_class": signal_class,
        "freq_hz": freq_hz,
        "power_dbm": power_dbm,
        "bandwidth_hz": bandwidth_hz,
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "confidence": 0.9,
        "snr_db": 15.0,
    }

# ---------------------------------------------------------------------------
# Unit tests: EmitterAssociator
# ---------------------------------------------------------------------------

class TestEmitterAssociator:
    """Core emitter association logic tests."""

    def test_empty_input(self) -> None:
        """Empty detection list produces no emitters."""
        assoc = EmitterAssociator()
        assert assoc.associate([]) == []

    def test_single_class_single_freq_cluster(self) -> None:
        """Multiple detections at the same freq form one emitter."""
        assoc = EmitterAssociator(min_detections=3)
        now = datetime.now(timezone.utc)
        dets = [
            _det(freq_hz=433.92e6, timestamp=now - timedelta(minutes=i))
            for i in range(5)
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 1
        assert emitters[0].signal_class == "bpsk"
        assert emitters[0].detection_count == 5
        assert len(emitters[0].associated_nodes) >= 1

    def test_two_freq_clusters(self) -> None:
        """Detections at widely separated frequencies form two emitters."""
        assoc = EmitterAssociator(min_detections=2, freq_tolerance_hz=50_000)
        now = datetime.now(timezone.utc)
        dets = [
            _det(freq_hz=433.92e6, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ] + [
            _det(freq_hz=915.0e6, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 2
        freqs = sorted(e.primary_freq_hz for e in emitters)
        assert freqs[0] < 500e6  # ~434 MHz cluster
        assert freqs[1] > 900e6  # ~915 MHz cluster

    def test_frequency_within_tolerance(self) -> None:
        """Detections within freq tolerance merge into one emitter."""
        assoc = EmitterAssociator(min_detections=2, freq_tolerance_hz=100_000)
        now = datetime.now(timezone.utc)
        dets = [
            _det(freq_hz=433.90e6, timestamp=now),
            _det(freq_hz=433.95e6, timestamp=now - timedelta(seconds=30)),
            _det(freq_hz=433.92e6, timestamp=now - timedelta(seconds=60)),
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 1
        assert emitters[0].detection_count == 3

    def test_power_consistency_splits(self) -> None:
        """Detections at same freq but very different power form separate emitters."""
        assoc = EmitterAssociator(
            min_detections=2,
            freq_tolerance_hz=100_000,
            power_tolerance_db=5.0,
        )
        now = datetime.now(timezone.utc)
        # Group 1: strong signal
        dets = [
            _det(freq_hz=433.92e6, power_dbm=-20.0, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ]
        # Group 2: weak signal at same freq
        dets += [
            _det(freq_hz=433.92e6, power_dbm=-80.0, timestamp=now - timedelta(minutes=i + 10))
            for i in range(3)
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 2
        powers = sorted(e.power_profile.get("mean_dbm", 0) for e in emitters)
        assert powers[0] < -60  # weak group
        assert powers[1] > -30  # strong group

    def test_min_detections_threshold(self) -> None:
        """Clusters with fewer than min_detections are dropped."""
        assoc = EmitterAssociator(min_detections=5)
        dets = [_det(freq_hz=433.92e6) for _ in range(3)]
        emitters = assoc.associate(dets)
        assert len(emitters) == 0

    def test_multi_signal_class(self) -> None:
        """Different signal classes produce separate emitters."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        dets = [
            _det(signal_class="bpsk", freq_hz=433.92e6, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ] + [
            _det(signal_class="fm", freq_hz=433.92e6, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 2
        classes = sorted(e.signal_class for e in emitters)
        assert classes == ["bpsk", "fm"]

    def test_multi_node_association(self) -> None:
        """Detections from multiple nodes at same freq form one emitter."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        dets = [
            _det(node_id="node-01", freq_hz=433.92e6, timestamp=now),
            _det(node_id="node-02", freq_hz=433.92e6, timestamp=now - timedelta(seconds=10)),
            _det(node_id="node-03", freq_hz=433.92e6, timestamp=now - timedelta(seconds=20)),
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 1
        assert set(emitters[0].associated_nodes) == {"node-01", "node-02", "node-03"}

    def test_emitter_id_determinism(self) -> None:
        """Same signal_class + freq produces the same emitter_id."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        dets = [
            _det(freq_hz=433.92e6, timestamp=now - timedelta(minutes=i))
            for i in range(3)
        ]
        emitters1 = assoc.associate(dets)
        emitters2 = assoc.associate(dets)
        assert emitters1[0].emitter_id == emitters2[0].emitter_id

    def test_power_profile_computed(self) -> None:
        """Power profile contains mean, median, min, max, std."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        dets = [
            _det(freq_hz=433.92e6, power_dbm=-40.0 + i, timestamp=now - timedelta(minutes=i))
            for i in range(5)
        ]
        emitters = assoc.associate(dets)
        profile = emitters[0].power_profile
        assert isinstance(profile["mean_dbm"], float)
        assert isinstance(profile["median_dbm"], float)
        assert profile["min_dbm"] == -40.0
        assert profile["max_dbm"] == -36.0
        assert isinstance(profile["std_dbm"], float)

    def test_activity_pattern_periodic(self) -> None:
        """Regularly spaced detections produce high regularity_score."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        # Perfect 60-second intervals
        dets = [
            _det(freq_hz=433.92e6, timestamp=now - timedelta(seconds=i * 60))
            for i in range(10)
        ]
        emitters = assoc.associate(dets)
        pattern = emitters[0].activity_pattern
        assert pattern["regularity_score"] > 0.9
        assert pattern["is_periodic"] is True
        assert abs(pattern["avg_interval_sec"] - 60.0) < 1.0

    def test_activity_pattern_irregular(self) -> None:
        """Randomly spaced detections have low regularity_score."""
        assoc = EmitterAssociator(min_detections=2)
        # Irregular: 1s, 100s, 3s, 200s gaps
        timestamps = [
            datetime.now(timezone.utc),
            datetime.now(timezone.utc) - timedelta(seconds=1),
            datetime.now(timezone.utc) - timedelta(seconds=101),
            datetime.now(timezone.utc) - timedelta(seconds=104),
            datetime.now(timezone.utc) - timedelta(seconds=304),
        ]
        dets = [
            _det(freq_hz=433.92e6, timestamp=ts) for ts in timestamps
        ]
        emitters = assoc.associate(dets)
        pattern = emitters[0].activity_pattern
        assert pattern["regularity_score"] < 0.5

    def test_no_power_detections(self) -> None:
        """Detections without power_dbm still cluster correctly."""
        assoc = EmitterAssociator(min_detections=2)
        now = datetime.now(timezone.utc)
        dets = [
            {
                "detection_id": f"d{i}",
                "node_id": "node-01",
                "signal_class": "bpsk",
                "freq_hz": 433.92e6,
                "power_dbm": None,
                "timestamp": (now - timedelta(minutes=i)).isoformat(),
            }
            for i in range(4)
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 1
        assert emitters[0].power_profile == {}

    def test_bandwidth_overrides_freq_tolerance(self) -> None:
        """Per-detection bandwidth_hz extends frequency tolerance."""
        assoc = EmitterAssociator(min_detections=2, freq_tolerance_hz=10_000)
        now = datetime.now(timezone.utc)
        # 60kHz apart, but bandwidth_hz = 100kHz overrides 10kHz tolerance
        dets = [
            _det(freq_hz=433.90e6, bandwidth_hz=100_000, timestamp=now),
            _det(freq_hz=433.96e6, bandwidth_hz=100_000, timestamp=now - timedelta(seconds=10)),
            _det(freq_hz=433.93e6, bandwidth_hz=100_000, timestamp=now - timedelta(seconds=20)),
        ]
        emitters = assoc.associate(dets)
        assert len(emitters) == 1

# ---------------------------------------------------------------------------
# Unit tests: EmitterStore
# ---------------------------------------------------------------------------

class TestEmitterStore:
    """SQLite storage tests for emitters."""

    def test_upsert_and_list(self, detection_store: DetectionStore) -> None:
        """Upserted emitters are retrievable via list."""
        emitter = Emitter(
            emitter_id="test-emitter-01",
            primary_freq_hz=433.92e6,
            bandwidth_hz=50_000,
            signal_class="bpsk",
            power_profile={"mean_dbm": -40.0},
            activity_pattern={"is_periodic": True},
            associated_nodes=["node-01", "node-02"],
            first_seen="2026-01-01T00:00:00+00:00",
            last_seen="2026-01-01T01:00:00+00:00",
            detection_count=42,
            detection_ids=["d1", "d2"],
        )
        count = detection_store.upsert_emitters([emitter.model_dump()])
        assert count == 1

        emitters = detection_store.list_emitters()
        assert len(emitters) == 1
        assert emitters[0]["emitter_id"] == "test-emitter-01"
        assert emitters[0]["signal_class"] == "bpsk"
        assert emitters[0]["detection_count"] == 42
        assert emitters[0]["associated_nodes"] == ["node-01", "node-02"]

    def test_get_emitter(self, detection_store: DetectionStore) -> None:
        """Single emitter retrieval by ID."""
        emitter = Emitter(
            emitter_id="test-get-01",
            primary_freq_hz=915e6,
            signal_class="fm",
            detection_count=10,
        )
        detection_store.upsert_emitters([emitter.model_dump()])
        result = detection_store.get_emitter("test-get-01")
        assert isinstance(result, dict)
        assert result["primary_freq_hz"] == 915e6

    def test_get_nonexistent(self, detection_store: DetectionStore) -> None:
        """Missing emitter returns None."""
        assert detection_store.get_emitter("nonexistent") is None

    def test_delete_all(self, detection_store: DetectionStore) -> None:
        """delete_all removes all emitters."""
        for i in range(3):
            detection_store.upsert_emitters([
                Emitter(
                    emitter_id=f"del-{i}",
                    signal_class="bpsk",
                    detection_count=1,
                ).model_dump()
            ])
        assert detection_store.count_emitters() == 3
        deleted = detection_store.delete_all_emitters()
        assert deleted == 3
        assert detection_store.count_emitters() == 0

    def test_upsert_replaces(self, detection_store: DetectionStore) -> None:
        """Upserting with same emitter_id replaces the record."""
        e1 = Emitter(
            emitter_id="upsert-test",
            signal_class="bpsk",
            detection_count=5,
        )
        detection_store.upsert_emitters([e1.model_dump()])
        assert detection_store.get_emitter("upsert-test")["detection_count"] == 5

        e2 = Emitter(
            emitter_id="upsert-test",
            signal_class="bpsk",
            detection_count=99,
        )
        detection_store.upsert_emitters([e2.model_dump()])
        assert detection_store.get_emitter("upsert-test")["detection_count"] == 99
        assert detection_store.count_emitters() == 1

    def test_list_with_signal_class_filter(self, detection_store: DetectionStore) -> None:
        """List filters by signal_class."""
        detection_store.upsert_emitters([
            Emitter(emitter_id="a", signal_class="bpsk", detection_count=1).model_dump(),
            Emitter(emitter_id="b", signal_class="fm", detection_count=1).model_dump(),
        ])
        bpsk = detection_store.list_emitters(signal_class="bpsk")
        assert len(bpsk) == 1
        assert bpsk[0]["signal_class"] == "bpsk"

    def test_list_with_min_detections_filter(self, detection_store: DetectionStore) -> None:
        """List filters by min_detections."""
        detection_store.upsert_emitters([
            Emitter(emitter_id="low", signal_class="bpsk", detection_count=2).model_dump(),
            Emitter(emitter_id="high", signal_class="bpsk", detection_count=50).model_dump(),
        ])
        result = detection_store.list_emitters(min_detections=10)
        assert len(result) == 1
        assert result[0]["emitter_id"] == "high"

# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------

class TestEmitterEndpoints:
    """Tests for emitter API endpoints."""

    def test_list_emitters_empty(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """GET /emitters with no data returns empty list."""
        resp = client.get("/api/emitters")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["emitters"] == []
        assert data["total"] == 0

    def test_recompute_no_data(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """POST /emitters/recompute with no detections discovers nothing."""
        resp = client.post("/api/emitters/recompute", params={"hours": 1})
        assert resp.status_code == 200
        data = resp.json()
        assert data["emitters_discovered"] == 0
        assert data["detections_analysed"] == 0

    def test_recompute_discovers_emitters(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """Recompute discovers emitters from ingested detection data."""
        now = datetime.now(timezone.utc)

        # Ingest a batch of detections
        detections = [
            {
                "node_id": registered_node,
                "signal_class": "bpsk",
                "confidence": 0.92,
                "family": "psk",
                "freq_hz": 433.92e6,
                "power_dbm": -40.0,
                "timestamp": (now - timedelta(minutes=i)).isoformat(),
            }
            for i in range(5)
        ]
        resp = client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=5)).isoformat(),
            "period_end": now.isoformat(),
            "detections": detections,
        })
        assert resp.status_code == 201

        # Recompute emitters
        resp = client.post("/api/emitters/recompute", params={
            "hours": 1,
            "min_detections": 3,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["emitters_discovered"] >= 1
        assert data["detections_analysed"] >= 5

        # List emitters
        resp = client.get("/api/emitters")
        assert resp.status_code == 200
        listing = resp.json()
        assert listing["count"] >= 1
        emitter = listing["emitters"][0]
        assert emitter["signal_class"] == "bpsk"
        assert emitter["detection_count"] >= 5

        # Get detail
        emitter_id = emitter["emitter_id"]
        resp = client.get(f"/api/emitters/{emitter_id}")
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["emitter"]["emitter_id"] == emitter_id

    def test_emitter_detail_not_found(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """GET /emitters/{id} for nonexistent emitter returns 404."""
        resp = client.get("/api/emitters/nonexistent-id")
        assert resp.status_code == 404

    def test_emitter_detail_with_detections(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """GET /emitters/{id}?include_detections=true fetches associated detections."""
        now = datetime.now(timezone.utc)

        # Ingest detections
        detections = [
            {
                "node_id": registered_node,
                "signal_class": "qam16",
                "confidence": 0.88,
                "family": "qam",
                "freq_hz": 915e6,
                "power_dbm": -35.0,
                "timestamp": (now - timedelta(minutes=i)).isoformat(),
            }
            for i in range(4)
        ]
        client.post("/api/detections/batch", json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=4)).isoformat(),
            "period_end": now.isoformat(),
            "detections": detections,
        })

        # Recompute
        resp = client.post("/api/emitters/recompute", params={
            "hours": 1,
            "min_detections": 3,
        })
        assert resp.status_code == 200

        # Find the emitter
        resp = client.get("/api/emitters", params={"signal_class": "qam16"})
        emitter_id = resp.json()["emitters"][0]["emitter_id"]

        # Get detail with detections
        resp = client.get(
            f"/api/emitters/{emitter_id}",
            params={"include_detections": True},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["detections"], list)
        assert data["detections_returned"] >= 1

    def test_list_emitters_requires_auth(self, bridge_app) -> None:
        """GET /emitters requires authentication."""
        unauth = TestClient(bridge_app)
        resp = unauth.get("/api/emitters")
        assert resp.status_code in (401, 403)

    def test_recompute_requires_analyst_role(self, bridge_app) -> None:
        """POST /emitters/recompute requires authentication."""
        unauth = TestClient(bridge_app)
        resp = unauth.post("/api/emitters/recompute")
        assert resp.status_code in (401, 403)

    def test_list_with_filters(
        self, client: TestClient, registered_node: str,
    ) -> None:
        """GET /emitters supports signal_class and min_detections filters."""
        now = datetime.now(timezone.utc)

        # Ingest two signal classes
        for sig, freq in [("bpsk", 433.92e6), ("fm", 100e6)]:
            dets = [
                {
                    "node_id": registered_node,
                    "signal_class": sig,
                    "confidence": 0.9,
                    "freq_hz": freq,
                    "power_dbm": -40.0,
                    "timestamp": (now - timedelta(minutes=i)).isoformat(),
                }
                for i in range(5)
            ]
            client.post("/api/detections/batch", json={
                "node_id": registered_node,
                "period_start": (now - timedelta(minutes=5)).isoformat(),
                "period_end": now.isoformat(),
                "detections": dets,
            })

        # Recompute
        client.post("/api/emitters/recompute", params={"hours": 1, "min_detections": 3})

        # Filter by signal_class
        resp = client.get("/api/emitters", params={"signal_class": "bpsk"})
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["signal_class"] == "bpsk" for e in data["emitters"])

        # Filter by min_detections (high threshold = fewer results)
        resp = client.get("/api/emitters", params={"min_detections": 100})
        assert resp.status_code == 200
        assert resp.json()["count"] == 0
