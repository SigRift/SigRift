"""Tests for Bluetooth SIGINT API endpoints.

Covers:
  - Batch ingest (auth, validation, success, edge cases)
  - Device listing and detail queries
  - Summary statistics
  - Anomaly listing, dismiss, snooze, bulk operations
  - BtAnomalyScorer dimension scoring and baseline behaviour
"""

from __future__ import annotations

import gzip
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.anomaly.bt_scorer import (
    BtAnomalyScorer,
    BtBaseline,
    BtBaselineManager,
)
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key with a given role in persistence and return raw key."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw_key


def _make_bt_record(**overrides) -> dict:
    """Return a minimal valid BT device record dict with optional overrides."""
    base = {
        "device_addr": "aa:bb:cc:dd:ee:ff",
        "device_name": "TestDevice",
        "device_type": "ble",
        "device_class": 0,
        "device_class_name": "",
        "appearance": 0,
        "rssi_dbm": -55.0,
        "tx_power_dbm": None,
        "manufacturer_id": None,
        "manufacturer": "Acme",
        "service_uuids": [],
        "adv_data": {},
        "connectable": True,
        "bonded": False,
        "channel": 37,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sensor_key(persistence: PersistenceManager) -> str:
    """Create a sensor-role API key."""
    return _make_key_and_store(persistence, "bt_sensor_key", role="sensor")


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    """Create a viewer-role API key."""
    return _make_key_and_store(persistence, "bt_viewer_key", role="viewer")


@pytest.fixture
def analyst_key(persistence: PersistenceManager) -> str:
    """Create an analyst-role API key."""
    return _make_key_and_store(persistence, "bt_analyst_key", role="analyst")


@pytest.fixture
def sensor_client(bridge_app: FastAPI, sensor_key: str) -> TestClient:
    """TestClient authenticated with a sensor-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": sensor_key})


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    """TestClient authenticated with a viewer-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def analyst_client(bridge_app: FastAPI, analyst_key: str) -> TestClient:
    """TestClient authenticated with an analyst-role key."""
    return TestClient(bridge_app, headers={"X-API-Key": analyst_key})


@pytest.fixture
def unauth_client(bridge_app: FastAPI) -> TestClient:
    """TestClient with no API key."""
    return TestClient(bridge_app)


@pytest.fixture
def bt_node(client: TestClient) -> str:
    """Register a test node for BT ingest and return its ID."""
    node_id = "bt-node-01"
    resp = client.post(
        "/api/nodes/register",
        json={
            "node_id": node_id,
            "host": "10.0.0.50",
            "port": 8080,
        },
    )
    assert resp.status_code == 200
    return node_id


# ---------------------------------------------------------------------------
# TestBtIngest
# ---------------------------------------------------------------------------


class TestBtIngest:
    """Tests for POST /api/bluetooth/ingest."""

    def test_ingest_basic(self, client: TestClient, bt_node: str):
        """Valid BT scan batch is accepted and returns correct counts."""
        resp = client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(
                        device_addr="aa:bb:cc:11:22:33", device_name="Device1"
                    ),
                    _make_bt_record(
                        device_addr="dd:ee:ff:44:55:66", device_name="Device2"
                    ),
                ],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 2
        assert data["total"] == 2
        assert isinstance(data["anomalies"], int)

    def test_ingest_empty_records(self, client: TestClient, bt_node: str):
        """Empty records list is accepted and returns 0 inserted."""
        resp = client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted"] == 0
        assert data["total"] == 0

    def test_ingest_too_many(self, client: TestClient, bt_node: str):
        """Over 500 records returns 400 Bad Request."""
        records = [
            _make_bt_record(device_addr=f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}")
            for i in range(501)
        ]
        resp = client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": records,
            },
        )
        assert resp.status_code == 400
        assert "500" in resp.json()["detail"]

    def test_ingest_missing_node_id(self, client: TestClient):
        """Missing node_id field returns 400 validation error."""
        resp = client.post(
            "/api/bluetooth/ingest",
            json={
                "records": [_make_bt_record()],
            },
        )
        assert resp.status_code == 400

    def test_ingest_auth_required(self, unauth_client: TestClient):
        """No API key returns 401 Unauthorized."""
        resp = unauth_client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": "some-node",
                "records": [_make_bt_record()],
            },
        )
        assert resp.status_code == 401

    def test_ingest_sensor_role_required(self, viewer_client: TestClient, bt_node: str):
        """An unbound VIEWER key cannot ingest for a node (contract K7b).

        VIEWER ranks above SENSOR, so the role check passes, but a viewer
        key is not a node credential: it is never bound to a node on first
        use and is refused on node-scoped routes.  (Before round 5 it was
        bound to the first node it named and could ingest for it.)
        """
        resp = viewer_client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [_make_bt_record()],
            },
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Node endpoints require a node API key"


# ---------------------------------------------------------------------------
# TestBtIngestSummary
# ---------------------------------------------------------------------------


def _make_bt_summary_device(**overrides) -> dict:
    """Return a minimal valid BT summary device dict with optional overrides."""
    base = {
        "device_addr": "aa:bb:cc:dd:ee:ff",
        "device_name": "TestDevice",
        "device_type": "ble",
        "manufacturer_id": None,
        "manufacturer": "Acme",
        "rssi_max_dbm": -40.0,
        "rssi_avg_dbm": -55.0,
        "observation_count": 12,
        "channel": 37,
        "service_uuids": ["180a"],
        "first_seen": "2026-05-26T22:00:00+00:00",
        "last_seen": "2026-05-26T22:00:30+00:00",
    }
    base.update(overrides)
    return base


class TestBtIngestSummary:
    """Tests for POST /api/bluetooth/ingest-summary."""

    def test_summary_basic(self, client: TestClient, bt_node: str):
        """Valid BT summary batch is accepted and writes one row per device."""
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            json={
                "node_id": bt_node,
                "scan_period_s": 30.0,
                "total_observations": 25,
                "devices": [
                    _make_bt_summary_device(device_addr="aa:bb:cc:11:22:33"),
                    _make_bt_summary_device(device_addr="dd:ee:ff:44:55:66"),
                ],
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 2
        assert data["devices"] == 2
        assert data["total_observations"] == 25

    def test_summary_gzipped_body(self, client: TestClient, bt_node: str):
        """A gzip-compressed summary (Content-Encoding: gzip) is accepted.

        The edge scanner gzips this POST; until the route read the body
        via read_json_body every summary was rejected with 400 and no BT
        data reached the bridge (staging incident 2026-06-10).
        """
        payload = {
            "node_id": bt_node,
            "scan_period_s": 30.0,
            "total_observations": 7,
            "devices": [_make_bt_summary_device(device_addr="aa:bb:cc:11:22:33")],
        }
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            content=gzip.compress(json.dumps(payload).encode("utf-8")),
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 1

    def test_summary_corrupt_gzip_rejected(self, client: TestClient, bt_node: str):
        """A Content-Encoding: gzip body that isn't valid gzip gets a clean 400."""
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            content=b"\x00not-gzip-at-all",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower()

    def test_summary_truncated_gzip_rejected(self, client: TestClient, bt_node: str):
        """A gzip stream cut mid-body (flaky network) gets 400, not 500."""
        payload = {"node_id": bt_node, "devices": []}
        full = gzip.compress(json.dumps(payload).encode("utf-8"))
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            content=full[: len(full) // 2],
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 400
        assert "decompress" in resp.json()["detail"].lower()

    def test_summary_corrupt_deflate_rejected(self, client: TestClient):
        """Garbage deflate data behind a valid gzip header gets 400."""
        valid_header = gzip.compress(b"x")[:10]
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            content=valid_header + b"\xff\xfe\xfd\xfc" * 8,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
            },
        )
        assert resp.status_code == 400

    def test_summary_invalid_payload_rejected(self, client: TestClient):
        """Schema violations surface as 400 with detail, like POST /ingest."""
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            json={"node_id": "bad node id!", "devices": []},
        )
        assert resp.status_code == 400

    def test_summary_empty_devices(self, client: TestClient, bt_node: str):
        """An empty summary (no devices observed in window) is accepted as a no-op."""
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            json={
                "node_id": bt_node,
                "scan_period_s": 30.0,
                "total_observations": 0,
                "devices": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["inserted"] == 0

    def test_summary_writes_avg_rssi(self, client: TestClient, bt_node: str):
        """Summary rows persist rssi_avg_dbm in the bt_devices.rssi_dbm column."""
        resp = client.post(
            "/api/bluetooth/ingest-summary",
            json={
                "node_id": bt_node,
                "scan_period_s": 30.0,
                "total_observations": 10,
                "devices": [
                    _make_bt_summary_device(
                        device_addr="11:22:33:44:55:66",
                        rssi_avg_dbm=-72.5,
                        rssi_max_dbm=-40.0,
                    )
                ],
            },
        )
        assert resp.status_code == 201
        # Round-trip through the listing endpoint to confirm the avg was stored.
        listing = client.get("/api/bluetooth/devices").json()
        rows = [
            d
            for d in listing.get("devices", [])
            if d["device_addr"] == "11:22:33:44:55:66"
        ]
        assert rows, "summary device should appear in device listing"
        assert rows[0]["avg_rssi_dbm"] == pytest.approx(-72.5)

    def test_summary_requires_auth(self, unauth_client: TestClient, bt_node: str):
        """Unauthenticated summary ingest is rejected."""
        resp = unauth_client.post(
            "/api/bluetooth/ingest-summary",
            json={
                "node_id": bt_node,
                "devices": [_make_bt_summary_device()],
            },
        )
        assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# TestBtDevices
# ---------------------------------------------------------------------------


class TestBtDevices:
    """Tests for GET /api/bluetooth/devices and /devices/{addr}."""

    def test_get_devices(self, client: TestClient, bt_node: str):
        """GET /devices returns a list of ingested devices."""
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(
                        device_addr="aa:bb:cc:11:22:33", device_name="Dev1"
                    ),
                    _make_bt_record(
                        device_addr="dd:ee:ff:44:55:66", device_name="Dev2"
                    ),
                ],
            },
        )
        resp = client.get("/api/bluetooth/devices")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 2
        assert isinstance(data["devices"], list)

    def test_get_devices_filter_type(self, client: TestClient, bt_node: str):
        """Filtering by device_type=ble returns only BLE devices."""
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(device_addr="aa:bb:cc:11:22:33", device_type="ble"),
                    _make_bt_record(
                        device_addr="dd:ee:ff:44:55:66", device_type="classic"
                    ),
                ],
            },
        )
        resp = client.get("/api/bluetooth/devices?device_type=ble")
        assert resp.status_code == 200
        data = resp.json()
        for dev in data["devices"]:
            assert dev["device_type"] == "ble"

    def test_get_device_detail(self, client: TestClient, bt_node: str):
        """GET /devices/{addr} returns device info and timeline."""
        addr = "aa:bb:cc:11:22:33"
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [_make_bt_record(device_addr=addr, device_name="DetailDev")],
            },
        )
        resp = client.get(f"/api/bluetooth/devices/{addr}")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["device"], dict)
        assert data["device"]["device_addr"] == addr
        assert isinstance(data["timeline"], list)

    def test_get_device_detail_not_found(self, client: TestClient):
        """Unknown device address returns 404."""
        resp = client.get("/api/bluetooth/devices/xx:xx:xx:xx:xx:xx")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestBtStats
# ---------------------------------------------------------------------------


class TestBtStats:
    """Tests for GET /api/bluetooth/stats."""

    def test_get_stats(self, client: TestClient, bt_node: str):
        """Stats endpoint returns correct structure after ingest."""
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(device_addr="aa:bb:cc:11:22:33", device_type="ble"),
                    _make_bt_record(
                        device_addr="dd:ee:ff:44:55:66", device_type="classic"
                    ),
                ],
            },
        )
        resp = client.get("/api/bluetooth/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_devices"] >= 2
        assert isinstance(data["type_breakdown"], dict)
        assert isinstance(data["top_manufacturers"], list)
        assert isinstance(data["active_bt_nodes"], list)

    def test_get_stats_empty(self, client: TestClient):
        """Stats returns zeros when no data has been ingested."""
        resp = client.get("/api/bluetooth/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_devices"] == 0
        assert data["type_breakdown"] == {}
        assert data["top_manufacturers"] == []


# ---------------------------------------------------------------------------
# TestBtAnomalies
# ---------------------------------------------------------------------------


class TestBtAnomalies:
    """Tests for anomaly query, dismiss, and snooze endpoints."""

    def _insert_anomaly(
        self, client: TestClient, bt_node: str, addr: str = "aa:bb:cc:11:22:33"
    ):
        """Ingest a device twice with a name change to trigger an anomaly."""
        # First ingest to establish baseline
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(
                        device_addr=addr,
                        device_name="OriginalName",
                        rssi_dbm=-50.0,
                    )
                ],
            },
        )
        # Second ingest with different name to trigger spoofed_identity
        client.post(
            "/api/bluetooth/ingest",
            json={
                "node_id": bt_node,
                "records": [
                    _make_bt_record(
                        device_addr=addr,
                        device_name="SpoofedName",
                        rssi_dbm=-50.0,
                    )
                ],
            },
        )

    def _insert_anomaly_direct(
        self, client: TestClient, detection_store, addr: str = "aa:bb:cc:99:88:77"
    ):
        """Insert an anomaly row directly into the store for deterministic testing."""
        detection_store.insert_bt_anomalies_batch(
            [
                {
                    "device_addr": addr,
                    "device_name": "DirectAnomaly",
                    "device_type": "ble",
                    "device_class": 0,
                    "device_class_name": "",
                    "manufacturer": "TestMfr",
                    "vendor": "",
                    "rssi_dbm": -60.0,
                    "anomaly_score": 0.8,
                    "priority": "warning",
                    "dimensions": {"rogue_device": 1.0},
                    "reasons": ["New device"],
                    "baseline_status": "new",
                    "node_id": "bt-node-01",
                    "timestamp": "2026-02-15T12:00:00+00:00",
                }
            ]
        )

    def test_get_anomalies(self, client: TestClient, detection_store, bt_node: str):
        """GET /anomalies returns a list of anomalies."""
        self._insert_anomaly_direct(client, detection_store)
        resp = client.get("/api/bluetooth/anomalies?min_score=0.0")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["count"], int)
        assert isinstance(data["total"], int)
        assert isinstance(data["anomalies"], list)
        assert data["count"] >= 1

    def test_dismiss_anomaly(self, client: TestClient, detection_store, bt_node: str):
        """PUT /anomalies/{id}/dismiss marks an anomaly as dismissed."""
        self._insert_anomaly_direct(client, detection_store, addr="dd:11:22:33:44:55")
        # Get the anomaly ID
        resp = client.get("/api/bluetooth/anomalies?min_score=0.0")
        anomalies = resp.json()["anomalies"]
        assert len(anomalies) >= 1
        anomaly_id = anomalies[0]["id"]

        resp = client.put(f"/api/bluetooth/anomalies/{anomaly_id}/dismiss")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["dismissed"] == anomaly_id

    def test_snooze_anomaly(self, client: TestClient, detection_store, bt_node: str):
        """PUT /anomalies/{id}/snooze snoozes an anomaly for given hours."""
        self._insert_anomaly_direct(client, detection_store, addr="ee:11:22:33:44:55")
        resp = client.get("/api/bluetooth/anomalies?min_score=0.0")
        anomalies = resp.json()["anomalies"]
        assert len(anomalies) >= 1
        anomaly_id = anomalies[0]["id"]

        resp = client.put(
            f"/api/bluetooth/anomalies/{anomaly_id}/snooze",
            json={"hours": 4},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["snoozed"] == anomaly_id
        assert isinstance(data["snoozed_until"], str)

    def test_bulk_dismiss(self, client: TestClient, detection_store, bt_node: str):
        """PUT /anomalies/bulk/dismiss dismisses multiple anomalies."""
        # Insert two anomalies with different addresses
        self._insert_anomaly_direct(client, detection_store, addr="f1:11:22:33:44:55")
        self._insert_anomaly_direct(client, detection_store, addr="f2:11:22:33:44:55")

        resp = client.get("/api/bluetooth/anomalies?min_score=0.0")
        anomalies = resp.json()["anomalies"]
        ids = [a["id"] for a in anomalies[:2]]
        assert len(ids) >= 1

        resp = client.put("/api/bluetooth/anomalies/bulk/dismiss", json={"ids": ids})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["dismissed_count"] >= 1

    def test_dismiss_requires_analyst(
        self,
        viewer_client: TestClient,
        client: TestClient,
        detection_store,
        bt_node: str,
    ):
        """VIEWER role cannot dismiss anomalies (requires ANALYST)."""
        self._insert_anomaly_direct(client, detection_store, addr="a1:22:33:44:55:66")
        resp = client.get("/api/bluetooth/anomalies?min_score=0.0")
        anomalies = resp.json()["anomalies"]
        assert len(anomalies) >= 1
        anomaly_id = anomalies[0]["id"]

        resp = viewer_client.put(f"/api/bluetooth/anomalies/{anomaly_id}/dismiss")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TestBtScorer
# ---------------------------------------------------------------------------


class TestBtScorer:
    """Unit tests for BtAnomalyScorer and BtBaselineManager."""

    def test_new_device_detection(self):
        """A brand-new device gets a rogue_device dimension score of 1.0."""
        mgr = BtBaselineManager()
        scorer = BtAnomalyScorer(mgr)

        records = [
            {
                "device_addr": "aa:bb:cc:dd:ee:ff",
                "device_name": "NewGadget",
                "device_type": "ble",
                "device_class": 0,
                "manufacturer": "Acme",
                "rssi_dbm": -60.0,
                "service_uuids": [],
            }
        ]

        results = scorer.score_batch(records, "node-01")
        assert len(results) >= 1
        result = results[0]
        assert result.dimensions["rogue_device"] == 1.0
        assert result.baseline_status == "new"
        assert result.anomaly_score > 0

    def test_identity_spoof_detection(self):
        """Device name change after baseline established triggers spoofed_identity."""
        mgr = BtBaselineManager()
        scorer = BtAnomalyScorer(mgr)

        # Build baseline with several observations
        for _ in range(5):
            scorer.score_batch(
                [
                    {
                        "device_addr": "11:22:33:44:55:66",
                        "device_name": "OriginalName",
                        "device_type": "ble",
                        "device_class": 0x20010C,
                        "manufacturer": "Acme",
                        "rssi_dbm": -55.0,
                        "service_uuids": [],
                    }
                ],
                "node-01",
            )

        # Now change the device name
        results = scorer.score_batch(
            [
                {
                    "device_addr": "11:22:33:44:55:66",
                    "device_name": "HackedName",
                    "device_type": "ble",
                    "device_class": 0x20010C,
                    "manufacturer": "Acme",
                    "rssi_dbm": -55.0,
                    "service_uuids": [],
                }
            ],
            "node-01",
        )

        assert len(results) >= 1
        result = results[0]
        assert result.dimensions["spoofed_identity"] >= 0.7
        assert any("Spoofed identity" in r for r in result.reasons)

    def test_service_change_detection(self):
        """Service UUID change from baseline triggers service_change dimension."""
        mgr = BtBaselineManager()
        scorer = BtAnomalyScorer(mgr)

        # Build baseline with a known service UUID
        for _ in range(5):
            scorer.score_batch(
                [
                    {
                        "device_addr": "22:33:44:55:66:77",
                        "device_name": "SvcDevice",
                        "device_type": "ble",
                        "device_class": 0,
                        "manufacturer": "Acme",
                        "rssi_dbm": -50.0,
                        "service_uuids": ["0000180a-0000-1000-8000-00805f9b34fb"],
                    }
                ],
                "node-01",
            )

        # Add a new service UUID (existing ones still present + new one)
        results = scorer.score_batch(
            [
                {
                    "device_addr": "22:33:44:55:66:77",
                    "device_name": "SvcDevice",
                    "device_type": "ble",
                    "device_class": 0,
                    "manufacturer": "Acme",
                    "rssi_dbm": -50.0,
                    "service_uuids": [
                        "0000180a-0000-1000-8000-00805f9b34fb",
                        "0000dead-0000-1000-8000-00805f9b34fb",
                    ],
                }
            ],
            "node-01",
        )

        assert len(results) >= 1
        result = results[0]
        # New UUID added -> score should be 0.5
        assert result.dimensions["service_change"] >= 0.5

    def test_learning_dampening(self):
        """During learning phase (< 30 observations), composite scores are dampened."""
        mgr = BtBaselineManager()
        scorer = BtAnomalyScorer(mgr)

        # First observation -> new device, learning phase
        results = scorer.score_batch(
            [
                {
                    "device_addr": "33:44:55:66:77:88",
                    "device_name": "LearnDev",
                    "device_type": "ble",
                    "device_class": 0,
                    "manufacturer": "Acme",
                    "rssi_dbm": -60.0,
                    "service_uuids": [],
                }
            ],
            "node-01",
        )

        assert len(results) >= 1
        first_score = results[0].anomaly_score
        assert results[0].baseline_status == "new"

        # After a few more observations, the device is still in learning
        for _ in range(3):
            scorer.score_batch(
                [
                    {
                        "device_addr": "33:44:55:66:77:88",
                        "device_name": "LearnDev",
                        "device_type": "ble",
                        "device_class": 0,
                        "manufacturer": "Acme",
                        "rssi_dbm": -60.0,
                        "service_uuids": [],
                    }
                ],
                "node-01",
            )

        baseline = mgr.get("33:44:55:66:77:88")
        assert isinstance(baseline, BtBaseline)
        assert baseline.is_learning() is True
        assert baseline.total_observations < 30

    def test_reevaluate(self):
        """Reevaluation of a known device returns a valid BtAnomalyResult."""
        mgr = BtBaselineManager()
        scorer = BtAnomalyScorer(mgr)

        # Build baseline
        for _ in range(5):
            scorer.score_batch(
                [
                    {
                        "device_addr": "44:55:66:77:88:99",
                        "device_name": "ReEvalDev",
                        "device_type": "ble",
                        "device_class": 0,
                        "manufacturer": "Acme",
                        "rssi_dbm": -50.0,
                        "service_uuids": [],
                    }
                ],
                "node-01",
            )

        result = scorer.reevaluate(
            {
                "device_addr": "44:55:66:77:88:99",
                "device_name": "ReEvalDev",
                "device_type": "ble",
                "device_class": 0,
                "manufacturer": "Acme",
                "rssi_dbm": -50.0,
                "service_uuids": [],
                "node_id": "node-01",
            }
        )

        assert result.device_addr == "44:55:66:77:88:99"
        assert result.anomaly_score >= 0.0
        assert isinstance(result.dimensions["rogue_device"], (int, float))
        assert isinstance(result.dimensions["spoofed_identity"], (int, float))
        # Known device should not be flagged as rogue
        assert result.dimensions["rogue_device"] == 0.0


# ---------------------------------------------------------------------------
# TestBtWebSocket
# ---------------------------------------------------------------------------


class TestBtWebSocket:
    """Tests for the Bluetooth WebSocket endpoint."""

    def test_ws_connect_and_ping(self, client: TestClient, master_key: str):
        """WebSocket connects and responds to ping with pong."""
        with client.websocket_connect(
            "/api/bluetooth/ws/bluetooth",
            subprotocols=["bridge-v1", master_key],
        ) as ws:
            ws.send_text("ping")
            resp = ws.receive_text()
            assert resp == "pong"


# ---------------------------------------------------------------------------
# TestBtScannerSummarize — exercises the edge aggregator without networking
# ---------------------------------------------------------------------------


class TestBtScannerSummarize:
    """Unit tests for ``BtScanner._absorb`` aggregation behaviour."""

    def _scanner(self):
        from sigrift.lib.bt_scanner import BtScanner

        return BtScanner(
            server_url="http://example.invalid",
            api_key="k",
            node_id="n",
            summarize=True,
        )

    def test_absorb_collapses_same_address(self):
        s = self._scanner()
        s._absorb(
            [
                {
                    "device_addr": "AA:BB",
                    "rssi_dbm": -40,
                    "device_name": "x",
                    "device_type": "ble",
                    "channel": 37,
                    "service_uuids": ["a"],
                },
                {
                    "device_addr": "AA:BB",
                    "rssi_dbm": -60,
                    "device_name": "x",
                    "channel": 37,
                    "service_uuids": ["a", "b"],
                },
            ]
        )
        assert set(s._agg) == {"AA:BB"}
        entry = s._agg["AA:BB"]
        assert entry["observation_count"] == 2
        assert entry["rssi_max"] == -40
        assert entry["rssi_sum"] == -100
        assert entry["service_uuids"] == ["a", "b"]
        assert s._agg_total_obs == 2

    def test_absorb_keeps_per_address_entries(self):
        s = self._scanner()
        s._absorb(
            [
                {"device_addr": "AA:BB", "rssi_dbm": -50, "device_type": "ble"},
                {"device_addr": "CC:DD", "rssi_dbm": -70, "device_type": "classic"},
            ]
        )
        assert set(s._agg) == {"AA:BB", "CC:DD"}
        assert s._agg_total_obs == 2

    def test_absorb_ignores_blank_address(self):
        s = self._scanner()
        s._absorb([{"device_addr": "", "rssi_dbm": -50}])
        assert s._agg == {}
        assert s._agg_total_obs == 0

    def test_env_truthy_defaults_on(self, monkeypatch):
        from sigrift.lib.bt_scanner import _env_truthy

        monkeypatch.delenv("MLRF_SUMMARIZE", raising=False)
        assert _env_truthy("MLRF_SUMMARIZE", default=True) is True
        monkeypatch.setenv("MLRF_SUMMARIZE", "0")
        assert _env_truthy("MLRF_SUMMARIZE", default=True) is False
        monkeypatch.setenv("MLRF_SUMMARIZE", "yes")
        assert _env_truthy("MLRF_SUMMARIZE", default=False) is True
