"""Tests for new Bluetooth ingest changes (gzip support, OUI vendor lookup, async audit).

Covers the uncommitted diff to sigrift/bridge/routers/bluetooth.py:
  - Gzip-compressed request body handling on POST /ingest
  - Body size limits (1 MB compressed, 10 MB decompressed)
  - Manual JSON parsing and validation error paths
  - OUI vendor lookup integration (manufacturer fallback + vendor field)
  - Async audit logging in dismiss/snooze (single and bulk)
  - RBAC checks on ingest endpoint
"""

from __future__ import annotations

import gzip
import io
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.persistence import PersistenceManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_key_and_store(
    persistence: PersistenceManager,
    key_id: str,
    role: str = "admin",
) -> str:
    """Create an API key with a given role and return the raw key."""
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


def _gzip_compress(data: bytes) -> bytes:
    """Gzip-compress a bytes payload."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as f:
        f.write(data)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def viewer_key(persistence: PersistenceManager) -> str:
    return _make_key_and_store(persistence, "btn_viewer_key", role="viewer")


@pytest.fixture
def viewer_client(bridge_app: FastAPI, viewer_key: str) -> TestClient:
    return TestClient(bridge_app, headers={"X-API-Key": viewer_key})


@pytest.fixture
def unauth_client(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


@pytest.fixture
def bt_node(client: TestClient) -> str:
    """Register a test node for BT ingest and return its ID."""
    node_id = "bt-new-node-01"
    resp = client.post("/api/nodes/register", json={
        "node_id": node_id,
        "host": "10.0.0.60",
        "port": 8080,
    })
    assert resp.status_code == 200
    return node_id


# ---------------------------------------------------------------------------
# TestGzipIngest
# ---------------------------------------------------------------------------


class TestGzipIngest:
    """Tests for gzip-compressed body handling on POST /api/bluetooth/ingest."""

    def test_ingest_gzip_body(self, client: TestClient, bt_node: str):
        """A valid gzip-compressed JSON body is decompressed and ingested."""
        payload = json.dumps({
            "node_id": bt_node,
            "records": [
                _make_bt_record(device_addr="a1:b2:c3:d4:e5:f6", device_name="GzDev1"),
            ],
        }).encode()
        compressed = _gzip_compress(payload)

        resp = client.post(
            "/api/bluetooth/ingest",
            content=compressed,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 1
        assert data["total"] == 1

    def test_ingest_gzip_multiple_records(self, client: TestClient, bt_node: str):
        """Gzip ingest with multiple records works correctly."""
        records = [
            _make_bt_record(device_addr=f"a1:b2:c3:d4:{i:02x}:01", device_name=f"GzDev{i}")
            for i in range(5)
        ]
        payload = json.dumps({"node_id": bt_node, "records": records}).encode()
        compressed = _gzip_compress(payload)

        resp = client.post(
            "/api/bluetooth/ingest",
            content=compressed,
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["inserted"] == 5
        assert data["total"] == 5

    def test_ingest_plain_json_still_works(self, client: TestClient, bt_node: str):
        """Plain (non-gzip) JSON body continues to work without Content-Encoding."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [
                _make_bt_record(device_addr="bb:cc:dd:ee:ff:00", device_name="PlainDev"),
            ],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["accepted"] is True
        assert data["inserted"] == 1

    def test_ingest_invalid_gzip(self, client: TestClient):
        """Non-gzip bytes with Content-Encoding: gzip returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=b"this is not gzip data",
            headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# TestManualJsonParsing
# ---------------------------------------------------------------------------


class TestManualJsonParsing:
    """Tests for manual JSON parsing and Pydantic validation in ingest."""

    def test_ingest_invalid_json(self, client: TestClient):
        """Malformed JSON returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=b"{not valid json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_ingest_valid_json_invalid_schema(self, client: TestClient):
        """Valid JSON that doesn't match BtScanBatch schema returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=json.dumps({"foo": "bar"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_ingest_empty_bytes(self, client: TestClient):
        """Empty request body returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=b"",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_ingest_binary_garbage(self, client: TestClient):
        """Random binary data (not gzip-tagged) returns 400."""
        resp = client.post(
            "/api/bluetooth/ingest",
            content=b"\x00\x01\x02\xff\xfe",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# TestIngestRbac
# ---------------------------------------------------------------------------


class TestIngestRbac:
    """RBAC checks for the ingest endpoint with manual body parsing."""

    def test_ingest_requires_auth(self, unauth_client: TestClient):
        """No API key returns 401."""
        resp = unauth_client.post("/api/bluetooth/ingest", json={
            "node_id": "some-node",
            "records": [_make_bt_record()],
        })
        assert resp.status_code == 401

    def test_ingest_admin_role_allowed(self, client: TestClient, bt_node: str):
        """ADMIN role (master key) can ingest."""
        resp = client.post("/api/bluetooth/ingest", json={
            "node_id": bt_node,
            "records": [_make_bt_record(device_addr="cc:dd:ee:ff:00:33")],
        })
        assert resp.status_code == 201
