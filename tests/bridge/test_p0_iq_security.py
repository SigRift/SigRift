"""Tests for P0-3 (ANALYST role for raw IQ) and P0-5 (iq_download audit logging).

Validates that:
  - VIEWER can access format=json (visualization metadata)
  - VIEWER is denied format=raw (interceptable communications)
  - ANALYST and ADMIN can access format=raw
  - All IQ downloads produce an ``iq_download`` audit log entry
  - Audit log details include the format field
"""

from __future__ import annotations

import gzip

import numpy as np
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.iq_store import IQStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_iq_data() -> bytes:
    """Create a small gzip-compressed IQ capture (float32 interleaved)."""
    n_samples = 256
    t = np.linspace(0, 1, n_samples, dtype=np.float32)
    i_vals = np.cos(2 * np.pi * 10 * t).astype(np.float32)
    q_vals = np.sin(2 * np.pi * 10 * t).astype(np.float32)
    interleaved = np.empty(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = i_vals
    interleaved[1::2] = q_vals
    return gzip.compress(interleaved.tobytes())


def _create_key(persistence, key_id: str, role: str) -> str:
    """Create an API key with a specific role and return the raw key."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role})
    return raw_key


def _seed_iq(iq_store: IQStore, detection_id: str) -> None:
    """Store a test IQ capture for the given detection."""
    iq_store.store(detection_id, _make_iq_data())


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def iq_store(tmp_path):
    """Create an IQStore backed by a temp directory."""
    return IQStore(base_dir=tmp_path / "iq_captures")


@pytest.fixture()
def det_id(bridge_app: FastAPI, iq_store: IQStore) -> str:
    """Wire the IQ store into the bridge app, seed IQ data, return detection ID."""
    bridge_app.state.iq_store = iq_store
    detection_id = "test-det-001"
    _seed_iq(iq_store, detection_id)
    return detection_id


# ---------------------------------------------------------------------------
# P0-3: Role elevation tests
# ---------------------------------------------------------------------------


class TestIQRoleElevation:
    """VIEWER may access json but NOT raw; ANALYST and ADMIN may access raw."""

    def test_iq_json_viewer_allowed(
        self, bridge_app: FastAPI, persistence, det_id: str,
    ):
        """VIEWER can retrieve format=json (visualization metadata)."""
        viewer_key = _create_key(persistence, "viewer-test", "VIEWER")
        c = TestClient(bridge_app, headers={"X-API-Key": viewer_key})

        resp = c.get(f"/api/detections/{det_id}/iq?format=json")
        assert resp.status_code == 200
        data = resp.json()
        assert "constellation_x" in data
        assert isinstance(data["constellation_x"], list)
        assert "psd_db" in data
        assert isinstance(data["psd_db"], list)

    def test_iq_raw_viewer_denied(
        self, bridge_app: FastAPI, persistence, det_id: str,
    ):
        """VIEWER gets 403 when requesting format=raw."""
        viewer_key = _create_key(persistence, "viewer-test", "VIEWER")
        c = TestClient(bridge_app, headers={"X-API-Key": viewer_key})

        resp = c.get(f"/api/detections/{det_id}/iq?format=raw")
        assert resp.status_code == 403
        assert "ANALYST" in resp.json()["detail"]

    def test_iq_raw_analyst_allowed(
        self, bridge_app: FastAPI, persistence, det_id: str,
    ):
        """ANALYST can retrieve format=raw."""
        analyst_key = _create_key(persistence, "analyst-test", "ANALYST")
        c = TestClient(bridge_app, headers={"X-API-Key": analyst_key})

        resp = c.get(f"/api/detections/{det_id}/iq?format=raw")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"

    def test_iq_raw_admin_allowed(
        self, bridge_app: FastAPI, persistence, det_id: str, master_key: str,
    ):
        """ADMIN can retrieve format=raw."""
        c = TestClient(bridge_app, headers={"X-API-Key": master_key})

        resp = c.get(f"/api/detections/{det_id}/iq?format=raw")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/octet-stream"


# ---------------------------------------------------------------------------
# P0-5: Audit logging tests
# ---------------------------------------------------------------------------


class TestIQDownloadAudit:
    """IQ downloads must produce ``iq_download`` audit entries."""

    def test_iq_download_audit_logged(
        self, bridge_app: FastAPI, persistence, detection_store, det_id: str,
    ):
        """After a JSON download, an iq_download audit entry exists."""
        viewer_key = _create_key(persistence, "viewer-audit", "VIEWER")
        c = TestClient(bridge_app, headers={"X-API-Key": viewer_key})

        resp = c.get(f"/api/detections/{det_id}/iq?format=json")
        assert resp.status_code == 200

        logs = detection_store.get_audit_log(action="iq_download", limit=10)
        assert len(logs) >= 1
        assert isinstance(logs, list)
        assert logs[0]["action"] == "iq_download"
        assert logs[0]["target_id"] == det_id

    def test_iq_download_audit_includes_format(
        self, bridge_app: FastAPI, persistence, detection_store, det_id: str,
    ):
        """Audit log details include the format field for both json and raw."""
        analyst_key = _create_key(persistence, "analyst-audit", "ANALYST")
        c = TestClient(bridge_app, headers={"X-API-Key": analyst_key})

        # Download raw
        resp = c.get(f"/api/detections/{det_id}/iq?format=raw")
        assert resp.status_code == 200

        # Download json
        resp = c.get(f"/api/detections/{det_id}/iq?format=json")
        assert resp.status_code == 200

        logs = detection_store.get_audit_log(action="iq_download", limit=10)
        assert isinstance(logs, list)
        assert len(logs) >= 2

        formats_logged = {entry["details"]["format"] for entry in logs if "details" in entry and entry["details"]}
        assert "raw" in formats_logged
        assert "json" in formats_logged
