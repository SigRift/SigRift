"""Tests for P1-9: IQ metadata index + tiered retention.

Covers:
  - IQMetadataStore CRUD operations
  - Query with filters (node_id, signal_class, freq_range, tier)
  - Tier setting and expiry calculation
  - get_expired returns only expired entries
  - cleanup_expired removes files and metadata
  - API endpoints: /api/iq/index, /api/iq/stats, /api/iq/cleanup
  - PUT /api/detections/{id}/iq/tier with RBAC (ADMIN required)
"""

from __future__ import annotations

import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from sigrift.bridge.iq_store import IQStore
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.iq_metadata import IQMetadataStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path: Path) -> SharedContext:
    """SharedContext backed by a temp database."""
    return SharedContext(db_path=tmp_path / "test.db")


@pytest.fixture
def iq_meta(ctx: SharedContext) -> IQMetadataStore:
    """IQMetadataStore for testing."""
    return IQMetadataStore(ctx)


@pytest.fixture
def iq_store(tmp_path: Path) -> IQStore:
    """IQStore backed by a temp directory."""
    return IQStore(base_dir=tmp_path / "iq_captures")


def _make_iq_bytes(n_samples: int = 256) -> bytes:
    """Create gzip-compressed float32 IQ data."""
    floats = np.random.randn(n_samples * 2).astype(np.float32)
    return gzip.compress(floats.tobytes())


def _make_metadata(
    node_id: str = "node-01",
    freq_hz: float = 433.92e6,
    signal_class: str = "bpsk",
    tier: str = "standard",
    captured_at: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Create a metadata dict for testing."""
    if captured_at is None:
        captured_at = datetime.now(timezone.utc).isoformat()
    return {
        "node_id": node_id,
        "freq_hz": freq_hz,
        "signal_class": signal_class,
        "sample_rate": 2.048e6,
        "n_samples": 256,
        "file_size_bytes": 1024,
        "quality_score": 0.85,
        "captured_at": captured_at,
        "tier": tier,
        **kwargs,
    }


# ---------------------------------------------------------------------------
# Unit tests — IQMetadataStore
# ---------------------------------------------------------------------------

class TestIQMetadataStore:
    """Tests for IQMetadataStore storage operations."""

    def test_index_and_get_metadata(self, iq_meta: IQMetadataStore) -> None:
        """index_capture stores metadata; get_metadata retrieves it."""
        meta = _make_metadata()
        iq_meta.index_capture("det-001", meta)

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["detection_id"] == "det-001"
        assert result["node_id"] == "node-01"
        assert result["signal_class"] == "bpsk"
        assert result["quality_score"] == 0.85
        assert result["tier"] == "standard"

    def test_get_metadata_not_found(self, iq_meta: IQMetadataStore) -> None:
        """get_metadata returns None for nonexistent detection."""
        assert iq_meta.get_metadata("nonexistent") is None

    def test_index_capture_upsert(self, iq_meta: IQMetadataStore) -> None:
        """index_capture with the same detection_id replaces the entry."""
        iq_meta.index_capture("det-001", _make_metadata(signal_class="bpsk"))
        iq_meta.index_capture("det-001", _make_metadata(signal_class="qpsk"))

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["signal_class"] == "qpsk"

    def test_query_no_filters(self, iq_meta: IQMetadataStore) -> None:
        """query() with no filters returns all entries."""
        for i in range(5):
            iq_meta.index_capture(f"det-{i:03d}", _make_metadata())

        results = iq_meta.query()
        assert len(results) == 5

    def test_query_by_node_id(self, iq_meta: IQMetadataStore) -> None:
        """query(node_id=...) filters by node."""
        iq_meta.index_capture("det-001", _make_metadata(node_id="node-01"))
        iq_meta.index_capture("det-002", _make_metadata(node_id="node-02"))
        iq_meta.index_capture("det-003", _make_metadata(node_id="node-01"))

        results = iq_meta.query(node_id="node-01")
        assert len(results) == 2
        assert all(r["node_id"] == "node-01" for r in results)

    def test_query_by_signal_class(self, iq_meta: IQMetadataStore) -> None:
        """query(signal_class=...) filters by signal class."""
        iq_meta.index_capture("det-001", _make_metadata(signal_class="bpsk"))
        iq_meta.index_capture("det-002", _make_metadata(signal_class="qam16"))

        results = iq_meta.query(signal_class="qam16")
        assert len(results) == 1
        assert results[0]["signal_class"] == "qam16"

    def test_query_by_freq_range(self, iq_meta: IQMetadataStore) -> None:
        """query(freq_range=...) filters by frequency band."""
        iq_meta.index_capture("det-001", _make_metadata(freq_hz=433.92e6))
        iq_meta.index_capture("det-002", _make_metadata(freq_hz=915.0e6))
        iq_meta.index_capture("det-003", _make_metadata(freq_hz=2400.0e6))

        results = iq_meta.query(freq_range=(400e6, 1000e6))
        assert len(results) == 2

    def test_query_by_tier(self, iq_meta: IQMetadataStore) -> None:
        """query(tier=...) filters by retention tier."""
        iq_meta.index_capture("det-001", _make_metadata(tier="critical"))
        iq_meta.index_capture("det-002", _make_metadata(tier="standard"))
        iq_meta.index_capture("det-003", _make_metadata(tier="temporary"))

        results = iq_meta.query(tier="critical")
        assert len(results) == 1
        assert results[0]["tier"] == "critical"

    def test_query_limit(self, iq_meta: IQMetadataStore) -> None:
        """query(limit=N) respects the limit."""
        for i in range(10):
            iq_meta.index_capture(f"det-{i:03d}", _make_metadata())

        results = iq_meta.query(limit=3)
        assert len(results) == 3

    def test_set_tier_standard_to_critical(self, iq_meta: IQMetadataStore) -> None:
        """set_tier changes the tier and recalculates expires_at."""
        iq_meta.index_capture("det-001", _make_metadata(tier="standard"))

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["tier"] == "standard"
        assert result["expires_at"] is not None  # standard has 30-day TTL
        assert isinstance(result["expires_at"], str)

        updated = iq_meta.set_tier("det-001", "critical")
        assert updated is True

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["tier"] == "critical"
        assert result["expires_at"] is None  # critical never expires

    def test_set_tier_with_custom_ttl(self, iq_meta: IQMetadataStore) -> None:
        """set_tier with ttl_hours overrides the default."""
        iq_meta.index_capture("det-001", _make_metadata(tier="standard"))

        iq_meta.set_tier("det-001", "standard", ttl_hours=48)

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["expires_at"] is not None
        assert isinstance(result["expires_at"], str)
        expires = datetime.fromisoformat(result["expires_at"])
        # Should be about 48 hours from now (within 1 minute tolerance)
        expected = datetime.now(timezone.utc) + timedelta(hours=48)
        assert abs((expires - expected).total_seconds()) < 60

    def test_set_tier_invalid(self, iq_meta: IQMetadataStore) -> None:
        """set_tier raises ValueError for invalid tier name."""
        iq_meta.index_capture("det-001", _make_metadata())
        with pytest.raises(ValueError, match="Invalid tier"):
            iq_meta.set_tier("det-001", "invalid_tier")

    def test_set_tier_not_found(self, iq_meta: IQMetadataStore) -> None:
        """set_tier returns False for nonexistent detection."""
        assert iq_meta.set_tier("nonexistent", "critical") is False

    def test_get_expired_returns_only_expired(self, iq_meta: IQMetadataStore) -> None:
        """get_expired returns only entries past their expires_at."""
        now = datetime.now(timezone.utc)

        # Entry that expired 1 hour ago
        past = (now - timedelta(hours=1)).isoformat()
        iq_meta.index_capture("det-expired", _make_metadata(
            tier="temporary",
            captured_at=(now - timedelta(hours=25)).isoformat(),
        ))

        # Entry that expires in the future
        iq_meta.index_capture("det-fresh", _make_metadata(tier="standard"))

        # Critical entry (never expires)
        iq_meta.index_capture("det-critical", _make_metadata(tier="critical"))

        expired = iq_meta.get_expired()
        assert "det-expired" in expired
        assert "det-fresh" not in expired
        assert "det-critical" not in expired

    def test_delete_metadata(self, iq_meta: IQMetadataStore) -> None:
        """delete_metadata removes the entry."""
        iq_meta.index_capture("det-001", _make_metadata())
        assert iq_meta.get_metadata("det-001") is not None
        assert isinstance(iq_meta.get_metadata("det-001"), dict)

        deleted = iq_meta.delete_metadata("det-001")
        assert deleted is True
        assert iq_meta.get_metadata("det-001") is None

    def test_delete_metadata_not_found(self, iq_meta: IQMetadataStore) -> None:
        """delete_metadata returns False for nonexistent entry."""
        assert iq_meta.delete_metadata("nonexistent") is False

    def test_get_stats(self, iq_meta: IQMetadataStore) -> None:
        """get_stats returns counts by tier, total size, date range."""
        iq_meta.index_capture("det-001", _make_metadata(
            tier="critical", file_size_bytes=1000,
        ))
        iq_meta.index_capture("det-002", _make_metadata(
            tier="standard", file_size_bytes=2000,
        ))
        iq_meta.index_capture("det-003", _make_metadata(
            tier="standard", file_size_bytes=3000,
        ))

        stats = iq_meta.get_stats()
        assert stats["total_captures"] == 3
        assert stats["total_size_bytes"] == 6000
        assert stats["by_tier"]["critical"] == 1
        assert stats["by_tier"]["standard"] == 2
        assert stats["oldest_capture"] is not None
        assert isinstance(stats["oldest_capture"], str)
        assert stats["newest_capture"] is not None
        assert isinstance(stats["newest_capture"], str)

    def test_get_stats_empty(self, iq_meta: IQMetadataStore) -> None:
        """get_stats on empty store returns zeros."""
        stats = iq_meta.get_stats()
        assert stats["total_captures"] == 0
        assert stats["total_size_bytes"] == 0
        assert stats["by_tier"] == {}

    def test_cleanup_expired_removes_files_and_metadata(
        self,
        iq_meta: IQMetadataStore,
        iq_store: IQStore,
    ) -> None:
        """cleanup_expired deletes expired IQ files and metadata entries."""
        now = datetime.now(timezone.utc)

        # Store an actual IQ file
        data = _make_iq_bytes()
        iq_store.store("det-expired", data)
        assert iq_store.exists("det-expired")

        # Index it as expired (temporary tier, captured 25 hours ago)
        iq_meta.index_capture("det-expired", _make_metadata(
            tier="temporary",
            captured_at=(now - timedelta(hours=25)).isoformat(),
        ))

        # Store a non-expired file
        iq_store.store("det-fresh", data)
        iq_meta.index_capture("det-fresh", _make_metadata(tier="critical"))

        # Run cleanup
        removed = iq_meta.cleanup_expired(iq_store)
        assert removed == 1

        # Expired file + metadata gone
        assert not iq_store.exists("det-expired")
        assert iq_meta.get_metadata("det-expired") is None

        # Fresh file + metadata still present
        assert iq_store.exists("det-fresh")
        assert iq_meta.get_metadata("det-fresh") is not None
        assert isinstance(iq_meta.get_metadata("det-fresh"), dict)

    def test_tier_defaults_to_standard(self, iq_meta: IQMetadataStore) -> None:
        """Metadata with no tier defaults to 'standard'."""
        meta = _make_metadata()
        del meta["tier"]
        iq_meta.index_capture("det-001", meta)

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["tier"] == "standard"

    def test_critical_tier_never_expires(self, iq_meta: IQMetadataStore) -> None:
        """Critical tier entries have NULL expires_at."""
        iq_meta.index_capture("det-001", _make_metadata(tier="critical"))

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["expires_at"] is None

    def test_temporary_tier_expires_24h(self, iq_meta: IQMetadataStore) -> None:
        """Temporary tier entries expire ~24 hours after capture."""
        now = datetime.now(timezone.utc)
        iq_meta.index_capture("det-001", _make_metadata(
            tier="temporary",
            captured_at=now.isoformat(),
        ))

        result = iq_meta.get_metadata("det-001")
        assert result is not None
        assert isinstance(result, dict)
        assert result["expires_at"] is not None
        assert isinstance(result["expires_at"], str)
        expires = datetime.fromisoformat(result["expires_at"])
        expected = now + timedelta(hours=24)
        assert abs((expires - expected).total_seconds()) < 60


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestIQMetadataEndpoints:
    """Tests for IQ metadata API endpoints via TestClient."""

    def test_get_iq_index(self, client: Any) -> None:
        """GET /api/iq/index returns empty list when no data."""
        resp = client.get("/api/iq/index")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_iq_stats(self, client: Any) -> None:
        """GET /api/iq/stats returns statistics."""
        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_captures" in data
        assert isinstance(data["total_captures"], int)
        assert "by_tier" in data
        assert isinstance(data["by_tier"], dict)
        assert data["total_captures"] == 0

    def test_iq_index_with_data(self, client: Any, bridge_app: Any) -> None:
        """GET /api/iq/index returns indexed captures."""
        meta_store = bridge_app.state.iq_metadata_store
        meta_store.index_capture("det-001", _make_metadata(node_id="node-01"))
        meta_store.index_capture("det-002", _make_metadata(node_id="node-02"))

        resp = client.get("/api/iq/index")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2

    def test_iq_index_filter_node(self, client: Any, bridge_app: Any) -> None:
        """GET /api/iq/index?node_id=... filters results."""
        meta_store = bridge_app.state.iq_metadata_store
        meta_store.index_capture("det-001", _make_metadata(node_id="node-01"))
        meta_store.index_capture("det-002", _make_metadata(node_id="node-02"))

        resp = client.get("/api/iq/index", params={"node_id": "node-01"})
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["node_id"] == "node-01"

    def test_iq_stats_with_data(self, client: Any, bridge_app: Any) -> None:
        """GET /api/iq/stats reflects indexed data."""
        meta_store = bridge_app.state.iq_metadata_store
        meta_store.index_capture("det-001", _make_metadata(
            tier="critical", file_size_bytes=5000,
        ))

        resp = client.get("/api/iq/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_captures"] == 1
        assert data["total_size_bytes"] == 5000
        assert data["by_tier"]["critical"] == 1

    def test_set_tier_requires_admin(self, client: Any, bridge_app: Any) -> None:
        """PUT /api/detections/{id}/iq/tier requires ADMIN role.

        The master key in our test fixture has ADMIN, so we test that
        a VIEWER-level key gets 403.
        """
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        # Create a viewer key
        viewer_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(viewer_key)
        persistence = bridge_app.state.persistence
        persistence.set_key("viewer-key", hash_hex, salt)
        persistence.set_key_meta("viewer-key", {"role": "viewer", "description": "test viewer"})

        meta_store = bridge_app.state.iq_metadata_store
        meta_store.index_capture("det-001", _make_metadata())

        from fastapi.testclient import TestClient
        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )

        resp = viewer_client.put(
            "/api/detections/det-001/iq/tier",
            json={"tier": "critical"},
        )
        assert resp.status_code == 403

    def test_set_tier_admin_success(self, client: Any, bridge_app: Any) -> None:
        """PUT /api/detections/{id}/iq/tier succeeds for ADMIN."""
        meta_store = bridge_app.state.iq_metadata_store
        meta_store.index_capture("det-001", _make_metadata(tier="standard"))

        resp = client.put(
            "/api/detections/det-001/iq/tier",
            json={"tier": "critical"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["tier"] == "critical"
        assert data["expires_at"] is None

    def test_set_tier_not_found(self, client: Any) -> None:
        """PUT /api/detections/{id}/iq/tier returns 404 for unknown detection."""
        resp = client.put(
            "/api/detections/nonexistent/iq/tier",
            json={"tier": "critical"},
        )
        assert resp.status_code == 404

    def test_cleanup_endpoint(self, client: Any, bridge_app: Any) -> None:
        """POST /api/iq/cleanup triggers expired capture cleanup."""
        resp = client.post("/api/iq/cleanup")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["removed"] == 0  # nothing to clean up

    def test_cleanup_requires_admin(self, client: Any, bridge_app: Any) -> None:
        """POST /api/iq/cleanup requires ADMIN role."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        from fastapi.testclient import TestClient

        viewer_key = generate_api_key(length=32)
        hash_hex, salt = hash_credential(viewer_key)
        persistence = bridge_app.state.persistence
        persistence.set_key("viewer-key2", hash_hex, salt)
        persistence.set_key_meta("viewer-key2", {"role": "viewer", "description": "test viewer"})

        viewer_client = TestClient(
            bridge_app,
            headers={"X-API-Key": viewer_key},
        )

        resp = viewer_client.post("/api/iq/cleanup")
        assert resp.status_code == 403
