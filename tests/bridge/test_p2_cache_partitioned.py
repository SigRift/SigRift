"""Tests for PartitionedCache — domain-partitioned TTL cache (P2-6)."""

from __future__ import annotations

import time

import pytest

from sigrift.bridge.cache import MISSING, PartitionedCache, TTLCache


class TestPartitionRouting:
    """Verify keys are routed to the correct partition."""

    def test_partition_routing_detection(self) -> None:
        pc = PartitionedCache()
        pc.put("detection_abc", "val_det", ttl=30.0)
        # Should be in the detection partition
        assert pc._partitions["detection"].get("detection_abc") == "val_det"
        # Should NOT be in _other
        assert pc._partitions["_other"].get("detection_abc") is MISSING

    def test_partition_routing_wifi(self) -> None:
        pc = PartitionedCache()
        pc.put("wifi_scan_1", "wifi_data", ttl=30.0)
        assert pc._partitions["wifi"].get("wifi_scan_1") == "wifi_data"
        assert pc._partitions["_other"].get("wifi_scan_1") is MISSING

    def test_partition_routing_other(self) -> None:
        pc = PartitionedCache()
        pc.put("unknown_prefix_key", "other_val", ttl=30.0)
        assert pc._partitions["_other"].get("unknown_prefix_key") == "other_val"
        # Should not be in any named partition
        for name in ("detection", "wifi", "bt", "rf", "audit", "zigbee", "spectrum", "feedback"):
            assert pc._partitions[name].get("unknown_prefix_key") is MISSING


class TestIsolation:
    """Cross-partition isolation and eviction independence."""

    def test_cross_partition_isolation(self) -> None:
        pc = PartitionedCache(partitions={
            "hot": 2,
            "cold": 2,
            "_other": 2,
        })
        # Fill 'hot' partition to capacity and trigger eviction
        pc.put("hot_a", 1, ttl=30.0)
        pc.put("hot_b", 2, ttl=30.0)
        # Put a value in 'cold'
        pc.put("cold_x", 99, ttl=30.0)
        # Evict from 'hot' by adding a third entry
        pc.put("hot_c", 3, ttl=30.0)
        # 'cold' partition must be unaffected
        assert pc.get("cold_x") == 99


class TestInvalidation:
    """Invalidation semantics."""

    def test_invalidate_all(self) -> None:
        pc = PartitionedCache()
        pc.put("detection_1", "d", ttl=30.0)
        pc.put("wifi_1", "w", ttl=30.0)
        pc.put("bt_1", "b", ttl=30.0)
        pc.put("unknown_1", "u", ttl=30.0)
        pc.invalidate()
        assert pc.get("detection_1") is MISSING
        assert pc.get("wifi_1") is MISSING
        assert pc.get("bt_1") is MISSING
        assert pc.get("unknown_1") is MISSING

    def test_invalidate_prefix(self) -> None:
        pc = PartitionedCache()
        pc.put("wifi_a", 1, ttl=30.0)
        pc.put("wifi_b", 2, ttl=30.0)
        pc.put("detection_a", 3, ttl=30.0)
        pc.put("bt_a", 4, ttl=30.0)
        # Invalidate only wifi partition
        pc.invalidate_prefix("wifi")
        assert pc.get("wifi_a") is MISSING
        assert pc.get("wifi_b") is MISSING
        # Other partitions untouched
        assert pc.get("detection_a") == 3
        assert pc.get("bt_a") == 4


class TestStats:
    """Stats aggregation across partitions."""

    def test_stats_aggregated(self) -> None:
        pc = PartitionedCache()
        pc.put("detection_x", "d", ttl=30.0)
        pc.put("wifi_x", "w", ttl=30.0)
        # Generate hits
        pc.get("detection_x")
        pc.get("wifi_x")
        # Generate misses
        pc.get("detection_missing")
        pc.get("wifi_missing")
        s = pc.stats()
        assert s["hits"] == 2
        assert s["misses"] == 2
        assert s["size"] == 2
        assert "partitions" in s
        assert isinstance(s["partitions"], dict)
        assert "detection" in s["partitions"]
        assert isinstance(s["partitions"]["detection"], dict)
        assert "wifi" in s["partitions"]
        assert isinstance(s["partitions"]["wifi"], dict)


class TestCapacity:
    """Total capacity check."""

    def test_total_capacity(self) -> None:
        pc = PartitionedCache()
        total = sum(cache._max for cache in pc._partitions.values())
        assert total == 2048


class TestTTLExpiry:
    """TTL expiration through partitioned cache."""

    def test_ttl_expiry_still_works(self) -> None:
        pc = PartitionedCache()
        pc.put("detection_ttl", "alive", ttl=0.05)
        assert pc.get("detection_ttl") == "alive"
        time.sleep(0.1)
        assert pc.get("detection_ttl") is MISSING


class TestMissingSentinel:
    """MISSING sentinel on cache miss."""

    def test_missing_sentinel(self) -> None:
        pc = PartitionedCache()
        result = pc.get("nonexistent_key")
        assert result is MISSING
