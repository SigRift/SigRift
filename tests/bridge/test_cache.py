"""Unit tests for the TTLCache utility.

Tests cover:
  - Basic get/put
  - TTL expiry
  - Full invalidation
  - LRU eviction at capacity
  - Cache statistics (hits, misses, ratio)
  - Thread-safety stress test
  - Float key normalization via make_key
"""

from __future__ import annotations

import threading
import time

import pytest

from sigrift.bridge.cache import MISSING, TTLCache


# ---------------------------------------------------------------------------
# Basic get / put
# ---------------------------------------------------------------------------


class TestGetPut:
    """Tests for basic cache get and put operations."""

    def test_get_missing_key(self) -> None:
        """get() returns MISSING for absent keys."""
        cache = TTLCache()
        assert cache.get("nonexistent") is MISSING

    def test_put_and_get(self) -> None:
        """put() stores a value; get() retrieves it."""
        cache = TTLCache()
        cache.put("k1", {"data": 42}, ttl=10.0)
        result = cache.get("k1")
        assert result == {"data": 42}

    def test_put_overwrites(self) -> None:
        """put() with same key overwrites the value."""
        cache = TTLCache()
        cache.put("k1", "first", ttl=10.0)
        cache.put("k1", "second", ttl=10.0)
        assert cache.get("k1") == "second"

    def test_none_value_cached(self) -> None:
        """None is a valid cached value, distinct from MISSING."""
        cache = TTLCache()
        cache.put("k1", None, ttl=10.0)
        assert cache.get("k1") is None
        assert cache.get("k1") is not MISSING


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------


class TestTTLExpiry:
    """Tests for time-based cache expiry."""

    def test_expired_entry_returns_missing(self) -> None:
        """Entries past their TTL return MISSING."""
        cache = TTLCache()
        cache.put("k1", "value", ttl=0.05)
        time.sleep(0.08)
        assert cache.get("k1") is MISSING

    def test_entry_alive_within_ttl(self) -> None:
        """Entries within TTL are returned normally."""
        cache = TTLCache()
        cache.put("k1", "value", ttl=5.0)
        time.sleep(0.01)
        assert cache.get("k1") == "value"

    def test_expired_entry_removed_from_cache(self) -> None:
        """Expired entries are removed on access, reducing entry count."""
        cache = TTLCache()
        cache.put("k1", "value", ttl=0.05)
        time.sleep(0.08)
        cache.get("k1")  # triggers removal
        assert cache.stats()["entries"] == 0


# ---------------------------------------------------------------------------
# Invalidation
# ---------------------------------------------------------------------------


class TestInvalidation:
    """Tests for cache invalidation."""

    def test_invalidate_clears_all(self) -> None:
        """invalidate() removes all entries."""
        cache = TTLCache()
        for i in range(10):
            cache.put(f"k{i}", i, ttl=60.0)
        assert cache.stats()["entries"] == 10
        cache.invalidate()
        assert cache.stats()["entries"] == 0

    def test_get_after_invalidate_returns_missing(self) -> None:
        """Previously cached values are gone after invalidation."""
        cache = TTLCache()
        cache.put("k1", "value", ttl=60.0)
        cache.invalidate()
        assert cache.get("k1") is MISSING


# ---------------------------------------------------------------------------
# LRU eviction
# ---------------------------------------------------------------------------


class TestLRUEviction:
    """Tests for LRU eviction at max capacity."""

    def test_eviction_at_max_entries(self) -> None:
        """Oldest-accessed entry is evicted when cache is full."""
        cache = TTLCache(max_entries=3)
        cache.put("k1", "v1", ttl=60.0)
        cache.put("k2", "v2", ttl=60.0)
        cache.put("k3", "v3", ttl=60.0)
        # Access k1 so it's most-recently used; k2 becomes LRU
        cache.get("k1")
        # Insert k4 — should evict k2 (least recently accessed)
        cache.put("k4", "v4", ttl=60.0)
        assert cache.stats()["entries"] == 3
        assert cache.get("k2") is MISSING
        assert cache.get("k1") == "v1"
        assert cache.get("k3") == "v3"
        assert cache.get("k4") == "v4"

    def test_eviction_preserves_hot_entries(self) -> None:
        """Frequently accessed entries survive eviction cycles."""
        cache = TTLCache(max_entries=2)
        cache.put("hot", "important", ttl=60.0)
        for i in range(10):
            cache.get("hot")  # keep it warm
            cache.put(f"cold{i}", i, ttl=60.0)
        assert cache.get("hot") == "important"


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------


class TestStats:
    """Tests for cache statistics."""

    def test_initial_stats(self) -> None:
        """Fresh cache has zero hits and misses."""
        cache = TTLCache()
        s = cache.stats()
        assert s["hits"] == 0
        assert s["misses"] == 0
        assert s["entries"] == 0
        assert s["hit_ratio"] == 0.0

    def test_hits_and_misses_counted(self) -> None:
        """Stats correctly track hit/miss counts."""
        cache = TTLCache()
        cache.put("k1", "v", ttl=60.0)
        cache.get("k1")  # hit
        cache.get("k1")  # hit
        cache.get("k2")  # miss
        s = cache.stats()
        assert s["hits"] == 2
        assert s["misses"] == 1
        assert s["hit_ratio"] == pytest.approx(2 / 3, abs=0.01)

    def test_stats_entries_reflects_size(self) -> None:
        """entries count matches actual cache size."""
        cache = TTLCache()
        for i in range(5):
            cache.put(f"k{i}", i, ttl=60.0)
        assert cache.stats()["entries"] == 5


# ---------------------------------------------------------------------------
# make_key
# ---------------------------------------------------------------------------


class TestMakeKey:
    """Tests for the make_key helper."""

    def test_basic_key(self) -> None:
        """Simple method + kwargs produces deterministic key."""
        key = TTLCache.make_key("get_stats", hours=24)
        assert key == "get_stats|hours=24"

    def test_sorted_params(self) -> None:
        """Parameters are sorted alphabetically."""
        k1 = TTLCache.make_key("m", b=2, a=1)
        k2 = TTLCache.make_key("m", a=1, b=2)
        assert k1 == k2

    def test_none_skipped(self) -> None:
        """None values are excluded from the key."""
        k1 = TTLCache.make_key("m", a=1, b=None)
        k2 = TTLCache.make_key("m", a=1)
        assert k1 == k2

    def test_float_rounding(self) -> None:
        """Floats are rounded to 2 decimal places."""
        k1 = TTLCache.make_key("m", score=0.30000001)
        k2 = TTLCache.make_key("m", score=0.30000002)
        assert k1 == k2
        assert "score=0.3" in k1

    def test_different_methods_different_keys(self) -> None:
        """Different method names produce different keys."""
        k1 = TTLCache.make_key("get_stats", hours=1)
        k2 = TTLCache.make_key("get_recent", hours=1)
        assert k1 != k2


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    """Stress test for concurrent cache access."""

    def test_concurrent_put_get(self) -> None:
        """Many threads doing put/get/invalidate concurrently shouldn't crash."""
        cache = TTLCache(max_entries=32)
        errors: list[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(100):
                    key = f"t{thread_id}_k{i % 10}"
                    cache.put(key, i, ttl=1.0)
                    cache.get(key)
                    if i % 25 == 0:
                        cache.invalidate()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert errors == [], f"Thread errors: {errors}"
        # Cache should still be functional after stress
        cache.put("final", "ok", ttl=10.0)
        assert cache.get("final") == "ok"
