"""Tests for the fast-hash index in auth key lookup.

Validates that:
  - A valid key lookup populates the fast-hash index on first call
    and uses it for O(1) candidate lookup on subsequent calls.
  - An invalid key is rejected without scanning all stored keys.
  - Key rotation (clear_fast_hash_index) invalidates the cache.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sigrift.lib.security.credentials import (
    generate_api_key,
    hash_credential,
    verify_credential,
)
from sigrift.lib.shiny.dependencies import (
    _compute_fast_hash,
    _fast_hash_index,
    _lookup_key,
    clear_fast_hash_index,
)


@pytest.fixture(autouse=True)
def _clean_index():
    """Ensure the fast-hash index is empty before and after each test."""
    clear_fast_hash_index()
    yield
    clear_fast_hash_index()


def _make_key_store(*raw_keys: str) -> tuple[list[str], dict[str, tuple[str, bytes]]]:
    """Create a key store from raw key strings.

    Returns (raw_keys_list, key_store_dict).
    """
    store: dict[str, tuple[str, bytes]] = {}
    for i, raw in enumerate(raw_keys):
        key_id = f"key-{i}"
        hash_hex, salt = hash_credential(raw)
        store[key_id] = (hash_hex, salt)
    return list(raw_keys), store


class TestFastHashIndex:
    """Fast-hash index populates on success and provides O(1) lookup."""

    def test_first_call_populates_index(self):
        raw = generate_api_key()
        _, store = _make_key_store(raw)

        assert len(_fast_hash_index) == 0
        result = _lookup_key(raw, store)
        assert result == "key-0"
        assert len(_fast_hash_index) == 1
        assert _fast_hash_index[_compute_fast_hash(raw)] == "key-0"

    def test_second_call_hits_fast_hash(self):
        raw = generate_api_key()
        _, store = _make_key_store(raw)

        # First call: full scan
        _lookup_key(raw, store)

        # Second call: should use fast-hash index.
        # Patch verify_credential to count calls.
        with patch(
            "sigrift.lib.shiny.dependencies.verify_credential",
            wraps=verify_credential,
        ) as mock_verify:
            result = _lookup_key(raw, store)
            assert result == "key-0"
            # Only 1 PBKDF2 call (the indexed candidate), not N keys
            assert mock_verify.call_count == 1

    def test_multiple_keys_index_correct_candidate(self):
        raw_a = generate_api_key()
        raw_b = generate_api_key()
        _, store = _make_key_store(raw_a, raw_b)

        # Authenticate with key B
        result = _lookup_key(raw_b, store)
        assert result == "key-1"

        # Second call for key B: only 1 verify call
        with patch(
            "sigrift.lib.shiny.dependencies.verify_credential",
            wraps=verify_credential,
        ) as mock_verify:
            result = _lookup_key(raw_b, store)
            assert result == "key-1"
            assert mock_verify.call_count == 1


class TestInvalidKeyRejection:
    """Invalid keys are rejected without full PBKDF2 scan on cache miss."""

    def test_invalid_key_not_indexed(self):
        raw = generate_api_key()
        _, store = _make_key_store(raw)

        bogus = generate_api_key()
        result = _lookup_key(bogus, store)
        assert result is None
        # Bogus key should not appear in the index
        assert _compute_fast_hash(bogus) not in _fast_hash_index

    def test_invalid_key_skips_indexed_candidate(self):
        """When index has an entry for a different key, invalid key still rejected."""
        raw = generate_api_key()
        _, store = _make_key_store(raw)

        # Populate index for the valid key
        _lookup_key(raw, store)

        bogus = generate_api_key()
        result = _lookup_key(bogus, store)
        assert result is None


class TestKeyRotation:
    """clear_fast_hash_index invalidates the cache on key rotation."""

    def test_clear_index_removes_all_entries(self):
        raw = generate_api_key()
        _, store = _make_key_store(raw)

        _lookup_key(raw, store)
        assert len(_fast_hash_index) == 1

        clear_fast_hash_index()
        assert len(_fast_hash_index) == 0

    def test_rotated_key_triggers_full_scan(self):
        raw_old = generate_api_key()
        _, store = _make_key_store(raw_old)

        # Populate index with old key
        _lookup_key(raw_old, store)
        assert len(_fast_hash_index) == 1

        # Simulate key rotation: new credential, clear index
        raw_new = generate_api_key()
        new_hash, new_salt = hash_credential(raw_new)
        store["key-0"] = (new_hash, new_salt)
        clear_fast_hash_index()

        # Old key should fail
        result = _lookup_key(raw_old, store)
        assert result is None

        # New key should succeed and re-populate index
        result = _lookup_key(raw_new, store)
        assert result == "key-0"
        assert _fast_hash_index[_compute_fast_hash(raw_new)] == "key-0"

    def test_stale_index_entry_cleared_on_mismatch(self):
        """If key was rotated but index not cleared, stale entry is removed."""
        raw_old = generate_api_key()
        _, store = _make_key_store(raw_old)

        # Populate index
        _lookup_key(raw_old, store)
        fast_hash_old = _compute_fast_hash(raw_old)
        assert fast_hash_old in _fast_hash_index

        # Rotate key in store WITHOUT clearing index
        raw_new = generate_api_key()
        new_hash, new_salt = hash_credential(raw_new)
        store["key-0"] = (new_hash, new_salt)

        # Old key: index candidate found but PBKDF2 fails -> stale entry removed
        result = _lookup_key(raw_old, store)
        assert result is None
        assert fast_hash_old not in _fast_hash_index
