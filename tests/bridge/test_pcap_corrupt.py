"""Tests for corrupt/invalid gzip data handling in PcapStore.load_pcap().

Covers the Sprint 1 fix that added zlib.error to the exception handler
in load_pcap() (line 122 of pcap_store.py). Ensures corrupt or truncated
gzip data returns None instead of raising.
"""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.pcap_store import PcapStore


class TestCorruptGzipHandling:
    def test_load_pcap_non_gzip_returns_none(self, tmp_path: Path):
        """Store raw non-gzip bytes as a .pcap.gz file, load_pcap should return None."""
        store = PcapStore(base_dir=tmp_path)
        # Write plain bytes that are NOT gzip-compressed
        corrupt_data = b"this is not gzip data at all"
        store.store(42, corrupt_data)
        assert store.exists(42)

        result = store.load_pcap(42)
        assert result is None, "load_pcap should return None for non-gzip data"

    def test_load_pcap_truncated_gzip_returns_none(self, tmp_path: Path):
        """Store truncated gzip data, load_pcap should return None."""
        store = PcapStore(base_dir=tmp_path)
        # Create valid gzip then truncate it
        valid_gzip = gzip.compress(b"valid pcap content here" * 100)
        truncated = valid_gzip[:20]  # cut off most of the gzip stream
        store.store(43, truncated)
        assert store.exists(43)

        # EOFError is caught by the handler and returns None
        result = store.load_pcap(43)
        assert result is None

    def test_load_pcap_empty_bytes_decompresses_empty(self, tmp_path: Path):
        """Store zero-length file, gzip.decompress(b'') returns b''."""
        store = PcapStore(base_dir=tmp_path)
        store.store(44, b"")
        assert store.exists(44)

        # gzip.decompress(b"") -> b"" (not an error), so load_pcap returns b""
        result = store.load_pcap(44)
        assert result == b""

    def test_load_pcap_random_bytes_returns_none(self, tmp_path: Path):
        """Store random-looking bytes (gzip header but invalid body)."""
        store = PcapStore(base_dir=tmp_path)
        # Start with gzip magic bytes but garbage after
        fake_gzip = b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"\xff\xfe\xfd\xfc\xfb"
        store.store(45, fake_gzip)

        result = store.load_pcap(45)
        assert result is None, "load_pcap should return None for invalid gzip body"

    def test_load_pcap_valid_gzip_still_works(self, tmp_path: Path):
        """Sanity check: valid gzip data should decompress correctly."""
        store = PcapStore(base_dir=tmp_path)
        original = b"valid pcap data for testing"
        compressed = gzip.compress(original)
        store.store(46, compressed)

        result = store.load_pcap(46)
        assert result == original
