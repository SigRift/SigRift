"""Tests for IQStore — filesystem-backed IQ capture storage and visualization."""

from __future__ import annotations

import gzip
import os
import time
from pathlib import Path

import numpy as np

from sigrift.bridge.iq_store import IQStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_iq_data(n_samples: int = 1024) -> tuple[bytes, np.ndarray]:
    """Generate gzipped interleaved float32 IQ data and the expected complex64 array.

    Returns
    -------
    tuple[bytes, np.ndarray]
        (gzip-compressed bytes, complex64 reference array)
    """
    rng = np.random.default_rng(42)
    iq = (rng.standard_normal(n_samples) + 1j * rng.standard_normal(n_samples)).astype(
        np.complex64,
    )
    interleaved = np.zeros(2 * n_samples, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    data = gzip.compress(interleaved.tobytes())
    return data, iq


# ---------------------------------------------------------------------------
# Basic store / load operations
# ---------------------------------------------------------------------------


class TestIQStoreBasic:
    """Tests for store, load_raw, load_iq, exists, and delete."""

    def test_store_and_load_roundtrip(self, tmp_path: Path) -> None:
        """store() writes gzipped IQ data; load_raw() returns the same bytes."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data()
        store.store("det-001", data)

        loaded = store.load_raw("det-001")
        assert loaded == data

    def test_load_iq_complex64(self, tmp_path: Path) -> None:
        """load_iq() decompresses interleaved float32 and returns complex64 array."""
        store = IQStore(base_dir=tmp_path)
        data, expected_iq = _make_iq_data(512)
        store.store("det-002", data)

        result = store.load_iq("det-002")
        assert result is not None
        assert isinstance(result, np.ndarray)
        assert result.dtype == np.complex64
        assert len(result) == 512
        np.testing.assert_array_almost_equal(result, expected_iq, decimal=5)

    def test_load_raw_missing_returns_none(self, tmp_path: Path) -> None:
        """load_raw() returns None for a nonexistent detection."""
        store = IQStore(base_dir=tmp_path)
        assert store.load_raw("nonexistent") is None

    def test_load_iq_missing_returns_none(self, tmp_path: Path) -> None:
        """load_iq() returns None for a nonexistent detection."""
        store = IQStore(base_dir=tmp_path)
        assert store.load_iq("nonexistent") is None

    def test_exists_true_and_false(self, tmp_path: Path) -> None:
        """exists() returns True after store, False for missing detection."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data()

        assert not store.exists("det-003")
        store.store("det-003", data)
        assert store.exists("det-003")

    def test_delete_existing(self, tmp_path: Path) -> None:
        """delete() removes a stored file, returns True, and exists() becomes False."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data()
        store.store("det-004", data)
        assert store.exists("det-004")

        assert store.delete("det-004") is True
        assert not store.exists("det-004")

    def test_delete_nonexistent(self, tmp_path: Path) -> None:
        """delete() returns False when the file does not exist."""
        store = IQStore(base_dir=tmp_path)
        assert store.delete("missing") is False


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


class TestIQStoreCleanup:
    """Tests for the cleanup() aged-file deletion."""

    def test_cleanup_aged_files(self, tmp_path: Path) -> None:
        """cleanup() deletes files older than max_age_days and returns the count."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data()
        store.store("old-det", data)

        # Backdate the file's mtime to 10 days ago
        path = store._path_for("old-det")
        old_time = time.time() - (10 * 86400)
        os.utime(path, (old_time, old_time))

        deleted = store.cleanup(max_age_days=7)
        assert deleted == 1
        assert not store.exists("old-det")

    def test_cleanup_keeps_recent(self, tmp_path: Path) -> None:
        """cleanup() does not delete recently created files."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data()
        store.store("recent-det", data)

        deleted = store.cleanup(max_age_days=7)
        assert deleted == 0
        assert store.exists("recent-det")


# ---------------------------------------------------------------------------
# Visualization
# ---------------------------------------------------------------------------


class TestIQStoreVisualization:
    """Tests for compute_visualization() output format and types."""

    def test_compute_visualization_output_format(self, tmp_path: Path) -> None:
        """compute_visualization() returns a dict with expected keys and list-of-float values."""
        store = IQStore(base_dir=tmp_path)
        data, _ = _make_iq_data(1024)
        store.store("viz-det", data)

        result = store.compute_visualization("viz-det")
        assert result is not None
        assert isinstance(result, dict)

        # All expected keys present
        expected_keys = {
            "constellation_x",
            "constellation_y",
            "psd_db",
            "psd_freq_hz",
            "dsp_features",
        }
        assert set(result.keys()) == expected_keys

        # constellation_x/y are lists of floats with same length
        assert isinstance(result["constellation_x"], list)
        assert isinstance(result["constellation_y"], list)
        assert len(result["constellation_x"]) == len(result["constellation_y"])
        assert len(result["constellation_x"]) <= 1024
        assert all(isinstance(v, float) for v in result["constellation_x"])
        assert all(isinstance(v, float) for v in result["constellation_y"])

        # PSD arrays are lists of floats with matching lengths
        assert isinstance(result["psd_db"], list)
        assert isinstance(result["psd_freq_hz"], list)
        assert len(result["psd_db"]) == len(result["psd_freq_hz"])
        assert len(result["psd_db"]) == 1024  # same as n_samples
        assert all(isinstance(v, float) for v in result["psd_db"])
        assert all(isinstance(v, float) for v in result["psd_freq_hz"])

        # dsp_features is a 16-element list of floats
        assert isinstance(result["dsp_features"], list)
        assert len(result["dsp_features"]) == 16
        assert all(isinstance(v, float) for v in result["dsp_features"])

    def test_compute_visualization_missing_returns_none(self, tmp_path: Path) -> None:
        """compute_visualization() returns None when detection does not exist."""
        store = IQStore(base_dir=tmp_path)
        assert store.compute_visualization("nonexistent") is None


# ---------------------------------------------------------------------------
# Path traversal protection
# ---------------------------------------------------------------------------


class TestIQStorePathTraversal:
    """Tests for path traversal sanitization in _path_for()."""

    def test_path_traversal_sanitization(self, tmp_path: Path) -> None:
        """_path_for() sanitizes path traversal attempts like ../../etc/passwd."""
        store = IQStore(base_dir=tmp_path)
        path = store._path_for("../../etc/passwd")

        # Path should be sanitized - no traversal characters survive
        assert ".." not in str(path.name)
        assert "/" not in str(path.name)
        # The mapping is injective: the traversal id is encoded instead of
        # stripped, so it cannot land on the file of the plain id
        # "etcpasswd" (stripping mapped both to "etcpasswd.iq.gz").
        assert path != store._path_for("etcpasswd")
        assert path.name.endswith(".iq.gz")

        # Verify path stays within base_dir
        assert path.is_relative_to(tmp_path.resolve())
