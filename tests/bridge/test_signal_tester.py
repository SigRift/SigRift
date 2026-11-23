"""Tests for signal tester CLI tool and REST API."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

# ---------------------------------------------------------------------------
# Imports from the CLI tool (tools/signal_tester.py)
# ---------------------------------------------------------------------------
from sigrift.tools.signal_tester import (
    BANDS,
    FAMILY_REPRESENTATIVE,
    PROTOCOL_FREQUENCIES,
    build_hackrf_cmd,
    compare_tx_rx,
    complex64_to_hackrf_int8,
    complex64_to_raw_iq,
    generate_test_signal,
    get_classes_for_band,
    get_classes_for_family,
    get_classes_for_super_family,
)
from sigrift.lib.taxonomy import CLASSES, FAMILY_TO_CLASSES


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_CLI_SCRIPT = _PROJECT_ROOT / "src" / "sigrift" / "tools" / "signal_tester.py"
_CLI_ENV = {**os.environ, "PYTHONPATH": str(_PROJECT_ROOT)}


# ===================================================================
# Unit Tests -- IQ Format Conversion
# ===================================================================


class TestComplex64ToHackRFInt8:
    def test_complex64_to_hackrf_int8_length(self):
        """Output is 2x input length (I+Q interleaved)."""
        iq = np.array([1 + 1j, 0.5 - 0.5j, 0 + 0j], dtype=np.complex64)
        out = complex64_to_hackrf_int8(iq)
        assert len(out) == len(iq) * 2

    def test_complex64_to_hackrf_int8_range(self):
        """All bytes in [-127, 127]."""
        rng = np.random.RandomState(42)
        iq = (rng.randn(256) + 1j * rng.randn(256)).astype(np.complex64)
        out = complex64_to_hackrf_int8(iq)
        arr = np.frombuffer(out, dtype=np.int8)
        assert arr.min() >= -127
        assert arr.max() <= 127

    def test_complex64_to_hackrf_int8_normalized(self):
        """Peak value maps to +/-127."""
        iq = np.array([1.0 + 0j], dtype=np.complex64)
        out = complex64_to_hackrf_int8(iq)
        arr = np.frombuffer(out, dtype=np.int8)
        # I = 1.0 -> 127, Q = 0.0 -> 0
        assert arr[0] == 127
        assert arr[1] == 0

    def test_complex64_to_hackrf_int8_zero_input(self):
        """Zero signal produces all zeros."""
        iq = np.zeros(64, dtype=np.complex64)
        out = complex64_to_hackrf_int8(iq)
        arr = np.frombuffer(out, dtype=np.int8)
        assert np.all(arr == 0)

    def test_complex64_to_raw_iq(self):
        """Output matches complex64 tobytes()."""
        iq = np.array([1 + 2j, 3 + 4j], dtype=np.complex64)
        out = complex64_to_raw_iq(iq)
        assert out == iq.astype(np.complex64).tobytes()


# ===================================================================
# Unit Tests -- Signal Generation
# ===================================================================


class TestGenerateTestSignal:
    def test_generate_test_signal_returns_dict(self):
        """Result has all expected keys."""
        r = generate_test_signal("bpsk")
        expected_keys = {
            "class_name", "canonical", "family", "freq_hz", "snr_db",
            "power_dbm", "n_samples", "sample_rate", "bandwidth_hz",
            "message", "iq_data", "timestamp",
        }
        assert expected_keys == set(r.keys())

    def test_generate_test_signal_iq_data(self):
        """iq_data is complex64 ndarray of correct length."""
        r = generate_test_signal("bpsk", n_samples=2048)
        assert isinstance(r["iq_data"], np.ndarray)
        assert r["iq_data"].dtype == np.complex64
        assert len(r["iq_data"]) == 2048

    def test_generate_test_signal_power_finite(self):
        """power_dbm is a finite float."""
        r = generate_test_signal("qpsk")
        assert isinstance(r["power_dbm"], float)
        assert np.isfinite(r["power_dbm"])

    def test_generate_test_signal_all_families(self):
        """Each family representative generates successfully."""
        for fam, rep in FAMILY_REPRESENTATIVE.items():
            r = generate_test_signal(rep, n_samples=512)
            assert r["class_name"] == rep, f"Failed for family {fam}"
            assert r["family"] != "UNKNOWN", f"Family unknown for {rep}"

    def test_generate_test_signal_custom_params(self):
        """Custom SNR, samples, and sample_rate flow through."""
        r = generate_test_signal("bpsk", snr_db=25.0, n_samples=1024,
                                 sample_rate=1_000_000)
        assert r["snr_db"] == 25.0
        assert r["n_samples"] == 1024
        assert r["sample_rate"] == 1_000_000
        assert r["bandwidth_hz"] == 1_000_000 * 0.8


# ===================================================================
# Unit Tests -- Selection Helpers
# ===================================================================


class TestSelectionHelpers:
    def test_get_classes_for_band_ism433(self):
        """ISM 433 band returns classes with freq in 433-435 MHz."""
        result = get_classes_for_band("ism_433")
        assert len(result) > 0
        for cls in result:
            freq = PROTOCOL_FREQUENCIES[cls]
            assert 433e6 <= freq <= 435e6, f"{cls} freq {freq} out of ISM 433 range"

    def test_get_classes_for_band_unknown(self):
        """Unknown band returns empty list."""
        assert get_classes_for_band("nonexistent_band") == []

    def test_get_classes_for_family_fsk(self):
        """Returns all FSK family classes."""
        result = get_classes_for_family("FSK")
        expected = FAMILY_TO_CLASSES["FSK"]
        assert set(result) == set(expected)

    def test_get_classes_for_family_unknown(self):
        """Unknown family returns empty list."""
        assert get_classes_for_family("DOES_NOT_EXIST") == []

    def test_get_classes_for_super_family(self):
        """Super-family returns classes from multiple families."""
        result = get_classes_for_super_family("CONSTANT_ENVELOPE")
        # CONSTANT_ENVELOPE includes FSK, TRUNKED, SATELLITE
        assert len(result) > 0
        fsk_classes = set(FAMILY_TO_CLASSES["FSK"])
        trunked_classes = set(FAMILY_TO_CLASSES["TRUNKED"])
        satellite_classes = set(FAMILY_TO_CLASSES["SATELLITE"])
        expected = fsk_classes | trunked_classes | satellite_classes
        assert set(result) == expected

    def test_protocol_frequencies_cover_all_classes(self):
        """Every class in CLASSES has a frequency entry."""
        for cls in CLASSES:
            assert cls in PROTOCOL_FREQUENCIES, f"Missing freq for {cls}"


# ===================================================================
# Unit Tests -- HackRF Command Building
# ===================================================================


class TestBuildHackRFCmd:
    def test_build_hackrf_cmd_basic(self):
        """Correct args for freq, sample rate, gain."""
        cmd = build_hackrf_cmd("/tmp/test.cs8", 433920000, 2048000, 20)
        assert cmd[0] == "hackrf_transfer"
        assert "-t" in cmd
        assert cmd[cmd.index("-t") + 1] == "/tmp/test.cs8"
        assert cmd[cmd.index("-f") + 1] == "433920000"
        assert cmd[cmd.index("-s") + 1] == "2048000"
        assert cmd[cmd.index("-x") + 1] == "20"
        assert "-a" not in cmd

    def test_build_hackrf_cmd_amp(self):
        """-a 1 flag when amp_enable=True."""
        cmd = build_hackrf_cmd("/tmp/test.cs8", 433920000, amp_enable=True)
        idx = cmd.index("-a")
        assert cmd[idx + 1] == "1"


# ===================================================================
# Functional Tests -- CLI (subprocess)
# ===================================================================


class TestCLI:
    def _run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(_CLI_SCRIPT)] + list(args),
            capture_output=True, text=True, env=_CLI_ENV, timeout=timeout,
        )

    def test_cli_list(self):
        """--list prints families, bands, classes without error."""
        r = self._run("--list")
        assert r.returncode == 0
        assert "FAMILIES" in r.stdout
        assert "BANDS" in r.stdout
        assert "ALL CLASSES" in r.stdout

    def test_cli_single_class(self):
        """--class bpsk generates 1 signal."""
        r = self._run("--class", "bpsk")
        assert r.returncode == 0
        assert "bpsk" in r.stdout
        assert "Total: 1 signals generated" in r.stdout

    def test_cli_family(self):
        """--family PSK generates multiple signals."""
        r = self._run("--family", "PSK")
        assert r.returncode == 0
        assert "Total:" in r.stdout
        # PSK has 5 classes
        assert "5 signals generated" in r.stdout

    def test_cli_band(self):
        """--band ism_433 generates signals."""
        r = self._run("--band", "ism_433")
        assert r.returncode == 0
        assert "Total:" in r.stdout

    def test_cli_representatives(self):
        """--representatives generates 16 signals."""
        r = self._run("--representatives")
        assert r.returncode == 0
        assert "16 signals generated" in r.stdout

    def test_cli_json_output(self):
        """--class bpsk --json produces valid JSON."""
        r = self._run("--class", "bpsk", "--json")
        assert r.returncode == 0
        data = json.loads(r.stdout)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["class_name"] == "bpsk"

    def test_cli_save_hackrf(self):
        """--class bpsk --save-hackrf creates file with correct size."""
        with tempfile.NamedTemporaryFile(suffix=".cs8", delete=False) as f:
            path = f.name
        try:
            r = self._run("--class", "bpsk", "--save-hackrf", path,
                           "--samples", "1024")
            assert r.returncode == 0
            assert os.path.exists(path)
            # 1024 complex samples -> 2048 int8 bytes
            assert os.path.getsize(path) == 1024 * 2
        finally:
            os.unlink(path)

    def test_cli_save_iq(self):
        """--class bpsk --save-iq creates file."""
        with tempfile.NamedTemporaryFile(suffix=".cf32", delete=False) as f:
            path = f.name
        try:
            r = self._run("--class", "bpsk", "--save-iq", path,
                           "--samples", "512")
            assert r.returncode == 0
            assert os.path.exists(path)
            # 512 complex64 samples -> 512 * 8 bytes
            assert os.path.getsize(path) == 512 * 8
        finally:
            os.unlink(path)

    def test_cli_save_hackrf_dir(self):
        """--family PULSED --save-hackrf-dir creates multiple .cs8 files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            r = self._run("--family", "PULSED", "--save-hackrf-dir", tmpdir,
                           "--samples", "512")
            assert r.returncode == 0
            cs8_files = list(Path(tmpdir).glob("*.cs8"))
            # PULSED has 3 classes: adsb, uat, tpms
            assert len(cs8_files) == 3

    def test_cli_tx_dry_run(self):
        """--class bpsk --tx --tx-dry-run prints command without error."""
        r = self._run("--class", "bpsk", "--tx", "--tx-dry-run")
        assert r.returncode == 0
        assert "DRY RUN" in r.stdout
        assert "hackrf_transfer" in r.stdout

    def test_cli_no_args_shows_help(self):
        """No args exits with code 2."""
        r = self._run()
        assert r.returncode == 2


# ===================================================================
# Integration Tests
# ===================================================================


class TestIntegration:
    def test_compare_tx_rx_identical(self):
        """Comparing identical signals gives excellent quality."""
        iq = generate_test_signal("bpsk", n_samples=2048)["iq_data"]
        result = compare_tx_rx(iq, iq)
        assert result["match_quality"] == "excellent"
        assert result["spectral_correlation"] > 0.9
        assert result["power_delta_db"] == 0.0

    def test_compare_tx_rx_noise(self):
        """Comparing signal vs noise gives poor quality."""
        tx = generate_test_signal("bpsk", snr_db=30.0, n_samples=2048)["iq_data"]
        rng = np.random.RandomState(99)
        rx = (rng.randn(2048) + 1j * rng.randn(2048)).astype(np.complex64)
        result = compare_tx_rx(tx, rx)
        assert result["match_quality"] in ("poor", "fair")

    def test_loopback_result_structure(self):
        """Loopback result dict has class, tx, rx, comparison keys."""
        from sigrift.tools.signal_tester import run_loopback_test

        r = generate_test_signal("bpsk", n_samples=1024)
        # dry_run avoids needing HackRF hardware
        lb = run_loopback_test(r, dry_run=True)
        assert "class" in lb
        assert "tx" in lb
        assert "rx" in lb
        assert "comparison" in lb
        assert lb["tx"]["status"] == "dry_run"

    def test_all_76_classes_generate(self):
        """Every taxonomy class produces a valid test signal."""
        for cls in CLASSES:
            r = generate_test_signal(cls, n_samples=256, snr_db=10.0)
            assert r["class_name"] == cls
            assert isinstance(r["iq_data"], np.ndarray)
            assert r["iq_data"].dtype == np.complex64
            assert len(r["iq_data"]) == 256
            assert np.isfinite(r["power_dbm"])

    def test_family_representatives_all_unique(self):
        """16 representatives are unique classes."""
        reps = list(FAMILY_REPRESENTATIVE.values())
        assert len(reps) == 16
        assert len(set(reps)) == 16
