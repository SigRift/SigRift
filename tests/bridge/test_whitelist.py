"""Tests for sigrift.bridge.anomaly.whitelist."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from sigrift.bridge.anomaly.whitelist import SignalWhitelist, WhitelistEntry


# ---------------------------------------------------------------------------
# Default seeding
# ---------------------------------------------------------------------------


class TestDefaultSeeding:
    def test_defaults_loaded(self):
        wl = SignalWhitelist()
        assert len(wl.entries) == 8

    def test_fm_broadcast_entry(self):
        wl = SignalWhitelist()
        fm = next(e for e in wl.entries if e.description == "FM Broadcast")
        assert fm.freq_min_hz == 87_500_000
        assert fm.freq_max_hz == 108_000_000
        assert "fm" in fm.expected_classes
        assert "am-dsb" in fm.expected_classes

    def test_ism_433_entry(self):
        wl = SignalWhitelist()
        ism = next(e for e in wl.entries if e.description == "ISM 433")
        assert ism.freq_min_hz == 433_050_000
        assert ism.freq_max_hz == 434_790_000
        assert "ook" in ism.expected_classes
        assert "lora-css" in ism.expected_classes

    def test_wifi_entry(self):
        wl = SignalWhitelist()
        wifi = next(e for e in wl.entries if e.description == "WiFi 2.4")
        assert wifi.freq_min_hz == 2_400_000_000
        assert wifi.freq_max_hz == 2_500_000_000
        assert "ofdm-64" in wifi.expected_classes

    def test_all_entries_have_description(self):
        wl = SignalWhitelist()
        for entry in wl.entries:
            assert entry.description != ""

    def test_all_entries_have_classes(self):
        wl = SignalWhitelist()
        for entry in wl.entries:
            assert len(entry.expected_classes) > 0

    def test_default_score_reduction(self):
        wl = SignalWhitelist()
        for entry in wl.entries:
            assert entry.score_reduction == 0.3


# ---------------------------------------------------------------------------
# Frequency matching
# ---------------------------------------------------------------------------


class TestFrequencyMatching:
    def test_in_range_match(self):
        wl = SignalWhitelist()
        result = wl.check(100_000_000, "fm")
        assert isinstance(result, WhitelistEntry)
        assert result.description == "FM Broadcast"

    def test_out_of_range_no_match(self):
        wl = SignalWhitelist()
        result = wl.check(200_000_000, "fm")
        assert result is None

    def test_exact_min_boundary(self):
        wl = SignalWhitelist()
        result = wl.check(87_500_000, "fm")
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"

    def test_exact_max_boundary(self):
        wl = SignalWhitelist()
        result = wl.check(108_000_000, "fm")
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"

    def test_below_min_no_match(self):
        wl = SignalWhitelist()
        result = wl.check(87_499_999, "fm")
        assert result is None


# ---------------------------------------------------------------------------
# Class matching
# ---------------------------------------------------------------------------


class TestClassMatching:
    def test_expected_class_matches(self):
        wl = SignalWhitelist()
        result = wl.check(100_000_000, "fm")
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"

    def test_unexpected_class_no_match(self):
        wl = SignalWhitelist()
        result = wl.check(100_000_000, "qam256")
        assert result is None

    def test_am_dsb_in_fm_band(self):
        wl = SignalWhitelist()
        result = wl.check(100_000_000, "am-dsb")
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"


# ---------------------------------------------------------------------------
# Time window matching
# ---------------------------------------------------------------------------


class TestTimeWindowMatching:
    def test_no_time_window_always_matches(self):
        wl = SignalWhitelist()
        # Default entries have no time windows
        result = wl.check(100_000_000, "fm", hour=3)
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"

    def test_within_time_window(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            time_windows=[(8, 17)],  # Business hours
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        assert isinstance(wl.check(150_000_000, "fm", hour=12), WhitelistEntry)

    def test_outside_time_window(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            time_windows=[(8, 17)],
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        assert wl.check(150_000_000, "fm", hour=3) is None

    def test_multiple_time_windows(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            time_windows=[(6, 9), (17, 20)],
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        assert isinstance(wl.check(150_000_000, "fm", hour=7), WhitelistEntry)
        assert isinstance(wl.check(150_000_000, "fm", hour=18), WhitelistEntry)
        assert wl.check(150_000_000, "fm", hour=12) is None

    def test_hour_none_skips_time_check(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            time_windows=[(8, 17)],
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        # hour=None should match (time window not checked)
        assert isinstance(wl.check(150_000_000, "fm", hour=None), WhitelistEntry)


# ---------------------------------------------------------------------------
# Node ID matching
# ---------------------------------------------------------------------------


class TestNodeIdMatching:
    def test_no_node_filter_matches_all(self):
        wl = SignalWhitelist()
        result = wl.check(100_000_000, "fm", node_id="node-1")
        assert isinstance(result, WhitelistEntry) and result.description == "FM Broadcast"

    def test_matching_node_id(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            node_ids=["node-1", "node-2"],
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        assert isinstance(wl.check(150_000_000, "fm", node_id="node-1"), WhitelistEntry)

    def test_non_matching_node_id(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            node_ids=["node-1", "node-2"],
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        assert wl.check(150_000_000, "fm", node_id="node-3") is None


# ---------------------------------------------------------------------------
# Score reduction
# ---------------------------------------------------------------------------


class TestScoreReduction:
    def test_whitelisted_reduces_score(self):
        wl = SignalWhitelist()
        score = wl.apply_reduction(0.5, 100_000_000, "fm")
        assert score == pytest.approx(0.2)

    def test_non_whitelisted_unchanged(self):
        wl = SignalWhitelist()
        score = wl.apply_reduction(0.5, 200_000_000, "qam256")
        assert score == 0.5

    def test_reduction_floor_at_zero(self):
        wl = SignalWhitelist()
        score = wl.apply_reduction(0.1, 100_000_000, "fm")
        assert score == 0.0

    def test_custom_score_reduction(self):
        entry = WhitelistEntry(
            freq_min_hz=100_000_000,
            freq_max_hz=200_000_000,
            expected_classes=["fm"],
            description="Test",
            score_reduction=0.5,
        )
        wl = SignalWhitelist()
        wl.entries = [entry]
        score = wl.apply_reduction(0.8, 150_000_000, "fm")
        assert score == pytest.approx(0.3)


# ---------------------------------------------------------------------------
# Add / remove entries
# ---------------------------------------------------------------------------


class TestAddRemoveEntries:
    def test_add_entry(self):
        wl = SignalWhitelist()
        initial = len(wl.entries)
        wl.add_entry(WhitelistEntry(
            freq_min_hz=300_000_000,
            freq_max_hz=400_000_000,
            expected_classes=["test"],
            description="Custom",
        ))
        assert len(wl.entries) == initial + 1
        result = wl.check(350_000_000, "test")
        assert isinstance(result, WhitelistEntry)
        assert result.description == "Custom"

    def test_remove_entry(self):
        wl = SignalWhitelist()
        initial = len(wl.entries)
        wl.remove_entry(0)
        assert len(wl.entries) == initial - 1

    def test_remove_invalid_index_raises(self):
        wl = SignalWhitelist()
        with pytest.raises(IndexError):
            wl.remove_entry(999)


# ---------------------------------------------------------------------------
# Save / load persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_save_load_roundtrip(self):
        wl = SignalWhitelist()
        wl.add_entry(WhitelistEntry(
            freq_min_hz=300_000_000,
            freq_max_hz=400_000_000,
            expected_classes=["custom"],
            description="Custom Band",
            time_windows=[(8, 17)],
            node_ids=["node-1"],
            score_reduction=0.5,
        ))

        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "whitelist.json")
            wl.save(path)

            # Verify file
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            assert isinstance(data["entries"], list)
            assert len(data["entries"]) == 9  # 8 defaults + 1 custom

            # Load into new whitelist
            wl2 = SignalWhitelist()
            wl2.load(path)
            assert len(wl2.entries) == 9

            # Verify custom entry survived
            custom = next(e for e in wl2.entries if e.description == "Custom Band")
            assert custom.freq_min_hz == 300_000_000
            assert custom.expected_classes == ["custom"]
            assert custom.time_windows == [(8, 17)]
            assert custom.node_ids == ["node-1"]
            assert custom.score_reduction == 0.5

    def test_load_missing_file(self):
        wl = SignalWhitelist()
        initial = len(wl.entries)
        wl.load("/nonexistent/path/whitelist.json")
        # Should keep existing entries
        assert len(wl.entries) == initial

    def test_save_creates_directory(self):
        wl = SignalWhitelist()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = str(Path(tmpdir) / "subdir" / "whitelist.json")
            wl.save(path)
            assert Path(path).exists()
