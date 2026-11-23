"""Tests for classification_refiner.refine_classification().

Covers band-aware label refinement for WiFi, DMR, and FHSS signals,
plus edge cases for unknown classes and invalid frequencies.
"""

from __future__ import annotations

import sys
import os
import unittest

# Ensure sigrift is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from sigrift.bridge.classification_refiner import refine_classification


class TestWiFiRefinement(unittest.TestCase):
    """WiFi / OFDM signals refined by ISM/UNII band."""

    def test_wifi_2_4ghz(self):
        self.assertEqual(refine_classification("wifi", 2_437_000_000), "WiFi 2.4GHz")

    def test_ofdm_2_4ghz(self):
        self.assertEqual(refine_classification("ofdm", 2_412_000_000), "WiFi 2.4GHz")

    def test_wifi_5ghz(self):
        self.assertEqual(refine_classification("wifi", 5_500_000_000), "WiFi 5GHz")

    def test_ofdm_5ghz(self):
        self.assertEqual(refine_classification("ofdm", 5_180_000_000), "WiFi 5GHz")

    def test_wifi_6e(self):
        self.assertEqual(refine_classification("wifi", 6_000_000_000), "WiFi 6E")

    def test_ofdm_6e(self):
        self.assertEqual(refine_classification("ofdm", 6_500_000_000), "WiFi 6E")

    def test_wifi_2_4ghz_boundary_low(self):
        self.assertEqual(refine_classification("wifi", 2_400_000_000), "WiFi 2.4GHz")

    def test_wifi_2_4ghz_boundary_high(self):
        self.assertEqual(refine_classification("wifi", 2_500_000_000), "WiFi 2.4GHz")

    def test_wifi_5ghz_boundary_low(self):
        self.assertEqual(refine_classification("wifi", 5_150_000_000), "WiFi 5GHz")

    def test_wifi_6e_boundary_high(self):
        self.assertEqual(refine_classification("wifi", 7_125_000_000), "WiFi 6E")

    def test_wifi_outside_bands_unchanged(self):
        """WiFi at a frequency outside known bands returns original."""
        self.assertEqual(refine_classification("wifi", 900_000_000), "wifi")


class TestDMRRefinement(unittest.TestCase):
    """DMR / DQPSK signals refined by VHF/UHF band."""

    def test_dmr_vhf(self):
        self.assertEqual(refine_classification("dmr", 150_000_000), "DMR VHF")

    def test_dqpsk_vhf(self):
        self.assertEqual(refine_classification("dqpsk", 155_000_000), "DMR VHF")

    def test_dmr_uhf(self):
        self.assertEqual(refine_classification("dmr", 450_000_000), "DMR UHF")

    def test_dqpsk_uhf(self):
        self.assertEqual(refine_classification("dqpsk", 460_000_000), "DMR UHF")

    def test_dmr_800mhz(self):
        self.assertEqual(refine_classification("dmr", 850_000_000), "DMR 800MHz")

    def test_dmr_outside_bands_unchanged(self):
        """DMR at a frequency outside known bands returns original."""
        self.assertEqual(refine_classification("dmr", 2_400_000_000), "dmr")


class TestFHSSRefinement(unittest.TestCase):
    """FHSS signals refined by ISM band."""

    def test_fhss_bluetooth_2_4ghz(self):
        self.assertEqual(
            refine_classification("fhss", 2_440_000_000),
            "Bluetooth/FHSS 2.4GHz",
        )

    def test_fhss_ism_900mhz(self):
        self.assertEqual(
            refine_classification("fhss", 915_000_000),
            "ISM 900MHz FHSS",
        )

    def test_fhss_900_boundary_low(self):
        self.assertEqual(
            refine_classification("fhss", 902_000_000),
            "ISM 900MHz FHSS",
        )

    def test_fhss_900_boundary_high(self):
        self.assertEqual(
            refine_classification("fhss", 928_000_000),
            "ISM 900MHz FHSS",
        )

    def test_fhss_outside_bands_unchanged(self):
        self.assertEqual(refine_classification("fhss", 433_000_000), "fhss")


class TestUnmatchedClasses(unittest.TestCase):
    """Unknown or unmatched signal classes return the original label."""

    def test_unknown_class_passthrough(self):
        self.assertEqual(
            refine_classification("am-broadcast", 1_000_000),
            "am-broadcast",
        )

    def test_random_class_passthrough(self):
        self.assertEqual(
            refine_classification("mystery-signal", 500_000_000),
            "mystery-signal",
        )

    def test_empty_string_passthrough(self):
        self.assertEqual(refine_classification("", 2_400_000_000), "")

    def test_case_insensitive_match(self):
        """WiFi matching should be case-insensitive."""
        self.assertEqual(refine_classification("WiFi", 2_437_000_000), "WiFi 2.4GHz")
        self.assertEqual(refine_classification("OFDM", 5_200_000_000), "WiFi 5GHz")


class TestEdgeCases(unittest.TestCase):
    """Edge cases: None freq_hz, 0 freq_hz."""

    def test_zero_freq_returns_original(self):
        """freq_hz=0 should not match any band."""
        self.assertEqual(refine_classification("wifi", 0), "wifi")

    def test_zero_freq_dmr_returns_original(self):
        self.assertEqual(refine_classification("dmr", 0), "dmr")

    def test_none_freq_returns_original(self):
        """None freq_hz returns the original signal class unchanged."""
        self.assertEqual(refine_classification("wifi", None), "wifi")

    def test_negative_freq_returns_original(self):
        """Negative frequency should not match any band."""
        self.assertEqual(refine_classification("wifi", -2_437_000_000), "wifi")


if __name__ == "__main__":
    unittest.main()
