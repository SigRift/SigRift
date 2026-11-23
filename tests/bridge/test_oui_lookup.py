"""Tests for OUI vendor lookup module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from sigrift.bridge.oui_lookup import _OUI_DB_PATH, _load_oui_db, lookup_vendor, oui_prefix

_OUI_DB_AVAILABLE = _OUI_DB_PATH.exists()


class TestOuiPrefix:
    def test_colon_separated(self):
        assert oui_prefix("AA:BB:CC:DD:EE:FF") == "AABBCC"

    def test_dash_separated(self):
        assert oui_prefix("aa-bb-cc-dd-ee-ff") == "AABBCC"

    def test_dot_separated(self):
        assert oui_prefix("aabb.ccdd.eeff") == "AABBCC"

    def test_raw_hex(self):
        assert oui_prefix("aabbccddeeff") == "AABBCC"

    def test_uppercase(self):
        assert oui_prefix("AA:BB:CC:DD:EE:FF") == "AABBCC"

    def test_lowercase(self):
        assert oui_prefix("aa:bb:cc:dd:ee:ff") == "AABBCC"

    def test_mixed_case(self):
        assert oui_prefix("Aa:Bb:Cc:11:22:33") == "AABBCC"

    def test_empty_string(self):
        assert oui_prefix("") == ""

    def test_too_short(self):
        assert oui_prefix("AA:BB") == ""

    def test_exactly_6_hex(self):
        assert oui_prefix("AABBCC") == "AABBCC"


class TestLookupVendor:
    def test_known_oui(self):
        """Known OUI should return vendor name."""
        with patch("sigrift.bridge.oui_lookup._oui_db", {"B827EB": "Raspberry Pi Foundation"}):
            assert lookup_vendor("B8:27:EB:AA:BB:CC") == "Raspberry Pi Foundation"

    def test_unknown_oui(self):
        """Unknown OUI should return empty string."""
        with patch("sigrift.bridge.oui_lookup._oui_db", {"B827EB": "Raspberry Pi Foundation"}):
            assert lookup_vendor("00:11:22:33:44:55") == ""

    def test_empty_mac(self):
        """Empty MAC should return empty string."""
        with patch("sigrift.bridge.oui_lookup._oui_db", {"B827EB": "Raspberry Pi Foundation"}):
            assert lookup_vendor("") == ""

    def test_case_insensitive(self):
        """Lookup should be case-insensitive."""
        with patch("sigrift.bridge.oui_lookup._oui_db", {"B827EB": "Raspberry Pi Foundation"}):
            assert lookup_vendor("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"

    def test_dash_separated_mac(self):
        """Dash-separated MAC should work."""
        with patch("sigrift.bridge.oui_lookup._oui_db", {"B827EB": "Raspberry Pi Foundation"}):
            assert lookup_vendor("B8-27-EB-AA-BB-CC") == "Raspberry Pi Foundation"


class TestLoadOuiDb:
    def test_loads_from_file(self):
        """Should load the gzip JSON database."""
        db = _load_oui_db()
        # Should load without error even if file is small
        assert isinstance(db, dict)

    def test_missing_file_returns_empty(self, tmp_path):
        """Should return empty dict if file doesn't exist."""
        with patch("sigrift.bridge.oui_lookup._OUI_DB_PATH", tmp_path / "nonexistent.json.gz"):
            db = _load_oui_db()
            assert db == {}


class TestLookupVendorIntegration:
    """Integration test using the actual OUI database file."""

    @pytest.mark.skipif(
        not _OUI_DB_AVAILABLE,
        reason="OUI database (data/oui.json.gz) not shipped in community repo",
    )
    def test_raspberry_pi(self):
        """Known Raspberry Pi OUI should resolve."""
        import sigrift.bridge.oui_lookup as mod
        # Reset module-level cache
        mod._oui_db = {}
        vendor = lookup_vendor("B8:27:EB:AA:BB:CC")
        assert "Raspberry Pi" in vendor

    @pytest.mark.skipif(
        not _OUI_DB_AVAILABLE,
        reason="OUI database (data/oui.json.gz) not shipped in community repo",
    )
    def test_cisco(self):
        """Known Cisco OUI should resolve."""
        import sigrift.bridge.oui_lookup as mod
        mod._oui_db = {}
        vendor = lookup_vendor("00:17:5A:AA:BB:CC")
        assert "Cisco" in vendor

    def test_unknown_returns_empty(self):
        """Unknown OUI should return empty string."""
        import sigrift.bridge.oui_lookup as mod
        mod._oui_db = {}
        assert lookup_vendor("FF:FF:FF:FF:FF:FE") == ""
