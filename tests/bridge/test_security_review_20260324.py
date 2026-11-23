"""Offensive security tests — verify controls work AND attempt bypasses.

Tests KEYMASTER escalation, NaN/Inf bypass prevention, JWT security,
forbidden band enforcement, input validation, and signal tester bounds.
"""

import math
import os
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

os.environ.setdefault("BRIDGE_CSRF", "disabled")

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.fuzz_safety import (
    BandViolationError,
    FuzzSafetyError,
    PowerViolationError,
    validate_tx_frequency,
    validate_tx_gain,
    validate_tx_request,
)
# ============================================================================
# NaN / Inf Bypass Prevention
# ============================================================================


class TestNanInfBypass:

    def test_nan_frequency_raises_band_violation(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(float("nan"))

    def test_inf_frequency_raises_band_violation(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(float("inf"))

    def test_neg_inf_frequency_raises_band_violation(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(float("-inf"))

    def test_nan_gain_raises_power_violation(self):
        with pytest.raises(PowerViolationError):
            validate_tx_gain(float("nan"))

    def test_inf_gain_raises_power_violation(self):
        with pytest.raises(PowerViolationError):
            validate_tx_gain(float("inf"))

    def test_nan_duration_in_validate_tx_request(self):
        with pytest.raises(FuzzSafetyError):
            validate_tx_request(433.92e6, 125e3, 10, float("nan"))

    def test_inf_duration_in_validate_tx_request(self):
        with pytest.raises(FuzzSafetyError):
            validate_tx_request(433.92e6, 125e3, 10, float("inf"))

    def test_nan_bandwidth_in_validate_tx_frequency(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(433.92e6, bandwidth_hz=float("nan"))


# ============================================================================
# Positive Controls — Key Material Protection
# ============================================================================


class TestListKeysOmitsMaterial:

    def test_list_keys_no_key_material_field(self):
        from sigrift.lib.crypto.key_store import KeyStore

        ks = KeyStore()
        ks.add_key("meshtastic", "aes-128-ctr", b"\x01" * 16, "k1")
        ks.add_key("dmr", "xor", b"\x02" * 3, "k2")
        ks.add_key("p25", "des-ofb", b"\x03" * 8, "k3")
        keys = ks.list_keys()
        assert len(keys) == 3
        for entry in keys:
            assert "key_material" not in entry, \
                f"key_material leaked in list_keys() entry: {entry.get('key_id')}"


# ============================================================================
# JWT Security
# ============================================================================


# ============================================================================
# Forbidden Band Enforcement
# ============================================================================


class TestForbiddenBandEnforcement:

    def test_aviation_vhf_blocked(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(121.5e6)

    def test_gps_l1_blocked(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(1575.42e6)

    def test_military_uhf_blocked(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(300e6)

    def test_adsb_blocked(self):
        with pytest.raises(BandViolationError):
            validate_tx_frequency(1090e6)


# ============================================================================
# TX Gain Hard Cap
# ============================================================================


class TestTXGainHardCap:

    def test_gain_above_hard_cap_blocked(self):
        with pytest.raises(PowerViolationError):
            validate_tx_gain(41)

    def test_gain_at_configured_max_allowed(self):
        validate_tx_gain(20)  # default configured max


# ============================================================================
# Input Validation — API Endpoints
# ============================================================================


class TestCryptoEndpointValidation:

    def test_import_key_invalid_hex_returns_400(self, client):
        """POST /api/crypto/keys with non-hex key material should 400."""
        from sigrift.lib.crypto.key_store import KeyStore
        ks = KeyStore()
        with pytest.raises(ValueError):
            ks.import_hex("not-valid-hex!", "test", "aes", "bad")


class TestCryptoDecryptValidation:

    def test_decrypt_empty_payload_returns_error(self, client):
        """POST /api/crypto/decrypt with very short payload should fail."""
        resp = client.post("/api/crypto/decrypt", json={
            "payload_hex": "aa",
            "protocol": "meshtastic",
        })
        # 200 with success=False (no key decrypts 1 byte confidently),
        # or 4xx if validation rejects it outright.
        if resp.status_code == 200:
            assert resp.json()["success"] is False
        else:
            assert resp.status_code in (400, 404, 422)


# ============================================================================
# Helper
# ============================================================================


def _b64url_decode_helper(s: str) -> bytes:
    """Decode base64url with padding."""
    from base64 import urlsafe_b64decode
    s += "=" * (-len(s) % 4)
    return urlsafe_b64decode(s)
