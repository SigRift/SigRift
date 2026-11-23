"""Credential compatibility and validation boundaries at the security API."""

import base64
import hashlib
from pathlib import Path

import pytest

from sigrift.lib.security import credentials, validation


def test_password_derivation_matches_independent_openssl_vector():
    # OpenSSL kdf PBKDF2, SHA256, password/password, salt/73616c74,
    # 600000 iterations, 32-byte result. Preserve the configured work factor.
    result, salt = credentials.hash_credential("password", salt=b"salt")
    assert result == "669cfe52482116fda1aa2cbe409b2f56c8e4563752b7a28f6eaab614ee005178"
    assert salt == b"salt"
    assert credentials.verify_credential("password", result, salt)
    assert not credentials.verify_credential("wrong password", result, salt)


def test_legacy_credentials_remain_readable_and_upgrade_to_salted_pbkdf2(caplog):
    password, old_salt = "legacy-α", b"old-salt"
    legacy = hashlib.sha256(old_salt + password.encode()).hexdigest()
    assert credentials.verify_credential(password, legacy, old_salt)
    assert "Legacy SHA-256 credential matched" in caplog.text
    caplog.clear()
    upgraded, salt, lookup = credentials.upgrade_legacy_credential(password)
    assert len(salt) == 32
    assert salt != old_salt
    assert upgraded != legacy
    assert lookup == hashlib.sha256(password.encode()).hexdigest()
    assert credentials.verify_credential(password, upgraded, salt)
    assert "Legacy SHA-256 credential matched" not in caplog.text
    assert not credentials.verify_credential("wrong", legacy, old_salt)


@pytest.mark.parametrize("stored", ["", "invalid hash", "0" * 64])
def test_unrecognized_or_nonmatching_credential_hash_is_rejected(stored):
    assert not credentials.verify_credential("password", stored, b"salt")


@pytest.mark.parametrize("byte_length", [16, 32, 64])
def test_generated_api_key_preserves_requested_entropy_bytes(byte_length):
    token = credentials.generate_api_key(byte_length)
    decoded = base64.b64decode(
        token + "=" * (-len(token) % 4), altchars=b"-_", validate=True
    )
    assert len(decoded) == byte_length
    assert set(token) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )


@pytest.mark.parametrize("byte_length", [-1, 0, 15])
def test_api_key_generation_rejects_less_than_minimum_random_bytes(byte_length):
    with pytest.raises(ValueError, match="at least 16"):
        credentials.generate_api_key(byte_length)


@pytest.mark.parametrize(
    "validator,lower,upper",
    [
        (validation.validate_frequency, 1e6, 6e9),
        (validation.validate_gain, 0, 73),
        (validation.validate_sample_rate, 225001, 3.2e6),
    ],
)
def test_radio_limits_accept_endpoints_and_reject_outside_or_nonfinite_values(
    validator, lower, upper
):
    assert validator(str(lower)) == lower
    assert validator(upper) == upper
    for invalid in (lower - 1, upper + 1, float("nan"), float("inf"), -float("inf")):
        with pytest.raises(ValueError):
            validator(invalid)


@pytest.mark.parametrize("host", ["localhost", "node-1.local", "127.0.0.1", "a"])
def test_host_validation_preserves_accepted_addresses(host):
    assert validation.validate_host(" " + host + " ") == host


@pytest.mark.parametrize("host", ["", " ", "a" * 254, "node name", "bad/host", "-node"])
def test_host_validation_rejects_empty_oversized_or_unsafe_addresses(host):
    with pytest.raises(ValueError):
        validation.validate_host(host)


class _UnstrippedStr(str):
    """A str whose str() and strip() keep it as it is (trailing newline too)."""

    def __str__(self):
        return self

    def strip(self, chars=None):
        return self


@pytest.mark.parametrize("host", ["node-1\n", "127.0.0.1\n"])
def test_host_validation_rejects_a_trailing_newline_without_relying_on_strip(host):
    """The format check holds on its own: '$' with re.match would accept it."""
    with pytest.raises(ValueError, match="Invalid host format"):
        validation.validate_host(_UnstrippedStr(host))
    assert validation.validate_host(host) == host.strip()


@pytest.mark.parametrize("port", [1, 65535, "443"])
def test_port_validation_accepts_usable_boundaries(port):
    assert validation.validate_port(port) == int(port)


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_port_validation_rejects_unusable_values(port):
    with pytest.raises(ValueError, match="outside valid range"):
        validation.validate_port(port)


def test_path_validation_accepts_internal_path_and_rejects_symlink_escape(tmp_path):
    base, outside = tmp_path / "base", tmp_path / "outside"
    base.mkdir()
    outside.mkdir()
    inside = base / "record.json"
    assert validation.validate_path(str(inside), str(base)) == str(inside.resolve())
    (base / "escape").symlink_to(outside, target_is_directory=True)
    for invalid in (
        base / ".." / "outside" / "record.json",
        base / "escape" / "record.json",
    ):
        with pytest.raises(ValueError, match="Path traversal"):
            validation.validate_path(str(invalid), str(base))
    with pytest.raises(ValueError, match="cannot be empty"):
        validation.validate_path("", str(base))
    # The returned absolute path stays valid independently of caller cwd.
    assert Path(validation.validate_path(str(base), str(base))).is_absolute()
