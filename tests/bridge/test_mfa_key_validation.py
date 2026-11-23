"""BRIDGE_MFA_KEY / BRIDGE_AUDIT_KEY fail-closed behaviour.

A BRIDGE_MFA_KEY that is set but is not a valid Fernet key (the release
installer generated such keys with ``secrets.token_urlsafe(32)``, which is
unpadded) used to be logged and ignored: TOTP secrets were then stored as
``b64:`` plaintext even in production, and the startup guard only checked
that the variable was non-empty.
"""

from __future__ import annotations

import base64
import logging
import os
import secrets
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

import sigrift.bridge.storage.users as users_mod
from sigrift.bridge.storage.users import (
    _decrypt_totp_secret,
    _encrypt_totp_secret,
    _get_fernet,
    mfa_key_problem,
)

from .test_lifespan import (
    _lifespan_env,
    _make_app_with_lifespan,
    _patch_data_paths,
    _patch_detection_store,
    _patch_iq_store,
    _patch_pcap_store,
    _patch_persistence_dir,
)

# What the old installer wrote: 43 url-safe chars, no '=' padding.  The
# old gateway accepted it, so appending '=' is the (lossless) repair.
# Fixed values (not secrets.token_urlsafe / Fernet.generate_key) so the
# parametrized test ids are identical on every xdist worker.
_INSTALLER_STYLE_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
_GENERATED_KEY = base64.urlsafe_b64encode(bytes(range(100, 132))).decode()
# An invalid key that cannot be repaired: a new key must be generated.
_GARBAGE_KEY = "not-a-fernet-key"
_APPEND_HINT = "append '='"
_KEYGEN_HINT = "Fernet.generate_key()"

# Shared vector (same one the gateway's fernet_enc.rs tests use): a
# standard-alphabet key ('+', '/') such as `openssl rand -base64 32` prints.
_STD_ALPHABET_KEY = "TtQXipRlc/PC8mwGViJxxI6CC0tEgRYHZIzYBDg3Dyg="
_STD_ALPHABET_KEY_BYTES = bytes.fromhex(
    "4ed4178a946573f3c2f26c06562271c48e820b4b44811607648cd80438370f28"
)

# Shared vectors from the gateway's fernet_enc.rs tests (computed with
# Python `cryptography`): URLSAFE_KEY with non-zero trailing bits in its
# 43rd character, which Python's Fernet and the gateway both accept and
# decode to URLSAFE_KEY's bytes, and a token the gateway encrypted under
# URLSAFE_KEY (Fernet(key)._encrypt_from_parts(b"JBSWY3DPEHPK3PXP",
# 1700000000, bytes(range(16)))).
_GATEWAY_URLSAFE_KEY = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzM="
_GATEWAY_NONCANONICAL_KEY = "gbhtBUbPkbiIqPMsYEdh1YUZAxWFy-1pp3gVY24zhzN="
_GATEWAY_URLSAFE_KEY_BYTES = bytes.fromhex(
    "81b86d0546cf91b888a8f32c604761d58519031585cbed69a77815636e338733"
)
_GATEWAY_URLSAFE_TOKEN = (
    "fernet:gAAAAABlU_EAAAECAwQFBgcICQoLDA0OD3hrj0EybXZ_uqlhhD-"
    "dLSQpOP9oZl2oyisR9kHusJYe_csoAJQW3vb2XeCyQUALyNHgqWsXDYYe1dOIVLlyqnc="
)


@pytest.fixture(autouse=True)
def _reset_fernet_cache():
    users_mod._fernet_instance = None
    users_mod._mfa_encryption_warned = False
    users_mod._mfa_invalid_key_warned = False
    yield
    users_mod._fernet_instance = None
    users_mod._mfa_encryption_warned = False
    users_mod._mfa_invalid_key_warned = False


def _env(**values: str) -> dict[str, str]:
    """Env overrides with the production switches cleared unless given."""
    base = {"BRIDGE_ENV": "", "BRIDGE_MODE": "", "BRIDGE_MFA_KEY": ""}
    base.update(values)
    return base


class TestMfaKeyProblem:
    def test_valid_fernet_key(self):
        assert mfa_key_problem(Fernet.generate_key().decode()) is None

    def test_installer_style_key_is_invalid(self):
        problem = mfa_key_problem(_INSTALLER_STYLE_KEY)
        assert problem is not None
        assert "not a valid Fernet key" in problem

    def test_wrong_length_key_is_invalid(self):
        short = base64.urlsafe_b64encode(b"x" * 16).decode()
        assert "not a valid Fernet key" in mfa_key_problem(short)

    @pytest.mark.parametrize("value", ["", "   "])
    def test_unset(self, value):
        assert mfa_key_problem(value) == "BRIDGE_MFA_KEY is not set"

    def test_reads_environment_by_default(self):
        with patch.dict(os.environ, _env(BRIDGE_MFA_KEY=_INSTALLER_STYLE_KEY)):
            assert mfa_key_problem() is not None
        with patch.dict(
            os.environ, _env(BRIDGE_MFA_KEY=Fernet.generate_key().decode())
        ):
            assert mfa_key_problem() is None


def _non_canonical(key: str) -> str:
    """Same 32 bytes, but the 43rd character's lowest unused bit set."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    return key[:42] + alphabet[alphabet.index(key[42]) | 0b01] + "="


class TestCanonicalKeyRule:
    """C1/C2: the BRIDGE_MFA_KEY rule shared with the gateway and installers."""

    @pytest.mark.parametrize(
        "key",
        [
            _GENERATED_KEY,
            _STD_ALPHABET_KEY,
            # URL-safe spelling of the same key, and a mix of both alphabets.
            _STD_ALPHABET_KEY.replace("/", "_"),
            "-tQXipRlc/PC8mwGViJxxI6CC0tEgRYHZIzYBDg3Dyg=",
            f"  {_STD_ALPHABET_KEY}\n",  # surrounding whitespace is trimmed
            # Non-zero trailing bits are ignored (C1: as Python's Fernet
            # and the gateway ignore them).
            _non_canonical(_GENERATED_KEY),
            _GATEWAY_NONCANONICAL_KEY,
        ],
    )
    def test_valid(self, key):
        assert users_mod.is_valid_fernet_key(key)
        assert mfa_key_problem(key) is None
        # Never accept a key Python's own Fernet would reject.
        Fernet(key.strip().encode())

    @pytest.mark.parametrize(
        "key",
        [
            _INSTALLER_STYLE_KEY,  # 43 chars, unpadded
            _INSTALLER_STYLE_KEY + "==",  # 45 chars
            "A" * 44,  # 44th char is not '='
            "A" * 42 + "==",  # '=' inside the first 43
            "A" * 21 + "!" + "A" * 21 + "=",  # outside both alphabets
            "A" * 21 + " " + "A" * 21 + "=",  # inner whitespace
            "A" * 21 + "." + "A" * 21 + "=",
            base64.urlsafe_b64encode(b"x" * 16).decode(),  # 16-byte key
            _GARBAGE_KEY,
        ],
    )
    def test_invalid(self, key):
        assert not users_mod.is_valid_fernet_key(key)
        assert "not a valid Fernet key" in mfa_key_problem(key)

    def test_standard_alphabet_vector_decodes_to_shared_bytes(self):
        assert (
            users_mod._decode_fernet_key(_STD_ALPHABET_KEY) == _STD_ALPHABET_KEY_BYTES
        )
        assert (
            users_mod._decode_fernet_key(_STD_ALPHABET_KEY.replace("/", "_"))
            == _STD_ALPHABET_KEY_BYTES
        )

    def test_trailing_bits_are_ignored(self):
        assert _non_canonical(_GENERATED_KEY) != _GENERATED_KEY
        assert users_mod._decode_fernet_key(
            _non_canonical(_GENERATED_KEY)
        ) == base64.urlsafe_b64decode(_GENERATED_KEY)
        for key in (_GATEWAY_URLSAFE_KEY, _GATEWAY_NONCANONICAL_KEY):
            assert users_mod._decode_fernet_key(key) == _GATEWAY_URLSAFE_KEY_BYTES

    @pytest.mark.parametrize("key", [_GATEWAY_URLSAFE_KEY, _GATEWAY_NONCANONICAL_KEY])
    @pytest.mark.parametrize("bridge_env", ["production", "development"])
    def test_decrypts_gateway_token(self, key, bridge_env):
        # A TOTP secret the gateway wrote stays readable through the bridge
        # under either spelling of the key, in production and in dev.
        with patch.dict(os.environ, _env(BRIDGE_ENV=bridge_env, BRIDGE_MFA_KEY=key)):
            assert mfa_key_problem() is None
            assert _decrypt_totp_secret(_GATEWAY_URLSAFE_TOKEN) == "JBSWY3DPEHPK3PXP"
            # ...and what the bridge writes, the gateway's key bytes read.
            stored = _encrypt_totp_secret("JBSWY3DPEHPK3PXP")
        assert stored.startswith("fernet:")
        gateway = Fernet(base64.urlsafe_b64encode(_GATEWAY_URLSAFE_KEY_BYTES))
        assert gateway.decrypt(stored[7:].encode()) == b"JBSWY3DPEHPK3PXP"

    def test_standard_alphabet_key_encrypts_for_url_safe_spelling(self):
        # Same 32 bytes ⇒ same Fernet key: a secret encrypted under the
        # '+'/'/' spelling decrypts under the '-'/'_' one (and the gateway,
        # which decodes with the same mapping).
        with patch.dict(
            os.environ,
            _env(BRIDGE_ENV="production", BRIDGE_MFA_KEY=_STD_ALPHABET_KEY),
        ):
            stored = _encrypt_totp_secret("JBSWY3DPEHPK3PXP")
        assert stored.startswith("fernet:")
        url_safe = Fernet(base64.urlsafe_b64encode(_STD_ALPHABET_KEY_BYTES))
        assert url_safe.decrypt(stored[7:].encode()) == b"JBSWY3DPEHPK3PXP"

    @pytest.mark.parametrize("seed", range(20))
    def test_every_encoder_output_is_valid(self, seed):
        raw = os.urandom(32)
        for encode in (base64.urlsafe_b64encode, base64.b64encode):
            key = encode(raw).decode()
            assert users_mod._decode_fernet_key(key) == raw

    @pytest.mark.parametrize(
        "key",
        [
            _INSTALLER_STYLE_KEY,
            _GATEWAY_URLSAFE_KEY[:43],
            # Non-zero trailing bits: still 32 bytes once '=' is appended,
            # so still repaired losslessly (C2), not replaced.
            _non_canonical(_INSTALLER_STYLE_KEY + "=")[:43],
            _GATEWAY_NONCANONICAL_KEY[:43],
            f" {_INSTALLER_STYLE_KEY}\n",
        ],
    )
    def test_repairable_legacy_key(self, key):
        assert len(key.strip()) == 43
        assert users_mod.is_repairable_mfa_key(key)
        assert not users_mod.is_valid_fernet_key(key)
        # Lossless: appending '=' keeps the same 32 bytes the old gateway used.
        repaired = key.strip() + "="
        assert users_mod._decode_fernet_key(repaired) == base64.urlsafe_b64decode(
            repaired
        )
        assert mfa_key_problem(repaired) is None
        assert "43 characters" in mfa_key_problem(key)
        assert _APPEND_HINT in users_mod.mfa_key_remedy(key)
        assert _KEYGEN_HINT not in users_mod.mfa_key_remedy(key)

    @pytest.mark.parametrize(
        "key",
        [
            _INSTALLER_STYLE_KEY[:42],  # too short
            _STD_ALPHABET_KEY[:43],  # standard alphabet: not what installers wrote
            "!" * 43,
            _GARBAGE_KEY,
        ],
    )
    def test_not_repairable(self, key):
        assert not users_mod.is_repairable_mfa_key(key)
        assert _KEYGEN_HINT in users_mod.mfa_key_remedy(key)


class TestGetFernet:
    @pytest.mark.parametrize(
        "prod_env",
        [
            {"BRIDGE_ENV": "production"},
            {"BRIDGE_ENV": "prod"},
            {"BRIDGE_MODE": "production"},
        ],
    )
    @pytest.mark.parametrize(
        ("bad_key", "hint", "not_hint"),
        [
            (_INSTALLER_STYLE_KEY, _APPEND_HINT, _KEYGEN_HINT),
            (_GARBAGE_KEY, _KEYGEN_HINT, _APPEND_HINT),
        ],
    )
    def test_invalid_key_raises_in_production(self, prod_env, bad_key, hint, not_hint):
        with patch.dict(os.environ, _env(BRIDGE_MFA_KEY=bad_key, **prod_env)):
            with pytest.raises(RuntimeError, match="not a valid Fernet key") as ei:
                _get_fernet()
            assert hint in str(ei.value)
            assert not_hint not in str(ei.value)
            # Never silently degrades to base64 in production.
            with pytest.raises(RuntimeError):
                _encrypt_totp_secret("JBSWY3DPEHPK3PXP")

    @pytest.mark.parametrize(
        ("bad_key", "hint"),
        [(_INSTALLER_STYLE_KEY, _APPEND_HINT), (_GARBAGE_KEY, _KEYGEN_HINT)],
    )
    def test_invalid_key_warns_once_and_falls_back_in_dev(self, caplog, bad_key, hint):
        with patch.dict(
            os.environ,
            _env(BRIDGE_ENV="development", BRIDGE_MFA_KEY=bad_key),
        ):
            with caplog.at_level(logging.WARNING, logger=users_mod.__name__):
                assert _get_fernet() is None
                assert _get_fernet() is None
                stored = _encrypt_totp_secret("JBSWY3DPEHPK3PXP")
        assert stored.startswith("b64:")
        warnings = [
            r for r in caplog.records if "not a valid Fernet key" in r.getMessage()
        ]
        assert len(warnings) == 1
        assert hint in warnings[0].getMessage()

    def test_valid_key_encrypts_in_production(self):
        key = Fernet.generate_key().decode()
        with patch.dict(os.environ, _env(BRIDGE_ENV="production", BRIDGE_MFA_KEY=key)):
            stored = _encrypt_totp_secret("JBSWY3DPEHPK3PXP")
            assert stored.startswith("fernet:")
            assert _decrypt_totp_secret(stored) == "JBSWY3DPEHPK3PXP"

    @pytest.mark.parametrize("mfa_key", ["valid", "invalid"])
    def test_existing_b64_secrets_stay_readable_in_production(self, mfa_key):
        key = (
            Fernet.generate_key().decode()
            if mfa_key == "valid"
            else _INSTALLER_STYLE_KEY
        )
        legacy = "b64:" + base64.b64encode(b"JBSWY3DPEHPK3PXP").decode()
        with patch.dict(os.environ, _env(BRIDGE_ENV="production", BRIDGE_MFA_KEY=key)):
            assert _decrypt_totp_secret(legacy) == "JBSWY3DPEHPK3PXP"

    def test_user_store_reads_b64_secret_after_key_fixed(self, detection_store):
        users = detection_store._users
        users.create_user("legacy_mfa", "Password123!", role="viewer")
        user = users.get_user("legacy_mfa")
        # Stored while the (invalid) installer key was in place, in dev.
        with patch.dict(os.environ, _env(BRIDGE_MFA_KEY=_INSTALLER_STYLE_KEY)):
            users.set_totp_secret(user["id"], "JBSWY3DPEHPK3PXP")
        raw = (
            detection_store.get_connection()
            .execute("SELECT totp_secret FROM users WHERE id = ?", [user["id"]])
            .fetchone()[0]
        )
        assert raw.startswith("b64:")

        users_mod._fernet_instance = None
        key = Fernet.generate_key().decode()
        with patch.dict(os.environ, _env(BRIDGE_ENV="production", BRIDGE_MFA_KEY=key)):
            assert (
                users.get_user_full("legacy_mfa")["totp_secret"] == "JBSWY3DPEHPK3PXP"
            )


class TestProductionStartupGuard:
    def _start(self, tmp_path: Path, **env_values: str) -> None:
        data = tmp_path / "data"
        data.mkdir()
        app = _make_app_with_lifespan()
        env = _lifespan_env(data)
        env.update(
            {
                "BRIDGE_ENV": "",
                "BRIDGE_MODE": "",
                "BRIDGE_MFA_KEY": "",
                "BRIDGE_AUDIT_KEY": "",
                "BRIDGE_MASTER_KEY": "",
                # tests/bridge/conftest.py turns CSRF off for the suite,
                # which production refuses; these tests start with it unset.
                "BRIDGE_CSRF": "",
            }
        )
        env.update(env_values)
        with (
            patch.dict(os.environ, env),
            _patch_data_paths(data),
            _patch_persistence_dir(data),
            _patch_detection_store(data),
            _patch_iq_store(data),
            _patch_pcap_store(data),
        ):
            with TestClient(app):
                pass

    def test_refuses_invalid_mfa_key(self, tmp_path):
        with pytest.raises(RuntimeError, match="not a valid Fernet key") as ei:
            self._start(
                tmp_path,
                BRIDGE_ENV="production",
                BRIDGE_MFA_KEY=_GARBAGE_KEY,
                BRIDGE_AUDIT_KEY=secrets.token_urlsafe(32),
            )
        assert _KEYGEN_HINT in str(ei.value)

    def test_refuses_unpadded_key_with_lossless_repair_hint(self, tmp_path):
        # C2: a 43-character key is repaired by appending '=' (existing
        # encrypted TOTP secrets stay readable), never by a new key.
        with pytest.raises(RuntimeError, match="not a valid Fernet key") as ei:
            self._start(
                tmp_path,
                BRIDGE_ENV="production",
                BRIDGE_MFA_KEY=_INSTALLER_STYLE_KEY,
                BRIDGE_AUDIT_KEY=secrets.token_urlsafe(32),
            )
        message = str(ei.value)
        assert "43 characters" in message
        assert _APPEND_HINT in message
        assert "keep existing encrypted TOTP secrets readable" in message
        assert _KEYGEN_HINT not in message

    @pytest.mark.parametrize("key", [_STD_ALPHABET_KEY, _GATEWAY_NONCANONICAL_KEY])
    def test_starts_with_any_key_the_gateway_accepts(self, tmp_path, key):
        # '+' and '/' keys and keys with non-zero trailing bits are valid
        # under the shared rule (the gateway accepts them too), so
        # production starts (with the other secrets it requires; no users
        # exist yet, so that includes BRIDGE_ADMIN_PASSWORD).
        self._start(
            tmp_path,
            BRIDGE_ENV="production",
            BRIDGE_MFA_KEY=key,
            BRIDGE_AUDIT_KEY=secrets.token_urlsafe(32),
            BRIDGE_MASTER_KEY=secrets.token_urlsafe(32),
            BRIDGE_ADMIN_PASSWORD=secrets.token_urlsafe(16),
            UC_PROXY_SECRET=secrets.token_urlsafe(32),
        )

    def test_refuses_missing_audit_key(self, tmp_path):
        with pytest.raises(RuntimeError, match="BRIDGE_AUDIT_KEY is not set"):
            self._start(
                tmp_path,
                BRIDGE_ENV="production",
                BRIDGE_MFA_KEY=Fernet.generate_key().decode(),
            )

    @pytest.mark.parametrize(
        "prod_env", [{"BRIDGE_ENV": "prod"}, {"BRIDGE_MODE": "production"}]
    )
    def test_production_aliases_also_fail_closed(self, tmp_path, prod_env):
        # Same production detection as the MFA/audit key stores: the audit
        # key is now required at startup for these spellings too.
        with pytest.raises(RuntimeError, match="BRIDGE_AUDIT_KEY is not set"):
            self._start(
                tmp_path,
                BRIDGE_MFA_KEY=Fernet.generate_key().decode(),
                **prod_env,
            )

    # Owner decision (2026-11-10): production refuses to start with CSRF
    # protection turned off. The CSRF middleware turns it off for every
    # non-empty BRIDGE_CSRF other than "enabled" (not just "disabled"), so
    # every such value is refused; the gateway refuses the same set.
    _PRODUCTION_KEYS = {
        "BRIDGE_MFA_KEY": _STD_ALPHABET_KEY,
        "BRIDGE_AUDIT_KEY": "audit-key-for-the-csrf-guard-tests",
        "BRIDGE_MASTER_KEY": "master-key-for-the-csrf-guard-tests",
        "UC_PROXY_SECRET": "proxy-secret-for-the-csrf-guard-tests",
        # No user exists yet, and production refuses to start without one.
        "BRIDGE_ADMIN_PASSWORD": "admin-password-for-the-csrf-guard-tests",
    }

    @pytest.mark.parametrize(
        "value", ["disabled", "Disabled", " disabled ", "off", "true", "0"]
    )
    @pytest.mark.parametrize(
        "prod_env",
        [{"BRIDGE_ENV": "production"}, {"BRIDGE_ENV": "prod"}, {"BRIDGE_MODE": "prod"}],
    )
    def test_refuses_csrf_protection_turned_off(self, tmp_path, prod_env, value):
        with pytest.raises(RuntimeError, match="BRIDGE_CSRF") as ei:
            self._start(
                tmp_path, BRIDGE_CSRF=value, **prod_env, **self._PRODUCTION_KEYS
            )
        message = str(ei.value)
        assert repr(value) in message
        assert "unset BRIDGE_CSRF or set it to enabled" in message

    @pytest.mark.parametrize("value", ["", "enabled", " Enabled "])
    def test_starts_with_csrf_protection_on(self, tmp_path, value):
        self._start(
            tmp_path,
            BRIDGE_ENV="production",
            BRIDGE_CSRF=value,
            **self._PRODUCTION_KEYS,
        )

    def test_csrf_off_outside_production_starts_with_a_warning(self, tmp_path, caplog):
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.app"):
            self._start(tmp_path, BRIDGE_ENV="development", BRIDGE_CSRF="disabled")
        assert any(
            "BRIDGE_CSRF='disabled' turns CSRF protection off" in r.getMessage()
            and r.levelno == logging.WARNING
            for r in caplog.records
        ), [r.getMessage() for r in caplog.records]


class TestHealthWarning:
    def test_invalid_key_reported_as_unencrypted(self, client):
        with patch.dict(os.environ, {"BRIDGE_MFA_KEY": _INSTALLER_STYLE_KEY}):
            resp = client.get("/api/health")
        assert resp.status_code == 200
        warnings = resp.json().get("security_warnings", [])
        assert any("TOTP" in w and "not a valid Fernet key" in w for w in warnings)
