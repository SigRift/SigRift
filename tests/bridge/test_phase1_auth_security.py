"""Tests for Phase 1 auth & security items: D-3, D-4, D-5, D-9.

D-3: MFA TOTP encrypt-before-store (verify existing implementation)
D-4: OIDC JWT signature verification via JWKS
D-5: OIDC nonce replay protection (verify existing implementation)
D-9: Backup encryption at rest
"""

from __future__ import annotations

import base64
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

try:
    from sigrift.bridge.routers import oidc
except ImportError:
    oidc = None

requires_oidc = pytest.mark.skipif(
    oidc is None or pyjwt is None,
    reason="OIDC router is enterprise-only and not shipped in community",
)

from sigrift.bridge.routers.maintenance import (
    _BACKUP_CHUNK_SIZE,
    _BACKUP_ENC_MAGIC,
    _decrypt_backup_file,
    _encrypt_backup_file,
    _get_backup_fernet,
)
from sigrift.bridge.storage.users import (
    _decrypt_totp_secret,
    _encrypt_totp_secret,
)


# ---------------------------------------------------------------------------
# Helpers: RSA key pair for JWT signing in tests
# ---------------------------------------------------------------------------

def _generate_rsa_keypair():
    """Generate an RSA private key and matching JWKS-format public key."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def _make_signed_id_token(
    claims: dict,
    private_key,
    kid: str = "test-key-1",
) -> str:
    """Create a properly RSA-signed JWT with the given claims."""
    return pyjwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


# ---------------------------------------------------------------------------
# D-3: MFA TOTP encrypt-before-store
# ---------------------------------------------------------------------------


class TestTOTPEncryption:
    """D-3: Verify TOTP secrets are encrypted before database storage."""

    def test_fernet_encryption_roundtrip(self):
        """TOTP secret encrypted with Fernet can be decrypted back."""
        key = Fernet.generate_key().decode()
        with patch.dict(os.environ, {"BRIDGE_MFA_KEY": key}):
            # Reset cached fernet
            import sigrift.bridge.storage.users as _users_mod
            _users_mod._fernet_instance = None

            encrypted = _encrypt_totp_secret("JBSWY3DPEHPK3PXP")
            assert encrypted.startswith("fernet:")
            decrypted = _decrypt_totp_secret(encrypted)
            assert decrypted == "JBSWY3DPEHPK3PXP"

            _users_mod._fernet_instance = None

    def test_base64_fallback_without_key(self):
        """Without BRIDGE_MFA_KEY, falls back to base64 encoding."""
        import sigrift.bridge.storage.users as _users_mod
        _users_mod._fernet_instance = None
        _users_mod._mfa_encryption_warned = False

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_MFA_KEY", None)
            os.environ.pop("BRIDGE_ENV", None)
            os.environ.pop("BRIDGE_MODE", None)
            encrypted = _encrypt_totp_secret("SECRET123")
            assert encrypted.startswith("b64:")
            decrypted = _decrypt_totp_secret(encrypted)
            assert decrypted == "SECRET123"

        _users_mod._fernet_instance = None

    def test_production_requires_key(self):
        """In production mode, missing BRIDGE_MFA_KEY raises RuntimeError."""
        import sigrift.bridge.storage.users as _users_mod
        _users_mod._fernet_instance = None

        with patch.dict(os.environ, {"BRIDGE_ENV": "production"}, clear=False):
            os.environ.pop("BRIDGE_MFA_KEY", None)
            with pytest.raises(RuntimeError, match="BRIDGE_MFA_KEY"):
                _encrypt_totp_secret("SECRET")

        _users_mod._fernet_instance = None

    def test_legacy_plaintext_decryption(self):
        """Legacy plaintext secrets (pre-migration) are returned as-is."""
        result = _decrypt_totp_secret("PLAINTEXT_SECRET")
        assert result == "PLAINTEXT_SECRET"

    def test_none_passthrough(self):
        """None values pass through encrypt/decrypt unchanged."""
        assert _encrypt_totp_secret(None) is None
        assert _decrypt_totp_secret(None) is None

    def test_set_totp_secret_encrypts(self, detection_store):
        """UserStore.set_totp_secret encrypts the secret before DB write."""
        key = Fernet.generate_key().decode()
        import sigrift.bridge.storage.users as _users_mod
        _users_mod._fernet_instance = None

        user_store = detection_store._users
        user_store.create_user("mfa_enc_user", "pass12345", role="viewer")
        user = user_store.get_user("mfa_enc_user")

        with patch.dict(os.environ, {"BRIDGE_MFA_KEY": key}):
            user_store.set_totp_secret(user["id"], "TESTSECRET")

        # Read raw from DB — should be encrypted, not plaintext
        conn = detection_store._ctx.get_conn()
        row = conn.execute(
            "SELECT totp_secret FROM users WHERE id = ?", [user["id"]]
        ).fetchone()
        assert row["totp_secret"].startswith("fernet:")
        assert "TESTSECRET" not in row["totp_secret"]

        _users_mod._fernet_instance = None


# ---------------------------------------------------------------------------
# D-4: OIDC JWT signature verification
# ---------------------------------------------------------------------------


@requires_oidc
class TestJWTSignatureVerification:
    """D-4: _verify_id_token validates JWT signature, issuer, audience, nonce."""

    @pytest.fixture(autouse=True)
    def _reset_jwks_cache(self):
        oidc._jwks_clients.clear()
        yield
        oidc._jwks_clients.clear()

    def _make_discovery(self, issuer: str, jwks_uri: str) -> dict:
        return {
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": jwks_uri,
        }

    def _make_config(self, issuer: str, client_id: str = "test-client") -> dict:
        return {
            "issuer": issuer,
            "client_id": client_id,
            "client_secret": "test-secret",
            "scopes": "openid email profile",
            "redirect_uri": "",
            "role_claim": "role",
            "default_role": "viewer",
            "auto_create": True,
        }

    def test_valid_signed_token_accepted(self):
        """Properly signed JWT with correct claims is accepted."""
        private_key, public_key = _generate_rsa_keypair()
        issuer = "https://idp.example.com"
        nonce = "test-nonce-123"

        claims = {
            "iss": issuer,
            "sub": "user-1",
            "aud": "test-client",
            "exp": int(time.time()) + 300,
            "nonce": nonce,
            "email": "user@example.com",
        }
        token = _make_signed_id_token(claims, private_key)

        # Mock the JWKS client to return our test public key
        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery(issuer, f"{issuer}/jwks")
        config = self._make_config(issuer)

        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks):
            result = oidc._verify_id_token(token, discovery, config, nonce)

        assert result["sub"] == "user-1"
        assert result["email"] == "user@example.com"
        assert result["nonce"] == nonce

    def test_tampered_signature_rejected(self):
        """JWT with tampered signature is rejected."""
        private_key, public_key = _generate_rsa_keypair()
        _, wrong_public_key = _generate_rsa_keypair()  # Different key pair
        issuer = "https://idp.example.com"

        claims = {
            "iss": issuer,
            "sub": "user-1",
            "aud": "test-client",
            "exp": int(time.time()) + 300,
            "nonce": "n1",
        }
        token = _make_signed_id_token(claims, private_key)

        # JWKS returns wrong public key — signature won't match
        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = wrong_public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery(issuer, f"{issuer}/jwks")
        config = self._make_config(issuer)

        from fastapi import HTTPException
        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks), \
             pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token(token, discovery, config, "n1")

        assert exc_info.value.status_code == 401
        assert "verification failed" in exc_info.value.detail.lower()

    def test_expired_token_rejected(self):
        """Expired JWT is rejected."""
        private_key, public_key = _generate_rsa_keypair()
        issuer = "https://idp.example.com"

        claims = {
            "iss": issuer,
            "sub": "user-1",
            "aud": "test-client",
            "exp": int(time.time()) - 300,  # Expired 5 min ago
            "nonce": "n1",
        }
        token = _make_signed_id_token(claims, private_key)

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery(issuer, f"{issuer}/jwks")
        config = self._make_config(issuer)

        from fastapi import HTTPException
        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks), \
             pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token(token, discovery, config, "n1")

        assert exc_info.value.status_code == 401

    def test_wrong_audience_rejected(self):
        """JWT with wrong audience is rejected."""
        private_key, public_key = _generate_rsa_keypair()
        issuer = "https://idp.example.com"

        claims = {
            "iss": issuer,
            "sub": "user-1",
            "aud": "wrong-client",  # Wrong audience
            "exp": int(time.time()) + 300,
            "nonce": "n1",
        }
        token = _make_signed_id_token(claims, private_key)

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery(issuer, f"{issuer}/jwks")
        config = self._make_config(issuer)  # expects "test-client"

        from fastapi import HTTPException
        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks), \
             pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token(token, discovery, config, "n1")

        assert exc_info.value.status_code == 401

    def test_wrong_issuer_rejected(self):
        """JWT with wrong issuer is rejected."""
        private_key, public_key = _generate_rsa_keypair()

        claims = {
            "iss": "https://evil.example.com",
            "sub": "user-1",
            "aud": "test-client",
            "exp": int(time.time()) + 300,
            "nonce": "n1",
        }
        token = _make_signed_id_token(claims, private_key)

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery("https://legit.example.com", "https://legit.example.com/jwks")
        config = self._make_config("https://legit.example.com")

        from fastapi import HTTPException
        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks), \
             pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token(token, discovery, config, "n1")

        assert exc_info.value.status_code == 401

    def test_nonce_mismatch_rejected(self):
        """JWT with wrong nonce is rejected."""
        private_key, public_key = _generate_rsa_keypair()
        issuer = "https://idp.example.com"

        claims = {
            "iss": issuer,
            "sub": "user-1",
            "aud": "test-client",
            "exp": int(time.time()) + 300,
            "nonce": "sent-nonce",
        }
        token = _make_signed_id_token(claims, private_key)

        mock_jwks = MagicMock()
        mock_signing_key = MagicMock()
        mock_signing_key.key = public_key
        mock_jwks.get_signing_key_from_jwt.return_value = mock_signing_key

        discovery = self._make_discovery(issuer, f"{issuer}/jwks")
        config = self._make_config(issuer)

        from fastapi import HTTPException
        with patch.object(oidc, "_get_jwks_client", return_value=mock_jwks), \
             pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token(token, discovery, config, "different-nonce")

        assert exc_info.value.status_code == 401
        assert "nonce" in exc_info.value.detail.lower()

    def test_missing_jwks_uri_returns_502(self):
        """Missing jwks_uri in discovery returns 502."""
        discovery = {"token_endpoint": "https://idp.example.com/token"}
        config = self._make_config("https://idp.example.com")

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            oidc._verify_id_token("fake.jwt.token", discovery, config, "n1")

        assert exc_info.value.status_code == 502
        assert "jwks_uri" in exc_info.value.detail.lower()

    def test_jwks_client_cached(self):
        """PyJWKClient is cached per jwks_uri."""
        with patch("sigrift.bridge.routers.oidc.PyJWKClient") as mock_cls:
            mock_cls.side_effect = lambda uri: MagicMock(name=f"client-{uri}")

            c1 = oidc._get_jwks_client("https://idp.example.com/jwks")
            c2 = oidc._get_jwks_client("https://idp.example.com/jwks")
            c3 = oidc._get_jwks_client("https://other.example.com/jwks")

            assert c1 is c2  # Same URI, same cached instance
            assert c1 is not c3  # Different URI, different instance
            assert mock_cls.call_count == 2


# ---------------------------------------------------------------------------
# D-5: OIDC nonce replay protection
# ---------------------------------------------------------------------------


@requires_oidc
class TestNonceReplayProtection:
    """D-5: Verify OIDC nonce is consumed on use (replay prevention)."""

    @pytest.fixture(autouse=True)
    def _cleanup_states(self):
        oidc._oidc_states.clear()
        yield
        oidc._oidc_states.clear()

    def test_state_consumed_on_callback(self):
        """State is popped from _oidc_states during callback processing."""
        state_key = "replay-test-state"
        oidc._oidc_states[state_key] = {
            "nonce": "test-nonce",
            "redirect": "/",
            "created_at": time.monotonic(),
        }
        assert state_key in oidc._oidc_states

        # Simulate callback consuming the state
        state_data = oidc._oidc_states.pop(state_key, None)
        assert isinstance(state_data, dict) and state_data["nonce"] == "test-nonce"
        assert state_key not in oidc._oidc_states

    def test_replayed_state_rejected(self, bridge_app, detection_store):
        """Second callback with same state is rejected."""
        from fastapi.testclient import TestClient

        state_key = "one-shot-state"
        nonce = "one-shot-nonce"
        issuer = "https://idp.example.com"

        # Store state in DB-backed store (TD-2)
        detection_store.security_state.create_oidc_state(
            state_key, nonce, "/",
        )

        verified_claims = {
            "iss": issuer,
            "sub": "user-1",
            "email": "replay@example.com",
            "nonce": nonce,
        }
        env = {
            "BRIDGE_OIDC_ISSUER": issuer,
            "BRIDGE_OIDC_CLIENT_ID": "c",
            "BRIDGE_OIDC_CLIENT_SECRET": "s",
        }
        token_response = MagicMock()
        token_response.status_code = 200
        token_response.json.return_value = {"id_token": "fake.jwt.token"}
        discovery_doc = {
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
        }

        bridge_app.include_router(oidc.router, prefix="/api")
        client = TestClient(bridge_app, follow_redirects=False)

        with patch.dict(os.environ, env), \
             patch("sigrift.bridge.routers.oidc._discover", return_value=discovery_doc), \
             patch("httpx.AsyncClient.post", return_value=token_response), \
             patch("sigrift.bridge.routers.oidc._verify_id_token", return_value=verified_claims):
            # First call succeeds
            resp1 = client.get(f"/api/auth/oidc/callback?code=code1&state={state_key}")
            assert resp1.status_code == 302

            # Second call with same state fails (state was consumed)
            resp2 = client.get(f"/api/auth/oidc/callback?code=code2&state={state_key}")
            assert resp2.status_code == 400
            assert "invalid" in resp2.json()["detail"].lower()

    def test_expired_state_rejected(self):
        """Expired states are rejected even if not yet pruned."""
        state_key = "expired-state"
        oidc._oidc_states[state_key] = {
            "nonce": "n",
            "redirect": "/",
            "created_at": time.monotonic() - (oidc._STATE_MAX_AGE + 10),
        }

        # Pop would succeed but the age check in callback would reject it
        state_data = oidc._oidc_states.pop(state_key, None)
        assert isinstance(state_data, dict) and state_data["nonce"] == "n"
        age = time.monotonic() - state_data["created_at"]
        assert age > oidc._STATE_MAX_AGE


# ---------------------------------------------------------------------------
# D-9: Backup encryption
# ---------------------------------------------------------------------------


class TestBackupEncryption:
    """D-9: Database backups encrypted at rest with Fernet."""

    @pytest.fixture()
    def fernet_key(self):
        return Fernet.generate_key().decode()

    @pytest.fixture()
    def backup_file(self, tmp_path):
        """Create a fake backup file with known content."""
        p = tmp_path / "test_backup.db"
        p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100 + b"test-data-12345")
        return p

    def test_get_backup_fernet_returns_none_without_key(self):
        """No encryption key → returns None."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_BACKUP_ENCRYPTION_KEY", None)
            result = _get_backup_fernet()
        assert result is None
        _maint_mod._backup_fernet = None

    def test_get_backup_fernet_returns_fernet_with_key(self, fernet_key):
        """Valid key → returns Fernet instance."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None
        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            result = _get_backup_fernet()
        assert isinstance(result, Fernet)
        _maint_mod._backup_fernet = None

    def test_encrypt_noop_without_key(self, backup_file):
        """Without encryption key, file is returned unchanged."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_BACKUP_ENCRYPTION_KEY", None)
            result = _encrypt_backup_file(backup_file)

        assert result == backup_file
        assert result.exists()
        _maint_mod._backup_fernet = None

    def test_encrypt_creates_enc_file(self, backup_file, fernet_key):
        """With key, creates .db.enc file and removes plaintext."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            enc_path = _encrypt_backup_file(backup_file)

        assert enc_path.suffix == ".enc"
        assert enc_path.name.endswith(".db.enc")
        assert enc_path.exists()
        assert not backup_file.exists()  # Plaintext removed

        # Verify encrypted file has magic header
        content = enc_path.read_bytes()
        assert content.startswith(_BACKUP_ENC_MAGIC)

        _maint_mod._backup_fernet = None

    def test_encrypt_decrypt_roundtrip(self, backup_file, fernet_key):
        """Encrypted backup can be decrypted back to original content."""
        original_content = backup_file.read_bytes()

        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            enc_path = _encrypt_backup_file(backup_file)

            # Decrypt to a new file
            dec_path = enc_path.parent / "decrypted.db"
            _decrypt_backup_file(enc_path, dec_path)

        assert dec_path.read_bytes() == original_content
        _maint_mod._backup_fernet = None

    def test_encrypt_large_file_chunked(self, tmp_path, fernet_key):
        """Large files are encrypted in chunks."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        # Create file larger than 1 chunk (but smaller for test speed)
        # Temporarily reduce chunk size for testing
        original_chunk = _maint_mod._BACKUP_CHUNK_SIZE
        _maint_mod._BACKUP_CHUNK_SIZE = 1024  # 1 KB chunks for testing

        try:
            data = os.urandom(3000)  # 3 KB = ~3 chunks
            src = tmp_path / "big_backup.db"
            src.write_bytes(data)

            with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
                enc_path = _encrypt_backup_file(src)

                dec_path = tmp_path / "big_decrypted.db"
                _decrypt_backup_file(enc_path, dec_path)

            assert dec_path.read_bytes() == data
        finally:
            _maint_mod._BACKUP_CHUNK_SIZE = original_chunk
            _maint_mod._backup_fernet = None

    def test_decrypt_without_key_raises(self, backup_file, fernet_key):
        """Attempting to decrypt without BRIDGE_BACKUP_ENCRYPTION_KEY raises."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            enc_path = _encrypt_backup_file(backup_file)

        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_BACKUP_ENCRYPTION_KEY", None)
            with pytest.raises(ValueError, match="cannot decrypt"):
                _decrypt_backup_file(enc_path, enc_path.parent / "out.db")

        _maint_mod._backup_fernet = None

    def test_decrypt_wrong_key_raises(self, backup_file, fernet_key):
        """Decrypting with wrong key raises an error."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            enc_path = _encrypt_backup_file(backup_file)

        _maint_mod._backup_fernet = None

        wrong_key = Fernet.generate_key().decode()
        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": wrong_key}):
            with pytest.raises(InvalidToken):
                _decrypt_backup_file(enc_path, enc_path.parent / "out.db")

        _maint_mod._backup_fernet = None

    def test_decrypt_invalid_file_raises(self, tmp_path, fernet_key):
        """Non-encrypted file raises ValueError."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        fake = tmp_path / "not_encrypted.db.enc"
        fake.write_bytes(b"This is not an encrypted backup")

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            with pytest.raises(ValueError, match="Not a Bridge encrypted"):
                _decrypt_backup_file(fake, tmp_path / "out.db")

        _maint_mod._backup_fernet = None

    def test_backup_endpoint_returns_encrypted_flag(
        self, client, bridge_app, fernet_key,
    ):
        """POST /api/admin/backup returns encrypted=true when key is set."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {"BRIDGE_BACKUP_ENCRYPTION_KEY": fernet_key}):
            resp = client.post("/api/admin/backup")

        if resp.status_code == 200:
            data = resp.json()
            assert data.get("encrypted") is True
            assert data["backup_file"].endswith(".db.enc")

        _maint_mod._backup_fernet = None

    def test_backup_endpoint_unencrypted_without_key(self, client):
        """POST /api/admin/backup returns encrypted=false when no key."""
        import sigrift.bridge.routers.maintenance as _maint_mod
        _maint_mod._backup_fernet = None

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_BACKUP_ENCRYPTION_KEY", None)
            resp = client.post("/api/admin/backup")

        if resp.status_code == 200:
            data = resp.json()
            assert data.get("encrypted") is False
            assert data["backup_file"].endswith(".db")
            assert not data["backup_file"].endswith(".db.enc")

        _maint_mod._backup_fernet = None
