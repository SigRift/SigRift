"""Tests for TOTP MFA (Multi-Factor Authentication) in The Bridge.

Covers:
  - TOTP generation and verification (RFC 6238 test vectors)
  - Time window tolerance
  - Provisioning URI format
  - MFA setup flow (generate -> verify -> enabled)
  - Login with MFA (two-step flow)
  - Backup code usage and single-use enforcement
  - Tenant MFA enforcement
  - Admin disable user MFA
  - MFA setup required when tenant enforces it
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.bridge.routers import mfa as _mfa_module
from sigrift.bridge.dependencies import (
    RateLimiter,
    WSConnectionLimiter,
    set_rate_limiter,
    set_ws_limiter,
)
from sigrift.bridge.anomaly.baseline import BaselineManager
from sigrift.bridge.anomaly.correlator import NodeCorrelator
from sigrift.bridge.anomaly.pcap_store import PcapStore
from sigrift.bridge.anomaly.scorer import AnomalyScorer
from sigrift.bridge.anomaly.wifi_scorer import WifiAnomalyScorer, WifiBaselineManager
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.notifications import NotificationManager
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.security import totp as _totp_module
from sigrift.bridge.security.totp import (
    compute_totp,
    generate_backup_codes,
    generate_secret,
    get_provisioning_uri,
    hash_backup_code,
    verify_totp,
)
from sigrift.bridge.state import AppState


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mfa_app(tmp_path: Path) -> FastAPI:
    """Build a Bridge app wired for MFA testing."""
    from sigrift.bridge.app import CombinedMiddleware
    from sigrift.bridge.routers import admin, auth, mfa

    app = FastAPI()
    app.add_middleware(CombinedMiddleware)

    detection_store = DetectionStore(db_path=tmp_path / "test.db")
    persistence = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    persistence.load_all()
    app_state = AppState()

    master_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(master_key)
    persistence.set_key("master", hash_hex, salt)

    app.state.persistence = persistence
    app.state.app_state = app_state
    app.state.detection_store = detection_store
    app.state.pcap_store = PcapStore(base_dir=tmp_path / "pcap")
    wifi_baseline_mgr = WifiBaselineManager()
    app.state.wifi_scorer = WifiAnomalyScorer(wifi_baseline_mgr)
    app.state.wifi_baseline_mgr = wifi_baseline_mgr
    rf_baseline_mgr = BaselineManager()
    app.state.rf_scorer = AnomalyScorer(rf_baseline_mgr)
    app.state.rf_baseline_mgr = rf_baseline_mgr
    app.state.correlator = NodeCorrelator()
    notifier = NotificationManager()
    notifier.load(persistence.get_webhooks())
    app.state.notifier = notifier

    limiter = RateLimiter(max_requests=1000, window_seconds=60.0)
    set_rate_limiter(limiter)
    ws_limiter = WSConnectionLimiter(max_concurrent=10, max_per_minute=30)
    set_ws_limiter(ws_limiter)
    app.state.ws_limiter = ws_limiter

    app.include_router(auth.router, prefix="/api", tags=["auth"])
    app.include_router(mfa.router, prefix="/api", tags=["mfa"])
    app.include_router(admin.router, prefix="/api/admin", tags=["admin"])

    # Store master_key on app for test access
    app.state._test_master_key = master_key

    return app


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    """Reset the per-IP login rate limiter between tests."""
    from sigrift.bridge.routers.auth import _login_attempts
    _login_attempts.clear()
    yield
    _login_attempts.clear()


@pytest.fixture(autouse=True)
def _reset_totp_replay_cache():
    """Clear the TOTP replay cache between tests to avoid cross-test code reuse rejections."""
    _mfa_module._used_totp_codes.clear()
    yield
    _mfa_module._used_totp_codes.clear()


@pytest.fixture
def mfa_client(mfa_app: FastAPI) -> TestClient:
    """TestClient with master key auth."""
    return TestClient(
        mfa_app,
        headers={"X-API-Key": mfa_app.state._test_master_key},
    )


def _create_test_user(
    client: TestClient,
    username: str = "testuser",
    password: str = "TestPass123!",
    role: str = "admin",
) -> dict[str, Any]:
    """Create a test user via the admin endpoint."""
    resp = client.post("/api/admin/users", json={
        "username": username,
        "password": password,
        "role": role,
    })
    assert resp.status_code in (200, 201, 409), resp.text
    return resp.json()


def _login(
    client: TestClient,
    username: str = "testuser",
    password: str = "TestPass123!",
) -> dict[str, Any]:
    """Login and return the response json."""
    resp = client.post("/api/auth/login", json={
        "username": username,
        "password": password,
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


def _session_headers(session_token: str) -> dict[str, str]:
    """Build auth headers for a session token."""
    return {"Authorization": f"Bearer {session_token}"}


# ===========================================================================
# Unit tests: TOTP core (RFC 6238)
# ===========================================================================


class TestTOTPCore:
    """Test TOTP generation and verification using stdlib implementation."""

    def test_generate_secret_length(self):
        """Secret should be base32, typically 32 chars for 20 bytes."""
        secret = generate_secret()
        assert len(secret) >= 20
        # Should be valid base32 chars
        for c in secret:
            assert c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    def test_generate_secret_uniqueness(self):
        """Each call should produce a different secret."""
        secrets = {generate_secret() for _ in range(50)}
        assert len(secrets) == 50

    def test_compute_totp_deterministic(self):
        """Same secret + timestamp produces same code."""
        secret = generate_secret()
        ts = 1234567890
        code1 = compute_totp(secret, ts)
        code2 = compute_totp(secret, ts)
        assert code1 == code2
        assert len(code1) == 6
        assert code1.isdigit()

    def test_compute_totp_different_timestamps(self):
        """Different time steps produce different codes (usually)."""
        secret = generate_secret()
        codes = {compute_totp(secret, ts) for ts in range(0, 3000, 30)}
        # Should have many distinct codes (not all the same)
        assert len(codes) > 50

    def test_compute_totp_6_digit_zero_padded(self):
        """TOTP output should always be exactly 6 digits."""
        secret = generate_secret()
        for ts in range(0, 10000, 30):
            code = compute_totp(secret, ts)
            assert len(code) == 6
            assert code.isdigit()

    def test_verify_totp_current_step(self):
        """Code for current time step should verify."""
        secret = generate_secret()
        ts = int(time.time())
        code = compute_totp(secret, ts)
        assert verify_totp(secret, code, timestamp=ts) is True

    def test_verify_totp_window_tolerance(self):
        """Codes within +/-1 time step should verify."""
        secret = generate_secret()
        ts = 1000000000
        period = 30

        # Code from T-1
        code_prev = compute_totp(secret, ts - period)
        assert verify_totp(secret, code_prev, window=1, timestamp=ts) is True

        # Code from T+1
        code_next = compute_totp(secret, ts + period)
        assert verify_totp(secret, code_next, window=1, timestamp=ts) is True

    def test_verify_totp_outside_window(self):
        """Code from 2 steps away should fail with window=1."""
        secret = generate_secret()
        ts = 1000000000
        period = 30

        code_far = compute_totp(secret, ts - 2 * period)
        assert not verify_totp(secret, code_far, window=1, timestamp=ts)

    def test_verify_totp_wrong_code(self):
        """Random wrong codes should fail verification."""
        secret = generate_secret()
        ts = int(time.time())
        assert not verify_totp(secret, "000000", timestamp=ts)
        assert not verify_totp(secret, "999999", timestamp=ts)

    def test_verify_totp_wrong_secret(self):
        """Code from one secret should not verify with a different secret."""
        secret1 = generate_secret()
        secret2 = generate_secret()
        ts = int(time.time())
        code = compute_totp(secret1, ts)
        assert not verify_totp(secret2, code, timestamp=ts)

    @pytest.mark.parametrize(
        "code",
        ["١٢٣٤٥٦", "١" * 6, "１２３４５６", "12345é", "", "12345 ", "+12345"],
    )
    def test_verify_totp_refuses_anything_but_ascii_digits(self, code):
        """Non-ASCII input is a plain False, never a TypeError from
        hmac.compare_digest (str.isdigit() accepts Arabic-Indic digits)."""
        secret = generate_secret()
        assert verify_totp(secret, code, timestamp=1_000_000_000) is False

    @pytest.mark.parametrize(
        "code", ["", "12345a", "abcdef", "12345 ", "+12345", "1234.5", "١٢٣٤٥٦"]
    )
    def test_verify_totp_refuses_non_digits_before_computing_any_code(
        self, monkeypatch, code
    ):
        """The guard alone refuses: no code is computed or compared, so an
        input that is not all ASCII digits cannot match even a compute_totp
        that returned that very string."""
        computed = []

        def _echo(*args, **kwargs):
            computed.append(args)
            return code

        monkeypatch.setattr(_totp_module, "compute_totp", _echo)
        assert verify_totp(generate_secret(), code, timestamp=1_000_000_000) is False
        assert computed == []
        # Control: the stand-in is live, so an ASCII-digit code reaches it.
        monkeypatch.setattr(_totp_module, "compute_totp", lambda *a, **k: "123456")
        assert verify_totp(generate_secret(), "123456", timestamp=1) is True

    def test_verify_totp_unicode_digits_never_match_the_ascii_code(self):
        secret = generate_secret()
        ts = 1_000_000_000
        code = compute_totp(secret, ts)
        arabic = code.translate(str.maketrans("0123456789", "٠١٢٣٤٥٦٧٨٩"))
        assert verify_totp(secret, code, timestamp=ts) is True
        assert verify_totp(secret, arabic, timestamp=ts) is False

    def test_rfc6238_sha1_test_vector(self):
        """Verify against RFC 6238 Appendix B SHA1 test vectors.

        The RFC uses the ASCII string '12345678901234567890' as the secret.
        In base32 that is 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'.
        """
        # ASCII secret: 12345678901234567890
        import base64
        raw_secret = b"12345678901234567890"
        b32_secret = base64.b32encode(raw_secret).decode("ascii").rstrip("=")

        # RFC 6238 Appendix B test vectors (SHA1, 8 digits)
        test_vectors = [
            (59,          "94287082"),
            (1111111109,  "07081804"),
            (1111111111,  "14050471"),
            (1234567890,  "89005924"),
            (2000000000,  "69279037"),
            (20000000000, "65353130"),
        ]

        for ts, expected in test_vectors:
            code = compute_totp(b32_secret, timestamp=ts, digits=8)
            assert code == expected, f"At time={ts}: expected {expected}, got {code}"


class TestProvisioningURI:
    """Test otpauth:// URI generation."""

    def test_basic_uri(self):
        """URI should be well-formed otpauth://totp/ URI."""
        secret = "JBSWY3DPEHPK3PXP"
        uri = get_provisioning_uri(secret, "alice")
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=SigRift" in uri
        assert "SigRift%3Aalice" in uri or "SigRift:alice" in uri

    def test_uri_custom_issuer(self):
        secret = "ABCDEFGH"
        uri = get_provisioning_uri(secret, "bob", issuer="MyApp")
        assert "issuer=MyApp" in uri
        assert "MyApp" in uri

    def test_uri_contains_algorithm(self):
        secret = "ABCDEFGH"
        uri = get_provisioning_uri(secret, "test")
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri


class TestBackupCodes:
    """Test backup code generation and hashing."""

    def test_generate_backup_codes_count(self):
        codes = generate_backup_codes(count=10)
        assert len(codes) == 10

    def test_generate_backup_codes_length(self):
        codes = generate_backup_codes(count=5, length=8)
        for c in codes:
            assert len(c) == 8
            # Should be valid hex
            int(c, 16)

    def test_generate_backup_codes_unique(self):
        codes = generate_backup_codes(count=100)
        assert len(set(codes)) == 100

    def test_hash_backup_code_deterministic(self):
        h1 = hash_backup_code("abcd1234")
        h2 = hash_backup_code("abcd1234")
        assert h1 == h2

    def test_hash_backup_code_case_insensitive(self):
        h1 = hash_backup_code("ABCD1234")
        h2 = hash_backup_code("abcd1234")
        assert h1 == h2

    def test_hash_backup_code_strips_whitespace(self):
        h1 = hash_backup_code("  abcd1234  ")
        h2 = hash_backup_code("abcd1234")
        assert h1 == h2


# ===========================================================================
# Integration tests: MFA setup flow
# ===========================================================================


class TestMFASetupFlow:
    """Test the MFA setup flow: generate secret -> verify code -> enabled."""

    def test_mfa_setup_returns_secret_and_uri(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        resp = mfa_client.post("/api/auth/mfa/setup", headers=headers)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert isinstance(data["secret"], str) and len(data["secret"]) >= 20
        assert isinstance(data["provisioning_uri"], str)
        assert isinstance(data["backup_codes"], list)
        assert len(data["backup_codes"]) == 10
        assert data["provisioning_uri"].startswith("otpauth://totp/")

    def test_mfa_verify_setup_enables_mfa(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        # Setup
        setup_resp = mfa_client.post("/api/auth/mfa/setup", headers=headers)
        setup_data = setup_resp.json()
        secret = setup_data["secret"]

        # Compute a valid TOTP code
        code = compute_totp(secret)

        # Verify setup
        resp = mfa_client.post(
            "/api/auth/mfa/verify-setup",
            headers=headers,
            json={"totp_code": code},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["status"] == "mfa_enabled"

    def test_mfa_verify_setup_wrong_code_fails(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        # Setup
        mfa_client.post("/api/auth/mfa/setup", headers=headers)

        # Bad code
        resp = mfa_client.post(
            "/api/auth/mfa/verify-setup",
            headers=headers,
            json={"totp_code": "000000"},
        )
        assert resp.status_code == 401

    def test_mfa_setup_twice_fails_when_enabled(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        # Setup and enable
        setup_data = mfa_client.post("/api/auth/mfa/setup", headers=headers).json()
        code = compute_totp(setup_data["secret"])
        mfa_client.post("/api/auth/mfa/verify-setup", headers=headers, json={"totp_code": code})

        # Try setup again
        resp = mfa_client.post("/api/auth/mfa/setup", headers=headers)
        assert resp.status_code == 409


# ===========================================================================
# Integration tests: Two-step MFA login
# ===========================================================================


class TestMFALoginFlow:
    """Test the two-step login flow when MFA is enabled."""

    def _enable_mfa(self, client: TestClient, session_token: str) -> str:
        """Setup + verify MFA, return the secret."""
        headers = _session_headers(session_token)
        setup_data = client.post("/api/auth/mfa/setup", headers=headers).json()
        secret = setup_data["secret"]
        code = compute_totp(secret)
        resp = client.post(
            "/api/auth/mfa/verify-setup",
            headers=headers,
            json={"totp_code": code},
        )
        assert resp.status_code == 200, resp.text
        return secret

    def test_login_returns_mfa_required(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        self._enable_mfa(mfa_client, login_data["session_token"])

        # Now login again — should require MFA
        resp = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["mfa_required"] is True
        assert isinstance(data["mfa_token"], str)
        assert data["mfa_token"] != ""
        assert data["session_token"] == ""

    def test_mfa_verify_completes_login(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        secret = self._enable_mfa(mfa_client, login_data["session_token"])

        # Step 1: password login
        login2 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()
        assert login2["mfa_required"] is True

        # Step 2: TOTP verification
        code = compute_totp(secret)
        resp = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": code,
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert isinstance(data["session_token"], str) and len(data["session_token"]) >= 32
        assert data["user"]["username"] == "testuser"

    def test_mfa_verify_wrong_code_fails(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        self._enable_mfa(mfa_client, login_data["session_token"])

        login2 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()

        resp = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": "000000",
        })
        assert resp.status_code == 401

    def test_mfa_token_is_single_use(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        secret = self._enable_mfa(mfa_client, login_data["session_token"])

        login2 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()

        code = compute_totp(secret)
        # First use succeeds
        resp1 = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": code,
        })
        assert resp1.status_code == 200

        # Second use fails (token consumed)
        resp2 = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": code,
        })
        assert resp2.status_code == 401

    def test_invalid_mfa_token(self, mfa_client: TestClient):
        resp = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": "totally-fake-token",
            "totp_code": "123456",
        })
        assert resp.status_code == 401


# ===========================================================================
# Integration tests: Backup codes
# ===========================================================================


class TestBackupCodeFlow:
    """Test backup code usage during MFA login and disable."""

    def _setup_mfa(self, client: TestClient) -> tuple[str, str, list[str]]:
        """Create user, login, enable MFA, return (session_token, secret, backup_codes)."""
        _create_test_user(client)
        login_data = _login(client)
        headers = _session_headers(login_data["session_token"])

        setup_data = client.post("/api/auth/mfa/setup", headers=headers).json()
        secret = setup_data["secret"]
        backup_codes = setup_data["backup_codes"]

        code = compute_totp(secret)
        client.post(
            "/api/auth/mfa/verify-setup",
            headers=headers,
            json={"totp_code": code},
        )

        return login_data["session_token"], secret, backup_codes

    def test_backup_code_works_for_mfa_verify(self, mfa_client: TestClient):
        """A backup code can be used instead of TOTP for login."""
        _token, secret, backup_codes = self._setup_mfa(mfa_client)

        # Login step 1
        login2 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()
        assert login2["mfa_required"] is True

        # Login step 2 with backup code
        resp = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": backup_codes[0],  # Use first backup code
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert isinstance(data["session_token"], str)
        assert data["session_token"] != ""

    def test_backup_code_single_use(self, mfa_client: TestClient):
        """A backup code can only be used once."""
        _token, secret, backup_codes = self._setup_mfa(mfa_client)

        # First login with backup code
        login2 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()
        resp = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login2["mfa_token"],
            "totp_code": backup_codes[0],
        })
        assert resp.status_code == 200

        # Second login with same backup code
        login3 = mfa_client.post("/api/auth/login", json={
            "username": "testuser",
            "password": "TestPass123!",
        }).json()
        resp2 = mfa_client.post("/api/auth/mfa/verify", json={
            "mfa_token": login3["mfa_token"],
            "totp_code": backup_codes[0],
        })
        assert resp2.status_code == 401

    def test_different_backup_codes_each_work_once(self, mfa_client: TestClient):
        """Multiple different backup codes each work once."""
        _token, secret, backup_codes = self._setup_mfa(mfa_client)

        for bc in backup_codes[:3]:
            login_resp = mfa_client.post("/api/auth/login", json={
                "username": "testuser",
                "password": "TestPass123!",
            }).json()
            resp = mfa_client.post("/api/auth/mfa/verify", json={
                "mfa_token": login_resp["mfa_token"],
                "totp_code": bc,
            })
            assert resp.status_code == 200, f"Backup code {bc} failed"

    def test_backup_code_for_disable_mfa(self, mfa_client: TestClient):
        """A backup code can be used to disable MFA."""
        session_token, secret, backup_codes = self._setup_mfa(mfa_client)
        headers = _session_headers(session_token)

        resp = mfa_client.post(
            "/api/auth/mfa/disable",
            headers=headers,
            json={"backup_code": backup_codes[5]},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "mfa_disabled"


# ===========================================================================
# Integration tests: MFA disable
# ===========================================================================


class TestMFADisable:
    """Test disabling MFA."""

    def test_disable_with_totp_code(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        setup_data = mfa_client.post("/api/auth/mfa/setup", headers=headers).json()
        secret = setup_data["secret"]
        code = compute_totp(secret)
        mfa_client.post("/api/auth/mfa/verify-setup", headers=headers, json={"totp_code": code})

        # Disable with current TOTP
        disable_code = compute_totp(secret)
        resp = mfa_client.post(
            "/api/auth/mfa/disable",
            headers=headers,
            json={"totp_code": disable_code},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "mfa_disabled"

    def test_disable_when_not_enabled(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        resp = mfa_client.post(
            "/api/auth/mfa/disable",
            headers=headers,
            json={"totp_code": "123456"},
        )
        assert resp.status_code == 400

    def test_disable_wrong_code_fails(self, mfa_client: TestClient):
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        setup_data = mfa_client.post("/api/auth/mfa/setup", headers=headers).json()
        code = compute_totp(setup_data["secret"])
        mfa_client.post("/api/auth/mfa/verify-setup", headers=headers, json={"totp_code": code})

        resp = mfa_client.post(
            "/api/auth/mfa/disable",
            headers=headers,
            json={"totp_code": "000000"},
        )
        assert resp.status_code == 401


# ===========================================================================
# Integration tests: Tenant MFA enforcement
# ===========================================================================


class TestTenantMFAEnforcement:
    """Test tenant-level MFA enforcement."""

    def test_set_tenant_mfa_required(self, mfa_client: TestClient):
        resp = mfa_client.put("/api/admin/settings/mfa", json={"mfa_required": True})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["mfa_required"] is True

    def test_get_tenant_mfa_setting(self, mfa_client: TestClient):
        mfa_client.put("/api/admin/settings/mfa", json={"mfa_required": True})
        resp = mfa_client.get("/api/admin/settings/mfa")
        assert resp.status_code == 200
        assert resp.json()["mfa_required"] is True

    def test_login_returns_mfa_setup_required_when_tenant_enforces(self, mfa_client: TestClient):
        """When tenant requires MFA but user hasn't set it up, login should flag it."""
        _create_test_user(mfa_client, username="noMfaUser")

        # Enable tenant MFA requirement
        mfa_client.put("/api/admin/settings/mfa", json={"mfa_required": True})

        # Login as user without MFA
        resp = mfa_client.post("/api/auth/login", json={
            "username": "noMfaUser",
            "password": "TestPass123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        # User should get a session but with mfa_setup_required flag
        assert isinstance(data["session_token"], str)
        assert data["session_token"] != ""
        assert data["mfa_setup_required"] is True
        assert data["mfa_required"] is False  # Not MFA challenge, just needs setup

    def test_login_no_flag_when_tenant_does_not_require(self, mfa_client: TestClient):
        """Without tenant enforcement, no setup flag."""
        _create_test_user(mfa_client, username="regularUser")

        resp = mfa_client.post("/api/auth/login", json={
            "username": "regularUser",
            "password": "TestPass123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["mfa_setup_required"] is False

    def test_toggle_tenant_mfa_off(self, mfa_client: TestClient):
        mfa_client.put("/api/admin/settings/mfa", json={"mfa_required": True})
        mfa_client.put("/api/admin/settings/mfa", json={"mfa_required": False})
        resp = mfa_client.get("/api/admin/settings/mfa")
        assert resp.json()["mfa_required"] is False


# ===========================================================================
# Integration tests: Admin MFA management
# ===========================================================================


class TestAdminMFAManagement:
    """Test admin operations on user MFA."""

    def test_admin_disable_user_mfa(self, mfa_client: TestClient):
        _create_test_user(mfa_client, username="mfaUser")
        login_data = mfa_client.post("/api/auth/login", json={
            "username": "mfaUser",
            "password": "TestPass123!",
        }).json()
        headers = _session_headers(login_data["session_token"])

        # Enable MFA
        setup_data = mfa_client.post("/api/auth/mfa/setup", headers=headers).json()
        code = compute_totp(setup_data["secret"])
        mfa_client.post("/api/auth/mfa/verify-setup", headers=headers, json={"totp_code": code})

        # Admin disables it (using API key auth)
        resp = mfa_client.post("/api/admin/users/mfaUser/disable-mfa")
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "mfa_disabled"

        # Now login should succeed without MFA
        login2 = mfa_client.post("/api/auth/login", json={
            "username": "mfaUser",
            "password": "TestPass123!",
        }).json()
        assert login2["mfa_required"] is False
        assert isinstance(login2["session_token"], str)
        assert login2["session_token"] != ""

    def test_admin_disable_mfa_user_not_found(self, mfa_client: TestClient):
        resp = mfa_client.post("/api/admin/users/nonexistent/disable-mfa")
        assert resp.status_code == 404

    def test_admin_disable_mfa_not_enabled(self, mfa_client: TestClient):
        _create_test_user(mfa_client, username="plainUser")
        resp = mfa_client.post("/api/admin/users/plainUser/disable-mfa")
        assert resp.status_code == 200
        assert resp.json()["status"] == "mfa_not_enabled"

    def test_non_admin_cannot_set_tenant_mfa(self, mfa_client: TestClient):
        """Viewer/analyst role cannot change tenant MFA policy."""
        _create_test_user(mfa_client, username="viewerUser", role="viewer")
        login_data = mfa_client.post("/api/auth/login", json={
            "username": "viewerUser",
            "password": "TestPass123!",
        }).json()
        headers = _session_headers(login_data["session_token"])

        resp = mfa_client.put(
            "/api/admin/settings/mfa",
            headers=headers,
            json={"mfa_required": True},
        )
        assert resp.status_code == 403


# ===========================================================================
# Edge cases
# ===========================================================================


class TestMFAEdgeCases:
    """Test edge cases and error handling."""

    def test_mfa_setup_requires_session(self, mfa_client: TestClient):
        """MFA setup with API key (no session) should fail."""
        resp = mfa_client.post("/api/auth/mfa/setup")
        assert resp.status_code == 403

    def test_verify_setup_without_setup_first(self, mfa_client: TestClient):
        """Verify-setup without calling setup first should fail."""
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        resp = mfa_client.post(
            "/api/auth/mfa/verify-setup",
            headers=headers,
            json={"totp_code": "123456"},
        )
        assert resp.status_code == 400

    def test_login_after_mfa_disabled_is_normal(self, mfa_client: TestClient):
        """After disabling MFA, login should be single-step again."""
        _create_test_user(mfa_client)
        login_data = _login(mfa_client)
        headers = _session_headers(login_data["session_token"])

        # Enable MFA
        setup_data = mfa_client.post("/api/auth/mfa/setup", headers=headers).json()
        secret = setup_data["secret"]
        code = compute_totp(secret)
        mfa_client.post("/api/auth/mfa/verify-setup", headers=headers, json={"totp_code": code})

        # Disable MFA
        disable_code = compute_totp(secret)
        mfa_client.post("/api/auth/mfa/disable", headers=headers, json={"totp_code": disable_code})

        # Login should be single-step
        login2 = _login(mfa_client)
        assert login2["mfa_required"] is False
        assert isinstance(login2["session_token"], str)
        assert login2["session_token"] != ""
