"""Tests for remaining P0 and non-business P1 items.

Covers:
- SEC-H5: CSRF Double Submit Cookie protection
- SEC-H2: TOTP base64 warning surfaced in /health
- SEC-H6: DAR encryption status surfaced in /health
- SEC-M14: API key → node_id binding
- DS-R4: MAD (Median Absolute Deviation) scoring
- UX-R1: Cross-protocol threat ribbon endpoint
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from sigrift.bridge.anomaly.baseline import FrequencyBaseline, BaselineManager

# A real Fernet key: the health check validates the format, not just presence.
_VALID_MFA_KEY = Fernet.generate_key().decode()


# ---------------------------------------------------------------------------
# SEC-H5: CSRF Protection Tests
# ---------------------------------------------------------------------------


class TestCSRFProtection:
    """CSRF Double Submit Cookie enforcement."""

    def test_csrf_disabled_in_dev_mode(self, client):
        """In dev mode (no BRIDGE_ENV=production), CSRF is not enforced."""
        resp = client.post(
            "/api/auth/login",
            json={"username": "x", "password": "y"},
        )
        # Should get auth error, not CSRF error
        assert resp.status_code != 403 or "CSRF" not in resp.text

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_blocks_session_post_without_token(self, bridge_app):
        """With CSRF enabled, session POST without token gets 403."""
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/me",
                headers={"Authorization": "Bearer fake_token"},
            )
            assert resp.status_code == 403
            assert "CSRF" in resp.json()["detail"]

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_allows_api_key_auth(self, client):
        """API key auth bypasses CSRF check."""
        resp = client.get("/api/health")
        # X-API-Key auth — should not be CSRF 403
        assert resp.status_code == 200

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_allows_login_endpoint(self, bridge_app):
        """Login is CSRF-exempt."""
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/login",
                json={"username": "x", "password": "y"},
            )
            assert resp.status_code != 403 or "CSRF" not in resp.text

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_allows_logout_endpoint(self, bridge_app):
        """Logout is CSRF-exempt."""
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/logout",
                headers={"Authorization": "Bearer fake_token"},
            )
            if resp.status_code == 403:
                assert "CSRF" not in resp.json().get("detail", "")

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_passes_with_matching_tokens(self, bridge_app):
        """Valid CSRF cookie + header should pass the CSRF check."""
        with TestClient(bridge_app) as c:
            csrf_val = "test_csrf_token_value"
            c.cookies.set("csrf_token", csrf_val)
            resp = c.post(
                "/api/auth/me",
                headers={
                    "Authorization": "Bearer fake_token",
                    "X-CSRF-Token": csrf_val,
                },
            )
            # Should not be CSRF 403 — may be 401 (invalid session)
            if resp.status_code == 403:
                assert "CSRF" not in resp.json().get("detail", "")

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_rejects_mismatched_tokens(self, bridge_app):
        """Mismatched CSRF cookie and header should be rejected."""
        with TestClient(bridge_app) as c:
            c.cookies.set("csrf_token", "cookie_value")
            resp = c.post(
                "/api/auth/me",
                headers={
                    "Authorization": "Bearer fake_token",
                    "X-CSRF-Token": "different_value",
                },
            )
            assert resp.status_code == 403
            assert "CSRF" in resp.json()["detail"]

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_skips_get_requests(self, bridge_app):
        """GET requests don't need CSRF tokens."""
        with TestClient(bridge_app) as c:
            resp = c.get(
                "/api/auth/me",
                headers={"Authorization": "Bearer fake_token"},
            )
            if resp.status_code == 403:
                assert "CSRF" not in resp.json().get("detail", "")

    @patch.dict(os.environ, {"BRIDGE_CSRF": "enabled"})
    def test_csrf_skips_unauthenticated(self, bridge_app):
        """No session token → skip CSRF (let auth return 401)."""
        with TestClient(bridge_app) as c:
            resp = c.post("/api/auth/me")
            # Should be 401 (no auth), not 403 CSRF
            assert resp.status_code in (401, 405, 422)

    def test_login_returns_csrf_token(self, bridge_app, detection_store):
        """Login response should include csrf_token in body."""
        from sigrift.bridge.routers.auth import _login_attempts
        _login_attempts.clear()
        detection_store.create_user(
            username="csrfuser", password="CsrfPass123!", role="viewer",
        )
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/login",
                json={"username": "csrfuser", "password": "CsrfPass123!"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert isinstance(data["csrf_token"], str)
            assert len(data["csrf_token"]) == 64  # hex(32 bytes)

    def test_login_sets_csrf_cookie(self, bridge_app, detection_store):
        """Login should set csrf_token cookie."""
        from sigrift.bridge.routers.auth import _login_attempts
        _login_attempts.clear()
        detection_store.create_user(
            username="cookieuser", password="CookiePass1!", role="viewer",
        )
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/login",
                json={"username": "cookieuser", "password": "CookiePass1!"},
            )
            assert resp.status_code == 200
            assert isinstance(resp.cookies.get("csrf_token"), str) and len(resp.cookies["csrf_token"]) == 64

    def test_csrf_token_body_matches_cookie(self, bridge_app, detection_store):
        """csrf_token in response body should match the cookie value."""
        from sigrift.bridge.routers.auth import _login_attempts
        _login_attempts.clear()
        detection_store.create_user(
            username="csrfflow", password="CsrfFlow123!", role="viewer",
        )
        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/login",
                json={"username": "csrfflow", "password": "CsrfFlow123!"},
            )
            assert resp.status_code == 200
            body_csrf = resp.json()["csrf_token"]
            cookie_csrf = resp.cookies.get("csrf_token")
            assert body_csrf == cookie_csrf


# ---------------------------------------------------------------------------
# SEC-H2 + SEC-H6: Security Warnings in Health Endpoint
# ---------------------------------------------------------------------------


class TestHealthSecurityWarnings:
    """Health endpoint surfaces security configuration warnings."""

    def test_totp_warning_when_no_mfa_key(self, client):
        """Without BRIDGE_MFA_KEY, health shows TOTP warning."""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_MFA_KEY", None)
            resp = client.get("/api/health")
            assert resp.status_code == 200
            warnings = resp.json().get("security_warnings", [])
            assert any("TOTP" in w for w in warnings)

    def test_no_totp_warning_when_mfa_key_set(self, client):
        """With BRIDGE_MFA_KEY set, no TOTP warning."""
        with patch.dict(os.environ, {"BRIDGE_MFA_KEY": _VALID_MFA_KEY}):
            resp = client.get("/api/health")
            assert resp.status_code == 200
            warnings = resp.json().get("security_warnings", [])
            assert not any("TOTP" in w for w in warnings)

    def test_dar_warning_when_no_encryption_key(self, client):
        """Without any encryption key, health shows DAR warning."""
        from sigrift.bridge.storage.encryption import reset_cached_key
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            reset_cached_key()
            try:
                resp = client.get("/api/health")
                assert resp.status_code == 200
                warnings = resp.json().get("security_warnings", [])
                dar_warnings = [w for w in warnings if "encryption" in w.lower()]
                assert len(dar_warnings) >= 1
            finally:
                reset_cached_key()

    def test_no_dar_warning_when_key_set(self, client):
        """With BRIDGE_ENCRYPTION_KEY set, no DAR warning (operator acknowledged)."""
        from sigrift.bridge.storage.encryption import reset_cached_key
        with patch.dict(os.environ, {"BRIDGE_ENCRYPTION_KEY": "luks-configured"}):
            reset_cached_key()
            try:
                resp = client.get("/api/health")
                assert resp.status_code == 200
                warnings = resp.json().get("security_warnings", [])
                assert not any("encryption" in w.lower() for w in warnings)
            finally:
                reset_cached_key()

    def test_both_warnings_present(self, client):
        """Without either key, both warnings appear."""
        from sigrift.bridge.storage.encryption import reset_cached_key
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("BRIDGE_MFA_KEY", None)
            os.environ.pop("BRIDGE_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            reset_cached_key()
            try:
                resp = client.get("/api/health")
                warnings = resp.json().get("security_warnings", [])
                assert len(warnings) >= 2
            finally:
                reset_cached_key()

    def test_no_warnings_when_both_keys_set(self, client):
        """With both keys set, no warnings."""
        from sigrift.bridge.storage.encryption import reset_cached_key
        with patch.dict(os.environ, {
            "BRIDGE_MFA_KEY": _VALID_MFA_KEY,
            "BRIDGE_ENCRYPTION_KEY": "some_key",
        }):
            # Ensure no DB key file leak from earlier tests / CI env
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY", None)
            os.environ.pop("BRIDGE_DB_ENCRYPTION_KEY_FILE", None)
            reset_cached_key()
            try:
                resp = client.get("/api/health")
                warnings = resp.json().get("security_warnings", [])
                # Filter out disk-usage warnings that depend on the CI host
                # filesystem (not under test control)
                sec_warnings = [
                    w for w in warnings
                    if "Disk usage" not in w
                ]
                assert len(sec_warnings) == 0, f"Unexpected warnings: {sec_warnings}"
            finally:
                reset_cached_key()

    def test_security_warnings_field_exists(self, client):
        """BridgeHealthResponse always includes security_warnings."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        assert isinstance(resp.json()["security_warnings"], list)

    def test_whitespace_only_keys_still_warn(self, client):
        """Empty string (whitespace-only) keys should trigger warnings."""
        with patch.dict(os.environ, {
            "BRIDGE_MFA_KEY": "   ",
            "BRIDGE_ENCRYPTION_KEY": "  ",
        }):
            resp = client.get("/api/health")
            warnings = resp.json().get("security_warnings", [])
            assert len(warnings) >= 2


# ---------------------------------------------------------------------------
# DS-R4: MAD (Median Absolute Deviation) Scoring
# ---------------------------------------------------------------------------


class TestMADScoring:
    """FrequencyBaseline MAD-based anomaly scoring."""

    @pytest.fixture
    def baseline(self) -> FrequencyBaseline:
        """Baseline with 100 power samples."""
        fb = FrequencyBaseline()
        for i in range(100):
            power = -60.0 + (i % 10) - 5  # -65 to -56
            fb.update("wifi", 0.9, power, hour=i % 24, snr_db=20.0 + (i % 5))
        return fb

    def test_power_samples_collected(self, baseline):
        assert len(baseline.power_samples) == 100

    def test_snr_samples_collected(self, baseline):
        assert len(baseline.snr_samples) == 100

    def test_power_mad_score_normal_value(self, baseline):
        score = baseline.power_mad_score(-60.0)
        assert 0.0 <= score <= 0.5

    def test_power_mad_score_outlier(self, baseline):
        score = baseline.power_mad_score(-20.0)
        assert score > 0.5

    def test_power_mad_score_extreme_outlier(self, baseline):
        score = baseline.power_mad_score(0.0)
        assert score > 0.8

    def test_snr_mad_score_normal(self, baseline):
        score = baseline.snr_mad_score(22.0)
        assert 0.0 <= score <= 0.5

    def test_snr_mad_score_outlier(self, baseline):
        score = baseline.snr_mad_score(50.0)
        assert score > 0.5

    def test_mad_score_insufficient_samples(self):
        fb = FrequencyBaseline()
        for i in range(5):
            fb.update("wifi", 0.9, -60.0, hour=0)
        assert fb.power_mad_score(-60.0) == 0.0

    def test_mad_score_zero_mad(self):
        """All samples identical → MAD=0 → score=0."""
        fb = FrequencyBaseline()
        for _ in range(20):
            fb.update("wifi", 0.9, -60.0, hour=0)
        assert fb.power_mad_score(-60.0) == 0.0

    def test_mad_score_bounded(self, baseline):
        for power in [-100, -80, -60, -40, -20, 0, 20]:
            score = baseline.power_mad_score(float(power))
            assert 0.0 <= score <= 1.0

    def test_sample_buffer_capped(self):
        fb = FrequencyBaseline()
        for i in range(1000):
            fb.update("wifi", 0.9, float(-60 + i % 20), hour=i % 24)
        assert len(fb.power_samples) <= 500

    def test_median_static_method(self):
        assert FrequencyBaseline._median([1, 2, 3]) == 2.0
        assert FrequencyBaseline._median([1, 2, 3, 4]) == 2.5
        assert FrequencyBaseline._median([5]) == 5.0
        assert FrequencyBaseline._median([]) == 0.0

    def test_mad_static_method(self):
        assert FrequencyBaseline._mad([1, 2, 3, 4, 5]) == 1.0
        assert FrequencyBaseline._mad([]) == 0.0
        assert FrequencyBaseline._mad([5]) == 0.0

    def test_serialization_roundtrip(self, baseline):
        d = baseline.to_dict()
        assert isinstance(d["power_samples"], list) and len(d["power_samples"]) == 100
        assert isinstance(d["snr_samples"], list) and len(d["snr_samples"]) == 100
        restored = FrequencyBaseline.from_dict(d)
        assert len(restored.power_samples) == len(baseline.power_samples)
        assert len(restored.snr_samples) == len(baseline.snr_samples)

    def test_manager_update_collects_samples(self):
        mgr = BaselineManager()
        for i in range(50):
            mgr.update(433.92e6, "fm", 0.9, power_dbm=-70.0 + i % 10)
        bl = mgr.get_baseline(433.92e6)
        assert isinstance(bl, FrequencyBaseline)
        assert len(bl.power_samples) == 50

    def test_mad_monotonically_increases(self):
        fb = FrequencyBaseline()
        for i in range(100):
            fb.update("fm", 0.9, -60.0 + (i % 10) - 5, hour=0)
        scores = [fb.power_mad_score(float(p)) for p in [-60, -50, -40, -30]]
        for i in range(len(scores) - 1):
            assert scores[i] <= scores[i + 1]

    def test_mad_symmetric_around_median(self):
        fb = FrequencyBaseline()
        for i in range(100):
            fb.update("fm", 0.9, -60.0 + (i % 20) - 10, hour=0)
        score_above = fb.power_mad_score(-40.0)
        score_below = fb.power_mad_score(-80.0)
        assert abs(score_above - score_below) < 0.15

    def test_from_dict_without_samples_field(self):
        """Backward compat: old data without samples → empty lists."""
        old_data = {
            "alpha": 0.01,
            "class_counts": {"fm": 100},
            "class_ewma": {"fm": 0.5},
            "hourly_counts": {},
            "power_ewma": -60.0,
            "power_var": 25.0,
            "snr_ewma": 20.0,
            "snr_var": 4.0,
            "total_detections": 100,
        }
        fb = FrequencyBaseline.from_dict(old_data)
        assert fb.power_samples == []
        assert fb.snr_samples == []
        assert fb.power_mad_score(-60.0) == 0.0


# ---------------------------------------------------------------------------
# SEC-M14: API Key → Node ID Binding
# ---------------------------------------------------------------------------


class TestAPIKeyNodeBinding:
    """API key node_id binding enforcement on detection ingest."""

    def test_unbound_key_allows_any_node(self, client, persistence):
        """Key without node_id binding can submit for any node."""
        persistence.set_node("node-free", {"last_seen": "2026-01-01T00:00:00Z"})
        resp = client.post(
            "/api/detections/batch",
            json={
                "node_id": "node-free", "batch_id": "b1", "detections": [],
                "period_start": "2026-01-01T00:00:00Z",
                "period_end": "2026-01-01T00:01:00Z",
            },
        )
        assert resp.status_code != 403

    def test_bound_key_rejects_wrong_node(self, bridge_app, persistence):
        """Key bound to node-A cannot submit for node-B."""
        from sigrift.lib.security.credentials import (
            compute_lookup_hash,
            generate_api_key,
            hash_credential,
        )

        raw_key = generate_api_key()
        hashed, salt = hash_credential(raw_key)
        lookup_hash = compute_lookup_hash(raw_key)
        persistence.set_key("bound-key", hashed, salt, lookup_hash=lookup_hash)
        persistence.set_key_meta("bound-key", {
            "role": "sensor",
            "node_id": "node-alpha",
            "description": "test bound key",
        })
        persistence.set_node("node-alpha", {"last_seen": "2026-01-01T00:00:00Z"})
        persistence.set_node("node-beta", {"last_seen": "2026-01-01T00:00:00Z"})

        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/detections/batch",
                headers={"X-API-Key": raw_key},
                json={
                    "node_id": "node-beta", "batch_id": "b2", "detections": [],
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-01-01T00:01:00Z",
                },
            )
            assert resp.status_code == 403
            assert "bound to node" in resp.json()["detail"]

    def test_bound_key_allows_correct_node(self, bridge_app, persistence):
        """Key bound to node-A can submit for node-A."""
        from sigrift.lib.security.credentials import (
            compute_lookup_hash,
            generate_api_key,
            hash_credential,
        )

        raw_key = generate_api_key()
        hashed, salt = hash_credential(raw_key)
        lookup_hash = compute_lookup_hash(raw_key)
        persistence.set_key("correct-key", hashed, salt, lookup_hash=lookup_hash)
        persistence.set_key_meta("correct-key", {
            "role": "sensor",
            "node_id": "node-correct",
            "description": "test correct binding",
        })
        persistence.set_node("node-correct", {"last_seen": "2026-01-01T00:00:00Z"})

        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/detections/batch",
                headers={"X-API-Key": raw_key},
                json={
                    "node_id": "node-correct", "batch_id": "b3", "detections": [],
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-01-01T00:01:00Z",
                },
            )
            assert resp.status_code != 403

    def test_session_auth_skips_binding(
        self, bridge_app, detection_store, persistence,
    ):
        """Session-authenticated users skip node_id binding check."""
        # Clear rate limiter to avoid 429 from prior test login attempts
        from sigrift.bridge.routers.auth import _login_attempts
        _login_attempts.clear()

        detection_store.create_user(
            username="nodetest", password="NodeTest123!", role="analyst",
        )
        persistence.set_node("any-node", {"last_seen": "2026-01-01T00:00:00Z"})

        with TestClient(bridge_app) as c:
            resp = c.post(
                "/api/auth/login",
                json={"username": "nodetest", "password": "NodeTest123!"},
            )
            assert resp.status_code == 200, f"Login failed: {resp.json()}"
            token = resp.json()["session_token"]

            resp = c.post(
                "/api/detections/batch",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "node_id": "any-node", "batch_id": "b4", "detections": [],
                    "period_start": "2026-01-01T00:00:00Z",
                    "period_end": "2026-01-01T00:01:00Z",
                },
            )
            if resp.status_code == 403:
                assert "bound to node" not in resp.json().get("detail", "")


# ---------------------------------------------------------------------------
# UX-R1: Cross-Protocol Threat Ribbon
# ---------------------------------------------------------------------------


class TestThreatRibbon:
    """Cross-protocol threat ribbon endpoint."""

    def test_endpoint_exists(self, client):
        resp = client.get("/api/detections/threat-ribbon")
        assert resp.status_code == 200

    def test_returns_structure(self, client):
        data = client.get("/api/detections/threat-ribbon").json()
        assert isinstance(data["hours"], (int, float))
        assert isinstance(data["threshold"], (int, float))
        assert isinstance(data["total"], int) and data["total"] >= 0
        assert isinstance(data["events"], list)
        assert isinstance(data["by_protocol"], dict)

    def test_empty_when_no_anomalies(self, client):
        data = client.get("/api/detections/threat-ribbon").json()
        assert data["total"] == 0
        assert data["events"] == []

    def test_custom_params(self, client):
        resp = client.get(
            "/api/detections/threat-ribbon",
            params={"hours": 24, "threshold": 0.8, "limit": 10},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["hours"] == 24
        assert data["threshold"] == 0.8

    def test_param_validation(self, client):
        resp = client.get(
            "/api/detections/threat-ribbon",
            params={"hours": 0},
        )
        assert resp.status_code == 422

        resp = client.get(
            "/api/detections/threat-ribbon",
            params={"threshold": 1.5},
        )
        assert resp.status_code == 422

    def test_with_injected_anomalies(self, client, detection_store):
        """Should return events when high-anomaly detections exist."""
        from sigrift.bridge.utils import utcnow

        conn = detection_store._ctx.get_conn()
        conn.execute(
            """INSERT INTO detections
               (detection_id, node_id, timestamp, signal_class, confidence,
                freq_hz, power_dbm, anomaly_score, tenant_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            ("threat-1", "n1", utcnow().isoformat(), "unknown_burst",
             0.8, 433.92e6, -40.0, 0.95, detection_store._ctx.tenant_id),
        )
        conn.commit()

        resp = client.get(
            "/api/detections/threat-ribbon",
            params={"threshold": 0.5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert data["events"][0]["anomaly_score"] >= 0.5
