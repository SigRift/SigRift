"""Security-path tests for ``routers/mfa.py``.

The production bridge does not mount this router (the gateway serves MFA;
see test_round4_br1.py::test_bridge_serves_no_mfa_endpoints). To test the
module itself it is mounted here onto the real test app
(``create_test_app``: real middleware, real SQLite stores) and driven over
HTTP. Basic enrol / login / backup-code cases live in test_totp_mfa.py;
these tests add the multi-step flows and the refusals:

* login -> MFA challenge -> verify -> session use -> logout -> the old
  bearer and cookie are rejected; the challenge and the TOTP code cannot be
  replayed;
* a wrong code burns the challenge; an expired challenge is refused;
* a disabled account cannot complete a pending challenge (the challenge
  is consumed, no backup code is spent), nor can one whose record does not
  affirm ``enabled``; a non-ASCII code is a 401;
* enrolment cannot be redone or re-verified while enabled;
* disable refuses a replayed TOTP code; backup codes are normalised and
  single use; regenerating backup codes needs a fresh TOTP code and
  invalidates the old codes;
* tenant MFA enforcement: a confined session can enrol, then the next
  login needs the second factor;
* admin endpoints refuse non-admin callers without changing anything.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import mfa as mfa_mod
from sigrift.bridge.security.totp import compute_totp
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

PASSWORD = "Mfa-Test-Password-1!"


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture
def mfa_app(bridge_app: FastAPI) -> FastAPI:
    bridge_app.include_router(mfa_mod.router, prefix="/api")
    return bridge_app


@pytest.fixture
def anon(mfa_app: FastAPI) -> TestClient:
    return TestClient(mfa_app)


@pytest.fixture
def admin(mfa_app: FastAPI, master_key: str) -> TestClient:
    return TestClient(mfa_app, headers={"X-API-Key": master_key})


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _user(store: DetectionStore, username: str, role: str = "admin") -> int:
    store.create_user(username=username, password=PASSWORD, role=role)
    return store.users.get_user(username)["id"]


def _session(store: DetectionStore, user_id: int) -> str:
    return store.create_session(user_id=user_id)["session_token"]


def _enrolled(store: DetectionStore, username: str, role: str = "admin"):
    """A user with MFA enabled; returns (user_id, secret, backup_codes)."""
    from sigrift.bridge.security.totp import generate_backup_codes, generate_secret

    uid = _user(store, username, role)
    secret = generate_secret()
    codes = generate_backup_codes(count=3)
    store.users.set_totp_secret(uid, secret)
    store.users.store_backup_codes(uid, [hash_credential(c) for c in codes])
    store.users.enable_mfa(uid)
    return uid, secret, codes


def _next_code(secret: str) -> str:
    """A code from the next time step: valid (window 1) but not yet used."""
    now = int(time.time())
    code = compute_totp(secret, timestamp=now + 30)
    if code == compute_totp(secret, timestamp=now):  # pragma: no cover - 1e-6
        code = compute_totp(secret, timestamp=now - 30)
    return code


def _challenge(c: TestClient, username: str) -> str:
    resp = c.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["mfa_required"] is True
    assert body["session_token"] == ""
    return body["mfa_token"]


def _verify(c: TestClient, mfa_token: str, code: str):
    return c.post(
        "/api/auth/mfa/verify", json={"mfa_token": mfa_token, "totp_code": code}
    )


def _mfa_enabled(store: DetectionStore, username: str) -> bool:
    return bool(store.users.get_user(username)["mfa_enabled"])


# ---------------------------------------------------------------------------
# Two-step login
# ---------------------------------------------------------------------------


class TestTwoStepLoginFlow:
    def test_challenge_verify_use_logout_then_rejected(
        self, mfa_app, anon, detection_store
    ) -> None:
        uid, secret, _ = _enrolled(detection_store, "alice")
        token = _challenge(anon, "alice")
        code = compute_totp(secret)

        resp = _verify(anon, token, code)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        session = body["session_token"]
        assert body["user"]["username"] == "alice"
        assert body["password_change_required"] is False
        assert resp.cookies["csrf_token"] == body["csrf_token"]

        # The session works as a bearer and as the gateway's cookie.
        assert anon.get("/api/admin/users", headers=_bearer(session)).status_code == 200
        browser = TestClient(mfa_app, cookies={"session_token": session})
        me = browser.get("/api/auth/me")
        assert me.json()["mfa_enabled"] is True
        assert me.json()["backup_codes_remaining"] == 3

        # The challenge is single use, and so is the TOTP code.
        assert _verify(anon, token, code).status_code == 401
        second = _challenge(anon, "alice")
        replay = _verify(anon, second, code)
        assert replay.status_code == 401
        assert replay.json() == {
            "detail": "TOTP code already used. Wait for a new code."
        }

        assert browser.post("/api/auth/logout").status_code == 200
        assert browser.get("/api/auth/me").status_code == 401
        assert anon.get("/api/auth/me", headers=_bearer(session)).status_code == 401
        conn = detection_store.get_connection()
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ?", [uid]
            ).fetchone()[0]
            == 0
        )
        assert (
            detection_store.count_audit_log(action="user_login_mfa", target_id="alice")
            == 1
        )

    def test_wrong_code_burns_the_challenge(self, anon, detection_store) -> None:
        _, secret, _ = _enrolled(detection_store, "bob")
        token = _challenge(anon, "bob")
        wrong = "000000" if compute_totp(secret) != "000000" else "111111"
        resp = _verify(anon, token, wrong)
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid TOTP code or backup code"}
        # A guess costs the whole challenge: the right code needs a new login.
        resp = _verify(anon, token, compute_totp(secret))
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid or expired MFA token"}

    def test_expired_challenge_is_refused(self, anon, detection_store) -> None:
        uid, secret, _ = _enrolled(detection_store, "carol")
        token = _challenge(anon, "carol")
        past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        conn = detection_store.get_connection()
        conn.execute(
            "UPDATE mfa_tokens SET expires_at = ? WHERE user_id = ?", [past, uid]
        )
        conn.commit()
        resp = _verify(anon, token, compute_totp(secret))
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM mfa_tokens WHERE user_id = ?", [uid]
            ).fetchone()[0]
            == 0
        )

    def test_forged_challenge_is_refused(self, anon, detection_store) -> None:
        _, secret, _ = _enrolled(detection_store, "dan")
        resp = _verify(anon, "not-a-real-token", compute_totp(secret))
        assert resp.status_code == 401

    def test_session_token_is_not_a_challenge(self, anon, detection_store) -> None:
        uid, secret, _ = _enrolled(detection_store, "dee")
        resp = _verify(anon, _session(detection_store, uid), compute_totp(secret))
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid or expired MFA token"}

    def test_disabled_account_cannot_complete_a_pending_challenge(
        self, anon, admin, detection_store
    ) -> None:
        uid, secret, _ = _enrolled(detection_store, "erin")
        token = _challenge(anon, "erin")
        assert admin.delete("/api/admin/users/erin").status_code == 200
        resp = _verify(anon, token, compute_totp(secret))
        assert resp.status_code == 401
        conn = detection_store.get_connection()
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ?", [uid]
            ).fetchone()[0]
            == 0
        )

    def test_disabled_account_challenge_is_consumed_and_no_code_is_burnt(
        self, anon, admin, detection_store
    ) -> None:
        uid, _, codes = _enrolled(detection_store, "eve")
        token = _challenge(anon, "eve")
        assert admin.delete("/api/admin/users/eve").status_code == 200

        resp = _verify(anon, token, codes[0])
        assert resp.status_code == 401
        # Generic, like the gateway: the response does not say "disabled".
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        conn = detection_store.get_connection()
        for table in ("mfa_tokens", "sessions"):
            assert (
                conn.execute(
                    f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", [uid]
                ).fetchone()[0]
                == 0
            ), table
        assert detection_store.count_audit_log(action="user_login_mfa") == 0

        # Re-enabled: the refused challenge stays consumed, and the backup
        # code offered while disabled was not spent.
        assert (
            admin.put("/api/admin/users/eve", json={"enabled": True}).status_code == 200
        )
        assert _verify(anon, token, codes[0]).json() == {
            "detail": "Invalid or expired MFA token"
        }
        resp = _verify(anon, _challenge(anon, "eve"), codes[0])
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize(
        "record",
        [{}, {"enabled": None}, {"enabled": ""}],
        ids=["no-field", "null", "empty-text"],
    )
    def test_record_that_does_not_affirm_enabled_is_refused(
        self, anon, detection_store, monkeypatch, record
    ) -> None:
        # Fail closed: users.enabled is NOT NULL, but only a truthy value
        # lets the login finish; anything else reads as disabled, not as
        # "not 0, so enabled".
        uid, secret, _ = _enrolled(detection_store, "ike")
        token = _challenge(anon, "ike")
        real = detection_store.users.get_user_by_id

        def _without_enabled(user_id):
            user = real(user_id)
            del user["enabled"]
            return {**user, **record}

        monkeypatch.setattr(detection_store.users, "get_user_by_id", _without_enabled)
        resp = _verify(anon, token, compute_totp(secret))
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        conn = detection_store.get_connection()
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = ?", [uid]
            ).fetchone()[0]
            == 0
        )
        assert detection_store.count_audit_log(action="user_login_mfa") == 0

    @pytest.mark.parametrize(
        "code",
        ["١٢٣٤٥٦", "١" * 6, "１２３４５６", "12345é"],
        ids=["arabic-indic", "arabic-indic-ones", "fullwidth", "latin-1"],
    )
    def test_non_ascii_code_is_refused_not_500(
        self, mfa_app, detection_store, code
    ) -> None:
        _enrolled(detection_store, "nan")
        c = TestClient(mfa_app, raise_server_exceptions=False)
        resp = _verify(c, _challenge(c, "nan"), code)
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid TOTP code or backup code"}

    def test_backup_code_is_normalised_and_single_use(
        self, anon, detection_store
    ) -> None:
        _, _, codes = _enrolled(detection_store, "fay")
        resp = _verify(anon, _challenge(anon, "fay"), codes[0].upper())
        assert resp.status_code == 200, resp.text
        session = resp.json()["session_token"]
        me = anon.get("/api/auth/me", headers=_bearer(session)).json()
        assert me["backup_codes_remaining"] == 2
        assert _verify(anon, _challenge(anon, "fay"), codes[0]).status_code == 401

    def test_user_gone_after_the_challenge(
        self, anon, detection_store, monkeypatch
    ) -> None:
        _, secret, _ = _enrolled(detection_store, "gus")
        token = _challenge(anon, "gus")
        monkeypatch.setattr(detection_store.users, "get_user_by_id", lambda uid: None)
        resp = _verify(anon, token, compute_totp(secret))
        assert resp.status_code == 401
        assert resp.json() == {"detail": "User not found"}

    @pytest.mark.parametrize(
        "body",
        [
            {"mfa_token": "", "totp_code": "123456"},
            {"mfa_token": "t", "totp_code": ""},
            {"mfa_token": "t", "totp_code": "123456789"},
            {"totp_code": "123456"},
        ],
    )
    def test_malformed_verify_body_is_422(self, anon, body) -> None:
        assert anon.post("/api/auth/mfa/verify", json=body).status_code == 422

    def test_no_store_is_503(self, anon, mfa_app) -> None:
        mfa_app.state.detection_store = None
        resp = _verify(anon, "t", "123456")
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------


class TestEnrolment:
    def test_setup_verify_then_login_needs_the_second_factor(
        self, anon, detection_store
    ) -> None:
        uid = _user(detection_store, "hal")
        auth = _bearer(_session(detection_store, uid))

        setup = anon.post("/api/auth/mfa/setup", headers=auth)
        assert setup.status_code == 200, setup.text
        data = setup.json()
        secret = data["secret"]
        assert data["provisioning_uri"].startswith("otpauth://totp/")
        assert len(data["backup_codes"]) == 10
        assert not _mfa_enabled(detection_store, "hal")
        # Backup codes are stored hashed, never as given.
        conn = detection_store.get_connection()
        stored = [
            r[0]
            for r in conn.execute(
                "SELECT code_hash FROM mfa_backup_codes WHERE user_id = ?", [uid]
            )
        ]
        assert len(stored) == 10
        assert not set(stored) & set(data["backup_codes"])

        wrong = "000000" if compute_totp(secret) != "000000" else "111111"
        bad = anon.post(
            "/api/auth/mfa/verify-setup", headers=auth, json={"totp_code": wrong}
        )
        assert bad.status_code == 401
        assert not _mfa_enabled(detection_store, "hal")

        ok = anon.post(
            "/api/auth/mfa/verify-setup",
            headers=auth,
            json={"totp_code": compute_totp(secret)},
        )
        assert ok.status_code == 200, ok.text
        assert ok.json() == {"status": "mfa_enabled", "backup_codes_remaining": 10}
        assert _mfa_enabled(detection_store, "hal")

        # Enrolment cannot be redone (or re-verified) while MFA is on.
        assert anon.post("/api/auth/mfa/setup", headers=auth).status_code == 409
        again = anon.post(
            "/api/auth/mfa/verify-setup",
            headers=auth,
            json={"totp_code": compute_totp(secret)},
        )
        assert again.status_code == 409
        assert again.json() == {"detail": "MFA is already enabled"}

        # A password alone no longer yields a session.
        token = _challenge(anon, "hal")
        assert _verify(anon, token, _next_code(secret)).status_code == 200
        assert (
            detection_store.count_audit_log(action="mfa_enable", target_id="hal") == 1
        )

    def test_api_key_cannot_enrol(self, admin) -> None:
        for path, body in (
            ("/api/auth/mfa/setup", None),
            ("/api/auth/mfa/verify-setup", {"totp_code": "123456"}),
            ("/api/auth/mfa/disable", {"totp_code": "123456"}),
            ("/api/auth/mfa/regenerate-backup-codes", {"totp_code": "123456"}),
        ):
            resp = admin.post(path, json=body) if body else admin.post(path)
            assert resp.status_code == 403, path
            assert resp.json() == {
                "detail": "Session authentication required for MFA operations"
            }

    def test_no_credential_is_401(self, anon) -> None:
        assert anon.post("/api/auth/mfa/setup").status_code == 401

    def test_session_whose_user_is_gone_is_404(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "ida")
        auth = _bearer(_session(detection_store, uid))
        monkeypatch.setattr(detection_store.users, "get_user_full", lambda name: None)
        resp = anon.post("/api/auth/mfa/setup", headers=auth)
        assert resp.status_code == 404

    def test_tenant_policy_confines_until_enrolled(
        self, anon, admin, detection_store
    ) -> None:
        assert admin.put(
            "/api/admin/settings/mfa", json={"mfa_required": True}
        ).json() == {
            "tenant_id": "default",
            "mfa_required": True,
        }
        _user(detection_store, "jon", role="admin")
        login = anon.post(
            "/api/auth/login", json={"username": "jon", "password": PASSWORD}
        )
        body = login.json()
        assert body["mfa_setup_required"] is True
        auth = _bearer(body["session_token"])

        # The confined session can reach MFA setup and nothing else.
        assert anon.get("/api/admin/users", headers=auth).status_code == 403
        assert anon.get("/api/keys/", headers=auth).status_code == 403
        secret = anon.post("/api/auth/mfa/setup", headers=auth).json()["secret"]
        ok = anon.post(
            "/api/auth/mfa/verify-setup",
            headers=auth,
            json={"totp_code": compute_totp(secret)},
        )
        assert ok.status_code == 200
        # Enabling MFA does not widen the confined session...
        assert anon.get("/api/admin/users", headers=auth).status_code == 403
        # ...a fresh login with both factors gives a full one.
        token = _challenge(anon, "jon")
        full = _verify(anon, token, _next_code(secret))
        assert full.status_code == 200, full.text
        new_auth = _bearer(full.json()["session_token"])
        assert anon.get("/api/admin/users", headers=new_auth).status_code == 200


# ---------------------------------------------------------------------------
# Disable and backup-code regeneration
# ---------------------------------------------------------------------------


class TestDisable:
    def test_replayed_code_cannot_disable(self, anon, detection_store) -> None:
        _, secret, _ = _enrolled(detection_store, "kai")
        code = compute_totp(secret)
        session = _verify(anon, _challenge(anon, "kai"), code).json()["session_token"]
        resp = anon.post(
            "/api/auth/mfa/disable", headers=_bearer(session), json={"totp_code": code}
        )
        assert resp.status_code == 401
        assert resp.json() == {"detail": "TOTP code already used. Wait for a new code."}
        assert _mfa_enabled(detection_store, "kai")

    def test_wrong_code_and_no_backup_changes_nothing(self, anon, detection_store):
        uid, secret, codes = _enrolled(detection_store, "lin")
        auth = _bearer(_session(detection_store, uid))
        wrong = "000000" if _next_code(secret) != "000000" else "111111"
        for body in ({}, {"totp_code": wrong}, {"backup_code": "deadbeef"}):
            resp = anon.post("/api/auth/mfa/disable", headers=auth, json=body)
            assert resp.status_code == 401, body
        assert _mfa_enabled(detection_store, "lin")
        assert detection_store.users.get_backup_code_count(uid) == len(codes)

    def test_fresh_code_disables_and_wipes_backup_codes(
        self, anon, detection_store
    ) -> None:
        uid, secret, _ = _enrolled(detection_store, "mo")
        auth = _bearer(_session(detection_store, uid))
        resp = anon.post(
            "/api/auth/mfa/disable",
            headers=auth,
            json={"totp_code": _next_code(secret)},
        )
        assert resp.status_code == 200
        assert resp.json() == {"status": "mfa_disabled"}
        assert not _mfa_enabled(detection_store, "mo")
        assert detection_store.users.get_backup_code_count(uid) == 0
        assert detection_store.users.get_user_full("mo")["totp_secret"] is None
        # Password-only login again, and disable is now a 400.
        login = anon.post(
            "/api/auth/login", json={"username": "mo", "password": PASSWORD}
        )
        assert login.json()["mfa_required"] is False
        assert (
            anon.post("/api/auth/mfa/disable", headers=auth, json={}).status_code == 400
        )
        assert (
            detection_store.count_audit_log(action="mfa_disable", target_id="mo") == 1
        )

    def test_backup_code_disables_after_a_wrong_totp(self, anon, detection_store):
        uid, secret, codes = _enrolled(detection_store, "nia")
        auth = _bearer(_session(detection_store, uid))
        wrong = "000000" if _next_code(secret) != "000000" else "111111"
        resp = anon.post(
            "/api/auth/mfa/disable",
            headers=auth,
            json={"totp_code": wrong, "backup_code": f"  {codes[1].upper()} "},
        )
        assert resp.status_code == 200
        assert not _mfa_enabled(detection_store, "nia")


class TestRegenerateBackupCodes:
    def test_needs_mfa_enabled(self, anon, detection_store) -> None:
        uid = _user(detection_store, "oli")
        resp = anon.post(
            "/api/auth/mfa/regenerate-backup-codes",
            headers=_bearer(_session(detection_store, uid)),
            json={"totp_code": "123456"},
        )
        assert resp.status_code == 400
        assert resp.json() == {"detail": "MFA is not enabled"}

    def test_wrong_code_keeps_the_old_codes(self, anon, detection_store) -> None:
        uid, secret, codes = _enrolled(detection_store, "pia")
        wrong = "000000" if _next_code(secret) != "000000" else "111111"
        resp = anon.post(
            "/api/auth/mfa/regenerate-backup-codes",
            headers=_bearer(_session(detection_store, uid)),
            json={"totp_code": wrong},
        )
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid TOTP code"}
        assert detection_store.users.get_backup_code_count(uid) == len(codes)

    def test_regenerate_flow(self, anon, detection_store) -> None:
        uid, secret, old_codes = _enrolled(detection_store, "quy")
        auth = _bearer(_session(detection_store, uid))
        code = _next_code(secret)
        resp = anon.post(
            "/api/auth/mfa/regenerate-backup-codes",
            headers=auth,
            json={"totp_code": code},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "backup_codes_regenerated"
        assert body["backup_codes_remaining"] == 10
        new_codes = body["backup_codes"]
        assert len(set(new_codes)) == 10
        assert not set(new_codes) & set(old_codes)
        assert detection_store.users.get_backup_code_count(uid) == 10

        # The same TOTP code cannot regenerate again.
        replay = anon.post(
            "/api/auth/mfa/regenerate-backup-codes",
            headers=auth,
            json={"totp_code": code},
        )
        assert replay.status_code == 401
        assert replay.json() == {
            "detail": "TOTP code already used. Wait for a new code."
        }

        # Old codes are dead; a new one logs in.
        assert _verify(anon, _challenge(anon, "quy"), old_codes[0]).status_code == 401
        assert _verify(anon, _challenge(anon, "quy"), new_codes[0]).status_code == 200
        assert (
            detection_store.count_audit_log(
                action="mfa_regenerate_backup_codes", target_id="quy"
            )
            == 1
        )

    @pytest.mark.parametrize("code", ["12345", "1234567"])
    def test_code_must_be_six_digits(self, anon, detection_store, code) -> None:
        uid, _, _ = _enrolled(detection_store, "ray")
        resp = anon.post(
            "/api/auth/mfa/regenerate-backup-codes",
            headers=_bearer(_session(detection_store, uid)),
            json={"totp_code": code},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Admin MFA management
# ---------------------------------------------------------------------------


def _add_key(persistence: PersistenceManager, key_id: str, role: str) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


class TestAdminMfaManagement:
    @pytest.mark.parametrize("role", ["viewer", "analyst"])
    def test_non_admin_sessions_and_keys_are_refused(
        self, mfa_app, persistence, detection_store, role
    ) -> None:
        _enrolled(detection_store, "target", role="viewer")
        uid = _user(detection_store, f"{role}-user", role=role)
        callers = [
            TestClient(mfa_app, headers=_bearer(_session(detection_store, uid))),
            TestClient(
                mfa_app, headers={"X-API-Key": _add_key(persistence, role, role)}
            ),
        ]
        for c in callers:
            assert c.get("/api/admin/settings/mfa").status_code == 403
            assert (
                c.put(
                    "/api/admin/settings/mfa", json={"mfa_required": True}
                ).status_code
                == 403
            )
            assert c.post("/api/admin/users/target/disable-mfa").status_code == 403
        assert _mfa_enabled(detection_store, "target")
        assert detection_store.users.get_tenant_mfa_required("default") is False

    def test_admin_disable_lets_the_user_in_with_a_password(
        self, anon, detection_store, persistence, mfa_app
    ) -> None:
        _enrolled(detection_store, "sid", role="viewer")
        admin_id = _user(detection_store, "boss", role="admin")
        boss = TestClient(mfa_app, headers=_bearer(_session(detection_store, admin_id)))
        resp = boss.post("/api/admin/users/sid/disable-mfa")
        assert resp.json() == {"status": "mfa_disabled", "username": "sid"}
        assert boss.post("/api/admin/users/sid/disable-mfa").json() == {
            "status": "mfa_not_enabled",
            "username": "sid",
        }
        assert boss.post("/api/admin/users/nobody/disable-mfa").status_code == 404
        login = anon.post(
            "/api/auth/login", json={"username": "sid", "password": PASSWORD}
        )
        assert login.json()["mfa_required"] is False
        conn = detection_store.get_connection()
        operator = conn.execute(
            "SELECT operator FROM audit_log WHERE action = 'admin_disable_mfa'"
        ).fetchone()[0]
        assert operator == "boss"

    def test_policy_round_trip_is_audited(self, admin, detection_store) -> None:
        assert admin.get("/api/admin/settings/mfa").json()["mfa_required"] is False
        admin.put("/api/admin/settings/mfa", json={"mfa_required": True})
        assert admin.get("/api/admin/settings/mfa").json()["mfa_required"] is True
        assert (
            admin.put(
                "/api/admin/settings/mfa", json={"mfa_required": "maybe"}
            ).status_code
            == 422
        )
        assert detection_store.count_audit_log(action="tenant_mfa_policy_change") == 1
