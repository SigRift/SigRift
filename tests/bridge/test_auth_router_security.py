"""Security-path tests for ``routers/auth.py`` through the real bridge app.

Drives ``create_test_app`` (real middleware, real SQLite stores) over HTTP.
Fault injection replaces a single store method where a failure cannot be
produced otherwise. Covered elsewhere and not repeated here: password
change / admin reset revoking every session (test_user_session_revocation.py),
the per-IP login limit and lockout (test_user_auth.py,
test_login_lockout_concurrency.py), forced password change
(test_round3_bridge_auth.py), foreign-tenant logout (test_tenant_boundaries.py).

Flows here:

* login -> session cookie use -> logout -> the cookie and the row are gone;
* the CSRF double-submit cookie's attributes (SameSite, Secure on https);
* the MFA password step issues no session and no usable credential;
* failed logins are audited, and a failing audit does not turn 401 into 500;
* a login fails closed (503, no session left) when the session scope
  cannot be determined;
* restricted and API-key callers cannot change a password, and a reissued
  session stays restricted if the forced-change flag cannot be cleared;
* every admin user endpoint refuses viewer / analyst / sensor callers and
  a foreign tenant's admin, without changing anything;
* disable -> re-enable keeps the old sessions dead.
"""

from __future__ import annotations

import hashlib

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import auth as auth_mod
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

PASSWORD = "Correct-Horse-42!"


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture
def anon(bridge_app: FastAPI) -> TestClient:
    return TestClient(bridge_app)


def _user(store: DetectionStore, username: str, role: str = "viewer", **kw) -> int:
    store.create_user(username=username, password=PASSWORD, role=role, **kw)
    return store.users.get_user(username)["id"]


def _login(c: TestClient, username: str, password: str = PASSWORD):
    return c.post("/api/auth/login", json={"username": username, "password": password})


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _session_rows(store: DetectionStore, user_id: int) -> int:
    conn = store.get_connection()
    return conn.execute(
        "SELECT COUNT(*) FROM sessions WHERE user_id = ?", [user_id]
    ).fetchone()[0]


def _add_key(persistence: PersistenceManager, key_id: str, role: str) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


# ---------------------------------------------------------------------------
# Login -> use -> logout
# ---------------------------------------------------------------------------


class TestLoginLogoutFlow:
    def test_cookie_session_is_dead_after_logout(
        self, bridge_app, detection_store
    ) -> None:
        uid = _user(detection_store, "alice", role="admin")
        login = _login(TestClient(bridge_app), "alice")
        assert login.status_code == 200, login.text
        token = login.json()["session_token"]
        assert login.json()["user"] == {
            "username": "alice",
            "role": "admin",
            "display_name": "",
        }

        # The gateway forwards the session as the session_token cookie.
        browser = TestClient(bridge_app, cookies={"session_token": token})
        me = browser.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["auth_type"] == "session"
        assert me.json()["username"] == "alice"
        assert "X-Session-Expires-In" in me.headers
        assert browser.get("/api/admin/users").status_code == 200

        out = browser.post("/api/auth/logout")
        assert out.status_code == 200
        assert out.json() == {"status": "logged_out"}
        assert _session_rows(detection_store, uid) == 0

        # The old cookie (and the same token as a bearer) are now rejected.
        assert browser.get("/api/auth/me").status_code == 401
        assert browser.get("/api/admin/users").status_code == 401
        assert (
            TestClient(bridge_app)
            .get("/api/auth/me", headers=_bearer(token))
            .status_code
            == 401
        )
        assert browser.post("/api/auth/logout").status_code == 401

        assert (
            detection_store.count_audit_log(action="user_login", target_id="alice") == 1
        )
        assert (
            detection_store.count_audit_log(action="user_logout", target_id="alice")
            == 1
        )

    def test_logout_ends_only_its_own_session(self, anon, detection_store) -> None:
        _user(detection_store, "bob")
        first = _login(anon, "bob").json()["session_token"]
        second = _login(anon, "bob").json()["session_token"]
        assert anon.post("/api/auth/logout", headers=_bearer(first)).status_code == 200
        assert anon.get("/api/auth/me", headers=_bearer(first)).status_code == 401
        assert anon.get("/api/auth/me", headers=_bearer(second)).status_code == 200

    def test_x_session_token_header_logs_out(self, anon, detection_store) -> None:
        _user(detection_store, "carol")
        token = _login(anon, "carol").json()["session_token"]
        hdr = {"X-Session-Token": token}
        assert anon.post("/api/auth/logout", headers=hdr).status_code == 200
        assert anon.get("/api/auth/me", headers=hdr).status_code == 401

    @pytest.mark.parametrize(
        ("column", "value"),
        [
            pytest.param("last_active", "garbage", id="unreadable-activity"),
            pytest.param("last_active", "", id="empty-activity"),
            pytest.param("expires_at", "damaged", id="unreadable-expiry"),
            pytest.param("last_active", "2000-01-01T00:00:00+00:00", id="idle"),
            pytest.param("expires_at", "2000-01-01T00:00:00+00:00", id="expired"),
        ],
    )
    def test_logout_ends_a_session_past_its_time_limits(
        self, anon, detection_store, column, value
    ) -> None:
        # The gateway's logout deletes the session row the token names and
        # answers 200 with an audit entry, whatever its times. The bridge's
        # lookup for the audit name deleted such a row first, so its logout
        # answered 401 and audited nothing.
        uid = _user(detection_store, "erin")
        token = _login(anon, "erin").json()["session_token"]
        conn = detection_store.get_connection()
        conn.execute(
            f"UPDATE sessions SET {column} = ? WHERE user_id = ?", [value, uid]
        )
        conn.commit()

        out = anon.post("/api/auth/logout", headers=_bearer(token))
        assert out.status_code == 200, out.text
        assert out.json() == {"status": "logged_out"}
        assert _session_rows(detection_store, uid) == 0
        audited = {"action": "user_logout", "target_id": "unknown"}
        assert detection_store.count_audit_log(**audited) == 1
        assert anon.post("/api/auth/logout", headers=_bearer(token)).status_code == 401
        assert detection_store.count_audit_log(action="user_logout") == 1

    def test_api_key_cannot_log_out(self, client) -> None:
        resp = client.post("/api/auth/logout")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "No session token provided"}


class TestLoginCsrfAndLogoutCookies:
    """Stage 0 of the cookie-only plan, on the standalone bridge.

    The gateway answers 415 to a login body not declared JSON (login
    CSRF). The bridge refuses such a body too, with FastAPI's 422; that is
    pinned here so a FastAPI upgrade cannot quietly start parsing a
    cross-site form's ``text/plain`` body. (The bridge serves no MFA
    verify route: ``test_round4_br1.py`` pins that.)
    """

    # What a form field named ``{"username":"zed","password":"…","x":"``
    # with the value ``"}`` posts as text/plain: still a JSON object.
    FORM_SHAPED = '{"username":"zed","password":"' + PASSWORD + '","x":"="}'

    @pytest.mark.parametrize(
        "content_type",
        [
            None,
            "text/plain",
            "text/plain;charset=UTF-8",
            "text/plain;charset=application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
        ],
    )
    def test_login_refuses_a_body_not_declared_json(
        self, bridge_app, detection_store, content_type
    ) -> None:
        uid = _user(detection_store, "zed")
        c = TestClient(bridge_app)
        headers = {"Origin": "https://evil.example"}
        if content_type is not None:
            headers["Content-Type"] = content_type
        resp = c.post("/api/auth/login", content=self.FORM_SHAPED, headers=headers)
        assert resp.status_code == 422, resp.text
        assert "set-cookie" not in resp.headers
        assert _session_rows(detection_store, uid) == 0

        ok = c.post(
            "/api/auth/login",
            content=self.FORM_SHAPED,
            headers={"Content-Type": "application/json"},
        )
        assert ok.status_code == 200, ok.text

    @staticmethod
    def _expires_csrf_cookie(resp) -> bool:
        cookies = resp.headers.get_list("set-cookie")
        return any(
            c.startswith("csrf_token=")
            and ("max-age=0" in c.lower() or "expires=thu, 01 jan 1970" in c.lower())
            for c in cookies
        )

    def test_logout_expires_the_csrf_cookie_whenever_signed_out(
        self, bridge_app, detection_store
    ) -> None:
        # The gateway's logout expires its cookies on every outcome that
        # leaves the caller signed out; the bridge's set none, not even on
        # success, so a standalone browser kept a CSRF cookie that told
        # its pages it was still signed in.
        _user(detection_store, "yan")
        token = _login(TestClient(bridge_app), "yan").json()["session_token"]
        anon = TestClient(bridge_app)
        # The browser's stale CSRF cookie rides along on a 401.
        stale = {"Cookie": "csrf_token=c"}
        for case, headers, status in [
            ("valid", _bearer(token), 200),
            ("already ended", {**_bearer(token), **stale}, 401),
            ("unknown", {**_bearer("not-a-session"), **stale}, 401),
            ("no token", stale, 401),
            ("stale session cookie", {"Cookie": "session_token=gone"}, 401),
        ]:
            resp = anon.post("/api/auth/logout", headers=headers)
            assert resp.status_code == status, case
            assert self._expires_csrf_cookie(resp), (case, resp.headers)
        resp = anon.post("/api/auth/logout", headers=stale)
        assert resp.json() == {"detail": "No session token provided"}

    @pytest.mark.parametrize(
        "headers",
        [
            # A cross-site form post: the SameSite cookies stay behind.
            {
                "Origin": "https://evil.example",
                "Sec-Fetch-Site": "cross-site",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            {"Origin": "null", "Sec-Fetch-Site": "cross-site"},
            _bearer("not-a-session"),
            {"X-Session-Token": "not-a-session"},
            {"Cookie": "theme=dark; session_token_hint=1; Csrf_Token=x; csrf_token"},
        ],
    )
    def test_logout_sets_no_cookie_for_a_request_that_carried_none(
        self, bridge_app, headers
    ) -> None:
        # Forced sign-out: logout is CSRF-exempt, and a cross-site form
        # post carries no SameSite cookie, so it gets the "no token" 401.
        # Browsers apply that top-level navigation's Set-Cookie whatever
        # its SameSite, so expiring the CSRF cookie there let any page
        # sign a visitor's standalone dashboard out. A 401 now expires it
        # only when the request carried the session or CSRF cookie.
        resp = TestClient(bridge_app).post("/api/auth/logout", headers=headers)
        assert resp.status_code == 401, resp.text
        assert "set-cookie" not in resp.headers, resp.headers

    @pytest.mark.parametrize(
        "cookie",
        [
            "csrf_token=c",
            "session_token=gone",
            "theme=dark;  csrf_token =c",
            "name=café; csrf_token=c",
        ],
    )
    def test_logout_expires_a_carried_cookie_however_it_was_sent(
        self, bridge_app, cookie
    ) -> None:
        resp = TestClient(bridge_app).post(
            "/api/auth/logout", headers={"Cookie": cookie.encode()}
        )
        assert resp.status_code == 401, resp.text
        assert self._expires_csrf_cookie(resp), resp.headers

    def test_expired_csrf_cookie_keeps_its_attributes_on_https(
        self, bridge_app, detection_store
    ) -> None:
        c = TestClient(bridge_app, base_url="https://testserver")
        resp = c.post("/api/auth/logout", headers={"Cookie": "csrf_token=c"})
        assert resp.status_code == 401
        (cookie,) = [
            v
            for v in resp.headers.get_list("set-cookie")
            if v.startswith("csrf_token=")
        ]
        lowered = cookie.lower()
        assert "path=/" in lowered and "samesite=strict" in lowered
        assert "secure" in lowered


class TestCsrfCookie:
    def test_cookie_attributes_on_http(self, anon, detection_store) -> None:
        _user(detection_store, "dave")
        resp = _login(anon, "dave")
        cookie = resp.headers["set-cookie"]
        assert cookie.startswith("csrf_token=")
        assert "samesite=strict" in cookie.lower()
        assert "path=/" in cookie.lower()
        assert "httponly" not in cookie.lower()  # the SPA must read it
        assert "secure" not in cookie.lower()
        assert resp.json()["csrf_token"] == resp.cookies["csrf_token"]
        assert len(resp.json()["csrf_token"]) == 64

    def test_cookie_is_secure_on_https(self, bridge_app, detection_store) -> None:
        _user(detection_store, "erin")
        c = TestClient(bridge_app, base_url="https://testserver")
        resp = _login(c, "erin")
        assert resp.status_code == 200
        assert "secure" in resp.headers["set-cookie"].lower()

    def test_each_login_gets_a_fresh_csrf_token(self, anon, detection_store) -> None:
        _user(detection_store, "fay")
        a = _login(anon, "fay").json()["csrf_token"]
        b = _login(anon, "fay").json()["csrf_token"]
        assert a != b


# ---------------------------------------------------------------------------
# MFA password step, failed logins
# ---------------------------------------------------------------------------


class TestMfaPasswordStep:
    def test_password_step_issues_no_session(self, anon, detection_store) -> None:
        uid = _user(detection_store, "mfa-user", role="admin")
        detection_store.users.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
        detection_store.users.enable_mfa(uid)

        resp = _login(anon, "mfa-user")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mfa_required"] is True
        assert body["session_token"] == ""
        assert body["mfa_token"]
        assert "set-cookie" not in resp.headers  # no CSRF cookie yet
        assert _session_rows(detection_store, uid) == 0
        # The challenge token is not a credential for anything else.
        assert (
            anon.get("/api/auth/me", headers=_bearer(body["mfa_token"])).status_code
            == 401
        )
        assert (
            anon.get(
                "/api/auth/me", headers={"X-API-Key": body["mfa_token"]}
            ).status_code
            == 401
        )
        assert (
            detection_store.count_audit_log(
                action="user_login_mfa_pending", target_id="mfa-user"
            )
            == 1
        )

    def test_wrong_password_issues_no_challenge(self, anon, detection_store) -> None:
        uid = _user(detection_store, "mfa-user2")
        detection_store.users.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
        detection_store.users.enable_mfa(uid)
        resp = _login(anon, "mfa-user2", "wrong-password")
        assert resp.status_code == 401
        conn = detection_store.get_connection()
        assert (
            conn.execute(
                "SELECT COUNT(*) FROM mfa_tokens WHERE user_id = ?", [uid]
            ).fetchone()[0]
            == 0
        )


class TestFailedLogin:
    def test_failure_is_audited_without_a_session(self, anon, detection_store):
        uid = _user(detection_store, "gina")
        resp = _login(anon, "gina", "nope-nope")
        assert resp.status_code == 401
        assert resp.json() == {"detail": "Invalid username or password"}
        assert "set-cookie" not in resp.headers
        assert _session_rows(detection_store, uid) == 0
        assert (
            detection_store.count_audit_log(action="auth_failure", target_id="gina")
            == 1
        )

    def test_unknown_user_and_wrong_password_look_the_same(self, anon, detection_store):
        _user(detection_store, "hank")
        a = _login(anon, "hank", "wrong-password")
        b = _login(anon, "nobody-here", "wrong-password")
        assert (a.status_code, a.json()) == (b.status_code, b.json())

    def test_audit_failure_still_answers_401(
        self, bridge_app, detection_store, monkeypatch
    ) -> None:
        _user(detection_store, "ivan")

        def _broken(**kwargs):
            raise RuntimeError("audit db locked")

        monkeypatch.setattr(detection_store, "log_audit", _broken)
        resp = _login(
            TestClient(bridge_app, raise_server_exceptions=False), "ivan", "x"
        )
        assert resp.status_code == 401

    def test_account_vanishing_after_the_password_check_is_401(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "jade")
        verified = detection_store.verify_password_credential("jade", PASSWORD)
        assert verified is not None
        monkeypatch.setattr(detection_store.users, "get_user_full", lambda name: None)
        monkeypatch.setattr(
            detection_store, "verify_password_credential", lambda u, p: verified
        )
        resp = _login(anon, "jade")
        assert resp.status_code == 401
        assert _session_rows(detection_store, uid) == 0

    def test_lockout_helper(self, detection_store) -> None:
        sec = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX - 1):
            assert sec.reserve_account_attempt("kim")
        auth_mod._check_account_lockout("kim", detection_store)  # below the limit
        assert sec.reserve_account_attempt("kim")
        with pytest.raises(HTTPException) as exc:
            auth_mod._check_account_lockout("kim", detection_store)
        assert exc.value.status_code == 429
        assert exc.value.headers == {"Retry-After": "1800"}


class TestLoginFailsClosed:
    def test_no_store_is_503(self, anon, bridge_app) -> None:
        bridge_app.state.detection_store = None
        resp = anon.post("/api/auth/login", json={"username": "a", "password": "b"})
        assert resp.status_code == 503

    def test_policy_read_error_refuses_the_login(
        self, bridge_app, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "lee", role="admin")

        def _broken(tenant):
            raise RuntimeError("database disk image is malformed")

        monkeypatch.setattr(detection_store.users, "get_tenant_mfa_required", _broken)
        c = TestClient(bridge_app, raise_server_exceptions=False)
        resp = _login(c, "lee")
        assert resp.status_code == 503
        assert resp.json() == {"detail": "Login temporarily unavailable"}
        assert _session_rows(detection_store, uid) == 0

    def test_missing_policy_table_means_no_policy(
        self, anon, detection_store, monkeypatch
    ) -> None:
        _user(detection_store, "max")

        def _no_table(tenant):
            raise RuntimeError("no such table: tenant_settings")

        monkeypatch.setattr(detection_store.users, "get_tenant_mfa_required", _no_table)
        resp = _login(anon, "max")
        assert resp.status_code == 200
        token = resp.json()["session_token"]
        assert resp.json()["mfa_setup_required"] is False
        assert anon.get("/api/keys/", headers=_bearer(token)).status_code == 200

    def test_user_gone_when_choosing_the_scope_is_503(
        self, bridge_app, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "ned")
        monkeypatch.setattr(detection_store.users, "get_user", lambda name: None)
        c = TestClient(bridge_app, raise_server_exceptions=False)
        resp = _login(c, "ned")
        assert resp.status_code == 503
        assert _session_rows(detection_store, uid) == 0

    def test_tenant_mfa_policy_confines_the_new_session(
        self, anon, client, detection_store
    ) -> None:
        detection_store.users.set_tenant_mfa_required("default", True)
        _user(detection_store, "olga", role="admin")
        resp = _login(anon, "olga")
        body = resp.json()
        assert body["mfa_setup_required"] is True
        assert body["password_change_required"] is False
        auth = _bearer(body["session_token"])
        refused = anon.get("/api/admin/users", headers=auth)
        assert refused.status_code == 403
        assert refused.json() == {
            "detail": "MFA setup required before accessing other endpoints"
        }
        # ...including changing the password before MFA is set up.
        resp = anon.post(
            "/api/auth/change-password",
            headers=auth,
            json={"current_password": PASSWORD, "new_password": "Another-pass-1!"},
        )
        assert resp.status_code == 403
        assert detection_store.verify_password("olga", PASSWORD)


# ---------------------------------------------------------------------------
# /auth/me
# ---------------------------------------------------------------------------


class TestWhoAmI:
    def test_mfa_session_reports_remaining_backup_codes(
        self, anon, detection_store
    ) -> None:
        uid = _user(detection_store, "pat")
        detection_store.users.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
        detection_store.users.enable_mfa(uid)
        detection_store.users.store_backup_codes(
            uid, [hash_credential("aaaa1111"), hash_credential("bbbb2222")]
        )
        token = detection_store.create_session(user_id=uid)["session_token"]
        me = anon.get("/api/auth/me", headers=_bearer(token)).json()
        assert me["mfa_enabled"] is True
        assert me["backup_codes_remaining"] == 2
        assert "password_hash" not in me
        assert "totp_secret" not in me
        assert "salt" not in me

    def test_backup_count_failure_reports_zero(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "quin")
        detection_store.users.enable_mfa(uid)
        token = detection_store.create_session(user_id=uid)["session_token"]

        def _broken(user_id):
            raise RuntimeError("locked")

        monkeypatch.setattr(detection_store.users, "get_backup_code_count", _broken)
        me = anon.get("/api/auth/me", headers=_bearer(token))
        assert me.status_code == 200
        assert me.json()["backup_codes_remaining"] == 0

    def test_api_key_principal(self, bridge_app, persistence) -> None:
        raw = _add_key(persistence, "sensor-1", "sensor")
        me = TestClient(bridge_app, headers={"X-API-Key": raw}).get("/api/auth/me")
        assert me.json() == {
            "auth_type": "api_key",
            "key_id": "sensor-1",
            "role": "sensor",
        }

    def test_no_credential_is_401(self, anon) -> None:
        assert anon.get("/api/auth/me").status_code == 401

    def test_session_whose_user_record_vanished_reveals_no_profile(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid = _user(detection_store, "zed", role="viewer")
        token = detection_store.create_session(user_id=uid)["session_token"]
        monkeypatch.setattr(detection_store, "get_user", lambda name: None)
        me = anon.get("/api/auth/me", headers=_bearer(token))
        assert me.status_code == 200
        assert me.json() == {
            "auth_type": "api_key",
            "key_id": "user:zed",
            "role": "viewer",
        }


# ---------------------------------------------------------------------------
# Change password
# ---------------------------------------------------------------------------


class TestChangePassword:
    def test_api_key_caller_is_refused(self, client) -> None:
        resp = client.post(
            "/api/auth/change-password",
            json={"current_password": "x", "new_password": "long-enough-1"},
        )
        assert resp.status_code == 403
        assert resp.json() == {
            "detail": "Password change requires session authentication"
        }

    def test_wrong_current_password_changes_nothing(self, anon, detection_store):
        uid = _user(detection_store, "rita")
        token = _login(anon, "rita").json()["session_token"]
        resp = anon.post(
            "/api/auth/change-password",
            headers=_bearer(token),
            json={"current_password": "not-it", "new_password": "New-pass-123!"},
        )
        assert resp.status_code == 401
        assert detection_store.verify_password("rita", PASSWORD)
        assert anon.get("/api/auth/me", headers=_bearer(token)).status_code == 200
        assert _session_rows(detection_store, uid) == 1

    @pytest.mark.parametrize("new", ["short", "x" * 129])
    def test_weak_or_oversized_new_password_is_422(
        self, anon, detection_store, new
    ) -> None:
        _user(detection_store, "sam")
        token = _login(anon, "sam").json()["session_token"]
        resp = anon.post(
            "/api/auth/change-password",
            headers=_bearer(token),
            json={"current_password": PASSWORD, "new_password": new},
        )
        assert resp.status_code == 422
        assert detection_store.verify_password("sam", PASSWORD)

    def test_reissued_session_stays_confined_if_flag_cannot_clear(
        self, anon, detection_store, monkeypatch
    ) -> None:
        _user(detection_store, "boot", role="admin", must_change_password=True)
        old = _login(anon, "boot").json()
        assert old["password_change_required"] is True

        def _broken(username):
            raise RuntimeError("write failed")

        monkeypatch.setattr(
            detection_store.users, "clear_must_change_password", _broken
        )
        resp = anon.post(
            "/api/auth/change-password",
            headers=_bearer(old["session_token"]),
            json={"current_password": PASSWORD, "new_password": "Brand-new-pass-9!"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["password_change_required"] is True
        new_auth = _bearer(body["session_token"])
        refused = anon.get("/api/admin/users", headers=new_auth)
        assert refused.status_code == 403
        assert refused.json() == {"detail": "password change required"}
        assert anon.get("/api/auth/me", headers=new_auth).status_code == 200
        # The old session is gone, the password did change.
        assert (
            anon.get("/api/auth/me", headers=_bearer(old["session_token"])).status_code
            == 401
        )
        assert detection_store.verify_password("boot", "Brand-new-pass-9!")

    def test_user_gone_after_change_requires_fresh_sign_in(
        self, anon, detection_store, monkeypatch
    ) -> None:
        _user(detection_store, "tess")
        token = _login(anon, "tess").json()["session_token"]
        real_change_password = detection_store.change_password_with_audit

        def _change_password_then_vanish(*args, **kwargs):
            changed = real_change_password(*args, **kwargs)
            # The account disappears right after the password commit, so
            # the replacement session cannot be issued.
            monkeypatch.setattr(detection_store.users, "get_user", lambda name: None)
            return changed

        monkeypatch.setattr(
            detection_store, "change_password_with_audit", _change_password_then_vanish
        )
        resp = anon.post(
            "/api/auth/change-password",
            headers=_bearer(token),
            json={"current_password": PASSWORD, "new_password": "Changed-pass-77!"},
        )
        assert resp.status_code == 200
        assert resp.json() == {
            "status": "password_changed",
            "reauthentication_required": True,
        }


# ---------------------------------------------------------------------------
# Admin user management: who may call it
# ---------------------------------------------------------------------------

_ADMIN_CALLS = [
    ("post", "/api/admin/users", {"username": "evil", "password": "Evil-pass-123"}),
    ("get", "/api/admin/users", None),
    ("put", "/api/admin/users/victim", {"role": "admin"}),
    ("delete", "/api/admin/users/victim", None),
    (
        "post",
        "/api/admin/users/victim/reset-password",
        {"new_password": "Hijacked-pass-1"},
    ),
]


class TestAdminUserEndpointsRefuseNonAdmins:
    @pytest.fixture
    def victim(self, detection_store) -> int:
        return _user(detection_store, "victim", role="viewer")

    def _assert_untouched(self, store: DetectionStore, victim_id: int) -> None:
        user = store.users.get_user("victim")
        assert user["role"] == "viewer"
        assert bool(user["enabled"]) is True
        assert store.verify_password("victim", PASSWORD)
        assert store.users.get_user("evil") is None
        assert store.count_audit_log(target_id="victim") == 0

    @pytest.mark.parametrize("method, path, body", _ADMIN_CALLS)
    @pytest.mark.parametrize("role", ["sensor", "viewer", "analyst"])
    def test_api_keys_below_admin(
        self, bridge_app, persistence, detection_store, victim, role, method, path, body
    ) -> None:
        raw = _add_key(persistence, f"{role}-key", role)
        c = TestClient(bridge_app, headers={"X-API-Key": raw})
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(c, method)(path, **kwargs)
        assert resp.status_code == 403, resp.text
        assert resp.json() == {"detail": "Admin role required"}
        self._assert_untouched(detection_store, victim)

    @pytest.mark.parametrize("method, path, body", _ADMIN_CALLS)
    def test_analyst_session(
        self, anon, detection_store, victim, method, path, body
    ) -> None:
        uid = _user(detection_store, "ana", role="analyst")
        token = detection_store.create_session(user_id=uid)["session_token"]
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(anon, method)(path, headers=_bearer(token), **kwargs)
        assert resp.status_code == 403
        self._assert_untouched(detection_store, victim)

    def test_analyst_cannot_promote_themselves(self, anon, detection_store) -> None:
        uid = _user(detection_store, "climber", role="analyst")
        token = detection_store.create_session(user_id=uid)["session_token"]
        resp = anon.put(
            "/api/admin/users/climber", headers=_bearer(token), json={"role": "admin"}
        )
        assert resp.status_code == 403
        assert detection_store.users.get_user("climber")["role"] == "analyst"

    @pytest.mark.parametrize("method, path, body", _ADMIN_CALLS)
    def test_foreign_tenant_admin(
        self, bridge_app, detection_store, victim, method, path, body
    ) -> None:
        other = DetectionStore(detection_store.db_path, tenant_id="other")
        try:
            other.create_user("intruder", PASSWORD, role="admin")
            token = other.create_session(other.get_user("intruder")["id"])[
                "session_token"
            ]
        finally:
            other.close()
        c = TestClient(bridge_app, headers=_bearer(token))
        kwargs = {"json": body} if body is not None else {}
        resp = getattr(c, method)(path, **kwargs)
        assert resp.status_code == 403
        self._assert_untouched(detection_store, victim)

    def test_keymaster_role_cannot_be_assigned_to_users(self, client) -> None:
        resp = client.post(
            "/api/admin/users",
            json={"username": "km", "password": "Long-enough-1", "role": "keymaster"},
        )
        assert resp.status_code == 422
        resp = client.put("/api/admin/users/anyone", json={"role": "keymaster"})
        assert resp.status_code == 422

    @pytest.mark.parametrize("username", ["../x", "a b", "<script>", ""])
    def test_malformed_usernames_are_422(self, client, username) -> None:
        resp = client.post(
            "/api/admin/users",
            json={"username": username, "password": "Long-enough-1"},
        )
        assert resp.status_code == 422


class TestAdminUserLifecycle:
    def test_create_disable_reenable_flow(self, client, anon, detection_store) -> None:
        created = client.post(
            "/api/admin/users",
            json={
                "username": "uma",
                "password": PASSWORD,
                "role": "analyst",
                "email": "uma@example.test",
            },
        )
        assert created.status_code == 200, created.text
        assert "password_hash" not in created.json()
        assert "salt" not in created.json()
        assert (
            client.post(
                "/api/admin/users", json={"username": "uma", "password": PASSWORD}
            ).status_code
            == 409
        )

        token = _login(anon, "uma").json()["session_token"]
        assert anon.get("/api/auth/me", headers=_bearer(token)).status_code == 200

        assert client.delete("/api/admin/users/uma").json() == {
            "status": "disabled",
            "username": "uma",
        }
        assert anon.get("/api/auth/me", headers=_bearer(token)).status_code == 401
        assert _login(anon, "uma").status_code == 401

        updated = client.put(
            "/api/admin/users/uma",
            json={"enabled": True, "email": "uma2@example.test"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["email"] == "uma2@example.test"
        # Re-enabling does not resurrect the session that was revoked.
        assert anon.get("/api/auth/me", headers=_bearer(token)).status_code == 401
        fresh = _login(anon, "uma")
        assert fresh.status_code == 200
        assert (
            detection_store.count_audit_log(action="user_disable", target_id="uma") == 1
        )

    def test_store_validation_error_is_400(
        self, client, detection_store, monkeypatch
    ) -> None:
        _user(detection_store, "vic")

        def _reject(username, **kwargs):
            raise ValueError("Invalid role: root")

        monkeypatch.setattr(detection_store, "update_user_with_audit", _reject)
        resp = client.put("/api/admin/users/vic", json={"display_name": "V"})
        assert resp.status_code == 400
        assert resp.json() == {"detail": "Invalid role: root"}

    def test_reset_password_of_unknown_user_is_404(self, client) -> None:
        resp = client.post(
            "/api/admin/users/ghost/reset-password",
            json={"new_password": "Whatever-123"},
        )
        assert resp.status_code == 404

    def test_reset_password_audit_names_the_session_admin(
        self, anon, detection_store
    ) -> None:
        admin_id = _user(detection_store, "root-admin", role="admin")
        _user(detection_store, "wes")
        token = detection_store.create_session(user_id=admin_id)["session_token"]
        resp = anon.post(
            "/api/admin/users/wes/reset-password",
            headers=_bearer(token),
            json={"new_password": "Reset-pass-456!"},
        )
        assert resp.status_code == 200
        conn = detection_store.get_connection()
        operator = conn.execute(
            "SELECT operator FROM audit_log WHERE action = 'password_reset' "
            "AND target_id = 'wes'"
        ).fetchone()[0]
        assert operator == "root-admin"


def test_session_token_is_stored_hashed(anon, detection_store) -> None:
    uid = _user(detection_store, "xena")
    token = _login(anon, "xena").json()["session_token"]
    conn = detection_store.get_connection()
    stored = [
        r[0]
        for r in conn.execute(
            "SELECT session_token FROM sessions WHERE user_id = ?", [uid]
        )
    ]
    assert stored == [hashlib.sha256(token.encode()).hexdigest()]
