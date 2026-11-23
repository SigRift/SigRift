"""The bridge's own auth routes commit only for the credential they verified.

The gateway serves ``/api/auth/*`` in the shipped deployment; these routes
serve bridge-only deployments (a reverse proxy in front, see
``src/sigrift/bridge/DEPLOYMENT.md``) and direct access to the bridge port.
They now match the gateway (CHANGELOG [Unreleased], "Security"):

* every password write, the admin reset included, ends the user's pending
  MFA logins (``mfa_tokens``) in its own transaction. The gateway shares
  ``detections.db`` and redeems those tokens too, so a bridge-side reset
  must end the gateway's pending logins as well;
* a login whose password check passed before a reset (or a disable) gets
  neither a session nor an MFA challenge, and one that upgraded a legacy
  hash is bound to the upgraded hash;
* an MFA login whose second factor was being checked during a reset (or a
  disable) gets no session;
* a password change commits only while the password it verified is still
  stored, its session still exists and the account is enabled; its
  replacement session is refused if a reset lands after the change;
* each of those checks and its write hold SQLite's write lock together, so
  a reset the gateway's process commits cannot land between them;
* wrong current passwords on ``POST /api/auth/change-password`` count
  toward the account lockout the login uses (atomically, also for parallel
  requests), are audited as ``auth_failure``, and a locked account gets
  429 without a password check.

Each race with a competing write is driven deterministically: that write
runs inside a hook on a call the request makes between its check and its
commit (for the other process, a second connection's write from a
statement trace).
The routers/mfa.py endpoints are mounted on the test app as in
test_mfa_router_security.py (the production bridge does not mount them).
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.routers import mfa as mfa_mod
from sigrift.bridge.security.totp import (
    compute_totp,
    generate_backup_codes,
    generate_secret,
)
from sigrift.bridge.storage import users as users_module
from sigrift.lib.security.credentials import hash_credential

USER = "victim"
PASSWORD = "Original-password-42!"
RESET = "Admin-reset-password-73!"
CHANGED = "User-changed-password-88!"
WRONG = "Not-the-password-19!"


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture
def app(bridge_app: FastAPI) -> FastAPI:
    bridge_app.include_router(mfa_mod.router, prefix="/api")
    return bridge_app


@pytest.fixture
def anon(app: FastAPI) -> TestClient:
    return TestClient(app)


@pytest.fixture
def admin(app: FastAPI, master_key: str) -> TestClient:
    return TestClient(app, headers={"X-API-Key": master_key})


def make_user(
    store: DetectionStore, *, mfa: bool = False, username: str = USER
) -> tuple[int, str, list[str]]:
    """Create the user; with *mfa*, enrolled. Returns (id, secret, codes)."""
    store.create_user(username, PASSWORD, role="viewer")
    uid = store.users.get_user(username)["id"]
    if not mfa:
        return uid, "", []
    secret = generate_secret()
    codes = generate_backup_codes(count=2)
    store.users.set_totp_secret(uid, secret)
    store.users.store_backup_codes(uid, [hash_credential(c) for c in codes])
    store.users.enable_mfa(uid)
    return uid, secret, codes


def admin_reset(store: DetectionStore) -> None:
    """Commit what ``POST /api/admin/users/{u}/reset-password`` commits."""
    assert store.set_password_with_audit(
        USER,
        RESET,
        action="password_reset",
        operator="test-admin",
        note="Password reset by admin",
    )


def disable_without_revoking(store: DetectionStore) -> None:
    """Disable the account and leave its sessions (``update_user``'s default)."""
    assert store.users.update_user(USER, enabled=False) is not None


def make_legacy(store: DetectionStore) -> str:
    """Store the user's password as a legacy SHA-256 hash; return that hash."""
    salt = b"synthetic-legacy-salt"
    legacy = hashlib.sha256(salt + PASSWORD.encode()).hexdigest()
    with store._ctx.write_transaction() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
            [legacy, salt, USER],
        )
    return legacy


def count(store: DetectionStore, table: str, uid: int) -> int:
    return (
        store.get_connection()
        .execute(f"SELECT COUNT(*) FROM {table} WHERE user_id = ?", [uid])
        .fetchone()[0]
    )


def stored_password_is(store: DetectionStore, password: str) -> bool:
    return store.users.verify_password(USER, password)


def run_once_after(monkeypatch, owner, name: str, action) -> list[bool]:
    """Wrap ``owner.name``: its first call runs, then *action*, then returns.

    Returns a list that holds ``True`` once the hook has fired.
    """
    real = getattr(owner, name)
    fired: list[bool] = []

    def hooked(*args, **kwargs):
        result = real(*args, **kwargs)
        if not fired:
            fired.append(True)
            action()
        return result

    monkeypatch.setattr(owner, name, hooked)
    return fired


def after_new_password_is_hashed(monkeypatch, action) -> list[bool]:
    """Run *action* once, right after the change hashes its new password.

    That is inside the change's commit step, after its current-password
    check: the window a racing reset or revocation lands in.
    """
    real = users_module.hash_credential
    fired: list[bool] = []

    def hooked(credential, *args, **kwargs):
        result = real(credential, *args, **kwargs)
        if credential == CHANGED and not fired:
            fired.append(True)
            action()
        return result

    monkeypatch.setattr(users_module, "hash_credential", hooked)
    return fired


def login(c: TestClient, password: str = PASSWORD):
    return c.post("/api/auth/login", json={"username": USER, "password": password})


def challenge(c: TestClient) -> str:
    resp = login(c)
    assert resp.status_code == 200, resp.text
    assert resp.json()["mfa_required"] is True
    return resp.json()["mfa_token"]


def verify(c: TestClient, mfa_token: str, code: str):
    return c.post(
        "/api/auth/mfa/verify", json={"mfa_token": mfa_token, "totp_code": code}
    )


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def change(c: TestClient, token: str, current: str = PASSWORD):
    return c.post(
        "/api/auth/change-password",
        headers=bearer(token),
        json={"current_password": current, "new_password": CHANGED},
    )


async def change_burst(app: FastAPI, token: str, n: int, current: str) -> list[int]:
    """Send *n* change-password requests at once; return their status codes."""
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:

        async def one() -> int:
            resp = await client.post(
                "/api/auth/change-password",
                headers=bearer(token),
                json={"current_password": current, "new_password": CHANGED},
            )
            return resp.status_code

        return list(await asyncio.gather(*(one() for _ in range(n))))


# ---------------------------------------------------------------------------
# 1a. A password write ends the user's pending MFA logins
# ---------------------------------------------------------------------------


class TestPasswordWriteEndsPendingMfaLogins:
    @pytest.mark.parametrize("revoke_sessions", [False, True])
    def test_every_password_write_deletes_the_users_tokens(
        self, detection_store, revoke_sessions
    ) -> None:
        uid, _, _ = make_user(detection_store)
        other_id, _, _ = make_user(detection_store, username="bystander")
        pending = detection_store.users.create_mfa_token(uid)
        bystander = detection_store.users.create_mfa_token(other_id)

        assert detection_store.users.set_password(
            USER, RESET, revoke_sessions=revoke_sessions
        )
        assert count(detection_store, "mfa_tokens", uid) == 0
        assert detection_store.users.verify_mfa_token(pending) is None
        # Only that user's logins end.
        assert detection_store.users.verify_mfa_token(bystander) == other_id

    @pytest.mark.parametrize("failing", ["mfa_tokens", "sessions"])
    @pytest.mark.parametrize("write", ["admin-reset", "change"])
    def test_the_token_delete_is_part_of_the_password_transaction(
        self, detection_store, write, failing
    ) -> None:
        """The token delete and the password commit as one.

        A failure of the token delete itself (``mfa_tokens``) leaves the old
        password, so the delete is not committed apart from the password
        write, after it; one of the revocation that follows it
        (``sessions``) leaves the token, so it is not committed apart and
        before.
        """
        uid, _, _ = make_user(detection_store)
        pending = detection_store.users.create_mfa_token(uid)
        # A session to revoke, so the write's revocation runs.
        detection_store.create_session(user_id=uid)
        if write == "admin-reset":
            new, action = RESET, "password_reset"

            def password_write() -> None:
                admin_reset(detection_store)

        else:
            new, action = CHANGED, "password_change"
            credential = detection_store.verify_password_credential(USER, PASSWORD)

            def password_write() -> None:
                assert detection_store.change_password_with_audit(
                    USER,
                    CHANGED,
                    credential=credential,
                    session_token=None,
                    action=action,
                    operator=USER,
                )

        with detection_store._ctx.write_transaction() as conn:
            conn.execute(
                f"CREATE TRIGGER refuse_delete BEFORE DELETE ON {failing} "
                "BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END"
            )
        with pytest.raises(Exception, match="injected delete failure"):
            password_write()
        # Rolled back as one: old password, challenge still pending.
        assert stored_password_is(detection_store, PASSWORD)
        assert count(detection_store, "mfa_tokens", uid) == 1
        assert count(detection_store, "sessions", uid) == 1
        assert detection_store.count_audit_log(action=action) == 0
        with detection_store._ctx.write_transaction() as conn:
            conn.execute("DROP TRIGGER refuse_delete")
        password_write()
        assert stored_password_is(detection_store, new)
        assert count(detection_store, "mfa_tokens", uid) == 0
        assert detection_store.users.verify_mfa_token(pending) is None

    @pytest.mark.parametrize("how", ["admin-reset", "self-change"])
    def test_pending_challenge_cannot_finish_after_a_password_change(
        self, anon, admin, detection_store, how
    ) -> None:
        uid, secret, _ = make_user(detection_store, mfa=True)
        mfa_token = challenge(anon)
        if how == "admin-reset":
            resp = admin.post(
                f"/api/admin/users/{USER}/reset-password",
                json={"new_password": RESET},
            )
            assert resp.status_code == 200, resp.text
        else:
            session = detection_store.create_session(user_id=uid)["session_token"]
            assert change(anon, session).status_code == 200
        assert count(detection_store, "mfa_tokens", uid) == 0
        sessions = count(detection_store, "sessions", uid)

        resp = verify(anon, mfa_token, compute_totp(secret))
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        assert count(detection_store, "sessions", uid) == sessions
        assert detection_store.count_audit_log(action="user_login_mfa") == 0


# ---------------------------------------------------------------------------
# 1b. Password login racing a reset
# ---------------------------------------------------------------------------


class TestLoginRacingAReset:
    def test_login_checked_before_a_reset_gets_no_session(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid, _, _ = make_user(detection_store)
        # Called after the password check, before the session is created.
        fired = run_once_after(
            monkeypatch,
            detection_store.security_state,
            "clear_account_failures",
            lambda: admin_reset(detection_store),
        )
        resp = login(anon)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid username or password"}
        assert "set-cookie" not in resp.headers
        assert count(detection_store, "sessions", uid) == 0
        assert detection_store.count_audit_log(action="user_login") == 0
        assert stored_password_is(detection_store, RESET)
        # The reset password works.
        assert login(anon, RESET).status_code == 200

    def test_mfa_login_checked_before_a_reset_gets_no_challenge(
        self, anon, detection_store, monkeypatch
    ) -> None:
        uid, _, _ = make_user(detection_store, mfa=True)
        fired = run_once_after(
            monkeypatch,
            detection_store.security_state,
            "clear_account_failures",
            lambda: admin_reset(detection_store),
        )
        resp = login(anon)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid username or password"}
        assert count(detection_store, "mfa_tokens", uid) == 0
        assert detection_store.count_audit_log(action="user_login_mfa_pending") == 0
        # The reset password gets a challenge.
        assert login(anon, RESET).json()["mfa_required"] is True


# ---------------------------------------------------------------------------
# 1c. MFA verification racing a reset
# ---------------------------------------------------------------------------


class TestMfaVerifyRacingAReset:
    @pytest.mark.parametrize("factor", ["totp", "backup-code"])
    def test_reset_during_the_second_factor_check_refuses_the_session(
        self, anon, detection_store, monkeypatch, factor
    ) -> None:
        uid, secret, codes = make_user(detection_store, mfa=True)
        mfa_token = challenge(anon)
        if factor == "totp":
            owner, name, code = (
                detection_store.security_state,
                "record_totp_use",
                compute_totp(secret),
            )
        else:
            owner, name, code = detection_store.users, "verify_backup_code", codes[0]
        fired = run_once_after(
            monkeypatch, owner, name, lambda: admin_reset(detection_store)
        )

        resp = verify(anon, mfa_token, code)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        assert count(detection_store, "sessions", uid) == 0
        assert detection_store.count_audit_log(action="user_login_mfa") == 0
        assert stored_password_is(detection_store, RESET)


# ---------------------------------------------------------------------------
# 1b/1c. A disable (without revocation) during the login refuses it too
# ---------------------------------------------------------------------------


class TestDisableDuringTheLogin:
    """The credential is current only while the account is enabled.

    ``update_user(enabled=False)`` leaves the sessions, so nothing but that
    check stops a login whose password (or second factor) was checked just
    before the disable.
    """

    @pytest.mark.parametrize("mfa", [False, True], ids=["session", "mfa-challenge"])
    def test_login_checked_before_a_disable_gets_nothing(
        self, anon, detection_store, monkeypatch, mfa
    ) -> None:
        uid, _, _ = make_user(detection_store, mfa=mfa)
        fired = run_once_after(
            monkeypatch,
            detection_store.security_state,
            "clear_account_failures",
            lambda: disable_without_revoking(detection_store),
        )
        resp = login(anon)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid username or password"}
        assert count(detection_store, "sessions", uid) == 0
        assert count(detection_store, "mfa_tokens", uid) == 0
        assert detection_store.count_audit_log(action="user_login") == 0
        assert detection_store.count_audit_log(action="user_login_mfa_pending") == 0

    @pytest.mark.parametrize("factor", ["totp", "backup-code"])
    def test_disable_during_the_second_factor_check_refuses_the_session(
        self, anon, detection_store, monkeypatch, factor
    ) -> None:
        uid, secret, codes = make_user(detection_store, mfa=True)
        mfa_token = challenge(anon)
        if factor == "totp":
            owner, name, code = (
                detection_store.security_state,
                "record_totp_use",
                compute_totp(secret),
            )
        else:
            owner, name, code = detection_store.users, "verify_backup_code", codes[0]
        fired = run_once_after(
            monkeypatch, owner, name, lambda: disable_without_revoking(detection_store)
        )

        resp = verify(anon, mfa_token, code)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Invalid or expired MFA token"}
        assert count(detection_store, "sessions", uid) == 0
        assert detection_store.count_audit_log(action="user_login_mfa") == 0


# ---------------------------------------------------------------------------
# 1b. A legacy hash upgraded by the login binds the login to the new hash
# ---------------------------------------------------------------------------


class TestLegacyHashLogin:
    def test_the_check_returns_the_upgraded_credential(self, detection_store) -> None:
        uid, _, _ = make_user(detection_store)
        legacy = make_legacy(detection_store)
        users = detection_store.users
        credential = users.verify_password_credential(USER, PASSWORD)
        stored = users.get_user_full(USER)["password_hash"]
        assert stored != legacy
        assert credential == users_module.VerifiedCredential(uid, stored)
        # Upgraded once: the next check verifies the same credential.
        assert users.verify_password_credential(USER, PASSWORD) == credential

    @pytest.mark.parametrize("mfa", [False, True], ids=["password", "mfa"])
    def test_the_login_that_upgrades_the_hash_succeeds(
        self, anon, detection_store, mfa
    ) -> None:
        uid, secret, _ = make_user(detection_store, mfa=mfa)
        legacy = make_legacy(detection_store)
        if mfa:
            resp = verify(anon, challenge(anon), compute_totp(secret))
        else:
            resp = login(anon)
        assert resp.status_code == 200, resp.text
        token = resp.json()["session_token"]
        assert token
        assert detection_store.users.get_user_full(USER)["password_hash"] != legacy
        assert count(detection_store, "sessions", uid) == 1
        assert anon.get("/api/auth/me", headers=bearer(token)).status_code == 200


# ---------------------------------------------------------------------------
# 1d. Password change racing a reset or a revocation
# ---------------------------------------------------------------------------


class TestChangeRacingAReset:
    @pytest.fixture
    def session(self, detection_store) -> tuple[int, str]:
        uid, _, _ = make_user(detection_store)
        return uid, detection_store.create_session(user_id=uid)["session_token"]

    def test_reset_during_the_change_wins(
        self, anon, detection_store, monkeypatch, session
    ) -> None:
        uid, token = session
        fired = after_new_password_is_hashed(
            monkeypatch, lambda: admin_reset(detection_store)
        )
        resp = change(anon, token)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Current password is incorrect"}
        assert stored_password_is(detection_store, RESET)
        assert not stored_password_is(detection_store, CHANGED)
        assert count(detection_store, "sessions", uid) == 0
        assert detection_store.count_audit_log(action="password_change") == 0

    @pytest.mark.parametrize("ended", ["session-revoked", "account-disabled"])
    def test_change_from_an_ended_session_changes_nothing(
        self, anon, detection_store, monkeypatch, session, ended
    ) -> None:
        uid, token = session
        if ended == "session-revoked":
            action = lambda: detection_store.users.delete_session(token)  # noqa: E731
        else:
            # Disabled without revoking: the session row is still there.
            action = lambda: detection_store.users.update_user(  # noqa: E731
                USER, enabled=False
            )
        fired = after_new_password_is_hashed(monkeypatch, action)
        resp = change(anon, token)
        assert fired
        assert resp.status_code == 401, resp.text
        assert resp.json() == {"detail": "Not authenticated"}
        assert verify_stored(detection_store, PASSWORD)
        assert not verify_stored(detection_store, CHANGED)
        assert detection_store.count_audit_log(action="password_change") == 0

    def test_reset_after_the_change_refuses_the_replacement_session(
        self, anon, detection_store, monkeypatch, session
    ) -> None:
        uid, token = session
        # Called after the change commits, before the replacement session.
        fired = run_once_after(
            monkeypatch,
            detection_store.users,
            "clear_must_change_password",
            lambda: admin_reset(detection_store),
        )
        resp = change(anon, token)
        assert fired
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "status": "password_changed",
            "reauthentication_required": True,
        }
        assert count(detection_store, "sessions", uid) == 0
        assert stored_password_is(detection_store, RESET)


def verify_stored(store: DetectionStore, password: str) -> bool:
    """Whether *password* is stored, checked without the enabled flag."""
    from sigrift.lib.security.credentials import verify_credential

    user = store.users.get_user_full(USER)
    return verify_credential(password, user["password_hash"], user["salt"])


# ---------------------------------------------------------------------------
# 2. Wrong current passwords on change-password count toward the lockout
# ---------------------------------------------------------------------------


class TestChangePasswordAttemptLimit:
    @pytest.fixture
    def session(self, detection_store, monkeypatch) -> tuple[int, str]:
        monkeypatch.setattr(detection_store.security_state, "LOCKOUT_MAX", 3)
        uid, _, _ = make_user(detection_store)
        return uid, detection_store.create_session(user_id=uid)["session_token"]

    def test_wrong_current_passwords_lock_the_account(
        self, anon, detection_store, monkeypatch, session
    ) -> None:
        _, token = session
        sec = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX):
            resp = change(anon, token, current=WRONG)
            assert resp.status_code == 401, resp.text
            assert resp.json() == {"detail": "Current password is incorrect"}
        assert sec.count_recent_failures(USER) == sec.LOCKOUT_MAX
        failures = detection_store.get_audit_log(action="auth_failure", target_id=USER)
        assert len(failures) == sec.LOCKOUT_MAX
        assert all(entry["operator"] == USER for entry in failures)
        assert all("password change" in entry["note"] for entry in failures)

        checked: list[str] = []
        real_check = detection_store.verify_password_credential

        def counted_check(username: str, password: str):
            checked.append(username)
            return real_check(username, password)

        monkeypatch.setattr(
            detection_store, "verify_password_credential", counted_check
        )
        # Locked: even the right password is refused, before it is checked
        # (no PBKDF2 for a locked account).
        locked = change(anon, token)
        assert locked.status_code == 429, locked.text
        assert locked.headers["retry-after"] == "1800"
        assert stored_password_is(detection_store, PASSWORD)
        assert detection_store.count_audit_log(action="password_change") == 0
        # One lockout for the account: the login is locked too ...
        assert login(anon).status_code == 429
        assert checked == []
        # ... and the session itself is not ended by it.
        assert anon.get("/api/auth/me", headers=bearer(token)).status_code == 200

    def test_parallel_wrong_changes_stop_at_the_limit(
        self, app, detection_store, session
    ) -> None:
        """The attempt is reserved before the check, atomically with the
        lockout check, as the login's is (test_login_lockout_concurrency.py):
        parallel guesses from one session get LOCKOUT_MAX checks in all,
        not one each."""
        _, token = session
        sec = detection_store.security_state
        attempts = sec.LOCKOUT_MAX * 3
        codes = asyncio.run(change_burst(app, token, attempts, WRONG))
        assert codes.count(401) == sec.LOCKOUT_MAX, codes
        assert codes.count(429) == attempts - sec.LOCKOUT_MAX, codes
        assert sec.count_recent_failures(USER) == sec.LOCKOUT_MAX
        assert detection_store.count_audit_log(action="auth_failure") == (
            sec.LOCKOUT_MAX
        )
        assert stored_password_is(detection_store, PASSWORD)

    def test_an_admin_reset_is_not_limited_by_the_lockout(
        self, anon, admin, detection_store, session
    ) -> None:
        _, token = session
        sec = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX):
            assert change(anon, token, current=WRONG).status_code == 401
        assert change(anon, token).status_code == 429
        resp = admin.post(
            f"/api/admin/users/{USER}/reset-password", json={"new_password": RESET}
        )
        assert resp.status_code == 200, resp.text
        assert stored_password_is(detection_store, RESET)

    def test_failed_logins_lock_the_change_too(
        self, anon, detection_store, session
    ) -> None:
        _, token = session
        sec = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX):
            assert login(anon, WRONG).status_code == 401
        resp = change(anon, token)
        assert resp.status_code == 429, resp.text
        assert stored_password_is(detection_store, PASSWORD)

    def test_a_successful_change_clears_the_count(
        self, anon, detection_store, session
    ) -> None:
        _, token = session
        sec = detection_store.security_state
        for _ in range(sec.LOCKOUT_MAX - 1):
            assert change(anon, token, current=WRONG).status_code == 401
        assert sec.count_recent_failures(USER) == sec.LOCKOUT_MAX - 1
        resp = change(anon, token)
        assert resp.status_code == 200, resp.text
        assert sec.count_recent_failures(USER) == 0
        assert stored_password_is(detection_store, CHANGED)


# ---------------------------------------------------------------------------
# Storage API: the verified credential
# ---------------------------------------------------------------------------


class TestVerifiedCredential:
    def test_stale_credential_creates_nothing(self, detection_store) -> None:
        from sigrift.bridge.storage.users import CredentialChangedError

        uid, _, _ = make_user(detection_store)
        users = detection_store.users
        credential = users.verify_password_credential(USER, PASSWORD)
        assert credential is not None and credential.user_id == uid
        assert credential.password_hash not in repr(credential)
        assert users.verify_password_credential(USER, WRONG) is None

        # Current: both commit.
        session = users.create_session(uid, credential=credential)
        assert users.get_session(session["session_token"]) is not None
        token = users.create_mfa_token(uid, credential=credential)
        claimed = users.claim_mfa_token(token)
        assert claimed == credential

        users.set_password(USER, RESET)
        for create in (
            lambda: users.create_session(uid, credential=credential),
            lambda: users.create_mfa_token(uid, credential=credential),
        ):
            with pytest.raises(CredentialChangedError):
                create()
        assert count(detection_store, "mfa_tokens", uid) == 0
        assert count(detection_store, "sessions", uid) == 1

    def test_change_returns_the_new_credential(self, detection_store) -> None:
        from sigrift.bridge.storage.users import CredentialChangedError

        uid, _, _ = make_user(detection_store)
        users = detection_store.users
        old = users.verify_password_credential(USER, PASSWORD)
        pending = users.create_mfa_token(uid, credential=old)
        users.create_session(uid, credential=old)

        new = users.change_password(USER, CHANGED, credential=old, session_token=None)
        assert new is not None and new.user_id == uid and new != old
        assert users.verify_password_credential(USER, CHANGED) == new
        assert count(detection_store, "sessions", uid) == 0
        assert users.verify_mfa_token(pending) is None
        # The new credential issues; the old one is spent.
        assert users.create_session(uid, credential=new)["user_id"] == uid
        with pytest.raises(CredentialChangedError):
            users.change_password(USER, RESET, credential=old, session_token=None)
        assert stored_password_is(detection_store, CHANGED)

    def test_misuse_is_refused(self, detection_store) -> None:
        uid, _, _ = make_user(detection_store)
        other_id, _, _ = make_user(detection_store, username="bystander")
        users = detection_store.users
        credential = users.verify_password_credential(USER, PASSWORD)
        # A credential only ever vouches for its own account.
        with pytest.raises(ValueError):
            users.create_session(other_id, credential=credential)
        with pytest.raises(ValueError):
            users.create_mfa_token(other_id, credential=credential)
        assert count(detection_store, "sessions", other_id) == 0
        assert count(detection_store, "mfa_tokens", other_id) == 0
        # A change for a user that does not exist changes nothing.
        assert (
            users.change_password(
                "nobody", CHANGED, credential=credential, session_token=None
            )
            is None
        )
        assert stored_password_is(detection_store, PASSWORD)

    def test_credential_of_a_disabled_account_creates_nothing(
        self, detection_store
    ) -> None:
        from sigrift.bridge.storage.users import CredentialChangedError

        uid, _, _ = make_user(detection_store)
        users = detection_store.users
        credential = users.verify_password_credential(USER, PASSWORD)
        users.update_user(USER, enabled=False)
        with pytest.raises(CredentialChangedError):
            users.create_session(uid, credential=credential)
        assert count(detection_store, "sessions", uid) == 0


class TestTheCheckHoldsTheDatabaseWriteLock:
    """The check and the write it allows are one IMMEDIATE transaction.

    The gateway writes ``detections.db`` from its own process, past the
    bridge's in-process write lock, so only SQLite's write lock keeps its
    reset from landing between a credential check and the write that check
    allows. Held from ``BEGIN IMMEDIATE`` on, it makes that reset wait (here
    it times out). In a deferred transaction the reset would commit there,
    and the session, challenge or change would then go ahead on the
    password it replaced.
    """

    # The write each check allows, as the statement that starts it.
    WRITES = {
        "session": "INSERT INTO sessions",
        "mfa-challenge": "INSERT INTO mfa_tokens",
        "mfa-claim": "DELETE FROM mfa_tokens",
        "change": "UPDATE users SET password_hash",
    }

    @pytest.mark.parametrize("write", list(WRITES))
    def test_another_process_cannot_reset_between_the_check_and_the_write(
        self, detection_store, tmp_path, write
    ) -> None:
        uid, _, _ = make_user(detection_store)
        users = detection_store.users
        credential = users.verify_password_credential(USER, PASSWORD)
        token = users.create_mfa_token(uid, credential=credential)
        conn = detection_store.get_connection()
        outcome: list[str] = []

        def other_process_resets(statement: str) -> None:
            if outcome or self.WRITES[write] not in statement:
                return
            other = sqlite3.connect(tmp_path / "test_detections.db", timeout=0.2)
            try:
                other.execute(
                    "UPDATE users SET password_hash = 'gateway-reset' "
                    "WHERE username = ?",
                    [USER],
                )
                other.commit()
                outcome.append("committed")
            except sqlite3.OperationalError as exc:
                outcome.append(f"blocked: {exc}")
            finally:
                other.close()

        conn.set_trace_callback(other_process_resets)
        try:
            if write == "session":
                result = users.create_session(uid, credential=credential)
            elif write == "mfa-challenge":
                result = users.create_mfa_token(uid, credential=credential)
            elif write == "mfa-claim":
                result = users.claim_mfa_token(token)
            else:
                result = users.change_password(
                    USER, CHANGED, credential=credential, session_token=None
                )
        finally:
            conn.set_trace_callback(None)

        assert outcome and outcome[0].startswith("blocked"), outcome
        assert result
        assert stored_password_is(
            detection_store, CHANGED if write == "change" else PASSWORD
        )
