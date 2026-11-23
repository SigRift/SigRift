"""Real SQLite audit failures cannot leave successful account changes behind.

The real auth router/dependencies run in FastAPI with a real DetectionStore.
Unrelated application routers/middleware are not needed for these transaction
contracts; password hashing, session authentication and storage are unchanged.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.storage import users as users_module
from sigrift.lib.security.credentials import verify_credential


OLD_PASSWORD = "Audit-original-42!"
NEW_PASSWORD = "Audit-replacement-73!"
ACTIONS = {
    "delete": "user_disable",
    "put": "user_update",
    "reset": "password_reset",
    "self": "password_change",
}


@pytest.fixture
def audit_store(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIDGE_ENV", "test")
    monkeypatch.setenv("BRIDGE_MASTER_KEY", "private-audit-regression-key")
    store = DetectionStore(tmp_path / "accounts.db")
    store.create_user("audit-admin", OLD_PASSWORD, role="admin")
    store.create_user("audit-target", OLD_PASSWORD, role="viewer")
    try:
        yield store
    finally:
        store.close()


@pytest.fixture
def account_api(audit_store):
    from sigrift.bridge.routers import auth

    app = FastAPI()
    app.state.detection_store = audit_store
    app.include_router(auth.router, prefix="/api")
    with TestClient(app, raise_server_exceptions=False) as client:

        def login(username):
            response = client.post(
                "/api/auth/login",
                json={"username": username, "password": OLD_PASSWORD},
            )
            assert response.status_code == 200
            client.cookies.clear()
            return response.json()["session_token"]

        admin_token = login("audit-admin")
        tokens = [login("audit-target") for _ in range(2)]
        yield client, admin_token, tokens


def mutate(api, operation):
    client, admin_token, tokens = api
    headers = {"Authorization": f"Bearer {admin_token}"}
    if operation == "delete":
        return client.delete("/api/admin/users/audit-target", headers=headers)
    if operation == "put":
        return client.put(
            "/api/admin/users/audit-target", headers=headers, json={"enabled": False}
        )
    if operation == "reset":
        return client.post(
            "/api/admin/users/audit-target/reset-password",
            headers=headers,
            json={"new_password": NEW_PASSWORD},
        )
    return client.post(
        "/api/auth/change-password",
        headers={"Authorization": f"Bearer {tokens[0]}"},
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
    )


def session_statuses(api):
    client, _, tokens = api
    return [
        client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        for token in tokens
    ]


def reject_audit(store):
    with store._ctx.write_transaction() as conn:
        conn.execute(
            """CREATE TRIGGER reject_account_audit BEFORE INSERT ON audit_log
            WHEN NEW.action IN ('user_disable', 'user_update',
                                'password_reset', 'password_change')
            BEGIN SELECT RAISE(ABORT, 'injected audit storage failure'); END"""
        )


@pytest.mark.parametrize("operation", ACTIONS)
def test_audit_failure_rolls_back_account_change(account_api, audit_store, operation):
    before = audit_store.users.get_user_full("audit-target")
    reject_audit(audit_store)
    response = mutate(account_api, operation)
    assert response.status_code == 500
    assert session_statuses(account_api) == [200, 200]
    reopened = DetectionStore(audit_store._ctx.db_path)
    try:
        after = reopened.users.get_user_full("audit-target")
        assert after["enabled"]
        assert verify_credential(OLD_PASSWORD, after["password_hash"], after["salt"])
        assert not verify_credential(
            NEW_PASSWORD, after["password_hash"], after["salt"]
        )
        # Self-service verifies the current password first; the existing
        # legacy-upgrade path can rehash that same credential before mutation.
        if operation != "self":
            assert (after["password_hash"], after["salt"]) == (
                before["password_hash"],
                before["salt"],
            )
        assert all(reopened.get_session(token) is not None for token in account_api[2])
        assert (
            reopened.count_audit_log(
                action=ACTIONS[operation], target_id="audit-target"
            )
            == 0
        )
        assert reopened.verify_audit_chain()["valid"]
    finally:
        reopened.close()

    # Once storage recovers, the original authenticated request can succeed.
    with audit_store._ctx.write_transaction() as conn:
        conn.execute("DROP TRIGGER reject_account_audit")
    assert mutate(account_api, operation).status_code == 200
    assert session_statuses(account_api) == [401, 401]
    assert (
        audit_store.count_audit_log(action=ACTIONS[operation], target_id="audit-target")
        == 1
    )
    assert audit_store.verify_audit_chain()["valid"]


@pytest.mark.parametrize("operation", ACTIONS)
def test_account_change_and_audit_persist_together(account_api, audit_store, operation):
    # Prime the real audit cache, so successful commit must invalidate it.
    assert audit_store.get_audit_log(action=ACTIONS[operation]) == []
    response = mutate(account_api, operation)
    assert response.status_code == 200
    assert session_statuses(account_api) == [401, 401]
    assert len(audit_store.get_audit_log(action=ACTIONS[operation])) == 1
    reopened = DetectionStore(audit_store._ctx.db_path)
    try:
        user = reopened.users.get_user_full("audit-target")
        assert bool(user["enabled"]) is (operation in {"reset", "self"})
        password = NEW_PASSWORD if operation in {"reset", "self"} else OLD_PASSWORD
        assert verify_credential(password, user["password_hash"], user["salt"])
        assert all(reopened.get_session(token) is None for token in account_api[2])
        entries = reopened.get_audit_log(
            action=ACTIONS[operation], target_id="audit-target"
        )
        assert len(entries) == 1
        assert entries[0]["operator"] == (
            "audit-target" if operation == "self" else "audit-admin"
        )
        assert reopened.verify_audit_chain()["valid"]
        if operation == "self":
            replacement = response.json()["session_token"]
            assert reopened.get_session(replacement) is not None
            assert (
                account_api[0]
                .get("/api/auth/me", headers={"Authorization": f"Bearer {replacement}"})
                .status_code
                == 200
            )
    finally:
        reopened.close()


def audited_mutation(store, operation, username="audit-target"):
    if operation == "password":
        return store.set_password_with_audit(
            username, NEW_PASSWORD, action="password_reset", operator="audit-admin"
        )
    return store.update_user_with_audit(
        username,
        enabled=False,
        revoke_sessions=True,
        action="user_disable",
        operator="audit-admin",
    )


@pytest.mark.parametrize("operation", ["password", "disable"])
@pytest.mark.parametrize("write_before", [False, True])
def test_audited_facade_refuses_caller_transaction_without_taking_ownership(
    audit_store, operation, write_before
):
    before = audit_store.users.get_user_full("audit-target")
    with audit_store._ctx.write_transaction() as conn:
        if write_before:
            conn.execute(
                "UPDATE users SET display_name = 'caller-owned' WHERE username = 'audit-admin'"
            )
        with pytest.raises(RuntimeError, match="own transaction"):
            audited_mutation(audit_store, operation)
        assert conn.in_transaction is write_before
        conn.execute(
            "UPDATE users SET display_name = 'caller-owned' WHERE username = 'audit-admin'"
        )
        assert (
            conn.execute(
                "SELECT display_name FROM users WHERE username = 'audit-admin'"
            ).fetchone()[0]
            == "caller-owned"
        )
    assert audit_store.get_user("audit-admin")["display_name"] == "caller-owned"
    assert audit_store.users.get_user_full("audit-target") == before
    assert audit_store.count_audit_log() == 0


@pytest.mark.parametrize("operation", ["password", "disable"])
def test_missing_user_does_not_write_success_audit(audit_store, operation):
    assert not audited_mutation(audit_store, operation, "missing")
    assert audit_store.count_audit_log() == 0
    assert audit_store.get_user("audit-target")["enabled"]


@pytest.mark.parametrize("operation", ["password", "disable"])
def test_explicit_sqlite_transaction_keeps_caller_owned_rollback(
    audit_store, operation
):
    before = audit_store.users.get_user_full("audit-target")
    conn = audit_store._ctx.get_conn()
    conn.execute("BEGIN")
    try:
        conn.execute(
            "UPDATE users SET display_name = 'uncommitted caller write' "
            "WHERE username = 'audit-admin'"
        )
        with pytest.raises(RuntimeError, match="own transaction"):
            audited_mutation(audit_store, operation)
        assert conn.in_transaction
        assert (
            conn.execute(
                "SELECT display_name FROM users WHERE username = 'audit-admin'"
            ).fetchone()[0]
            == "uncommitted caller write"
        )
    finally:
        conn.rollback()
    assert audit_store.get_user("audit-admin")["display_name"] == ""
    assert audit_store.users.get_user_full("audit-target") == before
    assert audit_store.count_audit_log() == 0


@pytest.mark.parametrize("reject", [False, True])
def test_empty_user_update_retains_audit_contract(account_api, audit_store, reject):
    if reject:
        reject_audit(audit_store)
    response = account_api[0].put(
        "/api/admin/users/audit-target",
        json={},
        headers={"Authorization": f"Bearer {account_api[1]}"},
    )
    assert response.status_code == (500 if reject else 200)
    assert session_statuses(account_api) == [200, 200]
    assert audit_store.count_audit_log(
        action="user_update", target_id="audit-target"
    ) == (0 if reject else 1)


def test_password_hashing_finishes_before_write_lock(audit_store, monkeypatch):
    real_hash = users_module.hash_credential
    observed = []

    def measured_hash(password):
        assert not audit_store._ctx.write_lock.locked()
        assert not audit_store._ctx.get_conn().in_transaction
        observed.append(password == NEW_PASSWORD)
        return real_hash(password)

    monkeypatch.setattr(users_module, "hash_credential", measured_hash)
    assert audited_mutation(audit_store, "password")
    assert observed == [True]
    assert audit_store.verify_audit_chain()["valid"]


def test_account_audit_blocks_competing_chain_writer(audit_store):
    conn = audit_store._ctx.get_conn()
    outcome = []

    def interloper(statement):
        if "SELECT hmac_chain FROM audit_log" not in statement or outcome:
            return
        other = sqlite3.connect(audit_store._ctx.db_path, timeout=0.05)
        try:
            try:
                other.execute(
                    "INSERT INTO audit_log (timestamp, action, target_id, tenant_id, hmac_chain) VALUES ('2026-01-01', 'other', 'x', 'default', 'invalid')"
                )
            except sqlite3.OperationalError as exc:
                outcome.append(str(exc))
            else:
                outcome.append("unexpected write")
        finally:
            other.close()

    conn.set_trace_callback(interloper)
    try:
        assert audited_mutation(audit_store, "disable")
    finally:
        conn.set_trace_callback(None)
    assert outcome == ["database is locked"]
    assert audit_store.verify_audit_chain()["valid"]
    assert audit_store.count_audit_log() == 1


@pytest.mark.parametrize("operation", ["password", "disable"])
def test_missing_production_audit_key_rolls_back_mutation(
    audit_store, monkeypatch, operation
):
    before = audit_store.users.get_user_full("audit-target")
    with monkeypatch.context() as settings:
        settings.setenv("BRIDGE_ENV", "production")
        for name in ("BRIDGE_AUDIT_KEY", "BRIDGE_AUDIT_SECRET", "BRIDGE_MASTER_KEY"):
            settings.delenv(name, raising=False)
        with pytest.raises(RuntimeError, match="No audit HMAC key"):
            audited_mutation(audit_store, operation)
    assert audit_store.users.get_user_full("audit-target") == before
    assert audit_store.count_audit_log() == 0
    assert audit_store.verify_audit_chain()["valid"]


@pytest.mark.parametrize("operation", ["password", "disable"])
def test_audited_mutation_and_event_stay_in_the_selected_tenant(audit_store, operation):
    tenant = DetectionStore(audit_store._ctx.db_path, tenant_id="other")
    try:
        tenant.create_user("other-target", OLD_PASSWORD)
        user_id = tenant.get_user("other-target")["id"]
        token = tenant.create_session(user_id)["session_token"]
        before = tenant.users.get_user_full("other-target")
        assert not audited_mutation(audit_store, operation, "other-target")
        assert audited_mutation(audit_store, operation)
        assert tenant.users.get_user_full("other-target") == before
        assert tenant.get_session(token) is not None
        assert tenant.count_audit_log() == 0
        assert audit_store.count_audit_log() == 1
        assert audit_store.verify_audit_chain()["valid"]
    finally:
        tenant.close()


def test_empty_update_for_missing_user_does_not_audit_success(account_api, audit_store):
    response = account_api[0].put(
        "/api/admin/users/missing",
        json={},
        headers={"Authorization": f"Bearer {account_api[1]}"},
    )
    assert response.status_code == 404
    assert audit_store.count_audit_log(action="user_update") == 0
    assert session_statuses(account_api) == [200, 200]


def test_parallel_audited_changes_keep_one_valid_chain(audit_store):
    for i in range(4):
        audit_store.create_user(f"parallel-{i}", OLD_PASSWORD)
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(
            executor.map(
                lambda i: audited_mutation(audit_store, "disable", f"parallel-{i}"),
                range(4),
            )
        )
    assert all(result and not result["enabled"] for result in results)
    assert audit_store.count_audit_log(action="user_disable") == 4
    assert audit_store.verify_audit_chain()["valid"]


def test_first_empty_audited_update_after_reopen_cannot_relock_schema_check(
    audit_store,
):
    # Fresh process/UserStore: create_user must not have warmed its lazy
    # schema check. A timeout bounds a regression in the non-reentrant lock.
    env = dict(os.environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """import json, sys
from sigrift.bridge.detection_store import DetectionStore
store = DetectionStore(sys.argv[1])
try:
    user = store.update_user_with_audit('audit-target', action='user_update', operator='audit-admin')
    print(json.dumps({'username': user['username'], 'audit_count': store.count_audit_log(action='user_update'), 'chain_valid': store.verify_audit_chain()['valid']}))
finally:
    store.close()
""",
            audit_store._ctx.db_path,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert json.loads(result.stdout) == {
        "username": "audit-target",
        "audit_count": 1,
        "chain_valid": True,
    }
