"""Public account changes and session revocation must commit together."""

from __future__ import annotations

from fastapi.testclient import TestClient
import pytest

from sigrift.bridge.detection_store import DetectionStore


OLD_PASSWORD = "Original-password-42!"
NEW_PASSWORD = "Replacement-password-73!"


@pytest.fixture
def account_clients(bridge_app, detection_store, master_key):
    detection_store.create_user("revocation-target", OLD_PASSWORD, role="viewer")
    with (
        TestClient(
            bridge_app,
            headers={"X-API-Key": master_key},
            raise_server_exceptions=False,
        ) as admin,
        TestClient(bridge_app, raise_server_exceptions=False) as member,
    ):
        tokens = []
        for _ in range(2):
            response = member.post(
                "/api/auth/login",
                json={"username": "revocation-target", "password": OLD_PASSWORD},
            )
            assert response.status_code == 200
            tokens.append(response.json()["session_token"])
        member.cookies.clear()
        yield admin, member, tokens


def session_statuses(member, tokens):
    return [
        member.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        for token in tokens
    ]


def reject_session_deletion(store):
    with store._ctx.write_transaction() as conn:
        conn.execute(
            """CREATE TRIGGER fail_session_revocation BEFORE DELETE ON sessions
            BEGIN SELECT RAISE(ABORT, 'injected session revocation failure'); END"""
        )


def allow_session_deletion(store):
    with store._ctx.write_transaction() as conn:
        conn.execute("DROP TRIGGER fail_session_revocation")


def persisted_account(store, tokens):
    """Read via a new storage instance, independently of request connections."""
    reopened = DetectionStore(db_path=store._ctx.db_path)
    try:
        return {
            "enabled": bool(reopened.get_user("revocation-target")["enabled"]),
            "old_password_valid": reopened.verify_password(
                "revocation-target", OLD_PASSWORD
            ),
            "new_password_valid": reopened.verify_password(
                "revocation-target", NEW_PASSWORD
            ),
            "sessions": [reopened.get_session(token) is not None for token in tokens],
        }
    finally:
        reopened.close()


def test_admin_disable_via_update_cannot_revive_old_sessions(account_clients):
    admin, member, tokens = account_clients
    assert session_statuses(member, tokens) == [200, 200]
    response = admin.put("/api/admin/users/revocation-target", json={"enabled": False})
    assert response.status_code == 200
    assert session_statuses(member, tokens) == [401, 401]
    response = admin.put("/api/admin/users/revocation-target", json={"enabled": True})
    assert response.status_code == 200
    assert session_statuses(member, tokens) == [401, 401]


@pytest.mark.parametrize("method", ["delete", "put"])
def test_admin_disable_failure_rolls_back_account_and_sessions(
    account_clients, detection_store, method
):
    admin, member, tokens = account_clients
    reject_session_deletion(detection_store)
    kwargs = {"json": {"enabled": False}} if method == "put" else {}
    response = getattr(admin, method)("/api/admin/users/revocation-target", **kwargs)
    observed = {
        "status": response.status_code,
        "enabled": bool(detection_store.get_user("revocation-target")["enabled"]),
        "sessions": session_statuses(member, tokens),
        "success_audits": detection_store.count_audit_log(
            action="user_disable" if method == "delete" else "user_update",
            target_id="revocation-target",
        ),
    }
    assert observed == {
        "status": 500,
        "enabled": True,
        "sessions": [200, 200],
        "success_audits": 0,
    }
    restored = persisted_account(detection_store, tokens)
    assert restored["enabled"] and restored["sessions"] == [True, True]
    allow_session_deletion(detection_store)
    assert (
        getattr(admin, method)(
            "/api/admin/users/revocation-target", **kwargs
        ).status_code
        == 200
    )
    assert (
        admin.put(
            "/api/admin/users/revocation-target", json={"enabled": True}
        ).status_code
        == 200
    )
    assert session_statuses(member, tokens) == [401, 401]
    restored = persisted_account(detection_store, tokens)
    assert restored["enabled"] and restored["sessions"] == [False, False]


@pytest.mark.parametrize("self_change", [False, True])
def test_password_change_failure_preserves_password_and_sessions(
    account_clients, detection_store, self_change
):
    admin, member, tokens = account_clients
    reject_session_deletion(detection_store)
    if self_change:
        response = member.post(
            "/api/auth/change-password",
            json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )
    else:
        response = admin.post(
            "/api/admin/users/revocation-target/reset-password",
            json={"new_password": NEW_PASSWORD},
        )
    observed = {
        "status": response.status_code,
        "old_password_valid": detection_store.verify_password(
            "revocation-target", OLD_PASSWORD
        ),
        "new_password_valid": detection_store.verify_password(
            "revocation-target", NEW_PASSWORD
        ),
        "sessions": session_statuses(member, tokens),
        "success_audits": detection_store.count_audit_log(
            action="password_change" if self_change else "password_reset",
            target_id="revocation-target",
        ),
    }
    assert observed == {
        "status": 500,
        "old_password_valid": True,
        "new_password_valid": False,
        "sessions": [200, 200],
        "success_audits": 0,
    }
    assert persisted_account(detection_store, tokens) == {
        "enabled": True,
        "old_password_valid": True,
        "new_password_valid": False,
        "sessions": [True, True],
    }
    allow_session_deletion(detection_store)
    response = admin.post(
        "/api/admin/users/revocation-target/reset-password",
        json={"new_password": NEW_PASSWORD},
    )
    assert response.status_code == 200
    assert session_statuses(member, tokens) == [401, 401]
    assert detection_store.verify_password("revocation-target", NEW_PASSWORD)
    assert persisted_account(detection_store, tokens) == {
        "enabled": True,
        "old_password_valid": False,
        "new_password_valid": True,
        "sessions": [False, False],
    }


@pytest.mark.parametrize("self_change", [False, True])
@pytest.mark.parametrize("same_password", [False, True])
def test_successful_password_changes_revoke_and_persist(
    account_clients, detection_store, self_change, same_password
):
    admin, member, tokens = account_clients
    password = OLD_PASSWORD if same_password else NEW_PASSWORD
    if self_change:
        response = member.post(
            "/api/auth/change-password",
            json={"current_password": OLD_PASSWORD, "new_password": password},
            headers={"Authorization": f"Bearer {tokens[0]}"},
        )
    else:
        response = admin.post(
            "/api/admin/users/revocation-target/reset-password",
            json={"new_password": password},
        )
    assert response.status_code == 200
    assert session_statuses(member, tokens) == [401, 401]
    persisted = persisted_account(detection_store, tokens)
    assert persisted["sessions"] == [False, False]
    assert persisted["old_password_valid"] is same_password
    assert persisted["new_password_valid"] is not same_password
    assert (
        detection_store.count_audit_log(
            action="password_change" if self_change else "password_reset",
            target_id="revocation-target",
        )
        == 1
    )
    if self_change:
        replacement = response.json()["session_token"]
        assert session_statuses(member, [replacement]) == [200]
        assert persisted_account(detection_store, [replacement])["sessions"] == [True]


@pytest.mark.parametrize("operation", ["update", "disable", "reset"])
def test_missing_user_does_not_mutate_other_sessions(
    account_clients, detection_store, operation
):
    admin, member, tokens = account_clients
    reject_session_deletion(detection_store)
    if operation == "update":
        response = admin.put("/api/admin/users/missing", json={"enabled": False})
    elif operation == "disable":
        response = admin.delete("/api/admin/users/missing")
    else:
        response = admin.post(
            "/api/admin/users/missing/reset-password",
            json={"new_password": NEW_PASSWORD},
        )
    assert response.status_code == 404
    assert session_statuses(member, tokens) == [200, 200]
    assert detection_store.count_audit_log(target_id="missing") == 0


def test_password_changed_with_failed_replacement_requires_fresh_sign_in(
    account_clients, detection_store
):
    admin, member, tokens = account_clients
    with detection_store._ctx.write_transaction() as conn:
        conn.execute(
            """CREATE TRIGGER fail_session_reissue BEFORE INSERT ON sessions
            BEGIN SELECT RAISE(ABORT, 'injected replacement failure'); END"""
        )
    response = member.post(
        "/api/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers={"Authorization": f"Bearer {tokens[0]}"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "status": "password_changed",
        "reauthentication_required": True,
    }
    assert session_statuses(member, tokens) == [401, 401]

    assert persisted_account(detection_store, tokens) == {
        "enabled": True,
        "old_password_valid": False,
        "new_password_valid": True,
        "sessions": [False, False],
    }
    assert (
        detection_store.count_audit_log(
            action="password_change", target_id="revocation-target"
        )
        == 1
    )
    with detection_store._ctx.write_transaction() as conn:
        conn.execute("DROP TRIGGER fail_session_reissue")
    login = member.post(
        "/api/auth/login",
        json={"username": "revocation-target", "password": NEW_PASSWORD},
    )
    assert login.status_code == 200
    assert session_statuses(member, [login.json()["session_token"]]) == [200]
    assert session_statuses(member, tokens) == [401, 401]


def test_unapplied_password_update_does_not_report_success(
    account_clients, detection_store
):
    admin, member, tokens = account_clients
    with detection_store._ctx.write_transaction() as conn:
        conn.execute(
            """CREATE TRIGGER ignore_password_update BEFORE UPDATE OF password_hash
            ON users BEGIN SELECT RAISE(IGNORE); END"""
        )
    response = member.post(
        "/api/auth/change-password",
        json={"current_password": OLD_PASSWORD, "new_password": NEW_PASSWORD},
        headers={"Authorization": f"Bearer {tokens[0]}"},
    )
    assert response.status_code == 404
    assert persisted_account(detection_store, tokens) == {
        "enabled": True,
        "old_password_valid": True,
        "new_password_valid": False,
        "sessions": [True, True],
    }
    assert (
        detection_store.count_audit_log(
            action="password_change", target_id="revocation-target"
        )
        == 0
    )
