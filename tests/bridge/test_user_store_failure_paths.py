"""Persisted account/session failure paths using the real SQLite store.

Legacy and damaged records are written as database fixtures, not returned by a
mock. All behavior under test enters through UserStore's public methods.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import sqlite3

from cryptography.fernet import Fernet
import pytest

from sigrift.bridge.storage import encryption
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage import users as users_module
from sigrift.bridge.storage.users import UserStore


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("BRIDGE_ENV", "production")
    monkeypatch.delenv("BRIDGE_MODE", raising=False)
    monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY_FILE", raising=False)
    monkeypatch.delenv("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", raising=False)
    monkeypatch.delenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", raising=False)
    monkeypatch.setattr(users_module, "_fernet_instance", None)
    encryption.reset_cached_key()
    context = SharedContext(tmp_path / "users.db")
    yield context
    context.get_conn().execute("PRAGMA query_only=OFF")
    context.close()
    encryption.reset_cached_key()


@pytest.fixture
def users(ctx):
    store = UserStore(ctx)
    store.create_user("alice", "A real test password 42!", role="admin")
    return store


def user_id(users):
    return users.get_user("alice")["id"]


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def persist(ctx, statement, values=()):
    with ctx.write_transaction() as conn:
        conn.execute(statement, values)


def secret_rows(ctx):
    return [
        tuple(row)
        for row in ctx.get_conn().execute(
            "SELECT id, totp_secret FROM users ORDER BY id"
        )
    ]


def test_user_updates_and_missing_users_keep_identity_and_credentials(users):
    before = users.get_user_full("alice")
    assert users.update_user("alice") == users.get_user("alice")
    changed = users.update_user(
        "alice",
        role="analyst",
        display_name="Alice Operator",
        email="alice@example.invalid",
    )
    assert changed["id"] == before["id"]
    assert changed["role"] == "analyst"
    assert changed["display_name"] == "Alice Operator"
    assert changed["email"] == "alice@example.invalid"
    assert users.get_user_full("alice")["password_hash"] == before["password_hash"]
    assert users.verify_password("alice", "A real test password 42!")
    assert users.update_user("missing", display_name="Not an account") is None
    assert users.get_user_full("missing") is None
    assert users.disable_user("missing") is False
    with pytest.raises(ValueError, match="Invalid role"):
        users.update_user("alice", role="owner")
    assert users.get_user("alice")["role"] == "analyst"


def test_session_creation_rolls_back_if_last_login_write_fails(ctx, users):
    persist(
        ctx,
        """CREATE TRIGGER reject_login_write BEFORE UPDATE OF last_login
        ON users BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""",
    )
    with pytest.raises(sqlite3.IntegrityError, match="storage failure"):
        users.create_session(user_id(users))
    assert ctx.get_conn().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert users.get_user("alice")["last_login"] is None
    assert not ctx.get_conn().in_transaction
    persist(ctx, "DROP TRIGGER reject_login_write")
    session = users.create_session(user_id(users))
    assert users.get_session(session["session_token"])["username"] == "alice"


def test_read_only_activity_update_keeps_existing_session_bounded(ctx, users):
    session = users.create_session(user_id(users))
    raw = session["session_token"]
    old = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    persist(
        ctx,
        "UPDATE sessions SET last_active = ? WHERE session_token = ?",
        (old, token_hash(raw)),
    )
    ctx.get_conn().execute("PRAGMA query_only=ON")
    found = users.get_session(raw)
    assert found["username"] == "alice"
    assert found["last_active"] == old
    assert (
        ctx.get_conn().execute("SELECT last_active FROM sessions").fetchone()[0] == old
    )
    assert not ctx.get_conn().in_transaction
    ctx.get_conn().execute("PRAGMA query_only=OFF")
    assert users.get_session(raw)["expires_at"] == session["expires_at"]
    assert (
        ctx.get_conn().execute("SELECT last_active FROM sessions").fetchone()[0] > old
    )


def test_raw_disable_retains_session_but_blocks_it_until_reenabled(users):
    raw = users.create_session(user_id(users))["session_token"]
    assert users.disable_user("alice")
    assert users.get_session(raw) is None
    assert users.update_user("alice", enabled=True)["enabled"]
    assert users.get_session(raw)["username"] == "alice"


@pytest.mark.parametrize("expired", [False, True])
def test_naive_legacy_session_timestamps_are_utc_and_expired_rows_are_deleted(
    ctx, users, expired
):
    raw = users.create_session(user_id(users))["session_token"]
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    expiry = now + timedelta(hours=-1 if expired else 1)
    persist(
        ctx,
        "UPDATE sessions SET expires_at = ?, last_active = ? WHERE session_token = ?",
        (expiry.isoformat(), now.isoformat(), token_hash(raw)),
    )
    found = users.get_session(raw)
    if expired:
        assert found is None
        assert users.delete_session(raw) is False
    else:
        assert found["username"] == "alice"
        assert users.delete_session(raw) is True


def test_legacy_idle_timeout_deletes_session_before_activity_touch(ctx, users):
    raw = users.create_session(user_id(users))["session_token"]
    idle = (
        (datetime.now(timezone.utc) - timedelta(hours=1))
        .replace(tzinfo=None)
        .isoformat()
    )
    persist(
        ctx,
        "UPDATE sessions SET last_active = ? WHERE session_token = ?",
        (idle, token_hash(raw)),
    )
    assert users.get_session(raw) is None
    assert users.delete_session(raw) is False


def test_damaged_absolute_expiration_never_authenticates(ctx, users):
    raw = users.create_session(user_id(users))["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
        ("damaged", token_hash(raw)),
    )
    # The read-only check refuses and keeps the row. A request refuses and
    # deletes it, as the gateway does: the periodic cleanup compares strings
    # and would never remove 'damaged'.
    assert users.get_session(raw, touch=False) is None
    assert users.get_session(raw) is None
    assert users.delete_session(raw) is False


def test_scope_migrates_legacy_table_and_read_only_failure_does_not_change_scope(
    ctx, users, caplog
):
    # Fresh/pre-scope tables acquire this column on the first restricted login.
    assert "scope" not in {
        row[1] for row in ctx.get_conn().execute("PRAGMA table_info(sessions)")
    }
    raw = users.create_session(user_id(users))["session_token"]
    users.set_session_scope(raw, "mfa_setup_only")
    assert users.get_session(raw)["scope"] == "mfa_setup_only"
    ctx.get_conn().execute("PRAGMA query_only=ON")
    users.set_session_scope(raw, "change_password_only")
    assert users.get_session(raw)["scope"] == "mfa_setup_only"
    assert "Failed to set session scope" in caplog.text
    assert raw not in caplog.text
    assert not ctx.get_conn().in_transaction


def test_mfa_token_cleanup_removes_only_expired_password_proofs(ctx, users):
    uid = user_id(users)
    expired = [users.create_mfa_token(uid, expires_minutes=-2) for _ in range(2)]
    live = users.create_mfa_token(uid, expires_minutes=5)
    assert users.cleanup_expired_mfa_tokens() == 2
    assert users.cleanup_expired_mfa_tokens() == 0
    assert all(users.verify_mfa_token(token) is None for token in expired)
    assert users.verify_mfa_token(live) == uid
    assert users.verify_mfa_token(live) is None
    assert ctx.get_conn().execute("SELECT COUNT(*) FROM mfa_tokens").fetchone()[0] == 0


def test_unsalted_legacy_recovery_codes_remain_single_use(ctx, users):
    uid = user_id(users)
    first, second = "legacy-0001", "legacy-0002"
    for code in (first, second):
        # This is the documented persisted format from before salted PBKDF2
        # recovery codes. Exercise the actual legacy hash verifier.
        persist(
            ctx,
            "INSERT INTO mfa_backup_codes "
            "(user_id, code_hash, salt, used, created_at) VALUES (?, ?, NULL, 0, ?)",
            (
                uid,
                hashlib.sha256(code.encode()).hexdigest(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
    assert users.verify_backup_code(uid, "wrong-code") is False
    assert users.get_backup_code_count(uid) == 2
    assert users.verify_backup_code(uid, first) is True
    assert users.verify_backup_code(uid, first) is False
    assert users.get_backup_code_count(uid) == 1
    assert users.verify_backup_code(uid, second) is True
    assert users.get_backup_code_count(uid) == 0


@pytest.mark.parametrize("accepted", [True, False])
def test_legacy_or_damaged_mfa_expiration_fails_closed_and_preserves_single_use(
    ctx, users, accepted
):
    uid = user_id(users)
    raw = users.create_mfa_token(uid)
    timestamp = (
        (datetime.now(timezone.utc) + timedelta(hours=1))
        .replace(tzinfo=None)
        .isoformat()
        if accepted
        else "damaged"
    )
    persist(
        ctx,
        "UPDATE mfa_tokens SET expires_at = ? WHERE token = ?",
        (timestamp, token_hash(raw)),
    )
    assert users.verify_mfa_token(raw) == (uid if accepted else None)
    assert users.verify_mfa_token(raw) is None
    assert not ctx.get_conn().in_transaction


def test_corrupted_encrypted_totp_secret_is_not_returned_as_plaintext(
    ctx, users, caplog
):
    uid = user_id(users)
    users.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
    users.enable_mfa(uid)
    encrypted = secret_rows(ctx)[0][1]
    persist(
        ctx,
        "UPDATE users SET totp_secret = ? WHERE id = ?",
        (encrypted[:-4] + "xxxx", uid),
    )
    for user in (users.get_user_full("alice"), users.get_user_by_id(uid)):
        assert user["totp_secret"] is None
        assert user["mfa_enabled"] == 1
    assert users.get_user_by_id(uid + 10000) is None
    assert "Failed to decrypt TOTP secret" in caplog.text
    assert "JBSWY3DPEHPK3PXP" not in caplog.text
    assert encrypted not in caplog.text


@pytest.mark.parametrize("valid_legacy", [False, True])
def test_legacy_totp_migration_preserves_undecodable_rows_and_encrypts_valid_ones(
    ctx, users, valid_legacy, caplog
):
    uid = user_id(users)
    # Invalid UTF-8 in an old b64 record is recoverable corruption; it must
    # remain untouched for recovery and must not abort other users' migration.
    persist(ctx, "UPDATE users SET totp_secret = 'b64:/w==' WHERE id = ?", (uid,))
    if valid_legacy:
        users.create_user("bob", "Another real password 43!")
        bob_id = users.get_user("bob")["id"]
        encoded = "b64:" + base64.b64encode(b"JBSWY3DPEHPK3PXP").decode()
        persist(ctx, "UPDATE users SET totp_secret = ? WHERE id = ?", (encoded, bob_id))
    assert users.reencrypt_legacy_totp_secrets() == int(valid_legacy)
    rows = secret_rows(ctx)
    assert rows[0] == (uid, "b64:/w==")
    if valid_legacy:
        assert rows[1][1].startswith("fernet:")
        assert users.get_user_by_id(bob_id)["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert users.reencrypt_legacy_totp_secrets() == 0
    assert "not decodable" in caplog.text


def test_startup_totp_migration_failure_keeps_original_secret_and_retries(
    ctx, users, caplog
):
    uid = user_id(users)
    legacy = "b64:" + base64.b64encode(b"JBSWY3DPEHPK3PXP").decode()
    persist(ctx, "UPDATE users SET totp_secret = ? WHERE id = ?", (legacy, uid))
    ctx.get_conn().execute("PRAGMA query_only=ON")
    restarted = UserStore(ctx)
    assert secret_rows(ctx) == [(uid, legacy)]
    assert restarted.get_user_full("alice")["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert "Could not encrypt base64-stored TOTP secrets" in caplog.text
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        restarted.reencrypt_legacy_totp_secrets()
    assert not ctx.get_conn().in_transaction
    ctx.get_conn().execute("PRAGMA query_only=OFF")
    assert restarted.reencrypt_legacy_totp_secrets() == 1
    assert secret_rows(ctx)[0][1].startswith("fernet:")
    assert restarted.get_user_full("alice")["totp_secret"] == "JBSWY3DPEHPK3PXP"
