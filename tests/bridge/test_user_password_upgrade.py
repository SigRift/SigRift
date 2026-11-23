"""Real password verification must preserve current credentials and racing writes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3
import threading

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage import users as users_module
from sigrift.bridge.storage.users import UserStore
from sigrift.lib.security.credentials import hash_credential

PASSWORD = "Synthetic initial password 42!"
REPLACEMENT = "Synthetic replacement password 73!"


@pytest.fixture
def account(tmp_path, monkeypatch):
    monkeypatch.delenv("BRIDGE_MFA_KEY", raising=False)
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("BRIDGE_DB_ENCRYPTION_KEY_FILE", raising=False)
    ctx = SharedContext(tmp_path / "users.db")
    store = UserStore(ctx)
    store.create_user("operator", PASSWORD, role="admin")
    try:
        yield ctx, store
    finally:
        ctx.close()


def rows(ctx):
    return [
        tuple(row) for row in ctx.get_conn().execute("SELECT * FROM users ORDER BY id")
    ]


def unchanged(ctx, before):
    if rows(ctx) != before:
        pytest.fail("Stored account bytes changed unexpectedly", pytrace=False)


def make_legacy(ctx):
    salt = b"synthetic-legacy-salt"
    legacy = hashlib.sha256(salt + PASSWORD.encode()).hexdigest()
    with ctx.write_transaction() as conn:
        conn.execute(
            "UPDATE users SET password_hash=?,salt=? WHERE username='operator'",
            (legacy, salt),
        )
    return legacy, salt


def test_current_pbkdf2_verification_preserves_exact_account_and_reopens(account):
    ctx, store = account
    before = rows(ctx)
    assert len(store.get_user_full("operator")["password_hash"]) == 64
    assert store.verify_password("operator", PASSWORD) is True
    assert store.verify_password("operator", PASSWORD) is True
    unchanged(ctx, before)
    reopened = SharedContext(ctx._db_path)
    try:
        assert UserStore(reopened).verify_password("operator", PASSWORD) is True
        unchanged(reopened, before)
    finally:
        reopened.close()


def test_real_legacy_upgrade_happens_once_and_preserves_other_fields(account):
    ctx, store = account
    old_hash, old_salt = make_legacy(ctx)
    original = store.get_user_full("operator")
    assert store.verify_password("operator", PASSWORD) is True
    upgraded = store.get_user_full("operator")
    assert upgraded["password_hash"] != old_hash and upgraded["salt"] != old_salt
    assert len(upgraded["salt"]) == 32
    calculated = hashlib.pbkdf2_hmac(
        "sha256", PASSWORD.encode(), upgraded["salt"], 600_000, dklen=32
    ).hex()
    assert calculated == upgraded["password_hash"]
    assert {
        k: v for k, v in original.items() if k not in {"password_hash", "salt"}
    } == {k: v for k, v in upgraded.items() if k not in {"password_hash", "salt"}}
    before = rows(ctx)
    assert store.verify_password("operator", PASSWORD) is True
    unchanged(ctx, before)


@pytest.mark.parametrize("legacy", [False, True], ids=["pbkdf2", "legacy"])
@pytest.mark.parametrize("case", ["wrong", "disabled", "missing"])
def test_refused_passwords_do_not_write(account, legacy, case):
    ctx, store = account
    if legacy:
        make_legacy(ctx)
    if case == "disabled":
        store.disable_user("operator")
    before = rows(ctx)
    assert (
        store.verify_password(
            "missing" if case == "missing" else "operator",
            REPLACEMENT if case == "wrong" else PASSWORD,
        )
        is False
    )
    unchanged(ctx, before)


@pytest.mark.parametrize("legacy", [False, True], ids=["pbkdf2", "legacy"])
@pytest.mark.parametrize(
    "change", ["reset", "disable", "delete", "tenant", "role", "mfa", "must_change"]
)
def test_password_verification_refuses_changed_account_without_overwriting(
    account, monkeypatch, legacy, change
):
    ctx, store = account
    if legacy:
        make_legacy(ctx)
    replacement_hash, replacement_salt = hash_credential(REPLACEMENT)
    verified, resume = threading.Event(), threading.Event()
    real_verify = users_module.verify_credential

    def gated_verify(*args):
        result = real_verify(*args)
        verified.set()
        if not resume.wait(10):
            raise RuntimeError("Password verification barrier timed out")
        return result

    monkeypatch.setattr(users_module, "verify_credential", gated_verify)
    with ThreadPoolExecutor(max_workers=1) as pool:
        attempt = pool.submit(store.verify_password, "operator", PASSWORD)
        try:
            assert verified.wait(10), "Real credential verification did not complete"
            with sqlite3.connect(ctx._db_path) as writer:
                if change == "reset":
                    writer.execute(
                        "UPDATE users SET password_hash=?,salt=? WHERE username='operator'",
                        (replacement_hash, replacement_salt),
                    )
                elif change == "delete":
                    writer.execute("DELETE FROM users WHERE username='operator'")
                else:
                    column, value = {
                        "disable": ("enabled", 0),
                        "tenant": ("tenant_id", "another-instance"),
                        "role": ("role", "viewer"),
                        "mfa": ("mfa_enabled", 1),
                        "must_change": ("must_change_password", 1),
                    }[change]
                    writer.execute(
                        f"UPDATE users SET {column}=? WHERE username='operator'",
                        (value,),
                    )
            committed = rows(ctx)
            resume.set()
            assert attempt.result(timeout=10) is False, (
                "An obsolete verified account must not authenticate"
            )
            unchanged(ctx, committed)
        finally:
            resume.set()


def test_unsupported_text_salt_does_not_mutate_account(account):
    ctx, store = account
    with ctx.write_transaction() as conn:
        conn.execute(
            "UPDATE users SET salt=? WHERE username='operator'",
            ("unsupported-text-salt",),
        )
    before = rows(ctx)
    with pytest.raises(TypeError):
        store.verify_password("operator", PASSWORD)
    unchanged(ctx, before)


def test_current_password_can_be_verified_on_read_only_connection(account):
    ctx, store = account
    before = rows(ctx)
    ctx.get_conn().execute("PRAGMA query_only=ON")
    try:
        assert store.verify_password("operator", PASSWORD) is True
    finally:
        ctx.get_conn().execute("PRAGMA query_only=OFF")
    unchanged(ctx, before)


@pytest.mark.parametrize("legacy", [False, True], ids=["pbkdf2", "legacy"])
def test_older_account_schema_without_lazy_password_change_flag(account, legacy):
    ctx, store = account
    if legacy:
        make_legacy(ctx)
    with ctx.write_transaction() as conn:
        conn.execute("ALTER TABLE users DROP COLUMN must_change_password")
    assert store.verify_password("operator", PASSWORD) is True
    before = rows(ctx)
    assert store.verify_password("operator", PASSWORD) is True
    unchanged(ctx, before)


def test_concurrent_reset_during_real_legacy_rehash_is_never_overwritten(
    account, monkeypatch
):
    ctx, store = account
    make_legacy(ctx)
    replacement_hash, replacement_salt = hash_credential(REPLACEMENT)
    rehashed, resume = threading.Event(), threading.Event()
    real_hash = users_module.hash_credential

    def gated_hash(*args, **kwargs):
        value = real_hash(*args, **kwargs)
        rehashed.set()
        if not resume.wait(10):
            raise RuntimeError("Legacy upgrade barrier timed out")
        return value

    monkeypatch.setattr(users_module, "hash_credential", gated_hash)
    with ThreadPoolExecutor(max_workers=1) as pool:
        attempt = pool.submit(store.verify_password, "operator", PASSWORD)
        try:
            assert rehashed.wait(10), "Real legacy rehash did not complete"
            with sqlite3.connect(ctx._db_path) as writer:
                writer.execute(
                    "UPDATE users SET password_hash=?,salt=? WHERE username='operator'",
                    (replacement_hash, replacement_salt),
                )
            reset = rows(ctx)
            resume.set()
            outcome = attempt.result(timeout=10)
            unchanged(ctx, reset)
            assert outcome is False
        finally:
            resume.set()
    monkeypatch.setattr(users_module, "hash_credential", real_hash)
    assert store.verify_password("operator", PASSWORD) is False
    assert store.verify_password("operator", REPLACEMENT) is True
    unchanged(ctx, reset)


def test_failed_legacy_write_rolls_back_and_can_retry(account):
    ctx, store = account
    make_legacy(ctx)
    with ctx.write_transaction() as conn:
        conn.execute(
            "CREATE TRIGGER refuse_upgrade BEFORE UPDATE OF password_hash ON users BEGIN SELECT RAISE(ABORT, 'synthetic upgrade failure'); END"
        )
    before = rows(ctx)
    with pytest.raises(sqlite3.IntegrityError, match="synthetic upgrade failure"):
        store.verify_password("operator", PASSWORD)
    unchanged(ctx, before)
    assert not ctx.get_conn().in_transaction
    with ctx.write_transaction() as conn:
        conn.execute("DROP TRIGGER refuse_upgrade")
    assert store.verify_password("operator", PASSWORD) is True
    stable = rows(ctx)
    assert store.verify_password("operator", PASSWORD) is True
    unchanged(ctx, stable)


def test_two_real_legacy_verifications_commit_only_one_upgrade(account, monkeypatch):
    ctx, store = account
    make_legacy(ctx)
    barrier = threading.Barrier(2)
    real_hash = users_module.hash_credential

    def simultaneous_hash(*args, **kwargs):
        value = real_hash(*args, **kwargs)
        barrier.wait(timeout=10)
        return value

    monkeypatch.setattr(users_module, "hash_credential", simultaneous_hash)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(store.verify_password, "operator", PASSWORD) for _ in range(2)
        ]
        assert sorted(task.result(timeout=15) for task in futures) == [False, True]
    monkeypatch.setattr(users_module, "hash_credential", real_hash)
    stable = rows(ctx)
    assert store.verify_password("operator", PASSWORD) is True
    unchanged(ctx, stable)


def test_foreign_store_cannot_verify_or_upgrade_local_account(account):
    ctx, _store = account
    make_legacy(ctx)
    before = rows(ctx)
    foreign = SharedContext(ctx._db_path, tenant_id="other-instance")
    try:
        assert UserStore(foreign).verify_password("operator", PASSWORD) is False
        unchanged(ctx, before)
    finally:
        foreign.close()


@pytest.mark.parametrize("legacy", [False, True], ids=["pbkdf2", "legacy"])
def test_concurrent_display_change_survives_successful_verification(
    account, monkeypatch, legacy
):
    ctx, store = account
    if legacy:
        make_legacy(ctx)
    real_verify = users_module.verify_credential

    def update_display_after_verify(*args):
        matched = real_verify(*args)
        with sqlite3.connect(ctx._db_path) as writer:
            writer.execute(
                "UPDATE users SET display_name='Updated display',email='updated@example.invalid' WHERE username='operator'"
            )
        return matched

    monkeypatch.setattr(users_module, "verify_credential", update_display_after_verify)
    assert store.verify_password("operator", PASSWORD) is True
    current = store.get_user("operator")
    assert current["display_name"] == "Updated display"
    assert current["email"] == "updated@example.invalid"
