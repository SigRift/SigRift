"""Guards of the DB-backed auth state, against a real SQLite file.

* An MFA password proof is accepted only by the call that removed it: if
  the row survives the DELETE (another claimer, a gateway process, a
  trigger), the claim is refused, so a proof is never usable twice.
* The OIDC state table is capped: cleanup evicts the oldest states of the
  tenant beyond ``OIDC_MAX_STATES`` (an unauthenticated /login flood cannot
  grow it without bound), keeps the newest ones usable, and never evicts or
  counts another tenant's states.
* Re-encrypting a base64-stored TOTP secret (once ``BRIDGE_MFA_KEY`` is
  set) never overwrites what another worker wrote meanwhile: a secret the
  user re-enrolled, or MFA an admin reset because the old secret leaked,
  is not replaced by the old secret.
"""

from __future__ import annotations

import logging
import types

from cryptography.fernet import Fernet
import pytest

from sigrift.bridge.storage import security_state as security_state_module
from sigrift.bridge.storage import users as users_module
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.security_state import SecurityStateStore
from sigrift.bridge.storage.users import UserStore
from sigrift.lib.security import credentials

PASSWORD = "Correct horse battery staple 42!"


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch):
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "auth.db"


@pytest.fixture
def ctx(db_path):
    context = SharedContext(db_path)
    yield context
    context.close()


def _token_rows(ctx):
    return ctx.get_conn().execute("SELECT COUNT(*) FROM mfa_tokens").fetchone()[0]


def test_an_mfa_proof_that_was_not_removed_is_never_accepted(ctx):
    store = UserStore(ctx)
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    token = store.create_mfa_token(uid)

    # The DELETE that consumes the proof removes nothing (as when another
    # claimer got there first): the proof must not be accepted.
    with ctx.write_transaction() as conn:
        conn.execute(
            "CREATE TRIGGER keep_mfa_tokens BEFORE DELETE ON mfa_tokens "
            "BEGIN SELECT RAISE(IGNORE); END"
        )
    assert store.claim_mfa_token(token) is None
    assert store.verify_mfa_token(token) is None
    assert _token_rows(ctx) == 1
    assert not ctx.get_conn().in_transaction

    with ctx.write_transaction() as conn:
        conn.execute("DROP TRIGGER keep_mfa_tokens")
    claimed = store.claim_mfa_token(token)
    assert claimed is not None and claimed.user_id == uid
    stored_hash = (
        ctx.get_conn()
        .execute("SELECT password_hash FROM users WHERE id = ?", [uid])
        .fetchone()[0]
    )
    assert claimed.password_hash == stored_hash
    assert _token_rows(ctx) == 0
    assert store.claim_mfa_token(token) is None  # used once only


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 10_000.0}
    monkeypatch.setattr(
        security_state_module, "time", types.SimpleNamespace(time=lambda: now["t"])
    )
    return now


def test_oidc_state_cap_evicts_only_the_oldest_states_of_the_tenant(
    db_path, ctx, clock, monkeypatch
):
    monkeypatch.setattr(SecurityStateStore, "OIDC_MAX_STATES", 3)
    other_ctx = SharedContext(db_path, tenant_id="tenant-b")
    try:
        mine = SecurityStateStore(ctx)
        theirs = SecurityStateStore(other_ctx)
        # The other tenant's states are the oldest in the table.
        for i in range(2):
            clock["t"] = 9_000.0 + i
            theirs.create_oidc_state(f"b-{i}", nonce=f"nb-{i}")
        for i in range(5):
            clock["t"] = 9_100.0 + i
            mine.create_oidc_state(f"a-{i}", nonce=f"na-{i}", redirect_to=f"/p{i}")
        clock["t"] = 9_200.0  # none is past OIDC_STATE_MAX_AGE

        assert mine.cleanup_oidc_states() == 2
        assert mine.cleanup_oidc_states() == 0  # at the cap now

        assert [mine.consume_oidc_state(f"a-{i}") for i in range(2)] == [None, None]
        for i in range(2, 5):
            state = mine.consume_oidc_state(f"a-{i}")
            assert state is not None
            assert (state["nonce"], state["redirect_to"]) == (f"na-{i}", f"/p{i}")
        for i in range(2):
            state = theirs.consume_oidc_state(f"b-{i}")
            assert state is not None and state["nonce"] == f"nb-{i}"
    finally:
        other_ctx.close()


OLD_TOTP = "JBSWY3DPEHPK3PXP"
NEW_TOTP = "KRSXG5CTMVRXEZLU"


@pytest.mark.parametrize("change", ["re-enrolled", "mfa-reset"])
def test_totp_re_encryption_never_overwrites_another_workers_change(
    db_path, ctx, monkeypatch, caplog, change
):
    for name in ("BRIDGE_ENV", "BRIDGE_MODE", "BRIDGE_MFA_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(users_module, "_fernet_instance", None)
    monkeypatch.setattr(users_module, "_mfa_encryption_warned", False)
    mine = UserStore(ctx)
    mine.create_user("alice", PASSWORD)
    uid = mine.get_user("alice")["id"]
    mine.set_totp_secret(uid, OLD_TOTP)  # no key yet: stored as b64:
    other_ctx = SharedContext(db_path)
    try:
        theirs = UserStore(other_ctx)  # another worker of the same release
        monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
        monkeypatch.setattr(users_module, "_fernet_instance", None)

        # The other worker's change lands after this worker read the old
        # secret and before it writes the encrypted one.
        real_encrypt = users_module._encrypt_totp_secret
        raced = []

        def encrypt_after_the_other_worker_wrote(plaintext):
            if not raced:
                raced.append(plaintext)
                if change == "re-enrolled":
                    theirs.set_totp_secret(uid, NEW_TOTP)
                else:
                    theirs.disable_mfa(uid)
            return real_encrypt(plaintext)

        monkeypatch.setattr(
            users_module, "_encrypt_totp_secret", encrypt_after_the_other_worker_wrote
        )
        with caplog.at_level(logging.WARNING):
            assert mine.reencrypt_legacy_totp_secrets() == 0
        assert raced == [OLD_TOTP]
        assert "Encrypted" not in caplog.text

        expected = NEW_TOTP if change == "re-enrolled" else None
        assert mine.get_user_by_id(uid)["totp_secret"] == expected
        assert theirs.get_user_by_id(uid)["totp_secret"] == expected
    finally:
        other_ctx.close()
