"""Security paths of the user/session sub-store, against a real SQLite file.

Covers what the existing user-store suites leave out: hostile input in every
account field, role whitelisting on create/update (no partial writes),
uniqueness across tenants, misconfigured session timeouts, legacy/damaged
session rows, expired MFA proofs, TOTP-secret handling without a usable
``BRIDGE_MFA_KEY``, backup-code replacement and tenant scoping of the
password-change flag and the MFA requirement, and the lazy
``must_change_password`` column step (retried after a failure at most once
per interval, not cached while the users table is missing, no write lock
once the column exists).  Assertions read the persisted rows back, not
only return values.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import logging
import sqlite3
import sys

from cryptography.fernet import Fernet
import pytest

from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import hash_credential
from sigrift.bridge.storage import encryption
from sigrift.bridge.storage import users as users_module
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.users import UserStore

PASSWORD = "Correct horse battery staple 42!"


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch):
    # The storage logic under test does not depend on the work factor; the
    # production 600k iterations would make each create/verify take ~0.5 s.
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in (
        "BRIDGE_ENV",
        "BRIDGE_MODE",
        "BRIDGE_MFA_KEY",
        "BRIDGE_DB_ENCRYPTION_KEY",
        "BRIDGE_DB_ENCRYPTION_KEY_FILE",
        "BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES",
        "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(users_module, "_fernet_instance", None)
    monkeypatch.setattr(users_module, "_mfa_encryption_warned", False)
    monkeypatch.setattr(users_module, "_mfa_invalid_key_warned", False)
    encryption.reset_cached_key()
    yield
    encryption.reset_cached_key()


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "users.db"


@pytest.fixture
def ctx(db_path):
    context = SharedContext(db_path)
    yield context
    context.get_conn().execute("PRAGMA query_only=OFF")
    context.close()


@pytest.fixture
def other_ctx(db_path, ctx):
    """A second tenant on the same database file."""
    context = SharedContext(db_path, tenant_id="tenant-b")
    yield context
    context.close()


@pytest.fixture
def store(ctx):
    return UserStore(ctx)


def persist(ctx, statement, values=()):
    with ctx.write_transaction() as conn:
        conn.execute(statement, values)


def user_rows(ctx):
    return [
        dict(row)
        for row in ctx.get_conn().execute(
            "SELECT username, role, display_name, email, enabled, password_hash, "
            "salt, tenant_id FROM users ORDER BY id"
        )
    ]


def session_row(ctx, raw_token):
    return (
        ctx.get_conn()
        .execute(
            "SELECT * FROM sessions WHERE session_token = ?",
            [hashlib.sha256(raw_token.encode()).hexdigest()],
        )
        .fetchone()
    )


def iso(delta):
    return (datetime.now(timezone.utc) + delta).isoformat()


# ---------------------------------------------------------------------------
# Hostile input reaches SQL only as bound parameters
# ---------------------------------------------------------------------------

HOSTILE_VALUES = [
    "o'brien",
    "x' OR '1'='1",
    "admin'; DROP TABLE users; --",
    'say "hi"',
    "back\\slash",
    "%_wild*cards_%",
    "名前-Ωμέγα-🙂",
    "nul\x00byte",
    "a" * 5_000,
]


@pytest.mark.parametrize("value", HOSTILE_VALUES, ids=range(len(HOSTILE_VALUES)))
def test_hostile_account_fields_round_trip_byte_for_byte(ctx, store, value):
    created = store.create_user(value, PASSWORD, display_name=value, email=value)
    assert created["username"] == value

    fetched = store.get_user(value)
    assert fetched is not None
    assert (fetched["username"], fetched["display_name"], fetched["email"]) == (
        value,
        value,
        value,
    )
    assert store.verify_password(value, PASSWORD) is True
    assert store.verify_password(value, PASSWORD + "x") is False

    updated = store.update_user(value, display_name=value[::-1], email=value * 2)
    assert updated["display_name"] == value[::-1]
    assert updated["email"] == value * 2

    # Exactly one row, the users table survived, and nothing else changed.
    rows = user_rows(ctx)
    assert [r["username"] for r in rows] == [value]
    assert rows[0]["role"] == "viewer"
    assert store.user_count() == 1


@pytest.mark.parametrize(
    "probe",
    [
        "' OR '1'='1",
        "alice' --",
        "alice'; --",
        "%",
        "_lice",
        "ali%",
        "ALICE",
        "Alice",
        "alice ",
        " alice",
        "alice\x00",
    ],
)
def test_lookup_probes_never_match_another_account(ctx, store, probe):
    store.create_user("alice", PASSWORD, role="admin")
    session = store.create_session(store.get_user("alice")["id"])

    assert store.get_user(probe) is None
    assert store.get_user_full(probe) is None
    assert store.verify_password(probe, PASSWORD) is False
    assert store.update_user(probe, role="viewer", enabled=False) is None
    assert store.disable_user(probe) is False
    assert store.set_password(probe, "attacker-chosen", revoke_sessions=True) is False
    store.clear_must_change_password(probe)

    # alice is untouched: same role, still enabled, old password, live session.
    alice = store.get_user("alice")
    assert alice["role"] == "admin"
    assert alice["enabled"] == 1
    assert store.verify_password("alice", PASSWORD) is True
    assert store.verify_password("alice", "attacker-chosen") is False
    assert store.get_session(session["session_token"]) is not None
    assert len(user_rows(ctx)) == 1


@pytest.mark.parametrize(
    "candidate",
    [
        PASSWORD[:-1],
        PASSWORD + " ",
        " " + PASSWORD,
        PASSWORD.upper(),
        PASSWORD.swapcase(),
        "\x00" + PASSWORD,
        "",
    ],
)
def test_password_verification_requires_the_exact_password(store, candidate):
    store.create_user("alice", PASSWORD)
    assert store.verify_password("alice", candidate) is False
    assert store.verify_password("alice", PASSWORD) is True


@pytest.mark.parametrize(
    "password",
    ["pässwörd-🔐-密码", "q'uote\"d; --", "x" * 10_000, "tab\tnew\nline"],
    ids=["unicode", "sql-quotes", "very-long", "control-chars"],
)
def test_unusual_passwords_hash_and_verify(ctx, store, password):
    store.create_user("alice", password)
    row = user_rows(ctx)[0]
    assert password not in row["password_hash"]
    assert len(row["password_hash"]) == 64
    assert store.verify_password("alice", password) is True
    assert store.verify_password("alice", password[:-1]) is False

    assert store.set_password("alice", password + "2") is True
    assert store.verify_password("alice", password) is False
    assert store.verify_password("alice", password + "2") is True


def test_identical_passwords_get_distinct_salts_and_hashes(ctx, store):
    store.create_user("alice", PASSWORD)
    store.create_user("bob", PASSWORD)
    alice, bob = user_rows(ctx)
    assert alice["salt"] != bob["salt"]
    assert alice["password_hash"] != bob["password_hash"]
    assert len(alice["salt"]) == 32


# ---------------------------------------------------------------------------
# Roles: strict whitelist, no partial writes
# ---------------------------------------------------------------------------

BAD_ROLES = [
    "superadmin",
    "Admin",
    "ADMIN",
    "admin ",
    "",
    "keymaster",
    "node",
    "sensor",
    "admin' --",
]


@pytest.mark.parametrize("role", BAD_ROLES)
def test_create_refuses_roles_outside_the_whitelist(ctx, store, role):
    with pytest.raises(ValueError, match="Invalid role"):
        store.create_user("mallory", PASSWORD, role=role)
    assert user_rows(ctx) == []
    assert store.get_user("mallory") is None


@pytest.mark.parametrize("role", BAD_ROLES)
def test_update_with_invalid_role_writes_none_of_the_other_fields(ctx, store, role):
    store.create_user("alice", PASSWORD, display_name="Alice", email="a@x.invalid")
    session = store.create_session(store.get_user("alice")["id"])
    before = user_rows(ctx)

    with pytest.raises(ValueError, match="Invalid role"):
        store.update_user(
            "alice",
            role=role,
            display_name="Mallory",
            email="m@x.invalid",
            enabled=False,
            revoke_sessions=True,
        )

    assert user_rows(ctx) == before
    assert store.get_session(session["session_token"]) is not None


def test_role_changes_persist_across_reopen(db_path, ctx, store):
    store.create_user("alice", PASSWORD)
    assert store.update_user("alice", role="admin")["role"] == "admin"
    assert store.update_user("alice", role="analyst")["role"] == "analyst"
    ctx.close()

    reopened = SharedContext(db_path)
    try:
        again = UserStore(reopened)
        assert again.get_user("alice")["role"] == "analyst"
        assert again.verify_password("alice", PASSWORD) is True
    finally:
        reopened.close()


# ---------------------------------------------------------------------------
# Uniqueness / conflicts
# ---------------------------------------------------------------------------


def test_duplicate_username_keeps_the_original_account(ctx, store):
    store.create_user("alice", PASSWORD, role="admin", display_name="Original")
    before = user_rows(ctx)

    with pytest.raises(ValueError, match="already exists"):
        store.create_user("alice", "attacker password", role="viewer")

    assert user_rows(ctx) == before
    assert store.verify_password("alice", PASSWORD) is True
    assert store.verify_password("alice", "attacker password") is False
    assert not ctx.get_conn().in_transaction


def test_other_tenant_cannot_claim_see_or_change_an_account(ctx, other_ctx, store):
    store.create_user("alice", PASSWORD, role="admin")
    alice_id = store.get_user("alice")["id"]
    session = store.create_session(alice_id)
    foreign = UserStore(other_ctx)
    before = user_rows(ctx)

    # Usernames are unique across tenants: a foreign create must not take
    # over (or duplicate) the account.
    with pytest.raises(ValueError, match="already exists"):
        foreign.create_user("alice", "foreign password", role="admin")

    assert foreign.get_user("alice") is None
    assert foreign.get_user_full("alice") is None
    assert foreign.list_users() == []
    assert foreign.user_count() == 0
    assert foreign.verify_password("alice", PASSWORD) is False
    assert foreign.update_user("alice", role="viewer", enabled=False) is None
    assert foreign.disable_user("alice") is False
    assert foreign.set_password("alice", "foreign", revoke_sessions=True) is False
    assert foreign.get_session(session["session_token"]) is None
    assert foreign.delete_session(session["session_token"]) is False
    assert foreign.session_tenant(session["session_token"]) == "default"

    assert user_rows(ctx) == before
    assert store.get_session(session["session_token"])["username"] == "alice"


def test_create_user_for_explicit_tenant_is_only_visible_there(ctx, other_ctx, store):
    created = store.create_user("bob", PASSWORD, tenant_id="tenant-b")
    assert created["tenant_id"] == "tenant-b"
    assert store.get_user("bob") is None
    assert store.verify_password("bob", PASSWORD) is False
    foreign = UserStore(other_ctx)
    assert foreign.get_user("bob")["tenant_id"] == "tenant-b"
    assert foreign.verify_password("bob", PASSWORD) is True


def test_storage_failure_on_create_is_not_reported_as_duplicate(ctx, store):
    store.create_user("existing", PASSWORD)  # runs the lazy schema step
    ctx.get_conn().execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        store.create_user("alice", PASSWORD)
    assert not ctx.get_conn().in_transaction
    ctx.get_conn().execute("PRAGMA query_only=OFF")

    # The write lock was released and the failed insert left nothing behind.
    assert store.get_user("alice") is None
    store.create_user("alice", PASSWORD)
    assert store.verify_password("alice", PASSWORD) is True


class _Clock:
    """A stand-in for ``users.monotonic`` that only moves when told to."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    fake = _Clock()
    monkeypatch.setattr(users_module, "monotonic", fake)
    return fake


RETRY_SECONDS = users_module.MUST_CHANGE_COLUMN_RETRY_SECONDS


def test_transient_failure_of_lazy_schema_step_is_retried(ctx, store, clock):
    ctx.get_conn().execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError):
        store.create_user("alice", PASSWORD)
    ctx.get_conn().execute("PRAGMA query_only=OFF")

    clock.advance(RETRY_SECONDS)
    store.create_user("alice", PASSWORD)
    assert store.get_user("alice")["must_change_password"] is False


def _has_must_change_column(ctx) -> bool:
    cols = {row[1] for row in ctx.get_conn().execute("PRAGMA table_info(users)")}
    return "must_change_password" in cols


def test_lazy_schema_step_retries_after_the_database_was_locked(
    ctx, store, db_path, caplog, clock
):
    assert not _has_must_change_column(ctx)
    ctx.get_conn().execute("PRAGMA busy_timeout=100")
    blocker = sqlite3.connect(db_path, isolation_level=None)
    try:
        blocker.execute("BEGIN IMMEDIATE")
        with caplog.at_level(logging.WARNING, logger=users_module.logger.name):
            with pytest.raises(sqlite3.OperationalError, match="no such column"):
                store.get_user("alice")
        # Logged where an operator sees it, not at DEBUG.
        assert "Could not add must_change_password column" in caplog.text
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()

    clock.advance(RETRY_SECONDS)
    store.create_user("alice", PASSWORD)
    assert store.get_user("alice")["must_change_password"] is False
    assert _has_must_change_column(ctx)


def test_failed_lazy_schema_step_is_retried_at_most_once_per_interval(
    ctx, store, clock, monkeypatch, caplog
):
    # Each ALTER try can hold the process write lock for the whole
    # busy_timeout, so during an outage it runs once per interval (and logs
    # once), not on every login.  The interval starts when a try fails.
    attempts = []
    real = ctx.write_transaction

    def _waits_out_busy_timeout(*args, **kwargs):
        attempts.append(clock())
        clock.advance(30)
        return real(*args, **kwargs)

    def _get_user_fails() -> None:
        with pytest.raises(sqlite3.OperationalError, match="no such column"):
            store.get_user("alice")

    monkeypatch.setattr(ctx, "write_transaction", _waits_out_busy_timeout)
    ctx.get_conn().execute("PRAGMA query_only=ON")
    with caplog.at_level(logging.WARNING, logger=users_module.logger.name):
        for _ in range(3):
            _get_user_fails()
        assert attempts == [1_000.0]
        clock.advance(RETRY_SECONDS - 1)
        _get_user_fails()
        assert attempts == [1_000.0]
        clock.advance(1)
        _get_user_fails()
        assert attempts == [1_000.0, 1_030.0 + RETRY_SECONDS]
    assert caplog.text.count("Could not add must_change_password column") == 2

    ctx.get_conn().execute("PRAGMA query_only=OFF")
    clock.advance(RETRY_SECONDS)
    store.create_user("alice", PASSWORD)
    assert store.get_user("alice")["must_change_password"] is False
    assert _has_must_change_column(ctx)


def test_column_added_elsewhere_during_the_retry_wait_is_used_at_once(
    ctx, store, db_path, clock
):
    # The wait only delays this store's own ALTER: a column another worker
    # adds meanwhile ends the outage straight away (the clock never moves).
    ctx.get_conn().execute("PRAGMA query_only=ON")
    with pytest.raises(sqlite3.OperationalError, match="no such column"):
        store.get_user("alice")
    ctx.get_conn().execute("PRAGMA query_only=OFF")
    other = sqlite3.connect(db_path, isolation_level=None)
    try:
        other.execute(
            "ALTER TABLE users ADD COLUMN must_change_password "
            "INTEGER NOT NULL DEFAULT 0"
        )
    finally:
        other.close()

    store.create_user("alice", PASSWORD, must_change_password=True)
    assert store.get_user("alice")["must_change_password"] is True


def test_lazy_schema_step_waits_for_the_users_table(ctx, store):
    # A store used before the schema created the users table: nothing to
    # alter yet, and the step must not be cached as done.
    persist(ctx, "ALTER TABLE users RENAME TO users_not_yet")
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        store.get_user("alice")
    persist(ctx, "ALTER TABLE users_not_yet RENAME TO users")
    assert not _has_must_change_column(ctx)

    store.create_user("alice", PASSWORD)
    assert store.get_user("alice")["must_change_password"] is False
    assert _has_must_change_column(ctx)


def test_lazy_schema_step_takes_no_write_lock_once_the_column_exists(
    ctx, store, monkeypatch
):
    store.create_user("alice", PASSWORD, must_change_password=True)
    reopened = UserStore(ctx)
    calls = []
    real = ctx.write_transaction

    def _recording(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(ctx, "write_transaction", _recording)
    assert reopened.get_user("alice")["must_change_password"] is True
    assert reopened.get_user("alice")["must_change_password"] is True
    assert calls == []


def test_missing_column_inside_a_callers_transaction_is_added_later(ctx, store):
    # Adding it there would re-take the non-reentrant write lock (deadlock).
    with pytest.raises(sqlite3.OperationalError, match="no such column"):
        with ctx.write_transaction():
            store.get_user("alice")
    assert not ctx.get_conn().in_transaction
    assert not _has_must_change_column(ctx)

    store.create_user("alice", PASSWORD)
    assert store.get_user("alice")["must_change_password"] is False


def test_existing_rows_read_as_not_flagged_once_the_column_is_added(ctx, store):
    persist(
        ctx,
        "INSERT INTO users (username, password_hash, salt, role, enabled, "
        "created_at, tenant_id) VALUES ('legacy', 'h', 's', 'viewer', 1, ?, "
        "'default')",
        [iso(timedelta(0))],
    )
    assert store.get_user("legacy")["must_change_password"] is False
    row = ctx.get_conn().execute(
        "SELECT must_change_password FROM users WHERE username = 'legacy'"
    )
    assert row.fetchone()[0] == 0


# ---------------------------------------------------------------------------
# Password-change flag (contract K3) is tenant-scoped
# ---------------------------------------------------------------------------


def test_must_change_password_flag_is_cleared_only_in_its_tenant(ctx, other_ctx, store):
    store.create_user("alice", PASSWORD, must_change_password=True)
    assert store.get_user("alice")["must_change_password"] is True

    UserStore(other_ctx).clear_must_change_password("alice")
    assert store.get_user("alice")["must_change_password"] is True

    store.clear_must_change_password("alice")
    assert store.get_user("alice")["must_change_password"] is False
    row = ctx.get_conn().execute("SELECT must_change_password FROM users").fetchone()
    assert row[0] == 0


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------


def test_stored_token_hash_is_not_itself_a_credential(ctx, store):
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    stored = session_row(ctx, raw)["session_token"]
    assert stored != raw

    # A leaked database row cannot be replayed as a session token.
    assert store.get_session(stored) is None
    assert store.session_tenant(stored) is None
    assert store.delete_session(stored) is False
    assert store.get_session(raw)["username"] == "alice"


@pytest.mark.parametrize("raw", ["abc", "0", "-5", "1.5", "  ", "24h"])
def test_misconfigured_session_timeouts_fall_back_to_safe_defaults(
    monkeypatch, ctx, store, raw
):
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", raw)
    monkeypatch.setenv("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", raw)
    assert UserStore._get_absolute_timeout_hours() == 24
    assert UserStore._get_idle_timeout_minutes() == 30

    store.create_user("alice", PASSWORD)
    session = store.create_session(store.get_user("alice")["id"])
    lifetime = datetime.fromisoformat(session["expires_at"]) - datetime.fromisoformat(
        session["created_at"]
    )
    assert lifetime == timedelta(hours=24)


@pytest.mark.parametrize("raw", ["10000001", "70000000", "10000000000", "9" * 30])
def test_absurd_absolute_timeout_falls_back_to_the_default(
    monkeypatch, ctx, store, caplog, raw
):
    # Before, it was used as is: from about 7e7 hours the expiry is past
    # year 9999 (or past timedelta's range), so create_session raised
    # OverflowError and every login answered 500.
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", raw)
    with caplog.at_level(logging.WARNING, logger=users_module.__name__):
        assert UserStore._get_absolute_timeout_hours() == 24
    assert "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS" in caplog.text

    store.create_user("alice", PASSWORD)
    session = store.create_session(store.get_user("alice")["id"])
    lifetime = datetime.fromisoformat(session["expires_at"]) - datetime.fromisoformat(
        session["created_at"]
    )
    assert lifetime == timedelta(hours=24)
    assert store.get_session(session["session_token"])["username"] == "alice"


def test_longest_absolute_timeout_gives_a_readable_expiry(monkeypatch, ctx, store):
    # The ceiling (as for API key lifetimes) keeps the expiry a four-digit
    # year, which the bridge and the gateway both read.
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", "10000000")
    assert UserStore._get_absolute_timeout_hours() == 10_000_000

    store.create_user("alice", PASSWORD)
    session = store.create_session(store.get_user("alice")["id"])
    lifetime = datetime.fromisoformat(session["expires_at"]) - datetime.fromisoformat(
        session["created_at"]
    )
    assert lifetime == timedelta(hours=10_000_000)
    assert store.get_session(session["session_token"])["username"] == "alice"


@pytest.mark.parametrize("raw", ["0", "-5"])
def test_non_positive_absolute_timeout_is_logged(monkeypatch, caplog, raw):
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", raw)
    with caplog.at_level(logging.WARNING, logger=users_module.__name__):
        assert UserStore._get_absolute_timeout_hours() == 24
    assert "BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS" in caplog.text


def test_long_invalid_absolute_timeout_is_logged_shortened(monkeypatch, caplog):
    # The warning quotes at most the first 64 characters of the value, so a
    # huge environment value does not become a huge log line.
    raw = "1" + "0" * 5000
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", raw)
    with caplog.at_level(logging.WARNING, logger=users_module.__name__):
        assert UserStore._get_absolute_timeout_hours() == 24
    assert f"={raw[:64]!r} (expected" in caplog.text
    assert raw[:65] not in caplog.text


def test_configured_session_timeouts_are_applied(monkeypatch, ctx, store):
    monkeypatch.setenv("BRIDGE_SESSION_ABSOLUTE_TIMEOUT_HOURS", "2")
    monkeypatch.setenv("BRIDGE_SESSION_IDLE_TIMEOUT_MINUTES", "5")
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    row = session_row(ctx, raw)
    lifetime = datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(
        row["created_at"]
    )
    assert lifetime == timedelta(hours=2)

    persist(
        ctx,
        "UPDATE sessions SET last_active = ? WHERE id = ?",
        (iso(timedelta(minutes=-6)), row["id"]),
    )
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


def test_legacy_session_without_activity_is_still_bounded_by_expiry(ctx, store):
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    persist(ctx, "UPDATE sessions SET last_active = NULL")

    found = store.get_session(raw, touch=False)
    assert found["username"] == "alice"
    assert session_row(ctx, raw)["last_active"] is None

    persist(ctx, "UPDATE sessions SET expires_at = ?", (iso(timedelta(seconds=-1)),))
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


# Session timestamps are read in the one layout the gateway reads
# (storage/sessions.rs parse_iso_datetime): YYYY-MM-DD, 'T' or one space,
# HH:MM:SS, an optional '.' fraction, an optional 'Z' or +-HH:MM offset.
# Every writer produces it: the gateway ('%Y-%m-%dT%H:%M:%S+00:00'), the
# bridge's isoformat() (naive in legacy rows) and SQLite's datetime().
STORED_FORMATS = [
    "%Y-%m-%dT%H:%M:%S+00:00",  # gateway
    "%Y-%m-%dT%H:%M:%S.%f+00:00",  # bridge isoformat(), aware
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S",  # legacy naive isoformat()
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",  # SQLite datetime()
    "%Y-%m-%d %H:%M:%S.%f",
]


def test_session_timestamps_are_read_in_the_gateway_layout_only():
    parse = users_module._parse_session_timestamp
    at = datetime(2026, 3, 4, 5, 6, 7, 123456, tzinfo=timezone.utc)
    whole = at.replace(microsecond=0)
    for fmt in STORED_FORMATS:
        text = at.strftime(fmt)
        assert parse(text) == (at if "%f" in fmt else whole), text
    # Another offset is applied, whatever the separator; naive means UTC.
    for text in [
        "2026-03-04T07:06:07+02:00",
        "2026-03-04 07:06:07+02:00",
        "2026-03-04T03:06:07-02:00",
        "2026-03-04T05:06:07-00:00",
        "2026-03-04 05:06:07Z",
        "2026-03-05T05:05:07+23:59",
    ]:
        assert parse(text) == whole, text
    # A fraction of any length (SQLite's strftime('%f') writes 3 digits).
    for text, micros in [
        ("2026-03-04T05:06:07.1", 100_000),
        ("2026-03-04T05:06:07.123", 123_000),
        ("2026-03-04 05:06:07.123456789+00:00", 123_456),
        ("2026-03-04T05:06:07.1234567890", 123_456),
    ]:
        assert parse(text) == whole.replace(microsecond=micros), text
    # The gateway's refused inputs, and what is not text at all.
    for value in [
        None,
        1772600767,
        b"2026-03-04T05:06:07+00:00",
        "",
        " ",
        "garbage",
        "never",
        "2026-13-45T99:99:99+00:00",
        "1772600767",
        "12026-03-04T05:06:07",
        "02026-03-04T05:06:07",
        "2026-003-04T05:06:07",
        "2026-03-04T05:06:07.",
        "2026-03-04T05:06:07 ",
        "2026-03-04T05:06:07Z+00:00",
        "2026-3-4 5:6:7",
        "2026-03-04T 5:06:07",
        "2026-03-04T23:59:60",
        "2026-03-04T23:59:60+00:00",
        "2026-03-04  05:06:07",
        "+12026-03-04T05:06:07",
        "2026-03-04T05:06:07z",
        " 2026-03-04T05:06:07",
        # fromisoformat reads these, the gateway does not.
        "2026-03-04",
        "2026-03-04T05:06",
        "20260304T050607",
        "2026-03-04T05:06:07+0000",
        "2026-03-04T05:06:07+02",
        "2026-03-04T05:06:07+00:00:00",
        "2026-03-04T05:06:07+00:60",
        "2026-03-04T05:06:07+24:00",
        "2026-03-04T05:06:07,5",
        "2026-03-04t05:06:07+00:00",
        "2026-03-04X05:06:07",
        "２０２６-03-04T05:06:07",
    ]:
        assert parse(value) is None, value


@pytest.mark.parametrize("fmt", STORED_FORMATS)
def test_both_session_limits_apply_in_every_stored_format(ctx, store, fmt):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    now = datetime.now(timezone.utc)
    for column, offset, alive in [
        ("expires_at", timedelta(seconds=-60), False),
        ("expires_at", timedelta(seconds=120), True),
        ("last_active", timedelta(minutes=-31), False),
        ("last_active", timedelta(minutes=-25), True),
    ]:
        raw = store.create_session(uid)["session_token"]
        value = (now + offset).strftime(fmt)
        persist(
            ctx,
            f"UPDATE sessions SET {column} = ? WHERE session_token = ?",
            (value, hashlib.sha256(raw.encode()).hexdigest()),
        )
        assert (store.get_session(raw) is not None) is alive, (column, value)
        assert (session_row(ctx, raw) is not None) is alive, (column, value)


def test_session_time_limit_names_the_first_limit_in_the_gateway_order():
    # As the gateway's session_time_limit (storage/sessions.rs): an
    # unreadable expires_at, then the expiry, then an unreadable non-NULL
    # last_active, then the idle timeout. The first one reached names it.
    limit = users_module._session_time_limit
    now = datetime(2026, 3, 4, 5, 6, 7, tzinfo=timezone.utc)
    later = (now + timedelta(hours=1)).isoformat()
    past = (now - timedelta(seconds=1)).isoformat()
    recent = (now - timedelta(minutes=1)).isoformat()
    stale = (now - timedelta(minutes=31)).isoformat()

    assert limit(later, recent, 30, now) is None
    assert limit(later, None, 30, now) is None
    # The expiry instant itself is still valid (the gateway: now > expiry).
    assert limit(now.isoformat(), recent, 30, now) is None
    assert limit(past, recent, 30, now) == "expired"
    assert limit(past, None, 30, now) == "expired"
    assert limit(later, stale, 30, now) == "idle"
    assert limit(later, "garbage", 30, now) == "unreadable"
    assert limit(later, "", 30, now) == "unreadable"
    assert limit("garbage", recent, 30, now) == "unreadable"
    assert limit(None, None, 30, now) == "unreadable"
    # Several limits at once: the expiry comes before the activity.
    assert limit("garbage", stale, 30, now) == "unreadable"
    assert limit("garbage", "garbage", 30, now) == "unreadable"
    assert limit(past, "garbage", 30, now) == "expired"
    assert limit(past, stale, 30, now) == "expired"


def test_idle_time_counts_whole_seconds_as_the_gateway_does():
    # The gateway compares (now - last_active).num_seconds(), whole seconds,
    # with the limit: 1800.5 s idle is within a 30-minute limit there.
    limit = users_module._session_time_limit
    now = datetime(2026, 3, 4, 5, 6, 7, 500_000, tzinfo=timezone.utc)
    later = (now + timedelta(hours=1)).isoformat()

    def idle_for(seconds: float) -> str:
        return (now - timedelta(seconds=seconds)).isoformat()

    assert limit(later, idle_for(1799), 30, now) is None
    assert limit(later, idle_for(1800), 30, now) is None
    assert limit(later, idle_for(1800.5), 30, now) is None
    assert limit(later, idle_for(1800.999999), 30, now) is None
    assert limit(later, idle_for(1801), 30, now) == "idle"
    assert limit(later, idle_for(61), 1, now) == "idle"
    assert limit(later, idle_for(60.9), 1, now) is None
    # A last_active ahead of now (clock skew) is not idle.
    assert limit(later, idle_for(-300.5), 30, now) is None


def test_only_an_unreadable_session_is_logged_as_unreadable(ctx, store, caplog):
    # An expired session whose last_active is also damaged is refused as
    # expired, as the gateway names it, without the unreadable warning.
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    expired = store.create_session(uid)["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET expires_at = ?, last_active = 'garbage' "
        "WHERE session_token = ?",
        (iso(timedelta(seconds=-60)), hashlib.sha256(expired.encode()).hexdigest()),
    )
    with caplog.at_level(logging.INFO, logger=users_module.__name__):
        assert store.get_session(expired) is None
    assert session_row(ctx, expired) is None
    assert "not a readable timestamp" not in caplog.text

    unreadable = store.create_session(uid)["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET last_active = 'garbage' WHERE session_token = ?",
        (hashlib.sha256(unreadable.encode()).hexdigest(),),
    )
    caplog.clear()
    with caplog.at_level(logging.INFO, logger=users_module.__name__):
        assert store.get_session(unreadable) is None
    assert session_row(ctx, unreadable) is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "not a readable timestamp" in warnings[0].getMessage()
    assert "alice" in warnings[0].getMessage()


# Damaged values for a timestamp column, each a function of the instant it
# should have held. Each one is refused by the gateway: not text (a BLOB
# fails its row mapping), not a timestamp, or a layout it does not read.
UNREADABLE_TIMESTAMPS = [
    pytest.param(lambda at: "not-a-timestamp", id="garbage"),
    pytest.param(lambda at: "", id="empty"),
    pytest.param(lambda at: " ", id="blank"),
    pytest.param(lambda at: "2099-13-45T99:99:99+00:00", id="out-of-range"),
    pytest.param(lambda at: int(at.timestamp()), id="epoch-integer"),
    pytest.param(lambda at: at.isoformat().encode(), id="blob"),
    pytest.param(lambda at: at.isoformat() + " ", id="trailing-space"),
    pytest.param(
        lambda at: at.strftime("%Y-%m-%dT%H:%M:%S+0000"), id="offset-no-colon"
    ),
    pytest.param(lambda at: at.strftime("%Y-%m-%dT%H:%M:%S+00"), id="short-offset"),
    pytest.param(lambda at: at.strftime("%Y%m%dT%H%M%S"), id="basic-form"),
    pytest.param(lambda at: at.strftime("%Y-%m-%dT%H:%M:%S,%f+00:00"), id="comma"),
    pytest.param(lambda at: at.strftime("%Y-%m-%dt%H:%M:%S+00:00"), id="lowercase-t"),
    pytest.param(lambda at: at.strftime("%Y-%m-%dX%H:%M:%S"), id="other-separator"),
    pytest.param(
        lambda at: (at + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:60"),
        id="offset-minute-60",
    ),
]


@pytest.mark.parametrize("damage", UNREADABLE_TIMESTAMPS)
def test_damaged_activity_timestamp_is_refused_and_deleted(ctx, store, damage):
    # Before, an unreadable last_active skipped the idle check and the touch
    # rewrote it to now: an idle session came back with a fresh idle clock.
    # The gateway refuses and deletes such a row. The value here stands for
    # an activity a minute ago, so the refusal is not the idle limit.
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    value = damage(datetime.now(timezone.utc) - timedelta(minutes=1))
    persist(ctx, "UPDATE sessions SET last_active = ?", (value,))
    stored = session_row(ctx, raw)["last_active"]

    # The read-only check (outgoing WebSocket data) refuses and keeps the row.
    assert store.get_session(raw, touch=False) is None
    assert session_row(ctx, raw)["last_active"] == stored
    # A request refuses and deletes it; nothing writes a fresh last_active.
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


@pytest.mark.parametrize("damage", UNREADABLE_TIMESTAMPS)
def test_damaged_absolute_expiry_is_refused_and_deleted(ctx, store, damage):
    # The periodic cleanup compares strings and never removes most of these,
    # so the request that finds one deletes it, as the gateway does.
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    value = damage(datetime.now(timezone.utc) + timedelta(hours=1))
    persist(ctx, "UPDATE sessions SET expires_at = ?", (value,))
    stored = session_row(ctx, raw)["expires_at"]

    assert store.get_session(raw, touch=False) is None
    assert session_row(ctx, raw)["expires_at"] == stored
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


def test_null_activity_timestamp_has_no_idle_limit_and_the_touch_starts_it(ctx, store):
    # NULL is a session from before the column: no idle information, so
    # only the absolute limit applies, and the first touch starts the clock.
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    persist(ctx, "UPDATE sessions SET last_active = NULL")
    assert store.get_session(raw)["username"] == "alice"
    touched = datetime.fromisoformat(session_row(ctx, raw)["last_active"])
    assert abs(datetime.now(timezone.utc) - touched) < timedelta(minutes=1)

    persist(ctx, "UPDATE sessions SET last_active = ?", (iso(timedelta(minutes=-31)),))
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


def test_unreadable_session_of_disabled_user_is_deleted(ctx, store):
    # The time limits come before the disabled-user refusal, as in the
    # gateway: a disabled user's session with unreadable times is deleted.
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    unreadable = store.create_session(uid)["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET last_active = 'garbage' WHERE session_token = ?",
        (hashlib.sha256(unreadable.encode()).hexdigest(),),
    )
    kept = store.create_session(uid)["session_token"]
    store.disable_user("alice")

    assert store.get_session(unreadable) is None
    assert session_row(ctx, unreadable) is None
    assert store.get_session(kept) is None
    assert session_row(ctx, kept) is not None


def test_damaged_activity_timestamp_never_outlives_absolute_expiry(ctx, store):
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET last_active = 'garbage', expires_at = ?",
        (iso(timedelta(seconds=-1)),),
    )
    assert store.get_session(raw) is None
    assert session_row(ctx, raw) is None


def test_session_of_disabled_user_is_refused_and_not_touched(ctx, store):
    store.create_user("alice", PASSWORD)
    raw = store.create_session(store.get_user("alice")["id"])["session_token"]
    old = iso(timedelta(minutes=-10))
    persist(ctx, "UPDATE sessions SET last_active = ?", (old,))
    store.disable_user("alice")

    assert store.get_session(raw) is None
    # A refused credential must not keep the session alive.
    assert session_row(ctx, raw)["last_active"] == old


def test_cleanup_keeps_live_sessions(ctx, store):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    live = store.create_session(uid)["session_token"]
    assert store.cleanup_expired_sessions() == 0
    assert store.get_session(live)["user_id"] == uid

    dead = store.create_session(uid)["session_token"]
    persist(
        ctx,
        "UPDATE sessions SET expires_at = ? WHERE session_token = ?",
        (iso(timedelta(hours=-1)), hashlib.sha256(dead.encode()).hexdigest()),
    )
    assert store.cleanup_expired_sessions() == 1
    assert session_row(ctx, dead) is None
    assert store.get_session(live) is not None


def test_delete_user_sessions_revokes_only_that_user(ctx, store):
    store.create_user("alice", PASSWORD)
    store.create_user("bob", PASSWORD)
    alice = store.get_user("alice")["id"]
    bob = store.get_user("bob")["id"]
    a1 = store.create_session(alice)["session_token"]
    a2 = store.create_session(alice)["session_token"]
    b1 = store.create_session(bob)["session_token"]

    assert store.delete_user_sessions(alice) == 2
    assert store.get_session(a1) is None
    assert store.get_session(a2) is None
    assert store.get_session(b1)["username"] == "bob"
    assert store.delete_user_sessions(alice) == 0


# ---------------------------------------------------------------------------
# MFA password proofs
# ---------------------------------------------------------------------------


def test_expired_mfa_proof_is_refused_and_purged_on_use(ctx, store):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    expired = store.create_mfa_token(uid, expires_minutes=-1)
    stored = ctx.get_conn().execute("SELECT token FROM mfa_tokens").fetchone()[0]
    assert stored == hashlib.sha256(expired.encode()).hexdigest()

    assert store.verify_mfa_token(expired) is None
    assert ctx.get_conn().execute("SELECT COUNT(*) FROM mfa_tokens").fetchone()[0] == 0
    assert store.verify_mfa_token(expired) is None
    # The stored hash is not usable as a proof either.
    live = store.create_mfa_token(uid)
    assert store.verify_mfa_token(hashlib.sha256(live.encode()).hexdigest()) is None
    assert store.verify_mfa_token(live) == uid
    assert not ctx.get_conn().in_transaction


# ---------------------------------------------------------------------------
# TOTP secrets without a usable BRIDGE_MFA_KEY
# ---------------------------------------------------------------------------


def test_production_without_mfa_key_refuses_to_store_a_totp_secret(
    monkeypatch, ctx, store
):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    monkeypatch.setenv("BRIDGE_MODE", "prod")

    with pytest.raises(RuntimeError, match="BRIDGE_MFA_KEY is not set"):
        store.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")

    row = ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()
    assert row[0] is None
    assert not ctx.get_conn().in_transaction


def test_encrypted_secret_is_withheld_when_the_key_disappears(
    monkeypatch, ctx, store, caplog
):
    monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    store.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
    stored = ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()[0]
    assert stored.startswith("fernet:")
    assert "JBSWY3DPEHPK3PXP" not in stored

    monkeypatch.delenv("BRIDGE_MFA_KEY")
    monkeypatch.setattr(users_module, "_fernet_instance", None)

    # Fail closed: no secret rather than ciphertext or a crash.
    assert store.get_user_by_id(uid)["totp_secret"] is None
    assert store.get_user_full("alice")["totp_secret"] is None
    with pytest.raises(ValueError, match="Fernet-encrypted"):
        users_module._decrypt_totp_secret(stored)
    # Nothing was rewritten while the key was missing.
    assert UserStore(ctx).reencrypt_legacy_totp_secrets() == 0
    assert (
        ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()[0] == stored
    )
    assert "JBSWY3DPEHPK3PXP" not in caplog.text


def test_legacy_plaintext_secret_is_readable_then_encrypted_once_key_is_set(
    monkeypatch, ctx, store
):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    persist(ctx, "UPDATE users SET totp_secret = 'JBSWY3DPEHPK3PXP'")
    assert store.get_user_by_id(uid)["totp_secret"] == "JBSWY3DPEHPK3PXP"

    monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
    assert store.reencrypt_legacy_totp_secrets() == 1
    stored = ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()[0]
    assert stored.startswith("fernet:")
    assert store.get_user_by_id(uid)["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert store.reencrypt_legacy_totp_secrets() == 0


def test_secret_without_key_is_stored_base64_and_cleared_on_request(ctx, store):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    assert store.set_totp_secret(uid, "JBSWY3DPEHPK3PXP") is True
    stored = ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()[0]
    assert stored == "b64:" + base64.b64encode(b"JBSWY3DPEHPK3PXP").decode()

    assert store.set_totp_secret(uid, None) is True
    assert ctx.get_conn().execute("SELECT totp_secret FROM users").fetchone()[0] is None
    assert store.get_user_by_id(uid)["totp_secret"] is None
    assert store.set_totp_secret(uid + 999, "X") is False
    assert users_module._encrypt_totp_secret(None) is None
    assert users_module._decrypt_totp_secret(None) is None


def test_reencryption_skips_a_missing_users_table(monkeypatch, ctx):
    monkeypatch.setenv("BRIDGE_MFA_KEY", Fernet.generate_key().decode())
    persist(ctx, "ALTER TABLE users RENAME TO users_moved")
    try:
        assert UserStore(ctx).reencrypt_legacy_totp_secrets() == 0
    finally:
        persist(ctx, "ALTER TABLE users_moved RENAME TO users")


def test_mfa_key_problem_without_cryptography(monkeypatch):
    monkeypatch.setitem(sys.modules, "cryptography.fernet", None)
    problem = users_module.mfa_key_problem(Fernet.generate_key().decode())
    assert "'cryptography' package is not installed" in problem


# ---------------------------------------------------------------------------
# Backup codes and MFA disable
# ---------------------------------------------------------------------------


def test_regenerated_backup_codes_invalidate_the_previous_set(ctx, store):
    store.create_user("alice", PASSWORD)
    uid = store.get_user("alice")["id"]
    store.store_backup_codes(uid, [hash_credential(c) for c in ("old-1", "old-2")])
    store.store_backup_codes(uid, [hash_credential("new-1")])

    assert store.get_backup_code_count(uid) == 1
    assert store.verify_backup_code(uid, "old-1") is False
    assert store.verify_backup_code(uid, "old-2") is False
    assert store.verify_backup_code(uid, "new-1") is True
    assert store.verify_backup_code(uid, "new-1") is False
    assert store.get_backup_code_count(uid) == 0


def test_backup_codes_are_bound_to_their_user(ctx, store):
    store.create_user("alice", PASSWORD)
    store.create_user("bob", PASSWORD)
    alice = store.get_user("alice")["id"]
    bob = store.get_user("bob")["id"]
    store.store_backup_codes(alice, [hash_credential("alice-code")])

    assert store.verify_backup_code(bob, "alice-code") is False
    assert store.get_backup_code_count(alice) == 1
    rows = ctx.get_conn().execute("SELECT code_hash FROM mfa_backup_codes").fetchall()
    assert all("alice-code" not in r[0] for r in rows)


def test_disable_mfa_removes_secret_flag_and_backup_codes(ctx, store):
    store.create_user("alice", PASSWORD)
    store.create_user("bob", PASSWORD)
    alice = store.get_user("alice")["id"]
    bob = store.get_user("bob")["id"]
    for uid in (alice, bob):
        store.set_totp_secret(uid, "JBSWY3DPEHPK3PXP")
        store.enable_mfa(uid)
        store.store_backup_codes(uid, [hash_credential("code-1")])

    assert store.disable_mfa(alice) is True
    row = store.get_user_by_id(alice)
    assert (row["mfa_enabled"], row["totp_secret"]) == (0, None)
    assert store.get_backup_code_count(alice) == 0
    assert store.verify_backup_code(alice, "code-1") is False

    # Bob's second factor is untouched.
    assert store.get_user_by_id(bob)["mfa_enabled"] == 1
    assert store.get_backup_code_count(bob) == 1
    assert store.disable_mfa(bob + 999) is False
    assert store.enable_mfa(bob + 999) is False


def test_tenant_mfa_requirement_is_per_tenant_and_toggles(store):
    assert store.get_tenant_mfa_required("default") is False
    assert store.get_tenant_mfa_required("x' OR '1'='1") is False
    store.set_tenant_mfa_required("default", True)
    assert store.get_tenant_mfa_required("default") is True
    assert store.get_tenant_mfa_required("tenant-b") is False
    store.set_tenant_mfa_required("default", False)
    assert store.get_tenant_mfa_required("default") is False


# ---------------------------------------------------------------------------
# End to end through the real auth/admin HTTP routes
# ---------------------------------------------------------------------------


@pytest.fixture
def http(monkeypatch, client):
    from fastapi.testclient import TestClient

    from sigrift.bridge.routers.auth import _login_attempts

    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "users-http-audit-key")
    _login_attempts.clear()
    yield client, TestClient(client.app)
    _login_attempts.clear()


def audit_rows(detection_store, action):
    return (
        detection_store.get_connection()
        .execute(
            "SELECT target_id, operator, note FROM audit_log WHERE action = ? ORDER BY id",
            [action],
        )
        .fetchall()
    )


def test_http_user_lifecycle_is_persisted_and_audited(http, detection_store):
    admin, anon = http
    hostile_name = "O'Brien \"; DROP TABLE users; -- 🙂"
    resp = admin.post(
        "/api/admin/users",
        json={
            "username": "ops.analyst-1",
            "password": PASSWORD,
            "role": "analyst",
            "display_name": hostile_name,
            "email": "o'brien@example.invalid",
        },
    )
    assert resp.status_code == 200, resp.text
    row = (
        detection_store.get_connection()
        .execute(
            "SELECT role, display_name, email, enabled, password_hash FROM users "
            "WHERE username = 'ops.analyst-1'"
        )
        .fetchone()
    )
    assert (row["role"], row["display_name"], row["enabled"]) == (
        "analyst",
        hostile_name,
        1,
    )
    assert PASSWORD not in row["password_hash"]
    created = audit_rows(detection_store, "user_create")
    assert [(r["target_id"], r["note"]) for r in created] == [
        ("ops.analyst-1", "Created user with role=analyst")
    ]
    assert created[0]["operator"]

    login = anon.post(
        "/api/auth/login", json={"username": "ops.analyst-1", "password": PASSWORD}
    )
    assert login.status_code == 200, login.text
    token = login.json()["session_token"]
    assert login.json()["user"]["role"] == "analyst"
    assert [r["target_id"] for r in audit_rows(detection_store, "user_login")] == [
        "ops.analyst-1"
    ]
    me = anon.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200

    promoted = admin.put("/api/admin/users/ops.analyst-1", json={"role": "admin"})
    assert promoted.status_code == 200
    assert detection_store.users.get_user("ops.analyst-1")["role"] == "admin"
    assert [r["target_id"] for r in audit_rows(detection_store, "user_update")] == [
        "ops.analyst-1"
    ]

    disabled = admin.delete("/api/admin/users/ops.analyst-1")
    assert disabled.status_code == 200
    assert detection_store.users.get_user("ops.analyst-1")["enabled"] == 0
    assert (
        detection_store.get_connection()
        .execute("SELECT COUNT(*) FROM sessions")
        .fetchone()[0]
        == 0
    )
    assert (
        anon.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        ).status_code
        == 401
    )
    assert [r["target_id"] for r in audit_rows(detection_store, "user_disable")] == [
        "ops.analyst-1"
    ]

    again = anon.post(
        "/api/auth/login", json={"username": "ops.analyst-1", "password": PASSWORD}
    )
    assert again.status_code == 401
    assert [r["target_id"] for r in audit_rows(detection_store, "auth_failure")] == [
        "ops.analyst-1"
    ]
    assert admin.get("/api/admin/audit/verify").json()["valid"] is True


@pytest.mark.parametrize(
    "body",
    [
        {"role": "keymaster"},
        {"role": "Admin"},
        {"role": "admin' --"},
        {"role": "superadmin", "display_name": "changed", "enabled": False},
    ],
)
def test_http_invalid_role_update_changes_and_audits_nothing(
    http, detection_store, body
):
    admin, _ = http
    detection_store.users.create_user("alice", PASSWORD, display_name="Alice")
    before = detection_store.users.get_user("alice")

    resp = admin.put("/api/admin/users/alice", json=body)
    assert resp.status_code in (400, 422)
    assert detection_store.users.get_user("alice") == before
    assert audit_rows(detection_store, "user_update") == []


def test_http_duplicate_create_keeps_the_original_account(http, detection_store):
    admin, anon = http
    first = {"username": "alice", "password": PASSWORD, "role": "admin"}
    assert admin.post("/api/admin/users", json=first).status_code == 200
    dup = {"username": "alice", "password": "Attacker password 1!", "role": "viewer"}
    resp = admin.post("/api/admin/users", json=dup)
    assert resp.status_code == 409

    assert detection_store.users.get_user("alice")["role"] == "admin"
    assert len(audit_rows(detection_store, "user_create")) == 1
    assert (
        anon.post(
            "/api/auth/login", json={"username": "alice", "password": dup["password"]}
        ).status_code
        == 401
    )
    assert (
        anon.post(
            "/api/auth/login", json={"username": "alice", "password": PASSWORD}
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "username",
    ["alice' OR '1'='1", "alice' --", "ALICE", "%", "alice\u0000"],
)
def test_http_login_probe_is_refused_and_audited_verbatim(
    http, detection_store, username
):
    admin, anon = http
    detection_store.users.create_user("alice", PASSWORD, role="admin")

    resp = anon.post(
        "/api/auth/login", json={"username": username, "password": PASSWORD}
    )
    assert resp.status_code == 401
    assert (
        detection_store.get_connection()
        .execute("SELECT COUNT(*) FROM sessions")
        .fetchone()[0]
        == 0
    )
    failures = audit_rows(detection_store, "auth_failure")
    assert [r["target_id"] for r in failures] == [username]
    assert audit_rows(detection_store, "user_login") == []
    assert admin.get("/api/admin/audit/verify").json()["valid"] is True
