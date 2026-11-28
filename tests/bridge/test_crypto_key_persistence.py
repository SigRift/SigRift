"""Imported protocol decryption keys are saved in ``crypto_keys`` (F10).

With ``BRIDGE_KEYSTORE_KEY`` set, a key imported through the console is
saved in the database, encrypted with it, and loaded again under the same
``key_id`` when the bridge restarts: the same payloads decrypt, through the
API and the decode pipeline.  Raw key bytes never reach the database file
or the log.  Revoking deletes the row.  Built-in keys are never saved.  A
missing, invalid or wrong keystore key, a damaged row or an unreadable
table never deletes or changes a row: the keys stay in the database,
unloaded, with a warning, and new imports stay memory-only.

A "restart" here builds a new key store from the same database with
``init_crypto_keys`` (what the lifespan does), and wires it into the app.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge import restore_marker
from sigrift.bridge.decode_pipeline import ProtocolDecodePipeline
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers import crypto as crypto_router
from sigrift.bridge.storage import crypto_keys
from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.crypto_keys import (
    CryptoKeyVault,
    Persistence,
    forget_unreadable,
    init_crypto_keys,
)
from sigrift.lib.crypto.key_store import KeyStore

from .test_console_crypto_protocols import (
    OPS_KEY,
    PACKET_ID,
    SOURCE_NODE,
    TEXT_DATA,
    _console_decrypt,
    _console_import,
    _meshtastic_ct,
)
from .test_crypto_router_refusals import _client_with_role, _decrypt_body

KEY_A = base64.urlsafe_b64encode(os.urandom(32)).decode()
KEY_B = base64.urlsafe_b64encode(os.urandom(32)).decode()
WITH_A = {"BRIDGE_KEYSTORE_KEY": KEY_A}
SAVE_FAILED = (
    "Could not save the key in the database; nothing was imported. "
    "Try again, and check the bridge log."
)
DELETE_FAILED = (
    "Could not delete the saved key from the database; it was not revoked. "
    "Try again, and check the bridge log."
)


def install(
    app: FastAPI, ctx: SharedContext, environ: dict[str, str]
) -> tuple[KeyStore, CryptoKeyVault]:
    """Start the key store again from the database (a bridge restart)."""
    store, vault = init_crypto_keys(ctx, environ)
    app.state.crypto_key_store = store
    app.state.crypto_key_vault = vault
    return store, vault


def rows(ctx: SharedContext) -> list[tuple]:
    """Every column of every crypto_keys row."""
    return [
        tuple(row)
        for row in ctx.execute("SELECT * FROM crypto_keys ORDER BY id").fetchall()
    ]


def _import(client: TestClient, key: bytes, protocol: str = "meshtastic", **extra):
    return client.post(
        "/api/crypto/keys",
        json={
            "protocol": protocol,
            "key_name": extra.pop("key_name", f"console {protocol}"),
            "raw_key_hex": key.hex(),
            **extra,
        },
    )


def _key_warnings(client: TestClient) -> list[str]:
    body = client.get("/api/health").json()
    return [
        w
        for w in body["security_warnings"]
        if w.startswith("Protocol decryption keys:")
    ]


@pytest.fixture
def ctx(detection_store: DetectionStore) -> SharedContext:
    return detection_store._ctx


@pytest.fixture
def saved(bridge_app: FastAPI, ctx: SharedContext) -> tuple[KeyStore, CryptoKeyVault]:
    """The app with keys persisted under KEY_A."""
    return install(bridge_app, ctx, WITH_A)


def test_the_test_app_keeps_keys_in_memory_without_a_keystore_key(
    bridge_app: FastAPI,
) -> None:
    assert bridge_app.state.crypto_key_vault.state is Persistence.DISABLED


def test_an_imported_key_is_saved_and_decrypts_under_the_same_id_after_a_restart(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    resp = _import(client, OPS_KEY)
    assert resp.status_code == 201
    assert resp.json()["persisted"] is True
    key_id = resp.json()["key_id"]
    (before,) = [k for k in client.get("/api/crypto/keys").json() if k["key_id"] == key_id]
    assert before["persisted"] is True

    store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ENABLED and vault.loaded == 1
    (after,) = [k for k in client.get("/api/crypto/keys").json() if k["key_id"] == key_id]
    assert after == before
    assert after["created_at"] == before["created_at"]

    resp = client.post(
        "/api/crypto/decrypt",
        json=_decrypt_body(_meshtastic_ct(OPS_KEY), key_id=key_id),
    )
    assert resp.status_code == 200
    assert resp.json()["success"] is True
    assert resp.json()["plaintext_hex"] == TEXT_DATA.hex()
    assert resp.json()["key_id"] == key_id

    message = SimpleNamespace(
        payload=_meshtastic_ct(OPS_KEY),
        decrypted=False,
        metadata={"packet_id": PACKET_ID, "source_node": SOURCE_NODE},
    )
    ProtocolDecodePipeline(None, store)._try_auto_decrypt([message], "meshtastic")
    assert message.decrypted is True and message.key_id == key_id


def test_a_console_import_is_saved_too(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    # The body crypto_admin.js sends (test_console_crypto_protocols.py).
    key_id = _console_import(client, "meshtastic", OPS_KEY)
    install(bridge_app, ctx, WITH_A)
    resp = client.post(
        "/api/crypto/decrypt",
        json=_console_decrypt("meshtastic", _meshtastic_ct(OPS_KEY), key_id=key_id),
    )
    assert resp.json()["key_id"] == key_id
    assert resp.json()["plaintext_hex"] == TEXT_DATA.hex()


def test_saved_keys_survive_a_new_database_connection(
    client: TestClient, detection_store: DetectionStore, saved
) -> None:
    key_id = _import(client, OPS_KEY).json()["key_id"]
    db_path = Path(detection_store._ctx.db_path)
    detection_store.close()
    reopened = DetectionStore(db_path=db_path)
    try:
        store, vault = init_crypto_keys(reopened._ctx, WITH_A)
        assert vault.loaded == 1
        assert bytes(store.lookup_key(key_id).key_material) == OPS_KEY
    finally:
        reopened.close()


def _key_forms(key: bytes) -> list[str]:
    return [
        key.hex(),
        key.hex().upper(),
        ":".join(f"{b:02x}" for b in key),
        base64.b64encode(key).decode(),
        base64.urlsafe_b64encode(key).decode(),
        base64.b64encode(key).decode().rstrip("="),
        hashlib.sha256(key).hexdigest(),
    ]


def test_raw_key_material_never_reaches_the_database_file_or_the_log(
    client: TestClient, ctx: SharedContext, saved, caplog: pytest.LogCaptureFixture
) -> None:
    key = bytes.fromhex("c0ffee5a17d00d1e") + os.urandom(24)
    with caplog.at_level(logging.DEBUG):
        assert _import(client, key).json()["persisted"] is True
        ctx.wal_checkpoint()
    files = [Path(ctx.db_path + suffix) for suffix in ("", "-wal", "-shm")]
    data = b"".join(f.read_bytes() for f in files if f.exists())
    assert data
    assert key not in data
    for form in _key_forms(key):
        assert form.encode() not in data, form
        assert form not in caplog.text, form


def test_the_row_follows_the_crypto_keys_columns(
    client: TestClient, ctx: SharedContext, saved
) -> None:
    resp = _import(client, OPS_KEY, key_name="ops channel", algorithm="aes-128-ctr")
    key_id = resp.json()["key_id"]
    (listed,) = [k for k in client.get("/api/crypto/keys").json() if k["key_id"] == key_id]
    (row,) = [dict(r) for r in ctx.execute("SELECT * FROM crypto_keys").fetchall()]
    assert row["id"] == key_id
    assert row["protocol"] == "meshtastic"
    assert row["key_name"] == "ops channel"
    assert row["algorithm"] == "aes-128-ctr"
    assert row["key_source"] == "import"
    assert row["tenant_id"] == "default"
    assert row["created_at"] == listed["created_at"]
    assert row["revoked_at"] is None
    assert row["notes"] == ""
    assert row["associated_source_id"] is None
    assert row["created_by"]  # the importing API key's id (never returned)
    assert "created_by" not in listed
    assert row["key_hash"].startswith("hmac-sha256:v1:")
    assert len(row["key_hash"]) == len("hmac-sha256:v1:") + 64
    envelope = json.loads(Fernet(KEY_A.encode()).decrypt(row["key_data_encrypted"]))
    assert envelope == {
        "algorithm": "aes-128-ctr",
        "format": 1,
        "key_id": key_id,
        "material": base64.b64encode(OPS_KEY).decode(),
        "protocol": "meshtastic",
    }


def test_the_key_hash_is_keyed(client: TestClient, ctx: SharedContext, saved) -> None:
    # The same well-known key imported under two keystore keys gets two
    # fingerprints, and neither is an unkeyed hash of it.
    longfast = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")
    _import(client, longfast)
    other = SharedContext(Path(ctx.db_path).with_name("other.db"))
    try:
        store, vault = init_crypto_keys(other, {"BRIDGE_KEYSTORE_KEY": KEY_B})
        key_id = store.import_hex(longfast.hex(), "meshtastic", "aes-128-ctr", "lf")
        assert vault.save(store.lookup_key(key_id))
        (hash_a,) = [r[0] for r in ctx.execute("SELECT key_hash FROM crypto_keys")]
        (hash_b,) = [r[0] for r in other.execute("SELECT key_hash FROM crypto_keys")]
    finally:
        other.close()
    assert hash_a != hash_b
    for digest in (hashlib.sha256(longfast).hexdigest(), hashlib.md5(longfast).hexdigest()):
        assert digest not in hash_a and digest not in hash_b


def test_revoke_deletes_the_row_and_zeroes_memory(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    store, _vault = saved
    key_id = _import(client, OPS_KEY).json()["key_id"]
    held = store.lookup_key(key_id)
    assert len(rows(ctx)) == 1

    resp = client.delete(f"/api/crypto/keys/{key_id}")
    assert resp.status_code == 200
    assert rows(ctx) == []
    assert held.key_material == bytearray(len(OPS_KEY))

    install(bridge_app, ctx, WITH_A)
    assert key_id not in [k["key_id"] for k in client.get("/api/crypto/keys").json()]
    resp = client.post(
        "/api/crypto/decrypt",
        json=_decrypt_body(_meshtastic_ct(OPS_KEY), key_id=key_id),
    )
    assert resp.status_code == 404


def test_builtin_keys_are_never_saved(
    client: TestClient, ctx: SharedContext, saved
) -> None:
    store, vault = saved
    assert rows(ctx) == []
    builtins = [k for k in client.get("/api/crypto/keys").json() if k["source"] == "builtin"]
    assert len(builtins) == 2
    assert all(k["persisted"] is False for k in builtins)
    assert vault.save(store.lookup_key(builtins[0]["key_id"])) is False
    assert rows(ctx) == []

    _import(client, OPS_KEY)
    before = rows(ctx)
    assert client.delete(f"/api/crypto/keys/{builtins[1]['key_id']}").status_code == 200
    assert store.lookup_key(builtins[1]["key_id"]) is None
    assert rows(ctx) == before


def test_without_a_keystore_key_keys_stay_memory_only(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext
) -> None:
    install(bridge_app, ctx, {})
    assert _key_warnings(client) == [], "nothing at risk before an import"
    resp = _import(client, OPS_KEY)
    assert resp.status_code == 201 and resp.json()["persisted"] is False
    assert rows(ctx) == []

    status = client.get("/api/crypto/status").json()
    assert status["persistence"] == "disabled"
    assert status["memory_only"] == 1
    assert "BRIDGE_KEYSTORE_KEY" in status["message"]

    health = client.get("/api/health").json()
    assert health["crypto_key_persistence"] == "disabled"
    (warning,) = _key_warnings(client)
    assert "memory only" in warning and "BRIDGE_KEYSTORE_KEY" in warning
    listed = [k for k in client.get("/api/crypto/keys").json() if k["source"] == "import"]
    assert [k["persisted"] for k in listed] == [False]


def test_saved_keys_are_left_alone_when_the_keystore_key_is_removed(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    key_id = _import(client, OPS_KEY).json()["key_id"]
    before = rows(ctx)

    store, vault = install(bridge_app, ctx, {})
    assert vault.state is Persistence.DISABLED
    assert store.lookup_key(key_id) is None
    assert rows(ctx) == before
    status = client.get("/api/crypto/status").json()
    assert status["not_loaded"] == 1 and status["loaded"] == 0
    (warning,) = _key_warnings(client)
    assert "not loaded" in warning

    # Putting the key back loads it again.
    store, vault = install(bridge_app, ctx, WITH_A)
    assert bytes(store.lookup_key(key_id).key_material) == OPS_KEY


def test_a_wrong_keystore_key_keeps_the_rows_and_warns(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    saved,
    caplog: pytest.LogCaptureFixture,
) -> None:
    key_id = _import(client, OPS_KEY).json()["key_id"]
    before = rows(ctx)

    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.crypto_keys"):
        store, vault = install(bridge_app, ctx, {"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert vault.state is Persistence.WRONG_KEY
    assert "does not decrypt any of the 1 saved" in caplog.text
    assert store.lookup_key(key_id) is None
    assert rows(ctx) == before
    health = client.get("/api/health").json()
    assert health["crypto_key_persistence"] == "wrong_key"
    (warning,) = _key_warnings(client)
    assert "was it changed?" in warning

    # A new import is not saved with a key that cannot read the others.
    resp = _import(client, bytes(range(16)))
    assert resp.json()["persisted"] is False
    assert rows(ctx) == before

    store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ENABLED
    assert bytes(store.lookup_key(key_id).key_material) == OPS_KEY


@pytest.mark.parametrize("value", ["not-a-key", KEY_A[:43]], ids=["garbage", "unpadded"])
def test_an_invalid_keystore_key_is_reported_without_its_value(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    saved,
    caplog: pytest.LogCaptureFixture,
    value: str,
) -> None:
    _import(client, OPS_KEY)
    before = rows(ctx)
    with caplog.at_level(logging.DEBUG):
        _store, vault = install(bridge_app, ctx, {"BRIDGE_KEYSTORE_KEY": value})
        status = client.get("/api/crypto/status").json()
        health = client.get("/api/health").json()
    assert vault.state is Persistence.INVALID_KEY
    assert status["persistence"] == health["crypto_key_persistence"] == "invalid_key"
    assert status["not_loaded"] == 1
    texts = [json.dumps(status), json.dumps(health), caplog.text]
    for i in range(len(value) - 7):
        run = value[i : i + 8]
        for text in texts:
            assert run not in text, run
    if len(value) == 43:
        assert "'='" in status["message"]
    else:
        assert "44 characters" in status["message"]
    assert rows(ctx) == before
    assert _import(client, bytes(range(16))).json()["persisted"] is False
    assert rows(ctx) == before


def test_one_damaged_row_does_not_block_the_others(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    saved,
    caplog: pytest.LogCaptureFixture,
) -> None:
    good, flipped, moved = (
        _import(client, bytes([n]) * 16, key_name=f"k{n}").json()["key_id"]
        for n in (1, 2, 3)
    )
    (token,) = ctx.execute(
        "SELECT key_data_encrypted FROM crypto_keys WHERE id = ?", (flipped,)
    ).fetchone()
    damaged = token[:40] + (b"A" if token[40:41] != b"A" else b"B") + token[41:]
    with ctx.write_transaction() as conn:
        conn.execute(
            "UPDATE crypto_keys SET key_data_encrypted = ? WHERE id = ?",
            (damaged, flipped),
        )
        # The envelope binds the protocol: an edited row is not loaded.
        conn.execute("UPDATE crypto_keys SET protocol = 'dmr' WHERE id = ?", (moved,))
    before = rows(ctx)

    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.crypto_keys"):
        store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ENABLED
    assert (vault.loaded, vault.not_loaded) == (1, 2)
    assert store.lookup_key(good) is not None
    assert store.lookup_key(flipped) is None and store.lookup_key(moved) is None
    (record,) = [r for r in caplog.records if "could not be read" in r.getMessage()]
    assert flipped in record.getMessage() and moved in record.getMessage()
    assert rows(ctx) == before
    (warning,) = _key_warnings(client)
    assert "2 saved key(s) could not be read" in warning

    assert _import(client, bytes(range(16))).json()["persisted"] is True


def test_a_failed_save_imports_nothing(
    client: TestClient, ctx: SharedContext, saved, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, vault = saved
    before = store.list_keys()

    def refuse(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(vault._ctx, "write_transaction", refuse)
    resp = _import(client, OPS_KEY)
    assert resp.status_code == 503
    assert resp.json()["detail"] == SAVE_FAILED
    assert store.list_keys() == before
    monkeypatch.undo()
    assert rows(ctx) == []


def test_a_failed_delete_revokes_nothing(
    client: TestClient, ctx: SharedContext, saved, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store, vault = saved
    key_id = _import(client, OPS_KEY).json()["key_id"]

    def refuse(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(vault._ctx, "write_transaction", refuse)
    resp = client.delete(f"/api/crypto/keys/{key_id}")
    assert resp.status_code == 503
    assert resp.json()["detail"] == DELETE_FAILED
    monkeypatch.undo()
    resp = client.post(
        "/api/crypto/decrypt",
        json=_decrypt_body(_meshtastic_ct(OPS_KEY), key_id=key_id),
    )
    assert resp.json()["plaintext_hex"] == TEXT_DATA.hex()
    assert [r[0] for r in rows(ctx)] == [key_id]
    assert vault.is_saved(key_id)


def test_an_unreadable_table_leaves_keys_memory_only(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(self):
        raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(CryptoKeyVault, "_read_rows", unreadable)
    store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ERROR
    assert "DatabaseError" in vault.problem
    assert {k["label"] for k in store.list_keys()} == {
        "meshtastic-default-AQ",
        "meshtastic-LongFast",
    }
    assert _import(client, OPS_KEY).json()["persisted"] is False
    assert rows(ctx) == []
    (warning,) = _key_warnings(client)
    assert "could not be read from the database" in warning


def test_status_role_gates_and_shape(
    bridge_app: FastAPI, persistence: PersistenceManager, saved
) -> None:
    viewer = _client_with_role(bridge_app, persistence, "viewer")
    resp = viewer.get("/api/crypto/status")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Analyst role required"

    analyst = _client_with_role(bridge_app, persistence, "analyst")
    resp = analyst.get("/api/crypto/status")
    assert resp.status_code == 200
    assert set(resp.json()) == {
        "persistence",
        "loaded",
        "not_loaded",
        "memory_only",
        "message",
    }
    assert resp.json()["persistence"] == "enabled"


def test_status_without_a_vault_reports_memory_only(
    bridge_app: FastAPI, client: TestClient
) -> None:
    bridge_app.state.crypto_key_vault = None
    _import(client, OPS_KEY)
    status = client.get("/api/crypto/status").json()
    assert status["persistence"] == "disabled" and status["memory_only"] == 1
    assert client.get("/api/health").json()["crypto_key_persistence"] == "unknown"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("key_name", "n" * 129),
        ("raw_key_hex", "0" * 513),
        ("raw_key_hex", "0" * 1025),
        ("protocol", "p" * 33),
        ("algorithm", "a" * 33),
    ],
)
def test_import_bounds(
    client: TestClient, ctx: SharedContext, saved, field: str, value: str
) -> None:
    store, _vault = saved
    before = store.list_keys()
    body = {"protocol": "dmr", "key_name": "k", "raw_key_hex": "0f" * 16, field: value}
    resp = client.post("/api/crypto/keys", json=body)
    assert resp.status_code == 422
    assert store.list_keys() == before
    assert rows(ctx) == []


def test_the_largest_key_within_the_bounds_round_trips(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    key = os.urandom(256)
    resp = _import(client, key, protocol="generic", key_name="n" * 128)
    assert resp.status_code == 201 and resp.json()["persisted"] is True
    store, _vault = install(bridge_app, ctx, WITH_A)
    assert bytes(store.lookup_key(resp.json()["key_id"]).key_material) == key


def test_an_unexpected_error_on_one_row_never_stops_the_startup(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    saved,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _import(client, OPS_KEY).json()["key_id"]
    _import(client, bytes(range(16)))
    before = rows(ctx)
    real = CryptoKeyVault._open_envelope

    def odd(plaintext, key_id, protocol, algorithm):
        if key_id == first:
            raise TypeError("unexpected")
        return real(plaintext, key_id, protocol, algorithm)

    monkeypatch.setattr(CryptoKeyVault, "_open_envelope", staticmethod(odd))
    store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ENABLED
    assert (vault.loaded, vault.not_loaded) == (1, 1)
    assert store.lookup_key(first) is None
    assert rows(ctx) == before


def test_empty_key_material_is_refused(client: TestClient, ctx: SharedContext, saved) -> None:
    resp = client.post(
        "/api/crypto/keys",
        json={"protocol": "dmr", "key_name": "empty", "raw_key_hex": " : "},
    )
    assert resp.status_code == 400
    assert rows(ctx) == []


# -- load-time integrity: each check has a row that only it rejects ---------


def _envelope_token(key_id: str, material: bytes, **overrides) -> bytes:
    envelope = {
        "algorithm": "aes-128",
        "format": 1,
        "key_id": key_id,
        "material": base64.b64encode(material).decode(),
        "protocol": "meshtastic",
        **overrides,
    }
    return Fernet(KEY_A.encode()).encrypt(
        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
    )


def _edit_hash(conn, victim: str, vault: CryptoKeyVault, victim_key: bytes) -> None:
    other = vault._fingerprint(b"another key entirely")
    conn.execute("UPDATE crypto_keys SET key_hash = ? WHERE id = ?", (other, victim))


def _edit_copy_token(conn, victim: str, vault, victim_key) -> None:
    # The victim's token copied into a new row: the envelope names the
    # victim's id, not the new row's.
    conn.execute(
        "INSERT INTO crypto_keys SELECT 'copied-row', protocol, key_name, "
        "key_data_encrypted, key_hash, algorithm, key_source, associated_source_id, "
        "notes, created_by, tenant_id, created_at, revoked_at FROM crypto_keys "
        "WHERE id = ?",
        (victim,),
    )


def _edit_algorithm(conn, victim: str, vault, victim_key) -> None:
    conn.execute("UPDATE crypto_keys SET algorithm = 'aes-256' WHERE id = ?", (victim,))


def _edit_format(conn, victim: str, vault, victim_key) -> None:
    token = _envelope_token(victim, victim_key, format=2)
    conn.execute(
        "UPDATE crypto_keys SET key_data_encrypted = ? WHERE id = ?", (token, victim)
    )


def _edit_revoked(conn, victim: str, vault, victim_key) -> None:
    conn.execute(
        "UPDATE crypto_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ?", (victim,)
    )


def _edit_tenant(conn, victim: str, vault, victim_key) -> None:
    conn.execute("UPDATE crypto_keys SET tenant_id = 'other' WHERE id = ?", (victim,))


@pytest.mark.parametrize(
    ("edit", "skipped_id", "not_loaded"),
    [
        (_edit_hash, None, 1),
        (_edit_copy_token, "copied-row", 1),
        (_edit_algorithm, None, 1),
        (_edit_format, None, 1),
        (_edit_revoked, None, 0),
        (_edit_tenant, None, 0),
    ],
    ids=["key-hash", "copied-token", "algorithm", "format", "revoked", "tenant"],
)
def test_each_integrity_check_rejects_its_own_row(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    saved,
    edit,
    skipped_id: str | None,
    not_loaded: int,
) -> None:
    _store, vault = saved
    good_key, victim_key = bytes([7]) * 16, bytes([9]) * 16
    good = _import(client, good_key, key_name="good").json()["key_id"]
    victim = _import(client, victim_key, key_name="victim").json()["key_id"]
    # The format case needs a token that is valid in every other way: check
    # that one built here loads when only the format is right.
    if edit is _edit_format:
        with ctx.write_transaction() as conn:
            conn.execute(
                "UPDATE crypto_keys SET key_data_encrypted = ? WHERE id = ?",
                (_envelope_token(victim, victim_key), victim),
            )
        assert install(bridge_app, ctx, WITH_A)[1].loaded == 2
    with ctx.write_transaction() as conn:
        edit(conn, victim, vault, victim_key)
    before = rows(ctx)

    store, vault = install(bridge_app, ctx, WITH_A)
    assert vault.state is Persistence.ENABLED
    assert store.lookup_key(good) is not None
    if skipped_id is None:
        assert store.lookup_key(victim) is None
        expected_loaded = 1
    else:  # the original row still loads; its copy does not
        assert store.lookup_key(skipped_id) is None
        assert store.lookup_key(victim) is not None
        expected_loaded = 2
    assert (vault.loaded, vault.not_loaded) == (expected_loaded, not_loaded)
    assert rows(ctx) == before


# -- revoke: serialised with imports, and the row does not linger -------------


def test_a_revoke_during_an_import_save_deletes_the_saved_row(
    bridge_app: FastAPI, ctx: SharedContext, saved, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The id is listed as soon as the key is in the store, before its row is
    # written: a revoke then must wait for the row and delete it, or the
    # "revoked" key comes back at the next start.
    _store, vault = saved
    request = SimpleNamespace(app=bridge_app)
    real_save = vault.save
    in_save = threading.Event()
    seen: dict[str, object] = {}

    def slow_save(key, created_by=""):
        seen["key_id"] = key.key_id
        in_save.set()
        time.sleep(0.3)  # a revoke that does not wait runs now
        return real_save(key, created_by=created_by)

    monkeypatch.setattr(vault, "save", slow_save)
    body = crypto_router.ImportKeyRequest(
        protocol="meshtastic", key_name="race", raw_key_hex=OPS_KEY.hex()
    )

    def do_import() -> None:
        seen["import"] = crypto_router.import_key(body, request, _key_id="admin")

    def do_revoke() -> None:
        assert in_save.wait(10)
        seen["revoke"] = crypto_router.revoke_key(
            str(seen["key_id"]), request, _key_id="admin"
        )

    threads = [threading.Thread(target=do_import), threading.Thread(target=do_revoke)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    key_id = seen["key_id"]
    assert seen["import"]["persisted"] is True
    assert seen["revoke"] == {"ok": True, "revoked": key_id}
    assert rows(ctx) == []
    store, _vault = install(bridge_app, ctx, WITH_A)
    assert store.lookup_key(key_id) is None


def test_a_key_gone_from_the_store_after_its_row_was_deleted_is_a_404(
    client: TestClient, ctx: SharedContext, saved, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _vault = saved
    key_id = _import(client, OPS_KEY).json()["key_id"]
    monkeypatch.setattr(store, "remove_key", lambda key_id: False)
    resp = client.delete(f"/api/crypto/keys/{key_id}")
    assert resp.status_code == 404
    assert rows(ctx) == []


def test_a_revoked_key_leaves_no_ciphertext_in_the_database_files(
    client: TestClient, ctx: SharedContext, saved
) -> None:
    _store, vault = saved
    key_id = _import(client, OPS_KEY).json()["key_id"]
    (token,) = ctx.execute(
        "SELECT key_data_encrypted FROM crypto_keys WHERE id = ?", (key_id,)
    ).fetchone()
    token = bytes(token)
    ctx.wal_checkpoint()
    files = [Path(ctx.db_path + suffix) for suffix in ("", "-wal", "-shm")]
    assert token in b"".join(f.read_bytes() for f in files if f.exists())

    assert client.delete(f"/api/crypto/keys/{key_id}").status_code == 200
    ctx.wal_checkpoint()
    data = b"".join(f.read_bytes() for f in files if f.exists())
    assert token not in data
    assert token[:40] not in data

    # The connection's own setting is put back afterwards.
    other = _import(client, bytes(range(16))).json()["key_id"]
    conn = ctx.get_conn()
    before = conn.execute("PRAGMA secure_delete").fetchone()[0]
    assert vault.delete(other) is True
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == before


# -- a 422 never repeats the key --------------------------------------------


def _hex_runs(text: str, key_hex: str) -> list[str]:
    """16-digit runs of *key_hex* that *text* repeats."""
    runs = (key_hex[i : i + 16] for i in range(0, len(key_hex) - 16, 8))
    return [run for run in runs if run in text]


@pytest.mark.parametrize(
    "body",
    [
        {"protocol": "dmr", "key_name": "k", "raw_key_hex": "{hex}" * 3},
        {"protocol": "dmr", "raw_key_hex": "{hex}"},
        {"protocol": "dmr", "key_name": "k", "raw_key_hex": "{hex}", "extra": 1},
        {"protocol": "d" * 40, "key_name": "k", "raw_key_hex": "{hex}"},
        [{"raw_key_hex": "{hex}"}],
    ],
    ids=["too-long-text", "missing-field", "extra-field", "bad-protocol", "list-body"],
)
def test_a_rejected_import_never_echoes_the_key(
    client: TestClient, ctx: SharedContext, saved, body
) -> None:
    key_hex = os.urandom(200).hex()
    payload = json.loads(json.dumps(body).replace("{hex}", key_hex))
    resp = client.post("/api/crypto/keys", json=payload)
    assert resp.status_code == 422
    assert _hex_runs(resp.text, key_hex) == []
    assert rows(ctx) == []


def test_a_key_over_256_bytes_is_refused_without_echoing_it(
    client: TestClient, ctx: SharedContext, saved
) -> None:
    key_hex = os.urandom(257).hex()
    resp = client.post(
        "/api/crypto/keys",
        json={"protocol": "dmr", "key_name": "k", "raw_key_hex": key_hex},
    )
    assert resp.status_code == 422
    assert resp.json() == {"detail": "raw_key_hex is too long: at most 256 key bytes"}
    assert rows(ctx) == []


def test_separators_do_not_count_against_the_256_byte_bound(
    client: TestClient, ctx: SharedContext, saved
) -> None:
    key = os.urandom(256)
    spelled = ":".join(f"{b:02x}" for b in key)  # 767 characters
    resp = client.post(
        "/api/crypto/keys",
        json={"protocol": "generic", "key_name": "k", "raw_key_hex": spelled},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["persisted"] is True


# -- BRIDGE_KEYSTORE_KEY must not be a secret the gateway holds -------------


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("BRIDGE_MFA_KEY", KEY_A),
        ("BRIDGE_MFA_KEY", KEY_A.replace("-", "+").replace("_", "/")),
        ("BRIDGE_AUDIT_KEY", KEY_A),
    ],
    ids=["mfa", "mfa-other-alphabet", "audit"],
)
def test_a_keystore_key_reusing_a_gateway_secret_is_warned_about(
    bridge_app: FastAPI,
    client: TestClient,
    ctx: SharedContext,
    caplog: pytest.LogCaptureFixture,
    name: str,
    value: str,
) -> None:
    with caplog.at_level(logging.WARNING, logger="sigrift.bridge.storage.crypto_keys"):
        _store, vault = install(bridge_app, ctx, {**WITH_A, name: value})
    assert vault.state is Persistence.ENABLED
    assert vault.reused_secret == name
    (warning,) = _key_warnings(client)
    assert f"has the same value as {name}, which the gateway also holds" in warning
    assert f"same value as {name}" in client.get("/api/crypto/status").json()["message"]
    assert f"same value as {name}" in caplog.text
    for text in (warning, caplog.text):
        assert KEY_A[:12] not in text and value[:12] not in text
    # Keys are still saved: refusing would strand the rows saved with it.
    assert _import(client, OPS_KEY).json()["persisted"] is True


def test_a_separate_keystore_key_is_not_warned_about(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext
) -> None:
    _store, vault = install(
        bridge_app, ctx, {**WITH_A, "BRIDGE_MFA_KEY": KEY_B, "BRIDGE_AUDIT_KEY": "x"}
    )
    assert vault.reused_secret is None
    assert _key_warnings(client) == []


# -- forget-unreadable: the way out of a lost BRIDGE_KEYSTORE_KEY ------------


def test_forget_unreadable_deletes_only_the_rows_the_key_cannot_read(
    bridge_app: FastAPI, client: TestClient, ctx: SharedContext, saved
) -> None:
    lost = _import(client, OPS_KEY).json()["key_id"]
    _store, vault = install(bridge_app, ctx, {"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert vault.state is Persistence.WRONG_KEY
    before = rows(ctx)

    assert forget_unreadable(ctx, KEY_B, delete=False) == (1, 0)
    assert rows(ctx) == before, "counting changes nothing"

    # A row the new key saved is kept.
    other = SharedContext(Path(ctx.db_path))
    try:
        store_b, vault_b = init_crypto_keys(other, {"BRIDGE_KEYSTORE_KEY": KEY_B})
        vault_b._state = Persistence.ENABLED  # the WRONG_KEY block, lifted here
        kept = store_b.import_hex(bytes(range(16)).hex(), "dmr", "aes-128", "new")
        assert vault_b.save(store_b.lookup_key(kept))
    finally:
        other.close()

    assert forget_unreadable(ctx, KEY_B, delete=True) == (1, 1)
    assert [r[0] for r in rows(ctx)] == [kept]
    assert lost not in [r[0] for r in rows(ctx)]
    _store, vault = install(bridge_app, ctx, {"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert vault.state is Persistence.ENABLED and vault.loaded == 1
    assert _import(client, OPS_KEY).json()["persisted"] is True


@pytest.mark.parametrize("value", [None, "not-a-key"], ids=["unset", "invalid"])
def test_forget_unreadable_needs_a_valid_key(
    client: TestClient, ctx: SharedContext, saved, value: str | None
) -> None:
    _import(client, OPS_KEY)
    before = rows(ctx)
    with pytest.raises(crypto_keys.CryptoKeyStorageError, match="not set to a valid key"):
        forget_unreadable(ctx, value, delete=True)
    assert rows(ctx) == before


def test_the_forget_unreadable_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    data = tmp_path / "data"
    data.mkdir()
    db = data / "detections.db"
    monkeypatch.setenv("BRIDGE_SECRETS_DIR", str(tmp_path / "secrets"))
    seed = SharedContext(db)
    try:
        store, vault = init_crypto_keys(seed, WITH_A)
        key_id = store.import_hex(OPS_KEY.hex(), "meshtastic", "aes-128", "lost")
        assert vault.save(store.lookup_key(key_id))
    finally:
        seed.close()

    monkeypatch.setenv("BRIDGE_KEYSTORE_KEY", KEY_B)
    assert crypto_keys._main(["forget-unreadable", "--db", str(db)]) == 0
    assert "1 saved key(s) cannot be read" in capsys.readouterr().out
    marker = data / restore_marker.RESTORE_MARKER_NAME
    marker.touch()
    assert crypto_keys._main(["forget-unreadable", "--yes", "--db", str(db)]) == 1
    assert "restore incomplete" in capsys.readouterr().err
    marker.unlink()
    assert crypto_keys._main(["forget-unreadable", "--yes", "--db", str(db)]) == 0
    assert "Deleted 1 saved key(s)" in capsys.readouterr().out
    assert crypto_keys._main(["forget-unreadable", "--db", str(db)]) == 0
    assert "Nothing to do: 0 saved key(s)" in capsys.readouterr().out
    monkeypatch.delenv("BRIDGE_KEYSTORE_KEY")
    assert crypto_keys._main(["forget-unreadable", "--db", str(db)]) == 1
    assert "not set to a valid key" in capsys.readouterr().err


# -- the real lifespan loads the saved keys ----------------------------------


def test_the_lifespan_loads_saved_keys_before_the_decode_pipeline(
    tmp_path: Path,
) -> None:
    from .test_lifespan import (
        _lifespan_env,
        _make_app_with_lifespan,
        _patch_data_paths,
        _patch_detection_store,
        _patch_iq_store,
        _patch_pcap_store,
        _patch_persistence_dir,
    )

    tmp_data_dir = tmp_path / "data"
    tmp_data_dir.mkdir()
    seed = SharedContext(tmp_data_dir / "test.db")
    try:
        store, vault = init_crypto_keys(seed, WITH_A)
        key_id = store.import_hex(OPS_KEY.hex(), "meshtastic", "aes-128-ctr", "saved")
        assert vault.save(store.lookup_key(key_id))
    finally:
        seed.close()

    app = _make_app_with_lifespan()
    with (
        patch.dict(os.environ, {**_lifespan_env(tmp_data_dir), **WITH_A}),
        _patch_data_paths(tmp_data_dir),
        _patch_persistence_dir(tmp_data_dir),
        _patch_detection_store(tmp_data_dir),
        _patch_iq_store(tmp_data_dir),
        _patch_pcap_store(tmp_data_dir),
        patch(
            "sigrift.bridge.decode_pipeline.ProtocolDecodePipeline",
            wraps=ProtocolDecodePipeline,
        ) as pipeline,
    ):
        with TestClient(app):
            vault = app.state.crypto_key_vault
            assert vault.state is Persistence.ENABLED
            assert (vault.loaded, vault.not_loaded) == (1, 0)
            key = app.state.crypto_key_store.lookup_key(key_id)
            assert bytes(key.key_material) == OPS_KEY
            assert pipeline.call_args.kwargs["crypto_key_store"] is (
                app.state.crypto_key_store
            )
