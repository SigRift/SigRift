"""Refusal and decryption paths of the crypto admin API (``/api/crypto``).

The basic CRUD calls are in ``test_router_coverage_20260326.py``. These pin
what the API does when something is wrong: every endpoint fails closed with
503 when no key store is wired, malformed hex is refused before anything is
stored, a store's own refusal is a 400 (not a 500), a missing or revoked key
cannot be used, a protocol without keys is a 404, and the role gates hold.
They also decrypt a real Meshtastic payload end to end, with the packet
parameters, and show that naming a key restricts the trial to that key.
"""

from __future__ import annotations

import base64
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.crypto.key_store import KeyStore
from sigrift.lib.security.credentials import generate_api_key, hash_credential

# The Meshtastic LongFast default PSK, which the key store ships as a builtin.
LONGFAST = base64.b64decode("1PG7OiApB1nwvP+rz05pAQ==")
OPS_KEY = bytes(range(0xA0, 0xB0))
# A Meshtastic Data protobuf: portnum=1 (TEXT_MESSAGE_APP), payload="hello".
TEXT_DATA = bytes([0x08, 0x01, 0x12, 0x05]) + b"hello"
PACKET_ID = 0x0BADF00D
SOURCE_NODE = 0xA1B2C3D4
NO_CONFIDENT_KEY = {
    "success": False,
    "error": "No key produced a confident decryption",
}


def _meshtastic_ct(key: bytes) -> bytes:
    """TEXT_DATA encrypted as Meshtastic firmware does (AES-CTR)."""
    nonce = struct.pack("<QI4x", PACKET_ID, SOURCE_NODE)
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(TEXT_DATA) + enc.finalize()


def _decrypt_body(ciphertext: bytes, **extra: object) -> dict:
    return {
        "payload_hex": ciphertext.hex(),
        "protocol": "meshtastic",
        "packet_id": PACKET_ID,
        "source_node": SOURCE_NODE,
        **extra,
    }


def _client_with_role(
    app: FastAPI, persistence: PersistenceManager, role: str
) -> TestClient:
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key(f"crypto-{role}", hash_hex, salt)
    persistence.set_key_meta(f"crypto-{role}", {"role": role, "description": role})
    return TestClient(app, headers={"X-API-Key": raw_key})


@pytest.fixture
def store(bridge_app: FastAPI) -> KeyStore:
    return bridge_app.state.crypto_key_store


@pytest.fixture
def longfast_id(store: KeyStore) -> str:
    (key,) = [k for k in store.list_keys() if k["label"] == "meshtastic-LongFast"]
    return key["key_id"]


@pytest.fixture
def ops_key_id(client: TestClient) -> str:
    resp = client.post(
        "/api/crypto/keys",
        json={
            "protocol": "meshtastic",
            "key_name": "ops-channel",
            "raw_key_hex": ":".join(f"{b:02x}" for b in OPS_KEY),
        },
    )
    assert resp.status_code == 201
    return resp.json()["key_id"]


# ---------------------------------------------------------------------------
# No key store
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/api/crypto/keys", None),
        (
            "POST",
            "/api/crypto/keys",
            {"protocol": "dmr", "key_name": "k", "raw_key_hex": "0f" * 16},
        ),
        ("DELETE", "/api/crypto/keys/some-id", None),
        ("POST", "/api/crypto/decrypt", {"payload_hex": "aabb", "protocol": "p25"}),
    ],
)
def test_every_endpoint_fails_closed_without_a_key_store(
    bridge_app: FastAPI, client: TestClient, method: str, path: str, body: dict
) -> None:
    bridge_app.state.crypto_key_store = None
    resp = client.request(method, path, json=body)
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Crypto key store not initialised"


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_key_hex",
    ["a0a1a2a3a4a5a6a7a8a9aaabacadaeafzz", "abc", "0x0102", "0g"],
)
def test_import_refuses_malformed_hex_before_storing_anything(
    client: TestClient, store: KeyStore, raw_key_hex: str
) -> None:
    before = store.list_keys()
    resp = client.post(
        "/api/crypto/keys",
        json={"protocol": "dmr", "key_name": "typo", "raw_key_hex": raw_key_hex},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"].startswith("Invalid hex key material")
    assert store.list_keys() == before


def test_a_store_refusal_is_a_400_not_a_server_error(
    bridge_app: FastAPI, client: TestClient
) -> None:
    class StrictStore(KeyStore):
        def import_hex(self, hex_str, protocol, algorithm, label):
            raise ValueError(f"algorithm {algorithm!r} is not supported for {protocol}")

    bridge_app.state.crypto_key_store = StrictStore()
    resp = client.post(
        "/api/crypto/keys",
        json={
            "protocol": "dmr",
            "key_name": "k",
            "raw_key_hex": "0f" * 16,
            "algorithm": "rot13",
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "algorithm 'rot13' is not supported for dmr"
    assert client.get("/api/crypto/keys").json() == []


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload_hex", ["zz", "abc", "de:ad:be:eg"])
def test_decrypt_refuses_a_malformed_hex_payload(
    client: TestClient, payload_hex: str
) -> None:
    resp = client.post(
        "/api/crypto/decrypt",
        json={"payload_hex": payload_hex, "protocol": "meshtastic"},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"].startswith("Invalid hex payload")


def test_decrypt_with_packet_parameters_recovers_the_plaintext(
    client: TestClient, longfast_id: str
) -> None:
    body = _decrypt_body(_meshtastic_ct(LONGFAST))
    # Separators are accepted in the payload, as in key material.
    body["payload_hex"] = ":".join(
        body["payload_hex"][i : i + 2] for i in range(0, len(body["payload_hex"]), 2)
    )
    resp = client.post("/api/crypto/decrypt", json=body)
    assert resp.status_code == 200
    assert resp.json() == {
        "success": True,
        "plaintext_hex": TEXT_DATA.hex(),
        "protocol": "meshtastic",
        "algorithm": "aes-128-ctr",
        "key_id": longfast_id,
        "confidence": 0.95,
        "error": None,
    }


def test_without_packet_parameters_no_key_is_confident(client: TestClient) -> None:
    # The Meshtastic nonce needs packet_id and source_node; without them no
    # key can be checked, so none is reported as the right one.
    resp = client.post(
        "/api/crypto/decrypt",
        json={"payload_hex": _meshtastic_ct(LONGFAST).hex(), "protocol": "meshtastic"},
    )
    assert resp.status_code == 200
    assert resp.json() == NO_CONFIDENT_KEY


def test_naming_a_key_tries_only_that_key(
    client: TestClient, longfast_id: str, ops_key_id: str
) -> None:
    ciphertext = _meshtastic_ct(OPS_KEY)

    # Trial over every Meshtastic key finds the imported one ...
    resp = client.post("/api/crypto/decrypt", json=_decrypt_body(ciphertext))
    assert resp.json()["success"] is True
    assert resp.json()["key_id"] == ops_key_id

    # ... naming it uses it ...
    resp = client.post(
        "/api/crypto/decrypt", json=_decrypt_body(ciphertext, key_id=ops_key_id)
    )
    assert resp.json()["key_id"] == ops_key_id
    assert resp.json()["plaintext_hex"] == TEXT_DATA.hex()

    # ... and naming another key does not fall back to the rest.
    resp = client.post(
        "/api/crypto/decrypt", json=_decrypt_body(ciphertext, key_id=longfast_id)
    )
    assert resp.status_code == 200
    assert resp.json() == NO_CONFIDENT_KEY


def test_a_revoked_key_can_no_longer_decrypt(
    client: TestClient, store: KeyStore, ops_key_id: str
) -> None:
    ciphertext = _meshtastic_ct(OPS_KEY)
    assert client.delete(f"/api/crypto/keys/{ops_key_id}").status_code == 200
    assert store.lookup_key(ops_key_id) is None

    resp = client.post(
        "/api/crypto/decrypt", json=_decrypt_body(ciphertext, key_id=ops_key_id)
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == f"Key {ops_key_id!r} not found"

    resp = client.post("/api/crypto/decrypt", json=_decrypt_body(ciphertext))
    assert resp.json() == NO_CONFIDENT_KEY


def test_decrypt_for_a_protocol_without_keys_is_a_404(client: TestClient) -> None:
    resp = client.post(
        "/api/crypto/decrypt",
        json={"payload_hex": "00" * 32, "protocol": "dmr_basic"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"] == "No keys available for protocol 'dmr_basic'"


# ---------------------------------------------------------------------------
# Role gates
# ---------------------------------------------------------------------------


def test_an_analyst_cannot_import_or_revoke_keys(
    bridge_app: FastAPI,
    persistence: PersistenceManager,
    store: KeyStore,
    longfast_id: str,
) -> None:
    analyst = _client_with_role(bridge_app, persistence, "analyst")
    before = store.list_keys()

    resp = analyst.post(
        "/api/crypto/keys",
        json={"protocol": "dmr", "key_name": "k", "raw_key_hex": "0f" * 16},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin role required"

    resp = analyst.delete(f"/api/crypto/keys/{longfast_id}")
    assert resp.status_code == 403
    assert store.list_keys() == before

    # Reading and decrypting are analyst work.
    assert analyst.get("/api/crypto/keys").status_code == 200
    resp = analyst.post("/api/crypto/decrypt", json=_decrypt_body(b"\x00" * 9))
    assert resp.status_code == 200


def test_a_viewer_cannot_list_keys_or_decrypt(
    bridge_app: FastAPI, persistence: PersistenceManager
) -> None:
    viewer = _client_with_role(bridge_app, persistence, "viewer")
    resp = viewer.get("/api/crypto/keys")
    assert resp.status_code == 403
    assert resp.json()["detail"] == "Analyst role required"
    resp = viewer.post(
        "/api/crypto/decrypt", json=_decrypt_body(_meshtastic_ct(LONGFAST))
    )
    assert resp.status_code == 403
