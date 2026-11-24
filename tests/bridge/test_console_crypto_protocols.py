"""The admin console's crypto forms send protocol names the API acts on.

``admin.html``'s Import Key and Manual Decrypt forms used to send
``Meshtastic``/``DMR``/``P25``/``LoRa``, while the key store files keys as
``meshtastic``/``dmr``/``p25`` and matches names case-sensitively: a console
decrypt never reached the built-in Meshtastic keys, and a key imported from
the console was filed under a name the decode pipeline never looks up.
These tests read the options from the shipped template and post them the
way ``crypto_admin.js`` does, to the real endpoints: a Meshtastic payload
decrypts with a key imported from the console, every decrypt protocol
reaches the same decryptor as the decode pipeline, and DMR and P25 requests
still answer "No key produced a confident decryption" (LEGAL.md section 4).
"""

from __future__ import annotations

import os
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi.testclient import TestClient

import sigrift.bridge
from sigrift.bridge.decode_pipeline import ProtocolDecodePipeline
from sigrift.lib.crypto import aes_decrypt
from sigrift.lib.crypto.key_store import KeyStore

_ADMIN_HTML = Path(sigrift.bridge.__file__).parent / "templates" / "admin.html"

OPS_KEY = bytes(range(0xA0, 0xB0))
# A Meshtastic Data protobuf: portnum=1 (TEXT_MESSAGE_APP), payload="hello".
TEXT_DATA = bytes([0x08, 0x01, 0x12, 0x05]) + b"hello"
PACKET_ID = 0x0BADF00D
SOURCE_NODE = 0xA1B2C3D4
NO_CONFIDENT_KEY = {
    "success": False,
    "error": "No key produced a confident decryption",
}


class _Options(HTMLParser):
    """``(label, value)`` of each ``<option>`` in the ``<select>`` *select_id*."""

    def __init__(self, select_id: str) -> None:
        super().__init__()
        self._select_id = select_id
        self._inside = False
        self._value: str | None = None
        self._label = ""
        self.options: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "select" and dict(attrs).get("id") == self._select_id:
            self._inside = True
        elif tag == "option" and self._inside:
            self._value, self._label = dict(attrs)["value"], ""

    def handle_data(self, data: str) -> None:
        if self._value is not None:
            self._label += data

    def handle_endtag(self, tag: str) -> None:
        if tag == "option" and self._value is not None:
            self.options.append((self._label.strip(), self._value))
            self._value = None
        elif tag == "select":
            self._inside = False


def _options(select_id: str) -> list[tuple[str, str]]:
    parser = _Options(select_id)
    parser.feed(_ADMIN_HTML.read_text(encoding="utf-8"))
    assert parser.options, f"admin.html has no options for #{select_id}"
    return parser.options


IMPORT_PROTOCOLS = dict(_options("crypto-import-protocol"))
DECRYPT_PROTOCOLS = dict(_options("crypto-decrypt-protocol"))
# The algorithm the import form starts on.
DEFAULT_ALGORITHM = _options("crypto-import-algorithm")[0][1]


def _meshtastic_ct(key: bytes) -> bytes:
    """TEXT_DATA encrypted as Meshtastic firmware does (AES-CTR)."""
    nonce = aes_decrypt.build_meshtastic_nonce(PACKET_ID, SOURCE_NODE)
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(TEXT_DATA) + enc.finalize()


def _console_import(client: TestClient, protocol: str, key: bytes) -> str:
    """Import *key* with the body ``crypto_admin.js`` sends."""
    resp = client.post(
        "/api/crypto/keys",
        json={
            "protocol": protocol,
            "key_name": f"console {protocol}",
            "raw_key_hex": key.hex(),
            "algorithm": DEFAULT_ALGORITHM,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["key_id"]


def _console_decrypt(protocol: str, ciphertext: bytes, **extra: object) -> dict:
    """The body ``crypto_admin.js`` sends with every Manual Decrypt field set."""
    return {
        "protocol": protocol,
        "payload_hex": ciphertext.hex(),
        "packet_id": PACKET_ID,
        "source_node": SOURCE_NODE,
        **extra,
    }


@pytest.fixture
def store(bridge_app) -> KeyStore:
    return bridge_app.state.crypto_key_store


@pytest.fixture
def decryptor_protocols(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The ``protocol`` of every ``try_decrypt`` call (the API and the
    pipeline both import it at call time)."""
    calls: list[str] = []
    real = aes_decrypt.try_decrypt

    def spy(ciphertext, protocol, keys, **params):
        calls.append(protocol)
        return real(ciphertext, protocol, keys, **params)

    monkeypatch.setattr(aes_decrypt, "try_decrypt", spy)
    return calls


def test_every_decrypt_protocol_can_have_keys_imported_from_the_console() -> None:
    assert DECRYPT_PROTOCOLS.items() <= IMPORT_PROTOCOLS.items()


@pytest.mark.parametrize("label", sorted(IMPORT_PROTOCOLS))
def test_the_console_files_an_imported_key_under_its_protocol(
    client: TestClient, label: str
) -> None:
    protocol = IMPORT_PROTOCOLS[label]
    key_id = _console_import(client, protocol, OPS_KEY)
    listed = client.get("/api/crypto/keys", params={"protocol": protocol}).json()
    assert key_id in [key["key_id"] for key in listed]


def test_console_meshtastic_decrypt_recovers_the_plaintext(
    client: TestClient, store: KeyStore
) -> None:
    key_id = _console_import(client, IMPORT_PROTOCOLS["Meshtastic"], OPS_KEY)
    resp = client.post(
        "/api/crypto/decrypt",
        json=_console_decrypt(DECRYPT_PROTOCOLS["Meshtastic"], _meshtastic_ct(OPS_KEY)),
    )
    assert resp.status_code == 200
    assert resp.json() == {
        "success": True,
        "plaintext_hex": TEXT_DATA.hex(),
        "protocol": "meshtastic",
        "algorithm": "aes-128-ctr",
        "key_id": key_id,
        "confidence": 0.95,
        "error": None,
    }

    # The decode pipeline decrypts with the same imported key.
    message = SimpleNamespace(
        payload=_meshtastic_ct(OPS_KEY),
        decrypted=False,
        metadata={"packet_id": PACKET_ID, "source_node": SOURCE_NODE},
    )
    ProtocolDecodePipeline(None, store)._try_auto_decrypt([message], "meshtastic")
    assert message.decrypted is True and message.key_id == key_id


@pytest.mark.parametrize("label", sorted(DECRYPT_PROTOCOLS))
def test_console_decrypt_reaches_the_decryptor_the_pipeline_uses(
    client: TestClient,
    store: KeyStore,
    decryptor_protocols: list[str],
    label: str,
) -> None:
    protocol = DECRYPT_PROTOCOLS[label]
    _console_import(client, IMPORT_PROTOCOLS[label], OPS_KEY)
    resp = client.post(
        "/api/crypto/decrypt", json=_console_decrypt(protocol, b"\x00" * 16)
    )
    assert resp.status_code == 200, resp.text
    message = SimpleNamespace(payload=b"\x00" * 16, decrypted=False, metadata={})
    ProtocolDecodePipeline(None, store)._try_auto_decrypt([message], protocol)

    api, pipeline = decryptor_protocols
    assert api == pipeline
    assert api in aes_decrypt._PROTOCOL_DECRYPTORS


@pytest.mark.parametrize("label", ["DMR", "P25"])
def test_console_dmr_and_p25_requests_never_decrypt(
    client: TestClient, label: str
) -> None:
    # LEGAL.md section 4: "a P25 or DMR request to POST /api/crypto/decrypt
    # always answers 'No key produced a confident decryption'".
    key = os.urandom(32)
    key_id = _console_import(client, IMPORT_PROTOCOLS[label], key)
    ciphertext = os.urandom(99)
    for extra in ({}, {"key_id": key_id}):
        resp = client.post(
            "/api/crypto/decrypt",
            json=_console_decrypt(DECRYPT_PROTOCOLS[label], ciphertext, **extra),
        )
        assert resp.status_code == 200
        assert resp.json() == NO_CONFIDENT_KEY
