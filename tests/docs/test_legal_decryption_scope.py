"""LEGAL.md section 4 must state which decryption the product applies (V7).

LEGAL.md used to say the P25 decryptor was "exposed through the
key-management and POST /decrypt API ... and applied by the decode
pipeline".  Neither can ever return a P25 (or DMR) result: ``try_decrypt``
accepts only ``confidence > 0.5``, the keystream decryptors always report
0.0, the API request model cannot even carry the P25 message indicator, and
the pipeline passes none.  These tests pin both halves: the code facts the
disclosure relies on, and the disclosure itself.  If P25 or DMR is ever
wired into the API or the pipeline, the code-fact tests fail and LEGAL.md
section 4 has to be updated with them.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("cryptography")

from sigrift.lib.crypto.aes_decrypt import (  # noqa: E402
    build_meshtastic_nonce,
    decrypt_p25_phase1,
    decrypt_p25_phase2,
    try_decrypt,
)

_LEGAL = Path(__file__).resolve().parents[2] / "LEGAL.md"


def _section_4() -> str:
    text = _LEGAL.read_text(encoding="utf-8")
    start = text.index("## 4. Decryption Capability Disclosure")
    end = text.index("\n## 5.", start)
    return text[start:end]


def _bullet(section: str, name: str) -> str:
    """The ``- **<name>**`` bullet of *section*, line wrapping collapsed."""
    start = section.index(f"- **{name}**")
    end = section.find("\n- **", start + 1)
    end = section.find("\n\n", start) if end == -1 else end
    return " ".join(section[start:end].split())


# -- code facts ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("protocol", "decryptor", "key_len"),
    [("p25_phase1", decrypt_p25_phase1, 8), ("p25_phase2", decrypt_p25_phase2, 32)],
)
def test_try_decrypt_never_returns_p25_even_for_the_right_key(
    protocol, decryptor, key_len
) -> None:
    key, mi = os.urandom(key_len), os.urandom(8)
    voice = os.urandom(99)  # one LDU1: 9 packed 11-byte IMBE codewords
    # OFB is an XOR: "decrypting" the plaintext gives its ciphertext.
    ciphertext = decryptor(voice, key, mi, frame_type="ldu1").plaintext
    right = decryptor(ciphertext, key, mi, frame_type="ldu1")
    assert right.error is None and right.plaintext == voice
    assert right.confidence == 0.0
    # try_decrypt (what the API and the pipeline use) still returns nothing,
    # with or without the P25-only parameters.
    for params in ({}, {"message_indicator": mi, "frame_type": "ldu1"}):
        assert try_decrypt(ciphertext, protocol, [(key, "k")], **params) is None


def test_decrypt_api_cannot_carry_the_p25_parameters() -> None:
    from pydantic import ValidationError

    from sigrift.bridge.routers.crypto import DecryptRequest

    fields = set(DecryptRequest.model_fields)
    assert not fields & {"message_indicator", "frame_type", "codeword_index"}
    with pytest.raises(ValidationError):
        DecryptRequest(
            payload_hex="00" * 99,
            protocol="p25_phase2",
            message_indicator="00" * 8,
        )


def _meshtastic_ciphertext(key: bytes, packet_id: int, node: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = b"\x08\x01" + b"\x12\x05hello"  # Data{portnum: TEXT, payload}
    nonce = build_meshtastic_nonce(packet_id, node)
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(data) + enc.finalize()


def test_decode_pipeline_decrypts_meshtastic_only() -> None:
    from sigrift.bridge.decode_pipeline import ProtocolDecodePipeline
    from sigrift.lib.crypto.key_store import KeyStore

    store = KeyStore()
    mesh_key = os.urandom(16)
    store.add_key("meshtastic", "aes-128", mesh_key, "mesh")
    store.add_key("p25", "aes-256", os.urandom(32), "p25")
    store.add_key("dmr", "des", os.urandom(5), "dmr")
    pipeline = ProtocolDecodePipeline(None, store)

    def message(payload: bytes, **metadata: object) -> SimpleNamespace:
        return SimpleNamespace(payload=payload, decrypted=False, metadata=metadata)

    # Positive control: a Meshtastic message with its stored key decrypts.
    mesh = message(
        _meshtastic_ciphertext(mesh_key, 7, 0x1234), packet_id=7, source_node=0x1234
    )
    pipeline._try_auto_decrypt([mesh], "meshtastic")
    assert mesh.decrypted is True

    # P25 and DMR messages stay encrypted whatever keys are stored.
    p25 = message(os.urandom(99), message_indicator=os.urandom(8).hex())
    dmr = message(os.urandom(27))
    pipeline._try_auto_decrypt([p25], "p25")
    pipeline._try_auto_decrypt([dmr], "dmr")
    assert p25.decrypted is False and dmr.decrypted is False


# -- the disclosure -------------------------------------------------------------


def test_legal_md_scopes_api_and_pipeline_decryption_to_meshtastic() -> None:
    section = _section_4()
    mesh = _bullet(section, "Meshtastic")
    assert "only" in mesh
    assert "POST /api/crypto/decrypt" in mesh and "decode pipeline" in mesh

    p25 = _bullet(section, "P25")
    assert "library-level helper only" in p25
    assert "neither the API nor the decode pipeline calls it" in p25
    assert "decrypt_p25_phase1" in p25 and "decrypt_p25_phase2" in p25
    assert "message indicator" in p25
    assert "unverified" in p25

    dmr = _bullet(section, "DMR")
    assert "library-level" in dmr
    assert "cannot be enabled through the API or the decode pipeline" in dmr

    text = " ".join(section.split())
    assert "which today means Meshtastic only" in text
