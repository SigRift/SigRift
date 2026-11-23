"""Security-path tests for ``sigrift.lib.crypto`` (key store and decryptors).

Real AES / DES through ``cryptography``, no mocks. Covers what the golden
and Meshtastic tests do not: key material never shown by ``repr``, list
or logs, zeroing on removal, the store keeping its own copy of a key,
import errors that do not echo the key, wrong key sizes, truncated or
corrupted ciphertext, bad message-indicator / IV lengths, malformed
parameters, and trial decryption carrying on past keys and decryptors
that fail.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sigrift.lib.crypto import (
    CryptoKey,
    DecryptResult,
    KeyStore,
    decrypt_dmr_basic,
    decrypt_dmr_enhanced,
    decrypt_meshtastic,
    decrypt_p25_phase1,
    decrypt_p25_phase2,
    p25_voice_keystream_offset,
    try_decrypt,
)

# Meshtastic LongFast default PSK, as the key store ships it.
LONGFAST_B64 = "1PG7OiApB1nwvP+rz05pAQ=="
LONGFAST = base64.b64decode(LONGFAST_B64)

# Distinctive key bytes, so a leak is easy to spot and never collides with
# the zero padding in nonces.
KEY16 = bytes(range(0xA0, 0xB0))
KEY32 = bytes(range(0xC0, 0xE0))
DES8 = bytes.fromhex("13579bdf02468ace")


def _key_forms(key: bytes) -> list[str]:
    """The ways a key could show up in text."""
    return [
        key.hex(),
        key.hex().upper(),
        base64.b64encode(key).decode(),
        repr(key)[2:-1],
    ]


def _assert_no_key(result: DecryptResult, key: bytes) -> None:
    text = " ".join(
        str(x) for x in (result.error, result.reason, result.nonce_hex, repr(result))
    )
    for form in _key_forms(key):
        if form:
            assert form not in text


def _meshtastic_ct(plaintext: bytes, key: bytes, packet_id: int, node: int) -> bytes:
    nonce = struct.pack("<QI4x", packet_id, node)  # firmware initNonce layout
    enc = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return enc.update(plaintext) + enc.finalize()


# A Meshtastic Data protobuf: portnum=1 (TEXT_MESSAGE_APP), payload="hello".
TEXT_DATA = bytes([0x08, 0x01, 0x12, 0x05]) + b"hello"


# ---------------------------------------------------------------------------
# KeyStore
# ---------------------------------------------------------------------------


class TestKeyStoreSecrecy:
    def test_repr_never_shows_key_material(self) -> None:
        store = KeyStore()
        kid = store.add_key("meshtastic", "aes-128-ctr", KEY16, "ops")
        key = store.lookup_key(kid)
        assert isinstance(key, CryptoKey)
        for text in (repr(key), str(key), repr([key]), f"{key}"):
            assert "key_len=16" in text
            for form in _key_forms(KEY16):
                assert form not in text

    def test_list_keys_is_metadata_only_and_filters_by_protocol(self) -> None:
        store = KeyStore()
        a = store.add_key("meshtastic", "aes-128-ctr", KEY16, "a", metadata={"x": 1})
        b = store.add_key("p25", "des-ofb", DES8, "b")
        assert len(store) == 2
        listed = {k["key_id"]: k for k in store.list_keys()}
        assert set(listed) == {a, b}
        assert listed[a]["key_len"] == 16 and listed[b]["key_len"] == 8
        assert [k["key_id"] for k in store.list_keys(protocol="p25")] == [b]
        assert store.list_keys(protocol="dmr") == []
        flat = repr(store.list_keys())
        for key in (KEY16, DES8):
            for form in _key_forms(key):
                assert form not in flat
        assert [k.key_id for k in store.lookup_by_protocol("meshtastic")] == [a]
        assert store.lookup_by_protocol("dmr") == []

    def test_store_keeps_its_own_copy(self) -> None:
        caller = bytearray(KEY16)
        store = KeyStore()
        kid = store.add_key("meshtastic", "aes-128-ctr", caller, "copy")
        caller[:] = b"\x00" * len(caller)  # the caller wipes its buffer ...
        assert bytes(store.lookup_key(kid).key_material) == KEY16  # ... ours stays

    def test_remove_key_zeroes_the_material(self) -> None:
        store = KeyStore()
        kid = store.add_key("meshtastic", "aes-128-ctr", KEY16, "gone")
        held = store.lookup_key(kid).key_material  # a reference someone kept
        assert store.remove_key(kid) is True
        assert held == bytearray(len(KEY16))
        assert store.lookup_key(kid) is None
        assert store.remove_key(kid) is False
        assert len(store) == 0

    def test_zeroing_an_empty_key_is_harmless(self) -> None:
        empty = bytearray()
        KeyStore._zero_bytes(empty)
        assert empty == bytearray()

    def test_logs_never_contain_key_material(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        store = KeyStore()
        with caplog.at_level(logging.DEBUG, logger="sigrift.lib.crypto"):
            store.load_builtin_defaults()
            kid = store.add_key("meshtastic", "aes-256-ctr", KEY32, "k32")
            store.import_hex(KEY16.hex(), "meshtastic", "aes-128-ctr", "hex")
            store.import_base64(
                base64.b64encode(DES8).decode(), "p25", "des-ofb", "b64"
            )
            derived = store.derive_meshtastic_psk("secret-channel")
            store.remove_key(kid)
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "Added key" in text and "Removed and zeroed key" in text
        for key in (KEY32, KEY16, DES8, derived, LONGFAST):
            for form in _key_forms(key):
                assert form not in text


class TestKeyImport:
    def test_import_hex_accepts_separators(self) -> None:
        store = KeyStore()
        spaced = " ".join(KEY16[i : i + 2].hex() for i in range(0, 16, 2))
        coloned = ":".join(f"{b:02X}" for b in KEY16)
        for text in (KEY16.hex(), spaced, coloned):
            kid = store.import_hex(text, "meshtastic", "aes-128-ctr", "imported")
            key = store.lookup_key(kid)
            # The temporary buffer is wiped after import; the stored copy is not.
            assert bytes(key.key_material) == KEY16
            assert key.source == "import" and key.protocol == "meshtastic"

    def test_import_base64(self) -> None:
        store = KeyStore()
        kid = store.import_base64(LONGFAST_B64, "meshtastic", "aes-128-ctr", "lf")
        assert bytes(store.lookup_key(kid).key_material) == LONGFAST

    @pytest.mark.parametrize(
        ("method", "secret"),
        [
            ("import_hex", "a0a1a2a3a4a5a6a7a8a9aaabacadaeafzz"),
            ("import_hex", "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0"),
            # 21 characters: one more than a multiple of 4, so undecodable.
            ("import_base64", base64.b64encode(KEY16).decode()[:21]),
        ],
    )
    def test_import_errors_do_not_echo_the_key(self, method: str, secret: str) -> None:
        store = KeyStore()
        with pytest.raises(ValueError) as exc:
            getattr(store, method)(secret, "meshtastic", "aes-128-ctr", "my-label")
        message = str(exc.value)
        assert "my-label" in message
        assert secret not in message
        assert secret[:16] not in message
        assert len(store) == 0


class TestKeyDerivation:
    @pytest.mark.parametrize("size", [16, 32])
    def test_derive_meshtastic_psk(self, size: int) -> None:
        store = KeyStore()
        psk = store.derive_meshtastic_psk("ops-channel", key_size=size)
        assert psk == hashlib.sha256(b"ops-channel").digest()[:size]
        (key,) = store.lookup_by_protocol("meshtastic")
        assert bytes(key.key_material) == psk
        assert key.algorithm == f"aes-{size * 8}-ctr" and key.source == "derived"

    @pytest.mark.parametrize("size", [0, 8, 24, 64])
    def test_derive_rejects_other_sizes(self, size: int) -> None:
        store = KeyStore()
        with pytest.raises(ValueError, match="16 or 32"):
            store.derive_meshtastic_psk("ops-channel", key_size=size)
        assert len(store) == 0


# ---------------------------------------------------------------------------
# Meshtastic AES-CTR
# ---------------------------------------------------------------------------


class TestMeshtastic:
    def test_round_trip_with_128_and_256_bit_keys(self) -> None:
        for key in (LONGFAST, KEY32):
            ct = _meshtastic_ct(TEXT_DATA, key, 0x1234, 0xBEEF)
            result = decrypt_meshtastic(ct, key, 0x1234, 0xBEEF, key_id="k")
            assert result.plaintext == TEXT_DATA
            assert result.confidence > 0.5 and result.error is None
            assert result.algorithm == f"aes-{len(key) * 8}-ctr"

    def test_wrong_nonce_inputs_are_not_verified(self) -> None:
        ct = _meshtastic_ct(TEXT_DATA, LONGFAST, 0x1234, 0xBEEF)
        for packet_id, node in ((0x1235, 0xBEEF), (0x1234, 0xBEEE)):
            result = decrypt_meshtastic(ct, LONGFAST, packet_id, node)
            assert result.confidence == 0.0
        assert (
            try_decrypt(
                ct, "meshtastic", [(LONGFAST, "lf")], packet_id=1, source_node=2
            )
            is None
        )

    @pytest.mark.parametrize("cut", range(3, len(TEXT_DATA)))
    def test_truncated_ciphertext_is_not_verified(self, cut: int) -> None:
        ct = _meshtastic_ct(TEXT_DATA, LONGFAST, 7, 9)[:cut]
        result = decrypt_meshtastic(ct, LONGFAST, 7, 9)
        assert result.plaintext == TEXT_DATA[:cut]  # CTR: a prefix decrypts
        assert result.confidence == 0.0  # ... but is not a valid Data message
        assert (
            try_decrypt(
                ct, "meshtastic", [(LONGFAST, "lf")], packet_id=7, source_node=9
            )
            is None
        )

    def test_corrupted_length_field_is_not_verified(self) -> None:
        ct = bytearray(_meshtastic_ct(TEXT_DATA, LONGFAST, 7, 9))
        ct[3] ^= 0x01  # payload length 5 -> 4: a stray byte is left over
        assert decrypt_meshtastic(bytes(ct), LONGFAST, 7, 9).confidence == 0.0

    def test_empty_ciphertext_is_not_verified(self) -> None:
        result = decrypt_meshtastic(b"", LONGFAST, 7, 9)
        assert result.plaintext == b"" and result.confidence == 0.0

    @pytest.mark.parametrize("size", [0, 1, 15, 17, 31, 33, 64])
    def test_bad_key_sizes_report_an_error_without_the_key(self, size: int) -> None:
        key = (KEY16 + KEY32 + KEY16)[:size]
        result = decrypt_meshtastic(b"\x01" * 16, key, 7, 9, key_id="bad")
        assert result.plaintext == b"" and result.confidence == 0.0
        # (64 bytes is an AES-XTS size, refused by CTR with another message.)
        assert result.error.startswith("Decryption failed:")
        assert result.key_id == "bad"
        _assert_no_key(result, key)


# ---------------------------------------------------------------------------
# Trial decryption
# ---------------------------------------------------------------------------


class TestTryDecrypt:
    def test_skips_unusable_keys_and_finds_the_right_one(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        ct = _meshtastic_ct(TEXT_DATA, LONGFAST, 42, 43)
        keys = [
            (b"", "empty"),
            (KEY16[:15], "short"),
            (KEY16, "wrong"),
            (KEY32, "wrong-256"),
            (LONGFAST, "right"),
        ]
        with caplog.at_level(logging.DEBUG, logger="sigrift.lib.crypto"):
            result = try_decrypt(ct, "meshtastic", keys, packet_id=42, source_node=43)
        assert result is not None
        assert result.key_id == "right" and result.plaintext == TEXT_DATA
        text = "\n".join(r.getMessage() for r in caplog.records)
        assert "key_id=right" in text
        for key, _ in keys:
            for form in _key_forms(key):
                if form:
                    assert form not in text

    def test_unknown_protocol(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.crypto"):
            assert try_decrypt(b"\x00" * 16, "tetra", [(KEY16, "k")]) is None
        assert any("Unknown protocol" in r.getMessage() for r in caplog.records)
        assert not any(KEY16.hex() in r.getMessage() for r in caplog.records)

    def test_a_decryptor_that_raises_does_not_stop_the_trial(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """An out-of-range MI makes the P25 decryptor raise for every key."""
        keys = [(DES8, "des-a"), (DES8[::-1], "des-b")]
        with caplog.at_level(logging.DEBUG, logger="sigrift.lib.crypto"):
            result = try_decrypt(
                b"\x00" * 11,
                "p25_phase1",
                keys,
                message_indicator=[0x1FF] * 8,
                frame_type="ldu1",
            )
        assert result is None
        errors = [
            r.getMessage() for r in caplog.records if "error for key" in r.getMessage()
        ]
        assert len(errors) == 2
        for message in errors:
            for key, _ in keys:
                assert key.hex() not in message


# ---------------------------------------------------------------------------
# DMR (experimental paths)
# ---------------------------------------------------------------------------


class TestDmr:
    def test_basic_privacy_rejects_an_empty_key(self) -> None:
        result = decrypt_dmr_basic(b"\x12\x34", b"", experimental=True)
        assert result.error == "Empty key" and result.plaintext == b""

    @pytest.mark.parametrize("length", [0, 3, 5, 8, 15, 17])
    def test_enhanced_rejects_bad_mi_lengths(self, length: int) -> None:
        result = decrypt_dmr_enhanced(
            b"\x00" * 8,
            KEY32,
            message_indicator=bytes(range(length)),
            experimental=True,
        )
        assert result.plaintext == b"" and result.nonce_hex == ""
        assert "unsupported MI length" in result.error
        _assert_no_key(result, KEY32)

    @pytest.mark.parametrize("size", [0, 8, 15, 33])
    def test_enhanced_rejects_bad_aes_key_sizes(self, size: int) -> None:
        key = (KEY32 + KEY32)[:size]
        result = decrypt_dmr_enhanced(
            b"\x00" * 8, key, message_indicator=b"\x01\x02\x03\x04", experimental=True
        )
        assert result.plaintext == b""
        assert result.error.startswith("Decryption failed: Invalid key size")
        _assert_no_key(result, key)

    @pytest.mark.parametrize("size", [16, 24, 32])
    def test_enhanced_runs_with_aes_key_sizes_but_stays_unverified(
        self, size: int
    ) -> None:
        result = decrypt_dmr_enhanced(
            b"\x00" * 8,
            KEY32[:size],
            message_indicator=b"\x01\x02\x03\x04",
            experimental=True,
        )
        assert result.error is None and len(result.plaintext) == 8
        assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# P25
# ---------------------------------------------------------------------------

MI8 = bytes.fromhex("0123456789abcdef")
LDU = bytes(range(99))  # one whole LDU: 9 packed IMBE codewords


class TestP25:
    @pytest.mark.parametrize("cipher", ["aes128", "AES", "rc4", ""])
    def test_offset_rejects_unknown_ciphers(self, cipher: str) -> None:
        with pytest.raises(ValueError, match="unknown P25 cipher"):
            p25_voice_keystream_offset(cipher, "ldu1", 0)

    @pytest.mark.parametrize("frame", ["hdu", "ldu3", "", "4v_4"])
    def test_offset_rejects_unknown_frame_types(self, frame: str) -> None:
        with pytest.raises(ValueError, match="unknown P25 voice frame type"):
            p25_voice_keystream_offset("aes", frame, 0)

    def test_frame_type_is_case_insensitive(self) -> None:
        assert p25_voice_keystream_offset(
            "des", "LDU2", 0
        ) == p25_voice_keystream_offset("des", "ldu2", 0)

    @pytest.mark.parametrize("index", ["abc", None, "1.5"])
    def test_malformed_codeword_index_is_reported(self, index: object) -> None:
        for result in (
            decrypt_p25_phase1(
                LDU[:11], DES8, MI8, frame_type="ldu1", codeword_index=index
            ),
            decrypt_p25_phase2(
                LDU[:11], KEY32, MI8, frame_type="ldu1", codeword_index=index
            ),
        ):
            assert result.plaintext == b""
            assert result.error.startswith("invalid codeword index")

    @pytest.mark.parametrize("size", [0, 7, 9, 16, 32])
    def test_des_rejects_bad_key_sizes(self, size: int) -> None:
        key = (DES8 * 4)[:size]
        result = decrypt_p25_phase1(LDU, key, MI8, frame_type="ldu1")
        assert result.plaintext == b"" and result.confidence == 0.0
        assert result.error == f"Invalid DES key length: {size} (expected 8 or 24)"
        _assert_no_key(result, key)

    def test_des_three_identical_subkeys_equal_single_des(self) -> None:
        single = decrypt_p25_phase1(LDU, DES8, MI8, frame_type="ldu1")
        triple = decrypt_p25_phase1(LDU, DES8 * 3, MI8, frame_type="ldu1")
        assert single.error is None and triple.error is None
        assert triple.plaintext == single.plaintext != LDU
        other = decrypt_p25_phase1(
            LDU, DES8 + DES8[::-1] + DES8, MI8, frame_type="ldu1"
        )
        assert other.error is None and other.plaintext != single.plaintext

    @pytest.mark.parametrize("size", [0, 16, 24, 31, 33])
    def test_aes_rejects_bad_key_sizes(self, size: int) -> None:
        key = (KEY32 * 2)[:size]
        result = decrypt_p25_phase2(LDU, key, MI8, frame_type="ldu1")
        assert result.plaintext == b""
        assert result.error == f"Invalid AES-256 key length: {size} (expected 32)"
        _assert_no_key(result, key)

    @pytest.mark.parametrize("algid", [0x00, 0x80, 0x81, 0x85, 0xAA])
    def test_unsupported_algorithm_ids(self, algid: int) -> None:
        result = decrypt_p25_phase2(
            LDU, KEY32, MI8, algorithm_id=algid, frame_type="ldu1"
        )
        assert result.plaintext == b""
        assert result.error == f"Unsupported P25 algorithm_id: 0x{algid:02x}"
        assert result.algorithm == f"unknown-0x{algid:02x}"
        assert result.nonce_hex == MI8.hex()
        assert (
            decrypt_p25_phase2(
                LDU, KEY32, b"", algorithm_id=algid, frame_type="ldu1"
            ).nonce_hex
            == ""
        )

    def test_short_and_long_message_indicators_are_normalised(self) -> None:
        """MI bytes past the first 8 are ignored; a short MI is zero-padded."""
        for decrypt, key in ((decrypt_p25_phase1, DES8), (decrypt_p25_phase2, KEY32)):
            exact = decrypt(LDU, key, MI8[:4] + b"\x00" * 4, frame_type="ldu1")
            short = decrypt(LDU, key, MI8[:4], frame_type="ldu1")
            assert short.error is None and short.plaintext == exact.plaintext
            assert short.nonce_hex == exact.nonce_hex
            full = decrypt(LDU, key, MI8, frame_type="ldu1")
            longer = decrypt(LDU, key, MI8 + b"\xff" * 8, frame_type="ldu1")
            assert longer.plaintext == full.plaintext
            assert longer.nonce_hex == full.nonce_hex

    def test_non_bytes_ciphertext_is_reported_not_raised(self) -> None:
        for result in (
            decrypt_p25_phase1("x" * 11, DES8, MI8, frame_type="ldu1"),
            decrypt_p25_phase2("x" * 11, KEY32, MI8, frame_type="ldu1"),
        ):
            assert result.plaintext == b"" and result.confidence == 0.0
            assert result.error.startswith("Decryption failed:")
        _assert_no_key(decrypt_p25_phase1("x" * 11, DES8, MI8, frame_type="ldu1"), DES8)
