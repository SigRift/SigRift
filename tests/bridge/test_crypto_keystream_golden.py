"""Golden-vector tests for the DMR / P25 keystream decryptors (D4b, Q12, P11).

The constructions here are the keystream layouts interoperable DMR and P25
decoders use, and the tests cross-check against an **independent** library
keystream (``modes.OFB``) and externally pinned IV vectors, never against the
module's own keystream helper, so they verify interoperability rather than
round-tripping the code against itself. The references below were written
for this project from the layout, not from any other implementation's source.

Covered:

* DMR AES IV is the ``LFSR128d`` 32-to-128 expansion of the 4-byte PI-header
  MI, pinned to an external vector (Q12).  The byte-wise DMR AES
  path and DMR basic privacy are experimental (disabled by default).
* P25 AES-256 / DES-OFB voice is checked against a reference keystream layout
  (library OFB keystream; discard round, LDU2 +101, 11 LCW/ES + reserved
  bytes before codeword 0, 2 LSD bytes before codeword 8, and the TDMA 4V/2V
  offsets), plus pinned ciphertext vectors computed from it (P11).
* The P25 MI is LFSR-expanded to the 128-bit IV (TIA-102.AAAD), checked
  against an independent bit-level reference and a pinned vector.
* Every keystream decryptor reports ``confidence == 0.0`` and
  :func:`try_decrypt` never returns them.
"""

import os

import pytest

from sigrift.lib.crypto.aes_decrypt import (
    decrypt_dmr_basic,
    decrypt_dmr_enhanced,
    decrypt_p25_phase1,
    decrypt_p25_phase2,
    dmr_aes_iv,
    expand_mi_to_128,
    p25_voice_keystream_offset,
    try_decrypt,
)


# -- independent library OFB keystream (modes.OFB, not the module's helper) --


def _ofb_mode(iv: bytes):
    try:  # OFB moved to "decrepit" in cryptography 43+
        from cryptography.hazmat.decrepit.ciphers.modes import OFB
    except ImportError:  # pragma: no cover - older cryptography
        from cryptography.hazmat.primitives.ciphers.modes import OFB
    return OFB(iv)


def _ofb_ref(algorithm, iv: bytes, n: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher

    enc = Cipher(algorithm, _ofb_mode(iv)).encryptor()
    return enc.update(b"\x00" * n)


def _aes_ref(key: bytes, iv: bytes, n: int) -> bytes:
    from cryptography.hazmat.primitives.ciphers import algorithms

    return _ofb_ref(algorithms.AES(key), iv, n)


def _des_ref(key8: bytes, iv: bytes, n: int) -> bytes:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

    return _ofb_ref(TripleDES(key8 * 3), iv, n)


# -- independent LFSR reference for the P25 MI expansion ---------------------


def _ref_expand_mi(mi8: bytes) -> bytes:
    """Bit-level Fibonacci LFSR from C(x)=1+x^15+x^27+x^38+x^46+x^62+x^64."""
    reg = [(mi8[i // 8] >> (7 - (i % 8))) & 1 for i in range(64)]
    bits = list(reg)
    for _ in range(64):
        val = 0
        for b in reg:
            val = (val << 1) | b
        fb = (
            (val >> 63)
            ^ (val >> 61)
            ^ (val >> 45)
            ^ (val >> 37)
            ^ (val >> 26)
            ^ (val >> 14)
        ) & 1
        reg = reg[1:] + [fb]
        bits.append(fb)
    out = bytearray(16)
    for i, b in enumerate(bits):
        if b:
            out[i // 8] |= 0x80 >> (i % 8)
    return bytes(out)


# -- DMR AES IV (LFSR128d) -------------------------------------------------


def test_dmr_aes_iv_known_vector():
    # Externally derived (LFSR128d): MI 12345678 -> 128-bit IV.
    iv = dmr_aes_iv(bytes.fromhex("12345678"))
    assert iv.hex() == "12345678b451463a41d78991a49a6402"
    assert iv[:4] == bytes.fromhex("12345678")  # MI fills the first 4 bytes


def test_dmr_aes_iv_accepts_16_byte_iv():
    raw = os.urandom(16)
    assert dmr_aes_iv(raw) == raw


@pytest.mark.parametrize("n", [0, 1, 2, 3, 5, 8, 12])
def test_dmr_aes_iv_rejects_other_lengths(n):
    with pytest.raises(ValueError):
        dmr_aes_iv(os.urandom(n))


# -- DMR AES voice path (experimental, disabled by default) -----------------


def test_dmr_enhanced_disabled_by_default():
    res = decrypt_dmr_enhanced(
        os.urandom(27), os.urandom(32), message_indicator=bytes.fromhex("0a0b0c0d")
    )
    assert res.plaintext == b""
    assert res.confidence == 0.0
    assert res.error and "experimental" in res.error


def test_dmr_enhanced_experimental_discards_first_block():
    # With experimental=True the keystream applies after a one-block discard,
    # cross-checked against the library's OFB keystream (not the module's).
    key = bytes.fromhex("00112233445566778899aabbccddeeff" * 2)  # 32-byte AES key
    mi = bytes.fromhex("0a0b0c0d")
    iv = dmr_aes_iv(mi)
    plaintext = bytes(range(27))
    ks = _aes_ref(key, iv, 16 + len(plaintext))[16:]  # discard the first block
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, ks))

    res = decrypt_dmr_enhanced(ciphertext, key, message_indicator=mi, experimental=True)
    assert res.error is None
    assert res.plaintext == plaintext
    assert res.confidence == 0.0  # no integrity check: never a verified decrypt
    assert res.reason is not None


def test_dmr_enhanced_requires_mi():
    res = decrypt_dmr_enhanced(os.urandom(27), os.urandom(32), experimental=True)
    assert res.plaintext == b""
    assert res.error and "message indicator" in res.error


def test_dmr_enhanced_not_reported_as_success():
    # Even run experimentally, try_decrypt (confidence > 0.5) never accepts it;
    # by default it is disabled and also yields None.
    ct = os.urandom(27)
    assert (
        try_decrypt(
            ct,
            "dmr_enhanced",
            [(os.urandom(32), "k")],
            message_indicator=bytes.fromhex("0a0b0c0d"),
        )
        is None
    )


# -- DMR basic privacy (experimental, disabled by default) ------------------


def test_dmr_basic_disabled_by_default():
    res = decrypt_dmr_basic(os.urandom(27), b"\x01\x02\x03")
    assert res.plaintext == b""
    assert res.confidence == 0.0
    assert res.error and "experimental" in res.error


def test_dmr_basic_experimental_is_unverified():
    res = decrypt_dmr_basic(bytes(27), b"\x01\x02\x03", experimental=True)
    assert res.error is None
    assert res.confidence == 0.0
    assert res.reason is not None


def test_dmr_basic_not_reported_as_success():
    # The old printable-byte heuristic scored most wrong keys above threshold;
    # try_decrypt must now never return a dmr_basic result.
    for _ in range(20):
        assert try_decrypt(os.urandom(27), "dmr_basic", [(os.urandom(3), "k")]) is None


# -- P25 MI expansion (TIA-102.AAAD LFSR) -----------------------------------


def test_p25_mi_expansion_matches_reference():
    for _ in range(50):
        mi = os.urandom(8)
        got = expand_mi_to_128(mi)
        assert got == _ref_expand_mi(mi)
        assert got[:8] == mi  # first 64 output bits are the MI unchanged


def test_p25_mi_expansion_known_vector():
    mi = bytes.fromhex("1122334455667788")
    assert expand_mi_to_128(mi).hex() == "1122334455667788ca315769150c8308"


def test_p25_mi_expansion_zero():
    assert expand_mi_to_128(bytes(8)) == bytes(16)


# -- Reference keystream layout for P25 voice encryption --------------------
#
# Written for this project from the keystream layout itself, not from any
# other implementation's source. One OFB keystream is generated per
# superframe from the message indicator (expanded to 128 bits for AES), and
# its first cipher block is discarded (16 bytes AES, 8 bytes DES). After
# that, FDMA IMBE codewords are 11 bytes each: an LDU1 starts at byte 0 and
# an LDU2 at byte 101, codeword i of the LDU sits at 11 + 11*i, and two
# extra bytes come before codeword 8. These are the offsets interoperable P25
# decoders use. The keystream comes from the library's OFB mode and the MI
# expansion from the bit-level reference above -- nothing from the module
# under test.

#
# TDMA AMBE codewords are 7 bytes (49 bits: only the top bit of the last byte
# is used) at 7*(subframe + 4k) in a 4V_k burst and 7*(subframe + 16) in a 2V
# burst, from a 9-block AES keystream (DES: the same 28 blocks).

_REF_LDU_BASE = {"LDU1": 0, "LDU2": 101}
_REF_TDMA_BURST = {"4V_0": 0, "4V_1": 4, "4V_2": 8, "4V_3": 12, "2V": 16}


def _ref_keystream(cipher: str, key: bytes, mi: bytes, *, tdma: bool = False) -> bytes:
    """The superframe keystream with the first cipher block discarded."""
    if cipher == "aes":
        blocks = 9 if tdma else 15
        return _aes_ref(key, _ref_expand_mi(mi[:8]), 16 * blocks)[16:]
    return _des_ref(key, mi[:8], 8 * 28)[8:]


def _ref_codeword_offset(fr_type: str, index: int) -> int:
    return _REF_LDU_BASE[fr_type] + 11 + 11 * index + (2 if index == 8 else 0)


def _ref_encrypt_ldu(cipher, key, mi, fr_type, codewords):
    ks = _ref_keystream(cipher, key, mi)
    return [
        bytes(b ^ ks[_ref_codeword_offset(fr_type, i) + j] for j, b in enumerate(cw))
        for i, cw in enumerate(codewords)
    ]


def _ref_encrypt_ambe(ks: bytes, fr_type: str, subframe: int, cw: bytes) -> bytes:
    offset = 7 * (subframe + _REF_TDMA_BURST[fr_type])
    out = bytearray(b ^ ks[offset + j] for j, b in enumerate(cw[:7]))
    out[6] &= 0x80
    return bytes(out)


# Pinned vectors from the reference above: key, 9-byte MI, and the nine
# IMBE codewords bytes(range(99)) of one LDU, encrypted with that layout.
_PIN_MI = bytes.fromhex("112233445566778899")
_PIN_PT = bytes(range(99))
_PIN_AES_KEY = bytes(range(32))
_PIN_DES_KEY = bytes.fromhex("0123456789abcdef")
_PIN_CT = {
    ("aes", "ldu1"): (
        "7d14f8aca87e66a83fb950fd4abf55ca075befeb4c321a93408a3037fe62ce5b96e872"
        "897dabdc1015c9a4f53f59a48a88ab7c8c0d2abc772a76975e9bed7ada5c20e95d5b4c"
        "a395b23bd0baab37ac6b92598ef7c26f35206c243d0e88e65963086f29"
    ),
    ("aes", "ldu2"): (
        "d2764b36d8e2ed33599d7f8dd807fa909529d558a1bd3aebbc0c9741bd2c4579e3ef47"
        "acf0b2e50be696acaafe9fc31460511adcebc7b6eadedda7872b101f5682bd44209984"
        "f87f5f2905882d237125ad4415dc9923da01da243dfd4e7b5b84b9a952"
    ),
    ("des", "ldu1"): (
        "967deef1a2582a1ad9a3227595b3c9623567c258493baf9536f7143291d6b3bb041961"
        "8de354d3eca46673eb3653f91528b3c40bafa628e20c5391df14f030ebfe57cf5f39de"
        "729c2606106f02d9a4a5a269fc932239eb6135e1354b682fb9bdf6373c"
    ),
    ("des", "ldu2"): (
        "5732e966925b7354f0043f2b8e49dfbc205e3e28353e2e797665d6c98b57546fb7a6e8"
        "e99b108973f5240aba686da530d10717ff8f22fc07dbf9669788913f6ec0d4859ecfc6"
        "cd936f1d4ab49d91977fbf92a8c975b9633dfd37e30461b97e5e10a137"
    ),
}


def _decrypt(cipher, ct, key, mi, **kw):
    fn = decrypt_p25_phase2 if cipher == "aes" else decrypt_p25_phase1
    return fn(ct, key, mi, **kw)


# -- Keystream addressing ----------------------------------------------------


@pytest.mark.parametrize(
    ("cipher", "frame_type", "index", "offset"),
    [
        # layout: 16/8 discard + LDU base + 11 + 11*i (+2 for i == 8)
        ("aes", "ldu1", 0, 27),
        ("aes", "ldu1", 7, 104),
        ("aes", "ldu1", 8, 117),
        ("aes", "ldu2", 0, 128),
        ("aes", "ldu2", 8, 218),
        ("des", "ldu1", 0, 19),
        ("des", "ldu2", 8, 210),
        # TDMA: discard + 7*(voice_subframe + 4*k) / 7*(voice_subframe + 16)
        ("aes", "4v_0", 0, 16),
        ("aes", "4v_1", 2, 58),
        ("aes", "4v_3", 3, 121),
        ("aes", "2v", 1, 135),
        ("des", "2v", 0, 120),
    ],
)
def test_p25_voice_keystream_offset_matches_layout(cipher, frame_type, index, offset):
    assert p25_voice_keystream_offset(cipher, frame_type, index) == offset


@pytest.mark.parametrize(
    ("cipher", "frame_type", "index"),
    [("aes", "ldu1", 9), ("aes", "ldu2", -1), ("des", "4v_0", 4), ("aes", "2v", 2)],
)
def test_p25_voice_keystream_offset_rejects_out_of_frame(cipher, frame_type, index):
    with pytest.raises(ValueError):
        p25_voice_keystream_offset(cipher, frame_type, index)


# -- P25 FDMA voice (LDU1/LDU2) against the reference -----------------------


@pytest.mark.parametrize("cipher", ["aes", "des"])
@pytest.mark.parametrize("frame_type", ["ldu1", "ldu2"])
def test_p25_fdma_pinned_vector(cipher, frame_type):
    key = _PIN_AES_KEY if cipher == "aes" else _PIN_DES_KEY
    ct = bytes.fromhex(_PIN_CT[(cipher, frame_type)])
    # The pinned ciphertext is what the reference produces ...
    ref = _ref_encrypt_ldu(
        cipher,
        key,
        _PIN_MI,
        frame_type.upper(),
        [_PIN_PT[i * 11 : (i + 1) * 11] for i in range(9)],
    )
    assert b"".join(ref) == ct
    # ... and the decryptor recovers the plaintext from it.
    res = _decrypt(cipher, ct, key, _PIN_MI, frame_type=frame_type)
    assert res.error is None
    assert res.plaintext == _PIN_PT
    assert res.confidence == 0.0
    assert res.reason is not None


@pytest.mark.parametrize("cipher", ["aes", "des"])
def test_p25_fdma_each_codeword_matches_reference(cipher):
    # Every IMBE codeword of an LDU1 and an LDU2, decrypted one at a time
    # with its own index, comes back as the plaintext the reference encrypted.
    key = os.urandom(32 if cipher == "aes" else 8)
    mi = os.urandom(9)
    for fr_type in ("LDU1", "LDU2"):
        pts = [os.urandom(11) for _ in range(9)]
        cts = _ref_encrypt_ldu(cipher, key, mi, fr_type, pts)
        for i, (pt, ct) in enumerate(zip(pts, cts)):
            res = _decrypt(cipher, ct, key, mi, frame_type=fr_type, codeword_index=i)
            assert res.error is None
            assert res.plaintext == pt, (fr_type, i)
        # A run of codewords starting mid-LDU uses the same addressing.
        res = _decrypt(
            cipher, b"".join(cts[6:]), key, mi, frame_type=fr_type, codeword_index=6
        )
        assert res.plaintext == b"".join(pts[6:])


def test_p25_fdma_requires_frame_type():
    # The keystream offset depends on the LDU type: there is no default.
    with pytest.raises(TypeError):
        decrypt_p25_phase2(os.urandom(11), os.urandom(32), os.urandom(8))


@pytest.mark.parametrize(
    ("length", "index"),
    [(10, 0), (16, 0), (0, 0), (22, 8), (11, 9), (11, -1)],
)
def test_p25_fdma_rejects_unaligned_or_out_of_frame(length, index):
    res = decrypt_p25_phase2(
        os.urandom(length),
        os.urandom(32),
        os.urandom(8),
        frame_type="ldu1",
        codeword_index=index,
    )
    assert res.plaintext == b""
    assert res.error
    assert res.confidence == 0.0


def test_p25_unknown_frame_type_rejected():
    res = decrypt_p25_phase1(
        os.urandom(11), os.urandom(8), os.urandom(8), frame_type="hdu"
    )
    assert res.plaintext == b""
    assert res.error and "frame type" in res.error


def test_p25_aes_requires_256_bit_key():
    res = decrypt_p25_phase2(
        os.urandom(11), os.urandom(16), os.urandom(8), frame_type="ldu1"
    )
    assert res.plaintext == b""
    assert res.error and "32" in res.error


def test_p25_phase2_iv_is_expanded_not_zero_padded():
    mi = os.urandom(8)
    res = decrypt_p25_phase2(os.urandom(11), os.urandom(32), mi, frame_type="ldu1")
    assert res.nonce_hex == expand_mi_to_128(mi).hex()
    assert res.nonce_hex[16:] != "0" * 16
    assert res.confidence == 0.0


# -- P25 TDMA voice (experimental) -------------------------------------------


def test_p25_tdma_disabled_by_default():
    res = decrypt_p25_phase2(
        os.urandom(7), os.urandom(32), os.urandom(8), frame_type="4v_0"
    )
    assert res.plaintext == b""
    assert res.error and "experimental" in res.error


@pytest.mark.parametrize("cipher", ["aes", "des"])
def test_p25_tdma_experimental_matches_reference(cipher):
    key = os.urandom(32 if cipher == "aes" else 8)
    mi = os.urandom(9)
    bursts = [("4V_0", 4), ("4V_1", 4), ("4V_2", 4), ("4V_3", 4), ("2V", 2)]
    for fr_type, n in bursts:
        ks = _ref_keystream(cipher, key, mi, tdma=True)
        for sub in range(n):
            pt = bytearray(os.urandom(7))
            pt[6] &= 0x80  # a 49-bit AMBE codeword
            ct = _ref_encrypt_ambe(ks, fr_type, sub, bytes(pt))
            res = _decrypt(
                cipher,
                ct,
                key,
                mi,
                frame_type=fr_type,
                codeword_index=sub,
                experimental=True,
            )
            assert res.error is None
            assert res.plaintext == bytes(pt), (fr_type, sub)
            assert res.confidence == 0.0


# -- never reported as a verified decryption ---------------------------------


def test_p25_phase2_wrong_key_not_reported_as_success():
    mi = os.urandom(8)
    for params in ({}, {"frame_type": "ldu1"}):
        out = try_decrypt(
            os.urandom(22),
            "p25_phase2",
            [(os.urandom(32), "wrong")],
            message_indicator=mi,
            **params,
        )
        assert out is None


def test_p25_phase1_wrong_key_not_reported_as_success():
    mi = os.urandom(8)
    res = decrypt_p25_phase1(os.urandom(22), os.urandom(8), mi, frame_type="ldu2")
    assert res.error is None
    assert res.confidence == 0.0
    out = try_decrypt(
        os.urandom(22),
        "p25_phase1",
        [(os.urandom(8), "wrong")],
        message_indicator=mi,
        frame_type="ldu2",
    )
    assert out is None
