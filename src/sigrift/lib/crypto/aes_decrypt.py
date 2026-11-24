"""Protocol-specific decryption for intercepted RF signals.

What is here, and how far each path can be trusted:

* **Meshtastic** AES-128/256-CTR -- supported; the result is verified by a
  structural parse of the plaintext (see below).
* **P25** DES-OFB (ALGID 0x81) and AES-256-OFB (ALGID 0x84) voice --
  follows OP25's keystream construction and per-codeword addressing for
  FDMA (LDU1/LDU2) IMBE codewords; the TDMA (Phase 2) bursts are
  experimental and off by default, as OP25 itself marks them.  Results are
  unverified (``confidence == 0.0``): there is no integrity check.
* **DMR** "basic privacy" (repeating-key XOR) and DMR AES (DMRA ALGID
  0x24/0x25) -- **experimental and disabled by default**
  (``experimental=True`` runs them); neither models a reference
  implementation's voice-bit layout and both always report confidence 0.0.
* **Motorola Enhanced Privacy** (ARC4, key||MI) -- not supported.

Where each path is reachable
----------------------------
Only Meshtastic is applied by the product itself: the bridge's
``POST /api/crypto/decrypt`` and its decode pipeline both go through
:func:`try_decrypt`, which accepts only a verified result
(``confidence > 0.5``).  The P25 and DMR decryptors are library-level,
unverified helpers that neither the API nor the pipeline calls: the
request model has no message indicator / frame type / codeword index for
P25 (so :func:`try_decrypt` skips every key), and their results score 0.0
anyway.  Call :func:`decrypt_p25_phase1` / :func:`decrypt_p25_phase2` (and
the experimental DMR functions) directly to use them.  ``LEGAL.md`` §4
states the same scope; keep the two in step.

The ``cryptography`` library is imported lazily so the module can be
loaded even on minimal deployments — callers get a ``DecryptResult``
with an error string instead of an ``ImportError``.

Confidence and key correctness
------------------------------
Meshtastic carries a full ``Data`` protobuf, so a structural parse of the
whole plaintext tells a right key from a wrong one and the result scores
0.95 / 0.0 accordingly.  The DMR-enhanced and P25 voice schemes decrypt a
raw keystream (OFB) over short AMBE/IMBE voice frames with **no** embedded
integrity check, so *any* key produces plausible-looking output.  These
decryptors therefore report ``confidence == 0.0`` ("ran, but unverified"):
without known plaintext a wrong key cannot be distinguished from the right
one, and :func:`try_decrypt` (which only accepts ``confidence > 0.5``) must
never report them as a successful decryption.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class DecryptResult:
    """Outcome of a decryption attempt.

    ``error`` is set when nothing was produced (bad input, a disabled
    experimental path, a missing library).  ``reason`` explains a result
    that did decrypt but whose ``confidence`` stays 0.0 because there is no
    integrity check over the plaintext.
    """

    plaintext: bytes
    protocol: str
    algorithm: str
    key_id: str
    nonce_hex: str
    confidence: float
    error: str | None
    reason: str | None = None


_UNVERIFIED = (
    "keystream cipher over voice codewords with no integrity check: a wrong "
    "key cannot be distinguished from the right one, so this is unverified"
)


def _experimental_off(what: str, why: str) -> str:
    return (
        f"{what} is experimental and disabled: {why}. Pass experimental=True "
        "to run it (the result is never reported as a verified decryption)."
    )


def _triple_des(key: bytes) -> Any:
    """``TripleDES`` algorithm object, wherever cryptography keeps it."""
    try:  # moved under "decrepit" in cryptography 43+
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:  # pragma: no cover - older cryptography
        from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    return TripleDES(key)


def _ofb_keystream(algorithm: Any, iv: bytes, n_bytes: int) -> bytes:
    """``n_bytes`` of OFB keystream: E(IV), E(E(IV)), ... from block 0.

    Built by chaining the block cipher in ECB (as the reference open
    implementations generate it) so the byte offset of each codeword is
    explicit and a leading discard round can be skipped by slicing.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    encryptor = Cipher(algorithm, modes.ECB()).encryptor()
    block = bytes(iv)
    out = bytearray()
    while len(out) < n_bytes:
        block = encryptor.update(block)
        out += block
    return bytes(out[:n_bytes])


# ---------------------------------------------------------------------------
# Meshtastic AES-CTR
# ---------------------------------------------------------------------------


def build_meshtastic_nonce(packet_id: int, source_node: int) -> bytes:
    """Build the 16-byte nonce used by Meshtastic AES-CTR.

    Mirrors firmware ``CryptoEngine::initNonce(fromNode, packetId)``::

        bytes 0-7   packet_id   (little-endian uint64)
        bytes 8-11  source_node (little-endian uint32, the ``from`` node)
        bytes 12-15 zero        (the CTR block counter starts here)
    """
    return struct.pack(
        "<QI4x",
        packet_id & 0xFFFFFFFFFFFFFFFF,
        source_node & 0xFFFFFFFF,
    )


# Confidence reported when the plaintext is a well-formed Meshtastic Data
# protobuf.  Anything else scores 0.0: AES-CTR "decrypts" under any key, so
# a structural check of the whole plaintext is the only key-correctness test.
_MESHTASTIC_VALID_CONFIDENCE = 0.95


def decrypt_meshtastic(
    ciphertext: bytes,
    key: bytes,
    packet_id: int,
    source_node: int,
    key_id: str = "",
) -> DecryptResult:
    """Decrypt a Meshtastic payload using AES-128/256-CTR (by key length).

    ``confidence`` is high only when the whole plaintext parses as a valid
    Meshtastic ``Data`` protobuf, and 0.0 otherwise (wrong key or not a
    Meshtastic packet).
    """
    nonce = build_meshtastic_nonce(packet_id, source_node)
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return DecryptResult(
            plaintext=b"",
            protocol="meshtastic",
            algorithm=f"aes-{len(key) * 8}-ctr",
            key_id=key_id,
            nonce_hex=nonce.hex(),
            confidence=0.0,
            error="cryptography library not installed",
        )

    try:
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as exc:
        return DecryptResult(
            plaintext=b"",
            protocol="meshtastic",
            algorithm=f"aes-{len(key) * 8}-ctr",
            key_id=key_id,
            nonce_hex=nonce.hex(),
            confidence=0.0,
            error=f"Decryption failed: {exc}",
        )

    # Lazy import: sigrift.lib.protocol.meshtastic imports this module.
    from sigrift.lib.protocol.meshtastic import parse_data_message

    confidence = (
        _MESHTASTIC_VALID_CONFIDENCE
        if parse_data_message(plaintext) is not None
        else 0.0
    )
    return DecryptResult(
        plaintext=plaintext,
        protocol="meshtastic",
        algorithm=f"aes-{len(key) * 8}-ctr",
        key_id=key_id,
        nonce_hex=nonce.hex(),
        confidence=confidence,
        error=None,
    )


# ---------------------------------------------------------------------------
# DMR basic (XOR expansion)
# ---------------------------------------------------------------------------


def decrypt_dmr_basic(
    ciphertext: bytes,
    key: bytes,
    key_id: str = "",
    *,
    experimental: bool = False,
) -> DecryptResult:
    """XOR the payload with the key repeated over its length. **Experimental.**

    This matches no published DMR privacy scheme: real Motorola Basic Privacy
    expands a 16-bit key in a defined way and applies it to the FEC-decoded
    49-bit AMBE vectors, not to the raw burst payload.  It is disabled unless
    ``experimental=True``, and even then reports ``confidence == 0.0`` — XOR
    has no integrity check, so the output of an unrelated key looks just as
    plausible.  (The previous printable-byte heuristic scored most wrong keys
    above the acceptance threshold, reporting arbitrary-key output as a
    successful decryption.)
    """
    if not experimental:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="xor",
            key_id=key_id,
            nonce_hex="",
            confidence=0.0,
            error=_experimental_off(
                "DMR basic privacy (repeating-key XOR)",
                "no reference implementation applies a DMR key this way",
            ),
        )
    if not key:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="xor",
            key_id=key_id,
            nonce_hex="",
            confidence=0.0,
            error="Empty key",
        )

    key_len = len(key)
    expanded = (key * ((len(ciphertext) // key_len) + 1))[: len(ciphertext)]
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, expanded))

    return DecryptResult(
        plaintext=plaintext,
        protocol="dmr",
        algorithm="xor",
        key_id=key_id,
        nonce_hex="",
        confidence=0.0,
        error=None,
        reason="experimental repeating-key XOR with no integrity check: unverified",
    )


# ---------------------------------------------------------------------------
# DMR AES (DMRA ALGID 0x24 / 0x25, OFB keystream) — EXPERIMENTAL
# ---------------------------------------------------------------------------

# DSD-FME ``processMbeFrame`` discards the first OFB block before applying the
# keystream to the AMBE voice bits.
_DMR_AES_DISCARD = 16


def dmr_aes_iv(message_indicator: bytes) -> bytes:
    """Expand the 32-bit DMR MI (PI header) to the 128-bit AES IV.

    Follows DSD-FME ``LFSR128d``: the 4-byte MI fills IV bytes 0-3, then a
    32-bit LFSR with taps 32, 22, 2, 1 (feedback ``b31 ^ b21 ^ b1 ^ b0``),
    seeded with the MI, is clocked 96 times and each output bit is appended
    MSB-first to fill bytes 4-15.  A 16-byte value is taken as an already
    expanded IV.

    Raises
    ------
    ValueError
        For any other length.
    """
    mi = bytes(message_indicator)
    if len(mi) == 16:
        return mi
    if len(mi) != 4:
        raise ValueError(
            f"unsupported MI length {len(mi)} (expected the 4-byte PI-header MI "
            "or a 16-byte IV)"
        )
    lfsr = int.from_bytes(mi, "big")
    tail = 0
    for _ in range(96):
        bit = ((lfsr >> 31) ^ (lfsr >> 21) ^ (lfsr >> 1) ^ lfsr) & 1
        lfsr = ((lfsr << 1) | bit) & 0xFFFFFFFF
        tail = (tail << 1) | bit
    return mi + tail.to_bytes(12, "big")


def decrypt_dmr_enhanced(
    ciphertext: bytes,
    key: bytes,
    slot: int = 0,
    frame_number: int = 0,
    color_code: int = 0,
    message_indicator: bytes | None = None,
    key_id: str = "",
    *,
    experimental: bool = False,
) -> DecryptResult:
    """Decrypt DMR AES voice (DMRA ALGID 0x24 / 0x25). **Experimental.**

    The AES IV is built from the 4-byte PI-header message indicator with the
    DSD-FME ``LFSR128d`` expansion (:func:`dmr_aes_iv`), and the first OFB
    block is discarded as DSD-FME does.  The keystream is then applied to
    ``ciphertext`` byte-wise.

    This path is **experimental** (disabled unless ``experimental=True``):
    DSD-FME applies the keystream bit-wise to the FEC-decoded 49-bit AMBE
    vectors with a 7-bit skip per frame, which this byte-wise application
    over a raw payload does not model, so it is not expected to recover real
    over-the-air traffic.  Motorola "Enhanced Privacy" is a different scheme
    (ARC4 keyed with key||MI, not AES) and is not supported.  The result
    always reports ``confidence == 0.0`` (no integrity check over the voice
    payload), so :func:`try_decrypt` never reports it as a success.

    ``slot``, ``frame_number`` and ``color_code`` are accepted for call
    compatibility but are not part of the IV (the MI carries the per-
    superframe state).
    """
    del slot, frame_number, color_code  # not part of the DMRA IV

    if not experimental:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="aes-ofb",
            key_id=key_id,
            nonce_hex="",
            confidence=0.0,
            error=_experimental_off(
                "DMR AES voice",
                "the byte-wise keystream application does not model DSD-FME's "
                "bit-wise 49-bit AMBE layout",
            ),
        )

    if message_indicator is None:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="aes-ofb",
            key_id=key_id,
            nonce_hex="",
            confidence=0.0,
            error="a message indicator (4-byte PI-header MI or 16-byte IV) is required",
        )
    try:
        iv = dmr_aes_iv(message_indicator)
    except ValueError as exc:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="aes-ofb",
            key_id=key_id,
            nonce_hex="",
            confidence=0.0,
            error=str(exc),
        )

    try:
        from cryptography.hazmat.primitives.ciphers import algorithms
    except ImportError:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="aes-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error="cryptography library not installed",
        )

    try:
        keystream = _ofb_keystream(
            algorithms.AES(key), iv, _DMR_AES_DISCARD + len(ciphertext)
        )
    except Exception as exc:
        return DecryptResult(
            plaintext=b"",
            protocol="dmr",
            algorithm="aes-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error=f"Decryption failed: {exc}",
        )

    ks = keystream[_DMR_AES_DISCARD:]
    plaintext = bytes(c ^ k for c, k in zip(ciphertext, ks))
    return DecryptResult(
        plaintext=plaintext,
        protocol="dmr",
        algorithm="aes-ofb",
        key_id=key_id,
        nonce_hex=iv.hex(),
        confidence=0.0,
        error=None,
        reason=_UNVERIFIED,
    )


# ---------------------------------------------------------------------------
# P25 voice keystream addressing (OP25)
# ---------------------------------------------------------------------------

# OP25 (boatbod/op25, ``op25_crypt_aes.cc`` / ``op25_crypt_des.cc``
# ``prepare()`` / ``process()``) builds ONE OFB keystream per superframe from
# the MI and XORs each FEC-decoded, packed voice codeword with the keystream
# bytes at a fixed offset:
#
#   offset  = discard round (16 bytes AES, 8 bytes DES)
#   FDMA (Phase 1, IMBE, 11-byte codewords ``imbe_pack``-ed u0..u7):
#           + 0 for LDU1 / + 101 for LDU2
#           + 11 + 11*i + (2 if i == 8 else 0)          i = codeword 0..8 of the LDU
#     (the leading 11 skips 9 LCW/ES bytes and 2 reserved bytes, the extra 2
#      skips the LSD between codewords 7 and 8)
#   TDMA (Phase 2, AMBE, 7-byte codewords, OP25 marks this "Experimental"):
#           + 7 * (voice_subframe + 4*k) for 4V burst k (0..3)
#           + 7 * (voice_subframe + 16)  for the 2V burst
#     and the decrypted codeword keeps only the MSB of its last byte (49 bits).
#
# The keystream is generated for the MI in effect for the superframe (the
# HDU's MI for the first one, then the MI from the previous LDU2's ESS; OP25
# decrypts an LDU2's own voice before switching to the MI that LDU2 carries).
_P25_DES_DISCARD = 8
_P25_AES_DISCARD = 16
_P25_IMBE_BYTES = 11
_P25_AMBE_BYTES = 7
_P25_FDMA_BASE = {"ldu1": 0, "ldu2": 101}
_P25_FDMA_CODEWORDS = 9
# 4V burst k starts at codeword slot 4*k; the 2V burst at slot 16.
_P25_TDMA_BASE = {"4v_0": 0, "4v_1": 4, "4v_2": 8, "4v_3": 12, "2v": 16}
_P25_TDMA_CODEWORDS = {"4v_0": 4, "4v_1": 4, "4v_2": 4, "4v_3": 4, "2v": 2}
_P25_FRAME_TYPES = tuple(_P25_FDMA_BASE) + tuple(_P25_TDMA_BASE)
_P25_DISCARD = {"aes": _P25_AES_DISCARD, "des": _P25_DES_DISCARD}


def p25_voice_keystream_offset(
    cipher: str, frame_type: str, codeword_index: int
) -> int:
    """OP25's keystream byte offset for one P25 voice codeword.

    Returns the ``offset`` OP25's ``process()`` computes: the discard round
    for ``cipher`` (``"aes"``: 16, ``"des"``: 8) plus the per-frame and
    per-codeword offset of codeword ``codeword_index`` in ``frame_type``
    (``"ldu1"``/``"ldu2"``: index 0..8; ``"4v_0"``..``"4v_3"``: voice
    subframe 0..3; ``"2v"``: voice subframe 0..1).  See the table above.

    Raises
    ------
    ValueError
        For an unknown cipher or frame type, or an index outside the frame.
    """
    try:
        discard = _P25_DISCARD[cipher]
    except KeyError:
        raise ValueError(
            f"unknown P25 cipher {cipher!r} (expected 'aes' or 'des')"
        ) from None
    ft = str(frame_type).lower()
    i = int(codeword_index)
    if ft in _P25_FDMA_BASE:
        if not 0 <= i < _P25_FDMA_CODEWORDS:
            raise ValueError(f"IMBE codeword index {i} outside 0..8 for {ft}")
        return discard + _P25_FDMA_BASE[ft] + 11 + 11 * i + (2 if i == 8 else 0)
    if ft in _P25_TDMA_BASE:
        if not 0 <= i < _P25_TDMA_CODEWORDS[ft]:
            raise ValueError(
                f"voice subframe {i} outside 0..{_P25_TDMA_CODEWORDS[ft] - 1} for {ft}"
            )
        return discard + _P25_AMBE_BYTES * (i + _P25_TDMA_BASE[ft])
    raise ValueError(
        f"unknown P25 voice frame type {frame_type!r} (expected one of "
        f"{', '.join(_P25_FRAME_TYPES)})"
    )


def _p25_voice_apply(
    ciphertext: bytes,
    cipher: str,
    make_algorithm: Any,
    iv: bytes,
    frame_type: str,
    codeword_index: int,
    experimental: bool,
) -> tuple[bytes, str | None]:
    """XOR packed voice codewords with OP25-addressed keystream.

    ``ciphertext`` holds one or more consecutive codewords of ``frame_type``
    starting at ``codeword_index``.  Returns ``(plaintext, error)``.
    """
    ft = str(frame_type).lower()
    if ft not in _P25_FDMA_BASE and ft not in _P25_TDMA_BASE:
        return b"", (
            f"unknown P25 voice frame type {frame_type!r} (expected one of "
            f"{', '.join(_P25_FRAME_TYPES)})"
        )
    tdma = ft in _P25_TDMA_BASE
    if tdma and not experimental:
        return b"", _experimental_off(
            "P25 Phase 2 (TDMA) voice decryption",
            "OP25 itself marks its TDMA keystream path experimental",
        )
    cw_len = _P25_AMBE_BYTES if tdma else _P25_IMBE_BYTES
    n_frame = _P25_TDMA_CODEWORDS[ft] if tdma else _P25_FDMA_CODEWORDS
    if not ciphertext or len(ciphertext) % cw_len:
        return b"", (
            f"ciphertext must be whole {cw_len}-byte packed "
            f"{'AMBE' if tdma else 'IMBE'} codewords (got {len(ciphertext)} bytes)"
        )
    n = len(ciphertext) // cw_len
    try:
        first = int(codeword_index)
    except (TypeError, ValueError):
        return b"", f"invalid codeword index {codeword_index!r}"
    if first < 0 or first + n > n_frame:
        return b"", (
            f"codewords {first}..{first + n - 1} do not fit in {ft} (0..{n_frame - 1})"
        )

    offsets = [p25_voice_keystream_offset(cipher, ft, first + k) for k in range(n)]
    keystream = _ofb_keystream(make_algorithm(), iv, offsets[-1] + cw_len)
    out = bytearray()
    for k, off in enumerate(offsets):
        cw = bytearray(
            c ^ s
            for c, s in zip(
                ciphertext[k * cw_len : (k + 1) * cw_len], keystream[off : off + cw_len]
            )
        )
        if tdma:
            cw[6] &= 0x80  # 49-bit AMBE codeword: only the MSB of byte 6 is data
        out += cw
    return bytes(out), None


# ---------------------------------------------------------------------------
# P25 DES-OFB (ALGID 0x81)
# ---------------------------------------------------------------------------


def decrypt_p25_phase1(
    ciphertext: bytes,
    key: bytes,
    message_indicator: bytes,
    key_id: str = "",
    *,
    frame_type: str,
    codeword_index: int = 0,
    experimental: bool = False,
) -> DecryptResult:
    """Decrypt P25 DES-OFB voice (ALGID 0x81) the way OP25 does.

    (The name is historical: this is the DES-OFB decryptor, used on both
    FDMA/Phase 1 and TDMA/Phase 2 voice.)

    ``ciphertext`` is one or more consecutive FEC-decoded, packed voice
    codewords of ``frame_type`` starting at ``codeword_index`` -- for
    ``"ldu1"``/``"ldu2"`` 11-byte IMBE codewords as OP25's ``imbe_pack``
    produces them (index 0..8; a whole LDU is 99 bytes at index 0), for the
    TDMA bursts ``"4v_0"``..``"4v_3"``/``"2v"`` 7-byte AMBE codewords (voice
    subframe index; experimental, see below).  Each codeword is XORed with
    the keystream at OP25's offset (:func:`p25_voice_keystream_offset`):
    8-byte discard round, +101 for LDU2, then 11 bytes of LCW/ES and
    reserved bytes before codeword 0 and the 2 LSD bytes before codeword 8.

    The OFB IV is the first 8 bytes of the MI in effect for the superframe
    (zero-padded).  Single DES runs as TripleDES with the 8-byte key
    repeated 3x (EDE with K1=K2=K3 == single DES); a 24-byte 3-key value is
    used as-is (3-key TDES is not an OP25 algorithm).

    TDMA frame types run only with ``experimental=True`` (OP25 labels its
    TDMA keystream path experimental).  No integrity check backs the voice
    payload, so ``confidence`` is always 0.0.
    """
    if len(key) == 8:
        tdes_key = key * 3
    elif len(key) == 24:
        tdes_key = key
    else:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="des-ofb",
            key_id=key_id,
            nonce_hex=message_indicator.hex() if message_indicator else "",
            confidence=0.0,
            error=f"Invalid DES key length: {len(key)} (expected 8 or 24)",
        )

    iv = bytes(message_indicator[:8]).ljust(8, b"\x00")

    try:
        plaintext, error = _p25_voice_apply(
            ciphertext,
            "des",
            lambda: _triple_des(tdes_key),
            iv,
            frame_type,
            codeword_index,
            experimental,
        )
    except ImportError:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="des-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error="cryptography library not installed",
        )
    except Exception as exc:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="des-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error=f"Decryption failed: {exc}",
        )

    return DecryptResult(
        plaintext=plaintext,
        protocol="p25",
        algorithm="des-ofb",
        key_id=key_id,
        nonce_hex=iv.hex(),
        confidence=0.0,
        error=error,
        reason=None if error else _UNVERIFIED,
    )


# ---------------------------------------------------------------------------
# P25 AES-256-OFB (ALGID 0x84)
# ---------------------------------------------------------------------------


def expand_mi_to_128(message_indicator: bytes) -> bytes:
    """Expand a 64-bit P25 message indicator to the 128-bit OFB IV.

    P25 (TIA-102.AAAD) derives the 128-bit cipher IV from the 64-bit MI with
    a Fibonacci LFSR over the characteristic polynomial::

        C(x) = 1 + x^15 + x^27 + x^38 + x^46 + x^62 + x^64

    The first 64 bits of the MI load the register; it is then clocked 64
    times, each feedback bit appended to form bits 64..127.  This matches
    OP25's ``expand_mi_to_128``.  The first 8 bytes of the result are the MI
    unchanged; the next 8 are the LFSR-generated continuation.

    Only the first 8 bytes of ``message_indicator`` are used (zero-padded if
    shorter).
    """
    mi = bytes(message_indicator[:8]).ljust(8, b"\x00")
    lfsr = int.from_bytes(mi, "big")  # 64-bit register, bit 63 = MSB

    out = bytearray(mi)  # bytes 0..7 == MI
    acc = 0
    for i in range(64):
        # Taps for C(x): x^64 -> bit 63, and x^k -> bit k-1 for the rest.
        fb = (
            (lfsr >> 63)
            ^ (lfsr >> 61)  # x^62
            ^ (lfsr >> 45)  # x^46
            ^ (lfsr >> 37)  # x^38
            ^ (lfsr >> 26)  # x^27
            ^ (lfsr >> 14)  # x^15
        ) & 1
        lfsr = ((lfsr << 1) | fb) & 0xFFFFFFFFFFFFFFFF
        acc = (acc << 1) | fb
    out += acc.to_bytes(8, "big")
    return bytes(out)


def decrypt_p25_phase2(
    ciphertext: bytes,
    key: bytes,
    message_indicator: bytes,
    algorithm_id: int = 0x84,
    key_id: str = "",
    *,
    frame_type: str,
    codeword_index: int = 0,
    experimental: bool = False,
) -> DecryptResult:
    """Decrypt P25 AES-256-OFB voice (ALGID 0x84) the way OP25 does.

    (The name is historical: this is the AES-256 decryptor, used on both
    FDMA/Phase 1 and TDMA/Phase 2 voice.)

    The 64-bit MI in effect for the superframe is LFSR-expanded to the
    128-bit IV (:func:`expand_mi_to_128`, TIA-102.AAAD / OP25) and ``key``
    must be the 32-byte AES-256 key.  ``ciphertext``, ``frame_type`` and
    ``codeword_index`` are as for :func:`decrypt_p25_phase1`: consecutive
    packed codewords (11-byte IMBE for ``"ldu1"``/``"ldu2"``, 7-byte AMBE
    for the TDMA bursts), each XORed with the keystream at OP25's offset --
    16-byte discard round, +101 for LDU2, 11 LCW/ES and reserved bytes
    before codeword 0, 2 LSD bytes before codeword 8
    (:func:`p25_voice_keystream_offset`).

    TDMA frame types run only with ``experimental=True`` (OP25 labels its
    TDMA keystream path experimental).  No integrity check backs the voice
    payload, so ``confidence`` is always 0.0.

    Parameters
    ----------
    algorithm_id : int
        P25 algorithm identifier (0x84 = AES-256).
    """
    if algorithm_id != 0x84:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm=f"unknown-0x{algorithm_id:02x}",
            key_id=key_id,
            nonce_hex=message_indicator.hex() if message_indicator else "",
            confidence=0.0,
            error=f"Unsupported P25 algorithm_id: 0x{algorithm_id:02x}",
        )

    iv = expand_mi_to_128(message_indicator)
    if len(key) != 32:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="aes-256-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error=f"Invalid AES-256 key length: {len(key)} (expected 32)",
        )

    try:
        from cryptography.hazmat.primitives.ciphers import algorithms
    except ImportError:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="aes-256-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error="cryptography library not installed",
        )

    try:
        plaintext, error = _p25_voice_apply(
            ciphertext,
            "aes",
            lambda: algorithms.AES(key),
            iv,
            frame_type,
            codeword_index,
            experimental,
        )
    except Exception as exc:
        return DecryptResult(
            plaintext=b"",
            protocol="p25",
            algorithm="aes-256-ofb",
            key_id=key_id,
            nonce_hex=iv.hex(),
            confidence=0.0,
            error=f"Decryption failed: {exc}",
        )

    return DecryptResult(
        plaintext=plaintext,
        protocol="p25",
        algorithm="aes-256-ofb",
        key_id=key_id,
        nonce_hex=iv.hex(),
        confidence=0.0,
        error=error,
        reason=None if error else _UNVERIFIED,
    )


# ---------------------------------------------------------------------------
# Multi-key trial decryption
# ---------------------------------------------------------------------------

_PROTOCOL_DECRYPTORS = {
    "meshtastic": decrypt_meshtastic,
    "dmr_basic": decrypt_dmr_basic,
    "dmr_enhanced": decrypt_dmr_enhanced,
    "p25_phase1": decrypt_p25_phase1,
    "p25_phase2": decrypt_p25_phase2,
}


def try_decrypt(
    ciphertext: bytes,
    protocol: str,
    keys: list[tuple[bytes, str]],
    **params: object,
) -> DecryptResult | None:
    """Try all keys for a given protocol; return first with confidence > 0.5.

    Only a decryptor that can verify its plaintext ever passes that bar,
    which today means ``"meshtastic"``: the DMR and P25 decryptors always
    report 0.0, so for them this returns ``None`` whatever the key (call
    those decryptors directly instead).

    Parameters
    ----------
    ciphertext : bytes
        Encrypted payload.
    protocol : str
        One of "meshtastic", "dmr_basic", "dmr_enhanced", "p25_phase1",
        "p25_phase2".
    keys : list[tuple[bytes, str]]
        List of (key_material, key_id) pairs to try.
    **params
        Protocol-specific parameters forwarded to the decryptor.
    """
    decryptor = _PROTOCOL_DECRYPTORS.get(protocol)
    if decryptor is None:
        logger.warning("Unknown protocol for trial decryption: %r", protocol)
        return None

    for key_material, key_id in keys:
        try:
            result = decryptor(
                ciphertext,
                key_material,
                key_id=key_id,
                **params,  # type: ignore[arg-type]
            )
            if result.confidence > 0.5:
                logger.info(
                    "Trial decryption succeeded: protocol=%s key_id=%s confidence=%.2f",
                    protocol,
                    key_id,
                    result.confidence,
                )
                return result
        except TypeError:
            # Missing required protocol-specific params — skip
            logger.debug(
                "Skipping key %s: missing required params for %s",
                key_id,
                protocol,
            )
            continue
        except Exception as exc:
            logger.debug(
                "Trial decryption error for key %s: %s",
                key_id,
                exc,
            )
            continue

    return None
