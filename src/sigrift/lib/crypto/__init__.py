"""Cryptographic utilities for RF protocol analysis.

Provides key management and protocol-specific decryption (Meshtastic,
DMR, P25). Only Meshtastic decryption is wired into the bridge API and
decode pipeline; the DMR and P25 decryptors are unverified library-level
helpers (see :mod:`sigrift.lib.crypto.aes_decrypt`). Protocol-aware frame
fuzzing lives in the commercial
sigrift-sentinel package and is discovered at runtime through
``sigrift.providers.registry.get_fuzz_provider``.
"""

from sigrift.lib.crypto.key_store import CryptoKey, KeyStore
from sigrift.lib.crypto.aes_decrypt import (
    DecryptResult,
    build_meshtastic_nonce,
    decrypt_dmr_basic,
    decrypt_dmr_enhanced,
    decrypt_meshtastic,
    decrypt_p25_phase1,
    decrypt_p25_phase2,
    dmr_aes_iv,
    expand_mi_to_128,
    p25_voice_keystream_offset,
    try_decrypt,
)

__all__ = [
    # key_store
    "CryptoKey",
    "KeyStore",
    # aes_decrypt
    "DecryptResult",
    "build_meshtastic_nonce",
    "decrypt_dmr_basic",
    "decrypt_dmr_enhanced",
    "decrypt_meshtastic",
    "decrypt_p25_phase1",
    "decrypt_p25_phase2",
    "dmr_aes_iv",
    "expand_mi_to_128",
    "p25_voice_keystream_offset",
    "try_decrypt",
]
