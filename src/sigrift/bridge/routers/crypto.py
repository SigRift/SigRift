"""Cryptographic key management and decryption API endpoints for The Bridge.

Provides endpoints for importing/listing/revoking crypto keys and
performing manual decryption of intercepted RF payloads.

Imported keys are saved in the database, encrypted with
``BRIDGE_KEYSTORE_KEY``, when it is set (``storage/crypto_keys.py``), and
loaded again at startup; without it they are kept in memory only.
``GET /status`` says which.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.storage.crypto_keys import (
    CryptoKeyStorageError,
    CryptoKeyVault,
    disabled_status,
)

logger = logging.getLogger(__name__)

router = APIRouter()

# Keys are stored under the key store's protocol names ("meshtastic", "dmr",
# "p25"), which are what the admin console sends, but ``try_decrypt`` names
# its decryptors differently.  This is the translation the decode pipeline
# uses (``ProtocolDecodePipeline._try_auto_decrypt``), so a stored key meets
# the same decryptor on either path.  A name not listed here (a decryptor
# name, say, with an explicit ``key_id``) is passed through unchanged.
_DECRYPTOR_FOR_PROTOCOL = {
    "meshtastic": "meshtastic",
    "dmr": "dmr_basic",
    "p25": "p25_phase1",
}


#: Key bytes an import may hold (the vault's envelope bound).
_MAX_KEY_BYTES = 256

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_crypto_key_store(request: Request) -> Any:
    """Retrieve the KeyStore from app state."""
    store = getattr(request.app.state, "crypto_key_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Crypto key store not initialised",
        )
    return store


def _get_crypto_key_vault(request: Request) -> CryptoKeyVault | None:
    """The vault that saves imported keys, or None (memory-only)."""
    return getattr(request.app.state, "crypto_key_vault", None)


def _mutation_lock(vault: CryptoKeyVault | None) -> Any:
    """The lock an import or a revoke holds (none without a vault)."""
    return vault.mutation_lock if vault is not None else contextlib.nullcontext()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ImportKeyRequest(BaseModel):
    """Request body for importing a cryptographic key."""

    model_config = {"extra": "forbid"}

    # Bounded: imported keys are saved in the database (crypto_keys).
    protocol: str = Field(
        ..., max_length=32, description="Protocol (meshtastic, dmr, p25, generic)"
    )
    key_name: str = Field(
        ..., min_length=1, max_length=128, description="Human-readable key label"
    )
    raw_key_hex: str = Field(
        ...,
        min_length=2,
        # A bound on the text, separators (':' and spaces) included; the key
        # itself may have at most 256 bytes (checked in import_key).  A 422
        # never repeats the value (sigrift.lib.validation_errors).
        max_length=1024,
        description="Key material as hex string (at most 256 bytes)",
    )
    algorithm: str = Field(
        "aes-128",
        max_length=32,
        description="Algorithm (aes-128, aes-256, des, des-ofb)",
    )


class DecryptRequest(BaseModel):
    """Request body for manual decryption."""

    model_config = {"extra": "forbid"}

    payload_hex: str = Field(..., min_length=2, description="Encrypted payload as hex")
    protocol: str = Field(
        ...,
        description=(
            "Key-store protocol of the keys to try (meshtastic, dmr, p25); "
            "only meshtastic can produce a verified decryption"
        ),
    )
    key_id: str | None = Field(None, description="Specific key ID to use")
    packet_id: int | None = Field(None, description="Packet ID (for Meshtastic nonce)")
    source_node: int | None = Field(
        None, description="Source node (for Meshtastic nonce)"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/keys")
def list_keys(
    request: Request,
    protocol: str | None = Query(None, description="Filter by protocol"),
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> list[dict[str, Any]]:
    """List the keys the bridge holds (metadata only, no key material).

    The built-in defaults and every imported key; ``persisted`` says
    whether a key is saved in the database (loaded again at startup).
    """
    store = _get_crypto_key_store(request)
    vault = _get_crypto_key_vault(request)
    keys = store.list_keys(protocol=protocol)
    for key in keys:
        key["persisted"] = bool(vault and vault.is_saved(key["key_id"]))
    return keys


@router.get("/status")
def key_persistence_status(
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Whether imported keys are saved in the database, and why not."""
    store = _get_crypto_key_store(request)
    vault = _get_crypto_key_vault(request)
    if vault is None:
        return disabled_status(store)
    return vault.status(store)


@router.post("/keys", status_code=status.HTTP_201_CREATED)
def import_key(
    body: ImportKeyRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Import a cryptographic key, and save it when keys are persisted."""
    # Validate hex.  The detail never echoes the value: it can be most of
    # a key.
    clean = body.raw_key_hex.replace(" ", "").replace(":", "")
    if len(clean) > 2 * _MAX_KEY_BYTES:
        raise HTTPException(
            status_code=422,
            detail=f"raw_key_hex is too long: at most {_MAX_KEY_BYTES} key bytes",
        )
    try:
        if not bytes.fromhex(clean):
            raise ValueError("no key bytes")
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid hex key material: use two hex digits per byte "
                "(':' and spaces allowed)"
            ),
        )

    store = _get_crypto_key_store(request)
    vault = _get_crypto_key_vault(request)
    persisted = False
    # Held across both steps: a revoke of this key (its id is listed as
    # soon as it is in the store) waits until the row is saved, and then
    # deletes it, instead of zeroing the key before the row is written.
    with _mutation_lock(vault):
        try:
            key_id = store.import_hex(
                hex_str=clean,
                protocol=body.protocol,
                algorithm=body.algorithm,
                label=body.key_name,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            )
        if vault is not None and vault.persists:
            try:
                persisted = vault.save(store.lookup_key(key_id), created_by=_key_id)
            except CryptoKeyStorageError as exc:
                store.remove_key(key_id)
                logger.error("Could not save imported key %s: %s", key_id, exc)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Could not save the key in the database; nothing was "
                        "imported. Try again, and check the bridge log."
                    ),
                )

    logger.info(
        "Imported key %s for protocol=%r (%s)",
        key_id,
        body.protocol,
        "saved" if persisted else "memory only",
    )
    return {
        "key_id": key_id,
        "protocol": body.protocol,
        "label": body.key_name,
        "persisted": persisted,
    }


@router.delete("/keys/{key_id}")
def revoke_key(
    key_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Revoke a crypto key: delete its saved row, then zero it in memory.

    The row goes first, so a failed delete never leaves a revoked key
    that comes back at the next start (503, and the key stays usable).
    """
    store = _get_crypto_key_store(request)
    not_found = HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Key {key_id!r} not found",
    )
    vault = _get_crypto_key_vault(request)
    # The import's lock: an import of this key still saving its row
    # finishes first, so is_saved sees the row and the delete removes it.
    with _mutation_lock(vault):
        if store.lookup_key(key_id) is None:
            raise not_found
        saved = vault is not None and vault.is_saved(key_id)
        if saved:
            try:
                vault.delete(key_id)
            except CryptoKeyStorageError as exc:
                logger.error("Could not delete saved key %s: %s", key_id, exc)
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=(
                        "Could not delete the saved key from the database; it "
                        "was not revoked. Try again, and check the bridge log."
                    ),
                )
        if not store.remove_key(key_id):
            raise not_found
    logger.info(
        "Revoked key %s (%s)", key_id, "saved row deleted" if saved else "memory only"
    )
    return {"ok": True, "revoked": key_id}


@router.post("/decrypt")
def decrypt_payload(
    body: DecryptRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ANALYST)),
) -> dict[str, Any]:
    """Attempt to decrypt an encrypted payload."""
    from sigrift.lib.crypto.aes_decrypt import try_decrypt

    # Validate hex payload
    clean = body.payload_hex.replace(" ", "").replace(":", "")
    try:
        ciphertext = bytes.fromhex(clean)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hex payload: {body.payload_hex!r}",
        )

    store = _get_crypto_key_store(request)

    # Build key list: specific key or all for protocol
    if body.key_id:
        key_obj = store.lookup_key(body.key_id)
        if key_obj is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Key {body.key_id!r} not found",
            )
        keys = [(bytes(key_obj.key_material), key_obj.key_id)]
    else:
        protocol_keys = store.lookup_by_protocol(body.protocol)
        if not protocol_keys:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No keys available for protocol {body.protocol!r}",
            )
        keys = [(bytes(k.key_material), k.key_id) for k in protocol_keys]

    # Build extra params for try_decrypt
    params: dict[str, Any] = {}
    if body.packet_id is not None:
        params["packet_id"] = body.packet_id
    if body.source_node is not None:
        params["source_node"] = body.source_node

    result = try_decrypt(
        ciphertext=ciphertext,
        protocol=_DECRYPTOR_FOR_PROTOCOL.get(body.protocol, body.protocol),
        keys=keys,
        **params,
    )

    if result is None:
        return {
            "success": False,
            "error": "No key produced a confident decryption",
        }

    return {
        "success": result.error is None,
        "plaintext_hex": result.plaintext.hex() if result.plaintext else "",
        "protocol": result.protocol,
        "algorithm": result.algorithm,
        "key_id": result.key_id,
        "confidence": result.confidence,
        "error": result.error,
    }
