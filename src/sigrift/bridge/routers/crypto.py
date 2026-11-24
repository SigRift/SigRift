"""Cryptographic key management and decryption API endpoints for The Bridge.

Provides endpoints for importing/listing/revoking crypto keys and
performing manual decryption of intercepted RF payloads.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from sigrift.bridge.dependencies import Role, require_role

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


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ImportKeyRequest(BaseModel):
    """Request body for importing a cryptographic key."""

    model_config = {"extra": "forbid"}

    protocol: str = Field(..., description="Protocol (meshtastic, dmr, p25, generic)")
    key_name: str = Field(..., min_length=1, description="Human-readable key label")
    raw_key_hex: str = Field(
        ..., min_length=2, description="Key material as hex string"
    )
    algorithm: str = Field(
        "aes-128", description="Algorithm (aes-128, aes-256, des, des-ofb)"
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
    """List stored crypto keys (metadata only, no key material)."""
    store = _get_crypto_key_store(request)
    return store.list_keys(protocol=protocol)


@router.post("/keys", status_code=status.HTTP_201_CREATED)
def import_key(
    body: ImportKeyRequest,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Import a cryptographic key."""
    # Validate hex
    clean = body.raw_key_hex.replace(" ", "").replace(":", "")
    try:
        bytes.fromhex(clean)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hex key material: {body.raw_key_hex!r}",
        )

    store = _get_crypto_key_store(request)
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

    logger.info("Imported key %s for protocol=%s", key_id, body.protocol)
    return {"key_id": key_id, "protocol": body.protocol, "label": body.key_name}


@router.delete("/keys/{key_id}")
def revoke_key(
    key_id: str,
    request: Request,
    _key_id: str = Depends(require_role(Role.ADMIN)),
) -> dict[str, Any]:
    """Revoke (delete and zero) a crypto key."""
    store = _get_crypto_key_store(request)
    removed = store.remove_key(key_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id!r} not found",
        )
    logger.info("Revoked key %s", key_id)
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
