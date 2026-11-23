"""Certificate-authority endpoints for The Bridge.

Phase A of the PKI rollout
(``plans/pki_replacement_for_api_keys_20260519.md``): the bridge issues
mTLS client certificates alongside the existing API-key auth. These
routes expose CSR signing, bridge-side cert issuance, CA-cert and CRL
publication, and the issued-cert registry.

Auth model:
- ``POST /sign`` / ``POST /issue`` / ``POST /revoke`` require the
  master (admin) key.
- ``GET /certs`` requires viewer role.
- ``GET /ca.pem`` and ``GET /crl.pem`` are unauthenticated by design —
  the CA certificate and CRL are public trust material that scanners
  must fetch *before* they hold a client cert (trust bootstrap).
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from sigrift.bridge.ca import CAError, CAStateError, CertificateAuthority
from sigrift.bridge.dependencies import (
    Role,
    rate_limit_sensitive,
    require_master_key,
    require_role,
)
from sigrift.bridge.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()

_PEM_MEDIA_TYPE = "application/x-pem-file"

# The 503 detail for unauthenticated callers and those below admin: the
# full message names files on the bridge host (the CA private key's path
# among them), so it goes to the log only.
_GENERIC_UNAVAILABLE_DETAIL = (
    "The certificate authority is unavailable; the bridge log says why."
)

# After the CA could not be opened, how long requests get the same 503
# without trying again. Anonymous /ca.pem and /crl.pem requests would
# otherwise redo the whole start-up (and log it) every time while the CA
# waits for an operator; after the fix, the CA is back within this delay.
_RETRY_AFTER_FAILURE_SECONDS = 15.0
_clock = time.monotonic

# Changes to the CA (sign, issue, revoke) run on threads of their own. Each
# one waits for the CA lock while another process (another bridge worker,
# scripts/pki_bootstrap.py) changes the registry: milliseconds, but up to
# ca._LOCK_TIMEOUT_SECONDS behind a holder that is stopped or hung. On the
# event loop that wait would hold up every other request of this worker
# (ingest, WebSocket feeds); on the default executor, the work queued there
# (API-key checks, logins, the detection write queue). The changes take
# turns on the lock anyway, so a couple of threads are enough.
_CA_CHANGE_WORKERS = 2
_ca_change_executor = ThreadPoolExecutor(
    max_workers=_CA_CHANGE_WORKERS, thread_name_prefix="bridge-ca-change"
)

_T = TypeVar("_T")


async def _change(fn: Callable[..., _T], /, *args: Any, **kwargs: Any) -> _T:
    """Run the CA change *fn(*args, **kwargs)* off the event loop."""
    call = functools.partial(contextvars.copy_context().run, fn, *args, **kwargs)
    return await asyncio.get_running_loop().run_in_executor(_ca_change_executor, call)


def _ca_unavailable(exc: CAError, *, generic: bool, log: bool = True) -> HTTPException:
    """A 503 for a CA whose files need an operator (see CAStateError)."""
    if log:
        logger.error("Certificate authority unavailable: %s", exc)
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=_GENERIC_UNAVAILABLE_DETAIL if generic else str(exc),
    )


def _get_ca(request: Request, *, generic: bool = False) -> CertificateAuthority:
    """Return the process-wide CA, lazily bootstrapping it on first use.

    The CA directory lives under the persistence data dir at ``ca/``.
    ``ensure_ca()`` is idempotent, so the lazy init is safe under
    concurrent first requests. A CA that ``ensure_ca()`` refuses to use
    (say, a private key without its certificate) is a 503 and is not
    cached: it is tried again once :data:`_RETRY_AFTER_FAILURE_SECONDS`
    have passed, so it comes back once an operator has fixed it. *generic*
    hides the reason (file paths) from the response.

    Unlike the changes (:func:`_change`), this runs on the event loop:
    opening an existing CA takes no lock, so only creating one can wait for
    it, and only while another process is creating the same CA.
    """
    app = request.app
    ca: CertificateAuthority | None = getattr(app.state, "ca", None)
    if ca is not None:
        return ca
    failure: tuple[float, CAError] | None = getattr(app.state, "ca_failure", None)
    if failure is not None and _clock() - failure[0] < _RETRY_AFTER_FAILURE_SECONDS:
        raise _ca_unavailable(failure[1], generic=generic, log=False)
    ca_dir = Path(app.state.persistence.data_dir) / "ca"
    try:
        ca = CertificateAuthority(ca_dir)
        ca.ensure_ca()
    except CAError as exc:
        app.state.ca_failure = (_clock(), exc)
        raise _ca_unavailable(exc, generic=generic) from exc
    app.state.ca_failure = None
    app.state.ca = ca
    return ca


def _below_admin(request: Request) -> bool:
    """True if the authenticated caller's role is below admin."""
    return getattr(request.state, "key_role", Role.VIEWER) < Role.ADMIN


def _get_app_state(request: Request) -> AppState:
    return request.app.state.app_state


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class CsrSignRequest(BaseModel):
    """Request body for ``POST /sign``."""

    csr_pem: str = Field(..., description="PEM-encoded certificate signing request")
    identity: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Cert identity — becomes the subject CN and DNS SAN",
    )
    role: str = Field("node", description="Role the cert carries")
    ttl_days: int = Field(90, ge=1, le=825, description="Cert lifetime in days")


class CertIssueRequest(BaseModel):
    """Request body for ``POST /issue`` (bridge generates the keypair)."""

    identity: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Cert identity — becomes the subject CN and DNS SAN",
    )
    role: str = Field("node", description="Role the cert carries")
    ttl_days: int = Field(90, ge=1, le=825, description="Cert lifetime in days")


# ---------------------------------------------------------------------------
# POST /sign -- sign a CSR into a client cert
# ---------------------------------------------------------------------------


@router.post("/sign", status_code=status.HTTP_201_CREATED)
async def sign_csr(
    request: Request,
    body: CsrSignRequest,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Sign a CSR. Returns the issued cert plus the CA cert for chaining."""
    ca = _get_ca(request)
    try:
        result = await _change(
            ca.sign_csr,
            body.csr_pem.encode(),
            identity=body.identity,
            role=body.role,
            ttl_days=body.ttl_days,
        )
    except CAStateError as exc:
        raise _ca_unavailable(exc, generic=False) from exc
    except CAError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    _get_app_state(request).log_activity(
        "cert_issued",
        message=f"Client cert issued: {result['identity']} (role={result['role']})",
    )
    logger.info(
        "Client cert issued: %s serial=%s", result["identity"], result["serial"]
    )

    result["ca_pem"] = ca.ca_cert_pem.decode()
    return result


# ---------------------------------------------------------------------------
# POST /issue -- bridge generates the keypair, then issues a cert
# ---------------------------------------------------------------------------


@router.post("/issue", status_code=status.HTTP_201_CREATED)
async def issue_cert(
    request: Request,
    body: CertIssueRequest,
    _master: str = Depends(require_master_key),
    _rate: str = Depends(rate_limit_sensitive),
) -> dict[str, Any]:
    """Issue a cert with a bridge-generated keypair.

    Returns the cert *and* its private key — used by the admin UI and
    bootstrap, where the operator installs both on the agent. The key
    is transmitted only over the already-TLS-protected admin session
    and is never stored by the bridge.
    """
    ca = _get_ca(request)
    try:
        result = await _change(
            ca.issue_cert,
            identity=body.identity,
            role=body.role,
            ttl_days=body.ttl_days,
        )
    except CAStateError as exc:
        raise _ca_unavailable(exc, generic=False) from exc
    except CAError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    _get_app_state(request).log_activity(
        "cert_issued",
        message=f"Client cert issued: {result['identity']} (role={result['role']})",
    )
    logger.info(
        "Client cert issued (keypair generated): %s serial=%s",
        result["identity"],
        result["serial"],
    )

    result["ca_pem"] = ca.ca_cert_pem.decode()
    return result


# ---------------------------------------------------------------------------
# GET /ca.pem -- publish the CA certificate (unauthenticated, public)
# ---------------------------------------------------------------------------


@router.get("/ca.pem")
async def get_ca_cert(request: Request) -> Response:
    """Return the CA certificate in PEM form, for trust bootstrap."""
    ca = _get_ca(request, generic=True)
    try:
        pem = ca.ca_cert_pem
    except CAError as exc:
        raise _ca_unavailable(exc, generic=True) from exc
    return Response(content=pem, media_type=_PEM_MEDIA_TYPE)


# ---------------------------------------------------------------------------
# GET /crl.pem -- publish the certificate revocation list (public)
# ---------------------------------------------------------------------------


@router.get("/crl.pem")
async def get_crl(request: Request) -> Response:
    """Return the current CRL in PEM form."""
    ca = _get_ca(request, generic=True)
    try:
        crl = ca.generate_crl()
    except CAError as exc:
        raise _ca_unavailable(exc, generic=True) from exc
    return Response(content=crl, media_type=_PEM_MEDIA_TYPE)


# ---------------------------------------------------------------------------
# GET /certs -- list issued certs (metadata only)
# ---------------------------------------------------------------------------


@router.get("/certs")
async def list_certs(
    request: Request,
    _key_id: str = Depends(require_role(Role.VIEWER)),
) -> list[dict[str, Any]]:
    """List every issued cert with its registry metadata. No private keys.

    A viewer gets the generic 503 detail: the full one names files on the
    bridge host, the CA private key's path among them.
    """
    generic = _below_admin(request)
    try:
        return _get_ca(request, generic=generic).list_certs()
    except CAError as exc:
        raise _ca_unavailable(exc, generic=generic) from exc


# ---------------------------------------------------------------------------
# POST /revoke/{serial} -- revoke an issued cert
# ---------------------------------------------------------------------------


@router.post("/revoke/{serial}")
async def revoke_cert(
    serial: str,
    request: Request,
    _master: str = Depends(require_master_key),
) -> dict[str, str]:
    """Revoke a cert by serial. The CRL reflects it on the next fetch."""
    ca = _get_ca(request)
    try:
        revoked = await _change(ca.revoke, serial)
    except CAError as exc:
        raise _ca_unavailable(exc, generic=False) from exc
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No issued cert with serial {serial}",
        )

    _get_app_state(request).log_activity(
        "cert_revoked",
        message=f"Client cert revoked: serial {serial}",
    )
    logger.info("Client cert revoked: serial=%s", serial)
    return {"status": "ok", "revoked": serial}
