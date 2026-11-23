#!/usr/bin/env python3
"""Bootstrap mTLS client certificates for SigRift edge agents — PKI Phase A.

Ensures the bridge CA exists, then mints a client certificate for each
requested identity and writes a ready-to-mount bundle:

    <out-dir>/<identity>/client.crt
    <out-dir>/<identity>/client.key   (mode 0600)
    <out-dir>/<identity>/ca.crt

A standalone deployment can call this once, then mount each bundle into
the matching scanner container and set ``MLRF_CLIENT_CERT`` /
``MLRF_CLIENT_KEY``. The ``MLRF_CLIENT_*`` paths are printed to stdout
(tab-separated) so the caller can wire them.

A ``node``-role certificate's identity must be the node id the agents
report (``MLRF_NODE_ID``): the gateway and the bridge accept a NODE
certificate only for the node whose id equals its identity, so all agents
of one node share one bundle. Per-agent identities (``wifi-scan``, …) are
refused for every heartbeat and detection.

Usage:
    PYTHONPATH=src python3 scripts/pki_bootstrap.py \\
        --data-dir /var/lib/sigrift/data \\
        local-edge:node          # one identity per NODE id

The CA certificate and registry live in ``<data-dir>/ca``; the CA private
key in the bridge's secrets directory: ``--secrets-dir``, else
``BRIDGE_SECRETS_DIR``, else ``secrets/`` next to the data dir — the same
place the bridge uses (a key still in ``<data-dir>/ca`` is moved there).

It can run while the bridge is running: every change to the CA registry
(each issuance, and the revocation of a bundle that could not be
published) holds the CA's inter-process lock (``<data-dir>/ca/.ca.lock``),
as the bridge's do, so neither undoes the other's issuances or
revocations. Use a ``pki_bootstrap.py`` from the same release as the
bridge: one from before that lock takes none.

The output directory must be owned by the invoking user and must not be
group/world writable or a symlink. Existing identity destinations are refused;
use a new ``--out-dir`` for rotation. Complete bundles are published from private
staging directories. POSIX rename refuses a concurrent nonempty destination,
but may replace a concurrent empty directory between the final check and rename;
this is not a strict race-proof no-clobber interface. Do not share the output
directory with another provisioning process. Failed publication attempts revoke
the issued certificate and remove the staging directory; failures of either
cleanup operation are reported for operator intervention. Abrupt termination
(e.g. SIGKILL or power loss) can leave staging files or an unrevoked certificate.
"""

from __future__ import annotations

import argparse
import logging
import os
import secrets
import shutil
import stat
import sys
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm

# Allow running straight from a checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sigrift.bridge.ca import (  # noqa: E402
    VALID_CERT_ROLES,
    CAError,
    CertificateAuthority,
    validate_identity,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    stream=sys.stderr,
)
logger = logging.getLogger("pki_bootstrap")
_PROVISION_ERRORS = (CAError, OSError, ValueError, TypeError, UnsupportedAlgorithm)


def _parse_agent(spec: str) -> tuple[str, str]:
    """Parse an ``identity[:role]`` agent spec; role defaults to ``node``."""
    identity, _, role = spec.partition(":")
    identity = identity.strip()
    role = role.strip() or "node"
    if not identity:
        raise argparse.ArgumentTypeError(f"empty identity in agent spec {spec!r}")
    if role not in VALID_CERT_ROLES:
        raise argparse.ArgumentTypeError(
            f"invalid role {role!r} in {spec!r}: "
            f"expected one of {sorted(VALID_CERT_ROLES)}"
        )
    return identity, role


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mint mTLS client certificates for SigRift edge agents."
    )
    parser.add_argument(
        "--data-dir",
        required=True,
        type=Path,
        help="Bridge data directory; the CA lives at <data-dir>/ca",
    )
    parser.add_argument(
        "--secrets-dir",
        type=Path,
        default=None,
        help=(
            "Bridge secrets directory; the CA private key lives at "
            "<secrets-dir>/ca/ca.key (default: $BRIDGE_SECRETS_DIR, else "
            "secrets/ next to the data dir)"
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Private output directory (default: <data-dir>/edge_certs); use a new "
        "--out-dir to rotate existing identities",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=90,
        help="Certificate lifetime in days (default: 90)",
    )
    parser.add_argument(
        "agents",
        nargs="+",
        type=_parse_agent,
        metavar="IDENTITY[:ROLE]",
        help="Identity and optional role, e.g. local-edge:node — for role "
        "node the identity must be the node id the agents report",
    )
    return parser


def _open_output(out_dir: Path) -> int:
    """Anchor bundle operations to an owned directory, without following its link."""
    out_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(out_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError(
                "output directory must be owned by the invoking user and not "
                "group/world writable"
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


def _require_new_destination(out_fd: int, identity: str) -> None:
    try:
        os.stat(identity, dir_fd=out_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise FileExistsError(f"identity {identity!r} already exists; use a new --out-dir")


def _publish_bundle(out_fd: int, identity: str, issued: dict, ca_pem: bytes) -> None:
    """Publish a complete private bundle; never write through an existing path."""
    stage = f".{identity}.{secrets.token_hex(16)}"
    os.mkdir(stage, mode=0o700, dir_fd=out_fd)
    published = False
    try:
        stage_fd = os.open(
            stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=out_fd
        )
        try:
            for name, content in (
                ("client.crt", issued["cert_pem"].encode("ascii")),
                ("client.key", issued["key_pem"].encode("ascii")),
                ("ca.crt", ca_pem),
            ):
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=stage_fd,
                )
                with os.fdopen(fd, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
        finally:
            os.close(stage_fd)
        _require_new_destination(out_fd, identity)
        os.rename(stage, identity, src_dir_fd=out_fd, dst_dir_fd=out_fd)
        published = True
    finally:
        if not published:
            try:
                shutil.rmtree(stage, dir_fd=out_fd)
            except OSError as exc:
                logger.error(
                    "Could not remove private staging directory %s: %s", stage, exc
                )


def _revoke_unpublished(ca: CertificateAuthority, serial: str) -> None:
    try:
        if not ca.revoke(serial):
            raise CAError("issued certificate is missing from the registry")
    except (CAError, OSError) as exc:
        logger.error("Could not revoke unpublished certificate %s: %s", serial, exc)


def main(argv: list[str] | None = None) -> int:
    """Provision certs for the requested agents. Returns a process exit code."""
    args = _build_parser().parse_args(argv)
    out_dir: Path = args.out_dir or (args.data_dir / "edge_certs")

    key_dir = args.secrets_dir / "ca" if args.secrets_dir else None
    try:
        ca = CertificateAuthority(args.data_dir / "ca", key_dir=key_dir)
        ca.ensure_ca()
        ca_pem = ca.ca_cert_pem
    except _PROVISION_ERRORS as exc:
        logger.error("CA bootstrap failed: %s", exc)
        return 1
    logger.info("CA ready at %s", args.data_dir / "ca")

    try:
        out_fd = _open_output(out_dir)
    except OSError as exc:
        logger.error("Unsafe or unavailable output directory %s: %s", out_dir, exc)
        return 1
    failures = 0
    try:
        for identity, role in args.agents:
            issued = None
            published = False
            try:
                validate_identity(identity)
                _require_new_destination(out_fd, identity)
                issued = ca.issue_cert(
                    identity=identity, role=role, ttl_days=args.ttl_days
                )
                _publish_bundle(out_fd, identity, issued, ca_pem)
                published = True
            except _PROVISION_ERRORS as exc:
                logger.error("Failed to provision %s: %s", identity, exc)
                failures += 1
                continue
            finally:
                if issued is not None and not published:
                    _revoke_unpublished(ca, issued["serial"])

            bundle = out_dir / identity
            logger.info(
                "Issued %s (role=%s, expires %s) -> %s",
                identity,
                role,
                issued["not_after"],
                bundle,
            )
            print(
                f"{identity}\tMLRF_CLIENT_CERT={bundle / 'client.crt'}\t"
                f"MLRF_CLIENT_KEY={bundle / 'client.key'}"
            )
    finally:
        os.close(out_fd)

    if failures:
        logger.error("%d agent(s) failed to provision", failures)
        return 1
    logger.info("Provisioned %d agent(s) under %s", len(args.agents), out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
