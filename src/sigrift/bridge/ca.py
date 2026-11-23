"""Embedded certificate authority for The Bridge.

Implements the PKI foundation described in
``plans/pki_replacement_for_api_keys_20260519.md`` (decision 1: embedded
``cryptography`` CA, no external sidecar).  The bridge becomes the
issuing CA for client (mTLS) certificates: it bootstraps a self-signed
CA, signs certificate signing requests into client-auth leaf certs,
tracks issued certs in a JSON registry, and publishes a CRL.

This module is deliberately standalone — it depends only on
``cryptography`` and the standard library so it can be unit-tested
without a running bridge.  Identity is decided by the bridge (the
caller passes a validated ``identity``); the CSR contributes only its
public key.  Subject / SAN fields inside the CSR are ignored so a
malicious CSR cannot claim an identity it was not granted.

Where the files live: the certificate and the registry stay in the CA
directory under the bridge data dir (``data/ca/``), which the gateway
mounts to verify client certificates.  The private key does not: it
lives in the bridge's secrets directory (:func:`secrets_dir`,
``BRIDGE_SECRETS_DIR``), which only the bridge mounts, so a compromised
gateway cannot read it.  A key left in the old location by an earlier
version is moved there (not copied) the first time the CA is opened —
the bridge image also does this at container start-up
(``python3 -m sigrift.bridge.ca migrate-key``).

Several processes can use one CA directory at the same time: each bridge
worker opens a CA of its own, and ``scripts/pki_bootstrap.py`` can run
against a live stack. So every change to the registry (issuing, revoking)
and creating the CA hold an advisory ``fcntl`` lock on ``.ca.lock`` next
to ``registry.json``, not only a lock of this process's threads; see
:meth:`CertificateAuthority._exclusive`.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import json
import logging
import os
import re
import stat
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

try:  # POSIX advisory locks; absent on Windows (one process there)
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX
    _fcntl = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# CA self-signed cert lifetime. Long-lived; rotated yearly via a separate
# runbook (see PKI_ARCHITECTURE.md), not by the per-cert rotation path.
_CA_VALIDITY_DAYS = 3650

# Default leaf-cert lifetime — decision 2 of the PKI plan: 90 days for
# scanners, auto-rotated by the agent at ~66 days.
DEFAULT_LEAF_TTL_DAYS = 90
_MAX_LEAF_TTL_DAYS = 825  # CA/Browser-forum historical leaf maximum

# CRL validity window: the staleness bound baked into the CRL. The in-stack
# gateway does not use the CRL; it re-reads registry.json when it changes.
_CRL_VALIDITY_DAYS = 7

# Clock-skew allowance so a freshly issued cert is not rejected by a
# verifier whose clock is a little behind.
_BACKDATE = timedelta(minutes=5)

# Roles a client cert may carry. Mirrors sigrift.bridge.dependencies.Role
# minus KEYMASTER (license authority is never delegated to a cert).
VALID_CERT_ROLES = frozenset({"sensor", "node", "viewer", "analyst", "admin"})

# DNS-label-ish identity: what goes in the CN and the DNS SAN. Decision 3
# of the PKI plan picked a plain DNS SAN over SPIFFE URIs. Anchored with
# \A/\Z and applied with fullmatch: '$' also matches before a trailing
# newline, which would let 'edge-1\n' into the CN, the SAN and the logs.
_IDENTITY_RE = re.compile(r"\A[a-zA-Z0-9]([a-zA-Z0-9._-]{0,251}[a-zA-Z0-9])?\Z")

# Secrets directory (see the module docstring). The bridge image sets
# BRIDGE_SECRETS_DIR=/app/secrets, backed by the `bridge_secrets` compose
# volume that only the bridge mounts.
SECRETS_DIR_ENV = "BRIDGE_SECRETS_DIR"
_KEY_NAME = "ca.key"

# The bridge's default data directory (persistence.py's default), used by
# the `migrate-key` command line.
_DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"

# registry.json: each entry is keyed by the certificate's serial in canonical
# decimal (str(int)); the fields the CA reads must have these types if set.
_SERIAL_RE = re.compile(r"\A[1-9][0-9]{0,47}\Z")
_ENTRY_FIELD_TYPES: dict[str, tuple[type, ...]] = {
    "revoked": (bool,),
    "revoked_at": (str, type(None)),
    "issued_at": (str, type(None)),
    "not_after": (str, type(None)),
}

# A CRL cannot hold a revocation date before this (RFC 5280 UTCTime).
_EARLIEST_REVOCATION_DATE = datetime(1950, 1, 1, tzinfo=timezone.utc)

# The lock serialising changes to registry.json, and creating the CA,
# between processes (CertificateAuthority._exclusive). An empty file next to
# the registry, so every process that shares the registry shares the lock,
# whatever key directory it was given.
_LOCK_NAME = ".ca.lock"
# How long a change waits for another process to release the lock. It is
# held for one read-modify-write of the registry or one CA creation:
# milliseconds. A wait this long means the holder is stopped or hung; the
# change then fails (CAStateError, a 503 from the API) rather than keep the
# caller waiting on it. (The API makes changes on threads of their own, so
# the wait does not hold up the bridge's other requests: routers/ca.py.)
_LOCK_TIMEOUT_SECONDS = 5.0
# How often a waiting change tries the lock again: the same short interval
# however long it has waited. A wait that backed off would, each time the
# lock is released, lose it to a change that has just arrived (and tries at
# once), such as the holder's next one, and could starve until it timed
# out. It is still not a queue, but a change that has waited long is as
# likely to get the lock as one that has just begun to wait.
_LOCK_POLL_SECONDS = 0.001


class CAError(Exception):
    """Raised for CA misuse: bad CSR, bad identity, uninitialised CA."""


class CAStateError(CAError):
    """The CA's files are in a state it refuses to use until an operator acts.

    For example: the private key does not belong to the CA certificate, a
    key exists without its certificate, the registry cannot be read, or
    the CA lock cannot be taken (another process has held it for longer
    than :data:`_LOCK_TIMEOUT_SECONDS`). Nothing is signed, issued, revoked
    or overwritten while it is raised; the message says what to do.
    """


class _NoCADirectoryError(CAStateError):
    """There is no CA directory yet, so no registry and no lock file."""


def validate_identity(identity: str) -> str:
    """Return *identity* unchanged if it is a usable cert identity.

    Raises :class:`CAError` otherwise. The identity becomes both the
    subject CN and a DNS SAN, so it must be a DNS-label-shaped string.
    """
    if not identity or not _IDENTITY_RE.fullmatch(identity):
        raise CAError(
            f"invalid identity {identity!r}: must be 1-253 chars, "
            "alphanumeric plus '.', '-', '_', no leading/trailing punctuation"
        )
    return identity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _atomic_write(path: Path, data: bytes, *, mode: int) -> None:
    """Write *data* to *path* atomically (tmp + rename) with *mode* perms.

    The temporary file is created ``0600``, so a private key is never
    readable by anyone else, even before the final chmod. Its name is
    fixed, so two processes writing the same *path* would remove or rename
    each other's temp file: ``registry.json`` and ``ca.crt`` are written
    only under the CA lock (:meth:`CertificateAuthority._exclusive`).
    """
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp_path.unlink()
    except FileNotFoundError:
        pass
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)


def _write_new_file(path: Path, data: bytes) -> tuple[int, int]:
    """Create *path* (``0600``) holding *data*; fail if anything is there.

    Returns the new file's ``(st_dev, st_ino)``.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(data)
            info = os.fstat(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)  # our own partial file, nothing else
        raise
    return info.st_dev, info.st_ino


# Temp copies of the CA private key made by _create_private_file. One is
# left behind only if the process is killed between writing and removing
# it; CertificateAuthority removes those once they are this old (a live
# bootstrap keeps its own for milliseconds).
_KEY_TEMP_RE = re.compile(r"\A\." + re.escape(_KEY_NAME) + r"\.[0-9a-f]{16}\.tmp\Z")
_STALE_KEY_TEMP_SECONDS = 60


def _create_private_file(path: Path, data: bytes) -> tuple[int, int]:
    """Create *path* holding *data* with mode ``0600``, never replacing anything.

    Returns the ``(st_dev, st_ino)`` of the file created at *path*.

    Raises :class:`FileExistsError` if anything (a file, a directory, a
    dangling symlink) is already at *path*. Unlike :func:`_atomic_write`,
    this cannot clobber a file another process created a moment earlier:
    the CA lock belongs to a CA directory, and two CA directories (two
    data directories) can share one key directory and bootstrap at the
    same time; without ``fcntl`` there is only the thread lock. The data
    goes to a temp file with a name of its own (created ``0600``, without
    following links, before any byte is written), which is then
    hard-linked into place, so *path* appears complete or not at all.
    """
    # A temp file left under the old fixed name (or planted there) is
    # removed, never followed.
    stale = path.with_suffix(path.suffix + ".tmp")
    try:
        stale.unlink()
    except FileNotFoundError:
        pass
    tmp_path = path.with_name(f".{path.name}.{os.urandom(8).hex()}.tmp")
    created = _write_new_file(tmp_path, data)
    try:
        os.link(tmp_path, path)
    except FileExistsError:
        raise
    except OSError:
        # No hard links on this filesystem: create it in place, still
        # exclusively (a crash mid-write leaves a partial key, which the
        # CA refuses to use or replace, as it does any key without ca.crt).
        created = _write_new_file(path, data)
    finally:
        tmp_path.unlink(missing_ok=True)
    return created


def _restrict_mode(path: Path, mode: int, *, directory: bool) -> None:
    """Remove any permission bits outside *mode* from *path*, if it exists.

    For a CA private key or key directory restored or copied with a loose
    mode. A symlink is left alone (never followed), and a failure (say, a
    root-owned file in a bridge running as another user) is logged, not
    raised: the CA must keep working.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno != errno.ELOOP:  # ELOOP: a symlink, left alone
            logger.warning("Could not check the permissions of %s: %s", path, exc)
        return
    try:
        info = os.fstat(fd)
        if not (stat.S_ISDIR if directory else stat.S_ISREG)(info.st_mode):
            return
        current = stat.S_IMODE(info.st_mode)
        if not current & ~mode:
            return
        try:
            os.fchmod(fd, current & mode)
        except OSError as exc:
            logger.warning(
                "%s has mode %04o, which lets other users get at the CA private "
                "key, and it could not be restricted to %04o (%s): fix its owner "
                "or mode",
                path,
                current,
                current & mode,
                exc,
            )
            return
        logger.warning(
            "Restricted %s from mode %04o to %04o: the CA private key is for the "
            "bridge only",
            path,
            current,
            current & mode,
        )
    finally:
        os.close(fd)


def _load_failure(exc: BaseException, what: str) -> str:
    """Why a CA file could not be loaded, without any of its content."""
    if isinstance(exc, OSError):
        return f"it cannot be read: {exc.strerror or exc.__class__.__name__}"
    return f"it is not {what}"


def _revocation_date(revoked_at: str | None, now: datetime) -> datetime:
    """The CRL date for a registry ``revoked_at``: *now* if unusable."""
    try:
        when = datetime.fromisoformat(revoked_at) if revoked_at else now
    except ValueError:
        return now
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when if when >= _EARLIEST_REVOCATION_DATE else now


def _spki(public_key: Any) -> bytes:
    """DER SubjectPublicKeyInfo of *public_key*, for comparing keys."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def secrets_dir(data_dir: str | Path) -> Path:
    """The bridge secrets directory belonging to the data dir *data_dir*.

    ``BRIDGE_SECRETS_DIR`` when it is set (the bridge image sets
    ``/app/secrets``); otherwise a ``secrets/`` directory next to
    *data_dir* (``src/sigrift/bridge/secrets`` for a from-source bridge).
    """
    configured = os.environ.get(SECRETS_DIR_ENV, "").strip()
    if configured:
        return Path(configured)
    return Path(data_dir).parent / "secrets"


def _st_dev(path: Path) -> int | None:
    """``st_dev`` of *path*, or of its nearest existing ancestor."""
    for candidate in (path, *path.parents):
        try:
            return candidate.stat().st_dev
        except OSError:
            continue
    return None


def _key_dir_is_ephemeral(key_dir: Path, ca_dir: Path) -> bool:
    """True if *key_dir* is on the root filesystem but *ca_dir* is not.

    In a container that means the CA dir is a volume while the key dir is
    part of the container's own, throw-away layer — a compose file from
    before the ``bridge_secrets`` volume. Moving the key there would lose
    it, and with it every issued client certificate, on the next
    ``docker compose up``, so the key stays where it is instead. (On a
    host whose data dir is on its own partition this also holds back a
    BRIDGE_SECRETS_DIR on ``/``: the safe direction, and logged.)
    """
    root_dev = _st_dev(Path("/"))
    ca_dev = _st_dev(ca_dir)
    return _st_dev(key_dir) == root_dev and ca_dev is not None and ca_dev != root_dev


def _same_key_entry(legacy: Path, key_path: Path) -> bool:
    """True if *key_path* names the directory entry *legacy* is.

    That is the same directory reached another way, or *key_path* a
    symlink to *legacy*.  A hard link (two entries, one inode) is not:
    removing one of its names leaves the key at the other.
    """
    try:
        if not os.path.samefile(legacy, key_path):
            return False
    except OSError:
        return False
    if key_path.is_symlink():
        return True
    return legacy.parent.resolve() == key_path.parent.resolve()


def _move_private_file(src: Path, dst: Path) -> None:
    """Move *src* to *dst* (mode 0600), across filesystems if need be.

    The source is removed only once the destination is complete.
    """
    try:
        os.replace(src, dst)
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
        _atomic_write(dst, src.read_bytes(), mode=0o600)
        src.unlink()
    else:
        os.chmod(dst, 0o600)


def _unused_name(directory: Path, kind: str) -> Path:
    """A new path for a set-aside CA key: ``ca.<kind>.<UTC time>[.<n>].key``.

    The name keeps the ``.key`` suffix so the ``*.key`` ignore rules
    (.gitignore, .dockerignore) cover it wherever the secrets directory
    is — it is a private key.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem, suffix = os.path.splitext(_KEY_NAME)
    candidate = directory / f"{stem}.{kind}.{stamp}{suffix}"
    n = 0
    while candidate.exists() or candidate.is_symlink():
        n += 1
        candidate = directory / f"{stem}.{kind}.{stamp}.{n}{suffix}"
    return candidate


class CertificateAuthority:
    """Issuing CA backed by ``cryptography`` and a JSON registry.

    Parameters
    ----------
    ca_dir : str or Path
        Directory holding ``ca.crt`` and ``registry.json``. Created on
        first use.
    key_dir : str or Path, optional
        Directory holding the private key ``ca.key``. Defaults to
        ``secrets_dir(<parent of ca_dir>) / <name of ca_dir>`` — e.g.
        ``/app/secrets/ca`` in the bridge container. An existing key in
        *ca_dir* (where earlier versions kept it) is moved here.
    """

    def __init__(
        self, ca_dir: str | Path, *, key_dir: str | Path | None = None
    ) -> None:
        self._dir = Path(ca_dir)
        self._cert_path = self._dir / "ca.crt"
        self._registry_path = self._dir / "registry.json"
        self._lock = threading.RLock()
        self._lock_path = self._dir / _LOCK_NAME
        self._held = threading.local()  # .depth: _exclusive() nesting per thread
        legacy_key = self._dir / _KEY_NAME
        if key_dir is None:
            key_dir = secrets_dir(self._dir.parent) / self._dir.name
        key_dir = Path(key_dir)
        if key_dir != self._dir and _key_dir_is_ephemeral(key_dir, self._dir):
            logger.warning(
                "The CA key directory %s (%s) is on the root filesystem — in "
                "a container, its throw-away layer — but the CA directory %s "
                "is on a volume: keeping the CA private key at %s, where the "
                "gateway can read it. To move it out, mount a volume at %s "
                "that only the bridge uses (the `bridge_secrets` volume in "
                "the shipped docker-compose.yml) or point %s at a directory "
                "on the data directory's filesystem.",
                key_dir,
                SECRETS_DIR_ENV,
                self._dir,
                legacy_key,
                key_dir.parent,
                SECRETS_DIR_ENV,
            )
            key_dir = self._dir
        self._key_path = key_dir / _KEY_NAME
        if self._key_path != legacy_key:
            try:
                self._migrate_legacy_key(legacy_key)
            except OSError as exc:
                # Never lose the CA over a failed move: keep using the key
                # where it is, loudly.
                logger.error(
                    "Could not move the CA private key from %s to %s (%s); "
                    "using it where it is, which the gateway can read",
                    legacy_key,
                    self._key_path,
                    exc,
                )
                self._key_path = legacy_key
        self._restrict_key_modes()
        self._remove_stale_key_temps()

    @property
    def key_path(self) -> Path:
        """Where the CA private key is (or will be) stored."""
        return self._key_path

    # -- Key location migration --------------------------------------------

    def _migrate_legacy_key(self, legacy: Path) -> None:
        """Move a key an earlier version left in the CA dir to the key dir."""
        if not legacy.is_symlink() and not legacy.exists():
            return
        with self._lock:
            if legacy.is_symlink() or not legacy.is_file():
                logger.error(
                    "%s is not a regular file — not moving it; remove it and "
                    "restore the CA private key to %s",
                    legacy,
                    self._key_path,
                )
                return
            self._key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self._key_path.exists() and _same_key_entry(legacy, self._key_path):
                # The key dir is the CA dir under another spelling (a
                # symlink, or BRIDGE_SECRETS_DIR set to the data dir), or
                # the key path links to this file: "both" keys are the one
                # key, and removing the "legacy" copy would delete it.
                logger.debug("%s is %s; nothing to move", legacy, self._key_path)
                return
            if not self._key_path.exists():
                _move_private_file(legacy, self._key_path)
                logger.info(
                    "Moved the CA private key from %s to %s (it no longer "
                    "lives in the data directory the gateway mounts)",
                    legacy,
                    self._key_path,
                )
                return
            old = legacy.read_bytes()
            current = self._key_path.read_bytes()
            if old == current:
                legacy.unlink()
                logger.info(
                    "Removed %s: the same CA private key is already at %s",
                    legacy,
                    self._key_path,
                )
                return
            # Two different keys. The one that belongs to ca.crt is the CA
            # key; the other is kept next to it (never deleted, never left
            # in the data directory).
            if self._matches_cert(old) and not self._matches_cert(current):
                kept = _unused_name(self._key_path.parent, "replaced")
                _move_private_file(self._key_path, kept)
                _move_private_file(legacy, self._key_path)
            else:
                kept = _unused_name(self._key_path.parent, "legacy")
                _move_private_file(legacy, kept)
            logger.warning(
                "Found two different CA private keys, %s and %s: kept the one "
                "that matches %s as %s and moved the other to %s",
                legacy,
                self._key_path,
                self._cert_path,
                self._key_path,
                kept,
            )

    def _matches_cert(self, key_pem: bytes) -> bool:
        """True if *key_pem* is the private key of the CA certificate."""
        try:
            cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
            key = serialization.load_pem_private_key(key_pem, password=None)
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
            return False
        return _spki(key.public_key()) == _spki(cert.public_key())

    def _restrict_key_modes(self) -> None:
        """Make an existing key ``0600`` and its own directory ``0700``.

        The CA creates both that way, but a key restored or copied with a
        loose mode would otherwise stay readable by other local users. The
        CA directory itself is never changed, even when the key is in it
        (the legacy and ephemeral fall-backs): the gateway reads ``ca.crt``
        and ``registry.json`` there.
        """
        key_dir = self._key_path.parent
        if key_dir != self._dir:
            # Compare the real paths too: the same directory spelled another
            # way, or a key dir that contains the CA dir, is not changed.
            try:
                real_key_dir = key_dir.resolve()
                real_ca_dir = self._dir.resolve()
            except (OSError, RuntimeError):  # a symlink loop
                real_key_dir = real_ca_dir = None
            if real_key_dir != real_ca_dir and real_key_dir not in real_ca_dir.parents:
                _restrict_mode(key_dir, 0o700, directory=True)
        _restrict_mode(self._key_path, 0o600, directory=False)

    def _remove_stale_key_temps(self) -> None:
        """Remove temp copies of the CA private key left by a killed start-up.

        Only regular files named like :func:`_create_private_file`'s temp
        files and older than :data:`_STALE_KEY_TEMP_SECONDS` (a bootstrap
        running right now in another process keeps its own for a moment);
        a symlink or anything else is left alone.
        """
        key_dir = self._key_path.parent
        try:
            names = os.listdir(key_dir)
        except OSError:
            return
        cutoff = time.time() - _STALE_KEY_TEMP_SECONDS
        for name in names:
            if not _KEY_TEMP_RE.fullmatch(name):
                continue
            path = key_dir / name
            try:
                info = os.lstat(path)
                if not stat.S_ISREG(info.st_mode) or info.st_mtime > cutoff:
                    continue
                path.unlink()
            except OSError as exc:
                logger.warning("Could not remove the stale temp file %s: %s", path, exc)
                continue
            logger.warning(
                "Removed %s, a temporary copy of the CA private key left by a "
                "start-up that was killed while creating the CA",
                path,
            )

    # -- Inter-process lock -------------------------------------------------

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold the CA lock: the file lock, then this object's thread lock.

        Held for every read-modify-write of ``registry.json`` and while the
        CA is created. The thread lock alone serialised only the threads of
        one process, but each bridge worker and ``scripts/pki_bootstrap.py``
        open a CA of their own on the same directory: one of them writing
        back a registry it read before another's change undid that change,
        a revocation already reported done or a certificate already handed
        out. The file lock is an advisory ``flock`` on :data:`_LOCK_NAME` in
        the CA directory, taken by every process that changes the registry.

        The file lock is waited for first, without the thread lock, so
        this object's readers (who take only the thread lock: the registry
        is replaced atomically, they never see half a write) do not wait
        for another process. Re-entrant within a thread. Raises
        :class:`CAStateError` (nothing changed) if the lock cannot be taken
        within :data:`_LOCK_TIMEOUT_SECONDS`, or the lock file is not a
        regular file this process can open.
        """
        depth = getattr(self._held, "depth", 0)
        if depth:  # this thread holds both locks already
            self._held.depth = depth + 1
            try:
                yield
            finally:
                self._held.depth = depth
            return
        fd = self._acquire_file_lock() if _fcntl is not None else None
        try:
            with self._lock:
                self._held.depth = 1
                try:
                    yield
                finally:
                    self._held.depth = 0
        finally:
            if fd is not None:
                # Unlock explicitly: a child forked meanwhile shares the
                # descriptor, so closing it alone would not release it.
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_UN)
                finally:
                    os.close(fd)

    def _acquire_file_lock(self) -> int:
        """Lock :data:`_LOCK_NAME`; returns the descriptor holding the lock."""
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        fd: int | None = self._open_lock_file()
        try:
            while True:
                try:
                    _fcntl.flock(fd, _fcntl.LOCK_EX | _fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    locked = False
                except OSError as exc:  # e.g. ENOLCK: no locks on this filesystem
                    raise self._lock_error(
                        f"cannot be locked ({exc.strerror or exc.__class__.__name__})"
                    ) from exc
                if locked:
                    if self._holds_lock_file(fd):
                        return fd
                    # The lock file was removed or replaced while this one
                    # waited: the file locked now excludes no one, as the
                    # next process locks the new one. Lock that instead.
                    os.close(fd)
                    fd = None
                    fd = self._open_lock_file()
                if time.monotonic() >= deadline:
                    raise CAStateError(
                        f"Could not take the CA lock {self._lock_path} within "
                        f"{_LOCK_TIMEOUT_SECONDS:g} seconds: another process using "
                        "this CA directory (another bridge worker, or "
                        "scripts/pki_bootstrap.py) holds it, and may be stopped or "
                        "hung. Nothing was issued, revoked or created. Retry; if "
                        "this persists, find the process holding the file (for "
                        "example with lsof or fuser) and let it finish or stop it."
                    )
                time.sleep(_LOCK_POLL_SECONDS)  # not backing off: see there
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise

    def _open_lock_file(self) -> int:
        """Open (or create, ``0600``) the lock file, never through a symlink."""
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(self._lock_path, flags, 0o600)
        except FileNotFoundError as exc:  # no CA directory
            raise _NoCADirectoryError(
                "CA is not initialised; call ensure_ca() first"
            ) from exc
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):  # O_NOFOLLOW refused
                raise self._lock_error(
                    "is a symlink, which the CA does not follow: remove it"
                ) from exc
            raise self._lock_error(
                f"cannot be opened ({exc.strerror or exc.__class__.__name__}): "
                "check the owner and mode of the CA directory and of the file"
            ) from exc
        try:
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
        except BaseException:
            os.close(fd)
            raise
        if not regular:  # O_NONBLOCK: a FIFO there did not block the open
            os.close(fd)
            raise self._lock_error("is not a regular file: remove it")
        return fd

    def _holds_lock_file(self, fd: int) -> bool:
        """True if *fd* is the file now at :data:`_LOCK_NAME`."""
        try:
            current = os.stat(self._lock_path, follow_symlinks=False)
            held = os.fstat(fd)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise self._lock_error(
                f"cannot be checked ({exc.strerror or exc.__class__.__name__})"
            ) from exc
        return (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino)

    def _lock_error(self, problem: str) -> CAStateError:
        return CAStateError(
            f"The CA lock file {self._lock_path} {problem}. Every process that "
            "changes the CA registry (each bridge worker, scripts/pki_bootstrap.py) "
            "takes this lock, so that none of them undoes another's issuance or "
            "revocation; without it, nothing was issued, revoked or created. The "
            "file is empty: removing it while no such process runs is safe."
        )

    # -- Bootstrap ----------------------------------------------------------

    @property
    def is_initialized(self) -> bool:
        """True once the CA cert and key both exist on disk."""
        return self._cert_path.exists() and self._key_path.exists()

    def ensure_ca(self, *, common_name: str = "SigRift Bridge CA") -> None:
        """Create the CA cert + key if they do not already exist.

        Idempotent: a second call with an existing CA is a no-op. The
        private key is written ``0600`` (in a ``0700`` key directory);
        the cert ``0644``. An existing ``registry.json`` is kept.

        Never replaces a private key or a CA certificate: if only one of
        them is there, :class:`CAStateError` says what to do instead (the
        certificates the CA issued would stop working, and a second data
        directory sharing the key directory would take over the first
        one's key). If creating the CA fails before ``ca.crt`` is written,
        the key this call created is removed again (no certificate can
        have been issued with it), so the next call starts afresh.

        Creating the CA holds the CA lock (:meth:`_exclusive`), so another
        process opening the same CA directory waits for the CA, and the
        empty registry written here cannot replace one that process wrote.
        An existing CA needs no lock (nor a writable CA directory).
        """
        if self.is_initialized:
            return
        self._dir.mkdir(parents=True, exist_ok=True)
        self._key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self._exclusive():
            if self.is_initialized:
                return  # another process created it while this one waited
            if self._key_path.exists() or self._key_path.is_symlink():
                raise CAStateError(self._orphaned_key_message())
            if self._cert_path.exists() or self._cert_path.is_symlink():
                raise CAStateError(self._missing_key_message())

            key = ec.generate_private_key(ec.SECP256R1())
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
            now = _utcnow()
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _BACKDATE)
                .not_valid_after(now + timedelta(days=_CA_VALIDITY_DAYS))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0), critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            # The key first, without replacing anything: if another process
            # created one since the check above, it is left as it is.
            try:
                created = _create_private_file(
                    self._key_path,
                    key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    ),
                )
            except FileExistsError as exc:
                if not (self._key_path.exists() or self._key_path.is_symlink()):
                    raise  # not the key: its temp file's name was taken
                raise CAStateError(
                    f"A CA private key appeared at {self._key_path} while this CA "
                    "was being created (another process is creating a CA with the "
                    "same key directory), so it was left untouched and no CA was "
                    "created here. Retry once the other process has finished."
                ) from exc
            try:
                _atomic_write(
                    self._cert_path,
                    cert.public_bytes(serialization.Encoding.PEM),
                    mode=0o644,
                )
                if not self._registry_path.exists():
                    self._write_registry({"issued": {}})
            except BaseException as exc:
                if not (self._cert_path.exists() or self._cert_path.is_symlink()):
                    self._discard_new_key(created, exc)
                raise
            logger.info("CA bootstrapped at %s (CN=%s)", self._dir, common_name)

    def _discard_new_key(self, created: tuple[int, int], exc: BaseException) -> None:
        """Remove the key :meth:`ensure_ca` just created, as ``ca.crt`` failed.

        No certificate can have been issued with it, and leaving it would
        make every later start-up refuse to create the CA until an operator
        moved it. Only the file this call created (*created* is its
        ``(st_dev, st_ino)``) is removed; anything else now at
        :attr:`key_path` is left alone.
        """
        try:
            info = os.lstat(self._key_path)
            if (info.st_dev, info.st_ino) != created:
                logger.warning(
                    "Creating the CA failed (%r); %s is no longer the key this "
                    "start-up created, so it was left alone",
                    exc,
                    self._key_path,
                )
                return
            os.unlink(self._key_path)
        except OSError as error:
            logger.error(
                "Creating the CA failed (%r) and the new CA private key %s could "
                "not be removed again (%s): move it aside before retrying",
                exc,
                self._key_path,
                error,
            )
            return
        logger.warning(
            "Creating the CA failed before %s was written (%r): removed the new CA "
            "private key %s again (no certificate was issued with it)",
            self._cert_path,
            exc,
            self._key_path,
        )

    def _missing_key_message(self) -> str:
        """What to do about a CA certificate whose private key is missing."""
        return (
            f"Refusing to create a new CA: there is a CA certificate at "
            f"{self._cert_path} but no private key at {self._key_path}, and a new "
            "CA would replace that certificate, so no certificate it issued would "
            "verify any more. Do one of these, then retry: (1) restore or mount the "
            "key: check that the volume holding it (bridge_secrets) is mounted, "
            f"that {SECRETS_DIR_ENV} (or scripts/pki_bootstrap.py --secrets-dir) "
            "names the same directory as when the CA was created, or restore "
            "ca.key from the same backup as ca.crt; (2) only if a new CA is really "
            "intended (every issued certificate must then be issued again), move "
            "ca.crt aside, e.g. to ca.retired.<date>.crt. Nothing was changed."
        )

    def _orphaned_key_message(self) -> str:
        """What to do about a private key whose CA certificate is missing."""
        if not self._key_path.exists():
            return (
                f"Refusing to create a new CA: {self._key_path} is a symlink to a "
                "file that does not exist (is the volume holding the CA private "
                "key mounted?), and a new CA would replace it. Restore or mount "
                "the key it points to; only if a new CA is really intended, "
                "remove the symlink. Nothing was changed."
            )
        return (
            f"Refusing to create a new CA: there is already a private key at "
            f"{self._key_path} but no CA certificate at {self._cert_path}, and a "
            "new CA would replace that key and invalidate every certificate it "
            "issued. First, if another bridge or scripts/pki_bootstrap.py is "
            "starting up with the same key directory right now, wait for it to "
            "finish and retry: it may be writing ca.crt. Otherwise do one of these, "
            "then retry: (1) if ca.crt was lost, restore it from the same backup "
            "as the key; (2) if this data directory is a second CA sharing the key "
            "directory with another one, give it a key directory of its own "
            f"(scripts/pki_bootstrap.py --secrets-dir, or {SECRETS_DIR_ENV}) and "
            "check that --data-dir is right; (3) if a new CA is really intended, "
            "or a first start-up was interrupted (killed) before it wrote ca.crt "
            "(no certificate was issued with that key then), move the key aside, "
            "e.g. to ca.retired.<date>.key. A key found at start-up is never "
            "removed or overwritten automatically."
        )

    # -- Internal load helpers ---------------------------------------------

    def _require_ca(self) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
        """The CA certificate and its private key, checked to belong together."""
        if not self.is_initialized:
            raise CAStateError("CA is not initialised; call ensure_ca() first")
        # Only the paths and the kind of problem go into the message: no
        # parser output that could quote the file.
        try:
            cert = x509.load_pem_x509_certificate(self._cert_path.read_bytes())
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise CAStateError(
                f"The CA certificate {self._cert_path} cannot be used: "
                f"{_load_failure(exc, 'a PEM certificate')}. Fix its owner or mode, "
                "or restore it from the same backup as the CA private key. Nothing "
                "was signed."
            ) from exc
        try:
            key = serialization.load_pem_private_key(
                self._key_path.read_bytes(), password=None
            )
        except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise CAStateError(
                f"The CA private key {self._key_path} cannot be used: "
                f"{_load_failure(exc, 'an unencrypted PEM private key')}. Fix its "
                f"owner or mode, or restore it from the same backup as "
                f"{self._cert_path}. Nothing was signed."
            ) from exc
        if not isinstance(key, ec.EllipticCurvePrivateKey):
            raise CAStateError(
                f"The CA private key {self._key_path} is not an EC private key, so "
                f"it is not the key of {self._cert_path}. Nothing was signed."
            )
        if _spki(key.public_key()) != _spki(cert.public_key()):
            # Anything signed with it would name this CA as issuer but not
            # chain to ca.crt, so nothing is signed or registered.
            raise CAStateError(
                f"The CA private key {self._key_path} does not belong to the CA "
                f"certificate {self._cert_path}, so nothing can be signed. Restore "
                "the ca.key that was backed up together with this ca.crt (the "
                "secrets and the data directory must come from the same backup), "
                "or check whether one of the set-aside keys next to it "
                "(ca.legacy.*.key, ca.replaced.*.key) is the right one."
            )
        return cert, key

    def _read_registry(self) -> dict[str, Any]:
        """The registry. Only a missing file means an empty one (a new CA).

        Raises :class:`CAStateError` if the file is there but cannot be read
        or is not a registry: it is the only record of the issued
        certificates and their revocations (the gateway enforces it), so it
        is never treated as empty or written over.
        """
        path = self._registry_path
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            if path.is_symlink():
                raise self._registry_error("is a dangling symlink") from None
            return {"issued": {}}
        except OSError as exc:
            reason = exc.strerror or exc.__class__.__name__
            raise self._registry_error(f"cannot be read ({reason})") from exc
        try:
            data = json.loads(raw.decode("utf-8"))
        except ValueError as exc:  # JSONDecodeError, UnicodeDecodeError
            raise self._registry_error(f"is not valid JSON ({exc})") from exc
        issued = data.get("issued") if isinstance(data, dict) else None
        if not isinstance(issued, dict) or not all(
            isinstance(entry, dict) for entry in issued.values()
        ):
            raise self._registry_error(
                "is not a CA registry (expected an 'issued' object mapping each "
                "serial to its entry)"
            )
        for serial, entry in issued.items():
            # What list_certs and generate_crl rely on: a canonical decimal
            # serial a certificate can carry, and fields of the right type.
            if not _SERIAL_RE.fullmatch(serial) or int(serial) >> 159:
                raise self._registry_error(
                    f"is not a CA registry: the entry {serial[:48]!r} is not under "
                    "a certificate serial number (a positive decimal integer below "
                    "2**159, no leading zeros)"
                )
            for field, types in _ENTRY_FIELD_TYPES.items():
                if field in entry and not isinstance(entry[field], types):
                    expected = " or ".join(
                        "null" if t is type(None) else t.__name__ for t in types
                    )
                    raise self._registry_error(
                        f"is not a CA registry: the entry {serial!r} has a "
                        f"{field!r} that is not {expected}"
                    )
        return data

    def _registry_error(self, problem: str) -> CAStateError:
        return CAStateError(
            f"The CA registry {self._registry_path} {problem}. It records every "
            "issued certificate and every revocation, so until it is fixed no "
            "certificate is issued or revoked, no CRL is signed and the file is "
            "not written over. Repair it or restore it from a backup; do not "
            "delete it, which would lose every revocation."
        )

    def _write_registry(self, data: dict[str, Any]) -> None:
        _atomic_write(
            self._registry_path,
            json.dumps(data, indent=2, sort_keys=True).encode("utf-8"),
            mode=0o600,
        )

    # -- Public read accessors ---------------------------------------------

    @property
    def ca_cert_pem(self) -> bytes:
        """PEM bytes of the CA certificate (public — safe to hand out)."""
        if not self._cert_path.exists():
            raise CAStateError("CA is not initialised; call ensure_ca() first")
        try:
            return self._cert_path.read_bytes()
        except OSError as exc:
            raise CAStateError(
                f"The CA certificate {self._cert_path} cannot be used: "
                f"{_load_failure(exc, 'a PEM certificate')}. Fix its owner or mode."
            ) from exc

    def list_certs(self) -> list[dict[str, Any]]:
        """Return registry entries for every issued cert (newest first).

        Raises :class:`CAStateError` if the registry is unreadable.
        """
        with self._lock:
            issued = self._read_registry()["issued"]
        rows = [{"serial": serial, **meta} for serial, meta in issued.items()]
        rows.sort(key=lambda r: r.get("issued_at") or "", reverse=True)
        return rows

    def get_cert(self, serial: str) -> dict[str, Any] | None:
        """Return the registry entry for *serial*, or None if unknown.

        Raises :class:`CAStateError` if the registry is unreadable.
        """
        with self._lock:
            return self._read_registry()["issued"].get(serial)

    # -- Signing ------------------------------------------------------------

    def _issue(
        self,
        public_key: Any,
        *,
        identity: str,
        role: str,
        ttl_days: int,
    ) -> tuple[x509.Certificate, dict[str, Any]]:
        """Build, sign, and register a client-auth leaf cert.

        Shared by :meth:`sign_csr` (public key from a CSR) and
        :meth:`issue_cert` (bridge-generated key). The bridge sets the
        subject CN, the DNS SAN, the client-auth EKU and the role — the
        caller never controls those, only the public key being bound.
        """
        identity = validate_identity(identity)
        if role not in VALID_CERT_ROLES:
            raise CAError(
                f"invalid role {role!r}: expected one of {sorted(VALID_CERT_ROLES)}"
            )
        if not 1 <= ttl_days <= _MAX_LEAF_TTL_DAYS:
            raise CAError(f"ttl_days must be 1..{_MAX_LEAF_TTL_DAYS}, got {ttl_days}")

        # The CA lock from reading the registry to writing it back: no other
        # process (bridge worker, pki_bootstrap) changes it in between.
        with self._exclusive():
            ca_cert, ca_key = self._require_ca()
            # Before signing: a cert is never handed out without being
            # recorded, and a broken registry is never replaced.
            registry = self._read_registry()
            now = _utcnow()
            not_after = now + timedelta(days=ttl_days)
            serial = x509.random_serial_number()

            cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, identity)])
                )
                .issuer_name(ca_cert.subject)
                .public_key(public_key)
                .serial_number(serial)
                .not_valid_before(now - _BACKDATE)
                .not_valid_after(not_after)
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None),
                    critical=True,
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=False,
                        crl_sign=False,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(identity)]),
                    critical=False,
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(public_key),
                    critical=False,
                )
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(
                        ca_key.public_key()
                    ),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            entry = {
                "identity": identity,
                "role": role,
                "san": f"DNS:{identity}",
                "fingerprint_sha256": fingerprint,
                "issued_at": now.isoformat(),
                "not_before": (now - _BACKDATE).isoformat(),
                "not_after": not_after.isoformat(),
                "revoked": False,
                "revoked_at": None,
            }
            registry["issued"][str(serial)] = entry
            self._write_registry(registry)

        logger.info(
            "Issued cert: identity=%s role=%s serial=%s expires=%s",
            identity,
            role,
            serial,
            not_after.isoformat(),
        )
        result = {
            "cert_pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "serial": str(serial),
            **entry,
        }
        return cert, result

    def sign_csr(
        self,
        csr_pem: bytes,
        *,
        identity: str,
        role: str,
        ttl_days: int = DEFAULT_LEAF_TTL_DAYS,
    ) -> dict[str, Any]:
        """Sign *csr_pem* into a client-auth leaf cert for *identity*.

        Only the CSR's public key is used; its subject and extensions
        are ignored, so a CSR cannot claim an identity or capability it
        was not granted.

        Returns a dict with ``cert_pem``, ``serial``, ``fingerprint_sha256``,
        ``not_before``, ``not_after``, ``identity`` and ``role``.
        """
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
        except ValueError as exc:
            raise CAError(f"could not parse CSR: {exc}") from exc
        if not csr.is_signature_valid:
            raise CAError("CSR signature is invalid")

        _cert, result = self._issue(
            csr.public_key(), identity=identity, role=role, ttl_days=ttl_days
        )
        return result

    def issue_cert(
        self,
        *,
        identity: str,
        role: str,
        ttl_days: int = DEFAULT_LEAF_TTL_DAYS,
    ) -> dict[str, Any]:
        """Generate a keypair and issue a client cert for *identity*.

        Unlike :meth:`sign_csr`, the bridge generates the private key
        itself and returns it alongside the certificate. Used by the
        admin UI and bootstrap, where the operator needs the key file
        to install on the agent. The returned dict adds ``key_pem`` to
        everything :meth:`sign_csr` returns.
        """
        key = ec.generate_private_key(ec.SECP256R1())
        _cert, result = self._issue(
            key.public_key(), identity=identity, role=role, ttl_days=ttl_days
        )
        result["key_pem"] = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return result

    # -- Revocation + CRL ---------------------------------------------------

    def revoke(self, serial: str) -> bool:
        """Mark the cert with *serial* revoked. Returns False if unknown.

        Idempotent: revoking an already-revoked cert returns True and
        leaves the original ``revoked_at`` untouched. Raises
        :class:`CAStateError` if the registry is unreadable (the cert may
        well be in it), or if the CA lock cannot be taken: a revocation is
        never reported done unless it was written under the lock, so no
        other process can write back a registry from before it.
        """
        with contextlib.ExitStack() as held:
            try:
                held.enter_context(self._exclusive())
            except _NoCADirectoryError:
                return False  # no CA directory, so no registry: nothing to revoke
            registry = self._read_registry()
            entry = registry["issued"].get(serial)
            if entry is None:
                return False
            if not entry.get("revoked"):
                entry["revoked"] = True
                entry["revoked_at"] = _utcnow().isoformat()
                self._write_registry(registry)
                logger.info(
                    "Revoked cert serial=%s identity=%s", serial, entry.get("identity")
                )
        return True

    def generate_crl(self) -> bytes:
        """Build and sign a CRL covering every revoked cert. Returns PEM.

        Raises :class:`CAStateError` rather than sign a CRL that would leave
        out revocations it cannot read.
        """
        with self._lock:
            ca_cert, ca_key = self._require_ca()
            issued = self._read_registry()["issued"]
            now = _utcnow()
            builder = (
                x509.CertificateRevocationListBuilder()
                .issuer_name(ca_cert.subject)
                .last_update(now - _BACKDATE)
                .next_update(now + timedelta(days=_CRL_VALIDITY_DAYS))
            )
            for serial, entry in issued.items():
                if not entry.get("revoked"):
                    continue
                builder = builder.add_revoked_certificate(
                    x509.RevokedCertificateBuilder()
                    .serial_number(int(serial))
                    .revocation_date(_revocation_date(entry.get("revoked_at"), now))
                    .build()
                )
            crl = builder.sign(ca_key, hashes.SHA256())
        return crl.public_bytes(serialization.Encoding.PEM)


# ---------------------------------------------------------------------------
# Command line: python3 -m sigrift.bridge.ca migrate-key
# ---------------------------------------------------------------------------


def _main(argv: list[str] | None = None) -> int:
    """Move the CA private key out of the data dir (container start-up)."""
    parser = argparse.ArgumentParser(
        prog="python3 -m sigrift.bridge.ca",
        description="Maintenance commands for the bridge's embedded CA.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    migrate = sub.add_parser(
        "migrate-key",
        help="move a CA private key left in <data-dir>/ca to the secrets dir",
    )
    migrate.add_argument(
        "--data-dir",
        type=Path,
        default=_DEFAULT_DATA_DIR,
        help="bridge data directory (default: %(default)s)",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    ca = CertificateAuthority(args.data_dir / "ca")
    if ca.key_path.exists():
        logger.info("CA private key: %s", ca.key_path)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
