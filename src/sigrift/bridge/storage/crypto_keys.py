"""Saved protocol decryption keys (the ``crypto_keys`` table, migration 51).

Keys imported from the admin console (``POST /api/crypto/keys``) used to
live in memory only and were lost at every restart, upgrade or move.  When
``BRIDGE_KEYSTORE_KEY`` is set (a Fernet key, the same format as
``BRIDGE_MFA_KEY``; the installers generate it) each imported key is saved
here, encrypted with it, and loaded back into the :class:`KeyStore` at
startup under the same ``key_id`` and ``created_at``.  Built-in and derived
keys are never saved.  Revoking a key deletes its row.

What a row holds:

* ``key_data_encrypted`` -- a Fernet token of the *envelope*, compact JSON
  ``{"algorithm", "format": 1, "key_id", "material", "protocol"}`` with the
  key bytes as standard base64.  The id, protocol and algorithm are bound
  inside the token, so an edited row cannot move a key to another id or
  protocol; the label is not, so a later rename stays possible.
* ``key_hash`` -- ``hmac-sha256:v1:<hex>``, an HMAC of the key bytes under
  a key derived from ``BRIDGE_KEYSTORE_KEY``.  It is keyed, so the database
  does not reveal whether a well-known key (LongFast, ``AQ==``, a
  channel-name PSK) was imported.  It is checked after decrypting.

Revoking a key deletes its row with ``secure_delete`` on, so the freed
database page holds zeros, and then runs a passive WAL checkpoint.
Copies made before the revoke -- the ``detections.db.pre-migration`` copy
an upgrade keeps for up to 7 days, maintenance backups, restore points --
still hold the row, readable with the same ``BRIDGE_KEYSTORE_KEY``.

Raw key bytes never reach the database file or a log line (only ids,
protocols and labels are logged).  Python leaves immutable copies while
encoding and decoding; every temporary ``bytearray`` is zeroed, as
``KeyStore.import_hex`` does (best effort).

A missing, invalid or wrong ``BRIDGE_KEYSTORE_KEY`` never deletes or
changes a row: the saved keys are left in the database, unloaded, new
imports stay memory-only, and ``/api/health`` and the console say why
(:meth:`CryptoKeyVault.health_warnings`, :meth:`CryptoKeyVault.status`).
When the value they were saved with is lost for good, the operator can
delete the rows the current key cannot read, explicitly::

    python3 -m sigrift.bridge.storage.crypto_keys forget-unreadable --yes

(without ``--yes`` it only counts them); the bridge then saves imports
again after its next restart.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import enum
import hashlib
import hmac
import json
import logging
import os
import re
import sqlite3
import sys
import threading
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography.fernet import Fernet, InvalidToken

from sigrift.bridge.storage.users import _decode_fernet_key, is_repairable_mfa_key
from sigrift.lib.crypto.key_store import CryptoKey, KeyStore

if TYPE_CHECKING:
    from sigrift.bridge.storage.base import SharedContext

logger = logging.getLogger(__name__)

KEYSTORE_KEY_ENV = "BRIDGE_KEYSTORE_KEY"
#: Secrets the gateway also holds (docker-compose.yml): BRIDGE_KEYSTORE_KEY
#: must not repeat one of them, or the gateway could read the saved keys.
_GATEWAY_SECRETS_ENV = ("BRIDGE_MFA_KEY", "BRIDGE_AUDIT_KEY")

_ENVELOPE_FORMAT = 1
_HASH_PREFIX = "hmac-sha256:v1:"
_HASH_KEY_INFO = b"sigrift crypto_keys key_hash v1"
_MAX_ID_CHARS = 128
_MAX_TOKEN_BYTES = 4096
_MAX_MATERIAL_BYTES = 256
_MAX_CREATED_BY_CHARS = 128
_LOGGED_IDS = 10
_PLAIN_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")

_KEYGEN_HINT = (
    'python3 -c "import base64, os; '
    'print(base64.urlsafe_b64encode(os.urandom(32)).decode())"'
)
_DOCS = 'see INSTALL.md, "Protocol decryption keys"'

_COUNT_SQL = (
    "SELECT COUNT(*) FROM crypto_keys WHERE tenant_id = ? AND revoked_at IS NULL"
)
_LOAD_SQL = (
    "SELECT id, protocol, key_name, key_data_encrypted, key_hash, algorithm, "
    "created_at FROM crypto_keys WHERE tenant_id = ? AND revoked_at IS NULL "
    "ORDER BY created_at, id"
)
_INSERT_SQL = (
    "INSERT INTO crypto_keys (id, protocol, key_name, key_data_encrypted, "
    "key_hash, algorithm, key_source, associated_source_id, notes, created_by, "
    "tenant_id, created_at, revoked_at) "
    "VALUES (?, ?, ?, ?, ?, ?, 'import', NULL, '', ?, ?, ?, NULL)"
)
_DELETE_SQL = "DELETE FROM crypto_keys WHERE id = ? AND tenant_id = ?"


class Persistence(str, enum.Enum):
    """Whether imported protocol decryption keys are saved, and why not."""

    #: A valid key: every saved row was loaded, or at least one was (the
    #: rest were damaged).  Imports are saved, revokes delete rows.
    ENABLED = "enabled"
    #: ``BRIDGE_KEYSTORE_KEY`` is unset or empty: memory-only, as before.
    DISABLED = "disabled"
    #: Set, but not a valid Fernet key.
    INVALID_KEY = "invalid_key"
    #: A valid key, saved rows exist, and none of them decrypts with it.
    WRONG_KEY = "wrong_key"
    #: The saved rows could not be read (a database error).
    ERROR = "error"


class CryptoKeyStorageError(RuntimeError):
    """A save or delete failed.  Carries no key material."""


def _invalid_key_problem(value: str) -> str:
    """Why *value* is not a usable ``BRIDGE_KEYSTORE_KEY`` (never the value)."""
    if is_repairable_mfa_key(value):
        return (
            "it is 43 characters long, missing the trailing '=' padding "
            "(append '=' to keep keys saved with it readable)"
        )
    return (
        "it must be 44 characters of base64 encoding 32 bytes; generate one "
        f"with: {_KEYGEN_HINT}"
    )


def _loggable_id(value: Any) -> str:
    """A row id as it may appear in a log line (no forged lines)."""
    text = value if isinstance(value, str) else repr(value)
    if _PLAIN_ID_RE.fullmatch(text):
        return text
    return repr(text)[: _MAX_ID_CHARS + 2]


def _zero(buffer: bytearray) -> None:
    KeyStore._zero_bytes(buffer)


class CryptoKeyVault:
    """Saves imported keys of a :class:`KeyStore` in ``crypto_keys``.

    Built by :func:`init_crypto_keys`, which loads the saved keys once at
    startup (:meth:`load_into`).  ``save`` and ``delete`` are called by the
    crypto router on import and revoke.
    """

    def __init__(self, ctx: SharedContext, keystore_key: str | None) -> None:
        self._ctx = ctx
        self._tenant_id = ctx.tenant_id
        self._fernet: Fernet | None = None
        self._hash_key: bytes | None = None
        self._problem: str | None = None
        self._loaded = 0
        self._not_loaded = 0
        # Set once load_into ran: until then nothing is saved, so a key
        # that cannot read the existing rows never writes next to them.
        self._checked = False
        self._saved: set[str] = set()
        self._lock = threading.Lock()
        #: Held by the crypto router across an import (add to the store,
        #: then save) and a revoke (check, delete the row, zero the key),
        #: so a revoke never slips between an import's two steps and
        #: leaves a row that brings the revoked key back at the next start.
        self.mutation_lock = threading.Lock()
        #: The gateway secret BRIDGE_KEYSTORE_KEY repeats, if any.
        self.reused_secret: str | None = None
        value = (keystore_key or "").strip()
        if not value:
            self._state = Persistence.DISABLED
            return
        raw = _decode_fernet_key(value)
        if raw is None:
            self._state = Persistence.INVALID_KEY
            self._problem = _invalid_key_problem(value)
            return
        self._fernet = Fernet(base64.urlsafe_b64encode(raw))
        self._hash_key = hmac.new(raw, _HASH_KEY_INFO, hashlib.sha256).digest()
        self._state = Persistence.ENABLED

    # -- state ----------------------------------------------------------------

    @property
    def state(self) -> Persistence:
        return self._state

    @property
    def persists(self) -> bool:
        """True when imports are saved and revokes delete rows."""
        return self._checked and self._state is Persistence.ENABLED

    @property
    def loaded(self) -> int:
        """Saved keys loaded at startup."""
        return self._loaded

    @property
    def not_loaded(self) -> int:
        """Saved keys left in the database, unloaded, at startup."""
        return self._not_loaded

    @property
    def problem(self) -> str | None:
        """Why the key is invalid, or the database error (never the key)."""
        return self._problem

    def is_saved(self, key_id: str) -> bool:
        """True for a key loaded from, or saved to, the database this run."""
        with self._lock:
            return key_id in self._saved

    def memory_only_count(self, store: KeyStore) -> int:
        """Imported keys in *store* that are not saved (lost at a restart)."""
        return sum(
            1
            for key in store.list_keys()
            if key.get("source") == "import" and not self.is_saved(key["key_id"])
        )

    # -- startup ----------------------------------------------------------------

    def load_into(self, store: KeyStore) -> None:
        """Load the saved keys into *store* (once, at startup).

        Never raises for a database or decryption problem, and never
        updates or deletes a row: what cannot be loaded stays as it is.
        """
        self._checked = True
        if self._fernet is None:
            try:
                self._not_loaded = self._count()
            except sqlite3.Error as exc:
                self._not_loaded = 0
                logger.warning(
                    "Protocol decryption keys: could not count the saved keys (%s: %s)",
                    type(exc).__name__,
                    exc,
                )
            self._log_startup([])
            return
        try:
            rows = self._read_rows()
        except sqlite3.Error as exc:
            self._state = Persistence.ERROR
            self._problem = f"{type(exc).__name__}: {exc}"
            self._loaded = self._not_loaded = 0
            self._log_startup([])
            return
        unreadable: list[Any] = []
        for row in rows:
            try:
                key_id = self._load_row(store, tuple(row))
            except Exception as exc:  # one odd row never stops the startup
                logger.warning(
                    "Protocol decryption keys: a saved key could not be loaded (%s)",
                    type(exc).__name__,
                )
                key_id = None
            if key_id is None:
                unreadable.append(row[0])
            else:
                with self._lock:
                    self._saved.add(key_id)
                self._loaded += 1
        self._not_loaded = len(unreadable)
        if unreadable and not self._loaded:
            self._state = Persistence.WRONG_KEY
        self._log_startup(unreadable)

    def _count(self) -> int:
        return int(self._ctx.execute(_COUNT_SQL, (self._tenant_id,)).fetchone()[0])

    def _read_rows(self) -> list[Any]:
        return list(self._ctx.execute(_LOAD_SQL, (self._tenant_id,)).fetchall())

    def _load_row(self, store: KeyStore, row: tuple[Any, ...]) -> str | None:
        """Add one row's key to *store*; its id, or None if unreadable."""
        key_id, protocol, label, token, key_hash, algorithm, created_at = row
        if not (isinstance(key_id, str) and 0 < len(key_id) <= _MAX_ID_CHARS):
            return None
        if not all(isinstance(v, str) for v in (protocol, label, algorithm)):
            return None
        if isinstance(token, str):
            try:
                token = token.encode("ascii")
            except UnicodeEncodeError:
                return None
        if not isinstance(token, bytes) or not 0 < len(token) <= _MAX_TOKEN_BYTES:
            return None
        assert self._fernet is not None
        try:
            plaintext = self._fernet.decrypt(token)
        except InvalidToken:
            return None
        material = self._open_envelope(plaintext, key_id, protocol, algorithm)
        if material is None:
            return None
        try:
            if not isinstance(key_hash, str) or not hmac.compare_digest(
                self._fingerprint(material), key_hash
            ):
                return None
            store.add_key(
                protocol,
                algorithm,
                material,
                label,
                source="import",
                key_id=key_id,
                created_at=created_at if isinstance(created_at, str) else None,
            )
        except ValueError:
            return None
        finally:
            _zero(material)
        return key_id

    @staticmethod
    def _open_envelope(
        plaintext: bytes, key_id: str, protocol: str, algorithm: str
    ) -> bytearray | None:
        """The key bytes of a decrypted envelope bound to this row, or None."""
        try:
            envelope = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not isinstance(envelope, dict):
            return None
        version = envelope.get("format")
        if (
            type(version) is not int
            or version != _ENVELOPE_FORMAT
            or envelope.get("key_id") != key_id
            or envelope.get("protocol") != protocol
            or envelope.get("algorithm") != algorithm
            or not isinstance(envelope.get("material"), str)
        ):
            return None
        try:
            material = bytearray(base64.b64decode(envelope["material"], validate=True))
        except (binascii.Error, ValueError):
            return None
        if not 0 < len(material) <= _MAX_MATERIAL_BYTES:
            _zero(material)
            return None
        return material

    def _fingerprint(self, material: bytes | bytearray) -> str:
        assert self._hash_key is not None
        return (
            _HASH_PREFIX
            + hmac.new(self._hash_key, material, hashlib.sha256).hexdigest()
        )

    def _log_startup(self, unreadable: list[Any]) -> None:
        state, n = self._state, self._not_loaded
        if state is Persistence.ENABLED:
            logger.info(
                "Protocol decryption keys: loaded %d saved key(s) (%s)",
                self._loaded,
                KEYSTORE_KEY_ENV,
            )
            if unreadable:
                logger.warning(
                    "Protocol decryption keys: %d saved key(s) could not be read "
                    "(damaged, or saved with another %s) and were left in the "
                    "database, not loaded: %s",
                    n,
                    KEYSTORE_KEY_ENV,
                    ", ".join(_loggable_id(i) for i in unreadable[:_LOGGED_IDS]),
                )
        elif state is Persistence.DISABLED and not n:
            logger.info(
                "Protocol decryption keys are memory-only: %s is not set "
                "(imported keys are lost when the bridge restarts)",
                KEYSTORE_KEY_ENV,
            )
        elif state is Persistence.DISABLED:
            logger.warning(
                "%s is not set: %d saved protocol decryption key(s) were left in "
                "the database, not loaded; imported keys are memory-only",
                KEYSTORE_KEY_ENV,
                n,
            )
        elif state is Persistence.INVALID_KEY:
            logger.warning(
                "%s is not a valid key (%s): protocol decryption keys are "
                "memory-only; %d saved key(s) were left in the database, not loaded",
                KEYSTORE_KEY_ENV,
                self._problem,
                n,
            )
        elif state is Persistence.WRONG_KEY:
            logger.warning(
                "%s does not decrypt any of the %d saved protocol decryption "
                "key(s): they were left in the database, not loaded, and new "
                "imports are memory-only (was %s changed?)",
                KEYSTORE_KEY_ENV,
                n,
                KEYSTORE_KEY_ENV,
            )
        else:
            logger.error(
                "Saved protocol decryption keys could not be read (%s): none were "
                "loaded; new imports are memory-only until the bridge restarts",
                self._problem,
            )

    # -- import / revoke ----------------------------------------------------------

    def save(self, key: CryptoKey, created_by: str = "") -> bool:
        """Save an imported *key*.  False when keys are not saved here.

        Raises :class:`CryptoKeyStorageError` when the database refuses the
        write; nothing was saved then.
        """
        if not self.persists or key.source != "import":
            return False
        assert self._fernet is not None
        encoded = bytearray(base64.b64encode(key.key_material))
        try:
            envelope = json.dumps(
                {
                    "algorithm": key.algorithm,
                    "format": _ENVELOPE_FORMAT,
                    "key_id": key.key_id,
                    "material": encoded.decode("ascii"),
                    "protocol": key.protocol,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        finally:
            _zero(encoded)
        token = self._fernet.encrypt(envelope)
        fingerprint = self._fingerprint(key.key_material)
        try:
            with self._ctx.write_transaction() as conn:
                conn.execute(
                    _INSERT_SQL,
                    (
                        key.key_id,
                        key.protocol,
                        key.label,
                        token,
                        fingerprint,
                        key.algorithm,
                        (created_by or "")[:_MAX_CREATED_BY_CHARS],
                        self._tenant_id,
                        key.created_at,
                    ),
                )
        except sqlite3.Error as exc:
            raise CryptoKeyStorageError(
                f"could not save key {key.key_id}: {type(exc).__name__}: {exc}"
            ) from exc
        with self._lock:
            self._saved.add(key.key_id)
        return True

    def delete(self, key_id: str) -> bool:
        """Delete the saved row of *key_id*.  True if a row went.

        Raises :class:`CryptoKeyStorageError` when the database refuses the
        delete; the row is still there then.
        """
        try:
            with _secure_delete(self._ctx), self._ctx.write_transaction() as conn:
                removed = conn.execute(_DELETE_SQL, (key_id, self._tenant_id)).rowcount
        except sqlite3.Error as exc:
            raise CryptoKeyStorageError(
                f"could not delete key {key_id}: {type(exc).__name__}: {exc}"
            ) from exc
        with self._lock:
            self._saved.discard(key_id)
        if removed:
            _checkpoint_quietly(self._ctx)
        return removed > 0

    def unreadable_rows(self) -> list[Any]:
        """Ids of the saved rows this key cannot load (the rows load_into reads).

        Raises :class:`CryptoKeyStorageError` without a valid key, and
        ``sqlite3.Error`` when the table cannot be read.
        """
        if self._fernet is None:
            raise CryptoKeyStorageError(
                f"{KEYSTORE_KEY_ENV} is not set to a valid key: set it to the "
                "value new keys are to be saved with first"
            )
        scratch = KeyStore()
        unreadable: list[Any] = []
        for row in self._read_rows():
            row = tuple(row)
            try:
                readable = self._load_row(scratch, row) is not None
            except Exception:
                readable = False
            if not readable:
                unreadable.append(row[0])
        for key in scratch.list_keys():
            scratch.remove_key(key["key_id"])  # zeroes the material
        return unreadable

    # -- reporting --------------------------------------------------------------

    def _not_loaded_sentence(self) -> str:
        if not self._not_loaded:
            return ""
        return (
            f" {self._not_loaded} key(s) saved earlier were left in the database, "
            f"not loaded: set {KEYSTORE_KEY_ENV} to the value they were saved "
            "with and restart the bridge."
        )

    def _message(self) -> str:
        state, n = self._state, self._not_loaded
        if state is Persistence.ENABLED and not n:
            return (
                f"Imported keys are saved in the database, encrypted with "
                f"{KEYSTORE_KEY_ENV}, and are loaded again when the bridge "
                "restarts or is upgraded."
            )
        if state is Persistence.ENABLED:
            return (
                f"Imported keys are saved encrypted with {KEYSTORE_KEY_ENV}. "
                f"{n} saved key(s) could not be read (damaged, or saved with "
                f"another {KEYSTORE_KEY_ENV}) and were left in the database, "
                "not loaded."
            )
        if state is Persistence.DISABLED:
            return (
                "Imported keys are kept in memory only and are lost when the "
                f"bridge restarts: {KEYSTORE_KEY_ENV} is not set ({_DOCS})."
                + self._not_loaded_sentence()
            )
        if state is Persistence.INVALID_KEY:
            return (
                f"Imported keys are kept in memory only: {KEYSTORE_KEY_ENV} is "
                f"not a valid key ({self._problem})." + self._not_loaded_sentence()
            )
        if state is Persistence.WRONG_KEY:
            return (
                f"{n} saved key(s) could not be read with this "
                f"{KEYSTORE_KEY_ENV} (was it changed?). They were left in the "
                "database, not loaded, and new imports are kept in memory only "
                f"until the {KEYSTORE_KEY_ENV} they were saved with is restored "
                "and the bridge restarted."
            )
        return (
            f"Saved keys could not be read from the database ({self._problem}). "
            "New imports are kept in memory only until the bridge restarts."
        )

    def _reuse_warning(self) -> str:
        if self.reused_secret is None:
            return ""
        return (
            f"{KEYSTORE_KEY_ENV} has the same value as {self.reused_secret}, "
            "which the gateway also holds, so the gateway could decrypt the "
            "saved keys. Generate a separate value for new installs; on this "
            "one, keys already saved need the current value to load (see "
            'INSTALL.md, "Protocol decryption keys").'
        )

    def status(self, store: KeyStore) -> dict[str, Any]:
        """The body of ``GET /api/crypto/status``."""
        reuse = self._reuse_warning()
        return {
            "persistence": self._state.value,
            "loaded": self._loaded,
            "not_loaded": self._not_loaded,
            "memory_only": self.memory_only_count(store),
            "message": self._message() + (" " + reuse if reuse else ""),
        }

    def health_warnings(self, store: KeyStore) -> list[str]:
        """``/api/health`` warnings: only when something is at risk."""
        reuse = self._reuse_warning()
        warnings = self._persistence_warnings(store)
        if reuse:
            warnings.append("Protocol decryption keys: " + reuse)
        return warnings

    def _persistence_warnings(self, store: KeyStore) -> list[str]:
        state, n = self._state, self._not_loaded
        if state is Persistence.DISABLED:
            m = self.memory_only_count(store)
            if m:
                return [
                    f"Protocol decryption keys: {m} imported key(s) are kept in "
                    "memory only and will be lost when the bridge restarts, "
                    f"because {KEYSTORE_KEY_ENV} is not set. Set it ({_DOCS}), "
                    "restart the bridge and import them again."
                    + self._not_loaded_sentence()
                ]
            if not n:
                return []
        elif state is Persistence.ENABLED and not n:
            return []
        return ["Protocol decryption keys: " + self._message()]


def disabled_status(store: KeyStore) -> dict[str, Any]:
    """``GET /api/crypto/status`` for an app without a vault (memory-only)."""
    imports = sum(1 for key in store.list_keys() if key.get("source") == "import")
    return {
        "persistence": Persistence.DISABLED.value,
        "loaded": 0,
        "not_loaded": 0,
        "memory_only": imports,
        "message": (
            "Imported keys are kept in memory only and are lost when the "
            f"bridge restarts: {KEYSTORE_KEY_ENV} is not set ({_DOCS})."
        ),
    }


def _reused_secret(value: str | None, environ: Mapping[str, str]) -> str | None:
    """The gateway secret (env name) that *value* repeats, or None."""
    value = (value or "").strip()
    raw = _decode_fernet_key(value) if value else None
    if raw is None:
        return None
    for name in _GATEWAY_SECRETS_ENV:
        other = (environ.get(name) or "").strip()
        if other and (other == value or _decode_fernet_key(other) == raw):
            return name
    return None


@contextlib.contextmanager
def _secure_delete(ctx: Any) -> Iterator[None]:
    """``PRAGMA secure_delete = ON`` on this thread's connection, for a block.

    The connection is shared by every write on the thread, so the setting
    it had is put back afterwards (zeroing freed pages costs I/O on the
    large cleanup deletes).  Set outside the transaction.
    """
    conn = ctx.get_conn() if hasattr(ctx, "get_conn") else None
    previous = None
    if conn is not None:
        try:
            previous = conn.execute("PRAGMA secure_delete").fetchone()[0]
            conn.execute("PRAGMA secure_delete = ON")
        except sqlite3.Error:
            previous = None
    try:
        yield
    finally:
        if conn is not None and previous is not None:
            with contextlib.suppress(sqlite3.Error):
                conn.execute(f"PRAGMA secure_delete = {int(previous)}")


def _checkpoint_quietly(ctx: Any) -> None:
    """Move the zeroed page into the database file now (best effort).

    PASSIVE: it never waits for readers or holds up writers (the scheduled
    TRUNCATE checkpoint, under the write lock, does the rest later).
    """
    try:
        ctx.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchall()
    except sqlite3.Error as exc:
        logger.debug("WAL checkpoint after a key revoke skipped: %s", exc)


def init_crypto_keys(
    ctx: SharedContext, environ: Mapping[str, str] = os.environ
) -> tuple[KeyStore, CryptoKeyVault]:
    """Built-in defaults first, then the saved keys (owner decision 1)."""
    store = KeyStore()
    store.load_builtin_defaults()
    vault = CryptoKeyVault(ctx, environ.get(KEYSTORE_KEY_ENV))
    vault.reused_secret = _reused_secret(environ.get(KEYSTORE_KEY_ENV), environ)
    if vault.reused_secret is not None:
        logger.warning("Protocol decryption keys: %s", vault._reuse_warning())
    vault.load_into(store)
    return store, vault


# -- forget-unreadable (an explicit operator action) ---------------------------


def forget_unreadable(
    ctx: Any, keystore_key: str | None, *, delete: bool
) -> tuple[int, int]:
    """Count, or with *delete* remove, the rows *keystore_key* cannot read.

    For a ``BRIDGE_KEYSTORE_KEY`` that is lost for good: the bridge never
    deletes those rows by itself, and while they are the only rows it
    saves no import (``WRONG_KEY``).  Returns (unreadable, readable).
    """
    vault = CryptoKeyVault(ctx, keystore_key)
    unreadable = vault.unreadable_rows()
    total = vault._count()
    if delete:
        for key_id in unreadable:
            vault.delete(key_id)
    return len(unreadable), total - len(unreadable)


def _main(argv: Sequence[str] | None = None) -> int:
    from sigrift.bridge.restore_marker import (
        find_restore_marker,
        restore_incomplete_message,
    )
    from sigrift.bridge.storage.base import _DEFAULT_DB_PATH, SharedContext

    parser = argparse.ArgumentParser(
        prog="python3 -m sigrift.bridge.storage.crypto_keys",
        description=(
            "Saved protocol decryption keys. forget-unreadable deletes the "
            f"saved keys the current {KEYSTORE_KEY_ENV} cannot read (lost "
            "for good: they cannot be recovered); without --yes it only "
            "counts them. Restart the bridge afterwards."
        ),
    )
    parser.add_argument("command", choices=["forget-unreadable"])
    parser.add_argument("--yes", action="store_true", help="delete them")
    parser.add_argument(
        "--db", type=Path, default=_DEFAULT_DB_PATH, help="default: %(default)s"
    )
    args = parser.parse_args(argv)
    marker = find_restore_marker(args.db.parent)
    if marker is not None:
        print(restore_incomplete_message(marker), file=sys.stderr)
        return 1
    if not args.db.is_file():
        print(f"error: no database at {args.db}", file=sys.stderr)
        return 1
    ctx = SharedContext(args.db)
    try:
        unreadable, readable = forget_unreadable(
            ctx, os.environ.get(KEYSTORE_KEY_ENV), delete=args.yes
        )
    except (CryptoKeyStorageError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        ctx.close()
    if not unreadable:
        print(f"Nothing to do: {readable} saved key(s), all readable.")
    elif args.yes:
        print(
            f"Deleted {unreadable} saved key(s) that {KEYSTORE_KEY_ENV} cannot "
            f"read; {readable} readable key(s) kept. Restart the bridge, then "
            "import the deleted keys again."
        )
    else:
        print(
            f"{unreadable} saved key(s) cannot be read with this "
            f"{KEYSTORE_KEY_ENV} ({readable} can). Run again with --yes to "
            "delete them (they cannot be recovered)."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
