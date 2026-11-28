"""Refuse to start on a volume whose restore did not finish.

While ``install-release.sh`` or ``scripts/quickstart.sh`` restores a
restore point into the bridge's volumes it puts a marker,
``.sigrift-restore-incomplete``, at the root of each volume it restores
(``bridge_data`` and ``bridge_secrets``) and removes it once the restore is
complete.  A marker that is still there means the restore stopped part way
(killed, power loss, full disk): the volume's files may be half replaced.
Starting the bridge on it would run migrations, rewrite ``keys.json`` and
move the CA key between half-restored volumes, so the bridge, and the
``ca migrate-key`` step before it, refuse instead, with one log line that
names the file and the next step.

The bridge never reads, creates or removes the marker.  Any directory
entry of that name counts: a file, a directory, a dangling symlink, an
unreadable file.  Standard library only: the image CMD runs this through
``python3 -m sigrift.bridge.ca`` before the app is imported.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

#: The marker's file name, at the root of bridge_data and bridge_secrets.
RESTORE_MARKER_NAME = ".sigrift-restore-incomplete"

#: The bridge data directory, where Compose mounts ``bridge_data``.  The
#: same directory as ``persistence._DEFAULT_DATA_DIR``,
#: ``base._DEFAULT_DB_PATH.parent`` and ``ca._DEFAULT_DATA_DIR``.
DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"


class RestoreIncompleteError(RuntimeError):
    """A restore marker exists: the bridge refuses to start."""


def find_restore_marker(
    data_dir: Path | None = None, secrets_dir: Path | None = None
) -> Path | None:
    """The first of ``<data_dir>/<name>`` and ``<secrets_dir>/<name>`` that exists.

    *data_dir* defaults to :data:`DEFAULT_DATA_DIR` (read at call time, so
    tests can move it); *secrets_dir* to ``ca.secrets_dir(data_dir)``
    (``BRIDGE_SECRETS_DIR``, else ``<data_dir>/../secrets``).  Uses
    ``os.path.lexists``: a dangling symlink counts.  Never reads, creates
    or removes the marker.
    """
    if data_dir is None:
        data_dir = DEFAULT_DATA_DIR
    if secrets_dir is None:
        from sigrift.bridge.ca import secrets_dir as _secrets_dir

        secrets_dir = _secrets_dir(data_dir)
    for directory in (Path(data_dir), Path(secrets_dir)):
        candidate = directory / RESTORE_MARKER_NAME
        if os.path.lexists(candidate):
            return candidate
    return None


def restore_incomplete_message(path: Path) -> str:
    """The one-line refusal naming *path* and the next step."""
    return (
        f"FATAL: restore incomplete — refusing to start: {path} exists, so a "
        "restore of this volume by install-release.sh or quickstart.sh did not "
        "finish and its files may be half replaced. Next step: in the install "
        "folder run 'bash install-release.sh --status' (source checkout: "
        "'scripts/quickstart.sh --status') and follow it (--resume or --abort). "
        f"Remove {path} by hand only if you restored the volume yourself and "
        "know it is complete."
    )


def check_restore_markers(
    data_dir: Path | None = None, secrets_dir: Path | None = None
) -> None:
    """Raise :class:`RestoreIncompleteError` (after one CRITICAL line) on a marker."""
    path = find_restore_marker(data_dir, secrets_dir)
    if path is not None:
        message = restore_incomplete_message(path)
        logger.critical(message)
        raise RestoreIncompleteError(message)
