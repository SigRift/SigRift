"""Runtime scanner config reloaded from a JSON file.

The bridge's admin panel sends ``update_config`` commands via the
heartbeat-command channel. ``node_agent`` persists the payload to a JSON
file on disk; each scanner polls the file on its flush cadence and
mutates its in-memory ``summarize`` flag without restarting.

The default path lives under ``/var/lib/sigrift-edge`` rather than ``/tmp``:
the agent that writes the file and the scanners that read it run as
separate systemd units, and ``PrivateTmp=yes`` gives each unit its own
``/tmp`` namespace, so a file written under ``/tmp`` by the agent is
invisible to a scanner.  ``/var/lib/sigrift-edge`` is a shared, persistent
state directory (``StateDirectory=sigrift-edge`` in the units) that every
edge user shares.  Override with ``MLRF_SCANNER_CONFIG_PATH`` (the agent and
every scanner must agree on the value; it is also how the tests redirect
the file to a temp dir).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

#: Shared default: writable by the edge units (StateDirectory=sigrift-edge)
#: and outside any unit's private ``/tmp``.  Overridable per deployment.
DEFAULT_SCANNER_CONFIG_PATH = "/var/lib/sigrift-edge/scanner-config.json"


def _default_path() -> Path:
    return Path(os.environ.get("MLRF_SCANNER_CONFIG_PATH", DEFAULT_SCANNER_CONFIG_PATH))


def reload_summarize(current: bool) -> bool:
    """Return the desired ``summarize`` flag from the on-disk config.

    Returns ``current`` unchanged when the file is missing or unreadable
    so the scanner keeps doing whatever it was doing. Logs only when the
    flag actually transitions, to keep idle ticks quiet.
    """
    path = _default_path()
    try:
        with path.open() as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        return current
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not read scanner config %s: %s", path, e)
        return current

    raw = cfg.get("summarize")
    if raw is None:
        return current
    if isinstance(raw, str):
        new = raw.lower() in ("1", "true", "yes", "on")
    else:
        new = bool(raw)
    if new != current:
        logger.info("Scanner summarize toggled %s -> %s via %s", current, new, path)
    return new


def write_config(params: dict) -> Path:
    """Atomically persist a config update to the scanner config file.

    Writes a new temporary file next to it (``mkstemp``: a random name,
    created with ``O_EXCL``, so a name planted in the directory -- a
    symlink, say, by another user the directory belongs to -- is never
    followed), makes it world-readable for the scanner units, then
    ``os.replace``s it, so a half-written file is never visible to a
    concurrent poll. Returns the final path.

    Raises
    ------
    OSError
        When the file cannot be written.  The message names the directory
        and how to provide it: the default ``/var/lib/sigrift-edge`` exists
        only once a unit with ``StateDirectory=sigrift-edge`` has started, and
        the agent (a non-root user) cannot create it under ``/var/lib``.
    """
    path = _default_path()
    tmp: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=path.parent
        )
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(params))
        # mkstemp makes it 0600; the scanners run as another user.
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
        tmp = None
    except OSError as exc:
        raise OSError(
            exc.errno,
            f"cannot write scanner config {path} ({exc.strerror or exc}): "
            f"{path.parent} must exist and be writable by this user. Add "
            "StateDirectory=sigrift-edge to this unit (it must run as User=pi, "
            "like the scanners), or create it once with "
            f"'sudo install -d -o pi -g pi -m 0755 {path.parent}', or point "
            "MLRF_SCANNER_CONFIG_PATH at a directory the agent and every "
            "scanner can reach (see the edge README)",
        ) from exc
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return path
