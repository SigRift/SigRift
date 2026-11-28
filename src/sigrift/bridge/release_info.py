"""The release this bridge image was built for (``SIGRIFT_RELEASE``).

The images bake it in as a build arg and environment variable:
``.github/workflows/release.yml`` passes the release tag (``v0.2.0``,
``v0.2.0-rc2``), ``build-and-push.yml`` ``main-<sha12>``, and any other
build (``docker compose build``, a source checkout) reports ``dev``.
``/api/version`` and ``/api/health`` report it next to ``server_version``,
which stays the API's own version (4.0.0; clients may depend on it), and
``GET /api/edge/install.sh`` fills the release tag into the edge
installer, which then checks out that tag.

Only values of those two shapes are reported; anything else set in the
environment is reported as ``dev`` (and logged once at startup), so the
value is safe to put into a served shell script.
"""

from __future__ import annotations

import logging
import os
import re

from sigrift.bridge import __version__

RELEASE_ENV = "SIGRIFT_RELEASE"
DEV_RELEASE = "dev"
_MAX_RELEASE_CHARS = 40
#: The tags release.yml's resolve-version job accepts (without ^ and $).
_RELEASE_TAG_RE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?")
#: build-and-push.yml's ``:main-<sha12>`` image tag.
_MAIN_BUILD_RE = re.compile(r"main-[0-9a-f]{12}")


def _configured() -> str:
    return os.environ.get(RELEASE_ENV, "").strip()


def _accepted(value: str) -> bool:
    return len(value) <= _MAX_RELEASE_CHARS and bool(
        _RELEASE_TAG_RE.fullmatch(value) or _MAIN_BUILD_RE.fullmatch(value)
    )


def current_release() -> str:
    """The release tag, ``main-<sha12>``, or ``dev``."""
    value = _configured()
    return value if _accepted(value) else DEV_RELEASE


def release_tag() -> str | None:
    """The release tag (``vX.Y.Z`` or ``vX.Y.Z-rcN``), or None."""
    value = current_release()
    return value if _RELEASE_TAG_RE.fullmatch(value) else None


def log_release(logger: logging.Logger) -> None:
    """Log the release at startup (and a rejected ``SIGRIFT_RELEASE``)."""
    value = _configured()
    # "dev" is the Dockerfile's default (a source build), not a rejected value.
    if value and value != DEV_RELEASE and not _accepted(value):
        logger.warning(
            "%s=%r is not a release tag or a main build: reporting release %r",
            RELEASE_ENV,
            value[:64],
            DEV_RELEASE,
        )
    logger.info(
        "SigRift release %s (server_version %s)", current_release(), __version__
    )
