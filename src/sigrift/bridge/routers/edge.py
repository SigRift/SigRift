"""Public endpoints that support edge-agent onboarding.

Serves `/api/edge/install.sh` — the unauthenticated host-install script
piped into `sudo bash` on the scanning host. The script requires a
NODE-role API key at runtime, so merely fetching it grants nothing.

The served script names the release the bridge runs (its
`SERVER_RELEASE="..."` line, filled in from `release_info.release_tag()`),
so the edge checks out that tag; a development or `main-<sha>` build fills
in "" and the script installs `main`. Only a `vX.Y.Z[-rcN]` tag is ever
filled in, so nothing else can reach the shell.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import PlainTextResponse

from sigrift.bridge.release_info import release_tag

router = APIRouter()

_INSTALL_SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "edge-install.sh"
)
#: The line of edge-install.sh that names the server's release.
_RELEASE_LINE = 'SERVER_RELEASE="__SIGRIFT_SERVER_RELEASE__"'


@router.get(
    "/install.sh",
    response_class=PlainTextResponse,
    # Plain-text with a sh-ish content-type so `curl | bash` treats it
    # as text without a charset guess.
    responses={200: {"content": {"text/x-shellscript": {}}}},
)
async def get_install_script() -> PlainTextResponse:
    """Return the host-install script as plain text.

    Unauthenticated by design — the script is harmless on its own (no
    embedded secrets) and requires the operator to supply a NODE API
    key at invocation time. Keeping it unauthenticated means the
    `curl | bash` one-liner shown in the dashboard works without the
    dashboard's own cookie.
    """
    try:
        content = _INSTALL_SCRIPT_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        # Shouldn't happen in a packaged install; surface loudly if it
        # does so we don't hand a caller an empty script.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="edge-install.sh missing from the bridge container",
        )
    if content.count(_RELEASE_LINE) != 1:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="edge-install.sh has no release line to fill in",
        )
    content = content.replace(_RELEASE_LINE, f'SERVER_RELEASE="{release_tag() or ""}"')
    return PlainTextResponse(
        content,
        media_type="text/x-shellscript",
        headers={"Cache-Control": "no-cache"},
    )
