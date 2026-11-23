"""The gateway retires a pooled bridge connection before the bridge closes it.

uvicorn closes a keep-alive connection that has been idle for
``--timeout-keep-alive`` seconds (``src/sigrift/bridge/Dockerfile``). The
gateway's proxy keeps idle bridge connections for reuse; one it sends a
request on just as the bridge closes it fails, and the browser gets 502
"Proxy error" for that asset or call (the candidate gate's browser suite
lost a dashboard script that way). The gateway therefore drops a pooled
connection after ``BACKEND_POOL_IDLE_TIMEOUT`` (``proxy/handler.rs``),
well under the bridge's timeout; the gateway's own
``idle_backend_connections_are_retired_before_keep_alive_closes_them``
test checks the pool honours it. No Rust toolchain is needed here.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_DOCKERFILE = _PROJECT_ROOT / "src" / "sigrift" / "bridge" / "Dockerfile"
_HANDLER_RS = (
    _PROJECT_ROOT
    / "src"
    / "gateway"
    / "crates"
    / "sigrift-gateway-core"
    / "src"
    / "proxy"
    / "handler.rs"
)
_IDLE_CONSTANT = re.compile(
    r"^pub const BACKEND_POOL_IDLE_TIMEOUT: std::time::Duration =\s*"
    r"std::time::Duration::from_secs\((\d+)\);$",
    re.MULTILINE,
)
#: A request is sent some milliseconds after the gateway checks the idle
#: time, and the bridge's clock starts before the gateway's (when it has
#: sent the response, not when the gateway has read it). Seconds of margin
#: cover both on a loaded Raspberry Pi.
_MARGIN_SECONDS = 2


def _gateway_pool_idle_seconds() -> int:
    found = _IDLE_CONSTANT.findall(_HANDLER_RS.read_text(encoding="utf-8"))
    assert len(found) == 1, (
        "expected one `pub const BACKEND_POOL_IDLE_TIMEOUT: std::time::Duration"
        f" = std::time::Duration::from_secs(N);` in {_HANDLER_RS}, found {len(found)}"
    )
    return int(found[0])


def _bridge_uvicorn_command() -> list[str]:
    """The arguments of the uvicorn command the bridge image starts."""
    commands = [
        json.loads(line[len("CMD ") :])
        for line in _DOCKERFILE.read_text(encoding="utf-8").splitlines()
        if line.startswith("CMD ")
    ]
    assert len(commands) == 1, f"expected one CMD in {_DOCKERFILE}"
    assert commands[0][:2] == ["sh", "-c"], commands[0]
    # The last command of the script: `exec python3 -m uvicorn ...`.
    uvicorn = shlex.split(commands[0][2].rsplit(";", 1)[1])
    assert uvicorn[:4] == ["exec", "python3", "-m", "uvicorn"], uvicorn
    return uvicorn


def _bridge_keep_alive_seconds() -> int:
    args = _bridge_uvicorn_command()
    values = [
        args[i + 1] for i, arg in enumerate(args[:-1]) if arg == "--timeout-keep-alive"
    ]
    assert len(values) == 1, (
        f"the bridge's uvicorn command ({_DOCKERFILE}) must state its "
        "--timeout-keep-alive once, so the gateway's pool timeout can be "
        f"checked against it: {args}"
    )
    return int(values[0])


def test_the_bridge_states_its_keep_alive_timeout():
    assert "sigrift.bridge.app:app" in _bridge_uvicorn_command()
    assert _bridge_keep_alive_seconds() > 0


def test_gateway_retires_idle_connections_well_before_the_bridge_closes_them():
    idle = _gateway_pool_idle_seconds()
    keep_alive = _bridge_keep_alive_seconds()
    assert 0 < idle and idle + _MARGIN_SECONDS <= keep_alive, (
        f"The gateway may reuse a bridge connection idle for up to {idle} s "
        f"(BACKEND_POOL_IDLE_TIMEOUT, {_HANDLER_RS.relative_to(_PROJECT_ROOT)}), "
        f"but the bridge closes one idle for {keep_alive} s "
        f"(--timeout-keep-alive, {_DOCKERFILE.relative_to(_PROJECT_ROOT)}). "
        f"Keep at least {_MARGIN_SECONDS} s between them, or requests race "
        "the close and fail with 502."
    )
