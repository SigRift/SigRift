"""Session token parity: the bridge and the gateway read a request's session alike.

Both services take a session token from ``Authorization: Bearer <token>``,
``X-Session-Token`` or the ``session_token`` cookie, in that order: the
bridge in ``dependencies._extract_session_token``, the gateway in
``middleware/auth.rs`` (``session_token_from_headers``, through
``bearer_credential`` and ``cookie_pair``), which the proxy, logout,
API-key and WebSocket paths share.  When the two disagree, a token one of
them ignores is authenticated by the other.  The gateway read only
``Bearer`` while the bridge matched the scheme case-insensitively (RFC 9110
section 11.1), and it read the cookie as ``session_token=`` exactly while
the bridge (Starlette's ``cookie_parser``) trims a cookie's name.  So
``bearer <token>`` and ``Cookie: session_token =<token>`` reached the
bridge as anonymous requests, and the bridge authenticated them without
the gateway's checks.

The table both sides are pinned to lives in the gateway crate
(``testdata/session_token_parity.json``); the gateway's
``session_tokens_are_read_as_on_the_bridge`` test reads the same file.  CI
runs this file also for a PR that touches only that table (the ``python``
paths filter in ``.github/workflows/ci.yml`` covers the gateway's
``testdata``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request

from sigrift.bridge.dependencies import _extract_session_token

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE_PATH = (
    _REPO_ROOT
    / "src"
    / "gateway"
    / "crates"
    / "sigrift-gateway-core"
    / "testdata"
    / "session_token_parity.json"
)
#: The table's size when last extended; the gateway's test
#: (``SESSION_PARITY_CASES``) has the same floor.
_MIN_CASES = 59

_CASES: list[dict[str, Any]] = json.loads(_TABLE_PATH.read_text(encoding="utf-8"))[
    "cases"
]


def _request(headers: list[list[str]]) -> Request:
    """A request carrying these header fields, in order (as Starlette
    decodes header bytes: latin-1)."""
    return Request(
        {
            "type": "http",
            "headers": [
                (name.encode("latin-1"), value.encode("latin-1"))
                for name, value in headers
            ],
        }
    )


def _case_id(case: dict[str, Any]) -> str:
    return "; ".join(f"{name}: {value!r}" for name, value in case["headers"])


def test_the_table_is_the_one_the_gateway_reads() -> None:
    assert len(_CASES) >= _MIN_CASES, "the shared table lost cases"
    tokens = {case["token"] for case in _CASES}
    assert None in tokens and len(tokens) > 1
    sources = {name for case in _CASES for name, _ in case["headers"]}
    assert sources == {"authorization", "x-session-token", "cookie"}
    schemes = {
        value[:6]
        for case in _CASES
        if case["token"]
        for name, value in case["headers"]
        if name == "authorization"
    }
    assert {"Bearer", "bearer", "BEARER"} <= schemes
    # The cookie whose name only the bridge used to trim.
    assert any(
        name == "cookie" and "session_token =" in value
        for case in _CASES
        if case["token"]
        for name, value in case["headers"]
    )


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_session_tokens_read_as_on_the_gateway(case: dict[str, Any]) -> None:
    assert _extract_session_token(_request(case["headers"])) == case["token"]
