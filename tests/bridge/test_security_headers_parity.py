"""The bridge sends the gateway's reviewed Content-Security-Policy.

Behind the gateway, the bridge's security headers never reach a browser:
the gateway replaces them with its own (``middleware/security.rs``). A
bridge run without a gateway sends its own, so the two policies must be the
same, or the standalone dashboard runs under a different policy than the
one the gateway was reviewed with. They had drifted: the bridge lacked
``base-uri`` and ``form-action`` (which do not fall back to
``default-src``, so the standalone bridge restricted neither), and its
``Permissions-Policy`` lacked ``payment=()``.

The reviewed values live in one table in the gateway crate
(``testdata/security_headers_parity.json``); the gateway's
``headers_match_the_shared_table`` test reads the same file. CI runs this
file also for a PR that touches only that table (the ``python`` paths
filter in ``.github/workflows/ci.yml`` covers the gateway's ``testdata``).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import app as bridge_app_module

_REPO_ROOT = Path(__file__).resolve().parents[2]
_TABLE_PATH = (
    _REPO_ROOT
    / "src"
    / "gateway"
    / "crates"
    / "sigrift-gateway-core"
    / "testdata"
    / "security_headers_parity.json"
)
_TABLE = json.loads(_TABLE_PATH.read_text(encoding="utf-8"))
_CSP = _TABLE["content-security-policy"]
_PERMISSIONS = _TABLE["permissions-policy"]


def _directives(policy: str) -> dict[str, list[str]]:
    """*policy* as {directive: sources}; a repeated directive fails."""
    parsed: dict[str, list[str]] = {}
    for directive in policy.split(";"):
        tokens = directive.split()
        if not tokens:
            continue
        name, *sources = tokens
        assert name not in parsed, f"{name} is repeated"
        parsed[name] = sources
    return parsed


def test_the_table_is_the_reviewed_policy() -> None:
    """Scripts only from the origin, no plugins: the policy the table pins."""
    directives = _directives(_CSP)
    # Exactly these directives: one added to the table and both services
    # alike fails here. script-src-elem and script-src-attr would take
    # precedence over script-src for <script> elements and handler
    # attributes, and could re-allow inline script.
    assert list(directives) == [
        "default-src",
        "script-src",
        "object-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "frame-ancestors",
        "base-uri",
        "form-action",
    ]
    assert directives["script-src"] == ["'self'"]
    assert directives["object-src"] == ["'none'"]
    assert directives["default-src"] == ["'self'"]
    assert directives["frame-ancestors"] == ["'none'"]
    # Neither falls back to default-src, so each must be named.
    assert directives["base-uri"] == ["'self'"]
    assert directives["form-action"] == ["'self'"]
    for name, sources in directives.items():
        for forbidden in (
            "*",
            "'unsafe-eval'",
            "'wasm-unsafe-eval'",
            "'unsafe-hashes'",
            "'strict-dynamic'",
        ):
            assert forbidden not in sources, f"{name} allows {forbidden}"
        for source in sources:
            assert not source.startswith(("'nonce-", "'sha")), f"{name}: {source}"
        if name != "style-src":
            # Inline styles only, until the template style attributes move.
            assert "'unsafe-inline'" not in sources, f"{name} allows inline"


@pytest.mark.parametrize("doc", ["SECURITY.md", "src/gateway/README.md"])
def test_the_operator_docs_state_the_shared_policy(doc: str) -> None:
    """Both documents print the whole policy: it must be the table's."""
    text = (_REPO_ROOT / doc).read_text(encoding="utf-8")
    printed = [
        policy
        for policy in re.findall(r"default-src 'self';[^`\n]*", text)
        if "script-src" in policy
    ]
    assert printed == [_CSP], doc


def test_bridge_policy_is_the_gateway_policy() -> None:
    assert bridge_app_module._CSP_VALUE == _CSP


def test_bridge_headers_are_the_shared_values() -> None:
    headers = dict(bridge_app_module._SECURITY_HEADERS)
    assert headers[b"content-security-policy"] == _CSP.encode()
    assert headers[b"permissions-policy"] == _PERMISSIONS.encode()


@pytest.fixture(scope="module")
def page_client() -> TestClient:
    """The real app, with its templates and static files (no lifespan)."""
    return TestClient(bridge_app_module.app)


@pytest.mark.parametrize(
    "path",
    [
        "/login",
        "/dashboard",
        "/admin",
        "/documentation/",
        "/static/docs_dropdown.js",
        "/api/healthz",
        "/no-such-page",
    ],
)
def test_served_pages_assets_and_errors_carry_the_shared_values(
    page_client: TestClient, path: str
) -> None:
    response = page_client.get(path, follow_redirects=False)
    assert response.headers.get_list("content-security-policy") == [_CSP], path
    assert response.headers.get_list("permissions-policy") == [_PERMISSIONS], path
