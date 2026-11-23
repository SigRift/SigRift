"""Security audit tests -- static analysis and runtime checks."""

from __future__ import annotations

import ast
import glob
import re
from pathlib import Path

import httpx
import pytest

from sigrift.lib.shiny.dependencies import RateLimiter
from sigrift.lib.shiny.state import AppState

_SHINY_ROOT = str(Path(__file__).resolve().parent.parent)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# AST-based static scans
# ---------------------------------------------------------------------------


def _iter_source_files():
    """Yield all .py files in sigrift/lib/shiny/ excluding tests/."""
    for py_file in glob.glob(f"{_SHINY_ROOT}/**/*.py", recursive=True):
        if "/tests/" in py_file:
            continue
        yield py_file


def test_no_bare_excepts() -> None:
    """AST scan: no bare `except:` in any shiny/ module."""
    for py_file in _iter_source_files():
        source = Path(py_file).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                assert False, f"Bare except in {py_file}:{node.lineno}"


def test_no_eval_exec() -> None:
    """No eval(), exec(), or pickle.loads() calls in source."""
    dangerous = {"eval", "exec"}
    for py_file in _iter_source_files():
        source = Path(py_file).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = None
                if isinstance(func, ast.Name):
                    name = func.id
                elif isinstance(func, ast.Attribute):
                    # Check for pickle.loads
                    if (
                        func.attr == "loads"
                        and isinstance(func.value, ast.Name)
                        and func.value.id == "pickle"
                    ):
                        assert False, f"pickle.loads() in {py_file}:{node.lineno}"
                    name = func.attr
                if name in dangerous:
                    assert False, f"{name}() in {py_file}:{node.lineno}"


def test_no_naive_datetime() -> None:
    """No datetime.now() without timezone argument."""
    for py_file in _iter_source_files():
        source = Path(py_file).read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "now":
                # datetime.now() must have a tz= or positional arg
                if not node.args and not node.keywords:
                    assert False, (
                        f"datetime.now() without tz in {py_file}:{node.lineno}"
                    )


def test_no_hardcoded_credentials() -> None:
    """No hardcoded passwords/secrets in source code."""
    patterns = [
        re.compile(r'password\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'secret\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
        re.compile(r'api_key\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']'),
    ]
    for py_file in _iter_source_files():
        source = Path(py_file).read_text()
        for lineno, line in enumerate(source.splitlines(), 1):
            # Skip comments and docstrings
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat in patterns:
                match = pat.search(line)
                if match:
                    # Exclude test fixtures and parameter names
                    if "default" in line.lower() or "label" in line.lower():
                        continue
                    assert False, (
                        f"Possible hardcoded credential in "
                        f"{py_file}:{lineno}: {match.group()}"
                    )


# ---------------------------------------------------------------------------
# Runtime security checks
# ---------------------------------------------------------------------------


async def test_csp_header_present(
    test_client: httpx.AsyncClient,
    api_key_header: dict[str, str],
) -> None:
    """Verify Content-Security-Policy header on responses."""
    # The test app does not include the CSP middleware by default.
    # We test the production app's middleware class directly.
    from fastapi import FastAPI
    from sigrift.lib.shiny.app import CSPMiddleware

    app = FastAPI()
    app.add_middleware(CSPMiddleware)

    @app.get("/test")
    async def _test_endpoint() -> dict:
        return {"ok": True}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/test")
        assert resp.status_code == 200
        assert "Content-Security-Policy" in resp.headers
        csp = resp.headers["Content-Security-Policy"]
        assert "default-src 'self'" in csp
        assert "script-src 'self'" in csp


async def test_rate_limiter_enforcement() -> None:
    """Rate limiter rejects after threshold is reached."""
    limiter = RateLimiter(max_requests=5, window_seconds=60.0)
    for _ in range(5):
        allowed, _ = limiter.is_allowed("client-1")
        assert allowed

    allowed, retry_after = limiter.is_allowed("client-1")
    assert not allowed
    assert retry_after >= 1


def test_html_escape_in_activity() -> None:
    """Activity log escapes HTML in user-supplied strings."""
    state = AppState()
    event = state.log_activity(
        event_type="test",
        node_id="<script>alert(1)</script>",
        message="<img src=x onerror=alert(1)>",
    )
    assert "<script>" not in event["node_id"]
    assert "&lt;script&gt;" in event["node_id"]
    assert "<img" not in event["message"]
    assert "&lt;img" in event["message"]


def test_id_pattern_validation() -> None:
    """Node/key IDs reject injection characters."""
    from sigrift.lib.shiny.models import NodeRegistration

    with pytest.raises(Exception):
        NodeRegistration(node_id="'; DROP TABLE nodes;--")

    with pytest.raises(Exception):
        NodeRegistration(node_id="a" * 65)  # Too long

    # Valid IDs pass
    node = NodeRegistration(node_id="edge-01_v2")
    assert node.node_id == "edge-01_v2"
