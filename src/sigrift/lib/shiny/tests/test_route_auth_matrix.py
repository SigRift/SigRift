"""Authentication and role enforcement on every route of the production app.

These tests drive ``sigrift.lib.shiny.app.app`` itself -- the object uvicorn
serves, with its CSP middleware, validation handler, static mount and index
page -- rather than a test app that re-mounts the routers, so a router that
is mounted without its guard, or a middleware that is dropped, shows up here.

``POLICY`` is the access level each HTTP route needs.  A new route must be
added to it (``test_route_inventory_is_classified`` fails otherwise), which
makes whoever adds one decide who may call it.

Each credential test walks every route in one test and lists every route
that misbehaves, so a single run names all of them and the suite stays
fast.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute
from starlette.routing import Mount, Route
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.lib.config import MLRFConfig
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny import dependencies as deps
from sigrift.lib.shiny.persistence import PersistenceManager
from sigrift.lib.shiny.routers import training
from sigrift.lib.shiny.spectrum_streamer import SpectrumStreamer
from sigrift.lib.shiny.state import AppState

VIEWER = "viewer"  # any valid key (rate limited)
ANALYST = "analyst"  # a key with the analyst role or higher (writes)
ADMIN = "admin"  # a key with the admin role (the master key is one)
MASTER = "master"  # the master key only

POLICY: dict[tuple[str, str], str] = {
    ("GET", "/api/health"): VIEWER,
    ("GET", "/api/status"): VIEWER,
    ("POST", "/api/nodes/register"): ADMIN,
    # Heartbeats are further gated by the key's node binding (test_roles_*).
    ("POST", "/api/nodes/heartbeat"): VIEWER,
    ("GET", "/api/nodes/"): VIEWER,
    ("GET", "/api/nodes/activity"): VIEWER,
    ("GET", "/api/nodes/{node_id}"): VIEWER,
    ("DELETE", "/api/nodes/{node_id}"): MASTER,
    ("POST", "/api/nodes/{node_id}/command"): ADMIN,
    # Connecting, disconnecting and retuning the SDR change what every
    # operator sees (the bridge's connect / disconnect need analyst too).
    ("POST", "/api/spectrum/connect"): ANALYST,
    ("GET", "/api/spectrum/disconnect"): ANALYST,
    ("GET", "/api/spectrum/config"): VIEWER,
    ("PUT", "/api/spectrum/config"): ANALYST,
    ("GET", "/api/spectrum/status"): VIEWER,
    ("GET", "/api/training/current"): VIEWER,
    ("GET", "/api/training/history"): VIEWER,
    ("GET", "/api/training/runs/{run_id}"): VIEWER,
    ("GET", "/api/training/models"): VIEWER,
    ("GET", "/api/training/models/{model_id}"): VIEWER,
    ("POST", "/api/training/models/{model_id}/evaluate"): ANALYST,
    ("GET", "/api/signals/classes"): VIEWER,
    ("GET", "/api/signals/families"): VIEWER,
    ("GET", "/api/signals/super-families"): VIEWER,
    ("GET", "/api/signals/generate"): VIEWER,
    ("GET", "/api/signals/dsp-features"): VIEWER,
    ("POST", "/api/signals/compare"): VIEWER,
    ("GET", "/api/alerts/"): VIEWER,
    ("POST", "/api/alerts/rules"): ANALYST,
    ("PUT", "/api/alerts/{alert_id}/ack"): ANALYST,
    ("DELETE", "/api/alerts/rules/{rule_id}"): MASTER,
    ("GET", "/api/alerts/history"): VIEWER,
    ("POST", "/api/keys/"): MASTER,
    ("GET", "/api/keys/"): VIEWER,
    ("PATCH", "/api/keys/{key_id}"): MASTER,
    ("DELETE", "/api/keys/{key_id}"): MASTER,
    ("PUT", "/api/keys/{key_id}/rotate"): MASTER,
    ("GET", "/api/jobs/presets"): VIEWER,
    ("GET", "/api/jobs/"): VIEWER,
    ("POST", "/api/jobs/"): ANALYST,
    ("GET", "/api/jobs/schedules"): VIEWER,
    ("POST", "/api/jobs/schedules"): ANALYST,
    ("DELETE", "/api/jobs/schedules/{schedule_id}"): MASTER,
    ("PUT", "/api/jobs/schedules/{schedule_id}"): ANALYST,
    ("GET", "/api/jobs/{job_id}"): VIEWER,
    ("DELETE", "/api/jobs/{job_id}"): MASTER,
    ("PUT", "/api/jobs/{job_id}/priority"): ANALYST,
    ("POST", "/api/jobs/{job_id}/rerun"): ANALYST,
    ("GET", "/api/export/nodes"): VIEWER,
    ("GET", "/api/export/training"): VIEWER,
    ("GET", "/api/export/alerts"): VIEWER,
}

# Served without a key: the dashboard page (it asks for the key in the
# browser) and FastAPI's generated API docs.
PUBLIC_PAGES = {("GET", "/")}
DOCS_ROUTES = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
WS_ROUTES = {
    "/api/nodes/ws/status",
    "/api/spectrum/ws/spectrum",
    "/api/training/ws/training",
    "/api/alerts/ws/alerts",
}

_PARAM = re.compile(r"\{[^}]+\}")
_SECURITY_HEADERS = {
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


def _concrete(path: str) -> str:
    """*path* with every ``{param}`` filled with a placeholder id."""
    return _PARAM.sub("probe-id", path)


def _routes(level: str) -> list[tuple[str, str]]:
    return sorted(k for k, v in POLICY.items() if v == level)


def _add_key(pm: PersistenceManager, key_id: str, **meta: Any) -> dict[str, str]:
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    pm.set_key(key_id, hash_hex, salt, meta=meta or None)
    return {"X-API-Key": raw}


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()


def _detail(resp: httpx.Response) -> Any:
    """The JSON ``detail`` of *resp*, or its raw text (e.g. an empty 204)."""
    try:
        return resp.json().get("detail")
    except ValueError:
        return resp.text


@pytest.fixture(autouse=True)
def _fast_hashing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cheap PBKDF2 (these tests hash many keys) and a clean key index."""
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)
    monkeypatch.setattr(deps, "_fast_hash_index", {})


@pytest.fixture()
def pm(tmp_path: Path) -> PersistenceManager:
    manager = PersistenceManager(data_dir=tmp_path / "data", auto_save_interval=0)
    manager.load_all()
    return manager


@pytest.fixture()
def prod_app(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pm: PersistenceManager
) -> FastAPI:
    """The production app with test state injected (its lifespan never runs)."""
    from sigrift.lib.shiny.app import app

    monkeypatch.setattr(app.state, "persistence", pm, raising=False)
    monkeypatch.setattr(app.state, "app_state", AppState(), raising=False)
    monkeypatch.setattr(
        app.state, "spectrum_streamer", SpectrumStreamer(), raising=False
    )
    monkeypatch.setattr(deps, "_config_singleton", MLRFConfig())
    monkeypatch.setattr(
        deps, "_rate_limiter", deps.RateLimiter(max_requests=10_000, window_seconds=60)
    )
    # Training routes scan the checkout for logs and models: point them at
    # empty test directories so results do not depend on the machine.
    monkeypatch.setattr(training, "_LOG_SEARCH_DIRS", [tmp_path / "logs"])
    monkeypatch.setattr(training, "_MODEL_SEARCH_DIRS", [tmp_path / "models"])
    return app


@pytest_asyncio.fixture()
async def client(prod_app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=prod_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def _status_by_route(
    client: httpx.AsyncClient,
    routes: list[tuple[str, str]],
    headers: dict[str, str] | None = None,
) -> dict[tuple[str, str], httpx.Response]:
    return {
        (method, path): await client.request(
            method, _concrete(path), headers=headers or {}
        )
        for method, path in routes
    }


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


def test_route_inventory_is_classified(prod_app: FastAPI) -> None:
    """Every route the app serves has an entry in POLICY (or is public)."""
    api, ws, docs, mounts = set(), set(), set(), set()
    for route in prod_app.routes:
        if isinstance(route, APIRoute):
            api |= {(m, route.path) for m in route.methods}
        elif isinstance(route, APIWebSocketRoute):
            ws.add(route.path)
        elif isinstance(route, Mount):
            mounts.add(route.path)
        elif isinstance(route, Route):
            docs.add(route.path)
    assert api - PUBLIC_PAGES == set(POLICY), (
        "unclassified routes: "
        f"{sorted(api - PUBLIC_PAGES - set(POLICY))}; "
        f"stale POLICY entries: {sorted(set(POLICY) - api)}"
    )
    assert PUBLIC_PAGES <= api
    assert ws == WS_ROUTES
    assert docs == DOCS_ROUTES
    assert mounts == {"/static"}


# ---------------------------------------------------------------------------
# Authentication: every API route, every bad credential
# ---------------------------------------------------------------------------


_REFUSED_CREDENTIALS: dict[str, tuple[str | None, dict[str, str], str]] = {
    # case: (stored key id or None for a key not in the store, its stored
    # metadata, expected 401 detail).  Expiry is checked even for the
    # master key; the master key's role is fixed (admin), so an unknown
    # role is tried on an ordinary admin-looking key.
    "missing": (None, {}, "API key required"),
    "unknown": (None, {}, "Invalid API key"),
    "expired": ("master", {"expires_at": "past"}, "API key expired"),
    "unparseable-expiry": ("master", {"expires_at": "next tuesday"}, "API key expired"),
    "unknown-role": (
        "ops-key",
        {"role": "superuser"},
        "API key has an unknown role 'superuser'",
    ),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", sorted(_REFUSED_CREDENTIALS))
async def test_every_api_route_refuses_a_bad_credential(
    client: httpx.AsyncClient, pm: PersistenceManager, case: str
) -> None:
    """401 with the reason on every API route, master-only routes included.

    Every response -- refusals included -- carries the dashboard's security
    headers.
    """
    _add_key(pm, "other-viewer")  # a valid key in the store that must not match
    key_id, meta, detail = _REFUSED_CREDENTIALS[case]
    if case == "missing":
        headers: dict[str, str] = {}
    elif key_id is None:
        headers = {"X-API-Key": generate_api_key()}
    else:
        meta = {k: (_past() if v == "past" else v) for k, v in meta.items()}
        headers = _add_key(pm, key_id, **meta)

    responses = await _status_by_route(client, sorted(POLICY), headers)
    wrong = {
        f"{m} {p}": (r.status_code, _detail(r))
        for (m, p), r in responses.items()
        if r.status_code != 401 or _detail(r) != detail
    }
    assert not wrong, f"routes that did not refuse a {case} key: {wrong}"
    missing_headers = {
        f"{m} {p}": name
        for (m, p), r in responses.items()
        for name, value in _SECURITY_HEADERS.items()
        if value not in r.headers.get(name, "")
    }
    assert not missing_headers


def test_query_parameter_key_is_refused_like_a_header_key(
    prod_app: FastAPI, pm: PersistenceManager
) -> None:
    """``?api_key=`` (still accepted for HTTP) goes through the same checks."""
    expired = _add_key(pm, "old", expires_at=_past())["X-API-Key"]
    good = _add_key(pm, "good")["X-API-Key"]
    client = TestClient(prod_app)
    assert client.get("/api/health", params={"api_key": good}).status_code == 200
    resp = client.get("/api/health", params={"api_key": expired})
    assert (resp.status_code, resp.json()["detail"]) == (401, "API key expired")
    resp = client.get("/api/health", params={"api_key": "x" + good})
    assert (resp.status_code, resp.json()["detail"]) == (401, "Invalid API key")


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_master_only_routes_refuse_every_other_key(
    client: httpx.AsyncClient, pm: PersistenceManager
) -> None:
    keys = {
        "admin": _add_key(pm, "ops-admin", role="admin"),
        "analyst": _add_key(pm, "ops-analyst", role="analyst"),
        "viewer": _add_key(pm, "ops-viewer"),
        # A key whose id merely contains "master" is not the master key.
        "master-like": _add_key(pm, "master-2", role="admin"),
    }
    wrong = {}
    for name, headers in keys.items():
        for (m, p), r in (
            await _status_by_route(client, _routes(MASTER), headers)
        ).items():
            if r.status_code != 403 or _detail(r) != "Master key required":
                wrong[f"{name}: {m} {p}"] = r.status_code
    assert not wrong


@pytest.mark.asyncio
async def test_admin_routes_refuse_viewer_and_analyst_keys(
    client: httpx.AsyncClient, pm: PersistenceManager
) -> None:
    keys = {
        "viewer (no stored role)": _add_key(pm, "legacy-viewer"),
        "viewer": _add_key(pm, "viewer-1", role="viewer"),
        "analyst": _add_key(pm, "analyst-1", role="analyst"),
        "node key": _add_key(pm, "node-1", purpose="node", node_id="probe-id"),
    }
    wrong = {}
    for name, headers in keys.items():
        for (m, p), r in (
            await _status_by_route(client, _routes(ADMIN), headers)
        ).items():
            if r.status_code != 403 or _detail(r) != "admin role required":
                wrong[f"{name}: {m} {p}"] = r.status_code
    assert not wrong


@pytest.mark.asyncio
async def test_analyst_routes_refuse_viewer_keys(
    client: httpx.AsyncClient, pm: PersistenceManager
) -> None:
    """Every write a viewer could make before roles mattered is now 403."""
    keys = {
        "viewer (no stored role)": _add_key(pm, "legacy-viewer"),
        "viewer": _add_key(pm, "viewer-1", role="viewer"),
        "dashboard viewer": _add_key(pm, "dash-1", role="viewer", purpose="dashboard"),
        "node key": _add_key(pm, "node-1", purpose="node", node_id="probe-id"),
    }
    wrong = {}
    for name, headers in keys.items():
        for (m, p), r in (
            await _status_by_route(client, _routes(ANALYST), headers)
        ).items():
            if r.status_code != 403 or _detail(r) != "analyst role required":
                wrong[f"{name}: {m} {p}"] = r.status_code
    assert not wrong


@pytest.mark.asyncio
async def test_each_route_admits_the_keys_its_level_allows(
    client: httpx.AsyncClient, pm: PersistenceManager
) -> None:
    """The positive side of POLICY: no 401/403 for a key at the right level.

    (Placeholder ids and missing bodies give 404 / 422: that is past auth.)
    """
    viewer = _add_key(pm, "viewer-1")
    analyst = _add_key(pm, "analyst-1", role="analyst")
    admin = _add_key(pm, "admin-1", role="admin")
    master = _add_key(pm, "master")
    allowed = {
        VIEWER: (viewer, analyst, admin, master),
        ANALYST: (analyst, admin, master),
        ADMIN: (admin, master),
        MASTER: (master,),
    }
    wrong = {}
    for level, key_set in allowed.items():
        for headers in key_set:
            for (m, p), r in (
                await _status_by_route(client, _routes(level), headers)
            ).items():
                if r.status_code in (401, 403, 429) or r.status_code >= 500:
                    wrong[f"{m} {p}"] = (r.status_code, r.text[:80])
    assert not wrong


@pytest.mark.asyncio
async def test_every_non_master_route_is_rate_limited_per_key(
    client: httpx.AsyncClient, pm: PersistenceManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second request inside the window is 429 with Retry-After.

    The limiter counts the key at authentication, so the 429 comes before
    any body validation or work.  (Master-only routes authenticate with
    ``require_master_key``; the key-management ones add a stricter
    ``rate_limit_sensitive`` bucket, tested in test_auth.py.)
    """
    limiter = deps.RateLimiter(max_requests=1, window_seconds=3600)
    monkeypatch.setattr(deps, "_rate_limiter", limiter)
    headers = _add_key(pm, "admin-1", role="admin")
    other = _add_key(pm, "admin-2", role="admin")
    wrong = {}
    for method, path in _routes(VIEWER) + _routes(ANALYST) + _routes(ADMIN):
        limiter.reset()
        first = await client.request(method, _concrete(path), headers=headers)
        second = await client.request(method, _concrete(path), headers=headers)
        # Another key has its own bucket.
        third = await client.request(method, _concrete(path), headers=other)
        if (
            first.status_code == 429
            or second.status_code != 429
            or not second.headers.get("Retry-After", "").isdigit()
            or third.status_code == 429
        ):
            wrong[f"{method} {path}"] = (
                first.status_code,
                second.status_code,
                third.status_code,
            )
    assert not wrong


# A key without a role is documented as read-only: "are now viewers
# (read-only)" (app.warn_legacy_viewer_keys), "viewer (default) reads the
# dashboard" (models.ManagedKeyCreate).  These writes need ANALYST, as the
# bridge's alert-rule, acknowledge and job-creation routes do.
_VIEWER_WRITES = [
    "create-alert-rule",
    "acknowledge-alert",
    "create-job",
    "change-job-priority",
    "rerun-job",
    "create-schedule",
    "update-schedule",
    "queue-model-evaluation",
]


async def _viewer_write_request(
    case: str, client: httpx.AsyncClient, master: dict[str, str], tmp_path: Path
) -> tuple[str, str, Any]:
    """Create what *case* writes to (with the master key); return the request."""
    if case == "create-alert-rule":
        return "POST", "/api/alerts/rules", {"name": "viewer rule"}
    if case == "acknowledge-alert":
        r = await client.post("/api/alerts/rules", headers=master, json={"name": "a"})
        return "PUT", f"/api/alerts/{r.json()['alert_id']}/ack", None
    if case == "create-schedule":
        body = {"name": "s", "node_id": "edge-01", "interval": "daily"}
        return "POST", "/api/jobs/schedules", body
    if case == "update-schedule":
        body = {"name": "s", "node_id": "edge-01", "interval": "daily"}
        r = await client.post("/api/jobs/schedules", headers=master, json=body)
        return (
            "PUT",
            f"/api/jobs/schedules/{r.json()['schedule_id']}",
            {"enabled": False},
        )
    if case == "queue-model-evaluation":
        (tmp_path / "models").mkdir()
        (tmp_path / "models" / "edge-v1.pth").write_bytes(b"weights")
        return "POST", "/api/training/models/edge-v1/evaluate", None
    if case == "create-job":
        return "POST", "/api/jobs/", {"name": "viewer-job"}
    r = await client.post("/api/jobs/", headers=master, json={"name": "base"})
    job_id = r.json()["job_id"]
    if case == "change-job-priority":
        return "PUT", f"/api/jobs/{job_id}/priority", {"priority": 99}
    return "POST", f"/api/jobs/{job_id}/rerun", None


_VIEWERS = {
    "legacy": {},  # stored before roles existed
    "viewer": {"role": "viewer"},
    "dashboard": {"role": "viewer", "purpose": "dashboard"},
}


@pytest.mark.asyncio
@pytest.mark.parametrize("viewer_meta", sorted(_VIEWERS))
@pytest.mark.parametrize("case", _VIEWER_WRITES)
async def test_viewer_key_cannot_write(
    client: httpx.AsyncClient,
    pm: PersistenceManager,
    tmp_path: Path,
    case: str,
    viewer_meta: str,
) -> None:
    master = _add_key(pm, "master")
    viewer = _add_key(pm, "viewer-1", **_VIEWERS[viewer_meta])
    method, path, body = await _viewer_write_request(case, client, master, tmp_path)
    before = (pm.get_alerts(), pm.get_jobs(), pm.get_schedules())
    before = repr(before)

    resp = await client.request(method, path, headers=viewer, json=body)

    assert resp.status_code == 403, (resp.status_code, resp.text[:120])
    assert resp.json()["detail"] == "analyst role required"
    assert repr((pm.get_alerts(), pm.get_jobs(), pm.get_schedules())) == before


@pytest.mark.asyncio
@pytest.mark.parametrize("role", ["analyst", "admin"])
@pytest.mark.parametrize("case", _VIEWER_WRITES)
async def test_analyst_and_admin_keys_can_write(
    client: httpx.AsyncClient,
    pm: PersistenceManager,
    tmp_path: Path,
    case: str,
    role: str,
) -> None:
    """The same writes succeed (and change state) for an analyst or admin key."""
    master = _add_key(pm, "master")
    writer = _add_key(pm, "writer-1", role=role)
    method, path, body = await _viewer_write_request(case, client, master, tmp_path)
    before = repr((pm.get_alerts(), pm.get_jobs(), pm.get_schedules()))

    resp = await client.request(method, path, headers=writer, json=body)

    assert resp.status_code in (200, 201), (resp.status_code, resp.text[:120])
    assert repr((pm.get_alerts(), pm.get_jobs(), pm.get_schedules())) != before


# ---------------------------------------------------------------------------
# Public pages and WebSockets through the production middleware
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/", "/static/dashboard.js", "/static/style.css"])
async def test_public_pages_need_no_key_and_carry_security_headers(
    client: httpx.AsyncClient, path: str
) -> None:
    resp = await client.get(path)
    assert resp.status_code == 200
    for name, value in _SECURITY_HEADERS.items():
        assert value in resp.headers.get(name, ""), name


@pytest.mark.asyncio
async def test_dashboard_page_runs_no_inline_script(client: httpx.AsyncClient) -> None:
    """The CSP allows only same-origin script files: the page must not need more."""
    html = (await client.get("/")).text
    scripts = re.findall(r"<script\b[^>]*>", html, flags=re.I)
    assert scripts and all(" src=" in tag for tag in scripts), scripts
    assert not re.search(r"\son[a-z]+\s*=", html, flags=re.I)
    assert "javascript:" not in html.lower()


@pytest.mark.parametrize("path", sorted(WS_ROUTES))
def test_websockets_refuse_rejected_keys_through_the_production_stack(
    prod_app: FastAPI, pm: PersistenceManager, path: str
) -> None:
    """Expired and unknown-role keys are refused with 4001 before accept."""
    client = TestClient(prod_app)  # not entered: the real lifespan never runs
    for meta in ({"expires_at": _past()}, {"role": "superuser"}):
        raw = _add_key(pm, "ws-key", **meta)["X-API-Key"]
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect(path, subprotocols=["bridge-v1", raw]):
                pass
        assert exc.value.code == 4001, meta
    good = _add_key(pm, "ws-good")["X-API-Key"]
    with client.websocket_connect(path, subprotocols=["bridge-v1", good]) as ws:
        assert ws.accepted_subprotocol == "bridge-v1"
