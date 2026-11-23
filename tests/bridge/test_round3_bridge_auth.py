"""Round-3 regression tests for the bridge's auth and HTTP/WS surface (group BA).

Each class covers one finding of docs/reviews/2026-11-05-repo-review.md and
the bridge side of the cross-group contracts:

* B3 / K2 — proxy-only bridge: constant-time X-Rust-Proxy check that never
  passes on an empty or default secret, also applied to WebSocket upgrades;
  loopback-only health-check exemptions; trusted proxies by IP, CIDR or
  host name.
* B4 / K3 — forced password change: ``password_change_only`` sessions are
  confined (HTTP, proxied reads, WebSockets); login fails closed; change
  password reissues a full session.
* B5 / K1 — WebSocket auth resolves role and session like HTTP auth.
* B1, B2 / K4 — node binding (trust on first use), capture needs ANALYST,
  admin queue headroom, the in-stack scanner key bound to its node.
* B7 / K5 — master-key rotation and role ceilings.
* B8 — CSV formula injection.  B10 — malformed input is a 4xx, not a 500.
* B11 — bounded, off-loop classifier inference.  G11 — no JS reads
  ``bridge_token``.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import os
import socket
import threading
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import sigrift.bridge.app as app_module
import sigrift.bridge.dependencies as deps
from sigrift.bridge.constants import LOCAL_SCANNER_KEY_ID
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_STATIC = Path(app_module.__file__).resolve().parent / "static"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_state():
    deps._verified_key_cache.clear()
    deps.set_ws_limiter(deps.WSConnectionLimiter())
    yield
    deps._verified_key_cache.clear()


def _add_key(
    persistence: PersistenceManager,
    key_id: str,
    role: str,
    node_id: str | None = None,
) -> str:
    """Create an indexed API key with *role*; return the raw key."""
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    if node_id is not None:
        meta["node_id"] = node_id
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _register(client: TestClient, *node_ids: str) -> None:
    for node_id in node_ids:
        resp = client.post("/api/nodes/register", json={"node_id": node_id})
        assert resp.status_code == 200, resp.text


def _session(
    store: DetectionStore,
    username: str,
    *,
    role: str = "viewer",
    scope: str = "",
    ip: str = "",
) -> str:
    """Create a user (if needed) and a session for it; return the token."""
    if store.users.get_user(username) is None:
        store.create_user(username=username, password="Password123!", role=role)
    user = store.users.get_user(username)
    token = store.create_session(user_id=user["id"], ip_address=ip)["session_token"]
    if scope:
        store.users.set_session_scope(token, scope=scope)
    return token


def _heartbeat(client: TestClient, key: str, node_id: str):
    return client.post(
        "/api/nodes/heartbeat",
        json={"node_id": node_id},
        headers={"X-API-Key": key},
    )


# ---------------------------------------------------------------------------
# B3 / K2 — proxy-only bridge
# ---------------------------------------------------------------------------

_SECRET = "s3cret-proxy-value-0123456789abcdef"


@pytest.fixture
def require_proxy(monkeypatch):
    def _set(secret: str) -> None:
        monkeypatch.setattr(app_module, "_REQUIRE_PROXY", True)
        monkeypatch.setattr(app_module, "_PROXY_SECRET", secret.encode())

    return _set


class TestProxyOnlyBridge:
    def test_missing_or_wrong_header_is_refused(self, bridge_app, require_proxy):
        require_proxy(_SECRET)
        c = TestClient(bridge_app)
        assert c.get("/api/healthz").status_code == 403
        bad = c.get("/api/healthz", headers={"X-Rust-Proxy": _SECRET[:-1] + "x"})
        assert bad.status_code == 403
        ok = c.get("/api/healthz", headers={"X-Rust-Proxy": _SECRET})
        assert ok.status_code == 200

    @pytest.mark.parametrize("secret", ["", "uppercrust-internal"])
    def test_empty_or_default_secret_never_passes(
        self, bridge_app, require_proxy, secret
    ):
        # Before: b"" == b"" let every request without the header through
        # when UC_PROXY_SECRET was unset.
        require_proxy(secret)
        c = TestClient(bridge_app)
        assert c.get("/api/healthz").status_code == 403
        resp = c.get("/api/healthz", headers={"X-Rust-Proxy": secret})
        assert resp.status_code == 403

    def test_websocket_upgrade_needs_the_header(
        self, bridge_app, require_proxy, master_key
    ):
        # Before: WebSocket scopes skipped the check entirely.
        require_proxy(_SECRET)
        c = TestClient(bridge_app)
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", master_key]
            ):
                pass
        with c.websocket_connect(
            "/api/nodes/ws/status",
            subprotocols=["bridge-v1", master_key],
            headers={"X-Rust-Proxy": _SECRET},
        ) as ws:
            assert ws.receive_json()["type"] == "snapshot"

    def test_health_checks_exempt_from_loopback_only(self, bridge_app, require_proxy):
        require_proxy(_SECRET)
        # TestClient's peer is "testclient" — not loopback.
        assert TestClient(bridge_app).get("/api/healthz").status_code == 403

        async def _get(peer: str, path: str, method: str = "GET") -> int:
            transport = httpx.ASGITransport(app=bridge_app, client=(peer, 40000))
            async with httpx.AsyncClient(
                transport=transport, base_url="http://bridge"
            ) as ac:
                return (await ac.request(method, path)).status_code

        assert asyncio.run(_get("127.0.0.1", "/api/healthz")) == 200
        assert asyncio.run(_get("::1", "/api/healthz")) == 200
        assert asyncio.run(_get("127.0.0.1", "/api/ready")) != 403
        # Only those two GETs, only from loopback.
        assert asyncio.run(_get("127.0.0.1", "/api/health")) == 403
        assert asyncio.run(_get("10.1.2.3", "/api/healthz")) == 403
        assert asyncio.run(_get("127.0.0.1", "/api/healthz", "POST")) == 403


class TestTrustedProxies:
    @pytest.fixture
    def trusted(self, monkeypatch):
        def _set(value: str) -> None:
            monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", value)
            deps.reload_trusted_proxies()

        yield _set
        monkeypatch.delenv("BRIDGE_TRUSTED_PROXIES", raising=False)
        deps.reload_trusted_proxies()

    @staticmethod
    def _ip(peer: str, xff: str) -> str:
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", xff.encode())],
            "client": (peer, 0),
        }
        return deps.get_client_ip(Request(scope))

    def test_host_name_is_resolved(self, trusted, monkeypatch):
        def fake_getaddrinfo(host, *args, **kwargs):
            assert host == "gateway"
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.29.84.2", 0))]

        monkeypatch.setattr(deps.socket, "getaddrinfo", fake_getaddrinfo)
        trusted("gateway")
        assert self._ip("172.29.84.2", "203.0.113.7") == "203.0.113.7"
        # Only the gateway: another container on the network is not trusted.
        assert self._ip("172.29.84.3", "203.0.113.7") == "172.29.84.3"

    def test_unresolvable_host_name_trusts_nothing(self, trusted, monkeypatch):
        def fail(*args, **kwargs):
            raise socket.gaierror("no such host")

        monkeypatch.setattr(deps.socket, "getaddrinfo", fail)
        trusted("gateway")
        assert self._ip("172.29.84.2", "203.0.113.7") == "172.29.84.2"

    def test_default_trusts_loopback_only(self, trusted):
        trusted("")
        assert self._ip("172.17.0.5", "203.0.113.7") == "172.17.0.5"
        assert self._ip("127.0.0.1", "203.0.113.7") == "203.0.113.7"
        assert self._ip("::ffff:127.0.0.1", "203.0.113.7") == "203.0.113.7"


# ---------------------------------------------------------------------------
# B4 / K3 — forced password change
# ---------------------------------------------------------------------------


class TestForcedPasswordChange:
    @pytest.fixture
    def anon(self, bridge_app) -> TestClient:
        return TestClient(bridge_app)

    def _login(self, anon: TestClient, password: str = "Bootstrap123!") -> dict:
        resp = anon.post(
            "/api/auth/login", json={"username": "boot", "password": password}
        )
        assert resp.status_code == 200, resp.text
        return resp.json()

    @pytest.fixture
    def flagged(self, detection_store):
        detection_store.create_user(
            username="boot",
            password="Bootstrap123!",
            role="admin",
            must_change_password=True,
        )

    def test_session_is_confined_until_the_password_changes(
        self, anon, detection_store, flagged
    ):
        data = self._login(anon)
        assert data["password_change_required"] is True
        auth = {"Authorization": f"Bearer {data['session_token']}"}

        # Before: the scope was set but never enforced (200 everywhere).
        for path in ("/api/nodes/", "/api/keys/", "/api/admin/keys"):
            resp = anon.get(path, headers=auth)
            assert resp.status_code == 403, path
            assert resp.json() == {"detail": "password change required"}
        # Proxied read paths are checked in the middleware.
        resp = anon.get("/api/detections/stats", headers=auth)
        assert resp.status_code == 403
        assert resp.json() == {"detail": "password change required"}
        assert anon.get("/api/auth/me", headers=auth).status_code == 200

        resp = anon.post(
            "/api/auth/change-password",
            headers=auth,
            json={"current_password": "Bootstrap123!", "new_password": "N3w-pass!!"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["password_change_required"] is False
        new_auth = {"Authorization": f"Bearer {body['session_token']}"}
        # The restricted session is gone; the reissued one is a full session.
        assert anon.get("/api/auth/me", headers=auth).status_code == 401
        assert anon.get("/api/nodes/", headers=new_auth).status_code == 200
        assert detection_store.users.get_user("boot")["must_change_password"] is False
        # And the next login is not restricted any more.
        assert self._login(anon, "N3w-pass!!")["password_change_required"] is False

    def test_websocket_refuses_a_password_change_session(
        self, anon, bridge_app, flagged
    ):
        token = self._login(anon)["session_token"]
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", token]
            ):
                pass
        assert exc.value.code == 4003

    def test_login_fails_closed_when_the_scope_does_not_stick(
        self, anon, detection_store, flagged, monkeypatch
    ):
        # set_session_scope swallows its errors; before, the login then
        # returned a full-scope session.
        monkeypatch.setattr(
            detection_store.users, "set_session_scope", lambda *a, **k: None
        )
        resp = anon.post(
            "/api/auth/login", json={"username": "boot", "password": "Bootstrap123!"}
        )
        assert resp.status_code == 503
        user_id = detection_store.users.get_user("boot")["id"]
        conn = detection_store.get_connection()
        left = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?", [user_id]
        ).fetchone()[0]
        assert left == 0

    def test_mfa_login_is_confined_too(self, tmp_path, detection_store, flagged):
        from sigrift.bridge.routers import auth, mfa
        from sigrift.bridge.security.totp import compute_totp, generate_secret

        app = FastAPI()
        app.add_middleware(app_module.CombinedMiddleware)
        app.state.detection_store = detection_store
        app.include_router(auth.router, prefix="/api")
        app.include_router(mfa.router, prefix="/api")
        user_id = detection_store.users.get_user("boot")["id"]
        secret = generate_secret()
        detection_store.users.set_totp_secret(user_id, secret)
        detection_store.users.enable_mfa(user_id)

        c = TestClient(app)
        step1 = c.post(
            "/api/auth/login", json={"username": "boot", "password": "Bootstrap123!"}
        ).json()
        assert step1["mfa_required"] is True
        resp = c.post(
            "/api/auth/mfa/verify",
            json={"mfa_token": step1["mfa_token"], "totp_code": compute_totp(secret)},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["password_change_required"] is True
        token = resp.json()["session_token"]
        session = detection_store.get_session(token)
        assert session["scope"] == "password_change_only"

    def test_unknown_scope_fails_closed(self, anon, detection_store):
        token = _session(detection_store, "odd", scope="something_new")
        auth = {"Authorization": f"Bearer {token}"}
        assert anon.get("/api/nodes/", headers=auth).status_code == 403
        assert anon.get("/api/auth/me", headers=auth).status_code == 200


class TestBootstrapAdmin:
    def test_generated_admin_password_must_be_changed(self, tmp_path):
        from .test_lifespan import (
            _lifespan_env,
            _make_app_with_lifespan,
            _patch_data_paths,
            _patch_detection_store,
            _patch_iq_store,
            _patch_pcap_store,
            _patch_persistence_dir,
        )

        data = tmp_path / "data"
        data.mkdir()
        app = _make_app_with_lifespan()
        env = _lifespan_env(data)
        env.update(
            {
                "BRIDGE_ENV": "",
                "BRIDGE_MODE": "",
                "BRIDGE_ADMIN_PASSWORD": "",
                "BRIDGE_ADMIN_USER": "admin",
                "BRIDGE_MASTER_KEY": generate_api_key(32),
                "BRIDGE_LOCAL_NODE_KEY": generate_api_key(32),
                "BRIDGE_LOCAL_NODE_ID": "edge-under-test",
            }
        )
        with (
            patch.dict(os.environ, env),
            _patch_data_paths(data),
            _patch_persistence_dir(data),
            _patch_detection_store(data),
            _patch_iq_store(data),
            _patch_pcap_store(data),
        ):
            with TestClient(app):
                store = app.state.detection_store
                assert store.users.get_user("admin")["must_change_password"] is True
                # K4: the in-stack scanner key is bound to its node.
                meta = app.state.persistence.get_key_meta()[LOCAL_SCANNER_KEY_ID]
                assert meta["node_id"] == "edge-under-test"
                assert meta["role"] == "node"


# ---------------------------------------------------------------------------
# B5 / K1 — WebSocket auth
# ---------------------------------------------------------------------------


class TestWebSocketAuth:
    @pytest.mark.parametrize("role", ["sensor", "node"])
    def test_node_and_sensor_keys_cannot_stream(self, bridge_app, persistence, role):
        raw = _add_key(persistence, f"k_{role}", role)
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/detections/ws/feed", subprotocols=["bridge-v1", raw]
            ):
                pass
        assert exc.value.code == 4003

    def test_viewer_key_streams_and_subprotocol_is_echoed(
        self, bridge_app, persistence
    ):
        raw = _add_key(persistence, "k_viewer", "viewer")
        with TestClient(bridge_app).websocket_connect(
            "/api/nodes/ws/status", subprotocols=["bridge-v1", raw]
        ) as ws:
            assert ws.accepted_subprotocol == "bridge-v1"
            assert ws.receive_json()["type"] == "snapshot"

    def test_mfa_pending_session_cannot_stream(self, bridge_app, detection_store):
        token = _session(detection_store, "mfa_user", scope="mfa_setup_only")
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/alerts/ws/alerts", subprotocols=["bridge-v1", token]
            ):
                pass
        assert exc.value.code == 4003

    def test_session_binding_is_checked(self, bridge_app, detection_store, monkeypatch):
        monkeypatch.setenv("BRIDGE_SESSION_BINDING", "ip")
        token = _session(detection_store, "roamer", ip="198.51.100.9")
        with pytest.raises(WebSocketDisconnect) as exc:
            with TestClient(bridge_app).websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", token]
            ):
                pass
        assert exc.value.code == 4001

    def test_session_cookie_authenticates_without_subprotocol(
        self, bridge_app, detection_store
    ):
        # K1: the gateway forwards the session_token cookie on upgrades.
        token = _session(detection_store, "cookie_user")
        c = TestClient(bridge_app, cookies={"session_token": token})
        with c.websocket_connect("/api/nodes/ws/status") as ws:
            assert ws.accepted_subprotocol is None
            assert ws.receive_json()["type"] == "snapshot"

    # One rule for the gateway and the bridge (K1): the upgrade's own
    # credential (session cookie, X-API-Key or client certificate — what the
    # gateway forwards once it has verified it) first, the credential in the
    # subprotocol list only when that finds none.  Before, the bridge
    # checked the subprotocol first and refused on it, so an upgrade the
    # gateway had accepted by its cookie was closed with 4001 at once.

    def test_bad_subprotocol_credential_falls_back_to_the_cookie(
        self, bridge_app, detection_store
    ):
        # E.g. a stale token in sessionStorage after logging in again in
        # another tab, next to the fresh cookie.
        token = _session(detection_store, "relogged")
        c = TestClient(bridge_app, cookies={"session_token": token})
        with c.websocket_connect(
            "/api/nodes/ws/status", subprotocols=["bridge-v1", "stale-token"]
        ) as ws:
            assert ws.accepted_subprotocol == "bridge-v1"
            assert ws.receive_json()["type"] == "snapshot"

    def test_bad_subprotocol_credential_falls_back_to_the_api_key(
        self, bridge_app, persistence
    ):
        raw = _add_key(persistence, "k_viewer", "viewer")
        with TestClient(bridge_app).websocket_connect(
            "/api/nodes/ws/status",
            subprotocols=["bridge-v1", "not-a-key"],
            headers={"X-API-Key": raw},
        ) as ws:
            assert ws.accepted_subprotocol == "bridge-v1"
            assert ws.receive_json()["type"] == "snapshot"

    def test_bad_subprotocol_credential_falls_back_to_the_client_cert(
        self, bridge_app, monkeypatch
    ):
        monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
        cert = {
            "x-auth-method": "client-cert",
            "x-rust-proxy": _SECRET,
            "x-auth-key-id": "edge-7",
            "x-auth-role": "viewer",
        }
        with TestClient(bridge_app).websocket_connect(
            "/api/nodes/ws/status",
            subprotocols=["bridge-v1", "not-a-key"],
            headers=cert,
        ) as ws:
            assert ws.receive_json()["type"] == "snapshot"

    def test_the_request_credential_wins_over_the_subprotocol(
        self, bridge_app, persistence, detection_store
    ):
        # The gateway authenticates (and forwards) the cookie; a SENSOR key
        # in the subprotocol list does not get the socket refused here.
        token = _session(detection_store, "watcher")
        sensor = _add_key(persistence, "k_sensor", "sensor")
        c = TestClient(bridge_app, cookies={"session_token": token})
        with c.websocket_connect(
            "/api/nodes/ws/status", subprotocols=["bridge-v1", sensor]
        ) as ws:
            assert ws.receive_json()["type"] == "snapshot"

    def test_stale_cookie_falls_back_to_the_subprotocol_credential(
        self, bridge_app, persistence
    ):
        raw = _add_key(persistence, "k_viewer", "viewer")
        c = TestClient(bridge_app, cookies={"session_token": "logged-out-long-ago"})
        with c.websocket_connect(
            "/api/nodes/ws/status", subprotocols=["bridge-v1", raw]
        ) as ws:
            assert ws.accepted_subprotocol == "bridge-v1"
            assert ws.receive_json()["type"] == "snapshot"

    def test_restricted_cookie_session_is_refused_even_with_a_valid_key(
        self, bridge_app, persistence, detection_store
    ):
        # As at the gateway: a restricted session is refused, not skipped.
        token = _session(detection_store, "pending", scope="password_change_only")
        raw = _add_key(persistence, "k_viewer", "viewer")
        c = TestClient(bridge_app, cookies={"session_token": token})
        with pytest.raises(WebSocketDisconnect) as exc:
            with c.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", raw]
            ):
                pass
        assert exc.value.code == 4003

    def test_no_valid_credential_anywhere_is_refused(self, bridge_app):
        c = TestClient(bridge_app, cookies={"session_token": "logged-out-long-ago"})
        with pytest.raises(WebSocketDisconnect) as exc:
            with c.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", "not-a-key"]
            ):
                pass
        assert exc.value.code == 4001

    def test_zigbee_feed_releases_its_connection_slot(self, bridge_app, master_key):
        with TestClient(bridge_app).websocket_connect(
            "/api/zigbee/ws/zigbee", subprotocols=["bridge-v1", master_key]
        ) as ws:
            assert ws.accepted_subprotocol == "bridge-v1"
        assert deps.get_ws_limiter()._active.get("testclient", 0) == 0


# ---------------------------------------------------------------------------
# B1, B2 / K4 — node binding
# ---------------------------------------------------------------------------


class TestNodeBinding:
    def test_unbound_key_is_bound_on_first_use(self, client, persistence):
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge_key", "sensor")
        assert _heartbeat(client, raw, "n1").status_code == 200
        assert persistence.get_key_meta()["edge_key"]["node_id"] == "n1"
        # Before: an unbound key could heartbeat as any node.
        assert _heartbeat(client, raw, "n2").status_code == 403

    def test_bound_key_cannot_take_another_nodes_commands(self, client, persistence):
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge_key", "node", node_id="n1")
        resp = client.post(
            "/api/nodes/n2/command", json={"command": "restart", "params": {}}
        )
        assert resp.status_code == 200, resp.text
        assert _heartbeat(client, raw, "n2").status_code == 403
        assert len(client.app.state.app_state.pending_commands["n2"]) == 1

    def test_ingest_routes_enforce_the_binding(self, client, persistence):
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge_key", "sensor", node_id="n1")
        h = {"X-API-Key": raw}
        summary = client.post(
            "/api/detections/ingest-summary",
            json={"node_id": "n2", "summaries": []},
            headers=h,
        )
        assert summary.status_code == 403  # before: 201 for any node
        wifi = client.post(
            "/api/wifi/ingest", json={"node_id": "n2", "records": []}, headers=h
        )
        assert wifi.status_code == 403
        bt = client.post(
            "/api/bluetooth/ingest-summary",
            json={"node_id": "n2", "devices": []},
            headers=h,
        )
        assert bt.status_code == 403
        own = client.post(
            "/api/detections/ingest-summary",
            json={"node_id": "n1", "summaries": []},
            headers=h,
        )
        assert own.status_code == 201

    def test_iq_upload_checks_the_node(self, client, persistence, bridge_app):
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge_key", "sensor", node_id="n1")
        store = bridge_app.state.detection_store
        data = gzip.compress(b"\x00" * 64)
        h = {"X-API-Key": raw, "Content-Encoding": "gzip"}
        resp = client.put(
            "/api/detections/iq_other/iq",
            content=data,
            headers={**h, "X-Node-Id": "n2"},
        )
        # Before: the stub's node came from X-Node-Id unchecked.
        assert resp.status_code == 403
        assert store.get_detection_by_id("iq_other") is None
        resp = client.put(
            "/api/detections/iq_mine/iq", content=data, headers={**h, "X-Node-Id": "n1"}
        )
        assert resp.status_code == 201, resp.text
        assert store.get_detection_by_id("iq_mine")["node_id"] == "n1"

    def test_escape_hatch_keeps_unbound_keys_unbound(
        self, client, persistence, monkeypatch
    ):
        monkeypatch.setenv(deps.ALLOW_UNBOUND_NODE_KEYS_ENV, "1")
        _register(client, "n1", "n2")
        raw = _add_key(persistence, "edge_key", "sensor")
        assert _heartbeat(client, raw, "n1").status_code == 200
        assert _heartbeat(client, raw, "n2").status_code == 200
        assert not persistence.get_key_meta()["edge_key"].get("node_id")

    def test_user_sessions_are_not_node_credentials(
        self, client, bridge_app, detection_store
    ):
        _register(client, "n1")
        token = _session(detection_store, "watcher", role="viewer")
        resp = TestClient(bridge_app).post(
            "/api/nodes/heartbeat",
            json={"node_id": "n1"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403

    def test_binding_is_atomic(self, persistence):
        raw = _add_key(persistence, "edge_key", "sensor")
        assert raw
        results: list[str | None] = []
        barrier = threading.Barrier(8)

        def bind(node: str) -> None:
            barrier.wait()
            results.append(persistence.bind_key_to_node("edge_key", node))

        threads = [threading.Thread(target=bind, args=(f"n{i}",)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(set(results)) == 1
        assert persistence.get_key_meta()["edge_key"]["node_id"] == results[0]
        assert persistence.bind_key_to_node("missing", "n1") is None

    def test_staging_smoke_ingest_step(self, bridge_app, persistence):
        """scripts/staging-smoke.sh step 4, as the bridge sees it.

        The scanner key posts a gzipped, empty BT summary for the node it is
        bound to (the script uses BRIDGE_LOCAL_NODE_ID): 201.  For any other
        node (the script used to send "smoke-probe"): 403, which failed the
        smoke and rolled every staging deploy back.
        """
        raw = generate_api_key(32)
        app_module._seed_local_scanner_key(persistence, raw, "edge-a")
        c = TestClient(bridge_app)

        def post(node_id: str):
            body = {
                "node_id": node_id,
                "scan_period_s": 1.0,
                "total_observations": 0,
                "devices": [],
            }
            return c.post(
                "/api/bluetooth/ingest-summary",
                content=gzip.compress(json.dumps(body).encode()),
                headers={
                    "X-API-Key": raw,
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                },
            )

        resp = post("edge-a")
        assert resp.status_code == 201, resp.text
        assert resp.json()["inserted"] == 0
        assert post("smoke-probe").status_code == 403

    def test_scanner_key_seeded_bound_to_its_node(self, persistence):
        raw = generate_api_key(32)
        app_module._seed_local_scanner_key(persistence, raw, "edge-a")
        meta = persistence.get_key_meta()[LOCAL_SCANNER_KEY_ID]
        assert (meta["role"], meta["node_id"]) == ("node", "edge-a")
        # BRIDGE_LOCAL_NODE_ID changed: the binding follows it.
        app_module._seed_local_scanner_key(persistence, raw, "edge-b")
        assert persistence.get_key_meta()[LOCAL_SCANNER_KEY_ID]["node_id"] == "edge-b"


class TestCaptureCommand:
    _BODY = {"freq_hz": 433.92e6}

    def test_sensor_keys_cannot_task_a_node(self, client, persistence):
        _register(client, "n1")
        sensor = _add_key(persistence, "sensor_key", "sensor", node_id="n1")
        analyst = _add_key(persistence, "analyst_key", "analyst")
        resp = client.post(
            "/api/nodes/n1/capture", json=self._BODY, headers={"X-API-Key": sensor}
        )
        assert resp.status_code == 403  # before: SENSOR was enough
        resp = client.post(
            "/api/nodes/n1/capture", json=self._BODY, headers={"X-API-Key": analyst}
        )
        assert resp.status_code == 200

    def test_admin_commands_keep_queue_headroom(self, client, persistence):
        from sigrift.bridge.routers import nodes as nodes_router

        _register(client, "n1")
        analyst = _add_key(persistence, "analyst_key", "analyst")
        deps.set_rate_limiter(deps.RateLimiter(max_requests=10_000))
        limit = nodes_router.command_queue_limit(deps.Role.ANALYST)
        assert limit < nodes_router._MAX_PENDING_COMMANDS_PER_NODE
        for _ in range(limit):
            resp = client.post(
                "/api/nodes/n1/capture",
                json=self._BODY,
                headers={"X-API-Key": analyst},
            )
            assert resp.status_code == 200
        resp = client.post(
            "/api/nodes/n1/capture", json=self._BODY, headers={"X-API-Key": analyst}
        )
        assert resp.status_code == 429
        # The admin can still queue.
        resp = client.post(
            "/api/nodes/n1/command", json={"command": "restart", "params": {}}
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# B7 / K5 — master key rotation and role ceilings
# ---------------------------------------------------------------------------


class TestRoleCeilings:
    def test_other_admins_cannot_rotate_the_master_key(
        self, bridge_app, persistence, master_key
    ):
        admin = TestClient(
            bridge_app,
            headers={"X-API-Key": _add_key(persistence, "ops", "admin")},
        )
        assert admin.put("/api/keys/master/rotate").status_code == 403
        assert admin.post("/api/keys/rotate-master").status_code == 403
        assert admin.delete("/api/keys/master").status_code == 403
        # The master key still works (it was not replaced).
        master = TestClient(bridge_app, headers={"X-API-Key": master_key})
        assert master.get("/api/keys/").status_code == 200

    def test_keymaster_may_rotate_the_master_key(self, bridge_app, persistence):
        km = TestClient(
            bridge_app,
            headers={"X-API-Key": _add_key(persistence, "km", "keymaster")},
        )
        assert km.post("/api/keys/rotate-master").status_code == 200

    def test_admin_cannot_reach_above_its_role(self, bridge_app, persistence):
        km_raw = _add_key(persistence, "km", "keymaster")
        km_hash = persistence.get_key_store()["km"]
        # A real https request: X-Forwarded-Proto from this untrusted test
        # peer is ignored, so a header-faked TLS request would be refused
        # by the TLS guard before the role ceiling is ever checked.
        admin = TestClient(
            bridge_app,
            base_url="https://testserver",
            headers={"X-API-Key": _add_key(persistence, "ops", "admin")},
        )

        def refused_by_ceiling(resp) -> None:
            # 403 alone is not enough: the TLS guard or another check could
            # produce it. The detail names the ceiling (K5).
            assert resp.status_code == 403, resp.text
            assert "above your own role" in resp.json()["detail"], resp.text

        refused_by_ceiling(admin.post("/api/admin/keys", json={"role": "keymaster"}))
        refused_by_ceiling(admin.put("/api/keys/km/rotate"))
        refused_by_ceiling(admin.post("/api/admin/keys/km/rotate", json={}))
        refused_by_ceiling(admin.delete("/api/admin/keys/km"))
        refused_by_ceiling(admin.delete("/api/keys/km"))
        refused_by_ceiling(
            admin.put("/api/admin/keys/km/permissions", json={"role": "viewer"})
        )
        # The keymaster key is untouched: same credential, same role.
        assert persistence.get_key_store()["km"] == km_hash
        assert persistence.get_key_meta()["km"]["role"] == "keymaster"
        km = TestClient(bridge_app, headers={"X-API-Key": km_raw})
        assert km.get("/api/keys/").status_code == 200

    def test_admin_may_rotate_a_key_within_its_role_over_tls(
        self, bridge_app, persistence
    ):
        # Control for the test above: the same https request on a key the
        # admin can reach gets past the TLS guard and the ceiling.
        _add_key(persistence, "an", "analyst")
        admin = TestClient(
            bridge_app,
            base_url="https://testserver",
            headers={"X-API-Key": _add_key(persistence, "ops", "admin")},
        )
        resp = admin.post("/api/admin/keys/an/rotate", json={})
        assert resp.status_code == 200, resp.text
        assert resp.json().get("raw_key")

    def test_admin_created_key_keeps_its_node(self, client, persistence):
        resp = client.post(
            "/api/admin/keys", json={"role": "node", "node_id": "edge-7"}
        )
        assert resp.status_code == 201, resp.text
        key_id = resp.json()["key_id"]
        assert persistence.get_key_meta()[key_id]["node_id"] == "edge-7"
        bad = client.post("/api/admin/keys", json={"role": "node", "node_id": "a b"})
        assert bad.status_code == 400


# ---------------------------------------------------------------------------
# B8 — CSV formula injection
# ---------------------------------------------------------------------------


class TestCsvExport:
    @pytest.mark.parametrize(
        ("cell", "expected"),
        [
            ('=HYPERLINK("http://x","y")', '\'=HYPERLINK("http://x","y")'),
            ("+cmd", "'+cmd"),
            ("-2+3", "'-2+3"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tx", "'\tx"),
            ("\rx", "'\rx"),
            ("-85.5", "-85.5"),
            ("+3", "+3"),
            ("plain", "plain"),
            (-85.5, -85.5),
            (None, None),
        ],
    )
    def test_cells_are_neutralised(self, cell, expected):
        from sigrift.bridge.routers.export import _csv_safe

        assert _csv_safe(cell) == expected

    def test_export_neutralises_over_the_air_text(self, client):
        resp = client.post(
            "/api/nodes/register",
            json={"node_id": "n1", "host": "=cmd|' /C calc'!A0"},
        )
        assert resp.status_code == 200
        csv_text = client.get("/api/export/nodes?format=csv").text
        assert "'=cmd|" in csv_text
        assert ",=cmd" not in csv_text


# ---------------------------------------------------------------------------
# B10 — malformed input is a 4xx, not a 500
# ---------------------------------------------------------------------------


class TestMalformedInput:
    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Freq-Hz": "abc", "X-Node-Id": "n1"},
            {"X-Sample-Rate": "nan", "X-Node-Id": "n1"},
            {"X-IQ-Samples": "-4", "X-Node-Id": "n1"},
            {"X-Node-Id": "../etc"},
        ],
    )
    def test_bad_iq_headers_are_400_and_write_nothing(
        self, client, bridge_app, headers
    ):
        _register(client, "n1")
        resp = client.put("/api/detections/iq_bad/iq", content=b"x", headers=headers)
        assert resp.status_code == 400, resp.text
        assert bridge_app.state.detection_store.get_detection_by_id("iq_bad") is None

    @pytest.mark.parametrize("detection_id", ["a.b", "%21%21", "x" * 129])
    def test_bad_iq_ids_are_400_and_write_nothing(
        self, client, bridge_app, detection_id
    ):
        resp = client.put(
            f"/api/detections/{detection_id}/iq",
            content=b"x",
            headers={"X-Node-Id": "n1"},
        )
        assert resp.status_code == 400, resp.text
        assert not any(bridge_app.state.iq_store._base_dir.glob("*.iq.gz"))

    def test_unknown_bundle_component_is_400(self, client):
        resp = client.post("/api/admin/presets/urban-dense/apply?components=rf,bogus")
        assert resp.status_code == 400
        assert "bogus" in resp.json()["detail"]

    @pytest.mark.parametrize("body", ["[1, 2]", '"x"', "not json", '{"value": {}}'])
    def test_runtime_config_rejects_bad_bodies(self, client, body):
        resp = client.put(
            "/api/admin/runtime-config/BRIDGE_LOG_LEVEL",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_runtime_config_does_not_claim_persistence(self, client, monkeypatch):
        monkeypatch.setenv("BRIDGE_LOG_LEVEL", "INFO")
        resp = client.put(
            "/api/admin/runtime-config/BRIDGE_LOG_LEVEL", json={"value": "DEBUG"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["persisted"] is False
        # Before: "Takes full effect on next restart" — but a restart
        # reverts the change (only os.environ was edited).
        assert "takes full effect" not in body["note"].lower()
        assert "reverts" in body["note"]


# ---------------------------------------------------------------------------
# B11 — classifier endpoints
# ---------------------------------------------------------------------------


class TestClassifierBounds:
    def test_oversized_iq_is_rejected_before_any_work(self, client):
        n = 65537
        resp = client.post(
            "/api/edge-models/classify/iq",
            json={"iq_real": [0.0] * n, "iq_imag": [0.0] * n},
        )
        assert resp.status_code == 422  # before: no bound

    def test_training_parameters_are_bounded(self):
        from pydantic import ValidationError

        from sigrift.bridge.routers.edge_models import TrainRequest

        for bad in ({"epochs": 10**6}, {"samples_per_class": 10**7}, {"lr": -1.0}):
            with pytest.raises(ValidationError):
                TrainRequest(**bad)
        TrainRequest()

    def test_inference_runs_off_the_event_loop(self, client, bridge_app, monkeypatch):
        from sigrift.bridge.routers import edge_models
        from sigrift.lib.dsp.family_classifier import LightweightClassifier

        model = LightweightClassifier()
        bridge_app.state.family_classifier = model
        seen: list[bool] = []
        real = edge_models._classify_features

        def spy(*args):
            try:
                asyncio.get_running_loop()
                seen.append(True)
            except RuntimeError:
                seen.append(False)
            return real(*args)

        monkeypatch.setattr(edge_models, "_classify_features", spy)
        resp = client.post(
            "/api/edge-models/classify", json={"features": [0.1] * model.input_dim}
        )
        assert resp.status_code == 200, resp.text
        assert seen == [False]

    def test_busy_classifier_is_503(self, client, bridge_app, monkeypatch):
        from sigrift.bridge.routers import edge_models
        from sigrift.lib.dsp.family_classifier import LightweightClassifier

        model = LightweightClassifier()
        bridge_app.state.family_classifier = model
        monkeypatch.setattr(edge_models, "_inference_slots", asyncio.Semaphore(0))
        resp = client.post(
            "/api/edge-models/classify", json={"features": [0.1] * model.input_dim}
        )
        assert resp.status_code == 503


# ---------------------------------------------------------------------------
# G11 (bridge side) — no JS depends on a readable session cookie
# ---------------------------------------------------------------------------


class TestNoReadableSessionCookie:
    def test_frontend_never_reads_bridge_token(self):
        for path in (*_STATIC.glob("*.js"), _STATIC.parent / "templates/index.html"):
            assert "bridge_token=" not in path.read_text(encoding="utf-8"), path

    def test_websockets_work_in_cookie_mode(self):
        js = (_STATIC / "dashboard.js").read_text(encoding="utf-8")
        assert "!self._cookieAuth) return;" in js
        assert "_wsProtocols" in js
        zigbee = (_STATIC / "zigbee.js").read_text(encoding="utf-8")
        assert "?api_key=" not in zigbee
