"""Authenticated principals cannot cross the configured instance/store boundary."""

from __future__ import annotations

import pytest
from fastapi import WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.lib.security.credentials import generate_api_key, hash_credential


@pytest.fixture(autouse=True)
def _ws_check_every_payload(monkeypatch):
    """These boundary tests revoke and send at once; check before every payload."""
    monkeypatch.setenv("BRIDGE_WS_REVALIDATE_SECONDS", "0")


@pytest.fixture(params=["session", "api_key"])
def tenant_actor(request, bridge_app, detection_store, persistence):
    """Real credentials issued for a different tenant, never auth overrides."""
    if request.param == "session":
        other = DetectionStore(detection_store.db_path, tenant_id="other")
        try:
            other.create_user("other-admin", "only-a-test-password", role="admin")
            user = other.get_user("other-admin")
            credential = other.create_session(user["id"])["session_token"]
        finally:
            other.close()
        headers = {"Authorization": "Bearer " + credential}
    else:
        credential = generate_api_key(length=32)
        digest, salt = hash_credential(credential)
        persistence.set_key("other-admin-key", digest, salt)
        persistence.set_key_meta(
            "other-admin-key", {"role": "admin", "tenant_id": "other"}
        )
        headers = {"X-API-Key": credential}
    with TestClient(bridge_app, headers=headers) as actor:
        yield actor


def test_foreign_principal_cannot_read_stored_detection(tenant_actor, detection_store):
    detection_store.insert_batch(
        [
            DetectionRecord(
                id="private-local",
                node_id="local",
                signal_class="bpsk",
                freq_hz=400e6,
                confidence=0.9,
            )
        ]
    )
    response = tenant_actor.get("/api/detections/private-local")
    assert response.status_code in {401, 403}


def test_foreign_principal_cannot_read_instance_configuration(tenant_actor):
    response = tenant_actor.get("/api/admin/config")
    assert response.status_code in {401, 403}


def test_foreign_principal_cannot_mutate_instance_alert_rules(
    tenant_actor, persistence
):
    before = persistence.get_alert_rules()
    response = tenant_actor.post(
        "/api/alerts/rules/conditions",
        json={
            "name": "foreign mutation",
            "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
            "cooldown_seconds": 0,
        },
    )
    assert response.status_code in {401, 403}
    assert persistence.get_alert_rules() == before


def test_foreign_principal_cannot_join_live_feed(tenant_actor):
    with pytest.raises(WebSocketDisconnect) as refused:
        with tenant_actor.websocket_connect("/api/detections/ws/feed"):
            pytest.fail("A different tenant's principal joined the instance feed")
    assert refused.value.code in {4001, 4003}


def test_legacy_local_key_still_reads_writes_and_streams(client, detection_store):
    detection_store.insert_batch(
        [
            DetectionRecord(
                id="local-control",
                node_id="local",
                signal_class="bpsk",
                freq_hz=400e6,
                confidence=0.9,
            )
        ]
    )
    assert client.get("/api/detections/local-control").status_code == 200
    assert client.get("/api/admin/config").status_code == 200
    assert (
        client.post(
            "/api/alerts/rules/conditions",
            json={
                "name": "local mutation",
                "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
                "cooldown_seconds": 0,
            },
        ).status_code
        == 201
    )
    with client.websocket_connect("/api/detections/ws/feed") as websocket:
        websocket.close()


def test_foreign_principal_rejected_by_proxy_middleware(tenant_actor):
    assert tenant_actor.get("/api/detections/recent").status_code == 403
    assert (
        tenant_actor.post(
            "/api/detections/batch", json={"node_id": "local", "detections": []}
        ).status_code
        == 403
    )


def test_valid_foreign_session_does_not_fall_through_to_local_key(
    bridge_app, detection_store, master_key
):
    other = DetectionStore(detection_store.db_path, tenant_id="other")
    try:
        other.create_user("precedence-other", "fixture-password-long", role="admin")
        user = other.get_user("precedence-other")
        token = other.create_session(user["id"])["session_token"]
    finally:
        other.close()
    with TestClient(
        bridge_app,
        headers={"Authorization": "Bearer " + token, "X-API-Key": master_key},
    ) as actor:
        assert actor.get("/api/admin/config").status_code == 403
        with pytest.raises(WebSocketDisconnect) as refused:
            with actor.websocket_connect("/api/detections/ws/feed"):
                pytest.fail("Foreign principal fell through to a local secondary key")
        assert refused.value.code == 4003


@pytest.mark.parametrize("tenant", [None, "", 7, []])
def test_explicit_malformed_key_tenant_is_not_legacy_absence(
    bridge_app, persistence, tenant
):
    raw = generate_api_key(length=32)
    digest, salt = hash_credential(raw)
    persistence.set_key("malformed-scope", digest, salt)
    persistence.set_key_meta("malformed-scope", {"role": "admin", "tenant_id": tenant})
    with TestClient(bridge_app, headers={"X-API-Key": raw}) as actor:
        assert actor.get("/api/admin/config").status_code == 403
        with pytest.raises(WebSocketDisconnect) as refused:
            with actor.websocket_connect("/api/detections/ws/feed"):
                pytest.fail("Malformed explicit tenant joined instance feed")
        assert refused.value.code == 4003


def test_foreign_subprotocol_credentials_are_refused(tenant_actor, bridge_app):
    raw = tenant_actor.headers.get("x-api-key") or tenant_actor.headers[
        "authorization"
    ].removeprefix("Bearer ")
    with TestClient(bridge_app) as actor:
        with pytest.raises(WebSocketDisconnect) as refused:
            with actor.websocket_connect(
                "/api/detections/ws/feed", subprotocols=["bridge-v1", raw]
            ):
                pytest.fail("Foreign subprotocol credential joined instance feed")
        assert refused.value.code == 4003


def test_foreign_session_and_mfa_challenge_are_not_touched_or_consumed(
    bridge_app, detection_store
):
    other = DetectionStore(detection_store.db_path, tenant_id="other")
    try:
        other.create_user("state-other", "fixture-password-long", role="admin")
        user = other.get_user("state-other")
        token = other.create_session(user["id"])["session_token"]
        challenge = other.users.create_mfa_token(user["id"])
        conn = other.get_connection()
        conn.execute(
            "UPDATE sessions SET last_active='2026-01-01T00:00:00+00:00' WHERE user_id=?",
            (user["id"],),
        )
        conn.commit()
        before = [
            tuple(row)
            for row in conn.execute(
                "SELECT * FROM sessions WHERE user_id=?", (user["id"],)
            )
        ]
        with TestClient(
            bridge_app, headers={"Authorization": "Bearer " + token}
        ) as actor:
            assert actor.get("/api/admin/config").status_code == 403
            assert actor.post("/api/auth/logout").status_code == 401
        assert detection_store.get_session(token) is None
        assert not detection_store.delete_session(token)
        assert detection_store.users.verify_mfa_token(challenge) is None
        assert [
            tuple(row)
            for row in conn.execute(
                "SELECT * FROM sessions WHERE user_id=?", (user["id"],)
            )
        ] == before
        assert other.users.verify_mfa_token(challenge) == user["id"]
    finally:
        other.close()


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/api/wifi/device-clusters", None),
        ("GET", "/api/wifi/device-clusters/foreign-cluster", None),
        ("GET", "/api/wifi/device-clusters/foreign-cluster/timeline", None),
        ("GET", "/api/wifi/fingerprint-stats", None),
        ("POST", "/api/wifi/identify", {"ie_fingerprint": "private-ie"}),
    ],
)
def test_wifi_query_cannot_select_another_tenant(
    client, bridge_app, method, path, body
):
    bridge_app.state.wifi_cluster_store.upsert_cluster(
        "foreign-cluster",
        "private-ie",
        tenant_id="other",
        mac_addresses=["02:00:00:00:00:01"],
    )
    response = client.request(method, path + "?tenant_id=other", json=body)
    assert response.status_code == 403
    assert "private-ie" not in response.text


@pytest.mark.parametrize("kind", ["session", "api_key"])
@pytest.mark.parametrize("change", ["foreign", "revoked", "expired", "unchanged"])
def test_established_socket_checks_original_principal_before_each_payload(
    bridge_app, detection_store, persistence, master_key, kind, change
):
    if kind == "session":
        detection_store.create_user(
            "live-local", "fixture-password-long", role="viewer"
        )
        user = detection_store.get_user("live-local")
        token = detection_store.create_session(user["id"])["session_token"]
        headers = {"Authorization": "Bearer " + token, "X-API-Key": master_key}
    else:
        token = generate_api_key(length=32)
        digest, salt = hash_credential(token)
        persistence.set_key("live-local", digest, salt)
        persistence.set_key_meta(
            "live-local", {"role": "viewer", "tenant_id": "default"}
        )
        headers = {"X-API-Key": token}
    with TestClient(bridge_app, headers=headers) as actor:
        with actor.websocket_connect("/api/detections/ws/feed") as socket:
            socket.send_text("ping")
            assert socket.receive_text() == "pong"
            actor.portal.call(
                bridge_app.state.app_state.ws_detection_clients.broadcast,
                {"sample": "before"},
            )
            assert socket.receive_json() == {"sample": "before"}
            if kind == "session":
                if change == "revoked":
                    detection_store.delete_session(token)
                elif change != "unchanged":
                    conn = detection_store.get_connection()
                    if change == "foreign":
                        conn.execute(
                            "UPDATE users SET tenant_id='other' WHERE id=?",
                            (user["id"],),
                        )
                    else:
                        conn.execute(
                            "UPDATE sessions SET expires_at='2000-01-01T00:00:00+00:00' WHERE user_id=?",
                            (user["id"],),
                        )
                    conn.commit()
            elif change == "revoked":
                persistence.remove_key("live-local")
            elif change != "unchanged":
                meta = {
                    "role": "viewer",
                    "tenant_id": "other" if change == "foreign" else "default",
                }
                if change == "expired":
                    meta["expires_at"] = "2000-01-01T00:00:00+00:00"
                persistence.set_key_meta("live-local", meta)
            actor.portal.call(
                bridge_app.state.app_state.ws_detection_clients.broadcast,
                {"sample": "after"},
            )
            if change == "unchanged":
                assert socket.receive_json() == {"sample": "after"}
            else:
                with pytest.raises(WebSocketDisconnect) as refused:
                    socket.receive_json()
                assert refused.value.code in {4001, 4003}


@pytest.mark.parametrize("kind", ["session", "api_key"])
@pytest.mark.parametrize("role", ["viewer", "analyst", "admin"])
def test_same_instance_principal_keeps_actual_role_permissions(
    bridge_app, detection_store, persistence, kind, role
):
    if kind == "session":
        detection_store.create_user("local-role", "fixture-password-long", role=role)
        user = detection_store.get_user("local-role")
        token = detection_store.create_session(user["id"])["session_token"]
        headers = {"Authorization": "Bearer " + token}
    else:
        token = generate_api_key(length=32)
        digest, salt = hash_credential(token)
        persistence.set_key("local-role", digest, salt)
        persistence.set_key_meta("local-role", {"role": role, "tenant_id": "default"})
        headers = {"X-API-Key": token}
    with TestClient(bridge_app, headers=headers) as actor:
        assert actor.get("/api/detections/count").status_code == 200
        assert actor.get("/api/admin/config").status_code == (
            200 if role == "admin" else 403
        )
        response = actor.post(
            "/api/alerts/rules/conditions",
            json={
                "name": "local role test",
                "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
                "cooldown_seconds": 0,
            },
        )
        assert response.status_code == (403 if role == "viewer" else 201)
        with actor.websocket_connect("/api/detections/ws/feed") as socket:
            socket.send_text("ping")
            assert socket.receive_text() == "pong"


def test_cookie_session_preserves_double_submit_csrf_and_logout(
    bridge_app, detection_store, monkeypatch
):
    monkeypatch.setenv("BRIDGE_CSRF", "enabled")
    detection_store.create_user("cookie-local", "TestPass123!", role="admin")
    with TestClient(bridge_app) as actor:
        login = actor.post(
            "/api/auth/login",
            json={"username": "cookie-local", "password": "TestPass123!"},
        )
        assert login.status_code == 200
        token = login.json()["session_token"]
        csrf = login.json()["csrf_token"]
        actor.cookies.set("session_token", token)
        assert actor.get("/api/admin/config").status_code == 200
        body = {
            "name": "cookie rule",
            "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
            "cooldown_seconds": 0,
        }
        assert actor.post("/api/alerts/rules/conditions", json=body).status_code == 403
        assert (
            actor.post(
                "/api/alerts/rules/conditions",
                json=body,
                headers={"X-CSRF-Token": "wrong"},
            ).status_code
            == 403
        )
        assert (
            actor.post(
                "/api/alerts/rules/conditions",
                json=body,
                headers={"X-CSRF-Token": csrf},
            ).status_code
            == 201
        )
        assert actor.post("/api/auth/logout").status_code == 200
        assert actor.get("/api/admin/config").status_code == 401
        assert detection_store.get_session(token) is None


@pytest.mark.parametrize("payload", ["text", "json", "bytes"])
def test_guard_covers_asgi_payload_types_and_permitted_role_downgrade(
    bridge_app, persistence, payload
):
    from sigrift.bridge.dependencies import require_ws_auth

    @bridge_app.websocket("/tenant-test-payload")
    async def stream(socket: WebSocket):
        await require_ws_auth(socket)
        await socket.accept()
        try:
            while True:
                command = await socket.receive_text()
                if command == "close":
                    await socket.close(code=1000)
                    break
                if payload == "bytes":
                    await socket.send_bytes(b"fixture")
                elif payload == "json":
                    await socket.send_json({"fixture": True})
                else:
                    await socket.send_text("fixture")
        except WebSocketDisconnect:
            pass

    token = generate_api_key(length=32)
    digest, salt = hash_credential(token)
    persistence.set_key("payload-local", digest, salt)
    persistence.set_key_meta("payload-local", {"role": "admin"})
    with TestClient(bridge_app, headers={"X-API-Key": token}) as actor:
        with actor.websocket_connect("/tenant-test-payload") as socket:
            receive = getattr(socket, "receive_" + payload)
            expected = (
                b"fixture"
                if payload == "bytes"
                else {"fixture": True}
                if payload == "json"
                else "fixture"
            )
            socket.send_text("next")
            assert receive() == expected
            persistence.set_key_meta("payload-local", {"role": "viewer"})
            socket.send_text("next")
            assert receive() == expected  # Still sufficient for this endpoint.
            persistence.set_key_meta("payload-local", {"role": "sensor"})
            socket.send_text("next")
            with pytest.raises(WebSocketDisconnect) as refused:
                receive()
            assert refused.value.code == 4003
        persistence.set_key_meta("payload-local", {"role": "viewer"})
        with actor.websocket_connect("/tenant-test-payload") as socket:
            socket.send_text("close")
            with pytest.raises(WebSocketDisconnect) as closed:
                socket.receive_text()
            assert closed.value.code == 1000
        # Receiver disconnect exits the same real route without a send recursion.
        with actor.websocket_connect("/tenant-test-payload") as socket:
            socket.close()


def test_database_read_failure_closes_stream_and_recovery_allows_new_connection(
    bridge_app, detection_store
):
    detection_store.create_user("db-retry", "fixture-password-long", role="viewer")
    user = detection_store.get_user("db-retry")
    token = detection_store.create_session(user["id"])["session_token"]
    conn = detection_store.get_connection()
    with TestClient(bridge_app, headers={"Authorization": "Bearer " + token}) as actor:
        with actor.websocket_connect("/api/detections/ws/feed") as socket:
            socket.send_text("ping")
            assert socket.receive_text() == "pong"
            # A real SQLite schema outage, not a fabricated auth result.
            conn.execute("ALTER TABLE sessions RENAME TO unavailable_sessions")
            conn.commit()
            try:
                actor.portal.call(
                    bridge_app.state.app_state.ws_detection_clients.broadcast,
                    {"must_not_arrive": True},
                )
                with pytest.raises(WebSocketDisconnect) as refused:
                    socket.receive_json()
                assert refused.value.code == 1011
                assert refused.value.reason == "Credential validation unavailable"
            finally:
                conn.execute("ALTER TABLE unavailable_sessions RENAME TO sessions")
                conn.commit()
        # Recovery needs a new authenticated connection; no global failure latch.
        with actor.websocket_connect("/api/detections/ws/feed") as socket:
            socket.send_text("ping")
            assert socket.receive_text() == "pong"


@pytest.mark.asyncio
async def test_concurrent_payloads_revalidate_after_waiting_for_transport(
    bridge_app, persistence
):
    import asyncio

    from sigrift.bridge.dependencies import get_ws_limiter, require_ws_auth

    raw = generate_api_key(length=32)
    digest, salt = hash_credential(raw)
    persistence.set_key("concurrent-local", digest, salt)
    persistence.set_key_meta("concurrent-local", {"role": "viewer"})
    entered = asyncio.Event()
    release = asyncio.Event()
    delivered = []

    async def receive():
        return {"type": "websocket.connect"}

    async def transport(message):
        if message["type"] == "websocket.send":
            entered.set()
            await release.wait()
        delivered.append(message)

    websocket = WebSocket(
        {
            "type": "websocket",
            "app": bridge_app,
            "headers": [(b"x-api-key", raw.encode())],
            "query_string": b"",
            "client": ("127.0.0.42", 40000),
        },
        receive,
        transport,
    )
    await require_ws_auth(websocket)
    first = second = None
    try:
        await websocket.accept()
        first = asyncio.create_task(websocket.send_text("already authorized"))
        await asyncio.wait_for(entered.wait(), 2)
        second = asyncio.create_task(websocket.send_bytes(b"must not arrive"))
        persistence.remove_key("concurrent-local")
        release.set()
        await asyncio.wait_for(first, 2)
        with pytest.raises(WebSocketDisconnect):
            await asyncio.wait_for(second, 2)
        with pytest.raises(WebSocketDisconnect):
            await websocket.send_json({"also_forbidden": True})
        assert [m for m in delivered if m["type"] == "websocket.send"] == [
            {"type": "websocket.send", "text": "already authorized"}
        ]
        closes = [m for m in delivered if m["type"] == "websocket.close"]
        assert len(closes) == 1
        assert closes[0]["code"] == 4001
    finally:
        release.set()
        for task in (first, second):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(*(t for t in (first, second) if t), return_exceptions=True)
        get_ws_limiter().release(websocket.state.ws_client_ip)


@pytest.mark.asyncio
async def test_payload_burst_reuses_one_credential_check_per_interval(
    bridge_app, persistence, monkeypatch
):
    from sigrift.bridge import dependencies
    from sigrift.bridge.dependencies import get_ws_limiter, require_ws_auth

    monkeypatch.setenv("BRIDGE_WS_REVALIDATE_SECONDS", "1")
    clock = [1000.0]
    monkeypatch.setattr(dependencies.time, "monotonic", lambda: clock[0])
    checks = []
    original = dependencies._revalidate_ws_principal

    async def counted(*args):
        checks.append(clock[0])
        return await original(*args)

    monkeypatch.setattr(dependencies, "_revalidate_ws_principal", counted)
    raw = generate_api_key(length=32)
    digest, salt = hash_credential(raw)
    persistence.set_key("burst-local", digest, salt)
    persistence.set_key_meta("burst-local", {"role": "viewer"})
    delivered = []

    async def receive():
        return {"type": "websocket.connect"}

    async def transport(message):
        delivered.append(message)

    websocket = WebSocket(
        {
            "type": "websocket",
            "app": bridge_app,
            "headers": [(b"x-api-key", raw.encode())],
            "query_string": b"",
            "client": ("127.0.0.43", 40000),
        },
        receive,
        transport,
    )
    await require_ws_auth(websocket)
    try:
        await websocket.accept()
        for i in range(50):
            await websocket.send_text(f"frame {i}")
        assert len(checks) == 1
        persistence.remove_key("burst-local")
        clock[0] += 1.0
        with pytest.raises(WebSocketDisconnect):
            await websocket.send_text("after revocation")
        assert len(checks) == 2
        sent = [m for m in delivered if m["type"] == "websocket.send"]
        assert len(sent) == 50
        assert [m["code"] for m in delivered if m["type"] == "websocket.close"] == [
            4001
        ]
    finally:
        get_ws_limiter().release(websocket.state.ws_client_ip)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, 1.0),
        ("0", 0.0),
        ("2.5", 2.5),
        ("-1", 0.0),
        ("999", 30.0),
        ("x", 1.0),
        ("nan", 1.0),
    ],
)
def test_ws_revalidate_interval_is_bounded(monkeypatch, raw, expected):
    from sigrift.bridge.dependencies import _ws_revalidate_interval

    if raw is None:
        monkeypatch.delenv("BRIDGE_WS_REVALIDATE_SECONDS", raising=False)
    else:
        monkeypatch.setenv("BRIDGE_WS_REVALIDATE_SECONDS", raw)
    assert _ws_revalidate_interval() == expected


def test_nondefault_instance_binds_keys_sessions_and_wifi_queries_to_its_store(
    tmp_path, persistence, app_state, master_key
):
    from sigrift.bridge.app import create_test_app

    local = DetectionStore(tmp_path / "scoped.db", tenant_id="private-instance")
    default = DetectionStore(local.db_path)
    try:
        local.create_user("private-owner", "fixture-password-long", role="admin")
        user = local.get_user("private-owner")
        token = local.create_session(user["id"])["session_token"]
        default.create_user("default-owner", "fixture-password-long", role="admin")
        foreign_user = default.get_user("default-owner")
        foreign = default.create_session(foreign_user["id"])["session_token"]
        app = create_test_app(
            tmp_path=tmp_path,
            detection_store=local,
            persistence=persistence,
            app_state=app_state,
            master_key=master_key,
        )
        for headers in (
            {"Authorization": "Bearer " + token},
            {"X-API-Key": master_key},  # Legacy absence means this instance.
        ):
            with TestClient(app, headers=headers) as actor:
                assert actor.get("/api/admin/config").status_code == 200
                assert (
                    actor.get(
                        "/api/wifi/device-clusters?tenant_id=private-instance",
                        headers={"X-Tenant-ID": "default"},
                    ).status_code
                    == 200
                )
                assert (
                    actor.get("/api/wifi/device-clusters?tenant_id=default").status_code
                    == 403
                )
                with actor.websocket_connect("/api/detections/ws/feed") as socket:
                    socket.send_text("ping")
                    assert socket.receive_text() == "pong"
        with TestClient(app, headers={"Authorization": "Bearer " + foreign}) as actor:
            assert actor.get("/api/admin/config").status_code == 403
        assert local.tenant_id == "private-instance"
    finally:
        default.close()
        local.close()


@pytest.mark.parametrize("source", ["bearer", "cookie", "x-session-token"])
@pytest.mark.parametrize("foreign", [True, False])
def test_proxy_gate_preserves_session_precedence_before_external_transport(
    bridge_app, detection_store, master_key, monkeypatch, source, foreign
):
    import sigrift.bridge.app as app_module
    from starlette.responses import JSONResponse

    other = DetectionStore(detection_store.db_path, tenant_id="other")
    forwarded = []

    async def upstream(scope, receive, send, **kwargs):
        # Only replace the external upstream boundary; real middleware/auth runs.
        forwarded.append(scope["path"])
        await JSONResponse({"upstream": True})(scope, receive, send)
        return True

    monkeypatch.setattr(app_module, "_proxy_to_uppercrust", upstream)
    try:
        other.create_user("proxy-other", "fixture-password-long", role="viewer")
        user = other.get_user("proxy-other")
        token = (
            other.create_session(user["id"])["session_token"]
            if foreign
            else "invalid-old-session"
        )
        headers = {"X-API-Key": master_key}
        if source == "bearer":
            headers["Authorization"] = "Bearer " + token
        elif source == "cookie":
            headers["Cookie"] = "session_token=" + token
        else:
            headers["X-Session-Token"] = token
        with TestClient(bridge_app, headers=headers) as actor:
            response = actor.get("/api/detections/recent")
        assert response.status_code == (403 if foreign else 200)
        assert forwarded == ([] if foreign else ["/api/detections/recent"])
    finally:
        other.close()


@pytest.mark.parametrize(
    "missing_or_invalid", [{}, {"tenant_id": None}, {"tenant_id": ""}, {"tenant_id": 4}]
)
def test_configured_store_without_valid_tenant_fails_closed(missing_or_invalid):
    from types import SimpleNamespace
    from starlette.requests import HTTPConnection
    from sigrift.bridge.dependencies import instance_tenant

    conn = HTTPConnection(
        {
            "type": "http",
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    detection_store=SimpleNamespace(**missing_or_invalid)
                )
            ),
        }
    )
    with pytest.raises(RuntimeError, match="Invalid configured store tenant"):
        instance_tenant(conn)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_ws_validation_timeout_and_cancellation_do_not_deliver_payload(
    bridge_app, detection_store, monkeypatch, cancel
):
    import asyncio
    import threading
    from sigrift.bridge.dependencies import get_ws_limiter, require_ws_auth

    detection_store.create_user("slow-store", "fixture-password-long", role="viewer")
    user = detection_store.get_user("slow-store")
    token = detection_store.create_session(user["id"])["session_token"]
    delivered = []

    async def receive():
        return {"type": "websocket.connect"}

    async def transport(message):
        delivered.append(message)

    websocket = WebSocket(
        {
            "type": "websocket",
            "app": bridge_app,
            "headers": [(b"authorization", ("Bearer " + token).encode())],
            "query_string": b"",
            "client": ("127.0.0.43", 40000),
        },
        receive,
        transport,
    )
    await require_ws_auth(websocket)
    await websocket.accept()
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    original = detection_store.users.session_tenant

    def delayed_database_read(value):
        # Deterministic storage-latency fault injection; release executes the
        # real SQLite query. No fabricated authentication verdict or clock.
        entered.set()
        try:
            if not release.wait(8):
                raise TimeoutError("Fixture storage wait exceeded")
            return original(value)
        finally:
            finished.set()

    monkeypatch.setattr(detection_store.users, "session_tenant", delayed_database_read)
    task = asyncio.create_task(websocket.send_text("must not arrive"))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(WebSocketDisconnect) as refused:
                await asyncio.wait_for(task, 7)
            assert refused.value.code == 1011
        assert not any(m["type"] == "websocket.send" for m in delivered)
        closes = [m for m in delivered if m["type"] == "websocket.close"]
        assert len(closes) == (0 if cancel else 1)
        if closes:
            assert closes[0]["reason"] == "Credential validation unavailable"
    finally:
        release.set()
        assert await asyncio.to_thread(finished.wait, 2)
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        get_ws_limiter().release(websocket.state.ws_client_ip)
    if cancel:
        # Cancellation is not an auth refusal latch and does not prevent the
        # application's normal shutdown close transition.
        await websocket.close(code=1000)
        assert delivered[-1] == {"type": "websocket.close", "code": 1000, "reason": ""}


@pytest.mark.asyncio
@pytest.mark.parametrize("writer", ["same_process", "other_worker"])
@pytest.mark.parametrize("phase", ["verification", "legacy_upgrade"])
@pytest.mark.parametrize(
    "change", ["foreign", "revoked", "rotated", "role", "unchanged"]
)
async def test_key_verification_rechecks_current_matching_credential_and_metadata(
    detection_store, persistence, monkeypatch, change, phase, writer
):
    import asyncio
    import threading
    from types import SimpleNamespace
    from fastapi import HTTPException
    from starlette.requests import HTTPConnection
    import sigrift.bridge.dependencies as deps
    from sigrift.lib.security.credentials import compute_lookup_hash

    raw = generate_api_key(length=32)
    digest, salt = hash_credential(raw)
    persistence.set_key(
        "race-key",
        digest,
        salt,
        lookup_hash=compute_lookup_hash(raw) if phase == "verification" else None,
    )
    persistence.set_key_meta("race-key", {"role": "viewer", "tenant_id": "default"})
    replacement = generate_api_key(length=32)
    replacement_hash, replacement_salt = hash_credential(replacement)
    if writer == "other_worker":
        from sigrift.bridge.persistence import PersistenceManager

        updater = PersistenceManager(
            data_dir=persistence._data_dir, auto_save_interval=0
        )
        updater.load_all()
    else:
        updater = persistence
    conn = HTTPConnection(
        {
            "type": "http",
            "app": SimpleNamespace(
                state=SimpleNamespace(
                    detection_store=detection_store, persistence=persistence
                )
            ),
        }
    )
    entered, release = threading.Event(), threading.Event()
    target = (
        "verify_credential" if phase == "verification" else "upgrade_legacy_credential"
    )
    original = getattr(deps, target)

    def verify_after_concurrent_change(*args):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("Fixture verification wait exceeded")
        return original(*args)

    deps._verified_key_cache.clear()
    monkeypatch.setattr(deps, target, verify_after_concurrent_change)
    task = asyncio.create_task(deps._authenticate_api_key(raw, persistence, conn))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        if change == "foreign":
            updater.set_key_meta("race-key", {"role": "viewer", "tenant_id": "other"})
        elif change == "revoked":
            updater.remove_key("race-key")
        elif change == "rotated":
            updater.set_key(
                "race-key",
                replacement_hash,
                replacement_salt,
                lookup_hash=compute_lookup_hash(replacement),
            )
        elif change == "role":
            updater.set_key_meta("race-key", {"role": "sensor", "tenant_id": "default"})
        release.set()
        if change == "foreign":
            with pytest.raises(HTTPException) as denied:
                await asyncio.wait_for(task, 3)
            assert denied.value.status_code == 403
        else:
            result = await asyncio.wait_for(task, 3)
            if change in {"revoked", "rotated"}:
                assert result == (None, None)
            else:
                assert result == (
                    "race-key",
                    deps.Role.SENSOR if change == "role" else deps.Role.VIEWER,
                )
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
        deps._verified_key_cache.clear()


def test_outgoing_stream_does_not_extend_idle_session_or_delete_expired_record(
    bridge_app, detection_store
):
    from datetime import datetime, timedelta, timezone

    detection_store.create_user("idle-viewer", "fixture-password-long", role="viewer")
    user = detection_store.get_user("idle-viewer")
    token = detection_store.create_session(user["id"])["session_token"]
    conn = detection_store.get_connection()
    with TestClient(bridge_app, headers={"Authorization": "Bearer " + token}) as actor:
        with actor.websocket_connect("/api/detections/ws/feed") as socket:
            socket.send_text("ping")
            assert socket.receive_text() == "pong"
            idle = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
            conn.execute(
                "UPDATE sessions SET last_active=? WHERE user_id=?", (idle, user["id"])
            )
            conn.commit()
            actor.portal.call(
                bridge_app.state.app_state.ws_detection_clients.broadcast,
                {"passive": True},
            )
            assert socket.receive_json() == {"passive": True}
            assert (
                conn.execute(
                    "SELECT last_active FROM sessions WHERE user_id=?", (user["id"],)
                ).fetchone()[0]
                == idle
            )
            expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
            conn.execute(
                "UPDATE sessions SET last_active=? WHERE user_id=?",
                (expired, user["id"]),
            )
            conn.commit()
            actor.portal.call(
                bridge_app.state.app_state.ws_detection_clients.broadcast,
                {"forbidden": True},
            )
            with pytest.raises(WebSocketDisconnect) as refused:
                socket.receive_json()
            assert refused.value.code == 4001
            assert (
                conn.execute(
                    "SELECT last_active FROM sessions WHERE user_id=?", (user["id"],)
                ).fetchone()[0]
                == expired
            )


@pytest.mark.parametrize("source", ["cookie", "bearer"])
@pytest.mark.parametrize("secondary", ["invalid", "valid", "stale-session"])
def test_csrf_follows_winning_session_not_secondary_header_presence(
    bridge_app, detection_store, master_key, monkeypatch, source, secondary
):
    monkeypatch.setenv("BRIDGE_CSRF", "enabled")
    detection_store.create_user("csrf-owner", "fixture-password-long", role="admin")
    user = detection_store.get_user("csrf-owner")
    token = detection_store.create_session(user["id"])["session_token"]
    if secondary == "stale-session":
        assert detection_store.delete_session(token)
    headers = {"X-API-Key": "invalid-key" if secondary == "invalid" else master_key}
    if source == "cookie":
        headers["Cookie"] = "session_token=" + token + "; csrf_token=fixture-csrf"
    else:
        headers["Authorization"] = "Bearer " + token
        headers["Cookie"] = "csrf_token=fixture-csrf"
    body = {
        "name": "winning credential",
        "conditions": [{"field": "freq_hz", "operator": "gt", "value": 1}],
        "cooldown_seconds": 0,
    }
    with TestClient(bridge_app, headers=headers) as actor:
        assert actor.post("/api/alerts/rules/conditions", json=body).status_code == (
            201 if secondary == "stale-session" else 403
        )
        assert (
            actor.post(
                "/api/alerts/rules/conditions",
                json=body,
                headers={"X-CSRF-Token": "fixture-csrf"},
            ).status_code
            == 201
        )


def test_csrf_exempt_login_can_replace_foreign_cookie_with_local_session(
    bridge_app, detection_store, master_key, monkeypatch
):
    monkeypatch.setenv("BRIDGE_CSRF", "enabled")
    detection_store.create_user("csrf-login-local", "TestPass123!", role="admin")
    other = DetectionStore(detection_store.db_path, tenant_id="other")
    try:
        other.create_user("csrf-login-other", "TestPass123!", role="admin")
        user = other.get_user("csrf-login-other")
        token = other.create_session(user["id"])["session_token"]
        with TestClient(
            bridge_app,
            headers={
                "Cookie": "session_token=" + token,
                "X-API-Key": master_key,
            },
        ) as actor:
            response = actor.post(
                "/api/auth/login",
                json={
                    "username": "csrf-login-local",
                    "password": "TestPass123!",
                },
            )
            assert response.status_code == 200
            session = detection_store.get_session(response.json()["session_token"])
            assert session["username"] == "csrf-login-local"
    finally:
        other.close()
