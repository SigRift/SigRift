"""Real authentication/logging and bounded dependency failure paths."""

from __future__ import annotations

import io
import logging
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, WebSocket
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from uvicorn.protocols.utils import get_path_with_query_string

from sigrift.lib.config import MLRFConfig
from sigrift.lib.security.credentials import hash_credential
from sigrift.lib.shiny import dependencies as deps
from sigrift.lib.shiny.persistence import PersistenceManager


@pytest.fixture(autouse=True)
def isolated_dependencies(monkeypatch):
    monkeypatch.setattr(deps, "_config_singleton", None)
    monkeypatch.setattr(deps, "_rate_limiter", None)
    monkeypatch.setattr(deps, "_fast_hash_index", {})
    monkeypatch.setattr(deps, "_ws_query_warned", False)


@pytest.fixture
def auth_app(tmp_path):
    app = FastAPI()
    app.state.persistence = PersistenceManager(tmp_path, auto_save_interval=0)
    raw = "disposable-redaction-test-credential"
    digest, salt = hash_credential(raw)
    app.state.persistence.set_key("edge-test", digest, salt)
    scopes = []

    @app.middleware("http")
    async def capture_scope(request, call_next):
        scopes.append(request.scope)
        return await call_next(request)

    @app.get("/probe")
    async def protected(key_id: str = Depends(deps.require_api_key)):
        return {"key_id": key_id}

    @app.websocket("/socket")
    async def socket(websocket: WebSocket):
        key_id = await deps.require_ws_auth(websocket)
        await deps.accept_ws(websocket)
        await websocket.send_json({"key_id": key_id})

    return app, raw, scopes


def emitted_access_log(path):
    """Use Uvicorn's access-record layout and a real filtering handler."""
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(deps.RedactQuerySecretsFilter())
    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:1234", "GET", path, "1.1", 200),
        None,
    )
    handler.handle(record)
    handler.close()
    return output.getvalue()


@pytest.mark.parametrize(
    "name", ["api_key", "api%5Fkey", "%61pi_key", "%61%70%69%5f%6b%65%79"]
)
def test_authenticated_query_name_is_redacted_in_actual_access_layout(auth_app, name):
    app, raw, scopes = auth_app
    with TestClient(app) as client:
        response = client.get(f"/probe?{name}={raw}&format=json")
    assert response.status_code == 200
    assert response.json() == {"key_id": "edge-test"}
    path = get_path_with_query_string(scopes[-1])
    assert name in path  # The server's access-log argument retains the encoding.
    output = emitted_access_log(path)
    assert raw not in output
    assert f"{name}=[REDACTED]&format=json" in output


@pytest.mark.parametrize(
    "name", ["api_key", "APIKEY", "api-key", "%6bey", "ToKeN", "access%5ftoken"]
)
def test_redaction_covers_supported_aliases_without_decoding_values(name):
    source = f"/probe?keep=a%26b&{name}=opaque%26another%3Dvalue%27&after=yes#part"
    expected = f"/probe?keep=a%26b&{name}=[REDACTED]&after=yes#part"
    assert deps.redact_query_secrets(source) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "/probe?api_key=&api%5fkey=second",
            "/probe?api_key=[REDACTED]&api%5fkey=[REDACTED]",
        ),
        ("/probe?%2561pi_key=public", "/probe?%2561pi_key=public"),
        (
            "/probe?api+key=public&apikey_extra=public",
            "/probe?api+key=public&apikey_extra=public",
        ),
        ("/probe?bad%=public&other=value=tail", "/probe?bad%=public&other=value=tail"),
        ("/api_key=ordinary-path", "/api_key=ordinary-path"),
        (
            'GET /probe?token=private HTTP/1.1" 200',
            'GET /probe?token=[REDACTED] HTTP/1.1" 200',
        ),
    ],
)
def test_redaction_preserves_query_structure_and_decodes_names_once(source, expected):
    assert deps.redact_query_secrets(source) == expected


@pytest.mark.parametrize("kind", ["http", "websocket"])
def test_service_not_ready_fails_before_accepting_credentials(auth_app, kind):
    app, raw, _scopes = auth_app
    del app.state.persistence
    with TestClient(app) as client:
        if kind == "http":
            response = client.get("/probe", headers={"X-API-Key": raw})
            assert response.status_code == 503
            assert response.json() == {"detail": "Service not ready"}
        else:
            with pytest.raises(WebSocketDisconnect) as error:
                with client.websocket_connect("/socket", headers={"X-API-Key": raw}):
                    pytest.fail("An unavailable service accepted the handshake")
            assert (error.value.code, error.value.reason) == (4001, "Service not ready")


@pytest.mark.parametrize("protocol", ["other", "other, ignored", "bridge-v1, , other"])
def test_incomplete_websocket_protocol_falls_back_to_valid_header(auth_app, protocol):
    app, raw, _scopes = auth_app
    with TestClient(app) as client:
        with client.websocket_connect(
            "/socket", headers={"Sec-WebSocket-Protocol": protocol, "X-API-Key": raw}
        ) as socket:
            assert socket.accepted_subprotocol is None
            assert socket.receive_json() == {"key_id": "edge-test"}


def test_websocket_skips_unrelated_offer_and_echoes_authenticated_protocol(auth_app):
    app, raw, _scopes = auth_app
    with TestClient(app) as client:
        with client.websocket_connect(
            "/socket", headers={"Sec-WebSocket-Protocol": f"other, bridge-v1, {raw}"}
        ) as socket:
            assert socket.accepted_subprotocol == "bridge-v1"
            assert socket.receive_json() == {"key_id": "edge-test"}


@pytest.fixture
def clock(monkeypatch):
    state = SimpleNamespace(now=0.0)
    monkeypatch.setattr(deps, "time", SimpleNamespace(monotonic=lambda: state.now))
    return state


def test_rate_cleanup_removes_expired_and_checked_but_unused_clients(clock):
    limiter = deps.RateLimiter(max_requests=1, window_seconds=60)
    assert limiter.check("unused") == (True, 0)
    assert limiter.is_allowed("expired") == (True, 0)
    clock.now = 280
    assert limiter.is_allowed("recent") == (True, 0)
    clock.now = 301
    assert limiter.check("recent") == (False, 40)
    assert set(limiter._requests) == {"recent"}
    assert limiter.is_allowed("expired") == (True, 0)


def test_rate_cleanup_evicts_oldest_active_client_when_capacity_is_exceeded(clock):
    limiter = deps.RateLimiter(max_requests=1, window_seconds=1000, max_keys=2)
    for now, key in [(0, "oldest"), (10, "middle"), (20, "recent")]:
        clock.now = now
        assert limiter.is_allowed(key) == (True, 0)
    clock.now = 301
    assert limiter.check("recent") == (False, 720)
    assert set(limiter._requests) == {"middle", "recent"}
    assert limiter.check("middle") == (False, 710)
    assert limiter.check("oldest") == (True, 0)


def test_rate_reset_is_scoped_or_global_and_window_boundary_expires(clock):
    limiter = deps.RateLimiter(max_requests=1, window_seconds=60)
    for key in ["one", "two"]:
        assert limiter.is_allowed(key) == (True, 0)
    limiter.reset("one")
    limiter.reset("missing")
    assert limiter.check("one") == (True, 0)
    assert limiter.check("two") == (False, 61)
    clock.now = 60
    assert limiter.is_allowed("two") == (True, 0)
    assert limiter.check("two") == (False, 61)
    limiter.reset()
    assert limiter.check("two") == (True, 0)


def test_configuration_and_limiter_factories_cache_real_configuration(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    config_file = tmp_path / "config.yaml"
    config_file.write_text("security:\n  rate_limit_per_minute: 2\n")
    config = deps.get_config()
    assert config.security.rate_limit_per_minute == 2
    config_file.write_text("security:\n  rate_limit_per_minute: 8\n")
    assert deps.get_config() is config
    limiter = deps.get_rate_limiter()
    assert deps.get_rate_limiter() is limiter
    assert limiter.is_allowed("client")[0]
    assert limiter.is_allowed("client")[0]
    assert not limiter.is_allowed("client")[0]
    replacement = MLRFConfig()
    deps.set_config(replacement)
    assert deps.get_config() is replacement
    replacement_limiter = deps.RateLimiter(max_requests=3)
    deps.set_rate_limiter(replacement_limiter)
    assert deps.get_rate_limiter() is replacement_limiter


def test_filter_redacts_mapping_values_and_preserves_numeric_arguments():
    record = logging.LogRecord(
        "uvicorn.error",
        logging.INFO,
        __file__,
        1,
        "%(path)s %(status)d",
        ({"path": "/socket?token=private&ok=1", "status": 403},),
        None,
    )
    assert deps.RedactQuerySecretsFilter().filter(record)
    assert record.getMessage() == "/socket?token=[REDACTED]&ok=1 403"


def test_filter_preserves_nonstring_message_and_absent_arguments():
    message = {"status": 200}
    record = logging.LogRecord(
        "uvicorn.error", logging.INFO, __file__, 1, message, None, None
    )
    assert deps.RedactQuerySecretsFilter().filter(record)
    assert record.msg is message
    assert record.getMessage() == "{'status': 200}"


def test_install_redaction_is_idempotent_and_preserves_unrelated_filters(monkeypatch):
    unrelated = logging.Filter()
    for name in deps._REDACTED_LOGGERS:
        monkeypatch.setattr(logging.getLogger(name), "filters", [unrelated])
    deps.install_log_redaction()
    deps.install_log_redaction()
    for name in deps._REDACTED_LOGGERS:
        filters = logging.getLogger(name).filters
        assert filters[0] is unrelated
        assert len(filters) == 2
        assert isinstance(filters[1], deps.RedactQuerySecretsFilter)
