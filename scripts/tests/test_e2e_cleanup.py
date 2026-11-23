"""Exercise the real urllib E2E client against a bounded HTTP test server."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from threading import Thread

import pytest

from tests.e2e import conftest as e2e


KEY = {"key_id": "key_fixture", "raw_key": "synthetic-sensor-key"}
BATCH = {"node_id": "synthetic-node", "batch_id": "synthetic-batch", "detections": []}


@contextmanager
def cleanup_server(replies, *, enforce_revocation=True):
    state = {"calls": [], "revoked": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_DELETE(self):
            state["calls"].append(("DELETE", self.path))
            code, retry = replies.pop(0)
            if code == 200:
                state["revoked"] = enforce_revocation
            self.respond(code, retry)

        def do_POST(self):
            state["calls"].append(("POST", self.path))
            size = int(self.headers.get("Content-Length", 0))
            state["last_batch"] = json.loads(self.rfile.read(size))
            state["last_key"] = self.headers.get("X-API-Key")
            self.respond(401 if state["revoked"] else 200, None)

        def respond(self, code, retry):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if retry is not None:
                self.send_header("Retry-After", retry)
            self.end_headers()
            self.wfile.write(b"{}")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = e2e.Settings(
            f"http://127.0.0.1:{server.server_port}",
            "admin",
            "synthetic-password",
            ssl.create_default_context(),
        )
        yield e2e.Client(settings), e2e.Client(settings), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(e2e.time, "sleep", calls.append)
    return calls


@pytest.mark.parametrize("retry", ["1", "60"])
def test_cleanup_retries_once_then_proves_old_key_rejected(sleeps, retry):
    with cleanup_server([(429, retry), (200, None)]) as (admin, sensor, state):
        sensor.request("POST", "/api/detections/batch", BATCH, key=KEY["raw_key"])
        e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert state["calls"] == [
            ("POST", "/api/detections/batch"),
            ("DELETE", "/api/admin/keys/key_fixture"),
            ("DELETE", "/api/admin/keys/key_fixture"),
            ("POST", "/api/detections/batch"),
        ]
        assert state["last_batch"] == BATCH
        assert state["last_key"] == KEY["raw_key"]
        assert state["revoked"] is True
    assert sleeps == [min(int(retry) + 1, 60)]


def test_cleanup_success_without_cooldown_still_checks_revocation(sleeps):
    with cleanup_server([(200, None)]) as (admin, sensor, state):
        e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert [method for method, _ in state["calls"]] == ["DELETE", "POST"]
    assert sleeps == []


@pytest.mark.parametrize("retry", [None, "", "0", "-1", "1.5", "60 ", "61", "sixty"])
def test_cleanup_rejects_missing_invalid_or_long_retry_after(sleeps, retry):
    with cleanup_server([(429, retry)]) as (admin, sensor, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert state["calls"] == [("DELETE", "/api/admin/keys/key_fixture")]
    assert sleeps == []


@pytest.mark.parametrize("code", [401, 403, 404, 500])
def test_cleanup_never_retries_other_errors(sleeps, code):
    with cleanup_server([(code, "1")]) as (admin, sensor, state):
        with pytest.raises(AssertionError, match=f"HTTP {code}"):
            e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert state["calls"] == [("DELETE", "/api/admin/keys/key_fixture")]
    assert sleeps == []


def test_cleanup_repeated_rate_limit_fails_after_one_retry(sleeps):
    with cleanup_server([(429, "1"), (429, "1")]) as (admin, sensor, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert len(state["calls"]) == 2
    assert sleeps == [2]


def test_successful_delete_with_still_usable_key_is_a_failure(sleeps):
    with cleanup_server([(200, None)], enforce_revocation=False) as (
        admin,
        sensor,
        state,
    ):
        with pytest.raises(AssertionError, match=r"HTTP 200, expected \(401,\)"):
            e2e.revoke_scanner_key(admin, sensor, KEY, BATCH)
        assert [method for method, _ in state["calls"]] == ["DELETE", "POST"]
    assert sleeps == []


def test_default_client_does_not_retry_admin_rate_limit(sleeps):
    with cleanup_server([(429, "1")]) as (admin, _sensor, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            admin.request("DELETE", "/api/admin/keys/key_fixture")
        assert len(state["calls"]) == 1
    assert sleeps == []


def test_sensor_construction_failure_does_not_create_an_owned_key(sleeps):
    class UnusableSettings:
        @property
        def context(self):
            raise RuntimeError("Invalid fixture TLS context")

    with cleanup_server([]) as (admin, _sensor, state):
        fixture = e2e.synthetic_scanner.__wrapped__(None, admin, UnusableSettings())
        with pytest.raises(RuntimeError, match="Invalid fixture TLS context"):
            next(fixture)
        # Registration happened, but construction failed before key creation.
        assert state["calls"] == [("POST", "/api/nodes/register")]
    assert sleeps == []


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/api/admin/keys"),
        ("DELETE", "/api/admin/users/synthetic"),
    ],
)
def test_cleanup_retry_cannot_be_used_for_other_operations(sleeps, method, path):
    with cleanup_server([]) as (admin, _sensor, state):
        with pytest.raises(ValueError, match="Cleanup retry is restricted"):
            admin.request(method, path, retry_key_cleanup=True)
        assert state["calls"] == []
    assert sleeps == []
