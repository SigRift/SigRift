"""A rejected synthetic-key POST may retry once; ambiguous outcomes may not."""

from contextlib import contextmanager
from http.client import IncompleteRead, RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from threading import Thread

import pytest

from tests.e2e import conftest as e2e
from tests.e2e import diagnostics


SECRET = "synthetic-private-key-password-response"
KEY = {"key_id": "owned_fixture_key", "raw_key": SECRET}
BODY = {"description": SECRET, "role": "sensor", "node_id": "synthetic-node"}


@contextmanager
def key_server(replies):
    state = {"calls": [], "key_bodies": [], "created": 0, "revoked": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self):
            state["calls"].append((self.command, self.path))
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.command == "POST" and self.path == "/api/admin/keys":
                state["key_bodies"].append(json.loads(body))
                code, retry = replies.pop(0)
                if code == "disconnect":
                    # The request reached the server; its outcome is ambiguous.
                    self.close_connection = True
                    return
                if code == "truncated":
                    self.send_response(201)
                    self.send_header("Content-Length", "1000")
                    self.end_headers()
                    self.wfile.write(b"{")
                    self.close_connection = True
                    return
                if code == "malformed":
                    self.send_response(201)
                    self.end_headers()
                    self.wfile.write(SECRET.encode())
                    return
                if code == 201:
                    state["created"] += 1
                payload = KEY if code == 201 else {"detail": SECRET}
            elif self.command == "DELETE":
                assert self.path == "/api/admin/keys/owned_fixture_key"
                state["revoked"] = True
                code, retry, payload = 200, None, {}
            elif self.path == "/api/detections/batch":
                assert self.headers.get("X-API-Key") == SECRET
                code, retry = (401 if state["revoked"] else 200), None
                payload = {"inserted": 1, "rejected": 0}
            elif self.path.startswith("/api/nodes/") and self.path.endswith(
                "/scanner-status"
            ):
                assert state["revoked"]
                assert self.headers.get("X-API-Key") == SECRET
                code, retry, payload = 401, None, {}
            elif self.path == "/api/wifi/ingest":
                code, retry, payload = 201, None, {"inserted": 1}
            else:
                assert self.path == "/api/nodes/register"
                code, retry, payload = 200, None, {}
            self.send_response(code)
            if retry is not None:
                self.send_header("Retry-After", retry)
            self.send_header("X-Secret", SECRET)
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode())

        do_POST = do_DELETE = reply

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=http.serve_forever, daemon=True)
    worker.start()
    try:
        settings = e2e.Settings(
            f"http://127.0.0.1:{http.server_port}",
            "admin",
            SECRET,
            ssl.create_default_context(),
        )
        yield e2e.Client(settings), state
    finally:
        http.shutdown()
        http.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.fixture
def sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(e2e.time, "sleep", calls.append)
    return calls


def create_key(client, **kwargs):
    return client.request(
        "POST",
        "/api/admin/keys",
        BODY,
        status=201,
        retry_key_creation=True,
        stage="scanner_key",
        **kwargs,
    )


@pytest.mark.parametrize("retry", ["1", "60"])
def test_real_scanner_retries_rejected_creation_then_cleans_up(
    tmp_path, monkeypatch, sleeps, retry, capsys
):
    output = tmp_path / "events.jsonl"
    monkeypatch.setenv("SIGRIFT_E2E_DIAGNOSTICS", str(output))
    try:
        with key_server([(429, retry), (201, None)]) as (admin, state):
            fixture = e2e.synthetic_scanner.__wrapped__(None, admin, admin.settings)
            scanner = next(fixture)
            assert set(scanner) == {
                "node_id",
                "detection_id",
                "ssid",
                "report",
                "observe_rf",
                "upload_iq",
            }
            assert callable(scanner["observe_rf"])
            assert callable(scanner["upload_iq"])
            fixture.close()
            assert state["created"] == 1
            assert state["key_bodies"][0] == state["key_bodies"][1]
            assert state["revoked"] is True
            assert state["calls"] == [
                ("POST", "/api/nodes/register"),
                ("POST", "/api/admin/keys"),
                ("POST", "/api/admin/keys"),
                ("POST", "/api/detections/batch"),
                ("POST", "/api/wifi/ingest"),
                ("DELETE", "/api/admin/keys/owned_fixture_key"),
                ("POST", "/api/detections/batch"),
                ("POST", f"/api/nodes/{scanner['node_id']}/scanner-status"),
            ]
        assert diagnostics.finish() is True
        assert sleeps == [min(int(retry) + 1, 60)]
        records = [json.loads(line) for line in output.read_text().splitlines()]
        key_events = [r for r in records if r["stage"] == "scanner_key"]
        assert key_events == [
            dict(
                method="POST",
                route="/api/admin/keys",
                status=status,
                expected=[201],
                stage="scanner_key",
                category=category,
            )
            for status, category in [(429, "cooldown"), (201, "ok")]
        ]
        assert any(
            r["stage"] == "scanner_cleanup"
            and r["status"] == 200
            and r["category"] == "ok"
            for r in records
        )
        assert any(
            r["stage"] == "scanner_revocation"
            and r["status"] == 401
            and r["category"] == "ok"
            for r in records
        )
        assert diagnostics.summarize(output) == 0
        assert SECRET not in output.read_text() + capsys.readouterr().out
    finally:
        diagnostics.finish()


def test_successful_creation_is_not_repeated(sleeps):
    with key_server([(201, None)]) as (client, state):
        assert create_key(client) == KEY
        assert len(state["calls"]) == state["created"] == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "retry",
    [
        None,
        "",
        "0",
        "-1",
        "+1",
        "1.5",
        "60 ",
        "61",
        "sixty",
        "Fri, 07 Nov 2026 09:00:00 GMT",
        "1, 2",
    ],
)
def test_invalid_cooldown_fails_without_repeating_creation(sleeps, retry):
    with key_server([(429, retry)]) as (client, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            create_key(client)
        assert len(state["calls"]) == 1
        assert state["created"] == 0
    assert sleeps == []


@pytest.mark.parametrize("code", [200, 202, 302, 400, 401, 403, 409, 500, 503])
def test_other_status_never_retries_even_with_retry_after(sleeps, code):
    with key_server([(code, "1")]) as (client, state):
        with pytest.raises(AssertionError, match=f"HTTP {code}"):
            create_key(client)
        assert len(state["calls"]) == 1
    assert sleeps == []


def test_repeated_rejection_stops_after_one_retry(sleeps):
    with key_server([(429, "1"), (429, "1")]) as (client, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            create_key(client)
        assert len(state["calls"]) == 2
        assert state["created"] == 0
    assert sleeps == [2]


@pytest.mark.parametrize(
    "failure,exception",
    [
        ("disconnect", RemoteDisconnected),
        ("truncated", IncompleteRead),
        ("malformed", json.JSONDecodeError),
    ],
)
@pytest.mark.parametrize("after_cooldown", [False, True])
def test_ambiguous_transport_outcomes_are_never_retried(
    sleeps, failure, exception, after_cooldown
):
    replies = ([(429, "1")] if after_cooldown else []) + [(failure, None)]
    with key_server(replies) as (client, state):
        with pytest.raises(exception):
            create_key(client)
        assert len(state["calls"]) == (2 if after_cooldown else 1)
    assert sleeps == ([2] if after_cooldown else [])


def test_key_creation_cooldown_requires_explicit_opt_in(sleeps):
    with key_server([(429, "1")]) as (client, state):
        with pytest.raises(AssertionError, match="HTTP 429"):
            client.request("POST", "/api/admin/keys", BODY, status=201)
        assert len(state["calls"]) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "method,path,status",
    [
        ("POST", "/api/admin/keys", 200),
        ("POST", "/api/admin/keys", (201, 429)),
        ("GET", "/api/admin/keys", 201),
        ("DELETE", "/api/admin/keys/owned_fixture_key", 201),
        ("POST", "/api/admin/users", 201),
        ("POST", "/api/admin/keys?alternate=1", 201),
    ],
)
def test_creation_opt_in_rejects_other_operations_before_network(
    sleeps, method, path, status
):
    with key_server([]) as (client, state):
        with pytest.raises(ValueError, match="Creation retry is restricted"):
            client.request(method, path, BODY, status=status, retry_key_creation=True)
        assert state["calls"] == []
    assert sleeps == []
