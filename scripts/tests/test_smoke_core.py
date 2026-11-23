"""The live smoke respects login cooldowns without retrying auth failures."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import inspect
import io
import json
from pathlib import Path
import ssl
from threading import Thread
import urllib.error
from unittest.mock import Mock

import pytest


spec = importlib.util.spec_from_file_location(
    "smoke_core", Path(__file__).resolve().parents[1] / "smoke-core.py"
)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def response(code, retry_after=None, body=None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return urllib.error.HTTPError(
        "https://localhost/api/auth/login",
        code,
        "fixture",
        headers,
        io.BytesIO(json.dumps(body or {}).encode()),
    )


def client(monkeypatch, replies):
    value = smoke.Client("https://localhost", ssl.create_default_context())
    value.opener.open = Mock(side_effect=replies)
    sleep = Mock()
    monkeypatch.setattr(smoke.time, "sleep", sleep)
    return value, sleep


def test_login_retries_once_after_short_server_cooldown(monkeypatch):
    limited = response(429, "60")
    value, sleep = client(
        monkeypatch, [limited, response(200, body={"csrf_token": "fixture"})]
    )
    assert value.login("admin", "fixture-password") == {"csrf_token": "fixture"}
    assert value.opener.open.call_count == 2
    sleep.assert_called_once_with(61)
    assert limited.fp.closed


def jar_cookie(name, value, *, httponly):
    import http.cookiejar

    # What the jar stores for a gateway cookie on localhost.
    return http.cookiejar.Cookie(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain="localhost.local",
        domain_specified=False,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=False,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None} if httponly else {},
    )


@pytest.mark.parametrize(
    ("cookies", "expected"),
    [
        ([], False),
        ([("csrf_token", "c", False)], False),
        ([("session_token", "s", False)], False),  # not HttpOnly
        ([("session_token", "", True)], False),
        ([("session_token", "s", True), ("csrf_token", "c", False)], True),
    ],
)
def test_has_session_needs_an_httponly_session_cookie(cookies, expected):
    # The session is the HttpOnly cookie, not the login body's
    # session_token, which newer gateways no longer return.
    value = smoke.Client("https://localhost", ssl.create_default_context())
    for name, cookie_value, httponly in cookies:
        value.cookies.set_cookie(jar_cookie(name, cookie_value, httponly=httponly))
    assert value.has_session() is expected


@pytest.mark.parametrize(
    "retry_after",
    [None, "", "0", "-1", "1.5", " 60", "60 ", "61", "1800", "sixty", "６０"],
)
def test_login_refuses_missing_invalid_or_long_retry_after(monkeypatch, retry_after):
    value, sleep = client(monkeypatch, [response(429, retry_after)])
    with pytest.raises(AssertionError, match="HTTP 429"):
        value.login("admin", "fixture-password")
    assert value.opener.open.call_count == 1
    sleep.assert_not_called()


def test_persistent_login_rate_limit_still_fails(monkeypatch):
    value, sleep = client(monkeypatch, [response(429, "60"), response(429, "60")])
    with pytest.raises(AssertionError, match="HTTP 429"):
        value.login("admin", "fixture-password")
    assert value.opener.open.call_count == 2
    sleep.assert_called_once_with(61)


@pytest.mark.parametrize("status", [401, 403, 500])
def test_login_does_not_retry_wrong_credentials_or_other_failures(monkeypatch, status):
    value, sleep = client(monkeypatch, [response(status, "60")])
    with pytest.raises(AssertionError, match=f"HTTP {status}"):
        value.login("admin", "fixture-password")
    assert value.opener.open.call_count == 1
    sleep.assert_not_called()


def test_other_requests_never_retry_even_if_opted_in(monkeypatch):
    value, sleep = client(monkeypatch, [response(429, "60")])
    with pytest.raises(AssertionError, match="HTTP 429"):
        value.request("POST", "/api/auth/mfa/verify", {}, retry_login_limit=True)
    assert value.opener.open.call_count == 1
    sleep.assert_not_called()


def test_expected_rate_limit_is_asserted_without_retry(monkeypatch):
    value, sleep = client(monkeypatch, [response(429, "60")])
    value.request("POST", "/api/auth/login", {}, status=429, retry_login_limit=True)
    sleep.assert_not_called()


SECRET = "JBSWY3DPEHPK3PXP"  # base32 fixture, not a real enrolment


@contextmanager
def mfa_server(mode):
    """A gateway's two-step MFA login. ``mode`` says what goes wrong:
    ``"leaky"`` sets the session at the password step, ``"no_session"``
    sets none at verify, ``"no_challenge"`` asks for no second step."""
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.loads(raw)
            calls.append(self.path)
            cookies = []
            if self.path == "/api/auth/login":
                assert body == {"username": "mfa-user", "password": "pw"}
                result = (
                    {"mfa_required": False}
                    if mode == "no_challenge"
                    else {"mfa_required": True, "mfa_token": "challenge"}
                )
                if mode == "leaky":
                    cookies.append("session_token=early; Path=/; HttpOnly")
            else:
                assert self.path == "/api/auth/mfa/verify"
                assert body == {
                    "mfa_token": "challenge",
                    "totp_code": smoke.totp(SECRET),
                }
                result = {"csrf_token": "c"}
                if mode != "no_session":
                    cookies.append("session_token=s; Path=/; SameSite=Lax; HttpOnly")
                cookies.append("csrf_token=c; Path=/; SameSite=Lax")
            data = json.dumps(result).encode()
            self.send_response(200)
            for value in cookies:
                self.send_header("Set-Cookie", value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_mfa_login_gets_its_session_from_verify_only():
    with mfa_server("gateway") as (base_url, calls):
        user = smoke.Client(base_url, ssl.create_default_context())
        verification = smoke.mfa_login(user, "mfa-user", "pw", SECRET)
    assert calls == ["/api/auth/login", "/api/auth/mfa/verify"]
    assert verification == {"mfa_token": "challenge", "totp_code": smoke.totp(SECRET)}
    assert user.has_session()


@pytest.mark.parametrize(
    ("mode", "calls", "message"),
    [
        # The smoke's MFA check: the password step must not sign in.
        ("leaky", ["/api/auth/login"], "the password step alone issued a session"),
        ("no_session", ["/api/auth/login", "/api/auth/mfa/verify"], "MFA verify"),
        ("no_challenge", ["/api/auth/login"], "no MFA challenge"),
    ],
)
def test_mfa_login_fails_when_a_step_misbehaves(mode, calls, message):
    with mfa_server(mode) as (base_url, seen):
        user = smoke.Client(base_url, ssl.create_default_context())
        with pytest.raises(AssertionError, match=message):
            smoke.mfa_login(user, "mfa-user", "pw", SECRET)
    assert seen == calls


def test_main_signs_the_mfa_user_in_through_mfa_login():
    # main() needs a live stack; pin that its MFA login is the step tested
    # above, and that the replay check reuses that step's verification.
    source = inspect.getsource(smoke.main)
    assert 'verification = mfa_login(user, username, changed, setup["secret"])' in (
        source
    )
    assert '"/api/auth/mfa/verify", verification, status=(400, 401)' in source
