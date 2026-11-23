"""The e2e client reads the session from the cookie the server set.

``Client.has_session()`` is the release gates' "I have a session" check
(e2e, ``soak-candidate.py``): newer gateways stop returning
``session_token`` in the login body, so the check is an HttpOnly
``session_token`` cookie in the jar. ``Client.browser_cookies()`` hands that
jar to Playwright with the attributes the server chose. Both run only
against a live stack otherwise, so a vacuous check would pass unnoticed.
Each case logs in against a local server whose ``Set-Cookie`` fields are the
fixture, so the jar parses them as it parses the gateway's.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
from threading import Thread

import pytest

from tests.e2e import conftest as e2e


@contextmanager
def login_server(set_cookies):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            assert self.path == "/api/auth/login"
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.send_response(200)
            for value in set_cookies:
                self.send_header("Set-Cookie", value)
            body = json.dumps({"csrf_token": "c"}).encode()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
    )
    thread.start()
    try:
        yield e2e.Settings(
            f"http://127.0.0.1:{server.server_port}",
            "admin",
            "fixture-password",
            ssl.create_default_context(),
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def signed_in(set_cookies):
    with login_server(set_cookies) as settings:
        client = e2e.Client(settings)
        assert client.login("admin", "fixture-password") == {"csrf_token": "c"}
        return client


GATEWAY = [
    "session_token=s3ss10n; Path=/; SameSite=Lax; HttpOnly",
    "csrf_token=c; Path=/; SameSite=Lax",
]


@pytest.mark.parametrize(
    ("set_cookies", "expected"),
    [
        ([], False),
        (["csrf_token=c; Path=/; SameSite=Lax"], False),
        # A JS-readable session cookie is not the gateway's session.
        (["session_token=s3ss10n; Path=/; SameSite=Lax"], False),
        (["bridge_token=s3ss10n; Path=/; HttpOnly"], False),
        (["session_token=; Path=/; HttpOnly"], False),
        (["session_token_hint=s3ss10n; Path=/; HttpOnly"], False),
        (GATEWAY, True),
        (["session_token=s3ss10n; path=/; httponly"], True),
    ],
)
def test_has_session_needs_an_httponly_session_cookie(set_cookies, expected):
    assert signed_in(set_cookies).has_session() is expected


def test_is_session_cookie_reads_the_cookie_the_server_set():
    client = signed_in(GATEWAY + ["theme=dark; Path=/"])
    assert {
        cookie.name: e2e.is_session_cookie(cookie) for cookie in client.cookies
    } == {"session_token": True, "csrf_token": False, "theme": False}


@pytest.mark.parametrize(
    ("attributes", "same_site"),
    [
        ("; SameSite=Lax", "Lax"),  # the gateway
        ("; SameSite=strict", "Strict"),  # the standalone bridge (Starlette)
        ("; samesite=none", "None"),
        ("", "Lax"),  # none sent: browsers default to Lax
        ("; SameSite=bogus", "Lax"),
    ],
)
def test_browser_cookies_keep_the_servers_same_site(attributes, same_site):
    client = signed_in([f"csrf_token=c; Path=/{attributes}"])
    (cookie,) = client.browser_cookies()
    assert cookie["sameSite"] == same_site
    assert cookie["httpOnly"] is False


def test_browser_cookies_keep_every_attribute_of_the_gateway_cookies():
    client = signed_in(GATEWAY)
    cookies = {cookie["name"]: cookie for cookie in client.browser_cookies()}
    assert set(cookies) == {"session_token", "csrf_token"}
    assert cookies["session_token"] == {
        "name": "session_token",
        "value": "s3ss10n",
        "domain": "127.0.0.1",
        "path": "/",
        "secure": False,
        "httpOnly": True,
        "sameSite": "Lax",
    }
    assert cookies["csrf_token"]["httpOnly"] is False
    assert cookies["csrf_token"]["sameSite"] == "Lax"
