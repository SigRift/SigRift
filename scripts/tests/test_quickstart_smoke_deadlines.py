"""Run shipped smoke commands against actual stalled loopback TLS responses."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socketserver
import ssl
import subprocess
import threading
import time

import pytest

from test_quickstart_endpoint import (
    assert_readiness_after_smoke,
    smoke_startup_context,
)


ROOT = Path(__file__).resolve().parents[2]
QUICKSTART = ROOT / "scripts/quickstart.sh"
ROUTES = [
    "/health",
    "/api/version",
    "/api/auth/login",
    "/api/auth/me",
    "/api/detections/recent",
]


@pytest.fixture(scope="module")
def tls_pair(tmp_path_factory):
    directory = tmp_path_factory.mktemp("smoke-deadline-cert")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return cert, key


@contextmanager
def tls_server(tls_pair, stalled_route, partial_body):
    release = threading.Event()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            route = self.path.partition("?")[0]
            body = None
            if self.command == "POST":
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((route, self.headers.get("Cookie"), body))
            response = json.dumps({"success": True, "username": "admin"}).encode()
            if route == stalled_route and not partial_body:
                release.wait(25)
                return
            self.send_response(200)
            self.send_header(
                "Content-Length",
                str(len(response) + (100 if route == stalled_route else 0)),
            )
            self.send_header("Content-Type", "application/json")
            if route == "/api/auth/login":
                self.send_header("Set-Cookie", "session=private-cookie; Secure; Path=/")
            self.end_headers()
            self.wfile.write(response)
            self.wfile.flush()
            if route == stalled_route:
                # The prefix is valid success JSON. curl must still fail when
                # the promised response body never completes, including login.
                release.wait(25)

        do_GET = respond
        do_POST = respond

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, tls_pair))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def run_smoke(tmp_path, port):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'if [ "$1 $2 $3 $4" = "compose port gateway 8444" ]; then\n'
        '  printf "127.0.0.1:%s\\n" "$TEST_PUBLISHED_PORT"; exit 0\n'
        "fi\ncat <<'JSON'\n"
        + json.dumps(
            {
                "services": {
                    "bridge": {
                        "environment": {
                            "BRIDGE_ADMIN_USER": "admin",
                            "BRIDGE_ADMIN_PASSWORD": "private-password",
                        }
                    }
                }
            }
        )
        + "\nJSON\n"
    )
    docker.chmod(0o700)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    # These files stand in for existing installation state; the smoke tail must
    # remove only its private cookie directory on either success or failure.
    (tmp_path / ".env").write_text("preserved configuration\n")
    (tmp_path / "tls").mkdir()
    (tmp_path / "tls/key.pem").write_text("preserved TLS key\n")
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COMPOSE_", "SIGRIFT_", "BRIDGE_", "UC_"))
    }
    for key in tuple(env):
        if key.lower().endswith("_proxy"):
            del env[key]
    env.update(
        PATH=str(bindir) + os.pathsep + os.environ["PATH"],
        TMPDIR=str(scratch),
        TEST_PUBLISHED_PORT=str(port),
    )
    # An owned empty curl config makes the real network test independent of
    # arbitrary user curlrc settings without modifying the shipped smoke tail.
    home = tmp_path / "home"
    home.mkdir()
    (home / ".curlrc").write_text("")
    env.update(HOME=str(home), CURL_HOME=str(home), XDG_CONFIG_HOME=str(home))
    tail = (
        QUICKSTART.read_text().split("# ── End-to-end smoke", 1)[1].partition("\n")[2]
    )
    context = smoke_startup_context(tmp_path)
    process = subprocess.Popen(
        [
            "bash",
            "-c",
            "set -euo pipefail\n"
            + context
            + f"UC_PORT={port}\ndescribe_stack() {{ :; }}\n"
            + tail,
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    started = time.monotonic()
    try:
        stdout, stderr = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        # This is a test failure, never a simulated curl timeout or retry. Kill
        # the whole shell/curl group so the old unbounded behavior leaves no job.
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=5)
        pytest.fail("Actual smoke command exceeded the external20s test deadline")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
    elapsed = time.monotonic() - started
    assert_readiness_after_smoke(tmp_path, process.returncode == 0)
    assert not list(scratch.iterdir()), "private session cookie scratch remains"
    assert (tmp_path / ".env").read_text() == "preserved configuration\n"
    assert (tmp_path / "tls/key.pem").read_text() == "preserved TLS key\n"
    for private in ("private-password", "private-cookie"):
        assert private not in stdout + stderr
    return process.returncode, stdout, stderr, elapsed


@pytest.mark.parametrize(
    "route,partial_body",
    [
        (ROUTES[0], False),
        (ROUTES[1], True),
        (ROUTES[2], True),
        (ROUTES[3], False),
        (ROUTES[4], True),
    ],
)
def test_actual_smoke_deadline_fails_stalled_response_then_finishes_other_checks(
    tmp_path, tls_pair, route, partial_body
):
    with tls_server(tls_pair, route, partial_body) as (port, requests):
        code, stdout, stderr, elapsed = run_smoke(tmp_path, port)
    assert code == 1
    assert "SigRift is up." not in stdout
    assert "startup verification failed" in stderr
    assert "scripts/quickstart.sh" in stderr
    assert [request[0] for request in requests] == ROUTES
    assert 10 <= elapsed < 20, (
        "real request deadline must trigger, without synthetic sleep or curl replacement"
    )


def test_actual_smoke_preserves_success_login_payload_cookies_and_self_signed_tls(
    tmp_path, tls_pair
):
    with tls_server(tls_pair, None, False) as (port, requests):
        code, stdout, stderr, _elapsed = run_smoke(tmp_path, port)
    assert code == 0, stderr
    assert "SigRift is up." in stdout
    assert requests[2][2] == {"username": "admin", "password": "private-password"}
    assert all("session=private-cookie" in row[1] for row in requests[3:])
    assert [request[0] for request in requests] == ROUTES


def test_connect_deadline_includes_unfinished_tls_handshake(tmp_path):
    release = threading.Event()
    accepted = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            assert self.request.recv(4096), "curl must send its TLS ClientHello"
            accepted.set()
            release.wait(15)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    function = re.search(
        r"^smoke_curl\(\) \{\n.*?^\}\n", QUICKSTART.read_text(), re.M | re.S
    )
    assert function is not None
    (tmp_path / ".curlrc").write_text("")
    env = os.environ | {
        "HOME": str(tmp_path),
        "CURL_HOME": str(tmp_path),
        "XDG_CONFIG_HOME": str(tmp_path),
    }
    started = time.monotonic()
    process = None
    try:
        process = subprocess.Popen(
            [
                "bash",
                "-c",
                function.group() + '\nsmoke_curl -sk -f --noproxy "*" "$1"',
                "bash",
                f"https://127.0.0.1:{server.server_address[1]}/health",
            ],
            cwd=tmp_path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        _stdout, stderr = process.communicate(timeout=12)
        assert accepted.is_set()
        assert process.returncode == 28, stderr
        assert 4 <= time.monotonic() - started < 10
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
