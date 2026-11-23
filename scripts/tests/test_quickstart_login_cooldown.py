"""Real TLS login cooldowns exercise the shipped installer smoke tail."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time

import pytest

from test_quickstart_endpoint import environment, smoke
from test_quickstart_endpoint import tls_pair as endpoint_tls_pair


@pytest.fixture(scope="module")
def tls_pair(tmp_path_factory):
    return endpoint_tls_pair.__wrapped__(tmp_path_factory)


@contextmanager
def login_server(tls_pair, replies):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            calls.append((time.monotonic(), body))
            status, headers, truncated = replies[min(len(calls) - 1, len(replies) - 1)]
            data = b'{"success":true,"username":"admin"}'
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            if status == 200:
                self.send_header(
                    "Set-Cookie", "session=private-cooldown-cookie; Secure; Path=/"
                )
            self.send_header(
                "Content-Length", str(len(data) + (100 if truncated else 0))
            )
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            self.close_connection = True

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, tls_pair))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()


def execute(tmp_path, port):
    env = environment(tmp_path, f"127.0.0.1:{port}\n")
    (tmp_path / ".env").write_text("preserved configuration\n")
    result = smoke(tmp_path, env, port)
    assert (tmp_path / ".env").read_text() == "preserved configuration\n"
    assert not list((tmp_path / "scratch").iterdir())
    assert "private-endpoint-password" not in result.stdout + result.stderr
    assert "private-cooldown-cookie" not in result.stdout + result.stderr
    return result


def test_completed_short_cooldown_retries_same_login_once_then_finishes(
    tmp_path, tls_pair
):
    replies = [(429, [("Retry-After", "1")], False), (200, [], False)]
    with login_server(tls_pair, replies) as (port, calls):
        result = execute(tmp_path, port)
    assert result.returncode == 0, result.stdout + result.stderr
    assert len(calls) == 2 and calls[0][1] == calls[1][1]
    assert json.loads(calls[0][1]) == {
        "username": "admin",
        "password": "private-endpoint-password",
    }
    assert calls[1][0] - calls[0][0] >= 1.8
    assert "Login rate-limited; retrying once after 2s" in result.stderr
    assert "SigRift is up." in result.stdout


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Retry-After", "0")],
        [("Retry-After", "61")],
        [("Retry-After", "1800")],
        [("Retry-After", "-1")],
        [("Retry-After", "1.5")],
        [("Retry-After", "tomorrow")],
        [("Retry-After", "1, 1")],
        [("Retry-After", "1"), ("retry-after", "1")],
    ],
)
def test_missing_invalid_or_long_cooldown_does_not_retry(tmp_path, tls_pair, headers):
    with login_server(tls_pair, [(429, headers, False), (200, [], False)]) as (
        port,
        calls,
    ):
        result = execute(tmp_path, port)
    assert result.returncode == 1 and len(calls) == 1
    assert "SigRift is up." not in result.stdout
    assert "retrying once" not in result.stderr


@pytest.mark.parametrize(
    "status,truncated", [(401, False), (403, False), (503, False), (429, True)]
)
def test_other_status_or_incomplete_response_never_retries(
    tmp_path, tls_pair, status, truncated
):
    with login_server(
        tls_pair, [(status, [("Retry-After", "1")], truncated), (200, [], False)]
    ) as (port, calls):
        result = execute(tmp_path, port)
    assert result.returncode == 1 and len(calls) == 1
    assert "retrying once" not in result.stderr


def test_second_cooldown_fails_without_third_request(tmp_path, tls_pair):
    with login_server(tls_pair, [(429, [("Retry-After", "1")], False)]) as (
        port,
        calls,
    ):
        result = execute(tmp_path, port)
    assert result.returncode == 1 and len(calls) == 2
    assert calls[1][0] - calls[0][0] >= 1.8
    assert result.stderr.count("retrying once") == 1
    assert "SigRift is up." not in result.stdout


def test_login_credentials_use_private_stdin_not_curl_arguments(tmp_path, tls_pair):
    import shutil
    import sys

    with login_server(
        tls_pair, [(429, [("Retry-After", "1")], False), (200, [], False)]
    ) as (port, calls):
        env = environment(tmp_path, f"127.0.0.1:{port}\n")
        (tmp_path / ".env").write_text("preserved\n")
        real_curl = shutil.which("curl")
        assert real_curl
        wrapper = tmp_path / "bin/curl"
        wrapper.write_text(
            f"#!{sys.executable}\nimport json,os,stat,sys\nfrom pathlib import Path\n"
            f"out=Path({str(tmp_path / 'curl-argv.jsonl')!r})\n"
            "row={'args':sys.argv[1:]}\n"
            "if any(a.endswith('/api/auth/login') for a in sys.argv):\n"
            " s=os.fstat(0);row['stdin_regular']=stat.S_ISREG(s.st_mode);row['stdin_mode']=stat.S_IMODE(s.st_mode)\n"
            " for flag in ['-D','-o','-c']:\n"
            "  row[flag]=stat.S_IMODE(Path(sys.argv[sys.argv.index(flag)+1]).stat().st_mode)\n"
            "with out.open('a') as f:f.write(json.dumps(row)+'\\n')\n"
            f"os.execv({real_curl!r},[{real_curl!r},*sys.argv[1:]])\n"
        )
        wrapper.chmod(0o700)
        result = smoke(tmp_path, env, port)
    assert result.returncode == 0, result.stderr
    recorded = (tmp_path / "curl-argv.jsonl").read_text()
    assert "private-endpoint-password" not in recorded
    assert "private-cooldown-cookie" not in recorded
    rows = [json.loads(line) for line in recorded.splitlines()]
    logins = [row for row in rows if "stdin_regular" in row]
    assert len(logins) == len(calls) == 2
    assert logins[0]["args"] == logins[1]["args"]
    for row in logins:
        assert row["stdin_regular"] and row["stdin_mode"] == 0o600
        assert all(row[flag] == 0o600 for flag in ("-D", "-o", "-c"))
        assert row["args"][row["args"].index("--data-binary") + 1] == "@-"
    assert not list((tmp_path / "scratch").iterdir())
    assert (tmp_path / ".env").read_text() == "preserved\n"


@pytest.mark.parametrize("signum,exit_code", [(15, 143), (2, 130)])
def test_signal_during_real_cooldown_reaps_sleep_and_removes_private_files(
    tmp_path, tls_pair, signum, exit_code
):
    import os
    import signal
    import stat
    import subprocess

    from test_quickstart_endpoint import QUICKSTART, smoke_startup_context

    with login_server(tls_pair, [(429, [("Retry-After", "60")], False)]) as (
        port,
        calls,
    ):
        env = environment(tmp_path, f"127.0.0.1:{port}\n")
        (tmp_path / ".env").write_text("preserved\n")
        tail = (
            QUICKSTART.read_text()
            .split("# ── End-to-end smoke", 1)[1]
            .partition("\n")[2]
        )
        script = (
            "set -euo pipefail\n"
            + smoke_startup_context(tmp_path)
            + f"UC_PORT={port}\n"
            + "describe_stack() { :; }\n"
            + tail
        )
        proc = subprocess.Popen(
            ["bash", "-c", script],
            cwd=tmp_path,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        child = None
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and proc.poll() is None:
                output = subprocess.check_output(
                    ["ps", "-axo", "pid=,ppid=,comm="], text=True, timeout=3
                )
                for line in output.splitlines():
                    values = line.strip().split(None, 2)
                    if (
                        len(values) == 3
                        and int(values[1]) == proc.pid
                        and values[2].rsplit("/", 1)[-1] == "sleep"
                    ):
                        child = int(values[0])
                if child:
                    break
                time.sleep(0.03)
            assert child is not None, (
                "Installer did not enter its real server-directed cooldown"
            )
            private = list((tmp_path / "scratch").iterdir())
            assert (
                len(private) == 1 and stat.S_IMODE(private[0].stat().st_mode) == 0o700
            )
            assert stat.S_IMODE((private[0] / "login-body").stat().st_mode) == 0o600
            assert (
                json.loads((private[0] / "login-body").read_text())["password"]
                == "private-endpoint-password"
            )
            os.kill(proc.pid, signum)
            stdout, stderr = proc.communicate(timeout=5)
            assert proc.returncode == exit_code
            assert "retrying once after 61s" in stderr
            assert "private-endpoint-password" not in stdout + stderr
            assert len(calls) == 1
            with pytest.raises(ProcessLookupError):
                os.kill(child, 0)
            assert not list((tmp_path / "scratch").iterdir())
            assert not (tmp_path / "readiness-calls.jsonl").exists()
            assert (tmp_path / ".env").read_text() == "preserved\n"
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate(timeout=5)


def test_failed_cooldown_wait_does_not_issue_another_login(tmp_path, tls_pair):
    with login_server(tls_pair, [(429, [("Retry-After", "1")], False)]) as (
        port,
        calls,
    ):
        env = environment(tmp_path, f"127.0.0.1:{port}\n")
        (tmp_path / ".env").write_text("preserved\n")
        sleeper = tmp_path / "bin/sleep"
        sleeper.write_text("#!/bin/sh\nexit 7\n")
        sleeper.chmod(0o700)
        result = smoke(tmp_path, env, port)
    assert result.returncode == 1 and len(calls) == 1
    assert "SigRift is up." not in result.stdout
    assert not list((tmp_path / "scratch").iterdir())
    assert not (tmp_path / "readiness-calls.jsonl").exists()
