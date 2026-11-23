"""Real HTTPS smoke follows published gateway bindings, without daemon changes."""

from contextlib import contextmanager
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading

import pytest

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
    directory = tmp_path_factory.mktemp("published-endpoint-cert")
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
def endpoint_server(tls_pair, binding, status=200):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            body = None
            if self.command == "POST":
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            route = self.path.partition("?")[0]
            requests.append((route, self.headers.get("Cookie"), body))
            code = status if route == "/api/auth/login" else 200
            data = b'{"success":true,"username":"admin"}'
            self.send_response(code)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "application/json")
            if code == 200 and route == "/api/auth/login":
                self.send_header(
                    "Set-Cookie", "session=private-endpoint-cookie; Secure; Path=/"
                )
            self.end_headers()
            self.wfile.write(data)

        do_GET = respond
        do_POST = respond

        def log_message(self, *_args):
            pass

    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ":" in binding else socket.AF_INET

    try:
        server = Server((binding, 0), Handler)
    except OSError as error:
        if error.errno not in (errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT):
            raise
        if binding == "127.0.0.2":
            # Linux serves the full127/8 loopback range. macOS needs an existing
            # local interface; never add addresses or change host networking.
            local = socket.gethostbyname(socket.gethostname())
            if ipaddress.ip_address(local).is_loopback and sys.platform == "darwin":
                interfaces = subprocess.check_output(
                    ["/sbin/ifconfig", "-a"], text=True, timeout=5
                )
                local = next(
                    (
                        address
                        for address in re.findall(
                            r"^\s+inet ([0-9.]+) ", interfaces, re.M
                        )
                        if not ipaddress.ip_address(address).is_loopback
                    ),
                    local,
                )
            if ipaddress.ip_address(local).is_loopback:
                pytest.skip("no existing non-default IPv4 binding available")
            server = Server((local, 0), Handler)
        else:
            pytest.skip("IPv6 loopback is unavailable on this host")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, tls_pair))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[0], server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def environment(tmp_path, published, *, port_status=0):
    home, binpath = tmp_path / "home", tmp_path / "bin"
    home.mkdir()
    binpath.mkdir()
    (home / ".curlrc").write_text("")
    (tmp_path / "published").write_text(published)
    (tmp_path / "scratch").mkdir()
    docker = binpath / "docker"
    docker.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\nimport sys\n"
        f"root=Path({str(tmp_path)!r})\n"
        "args=sys.argv[1:]\n"
        "with (root/'commands').open('a') as stream: stream.write(repr(args)+'\\n')\n"
        "if args==['compose','port','gateway','8444']:\n"
        " print((root/'published').read_text(),end='')\n"
        f" sys.exit({port_status})\n"
        "if args==['compose','--env-file','.env','config','--format','json']:\n"
        ' print(\'{"services":{"bridge":{"environment":{"BRIDGE_ADMIN_USER":"admin","BRIDGE_ADMIN_PASSWORD":"private-endpoint-password"}}}}\')\n'
        " sys.exit(0)\n"
        "sys.exit(97)\n"
    )
    docker.chmod(0o700)
    return {
        "PATH": str(binpath) + os.pathsep + os.environ["PATH"],
        "HOME": str(home),
        "CURL_HOME": str(home),
        "XDG_CONFIG_HOME": str(home),
        "NO_PROXY": "*",
        "TMPDIR": str(tmp_path / "scratch"),
    }


def smoke_startup_context(tmp_path):
    """Supply the earlier startup state; isolate only external host discovery."""
    helper = re.search(
        r"^report_setup_readiness\(\) \{\n.*?^\}\n",
        QUICKSTART.read_text(),
        re.M | re.S,
    )
    assert helper is not None
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    # The real wrapper calls this owned process, without inspecting this host's
    # Docker/devices. Sender transport/discovery has its own integration suite.
    (scripts / "scanner_readiness.py").write_text(
        "import json, sys\nfrom pathlib import Path\n"
        "with Path('readiness-calls.jsonl').open('a') as stream:\n"
        "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    return "QUICKSTART_MODE=dashboard-only\nSCANNER_MANAGED=0\n" + helper.group()


def assert_readiness_after_smoke(tmp_path, succeeded):
    receipt = tmp_path / "readiness-calls.jsonl"
    calls = (
        [json.loads(line) for line in receipt.read_text().splitlines()]
        if receipt.exists()
        else []
    )
    assert calls == ([["--dashboard-only"]] if succeeded else [])


def smoke(tmp_path, env, port):
    text = QUICKSTART.read_text()
    # Include the old exact dotenv port read so quoted-port regression fails
    # for its original reason before the published-binding selector replaces it.
    old_read = re.search(
        r"^UC_PORT=\$\(grep.*?^UC_PORT=\$\{UC_PORT:-8444\}\n", text, re.M | re.S
    )
    prefix = old_read.group() if old_read else f"UC_PORT={port}\n"
    tail = text.split("# ── End-to-end smoke", 1)[1].partition("\n")[2]
    context = smoke_startup_context(tmp_path)
    result = subprocess.run(
        [
            "bash",
            "-c",
            "set -euo pipefail\n"
            + context
            + prefix
            + "describe_stack() { :; }\n"
            + tail,
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=25,
    )
    assert_readiness_after_smoke(tmp_path, result.returncode == 0)
    return result


@pytest.mark.parametrize(
    "binding,quoted",
    [
        ("127.0.0.1", False),
        ("127.0.0.2", False),
        ("0.0.0.0", False),
        ("::1", False),
        ("::", False),
        ("127.0.0.1", True),
    ],
)
def test_actual_smoke_uses_real_compose_binding_without_changing_settings(
    tmp_path, tls_pair, binding, quoted
):
    with endpoint_server(tls_pair, binding) as (host, port, requests):
        shown = f"[{host}]" if ":" in host else host
        env = environment(tmp_path, f"{shown}:{port}\n")
        (tmp_path / ".env").write_text(
            f"UC_PORT={chr(34) if quoted else ''}{port}{chr(34) if quoted else ''}\n"
        )
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(
            'services:\n  gateway:\n    image: example.invalid/not-pulled\n    ports:\n      - "'
            + shown
            + ':${UC_PORT}:8444"\n'
        )
        real_docker = shutil.which("docker")
        assert real_docker
        parsed = subprocess.run(
            [real_docker, "compose", "config", "--format", "json"],
            cwd=tmp_path,
            env=env | {"HOME": os.environ["HOME"]},
            text=True,
            capture_output=True,
            timeout=15,
        )
        assert parsed.returncode == 0, parsed.stderr
        actual = json.loads(parsed.stdout)["services"]["gateway"]["ports"][0]
        assert actual["host_ip"] == host and actual["published"] == str(port)
        before = {p.name: p.read_bytes() for p in [tmp_path / ".env", compose]}
        result = smoke(tmp_path, env, port)
        assert result.returncode == 0, result.stderr
        assert "SigRift is up." in result.stdout
        assert [item[0] for item in requests] == ROUTES
        assert requests[2][2] == {
            "username": "admin",
            "password": "private-endpoint-password",
        }
        assert all(
            "session=private-endpoint-cookie" in item[1] for item in requests[3:]
        )
        expected_host = (
            "127.0.0.1" if host == "0.0.0.0" else "::1" if host == "::" else host
        )
        expected_url = (
            f"https://[{expected_host}]:{port}/"
            if ":" in expected_host
            else f"https://{expected_host}:{port}/"
        )
        acceptable = [expected_url]
        if host in ("127.0.0.1", "0.0.0.0"):
            acceptable.append(f"https://localhost:{port}/")
        assert any(f"Dashboard:  {url}" in result.stdout for url in acceptable)
        assert {p.name: p.read_bytes() for p in [tmp_path / ".env", compose]} == before
        assert not list((tmp_path / "scratch").iterdir())
        assert "private-endpoint-password" not in result.stdout + result.stderr
        assert "private-endpoint-cookie" not in result.stdout + result.stderr


def test_selected_interface_still_rejects_failed_login_without_retry(
    tmp_path, tls_pair
):
    with endpoint_server(tls_pair, "127.0.0.2", status=503) as (host, port, requests):
        env = environment(tmp_path, f"{host}:{port}\n")
        (tmp_path / ".env").write_text(f"UC_PORT={port}\n")
        result = smoke(tmp_path, env, port)
        assert result.returncode == 1
        assert "SigRift is up." not in result.stdout
        assert "startup verification failed" in result.stderr
        assert [row[0] for row in requests] == ROUTES
        assert sum(row[0] == "/api/auth/login" for row in requests) == 1
        assert not list((tmp_path / "scratch").iterdir())


def selection(tmp_path, env):
    match = re.search(
        r"^published_gateway_url\(\) \{\n.*?^\}\n", QUICKSTART.read_text(), re.M | re.S
    )
    assert match is not None
    return subprocess.run(
        [
            "bash",
            "-c",
            "set -euo pipefail\n" + match.group() + "\npublished_gateway_url",
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=15,
    )


@pytest.mark.parametrize(
    "published,expected",
    [
        ("127.0.0.1:8444\n", "https://127.0.0.1:8444"),
        ("0.0.0.0:18443\n", "https://127.0.0.1:18443"),
        ("192.0.2.50:9443\n", "https://192.0.2.50:9443"),
        ("[::]:8444\n", "https://[::1]:8444"),
        ("[::1]:9443\n", "https://[::1]:9443"),
        ("[fd00::5]:8444\n", "https://[fd00::5]:8444"),
        ("[::ffff:127.0.0.1]:8444\n", "https://[::ffff:7f00:1]:8444"),
        ("[::]:9443\n0.0.0.0:18443\n", "https://127.0.0.1:18443"),
        ("192.0.2.50:9443\n127.0.0.1:18443\n", "https://127.0.0.1:18443"),
    ],
)
def test_published_binding_validation_and_deterministic_selection(
    tmp_path, published, expected
):
    result = selection(tmp_path, environment(tmp_path, published))
    assert result.returncode == 0, result.stderr
    from urllib.parse import urlsplit

    actual_url, expected_url = urlsplit(result.stdout.strip()), urlsplit(expected)
    assert actual_url.scheme == expected_url.scheme == "https"
    assert actual_url.port == expected_url.port
    assert ipaddress.ip_address(actual_url.hostname) == ipaddress.ip_address(
        expected_url.hostname
    )
    assert actual_url.path == actual_url.query == actual_url.fragment == ""
    if ":" in actual_url.hostname:
        assert actual_url.netloc.startswith("[") and "]:" in actual_url.netloc
    assert (tmp_path / "commands").read_text().splitlines() == [
        repr(["compose", "port", "gateway", "8444"])
    ]


@pytest.mark.parametrize(
    "published",
    [
        "",
        "\n",
        "localhost:8444",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:abc",
        "127.0.0.1:-1",
        "127.0.0.1:8444/private",
        "127.0.0.1:8444?secret=private",
        "user@127.0.0.1:8444",
        "127.0.0.1:8444;private",
        "[127.0.0.1]:8444",
        "::1:8444",
        "[not-ip]:8444",
        "[fe80::1%lo0]:8444",
        "127.0.0.1:8444\nmalformed-private",
        "999.1.1.1:8444",
    ],
)
def test_unusable_binding_fails_before_requests_without_echoing_raw_output(
    tmp_path, published
):
    result = selection(tmp_path, environment(tmp_path, published))
    assert result.returncode == 1
    assert result.stdout == ""
    assert "docker compose port gateway 8444" in result.stderr
    assert "private" not in result.stderr
    assert not list((tmp_path / "scratch").iterdir())


def test_failed_port_lookup_cannot_use_success_shaped_output(tmp_path):
    result = selection(
        tmp_path, environment(tmp_path, "127.0.0.1:8444\n", port_status=1)
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert "Cannot read" in result.stderr


def test_stalled_port_lookup_is_bounded_and_kills_only_its_process_group(tmp_path):
    import signal
    import time

    env = environment(tmp_path, "")
    shim = tmp_path / "bin/docker"
    shim.write_text(
        f"#!{sys.executable}\nimport os,subprocess,sys,time\nfrom pathlib import Path\n"
        f"child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\n"
        f"Path({str(tmp_path / 'probe-pids')!r}).write_text(str(os.getpid())+' '+str(child.pid))\n"
        "time.sleep(60)\n"
    )
    unrelated = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )
    started = time.monotonic()
    pids = []
    try:
        result = selection(tmp_path, env)
        pids = [int(pid) for pid in (tmp_path / "probe-pids").read_text().split()]
        assert result.returncode == 1
        assert "timed out after 10 seconds" in result.stderr
        assert 8 <= time.monotonic() - started < 15
        for pid in pids:
            # A killed grandchild may briefly be an init-owned zombie on Linux;
            # it cannot execute, retain sockets, or keep the probe alive.
            state = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                capture_output=True,
                text=True,
                timeout=2,
            ).stdout.strip()
            assert not state or state.startswith("Z")
        assert unrelated.poll() is None
    finally:
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        os.killpg(unrelated.pid, signal.SIGKILL)
        unrelated.wait(timeout=5)


def test_local_gateway_requests_never_use_ambient_http_proxy(tmp_path, tls_pair):
    proxy_requests = []

    class Proxy(BaseHTTPRequestHandler):
        def do_CONNECT(self):
            proxy_requests.append(self.path)
            self.send_error(502)

        def log_message(self, *_args):
            pass

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        with endpoint_server(tls_pair, "127.0.0.2") as (host, port, requests):
            env = environment(tmp_path, f"{host}:{port}\n")
            env.pop("NO_PROXY")
            env.update(
                https_proxy=f"http://127.0.0.1:{proxy.server_port}",
                HTTPS_PROXY=f"http://127.0.0.1:{proxy.server_port}",
            )
            (tmp_path / ".env").write_text(f"UC_PORT={port}\n")
            # Prove the harmless decoy proxy actually intercepts this address
            # without the shipped wrapper's explicit proxy bypass.
            control = subprocess.run(
                [
                    "curl",
                    "--disable",
                    "-skf",
                    "--max-time",
                    "3",
                    f"https://{host}:{port}/health",
                ],
                env=env,
                capture_output=True,
                timeout=5,
            )
            assert control.returncode != 0
            assert proxy_requests == [f"{host}:{port}"]
            proxy_requests.clear()
            result = smoke(tmp_path, env, port)
            assert result.returncode == 0, result.stderr
            assert [row[0] for row in requests] == ROUTES
            assert proxy_requests == []
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()
