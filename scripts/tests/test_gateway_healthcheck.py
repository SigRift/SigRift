"""Exercise the shipped health probe against real HTTP and TLS listeners."""

from __future__ import annotations

import contextlib
import http.server
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import threading

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "src/gateway/healthcheck.sh"


@pytest.fixture(scope="module")
def tls_material(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl is required for the TLS health regression")
    directory = tmp_path_factory.mktemp("health-tls")
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=operator.example",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


@contextlib.contextmanager
def listener(*, tls=None, status=200):
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'{"status":"ok"}'
            self.send_response(status)
            # Frame the body explicitly. Newer OpenSSL rejects a TLS EOF
            # without close_notify when HTTP relies on connection-close.
            self.send_header("Content-Length", str(len(body)))
            if status == 302:
                self.send_header("Location", "/not-health")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(*tls)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def probe(port, *, tls=None, **extra):
    if not shutil.which("curl"):
        pytest.skip("curl is required for the health regression")
    env = {
        "PATH": os.environ["PATH"],
        "UC_PORT": str(port),
        # The health probe must ignore proxy settings even with NO_PROXY
        # absent: it must never send this request outside the container.
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
    }
    if tls:
        env.update(UC_TLS_CERT=str(tls[0]), UC_TLS_KEY=str(tls[1]))
    env.update(extra)
    return subprocess.run(
        ["sh", str(PROBE)],
        env=env,
        capture_output=True,
        text=True,
        timeout=6,
    )


@pytest.mark.parametrize("encrypted", [False, True])
def test_local_health_succeeds_in_the_gateways_configured_mode(tls_material, encrypted):
    tls = tls_material if encrypted else None
    with listener(tls=tls) as (port, requests):
        result = probe(port, tls=tls)
    assert result.returncode == 0, result.stderr
    assert requests == ["/health"]


@pytest.mark.parametrize("encrypted", [False, True])
def test_wrong_protocol_is_unhealthy(tls_material, encrypted):
    with listener(tls=tls_material if encrypted else None) as (port, _requests):
        result = probe(port, tls=None if encrypted else tls_material)
    assert result.returncode != 0


@pytest.mark.parametrize("status", [302, 401, 500])
def test_redirects_and_error_responses_are_unhealthy(tls_material, status):
    with listener(tls=tls_material, status=status) as (port, requests):
        result = probe(port, tls=tls_material)
    assert result.returncode != 0
    assert requests == ["/health"]  # redirects are never followed


@pytest.mark.parametrize("key", ["UC_TLS_CERT", "UC_TLS_KEY"])
def test_incomplete_tls_configuration_is_unhealthy(key):
    result = probe(8444, **{key: "/certificate-or-key.pem"})
    assert result.returncode != 0
    assert "requires both" in result.stderr


@pytest.mark.parametrize("port", ["0", "65536", "bad", "8444/path", "$(false)"])
def test_invalid_ports_fail_without_building_a_url(port):
    result = probe(port)
    assert result.returncode != 0
    assert "Invalid UC_PORT" in result.stderr


def test_every_shipped_container_uses_the_same_probe():
    # These are the three deployment entry points that used to probe HTTP
    # even though the installer configured TLS on the same port.
    assert (
        "COPY --chmod=755 src/gateway/healthcheck.sh /app/healthcheck.sh"
        in (ROOT / "src/gateway/Dockerfile").read_text()
    )
    assert (
        'CMD ["/app/healthcheck.sh"]' in (ROOT / "src/gateway/Dockerfile").read_text()
    )
    for path in ("docker-compose.yml", "scripts/install-release.sh"):
        text = (ROOT / path).read_text()
        if path.endswith(".sh"):
            # The upgrade helper must still recognize the old HTTP probe.
            # Validate the emitted configuration, not migration input strings.
            text = text.split("cat > docker-compose.yml <<EOF\n", 1)[1].split(
                "\nEOF", 1
            )[0]
        assert 'test: ["CMD", "/app/healthcheck.sh"]' in text, path
        assert "http://localhost:8444/health" not in text, path


def test_quickstart_smoke_is_a_real_pull_request_gate():
    yaml = pytest.importorskip("yaml")
    workflow = yaml.load(
        (ROOT / ".github/workflows/quickstart-smoke.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    assert "pull_request" in workflow["on"]
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["quickstart-smoke"]
    assert job["runs-on"] == "ubuntu-24.04"
    assert job.get("continue-on-error", "false") == "false"
    assert not any(step.get("continue-on-error") == "true" for step in job["steps"])
