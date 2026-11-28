"""Exercise quickstart mode decisions, Compose output, and real HTTPS smoke failures."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import threading

import pytest

from test_quickstart_endpoint import (
    assert_readiness_after_smoke,
    smoke_startup_context,
)


ROOT = Path(__file__).resolve().parents[2]
QUICKSTART = ROOT / "scripts/quickstart.sh"


def clean_env():
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COMPOSE_", "SIGRIFT_", "BRIDGE_", "UC_"))
    }


def shell(code, cwd, *, env=None):
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + code],
        cwd=cwd,
        env=clean_env() if env is None else env,
        text=True,
        capture_output=True,
        timeout=30,
    )


def function(name):
    match = re.search(
        rf"^{name}\(\) \{{\n.*?^\}}\n", QUICKSTART.read_text(), re.M | re.S
    )
    assert match, name
    return match.group()


@pytest.fixture
def tls_pair(tmp_path):
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
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
        capture_output=True,
        check=True,
    )
    return cert, key


@contextmanager
def smoke_server(tls_pair, failing_path):
    class Handler(BaseHTTPRequestHandler):
        def respond(self):
            route = self.path.partition("?")[0]
            if self.command == "POST":
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            status = 503 if route == failing_path else 200
            body = json.dumps(
                {"detail": "private diagnostic", "username": "admin"}
                if status != 200
                else {"success": True, "username": "admin"}
            ).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "application/json")
            if route == "/api/auth/login" and status == 200:
                self.send_header("Set-Cookie", "session=private-test-token; Secure")
            self.end_headers()
            self.wfile.write(body)

        do_GET = respond
        do_POST = respond

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, tls_pair))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.mark.parametrize(
    "failing_path",
    [
        "/health",
        "/api/version",
        "/api/auth/login",
        "/api/auth/me",
        "/api/detections/recent",
        None,
    ],
)
def test_actual_smoke_tail_only_announces_success_after_all_checks(
    tmp_path, tls_pair, failing_path
):
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
    env = clean_env() | {
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        "TMPDIR": str(scratch),
    }
    tail = QUICKSTART.read_text().split("# ── End-to-end smoke", 1)[1]
    tail = tail[tail.index("\n") + 1 :]
    context = smoke_startup_context(tmp_path)
    with smoke_server(tls_pair, failing_path) as port:
        env["TEST_PUBLISHED_PORT"] = str(port)
        result = shell(
            context + f"UC_PORT={port}\ndescribe_stack() {{ :; }}\n" + tail,
            tmp_path,
            env=env,
        )
    assert_readiness_after_smoke(tmp_path, failing_path is None)
    if failing_path is None:
        assert result.returncode == 0, result.stderr
        assert "SigRift is up." in result.stdout
    else:
        assert result.returncode != 0, result.stdout
        assert "SigRift is up." not in result.stdout
        assert "scripts/quickstart.sh" in result.stderr
    assert not list(scratch.iterdir()), "session cookie directory must be removed"
    assert "private-password" not in result.stdout + result.stderr
    assert "private-test-token" not in result.stdout + result.stderr
    assert "private diagnostic" not in result.stdout + result.stderr


def has_compose():
    return (
        bool(shutil.which("docker"))
        and subprocess.run(
            ["docker", "compose", "version"], capture_output=True
        ).returncode
        == 0
    )


needs_compose = pytest.mark.skipif(not has_compose(), reason="Compose CLI required")


def override_block():
    text = QUICKSTART.read_text()
    # The override's writer is a function (phase 2: an --import writes it
    # too), defined before quickstart's dispatch; the block calls it.
    writer = re.search(r"(?ms)^qs_write_override\(\) \{\n.*?^\}\n", text).group(0)
    return writer + (
        text.split("# ── Compose override:", 1)[1]
        .split("# ── Model for the `scan` service", 1)[0]
        .partition("\n")[2]
    )


def model_block():
    text = QUICKSTART.read_text()
    return (
        text.split("# ── Model for the `scan` service", 1)[1]
        .split("\n# ── Backend network subnet", 1)[0]
        .partition("\n")[2]
    )


def configure(tmp_path, request="", *, env=None):
    """Run real mode selection, new-env template, override and model work."""
    template = re.search(
        r'cat > "\$tmp_env" <<EOF\n(.*?)\nEOF\n', QUICKSTART.read_text(), re.S
    ).group(1)
    return shell(
        function("quickstart_mode")
        + f'QUICKSTART_MODE=$(quickstart_mode "{request}" plan)\n'
        + """
if [ ! -f .env ]; then
    BIND=127.0.0.1 MFA_KEY=placeholder KEYSTORE_KEY=placeholder AUDIT_KEY=placeholder
    MASTER_KEY=placeholder PROXY_SECRET=placeholder LOCAL_NODE_KEY=placeholder
    SIGRIFT_PRESET=none ADMIN_PASSWORD_ENV='"test password"'
    cat > .env <<EOF
"""
        + template
        + "\nEOF\nfi\n"
        + override_block()
        + model_block()
        + "\ndeclare -F try_download_latest_release_model\n"
        + "docker compose config --services\n",
        tmp_path,
        env=env,
    )


@pytest.fixture
def compose_project(tmp_path):
    shutil.copyfile(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    return tmp_path


@needs_compose
def test_dashboard_mode_persists_and_recreates_missing_override(compose_project):
    root = compose_project
    result = configure(root, "dashboard-only")
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("bridge\ngateway\nedge\n")
    assert "try_download_latest_release_model" in result.stdout
    assert "SIGRIFT_QUICKSTART_MODE=dashboard-only\n" in (root / ".env").read_text()
    assert not (root / "models").exists(), "dashboard-only must not prepare models"
    override = root / "docker-compose.override.yml"
    original = override.read_bytes()
    override.write_bytes(original + b"\n# Keep this operator note on every retry.\n")
    customized = override.read_bytes()
    env_before = (root / ".env").read_bytes()
    result = configure(root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("bridge\ngateway\nedge\n")
    assert override.read_bytes() == customized
    assert (root / ".env").read_bytes() == env_before
    override.unlink()
    result = configure(root)
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("bridge\ngateway\nedge\n")
    assert override.read_bytes() == original
    assert (root / ".env").read_bytes() == env_before


@needs_compose
def test_dashboard_does_not_modify_existing_models(compose_project):
    models = compose_project / "models"
    models.mkdir()
    model = models / "operator.onnx"
    model.write_bytes(b"operator-selected-model")
    model.chmod(0o600)
    (models / "open-default.onnx").symlink_to(model.name)
    before = model.stat()
    result = configure(compose_project, "dashboard-only")
    assert result.returncode == 0, result.stderr
    assert model.read_bytes() == b"operator-selected-model"
    assert model.stat().st_mode == before.st_mode
    assert model.stat().st_mtime_ns == before.st_mtime_ns
    assert (models / "open-default.onnx").readlink() == Path(model.name)


@needs_compose
@pytest.mark.parametrize("generated_header", [True, False])
def test_plain_retry_preserves_legacy_custom_override(
    compose_project, generated_header
):
    root = compose_project
    (root / ".env").write_text("BRIDGE_ADMIN_PASSWORD=operator-secret\n")
    models = root / "models"
    models.mkdir()
    (models / "operator.onnx").write_bytes(b"model")
    override = root / "docker-compose.override.yml"
    original = (
        ("# Generated by scripts/quickstart.sh\n" if generated_header else "")
        + "services:\n  edge:\n    environment:\n      OPERATOR_SETTING: preserved\n"
    ).encode()
    override.write_bytes(original)
    result = configure(root)
    assert result.returncode == 0, result.stderr
    assert override.read_bytes() == original
    assert (root / ".env").read_text() == "BRIDGE_ADMIN_PASSWORD=operator-secret\n"
    assert "rtl-tcp\n" in result.stdout


@needs_compose
@pytest.mark.parametrize("existing", ["env", "override", "both"])
def test_dashboard_flag_refuses_ambiguous_existing_install_before_writes(
    compose_project, existing
):
    root = compose_project
    if existing in {"env", "both"}:
        (root / ".env").write_text("BRIDGE_ADMIN_PASSWORD=operator-secret\n")
    if existing in {"override", "both"}:
        (root / "docker-compose.override.yml").write_text("services: {}\n")
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    result = configure(root, "dashboard-only")
    assert result.returncode != 0
    assert "cannot change an existing installation automatically" in result.stderr
    assert "QUICKSTART.md" in result.stderr
    assert "operator-secret" not in result.stdout + result.stderr
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


@needs_compose
@pytest.mark.parametrize("setting", ["COMPOSE_PROFILES", "COMPOSE_FILE"])
@pytest.mark.parametrize("location", ["shell", "dotenv"])
def test_dashboard_rejects_effective_compose_overrides_before_writes(
    compose_project, setting, location
):
    root = compose_project
    (root / ".env").write_text("SIGRIFT_QUICKSTART_MODE=dashboard-only\n")
    value = "hardware" if setting == "COMPOSE_PROFILES" else "docker-compose.yml"
    env = clean_env()
    if location == "shell":
        env[setting] = value
    else:
        with (root / ".env").open("a") as out:
            out.write(f"{setting}={value}\n")
    before = {p.name: p.read_bytes() for p in root.iterdir()}
    result = configure(root, env=env)
    assert result.returncode != 0
    assert "COMPOSE_FILE and COMPOSE_PROFILES unset" in result.stderr
    assert {p.name: p.read_bytes() for p in root.iterdir()} == before


@needs_compose
def test_dashboard_detects_hardware_reenabled_in_existing_override(compose_project):
    root = compose_project
    assert configure(root, "dashboard-only").returncode == 0
    override = root / "docker-compose.override.yml"
    override.write_text(
        override.read_text().replace('profiles: ["hardware"]', "profiles: []", 1)
    )
    before = override.read_bytes()
    result = configure(root)
    assert result.returncode != 0
    assert "must resolve exactly bridge, gateway and edge" in result.stderr
    assert override.read_bytes() == before


@needs_compose
def test_explicit_hardware_enable_uses_existing_dashboard_override(compose_project):
    root = compose_project
    assert configure(root, "dashboard-only").returncode == 0
    override = (root / "docker-compose.override.yml").read_bytes()
    envfile = root / ".env"
    envfile.write_text(
        envfile.read_text().replace(
            "SIGRIFT_QUICKSTART_MODE=dashboard-only", "SIGRIFT_QUICKSTART_MODE=hardware"
        )
        + "COMPOSE_PROFILES=hardware\n"
    )
    models = root / "models"
    models.mkdir()
    (models / "operator.onnx").write_bytes(b"model")
    result = configure(root)
    assert result.returncode == 0, result.stderr
    assert set(result.stdout.splitlines()[-7:]) == {
        "bridge",
        "gateway",
        "edge",
        "rtl-tcp",
        "scan",
        "wifi-scan",
        "bt-scan",
    }
    assert (root / "docker-compose.override.yml").read_bytes() == override
    assert (models / "open-default.onnx").readlink() == Path("operator.onnx")


@needs_compose
@pytest.mark.parametrize(
    "setting",
    [
        "SIGRIFT_QUICKSTART_MODE=other\n",
        "SIGRIFT_QUICKSTART_MODE=dashboard-only\nSIGRIFT_QUICKSTART_MODE=hardware\n",
        "export SIGRIFT_QUICKSTART_MODE='dashboard-only'\n",
    ],
)
def test_ambiguous_mode_assignment_refuses_without_writes(compose_project, setting):
    (compose_project / ".env").write_text(setting)
    result = configure(compose_project)
    assert result.returncode != 0
    assert "one plain SIGRIFT_QUICKSTART_MODE" in result.stderr
    assert not (compose_project / "docker-compose.override.yml").exists()
    assert not (compose_project / "models").exists()


@needs_compose
def test_complete_cli_builds_only_dashboard_services_and_keeps_retry_mode(tmp_path):
    """Run the unchanged CLI through real TLS setup; intercept only daemon I/O."""
    import sys

    root = tmp_path / "checkout"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(QUICKSTART, root / "scripts/quickstart.sh")
    shutil.copyfile(ROOT / "docker-compose.yml", root / "docker-compose.yml")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "commands.jsonl"
    real_docker = shutil.which("docker")
    docker = bindir / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        + f"real = {real_docker!r}\nlog = {str(log)!r}\n"
        + """import json, os, subprocess, sys
args = sys.argv[1:]
record = {'args': args}
if args == ['compose', 'build']:
    record['services'] = subprocess.check_output(
        [real, 'compose', 'config', '--services'], text=True).splitlines()
with open(log, 'a') as target:
    target.write(json.dumps(record) + '\\n')
if args[:2] == ['compose', 'config'] or args == ['compose', 'version']:
    os.execv(real, [real, *args])
if args[:2] == ['info', '--format'] or args == ['network', 'ls', '-q']:
    sys.exit(0)
if args[:2] == ['volume', 'ls'] or (args[:1] == ['ps'] and any(a in ('-a', '-q') for a in args)):
    sys.exit(0)  # lc_identity's read-only queries: an empty host
# No build, pull, helper container or other daemon operation is executed.
sys.exit(77 if args == ['compose', 'build'] else 97)
"""
    )
    docker.chmod(0o700)
    curl = bindir / "curl"
    curl.write_text("#!/bin/sh\necho unexpected-network-request >&2\nexit 96\n")
    curl.chmod(0o700)
    env = clean_env() | {
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        "SIGRIFT_PRESET": "none",
    }
    saved_env = saved_override = None
    for arguments in (["--dashboard-only"], [], []):
        result = subprocess.run(
            ["bash", str(root / "scripts/quickstart.sh"), *arguments],
            env=env,
            input="disposable-dashboard-password\ndisposable-dashboard-password\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 77, result.stdout + result.stderr
        assert "unexpected-network-request" not in result.stderr
        assert "disposable-dashboard-password" not in result.stdout + result.stderr
        assert not (root / "models").exists()
        assert (root / ".env").stat().st_mode & 0o777 == 0o600
        assert (root / "tls/cert.pem").is_file()
        current_env = (root / ".env").read_bytes()
        current_override = (root / "docker-compose.override.yml").read_bytes()
        if saved_env is None:
            saved_env, saved_override = current_env, current_override
        else:
            assert current_env == saved_env
            assert current_override == saved_override
        # Recovery from a missing generated override must retain the mode.
        (root / "docker-compose.override.yml").unlink()
    calls = [json.loads(line) for line in log.read_text().splitlines()]
    builds = [call for call in calls if call["args"] == ["compose", "build"]]
    assert len(builds) == 3
    assert all(
        set(call["services"]) == {"bridge", "gateway", "edge"} for call in builds
    )
    assert not any("pull" in call["args"] for call in calls)


@needs_compose
@pytest.mark.parametrize("alternate", ["compose.yml", "docker-compose.override.yaml"])
def test_dashboard_refuses_ambiguous_compose_filenames(compose_project, alternate):
    (compose_project / alternate).write_text("services: {}\n")
    result = configure(compose_project, "dashboard-only")
    assert result.returncode != 0
    assert "without alternate Compose filenames" in result.stderr
    assert not (compose_project / ".env").exists()


@needs_compose
def test_dashboard_refuses_symlink_override(compose_project):
    (compose_project / ".env").write_text("SIGRIFT_QUICKSTART_MODE=dashboard-only\n")
    target = compose_project / "operator.yml"
    target.write_text("services: {}\n")
    (compose_project / "docker-compose.override.yml").symlink_to(target.name)
    result = configure(compose_project)
    assert result.returncode != 0
    assert "requires a regular docker-compose.override.yml" in result.stderr
    assert target.read_text() == "services: {}\n"


@pytest.mark.parametrize(
    "arguments", [["--dashboard-only", "--renew-tls"], ["--unknown"]]
)
def test_invalid_cli_arguments_do_not_touch_installation(tmp_path, arguments):
    script = tmp_path / "scripts/quickstart.sh"
    script.parent.mkdir()
    shutil.copyfile(QUICKSTART, script)
    result = subprocess.run(
        ["bash", str(script), *arguments], capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 2
    assert "--dashboard-only" in result.stderr and "--renew-tls" in result.stderr
    assert not (tmp_path / ".env").exists()


@needs_compose
def test_renewal_also_refuses_dashboard_profile_override_before_tls_writes(tmp_path):
    root = tmp_path / "checkout"
    (root / "scripts").mkdir(parents=True)
    shutil.copyfile(QUICKSTART, root / "scripts/quickstart.sh")
    shutil.copyfile(ROOT / "docker-compose.yml", root / "docker-compose.yml")
    (root / ".env").write_text("SIGRIFT_QUICKSTART_MODE=dashboard-only\n")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    docker = bindir / "docker"
    docker.write_text(
        '#!/bin/sh\nif [ "$1" = info ]; then exit 0; fi\n'
        + f'exec "{shutil.which("docker")}" "$@"\n'
    )
    docker.chmod(0o700)
    # Renewal-only does not build an override, so it cannot safely proceed
    # after a profile override or missing generated file.
    result = subprocess.run(
        ["bash", str(root / "scripts/quickstart.sh"), "--renew-tls"],
        env=clean_env()
        | {
            "COMPOSE_PROFILES": "hardware",
            "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
        },
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode != 0
    assert "COMPOSE_FILE and COMPOSE_PROFILES unset" in result.stderr
    assert not (root / "tls").exists()
