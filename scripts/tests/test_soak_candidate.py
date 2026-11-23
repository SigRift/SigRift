"""Real HTTP contracts and bounded lifecycle/provenance for the soak runner."""

from contextlib import contextmanager
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
from threading import Thread
import time

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "soak_under_test", ROOT / "scripts/soak-candidate.py"
)
soak = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(soak)
SECRET = "private-soak-credential-never-share"


@contextmanager
def api_server(failure=None):
    state = {
        "sessions": set(),
        "logouts": [],
        "calls": [],
        "rows": {},
        "batches": set(),
        "created": 0,
        "revoked": False,
        "next_session": 0,
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def handle_request(self):
            state["calls"].append((self.command, self.path))
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            body = json.loads(raw) if raw else None
            cookie = self.headers.get("Cookie", "")
            token = next(
                (v for v in state["sessions"] if f"session_token={v}" in cookie), None
            )
            headers = []
            code, result = 200, {}
            if self.path == "/api/auth/login":
                assert body == {"username": "admin", "password": SECRET}
                state["next_session"] += 1
                token = f"{SECRET}-{state['next_session']}"
                state["sessions"].add(token)
                # As the gateway: the session only in an HttpOnly cookie
                # (newer gateways no longer return it in the body).
                headers = [
                    ("Set-Cookie", f"session_token={token}; Path=/; HttpOnly"),
                    ("Set-Cookie", "csrf_token=csrf-fixture; Path=/"),
                ]
                result = {"csrf_token": "csrf-fixture"}
            elif self.path == "/health":
                result = {
                    "post_ingest_hooks": {
                        "enabled": True,
                        "failed_batches": int(failure == "hooks"),
                        "dropped_batches": 0,
                        "enqueued_batches": len(state["batches"]),
                        "delivered_batches": len(state["batches"]),
                    }
                }
            elif self.path == "/api/ready":
                result = {"status": "ready"}
            elif self.path == "/api/detections/batch":
                assert self.headers.get("X-API-Key") == SECRET
                if state["revoked"]:
                    code = 401
                elif failure == "ingest500":
                    code = 500
                else:
                    duplicate = body["batch_id"] in state["batches"]
                    row = body["detections"][0] | {"node_id": body["node_id"]}
                    state["rows"][row["detection_id"]] = row
                    state["batches"].add(body["batch_id"])
                    result = {
                        "inserted": 1 if failure == "dedup" else int(not duplicate),
                        "rejected": 0,
                    }
            elif token is None:
                code = 401
            else:
                if self.command in {"POST", "DELETE"}:
                    assert self.headers.get("X-CSRF-Token") == "csrf-fixture"
                if self.path == "/api/auth/me":
                    result = {"username": "admin"}
                elif self.path == "/api/auth/logout":
                    state["sessions"].remove(token)
                    state["logouts"].append(token)
                elif self.path in {"/api/status", "/api/nodes/register"}:
                    result = {}
                elif self.path == "/api/admin/keys":
                    state["created"] += 1
                    code, result = 201, {"key_id": "owned_key", "raw_key": SECRET}
                    if failure == "key_contract":
                        result.pop("raw_key")
                elif (
                    self.path == "/api/admin/keys/owned_key"
                    and self.command == "DELETE"
                ):
                    state["revoked"] = True
                elif self.path.startswith("/api/detections/"):
                    result = state["rows"][self.path.rsplit("/", 1)[1]].copy()
                    if failure == "readback":
                        result["node_id"] = "wrong-node"
                    elif failure == "read401":
                        code = 401
                else:
                    raise AssertionError("Unexpected test API route")
            self.send_response(code)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())

        do_GET = do_POST = do_DELETE = handle_request

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        settings = soak.Settings(
            f"http://127.0.0.1:{server.server_port}",
            "admin",
            SECRET,
            ssl.create_default_context(),
        )
        yield soak.Protocol(settings, "soak-synthetic-node"), state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_short_real_http_soak_uses_exact_readback_dedup_and_revokes_old_sessions(
    monkeypatch, tmp_path
):
    foreign_sink = tmp_path / "foreign-events.jsonl"
    foreign_sink.write_text("untouched\n")
    monkeypatch.setenv("SIGRIFT_E2E_DIAGNOSTICS", str(foreign_sink))
    soak.isolate_parent_diagnostics()
    with api_server() as (protocol, state):
        protocol.setup()
        old_session = next(iter(state["sessions"]))
        samples = []
        started = time.monotonic()
        measured = soak.scheduled_soak(
            1,
            0.5,
            lambda sequence, elapsed, late: samples.append(protocol.cycle(sequence)),
        )
        assert time.monotonic() - started >= 1
        assert measured["cycles"] == len(samples) == 3
        assert measured["elapsed_seconds"] >= 1
        protocol.login()
        assert state["logouts"] == [old_session]
        assert old_session not in state["sessions"]
        assert len(state["sessions"]) == 1
        protocol.close()
        assert state["sessions"] == set()
        assert state["created"] == 1 and state["revoked"]
        assert len(state["batches"]) == len(state["rows"]) == 3
        assert state["calls"][-2:] == [
            ("POST", "/api/detections/batch"),
            ("POST", "/api/auth/logout"),
        ]
    assert foreign_sink.read_text() == "untouched\n"


@pytest.mark.parametrize(
    "failure", ["readback", "read401", "dedup", "hooks", "ingest500"]
)
def test_real_http_functional_failures_stop_instead_of_becoming_success(failure):
    with api_server(failure) as (protocol, state):
        protocol.setup()
        with pytest.raises((AssertionError, RuntimeError)):
            protocol.cycle(0)
        inserts = [
            call for call in state["calls"] if call == ("POST", "/api/detections/batch")
        ]
        assert len(inserts) == (
            0 if failure == "hooks" else 2 if failure == "dedup" else 1
        )


def test_valid_key_id_is_revoked_even_when_success_body_lacks_credential():
    with api_server("key_contract") as (protocol, state):
        with pytest.raises(RuntimeError, match="Invalid sensor key"):
            protocol.setup()
        protocol.close()
        assert state["revoked"]
        assert state["sessions"] == set()


def test_schedule_visits_endpoint_without_skipping_or_claiming_wall_time():
    now, seen = [0.0], []
    measured = soak.scheduled_soak(
        12,
        5,
        lambda *args: seen.append(args),
        clock=lambda: now[0],
        sleep=lambda n: now.__setitem__(0, now[0] + n),
    )
    assert [row[1] for row in seen] == [0, 5, 10, 12]
    assert measured == {"cycles": 4, "elapsed_seconds": 12}


def test_missed_interval_and_cycle_failure_cannot_be_skipped():
    now, seen = [0.0], []

    def delayed(*args):
        seen.append(args)
        now[0] += 11

    with pytest.raises(RuntimeError, match="interval was missed"):
        soak.scheduled_soak(20, 5, delayed, clock=lambda: now[0], sleep=lambda _: None)
    assert len(seen) == 1

    def broken(*_args):
        raise ValueError("real failed assertion")

    with pytest.raises(ValueError, match="real failed assertion"):
        soak.scheduled_soak(20, 5, broken)


@pytest.mark.parametrize(
    "mounted_owner,insufficient_space",
    [
        (None, False),
        (None, True),
        ({"uid": 0, "gid": 0}, False),
        ({"uid": -1, "gid": 0}, False),
        ({"uid": True, "gid": 0}, False),
        ({"uid": "1000", "gid": 1000}, False),
        ({"uid": 1000}, False),
    ],
)
def test_disk_preflight_keeps_owner_only_probe_and_cleans_its_volume(
    tmp_path, mounted_owner, insufficient_space
):
    dockerfile = tmp_path / "src/sigrift/bridge/Dockerfile"
    dockerfile.parent.mkdir(parents=True)
    base = "python:3.11-slim@sha256:" + "a" * 64
    dockerfile.write_text(f"FROM {base} AS runtime\n")
    project = "sigrift-soak-permission-test"
    volume = project + "_preflight"

    class ProbeRunner:
        volume_exists = False
        probe_executed = False
        owner = None

        def run(self, name, command, **kwargs):
            if name == "preflight-base":
                assert command == ["docker", "pull", base]
            else:
                assert command == ["docker", "volume", "rm", volume]
                self.volume_exists = False

        def capture(self, *command):
            if command[:3] == ("docker", "volume", "create"):
                self.volume_exists = True
                return volume
            if command[:2] == ("docker", "run"):
                assert {"--cap-drop=ALL", "--network=none", "--read-only"} <= set(
                    command
                )
                assert "--security-opt=no-new-privileges" in command
                assert (
                    f"type=bind,source={tmp_path},target=/candidate,readonly" in command
                )
                marker = tmp_path / ".soak-bind-check"
                assert marker.stat().st_uid == os.getuid()
                assert marker.stat().st_mode & 0o777 == 0o600
                # Execute the actual probe code against real owner-only files;
                # the separate Docker rehearsal verifies Linux capability rules.
                code = command[-1].replace("/candidate/", str(tmp_path) + "/")
                code = code.replace("'/probe'", repr(str(tmp_path)))
                if "--user" not in command:
                    assert ".read_text()" not in code
                    measured = json.loads(
                        subprocess.check_output([sys.executable, "-c", code], text=True)
                    )
                    assert measured == {"uid": os.getuid(), "gid": os.getgid()}
                    self.owner = measured if mounted_owner is None else mounted_owner
                    return json.dumps(self.owner)
                assert self.owner is not None
                assert (
                    command[command.index("--user") + 1]
                    == f"{self.owner['uid']}:{self.owner['gid']}"
                )
                self.probe_executed = True
                return subprocess.check_output([sys.executable, "-c", code], text=True)
            assert "--filter" in command
            assert f"label=com.docker.compose.project={project}" in command
            return (
                volume
                if command[:3] == ("docker", "volume", "ls") and self.volume_exists
                else ""
            )

    runner = ProbeRunner()
    invalid_owner = mounted_owner is not None and (
        set(mounted_owner) != {"uid", "gid"}
        or any(type(value) is not int or value < 0 for value in mounted_owner.values())
    )
    previous_umask = os.umask(0o077)
    try:
        if invalid_owner:
            with pytest.raises(RuntimeError, match="Invalid mounted probe ownership"):
                soak.disk_preflight(runner, project, tmp_path, 1)
        elif insufficient_space:
            with pytest.raises(RuntimeError, match="Insufficient Docker filesystem"):
                soak.disk_preflight(runner, project, tmp_path, sys.maxsize)
        else:
            measured = soak.disk_preflight(runner, project, tmp_path, 1)
            assert 0 < measured["free_bytes"] <= measured["total_bytes"]
    finally:
        os.umask(previous_umask)
    assert runner.probe_executed is not invalid_owner
    assert not runner.volume_exists
    assert not (tmp_path / ".soak-bind-check").exists()


def config(source, project="sigrift-soak-test"):
    return {
        "services": {
            "bridge": {
                "volumes": [
                    {"type": "volume", "source": "bridge_data", "target": "/data"}
                ]
            },
            "gateway": {
                "ports": [{"host_ip": "127.0.0.1", "published": "18444"}],
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(source / "tls"),
                        "target": "/app/tls",
                        "read_only": True,
                    }
                ],
            },
            "edge": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(source / "tls/cert.pem"),
                        "target": "/app/tls/cert.pem",
                        "read_only": True,
                    }
                ]
            },
        },
        "volumes": {"bridge_data": {"name": project + "_bridge_data"}},
        "networks": {"default": {"name": project + "_default"}},
    }


@pytest.mark.parametrize(
    "bad", ["external", "port", "device", "capability", "bind", "symlink", "writable"]
)
def test_scope_rejects_resources_outside_owned_hardware_free_stack(tmp_path, bad):
    cfg = config(tmp_path)
    soak.verify_scope(cfg, "sigrift-soak-test", 18444, tmp_path)
    if bad == "external":
        cfg["volumes"]["bridge_data"]["external"] = True
    elif bad == "port":
        cfg["services"]["bridge"]["ports"] = [{"published": "8001"}]
    elif bad == "device":
        cfg["services"]["edge"]["devices"] = ["/dev/bus/usb"]
    elif bad == "capability":
        cfg["services"]["edge"]["cap_add"] = ["NET_ADMIN"]
    elif bad == "bind":
        cfg["services"]["gateway"]["volumes"][0]["source"] = "/var/run/docker.sock"
    elif bad == "writable":
        cfg["services"]["gateway"]["volumes"][0]["read_only"] = False
    else:
        (tmp_path / "tls").symlink_to(tmp_path.parent)
    with pytest.raises(RuntimeError):
        soak.verify_scope(cfg, "sigrift-soak-test", 18444, tmp_path)


def rows():
    return [
        dict(
            service=name,
            project="owned",
            id=name + "123",
            image=name + "image",
            started_at="same",
            running=True,
            oom_killed=False,
            restarts=0,
            health=None if name == "edge" else "healthy",
        )
        for name in sorted(soak.SERVICES)
    ]


@contextmanager
def docker_inspect_api(containers):
    """Exercise Docker's real Go formatter with controlled Engine responses."""
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self):
            path = self.path.partition("?")[0]
            calls.append(path)
            if path.endswith("/_ping"):
                body = b"OK"
            else:
                name = path.removesuffix("/json").rsplit("/", 1)[-1]
                if "/containers/" not in path or name not in containers:
                    self.send_error(404)
                    return
                body = json.dumps(containers[name]).encode()
            self.send_response(200)
            self.send_header("API-Version", "1.47")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = respond
        do_HEAD = respond

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"tcp://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


@pytest.mark.parametrize(
    "service,health,accepted",
    [
        ("edge", "absent", True),
        ("edge", None, True),
        ("bridge", "healthy", True),
        ("gateway", "healthy", True),
        ("bridge", "absent", False),
        ("gateway", None, False),
        ("bridge", "unhealthy", False),
        ("gateway", "starting", False),
    ],
)
def test_real_docker_formatter_and_service_health_policy(
    tmp_path, service, health, accepted
):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is required; no Docker daemon is used")
    containers = {}
    for row in rows():
        name = row["service"]
        state = {
            "StartedAt": row["started_at"],
            "Running": True,
            "OOMKilled": False,
        }
        value = health if name == service else row["health"]
        if value != "absent":
            state["Health"] = None if value is None else {"Status": value}
        containers[name] = {
            "Id": row["id"],
            "Image": row["image"],
            "State": state,
            "RestartCount": 0,
            "Config": {
                "Env": ["PRIVATE_FIXTURE=must-not-appear"],
                "Labels": {
                    "com.docker.compose.project": "owned",
                    "com.docker.compose.service": name,
                },
            },
        }
    with docker_inspect_api(containers) as (endpoint, calls):
        result = subprocess.run(
            [
                docker,
                "--host",
                endpoint,
                "inspect",
                "--format",
                soak.INSPECT,
                *sorted(containers),
            ],
            env={
                "PATH": os.environ["PATH"],
                "HOME": str(tmp_path),
                "DOCKER_CONFIG": str(tmp_path),
                "DOCKER_API_VERSION": "1.47",
                "NO_PROXY": "127.0.0.1",
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode == 0, result.stderr
    actual = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(actual) == 3
    assert "must-not-appear" not in result.stdout + result.stderr
    assert {key for item in actual for key in item} == set(rows()[0])
    selected = next(item for item in actual if item["service"] == service)
    assert selected["health"] == (None if health == "absent" else health)
    assert all(
        any(f"/containers/{name}/json" in path for path in calls) for name in containers
    )
    if accepted:
        assert set(soak.validate_containers(actual, "owned")) == soak.SERVICES
    else:
        with pytest.raises(RuntimeError, match="Soak service is unhealthy"):
            soak.validate_containers(actual, "owned")


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", "replaced"),
        ("image", "different"),
        ("started_at", "later"),
        ("running", False),
        ("oom_killed", True),
        ("restarts", 1),
        ("health", "unhealthy"),
        ("project", "unrelated"),
    ],
)
def test_restart_replacement_oom_and_health_fail_observation(field, value):
    initial = rows()
    baseline = soak.validate_containers(initial, "owned")
    changed = copy.deepcopy(initial)
    changed[0][field] = value
    with pytest.raises(RuntimeError):
        soak.validate_containers(changed, "owned", baseline)


def test_stats_include_every_owned_service_and_no_unfiltered_fields():
    containers = soak.validate_containers(rows(), "owned")
    raw = "\n".join(
        json.dumps(
            {
                "ID": row["id"],
                "MemUsage": "1.5MiB / 4GiB",
                "CPUPerc": "2.50%",
                "PIDs": "3",
                "Unknown": SECRET,
            }
        )
        for row in containers.values()
    )
    measured = soak.parse_stats(raw, containers)
    assert set(measured) == soak.SERVICES
    assert all(
        row == {"memory_bytes": 1572864, "cpu_percent": 2.5, "pids": 3}
        for row in measured.values()
    )
    assert SECRET not in json.dumps(measured)
    with pytest.raises(RuntimeError, match="Missing Docker"):
        soak.parse_stats(raw.splitlines()[0], containers)


class CleanupRunner:
    def __init__(self, source, fail_logs=False, leftover=False):
        self.source, self.fail_logs, self.leftover = source, fail_logs, leftover
        self.commands = []

    def capture(self, *command):
        self.commands.append(command)
        if command[:3] == ("docker", "compose", "config"):
            return json.dumps(config(self.source))
        if (
            self.leftover
            and command[:3] == ("docker", "ps", "-aq")
            and not any("name=" in arg for arg in command)
        ):
            return "stopped-owned-container\n"
        assert "--filter" in command
        assert "label=com.docker.compose.project=sigrift-soak-test" in command
        return ""

    def run(self, name, command, **_kwargs):
        self.commands.append(tuple(command))
        if name == "service-logs" and self.fail_logs:
            raise RuntimeError("logging failed")


@pytest.mark.parametrize("fail_logs", [False, True])
def test_logging_failure_does_not_skip_scoped_cleanup_or_secret_deletion(
    tmp_path, fail_logs
):
    (tmp_path / ".env").write_text(SECRET)
    (tmp_path / ".env.backup").write_text(SECRET)
    (tmp_path / "tls").mkdir()
    (tmp_path / "tls/key.pem").write_text(SECRET)
    runner = CleanupRunner(tmp_path, fail_logs)
    assert soak.cleanup(runner, "sigrift-soak-test", tmp_path, 18444) is (not fail_logs)
    assert ("docker", "compose", "down", "-v", "--remove-orphans") in runner.commands
    assert any(command[:3] == ("docker", "ps", "-aq") for command in runner.commands)
    assert not (tmp_path / ".env").exists() and not (tmp_path / ".env.backup").exists()
    assert not (tmp_path / "tls").exists()
    assert all("prune" not in command for command in runner.commands)


def test_leftover_stopped_container_fails_cleanup_and_keeps_debug_secrets(tmp_path):
    (tmp_path / ".env").write_text(SECRET)
    assert not soak.cleanup(
        CleanupRunner(tmp_path, leftover=True), "sigrift-soak-test", tmp_path, 18444
    )
    assert (tmp_path / ".env").read_text() == SECRET


@pytest.mark.skipif(
    os.geteuid() == 0, reason="Root bypasses directory write permissions"
)
def test_real_secret_removal_error_fails_cleanup_without_raising(tmp_path):
    tls = tmp_path / "tls"
    tls.mkdir()
    (tls / "key.pem").write_text(SECRET)
    tls.chmod(0o500)
    try:
        assert not soak.cleanup(
            CleanupRunner(tmp_path), "sigrift-soak-test", tmp_path, 18444
        )
        assert (tls / "key.pem").read_text() == SECRET
    finally:
        tls.chmod(0o700)


def test_capture_timeout_kills_the_subprocess(tmp_path, monkeypatch):
    runner = soak.Runner(tmp_path, tmp_path, os.environ.copy())
    monkeypatch.setattr(runner, "budget", lambda _: 0.3)
    pidfile = tmp_path / "pid"
    with pytest.raises(subprocess.TimeoutExpired):
        runner.capture(
            sys.executable,
            "-c",
            "import os,time,pathlib; "
            f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(60)",
        )
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_parent_tls_context_does_not_write_caller_selected_session_secrets(
    tmp_path, monkeypatch
):
    path = tmp_path / "ambient-tls-secrets"
    monkeypatch.setenv("SSLKEYLOGFILE", str(path))
    assert ssl.create_default_context().keylog_filename == str(path)
    path.unlink()
    soak.isolate_parent_diagnostics()
    assert ssl.create_default_context().keylog_filename is None
    assert not path.exists()


def test_child_environment_does_not_inherit_github_registry_or_home_credentials(
    tmp_path, monkeypatch
):
    original = tmp_path / "original-docker"
    (original / "cli-plugins").mkdir(parents=True)
    plugin = original / "cli-plugins/docker-compose"
    plugin.write_text("nonsecret-tool")
    (original / "config.json").write_text(SECRET)
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "SSH_AUTH_SOCK",
        "DOCKER_AUTH_CONFIG",
        "DOCKER_DEFAULT_PLATFORM",
        "BUILDX_BUILDER",
        "BUILDKIT_HOST",
        "BUILDX_CONFIG",
        "CURL_HOME",
        "XDG_CONFIG_HOME",
        "GH_CONFIG_DIR",
        "COMPOSE_FILE",
    ):
        monkeypatch.setenv(key, SECRET)
    monkeypatch.setenv("DOCKER_HOST", "unix:///owned/docker.sock")
    monkeypatch.setenv("DOCKER_CONFIG", str(original))
    env = soak.isolated_environment(tmp_path / "run")
    assert SECRET not in json.dumps(env)
    assert env["DOCKER_HOST"] == "unix:///owned/docker.sock"
    assert env["HOME"] == str(tmp_path / "run/private-home")
    home = Path(env["HOME"])
    for variable in ("CURL_HOME", "XDG_CONFIG_HOME", "GH_CONFIG_DIR", "BUILDX_CONFIG"):
        assert Path(env[variable]).is_relative_to(home)
        assert Path(env[variable]).is_dir()
    assert (Path(env["CURL_HOME"]) / ".curlrc").read_text() == ""
    copied = Path(env["DOCKER_CONFIG"])
    assert not (copied / "config.json").exists()
    assert (copied / "cli-plugins/docker-compose").resolve() == plugin.resolve()


def test_tool_provenance_uses_actual_committed_bytes_and_rejects_dirty_input(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    relative = "runner.py"
    (tmp_path / relative).write_text("print('tool')\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", relative], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@invalid.test",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    hashes = {relative: hashlib.sha256((tmp_path / relative).read_bytes()).hexdigest()}
    assert len(soak.tool_identity(tmp_path, hashes)["commit"]) == 40
    (tmp_path / relative).write_text("print('modified')\n")
    with pytest.raises(RuntimeError, match="committed and unchanged"):
        soak.tool_identity(tmp_path, hashes)


@pytest.mark.parametrize("config_variable", ["HOME", "CURL_HOME", "XDG_CONFIG_HOME"])
def test_actual_curl_cannot_load_ambient_configuration(
    tmp_path, monkeypatch, config_variable
):
    ambient = tmp_path / "ambient"
    ambient.mkdir()
    for variable in ("CURL_HOME", "XDG_CONFIG_HOME"):
        monkeypatch.delenv(variable, raising=False)
    ordinary_home = tmp_path / "ordinary-home"
    ordinary_home.mkdir()
    monkeypatch.setenv("HOME", str(ordinary_home))
    monkeypatch.setenv(config_variable, str(ambient))
    monkeypatch.setenv("DOCKER_HOST", "unix:///owned/docker.sock")
    # Bundled macOS curl uses .curlrc for XDG; upstream documents curlrc.
    # Separate HOME ensures either filename is loaded from the intended source.
    for filename in ("curlrc", ".curlrc"):
        (ambient / filename).write_text('header = "X-Soak-Dummy: ambient-config"\n')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(self.headers.get("X-Soak-Dummy")).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--max-time",
        "5",
        f"http://127.0.0.1:{server.server_port}/",
    ]
    try:
        assert (
            json.loads(subprocess.check_output(command, env=os.environ.copy()))
            == "ambient-config"
        )
        isolated = soak.isolated_environment(tmp_path / "run")
        assert json.loads(subprocess.check_output(command, env=isolated)) is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def test_optimization_and_invalid_duration_are_rejected_before_resources(tmp_path):
    command = [
        sys.executable,
        "-O",
        str(ROOT / "scripts/soak-candidate.py"),
        "--commit",
        "a" * 40,
        "--work-dir",
        str(tmp_path / "output"),
    ]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 2 and "assertions enabled" in result.stderr
    assert not (tmp_path / "output").exists()
