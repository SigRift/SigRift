#!/usr/bin/env python3
"""Run a disposable, source-built software soak, then remove its own stack.

This is synthetic auth/ingest/storage evidence, separate from the required full
candidate/browser run and hardware tests. Default duration is 24 hours AFTER
startup and warmup. A short successful run never certifies the 24-hour gate.
Requires Python 3.11+, pytest (for the existing HTTP client), Docker/Compose,
git, openssl, curl and jq. No GitHub/GHCR credentials or radio hardware required.
Only results.json, observations.jsonl and junit.xml are shareable by default.
private/ can contain generated credentials and remains mode0700 on the host.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from urllib.parse import quote
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.e2e.conftest import Client, Settings  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "soak_candidate_helpers", ROOT / "scripts/test-candidate.py"
)
candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(candidate)
SERVICES = {"bridge", "gateway", "edge"}
INPUTS = (
    "scripts/test-candidate.py",
    "tests/e2e/conftest.py",
    "tests/e2e/diagnostics.py",
)
LOADED_HASHES = {
    relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    for relative in ("scripts/soak-candidate.py", *INPUTS)
}
INSPECT = (
    '{"id":{{json .Id}},"image":{{json .Image}},'
    '"started_at":{{json .State.StartedAt}},"running":{{json .State.Running}},'
    '"oom_killed":{{json .State.OOMKilled}},"restarts":{{json .RestartCount}},'
    '"health":{{with (index .State "Health")}}{{json .Status}}{{else}}null{{end}},'
    '"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}}}'
)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def tool_identity(root=ROOT, loaded_hashes=LOADED_HASHES):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(root), *args])

    commit = git("rev-parse", "HEAD").decode().strip()
    require(
        not git("status", "--porcelain", "--untracked-files=all", "--", *loaded_hashes),
        "Soak runner and helpers must be committed and unchanged",
    )
    for relative, expected in loaded_hashes.items():
        require(
            hashlib.sha256(git("show", f"{commit}:{relative}")).hexdigest() == expected
            and digest(root / relative) == expected,
            "Loaded soak tool differs from its committed source",
        )
    return {"commit": commit, "files_sha256": loaded_hashes}


def isolate_parent_diagnostics():
    # The reused Client reads this in the current process, not the child env.
    # Its bounded E2E recorder is deliberately not a 24-hour event sink.
    os.environ.pop("SIGRIFT_E2E_DIAGNOSTICS", None)
    # ssl.create_default_context otherwise writes TLS session secrets here.
    os.environ.pop("SSLKEYLOGFILE", None)


def isolated_environment(output):
    env = candidate.isolated_environment()
    for key in tuple(env):
        if key.startswith(("DOCKER_", "BUILDX_", "BUILDKIT_")):
            env.pop(key)
    for key in (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
        "GIT_ASKPASS",
        "GIT_SSH_COMMAND",
    ):
        env.pop(key, None)
    # Preserve only the selected local Docker socket, never registry credentials
    # or remote TLS client material from the caller's Docker configuration.
    endpoint = (
        os.environ.get("DOCKER_HOST")
        or subprocess.check_output(
            [
                "docker",
                "context",
                "inspect",
                "--format",
                '{{(index .Endpoints "docker").Host}}',
            ],
            text=True,
            timeout=15,
        ).strip()
    )
    require(
        endpoint.startswith("unix://"),
        "Soak requires a local Unix-socket Docker daemon",
    )
    home = output / "private-home"
    config = home / ".docker"
    config.mkdir(parents=True, mode=0o700)
    curl_config = home / "curl"
    env = candidate.isolate_curl_configuration(env, curl_config)
    for directory in (home / "xdg", home / "gh", config / "buildx"):
        directory.mkdir(mode=0o700)
    original_config = Path(
        os.environ.get("DOCKER_CONFIG", str(Path.home() / ".docker"))
    )
    plugin = original_config / "cli-plugins/docker-compose"
    if plugin.is_file():
        (config / "cli-plugins").mkdir()
        (config / "cli-plugins/docker-compose").symlink_to(plugin.resolve())
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / "xdg"),
        GH_CONFIG_DIR=str(home / "gh"),
        BUILDX_CONFIG=str(config / "buildx"),
        DOCKER_CONFIG=str(config),
        DOCKER_HOST=endpoint,
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    return env


class Runner(candidate.Runner):
    """Bound capture subprocess groups too, including during final cleanup."""

    cleanup_deadline = None

    def budget(self, requested):
        if self.cleanup_deadline is None:
            return requested
        remaining = self.cleanup_deadline - time.monotonic()
        require(remaining > 0, "Cleanup deadline exceeded")
        return min(requested, remaining)

    def run(self, name, command, **kwargs):
        kwargs["timeout"] = self.budget(kwargs.get("timeout", 1800))
        return super().run(name, command, **kwargs)

    def capture(self, *command):
        process = subprocess.Popen(
            command,
            cwd=self.source,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=self.budget(60))
        except BaseException:
            self.terminate(process, grace=2)
            raise
        if process.returncode:
            with (self.private / "capture-errors.log").open("a") as log:
                log.write(stderr)
            raise RuntimeError("Private Docker/git capture failed")
        return stdout


def disk_preflight(runner, project, source, minimum_bytes):
    """Measure Docker's actual volume filesystem, not just the host's disk."""
    base = (
        (source / "src/sigrift/bridge/Dockerfile")
        .read_text()
        .split("FROM ", 1)[1]
        .split()[0]
    )
    require(
        re.fullmatch(r"[A-Za-z0-9./:_-]+@sha256:[0-9a-f]{64}", base),
        "Disk helper must use the source's digest-pinned Python base",
    )
    volume, helper = project + "_preflight", project + "-preflight"
    marker = secrets.token_hex(16)
    (source / ".soak-bind-check").write_text(marker)
    try:
        runner.run("preflight-base", ["docker", "pull", base], timeout=300)
        runner.capture(
            "docker",
            "volume",
            "create",
            "--label",
            f"com.docker.compose.project={project}",
            volume,
        )
        command = (
            "docker",
            "run",
            "--rm",
            "--name",
            helper,
            "--pull=never",
            "--label",
            f"com.docker.compose.project={project}",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--mount",
            f"type=bind,source={source},target=/candidate,readonly",
            "--mount",
            f"type=volume,source={volume},target=/probe",
        )
        # Native Linux keeps the invoking user's ownership; macOS file sharing
        # may remap it. Stat needs no DAC override and never reads the marker.
        owner = json.loads(
            runner.capture(
                *command,
                base,
                "python3",
                "-c",
                "import json; from pathlib import Path; "
                "s=Path('/candidate/.soak-bind-check').stat(); "
                "print(json.dumps({'uid':s.st_uid,'gid':s.st_gid}))",
            )
        )
        require(
            isinstance(owner, dict)
            and set(owner) == {"uid", "gid"}
            and all(
                type(value) is int and 0 <= value < 2**32 - 1
                for value in owner.values()
            ),
            "Invalid mounted probe ownership",
        )
        raw = runner.capture(
            *command,
            "--user",
            f"{owner['uid']}:{owner['gid']}",
            base,
            "python3",
            "-c",
            "import json,shutil; from pathlib import Path; "
            f"assert Path('/candidate/.soak-bind-check').read_text()=={marker!r}; "
            "d=shutil.disk_usage('/probe'); "
            "print(json.dumps({'free_bytes':d.free,'total_bytes':d.total}))",
        )
        disk = json.loads(raw)
        require(
            disk["free_bytes"] >= minimum_bytes,
            "Insufficient Docker filesystem free space before build",
        )
        return disk
    finally:
        (source / ".soak-bind-check").unlink(missing_ok=True)
        cleanup_preflight(runner, project)


def cleanup_preflight(runner, project):
    # Names are generated by this process; labels must still agree before rm.
    for kind, name in (
        ("container", project + "-preflight"),
        ("volume", project + "_preflight"),
    ):
        ids = runner.capture(
            "docker",
            *(["ps", "-aq"] if kind == "container" else ["volume", "ls", "-q"]),
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"name={name}",
        ).split()
        if not ids:
            continue
        if kind == "volume":
            require(ids == [name], "Unexpected preflight volume ownership")
            runner.run(
                "preflight-volume-cleanup", ["docker", "volume", "rm", name], timeout=30
            )
        else:
            require(len(ids) == 1, "Unexpected preflight container ownership")
            actual = runner.capture(
                "docker", "inspect", "--format", "{{.Name}}", ids[0]
            ).strip()
            require(actual == "/" + name, "Unexpected preflight container name")
            runner.run(
                "preflight-container-cleanup",
                ["docker", "rm", "-f", ids[0]],
                timeout=30,
            )


def verify_scope(config, project, port, source):
    candidate.verify_compose_scope(config, project, port)
    allowed_binds = {
        "gateway": {(str(source / "tls"), "/app/tls")},
        "edge": {(str(source / "tls/cert.pem"), "/app/tls/cert.pem")},
        "bridge": set(),
    }
    for name, service in config["services"].items():
        require(
            not service.get("devices") and not service.get("cap_add"),
            "Soak services must not receive devices or extra capabilities",
        )
        require(
            name == "gateway" or not service.get("ports"),
            "Only the gateway may publish a port",
        )
        for mount in service.get("volumes", []):
            if mount["type"] == "bind":
                require(
                    (mount["source"], mount["target"]) in allowed_binds[name]
                    and mount.get("read_only") is True
                    and Path(mount["source"]).resolve() == Path(mount["source"]),
                    "Only owned read-only TLS binds are allowed",
                )
            else:
                require(mount["type"] == "volume", "Unsupported mount type")


def validate_containers(rows, project, baseline=None):
    current = {row["service"]: row for row in rows}
    require(
        len(rows) == len(current) == 3 and set(current) == SERVICES,
        "Expected exactly one container per soak service",
    )
    for name, row in current.items():
        require(
            row["project"] == project
            and row["running"]
            and not row["oom_killed"]
            and row["restarts"] == 0,
            "Soak container stopped, restarted or was OOM-killed",
        )
        require(
            name == "edge" or row["health"] == "healthy", "Soak service is unhealthy"
        )
        if baseline is not None:
            require(
                all(
                    row[field] == baseline[name][field]
                    for field in ("id", "image", "started_at")
                ),
                "A soak container was replaced during the observation period",
            )
    return current


def memory_bytes(value):
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)\s*(B|KiB|MiB|GiB|kB|MB|GB)", value)
    require(match is not None, "Unrecognized Docker memory measurement")
    factors = {
        "B": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "kB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
    }
    return int(float(match[1]) * factors[match[2]])


def parse_stats(raw, containers):
    names = {row["id"]: name for name, row in containers.items()}
    output = {}
    for line in raw.splitlines():
        row = json.loads(line)
        matches = [name for ident, name in names.items() if ident.startswith(row["ID"])]
        require(
            len(matches) == 1 and matches[0] not in output,
            "Docker stats do not match the owned containers",
        )
        output[matches[0]] = {
            "memory_bytes": memory_bytes(row["MemUsage"].split("/", 1)[0].strip()),
            "cpu_percent": float(row["CPUPerc"].removesuffix("%")),
            "pids": int(row["PIDs"]),
        }
        require(
            all(value >= 0 for value in output[matches[0]].values()),
            "Invalid Docker resource measurement",
        )
    require(set(output) == SERVICES, "Missing Docker resource measurements")
    return output


class Protocol:
    def __init__(self, settings, node_id):
        self.settings = settings
        self.node_id = node_id
        self.admin = Client(settings)
        self.sensor = Client(settings)  # Must succeed before a key is allocated.
        self.key = None
        self.last_batch = None
        self.login_count = 0

    def login(self):
        fresh = Client(self.settings)
        result = fresh.login(self.settings.username, self.settings.password)
        require(
            isinstance(result, dict)
            and fresh.has_session()
            and not result.get("password_change_required")
            and not result.get("mfa_required")
            and not result.get("mfa_setup_required"),
            "Soak login did not produce a full session",
        )
        require(
            fresh.request("GET", "/api/auth/me").get("username")
            == self.settings.username,
            "Authenticated identity mismatch",
        )
        fresh.request("GET", "/api/status")  # Python-proxied authorization.
        if self.login_count:
            # The opener refers to its jar: preserve the old credential there.
            replay = Client(self.settings)
            for cookie in self.admin.cookies:
                replay.cookies.set_cookie(copy.copy(cookie))
            self.admin.request("POST", "/api/auth/logout", {})
            replay.request("GET", "/api/auth/me", status=401)
        self.admin = fresh
        self.login_count += 1

    def setup(self):
        self.login()
        self.admin.request(
            "POST",
            "/api/nodes/register",
            {
                "node_id": self.node_id,
                "host": "synthetic.invalid",
                "capabilities": {"test_fixture": True, "role": "synthetic-scanner"},
            },
        )
        self.key = self.admin.request(
            "POST",
            "/api/admin/keys",
            {
                "description": "disposable software soak",
                "role": "sensor",
                "node_id": self.node_id,
            },
            status=201,
            retry_key_creation=True,
            stage="scanner_key",
        )
        require(
            isinstance(self.key, dict)
            and all(
                isinstance(self.key.get(k), str) and self.key[k]
                for k in ("key_id", "raw_key")
            ),
            "Invalid sensor key contract",
        )

    def cycle(self, sequence):
        health = self.admin.request("GET", "/health")
        hooks = health["post_ingest_hooks"]
        require(
            hooks["enabled"]
            and hooks["failed_batches"] == 0
            and hooks["dropped_batches"] == 0,
            "Ingest hook delivery failed",
        )
        require(
            self.admin.request("GET", "/api/ready")["status"] == "ready",
            "Bridge storage is not ready",
        )
        detection = {
            "detection_id": f"{self.node_id}-{sequence}",
            "signal_class": "bpsk",
            "confidence": 0.95,
            "freq_hz": 433920000,
            "snr_db": 20.0,
        }
        batch = {
            "node_id": self.node_id,
            "batch_id": f"{self.node_id}-batch-{sequence}",
            "detections": [detection],
        }
        result = self.sensor.request(
            "POST", "/api/detections/batch", batch, key=self.key["raw_key"]
        )
        require(
            result["inserted"] == 1 and result["rejected"] == 0,
            "Synthetic detection was not inserted exactly once",
        )
        self.last_batch = batch
        path = "/api/detections/" + quote(detection["detection_id"], safe="")
        stored = self.admin.request("GET", path)
        require(
            stored.get("node_id") == self.node_id
            and all(stored.get(field) == value for field, value in detection.items()),
            "Proxied detection readback differs from the inserted record",
        )
        before = self.admin.request("GET", "/health")["post_ingest_hooks"]
        duplicate = self.sensor.request(
            "POST", "/api/detections/batch", batch, key=self.key["raw_key"]
        )
        require(
            duplicate["inserted"] == 0 and duplicate["rejected"] == 0,
            "Duplicate batch was not deduplicated",
        )
        require(
            self.admin.request("GET", path) == stored,
            "Duplicate ingest changed the stored detection",
        )
        deadline = time.monotonic() + 30
        while True:
            hooks = self.admin.request("GET", "/health")["post_ingest_hooks"]
            require(
                hooks["failed_batches"] == hooks["dropped_batches"] == 0,
                "Ingest hook delivery failed",
            )
            require(
                hooks["enqueued_batches"] == before["enqueued_batches"],
                "Duplicate ingest enqueued another hook",
            )
            if hooks["delivered_batches"] == hooks["enqueued_batches"]:
                break
            require(time.monotonic() < deadline, "Ingest hooks failed to drain")
            time.sleep(0.25)
        return {
            "inserted": 1,
            "duplicate_inserted": 0,
            "hook_delivered_batches": hooks["delivered_batches"],
        }

    def close(self):
        if isinstance(self.key, dict) and isinstance(self.key.get("key_id"), str):
            self.admin.request(
                "DELETE",
                "/api/admin/keys/" + quote(self.key["key_id"], safe=""),
                retry_key_cleanup=True,
                stage="scanner_cleanup",
            )
            if self.last_batch is not None:
                self.sensor.request(
                    "POST",
                    "/api/detections/batch",
                    self.last_batch,
                    key=self.key["raw_key"],
                    status=401,
                    stage="scanner_revocation",
                )
        if self.login_count:
            self.admin.request("POST", "/api/auth/logout", {})


def scheduled_soak(
    duration, interval, cycle, *, clock=time.monotonic, sleep=time.sleep
):
    """Visit start and endpoint; fail instead of skipping a late scheduled cycle."""
    started = clock()
    deadline = started + duration
    sequence = 0
    while True:
        target = min(started + sequence * interval, deadline)
        remaining = target - clock()
        if remaining > 0:
            sleep(remaining)
        lateness = max(0.0, clock() - target)
        require(lateness < interval, "A full scheduled soak interval was missed")
        cycle(sequence, round(clock() - started, 3), round(lateness, 3))
        if target == deadline:
            return {"cycles": sequence + 1, "elapsed_seconds": clock() - started}
        sequence += 1


def cleanup(runner, project, source, port, *, timeout=180):
    """Log errors must never skip down; failure to remove owned state fails run."""
    runner.cleanup_deadline = time.monotonic() + timeout - 10
    errors = []

    def run(name, command):
        runner.run(name, command, timeout=60)

    try:
        cleanup_preflight(runner, project)
    except Exception:
        errors.append("preflight")
    try:
        config = json.loads(
            runner.capture("docker", "compose", "config", "--format", "json")
        )
        verify_scope(config, project, port, source)
    except Exception:
        return False
    try:
        run("service-logs", ["docker", "compose", "logs", "--no-color", "--tail=100"])
    except Exception:
        errors.append("logs")
    try:
        run("cleanup", ["docker", "compose", "down", "-v", "--remove-orphans"])
    except Exception:
        errors.append("down")
    for kind, command in (
        ("containers", ["docker", "ps", "-aq"]),
        ("volumes", ["docker", "volume", "ls", "-q"]),
        ("networks", ["docker", "network", "ls", "-q"]),
    ):
        try:
            remaining = runner.capture(
                *command, "--filter", f"label=com.docker.compose.project={project}"
            )
            require(not remaining.strip(), f"Owned {kind} remain after cleanup")
        except Exception:
            errors.append(kind)
    if not any(error != "logs" for error in errors):
        try:
            for path in source.glob(".env*"):
                if path.is_file() or path.is_symlink():
                    path.unlink()
            tls = source / "tls"
            if tls.is_symlink():
                tls.unlink()
            elif tls.exists():
                shutil.rmtree(tls)
            require(
                not list(source.glob(".env*"))
                and not tls.exists()
                and not tls.is_symlink(),
                "Generated secrets remain after cleanup",
            )
        except Exception:
            return False
        return not errors
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=ROOT)
    parser.add_argument(
        "--commit", required=True, help="Exact clean 40-hex source commit"
    )
    parser.add_argument("--work-dir", required=True, type=Path)
    parser.add_argument("--duration-seconds", type=int, default=86400)
    parser.add_argument("--interval-seconds", type=int, default=60)
    parser.add_argument("--min-free-gib", type=float, default=10)
    args = parser.parse_args()
    if not __debug__ or sys.version_info < (3, 11):
        parser.error("Python3.11+ with assertions enabled is required")
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
        parser.error("--commit must be a full lowercase commit ID")
    if not 1 <= args.interval_seconds <= args.duration_seconds <= 7 * 86400:
        parser.error("Require 1 <= interval <= duration <= 7days")
    if not 1 <= args.min_free_gib <= 1024:
        parser.error("--min-free-gib must be between1 and1024")
    for command in ("git", "docker", "openssl", "curl", "jq"):
        if not shutil.which(command):
            parser.error(f"Missing prerequisite: {command}")
    for relative in INPUTS:
        if digest(args.source_dir / relative) != digest(ROOT / relative):
            parser.error("Soak helpers differ from the selected source checkout")
    tool = tool_identity()
    isolate_parent_diagnostics()
    os.umask(0o077)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="sigrift-soak-", dir=args.work_dir.resolve()))
    source = output / "source"
    source.mkdir()
    env = isolated_environment(output)
    project = "sigrift-soak-" + secrets.token_hex(6)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env.update(
        COMPOSE_PROJECT_NAME=project,
        SIGRIFT_BIND="127.0.0.1",
        UC_PORT=str(port),
        SIGRIFT_PRESET="none",
        PYTHONDONTWRITEBYTECODE="1",
    )
    runner = Runner(source, output, env)
    results = {
        "passed": False,
        "completed_24h": False,
        "credential_revocation_verified": False,
        "project": project,
        "port": port,
        "requested_seconds": args.duration_seconds,
        "interval_seconds": args.interval_seconds,
        "scope": "synthetic software auth/ingest/storage; no hardware/browser claim",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "tool": tool,
    }
    scope_verified = False
    protocol = None

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    print(f"Private soak directory: {output}", flush=True)
    try:
        results["source"] = candidate.source_snapshot(args.source_dir, source, False)
        require(results["source"]["commit"] == args.commit, "Source commit mismatch")
        (source / "docker-compose.override.yml").write_text(candidate.OVERRIDE)
        source.chmod(0o755)
        for directory in source.rglob("*"):
            if directory.is_dir():
                directory.chmod(0o755)
        results["docker"] = runner.capture(
            "docker", "version", "--format", "{{.Server.Version}}"
        ).strip()
        results["docker_platform"] = runner.capture(
            "docker", "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"
        ).strip()
        results["compose"] = runner.capture(
            "docker", "compose", "version", "--short"
        ).strip()
        results["python"] = platform.python_version()
        config = json.loads(
            runner.capture("docker", "compose", "config", "--format", "json")
        )
        verify_scope(config, project, port, source)
        scope_verified = True
        # On native Linux this covers the build workspace and often Docker's
        # backing filesystem. The real volume free space is checked below.
        require(
            shutil.disk_usage(source).free >= args.min_free_gib * 1024**3,
            "Insufficient host workspace free space",
        )
        results["disk_before_build"] = disk_preflight(
            runner, project, source, args.min_free_gib * 1024**3
        )
        password = secrets.token_urlsafe(32)
        runner.run(
            "fresh-source-install",
            ["bash", "scripts/quickstart.sh", "--scanners=none"],
            stdin=f"{password}\n{password}\n",
            timeout=3600,
        )
        config = json.loads(
            runner.capture("docker", "compose", "config", "--format", "json")
        )
        verify_scope(config, project, port, source)
        require(
            all(
                config["services"][name]["environment"]["BRIDGE_ENV"] == "production"
                for name in ("bridge", "gateway")
            ),
            "Soak must use production mode",
        )
        context = ssl.create_default_context(cafile=str(source / "tls/cert.pem"))
        protocol = Protocol(
            Settings(f"https://127.0.0.1:{port}", "admin", password, context),
            "soak-" + secrets.token_hex(6),
        )
        protocol.setup()

        def containers():
            ids = runner.capture("docker", "compose", "ps", "-aq").split()
            require(len(ids) == 3, "Expected three owned containers")
            return [
                json.loads(line)
                for line in runner.capture(
                    "docker", "inspect", "--format", INSPECT, *ids
                ).splitlines()
            ]

        baseline = validate_containers(containers(), project)
        results["containers"] = baseline
        observation_path = output / "observations.jsonl"
        last_login = time.monotonic()

        def cycle(sequence, elapsed, lateness):
            nonlocal last_login
            if time.monotonic() - last_login >= 900:
                protocol.login()
                last_login = time.monotonic()
            started = time.monotonic()
            api = protocol.cycle(sequence)
            current = validate_containers(containers(), project, baseline)
            stats = parse_stats(
                runner.capture(
                    "docker",
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{json .}}",
                    *[r["id"] for r in current.values()],
                ),
                current,
            )
            disk = json.loads(
                runner.capture(
                    "docker",
                    "compose",
                    "exec",
                    "-T",
                    "bridge",
                    "python3",
                    "-c",
                    "import json,shutil; d=shutil.disk_usage('/app/src/sigrift/bridge/data'); print(json.dumps({'free_bytes':d.free,'total_bytes':d.total}))",
                )
            )
            require(
                disk["free_bytes"] >= args.min_free_gib * 1024**3,
                "Docker data volume free space is below the soak minimum",
            )
            row = {
                "sequence": sequence,
                "elapsed_seconds": elapsed,
                "lateness_seconds": lateness,
                "cycle_seconds": round(time.monotonic() - started, 3),
                "utc": datetime.now(timezone.utc).isoformat(),
                "api": api,
                "resources": stats,
                "disk": disk,
                "login_count": protocol.login_count,
            }
            with observation_path.open("a") as report:
                report.write(json.dumps(row, sort_keys=True) + "\n")
                report.flush()
                os.fsync(report.fileno())
            print(f"[soak] cycle{sequence} PASS elapsed={elapsed:.1f}s", flush=True)

        results["observation"] = scheduled_soak(
            args.duration_seconds, args.interval_seconds, cycle
        )
        protocol.close()
        protocol = None
        results["credential_revocation_verified"] = True
        results["passed"] = True
        results["completed_24h"] = (
            args.duration_seconds >= 86400
            and results["observation"]["elapsed_seconds"] >= 86400
        )
    except (Exception, KeyboardInterrupt) as error:
        results["failure_category"] = type(error).__name__
        (runner.private / "failure.txt").write_text(traceback.format_exc())
        print(
            f"Soak FAILED ({type(error).__name__}); inspect private evidence.",
            flush=True,
        )
    finally:
        # A second signal must not interrupt the bounded project teardown.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        # The success path proves credential revocation. After any failure,
        # prioritize deleting the owned stack/volumes over further API calls.
        results["cleanup_passed"] = scope_verified and cleanup(
            runner, project, source, port
        )
        results["passed"] = results["passed"] and results["cleanup_passed"]
        results["completed_24h"] = results["completed_24h"] and results["passed"]
        results["steps"] = runner.steps
        results["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        suite = ET.Element(
            "testsuite",
            name="disposable-soak",
            tests="1",
            failures="0" if results["passed"] else "1",
        )
        case = ET.SubElement(suite, "testcase", name="synthetic-software-soak")
        if not results["passed"]:
            ET.SubElement(case, "failure", message="See private diagnostics")
        ET.ElementTree(suite).write(output / "junit.xml", encoding="unicode")
        print(f"Result: {output / 'results.json'}", flush=True)
    return 0 if results["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
