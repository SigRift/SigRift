"""Exercise the shipped installer and real Compose environment persistence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
QUICKSTART = ROOT / "scripts/quickstart.sh"


class Installer:
    def __init__(self, temporary):
        self.root = temporary / "checkout"
        (self.root / "scripts").mkdir(parents=True)
        shutil.copyfile(QUICKSTART, self.root / "scripts/quickstart.sh")
        shutil.copyfile(ROOT / "docker-compose.yml", self.root / "docker-compose.yml")
        self.bin = temporary / "bin"
        self.bin.mkdir()
        self.log = temporary / "commands.jsonl"
        self.real_docker = shutil.which("docker")
        assert self.real_docker, "Docker Compose CLI is required (no daemon operations)"
        docker = self.bin / "docker"
        docker.write_text(
            f"#!{sys.executable}\nreal={self.real_docker!r}\nlog={str(self.log)!r}\n"
            + """import json, os, sys
args = sys.argv[1:]
with open(log, 'a') as target:
    target.write(json.dumps(args) + '\\n')
if args[:2] == ['compose', 'config'] or args == ['compose', 'version']:
    os.execv(real, [real, *args])
if args[:2] == ['info', '--format'] or args == ['network', 'ls', '-q']:
    sys.exit(0)
# Stop at build. Never execute a build, pull, helper container or other daemon I/O.
sys.exit(77 if args == ['compose', 'build'] else 97)
"""
        )
        docker.chmod(0o700)
        curl = self.bin / "curl"
        curl.write_text("#!/bin/sh\necho unexpected-network-request >&2\nexit 96\n")
        curl.chmod(0o700)
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COMPOSE_", "SIGRIFT_", "BRIDGE_", "UC_"))
        }
        self.env.update(
            PATH=str(self.bin) + os.pathsep + os.environ["PATH"], SIGRIFT_PRESET="none"
        )

    def run(self, mode=None, *, first=False):
        env = self.env.copy()
        if mode is not None:
            env["BRIDGE_ENV"] = mode
        return subprocess.run(
            [
                "bash",
                str(self.root / "scripts/quickstart.sh"),
                *(["--dashboard-only"] if first else []),
            ],
            env=env,
            input="disposable-password\ndisposable-password\n",
            text=True,
            capture_output=True,
            timeout=30,
        )

    def modes(self, mode=None):
        env = self.env.copy()
        if mode is not None:
            env["BRIDGE_ENV"] = mode
        config = json.loads(
            subprocess.check_output(
                [self.real_docker, "compose", "config", "--format", "json"],
                cwd=self.root,
                env=env,
                text=True,
            )
        )
        assert set(config["services"]) == {"bridge", "gateway", "edge"}
        return {
            service: config["services"][service]["environment"]["BRIDGE_ENV"]
            for service in ("bridge", "gateway")
        }


@pytest.mark.parametrize(
    "mode,expected",
    [
        (None, "development"),
        ("development", "development"),
        ("production", "production"),
    ],
)
def test_fresh_cli_persists_selected_mode_for_plain_compose_and_retry(
    tmp_path, mode, expected
):
    installer = Installer(tmp_path)
    result = installer.run(mode, first=True)
    assert result.returncode == 77, result.stdout + result.stderr
    assert "disposable-password" not in result.stdout + result.stderr
    assert installer.modes(mode) == {"bridge": expected, "gateway": expected}
    assert installer.modes() == {"bridge": expected, "gateway": expected}
    saved = (installer.root / ".env").read_bytes()
    assert (installer.root / ".env").stat().st_mode & 0o777 == 0o600
    result = installer.run()
    assert result.returncode == 77, result.stdout + result.stderr
    assert (installer.root / ".env").read_bytes() == saved
    assert installer.modes() == {"bridge": expected, "gateway": expected}


@pytest.mark.parametrize(
    "saved,override",
    [("production", "development"), ("development", "production"), ("test", None)],
)
def test_existing_env_mode_and_custom_settings_remain_byte_identical(
    tmp_path, saved, override
):
    installer = Installer(tmp_path)
    assert installer.run(first=True).returncode == 77
    path = installer.root / ".env"
    path.write_text(
        path.read_text().replace("BRIDGE_ENV=development", "BRIDGE_ENV=" + saved)
        + "# retained operator comment\n"
    )
    before = path.read_bytes()
    result = installer.run(override)
    assert result.returncode == 77, result.stdout + result.stderr
    assert path.read_bytes() == before
    assert installer.modes(override) == {
        "bridge": override or saved,
        "gateway": override or saved,
    }
    assert installer.modes() == {"bridge": saved, "gateway": saved}


@pytest.mark.parametrize(
    "mode",
    [
        "",
        "prod",
        "dev",
        "test",
        "Production",
        "unknown",
        "production\nBRIDGE_MASTER_KEY=bad",
    ],
)
@pytest.mark.parametrize("existing", [False, True])
def test_invalid_explicit_mode_rejected_before_probes_prompts_or_writes(
    tmp_path, mode, existing
):
    installer = Installer(tmp_path)
    if existing:
        (installer.root / ".env").write_text(
            'BRIDGE_ENV=production\nBRIDGE_ADMIN_PASSWORD="preserved"\n'
        )
        (installer.root / "tls").mkdir()
        (installer.root / "tls/key.pem").write_text("private fixture")
    before = {
        str(p.relative_to(installer.root)): (
            p.stat().st_mode & 0o777,
            p.read_bytes() if p.is_file() else None,
        )
        for p in installer.root.rglob("*")
    }
    result = installer.run(mode, first=not existing)
    assert result.returncode == 1
    assert "BRIDGE_ENV must be production or development" in result.stderr
    assert "This installer will create" not in result.stdout
    assert not installer.log.exists(), (
        "validation must precede even read-only Docker probes"
    )
    after = {
        str(p.relative_to(installer.root)): (
            p.stat().st_mode & 0o777,
            p.read_bytes() if p.is_file() else None,
        )
        for p in installer.root.rglob("*")
    }
    assert after == before
