"""Completion instructions identify the administrator used by the HTTPS smoke."""

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import pytest

from test_quickstart_endpoint import (
    ROUTES,
    endpoint_server,
    environment,
    smoke,
    tls_pair as shared_tls_pair,
)


ROOT = Path(__file__).resolve().parents[2]
QUICKSTART = ROOT / "scripts/quickstart.sh"
PASSWORD = "private-endpoint-password"
tls_pair = shared_tls_pair


def configured_environment(tmp_path, port, config, *, status=0):
    env = environment(tmp_path, f"127.0.0.1:{port}\n")
    (tmp_path / "resolved-config").write_text(config)
    docker = tmp_path / "bin/docker"
    text = docker.read_text()
    start = text.index("if args==['compose','--env-file'")
    docker.write_text(
        text[:start]
        + "if args==['compose','--env-file','.env','config','--format','json']:\n"
        + " print((root/'resolved-config').read_text(),end='')\n"
        + f" sys.exit({status})\n"
        + "sys.exit(97)\n"
    )
    # The installed file deliberately differs: the resolved service settings
    # (including operator overrides) are what the smoke actually authenticates.
    (tmp_path / ".env").write_text("BRIDGE_ADMIN_USER=stale-dotenv-name\n")
    return env


def config_with_user(username):
    values = {"BRIDGE_ADMIN_PASSWORD": PASSWORD}
    if username is not None:
        values["BRIDGE_ADMIN_USER"] = username
    return json.dumps({"services": {"bridge": {"environment": values}}})


@pytest.mark.parametrize(
    "configured,expected",
    [
        ("review-owner", "review-owner"),
        ("admin", "admin"),
        (None, "admin"),
        ("", "admin"),
        ("opératrice $$lab '\" #\\team", "opératrice $lab '\" #\\team"),
    ],
)
def test_banner_matches_the_single_resolved_https_login(
    tmp_path, tls_pair, configured, expected
):
    with endpoint_server(tls_pair, "127.0.0.1") as (_, port, requests):
        env = configured_environment(tmp_path, port, config_with_user(configured))
        before = (tmp_path / ".env").read_bytes()
        result = smoke(tmp_path, env, port)
    assert result.returncode == 0, result.stderr
    assert [request[0] for request in requests] == ROUTES
    assert requests[2][2] == {"username": expected, "password": PASSWORD}
    assert f"    Username:   {expected}\n" in result.stdout
    assert "SigRift is up." in result.stdout
    assert PASSWORD not in result.stdout + result.stderr
    assert (tmp_path / ".env").read_bytes() == before
    commands = (tmp_path / "commands").read_text().splitlines()
    assert sum("'config'" in command for command in commands) == 1
    assert not list((tmp_path / "scratch").iterdir())


def test_failed_custom_login_has_no_completion_instructions(tmp_path, tls_pair):
    with endpoint_server(tls_pair, "127.0.0.1", status=401) as (_, port, requests):
        env = configured_environment(tmp_path, port, config_with_user("review-owner"))
        result = smoke(tmp_path, env, port)
    assert result.returncode != 0
    assert requests[2][2]["username"] == "review-owner"
    assert "startup verification failed" in result.stderr
    assert "SigRift is up." not in result.stdout
    assert "Username:" not in result.stdout
    assert PASSWORD not in result.stdout + result.stderr
    assert not list((tmp_path / "scratch").iterdir())


def test_real_compose_shell_override_is_the_printed_https_identity(tmp_path, tls_pair):
    docker = shutil.which("docker")
    assert docker, "the installer requires Docker Compose"
    (tmp_path / ".env").write_text("BRIDGE_ADMIN_USER=stale-dotenv-name\n")
    (tmp_path / "compose.yml").write_text(
        "services:\n  bridge:\n    image: example.invalid/not-pulled\n"
        "    environment:\n"
        "      BRIDGE_ADMIN_USER: ${BRIDGE_ADMIN_USER:-admin}\n"
        "      BRIDGE_ADMIN_PASSWORD: ${BRIDGE_ADMIN_PASSWORD}\n"
    )
    username = 'operator $one "two" #three'
    parsed = subprocess.run(
        [docker, "compose", "--env-file", ".env", "config", "--format", "json"],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "HOME": os.environ["HOME"],
            "BRIDGE_ADMIN_USER": username,
            "BRIDGE_ADMIN_PASSWORD": PASSWORD,
        },
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert parsed.returncode == 0, parsed.stderr
    with endpoint_server(tls_pair, "127.0.0.1") as (_, port, requests):
        env = configured_environment(tmp_path, port, parsed.stdout)
        result = smoke(tmp_path, env, port)
    assert result.returncode == 0, result.stderr
    assert requests[2][2] == {"username": username, "password": PASSWORD}
    assert f"    Username:   {username}\n" in result.stdout
    assert PASSWORD not in result.stdout + result.stderr
    assert not list((tmp_path / "scratch").iterdir())


@pytest.mark.parametrize(
    "config,status",
    [
        (config_with_user(["not", "a", "username"]), 0),
        (config_with_user(True), 0),
        ('{"services":{}}', 0),
        ("not json", 0),
        (config_with_user("review-owner"), 1),
    ],
)
def test_login_body_rejects_unusable_or_failed_resolved_config(
    tmp_path, config, status
):
    # Exercise the actual login-body function directly. No HTTP request is
    # meaningful when Compose failed or returned an unusable service identity.
    env = configured_environment(tmp_path, 1, config, status=status)
    function = re.search(
        r"^login_body\(\) \{\n.*?^\}\n", QUICKSTART.read_text(), re.M | re.S
    ).group()
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + function + "\nlogin_body .env"],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode != 0
    assert PASSWORD not in result.stderr


def test_optional_username_receipt_is_private_and_contains_no_password(tmp_path):
    expected = 'owner $$one "two"'
    env = configured_environment(tmp_path, 1, config_with_user(expected))
    function = re.search(
        r"^login_body\(\) \{\n.*?^\}\n", QUICKSTART.read_text(), re.M | re.S
    ).group()
    result = subprocess.run(
        [
            "bash",
            "-c",
            "set -euo pipefail\n" + function + '\nlogin_body .env "$1"',
            "bash",
            str(tmp_path / "username"),
        ],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    body = json.loads(result.stdout)
    assert body == {"username": expected.replace("$$", "$"), "password": PASSWORD}
    receipt = tmp_path / "username"
    assert receipt.read_text() == body["username"]
    assert stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert PASSWORD not in receipt.read_text()
    assert not re.search(r"\bADMIN_PASS\b", QUICKSTART.read_text())
