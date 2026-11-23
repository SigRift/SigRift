"""Public installer regressions, using Compose's parser without a daemon."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
QUICKSTART = ROOT / "scripts/quickstart.sh"
RELEASE = ROOT / "scripts/install-release.sh"


def function(path: Path, name: str) -> str:
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", path.read_text(), re.M | re.S)
    assert match
    return match.group()


def clean_env() -> dict[str, str]:
    # Keep Docker's CLI plugin discovery (HOME/DOCKER_CONFIG), but isolate
    # variables that could change the Compose project or credential values.
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("COMPOSE_", "BRIDGE_", "SIGRIFT_"))
    }


def shell(code: str, cwd: Path, *, stdin: str = "", env=None):
    return subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + code],
        cwd=cwd,
        input=stdin,
        text=True,
        capture_output=True,
        env=clean_env() if env is None else env,
    )


def has_compose() -> bool:
    return (
        bool(shutil.which("docker"))
        and subprocess.run(
            ["docker", "compose", "version"], capture_output=True
        ).returncode
        == 0
    )


needs_compose = pytest.mark.skipif(
    not has_compose(), reason="Docker Compose CLI required"
)


@pytest.mark.parametrize("installer", [QUICKSTART, RELEASE])
def test_secret_tempfile_works_with_bsd_mktemp(tmp_path, installer):
    """Exercise the real installer command with BSD's option boundary."""
    tmpdir = tmp_path / "private temp files"
    tmpdir.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    real_mktemp = shutil.which("mktemp")
    assert real_mktemp
    shim = bindir / "mktemp"
    shim.write_text(
        f'#!/bin/sh\ncase "$1" in --*) exit 64;; esac\nexec "{real_mktemp}" "$@"\n'
    )
    shim.chmod(0o755)
    command = re.search(r"^    tmp_env=\$\(mktemp .*\)$", installer.read_text(), re.M)
    assert command
    env = clean_env() | {
        "TMPDIR": str(tmpdir),
        "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
    }
    result = shell(command.group() + '\nprintf "%s" "$tmp_env"\n', tmp_path, env=env)
    assert result.returncode == 0, result.stderr
    created = Path(result.stdout)
    assert created.parent == tmpdir
    assert created.stat().st_mode & 0o777 == 0o600


def test_fresh_quickstart_persists_requested_port(tmp_path):
    template = re.search(
        r'cat > "\$tmp_env" <<EOF\n(.*?)\nEOF\n', QUICKSTART.read_text(), re.S
    ).group(1)
    code = (
        """
BIND=127.0.0.1 MFA_KEY=x AUDIT_KEY=x MASTER_KEY=x PROXY_SECRET=x
LOCAL_NODE_KEY=x SIGRIFT_PRESET=none ADMIN_PASSWORD_ENV='"test-password"'
cat > .env <<EOF
"""
        + template
        + "\nEOF\n"
    )
    result = shell(code, tmp_path, env=clean_env() | {"UC_PORT": "18444"})
    assert result.returncode == 0, result.stderr
    assert "UC_PORT=18444\n" in (tmp_path / ".env").read_text()
    assert "UC_PORT=8444\n" not in (tmp_path / ".env").read_text()


PASSWORDS = [
    "long$DOLLAR#foo",
    "long # hash value",
    "many \\slashes\\ and 'quotes' \"double\" $money #!",
    "ends-with-slash\\",
    "slash-before-quote\\'end",
    "  padded password  ",
    "both$$pairs${VAR:-value}",
    "unicode café пароль",
]


@needs_compose
@pytest.mark.parametrize(
    "installer", [QUICKSTART, RELEASE], ids=["quickstart", "release"]
)
@pytest.mark.parametrize("password", PASSWORDS)
def test_password_reaches_compose_and_login_unchanged(tmp_path, installer, password):
    # Render the installer's actual .env template, with its actual encoder.
    template = re.search(
        r'cat > "\$tmp_env" <<EOF\n(.*?)\nEOF\n', installer.read_text(), re.S
    ).group(1)
    code = (
        function(installer, "dotenv_password")
        + """
IFS= read -r ADMIN_PASSWORD
ADMIN_PASSWORD_ENV=$(printf '%s' "$ADMIN_PASSWORD" | dotenv_password)
VERSION=v0.1.0 BIND=127.0.0.1 MFA_KEY=placeholder AUDIT_KEY=placeholder
MASTER_KEY=placeholder PROXY_SECRET=placeholder LOCAL_NODE_KEY=placeholder SIGRIFT_PRESET=none
cat > .env <<EOF
"""
        + template
        + "\nEOF\n"
    )
    result = shell(code, tmp_path, stdin=password + "\n")
    assert result.returncode == 0, result.stderr
    (tmp_path / "docker-compose.yml").write_text("""services:
  bridge:
    image: busybox
    environment:
      BRIDGE_ADMIN_USER: ${BRIDGE_ADMIN_USER}
      BRIDGE_ADMIN_PASSWORD: ${BRIDGE_ADMIN_PASSWORD}
""")
    interpolation = subprocess.run(
        ["docker", "compose", "config", "--environment"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=clean_env(),
        check=True,
    ).stdout
    actual = next(
        line.partition("=")[2]
        for line in interpolation.splitlines()
        if line.startswith("BRIDGE_ADMIN_PASSWORD=")
    )
    assert actual == password
    result = shell(function(QUICKSTART, "login_body") + "login_body .env", tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"username": "admin", "password": password}


@needs_compose
def test_login_uses_shell_override_and_service_environment(tmp_path):
    (tmp_path / ".env").write_text("BRIDGE_ADMIN_PASSWORD='file password'\n")
    (tmp_path / "docker-compose.yml").write_text("""services:
  bridge:
    image: busybox
    environment:
      BRIDGE_ADMIN_USER: custom-admin
      BRIDGE_ADMIN_PASSWORD: ${BRIDGE_ADMIN_PASSWORD}
""")
    env = clean_env() | {"BRIDGE_ADMIN_PASSWORD": "shell $dollar # password"}
    result = shell(
        function(QUICKSTART, "login_body") + "login_body .env", tmp_path, env=env
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "username": "custom-admin",
        "password": env["BRIDGE_ADMIN_PASSWORD"],
    }


def upgrade(tmp_path: Path, *, version="v0.2.0", owner="sigrift"):
    env = clean_env() | {"VERSION": version, "OWNER": owner}
    return shell(
        function(RELEASE, "update_release_images")
        + "update_release_images docker-compose.yml",
        tmp_path,
        env=env,
    )


MANAGED_COMPOSE = """# Generated by install-release.sh @ v0.1.0.
services:
  bridge:
    image: ghcr.io/sigrift/sigrift-bridge:v0.1.0 # keep this comment
    environment:
      CUSTOM_SETTING: 'operator choice'
    labels:
      operator-label: preserved
  gateway:
    image: ghcr.io/sigrift/sigrift-gateway:v0.1.0
    ports:
      - '127.0.0.1:9444:8444'
"""


@needs_compose
def test_release_upgrade_changes_only_images_and_preserves_backup(tmp_path):
    path = tmp_path / "docker-compose.yml"
    path.write_text(MANAGED_COMPOSE)
    result = upgrade(tmp_path)
    assert result.returncode == 0, result.stderr
    assert path.read_text() == MANAGED_COMPOSE.replace(
        "sigrift-bridge:v0.1.0", "sigrift-bridge:v0.2.0"
    ).replace("sigrift-gateway:v0.1.0", "sigrift-gateway:v0.2.0")
    backups = list(tmp_path.glob("docker-compose.yml.bak.*~"))
    assert len(backups) == 1 and backups[0].read_text() == MANAGED_COMPOSE
    assert backups[0].stat().st_mode & 0o777 == 0o600
    # Repeating an already-applied upgrade must not create another backup.
    assert upgrade(tmp_path).returncode == 0
    assert list(tmp_path.glob("docker-compose.yml.bak.*~")) == backups


@needs_compose
@pytest.mark.parametrize("legacy", [True, False])
def test_release_upgrade_migrates_only_the_known_legacy_healthcheck(tmp_path, legacy):
    command = (
        '["CMD", "sh", "-c", "wget -q --spider http://localhost:8444/health || exit 1"]'
        if legacy
        else '["CMD", "/operator/custom-healthcheck"]'
    )
    path = tmp_path / "docker-compose.yml"
    path.write_text(MANAGED_COMPOSE + "    healthcheck:\n      test: " + command + "\n")
    result = upgrade(tmp_path)
    assert result.returncode == 0, result.stderr
    expected = '["CMD", "/app/healthcheck.sh"]' if legacy else command
    assert "      test: " + expected in path.read_text()


@needs_compose
@pytest.mark.parametrize(
    "change",
    [
        "custom-image",
        "override",
        "invalid-compose",
        "unmanaged",
        "alternate-default",
        "dotenv-compose-file",
    ],
)
def test_release_upgrade_refuses_custom_images_or_invalid_config(tmp_path, change):
    path = tmp_path / "docker-compose.yml"
    text = MANAGED_COMPOSE
    if change == "custom-image":
        text = text.replace(
            "ghcr.io/sigrift/sigrift-bridge:v0.1.0", "example.com/custom:stable"
        )
    elif change == "override":
        (tmp_path / "docker-compose.override.yml").write_text(
            "services:\n  gateway:\n    image: example.com/custom:stable\n"
        )
    elif change == "invalid-compose":
        text += "invalid_top_level_setting: true\n"
    elif change == "alternate-default":
        (tmp_path / "compose.yml").write_text(MANAGED_COMPOSE)
    elif change == "dotenv-compose-file":
        (tmp_path / "alternate.yml").write_text(MANAGED_COMPOSE)
        (tmp_path / ".env").write_text("COMPOSE_FILE=alternate.yml\n")
    else:
        text = text.partition("\n")[2]
    path.write_text(text)
    result = upgrade(tmp_path)
    assert result.returncode != 0
    assert path.read_text() == text
    assert not list(tmp_path.glob("docker-compose.yml.bak.*~"))


@pytest.mark.parametrize(
    "version", ["v1.2.3\nmalicious: true", "v1.2.3;touch pwned", "../../elsewhere"]
)
def test_release_upgrade_rejects_invalid_tags_without_writing(tmp_path, version):
    path = tmp_path / "docker-compose.yml"
    path.write_text(MANAGED_COMPOSE)
    result = upgrade(tmp_path, version=version)
    assert result.returncode != 0
    assert path.read_text() == MANAGED_COMPOSE


def test_local_model_selection_handles_spaces_and_system_bsd_commands(tmp_path):
    old, new = tmp_path / "old.onnx", tmp_path / "new model's name.onnx"
    old.write_bytes(b"old")
    new.write_bytes(b"new")
    os.utime(old, ns=(1, 1))
    os.utime(new, ns=(2, 2))
    text = QUICKSTART.read_text()
    start = text.index('    newest=$(python3 - "${ONNX_FILES[@]}"')
    end = text.index("    newest_bn=", start)
    # This executes the real selection block, with spaces/apostrophes in paths.
    result = shell(
        'ONNX_FILES=("$PWD/old.onnx" "$PWD/new model\'s name.onnx")\n'
        + text[start:end]
        + '\nprintf "%s" "$newest"\n',
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == str(new)


def test_model_checksum_uses_stdlib_and_matches_bytes(tmp_path):
    model = tmp_path / "model with spaces.onnx"
    model.write_bytes(bytes(range(256)) * 128)
    text = QUICKSTART.read_text()
    # The helper is nested in the download function; it hashes the model
    # and its metadata sidecar alike.
    start = text.index("    staged_sha256() {\n")
    end = text.index("\n    }\n", start) + len("\n    }\n")
    helper = text[start:end]
    result = shell(
        'download_dir="$PWD"\nonnx_bn="model with spaces.onnx"\n'
        + helper
        + 'got=$(staged_sha256 "$onnx_bn") || exit 1\nprintf "%s" "$got"\n',
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == hashlib.sha256(model.read_bytes()).hexdigest()
    # An unreadable file fails and prints no digest.
    missing = shell(
        'download_dir="$PWD"\n' + helper + 'staged_sha256 "absent.onnx"\n', tmp_path
    )
    assert missing.returncode != 0 and missing.stdout == ""


def test_tls_file_modes_accept_leading_dash_paths_on_bsd_and_gnu(tmp_path):
    for name in ("-cert.pem", "-key.pem"):
        (tmp_path / name).write_text("test-only")
        (tmp_path / name).chmod(0o600)
    result = shell(
        "tls_key_perms() { return 1; }\n"
        + function(QUICKSTART, "secure_tls_files")
        + "secure_tls_files -cert.pem -key.pem\n",
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "-cert.pem").stat().st_mode & 0o777 == 0o644
    assert (tmp_path / "-key.pem").stat().st_mode & 0o777 == 0o644


def test_explicit_upgrade_remembers_version_for_future_reruns(tmp_path):
    (tmp_path / "VERSION").write_text("v0.1.0\n")
    text = RELEASE.read_text()
    start = text.index("# Remember an explicit upgrade")
    end = text.index("# ── .env: prompt", start)
    result = shell("VERSION_REQUESTED=1 VERSION=v0.2.0\n" + text[start:end], tmp_path)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "VERSION").read_text() == "v0.2.0\n"
