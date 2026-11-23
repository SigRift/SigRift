"""Public image source is readable without making runtime secrets public."""

from pathlib import Path
import shlex
import stat
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
PYTHON_IMAGES = ("src/sigrift/bridge/Dockerfile", "src/sigrift/edge/Dockerfile")
ALL_IMAGES = (*PYTHON_IMAGES, "src/gateway/Dockerfile")


def source_permission_command(dockerfile: str) -> str:
    commands = [
        line.removeprefix("RUN ")
        for line in dockerfile.splitlines()
        if line.startswith("RUN chmod ") and "/app/src/sigrift" in line
    ]
    assert len(commands) == 1, "Normalize the copied public package before USER"
    return commands[0]


@pytest.mark.parametrize("image", PYTHON_IMAGES)
@pytest.mark.parametrize(
    "file_mode,dir_mode", [(0o600, 0o700), (0o640, 0o750), (0o666, 0o777)]
)
def test_copied_package_permissions_are_independent_of_checkout_umask(
    tmp_path, image, file_mode, dir_mode
):
    dockerfile = (ROOT / image).read_text()
    command = source_permission_command(dockerfile)
    package = tmp_path / "src" / "sigrift"
    nested = package / "bridge" / "templates"
    nested.mkdir(parents=True)
    files = [package / "__init__.py", nested / "index.html"]
    for path in files:
        path.write_text("public authored content\n")
        path.chmod(file_mode)
    executable = package / "run.sh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    for directory in (package, package / "bridge", nested):
        directory.chmod(dir_mode)

    # Runtime key material outside the public package must retain private modes.
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    key = secrets / "ca.key"
    key.write_text("synthetic private fixture\n")
    key.chmod(0o600)
    subprocess.run(
        ["sh", "-c", command.replace("/app/src/sigrift", shlex.quote(str(package)))],
        check=True,
        timeout=5,
    )
    for path in files:
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
        assert path.read_text() == "public authored content\n"
    for directory in (package, package / "bridge", nested):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    assert stat.S_IMODE(executable.stat().st_mode) == 0o755
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o700
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert key.read_text() == "synthetic private fixture\n"


@pytest.mark.parametrize("image", PYTHON_IMAGES)
def test_normalization_precedes_runtime_directory_creation_and_nonroot_user(image):
    dockerfile = (ROOT / image).read_text()
    command = source_permission_command(dockerfile)
    assert dockerfile.index("COPY src/sigrift/ src/sigrift/") < dockerfile.index(
        command
    )
    assert dockerfile.index(command) < dockerfile.index("RUN groupadd")
    assert dockerfile.index(command) < dockerfile.index("USER appuser")
    if "/bridge/" in image:
        assert "&& chmod 0700 /app/secrets" in dockerfile


@pytest.mark.parametrize("image", ALL_IMAGES)
def test_public_legal_notices_have_explicit_readable_copy_permissions(image):
    dockerfile = (ROOT / image).read_text()
    assert "COPY --chmod=0644 LICENSE NOTICE /app/" in dockerfile
    if image == "src/gateway/Dockerfile":
        assert (
            "COPY --chmod=0644 licenses/gateway/THIRD-PARTY-NOTICES.txt "
            "/app/THIRD-PARTY-NOTICES.txt"
        ) in dockerfile
