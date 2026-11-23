"""UPGRADE.md's Docker upgrade and rollback commands match docker-compose.yml.

Regression: the rollback retagged ``bridge:previous`` / ``gateway:previous``
as ``bridge:latest`` / ``gateway:latest`` and mounted ``bridge_data``, names
compose never uses (for a ``build:`` service it runs ``<project>-bridge`` /
``<project>-gateway``, and the volume is ``<project>_bridge_data``). It also
restored a ``backups/detections.db.pre-upgrade`` that no Docker step created.
So the tags failed or changed nothing, the restore found an empty volume,
and the final ``docker compose up -d`` started the new release again.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
UPGRADE = ROOT / "src/sigrift/bridge/UPGRADE.md"
COMPOSE = ROOT / "docker-compose.yml"


def _docker_blocks() -> tuple[str, str]:
    """The bash blocks of "Docker Upgrade" (first) and "Docker Rollback" (last)."""
    text = UPGRADE.read_text(encoding="utf-8")
    upgrade = text.index("### Docker Upgrade")
    rollback = text.index("### Docker Rollback", upgrade)
    end = text.index("\n### ", rollback + 1)
    bash = re.compile(r"```bash\n(.*?)```", re.S)
    upgrade_blocks = bash.findall(text[upgrade:rollback])
    rollback_blocks = bash.findall(text[rollback:end])
    assert upgrade_blocks and rollback_blocks
    return upgrade_blocks[0], rollback_blocks[-1]


def _bridge_data_dir() -> str:
    """Where the bridge service mounts the ``bridge_data`` volume."""
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    for volume in services["bridge"]["volumes"]:
        source, _, target = volume.partition(":")
        if source == "bridge_data":
            return target
    raise AssertionError("bridge_data is not mounted on the bridge")


def test_compose_builds_the_bridge_and_gateway_images():
    # Why the doc must ask compose for the names: they depend on the project.
    services = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))["services"]
    for name in ("bridge", "gateway"):
        assert "build" in services[name], name
        assert "image" not in services[name], name


def test_docker_commands_never_guess_image_or_volume_names():
    commands = "\n".join(_docker_blocks())
    assert not re.search(r"(?<![\w-])(bridge|gateway):(latest|previous)\b", commands)
    assert not re.search(r"-v\s+\$?\(?\S*bridge_data", commands)
    assert "docker run" not in commands


def _docker_tags(block: str) -> dict[str, str]:
    """``{source: target}`` of the block's ``docker tag`` commands."""
    tags = {}
    for line in block.splitlines():
        if line.startswith("docker tag "):
            words = shlex.split(line)
            if words[-1] == "&&":
                words = words[:-1]
            _docker, _tag, source, target = words
            tags[source] = target
    return tags


def test_previous_images_are_kept_and_given_back_the_names_compose_runs():
    upgrade, rollback = _docker_blocks()
    assert _docker_tags(upgrade) == {
        "$(docker compose images -q bridge)": "sigrift-bridge:previous",
        "$(docker compose images -q gateway)": "sigrift-gateway:previous",
    }
    # Tagged before the new images are built.
    assert upgrade.index("docker tag") < upgrade.index("docker compose build")
    assert _docker_tags(rollback) == {
        "sigrift-bridge:previous": "$(image_of bridge)",
        "sigrift-gateway:previous": "$(image_of gateway)",
    }
    # Nothing starts if a tag fails, so bridge and gateway never run at
    # different versions on the restored database.
    assert (
        'docker tag sigrift-bridge:previous "$(image_of bridge)" &&\n'
        'docker tag sigrift-gateway:previous "$(image_of gateway)" &&\n'
        "docker compose up -d --no-build bridge gateway"
    ) in rollback


def _image_of_function(block: str) -> str:
    start = block.index("image_of() {")
    return block[start : block.index("\n}\n", start) + 3]


@pytest.mark.skipif(
    shutil.which("docker") is None
    or subprocess.run(["docker", "compose", "version"], capture_output=True).returncode
    != 0,
    reason="needs docker compose",
)
def test_image_of_prints_each_services_own_image_name(tmp_path):
    """``config --images gateway`` also lists the bridge (gateway depends on
    it), which made ``docker tag`` fail; ``image_of`` prints one name."""
    _upgrade, rollback = _docker_blocks()
    script = _image_of_function(rollback) + "image_of bridge\nimage_of gateway\n"
    env = {**os.environ, "COMPOSE_PROJECT_NAME": "imageofprobe"}
    for name in ("BRIDGE_ADMIN_PASSWORD", "UC_PROXY_SECRET"):
        env.setdefault(name, "x")
    out = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, env=env, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.splitlines() == ["imageofprobe-bridge", "imageofprobe-gateway"]
    both = subprocess.run(
        ["docker", "compose", "config", "--images", "gateway"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if both.returncode == 0:
        # Why image_of exists: compose adds the dependency.
        assert sorted(both.stdout.split()) == [
            "imageofprobe-bridge",
            "imageofprobe-gateway",
        ]


def test_rollback_restores_the_copy_the_upgrade_makes():
    upgrade, rollback = _docker_blocks()
    data_dir = _bridge_data_dir()
    for block in (upgrade, rollback):
        # In the stack's own volume, through the bridge service (its user
        # owns the files), with both services stopped.
        assert "docker compose stop gateway bridge" in block
        assert "docker compose run --rm --no-deps bridge sh -c" in block
        assert f"cd {data_dir} &&" in block
    assert "cp -p detections.db detections.db.pre-upgrade" in upgrade
    assert "cp -p detections.db-wal detections.db-wal.pre-upgrade" in upgrade
    assert upgrade.index("detections.db.pre-upgrade") < upgrade.index(
        "docker compose build"
    )
    assert "test -e detections.db.pre-upgrade &&" in rollback
    assert "cp -p detections.db.pre-upgrade detections.db" in rollback
    assert "cp -p detections.db-wal.pre-upgrade detections.db-wal" in rollback
    assert rollback.index("detections.db.pre-upgrade") < rollback.index("docker tag")
