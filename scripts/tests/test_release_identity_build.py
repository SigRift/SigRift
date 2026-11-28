"""The images carry the release they were built for, and compose passes the
new bridge settings (Phase 3 of the upgrade proposal).

    python3 -m pytest scripts/tests -q

``SIGRIFT_RELEASE`` is a build arg of the bridge and gateway images, set
after every ``RUN`` so no cached layer depends on it: release.yml passes
the validated tag, build-and-push.yml ``main-<sha12>``.  The bridge reports
it in ``/api/version``; the gateway only carries it (ENV and the OCI
version label).  docker-compose.yml passes ``BRIDGE_KEYSTORE_KEY`` and
``BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP`` to the bridge only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BRIDGE_DOCKERFILE = ROOT / "src" / "sigrift" / "bridge" / "Dockerfile"
GATEWAY_DOCKERFILE = ROOT / "src" / "gateway" / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"
RELEASE_LINES = [
    "ARG SIGRIFT_RELEASE=dev",
    "ENV SIGRIFT_RELEASE=${SIGRIFT_RELEASE}",
    "LABEL org.opencontainers.image.version=${SIGRIFT_RELEASE}",
]


def _instructions(path: Path) -> list[str]:
    """The Dockerfile's instruction lines (comments and continuations dropped)."""
    lines = []
    for line in path.read_text().splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            lines.append(line)
    return lines


def _index(lines: list[str], line: str) -> int:
    assert line in lines, line
    return lines.index(line)


def _yaml(name: str) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((WORKFLOWS / name).read_text())


def _build_step(workflow: dict, job: str) -> dict:
    (step,) = [s for s in workflow["jobs"][job]["steps"] if s.get("id") == "build"]
    return step


def test_bridge_image_declares_the_release_after_every_run_step() -> None:
    lines = _instructions(BRIDGE_DOCKERFILE)
    arg, env, label = (_index(lines, line) for line in RELEASE_LINES)
    assert arg < env < label
    runs = [i for i, line in enumerate(lines) if line.startswith("RUN ")]
    assert runs and arg > max(runs)
    (cmd,) = [line for line in lines if line.startswith("CMD ")]
    assert cmd.startswith('CMD ["sh", "-c", "python3 -m sigrift.bridge.ca migrate-key')


def test_gateway_image_declares_it_in_the_runtime_stage_only() -> None:
    lines = _instructions(GATEWAY_DOCKERFILE)
    froms = [i for i, line in enumerate(lines) if line.startswith("FROM ")]
    assert len(froms) == 2
    arg = _index(lines, RELEASE_LINES[0])
    assert all(_index(lines, line) > froms[-1] for line in RELEASE_LINES)
    copy_from_builder = [
        i for i, line in enumerate(lines) if line.startswith("COPY --from=builder")
    ]
    assert copy_from_builder and arg > max(copy_from_builder)
    builder = GATEWAY_DOCKERFILE.read_text().split("\nFROM ", 2)[1]
    assert "SIGRIFT_RELEASE" not in builder


def test_release_workflow_passes_the_validated_tag() -> None:
    step = _build_step(_yaml("release.yml"), "build-images")
    assert step["with"]["build-args"] == (
        "SIGRIFT_RELEASE=${{ needs.resolve-version.outputs.version }}"
    )


def test_build_and_push_passes_the_main_build_name() -> None:
    step = _build_step(_yaml("build-and-push.yml"), "build")
    assert step["with"]["build-args"] == (
        "SIGRIFT_RELEASE=main-${{ steps.meta.outputs.sha_short }}"
    )


def test_compose_passes_the_new_settings_to_the_bridge_only() -> None:
    yaml = pytest.importorskip("yaml")
    services = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
    wanted = [
        "BRIDGE_KEYSTORE_KEY=${BRIDGE_KEYSTORE_KEY:-}",
        "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=${BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP:-}",
    ]
    for line in wanted:
        assert line in services["bridge"]["environment"], line
    gateway = "\n".join(services["gateway"].get("environment", []))
    assert "BRIDGE_KEYSTORE_KEY" not in gateway
    assert "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP" not in gateway


def test_env_example_documents_the_new_settings() -> None:
    lines = (ROOT / ".env.example").read_text().splitlines()
    assert "BRIDGE_KEYSTORE_KEY=" in lines
    assert "# BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP=" in lines
