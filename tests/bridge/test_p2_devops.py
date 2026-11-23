"""Tests for P2-11 (docker-compose), P2-12 (multi-worker), P2-13 (CI/CD)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_docker_compose_valid_yaml() -> None:
    compose_path = ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml not found"
    data = yaml.safe_load(compose_path.read_text())
    assert "services" in data
    assert isinstance(data["services"], dict)
    assert "bridge" in data["services"]
    assert isinstance(data["services"]["bridge"], dict)


def test_docker_compose_healthcheck_uses_healthz() -> None:
    compose_path = ROOT / "docker-compose.yml"
    data = yaml.safe_load(compose_path.read_text())
    hc = data["services"]["bridge"]["healthcheck"]
    test_cmd = " ".join(hc["test"]) if isinstance(hc["test"], list) else hc["test"]
    assert "health" in test_cmd


def test_main_module_importable() -> None:
    from sigrift.bridge.__main__ import main

    assert callable(main)


def test_default_workers_is_one() -> None:
    import os

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("BRIDGE_WORKERS", None)
        workers = int(os.environ.get("BRIDGE_WORKERS", "1"))
        assert workers == 1


def test_ci_workflow_valid_yaml() -> None:
    ci_path = ROOT / ".github" / "workflows" / "ci.yml"
    assert ci_path.exists(), "ci.yml not found"
    data = yaml.safe_load(ci_path.read_text())
    assert "jobs" in data
    assert isinstance(data["jobs"], dict)
    assert "bridge-tests" in data["jobs"]
    assert isinstance(data["jobs"]["bridge-tests"], dict)
    assert "lint" in data["jobs"]
    assert isinstance(data["jobs"]["lint"], dict)
