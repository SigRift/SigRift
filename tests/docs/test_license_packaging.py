"""Check licence metadata and run release packaging with small local fixtures."""

from __future__ import annotations

import ast
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap
import tomllib

import pytest

ROOT = Path(__file__).resolve().parents[2]
LEAFLET = Path("src/sigrift/bridge/static/vendor/LEAFLET-LICENSE")
GATEWAY_NOTICE = Path("licenses/gateway/THIRD-PARTY-NOTICES.txt")
NOTICES = [Path("LICENSE"), Path("NOTICE"), LEAFLET, GATEWAY_NOTICE]


@pytest.mark.parametrize(
    "path,section",
    [
        ("pyproject.toml", "project"),
        ("src/gateway/crates/sigrift-gateway/Cargo.toml", "package"),
        ("src/gateway/crates/sigrift-gateway-core/Cargo.toml", "package"),
    ],
)
def test_package_licenses_match_the_root_grant(path, section):
    metadata = tomllib.loads((ROOT / path).read_text())
    assert metadata[section]["license"] == "MIT"
    assert (ROOT / "LICENSE").read_text().startswith("MIT License\n")


def test_vendored_leaflet_retains_its_exact_upstream_license():
    # https://raw.githubusercontent.com/Leaflet/Leaflet/v1.9.4/LICENSE
    # Pin the complete notice, not just its SPDX identifier or copyright
    # heading: the conditions and disclaimer must travel with the assets.
    assert hashlib.sha256((ROOT / LEAFLET).read_bytes()).hexdigest() == (
        "53e8dc25862014e4324741ca18fbe3611e11d42ef69f59f86ea8c5389647d4cb"
    )
    assert "Leaflet 1.9.4" in (ROOT / LEAFLET.parent / "leaflet.js").read_text()[:200]
    assert "LEAFLET-LICENSE" in (ROOT / "NOTICE").read_text()


@pytest.mark.parametrize(
    "dockerfile",
    [
        "src/gateway/Dockerfile",
        "src/sigrift/bridge/Dockerfile",
        "src/sigrift/edge/Dockerfile",
    ],
)
def test_runtime_stages_ship_the_project_notices(dockerfile):
    # A copy into the gateway builder would disappear from the runtime
    # image. Check the final stage and resolve COPY inputs from the tree.
    runtime = re.split(r"(?im)^FROM\s+", (ROOT / dockerfile).read_text())[-1]
    runtime = re.sub(r"\\\r?\n", " ", runtime)
    copied = set()
    copy_targets = set()
    for line in runtime.splitlines():
        if not line.startswith("COPY "):
            continue
        parts = shlex.split(line)[1:]
        if any(p.startswith("--from=") for p in parts):
            continue
        parts = [p for p in parts if not p.startswith("--")]
        copy_targets.update((source, parts[-1]) for source in parts[:-1])
        if parts[-1] in ("/app/", "./"):
            copied.update(parts[:-1])
    assert {"LICENSE", "NOTICE"} <= copied
    assert all((ROOT / name).is_file() for name in ("LICENSE", "NOTICE"))
    if "sigrift/" in dockerfile:
        # The Python images ship the entire package, including Leaflet.
        assert "COPY src/sigrift/ src/sigrift/" in runtime
        assert (ROOT / LEAFLET).is_file()
    else:
        assert (str(GATEWAY_NOTICE), "/app/THIRD-PARTY-NOTICES.txt") in copy_targets
        builder = (ROOT / dockerfile).read_text().split(" AS runtime")[0]
        assert "RUN sha256sum --check licenses/gateway/SHA256SUMS" in builder


def test_gateway_notices_retain_known_linked_dependency_texts():
    report = (ROOT / GATEWAY_NOTICE).read_text()
    locked = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    for name in ("tokio", "ring", "aws-lc-sys", "rustls", "libsqlite3-sys"):
        version = next(
            package["version"] for package in locked if package["name"] == name
        )
        assert f"{name} {version}" in report
    assert "Copyright (c) Tokio Contributors" in report
    assert "Permission is hereby granted, free of charge" in report
    assert "Copyright (c) 1998-2011 The OpenSSL Project" in report
    assert "Copyright Amazon.com, Inc. or its affiliates." in report
    assert "Copyright (c) 2018 the rustasync developers" in report
    assert "Copyright (c) 2017 Pierre Chifflier" in report
    assert "Copyright (c) <year> <copyright holders>" not in report
    assert "THIRD-PARTY-NOTICES.txt" in (ROOT / "NOTICE").read_text()


def test_gateway_notice_check_runs_without_rust_or_network_tools():
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/gateway-notices.py"), "--check"],
        cwd=ROOT,
        env=dict(os.environ, PATH="", CARGO_ABOUT="must-not-be-executed"),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    "changed",
    [
        "LICENSE",
        "Cargo.lock",
        "Cargo.toml",
        "src/gateway/crates/sigrift-gateway/Cargo.toml",
        "src/gateway/crates/sigrift-gateway-core/Cargo.toml",
        "licenses/gateway/about.toml",
        "licenses/gateway/about.hbs",
        "scripts/gateway-notices.py",
        str(GATEWAY_NOTICE),
        "licenses/gateway/manifest.json",
        "licenses/gateway/SHA256SUMS",
    ],
)
def test_gateway_notice_check_rejects_changed_inputs_and_outputs(tmp_path, changed):
    # Execute the actual offline entry point in a small fixture, after changing
    # one byte of an input or packaged output. No reporting tool is installed.
    import json

    manifest = json.loads((ROOT / "licenses/gateway/manifest.json").read_text())
    files = [
        *manifest["inputs"],
        *manifest["output"],
        "licenses/gateway/manifest.json",
        "licenses/gateway/SHA256SUMS",
    ]
    for path in files:
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, destination)
    with (tmp_path / changed).open("a") as changed_file:
        changed_file.write("\n")
    result = subprocess.run(
        [sys.executable, str(tmp_path / "scripts/gateway-notices.py"), "--check"],
        cwd=tmp_path,
        env=dict(os.environ, PATH="", CARGO_ABOUT="must-not-be-executed"),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "stale or modified" in result.stderr


def test_training_export_metadata_declares_mit_without_loading_ml():
    tree = ast.parse((ROOT / "training/train_open_default.py").read_text())
    declarations = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value == "license":
                declarations.append(ast.literal_eval(value))
    assert declarations == ["MIT"]


def packaging_script(step_name):
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    step = re.search(
        rf"^      - name: {re.escape(step_name)}\n(.*?)(?=^      - |\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    assert step, f"release packaging step missing: {step_name}"
    body = re.search(r"^        run: \|\n(.*)", step.group(1), re.MULTILINE | re.DOTALL)
    assert body, f"packaging step is not a shell block: {step_name}"
    script = textwrap.dedent(body.group(1))
    # Support the older workflow during the PR merge as well as the
    # hardened workflow's environment-based inputs. No input is external.
    for expression, value in {
        "needs.resolve-version.outputs.version": "v0.0.0-license-test",
        "needs.resolve-version.outputs.owner": "sigrift",
        "github.repository": "SigRift/SigRift",
    }.items():
        script = script.replace("${{ " + expression + " }}", value)
    assert "${{" not in script
    return script


def run(command, directory, env):
    return subprocess.run(
        command,
        cwd=directory,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


def assert_archive_notices(path, prefix, notices, *, flatten=False):
    with tarfile.open(path) as archive:
        for notice in notices:
            filename = notice.name if flatten else notice.as_posix()
            member = archive.extractfile(f"{prefix}{filename}")
            assert member is not None, notice
            assert member.read() == (ROOT / notice).read_bytes()


def test_release_archives_retain_notices(tmp_path):
    """Execute the real packaging steps; no compiler, image build or network."""
    for notice in NOTICES:
        destination = tmp_path / notice
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / notice, destination)
    for path in ("README.md", "scripts/install-release.sh", ".gitattributes"):
        if (ROOT / path).exists():
            destination = tmp_path / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)
    binary = tmp_path / "target/release/sigrift-gateway"
    binary.parent.mkdir(parents=True)
    binary.write_text("packaging fixture; never executed\n")
    env = dict(
        os.environ,
        VERSION="v0.0.0-license-test",
        OWNER="sigrift",
        REPO="SigRift/SigRift",
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_GLOBAL=os.devnull,
    )
    run(["git", "init", "--quiet"], tmp_path, env)
    run(["git", "add", "."], tmp_path, env)
    run(
        [
            "git",
            "-c",
            "user.name=License Test",
            "-c",
            "user.email=license-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        tmp_path,
        env,
    )
    run(["git", "tag", env["VERSION"]], tmp_path, env)
    env["COMMIT"] = run(["git", "rev-parse", "HEAD"], tmp_path, env).stdout.strip()
    # A moved tag must not change the source bytes approved by the preflight.
    marker = tmp_path / "post-approval-marker.txt"
    marker.write_text("This file is not part of the verified release commit.\n")
    run(["git", "add", marker.name], tmp_path, env)
    run(
        [
            "git",
            "-c",
            "user.name=License Test",
            "-c",
            "user.email=license-test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "advance tag after verification",
        ],
        tmp_path,
        env,
    )
    run(["git", "tag", "--force", env["VERSION"]], tmp_path, env)
    for name in (
        "Package gateway binary",
        "Source archive",
        "Build install-release tarball",
    ):
        run(["bash", "-eu", "-c", packaging_script(name)], tmp_path, env)

    dist, version = tmp_path / "dist", env["VERSION"]
    assert_archive_notices(
        dist / f"sigrift-gateway-{version}-linux-x86_64.tar.gz",
        "",
        [*NOTICES[:2], GATEWAY_NOTICE],
        flatten=True,
    )
    assert_archive_notices(
        dist / f"sigrift-{version}.tar.gz",
        f"sigrift-{version}/",
        [*NOTICES[:2], GATEWAY_NOTICE],
        flatten=True,
    )
    assert_archive_notices(
        dist / f"sigrift-open-{version}-source.tar.gz",
        f"sigrift-open-{version}/",
        NOTICES,
    )
    with tarfile.open(dist / f"sigrift-open-{version}-source.tar.gz") as archive:
        assert f"sigrift-open-{version}/{marker.name}" not in archive.getnames()
