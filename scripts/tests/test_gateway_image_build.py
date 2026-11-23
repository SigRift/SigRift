"""The gateway image compiles the gateway from the sources it was given."""

import os
from pathlib import Path
import re
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]


def cargo_build_command(dockerfile: str) -> str:
    """The shell command of the builder's ``RUN`` that runs cargo, without
    its ``--mount`` options and line continuations."""
    runs = re.findall(r"^RUN (.*?)(?<!\\)$", dockerfile, re.M | re.S)
    (command,) = [run for run in runs if "cargo build --release" in run]
    command = command.replace("\\\n", " ")
    return " ".join(re.sub(r"--mount=\S+", "", command).split())


def test_the_cargo_step_keeps_its_target_cache():
    command = cargo_build_command((ROOT / "src/gateway/Dockerfile").read_text())
    assert "cargo build --release -p sigrift-gateway" in command
    dockerfile = (ROOT / "src/gateway/Dockerfile").read_text()
    assert "--mount=type=cache,target=/build/target,sharing=locked" in dockerfile


def test_gateway_sources_are_newer_than_any_cached_build(tmp_path):
    """Cargo takes a workspace crate as fresh when none of its source files
    is newer than its cached build. The ``/build/target`` cache mount is
    shared by every image build on the host's BuildKit, and ``COPY`` keeps
    the build context's mtimes, so a checkout made before another
    checkout's build reused that build's binary: cargo printed "Finished"
    with nothing compiled, and the candidate gate ran a gateway that had
    none of its commit's changes. The cargo step must first make the
    gateway sources newer than any cached build; the other sources and
    the cached dependencies are left alone.
    """
    command = cargo_build_command((ROOT / "src/gateway/Dockerfile").read_text())
    before_cargo = command.split("cargo build", 1)[0].strip()
    assert before_cargo.endswith("&&"), command
    before_cargo = before_cargo.removesuffix("&&").strip()

    old = time.time() - 30 * 24 * 3600
    gateway = [
        tmp_path / "src/gateway/crates/sigrift-gateway-core/src/lib.rs",
        tmp_path / "src/gateway/crates/sigrift-gateway/Cargo.toml",
        tmp_path / "src/gateway/crates/sigrift-gateway-core/src/auth/mod.rs",
    ]
    other = tmp_path / "src/sigrift/bridge/app.py"
    for path in [*gateway, other]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n")
        os.utime(path, (old, old))
    started = time.time() - 5
    subprocess.run(["sh", "-c", before_cargo], cwd=tmp_path, check=True)
    for path in gateway:
        assert path.stat().st_mtime >= started, path
    assert other.stat().st_mtime == old
