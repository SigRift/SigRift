#!/usr/bin/env python3
"""Generate gateway dependency notices with cargo-about, or check them offline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = "0.9.3"
DIRECTORY = Path("licenses/gateway")
OUTPUT = DIRECTORY / "THIRD-PARTY-NOTICES.txt"
MANIFEST = DIRECTORY / "manifest.json"
CHECKSUMS = DIRECTORY / "SHA256SUMS"
INPUTS = (
    Path("LICENSE"),
    Path("Cargo.lock"),
    Path("Cargo.toml"),
    Path("src/gateway/crates/sigrift-gateway/Cargo.toml"),
    Path("src/gateway/crates/sigrift-gateway-core/Cargo.toml"),
    DIRECTORY / "about.toml",
    DIRECTORY / "about.hbs",
    Path("scripts/gateway-notices.py"),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def current_manifest(root: Path) -> dict:
    return {
        "format": 1,
        "generator": f"cargo-about {TOOL_VERSION}",
        "inputs": {path.as_posix(): digest(root / path) for path in INPUTS},
        "output": {OUTPUT.as_posix(): digest(root / OUTPUT)},
    }


def current_checksums(root: Path) -> str:
    # The builder has sha256sum already; no reporting tool or Python install
    # is needed to enforce the same input/output freshness during image builds.
    return "".join(
        f"{digest(root / path)}  {path.as_posix()}\n"
        for path in (*INPUTS, OUTPUT, MANIFEST)
    )


def check(root: Path) -> list[str]:
    try:
        recorded = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
        current = current_manifest(root)
        checksums_match = (root / CHECKSUMS).read_text(
            encoding="utf-8"
        ) == current_checksums(root)
    except (OSError, ValueError) as error:
        return [f"Cannot verify gateway notices: {error}"]
    if not isinstance(recorded, dict):
        return ["Gateway notice manifest is not an object"]
    problems = []
    if not checksums_match:
        problems.append("Gateway notice SHA256SUMS is stale or modified")
    for field in ("format", "generator"):
        if recorded.get(field) != current[field]:
            problems.append(f"Gateway notice {field} is outdated")
    for field in ("inputs", "output"):
        previous = recorded.get(field)
        if not isinstance(previous, dict):
            problems.append(f"Gateway notice manifest lacks {field}")
            continue
        for path in sorted(set(previous) | set(current[field])):
            if previous.get(path) != current[field].get(path):
                problems.append(f"Gateway notices are stale or modified: {path}")
    return problems


def generate(root: Path, *, verify: bool = False) -> None:
    executable = os.environ.get("CARGO_ABOUT", "cargo-about")
    version = subprocess.check_output([executable, "--version"], text=True).strip()
    if version != f"cargo-about {TOOL_VERSION}":
        raise RuntimeError(f"Expected cargo-about {TOOL_VERSION}; found {version!r}")
    result = subprocess.run(
        [
            executable,
            "generate",
            "--locked",
            "--workspace",
            "--fail",
            "--config",
            str(DIRECTORY / "about.toml"),
            str(DIRECTORY / "about.hbs"),
        ],
        cwd=root,
        stdout=subprocess.PIPE,
        check=True,
    ).stdout
    if not result.strip():
        raise RuntimeError("cargo-about produced no notices")
    if verify:
        if result != (root / OUTPUT).read_bytes():
            raise RuntimeError(
                "Regenerated gateway notices differ from the checked-in file"
            )
        return
    (root / OUTPUT).write_bytes(result)
    (root / MANIFEST).write_text(
        json.dumps(current_manifest(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / CHECKSUMS).write_text(current_checksums(root), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check", action="store_true", help="offline hash/freshness check"
    )
    mode.add_argument(
        "--generate", action="store_true", help="regenerate with pinned cargo-about"
    )
    mode.add_argument(
        "--verify-generated",
        action="store_true",
        help="regenerate and compare without writing",
    )
    args = parser.parse_args()
    try:
        if args.generate or args.verify_generated:
            generate(ROOT, verify=args.verify_generated)
        problems = check(ROOT)
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        problems = [str(error)]
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(
            "Run scripts/gateway-notices.py --generate with cargo-about 0.9.3.",
            file=sys.stderr,
        )
        return 1
    print("Gateway dependency notices match the locked inputs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
