#!/usr/bin/env python3
"""SEC-M17: Verify installed package integrity against pinned hashes.

Generates an SBOM (Software Bill of Materials) and optionally checks
the installed packages:

* every file a tracked package installed is hashed and compared with the
  sha256 its wheel recorded in ``<dist-info>/RECORD`` — a modified or
  missing file is reported (a ``.pyc``, which pip lists without a hash
  because it is generated at install time, cannot be checked this way);
* the hash of the RECORD file itself is compared with the one saved by
  ``--save``, which catches a reinstall or a rewritten RECORD.

Usage:
    python scripts/verify_deps.py                # Generate SBOM to stdout
    python scripts/verify_deps.py --check        # Verify against saved hashes
    python scripts/verify_deps.py --save         # Save current hashes
    python scripts/verify_deps.py -o sbom.json   # Write SBOM to file
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

# Packages we care about (from requirements.txt)
TRACKED_PACKAGES = [
    "numpy", "torch", "scipy", "scikit-learn", "h5py", "joblib",
    "onnxruntime", "fastapi", "uvicorn", "httpx", "pydantic",
    "starlette", "jinja2", "python-multipart",
    "cryptography", "paramiko", "psutil", "pyyaml",
]

HASH_FILE = Path(__file__).parent.parent / "data" / ".dep_hashes.json"


def _distribution(name: str) -> importlib.metadata.Distribution:
    """The installed distribution *name* (a seam for the tests)."""
    return importlib.metadata.distribution(name)


def _record_text(dist: importlib.metadata.Distribution) -> str | None:
    try:
        return dist.read_text("RECORD")
    except OSError:
        return None


def verify_record(dist: importlib.metadata.Distribution) -> list[str]:
    """Check each file *dist* installed against the hash in its RECORD.

    Returns one issue per missing or modified file (empty when all match),
    or a single issue when there is no RECORD or no hash entries to check
    against (e.g. an egg-info install or an empty manifest).
    """
    name = dist.metadata["Name"]
    text = _record_text(dist)
    if text is None:
        return [f"{name}: no RECORD file, so its installed files cannot be verified"]
    issues: list[str] = []
    has_hash_entries = False
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or not row[1]:
            continue  # RECORD itself, .pyc files: listed without a hash
        has_hash_entries = True
        path, digest = row[0], row[1]
        algo, sep, expected = digest.partition("=")
        if not sep or algo not in hashlib.algorithms_guaranteed:
            issues.append(f"{name}: {path}: unusable RECORD hash {digest!r}")
            continue
        h = hashlib.new(algo)
        if h.digest_size == 0:
            # Extendable-output hashes need a caller-chosen length; RECORD
            # has no such parameter. Report an unusable hash, not a crash.
            issues.append(f"{name}: {path}: unusable RECORD hash {digest!r}")
            continue
        try:
            with open(dist.locate_file(path), "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
        except FileNotFoundError:
            issues.append(f"{name}: {path} is missing")
            continue
        except OSError as exc:
            issues.append(f"{name}: {path} cannot be read ({exc.strerror})")
            continue
        actual = base64.urlsafe_b64encode(h.digest()).rstrip(b"=").decode()
        if actual != expected.rstrip("="):
            issues.append(
                f"{name}: {path} does not match the hash its wheel recorded "
                "(modified after install?)"
            )
    if not has_hash_entries:
        issues.append(
            f"{name}: no RECORD hash entries, so its installed files cannot be verified"
        )
    return issues


def get_package_info(name: str) -> dict | None:
    """Get installed package metadata."""
    try:
        dist = _distribution(name)
    except importlib.metadata.PackageNotFoundError:
        return None

    # sha256 of the RECORD file: the list of every installed file with its
    # hash, so it changes whenever the installed file set does. (No RECORD
    # — e.g. an egg-info install — means nothing to fingerprint.)
    text = _record_text(dist)
    record_hash = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else None

    return {
        "name": dist.metadata["Name"],
        "version": dist.version,
        "license": dist.metadata.get("License", "unknown"),
        "record_sha256": record_hash,
    }


def generate_sbom() -> dict:
    """Generate a Software Bill of Materials."""
    packages = []
    for name in sorted(TRACKED_PACKAGES):
        info = get_package_info(name)
        if info:
            packages.append(info)
        else:
            packages.append({
                "name": name,
                "version": "NOT INSTALLED",
                "license": "unknown",
                "record_sha256": None,
            })

    return {
        "sbom_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "packages": packages,
        "total_tracked": len(TRACKED_PACKAGES),
        "total_installed": sum(1 for p in packages if p["version"] != "NOT INSTALLED"),
    }


def save_hashes(sbom: dict) -> None:
    """Save current package hashes for future verification."""
    hashes = {
        p["name"]: {"version": p["version"], "sha256": p["record_sha256"]}
        for p in sbom["packages"]
        if p["record_sha256"]
    }
    HASH_FILE.parent.mkdir(parents=True, exist_ok=True)
    HASH_FILE.write_text(json.dumps(hashes, indent=2))
    logger.info("Saved %d package hashes to %s", len(hashes), HASH_FILE)


def check_hashes(sbom: dict) -> list[str]:
    """Check current packages against saved hashes. Returns list of issues.

    Besides the saved RECORD hashes, every installed file of each tracked
    package is checked against its RECORD (see :func:`verify_record`).
    """
    if not HASH_FILE.exists():
        return ["No saved hashes found. Run with --save first."]

    saved = json.loads(HASH_FILE.read_text())
    issues: list[str] = []

    for pkg in sbom["packages"]:
        name = pkg["name"]
        if pkg["version"] != "NOT INSTALLED":
            try:
                issues.extend(verify_record(_distribution(name)))
            except importlib.metadata.PackageNotFoundError:
                issues.append(f"{name}: no longer installed")
        if name not in saved:
            continue
        expected = saved[name]
        if pkg["version"] != expected["version"]:
            issues.append(
                f"{name}: version changed {expected['version']} → {pkg['version']}"
            )
        elif pkg["record_sha256"] and pkg["record_sha256"] != expected["sha256"]:
            issues.append(
                f"{name}: RECORD hash mismatch (possible tampering or reinstall)"
            )

    return issues


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description="Dependency integrity verifier")
    parser.add_argument("--check", action="store_true", help="Verify against saved hashes")
    parser.add_argument("--save", action="store_true", help="Save current hashes")
    parser.add_argument("-o", "--output", help="Write SBOM to file")
    args = parser.parse_args()

    sbom = generate_sbom()

    if args.save:
        save_hashes(sbom)
        print(f"Saved {sbom['total_installed']} package hashes.")
        return 0

    if args.check:
        issues = check_hashes(sbom)
        if issues:
            for issue in issues:
                print(f"WARN: {issue}", file=sys.stderr)
            return 1
        print(f"OK: {sbom['total_installed']} packages verified.")
        return 0

    output = json.dumps(sbom, indent=2)
    if args.output:
        Path(args.output).write_text(output)
        print(f"SBOM written to {args.output}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
