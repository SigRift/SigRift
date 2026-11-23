#!/usr/bin/env python3
"""Require LLVM line and branch coverage at or above the committed floor.

Regions are not branches. Every inventory, provenance and counter check fails
closed regardless of the floor; the measured line AND branch percentages must
then be at or above the ratchet floor in scripts/coverage-floors.json.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
FLOORS = ROOT / "scripts/coverage-floors.json"


def tracked_rust_files(root):
    paths = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z", "--", "*.rs"], text=True
    )
    inventory = set(paths.rstrip("\0").split("\0")) - {""}
    if not inventory:
        raise ValueError("Tracked Rust source inventory is empty")
    return inventory


def nonexecutable_files(root, inventory):
    """Accept only explicitly reviewed, byte-identical declaration-only files.

    LLVM omits modules containing no executable locations. A hash change
    requires a new review, so adding a function cannot inherit an exception.
    """
    manifest = root / "scripts/rust-coverage-nonexecutable.json"
    if not manifest.exists():
        return set()
    files = json.loads(manifest.read_text())["files"]
    if not isinstance(files, dict):
        raise ValueError("Nonexecutable Rust inventory must map paths to reviews")
    for name, review in files.items():
        if name not in inventory:
            raise ValueError(f"Nonexecutable Rust source is not tracked: {name}")
        if (
            not isinstance(review, dict)
            or not isinstance(review.get("reason"), str)
            or not review["reason"].strip()
        ):
            raise ValueError(f"Nonexecutable Rust source lacks a review reason: {name}")
        actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if review.get("sha256") != actual:
            raise ValueError(
                f"Nonexecutable Rust source changed; review required: {name}"
            )
    return set(files)


def counts(summary, metric):
    value = summary[metric]
    total, covered = value["count"], value["covered"]
    if (
        type(total) is not int
        or type(covered) is not int
        or total < 0
        or not 0 <= covered <= total
    ):
        raise ValueError(f"Invalid {metric} coverage counters")
    return total, covered


def summarize(report, expected_files, root=ROOT):
    if report.get("type") != "llvm.coverage.json.export":
        raise ValueError("Expected LLVM source-based coverage JSON")
    data = report["data"]
    if len(data) != 1 or not data[0]["files"]:
        raise ValueError("Expected one nonempty workspace coverage export")
    export = data[0]
    names = [item["filename"] for item in export["files"]]
    if any(not isinstance(name, str) or not name for name in names) or len(
        set(names)
    ) != len(names):
        raise ValueError("Coverage filenames must be nonempty and unique")
    # All tracked Rust sources are in scope, including modules the compiler
    # never visited. Nonexecutable exceptions are explicit and hash-checked
    # before this function; platform-only code is never silently excluded.
    root = root.resolve()
    actual_files = set()
    for name in names:
        path = Path(name)
        if not path.is_absolute():
            path = root / path
        actual_files.add(path.resolve().relative_to(root).as_posix())
    if actual_files != expected_files or len(actual_files) != len(names):
        raise ValueError(
            "Rust source inventory mismatch: "
            f"missing={sorted(expected_files - actual_files)}, "
            f"unexpected={sorted(actual_files - expected_files)}"
        )
    # Informational: the release gate is the committed floor (apply_floors).
    result = {"files": len(names), "complete": True}
    for metric in ("lines", "branches"):
        total, covered = counts(export["totals"], metric)
        per_file = [counts(item["summary"], metric) for item in export["files"]]
        if (total, covered) != tuple(map(sum, zip(*per_file, strict=True))):
            raise ValueError(f"{metric} totals do not match the reported files")
        if total == 0:
            raise ValueError(f"No {metric} measured; coverage cannot pass")
        result[metric] = {
            "total": total,
            "covered": covered,
            "missing": total - covered,
            "percent": round(100 * covered / total, 4),
        }
        result["complete"] &= covered == total
    return result


def load_floors(path=FLOORS, language="rust"):
    """Read one language's committed ratchet floors; malformed input fails closed."""
    try:
        floors = json.loads(Path(path).read_text())[language]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"Missing or invalid coverage floors for {language}") from exc
    if not isinstance(floors, dict) or set(floors) != {"lines", "branches"}:
        raise ValueError(f"Coverage floors for {language} need lines and branches")
    for metric, value in floors.items():
        if type(value) not in (int, float) or not 0 <= value <= 100:
            raise ValueError(f"Invalid {language} {metric} coverage floor")
    return floors


def apply_floors(summary, floors):
    """Pass only when exact covered/total meets each floor (no rounding)."""
    summary["floor"] = dict(floors)
    summary["passed"] = all(
        Fraction(100 * summary[metric]["covered"], summary[metric]["total"])
        >= Fraction(repr(floors[metric]))
        for metric in ("lines", "branches")
    )
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--floors",
        type=Path,
        default=FLOORS,
        help="Ratchet floors JSON (default: scripts/coverage-floors.json)",
    )
    args = parser.parse_args(argv)
    try:
        inventory = tracked_rust_files(args.root)
        nonexecutable = nonexecutable_files(args.root, inventory)
        floors = load_floors(args.floors)
        summary = apply_floors(
            summarize(
                json.loads(args.report.read_text()),
                inventory - nonexecutable,
                args.root,
            ),
            floors,
        )
        summary["tracked_files"] = len(inventory)
        summary["nonexecutable_files"] = sorted(nonexecutable)
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"Invalid Rust coverage report: {error}", file=sys.stderr)
        return 2
    rendered = json.dumps(summary, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered)
    print(rendered, end="")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
