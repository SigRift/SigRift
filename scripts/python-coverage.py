#!/usr/bin/env python3
"""Combine all Python CI partitions and enforce an honest release coverage gate.

The gate requires measured line AND branch percentages at or above the ratchet
floor committed in scripts/coverage-floors.json. Every provenance and inventory
check fails closed regardless of the floor.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import coverage

ROOT = Path(__file__).resolve().parents[1]
FLOORS = ROOT / "scripts/coverage-floors.json"
PARTS = ("bridge-1", "bridge-2", "bridge-3", "bridge-4", "shiny", "scripts")
MEASUREMENT_INPUTS = (
    ".coveragerc",
    "src/sigrift/bridge/requirements-test.in",
    "src/sigrift/bridge/requirements-test.txt",
)


def inventory(root):
    tracked = (
        subprocess.check_output(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                "*.py",
            ],
            cwd=root,
        )
        .decode()
        .split("\0")
    )
    # Test bodies, fixtures and embedded helpers are authored executable code.
    # Names and collection status never remove them from the denominator.
    included = sorted(set(filter(None, tracked)))
    if not included:
        raise ValueError("No first-party Python files found")
    return {"included": included, "excluded": []}


def source_state(root):
    sources = inventory(root)["included"]
    return {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root)
        .decode()
        .strip(),
        # Generated artifacts do not make source dirty. Authored Python and
        # measurement configuration must match the recorded commit.
        "dirty": bool(
            subprocess.check_output(
                [
                    "git",
                    "status",
                    "--porcelain",
                    "--untracked-files=all",
                    "--",
                    # Staged deletions are absent from the current inventory.
                    "*.py",
                    *sources,
                    *MEASUREMENT_INPUTS,
                ],
                cwd=root,
            )
        ),
    }


def measurement_identity(root):
    """Bind canonical configuration and exact tools used by trusted CI commands.

    Recording after a test command cannot attest arbitrary prior CLI overrides.
    CI invokes pytest-cov with this committed config, then records the partition
    using the same interpreter. All parts and report/check commands must agree.
    """
    root = root.resolve()
    config_path = root / ".coveragerc"
    override = os.environ.get("COVERAGE_RCFILE")
    if override and Path(override).resolve() != config_path:
        raise ValueError("Coverage provenance rejects alternate COVERAGE_RCFILE")
    hashes = {}
    for name in MEASUREMENT_INPUTS:
        path = root / name
        committed = subprocess.run(
            ["git", "show", "HEAD:" + name], cwd=root, capture_output=True
        )
        if committed.returncode:
            raise ValueError(
                "Coverage provenance requires committed measurement configuration"
            )
        if (
            not path.is_file()
            or path.is_symlink()
            or path.read_bytes() != committed.stdout
            or subprocess.check_output(
                ["git", "status", "--porcelain", "--untracked-files=all", "--", name],
                cwd=root,
            )
        ):
            raise ValueError(
                "Coverage provenance requires committed measurement configuration"
            )
        hashes[name] = hashlib.sha256(committed.stdout).hexdigest()
    configured = coverage.Coverage(config_file=str(config_path))
    if not configured.get_option("run:branch"):
        raise ValueError("Coverage measurement configuration requires branches")
    for option in ("run:omit", "report:omit"):
        if configured.get_option(option):
            raise ValueError(f"Authored Python exclusions are forbidden: {option}")
    for option in ("exclude_lines", "exclude_also", "partial_branches", "partial_also"):
        if configured.get_option("report:" + option):
            raise ValueError(f"Coverage suppression is forbidden: report:{option}")
    return {
        "scope": "all-authored-python-v1",
        "config_sha256": hashes.pop(".coveragerc"),
        "requirements_sha256": hashes,
        "python_implementation": sys.implementation.name,
        # Include release level/serial as well as major/minor/micro. Exclude
        # compiler/build timestamps, which are not interpreter version fields.
        "python_version": list(sys.version_info),
        "coverage_version": coverage.__version__,
    }


def record_partition(part, root=ROOT):
    source = source_state(root)
    if source["dirty"]:
        raise ValueError(
            "Coverage provenance requires committed Python source and measurement configuration"
        )
    path = root / (".coverage." + part)
    metadata = {
        "part": part,
        "source_commit": source["commit"],
        "data_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "measurement": measurement_identity(root),
    }
    path.with_name(path.name + ".metadata.json").write_text(
        json.dumps(metadata, sort_keys=True) + "\n"
    )
    return metadata


def partition_files(directory, expected_commit, expected_measurement):
    expected = {"python-coverage-part-" + part for part in PARTS}
    actual = {path.name for path in directory.iterdir() if path.is_dir()}
    if actual != expected:
        raise ValueError(
            f"Coverage partitions differ: expected {sorted(expected)}, got {sorted(actual)}"
        )
    paths = []
    for part in PARTS:
        path = directory / ("python-coverage-part-" + part) / (".coverage." + part)
        try:
            metadata = json.loads(
                path.with_name(path.name + ".metadata.json").read_text()
            )
            data_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Missing or invalid coverage provenance for {part}"
            ) from exc
        if (
            not isinstance(metadata, dict)
            or metadata.get("part") != part
            or metadata.get("source_commit") != expected_commit
            or metadata.get("data_sha256") != data_hash
            or metadata.get("measurement") != expected_measurement
        ):
            raise ValueError(f"Coverage provenance mismatch for {part}")
        data = coverage.CoverageData(basename=str(path))
        data.read()
        if not path.is_file() or not data.has_arcs() or not data.measured_files():
            raise ValueError(f"Missing or empty branch coverage for {part}")
        paths.append(str(path))
    return paths


def validate_report(report, source_inventory, expected_measurement=None):
    if (
        expected_measurement is not None
        and report["meta"].get("version") != expected_measurement["coverage_version"]
    ):
        raise ValueError("Coverage report writer version does not match provenance")
    if not report["meta"].get("branch_coverage"):
        raise ValueError("Python report has no branch instrumentation")
    expected, measured = set(source_inventory["included"]), set(report["files"])
    if expected != measured:
        raise ValueError(
            f"Python source inventory mismatch: missing={sorted(expected - measured)}, unexpected={sorted(measured - expected)}"
        )
    counts = {
        key: 0
        for key in (
            "covered_lines",
            "num_statements",
            "covered_branches",
            "num_branches",
        )
    }
    for name, result in report["files"].items():
        summary = result["summary"]
        for key in (*counts, "excluded_lines"):
            if type(summary[key]) is not int or summary[key] < 0:
                raise ValueError(f"Invalid coverage count for {name}: {key}")
        if (
            summary["covered_lines"] > summary["num_statements"]
            or summary["covered_branches"] > summary["num_branches"]
        ):
            raise ValueError(f"Coverage exceeds executable code for {name}")
        if summary["excluded_lines"]:
            raise ValueError(f"Runtime lines were excluded from coverage: {name}")
        for key in counts:
            counts[key] += summary[key]
    totals = report["totals"]
    if any(
        type(totals[key]) is not int or totals[key] != value
        for key, value in counts.items()
    ):
        raise ValueError("Coverage totals do not match the file inventory")
    lines, branches = totals["num_statements"], totals["num_branches"]
    covered_lines, covered_branches = (
        totals["covered_lines"],
        totals["covered_branches"],
    )
    if (
        not (0 <= covered_lines <= lines and 0 <= covered_branches <= branches)
        or not lines
        or not branches
    ):
        raise ValueError("Coverage totals are empty or inconsistent")
    return {
        "files": len(expected),
        "lines": {
            "covered": covered_lines,
            "total": lines,
            "percent": round(100 * covered_lines / lines, 4),
        },
        "branches": {
            "covered": covered_branches,
            "total": branches,
            "percent": round(100 * covered_branches / branches, 4),
        },
        # Informational: the release gate is the committed floor, not 100%.
        "complete": covered_lines == lines and covered_branches == branches,
    }


def load_floors(path=FLOORS, language="python"):
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


def combine(directory, output, root=ROOT):
    source = source_state(root)
    if source["dirty"]:
        raise ValueError(
            "Coverage provenance requires committed Python source and measurement configuration"
        )
    identity = measurement_identity(root)
    paths = partition_files(directory, source["commit"], identity)
    output.mkdir(parents=True, exist_ok=True)
    measurement = coverage.Coverage(
        config_file=str(root / ".coveragerc"), data_file=str(output / ".coverage")
    )
    measurement.combine(data_paths=paths, strict=True, keep=True)
    measurement.save()
    measurement.json_report(outfile=str(output / "coverage.json"))
    measurement.xml_report(outfile=str(output / "coverage.xml"))
    measurement.html_report(directory=str(output / "html"))
    source_inventory = inventory(root)
    report = json.loads((output / "coverage.json").read_text())
    summary = validate_report(report, source_inventory, identity)
    summary["source"] = source
    summary["measurement"] = identity
    summary["report_sha256"] = hashlib.sha256(
        (output / "coverage.json").read_bytes()
    ).hexdigest()
    (output / "inventory.json").write_text(
        json.dumps(source_inventory, indent=2) + "\n"
    )
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def check_report(path, root=ROOT):
    source = source_state(root)
    if source["dirty"]:
        raise ValueError(
            "Coverage provenance requires committed Python source and measurement configuration"
        )
    identity = measurement_identity(root)
    try:
        provenance = json.loads(path.with_name("summary.json").read_text())
        raw = path.read_bytes()
    except (OSError, ValueError) as exc:
        raise ValueError("Missing or invalid combined coverage provenance") from exc
    if (
        not isinstance(provenance, dict)
        or provenance.get("source") != source
        or provenance.get("report_sha256") != hashlib.sha256(raw).hexdigest()
        or provenance.get("measurement") != identity
    ):
        raise ValueError(
            "Combined coverage provenance does not match this checkout/report"
        )
    summary = validate_report(json.loads(raw), inventory(root), identity)
    summary["source"] = source
    summary["measurement"] = identity
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--data-dir", type=Path)
    mode.add_argument(
        "--record-part",
        choices=PARTS,
        help="Bind a partition to committed source, configuration and exact tools",
    )
    mode.add_argument(
        "--check",
        type=Path,
        help="Require line AND branch %% at or above the committed floors",
    )
    parser.add_argument(
        "--floors",
        type=Path,
        default=FLOORS,
        help="Ratchet floors JSON (default: scripts/coverage-floors.json)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("reports/coverage/python")
    )
    args = parser.parse_args()
    if args.record_part:
        print(json.dumps(record_partition(args.record_part), sort_keys=True))
        return 0
    if args.check:
        floors = load_floors(args.floors, "python")
        summary = apply_floors(check_report(args.check, ROOT), floors)
    else:
        summary = combine(args.data_dir, args.output_dir)
    print(json.dumps(summary, sort_keys=True))
    return int(bool(args.check) and not summary["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
