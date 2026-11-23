#!/usr/bin/env python3
"""Emit a metrics.json artifact summarising countable repo facts.

Documentation regularly cites figures like "X bridge routers" or
"Y TSCM signatures".  Hand-maintained, those numbers decay.  This
script walks the tree and emits a single JSON document that CI
can publish and docs can cite.

Stdlib only -- runs on any fresh checkout with Python 3.11+.
"""
from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
    level=logging.INFO,
    stream=sys.stderr,
)
log = logging.getLogger("emit_metrics")


def _count_lines_matching(path: Path, pattern: re.Pattern[str]) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("read failed for %s: %s", path, exc)
        return 0
    return sum(1 for line in text.splitlines() if pattern.search(line))


def _count_in_tree(root: Path, suffixes: tuple[str, ...], pattern: re.Pattern[str]) -> int:
    if not root.is_dir():
        log.warning("missing directory: %s", root)
        return 0
    total = 0
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in suffixes:
            continue
        total += _count_lines_matching(path, pattern)
    return total


def _count_py_modules(root: Path) -> int:
    if not root.is_dir():
        log.warning("missing directory: %s", root)
        return 0
    return sum(
        1
        for p in root.glob("*.py")
        if p.is_file() and p.name != "__init__.py"
    )


def count_python_bridge_tests(repo: Path) -> int:
    pattern = re.compile(r"^\s*(?:async\s+)?def\s+test_")
    return _count_in_tree(repo / "tests" / "bridge", (".py",), pattern)


def count_rust_workspace_tests(repo: Path) -> int:
    pattern = re.compile(r"#\[(?:tokio::)?test\]")
    return _count_in_tree(repo / "src" / "gateway" / "crates", (".rs",), pattern)


def count_bridge_routers(repo: Path) -> int:
    return _count_py_modules(repo / "src" / "sigrift" / "bridge" / "routers")


def count_bridge_storage(repo: Path) -> int:
    return _count_py_modules(repo / "src" / "sigrift" / "bridge" / "storage")


def count_edge_modules(repo: Path) -> int:
    return _count_py_modules(repo / "src" / "sigrift" / "edge")


def _find_signature_library(repo: Path) -> Path | None:
    candidates = [
        repo / "src" / "sigrift" / "bridge" / "signature_library.py",
        repo / "src" / "sigrift" / "bridge" / "storage" / "signature_library.py",
        repo / "src" / "sigrift" / "bridge" / "routers" / "signature_library.py",
    ]
    sized: list[tuple[int, Path]] = []
    for c in candidates:
        if c.is_file():
            try:
                sized.append((c.stat().st_size, c))
            except OSError:
                continue
    if not sized:
        return None
    # The storage module holds the curated list; pick the largest.
    sized.sort(reverse=True)
    return sized[0][1]


def count_tscm_threat_signatures(repo: Path) -> int:
    path = _find_signature_library(repo)
    if path is None:
        log.warning("signature_library.py not found")
        return 0
    pattern = re.compile(r'"name"\s*:')
    return _count_lines_matching(path, pattern)


def _scorer_weight_split(repo: Path) -> tuple[int | None, int | None]:
    """Return (active_count, opt_in_count) from scorer.py _DEFAULT_WEIGHTS.

    On parse failure both values are None so the emitter can mark them null.
    """
    path = repo / "src" / "sigrift" / "bridge" / "anomaly" / "scorer.py"
    if not path.is_file():
        log.warning("scorer.py not found at %s", path)
        return None, None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, OSError) as exc:
        log.warning("scorer.py parse failed: %s", exc)
        return None, None

    target: ast.Dict | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name) and t.id == "_DEFAULT_WEIGHTS":
                    if isinstance(node.value, ast.Dict):
                        target = node.value
                        break
            if target is not None:
                break
    if target is None:
        log.warning("_DEFAULT_WEIGHTS dict literal not found in scorer.py")
        return None, None

    active = 0
    opt_in = 0
    for value in target.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, (int, float)):
            if float(value.value) == 0.0:
                opt_in += 1
            else:
                active += 1
        else:
            # Non-literal value; count as active by default.
            active += 1
    return active, opt_in


def count_rust_gateway_dimensions(repo: Path) -> int:
    path = repo / "src" / "gateway" / "crates" / "sigrift-gateway-core" / "src" / "scoring" / "weights.rs"
    if not path.is_file():
        log.warning("rust weights.rs not found at %s", path)
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("read failed for %s: %s", path, exc)
        return 0

    # Prefer constants if they exist; otherwise fall back to ScoringWeights fields.
    const_pat = re.compile(r"\bpub\s+const\s+\w*(?:_WEIGHT|_weight)\b")
    const_count = sum(1 for line in text.splitlines() if const_pat.search(line))
    if const_count:
        return const_count

    struct_re = re.compile(
        r"pub\s+struct\s+ScoringWeights\s*\{([^}]*)\}", re.DOTALL
    )
    m = struct_re.search(text)
    if not m:
        log.warning("ScoringWeights struct not found in weights.rs")
        return 0
    field_pat = re.compile(r"^\s*pub\s+\w+\s*:\s*f(?:32|64)\s*,", re.MULTILINE)
    return len(field_pat.findall(m.group(1)))


def collect(repo: Path, commit: str | None) -> dict:
    active, opt_in = _scorer_weight_split(repo)
    return {
        "generated_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commit": commit if commit else None,
        "tests": {
            "python_bridge": count_python_bridge_tests(repo),
            "rust_workspace": count_rust_workspace_tests(repo),
        },
        "code": {
            "bridge_routers": count_bridge_routers(repo),
            "bridge_storage": count_bridge_storage(repo),
            "edge_modules": count_edge_modules(repo),
        },
        "signatures": {
            "tscm_threat_signatures": count_tscm_threat_signatures(repo),
        },
        "scoring": {
            "python_anomaly_dimensions": active,
            "python_anomaly_dimensions_opt_in": opt_in,
            "rust_gateway_dimensions": count_rust_gateway_dimensions(repo),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repo root (default: script's parent's parent).",
    )
    parser.add_argument(
        "--commit",
        default=None,
        help="Commit SHA to embed (default: omitted/null).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output path (default: stdout).",
    )
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    if not repo.is_dir():
        log.error("repo root does not exist: %s", repo)
        return 2

    metrics = collect(repo, args.commit)
    payload = json.dumps(metrics, indent=2, sort_keys=True) + "\n"

    if args.out is None:
        sys.stdout.write(payload)
        destination = "<stdout>"
    else:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
        destination = str(args.out)

    leaf_counts = sum(
        len(v) if isinstance(v, dict) else 1
        for k, v in metrics.items()
        if k not in {"generated_at", "commit"}
    )
    log.info("[metrics] emitted %d counts to %s", leaf_counts, destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
