"""Assert that documented numeric claims match docs/metrics.json.

Why this exists
---------------
Numbers in human-written docs ("82 TSCM signatures", "54 routers",
"~4,800 bridge tests") rot the moment the codebase changes.
``scripts/emit_metrics.py`` regenerates ``docs/metrics.json``;
``.github/workflows/metrics.yml`` emits it on pushes and pull requests
and commits a refresh only when a maintainer runs it by hand on
``main``. This test consumes that committed truth file and asserts each
parametrized doc claim matches the corresponding metric within
tolerance.

How to add a new claim
----------------------
When you write a new sentence like "we ship N foos" in a tracked
doc, add a row to ``DOC_CLAIMS`` below:

    (doc_path, regex_with_one_capture_group, metric_key, tolerance)

- ``doc_path`` is relative to repo root.
- ``regex_with_one_capture_group`` MUST capture exactly one group
  containing the number (commas allowed; they're stripped).
- ``metric_key`` is a dotted path into ``docs/metrics.json``
  (e.g. ``"signatures.tscm_threat_signatures"``).
- ``tolerance`` is the allowed absolute delta. ``0`` means exact
  match; nonzero means the claim may drift by up to ±N without
  failing (useful for fast-moving counts like test totals).

This test is run by CI as a ``continue-on-error`` job — drift is
surfaced but doesn't block merges (yet). Operators can flip the
gate to required via branch protection once the docs are clean.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
METRICS_PATH = REPO_ROOT / "docs" / "metrics.json"

# (doc_path, regex_pattern, metric_key, tolerance)
# Patterns must contain exactly one capture group that matches the number.
DOC_CLAIMS: list[tuple[str, str, str, int]] = [
    # Current architecture claims only: historical CHANGELOG.md entries
    # describe their release snapshots and must not track today's metrics.
    (
        "ARCHITECTURE.md",
        r"(\d+) API router files",
        "code.bridge_routers",
        0,
    ),
    (
        "ARCHITECTURE.md",
        r"(\d+) SQLite storage backend files",
        "code.bridge_storage",
        0,
    ),
    (
        "ARCHITECTURE.md",
        r"(\d+) sub-store files",
        "code.bridge_storage",
        0,
    ),
    # ARCHITECTURE.md — system-architecture box and anomaly-scoring section
    (
        "ARCHITECTURE.md",
        r"(\d+)\s+Storage Backends",
        "code.bridge_storage",
        0,
    ),
    (
        "ARCHITECTURE.md",
        r"\((\d+) active dimensions",
        "scoring.python_anomaly_dimensions",
        0,
    ),
    (
        "ARCHITECTURE.md",
        r"active dimensions \+ (\d+) opt-in",
        "scoring.python_anomaly_dimensions_opt_in",
        0,
    ),
    # CONTRIBUTING.md — "Running Tests" section, approximate counts
    (
        "CONTRIBUTING.md",
        r"~([\d,]+)\s+bridge tests",
        "tests.python_bridge",
        200,
    ),
    (
        "CONTRIBUTING.md",
        r"Rust \(~([\d,]+)\s+tests",
        "tests.rust_workspace",
        50,
    ),
]


def _load_metrics() -> dict | None:
    """Return parsed metrics.json, or ``None`` if not present.

    Absent on feature branches where the metrics workflow hasn't yet
    committed an updated file — in that case the test skips cleanly.
    """
    if not METRICS_PATH.exists():
        return None
    return json.loads(METRICS_PATH.read_text(encoding="utf-8"))


def _resolve_metric(metrics: dict, dotted_key: str) -> int:
    """Walk a dotted path into the metrics dict."""
    node: object = metrics
    for part in dotted_key.split("."):
        if not isinstance(node, dict) or part not in node:
            raise KeyError(
                f"metric_key {dotted_key!r} not found in docs/metrics.json "
                f"(failed at segment {part!r})"
            )
        node = node[part]
    if not isinstance(node, int):
        raise TypeError(
            f"metric_key {dotted_key!r} resolved to {type(node).__name__}, expected int"
        )
    return node


@pytest.mark.parametrize(
    ("doc_path", "pattern", "metric_key", "tolerance"),
    DOC_CLAIMS,
    ids=[f"{c[0]}::{c[2]}" for c in DOC_CLAIMS],
)
def test_doc_claim_matches_metric(
    doc_path: str, pattern: str, metric_key: str, tolerance: int
) -> None:
    metrics = _load_metrics()
    if metrics is None:
        pytest.skip(
            f"docs/metrics.json not present at {METRICS_PATH} — "
            "metrics workflow may not have run on this branch yet"
        )

    doc_file = REPO_ROOT / doc_path
    if not doc_file.exists():
        pytest.skip(f"doc file {doc_path} not present")

    text = doc_file.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    assert match is not None, (
        f"Pattern {pattern!r} not found in {doc_path}; either the doc "
        f"removed the claim (remove this row from DOC_CLAIMS) or the "
        f"wording changed (update the pattern)."
    )

    raw = match.group(1).replace(",", "")
    try:
        found = int(raw)
    except ValueError as exc:
        raise AssertionError(
            f"Captured group {match.group(1)!r} from {doc_path} is not an integer"
        ) from exc

    expected = _resolve_metric(metrics, metric_key)
    delta = abs(found - expected)
    assert delta <= tolerance, (
        f"Doc {doc_path} claims {found} but metrics.json has {expected} "
        f"({metric_key}); delta={delta}, tolerance=±{tolerance}"
    )
