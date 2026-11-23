"""The Rust release gate requires measured lines and branches at the floor."""

import copy
import hashlib
import importlib.util
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "rust_coverage", Path(__file__).resolve().parents[1] / "check-rust-coverage.py"
)
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


@pytest.fixture
def rust_repo(tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src/main.rs").write_text("fn main() {}\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "src/main.rs"], check=True)
    return root


def report():
    summary = {
        "lines": {"count": 4, "covered": 4},
        "branches": {"count": 2, "covered": 2},
        "regions": {"count": 8, "covered": 8},
    }
    return {
        "type": "llvm.coverage.json.export",
        "data": [
            {
                "totals": copy.deepcopy(summary),
                "files": [{"filename": "src/main.rs", "summary": summary}],
            }
        ],
    }


@pytest.mark.parametrize("metric", ["lines", "branches"])
def test_incomplete_measurements_fail_even_with_complete_regions(metric):
    fixture = report()
    fixture["data"][0]["totals"][metric]["covered"] -= 1
    fixture["data"][0]["files"][0]["summary"][metric]["covered"] -= 1
    result = coverage.summarize(fixture, {"src/main.rs"})
    assert result["complete"] is False
    assert result[metric]["missing"] == 1


@pytest.mark.parametrize("value", [-1, True, 1.5, "2", None])
def test_invalid_counts_cannot_pass(value):
    fixture = report()
    fixture["data"][0]["totals"]["branches"]["count"] = value
    with pytest.raises(ValueError):
        coverage.summarize(fixture, {"src/main.rs"})


def test_totals_cannot_hide_an_uncovered_file():
    fixture = report()
    fixture["data"][0]["files"][0]["summary"]["branches"]["covered"] = 1
    with pytest.raises(ValueError, match="totals"):
        coverage.summarize(fixture, {"src/main.rs"})


@pytest.mark.parametrize("metric", ["lines", "branches"])
def test_zero_instrumentation_cannot_pass(metric):
    fixture = report()
    fixture["data"][0]["totals"][metric] = {"count": 0, "covered": 0}
    fixture["data"][0]["files"][0]["summary"][metric] = {
        "count": 0,
        "covered": 0,
    }
    with pytest.raises(ValueError, match="No .* measured"):
        coverage.summarize(fixture, {"src/main.rs"})


@pytest.mark.parametrize("filename", ["", None, 1])
def test_filename_must_identify_source(filename):
    fixture = report()
    fixture["data"][0]["files"][0]["filename"] = filename
    with pytest.raises(ValueError, match="filenames"):
        coverage.summarize(fixture, {"src/main.rs"})


def test_duplicate_files_cannot_inflate_coverage():
    fixture = report()
    fixture["data"][0]["files"] *= 2
    with pytest.raises(ValueError, match="unique"):
        coverage.summarize(fixture, {"src/main.rs"})


@pytest.mark.parametrize("data", [[], [{"files": []}], [{}, {}]])
def test_empty_or_multiple_exports_cannot_pass(data):
    fixture = report()
    fixture["data"] = data
    with pytest.raises(ValueError, match="nonempty"):
        coverage.summarize(fixture, {"src/main.rs"})


def test_missing_branch_measurement_fails_cli(tmp_path, capsys, rust_repo):
    fixture = report()
    del fixture["data"][0]["totals"]["branches"]
    path = tmp_path / "report.json"
    path.write_text(json.dumps(fixture))
    assert coverage.main([str(path), "--root", str(rust_repo)]) == 2
    assert "Invalid Rust coverage report" in capsys.readouterr().err


def test_complete_cli_writes_summary_and_incomplete_cli_fails(tmp_path, rust_repo):
    fixture = report()
    path, output = tmp_path / "report.json", tmp_path / "summary.json"
    path.write_text(json.dumps(fixture))
    assert (
        coverage.main([str(path), "--output", str(output), "--root", str(rust_repo)])
        == 0
    )
    assert json.loads(output.read_text())["branches"]["percent"] == 100
    fixture["data"][0]["totals"]["lines"]["covered"] = 1
    fixture["data"][0]["files"][0]["summary"]["lines"]["covered"] = 1
    path.write_text(json.dumps(fixture))
    assert coverage.main([str(path), "--root", str(rust_repo)]) == 1


def test_other_formats_are_not_accepted_as_llvm_coverage():
    with pytest.raises(ValueError, match="LLVM"):
        coverage.summarize({"type": "lcov"}, {"src/main.rs"})


def test_uncompiled_or_platform_only_sources_cannot_disappear(rust_repo):
    (rust_repo / "src/platform.rs").write_text("pub fn untested() {}\n")
    subprocess.run(["git", "-C", str(rust_repo), "add", "."], check=True)
    with pytest.raises(ValueError, match="missing=.*src/platform.rs"):
        coverage.summarize(report(), coverage.tracked_rust_files(rust_repo), rust_repo)


def test_unexpected_source_cannot_inflate_totals(rust_repo):
    fixture = report()
    fixture["data"][0]["files"][0]["filename"] = "dependency.rs"
    with pytest.raises(ValueError, match="unexpected=.*dependency.rs"):
        coverage.summarize(fixture, coverage.tracked_rust_files(rust_repo), rust_repo)


def test_absolute_paths_map_to_the_exact_tracked_inventory(rust_repo):
    fixture = report()
    fixture["data"][0]["files"][0]["filename"] = str(rust_repo / "src/main.rs")
    assert coverage.summarize(
        fixture, coverage.tracked_rust_files(rust_repo), rust_repo
    )["complete"]


def test_outside_sources_and_aliased_duplicate_paths_are_rejected(rust_repo):
    fixture = report()
    fixture["data"][0]["files"][0]["filename"] = "../outside.rs"
    with pytest.raises(ValueError):
        coverage.summarize(fixture, {"src/main.rs"}, rust_repo)
    fixture = report()
    item = copy.deepcopy(fixture["data"][0]["files"][0])
    item["filename"] = str(rust_repo / "src/main.rs")
    fixture["data"][0]["files"].append(item)
    with pytest.raises(ValueError, match="inventory mismatch"):
        coverage.summarize(fixture, {"src/main.rs"}, rust_repo)


def test_empty_tracked_inventory_is_rejected(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(ValueError, match="inventory is empty"):
        coverage.tracked_rust_files(tmp_path)


def test_script_entrypoint_returns_the_gate_status(tmp_path, rust_repo, monkeypatch):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    monkeypatch.setattr(
        sys, "argv", [str(SPEC.origin), str(path), "--root", str(rust_repo)]
    )
    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(SPEC.origin), run_name="__main__")
    assert result.value.code == 0


def declaration_manifest(root):
    source = root / "src/mod.rs"
    source.write_text("pub mod main;\n")
    subprocess.run(["git", "-C", str(root), "add", "src/mod.rs"], check=True)
    manifest = root / "scripts/rust-coverage-nonexecutable.json"
    manifest.parent.mkdir()
    review = {
        "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "reason": "Module declaration only; no executable initializer, macro or derive.",
    }
    manifest.write_text(json.dumps({"files": {"src/mod.rs": review}}))
    return source, manifest, review


def test_reviewed_declarations_are_explicit_in_the_summary(tmp_path, rust_repo):
    declaration_manifest(rust_repo)
    path, output = tmp_path / "report.json", tmp_path / "summary.json"
    path.write_text(json.dumps(report()))
    assert (
        coverage.main([str(path), "--root", str(rust_repo), "--output", str(output)])
        == 0
    )
    summary = json.loads(output.read_text())
    assert summary["files"] == 1 and summary["tracked_files"] == 2
    assert summary["nonexecutable_files"] == ["src/mod.rs"]


@pytest.mark.parametrize(
    "addition",
    [
        "pub fn newly_executable() {}",
        "const VALUE: u8 = compute();",
        "static VALUE: u8 = compute();",
        "generate_code!();",
        "#[derive(Default)]\npub struct NewType;",
    ],
)
def test_declaration_exception_cannot_survive_source_changes(rust_repo, addition):
    source, _, _ = declaration_manifest(rust_repo)
    source.write_text(source.read_text() + addition + "\n")
    with pytest.raises(ValueError, match="source changed; review required"):
        coverage.nonexecutable_files(rust_repo, coverage.tracked_rust_files(rust_repo))


@pytest.mark.parametrize(
    "review", [None, {}, {"reason": ""}, {"reason": "   "}, {"reason": 123}]
)
def test_exceptions_require_a_documented_review(rust_repo, review):
    _, manifest, _ = declaration_manifest(rust_repo)
    manifest.write_text(json.dumps({"files": {"src/mod.rs": review}}))
    with pytest.raises(ValueError, match="lacks a review reason"):
        coverage.nonexecutable_files(rust_repo, coverage.tracked_rust_files(rust_repo))


def test_exception_inventory_rejects_untracked_paths_and_invalid_schema(rust_repo):
    _, manifest, review = declaration_manifest(rust_repo)
    manifest.write_text(json.dumps({"files": {"../outside.rs": review}}))
    with pytest.raises(ValueError, match="not tracked"):
        coverage.nonexecutable_files(rust_repo, coverage.tracked_rust_files(rust_repo))
    manifest.write_text(json.dumps({"files": []}))
    with pytest.raises(ValueError, match="map paths"):
        coverage.nonexecutable_files(rust_repo, coverage.tracked_rust_files(rust_repo))


def test_reported_executable_locations_cannot_be_exempted(tmp_path, rust_repo):
    _, manifest, review = declaration_manifest(rust_repo)
    review["sha256"] = hashlib.sha256(
        (rust_repo / "src/main.rs").read_bytes()
    ).hexdigest()
    manifest.write_text(json.dumps({"files": {"src/main.rs": review}}))
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    assert coverage.main([str(path), "--root", str(rust_repo)]) == 2


def test_repository_declaration_inventory_matches_reviewed_bytes():
    root = Path(SPEC.origin).resolve().parents[1]
    inventory = coverage.tracked_rust_files(root)
    exceptions = coverage.nonexecutable_files(root, inventory)
    assert len(exceptions) == 13
    assert all(path.endswith(("/mod.rs", "/lib.rs")) for path in exceptions)


def floors_file(tmp_path, **rust):
    path = tmp_path / "floors.json"
    path.write_text(json.dumps({"rust": rust}))
    return path


def partial_report(lines_covered, branches_covered, lines=1000, branches=1000):
    fixture = report()
    for target in (fixture["data"][0]["totals"], fixture["data"][0]["files"][0]["summary"]):
        target["lines"] = {"count": lines, "covered": lines_covered}
        target["branches"] = {"count": branches, "covered": branches_covered}
    return fixture


@pytest.mark.parametrize(
    ("lines", "branches", "status"),
    [(842, 729, 0), (900, 900, 0), (841, 999, 1), (999, 728, 1)],
)
def test_cli_gate_is_the_committed_floor_not_completeness(
    tmp_path, rust_repo, lines, branches, status
):
    path, output = tmp_path / "report.json", tmp_path / "summary.json"
    path.write_text(json.dumps(partial_report(lines, branches)))
    floors = floors_file(tmp_path, lines=84.2, branches=72.9)
    argv = [str(path), "--root", str(rust_repo), "--floors", str(floors)]
    assert coverage.main([*argv, "--output", str(output)]) == status
    summary = json.loads(output.read_text())
    assert summary["passed"] is (status == 0)
    assert summary["complete"] is False
    assert summary["floor"] == {"lines": 84.2, "branches": 72.9}


def test_floor_comparison_is_exact_not_rounded():
    # 84.19999...% would display as 84.2 but must not pass an 84.2 floor.
    summary = coverage.summarize(
        partial_report(8419999, 10, lines=10000000, branches=10), {"src/main.rs"}
    )
    assert summary["lines"]["percent"] == 84.2
    assert coverage.apply_floors(summary, {"lines": 84.2, "branches": 0})["passed"] is False
    assert coverage.apply_floors(summary, {"lines": 84.19, "branches": 0})["passed"] is True


@pytest.mark.parametrize(
    "content",
    [
        None,
        "{",
        json.dumps({"python": {"lines": 1, "branches": 1}}),
        json.dumps({"rust": {"lines": 1}}),
        json.dumps({"rust": {"lines": 1, "branches": 1, "regions": 1}}),
        json.dumps({"rust": {"lines": "84", "branches": 1}}),
        json.dumps({"rust": {"lines": True, "branches": 1}}),
        json.dumps({"rust": {"lines": 1, "branches": 101}}),
        json.dumps({"rust": {"lines": -1, "branches": 1}}),
        json.dumps({"rust": [1, 2]}),
    ],
)
def test_missing_or_malformed_floors_fail_closed(tmp_path, rust_repo, capsys, content):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report()))
    floors = tmp_path / "floors.json"
    if content is not None:
        floors.write_text(content)
    argv = [str(path), "--root", str(rust_repo), "--floors", str(floors)]
    assert coverage.main(argv) == 2
    assert "coverage floor" in capsys.readouterr().err.lower()


def test_committed_repository_floors_are_valid():
    floors = coverage.load_floors()
    assert 0 < floors["lines"] <= 100 and 0 < floors["branches"] <= 100
