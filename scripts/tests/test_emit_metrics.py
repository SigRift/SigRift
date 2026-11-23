"""Metrics contracts from real miniature repositories, without importing inputs."""

from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import json
import logging
from pathlib import Path
import re
import runpy
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/emit_metrics.py"
SCORER = "src/sigrift/bridge/anomaly/scorer.py"
RUST_WEIGHTS = "src/gateway/crates/sigrift-gateway-core/src/scoring/weights.rs"
SIGNATURES = "src/sigrift/bridge/storage/signature_library.py"


@pytest.fixture
def metrics():
    spec = importlib.util.spec_from_file_location("metrics_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "checkout with spaces"
    write(
        root,
        "tests/bridge/test_sample.py",
        "def test_sync(): pass\nclass Suite:\n    async def test_async(self): pass\n"
        "def helper(): pass\n# def test_commented(): pass\n",
    )
    write(root, "tests/bridge/nested/test_more.py", "def test_nested(): pass\n")
    write(root, "tests/bridge/ignored.txt", "def test_not_python(): pass\n")
    write(root, "tests/outside/test_outside.py", "def test_outside(): pass\n")
    write(
        root,
        "src/gateway/crates/core/src/tests.rs",
        "#[test]\nfn one() {}\n#[tokio::test]\nasync fn two() {}\n",
    )
    write(root, "src/gateway/crates/core/ignored.py", "#[test]\n")
    write(root, "src/gateway/outside.rs", "#[test]\n")
    for directory, modules in [
        ("bridge/routers", ["auth", "wifi"]),
        ("bridge/storage", ["one"]),
        ("edge", ["first", "second", "third"]),
    ]:
        for name in ["__init__", *modules]:
            write(root, f"src/sigrift/{directory}/{name}.py", "# module\n")
        write(root, f"src/sigrift/{directory}/nested/ignored.py", "# nested module\n")
        (root / f"src/sigrift/{directory}/directory.py").mkdir()
        write(root, f"src/sigrift/{directory}/ignored.pyc", b"compiled")
    write(
        root, SIGNATURES, 'entries = [\n {"name": "first"},\n {"name" : "second"},\n]\n'
    )
    write(
        root,
        SCORER,
        "raise AssertionError('metric inputs must not execute')\n_DEFAULT_WEIGHTS = {'active': 0.4, 'disabled': 0, 'custom': dynamic()}\n",
    )
    write(
        root,
        RUST_WEIGHTS,
        "pub struct ScoringWeights {\n pub first: f32,\n pub second: f64,\n private: f32,\n pub label: String,\n}\n",
    )
    return root


def expected_counts():
    return {
        "tests": {"python_bridge": 3, "rust_workspace": 2},
        "code": {"bridge_routers": 2, "bridge_storage": 2, "edge_modules": 3},
        "signatures": {"tscm_threat_signatures": 2},
        "scoring": {
            "python_anomaly_dimensions": 2,
            "python_anomaly_dimensions_opt_in": 1,
            "rust_gateway_dimensions": 2,
        },
    }


@pytest.mark.parametrize("commit", [None, "", "a" * 40])
def test_collect_counts_actual_scoped_sources_and_emits_utc_provenance(
    metrics, repository, commit
):
    before = datetime.now(timezone.utc).replace(microsecond=0)
    result = metrics.collect(repository, commit)
    generated = datetime.strptime(
        result.pop("generated_at"), "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=timezone.utc)
    assert before <= generated <= datetime.now(timezone.utc)
    assert result.pop("commit") == (commit or None)
    assert result == expected_counts()


def test_empty_checkout_distinguishes_missing_weight_values_from_zero_counts(
    metrics, tmp_path, caplog
):
    result = metrics.collect(tmp_path, None)
    assert result["tests"] == {"python_bridge": 0, "rust_workspace": 0}
    assert result["code"] == {
        "bridge_routers": 0,
        "bridge_storage": 0,
        "edge_modules": 0,
    }
    assert result["signatures"] == {"tscm_threat_signatures": 0}
    assert result["scoring"] == {
        "python_anomaly_dimensions": None,
        "python_anomaly_dimensions_opt_in": None,
        "rust_gateway_dimensions": 0,
    }
    assert "missing directory" in caplog.text
    assert "signature_library.py not found" in caplog.text
    assert "scorer.py not found" in caplog.text
    assert "rust weights.rs not found" in caplog.text


def test_line_counter_tolerates_non_utf8_but_reports_missing_files(
    metrics, tmp_path, caplog
):
    source = write(tmp_path, "input.txt", b"match\xff\nnot this line\nmatch match\n")
    assert metrics._count_lines_matching(source, re.compile("match")) == 2
    assert metrics._count_lines_matching(tmp_path / "missing", re.compile("match")) == 0
    assert "read failed" in caplog.text


def test_signature_selection_prefers_largest_existing_candidate(metrics, tmp_path):
    write(tmp_path, "src/sigrift/bridge/signature_library.py", '"name": "small"\n')
    write(
        tmp_path,
        "src/sigrift/bridge/routers/signature_library.py",
        '# medium\n"name": "router"\n',
    )
    largest = write(
        tmp_path,
        SIGNATURES,
        '# curated\n"name": "one"\n"name": "two"\n"name": "three"\n',
    )
    assert metrics._find_signature_library(tmp_path) == largest
    assert metrics.count_tscm_threat_signatures(tmp_path) == 3


def test_signature_disappearing_between_file_check_and_stat_uses_remaining_candidate(
    metrics, tmp_path, monkeypatch
):
    vanishing = write(
        tmp_path, "src/sigrift/bridge/signature_library.py", "# long candidate\n" * 20
    )
    remaining = write(tmp_path, SIGNATURES, '"name": "retained"\n')
    original = Path.stat
    calls = 0

    def race(path, *args, **kwargs):
        nonlocal calls
        if path == vanishing:
            calls += 1
            if calls == 2:
                path.unlink()
        return original(path, *args, **kwargs)

    # Only the OS stat boundary is interposed; deletion and failure are real.
    monkeypatch.setattr(Path, "stat", race)
    assert metrics._find_signature_library(tmp_path) == remaining
    assert not vanishing.exists()


@pytest.mark.parametrize(
    "source,expected",
    [
        ("_DEFAULT_WEIGHTS = {}", (0, 0)),
        ("_DEFAULT_WEIGHTS: dict[str,float] = {'zero':0.0, 'active':2}", (1, 1)),
        (
            "irrelevant = 1\nobj.attr = {}\nfirst = _DEFAULT_WEIGHTS = {'a':1, 'b':0}\n",
            (1, 1),
        ),
        (
            "_DEFAULT_WEIGHTS = None\n_DEFAULT_WEIGHTS = {'x':0, 'y':computed(), 'z':'unknown'}",
            (2, 1),
        ),
        ("_DEFAULT_WEIGHTS: dict\n", (None, None)),
        ("other = {'a':1}\n", (None, None)),
        ("_DEFAULT_WEIGHTS = computed()", (None, None)),
        ("_DEFAULT_WEIGHTS = {syntax error", (None, None)),
    ],
)
def test_weight_ast_forms_and_parse_failure_do_not_execute_source(
    metrics, tmp_path, source, expected
):
    write(tmp_path, SCORER, source)
    assert metrics._scorer_weight_split(tmp_path) == expected


@pytest.mark.parametrize(
    "relative,reader,expected",
    [
        (SCORER, "_scorer_weight_split", (None, None)),
        (RUST_WEIGHTS, "count_rust_gateway_dimensions", 0),
    ],
)
def test_source_disappearing_after_file_check_is_reported_without_a_fake_count(
    metrics, tmp_path, monkeypatch, caplog, relative, reader, expected
):
    source = write(tmp_path, relative, "# initial source\n")
    original = Path.read_text

    def race(path, *args, **kwargs):
        if path == source:
            path.unlink()
        return original(path, *args, **kwargs)

    # A deterministic exists/open race at the filesystem boundary, not a
    # replacement parser or fabricated AST/error object.
    monkeypatch.setattr(Path, "read_text", race)
    assert getattr(metrics, reader)(tmp_path) == expected
    assert not source.exists()
    assert "failed" in caplog.text


@pytest.mark.parametrize(
    "source,expected",
    [
        (
            "pub const FIRST_WEIGHT: f32 = 0.1;\npub const second_weight: f64 = 0.2;\npub const OTHER: i32 = 3;\npub struct ScoringWeights {pub unused: f32,}",
            2,
        ),
        (
            "pub struct ScoringWeights {\n pub a: f32,\n pub b: f64,\n pub count: u32,\n private: f32,\n}\npub struct Other {pub extra: f64,}",
            2,
        ),
        ("pub struct Other {pub extra: f64,}", 0),
        ("pub struct ScoringWeights { pub name: String, }", 0),
    ],
)
def test_rust_constants_take_precedence_then_only_public_float_fields_count(
    metrics, tmp_path, source, expected
):
    write(tmp_path, RUST_WEIGHTS, source)
    assert metrics.count_rust_gateway_dimensions(tmp_path) == expected


def test_stdout_cli_has_only_valid_json_and_logs_nine_leaf_counts(
    metrics, repository, capsys, caplog
):
    caplog.set_level(logging.INFO, logger="emit_metrics")
    assert (
        metrics.main(["--repo-root", str(repository), "--commit", "fixture-sha"]) == 0
    )
    output = capsys.readouterr()
    result = json.loads(output.out)
    assert output.out.endswith("\n")
    assert result["commit"] == "fixture-sha"
    assert {key: result[key] for key in expected_counts()} == expected_counts()
    assert "emitted 9 counts to <stdout>" in caplog.text


def test_file_cli_creates_parent_directories_and_does_not_mix_stdout(
    metrics, repository, tmp_path, capsys, caplog
):
    caplog.set_level(logging.INFO, logger="emit_metrics")
    destination = tmp_path / "artifacts with spaces" / "nested" / "metrics.json"
    assert (
        metrics.main(["--repo-root", str(repository), "--out", str(destination)]) == 0
    )
    assert capsys.readouterr().out == ""
    payload = destination.read_text()
    assert payload.endswith("\n")
    result = json.loads(payload)
    assert {key: result[key] for key in expected_counts()} == expected_counts()
    assert result["commit"] is None
    assert f"emitted 9 counts to {destination}" in caplog.text


def test_nonexistent_repo_fails_without_creating_output(metrics, tmp_path, caplog):
    destination = tmp_path / "no-artifact.json"
    assert (
        metrics.main(
            ["--repo-root", str(tmp_path / "missing"), "--out", str(destination)]
        )
        == 2
    )
    assert not destination.exists()
    assert "repo root does not exist" in caplog.text


def test_output_directory_collision_is_not_reported_as_success(
    metrics, repository, tmp_path
):
    with pytest.raises(IsADirectoryError):
        metrics.main(["--repo-root", str(repository), "--out", str(tmp_path)])


def test_cli_rejects_unknown_options(metrics):
    with pytest.raises(SystemExit) as failure:
        metrics.main(["--unknown"])
    assert failure.value.code == 2


def test_real_script_entrypoint_uses_requested_repository(
    repository, monkeypatch, capsys
):
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--repo-root", str(repository), "--commit", "entrypoint-sha"],
    )
    with pytest.raises(SystemExit) as success:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert success.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["commit"] == "entrypoint-sha"
    assert {key: result[key] for key in expected_counts()} == expected_counts()


def test_real_process_default_root_is_script_location_not_working_directory(
    repository, tmp_path
):
    script = write(repository, "scripts/emit_metrics.py", SCRIPT.read_bytes())
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=tmp_path,
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["commit"] is None
    assert {key: payload[key] for key in expected_counts()} == expected_counts()
    assert "emitted 9 counts to <stdout>" in result.stderr
