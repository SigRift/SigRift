"""Coverage reports must include every source file and every CI partition."""

import copy
import hashlib
import importlib.util
import json
import os
import runpy
from pathlib import Path
import subprocess
import sys

import coverage
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "python-coverage.py"
SPEC = importlib.util.spec_from_file_location("python_coverage", SCRIPT)
reporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reporter)


def fork_measurement(tmp_path, exit_method, patches=None):
    """Execute actual parent/child code and retain each process's raw data."""
    assert hasattr(os, "fork") and hasattr(os, "register_at_fork"), (
        "Canonical release coverage requires POSIX fork support (Linux/macOS); "
        "unsupported platform paths must not be skipped or removed from inventory"
    )
    for directory in ("src/sigrift", "scripts", "training", "tests"):
        (tmp_path / directory).mkdir(parents=True)
    config = tmp_path / ".coveragerc"
    config.write_text((SCRIPT.parents[1] / ".coveragerc").read_text())
    if patches is not None:
        import configparser

        options = configparser.ConfigParser()
        options.read(config)
        options.set("run", "patch", ", ".join(patches))
        with config.open("w") as stream:
            options.write(stream)
    program = tmp_path / "src/sigrift/fork_probe.py"
    program.write_text(
        "import json\nimport os\nimport sys\n\n"
        "def marker(role):\n"
        "    if role == 'child':\n"
        "        return 'child-result'\n"
        "    return 'parent-result'\n\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    assert marker('child') == 'child-result'\n"
        "    if sys.argv[1] == 'immediate':\n"
        "        os._exit(23)\n"
        "    sys.exit(23)\n"
        "assert marker('parent') == 'parent-result'\n"
        "_, status = os.waitpid(child, 0)\n"
        "assert os.waitstatus_to_exitcode(status) == 23\n"
        "print(json.dumps({'parent': os.getpid(), 'child': child}))\n"
    )
    # Collection must retain code that no process imported or executed.
    (program.parent / "unloaded.py").write_text(
        "def untouched(flag):\n    if flag:\n        return 1\n    return 2\n"
    )
    output = tmp_path / "data"
    output.mkdir()
    # Prevent an outer pytest-cov/subprocess session from redirecting this
    # independently configured probe's files or restoring its collector.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COVERAGE_", "COV_CORE_"))
    }
    env["COVERAGE_FILE"] = str(output / ".coverage")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "--rcfile=" + str(config),
            str(program),
            exit_method,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    processes = json.loads(result.stdout)
    assert processes["parent"] != processes["child"]
    raw = []
    raw_hashes = {}
    for path in sorted(output.glob(".coverage.*")):
        raw_hashes[path] = hashlib.sha256(path.read_bytes()).hexdigest()
        data = coverage.CoverageData(basename=str(path))
        data.read()
        assert data.has_arcs()
        raw.append({name: set(data.arcs(name) or []) for name in data.measured_files()})
    assert raw, "Real process execution saved no coverage data"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "combine",
            "--rcfile=" + str(config),
            "--keep",
            str(output),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    combined = coverage.CoverageData(basename=str(output / ".coverage"))
    combined.read()
    files = set().union(*(set(data) for data in raw))
    assert combined.measured_files() == files
    for name in files:
        assert set(combined.arcs(name) or []) == set().union(
            *(data.get(name, set()) for data in raw)
        )
    report = output / "coverage.json"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "json",
            "--keep-combined",
            "--rcfile=" + str(config),
            "-o",
            str(report),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    assert all(
        hashlib.sha256(path.read_bytes()).hexdigest() == digest
        for path, digest in raw_hashes.items()
    ), "Combining/reporting must preserve each original process data file"
    measured = json.loads(report.read_text())
    unloaded = measured["files"]["src/sigrift/unloaded.py"]
    assert unloaded["executed_lines"] == []
    assert unloaded["missing_lines"] == [1, 2, 3, 4]
    assert unloaded["summary"]["covered_branches"] == 0
    assert unloaded["summary"]["num_branches"] == 2
    assert all(
        item["summary"]["excluded_lines"] == 0 for item in measured["files"].values()
    )
    combined_arcs = {name: set(combined.arcs(name) or []) for name in files}
    return raw, combined_arcs, measured


@pytest.mark.parametrize("exit_method", ["normal", "immediate"])
def test_canonical_fork_child_lines_and_arcs_survive_exit_and_combine(
    tmp_path, exit_method
):
    raw, combined, report = fork_measurement(tmp_path, exit_method)
    name = "src/sigrift/fork_probe.py"
    # Line7 and6->7 are executable only in the real forked child.
    assert any((6, 7) in data.get(name, set()) for data in raw)
    assert (6, 7) in combined[name]
    assert (7, -5) in combined[name]
    assert 7 in report["files"][name]["executed_lines"]
    assert [6, 7] in report["files"][name]["executed_branches"]


@pytest.mark.parametrize("patches", [["subprocess"], ["subprocess", "fork"]])
def test_immediate_exit_without_save_patch_really_loses_child_data(tmp_path, patches):
    raw, combined, report = fork_measurement(tmp_path, "immediate", patches)
    name = "src/sigrift/fork_probe.py"
    assert not any((6, 7) in data.get(name, set()) for data in raw)
    assert (6, 7) not in combined[name]
    assert 7 in report["files"][name]["missing_lines"]
    assert [6, 7] in report["files"][name]["missing_branches"]


def test_all_authored_inventory_keeps_mixed_tests_and_uncalled_helpers(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    source = tmp_path / "tests/test_mixed.py"
    source.parent.mkdir()
    source.write_text(
        "def helper(flag):\n    if flag:\n        return 1\n    return 2\n"
        "def test_behavior():\n    assert helper(True) == 1\n"
    )
    assert reporter.inventory(tmp_path) == {
        "included": ["tests/test_mixed.py"],
        "excluded": [],
    }


def test_all_authored_canonical_config_retains_unexecuted_test_branches(tmp_path):
    source = tmp_path / "tests/test_mixed.py"
    source.parent.mkdir()
    source.write_text(
        "def helper(flag):\n    if flag:\n        return 1\n    return 2\n"
        "def test_behavior():\n    assert helper(True) == 1\n"
    )
    measurement = coverage.Coverage(
        config_file=str(SCRIPT.parents[1] / ".coveragerc"),
        source=[str(source.parent)],
        data_file=str(tmp_path / ".coverage.probe"),
    )
    measurement.start()
    namespace = runpy.run_path(str(source))
    namespace["test_behavior"]()
    measurement.stop()
    output = tmp_path / "coverage.json"
    measurement.json_report(outfile=str(output))
    files = json.loads(output.read_text())["files"]
    measured = next(
        (value for name, value in files.items() if name.endswith("test_mixed.py")), None
    )
    assert measured is not None, "Authored test/helper code disappeared from coverage"
    assert measured["summary"]["num_branches"] == 2
    assert measured["summary"]["covered_branches"] == 1
    assert measured["missing_lines"] == [4]


@pytest.fixture
def measured_repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    (root / "src").mkdir()
    source = root / "src/example.py"
    source.write_text("if flag:\n    answer = 1\nelse:\n    answer = 2\n")
    (root / "tests").mkdir()
    (root / "tests/test_example.py").write_text(
        "def test_example():\n    assert True\n"
    )
    (root / ".coveragerc").write_text(
        "[run]\nbranch=True\nrelative_files=True\nsource=\n    src\n    tests\n"
        "[report]\nexclude_lines=\npartial_branches=\n"
    )
    tooling = root / "src/sigrift/bridge"
    tooling.mkdir(parents=True)
    for name in ("requirements-test.in", "requirements-test.txt"):
        (tooling / name).write_text("coverage==" + coverage.__version__ + "\n")
    subprocess.run(["git", "add", "."], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=root,
        check=True,
    )
    data_dir = root / "partitions"
    for index, part in enumerate(reporter.PARTS):
        directory = data_dir / ("python-coverage-part-" + part)
        directory.mkdir(parents=True)
        measurement = coverage.Coverage(
            config_file=str(root / ".coveragerc"),
            data_file=str(directory / (".coverage." + part)),
        )
        measurement.start()
        exec(
            compile(source.read_text(), str(source), "exec"), {"flag": bool(index % 2)}
        )
        runpy.run_path(str(root / "tests/test_example.py"))["test_example"]()
        measurement.stop()
        measurement.save()
        # The real recorder binds file content and commit; artifacts retain
        # canonical filenames when the CI uploader groups them.
        root_data = root / (".coverage." + part)
        root_data.write_bytes((directory / root_data.name).read_bytes())
        reporter.record_partition(part, root)
        metadata = root_data.with_name(root_data.name + ".metadata.json")
        metadata.rename(directory / metadata.name)
        root_data.unlink()
    return root, data_dir


def test_combines_every_partition_and_retains_unexecuted_branches(measured_repo):
    root, data_dir = measured_repo
    output = root / "report"
    summary = reporter.combine(data_dir, output, root)
    assert summary["complete"] is True
    assert summary["lines"] == {"covered": 5, "total": 5, "percent": 100.0}
    assert summary["branches"] == {"covered": 2, "total": 2, "percent": 100.0}
    assert (output / "html/index.html").is_file()
    assert (output / "coverage.xml").is_file()
    assert json.loads((output / "inventory.json").read_text()) == {
        "included": ["src/example.py", "tests/test_example.py"],
        "excluded": [],
    }
    # A part is not replaced by an empty or single-language summary.
    paths = reporter.partition_files(
        data_dir,
        reporter.source_state(root)["commit"],
        reporter.measurement_identity(root),
    )
    assert len(paths) == 6 and all(Path(path).is_file() for path in paths)


@pytest.mark.parametrize(
    "change", ["missing-part", "extra-part", "missing-file", "line-only", "empty"]
)
def test_rejects_missing_or_non_branch_partitions(measured_repo, change):
    root, data_dir = measured_repo
    directory = data_dir / "python-coverage-part-scripts"
    path = directory / ".coverage.scripts"
    if change == "missing-part":
        directory.rename(root / "removed-part")
    elif change == "extra-part":
        (data_dir / "unexpected").mkdir()
    elif change == "missing-file":
        path.unlink()
    else:
        path.unlink()
        data = coverage.CoverageData(basename=str(path))
        if change == "line-only":
            data.add_lines({"src/example.py": [1, 2]})
        else:
            data.add_arcs({})
        data.write()
        metadata_path = path.with_name(path.name + ".metadata.json")
        metadata = json.loads(metadata_path.read_text())
        metadata["data_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        reporter.partition_files(
            data_dir,
            reporter.source_state(root)["commit"],
            reporter.measurement_identity(root),
        )


def example_report():
    counts = {
        "covered_lines": 3,
        "num_statements": 3,
        "covered_branches": 2,
        "num_branches": 2,
        "excluded_lines": 0,
    }
    return {
        "meta": {"branch_coverage": True},
        "files": {"src/example.py": {"summary": counts}},
        "totals": dict(counts),
    }


@pytest.mark.parametrize(
    "change",
    [
        "missing-branch-data",
        "missing-source",
        "excluded",
        "inconsistent",
        "empty",
        "impossible",
        "negative",
        "boolean",
        "string",
        "boolean-total",
    ],
)
def test_release_report_fails_closed_on_incomplete_measurement(change):
    report = example_report()
    sources = {"included": ["src/example.py"]}
    if change == "missing-branch-data":
        report["meta"]["branch_coverage"] = False
    elif change == "missing-source":
        sources["included"].append("training/unexecuted.py")
    elif change == "excluded":
        report["files"]["src/example.py"]["summary"]["excluded_lines"] = 1
    elif change == "inconsistent":
        report["totals"]["covered_lines"] = 2
    elif change in ("negative", "boolean", "string"):
        report["files"]["src/example.py"]["summary"]["covered_lines"] = {
            "negative": -1,
            "boolean": True,
            "string": "3",
        }[change]
    elif change == "boolean-total":
        report["totals"]["covered_lines"] = True
    else:
        for summary in (report["files"]["src/example.py"]["summary"], report["totals"]):
            summary["num_branches"] = 0 if change == "empty" else 1
            summary["covered_branches"] = 0 if change == "empty" else 2
    with pytest.raises(ValueError):
        reporter.validate_report(report, sources)


def test_inventory_cannot_be_empty(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    with pytest.raises(ValueError, match="No first-party"):
        reporter.inventory(tmp_path)


def test_helpers_under_test_directories_are_included_and_source_tracked(
    measured_repo,
):
    root, _ = measured_repo
    helpers = [
        "tests/e2e/javascript_coverage.py",
        "tests/bridge/js/inventory.py",
        "tests/conftest.py",
        "tests/bench_utils.py",
        "tests/__init__.py",
        "src/tests/fixtures.py",
        "scripts/test-command.py",
    ]
    for name in helpers:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "def helper(flag):\n    if flag:\n        return 1\n    return 2\n"
        )
    sources = reporter.inventory(root)
    assert sources["included"] == sorted(
        ["src/example.py", "tests/test_example.py", *helpers]
    )
    assert sources["excluded"] == []
    assert reporter.source_state(root)["dirty"] is True
    with pytest.raises(ValueError, match="committed Python source"):
        reporter.record_partition("scripts", root)


@pytest.mark.parametrize(
    "body",
    [
        "def test_behavior():\n    assert True\n",
        "async def test_behavior():\n    assert True\n",
        "class TestBehavior:\n    def test_behavior(self):\n        assert True\n",
        "class TestBehavior:\n    async def test_behavior(self):\n        assert True\n",
    ],
)
def test_collected_test_modules_remain_authored_source(measured_repo, body):
    root, _ = measured_repo
    dedicated = root / "tests/nested/test_behavior.py"
    dedicated.parent.mkdir()
    dedicated.write_text(body)
    assert reporter.inventory(root) == {
        "included": [
            "src/example.py",
            "tests/nested/test_behavior.py",
            "tests/test_example.py",
        ],
        "excluded": [],
    }
    # The same filename and contents outside a test directory remain authored
    # source: the filename alone must not exempt an operational command.
    (root / "src/test_behavior.py").write_text(body)
    assert "src/test_behavior.py" in reporter.inventory(root)["included"]


@pytest.mark.parametrize(
    "body",
    [
        "def main():\n    print('operational command')\n",
        "def main():\n    def test_nested():\n        assert True\n",
        "class Helper:\n    def test_not_collected(self):\n        assert True\n",
        "class TestHelper:\n    def helper(self):\n        return True\n",
        "# test_placeholder has no collected test body\n",
        "def test_broken(:\n",
    ],
)
def test_test_named_modules_cannot_hide_from_inventory(measured_repo, body):
    root, _ = measured_repo
    (root / "tests/test_operational.py").write_text(body)
    assert "tests/test_operational.py" in reporter.inventory(root)["included"]
    assert reporter.inventory(root)["excluded"] == []


def test_real_config_measures_unimported_helpers_and_test_modules(
    tmp_path, monkeypatch
):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.chdir(root)
    subprocess.run(["git", "init", "-q"], check=True)
    config = root / ".coveragerc"
    config.write_text((SCRIPT.parents[1] / ".coveragerc").read_text())
    helpers = [
        "tests/e2e/javascript_coverage.py",
        # No __init__.py in this directory: namespace discovery must still
        # include a never-imported command, not just files that executed.
        "tests/bridge/js/inventory.py",
        "tests/conftest.py",
        "tests/bench_utils.py",
        "src/sigrift/tests/helper.py",
        "scripts/test-command.py",
        "training/helper.py",
    ]
    for name in helpers:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "def helper(flag):\n    if flag:\n        return 1\n    return 2\n"
        )
    package_marker = root / "tests/__init__.py"
    package_marker.write_text("")
    test_modules = [
        "tests/test_root.py",
        "tests/bridge/test_nested.py",
        "src/sigrift/tests/test_nested.py",
        "scripts/tests/deep/test_nested.py",
    ]
    for name in test_modules:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("def test_behavior():\n    assert True\n")
    executed = root / "src/sigrift/example.py"
    executed.write_text("if flag:\n    answer = 1\nelse:\n    answer = 2\n")
    # Isolate synthetic source data from the enclosing CI shard's COVERAGE_FILE.
    measurement = coverage.Coverage(
        config_file=str(config), data_file=str(root / ".coverage.probe")
    )
    measurement.start()
    exec(compile(executed.read_text(), str(executed), "exec"), {"flag": True})
    # Executed and never-collected test modules stay in the same denominator.
    dedicated = root / test_modules[0]
    exec(compile(dedicated.read_text(), str(dedicated), "exec"), {})
    measurement.stop()
    output = root / "coverage.json"
    measurement.json_report(outfile=str(output))
    report = json.loads(output.read_text())
    sources = reporter.inventory(root)
    assert sources["included"] == sorted(
        [*helpers, *test_modules, "tests/__init__.py", "src/sigrift/example.py"]
    )
    assert sources["excluded"] == []
    assert set(report["files"]) == set(sources["included"])
    for name in helpers:
        counts = report["files"][name]["summary"]
        assert counts["num_statements"] > 0
        assert counts["covered_lines"] == 0
        assert counts["num_branches"] == 2
        assert counts["covered_branches"] == 0
    for name in test_modules[1:]:
        assert report["files"][name]["summary"]["num_statements"] == 2
        assert report["files"][name]["summary"]["covered_lines"] == 0
    assert report["files"]["tests/__init__.py"]["summary"]["num_statements"] == 0
    assert reporter.validate_report(report, sources)["complete"] is False
    del report["files"][helpers[0]]
    with pytest.raises(ValueError, match="source inventory mismatch"):
        reporter.validate_report(report, sources)


def test_command_publishes_baseline_but_gate_requires_both_metrics(
    measured_repo, monkeypatch, capsys
):
    root, data_dir = measured_repo
    monkeypatch.setattr(reporter, "ROOT", root)
    output = root / "report"
    # main's combine call uses the real root configuration via its explicit root.
    original = reporter.combine
    monkeypatch.setattr(
        reporter, "combine", lambda directory, out: original(directory, out, root)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--data-dir", str(data_dir), "--output-dir", str(output)],
    )
    assert reporter.main() == 0
    report_path = output / "coverage.json"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--check", str(report_path)])
    assert reporter.main() == 0
    complete = json.loads(report_path.read_text())
    for metric in ("covered_lines", "covered_branches"):
        incomplete = copy.deepcopy(complete)
        incomplete["totals"][metric] -= 1
        incomplete["files"]["src/example.py"]["summary"][metric] -= 1
        report_path.write_text(json.dumps(incomplete))
        provenance_path = output / "summary.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["report_sha256"] = hashlib.sha256(
            report_path.read_bytes()
        ).hexdigest()
        provenance_path.write_text(json.dumps(provenance))
        assert reporter.main() == 1
    assert '"complete": false' in capsys.readouterr().out


@pytest.mark.parametrize(
    "change",
    [
        "missing",
        "invalid-json",
        "wrong-commit",
        "wrong-part",
        "wrong-data",
        "not-object",
    ],
)
def test_partition_provenance_rejects_stale_or_mixed_artifacts(measured_repo, change):
    root, data_dir = measured_repo
    metadata_path = (
        data_dir / "python-coverage-part-scripts/.coverage.scripts.metadata.json"
    )
    metadata = json.loads(metadata_path.read_text())
    if change == "missing":
        metadata_path.unlink()
    elif change == "invalid-json":
        metadata_path.write_text("broken")
    else:
        if change == "wrong-commit":
            metadata["source_commit"] = "f" * 40
        elif change == "wrong-part":
            metadata["part"] = "bridge-1"
        elif change == "wrong-data":
            metadata["data_sha256"] = "0" * 64
        else:
            metadata = []
        metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="provenance"):
        reporter.partition_files(
            data_dir,
            reporter.source_state(root)["commit"],
            reporter.measurement_identity(root),
        )


def test_dirty_python_source_cannot_be_stamped_or_combined(measured_repo):
    root, data_dir = measured_repo
    (root / "src/example.py").write_text("print('different source')\n")
    with pytest.raises(ValueError, match="committed Python source"):
        reporter.record_partition("scripts", root)
    with pytest.raises(ValueError, match="committed Python source"):
        reporter.combine(data_dir, root / "report", root)


@pytest.mark.parametrize("change", ["edit", "staged-delete"])
def test_authored_test_changes_invalidate_partition_and_report_provenance(
    measured_repo, change
):
    root, data_dir = measured_repo
    output = root / "report"
    reporter.combine(data_dir, output, root)
    assert reporter.check_report(output / "coverage.json", root)["complete"] is True
    source = root / "tests/test_example.py"
    if change == "edit":
        source.write_text(
            source.read_text() + "\ndef fixture_cleanup():\n    return False\n"
        )
    else:
        subprocess.run(
            ["git", "rm", "--", "tests/test_example.py"], cwd=root, check=True
        )
    assert reporter.source_state(root)["dirty"] is True
    with pytest.raises(ValueError, match="committed Python source"):
        reporter.record_partition("scripts", root)
    with pytest.raises(ValueError, match="provenance"):
        reporter.check_report(output / "coverage.json", root)


def test_new_untracked_source_is_in_inventory_and_dirty(measured_repo):
    root, _ = measured_repo
    (root / "training").mkdir()
    (root / "training/new.py").write_text("print('new runtime code')\n")
    assert "training/new.py" in reporter.inventory(root)["included"]
    assert reporter.source_state(root)["dirty"] is True


def test_record_command_and_real_cli_help(measured_repo, monkeypatch, capsys):
    root, data_dir = measured_repo
    part = "scripts"
    path = data_dir / "python-coverage-part-scripts/.coverage.scripts"
    (root / path.name).write_bytes(path.read_bytes())
    original = reporter.record_partition
    monkeypatch.setattr(reporter, "record_partition", lambda part: original(part, root))
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--record-part", part])
    assert reporter.main() == 0
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["source_commit"] == reporter.source_state(root)["commit"]
    assert metadata["part"] == part
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--help"])
    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert result.value.code == 0
    assert "--record-part" in capsys.readouterr().out


def test_ci_records_and_uploads_provenance_for_every_partition():
    import yaml

    workflow = yaml.safe_load(
        (SCRIPT.parents[1] / ".github/workflows/ci.yml").read_text()
    )
    for job in (
        "scripts",
        "bridge-tests-shard",
        "shiny-tests",
        "python-coverage-report",
        "python-coverage-release-gate",
    ):
        setup = next(
            step
            for step in workflow["jobs"][job]["steps"]
            if step.get("uses", "").startswith("actions/setup-python@")
        )
        assert setup["with"]["python-version"] == "3.11"
        install_commands = "\n".join(
            step.get("run", "") for step in workflow["jobs"][job]["steps"]
        )
        assert "--require-hashes" in install_commands
        assert "-r src/sigrift/bridge/requirements-test.txt" in install_commands
    assert reporter.MEASUREMENT_INPUTS == (
        ".coveragerc",
        "src/sigrift/bridge/requirements-test.in",
        "src/sigrift/bridge/requirements-test.txt",
    )
    for name in reporter.MEASUREMENT_INPUTS:
        assert (SCRIPT.parents[1] / name).is_file()
    for job in ("scripts", "bridge-tests-shard", "shiny-tests"):
        steps = workflow["jobs"][job]["steps"]
        measured = next(
            step for step in steps if "COVERAGE_FILE" in step.get("env", {})
        )
        filename = measured["env"]["COVERAGE_FILE"]
        part = filename.removeprefix(".coverage.")
        recorder = next(
            step for step in steps if "--record-part" in step.get("run", "")
        )
        uploader = next(
            step
            for step in steps
            if step.get("with", {}).get("name", "").startswith("python-coverage-part-")
        )
        assert (
            recorder["run"]
            == f"python scripts/python-coverage.py --record-part '{part}'"
        )
        assert steps.index(measured) < steps.index(recorder) < steps.index(uploader)
        assert recorder["if"] == "always()"
        assert uploader["with"]["include-hidden-files"] is True
        assert uploader["with"]["path"].splitlines() == [
            filename,
            filename + ".metadata.json",
        ]


@pytest.mark.parametrize(
    "change",
    [
        "new-commit",
        "dirty",
        "changed-report",
        "missing-provenance",
        "invalid-provenance",
        "not-object",
    ],
)
def test_check_rejects_stale_or_mixed_complete_reports(measured_repo, change):
    root, data_dir = measured_repo
    output = root / "report"
    reporter.combine(data_dir, output, root)
    report_path = output / "coverage.json"
    assert reporter.check_report(report_path, root)["complete"] is True
    if change == "new-commit":
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--allow-empty",
                "-qm",
                "next candidate",
            ],
            cwd=root,
            check=True,
        )
    elif change == "dirty":
        (root / "src/example.py").write_text("print('different source')\n")
    elif change == "changed-report":
        report_path.write_bytes(report_path.read_bytes() + b"\n")
    elif change == "missing-provenance":
        (output / "summary.json").unlink()
    elif change == "invalid-provenance":
        (output / "summary.json").write_text("broken")
    else:
        (output / "summary.json").write_text("[]")
    with pytest.raises(ValueError, match="provenance"):
        reporter.check_report(report_path, root)


def test_dirty_branch_suppression_cannot_certify_a_clean_commit(measured_repo):
    root, data_dir = measured_repo
    source = root / "src/example.py"
    source.write_text("flag = True\nif flag:\n    result = 1\ndone = True\n")
    subprocess.run(["git", "add", "src/example.py"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "one unexecuted branch",
        ],
        cwd=root,
        check=True,
    )
    for part in reporter.PARTS:
        path = root / (".coverage." + part)
        measurement = coverage.Coverage(
            config_file=str(root / ".coveragerc"), data_file=str(path)
        )
        measurement.start()
        exec(compile(source.read_text(), str(source), "exec"), {})
        measurement.stop()
        measurement.save()
        reporter.record_partition(part, root)
        directory = data_dir / ("python-coverage-part-" + part)
        path.replace(directory / path.name)
        metadata = path.with_name(path.name + ".metadata.json")
        metadata.replace(directory / metadata.name)
    baseline = reporter.combine(data_dir, root / "baseline", root)
    assert baseline["lines"] == {"covered": 4, "total": 6, "percent": 66.6667}
    assert baseline["branches"] == {"covered": 1, "total": 2, "percent": 50.0}
    assert baseline["complete"] is False
    config = root / ".coveragerc"
    config.write_text(
        config.read_text().replace(
            "partial_branches=\n", "partial_branches=\n    if flag:\n"
        )
    )
    with pytest.raises(ValueError, match="committed|suppression"):
        reporter.combine(data_dir, root / "forged-complete", root)


@pytest.mark.parametrize(
    "option", ["exclude_lines", "exclude_also", "partial_branches", "partial_also"]
)
def test_committed_suppression_settings_are_rejected(measured_repo, option):
    root, data_dir = measured_repo
    config = root / ".coveragerc"
    text = config.read_text()
    if option + "=" in text:
        text = text.replace(option + "=\n", option + "=\n    if flag:\n")
    else:
        text += option + "=\n    if flag:\n"
    config.write_text(text)
    subprocess.run(["git", "add", ".coveragerc"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "suppressed configuration",
        ],
        cwd=root,
        check=True,
    )
    with pytest.raises(ValueError, match="suppression"):
        reporter.measurement_identity(root)


@pytest.mark.parametrize("section", ["run", "report"])
def test_committed_file_omissions_cannot_hide_authored_tests(measured_repo, section):
    root, _ = measured_repo
    config = root / ".coveragerc"
    text = config.read_text().replace(
        f"[{section}]\n", f"[{section}]\nomit=tests/test_*.py\n"
    )
    config.write_text(text)
    commit_measurement_fixture(root)
    with pytest.raises(ValueError, match="Authored Python exclusions"):
        reporter.measurement_identity(root)


@pytest.mark.parametrize(
    "field",
    [
        "python_version",
        "python_implementation",
        "coverage_version",
        "config_sha256",
        "requirements_sha256",
    ],
)
def test_partition_measurement_identity_must_match(measured_repo, field):
    root, data_dir = measured_repo
    path = data_dir / "python-coverage-part-scripts/.coverage.scripts.metadata.json"
    metadata = json.loads(path.read_text())
    metadata.setdefault("measurement", {})[field] = "different"
    path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="provenance"):
        reporter.combine(data_dir, root / "report", root)


def test_committed_empty_settings_and_toolchain_are_bound(measured_repo):
    root, data_dir = measured_repo
    identity = reporter.measurement_identity(root)
    assert (
        identity["config_sha256"]
        == hashlib.sha256((root / ".coveragerc").read_bytes()).hexdigest()
    )
    assert identity["python_implementation"] == sys.implementation.name
    assert identity["python_version"] == list(sys.version_info)
    assert identity["coverage_version"] == coverage.__version__
    summary = reporter.combine(data_dir, root / "report", root)
    assert summary["measurement"] == identity
    assert (
        reporter.check_report(root / "report/coverage.json", root)["measurement"]
        == identity
    )


def test_new_process_patches_invalidate_existing_partitions_and_report(measured_repo):
    root, data_dir = measured_repo
    previous_commit = reporter.source_state(root)["commit"]
    previous_identity = reporter.measurement_identity(root)
    output = root / "previous-report"
    reporter.combine(data_dir, output, root)
    files = list(data_dir.rglob(".coverage.*")) + list(output.rglob("*"))
    preserved = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
        if path.is_file()
    }
    config = root / ".coveragerc"
    config.write_text(
        config.read_text().replace("[run]\n", "[run]\npatch=subprocess,fork,_exit\n")
    )
    commit_measurement_fixture(root)
    current_identity = reporter.measurement_identity(root)
    assert current_identity["config_sha256"] != previous_identity["config_sha256"]
    assert {
        key: value for key, value in current_identity.items() if key != "config_sha256"
    } == {
        key: value for key, value in previous_identity.items() if key != "config_sha256"
    }
    # Holding the expected commit constant isolates the measurement mismatch.
    with pytest.raises(ValueError, match="provenance mismatch"):
        reporter.partition_files(data_dir, previous_commit, current_identity)
    with pytest.raises(ValueError, match="provenance mismatch"):
        reporter.combine(data_dir, root / "new-report", root)
    with pytest.raises(ValueError, match="provenance"):
        reporter.check_report(output / "coverage.json", root)
    assert all(
        hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest
        for path, digest in preserved.items()
    ), "Rejecting stale artifacts must preserve the historical evidence"


@pytest.mark.parametrize(
    "field", ["python_version", "coverage_version", "config_sha256"]
)
def test_combined_measurement_identity_must_match(measured_repo, field):
    root, data_dir = measured_repo
    output = root / "report"
    reporter.combine(data_dir, output, root)
    provenance_path = output / "summary.json"
    metadata = json.loads(provenance_path.read_text())
    metadata.setdefault("measurement", {})[field] = "different"
    provenance_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="provenance"):
        reporter.check_report(output / "coverage.json", root)


def test_report_cannot_claim_a_different_coverage_writer(measured_repo):
    root, data_dir = measured_repo
    output = root / "report"
    reporter.combine(data_dir, output, root)
    report_path = output / "coverage.json"
    report = json.loads(report_path.read_text())
    report["meta"]["version"] = "0.0.0"
    report_path.write_text(json.dumps(report))
    metadata_path = output / "summary.json"
    metadata = json.loads(metadata_path.read_text())
    metadata["report_sha256"] = hashlib.sha256(report_path.read_bytes()).hexdigest()
    metadata_path.write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="version"):
        reporter.check_report(report_path, root)


def commit_measurement_fixture(root):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "measurement fixture",
        ],
        cwd=root,
        check=True,
    )


@pytest.mark.parametrize(
    "change", ["missing", "untracked", "symlink", "dirty", "staged"]
)
def test_configuration_must_be_present_regular_and_committed(measured_repo, change):
    root, _ = measured_repo
    path = root / ".coveragerc"
    if change == "missing":
        path.unlink()
    elif change == "untracked":
        subprocess.run(["git", "rm", "--cached", ".coveragerc"], cwd=root, check=True)
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "remove tracked configuration",
            ],
            cwd=root,
            check=True,
        )
    elif change == "symlink":
        target = root / "alternate-configuration"
        path.rename(target)
        path.symlink_to(target)
    elif change == "dirty":
        path.write_bytes(path.read_bytes() + b"\n")
    else:
        original = path.read_bytes()
        path.write_bytes(original + b"\n")
        subprocess.run(["git", "add", ".coveragerc"], cwd=root, check=True)
        path.write_bytes(original)
    assert reporter.source_state(root)["dirty"] is True
    with pytest.raises(ValueError, match="committed measurement"):
        reporter.measurement_identity(root)


@pytest.mark.parametrize(
    "name",
    [
        "src/sigrift/bridge/requirements-test.in",
        "src/sigrift/bridge/requirements-test.txt",
    ],
)
def test_test_toolchain_inputs_are_bound_and_dirty_changes_rejected(
    measured_repo, name
):
    root, _ = measured_repo
    path = root / name
    path.write_text("coverage==" + coverage.__version__ + "\n# changed input\n")
    with pytest.raises(ValueError, match="committed measurement"):
        reporter.measurement_identity(root)
    commit_measurement_fixture(root)
    identity = reporter.measurement_identity(root)
    assert (
        identity["requirements_sha256"][name]
        == hashlib.sha256(path.read_bytes()).hexdigest()
    )
    path.write_text("coverage==0.0.0\n")
    assert reporter.source_state(root)["dirty"] is True
    with pytest.raises(ValueError, match="committed measurement"):
        reporter.measurement_identity(root)


@pytest.mark.parametrize(
    "name",
    [
        "src/sigrift/bridge/requirements-test.in",
        "src/sigrift/bridge/requirements-test.txt",
    ],
)
def test_test_toolchain_inputs_cannot_be_deleted_or_untracked(measured_repo, name):
    root, _ = measured_repo
    (root / name).unlink()
    assert reporter.source_state(root)["dirty"] is True
    with pytest.raises(ValueError, match="committed measurement"):
        reporter.measurement_identity(root)
    commit_measurement_fixture(root)
    with pytest.raises(ValueError, match="committed measurement"):
        reporter.measurement_identity(root)


def test_alternate_config_override_is_rejected_and_canonical_override_allowed(
    measured_repo, monkeypatch
):
    root, _ = measured_repo
    monkeypatch.setenv("COVERAGE_RCFILE", str(root / "other.coveragerc"))
    with pytest.raises(ValueError, match="COVERAGE_RCFILE"):
        reporter.measurement_identity(root)
    monkeypatch.setenv("COVERAGE_RCFILE", str(root / ".coveragerc"))
    assert (
        reporter.measurement_identity(root)["config_sha256"]
        == hashlib.sha256((root / ".coveragerc").read_bytes()).hexdigest()
    )


def test_committed_line_only_configuration_is_rejected(measured_repo):
    root, _ = measured_repo
    path = root / ".coveragerc"
    path.write_text(path.read_text().replace("branch=True", "branch=False"))
    commit_measurement_fixture(root)
    with pytest.raises(ValueError, match="requires branches"):
        reporter.measurement_identity(root)


@pytest.mark.parametrize("tool", ["python", "coverage"])
def test_current_report_toolchain_must_match_measured_partitions(
    measured_repo, monkeypatch, tool
):
    root, data_dir = measured_repo
    if tool == "python":
        monkeypatch.setattr(sys, "version_info", (3, 99, 0, "final", 0))
    else:
        monkeypatch.setattr(coverage, "__version__", "0.0.0")
    with pytest.raises(ValueError, match="provenance mismatch"):
        reporter.combine(data_dir, root / "report", root)


def floor_summary(lines, branches, total=1000):
    return {
        "lines": {"covered": lines, "total": total},
        "branches": {"covered": branches, "total": total},
    }


@pytest.mark.parametrize(
    ("lines", "branches", "passed"),
    [(895, 759, True), (1000, 1000, True), (894, 999, False), (999, 758, False)],
)
def test_gate_is_the_committed_floor_not_completeness(lines, branches, passed):
    floors = {"lines": 89.5, "branches": 75.9}
    result = reporter.apply_floors(floor_summary(lines, branches), floors)
    assert result["passed"] is passed
    assert result["floor"] == floors


def test_floor_comparison_is_exact_not_rounded():
    # 89.49999...% displays as 89.5 but must not pass an 89.5 floor.
    summary = floor_summary(8949999, 10, total=10000000)
    summary["branches"] = {"covered": 1, "total": 1}
    assert reporter.apply_floors(summary, {"lines": 89.5, "branches": 0})["passed"] is False
    assert reporter.apply_floors(summary, {"lines": 89.49, "branches": 0})["passed"] is True


@pytest.mark.parametrize(
    "content",
    [
        None,
        "{",
        json.dumps({"rust": {"lines": 1, "branches": 1}}),
        json.dumps({"python": {"lines": 1}}),
        json.dumps({"python": {"lines": 1, "branches": 1, "regions": 1}}),
        json.dumps({"python": {"lines": "89", "branches": 1}}),
        json.dumps({"python": {"lines": True, "branches": 1}}),
        json.dumps({"python": {"lines": 1, "branches": 101}}),
        json.dumps({"python": {"lines": -1, "branches": 1}}),
        json.dumps({"python": [1, 2]}),
    ],
)
def test_missing_or_malformed_floors_fail_closed(tmp_path, content):
    floors = tmp_path / "floors.json"
    if content is not None:
        floors.write_text(content)
    with pytest.raises(ValueError, match="(?i)coverage floor"):
        reporter.load_floors(floors, "python")


def test_committed_repository_floors_are_valid():
    floors = reporter.load_floors()
    assert 0 < floors["lines"] <= 100 and 0 < floors["branches"] <= 100
