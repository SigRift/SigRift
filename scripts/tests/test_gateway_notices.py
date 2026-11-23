"""Offline release-notice contracts using real files and a deterministic tool."""

import hashlib
import importlib.util
import json
from pathlib import Path
import runpy
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/gateway-notices.py"
INPUTS = (
    "LICENSE",
    "Cargo.lock",
    "Cargo.toml",
    "src/gateway/crates/sigrift-gateway/Cargo.toml",
    "src/gateway/crates/sigrift-gateway-core/Cargo.toml",
    "licenses/gateway/about.toml",
    "licenses/gateway/about.hbs",
    "scripts/gateway-notices.py",
)
NOTICE = "licenses/gateway/THIRD-PARTY-NOTICES.txt"
MANIFEST = "licenses/gateway/manifest.json"
CHECKSUMS = "licenses/gateway/SHA256SUMS"
TEXT = b"Example dependency\nMIT License\nCopyright fixture author\n"


@pytest.fixture
def notices():
    spec = importlib.util.spec_from_file_location("gateway_notices_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_checksums(root):
    # Independent implementation of the public sha256sum-file contract.
    (root / CHECKSUMS).write_text(
        "".join(f"{sha(root / name)}  {name}\n" for name in (*INPUTS, NOTICE, MANIFEST))
    )


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "repository with spaces"
    for name in INPUTS:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture bytes for " + name + "\n")
    (root / NOTICE).write_bytes(TEXT)
    (root / MANIFEST).write_text(
        json.dumps(
            {
                "format": 1,
                "generator": "cargo-about 0.9.3",
                "inputs": {name: sha(root / name) for name in INPUTS},
                "output": {NOTICE: sha(root / NOTICE)},
            }
        )
    )
    write_checksums(root)
    return root


def cargo_tool(
    monkeypatch, tmp_path, *, version="cargo-about 0.9.3", text=TEXT, fail=0
):
    """Only the external generator is controlled; execute it as a real process."""
    tool = tmp_path / "cargo about fixture"
    tool.write_text(
        f"#!{sys.executable}\n"
        "import json, pathlib, sys\n"
        "if sys.argv[1:] == ['--version']:\n"
        f"    print({version!r})\n"
        "else:\n"
        "    assert sys.argv[1:] == ['generate', '--locked', '--workspace', '--fail', "
        "'--config', 'licenses/gateway/about.toml', 'licenses/gateway/about.hbs']\n"
        "    assert pathlib.Path('Cargo.lock').is_file()\n"
        "    pathlib.Path('tool-invocation.json').write_text(json.dumps(sys.argv[1:]))\n"
        f"    sys.stdout.buffer.write({text!r})\n"
        f"    sys.exit({fail})\n"
    )
    tool.chmod(0o755)
    monkeypatch.setenv("CARGO_ABOUT", str(tool))
    return tool


def snapshot(root):
    return {name: (root / name).read_bytes() for name in (NOTICE, MANIFEST, CHECKSUMS)}


def test_offline_check_accepts_exact_documented_inputs_and_bytes(notices, repository):
    assert tuple(p.as_posix() for p in notices.INPUTS) == INPUTS
    assert notices.check(repository) == []


@pytest.mark.parametrize("name", (*INPUTS, NOTICE))
def test_each_modified_input_or_notice_is_rejected(notices, repository, name):
    with (repository / name).open("ab") as out:
        out.write(b"modified\n")
    problems = notices.check(repository)
    assert "Gateway notice SHA256SUMS is stale or modified" in problems
    assert f"Gateway notices are stale or modified: {name}" in problems


@pytest.mark.parametrize("name", ("Cargo.lock", NOTICE, MANIFEST, CHECKSUMS))
def test_missing_required_file_fails_closed(notices, repository, name):
    (repository / name).unlink()
    assert notices.check(repository)[0].startswith("Cannot verify gateway notices:")


@pytest.mark.parametrize("body", ["{invalid", "\udcff"])
def test_invalid_manifest_encoding_or_json_fails_closed(notices, repository, body):
    (repository / MANIFEST).write_bytes(body.encode("utf-8", errors="surrogateescape"))
    assert notices.check(repository)[0].startswith("Cannot verify gateway notices:")


@pytest.mark.parametrize("body", [[], None, "text", 1])
def test_manifest_must_be_an_object(notices, repository, body):
    (repository / MANIFEST).write_text(json.dumps(body))
    write_checksums(repository)
    assert notices.check(repository) == ["Gateway notice manifest is not an object"]


@pytest.mark.parametrize(
    "field,value", [("format", 2), ("generator", "cargo-about 9.9")]
)
def test_recomputed_checksums_do_not_hide_obsolete_manifest(
    notices, repository, field, value
):
    manifest = json.loads((repository / MANIFEST).read_text())
    manifest[field] = value
    (repository / MANIFEST).write_text(json.dumps(manifest))
    write_checksums(repository)
    assert notices.check(repository) == [f"Gateway notice {field} is outdated"]


@pytest.mark.parametrize("field", ["inputs", "output"])
@pytest.mark.parametrize("value", [None, [], "not a mapping"])
def test_manifest_requires_both_hash_maps(notices, repository, field, value):
    manifest = json.loads((repository / MANIFEST).read_text())
    manifest[field] = value
    (repository / MANIFEST).write_text(json.dumps(manifest))
    write_checksums(repository)
    assert notices.check(repository) == [f"Gateway notice manifest lacks {field}"]


@pytest.mark.parametrize("mode", ["removed", "added"])
def test_manifest_file_set_must_match_even_with_valid_checksums(
    notices, repository, mode
):
    manifest = json.loads((repository / MANIFEST).read_text())
    if mode == "removed":
        path = "LICENSE"
        del manifest["inputs"][path]
    else:
        path = "unexpected/dependency"
        manifest["inputs"][path] = "0" * 64
    (repository / MANIFEST).write_text(json.dumps(manifest))
    write_checksums(repository)
    assert notices.check(repository) == [
        f"Gateway notices are stale or modified: {path}"
    ]


def test_checksums_file_itself_is_verified(notices, repository):
    (repository / CHECKSUMS).write_text("untrusted checksums\n")
    assert notices.check(repository) == [
        "Gateway notice SHA256SUMS is stale or modified"
    ]


def test_generation_uses_locked_workspace_and_refreshes_all_attestations(
    notices, repository, monkeypatch, tmp_path
):
    fresh = TEXT + b"Second dependency license\n"
    cargo_tool(monkeypatch, tmp_path, text=fresh)
    notices.generate(repository)
    assert (repository / NOTICE).read_bytes() == fresh
    recorded = json.loads((repository / MANIFEST).read_text())
    assert recorded["output"] == {NOTICE: hashlib.sha256(fresh).hexdigest()}
    assert notices.check(repository) == []
    assert (repository / "tool-invocation.json").exists()


@pytest.mark.parametrize(
    "version,text,fail,exception,match",
    [
        ("cargo-about 0.9.2", TEXT, 0, RuntimeError, "Expected cargo-about 0.9.3"),
        ("cargo-about 0.9.3", b" \n\t", 0, RuntimeError, "produced no notices"),
        ("cargo-about 0.9.3", TEXT, 7, subprocess.CalledProcessError, "exit status 7"),
    ],
)
def test_failed_generator_keeps_existing_artifacts(
    notices, repository, monkeypatch, tmp_path, version, text, fail, exception, match
):
    before = snapshot(repository)
    cargo_tool(monkeypatch, tmp_path, version=version, text=text, fail=fail)
    with pytest.raises(exception, match=match):
        notices.generate(repository)
    assert snapshot(repository) == before


@pytest.mark.parametrize("different", [False, True])
def test_verify_generated_never_writes(
    notices, repository, monkeypatch, tmp_path, different
):
    before = snapshot(repository)
    cargo_tool(monkeypatch, tmp_path, text=TEXT + (b"changed" if different else b""))
    if different:
        with pytest.raises(RuntimeError, match="differ from the checked-in file"):
            notices.generate(repository, verify=True)
    else:
        notices.generate(repository, verify=True)
    assert snapshot(repository) == before


@pytest.mark.parametrize("mode", ["--check", "--generate", "--verify-generated"])
def test_cli_modes_report_success(
    notices, repository, monkeypatch, tmp_path, capsys, mode
):
    monkeypatch.setattr(notices, "ROOT", repository)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), mode])
    cargo_tool(monkeypatch, tmp_path)
    assert notices.main() == 0
    output = capsys.readouterr()
    assert output.out == "Gateway dependency notices match the locked inputs.\n"
    assert output.err == ""


@pytest.mark.parametrize("failure", ["missing-tool", "tool-exit", "version", "stale"])
def test_cli_failure_exits_one_and_explains_regeneration(
    notices, repository, monkeypatch, tmp_path, capsys, failure
):
    monkeypatch.setattr(notices, "ROOT", repository)
    mode = "--check" if failure == "stale" else "--generate"
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), mode])
    if failure == "missing-tool":
        monkeypatch.setenv("CARGO_ABOUT", str(tmp_path / "absent-tool"))
    elif failure == "stale":
        (repository / NOTICE).write_bytes(b"stale")
    else:
        cargo_tool(
            monkeypatch,
            tmp_path,
            fail=7 if failure == "tool-exit" else 0,
            version="old-version" if failure == "version" else "cargo-about 0.9.3",
        )
    assert notices.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.endswith(
        "Run scripts/gateway-notices.py --generate with cargo-about 0.9.3.\n"
    )


@pytest.mark.parametrize("args", [[], ["--check", "--generate"], ["--unknown"]])
def test_cli_requires_exactly_one_known_mode(notices, monkeypatch, args):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), *args])
    with pytest.raises(SystemExit) as error:
        notices.main()
    assert error.value.code == 2


def test_actual_script_entrypoint_checks_checked_in_notice_bundle(monkeypatch):
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--check"])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert error.value.code == 0
