"""scripts/verify_deps.py checks installed files against their RECORD hashes.

    python3 -m pytest scripts/tests -q

A throwaway "installed" package (a dist-info directory with a RECORD, as
pip writes it) stands in for the real ones.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import runpy
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def verify_deps():
    spec = importlib.util.spec_from_file_location(
        "verify_deps_under_test", ROOT / "scripts" / "verify_deps.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(
        b"="
    ).decode("ascii")


def install_fake(site: Path, name: str = "fakepkg") -> importlib.metadata.Distribution:
    """Lay out an installed wheel the way pip does and return its Distribution."""
    pkg = site / name
    pkg.mkdir(parents=True)
    files = {
        f"{name}/__init__.py": b"VALUE = 1\n",
        f"{name}/core.py": b"def run():\n    return 'ok'\n",
    }
    for rel, data in files.items():
        (site / rel).write_bytes(data)
    (pkg / "__pycache__").mkdir()
    (pkg / "__pycache__" / "core.cpython-311.pyc").write_bytes(b"\x00compiled")
    info = site / f"{name}-1.0.dist-info"
    info.mkdir()
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\nLicense: MIT\n"
    (info / "METADATA").write_text(metadata)
    rows = [f"{rel},{_record_hash(data)},{len(data)}" for rel, data in files.items()]
    rows.append(
        f"{name}-1.0.dist-info/METADATA,{_record_hash(metadata.encode())},"
        f"{len(metadata)}"
    )
    rows.append(f"{name}/__pycache__/core.cpython-311.pyc,,")  # pip: no hash
    rows.append(f"{name}-1.0.dist-info/RECORD,,")
    (info / "RECORD").write_text("\n".join(rows) + "\n")
    return importlib.metadata.PathDistribution(info)


@pytest.fixture
def fake(tmp_path, verify_deps, monkeypatch):
    dist = install_fake(tmp_path / "site")

    def distribution(name):
        if name == "fakepkg":
            return dist
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(verify_deps, "_distribution", distribution)
    monkeypatch.setattr(verify_deps, "TRACKED_PACKAGES", ["fakepkg"])
    monkeypatch.setattr(verify_deps, "HASH_FILE", tmp_path / "hashes.json")
    return dist, tmp_path / "site"


def test_untouched_install_verifies(verify_deps, fake):
    dist, _ = fake
    assert verify_deps.verify_record(dist) == []


def test_a_modified_file_is_reported(verify_deps, fake):
    dist, site = fake
    (site / "fakepkg" / "core.py").write_bytes(b"import os; os.system('evil')\n")
    issues = verify_deps.verify_record(dist)
    assert len(issues) == 1 and "fakepkg/core.py" in issues[0]


def test_a_missing_file_is_reported(verify_deps, fake):
    dist, site = fake
    (site / "fakepkg" / "__init__.py").unlink()
    assert any("missing" in i for i in verify_deps.verify_record(dist))


def test_no_record_is_reported(verify_deps, fake):
    dist, site = fake
    (site / "fakepkg-1.0.dist-info" / "RECORD").unlink()
    assert "no RECORD" in verify_deps.verify_record(dist)[0]


def test_check_catches_tampering_that_leaves_metadata_alone(verify_deps, fake):
    """The old check hashed METADATA only, so this tampering went unnoticed."""
    dist, site = fake
    verify_deps.save_hashes(verify_deps.generate_sbom())
    assert verify_deps.check_hashes(verify_deps.generate_sbom()) == []

    metadata = (site / "fakepkg-1.0.dist-info" / "METADATA").read_bytes()
    (site / "fakepkg" / "core.py").write_bytes(b"def run():\n    return 'pwned'\n")
    assert (site / "fakepkg-1.0.dist-info" / "METADATA").read_bytes() == metadata

    issues = verify_deps.check_hashes(verify_deps.generate_sbom())
    assert any("fakepkg/core.py" in i for i in issues), issues


def test_saved_fingerprint_is_the_record_file(verify_deps, fake):
    dist, site = fake
    sbom = verify_deps.generate_sbom()
    record = (site / "fakepkg-1.0.dist-info" / "RECORD").read_bytes()
    assert sbom["packages"][0]["record_sha256"] == hashlib.sha256(record).hexdigest()
    verify_deps.save_hashes(sbom)
    saved = json.loads(verify_deps.HASH_FILE.read_text())
    assert saved["fakepkg"]["sha256"] == hashlib.sha256(record).hexdigest()

    # A rewritten RECORD (reinstall, or tampering that also fixes RECORD up).
    with open(site / "fakepkg-1.0.dist-info" / "RECORD", "a") as f:
        f.write("fakepkg/extra.py,,\n")
    issues = verify_deps.check_hashes(verify_deps.generate_sbom())
    assert any("RECORD hash mismatch" in i for i in issues), issues


@pytest.mark.parametrize(
    "record_text",
    [
        "",
        " \t\n\n",
        "fakepkg-1.0.dist-info/RECORD,,\n"
        "fakepkg/__pycache__/core.cpython-311.pyc,,\n",
    ],
    ids=["empty", "whitespace", "unhashed-entries-only"],
)
def test_unverifiable_record_cannot_certify_installed_files(
    verify_deps, fake, monkeypatch, capsys, record_text
):
    dist, site = fake
    verify_deps.save_hashes(verify_deps.generate_sbom())
    (site / "fakepkg-1.0.dist-info" / "RECORD").write_text(record_text)
    issue = "fakepkg: no RECORD hash entries, so its installed files cannot be verified"
    assert verify_deps.verify_record(dist) == [issue]
    assert issue in verify_deps.check_hashes(verify_deps.generate_sbom())
    monkeypatch.setattr(sys, "argv", ["verify_deps.py", "--check"])
    assert verify_deps.main() == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert issue in output.err


def test_record_removed_after_saved_baseline_fails_verification(verify_deps, fake):
    _dist, site = fake
    verify_deps.save_hashes(verify_deps.generate_sbom())
    (site / "fakepkg-1.0.dist-info" / "RECORD").unlink()
    sbom = verify_deps.generate_sbom()
    assert sbom["packages"][0]["version"] == "1.0"
    assert sbom["packages"][0]["record_sha256"] is None
    assert verify_deps.check_hashes(sbom) == [
        "fakepkg: no RECORD file, so its installed files cannot be verified"
    ]


def test_record_symlink_loop_is_reported_without_crashing(verify_deps, fake):
    dist, site = fake
    verify_deps.save_hashes(verify_deps.generate_sbom())
    record = site / "fakepkg-1.0.dist-info" / "RECORD"
    record.unlink()
    record.symlink_to("RECORD")
    # PathDistribution suppresses ordinary missing/permission errors, but a
    # real filesystem ELOOP reaches the verifier's OSError handling.
    with pytest.raises(OSError) as error:
        dist.read_text("RECORD")
    assert error.value.errno == errno.ELOOP
    issue = "fakepkg: no RECORD file, so its installed files cannot be verified"
    assert verify_deps.verify_record(dist) == [issue]
    sbom = verify_deps.generate_sbom()
    assert sbom["packages"][0]["record_sha256"] is None
    assert verify_deps.check_hashes(sbom) == [issue]


@pytest.mark.parametrize("algorithm", ["shake_128", "shake_256"])
def test_variable_length_record_hash_is_reported_without_crashing(
    verify_deps, fake, algorithm
):
    dist, site = fake
    (site / "fakepkg-1.0.dist-info" / "RECORD").write_text(
        f"fakepkg/core.py,{algorithm}=unusable,1\n"
    )
    issues = verify_deps.verify_record(dist)
    assert len(issues) == 1
    assert "unusable RECORD hash" in issues[0]


@pytest.mark.parametrize("digest", ["missing-equals", "unknown=abc"])
def test_invalid_record_algorithm_is_reported(verify_deps, fake, digest):
    dist, site = fake
    (site / "fakepkg-1.0.dist-info" / "RECORD").write_text(
        f"fakepkg/core.py,{digest},1\n"
    )
    assert "unusable RECORD hash" in verify_deps.verify_record(dist)[0]


def test_record_file_read_failure_is_reported(verify_deps, fake):
    dist, site = fake
    record = site / "fakepkg-1.0.dist-info" / "RECORD"
    record.unlink()
    record.mkdir()
    assert "no RECORD file" in verify_deps.verify_record(dist)[0]


def test_installed_file_read_failure_is_reported(verify_deps, fake):
    dist, site = fake
    installed = site / "fakepkg" / "core.py"
    installed.unlink()
    installed.mkdir()
    issues = verify_deps.verify_record(dist)
    assert len(issues) == 1
    assert "fakepkg/core.py cannot be read" in issues[0]


def test_real_metadata_discovery_and_missing_optional_package(
    verify_deps, tmp_path, monkeypatch
):
    site = tmp_path / "site"
    install_fake(site)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setattr(
        verify_deps, "TRACKED_PACKAGES", ["absent-fixture-package", "fakepkg"]
    )
    sbom = verify_deps.generate_sbom()
    assert sbom["total_tracked"] == 2
    assert sbom["total_installed"] == 1
    assert sbom["packages"][0] == {
        "name": "absent-fixture-package",
        "version": "NOT INSTALLED",
        "license": "unknown",
        "record_sha256": None,
    }
    assert sbom["packages"][1]["name"] == "fakepkg"
    assert sbom["packages"][1]["version"] == "1.0"
    assert sbom["packages"][1]["license"] == "MIT"


def test_package_without_record_has_no_fingerprint(verify_deps, fake):
    _dist, site = fake
    (site / "fakepkg-1.0.dist-info" / "RECORD").unlink()
    assert verify_deps.get_package_info("fakepkg")["record_sha256"] is None
    sbom = verify_deps.generate_sbom()
    verify_deps.save_hashes(sbom)
    assert json.loads(verify_deps.HASH_FILE.read_text()) == {}
    assert "no RECORD file" in verify_deps.check_hashes(sbom)[0]


def test_verification_requires_a_saved_baseline(verify_deps, fake):
    assert verify_deps.check_hashes(verify_deps.generate_sbom()) == [
        "No saved hashes found. Run with --save first."
    ]


def test_changed_package_version_is_reported(verify_deps, fake):
    _dist, site = fake
    verify_deps.save_hashes(verify_deps.generate_sbom())
    metadata = site / "fakepkg-1.0.dist-info" / "METADATA"
    metadata.write_text(metadata.read_text().replace("Version: 1.0", "Version: 2.0"))
    issues = verify_deps.check_hashes(verify_deps.generate_sbom())
    assert "fakepkg: version changed 1.0 → 2.0" in issues
    assert any("METADATA does not match" in issue for issue in issues)


def test_uninstall_between_inventory_and_check_is_reported(
    verify_deps, tmp_path, monkeypatch
):
    site = tmp_path / "site"
    install_fake(site)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setattr(verify_deps, "TRACKED_PACKAGES", ["fakepkg"])
    monkeypatch.setattr(verify_deps, "HASH_FILE", tmp_path / "hashes.json")
    sbom = verify_deps.generate_sbom()
    verify_deps.save_hashes(sbom)
    metadata = site / "fakepkg-1.0.dist-info"
    for entry in metadata.iterdir():
        entry.unlink()
    metadata.rmdir()
    assert verify_deps.check_hashes(sbom) == ["fakepkg: no longer installed"]
    # A fresh inventory must also reject removal of a previously saved package.
    current = verify_deps.generate_sbom()
    assert current["packages"][0]["version"] == "NOT INSTALLED"
    assert verify_deps.check_hashes(current) == [
        "fakepkg: version changed 1.0 → NOT INSTALLED"
    ]


@pytest.mark.parametrize("mode", ["stdout", "file", "save", "check", "check-failure"])
def test_command_line_outputs_and_exit_codes(
    verify_deps, fake, tmp_path, monkeypatch, capsys, mode
):
    _dist, site = fake
    args = ["verify_deps.py"]
    if mode == "file":
        args += ["-o", str(tmp_path / "sbom.json")]
    elif mode == "save":
        args += ["--save"]
    elif mode.startswith("check"):
        verify_deps.save_hashes(verify_deps.generate_sbom())
        args += ["--check"]
        if mode == "check-failure":
            (site / "fakepkg" / "core.py").write_bytes(b"changed after install")
    monkeypatch.setattr(sys, "argv", args)
    assert verify_deps.main() == (1 if mode == "check-failure" else 0)
    output = capsys.readouterr()
    if mode == "stdout":
        assert json.loads(output.out)["total_installed"] == 1
    elif mode == "file":
        assert json.loads((tmp_path / "sbom.json").read_text())["total_installed"] == 1
        assert output.out == f"SBOM written to {tmp_path / 'sbom.json'}\n"
    elif mode == "save":
        assert (
            json.loads(verify_deps.HASH_FILE.read_text())["fakepkg"]["version"] == "1.0"
        )
        assert output.out == "Saved 1 package hashes.\n"
    elif mode == "check":
        assert output.out == "OK: 1 packages verified.\n"
    else:
        assert output.out == ""
        assert "WARN: fakepkg: fakepkg/core.py does not match" in output.err
    if mode != "check-failure":
        assert output.err == ""


def test_actual_entrypoint_emits_metadata_without_writing_a_baseline(
    monkeypatch, capsys
):
    script = ROOT / "scripts/verify_deps.py"
    monkeypatch.setattr(sys, "argv", [str(script)])
    with pytest.raises(SystemExit) as error:
        runpy.run_path(str(script), run_name="__main__")
    assert error.value.code == 0
    sbom = json.loads(capsys.readouterr().out)
    assert sbom["sbom_version"] == "1.0"
    assert sbom["total_tracked"] == len(sbom["packages"])
    assert sbom["total_installed"] == sum(
        p["version"] != "NOT INSTALLED" for p in sbom["packages"]
    )
