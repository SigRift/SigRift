"""Which install an installer run acts on (lc_identity) and its refusals.

The installers run for real against FakeDockerHost (lifecycle_fakes.py),
a Docker host played from a JSON file. A refusal must change no file and
start nothing, and end with one next command and "Nothing was changed.".
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from bash_file import script_argv  # noqa: E402
from pathlib import Path

import pytest

from lifecycle_fakes import (
    BASH,
    INSTALL_RELEASE,
    INSTALLED_ENV,
    KEY_A,
    KEY_B,
    KEY_C,
    QUICKSTART,
    SECRET_VALUES,
    FakeDockerHost,
    changing_calls,
    derive,
    release_install,
    run_installer,
    shared_block,
    source_checkout,
    tree_digest,
    unpacked_release,
)


def have_compose() -> bool:
    return bool(shutil.which("docker")) and subprocess.run(
        ["docker", "compose", "version"], capture_output=True).returncode == 0


needs_compose = pytest.mark.skipif(not have_compose(), reason="docker compose not available")
# Installer runs against the fake host start many processes; slow CI
# runners need far more than the repo's 30 s default.
pytestmark = pytest.mark.timeout(240)
INSTALLED_ENV_B = INSTALLED_ENV.replace(KEY_A, KEY_B)
INSTALLED_ENV_NO_MFA = INSTALLED_ENV.replace(f"BRIDGE_MFA_KEY={KEY_A}\n", "")


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


def free_port() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return str(port)


def env_of(folder: Path) -> dict:
    out = {}
    for line in (folder / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def identity(host, folder: Path, installer="release", *flags, env=None, version="v0.2.0"):
    """lc_identity's decision as a dict, or the CompletedProcess of a refusal."""
    blocks = "".join(shared_block(INSTALL_RELEASE, n) for n in (
        "tls-key-perms", "lifecycle-tool", "lifecycle-engine", "identity"))
    lib = host.tmp / "identity-blocks.sh"
    lib.write_text(blocks)
    script = (f'set -euo pipefail\nsource "{lib}"\nLC_SELF_DIR="{folder}"\n'
              f'VERSION={version} OWNER=sigrift\n'
              # install-release.sh sets PORT from UC_PORT itself.
              + ('PORT=${UC_PORT:-8444}\n' if installer == "release" else "")
              + "".join(f"{k}={v!r}\n" for k, v in (flags[0] if flags else {}).items())
              + f"lc_identity {installer}\n"
              + 'for k in $LC_DECISION_KEYS; do printf "%s=%s\\n" "$k" "${!k}"; done\n')
    r = subprocess.run(script_argv(BASH, script), capture_output=True, text=True, cwd=folder,
                       env=host.env(**(env or {})))
    if r.returncode:
        return r
    return dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)


def assert_refused(r, *needles):
    assert r.returncode == 3, (r.returncode, r.stdout, r.stderr)
    lines = r.stderr.rstrip("\n").splitlines()
    assert lines[-1] == "Nothing was changed.", r.stderr
    assert lines[-2].startswith("Next: ") and len(lines[-2]) > len("Next: "), r.stderr
    assert any(line.startswith("Error: ") for line in lines), r.stderr
    for n in needles:
        assert n in r.stderr, (n, r.stderr)


# ── project names ───────────────────────────────────────────────────────


@pytest.mark.parametrize("name,expected", [
    ("sigrift-v0.1.0", "sigrift-v010"), ("SigRift", "sigrift"), ("My Lab", "mylab"),
    ("_x.y", "xy")])
def test_derive_project_matches_compose(tmp_path, name, expected):
    from lifecycle_fakes import load_lifecycle_tool

    tool = load_lifecycle_tool()
    assert tool.derive_project(str(tmp_path / name)) == expected == derive(name)
    if not have_compose():
        return
    d = tmp_path / name
    d.mkdir()
    (d / "docker-compose.yml").write_text("services:\n  x:\n    image: scratch\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("COMPOSE_")}
    r = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=d,
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["name"] == expected


# ── existing installs ───────────────────────────────────────────────────


def test_first_run_on_a_v01x_install_pins_the_derived_name(host, tmp_path):
    d = release_install(host, tmp_path)
    volumes = [v["name"] for v in host.load()["volumes"]]
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert "==> Pinned COMPOSE_PROJECT_NAME=sigrift-v010 in .env (the name Docker Compose " \
        "already used; volume names stay the same)." in r.stdout
    assert env_of(d)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"
    backups = list(d.glob(".env.bak.*~"))
    assert len(backups) == 1 and backups[0].stat().st_mode & 0o777 == 0o600
    state = host.load()
    assert [v["name"] for v in state["volumes"]] == volumes
    assert {c["project"] for c in state["containers"]} == {"sigrift-v010"}
    record = json.loads((d / ".sigrift" / "install.json").read_text())
    assert record["project"] == "sigrift-v010" and record["working_dir"] == str(d.resolve())
    assert state["records"]["sigrift-v010_bridge_data"]["install_id"] == record["install_id"]
    # A second run finds the pin and changes nothing about it.
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert "Pinned" not in r.stdout
    assert env_of(d)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"


def test_pin_is_written_only_after_compose_honours_it(host, tmp_path):
    d = release_install(host, tmp_path)
    host.update(compose_honours_env_file=False)
    before = tree_digest(d)
    r = run_installer(d, host=host)
    assert_refused(r, "docker compose ignored COMPOSE_PROJECT_NAME")
    assert tree_digest(d) == before and changing_calls(host) == []


def test_pinned_folder_renamed_keeps_its_project_and_records_the_move(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    assert run_installer(d, host=host).returncode == 0
    install_id = json.loads((d / ".sigrift" / "install.json").read_text())["install_id"]
    moved = d.rename(tmp_path / "lab")
    r = run_installer(moved, host=host)
    assert r.returncode == 0, r.stderr
    assert f"==> This install moved from {d.resolve()} to {moved.resolve()}" in r.stdout
    record = json.loads((moved / ".sigrift" / "install.json").read_text())
    assert record["install_id"] == install_id and record["working_dir"] == str(moved.resolve())
    assert env_of(moved)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"
    assert {c["project"] for c in host.load()["containers"]} == {"sigrift-v010"}


def test_copied_folder_is_refused(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    assert run_installer(d, host=host).returncode == 0
    install_id = json.loads((d / ".sigrift" / "install.json").read_text())["install_id"]
    copy = tmp_path / "copy"
    shutil.copytree(d, copy, symlinks=True)
    before = tree_digest(copy, d)
    host.clear_log()
    r = run_installer(copy, host=host)
    assert_refused(r, f"this folder is a copy of {d.resolve()} (same install id {install_id[:8]}",
                   f"Next: bash install-release.sh --upgrade {d.resolve()}")
    assert tree_digest(copy, d) == before and changing_calls(host) == []


def test_copied_folder_without_a_host_record_is_refused_by_its_labels(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    copy = tmp_path / "copy"
    shutil.copytree(d, copy)
    before = tree_digest(copy, d)
    r = run_installer(copy, host=host)
    assert_refused(r, f"this folder and {d.resolve()} address the same Docker Compose project")
    assert tree_digest(copy, d) == before and changing_calls(host) == []


def test_unpinned_folder_with_the_same_name_elsewhere_is_refused(host, tmp_path):
    d = release_install(host, tmp_path)
    twin = tmp_path / "elsewhere" / d.name
    twin.parent.mkdir()
    shutil.copytree(d, twin)
    r = run_installer(twin, host=host)
    assert_refused(r, f"this folder and {d.resolve()} address the same Docker Compose project")


# ── renamed before the pin existed ──────────────────────────────────────


def renamed(host, tmp_path, **kw):
    d = release_install(host, tmp_path, **kw)
    return d, d.rename(tmp_path / "lab")


def test_renamed_unpinned_folder_adopts_the_single_matching_orphan(host, tmp_path):
    old, d = renamed(host, tmp_path)
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert f"==> Adopted project sigrift-v010 for this folder (renamed from {old}" in r.stdout
    assert "TOTP secrets verify" in r.stdout and "audit chain verifies" in r.stdout
    assert env_of(d)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"
    assert {c["project"] for c in host.load()["containers"]} == {"sigrift-v010"}
    assert not [v for v in host.load()["volumes"] if v["project"] == "lab"]


def test_renamed_folder_of_a_down_stack_is_found_through_its_volume_record(host, tmp_path):
    d = release_install(host, tmp_path, containers=False)
    host.load()
    host.state["records"]["sigrift-v010_bridge_data"] = {
        "format": 1, "install_id": "11111111-2222-3333-4444-555555555555",
        "install_type": "release", "project": "sigrift-v010", "working_dir": str(d),
        "last_version": "v0.1.0"}
    host.save()
    lab = d.rename(tmp_path / "lab")
    r = run_installer(lab, host=host)
    assert r.returncode == 0, r.stderr
    assert "==> Adopted project sigrift-v010" in r.stdout and f"renamed from {d}" in r.stdout
    # Read as the bridge's uid with no capabilities, at most 64 KiB.
    reads = [a for a in host.argvs() if a.endswith("/v/.sigrift-install.json")]
    assert reads and all("--log-driver none" in a and "--user 1500:1500 --cap-drop ALL" in a
                         and "head -c 65537" in a for a in reads), reads


def test_renamed_folder_with_two_orphans_is_refused_with_adopt_project(host, tmp_path):
    _, d = renamed(host, tmp_path)
    other = release_install(host, tmp_path, name="sigrift-old")
    gone = other.rename(tmp_path / "gone-later")
    shutil.rmtree(gone)
    before = tree_digest(d)
    r = run_installer(d, host=host)
    assert_refused(r, "it looks like a folder renamed before this installer pinned it",
                   "sigrift-v010  last folder", "sigrift-old  last folder",
                   "Next: bash install-release.sh --adopt-project sigrift-")
    assert tree_digest(d) == before and changing_calls(host) == []


def test_renamed_folder_can_start_empty_with_new_instance(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"totp_fernet": 0, "audit_rows": 0})
    port = free_port()
    (d / "docker-compose.yml").write_text(
        (d / "docker-compose.yml").read_text().replace(":8444:8444", f":{port}:8444"))
    r = identity(host, d, "release", {"LC_NEW_INSTANCE": "1"})
    assert isinstance(r, dict), r.stderr
    assert (r["LC_PROJECT"], r["LC_PIN"], r["LC_HAS_DATA"]) == ("lab", "1", "0")


def test_orphan_without_proof_is_not_adopted_automatically(host, tmp_path):
    # No TOTP user, empty audit log, no volume record: nothing proves the
    # .env belongs to that data.
    _, d = renamed(host, tmp_path, data={"totp_fernet": 0, "audit_rows": 0})
    r = run_installer(d, host=host)
    assert_refused(r, "Next: bash install-release.sh --adopt-project sigrift-v010",
                   ".env matches: TOTP key n.a., audit key n.a.")


def test_orphan_contradicting_the_env_is_not_adopted(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"mfa_key": KEY_B})
    r = run_installer(d, host=host)
    assert_refused(r, ".env matches: TOTP key no")


def test_adopt_project_pins_the_named_project(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"totp_fernet": 0, "audit_rows": 0})
    r = run_installer(d, "--adopt-project", "sigrift-v010", host=host)
    assert r.returncode == 0, r.stderr
    assert "==> Adopted project sigrift-v010" in r.stdout
    assert env_of(d)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"


def test_adopt_project_refuses_contradicting_secrets(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"mfa_key": KEY_B})
    before = tree_digest(d)
    r = run_installer(d, "--adopt-project=sigrift-v010", host=host)
    assert_refused(r, "do not match the data of project sigrift-v010 (BRIDGE_MFA_KEY does "
                      "not verify its TOTP secrets)")
    assert tree_digest(d) == before


def test_adopt_project_refuses_a_project_another_folder_uses(host, tmp_path):
    d = release_install(host, tmp_path)
    lab = tmp_path / "lab"
    lab.mkdir()
    shutil.copy(d / "docker-compose.yml", lab)
    shutil.copy(d / ".env", lab)
    shutil.copy(INSTALL_RELEASE, lab / "install-release.sh")
    r = run_installer(lab, "--adopt-project", "sigrift-v010", host=host)
    assert_refused(r, f"project sigrift-v010 belongs to {d.resolve()}, which still exists",
                   f"Next: bash install-release.sh --upgrade {d.resolve()}")


def test_shell_project_differing_from_the_pin_is_refused(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    r = run_installer(d, host=host, env={"COMPOSE_PROJECT_NAME": "other"})
    assert_refused(r, "COMPOSE_PROJECT_NAME in your shell (other) differs from the project "
                      "pinned in .env (sigrift-v010)",
                   "Next: unset COMPOSE_PROJECT_NAME && bash install-release.sh")


def test_existing_env_without_data_anywhere_starts_with_empty_data(host, tmp_path):
    d = release_install(host, tmp_path)
    host.update(volumes=[], containers=[], data={})
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert "NOTE: no data volumes exist for project sigrift-v010 on this host" in r.stderr
    assert env_of(d)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"


def test_existing_env_without_data_beside_another_install_is_refused(host, tmp_path):
    release_install(host, tmp_path, name="sigrift-v0.1.0")
    d = tmp_path / "second"
    d.mkdir()
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    (d / ".env").write_text("BRIDGE_ENV=production\n")
    r = run_installer(d, host=host, env={"SIGRIFT_VERSION": "v0.1.0"})
    assert_refused(r, "this folder has no data yet and this host already runs SigRift",
                   "sigrift-v010  v0.1.0, running, port 8444",
                   "--new-instance")


def test_missing_env_with_data_is_refused(host, tmp_path):
    d = release_install(host, tmp_path)
    (d / ".env").unlink()
    before = tree_digest(d)
    r = run_installer(d, host=host)
    assert_refused(r, "there is no .env here, but project sigrift-v010 has data",
                   "Next: ls -la .env.bak.*~ .sigrift/snapshots/")
    assert tree_digest(d) == before and changing_calls(host) == []


def test_quickstart_checkout_without_env_beside_its_data_is_refused(host, tmp_path):
    d = source_checkout(tmp_path, "SigRift")
    host.add_project("sigrift", d, image="sigrift-bridge", data={"users": 1})
    r = identity(host, d, "quickstart")
    assert_refused(r, "there is no .env here, but project sigrift has data")


# ── a newly unpacked release folder ─────────────────────────────────────


def with_source_install(host, tmp_path):
    src = source_checkout(tmp_path, "SigRift-src", env="BRIDGE_ENV=development\n")
    host.add_project("sigrift-src", src, image="sigrift-src-bridge", port="8454",
                     data={"users": 1})
    return src


def test_new_folder_with_one_release_install_upgrades_it_without_a_tty(host, tmp_path):
    old = release_install(host, tmp_path)
    with_source_install(host, tmp_path)
    new = unpacked_release(tmp_path, "v0.2.0")
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.2.0", 57)
    host.add_image("ghcr.io/sigrift/sigrift-gateway:v0.2.0")
    plan = run_installer(new, "--dry-run", host=host)
    assert plan.returncode == 0, plan.stderr
    assert "also here sigrift-src" in plan.stdout
    before = tree_digest(new)
    r = run_installer(new, host=host)
    assert r.returncode == 0, r.stderr
    assert "==> Found one SigRift release install on this host:" in r.stdout
    assert f"folder {old.resolve()}" in r.stdout
    # The plan comes before anything changes, also without --dry-run.
    assert r.stdout.index("==> Plan\n") < r.stdout.index("==> Updated bridge + gateway images")
    assert "also here sigrift-src" in r.stdout
    assert tree_digest(new) == before
    assert (old / "VERSION").read_text() == "v0.2.0\n"
    assert "ghcr.io/sigrift/sigrift-bridge:v0.2.0" in (old / "docker-compose.yml").read_text()
    assert env_of(old)["COMPOSE_PROJECT_NAME"] == "sigrift-v010"
    ups = [c for c in host.calls() if c["argv"][:2] == ["compose", "up"]]
    assert ups and all(c["cwd"] == str(old.resolve()) for c in ups)
    assert f"The folder you ran this from ({new.resolve()}) is not used" in r.stdout
    # Secrets reach the engine on stdin only, and the daemon keeps no log
    # of an engine run.
    for value in SECRET_VALUES:
        assert all(value not in a for a in host.argvs()), value
    assert any(b"audit-123456" in i for i in host.engine_inputs())
    engine_runs = [c["argv"] for c in host.calls() if c["argv"][:1] == ["run"] and "-i" in c["argv"]]
    assert engine_runs and all("--log-driver" in a and a[a.index("--log-driver") + 1] == "none"
                               and "--network" in a and "--user" in a for a in engine_runs)


def test_new_folder_prompt_answered_no_changes_nothing(host, tmp_path):
    old = release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    before = tree_digest(old, new)
    r = run_installer(new, host=host, tty=True, answer="n",
                      env={"SIGRIFT_UPGRADE_PROMPT_SECONDS": "30"})
    assert r.returncode == 3, r.stdout
    assert "Upgrade it now? [Y/n] (continues in 30 s)" in r.stdout
    assert "Not upgraded: you answered no. Nothing was changed." in r.stdout
    assert tree_digest(old, new) == before and changing_calls(host) == []


def test_new_folder_prompt_times_out_to_yes(host, tmp_path):
    old = release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    r = run_installer(new, host=host, tty=True, env={"SIGRIFT_UPGRADE_PROMPT_SECONDS": "1"})
    assert r.returncode == 0, r.stdout
    assert "Upgrade it now?" in r.stdout and "SigRift v0.2.0 is up in" in r.stdout
    assert (old / "VERSION").read_text() == "v0.2.0\n"


def test_dry_run_prints_the_plan_and_changes_nothing(host, tmp_path):
    old = release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    before = tree_digest(old, new)
    r = run_installer(new, "--dry-run", host=host, tty=True,
                      env={"SIGRIFT_UPGRADE_PROMPT_SECONDS": "30"})
    assert r.returncode == 0, r.stdout
    assert "Upgrade it now?" not in r.stdout
    for needle in (f"target    {old.resolve()} (project sigrift-v010, pins "
                   "COMPOSE_PROJECT_NAME=sigrift-v010 on this first run)",
                   "version   v0.1.0 -> v0.2.0", "adds: BRIDGE_KEYSTORE_KEY",
                   "TOTP: 2 rows verify", "audit: chain verifies (40 entries)"):
        assert needle in r.stdout, r.stdout
    assert tree_digest(old, new) == before and changing_calls(host) == []


def test_new_folder_with_two_release_installs_is_refused_with_the_list(host, tmp_path):
    a = release_install(host, tmp_path, name="sigrift-v0.1.0")
    b = release_install(host, tmp_path, name="lab-release", port="8454")
    new = unpacked_release(tmp_path)
    r = run_installer(new, host=host)
    assert_refused(r, "this host runs 2 SigRift release installs",
                   f"sigrift-v010  v0.1.0, running, port 8444  {a.resolve()}",
                   f"lab-release  v0.1.0, running, port 8454  {b.resolve()}",
                   "Next: bash install-release.sh --upgrade <one of the folders above>")


def test_new_folder_beside_only_a_source_install_is_refused_with_a_free_port(host, tmp_path):
    src = with_source_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    r = run_installer(new, host=host)
    assert_refused(r, "already runs SigRift from a source checkout",
                   f"cd {src} && git pull && scripts/quickstart.sh",
                   "Next: UC_PORT=", "bash install-release.sh --new-instance")


def test_new_folder_with_data_of_an_unknown_folder_is_refused(host, tmp_path):
    host.add_project("sigrift-v010", None, containers=False, data={"users": 1})
    new = unpacked_release(tmp_path)
    r = run_installer(new, host=host)
    assert_refused(r, "SigRift data whose install folder is not known",
                   "sigrift-v010  volumes sigrift-v010_bridge_data, sigrift-v010_bridge_secrets; no containers",
                   "Next: bash install-release.sh --upgrade /path/to/that/folder")


def test_main_version_never_auto_targets(host, tmp_path):
    old = release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    (new / "VERSION").unlink()
    r = run_installer(new, host=host)
    assert_refused(r, "this installer has no release version",
                   f"Next: SIGRIFT_VERSION=vX.Y.Z bash install-release.sh --upgrade {old.resolve()}")


def test_upgrade_dir_names_the_install_and_refuses_a_source_checkout(host, tmp_path):
    old = release_install(host, tmp_path)
    src = with_source_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    r = run_installer(new, "--upgrade", str(src), host=host)
    assert_refused(r, f"{src} is a source checkout (quickstart install)",
                   f"Next: cd {src} && git pull && scripts/quickstart.sh")
    r = run_installer(new, "--upgrade", str(old), "--dry-run", host=host)
    assert r.returncode == 0, r.stderr
    assert f"target    {old.resolve()}" in r.stdout


# ── deliberate second stacks ────────────────────────────────────────────


@pytest.mark.parametrize("installer", ["release", "quickstart"])
def test_new_instance_needs_an_unused_project_and_a_free_port(host, tmp_path, installer):
    release_install(host, tmp_path)
    folder = (unpacked_release(tmp_path, name="second") if installer == "release"
              else source_checkout(tmp_path, "second"))
    port = free_port()
    flags = {"LC_NEW_INSTANCE": "1"}
    busy = identity(host, folder, installer, flags, env={"UC_PORT": "8444"})
    assert_refused(busy, "port 8444 is already in use (published by container sigrift-v010-gateway-1)",
                   "--new-instance")
    host.add_project("second", None, containers=False)
    taken = identity(host, folder, installer, flags, env={"UC_PORT": port})
    assert_refused(taken, "Docker Compose project second already exists on this host (data only)",
                   "Next: COMPOSE_PROJECT_NAME=second-2 ")
    host.load()
    host.state["volumes"] = [v for v in host.state["volumes"] if v["project"] != "second"]
    host.save()
    d = identity(host, folder, installer, flags, env={"UC_PORT": port})
    assert isinstance(d, dict), d.stderr
    assert d["LC_PROJECT"] == "second" and d["LC_PIN"] == "1" and d["LC_HAS_DATA"] == "0"


@pytest.mark.parametrize("installer", ["release", "quickstart"])
def test_explicit_shell_project_and_free_port_is_a_deliberate_second_stack(host, tmp_path, installer):
    release_install(host, tmp_path)
    folder = (unpacked_release(tmp_path, name="stage") if installer == "release"
              else source_checkout(tmp_path, "stage"))
    port = free_port()
    d = identity(host, folder, installer,
                 env={"COMPOSE_PROJECT_NAME": "sigrift-test-0a1b", "UC_PORT": port})
    assert isinstance(d, dict), d.stderr
    assert (d["LC_PROJECT"], d["LC_PROJECT_HOW"], d["LC_PIN"], d["LC_AUTO"]) == (
        "sigrift-test-0a1b", "shell", "1", "0")
    # The harness re-run: the shell and the pin agree.
    if installer == "quickstart":
        (folder / ".env").write_text("COMPOSE_PROJECT_NAME=sigrift-test-0a1b\n")
        d = identity(host, folder, installer,
                     env={"COMPOSE_PROJECT_NAME": "sigrift-test-0a1b", "UC_PORT": port})
        assert d["LC_PROJECT"] == "sigrift-test-0a1b" and d["LC_PIN"] == "0"


def test_shell_project_naming_a_release_install_targets_it(host, tmp_path):
    old = release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    d = identity(host, new, "release", env={"COMPOSE_PROJECT_NAME": "sigrift-v010"})
    assert d["LC_TARGET_DIR"] == str(old.resolve()) and d["LC_AUTO"] == "1"


def test_quickstart_fresh_run_beside_another_install_is_refused(host, tmp_path):
    release_install(host, tmp_path)
    d = source_checkout(tmp_path, "SigRift")
    before = tree_digest(d)
    r = run_installer(d, "--dashboard-only", host=host, script="scripts/quickstart.sh",
                      stdin="disposable-password\ndisposable-password\n")
    assert_refused(r, "a fresh quickstart here would start a second, empty stack",
                   "Next: UC_PORT=", "scripts/quickstart.sh --new-instance")
    assert "Admin password" not in r.stdout + r.stderr
    assert tree_digest(d) == before and changing_calls(host) == []


# ── refusals change nothing ─────────────────────────────────────────────


def scenario_marker(host, tmp_path):
    d = release_install(host, tmp_path, data={"restore_marker": True})
    return d, [], {}, "holds .sigrift-restore-incomplete, left by an interrupted restore"


def scenario_foreign_mount(host, tmp_path):
    d = release_install(host, tmp_path)
    host.load()
    host.state["containers"].append({
        "id": "f00f00f00f00", "name": "backup-helper", "project": "tools", "service": "copy",
        "working_dir": "", "state": "running", "image": "alpine", "env": {},
        "mounts": ["sigrift-v010_bridge_data"], "ports": ""})
    host.save()
    return d, [], {}, "container backup-helper (project tools) also mounts sigrift-v010_bridge_data"


def scenario_downgrade(host, tmp_path):
    d = release_install(host, tmp_path, version="v0.2.0", data={"schema": 56})
    return d, [], {"SIGRIFT_VERSION": "v0.1.0"}, \
        "v0.1.0 is older than the installed v0.2.0"


def scenario_rc_downgrade(host, tmp_path):
    d = release_install(host, tmp_path, version="v0.2.0")
    return d, [], {"SIGRIFT_VERSION": "v0.2.0-rc3"}, "v0.2.0-rc3 is older than the installed v0.2.0"


def scenario_schema(host, tmp_path):
    d = release_install(host, tmp_path, data={"schema": 59})
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.1.1", 56)
    return d, [], {"SIGRIFT_VERSION": "v0.1.1"}, \
        "the v0.1.1 bridge knows database migrations up to 56, but this install's database is at migration 59"


def scenario_shell_secret(host, tmp_path):
    d = release_install(host, tmp_path)
    return d, [], {"BRIDGE_AUDIT_KEY": "something-else"}, \
        "BRIDGE_AUDIT_KEY is set in your shell and differs from .env"


def scenario_unmanaged(host, tmp_path):
    d = release_install(host, tmp_path)
    (d / "docker-compose.yml").write_text(
        (d / "docker-compose.yml").read_text().replace("# Generated by install-release.sh", "# mine"))
    return d, [], {"SIGRIFT_VERSION": "v0.2.0"}, "Compose is not installer-managed"


def scenario_several(host, tmp_path):
    release_install(host, tmp_path, name="a-one")
    release_install(host, tmp_path, name="b-two", port="8454")
    return unpacked_release(tmp_path), [], {}, "this host runs 2 SigRift release installs"


def scenario_pull_failed(host, tmp_path):
    d = release_install(host, tmp_path)
    host.load()
    host.state["images"] = {}
    host.state["containers"] = []
    host.state["pull_rc_default"] = 1
    host.save()
    return d, [], {}, "could not pull ghcr.io/sigrift/sigrift-bridge:v0.1.0 (docker pull exited 1)"


def scenario_copy(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    copy = tmp_path / "sigrift-copy"
    shutil.copytree(d, copy)
    return copy, [], {}, "address the same Docker Compose project"


def scenario_renamed(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"totp_fernet": 0, "audit_rows": 0})
    return d, [], {}, "it looks like a folder renamed before this installer pinned it"


def scenario_env_missing(host, tmp_path):
    d = release_install(host, tmp_path)
    (d / ".env").unlink()
    return d, [], {}, "there is no .env here, but project sigrift-v010 has data"


def scenario_shell_mismatch(host, tmp_path):
    d = release_install(host, tmp_path, pinned=True)
    return d, [], {"COMPOSE_PROJECT_NAME": "other"}, "differs from the project pinned in .env"


def scenario_pin_ignored(host, tmp_path):
    d = release_install(host, tmp_path)
    host.update(compose_honours_env_file=False)
    return d, [], {}, "docker compose ignored COMPOSE_PROJECT_NAME"


def scenario_source_only(host, tmp_path):
    with_source_install(host, tmp_path)
    return unpacked_release(tmp_path), [], {}, "already runs SigRift from a source checkout"


def scenario_unknown_folder(host, tmp_path):
    host.add_project("sigrift-v010", None, containers=False)
    return unpacked_release(tmp_path), [], {}, "whose install folder is not known"


def scenario_needs_version(host, tmp_path):
    release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    (new / "VERSION").unlink()
    return new, [], {}, "this installer has no release version"


def scenario_second_stack(host, tmp_path):
    release_install(host, tmp_path)
    d = tmp_path / "sigrift-second"
    d.mkdir()
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    (d / ".env").write_text("BRIDGE_ENV=production\n")
    return d, [], {"SIGRIFT_VERSION": "v0.1.0"}, "this folder has no data yet"


def scenario_port_busy(host, tmp_path):
    release_install(host, tmp_path)
    return unpacked_release(tmp_path), ["--new-instance"], {"UC_PORT": "8444"}, \
        "port 8444 is already in use"


def scenario_project_taken(host, tmp_path):
    release_install(host, tmp_path)
    host.add_project("sigrift-v020", None, containers=False)
    return unpacked_release(tmp_path), ["--new-instance"], {"UC_PORT": free_port()}, \
        "Docker Compose project sigrift-v020 already exists"


def scenario_shell_project_taken(host, tmp_path):
    with_source_install(host, tmp_path)
    return unpacked_release(tmp_path), [], {"COMPOSE_PROJECT_NAME": "sigrift-src"}, \
        "COMPOSE_PROJECT_NAME=sigrift-src in your shell names an existing SigRift install"


def scenario_secret_differs(host, tmp_path):
    d = release_install(host, tmp_path, env=INSTALLED_ENV_B)
    host.load()
    for c in host.state["containers"]:
        c["env"]["BRIDGE_MFA_KEY"] = KEY_A
    host.save()
    return d, [], {}, "the data needs the running one"


def scenario_none_matches(host, tmp_path):
    d = release_install(host, tmp_path, env=INSTALLED_ENV_B, data={"mfa_key": KEY_C})
    host.load()
    for c in host.state["containers"]:
        c["env"]["BRIDGE_MFA_KEY"] = KEY_A
    host.save()
    return d, [], {}, "neither .env's BRIDGE_MFA_KEY nor the running bridge's verifies"


def scenario_mfa_missing(host, tmp_path):
    d = release_install(host, tmp_path, env=INSTALLED_ENV_NO_MFA, containers=False)
    return d, [], {}, "but 2 users' TOTP secrets are encrypted with one"


def scenario_bridge_gateway_differ(host, tmp_path):
    d = release_install(host, tmp_path)
    host.load()
    for c in host.state["containers"]:
        if c["service"] == "gateway":
            c["env"]["BRIDGE_MFA_KEY"] = KEY_B
    host.save()
    return d, [], {}, "the bridge and the gateway run with different BRIDGE_MFA_KEY values"


def scenario_adopt_mismatch(host, tmp_path):
    _, d = renamed(host, tmp_path, data={"mfa_key": KEY_B})
    return d, ["--adopt-project", "sigrift-v010"], {}, "do not match the data of project"


def scenario_source_target(host, tmp_path):
    src = with_source_install(host, tmp_path)
    return unpacked_release(tmp_path), ["--upgrade", str(src)], {}, "is a source checkout"


def scenario_not_installed(host, tmp_path):
    empty = tmp_path / "sigrift-empty"
    empty.mkdir()
    return unpacked_release(tmp_path), ["--upgrade", str(empty)], {}, "holds no SigRift install"


def scenario_none_matches_stopped(host, tmp_path):
    # Stopped with the same wrong key .env has: no bridge value verifies
    # the data (the upgrade would migrate first and fail its checks after).
    d = release_install(host, tmp_path, env=INSTALLED_ENV_B, running=False)
    return d, [], {}, ".env's BRIDGE_MFA_KEY does not verify this install's 2 TOTP secrets, " \
        "and no running bridge has one that does"


def scenario_none_matches_down(host, tmp_path):
    # Down (no containers): nothing ties the data to this folder but its name.
    d = release_install(host, tmp_path, env=INSTALLED_ENV_B, containers=False)
    return d, [], {}, "has data that this folder's .env does not match (BRIDGE_MFA_KEY does " \
        "not verify its TOTP secrets): either another install used this folder's name, or .env " \
        "no longer holds the key that data was written with"


def scenario_shell_unused_name(host, tmp_path):
    # Left over from working on a soak stack: an unused name in the shell
    # must not pin this folder's .env to new, empty volumes.
    d = release_install(host, tmp_path, running=False)
    return d, [], {"COMPOSE_PROJECT_NAME": "scratch-test", "UC_PORT": free_port()}, \
        "this folder's data is in project sigrift-v010"


def scenario_copy_of_a_down_stack(host, tmp_path):
    d = release_install(host, tmp_path, containers=False)
    copy = tmp_path / "sigrift-test"
    shutil.copytree(d, copy)
    return copy, [], {}, "No container or volume record names its last folder"


def scenario_main_with_shell_project(host, tmp_path):
    release_install(host, tmp_path)
    new = unpacked_release(tmp_path)
    (new / "VERSION").unlink()
    return new, [], {"COMPOSE_PROJECT_NAME": "sigrift-v010"}, \
        "this installer has no release version"


def scenario_name_collision(host, tmp_path):
    d = release_install(host, tmp_path, containers=False)
    moved = d.rename(tmp_path / "sigrift")
    # Another install's data, down, under the name the renamed folder gives.
    host.add_project("sigrift", None, containers=False,
                     data={"totp_fernet": 2, "mfa_key": KEY_C, "audit_rows": 9,
                           "audit_values": {"BRIDGE_AUDIT_KEY": "theirs"}})
    return moved, [], {}, "project sigrift, the one this folder's name gives, has data that " \
        "this folder's .env does not match (BRIDGE_MFA_KEY does not verify its TOTP secrets)"


def scenario_record_fingerprint(host, tmp_path):
    d, lab = renamed(host, tmp_path, containers=False)
    host.load()
    host.state["records"]["sigrift-v010_bridge_data"] = {
        "format": 1, "install_id": "1" * 8, "install_type": "release", "project": "sigrift-v010",
        "working_dir": str(d), "fingerprints": {"mfa": "0" * 32}}
    host.save()
    return lab, [], {}, "it looks like a folder renamed before this installer pinned it"


def scenario_source_orphan(host, tmp_path):
    src = source_checkout(tmp_path, "sigrift-src")
    host.add_project("sigrift-src", src, image="sigrift-src-bridge")
    src.rename(tmp_path / "gone-src")
    lab = tmp_path / "lab"
    lab.mkdir()
    shutil.copy(INSTALL_RELEASE, lab / "install-release.sh")
    (lab / ".env").write_text(INSTALLED_ENV)
    return lab, [], {"SIGRIFT_VERSION": "v0.1.0"}, \
        "it looks like a folder renamed before this installer pinned it"


def scenario_volume_audit_key(host, tmp_path):
    # The volume's own audit.key verifies its chain; this .env has no audit
    # key, so that proves nothing about this folder.
    no_audit = "".join(line + "\n" for line in INSTALLED_ENV.splitlines()
                       if not line.startswith(("BRIDGE_AUDIT_KEY=", "BRIDGE_MASTER_KEY=")))
    _, d = renamed(host, tmp_path, env=no_audit,
                   data={"totp_fernet": 0, "audit_values": {}, "audit_file": "dev-key"})
    return d, [], {}, ".env matches: TOTP key n.a., audit key yes"


def scenario_shell_names_another_folder(host, tmp_path):
    release_install(host, tmp_path)
    d = tmp_path / "sigrift-mine"
    d.mkdir()
    shutil.copy(INSTALL_RELEASE, d / "install-release.sh")
    (d / ".env").write_text("BRIDGE_ENV=production\n")
    return d, [], {"COMPOSE_PROJECT_NAME": "sigrift-v010", "SIGRIFT_VERSION": "v0.1.0"}, \
        "COMPOSE_PROJECT_NAME=sigrift-v010 in your shell names an existing SigRift install"


def scenario_record_only_folder(host, tmp_path):
    # The bridge and the gateway can write the volume record: a folder it
    # names is not a target until that folder's own records confirm it.
    d = release_install(host, tmp_path, containers=False)
    host.load()
    host.state["records"]["sigrift-v010_bridge_data"] = {
        "format": 1, "install_id": "2" * 8, "install_type": "release",
        "project": "sigrift-v010", "working_dir": str(d)}
    host.save()
    return unpacked_release(tmp_path), [], {}, "which does not confirm it"


def scenario_unsafe_folder(host, tmp_path):
    d = release_install(host, tmp_path)
    d.chmod(0o777)
    return unpacked_release(tmp_path), [], {}, \
        f"but every user on this host can change {d.resolve()}"


def scenario_unreadable_env(host, tmp_path):
    d = release_install(host, tmp_path)
    (d / ".env").write_bytes(b"BRIDGE_ENV=production\nUC_TLS_CERT=/app/tls/\xe9.pem\n")
    return d, [], {}, "exists but cannot be read as UTF-8 text"


def scenario_symlinked_env(host, tmp_path):
    d = release_install(host, tmp_path)
    (d / ".env").rename(tmp_path / "real.env")
    (d / ".env").symlink_to(tmp_path / "real.env")
    return d, [], {}, ".env is a symbolic link"


def scenario_shell_only_key(host, tmp_path):
    d = release_install(host, tmp_path, data={"crypto_keys": 2})
    return d, [], {"BRIDGE_KEYSTORE_KEY": KEY_C}, \
        ".env has no BRIDGE_KEYSTORE_KEY and only your shell sets one"


def scenario_owned_twice(host, tmp_path):
    d = release_install(host, tmp_path)
    host.add_project("relsoak", d, port="8454")
    return d, [], {}, "this folder's data could be in more than one Docker Compose project"


SCENARIOS = [scenario_marker, scenario_foreign_mount, scenario_downgrade, scenario_rc_downgrade,
             scenario_schema, scenario_shell_secret, scenario_unmanaged, scenario_several,
             scenario_pull_failed, scenario_copy, scenario_renamed, scenario_env_missing,
             scenario_shell_mismatch, scenario_pin_ignored, scenario_source_only,
             scenario_unknown_folder, scenario_needs_version, scenario_second_stack,
             scenario_port_busy, scenario_project_taken, scenario_shell_project_taken,
             scenario_secret_differs, scenario_none_matches, scenario_mfa_missing,
             scenario_bridge_gateway_differ, scenario_adopt_mismatch, scenario_source_target,
             scenario_not_installed, scenario_none_matches_stopped,
             scenario_none_matches_down, scenario_shell_unused_name,
             scenario_copy_of_a_down_stack, scenario_main_with_shell_project,
             scenario_name_collision, scenario_record_fingerprint, scenario_source_orphan,
             scenario_volume_audit_key, scenario_shell_names_another_folder,
             scenario_record_only_folder, scenario_unsafe_folder, scenario_unreadable_env,
             scenario_symlinked_env, scenario_shell_only_key, scenario_owned_twice]


def all_folders(tmp_path):
    return [p for p in tmp_path.iterdir() if p.is_dir() and p.name not in ("fake-docker", "fake-bin")]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.__name__[9:] for s in SCENARIOS])
def test_every_refusal_changes_nothing_and_starts_nothing(host, tmp_path, scenario):
    d, args, env, needle = scenario(host, tmp_path)
    before = tree_digest(*all_folders(tmp_path))
    host.clear_log()
    r = run_installer(d, *args, host=host, env=env)
    assert_refused(r, needle)
    assert tree_digest(*all_folders(tmp_path)) == before
    assert changing_calls(host) == []
    # No secret value reached docker's argv.
    for value in ("audit-123456", "master-123456", "proxy-123456", "correct-horse-battery",
                  KEY_A, KEY_B):
        assert all(value not in a for a in host.argvs())


def test_restore_marker_name_is_reserved_and_refused(host, tmp_path):
    for installer in (INSTALL_RELEASE, QUICKSTART):
        block = shared_block(installer, "identity")
        assert "\nLC_RESTORE_MARKER=.sigrift-restore-incomplete\n" in block
    engine = shared_block(INSTALL_RELEASE, "lifecycle-engine")
    assert 'MARKER = ".sigrift-restore-incomplete"' in engine
    d, _, _, needle = scenario_marker(host, tmp_path)
    r = run_installer(d, host=host)
    assert_refused(r, needle, "Next: bash install-release.sh --status")


def test_foreign_container_mounting_the_volumes_is_refused(host, tmp_path):
    d, _, _, needle = scenario_foreign_mount(host, tmp_path)
    r = run_installer(d, host=host)
    assert_refused(r, needle, "Next: docker stop backup-helper")


# ── which project a folder's own containers ran under ───────────────────


def test_an_install_started_under_a_shell_name_is_found_by_its_labels(host, tmp_path):
    # v0.1.0 started with COMPOSE_PROJECT_NAME=relsoak exported (a soak).
    d = release_install(host, tmp_path)
    host.load()
    host.state["volumes"] = [v for v in host.state["volumes"] if v["project"] != "sigrift-v010"]
    host.state["containers"] = [c for c in host.state["containers"] if c["project"] != "sigrift-v010"]
    host.save()
    host.add_project("relsoak", d, env=dict(line.split("=", 1) for line in INSTALLED_ENV.splitlines()),
                     data={"totp_fernet": 2, "mfa_key": KEY_A, "audit_rows": 40,
                           "audit_values": {"BRIDGE_AUDIT_KEY": "audit-123456"}})
    r = identity(host, d)
    assert isinstance(r, dict), r.stderr
    assert (r["LC_PROJECT"], r["LC_PROJECT_HOW"], r["LC_PIN"]) == ("relsoak", "labels", "1")
    new = unpacked_release(tmp_path)
    r = identity(host, new)
    assert isinstance(r, dict), r.stderr
    assert (r["LC_TARGET_DIR"], r["LC_PROJECT"], r["LC_AUTO"]) == (str(d.resolve()), "relsoak", "1")


def test_an_unused_shell_name_with_new_instance_is_a_deliberate_stack(host, tmp_path):
    d = release_install(host, tmp_path, running=False)
    port = free_port()
    (d / "docker-compose.yml").write_text(
        (d / "docker-compose.yml").read_text().replace(":8444:8444", f":{port}:8444"))
    r = identity(host, d, "release", {"LC_NEW_INSTANCE": "1"},
                 env={"COMPOSE_PROJECT_NAME": "scratch-test"})
    assert isinstance(r, dict), r.stderr
    assert (r["LC_PROJECT"], r["LC_PROJECT_HOW"], r["LC_HAS_DATA"]) == ("scratch-test", "shell", "0")


def test_a_down_stack_whose_folder_is_unknown_is_adopted_only_when_named(host, tmp_path):
    d = release_install(host, tmp_path, containers=False)
    lab = d.rename(tmp_path / "lab")
    r = identity(host, lab)
    assert_refused(r, "No container or volume record names its last folder",
                   "Next: bash install-release.sh --adopt-project sigrift-v010")
    r = identity(host, lab, "release", {"LC_ADOPT_PROJECT": "sigrift-v010"})
    assert isinstance(r, dict), r.stderr
    assert (r["LC_PROJECT"], r["LC_PROJECT_HOW"]) == ("sigrift-v010", "adopted")


def test_a_volume_record_confirmed_by_its_folder_makes_that_folder_the_target(host, tmp_path):
    d = release_install(host, tmp_path, containers=False)
    install_id = "3" * 8 + "-confirmed"
    host.load()
    host.state["records"]["sigrift-v010_bridge_data"] = {
        "format": 1, "install_id": install_id, "install_type": "release",
        "project": "sigrift-v010", "working_dir": str(d)}
    host.save()
    (d / ".sigrift").mkdir()
    (d / ".sigrift" / "install.json").write_text(json.dumps(
        {"format": 1, "install_id": install_id, "install_type": "release"}))
    r = identity(host, unpacked_release(tmp_path))
    assert isinstance(r, dict), r.stderr
    assert (r["LC_TARGET_DIR"], r["LC_AUTO"]) == (str(d.resolve()), "1")
    # A record of the wrong shape is no record at all.
    host.load()
    host.state["records"]["sigrift-v010_bridge_data"]["working_dir"] = ["/", "etc"]
    host.save()
    r = identity(host, tmp_path / "sigrift-v0.2.0")
    assert_refused(r, "whose install folder is not known")


def test_a_folder_inside_dockers_own_data_is_never_a_target(host, tmp_path):
    root = tmp_path / "docker-root"
    d = release_install(host, tmp_path, parent=root / "volumes" / "x_bridge_data" / "_data")
    host.update(docker_root=str(root))
    r = identity(host, unpacked_release(tmp_path))
    assert_refused(r, f"but it is inside Docker's own data folder ({root.resolve()})",
                   f"Next: bash install-release.sh --upgrade {d.resolve()}")


def test_folders_and_names_in_next_commands_are_quoted(host, tmp_path):
    import shlex

    d = release_install(host, tmp_path, name="my lab; touch PWNED")
    # A container whose project label Compose would never write.
    host.load()
    host.state["volumes"].append({"name": "Bad Name_bridge_data", "project": "Bad Name",
                                  "volume": "bridge_data"})
    host.save()
    new = unpacked_release(tmp_path)
    (new / "VERSION").unlink()
    r = identity(host, new, version="main")
    assert_refused(r, "this installer has no release version")
    nxt = r.stderr.rstrip().splitlines()[-2][len("Next: "):]
    words = shlex.split(nxt)
    assert words[-2:] == ["--upgrade", str(d.resolve())], nxt
    assert not (tmp_path / "PWNED").exists()
    # The invalid name is listed as such.
    r = run_installer(unpacked_release(tmp_path, name="other"), "--status", host=host)
    assert_refused(r, "Bad Name (invalid name)")


def test_quickstart_takes_both_adopt_project_forms(host, tmp_path):
    src = source_checkout(tmp_path, "sigrift-old",
                          env=INSTALLED_ENV + "SIGRIFT_QUICKSTART_MODE=dashboard-only\n")
    host.add_project("sigrift-old", src, image="sigrift-old-bridge",
                     env=dict(line.split("=", 1) for line in INSTALLED_ENV.splitlines()),
                     data={"totp_fernet": 0, "audit_rows": 0})
    lab = src.rename(tmp_path / "lab")
    r = identity(host, lab, "quickstart")
    # One orphan without proof: named with the form quickstart takes.
    assert_refused(r, "Next: scripts/quickstart.sh --adopt-project=sigrift-old")
    for bad in (["--adopt-project"], ["--adopt-project", "--new-instance"],
                ["--adopt-project", "a", "--adopt-project=b"]):
        r = run_installer(lab, *bad, host=host, script="scripts/quickstart.sh")
        assert r.returncode == 2, (bad, r.stderr)
    r = run_installer(lab, "--adopt-project", "sigrift-old", host=host,
                      script="scripts/quickstart.sh", stdin="")
    assert "==> Adopted project sigrift-old" in r.stdout, r.stdout + r.stderr
    assert env_of(lab)["COMPOSE_PROJECT_NAME"] == "sigrift-old"


def test_quickstart_ignores_a_port_exported_for_something_else(host, tmp_path):
    release_install(host, tmp_path)
    folder = source_checkout(tmp_path, "second")
    port = free_port()
    r = identity(host, folder, "quickstart", {"LC_NEW_INSTANCE": "1"},
                 env={"UC_PORT": port, "PORT": "8444"})
    assert isinstance(r, dict), r.stderr
    assert r["LC_PORT"] == port


def test_a_volume_record_with_another_fingerprint_blocks_adopt_project(host, tmp_path):
    lab, args, env, _ = scenario_record_fingerprint(host, tmp_path)
    r = identity(host, lab, "release", {"LC_ADOPT_PROJECT": "sigrift-v010"})
    assert_refused(r, "do not match the data of project sigrift-v010 (BRIDGE_MFA_KEY does not "
                      "match its volume record)")
