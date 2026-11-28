"""The .env rules of the installers (lc_tool env-merge and secrets-check).

An existing .env is never replaced. A missing key is added only where no
data depends on it; a data-bound one is restored from the running bridge
when the engine shows it matches the data; secrets that differ between
the running bridge, .env and the shell are refused unless the data shows
which one is right. Unit tests import the lifecycle-tool heredoc as a
module; the rest run the installer against FakeDockerHost.
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from lifecycle_fakes import (
    BASH,
    INSTALL_RELEASE,
    INSTALLED_ENV,
    KEY_A,
    KEY_B,
    QUICKSTART,
    ROOT,
    FakeDockerHost,
    load_lifecycle_tool,
    release_compose,
    release_install,
    run_installer,
)

TOOL = load_lifecycle_tool()


def have_compose() -> bool:
    return bool(shutil.which("docker")) and subprocess.run(
        ["docker", "compose", "version"], capture_output=True).returncode == 0


needs_compose = pytest.mark.skipif(not have_compose(), reason="docker compose not available")
# Installer runs against the fake host start many processes; slow CI
# runners need far more than the repo's 30 s default.
pytestmark = pytest.mark.timeout(240)


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


def facts(users=1, totp=0, audit_rows=0, crypto=0, env=None, container=None, schema=56, ok=True):
    return {"format": 1, "ok": ok, "db": {"encrypted": False, "schema": schema},
            "counts": {"users": users, "totp_fernet": totp, "audit_rows": audit_rows,
                       "crypto_keys": crypto},
            "candidates": {"env": env or {}, "container": container, "shell": None}}


def plan(tmp_path, text, *, installer="release", f=None, cenv=None, shell=None, **flags):
    path = tmp_path / ".env"
    path.write_text(text)
    flags.setdefault("has_data", f is not None)
    return TOOL.env_plan(str(path), installer, f, cenv or {}, shell or {}, flags)


def plan_sets(p):
    return {name: value for name, value, _, _ in p.sets}


def refusal(capsys, fn, *args, **kw):
    with pytest.raises(SystemExit) as e:
        fn(*args, **kw)
    assert e.value.code == 3
    err = capsys.readouterr().err
    assert err.rstrip().splitlines()[-1] == "Nothing was changed."
    return err


def effective(text):
    return TOOL.env_effective(text)


# ── classes and the parser ──────────────────────────────────────────────


def template_keys(path: Path) -> set:
    body = re.search(r'cat > "\$tmp_env" <<EOF\n(.*?)\nEOF\n', path.read_text(), re.S).group(1)
    return {line.split("=", 1)[0] for line in body.splitlines() if "=" in line and line[0] != "#"}


def test_every_env_key_has_a_class(tmp_path):
    keys = template_keys(INSTALL_RELEASE) | template_keys(QUICKSTART)
    example = (ROOT / ".env.example").read_text()
    keys |= set(re.findall(r"(?m)^#? ?([A-Z][A-Z0-9_]+)=", example))
    for text in ((ROOT / "docker-compose.yml").read_text(), release_compose(keystore=True)):
        keys |= set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", text))
    # Everything a merge can add, when every key is missing.
    p = plan(tmp_path, "", installer="quickstart", password="a-good-password")
    keys |= set(plan_sets(p))
    p = plan(tmp_path, "", pin="lab")
    keys |= set(plan_sets(p))
    missing = sorted(k for k in keys if k not in TOOL.KEY_CLASSES)
    assert missing == []
    assert set(TOOL.KEY_CLASSES.values()) == {
        "identity", "setting", "host", "data-bound", "regenerable", "bootstrap", "compose"}


CORPUS = [
    ("A=1\n", {"A": "1"}),
    ("export A=1\n", {"A": "1"}),
    ("A = 1 # comment\n", {"A": "1"}),
    ("A=1#not-a-comment\n", {"A": "1#not-a-comment"}),
    ("A='x # y'\n", {"A": "x # y"}),
    ('A="x # y" # tail\n', {"A": "x # y"}),
    ("A=1\nA=2\n", {"A": "2"}),
    ("A=1\r\nB=2\r\n", {"A": "1", "B": "2"}),
    ("A: colon\n", {"A": "colon"}),
    ("A=$HOME\n", {"A": None}),
    ('A="a\\nb"\n', {"A": None}),
    ("A='\n", {"A": None}),
    ("# A=1\n", {}),
]


@pytest.mark.parametrize("text,expected", CORPUS)
def test_env_parser_reads_like_repair_mfa_key(tmp_path, text, expected):
    assert effective(text) == expected
    # repair_mfa_key reads BRIDGE_MFA_KEY with the same loop: a value the
    # parser reads is the one repair_mfa_key leaves alone or repairs.
    mfa = text.replace("A", "BRIDGE_MFA_KEY").replace("BRIDGE_MFA_KEY=1", f"BRIDGE_MFA_KEY={KEY_A}")
    if effective(mfa).get("BRIDGE_MFA_KEY") == KEY_A:
        env = tmp_path / ".env"
        env.write_text(mfa)
        lib = tmp_path / "mfa.sh"
        src = INSTALL_RELEASE.read_text()
        lib.write_text(re.search(r"(?ms)^# >>> shared: mfa-key .*?^# <<< shared: mfa-key\n", src).group(0))
        r = subprocess.run([BASH, "-c", f'source "{lib}"; repair_mfa_key "{env}"'],
                           capture_output=True, text=True)
        assert r.returncode == 0 and r.stdout == "", r.stdout + r.stderr


@needs_compose
@pytest.mark.parametrize("text,expected", [c for c in CORPUS if None not in c[1].values()
                                            and "\r" not in c[0] and ":" not in c[0]])
def test_env_parser_agrees_with_compose(tmp_path, text, expected):
    (tmp_path / ".env").write_text(text)
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  x:\n    image: scratch\n    environment:\n      A: ${A:-unset}\n      B: ${B:-unset}\n")
    env = {k: v for k, v in os.environ.items() if k not in ("A", "B") and not k.startswith("COMPOSE_")}
    out = json.loads(subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=tmp_path,
                                    capture_output=True, text=True, env=env, check=True).stdout)
    got = out["services"]["x"]["environment"]
    for k, v in expected.items():
        assert got[k] == v


# ── what a merge adds ───────────────────────────────────────────────────


def test_existing_env_without_the_admin_password_line_is_kept(host, tmp_path):
    env = INSTALLED_ENV.replace("BRIDGE_ADMIN_PASSWORD=correct-horse-battery\n", "")
    d = release_install(host, tmp_path, env=env)
    r = run_installer(d, host=host, stdin="")
    assert r.returncode == 0, r.stderr
    assert "Admin password" not in r.stdout + r.stderr
    after = effective((d / ".env").read_text())
    for k, v in effective(env).items():
        assert after[k] == v, k
    assert "BRIDGE_ADMIN_PASSWORD" not in after
    # The quickstart rules are the same.
    p = plan(tmp_path, env, installer="quickstart", f=facts(users=2))
    assert not p.needs_password and "BRIDGE_ADMIN_PASSWORD" not in plan_sets(p)
    assert set(plan_sets(p)) == {"BRIDGE_LOCAL_NODE_KEY", "BRIDGE_KEYSTORE_KEY"}


def test_missing_admin_password_is_prompted_only_without_users(host, tmp_path):
    env = INSTALLED_ENV.replace("BRIDGE_ADMIN_PASSWORD=correct-horse-battery\n", "")
    assert plan(tmp_path, env, f=facts(users=0)).needs_password
    assert plan(tmp_path, env).needs_password  # no data at all
    assert not plan(tmp_path, env, f=facts(users=1)).needs_password
    assert not plan(tmp_path, env, f=None, has_data=True).needs_password  # unknown: assume users
    d = release_install(host, tmp_path, env=env, data={"users": 0, "totp_fernet": 0})
    r = run_installer(d, host=host, stdin="a-new-password-1\na-new-password-1\n")
    assert r.returncode == 0, r.stderr
    assert "This installer will create a local admin account." in r.stdout
    text = (d / ".env").read_text()
    assert '\nBRIDGE_ADMIN_PASSWORD="a-new-password-1"\n' in text
    assert effective(text)["BRIDGE_ADMIN_PASSWORD"] == "a-new-password-1"
    assert effective(text)["BRIDGE_MFA_KEY"] == KEY_A


def test_proxy_secret_is_always_added(tmp_path):
    for f in (None, facts(users=3, totp=2, audit_rows=9)):
        p = plan(tmp_path, f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\n", f=f)
        assert len(plan_sets(p)["UC_PROXY_SECRET"]) >= 32


def test_empty_assignment_is_replaced_in_place(tmp_path):
    text = f"BRIDGE_MFA_KEY={KEY_A}\nUC_PROXY_SECRET=\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MASTER_KEY=m\nBRIDGE_KEYSTORE_KEY=k\n"
    p = plan(tmp_path, text, f=facts())
    new = TOOL.render_plan(p, "release", "v0.2.0")
    lines = new.splitlines()
    assert lines[1].startswith("UC_PROXY_SECRET=") and len(lines[1]) > 40
    assert "# Added by" not in new


def test_master_key_is_added_only_with_an_audit_key(tmp_path):
    base = f"BRIDGE_MFA_KEY={KEY_A}\nUC_PROXY_SECRET=p\n"
    assert "BRIDGE_MASTER_KEY" in plan_sets(plan(tmp_path, base + "BRIDGE_AUDIT_KEY=a\n", f=facts()))
    assert "BRIDGE_MASTER_KEY" in plan_sets(plan(tmp_path, base + "BRIDGE_AUDIT_SECRET=a\n", f=facts()))
    # Without one, the master key derives the audit chain's key: not added
    # to a chain that has entries (and no audit key is added to it either).
    p = plan(tmp_path, base, f=facts(audit_rows=5))
    assert "BRIDGE_MASTER_KEY" not in plan_sets(p) and "BRIDGE_AUDIT_KEY" not in plan_sets(p)


def test_mfa_key_is_added_only_without_fernet_rows(tmp_path):
    for f in (None, facts(totp=0)):
        key = plan_sets(plan(tmp_path, "UC_PROXY_SECRET=p\n", f=f))["BRIDGE_MFA_KEY"]
        assert TOOL.mfa_valid(key)


def test_missing_mfa_key_with_fernet_rows_is_refused(tmp_path, capsys):
    err = refusal(capsys, plan, tmp_path, "UC_PROXY_SECRET=p\n", f=facts(totp=3))
    assert "Error: .env has no BRIDGE_MFA_KEY, but 3 users' TOTP secrets are encrypted with one" in err
    assert "Next: grep -l '^BRIDGE_MFA_KEY=' .env.bak.*~" in err
    err = refusal(capsys, plan, tmp_path, "UC_PROXY_SECRET=p\n", f=None, has_data=True)
    assert "could not read the database" in err


def test_audit_key_is_added_only_to_an_empty_audit_log(host, tmp_path):
    assert "BRIDGE_AUDIT_KEY" in plan_sets(plan(tmp_path, f"BRIDGE_MFA_KEY={KEY_A}\n", f=facts()))
    assert "BRIDGE_AUDIT_KEY" not in plan_sets(plan(tmp_path, f"BRIDGE_MFA_KEY={KEY_A}\n",
                                                    f=facts(audit_rows=7)))
    env = INSTALLED_ENV.replace("BRIDGE_AUDIT_KEY=audit-123456\n", "")
    d = release_install(host, tmp_path, env=env,
                        data={"audit_values": {"BRIDGE_MASTER_KEY": "master-123456"}})
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert "has no BRIDGE_AUDIT_KEY" in r.stderr
    assert "BRIDGE_AUDIT_KEY" not in effective((d / ".env").read_text())


def test_keystore_key_is_added_only_without_crypto_keys_rows(tmp_path, capsys):
    text = f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MASTER_KEY=m\nUC_PROXY_SECRET=p\n"
    for f in (None, facts(crypto=0)):
        p = plan(tmp_path, text, f=f)
        assert set(plan_sets(p)) == {"BRIDGE_KEYSTORE_KEY"}
        assert any("Added BRIDGE_KEYSTORE_KEY" in n for _, n in p.notes)
    p = plan(tmp_path, text, f=facts(crypto=4))
    assert "BRIDGE_KEYSTORE_KEY" not in plan_sets(p)
    assert any("the database holds 4 stored protocol keys" in n for _, n in p.notes)
    p = plan(tmp_path, text, f=None, has_data=True)
    assert "BRIDGE_KEYSTORE_KEY" not in plan_sets(p)
    assert any("BRIDGE_KEYSTORE_KEY was not added: the installer could not read the database" in n
               for _, n in p.notes)


def test_keystore_key_is_a_valid_fernet_key(tmp_path):
    for installer in (INSTALL_RELEASE, QUICKSTART):
        text = installer.read_text()
        assert re.search(r"^    KEYSTORE_KEY=\$\(fernet_key\)$", text, re.M)
        assert "BRIDGE_KEYSTORE_KEY=${KEYSTORE_KEY}\n" in text
    key = plan_sets(plan(tmp_path, "", f=None))["BRIDGE_KEYSTORE_KEY"]
    assert TOOL.mfa_valid(key) and len(base64.urlsafe_b64decode(key)) == 32
    fernet = pytest.importorskip("cryptography.fernet")
    fernet.Fernet(key.encode())


# ── the running bridge, .env and the shell ──────────────────────────────


def test_missing_key_is_restored_from_the_running_bridge_when_it_matches_the_data(host, tmp_path):
    env = INSTALLED_ENV.replace(f"BRIDGE_MFA_KEY={KEY_A}\n", "")
    d = release_install(host, tmp_path, env=env)
    host.load()
    for c in host.state["containers"]:
        c["env"]["BRIDGE_MFA_KEY"] = KEY_A
    host.save()
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert ("==> .env had no BRIDGE_MFA_KEY; restored the value the running bridge uses "
            "(2 TOTP secrets verify with it).") in r.stdout
    assert effective((d / ".env").read_text())["BRIDGE_MFA_KEY"] == KEY_A


def test_missing_key_is_not_restored_when_it_contradicts_the_data(tmp_path, capsys):
    f = facts(totp=2, container={"mfa": "fail"})
    err = refusal(capsys, plan, tmp_path, "BRIDGE_AUDIT_KEY=a\n", f=f,
                  cenv={"BRIDGE_MFA_KEY": KEY_B})
    assert "neither .env's BRIDGE_MFA_KEY nor the running bridge's verifies" in err


def differing(host, tmp_path, **data):
    env = INSTALLED_ENV.replace(KEY_A, KEY_B)
    d = release_install(host, tmp_path, env=env, data=data)
    host.load()
    for c in host.state["containers"]:
        c["env"]["BRIDGE_MFA_KEY"] = KEY_A
    host.save()
    return d


def test_secret_differing_from_the_running_bridge_is_refused_when_the_data_needs_it(host, tmp_path):
    d = differing(host, tmp_path)
    before = (d / ".env").read_bytes()
    r = run_installer(d, host=host)
    assert r.returncode == 3, r.stderr
    assert ("Error: the running bridge uses a different BRIDGE_MFA_KEY than .env, and the data "
            "needs the running one (2 TOTP secrets verify with it, none with .env's). Starting "
            "from .env would lock those users out of MFA.") in r.stderr
    assert "Next: bash install-release.sh --keep-running-secrets" in r.stderr
    assert KEY_A not in r.stderr + r.stdout and KEY_B not in r.stderr + r.stdout
    assert (d / ".env").read_bytes() == before


def test_secret_differing_from_the_running_bridge_is_noted_when_no_data_depends_on_it(host, tmp_path):
    d = differing(host, tmp_path, totp_fernet=0)
    r = run_installer(d, host=host)
    assert r.returncode == 0, r.stderr
    assert ("NOTE: the running bridge uses another BRIDGE_MFA_KEY than .env; no data depends on "
            "it, so this run starts the stack with .env's value.") in r.stderr
    assert effective((d / ".env").read_text())["BRIDGE_MFA_KEY"] == KEY_B


def test_keep_running_secrets_writes_the_running_values(host, tmp_path):
    d = differing(host, tmp_path)
    r = run_installer(d, "--keep-running-secrets", host=host)
    assert r.returncode == 0, r.stderr
    assert "BRIDGE_MFA_KEY now holds the value the running bridge uses" in r.stdout
    assert effective((d / ".env").read_text())["BRIDGE_MFA_KEY"] == KEY_A
    assert len(list(d.glob(".env.bak.*~"))) == 1


def test_shell_secret_differing_from_env_is_refused(tmp_path, capsys, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\n")
    monkeypatch.setenv("BRIDGE_MFA_KEY", KEY_B)
    err = refusal(capsys, TOOL.check_secrets, str(env), "", "", None, False, False,
                  "bash install-release.sh")
    assert "BRIDGE_MFA_KEY is set in your shell and differs from .env" in err
    assert "Next: unset BRIDGE_MFA_KEY && bash install-release.sh" in err
    # The same key in other spelling (decoded bytes) is not a difference.
    monkeypatch.setenv("BRIDGE_MFA_KEY", KEY_A.replace("-", "+").replace("_", "/"))
    TOOL.check_secrets(str(env), "", "", None, False, False, "bash install-release.sh")


def test_bridge_and_gateway_with_different_keys_are_refused(host, tmp_path):
    d = release_install(host, tmp_path)
    host.load()
    for c in host.state["containers"]:
        if c["service"] == "gateway":
            c["env"]["BRIDGE_AUDIT_KEY"] = "another-audit-key"
    host.save()
    r = run_installer(d, host=host)
    assert r.returncode == 3, r.stderr
    assert ("Error: the bridge and the gateway run with different BRIDGE_AUDIT_KEY values, so "
            "the stack is already inconsistent.") in r.stderr
    # .env holds the bridge's value: recreating both from it is right.
    assert "Recreate both containers from .env (.env holds the bridge's value)." in r.stderr
    assert "Next: docker compose up -d --force-recreate" in r.stderr


def test_unknown_keys_are_kept_and_named(tmp_path):
    text = f"BRIDGE_MFA_KEY={KEY_A}\nMY_SETTING=1\nOTHER=2\n"
    p = plan(tmp_path, text, f=facts())
    assert any("NOTE: .env keeps keys this installer does not use: MY_SETTING, OTHER." == n
               for _, n in p.notes)
    new = TOOL.render_plan(p, "release", "v0.2.0")
    assert "MY_SETTING=1\nOTHER=2\n" in new


def test_one_0600_backup_per_run_keeps_export_quotes_and_comments(tmp_path):
    text = (f"# my notes\nexport BRIDGE_MFA_KEY={KEY_A}  # mfa\nexport UC_PROXY_SECRET=\"\"  # proxy\n"
            "BRIDGE_AUDIT_KEY='a b' # quoted\nBRIDGE_ADMIN_PASSWORD=x\n")
    path = tmp_path / ".env"
    path.write_text(text)
    path.chmod(0o600)
    r = subprocess.run(
        [BASH, "-c", 'source "$1"; lc_tool env-merge --env-file .env --installer release '
                     '--version v0.2.0 --has-data 0 --pin lab',
         "x", str(blocks(tmp_path))], capture_output=True, text=True, cwd=tmp_path,
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)})
    assert r.returncode == 0, r.stderr
    backups = list(tmp_path.glob(".env.bak.*~"))
    assert len(backups) == 1 and backups[0].read_text() == text
    assert stat.S_IMODE(backups[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    new = path.read_text()
    assert new.startswith(f"# my notes\nexport BRIDGE_MFA_KEY={KEY_A}  # mfa\nexport UC_PROXY_SECRET=")
    assert re.search(r"(?m)^export UC_PROXY_SECRET=[A-Za-z0-9_-]{40,}  # proxy$", new)
    assert "BRIDGE_AUDIT_KEY='a b' # quoted\n" in new
    assert "\nCOMPOSE_PROJECT_NAME=lab\n" in new
    assert "LC_ENV_RESULT=" in r.stdout
    # Docker compose reads every value back unchanged.
    eff = effective(new)
    assert eff["BRIDGE_AUDIT_KEY"] == "a b" and eff["BRIDGE_MFA_KEY"] == KEY_A


def blocks(tmp_path: Path) -> Path:
    from lifecycle_fakes import shared_block

    lib = tmp_path / "lc-blocks.sh"
    lib.write_text("".join(shared_block(INSTALL_RELEASE, n) for n in (
        "tls-key-perms", "lifecycle-tool", "lifecycle-engine", "identity", "preflight")))
    return lib


# ── config migrations ───────────────────────────────────────────────────


def test_config_migrations_apply_once_in_order(tmp_path, monkeypatch):
    table = [
        {"id": "cm-t1", "since": "v0.1.0", "kind": "rename", "old": "OLD_NAME", "new": "UC_CSP_MODE"},
        {"id": "cm-t2", "since": "v0.1.0", "kind": "default", "key": "UC_CSP_MODE",
         "when": ["report-only"], "new": "strict", "why": "a test default"},
        {"id": "cm-t3", "since": "v0.1.0", "kind": "note", "key": "UC_CSP_MODE", "text": "noted"},
        {"id": "cm-t4", "since": "v9.0.0", "kind": "default", "key": "UC_CSP_MODE",
         "when": ["strict"], "new": "disabled", "why": "a future default"},
    ]
    monkeypatch.setattr(TOOL, "CONFIG_MIGRATIONS", table)
    text = f"BRIDGE_MFA_KEY={KEY_A}\nOLD_NAME=report-only\n"
    p = plan(tmp_path, text, f=facts(), version="v0.2.0")
    assert p.cm == ["cm-t1", "cm-t2"]
    new = TOOL.render_plan(p, "release", "v0.2.0")
    assert "UC_CSP_MODE=strict\n" in new and "OLD_NAME" not in new
    assert any(n == "NOTE: .env: cm-t3: noted" for _, n in p.notes)
    again = plan(tmp_path, new, f=facts(), version="v0.2.0")
    assert again.cm == [] and plan_sets(again) == {}


def test_cm_0001_replaces_the_old_public_proxy_secret(tmp_path):
    text = (f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MASTER_KEY=m\n"
            "BRIDGE_KEYSTORE_KEY=" + KEY_B + "\nUC_PROXY_SECRET=uppercrust-internal\n")
    # From the release that brings the guarded upgrade (v0.2.0).
    p = plan(tmp_path, text, f=facts(), version="v0.2.0")
    assert p.cm == ["cm-0001"]
    assert plan_sets(p)["UC_PROXY_SECRET"] != "uppercrust-internal"
    assert any("cm-0001: replaced UC_PROXY_SECRET=uppercrust-internal (the old public default, "
               "which the bridge refuses (it stays unhealthy)) with a random secret" in n
               for _, n in p.notes)
    assert plan(tmp_path, text, f=facts(), version="v0.1.0").cm == []
    assert plan(tmp_path, text, f=facts(), version="v0.1.9").cm == []
    assert plan(tmp_path, text, f=facts(), version="v0.2.0-rc2").cm == []
    assert plan(tmp_path, text, f=facts(), version="main").cm == ["cm-0001"]


def test_config_migrations_are_recorded_in_the_host_record(host, tmp_path):
    env = INSTALLED_ENV.replace("UC_PROXY_SECRET=proxy-123456", "UC_PROXY_SECRET=uppercrust-internal")
    d = release_install(host, tmp_path, env=env)
    host.add_image("ghcr.io/sigrift/sigrift-bridge:v0.2.0")
    r = run_installer(d, host=host, env={"SIGRIFT_VERSION": "v0.2.0"})
    assert r.returncode == 0, r.stderr
    assert "==> .env: cm-0001: replaced UC_PROXY_SECRET=uppercrust-internal" in r.stdout
    record = json.loads((d / ".sigrift" / "install.json").read_text())
    assert record["config_migrations"] == ["cm-0001"]
    assert record["history"][-1]["op"] == "upgrade"
    assert effective((d / ".env").read_text())["UC_PROXY_SECRET"] != "uppercrust-internal"


# ── compose files and BRIDGE_KEYSTORE_KEY ───────────────────────────────


@needs_compose
@pytest.mark.parametrize("which", ["docker-compose.yml", "install-release.sh"])
def test_generated_compose_files_pass_the_keystore_key_to_the_bridge_only(tmp_path, which):
    if which == "docker-compose.yml":
        shutil.copy(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    else:
        (tmp_path / "docker-compose.yml").write_text(release_compose(keystore=True))
    (tmp_path / ".env").write_text(f"BRIDGE_KEYSTORE_KEY={KEY_B}\n")
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("COMPOSE_", "BRIDGE_", "SIGRIFT_", "UC_"))}
    out = subprocess.run(["docker", "compose", "config", "--format", "json"], cwd=tmp_path,
                         capture_output=True, text=True, env=env, check=True).stdout
    services = json.loads(out)["services"]
    assert services["bridge"]["environment"]["BRIDGE_KEYSTORE_KEY"] == KEY_B
    for name, svc in services.items():
        if name != "bridge":
            assert "BRIDGE_KEYSTORE_KEY" not in (svc.get("environment") or {}), name


def check_gateway_env(compose: Path):
    text = INSTALL_RELEASE.read_text()
    fn = re.search(r"^check_compose_gateway_env\(\) \{\n.*?^\}\n", text, re.S | re.M).group(0)
    return subprocess.run([BASH, "-c", fn + f'check_compose_gateway_env "{compose}"'],
                          capture_output=True, text=True, cwd=compose.parent)


def test_old_compose_without_the_keystore_key_gets_a_note(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(release_compose(keystore=False))
    r = check_gateway_env(compose)
    assert "NOTE: the bridge service in" in r.stderr
    assert "imported protocol decryption keys stay in memory only" in r.stderr
    assert "- BRIDGE_KEYSTORE_KEY=${BRIDGE_KEYSTORE_KEY:-}" in r.stderr
    compose.write_text(release_compose(keystore=True))
    assert check_gateway_env(compose).stderr == ""
    bad = release_compose(keystore=True).replace(
        "      - UC_TLS_CERT=", "      - BRIDGE_KEYSTORE_KEY=${BRIDGE_KEYSTORE_KEY:-}\n      - UC_TLS_CERT=")
    compose.write_text(bad)
    assert "passes BRIDGE_KEYSTORE_KEY to the gateway service" in check_gateway_env(compose).stderr


# ── facts the engine could not establish ────────────────────────────────


def unreadable(kind="error", **cands):
    f = facts(**cands)
    f["counts"] = dict((k, None) for k in ("users", "totp_fernet", "audit_rows", "crypto_keys"))
    if kind == "encrypted":
        f["db"]["encrypted"] = True
    else:
        f["db"]["error"] = "DatabaseError: database disk image is malformed"
    return f


@pytest.mark.parametrize("kind", ["encrypted", "error"])
def test_unknown_counts_generate_no_data_bound_key(tmp_path, capsys, kind):
    text = f"BRIDGE_MFA_KEY={KEY_A}\nUC_PROXY_SECRET=p\nBRIDGE_ADMIN_USER=admin\n"
    p = plan(tmp_path, text, f=unreadable(kind))
    sets = plan_sets(p)
    # No audit key under entries that may exist, no keystore key under
    # stored protocol keys, no admin password prompt over existing users.
    assert "BRIDGE_AUDIT_KEY" not in sets and "BRIDGE_KEYSTORE_KEY" not in sets
    assert "BRIDGE_MASTER_KEY" not in sets and not p.needs_password
    why = "it is encrypted" if kind == "encrypted" else "DatabaseError: database disk image"
    assert any("BRIDGE_KEYSTORE_KEY was not added" in n and why in n for _, n in p.notes), p.notes
    # And no new MFA key over TOTP secrets that may exist.
    err = refusal(capsys, plan, tmp_path, "UC_PROXY_SECRET=p\n", f=unreadable(kind))
    assert "could not read the database to tell whether TOTP secrets are encrypted" in err


def test_a_value_that_differs_over_unreadable_data_is_never_waved_through(tmp_path, capsys):
    # With the counts unknown, "no data depends on it" cannot be said.
    assert TOOL.depends("BRIDGE_MFA_KEY", unreadable(), True) == "unknown"
    assert TOOL.depends("BRIDGE_AUDIT_KEY", unreadable("encrypted"), True) == "unknown"
    err = refusal(capsys, plan, tmp_path, f"BRIDGE_MFA_KEY={KEY_B}\nBRIDGE_AUDIT_KEY=a\n",
                  f=unreadable(), cenv={"BRIDGE_MFA_KEY": KEY_A})
    assert "the installer cannot check which one this install's data needs" in err
    assert "Next: bash install-release.sh --keep-running-secrets" in err


def test_unverifiable_keys_come_from_the_running_bridge_only(tmp_path, capsys):
    text = f"BRIDGE_MFA_KEY={KEY_A}\nBRIDGE_AUDIT_KEY=a\nBRIDGE_MASTER_KEY=m\nUC_PROXY_SECRET=p\n"
    f = facts(crypto=3)
    p = plan(tmp_path, text, f=f, cenv={"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert plan_sets(p)["BRIDGE_KEYSTORE_KEY"] == KEY_B
    assert any("restored the value the running bridge uses (the running bridge uses it; the "
               "installer could not check it against the data)" in n for _, n in p.notes)
    # Only the shell has it: it stays out of .env.
    err = refusal(capsys, plan, tmp_path, text, f=f, shell={"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert ".env has no BRIDGE_KEYSTORE_KEY and only your shell sets one" in err
    assert "Next: grep -c '^BRIDGE_KEYSTORE_KEY=' .env" in err
    # With no stored key there is nothing to check: the shell's goes in.
    p = plan(tmp_path, text, f=facts(crypto=0), shell={"BRIDGE_KEYSTORE_KEY": KEY_B})
    assert plan_sets(p)["BRIDGE_KEYSTORE_KEY"] == KEY_B


def test_bridge_value_the_data_needs_makes_keep_running_the_next_command(host, tmp_path):
    d = release_install(host, tmp_path, env=INSTALLED_ENV.replace(KEY_A, KEY_B))
    host.load()
    for c in host.state["containers"]:
        c["env"]["BRIDGE_MFA_KEY"] = KEY_A if c["service"] == "bridge" else KEY_B
    host.save()
    r = run_installer(d, host=host)
    assert r.returncode == 3, r.stderr
    assert "the bridge and the gateway run with different BRIDGE_MFA_KEY values" in r.stderr
    assert "The bridge's value is the one the data verifies with" in r.stderr
    assert r.stderr.rstrip().splitlines()[-2] == \
        "Next: bash install-release.sh --keep-running-secrets"
    r = run_installer(d, "--keep-running-secrets", host=host)
    assert r.returncode == 0, r.stdout + r.stderr
    assert effective((d / ".env").read_text())["BRIDGE_MFA_KEY"] == KEY_A
    gateway = [c for c in host.load()["containers"] if c["service"] == "gateway"][0]
    assert gateway["env"]["BRIDGE_MFA_KEY"] == KEY_A


def test_phase_3_settings_have_a_class():
    assert TOOL.KEY_CLASSES["BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP"] == "setting"


def test_unreadable_env_is_refused_not_read_as_empty(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("BRIDGE_ENV=production\n")
    env.chmod(0)
    try:
        if os.access(env, os.R_OK):
            pytest.skip("running as root")
        err = refusal(capsys, TOOL.env_plan, str(env), "release", None, {}, {}, {})
        assert "exists but cannot be read as UTF-8 text" in err
    finally:
        env.chmod(0o600)


def test_a_root_run_keeps_the_owner_of_what_it_rewrites(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("A=1\n")
    st = env.stat()
    calls = []
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fchown", lambda fd, uid, gid: calls.append(("fd", uid, gid)))
    monkeypatch.setattr(os, "lchown", lambda path, uid, gid: calls.append((str(path), uid, gid)))
    TOOL.write_new_text(str(env), "A=1\n", "A=2\n")
    assert calls == [("fd", st.st_uid, st.st_gid)] * 2  # the backup and the new file
    calls.clear()
    TOOL.ensure_state_dir(str(tmp_path))
    assert calls == [(str(tmp_path / ".sigrift"), st.st_uid, st.st_gid)]
    calls.clear()
    TOOL.atomic_write(str(tmp_path / ".sigrift" / "journal.json"), b"{}", 0o600)
    assert calls == [("fd", st.st_uid, st.st_gid)]
