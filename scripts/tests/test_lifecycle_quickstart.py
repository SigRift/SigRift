"""scripts/quickstart.sh's own use of the lifecycle blocks, run end to end.

Quickstart runs for real against FakeDockerHost (lifecycle_fakes.py) as far
as its .env, pin and identity steps go; later steps (building images, the
smoke test) fail against the fake and are not what these tests look at.
What they must show: an existing .env is never replaced (the old keep-test
was only a BRIDGE_ADMIN_PASSWORD= line), a new one is pinned, a secret the
data contradicts is refused before anything else happens, and each
lifecycle flag changes the decision.
"""

from __future__ import annotations

import socket

import pytest

from lifecycle_fakes import (
    INSTALLED_ENV,
    KEY_A,
    KEY_B,
    FakeDockerHost,
    changing_calls,
    release_install,
    run_installer,
    source_checkout,
    tree_digest,
)

pytestmark = pytest.mark.timeout(240)
QUICKSTART = "scripts/quickstart.sh"
DASHBOARD = "SIGRIFT_QUICKSTART_MODE=dashboard-only\n"
NO_PASSWORD = "".join(line + "\n" for line in INSTALLED_ENV.splitlines()
                      if not line.startswith("BRIDGE_ADMIN_PASSWORD="))
PASSWORD = "a-good-password\na-good-password\n"


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


def env_values(folder):
    out = {}
    for line in (folder / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k] = v
    return out


def free_port() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return str(port)


def checkout_with_data(host, tmp_path, env, container_env=None, **data):
    d = source_checkout(tmp_path, "SigRift", env=env)
    model = {"users": 1, "totp_fernet": 2, "mfa_key": KEY_A, "audit_rows": 40,
             "audit_values": {"BRIDGE_AUDIT_KEY": "audit-123456"}, "schema": 56}
    model.update(data)
    cenv = container_env or dict(line.split("=", 1) for line in env.splitlines() if "=" in line)
    host.add_project("sigrift", d, image="sigrift-bridge", env=cenv, data=model)
    return d


def test_an_env_without_the_admin_password_line_keeps_every_secret(host, tmp_path):
    d = checkout_with_data(host, tmp_path, NO_PASSWORD + DASHBOARD)
    before = env_values(d)
    r = run_installer(d, host=host, script=QUICKSTART, stdin=PASSWORD)
    out = r.stdout + r.stderr
    assert "Admin password" not in out and "Wrote .env" not in out, out
    after = env_values(d)
    # Kept as they were; only the keys nothing depends on were added.
    assert {k: after[k] for k in before} == before
    assert sorted(set(after) - set(before)) == [
        "BRIDGE_KEYSTORE_KEY", "BRIDGE_LOCAL_NODE_KEY", "COMPOSE_PROJECT_NAME"]
    assert after["COMPOSE_PROJECT_NAME"] == "sigrift"
    assert len(list(d.glob(".env.bak.*~"))) == 1


def test_a_fresh_checkout_gets_its_project_pinned(host, tmp_path):
    d = source_checkout(tmp_path, "SigRift")
    r = run_installer(d, "--dashboard-only", host=host, script=QUICKSTART, stdin=PASSWORD)
    assert "==> Wrote .env (chmod 600)" in r.stdout, r.stdout + r.stderr
    assert env_values(d)["COMPOSE_PROJECT_NAME"] == "sigrift"


def test_a_secret_the_data_contradicts_is_refused_before_anything_else(host, tmp_path):
    d = checkout_with_data(host, tmp_path, INSTALLED_ENV.replace(KEY_A, KEY_B) + DASHBOARD,
                           container_env=dict(line.split("=", 1)
                                              for line in INSTALLED_ENV.splitlines()))
    before = tree_digest(d)
    r = run_installer(d, "--scanners=none", host=host, script=QUICKSTART)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "the running bridge uses a different BRIDGE_MFA_KEY than .env, and the data needs " \
        "the running one" in r.stderr
    assert r.stderr.rstrip().splitlines()[-2:] == [
        "Next: scripts/quickstart.sh --keep-running-secrets", "Nothing was changed."]
    assert "==>" not in r.stdout.replace("==> Quickstart mode", "")
    assert tree_digest(d) == before and changing_calls(host) == []
    # --keep-running-secrets takes the running bridge's value.
    r = run_installer(d, "--keep-running-secrets", host=host, script=QUICKSTART)
    assert "BRIDGE_MFA_KEY now holds the value the running bridge uses" in r.stdout, r.stderr
    assert env_values(d)["BRIDGE_MFA_KEY"] == KEY_A


def test_new_instance_beside_another_install_starts_a_separate_stack(host, tmp_path):
    release_install(host, tmp_path)
    d = source_checkout(tmp_path, "second")
    r = run_installer(d, "--dashboard-only", host=host, script=QUICKSTART, stdin=PASSWORD)
    assert r.returncode == 3 and "a fresh quickstart here would start a second" in r.stderr
    r = run_installer(d, "--dashboard-only", "--new-instance", host=host, script=QUICKSTART,
                      stdin=PASSWORD, env={"UC_PORT": free_port()})
    assert "==> Wrote .env (chmod 600)" in r.stdout, r.stdout + r.stderr
    assert env_values(d)["COMPOSE_PROJECT_NAME"] == "second"


def test_adopt_project_takes_a_renamed_checkouts_data(host, tmp_path):
    d = checkout_with_data(host, tmp_path, INSTALLED_ENV + DASHBOARD, totp_fernet=0, audit_rows=0)
    lab = d.rename(tmp_path / "lab")
    r = run_installer(lab, host=host, script=QUICKSTART)
    assert r.returncode == 3 and "Next: scripts/quickstart.sh --adopt-project=sigrift" in r.stderr
    r = run_installer(lab, "--adopt-project=sigrift", host=host, script=QUICKSTART)
    assert "==> Adopted project sigrift" in r.stdout, r.stdout + r.stderr
    assert env_values(lab)["COMPOSE_PROJECT_NAME"] == "sigrift"
