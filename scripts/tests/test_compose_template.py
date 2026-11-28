"""Compose regeneration on upgrade (phase1b-spec 4.9, 11.4).

The pinned table LC_COMPOSE_TEMPLATES must name the canonical hash of every
template this installer can regenerate from, the last entry being the
heredoc of release_write_compose itself; release_switch_compose regenerates
an unedited installer file for a release at or above LC_TEMPLATE_SINCE and
keeps everything else tag-only. Runs against the fake docker host.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

from lifecycle_fakes import (
    BASH,
    INSTALL_RELEASE,
    FakeDockerHost,
    load_state_tool,
    shared_block,
)

ROOT = Path(__file__).resolve().parents[2]
V010 = ROOT / "scripts" / "tests" / "fixtures" / "install-release-v0.1.0.sh"
TEXT = INSTALL_RELEASE.read_text()
TOOL = load_state_tool()


def heredoc(path: Path) -> str:
    return re.search(r"cat > docker-compose\.yml <<EOF\n(.*?)\nEOF\n", path.read_text(),
                     re.S).group(1)


def render(path: Path, version, owner="sigrift", port="8444", policy=None) -> str:
    pre = "LC_PULL_POLICY=%s\n" % policy if policy else ""
    r = subprocess.run([BASH, "-c", "%sVERSION=%s OWNER=%s PORT=%s\ncat <<EOF\n%s\nEOF\n"
                        % (pre, version, owner, port, heredoc(path))],
                       capture_output=True, text=True, check=True)
    return r.stdout


def table() -> list:
    m = re.search(r'^LC_COMPOSE_TEMPLATES="([^"]*)"$', TEXT, re.M)
    return [tuple(x.split(":", 1)) for x in m.group(1).split()]


def function(name: str) -> str:
    return re.search(r"(?ms)^%s\(\) \{\n.*?^\}\n" % re.escape(name), TEXT).group(0)


VARIANTS = [("v0.1.0", "sigrift", "8444"), ("v0.2.0-rc3", "acme-labs", "9555"),
            ("main-abc1234", "sigrift", "1")]


@pytest.mark.parametrize("version, owner, port", VARIANTS)
def test_v010_template_canonical_hash_is_pinned(version, owner, port):
    c = TOOL.compose_canon(render(V010, version, owner, port),
                           " ".join("%s:%s" % e for e in table()))
    assert table()[0][0] == "t0-v0.1.0" and c["sha256"] == table()[0][1]
    assert (c["template"], c["owner"], c["port"]) == ("t0-v0.1.0", owner, port)


@pytest.mark.parametrize("version, owner, port", VARIANTS)
def test_current_template_hash_is_the_last_table_entry(version, owner, port):
    for policy in (None, "missing"):
        c = TOOL.compose_canon(render(INSTALL_RELEASE, version, owner, port, policy))
        assert c["sha256"] == table()[-1][1], "the heredoc changed: append its hash"


def test_canon_refuses_other_files():
    text = render(INSTALL_RELEASE, "v0.2.0")
    assert TOOL.compose_canon("services: {}\n")["template"] == "not-installer"
    mixed = text.replace("sigrift-gateway:v0.2.0", "sigrift-gateway:v0.1.9")
    assert TOOL.compose_canon(mixed, "t1:%s" % table()[-1][1])["template"] == "custom"
    edited = text.replace("      - BRIDGE_SECRETS_DIR=/app/secrets\n",
                          "      - BRIDGE_SECRETS_DIR=/app/secrets\n      - EXTRA=1\n")
    assert TOOL.compose_canon(edited, "t1:%s" % table()[-1][1])["template"] == "custom"


@pytest.fixture
def host(tmp_path):
    return FakeDockerHost(tmp_path)


def switch(host, folder: Path, version, *extra):
    names = ("release_write_compose", "release_render_compose", "release_validate_compose",
             "release_switch_compose", "update_release_images", "check_compose_gateway_env")
    script = "\n".join([shared_block(INSTALL_RELEASE, "state-tool"),
                        "lc_tool() { return 1; }"] + [function(n) for n in names] + [
        re.search(r'^LC_COMPOSE_TEMPLATES=.*$', TEXT, re.M).group(0),
        re.search(r'^LC_TEMPLATE_SINCE=.*$', TEXT, re.M).group(0),
        'VERSION=%s OWNER=sigrift PORT=8444' % version,
        'release_switch_compose docker-compose.yml %s' % " ".join(extra),
        'echo "SHA=${LC_COMPOSE_TEMPLATE_SHA256:-}"'])
    return subprocess.run([BASH, "-c", script], cwd=folder, capture_output=True, text=True,
                          env=host.env())


def folder_with(tmp_path, text, override=True):
    d = tmp_path / "inst"
    d.mkdir()
    (d / "docker-compose.yml").write_text(text)
    (d / ".env").write_text("UC_PROXY_SECRET=p\n")
    if override:
        (d / "docker-compose.override.yml").write_text("services:\n  gateway: {}\n")
    return d


def test_regeneration_keeps_owner_and_port_backs_up_and_validates(host, tmp_path):
    old = render(V010, "v0.1.0", port="9555")
    d = folder_with(tmp_path, old)
    r = switch(host, d, "v0.2.0", "--check")
    assert r.returncode == 0 and (d / "docker-compose.yml").read_text() == old, r.stderr
    assert not list(d.glob(".docker-compose.yml.sigrift-new"))
    r = switch(host, d, "v0.2.0")
    assert r.returncode == 0, r.stderr
    new = (d / "docker-compose.yml").read_text()
    assert new == render(INSTALL_RELEASE, "v0.2.0", port="9555", policy="missing")
    assert "regenerated from the v0.2.0 template (owner sigrift, port 9555 kept)" in r.stdout
    backups = list(d.glob("docker-compose.yml.bak.*~"))
    assert len(backups) == 1 and backups[0].read_text() == old
    assert "SHA=%s" % table()[-1][1] in r.stdout
    checks = [a for a in host.argvs() if a.startswith("compose --project-directory")]
    assert checks and all("--project-directory . -f ./.docker-compose.yml.sigrift-new -f "
                          "./docker-compose.override.yml config" in a for a in checks)
    assert all(".docker-compose.yml.sigrift-new" in a for a in checks)


def test_custom_compose_stays_tag_only_with_a_logged_diff(host, tmp_path):
    old = render(V010, "v0.1.0").replace(
        "      - BRIDGE_SECRETS_DIR=/app/secrets\n",
        "      - BRIDGE_SECRETS_DIR=/app/secrets\n      - MY_OWN=1\n")
    d = folder_with(tmp_path, old)
    r = switch(host, d, "v0.2.0")
    assert r.returncode == 0, r.stderr
    new = (d / "docker-compose.yml").read_text()
    assert "MY_OWN=1" in new and "sigrift-bridge:v0.2.0" in new and "start_period: 15s" in new
    diff = d / ".sigrift" / "logs" / "compose-template-run.diff"
    assert "differs from every template this installer knows" in r.stderr and diff.exists()
    assert "-      - MY_OWN=1" in diff.read_text() and len(diff.read_text().splitlines()) <= 200


@pytest.mark.parametrize("version, meets", [("v0.2.0-rc1", True), ("v0.2.0", True),
                                            ("v0.3.1", True), ("v0.1.0", False),
                                            ("v0.1.9-rc2", False), ("main", True),
                                            ("dev", True), ("garbage", False)])
def test_version_floor_ignores_rc_and_keeps_tag_only_below_it(version, meets):
    since = re.search(r"^LC_TEMPLATE_SINCE=(\S+)$", TEXT, re.M).group(1)
    assert since == "v0.2.0" and TOOL.version_meets(version, since) is meets


def test_below_the_floor_a_rerun_stays_tag_only_and_the_keystore_note_is_silent(host, tmp_path):
    old = render(V010, "v0.1.0")
    d = folder_with(tmp_path, old)
    r = switch(host, d, "v0.1.0")
    assert r.returncode == 0 and (d / "docker-compose.yml").read_text() == old, r.stderr
    assert "BRIDGE_KEYSTORE_KEY" not in r.stderr and "regenerated" not in r.stdout


@pytest.mark.parametrize("version, policy", [("v0.2.0", "missing"), ("v0.2.0-rc1", "missing"),
                                             ("main", "always"), ("main-abc1234", "always")])
def test_pull_policy_is_missing_for_tags_and_always_for_main(tmp_path, version, policy):
    script = function("release_write_compose") + \
        "VERSION=%s OWNER=sigrift PORT=8444 release_write_compose >/dev/null\n" % version
    subprocess.run([BASH, "-c", script], cwd=tmp_path, check=True)
    text = (tmp_path / "docker-compose.yml").read_text()
    assert text.count("    pull_policy: %s\n" % policy) == 2


def test_regenerated_bridge_has_a_ten_minute_start_period_and_both_new_env_lines_and_the_gateway_neither():
    yaml = pytest.importorskip("yaml")
    svc = yaml.safe_load(render(INSTALL_RELEASE, "v0.2.0", policy="missing"))["services"]
    assert svc["bridge"]["healthcheck"]["start_period"] == "10m"
    assert svc["gateway"]["healthcheck"]["start_period"] == "10s"
    for key in ("BRIDGE_KEYSTORE_KEY", "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP"):
        assert "%s=${%s:-}" % (key, key) in svc["bridge"]["environment"]
        assert not any(e.startswith(key) for e in svc["gateway"]["environment"])
    assert "name" not in yaml.safe_load(render(INSTALL_RELEASE, "v0.2.0"))
    assert svc["bridge"]["pull_policy"] == "missing"


def test_rollback_never_regenerates():
    for m in re.finditer(r"(?ms)^(lc_(?:step_rb|step_ab|rb|abort_rollback)[a-z_]*)\(\) \{\n"
                         r"(.*?)^\}\n", TEXT):
        assert "release_switch_compose" not in m.group(2), m.group(1)
    assert "release_switch_compose" not in shared_block(INSTALL_RELEASE, "state-tool")
