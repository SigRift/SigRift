"""Re-running ``edge-install.sh`` (the script ``GET /api/edge/install.sh`` serves).

A re-run keeps ``/etc/sigrift-edge.env`` (API URL, API key, node ID, gateway
trust) and the CA certificate, so upgrading an edge after a server upgrade
needs no flags; a flag given replaces its value, and lines the script does
not manage are kept.  The agent is checked out at the release the server
runs (``SERVER_RELEASE``, filled in by the bridge), at ``main`` for a
development server, or at ``--ref``.  The unit can write
``/var/lib/sigrift-edge`` (F12) without a ``StateDirectory=``, and a running
agent is restarted.

The cases source the script with ``SIGRIFT_EDGE_INSTALL_SOURCE_ONLY=1``,
move its paths into ``tmp_path`` and call its functions, with ``git``,
``systemctl``, ``install`` and ``id`` stubbed on PATH (each call logged).
They never reach ``/etc/os-release`` or apt, so they run on macOS too.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "sigrift"
    / "bridge"
    / "scripts"
    / "edge-install.sh"
)
API_KEY = "nodekey-7f3a9c1e5b2d4f6a8c0e"
PEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
REPO = "https://github.com/SigRift/SigRift.git"

# What main() runs up to the env file, without the OS, apt and venv steps.
CONFIGURE = """
parse_args "$@"
load_existing_env
resolve_settings
check_ca_cert
resolve_ref
ensure_node_id
install_trust_anchor
write_env_file
"""

_STUBS = {
    "id": 'echo "id $*" >> "$CALLS"; echo 0',
    "git": """echo "git $*" >> "$CALLS"
case "$*" in
  *" rev-parse --short HEAD") echo abc1234 ;;
  *" fetch "*) exit "${GIT_FETCH_RC:-0}" ;;
  "clone "*) exit "${GIT_CLONE_RC:-0}" ;;
esac
exit 0""",
    "systemctl": """echo "systemctl $*" >> "$CALLS"
case "$1" in is-active) exit "${SYSTEMCTL_ACTIVE_RC:-3}" ;; esac
exit 0""",
    "install": 'echo "install $*" >> "$CALLS"; exec /usr/bin/install "$@"',
    "hostname": "echo testhost",
}


class Host:
    """A fake root file system for the installer, under *tmp_path*."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        self.env_file = self.root / "etc" / "sigrift-edge.env"
        self.ca_dest = self.root / "etc" / "sigrift-edge" / "ca.pem"
        self.state_dir = self.root / "var" / "lib" / "sigrift-edge"
        self.install_dir = self.root / "opt" / "sigrift-edge"
        self.service_file = self.root / "etc" / "systemd" / "system" / "sigrift-edge.service"
        self.calls = tmp_path / "calls.log"
        self.stubs = tmp_path / "stubs"
        for directory in (self.env_file.parent, self.service_file.parent, self.stubs):
            directory.mkdir(parents=True, exist_ok=True)
        for name, body in _STUBS.items():
            stub = self.stubs / name
            stub.write_text(f"#!/bin/sh\n{body}\n")
            stub.chmod(0o755)
        self.gateway_cert = tmp_path / "gateway-cert.pem"
        self.gateway_cert.write_text(PEM)

    def run(
        self, body: str, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess:
        prelude = f"""
set -euo pipefail
SIGRIFT_EDGE_INSTALL_SOURCE_ONLY=1
source "{SCRIPT}"
ENV_FILE="{self.env_file}"
CA_DEST="{self.ca_dest}"
STATE_DIR="{self.state_dir}"
INSTALL_DIR="{self.install_dir}"
VENV_DIR="{self.install_dir}/venv"
SERVICE_FILE="{self.service_file}"
"""
        self.calls.write_text("")
        return subprocess.run(
            ["bash", "-c", prelude + body, "edge-install.sh", *args],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                "PATH": f"{self.stubs}:/usr/bin:/bin",
                "CALLS": str(self.calls),
                **(env or {}),
            },
        )

    def configure(self, *args: str, **kwargs) -> subprocess.CompletedProcess:
        return self.run(CONFIGURE, *args, **kwargs)

    def log(self) -> list[str]:
        return self.calls.read_text().splitlines()

    def env_lines(self) -> list[str]:
        return self.env_file.read_text().splitlines()

    def first_install(self) -> subprocess.CompletedProcess:
        proc = self.configure(
            "--api-url",
            "https://gw.example:8444",
            "--api-key",
            API_KEY,
            "--node-id",
            "edge-7",
            "--ca-cert",
            str(self.gateway_cert),
        )
        assert proc.returncode == 0, proc.stderr
        return proc


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def _managed(host: Host, *, url: str, key: str, node: str, tls: str | None) -> list[str]:
    lines = [
        "# edge-install.sh: written by the SigRift edge installer; mode 0600, it holds a NODE-role API key.",
        "# edge-install.sh: a re-run keeps these values unless new ones are given (--api-url, --api-key,",
        "# edge-install.sh: --node-id, --ca-cert, --insecure-tls), and keeps every other line as it is.",
        f"MLRF_API_URL={url}",
        f"MLRF_API_KEY={key}",
        f"MLRF_NODE_ID={node}",
    ]
    if tls:
        lines.append(tls)
    return [*lines, f"PYTHONPATH={host.install_dir}/src", "PYTHONUNBUFFERED=1"]


def test_a_rerun_without_flags_keeps_url_key_node_and_ca(host: Host) -> None:
    host.first_install()
    assert host.ca_dest.read_text() == PEM
    first = host.env_file.read_bytes()

    proc = host.configure()
    assert proc.returncode == 0, proc.stderr
    assert host.env_file.read_bytes() == first
    assert host.env_lines() == _managed(
        host,
        url="https://gw.example:8444",
        key=API_KEY,
        node="edge-7",
        tls=f"MLRF_CA_CERT={host.ca_dest}",
    )
    assert "keeping the API URL from" in proc.stdout
    assert "keeping the API key from" in proc.stdout
    assert "keeping node ID edge-7 from" in proc.stdout
    assert f"keeping the gateway CA certificate {host.ca_dest}" in proc.stdout
    assert not [c for c in host.log() if c.startswith("install ")], "the CA is not copied again"
    assert API_KEY not in proc.stdout + proc.stderr
    assert not Path(str(host.env_file) + ".bak").exists(), "nothing changed"


@pytest.mark.parametrize(
    "url", ["https://gw.example:8444/", "HTTPS://GW.example:8444"], ids=["slash", "case"]
)
def test_the_same_api_url_spelled_differently_keeps_the_key(host: Host, url: str) -> None:
    host.first_install()
    proc = host.configure("--api-url", url)
    assert proc.returncode == 0, proc.stderr
    assert f"MLRF_API_KEY={API_KEY}" in host.env_lines()
    assert f"MLRF_CA_CERT={host.ca_dest}" in host.env_lines()


def test_a_new_api_url_needs_a_new_api_key(host: Host) -> None:
    host.first_install()
    first = host.env_file.read_bytes()
    proc = host.configure("--api-url", "https://other-gw.example:8444")
    assert proc.returncode == 1
    assert "--api-key is required when --api-url changes" in proc.stderr
    assert "https://gw.example:8444" in proc.stderr
    assert API_KEY not in proc.stdout + proc.stderr
    assert host.env_file.read_bytes() == first


@pytest.mark.parametrize("kept", ["ca", "insecure"])
def test_a_new_api_url_drops_the_kept_gateway_trust(host: Host, kept: str) -> None:
    if kept == "ca":
        host.first_install()
    else:
        proc = host.configure(
            "--api-url", "https://gw.example:8444", "--api-key", API_KEY, "--insecure-tls"
        )
        assert proc.returncode == 0, proc.stderr
    proc = host.configure(
        "--api-url", "https://other-gw.example:8444", "--api-key", "other-key"
    )
    assert proc.returncode == 0, proc.stderr
    assert "not keeping the gateway trust from" in proc.stdout
    lines = host.env_lines()
    assert "MLRF_API_URL=https://other-gw.example:8444" in lines
    assert "MLRF_API_KEY=other-key" in lines
    assert "MLRF_NODE_ID=edge-7" in lines or kept == "insecure"
    assert not [x for x in lines if x.startswith(("MLRF_CA_CERT", "MLRF_INSECURE_TLS"))]

    # Trust given with the new URL is used as usual.
    proc = host.configure(
        "--api-url", "https://third-gw.example:8444", "--api-key", "third-key",
        "--ca-cert", str(host.gateway_cert),
    )
    assert proc.returncode == 0, proc.stderr
    assert "not keeping the gateway trust" not in proc.stdout
    assert f"MLRF_CA_CERT={host.ca_dest}" in host.env_lines()


def test_the_bak_is_0600_even_from_a_widened_env_file(host: Host) -> None:
    host.first_install()
    host.env_file.chmod(0o644)
    old_bak = Path(str(host.env_file) + ".bak")
    old_bak.write_text("an older backup")
    old_bak.chmod(0o644)
    proc = host.configure("--node-id", "edge-8")
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE(old_bak.stat().st_mode) == 0o600
    assert f"MLRF_API_KEY={API_KEY}" in old_bak.read_text().splitlines()
    assert stat.S_IMODE(host.env_file.stat().st_mode) == 0o600


def test_flags_replace_kept_values(host: Host) -> None:
    host.first_install()
    first = host.env_file.read_text()
    proc = host.configure("--api-key", "replacement-key", "--node-id", "edge-8")
    assert proc.returncode == 0, proc.stderr
    assert host.env_lines() == _managed(
        host,
        url="https://gw.example:8444",
        key="replacement-key",
        node="edge-8",
        tls=f"MLRF_CA_CERT={host.ca_dest}",
    )
    backup = Path(str(host.env_file) + ".bak")
    assert backup.read_text() == first
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_operator_lines_are_kept_and_a_second_run_changes_nothing(host: Host) -> None:
    host.ca_dest.parent.mkdir(parents=True)
    host.ca_dest.write_text(PEM)
    legacy = "\n".join(
        [
            "# Generated by edge-install.sh. Re-running the installer will",
            "# overwrite this file. Chmod 600 — contains a NODE-role API key.",
            "MLRF_API_URL=https://gw.example:8444",
            f"MLRF_API_KEY={API_KEY}",
            "MLRF_NODE_ID=edge-7",
            f"MLRF_CA_CERT={host.ca_dest}",
            "PYTHONPATH=/opt/sigrift-edge/src",
            "PYTHONUNBUFFERED=1",
            "MLRF_CLIENT_CERT=/x",
            "# note",
            "",
        ]
    )
    host.env_file.write_text(legacy)
    host.env_file.chmod(0o600)

    proc = host.configure()
    assert proc.returncode == 0, proc.stderr
    assert host.env_lines() == [
        *_managed(
            host,
            url="https://gw.example:8444",
            key=API_KEY,
            node="edge-7",
            tls=f"MLRF_CA_CERT={host.ca_dest}",
        ),
        "MLRF_CLIENT_CERT=/x",
        "# note",
    ]
    backup = Path(str(host.env_file) + ".bak")
    assert backup.read_text() == legacy
    written, backed_up = host.env_file.read_bytes(), backup.stat()

    proc = host.configure()
    assert proc.returncode == 0, proc.stderr
    assert host.env_file.read_bytes() == written
    assert backup.read_text() == legacy
    assert backup.stat().st_mtime_ns == backed_up.st_mtime_ns, "no new .bak"


def test_quoted_values_are_read_as_systemd_reads_them(host: Host) -> None:
    host.env_file.write_text(
        "MLRF_API_URL=\"https://gw.example:8444\"\nMLRF_API_KEY='quoted-key'\nMLRF_NODE_ID=edge-7\n"
    )
    proc = host.configure("--insecure-tls")
    assert proc.returncode == 0, proc.stderr
    assert "MLRF_API_URL=https://gw.example:8444" in host.env_lines()
    assert "MLRF_API_KEY=quoted-key" in host.env_lines()


def test_a_kept_ca_that_is_gone_stops(host: Host) -> None:
    host.first_install()
    host.ca_dest.unlink()
    proc = host.configure()
    assert proc.returncode == 1
    assert f"names MLRF_CA_CERT={host.ca_dest}, which does not exist" in proc.stderr
    assert "--ca-cert" in proc.stderr


def test_no_earlier_install_and_no_flags_needs_api_url(host: Host) -> None:
    proc = host.configure()
    assert proc.returncode == 1
    assert "--api-url is required (there is no " in proc.stderr
    assert "from an earlier install)" in proc.stderr
    proc = host.configure("--api-url", "https://gw.example:8444")
    assert proc.returncode == 1
    assert "--api-key is required" in proc.stderr
    assert not host.env_file.exists()


@pytest.mark.parametrize("flag", ["--api-url", "--api-key", "--node-id", "--ca-cert", "--ref"])
def test_a_flag_without_its_value_is_refused(host: Host, flag: str) -> None:
    proc = host.run('parse_args "$@"', flag)
    assert proc.returncode == 1
    assert f"{flag} needs a value" in proc.stderr


def test_kept_insecure_tls_warns_and_ca_cert_replaces_it(host: Host) -> None:
    proc = host.configure(
        "--api-url", "https://gw.example:8444", "--api-key", API_KEY, "--insecure-tls"
    )
    assert proc.returncode == 0, proc.stderr
    assert "MLRF_INSECURE_TLS=1" in host.env_lines()

    proc = host.configure()
    assert proc.returncode == 0, proc.stderr
    assert "WARN: keeping MLRF_INSECURE_TLS=1 from" in proc.stdout
    assert "MLRF_INSECURE_TLS=1" in host.env_lines()

    proc = host.configure("--ca-cert", str(host.gateway_cert))
    assert proc.returncode == 0, proc.stderr
    assert f"MLRF_CA_CERT={host.ca_dest}" in host.env_lines()
    assert not [line for line in host.env_lines() if line.startswith("MLRF_INSECURE_TLS")]


def test_insecure_tls_replaces_a_kept_ca(host: Host) -> None:
    host.first_install()
    proc = host.configure("--insecure-tls")
    assert proc.returncode == 0, proc.stderr
    assert "MLRF_INSECURE_TLS=1" in host.env_lines()
    assert not [line for line in host.env_lines() if line.startswith("MLRF_CA_CERT")]
    assert host.ca_dest.exists(), "the CA file is left on disk"


def test_the_env_file_is_0600_and_no_temp_file_is_left(host: Host) -> None:
    host.first_install()
    host.configure("--node-id", "edge-9")
    assert stat.S_IMODE(host.env_file.stat().st_mode) == 0o600
    names = sorted(p.name for p in host.env_file.parent.iterdir() if p.is_file())
    assert names == ["sigrift-edge.env", "sigrift-edge.env.bak"]


@pytest.mark.parametrize("flag", ["--api-url", "--api-key", "--node-id"])
def test_values_with_a_newline_are_refused(host: Host, flag: str) -> None:
    args = {"--api-url": "https://gw.example:8444", "--api-key": API_KEY, "--node-id": "n"}
    args[flag] = args[flag] + "\nMLRF_INSECURE_TLS=1"
    proc = host.configure(*[item for pair in args.items() for item in pair])
    assert proc.returncode == 1
    assert f"{flag} must be a single line" in proc.stderr
    assert not host.env_file.exists()


_RESOLVE = 'parse_args "$@"\n{assign}resolve_ref\necho "REF=$REF"\n'


@pytest.mark.parametrize(
    ("server_release", "args", "ref", "message"),
    [
        ("v0.2.0", (), "v0.2.0", "installing v0.2.0, the release the server runs"),
        ("v0.2.0-rc2", (), "v0.2.0-rc2", "the release the server runs"),
        ("", (), "main", "the server did not name a release (a development build)"),
        (None, (), "main", "the server did not name a release"),
        ("v0.2.0", ("--ref", "v0.1.0"), "v0.1.0", "installing v0.1.0 (--ref)"),
        ("", ("--ref", "main"), "main", "installing main (--ref)"),
    ],
    ids=["release", "rc", "dev-server", "unserved-script", "ref-wins", "ref-main"],
)
def test_ref_resolution(
    host: Host, server_release: str | None, args: tuple[str, ...], ref: str, message: str
) -> None:
    # None: the script as it is on disk (run from a checkout), placeholder kept.
    assign = "" if server_release is None else f'SERVER_RELEASE="{server_release}"\n'
    proc = host.run(_RESOLVE.format(assign=assign), *args)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.splitlines()[-1] == f"REF={ref}"
    assert message in proc.stdout


@pytest.mark.parametrize(
    "ref", ["-x", "a..b", "x y", "x;id", "`id`", "@{1}", "v1/", "v1.lock", "x//y", "", "x" * 101]
)
def test_bad_refs_are_refused(host: Host, ref: str) -> None:
    proc = host.run(_RESOLVE.format(assign=""), "--ref", ref)
    assert proc.returncode == 1
    assert "--ref must be a tag or branch name such as v0.2.0 or main" in proc.stderr
    assert "REF=" not in proc.stdout


def test_checkout_clones_or_fetches_the_ref(host: Host) -> None:
    proc = host.run('REF=v0.2.0\ncheckout_ref')
    assert proc.returncode == 0, proc.stderr
    assert host.log()[0] == (
        f"git clone --quiet --depth 1 --branch v0.2.0 {REPO} {host.install_dir}"
    )
    assert "checked out v0.2.0 at abc1234" in proc.stdout

    (host.install_dir / ".git").mkdir(parents=True)
    proc = host.run('REF=v0.2.0\ncheckout_ref')
    assert proc.returncode == 0, proc.stderr
    assert host.log()[:2] == [
        f"git -C {host.install_dir} fetch --quiet --depth 1 origin v0.2.0",
        f"git -C {host.install_dir} checkout --quiet --force --detach FETCH_HEAD",
    ]
    assert not [c for c in host.log() if "reset" in c or "origin/main" in c]

    proc = host.run('REF=v9.9.9\ncheckout_ref', env={"GIT_FETCH_RC": "128"})
    assert proc.returncode == 1
    assert "could not fetch v9.9.9" in proc.stderr and "--ref main" in proc.stderr
    assert not [c for c in host.log() if " checkout " in c]


def test_a_failed_clone_names_the_ref(host: Host) -> None:
    proc = host.run('REF=v0.2.0-rc9\ncheckout_ref', env={"GIT_CLONE_RC": "128"})
    assert proc.returncode == 1
    assert "could not clone v0.2.0-rc9" in proc.stderr and "--ref main" in proc.stderr


def test_the_state_dir_is_created_only_when_missing(host: Host) -> None:
    proc = host.run("prepare_state_dir")
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE(host.state_dir.stat().st_mode) == 0o755
    assert f"creating {host.state_dir}" in proc.stdout

    host.state_dir.chmod(0o700)
    (host.state_dir / "scanner-config.json").write_text("{}")
    proc = host.run("prepare_state_dir")
    assert proc.returncode == 0, proc.stderr
    assert stat.S_IMODE(host.state_dir.stat().st_mode) == 0o700
    assert host.log() == [], "an existing directory is left as it is"
    assert (host.state_dir / "scanner-config.json").read_text() == "{}"


def test_the_unit_grants_the_state_dir_without_a_state_directory(host: Host) -> None:
    proc = host.run("write_unit")
    assert proc.returncode == 0, proc.stderr
    unit = host.service_file.read_text().splitlines()
    assert f"ReadWritePaths=/var/log /tmp -{host.state_dir}" in unit
    assert not [line for line in unit if line.startswith("StateDirectory")]
    assert "ProtectSystem=strict" in unit
    # /sys and /proc/sys stay read-only although the root agent can now
    # write the state directory.
    for line in (
        "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes",
        "ProtectControlGroups=yes",
    ):
        assert line in unit
    assert f"EnvironmentFile={host.env_file}" in unit


@pytest.mark.parametrize(("active", "expected"), [(0, "restart"), (3, "enable --now")])
def test_a_running_agent_is_restarted(host: Host, active: int, expected: str) -> None:
    proc = host.run("start_service", env={"SYSTEMCTL_ACTIVE_RC": str(active)})
    assert proc.returncode == 0, proc.stderr
    calls = host.log()
    assert calls[:2] == [
        "systemctl daemon-reload",
        "systemctl is-active --quiet sigrift-edge.service",
    ]
    if expected == "restart":
        assert calls[2:] == [
            "systemctl enable sigrift-edge.service",
            "systemctl restart sigrift-edge.service",
        ]
    else:
        assert calls[2:] == ["systemctl enable --now sigrift-edge.service"]


_SUMMARY = (
    "REF=v0.2.0; NODE_ID=edge-7; API_URL=https://gw.example:8444/\n{trust}\n"
    "sleep() {{ :; }}\nprint_summary"
)


@pytest.mark.parametrize(
    ("trust", "curl_trust"),
    [
        ('CA_CERT=/x/gateway-cert.pem', "--cacert {ca_dest} "),
        ("", ""),
        ("INSECURE_TLS=1", "-k "),
    ],
    ids=["ca", "system-trust", "insecure"],
)
def test_the_summary_names_the_release_and_the_upgrade_command(
    host: Host, trust: str, curl_trust: str
) -> None:
    proc = host.run(_SUMMARY.format(trust=trust), env={"SYSTEMCTL_ACTIVE_RC": "0"})
    assert proc.returncode == 0, proc.stderr
    assert "Release:  v0.2.0 (abc1234)" in proc.stdout
    assert "Upgrade:  after a server upgrade, run (no flags needed):" in proc.stdout
    command = (
        f'f=$(mktemp) && curl -fsSL {curl_trust.format(ca_dest=host.ca_dest)}-o "$f" '
        'https://gw.example:8444/api/edge/install.sh && sudo bash "$f"; rm -f "$f"'
    )
    assert f"    {command}" in proc.stdout
    insecure_warning = "WARN: the gateway certificate is NOT verified"
    assert (insecure_warning in proc.stdout) is (trust == "INSECURE_TLS=1")


def test_the_printed_upgrade_command_runs_nothing_when_the_download_fails(
    tmp_path: Path,
) -> None:
    # Piped into bash a failed curl ran an empty script and exited 0.
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    ran = tmp_path / "ran"
    for name, body in {
        "curl": "exit 60",
        "sudo": f'echo "sudo $*" >> "{ran}"',
    }.items():
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    host = Host(tmp_path / "h")
    printed = host.run(
        "API_URL=https://gw.example:8444; CA_CERT=x\nupgrade_command"
    ).stdout
    proc = subprocess.run(
        ["bash", "-c", printed],
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": f"{stubs}:/usr/bin:/bin"},
    )
    # curl -S prints its own error; the installer never runs.
    assert proc.stdout == ""
    assert not ran.exists(), "nothing ran as root"
    assert "-fsSL" in printed


# main() itself, with only the OS, apt, DVB and venv steps (and sleep)
# replaced: the order and the calls are the script's own.
_MAIN = """
check_os() { :; }
install_packages() { :; }
blacklist_dvb() { :; }
install_python_deps() { :; }
sleep() { :; }
SERVER_RELEASE="v0.2.0"
main "$@"
"""

_MAIN_STUBS = {
    "curl": 'echo "curl $*" >> "$CALLS"; exit 0',
    # A clone leaves a checkout behind, so the re-run fetches.
    "git": """echo "git $*" >> "$CALLS"
case "$*" in
  "clone "*) for last; do :; done; mkdir -p "$last/.git" ;;
  *" rev-parse --short HEAD") echo abc1234 ;;
esac
exit 0""",
    # Active once started, so the first run starts it and the re-run restarts it.
    "systemctl": """echo "systemctl $*" >> "$CALLS"
case "$*" in
  "is-active "*) [ -f "$CALLS.active" ] && exit 0; exit 3 ;;
  "enable --now "*|"restart "*) : > "$CALLS.active" ;;
esac
exit 0""",
}


def test_main_installs_then_upgrades_with_no_flags(host: Host) -> None:
    for name, body in _MAIN_STUBS.items():
        (host.stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (host.stubs / name).chmod(0o755)
    proc = host.run(
        _MAIN,
        "--api-url",
        "https://gw.example:8444",
        "--api-key",
        API_KEY,
        "--ca-cert",
        str(host.gateway_cert),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    first = host.env_lines()
    (node_line,) = [x for x in first if x.startswith("MLRF_NODE_ID=testhost-")]
    assert host.log()[0] == "id -u"
    assert (
        f"git clone --quiet --depth 1 --branch v0.2.0 {REPO} {host.install_dir}"
        in host.log()
    )
    assert "systemctl enable --now sigrift-edge.service" in host.log()

    proc = host.run(_MAIN)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert host.env_lines() == first
    assert node_line in host.env_lines()
    assert f"MLRF_API_KEY={API_KEY}" in host.env_lines()
    assert f"MLRF_CA_CERT={host.ca_dest}" in host.env_lines()
    assert "keeping the API key from" in proc.stdout
    assert API_KEY not in proc.stdout + proc.stderr
    log = host.log()
    assert f"curl -sS -o /dev/null --max-time 10 --cacert {host.ca_dest} https://gw.example:8444" in log
    assert log.index(
        f"git -C {host.install_dir} fetch --quiet --depth 1 origin v0.2.0"
    ) < log.index("systemctl daemon-reload")
    assert "systemctl restart sigrift-edge.service" in log
    assert host.state_dir.is_dir()
    unit = host.service_file.read_text().splitlines()
    assert f"ReadWritePaths=/var/log /tmp -{host.state_dir}" in unit
    assert "Release:  v0.2.0 (abc1234)" in proc.stdout


def test_a_bad_ref_stops_before_installing_anything(tmp_path: Path) -> None:
    if os.path.lexists("/etc/sigrift-edge.env"):
        pytest.skip("this host has a real /etc/sigrift-edge.env")
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    calls = tmp_path / "calls.log"
    for name, body in {
        "id": "echo 0",
        "curl": f'echo "curl $*" >> "{calls}"; exit 0',
        "apt-get": f'echo "apt-get $*" >> "{calls}"; exit 97',
    }.items():
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    proc = subprocess.run(
        [
            "bash",
            str(SCRIPT),
            "--api-url",
            "https://gw.example:8444",
            "--api-key",
            "k",
            "--ref",
            "x;id",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={"PATH": f"{stubs}:/usr/bin:/bin"},
    )
    assert proc.returncode == 1
    assert "--ref must be a tag or branch name" in proc.stderr
    log = calls.read_text() if calls.exists() else ""
    assert "apt-get" not in log and "curl" not in log


def test_help_prints_usage_when_piped_into_bash(tmp_path: Path) -> None:
    # `curl ... | sudo bash -s -- --help`: $0 is "bash", so the old
    # `sed -n '2,29p' "$0"` printed nothing.
    proc = subprocess.run(
        ["bash", "-s", "--", "--help"],
        input=SCRIPT.read_text(),
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0
    assert "Upgrade or re-run (keeps /etc/sigrift-edge.env" in proc.stdout
    assert "--ref REF" in proc.stdout


def test_a_truncated_download_runs_nothing(tmp_path: Path) -> None:
    text = SCRIPT.read_text()
    cut = text[: text.index("main() {")]
    proc = subprocess.run(
        ["bash", "-s", "--", "--api-url", "https://gw.example:8444", "--api-key", "k"],
        input=cut,
        capture_output=True,
        text=True,
        timeout=30,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0
    assert proc.stdout == "" and proc.stderr == ""
