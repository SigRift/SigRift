"""Edge systemd units must not leak secrets or hand out root (finding D10).

* zigbee-scan.service passed ``--api-key ${MLRF_BRIDGE_KEY}`` on the command
  line, readable by every local user via ps / /proc/<pid>/cmdline;
* wifi-scan.service ran as root with an EnvironmentFile under /home/pi, so
  the pi user could set PYTHONPATH / LD_PRELOAD for a root process.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_EDGE = Path(__file__).resolve().parents[2] / "src" / "sigrift" / "edge"
_UNITS = sorted(_EDGE.glob("*.service"))


def _service_section(path: Path) -> list[tuple[str, str]]:
    """(key, value) pairs of the [Service] section, continuation lines joined."""
    items: list[tuple[str, str]] = []
    section = None
    pending = ""
    for raw in path.read_text().splitlines():
        line = pending + raw.strip()
        if line.endswith("\\"):
            pending = line[:-1] + " "
            continue
        pending = ""
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section == "Service" and "=" in line:
            key, value = line.split("=", 1)
            items.append((key.strip(), value.strip()))
    return items


def _values(path: Path, key: str) -> list[str]:
    return [v for k, v in _service_section(path) if k == key]


def test_units_found() -> None:
    names = {p.name for p in _UNITS}
    assert {"wifi-scan.service", "zigbee-scan.service", "rf-edge.service"} <= names


@pytest.mark.parametrize("unit", _UNITS, ids=lambda p: p.name)
def test_no_secret_on_the_command_line(unit: Path) -> None:
    for cmd in _values(unit, "ExecStart"):
        assert "KEY" not in cmd.upper(), cmd
        assert "--api-key" not in cmd and "--password" not in cmd, cmd
        assert "$" not in cmd, f"env expansion into argv: {cmd}"


@pytest.mark.parametrize("unit", _UNITS, ids=lambda p: p.name)
def test_never_root_and_no_privilege_gain(unit: Path) -> None:
    users = _values(unit, "User")
    assert users and users[-1] not in ("root", "0"), users
    assert _values(unit, "NoNewPrivileges")[-1:] == ["yes"]
    assert _values(unit, "CapabilityBoundingSet"), "bounding set must be explicit"


@pytest.mark.parametrize("unit", _UNITS, ids=lambda p: p.name)
def test_environment_files_are_not_user_writable_locations(unit: Path) -> None:
    for env_file in _values(unit, "EnvironmentFile"):
        path = env_file.lstrip("-")
        assert path.startswith("/etc/"), env_file
        assert not path.startswith(("/home", "/opt", "/tmp", "/var/tmp")), env_file


def test_wifi_scan_config_handoff_is_not_in_private_tmp() -> None:
    """wifi-scan reads the summarize toggle from a shared dir, not /tmp (Q15).

    With PrivateTmp=yes the agent's /tmp and the scanner's /tmp are separate,
    so the handoff file must live under a StateDirectory the units share.
    """
    unit = _EDGE / "wifi-scan.service"
    paths = _values(unit, "Environment")
    cfg = [v for v in paths if v.startswith("MLRF_SCANNER_CONFIG_PATH=")]
    assert cfg, "wifi-scan.service must pin MLRF_SCANNER_CONFIG_PATH"
    value = cfg[-1].split("=", 1)[1]
    assert not value.startswith("/tmp/"), value
    assert value.startswith("/var/lib/sigrift-edge/"), value
    assert "sigrift-edge" in " ".join(_values(unit, "StateDirectory"))


def test_wifi_scan_capabilities_are_exactly_net_admin_and_net_raw() -> None:
    unit = _EDGE / "wifi-scan.service"
    want = {"CAP_NET_ADMIN", "CAP_NET_RAW"}
    assert set(" ".join(_values(unit, "AmbientCapabilities")).split()) == want
    assert set(" ".join(_values(unit, "CapabilityBoundingSet")).split()) == want


@pytest.mark.parametrize(
    "unit", ["zigbee-scan.service", "rf-edge.service"], ids=lambda n: n
)
def test_other_units_need_no_capabilities(unit: str) -> None:
    path = _EDGE / unit
    assert _values(path, "CapabilityBoundingSet") == [""]
    assert not _values(path, "AmbientCapabilities")


def test_zigbee_scanner_reads_the_key_from_the_environment() -> None:
    """The unit only works if the scanner falls back to MLRF_BRIDGE_KEY."""
    src = (_EDGE.parent / "bridge" / "zigbee_scanner.py").read_text()
    assert '"MLRF_BRIDGE_KEY"' in src and '"MLRF_BRIDGE_URL"' in src
    assert '"MLRF_CA_BUNDLE"' in src and '"MLRF_NODE_ID"' in src


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="no systemd")
@pytest.mark.parametrize("unit", _UNITS, ids=lambda p: p.name)
def test_systemd_analyze_verify(unit: Path) -> None:
    proc = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", str(unit)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    # Unknown keys / bad values are reported on stderr even with exit 0.
    noise = [
        line
        for line in proc.stderr.splitlines()
        if "Unknown key" in line or "Invalid" in line or "Failed to parse" in line
    ]
    assert not noise, proc.stderr
