"""Current node reports and optional, explicitly configured SSH host audits.

Registration addresses are not SSH targets. Only the operator-owned configuration
can enable an audit; scanner reports require no SSH setup. SSH results are cached
for five minutes, while report lifetimes are recomputed on every request.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import stat
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request

from sigrift.bridge.dependencies import Role, require_role
from sigrift.bridge.scanner_status import SCANNER_REPORTS_FIELD, scanner_status_snapshot
from sigrift.bridge.state import AppState

logger = logging.getLogger(__name__)

router = APIRouter()

_CACHE_TTL = 300  # seconds
_SSH_TIMEOUT = 10  # seconds per node
_MAX_SSH_TARGETS = 32
_SSH_CONCURRENCY = 4
_SSH_CONFIG_LIMIT = 65536


def _load_ssh_targets() -> tuple[dict, str, str | None]:
    """Read bounded, nonsecret operator configuration; never infer a target."""
    filename = os.environ.get("BRIDGE_DEPLOYMENT_SSH_CONFIG", "")
    if not filename:
        return {}, "disabled", None
    try:
        # Reject FIFOs/devices rather than blocking an API request on a path
        # accidentally mounted in place of the operator's JSON document.
        with os.fdopen(os.open(filename, os.O_RDONLY | os.O_NONBLOCK), "rb") as config:
            if not stat.S_ISREG(os.fstat(config.fileno()).st_mode):
                raise ValueError("regular configuration file required")
            raw = config.read(_SSH_CONFIG_LIMIT + 1)
        if len(raw) > _SSH_CONFIG_LIMIT:
            raise ValueError("too large")

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result

        targets = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(targets, dict) or len(targets) > _MAX_SSH_TARGETS:
            raise ValueError("target map required")
        required = {"host", "user", "known_hosts_file", "identity_file"}
        for node_id, target in targets.items():
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", node_id):
                raise ValueError("invalid node id")
            if not isinstance(target, dict) or not required <= target.keys():
                raise ValueError("missing target fields")
            if target.keys() - required - {"port"}:
                raise ValueError("unknown target fields")
            host, user = target["host"], target["user"]
            if not isinstance(host, str) or len(host) > 253 or "%" in host:
                raise ValueError("invalid host")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if not all(
                    re.fullmatch(
                        r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label
                    )
                    for label in host.rstrip(".").split(".")
                ):
                    raise ValueError("invalid host") from None
            if not isinstance(user, str) or not re.fullmatch(
                r"[a-zA-Z_][a-zA-Z0-9_-]{0,63}", user
            ):
                raise ValueError("invalid user")
            port = target.get("port", 22)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid port")
            target["port"] = port
            for key in ("known_hosts_file", "identity_file"):
                value = target[key]
                if (
                    not isinstance(value, str)
                    or len(value) > 4096
                    or not Path(value).is_absolute()
                    or any(char.isspace() or ord(char) < 32 for char in value)
                ):
                    raise ValueError("invalid file path")
        return targets, hashlib.sha256(raw).hexdigest(), None
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return (
            {},
            "invalid",
            "SSH audit configuration is unreadable or invalid. Check BRIDGE_DEPLOYMENT_SSH_CONFIG and the Deployment Guide.",
        )


def _report_snapshot(data: dict, now: datetime) -> dict:
    try:
        status = AppState.get_node_status(data).value
    except (TypeError, ValueError, AttributeError):
        status = "unknown"
    return {
        "node_status": status,
        "last_seen": data.get("last_seen"),
        "scanner_status": scanner_status_snapshot(data.get(SCANNER_REPORTS_FIELD), now),
    }


_SERVICES = (
    "rf-edge",
    "mlrf-agent",
    "mlrf-bt-scanner",
    "wifi-scan",
    "readsb",
    "zigbee-scan",
)

# SSH audit script run on each node.  Single SSH call, multiple commands.
_AUDIT_SCRIPT = r"""
echo "===HOSTNAME==="
hostname
echo "===IP==="
ip -4 addr show 2>/dev/null | grep -oP 'inet \K[0-9.]+' | grep -v 127.0.0.1 | head -1 || echo "unknown"
echo "===MAC==="
ip link show 2>/dev/null | grep -A1 'state UP' | grep -oP 'link/ether \K[0-9a-f:]+' | head -1 || echo "unknown"
echo "===LINK==="
link_iface=$(ip link show 2>/dev/null | grep 'state UP' | head -1 | awk '{print $2}' | tr -d ':')
if echo "$link_iface" | grep -q wlan; then
    echo "wifi"
    echo "$link_iface"
    # SSID from active connection
    active_con=$(nmcli -t -f NAME,TYPE con show --active 2>/dev/null | grep 802-11-wireless | head -1 | cut -d: -f1)
    if [ -n "$active_con" ]; then
        nmcli -t con show "$active_con" 2>/dev/null | grep -oP '802-11-wireless.ssid:\K.*' || echo "unknown"
    else
        echo "unknown"
    fi
    # Signal strength from /proc/net/wireless
    cat /proc/net/wireless 2>/dev/null | tail -1 | awk '{gsub(/\./,"",$4); print $4}' || echo "0"
elif [ -n "$link_iface" ]; then
    echo "ethernet"
    echo "$link_iface"
    cat /sys/class/net/"$link_iface"/speed 2>/dev/null || echo "unknown"
    echo "n/a"
else
    echo "unknown"
    echo "unknown"
    echo "unknown"
    echo "0"
fi
echo "===OS==="
cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION_ID)=' || echo "unknown"
echo "===KERNEL==="
uname -r
echo "===PYTHON==="
python3 --version 2>&1 | awk '{print $2}'
echo "===NUMPY==="
python3 -c "import numpy; print(numpy.__version__)" 2>/dev/null || echo "missing"
echo "===ONNXRUNTIME==="
python3 -c "import onnxruntime; print(onnxruntime.__version__)" 2>/dev/null || echo "missing"
echo "===BLEAK==="
pip3 show bleak 2>/dev/null | grep -oP '^Version: \K.*' || echo "missing"
echo "===BELLOWS==="
pip3 show bellows 2>/dev/null | grep -oP '^Version: \K.*' || echo "missing"
echo "===ZIGPY==="
pip3 show zigpy 2>/dev/null | grep -oP '^Version: \K.*' || echo "missing"
echo "===SERVICES==="
for svc in rf-edge mlrf-agent mlrf-bt-scanner wifi-scan readsb zigbee-scan; do
    active=$(systemctl is-active "$svc" 2>/dev/null || echo "missing")
    enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "missing")
    echo "$svc:$active:$enabled"
done
echo "===READSB==="
readsb --version 2>&1 | head -1 || echo "not installed"
echo "===CONFIGS==="
for cfg in /home/pi/mlrf-agent/rf_scan.py /home/pi/mlrf-agent/node_agent.py /home/pi/mlrf-agent/detection_reporter.py /home/pi/mlrf-agent/bt_scanner.py /home/pi/mlrf-agent/wifi_scan.py /home/pi/mlrf-agent/edge_inference.py /opt/rf-edge/bin/zigbee_scanner.py /etc/systemd/system/rf-edge.service /etc/systemd/system/mlrf-agent.service /etc/systemd/system/zigbee-scan.service; do
    if [ -f "$cfg" ]; then
        hash=$(sha256sum "$cfg" 2>/dev/null | cut -c1-16)
        echo "$(basename $cfg):$hash"
    fi
done
echo "===FIREWALL==="
fw_out=$(sudo nft list ruleset 2>/dev/null)
if [ -n "$fw_out" ] && echo "$fw_out" | grep -q 'table'; then
    echo "active"
    echo "$fw_out" | grep -oP 'policy \K\w+' | head -1 || echo "unknown"
elif command -v nft >/dev/null 2>&1; then
    echo "inactive"
    echo "n/a"
else
    echo "missing"
    echo "n/a"
fi
echo "===SSH==="
grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "unknown"
grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "unknown"
echo "===DISK==="
df -BG --output=pcent,avail / 2>/dev/null | tail -1
echo "===RAM==="
free -m 2>/dev/null | awk '/^Mem:/{print $2, $3}'
echo "===UPTIME==="
awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "0"
echo "===MODEL==="
model_file=""
# Prefer current_model.onnx symlink (points to active model)
for d in /home/pi/mlrf-agent /opt/rf-edge; do
    if [ -f "$d/current_model.onnx" ]; then
        model_file=$(readlink -f "$d/current_model.onnx" 2>/dev/null || echo "$d/current_model.onnx")
        break
    fi
done
# Fallback: find newest .onnx file
if [ -z "$model_file" ]; then
    model_file=$(find /home/pi/mlrf-agent /home/pi/mlrf /opt/mlrf -name '*.onnx' -not -name 'current_model.onnx' -not -path '*/site-packages/*' 2>/dev/null | sort -r | head -1 || true)
fi
if [ -n "$model_file" ]; then
    echo "$model_file"
    stat --printf='%s\n' "$model_file" 2>/dev/null || echo "0"
else
    echo "none"
    echo "0"
fi
echo "===RFSCAN_HASH==="
rf_scan=$(find /home/pi/mlrf-agent /home/pi/mlrf /opt/mlrf -name 'rf_scan.py' 2>/dev/null | head -1 || true)
if [ -n "$rf_scan" ]; then
    sha256sum "$rf_scan" | awk '{print $1}'
else
    echo "unknown"
fi
echo "===SCRIPT_VERSIONS==="
# Hash each service script to detect version drift
for script_path in \
    /home/pi/mlrf-agent/rf_scan.py \
    /home/pi/mlrf-agent/node_agent.py \
    /home/pi/bt_scanner.py \
    /opt/rf-edge/bin/wifi_scan.py \
    /opt/rf-edge/bin/zigbee_scanner.py; do
    if [ -f "$script_path" ]; then
        h=$(sha256sum "$script_path" | awk '{print $1}')
        d=$(stat -c '%Y' "$script_path" 2>/dev/null || echo "0")
        echo "$(basename "$script_path"):$h:$d"
    else
        echo "$(basename "$script_path"):missing:0"
    fi
done
echo "===OLD_SCRIPTS==="
# Check for deprecated scripts that should no longer be deployed
for old in monitor.py edge_node.py node.py; do
    found=$(find /home/pi /opt/rf-edge -name "$old" -not -path '*/site-packages/*' 2>/dev/null | head -1 || true)
    if [ -n "$found" ]; then
        echo "$old:$found"
    fi
done
echo "===API_KEYS==="
# All services now use MLRF_BRIDGE_KEY from the shared .env file.
# Extract the canonical key from .env and verify all services reference
# the same env var (MLRF_BRIDGE_KEY) — no more MLRF_API_KEY fragmentation.
bridge_key=$(grep -oP '^MLRF_BRIDGE_KEY=\K\S+' /home/pi/mlrf-agent/.env 2>/dev/null)
if [ -z "$bridge_key" ]; then
    echo "fragmented"
    echo "unknown"
else
    # Check that no service files still reference the old MLRF_API_KEY variable
    stale=$(grep -l 'MLRF_API_KEY' /etc/systemd/system/mlrf-agent.service /etc/systemd/system/mlrf-bt-scanner.service /etc/systemd/system/rf-edge.service /etc/systemd/system/wifi-scan.service 2>/dev/null)
    if [ -n "$stale" ]; then
        echo "fragmented"
    else
        echo "unified"
    fi
    echo "$bridge_key" | sha256sum | awk '{print $1}'
fi
echo "===END==="
"""


def _parse_script_versions(lines: list[str]) -> dict[str, dict[str, Any]]:
    """Parse SCRIPT_VERSIONS lines like 'rf_scan.py:abc123:1708012345'."""
    result = {}
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) >= 3:
            name = parts[0]
            h = parts[1]
            try:
                ts = int(parts[2])
            except ValueError:
                ts = 0
            result[name] = {"hash": h, "mtime": ts}
        elif len(parts) == 2:
            result[parts[0]] = {"hash": parts[1], "mtime": 0}
    return result


def _parse_config_checksums(lines: list[str]) -> dict[str, str]:
    """Parse CONFIGS lines like 'rf_scan.py:abc123def456'."""
    result = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1]
    return result


def _parse_old_scripts(lines: list[str]) -> list[dict[str, str]]:
    """Parse OLD_SCRIPTS lines like 'monitor.py:/home/pi/monitor.py'."""
    result = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)
        if len(parts) == 2:
            result.append({"name": parts[0], "path": parts[1]})
    return result


def _parse_audit_output(raw: str) -> dict[str, Any]:
    """Parse the structured output from the audit script."""
    sections: dict[str, list[str]] = {}
    current = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("===") and line.endswith("==="):
            current = line.strip("=")
            sections[current] = []
        elif current and current != "END":
            sections.setdefault(current, []).append(line)

    def first(key: str, default: str = "unknown") -> str:
        vals = sections.get(key, [])
        return vals[0].strip() if vals else default

    # OS
    os_lines = sections.get("OS", [])
    os_name = "unknown"
    for l in os_lines:  # noqa: E741
        if l.startswith("PRETTY_NAME="):
            os_name = l.split("=", 1)[1].strip('"')

    # Services
    services: dict[str, dict[str, bool]] = {}
    for l in sections.get("SERVICES", []):  # noqa: E741
        parts = l.split(":")
        if len(parts) >= 3:
            svc = parts[0]
            services[svc] = {
                "active": parts[1] == "active",
                "enabled": parts[2] == "enabled",
            }

    # Firewall
    fw_lines = sections.get("FIREWALL", [])
    fw_active = fw_lines[0] if fw_lines else "unknown"
    fw_policy = fw_lines[1] if len(fw_lines) > 1 else "unknown"

    # SSH
    ssh_lines = sections.get("SSH", [])
    pass_auth = ssh_lines[0].lower() if ssh_lines else "unknown"
    root_login = ssh_lines[1].lower() if len(ssh_lines) > 1 else "unknown"

    # Disk
    disk_line = first("DISK", "0% 0G")
    disk_parts = disk_line.split()
    disk_pct = int(disk_parts[0].replace("%", "").strip()) if disk_parts else 0
    disk_avail = disk_parts[1].replace("G", "").strip() if len(disk_parts) > 1 else "0"
    try:
        disk_avail_gb = int(disk_avail)
    except ValueError:
        disk_avail_gb = 0

    # RAM
    ram_line = first("RAM", "0 0")
    ram_parts = ram_line.split()
    try:
        ram_total = int(ram_parts[0]) if ram_parts else 0
        ram_used = int(ram_parts[1]) if len(ram_parts) > 1 else 0
    except ValueError:
        ram_total = ram_used = 0

    # Uptime
    try:
        uptime = int(first("UPTIME", "0"))
    except ValueError:
        uptime = 0

    # Model
    model_lines = sections.get("MODEL", [])
    model_file = model_lines[0] if model_lines else "none"
    model_size_str = model_lines[1] if len(model_lines) > 1 else "0"
    try:
        model_size = int(model_size_str)
    except ValueError:
        model_size = 0
    import os.path

    model_filename = os.path.basename(model_file) if model_file != "none" else None

    # Link / physical layer
    link_lines = sections.get("LINK", [])
    link_type = link_lines[0] if link_lines else "unknown"
    link_iface = link_lines[1] if len(link_lines) > 1 else "unknown"
    if link_type == "wifi":
        link_ssid = link_lines[2] if len(link_lines) > 2 else "unknown"
        link_signal_str = link_lines[3] if len(link_lines) > 3 else "0"
        try:
            link_signal = int(link_signal_str)
        except ValueError:
            link_signal = 0
        link_info = {
            "type": "wifi",
            "interface": link_iface,
            "ssid": link_ssid,
            "signal_dbm": link_signal,
        }
    elif link_type == "ethernet":
        link_speed = link_lines[2] if len(link_lines) > 2 else "unknown"
        link_info = {
            "type": "ethernet",
            "interface": link_iface,
            "speed_mbps": link_speed,
        }
    else:
        link_info = {"type": "unknown"}

    return {
        "hostname": first("HOSTNAME", "unknown"),
        "ip": first("IP", "unknown"),
        "mac": first("MAC", "unknown"),
        "link": link_info,
        "os": os_name,
        "kernel": first("KERNEL"),
        "python": first("PYTHON"),
        "numpy": first("NUMPY"),
        "onnxruntime": first("ONNXRUNTIME"),
        "bleak": first("BLEAK"),
        "bellows": first("BELLOWS"),
        "zigpy": first("ZIGPY"),
        "services": services,
        "firewall": {
            "active": fw_active == "active",
            "policy": fw_policy,
            "backend": "nftables" if fw_active != "missing" else "none",
        },
        "ssh": {
            "password_auth": pass_auth not in ("no", "unknown"),
            "root_login": root_login not in ("no", "prohibit-password", "unknown"),
        },
        "disk_used_pct": disk_pct,
        "disk_avail_gb": disk_avail_gb,
        "ram_total_mb": ram_total,
        "ram_used_mb": ram_used,
        "uptime_seconds": uptime,
        "model": {
            "filename": model_filename,
            "size_bytes": model_size,
        },
        "rf_scan_hash": first("RFSCAN_HASH"),
        "script_versions": _parse_script_versions(sections.get("SCRIPT_VERSIONS", [])),
        "old_scripts": _parse_old_scripts(sections.get("OLD_SCRIPTS", [])),
        "api_keys_unified": first("API_KEYS") == "unified",
        "_key_hash": sections.get("API_KEYS", ["", ""])[1].strip()
        if len(sections.get("API_KEYS", [])) > 1
        else "unknown",
        "readsb_version": first("READSB", "not installed"),
        "config_checksums": _parse_config_checksums(sections.get("CONFIGS", [])),
    }


def _compute_key_hash() -> str | None:
    """Compute SHA-256 of the master key for hash-only comparison with node keys.

    Returns the SHA-256 hex digest, or None if the master key is unavailable.
    Never exposes the raw key beyond this function's scope.
    """
    import hashlib
    import os

    master_raw = os.environ.get("BRIDGE_MASTER_KEY", "").strip()
    if not master_raw:
        return None
    return hashlib.sha256((master_raw + "\n").encode()).hexdigest()


def _ssh_failure(status: str, error: str, guidance: str) -> dict[str, Any]:
    return {
        "reachable": False,
        "ssh_status": status,
        "error": error,
        "guidance": guidance,
    }


def _ssh_audit_node(
    host: str,
    user: str = "pi",
    *,
    port: int = 22,
    known_hosts_file: str | None = None,
    identity_file: str | None = None,
) -> dict[str, Any]:
    """Run one bounded audit with strict host trust and no ambient SSH config."""
    cmd = [
        "ssh",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=yes",
        "-p",
        str(port),
        "-l",
        user,
    ]
    if known_hosts_file is not None:
        if not Path(known_hosts_file).is_file() or not os.access(
            known_hosts_file, os.R_OK
        ):
            return _ssh_failure(
                "host_key_unverified",
                "SSH host trust is not configured.",
                "Mount a readable known_hosts file containing independently verified host keys; then refresh.",
            )
        cmd += [
            "-o",
            f"UserKnownHostsFile={known_hosts_file}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
        ]
    if identity_file is not None:
        if not Path(identity_file).is_file() or not os.access(identity_file, os.R_OK):
            return _ssh_failure(
                "credentials_missing",
                "SSH audit credentials are unavailable.",
                "Mount the configured audit identity read-only and make it readable by the Bridge user; then refresh.",
            )
        cmd += ["-o", "IdentitiesOnly=yes", "-i", identity_file]
    cmd += ["--", host, "bash", "-s"]
    try:
        result = subprocess.run(
            cmd,
            input=_AUDIT_SCRIPT,
            capture_output=True,
            text=True,
            timeout=_SSH_TIMEOUT,
            env={**os.environ, "LC_ALL": "C"},
        )
        if result.returncode != 0:
            stderr = result.stderr.lower()
            if "remote host identification has changed" in stderr:
                failure = _ssh_failure(
                    "host_key_changed",
                    "SSH host identity changed.",
                    "Stop and verify the host fingerprint through a trusted channel before updating known_hosts.",
                )
            elif (
                "host key verification failed" in stderr
                or "no " in stderr
                and " host key is known" in stderr
                or "host key known" in stderr
            ):
                failure = _ssh_failure(
                    "host_key_unverified",
                    "SSH host identity has not been verified.",
                    "Verify the host fingerprint through a trusted channel and add it to the configured known_hosts file; then refresh.",
                )
            elif "permission denied" in stderr or "load key" in stderr:
                failure = _ssh_failure(
                    "authentication_failed",
                    "SSH authentication failed.",
                    "Check the configured audit user and read-only identity; scanner API keys are not SSH credentials.",
                )
            elif "could not resolve hostname" in stderr:
                failure = _ssh_failure(
                    "host_unresolved",
                    "SSH hostname could not be resolved.",
                    "Configure a host reachable from the Bridge container; a registered scanner or Compose service name is not an SSH endpoint.",
                )
            else:
                failure = _ssh_failure(
                    "unreachable",
                    "SSH connection or audit failed.",
                    "Check the configured SSH host, port and audit permissions. Scanner activity is reported separately.",
                )
            logger.warning(
                "SSH audit failed: %s (rc=%d)", failure["ssh_status"], result.returncode
            )
            return failure
        if "===HOSTNAME===" not in result.stdout or "===END===" not in result.stdout:
            return _ssh_failure(
                "invalid_response",
                "SSH audit returned incomplete data.",
                "Check that the target supports the host audit commands; no successful audit is claimed.",
            )
        parsed = _parse_audit_output(result.stdout)
        parsed.update(reachable=True, ssh_status="verified")
        return parsed
    except subprocess.TimeoutExpired:
        return _ssh_failure(
            "timeout",
            "SSH timeout",
            "Check host connectivity; the audit stopped after 10 seconds.",
        )
    except FileNotFoundError:
        return _ssh_failure(
            "client_missing",
            "SSH client is unavailable.",
            "Install the supported Bridge image with its OpenSSH client.",
        )
    except Exception:
        logger.exception("SSH audit could not complete")
        return _ssh_failure(
            "audit_error",
            "SSH audit could not complete.",
            "Check the Bridge audit configuration and logs.",
        )


@router.get("/deployment", dependencies=[Depends(require_role(Role.ADMIN))])
async def get_deployment_status(request: Request):
    """Return current node reports and explicitly configured optional SSH audits.

    Results are cached for 5 minutes.  Pass ``?refresh=true`` to force re-scan.
    """
    force = request.query_params.get("refresh", "").lower() == "true"

    persistence = request.app.state.persistence
    nodes = persistence.get_nodes()
    targets, fingerprint, config_error = _load_ssh_targets()
    cache_key = (fingerprint, tuple(sorted(nodes)))
    cache = getattr(request.app.state, "_deployment_cache", None)
    if (
        cache
        and not force
        and cache.get("_key") == cache_key
        and time.monotonic() - cache["_mono"] < _CACHE_TTL
    ):
        now = datetime.now(timezone.utc)
        return {
            "cached": True,
            "cached_at": cache["cached_at"],
            "cache_ttl_sec": _CACHE_TTL,
            "generated_at": now.isoformat(),
            "nodes": {
                nid: {**info, **_report_snapshot(nodes[nid], now)}
                for nid, info in cache["nodes"].items()
            },
        }
    if not nodes:
        return {
            "cached": False,
            "cached_at": None,
            "cache_ttl_sec": _CACHE_TTL,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "nodes": {},
        }

    # At most four bounded SSH processes per request, and at most 32 configured
    # targets. Unconfigured nodes never launch a process or resolve a hostname.
    semaphore = asyncio.Semaphore(_SSH_CONCURRENCY)

    async def _audit(node_id: str) -> tuple[str, dict]:
        if config_error:
            return node_id, _ssh_failure(
                "configuration_error",
                config_error,
                "SSH auditing is optional. Normal scanner reports do not require SSH setup.",
            )
        target = targets.get(node_id)
        if target is None:
            return node_id, _ssh_failure(
                "not_configured",
                "SSH audit not configured",
                "Normal scanner reports do not require SSH. For an optional host audit, configure this node in BRIDGE_DEPLOYMENT_SSH_CONFIG; see the Deployment Guide.",
            )
        async with semaphore:
            info = await asyncio.to_thread(
                _ssh_audit_node,
                target["host"],
                user=target["user"],
                port=target["port"],
                known_hosts_file=target["known_hosts_file"],
                identity_file=target["identity_file"],
            )
        info.setdefault(
            "ssh_status", "verified" if info.get("reachable") else "unreachable"
        )
        return node_id, info

    node_map = dict(await asyncio.gather(*(_audit(nid) for nid in nodes)))

    # Cross-node key consistency: check all reachable nodes use the same key
    key_hashes = {}
    for nid, info in node_map.items():
        kh = info.get("_key_hash", "unknown")
        if info.get("reachable") and kh != "unknown":
            key_hashes[nid] = kh
    unique_hashes = set(key_hashes.values())
    all_keys_match = len(unique_hashes) <= 1

    # Validate node keys against Bridge master key using hash-only comparison.
    # The audit script collects a hash of the key from each node. We compute
    # SHA-256 of the local master key and compare — no raw key is ever
    # fetched via SSH.
    bridge_key_valid = None
    if key_hashes:
        try:
            bridge_hash = await asyncio.to_thread(_compute_key_hash)
            if bridge_hash:
                node_hashes = set(key_hashes.values())
                bridge_key_valid = bridge_hash in node_hashes
        except Exception:
            bridge_key_valid = None

    # Annotate each node and strip internal _key_hash
    for nid, info in node_map.items():
        if info.get("reachable"):
            info["api_keys_consistent"] = all_keys_match
            info["api_key_bridge_valid"] = bridge_key_valid
        info.pop("_key_hash", None)

    now_iso = datetime.now(timezone.utc).isoformat()
    request.app.state._deployment_cache = {
        "_mono": time.monotonic(),
        "_key": cache_key,
        "cached_at": now_iso,
        "nodes": node_map,
    }

    return {
        "cached": False,
        "cached_at": now_iso,
        "cache_ttl_sec": _CACHE_TTL,
        "generated_at": now_iso,
        "nodes": {
            nid: {
                **info,
                **_report_snapshot(nodes[nid], datetime.fromisoformat(now_iso)),
            }
            for nid, info in node_map.items()
        },
    }
