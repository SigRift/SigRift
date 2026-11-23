#!/usr/bin/env python3
"""Send a bounded, sanitized last host check using the installed node credential.

This optional first-run/retry receipt never changes selection, devices, network
interfaces or credentials. It is not a daemon and does not assert capture health.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path, PurePosixPath
import re
import signal
import ssl
import sys
import urllib.error
import urllib.request

import scanner_setup as setup

USB_INVENTORY = Path("/sys/bus/usb/devices")

REASONS = {
    "kernel driver owns this receiver": "driver_in_use",
    "USB device node is unavailable": "device_unavailable",
    "USB path is not a character device": "device_unavailable",
    "USB device node does not match the kernel device identity": "device_unavailable",
    "USB permissions do not grant read/write to the scanner": "permissions",
    setup.SHARED_GROUP: "permissions",
    "radio carries SSH, routed/addressed traffic or an active/unknown sibling": "management_interface",
    "driver does not advertise monitor mode": "monitor_unsupported",
    "radio is blocked by rfkill": "radio_blocked",
}


def host_receipt(root, *, dashboard_only=False):
    """Read desired selection and actual probes separately; discard identities."""
    if dashboard_only:
        return {
            kind: {
                "adapter": "unknown",
                "selection": "not_selected",
                "reason": "not_checked",
            }
            for kind in setup.SCANNERS
        }
    try:
        active = setup.saved_selection(root)
        pending = setup.pending_selection(root)
        if active is not None and pending is not None and active != pending:
            raise setup.SetupError("Conflicting pending selection")
        desired = pending if pending is not None else active
    except (setup.SetupError, OSError, ValueError):
        return {
            kind: {
                "adapter": "unknown",
                "selection": "unmanaged",
                "reason": "selection_unavailable",
            }
            for kind in setup.SCANNERS
        }
    result = {
        kind: {
            "adapter": "unknown",
            "selection": "unmanaged"
            if desired is None
            else "selected"
            if kind in desired
            else "not_selected",
            "reason": "probe_failed",
        }
        for kind in setup.SCANNERS
    }
    try:
        setup.native_docker()
    except setup.SetupError:
        for entry in result.values():
            entry["reason"] = "unsupported_host"
        return result
    for kind, probe in (("sdr", setup.rtl_devices), ("wifi", setup.wifi_devices)):
        entry = result[kind]
        try:
            if (
                kind == "wifi"
                and desired
                and kind in desired
                and "identity" not in desired[kind]
            ):
                entry["reason"] = "selection_unavailable"
                continue
            if kind == "sdr":
                # Path.glob treats an unavailable directory like an empty one.
                # Establish readable inventory before interpreting no matches.
                list(USB_INVENTORY.iterdir())
            discovered = probe()
            if kind == "sdr":
                discovered = setup.managed_rtl_devices(root, discovered)
            candidates = discovered
            if desired and kind in desired:
                candidates = setup.matching_devices(kind, discovered, desired)
            if not candidates:
                entry.update(
                    adapter="missing",
                    reason="selected_absent"
                    if entry["selection"] == "selected"
                    else "not_found",
                )
            elif kind == "sdr" and len(discovered) > 1:
                entry.update(adapter="blocked", reason="ambiguous")
            elif any(not item["reasons"] for item in candidates):
                entry.update(adapter="ready", reason="checked")
            else:
                reasons = [reason for item in candidates for reason in item["reasons"]]
                # Unknown/freeform discovery errors never become public strings.
                if any(reason not in REASONS for reason in reasons):
                    entry.update(adapter="unknown", reason="probe_failed")
                else:
                    entry.update(adapter="blocked", reason=REASONS[reasons[0]])
        except (setup.SetupError, OSError, ValueError, KeyError, TypeError):
            entry.update(adapter="unknown", reason="probe_failed")
    return result


def published_url(output):
    candidates = []
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(
            r"(?:\[([0-9A-Fa-f:.]+)\]|([^:\s]+)):([0-9]+)", line.strip()
        )
        if not match:
            raise setup.SetupError("Invalid gateway endpoint")
        address = ipaddress.ip_address(match[1] or match[2])
        port = int(match[3])
        if not 1 <= port <= 65535 or (address.version == 6) != bool(match[1]):
            raise setup.SetupError("Invalid gateway endpoint")
        if address.is_unspecified:
            address = ipaddress.ip_address(
                "127.0.0.1" if address.version == 4 else "::1"
            )
        host = str(address) if address.version == 4 else f"[{address}]"
        candidates.append(
            (
                (address.version, not address.is_loopback, host, port),
                f"https://{host}:{port}",
            )
        )
    if not candidates:
        raise setup.SetupError("Gateway has no published endpoint")
    return min(candidates)[1]


def installed_target(root):
    """Resolve only existing standard Compose inputs; never synthesize a key."""
    for path in (root / ".env", root / "docker-compose.yml", root / "tls/cert.pem"):
        if path.is_symlink() or not path.is_file():
            raise setup.SetupError("Installed configuration is unavailable")
    if (root / "tls").is_symlink():
        raise setup.SetupError("TLS directory must be local")
    setup.compose_inputs(root)
    command = [
        "docker",
        "compose",
        "--project-directory",
        str(root),
        "-f",
        str(root / "docker-compose.yml"),
    ]
    if (root / "docker-compose.override.yml").exists():
        command += ["-f", str(root / "docker-compose.override.yml")]
    config = setup.json_command(command + ["config", "--format", "json"])
    bridge = config["services"]["bridge"].get("environment", {})
    edge = config["services"]["edge"].get("environment", {})
    gateway = config["services"]["gateway"]

    def actual(values, name):
        value = values.get(name)
        if not isinstance(value, str) or not value:
            raise setup.SetupError("Installed node credential is unavailable")
        return value.replace("$$", "$")

    node_id = actual(edge, "MLRF_NODE_ID")
    key = actual(edge, "MLRF_API_KEY")
    if (
        not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", node_id)
        or key != actual(bridge, "BRIDGE_LOCAL_NODE_KEY")
        or node_id != actual(bridge, "BRIDGE_LOCAL_NODE_ID")
        or any(char in key for char in "\r\n")
    ):
        raise setup.SetupError("Installed node credential does not match")
    cert = actual(gateway.get("environment", {}), "UC_TLS_CERT")
    certificate = PurePosixPath(cert)
    if not certificate.is_absolute() or ".." in certificate.parts:
        raise setup.SetupError("Expected gateway certificate is not mounted")
    mounts = []
    for item in gateway.get("volumes", []):
        target = PurePosixPath(item.get("target", ""))
        if target.is_absolute() and certificate.is_relative_to(target):
            mounts.append((len(target.parts), item, certificate.relative_to(target)))
    if not mounts:
        raise setup.SetupError("Expected gateway certificate is not mounted")
    _, mount, relative = max(mounts, key=lambda item: item[0])
    if (
        mount.get("type") != "bind"
        or not mount.get("read_only")
        or (Path(mount.get("source", "")) / relative).resolve()
        != (root / "tls/cert.pem").resolve()
    ):
        raise setup.SetupError("Expected gateway certificate is not mounted")
    url = published_url(setup.run(command + ["port", "gateway", "8444"]))
    return url, node_id, key, root / "tls/cert.pem"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_receipt(url, node_id, key, cert, payload):
    # Construct directly: create_default_context would honor SSLKEYLOGFILE in
    # this process. Trust only this installed gateway certificate, with normal
    # hostname verification. No proxy, redirects, retries or response logging.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(cert))
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url + "/api/nodes/" + node_id + "/setup-readiness",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    with opener.open(request, timeout=5) as response:
        if response.status != 200:
            raise setup.SetupError("Readiness was not accepted")
        body = response.read(4097)
        if len(body) > 4096:
            raise setup.SetupError("Unexpected readiness response")
        result = json.loads(body)
    if (
        not isinstance(result, dict)
        or result.get("fresh") is not True
        or type(result.get("expires_in_seconds")) not in (int, float)
        or not 0 < result["expires_in_seconds"] <= 300
        or any(result.get(kind) != payload[kind] for kind in setup.SCANNERS)
    ):
        raise setup.SetupError("Unexpected readiness response")


class ReceiptDeadline(Exception):
    """An overall deadline that cannot be mistaken for a failed device probe."""


class ReceiptCancelled(Exception):
    """An explicit termination must remain distinct from delivery failure."""


def main():
    if sys.argv[1:] not in ([], ["--dashboard-only"]):
        print("Readiness accepts only --dashboard-only.", file=sys.stderr)
        return 2

    def interrupted(*_):
        raise ReceiptDeadline("Readiness deadline")

    def cancelled(*_):
        raise ReceiptCancelled()

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(45)
    try:
        root = Path.cwd()
        target = installed_target(root)
        send_receipt(
            *target,
            host_receipt(root, dashboard_only="--dashboard-only" in sys.argv[1:]),
        )
    except KeyboardInterrupt:
        return 130
    except ReceiptCancelled:
        return 143
    except (
        setup.SetupError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ReceiptDeadline,
    ):
        # Raw command errors, bodies, paths and credentials never reach output.
        print(
            "    Host readiness was not reported. Setup/configuration are unchanged; capture status remains separate.",
            file=sys.stderr,
        )
        return 1
    finally:
        signal.alarm(0)
    print(
        "    Last host check reported (fresh for five minutes). Live capture and recent data are separate checks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
