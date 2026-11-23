#!/usr/bin/env python3
"""SigRift edge node monitor agent.

Runs on each edge node, periodically sending heartbeats with live
system metrics to the SigRift dashboard API.

Metrics collected:
    - CPU usage (two-sample /proc/stat)
    - Memory usage (/proc/meminfo)
    - Disk usage (shutil.disk_usage)
    - CPU temperature (/sys/class/thermal)
    - Load averages (os.getloadavg)
    - System uptime (/proc/uptime)
    - Classifications/sec from local rf_scan status endpoint

Usage:
    python3 node_agent.py --node-id <NODE_ID> --api-url https://<HOST>:8443 --api-key <KEY>

Environment variables (alternative to CLI args):
    MLRF_NODE_ID, MLRF_API_URL, MLRF_API_KEY

TLS: the bridge certificate is verified against MLRF_CA_CERT /
MLRF_CA_BUNDLE (or the system trust store). A CA file that exists but
cannot be loaded is a fatal startup error. MLRF_INSECURE_TLS=1 disables
verification (not recommended).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
import urllib.request
import urllib.error
import ssl

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("node_monitor")

AGENT_VERSION = "4.2.0"

SCAN_STATUS_URL = f"http://127.0.0.1:{os.environ.get('MLRF_STATUS_PORT', '8080')}"


# ---------------------------------------------------------------------------
# Client-cert (mTLS) auth — PKI Phase A
# ---------------------------------------------------------------------------
# When MLRF_CLIENT_CERT and MLRF_CLIENT_KEY both point at readable files the
# agent authenticates with an mTLS client certificate and omits X-API-Key.


def _client_cert_pair() -> tuple[str, str] | None:
    """Return (cert, key) paths when mTLS client-cert auth is configured."""
    cert = os.environ.get("MLRF_CLIENT_CERT", "").strip()
    key = os.environ.get("MLRF_CLIENT_KEY", "").strip()
    if cert and key and Path(cert).is_file() and Path(key).is_file():
        return cert, key
    return None


# Set True by _apply_client_cert only once the cert actually loads.
# _auth_headers keys off this — not off file presence — so a configured
# but unloadable cert pair falls back to API-key auth instead of leaving
# the agent with no credential at all.
_cert_auth_active = False


def _apply_client_cert(ctx: ssl.SSLContext) -> None:
    """Load the mTLS client certificate into *ctx* when configured."""
    global _cert_auth_active
    pair = _client_cert_pair()
    if pair is None:
        return
    try:
        ctx.load_cert_chain(certfile=pair[0], keyfile=pair[1])
        _cert_auth_active = True
        logger.info("Client-cert (mTLS) auth enabled: %s", pair[0])
    except (ssl.SSLError, OSError) as exc:
        logger.error(
            "Failed to load client cert %s: %s; falling back to API-key auth",
            pair[0],
            exc,
        )


def _auth_headers(api_key: str) -> dict:
    """Auth headers: empty under mTLS (cert is the identity), else X-API-Key."""
    return {} if _cert_auth_active else {"X-API-Key": api_key}


# ---------------------------------------------------------------------------
# SSL / TLS verification
# ---------------------------------------------------------------------------
# Verification is ON by default: the system trust store is used with
# hostname checking. Point MLRF_CA_CERT (or MLRF_CA_BUNDLE) at a CA bundle
# to trust a private/staging CA. Verification is skipped only when
# MLRF_INSECURE_TLS=1 is set explicitly -- a missing or unset CA cert never
# disables it.
#
# A CA path that does not exist logs one error and the system trust store
# is used (still verifying). A CA path that exists but cannot be loaded
# (unreadable by this user, not PEM, a private key, a directory without a
# loadable hashed CA certificate, ...) raises
# TLSConfigError: the operator pinned that CA on purpose, so trusting
# something else instead would be wrong. main() checks this once at startup
# and exits with a clear message; at runtime the request fails closed.
#
# Same policy as rf_scan, wifi_scan and detection_reporter; the block is
# inlined because this script also runs as a standalone file.

_CA_ENV_VARS = ("MLRF_CA_CERT", "MLRF_CA_BUNDLE")


class TLSConfigError(ValueError):
    """The configured CA bundle exists but cannot be loaded."""


_missing_ca_logged: set[str] = set()


def _ca_bundle_source() -> tuple[str, str] | None:
    """(env var, path) of the configured CA bundle, or None for the system store.

    A path that does not exist is logged (once) and skipped. Any path that
    exists -- even one this user cannot stat or read -- is returned, so that
    loading it fails loudly instead of silently trusting something else.
    """
    for var in _CA_ENV_VARS:
        path = os.environ.get(var, "").strip()
        if not path:
            continue
        try:
            os.stat(path)
        except (FileNotFoundError, NotADirectoryError):
            if path not in _missing_ca_logged:
                _missing_ca_logged.add(path)
                logger.error(
                    "%s=%s does not exist, falling back to the system trust store",
                    var,
                    path,
                )
            continue
        except (OSError, ValueError):
            pass  # exists but cannot be inspected (e.g. EACCES): load fails below
        return var, path
    return None


def _load_ca_context(var: str, path: str) -> ssl.SSLContext:
    """Verifying context trusting the CA bundle *path* (file or hashed dir).

    OpenSSL reads a CA directory lazily, during each handshake, so building
    a context from one succeeds even when this user cannot read it or it
    holds nothing (e.g. the empty directory Docker creates when a
    bind-mounted host file does not exist) -- and then every request fails
    with "certificate verify failed". A directory is therefore probed here:
    it must be listable and hold at least one hash-named CA certificate
    (``<8 hex digits>.<n>``, as written by ``openssl rehash``) that this
    user can load.
    """
    try:
        if not os.path.isdir(path):
            return ssl.create_default_context(cafile=path)
        entries = os.listdir(path)
        if not entries:
            raise ValueError(
                "it is an empty directory -- Docker creates one when a "
                "bind-mounted host file does not exist; mount an existing "
                "CA file"
            )
        hashed = sorted(
            name for name in entries if re.fullmatch(r"[0-9a-f]{8}\.[0-9]+", name)
        )
        if not hashed:
            raise ValueError(
                "it is a directory with no hash-named CA certificates "
                "(<8 hex digits>.0); run `openssl rehash` on it, or point "
                f"{var} at the PEM file itself"
            )
        last_error: Exception | None = None
        for name in hashed:
            try:
                probe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                probe.load_verify_locations(cafile=os.path.join(path, name))
            except (ssl.SSLError, OSError) as exc:
                last_error = exc
            else:
                return ssl.create_default_context(capath=path)
        raise ValueError(
            f"none of the {len(hashed)} hash-named CA certificates in this "
            f"directory can be loaded; last error: {last_error}"
        )
    except (ssl.SSLError, OSError, ValueError) as exc:
        uid = os.getuid() if hasattr(os, "getuid") else "?"
        raise TLSConfigError(
            f"{var}={path} cannot be loaded as a CA bundle ({exc}). It must be "
            "a PEM CA certificate file (or a directory of them indexed by "
            f"`openssl rehash`) readable by uid {uid}; fix it, or unset {var} "
            "to verify against the system trust store. TLS verification stays "
            "on -- refusing to talk to the bridge."
        ) from exc


def _insecure_tls_requested() -> bool:
    """True only when the operator explicitly set MLRF_INSECURE_TLS=1."""
    return os.environ.get("MLRF_INSECURE_TLS", "").strip() == "1"


_insecure_tls_warned = False


def _warn_insecure_tls() -> None:
    """Log the MLRF_INSECURE_TLS warning (once per process)."""
    global _insecure_tls_warned
    if _insecure_tls_warned:
        return
    _insecure_tls_warned = True
    logger.warning(
        "TLS verification DISABLED via MLRF_INSECURE_TLS=1 -- the bridge "
        "is NOT authenticated, so %s can be intercepted or forged by "
        "anyone on the network path. Set MLRF_CA_CERT instead.",
        "the API key and the remote commands carried in heartbeat "
        "responses (update, update_config, iq_capture)",
    )


def _build_ssl_context() -> ssl.SSLContext:
    """TLS context for calls to the bridge (verifying unless MLRF_INSECURE_TLS=1).

    Raises TLSConfigError when the configured CA bundle cannot be loaded.
    """
    source = _ca_bundle_source()
    if source:
        ctx = _load_ca_context(*source)
    elif _insecure_tls_requested():
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        _warn_insecure_tls()
    else:
        ctx = ssl.create_default_context()
    _apply_client_cert(ctx)
    return ctx


def _check_tls_config() -> bool:
    """Startup check: log the TLS mode and prove the CA bundle loads.

    Returns False, after logging one clear error, when the configured CA
    bundle exists but cannot be loaded; the caller then exits non-zero
    instead of dying with a traceback on its first request.
    """
    source = _ca_bundle_source()
    if source:
        try:
            _load_ca_context(*source)
        except TLSConfigError as exc:
            logger.error("%s", exc)
            return False
        logger.info("TLS verification enabled (%s=%s)", *source)
    elif _insecure_tls_requested():
        _warn_insecure_tls()
    else:
        logger.info("TLS verification enabled (system trust store)")
    return True


# ---------------------------------------------------------------------------
# Metric collectors
# ---------------------------------------------------------------------------


def get_cpu_percent() -> float:
    """Read CPU usage from /proc/stat (two samples, 0.5s apart)."""
    try:
        with open("/proc/stat") as f:
            line1 = f.readline().split()
        time.sleep(0.5)
        with open("/proc/stat") as f:
            line2 = f.readline().split()
        vals1 = [int(x) for x in line1[1:]]
        vals2 = [int(x) for x in line2[1:]]
        d_idle = vals2[3] - vals1[3]
        d_total = sum(vals2) - sum(vals1)
        if d_total == 0:
            return 0.0
        return round((1.0 - d_idle / d_total) * 100, 1)
    except Exception:
        return 0.0


def get_memory_mb() -> float:
    """Read used memory from /proc/meminfo."""
    try:
        info: dict[str, int] = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1])
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", 0)
        return round((total - available) / 1024, 0)
    except Exception:
        return 0.0


def get_disk_percent() -> float:
    """Return root partition disk usage percentage."""
    try:
        total, used, _free = shutil.disk_usage("/")
        if total == 0:
            return 0.0
        return round(100.0 * used / total, 1)
    except Exception:
        return 0.0


def get_cpu_temp() -> float | None:
    """Read CPU temperature from thermal zone (Linux)."""
    try:
        path = "/sys/class/thermal/thermal_zone0/temp"
        if os.path.exists(path):
            with open(path) as f:
                return round(int(f.read().strip()) / 1000.0, 1)
    except Exception:
        pass
    return None


def get_load_avg() -> tuple[float, float, float] | None:
    """Return 1/5/15 minute load averages."""
    try:
        l1, l5, l15 = os.getloadavg()
        return round(l1, 2), round(l5, 2), round(l15, 2)
    except Exception:
        return None


def get_uptime_seconds() -> int:
    """Read system uptime from /proc/uptime."""
    try:
        with open("/proc/uptime") as f:
            return int(float(f.readline().split()[0]))
    except Exception:
        return 0


def get_scan_status() -> dict | None:
    """Fetch scan status from local rf_scan.py status endpoint."""
    try:
        req = urllib.request.Request(SCAN_STATUS_URL, method="GET")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def get_platform_info() -> dict:
    """Detect hardware platform and OS details."""
    info: dict[str, str] = {}
    try:
        import platform

        info["platform"] = platform.platform()
        info["os"] = f"{platform.system()}-{platform.release()}"
        info["python_version"] = platform.python_version()
        # Raspberry Pi model
        model_path = Path("/proc/device-tree/model")
        if model_path.exists():
            info["platform"] = model_path.read_text().strip("\x00\n")
    except Exception:
        pass
    return info


# ---------------------------------------------------------------------------
# Heartbeat sender
# ---------------------------------------------------------------------------


def send_heartbeat(
    api_url: str,
    api_key: str,
    node_id: str,
    metrics: dict,
) -> bool:
    """Send a heartbeat to the dashboard API."""
    url = f"{api_url}/api/nodes/heartbeat"
    payload = json.dumps({"node_id": node_id, "metrics": metrics}).encode()

    try:
        # The heartbeat response carries remote commands (update,
        # update_config, iq_capture), so the bridge must be authenticated.
        # Built inside the try: a CA bundle that became unusable after
        # startup fails this heartbeat (closed) instead of killing the agent.
        # Built before the request so _auth_headers sees the loaded cert.
        ctx = _build_ssl_context()
    except TLSConfigError as e:
        logger.error("Heartbeat not sent: %s", e)
        return False

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            **_auth_headers(api_key),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read())
            if data.get("accepted"):
                logger.info(
                    "Heartbeat accepted (server_time=%s)", data.get("server_time")
                )
                cmds = data.get("pending_commands", [])
                if cmds:
                    logger.info(
                        "Pending commands: %s", [c.get("command") for c in cmds]
                    )
                    for cmd in cmds:
                        _dispatch_command(cmd)
                return True
            else:
                logger.warning("Heartbeat not accepted: %s", data)
                return False
    except urllib.error.HTTPError as e:
        logger.error("HTTP %d: %s", e.code, e.read().decode()[:200])
        return False
    except Exception as e:
        logger.error("Heartbeat failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Command dispatch
# ---------------------------------------------------------------------------


def _dispatch_command(cmd: dict) -> None:
    """Dispatch a command received from the bridge."""
    command = cmd.get("command", "")
    command_id = cmd.get("command_id", "unknown")

    if command == "iq_capture":
        params = cmd.get("params", {})
        params["command_id"] = command_id
        payload = json.dumps(params).encode()
        req = urllib.request.Request(
            f"{SCAN_STATUS_URL}/capture",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())
                logger.info("IQ capture forwarded to rf_scan: %s", result)
        except Exception as e:
            logger.error("Failed to forward IQ capture to rf_scan: %s", e)

    elif command == "update":
        _handle_update(command_id)

    elif command == "restart":
        _handle_restart(command_id)

    elif command == "update_config":
        params = cmd.get("params", {}) or {}
        try:
            from sigrift.edge.scanner_config import write_config

            path = write_config(params)
            logger.info(
                "[%s] Wrote scanner config update (keys=%s) to %s",
                command_id,
                sorted(params.keys()),
                path,
            )
        except Exception as e:
            logger.error("[%s] Failed to write scanner config: %s", command_id, e)

    elif command == "status":
        logger.info("[%s] Status check — agent running normally", command_id)

    elif command == "ping":
        logger.info("[%s] Pong", command_id)

    else:
        logger.info("Ignoring unhandled command: %s", command)


_AGENT_DIR = Path(os.environ.get("MLRF_AGENT_DIR", "/home/pi/mlrf-agent"))
_SERVICES = ["rf-edge", "mlrf-agent", "mlrf-bt-scanner", "wifi-scan"]


def _handle_update(command_id: str) -> None:
    """Pull latest code and restart all MLRF services."""
    logger.info("[%s] Starting software update...", command_id)

    # Pull latest code
    try:
        result = subprocess.run(
            ["git", "pull", "--ff-only"],
            cwd=str(_AGENT_DIR),
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            logger.info("[%s] git pull: %s", command_id, result.stdout.strip())
        else:
            logger.error("[%s] git pull failed: %s", command_id, result.stderr.strip())
            return
    except Exception as e:
        logger.error("[%s] git pull error: %s", command_id, e)
        return

    # Restart all MLRF services (self-restart last)
    for svc in _SERVICES:
        if svc == "mlrf-agent":
            continue  # restart self last
        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", svc],
                capture_output=True,
                text=True,
                timeout=30,
            )
            logger.info("[%s] Restarted %s", command_id, svc)
        except Exception as e:
            logger.warning("[%s] Failed to restart %s: %s", command_id, svc, e)

    # Restart self — systemd will re-launch us
    logger.info("[%s] Update complete, restarting mlrf-agent...", command_id)
    try:
        subprocess.Popen(["sudo", "systemctl", "restart", "mlrf-agent"])
    except Exception as e:
        logger.error("[%s] Failed to restart self: %s", command_id, e)


def _handle_restart(command_id: str) -> None:
    """Restart all MLRF services."""
    logger.info("[%s] Restarting all MLRF services...", command_id)
    for svc in _SERVICES:
        if svc == "mlrf-agent":
            continue
        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", svc],
                capture_output=True,
                text=True,
                timeout=30,
            )
            logger.info("[%s] Restarted %s", command_id, svc)
        except Exception as e:
            logger.warning("[%s] Failed to restart %s: %s", command_id, svc, e)

    logger.info("[%s] Restart complete, restarting mlrf-agent...", command_id)
    try:
        subprocess.Popen(["sudo", "systemctl", "restart", "mlrf-agent"])
    except Exception as e:
        logger.error("[%s] Failed to restart self: %s", command_id, e)


# ---------------------------------------------------------------------------
# Metrics collection
# ---------------------------------------------------------------------------


def collect_metrics() -> dict:
    """Gather all system metrics into a single dict."""
    m: dict = {
        "cpu_percent": get_cpu_percent(),
        "memory_mb": get_memory_mb(),
        "disk_percent": get_disk_percent(),
        "agent_version": AGENT_VERSION,
    }

    temp = get_cpu_temp()
    if temp is not None:
        m["cpu_temp"] = temp

    load = get_load_avg()
    if load is not None:
        m["load_1m"] = load[0]
        m["load_5m"] = load[1]
        m["load_15m"] = load[2]

    uptime = get_uptime_seconds()
    if uptime > 0:
        m["uptime_seconds"] = uptime

    # Platform info (first heartbeat only, cached)
    if not hasattr(collect_metrics, "_platform"):
        collect_metrics._platform = get_platform_info()
    m.update(collect_metrics._platform)

    # Scrape scan service for cls/sec and scan stats
    scan = get_scan_status()
    if scan:
        cls = scan.get("cls_per_sec", 0.0)
        if cls > 0:
            m["classifications_per_sec"] = round(cls, 1)
        m["scan_count"] = scan.get("scan_count", 0)
        m["capture_mode"] = scan.get("capture_mode", "unknown")
        m["anomaly_enabled"] = scan.get("anomaly_enabled", False)
        m["anomaly_count"] = scan.get("anomaly_count", 0)
        m["anomaly_baseline"] = scan.get("anomaly_baseline", "unknown")
        if "hardware" in scan:
            m["hardware"] = scan["hardware"]

    return m


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="SigRift edge node monitor agent")
    parser.add_argument("--node-id", default=os.environ.get("MLRF_NODE_ID", ""))
    parser.add_argument(
        "--api-url",
        "--bridge-url",
        default=os.environ.get(
            "MLRF_API_URL", os.environ.get("MLRF_BRIDGE_URL", "https://localhost:8443")
        ),
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("MLRF_API_KEY", os.environ.get("MLRF_BRIDGE_KEY", "")),
    )
    parser.add_argument(
        "--interval", type=int, default=30, help="Heartbeat interval in seconds"
    )
    parser.add_argument(
        "--once", action="store_true", help="Send one heartbeat and exit"
    )
    args = parser.parse_args()

    if not args.node_id:
        logger.error("--node-id or MLRF_NODE_ID is required")
        sys.exit(1)
    if not args.api_key:
        logger.error("--api-key or MLRF_API_KEY is required")
        sys.exit(1)

    logger.info(
        "SigRift node monitor v%s starting (node=%s, interval=%ds)",
        AGENT_VERSION,
        args.node_id,
        args.interval,
    )
    if not _check_tls_config():
        sys.exit(1)

    running = True

    def _stop(sig, frame):
        nonlocal running
        logger.info("Shutting down...")
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while running:
        metrics = collect_metrics()
        send_heartbeat(args.api_url, args.api_key, args.node_id, metrics)

        if args.once:
            break

        # Sleep in small increments so we can respond to signals
        for _ in range(args.interval * 2):
            if not running:
                break
            time.sleep(0.5)

    logger.info("Monitor stopped")


if __name__ == "__main__":
    main()
