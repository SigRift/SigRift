#!/usr/bin/env python3
"""Edge Bluetooth scanner for SigRift.

Scans for Bluetooth Classic and BLE devices using the Linux HCI interface,
formats results as BtScanBatch records, and POSTs them to the Bridge
controller's ``/api/bluetooth/ingest`` endpoint.

Requires:
  - Linux with BlueZ (``hcitool``, ``bluetoothctl``, or D-Bus access)
  - Bluetooth adapter (built-in on RPi5, or USB dongle)
  - Python 3.10+

Usage:
    # Standalone
    python3 -m sigrift.lib.bt_scanner \\
        --server-url https://bridge:8444 \\
        --api-key KEY --node-id node-01

    # Integrated with detection_reporter
    scanner = BtScanner(server_url, api_key, node_id)
    scanner.start()   # launches background scan thread
    scanner.stop()

The adapter is re-checked every cycle: while it is absent, replaced or
down the scanner waits and reports why to the bridge ("bluetooth" scanner
status), then resumes on its own (docs/sensor-lifecycle.md).

Environment variables:
    MLRF_BRIDGE_URL, MLRF_API_KEY, MLRF_NODE_ID,
    MLRF_BT_ADAPTER (default: hci0; "hciN", or the adapter's Bluetooth
        address, which is followed across re-plugs and renumbering),
    MLRF_BT_SCAN_INTERVAL (default: 30 seconds),
    MLRF_BT_ENABLED (default: 0, set to 1 to enable)
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sigrift.edge import sensor_presence
from sigrift.edge.scanner_status import ScannerStatusReporter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Client-cert (mTLS) auth — PKI Phase A
# ---------------------------------------------------------------------------
# When MLRF_CLIENT_CERT and MLRF_CLIENT_KEY both point at readable files the
# scanner authenticates with an mTLS client certificate and omits X-API-Key.


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
# the scanner with no credential at all.
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
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_SCAN_INTERVAL = 30  # seconds between scans
_DEFAULT_ADAPTER = "hci0"
_BLE_SCAN_DURATION = 10  # seconds for BLE scan
_MAX_BATCH = 500
_UPLOAD_TIMEOUT = 15
_BT_SYSFS = Path("/sys/class/bluetooth")
_RECHECK_INTERVAL = 5.0  # seconds between checks while the adapter is unusable
# Shutdown waits this long for a scan in progress; Docker kills after 10 s.
_STOP_TIMEOUT = 5.0


def _env_truthy(name: str, default: bool = False) -> bool:
    """Parse a truthy env var (``1/true/yes/on``). Returns ``default`` if unset."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# BT Scanner
# ---------------------------------------------------------------------------


class BtScanner:
    """Edge Bluetooth scanner that reports to the SigRift controller."""

    def __init__(
        self,
        server_url: str,
        api_key: str,
        node_id: str,
        adapter: str = _DEFAULT_ADAPTER,
        scan_interval: int = _DEFAULT_SCAN_INTERVAL,
        ca_bundle: str | None = None,
        syslog_client: Any | None = None,
        summarize: bool = True,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.node_id = node_id
        self.adapter = adapter
        self.scan_interval = scan_interval
        self.ca_bundle = ca_bundle
        self.syslog_client = syslog_client
        self.summarize = summarize
        # Kernel name the hci tools use; follows the adapter each cycle.
        # hcitool also accepts an address, so this is usable before then.
        self._hci = adapter
        # Where a by-address adapter was last found, to tell a swap there
        # from plain absence.
        self._last_hci: str | None = None
        self._presence = sensor_presence.PresenceTracker("Bluetooth", logger)
        self._down = False
        # Set by the scan methods when one ran to completion this cycle.
        self._scan_ok = False
        self._classic_failure: str | None = None
        self._status: tuple[str, str | None] = ("error", sensor_presence.STARTING)

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._scan_count = 0
        # Last failure detail per BLE method, for once-per-cause logging.
        self._ble_failures: dict[str, str] = {}
        self._upload_count = 0
        self._error_count = 0
        # Per-device rolling aggregator used when ``summarize`` is True.
        self._agg: dict[str, dict[str, Any]] = {}
        self._agg_total_obs = 0
        self._agg_window_start: float = time.time()

    # -- Lifecycle --------------------------------------------------------

    def start(self) -> None:
        """Start the background scan thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._scan_loop,
            daemon=True,
            name="bt-scanner",
        )
        self._thread.start()
        logger.info(
            "Bluetooth scanner started on %s (interval=%ds)",
            self._hci_label(),
            self.scan_interval,
        )

    def stop(self, timeout: float = 15) -> None:
        """Stop the background scan thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info(
            "Bluetooth scanner stopped: %d scans, %d uploads, %d errors",
            self._scan_count,
            self._upload_count,
            self._error_count,
        )

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stats(self) -> dict[str, Any]:
        return {
            "running": self.is_running,
            "adapter": self.adapter,
            "scan_count": self._scan_count,
            "upload_count": self._upload_count,
            "error_count": self._error_count,
        }

    def capture_status(self) -> tuple[str, str | None]:
        """The last cycle's outcome, as a ScannerStatusReporter capture_state."""
        thread = self._thread
        if thread is not None and not thread.is_alive():
            # A dead scan thread must not leave a stale "running" lease.
            return "error", sensor_presence.CAPTURE_FAILED
        return self._status

    def _hci_label(self) -> str:
        # Logs and syslog name the kernel interface, never an address.
        return self._hci if self._hci.startswith("hci") else "Bluetooth adapter"

    # -- Adapter ----------------------------------------------------------

    def _resolve_adapter(self) -> sensor_presence.Presence:
        presence = sensor_presence.find_bluetooth_adapter(self.adapter, sysfs=_BT_SYSFS)
        if presence.state == "present":
            self._last_hci = presence.detail["hci"]
            return presence
        last = self._last_hci
        # Selected by address: another adapter where it was is a swap. An
        # "hciN" setting has no identity, so whatever holds it is used.
        if last is not None and not self.adapter.startswith("hci"):
            try:
                there = (_BT_SYSFS / last).exists()
            except OSError:
                there = False
            address = sensor_presence.bluetooth_address(last) if there else None
            if address is not None and address != self.adapter.lower():
                return sensor_presence.Presence("changed")
        return presence

    def _adapter_problem(self) -> str | None:
        """None when the adapter can scan now, else the status reason."""
        presence = self._resolve_adapter()
        self._presence.update(presence)
        if presence.state != "present":
            # Re-announce "down" if it comes back down after an absence.
            self._down = False
            return self._presence.reason
        self._hci = presence.detail["hci"]
        # Bringing it up needs a capability this service does not have, so
        # only wait for the host (or the operator) to do it.
        down = not check_adapter(self._hci)
        if down != self._down:
            self._down = down
            if down:
                logger.warning(
                    "Bluetooth adapter %s is down; waiting for it to come up",
                    self._hci,
                )
            else:
                logger.info("Bluetooth adapter %s is up", self._hci)
        return sensor_presence.CAPTURE_FAILED if down else None

    # -- Scan loop --------------------------------------------------------

    def _scan_loop(self) -> None:
        """Main scan loop."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._cycle())

    def _cycle(self) -> float:
        """One scan cycle; returns the seconds to wait before the next one."""
        from sigrift.edge.scanner_config import reload_summarize

        # Poll the on-disk config for a runtime summarize toggle
        # written by node_agent in response to bridge update_config.
        self.summarize = reload_summarize(self.summarize)
        problem = self._adapter_problem()
        if problem is not None:
            self._status = ("error", problem)
            return min(_RECHECK_INTERVAL, self.scan_interval)
        try:
            devices = self._scan()
            self._scan_count += 1
            if not self._scan_ok:
                # A scan that failed because the adapter just left is
                # reported as that, not as a capture failure.
                problem = self._adapter_problem() or sensor_presence.CAPTURE_FAILED
            # Zero devices from a working scan is still "running".
            self._status = ("error", problem) if problem else ("running", None)
            if devices:
                if self.summarize:
                    self._absorb(devices)
                    self._upload_summary()
                    self._upload_count += 1
                else:
                    self._upload(devices)
                    self._upload_count += 1
                self._forward_to_syslog(devices)
        except Exception as exc:
            self._error_count += 1
            logger.warning("BT scan error: %s", exc)
        return self.scan_interval

    # -- Scanning ---------------------------------------------------------

    def _scan(self) -> list[dict[str, Any]]:
        """Perform a BLE + Classic scan and return device records."""
        devices: list[dict[str, Any]] = []
        # Either kind completing is a usable adapter: an LE-only dongle
        # always fails the Classic inquiry.
        self._scan_ok = False

        # Try BLE scan first (more common, lower power)
        try:
            ble_devices = self._scan_ble()
            devices.extend(ble_devices)
        except Exception as exc:
            logger.warning("BLE scan failed: %s", exc)

        # Try Classic scan
        try:
            classic_devices = self._scan_classic()
            devices.extend(classic_devices)
        except Exception as exc:
            logger.warning("Classic BT scan failed: %s", exc)

        if devices:
            logger.info(
                "BT scan found %d devices (%d BLE, %d Classic)",
                len(devices),
                sum(1 for d in devices if d.get("device_type") == "ble"),
                sum(1 for d in devices if d.get("device_type") == "classic"),
            )

        return devices[:_MAX_BATCH]

    def _scan_ble(self) -> list[dict[str, Any]]:
        """Scan for BLE devices using hcitool lescan + hcidump."""
        devices: list[dict[str, Any]] = []

        # Method 1: Try bluetoothctl (more reliable on modern systems).
        # Requires the host BlueZ daemon over D-Bus; in a container the
        # host's D-Bus policy typically only admits root or the
        # ``bluetooth`` group, in which case bluetoothctl prints a D-Bus
        # error, exits 0, and yields nothing — so an empty result here
        # must fall through to the raw-HCI method below, never return.
        try:
            scan_proc = subprocess.run(
                ["bluetoothctl", "--timeout", str(_BLE_SCAN_DURATION), "scan", "on"],
                capture_output=True,
                text=True,
                timeout=_BLE_SCAN_DURATION + 5,
            )
            # Parse bluetoothctl output for discovered devices
            result2 = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result2.stdout.splitlines():
                # Format: "Device XX:XX:XX:XX:XX:XX DeviceName"
                parts = line.strip().split(None, 2)
                if len(parts) >= 2 and parts[0] == "Device":
                    addr = parts[1]
                    name = parts[2] if len(parts) > 2 else ""
                    rssi = self._get_rssi(addr)
                    devices.append(
                        {
                            "device_addr": addr,
                            "device_name": name,
                            "device_type": "ble",
                            "rssi_dbm": rssi,
                            "connectable": True,
                        }
                    )
            if devices:
                # Not counted toward _scan_ok: this list is BlueZ's cache for
                # the default controller, not proof the selected one scanned.
                return devices
            self._note_ble_method_failure(
                "bluetoothctl",
                (scan_proc.stderr or scan_proc.stdout or "").strip()[-200:],
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self._note_ble_method_failure("bluetoothctl", str(exc))

        # Method 2: hcitool lescan (fallback). hcitool block-buffers
        # stdout when it is a pipe, so results sit in its stdio buffer
        # until the process flushes. SIGINT is what guarantees they
        # arrive: hcitool installs a SIGINT handler that stops the scan
        # and exits normally, flushing stdio on the way out. (stdbuf -oL
        # also helps, but only when hcitool has NO file capabilities —
        # a setcap binary execs in secure-execution mode, where ld.so
        # drops the LD_PRELOAD that stdbuf relies on — so it cannot be
        # the primary mechanism in the container, where the image
        # setcaps hcitool for non-root LE scans.)
        lescan_cmd = ["hcitool", "-i", self._hci, "lescan", "--duplicates"]
        if shutil.which("stdbuf"):
            lescan_cmd = ["stdbuf", "-oL", *lescan_cmd]
        try:
            proc = subprocess.Popen(
                lescan_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            time.sleep(_BLE_SCAN_DURATION)
            proc.send_signal(signal.SIGINT)
            try:
                returncode = proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                # SIGINT handler didn't exit (or no handler — e.g. the
                # stdbuf wrapper on some coreutils versions); fall back
                # to SIGTERM and accept possible buffer loss.
                proc.terminate()
                returncode = proc.wait(timeout=3)

            stdout = (
                proc.stdout.read().decode("utf-8", errors="replace")
                if proc.stdout
                else ""
            )
            seen: set[str] = set()
            for line in stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) >= 1 and ":" in parts[0] and len(parts[0]) == 17:
                    addr = parts[0].upper()
                    if addr in seen:
                        continue
                    seen.add(addr)
                    name = parts[1] if len(parts) > 1 else ""
                    if name == "(unknown)":
                        name = ""
                    devices.append(
                        {
                            "device_addr": addr,
                            "device_name": name,
                            "device_type": "ble",
                            "rssi_dbm": 0.0,
                            "connectable": True,
                        }
                    )
            # hcitool exits 0 after a SIGINT-stopped scan; it exits 1 when
            # it cannot set up the scan (adapter gone, down, no permission).
            if devices or returncode == 0:
                self._scan_ok = True
            if not devices:
                stderr = (
                    proc.stderr.read().decode("utf-8", errors="replace")
                    if proc.stderr
                    else ""
                )
                self._note_ble_method_failure("hcitool lescan", stderr.strip()[-200:])
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            self._note_ble_method_failure("hcitool lescan", str(exc))

        return devices

    def _note_ble_method_failure(self, method: str, detail: str) -> None:
        """Log a BLE scan method producing nothing — once per distinct cause.

        Both BLE methods can fail persistently (D-Bus policy, missing
        CAP_NET_ADMIN) while the scan loop keeps running every cycle;
        logging the first occurrence at WARNING and repeats at DEBUG
        keeps the failure visible without flooding the log. Tracked per
        method — both methods failing every cycle is the steady state on
        a misconfigured host, and a shared slot would alternate and warn
        every scan.
        """
        if self._ble_failures.get(method) != detail:
            self._ble_failures[method] = detail
            logger.warning(
                "BLE scan via %s produced no devices: %s",
                method,
                detail or "(no diagnostic output)",
            )
        else:
            logger.debug("BLE scan via %s still failing: %s", method, detail)

    def _scan_classic(self) -> list[dict[str, Any]]:
        """Scan for Classic Bluetooth devices using hcitool inq."""
        devices: list[dict[str, Any]] = []

        try:
            result = subprocess.run(
                ["hcitool", "-i", self._hci, "inq", "--flush"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode == 0:
                self._scan_ok = True
                self._classic_failure = None
            else:
                self._note_classic_failure(
                    (result.stderr or result.stdout or "").strip()[-200:]
                )
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or "Inquiring" in line:
                    continue
                parts = line.split()
                if len(parts) >= 1 and ":" in parts[0] and len(parts[0]) == 17:
                    addr = parts[0].upper()
                    # Parse class if present
                    device_class = 0
                    if len(parts) >= 3 and parts[1].startswith("class:"):
                        try:
                            device_class = int(parts[2], 16)
                        except ValueError:
                            pass

                    # Get device name
                    name = self._get_name(addr)

                    devices.append(
                        {
                            "device_addr": addr,
                            "device_name": name,
                            "device_type": "classic",
                            "device_class": device_class,
                            "rssi_dbm": 0.0,
                            "connectable": True,
                        }
                    )
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            self._note_classic_failure(str(exc))

        return devices

    def _note_classic_failure(self, detail: str) -> None:
        # Once per distinct cause, like _note_ble_method_failure.
        if self._classic_failure != detail:
            self._classic_failure = detail
            logger.warning(
                "Classic BT scan failed: %s", detail or "(no diagnostic output)"
            )
        else:
            logger.debug("Classic BT scan still failing: %s", detail)

    def _get_rssi(self, addr: str) -> float:
        """Get RSSI for a device (best-effort)."""
        try:
            result = subprocess.run(
                ["hcitool", "-i", self._hci, "rssi", addr],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.splitlines():
                if "RSSI" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return float(parts[-1].strip())
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired, ValueError):
            pass
        return 0.0

    def _get_name(self, addr: str) -> str:
        """Get the friendly name for a device."""
        try:
            result = subprocess.run(
                ["hcitool", "-i", self._hci, "name", addr],
                capture_output=True,
                text=True,
                timeout=5,
            )
            name = result.stdout.strip()
            return name if name else ""
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            return ""

    # -- Syslog forwarding ------------------------------------------------

    def _forward_to_syslog(self, devices: list[dict[str, Any]]) -> None:
        """Forward BT scan results to syslog if a client is configured."""
        if self.syslog_client is None:
            return
        try:
            sd = {
                "mlrf@0": {
                    "type": "bt_scan",
                    "node": self.node_id,
                    "adapter": self._hci_label(),
                    "device_count": str(len(devices)),
                    "ble_count": str(
                        sum(1 for d in devices if d.get("device_type") == "ble")
                    ),
                    "classic_count": str(
                        sum(1 for d in devices if d.get("device_type") == "classic")
                    ),
                },
            }
            message = (
                f"BT scan: {len(devices)} devices found on {self._hci_label()} "
                f"(scan #{self._scan_count})"
            )
            self.syslog_client.send(
                "info", message, structured_data=sd, msg_id="bt_scan"
            )
        except Exception as exc:
            logger.debug("Syslog forward failed for BT scan: %s", exc)

    # -- Upload -----------------------------------------------------------

    def _upload(self, devices: list[dict[str, Any]]) -> None:
        """Upload scanned devices to the Bridge controller."""
        payload = {
            "node_id": self.node_id,
            "records": devices,
        }

        body = json.dumps(payload).encode("utf-8")
        compressed = gzip.compress(body)

        url = f"{self.server_url}/api/bluetooth/ingest"
        req = urllib.request.Request(
            url,
            data=compressed,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                **_auth_headers(self.api_key),
            },
        )

        ctx = ssl.create_default_context()
        if self.ca_bundle:
            ctx.load_verify_locations(self.ca_bundle)
        _apply_client_cert(ctx)

        try:
            resp = urllib.request.urlopen(req, timeout=_UPLOAD_TIMEOUT, context=ctx)
            data = json.loads(resp.read().decode())
            logger.info(
                "BT upload: %d/%d accepted, %d anomalies",
                data.get("inserted", 0),
                len(devices),
                data.get("anomalies", 0),
            )
        except urllib.error.HTTPError as exc:
            logger.warning("BT upload HTTP %d: %s", exc.code, exc.reason)
        except Exception as exc:
            logger.warning("BT upload failed: %s", exc)

    # -- Summarize --------------------------------------------------------

    def _absorb(self, devices: list[dict[str, Any]]) -> None:
        """Fold scan-window devices into the per-address aggregator."""
        now_iso = datetime.now(timezone.utc).isoformat()
        for dev in devices:
            addr = dev.get("device_addr") or ""
            if not addr:
                continue
            self._agg_total_obs += 1
            rssi = float(dev.get("rssi_dbm") or -100.0)
            entry = self._agg.get(addr)
            if entry is None:
                self._agg[addr] = {
                    "device_addr": addr,
                    "device_name": dev.get("device_name") or "",
                    "device_type": dev.get("device_type") or "unknown",
                    "manufacturer_id": dev.get("manufacturer_id"),
                    "manufacturer": dev.get("manufacturer") or "",
                    "rssi_sum": rssi,
                    "rssi_max": rssi,
                    "observation_count": 1,
                    "channel": int(dev.get("channel") or 0),
                    "service_uuids": list(dev.get("service_uuids") or []),
                    "first_seen": now_iso,
                    "last_seen": now_iso,
                }
            else:
                entry["rssi_sum"] += rssi
                if rssi > entry["rssi_max"]:
                    entry["rssi_max"] = rssi
                entry["observation_count"] += 1
                entry["last_seen"] = now_iso
                # Keep the most recently seen name/type if previously unknown.
                if dev.get("device_name") and not entry["device_name"]:
                    entry["device_name"] = dev["device_name"]
                if dev.get("device_type") and entry["device_type"] == "unknown":
                    entry["device_type"] = dev["device_type"]
                # Union service UUIDs.
                for u in dev.get("service_uuids") or []:
                    if u not in entry["service_uuids"]:
                        entry["service_uuids"].append(u)

    def _upload_summary(self) -> None:
        """Flush the aggregator to the Bridge as one summary payload."""
        if not self._agg:
            return

        devices_out: list[dict[str, Any]] = []
        for entry in self._agg.values():
            n = entry["observation_count"] or 1
            devices_out.append(
                {
                    "device_addr": entry["device_addr"],
                    "device_name": entry["device_name"],
                    "device_type": entry["device_type"],
                    "manufacturer_id": entry["manufacturer_id"],
                    "manufacturer": entry["manufacturer"],
                    "rssi_max_dbm": entry["rssi_max"],
                    "rssi_avg_dbm": entry["rssi_sum"] / n,
                    "observation_count": n,
                    "channel": entry["channel"],
                    "service_uuids": entry["service_uuids"],
                    "first_seen": entry["first_seen"],
                    "last_seen": entry["last_seen"],
                }
            )

        scan_period_s = max(time.time() - self._agg_window_start, 0.0)
        payload = {
            "node_id": self.node_id,
            "scan_period_s": scan_period_s,
            "total_observations": self._agg_total_obs,
            "devices": devices_out,
        }

        body = json.dumps(payload).encode("utf-8")
        compressed = gzip.compress(body)

        url = f"{self.server_url}/api/bluetooth/ingest-summary"
        req = urllib.request.Request(
            url,
            data=compressed,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                **_auth_headers(self.api_key),
            },
        )

        ctx = ssl.create_default_context()
        if self.ca_bundle:
            ctx.load_verify_locations(self.ca_bundle)
        _apply_client_cert(ctx)

        try:
            resp = urllib.request.urlopen(req, timeout=_UPLOAD_TIMEOUT, context=ctx)
            data = json.loads(resp.read().decode())
            logger.info(
                "BT summary: %d devices / %d observations -> inserted=%d",
                len(devices_out),
                self._agg_total_obs,
                data.get("inserted", 0),
            )
            # Reset window only on successful flush.
            self._agg.clear()
            self._agg_total_obs = 0
            self._agg_window_start = time.time()
        except urllib.error.HTTPError as exc:
            logger.warning("BT summary HTTP %d: %s", exc.code, exc.reason)
        except Exception as exc:
            logger.warning("BT summary upload failed: %s", exc)


# ---------------------------------------------------------------------------
# Adapter check
# ---------------------------------------------------------------------------


def check_adapter(adapter: str = _DEFAULT_ADAPTER) -> bool:
    """Check if a Bluetooth adapter is available."""
    try:
        result = subprocess.run(
            ["hciconfig", adapter],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "UP RUNNING" in result.stdout
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def enable_adapter(adapter: str = _DEFAULT_ADAPTER) -> bool:
    """Attempt to bring up a Bluetooth adapter."""
    try:
        subprocess.run(
            ["hciconfig", adapter, "up"],
            capture_output=True,
            timeout=5,
        )
        return check_adapter(adapter)
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Edge Bluetooth scanner for SigRift")
    parser.add_argument(
        "--server-url",
        default=os.environ.get("MLRF_BRIDGE_URL", "https://localhost:8444"),
    )
    parser.add_argument("--api-key", default=os.environ.get("MLRF_API_KEY", ""))
    parser.add_argument("--node-id", default=os.environ.get("MLRF_NODE_ID", "node-01"))
    parser.add_argument(
        "--adapter", default=os.environ.get("MLRF_BT_ADAPTER", _DEFAULT_ADAPTER)
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(
            os.environ.get("MLRF_BT_SCAN_INTERVAL", str(_DEFAULT_SCAN_INTERVAL))
        ),
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.environ.get("MLRF_CA_BUNDLE"),
        help="Path to CA bundle for TLS verification",
    )
    parser.add_argument(
        "--no-summarize",
        action="store_true",
        default=_env_truthy("MLRF_SUMMARIZE", default=True) is False,
        help=(
            "Disable edge aggregation; upload raw per-scan device records "
            "(env: MLRF_SUMMARIZE=0)"
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )

    stop_event = threading.Event()

    def handle_signal(signum: int, frame: Any) -> None:
        logger.info("Signal %d received, stopping...", signum)
        stop_event.set()

    # Installed first so SIGTERM exits 0 from any state.
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if not args.api_key:
        logger.error("No API key provided (--api-key or MLRF_API_KEY)")
        sys.exit(1)

    # No adapter check here: an absent or down adapter is waited for by the
    # scan loop, which reports why, instead of exiting into a restart loop.
    scanner = BtScanner(
        server_url=args.server_url,
        api_key=args.api_key,
        node_id=args.node_id,
        adapter=args.adapter,
        scan_interval=args.interval,
        ca_bundle=args.ca_bundle,
        summarize=not args.no_summarize,
    )

    def tls_context() -> ssl.SSLContext:
        # Same trust and client cert as the uploads.
        ctx = ssl.create_default_context()
        if args.ca_bundle:
            ctx.load_verify_locations(args.ca_bundle)
        _apply_client_cert(ctx)
        return ctx

    status: ScannerStatusReporter | None
    try:
        status = ScannerStatusReporter(
            args.server_url,
            args.node_id,
            "bluetooth",
            tls_context,
            lambda: _auth_headers(args.api_key),
            scanner.capture_status,
        )
    except ValueError:
        # Status is best effort; scanning does not depend on it.
        logger.warning("Scanner status disabled: invalid bridge URL or node id")
        status = None

    scanner.start()
    if status is not None:
        status.start()
    logger.info("Bluetooth scanner running. Press Ctrl+C to stop.")

    stop_event.wait()
    scanner.stop(timeout=_STOP_TIMEOUT)
    if status is not None:
        status.stop()


if __name__ == "__main__":
    main()
