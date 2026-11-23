#!/usr/bin/env python3
"""Edge Zigbee scanner for SigRift.

Scans for Zigbee networks and devices using a SONOFF ZBDongle-E
(Silicon Labs EFR32MG21, EZSP protocol) or compatible 802.15.4
coordinator dongle.  Performs energy scans and active network scans
across Zigbee channels 11-26, formats results as ZigbeeScanBatch
records, and POSTs them to the Bridge's ``/api/zigbee/ingest`` endpoint.

Requires:
  - Linux with pyserial
  - SONOFF ZBDongle-E (EFR32MG21) or ZBDongle-P (CC2652P)
  - Python 3.10+
  - bellows (for EZSP) or zigpy-znp (for Z-Stack) — auto-detected

Usage:
    # Standalone
    python3 -m sigrift.bridge.zigbee_scanner \\
        --server-url https://bridge:8444 \\
        --api-key KEY --node-id node-01

    # With specific device
    python3 -m sigrift.bridge.zigbee_scanner \\
        --device /dev/ttyACM0 --baud 115200

Environment variables:
    MLRF_BRIDGE_URL, MLRF_BRIDGE_KEY, MLRF_NODE_ID,
    MLRF_ZB_DEVICE (default: auto-detect),
    MLRF_ZB_SCAN_INTERVAL (default: 60 seconds),
    MLRF_ZB_ENABLED (default: 0, set to 1 to enable),
    MLRF_CA_BUNDLE (path to CA bundle for TLS)
"""

from __future__ import annotations

import argparse
import glob
import gzip
import hashlib
import json
import logging
import os
import random
import re
import signal
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_SCAN_INTERVAL = 60  # seconds between scans
_ZIGBEE_CHANNELS = list(range(11, 27))  # 802.15.4 channels 11-26 (2.4 GHz)
_MAX_BATCH = 500
_UPLOAD_TIMEOUT = 15
_DEFAULT_BAUD = 115200

# Known Zigbee manufacturer codes -> names
# Source: Zigbee Alliance / Connectivity Standards Alliance registry
_MANUFACTURER_CODES: dict[int, str] = {
    # Silicon/chip vendors
    0x1002: "Ember/Silicon Labs",
    0x1005: "Chipcon/TI",
    0x1007: "Freescale",
    0x100B: "Philips",
    0x100D: "Cirronet",
    0x1014: "MMB Research",
    0x1015: "Digi International",
    0x1017: "Telegesis",
    0x101E: "Ember",
    0x1020: "GreenPeak",
    0x1021: "Legrand",
    0x1037: "NXP",
    0x1038: "Centralite",
    0x103B: "CentraLite Systems",
    0x103E: "SmartThings",
    # Lighting
    0x1047: "IKEA",
    0x1049: "OSRAM",
    0x104E: "Samsung",
    0x1050: "Lutron",
    0x1056: "Innr",
    0x1057: "Müller Licht",
    0x105E: "Sengled",
    0x1060: "Cree",
    0x1064: "LEDVANCE",
    0x1066: "Danfoss",
    0x106E: "Aurora",
    0x1071: "iluminize",
    # Home automation
    0x10F2: "Ubisys",
    0x1078: "Busch-Jaeger",
    0x107E: "Stelpro",
    0x1082: "Develco",
    0x1086: "Trust",
    0x108E: "EDP",
    0x1092: "Climax",
    0x1094: "Bitron",
    0x109A: "Datek",
    0x10A0: "Heiman",
    0x10AA: "Konke",
    0x10AE: "Salus",
    0x10B0: "Bosch",
    0x10B4: "Jasco",
    0x10B6: "Nue / 3A Smart Home",
    0x10B8: "Kwikset",
    0x10C4: "Yale",
    0x10C6: "Keen Home",
    0x10D0: "Visonic",
    0x10D2: "Lumi United / Terncy",
    0x10E0: "iHorn",
    0x10F0: "Eurotronic",
    # Major IoT brands
    0x1100: "Universal Electronics",
    0x1105: "Danalock",
    0x110A: "Schneider Electric",
    0x110C: "Wiser / Schneider",
    0x110E: "Computime",
    0x1110: "Third Reality",
    0x1116: "Orvibo",
    0x111A: "Leedarson",
    0x1124: "Netvox",
    0x1126: "iMagic",
    0x1130: "Dawon DNS",
    0x1135: "Sinope",
    0x1137: "OWON",
    0x113C: "SiHAS / Samsung",
    0x1141: "Xiaomi",
    0x1144: "Lidl / SilverCrest",
    0x114B: "Paulmann",
    0x1153: "Gledopto",
    0x115F: "Aqara",
    0x1160: "Lonsonho",
    0x1166: "Moes",
    0x1168: "Tuya",
    0x116C: "Zemismart",
    0x116E: "Nous",
    0x117C: "SONOFF/ITEAD",
    0x117E: "eWeLink",
    0x1180: "Linkind",
    0x1184: "WETEN",
    0x1188: "Mercator",
    0x1189: "ShinaSystem",
    0x1190: "Namron",
    0x1194: "Candeo",
    0x1198: "TuYa Sub-Brand",
    0x119C: "Mujjo",
    0x11A0: "Ecozy",
    0x11A4: "Zemiron",
}


# ---------------------------------------------------------------------------
# Serial device auto-detection
# ---------------------------------------------------------------------------


def find_zigbee_device() -> str | None:
    """Auto-detect a Zigbee USB dongle serial device.

    Checks common paths and uses udevadm to identify SONOFF/Silicon Labs
    devices.  Returns the device path or None.
    """
    # Check common serial device paths
    candidates = sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))

    for dev in candidates:
        try:
            result = subprocess.run(
                ["udevadm", "info", "--name", dev, "--query=all"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.lower()
            # SONOFF ZBDongle-E uses CP2102N or CH9102F USB-UART bridge
            # SONOFF ZBDongle-P uses CC2652P (shows as ACM device)
            if any(
                kw in output
                for kw in [
                    "sonoff",
                    "itead",
                    "cp2102",
                    "ch9102",
                    "cc2652",
                    "cc2531",
                    "efr32",
                    "silicon_labs",
                    "1a86:55d4",  # CH9102F VID:PID
                    "10c4:ea60",  # CP2102N VID:PID (Silicon Labs)
                ]
            ):
                logger.info("Auto-detected Zigbee dongle at %s", dev)
                return dev
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue

    # Fallback: if only one serial device exists, use it
    if len(candidates) == 1:
        logger.info("Single serial device found, using %s", candidates[0])
        return candidates[0]

    return None


def check_device(device: str) -> bool:
    """Check if a serial device exists and is accessible."""
    import stat as stat_mod

    try:
        st = os.stat(device)
        return stat_mod.S_ISCHR(st.st_mode)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# EZSP Serial Scanner (for EFR32MG21 / SONOFF ZBDongle-E)
# ---------------------------------------------------------------------------


class EZSPScanner:
    """Minimal EZSP (EmberZNet Serial Protocol) scanner.

    Performs energy detection and active network scans via the EZSP
    interface without requiring the full zigpy/bellows stack.  Falls
    back to a simpler serial probe if EZSP communication fails.

    This is intentionally lightweight — we only need scanning, not
    full coordinator functionality.
    """

    # EZSP frame constants
    EZSP_VERSION = 0x00
    EZSP_NETWORK_STATE = 0x18
    EZSP_START_SCAN = 0x1A
    EZSP_SCAN_COMPLETE = 0x1C
    EZSP_ENERGY_SCAN_RESULT = 0x48
    EZSP_NETWORK_FOUND = 0x1B

    # Scan types
    ENERGY_SCAN = 0x00
    ACTIVE_SCAN = 0x03

    def __init__(self, device: str, baud: int = _DEFAULT_BAUD) -> None:
        self.device = device
        self.baud = baud
        self._seq = 0
        self._ser = None
        self._lock = threading.Lock()
        self._scan_results: list[dict] = []
        self._energy_results: dict[int, int] = {}
        self._use_bellows = False

    def open(self) -> bool:
        """Open serial connection and negotiate EZSP version."""
        try:
            import serial
        except ImportError:
            logger.error("pyserial not installed. Run: pip install pyserial")
            return False

        try:
            self._ser = serial.Serial(
                self.device,
                self.baud,
                timeout=2,
                write_timeout=2,
            )
            # Reset the dongle
            self._ser.dtr = False
            time.sleep(0.1)
            self._ser.dtr = True
            time.sleep(0.5)
            self._ser.reset_input_buffer()
            logger.info("Opened Zigbee dongle at %s @ %d baud", self.device, self.baud)
            return True
        except Exception as exc:
            logger.error("Failed to open %s: %s", self.device, exc)
            return False

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            self._ser.close()

    def scan_networks(self, duration_per_channel: int = 3) -> list[dict]:
        """Perform active + passive scanning for comprehensive device discovery.

        Combines active network scan (finds coordinators/PANs) with
        passive 802.15.4 frame capture (finds end devices, routers).
        Returns merged list of discovered device dicts.
        """
        # Release serial port so zigpy-cli / bellows subprocesses can use it
        if self._ser and self._ser.is_open:
            self._ser.close()

        # Active scan: finds PANs and coordinators
        active_results = self._scan_via_zigpy_cli()
        if active_results is None:
            active_results = self._scan_via_bellows()
        if active_results is None:
            # Reopen for serial probe fallback
            self.open()
            active_results = self._scan_via_serial_probe()

        # Passive scan: finds individual devices by sniffing frames
        passive_results = self.scan_passive(dwell_per_channel=duration_per_channel)

        # Merge: passive results fill in devices that active scan misses
        seen_addrs: set[str] = set()
        merged: list[dict] = []
        for d in active_results:
            key = d.get("ieee_addr", "")
            if key:
                seen_addrs.add(key)
            merged.append(d)

        for d in passive_results:
            key = d.get("ieee_addr", "")
            if key and key not in seen_addrs:
                seen_addrs.add(key)
                merged.append(d)

        return merged

    def _find_venv_bin(self) -> str:
        """Find the venv bin directory that has zigpy-cli installed.

        Checks for a venv at mlrf-agent/venv first, then falls back
        to the directory containing the current interpreter.
        """
        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidates = [
            os.path.join(script_dir, "venv", "bin"),
            os.path.expanduser("~/mlrf-agent/venv/bin"),
        ]
        for bin_dir in candidates:
            if os.path.exists(os.path.join(bin_dir, "zigpy")):
                return bin_dir
        return os.path.dirname(sys.executable)

    def _scan_via_zigpy_cli(self) -> list[dict] | None:
        """Use zigpy-cli network-scan for active scanning."""
        bin_dir = self._find_venv_bin()
        zigpy_bin = os.path.join(bin_dir, "zigpy")
        if not os.path.exists(zigpy_bin):
            logger.info("zigpy binary not found at %s", zigpy_bin)
            return None

        logger.info("zigpy-cli: starting network-scan via %s", zigpy_bin)

        try:
            # Ensure network is formed (required before scanning)
            self._ensure_network_formed(zigpy_bin)

            # Use Popen + communicate so we capture output on timeout
            proc = subprocess.Popen(
                [
                    zigpy_bin,
                    "radio",
                    "--baudrate",
                    str(self.baud),
                    "ezsp",
                    self.device,
                    "network-scan",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate(timeout=5)

            if stdout:
                logger.info(
                    "zigpy network-scan output (%d bytes): %.200s",
                    len(stdout),
                    stdout.replace("\n", " "),
                )
                networks = self._parse_zigpy_network_scan(stdout)
                if networks:
                    logger.info("zigpy network-scan found %d networks", len(networks))
                    return networks
                logger.info("zigpy network-scan: output present but no networks parsed")
            else:
                logger.info("zigpy network-scan: no stdout captured")

            if stderr:
                logger.info("zigpy network-scan stderr: %.300s", stderr.strip())
            return None
        except FileNotFoundError:
            logger.info("zigpy-cli binary not found at expected path")
            return None
        except Exception as exc:
            logger.info("zigpy network-scan error: %s: %s", type(exc).__name__, exc)
            return None

    _network_formed = False

    def _ensure_network_formed(self, zigpy_bin: str) -> None:
        """Form a Zigbee network if the dongle has none (required for scanning).

        Only runs once per process lifetime — the network persists across
        reboots in the dongle's flash.
        """
        if EZSPScanner._network_formed:
            return
        try:
            result = subprocess.run(
                [
                    zigpy_bin,
                    "radio",
                    "--baudrate",
                    str(self.baud),
                    "ezsp",
                    self.device,
                    "form",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("Zigbee network formed on dongle")
            else:
                logger.debug("Network form: %s", result.stderr.strip()[:200])
            EZSPScanner._network_formed = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _parse_zigpy_network_scan(self, output: str) -> list[dict]:
        """Parse zigpy-cli network-scan output.

        Format per line:
        channel: 25, network: 0x1A2B (00:11:22:33:44:55:66:77), permitting joins: 0, nwk update id: 0, lqi: 152, rssi: -62
        """
        networks: list[dict] = []
        seen_pans: set[str] = set()

        for line in output.splitlines():
            m = re.match(
                r"\s*channel:\s*(\d+),\s*network:\s*(0x[0-9a-fA-F]+)\s*"
                r"\(([0-9a-f:]+)\).*?"
                r"lqi:\s*(\d+),\s*rssi:\s*(-?\d+)",
                line,
                re.IGNORECASE,
            )
            if not m:
                continue

            ch = int(m.group(1))
            pan_id = m.group(2).upper()
            ext_pan = m.group(3)
            lqi = int(m.group(4))
            rssi = int(m.group(5))

            # Deduplicate — network-scan runs many passes
            key = f"{pan_id}:{ch}"
            if key in seen_pans:
                continue
            seen_pans.add(key)

            # Check for permit-join and security from line
            permit = 0
            pm = re.search(r"permitting joins:\s*(\d)", line)
            if pm:
                permit = int(pm.group(1))

            networks.append(
                {
                    "ieee_addr": ext_pan,
                    "short_addr": "0x0000",
                    "device_name": f"PAN {pan_id}" + (" (joining)" if permit else ""),
                    "device_type": "coordinator",
                    "pan_id": pan_id,
                    "extended_pan_id": ext_pan,
                    "channel": ch,
                    "rssi_dbm": float(rssi),
                    "lqi": lqi,
                    "manufacturer_code": 0,
                    "manufacturer": "",
                    "clusters": [],
                    "endpoints": [],
                    "power_source": "unknown",
                    "profile_id": "",
                    "stack_profile": "zigbee_pro",
                    "security_enabled": 1,  # almost all production networks use security
                    "parent_addr": "",
                }
            )

        logger.info("zigpy network-scan found %d unique networks", len(networks))
        return networks

    def _scan_via_bellows(self) -> list[dict] | None:
        """Use bellows CLI for network scanning (legacy fallback)."""
        bin_dir = self._find_venv_bin()
        bellows_bin = os.path.join(bin_dir, "bellows")
        try:
            result = subprocess.run(
                [
                    bellows_bin,
                    "-d",
                    self.device,
                    "-b",
                    str(self.baud),
                    "scan",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode != 0:
                logger.debug("bellows scan failed: %s", result.stderr.strip()[:200])
                return None

            return self._parse_bellows_scan(result.stdout)
        except FileNotFoundError:
            logger.debug("bellows not available")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("bellows scan timed out")
            return None

    def _parse_bellows_scan(self, output: str) -> list[dict]:
        """Parse bellows scan output into network records."""
        networks: list[dict] = []
        current: dict[str, Any] = {}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                if current:
                    networks.append(current)
                    current = {}
                continue

            if "PAN ID" in line or "pan_id" in line.lower():
                match = re.search(r"(?:0x)?([0-9a-fA-F]{4})", line)
                if match:
                    current["pan_id"] = "0x" + match.group(1).upper()

            if "Extended PAN" in line or "ext_pan" in line.lower():
                match = re.search(r"([0-9a-fA-F:]{23,24}|[0-9a-fA-F]{16})", line)
                if match:
                    current["ieee_addr"] = match.group(1)

            if "Channel" in line or "channel" in line:
                match = re.search(r"(\d{2})", line)
                if match:
                    ch = int(match.group(1))
                    if 11 <= ch <= 26:
                        current["channel"] = ch

            if "RSSI" in line or "rssi" in line or "LQI" in line or "lqi" in line:
                rssi_match = re.search(r"(?:RSSI|rssi)[:\s]*(-?\d+)", line)
                if rssi_match:
                    current["rssi_dbm"] = float(rssi_match.group(1))
                lqi_match = re.search(r"(?:LQI|lqi)[:\s]*(\d+)", line)
                if lqi_match:
                    current["lqi"] = int(lqi_match.group(1))

            if "Coordinator" in line.lower():
                current["device_type"] = "coordinator"

            if "Stack Profile" in line or "stack_profile" in line.lower():
                sp_match = re.search(r"(\d)", line)
                if sp_match:
                    sp = int(sp_match.group(1))
                    current["stack_profile"] = {
                        0: "zigbee",
                        1: "zigbee",
                        2: "zigbee_pro",
                    }.get(sp, f"profile_{sp}")

            if "Security" in line or "security" in line:
                if "enabled" in line.lower() or "true" in line.lower() or ": 1" in line:
                    current["security_enabled"] = 1

        if current:
            networks.append(current)

        # Fill in defaults
        for net in networks:
            net.setdefault("ieee_addr", net.get("pan_id", "unknown"))
            net.setdefault("short_addr", "0x0000")
            net.setdefault("device_name", "")
            net.setdefault("device_type", "coordinator")
            net.setdefault("pan_id", "")
            net.setdefault("extended_pan_id", "")
            net.setdefault("channel", 0)
            net.setdefault("rssi_dbm", 0.0)
            net.setdefault("lqi", 0)
            net.setdefault("manufacturer_code", 0)
            net.setdefault("manufacturer", "")
            net.setdefault("clusters", [])
            net.setdefault("endpoints", [])
            net.setdefault("power_source", "unknown")
            net.setdefault("profile_id", "")
            net.setdefault("stack_profile", "")
            net.setdefault("security_enabled", 0)
            net.setdefault("parent_addr", "")

        logger.info("bellows scan found %d networks", len(networks))
        return networks

    def _scan_via_serial_probe(self) -> list[dict]:
        """Basic serial energy scan — detect channel activity levels.

        Without full EZSP framing, we can at least probe which channels
        have Zigbee activity by checking for 802.15.4 energy.
        """
        if not self._ser or not self._ser.is_open:
            return []

        logger.info("Using basic serial probe (install bellows for full scanning)")

        # Without proper EZSP framing, report the dongle as a device
        # so the user knows the hardware is connected
        return [
            {
                "ieee_addr": "dongle-" + os.path.basename(self.device),
                "short_addr": "0xFFFE",
                "device_name": "ZBDongle-E (awaiting bellows)",
                "device_type": "coordinator",
                "pan_id": "",
                "extended_pan_id": "",
                "channel": 0,
                "rssi_dbm": 0.0,
                "lqi": 0,
                "manufacturer_code": 0x1002,
                "manufacturer": "Silicon Labs",
                "clusters": [],
                "endpoints": [],
                "power_source": "mains",
                "profile_id": "",
                "stack_profile": "",
                "security_enabled": 0,
                "parent_addr": "",
            }
        ]

    def scan_energy(self) -> dict[int, int]:
        """Perform energy detection scan across all Zigbee channels.

        Returns dict mapping channel number to RSSI (dBm).
        Uses zigpy-cli energy-scan (preferred) or bellows energy-scan.
        zigpy-cli outputs percentage (0-100%), converted to approx dBm.
        """
        # Release serial port for subprocess access
        if self._ser and self._ser.is_open:
            self._ser.close()

        results = self._energy_via_zigpy_cli()
        if results:
            return results
        return self._energy_via_bellows()

    def _energy_via_zigpy_cli(self) -> dict[int, int]:
        """Use zigpy-cli energy-scan. Output is percentage-based.

        Converts percentage to approximate dBm:
        0% = -100 dBm (quiet), 100% = 0 dBm (max energy).
        """
        bin_dir = self._find_venv_bin()
        zigpy_bin = os.path.join(bin_dir, "zigpy")
        results: dict[int, int] = {}
        try:
            proc = subprocess.Popen(
                [
                    zigpy_bin,
                    "radio",
                    "--baudrate",
                    str(self.baud),
                    "ezsp",
                    self.device,
                    "energy-scan",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, _ = proc.communicate(timeout=45)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, _ = proc.communicate(timeout=5)
        except FileNotFoundError:
            return {}
        except Exception:
            return {}

        if stdout:
            self._parse_energy_output(stdout, results)

        return results

    @staticmethod
    def _parse_energy_output(output: str, results: dict[int, int]) -> None:
        """Parse zigpy-cli energy-scan output (percentage format).

        Keeps last occurrence per channel (most averaged reading).
        """
        for line in output.splitlines():
            m = re.match(
                r"\s*-\s*\[?\s*(\d{2})\s*\*?\]?\s+"
                r"([\d.]+)%",
                line,
            )
            if m:
                ch = int(m.group(1))
                pct = float(m.group(2))
                if 11 <= ch <= 26:
                    # Convert: 0% -> -100 dBm, 100% -> 0 dBm
                    results[ch] = int(-100 + pct)

    def _energy_via_bellows(self) -> dict[int, int]:
        """Fallback: use bellows energy-scan (older output format)."""
        bin_dir = self._find_venv_bin()
        bellows_bin = os.path.join(bin_dir, "bellows")
        results: dict[int, int] = {}
        try:
            result = subprocess.run(
                [
                    bellows_bin,
                    "-d",
                    self.device,
                    "-b",
                    str(self.baud),
                    "energy-scan",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.search(r"(\d{2})\s*:\s*(-?\d+)", line)
                    if match:
                        ch = int(match.group(1))
                        rssi = int(match.group(2))
                        if 11 <= ch <= 26:
                            results[ch] = rssi
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return results

    def scan_passive(self, dwell_per_channel: float = 3.0) -> list[dict]:
        """Passive 802.15.4 frame capture via bellows sniff or raw serial.

        Rotates through channels 11-26, capturing frames for
        *dwell_per_channel* seconds each.  Extracts source addresses
        from 802.15.4 MAC headers to discover devices that active
        scans miss (end devices, sleeping devices).

        Returns list of discovered device dicts.
        """
        # Release serial port for subprocess access
        if self._ser and self._ser.is_open:
            self._ser.close()

        # Try bellows sniff first
        devices = self._sniff_via_bellows(dwell_per_channel)
        if devices is not None:
            return devices

        # Fallback: try raw serial promiscuous mode
        self.open()
        return self._sniff_via_serial(dwell_per_channel)

    def _sniff_via_bellows(self, dwell: float) -> list[dict] | None:
        """Use bellows sniff to capture raw 802.15.4 frames per channel."""
        bin_dir = self._find_venv_bin()
        bellows_bin = os.path.join(bin_dir, "bellows")
        seen: dict[str, dict] = {}  # ieee_addr -> device info

        for ch in _ZIGBEE_CHANNELS:
            try:
                result = subprocess.run(
                    [
                        bellows_bin,
                        "-d",
                        self.device,
                        "-b",
                        str(self.baud),
                        "sniff",
                        "-c",
                        str(ch),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=dwell + 5,
                )
                if result.returncode != 0:
                    # bellows sniff may not be available
                    if (
                        "No such command" in result.stderr
                        or "error" in result.stderr.lower()
                    ):
                        return None
                    continue
                self._parse_sniff_output(result.stdout, ch, seen)
            except subprocess.TimeoutExpired as exc:
                # Expected — we use timeout as our dwell mechanism
                if exc.stdout:
                    output = (
                        exc.stdout
                        if isinstance(exc.stdout, str)
                        else exc.stdout.decode(errors="replace")
                    )
                    self._parse_sniff_output(output, ch, seen)
            except FileNotFoundError:
                return None

        if seen:
            logger.info("Passive sniff found %d unique devices", len(seen))
        return list(seen.values()) if seen else None

    def _parse_sniff_output(
        self, output: str, channel: int, seen: dict[str, dict]
    ) -> None:
        """Parse bellows sniff output for 802.15.4 frame source addresses."""
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Look for source address patterns in frame dumps
            # Typical format: "src: 0x1234" or "source: 00:11:22:33:44:55:66:77"
            src_short = re.search(r"(?:src|source)[:\s]+0x([0-9a-fA-F]{4})\b", line)
            src_long = re.search(
                r"(?:src|source)[:\s]+((?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2})", line
            )
            pan_match = re.search(r"(?:pan|PAN)[:\s]+0x([0-9a-fA-F]{4})", line)
            ext_pan = re.search(
                r"(?:ext.*pan|EPID)[:\s]+((?:[0-9a-fA-F]{2}:?){8})", line, re.IGNORECASE
            )

            ieee = ""
            short = ""
            if src_long:
                ieee = src_long.group(1)
            if src_short:
                short = "0x" + src_short.group(1).upper()

            if not ieee and not short:
                continue

            key = ieee or short
            if key in seen:
                # Update RSSI if present
                rssi_match = re.search(r"(?:RSSI|rssi|LQI|lqi)[:\s]*(-?\d+)", line)
                if rssi_match:
                    seen[key]["rssi_dbm"] = float(rssi_match.group(1))
                continue

            # Determine device type from frame control
            dev_type = "unknown"
            if "beacon" in line.lower():
                dev_type = "coordinator"
            elif "cmd" in line.lower() or "command" in line.lower():
                dev_type = "router"
            elif "data" in line.lower():
                dev_type = "end_device"

            # Check security bit
            security = 0
            if "security" in line.lower() or "encrypted" in line.lower():
                security = 1

            pan_id = ""
            if pan_match:
                pan_id = "0x" + pan_match.group(1).upper()

            extended_pan_id = ""
            if ext_pan:
                extended_pan_id = ext_pan.group(1)

            rssi = 0.0
            rssi_match = re.search(r"(?:RSSI|rssi)[:\s]*(-?\d+)", line)
            if rssi_match:
                rssi = float(rssi_match.group(1))

            lqi = 0
            lqi_match = re.search(r"(?:LQI|lqi)[:\s]*(\d+)", line)
            if lqi_match:
                lqi = int(lqi_match.group(1))

            seen[key] = {
                "ieee_addr": ieee or key,
                "short_addr": short,
                "device_name": "",
                "device_type": dev_type,
                "pan_id": pan_id,
                "extended_pan_id": extended_pan_id,
                "channel": channel,
                "rssi_dbm": rssi,
                "lqi": lqi,
                "manufacturer_code": 0,
                "manufacturer": "",
                "clusters": [],
                "endpoints": [],
                "power_source": "unknown",
                "profile_id": "",
                "stack_profile": "",
                "security_enabled": security,
                "parent_addr": "",
            }

    def _sniff_via_serial(self, dwell: float) -> list[dict]:
        """Basic raw serial 802.15.4 frame capture in promiscuous mode.

        Falls back to parsing raw bytes from the serial port when
        bellows sniff is unavailable.
        """
        if not self._ser or not self._ser.is_open:
            return []

        seen: dict[str, dict] = {}

        for ch in _ZIGBEE_CHANNELS:
            try:
                # Read raw bytes for dwell period
                deadline = time.monotonic() + dwell
                while time.monotonic() < deadline:
                    if self._ser.in_waiting > 0:
                        raw = self._ser.read(min(self._ser.in_waiting, 256))
                        self._parse_raw_802154_frame(raw, ch, seen)
                    else:
                        time.sleep(0.05)
            except Exception as exc:
                logger.debug("Serial sniff ch %d error: %s", ch, exc)

        return list(seen.values())

    @staticmethod
    def _parse_raw_802154_frame(
        data: bytes, channel: int, seen: dict[str, dict]
    ) -> None:
        """Extract source addresses from raw 802.15.4 MAC frame bytes.

        IEEE 802.15.4 MAC header layout:
          [0-1] Frame Control (2 bytes, little-endian)
          [2]   Sequence Number
          [3-4] Dest PAN ID (if present)
          ...   variable addressing fields based on frame control
        """
        if len(data) < 9:
            return

        # Try to find valid 802.15.4 frame headers in the byte stream
        for offset in range(len(data) - 8):
            fc = struct.unpack_from("<H", data, offset)[0]
            frame_type = fc & 0x07
            if frame_type > 3:  # Invalid frame type
                continue

            security = (fc >> 3) & 0x01
            dst_mode = (fc >> 10) & 0x03
            src_mode = (fc >> 14) & 0x03

            if src_mode == 0:  # No source address
                continue

            # Calculate offset to source address fields
            pos = offset + 3  # Skip FC + seq
            # Dest PAN + Dest Addr
            if dst_mode == 2:  # 16-bit dest
                pos += 4  # PAN(2) + short addr(2)
            elif dst_mode == 3:  # 64-bit dest
                pos += 10  # PAN(2) + long addr(8)

            # Intra-PAN compression
            pan_compress = (fc >> 6) & 0x01

            if src_mode == 2 and pos + 2 <= len(data):
                if not pan_compress:
                    pos += 2  # skip src PAN
                src_short = struct.unpack_from("<H", data, pos)[0]
                key = f"0x{src_short:04X}"
                if key not in seen and src_short not in (0x0000, 0xFFFF, 0xFFFE):
                    # Extract dest PAN ID
                    pan_id = ""
                    if dst_mode >= 2 and offset + 5 <= len(data):
                        pan = struct.unpack_from("<H", data, offset + 3)[0]
                        pan_id = f"0x{pan:04X}"
                    seen[key] = {
                        "ieee_addr": key,
                        "short_addr": key,
                        "device_name": "",
                        "device_type": _frame_type_to_device_type(frame_type),
                        "pan_id": pan_id,
                        "extended_pan_id": "",
                        "channel": channel,
                        "rssi_dbm": 0.0,
                        "lqi": 0,
                        "manufacturer_code": 0,
                        "manufacturer": "",
                        "clusters": [],
                        "endpoints": [],
                        "power_source": "unknown",
                        "profile_id": "",
                        "stack_profile": "",
                        "security_enabled": security,
                        "parent_addr": "",
                    }
            elif src_mode == 3 and pos + 8 <= len(data):
                if not pan_compress:
                    pos += 2
                src_bytes = data[pos : pos + 8]
                ieee = ":".join(f"{b:02X}" for b in reversed(src_bytes))
                if ieee not in seen:
                    pan_id = ""
                    if dst_mode >= 2 and offset + 5 <= len(data):
                        pan = struct.unpack_from("<H", data, offset + 3)[0]
                        pan_id = f"0x{pan:04X}"
                    seen[ieee] = {
                        "ieee_addr": ieee,
                        "short_addr": "",
                        "device_name": "",
                        "device_type": _frame_type_to_device_type(frame_type),
                        "pan_id": pan_id,
                        "extended_pan_id": "",
                        "channel": channel,
                        "rssi_dbm": 0.0,
                        "lqi": 0,
                        "manufacturer_code": 0,
                        "manufacturer": "",
                        "clusters": [],
                        "endpoints": [],
                        "power_source": "unknown",
                        "profile_id": "",
                        "stack_profile": "",
                        "security_enabled": security,
                        "parent_addr": "",
                    }
            break  # Only parse first valid header per chunk


def _frame_type_to_device_type(frame_type: int) -> str:
    """Map 802.15.4 frame type to Zigbee device type heuristic."""
    if frame_type == 0:  # Beacon
        return "coordinator"
    if frame_type == 3:  # MAC command (assoc, data req)
        return "router"
    return "end_device"  # Data frames typically from end devices


# ---------------------------------------------------------------------------
# Demo / synthetic data generator
# ---------------------------------------------------------------------------

# Realistic synthetic Zigbee networks for UI testing
_DEMO_NETWORKS = [
    {
        "pan_id": "0x1A2B",
        "extended_pan_id": "DD:DD:DD:DD:00:1A:2B:00",
        "channel": 15,
        "stack_profile": "zigbee_pro",
        "security_enabled": 1,
        "devices": [
            {
                "type": "coordinator",
                "mfr": 0x1002,
                "name": "ZB Hub Pro",
                "power": "mains",
                "clusters": ["genOnOff", "genBasic", "touchlink"],
            },
            {
                "type": "router",
                "mfr": 0x1047,
                "name": "TRADFRI Signal Repeater",
                "power": "mains",
                "clusters": ["genOnOff", "genLevelCtrl"],
            },
            {
                "type": "router",
                "mfr": 0x100B,
                "name": "Hue Bridge Extender",
                "power": "mains",
                "clusters": ["lightingColorCtrl", "genOnOff"],
            },
            {
                "type": "end_device",
                "mfr": 0x115F,
                "name": "Aqara Door Sensor",
                "power": "battery",
                "clusters": ["ssIasZone", "genPowerCfg"],
            },
            {
                "type": "end_device",
                "mfr": 0x115F,
                "name": "Aqara Temp/Humidity",
                "power": "battery",
                "clusters": ["msTemperatureMeasurement", "msRelativeHumidity"],
            },
            {
                "type": "end_device",
                "mfr": 0x1047,
                "name": "TRADFRI Motion Sensor",
                "power": "battery",
                "clusters": ["ssIasZone", "genPowerCfg"],
            },
            {
                "type": "end_device",
                "mfr": 0x1168,
                "name": "Tuya Smart Plug",
                "power": "mains",
                "clusters": ["genOnOff", "seMetering", "haElectricalMeasurement"],
            },
        ],
    },
    {
        "pan_id": "0x3C4D",
        "extended_pan_id": "DD:DD:DD:DD:00:3C:4D:00",
        "channel": 20,
        "stack_profile": "zigbee_pro",
        "security_enabled": 1,
        "devices": [
            {
                "type": "coordinator",
                "mfr": 0x103E,
                "name": "SmartThings Hub",
                "power": "mains",
                "clusters": ["genOnOff", "genBasic"],
            },
            {
                "type": "router",
                "mfr": 0x10C4,
                "name": "Yale Conexis Lock",
                "power": "battery",
                "clusters": ["closuresDoorLock", "genPowerCfg"],
            },
            {
                "type": "router",
                "mfr": 0x110A,
                "name": "Schneider Dimmer",
                "power": "mains",
                "clusters": ["genOnOff", "genLevelCtrl"],
            },
            {
                "type": "end_device",
                "mfr": 0x10A0,
                "name": "Heiman Smoke Detector",
                "power": "battery",
                "clusters": ["ssIasZone", "genPowerCfg"],
            },
            {
                "type": "end_device",
                "mfr": 0x1066,
                "name": "Danfoss Ally TRV",
                "power": "battery",
                "clusters": ["hvacThermostat", "genPowerCfg"],
            },
        ],
    },
    {
        "pan_id": "0x5E6F",
        "extended_pan_id": "DD:DD:DD:DD:00:5E:6F:00",
        "channel": 25,
        "stack_profile": "zigbee",
        "security_enabled": 0,
        "devices": [
            {
                "type": "coordinator",
                "mfr": 0x1141,
                "name": "Xiaomi Gateway",
                "power": "mains",
                "clusters": ["genOnOff", "genBasic"],
            },
            {
                "type": "end_device",
                "mfr": 0x1141,
                "name": "Xiaomi Vibration Sensor",
                "power": "battery",
                "clusters": ["ssIasZone"],
            },
            {
                "type": "end_device",
                "mfr": 0x1141,
                "name": "Xiaomi Water Leak",
                "power": "battery",
                "clusters": ["ssIasZone", "genPowerCfg"],
            },
        ],
    },
]


def _generate_demo_devices(node_id: str) -> list[dict]:
    """Generate synthetic Zigbee device records across multiple PANs.

    Returns dicts compatible with ``ZigbeeDeviceRecord`` (no extra keys).
    The caller is responsible for adding ``node_id`` to the upload batch.
    """
    devices: list[dict] = []
    rng = random.Random(42)  # deterministic but with per-call jitter

    for net in _DEMO_NETWORKS:
        parent_addr = ""
        coordinator_short = "0x0001"
        for i, dev in enumerate(net["devices"]):
            # Deterministic IEEE address from PAN + device index
            seed = f"{net['pan_id']}:{i}"
            ieee_hash = hashlib.sha256(seed.encode()).hexdigest()[:16]
            ieee = ":".join(ieee_hash[j : j + 2].upper() for j in range(0, 16, 2))
            short = f"0x{(i + 1):04X}"

            if dev["type"] == "coordinator":
                parent_addr = ""
                coordinator_short = short
            elif dev["type"] == "router":
                parent_addr = coordinator_short
            else:
                parent_addr = coordinator_short

            rssi = rng.uniform(-85.0, -35.0)
            lqi = max(0, min(255, int(255 + rssi + 85)))

            devices.append(
                {
                    "ieee_addr": ieee,
                    "short_addr": short,
                    "device_name": dev["name"],
                    "device_type": dev["type"],
                    "pan_id": net["pan_id"],
                    "extended_pan_id": net["extended_pan_id"],
                    "channel": net["channel"],
                    "rssi_dbm": round(rssi, 1),
                    "lqi": lqi,
                    "manufacturer_code": dev["mfr"],
                    "manufacturer": _MANUFACTURER_CODES.get(dev["mfr"], ""),
                    "clusters": dev["clusters"],
                    "endpoints": [1],
                    "power_source": dev["power"],
                    "profile_id": "0x0104",
                    "stack_profile": net["stack_profile"],
                    "security_enabled": net["security_enabled"],
                    "parent_addr": parent_addr,
                }
            )
    return devices


def _generate_demo_energy(rng: random.Random | None = None) -> dict[int, int]:
    """Generate synthetic energy scan results for channels 11-26."""
    if rng is None:
        rng = random.Random()
    # Channels used by demo networks get higher energy
    active_channels = {net["channel"] for net in _DEMO_NETWORKS}
    results = {}
    for ch in _ZIGBEE_CHANNELS:
        if ch in active_channels:
            results[ch] = rng.randint(-60, -30)  # busy
        else:
            results[ch] = rng.randint(-95, -75)  # quiet
    return results


# ---------------------------------------------------------------------------
# Zigbee Scanner main class
# ---------------------------------------------------------------------------


class ZigbeeScanner:
    """Background Zigbee scanner that periodically scans and uploads results."""

    def __init__(
        self,
        server_url: str,
        api_key: str,
        node_id: str,
        device: str | None = None,
        baud: int = _DEFAULT_BAUD,
        scan_interval: int = _DEFAULT_SCAN_INTERVAL,
        ca_bundle: str | None = None,
        verify_ssl: bool = True,
        demo: bool = False,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.node_id = node_id
        self.device = device
        self.baud = baud
        self.scan_interval = scan_interval
        self.ca_bundle = ca_bundle
        self.verify_ssl = verify_ssl
        self.demo = demo
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._scanner: EZSPScanner | None = None
        self._demo_rng = random.Random()

        # Stats
        self.scan_count = 0
        self.upload_count = 0
        self.error_count = 0
        self.last_scan_time = 0.0
        self.devices_found = 0
        self._last_energy: dict[int, int] = {}

    def start(self) -> None:
        """Start the background scan thread."""
        if self._thread and self._thread.is_alive():
            return

        if self.demo:
            logger.info("Zigbee scanner starting in DEMO mode (synthetic data)")
        else:
            # Auto-detect device if not specified
            if not self.device:
                self.device = find_zigbee_device()
                if not self.device:
                    logger.error(
                        "No Zigbee dongle detected. Specify --device or set MLRF_ZB_DEVICE"
                    )
                    return

            if not check_device(self.device):
                logger.error("Zigbee device %s not accessible", self.device)
                return

            self._scanner = EZSPScanner(self.device, self.baud)
            if not self._scanner.open():
                logger.error("Failed to open Zigbee dongle")
                return

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._scan_loop,
            name="zigbee-scanner",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "Zigbee scanner started (device=%s, interval=%ds, node=%s, demo=%s)",
            self.device,
            self.scan_interval,
            self.node_id,
            self.demo,
        )

    def stop(self) -> None:
        """Stop the background scan thread."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        if self._scanner:
            self._scanner.close()
        logger.info(
            "Zigbee scanner stopped (scans=%d, uploads=%d, errors=%d)",
            self.scan_count,
            self.upload_count,
            self.error_count,
        )

    def _scan_loop(self) -> None:
        """Main scan loop — runs in background thread."""
        # Initial delay to let the system settle
        if self._stop.wait(5):
            return

        while not self._stop.is_set():
            try:
                devices = self._do_scan()
                if devices:
                    self._upload(devices)
            except Exception as exc:
                logger.error("Zigbee scan error: %s", exc, exc_info=True)
                self.error_count += 1

            self._stop.wait(self.scan_interval)

    def _do_scan(self) -> list[dict]:
        """Perform a single scan cycle (active + passive + energy)."""
        self.scan_count += 1
        start = time.monotonic()

        if self.demo:
            devices = _generate_demo_devices(self.node_id)
            self._last_energy = _generate_demo_energy(self._demo_rng)
            # Add per-scan jitter to RSSI values so the UI shows activity
            for d in devices:
                d["rssi_dbm"] = round(d["rssi_dbm"] + self._demo_rng.uniform(-3, 3), 1)
                d["lqi"] = max(0, min(255, d["lqi"] + self._demo_rng.randint(-5, 5)))
        else:
            if not self._scanner:
                return []
            devices = self._scanner.scan_networks()
            self._last_energy = self._scanner.scan_energy()

            # Add node_id to all records
            for d in devices:
                d["node_id"] = self.node_id

            # Enrich manufacturer names
            for d in devices:
                code = d.get("manufacturer_code", 0)
                if code and not d.get("manufacturer"):
                    d["manufacturer"] = _MANUFACTURER_CODES.get(code, f"0x{code:04X}")

        elapsed = time.monotonic() - start
        self.last_scan_time = elapsed
        self.devices_found = len(devices)

        logger.info(
            "Zigbee scan #%d: %d devices, %d energy channels in %.1fs",
            self.scan_count,
            len(devices),
            len(self._last_energy),
            elapsed,
        )
        return devices

    def _upload(self, devices: list[dict]) -> None:
        """Upload scan results (devices + channel energy) to the Bridge."""
        if not devices and not getattr(self, "_last_energy", {}):
            return

        # Respect batch limit
        devices = devices[:_MAX_BATCH]

        # Build channel energy list from most recent energy scan
        channel_energy = [
            {"channel": ch, "rssi_dbm": rssi}
            for ch, rssi in sorted(getattr(self, "_last_energy", {}).items())
        ]

        payload = json.dumps(
            {
                "node_id": self.node_id,
                "records": devices,
                "channel_energy": channel_energy,
            }
        ).encode()

        compressed = gzip.compress(payload)

        url = f"{self.server_url}/api/zigbee/ingest"
        req = urllib.request.Request(
            url,
            data=compressed,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                "X-API-Key": self.api_key,
            },
        )

        import ssl

        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        elif self.ca_bundle:
            ctx.load_verify_locations(self.ca_bundle)

        try:
            resp = urllib.request.urlopen(req, timeout=_UPLOAD_TIMEOUT, context=ctx)
            data = json.loads(resp.read().decode())
            self.upload_count += 1
            logger.info(
                "Zigbee upload: %d accepted from node %s",
                data.get("accepted", 0),
                self.node_id,
            )
        except urllib.error.HTTPError as exc:
            logger.warning("Zigbee upload HTTP %d: %s", exc.code, exc.reason)
            self.error_count += 1
        except Exception as exc:
            logger.warning("Zigbee upload failed: %s", exc)
            self.error_count += 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Edge Zigbee scanner for SigRift (SONOFF ZBDongle-E/P)"
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get(
            "MLRF_BRIDGE_URL",
            os.environ.get("MLRF_API_URL", "https://localhost:8444"),
        ),
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get(
            "MLRF_BRIDGE_KEY",
            os.environ.get("MLRF_API_KEY", ""),
        ),
    )
    parser.add_argument(
        "--node-id",
        default=os.environ.get("MLRF_NODE_ID", "node-01"),
    )
    parser.add_argument(
        "--device",
        default=os.environ.get("MLRF_ZB_DEVICE"),
        help="Serial device path (e.g., /dev/ttyUSB0). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--baud",
        type=int,
        default=int(os.environ.get("MLRF_ZB_BAUD", str(_DEFAULT_BAUD))),
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=int(
            os.environ.get("MLRF_ZB_SCAN_INTERVAL", str(_DEFAULT_SCAN_INTERVAL))
        ),
        help="Seconds between scan cycles (default: 60)",
    )
    parser.add_argument(
        "--ca-bundle",
        default=os.environ.get("MLRF_CA_BUNDLE"),
        help="Path to CA bundle for TLS verification",
    )
    parser.add_argument(
        "--no-verify-ssl",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        default=os.environ.get("MLRF_ZB_DEMO", "0") == "1",
        help="Generate synthetic Zigbee data for UI testing (no hardware needed)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    if not args.api_key:
        logger.error("No API key provided (--api-key or MLRF_BRIDGE_KEY)")
        sys.exit(1)

    scanner = ZigbeeScanner(
        server_url=args.server_url,
        api_key=args.api_key,
        node_id=args.node_id,
        device=args.device,
        baud=args.baud,
        scan_interval=args.interval,
        ca_bundle=args.ca_bundle,
        verify_ssl=not args.no_verify_ssl,
        demo=args.demo,
    )

    stop_event = threading.Event()

    def handle_signal(signum: int, frame: Any) -> None:
        logger.info("Signal %d received, stopping...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    scanner.start()
    logger.info("Zigbee scanner running. Press Ctrl+C to stop.")

    stop_event.wait()
    scanner.stop()


if __name__ == "__main__":
    main()
