#!/usr/bin/env python3
"""WiFi SIGINT edge client for monitor-mode capture and Bridge upload.

Puts a WiFi interface into monitor mode, hops channels, captures 802.11
frames via tcpdump, extracts metadata (BSSID, SSID, channel, signal,
security, clients), and batch-POSTs to The Bridge ``POST /api/wifi/ingest``.

Env vars:
    MLRF_BRIDGE_URL    - Bridge server URL (required)
    MLRF_BRIDGE_KEY    - Bridge API key (required)
    MLRF_NODE_ID       - Node identifier (required)
    MLRF_WIFI_IFACE    - WiFi interface (default: wlan1)
    MLRF_WIFI_IDENTITY - Adapter identity pinned by scanner setup (64 hex);
                         unset means whatever adapter has that name is used
    MLRF_WIFI_BANDS    - Bands to scan: "2.4", "5", "both" (default: both)
    MLRF_CHANNEL_DWELL - Seconds per channel (default: 0.5)
    MLRF_FLUSH_INTERVAL - Batch upload interval secs (default: 10, or 30 if summarize)
    MLRF_FLUSH_SIZE    - Max records per batch (default: 200)
    MLRF_SUMMARIZE     - Aggregate locally before upload (default: true).
                         Legacy MLRF_WIFI_SUMMARIZE is honored for one release.
    MLRF_CA_CERT       - CA bundle used to verify the bridge (default: system store)
    MLRF_CA_BUNDLE     - Alternative name for MLRF_CA_CERT
    MLRF_INSECURE_TLS  - "1" disables TLS verification (NOT recommended)
"""

from __future__ import annotations

import collections
import io
import json
import logging
import os
import random
import re
import select
import signal
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

try:
    from sigrift.edge import sensor_presence
    from sigrift.edge.scanner_status import ScannerStatusReporter
except ImportError:  # Legacy standalone edge directory.
    import sensor_presence
    from scanner_status import ScannerStatusReporter

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR = Path("/opt/rf-edge/logs")
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    _log_handlers = [
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "wifi_scan.log"),
    ]
except OSError:
    _log_handlers = [logging.StreamHandler()]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=_log_handlers,
)
logger = logging.getLogger("wifi_scan")

SCANNER_VERSION = "1.0.0"

# Sensor lifecycle (docs/sensor-lifecycle.md). Read at call time, so tests can
# point them at a fake sysfs and shorten the waits.
NET_SYSFS = Path("/sys/class/net")
RETRY_INTERVAL = 5.0  # presence re-check; first retry after a failed round
RETRY_MAX = 60.0  # longest back-off between failed rounds on a present radio
WATCH_INTERVAL = 5.0  # watchdog period while capturing
HOP_FAILURE_LIMIT = 60.0  # no successful channel hop for this long ends a round


def _interface_exists(iface: str) -> bool:
    try:
        return (NET_SYSFS / iface).exists()
    except OSError:
        return True  # Cannot tell: keep treating a failure as real.


class _FailureLog:
    """Log a failure once; the same failure again goes to DEBUG until reset()."""

    def __init__(self, log: logging.Logger) -> None:
        self._log = log
        self._last: str | None = None

    @property
    def failing(self) -> bool:
        return self._last is not None

    def warn(self, message: str, *args) -> None:
        text = message % args
        level = logging.DEBUG if text == self._last else logging.WARNING
        self._last = text
        self._log.log(level, "%s", text)

    def reset(self) -> None:
        self._last = None


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
# Same policy as node_agent, rf_scan and detection_reporter; the block is
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
        "the API key and uploaded observations",
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
# Channel plans
# ---------------------------------------------------------------------------

CHANNELS_24 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
CHANNELS_5 = [
    36,
    40,
    44,
    48,
    52,
    56,
    60,
    64,
    100,
    104,
    108,
    112,
    116,
    120,
    124,
    128,
    132,
    136,
    140,
    144,
    149,
    153,
    157,
    161,
    165,
]

# Channel → frequency mapping (for band detection from radiotap)
CHANNEL_TO_FREQ = {}
for _ch in CHANNELS_24:
    CHANNEL_TO_FREQ[_ch] = 2407 + _ch * 5
for _ch in CHANNELS_5:
    if _ch <= 48:
        CHANNEL_TO_FREQ[_ch] = 5000 + _ch * 5
    elif _ch <= 64:
        CHANNEL_TO_FREQ[_ch] = 5000 + _ch * 5
    elif _ch <= 144:
        CHANNEL_TO_FREQ[_ch] = 5000 + _ch * 5
    else:
        CHANNEL_TO_FREQ[_ch] = 5000 + _ch * 5

FREQ_TO_CHANNEL = {v: k for k, v in CHANNEL_TO_FREQ.items()}


def freq_to_band(freq_mhz: int) -> str:
    """Map a frequency in MHz to a band string."""
    if 2400 <= freq_mhz <= 2500:
        return "2.4GHz"
    if 5150 <= freq_mhz <= 5900:
        return "5GHz"
    if 5925 <= freq_mhz <= 7125:
        return "6GHz"
    return "unknown"


def freq_to_channel(freq_mhz: int) -> int:
    """Map a frequency in MHz to a channel number."""
    ch = FREQ_TO_CHANNEL.get(freq_mhz, 0)
    if ch:
        return ch
    # Fallback for 2.4 GHz
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    # Fallback for 5 GHz
    if 5180 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5
    return 0


# ---------------------------------------------------------------------------
# MonitorMode — interface lifecycle management
# ---------------------------------------------------------------------------


class MonitorMode:
    """Manages WiFi interface monitor mode lifecycle.

    Usage::

        with MonitorMode("wlan1") as mon:
            mon.set_channel(6)
            ...
    """

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._enabled = False
        self._restore_required = False
        # Routine lines drop to DEBUG while capture rounds keep failing.
        self.log_level = logging.INFO

    @property
    def pending(self) -> bool:
        """True while managed mode still has to be restored."""
        return self._enabled or self._restore_required

    def forget(self) -> None:
        """Drop pending restoration: the interface it applied to is gone."""
        self._enabled = False
        self._restore_required = False

    def enable(self) -> None:
        """Put interface into monitor mode."""
        logger.log(self.log_level, "Enabling monitor mode on %s", self.iface)
        # Even a command that fails may already have changed the interface.
        # __exit__ is not called when __enter__/enable fails, so roll back here.
        self._restore_required = True
        try:
            for command in (
                ["ip", "link", "set", self.iface, "down"],
                ["iw", "dev", self.iface, "set", "type", "monitor"],
                ["ip", "link", "set", self.iface, "up"],
            ):
                subprocess.run(command, check=True, capture_output=True)
        except BaseException as startup_error:
            try:
                self.disable()
            except Exception as cleanup_error:
                raise startup_error from cleanup_error
            raise
        self._enabled = True
        logger.log(self.log_level, "Monitor mode enabled on %s", self.iface)

    def disable(self) -> None:
        """Restore interface to managed mode."""
        if not self._enabled and not self._restore_required:
            return
        logger.log(self.log_level, "Restoring managed mode on %s", self.iface)
        self._enabled = False
        errors = []
        for command in (
            ["ip", "link", "set", self.iface, "down"],
            ["iw", "dev", self.iface, "set", "type", "managed"],
            ["ip", "link", "set", self.iface, "up"],
        ):
            try:
                subprocess.run(command, check=True, capture_output=True)
            except Exception as error:
                errors.append(error)
        if errors and not _interface_exists(self.iface):
            # Unplugged: nothing is left to restore, and an adapter that
            # returns comes back in managed mode.
            logger.log(self.log_level, "%s is gone; nothing to restore", self.iface)
            self._restore_required = False
            return
        for error in errors:
            logger.warning("Failed to restore managed mode: %s", error)
        if errors:
            # Keep recovery pending so an explicit retry can finish restoring.
            raise errors[0]
        self._restore_required = False

    def set_channel(self, channel: int) -> bool:
        """Hop to a specific channel."""
        try:
            subprocess.run(
                ["iw", "dev", self.iface, "set", "channel", str(channel)],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.debug(
                "Channel %d hop failed: %s", channel, e.stderr.decode().strip()
            )
            return False

    def __enter__(self) -> MonitorMode:
        self.enable()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        try:
            self.disable()
        except Exception as cleanup_error:
            if exc is not None:
                raise exc.with_traceback(traceback) from cleanup_error
            raise


# ---------------------------------------------------------------------------
# FrameParser — parse raw pcap/radiotap bytes
# ---------------------------------------------------------------------------


class FrameParser:
    """Parse raw pcap + radiotap + 802.11 frames from tcpdump output."""

    # 802.11 frame subtypes (management)
    SUBTYPE_ASSOC_REQ = 0x00
    SUBTYPE_PROBE_REQ = 0x04
    SUBTYPE_PROBE_RESP = 0x05
    SUBTYPE_BEACON = 0x08

    # Frame types
    TYPE_MGMT = 0
    TYPE_CTRL = 1
    TYPE_DATA = 2

    @staticmethod
    def format_mac(raw: bytes) -> str:
        """Format 6 raw bytes as a MAC address string."""
        return ":".join(f"{b:02x}" for b in raw)

    @staticmethod
    def parse_radiotap(buf: bytes) -> dict:
        """Parse radiotap v0 header.

        Returns dict with available fields:
            signal_dbm, noise_dbm, freq_mhz, data_rate_mbps, header_len
        Invalid or truncated headers return ``{"header_len": 0}`` so the
        caller can discard the packet without interpreting MAC payload bytes
        as missing radiotap metadata.
        """
        if len(buf) < 8:
            return {"header_len": 0}

        # Radiotap header: version(1), pad(1), length(2), present(4)
        version, _pad, hdr_len, present = struct.unpack_from("<BBHI", buf, 0)
        if version != 0 or hdr_len < 8 or hdr_len > len(buf):
            return {"header_len": 0}

        result: dict = {"header_len": hdr_len}
        offset = 8

        # Skip extended present bitmasks (bit 31 = "more bitmasks follow")
        first_present = present
        while present & (1 << 31):
            if offset + 4 > hdr_len:
                return {"header_len": 0}
            present = struct.unpack_from("<I", buf, offset)[0]
            offset += 4

        # Fields start after all present bitmask words; parse using first mask
        present = first_present

        # Bit 0: TSFT (8 bytes, aligned to 8)
        if present & (1 << 0):
            offset = (offset + 7) & ~7  # align to 8
            if offset + 8 > hdr_len:
                return {"header_len": 0}
            offset += 8

        # Bit 1: Flags (1 byte)
        if present & (1 << 1):
            if offset >= hdr_len:
                return {"header_len": 0}
            result["flags"] = buf[offset]
            offset += 1

        # Bit 2: Rate (1 byte) — data rate in 500 kbps units
        if present & (1 << 2):
            if offset >= hdr_len:
                return {"header_len": 0}
            result["data_rate_mbps"] = buf[offset] * 0.5
            offset += 1

        # Bit 3: Channel (2 + 2 bytes, aligned to 2)
        if present & (1 << 3):
            offset = (offset + 1) & ~1  # align to 2
            if offset + 4 > hdr_len:
                return {"header_len": 0}
            freq, _flags = struct.unpack_from("<HH", buf, offset)
            result["freq_mhz"] = freq
            offset += 4

        # Bit 4: FHSS (2 bytes, aligned to 2)
        if present & (1 << 4):
            offset = (offset + 1) & ~1
            if offset + 2 > hdr_len:
                return {"header_len": 0}
            offset += 2

        # Bit 5: Antenna signal dBm (int8)
        if present & (1 << 5):
            if offset >= hdr_len:
                return {"header_len": 0}
            result["signal_dbm"] = struct.unpack_from("<b", buf, offset)[0]
            offset += 1

        # Bit 6: Antenna noise dBm (int8)
        if present & (1 << 6):
            if offset >= hdr_len:
                return {"header_len": 0}
            result["noise_dbm"] = struct.unpack_from("<b", buf, offset)[0]
            offset += 1

        return result

    @staticmethod
    def parse_80211(buf: bytes) -> dict | None:
        """Parse 802.11 MAC header.

        Returns dict with: frame_type, frame_subtype, addr1, addr2, addr3,
                          retry_flag, or None if too short.
        """
        if len(buf) < 24:
            return None

        fc = struct.unpack_from("<H", buf, 0)[0]
        frame_type = (fc >> 2) & 0x03
        frame_subtype = (fc >> 4) & 0x0F
        retry = (fc >> 11) & 0x01

        addr1 = buf[4:10]
        addr2 = buf[10:16]
        addr3 = buf[16:22]

        return {
            "frame_type": frame_type,
            "frame_subtype": frame_subtype,
            "retry_flag": retry,
            "addr1": addr1,
            "addr2": addr2,
            "addr3": addr3,
        }

    @staticmethod
    def parse_beacon_ies(buf: bytes) -> dict:
        """Parse information elements from beacon/probe response body.

        Beacon body layout: timestamp(8) + beacon_interval(2) + capability(2) + IEs
        """
        result: dict = {"ssid": "", "channel_from_ie": 0, "security": "Unknown"}
        if len(buf) < 12:
            return result
        # Capability bit4 advertises privacy, not a particular cipher. Without
        # recognized WPA/RSN metadata, do not invent either Open or WEP.
        privacy = bool(struct.unpack_from("<H", buf, 10)[0] & 0x10)
        has_rsn = False
        has_wpa = False
        is_wpa3 = False

        # Skip fixed fields (timestamp + interval + capability = 12 bytes)
        offset = 12
        while offset + 2 <= len(buf):
            tag_id = buf[offset]
            tag_len = buf[offset + 1]
            offset += 2
            if offset + tag_len > len(buf):
                break

            tag_data = buf[offset : offset + tag_len]

            # Tag 0: SSID
            if tag_id == 0 and tag_len > 0:
                try:
                    result["ssid"] = tag_data.decode("utf-8", errors="replace")
                except Exception:
                    result["ssid"] = ""

            # Tag 3: DS Parameter Set (channel)
            elif tag_id == 3 and tag_len >= 1:
                result["channel_from_ie"] = tag_data[0]

            # Tag 48: RSN Information Element (WPA2/WPA3)
            elif tag_id == 48:
                has_rsn = True
                # Check AKM suites for WPA3 (SAE)
                # RSN IE: version(2) + group cipher(4) + pairwise count(2) +
                #         pairwise suites(4*n) + AKM count(2) + AKM suites(4*n)
                try:
                    ie_offset = 2 + 4  # skip version + group cipher
                    if ie_offset + 2 <= tag_len:
                        pw_count = struct.unpack_from("<H", tag_data, ie_offset)[0]
                        ie_offset += 2 + pw_count * 4
                        if ie_offset + 2 <= tag_len:
                            akm_count = struct.unpack_from("<H", tag_data, ie_offset)[0]
                            ie_offset += 2
                            for _ in range(akm_count):
                                if ie_offset + 4 <= tag_len:
                                    oui = tag_data[ie_offset : ie_offset + 3]
                                    akm_type = tag_data[ie_offset + 3]
                                    # 00-0F-AC:8 = SAE (WPA3)
                                    if oui == b"\x00\x0f\xac" and akm_type == 8:
                                        is_wpa3 = True
                                    ie_offset += 4
                except Exception:
                    pass

            # Tag 221: Vendor Specific — check for WPA IE
            elif tag_id == 221 and tag_len >= 4:
                # WPA OUI: 00-50-F2, type 1
                if tag_data[:4] == b"\x00\x50\xf2\x01":
                    has_wpa = True

            offset += tag_len

        if is_wpa3:
            result["security"] = "WPA3"
        elif has_rsn and has_wpa:
            result["security"] = "WPA2/WPA"
        elif has_rsn:
            result["security"] = "WPA2"
        elif has_wpa:
            result["security"] = "WPA"
        else:
            result["security"] = "Protected (unspecified)" if privacy else "Open"

        return result

    @classmethod
    def frame_type_label(cls, frame_type: int, subtype: int) -> str:
        """Map frame type/subtype to a human label."""
        if frame_type == cls.TYPE_MGMT:
            labels = {
                0x00: "assoc_req",
                0x01: "assoc_resp",
                0x04: "probe_req",
                0x05: "probe_resp",
                0x08: "beacon",
                0x0B: "auth",
                0x0C: "deauth",
                0x0A: "disassoc",
            }
            return labels.get(subtype, f"mgmt_{subtype:#x}")
        if frame_type == cls.TYPE_DATA:
            return "data"
        if frame_type == cls.TYPE_CTRL:
            return "ctrl"
        return "unknown"


# ---------------------------------------------------------------------------
# WifiScanner — capture loop
# ---------------------------------------------------------------------------


class SensorLost(Exception):
    """start() refused: the selected adapter is not the one it can configure."""


class WifiScanner:
    """Main WiFi scan loop: run tcpdump, hop channels, parse frames."""

    # Pcap global header size
    PCAP_GLOBAL_HDR = 24
    # Pcap per-packet header size
    PCAP_PKT_HDR = 16
    # How long stop() waits for tcpdump after each attempt to end it.
    STOP_TIMEOUT = 5.0
    KILL_TIMEOUT = 2.0
    # After a signal is refused (EPERM), only the closed stdout can end it.
    SIGNAL_DENIED_TIMEOUT = 0.5
    # tcpdump ended its own output: how long to wait for its exit to be
    # collectable. The closed stream can be seen a moment before that.
    EXIT_GRACE = 1.0
    # Error output still read after the round is told to stop, and how long
    # stop() waits for that reader to finish.
    STDERR_FINAL_BYTES = 65536
    STDERR_JOIN_TIMEOUT = 1.0

    def __init__(
        self,
        iface: str,
        bands: str = "both",
        channel_dwell: float = 0.5,
        pcap_ring_size: int = 500,
        probe: Callable[[], sensor_presence.Presence] | None = None,
    ) -> None:
        self.iface = iface
        self.bands = bands
        self.channel_dwell = channel_dwell
        self._monitor = MonitorMode(iface)
        self._proc: subprocess.Popen | None = None
        self._hop_thread: threading.Thread | None = None
        self._running = False
        self._current_channel = 0
        self._last_channel_success: float | None = None
        self._reading_pcap = False
        self._parser = FrameParser()
        # Per-round watchdog state; without a probe there is no watchdog.
        self._probe = probe
        self._ifindex: int | None = None
        self._started_at = 0.0
        self._watch_thread: threading.Thread | None = None
        self._watch_stop = threading.Event()
        self._stderr_thread: threading.Thread | None = None
        self._stderr_stop = threading.Event()
        self._stderr_tail: collections.deque[str] = collections.deque(maxlen=5)
        self._stream_ended = False  # tcpdump's output ended while still wanted
        self.end_reason: str | None = None  # why the watchdog ended the round
        self.captured = False  # this round reached the "running" state
        self.failures = _FailureLog(logger)

        # Ring buffer of raw packet bytes for pcap capture on anomaly
        self._pcap_ring: collections.deque[tuple[int, bytes]] = collections.deque(
            maxlen=pcap_ring_size,
        )
        self._pcap_ring_lock = threading.Lock()

    def _channel_plan(self) -> list[tuple[int, str]]:
        """Build channel hop sequence prioritizing non-overlapping channels."""
        plan: list[tuple[int, str]] = []

        include_24 = self.bands in ("2.4", "both")
        include_5 = self.bands in ("5", "both")

        if include_24 and include_5:
            # Interleave: non-overlapping 2.4 first, then fill in with 5 GHz
            priority_24 = [1, 6, 11]
            remaining_24 = [ch for ch in CHANNELS_24 if ch not in priority_24]
            # Interleave priority 2.4 with chunks of 5 GHz
            chunk_size = len(CHANNELS_5) // 3
            plan.append((priority_24[0], "2.4GHz"))
            for ch in CHANNELS_5[:chunk_size]:
                plan.append((ch, "5GHz"))
            plan.append((priority_24[1], "2.4GHz"))
            for ch in CHANNELS_5[chunk_size : chunk_size * 2]:
                plan.append((ch, "5GHz"))
            plan.append((priority_24[2], "2.4GHz"))
            for ch in CHANNELS_5[chunk_size * 2 :]:
                plan.append((ch, "5GHz"))
            for ch in remaining_24:
                plan.append((ch, "2.4GHz"))
        elif include_24:
            priority = [1, 6, 11]
            for ch in priority:
                plan.append((ch, "2.4GHz"))
            for ch in CHANNELS_24:
                if ch not in priority:
                    plan.append((ch, "2.4GHz"))
        elif include_5:
            for ch in CHANNELS_5:
                plan.append((ch, "5GHz"))

        return plan

    def start(self) -> None:
        """Enable monitor mode, start tcpdump, channel hopping and the watchdog.

        Called once per capture round; stop() ends the round.
        """
        self.end_reason = None
        self.captured = False
        self._last_channel_success = None
        self._stream_ended = False
        self._stderr_tail.clear()
        self._watch_stop = threading.Event()
        self._stderr_stop = threading.Event()
        self._monitor.log_level = (
            logging.DEBUG if self.failures.failing else logging.INFO
        )
        self._ifindex = None
        if self._probe is not None:
            # Probed right before enable(): the adapter may have been swapped
            # since the presence check, and enable() reconfigures whatever
            # holds the name. stop() restores only this ifindex.
            before = self._snapshot()
            if not isinstance(before, tuple):
                self._refuse(before, "before monitor mode")
            self._ifindex = before[0]
        self._monitor.enable()
        if self._probe is not None:
            after = self._snapshot()
            if after != before:
                # stop() decides from the ifindex whether to restore it.
                self._refuse(after, "while monitor mode was enabled")
        self._running = True
        self._started_at = time.monotonic()

        # Start tcpdump: write pcap to stdout, unbuffered, snap 512 bytes
        cmd = [
            "tcpdump",
            "-i",
            self.iface,
            "-w",
            "-",
            "-U",
            "--immediate-mode",
            "-s",
            "512",
            "type",
            "mgt",
            "or",
            "type",
            "data",
        ]
        logger.log(self._monitor.log_level, "Starting tcpdump: %s", " ".join(cmd))
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            args=(self._proc.stderr, self._stderr_stop),
            name="tcpdump-stderr",
            daemon=True,
        )
        self._stderr_thread.start()

        # Start channel hopping thread
        self._hop_thread = threading.Thread(
            target=self._hop_channels,
            name="channel-hop",
            daemon=True,
        )
        self._hop_thread.start()
        if self._probe is not None:
            self._watch_thread = threading.Thread(
                target=self._watch, name="wifi-watchdog", daemon=True
            )
            self._watch_thread.start()

    def _snapshot(self) -> tuple[int, str | None] | str:
        """(ifindex, radio identity) of the selected adapter, or the reason."""
        presence = self._probe()
        if presence.state == "changed":
            return sensor_presence.SENSOR_CHANGED
        if presence.state != "present":
            return sensor_presence.SENSOR_ABSENT
        identity = sensor_presence.wifi_identity(self.iface, sysfs=NET_SYSFS)
        return presence.detail["ifindex"], identity

    def _refuse(self, found: tuple[int, str | None] | str, when: str) -> None:
        # A re-created or swapped interface is picked up by the next round;
        # PresenceTracker logs the state change, so this stays at DEBUG.
        self.end_reason = (
            found if isinstance(found, str) else sensor_presence.SENSOR_ABSENT
        )
        logger.debug("Not capturing on %s: the adapter changed %s", self.iface, when)
        raise SensorLost(self.end_reason)

    def _drain_stderr(self, pipe, stop: threading.Event) -> None:
        """Keep the last few short tcpdump stderr lines for its exit log."""
        pending = b""
        try:
            descriptor = pipe.fileno()
            final = self.STDERR_FINAL_BYTES
            while final > 0:
                # Once stopped, take only what is already in the pipe: the
                # last lines are written just before tcpdump exits.
                stopping = stop.is_set()
                if not select.select([descriptor], [], [], 0 if stopping else 0.2)[0]:
                    if stopping:
                        break
                    continue
                chunk = os.read(descriptor, 4096)
                if not chunk:
                    break
                if stopping:
                    final -= len(chunk)
                *lines, pending = (pending + chunk).split(b"\n")
                pending = pending[-200:]
                for line in lines:
                    if line.strip():
                        self._stderr_tail.append(line.decode(errors="replace")[:200])
            if pending.strip():
                self._stderr_tail.append(pending.decode(errors="replace"))
        except (OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def health_problem(self) -> tuple[str, str] | None:
        """Why the current round must end, as (reason code, log text), or None."""
        presence = self._probe()
        if presence.state == "changed":
            return sensor_presence.SENSOR_CHANGED, (
                f"a different adapter is now {self.iface}"
            )
        if presence.state != "present":
            return sensor_presence.SENSOR_ABSENT, f"{self.iface} disappeared"
        if presence.detail["ifindex"] != self._ifindex:
            return sensor_presence.SENSOR_ABSENT, (
                f"{self.iface} was re-created; its capture socket is stale"
            )
        if not presence.detail["monitor"]:
            return sensor_presence.CAPTURE_FAILED, f"{self.iface} left monitor mode"
        last = self._last_channel_success or self._started_at
        if time.monotonic() - last > HOP_FAILURE_LIMIT:
            return sensor_presence.CAPTURE_FAILED, (
                f"channel hopping on {self.iface} has failed for over "
                f"{HOP_FAILURE_LIMIT:.0f} s"
            )
        return None

    def _watch(self) -> None:
        """End the round when the radio vanishes, is re-created or stops working."""
        while self._running:
            if not self.captured and self.capture_state() == "running":
                self.captured = True
                self.failures.reset()
                logger.info("Capture running on %s", self.iface)
            problem = self.health_problem()
            if problem is not None:
                self.end_reason, message = problem
                if self.end_reason == sensor_presence.CAPTURE_FAILED:
                    self.failures.warn("Ending capture round: %s", message)
                else:
                    # PresenceTracker logs the one WARNING for this change.
                    logger.debug("Ending capture round: %s", message)
                self.request_stop()
                return
            if self._watch_stop.wait(WATCH_INTERVAL):
                return

    def _hop_channels(self) -> None:
        """Background thread cycling through channel plan."""
        plan = self._channel_plan()
        if not plan:
            logger.error("Empty channel plan")
            return

        idx = 0
        while self._running:
            channel, _band = plan[idx % len(plan)]
            if self._monitor.set_channel(channel):
                self._current_channel = channel
                self._last_channel_success = time.monotonic()
            idx += 1
            time.sleep(self.channel_dwell)

    def read_frames(self):
        """Generator: read pcap packets from tcpdump and yield observations."""
        pipe = self._proc.stdout
        if pipe is None:
            return

        # Read and validate pcap global header
        ghdr = self._read_exact(pipe, self.PCAP_GLOBAL_HDR)
        if ghdr is None or len(ghdr) < self.PCAP_GLOBAL_HDR:
            if self._running:
                logger.error("Failed to read pcap global header")
            return

        magic = struct.unpack_from("<I", ghdr, 0)[0]
        if magic == 0xA1B2C3D4:
            endian = "<"
        elif magic == 0xD4C3B2A1:
            endian = ">"
        else:
            logger.error("Invalid pcap magic: %#x", magic)
            return

        link_type = struct.unpack_from(f"{endian}I", ghdr, 20)[0]
        if link_type != 127:  # LINKTYPE_IEEE802_11_RADIOTAP
            logger.warning("Unexpected link type %d (expected 127/radiotap)", link_type)

        # A valid radiotap stream, live tcpdump and successful channel hopping
        # qualify even when there are no over-air packets to upload.
        self._reading_pcap = link_type == 127
        try:
            # Read packets
            while self._running:
                # Packet header: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
                phdr = self._read_exact(pipe, self.PCAP_PKT_HDR)
                if phdr is None or len(phdr) < self.PCAP_PKT_HDR:
                    break

                _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(
                    f"{endian}IIII",
                    phdr,
                    0,
                )

                if incl_len == 0 or incl_len > 65535:
                    continue

                pkt_data = self._read_exact(pipe, incl_len)
                if pkt_data is None or len(pkt_data) < incl_len:
                    break

                # Store raw packet in ring buffer for pcap capture
                ts_us = _ts_sec * 1_000_000 + _ts_usec
                with self._pcap_ring_lock:
                    self._pcap_ring.append((ts_us, pkt_data))

                obs = self._parse_packet(pkt_data)
                if obs is not None:
                    yield obs
        finally:
            self._reading_pcap = False

    def capture_state(self) -> str:
        """Actual capture readiness, independent of agent heartbeat and traffic."""
        selected = self._last_channel_success
        return (
            "running"
            if self._running
            and self._reading_pcap
            and self._proc is not None
            and self._proc.poll() is None
            and self._hop_thread is not None
            and self._hop_thread.is_alive()
            and selected is not None
            and time.monotonic() - selected < max(30.0, self.channel_dwell * 2)
            else "error"
        )

    def _parse_packet(self, pkt: bytes) -> dict | None:
        """Parse a single radiotap + 802.11 packet into an observation dict."""
        rt = FrameParser.parse_radiotap(pkt)
        hdr_len = rt.get("header_len", 0)
        if hdr_len == 0 or hdr_len >= len(pkt):
            return None

        flags = rt.get("flags", 0)
        if flags & 0x40:  # Radiotap: driver reports a failed FCS check.
            return None

        mac_buf = pkt[hdr_len:]
        if flags & 0x10:  # Radiotap: the final four bytes are the FCS, not IEs.
            if len(mac_buf) < 4:
                return None
            mac_buf = mac_buf[:-4]
        mac_hdr = FrameParser.parse_80211(mac_buf)
        if mac_hdr is None:
            return None

        frame_type = mac_hdr["frame_type"]
        subtype = mac_hdr["frame_subtype"]
        type_label = FrameParser.frame_type_label(frame_type, subtype)

        # Extract addresses
        bssid = ""
        src_mac = ""
        client_mac = ""

        if frame_type == FrameParser.TYPE_MGMT:
            # Management frames: addr1=DA, addr2=SA, addr3=BSSID
            bssid = FrameParser.format_mac(mac_hdr["addr3"])
            src_mac = FrameParser.format_mac(mac_hdr["addr2"])
            if subtype == FrameParser.SUBTYPE_PROBE_REQ:
                client_mac = src_mac
                bssid = "ff:ff:ff:ff:ff:ff"  # broadcast
            elif subtype == FrameParser.SUBTYPE_ASSOC_REQ:
                client_mac = src_mac
        elif frame_type == FrameParser.TYPE_DATA:
            # Data frames: check To DS / From DS bits
            fc = struct.unpack_from("<H", mac_buf, 0)[0]
            to_ds = (fc >> 8) & 0x01
            from_ds = (fc >> 9) & 0x01
            if to_ds == 0 and from_ds == 1:
                # From AP: addr1=DA(client), addr2=BSSID, addr3=SA
                bssid = FrameParser.format_mac(mac_hdr["addr2"])
                client_mac = FrameParser.format_mac(mac_hdr["addr1"])
            elif to_ds == 1 and from_ds == 0:
                # To AP: addr1=BSSID, addr2=SA(client), addr3=DA
                bssid = FrameParser.format_mac(mac_hdr["addr1"])
                client_mac = FrameParser.format_mac(mac_hdr["addr2"])
            else:
                bssid = FrameParser.format_mac(mac_hdr["addr3"])

        # Skip broadcast BSSID for non-probe frames
        if bssid == "ff:ff:ff:ff:ff:ff" and subtype != FrameParser.SUBTYPE_PROBE_REQ:
            return None

        # Parse beacon/probe response IEs for SSID, security, channel
        ssid = ""
        security = ""
        ie_channel = 0
        if frame_type == FrameParser.TYPE_MGMT and subtype in (
            FrameParser.SUBTYPE_BEACON,
            FrameParser.SUBTYPE_PROBE_RESP,
        ):
            ie_buf = mac_buf[24:]  # Skip MAC header (24 bytes)
            ies = FrameParser.parse_beacon_ies(ie_buf)
            ssid = ies.get("ssid", "")
            security = ies.get("security", "")
            ie_channel = ies.get("channel_from_ie", 0)

        # Determine channel and band
        freq = rt.get("freq_mhz", 0)
        channel = ie_channel or freq_to_channel(freq) or self._current_channel
        band = (
            freq_to_band(freq)
            if freq
            else ("2.4GHz" if channel <= 14 else "5GHz" if channel else "unknown")
        )

        signal_dbm = rt.get("signal_dbm", 0)
        noise_dbm = rt.get("noise_dbm", 0)
        data_rate = rt.get("data_rate_mbps", 0.0)

        return {
            "bssid": bssid,
            "ssid": ssid,
            "channel": channel,
            "channel_width": 20,  # default; HT/VHT IE parsing could refine
            "band": band,
            "security": security,
            "signal_dbm": signal_dbm,
            "noise_dbm": noise_dbm,
            "frame_type": type_label,
            "client_mac": client_mac,
            "data_rate_mbps": data_rate,
            "retry_flag": mac_hdr.get("retry_flag", 0),
        }

    def _read_exact(self, pipe, n: int) -> bytes | None:
        """Read exactly n bytes, allowing quiet or partial streams to stop."""
        try:
            descriptor = pipe.fileno()
        except (AttributeError, io.UnsupportedOperation):
            # In-memory pcap streams have no descriptor and cannot block.
            descriptor = None
        data = b""
        while len(data) < n:
            if not self._running:
                return None
            try:
                if descriptor is None:
                    chunk = pipe.read(n - len(data))
                else:
                    if not select.select([descriptor], [], [], 0.2)[0]:
                        continue
                    # BufferedReader.read(n) can wait for all n bytes even
                    # after select; os.read consumes only currently available
                    # bytes, then lets the next loop observe cancellation.
                    chunk = os.read(descriptor, n - len(data))
            except (OSError, ValueError):
                if not self._running:
                    return None
                raise
            if not chunk:
                # End of stream while it was still wanted: tcpdump ended it.
                self._stream_ended = self._running
                return None
            data += chunk
        return data

    def drain_pcap_ring(self) -> bytes:
        """Drain the raw packet ring buffer and return a gzip-compressed pcap file.

        Returns an empty bytes object if the ring buffer is empty.
        Thread-safe: takes a snapshot of the ring buffer without blocking
        the capture loop for long.
        """
        import gzip as _gzip

        with self._pcap_ring_lock:
            if not self._pcap_ring:
                return b""
            packets = list(self._pcap_ring)
            # Don't clear — keep the ring buffer rolling so overlapping
            # anomalies in the same window still get context

        # Build libpcap file
        # Global header: magic, version 2.4, thiszone=0, sigfigs=0,
        #                snaplen=65535, linktype=127 (radiotap)
        header = struct.pack(
            "<IHHiIII",
            0xA1B2C3D4,
            2,
            4,
            0,
            0,
            65535,
            127,
        )
        body = bytearray()
        for ts_us, pkt_data in packets:
            ts_sec = ts_us // 1_000_000
            ts_usec = ts_us % 1_000_000
            pkt_len = len(pkt_data)
            body.extend(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            body.extend(pkt_data)

        pcap_bytes = header + bytes(body)
        compressed = _gzip.compress(pcap_bytes, compresslevel=6)
        logger.debug(
            "Drained pcap ring: %d packets, %d bytes compressed",
            len(packets),
            len(compressed),
        )
        return compressed

    def request_stop(self) -> None:
        """Cancel reads/hopping without blocking inside a signal handler."""
        self._running = False
        self._reading_pcap = False

    def stop(self) -> None:
        """Reap tcpdump and restore managed mode, including after cancellation.

        Only a failed restore of an interface that still exists raises.
        """
        self.request_stop()
        self._watch_stop.set()
        proc, self._proc = self._proc, None
        try:
            if proc is not None:
                self._stop_child(proc)
        finally:
            for thread in (self._hop_thread, self._watch_thread):
                if thread is not None:
                    thread.join(timeout=3)
            self._hop_thread = self._watch_thread = None
            if self._probe is not None and self._monitor.pending:
                presence = self._probe()
                if (
                    presence.state != "present"
                    or presence.detail["ifindex"] != self._ifindex
                ):
                    # Gone, swapped or re-created: never touch an adapter this
                    # round did not configure; a new one starts managed.
                    self._monitor.forget()
            self._monitor.disable()

    def _stop_child(self, proc: subprocess.Popen) -> None:
        """End tcpdump without CAP_KILL; never raises.

        tcpdump drops to its own user and this container has no CAP_KILL, so
        signalling it fails with EPERM. Closing our end of its stdout makes
        its next write fail, which ends it. Signals are still tried for a
        child that runs as this user.
        """
        exited_early = proc.poll() is not None
        if not exited_early and self._stream_ended:
            # It ended its own output, so it is exiting; give that exit a
            # moment to be collectable, or it would be stopped and never
            # reported as an unexpected exit.
            try:
                proc.wait(timeout=self.EXIT_GRACE)
                exited_early = True
            except subprocess.TimeoutExpired:
                pass
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass
        for end_child, timeout in (
            (proc.terminate, self.STOP_TIMEOUT),
            (proc.kill, self.KILL_TIMEOUT),
        ):
            if proc.poll() is not None:
                break
            denied = False
            try:
                end_child()
            except PermissionError:
                # No signal will reach it. Give the closed stdout a moment;
                # the link going down in disable() ends a quiet one, and
                # waiting longer overruns Docker's stop window.
                denied = True
                timeout = min(timeout, self.SIGNAL_DENIED_TIMEOUT)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
            if denied:
                break
        self._stderr_stop.set()
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=self.STDERR_JOIN_TIMEOUT)
            self._stderr_thread = None
        if proc.returncode is None:
            logger.warning(
                "tcpdump on %s did not exit and cannot be signalled; "
                "it ends when the interface goes down",
                self.iface,
            )
        elif exited_early and (
            self.end_reason
            in (sensor_presence.SENSOR_ABSENT, sensor_presence.SENSOR_CHANGED)
            or not _interface_exists(self.iface)
        ):
            # Its interface went away; PresenceTracker logs that change once.
            logger.debug(
                "tcpdump on %s exited with its interface (code %s)",
                self.iface,
                proc.returncode,
            )
        elif exited_early:
            self.failures.warn(
                "tcpdump on %s exited unexpectedly (code %s): %s",
                self.iface,
                proc.returncode,
                " | ".join(self._stderr_tail) or "no error output",
            )


# ---------------------------------------------------------------------------
# WifiReporter — batch upload thread
# ---------------------------------------------------------------------------


class WifiReporter:
    """Batch upload WiFi observations to The Bridge.

    Mirrors the DetectionReporter pattern: thread-safe deque buffer,
    background flush thread, exponential backoff retry.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        node_id: str,
        flush_interval: float = 10.0,
        flush_size: int = 200,
        max_retries: int = 3,
        pcap_source: WifiScanner | None = None,
        summarize: bool = True,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.node_id = node_id
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.max_retries = max_retries
        self._pcap_source = pcap_source
        self.summarize = summarize

        self._buffer: collections.deque[dict] = collections.deque(maxlen=2000)
        self._lock = threading.Lock()
        self._flush_thread: threading.Thread | None = None
        self._running = False

        # Stats
        self._stats_lock = threading.Lock()
        self.total_recorded = 0
        self.total_uploaded = 0
        self.total_batches = 0
        self.total_dropped = 0
        self.total_failures = 0
        self.total_pcap_uploads = 0

        # SSL context — verifies the bridge unless MLRF_INSECURE_TLS=1.
        # Self-signed / private-CA bridges: point MLRF_CA_CERT at the CA.
        # Raises TLSConfigError if that CA file exists but cannot be loaded
        # (main() checks this up front and exits with a clear message).
        self._ssl_ctx = _build_ssl_context()

    def record(self, observation: dict) -> None:
        """Thread-safe append to buffer."""
        with self._lock:
            self._buffer.append(observation)
        with self._stats_lock:
            self.total_recorded += 1

        # Trigger immediate flush if buffer exceeds flush size
        with self._lock:
            buf_len = len(self._buffer)
        if buf_len >= self.flush_size:
            self._do_flush()

    def start(self) -> None:
        """Start background flush thread."""
        if self._running:
            return
        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="wifi-flush",
            daemon=True,
        )
        self._flush_thread.start()
        logger.info(
            "WiFi reporter started (server=%s, flush=%.0fs, batch=%d)",
            self.server_url,
            self.flush_interval,
            self.flush_size,
        )

    def stop(self) -> None:
        """Flush remaining buffer and stop."""
        self._running = False
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=10.0)
            self._flush_thread = None
        self._do_flush()
        logger.info(
            "WiFi reporter stopped (uploaded=%d, dropped=%d)",
            self.total_uploaded,
            self.total_dropped,
        )

    def _flush_loop(self) -> None:
        """Background loop: sleep then flush."""
        from sigrift.edge.scanner_config import reload_summarize

        while self._running:
            time.sleep(min(1.0, self.flush_interval))
            # Poll the on-disk config for a runtime summarize toggle
            # written by node_agent in response to bridge update_config.
            self.summarize = reload_summarize(self.summarize)
            # Only flush at interval boundary
            self._do_flush()
            # Next sleep for remaining interval
            remaining = max(0, self.flush_interval - 1.0)
            slept = 0.0
            while slept < remaining and self._running:
                time.sleep(min(1.0, remaining - slept))
                slept += 1.0

    def _do_flush(self) -> None:
        """Drain buffer and upload (raw or summarized)."""
        with self._lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()

        if self.summarize:
            summary = self._summarize_buffer(batch)
            result = self._upload_summary(summary)
            if result is not None:
                with self._stats_lock:
                    self.total_uploaded += len(batch)
                    self.total_batches += 1
                anomaly_ids = result.get("anomaly_ids", [])
                if anomaly_ids and self._pcap_source is not None:
                    self._upload_pcap_for_anomalies(anomaly_ids)
            else:
                with self._stats_lock:
                    self.total_dropped += len(batch)
            return

        # Raw upload path
        for i in range(0, len(batch), self.flush_size):
            chunk = batch[i : i + self.flush_size]
            result = self._upload_batch(chunk)
            if result is not None:
                with self._stats_lock:
                    self.total_uploaded += len(chunk)
                    self.total_batches += 1

                # Upload pcap captures for any detected anomalies
                anomaly_ids = result.get("anomaly_ids", [])
                if anomaly_ids and self._pcap_source is not None:
                    self._upload_pcap_for_anomalies(anomaly_ids)
            else:
                with self._stats_lock:
                    self.total_dropped += len(chunk)

    def _summarize_buffer(self, records: list[dict]) -> dict:
        """Aggregate raw WiFi records into a compact summary."""
        networks: dict[str, dict] = {}
        channel_frames: collections.Counter = collections.Counter()
        deauth_count = 0
        probe_count = 0

        for rec in records:
            bssid = rec.get("bssid", "")
            if bssid not in networks:
                networks[bssid] = {
                    "bssid": bssid,
                    "ssid": rec.get("ssid", ""),
                    "channel": rec.get("channel"),
                    "channel_width": rec.get("channel_width"),
                    "band": rec.get("band", ""),
                    "security": rec.get("security", ""),
                    "signal_max_dbm": rec.get("signal_dbm", -100),
                    "signal_sum": 0.0,
                    "frame_count": 0,
                    "clients": set(),
                    "first_seen": rec.get("timestamp", ""),
                    "last_seen": rec.get("timestamp", ""),
                }
            net = networks[bssid]
            sig = rec.get("signal_dbm", -100)
            net["signal_max_dbm"] = max(net["signal_max_dbm"], sig)
            net["signal_sum"] += sig
            net["frame_count"] += 1
            if rec.get("client_mac"):
                net["clients"].add(rec["client_mac"])
            net["last_seen"] = rec.get("timestamp", net["last_seen"])

            channel_frames[rec.get("channel", 0)] += 1
            if rec.get("frame_type") in ("deauth", "disassoc"):
                deauth_count += 1
            if rec.get("frame_type") == "probe_request":
                probe_count += 1

        network_list = []
        for net in networks.values():
            net["signal_avg_dbm"] = round(
                net["signal_sum"] / max(net["frame_count"], 1)
            )
            net["client_count"] = len(net["clients"])
            del net["signal_sum"]
            del net["clients"]
            network_list.append(net)

        total_frames = sum(channel_frames.values()) or 1
        channel_util = {
            str(ch): round(cnt / total_frames, 3) for ch, cnt in channel_frames.items()
        }

        return {
            "node_id": self.node_id,
            "scan_period_s": self.flush_interval,
            "total_frames": len(records),
            "networks": network_list,
            "channel_utilization": channel_util,
            "deauth_count": deauth_count,
            "probe_request_count": probe_count,
        }

    def _upload_summary(self, summary: dict) -> dict | None:
        """POST summary to /api/wifi/ingest-summary with retry.

        Returns the parsed JSON response on success, or None on failure.
        """
        url = f"{self.server_url}/api/wifi/ingest-summary"
        body = json.dumps(summary).encode("utf-8")

        delay = 1.0
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    **_auth_headers(self.api_key),
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    req, context=self._ssl_ctx, timeout=15
                ) as resp:
                    if resp.status in (200, 201):
                        resp_body = resp.read()
                        logger.info(
                            "Uploaded WiFi summary: %d networks, %d frames (batch %d)",
                            len(summary.get("networks", [])),
                            summary.get("total_frames", 0),
                            self.total_batches + 1,
                        )
                        try:
                            return json.loads(resp_body)
                        except (json.JSONDecodeError, ValueError):
                            return {"accepted": True}
                    logger.warning("Summary upload returned %d", resp.status)
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode()[:200]
                except Exception:
                    pass
                logger.warning(
                    "Summary upload attempt %d/%d HTTP %d: %s",
                    attempt,
                    self.max_retries,
                    e.code,
                    detail,
                )
                with self._stats_lock:
                    self.total_failures += 1
            except Exception as e:
                logger.warning(
                    "Summary upload attempt %d/%d failed: %s",
                    attempt,
                    self.max_retries,
                    e,
                )
                with self._stats_lock:
                    self.total_failures += 1

            if attempt < self.max_retries:
                jitter = delay * 0.2 * random.random()
                time.sleep(delay + jitter)
                delay = min(delay * 2, 30.0)

        return None

    def _upload_pcap_for_anomalies(self, anomaly_ids: list[int]) -> None:
        """Drain pcap ring buffer and upload for each anomaly ID."""
        pcap_gz = self._pcap_source.drain_pcap_ring()
        if not pcap_gz:
            logger.debug(
                "No pcap data in ring buffer for %d anomalies", len(anomaly_ids)
            )
            return

        # Upload the same pcap snapshot for each anomaly (they share the
        # same capture window since they came from the same ingest batch)
        for aid in anomaly_ids:
            self.upload_pcap(aid, pcap_gz)

    def _upload_batch(self, records: list[dict]) -> dict | None:
        """POST batch to /api/wifi/ingest with retry.

        Returns the parsed JSON response on success, or None on failure.
        """
        url = f"{self.server_url}/api/wifi/ingest"
        payload = {
            "node_id": self.node_id,
            "records": records,
        }
        body = json.dumps(payload).encode("utf-8")

        delay = 1.0
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                url,
                data=body,
                headers={
                    "Content-Type": "application/json",
                    **_auth_headers(self.api_key),
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    req, context=self._ssl_ctx, timeout=15
                ) as resp:
                    if resp.status in (200, 201):
                        resp_body = resp.read()
                        logger.info(
                            "Uploaded %d WiFi records (batch %d)",
                            len(records),
                            self.total_batches + 1,
                        )
                        try:
                            return json.loads(resp_body)
                        except (json.JSONDecodeError, ValueError):
                            return {"accepted": True}
                    logger.warning("Upload returned %d", resp.status)
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode()[:200]
                except Exception:
                    pass
                logger.warning(
                    "Upload attempt %d/%d HTTP %d: %s",
                    attempt,
                    self.max_retries,
                    e.code,
                    detail,
                )
                with self._stats_lock:
                    self.total_failures += 1
            except Exception as e:
                logger.warning(
                    "Upload attempt %d/%d failed: %s", attempt, self.max_retries, e
                )
                with self._stats_lock:
                    self.total_failures += 1

            if attempt < self.max_retries:
                jitter = delay * 0.2 * random.random()
                time.sleep(delay + jitter)
                delay = min(delay * 2, 30.0)

        return None

    def upload_pcap(self, anomaly_id: int, pcap_gz: bytes) -> bool:
        """Upload gzip-compressed pcap data for a WiFi anomaly.

        Parameters
        ----------
        anomaly_id : int
            WiFi anomaly row ID from the bridge.
        pcap_gz : bytes
            Gzip-compressed pcap file data.
        """
        url = f"{self.server_url}/api/wifi/anomalies/{anomaly_id}/pcap"
        req = urllib.request.Request(
            url,
            data=pcap_gz,
            headers={
                "Content-Type": "application/octet-stream",
                **_auth_headers(self.api_key),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                if resp.status in (200, 201):
                    with self._stats_lock:
                        self.total_pcap_uploads += 1
                    logger.info(
                        "Uploaded pcap for anomaly %d (%d bytes)",
                        anomaly_id,
                        len(pcap_gz),
                    )
                    return True
                logger.warning(
                    "Pcap upload for anomaly %d returned %d", anomaly_id, resp.status
                )
        except Exception as e:
            logger.warning("Pcap upload for anomaly %d failed: %s", anomaly_id, e)
        return False


# ---------------------------------------------------------------------------
# Synthetic frame generator (for --test mode)
# ---------------------------------------------------------------------------


def _generate_synthetic_frames(
    reporter: WifiReporter,
    running: threading.Event,
    count: int = 500,
    interval: float = 0.02,
) -> None:
    """Generate synthetic WiFi observations for testing."""
    test_networks = [
        ("aa:bb:cc:dd:ee:01", "HomeNetwork-5G", 36, "5GHz", "WPA2"),
        ("aa:bb:cc:dd:ee:02", "CoffeeShop_Free", 1, "2.4GHz", "Open"),
        ("aa:bb:cc:dd:ee:03", "CorpWiFi", 6, "2.4GHz", "WPA3"),
        ("aa:bb:cc:dd:ee:04", "IoT_Devices", 11, "2.4GHz", "WPA2"),
        ("aa:bb:cc:dd:ee:05", "Hidden", 44, "5GHz", "WPA2"),
        ("aa:bb:cc:dd:ee:06", "Neighbor_Net", 149, "5GHz", "WPA2/WPA"),
        ("aa:bb:cc:dd:ee:07", "Guest_Network", 6, "2.4GHz", "WPA2"),
        ("aa:bb:cc:dd:ee:08", "", 48, "5GHz", "WPA2"),  # hidden SSID
    ]

    test_clients = [
        "11:22:33:44:55:01",
        "11:22:33:44:55:02",
        "11:22:33:44:55:03",
        "11:22:33:44:55:04",
        "11:22:33:44:55:05",
    ]

    frame_types = ["beacon", "probe_resp", "probe_req", "data", "assoc_req"]

    logger.info("Generating %d synthetic WiFi observations...", count)
    for i in range(count):
        if not running.is_set():
            break

        bssid, ssid, channel, band, security = random.choice(test_networks)
        ft = random.choice(frame_types)
        client = (
            random.choice(test_clients)
            if ft in ("data", "assoc_req", "probe_req")
            else ""
        )

        obs = {
            "bssid": bssid,
            "ssid": ssid if ft != "probe_req" else "",
            "channel": channel,
            "channel_width": random.choice([20, 40, 80]),
            "band": band,
            "security": security if ft in ("beacon", "probe_resp") else "",
            "signal_dbm": random.uniform(-90, -30),
            "noise_dbm": random.uniform(-100, -90),
            "frame_type": ft,
            "client_mac": client,
            "data_rate_mbps": random.choice(
                [6.0, 12.0, 24.0, 54.0, 65.0, 130.0, 300.0]
            ),
            "retry_flag": random.choice([0, 0, 0, 1]),
        }
        reporter.record(obs)

        if (i + 1) % 100 == 0:
            logger.info(
                "[%d/%d] recorded=%d uploaded=%d batches=%d dropped=%d",
                i + 1,
                count,
                reporter.total_recorded,
                reporter.total_uploaded,
                reporter.total_batches,
                reporter.total_dropped,
            )

        time.sleep(interval)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main() -> int:
    bridge_url = os.environ.get("MLRF_BRIDGE_URL", "")
    bridge_key = os.environ.get("MLRF_BRIDGE_KEY", "")
    node_id = os.environ.get("MLRF_NODE_ID", "")
    iface = os.environ.get("MLRF_WIFI_IFACE", "wlan1")
    bands = os.environ.get("MLRF_WIFI_BANDS", "both")
    channel_dwell = float(os.environ.get("MLRF_CHANNEL_DWELL", "0.5"))
    # MLRF_SUMMARIZE is the unified knob across rf/wifi/bt scanners
    # (default on). MLRF_WIFI_SUMMARIZE is the legacy name and is honored
    # for one release as a fallback; a deprecation note is logged when used.
    _raw_summarize = os.environ.get("MLRF_SUMMARIZE")
    _truthy = ("true", "1", "yes", "on")
    if _raw_summarize is None:
        _legacy = os.environ.get("MLRF_WIFI_SUMMARIZE")
        if _legacy is not None:
            logger.warning(
                "MLRF_WIFI_SUMMARIZE is deprecated; use MLRF_SUMMARIZE instead"
            )
            summarize = _legacy.lower() in _truthy
        else:
            summarize = True
    else:
        summarize = _raw_summarize.lower() in _truthy
    flush_default = "30" if summarize else "10"
    flush_interval = float(os.environ.get("MLRF_FLUSH_INTERVAL", flush_default))
    # Size cap: 200 frames hits in 2-8 seconds in a busy RF environment,
    # which trips the size-based flush long before the time window closes
    # and produces near-realtime micro-summaries instead of true windowed
    # roll-ups. Use a larger cap when summarizing so the time window
    # actually drives cadence; keep 200 for raw mode where small batches
    # match the per-frame upload intent. Override per-host via MLRF_FLUSH_SIZE.
    size_default = "2000" if summarize else "200"
    flush_size = int(os.environ.get("MLRF_FLUSH_SIZE", size_default))

    test_mode = "--test" in sys.argv

    if not bridge_url or not bridge_key or not node_id:
        if not test_mode:
            logger.error("MLRF_BRIDGE_URL, MLRF_BRIDGE_KEY, MLRF_NODE_ID required")
            return 1
        # Defaults for test mode
        bridge_url = bridge_url or "https://localhost:8444"
        bridge_key = bridge_key or "test-key"
        node_id = node_id or "wifi-test-node"

    logger.info("=== WiFi Scanner v%s — %s ===", SCANNER_VERSION, node_id)
    logger.info("Bridge: %s", bridge_url)
    logger.info(
        "Interface: %s | Bands: %s | Dwell: %.1fs | Summarize: %s",
        iface,
        bands,
        channel_dwell,
        summarize,
    )
    if not _check_tls_config():
        return 1

    # Initialize reporter
    reporter = WifiReporter(
        server_url=bridge_url,
        api_key=bridge_key,
        node_id=node_id,
        flush_interval=flush_interval,
        flush_size=flush_size,
        summarize=summarize,
    )

    # Running flag for clean shutdown; stop_event is its inverse for waits.
    running = threading.Event()
    running.set()
    stop_event = threading.Event()
    scanner = None

    def _shutdown(sig, _frame):
        logger.info("Shutting down (signal %d)...", sig)
        running.clear()
        stop_event.set()
        if scanner is not None:
            scanner.request_stop()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    if test_mode:
        # Synthetic mode — no hardware needed
        reporter.start()
        logger.info("Running in TEST mode (synthetic frames)")
        _generate_synthetic_frames(reporter, running)
        time.sleep(flush_interval + 2)
        reporter.stop()
        logger.info(
            "Test complete: recorded=%d uploaded=%d batches=%d dropped=%d",
            reporter.total_recorded,
            reporter.total_uploaded,
            reporter.total_batches,
            reporter.total_dropped,
        )
        return 0

    # Real capture mode. The adapter is pinned by name and, once setup has
    # run, by identity. An adapter that returns under another name is not
    # followed: setup pins the name and keeps the management interface out
    # of reach, so it stays sensor_absent until setup is re-run.
    identity = os.environ.get("MLRF_WIFI_IDENTITY", "").strip().lower() or None
    if identity is not None and not re.fullmatch(r"[0-9a-f]{64}", identity):
        logger.error("MLRF_WIFI_IDENTITY is invalid; re-run scanner setup")
        return 1
    logger.info(
        "Adapter identity: %s",
        "pinned by setup" if identity else "not configured (any adapter)",
    )

    def probe() -> sensor_presence.Presence:
        return sensor_presence.find_wifi_sensor(iface, identity, sysfs=NET_SYSFS)

    tracker = sensor_presence.PresenceTracker("wifi", logger)
    # Wire pcap source BEFORE starting flush thread
    scanner = WifiScanner(
        iface=iface, bands=bands, channel_dwell=channel_dwell, probe=probe
    )
    reporter._pcap_source = scanner
    reporter.start()
    # Why capture is not running, from the closed list. "starting" holds
    # until a round ends; a returning sensor keeps its reason until then.
    not_running = [sensor_presence.STARTING]

    def sensor_changed(reason: str | None) -> None:
        if reason is not None:
            not_running[0] = reason

    def capture_status():
        if not running.is_set():
            return "stopped"
        if scanner.capture_state() == "running":
            return "running"
        # Set by the watchdog before teardown, which can take seconds.
        if scanner.end_reason is not None:
            return "error", scanner.end_reason
        if scanner.captured and scanner._running:
            return "error", sensor_presence.CAPTURE_FAILED  # ran, then stalled
        return "error", not_running[0]

    scanner_status = ScannerStatusReporter(
        bridge_url,
        node_id,
        "wifi",
        _build_ssl_context,
        lambda: _auth_headers(bridge_key),
        capture_status,
    )
    frames_total = 0
    networks_seen: set[str] = set()

    def capture_round() -> str | None:
        """One capture round; None when stopping, else the reason it ended."""
        nonlocal frames_total
        try:
            try:
                scanner.start()
            except subprocess.CalledProcessError as exc:
                if not stop_event.is_set():
                    scanner.failures.warn(
                        "Could not enable monitor mode on %s: %s %s",
                        iface,
                        exc,
                        (exc.stderr or b"").decode(errors="replace").strip()[:200],
                    )
                return None if stop_event.is_set() else sensor_presence.CAPTURE_FAILED
            except SensorLost:
                return None if stop_event.is_set() else scanner.end_reason
            # A signal can arrive during monitor setup, before start() sets its
            # internal running flag. Preserve the outer cancellation request.
            if stop_event.is_set():
                scanner.request_stop()

            last_status = time.monotonic()

            for obs in scanner.read_frames():
                if stop_event.is_set():
                    break

                reporter.record(obs)
                frames_total += 1
                if obs.get("bssid"):
                    networks_seen.add(obs["bssid"])

                # Status log every 30 seconds
                now = time.monotonic()
                if now - last_status >= 30.0:
                    logger.info(
                        "Status: %d frames, %d networks, ch=%d | "
                        "uploaded=%d batches=%d dropped=%d pcaps=%d",
                        frames_total,
                        len(networks_seen),
                        scanner._current_channel,
                        reporter.total_uploaded,
                        reporter.total_batches,
                        reporter.total_dropped,
                        reporter.total_pcap_uploads,
                    )
                    last_status = now
        except (FileNotFoundError, PermissionError):
            raise  # A missing tool or privilege; main() exits.
        except Exception as exc:
            if not stop_event.is_set():
                scanner.failures.warn("Capture error on %s: %s", iface, exc)
        finally:
            try:
                scanner.stop()
            except Exception as exc:
                # The next round sets monitor mode again anyway.
                logger.error("Could not restore managed mode on %s: %s", iface, exc)
        if stop_event.is_set():
            return None
        return scanner.end_reason or sensor_presence.CAPTURE_FAILED

    final_status, final_reason, exit_code = "stopped", None, 0
    scanner_status.start()
    delay = RETRY_INTERVAL
    try:
        # Wait for the radio, capture until the round ends, clean up, repeat.
        # Only a signal or an error that waiting cannot fix ends the loop.
        while not stop_event.is_set():
            found = sensor_presence.wait_until_present(
                probe,
                stop_event,
                tracker,
                interval=RETRY_INTERVAL,
                on_change=sensor_changed,
            )
            if found is None:
                break
            ended = capture_round()
            if ended is None:
                break
            not_running[0] = ended
            # Now held in not_running, which a later presence change updates.
            scanner.end_reason = None
            if scanner.captured:
                delay = RETRY_INTERVAL
            if ended == sensor_presence.CAPTURE_FAILED and probe().state == "present":
                # A present radio that keeps failing is retried with back-off.
                stop_event.wait(delay)
                delay = min(delay * 2, RETRY_MAX)
    except (FileNotFoundError, PermissionError) as exc:
        if not stop_event.is_set():
            logger.error("Cannot capture on %s: %s", iface, exc)
            final_status, final_reason = "error", sensor_presence.CAPTURE_FAILED
            exit_code = 1
    except KeyboardInterrupt:
        running.clear()
        stop_event.set()
    finally:
        try:
            scanner_status.stop(final_status, final_reason)
        finally:
            reporter.stop()

    logger.info(
        "Stopped: %d frames, %d networks, %d uploaded, %d dropped",
        frames_total,
        len(networks_seen),
        reporter.total_uploaded,
        reporter.total_dropped,
    )
    return exit_code


if __name__ == "__main__":
    sys.exit(main() or 0)
