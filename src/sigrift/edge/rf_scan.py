#!/usr/bin/env python3
"""RF scan loop for ONNX edge nodes.

Scans frequencies via rtl_tcp and/or hackrf_transfer, classifies with
ONNX Runtime, and reports detections to The Bridge via DetectionReporter.

Env vars:
    MLRF_BRIDGE_URL   - Bridge server URL (required)
    MLRF_BRIDGE_KEY   - Bridge API key (required)
    MLRF_NODE_ID      - Node identifier (required)
    MLRF_MODEL_PATH   - Path to ONNX model (default: /home/pi/mlrf-agent/gen3_edge_*.onnx)
    MLRF_RTL_HOST     - rtl_tcp host (default: 127.0.0.1)
    MLRF_RTL_PORT     - rtl_tcp port (default: 1234)
    MLRF_RTL_STATUS_PORT - rtl-tcp supervisor state port on MLRF_RTL_HOST,
                        asked why rtl_tcp cannot capture (default: 1235)
    MLRF_CAPTURE_MODE - "rtltcp", "hackrf", "b210", or "dual" (default: rtltcp)
    MLRF_RTL_SAMPLE_RATE - rtl_tcp scan sample rate in Hz, set on every
                        connect (default: 2048000, rtl_tcp's own default)
    MLRF_RTL_GAIN     - rtl_tcp scan gain in dB (default: unset = leave the
                        gain rtl_tcp was started with; tuner AGC after a
                        remote iq_capture that set a gain)
    MLRF_DWELL_TIME   - seconds per frequency (default: 0.25)
    MLRF_INTER_THREADS - ONNX inter_op threads (default: 2)
    MLRF_INTRA_THREADS - ONNX intra_op threads (default: 4)
    MLRF_CA_CERT      - CA bundle used to verify the bridge (default: system store)
    MLRF_CA_BUNDLE    - Alternative name for MLRF_CA_CERT
    MLRF_INSECURE_TLS - "1" disables TLS verification (NOT recommended)
"""

import gzip
import inspect
import json
import logging
import math
import os
import queue
import re
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import ssl
from datetime import datetime, timezone
from glob import glob
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import numpy as np

try:
    from sigrift.edge.scanner_status import CaptureActivity, ScannerStatusReporter
except ImportError:  # Legacy standalone edge directory.
    from scanner_status import CaptureActivity, ScannerStatusReporter

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Both AGENT_DIR (for legacy model globbing + sys.path) and LOG_DIR
# are env-configurable so this script runs cleanly in a container
# where /opt/rf-edge and /home/pi/mlrf-agent don't exist. In the
# compose `scan` service we mount /opt/sigrift/models at /app/models
# and set MLRF_AGENT_DIR=/app/models, MLRF_LOG_DIR=/app/logs.
AGENT_DIR = Path(os.environ.get("MLRF_AGENT_DIR", "/home/pi/mlrf-agent"))
sys.path.insert(0, str(AGENT_DIR))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR = Path(os.environ.get("MLRF_LOG_DIR", "/opt/rf-edge/logs"))
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOG_DIR / "rf_scan.log"),
    ],
)
logger = logging.getLogger("rf_scan")

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
# Same policy as node_agent, wifi_scan and detection_reporter; the block is
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
        "the API key and uploaded IQ captures",
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
# Configuration
# ---------------------------------------------------------------------------

# Extended-range RTL-SDR (V4) extra HF frequencies: 500 kHz – 24 MHz
# Enabled via MLRF_EXTENDED_HF=1 env var for nodes with V4 dongles
EXTENDED_HF_FREQUENCIES = {
    0.5: "MF 500 kHz",
    1.0: "MF 1 MHz",
    1.8: "160m Ham",
    3.5: "80m Ham",
    3.885: "80m SSB",
    5.3305: "60m Ham",
    7.074: "40m FT8",
    7.2: "40m Ham",
    10.136: "30m FT8",
    14.074: "20m FT8",
    14.3: "20m SSB",
    18.1: "17m Ham",
    21.074: "15m FT8",
    24.915: "12m Ham",
}

# Extended upper range for wideband RTL-SDR dongles (e.g. Nooelec SMArt v5)
# that tune above 1766 MHz up to ~2300 MHz. Enabled via MLRF_EXTENDED_UPPER=1.
EXTENDED_UPPER_FREQUENCIES = {
    1800.0: "GSM 1800",
    1930.0: "PCS 1900",
    2110.0: "UMTS 2100",
    2200.0: "S-band 2.2 GHz",
}

# RTL-SDR range: 24–1766 MHz — cover all major allocations
FREQUENCIES = {
    # HF/VHF low (RTL-SDR starts ~24 MHz)
    27.185: "CB Ch19",
    28.4: "10m Ham",
    50.125: "6m Ham",
    # VHF broadcast & air
    88.1: "FM Broadcast low",
    97.5: "FM Broadcast mid",
    107.9: "FM Broadcast high",
    118.0: "Air Band",
    121.5: "Aviation Emergency",
    127.85: "Air Band upper",
    # VHF marine, weather, public safety
    146.52: "2m Ham",
    151.625: "MURS Ch1",
    154.57: "Public Safety",
    156.8: "Marine Ch16",
    162.4: "NOAA Weather 1",
    162.55: "NOAA Weather 7",
    169.445: "MURS Ch5",
    # UHF
    220.0: "1.25m Ham",
    315.0: "Keyless Entry/Remotes",
    390.0: "US Military UHF",
    406.0: "EPIRB/SARSAT",
    420.0: "70cm Ham low",
    433.92: "ISM 433",
    446.0: "GMRS/FRS",
    450.0: "70cm Ham high",
    462.5625: "FRS Ch1",
    467.5625: "GMRS Rpt",
    # P25 / LMR
    769.0: "FirstNet/700MHz",
    # ISM & IoT
    868.3: "LoRa EU",
    902.0: "ISM 902 low",
    915.0: "ISM 915 mid",
    928.0: "ISM 928 high",
    # Cellular (within RTL-SDR range)
    880.0: "GSM 900 uplink",
    935.0: "GSM 900 downlink",
    # L-band (RTL-SDR upper range)
    1030.0: "Mode-S interrogation",
    1090.0: "ADS-B",
    1176.45: "GPS L5",
    1227.60: "GPS L2",
    1381.05: "Iridium Ring Alert",
    1545.0: "Inmarsat",
    1575.42: "GPS L1",
    1621.35: "Iridium",
    1688.0: "GOES LRIT",
    1700.0: "NOAA HRPT",
}

# HackRF can tune 1 MHz–6 GHz — extra frequencies beyond RTL-SDR range
HACKRF_EXTRA_FREQUENCIES = {
    # GSM/UMTS upper bands
    1800.0: "GSM 1800",
    1930.0: "PCS 1900",
    2110.0: "UMTS 2100",
    # 2.4 GHz ISM / WiFi / Bluetooth / Zigbee
    2412.0: "WiFi Ch1",
    2437.0: "WiFi Ch6",
    2462.0: "WiFi Ch11",
    # LTE
    2600.0: "LTE B7",
    3500.0: "CBRS/5G mid-band",
    # 5 GHz WiFi (UNII bands)
    5180.0: "WiFi 5G Ch36",
    5240.0: "WiFi 5G Ch48",
    5320.0: "WiFi 5G Ch64",
    5500.0: "WiFi 5G Ch100",
    5660.0: "WiFi 5G Ch132",
    5745.0: "WiFi 5G Ch149",
    5825.0: "WiFi 5G Ch165",
}

# Merge extended HF if enabled (RTL-SDR V4 / extended-range dongle)
if os.environ.get("MLRF_EXTENDED_HF", "").lower() in ("1", "true", "yes"):
    FREQUENCIES.update(EXTENDED_HF_FREQUENCIES)

# Merge extended upper range if enabled (wideband dongles tuning above 1766 MHz)
if os.environ.get("MLRF_EXTENDED_UPPER", "").lower() in ("1", "true", "yes"):
    FREQUENCIES.update(EXTENDED_UPPER_FREQUENCIES)

DWELL_TIME = float(os.environ.get("MLRF_DWELL_TIME", "0.25"))
INPUT_SAMPLES = int(os.environ.get("MLRF_INPUT_SAMPLES", "4096"))
SNR_THRESHOLD = 5.0
STATUS_PORT = 8080

# Bounds for the remote ``iq_capture`` command (bridge -> node_agent ->
# POST /capture). Its fields are untrusted: n_samples = sample_rate x
# duration_ms is otherwise unbounded and a single command could exhaust
# memory on the edge node.
IQ_CAPTURE_MAX_SAMPLES = 1 << 23  # ~3.5 s at 2.4 Msps; 64 MiB as complex64
IQ_CAPTURE_MAX_DURATION_MS = 60_000.0
IQ_CAPTURE_MAX_SAMPLE_RATE = 61.44e6  # B210 ceiling; RTL/HackRF are lower
IQ_CAPTURE_MAX_FREQ_HZ = 7.25e9  # HackRF upper tuning limit
IQ_CAPTURE_MAX_GAIN_DB = 102.0  # HackRF LNA+VGA reach; RTL ~50 dB and B210
# ~76 dB are clamped to the device range in each backend's configure_capture.
_IQ_COMMAND_ID_MAX_LEN = 64


def _iq_capture_number(cmd: dict, name: str, default: float) -> float:
    """Fetch a finite numeric field from an iq_capture command."""
    value = cmd.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number, got {value!r}")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite, got {value!r}")
    return value


def iq_capture_sample_count(sample_rate: float, duration_ms: float) -> int:
    """Samples for *duration_ms* at *sample_rate*, in [INPUT_SAMPLES, MAX]."""
    n_samples = max(int(sample_rate * duration_ms / 1000), INPUT_SAMPLES)
    if n_samples > IQ_CAPTURE_MAX_SAMPLES:
        logger.warning(
            "iq_capture: %d samples requested, capping at %d",
            n_samples,
            IQ_CAPTURE_MAX_SAMPLES,
        )
        n_samples = IQ_CAPTURE_MAX_SAMPLES
    return n_samples


def parse_iq_capture_command(cmd: object) -> dict:
    """Validate and clamp a remote iq_capture command.

    Returns a dict with ``freq_hz``, ``duration_ms``, ``sample_rate``,
    ``gain_db`` (None when the command has none), ``n_samples`` and a
    sanitised ``command_id``. ``n_samples`` is for the *requested* rate and
    capped at IQ_CAPTURE_MAX_SAMPLES; the capture itself recomputes it for
    the rate the device actually runs at. Raises ValueError for nonsense
    input (wrong types, NaN/inf, non-positive or out-of-range values).
    """
    if not isinstance(cmd, dict):
        raise ValueError("iq_capture command must be a JSON object")

    freq_hz = _iq_capture_number(cmd, "freq_hz", 0)
    if not 0 < freq_hz <= IQ_CAPTURE_MAX_FREQ_HZ:
        raise ValueError(f"freq_hz out of range: {freq_hz!r}")

    duration_ms = _iq_capture_number(cmd, "duration_ms", 1000)
    if not 0 < duration_ms <= IQ_CAPTURE_MAX_DURATION_MS:
        raise ValueError(f"duration_ms out of range: {duration_ms!r}")

    sample_rate = _iq_capture_number(cmd, "sample_rate", 2.4e6)
    if not 0 < sample_rate <= IQ_CAPTURE_MAX_SAMPLE_RATE:
        raise ValueError(f"sample_rate out of range: {sample_rate!r}")

    gain_db = None
    if cmd.get("gain_db") is not None:
        gain_db = _iq_capture_number(cmd, "gain_db", 0)
        if not 0 <= gain_db <= IQ_CAPTURE_MAX_GAIN_DB:
            raise ValueError(f"gain_db out of range: {gain_db!r}")

    n_samples = iq_capture_sample_count(sample_rate, duration_ms)

    # command_id ends up in the upload URL path -- keep it to a safe charset.
    raw_id = str(cmd.get("command_id", "manual"))[:_IQ_COMMAND_ID_MAX_LEN]
    command_id = (
        "".join(
            c if c.isascii() and (c.isalnum() or c in "-_.") else "_" for c in raw_id
        )
        or "manual"
    )

    return {
        "freq_hz": freq_hz,
        "duration_ms": duration_ms,
        "sample_rate": sample_rate,
        "gain_db": gain_db,
        "n_samples": n_samples,
        "command_id": command_id,
    }


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------

state = {
    "start_time": None,
    "scan_count": 0,
    "detections": 0,
    "last_scan": None,
    "rtl_connected": False,
    "hackrf_connected": False,
    "bridge_connected": False,
    "bridge_uploaded": 0,
    "cls_per_sec": 0.0,
    "capture_mode": "rtltcp",
    "last_error": None,
    "last_successful_capture": None,
    "running": True,
    "anomaly_enabled": False,
    "anomaly_count": 0,
    "anomaly_baseline": "unknown",
}

# Thread-safe queue for on-demand IQ capture requests
capture_queue: queue.Queue = queue.Queue(maxsize=20)


# ---------------------------------------------------------------------------
# SDR backends
# ---------------------------------------------------------------------------
# Every backend scans at a fixed, known rate and gain. A remote iq_capture
# can ask for another rate and gain: configure_capture() applies what the
# device supports and returns the sample rate the device then really runs
# at (that is what the upload reports in X-Sample-Rate), and
# restore_scan_settings() puts the scan settings back afterwards.


def _env_number(name: str, default: float | None) -> float | None:
    """Finite float from env var *name*, or *default* when unset/invalid."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        value = math.nan
    if not math.isfinite(value) or value < 0:
        logger.error("%s=%r is not a valid number; using %s", name, raw, default)
        return default
    return value


# rtl_tcp control protocol (librtlsdr src/rtl_tcp.c): each command is one
# byte followed by a 4-byte big-endian parameter.
_RTL_CMD_SET_FREQ = 0x01
_RTL_CMD_SET_SAMPLE_RATE = 0x02
_RTL_CMD_SET_GAIN_MODE = 0x03  # 0 = automatic (tuner AGC), 1 = manual
_RTL_CMD_SET_GAIN = 0x04  # tenths of a dB
# Sent once after connect: b"RTL0" + tuner type (u32) + gain count (u32).
_RTL_HEADER_LEN = 12
RTL_TCP_DEFAULT_SAMPLE_RATE = 2_048_000  # rtl_tcp's built-in default (-s)
_RTL_XTAL_HZ = 28_800_000


def rtl_sample_rate_supported(rate: float) -> bool:
    """Whether librtlsdr accepts *rate* (anything else leaves the rate as-is)."""
    return 225_000 < rate <= 300_000 or 900_000 < rate <= 3_200_000


RTL_RETRY_SECONDS = 5.0  # between reconnection attempts while rtl_tcp is away
RTL_STATUS_TIMEOUT = 1.0
DEFAULT_RTL_STATUS_PORT = 1235
# What the rtl-tcp supervisor may answer that is also a status reason; any other
# answer (or none) means capture_failed. Literal strings, like scanner_status,
# so legacy standalone copies import without sensor_presence.
_SUPERVISOR_REASONS = frozenset({"sensor_absent", "sensor_changed", "sensor_unusable"})


def rtl_supervisor_reason(host, port, timeout=RTL_STATUS_TIMEOUT) -> str:
    """Why rtl_tcp cannot capture, from the rtl-tcp supervisor's state port."""
    answer = b""
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            while len(answer) < 64 and b"\n" not in answer:
                chunk = conn.recv(64 - len(answer))
                if not chunk:
                    break
                answer += chunk
    except Exception:
        return "capture_failed"
    text = answer.decode("ascii", "replace").strip()
    return text if text in _SUPERVISOR_REASONS else "capture_failed"


def _rtl_status_port() -> int:
    try:
        port = int(os.environ.get("MLRF_RTL_STATUS_PORT", DEFAULT_RTL_STATUS_PORT))
    except ValueError:
        return DEFAULT_RTL_STATUS_PORT
    return port if 0 < port < 65536 else DEFAULT_RTL_STATUS_PORT


def rtl_actual_sample_rate(rate: int) -> float:
    """The rate an RTL2832U really samples at when *rate* is requested.

    Same resampler arithmetic as librtlsdr's rtlsdr_set_sample_rate(),
    which stores the result as an integer.
    """
    ratio = int(_RTL_XTAL_HZ * (1 << 22) / rate) & 0x0FFFFFFC
    real_ratio = ratio | ((ratio & 0x08000000) << 1)
    return float(int(_RTL_XTAL_HZ * (1 << 22) / real_ratio))


class RTLTCPClient:
    """Persistent rtl_tcp connection for IQ capture.

    rtl_tcp streams interleaved unsigned 8-bit I/Q bytes without framing.
    The client counts every stream byte it consumes after the 12-byte
    header, so a capture always starts on an I byte: dropping stale data
    in arbitrary-sized chunks can stop on an odd byte count, and reading
    on from there would swap I and Q (a mirrored spectrum) in this and
    every later capture.

    While rtl_tcp is unreachable or capture fails, reconnection waits
    ``retry_interval`` (see ``retry_in``), one line is logged when it becomes
    unavailable and one when capture resumes, and ``unavailable_reason`` says
    why, as the supervisor reports it.
    """

    def __init__(
        self,
        host="127.0.0.1",
        port=1234,
        sample_rate=None,
        gain_db=None,
        status_port=None,
    ):
        self.host = host
        self.port = port
        self.status_port = _rtl_status_port() if status_port is None else status_port
        self.retry_interval = RTL_RETRY_SECONDS
        self.unavailable_reason = None
        self._retry_at = 0.0
        self._available = None  # unknown until the first capture or failure
        self.sock = None
        self.name = "rtltcp"
        if sample_rate is None:
            sample_rate = _env_number(
                "MLRF_RTL_SAMPLE_RATE", RTL_TCP_DEFAULT_SAMPLE_RATE
            )
        if not rtl_sample_rate_supported(sample_rate):
            logger.error(
                "rtl_tcp scan rate %.0f Hz is not supported by the RTL2832U "
                "(225-300 kHz or 0.9-3.2 MHz); using %d Hz",
                sample_rate,
                RTL_TCP_DEFAULT_SAMPLE_RATE,
            )
            sample_rate = RTL_TCP_DEFAULT_SAMPLE_RATE
        self.scan_sample_rate = int(sample_rate)
        self.scan_gain_db = (
            _env_number("MLRF_RTL_GAIN", None) if gain_db is None else gain_db
        )
        self._rate_setting = self.scan_sample_rate  # last rate sent to rtl_tcp
        self._gain_overridden = False  # an iq_capture changed the gain
        self._stream_bytes = 0  # I/Q bytes consumed since the header

    @property
    def connected(self):
        return self.sock is not None

    @property
    def sample_rate(self) -> float:
        """Rate the dongle is sampling at right now (Hz)."""
        return rtl_actual_sample_rate(self._rate_setting)

    def retry_in(self) -> float:
        """Seconds until a reconnection attempt is due (0 when due)."""
        if self.connected:
            return 0.0
        return max(0.0, self._retry_at - time.monotonic())

    def _unavailable(self, error) -> None:
        """Close the stream; log once per outage (and on a new reason)."""
        self.disconnect()
        self._retry_at = time.monotonic() + self.retry_interval
        reason = rtl_supervisor_reason(self.host, self.status_port)
        if self._available is not False:
            logger.warning(
                "rtl_tcp %s:%d unavailable (%s; receiver: %s); retrying every %g s",
                self.host,
                self.port,
                error,
                reason,
                self.retry_interval,
            )
        elif reason != self.unavailable_reason:
            logger.warning(
                "rtl_tcp %s:%d still unavailable (receiver: %s)",
                self.host,
                self.port,
                reason,
            )
        self._available = False
        self.unavailable_reason = reason

    def _command(self, cmd: int, param: int) -> None:
        self.sock.sendall(struct.pack(">BI", cmd, param))

    def _set_manual_gain(self, gain_db: float) -> None:
        self._command(_RTL_CMD_SET_GAIN_MODE, 1)
        self._command(_RTL_CMD_SET_GAIN, int(round(gain_db * 10)))

    def _recv_exact(self, n: int) -> bytearray:
        buf = bytearray(n)
        view = memoryview(buf)
        got = 0
        while got < n:
            k = self.sock.recv_into(view[got:], n - got)
            if not k:
                raise ConnectionError("rtl_tcp closed the connection")
            got += k
        self._stream_bytes += n
        return buf

    def _discard_buffered(self) -> None:
        """Drop the samples queued since the last read (stale frequency/rate)."""
        self.sock.setblocking(False)
        try:
            while True:
                try:
                    chunk = self.sock.recv(65536)
                except BlockingIOError:
                    return
                if not chunk:
                    raise ConnectionError("rtl_tcp closed the connection")
                self._stream_bytes += len(chunk)
        finally:
            self.sock.setblocking(True)

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            header = self._recv_exact(_RTL_HEADER_LEN)
            if header[:4] != b"RTL0":
                logger.warning(
                    "rtl_tcp %s:%d sent an unexpected header %r",
                    self.host,
                    self.port,
                    bytes(header[:4]),
                )
            self._stream_bytes = 0
            # Set the scan rate explicitly so the rate is known (rtl_tcp
            # may have been started with any -s) and restorable.
            self._command(_RTL_CMD_SET_SAMPLE_RATE, self.scan_sample_rate)
            self._rate_setting = self.scan_sample_rate
            if self.scan_gain_db is not None:
                self._set_manual_gain(self.scan_gain_db)
            elif self._gain_overridden:
                # rtl_tcp keeps the dongle open across clients: undo a gain
                # an interrupted iq_capture left behind.
                self._command(_RTL_CMD_SET_GAIN_MODE, 0)
            self._gain_overridden = False
            if self._available is not False:
                # During an outage the "capture resumed" line says it instead.
                logger.info(
                    "Connected to rtl_tcp %s:%d (%.0f Hz)",
                    self.host,
                    self.port,
                    self.sample_rate,
                )
            state["rtl_connected"] = True
            return True
        except Exception as e:
            self._unavailable(f"connect failed: {e}")
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        self.sock = None
        state["rtl_connected"] = False

    def set_frequency(self, freq_hz):
        if not self.connected:
            return False
        try:
            self._command(_RTL_CMD_SET_FREQ, int(freq_hz))
            return True
        except Exception as e:
            self._unavailable(f"tune failed: {e}")
            return False

    def configure_capture(self, sample_rate, gain_db=None):
        """Apply an iq_capture's rate/gain; return the rate now in use (Hz)."""
        if not self.connected:
            return None
        rate = int(sample_rate)
        if not rtl_sample_rate_supported(rate):
            logger.warning(
                "rtl_tcp cannot sample at %.0f Hz (RTL2832U: 225-300 kHz or "
                "0.9-3.2 MHz); capturing at %.0f Hz",
                sample_rate,
                self.sample_rate,
            )
            rate = self._rate_setting
        try:
            if rate != self._rate_setting:
                self._command(_RTL_CMD_SET_SAMPLE_RATE, rate)
                self._rate_setting = rate
            if gain_db is not None:
                self._gain_overridden = True
                self._set_manual_gain(gain_db)
        except (OSError, struct.error) as e:
            logger.error("rtl_tcp capture setup failed: %s", e)
            self.disconnect()
            return None
        return self.sample_rate

    def restore_scan_settings(self):
        """Return to the scan rate and gain after an iq_capture."""
        if not self.connected:
            return
        try:
            if self._rate_setting != self.scan_sample_rate:
                self._command(_RTL_CMD_SET_SAMPLE_RATE, self.scan_sample_rate)
                self._rate_setting = self.scan_sample_rate
            if self._gain_overridden:
                if self.scan_gain_db is None:
                    self._command(_RTL_CMD_SET_GAIN_MODE, 0)
                else:
                    self._set_manual_gain(self.scan_gain_db)
                self._gain_overridden = False
        except (OSError, struct.error) as e:
            # connect() re-applies the scan settings on the next attempt.
            logger.error("rtl_tcp scan settings not restored: %s", e)
            self.disconnect()

    def capture(self, num_samples=INPUT_SAMPLES):
        if not self.connected:
            return None
        try:
            time.sleep(DWELL_TIME)
            self._discard_buffered()
            self.sock.settimeout(5)
            if self._stream_bytes % 2:
                self._recv_exact(1)  # finish the half-read sample: realign on I
            data = self._recv_exact(num_samples * 2)

            raw = np.frombuffer(data, dtype=np.uint8)
            iq = (raw.astype(np.float32) - 127.5) / 127.5
        except Exception as e:
            self._unavailable(f"capture failed: {e}")
            return None
        if self._available is False:
            logger.info("rtl_tcp %s:%d capture resumed", self.host, self.port)
        self._available = True
        self.unavailable_reason = None
        return iq[0::2] + 1j * iq[1::2]


# ---------------------------------------------------------------------------
# HackRF capture
# ---------------------------------------------------------------------------

HACKRF_SCAN_SAMPLE_RATE = 2_000_000
HACKRF_MIN_SAMPLE_RATE = 2_000_000  # hackrf_transfer -s limits
HACKRF_MAX_SAMPLE_RATE = 20_000_000
_HACKRF_SKIP_SAMPLES = 4096  # start-up transient discarded from each capture
_HACKRF_LNA_MAX, _HACKRF_LNA_STEP = 40, 8  # hackrf_transfer -l: 0-40 dB, 8 dB steps
_HACKRF_VGA_MAX, _HACKRF_VGA_STEP = 62, 2  # hackrf_transfer -g: 0-62 dB, 2 dB steps


def hackrf_split_gain(gain_db: float) -> tuple[int, int]:
    """Split a total RX gain into HackRF (LNA, VGA) settings.

    LNA gain first (better noise figure), the rest on the baseband VGA,
    each rounded down to the stage's step. The RF amp (``-a``) is not part
    of the split.
    """
    lna = min(_HACKRF_LNA_MAX, int(gain_db // _HACKRF_LNA_STEP) * _HACKRF_LNA_STEP)
    vga = min(
        _HACKRF_VGA_MAX,
        int((gain_db - lna) // _HACKRF_VGA_STEP) * _HACKRF_VGA_STEP,
    )
    return lna, max(vga, 0)


class HackRFCapture:
    """Capture IQ samples using hackrf_transfer subprocess."""

    def __init__(self):
        self.current_freq = 0
        self.lna_gain = int(os.environ.get("MLRF_HACKRF_LNA", "40"))
        self.vga_gain = int(os.environ.get("MLRF_HACKRF_VGA", "48"))
        self._scan_gains = (self.lna_gain, self.vga_gain)
        self.scan_sample_rate = HACKRF_SCAN_SAMPLE_RATE
        self.sample_rate = self.scan_sample_rate
        self.name = "hackrf"

    @property
    def connected(self):
        return True  # always available if binary exists

    def connect(self):
        state["hackrf_connected"] = True
        return True

    def disconnect(self):
        state["hackrf_connected"] = False

    def set_frequency(self, freq_hz):
        self.current_freq = int(freq_hz)
        return True

    def configure_capture(self, sample_rate, gain_db=None):
        """Apply an iq_capture's rate/gain; return the rate now in use (Hz)."""
        rate = int(sample_rate)
        if not HACKRF_MIN_SAMPLE_RATE <= rate <= HACKRF_MAX_SAMPLE_RATE:
            logger.warning(
                "HackRF cannot sample at %.0f Hz (2-20 MHz); capturing at %d Hz",
                sample_rate,
                self.scan_sample_rate,
            )
            rate = self.scan_sample_rate
        self.sample_rate = rate
        if gain_db is not None:
            self.lna_gain, self.vga_gain = hackrf_split_gain(gain_db)
        return float(rate)

    def restore_scan_settings(self):
        self.sample_rate = self.scan_sample_rate
        self.lna_gain, self.vga_gain = self._scan_gains

    def capture(self, num_samples=INPUT_SAMPLES):
        try:
            need_bytes = num_samples * 2
            # hackrf_transfer -n counts samples (2 bytes each), not bytes.
            n_transfer = num_samples + _HACKRF_SKIP_SAMPLES
            timeout = 5.0 + 2.0 * n_transfer / self.sample_rate
            # Use temp file instead of stdout for reliable capture
            with tempfile.NamedTemporaryFile(suffix=".iq", delete=True) as tmp:
                proc = subprocess.run(
                    [
                        "hackrf_transfer",
                        "-r",
                        tmp.name,
                        "-f",
                        str(self.current_freq),
                        "-s",
                        str(int(self.sample_rate)),
                        "-n",
                        str(n_transfer),
                        "-l",
                        str(self.lna_gain),
                        "-g",
                        str(self.vga_gain),
                        "-a",
                        "1",
                    ],
                    capture_output=True,
                    timeout=timeout,
                )
                if proc.returncode != 0:
                    return None
                data = tmp.read()
            if len(data) < need_bytes:
                return None
            # Skip the start-up transient; keep the offset even so the
            # slice starts on an I byte.
            offset = min(_HACKRF_SKIP_SAMPLES * 2, (len(data) - need_bytes) & ~1)
            raw = np.frombuffer(data[offset : offset + need_bytes], dtype=np.int8)
            iq = raw.astype(np.float32) / 128.0
            return iq[0::2] + 1j * iq[1::2]
        except Exception as e:
            logger.error("HackRF capture failed: %s", e)
            return None


class UHDClient:
    """Capture IQ samples from USRP B210/B200 via UHD Python API or rx_samples_to_file."""

    def __init__(self):
        self.current_freq = 0
        self.gain = int(os.environ.get("MLRF_UHD_GAIN", "40"))
        self.sample_rate = int(os.environ.get("MLRF_UHD_RATE", "2048000"))
        self.scan_sample_rate = self.sample_rate
        self.scan_gain = self.gain
        self.name = "b210"
        self._usrp = None
        self._connected = False

    @property
    def connected(self):
        return self._connected

    def connect(self):
        try:
            import uhd

            self._usrp = uhd.usrp.MultiUSRP()
            self._usrp.set_rx_rate(self.sample_rate)
            self._usrp.set_rx_gain(self.gain)
            self._connected = True
            logger.info(
                "Connected to USRP B210 (rate=%d, gain=%d)", self.sample_rate, self.gain
            )
            return True
        except ImportError:
            # Fallback: check for rx_samples_to_file CLI
            import shutil

            if shutil.which("rx_samples_to_file"):
                self._connected = True
                logger.info("USRP CLI mode (rx_samples_to_file)")
                return True
            logger.error("UHD Python API and rx_samples_to_file not found")
            return False
        except Exception as e:
            logger.error("USRP connect failed: %s", e)
            return False

    def disconnect(self):
        self._usrp = None
        self._connected = False

    def set_frequency(self, freq_hz):
        self.current_freq = int(freq_hz)
        if self._usrp is not None:
            try:
                import uhd

                self._usrp.set_rx_freq(uhd.libpyuhd.types.tune_request(float(freq_hz)))
            except Exception:
                pass
        return True

    def _apply_rate_gain(self, sample_rate, gain):
        """Set rate/gain; return the rate the device reports (Hz) or None."""
        if self._usrp is not None:
            try:
                self._usrp.set_rx_rate(float(sample_rate))
                self._usrp.set_rx_gain(gain)
                actual = float(self._usrp.get_rx_rate())
            except Exception as e:
                logger.error("USRP rate/gain change failed: %s", e)
                return None
        else:
            actual = float(sample_rate)  # rx_samples_to_file --rate
        self.sample_rate = actual
        self.gain = gain
        return actual

    def configure_capture(self, sample_rate, gain_db=None):
        """Apply an iq_capture's rate/gain; return the rate now in use (Hz)."""
        return self._apply_rate_gain(
            sample_rate, self.gain if gain_db is None else gain_db
        )

    def restore_scan_settings(self):
        self._apply_rate_gain(self.scan_sample_rate, self.scan_gain)

    def capture(self, num_samples=INPUT_SAMPLES):
        if self._usrp is not None:
            return self._capture_uhd_api(num_samples)
        return self._capture_uhd_cli(num_samples)

    def _capture_uhd_api(self, num_samples):
        try:
            import uhd

            self._usrp.set_rx_freq(
                uhd.libpyuhd.types.tune_request(float(self.current_freq))
            )
            streamer = self._usrp.get_rx_stream(uhd.usrp.StreamArgs("fc32", "sc16"))
            rx_md = uhd.types.RXMetadata()
            stream_cmd = uhd.types.StreamCMD(uhd.types.StreamMode.num_done)
            stream_cmd.num_samps = num_samples + 1024
            stream_cmd.stream_now = True
            streamer.issue_stream_cmd(stream_cmd)

            buf = np.zeros(num_samples + 1024, dtype=np.complex64)
            streamer.recv(buf, rx_md)

            # Skip first 1024 samples (transient)
            return buf[1024 : 1024 + num_samples]
        except Exception as e:
            logger.error("USRP API capture failed: %s", e)
            return None

    def _capture_uhd_cli(self, num_samples):
        try:
            nsamps = num_samples + 1024
            # --duration caps the run; leave room for the requested count.
            duration = math.ceil(nsamps / self.sample_rate) + 1
            with tempfile.NamedTemporaryFile(suffix=".cf32", delete=True) as tmp:
                cmd = [
                    "rx_samples_to_file",
                    "--file",
                    tmp.name,
                    "--type",
                    "float",
                    "--freq",
                    str(self.current_freq),
                    "--rate",
                    str(self.sample_rate),
                    "--gain",
                    str(self.gain),
                    "--nsamps",
                    str(nsamps),
                    "--duration",
                    str(duration),
                ]
                proc = subprocess.run(cmd, capture_output=True, timeout=duration + 4)
                if proc.returncode != 0:
                    return None
                data = np.fromfile(tmp.name, dtype=np.float32)
            if len(data) < num_samples * 2:
                return None
            iq = data[0::2] + 1j * data[1::2]
            return (
                iq[1024 : 1024 + num_samples]
                if len(iq) > 1024 + num_samples
                else iq[:num_samples]
            )
        except Exception as e:
            logger.error("USRP CLI capture failed: %s", e)
            return None


# ---------------------------------------------------------------------------
# Signal analysis helpers
# ---------------------------------------------------------------------------


def estimate_snr(iq):
    fft = np.fft.fftshift(np.abs(np.fft.fft(iq)))
    n = len(fft)
    signal_power = np.mean(np.sort(fft)[-n // 10 :] ** 2)
    noise_power = np.mean(np.sort(fft)[: n // 2] ** 2)
    return float(10 * np.log10(signal_power / (noise_power + 1e-10)))


def estimate_power(iq):
    return float(10 * np.log10(np.mean(np.abs(iq) ** 2) + 1e-10))


# ---------------------------------------------------------------------------
# Status HTTP server
# ---------------------------------------------------------------------------


class StatusHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        uptime = None
        if state["start_time"]:
            uptime = (datetime.now() - state["start_time"]).total_seconds()
        body = {
            "service": "rf-scan",
            "status": "running" if state["running"] else "stopped",
            "uptime_seconds": uptime,
            "scan_count": state["scan_count"],
            "detections": state["detections"],
            "cls_per_sec": state["cls_per_sec"],
            "capture_mode": state["capture_mode"],
            "rtl_connected": state["rtl_connected"],
            "hackrf_connected": state["hackrf_connected"],
            "bridge_connected": state["bridge_connected"],
            "bridge_uploaded": state["bridge_uploaded"],
            "last_scan": state["last_scan"],
            "last_error": state["last_error"],
            "last_successful_capture": state["last_successful_capture"],
            "frequencies": sorted(
                set(FREQUENCIES.keys())
                | (
                    set(HACKRF_EXTRA_FREQUENCIES.keys())
                    if state["capture_mode"] in ("hackrf", "dual")
                    else set()
                )
            ),
            "anomaly_enabled": state["anomaly_enabled"],
            "anomaly_count": state["anomaly_count"],
            "anomaly_baseline": state["anomaly_baseline"],
        }
        self.wfile.write(json.dumps(body, indent=2).encode())

    def do_POST(self):
        """Accept IQ capture commands from node_agent."""
        if self.path != "/capture":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            if not 0 <= length <= 65536:
                raise ValueError("request body too large")
            body = json.loads(self.rfile.read(length)) if length else {}
            # Reject nonsense up front so the caller gets a 400; the
            # command is validated again (and clamped) when executed.
            parse_iq_capture_command(body)
            capture_queue.put_nowait(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"queued": True}).encode())
            logger.info(
                "IQ capture request queued: %.3f MHz", body.get("freq_hz", 0) / 1e6
            )
        except queue.Full:
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "capture queue full"}).encode())
        except Exception as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())


def start_status_server():
    bind_addr = os.environ.get("STATUS_BIND", "127.0.0.1")
    srv = HTTPServer((bind_addr, STATUS_PORT), StatusHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    logger.info("Status endpoint on %s:%d", bind_addr, STATUS_PORT)


# ---------------------------------------------------------------------------
# Edge protocol decoding (best-effort, modules may not be installed)
# ---------------------------------------------------------------------------

_EDGE_DECODABLE = {"meshtastic", "lora-css", "lorawan", "adsb"}

# ---------------------------------------------------------------------------
# ADS-B decode via dump1090 --ifile (time-shares SDR at 1090 MHz dwell)
# ---------------------------------------------------------------------------

_DUMP1090_PATH = None  # cached on first use


def _find_dump1090():
    """Find dump1090 binary on the system."""
    global _DUMP1090_PATH
    if _DUMP1090_PATH is not None:
        return _DUMP1090_PATH
    import shutil

    for name in ("readsb", "dump1090", "dump1090-mutability", "dump1090-fa"):
        p = shutil.which(name)
        if p:
            _DUMP1090_PATH = p
            return p
    _DUMP1090_PATH = ""
    return ""


def _iq_to_uc8(iq):
    """Convert complex64 IQ to unsigned 8-bit interleaved (dump1090 format)."""
    interleaved = np.empty(len(iq) * 2, dtype=np.uint8)
    interleaved[0::2] = np.clip((iq.real * 127.5 + 127.5), 0, 255).astype(np.uint8)
    interleaved[1::2] = np.clip((iq.imag * 127.5 + 127.5), 0, 255).astype(np.uint8)
    return interleaved.tobytes()


def try_adsb_decode(iq, freq_hz):
    """Decode ADS-B from IQ via dump1090 --ifile.

    Writes IQ to a temp file in UC8 format, runs dump1090 in one-shot mode,
    parses the SBS output. Returns list of aircraft dicts for the bridge.
    """
    if abs(freq_hz - 1.09e9) > 5e6:
        return []

    dump1090 = _find_dump1090()
    if not dump1090:
        return []

    uc8_data = _iq_to_uc8(iq)
    aircraft = {}

    try:
        with tempfile.NamedTemporaryFile(suffix=".uc8", delete=False) as f:
            f.write(uc8_data)
            tmp_path = f.name

        # Run readsb/dump1090 with JSON output to temp dir
        json_dir = tempfile.mkdtemp(prefix="adsb_")
        if "readsb" in dump1090:
            cmd = [
                dump1090,
                "--device-type",
                "ifile",
                "--ifile",
                tmp_path,
                "--iformat",
                "UC8",
                "--quiet",
                "--no-interactive",
                "--write-json",
                json_dir,
                "--write-json-every",
                "0.1",
            ]
        else:
            cmd = [
                dump1090,
                "--ifile",
                tmp_path,
                "--no-interactive",
                "--quiet",
                "--write-json",
                json_dir,
            ]
        subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        # Parse aircraft.json written by readsb/dump1090
        aircraft_json = os.path.join(json_dir, "aircraft.json")
        if os.path.exists(aircraft_json):
            try:
                with open(aircraft_json) as f:
                    data = json.loads(f.read())
                for ac in data.get("aircraft", []):
                    icao = ac.get("hex", "").strip().upper()
                    if not icao or len(icao) != 6:
                        continue
                    aircraft[icao] = {
                        "icao_address": icao,
                        "callsign": ac.get("flight", "").strip() or None,
                        "altitude_ft": ac.get("alt_baro") or ac.get("altitude"),
                        "ground_speed_kt": ac.get("gs"),
                        "heading_deg": ac.get("track"),
                        "latitude": ac.get("lat"),
                        "longitude": ac.get("lon"),
                        "vertical_rate_fpm": ac.get("baro_rate") or ac.get("vert_rate"),
                        "squawk": ac.get("squawk"),
                    }
            except (json.JSONDecodeError, IOError):
                pass
    except subprocess.TimeoutExpired:
        logger.debug("dump1090 timed out on IQ decode")
    except Exception as exc:
        logger.debug("dump1090 decode failed: %s", exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            import shutil as _shutil

            _shutil.rmtree(json_dir, ignore_errors=True)
        except Exception:
            pass

    if aircraft:
        logger.info("ADS-B: %d aircraft decoded via dump1090", len(aircraft))

    return list(aircraft.values())


def _safe_int(s):
    try:
        return int(float(s.strip()))
    except (ValueError, TypeError):
        return None


def _safe_float(s):
    try:
        return float(s.strip())
    except (ValueError, TypeError):
        return None


def try_edge_decode(iq, signal_class, freq_hz):
    """Attempt on-edge protocol decoding of IQ samples.

    Returns a list of decoded message dicts, or an empty list if decoding
    is unavailable or fails.  All decode imports are guarded by try/except
    so this never breaks the scan loop.
    """
    sc = signal_class.lower().strip()

    # ADS-B: trigger on frequency (1090 MHz) regardless of classifier output
    is_adsb_freq = abs(freq_hz - 1.09e9) < 5e6
    if is_adsb_freq:
        sc = "adsb"

    if sc not in _EDGE_DECODABLE:
        return []

    # ADS-B: decode via readsb/dump1090 --ifile, not the LoRa demodulator
    if sc == "adsb":
        aircraft = try_adsb_decode(iq, freq_hz)
        if not aircraft:
            return []
        now = datetime.now(timezone.utc).isoformat()
        msgs = []
        for a in aircraft:
            msgs.append(
                {
                    "protocol": "adsb",
                    "source_id": a.get("icao_address", ""),
                    "dest_id": "",
                    "message_type": "aircraft_track",
                    "payload_hex": "",
                    "encrypted": 0,
                    "decrypted_payload": json.dumps(a),
                    "gps_lat": a.get("latitude"),
                    "gps_lon": a.get("longitude"),
                    "confidence": 0.95,
                    "freq_hz": freq_hz,
                    "timestamp": now,
                    "text": a.get("callsign"),
                    "metadata": a,
                }
            )
        return msgs

    try:
        from sigrift.lib.dsp.lora_demodulator import demodulate_and_decode
    except ImportError:
        return []

    # Default LoRa parameters — SF7, 125 kHz BW, 2 Msps
    sf = 7
    bw = 125_000.0
    fs = 2_000_000.0

    try:
        result = demodulate_and_decode(iq, sf, bw, fs)
    except Exception:
        return []

    if result is None:
        return []

    # Convert MeshNetworkIntelligence to a decoded message dict
    now = datetime.now(timezone.utc).isoformat()
    encryption_status = getattr(result, "encryption_status", "unknown")

    # Determine message_type from port_num
    port_num = getattr(result, "port_num", None)
    _port_map = {1: "text", 3: "position", 4: "nodeinfo", 67: "telemetry"}
    message_type = _port_map.get(port_num, "unknown") if port_num else "unknown"

    encrypted = 1 if encryption_status in ("custom_encrypted", "default_key") else 0
    confidence = 0.9 if encryption_status == "default_key" else 0.5

    # GPS extraction from decoded_position
    gps_lat = None
    gps_lon = None
    pos = getattr(result, "decoded_position", None)
    if isinstance(pos, dict):
        gps_lat = pos.get("lat") or (
            pos.get("lat_i", 0) / 1e7 if "lat_i" in pos else None
        )
        gps_lon = pos.get("lon") or (
            pos.get("lon_i", 0) / 1e7 if "lon_i" in pos else None
        )

    raw_hex = getattr(result, "raw_hex", "") or ""

    msg = {
        "protocol": getattr(result, "protocol", sc),
        "source_id": getattr(result, "source_node_id", "") or "",
        "dest_id": getattr(result, "dest_node_id", "") or "",
        "message_type": message_type,
        "payload_hex": raw_hex,
        "encrypted": encrypted,
        "decrypted_payload": getattr(result, "decoded_text", None),
        "gps_lat": gps_lat,
        "gps_lon": gps_lon,
        "confidence": confidence,
        "freq_hz": freq_hz,
        "timestamp": now,
    }
    return [msg]


# ---------------------------------------------------------------------------
# Scan a single frequency with a given SDR backend
# ---------------------------------------------------------------------------


_REPORT_TAKES_RATE: dict[type, bool] = {}


def _reporter_takes_sample_rate(reporter) -> bool:
    """Whether reporter.report() accepts sample_rate (older copies do not)."""
    cls = type(reporter)
    if cls not in _REPORT_TAKES_RATE:
        try:
            params = inspect.signature(reporter.report).parameters
        except (TypeError, ValueError):
            params = {}
        _REPORT_TAKES_RATE[cls] = "sample_rate" in params
    return _REPORT_TAKES_RATE[cls]


def _failure_reason(sdr) -> str:
    """Status reason for a failed capture: the supervisor's, else capture_failed."""
    reason = getattr(sdr, "unavailable_reason", None)
    return reason if reason in _SUPERVISOR_REASONS else "capture_failed"


def _pause(seconds: float) -> None:
    """Sleep up to *seconds*, returning early once shutdown is requested."""
    deadline = time.monotonic() + seconds
    while state["running"] and (left := deadline - time.monotonic()) > 0:
        time.sleep(min(0.25, left))


def scan_frequency(sdr, freq_hz, engine, reporter, activity=None):
    """Capture, classify, and report one frequency. Returns True if detection accepted."""
    if not sdr.connected:
        # A backend that paces reconnection is tried once per interval, not
        # once per frequency of the sweep.
        retry_in = getattr(sdr, "retry_in", None)
        if retry_in is None or retry_in() <= 0:
            sdr.connect()
        if not sdr.connected:
            state["last_error"] = "connection_failed"
            if activity is not None:
                activity.failed(_failure_reason(sdr))
            return False

    sdr.set_frequency(freq_hz)
    # The model's fixed input length wins over MLRF_INPUT_SAMPLES: a frame
    # of any other length is rejected by the model on every scan.
    iq = sdr.capture(getattr(engine, "input_samples", INPUT_SAMPLES))
    if iq is None:
        state["last_error"] = "capture_failed"
        if activity is not None:
            activity.failed(_failure_reason(sdr))
        return False

    # A TCP handshake is not evidence of samples. Keep this timestamp across
    # failed captures/reconnects so the status endpoint can show actual progress.
    state["last_successful_capture"] = datetime.now(timezone.utc).isoformat()
    snr_db = estimate_snr(iq)
    power_dbm = estimate_power(iq)

    iq_2ch = np.stack([iq.real, iq.imag], axis=0)
    result = engine.classify(iq_2ch)
    if activity is not None:
        activity.succeeded()
    state["cls_per_sec"] = engine.avg_cls_per_sec

    # Attempt on-edge protocol decoding for supported signal classes
    decoded_msgs = None
    signal_class = result.get("class", "")
    try:
        decoded_msgs = try_edge_decode(iq, signal_class, float(freq_hz)) or None
    except Exception:
        pass  # never break the scan loop

    # The rate the IQ was sampled at, for an anomaly/low-confidence capture.
    extra = {}
    rate = getattr(sdr, "sample_rate", None)
    if rate and _reporter_takes_sample_rate(reporter):
        extra["sample_rate"] = float(rate)
    accepted = reporter.report(
        classification=result,
        freq_hz=float(freq_hz),
        snr_db=snr_db,
        power_dbm=power_dbm,
        iq_data=iq,
        decoded_messages=decoded_msgs,
        **extra,
    )
    if accepted:
        state["detections"] += 1

    state["bridge_uploaded"] = getattr(reporter, "_total_uploaded", 0)
    state["anomaly_count"] = getattr(reporter, "_total_anomalies", 0)
    # Update baseline status from the scorer's last result
    bm = getattr(reporter, "_baseline_manager", None)
    if bm is not None:
        baselines = getattr(bm, "_baselines", {})
        if baselines:
            all_stable = all(not fb.is_learning() for fb in baselines.values())
            state["anomaly_baseline"] = "stable" if all_stable else "learning"
    state["last_error"] = None
    return accepted


# ---------------------------------------------------------------------------
# On-demand IQ capture (remote iq_capture command)
# ---------------------------------------------------------------------------


def execute_iq_capture(cmd, sdr_list, bridge_url, bridge_key, node_id) -> bool:
    """Capture IQ as an iq_capture command asks and upload it to the bridge.

    The device is set to the command's sample rate and gain where it
    supports them (and back to the scan settings afterwards). The capture
    length is computed for the rate the device actually runs at, and that
    rate -- not the requested one -- is what X-Sample-Rate reports.
    Returns True once the upload has been accepted.
    """
    try:
        params = parse_iq_capture_command(cmd)
    except ValueError as e:
        logger.error("Rejected iq_capture command: %s", e)
        return False
    freq_hz = params["freq_hz"]
    command_id = params["command_id"]

    # Pick the best SDR for this frequency
    freq_mhz = freq_hz / 1e6
    sdr = sdr_list[0]  # default to first
    if len(sdr_list) > 1 and freq_mhz > 1766:
        sdr = sdr_list[1]  # use HackRF for high freqs

    if not sdr.connected:
        sdr.connect()
        if not sdr.connected:
            logger.error("IQ capture failed: SDR not connected")
            return False

    if not sdr.set_frequency(int(freq_hz)):
        logger.error("IQ capture failed: %s could not tune", sdr.name)
        return False
    sample_rate = sdr.configure_capture(params["sample_rate"], params["gain_db"])
    if sample_rate is None:
        logger.error("IQ capture failed: %s rejected the capture settings", sdr.name)
        sdr.restore_scan_settings()
        return False
    n_samples = iq_capture_sample_count(sample_rate, params["duration_ms"])

    logger.info(
        "IQ capture %s: %.3f MHz, %d samples at %.0f Hz (requested %.0f Hz), "
        "gain %s, %s",
        command_id,
        freq_mhz,
        n_samples,
        sample_rate,
        params["sample_rate"],
        "unchanged" if params["gain_db"] is None else f"{params['gain_db']:g} dB",
        sdr.name,
    )

    try:
        iq = sdr.capture(n_samples)
    finally:
        sdr.restore_scan_settings()
    if iq is None:
        logger.error("IQ capture failed: no data from %s", sdr.name)
        return False

    # Compress IQ data (interleaved float32)
    interleaved = np.empty(len(iq) * 2, dtype=np.float32)
    interleaved[0::2] = iq.real
    interleaved[1::2] = iq.imag
    compressed = gzip.compress(interleaved.tobytes())

    # Generate a detection_id for this manual capture
    det_id = f"iq_{command_id}_{node_id}_{int(time.time())}"

    # Upload to bridge — includes node/freq headers so bridge
    # can auto-create a stub detection if it doesn't exist yet
    url = f"{bridge_url}/api/detections/{det_id}/iq"
    try:
        ctx = _build_ssl_context()
    except TLSConfigError as e:
        logger.error("IQ upload skipped for %s: %s", det_id, e)
        return False
    headers = {
        **_auth_headers(bridge_key),
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "gzip",
        "X-Sample-Rate": str(float(sample_rate)),
        "X-IQ-Samples": str(len(iq)),
        "X-Node-Id": node_id,
        "X-Freq-Hz": str(freq_hz),
    }
    req = urllib.request.Request(url, data=compressed, headers=headers, method="PUT")
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            result = json.loads(resp.read())
            logger.info(
                "IQ capture uploaded: %s (%d bytes compressed) -> %s",
                det_id,
                len(compressed),
                result,
            )
            return True
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:200]
        logger.error("IQ upload HTTP %d for %s: %s", e.code, det_id, detail)
    except Exception as e:
        logger.error("IQ upload failed for %s: %s", det_id, e)
    return False


# ---------------------------------------------------------------------------
# Main scan loop
# ---------------------------------------------------------------------------


def main():
    bridge_url = os.environ.get("MLRF_BRIDGE_URL", "")
    bridge_key = os.environ.get("MLRF_BRIDGE_KEY", "")
    node_id = os.environ.get("MLRF_NODE_ID", "")
    capture_mode = os.environ.get("MLRF_CAPTURE_MODE", "rtltcp")
    rtl_host = os.environ.get("MLRF_RTL_HOST", "127.0.0.1")
    rtl_port = int(os.environ.get("MLRF_RTL_PORT", "1234"))

    if not bridge_url or not bridge_key or not node_id:
        logger.error("MLRF_BRIDGE_URL, MLRF_BRIDGE_KEY, MLRF_NODE_ID required")
        return 1

    # Find ONNX model
    model_path = os.environ.get("MLRF_MODEL_PATH", "")
    if not model_path:
        candidates = sorted(glob(str(AGENT_DIR / "gen3_edge_*.onnx")))
        if candidates:
            model_path = candidates[-1]
        else:
            logger.error("No ONNX model found in %s", AGENT_DIR)
            return 1

    state["capture_mode"] = capture_mode

    logger.info("=== RF Scan — %s ===", node_id)
    logger.info("Model: %s", model_path)
    logger.info("Bridge: %s", bridge_url)
    logger.info("Capture: %s (dwell=%.3fs)", capture_mode, DWELL_TIME)
    if not _check_tls_config():
        return 1

    # Start status server
    start_status_server()

    # Initialize inference engine. Try the packaged module first
    # (preferred — what the compose `scan` service installs at
    # /app/src/sigrift/edge/edge_inference.py). Fall back to the bare
    # import for the legacy Pi-host layout where edge_inference.py
    # lives next to rf_scan.py in AGENT_DIR.
    try:
        from sigrift.edge.edge_inference import InferenceEngine  # type: ignore
    except ImportError:
        from edge_inference import InferenceEngine  # type: ignore

    # Older standalone edge_inference.py copies have no ModelContractError;
    # an empty tuple then catches nothing.
    model_error = getattr(
        sys.modules.get(InferenceEngine.__module__), "ModelContractError", ()
    )
    try:
        engine = InferenceEngine(model_path, backend="onnx")
    except model_error as e:
        # Class names that do not match the model would mislabel every
        # detection: refuse to start, like a missing model.
        logger.error("Cannot use the model: %s", e)
        return 1
    logger.info("ONNX engine ready (%d classes)", len(engine.class_names))

    # Initialize capture backends
    sdrs = []
    if capture_mode == "dual":
        rtl = RTLTCPClient(rtl_host, rtl_port)
        hackrf = HackRFCapture()
        sdrs = [rtl, hackrf]
        logger.info("Dual SDR mode: RTL-SDR + HackRF")
    elif capture_mode == "hackrf":
        sdrs = [HackRFCapture()]
    elif capture_mode == "b210":
        sdrs = [UHDClient()]
    else:
        sdrs = [RTLTCPClient(rtl_host, rtl_port)]

    # Build frequency plan: assign each freq to the best SDR
    # RTL-SDR covers 24-1766 MHz, HackRF covers 1-6000 MHz
    # In dual mode, use RTL-SDR for shared freqs (better sensitivity)
    # and HackRF for freqs above 1766 MHz or HackRF-only extras
    freq_plan = []  # list of (freq_mhz, desc, sdr_backend)
    if capture_mode == "dual":
        rtl_sdr = sdrs[0]
        hackrf_sdr = sdrs[1]
        for freq_mhz, desc in sorted(FREQUENCIES.items()):
            freq_plan.append((freq_mhz, desc, rtl_sdr))
        for freq_mhz, desc in sorted(HACKRF_EXTRA_FREQUENCIES.items()):
            freq_plan.append((freq_mhz, desc, hackrf_sdr))
    else:
        sdr = sdrs[0]
        all_freqs = dict(FREQUENCIES)
        if capture_mode == "hackrf":
            all_freqs.update(HACKRF_EXTRA_FREQUENCIES)
        for freq_mhz, desc in sorted(all_freqs.items()):
            freq_plan.append((freq_mhz, desc, sdr))

    # Initialize detection reporter. Try the packaged module first
    # (preferred — what the compose `scan` service installs at
    # /app/src/sigrift/edge/detection_reporter.py). Fall back to the
    # bare import for the legacy Pi-host layout where the file lives
    # next to rf_scan.py in AGENT_DIR.
    try:
        from sigrift.edge.detection_reporter import DetectionReporter  # type: ignore
    except ImportError:
        from detection_reporter import DetectionReporter  # type: ignore
    # Older standalone detection_reporter.py copies have no TLSConfigError.
    reporter_tls_error = getattr(
        sys.modules[DetectionReporter.__module__], "TLSConfigError", TLSConfigError
    )

    min_conf = 0.15 if capture_mode in ("hackrf", "dual") else 0.5
    anomaly_on = os.environ.get("MLRF_ANOMALY", "").lower() in ("1", "true", "yes")
    iq_capture_on = os.environ.get("MLRF_IQ_CAPTURE", "").lower() in (
        "1",
        "true",
        "yes",
    )
    iq_capture_threshold = float(os.environ.get("MLRF_IQ_CAPTURE_THRESHOLD", "0.5"))
    iq_low_conf = float(os.environ.get("MLRF_IQ_LOW_CONFIDENCE", "0.4"))
    summarize_on = os.environ.get("MLRF_SUMMARIZE", "").lower() in ("1", "true", "yes")
    summary_threshold = float(os.environ.get("MLRF_SUMMARY_ANOMALY_THRESHOLD", "0.8"))
    # Persist learned anomaly baselines across restarts. DetectionReporter has
    # had the data_dir/baselines.json plumbing (load + 300s autosave) all along;
    # the default scan path just never passed it, so edge nodes relearned from
    # zero on every restart. Summary mode additionally requires this persistent
    # directory for its journal; raw mode still does not create a summary journal.
    data_dir = os.environ.get("MLRF_DATA_DIR", "").strip() or None
    baseline_save_interval = float(os.environ.get("MLRF_BASELINE_SAVE_INTERVAL", "300"))
    reporter_journal_error = getattr(
        sys.modules[DetectionReporter.__module__],
        "SummaryJournalError",
        reporter_tls_error,
    )

    try:
        reporter = DetectionReporter(
            server_url=bridge_url,
            api_key=bridge_key,
            node_id=node_id,
            min_confidence=min_conf,
            min_snr_db=3.0,
            batch_size=50,
            flush_interval_seconds=5.0,
            anomaly_scoring=anomaly_on,
            iq_capture=iq_capture_on,
            iq_capture_threshold=iq_capture_threshold,
            iq_capture_low_confidence=iq_low_conf,
            summarize=summarize_on,
            summary_anomaly_threshold=summary_threshold,
            data_dir=data_dir,
            baseline_save_interval=baseline_save_interval,
        )
    except (reporter_tls_error, reporter_journal_error) as e:
        # The reporter's CA bundle (it also honours the legacy
        # BRIDGE_CA_BUNDLE) cannot be loaded: one clear line and a non-zero
        # exit instead of a traceback.
        logger.error("Cannot start the detection reporter: %s", e)
        for sdr in sdrs:
            sdr.disconnect()
        return 1
    from contextlib import ExitStack

    final_status = "error"
    with ExitStack() as cleanup:
        for sdr in reversed(sdrs):
            cleanup.callback(sdr.disconnect)
        cleanup.callback(getattr(reporter, "close", reporter.stop))
        reporter.start()
        state["bridge_connected"] = True
        state["anomaly_enabled"] = anomaly_on
        if not anomaly_on:
            state["anomaly_baseline"] = "unknown"
        elif data_dir and (Path(data_dir) / "baselines.json").exists():
            # Restored a persisted baseline rather than starting cold.
            state["anomaly_baseline"] = "loaded"
        else:
            state["anomaly_baseline"] = "learning"
        logger.info(
            "Detection reporter started (%d frequencies across %d SDR(s), anomaly=%s)",
            len(freq_plan),
            len(sdrs),
            anomaly_on,
        )

        # Graceful shutdown
        def _shutdown(sig, frame):
            logger.info("Shutting down (signal %d)...", sig)
            state["running"] = False

        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)

        state["start_time"] = datetime.now()

        activity = CaptureActivity()
        scanner_status = ScannerStatusReporter(
            bridge_url,
            node_id,
            "sdr",
            _build_ssl_context,
            lambda: _auth_headers(bridge_key),
            lambda: activity.status() if state["running"] else "stopped",
        )
        scanner_status.start()
        cleanup.callback(lambda: scanner_status.stop(final_status))
        cleanup.callback(activity.failed)
        # Connect all SDRs. A receiver that is away is waited for: the scan
        # never exits because of it, and status says why it is not capturing.
        for sdr in sdrs:
            warned = False
            while state["running"]:
                if sdr.connect():
                    break
                activity.failed(_failure_reason(sdr))
                if not warned and not hasattr(sdr, "retry_in"):
                    # RTLTCPClient logs its own outage line.
                    logger.warning("%s not ready; retrying", sdr.name)
                warned = True
                _pause(getattr(sdr, "retry_interval", 10))

        # Scan loop
        while state["running"]:
            state["scan_count"] += 1
            state["last_scan"] = datetime.now(timezone.utc).isoformat()

            # Process any pending IQ capture requests between sweeps
            while not capture_queue.empty():
                try:
                    cmd = capture_queue.get_nowait()
                    execute_iq_capture(cmd, sdrs, bridge_url, bridge_key, node_id)
                except queue.Empty:
                    break
                except Exception as e:
                    logger.error("IQ capture execution error: %s", e)

            for freq_mhz, desc, sdr in freq_plan:
                if not state["running"]:
                    break
                freq_hz = int(freq_mhz * 1e6)

                try:
                    scan_frequency(sdr, freq_hz, engine, reporter, activity)
                except model_error as e:
                    # A symbolic class dimension is only checked on the
                    # first inference; retrying cannot fix it. Stop with
                    # final status "error".
                    logger.error("Cannot use the model: %s", e)
                    return 1
                except Exception as e:
                    activity.failed()
                    # Public status uses fixed categories, never raw errors
                    # that may contain credential paths or endpoint details.
                    state["last_error"] = "scan_failed"
                    logger.error("%7.2f MHz [%s] | %s", freq_mhz, sdr.name, e)

            capturing = any(sdr.connected for sdr in sdrs)
            if not capturing:
                # Every receiver is away: wait for the next reconnection
                # attempt instead of spinning through the frequency plan.
                _pause(
                    min(
                        (sdr.retry_in() for sdr in sdrs if hasattr(sdr, "retry_in")),
                        default=RTL_RETRY_SECONDS,
                    )
                )

            if state["scan_count"] % 10 == 0:
                if capturing:  # empty sweeps while the receiver is away
                    logger.info(
                        "Scan %d: %d detections, %.1f cls/sec, %d uploaded",
                        state["scan_count"],
                        state["detections"],
                        state["cls_per_sec"],
                        state["bridge_uploaded"],
                    )
                # Poll the on-disk config file for a runtime summarize toggle
                # pushed by the bridge via update_config. Reads on the same
                # 10-scan cadence as the stats log to keep noise low.
                from sigrift.edge.scanner_config import reload_summarize

                wanted = reload_summarize(reporter.summarize)
                try:
                    reporter.summarize = wanted
                except (reporter_journal_error, ValueError) as exc:
                    # SummaryJournalError is a ValueError. Summary mode needs a usable persistent journal (for
                    # example MLRF_DATA_DIR). A runtime toggle that cannot
                    # open it must not stop scanning: stay in the current
                    # mode and say why, once per attempt.
                    logger.error(
                        "Cannot switch to summary mode; staying in %s mode: %s",
                        "summary" if reporter.summarize else "raw",
                        exc,
                    )

        final_status = "stopped"
    logger.info(
        "Stopped after %d scans, %d detections",
        state["scan_count"],
        state["detections"],
    )
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
