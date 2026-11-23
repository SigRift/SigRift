"""Syslog forwarding for The Bridge alert notifications.

Forwards alert notifications to remote syslog servers using RFC 5424
format over UDP, TCP, or TLS transport protocols.  Supports granular
alert filtering by severity, signal class, node ID, frequency range,
and alert rule name.

Configuration is persisted via PersistenceManager alongside webhooks.

Usage:
    forwarder = SyslogForwarder()
    forwarder.load(persistence.get_syslog_targets())
    forwarder.submit(alert_dict)  # from the event loop: never waits
    forwarder.forward(alert_dict)  # blocking, from a worker thread

Request handlers use :meth:`SyslogForwarder.submit`: a TCP/TLS target
that does not answer blocks a send for up to ``_CONNECT_TIMEOUT``
seconds, which must not delay an ingest request (contract K8b).  The
background sends run in the forwarder's own threads, never in the event
loop's default executor, which every ``asyncio.to_thread`` call of the
bridge shares.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import secrets
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 5424 severity mapping
# ---------------------------------------------------------------------------

# Bridge severities -> syslog severity codes (RFC 5424 Section 6.2.1)
_SEVERITY_MAP = {
    "critical": 2,  # Critical
    "warning": 4,  # Warning
    "info": 6,  # Informational
}

# Syslog facility codes (RFC 5424 Section 6.2.1)
FACILITY_MAP = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "authpriv": 10,
    "ftp": 11,
    "ntp": 12,
    "security": 13,
    "console": 14,
    "solaris-cron": 15,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

# Default facility
DEFAULT_FACILITY = "local0"

# Connection constants
_CONNECT_TIMEOUT = 10
_SEND_TIMEOUT = 5
_MAX_RECONNECT_DELAY = 300  # 5 minutes
_INITIAL_RECONNECT_DELAY = 1
#: Background forwards (:meth:`SyslogForwarder.submit`): worker threads
#: they use at most (the forwarder's own pool, not the default executor),
#: and forwards in flight at most (the excess is dropped and counted).
_MAX_CONCURRENT_FORWARDS = 2
_MAX_PENDING_FORWARDS = 256
_MAX_MSG_SIZE = 65000  # UDP max practical size

# App name for syslog messages
_APP_NAME = "SigRift"
_ENTERPRISE_ID = "sigrift"


# ---------------------------------------------------------------------------
# RFC 5424 message formatting
# ---------------------------------------------------------------------------


def _compute_priority(facility_name: str, severity_name: str) -> int:
    """Compute RFC 5424 PRI value from facility and severity names."""
    facility_code = FACILITY_MAP.get(facility_name, FACILITY_MAP[DEFAULT_FACILITY])
    severity_code = _SEVERITY_MAP.get(severity_name, 6)
    return facility_code * 8 + severity_code


def format_rfc5424(
    alert: dict[str, Any],
    facility: str = DEFAULT_FACILITY,
    hostname: str | None = None,
) -> bytes:
    """Format an alert as an RFC 5424 syslog message.

    Returns the message as UTF-8 bytes suitable for transmission.

    RFC 5424 format:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        [SD-ELEMENT] MSG

    Structured data includes SigRift-specific fields as an SD-ELEMENT
    with enterprise ID ``sigrift``.
    """
    severity = alert.get("severity", "info")
    pri = _compute_priority(facility, severity)

    # HEADER
    version = 1
    timestamp = alert.get("triggered_at", datetime.now(timezone.utc).isoformat())
    # Ensure RFC 5424 timestamp format (ISO 8601 with T separator)
    if isinstance(timestamp, str) and " " in timestamp:
        timestamp = timestamp.replace(" ", "T")

    if hostname is None:
        try:
            hostname = socket.gethostname()
        except OSError:
            hostname = "-"

    app_name = _APP_NAME
    procid = "-"
    msgid = alert.get("alert_id", "-") or "-"

    # STRUCTURED-DATA
    sd_params = []
    sd_fields = {
        "signal_class": alert.get("signal_class", ""),
        "freq_hz": str(alert.get("freq_hz", "")),
        "node_id": alert.get("node_id", ""),
        "anomaly_score": str(alert.get("anomaly_score", "")),
        "severity": severity,
        "alert_id": alert.get("alert_id", ""),
        "rule_name": alert.get("name", ""),
    }

    for key, val in sd_fields.items():
        if val:
            # Escape SD-PARAM values per RFC 5424: \ " ] must be escaped
            escaped = (
                str(val).replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")
            )
            sd_params.append(f'{key}="{escaped}"')

    if sd_params:
        structured_data = f"[{_ENTERPRISE_ID}@0 {' '.join(sd_params)}]"
    else:
        structured_data = "-"

    # MSG
    msg_text = alert.get("message", "")
    if not msg_text:
        name = alert.get("name", "alert")
        msg_text = f"{name}: {severity} alert on {alert.get('node_id', 'unknown')}"

    # Assemble RFC 5424 message
    header = f"<{pri}>{version} {timestamp} {hostname} {app_name} {procid} {msgid}"
    message = f"{header} {structured_data} {msg_text}"

    return message.encode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# CEF (Common Event Format) formatting
# ---------------------------------------------------------------------------

# CEF event IDs by alert type
CEF_EVENT_RF_DETECTION = 100
CEF_EVENT_RF_ANOMALY = 200
CEF_EVENT_WIFI_ALERT = 300
CEF_EVENT_BT_ALERT = 400

# Priority label to CEF severity mapping
_PRIORITY_SEVERITY_MAP = {
    "Normal": 3,
    "Interesting": 5,
    "Anomalous": 7,
    "Critical": 10,
}


def _cef_escape(value: str) -> str:
    """Escape special characters for CEF extension values."""
    return str(value).replace("\\", "\\\\").replace("=", "\\=")


def _cef_header_escape(value: str) -> str:
    """Escape pipe and backslash in CEF header fields."""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


class CEFFormatter:
    """Formats alerts and detections as CEF (Common Event Format) messages.

    CEF header format:
        CEF:0|SigRift|SigRift|1.0|{event_id}|{event_name}|{severity}|

    Followed by key=value extension pairs.
    """

    DEVICE_VENDOR = "SigRift"
    DEVICE_PRODUCT = "SigRift"
    DEVICE_VERSION = "1.0"

    @staticmethod
    def _detect_event_type(alert: dict[str, Any]) -> tuple[int, str]:
        """Determine CEF event ID and name from alert data."""
        signal_class = str(alert.get("signal_class", "")).lower()
        name = str(alert.get("name", "")).lower()

        if "wifi" in signal_class or "wifi" in name:
            return CEF_EVENT_WIFI_ALERT, "WiFi Alert"
        if "bluetooth" in signal_class or "bt" in signal_class or "bluetooth" in name:
            return CEF_EVENT_BT_ALERT, "Bluetooth Alert"

        anomaly_score = alert.get("anomaly_score", 0.0)
        try:
            score = float(anomaly_score)
        except (TypeError, ValueError):
            score = 0.0

        if score > 0.0:
            return CEF_EVENT_RF_ANOMALY, "RF Anomaly"
        return CEF_EVENT_RF_DETECTION, "RF Detection"

    @staticmethod
    def _compute_severity(alert: dict[str, Any]) -> int:
        """Compute CEF severity (0-10) from alert data.

        Uses priority label mapping if available, otherwise derives from
        anomaly_score (score * 10, rounded, clamped to 0-10).
        """
        priority = alert.get("priority")
        if priority and priority in _PRIORITY_SEVERITY_MAP:
            return _PRIORITY_SEVERITY_MAP[priority]

        anomaly_score = alert.get("anomaly_score", 0.0)
        try:
            score = float(anomaly_score)
        except (TypeError, ValueError):
            score = 0.0

        return max(0, min(10, round(score * 10)))

    @classmethod
    def format(cls, alert: dict[str, Any]) -> str:
        """Format an alert dict as a CEF message string."""
        event_id, event_name = cls._detect_event_type(alert)
        severity = cls._compute_severity(alert)

        header = (
            f"CEF:0|{_cef_header_escape(cls.DEVICE_VENDOR)}"
            f"|{_cef_header_escape(cls.DEVICE_PRODUCT)}"
            f"|{_cef_header_escape(cls.DEVICE_VERSION)}"
            f"|{event_id}|{_cef_header_escape(event_name)}"
            f"|{severity}|"
        )

        extensions = []

        node_id = alert.get("node_id", "")
        if node_id:
            extensions.append(f"src={_cef_escape(str(node_id))}")

        signal_class = alert.get("signal_class", "")
        if signal_class:
            extensions.append(
                f"cs1={_cef_escape(str(signal_class))} cs1Label=SignalClass"
            )

        freq_hz = alert.get("freq_hz")
        if freq_hz is not None:
            extensions.append(f"cs2={_cef_escape(str(freq_hz))} cs2Label=FrequencyHz")

        power_dbm = alert.get("power_dbm")
        if power_dbm is not None:
            extensions.append(f"cn1={_cef_escape(str(power_dbm))} cn1Label=PowerDBm")

        snr_db = alert.get("snr_db")
        if snr_db is not None:
            extensions.append(f"cn2={_cef_escape(str(snr_db))} cn2Label=SNRdB")

        anomaly_score = alert.get("anomaly_score")
        if anomaly_score is not None:
            extensions.append(
                f"cfp1={_cef_escape(str(anomaly_score))} cfp1Label=AnomalyScore"
            )

        reasons = alert.get("reasons")
        if reasons:
            if isinstance(reasons, list):
                msg = " ".join(str(r) for r in reasons)
            else:
                msg = str(reasons)
            extensions.append(f"msg={_cef_escape(msg)}")
        elif alert.get("message"):
            extensions.append(f"msg={_cef_escape(str(alert['message']))}")

        ts = alert.get("triggered_at") or alert.get("timestamp")
        if ts is not None:
            try:
                if isinstance(ts, str):
                    dt = datetime.fromisoformat(ts)
                elif isinstance(ts, (int, float)):
                    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                else:
                    dt = ts
                epoch_ms = int(dt.timestamp() * 1000)
                extensions.append(f"rt={epoch_ms}")
            except (ValueError, TypeError, OSError):
                pass

        priority = alert.get("priority") or alert.get("severity", "")
        if priority:
            extensions.append(f"cat={_cef_escape(str(priority))}")

        return header + " ".join(extensions)


# ---------------------------------------------------------------------------
# Connection wrapper for TCP/TLS with keepalive
# ---------------------------------------------------------------------------


class _SyslogConnection:
    """Manages a persistent TCP or TLS connection to a syslog server.

    Handles automatic reconnection with exponential backoff.
    Thread-safe for concurrent use.
    """

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        tls_ca_bundle: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._protocol = protocol.lower()
        self._tls_ca_bundle = tls_ca_bundle
        self._tls_client_cert = tls_client_cert
        self._tls_client_key = tls_client_key

        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._reconnect_delay = _INITIAL_RECONNECT_DELAY
        self._last_connect_attempt = 0.0
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> bool:
        """Establish or re-establish connection. Returns True on success."""
        with self._lock:
            return self._connect_locked()

    def _connect_locked(self) -> bool:
        """Connect while holding lock."""
        # Rate-limit reconnection attempts
        now = time.monotonic()
        if now - self._last_connect_attempt < self._reconnect_delay:
            return False
        self._last_connect_attempt = now

        self._close_locked()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(_CONNECT_TIMEOUT)
            sock.connect((self._host, self._port))
            sock.settimeout(_SEND_TIMEOUT)

            # Enable TCP keepalive
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            if self._protocol == "tls":
                ctx = ssl.create_default_context()
                if self._tls_ca_bundle:
                    ctx.load_verify_locations(self._tls_ca_bundle)
                if self._tls_client_cert:
                    ctx.load_cert_chain(
                        certfile=self._tls_client_cert,
                        keyfile=self._tls_client_key,
                    )

                sock = ctx.wrap_socket(sock, server_hostname=self._host)

            self._sock = sock
            self._connected = True
            self._reconnect_delay = _INITIAL_RECONNECT_DELAY
            logger.info(
                "Syslog %s connection established to %s:%d",
                self._protocol.upper(),
                self._host,
                self._port,
            )
            return True

        except Exception as exc:
            logger.warning(
                "Syslog connection to %s:%d failed: %s",
                self._host,
                self._port,
                exc,
            )
            self._reconnect_delay = min(
                self._reconnect_delay * 2,
                _MAX_RECONNECT_DELAY,
            )
            self._connected = False
            return False

    def send(self, data: bytes) -> bool:
        """Send data over the connection.

        For TCP/TLS, messages are framed with octet-counting per RFC 5425:
        ``<MSG_LEN> <MSG>``.

        Returns True on success, False on failure (triggers reconnect).
        """
        with self._lock:
            if not self._connected or self._sock is None:
                if not self._connect_locked():
                    return False

            try:
                # RFC 5425 octet-counting framing for TCP/TLS
                framed = f"{len(data)} {data.decode('utf-8', errors='replace')}"
                self._sock.sendall(framed.encode("utf-8"))
                return True
            except Exception as exc:
                logger.warning(
                    "Syslog send to %s:%d failed: %s",
                    self._host,
                    self._port,
                    exc,
                )
                self._connected = False
                self._close_locked()
                # Attempt immediate reconnect
                self._connect_locked()
                return False

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        """Close while holding lock."""
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
            self._connected = False


# ---------------------------------------------------------------------------
# Syslog target filter matching
# ---------------------------------------------------------------------------


def _matches_filter(
    alert: dict[str, Any],
    target: dict[str, Any],
) -> bool:
    """Check if an alert matches the filters configured on a syslog target.

    Filters are AND-combined: the alert must pass all configured filters.
    An empty or missing filter matches everything for that dimension.
    """
    # Severity filter
    severity_filter = target.get("severity_filter")
    if severity_filter:
        alert_severity = alert.get("severity", "info")
        if alert_severity not in severity_filter:
            return False

    # Signal class filter
    signal_class_filter = target.get("signal_class_filter")
    if signal_class_filter:
        alert_class = alert.get("signal_class", "")
        if alert_class and alert_class not in signal_class_filter:
            return False

    # Node ID filter
    node_filter = target.get("node_filter")
    if node_filter:
        alert_node = alert.get("node_id", "")
        if alert_node and alert_node not in node_filter:
            return False

    # Frequency range filter
    freq_min = target.get("freq_min_hz")
    freq_max = target.get("freq_max_hz")
    if freq_min is not None or freq_max is not None:
        alert_freq = alert.get("freq_hz")
        if alert_freq is not None:
            try:
                freq_val = float(alert_freq)
                if freq_min is not None and freq_val < float(freq_min):
                    return False
                if freq_max is not None and freq_val > float(freq_max):
                    return False
            except (ValueError, TypeError):
                pass

    # Alert rule name filter
    rule_name_filter = target.get("rule_name_filter")
    if rule_name_filter:
        alert_name = alert.get("name", "")
        if alert_name and alert_name not in rule_name_filter:
            return False

    return True


# ---------------------------------------------------------------------------
# SyslogForwarder
# ---------------------------------------------------------------------------


class SyslogForwarder:
    """Manages syslog forwarding targets and delivers alert notifications.

    Target configs are a list of dicts stored in persistence:
    [
        {
            "id": "abc123",
            "host": "syslog.example.com",
            "port": 514,
            "protocol": "udp",
            "facility": "local0",
            "format": "rfc5424",
            "enabled": true,
            "severity_filter": ["critical", "warning"],
            "signal_class_filter": [],
            "node_filter": [],
            "freq_min_hz": null,
            "freq_max_hz": null,
            "rule_name_filter": [],
            "tls_ca_bundle": null,
            "tls_client_cert": null,
            "tls_client_key": null,
            "created_at": "2026-02-15T...",
            "delivery_count": 0,
            "failure_count": 0,
            "last_delivery": null,
            "last_error": null,
        }
    ]

    Thread-safe: all methods may be called from any thread or coroutine.
    """

    def __init__(self) -> None:
        self._targets: list[dict[str, Any]] = []
        self._connections: dict[str, _SyslogConnection] = {}
        self._lock = threading.Lock()
        self._hostname: str | None = None
        try:
            self._hostname = socket.gethostname()
        except OSError:
            self._hostname = "sigrift"
        self._pending: set[asyncio.Task[Any]] = set()
        self._forward_slots: asyncio.Semaphore | None = None
        self._dropped = 0
        self._forward_executor: ThreadPoolExecutor | None = None
        self._executor_lock = threading.Lock()

    def _executor(self) -> ThreadPoolExecutor:
        """The pool background forwards run in (created on first use)."""
        with self._executor_lock:
            if self._forward_executor is None:
                self._forward_executor = ThreadPoolExecutor(
                    max_workers=_MAX_CONCURRENT_FORWARDS,
                    thread_name_prefix="syslog-forward",
                )
            return self._forward_executor

    def _shutdown_executor(self) -> None:
        """Stop the forward pool (queued sends dropped); a later submit starts one."""
        with self._executor_lock:
            executor, self._forward_executor = self._forward_executor, None
        if executor is not None:
            executor.shutdown(wait=False, cancel_futures=True)

    def load(self, targets: list[dict[str, Any]]) -> None:
        """Load target configs from persistence."""
        with self._lock:
            self._targets = list(targets)
            # Close stale connections
            active_ids = {t["id"] for t in self._targets}
            stale_ids = [k for k in self._connections if k not in active_ids]
            for tid in stale_ids:
                self._connections[tid].close()
                del self._connections[tid]

    @property
    def targets(self) -> list[dict[str, Any]]:
        """Return the current target list."""
        return list(self._targets)

    def add_target(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        facility: str = DEFAULT_FACILITY,
        fmt: str = "rfc5424",
        severity_filter: list[str] | None = None,
        signal_class_filter: list[str] | None = None,
        node_filter: list[str] | None = None,
        freq_min_hz: float | None = None,
        freq_max_hz: float | None = None,
        rule_name_filter: list[str] | None = None,
        tls_ca_bundle: str | None = None,
        tls_client_cert: str | None = None,
        tls_client_key: str | None = None,
    ) -> dict[str, Any]:
        """Add a new syslog target. Returns the config dict."""
        target = {
            "id": secrets.token_hex(6),
            "host": host,
            "port": port,
            "protocol": protocol.lower(),
            "facility": facility,
            "format": fmt,
            "enabled": True,
            "severity_filter": severity_filter or ["critical", "warning"],
            "signal_class_filter": signal_class_filter or [],
            "node_filter": node_filter or [],
            "freq_min_hz": freq_min_hz,
            "freq_max_hz": freq_max_hz,
            "rule_name_filter": rule_name_filter or [],
            "tls_ca_bundle": tls_ca_bundle,
            "tls_client_cert": tls_client_cert,
            "tls_client_key": tls_client_key,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "delivery_count": 0,
            "failure_count": 0,
            "last_delivery": None,
            "last_error": None,
        }
        with self._lock:
            self._targets.append(target)
        return target

    def remove_target(self, target_id: str) -> bool:
        """Remove a target by ID. Returns True if found."""
        with self._lock:
            for i, t in enumerate(self._targets):
                if t["id"] == target_id:
                    self._targets.pop(i)
                    # Close the connection if one exists
                    conn = self._connections.pop(target_id, None)
                    if conn is not None:
                        conn.close()
                    return True
        return False

    def update_target(
        self,
        target_id: str,
        updates: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Update a target's config. Returns updated config or None."""
        allowed = {
            "host",
            "port",
            "protocol",
            "facility",
            "format",
            "enabled",
            "severity_filter",
            "signal_class_filter",
            "node_filter",
            "freq_min_hz",
            "freq_max_hz",
            "rule_name_filter",
            "tls_ca_bundle",
            "tls_client_cert",
            "tls_client_key",
        }
        with self._lock:
            for t in self._targets:
                if t["id"] == target_id:
                    reconnect_needed = False
                    for k, v in updates.items():
                        if k in allowed:
                            if k in (
                                "host",
                                "port",
                                "protocol",
                                "tls_ca_bundle",
                                "tls_client_cert",
                                "tls_client_key",
                            ):
                                if t.get(k) != v:
                                    reconnect_needed = True
                            t[k] = v
                    # If connection params changed, drop the existing connection
                    if reconnect_needed and target_id in self._connections:
                        self._connections[target_id].close()
                        del self._connections[target_id]
                    return dict(t)
        return None

    def get_target(self, target_id: str) -> dict[str, Any] | None:
        """Find a target by ID."""
        for t in self._targets:
            if t["id"] == target_id:
                return t
        return None

    def _get_connection(self, target: dict[str, Any]) -> _SyslogConnection | None:
        """Get or create a TCP/TLS connection for a target.

        Returns None for UDP targets (connectionless).
        """
        protocol = target.get("protocol", "udp").lower()
        if protocol == "udp":
            return None

        target_id = target["id"]
        with self._lock:
            conn = self._connections.get(target_id)
            if conn is None:
                conn = _SyslogConnection(
                    host=target["host"],
                    port=target.get("port", 514),
                    protocol=protocol,
                    tls_ca_bundle=target.get("tls_ca_bundle"),
                    tls_client_cert=target.get("tls_client_cert"),
                    tls_client_key=target.get("tls_client_key"),
                )
                self._connections[target_id] = conn
            return conn

    def _send_udp(self, host: str, port: int, data: bytes) -> bool:
        """Send a syslog message over UDP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(_SEND_TIMEOUT)
            try:
                # Truncate to max UDP size
                payload = data[:_MAX_MSG_SIZE]
                sock.sendto(payload, (host, port))
                return True
            finally:
                sock.close()
        except Exception as exc:
            logger.warning("Syslog UDP send to %s:%d failed: %s", host, port, exc)
            return False

    def _format_message(
        self,
        alert: dict[str, Any],
        target: dict[str, Any],
    ) -> bytes:
        """Format an alert message according to the target's format setting."""
        fmt = target.get("format", "rfc5424")
        facility = target.get("facility", DEFAULT_FACILITY)

        if fmt == "cef":
            cef_str = self.format_cef(alert)
            return cef_str.encode("utf-8", errors="replace")
        else:
            return format_rfc5424(alert, facility=facility, hostname=self._hostname)

    def format_cef(self, alert_data: dict[str, Any]) -> str:
        """Format an alert dict as a CEF message string."""
        return CEFFormatter.format(alert_data)

    def forward(self, alert: dict[str, Any]) -> int:
        """Forward an alert to all matching syslog targets.

        This method is synchronous and thread-safe; it blocks for up to
        ``_CONNECT_TIMEOUT`` + ``_SEND_TIMEOUT`` seconds per TCP/TLS target.
        From async code use :meth:`submit`, which runs it in the
        forwarder's own threads.

        Returns the number of successful deliveries.
        """
        delivered = 0
        targets = list(self._targets)  # Snapshot

        for target in targets:
            if not target.get("enabled", True):
                continue

            if not _matches_filter(alert, target):
                continue

            msg = self._format_message(alert, target)

            protocol = target.get("protocol", "udp").lower()
            success = False

            if protocol == "udp":
                success = self._send_udp(
                    target["host"],
                    target.get("port", 514),
                    msg,
                )
            else:
                # TCP or TLS
                conn = self._get_connection(target)
                if conn is not None:
                    success = conn.send(msg)

            now_iso = datetime.now(timezone.utc).isoformat()
            if success:
                target["delivery_count"] = target.get("delivery_count", 0) + 1
                target["last_delivery"] = now_iso
                target["last_error"] = None
                delivered += 1
            else:
                target["failure_count"] = target.get("failure_count", 0) + 1
                target["last_error"] = f"Send failed at {now_iso}"

        return delivered

    @property
    def dropped(self) -> int:
        """Background forwards dropped because too many were in flight."""
        return self._dropped

    @property
    def pending_forwards(self) -> int:
        """Background forwards (:meth:`submit`) still in flight."""
        return len(self._pending)

    def submit(self, alert: dict[str, Any]) -> bool:
        """Forward *alert* in the background (worker threads, bounded).

        Returns at once: False when no target is configured or too many
        forwards are in flight already (the alert is then dropped and
        counted in :attr:`dropped`).  Must be called from the running
        event loop.
        """
        if not self._targets:
            return False
        if len(self._pending) >= _MAX_PENDING_FORWARDS:
            self._dropped += 1
            if self._dropped == 1 or self._dropped % 100 == 0:
                logger.warning(
                    "Syslog forwarding backlog full (%d in flight): alert %s "
                    "dropped (%d dropped so far)",
                    _MAX_PENDING_FORWARDS,
                    alert.get("alert_id", ""),
                    self._dropped,
                )
            return False
        task = asyncio.get_running_loop().create_task(
            self._forward_in_background(dict(alert)), name="syslog-forward"
        )
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        return True

    async def _forward_in_background(self, alert: dict[str, Any]) -> None:
        if self._forward_slots is None:
            self._forward_slots = asyncio.Semaphore(_MAX_CONCURRENT_FORWARDS)
        try:
            async with self._forward_slots:
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    self._executor(), functools.partial(self.forward, alert)
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Syslog forwarding failed: %s", exc)

    async def stop_forwards(self, grace_seconds: float = 2.0) -> None:
        """Wait up to *grace_seconds* for background forwards, then cancel them.

        Then stops the forward thread pool (a send already running ends
        within its timeouts; nothing queued starts).
        """
        pending = list(self._pending)
        if pending:
            _done, still = await asyncio.wait(pending, timeout=max(0.0, grace_seconds))
            for task in still:
                task.cancel()
            if still:
                await asyncio.gather(*still, return_exceptions=True)
        self._shutdown_executor()

    def send_test(self, target_id: str) -> dict[str, Any]:
        """Send a test syslog message to a specific target.

        Returns a result dict with ``status`` (``delivered`` or ``failed``)
        and optional ``error`` message.
        """
        target = self.get_target(target_id)
        if target is None:
            return {"status": "failed", "error": "Target not found"}

        test_alert = {
            "alert_id": f"test-syslog-{secrets.token_hex(4)}",
            "name": "syslog_test",
            "severity": "info",
            "message": "SigRift syslog forwarding test message",
            "node_id": "test",
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "signal_class": "test",
            "freq_hz": 0,
            "anomaly_score": 0.0,
        }

        msg = self._format_message(test_alert, target)

        protocol = target.get("protocol", "udp").lower()
        success = False

        try:
            if protocol == "udp":
                success = self._send_udp(
                    target["host"],
                    target.get("port", 514),
                    msg,
                )
            else:
                conn = self._get_connection(target)
                if conn is not None:
                    success = conn.send(msg)

            if success:
                now_iso = datetime.now(timezone.utc).isoformat()
                target["delivery_count"] = target.get("delivery_count", 0) + 1
                target["last_delivery"] = now_iso
                return {"status": "delivered"}
            else:
                return {
                    "status": "failed",
                    "error": "Connection or send failed",
                }
        except Exception as exc:
            return {"status": "failed", "error": str(exc)[:200]}

    def close_all(self) -> None:
        """Close all persistent connections."""
        with self._lock:
            for conn in self._connections.values():
                conn.close()
            self._connections.clear()
