#!/usr/bin/env python3
"""Lightweight edge syslog client for forwarding detection events.

Sends RFC 5424 formatted syslog messages over UDP, TCP, or TLS to a remote
syslog collector.  Uses only stdlib modules so it can run on resource-
constrained edge nodes without additional dependencies.

Structured data elements carry RF detection fields in the ``mlrf`` SD-ID,
making it easy to parse and correlate events in downstream SIEM systems.

Usage:
    client = EdgeSyslogClient(
        host="syslog.example.com",
        port=514,
        protocol="udp",
        node_id="edge-01",
        facility="local0",
        severity_threshold="info",
    )
    client.start()
    client.forward_detection({"signal_class": "ofdm-256", "freq_hz": 5.8e9, ...})
    client.stop()

Environment variables (used by detection_reporter.py):
    MLRF_SYSLOG_SERVER, MLRF_SYSLOG_PORT, MLRF_SYSLOG_PROTOCOL,
    MLRF_SYSLOG_FACILITY, MLRF_SYSLOG_SEVERITY
"""

from __future__ import annotations

import logging
import queue
import socket
import ssl
import threading
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# RFC 5424 facility & severity mappings
# ---------------------------------------------------------------------------

FACILITY_MAP: dict[str, int] = {
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
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

SEVERITY_MAP: dict[str, int] = {
    "emerg": 0,
    "alert": 1,
    "crit": 2,
    "err": 3,
    "warning": 4,
    "notice": 5,
    "info": 6,
    "debug": 7,
}

# Reverse map for log display
SEVERITY_NAMES: dict[int, str] = {v: k for k, v in SEVERITY_MAP.items()}

# App name and version embedded in syslog messages
_APP_NAME = "mlrf-edge"
_SYSLOG_VERSION = 1

# Queue sentinel to signal shutdown
_SHUTDOWN = object()


# ---------------------------------------------------------------------------
# RFC 5424 message builder
# ---------------------------------------------------------------------------


def _rfc5424_timestamp() -> str:
    """Return current UTC timestamp in RFC 5424 format."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _escape_sd_value(value: str) -> str:
    r"""Escape structured data param values per RFC 5424 section 6.3.3.

    Characters ``\``, ``"``, and ``]`` must be escaped with a backslash.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def build_rfc5424(
    facility: int,
    severity: int,
    hostname: str,
    app_name: str,
    proc_id: str,
    msg_id: str,
    message: str,
    structured_data: dict[str, dict[str, str]] | None = None,
) -> str:
    """Build a complete RFC 5424 syslog message string.

    Args:
        facility: Syslog facility code (0-23).
        severity: Syslog severity code (0-7).
        hostname: Originating hostname / node ID.
        app_name: Application name (up to 48 chars).
        proc_id: Process ID or ``-`` for nil.
        msg_id: Message type identifier or ``-``.
        message: Free-form message body (UTF-8).
        structured_data: Optional dict of SD-ID -> {param: value}.

    Returns:
        RFC 5424 formatted syslog string.
    """
    pri = facility * 8 + severity
    timestamp = _rfc5424_timestamp()

    # Build structured data string
    if structured_data:
        sd_parts: list[str] = []
        for sd_id, params in structured_data.items():
            param_str = " ".join(
                f'{k}="{_escape_sd_value(str(v))}"' for k, v in params.items()
            )
            sd_parts.append(f"[{sd_id} {param_str}]")
        sd_string = "".join(sd_parts)
    else:
        sd_string = "-"

    return (
        f"<{pri}>{_SYSLOG_VERSION} {timestamp} {hostname} "
        f"{app_name} {proc_id} {msg_id} {sd_string} {message}"
    )


# ---------------------------------------------------------------------------
# Edge Syslog Client
# ---------------------------------------------------------------------------


class EdgeSyslogClient:
    """Queue-based async syslog client for edge detection forwarding.

    Sends RFC 5424 messages over UDP, TCP, or TLS without blocking the
    detection pipeline.  TCP/TLS connections auto-reconnect with exponential
    backoff on failure.

    Args:
        host: Syslog server hostname or IP.
        port: Syslog server port (default 514).
        protocol: Transport protocol — ``"udp"``, ``"tcp"``, or ``"tls"``.
        node_id: Edge node identifier (used as hostname in syslog header).
        facility: Syslog facility name (default ``"local0"``).
        severity_threshold: Minimum severity to forward (default ``"info"``).
            Messages below this severity (higher numeric value) are silently
            dropped.
        max_queue_size: Maximum queued messages before dropping (default 5000).
        reconnect_base_delay: Initial reconnect delay in seconds (default 1.0).
        reconnect_max_delay: Maximum reconnect delay in seconds (default 60.0).
        tls_ca_bundle: Path to CA bundle for TLS verification (optional).
    """

    def __init__(
        self,
        host: str,
        port: int = 514,
        protocol: str = "udp",
        node_id: str = "edge-node",
        facility: str = "local0",
        severity_threshold: str = "info",
        *,
        max_queue_size: int = 5000,
        reconnect_base_delay: float = 1.0,
        reconnect_max_delay: float = 60.0,
        tls_ca_bundle: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.node_id = node_id

        if self.protocol not in ("udp", "tcp", "tls"):
            raise ValueError(
                f"protocol must be 'udp', 'tcp', or 'tls', got {protocol!r}"
            )

        # Facility / severity
        if facility.lower() not in FACILITY_MAP:
            raise ValueError(f"Unknown facility {facility!r}")
        self._facility = FACILITY_MAP[facility.lower()]
        if severity_threshold.lower() not in SEVERITY_MAP:
            raise ValueError(f"Unknown severity {severity_threshold!r}")
        self._severity_threshold = SEVERITY_MAP[severity_threshold.lower()]

        # Queue for async sending
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)

        # TCP / TLS reconnect parameters
        self._reconnect_base_delay = reconnect_base_delay
        self._reconnect_max_delay = reconnect_max_delay
        self._tls_ca_bundle = tls_ca_bundle

        # Connection state
        self._socket: socket.socket | None = None
        self._sender_thread: threading.Thread | None = None
        self._running = False
        # Monotonic deadline for draining the backlog during stop(); None
        # while running normally.  The sender keeps sending (and stream
        # transports keep reconnecting) until the shutdown sentinel or
        # this deadline, whichever comes first.
        self._drain_deadline: float | None = None

        # Stats
        self._stats_lock = threading.Lock()
        self._sent_count = 0
        self._drop_count = 0
        self._error_count = 0
        self._reconnect_count = 0

        logger.info(
            "EdgeSyslogClient configured: %s:%d/%s facility=%s threshold=%s node=%s",
            host,
            port,
            self.protocol,
            facility,
            severity_threshold,
            node_id,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background sender thread."""
        if self._running:
            return
        self._running = True
        self._connect()
        self._sender_thread = threading.Thread(
            target=self._send_loop,
            name="syslog-sender",
            daemon=True,
        )
        self._sender_thread.start()
        logger.info("Syslog sender thread started")

    def stop(self, drain_timeout: float = 10.0) -> None:
        """Send the queued backlog, then stop the sender thread.

        Messages queued before ``stop()`` are sent until the shutdown
        sentinel is reached, bounded by *drain_timeout* seconds; whatever
        is still queued at the deadline is counted as dropped.  New
        messages are refused as soon as ``stop()`` starts.
        """
        if not self._running:
            return
        # Deadline first: the sender treats "not running and no deadline"
        # as "stop now", and must never see that state while draining.
        self._drain_deadline = time.monotonic() + max(0.0, drain_timeout)
        self._running = False
        sender = self._sender_thread
        if sender is not None and sender.is_alive():
            # The sentinel goes behind the backlog.  On a full queue wait
            # for the sender to make room instead of skipping it: without
            # the sentinel the sender could only stop at the deadline.
            try:
                self._queue.put(_SHUTDOWN, timeout=max(0.0, drain_timeout))
            except queue.Full:
                pass
            sender.join(timeout=max(0.0, self._drain_remaining()) + 1.0)
        self._sender_thread = None
        self._drain_deadline = None
        self._disconnect()
        with self._stats_lock:
            logger.info(
                "Syslog client stopped: sent=%d dropped=%d errors=%d reconnects=%d",
                self._sent_count,
                self._drop_count,
                self._error_count,
                self._reconnect_count,
            )

    # ------------------------------------------------------------------
    # Public send methods
    # ------------------------------------------------------------------

    def send(
        self,
        severity: str,
        message: str,
        structured_data: dict[str, dict[str, str]] | None = None,
        msg_id: str = "-",
    ) -> bool:
        """Enqueue a syslog message for async sending.

        Args:
            severity: Severity name (e.g. ``"info"``, ``"warning"``).
            message: Free-form message body.
            structured_data: Optional RFC 5424 structured data.
            msg_id: Message type identifier (default ``"-"``).

        Returns:
            True if enqueued, False if the queue is full or severity is
            below the configured threshold.
        """
        sev_num = SEVERITY_MAP.get(severity.lower())
        if sev_num is None:
            logger.warning("Unknown severity %r, defaulting to 'info'", severity)
            sev_num = SEVERITY_MAP["info"]

        # Filter by severity threshold (lower numeric = more severe)
        if sev_num > self._severity_threshold:
            return False

        syslog_msg = build_rfc5424(
            facility=self._facility,
            severity=sev_num,
            hostname=self.node_id,
            app_name=_APP_NAME,
            proc_id="-",
            msg_id=msg_id,
            message=message,
            structured_data=structured_data,
        )

        if self._drain_deadline is not None:
            # stop() is draining: the backlog is final.
            with self._stats_lock:
                self._drop_count += 1
            return False

        try:
            self._queue.put_nowait(syslog_msg)
            return True
        except queue.Full:
            with self._stats_lock:
                self._drop_count += 1
            return False

    def forward_detection(self, detection: dict) -> bool:
        """Forward a detection event as a syslog message.

        Args:
            detection: Detection record dict with keys like ``signal_class``,
                ``freq_hz``, ``confidence``, ``snr_db``, ``power_dbm``, etc.

        Returns:
            True if enqueued successfully.
        """
        signal_class = detection.get("signal_class", "unknown")
        confidence = detection.get("confidence", 0.0)
        freq_hz = detection.get("freq_hz", 0.0)
        snr_db = detection.get("snr_db", 0.0)
        power_dbm = detection.get("power_dbm", 0.0)
        anomaly_score = detection.get("anomaly_score", 0.0)

        # Determine severity from anomaly score
        if anomaly_score >= 0.8:
            severity = "warning"
        elif anomaly_score >= 0.5:
            severity = "notice"
        else:
            severity = "info"

        freq_mhz = freq_hz / 1e6

        sd = {
            "mlrf@0": {
                "class": signal_class,
                "conf": f"{confidence:.4f}",
                "freq_hz": f"{freq_hz:.0f}",
                "snr_db": f"{snr_db:.2f}",
                "power_dbm": f"{power_dbm:.2f}",
                "anomaly": f"{anomaly_score:.4f}",
                "node": self.node_id,
            },
        }

        # Include optional fields
        if detection.get("family"):
            sd["mlrf@0"]["family"] = detection["family"]
        if detection.get("bandwidth_hz") is not None:
            sd["mlrf@0"]["bw_hz"] = f"{detection['bandwidth_hz']:.0f}"
        if detection.get("id"):
            sd["mlrf@0"]["det_id"] = detection["id"]

        message = (
            f"RF detection: {signal_class} at {freq_mhz:.3f} MHz "
            f"conf={confidence:.2f} snr={snr_db:.1f}dB power={power_dbm:.1f}dBm"
        )

        return self.send(severity, message, structured_data=sd, msg_id="detection")

    def forward_anomaly(self, anomaly: dict) -> bool:
        """Forward an anomaly scoring event as a syslog message.

        Args:
            anomaly: Dict with anomaly info including ``score``, ``freq_hz``,
                ``signal_class``, ``baseline_status``, etc.

        Returns:
            True if enqueued successfully.
        """
        score = anomaly.get("score", anomaly.get("anomaly_score", 0.0))
        freq_hz = anomaly.get("freq_hz", 0.0)
        signal_class = anomaly.get("signal_class", "unknown")
        baseline_status = anomaly.get("baseline_status", "unknown")

        if score >= 0.8:
            severity = "warning"
        elif score >= 0.5:
            severity = "notice"
        else:
            severity = "info"

        freq_mhz = freq_hz / 1e6

        sd = {
            "mlrf@0": {
                "type": "anomaly",
                "score": f"{score:.4f}",
                "class": signal_class,
                "freq_hz": f"{freq_hz:.0f}",
                "baseline": baseline_status,
                "node": self.node_id,
            },
        }

        message = (
            f"Anomaly score={score:.4f} for {signal_class} at {freq_mhz:.3f} MHz "
            f"baseline={baseline_status}"
        )

        return self.send(severity, message, structured_data=sd, msg_id="anomaly")

    def forward_health(self, stats: dict) -> bool:
        """Forward a node health / stats report as a syslog message.

        Args:
            stats: Dict with reporter stats (total_received, total_uploaded,
                buffer_size, etc.).

        Returns:
            True if enqueued successfully.
        """
        sd = {
            "mlrf@0": {
                "type": "health",
                "node": self.node_id,
                "received": str(stats.get("total_received", 0)),
                "uploaded": str(stats.get("total_uploaded", 0)),
                "filtered": str(stats.get("total_filtered", 0)),
                "dropped": str(stats.get("total_dropped", 0)),
                "anomalies": str(stats.get("total_anomalies", 0)),
                "buffer": str(stats.get("buffer_size", 0)),
            },
        }

        uploaded = stats.get("total_uploaded", 0)
        received = stats.get("total_received", 0)
        anomalies = stats.get("total_anomalies", 0)

        message = (
            f"Node health: received={received} uploaded={uploaded} "
            f"anomalies={anomalies} buffer={stats.get('buffer_size', 0)}"
        )

        return self.send("info", message, structured_data=sd, msg_id="health")

    def stats(self) -> dict:
        """Return syslog client statistics."""
        with self._stats_lock:
            return {
                "sent": self._sent_count,
                "dropped": self._drop_count,
                "errors": self._error_count,
                "reconnects": self._reconnect_count,
                "queue_size": self._queue.qsize(),
            }

    # ------------------------------------------------------------------
    # Internal: connection management
    # ------------------------------------------------------------------

    def _connect(self) -> None:
        """Establish the transport connection."""
        try:
            if self.protocol == "udp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.protocol in ("tcp", "tls"):
                raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                raw.settimeout(10.0)
                if self.protocol == "tls":
                    ctx = ssl.create_default_context()
                    if self._tls_ca_bundle:
                        ctx.load_verify_locations(self._tls_ca_bundle)
                    self._socket = ctx.wrap_socket(raw, server_hostname=self.host)
                else:
                    self._socket = raw
                self._socket.connect((self.host, self.port))
            logger.debug(
                "Syslog connection established: %s:%d/%s",
                self.host,
                self.port,
                self.protocol,
            )
        except Exception as exc:
            logger.warning("Syslog connect failed: %s", exc)
            self._socket = None

    def _disconnect(self) -> None:
        """Close the transport connection."""
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def _reconnect(self) -> None:
        """Reconnect with exponential backoff (TCP/TLS only)."""
        self._disconnect()
        delay = self._reconnect_base_delay
        while self._sending_allowed():
            try:
                self._connect()
                if self._socket is not None:
                    with self._stats_lock:
                        self._reconnect_count += 1
                    logger.info("Syslog reconnected to %s:%d", self.host, self.port)
                    return
            except Exception as exc:
                logger.debug("Syslog reconnect attempt failed: %s", exc)

            # Exponential backoff with cap (never past the drain deadline)
            if self._drain_deadline is not None:
                time.sleep(max(0.0, min(delay, self._drain_remaining())))
            else:
                time.sleep(delay)
            delay = min(delay * 2, self._reconnect_max_delay)

    # ------------------------------------------------------------------
    # Internal: sender loop
    # ------------------------------------------------------------------

    def _drain_remaining(self) -> float:
        """Seconds left before the stop() drain deadline (inf if running)."""
        deadline = self._drain_deadline
        if deadline is None:
            return float("inf")
        return deadline - time.monotonic()

    def _sending_allowed(self) -> bool:
        """True while running, or while stop() is draining within its deadline."""
        if self._running:
            return True
        return self._drain_deadline is not None and self._drain_remaining() > 0

    def _send_loop(self) -> None:
        """Send queued messages until the shutdown sentinel.

        The loop ends only at the sentinel that ``stop()`` queues behind
        the backlog (so everything enqueued before ``stop()`` is sent), or
        at the drain deadline, when the rest of the backlog is dropped.
        """
        while True:
            if not self._sending_allowed():
                self._drop_backlog()
                return
            try:
                msg = self._queue.get(timeout=0.5)
            except queue.Empty:
                if not self._running and self._drain_deadline is None:
                    # stop() already returned (e.g. join timed out).
                    return
                continue

            if msg is _SHUTDOWN:
                return

            self._send_message(msg)

    def _drop_backlog(self) -> None:
        """Count every message still queued as dropped (drain deadline hit)."""
        dropped = 0
        while True:
            try:
                msg = self._queue.get_nowait()
            except queue.Empty:
                break
            if msg is not _SHUTDOWN:
                dropped += 1
        if dropped:
            with self._stats_lock:
                self._drop_count += dropped
            logger.warning(
                "Syslog drain timed out: %d queued message(s) dropped", dropped
            )

    def _send_message(self, msg: str) -> None:
        """Send a single syslog message over the configured transport."""
        data = msg.encode("utf-8")

        try:
            if self.protocol == "udp":
                if self._socket is None:
                    self._connect()
                if self._socket is not None:
                    self._socket.sendto(data, (self.host, self.port))
                    with self._stats_lock:
                        self._sent_count += 1
                    return

            elif self.protocol in ("tcp", "tls"):
                # TCP/TLS: send with octet-counting framing (RFC 5425)
                framed = f"{len(data)} ".encode("ascii") + data
                if self._socket is None:
                    self._reconnect()
                if self._socket is not None:
                    self._socket.sendall(framed)
                    with self._stats_lock:
                        self._sent_count += 1
                    return

        except (OSError, BrokenPipeError, ConnectionResetError) as exc:
            with self._stats_lock:
                self._error_count += 1
            logger.debug("Syslog send error: %s", exc)

            # Reconnect for stream protocols
            if self.protocol in ("tcp", "tls"):
                self._reconnect()
                # Retry once after reconnect
                if self._socket is not None:
                    try:
                        framed = f"{len(data)} ".encode("ascii") + data
                        self._socket.sendall(framed)
                        with self._stats_lock:
                            self._sent_count += 1
                        return
                    except OSError:
                        pass

        with self._stats_lock:
            self._drop_count += 1
