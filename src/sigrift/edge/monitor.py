#!/usr/bin/env python3
"""
Simple RF monitoring script for edge node testing.
Continuously scans frequencies and classifies signals.
Logs detections to /opt/rf-edge/logs/

HTTP Status endpoint on port 8080:
  GET /status - JSON status info
  GET /       - Human-readable status
"""

import os
import socket
import numpy as np
import time
import sys
import json
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from logging.handlers import RotatingFileHandler
from datetime import datetime, timezone
from pathlib import Path

# The Hailo classifier lives under the deployed lib dir and pulls in the NPU
# runtime, which is absent off-device. Import it lazily in main() so this
# module (and its RTLTCPClient) can be imported for unit tests without it.


def _load_classifier(*args, **kwargs):
    """Import and construct the HailoClassifier at call time."""
    if "/opt/rf-edge/lib" not in sys.path:
        sys.path.insert(0, "/opt/rf-edge/lib")
    from node import HailoClassifier

    return HailoClassifier(*args, **kwargs)


# Setup logging. LOG_DIR is env-overridable (MLRF_LOG_DIR) so the module can
# be imported off-device (and in tests) without needing /opt/rf-edge/logs.
LOG_DIR = Path(os.environ.get("MLRF_LOG_DIR", "/opt/rf-edge/logs"))

# Console + file logging with rotation (5MB max)
LOG_START_TIME = datetime.now().strftime("%Y%m%d_%H%M%S")
MONITOR_LOG = LOG_DIR / f"monitor_{LOG_START_TIME}.log"
DETECTION_LOG = LOG_DIR / f"detections_{LOG_START_TIME}.jsonl"

logger = logging.getLogger("rf-monitor")
logger.setLevel(logging.INFO)
logger.propagate = False

formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# The rotating file handler is best-effort: if the log dir cannot be created
# or opened (no device filesystem), keep console logging rather than failing
# at import time.
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        MONITOR_LOG, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
except OSError as _log_exc:  # pragma: no cover - device-only path
    logger.warning("File logging disabled (%s): %s", LOG_DIR, _log_exc)

# Configuration
FREQUENCIES = {
    97.5: "FM Broadcast",
    101.1: "FM Broadcast",
    146.52: "2m Ham",
    162.55: "NOAA Weather",
    433.92: "ISM 433",
    462.5625: "FRS Ch1",
    868.3: "LoRa EU",
    915.0: "ISM 915",
}

DWELL_TIME = 0.2
CONFIDENCE_THRESHOLD = 0.6
SNR_THRESHOLD = 10.0
STATUS_PORT = 8080

# Global state for status endpoint
monitor_state = {
    "start_time": None,
    "scan_count": 0,
    "detections": 0,
    "last_scan": None,
    "classifier": None,
    "model_metadata": None,
    "rtl_connected": False,
    "cls_per_sec": 0.0,
    "cls_count": 0,
    "cls_window_start": None,
    "anomaly_enabled": False,
    "anomaly_count": 0,
    "anomaly_baseline": "unknown",
}


class StatusHandler(BaseHTTPRequestHandler):
    """HTTP handler for status endpoint."""

    def log_message(self, format, *args):
        pass  # Suppress HTTP logging

    def do_GET(self):
        if self.path == "/status" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            uptime = None
            if monitor_state["start_time"]:
                uptime = (datetime.now() - monitor_state["start_time"]).total_seconds()

            status = {
                "service": "rf-edge-monitor",
                "status": "running",
                "uptime_seconds": uptime,
                "start_time": monitor_state["start_time"].isoformat()
                if monitor_state["start_time"]
                else None,
                "scan_count": monitor_state["scan_count"],
                "detections": monitor_state["detections"],
                "cls_per_sec": monitor_state["cls_per_sec"],
                "capture_mode": "hailo",
                "anomaly_enabled": monitor_state["anomaly_enabled"],
                "anomaly_count": monitor_state["anomaly_count"],
                "anomaly_baseline": monitor_state["anomaly_baseline"],
                "last_scan": monitor_state["last_scan"],
                "rtl_connected": monitor_state["rtl_connected"],
                "frequencies": list(FREQUENCIES.keys()),
                "dwell_time_ms": int(DWELL_TIME * 1000),
                "model": monitor_state["model_metadata"],
                "log_file": str(MONITOR_LOG),
            }
            self.wfile.write(json.dumps(status, indent=2).encode())
        else:
            self.send_response(404)
            self.end_headers()


def start_status_server():
    """Start HTTP status server in background thread."""
    bind_addr = os.environ.get("STATUS_BIND", "127.0.0.1")
    server = HTTPServer((bind_addr, STATUS_PORT), StatusHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Status server started on %s:%d", bind_addr, STATUS_PORT)


class RTLTCPClient:
    """Persistent connection to rtl_tcp server.

    rtl_tcp streams interleaved unsigned 8-bit I/Q bytes with no framing, so
    a capture must start on an I byte. The client counts every stream byte it
    consumes after the 12-byte header; dropping stale data in arbitrary-sized
    chunks can stop on an odd byte count, and reading on from there would swap
    I and Q (a mirrored spectrum) in this and every later capture.
    """

    _HEADER_LEN = 12

    def __init__(self, host="127.0.0.1", port=1234):
        self.host = host
        self.port = port
        self.sock = None
        self.connected = False
        self._stream_bytes = 0  # I/Q bytes consumed since the header

    def _recv_exact(self, n):
        """Read exactly *n* stream bytes, counting them for I/Q alignment."""
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

    def _read_header(self):
        """Read the 12-byte rtl_tcp header exactly (recv may return fewer)."""
        got = 0
        while got < self._HEADER_LEN:
            chunk = self.sock.recv(self._HEADER_LEN - got)
            if not chunk:
                raise ConnectionError("rtl_tcp closed the connection")
            got += len(chunk)

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((self.host, self.port))
            self._read_header()
            self._stream_bytes = 0  # the header is not part of the I/Q stream
            self.connected = True
            monitor_state["rtl_connected"] = True
            logger.info(f"Connected to rtl_tcp at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to rtl_tcp: {e}")
            self.connected = False
            monitor_state["rtl_connected"] = False
            return False

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:  # noqa: E722
                pass
        self.connected = False
        monitor_state["rtl_connected"] = False

    def set_frequency(self, freq_hz):
        if not self.connected:
            return False
        try:
            cmd = bytes([0x01]) + int(freq_hz).to_bytes(4, "big")
            self.sock.send(cmd)
            return True
        except Exception as e:
            logger.error(f"Failed to set frequency: {e}")
            self.connected = False
            monitor_state["rtl_connected"] = False
            return False

    def _discard_buffered(self):
        """Drop samples queued since the last read (stale frequency/rate)."""
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

    def capture(self, num_samples=8192, dwell_time=0.2):
        if not self.connected:
            return None

        try:
            time.sleep(dwell_time)

            self._discard_buffered()
            self.sock.settimeout(5)
            if self._stream_bytes % 2:
                self._recv_exact(1)  # finish the half-read sample: realign on I

            data = self._recv_exact(num_samples * 2)

            raw = np.frombuffer(data, dtype=np.uint8)
            iq = (raw.astype(np.float32) - 127.5) / 127.5
            return iq[0::2] + 1j * iq[1::2]

        except Exception as e:
            logger.error(f"Capture failed: {e}")
            self.connected = False
            monitor_state["rtl_connected"] = False
            return None


rtl_client = None


def get_rtl_client():
    global rtl_client
    if rtl_client is None or not rtl_client.connected:
        rtl_client = RTLTCPClient()
        rtl_client.connect()
    return rtl_client


def capture_iq(freq_hz, num_samples=8192):
    client = get_rtl_client()
    if not client.connected:
        if not client.connect():
            raise ConnectionError("Cannot connect to rtl_tcp")

    if not client.set_frequency(freq_hz):
        raise ConnectionError("Cannot set frequency")

    iq = client.capture(num_samples, DWELL_TIME)
    if iq is None:
        raise ConnectionError("Capture failed")

    return iq


def estimate_snr(iq):
    fft = np.fft.fftshift(np.abs(np.fft.fft(iq)))
    signal_power = np.mean(np.sort(fft)[-len(fft) // 10 :] ** 2)
    noise_power = np.mean(np.sort(fft)[: len(fft) // 2] ** 2)
    return 10 * np.log10(signal_power / (noise_power + 1e-10))


def log_detection(freq_mhz, desc, snr_db, power_db, cls, conf, family):
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frequency_mhz": float(freq_mhz),
        "description": desc,
        "snr_db": float(round(snr_db, 1)),
        "power_db": float(round(power_db, 1)),
        "classification": cls,
        "confidence": float(round(conf, 3)),
        "family": family,
    }
    with open(DETECTION_LOG, "a") as f:
        f.write(json.dumps(record) + "\n")


def main():
    print("=" * 60)
    print("RF Signal Monitor - Edge Node")
    print("=" * 60)

    # Start status server
    start_status_server()

    # Initialize classifier
    print("Initializing classifier...")
    classifier = _load_classifier(
        "/opt/rf-edge/models/hailo_classifier.hef",
        "/opt/rf-edge/models/hailo_classifier_metadata.json",
    )

    if not classifier.available:
        print("ERROR: Classifier not available!")
        return 1

    # Load model metadata for status endpoint
    try:
        with open("/opt/rf-edge/models/hailo_classifier_metadata.json") as f:
            monitor_state["model_metadata"] = json.load(f)
    except:  # noqa: E722
        pass

    monitor_state["start_time"] = datetime.now()
    monitor_state["classifier"] = classifier
    monitor_state["anomaly_enabled"] = os.environ.get("MLRF_ANOMALY", "").lower() in (
        "1",
        "true",
        "yes",
    )
    if monitor_state["anomaly_enabled"]:
        monitor_state["anomaly_baseline"] = "learning"

    print(f"Classifier ready ({len(classifier.class_names)} classes)")
    print(f"Using ONNX: {getattr(classifier, 'use_onnx', False)}")
    print(f"Status endpoint: http://0.0.0.0:{STATUS_PORT}/status")
    print()

    monitor_state["cls_window_start"] = time.time()

    try:
        while True:
            monitor_state["scan_count"] += 1
            monitor_state["last_scan"] = datetime.now().isoformat()

            for freq_mhz, desc in sorted(FREQUENCIES.items()):
                freq_hz = int(freq_mhz * 1e6)

                try:
                    iq = capture_iq(freq_hz)
                    power_db = float(10 * np.log10(np.mean(np.abs(iq) ** 2) + 1e-10))
                    snr_db = float(estimate_snr(iq))

                    cls, conf, family, _ = classifier.classify(iq)
                    conf = float(conf)

                    # Track classifications per second
                    monitor_state["cls_count"] += 1
                    elapsed = time.time() - monitor_state["cls_window_start"]
                    if elapsed > 0:
                        monitor_state["cls_per_sec"] = round(
                            monitor_state["cls_count"] / elapsed, 1
                        )
                    # Reset window every 60s to keep rate current
                    if elapsed > 60:
                        monitor_state["cls_count"] = 0
                        monitor_state["cls_window_start"] = time.time()

                    if snr_db > SNR_THRESHOLD or conf > CONFIDENCE_THRESHOLD:
                        monitor_state["detections"] += 1
                        logger.info(
                            f"{freq_mhz:7.2f} MHz | {desc:14s} | "
                            f"SNR: {snr_db:5.1f} dB | {cls:12s} ({conf * 100:4.1f}%)"
                        )
                        log_detection(
                            freq_mhz, desc, snr_db, power_db, cls, conf, family
                        )

                except Exception as e:
                    logger.error(f"{freq_mhz:7.2f} MHz | Error: {e}")

            if monitor_state["scan_count"] % 10 == 0:
                print(
                    f"--- Scan {monitor_state['scan_count']}: {monitor_state['detections']} detections | {monitor_state['cls_per_sec']} cls/sec ---"
                )

    except KeyboardInterrupt:
        print(
            f"\nStopped after {monitor_state['scan_count']} scans, {monitor_state['detections']} detections"
        )


if __name__ == "__main__":
    sys.exit(main() or 0)
