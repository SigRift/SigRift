#!/usr/bin/env python3
"""SigRift edge detection reporter.

Runs on each edge node alongside node_agent.py and edge_inference.py.
Receives classification results, filters/deduplicates them, and uploads
detection batches to The Bridge central server.

Pipeline:
    edge_inference.py  ->  report()  ->  filter  ->  dedup  ->  score  ->  buffer  ->  upload
                                          |            |          |          |           |
                                       min_conf    sliding    anomaly     deque     gzip POST
                                       min_snr     5s window  (opt)      flush     exp backoff

When anomaly scoring is enabled (--anomaly-detection / MLRF_ANOMALY=1),
each detection is scored by the Tier 1 statistical scorer before buffering.
Baselines are learned per-frequency and saved to disk periodically.

Usage:
    # Integrated with edge_inference.py (programmatic)
    reporter = DetectionReporter(server_url, api_key, node_id, anomaly_scoring=True)
    reporter.start()
    result = engine.classify(iq)
    reporter.report(result, freq_hz=433.92e6, snr_db=12.5, power_dbm=-65.0)
    reporter.stop()

    # Standalone testing (synthetic detections)
    python3 detection_reporter.py --server-url https://host:8444 --api-key KEY --node-id N1 --test

    # With anomaly scoring
    python3 detection_reporter.py --test --anomaly-detection --data-dir /tmp/bridge

Environment variables:
    MLRF_BRIDGE_URL, MLRF_API_KEY, MLRF_NODE_ID, MLRF_ANOMALY
"""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import logging
import os
from pathlib import Path
import random
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import ssl
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("detection_reporter")

from sigrift.bridge import API_VERSION  # noqa: E402

REPORTER_VERSION = "3.2.0"

# Default class list (matches edge_inference.py)
DEFAULT_CLASSES = [
    "ook",
    "4ask",
    "8ask",
    "16ask",
    "4pam",
    "8pam",
    "16pam",
    "bpsk",
    "qpsk",
    "8psk",
    "16psk",
    "32psk",
    "16qam",
    "32qam",
    "64qam",
    "128qam",
    "256qam",
    "16apsk",
    "32apsk",
    "64apsk",
    "128apsk",
    "2fsk",
    "4fsk",
    "2gfsk",
    "4gfsk",
    "2msk",
    "4msk",
    "2gmsk",
    "4gmsk",
    "ofdm-64",
    "ofdm-128",
    "ofdm-256",
    "ofdm-512",
    "ofdm-1024",
    "ofdm-2048",
    "lora-css",
    "am-dsb",
    "am-ssb",
    "fm",
    "tone",
]

FAMILIES = {
    "ASK": {"ook", "4ask", "8ask", "16ask"},
    "PAM": {"4pam", "8pam", "16pam"},
    "PSK": {"bpsk", "qpsk", "8psk", "16psk", "32psk"},
    "QAM": {"16qam", "32qam", "64qam", "128qam", "256qam"},
    "APSK": {"16apsk", "32apsk", "64apsk", "128apsk"},
    "FSK": {"2fsk", "4fsk", "2gfsk", "4gfsk"},
    "MSK": {"2msk", "4msk", "2gmsk", "4gmsk"},
    "OFDM": {"ofdm-64", "ofdm-128", "ofdm-256", "ofdm-512", "ofdm-1024", "ofdm-2048"},
    "ANALOG": {"lora-css", "am-dsb", "am-ssb", "fm", "tone"},
}


def _class_to_family(cls_name: str) -> str:
    for fam, members in FAMILIES.items():
        if cls_name in members:
            return fam
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Dedup window entry
# ---------------------------------------------------------------------------


class _DedupEntry:
    """Tracks a signal class seen at a specific frequency within the dedup window."""

    __slots__ = (
        "signal_class",
        "count",
        "first_seen",
        "last_seen",
        "max_confidence",
        "max_snr_db",
        "max_power_dbm",
    )

    def __init__(
        self,
        signal_class: str,
        confidence: float,
        snr_db: float,
        power_dbm: float,
        ts: float,
    ) -> None:
        self.signal_class = signal_class
        self.count = 1
        self.first_seen = ts
        self.last_seen = ts
        self.max_confidence = confidence
        self.max_snr_db = snr_db
        self.max_power_dbm = power_dbm

    def update(
        self, confidence: float, snr_db: float, power_dbm: float, ts: float
    ) -> None:
        self.count += 1
        self.last_seen = ts
        if confidence > self.max_confidence:
            self.max_confidence = confidence
        if snr_db > self.max_snr_db:
            self.max_snr_db = snr_db
        if power_dbm > self.max_power_dbm:
            self.max_power_dbm = power_dbm


# ---------------------------------------------------------------------------
# Store-and-Forward Buffer
# ---------------------------------------------------------------------------


class SAFBuffer:
    """SQLite-backed store-and-forward buffer for unsent detection batches.

    When upload fails after retries, batches are persisted to a local SQLite
    database. A background replay loop periodically attempts to resend them.
    """

    def __init__(self, db_path: str | Path = "saf_buffer.db"):
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Create the buffer table if it doesn't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS saf_queue (
                    id INTEGER PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    last_attempt TEXT,
                    status TEXT DEFAULT 'pending'
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with WAL mode for concurrent access."""
        from sigrift.bridge.storage.encryption import open_db

        conn = open_db(self._db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def enqueue(self, payload: dict) -> int:
        """Store a failed batch for later replay. Returns queue ID."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        payload_json = json.dumps(payload)
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "INSERT INTO saf_queue (payload, created_at, status) VALUES (?, ?, 'pending')",
                    (payload_json, now),
                )
                queue_id = cur.lastrowid
        logger.info(
            "SAF: enqueued batch (queue_id=%d, size=%d bytes)",
            queue_id,
            len(payload_json),
        )
        return queue_id

    def peek(self, limit: int = 10) -> list[tuple[int, dict]]:
        """Get oldest pending batches without removing them."""
        with self._lock:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, payload FROM saf_queue WHERE status = 'pending' ORDER BY id ASC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def mark_sent(self, queue_id: int) -> None:
        """Remove successfully sent batch from queue."""
        with self._lock:
            with self._connect() as conn:
                conn.execute("DELETE FROM saf_queue WHERE id = ?", (queue_id,))
        logger.info("SAF: batch sent and removed (queue_id=%d)", queue_id)

    def mark_failed(self, queue_id: int) -> None:
        """Increment attempt count for a failed retry."""
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    "UPDATE saf_queue SET attempts = attempts + 1, last_attempt = ?, status = 'pending' WHERE id = ?",
                    (now, queue_id),
                )

    def pending_count(self) -> int:
        """Return number of unsent batches."""
        with self._lock:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) FROM saf_queue WHERE status = 'pending'"
                ).fetchone()
        return row[0] if row else 0

    def cleanup(self, max_age_hours: int = 72) -> int:
        """Remove batches older than max_age. Returns count removed."""
        import datetime as _dt

        cutoff = _dt.datetime.utcnow() - _dt.timedelta(hours=max_age_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM saf_queue WHERE created_at < ?",
                    (cutoff_str,),
                )
                removed = cur.rowcount
        if removed:
            logger.info(
                "SAF: cleaned up %d expired batches (older than %dh)",
                removed,
                max_age_hours,
            )
        return removed


# ---------------------------------------------------------------------------
# Detection Reporter
# ---------------------------------------------------------------------------


class DetectionReporter:
    """Edge-side detection reporter with filtering, dedup, and batch upload.

    Thread-safe — the flush thread runs independently of the inference
    thread that calls ``report()``.
    """

    def __init__(
        self,
        server_url: str,
        api_key: str,
        node_id: str,
        *,
        min_confidence: float = 0.2,  # lowered from 0.5 — allow weak signals to reach server for central scoring
        min_snr_db: float = 3.0,
        batch_size: int = 100,
        flush_interval_seconds: float = 5.0,
        max_buffer: int = 500,
        dedup_window_seconds: float = 5.0,
        repeat_report_interval: int = 30,
        max_retries: int = 5,
        base_retry_delay: float = 1.0,
        max_retry_delay: float = 30.0,
        anomaly_scoring: bool = False,
        data_dir: str | None = None,
        baseline_save_interval: float = 300.0,
        iq_capture: bool = False,
        iq_capture_threshold: float = 0.5,
        saf_db_path: str | Path | None = None,
        saf_replay_interval: float = 60.0,
    ) -> None:
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key
        self.node_id = node_id

        # Filtering
        self.min_confidence = min_confidence
        self.min_snr_db = min_snr_db

        # Batching
        self.batch_size = batch_size
        self.flush_interval_seconds = flush_interval_seconds
        self.max_buffer = max_buffer

        # Dedup
        self.dedup_window_seconds = dedup_window_seconds
        self.repeat_report_interval = repeat_report_interval

        # Retry
        self.max_retries = max_retries
        self.base_retry_delay = base_retry_delay
        self.max_retry_delay = max_retry_delay

        # Buffer (thread-safe via lock)
        self._buffer: collections.deque[dict] = collections.deque(maxlen=max_buffer)
        self._lock = threading.Lock()

        # Dedup state: freq_hz -> _DedupEntry
        self._dedup: dict[float, _DedupEntry] = {}
        self._dedup_lock = threading.Lock()

        # Class-change tracking: freq_hz -> (last_class, consecutive_count)
        self._last_class: dict[float, tuple[str, int]] = {}

        # Background flush thread
        self._flush_thread: threading.Thread | None = None
        self._running = False
        self._last_flush_time = time.monotonic()

        # Stats
        self._stats_lock = threading.Lock()
        self._total_received = 0
        self._total_filtered = 0
        self._total_deduped = 0
        self._total_buffered = 0
        self._total_uploaded = 0
        self._total_upload_failures = 0
        self._total_batches_sent = 0
        self._total_dropped = 0
        self._total_anomalies = 0

        # SSL context — uses system trust store by default; set BRIDGE_CA_BUNDLE
        # to override with a custom CA bundle path.
        self._ssl_ctx = ssl.create_default_context()
        ca_bundle = os.environ.get("BRIDGE_CA_BUNDLE")
        if ca_bundle:
            self._ssl_ctx.load_verify_locations(ca_bundle)

        # --- Anomaly scoring (optional, Tier 1) ---
        self.anomaly_scoring = anomaly_scoring
        self._baseline_manager = None
        self._anomaly_scorer = None
        self._data_dir = data_dir
        self._baseline_save_interval = baseline_save_interval
        self._last_baseline_save = time.monotonic()

        if anomaly_scoring:
            self._init_anomaly_scoring(data_dir)

        # --- IQ capture (optional) ---
        self._iq_capture_enabled = iq_capture
        self._iq_capture_threshold = iq_capture_threshold
        self._iq_queue: collections.deque[tuple[str, bytes]] = collections.deque(
            maxlen=50
        )
        self._iq_lock = threading.Lock()

        # --- Syslog forwarding (optional, set externally) ---
        self.syslog_client = None

        # --- Store-and-forward buffer ---
        if saf_db_path is None and data_dir:
            saf_db_path = Path(data_dir) / "saf_buffer.db"
        elif saf_db_path is None:
            saf_db_path = "saf_buffer.db"
        self._saf = SAFBuffer(db_path=saf_db_path)
        self._saf_replay_interval = saf_replay_interval
        self._last_saf_replay = time.monotonic()
        self._total_saf_enqueued = 0
        self._total_saf_replayed = 0

        logger.info(
            "DetectionReporter v%s initialized (node=%s, server=%s, "
            "batch=%d, flush=%.1fs, buffer=%d, anomaly=%s, iq_capture=%s)",
            REPORTER_VERSION,
            node_id,
            self.server_url,
            batch_size,
            flush_interval_seconds,
            max_buffer,
            "enabled" if anomaly_scoring else "disabled",
            "enabled" if iq_capture else "disabled",
        )

    # ------------------------------------------------------------------
    # Anomaly scoring init
    # ------------------------------------------------------------------

    def _init_anomaly_scoring(self, data_dir: str | None) -> None:
        """Initialize Tier 1 anomaly scoring components."""
        try:
            from sigrift.bridge.anomaly.baseline import BaselineManager
            from sigrift.bridge.anomaly.scorer import AnomalyScorer
        except ImportError:
            logger.warning("Anomaly package not available — scoring disabled")
            self.anomaly_scoring = False
            return

        self._baseline_manager = BaselineManager()
        self._anomaly_scorer = AnomalyScorer(self._baseline_manager)

        # Load saved baselines if available
        if data_dir:
            baseline_path = Path(data_dir) / "baselines.json"
            if baseline_path.exists():
                self._baseline_manager.load(str(baseline_path))

        logger.info("Tier 1 anomaly scoring initialized")

    def _baselines_path(self) -> Path | None:
        """Return path to baselines JSON, or None if no data_dir."""
        if self._data_dir:
            return Path(self._data_dir) / "baselines.json"
        return None

    def _maybe_save_baselines(self) -> None:
        """Save baselines if enough time has elapsed since last save."""
        if not self.anomaly_scoring or self._baseline_manager is None:
            return
        path = self._baselines_path()
        if path is None:
            return
        now = time.monotonic()
        if now - self._last_baseline_save >= self._baseline_save_interval:
            try:
                self._baseline_manager.save(str(path))
            except Exception as e:
                logger.warning("Failed to save baselines: %s", e)
            self._last_baseline_save = now

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background flush thread."""
        if self._running:
            return
        self._running = True
        self._last_flush_time = time.monotonic()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="detection-flush",
            daemon=True,
        )
        self._flush_thread.start()
        logger.info("Background flush thread started")

    def stop(self) -> None:
        """Flush remaining buffer and stop the background thread."""
        self._running = False
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=10.0)
            self._flush_thread = None
        # Final flush
        self._do_flush()
        # Final SAF replay attempt
        self._replay_saf()
        # Upload remaining IQ captures
        if self._iq_capture_enabled:
            self._upload_iq_captures()
        # Save baselines on shutdown
        if self.anomaly_scoring and self._baseline_manager is not None:
            path = self._baselines_path()
            if path:
                try:
                    self._baseline_manager.save(str(path))
                except Exception as e:
                    logger.warning("Failed to save baselines on shutdown: %s", e)
        logger.info(
            "Reporter stopped (uploaded=%d, filtered=%d, dropped=%d, anomalies=%d)",
            self._total_uploaded,
            self._total_filtered,
            self._total_dropped,
            self._total_anomalies,
        )

    def report(
        self,
        classification: dict,
        freq_hz: float,
        snr_db: float,
        power_dbm: float,
        iq_hash: str | None = None,
        iq_data=None,
        gain_db: float | None = None,
        lna_state: str | None = None,
        bandwidth_hz: float | None = None,
    ) -> bool:
        """Submit a classification result for reporting.

        Args:
            classification: Dict from edge_inference.py classify() with
                keys: class, confidence, family, inference_ms
            freq_hz: Center frequency in Hz.
            snr_db: Signal-to-noise ratio in dB.
            power_dbm: Signal power in dBm.
            iq_hash: Optional SHA-256 hash of first 256 IQ samples (16 hex chars).
            iq_data: Optional numpy complex IQ array for capture on anomaly.
            gain_db: Optional SDR receiver gain in dB (for AGC tracking).
            lna_state: Optional LNA state description (e.g. "auto", "max", "off").
            bandwidth_hz: Optional measured occupied bandwidth in Hz.
                If not provided, the server will estimate from signal_class.

        Returns:
            True if the detection was accepted (buffered), False if filtered/deduped.
        """
        with self._stats_lock:
            self._total_received += 1

        signal_class = classification.get("class", "")
        confidence = classification.get("confidence", 0.0)
        family = classification.get("family", _class_to_family(signal_class))
        inference_ms = classification.get("inference_ms", 0.0)

        # --- Filter: confidence ---
        if confidence < self.min_confidence:
            with self._stats_lock:
                self._total_filtered += 1
            return False

        # --- Filter: SNR ---
        if snr_db < self.min_snr_db:
            with self._stats_lock:
                self._total_filtered += 1
            return False

        # --- Class-change detection ---
        prev = self._last_class.get(freq_hz)
        if prev is not None:
            prev_class, prev_count = prev
            if signal_class == prev_class:
                new_count = prev_count + 1
                self._last_class[freq_hz] = (signal_class, new_count)
                # Only re-report after repeat_report_interval consecutive identical
                if new_count > 1 and new_count % self.repeat_report_interval != 0:
                    with self._stats_lock:
                        self._total_filtered += 1
                    return False
            else:
                self._last_class[freq_hz] = (signal_class, 1)
        else:
            self._last_class[freq_hz] = (signal_class, 1)

        now = time.time()

        # --- Dedup: sliding window ---
        with self._dedup_lock:
            self._clean_dedup(now)
            # Bin frequency to nearest 100 kHz to avoid float-precision misses
            dedup_key = round(freq_hz / 100_000) * 100_000
            entry = self._dedup.get(dedup_key)
            if entry is not None and entry.signal_class == signal_class:
                entry.update(confidence, snr_db, power_dbm, now)
                with self._stats_lock:
                    self._total_deduped += 1
                return False
            # New or different class at this frequency
            self._dedup[dedup_key] = _DedupEntry(
                signal_class,
                confidence,
                snr_db,
                power_dbm,
                now,
            )

        # --- Buffer the detection ---
        record = {
            "id": uuid.uuid4().hex[:16],
            "node_id": self.node_id,
            "timestamp": now,
            "signal_class": signal_class,
            "confidence": round(confidence, 4),
            "family": family,
            "freq_hz": freq_hz,
            "snr_db": round(snr_db, 2),
            "power_dbm": round(power_dbm, 2),
            "inference_ms": round(inference_ms, 2),
        }
        if gain_db is not None:
            record["gain_db"] = round(gain_db, 2)
        if lna_state is not None:
            record["lna_state"] = lna_state
        if bandwidth_hz is not None:
            record["bandwidth_hz"] = round(bandwidth_hz, 1)
        if iq_hash:
            record["iq_hash"] = iq_hash[:16]

        # Check for repeat_count
        if prev is not None:
            prev_class, prev_count = self._last_class[freq_hz]
            if prev_count > 1 and prev_count % self.repeat_report_interval == 0:
                record["repeat_count"] = prev_count

        # --- Anomaly scoring (Tier 1) ---
        if self.anomaly_scoring and self._baseline_manager is not None:
            self._baseline_manager.update(
                freq_hz,
                signal_class,
                confidence,
                power_dbm,
                snr_db=snr_db,
                bandwidth_hz=record.get("bandwidth_hz"),
                timestamp_epoch=time.time(),
            )
            result = self._anomaly_scorer.score(record)
            record["anomaly_score"] = result.score
            record["baseline_status"] = result.baseline_status
            if result.score >= 0.5:
                with self._stats_lock:
                    self._total_anomalies += 1

            # --- IQ capture on anomaly ---
            if (
                self._iq_capture_enabled
                and result.score >= self._iq_capture_threshold
                and iq_data is not None
            ):
                self._stage_iq_capture(record["id"], iq_data)

        with self._lock:
            self._buffer.append(record)
            buf_len = len(self._buffer)
        with self._stats_lock:
            self._total_buffered += 1

        # Forward to syslog if configured
        if self.syslog_client is not None:
            try:
                self.syslog_client.forward_detection(record)
                if self.anomaly_scoring and record.get("anomaly_score", 0) >= 0.5:
                    self.syslog_client.forward_anomaly(record)
            except Exception:
                pass  # never block the detection pipeline

        # Trigger immediate flush if buffer is full
        if buf_len >= self.batch_size:
            self._do_flush()

        return True

    def get_stats(self) -> dict:
        """Return reporter statistics."""
        with self._stats_lock:
            stats = {
                "total_received": self._total_received,
                "total_filtered": self._total_filtered,
                "total_deduped": self._total_deduped,
                "total_buffered": self._total_buffered,
                "total_uploaded": self._total_uploaded,
                "total_upload_failures": self._total_upload_failures,
                "total_batches_sent": self._total_batches_sent,
                "total_dropped": self._total_dropped,
                "total_anomalies": self._total_anomalies,
                "buffer_size": len(self._buffer),
                "anomaly_scoring": self.anomaly_scoring,
                "saf_enqueued": self._total_saf_enqueued,
                "saf_replayed": self._total_saf_replayed,
                "saf_pending": self._saf.pending_count(),
            }
        if self.anomaly_scoring and self._baseline_manager is not None:
            stats["baseline_frequencies"] = len(self._baseline_manager.baselines)
        return stats

    # ------------------------------------------------------------------
    # IQ fingerprint helper
    # ------------------------------------------------------------------

    @staticmethod
    def iq_fingerprint(iq_samples: bytes | list[float], n: int = 256) -> str:
        """Compute SHA-256 fingerprint of the first *n* IQ samples.

        Args:
            iq_samples: Raw bytes or list of float32 IQ values.
            n: Number of samples to hash (default 256).

        Returns:
            16-char hex string.
        """
        if isinstance(iq_samples, (bytes, bytearray)):
            data = bytes(iq_samples[: n * 4])  # 4 bytes per float32
        else:
            import struct

            data = struct.pack(f"<{min(len(iq_samples), n)}f", *iq_samples[:n])
        return hashlib.sha256(data).hexdigest()[:16]

    # ------------------------------------------------------------------
    # IQ capture
    # ------------------------------------------------------------------

    def _stage_iq_capture(self, detection_id: str, iq_data) -> None:
        """Compress IQ data and add to upload queue."""
        try:
            import struct as _struct

            # iq_data is a complex numpy array — interleave I/Q as float32
            i_vals = iq_data.real.astype("float32")
            q_vals = iq_data.imag.astype("float32")
            interleaved = bytearray()
            for i_val, q_val in zip(i_vals, q_vals):
                interleaved.extend(_struct.pack("<f", float(i_val)))
                interleaved.extend(_struct.pack("<f", float(q_val)))

            compressed = gzip.compress(bytes(interleaved))
            with self._iq_lock:
                self._iq_queue.append((detection_id, compressed, len(iq_data)))
            logger.info(
                "IQ capture staged: %s (%d samples, %d bytes compressed)",
                detection_id,
                len(iq_data),
                len(compressed),
            )
        except Exception as e:
            logger.warning("Failed to stage IQ capture for %s: %s", detection_id, e)

    def _upload_iq(
        self, detection_id: str, compressed_data: bytes, n_samples: int
    ) -> bool:
        """Upload a single IQ capture to the Bridge."""
        url = f"{self.server_url}/api/detections/{detection_id}/iq"
        req = urllib.request.Request(
            url,
            data=compressed_data,
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "gzip",
                "X-API-Key": self.api_key,
                "X-API-Version": API_VERSION,
                "X-Node-ID": self.node_id,
                "X-IQ-Format": "float32-interleaved",
                "X-IQ-Samples": str(n_samples),
            },
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=15) as resp:
                if resp.status in (200, 201):
                    logger.info("IQ capture uploaded: %s", detection_id)
                    return True
                logger.warning(
                    "IQ upload returned %d for %s", resp.status, detection_id
                )
        except Exception as e:
            logger.warning("IQ upload failed for %s: %s", detection_id, e)
        return False

    def _upload_iq_captures(self) -> None:
        """Drain IQ queue and upload each capture."""
        items = []
        with self._iq_lock:
            while self._iq_queue:
                items.append(self._iq_queue.popleft())
        for detection_id, data, n_samples in items:
            self._upload_iq(detection_id, data, n_samples)

    # ------------------------------------------------------------------
    # Internal: dedup cleanup
    # ------------------------------------------------------------------

    def _clean_dedup(self, now: float) -> None:
        """Remove expired dedup entries. Caller must hold _dedup_lock."""
        cutoff = now - self.dedup_window_seconds
        expired = [k for k, v in self._dedup.items() if v.last_seen < cutoff]
        for k in expired:
            del self._dedup[k]

    # ------------------------------------------------------------------
    # Internal: flush
    # ------------------------------------------------------------------

    def _flush_loop(self) -> None:
        """Background loop that flushes buffer periodically."""
        while self._running:
            time.sleep(0.5)
            elapsed = time.monotonic() - self._last_flush_time
            if elapsed >= self.flush_interval_seconds:
                self._do_flush()
                # Upload any staged IQ captures after batch flush
                if self._iq_capture_enabled:
                    self._upload_iq_captures()
            # Replay SAF buffer periodically
            saf_elapsed = time.monotonic() - self._last_saf_replay
            if saf_elapsed >= self._saf_replay_interval:
                self._replay_saf()
            self._maybe_save_baselines()

    def _do_flush(self) -> None:
        """Drain buffer and upload a batch."""
        with self._lock:
            if not self._buffer:
                self._last_flush_time = time.monotonic()
                return
            batch = list(self._buffer)
            self._buffer.clear()
        self._last_flush_time = time.monotonic()

        # Build payload
        now = time.time()
        period_end = now
        period_start = batch[0]["timestamp"] if batch else now

        # Compute summary
        class_counts: dict[str, int] = {}
        total_conf = 0.0
        for det in batch:
            cls = det["signal_class"]
            class_counts[cls] = class_counts.get(cls, 0) + 1
            total_conf += det["confidence"]

        dominant_class = max(class_counts, key=class_counts.get) if class_counts else ""

        payload = {
            "node_id": self.node_id,
            "batch_id": uuid.uuid4().hex[:16],
            "period_start": period_start,
            "period_end": period_end,
            "detections": batch,
            "summary": {
                "total_detections": len(batch),
                "class_counts": class_counts,
                "avg_confidence": round(total_conf / len(batch), 4) if batch else 0,
                "dominant_class": dominant_class,
                "dominant_family": _class_to_family(dominant_class),
            },
        }

        success = self._upload(payload)
        if success:
            with self._stats_lock:
                self._total_uploaded += len(batch)
                self._total_batches_sent += 1
            logger.info(
                "Uploaded batch %s (%d detections)", payload["batch_id"], len(batch)
            )
        else:
            # Store failed batch in SAF buffer instead of dropping
            try:
                self._saf.enqueue(payload)
                with self._stats_lock:
                    self._total_saf_enqueued += 1
            except Exception as e:
                logger.error("SAF enqueue failed, batch dropped: %s", e)
                with self._stats_lock:
                    self._total_dropped += len(batch)
            logger.warning(
                "Batch %s (%d detections) saved to SAF buffer after retries exhausted",
                payload["batch_id"],
                len(batch),
            )

    # ------------------------------------------------------------------
    # Internal: SAF replay
    # ------------------------------------------------------------------

    def _replay_saf(self) -> int:
        """Attempt to replay queued SAF batches. Returns count replayed."""
        self._last_saf_replay = time.monotonic()
        pending = self._saf.peek(limit=10)
        if not pending:
            return 0

        logger.info("SAF: replaying %d pending batches", len(pending))
        replayed = 0
        for queue_id, payload in pending:
            success = self._upload(payload)
            if success:
                self._saf.mark_sent(queue_id)
                n_dets = len(payload.get("detections", []))
                with self._stats_lock:
                    self._total_uploaded += n_dets
                    self._total_batches_sent += 1
                    self._total_saf_replayed += 1
                replayed += 1
            else:
                self._saf.mark_failed(queue_id)
                # Stop trying if server is still down
                break

        # Periodic cleanup of very old entries
        self._saf.cleanup(max_age_hours=72)
        return replayed

    # ------------------------------------------------------------------
    # Internal: upload with retry
    # ------------------------------------------------------------------

    def _upload(self, payload: dict) -> bool:
        """Upload a detection batch with exponential backoff retry."""
        url = f"{self.server_url}/api/detections/batch"
        body = json.dumps(payload).encode("utf-8")
        compressed = gzip.compress(body)

        delay = self.base_retry_delay
        for attempt in range(1, self.max_retries + 1):
            req = urllib.request.Request(
                url,
                data=compressed,
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                    "X-API-Key": self.api_key,
                    "X-API-Version": API_VERSION,
                    "X-Node-ID": self.node_id,
                    "X-Reporter-Version": REPORTER_VERSION,
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(
                    req, context=self._ssl_ctx, timeout=15
                ) as resp:
                    data = json.loads(resp.read())
                    if resp.status == 200 or resp.status == 201:
                        return True
                    logger.warning("Upload returned %d: %s", resp.status, data)
            except urllib.error.HTTPError as e:
                body_text = ""
                try:
                    body_text = e.read().decode()[:200]
                except Exception:
                    pass
                logger.warning(
                    "Upload attempt %d/%d HTTP %d: %s",
                    attempt,
                    self.max_retries,
                    e.code,
                    body_text,
                )
                with self._stats_lock:
                    self._total_upload_failures += 1
            except Exception as e:
                logger.warning(
                    "Upload attempt %d/%d failed: %s", attempt, self.max_retries, e
                )
                with self._stats_lock:
                    self._total_upload_failures += 1

            if attempt < self.max_retries:
                jitter = delay * 0.2 * random.random()
                sleep_time = min(delay + jitter, self.max_retry_delay)
                logger.debug("Retrying in %.1fs...", sleep_time)
                time.sleep(sleep_time)
                delay = min(delay * 2, self.max_retry_delay)

        return False


# ---------------------------------------------------------------------------
# Standalone test mode
# ---------------------------------------------------------------------------


def _generate_synthetic_detections(
    reporter: DetectionReporter, count: int, interval: float
) -> None:
    """Generate synthetic detection events for testing upload."""
    test_freqs = [
        433.92e6,
        868.0e6,
        915.0e6,
        2.4e9,
        5.8e9,
        144.39e6,
        162.4e6,
        462.5625e6,
        1575.42e6,
    ]
    logger.info(
        "Generating %d synthetic detections (interval=%.2fs)...", count, interval
    )

    for i in range(count):
        if not reporter._running:
            break

        cls = random.choice(DEFAULT_CLASSES)
        freq = random.choice(test_freqs)
        confidence = round(random.uniform(0.3, 0.99), 4)
        snr = round(random.uniform(0.0, 30.0), 2)
        power = round(random.uniform(-90.0, -20.0), 2)
        inference_ms = round(random.uniform(1.0, 50.0), 2)

        classification = {
            "class": cls,
            "confidence": confidence,
            "family": _class_to_family(cls),
            "inference_ms": inference_ms,
        }

        accepted = reporter.report(classification, freq, snr, power)
        status = "accepted" if accepted else "filtered"

        if (i + 1) % 50 == 0 or i == 0:
            stats = reporter.get_stats()
            logger.info(
                "[%d/%d] %s=%s conf=%.2f snr=%.1f (%s) | buf=%d up=%d filt=%d dedup=%d",
                i + 1,
                count,
                cls,
                _class_to_family(cls),
                confidence,
                snr,
                status,
                stats["buffer_size"],
                stats["total_uploaded"],
                stats["total_filtered"],
                stats["total_deduped"],
            )

        time.sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SigRift edge detection reporter (standalone test mode)",
    )
    parser.add_argument(
        "--server-url",
        default=os.environ.get("MLRF_BRIDGE_URL", "https://localhost:8444"),
        help="The Bridge server URL",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("MLRF_API_KEY", ""),
        help="API key for authentication",
    )
    parser.add_argument(
        "--node-id",
        default=os.environ.get("MLRF_NODE_ID", "test-node"),
        help="Edge node identifier",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run in test mode with synthetic detections",
    )
    parser.add_argument(
        "--test-count",
        type=int,
        default=500,
        help="Number of synthetic detections to generate",
    )
    parser.add_argument(
        "--test-interval",
        type=float,
        default=0.02,
        help="Interval between synthetic detections (seconds)",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="Minimum confidence threshold",
    )
    parser.add_argument(
        "--min-snr",
        type=float,
        default=3.0,
        help="Minimum SNR threshold (dB)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Detections per upload batch",
    )
    parser.add_argument(
        "--flush-interval",
        type=float,
        default=5.0,
        help="Flush interval in seconds",
    )
    parser.add_argument(
        "--anomaly-detection",
        action="store_true",
        default=os.environ.get("MLRF_ANOMALY", "").lower() in ("1", "true", "yes"),
        help="Enable Tier 1 anomaly scoring",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=os.environ.get("MLRF_DATA_DIR", ""),
        help="Directory for baselines and persistent data",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Just print stats (for integration testing)",
    )
    parser.add_argument(
        "--bluetooth",
        action="store_true",
        default=os.environ.get("MLRF_BT_ENABLED", "").lower() in ("1", "true", "yes"),
        help="Enable Bluetooth scanning (requires BT adapter)",
    )
    parser.add_argument(
        "--bt-adapter",
        type=str,
        default=os.environ.get("MLRF_BT_ADAPTER", "hci0"),
        help="Bluetooth adapter (default: hci0)",
    )
    parser.add_argument(
        "--bt-interval",
        type=int,
        default=int(os.environ.get("MLRF_BT_SCAN_INTERVAL", "30")),
        help="Bluetooth scan interval in seconds (default: 30)",
    )
    parser.add_argument(
        "--syslog-server",
        type=str,
        default=os.environ.get("MLRF_SYSLOG_SERVER", ""),
        help="Syslog server hostname (enables syslog forwarding)",
    )
    parser.add_argument(
        "--syslog-port",
        type=int,
        default=int(os.environ.get("MLRF_SYSLOG_PORT", "514")),
        help="Syslog server port (default: 514)",
    )
    parser.add_argument(
        "--syslog-protocol",
        type=str,
        default=os.environ.get("MLRF_SYSLOG_PROTOCOL", "udp"),
        choices=["udp", "tcp", "tls"],
        help="Syslog transport protocol (default: udp)",
    )
    parser.add_argument(
        "--syslog-facility",
        type=str,
        default=os.environ.get("MLRF_SYSLOG_FACILITY", "local0"),
        help="Syslog facility (default: local0)",
    )
    parser.add_argument(
        "--syslog-severity",
        type=str,
        default=os.environ.get("MLRF_SYSLOG_SEVERITY", "info"),
        help="Minimum syslog severity to forward (default: info)",
    )
    parser.add_argument(
        "--spectrum-sweep",
        action="store_true",
        default=os.environ.get("MLRF_SWEEP_ENABLED", "").lower()
        in ("1", "true", "yes"),
        help="Enable wideband spectrum sweeping (requires rtl_power or hackrf_sweep)",
    )
    parser.add_argument(
        "--sweep-interval",
        type=int,
        default=int(os.environ.get("MLRF_SWEEP_INTERVAL", "60")),
        help="Spectrum sweep interval in seconds (default: 60)",
    )
    parser.add_argument(
        "--sweep-freq-start",
        type=float,
        default=float(os.environ.get("MLRF_SWEEP_FREQ_START", "70000000")),
        help="Sweep start frequency in Hz (default: 70e6)",
    )
    parser.add_argument(
        "--sweep-freq-end",
        type=float,
        default=float(os.environ.get("MLRF_SWEEP_FREQ_END", "6000000000")),
        help="Sweep end frequency in Hz (default: 6e9)",
    )
    args = parser.parse_args()

    if not args.test:
        logger.error("Standalone mode requires --test flag")
        logger.error("For integration, import DetectionReporter from this module")
        sys.exit(1)

    logger.info("Detection reporter v%s — test mode", REPORTER_VERSION)

    reporter = DetectionReporter(
        server_url=args.server_url,
        api_key=args.api_key,
        node_id=args.node_id,
        min_confidence=args.min_confidence,
        min_snr_db=args.min_snr,
        batch_size=args.batch_size,
        flush_interval_seconds=args.flush_interval,
        anomaly_scoring=args.anomaly_detection,
        data_dir=args.data_dir or None,
    )

    # Signal handling
    def _stop(sig, frame):
        logger.info("Signal received, stopping...")
        reporter.stop()
        stats = reporter.get_stats()
        logger.info("Final stats: %s", json.dumps(stats, indent=2))
        sys.exit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    reporter.start()

    # Start Bluetooth scanner if requested
    bt_scanner = None
    if args.bluetooth:
        try:
            from sigrift.lib.bt_scanner import BtScanner

            # No availability gate: the scanner waits for an absent or down
            # adapter itself and resumes when it returns.
            bt_scanner = BtScanner(
                server_url=args.server_url,
                api_key=args.api_key,
                node_id=args.node_id,
                adapter=args.bt_adapter,
                scan_interval=args.bt_interval,
            )
            bt_scanner.start()
            logger.info("Bluetooth scanner started")
        except ImportError:
            logger.warning("bt_scanner module not available, skipping BT scanning")

    # Start spectrum sweeper if requested
    spectrum_sweeper = None
    if args.spectrum_sweep:
        try:
            from sigrift.bridge.spectrum_sweeper import SpectrumSweeper, check_backend

            available_backend = check_backend()
            if available_backend is not None:
                spectrum_sweeper = SpectrumSweeper(
                    server_url=args.server_url,
                    api_key=args.api_key,
                    node_id=args.node_id,
                    freq_start_hz=args.sweep_freq_start,
                    freq_end_hz=args.sweep_freq_end,
                    sweep_interval=args.sweep_interval,
                )
                spectrum_sweeper.start()
                logger.info(
                    "Spectrum sweeper started (backend=%s, %.1f-%.1f MHz, interval=%ds)",
                    available_backend,
                    args.sweep_freq_start / 1e6,
                    args.sweep_freq_end / 1e6,
                    args.sweep_interval,
                )
            else:
                logger.warning(
                    "No sweep backend available (rtl_power or hackrf_sweep), "
                    "skipping spectrum sweeping"
                )
        except ImportError:
            logger.warning(
                "spectrum_sweeper module not available, skipping spectrum sweeping"
            )

    # Start syslog forwarder if configured
    syslog_client = None
    if args.syslog_server:
        try:
            from sigrift.bridge.edge_syslog import EdgeSyslogClient

            syslog_client = EdgeSyslogClient(
                host=args.syslog_server,
                port=args.syslog_port,
                protocol=args.syslog_protocol,
                node_id=args.node_id,
                facility=args.syslog_facility,
                severity_threshold=args.syslog_severity,
            )
            syslog_client.start()
            reporter.syslog_client = syslog_client
            logger.info(
                "Syslog forwarding started: %s:%d/%s",
                args.syslog_server,
                args.syslog_port,
                args.syslog_protocol,
            )
        except Exception:
            logger.warning("Failed to start syslog client", exc_info=True)

    # Pass syslog client to BT scanner if both are active
    if syslog_client and bt_scanner:
        bt_scanner.syslog_client = syslog_client

    _generate_synthetic_detections(reporter, args.test_count, args.test_interval)

    # Forward final health stats via syslog
    if syslog_client:
        syslog_client.forward_health(reporter.get_stats())

    # Wait for final flush
    time.sleep(reporter.flush_interval_seconds + 1)
    if syslog_client:
        syslog_client.stop()
    if spectrum_sweeper:
        spectrum_sweeper.stop()
    if bt_scanner:
        bt_scanner.stop()
    reporter.stop()

    stats = reporter.get_stats()
    logger.info("Final stats: %s", json.dumps(stats, indent=2))

    if args.stats_only:
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
