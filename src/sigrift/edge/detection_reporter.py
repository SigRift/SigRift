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
    reporter.close()  # Final disposal; stop() can be followed by start()/retry.

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
import re
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
import ssl
import uuid


class SummaryJournalError(ValueError):
    """Preserve/recover summary state before proceeding."""


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("detection_reporter")

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
# hostname checking. Point MLRF_CA_CERT (or MLRF_CA_BUNDLE, or the legacy
# BRIDGE_CA_BUNDLE) at a CA bundle to trust a private/staging CA.
# Verification is skipped only when
# MLRF_INSECURE_TLS=1 is set explicitly -- a missing or unset CA cert never
# disables it.
#
# A CA path that does not exist logs one error and the system trust store
# is used (still verifying). A CA path that exists but cannot be loaded
# (unreadable by this user, not PEM, a private key, a directory without a
# loadable hashed CA certificate, ...) raises
# TLSConfigError: the operator pinned that CA on purpose, so trusting
# something else instead would be wrong. main() checks this once at startup
# and exits with a clear message; DetectionReporter() raises it.
#
# Same policy as node_agent, rf_scan and wifi_scan; the block is
# inlined because this script also runs as a standalone file.

_CA_ENV_VARS = ("MLRF_CA_CERT", "MLRF_CA_BUNDLE", "BRIDGE_CA_BUNDLE")


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
        "the API key and the uploaded detections and IQ captures",
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


try:
    from sigrift.bridge import API_VERSION
except ImportError:
    API_VERSION = "1"

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

# The bare names (ask, psk, ..., pocsag) are the open-default model's
# classes, with the families the bridge's class_map assigns; UNKNOWN would
# trip the default "Novel Signal Detected" rule. lora-css is spread
# spectrum there and in edge_inference.FAMILIES, not analog.
FAMILIES = {
    "ASK": {"ook", "4ask", "8ask", "16ask", "ask"},
    "PAM": {"4pam", "8pam", "16pam"},
    "PSK": {"bpsk", "qpsk", "8psk", "16psk", "32psk", "psk"},
    "QAM": {"16qam", "32qam", "64qam", "128qam", "256qam", "qam"},
    "APSK": {"16apsk", "32apsk", "64apsk", "128apsk"},
    "FSK": {"2fsk", "4fsk", "2gfsk", "4gfsk", "fsk", "gfsk", "msk", "pocsag"},
    "MSK": {"2msk", "4msk", "2gmsk", "4gmsk"},
    "OFDM": {
        "ofdm-64",
        "ofdm-128",
        "ofdm-256",
        "ofdm-512",
        "ofdm-1024",
        "ofdm-2048",
        "ofdm",
    },
    "ANALOG": {"am-dsb", "am-ssb", "fm", "tone", "am", "fpv-analog"},
    "SPREAD_SPECTRUM": {"lora-css", "dsss"},
    "NOISE": {"noise"},
    "PULSED": {"adsb"},
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
# Hourly accumulator for edge-side summarization
# ---------------------------------------------------------------------------


class _BinStats:
    """Running statistics for a single (hour, class, family, freq_bin) bucket."""

    __slots__ = (
        "count",
        "conf_sum",
        "conf_min",
        "conf_max",
        "snr_sum",
        "snr_count",
        "power_sum",
        "power_count",
        "anomaly_sum",
        "anomaly_max",
    )

    def __init__(self) -> None:
        self.count = 0
        self.conf_sum = 0.0
        self.conf_min = 1.0
        self.conf_max = 0.0
        self.snr_sum = 0.0
        self.snr_count = 0
        self.power_sum = 0.0
        self.power_count = 0
        self.anomaly_sum = 0.0
        self.anomaly_max = 0.0

    def update(
        self,
        confidence: float,
        snr_db: float | None,
        power_dbm: float | None,
        anomaly_score: float,
    ) -> None:
        self.count += 1
        self.conf_sum += confidence
        if confidence < self.conf_min:
            self.conf_min = confidence
        if confidence > self.conf_max:
            self.conf_max = confidence
        if snr_db is not None:
            self.snr_sum += snr_db
            self.snr_count += 1
        if power_dbm is not None:
            self.power_sum += power_dbm
            self.power_count += 1
        self.anomaly_sum += anomaly_score
        if anomaly_score > self.anomaly_max:
            self.anomaly_max = anomaly_score

    def to_dict(self) -> dict:
        return {
            "detection_count": self.count,
            "avg_confidence": round(self.conf_sum / self.count, 4)
            if self.count
            else 0.0,
            "min_confidence": round(self.conf_min, 4),
            "max_confidence": round(self.conf_max, 4),
            "avg_snr_db": round(self.snr_sum / self.snr_count, 2)
            if self.snr_count
            else None,
            "avg_power_dbm": round(self.power_sum / self.power_count, 2)
            if self.power_count
            else None,
            "avg_anomaly": round(self.anomaly_sum / self.count, 4)
            if self.count
            else 0.0,
            "max_anomaly": round(self.anomaly_max, 4),
        }


def _adaptive_bin_hz(freq_hz: float) -> float:
    """Bin frequency: 25 kHz below 1 GHz, 500 kHz at/above 1 GHz."""
    if freq_hz < 1e9:
        return round(freq_hz / 25_000) * 25_000
    return round(freq_hz / 500_000) * 500_000


class _HourlyAccumulator:
    """Bounded cumulative UTC-hour state, retained after acknowledgement.

    Keep 24 contiguous UTC hours by default, retiring only acknowledged history.
    Limits cover encoded bytes and entry counts, not Python heap overhead. Each
    hour is at most 512 KiB encoded, safely below the Bridge's 1 MiB gzip ingress
    limit; one in-flight immutable body adds at most one hour to memory use.

    A reporter supplies a durable single-writer journal. Standalone accumulator
    instances remain useful for arithmetic tests; they do not promise durability.
    Neither mode is a raw-ingestion or alert outbox.
    """

    def __init__(
        self,
        anomaly_threshold: float = 0.8,
        *,
        node_id: str = "",
        hours: int = 24,
        max_bytes: int = 8 * 1024 * 1024,
        journal=None,
    ) -> None:
        if isinstance(hours, bool) or not isinstance(hours, int) or hours < 1:
            raise ValueError("summary retention hours must be a positive integer")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or max_bytes < 1
        ):
            raise ValueError("summary byte limit must be a positive integer")
        self._lock = threading.Lock()
        self._journal = journal
        self._node_id = node_id
        self._hours = {}
        self._latest_hour = None
        self._retention = hours
        self._max_bytes = max_bytes
        self._hour_max_bytes = min(max_bytes, 512 * 1024)
        self._max_entries = 16_384
        self._hour_max_entries = 4096
        self._entries = 0
        self._bytes = 0
        self._rejections = collections.Counter()
        self._anomaly_threshold = anomaly_threshold
        self._prefix = b'{"node_id":' + self._encode(node_id) + b',"summaries":['
        self._middle = b'],"high_anomaly_detections":['
        self._suffix = b"]}"
        self._empty_size = len(self._prefix + self._middle + self._suffix)
        if self._empty_size >= self._hour_max_bytes:
            raise ValueError("summary byte limit cannot hold node metadata")
        if journal is not None:
            self._restore()

    def _restore(self):
        """Refuse corrupt/incompatible retained state rather than reset it."""
        import math

        latest, rows, bins, raw = self._journal.load()
        for hour, generation, acked, size in rows:
            if (
                not all(type(v) is int for v in (hour, generation, acked, size))
                or not 0 <= acked <= generation <= 2**63 - 1
            ):
                raise ValueError("Invalid persisted summary hour")
            self._hours[hour] = {
                "bins": {},
                "raw": [],
                "generation": generation,
                "acked": acked,
                "size": size,
            }
        for hour, key, values, encoded in bins:
            key = tuple(json.loads(key))
            values = json.loads(values)
            if (
                len(key) != 3
                or set(values) != set(_BinStats.__slots__)
                or any(
                    type(v) not in (int, float) or not math.isfinite(v)
                    for v in values.values()
                )
            ):
                raise ValueError("Invalid persisted summary statistics")
            stats = _BinStats()
            for name, value in values.items():
                setattr(stats, name, value)
            if (
                type(stats.count) is not int
                or stats.count <= 0
                or any(
                    type(v) is not int or not 0 <= v <= stats.count
                    for v in (stats.snr_count, stats.power_count)
                )
            ):
                raise ValueError("Invalid persisted summary sample counts")
            expected = {
                **stats.to_dict(),
                "hour": self._hour_str(hour * 3600),
                "signal_class": key[0],
                "family": key[1],
                "freq_bin_hz": key[2],
            }
            if self._encode(expected) != encoded:
                raise ValueError("Persisted summary statistics/encoding mismatch")
            self._hours[hour]["bins"][key] = (stats, encoded)
        for hour, encoded in raw:
            if self._hour_str(
                float(json.loads(encoded)["timestamp"])
            ) != self._hour_str(hour * 3600):
                raise ValueError("Persisted summary raw hour mismatch")
            self._hours[hour]["raw"].append(encoded)
        self._latest_hour = latest
        for hour, bucket in self._hours.items():
            count = sum(item[0].count for item in bucket["bins"].values()) + len(
                bucket["raw"]
            )
            entries = len(bucket["bins"]) + len(bucket["raw"])
            if (
                count != bucket["generation"]
                or bucket["size"] != len(self._legacy_body(bucket))
                or bucket["size"] + 512 > self._hour_max_bytes
                or entries > self._hour_max_entries
            ):
                raise ValueError(
                    "Persisted summary exceeds limits or count/size differs"
                )
            from sigrift.edge.summary_protocol import validate

            validate(json.loads(self._body(bucket, hour)))
            self._entries += entries
            self._bytes += bucket["size"]
        if (
            self._entries > self._max_entries
            or self._bytes + len(self._hours) * 512 > self._max_bytes
            or (
                self._hours
                and (
                    type(latest) is not int
                    or max(self._hours) != latest
                    or latest - min(self._hours) >= self._retention
                )
            )
        ):
            raise ValueError("Persisted summary retention/limits incompatible")

    @staticmethod
    def _encode(value: object) -> bytes:
        return json.dumps(
            value, separators=(",", ":"), sort_keys=True, allow_nan=False
        ).encode("utf-8")

    @staticmethod
    def _hour_str(ts: float) -> str:
        import datetime

        return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:00:00Z"
        )

    def _reject(self, reason: str) -> bool:
        self._rejections[reason] += 1
        logger.warning("Summary observation rejected (%s)", reason)
        return False

    def accumulate(self, record: dict) -> bool:
        """Admit one observation atomically; rejection leaves accepted state intact."""
        import copy
        import datetime
        import math

        try:
            ts = record.get("timestamp", time.time())
            if isinstance(ts, str):
                ts = datetime.datetime.fromisoformat(ts).timestamp()
            hour = math.floor(ts / 3600)
            hour_text = self._hour_str(hour * 3600)
        except (TypeError, ValueError, OverflowError):
            with self._lock:
                return self._reject("invalid")
        with self._lock:
            latest = max(
                hour, self._latest_hour if self._latest_hour is not None else hour
            )
            cutoff = latest - self._retention + 1
            if hour < cutoff:
                return self._reject("too_old")
            expired = [key for key in self._hours if key < cutoff]
            # Never evict accepted, unacknowledged observations to make room.
            if any(
                self._hours[key]["generation"] != self._hours[key]["acked"]
                for key in expired
            ):
                return self._reject("backpressure")
            bucket = self._hours.get(hour)
            if bucket is None:
                bucket = {
                    "bins": {},
                    "raw": [],
                    "size": self._empty_size,
                    "generation": 0,
                    "acked": 0,
                }
            try:
                anomaly = record.get("anomaly_score", 0.0)
                if self._journal is not None:
                    from sigrift.edge.summary_protocol import (
                        valid_record_id,
                        valid_signal_class,
                    )

                    # Never durably accept a row that the versioned receiver
                    # cannot acknowledge; an invalid row would pin its hour.
                    for field in ("confidence", "anomaly_score", "freq_hz"):
                        value = record.get(field, 0.0)
                        if (
                            type(value) not in (int, float)
                            or not math.isfinite(value)
                            or value < 0
                            or (field != "freq_hz" and value > 1)
                        ):
                            return self._reject("invalid")
                    for field in ("signal_class", "family"):
                        value = record.get(field, "")
                        if not isinstance(value, str) or len(value) > 128:
                            return self._reject("invalid")
                    for field in ("snr_db", "power_dbm"):
                        value = record.get(field)
                        if value is not None and (
                            type(value) not in (int, float) or not math.isfinite(value)
                        ):
                            return self._reject("invalid")
                    if anomaly >= self._anomaly_threshold and (
                        type(record.get("timestamp")) not in (int, float)
                        or record.get("node_id") != self._node_id
                        or not valid_signal_class(record.get("signal_class"))
                        or not valid_record_id(record.get("id"))
                        or any(
                            json.loads(raw)["id"] == record["id"]
                            for raw in bucket["raw"]
                        )
                    ):
                        return self._reject("invalid")
                if anomaly >= self._anomaly_threshold:
                    encoded = self._encode(record)
                    delta = len(encoded) + bool(bucket["raw"])
                    key = stats = None
                else:
                    key = (
                        record.get("signal_class", ""),
                        record.get("family", ""),
                        _adaptive_bin_hz(record.get("freq_hz", 0.0)),
                    )
                    previous = bucket["bins"].get(key)
                    stats = copy.copy(previous[0]) if previous else _BinStats()
                    stats.update(
                        record.get("confidence", 0.0),
                        record.get("snr_db"),
                        record.get("power_dbm"),
                        anomaly,
                    )
                    encoded = self._encode(
                        {
                            **stats.to_dict(),
                            "hour": hour_text,
                            "signal_class": key[0],
                            "family": key[1],
                            "freq_bin_hz": key[2],
                        }
                    )
                    delta = (
                        len(encoded) - len(previous[1])
                        if previous
                        else len(encoded) + bool(bucket["bins"])
                    )
            except (TypeError, ValueError, OverflowError):
                return self._reject("invalid")
            proposed = (
                self._bytes - sum(self._hours[key]["size"] for key in expired) + delta
            )
            added_entry = int(stats is None or key not in bucket["bins"])
            expired_entries = sum(
                len(self._hours[key]["bins"]) + len(self._hours[key]["raw"])
                for key in expired
            )
            proposed_entries = self._entries - expired_entries + added_entry
            if hour not in self._hours:
                proposed += self._empty_size
            if (
                proposed
                + (len(self._hours) - len(expired) + int(hour not in self._hours))
                * (512 if self._journal else 0)
                > self._max_bytes
                or bucket["size"] + delta + (512 if self._journal else 0)
                > self._hour_max_bytes
                or proposed_entries > self._max_entries
                or len(bucket["bins"]) + len(bucket["raw"]) + added_entry
                > self._hour_max_entries
            ):
                return self._reject("capacity")
            if bucket["generation"] >= 2**63 - 1:
                return self._reject("generation_overflow")
            if self._journal is not None:
                try:
                    self._journal.admit(
                        hour,
                        bucket["generation"] + 1,
                        bucket["size"] + delta,
                        latest,
                        expired,
                        key,
                        {name: getattr(stats, name) for name in _BinStats.__slots__}
                        if stats
                        else None,
                        encoded,
                    )
                except (OSError, sqlite3.Error):
                    return self._reject("storage")
            for key_to_remove in expired:
                del self._hours[key_to_remove]
            if stats is None:
                bucket["raw"].append(encoded)
            else:
                bucket["bins"][key] = (stats, encoded)
            bucket["size"] += delta
            bucket["generation"] += 1
            self._hours[hour] = bucket
            self._latest_hour = latest
            self._bytes = proposed
            self._entries = proposed_entries
            return True

    def _legacy_body(self, bucket: dict) -> bytes:
        body = (
            self._prefix
            + b",".join(bucket["bins"][key][1] for key in sorted(bucket["bins"]))
            + self._middle
            + b",".join(bucket["raw"])
            + self._suffix
        )
        assert len(body) == bucket["size"]
        return body

    def _body(self, bucket: dict, hour: int) -> bytes:
        body = self._legacy_body(bucket)
        if self._journal is None:
            return body
        payload = json.loads(body)
        payload.update(
            protocol="rf-summary-v2",
            stream_id=self._journal.stream_id,
            hour=self._hour_str(hour * 3600),
            generation=bucket["generation"],
        )
        payload["payload_digest"] = hashlib.sha256(self._encode(payload)).hexdigest()
        return self._encode(payload)

    def pending_hours(self) -> list[int]:
        with self._lock:
            return [
                hour
                for hour, bucket in sorted(self._hours.items())
                if bucket["generation"] != bucket["acked"]
            ]

    def pending_snapshot(self, hour: int) -> tuple[int, bytes] | None:
        with self._lock:
            bucket = self._hours.get(hour)
            if bucket is None or bucket["generation"] == bucket["acked"]:
                return None
            return bucket["generation"], self._body(bucket, hour)

    def acknowledge(self, hour: int, generation: int) -> None:
        with self._lock:
            bucket = self._hours.get(hour)
            if bucket is not None:
                if not 0 <= generation <= bucket["generation"]:
                    raise ValueError("Invalid summary acknowledgement generation")
                if self._journal is not None:
                    self._journal.acknowledge(hour, generation)
                bucket["acked"] = max(bucket["acked"], generation)

    def snapshot(self) -> dict | None:
        """Read cumulative retained observations without changing acknowledgement."""
        with self._lock:
            if not self._hours:
                return None
            bodies = [
                json.loads(self._legacy_body(bucket)) for bucket in self._hours.values()
            ]
            return {
                "summaries": [row for body in bodies for row in body["summaries"]],
                "high_anomaly_detections": [
                    row for body in bodies for row in body["high_anomaly_detections"]
                ],
            }

    def stats(self) -> dict:
        with self._lock:
            overhead = 0
            if self._journal is not None:
                # JSON object concatenation adds the metadata fields and one
                # comma, without rebuilding all retained observation bodies.
                overhead = sum(
                    len(
                        self._encode(
                            {
                                "protocol": "rf-summary-v2",
                                "stream_id": self._journal.stream_id,
                                "hour": self._hour_str(hour * 3600),
                                "generation": bucket["generation"],
                                "payload_digest": "0" * 64,
                            }
                        )
                    )
                    - 1
                    for hour, bucket in self._hours.items()
                )
            return {
                "summary_retained_hours": len(self._hours),
                "summary_retained_bytes": self._bytes + overhead,
                "summary_retained_entries": self._entries,
                "summary_pending_hours": sum(
                    bucket["generation"] != bucket["acked"]
                    for bucket in self._hours.values()
                ),
                "summary_rejections": dict(self._rejections),
            }


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
        min_confidence: float = 0.5,
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
        iq_capture_low_confidence: float = 0.0,
        summarize: bool = False,
        summary_anomaly_threshold: float = 0.8,
        summary_retention_hours: int = 24,
        summary_max_bytes: int = 8 * 1024 * 1024,
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

        # SSL context — verifies the bridge unless MLRF_INSECURE_TLS=1 (see
        # _build_ssl_context). Raises TLSConfigError if the configured CA
        # bundle exists but cannot be loaded.
        self._ssl_ctx = _build_ssl_context()

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
        self._iq_capture_low_confidence = iq_capture_low_confidence
        # (detection_id, gzip bytes, n_samples, sample_rate or None)
        self._iq_queue: collections.deque[tuple] = collections.deque(maxlen=50)
        self._iq_lock = threading.Lock()

        # --- Syslog forwarding (optional, set externally) ---
        self.syslog_client = None

        # --- Hourly summarization (edge-side aggregation) ---
        self._report_lock = threading.Lock()
        self._summary_send_lock = threading.Lock()
        self._summary_retention_hours = summary_retention_hours
        self._summary_max_bytes = summary_max_bytes
        self._mode_lock = threading.Lock()
        self._summarize = summarize
        self._summary_anomaly_threshold = summary_anomaly_threshold
        self._accumulator: _HourlyAccumulator | None = None
        self._summary_journal = None
        self._closed = False
        if summarize or (
            data_dir
            and (Path(data_dir) / "summary-journal" / "summary.sqlite3").exists()
        ):
            self._accumulator = self._open_summary_accumulator()
            logger.info(
                "Edge-side hourly summarization enabled (anomaly_threshold=%.2f)",
                summary_anomaly_threshold,
            )

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

    def _open_summary_accumulator(self):
        try:
            from sigrift.edge.summary_journal import SummaryJournal
        except ImportError as exc:
            raise SummaryJournalError(
                "Summary mode requires the installed sigrift package with journal/protocol support; "
                "bare-file raw mode remains supported. Preserve the existing journal."
            ) from exc

        journal = None
        try:
            journal = SummaryJournal(self._data_dir, self.server_url, self.node_id)
            accumulator = _HourlyAccumulator(
                anomaly_threshold=self._summary_anomaly_threshold,
                node_id=self.node_id,
                hours=self._summary_retention_hours,
                max_bytes=self._summary_max_bytes,
                journal=journal,
            )
        except (
            OSError,
            sqlite3.Error,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
        ) as exc:
            if journal is not None:
                journal.close()
            raise SummaryJournalError(
                "Cannot open durable RF summary journal. Set a persistent data_dir/MLRF_DATA_DIR; "
                "preserve existing journal and node/receiver identity, stop competing writers, "
                "and recover the original journal rather than delete or reset it."
            ) from exc
        except BaseException:
            if journal is not None:
                journal.close()
            raise
        self._summary_journal = journal
        return accumulator

    @property
    def summarize(self) -> bool:
        """Whether new detections use hourly summaries instead of raw batches."""
        with self._mode_lock:
            return self._summarize

    @summarize.setter
    def summarize(self, enabled: bool) -> None:
        # Keep one accumulator across off/on transitions: the bridge replaces
        # hourly bins, so resetting it would overwrite earlier same-hour counts.
        # Retained summaries and pending raw batches both continue to flush.
        with self._mode_lock:
            if enabled and self._accumulator is None:
                if self._closed:
                    raise RuntimeError("Reporter is closed")
                self._accumulator = self._open_summary_accumulator()
            self._summarize = enabled

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
        if self._closed:
            raise RuntimeError("Reporter is closed")
        if self._running:
            return
        if self._flush_thread is not None and self._flush_thread.is_alive():
            raise RuntimeError("Previous reporter flush thread is still stopping")
        self._running = True
        self._last_flush_time = time.monotonic()
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            name="detection-flush",
            daemon=True,
        )
        try:
            self._flush_thread.start()
        except BaseException:
            self._running = False
            self._flush_thread = None
            raise
        logger.info("Background flush thread started")

    def stop(self) -> None:
        """Flush remaining buffer and stop the background thread."""
        if self._closed:
            return
        self._running = False
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=10.0)
            if not self._flush_thread.is_alive():
                self._flush_thread = None
        # Final flush
        self._do_flush()
        # Upload remaining IQ captures
        if self._iq_capture_enabled:
            self._upload_iq_captures()
        # Retain unsuccessful summaries in memory for a later explicit retry.
        self._flush_summaries()
        if self._accumulator is not None and self._accumulator.pending_hours():
            logger.warning("Reporter stopped with unacknowledged hourly summaries")
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

    def close(self) -> None:
        """Permanently dispose the reporter; stop() itself remains retryable.

        Never release the single-writer journal while an owned worker may use it.
        A timed-out worker is a visible close failure, not permission to start a
        second writer. HTTP/DNS has the same bounded-operation limits as stop().
        """
        if self._closed:
            return
        self.stop()
        if self._flush_thread is not None and self._flush_thread.is_alive():
            raise RuntimeError(
                "Reporter flush worker did not finish; journal remains owned"
            )
        if not self._summary_send_lock.acquire(timeout=15):
            raise RuntimeError("Summary sender did not finish; journal remains owned")
        try:
            with self._report_lock, self._mode_lock:
                self._closed = True
                if self._summary_journal is not None:
                    self._summary_journal.close()
        finally:
            self._summary_send_lock.release()

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
        decoded_messages: list[dict] | None = None,
        sample_rate: float | None = None,
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
            sample_rate: Optional rate (Hz) *iq_data* was sampled at; sent
                as X-Sample-Rate with a staged IQ capture (the bridge
                otherwise assumes 2.048 MHz).

        Returns:
            True if accepted into the raw buffer or retained summary state.
            False if filtered/deduped or summary admission was rejected; summary
            rejection reasons are exposed by get_stats().
        """
        with self._report_lock:
            if self._closed:
                raise RuntimeError("Reporter is closed")
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
                )
                result = self._anomaly_scorer.score(record)
                record["anomaly_score"] = result.score
                record["baseline_status"] = result.baseline_status
                if result.score >= 0.5:
                    with self._stats_lock:
                        self._total_anomalies += 1

            # --- Attach edge-decoded messages if provided ---
            if decoded_messages:
                record["decoded_messages"] = decoded_messages

            # Admission is atomic with dedup/repeat bookkeeping. The accumulator
            # retains acknowledged cumulative hours so late observations cannot
            # replace a larger previous snapshot with a partial reopened hour.
            with self._mode_lock:
                accumulator = self._accumulator if self._summarize else None
            if accumulator is None:
                with self._lock:
                    self._buffer.append(record)
                    buf_len = len(self._buffer)
            else:
                buf_len = 0
                if not accumulator.accumulate(record):
                    with self._dedup_lock:
                        if entry is None:
                            self._dedup.pop(dedup_key, None)
                        else:
                            self._dedup[dedup_key] = entry
                    if prev is None:
                        self._last_class.pop(freq_hz, None)
                    else:
                        self._last_class[freq_hz] = prev
                    return False
            with self._stats_lock:
                self._total_buffered += 1

        if self._iq_capture_enabled and iq_data is not None:
            if (
                self.anomaly_scoring
                and record.get("anomaly_score", 0) >= self._iq_capture_threshold
            ):
                self._stage_iq_capture(record["id"], iq_data, sample_rate)
            if (
                self._iq_capture_low_confidence > 0
                and confidence < self._iq_capture_low_confidence
            ):
                self._stage_iq_capture(record["id"], iq_data, sample_rate)

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
            }
        if self._accumulator is not None:
            stats.update(self._accumulator.stats())
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

    def _stage_iq_capture(
        self, detection_id: str, iq_data, sample_rate: float | None = None
    ) -> None:
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
                self._iq_queue.append(
                    (detection_id, compressed, len(iq_data), sample_rate)
                )
            logger.info(
                "IQ capture staged: %s (%d samples, %d bytes compressed)",
                detection_id,
                len(iq_data),
                len(compressed),
            )
        except Exception as e:
            logger.warning("Failed to stage IQ capture for %s: %s", detection_id, e)

    def _upload_iq(
        self,
        detection_id: str,
        compressed_data: bytes,
        n_samples: int,
        sample_rate: float | None = None,
    ) -> bool:
        """Upload a single IQ capture to the Bridge."""
        url = f"{self.server_url}/api/detections/{detection_id}/iq"
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "gzip",
            **_auth_headers(self.api_key),
            "X-API-Version": API_VERSION,
            "X-Node-ID": self.node_id,
            "X-IQ-Format": "float32-interleaved",
            "X-IQ-Samples": str(n_samples),
        }
        if sample_rate:
            headers["X-Sample-Rate"] = str(float(sample_rate))
        req = urllib.request.Request(
            url,
            data=compressed_data,
            headers=headers,
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
        for detection_id, data, n_samples, sample_rate in items:
            self._upload_iq(detection_id, data, n_samples, sample_rate)

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
                # A mode change must not strand records accepted in the
                # previous mode. The raw buffer and retained hourly bins are
                # disjoint, and each keeps its existing upload semantics.
                self._do_flush()
                self._flush_summaries()
                self._last_flush_time = time.monotonic()
                # Upload any staged IQ captures after batch flush
                if self._iq_capture_enabled:
                    self._upload_iq_captures()
            self._maybe_save_baselines()
            # Dirty closed hours remain pending even through quiet intervals.

    def _flush_summaries(self) -> None:
        """Serialize a bounded pass; socket/DNS behavior is not a hard wall deadline."""
        if self._accumulator is None:
            return
        deadline = time.monotonic() + 15.0
        if not self._summary_send_lock.acquire(timeout=15.0):
            return
        try:
            for hour in self._accumulator.pending_hours():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                snapshot = self._accumulator.pending_snapshot(hour)
                if snapshot is None:
                    continue
                generation, body = snapshot
                if self._upload_summary_bytes(body, timeout=remaining):
                    try:
                        self._accumulator.acknowledge(hour, generation)
                    except (OSError, sqlite3.Error):
                        logger.warning(
                            "Summary acknowledgement storage failed; snapshot remains pending"
                        )
        finally:
            self._summary_send_lock.release()

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
            with self._stats_lock:
                self._total_dropped += len(batch)
            logger.warning(
                "Dropped batch %s (%d detections) after retries exhausted",
                payload["batch_id"],
                len(batch),
            )

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
                    **_auth_headers(self.api_key),
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

    def _upload_summary_bytes(self, body: bytes, *, timeout: float) -> bool:
        """Send immutable bytes; the caller owns retention and acknowledgement."""
        url = f"{self.server_url}/api/detections/ingest-summary"
        compressed = gzip.compress(body)

        req = urllib.request.Request(
            url,
            data=compressed,
            headers={
                "Content-Type": "application/json",
                "Content-Encoding": "gzip",
                **_auth_headers(self.api_key),
                "X-API-Version": API_VERSION,
                "X-Node-ID": self.node_id,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                req, context=self._ssl_ctx, timeout=timeout
            ) as resp:
                if resp.status in (200, 201):
                    from sigrift.edge.summary_protocol import canonical_json, receipt

                    acknowledgement = json.loads(resp.read(65537))
                    if canonical_json(
                        acknowledgement.get("summary_receipt")
                    ) != canonical_json(receipt(json.loads(body))):
                        raise ValueError(
                            "Receiver did not acknowledge the exact versioned RF summary"
                        )
                    logger.info("Hourly summary acknowledged")
                    return True
                logger.warning("Summary upload returned %d", resp.status)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                logger.warning(
                    "RF summary stream/generation conflict: preserve the journal and receiver database; "
                    "restore the original node/receiver journal before retrying. No protocol downgrade was attempted."
                )
            else:
                logger.warning("Summary upload returned HTTP %d", e.code)
        except Exception as e:
            logger.warning("Summary upload failed: %s", e)
        with self._stats_lock:
            self._total_upload_failures += 1
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
        "--summarize",
        action="store_true",
        default=os.environ.get("MLRF_SUMMARIZE", "").lower() in ("1", "true", "yes"),
        help="Enable edge-side hourly summarization",
    )
    parser.add_argument(
        "--summary-anomaly-threshold",
        type=float,
        default=float(os.environ.get("MLRF_SUMMARY_ANOMALY_THRESHOLD", "0.8")),
        help="Anomaly threshold for high-anomaly bypass in summaries (default: 0.8)",
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
    if not _check_tls_config():
        sys.exit(1)

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
        summarize=args.summarize,
        summary_anomaly_threshold=args.summary_anomaly_threshold,
    )

    # Signal handling
    def _stop(sig, frame):
        logger.info("Signal received, stopping...")
        # Unwind any report()/journal lock before final resource cleanup.
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    from contextlib import ExitStack

    bt_scanner = spectrum_sweeper = syslog_client = None
    with ExitStack() as cleanup:
        cleanup.callback(reporter.close)
        reporter.start()

        # Start Bluetooth scanner if requested
        if args.bluetooth:
            try:
                from sigrift.lib.bt_scanner import BtScanner

                # No availability gate: the scanner waits for an absent or
                # down adapter itself and resumes when it returns.
                bt_scanner = BtScanner(
                    server_url=args.server_url,
                    api_key=args.api_key,
                    node_id=args.node_id,
                    adapter=args.bt_adapter,
                    scan_interval=args.bt_interval,
                )
                cleanup.callback(bt_scanner.stop)
                bt_scanner.start()
                logger.info("Bluetooth scanner started")
            except ImportError:
                logger.warning("bt_scanner module not available, skipping BT scanning")

        # Start spectrum sweeper if requested
        if args.spectrum_sweep:
            try:
                from sigrift.bridge.spectrum_sweeper import (
                    SpectrumSweeper,
                    check_backend,
                )

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
                    cleanup.callback(spectrum_sweeper.stop)
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
                cleanup.callback(syslog_client.stop)
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

    stats = reporter.get_stats()
    logger.info("Final stats: %s", json.dumps(stats, indent=2))

    if args.stats_only:
        print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
