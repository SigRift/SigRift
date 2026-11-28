"""Shared storage infrastructure: schema, migrations, connection management.

All sub-stores receive a ``SharedContext`` instance that provides
thread-safe database access, write locking, and caching.
"""

from __future__ import annotations

import asyncio
import contextlib
import errno
import logging
import os
import shutil
import time
import sqlite3
import stat
import tempfile
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sigrift.bridge.cache import PartitionedCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class SQLDialect(str, Enum):
    """Supported database dialects."""

    SQLITE = "sqlite"
    POSTGRES = "postgres"


_DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "detections.db"

# Pre-migration copy policy (``_run_migrations``).  Before it applies
# pending migrations to an existing database the bridge copies it to
# ``<db>.pre-migration`` and refuses to migrate when that copy fails, unless
# BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP is set.  After a successful upgrade
# the copy is kept for the 7-day sweep (``_cleanup_orphan_migration_files``)
# while at least max(_KEEP_MIN_FREE_BYTES, the database's size) stays free
# and the disk stays below _KEEP_MAX_USED_FRACTION used (the "Disk usage
# HIGH" band of /api/health): the copy is about the database's size (7+ GB
# on production volumes), and the volume must still absorb another
# database-size of growth (WAL, the next upgrade's own copy).  Otherwise,
# and for a new database, it is deleted at once, as before; the periodic
# sweep removes a kept copy early once that stops being true.  The free
# space is checked before the copy is written (the database and its WAL,
# plus max(_COPY_MIN_MARGIN_BYTES, 2%)): a copy that cannot fit is refused
# without writing anything, so a bridge that Compose restarts after the
# refusal never fills the volume again at every start.
_ALLOW_MIGRATION_WITHOUT_BACKUP_ENV = "BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP"
_KEEP_MIN_FREE_BYTES = 1 << 30  # 1 GiB
_KEEP_MAX_USED_FRACTION = 0.80
_COPY_MIN_MARGIN_BYTES = 64 << 20  # 64 MiB
#: shutil.disk_usage, at module level so tests can fake a full disk.
_disk_usage = shutil.disk_usage

# Filter clause for "active" anomalies: not dismissed AND not snoozed.
#
# ``snoozed_until`` is written by Python as ``datetime.isoformat()``
# ("2026-11-05T10:00:00.123456+00:00").  It must not be compared as text
# with SQLite's ``datetime('now')`` ("2026-11-05 10:00:00"): 'T' sorts
# after ' ', so on the snooze's own UTC date every value compared later
# than "now" and a 1-hour snooze lasted until the next UTC midnight.
# ``julianday()`` parses both forms (and any UTC offset) into the same
# numeric scale.  A value it cannot parse yields NULL; COALESCE treats it
# as not snoozed, as the Python-side checks do.
ACTIVE_FILTER = (
    "dismissed = 0 AND (snoozed_until IS NULL OR "
    "COALESCE(julianday(snoozed_until) <= julianday('now'), 1))"
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS known_rf_signals (
    pattern_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    freq_min_hz REAL NOT NULL CHECK (freq_min_hz >= 0),
    freq_max_hz REAL NOT NULL CHECK (freq_max_hz > freq_min_hz),
    signal_class TEXT NOT NULL,
    node_id TEXT,
    note TEXT NOT NULL,
    source_detection_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_known_rf_match
    ON known_rf_signals(tenant_id, COALESCE(node_id, ''), signal_class, freq_min_hz, freq_max_hz);

CREATE TABLE IF NOT EXISTS detections (
    detection_id   TEXT PRIMARY KEY,
    node_id        TEXT NOT NULL,
    timestamp      TEXT NOT NULL,
    signal_class   TEXT NOT NULL,
    confidence     REAL NOT NULL,
    family         TEXT NOT NULL DEFAULT '',
    freq_hz        REAL NOT NULL DEFAULT 0.0,
    snr_db         REAL,
    power_dbm      REAL,
    inference_ms   REAL,
    backend        TEXT DEFAULT 'onnx',
    anomaly_score  REAL NOT NULL DEFAULT 0.0,
    baseline_status TEXT NOT NULL DEFAULT 'stable',
    has_iq_capture INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_detections_timestamp
    ON detections (timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_node_id
    ON detections (node_id);
CREATE INDEX IF NOT EXISTS idx_detections_signal_class
    ON detections (signal_class);
CREATE INDEX IF NOT EXISTS idx_detections_family
    ON detections (family);
CREATE INDEX IF NOT EXISTS idx_detections_node_timestamp
    ON detections (node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_detections_anomaly
    ON detections (anomaly_score) WHERE anomaly_score > 0.0;
CREATE INDEX IF NOT EXISTS idx_detections_timestamp_freq
    ON detections (timestamp, freq_hz);
CREATE INDEX IF NOT EXISTS idx_detections_timestamp_confidence
    ON detections (timestamp, confidence);

CREATE TABLE IF NOT EXISTS detection_aggregates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    hour           TEXT NOT NULL,
    node_id        TEXT NOT NULL,
    signal_class   TEXT NOT NULL,
    family         TEXT NOT NULL DEFAULT '',
    detection_count INTEGER NOT NULL DEFAULT 0,
    avg_confidence REAL NOT NULL DEFAULT 0.0,
    avg_snr_db     REAL,
    avg_power_dbm  REAL,
    avg_anomaly    REAL NOT NULL DEFAULT 0.0,
    min_freq_hz    REAL,
    max_freq_hz    REAL
);

-- The family-aware unique index (migrations 34/37).  This script runs at
-- every start-up, before _run_migrations applies the pending ones, so on a
-- database migrated earlier it runs after 34/37 and must not re-create the
-- family-less idx_agg_unique they dropped: INSERT OR REPLACE would then
-- collapse every family of a class into one row.  The DROP removes the
-- copy that earlier start-ups re-created; once it is gone both statements
-- are no-ops.  Like everything here, it may only use columns and tables
-- the CREATE statements above define, never ones a migration adds.
DROP INDEX IF EXISTS idx_agg_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agg_unique_v2
    ON detection_aggregates (hour, node_id, signal_class, family);
CREATE INDEX IF NOT EXISTS idx_agg_hour
    ON detection_aggregates (hour);

CREATE TABLE IF NOT EXISTS detection_feedback (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id   TEXT NOT NULL,
    label          TEXT NOT NULL,
    note           TEXT DEFAULT '',
    created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_feedback_detection_id
    ON detection_feedback (detection_id);
CREATE INDEX IF NOT EXISTS idx_feedback_label
    ON detection_feedback (label);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_id   TEXT NOT NULL,
    target_ids  TEXT DEFAULT '',
    signal_class TEXT DEFAULT '',
    freq_hz     REAL DEFAULT 0.0,
    node_id     TEXT DEFAULT '',
    operator    TEXT DEFAULT '',
    note        TEXT DEFAULT '',
    details     TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action
    ON audit_log (action);
CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_log (target_id);

CREATE TABLE IF NOT EXISTS wifi_metadata (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  TEXT NOT NULL,
    bssid         TEXT NOT NULL DEFAULT '',
    ssid          TEXT NOT NULL DEFAULT '',
    channel       INTEGER DEFAULT 0,
    channel_width INTEGER DEFAULT 20,
    band          TEXT DEFAULT '2.4GHz',
    security      TEXT DEFAULT '',
    signal_dbm    REAL DEFAULT 0.0,
    noise_dbm     REAL DEFAULT 0.0,
    frame_type    TEXT DEFAULT '',
    client_mac    TEXT DEFAULT '',
    data_rate_mbps REAL DEFAULT 0.0,
    retry_flag    INTEGER DEFAULT 0,
    timestamp     TEXT NOT NULL,
    node_id       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_wifi_bssid
    ON wifi_metadata (bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_channel
    ON wifi_metadata (channel);
CREATE INDEX IF NOT EXISTS idx_wifi_timestamp
    ON wifi_metadata (timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_detection
    ON wifi_metadata (detection_id);
CREATE INDEX IF NOT EXISTS idx_wifi_band_channel
    ON wifi_metadata (band, channel);
CREATE INDEX IF NOT EXISTS idx_wifi_node_id
    ON wifi_metadata (node_id);

CREATE TABLE IF NOT EXISTS wifi_anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid           TEXT NOT NULL,
    ssid            TEXT NOT NULL DEFAULT '',
    channel         INTEGER DEFAULT 0,
    band            TEXT DEFAULT '2.4GHz',
    security        TEXT DEFAULT '',
    signal_dbm      REAL DEFAULT 0.0,
    anomaly_score   REAL NOT NULL DEFAULT 0.0,
    priority        TEXT NOT NULL DEFAULT 'normal',
    dimensions      TEXT DEFAULT '',
    reasons         TEXT DEFAULT '',
    baseline_status TEXT NOT NULL DEFAULT 'stable',
    node_id         TEXT NOT NULL DEFAULT '',
    timestamp       TEXT NOT NULL,
    dismissed       INTEGER NOT NULL DEFAULT 0,
    client_count     INTEGER DEFAULT 0,
    retry_rate       REAL DEFAULT 0.0,
    noise_dbm_max    REAL DEFAULT 0.0,
    data_rate_min    REAL DEFAULT 0.0,
    data_rate_max    REAL DEFAULT 0.0,
    channel_width    INTEGER DEFAULT 0,
    frame_count      INTEGER DEFAULT 0,
    deauth_count     INTEGER DEFAULT 0,
    frame_type_counts TEXT DEFAULT '{}',
    expected_signal  REAL,
    signal_zscore    REAL DEFAULT 0.0,
    expected_channel INTEGER,
    expected_security TEXT DEFAULT '',
    expected_client_count REAL DEFAULT 0.0,
    expected_retry_rate REAL DEFAULT 0.0,
    baseline_observations INTEGER DEFAULT 0,
    client_macs      TEXT DEFAULT '[]',
    frame_capture    TEXT DEFAULT '[]',
    has_pcap_capture INTEGER NOT NULL DEFAULT 0,
    pcap_frame_count INTEGER NOT NULL DEFAULT 0,
    seen_count       INTEGER NOT NULL DEFAULT 1,
    first_seen       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_wifi_anomaly_score
    ON wifi_anomalies (anomaly_score) WHERE anomaly_score > 0.0;
CREATE INDEX IF NOT EXISTS idx_wifi_anomaly_bssid
    ON wifi_anomalies (bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_anomaly_timestamp
    ON wifi_anomalies (timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_anomaly_active
    ON wifi_anomalies (dismissed, anomaly_score DESC, timestamp DESC);

CREATE TABLE IF NOT EXISTS rf_anomalies (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id    TEXT NOT NULL DEFAULT '',
    signal_class    TEXT NOT NULL DEFAULT '',
    family          TEXT NOT NULL DEFAULT '',
    freq_hz         REAL NOT NULL DEFAULT 0.0,
    dedup_key       TEXT NOT NULL DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    timestamp       TEXT NOT NULL,
    confidence      REAL NOT NULL DEFAULT 0.0,
    snr_db          REAL,
    power_dbm       REAL,
    anomaly_score   REAL NOT NULL DEFAULT 0.0,
    priority        TEXT NOT NULL DEFAULT 'normal',
    dimensions      TEXT DEFAULT '{}',
    reasons         TEXT DEFAULT '[]',
    baseline_status TEXT NOT NULL DEFAULT 'stable',
    has_iq_capture  INTEGER NOT NULL DEFAULT 0,
    dismissed       INTEGER NOT NULL DEFAULT 0,
    seen_count      INTEGER NOT NULL DEFAULT 1,
    first_seen      TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_rf_anomaly_active
    ON rf_anomalies (dismissed, anomaly_score DESC, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_rf_anomaly_dedup
    ON rf_anomalies (dedup_key, dismissed) WHERE dismissed = 0;
CREATE INDEX IF NOT EXISTS idx_rf_anomaly_timestamp
    ON rf_anomalies (timestamp);

CREATE TABLE IF NOT EXISTS schema_version (
    version     INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at  TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Numbered migrations — append new entries at the end.
# Each is (version, description, sql).  The SQL is executed once; the
# version number is recorded in ``schema_version`` to prevent re-runs.
# ---------------------------------------------------------------------------

_MIGRATIONS: list[tuple[int, str, str]] = [
    # Migration 1: upsert index for active wifi anomalies per BSSID
    (
        1,
        "wifi anomaly BSSID active index",
        "CREATE INDEX IF NOT EXISTS idx_wifi_anomaly_bssid_active "
        "ON wifi_anomalies (bssid, dismissed) WHERE dismissed = 0",
    ),
    # Migration 2: covering index for get_wifi_networks() GROUP BY bssid
    (
        2,
        "wifi metadata bssid covering index",
        "CREATE INDEX IF NOT EXISTS idx_wifi_bssid_ts "
        "ON wifi_metadata (bssid, timestamp, signal_dbm, client_mac, node_id)",
    ),
    # Migration 3: audit_log action+target composite for get_dismissed_ids()
    (
        3,
        "audit log action target index",
        "CREATE INDEX IF NOT EXISTS idx_audit_action_target "
        "ON audit_log (action, target_id)",
    ),
    # Migration 4: hourly WiFi summary table
    (
        4,
        "wifi_metadata_hourly table",
        """
CREATE TABLE IF NOT EXISTS wifi_metadata_hourly (
    hour            TEXT NOT NULL,
    bssid           TEXT NOT NULL DEFAULT '',
    ssid            TEXT NOT NULL DEFAULT '',
    channel         INTEGER DEFAULT 0,
    channel_width   INTEGER DEFAULT 20,
    band            TEXT DEFAULT '2.4GHz',
    security        TEXT DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    avg_signal_dbm  REAL DEFAULT 0.0,
    min_signal_dbm  REAL DEFAULT 0.0,
    max_signal_dbm  REAL DEFAULT 0.0,
    avg_noise_dbm   REAL DEFAULT 0.0,
    frame_count     INTEGER DEFAULT 0,
    client_count    INTEGER DEFAULT 0,
    avg_data_rate_mbps REAL DEFAULT 0.0,
    retry_count     INTEGER DEFAULT 0,
    client_macs_json TEXT DEFAULT '[]'
);
""",
    ),
    # Migration 5: indexes for wifi_metadata_hourly
    (
        5,
        "wifi_metadata_hourly indexes",
        """
CREATE UNIQUE INDEX IF NOT EXISTS idx_wifi_hourly_unique
    ON wifi_metadata_hourly (hour, bssid, channel, band, node_id);
CREATE INDEX IF NOT EXISTS idx_wifi_hourly_hour
    ON wifi_metadata_hourly (hour);
CREATE INDEX IF NOT EXISTS idx_wifi_hourly_bssid
    ON wifi_metadata_hourly (bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_hourly_band_channel
    ON wifi_metadata_hourly (band, channel);
""",
    ),
    # Migration 6: snooze support for anomalies
    (
        6,
        "anomaly snoozed_until columns",
        """
ALTER TABLE wifi_anomalies ADD COLUMN snoozed_until TEXT DEFAULT NULL;
ALTER TABLE rf_anomalies ADD COLUMN snoozed_until TEXT DEFAULT NULL;
""",
    ),
    # Migration 7: AGC gain tracking columns
    (
        7,
        "AGC gain_db and lna_state columns",
        """
ALTER TABLE detections ADD COLUMN gain_db REAL DEFAULT NULL;
ALTER TABLE detections ADD COLUMN lna_state TEXT DEFAULT NULL;
""",
    ),
    # Migration 8: Multi-tenant isolation — tenant_id column on all tables
    (
        8,
        "tenant_id columns for multi-tenant isolation",
        """
ALTER TABLE detections ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE rf_anomalies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE wifi_anomalies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE wifi_metadata ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE detection_feedback ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE detection_aggregates ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE wifi_metadata_hourly ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
""",
    ),
    # Migration 9: Indexes on tenant_id for all tables
    (
        9,
        "tenant_id indexes",
        """
CREATE INDEX IF NOT EXISTS idx_detections_tenant ON detections (tenant_id);
CREATE INDEX IF NOT EXISTS idx_rf_anomalies_tenant ON rf_anomalies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_wifi_anomalies_tenant ON wifi_anomalies (tenant_id);
CREATE INDEX IF NOT EXISTS idx_wifi_metadata_tenant ON wifi_metadata (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log (tenant_id);
CREATE INDEX IF NOT EXISTS idx_feedback_tenant ON detection_feedback (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agg_tenant ON detection_aggregates (tenant_id);
CREATE INDEX IF NOT EXISTS idx_wifi_hourly_tenant ON wifi_metadata_hourly (tenant_id);
""",
    ),
    # Migration 10: OUI vendor lookup columns
    (
        10,
        "vendor columns for OUI lookup",
        """
ALTER TABLE wifi_metadata ADD COLUMN vendor TEXT NOT NULL DEFAULT '';
ALTER TABLE wifi_metadata ADD COLUMN client_vendor TEXT NOT NULL DEFAULT '';
ALTER TABLE wifi_metadata_hourly ADD COLUMN vendor TEXT NOT NULL DEFAULT '';
ALTER TABLE wifi_anomalies ADD COLUMN vendor TEXT NOT NULL DEFAULT '';
""",
    ),
    # Migration 11: HMAC chain for audit log tamper detection
    (
        11,
        "audit log hmac_chain column",
        "ALTER TABLE audit_log ADD COLUMN hmac_chain TEXT NOT NULL DEFAULT ''",
    ),
    # Migration 12: Bandwidth estimation column
    (
        12,
        "bandwidth_hz column on detections",
        "ALTER TABLE detections ADD COLUMN bandwidth_hz REAL DEFAULT NULL",
    ),
    # Migration 13: User accounts table
    (
        13,
        "users table for session-based auth",
        """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    display_name TEXT DEFAULT '',
    email TEXT DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users (tenant_id);
""",
    ),
    # Migration 14: Sessions table
    (
        14,
        "sessions table for login tokens",
        """
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token ON sessions (session_token);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at);
""",
    ),
    # Migration 15: Spectrum snapshots table for wideband FFT monitoring
    (
        15,
        "spectrum_snapshots table",
        """
CREATE TABLE IF NOT EXISTS spectrum_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    center_freq_hz REAL NOT NULL,
    bandwidth_hz REAL NOT NULL,
    fft_size INTEGER NOT NULL,
    bin_width_hz REAL NOT NULL,
    psd_dbm TEXT NOT NULL,
    noise_floor_dbm REAL,
    peak_freq_hz REAL,
    peak_power_dbm REAL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_spectrum_snap_node_ts
    ON spectrum_snapshots (node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_spectrum_snap_timestamp
    ON spectrum_snapshots (timestamp);
CREATE INDEX IF NOT EXISTS idx_spectrum_snap_tenant
    ON spectrum_snapshots (tenant_id);
CREATE INDEX IF NOT EXISTS idx_spectrum_snap_freq
    ON spectrum_snapshots (center_freq_hz);
""",
    ),
    # Migration 16: MFA columns on users table
    (
        16,
        "MFA columns on users table",
        """
ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL;
ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN mfa_enforced BOOLEAN NOT NULL DEFAULT 0;
""",
    ),
    # Migration 17: MFA backup codes table
    (
        17,
        "mfa_backup_codes table",
        """
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_user ON mfa_backup_codes (user_id);
""",
    ),
    # Migration 18: MFA tokens table (short-lived tokens for two-step login)
    (
        18,
        "mfa_tokens table for two-step login",
        """
CREATE TABLE IF NOT EXISTS mfa_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_mfa_tokens_token ON mfa_tokens (token);
CREATE INDEX IF NOT EXISTS idx_mfa_tokens_expires ON mfa_tokens (expires_at);
""",
    ),
    # Migration 19: Tenant settings table for MFA enforcement
    (
        19,
        "tenant_settings table",
        """
CREATE TABLE IF NOT EXISTS tenant_settings (
    tenant_id TEXT PRIMARY KEY,
    mfa_required BOOLEAN NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT ''
);
""",
    ),
    # Migration 20: Bluetooth devices table
    (
        20,
        "bt_devices table",
        """
CREATE TABLE IF NOT EXISTS bt_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_addr TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    device_class INTEGER DEFAULT 0,
    device_class_name TEXT NOT NULL DEFAULT '',
    appearance INTEGER DEFAULT 0,
    rssi_dbm REAL DEFAULT 0.0,
    tx_power_dbm REAL DEFAULT NULL,
    manufacturer_id INTEGER DEFAULT NULL,
    manufacturer TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    service_uuids TEXT DEFAULT '[]',
    adv_data TEXT DEFAULT '{}',
    connectable INTEGER DEFAULT 1,
    bonded INTEGER DEFAULT 0,
    channel INTEGER DEFAULT 0,
    timestamp TEXT NOT NULL,
    node_id TEXT NOT NULL DEFAULT '',
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_bt_device_addr ON bt_devices(device_addr);
CREATE INDEX IF NOT EXISTS idx_bt_device_type ON bt_devices(device_type);
CREATE INDEX IF NOT EXISTS idx_bt_timestamp ON bt_devices(timestamp);
CREATE INDEX IF NOT EXISTS idx_bt_node_id ON bt_devices(node_id);
CREATE INDEX IF NOT EXISTS idx_bt_tenant ON bt_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_bt_manufacturer ON bt_devices(manufacturer_id);
""",
    ),
    # Migration 21: Bluetooth anomalies table
    (
        21,
        "bt_anomalies table",
        """
CREATE TABLE IF NOT EXISTS bt_anomalies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_addr TEXT NOT NULL,
    device_name TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    device_class INTEGER DEFAULT 0,
    device_class_name TEXT NOT NULL DEFAULT '',
    manufacturer TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    rssi_dbm REAL DEFAULT 0.0,
    anomaly_score REAL NOT NULL DEFAULT 0.0,
    priority TEXT NOT NULL DEFAULT 'normal',
    dimensions TEXT DEFAULT '{}',
    reasons TEXT DEFAULT '[]',
    baseline_status TEXT NOT NULL DEFAULT 'stable',
    node_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    dismissed INTEGER NOT NULL DEFAULT 0,
    snoozed_until TEXT DEFAULT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT DEFAULT '',
    device_count_nearby INTEGER DEFAULT 0,
    service_uuids TEXT DEFAULT '[]',
    adv_data TEXT DEFAULT '{}',
    expected_rssi REAL DEFAULT NULL,
    rssi_zscore REAL DEFAULT 0.0,
    baseline_observations INTEGER DEFAULT 0,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_bt_anomaly_active ON bt_anomalies(dismissed, anomaly_score DESC, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_bt_anomaly_device ON bt_anomalies(device_addr);
CREATE INDEX IF NOT EXISTS idx_bt_anomaly_timestamp ON bt_anomalies(timestamp);
CREATE INDEX IF NOT EXISTS idx_bt_anomaly_tenant ON bt_anomalies(tenant_id);
""",
    ),
    # Migration 22: Bluetooth hourly summary table
    (
        22,
        "bt_devices_hourly table",
        """
CREATE TABLE IF NOT EXISTS bt_devices_hourly (
    hour TEXT NOT NULL,
    device_addr TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    device_class INTEGER DEFAULT 0,
    manufacturer TEXT NOT NULL DEFAULT '',
    vendor TEXT NOT NULL DEFAULT '',
    node_id TEXT NOT NULL DEFAULT '',
    avg_rssi_dbm REAL DEFAULT 0.0,
    min_rssi_dbm REAL DEFAULT 0.0,
    max_rssi_dbm REAL DEFAULT 0.0,
    observation_count INTEGER DEFAULT 0,
    service_uuids_json TEXT DEFAULT '[]',
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_bt_hourly_unique ON bt_devices_hourly(hour, device_addr, node_id);
CREATE INDEX IF NOT EXISTS idx_bt_hourly_hour ON bt_devices_hourly(hour);
CREATE INDEX IF NOT EXISTS idx_bt_hourly_device ON bt_devices_hourly(device_addr);
CREATE INDEX IF NOT EXISTS idx_bt_hourly_tenant ON bt_devices_hourly(tenant_id);
""",
    ),
    # Migration 23: FHSS events table
    (
        23,
        "fhss_events table for frequency-hopping detection",
        """
CREATE TABLE IF NOT EXISTS fhss_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fhss_id TEXT UNIQUE NOT NULL,
    node_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    hop_rate_hz REAL NOT NULL DEFAULT 0.0,
    hop_set TEXT NOT NULL DEFAULT '[]',
    bandwidth_hz REAL NOT NULL DEFAULT 0.0,
    dwell_time_ms REAL NOT NULL DEFAULT 0.0,
    duration_sec REAL NOT NULL DEFAULT 0.0,
    signal_class TEXT NOT NULL DEFAULT '',
    detection_count INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.0,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fhss_id ON fhss_events(fhss_id);
CREATE INDEX IF NOT EXISTS idx_fhss_node_ts ON fhss_events(node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_fhss_timestamp ON fhss_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_fhss_tenant ON fhss_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fhss_hop_rate ON fhss_events(hop_rate_hz);
""",
    ),
    # Migration 24: Emitters table for emitter association engine
    (
        24,
        "emitters table for emitter association",
        """
CREATE TABLE IF NOT EXISTS emitters (
    emitter_id      TEXT NOT NULL,
    primary_freq_hz REAL NOT NULL DEFAULT 0.0,
    bandwidth_hz    REAL NOT NULL DEFAULT 0.0,
    signal_class    TEXT NOT NULL DEFAULT '',
    power_profile   TEXT DEFAULT '{}',
    activity_pattern TEXT DEFAULT '{}',
    associated_nodes TEXT DEFAULT '[]',
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    detection_count INTEGER NOT NULL DEFAULT 0,
    detection_ids   TEXT DEFAULT '[]',
    updated_at      TEXT NOT NULL DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (emitter_id, tenant_id)
);
CREATE INDEX IF NOT EXISTS idx_emitters_signal_class ON emitters(signal_class);
CREATE INDEX IF NOT EXISTS idx_emitters_freq ON emitters(primary_freq_hz);
CREATE INDEX IF NOT EXISTS idx_emitters_detection_count ON emitters(detection_count DESC);
CREATE INDEX IF NOT EXISTS idx_emitters_tenant ON emitters(tenant_id);
CREATE INDEX IF NOT EXISTS idx_emitters_last_seen ON emitters(last_seen);
""",
    ),
    # Migration 25: TDOA estimates table for geolocation
    (
        25,
        "tdoa_estimates table for TDOA geolocation",
        """
CREATE TABLE IF NOT EXISTS tdoa_estimates (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    estimate_id       TEXT UNIQUE NOT NULL,
    timestamp         TEXT NOT NULL,
    signal_class      TEXT NOT NULL DEFAULT '',
    freq_hz           REAL NOT NULL DEFAULT 0.0,
    node_count        INTEGER NOT NULL DEFAULT 0,
    contributing_nodes TEXT DEFAULT '[]',
    coordinate_mode   TEXT NOT NULL DEFAULT '2d',
    location_json     TEXT DEFAULT '{}',
    cep_m             REAL NOT NULL DEFAULT 0.0,
    gdop              REAL NOT NULL DEFAULT 0.0,
    confidence        REAL NOT NULL DEFAULT 0.0,
    time_spread_ms    REAL NOT NULL DEFAULT 0.0,
    tdoa_pairs_json   TEXT DEFAULT '[]',
    tenant_id         TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_tdoa_estimate_id ON tdoa_estimates(estimate_id);
CREATE INDEX IF NOT EXISTS idx_tdoa_timestamp ON tdoa_estimates(timestamp);
CREATE INDEX IF NOT EXISTS idx_tdoa_signal_class ON tdoa_estimates(signal_class);
CREATE INDEX IF NOT EXISTS idx_tdoa_tenant ON tdoa_estimates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tdoa_confidence ON tdoa_estimates(confidence DESC);
""",
    ),
    # Migration 26: Config snapshots table for config versioning
    (
        26,
        "config_snapshots table for config versioning",
        """
CREATE TABLE IF NOT EXISTS config_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    trigger     TEXT NOT NULL,
    description TEXT DEFAULT '',
    files       TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_config_snap_timestamp ON config_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_config_snap_trigger ON config_snapshots(trigger);
CREATE INDEX IF NOT EXISTS idx_config_snap_tenant ON config_snapshots(tenant_id);
""",
    ),
    (
        27,
        "node_ids JSON column on bt_anomalies",
        """
ALTER TABLE bt_anomalies ADD COLUMN node_ids TEXT DEFAULT '{}';
""",
    ),
    (
        28,
        "salt column on mfa_backup_codes for PBKDF2",
        """
ALTER TABLE mfa_backup_codes ADD COLUMN salt BLOB DEFAULT NULL;
""",
    ),
    (
        29,
        "last_active column on sessions for idle timeout (NIST 800-63B)",
        """
ALTER TABLE sessions ADD COLUMN last_active TEXT DEFAULT NULL;
""",
    ),
    (
        30,
        "refined_class column for post-classification refinement",
        "ALTER TABLE detections ADD COLUMN refined_class TEXT NOT NULL DEFAULT ''",
    ),
    (
        32,
        "zigbee_devices and zigbee_devices_hourly tables",
        """
CREATE TABLE IF NOT EXISTS zigbee_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ieee_addr TEXT NOT NULL DEFAULT '',
    short_addr TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    pan_id TEXT NOT NULL DEFAULT '',
    channel INTEGER NOT NULL DEFAULT 0,
    rssi_dbm REAL NOT NULL DEFAULT 0.0,
    lqi INTEGER NOT NULL DEFAULT 0,
    manufacturer_code INTEGER NOT NULL DEFAULT 0,
    manufacturer TEXT NOT NULL DEFAULT '',
    clusters_json TEXT DEFAULT '[]',
    endpoints_json TEXT DEFAULT '[]',
    power_source TEXT NOT NULL DEFAULT 'unknown',
    profile_id TEXT NOT NULL DEFAULT '',
    node_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_zb_ieee_addr ON zigbee_devices(ieee_addr);
CREATE INDEX IF NOT EXISTS idx_zb_pan_id ON zigbee_devices(pan_id);
CREATE INDEX IF NOT EXISTS idx_zb_timestamp ON zigbee_devices(timestamp);
CREATE INDEX IF NOT EXISTS idx_zb_tenant ON zigbee_devices(tenant_id);
CREATE INDEX IF NOT EXISTS idx_zb_node_id ON zigbee_devices(node_id);

CREATE TABLE IF NOT EXISTS zigbee_devices_hourly (
    hour TEXT NOT NULL,
    ieee_addr TEXT NOT NULL DEFAULT '',
    short_addr TEXT NOT NULL DEFAULT '',
    device_name TEXT NOT NULL DEFAULT '',
    device_type TEXT NOT NULL DEFAULT 'unknown',
    pan_id TEXT NOT NULL DEFAULT '',
    channel INTEGER NOT NULL DEFAULT 0,
    manufacturer TEXT NOT NULL DEFAULT '',
    node_id TEXT NOT NULL DEFAULT '',
    avg_rssi_dbm REAL DEFAULT 0.0,
    min_rssi_dbm REAL DEFAULT 0.0,
    max_rssi_dbm REAL DEFAULT 0.0,
    avg_lqi REAL DEFAULT 0.0,
    observation_count INTEGER DEFAULT 0,
    clusters_json TEXT DEFAULT '[]',
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_zb_hourly_unique ON zigbee_devices_hourly(hour, ieee_addr, node_id);
CREATE INDEX IF NOT EXISTS idx_zb_hourly_hour ON zigbee_devices_hourly(hour);
CREATE INDEX IF NOT EXISTS idx_zb_hourly_tenant ON zigbee_devices_hourly(tenant_id);
""",
    ),
    (
        31,
        "covering indexes for dashboard query performance",
        """
CREATE INDEX IF NOT EXISTS idx_detections_tenant_ts_class
    ON detections (tenant_id, timestamp, signal_class, family, confidence);
CREATE INDEX IF NOT EXISTS idx_wifi_tenant_bssid_ts
    ON wifi_metadata (tenant_id, bssid, timestamp, ssid, channel, channel_width, band, security, signal_dbm, client_mac, node_id, vendor);
CREATE INDEX IF NOT EXISTS idx_wifi_tenant_ts
    ON wifi_metadata (tenant_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_tenant_band_ch
    ON wifi_metadata (tenant_id, band, channel, signal_dbm);
""",
    ),
    (
        33,
        "spectrum_all unified view for cross-protocol spectrum analytics",
        """
DROP VIEW IF EXISTS spectrum_all;
CREATE VIEW spectrum_all AS
SELECT
    timestamp, freq_hz, power_dbm, signal_class, node_id,
    bandwidth_hz, confidence, tenant_id, anomaly_score, snr_db
FROM detections
WHERE freq_hz > 0

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 1 AND channel <= 13 THEN (2407 + channel * 5) * 1000000.0
        WHEN channel = 14 THEN 2484000000.0
        WHEN channel >= 32 THEN (5000 + channel * 5) * 1000000.0
        ELSE 0
    END AS freq_hz,
    signal_dbm AS power_dbm,
    'wifi' AS signal_class,
    node_id,
    COALESCE(channel_width, 20) * 1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    CASE WHEN noise_dbm IS NOT NULL AND noise_dbm != 0
        THEN signal_dbm - noise_dbm ELSE NULL END AS snr_db
FROM wifi_metadata
WHERE signal_dbm IS NOT NULL

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel > 0 AND channel <= 39 THEN (2402 + channel * 2) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    CASE
        WHEN device_type = 'ble' THEN 'bluetooth-le'
        ELSE 'bluetooth-classic'
    END AS signal_class,
    node_id,
    1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM bt_devices

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 11 AND channel <= 26 THEN (2405 + (channel - 11) * 5) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    'zigbee' AS signal_class,
    node_id,
    2000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM zigbee_devices;
""",
    ),
    # Migration 34: Fix detection_aggregates UNIQUE index to include family
    (
        34,
        "detection_aggregates unique index includes family",
        """
CREATE UNIQUE INDEX IF NOT EXISTS idx_agg_unique_v2
    ON detection_aggregates (hour, node_id, signal_class, family);
DROP INDEX IF EXISTS idx_agg_unique;
""",
    ),
    (
        35,
        "status column on rf_anomalies for auto-resolution tracking",
        "ALTER TABLE rf_anomalies ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
    ),
    (
        36,
        "zigbee extended fields and channel energy table",
        """
ALTER TABLE zigbee_devices ADD COLUMN extended_pan_id TEXT NOT NULL DEFAULT '';
ALTER TABLE zigbee_devices ADD COLUMN stack_profile TEXT NOT NULL DEFAULT '';
ALTER TABLE zigbee_devices ADD COLUMN security_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zigbee_devices ADD COLUMN parent_addr TEXT NOT NULL DEFAULT '';

ALTER TABLE zigbee_devices_hourly ADD COLUMN extended_pan_id TEXT NOT NULL DEFAULT '';
ALTER TABLE zigbee_devices_hourly ADD COLUMN stack_profile TEXT NOT NULL DEFAULT '';
ALTER TABLE zigbee_devices_hourly ADD COLUMN security_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE zigbee_devices_hourly ADD COLUMN parent_addr TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS zigbee_channel_energy (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel INTEGER NOT NULL,
    rssi_dbm REAL NOT NULL DEFAULT 0.0,
    node_id TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_zb_energy_ts ON zigbee_channel_energy(timestamp);
CREATE INDEX IF NOT EXISTS idx_zb_energy_node ON zigbee_channel_energy(node_id);
CREATE INDEX IF NOT EXISTS idx_zb_energy_tenant ON zigbee_channel_energy(tenant_id);
""",
    ),
    (
        37,
        "drop redundant single-column indexes and ensure aggregate unique index",
        """
DROP INDEX IF EXISTS idx_detections_timestamp;
DROP INDEX IF EXISTS idx_detections_node_id;
DROP INDEX IF EXISTS idx_agg_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_agg_unique_v2
    ON detection_aggregates (hour, node_id, signal_class, family);
""",
    ),
    (
        38,
        "add max_anomaly_score column and get_recent composite index",
        """
ALTER TABLE detection_aggregates ADD COLUMN max_anomaly_score REAL NOT NULL DEFAULT 0.0;
CREATE INDEX IF NOT EXISTS idx_detections_tenant_node_ts
    ON detections (tenant_id, node_id, timestamp);
""",
    ),
    (
        40,
        "check_constraints_via_triggers",
        """
CREATE TRIGGER IF NOT EXISTS trg_detections_check_insert
BEFORE INSERT ON detections
BEGIN
    SELECT RAISE(ABORT, 'anomaly_score must be between 0 and 1')
    WHERE NEW.anomaly_score IS NOT NULL AND (NEW.anomaly_score < 0.0 OR NEW.anomaly_score > 1.0);
    SELECT RAISE(ABORT, 'confidence must be between 0 and 1')
    WHERE NEW.confidence IS NOT NULL AND (NEW.confidence < 0.0 OR NEW.confidence > 1.0);
END;

CREATE TRIGGER IF NOT EXISTS trg_detections_check_update
BEFORE UPDATE ON detections
BEGIN
    SELECT RAISE(ABORT, 'anomaly_score must be between 0 and 1')
    WHERE NEW.anomaly_score IS NOT NULL AND (NEW.anomaly_score < 0.0 OR NEW.anomaly_score > 1.0);
    SELECT RAISE(ABORT, 'confidence must be between 0 and 1')
    WHERE NEW.confidence IS NOT NULL AND (NEW.confidence < 0.0 OR NEW.confidence > 1.0);
END;
""",
    ),
    (
        41,
        "security state tables for DB-backed rate limits, lockout, OIDC, TOTP replay",
        """
CREATE TABLE IF NOT EXISTS rate_limit_login (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip   TEXT NOT NULL,
    attempt_at  REAL NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_login_ip
    ON rate_limit_login (client_ip, attempt_at);

CREATE TABLE IF NOT EXISTS account_lockout (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL,
    failure_at      REAL NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_account_lockout_user
    ON account_lockout (username, failure_at);

CREATE TABLE IF NOT EXISTS oidc_states (
    state       TEXT PRIMARY KEY,
    nonce       TEXT NOT NULL,
    redirect_to TEXT NOT NULL DEFAULT '/',
    created_at  REAL NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_oidc_states_created
    ON oidc_states (created_at);

CREATE TABLE IF NOT EXISTS totp_replay_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    totp_code   TEXT NOT NULL,
    used_at     REAL NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_totp_replay_user_code
    ON totp_replay_cache (username, totp_code, used_at);
""",
    ),
    (
        42,
        "remove FK constraints from wifi_metadata and detection_feedback for async pipelines",
        """
-- Migration 42: On fresh databases the initial schema already lacks FKs
-- and indexes are created by earlier migrations.  This migration now
-- only ensures the spectrum_all view is consistent.

-- Recreate spectrum_all view to ensure consistency
DROP VIEW IF EXISTS spectrum_all;
CREATE VIEW spectrum_all AS
SELECT
    timestamp, freq_hz, power_dbm, signal_class, node_id,
    bandwidth_hz, confidence, tenant_id, anomaly_score, snr_db
FROM detections
WHERE freq_hz > 0

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 1 AND channel <= 13 THEN (2407 + channel * 5) * 1000000.0
        WHEN channel = 14 THEN 2484000000.0
        WHEN channel >= 32 THEN (5000 + channel * 5) * 1000000.0
        ELSE 0
    END AS freq_hz,
    signal_dbm AS power_dbm,
    'wifi' AS signal_class,
    node_id,
    COALESCE(channel_width, 20) * 1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    CASE WHEN noise_dbm IS NOT NULL AND noise_dbm != 0
        THEN signal_dbm - noise_dbm ELSE NULL END AS snr_db
FROM wifi_metadata
WHERE signal_dbm IS NOT NULL

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel > 0 AND channel <= 39 THEN (2402 + channel * 2) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    CASE
        WHEN device_type = 'ble' THEN 'bluetooth-le'
        ELSE 'bluetooth-classic'
    END AS signal_class,
    node_id,
    1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM bt_devices

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 11 AND channel <= 26 THEN (2405 + (channel - 11) * 5) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    'zigbee' AS signal_class,
    node_id,
    2000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM zigbee_devices;
""",
    ),
    (
        43,
        "rebuild wifi_metadata and detection_feedback without FK constraints",
        """
-- SQLite cannot ALTER TABLE DROP FOREIGN KEY, so rebuild both tables.
-- Must drop dependent views first (spectrum_all references wifi_metadata).

DROP VIEW IF EXISTS spectrum_all;

-- 1. wifi_metadata
ALTER TABLE wifi_metadata RENAME TO _wifi_metadata_old;

CREATE TABLE wifi_metadata (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id  TEXT NOT NULL,
    bssid         TEXT NOT NULL DEFAULT '',
    ssid          TEXT NOT NULL DEFAULT '',
    channel       INTEGER DEFAULT 0,
    channel_width INTEGER DEFAULT 20,
    band          TEXT DEFAULT '2.4GHz',
    security      TEXT DEFAULT '',
    signal_dbm    REAL DEFAULT 0.0,
    noise_dbm     REAL DEFAULT 0.0,
    frame_type    TEXT DEFAULT '',
    client_mac    TEXT DEFAULT '',
    data_rate_mbps REAL DEFAULT 0.0,
    retry_flag    INTEGER DEFAULT 0,
    timestamp     TEXT NOT NULL,
    node_id       TEXT NOT NULL DEFAULT '',
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    vendor        TEXT NOT NULL DEFAULT '',
    client_vendor TEXT NOT NULL DEFAULT ''
);

INSERT INTO wifi_metadata (
    id, detection_id, bssid, ssid, channel, channel_width,
    band, security, signal_dbm, noise_dbm, frame_type,
    client_mac, data_rate_mbps, retry_flag, timestamp, node_id,
    tenant_id, vendor, client_vendor
)
SELECT
    id, detection_id, bssid, ssid, channel, channel_width,
    band, security, signal_dbm, noise_dbm, frame_type,
    client_mac, data_rate_mbps, retry_flag, timestamp, node_id,
    COALESCE(tenant_id, 'default'),
    COALESCE(vendor, ''),
    COALESCE(client_vendor, '')
FROM _wifi_metadata_old;
DROP TABLE _wifi_metadata_old;

CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_metadata (bssid);
CREATE INDEX IF NOT EXISTS idx_wifi_channel ON wifi_metadata (channel);
CREATE INDEX IF NOT EXISTS idx_wifi_timestamp ON wifi_metadata (timestamp);
CREATE INDEX IF NOT EXISTS idx_wifi_detection ON wifi_metadata (detection_id);
CREATE INDEX IF NOT EXISTS idx_wifi_band_channel ON wifi_metadata (band, channel);
CREATE INDEX IF NOT EXISTS idx_wifi_node_id ON wifi_metadata (node_id);

-- 2. detection_feedback
ALTER TABLE detection_feedback RENAME TO _detection_feedback_old;

CREATE TABLE detection_feedback (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_id   TEXT NOT NULL,
    label          TEXT NOT NULL,
    note           TEXT DEFAULT '',
    created_at     TEXT NOT NULL,
    tenant_id      TEXT NOT NULL DEFAULT 'default'
);

INSERT INTO detection_feedback (id, detection_id, label, note, created_at, tenant_id)
SELECT id, detection_id, label, note, created_at, COALESCE(tenant_id, 'default')
FROM _detection_feedback_old;
DROP TABLE _detection_feedback_old;

CREATE INDEX IF NOT EXISTS idx_feedback_detection
    ON detection_feedback (detection_id);

-- Recreate spectrum_all view (was dropped at start of this migration)
CREATE VIEW spectrum_all AS
SELECT
    timestamp, freq_hz, power_dbm, signal_class, node_id,
    bandwidth_hz, confidence, tenant_id, anomaly_score, snr_db
FROM detections
WHERE freq_hz > 0

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 1 AND channel <= 13 THEN (2407 + channel * 5) * 1000000.0
        WHEN channel = 14 THEN 2484000000.0
        WHEN channel >= 32 THEN (5000 + channel * 5) * 1000000.0
        ELSE 0
    END AS freq_hz,
    signal_dbm AS power_dbm,
    'wifi' AS signal_class,
    node_id,
    COALESCE(channel_width, 20) * 1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    CASE WHEN noise_dbm IS NOT NULL AND noise_dbm != 0
        THEN signal_dbm - noise_dbm ELSE NULL END AS snr_db
FROM wifi_metadata
WHERE signal_dbm IS NOT NULL

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel > 0 AND channel <= 39 THEN (2402 + channel * 2) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    CASE
        WHEN device_type = 'ble' THEN 'bluetooth-le'
        ELSE 'bluetooth-classic'
    END AS signal_class,
    node_id,
    1000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM bt_devices

UNION ALL

SELECT
    timestamp,
    CASE
        WHEN channel >= 11 AND channel <= 26 THEN (2405 + (channel - 11) * 5) * 1000000.0
        ELSE 2440000000.0
    END AS freq_hz,
    rssi_dbm AS power_dbm,
    'zigbee' AS signal_class,
    node_id,
    2000000.0 AS bandwidth_hz,
    NULL AS confidence,
    tenant_id,
    NULL AS anomaly_score,
    NULL AS snr_db
FROM zigbee_devices;
""",
    ),
    (
        45,
        "threat signature fields on reference_signatures",
        """
-- Create table if fresh DB (normally created by SignatureLibraryStore._ensure_table)
CREATE TABLE IF NOT EXISTS reference_signatures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    signal_class TEXT NOT NULL,
    description TEXT DEFAULT '',
    center_freq_hz REAL,
    bandwidth_hz REAL,
    sample_rate_hz REAL,
    embedding BLOB,
    features_48dim BLOB,
    iq_file_path TEXT,
    iq_samples INTEGER,
    sigmf_metadata TEXT,
    tags TEXT DEFAULT '[]',
    source TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    threat_category TEXT DEFAULT '',
    threat_level TEXT DEFAULT '',
    freq_min_hz REAL,
    freq_max_hz REAL,
    burst_duration_ms REAL,
    burst_interval_ms REAL,
    power_min_dbm REAL,
    power_max_dbm REAL,
    active INTEGER DEFAULT 1,
    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
""",
    ),
    (
        46,
        "incident lifecycle management tables",
        """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id   TEXT PRIMARY KEY,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'warning',
    description   TEXT DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    node_id       TEXT DEFAULT '',
    freq_hz       REAL DEFAULT 0.0,
    signal_class  TEXT DEFAULT '',
    anomaly_score REAL DEFAULT 0.0,
    alert_id      TEXT DEFAULT '',
    assigned_to   TEXT DEFAULT '',
    resolution    TEXT DEFAULT '',
    resolution_note TEXT DEFAULT '',
    created_by    TEXT DEFAULT '',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    resolved_at   TEXT,
    tenant_id     TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_incidents_status
    ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status
    ON incidents (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_assigned
    ON incidents (assigned_to) WHERE assigned_to != '';
CREATE INDEX IF NOT EXISTS idx_incidents_created
    ON incidents (created_at);

CREATE TABLE IF NOT EXISTS incident_events (
    event_id      TEXT PRIMARY KEY,
    incident_id   TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    actor         TEXT DEFAULT '',
    detail        TEXT DEFAULT '',
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incident_events_incident
    ON incident_events (incident_id, created_at);

CREATE TABLE IF NOT EXISTS incident_detections (
    incident_id   TEXT NOT NULL,
    detection_id  TEXT NOT NULL,
    linked_at     TEXT NOT NULL,
    PRIMARY KEY (incident_id, detection_id)
);
CREATE INDEX IF NOT EXISTS idx_incident_detections_detection
    ON incident_detections (detection_id);
""",
    ),
    (
        47,
        "sweep session lifecycle tables",
        """
CREATE TABLE IF NOT EXISTS sweeps (
    sweep_id          TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    location          TEXT DEFAULT '',
    phase             TEXT NOT NULL DEFAULT 'pre_assessment',
    status            TEXT NOT NULL DEFAULT 'active',
    start_time        TEXT,
    end_time          TEXT,
    scope_description TEXT DEFAULT '',
    threat_profile    TEXT DEFAULT '',
    notes             TEXT DEFAULT '',
    created_by        TEXT DEFAULT '',
    tenant_id         TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_sweeps_phase
    ON sweeps (phase);
CREATE INDEX IF NOT EXISTS idx_sweeps_tenant
    ON sweeps (tenant_id, phase);

CREATE TABLE IF NOT EXISTS sweep_zones (
    zone_id        TEXT PRIMARY KEY,
    sweep_id       TEXT NOT NULL,
    zone_name      TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    entered_at     TEXT,
    cleared_at     TEXT,
    anomaly_count  INTEGER DEFAULT 0,
    flagged_reason TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sweep_zones_sweep
    ON sweep_zones (sweep_id);

CREATE TABLE IF NOT EXISTS sweep_detections (
    sweep_id     TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    zone_id      TEXT DEFAULT '',
    linked_at    TEXT NOT NULL,
    PRIMARY KEY (sweep_id, detection_id)
);

CREATE TABLE IF NOT EXISTS sweep_incidents (
    sweep_id    TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    zone_id     TEXT DEFAULT '',
    linked_at   TEXT NOT NULL,
    PRIMARY KEY (sweep_id, incident_id)
);
""",
    ),
    (
        48,
        "cross_correlations table for N-way source correlation engine",
        """
CREATE TABLE IF NOT EXISTS cross_correlations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_a        TEXT NOT NULL,
    source_a_id     TEXT DEFAULT '',
    source_b        TEXT NOT NULL DEFAULT '',
    source_b_id     TEXT DEFAULT '',
    freq_hz         REAL NOT NULL DEFAULT 0.0,
    time_delta_ms   REAL NOT NULL DEFAULT 0.0,
    correlation_type TEXT NOT NULL DEFAULT '',
    node_id         TEXT NOT NULL DEFAULT '',
    timestamp       TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_xcorr_node_ts
    ON cross_correlations (node_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_xcorr_type
    ON cross_correlations (correlation_type);
CREATE INDEX IF NOT EXISTS idx_xcorr_source_a
    ON cross_correlations (source_a, source_a_id);
CREATE INDEX IF NOT EXISTS idx_xcorr_tenant
    ON cross_correlations (tenant_id);
""",
    ),
    (
        49,
        "aircraft_tracks table for ADS-B and UAT position tracking",
        """
CREATE TABLE IF NOT EXISTS aircraft_tracks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    icao_address TEXT NOT NULL,
    callsign TEXT,
    source TEXT NOT NULL,
    lat REAL,
    lon REAL,
    altitude_ft REAL,
    velocity_kts REAL,
    heading_deg REAL,
    squawk TEXT,
    rssi_dbm REAL,
    node_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_aircraft_icao ON aircraft_tracks(icao_address, timestamp);
CREATE INDEX IF NOT EXISTS idx_aircraft_ts ON aircraft_tracks(timestamp);
""",
    ),
    (
        50,
        "mesh_nodes and mesh_messages tables for mesh network tracking",
        """
CREATE TABLE IF NOT EXISTS mesh_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,
    node_id_hex TEXT NOT NULL,
    long_name TEXT,
    short_name TEXT,
    hw_model TEXT,
    last_lat REAL,
    last_lon REAL,
    last_altitude REAL,
    last_rssi_dbm REAL,
    last_snr_db REAL,
    channel_hash INTEGER,
    encryption_status TEXT,
    packet_count INTEGER DEFAULT 0,
    sdr_node_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    UNIQUE(protocol, node_id_hex, sdr_node_id)
);
CREATE INDEX IF NOT EXISTS idx_mesh_nodes_protocol ON mesh_nodes(protocol);
CREATE INDEX IF NOT EXISTS idx_mesh_nodes_last_seen ON mesh_nodes(last_seen);

CREATE TABLE IF NOT EXISTS mesh_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol TEXT NOT NULL,
    source_node_id TEXT,
    dest_node_id TEXT,
    packet_id INTEGER,
    port_num INTEGER,
    hop_limit INTEGER,
    channel_hash INTEGER,
    encryption_status TEXT,
    decoded_text TEXT,
    decoded_position TEXT,
    raw_hex TEXT,
    sdr_node_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_mesh_messages_ts ON mesh_messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_mesh_messages_source ON mesh_messages(source_node_id);
""",
    ),
    (
        51,
        "crypto_keys table for protocol key management",
        """
CREATE TABLE IF NOT EXISTS crypto_keys (
    id TEXT PRIMARY KEY,
    protocol TEXT NOT NULL,
    key_name TEXT NOT NULL,
    key_data_encrypted BLOB NOT NULL,
    key_hash TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'aes-128-ctr',
    key_source TEXT NOT NULL DEFAULT 'manual',
    associated_source_id TEXT,
    notes TEXT DEFAULT '',
    created_by TEXT DEFAULT '',
    tenant_id TEXT NOT NULL DEFAULT 'default',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_crypto_key_protocol ON crypto_keys(protocol);
CREATE INDEX IF NOT EXISTS idx_crypto_key_hash ON crypto_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_crypto_key_active ON crypto_keys(revoked_at) WHERE revoked_at IS NULL;
""",
    ),
    (
        52,
        "summarization tables: detection_summaries_hourly, iq_capture_sessions, device_lifecycles_daily, fhss_event_summaries",
        """
CREATE TABLE IF NOT EXISTS detection_summaries_hourly (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hour            TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    signal_class    TEXT NOT NULL,
    family          TEXT NOT NULL DEFAULT '',
    freq_bin_hz     REAL NOT NULL DEFAULT 0.0,
    detection_count INTEGER NOT NULL DEFAULT 0,
    avg_confidence  REAL NOT NULL DEFAULT 0.0,
    min_confidence  REAL NOT NULL DEFAULT 0.0,
    max_confidence  REAL NOT NULL DEFAULT 0.0,
    avg_snr_db      REAL,
    avg_power_dbm   REAL,
    avg_anomaly     REAL NOT NULL DEFAULT 0.0,
    max_anomaly     REAL NOT NULL DEFAULT 0.0,
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_det_summary_unique
    ON detection_summaries_hourly (hour, node_id, signal_class, family, freq_bin_hz);
CREATE INDEX IF NOT EXISTS idx_det_summary_hour
    ON detection_summaries_hourly (hour);
CREATE INDEX IF NOT EXISTS idx_det_summary_node_ts
    ON detection_summaries_hourly (node_id, hour);

CREATE TABLE IF NOT EXISTS iq_capture_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE NOT NULL,
    node_id         TEXT NOT NULL,
    start_time      TEXT NOT NULL,
    end_time        TEXT NOT NULL,
    freq_min_hz     REAL NOT NULL DEFAULT 0.0,
    freq_max_hz     REAL NOT NULL DEFAULT 0.0,
    capture_count   INTEGER NOT NULL DEFAULT 0,
    anomaly_count   INTEGER NOT NULL DEFAULT 0,
    total_samples   INTEGER NOT NULL DEFAULT 0,
    total_size_bytes INTEGER NOT NULL DEFAULT 0,
    signal_classes  TEXT NOT NULL DEFAULT '[]',
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_iq_session_node
    ON iq_capture_sessions (node_id);
CREATE INDEX IF NOT EXISTS idx_iq_session_time
    ON iq_capture_sessions (start_time);

CREATE TABLE IF NOT EXISTS device_lifecycles_daily (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    date            TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    device_type     TEXT NOT NULL DEFAULT 'bt',
    device_id       TEXT NOT NULL DEFAULT '',
    device_name     TEXT NOT NULL DEFAULT '',
    manufacturer    TEXT NOT NULL DEFAULT '',
    discovery_count INTEGER NOT NULL DEFAULT 0,
    avg_signal_dbm  REAL DEFAULT 0.0,
    min_signal_dbm  REAL DEFAULT 0.0,
    max_signal_dbm  REAL DEFAULT 0.0,
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT 'active',
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_device_lifecycle_unique
    ON device_lifecycles_daily (date, node_id, device_type, device_id);
CREATE INDEX IF NOT EXISTS idx_device_lifecycle_date
    ON device_lifecycles_daily (date);

CREATE TABLE IF NOT EXISTS fhss_event_summaries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start    TEXT NOT NULL,
    node_id         TEXT NOT NULL DEFAULT '',
    hop_rate_hz     REAL NOT NULL DEFAULT 0.0,
    hop_set_hash    TEXT NOT NULL DEFAULT '',
    bandwidth_hz    REAL NOT NULL DEFAULT 0.0,
    signal_class    TEXT NOT NULL DEFAULT '',
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    avg_confidence  REAL NOT NULL DEFAULT 0.0,
    max_confidence  REAL NOT NULL DEFAULT 0.0,
    avg_dwell_time_ms REAL NOT NULL DEFAULT 0.0,
    total_duration_sec REAL NOT NULL DEFAULT 0.0,
    first_seen      TEXT NOT NULL DEFAULT '',
    last_seen       TEXT NOT NULL DEFAULT '',
    tenant_id       TEXT NOT NULL DEFAULT 'default'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fhss_summary_unique
    ON fhss_event_summaries (window_start, node_id, hop_set_hash, signal_class);
CREATE INDEX IF NOT EXISTS idx_fhss_summary_time
    ON fhss_event_summaries (window_start);
""",
    ),
    # Migrations 53-55: composite (node_id, timestamp) indexes for the
    # cross-correlator's _query_nearby_detections. detections already
    # has idx_detections_node_timestamp, but wifi_metadata / bt_devices
    # / zigbee_devices only had single-column indexes — the correlator's
    # SQL was forced into table scans per query (one per event per
    # other-source), pegging an executor thread on staging.
    #
    # Split one-index-per-migration so the WAL gets a TRUNCATE checkpoint
    # between each. The original combined version OOM'd a staging Pi 5
    # with a 7 GB detections.db — three concurrent index builds in a
    # single transaction grew the WAL to ~7 GB before the bridge process
    # was killed by docker's healthcheck timeout.
    (
        53,
        "composite (node_id, timestamp) on wifi_metadata for xcorr hot path",
        "CREATE INDEX IF NOT EXISTS idx_wifi_node_timestamp "
        "ON wifi_metadata (node_id, timestamp);",
    ),
    (
        54,
        "composite (node_id, timestamp) on bt_devices for xcorr hot path",
        "CREATE INDEX IF NOT EXISTS idx_bt_node_timestamp "
        "ON bt_devices (node_id, timestamp);",
    ),
    (
        55,
        "composite (node_id, timestamp) on zigbee_devices for xcorr hot path",
        "CREATE INDEX IF NOT EXISTS idx_zb_node_timestamp "
        "ON zigbee_devices (node_id, timestamp);",
    ),
    (
        56,
        "versioned RF summary components and immutable legacy bases",
        """
CREATE TABLE rf_summary_streams (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    PRIMARY KEY(tenant_id,node_id)
);
CREATE TABLE rf_summary_generations (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    hour TEXT NOT NULL,
    generation INTEGER NOT NULL,
    digest TEXT NOT NULL,
    payload BLOB NOT NULL,
    retired INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(tenant_id,node_id,hour)
);
CREATE TABLE rf_summary_components (
    tenant_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    stream_id TEXT NOT NULL,
    component TEXT NOT NULL CHECK(component IN ('stream_summary','raw_rollup')),
    hour TEXT NOT NULL,
    signal_class TEXT NOT NULL,
    family TEXT NOT NULL,
    freq_bin_hz REAL NOT NULL,
    detection_count INTEGER NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY(tenant_id,node_id,component,stream_id,hour,signal_class,family,freq_bin_hz)
);
CREATE INDEX idx_rf_summary_component_node_time ON rf_summary_components(node_id,tenant_id,hour);
DROP INDEX idx_det_summary_unique;
CREATE UNIQUE INDEX idx_det_summary_unique ON detection_summaries_hourly(tenant_id,hour,node_id,signal_class,family,freq_bin_hz);
CREATE TRIGGER rf_summary_legacy_insert BEFORE INSERT ON detection_summaries_hourly
WHEN EXISTS(SELECT 1 FROM rf_summary_streams WHERE tenant_id=NEW.tenant_id AND node_id=NEW.node_id)
BEGIN SELECT RAISE(ABORT,'versioned RF summary node rejects legacy writes'); END;
CREATE TRIGGER rf_summary_legacy_update BEFORE UPDATE ON detection_summaries_hourly
WHEN EXISTS(SELECT 1 FROM rf_summary_streams WHERE (tenant_id=OLD.tenant_id AND node_id=OLD.node_id) OR (tenant_id=NEW.tenant_id AND node_id=NEW.node_id))
BEGIN SELECT RAISE(ABORT,'versioned RF summary base is immutable'); END;
""",
    ),
]


# ---------------------------------------------------------------------------
# Transactions — commit on success, roll back on any exception
# ---------------------------------------------------------------------------

# Per-thread nesting depth of ``sqlite_transaction`` blocks, keyed by
# ``id(conn)``.  Connections are thread-local (``SharedContext.get_conn``)
# and outlive every block that uses them, so the id is stable for the
# block's lifetime.
_tx_state = threading.local()


def _rollback_quietly(conn: sqlite3.Connection) -> None:
    """Roll back *conn*'s open transaction, logging (not raising) failures.

    Used on the error path, where the original exception must propagate
    unchanged even if the rollback itself fails (e.g. closed connection).
    """
    try:
        if conn.in_transaction:
            conn.rollback()
    except sqlite3.Error as exc:
        logger.warning("Transaction rollback failed: %s", exc)


@contextlib.contextmanager
def sqlite_transaction(
    conn: sqlite3.Connection, *, immediate: bool = False
) -> Iterator[sqlite3.Connection]:
    """Run the enclosed statements on *conn* as one transaction.

    Commits when the block exits normally (including via ``return``) and
    rolls back when it raises — any exception, including the
    ``IntegrityError`` of a failed INSERT.  Without the rollback a failed
    statement leaves Python's implicit ``BEGIN`` open: the thread-local
    connection keeps holding the WAL write lock (other writers wait out
    ``busy_timeout``), and the next unrelated ``commit()`` on that thread
    would commit whatever half of the failed block had already run.

    The outermost block keeps sqlite3's lazy ``BEGIN`` (issued just before
    the first INSERT/UPDATE/DELETE), so lock acquisition is unchanged
    from the previous ``execute(...); commit()`` pattern.  Pass
    ``immediate=True`` when the block reads something it then writes
    based on (read-then-insert, e.g. the audit HMAC chain head): it issues
    ``BEGIN IMMEDIATE`` up front, so the write lock — which also excludes
    other processes such as the Rust gateway — is held from the read
    onwards.  With the lazy ``BEGIN`` that leading SELECT runs outside any
    transaction, and another process can commit between it and the write.

    Blocks nest: an inner block on the same connection runs inside a
    ``SAVEPOINT`` so that, if its exception is caught by the outer block,
    only the inner block's writes are undone; the outer block still
    commits or rolls back as a whole.  Code inside a block must not call
    ``conn.commit()`` / ``conn.rollback()`` itself, and should not call
    ``executescript()`` after it has written (``executescript`` COMMITs a
    pending transaction first).
    """
    depths: dict[int, int] = _tx_state.__dict__.setdefault("depths", {})
    key = id(conn)
    depth = depths.get(key, 0)
    depths[key] = depth + 1
    try:
        if depth == 0:
            try:
                if immediate and not conn.in_transaction:
                    conn.execute("BEGIN IMMEDIATE")
                yield conn
                conn.commit()
            except BaseException:
                _rollback_quietly(conn)
                raise
        else:
            if not conn.in_transaction:
                # The outer block has not written yet.  Open its
                # transaction now (taking the write lock up front, with
                # busy_timeout) so the savepoint nests inside it and its
                # RELEASE does not commit on its own.
                conn.execute("BEGIN IMMEDIATE")
            savepoint = f"sigrift_tx_{depth}"
            conn.execute(f"SAVEPOINT {savepoint}")
            try:
                yield conn
            except BaseException:
                if conn.in_transaction:
                    try:
                        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
                    except sqlite3.Error as exc:
                        logger.warning(
                            "Rollback to savepoint %s failed: %s", savepoint, exc
                        )
                raise
            if conn.in_transaction:
                conn.execute(f"RELEASE SAVEPOINT {savepoint}")
    finally:
        if depth == 0:
            depths.pop(key, None)
        else:
            depths[key] = depth


# ---------------------------------------------------------------------------
# SharedContext — threaded connection + write lock + cache
# ---------------------------------------------------------------------------


def _file_size(path: str | Path) -> int:
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0


def _live_db_bytes(db_path: Path) -> int:
    """Size of the database and its WAL: what a copy of it needs."""
    return _file_size(db_path) + _file_size(str(db_path) + "-wal")


def allow_migration_without_backup() -> bool:
    """True when BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP disables the copy guard.

    ``/api/health`` warns while it is set, and the lifespan logs it at every
    start: it is meant for one upgrade only.
    """
    value = os.environ.get(_ALLOW_MIGRATION_WITHOUT_BACKUP_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "enabled")


_allow_migration_without_backup = allow_migration_without_backup


def _copy_space_problem(db_path: Path) -> OSError | None:
    """An ENOSPC error when the pre-migration copy cannot fit, else None.

    Checked before anything is written.  The copy needs about the database
    and its WAL, plus max(64 MiB, 2%) for SQLite's own overhead.  When the
    free space cannot be read the copy is simply tried.
    """
    need = _live_db_bytes(db_path)
    try:
        free = _disk_usage(db_path.parent).free
    except OSError:
        return None
    margin = max(_COPY_MIN_MARGIN_BYTES, need // 50)
    if free < need + margin:
        return OSError(
            errno.ENOSPC,
            f"not enough free space for the copy (it needs about "
            f"{(need + margin) / 1e6:.0f} MB; nothing was written)",
        )
    return None


def _pre_migration_failure_message(
    exc: BaseException, db_path: Path, pending: int
) -> str:
    """The CRITICAL line for a pre-migration copy that could not be made."""
    try:
        free = f"{_disk_usage(db_path.parent).free / 1e6:.0f} MB are free there"
    except OSError:
        free = "the free space there could not be read"
    message = (
        f"Pre-migration backup failed: {exc}. Refusing to apply {pending} "
        f"pending migration(s) to {db_path} without a recovery copy: the copy "
        f"needs about {_live_db_bytes(db_path) / 1e6:.0f} MB next to the "
        f"database and {free}. Free space in the volume and restart the bridge, "
        f"or set {_ALLOW_MIGRATION_WITHOUT_BACKUP_ENV}=1 in the bridge's "
        "environment to migrate without it (only with a backup of your own; "
        "remove it afterwards): in .env for a docker-compose.yml that passes "
        "it to the bridge; a release install generated before v0.2.0 also "
        "needs it in docker-compose.override.yml, under services: bridge: "
        "environment:."
    )
    previous = Path(str(db_path) + ".pre-migration")
    try:
        st = previous.stat()
    except OSError:
        return message
    made = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M")
    return message + (
        f" A copy from an earlier run is still there: {previous} "
        f"({st.st_size / 1e6:.0f} MB, made {made} UTC); if the upgrade that "
        "made it went well, delete it and restart."
    )


def _keep_pre_migration_copy(db_path: Path, had_migrations: bool) -> tuple[bool, str]:
    """Whether to keep a successful run's ``.pre-migration`` copy, and why not.

    *had_migrations*: the database had applied migrations before this run
    (an upgrade, not a new database).  The copy is already on disk, so the
    free space read here is what stays free if it is kept.
    """
    if not had_migrations:
        return False, "a new database: nothing to keep"
    try:
        usage = _disk_usage(db_path.parent)
    except OSError as exc:
        return False, f"the free space could not be read ({exc})"
    need = max(_KEEP_MIN_FREE_BYTES, _live_db_bytes(db_path))
    if usage.free < need:
        return False, (
            f"only {usage.free / 1e9:.1f} GB would stay free; it is kept only "
            f"while at least {need / 1e9:.1f} GB (1 GB, or the database's size "
            "if larger) stay free"
        )
    if usage.total and usage.used / usage.total >= _KEEP_MAX_USED_FRACTION:
        return False, (
            f"the disk would be {100 * usage.used / usage.total:.0f}% used; it "
            f"is kept only below {_KEEP_MAX_USED_FRACTION:.0%}"
        )
    return True, ""


def _refuse_newer_schema(conn: sqlite3.Connection) -> None:
    """Refuse a database that a newer build has already migrated (PRE-68).

    ``_run_migrations`` only applies pending migrations, so without this an
    older build rolled back onto live volumes would run against a schema it
    does not understand (for example RF summary streams and fences). Runs
    before the base schema and any migration. Connection setup (WAL mode)
    and optional at-rest encryption have already run by then; they do not
    change the schema. Versions at or below the newest known migration are
    accepted, including historical gaps. Only a missing ``schema_version``
    table means a fresh database; any other error (locked, damaged, an
    unexpected table shape) propagates, so startup fails closed.
    """
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if exists is None:
        return  # fresh database
    rows = conn.execute("SELECT version FROM schema_version").fetchall()
    newest_known = max(version for version, _, _ in _MIGRATIONS)
    newer = sorted(r[0] for r in rows if r[0] > newest_known)
    if newer:
        logger.critical(
            "Database schema has migrations %s newer than this build (newest %d)",
            newer,
            newest_known,
        )
        raise RuntimeError(
            f"Database schema has migrations {newer} newer than this build "
            f"(newest known {newest_known}); refusing to start. Run the newer "
            "build or repair forward. A full pre-upgrade restore is safe only "
            "when no RF summary stream, generation or component exists; see "
            "src/sigrift/bridge/UPGRADE.md (rollback) and "
            "docs/rf-summary-recovery.md ('Downgrade restriction')."
        )


class SharedContext:
    """Shared infrastructure passed to every sub-store.

    Encapsulates the database path, thread-local connections,
    serialised write lock, and TTL cache.

    Parameters
    ----------
    db_path : str or Path or None
        Path to the SQLite database file.  Parent directories are
        created if they do not exist.  Defaults to
        ``sigrift/bridge/data/detections.db``.
    """

    def __init__(
        self,
        db_path: str | Path | None = None,
        tenant_id: str = "default",
    ) -> None:
        self._db_path = str(db_path or _DEFAULT_DB_PATH)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.Lock()
        self._local = threading.local()
        self._cache = PartitionedCache()
        self.tenant_id: str = tenant_id
        self._integrity_checked = False
        # Registry of all thread-local connections for clean shutdown:
        # connection -> the thread that opened (and alone uses) it.
        self._conn_registry: dict[sqlite3.Connection, threading.Thread] = {}
        self._conn_registry_lock = threading.Lock()
        # Bumped by close(): a thread whose connection belongs to an older
        # generation closes it itself (close() leaves live threads'
        # connections alone) and opens a fresh one.
        self._conn_generation = 0
        self._row_limit = int(os.environ.get("BRIDGE_TENANT_ROW_LIMIT", "0"))
        self._init_db()

    # -- Connection management ----------------------------------------------

    def get_conn(self) -> sqlite3.Connection:
        """Return a thread-local connection with WAL mode and row factory.

        When ``BRIDGE_DB_ENCRYPTION_KEY`` is set and ``pysqlcipher3`` is
        installed, connections are transparently encrypted via SQLCipher.
        Otherwise falls back to plain sqlite3.
        """
        conn = getattr(self._local, "conn", None)
        if conn is not None and self._local.generation != self._conn_generation:
            # close() ran since this connection was opened.  It closes only
            # connections no thread can be using (see close()); this one
            # belongs to the calling thread, so close it here and open a
            # fresh one — unless a transaction of this thread is still open
            # on it (a nested call), which must finish on the same
            # connection; it is retired on a later call.
            if conn.in_transaction:
                return conn
            self._retire_own_connection(conn)
            conn = None
        if conn is None:
            from sigrift.bridge.storage.encryption import open_db

            # check_same_thread=False only so close() can close this
            # connection once its thread has exited (sqlite3 otherwise
            # refuses with ProgrammingError and the connection leaks).  It
            # is never used by any other thread: it lives in self._local.
            conn = open_db(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            # DB-C5: FK enforcement enabled.  Migration 42 removed the
            # problematic FK constraints on wifi_metadata and
            # detection_feedback (detection_id is standalone in async
            # pipelines).  Remaining FKs (sessions→users,
            # mfa_backup_codes→users, mfa_tokens→users) are valid.
            # busy_timeout MUST be set before journal_mode=WAL. Switching
            # to WAL takes a brief exclusive lock; under uvicorn
            # --workers 2 both workers init their connections at startup
            # and race for it. Without busy_timeout already in effect, the
            # losing worker gets an immediate "database is locked" instead
            # of waiting — its lifespan crashes, so its background tasks
            # (WAL checkpoint, materializer, ...) never start. That left a
            # staging WAL to grow to 21 GB (2026-06-06 incident): no
            # checkpoint ever ran because the lifespan died here first.
            conn.execute("PRAGMA busy_timeout=30000")  # 30s wait before SQLITE_BUSY
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, faster than FULL
            _cache_sz = int(os.environ.get("BRIDGE_SQLITE_CACHE_SIZE", "-64000"))
            conn.execute(f"PRAGMA cache_size={_cache_sz}")
            _mmap_sz = int(os.environ.get("BRIDGE_SQLITE_MMAP_SIZE", "268435456"))
            conn.execute(f"PRAGMA mmap_size={_mmap_sz}")
            conn.execute("PRAGMA temp_store=MEMORY")  # temp tables in RAM
            # Tight autocheckpoint so the WAL trends to ~0 between bursts.
            # ~800 KB per fire — cheap; the alternative is letting WAL stay
            # at its high-water mark, which is what tripped the bridge
            # earlier on a 7 GB DB when an index-building migration ran.
            conn.execute("PRAGMA wal_autocheckpoint=200")
            conn.execute("PRAGMA journal_size_limit=67108864")  # 64 MB WAL size limit
            with self._conn_registry_lock:
                self._local.conn = conn
                self._local.generation = self._conn_generation
                self._conn_registry[conn] = threading.current_thread()
        return conn

    def _retire_own_connection(self, conn: sqlite3.Connection) -> None:
        """Close the calling thread's stale connection and forget it."""
        self._local.conn = None
        with self._conn_registry_lock:
            registered = self._conn_registry.pop(conn, None) is not None
        if not registered:
            return  # close() already closed it (its thread had exited)
        try:
            conn.close()
        except Exception as exc:
            logger.warning("SharedContext: failed to close stale connection: %s", exc)

    @property
    def is_encrypted(self) -> bool:
        """Whether the database is using SQLCipher encryption."""
        from sigrift.bridge.storage.encryption import encryption_status

        return encryption_status()["enabled"]

    def _maybe_encrypt_existing_db(self) -> None:
        """If encryption key is set and DB exists as plaintext, encrypt it."""
        from sigrift.bridge.storage.encryption import (
            _resolve_encryption_key,
            encrypt_existing_db,
            is_plaintext_db,
            _HAS_SQLCIPHER,
        )

        key = _resolve_encryption_key()
        if not key or not _HAS_SQLCIPHER:
            return
        db_path = Path(self._db_path)
        if not db_path.exists():
            return  # New DB — will be created encrypted
        if is_plaintext_db(db_path):
            logger.warning(
                "Plaintext database detected with encryption key configured. "
                "Migrating %s to SQLCipher.",
                db_path,
            )
            encrypt_existing_db(db_path, key)

    def _init_db(self) -> None:
        """Create tables/indices, run integrity check, and apply migrations."""
        # Sweep stale migration carcasses before anything else — failed
        # migration runs in the past left .pre-migration and
        # .failed-migration-* files that can total tens of GB on a
        # production-sized volume. Anything older than 7 days has no
        # forensic value; the current run's .pre-migration is created
        # fresh further down (in _run_migrations) so it's safe to delete
        # older copies here. A copy kept after a successful upgrade is
        # swept the same way: here and on every periodic cleanup
        # (app.py _periodic_cleanup), 7 days after it was made.
        self._cleanup_orphan_migration_files()
        # Auto-encrypt existing plaintext DB if encryption key is configured
        self._maybe_encrypt_existing_db()
        conn = self.get_conn()
        # DB-P11: Integrity check — fast path for large DBs, full check in background
        if not self._integrity_checked:
            self._integrity_checked = True
            db_size = (
                Path(self._db_path).stat().st_size
                if Path(self._db_path).exists()
                else 0
            )
            skip = os.environ.get("BRIDGE_SKIP_INTEGRITY_CHECK", "").lower() in (
                "1",
                "true",
                "yes",
                "enabled",
            )
            self._integrity_status = {
                "state": "pending",
                "db_size_mb": round(db_size / 1e6, 1),
            }
            if skip:
                logger.info("Integrity check skipped (BRIDGE_SKIP_INTEGRITY_CHECK)")
                self._integrity_status = {
                    "state": "skipped",
                    "db_size_mb": round(db_size / 1e6, 1),
                }
            elif db_size > 500_000_000:  # >500 MB: defer to background
                logger.info(
                    "Database is %.0f MB — deferring integrity check to background",
                    db_size / 1e6,
                )
                self._integrity_status = {
                    "state": "running",
                    "db_size_mb": round(db_size / 1e6, 1),
                    "started_at": time.time(),
                }
                import threading

                def _bg_check():
                    try:
                        bg_conn = sqlite3.connect(self._db_path)
                        # Same ordering rule as get_conn: busy_timeout first
                        # so the journal_mode switch waits for a concurrent
                        # worker's lock instead of raising immediately.
                        bg_conn.execute("PRAGMA busy_timeout=30000")
                        bg_conn.execute("PRAGMA journal_mode=WAL")
                        result = bg_conn.execute("PRAGMA quick_check").fetchone()
                        bg_conn.close()
                        elapsed = time.time() - self._integrity_status["started_at"]
                        if result[0] != "ok":
                            logger.critical(
                                "Background integrity check FAILED: %s", result[0]
                            )
                            self._integrity_status["state"] = "failed"
                            self._integrity_status["error"] = result[0]
                        else:
                            logger.info(
                                "Background integrity check passed (%.0f MB, %.0fs)",
                                db_size / 1e6,
                                elapsed,
                            )
                            self._integrity_status["state"] = "passed"
                        self._integrity_status["elapsed_s"] = round(elapsed, 1)
                    except Exception as exc:
                        logger.error("Background integrity check error: %s", exc)
                        self._integrity_status["state"] = "error"
                        self._integrity_status["error"] = str(exc)

                threading.Thread(target=_bg_check, daemon=True).start()
            else:
                result = conn.execute("PRAGMA quick_check").fetchone()
                if result[0] != "ok":
                    logger.critical(
                        "Database integrity check FAILED for %s: %s",
                        self._db_path,
                        result[0],
                    )
                    self._integrity_status = {"state": "failed", "error": result[0]}
                    raise sqlite3.DatabaseError(
                        f"Database corruption detected: {result[0]}"
                    )
                self._integrity_status = {
                    "state": "passed",
                    "db_size_mb": round(db_size / 1e6, 1),
                }
                logger.info("Database integrity check passed: %s", self._db_path)
        # Not a sqlite_transaction block: executescript() and each migration
        # commit on their own (executescript always COMMITs a pending
        # transaction first).  Still roll back whatever a failure left open
        # so the thread-local connection does not keep the write lock.
        try:
            _refuse_newer_schema(conn)
            conn.executescript(_SCHEMA)
            self._run_migrations(conn)
            conn.commit()
        except BaseException:
            _rollback_quietly(conn)
            raise
        logger.info("DetectionStore initialised: %s", self._db_path)

    def _run_migrations(self, conn: sqlite3.Connection) -> None:
        """Apply any unapplied numbered migrations from ``_MIGRATIONS``.

        P2-14: Creates a .pre-migration backup before applying pending
        migrations, and raises RuntimeError on any migration failure
        instead of silently skipping.  A backup that cannot be made stops
        the run before any migration (RuntimeError) unless
        BRIDGE_ALLOW_MIGRATION_WITHOUT_BACKUP is set; after a successful
        upgrade the backup is kept for the 7-day sweep while space allows
        (see ``_keep_pre_migration_copy``).
        """
        try:
            rows = conn.execute("SELECT version FROM schema_version").fetchall()
            applied = {r[0] for r in rows}
        except sqlite3.OperationalError:
            applied = set()

        pending = [(v, d, s) for v, d, s in _MIGRATIONS if v not in applied]
        if not pending:
            return

        # Refuse to apply migrations on a corrupt DB. A crashed migration
        # earlier today (2026-06-02 incident) left the live DB structurally
        # damaged on wifi_metadata — bridge ran fine for hours on the old
        # image because it never full-scanned that table, but the next
        # migration's CREATE INDEX walked into the damage and crashed
        # mid-run with a multi-GB WAL. quick_check is seconds even on a
        # 7 GB DB; preferable to discovering corruption inside a migration.
        # Skip via BRIDGE_SKIP_INTEGRITY_CHECK for the rare case where
        # an operator has decided the risk is acceptable.
        skip_check = os.environ.get("BRIDGE_SKIP_INTEGRITY_CHECK", "").lower() in (
            "1",
            "true",
            "yes",
            "enabled",
        )
        if not skip_check and str(self._db_path) != ":memory:":
            try:
                check_result = conn.execute("PRAGMA quick_check").fetchone()
            except sqlite3.OperationalError as exc:
                check_result = (str(exc),)
            if check_result[0] != "ok":
                self._integrity_status = {
                    "state": "failed",
                    "error": check_result[0],
                    "blocked_migrations": [v for v, _, _ in pending],
                }
                logger.critical(
                    "Database integrity check FAILED for %s before migrations: %s",
                    self._db_path,
                    check_result[0],
                )
                logger.critical(
                    "Refusing to apply %d pending migrations on a corrupt DB. "
                    "Recovery options: "
                    "(1) `sqlite3 %s .recover | sqlite3 %s.recovered`, then "
                    "    `mv %s.recovered %s`; "
                    "(2) restore from .pre-migration if present; "
                    "(3) BRIDGE_SKIP_INTEGRITY_CHECK=1 to bypass (not recommended).",
                    len(pending),
                    self._db_path,
                    self._db_path,
                    self._db_path,
                    self._db_path,
                )
                raise RuntimeError(
                    f"Refusing to apply migrations on corrupt DB: {check_result[0]}"
                )

        # Pre-migration backup (skip for :memory: DBs). Use SQLite's online
        # backup API: a raw file copy misses committed WAL pages, and closing
        # its file descriptor drops this process's POSIX locks on the live
        # DB. A gateway restart could then unlink its WAL while the bridge
        # still uses it, making new gateway writes invisible to the bridge.
        # Publish the complete snapshot atomically, retaining any prior
        # recovery backup if creating its replacement fails.
        db_str = str(self._db_path)
        backup_path = db_str + ".pre-migration"
        backup_created = False
        allow_without_backup = _allow_migration_without_backup()
        snapshot_wanted = db_str != ":memory:" and Path(db_str).exists()
        backup = getattr(conn, "backup", None)
        if snapshot_wanted and not callable(backup):
            if not allow_without_backup:
                raise RuntimeError(
                    "Database driver lacks the online backup API; refusing "
                    "migrations without a consistent recovery snapshot"
                )
            logger.warning(
                "Database driver lacks the online backup API — applying %d "
                "pending migration(s) WITHOUT a recovery copy because %s is set",
                len(pending),
                _ALLOW_MIGRATION_WITHOUT_BACKUP_ENV,
            )
        elif snapshot_wanted:
            snapshot_path = None
            backup_error: BaseException | None = None
            try:
                # The space first: a copy that cannot fit would fill the
                # volume before it failed, and Compose restarts a bridge
                # that refused, so it would do so again at every start.
                space_problem = _copy_space_problem(Path(db_str))
                if space_problem is not None:
                    raise space_problem
                # mkstemp creates a private file before any database pages
                # are written. Its descriptor is closed before SQLite opens
                # this separate destination, never the live source file.
                fd, snapshot_path = tempfile.mkstemp(
                    prefix=Path(backup_path).name + ".", dir=Path(db_str).parent
                )
                os.close(fd)
                from sigrift.bridge.storage.encryption import open_db

                snapshot = open_db(snapshot_path)
                try:
                    # _init_db's executescript committed before this call;
                    # backup() includes every committed WAL page as well.
                    backup(snapshot)
                finally:
                    snapshot.close()
                os.chmod(snapshot_path, stat.S_IMODE(Path(db_str).stat().st_mode))
                os.replace(snapshot_path, backup_path)
                backup_created = True
                logger.info("Pre-migration backup created: %s", backup_path)
            except (OSError, sqlite3.Error) as exc:
                backup_error = exc
            finally:
                if snapshot_path is not None:
                    Path(snapshot_path).unlink(missing_ok=True)
            if backup_error is not None and allow_without_backup:
                logger.warning(
                    "Pre-migration backup failed: %s — applying %d pending "
                    "migration(s) WITHOUT a recovery copy because %s is set",
                    backup_error,
                    len(pending),
                    _ALLOW_MIGRATION_WITHOUT_BACKUP_ENV,
                )
            elif backup_error is not None:
                logger.critical(
                    "%s",
                    _pre_migration_failure_message(
                        backup_error, Path(db_str), len(pending)
                    ),
                )
                raise RuntimeError(
                    f"Pre-migration backup failed ({backup_error}); refusing to "
                    "migrate without it "
                    f"({_ALLOW_MIGRATION_WITHOUT_BACKUP_ENV}=1 overrides)"
                ) from backup_error

        for version, description, sql in pending:
            try:
                # Temporarily disable FK checks during migrations — table
                # recreation patterns (DROP + ALTER RENAME) can trigger
                # spurious FK/view validation errors in executescript.
                conn.execute("PRAGMA foreign_keys=OFF")
                if "\n" in sql.strip() and ";" in sql:
                    conn.executescript(sql)
                else:
                    conn.execute(sql)
                conn.execute("PRAGMA foreign_keys=ON")
                conn.execute(
                    "INSERT OR IGNORE INTO schema_version (version, description, applied_at) "
                    "VALUES (?, ?, ?)",
                    (version, description, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
                logger.info("Migration %d applied: %s", version, description)
                # Force a TRUNCATE checkpoint between migrations so the WAL
                # doesn't carry into the next one's transaction. Without this,
                # a sequence of large index-building migrations layers a
                # multi-GB WAL on top of itself and OOMs the host before any
                # individual migration commits. wal_autocheckpoint is too
                # coarse to fire mid-transaction.
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.OperationalError as ckpt_exc:
                    logger.warning(
                        "post-migration %d WAL checkpoint failed (continuing): %s",
                        version,
                        ckpt_exc,
                    )
            except sqlite3.OperationalError as exc:
                # Discard the failed migration's partial, uncommitted work
                # before either the fallback below or the re-raise.
                _rollback_quietly(conn)
                conn.execute("PRAGMA foreign_keys=ON")
                # For migration 45 specifically, handle existing table missing columns
                if version == 45 and "no such column" in str(exc):
                    logger.info(
                        "Migration 45: table exists, adding missing columns safely"
                    )
                    self._safe_add_columns(
                        conn,
                        "reference_signatures",
                        [
                            ("threat_category", "TEXT DEFAULT ''"),
                            ("threat_level", "TEXT DEFAULT ''"),
                            ("freq_min_hz", "REAL"),
                            ("freq_max_hz", "REAL"),
                            ("burst_duration_ms", "REAL"),
                            ("burst_interval_ms", "REAL"),
                            ("power_min_dbm", "REAL"),
                            ("power_max_dbm", "REAL"),
                            ("active", "INTEGER DEFAULT 1"),
                            ("created_by", "TEXT DEFAULT ''"),
                        ],
                    )
                    with sqlite_transaction(conn):
                        conn.execute(
                            "INSERT OR IGNORE INTO schema_version (version, description, applied_at) "
                            "VALUES (?, ?, ?)",
                            (
                                version,
                                description,
                                datetime.now(timezone.utc).isoformat(),
                            ),
                        )
                    logger.info(
                        "Migration %d applied (with ALTER TABLE fallback): %s",
                        version,
                        description,
                    )
                else:
                    raise RuntimeError(
                        f"Migration {version} ({description}) failed: {exc}"
                    ) from exc
            except BaseException:
                _rollback_quietly(conn)
                raise

        # All pending migrations applied successfully. After an upgrade the
        # copy is the database as it was just before them: keep it for the
        # 7-day sweep (a rollback point while the upgrade is verified) as
        # long as the volume has room (see _keep_pre_migration_copy: it is
        # about the database's size, 7+ GB on production volumes). A new
        # database, or too little space, removes it at once, as before.
        if backup_created:
            keep, reason = _keep_pre_migration_copy(
                Path(db_str), had_migrations=bool(applied)
            )
            if keep:
                logger.info(
                    "Pre-migration backup kept: %s (%.0f MB). It is removed "
                    "automatically 7 days after it was made; delete it yourself "
                    "once the upgrade is verified.",
                    backup_path,
                    _file_size(backup_path) / 1e6,
                )
            else:
                try:
                    Path(backup_path).unlink()
                    (logger.info if not applied else logger.warning)(
                        "Pre-migration backup removed after successful run: %s (%s)",
                        backup_path,
                        reason,
                    )
                except OSError as exc:
                    logger.warning("Pre-migration backup cleanup failed: %s", exc)

    def sweep_migration_leftovers(self) -> None:
        """The periodic sweep (app.py ``_periodic_cleanup``, every cycle).

        Like the startup sweep, and it also removes a kept
        ``.pre-migration`` copy before its 7 days are up once the volume no
        longer has room for it (``_keep_pre_migration_copy``).
        """
        self._cleanup_orphan_migration_files(recheck_space=True)

    def _cleanup_orphan_migration_files(
        self, max_age_days: int = 7, *, recheck_space: bool = False
    ) -> None:
        """Delete stale `<db>.pre-migration` and `<db>.failed-migration-*` files.

        These accumulate when migrations crash or get rolled back manually,
        and a successful upgrade keeps its `.pre-migration` copy on purpose
        (``_keep_pre_migration_copy``). Runs at startup (``_init_db``) and on
        every periodic cleanup (app.py), so a long-running bridge removes a
        kept copy too; its mtime is the time it was made.
        On a 7 GB production DB, each one is ~7 GB; without cleanup the
        volume bloats fast. Anything older than ``max_age_days`` is safe
        to remove — the live schema_version table tracks what applied.
        ``<db>.pre-migration.XXXXXX`` is a copy that was still being written
        when its process died (SIGKILL, power loss); one being written now
        is never that old.

        *recheck_space* (the periodic sweep only, never at startup, where
        the bridge never deletes an older copy to make room): a younger
        ``.pre-migration`` copy is removed too, with a WARNING, once the
        volume no longer has room to keep it.
        """
        db_str = str(self._db_path)
        if db_str == ":memory:":
            return
        db_path = Path(db_str)
        parent = db_path.parent
        if not parent.is_dir():
            return
        prefix = db_path.name
        cutoff = time.time() - max_age_days * 86400
        patterns = [
            f"{prefix}.pre-migration",
            f"{prefix}.pre-migration.*",
            f"{prefix}.failed-migration-*",
            f"{prefix}-wal.failed-migration-*",
            f"{prefix}-shm.failed-migration-*",
        ]
        kept = parent / f"{prefix}.pre-migration"
        if recheck_space and kept.is_file():
            try:
                young = kept.stat().st_mtime >= cutoff
            except OSError:
                young = False
            if young:
                try:
                    _disk_usage(parent)
                except OSError:
                    young = False  # unknown free space: keep it this cycle
            if young:
                keep, reason = _keep_pre_migration_copy(db_path, had_migrations=True)
                if not keep:
                    size = _file_size(kept)
                    try:
                        kept.unlink()
                        logger.warning(
                            "Removed the kept pre-migration copy %s (%.1f MB) "
                            "before its 7 days were up: %s",
                            kept,
                            size / 1e6,
                            reason,
                        )
                    except OSError as exc:
                        logger.warning(
                            "Could not remove the kept pre-migration copy %s: %s",
                            kept,
                            exc,
                        )
        for pattern in patterns:
            for candidate in parent.glob(pattern):
                try:
                    if candidate.stat().st_mtime < cutoff:
                        size = candidate.stat().st_size
                        candidate.unlink()
                        logger.info(
                            "Removed stale migration artifact %s (%.1f MB)",
                            candidate,
                            size / 1e6,
                        )
                except OSError as exc:
                    logger.warning(
                        "Could not remove migration artifact %s: %s", candidate, exc
                    )

    @staticmethod
    def _safe_add_columns(
        conn: sqlite3.Connection, table: str, columns: list[tuple[str, str]]
    ) -> None:
        """Add columns to a table, ignoring errors for columns that already exist."""
        for col_name, col_type in columns:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")
            except sqlite3.OperationalError:
                pass  # Column already exists

    def ensure_rf_anomalies_table(self, conn: sqlite3.Connection) -> None:
        """Create rf_anomalies table if it does not exist (late migration)."""
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS rf_anomalies (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                detection_id    TEXT NOT NULL DEFAULT '',
                signal_class    TEXT NOT NULL DEFAULT '',
                family          TEXT NOT NULL DEFAULT '',
                freq_hz         REAL NOT NULL DEFAULT 0.0,
                dedup_key       TEXT NOT NULL DEFAULT '',
                node_id         TEXT NOT NULL DEFAULT '',
                timestamp       TEXT NOT NULL DEFAULT '',
                confidence      REAL NOT NULL DEFAULT 0.0,
                snr_db          REAL,
                power_dbm       REAL,
                anomaly_score   REAL NOT NULL DEFAULT 0.0,
                priority        TEXT NOT NULL DEFAULT 'normal',
                dimensions      TEXT DEFAULT '{}',
                reasons         TEXT DEFAULT '[]',
                baseline_status TEXT NOT NULL DEFAULT 'stable',
                has_iq_capture  INTEGER NOT NULL DEFAULT 0,
                dismissed       INTEGER NOT NULL DEFAULT 0,
                seen_count      INTEGER NOT NULL DEFAULT 1,
                first_seen      TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_rf_anomaly_active
                ON rf_anomalies (dismissed, anomaly_score DESC, timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_rf_anomaly_dedup
                ON rf_anomalies (dedup_key, dismissed) WHERE dismissed = 0;
            CREATE INDEX IF NOT EXISTS idx_rf_anomaly_timestamp
                ON rf_anomalies (timestamp);
        """)
        logger.info("rf_anomalies table created via late migration")

    # -- Tenant filtering ---------------------------------------------------

    def tenant_filter(self, table_alias: str = "") -> tuple[str, list]:
        """Return a WHERE clause fragment and params for tenant isolation.

        Parameters
        ----------
        table_alias : str
            Optional table alias prefix (e.g. ``"t."``).

        Returns
        -------
        tuple[str, list]
            SQL clause ``"tenant_id = ?"`` and ``[self.tenant_id]``.
        """
        prefix = f"{table_alias}." if table_alias else ""
        return f"{prefix}tenant_id = ?", [self.tenant_id]

    @property
    def row_limit(self) -> int:
        """Per-tenant row limit (0 = unlimited)."""
        return self._row_limit

    _USAGE_TABLES = [
        "detections",
        "wifi_metadata",
        "bt_devices",
        "zigbee_devices",
        "audit_log",
        "detection_feedback",
    ]

    def get_tenant_usage(self) -> dict[str, Any]:
        """Return row counts per table for the current tenant."""
        conn = self.get_conn()
        tf_clause, tf_params = self.tenant_filter()
        usage: dict[str, int] = {}
        for table in self._USAGE_TABLES:
            try:
                row = conn.execute(
                    f"SELECT COUNT(*) AS cnt FROM {table} WHERE {tf_clause}",
                    tf_params,
                ).fetchone()
                usage[table] = row["cnt"] if row else 0
            except Exception:
                usage[table] = 0
        return usage

    # -- Backup -------------------------------------------------------------

    def backup(self, dest_path: str | Path) -> dict[str, Any]:
        """Create online backup using SQLite backup API.

        Uses pages=100, sleep=0.01 to allow concurrent reads during copy.

        Parameters
        ----------
        dest_path : str or Path
            Destination file path for the backup database.

        Returns
        -------
        dict
            Metadata including path, size_bytes, elapsed_sec, and status.
        """
        import time

        dest = str(dest_path)
        src_conn = self.get_conn()
        from sigrift.bridge.storage.encryption import open_db

        dst_conn = open_db(dest)
        try:
            t0 = time.monotonic()
            src_conn.backup(dst_conn, pages=100, sleep=0.01)
            elapsed = time.monotonic() - t0
            size = Path(dest).stat().st_size
            logger.info("Backup complete: %s (%d bytes, %.2fs)", dest, size, elapsed)
            return {
                "path": dest,
                "size_bytes": size,
                "elapsed_sec": round(elapsed, 3),
                "status": "complete",
            }
        finally:
            dst_conn.close()

    # -- Lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close every tracked connection that no thread can be using.

        That is the calling thread's own connection and those of threads
        that have exited.  A connection of another *live* thread is left
        open and registered: that thread may be stepping a statement on it
        right now (a job handler or maintenance task still running in a
        worker thread after its task was cancelled), and closing a sqlite3
        connection under a running statement crashes the interpreter.
        Such a thread closes its connection itself the next time it uses
        the context (the generation check in :meth:`get_conn`, which also
        gives it a fresh connection); a later ``close()`` closes it once
        the thread has exited; process exit releases the rest.

        A connection that fails to close stays registered (so a later
        ``close()`` retries it) instead of being forgotten while open.
        """
        me = threading.current_thread()
        with self._conn_registry_lock:
            self._conn_generation += 1
            conns = [
                (conn, owner)
                for conn, owner in self._conn_registry.items()
                if owner is me or not owner.is_alive()
            ]
            # Claimed under the lock: a concurrent _retire_own_connection
            # (or close()) cannot close them a second time.
            for conn, _owner in conns:
                del self._conn_registry[conn]
            busy = len(self._conn_registry)
        closed = 0
        for conn, owner in conns:
            try:
                conn.close()
                closed += 1
                logger.debug(
                    "SharedContext: closed connection %r (thread %s)", conn, owner.name
                )
            except Exception as exc:
                with self._conn_registry_lock:
                    self._conn_registry[conn] = owner
                logger.error(
                    "SharedContext: failed to close connection %r (thread %s): %s",
                    conn,
                    owner.name,
                    exc,
                )
        # Also clear the calling thread's local ref
        self._local.conn = None
        logger.debug(
            "SharedContext closed %d connection(s); %d left to live threads",
            closed,
            busy,
        )

    def check_disk_space(self) -> float:
        """Return disk usage percentage for the database's filesystem.

        Returns
        -------
        float
            Disk usage as a percentage (0.0–100.0).
        """
        import shutil

        db_dir = str(Path(self._db_path).parent)
        try:
            usage = shutil.disk_usage(db_dir)
            return round(usage.used / usage.total * 100.0, 1)
        except OSError as exc:
            logger.warning("check_disk_space failed for %s: %s", db_dir, exc)
            return 0.0

    def wal_checkpoint(self) -> tuple[int, int, int]:
        """Run a TRUNCATE WAL checkpoint under the write lock.

        TRUNCATE merges the WAL into the main DB and truncates the WAL
        file to zero. On a busy multi-worker bridge the truncate step
        returns ``busy=1`` and skips the file truncation whenever another
        connection is mid-read/write — so the file never shrinks even
        though all frames were checkpointed (observed 2026-06-07: a
        TRUNCATE returned ``busy=1, log=2404242, checkpointed=2404242``,
        i.e. it merged 9 GB of frames but couldn't shrink the file).

        Holding ``write_lock`` removes writer-caused contention; the
        scheduled loop additionally retries to catch a gap between the
        short-lived reader snapshots from request handlers.

        Returns
        -------
        tuple[int, int, int]
            (busy, log_pages, checkpointed_pages) from PRAGMA wal_checkpoint.
        """
        conn = self.get_conn()
        with self._write_lock:
            result = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        logger.debug(
            "WAL checkpoint (TRUNCATE): busy=%s, log=%s, checkpointed=%s",
            result[0],
            result[1],
            result[2],
        )
        return (result[0], result[1], result[2])

    def schedule_wal_checkpoint(
        self,
        interval_seconds: float = 300.0,
        retry_attempts: int = 5,
        retry_delay: float = 1.0,
    ) -> asyncio.Task:
        """Start a background task that runs periodic WAL checkpoints.

        Each tick runs ``PRAGMA wal_checkpoint(TRUNCATE)`` under the write
        lock (via a worker thread so the event loop isn't blocked for the
        checkpoint duration). If it returns ``busy=1`` — the truncate step
        couldn't get its exclusive moment because a reader was active — it
        retries up to ``retry_attempts`` times with ``retry_delay`` between
        attempts, to catch a gap between the short reader snapshots from
        request handlers. Without the retry the WAL file never shrinks on a
        continuously-busy 2-worker bridge and grows ~5 GB/day on disk even
        though every frame is being merged.

        Logs each tick at INFO when busy or when frames were checkpointed.
        Silence is a deliberate anti-pattern here: an earlier inline loop
        logged at DEBUG and the WAL silently grew to 18 GB before anyone
        noticed.

        Returns
        -------
        asyncio.Task
            The background task handle (can be cancelled on shutdown).
        """

        async def _checkpoint_loop() -> None:
            while True:
                await asyncio.sleep(interval_seconds)
                try:
                    busy = log_pages = checkpointed = 0
                    attempt = 0
                    for attempt in range(retry_attempts):
                        busy, log_pages, checkpointed = await asyncio.to_thread(
                            self.wal_checkpoint
                        )
                        if not busy:
                            break
                        await asyncio.sleep(retry_delay)
                    if busy or checkpointed:
                        logger.info(
                            "WAL checkpoint (TRUNCATE): busy=%s, log=%s, "
                            "checkpointed=%s, attempts=%d",
                            busy,
                            log_pages,
                            checkpointed,
                            attempt + 1,
                        )
                except Exception as exc:
                    logger.warning("WAL checkpoint failed: %s", exc)

        return asyncio.create_task(_checkpoint_loop())

    def cache_stats(self) -> dict[str, Any]:
        """Return TTL cache hit/miss statistics."""
        return self._cache.stats()

    @property
    def db_path(self) -> str:
        """Return the database file path."""
        return self._db_path

    @property
    def write_lock(self) -> threading.Lock:
        """Return the write serialization lock."""
        return self._write_lock

    @property
    def cache(self) -> PartitionedCache:
        """Return the partitioned TTL cache instance."""
        return self._cache

    # -- DB abstraction (forward-compatible for PostgreSQL) ------------------

    @property
    def dialect(self) -> SQLDialect:
        """Current database dialect."""
        return SQLDialect.SQLITE

    @property
    def backend(self) -> str:
        """Current database backend name."""
        return "sqlite"

    def execute(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        """Execute SQL on the current connection."""
        return self.get_conn().execute(sql, params)

    def executemany(self, sql: str, rows: list) -> sqlite3.Cursor:
        """Execute SQL for multiple parameter sets."""
        return self.get_conn().executemany(sql, rows)

    def commit(self) -> None:
        """Commit current transaction.

        Prefer :meth:`transaction` / :meth:`write_transaction`, which also
        roll back on error.
        """
        self.get_conn().commit()

    # -- Transactions -------------------------------------------------------

    @property
    def transaction_active(self) -> bool:
        """Whether this thread owns a transaction, including a lazy scope.

        Before its first SQL write, ``write_transaction`` already owns the
        non-reentrant write lock even though SQLite's ``in_transaction`` is
        still false. Operations that must own their commit can reject that
        caller-owned scope without mistaking another thread's lock for it.
        """
        conn = self.get_conn()
        depth = _tx_state.__dict__.get("depths", {}).get(id(conn), 0)
        return bool(depth) or conn.in_transaction

    def transaction(
        self, *, immediate: bool = False
    ) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        """Context manager yielding this thread's connection in a transaction.

        Commits on normal exit, rolls back on any exception (see
        :func:`sqlite_transaction`).  Does **not** take :attr:`write_lock`;
        use it inside an existing ``with ctx.write_lock:`` block, or use
        :meth:`write_transaction`.
        """
        return sqlite_transaction(self.get_conn(), immediate=immediate)

    @contextlib.contextmanager
    def write_transaction(
        self, *, immediate: bool = False
    ) -> Iterator[sqlite3.Connection]:
        """Hold :attr:`write_lock` for a :meth:`transaction` block.

        The usual wrapper for a write path::

            with ctx.write_transaction() as conn:
                conn.execute("UPDATE ...")
            ctx.cache.invalidate_prefix(...)  # after the commit

        ``write_lock`` is not re-entrant: do not call this (or anything
        that takes ``write_lock``) from inside another
        ``write_transaction`` / ``write_lock`` block.
        """
        with (
            self._write_lock,
            sqlite_transaction(self.get_conn(), immediate=immediate) as conn,
        ):
            yield conn
