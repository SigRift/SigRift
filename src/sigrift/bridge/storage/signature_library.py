"""Reference IQ signature library storage sub-store.

SQLite-backed storage for curated known-good IQ signatures with metadata,
fingerprint embeddings, and cosine similarity matching against unknown signals.
"""

from __future__ import annotations

import json
import logging
import math
import struct
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _normalize_class(signal_class: str) -> str:
    """Normalize signal class for matching (lazy import to avoid circular deps)."""
    try:
        from sigrift.bridge.class_map import normalize_class

        return normalize_class(signal_class)
    except ImportError:
        # Strip numeric OFDM suffixes as fallback
        if signal_class.startswith("ofdm-"):
            return "ofdm"
        return signal_class


_SIGNATURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS reference_signatures (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    signal_class TEXT NOT NULL,
    description TEXT DEFAULT '',

    -- Signal parameters
    center_freq_hz REAL,
    bandwidth_hz REAL,
    sample_rate_hz REAL,

    -- Fingerprint embedding (32 x float32 = 128 bytes)
    embedding BLOB,
    features_48dim BLOB,

    -- IQ storage
    iq_file_path TEXT,
    iq_samples INTEGER,

    -- SigMF metadata
    sigmf_metadata TEXT,

    -- Threat assessment
    threat_category TEXT DEFAULT '',
    threat_level TEXT DEFAULT '',
    freq_min_hz REAL,
    freq_max_hz REAL,
    burst_duration_ms REAL,
    burst_interval_ms REAL,
    power_min_dbm REAL,
    power_max_dbm REAL,
    active INTEGER DEFAULT 1,

    -- Classification
    tags TEXT DEFAULT '[]',
    source TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,

    created_by TEXT DEFAULT '',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_refsig_protocol
    ON reference_signatures (protocol);
CREATE INDEX IF NOT EXISTS idx_refsig_signal_class
    ON reference_signatures (signal_class);
CREATE INDEX IF NOT EXISTS idx_refsig_verified
    ON reference_signatures (verified) WHERE verified = 1;
CREATE INDEX IF NOT EXISTS idx_refsig_created_at
    ON reference_signatures (created_at);
"""


_THREAT_SEED_DATA: list[dict[str, Any]] = [
    # =====================================================================
    # COVERT MICROPHONES / AUDIO BUGS (10)
    # =====================================================================
    {
        "name": "VHF Audio Bug (170-180 MHz)",
        "protocol": "analog",
        "signal_class": "fm",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 175e6,
        "freq_min_hz": 170e6,
        "freq_max_hz": 180e6,
        "power_min_dbm": -35,
        "power_max_dbm": -5,
        "description": "Analog FM audio surveillance device in VHF band",
    },
    {
        "name": "UHF Audio Bug (430-440 MHz)",
        "protocol": "analog",
        "signal_class": "fm",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 435e6,
        "freq_min_hz": 430e6,
        "freq_max_hz": 440e6,
        "power_min_dbm": -40,
        "power_max_dbm": -5,
        "description": "Analog FM audio surveillance device in UHF band",
    },
    {
        "name": "ISM 433 Audio Bug",
        "protocol": "digital",
        "signal_class": "ook",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 434e6,
        "freq_min_hz": 433e6,
        "freq_max_hz": 435e6,
        "burst_duration_ms": 20,
        "burst_interval_ms": 100,
        "description": "Digital burst audio bug in ISM 433 band",
    },
    {
        "name": "UHF Wideband Room Bug",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 460e6,
        "freq_min_hz": 450e6,
        "freq_max_hz": 470e6,
        "power_min_dbm": -50,
        "power_max_dbm": -10,
        "description": "Digital FSK audio surveillance with frequency hopping",
    },
    {
        "name": "DECT Phone Interceptor",
        "protocol": "digital",
        "signal_class": "dect",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 1905e6,
        "freq_min_hz": 1880e6,
        "freq_max_hz": 1930e6,
        "description": "DECT cordless phone interception — captures voice/data",
    },
    {
        "name": "Spread-Spectrum Room Bug",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 915e6,
        "freq_min_hz": 900e6,
        "freq_max_hz": 930e6,
        "power_min_dbm": -60,
        "power_max_dbm": -20,
        "description": "FHSS audio bug in ISM 915 — hops across 26 MHz band, hard to detect",
    },
    {
        "name": "Digital Encrypted Room Bug",
        "protocol": "digital",
        "signal_class": "4fsk",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 868e6,
        "freq_min_hz": 863e6,
        "freq_max_hz": 870e6,
        "burst_duration_ms": 50,
        "burst_interval_ms": 200,
        "power_min_dbm": -55,
        "power_max_dbm": -15,
        "description": "Encrypted digital audio bug in EU ISM 868 band — AES-encrypted bursts",
    },
    {
        "name": "Bluetooth Audio Interceptor",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "Bluetooth audio stream interception device",
    },
    {
        "name": "UHF Bump Mic (Induction)",
        "protocol": "analog",
        "signal_class": "am-dsb",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 150e6,
        "freq_min_hz": 140e6,
        "freq_max_hz": 160e6,
        "power_min_dbm": -70,
        "power_max_dbm": -30,
        "description": "Low-power AM contact microphone — requires close proximity receiver",
    },
    {
        "name": "DMR Covert Radio",
        "protocol": "digital",
        "signal_class": "dmr",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 446e6,
        "freq_min_hz": 440e6,
        "freq_max_hz": 450e6,
        "description": "DMR digital radio used covertly — encrypted TDMA voice",
    },
    # =====================================================================
    # VIDEO TRANSMITTERS (5)
    # =====================================================================
    {
        "name": "WiFi Covert Exfil Camera",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "video_tx",
        "threat_level": "critical",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "WiFi-connected covert video surveillance device",
    },
    {
        "name": "1.2 GHz Analog Video TX",
        "protocol": "analog",
        "signal_class": "fpv-analog",
        "threat_category": "video_tx",
        "threat_level": "critical",
        "center_freq_hz": 1280e6,
        "freq_min_hz": 1240e6,
        "freq_max_hz": 1320e6,
        "power_min_dbm": -20,
        "power_max_dbm": 10,
        "description": "Analog video transmitter at 1.2 GHz — covert pinhole camera feed",
    },
    {
        "name": "2.4 GHz Analog Video TX",
        "protocol": "analog",
        "signal_class": "fpv-analog",
        "threat_category": "video_tx",
        "threat_level": "critical",
        "center_freq_hz": 2450e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2500e6,
        "power_min_dbm": -25,
        "power_max_dbm": 5,
        "description": "Analog video transmitter in 2.4 GHz ISM — common covert camera frequency",
    },
    {
        "name": "5.8 GHz Digital Video TX",
        "protocol": "digital",
        "signal_class": "ofdm-64",
        "threat_category": "video_tx",
        "threat_level": "critical",
        "center_freq_hz": 5800e6,
        "freq_min_hz": 5725e6,
        "freq_max_hz": 5875e6,
        "description": "Digital video transmitter in 5.8 GHz ISM — high-bandwidth covert camera",
    },
    {
        "name": "Body-Cam WiFi Exfil",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "video_tx",
        "threat_level": "high",
        "center_freq_hz": 5500e6,
        "freq_min_hz": 5170e6,
        "freq_max_hz": 5835e6,
        "description": "Body-worn camera exfiltrating video over WiFi 5 GHz",
    },
    # =====================================================================
    # BODY-WORN TRANSMITTERS (5)
    # =====================================================================
    {
        "name": "GSM Audio Bug (900 MHz)",
        "protocol": "digital",
        "signal_class": "gsm",
        "threat_category": "body_worn_tx",
        "threat_level": "critical",
        "center_freq_hz": 897e6,
        "freq_min_hz": 880e6,
        "freq_max_hz": 915e6,
        "power_min_dbm": -30,
        "power_max_dbm": 10,
        "description": "GSM-based audio surveillance device using cellular network",
    },
    {
        "name": "ISM 915 Body-Worn TX",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "body_worn_tx",
        "threat_level": "high",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "description": "ISM 915 band body-worn audio transmitter",
    },
    {
        "name": "GSM Audio Bug (1800 MHz)",
        "protocol": "digital",
        "signal_class": "gsm",
        "threat_category": "body_worn_tx",
        "threat_level": "critical",
        "center_freq_hz": 1747e6,
        "freq_min_hz": 1710e6,
        "freq_max_hz": 1785e6,
        "description": "GSM 1800 band audio bug",
    },
    {
        "name": "LTE Covert Body-Worn TX",
        "protocol": "digital",
        "signal_class": "ofdm-1024",
        "threat_category": "body_worn_tx",
        "threat_level": "critical",
        "center_freq_hz": 2600e6,
        "freq_min_hz": 2500e6,
        "freq_max_hz": 2690e6,
        "description": "LTE-based covert body-worn transmitter — uses mobile data for exfil",
    },
    {
        "name": "BLE Body-Worn Audio",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "body_worn_tx",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "burst_duration_ms": 5,
        "burst_interval_ms": 50,
        "description": "Bluetooth Low Energy covert audio stream from body-worn device",
    },
    # =====================================================================
    # GPS / LOCATION TRACKERS (5)
    # =====================================================================
    {
        "name": "BLE Tracking Beacon",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "gps_tracker",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "burst_duration_ms": 2,
        "burst_interval_ms": 1000,
        "description": "BLE advertising beacon used for location tracking (AirTag-like)",
    },
    {
        "name": "Cellular GPS Tracker",
        "protocol": "digital",
        "signal_class": "gsm",
        "threat_category": "gps_tracker",
        "threat_level": "high",
        "center_freq_hz": 897e6,
        "freq_min_hz": 880e6,
        "freq_max_hz": 915e6,
        "burst_duration_ms": 200,
        "burst_interval_ms": 60000,
        "description": "GSM/LTE GPS tracker — periodic position reports via cellular",
    },
    {
        "name": "LoRa GPS Tracker",
        "protocol": "digital",
        "signal_class": "lora-css",
        "threat_category": "gps_tracker",
        "threat_level": "medium",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 1000,
        "burst_interval_ms": 300000,
        "description": "LoRa-based GPS tracker — low-power, long-range, infrequent bursts",
    },
    {
        "name": "ISM 433 Vehicle Tracker",
        "protocol": "digital",
        "signal_class": "ook",
        "threat_category": "gps_tracker",
        "threat_level": "high",
        "center_freq_hz": 434e6,
        "freq_min_hz": 433e6,
        "freq_max_hz": 435e6,
        "burst_duration_ms": 50,
        "burst_interval_ms": 30000,
        "description": "OOK vehicle tracker in ISM 433 — periodic short bursts with GPS data",
    },
    {
        "name": "Satellite Tracker (Iridium)",
        "protocol": "digital",
        "signal_class": "iridium",
        "threat_category": "gps_tracker",
        "threat_level": "high",
        "center_freq_hz": 1621e6,
        "freq_min_hz": 1616e6,
        "freq_max_hz": 1626.5e6,
        "burst_duration_ms": 100,
        "burst_interval_ms": 600000,
        "description": "Iridium satellite-based GPS tracker — global coverage, very hard to detect",
    },
    # =====================================================================
    # JAMMERS (6)
    # =====================================================================
    {
        "name": "GPS L1 Jammer",
        "protocol": "interference",
        "signal_class": "gps-jammer",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 1575.42e6,
        "freq_min_hz": 1565.42e6,
        "freq_max_hz": 1585.42e6,
        "description": "GPS L1 band jammer — disrupts navigation and timing",
    },
    {
        "name": "2.4 GHz Wideband Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Wideband 2.4 GHz jammer — disrupts WiFi, Bluetooth, Zigbee",
    },
    {
        "name": "Cellular Band Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 900e6,
        "freq_min_hz": 850e6,
        "freq_max_hz": 960e6,
        "description": "Cellular 850/900 MHz band jammer — blocks voice and data",
    },
    {
        "name": "VHF/UHF Public Safety Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 460e6,
        "freq_min_hz": 400e6,
        "freq_max_hz": 520e6,
        "description": "VHF/UHF jammer targeting public safety and first responder bands",
    },
    {
        "name": "DECT Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "high",
        "center_freq_hz": 1905e6,
        "freq_min_hz": 1880e6,
        "freq_max_hz": 1930e6,
        "description": "DECT band jammer — disrupts cordless phones",
    },
    {
        "name": "Drone Counter-UAS Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 5875e6,
        "description": "Wideband counter-drone jammer — covers 2.4 + 5.8 GHz control bands",
    },
    # =====================================================================
    # REMOTE CONTROL / EXPLOITATION (5)
    # =====================================================================
    {
        "name": "WiFi Deauth Attack",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "remote_control",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "burst_duration_ms": 1,
        "burst_interval_ms": 10,
        "description": "802.11 deauthentication flood indicating active WiFi attack",
    },
    {
        "name": "WiFi Evil Twin AP",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "remote_control",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Rogue access point mimicking legitimate network",
    },
    {
        "name": "5 GHz Rogue AP",
        "protocol": "wifi",
        "signal_class": "ofdm-256",
        "threat_category": "remote_control",
        "threat_level": "high",
        "center_freq_hz": 5500e6,
        "freq_min_hz": 5170e6,
        "freq_max_hz": 5835e6,
        "description": "Rogue access point on 5 GHz — harder to detect than 2.4 GHz",
    },
    {
        "name": "Drone C2 Link (2.4 GHz)",
        "protocol": "digital",
        "signal_class": "ofdm-64",
        "threat_category": "remote_control",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Drone command and control link in 2.4 GHz ISM band",
    },
    {
        "name": "Zigbee IoT Exploitation",
        "protocol": "zigbee",
        "signal_class": "oqpsk-dsss",
        "threat_category": "remote_control",
        "threat_level": "medium",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2405e6,
        "freq_max_hz": 2480e6,
        "description": "Unauthorized Zigbee frames targeting smart building infrastructure",
    },
    # =====================================================================
    # IMSI CATCHERS / STINGRAYS (3)
    # =====================================================================
    {
        "name": "IMSI Catcher (900 MHz)",
        "protocol": "digital",
        "signal_class": "gsm",
        "threat_category": "imsi_catcher",
        "threat_level": "critical",
        "center_freq_hz": 940e6,
        "freq_min_hz": 925e6,
        "freq_max_hz": 960e6,
        "power_min_dbm": -20,
        "power_max_dbm": 20,
        "description": "Rogue cell tower (Stingray) at 900 MHz — intercepts IMSI and voice",
    },
    {
        "name": "IMSI Catcher (1800 MHz)",
        "protocol": "digital",
        "signal_class": "gsm",
        "threat_category": "imsi_catcher",
        "threat_level": "critical",
        "center_freq_hz": 1842e6,
        "freq_min_hz": 1805e6,
        "freq_max_hz": 1880e6,
        "power_min_dbm": -20,
        "power_max_dbm": 15,
        "description": "Rogue cell tower at 1800 MHz — forces 2G downgrade for interception",
    },
    {
        "name": "LTE IMSI Catcher",
        "protocol": "digital",
        "signal_class": "ofdm-1024",
        "threat_category": "imsi_catcher",
        "threat_level": "critical",
        "center_freq_hz": 2140e6,
        "freq_min_hz": 2110e6,
        "freq_max_hz": 2170e6,
        "description": "4G LTE rogue eNodeB — captures IMSI via attach procedure",
    },
    # =====================================================================
    # DRONE SURVEILLANCE (3)
    # =====================================================================
    {
        "name": "DJI Drone (OcuSync)",
        "protocol": "digital",
        "signal_class": "ofdm-1024",
        "threat_category": "drone_surveillance",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "DJI drone OcuSync C2 link — potential aerial surveillance platform",
    },
    {
        "name": "FPV Racing Drone (5.8 GHz)",
        "protocol": "analog",
        "signal_class": "fpv-analog",
        "threat_category": "drone_surveillance",
        "threat_level": "medium",
        "center_freq_hz": 5800e6,
        "freq_min_hz": 5725e6,
        "freq_max_hz": 5875e6,
        "description": "Analog FPV video downlink — may carry covert surveillance camera",
    },
    {
        "name": "Drone Telemetry (915 MHz)",
        "protocol": "digital",
        "signal_class": "lora-css",
        "threat_category": "drone_surveillance",
        "threat_level": "medium",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 200,
        "burst_interval_ms": 1000,
        "description": "LoRa-based drone telemetry — position, altitude, heading reports",
    },
    # =====================================================================
    # DATA EXFILTRATION (3)
    # =====================================================================
    {
        "name": "Covert Data Exfil (ISM 433)",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "data_exfil",
        "threat_level": "critical",
        "center_freq_hz": 434e6,
        "freq_min_hz": 433e6,
        "freq_max_hz": 435e6,
        "burst_duration_ms": 100,
        "burst_interval_ms": 5000,
        "description": "Periodic FSK data bursts exfiltrating captured data via ISM 433",
    },
    {
        "name": "USB-to-Radio Exfil Device",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "data_exfil",
        "threat_level": "critical",
        "center_freq_hz": 315e6,
        "freq_min_hz": 310e6,
        "freq_max_hz": 320e6,
        "burst_duration_ms": 500,
        "burst_interval_ms": 10000,
        "description": "USB implant exfiltrating data via 315 MHz RF — bridges air gap",
    },
    {
        "name": "WiFi Covert Channel Exfil",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "data_exfil",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Steganographic WiFi exfiltration — data hidden in beacon frames",
    },
    # =====================================================================
    # UNKNOWN / ANOMALOUS (4)
    # =====================================================================
    {
        "name": "Anomalous ISM 915 Burst",
        "protocol": "digital",
        "signal_class": "lora-css",
        "threat_category": "unknown_threat",
        "threat_level": "medium",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 500,
        "description": "Unusual LoRa-like burst in ISM 915 band — possible covert data exfiltration",
    },
    {
        "name": "Narrowband Carrier (Beacon)",
        "protocol": "analog",
        "signal_class": "tone",
        "threat_category": "unknown_threat",
        "threat_level": "medium",
        "center_freq_hz": 200e6,
        "freq_min_hz": 100e6,
        "freq_max_hz": 1000e6,
        "description": "Unmodulated carrier — possible tracking beacon or device test signal",
    },
    {
        "name": "Wideband Anomaly (UHF)",
        "protocol": "unknown",
        "signal_class": "noise",
        "threat_category": "unknown_threat",
        "threat_level": "low",
        "center_freq_hz": 500e6,
        "freq_min_hz": 400e6,
        "freq_max_hz": 600e6,
        "description": "Unexplained wideband energy in UHF — requires manual investigation",
    },
    {
        "name": "FHSS Unknown Protocol",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "unknown_threat",
        "threat_level": "high",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 10,
        "burst_interval_ms": 50,
        "description": "Fast-hopping FSK signal — unknown protocol, possible covert comms",
    },
    # =====================================================================
    # SURVEILLANCE INFRASTRUCTURE (5) — Flock Safety, Raven, SoundThinking
    # =====================================================================
    {
        "name": "Flock Safety ALPR Camera (BLE)",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "surveillance_infra",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "burst_duration_ms": 5,
        "burst_interval_ms": 2000,
        "description": "Flock Safety ALPR camera BLE beacon — OUI 58:8e:81/cc:cc:cc/ec:1b:bd, MFG ID 0x09C8",
    },
    {
        "name": "SoundThinking Raven Gunshot Sensor",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "surveillance_infra",
        "threat_level": "low",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "SoundThinking Raven sensor — MAC d4:11:d6, GATT UUIDs 0x3100-0x3500",
    },
    {
        "name": "Ring Doorbell/Camera (BLE)",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "surveillance_infra",
        "threat_level": "low",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "Ring doorbell/security camera BLE advertising — 11 known OUI prefixes",
    },
    {
        "name": "Axon Body Camera (BLE)",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "surveillance_infra",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "Axon law enforcement body camera BLE beacon",
    },
    {
        "name": "Meta Ray-Ban Smart Glasses (BLE)",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "surveillance_infra",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "Meta Ray-Ban smart glasses with camera — BLE advertising",
    },
    # =====================================================================
    # DRONE REMOTE ID (4) — ASTM F3411 detection + spoofing
    # =====================================================================
    {
        "name": "FAA Remote ID (WiFi NAN)",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "drone_surveillance",
        "threat_level": "low",
        "center_freq_hz": 2437e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "burst_duration_ms": 10,
        "burst_interval_ms": 1000,
        "description": "ASTM F3411 OpenDroneID via WiFi NAN on channel 6 — legitimate drone broadcast",
    },
    {
        "name": "FAA Remote ID (BLE)",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "drone_surveillance",
        "threat_level": "low",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "burst_duration_ms": 5,
        "burst_interval_ms": 1000,
        "description": "ASTM F3411 OpenDroneID via BLE 5.0 — service UUID 0xFFFA",
    },
    {
        "name": "Spoofed Remote ID (ESP32)",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "drone_surveillance",
        "threat_level": "critical",
        "center_freq_hz": 2437e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "burst_duration_ms": 10,
        "burst_interval_ms": 1000,
        "description": "Spoofed drone Remote ID from ESP32 — multiple fake drone IDs from single source",
    },
    {
        "name": "Remote ID Swarm Spoof",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "drone_surveillance",
        "threat_level": "critical",
        "center_freq_hz": 2437e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 5875e6,
        "description": "Mass spoofed Remote ID — 20+ fake drones, ESP32 RF fingerprint, algorithmic GPS patterns",
    },
    # =====================================================================
    # COUNTER-SURVEILLANCE TOOLS (4) — OUI-SPY ecosystem detection
    # =====================================================================
    {
        "name": "OUI-SPY Detector AP",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "counter_surveillance",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "OUI-SPY detector WiFi AP — SSID snoopuntothem/foxhunter — adversary recon tool active",
    },
    {
        "name": "Flock-You Scanner AP",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "counter_surveillance",
        "threat_level": "medium",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Flock-You scanner WiFi AP — SSID flockyou — scanning for surveillance infrastructure",
    },
    {
        "name": "Mesh-Detect Scanner",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "counter_surveillance",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Mesh-Detect WiFi AP — adversary BLE/WiFi OUI scanner with LoRa mesh alerting",
    },
    {
        "name": "AntiHunter Fox Tracker",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "counter_surveillance",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "AntiHunter WiFi AP — RSSI-based device hunting tool with Meshtastic mesh relay",
    },
    # =====================================================================
    # P25 / TETRA / TRUNKED RADIO SURVEILLANCE (3)
    # =====================================================================
    {
        "name": "P25 Digital Voice Bug",
        "protocol": "digital",
        "signal_class": "p25",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 800e6,
        "freq_min_hz": 750e6,
        "freq_max_hz": 870e6,
        "power_min_dbm": -25,
        "power_max_dbm": 10,
        "description": "P25 Phase II encrypted voice — law enforcement tactical radio used covertly",
    },
    {
        "name": "TETRA Covert Transmitter",
        "protocol": "digital",
        "signal_class": "tetra",
        "threat_category": "covert_mic",
        "threat_level": "critical",
        "center_freq_hz": 405e6,
        "freq_min_hz": 380e6,
        "freq_max_hz": 430e6,
        "power_min_dbm": -20,
        "power_max_dbm": 10,
        "description": "TETRA encrypted TDMA — EU/INTERPOL standard, used for covert comms",
    },
    {
        "name": "PMR446 Wireless Mic",
        "protocol": "analog",
        "signal_class": "pmr446",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 446.05e6,
        "freq_min_hz": 446e6,
        "freq_max_hz": 446.2e6,
        "power_min_dbm": -40,
        "power_max_dbm": -10,
        "description": "PMR446 license-free radio as covert microphone — 16 channels, commonly overlooked",
    },
    # =====================================================================
    # RFID / NFC / PROXIMITY CARD ATTACKS (3)
    # =====================================================================
    {
        "name": "RFID 125 kHz Card Cloner",
        "protocol": "analog",
        "signal_class": "ook",
        "threat_category": "data_exfil",
        "threat_level": "critical",
        "center_freq_hz": 125e3,
        "freq_min_hz": 100e3,
        "freq_max_hz": 150e3,
        "power_min_dbm": -40,
        "power_max_dbm": -10,
        "description": "Low-frequency RFID proximity card cloner — duplicates HID ProxCard, EM4100 badges",
    },
    {
        "name": "NFC 13.56 MHz Card Cloner",
        "protocol": "digital",
        "signal_class": "ask",
        "threat_category": "data_exfil",
        "threat_level": "critical",
        "center_freq_hz": 13.56e6,
        "freq_min_hz": 13e6,
        "freq_max_hz": 14e6,
        "power_min_dbm": -30,
        "power_max_dbm": -5,
        "description": "NFC/MIFARE card cloner — steals payment cards, access badges at close range",
    },
    {
        "name": "UHF RFID Skimmer",
        "protocol": "digital",
        "signal_class": "ask",
        "threat_category": "data_exfil",
        "threat_level": "high",
        "center_freq_hz": 915e6,
        "freq_min_hz": 860e6,
        "freq_max_hz": 960e6,
        "power_min_dbm": -20,
        "power_max_dbm": 10,
        "description": "UHF RFID reader at extended range — skims asset tags, passports, eID cards",
    },
    # =====================================================================
    # CAR KEY RELAY / KEYLESS ENTRY ATTACKS (3)
    # =====================================================================
    {
        "name": "Car Key Relay (315 MHz NA)",
        "protocol": "digital",
        "signal_class": "ook",
        "threat_category": "remote_control",
        "threat_level": "critical",
        "center_freq_hz": 315e6,
        "freq_min_hz": 310e6,
        "freq_max_hz": 320e6,
        "burst_duration_ms": 20,
        "burst_interval_ms": 500,
        "power_min_dbm": -50,
        "power_max_dbm": -15,
        "description": "Car key relay/amplifier attack at 315 MHz — extends keyfob range for vehicle theft",
    },
    {
        "name": "Car Key Relay (433 MHz EU)",
        "protocol": "digital",
        "signal_class": "ook",
        "threat_category": "remote_control",
        "threat_level": "critical",
        "center_freq_hz": 433.92e6,
        "freq_min_hz": 430e6,
        "freq_max_hz": 436e6,
        "burst_duration_ms": 20,
        "burst_interval_ms": 500,
        "power_min_dbm": -50,
        "power_max_dbm": -15,
        "description": "Car key relay/amplifier attack at 433 MHz — EU keyfob frequencies",
    },
    {
        "name": "Keyless Entry Jammer",
        "protocol": "interference",
        "signal_class": "noise",
        "threat_category": "jammer",
        "threat_level": "high",
        "center_freq_hz": 433e6,
        "freq_min_hz": 310e6,
        "freq_max_hz": 440e6,
        "description": "Jamming car key lock/unlock to enable theft via unprotected vehicle",
    },
    # =====================================================================
    # GPS JAMMER VARIANTS (2) — L2/L5 bands
    # =====================================================================
    {
        "name": "GPS L2 Jammer",
        "protocol": "interference",
        "signal_class": "gps-jammer",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 1227.6e6,
        "freq_min_hz": 1217e6,
        "freq_max_hz": 1238e6,
        "description": "GPS L2 band jammer — disrupts precision military/survey GPS",
    },
    {
        "name": "GPS L5 Jammer",
        "protocol": "interference",
        "signal_class": "gps-jammer",
        "threat_category": "jammer",
        "threat_level": "critical",
        "center_freq_hz": 1176.45e6,
        "freq_min_hz": 1166e6,
        "freq_max_hz": 1187e6,
        "description": "GPS L5 band jammer — disrupts safety-of-life navigation signals",
    },
    # =====================================================================
    # IOT / SMART DEVICE SURVEILLANCE (3)
    # =====================================================================
    {
        "name": "Z-Wave Covert Sensor",
        "protocol": "digital",
        "signal_class": "2fsk",
        "threat_category": "covert_mic",
        "threat_level": "high",
        "center_freq_hz": 908.4e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 250,
        "burst_interval_ms": 5000,
        "power_min_dbm": -20,
        "power_max_dbm": 0,
        "description": "Z-Wave hidden sensor — motion/door/audio covertly placed in smart home mesh",
    },
    {
        "name": "Amazon Sidewalk Listening Device",
        "protocol": "digital",
        "signal_class": "lora-css",
        "threat_category": "covert_mic",
        "threat_level": "medium",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 500,
        "burst_interval_ms": 10000,
        "description": "Amazon Sidewalk mesh device with microphone — always-on neighborhood mesh relay",
    },
    {
        "name": "Covert Smart Camera (WiFi)",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "video_tx",
        "threat_level": "high",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Hidden WiFi camera (Wyze/Tapo/generic) — covert video with cloud upload",
    },
    # =====================================================================
    # ADDITIONAL DATA EXFILTRATION (2)
    # =====================================================================
    {
        "name": "LoRa Covert Data Exfil",
        "protocol": "digital",
        "signal_class": "lora-css",
        "threat_category": "data_exfil",
        "threat_level": "critical",
        "center_freq_hz": 915e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 928e6,
        "burst_duration_ms": 2000,
        "burst_interval_ms": 60000,
        "power_min_dbm": -40,
        "power_max_dbm": -10,
        "description": "LoRa-modulated data exfil — low power, long range, infrequent bursts evade detection",
    },
    {
        "name": "Sigfox Covert Tracker/Exfil",
        "protocol": "digital",
        "signal_class": "sigfox",
        "threat_category": "gps_tracker",
        "threat_level": "medium",
        "center_freq_hz": 902.2e6,
        "freq_min_hz": 902e6,
        "freq_max_hz": 903e6,
        "burst_duration_ms": 150,
        "burst_interval_ms": 600000,
        "power_min_dbm": -40,
        "power_max_dbm": -15,
        "description": "Sigfox LPWAN tracker — ultra-narrowband 100 Hz bursts, 6 uplinks/day, extremely hard to detect",
    },
    # =====================================================================
    # IMSI CATCHER VARIANTS (2) — additional bands
    # =====================================================================
    {
        "name": "IMSI Catcher (700 MHz LTE)",
        "protocol": "digital",
        "signal_class": "ofdm-1024",
        "threat_category": "imsi_catcher",
        "threat_level": "critical",
        "center_freq_hz": 740e6,
        "freq_min_hz": 728e6,
        "freq_max_hz": 756e6,
        "power_min_dbm": -20,
        "power_max_dbm": 20,
        "description": "LTE Band 12/13/17 rogue eNodeB — first responder/FirstNet intercept capable",
    },
    {
        "name": "IMSI Catcher (2600 MHz LTE)",
        "protocol": "digital",
        "signal_class": "ofdm-1024",
        "threat_category": "imsi_catcher",
        "threat_level": "critical",
        "center_freq_hz": 2620e6,
        "freq_min_hz": 2600e6,
        "freq_max_hz": 2640e6,
        "power_min_dbm": -15,
        "power_max_dbm": 15,
        "description": "LTE Band 7 rogue eNodeB — high-capacity urban IMSI catching",
    },
    # =====================================================================
    # PERIMETER INTRUSION (2) — Deepwoods-style new device detection
    # =====================================================================
    {
        "name": "New BLE Device in Secure Area",
        "protocol": "bluetooth",
        "signal_class": "2gfsk",
        "threat_category": "unknown_threat",
        "threat_level": "medium",
        "center_freq_hz": 2441e6,
        "freq_min_hz": 2402e6,
        "freq_max_hz": 2480e6,
        "description": "Previously unseen BLE device in monitored area — possible inserted surveillance",
    },
    {
        "name": "New WiFi Device in Secure Area",
        "protocol": "wifi",
        "signal_class": "ofdm-64",
        "threat_category": "unknown_threat",
        "threat_level": "medium",
        "center_freq_hz": 2442e6,
        "freq_min_hz": 2400e6,
        "freq_max_hz": 2484e6,
        "description": "Previously unseen WiFi device probing in monitored area — possible inserted device",
    },
]


class SignatureLibraryStore:
    """Reference IQ signature library backed by a :class:`SharedContext`.

    Parameters
    ----------
    ctx : SharedContext
        Shared infrastructure (connection, write lock, cache).
    """

    def __init__(self, ctx: Any) -> None:
        self._ctx = ctx
        self._ensure_table()

    def _ensure_table(self) -> None:
        """Create the reference_signatures table and add threat columns if missing."""
        _threat_columns = [
            ("threat_category", "TEXT DEFAULT ''"),
            ("threat_level", "TEXT DEFAULT ''"),
            ("freq_min_hz", "REAL"),
            ("freq_max_hz", "REAL"),
            ("burst_duration_ms", "REAL"),
            ("burst_interval_ms", "REAL"),
            ("power_min_dbm", "REAL"),
            ("power_max_dbm", "REAL"),
            ("active", "INTEGER DEFAULT 1"),
        ]
        with self._ctx.transaction() as conn:
            conn.executescript(_SIGNATURE_SCHEMA)
            # Add threat columns to existing tables (ALTER TABLE is idempotent via try/except)
            for col_name, col_type in _threat_columns:
                try:
                    conn.execute(
                        f"ALTER TABLE reference_signatures ADD COLUMN {col_name} {col_type}"
                    )
                except Exception:
                    pass  # column already exists

    # -- Serialization ------------------------------------------------------

    @staticmethod
    def _serialize_vec(vec: list[float]) -> bytes:
        """Pack a list of floats to little-endian float32 blob."""
        return struct.pack(f"<{len(vec)}f", *vec)

    @staticmethod
    def _deserialize_vec(blob: bytes) -> list[float]:
        """Unpack a little-endian float32 blob to a list of floats."""
        n = len(blob) // 4
        return list(struct.unpack(f"<{n}f", blob))

    # -- Row conversion -----------------------------------------------------

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        """Convert a database row to a dict with deserialized fields."""
        d = dict(row)
        if d.get("embedding"):
            d["embedding"] = self._deserialize_vec(d["embedding"])
        if d.get("features_48dim"):
            d["features_48dim"] = self._deserialize_vec(d["features_48dim"])
        if d.get("tags") and isinstance(d["tags"], str):
            try:
                d["tags"] = json.loads(d["tags"])
            except (json.JSONDecodeError, TypeError):
                d["tags"] = []
        if d.get("sigmf_metadata") and isinstance(d["sigmf_metadata"], str):
            try:
                d["sigmf_metadata"] = json.loads(d["sigmf_metadata"])
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    # -- Write operations ---------------------------------------------------

    def add_signature(
        self,
        name: str,
        protocol: str,
        signal_class: str,
        embedding: list[float] | None = None,
        features: list[float] | None = None,
        sig_id: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Store a new reference signature.

        Parameters
        ----------
        name : str
            Human-readable name for the signature.
        protocol : str
            Protocol type (e.g. wifi, bluetooth, zigbee).
        signal_class : str
            Modulation type (e.g. bpsk, qpsk).
        embedding : list[float] or None
            32-dim fingerprint embedding.
        features : list[float] or None
            49-dim DSP feature vector.
        sig_id : str or None
            Optional ID; generated if not provided.
        **kwargs
            Additional columns: center_freq_hz, bandwidth_hz, sample_rate_hz,
            iq_file_path, iq_samples, sigmf_metadata, tags, source, verified,
            description, created_by.

        Returns
        -------
        str
            The signature ID.
        """
        if sig_id is None:
            sig_id = str(uuid.uuid4())

        emb_blob = self._serialize_vec(embedding) if embedding else None
        feat_blob = self._serialize_vec(features) if features else None
        now = datetime.now(timezone.utc).isoformat()

        tags = kwargs.get("tags", [])
        if isinstance(tags, list):
            tags_str = json.dumps(tags)
        else:
            tags_str = tags

        sigmf = kwargs.get("sigmf_metadata")
        if isinstance(sigmf, dict):
            sigmf = json.dumps(sigmf)

        with self._ctx.write_transaction() as conn:
            conn.execute(
                """
                INSERT INTO reference_signatures
                    (id, name, protocol, signal_class, description,
                     center_freq_hz, bandwidth_hz, sample_rate_hz,
                     embedding, features_48dim,
                     iq_file_path, iq_samples,
                     sigmf_metadata,
                     threat_category, threat_level,
                     freq_min_hz, freq_max_hz,
                     burst_duration_ms, burst_interval_ms,
                     power_min_dbm, power_max_dbm, active,
                     tags, source, verified,
                     created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?)
                """,
                (
                    sig_id,
                    name,
                    protocol,
                    signal_class,
                    kwargs.get("description", ""),
                    kwargs.get("center_freq_hz"),
                    kwargs.get("bandwidth_hz"),
                    kwargs.get("sample_rate_hz"),
                    emb_blob,
                    feat_blob,
                    kwargs.get("iq_file_path"),
                    kwargs.get("iq_samples"),
                    sigmf,
                    kwargs.get("threat_category", ""),
                    kwargs.get("threat_level", ""),
                    kwargs.get("freq_min_hz"),
                    kwargs.get("freq_max_hz"),
                    kwargs.get("burst_duration_ms"),
                    kwargs.get("burst_interval_ms"),
                    kwargs.get("power_min_dbm"),
                    kwargs.get("power_max_dbm"),
                    1 if kwargs.get("active", True) else 0,
                    tags_str,
                    kwargs.get("source", ""),
                    1 if kwargs.get("verified") else 0,
                    kwargs.get("created_by", ""),
                    now,
                    now,
                ),
            )
        logger.debug("Reference signature stored: %s (name=%s)", sig_id, name)
        return sig_id

    # -- Read operations ----------------------------------------------------

    def get_signature(self, sig_id: str) -> dict[str, Any] | None:
        """Return a single reference signature by ID, or None."""
        conn = self._ctx.get_conn()
        row = conn.execute(
            "SELECT * FROM reference_signatures WHERE id = ?",
            (sig_id,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_dict(row)

    def list_signatures(
        self,
        protocol: str | None = None,
        signal_class: str | None = None,
        verified: bool | None = None,
        tags: list[str] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List reference signatures with optional filters.

        Parameters
        ----------
        protocol : str or None
            Filter by protocol.
        signal_class : str or None
            Filter by signal class.
        verified : bool or None
            Filter by verified flag.
        tags : list[str] or None
            Filter by tags (any tag must match).
        limit : int
            Maximum results.
        offset : int
            Pagination offset.

        Returns
        -------
        list[dict]
            Matching signatures, ordered by created_at DESC.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if protocol is not None:
            clauses.append("protocol = ?")
            params.append(protocol)
        if signal_class is not None:
            clauses.append("signal_class = ?")
            params.append(signal_class)
        if verified is not None:
            clauses.append("verified = ?")
            params.append(1 if verified else 0)

        where = " AND ".join(clauses) if clauses else "1=1"
        params.extend([limit, offset])

        conn = self._ctx.get_conn()
        rows = conn.execute(
            f"SELECT * FROM reference_signatures WHERE {where} "
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()

        results = [self._row_to_dict(r) for r in rows]

        # Post-filter by tags if needed (JSON array stored as text)
        if tags:
            tag_set = set(tags)
            results = [
                r
                for r in results
                if isinstance(r.get("tags"), list) and tag_set.intersection(r["tags"])
            ]

        return results

    # -- Similarity search --------------------------------------------------

    @staticmethod
    def _cosine_similarity(a: list[float], b: list[float]) -> float:
        """Compute cosine similarity between two vectors."""
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0.0 or norm_b == 0.0:
            return 0.0
        return dot / (norm_a * norm_b)

    def search_similar(
        self,
        embedding: list[float],
        top_k: int = 10,
        threshold: float = 0.5,
    ) -> list[dict[str, Any]]:
        """Search for reference signatures similar to the given embedding.

        Parameters
        ----------
        embedding : list[float]
            Query embedding vector (32 floats).
        top_k : int
            Maximum number of results.
        threshold : float
            Minimum cosine similarity threshold.

        Returns
        -------
        list[dict]
            Matching signatures with ``similarity`` field, sorted descending.
        """
        conn = self._ctx.get_conn()
        rows = conn.execute(
            "SELECT * FROM reference_signatures WHERE embedding IS NOT NULL"
        ).fetchall()

        results: list[tuple[float, dict[str, Any]]] = []
        for row in rows:
            d = self._row_to_dict(row)
            emb = d.get("embedding")
            if not emb or len(emb) != len(embedding):
                continue
            sim = self._cosine_similarity(embedding, emb)
            if sim >= threshold:
                d["similarity"] = round(sim, 6)
                results.append((sim, d))

        results.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in results[:top_k]]

    def match_signal(
        self,
        embedding: list[float],
        threshold: float = 0.8,
    ) -> dict[str, Any] | None:
        """Match an unknown signal against the library.

        Parameters
        ----------
        embedding : list[float]
            Query embedding vector.
        threshold : float
            Minimum cosine similarity to consider a match.

        Returns
        -------
        dict or None
            Best matching signature with ``similarity`` field, or None.
        """
        matches = self.search_similar(embedding, top_k=1, threshold=threshold)
        return matches[0] if matches else None

    def match_by_parameters(
        self,
        freq_hz: float | None = None,
        signal_class: str | None = None,
        power_dbm: float | None = None,
        bandwidth_hz: float | None = None,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Match threat signatures by signal parameters.

        Scores each active threat signature based on frequency range overlap,
        signal class match, power range, and bandwidth proximity.

        Parameters
        ----------
        freq_hz : float or None
            Center frequency of the observed signal.
        signal_class : str or None
            Classified signal type.
        power_dbm : float or None
            Observed signal power.
        bandwidth_hz : float or None
            Observed signal bandwidth.
        active_only : bool
            If True, only match active signatures.

        Returns
        -------
        list[dict]
            Matching signatures sorted by ``match_score`` descending.
        """
        where = ["threat_category != ''"]
        if active_only:
            where.append("active = 1")
        sql = f"SELECT * FROM reference_signatures WHERE {' AND '.join(where)}"
        conn = self._ctx.get_conn()
        rows = conn.execute(sql).fetchall()

        results: list[dict[str, Any]] = []
        for row in rows:
            d = self._row_to_dict(row)
            score = 0.0
            factors = 0

            # Frequency range scoring (soft decay at band edges)
            if freq_hz is not None:
                f_min = d.get("freq_min_hz")
                f_max = d.get("freq_max_hz")
                c_freq = d.get("center_freq_hz")
                if f_min is not None and f_max is not None:
                    span = (f_max - f_min) / 2 if f_max > f_min else 1.0
                    mid = (f_min + f_max) / 2
                    if f_min <= freq_hz <= f_max:
                        # Inside range — score by how centered
                        offset = abs(freq_hz - mid) / span if span > 0 else 0
                        score += 1.0 - 0.3 * offset  # 0.7–1.0
                        factors += 1
                    else:
                        # Outside range — soft decay within ±20% of band span
                        distance = min(abs(freq_hz - f_min), abs(freq_hz - f_max))
                        edge_pct = distance / span if span > 0 else 1.0
                        if edge_pct < 0.2:
                            score += 0.3 * (1.0 - edge_pct / 0.2)  # 0.0–0.3
                            factors += 1
                        else:
                            continue  # too far outside range
                elif c_freq is not None:
                    # Fallback: center_freq proximity (±50% bandwidth)
                    bw = d.get("bandwidth_hz") or 1e6
                    if abs(freq_hz - c_freq) < bw * 0.5:
                        score += 0.7
                        factors += 1
                    else:
                        continue
                # No freq info on sig — skip freq scoring
            else:
                factors += 1  # no freq given, don't penalize

            # Signal class scoring (with normalization)
            if signal_class is not None:
                sig_class = d.get("signal_class", "")
                # Normalize both sides so ofdm-64 matches ofdm, etc.
                det_norm = _normalize_class(signal_class)
                sig_norm = _normalize_class(sig_class)
                if sig_norm and det_norm.lower() == sig_norm.lower():
                    score += 1.0
                    factors += 1
                elif sig_class:
                    score += 0.2  # wrong class but freq matched
                    factors += 1
            else:
                factors += 1

            # Power range scoring
            if power_dbm is not None:
                p_min = d.get("power_min_dbm")
                p_max = d.get("power_max_dbm")
                if p_min is not None and p_max is not None:
                    if p_min <= power_dbm <= p_max:
                        score += 1.0
                    else:
                        score += 0.3  # out of power range but still a candidate
                    factors += 1

            # Bandwidth proximity scoring
            if bandwidth_hz is not None and d.get("bandwidth_hz"):
                ratio = min(bandwidth_hz, d["bandwidth_hz"]) / max(
                    bandwidth_hz, d["bandwidth_hz"]
                )
                score += ratio
                factors += 1

            if factors == 0:
                continue

            match_score = score / factors
            if match_score > 0.3:
                d["match_score"] = round(match_score, 4)
                results.append(d)

        results.sort(key=lambda x: x["match_score"], reverse=True)
        return results

    # -- Update operations --------------------------------------------------

    def update_signature(self, sig_id: str, **kwargs: Any) -> bool:
        """Update fields of a reference signature.

        Parameters
        ----------
        sig_id : str
            Signature ID.
        **kwargs
            Fields to update. Supported: name, protocol, signal_class,
            description, center_freq_hz, bandwidth_hz, sample_rate_hz,
            source, verified, created_by.

        Returns
        -------
        bool
            True if a row was updated.
        """
        allowed = {
            "name",
            "protocol",
            "signal_class",
            "description",
            "center_freq_hz",
            "bandwidth_hz",
            "sample_rate_hz",
            "source",
            "verified",
            "created_by",
            "threat_category",
            "threat_level",
            "freq_min_hz",
            "freq_max_hz",
            "burst_duration_ms",
            "burst_interval_ms",
            "power_min_dbm",
            "power_max_dbm",
            "active",
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        if "verified" in updates:
            updates["verified"] = 1 if updates["verified"] else 0

        now = datetime.now(timezone.utc).isoformat()
        set_clauses = ", ".join(f"{k} = ?" for k in updates)
        set_clauses += ", updated_at = ?"
        params = list(updates.values()) + [now, sig_id]

        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                f"UPDATE reference_signatures SET {set_clauses} WHERE id = ?",
                params,
            )
        return cursor.rowcount > 0

    # -- Delete -------------------------------------------------------------

    def delete_signature(self, sig_id: str) -> bool:
        """Delete a reference signature by ID.

        Returns
        -------
        bool
            True if a row was deleted.
        """
        with self._ctx.write_transaction() as conn:
            cursor = conn.execute(
                "DELETE FROM reference_signatures WHERE id = ?",
                (sig_id,),
            )
        return cursor.rowcount > 0

    # -- Tag management -----------------------------------------------------

    def add_tag(self, sig_id: str, tag: str) -> bool:
        """Add a tag to a signature.

        Returns
        -------
        bool
            True if updated.
        """
        sig = self.get_signature(sig_id)
        if sig is None:
            return False
        tags = sig.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        if tag in tags:
            return True  # already present
        tags.append(tag)
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "UPDATE reference_signatures SET tags = ?, updated_at = ? WHERE id = ?",
                (json.dumps(tags), now, sig_id),
            )
        return True

    def remove_tag(self, sig_id: str, tag: str) -> bool:
        """Remove a tag from a signature.

        Returns
        -------
        bool
            True if updated.
        """
        sig = self.get_signature(sig_id)
        if sig is None:
            return False
        tags = sig.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        if tag not in tags:
            return True  # not present, still success
        tags.remove(tag)
        now = datetime.now(timezone.utc).isoformat()
        with self._ctx.write_transaction() as conn:
            conn.execute(
                "UPDATE reference_signatures SET tags = ?, updated_at = ? WHERE id = ?",
                (json.dumps(tags), now, sig_id),
            )
        return True

    # -- Verify -------------------------------------------------------------

    def verify_signature(self, sig_id: str) -> bool:
        """Mark a signature as verified.

        Returns
        -------
        bool
            True if updated.
        """
        return self.update_signature(sig_id, verified=True)

    # -- Stats --------------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Return library statistics.

        Returns
        -------
        dict
            Keys: total, by_protocol, by_signal_class, verified_count.
        """
        conn = self._ctx.get_conn()

        total_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM reference_signatures"
        ).fetchone()
        total = total_row["cnt"] if total_row else 0

        proto_rows = conn.execute(
            "SELECT protocol, COUNT(*) as cnt "
            "FROM reference_signatures GROUP BY protocol"
        ).fetchall()
        by_protocol = {r["protocol"]: r["cnt"] for r in proto_rows}

        class_rows = conn.execute(
            "SELECT signal_class, COUNT(*) as cnt "
            "FROM reference_signatures GROUP BY signal_class"
        ).fetchall()
        by_signal_class = {r["signal_class"]: r["cnt"] for r in class_rows}

        ver_row = conn.execute(
            "SELECT COUNT(*) as cnt FROM reference_signatures WHERE verified = 1"
        ).fetchone()
        verified_count = ver_row["cnt"] if ver_row else 0

        return {
            "total": total,
            "by_protocol": by_protocol,
            "by_signal_class": by_signal_class,
            "verified_count": verified_count,
        }

    # -- Export / Import ----------------------------------------------------

    def export_signature(self, sig_id: str) -> dict[str, Any] | None:
        """Export a single signature with all metadata for external use.

        Returns
        -------
        dict or None
            Full signature record ready for JSON serialization, or None.
        """
        sig = self.get_signature(sig_id)
        if sig is None:
            return None
        # Remove internal fields that are not needed for export
        export = dict(sig)
        return export

    def export_signatures(
        self, sig_ids: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Export multiple signatures.

        Parameters
        ----------
        sig_ids : list[str] or None
            IDs to export. If None, export all.

        Returns
        -------
        list[dict]
            List of signature records.
        """
        if sig_ids is not None:
            return [
                s for sid in sig_ids if (s := self.export_signature(sid)) is not None
            ]
        return self.list_signatures(limit=10000)

    def import_signatures(self, data: list[dict[str, Any]]) -> int:
        """Bulk import signatures from JSON data.

        Parameters
        ----------
        data : list[dict]
            List of signature dicts. Each must have name, protocol, signal_class.

        Returns
        -------
        int
            Number of signatures imported.
        """
        count = 0
        for item in data:
            name = item.get("name")
            protocol = item.get("protocol")
            signal_class = item.get("signal_class")
            if not all([name, protocol, signal_class]):
                continue
            self.add_signature(
                name=name,
                protocol=protocol,
                signal_class=signal_class,
                embedding=item.get("embedding"),
                features=item.get("features_48dim"),
                sig_id=item.get("id"),
                description=item.get("description", ""),
                center_freq_hz=item.get("center_freq_hz"),
                bandwidth_hz=item.get("bandwidth_hz"),
                sample_rate_hz=item.get("sample_rate_hz"),
                iq_file_path=item.get("iq_file_path"),
                iq_samples=item.get("iq_samples"),
                sigmf_metadata=item.get("sigmf_metadata"),
                tags=item.get("tags", []),
                source=item.get("source", ""),
                verified=item.get("verified", False),
                created_by=item.get("created_by", ""),
            )
            count += 1
        return count

    # -- Threat signature operations ----------------------------------------

    def seed_threat_signatures(self) -> int:
        """Populate the library with curated TSCM threat signatures.

        Idempotent: skips signatures whose name already exists.

        Returns
        -------
        int
            Number of new signatures added (0 if already seeded).
        """
        existing = {s["name"] for s in self.list_signatures(limit=10000)}
        added = 0
        for threat in _THREAT_SEED_DATA:
            if threat["name"] in existing:
                continue
            self.add_signature(
                name=threat["name"],
                protocol=threat["protocol"],
                signal_class=threat["signal_class"],
                description=threat.get("description", ""),
                threat_category=threat.get("threat_category", ""),
                threat_level=threat.get("threat_level", ""),
                freq_min_hz=threat.get("freq_min_hz"),
                freq_max_hz=threat.get("freq_max_hz"),
                burst_duration_ms=threat.get("burst_duration_ms"),
                burst_interval_ms=threat.get("burst_interval_ms"),
                power_min_dbm=threat.get("power_min_dbm"),
                power_max_dbm=threat.get("power_max_dbm"),
                source="seed",
                verified=True,
                tags=["threat", threat.get("threat_category", "")],
            )
            added += 1
        if added:
            logger.info("Seeded %d threat signatures", added)
        return added

    def get_threat_signatures(
        self,
        threat_category: str | None = None,
        threat_level: str | None = None,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Return threat signatures with optional filtering.

        Parameters
        ----------
        threat_category : str or None
            Filter by category (e.g. "covert_mic", "gsm_bug").
        threat_level : str or None
            Filter by level (e.g. "critical", "high", "medium", "low").
        active_only : bool
            If True, only return active signatures.

        Returns
        -------
        list[dict]
            Matching threat signatures.
        """
        where = ["threat_category != ''"]
        params: list[Any] = []
        if threat_category:
            where.append("threat_category = ?")
            params.append(threat_category)
        if threat_level:
            where.append("threat_level = ?")
            params.append(threat_level)
        if active_only:
            where.append("active = 1")

        sql = f"SELECT * FROM reference_signatures WHERE {' AND '.join(where)} ORDER BY threat_level, name"
        conn = self._ctx.get_conn()
        conn.row_factory = self._ctx.get_conn().row_factory
        rows = conn.execute(sql, params).fetchall()
        return [self._row_to_dict(r) for r in rows]
