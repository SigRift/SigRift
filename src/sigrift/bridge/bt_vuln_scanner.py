"""Bluetooth vulnerability scanner for SigRift.

Analyzes Bluetooth devices for known vulnerabilities (CVE-based), protocol
weaknesses, risky service exposure, and behavioral anomalies.  Produces a
per-device risk assessment with composite scoring.

The scanner is **stateless** -- it operates on device-info dicts produced
by :class:`BtScanner` and stored via :class:`BtMetadataStore`.  No
persistent state or background threads are required.

Usage::

    scanner = BtVulnScanner()
    result  = scanner.assess_device(device_info)
    batch   = scanner.assess_batch(device_list)
    summary = scanner.get_risk_summary(batch)

Scoring
-------
Each device receives four sub-scores in [0.0, 1.0]:

* ``protocol_risk``      -- protocol version & pairing weaknesses
* ``service_exposure``    -- risky or unusual service profiles
* ``vuln_match``          -- CVE-based vulnerability matches
* ``behavioral_anomaly``  -- runtime behavioral red flags

A weighted composite produces the final ``risk_score``.  Risk levels are
mapped from the composite: ``safe``, ``low_risk``, ``medium_risk``,
``high_risk``, ``critical``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OUI prefix -> manufacturer (common BT chipset vendors, trimmed set)
# ---------------------------------------------------------------------------

_OUI_DB: dict[str, str] = {
    "00:1A:7D": "Cyber-Blue(ShenZhen)",
    "00:02:72": "CC&C Technologies",
    "00:07:80": "Bluegiga Technologies",
    "00:0F:DE": "Sony Mobile",
    "00:12:6F": "Raylink",
    "00:15:83": "IVT Corporation",
    "00:17:C9": "Samsung Electronics",
    "00:18:09": "Cresyn",
    "00:19:86": "Partnerships in Care",
    "00:1B:DC": "Vencer",
    "00:1E:3D": "Alps Electric",
    "00:1E:45": "Sony Mobile",
    "00:21:3E": "TomTom",
    "00:22:D0": "Polar Electro",
    "00:23:76": "HTC Corporation",
    "00:24:1C": "FuGang Electronic",
    "00:25:D3": "Azurewave Technologies",
    "00:26:43": "Alps Electric",
    "00:26:7E": "Parrot",
    "00:26:B4": "Ford Motor Company",
    "00:27:13": "Universal Electronics",
    "00:50:CD": "Philips Sound Solutions",
    "00:60:57": "Murata Manufacturing",
    "00:80:25": "Stollmann E+V",
    "04:52:C7": "Bose Corporation",
    "04:E4:51": "Texas Instruments",
    "08:3E:8E": "Samsung Electronics",
    "0C:E0:E4": "Plantronics",
    "10:2C:6B": "Microsoft",
    "14:07:08": "Private",
    "18:2A:7B": "Nintendo",
    "1C:52:16": "Amazon Technologies",
    "20:68:9D": "Texas Instruments",
    "28:11:A5": "Bose Corporation",
    "2C:41:A1": "Bose Corporation",
    "30:21:19": "LG Electronics",
    "34:14:B5": "Qualcomm Technologies",
    "38:01:95": "Samsung Electronics",
    "40:4E:36": "HTC Corporation",
    "44:D8:84": "Apple",
    "48:A4:93": "Apple",
    "4C:32:75": "Apple",
    "50:32:37": "Apple",
    "54:40:AD": "Samsung Electronics",
    "58:CB:52": "Google",
    "5C:F3:70": "Google",
    "60:A4:4C": "ASUSTek Computer",
    "64:A2:F9": "OnePlus Technology",
    "68:D9:3C": "Apple",
    "6C:AB:31": "Apple",
    "70:56:81": "Apple",
    "74:E1:4A": "Apple",
    "78:CA:39": "Apple",
    "7C:D1:C3": "Apple",
    "80:BE:05": "Apple",
    "84:38:35": "Apple",
    "88:E9:FE": "Apple",
    "8C:85:90": "Apple",
    "90:B2:1F": "Apple",
    "94:E9:79": "Apple",
    "98:46:0A": "Apple",
    "9C:8D:7C": "Apple",
    "A0:E4:53": "Apple",
    "A4:D1:8C": "Apple",
    "A8:51:AB": "Apple",
    "AC:BC:32": "Apple",
    "B0:34:95": "Apple",
    "B4:F1:DA": "Apple",
    "B8:63:4D": "Apple",
    "BC:6C:21": "Apple",
    "C0:D0:12": "Apple",
    "C8:69:CD": "Apple",
    "CC:08:8D": "Apple",
    "D0:03:4B": "Apple",
    "D4:61:9D": "Apple",
    "D8:A2:5E": "Apple",
    "DC:2B:2A": "Apple",
    "E0:5F:45": "Apple",
    "E4:CE:8F": "Apple",
    "E8:80:2E": "Apple",
    "EC:85:2F": "Apple",
    "F0:18:98": "Apple",
    "F4:0F:24": "Apple",
    "F8:E0:79": "Motorola Mobility",
    "FC:25:3F": "Apple",
}

# ---------------------------------------------------------------------------
# Well-known BT service UUIDs -> service names and risk metadata
# ---------------------------------------------------------------------------

# UUID-16 values (as lowercase hex strings without dashes)
_SERVICE_UUID_MAP: dict[str, tuple[str, float]] = {
    # (service_name, inherent_risk 0-1)
    "1101": ("SPP - Serial Port", 0.5),
    "1102": ("LAN Access", 0.4),
    "1103": ("Dialup Networking", 0.6),
    "1104": ("IrMC Sync", 0.3),
    "1105": ("OBEX Object Push", 0.7),
    "1106": ("OBEX File Transfer", 0.8),
    "1107": ("IrMC Sync Command", 0.3),
    "1108": ("Headset", 0.1),
    "110a": ("A2DP Source", 0.1),
    "110b": ("A2DP Sink", 0.1),
    "110c": ("AVRCP Target", 0.1),
    "110d": ("Advanced Audio", 0.1),
    "110e": ("AVRCP Controller", 0.1),
    "1112": ("Headset AG", 0.1),
    "1115": ("PAN PANU", 0.5),
    "1116": ("PAN NAP", 0.6),
    "1117": ("PAN GN", 0.5),
    "1124": ("HID", 0.7),
    "112d": ("SIM Access", 0.8),
    "112f": ("Phonebook Access PCE", 0.6),
    "1130": ("Phonebook Access PSE", 0.6),
    "1132": ("Message Access Server", 0.6),
    "1133": ("Message Notification Server", 0.5),
    "1200": ("PnP Information", 0.2),
    "1800": ("Generic Access", 0.1),
    "1801": ("Generic Attribute", 0.1),
    "180a": ("Device Information", 0.2),
    "180f": ("Battery Service", 0.1),
    "1812": ("HID over GATT", 0.7),
    "fe2c": ("Google Fast Pair", 0.1),
}

# High-risk service short names for anomaly detection
_HIGH_RISK_SERVICES = {
    "OBEX Object Push",
    "OBEX File Transfer",
    "HID",
    "HID over GATT",
    "SIM Access",
    "SPP - Serial Port",
}

# Services that are suspicious on non-input devices
_INPUT_SERVICES = {"HID", "HID over GATT"}

# ---------------------------------------------------------------------------
# Known vulnerability database (CVE-based)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KnownVuln:
    """Descriptor for a known Bluetooth vulnerability."""

    cve_id: str
    name: str
    severity: float  # 0.0–1.0
    description: str
    affected_versions: tuple[str, ...]  # BT version strings like "4.0", "5.0"
    affected_device_types: tuple[str, ...]  # "classic", "ble", "dual", ""
    min_bt_version: str  # Minimum affected version (inclusive)
    max_bt_version: str  # Maximum affected version (inclusive)
    extra_condition: str  # Additional condition key for matching logic


_KNOWN_VULNS: list[KnownVuln] = [
    KnownVuln(
        cve_id="CVE-2017-0781",
        name="BlueBorne (RCE)",
        severity=0.95,
        description=(
            "Remote code execution via Bluetooth on Linux/Android. "
            "Affects devices running BT protocol versions below 5.0 on "
            "Linux and Android platforms."
        ),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2"),
        affected_device_types=("classic", "dual", "ble"),
        min_bt_version="2.0",
        max_bt_version="4.2",
        extra_condition="linux_android",
    ),
    KnownVuln(
        cve_id="CVE-2017-0782",
        name="BlueBorne (BNEP)",
        severity=0.90,
        description=(
            "Bluetooth Network Encapsulation Protocol vulnerability "
            "allowing privilege escalation on Android."
        ),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2"),
        affected_device_types=("classic", "dual"),
        min_bt_version="2.0",
        max_bt_version="4.2",
        extra_condition="linux_android",
    ),
    KnownVuln(
        cve_id="CVE-2017-0783",
        name="BlueBorne (PAN MitM)",
        severity=0.85,
        description=("Man-in-the-middle attack via Bluetooth PAN profile on Android."),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2"),
        affected_device_types=("classic", "dual"),
        min_bt_version="2.0",
        max_bt_version="4.2",
        extra_condition="linux_android",
    ),
    KnownVuln(
        cve_id="CVE-2017-0785",
        name="BlueBorne (Info Leak)",
        severity=0.70,
        description=("Information disclosure via Bluetooth SDP on Android."),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2"),
        affected_device_types=("classic", "dual"),
        min_bt_version="2.0",
        max_bt_version="4.2",
        extra_condition="linux_android",
    ),
    KnownVuln(
        cve_id="CVE-2019-9506",
        name="KNOB",
        severity=0.80,
        description=(
            "Key Negotiation of Bluetooth attack. Forces encryption key "
            "entropy down to 1 byte on devices that do not enforce a "
            "minimum 7-byte entropy requirement."
        ),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2", "5.0"),
        affected_device_types=("classic", "dual"),
        min_bt_version="2.0",
        max_bt_version="5.0",
        extra_condition="no_min_entropy",
    ),
    KnownVuln(
        cve_id="CVE-2020-15802",
        name="BLURtooth",
        severity=0.75,
        description=(
            "Cross-Transport Key Derivation vulnerability in dual-mode "
            "(BR/EDR + BLE) devices allowing key overwrite and MitM."
        ),
        affected_versions=("4.0", "4.1", "4.2", "5.0"),
        affected_device_types=("dual",),
        min_bt_version="4.0",
        max_bt_version="5.0",
        extra_condition="dual_mode",
    ),
    KnownVuln(
        cve_id="CVE-2020-SWEYNTOOTH",
        name="SweynTooth",
        severity=0.70,
        description=(
            "Family of BLE implementation vulnerabilities affecting "
            "BLE 4.x and 5.0 SoCs from multiple vendors. Can cause "
            "crashes, deadlocks, and security bypasses."
        ),
        affected_versions=("4.0", "4.1", "4.2", "5.0"),
        affected_device_types=("ble", "dual"),
        min_bt_version="4.0",
        max_bt_version="5.0",
        extra_condition="ble_device",
    ),
    KnownVuln(
        cve_id="CVE-2020-10135",
        name="BIAS",
        severity=0.80,
        description=(
            "Bluetooth Impersonation AttackS. Allows impersonation of "
            "a previously paired device if Secure Connections are not "
            "enforced."
        ),
        affected_versions=("2.0", "2.1", "3.0", "4.0", "4.1", "4.2", "5.0"),
        affected_device_types=("classic", "dual"),
        min_bt_version="2.0",
        max_bt_version="5.0",
        extra_condition="no_secure_connections",
    ),
    KnownVuln(
        cve_id="CVE-2021-BRAKTOOTH",
        name="BrakTooth",
        severity=0.75,
        description=(
            "Family of vulnerabilities in commercial BT Classic firmware. "
            "Affects BR/EDR chipsets implementing BT 3.0 through 5.2, "
            "enabling DoS and potentially RCE."
        ),
        affected_versions=("3.0", "4.0", "4.1", "4.2", "5.0", "5.1", "5.2"),
        affected_device_types=("classic", "dual"),
        min_bt_version="3.0",
        max_bt_version="5.2",
        extra_condition="classic_chipset",
    ),
    KnownVuln(
        cve_id="CVE-2023-24023",
        name="BLUFFS",
        severity=0.85,
        description=(
            "Bluetooth Forward and Future Secrecy attacks. Exploits "
            "session key derivation flaws in BT 4.2 through 5.4, "
            "enabling session key compromise."
        ),
        affected_versions=("4.2", "5.0", "5.1", "5.2", "5.3", "5.4"),
        affected_device_types=("classic", "ble", "dual"),
        min_bt_version="4.2",
        max_bt_version="5.4",
        extra_condition="",
    ),
]

# ---------------------------------------------------------------------------
# BT version utilities
# ---------------------------------------------------------------------------

_BT_VERSION_ORDER: list[str] = [
    "1.0",
    "1.1",
    "1.2",
    "2.0",
    "2.1",
    "3.0",
    "4.0",
    "4.1",
    "4.2",
    "5.0",
    "5.1",
    "5.2",
    "5.3",
    "5.4",
]

_DEPRECATED_VERSIONS = {"1.0", "1.1", "1.2", "2.0", "2.1", "3.0"}


def _version_index(v: str) -> int:
    """Return the ordinal index for a BT version string, or -1 if unknown."""
    try:
        return _BT_VERSION_ORDER.index(v)
    except ValueError:
        return -1


def _version_in_range(version: str, min_ver: str, max_ver: str) -> bool:
    """Return True if *version* falls within [min_ver, max_ver] inclusive."""
    vi = _version_index(version)
    lo = _version_index(min_ver)
    hi = _version_index(max_ver)
    if vi < 0 or lo < 0 or hi < 0:
        return False
    return lo <= vi <= hi


# ---------------------------------------------------------------------------
# Device-class parsing helpers
# ---------------------------------------------------------------------------

_DEVICE_CLASS_MAJOR: dict[int, str] = {
    0x01: "Computer",
    0x02: "Phone",
    0x03: "LAN/Network AP",
    0x04: "Audio/Video",
    0x05: "Peripheral",
    0x06: "Imaging",
    0x07: "Wearable",
    0x08: "Toy",
    0x09: "Health",
    0x1F: "Uncategorized",
}

_INPUT_MAJOR_CLASSES = {0x05}  # Peripheral


def _parse_major_class(device_class: int) -> tuple[int, str]:
    """Extract the major device class from a CoD (Class of Device) integer."""
    major = (device_class >> 8) & 0x1F
    return major, _DEVICE_CLASS_MAJOR.get(major, "Unknown")


# ---------------------------------------------------------------------------
# MAC randomization detection
# ---------------------------------------------------------------------------


def _is_random_mac(mac: str) -> bool:
    """Detect whether a MAC address uses BLE random addressing.

    BLE random addresses have the two most-significant bits of the first
    octet set (``11xxxxxx``), making the first octet an odd number with
    the locally-administered bit set.  We check the second-least-significant
    bit of the first octet (the "locally administered" / U/L bit).
    """
    if not mac:
        return False
    clean = mac.replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 2:
        return False
    try:
        first_octet = int(clean[:2], 16)
    except ValueError:
        return False
    # Locally-administered bit (bit 1) set indicates random/private address
    return bool(first_octet & 0x02)


# ---------------------------------------------------------------------------
# Risk level mapping
# ---------------------------------------------------------------------------

_RISK_LEVELS = [
    (0.0, "safe"),
    (0.20, "low_risk"),
    (0.45, "medium_risk"),
    (0.70, "high_risk"),
    (0.85, "critical"),
]


def _risk_level(score: float) -> str:
    """Map a composite risk score to a human-readable level string."""
    level = "safe"
    for threshold, name in _RISK_LEVELS:
        if score >= threshold:
            level = name
    return level


# ---------------------------------------------------------------------------
# BtVulnScanner
# ---------------------------------------------------------------------------


class BtVulnScanner:
    """Stateless Bluetooth vulnerability and risk scanner.

    Analyzes device info dicts (as produced by :class:`BtScanner` /
    :class:`BtMetadataStore`) for protocol weaknesses, CVE matches,
    service exposure, and behavioral anomalies.

    Parameters
    ----------
    weights : dict[str, float] | None
        Override the default composite-score weights.  Keys are
        ``protocol_risk``, ``service_exposure``, ``vuln_match``,
        ``behavioral_anomaly``.  Values are relative weights (they are
        normalised internally).
    """

    DEFAULT_WEIGHTS: dict[str, float] = {
        "protocol_risk": 0.20,
        "service_exposure": 0.20,
        "vuln_match": 0.40,
        "behavioral_anomaly": 0.20,
    }

    def __init__(
        self,
        weights: dict[str, float] | None = None,
    ) -> None:
        w = dict(self.DEFAULT_WEIGHTS)
        if weights:
            for k in w:
                if k in weights:
                    w[k] = float(weights[k])
        total = sum(w.values()) or 1.0
        self._weights = {k: v / total for k, v in w.items()}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess_device(self, device_info: dict[str, Any]) -> dict[str, Any]:
        """Perform a full vulnerability assessment of a single device.

        Parameters
        ----------
        device_info : dict
            Device record as returned by the BT metadata store.  Expected
            keys include ``device_addr``, ``device_name``, ``device_type``,
            ``device_class``, ``rssi_dbm`` (or ``avg_rssi_dbm``),
            ``service_uuids``, ``manufacturer``, ``connectable``, ``bonded``.

        Returns
        -------
        dict
            Assessment result with keys:
            ``device_addr``, ``device_name``, ``bt_version``,
            ``manufacturer``, ``is_random_mac``, ``major_device_class``,
            ``protocol_risk``, ``service_exposure``, ``vuln_match``,
            ``behavioral_anomaly``, ``risk_score``, ``risk_level``,
            ``matched_cves``, ``risky_services``, ``flags``.
        """
        addr = device_info.get("device_addr", "")
        name = device_info.get("device_name", "")
        dev_type = device_info.get("device_type", "unknown")
        dev_class = device_info.get("device_class", 0)
        rssi = device_info.get("rssi_dbm") or device_info.get("avg_rssi_dbm") or 0.0
        service_uuids = device_info.get("service_uuids") or []
        manufacturer = device_info.get("manufacturer", "")
        connectable = device_info.get("connectable", False)
        bonded = device_info.get("bonded", False)

        # Normalise service_uuids from JSON string if needed
        if isinstance(service_uuids, str):
            try:
                import json as _json

                service_uuids = _json.loads(service_uuids)
            except (ValueError, TypeError):
                service_uuids = []

        bt_version = self._infer_bt_version(dev_type, device_info)
        oui_manufacturer = self._lookup_oui(addr)
        if not manufacturer and oui_manufacturer:
            manufacturer = oui_manufacturer

        random_mac = _is_random_mac(addr)
        major_class_id, major_class_name = _parse_major_class(dev_class)

        # -- Sub-scores ------------------------------------------------
        protocol_result = self._score_protocol(
            bt_version,
            dev_type,
            connectable,
            bonded,
            random_mac,
        )
        service_result = self._score_services(
            service_uuids,
            major_class_id,
            dev_type,
        )
        vuln_result = self._score_vulns(
            bt_version,
            dev_type,
            connectable,
            bonded,
            service_uuids,
        )
        behavioral_result = self._score_behavior(
            device_info,
            rssi,
            random_mac,
            service_uuids,
            major_class_id,
        )

        # -- Composite -------------------------------------------------
        composite = (
            self._weights["protocol_risk"] * protocol_result["score"]
            + self._weights["service_exposure"] * service_result["score"]
            + self._weights["vuln_match"] * vuln_result["score"]
            + self._weights["behavioral_anomaly"] * behavioral_result["score"]
        )
        composite = round(min(1.0, max(0.0, composite)), 4)

        # Collect all flags
        flags: list[str] = (
            protocol_result["flags"]
            + service_result["flags"]
            + vuln_result["flags"]
            + behavioral_result["flags"]
        )

        return {
            "device_addr": addr,
            "device_name": name,
            "device_type": dev_type,
            "bt_version": bt_version,
            "manufacturer": manufacturer,
            "oui_manufacturer": oui_manufacturer,
            "is_random_mac": random_mac,
            "major_device_class": major_class_name,
            "protocol_risk": round(protocol_result["score"], 4),
            "service_exposure": round(service_result["score"], 4),
            "vuln_match": round(vuln_result["score"], 4),
            "behavioral_anomaly": round(behavioral_result["score"], 4),
            "risk_score": composite,
            "risk_level": _risk_level(composite),
            "matched_cves": vuln_result["matched_cves"],
            "risky_services": service_result["risky_services"],
            "flags": flags,
        }

    def assess_batch(
        self,
        devices: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Assess a batch of devices.

        Parameters
        ----------
        devices : list[dict]
            List of device-info dicts.

        Returns
        -------
        list[dict]
            List of assessment results, one per device, sorted by
            ``risk_score`` descending.
        """
        results = [self.assess_device(d) for d in devices]
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def get_risk_summary(
        self,
        assessments: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Produce an aggregate risk summary from a list of assessments.

        Parameters
        ----------
        assessments : list[dict]
            Assessment dicts as returned by :meth:`assess_device` or
            :meth:`assess_batch`.

        Returns
        -------
        dict
            Summary with keys: ``total_devices``, ``risk_distribution``,
            ``avg_risk_score``, ``max_risk_score``, ``critical_devices``,
            ``cve_frequency``, ``top_flags``.
        """
        if not assessments:
            return {
                "total_devices": 0,
                "risk_distribution": {
                    "safe": 0,
                    "low_risk": 0,
                    "medium_risk": 0,
                    "high_risk": 0,
                    "critical": 0,
                },
                "avg_risk_score": 0.0,
                "max_risk_score": 0.0,
                "critical_devices": [],
                "cve_frequency": {},
                "top_flags": [],
            }

        risk_dist: dict[str, int] = {
            "safe": 0,
            "low_risk": 0,
            "medium_risk": 0,
            "high_risk": 0,
            "critical": 0,
        }
        cve_freq: dict[str, int] = {}
        flag_freq: dict[str, int] = {}
        total_score = 0.0
        max_score = 0.0
        critical_devices: list[dict[str, Any]] = []

        for a in assessments:
            level = a.get("risk_level", "safe")
            risk_dist[level] = risk_dist.get(level, 0) + 1

            score = a.get("risk_score", 0.0)
            total_score += score
            if score > max_score:
                max_score = score

            if level in ("high_risk", "critical"):
                critical_devices.append(
                    {
                        "device_addr": a.get("device_addr", ""),
                        "device_name": a.get("device_name", ""),
                        "risk_score": score,
                        "risk_level": level,
                        "matched_cves": a.get("matched_cves", []),
                    }
                )

            for cve in a.get("matched_cves", []):
                cve_id = cve.get("cve_id", "")
                if cve_id:
                    cve_freq[cve_id] = cve_freq.get(cve_id, 0) + 1

            for f in a.get("flags", []):
                flag_freq[f] = flag_freq.get(f, 0) + 1

        n = len(assessments)
        top_flags = sorted(flag_freq.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_devices": n,
            "risk_distribution": risk_dist,
            "avg_risk_score": round(total_score / n, 4) if n else 0.0,
            "max_risk_score": round(max_score, 4),
            "critical_devices": critical_devices,
            "cve_frequency": cve_freq,
            "top_flags": [{"flag": f, "count": c} for f, c in top_flags],
        }

    # ------------------------------------------------------------------
    # Protocol risk scoring
    # ------------------------------------------------------------------

    def _score_protocol(
        self,
        bt_version: str,
        device_type: str,
        connectable: bool,
        bonded: bool,
        random_mac: bool,
    ) -> dict[str, Any]:
        """Score protocol-level risks.

        Checks BT version deprecation, pairing mode exposure, MAC
        randomization, and secure connections support.
        """
        score = 0.0
        flags: list[str] = []

        # Deprecated protocol version
        if bt_version in _DEPRECATED_VERSIONS:
            score += 0.4
            flags.append(f"deprecated_bt_version:{bt_version}")

        # Version-based risk gradient
        vi = _version_index(bt_version)
        if 0 <= vi <= 4:
            # BT 1.x-2.x: high protocol risk
            score += 0.3
        elif 5 <= vi <= 5:
            # BT 3.0: moderate
            score += 0.15
        elif 6 <= vi <= 8:
            # BT 4.x: some risk
            score += 0.05

        # Discoverable / connectable = pairing risk
        if connectable and not bonded:
            score += 0.15
            flags.append("connectable_not_bonded")

        # Non-randomized MAC = privacy risk
        if not random_mac:
            score += 0.10
            flags.append("non_randomized_mac")

        return {
            "score": min(1.0, score),
            "flags": flags,
        }

    # ------------------------------------------------------------------
    # Service exposure scoring
    # ------------------------------------------------------------------

    def _score_services(
        self,
        service_uuids: list[str],
        major_class_id: int,
        device_type: str,
    ) -> dict[str, Any]:
        """Score based on exposed service profiles.

        Flags high-risk services (OBEX, FTP, HID, SIM Access, SPP) and
        detects unusual service profiles (e.g., HID on a non-peripheral
        device).
        """
        score = 0.0
        flags: list[str] = []
        risky_services: list[dict[str, Any]] = []

        resolved = self._resolve_services(service_uuids)

        for svc_name, svc_risk in resolved:
            if svc_risk >= 0.5:
                risky_services.append(
                    {
                        "service": svc_name,
                        "risk": round(svc_risk, 2),
                    }
                )
                flags.append(f"risky_service:{svc_name}")
            # Accumulate (capped)
            score += svc_risk * 0.15

        # Anomalous service profile: HID on non-input device
        has_input_service = any(svc_name in _INPUT_SERVICES for svc_name, _ in resolved)
        if has_input_service and major_class_id not in _INPUT_MAJOR_CLASSES:
            score += 0.25
            flags.append("hid_on_non_input_device")

        # Many exposed services
        if len(resolved) > 6:
            score += 0.10
            flags.append(f"many_services_exposed:{len(resolved)}")

        return {
            "score": min(1.0, score),
            "flags": flags,
            "risky_services": risky_services,
        }

    # ------------------------------------------------------------------
    # CVE / vulnerability matching
    # ------------------------------------------------------------------

    def _score_vulns(
        self,
        bt_version: str,
        device_type: str,
        connectable: bool,
        bonded: bool,
        service_uuids: list[str],
    ) -> dict[str, Any]:
        """Match device characteristics against known CVEs.

        Each matched CVE contributes its severity (weighted) to the
        overall vuln score.  The score is capped at 1.0.
        """
        score = 0.0
        flags: list[str] = []
        matched_cves: list[dict[str, Any]] = []

        is_dual = device_type == "dual"
        is_classic = device_type in ("classic", "dual")
        is_ble = device_type in ("ble", "dual")

        for vuln in _KNOWN_VULNS:
            # Version range check
            if bt_version and not _version_in_range(
                bt_version,
                vuln.min_bt_version,
                vuln.max_bt_version,
            ):
                continue

            # Device type check (empty means all types)
            if (
                vuln.affected_device_types
                and device_type not in vuln.affected_device_types
            ):
                continue

            # Extra condition checks
            match = True
            if vuln.extra_condition == "dual_mode" and not is_dual:
                match = False
            elif vuln.extra_condition == "ble_device" and not is_ble:
                match = False
            elif vuln.extra_condition == "classic_chipset" and not is_classic:
                match = False
            elif vuln.extra_condition == "no_secure_connections" and bonded:
                # Bonded devices are more likely to have Secure Connections;
                # still flag but at reduced severity.
                pass
            elif vuln.extra_condition == "no_min_entropy":
                # Cannot definitively verify entropy enforcement from scan
                # data alone; flag as potential risk.
                pass
            elif vuln.extra_condition == "linux_android":
                # From scan data we cannot determine the remote OS, so we
                # flag all devices in the affected version range as
                # *potentially* vulnerable.
                pass

            if not match:
                continue

            matched_cves.append(
                {
                    "cve_id": vuln.cve_id,
                    "name": vuln.name,
                    "severity": vuln.severity,
                    "description": vuln.description,
                }
            )
            score += vuln.severity * 0.20
            flags.append(f"cve:{vuln.cve_id}:{vuln.name}")

        return {
            "score": min(1.0, score),
            "flags": flags,
            "matched_cves": matched_cves,
        }

    # ------------------------------------------------------------------
    # Behavioral anomaly scoring
    # ------------------------------------------------------------------

    def _score_behavior(
        self,
        device_info: dict[str, Any],
        rssi: float,
        random_mac: bool,
        service_uuids: list[str],
        major_class_id: int,
    ) -> dict[str, Any]:
        """Score behavioral anomalies observable from a single snapshot.

        Detects:
        - Signal strength anomalies (unusually strong or variable RSSI)
        - Drive-by indicators (low observation count)
        - Excessive MAC churn indicators
        - Mismatched name/class patterns
        """
        score = 0.0
        flags: list[str] = []

        # RSSI anomaly: extremely strong signal (potential proximity attack)
        if rssi != 0.0 and rssi > -20.0:
            score += 0.15
            flags.append(f"unusually_strong_rssi:{rssi:.0f}dBm")

        # RSSI anomaly: suspiciously variable (if min/max available)
        min_rssi = device_info.get("min_rssi_dbm")
        max_rssi = device_info.get("max_rssi_dbm")
        if min_rssi is not None and max_rssi is not None:
            rssi_range = abs(max_rssi - min_rssi)
            if rssi_range > 40:
                score += 0.20
                flags.append(f"rssi_variance_high:{rssi_range:.0f}dB_range")

        # Drive-by: low observation count suggests device appeared briefly
        obs = device_info.get("observation_count", 0)
        if 0 < obs <= 2:
            score += 0.15
            flags.append("possible_drive_by")

        # Excessive connection attempts (if tracked)
        conn_attempts = device_info.get("connection_attempts", 0)
        if conn_attempts > 10:
            score += 0.25
            flags.append(f"excessive_connection_attempts:{conn_attempts}")

        # Rapid MAC changes indicator: random MAC with very low obs
        if random_mac and 0 < obs <= 1:
            score += 0.10
            flags.append("rapid_mac_rotation_suspected")

        # Name/class mismatch: device claims to be audio but exposes HID
        resolved = self._resolve_services(service_uuids)
        has_hid = any(n in _INPUT_SERVICES for n, _ in resolved)
        # Major class 0x04 = Audio/Video
        if has_hid and major_class_id == 0x04:
            score += 0.20
            flags.append("hid_service_on_audio_device")

        # Empty name on connectable device (hiding identity)
        name = device_info.get("device_name", "")
        connectable = device_info.get("connectable", False)
        if connectable and not name:
            score += 0.05
            flags.append("unnamed_connectable_device")

        return {
            "score": min(1.0, score),
            "flags": flags,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _infer_bt_version(
        self,
        device_type: str,
        device_info: dict[str, Any],
    ) -> str:
        """Best-effort BT version inference from available device data.

        Uses explicit ``bt_version`` if present, otherwise infers from
        ``device_type`` and advertised capabilities.
        """
        # Explicit version if provided
        explicit = device_info.get("bt_version", "")
        if explicit:
            return explicit

        # Infer from device_type
        if device_type == "ble":
            # BLE was introduced in 4.0
            return "4.0"
        elif device_type == "classic":
            # Classic-only devices are typically older; assume 3.0 as
            # conservative baseline (BR/EDR without LE)
            return "3.0"
        elif device_type == "dual":
            # Dual-mode = BR/EDR + LE, available from 4.0+
            return "4.0"

        return ""

    def _lookup_oui(self, addr: str) -> str:
        """Look up the manufacturer from the OUI prefix of a MAC address.

        Parameters
        ----------
        addr : str
            MAC address in colon-separated format (e.g., ``AA:BB:CC:DD:EE:FF``).

        Returns
        -------
        str
            Manufacturer name, or empty string if not found.
        """
        if not addr or len(addr) < 8:
            return ""
        # Normalise to colon format
        clean = addr.replace("-", ":").replace(".", ":")
        prefix = clean[:8].upper()
        return _OUI_DB.get(prefix, "")

    def _resolve_services(
        self,
        service_uuids: list[str],
    ) -> list[tuple[str, float]]:
        """Resolve a list of service UUIDs to (name, risk) tuples.

        Handles full 128-bit UUIDs (extracts the 16-bit short form from
        the Bluetooth Base UUID pattern) and raw 16-bit hex values.
        """
        results: list[tuple[str, float]] = []
        seen: set[str] = set()

        for uuid_str in service_uuids:
            if not uuid_str:
                continue
            short = self._extract_uuid16(uuid_str)
            if short and short not in seen:
                seen.add(short)
                entry = _SERVICE_UUID_MAP.get(short)
                if entry:
                    results.append(entry)

        return results

    @staticmethod
    def _extract_uuid16(uuid_str: str) -> str:
        """Extract the 16-bit UUID portion from various UUID formats.

        Supports:
        - ``"1101"`` (raw 16-bit hex)
        - ``"0x1101"`` (prefixed 16-bit hex)
        - ``"00001101-0000-1000-8000-00805f9b34fb"`` (full Bluetooth Base UUID)
        """
        s = uuid_str.strip().lower()

        # Full 128-bit Bluetooth Base UUID
        if len(s) == 36 and s.endswith("-0000-1000-8000-00805f9b34fb"):
            return s[4:8]

        # 0x prefix
        if s.startswith("0x"):
            s = s[2:]

        # 4-hex-digit short UUID
        if re.match(r"^[0-9a-f]{4}$", s):
            return s

        return ""
