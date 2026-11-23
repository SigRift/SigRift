"""Short-lived scanner runtime reports, independent of node heartbeats.

Only the authenticated scanner-status route writes these records. Registration
capabilities, detections and ordinary node metrics cannot renew a scanner lease.
"""

from datetime import datetime, timezone
from typing import Any, Literal

ScannerProtocol = Literal["sdr", "wifi", "bluetooth", "zigbee", "adsb"]
ScannerState = Literal["running", "stopped", "error"]
# Why a scanner reports "error"; a closed list so no device detail can leak.
ScannerReason = Literal[
    "starting", "sensor_absent", "sensor_changed", "sensor_unusable", "capture_failed"
]
SCANNER_REASONS = (
    "starting",
    "sensor_absent",
    "sensor_changed",
    "sensor_unusable",
    "capture_failed",
)
SCANNER_PROTOCOLS = ("sdr", "wifi", "bluetooth", "zigbee", "adsb")
SCANNER_LEASE_SECONDS = 120
SCANNER_REPORTS_FIELD = "_scanner_reports"


def scanner_status_snapshot(records: Any, now: datetime) -> dict[str, dict[str, Any]]:
    """Return validated reports with server-derived remaining lifetimes.

    Keep stopped/expired records so the UI can distinguish an online monitor
    from a scanner that stopped reporting. Invalid saved data never enables a
    scanner. The caller passes server time, never a timestamp from the sensor.
    """
    if not isinstance(records, dict):
        return {}
    result = {}
    for protocol in SCANNER_PROTOCOLS:
        record = records.get(protocol)
        if not isinstance(record, dict) or record.get("state") not in (
            "running",
            "stopped",
            "error",
        ):
            continue
        try:
            reported = datetime.fromisoformat(record["reported_at"])
            if reported.tzinfo is None:
                continue
            age = (now - reported).total_seconds()
        except (KeyError, TypeError, ValueError):
            continue
        if age < 0:
            continue
        remaining = max(0.0, SCANNER_LEASE_SECONDS - age)
        active = record["state"] == "running" and remaining > 0
        # A reason explains a live error report only: once the lease ends the
        # scanner has stopped telling us anything, so the old cause is stale.
        reason = record.get("reason")
        if (
            record["state"] != "error"
            or remaining <= 0
            or not isinstance(reason, str)
            or reason not in SCANNER_REASONS
        ):
            reason = None
        result[protocol] = {
            "protocol": protocol,
            "state": record["state"],
            "reported_at": reported.astimezone(timezone.utc).isoformat(),
            "expires_in_seconds": remaining if active else 0.0,
            "active": active,
            "reason": reason,
        }
    return result
