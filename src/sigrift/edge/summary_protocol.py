"""Canonical versioned RF summary envelopes shared by sender and receiver."""

from datetime import datetime, timezone
import hashlib
import json
import math
import re


def canonical_json(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


PROTOCOL = "rf-summary-v2"
MAX_GENERATION = 2**63 - 1


def valid_node(value):
    """Portable counterpart of Bridge's public node-ID validation contract."""
    return (
        isinstance(value, str)
        and re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", value) is not None
    )


def valid_signal_class(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[a-zA-Z0-9_/.-]{1,128}", value) is not None
    )


def valid_record_id(value):
    """Portable counterpart of the detection-id rule the gateway and Bridge
    apply: ``[a-zA-Z0-9_.:-]{1,128}`` without ``..``."""
    return (
        isinstance(value, str)
        and re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", value) is not None
        and ".." not in value
    )


def receipt(payload):
    return {
        key: payload[key]
        for key in ("protocol", "stream_id", "hour", "generation", "payload_digest")
    }


def validate(payload):
    """Reject ambiguous/non-finite envelopes before any registration or write."""
    expected = {
        "protocol",
        "stream_id",
        "hour",
        "generation",
        "payload_digest",
        "node_id",
        "summaries",
        "high_anomaly_detections",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != expected
        or payload["protocol"] != PROTOCOL
    ):
        raise ValueError("Invalid RF summary protocol fields")
    if not isinstance(payload["stream_id"], str) or not re.fullmatch(
        "[0-9a-f]{32}", payload["stream_id"]
    ):
        raise ValueError("Invalid RF summary stream identity")
    if (
        type(payload["generation"]) is not int
        or not 1 <= payload["generation"] <= MAX_GENERATION
    ):
        raise ValueError("Invalid RF summary generation")
    hour = payload["hour"]
    if not isinstance(hour, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:00:00Z", hour
    ):
        raise ValueError("Invalid RF summary hour")
    datetime.fromisoformat(hour.replace("Z", "+00:00"))
    if not valid_node(payload["node_id"]):
        raise ValueError("Invalid RF summary node")
    if (
        not isinstance(payload["summaries"], list)
        or not isinstance(payload["high_anomaly_detections"], list)
        or not 1
        <= len(payload["summaries"]) + len(payload["high_anomaly_detections"])
        <= 4096
    ):
        raise ValueError("Invalid RF summary entries")
    digest = payload["payload_digest"]
    unsigned = {key: value for key, value in payload.items() if key != "payload_digest"}
    encoded = canonical_json(unsigned)
    if (
        len(encoded) > 512 * 1024
        or not isinstance(digest, str)
        or hashlib.sha256(encoded).hexdigest() != digest
    ):
        raise ValueError("Invalid RF summary digest or size")
    keys, raw_ids, count = set(), set(), 0
    row_fields = {
        "hour",
        "signal_class",
        "family",
        "freq_bin_hz",
        "detection_count",
        "avg_confidence",
        "min_confidence",
        "max_confidence",
        "avg_snr_db",
        "avg_power_dbm",
        "avg_anomaly",
        "max_anomaly",
    }
    for row in payload["summaries"]:
        if (
            not isinstance(row, dict)
            or set(row) != row_fields
            or row["hour"] != hour
            or not all(
                isinstance(row[key], str) and len(row[key]) <= 128
                for key in ("signal_class", "family")
            )
        ):
            raise ValueError("Invalid RF summary row")
        for key in row_fields - {"hour", "signal_class", "family", "detection_count"}:
            value = row[key]
            if value is None and key in {"avg_snr_db", "avg_power_dbm"}:
                continue
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("Invalid RF summary numeric value")
        if (
            type(row["detection_count"]) is not int
            or not 1 <= row["detection_count"] <= MAX_GENERATION
            or row["freq_bin_hz"] < 0
        ):
            raise ValueError("Invalid RF summary count/frequency")
        if (
            not 0
            <= row["min_confidence"]
            <= row["avg_confidence"]
            <= row["max_confidence"]
            <= 1
            or not 0 <= row["avg_anomaly"] <= row["max_anomaly"] <= 1
        ):
            raise ValueError("Invalid RF summary statistic range")
        key = (row["signal_class"], row["family"], row["freq_bin_hz"])
        if key in keys:
            raise ValueError("Duplicate RF summary bin")
        keys.add(key)
        count += row["detection_count"]
    for raw in payload["high_anomaly_detections"]:
        if (
            not isinstance(raw, dict)
            or not valid_record_id(raw.get("id"))
            or raw["id"] in raw_ids
        ):
            raise ValueError("Invalid or duplicate RF raw ID")
        timestamp = raw.get("timestamp")
        if (
            type(timestamp) not in (int, float)
            or not math.isfinite(timestamp)
            or datetime.fromtimestamp(timestamp, timezone.utc).strftime(
                "%Y-%m-%dT%H:00:00Z"
            )
            != hour
        ):
            raise ValueError("RF raw timestamp does not belong to the snapshot hour")
        raw_ids.add(raw["id"])
        if (
            raw.get("node_id") != payload["node_id"]
            or not valid_signal_class(raw.get("signal_class"))
            or type(raw.get("confidence")) not in (int, float)
            or not 0 <= raw["confidence"] <= 1
            or raw.get("baseline_status", "stable")
            not in {"learning", "stable", "unknown"}
            or (
                raw.get("backend") is not None
                and not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}", str(raw["backend"]))
            )
        ):
            raise ValueError("RF raw record is incompatible with Bridge ingestion")
    if count + len(raw_ids) != payload["generation"]:
        raise ValueError("RF summary generation differs from observation count")
    return encoded


def extends(previous, current):
    """A newer snapshot cannot discard previously acknowledged observations."""
    bins = {
        (row["signal_class"], row["family"], row["freq_bin_hz"]): row
        for row in current["summaries"]
    }
    for old in previous["summaries"]:
        new = bins.get((old["signal_class"], old["family"], old["freq_bin_hz"]))
        if (
            new is None
            or new["detection_count"] < old["detection_count"]
            or new["min_confidence"] > old["min_confidence"]
            or new["max_confidence"] < old["max_confidence"]
            or new["max_anomaly"] < old["max_anomaly"]
        ):
            raise ValueError("RF summary would discard accepted observations")
        if new["detection_count"] == old["detection_count"] and new != old:
            raise ValueError("RF summary rewrites an unchanged bin")
    raw = {row["id"]: row for row in current["high_anomaly_detections"]}
    if any(raw.get(row["id"]) != row for row in previous["high_anomaly_detections"]):
        raise ValueError("RF summary would discard or change accepted raw records")
