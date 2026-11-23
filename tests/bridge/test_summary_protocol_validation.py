"""Malformed signed envelopes cannot register streams or rewrite accepted evidence."""

import copy
from datetime import datetime, timezone
import hashlib
import json

import pytest

from sigrift.bridge.storage.base import SharedContext
from sigrift.bridge.storage.detection_summaries import (
    DetectionSummaryStore,
    SummaryConflict,
)
from sigrift.edge.summary_protocol import receipt, validate


HOUR = "2026-11-07T12:00:00Z"


def signed(body):
    """Independent wire encoder: hash the unsigned compact sorted JSON bytes."""
    body = copy.deepcopy(body)
    body.pop("payload_digest", None)
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["payload_digest"] = hashlib.sha256(encoded).hexdigest()
    return body, encoded


def envelope():
    return {
        "protocol": "rf-summary-v2",
        "stream_id": "abcdef0123456789" * 2,
        "node_id": "synthetic-node",
        "hour": HOUR,
        "generation": 2,
        "summaries": [
            {
                "hour": HOUR,
                "signal_class": "bpsk",
                "family": "PSK",
                "freq_bin_hz": 915_000_000,
                "detection_count": 1,
                "avg_confidence": 0.8,
                "min_confidence": 0.7,
                "max_confidence": 0.9,
                "avg_snr_db": None,
                "avg_power_dbm": -50,
                "avg_anomaly": 0.1,
                "max_anomaly": 0.2,
            }
        ],
        "high_anomaly_detections": [
            {
                "id": "synthetic-observation",
                "node_id": "synthetic-node",
                "timestamp": datetime(
                    2026, 11, 7, 12, 1, tzinfo=timezone.utc
                ).timestamp(),
                "signal_class": "bpsk",
                "confidence": 0.8,
                "baseline_status": "stable",
                "backend": "onnx_cpu",
            }
        ],
    }


def database_state(ctx):
    return tuple(
        tuple(tuple(row) for row in ctx.get_conn().execute(f"SELECT * FROM {table}"))
        for table in (
            "rf_summary_streams",
            "rf_summary_generations",
            "rf_summary_components",
        )
    )


def test_valid_wire_digest_and_receipt_are_independently_reproducible():
    body, wire = signed(envelope())
    before = copy.deepcopy(body)
    assert validate(body) == wire
    assert receipt(body) == {
        "protocol": "rf-summary-v2",
        "stream_id": "abcdef0123456789" * 2,
        "hour": HOUR,
        "generation": 2,
        "payload_digest": hashlib.sha256(wire).hexdigest(),
    }
    assert body == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("stream_id", None),
        ("stream_id", "A" * 32),
        ("stream_id", "a" * 31),
        ("hour", 0),
        ("hour", "2026-11-07T12:01:00Z"),
        ("hour", "2026-02-30T12:00:00Z"),
        ("node_id", "../another-node"),
        ("summaries", {}),
        ("high_anomaly_detections", None),
        ("generation", 3),
    ],
)
def test_invalid_envelope_identity_or_count_cannot_register(tmp_path, field, value):
    body = envelope()
    body[field] = value
    body, _ = signed(body)
    before = copy.deepcopy(body)
    ctx = SharedContext(tmp_path / "receiver.db")
    try:
        store = DetectionSummaryStore(ctx)
        with pytest.raises(ValueError):
            store.accept_snapshot(body)
        assert database_state(ctx) == ((), (), ())
        assert body == before
        valid, _ = signed(envelope())
        assert store.accept_snapshot(valid) == receipt(valid)
    finally:
        ctx.close()


@pytest.mark.parametrize("kind", ["empty", "entries", "encoded_bytes"])
def test_entry_and_wire_limits_reject_without_mutating_input(kind):
    body = envelope()
    if kind == "empty":
        body["summaries"] = body["high_anomaly_detections"] = []
    elif kind == "entries":
        body["summaries"] *= 4097
        body["high_anomaly_detections"] = []
    else:
        body["high_anomaly_detections"][0]["detail"] = "x" * (512 * 1024)
    body, _ = signed(body)
    before = copy.deepcopy(body)
    with pytest.raises(ValueError, match="entries|size"):
        validate(body)
    assert body == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("hour", "2026-11-07T13:00:00Z"),
        ("family", "x" * 129),
        ("signal_class", None),
        ("avg_confidence", True),
        ("avg_snr_db", "12"),
        ("avg_power_dbm", False),
    ],
)
def test_invalid_row_shape_or_numeric_type_preserves_payload(field, value):
    body = envelope()
    body["summaries"][0][field] = value
    body, _ = signed(body)
    before = copy.deepcopy(body)
    with pytest.raises(ValueError, match="row|numeric"):
        validate(body)
    assert body == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("node_id", "another-node"),
        ("signal_class", "invalid class"),
        ("confidence", True),
        ("confidence", 1.1),
        ("baseline_status", "invented"),
        ("backend", "../engine"),
    ],
)
def test_raw_ingestion_contract_rejects_incompatible_records(field, value):
    body = envelope()
    body["high_anomaly_detections"][0][field] = value
    body, _ = signed(body)
    with pytest.raises(ValueError, match="incompatible"):
        validate(body)


@pytest.mark.parametrize(
    "change", ["same_bin_statistics", "raw_changed", "raw_removed"]
)
def test_new_generation_cannot_rewrite_or_drop_prior_evidence(tmp_path, change):
    ctx = SharedContext(tmp_path / "receiver.db")
    try:
        store = DetectionSummaryStore(ctx)
        original, _ = signed(envelope())
        accepted_receipt = store.accept_snapshot(original)
        before = database_state(ctx)
        next_body = envelope()
        extra = {**next_body["summaries"][0], "freq_bin_hz": 916_000_000}
        next_body["summaries"].append(extra)
        next_body["generation"] = 3
        if change == "same_bin_statistics":
            next_body["summaries"][0]["avg_confidence"] = 0.75
        elif change == "raw_changed":
            next_body["high_anomaly_detections"][0]["confidence"] = 0.85
        else:
            next_body["high_anomaly_detections"] = []
            # Still a newer envelope: add another independent observation.
            next_body["summaries"].append({**extra, "freq_bin_hz": 917_000_000})
            next_body["generation"] = 3
        rejected, _ = signed(next_body)
        validate(rejected)  # Individually valid; the persisted history forbids it.
        with pytest.raises(SummaryConflict):
            store.accept_snapshot(rejected)
        assert database_state(ctx) == before
        assert store.accept_snapshot(original) == accepted_receipt
        retry = envelope()
        retry["summaries"].append(extra)
        retry["generation"] = 3
        retry, _ = signed(retry)
        assert store.accept_snapshot(retry) == receipt(retry)
    finally:
        ctx.close()
