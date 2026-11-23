"""Actual Bridge authentication, storage, query and raw-hook summary contracts."""

from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from sigrift.edge.summary_protocol import canonical_json, receipt
from sigrift.lib.security.credentials import generate_api_key, hash_credential


def signed(value):
    value.pop("payload_digest", None)
    value["payload_digest"] = hashlib.sha256(canonical_json(value)).hexdigest()
    return value


def snapshot(node, count=1):
    hour = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")
    return signed(
        {
            "protocol": "rf-summary-v2",
            "stream_id": "a" * 32,
            "node_id": node,
            "hour": hour,
            "generation": count,
            "summaries": [
                {
                    "hour": hour,
                    "signal_class": "bpsk",
                    "family": "PSK",
                    "freq_bin_hz": 915e6,
                    "detection_count": count,
                    "avg_confidence": 0.8,
                    "min_confidence": 0.8,
                    "max_confidence": 0.8,
                    "avg_snr_db": 12,
                    "avg_power_dbm": -55,
                    "avg_anomaly": 0.1,
                    "max_anomaly": 0.1,
                }
            ],
            "high_anomaly_detections": [],
        }
    )


def post(client, body):
    return client.post(
        "/api/detections/ingest-summary",
        content=gzip.compress(canonical_json(body)),
        headers={"Content-Encoding": "gzip", "Content-Type": "application/json"},
    )


def test_actual_upgrade_and_replay_preserve_base_and_query_activity(
    client, registered_node, detection_store
):
    body = snapshot(registered_node, 2)
    legacy = {
        "node_id": registered_node,
        "summaries": [dict(body["summaries"][0], detection_count=7, avg_snr_db=None)],
    }
    assert post(client, legacy).status_code == 201
    before = dict(
        detection_store.get_connection()
        .execute("SELECT * FROM detection_summaries_hourly")
        .fetchone()
    )
    response = post(client, body)
    assert response.status_code == 201, response.text
    assert response.json()["summary_receipt"] == receipt(body)
    assert post(client, body).json()["summary_receipt"] == receipt(body)
    assert (
        dict(
            detection_store.get_connection()
            .execute("SELECT * FROM detection_summaries_hourly")
            .fetchone()
        )
        == before
    )
    assert post(client, legacy).status_code == 409
    assert post(client, snapshot(registered_node, 1)).status_code == 409
    assert post(client, snapshot(registered_node, 3)).status_code == 201
    rows = detection_store._detection_summaries.get_summaries(node_id=registered_node)
    assert {row["component"]: row["detection_count"] for row in rows} == {
        "legacy_base": 7,
        "stream_summary": 3,
    }
    from sigrift.bridge.setup_checklist import collect_observations

    observed = collect_observations(detection_store, [registered_node])[
        registered_node
    ]["rf_summary"]
    assert observed["status"] == "available"
    assert datetime.fromisoformat(observed["timestamp"]) == datetime.fromisoformat(
        body["hour"].replace("Z", "+00:00")
    )


@pytest.mark.parametrize(
    "change",
    ["bad_digest", "unknown_protocol", "bool_count", "raw_other_hour", "duplicate_bin"],
)
def test_invalid_envelope_cannot_bind_node_or_mutate_state(
    client, registered_node, detection_store, change
):
    body = snapshot(registered_node)
    if change == "bad_digest":
        body["payload_digest"] = "0" * 64
    elif change == "unknown_protocol":
        body["protocol"] = "rf-summary-v999"
    elif change == "bool_count":
        body["summaries"][0]["detection_count"] = True
    elif change == "raw_other_hour":
        body["generation"] = 2
        body["high_anomaly_detections"] = [
            {
                "id": "wrong-hour",
                "timestamp": (
                    datetime.now(timezone.utc) - timedelta(hours=1)
                ).timestamp(),
                "signal_class": "bpsk",
                "confidence": 0.9,
            }
        ]
    else:
        body["generation"] = 2
        body["summaries"] *= 2
    if change != "bad_digest":
        signed(body)
    response = post(client, body)
    assert response.status_code == 422
    connection = detection_store.get_connection()
    for table in (
        "rf_summary_streams",
        "rf_summary_generations",
        "rf_summary_components",
    ):
        assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


@pytest.mark.parametrize(
    ("role", "other_binding"),
    [("sensor", False), ("viewer", False), ("admin", False), ("admin", True)],
)
def test_existing_same_instance_role_hierarchy_can_ingest(
    bridge_app, persistence, registered_node, role, other_binding
):
    # enforce_node_binding explicitly permits ADMIN to act for any node in
    # its authenticated tenant, including when key metadata names another node.
    key = generate_api_key(length=32)
    digest, salt = hash_credential(key)
    persistence.set_key("protocol-role", digest, salt)
    persistence.set_key_meta(
        "protocol-role",
        {
            "role": role,
            "node_id": "other-node" if other_binding else registered_node,
            "tenant_id": "default",
        },
    )
    with TestClient(bridge_app, headers={"X-API-Key": key}) as actor:
        response = post(actor, snapshot(registered_node))
        assert response.status_code == 201, response.text


@pytest.mark.parametrize(
    ("role", "scope"),
    [
        ("sensor", "foreign"),
        ("sensor", "wrong_node"),
        ("sensor", "bad_key"),
        ("admin", "foreign"),
        ("admin", "bad_key"),
    ],
)
def test_foreign_or_unbound_credential_does_not_register(
    bridge_app, persistence, registered_node, detection_store, scope, role
):
    key = generate_api_key(length=32)
    digest, salt = hash_credential(key)
    persistence.set_key("protocol-refusal", digest, salt)
    persistence.set_key_meta(
        "protocol-refusal",
        {
            "role": role,
            "node_id": "other-node" if scope == "wrong_node" else registered_node,
            "tenant_id": "other" if scope == "foreign" else "default",
        },
    )
    with TestClient(
        bridge_app, headers={"X-API-Key": "invalid" if scope == "bad_key" else key}
    ) as actor:
        response = post(actor, snapshot(registered_node))
        assert response.status_code in {401, 403}
    assert (
        detection_store.get_connection()
        .execute("SELECT COUNT(*) FROM rf_summary_streams")
        .fetchone()[0]
        == 0
    )


def test_actual_storage_failure_has_no_success_ack_and_retry_works(
    client, registered_node, detection_store
):
    conn = detection_store.get_connection()
    conn.execute(
        "CREATE TRIGGER fail_summary BEFORE INSERT ON rf_summary_components BEGIN SELECT RAISE(ABORT,'real write failure'); END"
    )
    body = snapshot(registered_node)
    # TestClient propagates genuine server errors; never manufacture a 201.
    with pytest.raises(sqlite3.IntegrityError):
        post(client, body)
    assert conn.execute("SELECT COUNT(*) FROM rf_summary_streams").fetchone()[0] == 0
    conn.execute("DROP TRIGGER fail_summary")
    assert post(client, body).json()["summary_receipt"] == receipt(body)
