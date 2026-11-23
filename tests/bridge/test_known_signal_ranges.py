"""Direct reviewed RF ranges use real API/auth, SQLite audit and ingest effects."""

import asyncio

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import dependencies
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.routers.detections import post_ingest

URL = "/api/detections/known-signals"
BAND = {
    "freq_min_hz": 88e6,
    "freq_max_hz": 108e6,
    "signal_class": "*",
    "node_id": "rf-one",
    "note": "Reviewed FM range",
}


@pytest.fixture(autouse=True)
def limits(monkeypatch):
    monkeypatch.setattr(dependencies, "_rate_limiter", dependencies.RateLimiter())
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "isolated-range-review-audit-key")


def create(client, body=None):
    response = client.post(URL, json=BAND if body is None else body)
    assert response.status_code == 201, response.text
    return response.json()


def test_create_without_detection_is_durable_audited_and_idempotent(
    client, detection_store
):
    saved = create(client)
    assert saved["source_detection_id"] is None
    assert saved["revision"] == 1
    assert create(client, {**BAND, "note": "Retry must not edit"}) == saved
    reopened = DetectionStore(detection_store.db_path)
    try:
        assert reopened.known_signals.list() == [saved]
        audit = reopened.get_audit_log(action="known_signal_create")
        assert len(audit) == 1 and audit[0]["target_id"] == saved["pattern_id"]
        assert reopened.verify_audit_chain()["valid"] is True
        assert (
            reopened.get_connection()
            .execute("SELECT COUNT(*) FROM detections")
            .fetchone()[0]
            == 0
        )
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "change",
    [
        {"freq_min_hz": -1},
        {"freq_min_hz": 109e6},
        {"freq_max_hz": 88e6},
        {"freq_max_hz": "Infinity"},
        {"signal_class": "fm*"},
        {"signal_class": "qpsk\n"},
        {"node_id": ""},
        {"note": "x" * 501},
        {"tenant_id": "other"},
        {"source_detection_id": "made-up"},
    ],
)
def test_invalid_create_never_saves(client, detection_store, change):
    assert client.post(URL, json={**BAND, **change}).status_code == 422
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log() == []


def test_scope_must_be_explicit_and_all_nodes_is_supported(client, detection_store):
    body = {key: value for key, value in BAND.items() if key != "node_id"}
    assert client.post(URL, json=body).status_code == 422
    assert detection_store.known_signals.list() == []
    assert create(client, {**body, "node_id": None})["node_id"] is None


@pytest.mark.parametrize("table", ["known_rf_signals", "audit_log"])
def test_storage_or_audit_failure_rolls_back_then_retry_succeeds(
    client, detection_store, table
):
    conn = detection_store.get_connection()
    conn.execute(
        f"CREATE TRIGGER reject_band BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'test disk failure'); END"
    )
    conn.commit()
    assert client.post(URL, json=BAND).status_code == 503
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log() == []
    conn.execute("DROP TRIGGER reject_band")
    conn.commit()
    assert create(client)["revision"] == 1


@pytest.mark.parametrize(
    "role,allowed",
    [("viewer", False), ("analyst", True), ("admin", True)],
)
def test_session_roles_guard_direct_creation(
    bridge_app, detection_store, role, allowed
):
    detection_store.create_user("range-" + role, "fixture-password-long", role=role)
    user = detection_store.get_user("range-" + role)
    token = detection_store.create_session(user["id"])["session_token"]
    with TestClient(bridge_app, headers={"Authorization": "Bearer " + token}) as actor:
        assert actor.post(URL, json=BAND).status_code == (201 if allowed else 403)
    assert bool(detection_store.known_signals.list()) is allowed


@pytest.mark.parametrize("credential", ["foreign-key", "foreign-session"])
def test_foreign_identity_cannot_create(
    bridge_app, detection_store, persistence, credential
):
    if credential == "foreign-key":
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        token = generate_api_key(length=32)
        digest, salt = hash_credential(token)
        persistence.set_key("foreign-range", digest, salt)
        persistence.set_key_meta(
            "foreign-range", {"role": "analyst", "tenant_id": "other"}
        )
        headers = {"X-API-Key": token}
    else:
        other = DetectionStore(detection_store.db_path, tenant_id="other")
        try:
            other.create_user("foreign-range", "fixture-password-long", role="analyst")
            token = other.create_session(other.get_user("foreign-range")["id"])[
                "session_token"
            ]
        finally:
            other.close()
        headers = {"Authorization": "Bearer " + token}
    with TestClient(bridge_app, headers=headers) as actor:
        assert actor.post(URL, json=BAND).status_code == 403
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log() == []


@pytest.mark.parametrize("scope", ["rf-one", None])
def test_range_suppresses_only_matching_future_alerts_and_remove_restores(
    client, bridge_app, persistence, detection_store, scope
):
    for attribute in (
        "signal_whitelist",
        "rf_scorer",
        "rf_baseline_mgr",
        "correlator",
        "score_calibrator",
        "drift_detector",
    ):
        setattr(bridge_app.state, attribute, None)
    persistence.add_alert_rule(
        {
            "rule_id": "range-rule",
            "name": "Range control",
            "enabled": True,
            "conditions": [
                {"field": "freq_hz", "operator": "between", "value": [80e6, 120e6]}
            ],
            "logic": "AND",
            "cooldown_seconds": 0,
            "notify_webhook": False,
        }
    )
    pattern = create(client, {**BAND, "node_id": scope})
    records = [
        DetectionRecord(
            id=ident,
            node_id=node,
            signal_class=cls,
            freq_hz=freq,
            confidence=0.99,
            anomaly_score=0.99,
            power_dbm=power,
        )
        for ident, freq, node, cls, power in [
            ("low-bound", 88e6, "rf-one", "bpsk", -70),
            ("high-bound", 108e6, "rf-one", "qpsk", -10),
            ("inside", 99e6, "rf-one", "unknown", -40),
            ("outside", 108000001, "rf-one", "bpsk", -70),
            ("other-node", 99e6, "rf-two", "bpsk", -70),
        ]
    ]
    detection_store.insert_batch(records)
    before = {
        d.detection_id: detection_store.get_detection_by_id(d.detection_id)
        for d in records
    }
    for d in records:
        asyncio.run(post_ingest(bridge_app, [d], d.node_id, native_analysis=True))
    ids = {a.get("detection_id") for a in persistence.get_alerts()}
    assert "outside" in ids
    assert not {"low-bound", "high-bound", "inside"} & ids
    assert ("other-node" in ids) is (scope is not None)
    assert before == {
        d.detection_id: detection_store.get_detection_by_id(d.detection_id)
        for d in records
    }
    assert (
        client.delete(URL + "/" + pattern["pattern_id"] + "?revision=1").status_code
        == 200
    )
    restored = records[2].model_copy(update={"detection_id": "after-removal"})
    detection_store.insert_batch([restored])
    asyncio.run(
        post_ingest(bridge_app, [restored], restored.node_id, native_analysis=True)
    )
    assert "after-removal" in {a.get("detection_id") for a in persistence.get_alerts()}


def test_sensor_key_and_unauthenticated_creation_are_refused(
    bridge_app, persistence, detection_store
):
    from sigrift.lib.security.credentials import generate_api_key, hash_credential

    token = generate_api_key(length=32)
    digest, salt = hash_credential(token)
    persistence.set_key("range-sensor", digest, salt)
    persistence.set_key_meta("range-sensor", {"role": "sensor", "node_id": "rf-one"})
    with TestClient(bridge_app, headers={"X-API-Key": token}) as actor:
        assert actor.post(URL, json=BAND).status_code == 403
    with TestClient(bridge_app) as actor:
        assert actor.post(URL, json=BAND).status_code == 401
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log() == []
