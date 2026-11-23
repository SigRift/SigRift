"""Known RF patterns: real SQLite, authenticated routes, and post-ingest alerts."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import dependencies
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.routers.detections import post_ingest
from sigrift.bridge.storage.known_signals import KnownSignalPattern, matches


@pytest.fixture(autouse=True)
def limits(monkeypatch):
    monkeypatch.setattr(dependencies, "_rate_limiter", dependencies.RateLimiter())
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "isolated-known-pattern-audit-key")


@pytest.fixture
def rf(detection_store):
    record = DetectionRecord(
        id="known-source",
        node_id="node-rf",
        signal_class="bpsk",
        freq_hz=400e6,
        confidence=0.99,
        anomaly_score=0.99,
    )
    detection_store.insert_batch([record])
    return record


def create(client, rf, body=None):
    response = client.put(
        f"/api/detections/anomalies/{rf.detection_id}/baseline", json=body
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["baselined"] is True
    return data["pattern"]


def test_durable_node_scoped_retry_preserves_records_and_scores(
    client, rf, detection_store
):
    before = detection_store.get_detection_by_id(rf.detection_id)
    pattern = create(client, rf)
    assert pattern["node_id"] == rf.node_id
    assert pattern["signal_class"] == "bpsk"
    assert (pattern["freq_min_hz"], pattern["freq_max_hz"]) == (399950000, 400050000)
    assert create(client, rf) == pattern
    assert detection_store.get_detection_by_id(rf.detection_id) == before
    assert rf.detection_id not in detection_store.get_dismissed_ids()
    with_store = DetectionStore(detection_store.db_path)
    try:
        assert with_store.known_signals.list() == [pattern]
        assert len(with_store.get_audit_log(action="baseline")) == 1
        assert with_store.verify_audit_chain()["valid"] is True
    finally:
        with_store.close()


@pytest.mark.parametrize("signal_class", ["bpsk", "*"])
@pytest.mark.parametrize("table", ["known_rf_signals", "audit_log"])
def test_failed_save_is_truthful_and_retryable(
    client, rf, detection_store, table, signal_class
):
    conn = detection_store.get_connection()
    conn.execute(
        f"CREATE TRIGGER reject_save BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT, 'full disk simulation'); END"
    )
    conn.commit()
    body = client.get(f"/api/detections/anomalies/{rf.detection_id}/baseline").json()[
        "defaults"
    ]
    body["signal_class"] = signal_class
    response = client.put(
        f"/api/detections/anomalies/{rf.detection_id}/baseline", json=body
    )
    assert response.status_code == 503
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log(action="baseline") == []
    assert detection_store.get_detection_by_id(rf.detection_id)["anomaly_score"] == 0.99
    conn.execute("DROP TRIGGER reject_save")
    conn.commit()
    assert create(client, rf, body)["revision"] == 1


@pytest.mark.parametrize(
    "change",
    [
        {"freq_min_hz": float("inf")},
        {"freq_max_hz": 0},
        {"freq_min_hz": 500e6},
        {"signal_class": "other"},
        {"node_id": "other-node"},
        {"node_id": ""},
    ],
)
def test_invalid_or_unrelated_review_does_not_save(client, rf, detection_store, change):
    body = KnownSignalPattern(
        freq_min_hz=399950000,
        freq_max_hz=400050000,
        signal_class="bpsk",
        node_id="node-rf",
    ).model_dump()
    body.update(change)
    if change.get("freq_min_hz") == float("inf"):
        response = client.put(
            f"/api/detections/anomalies/{rf.detection_id}/baseline",
            content='{"freq_min_hz":"Infinity","freq_max_hz":400050000,"signal_class":"bpsk","node_id":"node-rf"}',
            headers={"Content-Type": "application/json"},
        )
    else:
        response = client.put(
            f"/api/detections/anomalies/{rf.detection_id}/baseline", json=body
        )
    assert response.status_code == 422
    assert detection_store.known_signals.list() == []


def test_bulk_is_atomic_and_idempotent(client, rf, detection_store):
    url = "/api/detections/anomalies/bulk/baseline"
    assert (
        client.put(
            url, json={"detection_ids": [rf.detection_id, "missing"]}
        ).status_code
        == 404
    )
    assert detection_store.known_signals.list() == []
    second = rf.model_copy(update={"detection_id": "second", "node_id": "second-node"})
    detection_store.insert_batch([second])
    response = client.put(
        url,
        json={"detection_ids": [rf.detection_id, second.detection_id, rf.detection_id]},
    )
    assert response.status_code == 200
    assert response.json()["count"] == 2
    assert (
        client.put(
            url, json={"detection_ids": [rf.detection_id, second.detection_id]}
        ).json()["patterns"]
        == response.json()["patterns"]
    )
    assert len(detection_store.known_signals.list()) == 2


def test_edit_remove_optimistic_revision_and_actual_reopen(client, rf, detection_store):
    original = create(client, rf)
    url = "/api/detections/known-signals/" + original["pattern_id"]
    body = {k: original[k] for k in KnownSignalPattern.model_fields}
    body.update(freq_max_hz=401e6, note='Known "sensor" <literal>', revision=1)
    response = client.put(url, json=body)
    assert response.status_code == 200
    updated = response.json()
    assert updated["revision"] == 2
    assert client.put(url, json=body).status_code == 409
    assert client.delete(url + "?revision=1").status_code == 409
    fresh = DetectionStore(detection_store.db_path)
    try:
        assert fresh.known_signals.list() == [updated]
        assert matches(updated, rf)
        assert client.delete(url + "?revision=2").status_code == 200
        assert fresh.known_signals.list() == []
        assert fresh.get_detection_by_id(rf.detection_id) is not None
    finally:
        fresh.close()


@pytest.mark.parametrize("method,operation", [("put", "UPDATE"), ("delete", "DELETE")])
def test_edit_and_remove_failure_keep_committed_rule(
    client, rf, detection_store, method, operation
):
    pattern = create(client, rf)
    conn = detection_store.get_connection()
    conn.execute(
        f"CREATE TRIGGER reject_change BEFORE {operation} ON known_rf_signals BEGIN SELECT RAISE(ABORT,'write failure'); END"
    )
    conn.commit()
    url = "/api/detections/known-signals/" + pattern["pattern_id"]
    body = {k: pattern[k] for k in KnownSignalPattern.model_fields}
    body.update(note="edit", revision=1)
    response = (
        client.put(url, json=body)
        if method == "put"
        else client.delete(url + "?revision=1")
    )
    assert response.status_code == 503
    assert detection_store.known_signals.list() == [pattern]
    assert len(detection_store.get_audit_log()) == 1


@pytest.mark.parametrize("signal_class", ["bpsk", "*"])
def test_tenant_isolation_and_concurrent_idempotent_writers(tmp_path, signal_class):
    path = tmp_path / "tenants.db"
    owner = DetectionStore(path, tenant_id="owner")
    other = DetectionStore(path, tenant_id="other")
    body = KnownSignalPattern(
        freq_min_hz=1, freq_max_hz=2, signal_class=signal_class, node_id="rf"
    )

    def save(_):
        store = DetectionStore(path, tenant_id="owner")
        try:
            return store.known_signals.create_many([("source", body)], "analyst")[0][
                "pattern_id"
            ]
        finally:
            store.close()

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            ids = list(pool.map(save, range(8)))
        assert len(set(ids)) == 1
        assert len(owner.known_signals.list()) == 1
        assert other.known_signals.list() == []
        with pytest.raises(KeyError):
            other.known_signals.remove(ids[0], 1, "analyst")
        assert len(owner.get_audit_log()) == 1
    finally:
        owner.close()
        other.close()


@pytest.mark.parametrize("signal_class", ["bpsk", "*"])
@pytest.mark.parametrize(
    "role,allowed", [("viewer", False), ("analyst", True), ("admin", True)]
)
def test_real_session_roles_read_only_or_manage(
    bridge_app, detection_store, rf, role, allowed, signal_class
):
    detection_store.create_user("known-" + role, "fixture-password-long", role=role)
    user = detection_store.users.get_user("known-" + role)
    session = detection_store.create_session(user["id"])
    with TestClient(
        bridge_app, headers={"Authorization": "Bearer " + session["session_token"]}
    ) as actor:
        response = actor.get("/api/detections/known-signals")
        assert response.status_code == 200
        assert response.json()["can_manage"] is allowed
        preview = actor.get(f"/api/detections/anomalies/{rf.detection_id}/baseline")
        assert preview.status_code == 200
        assert preview.json()["can_manage"] is allowed
        body = {**preview.json()["defaults"], "signal_class": signal_class}
        save = actor.put(
            f"/api/detections/anomalies/{rf.detection_id}/baseline", json=body
        )
        assert save.status_code == (200 if allowed else 403)


@pytest.mark.parametrize("scope", ["password_change_only", "mfa_setup_only"])
def test_restricted_session_cannot_baseline(bridge_app, detection_store, rf, scope):
    detection_store.create_user(
        "known-restricted", "fixture-password-long", role="admin"
    )
    user = detection_store.users.get_user("known-restricted")
    session = detection_store.create_session(user["id"])
    detection_store.users.set_session_scope(session["session_token"], scope)
    with TestClient(
        bridge_app, headers={"Authorization": "Bearer " + session["session_token"]}
    ) as actor:
        assert (
            actor.put(
                f"/api/detections/anomalies/{rf.detection_id}/baseline"
            ).status_code
            == 403
        )
    assert detection_store.known_signals.list() == []


@pytest.mark.parametrize("signal_class", ["bpsk", "*"])
@pytest.mark.parametrize("native_analysis", [False, True])
def test_post_ingest_filters_only_matching_alerts_and_undo_reenables(
    client, bridge_app, detection_store, persistence, rf, native_analysis, signal_class
):
    # Isolate the operator feature from preexisting calibration/learned scoring.
    bridge_app.state.signal_whitelist = None
    bridge_app.state.rf_scorer = None
    bridge_app.state.rf_baseline_mgr = None
    bridge_app.state.correlator = None
    bridge_app.state.score_calibrator = None
    bridge_app.state.drift_detector = None
    rule = {
        "rule_id": "known-test-rule",
        "name": "RF monitor",
        "enabled": True,
        "conditions": [{"field": "anomaly_score", "operator": "gte", "value": 0.8}],
        "logic": "AND",
        "cooldown_seconds": 0,
        "notify_webhook": False,
    }
    persistence.add_alert_rule(rule)
    persistence.add_watch_band(
        {
            "watch_id": "known-watch",
            "name": "RF band",
            "freq_min_hz": 399e6,
            "freq_max_hz": 402e6,
            "trigger": "new_activity",
            "cooldown_seconds": 0,
            "notify_webhook": False,
        }
    )
    reviewed = client.get(
        f"/api/detections/anomalies/{rf.detection_id}/baseline"
    ).json()["defaults"]
    reviewed["signal_class"] = signal_class
    pattern = create(client, rf, reviewed)
    persistence.add_alert(
        {"alert_id": "existing-system", "name": "disk_warning", "severity": "warning"}
    )
    dets = [
        rf.model_copy(update={"detection_id": "match"}),
        rf.model_copy(update={"detection_id": "node-mismatch", "node_id": "elsewhere"}),
        rf.model_copy(
            update={
                "detection_id": "class-mismatch",
                "signal_class": "qpsk",
                "power_dbm": -12,
            }
        ),
        rf.model_copy(update={"detection_id": "frequency-mismatch", "freq_hz": 401e6}),
    ]
    detection_store.insert_batch(dets)
    before = {
        d.detection_id: detection_store.get_detection_by_id(d.detection_id)
        for d in dets
    }
    for d in dets:
        asyncio.run(
            post_ingest(bridge_app, [d], d.node_id, native_analysis=native_analysis)
        )
        if d.detection_id == "match" and not native_analysis:
            assert "match" in {
                a["detection_id"] for a in detection_store.get_rf_anomalies(min_score=0)
            }
    alerts = persistence.get_alerts()
    ids = {a.get("detection_id") for a in alerts}
    assert "match" not in ids
    assert {"node-mismatch", "frequency-mismatch"} <= ids
    assert ("class-mismatch" in ids) is (signal_class != "*")
    assert any(a.get("alert_id") == "existing-system" for a in alerts)
    assert any(a.get("watch_id") == "known-watch" for a in alerts)
    assert any(a.get("rule_id") == "known-test-rule" for a in alerts)
    assert any(a.get("name") == "anomaly_detected" for a in alerts)
    assert {
        d.detection_id: detection_store.get_detection_by_id(d.detection_id)
        for d in dets
    } == before
    assert all(d.anomaly_score == 0.99 for d in dets)
    assert (
        client.delete(
            "/api/detections/known-signals/" + pattern["pattern_id"] + "?revision=1"
        ).status_code
        == 200
    )
    undo = rf.model_copy(
        update={
            "detection_id": "after-undo",
            "signal_class": "qpsk" if signal_class == "*" else "bpsk",
            "power_dbm": -60,
        }
    )
    detection_store.insert_batch([undo])
    asyncio.run(
        post_ingest(bridge_app, [undo], undo.node_id, native_analysis=native_analysis)
    )
    assert "after-undo" in {a.get("detection_id") for a in persistence.get_alerts()}


def test_alert_entry_point_requires_real_linked_rf_producer(client, persistence, rf):
    records = [
        ("rf", "anomaly_detected", rf.detection_id, {}),
        ("system", "disk_warning", rf.detection_id, {}),
        ("wifi", "wifi_anomaly", rf.detection_id, {}),
        ("bt", "bluetooth_anomaly", rf.detection_id, {}),
        ("missing", "anomaly_detected", "gone", {}),
        ("rule", "rule_RF", rf.detection_id, {"rule_id": "condition"}),
        ("watch", "watch_band_RF", rf.detection_id, {"watch_id": "watch"}),
    ]
    for aid, name, det_id, extra in records:
        persistence.add_alert(
            {
                "alert_id": aid,
                "name": name,
                "detection_id": det_id,
                "severity": "warning",
                **extra,
            }
        )
    response = client.get("/api/alerts/")
    assert response.status_code == 200
    links = {a["alert_id"]: a["rf_detection_id"] for a in response.json()}
    assert {key for key, value in links.items() if value} == {"rf", "rule", "watch"}


def test_unavailable_pattern_table_does_not_silence_alerts(
    bridge_app, detection_store, persistence, rf
):
    bridge_app.state.signal_whitelist = None
    bridge_app.state.rf_scorer = None
    bridge_app.state.rf_baseline_mgr = None
    conn = detection_store.get_connection()
    conn.execute("DROP TABLE known_rf_signals")
    conn.commit()
    result = asyncio.run(
        post_ingest(bridge_app, [rf], rf.node_id, native_analysis=True)
    )
    assert result["alerts_created"] >= 1
    assert rf.detection_id in {a.get("detection_id") for a in persistence.get_alerts()}
    assert detection_store.get_detection_by_id(rf.detection_id)["anomaly_score"] == 0.99


def test_upgrade_existing_database_adds_rules_without_changing_rows(tmp_path):
    path = tmp_path / "upgrade.db"
    prior = DetectionStore(path)
    record = DetectionRecord(
        id="existing",
        node_id="site",
        signal_class="bpsk",
        freq_hz=400e6,
        confidence=0.9,
    )
    prior.insert_batch([record])
    before = prior.get_detection_by_id(record.detection_id)
    conn = prior.get_connection()
    conn.execute("DROP TABLE known_rf_signals")
    conn.commit()
    versions = [tuple(row) for row in conn.execute("SELECT * FROM schema_version")]
    prior.close()
    upgraded = DetectionStore(path)
    try:
        assert upgraded.known_signals.list() == []
        assert upgraded.get_detection_by_id(record.detection_id) == before
        assert [
            tuple(row)
            for row in upgraded.get_connection().execute("SELECT * FROM schema_version")
        ] == versions
    finally:
        upgraded.close()


@pytest.mark.parametrize("credential", ["foreign-key", "foreign-session"])
def test_explicit_foreign_tenant_cannot_access_or_mutate_patterns(
    client, bridge_app, persistence, detection_store, rf, credential
):
    pattern = create(client, rf)
    persistence.add_alert(
        {
            "alert_id": "tenant-rf",
            "name": "anomaly_detected",
            "detection_id": rf.detection_id,
            "severity": "warning",
        }
    )
    if credential == "foreign-key":
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        token = generate_api_key(length=32)
        digest, salt = hash_credential(token)
        persistence.set_key("other-tenant-analyst", digest, salt)
        persistence.set_key_meta(
            "other-tenant-analyst", {"role": "analyst", "tenant_id": "other"}
        )
        headers = {"X-API-Key": token}
    else:
        foreign = DetectionStore(detection_store.db_path, tenant_id="other")
        try:
            foreign.create_user(
                "foreign-analyst", "fixture-password-long", role="analyst"
            )
            user = foreign.get_user("foreign-analyst")
            token = foreign.create_session(user["id"])["session_token"]
        finally:
            foreign.close()
        headers = {"Authorization": "Bearer " + token}
    body = {key: pattern[key] for key in KnownSignalPattern.model_fields}
    with TestClient(bridge_app, headers=headers) as actor:
        requests = [
            ("GET", "/api/detections/known-signals", None),
            ("GET", f"/api/detections/anomalies/{rf.detection_id}/baseline", None),
            ("PUT", f"/api/detections/anomalies/{rf.detection_id}/baseline", None),
            (
                "PUT",
                "/api/detections/anomalies/bulk/baseline",
                {"detection_ids": [rf.detection_id]},
            ),
            (
                "PUT",
                "/api/detections/known-signals/" + pattern["pattern_id"],
                {**body, "revision": 1, "note": "forbidden"},
            ),
            (
                "DELETE",
                "/api/detections/known-signals/"
                + pattern["pattern_id"]
                + "?revision=1",
                None,
            ),
        ]
        for method, path, body in requests:
            assert actor.request(method, path, json=body).status_code == 403
        # Fixed-instance authentication now refuses the entire foreign feed;
        # per-pattern redaction must never substitute for that boundary.
        response = actor.get("/api/alerts/")
        assert response.status_code == 403
    assert detection_store.known_signals.list() == [pattern]
    assert len(detection_store.get_audit_log(action="baseline")) == 1


@pytest.mark.parametrize(
    "invalid", ["b*", "*psk", "**", "?", "", " bpsk", "bpsk\n", "a" * 129]
)
def test_only_exact_any_modulation_marker_is_accepted(
    client, rf, detection_store, invalid
):
    body = client.get(f"/api/detections/anomalies/{rf.detection_id}/baseline").json()[
        "defaults"
    ]
    body["signal_class"] = invalid
    response = client.put(
        f"/api/detections/anomalies/{rf.detection_id}/baseline", json=body
    )
    assert response.status_code == 422
    assert detection_store.known_signals.list() == []
    assert detection_store.get_audit_log(action="baseline") == []


def test_any_modulation_is_explicit_and_preserves_preview_bulk_and_bodyless_defaults(
    client, rf, detection_store
):
    url = f"/api/detections/anomalies/{rf.detection_id}/baseline"
    preview = client.get(url).json()
    assert preview["defaults"]["signal_class"] == "bpsk"
    body = {**preview["defaults"], "signal_class": "*"}
    broad = create(client, rf, body)
    assert broad["signal_class"] == "*"
    assert create(client, rf, body) == broad
    exact = create(client, rf)
    assert (
        exact["signal_class"] == "bpsk" and exact["pattern_id"] != broad["pattern_id"]
    )
    bulk = client.put(
        "/api/detections/anomalies/bulk/baseline",
        json={"detection_ids": [rf.detection_id]},
    )
    assert bulk.status_code == 200
    assert bulk.json()["patterns"] == [exact]
    preview = client.get(url).json()
    assert preview["defaults"]["signal_class"] == "bpsk"
    assert {p["pattern_id"] for p in preview["matching_patterns"]} == {
        broad["pattern_id"],
        exact["pattern_id"],
    }
    assert len(detection_store.get_audit_log(action="baseline")) == 2


def test_any_modulation_edit_conflict_reopen_remove_and_exact_mode(
    client, rf, detection_store
):
    before = detection_store.get_detection_by_id(rf.detection_id)
    pattern = create(client, rf)
    url = "/api/detections/known-signals/" + pattern["pattern_id"]
    body = {k: pattern[k] for k in KnownSignalPattern.model_fields}
    broad_body = {**body, "signal_class": "*", "revision": 1}
    edited = client.put(url, json=broad_body)
    assert edited.status_code == 200
    broad = edited.json()
    assert broad["revision"] == 2
    assert client.put(url, json=broad_body).status_code == 409
    fresh = DetectionStore(detection_store.db_path)
    changed = rf.model_copy(update={"signal_class": "qpsk", "power_dbm": -5})
    try:
        assert fresh.known_signals.list() == [broad]
        assert matches(broad, changed)
        assert not matches(broad, changed.model_copy(update={"freq_hz": 401e6}))
        assert not matches(broad, changed.model_copy(update={"node_id": "other"}))
        narrowed = client.put(url, json={**body, "revision": 2})
        assert narrowed.status_code == 200
        assert not matches(fresh.known_signals.list()[0], changed)
        assert client.delete(url + "?revision=2").status_code == 409
        assert client.delete(url + "?revision=3").status_code == 200
        assert fresh.known_signals.list() == []
        assert fresh.get_detection_by_id(rf.detection_id) == before
        assert fresh.verify_audit_chain()["valid"] is True
    finally:
        fresh.close()


def test_any_modulation_all_nodes_remains_an_explicit_review_choice(client, rf):
    body = client.get(f"/api/detections/anomalies/{rf.detection_id}/baseline").json()[
        "defaults"
    ]
    pattern = create(client, rf, {**body, "signal_class": "*", "node_id": None})
    other = rf.model_copy(
        update={"node_id": "second", "signal_class": "qpsk", "power_dbm": -85}
    )
    assert matches(pattern, other)
    assert not matches(pattern, other.model_copy(update={"freq_hz": 399e6}))


def test_bulk_baseline_runs_off_the_event_loop():
    """Soak ALR-1: blocking SQLite work must not run inside an async handler."""
    import inspect

    from sigrift.bridge.routers.detection_audit import bulk_baseline_anomalies

    assert not inspect.iscoroutinefunction(bulk_baseline_anomalies)
