"""Successful alert writes must survive independent reads and disk reloads."""

import html

import pytest

from sigrift.bridge.persistence import PersistenceManager


def reloaded(persistence):
    persistence.save_all()
    fresh = PersistenceManager(persistence.data_dir, auto_save_interval=0)
    fresh.load_all()
    return fresh


def create_condition(client, name="before"):
    response = client.post(
        "/api/alerts/rules/conditions",
        json={
            "name": name,
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"}
            ],
        },
    )
    assert response.status_code == 201
    return response.json()["rule_id"]


def create_alert(client, name="before"):
    response = client.post("/api/alerts/rules", json={"name": name})
    assert response.status_code == 201
    return response.json()["alert_id"]


def test_condition_edit_survives_get_and_reload(client, persistence):
    rule_id = create_condition(client)
    untouched_id = create_condition(client, "untouched")
    persistence.record_alert_rule_trigger(rule_id, "2026-11-06T12:00:00+00:00")
    changes = {
        "name": "Operator's <rule> & monitor",
        "severity": "critical",
        "enabled": False,
        "cooldown_seconds": 42,
        "notify_webhook": False,
        "logic": "OR",
        "conditions": [{"field": "node_id", "operator": "eq", "value": "changed-node"}],
    }
    response = client.put(f"/api/alerts/rules/conditions/{rule_id}", json=changes)
    assert response.status_code == 200
    expected = {**changes, "name": html.escape(changes["name"]), "trigger_count": 1}
    readback = client.get(f"/api/alerts/rules/conditions/{rule_id}")
    assert readback.status_code == 200
    fresh = reloaded(persistence)
    stored = next(r for r in fresh.get_alert_rules() if r["rule_id"] == rule_id)
    for record in (response.json(), readback.json(), stored):
        assert {key: record[key] for key in expected} == expected
    assert (
        next(r for r in fresh.get_alert_rules() if r["rule_id"] == untouched_id)["name"]
        == "untouched"
    )


def test_acknowledgement_survives_get_filter_and_reload(client, persistence):
    alert_id = create_alert(client)
    note = "Checked <signal> & operator's note"
    response = client.put(
        f"/api/alerts/{alert_id}/ack", json={"note": note, "escalated": True}
    )
    assert response.status_code == 200
    readback = client.get("/api/alerts/", params={"acknowledged": True})
    assert readback.status_code == 200
    assert any(a["alert_id"] == alert_id for a in readback.json())
    records = (
        response.json(),
        next(a for a in readback.json() if a["alert_id"] == alert_id),
        next(
            a for a in reloaded(persistence).get_alerts() if a["alert_id"] == alert_id
        ),
    )
    for record in records:
        assert record["acknowledged"] is True
        assert record["acknowledged_at"]
        assert record["acknowledged_by"]
        assert record["ack_note"] == html.escape(note)
        assert record["escalated"] is True
    assert all(
        a["alert_id"] != alert_id
        for a in client.get("/api/alerts/", params={"acknowledged": False}).json()
    )


def test_admin_alert_edit_survives_get_and_reload(client, persistence):
    alert_id = create_alert(client)
    untouched_id = create_alert(client, "untouched")
    changes = {
        "name": "Updated <rule> & monitor",
        "message": "Operator's <message>",
        "severity": "critical",
        "enabled": False,
        "cooldown_seconds": 42,
        "notify_webhook": False,
        "thresholds": {"min_confidence": 0.9},
        "conditions": [{"field": "node_id", "operator": "eq", "value": "changed-node"}],
    }
    response = client.put(f"/api/admin/alerts/{alert_id}", json=changes)
    assert response.status_code == 200
    expected = {
        **changes,
        "name": html.escape(changes["name"]),
        "message": html.escape(changes["message"]),
    }
    readback = client.get("/api/admin/alerts")
    assert readback.status_code == 200
    fresh = reloaded(persistence)
    for record in (
        response.json(),
        next(a for a in readback.json() if a["alert_id"] == alert_id),
        next(a for a in fresh.get_alerts() if a["alert_id"] == alert_id),
    ):
        assert {key: record[key] for key in expected} == expected
    assert (
        next(a for a in fresh.get_alerts() if a["alert_id"] == untouched_id)["name"]
        == "untouched"
    )


@pytest.mark.parametrize("endpoint", ["/api/alerts/rules/", "/api/admin/alerts/"])
def test_alert_delete_survives_get_and_reload(client, persistence, endpoint):
    alert_id = create_alert(client)
    untouched_id = create_alert(client, "untouched")
    response = client.delete(endpoint + alert_id)
    assert response.status_code == 200
    assert response.json()["deleted"] == alert_id
    for records in (
        client.get("/api/alerts/").json(),
        reloaded(persistence).get_alerts(),
    ):
        assert all(a["alert_id"] != alert_id for a in records)
        assert any(a["alert_id"] == untouched_id for a in records)
    assert client.delete(endpoint + alert_id).status_code == 404


@pytest.mark.parametrize(
    "endpoint", ["/api/alerts/rules/", "/api/alerts/rules/conditions/"]
)
def test_condition_delete_preserves_other_rules(client, persistence, endpoint):
    rule_id = create_condition(client)
    untouched_id = create_condition(client, "untouched")
    persistence.record_alert_rule_trigger(untouched_id, "2026-11-06T12:00:00+00:00")
    response = client.delete(endpoint + rule_id)
    assert response.status_code == 200
    assert client.get(f"/api/alerts/rules/conditions/{rule_id}").status_code == 404
    for records in (
        client.get("/api/alerts/rules/conditions").json(),
        reloaded(persistence).get_alert_rules(),
    ):
        assert all(r["rule_id"] != rule_id for r in records)
        assert (
            next(r for r in records if r["rule_id"] == untouched_id)["trigger_count"]
            == 1
        )
    assert client.delete(endpoint + rule_id).status_code == 404


@pytest.mark.parametrize("ack_first", [True, False])
def test_ack_and_admin_edit_preserve_each_other(client, persistence, ack_first):
    alert_id = create_alert(client)
    actions = [
        (f"/api/alerts/{alert_id}/ack", {"note": "reviewed", "escalated": True}),
        (f"/api/admin/alerts/{alert_id}", {"name": "renamed"}),
    ]
    if not ack_first:
        actions.reverse()
    for endpoint, body in actions:
        assert client.put(endpoint, json=body).status_code == 200
    for records in (
        client.get("/api/admin/alerts").json(),
        reloaded(persistence).get_alerts(),
    ):
        stored = next(a for a in records if a["alert_id"] == alert_id)
        assert stored["name"] == "renamed"
        assert stored["acknowledged"] is True
        assert stored["ack_note"] == "reviewed"
        assert stored["escalated"] is True


def test_admin_explicit_patch_and_audit_use_current_stored_values(
    client, persistence, detection_store, monkeypatch
):
    alert_id = create_alert(client)
    original = persistence.update_alert
    audit = []

    def concurrent_change_before_update(record_id, patch):
        # Simulate an edit and ACK after request validation but before the
        # atomic mutation. A supplied name must win even if it matched an
        # earlier snapshot; omitted acknowledgement fields must survive.
        original(record_id, {"name": "concurrent", "acknowledged": True})
        return original(record_id, patch)

    monkeypatch.setattr(persistence, "update_alert", concurrent_change_before_update)
    monkeypatch.setattr(
        detection_store, "log_audit", lambda **event: audit.append(event)
    )
    response = client.put(f"/api/admin/alerts/{alert_id}", json={"name": "before"})
    assert response.status_code == 200
    assert response.json()["name"] == "before"
    assert response.json()["acknowledged"] is True
    event = next(e for e in audit if e["action"] == "admin_update_alert")
    assert event["details"]["changes"] == [
        {"key": "name", "old": "concurrent", "new": "before"}
    ]
    stored = next(
        a for a in reloaded(persistence).get_alerts() if a["alert_id"] == alert_id
    )
    assert stored["name"] == "before"
    assert stored["acknowledged"] is True


def test_condition_edit_preserves_trigger_at_commit(client, persistence, monkeypatch):
    rule_id = create_condition(client)
    original = persistence.update_alert_rule

    def trigger_before_update(record_id, patch):
        persistence.record_alert_rule_trigger(record_id, "2026-11-06T12:00:00+00:00")
        return original(record_id, patch)

    monkeypatch.setattr(persistence, "update_alert_rule", trigger_before_update)
    response = client.put(
        f"/api/alerts/rules/conditions/{rule_id}", json={"enabled": False}
    )
    assert response.status_code == 200
    for record in (
        response.json(),
        client.get(f"/api/alerts/rules/conditions/{rule_id}").json(),
        next(
            r
            for r in reloaded(persistence).get_alert_rules()
            if r["rule_id"] == rule_id
        ),
    ):
        assert record["enabled"] is False
        assert record["trigger_count"] == 1
        assert record["last_triggered_at"] == "2026-11-06T12:00:00+00:00"


def test_mutation_inputs_results_and_audit_do_not_alias_stored_state(persistence):
    persistence.add_alert({"alert_id": "alias-alert", "conditions": []})
    patch = {"conditions": [{"field": "node_id", "value": ["original"]}]}
    updated, audit = persistence.update_alert("alias-alert", patch)
    patch["conditions"][0]["value"].append("input mutation")
    updated["conditions"][0]["value"].append("response mutation")
    audit[0]["new"][0]["value"].append("audit mutation")
    assert persistence.get_alerts()[0]["conditions"][0]["value"] == ["original"]

    persistence.add_alert_rule({"rule_id": "alias-rule", "conditions": []})
    patch = {"conditions": [{"field": "node_id", "value": ["original"]}]}
    updated = persistence.update_alert_rule("alias-rule", patch)
    patch["conditions"][0]["value"].append("input mutation")
    updated["conditions"][0]["value"].append("response mutation")
    assert persistence.get_alert_rules()[0]["conditions"][0]["value"] == ["original"]


def test_missing_mutations_do_not_create_records(persistence):
    assert persistence.update_alert("missing", {"name": "new"}) is None
    assert persistence.update_alert_rule("missing", {"enabled": False}) is None
    assert persistence.delete_alert("missing") is False
    assert persistence.delete_alert_rule("missing") is False
    assert reloaded(persistence).get_alerts() == []
    assert reloaded(persistence).get_alert_rules() == []
