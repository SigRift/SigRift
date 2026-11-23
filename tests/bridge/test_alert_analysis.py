"""Alert analysis: grouping by type and RF frequency, and mark-known + acknowledge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import dependencies
from sigrift.bridge.alert_analysis import RFTargets, analyse, parse_time
from sigrift.bridge.models import DetectionRecord


@pytest.fixture(autouse=True)
def limits(monkeypatch):
    monkeypatch.setattr(dependencies, "_rate_limiter", dependencies.RateLimiter())
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "isolated-alert-analysis-audit-key")


NOW = datetime.now(timezone.utc)


def detection(store, det_id, freq_hz, signal_class="bpsk", node_id="node-a"):
    record = DetectionRecord(
        id=det_id,
        node_id=node_id,
        signal_class=signal_class,
        freq_hz=freq_hz,
        confidence=0.9,
        anomaly_score=0.9,
    )
    store.insert_batch([record])
    return record.detection_id


def rf_alert(persistence, alert_id, det_id, *, node_id="node-a", age_minutes=5,
             acknowledged=False, name="anomaly_detected", severity="warning"):
    alert = {
        "alert_id": alert_id,
        "name": name,
        "severity": severity,
        "message": f"alert {alert_id}",
        "node_id": node_id,
        "triggered_at": (NOW - timedelta(minutes=age_minutes)).isoformat(),
        "acknowledged": acknowledged,
        "acknowledged_at": None,
        "detection_id": det_id,
    }
    if name.startswith("rule_"):
        alert["rule_id"] = "rule-1"
    persistence.add_alert(alert)
    return alert


def other_alert(persistence, alert_id, name="node_offline", age_minutes=5):
    persistence.add_alert(
        {
            "alert_id": alert_id,
            "name": name,
            "severity": "info",
            "message": "node went quiet",
            "node_id": "node-a",
            "triggered_at": (NOW - timedelta(minutes=age_minutes)).isoformat(),
            "acknowledged": False,
            "acknowledged_at": None,
        }
    )


@pytest.fixture
def populated(detection_store, persistence):
    """Three open alerts at ~433.92 MHz (two classes), one at 868.3 MHz, one other."""
    a = detection(detection_store, "d1", 433.92e6, "ook")
    b = detection(detection_store, "d2", 433.95e6, "2fsk")
    c = detection(detection_store, "d3", 433.91e6, "ook")
    d = detection(detection_store, "d4", 868.3e6, "lora")
    rf_alert(persistence, "a1", a)
    rf_alert(persistence, "a2", b, name="rule_Lab", severity="critical")
    rf_alert(persistence, "a3", c)
    rf_alert(persistence, "a4", d)
    other_alert(persistence, "a5")
    return {"a1": a, "a2": b, "a3": c, "a4": d}


def test_groups_by_frequency_and_type_most_open_first(client, populated):
    response = client.get("/api/alerts/analysis")
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["alerts_considered"] == 5
    assert data["unlinked_open"] == 1
    assert data["can_manage"] is True

    top = data["frequencies"][0]
    assert (top["node_id"], top["count"], top["open"]) == ("node-a", 3, 3)
    assert top["freq_min_hz"] == 433.91e6 and top["freq_max_hz"] == 433.95e6
    assert {c["signal_class"]: c["count"] for c in top["classes"]} == {"ook": 2, "2fsk": 1}
    # Mixed classes in one bucket: the suggestion matches any modulation.
    assert top["suggested_pattern"] == {
        "freq_min_hz": 433_900_000,
        "freq_max_hz": 434_000_000,
        "signal_class": "*",
        "node_id": "node-a",
    }
    assert top["covered_by"] == []
    second = data["frequencies"][1]
    assert second["suggested_pattern"]["signal_class"] == "lora"

    types = {t["name"]: t for t in data["alert_types"]}
    assert types["anomaly_detected"]["count"] == 3
    assert types["rule_Lab"]["severities"] == {"critical": 1}
    assert types["node_offline"]["top_frequencies"] == []
    assert types["anomaly_detected"]["top_frequencies"][0]["count"] == 2


def test_window_and_acknowledged_filters(client, detection_store, persistence):
    old = detection(detection_store, "old", 100.1e6)
    rf_alert(persistence, "old", old, age_minutes=3 * 60)
    rf_alert(persistence, "acked", old, acknowledged=True)
    assert client.get("/api/alerts/analysis?hours=1").json()["alerts_considered"] == 0
    assert client.get("/api/alerts/analysis?hours=6").json()["alerts_considered"] == 1
    both = client.get("/api/alerts/analysis?hours=6&include_acknowledged=true").json()
    assert both["alerts_considered"] == 2
    assert both["frequencies"][0]["open"] == 1


def test_missing_detection_is_not_grouped(client, persistence):
    rf_alert(persistence, "gone", "no-such-detection")
    data = client.get("/api/alerts/analysis").json()
    assert data["frequencies"] == [] and data["unlinked_open"] == 1


def test_mark_known_saves_pattern_and_acks_only_covered_open_alerts(
    client, populated, detection_store, persistence
):
    suggestion = client.get("/api/alerts/analysis").json()["frequencies"][0][
        "suggested_pattern"
    ]
    response = client.post(
        "/api/alerts/analysis/known", json={**suggestion, "note": "garage remotes"}
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["acknowledged_count"] == 3
    assert sorted(data["acknowledged_alert_ids"]) == ["a1", "a2", "a3"]
    assert data["pattern"]["note"] == "garage remotes"

    alerts = {a["alert_id"]: a for a in persistence.get_alerts()}
    for alert_id in ("a1", "a2", "a3"):
        assert alerts[alert_id]["acknowledged"] is True
        assert data["pattern"]["pattern_id"] in alerts[alert_id]["ack_note"]
    assert alerts["a4"]["acknowledged"] is False
    assert alerts["a5"]["acknowledged"] is False
    # Detections are untouched; the pattern is the ordinary audited store row.
    assert detection_store.get_detection_by_id(populated["a1"])["anomaly_score"] == 0.9
    assert detection_store.known_signals.list() == [data["pattern"]]

    after = client.get("/api/alerts/analysis?include_acknowledged=true").json()
    group = next(g for g in after["frequencies"] if g["freq_min_hz"] < 434e6)
    assert group["open"] == 0
    assert group["covered_by"] == [data["pattern"]["pattern_id"]]
    # Retrying is idempotent: same pattern, nothing left to acknowledge.
    retry = client.post("/api/alerts/analysis/known", json=suggestion).json()
    assert retry["pattern"]["pattern_id"] == data["pattern"]["pattern_id"]
    assert retry["acknowledged_count"] == 0


def test_mark_known_without_acknowledging(client, populated, persistence):
    suggestion = client.get("/api/alerts/analysis").json()["frequencies"][0][
        "suggested_pattern"
    ]
    response = client.post(
        "/api/alerts/analysis/known",
        json={**suggestion, "acknowledge_covered": False},
    )
    assert response.status_code == 200
    assert response.json()["acknowledged_count"] == 0
    assert all(a["acknowledged"] is False for a in persistence.get_alerts())


def test_class_specific_pattern_acks_only_that_class(client, populated, persistence):
    body = {
        "freq_min_hz": 433_900_000,
        "freq_max_hz": 434_000_000,
        "signal_class": "ook",
        "node_id": "node-a",
    }
    data = client.post("/api/alerts/analysis/known", json=body).json()
    assert sorted(data["acknowledged_alert_ids"]) == ["a1", "a3"]


def test_node_scope_must_be_explicit_and_range_ordered(client, populated):
    body = {"freq_min_hz": 433_900_000, "freq_max_hz": 434_000_000, "signal_class": "*"}
    assert client.post("/api/alerts/analysis/known", json=body).status_code == 422
    bad = {**body, "node_id": "node-a", "freq_max_hz": 433_000_000}
    assert client.post("/api/alerts/analysis/known", json=bad).status_code == 422


def test_all_nodes_scope_covers_every_node(client, detection_store, persistence):
    one = detection(detection_store, "n1", 162.4e6, "fm", node_id="node-a")
    two = detection(detection_store, "n2", 162.45e6, "fm", node_id="node-b")
    rf_alert(persistence, "x1", one)
    rf_alert(persistence, "x2", two, node_id="node-b")
    body = {
        "freq_min_hz": 162_400_000,
        "freq_max_hz": 162_500_000,
        "signal_class": "*",
        "node_id": None,
    }
    data = client.post("/api/alerts/analysis/known", json=body).json()
    assert sorted(data["acknowledged_alert_ids"]) == ["x1", "x2"]


@pytest.mark.parametrize(
    "role,read,write", [("viewer", 200, 403), ("analyst", 200, 200)]
)
def test_roles(bridge_app, detection_store, populated, role, read, write):
    detection_store.create_user("analysis-" + role, "fixture-password-long", role=role)
    user = detection_store.users.get_user("analysis-" + role)
    session = detection_store.create_session(user["id"])
    with TestClient(
        bridge_app, headers={"Authorization": "Bearer " + session["session_token"]}
    ) as actor:
        response = actor.get("/api/alerts/analysis")
        assert response.status_code == read
        assert response.json()["can_manage"] is (role == "analyst")
        body = {
            "freq_min_hz": 868_300_000,
            "freq_max_hz": 868_400_000,
            "signal_class": "*",
            "node_id": "node-a",
        }
        assert actor.post("/api/alerts/analysis/known", json=body).status_code == write


def test_failed_save_acknowledges_nothing(client, populated, detection_store, persistence):
    conn = detection_store.get_connection()
    conn.execute(
        "CREATE TRIGGER reject_save BEFORE INSERT ON known_rf_signals "
        "BEGIN SELECT RAISE(ABORT, 'full disk simulation'); END"
    )
    conn.commit()
    body = {
        "freq_min_hz": 433_900_000,
        "freq_max_hz": 434_000_000,
        "signal_class": "*",
        "node_id": "node-a",
    }
    assert client.post("/api/alerts/analysis/known", json=body).status_code == 503
    assert all(a["acknowledged"] is False for a in persistence.get_alerts())
    assert detection_store.known_signals.list() == []


def test_analyse_limits_and_timestamps():
    alerts = [
        {"alert_id": str(i), "name": f"type_{i % 3}", "triggered_at": NOW.isoformat()}
        for i in range(9)
    ] + [{"alert_id": "bad", "name": "type_0", "triggered_at": "not a time"}]
    result = analyse(
        alerts, RFTargets(None), [], hours=1, include_acknowledged=False, limit=2
    )
    assert result["alerts_considered"] == 9
    assert result["alert_types_total"] == 3 and len(result["alert_types"]) == 2
    assert parse_time("2026-11-08T10:00:00Z").tzinfo is not None
    assert parse_time("2026-11-08T10:00:00").utcoffset() == timedelta(0)
    assert parse_time(None) is None and parse_time("") is None
