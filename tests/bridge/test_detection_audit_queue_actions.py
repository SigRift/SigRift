"""RF anomaly queue actions: snooze, re-evaluation, summary and pattern edits.

Real SQLite store, real routes and auth. A scorer is replaced only where the
test needs a known re-evaluation result; every change is checked in the store,
the audit log and the activity feed, not just in the response.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge.models import DetectionRecord
from sigrift.lib.security.credentials import generate_api_key, hash_credential

ANOMALIES = [
    ("det-a", "bpsk", 433.92e6, "node-a", 0.8),
    ("det-b", "qpsk", 915.0e6, "node-b", 0.5),
    ("det-c", "fsk", 868.3e6, "node-a", 0.6),
]


@pytest.fixture(autouse=True)
def audit_key(monkeypatch):
    # The audit chain's HMAC key; without it a dev key file would be created.
    monkeypatch.setenv("BRIDGE_AUDIT_KEY", "isolated-queue-action-audit-key")


@pytest.fixture
def rows(detection_store) -> dict[str, int]:
    """detection_id -> rf_anomalies row id for three active anomalies."""
    ids = {}
    for detection_id, signal_class, freq_hz, node_id, score in ANOMALIES:
        (row_id,) = detection_store.insert_rf_anomalies_batch(
            [
                {
                    "detection_id": detection_id,
                    "signal_class": signal_class,
                    "family": "test",
                    "freq_hz": freq_hz,
                    "node_id": node_id,
                    "timestamp": "2026-11-18T00:00:00+00:00",
                    "anomaly_score": score,
                }
            ]
        )
        ids[detection_id] = row_id
    return ids


def active(client) -> list[str]:
    response = client.get("/api/detections/anomalies")
    assert response.status_code == 200
    return sorted(row["detection_id"] for row in response.json()["anomalies"])


def viewer(bridge_app, persistence) -> TestClient:
    key = generate_api_key(length=32)
    digest, salt = hash_credential(key)
    persistence.set_key("queue-viewer", digest, salt)
    persistence.set_key_meta("queue-viewer", {"role": "viewer"})
    return TestClient(bridge_app, headers={"X-API-Key": key})


def scorer(scores: dict[str, float]):
    """An RF scorer with fixed results; a missing detection id raises."""

    def score(anomaly):
        value = scores[anomaly["detection_id"]]
        return SimpleNamespace(
            score=value,
            priority="critical" if value >= 0.7 else "low",
            dimensions={"novel_class": value},
            reasons=[f"fixed score {value}"],
            baseline_status="stable",
        )

    return SimpleNamespace(score=score)


def test_bulk_snooze_hides_until_expiry_and_is_audited(
    client, detection_store, app_state, rows
):
    before = datetime.now(timezone.utc)
    ids = [rows["det-a"], rows["det-b"]]
    response = client.put(
        "/api/detections/anomalies/bulk/snooze", json={"ids": ids, "hours": 2}
    )
    after = datetime.now(timezone.utc)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True and body["snoozed_count"] == 2
    until = datetime.fromisoformat(body["snoozed_until"])
    assert before + timedelta(hours=2) <= until <= after + timedelta(hours=2)
    assert active(client) == ["det-c"]
    (entry,) = detection_store.get_audit_log(action="bulk_snooze_rf")
    assert entry["target_id"] == str(ids[0])
    assert f"Snoozed for 2h until {body['snoozed_until']}" in entry["note"]
    assert detection_store.verify_audit_chain()["valid"] is True
    event = app_state.activity_log[-1]
    assert event["event_type"] == "rf_anomaly_bulk_snoozed"
    assert event["details"] == {"ids": ids, "snoozed_until": body["snoozed_until"]}
    # Once the snooze time has passed, the anomalies are back in the queue.
    expired = (before - timedelta(minutes=1)).isoformat()
    assert detection_store.snooze_rf_anomalies_bulk(ids, expired) == 2
    assert active(client) == ["det-a", "det-b", "det-c"]


@pytest.mark.parametrize(
    "body",
    [
        {"ids": [1], "hours": 0},
        {"ids": [1], "hours": 169},
        {"ids": [], "hours": 1},
        {"ids": [1], "hours": 1, "until": "2099-01-01T00:00:00+00:00"},
    ],
)
def test_bulk_snooze_outside_its_bounds_changes_nothing(
    client, detection_store, rows, body
):
    response = client.put("/api/detections/anomalies/bulk/snooze", json=body)
    assert response.status_code == 422
    assert active(client) == ["det-a", "det-b", "det-c"]
    assert detection_store.get_audit_log() == []


def test_single_snooze_is_analyst_only_and_audited(
    client, bridge_app, persistence, detection_store, app_state, rows
):
    url = f"/api/detections/anomalies/{rows['det-b']}/snooze"
    refused = viewer(bridge_app, persistence).put(url, json={"hours": 1})
    assert refused.status_code == 403
    assert active(client) == ["det-a", "det-b", "det-c"]
    response = client.put(url, json={"hours": 1})
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True and body["snoozed_id"] == rows["det-b"]
    assert active(client) == ["det-a", "det-c"]
    (entry,) = detection_store.get_audit_log(action="snooze_rf")
    assert entry["target_id"] == str(rows["det-b"])
    assert entry["note"] == f"Snoozed for 1h until {body['snoozed_until']}"
    event = app_state.activity_log[-1]
    assert event["event_type"] == "rf_anomaly_snoozed"
    assert event["details"] == {
        "anomaly_id": rows["det-b"],
        "snoozed_until": body["snoozed_until"],
    }


def test_summary_counts_only_active_anomalies_above_the_threshold(
    client, detection_store, rows
):
    detection_store.insert_rf_anomalies_batch(
        [
            {
                "detection_id": "det-low",
                "signal_class": "ook",
                "freq_hz": 315.0e6,
                "node_id": "node-c",
                "timestamp": "2026-11-18T00:00:00+00:00",
                "anomaly_score": 0.1,
            }
        ]
    )
    summary = client.get("/api/detections/anomalies/summary").json()
    assert summary["total"] == 3
    assert summary["unique_classes"] == ["bpsk", "fsk", "qpsk"]
    assert summary["unique_nodes"] == ["node-a", "node-b"]
    assert {row["node_id"]: row["count"] for row in summary["by_node"]} == {
        "node-a": 2,
        "node-b": 1,
    }
    high = client.get("/api/detections/anomalies/summary?min_score=0.7").json()
    assert high["total"] == 1 and high["unique_classes"] == ["bpsk"]
    # A dismissal is reflected at once, not after the summary cache expires.
    assert client.put(f"/api/detections/anomalies/{rows['det-a']}/dismiss").is_success
    after = client.get("/api/detections/anomalies/summary").json()
    assert after["total"] == 2 and after["unique_classes"] == ["fsk", "qpsk"]
    out_of_range = client.get("/api/detections/anomalies/summary?min_score=1.5")
    assert out_of_range.status_code == 422


def test_unknown_sort_and_order_fall_back_to_score_descending(
    client, detection_store, rows, monkeypatch
):
    listed = detection_store.get_rf_anomalies
    queried = []

    def recording(**options):
        queried.append((options["sort_by"], options["sort_order"]))
        return listed(**options)

    monkeypatch.setattr(detection_store, "get_rf_anomalies", recording)
    response = client.get(
        "/api/detections/anomalies",
        params={"sort": "anomaly_score; DROP TABLE rf_anomalies", "order": "sideways"},
    )
    assert response.status_code == 200
    # The route itself replaces both before they reach the store.
    assert queried == [("score", "desc")]
    scores = [row["anomaly_score"] for row in response.json()["anomalies"]]
    assert scores == [0.8, 0.6, 0.5]
    assert response.json()["total"] == 3
    # The table is intact and answers ordinary queries afterwards.
    assert active(client) == ["det-a", "det-b", "det-c"]
    ascending = client.get(
        "/api/detections/anomalies", params={"sort": "score", "order": "asc"}
    )
    assert queried[-1] == ("score", "asc")
    assert [row["anomaly_score"] for row in ascending.json()["anomalies"]] == [
        0.5,
        0.6,
        0.8,
    ]


def test_reevaluation_without_a_scorer_returns_the_plain_queue(
    client, bridge_app, rows, monkeypatch
):
    monkeypatch.setattr(bridge_app.state, "rf_scorer", None)
    data = client.get("/api/detections/anomalies?reevaluate=true").json()
    assert data["count"] == 3
    assert "reeval_summary" not in data
    assert all("reeval" not in row for row in data["anomalies"])


def test_reevaluation_without_whitelist_and_with_a_failing_row(
    client, bridge_app, rows, monkeypatch
):
    # det-c has no fixed score, so scoring it raises.
    monkeypatch.setattr(
        bridge_app.state, "rf_scorer", scorer({"det-a": 0.9, "det-b": 0.1})
    )
    monkeypatch.setattr(bridge_app.state, "signal_whitelist", None)
    data = client.get("/api/detections/anomalies?reevaluate=true").json()
    assert data["reeval_summary"] == {"still_anomalous": 1, "resolved": 1}
    by_id = {row["detection_id"]: row for row in data["anomalies"]}
    assert by_id["det-a"]["reeval"]["still_anomalous"] is True
    assert by_id["det-a"]["reeval"]["new_score"] == 0.9
    assert by_id["det-b"]["reeval"] == {
        "still_anomalous": False,
        "new_score": 0.1,
        "score_delta": -0.4,
        "new_priority": "low",
        "new_dimensions": {"novel_class": 0.1},
        "new_reasons": ["fixed score 0.1"],
        "baseline_status": "stable",
    }
    # The row that could not be re-scored is returned as it was, not dropped.
    assert "reeval" not in by_id["det-c"]
    assert by_id["det-c"]["anomaly_score"] == 0.6
    # Re-evaluation only reports; it dismisses nothing.
    assert active(client) == ["det-a", "det-b", "det-c"]


def test_reeval_dismiss_without_a_scorer_is_refused(
    client, bridge_app, rows, monkeypatch
):
    monkeypatch.setattr(bridge_app.state, "rf_scorer", None)
    response = client.post("/api/detections/anomalies/bulk/reeval-dismiss")
    assert response.status_code == 503
    assert response.json()["detail"] == "RF scorer not initialised"
    assert active(client) == ["det-a", "det-b", "det-c"]


def test_reeval_dismiss_dismisses_only_resolved_and_counts_errors(
    client, bridge_app, detection_store, rows, monkeypatch
):
    monkeypatch.setattr(
        bridge_app.state, "rf_scorer", scorer({"det-a": 0.1, "det-b": 0.95})
    )
    response = client.post("/api/detections/anomalies/bulk/reeval-dismiss")
    assert response.status_code == 200
    assert response.json() == {
        "ok": True,
        "processed": 3,
        "still_anomalous": 1,
        "dismissed": 1,
        "errors": 1,
        "remaining_total": 2,
    }
    # The row that could not be scored is kept for the operator.
    assert active(client) == ["det-b", "det-c"]


def test_feedback_recreates_a_missing_dismissed_set(client, detection_store, app_state):
    detection_store.insert_batch(
        [
            DetectionRecord(
                id="det-feedback",
                node_id="node-a",
                signal_class="bpsk",
                freq_hz=433.92e6,
                confidence=0.9,
                anomaly_score=0.7,
            )
        ]
    )
    del app_state.dismissed_anomalies
    response = client.post(
        "/api/detections/anomalies/det-feedback/feedback",
        json={"label": "expected", "note": "garage door"},
    )
    assert response.status_code == 200
    assert response.json()["auto_dismissed"] is True
    assert app_state.dismissed_anomalies == {"det-feedback"}
    (entry,) = detection_store.get_audit_log(action="feedback")
    assert entry["target_id"] == "det-feedback" and entry["note"] == "garage door"


def _pattern(client, **fields):
    body = {
        "freq_min_hz": 433.0e6,
        "freq_max_hz": 434.0e6,
        "signal_class": "bpsk",
        "node_id": "node-a",
    } | fields
    response = client.post("/api/detections/known-signals", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def test_unknown_pattern_cannot_be_edited_or_removed(client, detection_store):
    kept = _pattern(client)
    body = {
        "freq_min_hz": 1.0e6,
        "freq_max_hz": 2.0e6,
        "signal_class": "*",
        "node_id": None,
        "revision": 1,
    }
    url = "/api/detections/known-signals/no-such-pattern"
    edited = client.put(url, json=body)
    assert edited.status_code == 404
    assert edited.json()["detail"] == "Known RF pattern not found"
    removed = client.delete(url + "?revision=1")
    assert removed.status_code == 404
    assert detection_store.known_signals.list() == [kept]
    assert [e["action"] for e in detection_store.get_audit_log()] == [
        "known_signal_create"
    ]


def test_edit_that_duplicates_another_pattern_is_a_conflict(client, detection_store):
    first = _pattern(client)
    second = _pattern(client, freq_min_hz=868.0e6, freq_max_hz=869.0e6)
    body = {
        "freq_min_hz": first["freq_min_hz"],
        "freq_max_hz": first["freq_max_hz"],
        "signal_class": first["signal_class"],
        "node_id": first["node_id"],
        "note": "",
        "revision": second["revision"],
    }
    response = client.put(
        f"/api/detections/known-signals/{second['pattern_id']}", json=body
    )
    assert response.status_code == 409
    assert response.json()["detail"] == (
        "That matching pattern already exists; refresh the list."
    )
    # Both rules are unchanged and no edit was audited.
    assert detection_store.known_signals.list() == [first, second]
    assert [e["action"] for e in detection_store.get_audit_log()] == [
        "known_signal_create",
        "known_signal_create",
    ]
    assert detection_store.verify_audit_chain()["valid"] is True
