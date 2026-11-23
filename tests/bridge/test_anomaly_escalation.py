"""Escalating RF and WiFi anomalies raises a critical alert and dismisses none.

Covers POST /api/detections/anomalies/bulk/escalate and
POST /api/wifi/anomalies/bulk/escalate: one alert per request naming every
escalated anomaly (stored, listed, sent to webhooks, syslog and the live
alert feed), however many it names, so the bounded alert store keeps the
other alerts; no second alert for an anomaly while one naming it is
unacknowledged; unknown and other-tenant IDs reported, the anomalies left
in their queue, sensor-supplied names escaped in the message, the
escalation audited, the analyst role required, and the request body
validated.
"""

from __future__ import annotations

import html
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import MAX_ALERTS, PersistenceManager
from sigrift.lib.security.credentials import generate_api_key, hash_credential

RF = "/api/detections/anomalies"
WIFI = "/api/wifi/anomalies"


def _key(persistence: PersistenceManager, key_id: str, role: str) -> str:
    raw = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw)
    persistence.set_key(key_id, hash_hex, salt)
    persistence.set_key_meta(key_id, {"role": role, "description": f"test {role}"})
    return raw


@pytest.fixture
def notifier(bridge_app: FastAPI) -> MagicMock:
    mock = MagicMock()
    bridge_app.state.notifier = mock
    return mock


@pytest.fixture
def syslog(app_state, monkeypatch) -> MagicMock:
    mock = MagicMock()
    monkeypatch.setattr(app_state, "_syslog_forwarder", mock, raising=False)
    return mock


class _LiveFeed:
    """Stands in for the alert WebSocket clients and records what they get."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def broadcast(self, data: dict) -> None:
        self.sent.append(data)


@pytest.fixture
def live_feed(app_state, monkeypatch) -> _LiveFeed:
    feed = _LiveFeed()
    monkeypatch.setattr(app_state, "ws_alert_clients", feed)
    return feed


@pytest.fixture
def analyst(bridge_app: FastAPI, persistence: PersistenceManager) -> TestClient:
    return TestClient(
        bridge_app, headers={"X-API-Key": _key(persistence, "analyst_key", "analyst")}
    )


@pytest.fixture
def viewer(bridge_app: FastAPI, persistence: PersistenceManager) -> TestClient:
    return TestClient(
        bridge_app, headers={"X-API-Key": _key(persistence, "viewer_key", "viewer")}
    )


@pytest.fixture
def rf_ids(detection_store) -> list[int]:
    return detection_store.insert_rf_anomalies_batch(
        [
            {
                "detection_id": "det-<b>1</b>",
                "signal_class": "dmr",
                "family": "fsk",
                "freq_hz": 446.0e6,
                "node_id": "edge-1",
                "timestamp": "2026-11-10T00:00:00+00:00",
                "anomaly_score": 0.91,
            },
            {
                "detection_id": "det-2",
                "signal_class": "p25",
                "freq_hz": 851.0125e6,
                "node_id": "edge-2",
                "timestamp": "2026-11-10T00:01:00+00:00",
                "anomaly_score": 0.62,
            },
        ]
    )


@pytest.fixture
def wifi_ids(detection_store) -> list[int]:
    return [
        detection_store.insert_wifi_anomaly(
            {
                "bssid": f"aa:bb:cc:11:22:{i:02x}",
                "ssid": f"Net{i}",
                "anomaly_score": 0.8 - i / 10,
                "priority": "critical",
                "dimensions": {"evil_twin": 1.0},
                "node_id": "node-01",
                "timestamp": "2026-11-10T00:00:00+00:00",
            }
        )
        for i in range(2)
    ]


def _alerts(client: TestClient, name: str) -> list[dict]:
    resp = client.get("/api/alerts/", params={"limit": 500})
    assert resp.status_code == 200
    return [a for a in resp.json() if a["name"] == name]


def _other_tenant(detection_store: DetectionStore) -> DetectionStore:
    """The same database, seen as another tenant."""
    return DetectionStore(db_path=detection_store.db_path, tenant_id="other")


def _rf_anomaly(i: int, **fields) -> dict:
    # A frequency of its own: the store merges anomalies of one class and
    # 100 kHz bucket.
    return {
        "detection_id": f"det-{i}",
        "signal_class": "dmr",
        "freq_hz": 446.0e6 + i * 1e6,
        "node_id": "edge-1",
        "timestamp": "2026-11-10T00:00:00+00:00",
        "anomaly_score": 0.5,
        **fields,
    }


class TestRfEscalation:
    def test_one_critical_alert_names_every_anomaly_and_they_stay_in_the_queue(
        self, client, analyst, notifier, syslog, live_feed, rf_ids, persistence
    ):
        missing = max(rf_ids) + 100
        resp = analyst.post(f"{RF}/bulk/escalate", json={"ids": [*rf_ids, missing]})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["escalated_count"] == 2
        assert data["escalated"] == rf_ids
        assert data["already_escalated"] == []
        assert data["not_found"] == [missing]

        [alert] = _alerts(client, "anomaly_escalated")
        assert alert["alert_id"] == data["alert_id"]
        assert alert["severity"] == "critical"
        assert alert["acknowledged"] is False
        # The anomalies are from two nodes: the alert is not filed under one.
        assert alert["node_id"] is None
        assert alert["message"] == (
            "Escalated by an operator: 2 RF anomalies: dmr score 0.91 at "
            "446.00 MHz on edge-1; p25 score 0.62 at 851.01 MHz on edge-2"
        )
        [stored] = [
            a for a in persistence.get_alerts() if a["name"] == "anomaly_escalated"
        ]
        assert (
            stored["anomaly_ids"],
            stored["detection_ids"],
            stored["anomaly_score"],
            stored["escalated_by"],
        ) == (rf_ids, ["det-<b>1</b>", "det-2"], 0.91, "analyst_key")
        assert "freq_hz" not in stored, "two frequencies: none is the alert's"
        # Webhooks, syslog and the live alert feed receive that one alert.
        assert [c.args[0]["alert_id"] for c in notifier.submit.call_args_list] == [
            data["alert_id"]
        ]
        [forwarded] = [c.args[0] for c in syslog.submit.call_args_list]
        assert forwarded["alert_id"] == data["alert_id"]
        assert "signal_class" not in forwarded, "two classes: none is the alert's"
        assert [a["alert_id"] for a in live_feed.sent] == [data["alert_id"]]

        # Nothing was dismissed: both anomalies are still in the queue.
        listed = client.get(RF).json()
        assert sorted(a["id"] for a in listed["anomalies"]) == sorted(rf_ids)
        assert all(not a.get("dismissed") for a in listed["anomalies"])

        audit = client.get(f"{RF}/audit", params={"action": "bulk_escalate_rf"}).json()
        assert audit["count"] == 1
        assert audit["entries"][0]["operator"] == "analyst_key"
        assert audit["entries"][0]["target_id"] == str(rf_ids[0])

    def test_anomalies_of_one_node_and_class_file_the_alert_under_them(
        self, client, analyst, syslog, detection_store, persistence
    ):
        def escalate(ids):
            data = analyst.post(f"{RF}/bulk/escalate", json={"ids": ids}).json()
            [stored] = [
                a for a in persistence.get_alerts() if a["alert_id"] == data["alert_id"]
            ]
            return stored, syslog.submit.call_args_list[-1].args[0]

        ids = detection_store.insert_rf_anomalies_batch(
            [_rf_anomaly(i, anomaly_score=score) for i, score in enumerate((0.6, 0.8))]
        )
        stored, forwarded = escalate(ids)
        assert (stored["node_id"], stored["anomaly_score"]) == ("edge-1", 0.8)
        assert [a["node_id"] for a in _alerts(client, "anomaly_escalated")] == [
            "edge-1"
        ]
        assert forwarded["signal_class"] == "dmr"
        assert "freq_hz" not in stored and "freq_hz" not in forwarded
        # A single anomaly: its frequency is the alert's.
        stored, forwarded = escalate(
            detection_store.insert_rf_anomalies_batch([_rf_anomaly(5)])
        )
        assert stored["freq_hz"] == forwarded["freq_hz"] == 451.0e6

    @pytest.mark.parametrize(
        ("count", "ending"),
        [(5, "on edge-4"), (6, "on edge-4; and 1 more")],
    )
    def test_the_message_describes_five_anomalies_and_counts_the_rest(
        self, client, analyst, detection_store, count, ending
    ):
        ids = detection_store.insert_rf_anomalies_batch(
            [_rf_anomaly(i, node_id=f"edge-{i}") for i in range(count)]
        )
        analyst.post(f"{RF}/bulk/escalate", json={"ids": ids})
        [alert] = _alerts(client, "anomaly_escalated")
        described = alert["message"].split(": ", 1)[1]
        assert described.startswith(f"{count} RF anomalies: dmr score 0.50 ")
        assert described.count("dmr score") == 5
        assert described.endswith(ending)

    def test_a_full_request_adds_one_alert_and_the_store_keeps_the_others(
        self, client, analyst, notifier, detection_store, persistence
    ):
        for i in range(MAX_ALERTS - 10):
            persistence.add_alert(
                {"alert_id": f"older_{i}", "name": "older", "severity": "warning"}
            )
        ids = detection_store.insert_rf_anomalies_batch(
            [_rf_anomaly(i, node_id=f"edge-{i}") for i in range(100)]
        )
        data = analyst.post(f"{RF}/bulk/escalate", json={"ids": ids}).json()
        assert data["escalated"] == ids
        kept = [a["alert_id"] for a in persistence.get_alerts()]
        assert kept[: MAX_ALERTS - 10] == [f"older_{i}" for i in range(MAX_ALERTS - 10)]
        assert kept[MAX_ALERTS - 10 :] == [data["alert_id"]]
        assert notifier.submit.call_count == 1
        [alert] = _alerts(client, "anomaly_escalated")
        assert alert["message"].startswith(
            "Escalated by an operator: 100 RF anomalies: "
        )
        assert alert["message"].endswith(
            "dmr score 0.50 at 450.00 MHz on edge-4; and 95 more"
        )
        # Every anomaly it names counts as escalated, the undescribed too.
        again = analyst.post(f"{RF}/bulk/escalate", json={"ids": ids[-3:]}).json()
        assert again["already_escalated"] == ids[-3:]

    def test_an_open_escalation_is_not_alerted_twice_until_acknowledged(
        self, client, analyst, notifier, rf_ids
    ):
        first = analyst.post(f"{RF}/bulk/escalate", json={"ids": [rf_ids[0]]}).json()
        second = analyst.post(f"{RF}/bulk/escalate", json={"ids": rf_ids}).json()
        assert second["escalated"] == [rf_ids[1]]
        assert second["already_escalated"] == [rf_ids[0]]
        again = analyst.post(
            f"{RF}/bulk/escalate", json={"ids": [*rf_ids, rf_ids[0]]}
        ).json()
        assert (again["escalated_count"], again["alert_id"]) == (0, None)
        assert again["already_escalated"] == rf_ids
        assert len(_alerts(client, "anomaly_escalated")) == 2

        acked = first["alert_id"]
        assert analyst.put(f"/api/alerts/{acked}/ack").status_code == 200
        third = analyst.post(f"{RF}/bulk/escalate", json={"ids": rf_ids}).json()
        assert third["escalated"] == [rf_ids[0]]
        assert third["already_escalated"] == [rf_ids[1]]
        assert len(_alerts(client, "anomaly_escalated")) == 3
        assert notifier.submit.call_count == 3

    def test_sensor_supplied_names_are_escaped_in_the_alert_message(
        self, client, analyst, detection_store
    ):
        markup = '<img src=x onerror="alert(1)">'
        ids = detection_store.insert_rf_anomalies_batch(
            [_rf_anomaly(0, signal_class=markup, node_id=markup + "&")]
        )
        analyst.post(f"{RF}/bulk/escalate", json={"ids": ids})
        [alert] = _alerts(client, "anomaly_escalated")
        assert "<" not in alert["message"] and '"' not in alert["message"]
        assert html.unescape(alert["message"]) == (
            f"Escalated by an operator: 1 RF anomaly: {markup} score 0.50 at "
            f"446.00 MHz on {markup}&"
        )

    def test_another_tenants_anomaly_is_not_found_and_not_alerted(
        self, client, analyst, notifier, detection_store
    ):
        [foreign] = _other_tenant(detection_store).insert_rf_anomalies_batch(
            [_rf_anomaly(0, signal_class="secret-class", node_id="their-node")]
        )
        [own] = detection_store.insert_rf_anomalies_batch([_rf_anomaly(1)])
        data = analyst.post(f"{RF}/bulk/escalate", json={"ids": [foreign, own]}).json()
        assert data["not_found"] == [foreign]
        assert data["escalated"] == [own]
        [alert] = _alerts(client, "anomaly_escalated")
        assert "secret-class" not in alert["message"]
        assert "their-node" not in alert["message"]
        assert notifier.submit.call_count == 1

    def test_a_viewer_cannot_escalate(self, client, viewer, notifier, rf_ids):
        resp = viewer.post(f"{RF}/bulk/escalate", json={"ids": rf_ids})
        assert resp.status_code == 403
        assert _alerts(client, "anomaly_escalated") == []
        notifier.submit.assert_not_called()

    @pytest.mark.parametrize(
        "body",
        [
            {"ids": []},
            {"ids": list(range(1, 102))},
            {"ids": [1], "dismiss": True},
            {"ids": ["x"]},
            {},
        ],
    )
    def test_a_malformed_request_is_refused(self, client, analyst, body):
        assert analyst.post(f"{RF}/bulk/escalate", json=body).status_code == 422
        assert _alerts(client, "anomaly_escalated") == []

    def test_dismiss_is_not_reachable_through_escalate(self, analyst, rf_ids):
        # The old placeholder sent escalations to bulk/dismiss with PUT.
        assert (
            analyst.put(f"{RF}/bulk/escalate", json={"ids": rf_ids}).status_code == 405
        )


def _wifi_anomaly(store: DetectionStore, **fields) -> int:
    return store.insert_wifi_anomaly(
        {
            "bssid": "aa:bb:cc:11:22:ff",
            "ssid": "Net",
            "anomaly_score": 0.5,
            "priority": "critical",
            "dimensions": {"evil_twin": 1.0},
            "node_id": "node-01",
            "timestamp": "2026-11-10T00:00:00+00:00",
            **fields,
        }
    )


class TestWifiEscalation:
    def test_one_critical_alert_names_every_anomaly_and_they_stay_in_the_queue(
        self, client, analyst, notifier, syslog, wifi_ids, persistence
    ):
        missing = max(wifi_ids) + 100
        resp = analyst.post(
            f"{WIFI}/bulk/escalate",
            json={"ids": [str(i) for i in wifi_ids] + [missing]},
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["escalated_count"] == 2
        assert data["escalated"] == wifi_ids
        assert data["not_found"] == [missing]

        [alert] = _alerts(client, "wifi_anomaly_escalated")
        assert (alert["alert_id"], alert["severity"]) == (data["alert_id"], "critical")
        assert alert["node_id"] == "node-01"
        assert alert["message"] == (
            "Escalated by an operator: 2 WiFi anomalies: score 0.80 for Net0 on "
            "node-01; score 0.70 for Net1 on node-01"
        )
        [stored] = [
            a for a in persistence.get_alerts() if a["name"] == "wifi_anomaly_escalated"
        ]
        assert (stored["anomaly_ids"], stored["bssids"], stored["anomaly_score"]) == (
            wifi_ids,
            ["aa:bb:cc:11:22:00", "aa:bb:cc:11:22:01"],
            0.8,
        )
        assert notifier.submit.call_count == 1
        [forwarded] = [c.args[0] for c in syslog.submit.call_args_list]
        assert (forwarded["alert_id"], forwarded["signal_class"]) == (
            data["alert_id"],
            "wifi",
        )

        listed = client.get(WIFI).json()
        assert sorted(a["id"] for a in listed["anomalies"]) == sorted(wifi_ids)

        again = analyst.post(f"{WIFI}/bulk/escalate", json={"ids": wifi_ids}).json()
        assert again["escalated_count"] == 0
        assert again["already_escalated"] == wifi_ids

    def test_each_escalated_anomaly_is_audited(
        self, client, analyst, wifi_ids, detection_store
    ):
        missing = max(wifi_ids) + 100
        data = analyst.post(
            f"{WIFI}/bulk/escalate", json={"ids": [*wifi_ids, missing]}
        ).json()
        entries = detection_store.get_audit_log(action="wifi_anomaly_escalate")
        assert sorted(
            (e["target_id"], e["operator"], e["note"]) for e in entries
        ) == sorted(
            (str(i), "analyst_key", f"Raised critical alert {data['alert_id']}")
            for i in wifi_ids
        )
        # A request that raises nothing audits nothing.
        analyst.post(f"{WIFI}/bulk/escalate", json={"ids": wifi_ids})
        assert len(detection_store.get_audit_log(action="wifi_anomaly_escalate")) == 2

    def test_sensor_supplied_names_are_escaped_in_the_alert_message(
        self, client, analyst, detection_store
    ):
        markup = "<svg onload='alert(1)'>"
        anomaly_id = _wifi_anomaly(detection_store, ssid=markup, node_id="n&" + markup)
        analyst.post(f"{WIFI}/bulk/escalate", json={"ids": [anomaly_id]})
        [alert] = _alerts(client, "wifi_anomaly_escalated")
        assert "<" not in alert["message"] and "'" not in alert["message"]
        assert html.unescape(alert["message"]) == (
            f"Escalated by an operator: 1 WiFi anomaly: score 0.50 for {markup} "
            f"on n&{markup}"
        )

    def test_another_tenants_anomaly_is_not_found_and_not_alerted(
        self, client, analyst, notifier, detection_store
    ):
        foreign = _wifi_anomaly(_other_tenant(detection_store), ssid="TheirNet")
        own = _wifi_anomaly(detection_store)
        data = analyst.post(
            f"{WIFI}/bulk/escalate", json={"ids": [foreign, own]}
        ).json()
        assert (data["escalated"], data["not_found"]) == ([own], [foreign])
        [alert] = _alerts(client, "wifi_anomaly_escalated")
        assert "TheirNet" not in alert["message"]
        assert notifier.submit.call_count == 1

    def test_a_viewer_cannot_escalate(self, client, viewer, notifier, wifi_ids):
        assert (
            viewer.post(f"{WIFI}/bulk/escalate", json={"ids": wifi_ids}).status_code
            == 403
        )
        assert _alerts(client, "wifi_anomaly_escalated") == []
        notifier.submit.assert_not_called()

    @pytest.mark.parametrize(
        "body", [{"ids": []}, {"ids": list(range(1, 102))}, {"ids": [1], "x": 1}]
    )
    def test_a_malformed_request_is_refused(self, client, analyst, body):
        assert analyst.post(f"{WIFI}/bulk/escalate", json=body).status_code == 422
        assert _alerts(client, "wifi_anomaly_escalated") == []
