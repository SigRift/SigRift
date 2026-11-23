"""HTML-encoded alert fields preserve user text without nested encoding."""

import html
from datetime import datetime, timezone

import pytest

from sigrift.bridge.alert_engine import AlertEngine


NAMES = [
    "Operator's <rule> & monitor",
    "Literal &amp; &lt;tag&gt; &#x27;",
    '<img src=x onerror="alert(1)">',
]


@pytest.mark.parametrize("name", NAMES)
def test_engine_summary_encodes_raw_rule_name_exactly_once(name):
    wire_name = html.escape(name)
    result = AlertEngine().evaluate(
        {"node_id": "test-node", "signal_class": "bpsk", "freq_hz": 433920000},
        [
            {
                "rule_id": "test-rule",
                "name": wire_name,
                "conditions": [
                    {"field": "signal_class", "operator": "eq", "value": "bpsk"}
                ],
            }
        ],
    )[0]
    expected = f"Rule '{name}' triggered on test-node: bpsk at 433.92 MHz (signal_class eq bpsk)"
    assert result["rule_name"] == wire_name
    assert result["detection_summary"] == html.escape(expected)
    assert html.unescape(result["detection_summary"]) == expected


@pytest.mark.parametrize("name", NAMES)
def test_rule_create_ingest_and_edit_keep_encoded_api_contract(
    client, registered_node, name
):
    response = client.post(
        "/api/alerts/rules/conditions",
        json={
            "name": name,
            "conditions": [
                {"field": "signal_class", "operator": "eq", "value": "bpsk"}
            ],
            "notify_webhook": False,
            "cooldown_seconds": 0,
        },
    )
    assert response.status_code == 201
    rule = response.json()
    assert rule["name"] == html.escape(name)
    now = datetime.now(timezone.utc).isoformat()
    ingested = client.post(
        "/api/detections/batch",
        json={
            "node_id": registered_node,
            "period_start": now,
            "period_end": now,
            "detections": [
                {
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.92,
                    "family": "psk",
                    "freq_hz": 433920000,
                    "timestamp": now,
                }
            ],
        },
    )
    assert ingested.status_code == 201
    assert ingested.json()["alerts_created"] >= 1
    alerts = client.get("/api/alerts/")
    assert alerts.status_code == 200
    expected = f"Rule '{name}' triggered on {registered_node}: bpsk at 433.92 MHz (signal_class eq bpsk)"
    matching = [a for a in alerts.json() if a["message"] == html.escape(expected)]
    assert len(matching) == 1
    # Request fields remain plain text; wire/storage response fields remain
    # encoded. Saving the visible name preserves the original wire value.
    edited = client.put(
        f"/api/alerts/rules/conditions/{rule['rule_id']}",
        json={"name": name, "cooldown_seconds": 42},
    )
    assert edited.status_code == 200
    readback = client.get(f"/api/alerts/rules/conditions/{rule['rule_id']}")
    assert readback.status_code == 200
    assert readback.json()["name"] == html.escape(name)
