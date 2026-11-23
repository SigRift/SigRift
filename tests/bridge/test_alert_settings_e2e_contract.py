"""The browser's completion barrier consumes actual serialized public alerts."""

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.bridge.models import DetectionRecord
from sigrift.bridge.routers.detections import post_ingest


@pytest.mark.parametrize("different", [None, "name", "node", "detection"])
def test_browser_rule_barrier_matches_public_alert_identity(
    client, bridge_app, detection_store, different
):
    node_id = "public-contract-receiver"
    detection_id = "public-contract-outside"
    created = client.post(
        "/api/alerts/rules/conditions",
        json={
            "name": "FM contract unique-control",
            "conditions": [
                {"field": "node_id", "operator": "eq", "value": node_id},
                {"field": "freq_hz", "operator": "between", "value": [80e6, 120e6]},
            ],
            "cooldown_seconds": 0,
            "notify_webhook": False,
        },
    )
    assert created.status_code == 201
    rule = created.json()
    detection = DetectionRecord(
        id=detection_id,
        node_id=node_id,
        signal_class="bpsk",
        freq_hz=109e6,
        confidence=0.99,
        anomaly_score=0.01,
        power_dbm=-70,
    )
    detection_store.insert_batch([detection])
    asyncio.run(post_ingest(bridge_app, [detection], node_id, native_analysis=True))
    response = client.get("/api/alerts/?limit=500")
    assert response.status_code == 200
    public = response.json()
    matching = [a for a in public if a["name"] == "rule_" + rule["name"]]
    assert len(matching) == 1
    assert matching[0]["node_id"] == node_id
    assert matching[0]["rf_detection_id"] == detection_id
    assert "rule_id" not in matching[0]

    # Execute the exact nested browser waiter, with its real HTTP route and a
    # deterministic clock. No alternate implementation of its match condition:
    # the fake clock only avoids waiting20s for each deliberate negative case.
    path = Path(__file__).parents[1] / "e2e/test_alert_settings.py"
    module = ast.parse(path.read_text(), filename=str(path))
    case = next(
        n
        for n in module.body
        if isinstance(n, ast.FunctionDef) and n.name.startswith("test_alert_settings_")
    )
    waiter = next(
        n
        for n in case.body
        if isinstance(n, ast.FunctionDef) and n.name == "wait_for_alert"
    )
    clock = iter([0, 0, 21])
    calls = []

    def request(method, url):
        calls.append((method, url))
        actual = client.request(method, url)
        assert actual.status_code == 200
        return actual.json()

    expected_rule = dict(rule)
    expected_node = node_id
    expected_detection = detection_id
    if different == "name":
        expected_rule["name"] = "different-condition-name"
    elif different == "node":
        expected_node = "different-receiver"
    elif different == "detection":
        expected_detection = "different-detection"
    namespace = {
        "time": SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _s: None),
        "admin_api": SimpleNamespace(request=request),
        "rule": expected_rule,
        "node_id": expected_node,
    }
    exec(
        compile(ast.Module(body=[waiter], type_ignores=[]), str(path), "exec"),
        namespace,
    )
    if different is None:
        assert namespace["wait_for_alert"](expected_detection) == public
    else:
        with pytest.raises(AssertionError, match="did not alert"):
            namespace["wait_for_alert"](expected_detection)
    assert calls == [("GET", "/api/alerts/?limit=500")]
