"""Radio-reported names are stored as heard and escaped where they are shown.

Every Wi-Fi ingest route used to HTML-escape SSIDs (and security and frame
text) before storing them, and /api/bluetooth/ingest did the same to device
names while /api/bluetooth/ingest-summary did not. The pages escape on
output as well, so the escaped copies showed entities such as ``&#x27;``.
These cases pin the one rule now used everywhere: store what the radio
sent, escape it in the page (tests/bridge/js/ covers the rendering), and
keep the HTML-encoded alert message encoded exactly once.
"""

from __future__ import annotations

import html
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from sigrift.bridge import bundles
from sigrift.bridge.anomaly.bt_scorer import BtAnomalyScorer, BtBaselineManager
from sigrift.bridge.anomaly.wifi_scorer import WifiAnomalyResult, WifiBaselineManager

NAME = 'Joe\'s "Cafe" & <b>Bar</b>'
BSSID = "aa:bb:cc:11:22:33"


@pytest.fixture(autouse=True)
def _clear_wifi_rate_limit():
    from sigrift.bridge.routers.wifi import _wifi_ingest_cooldown

    _wifi_ingest_cooldown.clear()


class _OneAnomalyScorer:
    """Scores every batch as one critical anomaly carrying the batch's text."""

    def score_batch(self, records, node_id):
        rec = records[0]
        frame = {"ssid": rec["ssid"], "security": rec["security"]}
        frame["frame_type"] = rec["frame_type"]
        return [
            WifiAnomalyResult(
                bssid=rec["bssid"],
                ssid=rec["ssid"],
                security=rec["security"],
                score=0.95,
                priority="critical",
                frame_capture=[frame],
            )
        ]


def _networks(client: TestClient) -> list[dict]:
    resp = client.get("/api/wifi/networks")
    assert resp.status_code == 200
    return resp.json()["networks"]


def test_raw_wifi_ingest_stores_ssid_and_frame_text_as_heard(
    client: TestClient, registered_node: str, bridge_app
):
    bridge_app.state.wifi_scorer = _OneAnomalyScorer()
    record = {
        "bssid": BSSID,
        "ssid": NAME,
        "channel": 6,
        "band": "2.4GHz",
        "security": "WPA2 <&>",
        "frame_type": "beacon's",
        "signal_dbm": -45.0,
    }
    resp = client.post(
        "/api/wifi/ingest", json={"node_id": registered_node, "records": [record]}
    )
    assert resp.status_code == 201, resp.text

    [network] = _networks(client)
    assert (network["ssid"], network["security"]) == (NAME, "WPA2 <&>")

    resp = client.get("/api/wifi/anomalies?include_frames=true")
    [anomaly] = resp.json()["anomalies"]
    assert anomaly["ssid"] == NAME
    assert anomaly["frame_capture"] == [
        {"ssid": NAME, "security": "WPA2 <&>", "frame_type": "beacon's"}
    ]
    # The alert message is the one documented HTML-encoded field: encoded
    # once, so the page's single decode shows the SSID as heard.
    alerts = client.get("/api/alerts/").json()
    [alert] = [a for a in alerts if a["name"] == "wifi_anomaly_detected"]
    assert alert["message"] == html.escape(
        f"WiFi anomaly score 0.95 for {NAME} on {registered_node}"
    )


def test_summary_wifi_ingest_stores_ssid_and_frame_text_as_heard(
    client: TestClient, registered_node: str, bridge_app
):
    bridge_app.state.wifi_scorer = _OneAnomalyScorer()
    resp = client.post(
        "/api/wifi/ingest-summary",
        json={
            "node_id": registered_node,
            "scan_period_s": 60.0,
            "total_frames": 1,
            "networks": [
                {
                    "bssid": BSSID,
                    "ssid": NAME + "\x00\x1f",
                    "channel": 6,
                    "band": "2.4GHz",
                    "security": "WPA2 <&>",
                    "signal_avg_dbm": -50.0,
                    "frame_count": 1,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    # Control characters are still stripped; nothing else changes.
    [network] = _networks(client)
    assert (network["ssid"], network["security"]) == (NAME, "WPA2 <&>")

    resp = client.get("/api/wifi/anomalies?include_frames=true")
    [anomaly] = resp.json()["anomalies"]
    assert (anomaly["ssid"], anomaly["security"]) == (NAME, "WPA2 <&>")
    assert anomaly["frame_capture"] == [
        {"ssid": NAME, "security": "WPA2 <&>", "frame_type": "summary"}
    ]


def test_both_bluetooth_ingest_routes_store_names_alike(
    client: TestClient, registered_node: str
):
    resp = client.post(
        "/api/bluetooth/ingest",
        json={
            "node_id": registered_node,
            "records": [
                {
                    "device_addr": "AA:BB:CC:DD:EE:01",
                    "device_name": NAME,
                    "device_type": "ble's",
                    "device_class_name": "<Phone>",
                    "manufacturer": "A&B",
                    "rssi_dbm": -40,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    resp = client.post(
        "/api/bluetooth/ingest-summary",
        json={
            "node_id": registered_node,
            "scan_period_s": 30,
            "total_observations": 1,
            "devices": [
                {
                    "device_addr": "AA:BB:CC:DD:EE:02",
                    "device_name": NAME,
                    "device_type": "ble",
                    "manufacturer": "A&B",
                    "rssi_avg_dbm": -20,
                    "rssi_max_dbm": -20,
                    "observation_count": 1,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    devices = {
        d["device_addr"]: d
        for d in client.get("/api/bluetooth/devices").json()["devices"]
    }
    for addr in ("AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"):
        assert (devices[addr]["device_name"], devices[addr]["manufacturer"]) == (
            NAME,
            "A&B",
        )
    assert devices["AA:BB:CC:DD:EE:01"]["device_type"] == "ble's"
    assert devices["AA:BB:CC:DD:EE:01"]["device_class_name"] == "<Phone>"


# ---------------------------------------------------------------------------
# Wi-Fi baselines saved while SSIDs were stored escaped
# ---------------------------------------------------------------------------

ESCAPED = html.escape(NAME)
LITERAL = "AT&amp;T"  # an SSID that really is spelled with an entity


def _state(version: int | None) -> dict:
    state = {
        "alpha": 0.02,
        "baselines": {
            BSSID: {"expected_ssids": [ESCAPED], "total_observations": 60},
            "dd:ee:ff:44:55:66": {"expected_ssids": [ESCAPED, LITERAL]},
        },
        "ssid_to_bssids": {
            ESCAPED: [BSSID, "dd:ee:ff:44:55:66"],
            LITERAL: ["dd:ee:ff:44:55:66"],
        },
    }
    if version is not None:
        state["schema_version"] = version
    return state


@pytest.mark.parametrize("version", [None, 1])
def test_a_schema_1_baseline_file_is_read_as_heard_and_saved_as_schema_2(
    tmp_path: Path, version
):
    path = tmp_path / "wifi_baselines.json"
    path.write_text(json.dumps(_state(version)))
    mgr = WifiBaselineManager()
    mgr.load(str(path))
    # The evil-twin index matches the SSID a radio now reports.
    assert mgr.get_bssids_for_ssid(NAME) == {BSSID, "dd:ee:ff:44:55:66"}
    assert mgr.get_bssids_for_ssid(ESCAPED) == set()
    # Exactly one layer: the escaped literal becomes the literal SSID.
    assert mgr.get_bssids_for_ssid("AT&T") == {"dd:ee:ff:44:55:66"}
    assert mgr.get_baseline(BSSID).expected_ssids == {NAME}
    assert mgr.dirty, "the decoded state is saved as schema 2"

    mgr.save(str(path))
    saved = json.loads(path.read_text())
    assert saved["schema_version"] == WifiBaselineManager.SCHEMA_VERSION == 2
    again = WifiBaselineManager()
    again.load(str(path))
    assert again.get_bssids_for_ssid("AT&T") == {"dd:ee:ff:44:55:66"}
    assert again.get_baseline(BSSID).expected_ssids == {NAME}
    assert not again.dirty


def test_a_schema_2_baseline_file_keeps_entity_spelled_ssids(tmp_path: Path):
    path = tmp_path / "wifi_baselines.json"
    path.write_text(json.dumps(_state(2)))
    mgr = WifiBaselineManager()
    mgr.load(str(path))
    assert mgr.get_bssids_for_ssid(LITERAL) == {"dd:ee:ff:44:55:66"}
    assert mgr.get_bssids_for_ssid(ESCAPED) == {BSSID, "dd:ee:ff:44:55:66"}
    assert not mgr.dirty


# Raw SSIDs html.unescape() would also rewrite: legacy entity names without a
# semicolon, named and numeric entities html.escape() never writes.
RAW_WITH_ENTITIES = ["Bob&copy", "Lab&not1", "Tom&reg;", "AP&#38;1", "x&#39;s"]


def test_a_schema_1_file_mixing_raw_ssids_decodes_only_the_escaped_ones(
    tmp_path: Path,
):
    """An older bridge saves schema 1 after a rollback with raw SSIDs in it.

    Those are the schema 2 SSIDs it loaded, next to the escaped ones its own
    ingest learned; upgrading again must decode the escaped ones exactly and
    leave every raw one as it is.
    """
    state = _state(1)
    for n, ssid in enumerate(RAW_WITH_ENTITIES):
        bssid = f"02:00:00:00:00:{n:02x}"
        state["baselines"][bssid] = {"expected_ssids": [ssid]}
        state["ssid_to_bssids"][ssid] = [bssid]
    path = tmp_path / "wifi_baselines.json"
    path.write_text(json.dumps(state))
    mgr = WifiBaselineManager()
    mgr.load(str(path))
    for n, ssid in enumerate(RAW_WITH_ENTITIES):
        bssid = f"02:00:00:00:00:{n:02x}"
        assert mgr.get_bssids_for_ssid(ssid) == {bssid}, ssid
        assert mgr.get_baseline(bssid).expected_ssids == {ssid}, ssid
    assert mgr.get_bssids_for_ssid(NAME) == {BSSID, "dd:ee:ff:44:55:66"}
    assert mgr.get_bssids_for_ssid("AT&T") == {"dd:ee:ff:44:55:66"}

    _, ssid_to_bssids, _ = bundles.load_wifi_baselines_from_bytes(
        json.dumps(state).encode()
    )
    assert set(ssid_to_bssids) == {NAME, "AT&T", *RAW_WITH_ENTITIES}


@pytest.mark.parametrize(
    ("version", "expected"),
    [(None, {NAME, "AT&T"}), (1, {NAME, "AT&T"}), (2, {ESCAPED, LITERAL})],
)
def test_baseline_bundles_are_read_by_their_schema(version, expected):
    baselines, ssid_to_bssids, _ = bundles.load_wifi_baselines_from_bytes(
        json.dumps(_state(version)).encode()
    )
    assert set(ssid_to_bssids) == expected
    assert baselines["dd:ee:ff:44:55:66"].expected_ssids == expected


# ---------------------------------------------------------------------------
# Bluetooth baselines learned while /api/bluetooth/ingest stored names escaped
# ---------------------------------------------------------------------------


def _bt(name: str, manufacturer: str = "A&B") -> dict:
    return {
        "device_addr": "11:22:33:44:55:66",
        "device_name": name,
        "device_type": "ble",
        "device_class": 0x20010C,
        "manufacturer": manufacturer,
        "rssi_dbm": -55.0,
        "service_uuids": [],
    }


def _dimension(results: list, name: str) -> float:
    return results[0].dimensions.get(name, 0.0) if results else 0.0


def test_a_bluetooth_name_learned_escaped_is_not_a_changed_identity():
    mgr = BtBaselineManager()
    scorer = BtAnomalyScorer(mgr)
    for _ in range(5):
        scorer.score_batch([_bt(html.escape(NAME), html.escape("A&B"))], "node-01")

    results = scorer.score_batch([_bt(NAME)], "node-01")
    assert _dimension(results, "spoofed_identity") == 0.0
    assert _dimension(results, "ble_beacon_spoof") == 0.0
    # The baseline now holds the name as heard.
    baseline = mgr.baselines["11:22:33:44:55:66"]
    assert (baseline.expected_name, baseline.expected_manufacturer) == (NAME, "A&B")

    # A real change still counts, against the name as heard.
    results = scorer.score_batch([_bt("Other")], "node-01")
    assert _dimension(results, "spoofed_identity") >= 0.7
    assert f"name '{NAME}' → 'Other'" in " ".join(results[0].reasons)
