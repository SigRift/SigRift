"""Security tests for the admin system-config router (``/api/admin/...``).

Covers ``routers/system_config.py``:

* every route of the router refuses unauthenticated callers (401) and every
  role below ADMIN, ANALYST included (403), a refused request changes
  nothing (detection config, both whitelists, snapshots, session binding,
  RF anomaly rows, the audit log), and ADMIN succeeds (2xx);
* ``GET /sessions`` never discloses a full session token;
* ``POST /wifi-whitelist``: BSSID validation and normalisation, duplicate
  detection across separators and case, HTML escaping and the notes cap,
  the live scorer sync and the audit trail; ``DELETE`` likewise;
* ``PUT /detection-config``: weight dicts merge, the live scorer and the
  ingest alerting follow, a pre-change snapshot holds the old values, and
  the audit entry names the operator and only the keys that changed;
* ``POST /rescore-rf-anomalies``: floor / threshold removal, rounded
  updates, a critical audit entry, and a part-way failure rolls back every
  row; ``POST /simulate-rescore-rf`` writes nothing;
* ``PUT /protocols`` toggles only protocols that already exist.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security import credentials
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)


@pytest.fixture(autouse=True)
def _fast_pbkdf2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(credentials, "_PBKDF2_ITERATIONS", 1_000)


def _add_key(persistence: PersistenceManager, key_id: str, role: str) -> str:
    raw = generate_api_key(32)
    digest, salt = hash_credential(raw)
    assert persistence.add_key(
        key_id,
        digest,
        salt,
        lookup_hash=compute_lookup_hash(raw),
        meta={"role": role, "description": "", "created_at": "", "expires_at": None},
    )
    return raw


@pytest.fixture
def role_clients(bridge_app: FastAPI, persistence: PersistenceManager):
    """TestClients for every role below ADMIN, plus an anonymous one."""
    clients = {
        role: TestClient(
            bridge_app,
            headers={"X-API-Key": _add_key(persistence, f"sc_{role}", role)},
        )
        for role in ("sensor", "node", "viewer", "analyst")
    }
    clients["anonymous"] = TestClient(bridge_app)
    return clients


# ---------------------------------------------------------------------------
# Role checks
# ---------------------------------------------------------------------------

# Every route of the router; {snap} is an existing config snapshot, {wl} and
# {bt} existing whitelist entries (so a refused DELETE has something to
# remove, and the admin's DELETE succeeds).
_ROUTES: list[tuple[str, str, Any]] = [
    ("GET", "/api/admin/detection-config", None),
    ("PUT", "/api/admin/detection-config", {"rf_anomaly_alert_threshold": 0.01}),
    ("POST", "/api/admin/rescore-rf-anomalies", None),
    ("POST", "/api/admin/simulate-rescore-rf", None),
    ("GET", "/api/admin/config", None),
    ("GET", "/api/admin/stats", None),
    ("GET", "/api/admin/sessions", None),
    ("GET", "/api/admin/wifi-whitelist", None),
    ("POST", "/api/admin/wifi-whitelist", {"bssid": "AA:BB:CC:DD:EE:FF"}),
    ("DELETE", "/api/admin/wifi-whitelist/{wl}", None),
    ("GET", "/api/admin/bt-whitelist", None),
    ("POST", "/api/admin/bt-whitelist", {"device_addr": "AA:BB:CC:DD:EE:FF"}),
    ("DELETE", "/api/admin/bt-whitelist/{bt}", None),
    ("GET", "/api/admin/config-snapshots", None),
    ("POST", "/api/admin/config-snapshots", {"description": "refused"}),
    ("GET", "/api/admin/config-snapshots/{snap}", None),
    ("POST", "/api/admin/config-snapshots/{snap}/restore", None),
    ("DELETE", "/api/admin/config-snapshots/{snap}", None),
    ("GET", "/api/admin/auto-rescan", None),
    ("POST", "/api/admin/auto-rescan", {"enabled": True}),
    ("GET", "/api/admin/scoring/thresholds", None),
    ("GET", "/api/admin/scoring/evaluation", None),
    ("GET", "/api/admin/protocols", None),
    ("PUT", "/api/admin/protocols", {"adsb": False}),
    ("GET", "/api/admin/session-binding", None),
    ("PUT", "/api/admin/session-binding", {"mode": "strict"}),
]


def _state(bridge_app: FastAPI, detection_store) -> dict[str, Any]:
    """Everything a refused admin call must leave as it was."""
    persistence = bridge_app.state.persistence
    conn = detection_store.get_connection()
    return {
        "config": persistence.get_detection_config(),
        "live_config": bridge_app.state.detection_config,
        "whitelist": persistence.get_wifi_whitelist(),
        "bt_whitelist": persistence.get_bt_whitelist(),
        "snapshots": [
            s["id"] for s in PersistenceManager.list_config_snapshots(conn, limit=200)
        ],
        "session_binding": persistence.get_session_binding(),
        "rf_anomalies": conn.execute(
            "SELECT id, anomaly_score, priority FROM rf_anomalies ORDER BY id"
        ).fetchall(),
        "audit": len(detection_store.get_audit_log(limit=1000)),
    }


def test_only_admin_passes_and_refusals_change_nothing(
    bridge_app, persistence, detection_store, role_clients
):
    # One app for every route (an app per route costs CI minutes).  The
    # admin calls rotate over three admin keys: the sensitive rate limit is
    # 10 calls a minute per key.
    admins = [
        TestClient(
            bridge_app,
            headers={"X-API-Key": _add_key(persistence, f"sc_admin_{i}", "admin")},
        )
        for i in range(3)
    ]
    _seed_rf_anomaly(detection_store, confidence=0.1)
    persistence.set_wifi_whitelist(
        [{"id": "seeded-ap", "bssid": "11:22:33:44:55:66", "ssid": "", "notes": ""}]
    )
    persistence.set_bt_whitelist(
        [{"id": "seeded-bt", "device_addr": "11:22:33:44:55:66", "notes": ""}]
    )
    snap = persistence.create_config_snapshot(
        "manual", "seeded", db_conn=detection_store.get_connection()
    )
    assert snap is not None
    failures: list[str] = []
    for index, (method, template, body) in enumerate(_ROUTES):
        path = template.format(snap=snap, wl="seeded-ap", bt="seeded-bt")
        before = _state(bridge_app, detection_store)
        for role, caller in role_clients.items():
            resp = caller.request(method, path, json=body)
            expected = (
                (401, None) if role == "anonymous" else (403, "Admin role required")
            )
            got = (
                resp.status_code,
                resp.json().get("detail") if role != "anonymous" else None,
            )
            if got != expected:
                failures.append(
                    f"{method} {path} as {role}: {resp.status_code} {resp.text}"
                )
            if _state(bridge_app, detection_store) != before:
                failures.append(f"{method} {path} as {role} changed the state")
        resp = admins[index // 9].request(method, path, json=body)
        if not 200 <= resp.status_code < 300:
            failures.append(f"{method} {path} as admin: {resp.status_code} {resp.text}")
    assert failures == []


# ---------------------------------------------------------------------------
# GET /sessions — token prefix only
# ---------------------------------------------------------------------------


def test_session_listing_never_discloses_a_full_token(client, detection_store):
    detection_store.create_user("watcher", "fixture-password-long", role="viewer")
    user = detection_store.get_user("watcher")
    token = detection_store.create_session(user["id"], ip_address="198.51.100.7")[
        "session_token"
    ]
    # Sessions are stored by token hash; even the hash is shown only as a
    # short prefix (enough to tell sessions apart, too little to look one up).
    stored = hashlib.sha256(token.encode()).hexdigest()
    assert detection_store.get_session(token) is not None

    resp = client.get("/api/admin/sessions")
    assert resp.status_code == 200
    assert token[:8] not in resp.text
    assert stored[:9] not in resp.text
    data = resp.json()
    assert data["count"] == 1
    [session] = data["sessions"]
    assert session["token_prefix"] == stored[:8] + "..."
    assert session["user_id"] == user["id"]
    assert session["ip_address"] == "198.51.100.7"


# ---------------------------------------------------------------------------
# WiFi AP whitelist
# ---------------------------------------------------------------------------


class _RecordingWifiScorer:
    """Stands in for the live WiFi scorer; records each whitelist it is given."""

    def __init__(self) -> None:
        self.whitelists: list[list[dict[str, Any]]] = []

    def set_whitelist(self, entries: list[dict[str, Any]]) -> None:
        self.whitelists.append([dict(e) for e in entries])

    def update_weights(self, weights: dict[str, float]) -> None:
        pass


_MALFORMED_BSSIDS = [
    "not-a-mac",
    "AA:BB:CC:DD:EE",
    "AA:BB:CC:DD:EE:FF:00",
    "GG:BB:CC:DD:EE:FF",
    "AABBCCDDEEFF",
    "AA:BB:CC:DD:EE:FF\nEVIL",
    "AA:BB:CC:DD:EE:FF;DROP",
    "<script>:BB:CC:DD:EE:FF",
    "",
]


@pytest.mark.parametrize(
    "batch", [_MALFORMED_BSSIDS[:5], _MALFORMED_BSSIDS[5:]], ids=["shape", "injection"]
)
def test_whitelist_rejects_malformed_bssids(
    client, persistence, detection_store, batch
):
    # At most nine admin calls per test: the sensitive limit is 10/min/key.
    for bssid in batch:
        resp = client.post("/api/admin/wifi-whitelist", json={"bssid": bssid})
        assert resp.status_code == 400, bssid
        assert "Invalid BSSID" in resp.json()["detail"]
    assert persistence.get_wifi_whitelist() == []
    assert detection_store.get_audit_log(action="admin_whitelist_add") == []


def test_whitelist_rejects_unknown_fields(client, persistence):
    resp = client.post(
        "/api/admin/wifi-whitelist",
        json={"bssid": "AA:BB:CC:DD:EE:FF", "id": "chosen-by-client"},
    )
    assert resp.status_code == 422
    assert persistence.get_wifi_whitelist() == []


def test_whitelist_add_normalises_escapes_syncs_and_audits(
    client, bridge_app, persistence, detection_store
):
    scorer = _RecordingWifiScorer()
    bridge_app.state.wifi_scorer = scorer
    resp = client.post(
        "/api/admin/wifi-whitelist",
        json={
            "bssid": " aa-bb-cc-dd-ee-0f ",
            "ssid": ' <img src=x onerror="alert(1)"> ',
            "notes": "<b>" + "n" * 300,
        },
    )
    assert resp.status_code == 201, resp.text
    entry = resp.json()["entry"]
    assert entry["bssid"] == "AA:BB:CC:DD:EE:0F"
    # The SSID is stored as given, like the networks it names; pages
    # escape it on output. Notes are still escaped when stored.
    assert entry["ssid"] == '<img src=x onerror="alert(1)">'
    assert entry["notes"].startswith("&lt;b&gt;nnn")
    assert len(entry["notes"]) == 200
    assert "<" not in entry["notes"]
    assert persistence.get_wifi_whitelist() == [entry]
    assert scorer.whitelists == [[entry]]

    [audit] = detection_store.get_audit_log(action="admin_whitelist_add")
    assert audit["target_id"] == "AA:BB:CC:DD:EE:0F"
    assert audit["operator"] == "master"


def test_whitelist_duplicate_is_refused_across_case_and_separator(client, persistence):
    first = client.post(
        "/api/admin/wifi-whitelist", json={"bssid": "AA:BB:CC:DD:EE:FF"}
    )
    assert first.status_code == 201
    for duplicate in ("aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", " aa-bb-cc-dd-ee-ff"):
        resp = client.post("/api/admin/wifi-whitelist", json={"bssid": duplicate})
        assert resp.status_code == 409, duplicate
    assert persistence.get_wifi_whitelist() == [first.json()["entry"]]


def test_whitelist_remove_syncs_scorer_and_audits(
    client, bridge_app, persistence, detection_store
):
    kept = client.post("/api/admin/wifi-whitelist", json={"bssid": "11:22:33:44:55:66"})
    gone = client.post("/api/admin/wifi-whitelist", json={"bssid": "AA:BB:CC:DD:EE:FF"})
    scorer = _RecordingWifiScorer()
    bridge_app.state.wifi_scorer = scorer

    resp = client.delete(f"/api/admin/wifi-whitelist/{gone.json()['entry']['id']}")
    assert resp.status_code == 200
    assert resp.json()["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert persistence.get_wifi_whitelist() == [kept.json()["entry"]]
    assert scorer.whitelists == [[kept.json()["entry"]]]
    [audit] = detection_store.get_audit_log(action="admin_whitelist_remove")
    assert audit["target_id"] == "AA:BB:CC:DD:EE:FF"

    again = client.delete(f"/api/admin/wifi-whitelist/{gone.json()['entry']['id']}")
    assert again.status_code == 404
    assert scorer.whitelists == [[kept.json()["entry"]]]
    assert len(detection_store.get_audit_log(action="admin_whitelist_remove")) == 1


# ---------------------------------------------------------------------------
# PUT /detection-config
# ---------------------------------------------------------------------------


class _RecordingRfScorer:
    """Wraps the live RF scorer and records each weights dict it is given."""

    def __init__(self, real: Any) -> None:
        self._real = real
        self.weights_given: list[dict[str, float]] = []

    def update_weights(self, weights: dict[str, float]) -> None:
        self.weights_given.append(dict(weights))
        self._real.update_weights(weights)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def _snapshot_ids(client: TestClient) -> set[int]:
    resp = client.get("/api/admin/config-snapshots")
    assert resp.status_code == 200
    return {s["id"] for s in resp.json()["snapshots"]}


def test_detection_config_update_merges_propagates_snapshots_and_audits(
    client, bridge_app, persistence, detection_store
):
    # Seven admin calls: the sensitive limit is 10/min/key.
    scorer = _RecordingRfScorer(bridge_app.state.rf_scorer)
    bridge_app.state.rf_scorer = scorer
    before = client.get("/api/admin/detection-config").json()["config"]
    old_weights = before["rf_dimension_weights"]
    assert {"novel_class", "rare_class"} <= set(old_weights)
    old_alert = before["rf_anomaly_alert_threshold"]
    assert old_alert < 0.9
    first = client.put(
        "/api/admin/detection-config", json={"rf_anomaly_critical_threshold": 0.88}
    )
    assert first.status_code == 200
    snapshots_before = _snapshot_ids(client)

    resp = client.put(
        "/api/admin/detection-config",
        json={
            "rf_dimension_weights": {"novel_class": 0.31},
            "rf_anomaly_alert_threshold": old_alert,  # unchanged: not audited
            "rf_anomaly_critical_threshold": 0.93,
        },
    )
    assert resp.status_code == 200, resp.text
    config = resp.json()["config"]
    # A partial weights dict merges into, never replaces, the stored weights.
    assert config["rf_dimension_weights"] == {**old_weights, "novel_class": 0.31}
    assert config["rf_anomaly_critical_threshold"] == 0.93
    assert client.get("/api/admin/detection-config").json()["config"] == config
    assert persistence.get_detection_config() == config
    # The live scorer is given the merged weights.
    assert scorer.weights_given[-1] == config["rf_dimension_weights"]

    # Ingest alerting follows at once: 0.9 is critical under the old
    # threshold (0.88) and the default (0.85), a warning under the new one.
    resp = client.post("/api/nodes/register", json={"node_id": "cfg-node"})
    assert resp.status_code == 200
    now = datetime.now(timezone.utc)
    resp = client.post(
        "/api/detections/batch",
        json={
            "node_id": "cfg-node",
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "id": "between-thresholds",
                    "node_id": "cfg-node",
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                    "anomaly_score": 0.9,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["alerts_created"] == 1
    [alert] = [
        a
        for a in persistence.get_alerts()
        if a.get("detection_id") == "between-thresholds"
    ]
    assert alert["severity"] == "warning"

    # Exactly one snapshot was taken by the change, and it holds the old
    # values: undoable.
    [latest] = _snapshot_ids(client) - snapshots_before
    detail = client.get(f"/api/admin/config-snapshots/{latest}").json()
    saved = detail["snapshot"]["files"]["detection_config.json"]["config"]
    assert saved["rf_anomaly_critical_threshold"] == 0.88
    assert saved["rf_dimension_weights"]["novel_class"] == old_weights["novel_class"]

    audits = detection_store.get_audit_log(action="admin_update_detection_config")
    assert len(audits) == 2
    newest = max(audits, key=lambda a: a["id"])
    assert newest["operator"] == "master"
    assert newest["details"]["changes"] == [
        {
            "key": "rf_dimension_weights.novel_class",
            "old": old_weights["novel_class"],
            "new": 0.31,
        },
        {"key": "rf_anomaly_critical_threshold", "old": 0.88, "new": 0.93},
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"rf_anomaly_insert_threshold": "abc"},
        {"rf_dimension_weights": {"snr_zscore": "abc"}},
    ],
    ids=["threshold", "weight"],
)
def test_detection_config_rejects_non_numeric_values(client, persistence, body):
    before = persistence.get_detection_config()
    resp = client.put("/api/admin/detection-config", json=body)
    assert resp.status_code in (400, 422), resp.text
    assert persistence.get_detection_config() == before


@pytest.mark.parametrize(
    ("body", "problem"),
    [
        ({"wifi_anomaly_alert_threshold": None}, "wifi_anomaly_alert_threshold"),
        ({"rf_anomaly_alert_threshold": True}, "rf_anomaly_alert_threshold"),
        ({"rf_anomaly_critical_threshold": 1.5}, "rf_anomaly_critical_threshold"),
        ({"rf_min_confidence_floor": -0.1}, "rf_min_confidence_floor"),
        ('{"rf_anomaly_insert_threshold": NaN}', "rf_anomaly_insert_threshold"),
        ('{"wifi_auto_snooze_max_score": Infinity}', "wifi_auto_snooze_max_score"),
        ('{"rf_auto_snooze_hours": 1e400}', "rf_auto_snooze_hours"),
        ({"rf_auto_snooze_seen_count": "100"}, "rf_auto_snooze_seen_count"),
        ({"rf_auto_snooze_seen_count": 2.5}, "rf_auto_snooze_seen_count"),
        ({"wifi_anomaly_cooldown_seconds": -1}, "wifi_anomaly_cooldown"),
        ({"rf_auto_snooze_hours": 10**8}, "rf_auto_snooze_hours"),
        ({"rf_min_learning_detections": [300]}, "rf_min_learning_detections"),
        ({"wifi_dimension_weights": 0.5}, "wifi_dimension_weights"),
        ({"rf_dimension_weights": {"novel_class": 2}}, "novel_class"),
        ({"rf_dimension_weights": {"novel_class": None}}, "novel_class"),
        ({"protocol_detection": {"adsb": "false"}}, "protocol_detection.adsb"),
        ({"protocol_detection": {"bpsk": False}}, "unknown protocol"),
        ({"protocol_detection": ["adsb"]}, "protocol_detection"),
        ({"auto_rescan": {"enabled": True, "max_retries": 99}}, "auto_rescan"),
        ({"auto_rescan": {"enabled": True, "extra": 1}}, "auto_rescan"),
        # Strict, like every other value: never converted.
        ({"auto_rescan": {"enabled": "false"}}, "auto_rescan"),
        ({"auto_rescan": {"confidence_threshold": "0.4"}}, "auto_rescan"),
        ({"auto_rescan": {"max_retries": True}}, "auto_rescan"),
        # The bounds hold for the objects as stored, merged with the 14 RF
        # weights and 7 WiFi weights in force.
        (
            {"rf_dimension_weights": {f"dim_{i}": 0.0 for i in range(51)}},
            "rf_dimension_weights: at most 64 entries in all, and with the ones "
            "already stored there would be 65",
        ),
        (
            {
                "wifi_dimension_weights": {
                    name: 1.0
                    for name in PersistenceManager._DETECTION_CONFIG_DEFAULTS[
                        "wifi_dimension_weights"
                    ]
                }
            },
            "wifi_dimension_weights: the weights must sum to at most 2.0, and "
            "with the ones already stored they would sum to 7.00",
        ),
        ({"rf_dimension_weights": {"novel_class": 1.0, "x": 0.9}}, "sum to 2.86"),
        ({"iq_capture_enabled": "yes"}, "iq_capture_enabled"),
        ({"rf_anomaly_insert_treshold": 0.4}, "unknown setting"),
    ],
)
def test_detection_config_refuses_every_wrong_value(
    client, persistence, detection_store, body, problem
):
    # Wrong type, out of range, non-finite, or unknown: 422 naming the value,
    # and nothing changes (config, snapshot, audit).  A str body is sent as
    # is (NaN / Infinity literals, which Python's JSON parser accepts).
    before = persistence.get_detection_config()
    if isinstance(body, str):
        resp = client.put(
            "/api/admin/detection-config",
            content=body,
            headers={"Content-Type": "application/json"},
        )
    else:
        resp = client.put("/api/admin/detection-config", json=body)
    assert resp.status_code == 422, resp.text
    assert problem in resp.json()["detail"]
    assert persistence.get_detection_config() == before
    assert not (persistence.data_dir / "detection_config.json").exists()
    assert client.get("/api/admin/config-snapshots").json()["snapshots"] == []
    assert detection_store.get_audit_log(action="admin_update_detection_config") == []


def test_detection_config_refusal_names_every_problem_and_keeps_ingest_working(
    client, persistence, registered_node
):
    resp = client.put(
        "/api/admin/detection-config",
        json={
            "rf_anomaly_insert_threshold": "abc",
            "rf_anomaly_alert_threshold": 0.5,  # valid, but not applied either
            "rf_dimension_weights": {"snr_zscore": "abc", "novel_class": 0.2},
        },
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "rf_anomaly_insert_threshold" in detail
    assert "rf_dimension_weights.snr_zscore" in detail
    assert "novel_class" not in detail
    assert persistence.get_detection_config()["rf_anomaly_alert_threshold"] == 0.7

    now = datetime.now(timezone.utc)
    resp = client.post(
        "/api/detections/batch",
        json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "id": "after-refused-config",
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                    "anomaly_score": 0.5,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text


def test_detection_config_accepts_valid_values_and_round_trips(
    client, bridge_app, persistence
):
    resp = client.put(
        "/api/admin/detection-config",
        json={
            "rf_anomaly_insert_threshold": 0,
            "rf_anomaly_alert_threshold": 1,
            "rf_min_confidence_floor": 0.25,
            "rf_auto_snooze_seen_count": 120.0,  # a whole number: stored as int
            "rf_auto_snooze_hours": 0,
            "rf_min_learning_detections": 1_000_000_000,
            "wifi_dimension_weights": {"evil_twin": 1.0, "client_surge": 0},
            "protocol_detection": {"adsb": False},
            "auto_rescan": {"enabled": True, "confidence_threshold": 0.4},
            "iq_capture_enabled": True,
        },
    )
    assert resp.status_code == 200, resp.text
    config = resp.json()["config"]
    assert config["rf_auto_snooze_seen_count"] == 120
    assert type(config["rf_auto_snooze_seen_count"]) is int
    assert config["wifi_dimension_weights"]["evil_twin"] == 1.0
    assert config["protocol_detection"]["adsb"] is False
    assert config["auto_rescan"] == {
        "enabled": True,
        "confidence_threshold": 0.4,
        "max_retries": 2,
    }
    assert persistence.get_detection_config() == config
    assert bridge_app.state.detection_config == config

    # A key this bridge does not know, already stored (by an older build):
    # sending back the whole configuration read from GET is accepted, a
    # changed value of that key is not.
    persistence.set_detection_config({**config, "legacy_setting": {"x": 1}})
    full = client.get("/api/admin/detection-config").json()["config"]
    assert full["legacy_setting"] == {"x": 1}
    resp = client.put("/api/admin/detection-config", json=full)
    assert resp.status_code == 200, resp.text
    assert resp.json()["config"] == full
    resp = client.put("/api/admin/detection-config", json={"legacy_setting": {"x": 2}})
    assert resp.status_code == 422
    assert "legacy_setting: unknown setting" in resp.json()["detail"]


def test_detection_config_partial_protocol_toggles_merge(client, persistence):
    # Like the weights, a partial protocol_detection merges into the stored
    # toggles: one it leaves out keeps its saved value.
    resp = client.put("/api/admin/protocols", json={"dect": False})
    assert resp.status_code == 200
    resp = client.put(
        "/api/admin/detection-config", json={"protocol_detection": {"adsb": False}}
    )
    assert resp.status_code == 200, resp.text
    toggles = persistence.get_detection_config()["protocol_detection"]
    assert (toggles["adsb"], toggles["dect"], toggles["p25"]) == (False, False, True)
    assert resp.json()["config"]["protocol_detection"] == toggles


def test_detection_config_weights_stay_within_their_bounds_as_stored(
    client, persistence
):
    # Partial weights merge into the stored ones, so the 64-weight cap (and
    # the 2.0 sum) is the stored object's: PUTs that each add new names
    # cannot grow it past 64, and the result always goes back through PUT.
    defaults = len(persistence.get_detection_config()["rf_dimension_weights"])
    first = {f"dim_{i}": 0.0 for i in range(64 - defaults - 1)}
    resp = client.put(
        "/api/admin/detection-config", json={"rf_dimension_weights": first}
    )
    assert resp.status_code == 200, resp.text
    last = {"dim_last": 0.0}
    resp = client.put(
        "/api/admin/detection-config", json={"rf_dimension_weights": last}
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["config"]["rf_dimension_weights"]) == 64
    resp = client.put(
        "/api/admin/detection-config", json={"rf_dimension_weights": {"one_more": 0.0}}
    )
    assert resp.status_code == 422
    assert "there would be 65" in resp.json()["detail"]
    full = client.get("/api/admin/detection-config").json()["config"]
    assert len(full["rf_dimension_weights"]) == 64
    resp = client.put("/api/admin/detection-config", json=full)
    assert resp.status_code == 200, resp.text
    assert resp.json()["config"] == full

    # A sum of exactly 2.0 is allowed.
    weights = {name: 0.0 for name in full["rf_dimension_weights"]}
    weights.update(novel_class=1.0, rare_class=1.0)
    resp = client.put(
        "/api/admin/detection-config", json={"rf_dimension_weights": weights}
    )
    assert resp.status_code == 200, resp.text


def test_protocol_toggles_refuse_values_that_are_not_booleans(
    client, persistence, detection_store
):
    # PUT /protocols has the rule protocol_detection has in PUT
    # /detection-config: the string "false" used to turn adsb ON (bool()).
    before = persistence.get_detection_config()["protocol_detection"]
    for value in ("false", "true", 0, 1, None, [False]):
        resp = client.put(
            "/api/admin/protocols", json={"adsb": not before["adsb"], "dect": value}
        )
        assert resp.status_code == 422, (value, resp.text)
        assert resp.json()["detail"] == (
            "protocol_detection.dect: must be true or false"
        )
    assert persistence.get_detection_config()["protocol_detection"] == before
    assert not (persistence.data_dir / "detection_config.json").exists()
    assert detection_store.get_audit_log(action="admin_update_protocol_config") == []
    # A name the bridge does not list is still ignored, whatever its value.
    resp = client.put(
        "/api/admin/protocols", json={"dect": False, "not_a_protocol": "x"}
    )
    assert resp.status_code == 200, resp.text
    after = persistence.get_detection_config()["protocol_detection"]
    assert after == {**before, "dect": False}


def test_auto_rescan_body_is_strict(client, persistence):
    # The POST /auto-rescan body is the auto_rescan rule of PUT
    # /detection-config: a string or a boolean where a number belongs is
    # refused, never converted ("false" used to become False, true 1).
    before = persistence.get_detection_config()
    for body in (
        {"enabled": "false"},
        {"enabled": 1},
        {"confidence_threshold": "0.4"},
        {"confidence_threshold": True},
        {"max_retries": True},
        {"max_retries": "3"},
    ):
        resp = client.post("/api/admin/auto-rescan", json=body)
        assert resp.status_code == 422, (body, resp.text)
    assert persistence.get_detection_config() == before
    resp = client.post(
        "/api/admin/auto-rescan", json={"enabled": True, "confidence_threshold": 1}
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["auto_rescan"] == {
        "enabled": True,
        "confidence_threshold": 1.0,
        "max_retries": 2,
    }


def test_stored_values_the_rules_refuse_are_left_out_on_read(
    client, bridge_app, persistence, registered_node, caplog
):
    # A configuration an older bridge stored, or a snapshot taken before
    # these rules restores: a refused value is left out when the
    # configuration is read (its default applies), so ingest keeps working.
    legacy = {
        "rf_anomaly_insert_threshold": "0.4",  # ingest answered 500
        "rf_auto_snooze_hours": 0.5,
        "rf_anomaly_alert_threshold": 0.6,  # good: kept
        "rf_dimension_weights": {"snr_zscore": "abc", "novel_class": 0.3},
        "protocol_detection": {"adsb": "false", "dect": False},
        "auto_rescan": {"enabled": "false"},
        "legacy_setting": {"x": 1},  # unknown: kept as is
    }
    persistence.set_detection_config(legacy)
    persistence.save_all()  # the snapshot (and so the restore) keeps the node
    snap = client.post("/api/admin/config-snapshots", json={"description": "old"})
    assert snap.status_code == 201, snap.text
    snap_id = snap.json()["snapshot_id"]

    defaults = persistence.get_detection_config_defaults()
    with caplog.at_level("WARNING", logger="sigrift.bridge.persistence"):
        caplog.clear()
        config = client.get("/api/admin/detection-config").json()["config"]
        client.get("/api/admin/detection-config")
    left_out = [r for r in caplog.records if "left out" in r.getMessage()]
    assert len(left_out) == 1  # logged once, not on every read
    for problem in (
        "rf_anomaly_insert_threshold",
        "rf_auto_snooze_hours",
        "rf_dimension_weights.snr_zscore",
        "protocol_detection.adsb",
        "auto_rescan",
    ):
        assert problem in left_out[0].getMessage()
    assert (
        config["rf_anomaly_insert_threshold"] == defaults["rf_anomaly_insert_threshold"]
    )
    assert config["rf_auto_snooze_hours"] == defaults["rf_auto_snooze_hours"]
    assert config["rf_anomaly_alert_threshold"] == 0.6
    weights = config["rf_dimension_weights"]
    assert weights["snr_zscore"] == defaults["rf_dimension_weights"]["snr_zscore"]
    assert weights["novel_class"] == 0.3
    toggles = config["protocol_detection"]
    assert (toggles["adsb"], toggles["dect"]) == (True, False)
    assert "auto_rescan" not in config
    assert config["legacy_setting"] == {"x": 1}

    # The configuration GET returns goes back through PUT; that write drops
    # the refused values from the file.
    resp = client.put("/api/admin/detection-config", json=config)
    assert resp.status_code == 200, resp.text
    saved = json.loads((persistence.data_dir / "detection_config.json").read_text())
    assert saved["config"] == config

    # Restoring the old snapshot brings the string threshold back into the
    # file, but no reader gets it: ingest still answers 201.
    resp = client.post(f"/api/admin/config-snapshots/{snap_id}/restore")
    assert resp.status_code == 200, resp.text
    saved = json.loads((persistence.data_dir / "detection_config.json").read_text())
    assert saved["config"]["rf_anomaly_insert_threshold"] == "0.4"
    live = bridge_app.state.detection_config
    assert (
        live["rf_anomaly_insert_threshold"] == defaults["rf_anomaly_insert_threshold"]
    )
    now = datetime.now(timezone.utc)
    resp = client.post(
        "/api/detections/batch",
        json={
            "node_id": registered_node,
            "period_start": (now - timedelta(minutes=1)).isoformat(),
            "period_end": now.isoformat(),
            "detections": [
                {
                    "id": "after-restored-config",
                    "node_id": registered_node,
                    "signal_class": "bpsk",
                    "confidence": 0.9,
                    "freq_hz": 433.92e6,
                    "anomaly_score": 0.5,
                }
            ],
        },
    )
    assert resp.status_code == 201, resp.text


# ---------------------------------------------------------------------------
# Rescore / simulate
# ---------------------------------------------------------------------------


def _seed_rf_anomaly(
    store,
    *,
    signal_class: str = "bpsk",
    confidence: float = 0.9,
    score: float = 0.5,
    priority: str = "normal",
) -> int:
    conn = store.get_connection()
    cur = conn.execute(
        "INSERT INTO rf_anomalies (detection_id, signal_class, freq_hz, node_id, "
        "timestamp, confidence, anomaly_score, priority) "
        "VALUES (?, ?, 433.92e6, 'n1', '2026-01-01T00:00:00+00:00', ?, ?, ?)",
        (f"det-{signal_class}-{confidence}", signal_class, confidence, score, priority),
    )
    conn.commit()
    return cur.lastrowid


class _StubScorer:
    """A deterministic RF scorer: the score is chosen per signal class."""

    def __init__(self, scores: dict[str, float], fail_on: str | None = None) -> None:
        self.scores = scores
        self.fail_on = fail_on
        self.calls: list[str] = []

    def score(self, det: dict[str, Any]) -> SimpleNamespace:
        self.calls.append(det["signal_class"])
        if det["signal_class"] == self.fail_on:
            raise RuntimeError("scorer failed part-way")
        value = self.scores[det["signal_class"]]
        return SimpleNamespace(
            score=value,
            priority="high" if value >= 0.7 else "normal",
            dimensions={"novel_class": 0.123456},
            reasons=[f"scored {det['signal_class']}"],
        )


def _committed_rows(store) -> list[tuple]:
    """rf_anomalies rows as another connection sees them (committed only)."""
    conn = sqlite3.connect(store.db_path)
    try:
        return conn.execute(
            "SELECT id, signal_class, anomaly_score, priority, dimensions, reasons "
            "FROM rf_anomalies ORDER BY id"
        ).fetchall()
    finally:
        conn.close()


def test_rescore_removes_below_floor_and_threshold_and_audits(
    client, bridge_app, detection_store
):
    resp = client.put(
        "/api/admin/detection-config",
        json={"rf_min_confidence_floor": 0.5, "rf_anomaly_insert_threshold": 0.3},
    )
    assert resp.status_code == 200
    low_conf = _seed_rf_anomaly(detection_store, signal_class="fsk", confidence=0.2)
    low_score = _seed_rf_anomaly(detection_store, signal_class="bpsk")
    kept = _seed_rf_anomaly(detection_store, signal_class="qam16")
    assert [row[0] for row in _committed_rows(detection_store)] == [
        low_conf,
        low_score,
        kept,
    ]
    scorer = _StubScorer({"bpsk": 0.29, "qam16": 0.81234})
    bridge_app.state.rf_scorer = scorer

    resp = client.post("/api/admin/rescore-rf-anomalies")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok", "total": 3, "updated": 1, "removed": 2}
    # The confidence floor drops a row before it is ever scored.
    assert scorer.calls == ["bpsk", "qam16"]
    assert _committed_rows(detection_store) == [
        (
            kept,
            "qam16",
            0.8123,
            "high",
            json.dumps({"novel_class": 0.1235}),
            json.dumps(["scored qam16"]),
        )
    ]
    [audit] = detection_store.get_audit_log(action="admin_rescore_rf_anomalies")
    assert audit["operator"] == "master"
    assert audit["details"]["severity"] == "critical"
    assert (audit["details"]["updated"], audit["details"]["removed"]) == (1, 2)


def test_rescore_failure_part_way_rolls_back_every_row(
    bridge_app, master_key, detection_store
):
    _seed_rf_anomaly(
        detection_store, signal_class="fsk", confidence=0.2
    )  # deleted first
    _seed_rf_anomaly(detection_store, signal_class="bpsk")  # updated second
    _seed_rf_anomaly(detection_store, signal_class="qam16")  # scorer raises
    before = _committed_rows(detection_store)

    with TestClient(
        bridge_app, headers={"X-API-Key": master_key}, raise_server_exceptions=False
    ) as admin:
        resp = admin.put(
            "/api/admin/detection-config", json={"rf_min_confidence_floor": 0.5}
        )
        assert resp.status_code == 200
        bridge_app.state.rf_scorer = _StubScorer({"bpsk": 0.9}, fail_on="qam16")
        resp = admin.post("/api/admin/rescore-rf-anomalies")
        assert resp.status_code == 500
        # Any later commit on the same worker connection must not carry the
        # half-done rescore with it.
        assert admin.post("/api/admin/config-snapshots").status_code == 201
    assert _committed_rows(detection_store) == before
    assert detection_store.get_audit_log(action="admin_rescore_rf_anomalies") == []


def test_rescore_without_a_scorer_is_503_and_changes_nothing(
    client, bridge_app, detection_store
):
    resp = client.put(
        "/api/admin/detection-config", json={"rf_min_confidence_floor": 0.5}
    )
    assert resp.status_code == 200
    # Below the floor: any rescore that got under way would delete it.
    _seed_rf_anomaly(detection_store, confidence=0.2)
    before = _committed_rows(detection_store)
    bridge_app.state.rf_scorer = None
    for path in ("/api/admin/rescore-rf-anomalies", "/api/admin/simulate-rescore-rf"):
        resp = client.post(path)
        assert resp.status_code == 503, path
        assert resp.json()["detail"] == "RF scorer not available"
    assert _committed_rows(detection_store) == before
    for action in ("admin_rescore_rf_anomalies", "admin_simulate_rescore_rf"):
        assert detection_store.get_audit_log(action=action) == []


def test_simulated_rescore_reports_without_writing(client, bridge_app, detection_store):
    resp = client.put(
        "/api/admin/detection-config",
        json={"rf_min_confidence_floor": 0.5, "rf_anomaly_insert_threshold": 0.3},
    )
    assert resp.status_code == 200
    _seed_rf_anomaly(detection_store, signal_class="fsk", confidence=0.2)
    _seed_rf_anomaly(detection_store, signal_class="bpsk", score=0.5, priority="normal")
    _seed_rf_anomaly(
        detection_store, signal_class="qam16", score=0.5, priority="normal"
    )
    _seed_rf_anomaly(detection_store, signal_class="ook", score=0.5, priority="normal")
    before = _committed_rows(detection_store)
    bridge_app.state.rf_scorer = _StubScorer({"bpsk": 0.1, "qam16": 0.9, "ook": 0.502})

    resp = client.post("/api/admin/simulate-rescore-rf")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "total": 4,
        "would_remove": 2,
        "would_update": 1,
        "unchanged": 1,
        "remaining": 2,
        "priority_before": {"normal": 4},
        "priority_after": {"high": 1, "normal": 1},
    }
    assert _committed_rows(detection_store) == before
    [audit] = detection_store.get_audit_log(action="admin_simulate_rescore_rf")
    assert audit["details"]["severity"] == "warning"


# ---------------------------------------------------------------------------
# PUT /protocols
# ---------------------------------------------------------------------------


def test_protocol_toggle_cannot_add_unknown_keys(client, persistence, detection_store):
    # Relative to the starting value, whatever the factory default is.
    before = dict(persistence.get_detection_config()["protocol_detection"])
    assert "adsb" in before and "evil_proto" not in before
    flipped = not before["adsb"]

    resp = client.put(
        "/api/admin/protocols",
        json={"adsb": flipped, "evil_proto": True, "__proto__": {"x": True}},
    )
    assert resp.status_code == 200
    after = persistence.get_detection_config()["protocol_detection"]
    assert after == {**before, "adsb": flipped}
    [audit] = detection_store.get_audit_log(action="admin_update_protocol_config")
    assert audit["details"]["changed"] == {"adsb": flipped}

    # No change: nothing new is audited.
    assert client.put("/api/admin/protocols", json={"adsb": flipped}).status_code == 200
    assert (
        len(detection_store.get_audit_log(action="admin_update_protocol_config")) == 1
    )


def test_protocol_toggle_leaves_factory_defaults_alone(client, tmp_path):
    default = client.get("/api/admin/detection-config").json()["defaults"]
    default = default["protocol_detection"]["adsb"]
    resp = client.put("/api/admin/protocols", json={"adsb": not default})
    assert resp.status_code == 200
    defaults = client.get("/api/admin/detection-config").json()["defaults"]
    other = PersistenceManager(data_dir=tmp_path / "other", auto_save_interval=0)
    other.load_all()
    assert (
        defaults["protocol_detection"]["adsb"],
        other.get_detection_config()["protocol_detection"]["adsb"],
    ) == (default, default)


def test_detection_config_is_the_callers_own_copy(persistence, tmp_path):
    # Every nested dict of the returned configuration, saved or not, is a
    # copy: changing it changes neither the factory defaults nor what any
    # PersistenceManager reads next.
    factory = persistence.get_detection_config_defaults()
    persistence.set_detection_config({"rf_dimension_weights": {"novel_class": 0.3}})
    fresh = PersistenceManager(data_dir=tmp_path / "fresh", auto_save_interval=0)
    fresh.load_all()
    for manager in (persistence, fresh):
        config = manager.get_detection_config()
        expected = manager.get_detection_config()
        nested = [value for value in config.values() if isinstance(value, dict)]
        assert len(nested) == 3
        for value in nested:
            for name in list(value):
                value[name] = "changed"
            value["added"] = "changed"
        assert manager.get_detection_config() == expected
        assert manager.get_detection_config_defaults() == factory
    assert PersistenceManager._DETECTION_CONFIG_DEFAULTS == factory
