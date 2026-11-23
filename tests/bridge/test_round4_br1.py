"""Round-4 regression tests for the bridge (group BR1).

* K8 / Q7 — post-ingest hooks for gateway-ingested batches: the gateway
  serves ``POST /api/detections/batch`` itself, so condition rules, watch
  bands, anomaly alerts, ``trigger_count`` and edge-decoded messages only
  run when the gateway hands the batch to ``/api/internal/ingest-hook``.
* K7 — ``/api/internal/bind-node-key``: the gateway binds unbound node keys
  through the bridge's own trust-on-first-use routine.
* K9 (bridge half) — ``/api/internal/*`` needs a valid ``X-Rust-Proxy``.
* P4 — client-certificate principals are bound to the node their
  identity names.
* P1 (bridge side) — the bridge serves no MFA endpoint.
* P3 — maintenance tasks no longer delete live audit rows.
* P5 — host names in BRIDGE_TRUSTED_PROXIES are re-resolved.
* P6 — WiFi / RF anomaly alert cooldowns right after host boot.
* P7 — uploaded pcaps are inflated with a bound, off the event loop.
"""

from __future__ import annotations

import asyncio
import gzip
import json
import logging
import socket
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
import sigrift.bridge.routers.detections as detections_mod
import sigrift.bridge.routers.internal as internal_mod
import sigrift.bridge.routers.wifi as wifi_mod
from sigrift.bridge.anomaly import pcap_store as pcap_mod
from sigrift.bridge.anomaly.pcap_store import PcapStore
from sigrift.bridge.detection_store import DetectionStore
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.state import AppState
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_SECRET = "round4-proxy-secret-0123456789abcdef"


@pytest.fixture(autouse=True)
def _fresh_state():
    deps._verified_key_cache.clear()
    deps._cert_mismatch_logged.clear()
    yield
    deps._verified_key_cache.clear()
    deps._cert_mismatch_logged.clear()


@pytest.fixture
def proxy_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
    return _SECRET


@pytest.fixture
def anon(bridge_app) -> TestClient:
    return TestClient(bridge_app)


def _gw(secret: str = _SECRET) -> dict[str, str]:
    return {"X-Rust-Proxy": secret}


def _add_key(
    persistence: PersistenceManager,
    key_id: str,
    role: str,
    node_id: str | None = None,
) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    if node_id is not None:
        meta["node_id"] = node_id
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _register(client: TestClient, *node_ids: str) -> None:
    for node_id in node_ids:
        resp = client.post("/api/nodes/register", json={"node_id": node_id})
        assert resp.status_code == 200, resp.text


def _keys_json(persistence: PersistenceManager) -> dict:
    return json.loads((persistence._data_dir / "keys.json").read_text())


# ---------------------------------------------------------------------------
# K9 — /api/internal/* is gateway-only
# ---------------------------------------------------------------------------

_INTERNAL_ROUTES = ("/api/internal/ingest-hook", "/api/internal/bind-node-key")


class TestInternalRoutesNeedTheProxySecret:
    @pytest.mark.parametrize("path", _INTERNAL_ROUTES)
    def test_missing_or_wrong_secret_is_refused(self, anon, proxy_secret, path):
        body = {"node_id": "edge-a", "key_id": "k", "detections": []}
        assert anon.post(path, json=body).status_code == 403
        assert anon.post(path, json=body, headers=_gw("wrong")).status_code == 403
        assert anon.post(path, json=body, headers=_gw("")).status_code == 403

    @pytest.mark.parametrize("path", _INTERNAL_ROUTES)
    def test_api_keys_and_sessions_are_not_accepted(
        self, client, detection_store, proxy_secret, path
    ):
        # ``client`` sends the master API key; still not the proxy secret.
        body = {"node_id": "edge-a", "key_id": "k", "detections": []}
        assert client.post(path, json=body).status_code == 403
        detection_store.create_user(
            username="ops", password="Password123!", role="admin"
        )
        user = detection_store.users.get_user("ops")
        token = detection_store.create_session(user_id=user["id"])["session_token"]
        resp = client.post(
            path, json=body, headers={"Authorization": f"Bearer {token}"}
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize("secret", ["", "uppercrust-internal"])
    def test_empty_or_default_secret_never_matches(self, anon, monkeypatch, secret):
        monkeypatch.setenv("UC_PROXY_SECRET", secret)
        resp = anon.post(
            "/api/internal/ingest-hook",
            json={"node_id": "edge-a", "detections": []},
            headers=_gw(secret),
        )
        assert resp.status_code == 403

    def test_the_whole_prefix_is_refused_in_any_spelling(self, anon, proxy_secret):
        for path in (
            "/api/internal/no-such-route",
            "/API/Internal/ingest-hook",
            "/api//internal/bind-node-key",
            "/api/internal",
        ):
            assert anon.post(path, json={}).status_code == 403, path
        # With the secret the middleware lets it through (the route decides).
        resp = anon.post("/api/internal/no-such-route", json={}, headers=_gw())
        assert resp.status_code == 404

    def test_valid_secret_is_accepted(self, anon, proxy_secret):
        resp = anon.post(
            "/api/internal/ingest-hook",
            json={"node_id": "edge-a", "detections": []},
            headers=_gw(),
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["accepted"] == 0


# ---------------------------------------------------------------------------
# K7 — bind-node-key
# ---------------------------------------------------------------------------


class TestBindNodeKey:
    def _bind(self, anon: TestClient, key_id: str, node_id: str):
        return anon.post(
            "/api/internal/bind-node-key",
            json={"key_id": key_id, "node_id": node_id},
            headers=_gw(),
        )

    def test_unbound_key_is_bound_on_first_call(self, anon, persistence, proxy_secret):
        _add_key(persistence, "sensor-a", "sensor")
        resp = self._bind(anon, "sensor-a", "edge-a")
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"node_id": "edge-a", "bound": True}
        # Written to keys.json, which the gateway reads.
        assert _keys_json(persistence)["keys"]["sensor-a"]["node_id"] == "edge-a"
        # Idempotent for the same node...
        assert self._bind(anon, "sensor-a", "edge-a").json() == {
            "node_id": "edge-a",
            "bound": True,
        }
        # ...and refused for any other.
        resp = self._bind(anon, "sensor-a", "edge-b")
        assert resp.status_code == 409
        assert resp.json() == {"node_id": "edge-a"}

    def test_the_binding_is_the_one_bridge_routes_enforce(
        self, anon, client, persistence, proxy_secret
    ):
        _register(client, "edge-a", "edge-b")
        raw = _add_key(persistence, "sensor-a", "sensor")
        assert self._bind(anon, "sensor-a", "edge-a").status_code == 200
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-b"},
            headers={"X-API-Key": raw},
        )
        assert hb.status_code == 403
        # And the other way round: a key bound by a bridge route is
        # reported to the gateway as bound there.
        raw_b = _add_key(persistence, "sensor-b", "sensor")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-b"},
            headers={"X-API-Key": raw_b},
        )
        assert hb.status_code == 200, hb.text
        resp = self._bind(anon, "sensor-b", "edge-a")
        assert resp.status_code == 409
        assert resp.json() == {"node_id": "edge-b"}

    def test_unknown_key_is_404(self, anon, proxy_secret):
        assert self._bind(anon, "no-such-key", "edge-a").status_code == 404

    def test_admin_keys_are_never_bound(self, anon, persistence, proxy_secret):
        _add_key(persistence, "ops-admin", "admin")
        resp = self._bind(anon, "ops-admin", "edge-a")
        assert resp.status_code == 200
        assert resp.json() == {"node_id": "edge-a", "bound": False}
        assert "node_id" not in persistence.get_key_meta()["ops-admin"]

    def test_invalid_node_id_is_422(self, anon, persistence, proxy_secret):
        _add_key(persistence, "sensor-a", "sensor")
        assert self._bind(anon, "sensor-a", "../etc").status_code == 422
        assert "node_id" not in persistence.get_key_meta()["sensor-a"]

    def test_key_named_after_a_node_is_bound_to_it(
        self, anon, client, persistence, proxy_secret
    ):
        _register(client, "edge-7")
        _add_key(persistence, "edge-7", "node")
        resp = self._bind(anon, "edge-7", "edge-8")
        assert resp.status_code == 409
        assert resp.json() == {"node_id": "edge-7"}
        # The convention is now written down, so the gateway enforces it.
        assert _keys_json(persistence)["keys"]["edge-7"]["node_id"] == "edge-7"

    def test_concurrent_first_binds_cannot_both_win(
        self, bridge_app, persistence, proxy_secret
    ):
        _add_key(persistence, "sensor-race", "sensor")

        async def _race() -> list[int]:
            transport = httpx.ASGITransport(app=bridge_app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://bridge"
            ) as ac:
                responses = await asyncio.gather(
                    *(
                        ac.post(
                            "/api/internal/bind-node-key",
                            json={"key_id": "sensor-race", "node_id": node},
                            headers=_gw(),
                        )
                        for node in ("edge-x", "edge-y", "edge-z")
                    )
                )
            return sorted(r.status_code for r in responses)

        assert asyncio.run(_race()) == [200, 409, 409]
        assert persistence.get_key_meta()["sensor-race"]["node_id"] in (
            "edge-x",
            "edge-y",
            "edge-z",
        )


class TestLegacyNodeNamedKeyIsPersisted:
    def test_heartbeat_writes_the_binding(self, anon, client, persistence):
        _register(client, "edge-7")
        raw = _add_key(persistence, "edge-7", "node")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-7"},
            headers={"X-API-Key": raw},
        )
        assert hb.status_code == 200, hb.text
        # Before: enforced by the bridge only, invisible to the gateway.
        assert _keys_json(persistence)["keys"]["edge-7"]["node_id"] == "edge-7"


# ---------------------------------------------------------------------------
# P4 — client-certificate principals are node-bound
# ---------------------------------------------------------------------------


class TestCertPrincipalNodeBinding:
    @staticmethod
    def _cert(identity: str, role: str) -> dict[str, str]:
        return {
            "x-auth-method": "client-cert",
            "x-auth-key-id": identity,
            "x-auth-role": role,
            "x-rust-proxy": _SECRET,
        }

    def test_node_cert_acts_only_for_its_own_node(self, anon, client, proxy_secret):
        _register(client, "edge-a", "edge-b")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-b"},
            headers=self._cert("edge-a", "node"),
        )
        assert hb.status_code == 403
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-a"},
            headers=self._cert("edge-a", "node"),
        )
        assert hb.status_code == 200, hb.text

    @pytest.mark.parametrize("role", ["sensor", "node", "viewer", "analyst"])
    def test_every_non_admin_cert_role_is_bound(self, anon, client, proxy_secret, role):
        _register(client, "edge-b")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-b"},
            headers=self._cert("edge-a", role),
        )
        assert hb.status_code == 403

    def test_admin_cert_may_act_for_any_node(self, anon, client, proxy_secret):
        _register(client, "edge-b")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge-b"},
            headers=self._cert("ops-console", "admin"),
        )
        assert hb.status_code == 200, hb.text

    def test_shared_agent_cert_gets_a_403_that_says_how_to_fix_it(
        self, anon, client, proxy_secret
    ):
        # The pre-K7 provisioning: one `local-edge` cert shared by every
        # scanner of a node whose MLRF_NODE_ID is the host name.
        _register(client, "lab-pi")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "lab-pi"},
            headers=self._cert("local-edge", "node"),
        )
        assert hb.status_code == 403
        detail = hb.json()["detail"]
        assert "identity must be the node id" in detail
        assert "identity 'lab-pi'" in detail
        assert "MLRF_NODE_ID to 'local-edge'" in detail
        assert "API key" in detail

    def test_node_id_that_cannot_be_a_cert_identity(self, anon, client, proxy_secret):
        _register(client, "lab-pi-")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "lab-pi-"},
            headers=self._cert("local-edge", "node"),
        )
        assert hb.status_code == 403
        assert "cannot be a certificate identity" in hb.json()["detail"]

    def test_node_id_with_an_inner_underscore_can_use_a_cert(
        self, anon, client, proxy_secret
    ):
        from sigrift.bridge.ca import validate_identity

        assert validate_identity("edge_lab1") == "edge_lab1"
        _register(client, "edge_lab1")
        hb = anon.post(
            "/api/nodes/heartbeat",
            json={"node_id": "edge_lab1"},
            headers=self._cert("edge_lab1", "node"),
        )
        assert hb.status_code == 200, hb.text

    def test_a_refused_pair_is_logged_once_per_interval(
        self, anon, client, proxy_secret, caplog
    ):
        _register(client, "lab-pi", "lab-pi-2")
        caplog.set_level(logging.WARNING, logger=deps.logger.name)

        def _beat(node_id: str) -> None:
            hb = anon.post(
                "/api/nodes/heartbeat",
                json={"node_id": node_id},
                headers=self._cert("local-edge", "node"),
            )
            assert hb.status_code == 403

        def _logged() -> list[logging.LogRecord]:
            return [
                r
                for r in caplog.records
                if "Refused client certificate" in r.getMessage()
            ]

        for _ in range(3):
            _beat("lab-pi")
        [record] = _logged()
        assert record.levelno == logging.ERROR
        assert "'lab-pi'" in record.getMessage()
        _beat("lab-pi-2")  # another pair is logged on its own
        assert len(_logged()) == 2


# ---------------------------------------------------------------------------
# K8 / Q7 — post-ingest hook for gateway-ingested batches
# ---------------------------------------------------------------------------

_RULE = {
    "rule_id": "r-loud",
    "name": "loud",
    "enabled": True,
    "cooldown_seconds": 300,
    "conditions": [{"field": "power_dbm", "operator": "gt", "value": -30}],
    "trigger_count": 0,
    "last_triggered_at": None,
}
_BAND = {
    "watch_id": "w-ism",
    "name": "ISM 433",
    "enabled": True,
    "freq_min_hz": 433e6,
    "freq_max_hz": 435e6,
    "trigger": "new_activity",
    "severity": "critical",
}


def _gateway_detection(det_id: str, node_id: str = "edge-a", **fields) -> dict:
    """A detection the way the gateway serializes it after its insert."""
    det = {
        "detection_id": det_id,
        "node_id": node_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signal_class": "fm",
        "confidence": 0.9,
        "family": "analog",
        "freq_hz": 433.92e6,
        "snr_db": 12.0,
        "power_dbm": -10.0,
        "inference_ms": 1.5,
        "backend": "onnx",
        "anomaly_score": 0.1,
        "baseline_status": "stable",
        "has_iq_capture": False,
        "gain_db": None,
        "lna_state": None,
        "bandwidth_hz": None,
    }
    det.update(fields)
    return det


def _adsb_message(icao: str = "abc123") -> dict:
    return {
        "protocol": "adsb",
        "payload_hex": "8d4840d6202cc371c32ce0576098",
        "metadata": {"icao": icao},
    }


class TestIngestHook:
    @pytest.fixture
    def hook(self, anon, proxy_secret):
        def _post(body: dict):
            resp = anon.post("/api/internal/ingest-hook", json=body, headers=_gw())
            assert resp.status_code == 200, resp.text
            return resp.json()

        return _post

    def test_runs_rules_watch_bands_and_stores_edge_decoded(
        self, hook, bridge_app, detection_store, persistence
    ):
        persistence.add_watch_band(dict(_BAND))
        persistence.set_alert_rules([dict(_RULE)])
        det = _gateway_detection("gw-det-1", decoded_messages=[_adsb_message()])
        result = hook(
            {
                "node_id": "edge-a",
                "detections": [det],
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        assert result["accepted"] == 1
        assert result["alerts_created"] == 2
        assert result["decoded_stored"] == 1

        alerts = persistence.get_alerts()
        [band_alert] = [a for a in alerts if a.get("watch_id") == "w-ism"]
        assert band_alert["severity"] == "critical"
        [rule_alert] = [a for a in alerts if a.get("rule_id") == "r-loud"]
        assert rule_alert["detection_id"] == "gw-det-1"
        [rule] = persistence.get_alert_rules()
        assert rule["trigger_count"] == 1
        assert rule["last_triggered_at"]

        [msg] = bridge_app.state.decoded_message_store.get_messages(
            detection_id="gw-det-1"
        )
        assert msg["protocol"] == "adsb"
        assert msg["node_id"] == "edge-a"
        # The hook never inserts the detections: the gateway did.
        assert detection_store.row_count() == 0

    def test_anomaly_alert_from_the_gateway_score(self, hook, persistence):
        det = _gateway_detection("gw-det-hot", anomaly_score=0.95)
        assert hook({"node_id": "edge-a", "detections": [det]})["alerts_created"] == 1
        [alert] = [
            a for a in persistence.get_alerts() if a["name"] == "anomaly_detected"
        ]
        assert alert["severity"] == "critical"
        assert alert["detection_id"] == "gw-det-hot"

    def test_same_batch_twice_fires_alerts_once(self, hook, persistence):
        persistence.add_watch_band(dict(_BAND, trigger="any_activity"))
        persistence.set_alert_rules([dict(_RULE, cooldown_seconds=0)])
        body = {"node_id": "edge-a", "detections": [_gateway_detection("gw-dup")]}
        first = hook(body)
        assert first["alerts_created"] >= 1
        alerts_after_first = len(persistence.get_alerts())
        second = hook(body)
        assert second["accepted"] == 0
        assert second["duplicates"] == 1
        assert second["alerts_created"] == 0
        assert len(persistence.get_alerts()) == alerts_after_first
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1

    def test_a_claim_expires_after_the_retry_window(
        self, hook, persistence, monkeypatch
    ):
        clock = [1000.0]
        monkeypatch.setattr(internal_mod, "_clock", lambda: clock[0])
        persistence.set_alert_rules([dict(_RULE, cooldown_seconds=0)])
        body = {"node_id": "edge-a", "detections": [_gateway_detection("gw-old")]}
        assert hook(body)["accepted"] == 1
        # A retry inside the window is a duplicate ...
        clock[0] += internal_mod._HOOK_SEEN_TTL - 1
        assert hook(body)["duplicates"] == 1
        # ... and the claim is gone once the window has passed, so the
        # set does not keep every detection id the gateway ever sent.
        clock[0] += 2
        again = hook(body)
        assert again["accepted"] == 1
        assert again["duplicates"] == 0

    def test_concurrent_deliveries_of_one_batch_fire_once(
        self, bridge_app, persistence, proxy_secret
    ):
        persistence.set_alert_rules([dict(_RULE, cooldown_seconds=0)])
        body = {"node_id": "edge-a", "detections": [_gateway_detection("gw-race")]}

        async def _race() -> list[dict]:
            transport = httpx.ASGITransport(app=bridge_app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://bridge"
            ) as ac:
                responses = await asyncio.gather(
                    *(
                        ac.post("/api/internal/ingest-hook", json=body, headers=_gw())
                        for _ in range(4)
                    )
                )
            return [r.json() for r in responses]

        results = asyncio.run(_race())
        assert sorted(r["accepted"] for r in results) == [0, 0, 0, 1]
        assert persistence.get_alert_rules()[0]["trigger_count"] == 1

    def test_the_same_detection_id_on_another_node_is_not_a_duplicate(self, hook):
        hook({"node_id": "edge-a", "detections": [_gateway_detection("shared")]})
        result = hook(
            {
                "node_id": "edge-b",
                "detections": [_gateway_detection("shared", node_id="edge-b")],
            }
        )
        assert result["accepted"] == 1

    @pytest.mark.parametrize(
        "shape",
        ["nested", "flat", "groups", "mapping", "parallel"],
    )
    def test_decoded_message_shapes(self, hook, bridge_app, shape):
        dets = [_gateway_detection("d-1"), _gateway_detection("d-2")]
        msg = _adsb_message
        body: dict = {"node_id": "edge-a", "detections": dets}
        if shape == "nested":
            dets[0]["decoded_messages"] = [msg("a1")]
            dets[1]["decoded_messages"] = [msg("a2")]
        elif shape == "flat":
            body["decoded_messages"] = [
                dict(msg("a1"), detection_id="d-1"),
                dict(msg("a2"), detection_id="d-2"),
            ]
        elif shape == "groups":
            body["decoded_messages"] = [
                {"detection_id": "d-1", "decoded_messages": [msg("a1")]},
                {"detection_id": "d-2", "decoded_messages": [msg("a2")]},
            ]
        elif shape == "mapping":
            body["decoded_messages"] = {"d-1": [msg("a1")], "d-2": [msg("a2")]}
        else:
            body["decoded_messages"] = [[msg("a1")], [msg("a2")]]
        assert hook(body)["decoded_stored"] == 2
        store = bridge_app.state.decoded_message_store
        for det_id in ("d-1", "d-2"):
            [stored] = store.get_messages(detection_id=det_id)
            assert stored["node_id"] == "edge-a"

    def test_messages_cannot_be_attributed_to_unknown_detections(
        self, hook, bridge_app
    ):
        body = {
            "node_id": "edge-a",
            "detections": [_gateway_detection("d-1")],
            "decoded_messages": [dict(_adsb_message(), detection_id="other")],
        }
        assert hook(body)["decoded_stored"] == 0
        assert bridge_app.state.decoded_message_store.count() == 0

    def test_detections_of_another_node_are_ignored(self, hook, persistence):
        persistence.add_watch_band(dict(_BAND))
        body = {
            "node_id": "edge-a",
            "detections": [
                _gateway_detection("x-1", node_id="edge-b"),
                {"signal_class": "fm"},  # no detection_id
                "not-an-object",
            ],
        }
        result = hook(body)
        assert result["accepted"] == 0
        assert result["invalid"] == 3
        assert persistence.get_alerts() == []

    def test_native_analysis_is_not_repeated(self, hook, detection_store):
        # The gateway already upserted rf_anomalies (and ran FHSS /
        # correlation); the hook must not store them a second time.
        det = _gateway_detection("gw-anom", anomaly_score=0.9)
        hook({"node_id": "edge-a", "detections": [det]})
        assert detection_store.get_rf_anomalies(min_score=0.0) == []

    def test_detections_are_not_rebroadcast_but_alerts_are(
        self, hook, bridge_app, persistence, monkeypatch
    ):
        app_state: AppState = bridge_app.state.app_state

        class _Recorder:
            def __init__(self) -> None:
                self.sent: list = []

            async def broadcast(self, data) -> None:
                self.sent.append(data)

        dets, alerts = _Recorder(), _Recorder()
        monkeypatch.setattr(app_state, "ws_detection_clients", dets)
        monkeypatch.setattr(app_state, "ws_alert_clients", alerts)
        persistence.add_watch_band(dict(_BAND))
        hook({"node_id": "edge-a", "detections": [_gateway_detection("b-1")]})
        assert dets.sent == []
        assert [a.get("watch_id") for a in alerts.sent] == ["w-ism"]

    def test_a_failing_stage_does_not_stop_the_others(
        self, hook, persistence, monkeypatch
    ):
        persistence.add_watch_band(dict(_BAND))

        def _broken():
            raise RuntimeError("rules store unavailable")

        monkeypatch.setattr(persistence, "get_alert_rules", _broken)
        result = hook({"node_id": "edge-a", "detections": [_gateway_detection("f-1")]})
        assert result["alerts_created"] == 1
        assert [a.get("watch_id") for a in persistence.get_alerts()] == ["w-ism"]

    def test_malformed_body_is_422(self, anon, proxy_secret):
        for body in (
            {"node_id": "../x", "detections": []},
            {"node_id": "edge-a", "detections": "nope"},
        ):
            resp = anon.post("/api/internal/ingest-hook", json=body, headers=_gw())
            assert resp.status_code == 422, body

    def test_bridge_ingest_still_runs_the_same_post_ingest(
        self, client, persistence, registered_node
    ):
        # The bridge's own /api/detections/batch keeps doing (a) + (b).
        persistence.add_watch_band(dict(_BAND))
        now = datetime.now(timezone.utc)
        resp = client.post(
            "/api/detections/batch",
            json={
                "node_id": registered_node,
                "period_start": (now - timedelta(minutes=1)).isoformat(),
                "period_end": now.isoformat(),
                "detections": [
                    {
                        "id": "edge-det-1",
                        "node_id": registered_node,
                        "signal_class": "fm",
                        "confidence": 0.9,
                        "freq_hz": 433.92e6,
                        "power_dbm": -10.0,
                        "decoded_messages": [_adsb_message()],
                    }
                ],
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["alerts_created"] == 1
        store = client.app.state.decoded_message_store
        assert len(store.get_messages(detection_id="edge-det-1")) == 1


class TestHookClaims:
    """Bounds of the ingest-hook claims.

    Round 5 (K8b, review V5) moved the claims from a per-process
    ``RecentDetections`` set into ``detections.db`` (``IngestClaimStore``),
    which every worker shares; these are the same bounds, on that store.
    """

    @pytest.fixture
    def claims(self, detection_store):
        from sigrift.bridge.storage.ingest_claims import IngestClaimStore

        return IngestClaimStore(detection_store._ctx)

    def test_bounds_cover_one_hook_and_the_gateway_retry_window(self) -> None:
        # One whole hook must fit, so its own retry is caught ...
        assert internal_mod._HOOK_SEEN_MAX >= internal_mod._HOOK_MAX_DETECTIONS
        # ... and a claim must outlive the gateway's retries of a chunk:
        # 3 attempts of up to 10 s each, 0.5 s and 1 s apart.
        assert internal_mod._HOOK_SEEN_TTL >= 3 * 10 + 0.5 + 1

    def test_count_cap_drops_the_oldest(self, claims) -> None:
        for i in range(5):
            fresh = claims.claim_hook_detections(
                "n", [f"d{i}"], now=float(i), ttl=60.0, max_rows=3
            )
            assert fresh == {f"d{i}"}
        claims.trim_hook_claims(3)
        assert claims.hook_claim_count() == 3
        # The two oldest went; the newest is still claimed.
        fresh = claims.claim_hook_detections(
            "n", ["d0", "d1", "d4"], now=5.0, ttl=60.0, max_rows=3
        )
        assert fresh == {"d0", "d1"}

    def test_expiry_pops_only_old_claims(self, claims) -> None:
        claims.claim_hook_detections("n", ["a"], now=0.0, ttl=10.0, max_rows=100)
        claims.claim_hook_detections("n", ["b"], now=5.0, ttl=10.0, max_rows=100)
        fresh = claims.claim_hook_detections(
            "n", ["a", "b"], now=12.0, ttl=10.0, max_rows=100
        )
        assert fresh == {"a"}  # "a" expired and is claimed again; "b" is not

    def test_a_full_store_stays_bounded(self, claims, monkeypatch) -> None:
        import sigrift.bridge.storage.ingest_claims as claims_mod

        monkeypatch.setattr(claims_mod, "_TRIM_EVERY", 100)
        for chunk in range(30):
            claims.claim_hook_detections(
                "sigrift-staging",
                [f"{chunk:04x}{i:012x}" for i in range(100)],
                now=float(chunk),
                ttl=3600.0,
                max_rows=1000,
            )
        assert claims.hook_claim_count() <= 1000 + 100


# ---------------------------------------------------------------------------
# P1 (bridge side) — no MFA endpoint is served by the bridge
# ---------------------------------------------------------------------------


def test_bridge_serves_no_mfa_endpoints() -> None:
    """The bridge's MFA handlers stay unmounted (the gateway owns MFA).

    routers/mfa.py has no per-user attempt limit and a check-then-record
    TOTP replay test; a percent-encoded path the gateway does not route
    natively would reach it if it were mounted.
    """
    from sigrift.bridge.app import app

    paths = {getattr(route, "path", "") for route in app.routes}
    assert not [p for p in paths if p.startswith("/api/auth/mfa")]
    assert "/api/admin/users/{username}/disable-mfa" not in paths
    assert "/api/admin/settings/mfa" not in paths


def test_test_app_serves_no_mfa_endpoints(anon) -> None:
    for path in (
        "/api/auth/mfa/disable",
        "/api/auth/mfa/verify",
        "/api/auth/mfa/regenerate-backup-codes",
    ):
        assert anon.post(path, json={"totp_code": "123456"}).status_code == 404


# ---------------------------------------------------------------------------
# P3 — maintenance never deletes live audit rows
# ---------------------------------------------------------------------------


def _backdated_audit_entry(store: DetectionStore, days_ago: int) -> None:
    from sigrift.bridge.storage.audit import _compute_hmac_v2, _get_audit_secret

    old_ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
    conn = store._ctx.get_conn()
    prev = conn.execute(
        "SELECT hmac_chain FROM audit_log WHERE tenant_id = ? ORDER BY id DESC LIMIT 1",
        [store._ctx.tenant_id],
    ).fetchone()
    previous = (prev["hmac_chain"] or "") if prev else ""
    entry_hmac = _compute_hmac_v2(
        _get_audit_secret(), previous, "old_action", "t", "tester", old_ts,
        "", "", "", "0.0", "",
    )  # fmt: skip
    conn.execute(
        "INSERT INTO audit_log (timestamp, action, target_id, target_ids, "
        "signal_class, freq_hz, node_id, operator, note, details, tenant_id, "
        "hmac_chain) VALUES (?, 'old_action', 't', '', '', 0.0, '', 'tester', "
        "'', '', ?, ?)",
        [old_ts, store._ctx.tenant_id, entry_hmac],
    )
    conn.commit()


def _audit_rows(store: DetectionStore) -> int:
    conn = store._ctx.get_conn()
    return conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]


class TestMaintenanceKeepsTheAuditLog:
    def test_purge_audit_log_is_refused(self, client, detection_store):
        for days in (200, 100, 30):
            _backdated_audit_entry(detection_store, days)
        before = _audit_rows(detection_store)
        resp = client.post(
            "/api/admin/maintenance",
            json={"task": "purge_audit_log", "retention_days": 1},
        )
        assert resp.status_code == 409
        assert "/api/admin/audit/archive" in resp.json()["detail"]
        assert _audit_rows(detection_store) == before
        assert detection_store.verify_audit_chain()["valid"] is True

    def test_purge_old_data_leaves_the_audit_log(self, client, detection_store):
        for days in (400, 200):
            _backdated_audit_entry(detection_store, days)
        before = _audit_rows(detection_store)
        resp = client.post(
            "/api/admin/maintenance",
            json={"task": "purge_old_data", "retention_days": 7},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["deleted"]["audit_log"] == 0
        # Nothing removed; only the maintenance entry itself was appended.
        assert _audit_rows(detection_store) == before + 1
        assert detection_store.verify_audit_chain()["valid"] is True

    def test_store_has_no_plain_audit_delete(self) -> None:
        assert not hasattr(DetectionStore, "purge_audit_log")


# ---------------------------------------------------------------------------
# P5 — BRIDGE_TRUSTED_PROXIES host names are re-resolved
# ---------------------------------------------------------------------------


class TestTrustedProxyHostNames:
    @pytest.fixture
    def dns(self, monkeypatch):
        answers: dict[str, str | None] = {"gateway": None}

        def fake_getaddrinfo(host, *args, **kwargs):
            ip = answers.get(host)
            if ip is None:
                raise socket.gaierror("Name or service not known")
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

        monkeypatch.setattr(deps.socket, "getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr(deps._ProxyHostResolver, "RETRY_SECONDS", 0.0)
        monkeypatch.setenv("BRIDGE_TRUSTED_PROXIES", "gateway")
        yield answers
        monkeypatch.delenv("BRIDGE_TRUSTED_PROXIES", raising=False)
        deps.reload_trusted_proxies()

    @staticmethod
    def _ip(peer: str, xff: str = "203.0.113.7") -> str:
        from starlette.requests import Request

        scope = {
            "type": "http",
            "method": "GET",
            "path": "/",
            "query_string": b"",
            "headers": [(b"x-forwarded-for", xff.encode())],
            "client": (peer, 0),
        }
        return deps.get_client_ip(Request(scope))

    def _eventually(self, peer: str, expected: str) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self._ip(peer) == expected:
                return
            time.sleep(0.01)
        assert self._ip(peer) == expected

    def test_name_that_resolves_after_start_up_becomes_trusted(self, dns, caplog):
        with caplog.at_level(logging.ERROR, logger=deps.__name__):
            deps.reload_trusted_proxies()
        assert "does not resolve yet" in caplog.text
        assert self._ip("172.29.84.2") == "172.29.84.2"
        # The gateway container starts (after the bridge is healthy).
        dns["gateway"] = "172.29.84.2"
        self._eventually("172.29.84.2", "203.0.113.7")
        # Still only the gateway.
        assert self._ip("172.29.84.3") == "172.29.84.3"

    def test_a_changed_address_replaces_the_old_one(self, dns, monkeypatch):
        dns["gateway"] = "172.29.84.2"
        deps.reload_trusted_proxies()
        assert self._ip("172.29.84.2") == "203.0.113.7"
        monkeypatch.setattr(deps._ProxyHostResolver, "REFRESH_SECONDS", 0.0)
        dns["gateway"] = "172.29.84.9"  # container recreated
        self._eventually("172.29.84.9", "203.0.113.7")
        self._eventually("172.29.84.2", "172.29.84.2")

    def test_a_dns_failure_keeps_the_last_address(self, dns, monkeypatch):
        dns["gateway"] = "172.29.84.2"
        deps.reload_trusted_proxies()
        dns["gateway"] = None
        resolver = deps._TRUSTED_PROXY_HOSTS
        assert resolver.resolve() == frozenset({"172.29.84.2"})
        assert self._ip("172.29.84.2") == "203.0.113.7"


# ---------------------------------------------------------------------------
# P6 — cooldowns right after host boot (time.monotonic() is small)
# ---------------------------------------------------------------------------


class _Clock:
    """Stand-in for the ``time`` module with a fixed monotonic clock."""

    def __init__(self, now: float) -> None:
        self.now = now

    def monotonic(self) -> float:
        return self.now

    def time(self) -> float:
        return time.time()


class TestCooldownsAfterBoot:
    def test_first_rf_anomaly_alert_is_not_suppressed(self, persistence, monkeypatch):
        monkeypatch.setattr(detections_mod, "time", _Clock(40.0))
        app_state = AppState()
        det = SimpleNamespace(
            anomaly_score=0.9,
            confidence=0.9,
            freq_hz=433.92e6,
            signal_class="fm",
            detection_id="boot-1",
        )
        created = asyncio.run(
            detections_mod._maybe_create_anomaly_alerts(
                app_state, persistence, [det], "edge-a"
            )
        )
        assert created == 1
        # The cooldown still applies to the next one.
        detections_mod.time.now = 41.0
        assert (
            asyncio.run(
                detections_mod._maybe_create_anomaly_alerts(
                    app_state, persistence, [det], "edge-a"
                )
            )
            == 0
        )

    def test_first_wifi_anomaly_alert_is_not_suppressed(self, persistence, monkeypatch):
        monkeypatch.setattr(wifi_mod, "time", _Clock(40.0))
        app_state = AppState()
        result = SimpleNamespace(
            score=0.95, bssid="aa:bb:cc:dd:ee:ff", ssid="evil-twin", dimensions={}
        )
        assert asyncio.run(
            wifi_mod._maybe_create_wifi_alert(app_state, persistence, result, "edge-a")
        )
        wifi_mod.time.now = 41.0
        assert not asyncio.run(
            wifi_mod._maybe_create_wifi_alert(app_state, persistence, result, "edge-a")
        )


# ---------------------------------------------------------------------------
# P7 — bounded pcap inflation
# ---------------------------------------------------------------------------


def _pcap_gz(frames: int = 2) -> bytes:
    header = struct.pack(
        "<IHHiIII",
        pcap_mod._PCAP_MAGIC,
        2,
        4,
        0,
        0,
        65535,
        pcap_mod._PCAP_LINKTYPE_RADIOTAP,
    )
    frame = struct.pack("<BBHI", 0, 0, 8, 0) + struct.pack("<H", 8 << 4) + bytes(22)
    packets = b"".join(
        struct.pack("<IIII", i + 1, 0, len(frame), len(frame)) + frame
        for i in range(frames)
    )
    return gzip.compress(header + packets)


class TestPcapBounds:
    def test_decompress_stops_at_the_limit(self) -> None:
        bomb = gzip.compress(bytes(32 * 1024 * 1024))
        with pytest.raises(pcap_mod.PcapSizeLimitError):
            pcap_mod.decompress_pcap(bomb, max_bytes=1024 * 1024)
        assert pcap_mod.decompress_pcap(_pcap_gz(), max_bytes=1024 * 1024)

    def test_decompress_matches_gzip_for_valid_input(self) -> None:
        data = _pcap_gz(5)
        two_members = data + gzip.compress(b"tail") + bytes(16)
        assert pcap_mod.decompress_pcap(two_members) == gzip.decompress(two_members)
        with pytest.raises(pcap_mod.PcapDecompressionError):
            pcap_mod.decompress_pcap(data[:-10])
        with pytest.raises(pcap_mod.PcapDecompressionError):
            pcap_mod.decompress_pcap(b"not gzip at all")

    def test_load_pcap_refuses_an_oversized_capture(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_PCAP_MAX_BYTES", str(1024 * 1024))
        store = PcapStore(base_dir=tmp_path)
        store.store(7, gzip.compress(bytes(8 * 1024 * 1024)))
        assert store.load_pcap(7) is None
        assert store.parse_summary(7) is None

    def test_upload_of_a_gzip_bomb_is_refused(
        self, client, detection_store, bridge_app, monkeypatch
    ) -> None:
        monkeypatch.setenv("BRIDGE_PCAP_MAX_BYTES", str(1024 * 1024))
        aid = detection_store.insert_wifi_anomaly(
            {
                "bssid": "aa:bb:cc:11:22:33",
                "anomaly_score": 0.7,
                "priority": "critical",
                "baseline_status": "stable",
                "timestamp": "2026-02-11T00:00:00+00:00",
            }
        )
        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=gzip.compress(bytes(8 * 1024 * 1024)),
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 413
        assert not bridge_app.state.pcap_store.exists(aid)
        # A normal capture is still accepted and summarized.
        resp = client.post(
            f"/api/wifi/anomalies/{aid}/pcap",
            content=_pcap_gz(3),
            headers={"Content-Type": "application/octet-stream"},
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["frame_count"] == 3
