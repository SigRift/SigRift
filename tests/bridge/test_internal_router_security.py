"""Security-path tests for ``routers/internal.py`` (``/api/internal/*``).

The middleware refuses the whole prefix without ``X-Rust-Proxy``
(tests/bridge/test_round4_br1.py). These tests cover what those do not:

* the router's own ``require_rust_proxy`` dependency, with the middleware
  out of the way, so the route stays gateway-only even if it were mounted
  without ``CombinedMiddleware``;
* ``read_json_body`` limits and errors on the bind-node-key body (size,
  gzip bombs, corrupt gzip, non-JSON, non-object);
* bind-node-key input validation, the master key, a key revoked while it
  was being bound, and the 503 before start-up finished;
* ingest-hook records that fail validation, the per-hook detection cap and
  the 503s before start-up finished.
"""

from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.dependencies as deps
import sigrift.bridge.routers.internal as internal_mod
from sigrift.bridge.persistence import PersistenceManager
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)

_SECRET = "p3-internal-proxy-secret-0123456789abcdef"
_BIND = "/api/internal/bind-node-key"
_HOOK = "/api/internal/ingest-hook"


@pytest.fixture(autouse=True)
def _fresh_cache():
    deps._verified_key_cache.clear()
    yield
    deps._verified_key_cache.clear()


@pytest.fixture
def proxy_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("UC_PROXY_SECRET", _SECRET)
    return _SECRET


@pytest.fixture
def gw(bridge_app: FastAPI, proxy_secret: str) -> TestClient:
    """A client that presents the gateway's proxy secret."""
    return TestClient(bridge_app, headers={"X-Rust-Proxy": proxy_secret})


def _add_key(persistence: PersistenceManager, key_id: str, role: str) -> str:
    raw = generate_api_key(32)
    hash_hex, salt = hash_credential(raw)
    meta = {"role": role, "description": "", "created_at": "", "expires_at": None}
    assert persistence.add_key(
        key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw), meta=meta
    )
    return raw


def _detection(det_id: str, node_id: str = "edge-a", **fields) -> dict:
    det = {
        "detection_id": det_id,
        "node_id": node_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "signal_class": "fm",
        "confidence": 0.9,
        "family": "analog",
        "freq_hz": 433.92e6,
        "snr_db": 12.0,
        "power_dbm": -80.0,
        "anomaly_score": 0.0,
    }
    det.update(fields)
    return det


# ---------------------------------------------------------------------------
# The router dependency itself (no middleware in front of it)
# ---------------------------------------------------------------------------


class TestRouterDependencyWithoutMiddleware:
    """``require_rust_proxy`` guards the routes on its own."""

    @pytest.fixture
    def bare(self, persistence: PersistenceManager, app_state) -> FastAPI:
        app = FastAPI()
        app.include_router(internal_mod.router, prefix="/api/internal")
        app.state.persistence = persistence
        app.state.app_state = app_state
        return app

    @pytest.mark.parametrize("path", [_BIND, _HOOK])
    def test_no_or_wrong_secret_is_403(self, bare, proxy_secret, path) -> None:
        anon = TestClient(bare)
        body = {"key_id": "k", "node_id": "edge-a", "detections": []}
        for headers in ({}, {"X-Rust-Proxy": "wrong"}, {"X-Rust-Proxy": ""}):
            resp = anon.post(path, json=body, headers=headers)
            assert resp.status_code == 403, headers
            assert resp.json() == {
                "detail": "Internal endpoint: only the gateway may call it"
            }

    def test_api_key_is_not_a_substitute_for_the_secret(
        self, bare, persistence, proxy_secret
    ) -> None:
        raw = _add_key(persistence, "ops", "admin")
        resp = TestClient(bare).post(
            _BIND,
            json={"key_id": "ops", "node_id": "edge-a"},
            headers={"X-API-Key": raw},
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize("secret", ["", "uppercrust-internal"])
    def test_insecure_configured_secret_never_matches(
        self, bare, monkeypatch, secret
    ) -> None:
        monkeypatch.setenv("UC_PROXY_SECRET", secret)
        resp = TestClient(bare).post(
            _BIND,
            json={"key_id": "k", "node_id": "edge-a"},
            headers={"X-Rust-Proxy": secret},
        )
        assert resp.status_code == 403

    def test_correct_secret_reaches_the_route(self, bare, proxy_secret) -> None:
        resp = TestClient(bare).post(
            _BIND,
            json={"key_id": "nope", "node_id": "edge-a"},
            headers={"X-Rust-Proxy": proxy_secret},
        )
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Unknown API key"}

    def test_prefix_of_the_secret_is_refused(self, bare, proxy_secret) -> None:
        resp = TestClient(bare).post(
            _BIND,
            json={"key_id": "nope", "node_id": "edge-a"},
            headers={"X-Rust-Proxy": proxy_secret[:-1]},
        )
        assert resp.status_code == 403

    def test_missing_persistence_is_503(self, bare, proxy_secret) -> None:
        bare.state.persistence = None
        resp = TestClient(bare).post(
            _BIND,
            json={"key_id": "k", "node_id": "edge-a"},
            headers={"X-Rust-Proxy": proxy_secret},
        )
        assert resp.status_code == 503
        assert resp.json() == {"detail": "Service not ready"}


# ---------------------------------------------------------------------------
# read_json_body (bind-node-key caps its body at 4 KiB)
# ---------------------------------------------------------------------------


class TestBodyParsing:
    def test_oversized_body_is_413(self, gw) -> None:
        body = json.dumps({"key_id": "k" * 5000, "node_id": "edge-a"})
        resp = gw.post(
            _BIND, content=body, headers={"Content-Type": "application/json"}
        )
        assert resp.status_code == 413
        assert "byte limit" in resp.json()["detail"]

    def test_gzip_bomb_is_413(self, gw) -> None:
        # Compresses far below the 4 KiB wire limit, inflates past it.
        raw = json.dumps({"key_id": "k", "node_id": "edge-a", "pad": "x" * 200_000})
        packed = gzip.compress(raw.encode())
        assert len(packed) < 4096
        resp = gw.post(
            _BIND,
            content=packed,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        assert resp.status_code == 413
        assert resp.json()["detail"] == "Decompressed payload exceeds size limit"

    @pytest.mark.parametrize(
        "payload",
        [
            b"definitely not gzip",  # bad magic
            gzip.compress(b'{"key_id": "k", "node_id": "edge-a"}')[:12],  # truncated
            gzip.compress(b'{"key_id": "k"}')[:10] + b"\xff" * 16,  # corrupt deflate
        ],
        ids=["bad-magic", "truncated", "corrupt"],
    )
    def test_corrupt_gzip_is_400(self, gw, payload: bytes) -> None:
        resp = gw.post(
            _BIND,
            content=payload,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "Failed to decompress gzip body"

    def test_valid_gzip_body_is_accepted(self, gw) -> None:
        packed = gzip.compress(b'{"key_id": "nope", "node_id": "edge-a"}')
        resp = gw.post(
            _BIND,
            content=packed,
            headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
        )
        assert resp.status_code == 404  # parsed; unknown key

    @pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe\x00"])
    def test_invalid_json_is_400(self, gw, content: bytes) -> None:
        resp = gw.post(
            _BIND, content=content, headers={"Content-Type": "application/json"}
        )
        assert resp.status_code == 400
        assert resp.json()["detail"].startswith("Invalid JSON")

    @pytest.mark.parametrize("content", [b"[]", b'"key"', b"42", b"null"])
    def test_non_object_json_is_400(self, gw, content: bytes) -> None:
        resp = gw.post(
            _BIND, content=content, headers={"Content-Type": "application/json"}
        )
        assert resp.status_code == 400
        assert resp.json()["detail"] == "JSON body must be an object"


# ---------------------------------------------------------------------------
# bind-node-key
# ---------------------------------------------------------------------------


class TestBindNodeKeyValidation:
    @pytest.mark.parametrize(
        "key_id", [None, "", 7, ["k"], {"k": 1}, "k" * 257], ids=repr
    )
    def test_bad_key_id_is_422(self, gw, persistence, key_id) -> None:
        resp = gw.post(_BIND, json={"key_id": key_id, "node_id": "edge-a"})
        assert resp.status_code == 422
        assert resp.json()["detail"] == "key_id must be a non-empty string"

    @pytest.mark.parametrize(
        "node_id", [None, "", 5, "a b", "x" * 65, "edge/a", "édge"], ids=repr
    )
    def test_bad_node_id_is_422_and_binds_nothing(
        self, gw, persistence, node_id
    ) -> None:
        _add_key(persistence, "sensor-a", "sensor")
        resp = gw.post(_BIND, json={"key_id": "sensor-a", "node_id": node_id})
        assert resp.status_code == 422
        assert "node_id" not in persistence.get_key_meta()["sensor-a"]

    def test_master_key_is_never_bound(self, gw, persistence) -> None:
        resp = gw.post(_BIND, json={"key_id": "master", "node_id": "edge-a"})
        assert resp.status_code == 200
        assert resp.json() == {"node_id": "edge-a", "bound": False}
        assert not persistence.get_key_meta().get("master", {}).get("node_id")

    def test_keymaster_key_is_never_bound(self, gw, persistence) -> None:
        _add_key(persistence, "km", "keymaster")
        resp = gw.post(_BIND, json={"key_id": "km", "node_id": "edge-a"})
        assert resp.json() == {"node_id": "edge-a", "bound": False}
        assert "node_id" not in persistence.get_key_meta()["km"]

    def test_key_revoked_while_binding_is_404(
        self, gw, persistence, monkeypatch
    ) -> None:
        _add_key(persistence, "sensor-a", "sensor")

        async def _revoked(_persistence, _key_id, _node_id):
            return deps.NodeKeyBinding(deps.NodeBindOutcome.UNKNOWN_KEY)

        monkeypatch.setattr(internal_mod, "bind_node_key", _revoked)
        resp = gw.post(_BIND, json={"key_id": "sensor-a", "node_id": "edge-a"})
        assert resp.status_code == 404
        assert resp.json() == {"detail": "Unknown API key"}

    def test_revoked_key_still_in_the_store_does_not_claim_the_node(
        self, gw, persistence
    ) -> None:
        # A revoked key that already holds a node must not keep another
        # (live) key from claiming it (K7b: only usable keys hold a node).
        _add_key(persistence, "old", "sensor")
        meta = persistence.get_key_meta()["old"]
        persistence.set_key_meta("old", {**meta, "node_id": "edge-a", "revoked": True})
        _add_key(persistence, "new", "sensor")
        resp = gw.post(_BIND, json={"key_id": "new", "node_id": "edge-a"})
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"node_id": "edge-a", "bound": True}


# ---------------------------------------------------------------------------
# ingest-hook
# ---------------------------------------------------------------------------


class TestIngestHookHardening:
    def test_records_that_fail_validation_are_counted_invalid(self, gw) -> None:
        body = {
            "node_id": "edge-a",
            "detections": [
                _detection("ok-1"),
                _detection("bad-conf", confidence="very"),
                _detection("bad-freq", freq_hz={"hz": 1}),
                "not-a-dict",
                {"signal_class": "fm"},  # no id at all
                _detection("", node_id="edge-a"),
                _detection("foreign", node_id="edge-b"),
            ],
        }
        resp = gw.post(_HOOK, json=body)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["accepted"] == 1
        assert data["invalid"] == 6
        assert data["skipped"] == 0

    def test_legacy_id_field_is_accepted(self, gw) -> None:
        det = _detection("ignored")
        det.pop("detection_id")
        det["id"] = "legacy-1"
        resp = gw.post(_HOOK, json={"node_id": "edge-a", "detections": [det]})
        assert resp.json()["accepted"] == 1

    def test_detections_beyond_the_cap_are_skipped(self, gw, monkeypatch) -> None:
        monkeypatch.setattr(internal_mod, "_HOOK_MAX_DETECTIONS", 2)
        dets = [_detection(f"cap-{i}") for i in range(5)]
        resp = gw.post(_HOOK, json={"node_id": "edge-a", "detections": dets})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["accepted"] == 2
        assert data["skipped"] == 3
        # The skipped ones were never claimed: a later delivery processes them.
        again = gw.post(_HOOK, json={"node_id": "edge-a", "detections": dets[2:4]})
        assert again.json()["accepted"] == 2
        assert again.json()["duplicates"] == 0

    def test_batch_id_is_truncated(self, gw, monkeypatch) -> None:
        seen: dict = {}

        async def _post_ingest(app, fresh, node_id, edge_decoded, **kwargs):
            seen.update(kwargs)
            return {"alerts_created": 0, "decoded_stored": 0, "decode_jobs": 0}

        monkeypatch.setattr(internal_mod, "post_ingest", _post_ingest)
        resp = gw.post(
            _HOOK,
            json={
                "node_id": "edge-a",
                "batch_id": "b" * 500,
                "detections": [_detection("batch-1")],
            },
        )
        assert resp.status_code == 200, resp.text
        assert seen["batch_id"] == "b" * 128
        assert seen["native_analysis"] is True

    def test_non_string_batch_id_becomes_empty(self, gw, monkeypatch) -> None:
        seen: dict = {}

        async def _post_ingest(app, fresh, node_id, edge_decoded, **kwargs):
            seen.update(kwargs)
            return {"alerts_created": 0, "decoded_stored": 0, "decode_jobs": 0}

        monkeypatch.setattr(internal_mod, "post_ingest", _post_ingest)
        gw.post(
            _HOOK,
            json={
                "node_id": "edge-a",
                "batch_id": {"x": 1},
                "detections": [_detection("batch-2")],
            },
        )
        assert seen["batch_id"] == ""

    @pytest.mark.parametrize(
        "body",
        [
            {"node_id": "../x", "detections": []},
            {"detections": []},
            {"node_id": "edge-a"},
            {"node_id": "edge-a", "detections": {"a": 1}},
        ],
    )
    def test_malformed_body_is_422(self, gw, body) -> None:
        assert gw.post(_HOOK, json=body).status_code == 422

    def test_missing_app_state_is_503(self, gw, bridge_app) -> None:
        bridge_app.state.app_state = None
        resp = gw.post(_HOOK, json={"node_id": "edge-a", "detections": []})
        assert resp.status_code == 503

    def test_missing_persistence_is_503(self, gw, bridge_app) -> None:
        bridge_app.state.persistence = None
        resp = gw.post(_HOOK, json={"node_id": "edge-a", "detections": []})
        assert resp.status_code == 503

    def test_missing_claim_store_is_503_and_runs_nothing(self, gw, monkeypatch) -> None:
        ran: list = []

        async def _post_ingest(*args, **kwargs):  # pragma: no cover - must not run
            ran.append(args)
            return {"alerts_created": 0, "decoded_stored": 0, "decode_jobs": 0}

        monkeypatch.setattr(internal_mod, "get_ingest_claims", lambda state: None)
        monkeypatch.setattr(internal_mod, "post_ingest", _post_ingest)
        resp = gw.post(
            _HOOK, json={"node_id": "edge-a", "detections": [_detection("c-1")]}
        )
        assert resp.status_code == 503
        assert ran == []
