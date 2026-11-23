"""Security-path tests for ``sigrift.bridge.routers.admin``.

Complements ``test_admin_endpoints.py`` / ``test_admin_new.py`` (happy
paths and basic auth) with the paths that guard the admin surface:

  - every admin route refuses unauthenticated and non-admin callers and a
    refused request changes nothing (keys, nodes, alerts, syslog targets,
    queued commands, environment, audit trail)
  - role ceilings for the keymaster role, privilege changes taking effect
    on the next request, rotation invalidating the old credential
  - unknown body fields rejected (no smuggling ``key_id`` / ``alert_id``),
    key-id collisions never replacing an existing key, ``expires_days``
    defaulted and capped to the max lifetime (422 for zero, negative or
    past the route's 3650-day ceiling), a non-finite number anywhere in a
    body a 422 and not a 500
  - the audit trail: attribution to the acting key, change diffs, no entry
    for refused or failed actions, no raw key material in logs or audit
  - SSH key deployment guards (host / remote temp path validation, step
    failures, local temp file cleanup)
  - syslog target and runtime-config validation, node diagnostics

Tests marked ``xfail(strict=True)`` assert the correct behaviour for a
bug the test exposed; the reason names the defect.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import socket
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import sigrift.bridge.routers.keys as keys_mod
from sigrift.bridge.persistence import PersistenceManager
from sigrift.bridge.routers.admin import _config_diff
from sigrift.lib.security.credentials import (
    compute_lookup_hash,
    generate_api_key,
    hash_credential,
)
from sigrift.lib.shiny.models import MAX_KEY_EXPIRES_IN_HOURS

# Key rotation needs TLS: requests to it go to an https:// URL.
_HTTPS = "https://testserver"
#: The longest ``expires_days`` POST /api/admin/keys accepts (422 above it);
#: the key's lifetime is still capped to BRIDGE_MAX_KEY_LIFETIME_DAYS.
_MAX_EXPIRES_DAYS = 3650
_NODE = "node-sec-01"
_VICTIM = "victim"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_key(
    persistence: PersistenceManager,
    key_id: str,
    role: str | None = "viewer",
    *,
    node_id: str | None = None,
) -> str:
    """Store an API key (with a lookup hash) and return the raw key.

    ``role=None`` stores the key without any metadata (a legacy key).
    """
    raw = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw)
    persistence.set_key(key_id, hash_hex, salt, lookup_hash=compute_lookup_hash(raw))
    if role is not None:
        meta: dict[str, Any] = {"role": role, "description": f"test {role}"}
        if node_id is not None:
            meta["node_id"] = node_id
        persistence.set_key_meta(key_id, meta)
    return raw


def _now_iso(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def _add_node(
    persistence: PersistenceManager, node_id: str = _NODE, **fields: Any
) -> str:
    data: dict[str, Any] = {
        "host": "10.0.0.1",
        "port": 8080,
        "last_seen": _now_iso(),
        "registered_at": _now_iso(3600),
        "capabilities": {},
    }
    data.update(fields)
    persistence.set_node(node_id, data)
    return node_id


def _audit(store: Any, action: str | None = None) -> list[dict[str, Any]]:
    return store.get_audit_log(action=action, limit=1000)


def _admin_audit(store: Any) -> list[dict[str, Any]]:
    return [e for e in _audit(store) if e["action"].startswith("admin_")]


def _client(app: FastAPI, raw_key: str | None) -> TestClient:
    headers = {"X-API-Key": raw_key} if raw_key else {}
    return TestClient(app, headers=headers)


def _state(app: FastAPI) -> dict[str, Any]:
    """Snapshot of everything an admin route can change."""
    p = app.state.persistence
    meta = p.get_key_meta()
    keys = p.get_key_store()
    return {
        "keys": {k: keys.get(k) for k in ("master", _VICTIM)},
        "meta": {k: meta.get(k) for k in ("master", _VICTIM)},
        "key_ids": sorted(keys),
        "nodes": p.get_nodes(),
        "alerts": p.get_alerts(),
        "syslog": copy.deepcopy(app.state.syslog_forwarder.targets),
        "persisted_syslog": p.get_syslog_targets(),
        "pending": copy.deepcopy(app.state.app_state.pending_commands),
        "history": copy.deepcopy(list(app.state.app_state.command_history)),
        "log_level": os.environ.get("BRIDGE_LOG_LEVEL"),
        "admin_audit": len(_admin_audit(app.state.detection_store)),
    }


@pytest.fixture
def seeded(
    bridge_app: FastAPI, persistence: PersistenceManager, monkeypatch
) -> SimpleNamespace:
    """A node, a victim key, an alert and a syslog target to aim at."""
    monkeypatch.setenv("BRIDGE_LOG_LEVEL", "INFO")
    _add_node(persistence)
    _add_key(persistence, _VICTIM, "viewer")
    alert = {
        "alert_id": "alert_seed",
        "name": "seed",
        "severity": "warning",
        "message": "",
        "node_id": "",
        "acknowledged": False,
    }
    persistence.add_alert(alert)
    fwd = bridge_app.state.syslog_forwarder
    target = fwd.add_target(host="127.0.0.1", port=5514)
    persistence.set_syslog_targets(fwd.targets)
    return SimpleNamespace(alert_id="alert_seed", target_id=target["id"])


# (method, path, json body, extra headers, mutating)
_ENDPOINTS: list[tuple[str, str, Any, dict[str, str], bool]] = [
    ("GET", "/api/admin/keys", None, {}, False),
    ("POST", "/api/admin/keys", {"role": "admin"}, {}, True),
    ("DELETE", f"/api/admin/keys/{_VICTIM}", None, {}, True),
    ("PUT", f"/api/admin/keys/{_VICTIM}/permissions", {"role": "admin"}, {}, True),
    ("POST", f"{_HTTPS}/api/admin/keys/{_VICTIM}/rotate", {}, {}, True),
    ("GET", "/api/admin/nodes", None, {}, False),
    ("DELETE", f"/api/admin/nodes/{_NODE}", None, {}, True),
    ("PUT", f"/api/admin/nodes/{_NODE}/config", {"config": {"gain": 1}}, {}, True),
    ("POST", f"/api/admin/nodes/{_NODE}/command", {"command": "restart"}, {}, True),
    ("GET", f"/api/admin/nodes/{_NODE}/diagnostics", None, {}, False),
    ("GET", "/api/admin/alerts", None, {}, False),
    ("POST", "/api/admin/alerts", {"name": "x"}, {}, True),
    ("PUT", "/api/admin/alerts/{alert}", {"severity": "critical"}, {}, True),
    ("DELETE", "/api/admin/alerts/{alert}", None, {}, True),
    ("GET", "/api/admin/audit", None, {}, False),
    ("GET", "/api/admin/audit/actions", None, {}, False),
    ("GET", "/api/admin/audit/filters", None, {}, False),
    ("GET", "/api/admin/audit/verify", None, {}, False),
    ("GET", "/api/admin/logs", None, {}, False),
    ("GET", "/api/admin/syslog", None, {}, False),
    ("POST", "/api/admin/syslog", {"host": "127.0.0.1"}, {}, True),
    ("PUT", "/api/admin/syslog/{target}", {"enabled": False}, {}, True),
    ("DELETE", "/api/admin/syslog/{target}", None, {}, True),
    ("POST", "/api/admin/syslog/{target}/test", None, {}, True),
    ("GET", "/api/admin/runtime-config", None, {}, False),
    ("PUT", "/api/admin/runtime-config/BRIDGE_LOG_LEVEL", {"value": "DEBUG"}, {}, True),
]


def _send(
    client: TestClient,
    seeded: SimpleNamespace,
    method: str,
    path: str,
    body: Any,
    headers: dict[str, str],
):
    url = path.format(alert=seeded.alert_id, target=seeded.target_id)
    kwargs: dict[str, Any] = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    return client.request(method, url, **kwargs)


# ---------------------------------------------------------------------------
# Authorization: who may call the admin routes at all
# ---------------------------------------------------------------------------


class TestAdminRoutesRefuseNonAdmins:
    @pytest.mark.parametrize(
        ("method", "path", "body", "headers"),
        [pytest.param(m, p, b, h, id=f"{m} {p}") for m, p, b, h, _ in _ENDPOINTS],
    )
    def test_analyst_is_refused_and_nothing_changes(
        self, bridge_app, persistence, seeded, method, path, body, headers
    ):
        """ANALYST is the highest non-admin role: one step below the line."""
        analyst = _client(bridge_app, _add_key(persistence, "ops-analyst", "analyst"))
        before = _state(bridge_app)
        resp = _send(analyst, seeded, method, path, body, headers)
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"] == "Admin role required"
        assert _state(bridge_app) == before

    @pytest.mark.parametrize("role", ["sensor", "node", "viewer"])
    def test_lower_roles_are_refused(self, bridge_app, persistence, seeded, role):
        raw = _add_key(persistence, f"low-{role}", role, node_id=_NODE)
        low = _client(bridge_app, raw)
        before = _state(bridge_app)
        for method, path, body, headers, mutating in _ENDPOINTS:
            if not mutating:
                continue
            resp = _send(low, seeded, method, path, body, headers)
            assert resp.status_code == 403, f"{role}: {method} {path} -> {resp.text}"
        assert _state(bridge_app) == before

    @pytest.mark.parametrize(
        "credential", ["none", "unknown-key"], ids=["no-key", "unknown-key"]
    )
    def test_unauthenticated_mutations_are_refused(
        self, bridge_app, seeded, credential
    ):
        raw = None if credential == "none" else generate_api_key(length=32)
        anon = _client(bridge_app, raw)
        before = _state(bridge_app)
        for method, path, body, headers, mutating in _ENDPOINTS:
            if not mutating and path in (
                "/api/admin/keys",
                "/api/admin/nodes",
                "/api/admin/alerts",
                "/api/admin/audit",
                "/api/admin/logs",
            ):
                continue  # 401 already covered by test_admin_endpoints.py
            resp = _send(anon, seeded, method, path, body, headers)
            assert resp.status_code == 401, f"{method} {path} -> {resp.text}"
        assert _state(bridge_app) == before

    def test_a_non_master_admin_key_is_accepted_and_attributed(
        self, bridge_app, persistence, detection_store
    ):
        """An ADMIN-role key passes the gate; the audit names that key."""
        ops = _client(bridge_app, _add_key(persistence, "ops", "admin"))
        resp = ops.post("/api/admin/keys", json={"role": "admin", "description": "d"})
        assert resp.status_code == 201, resp.text
        key_id = resp.json()["key_id"]
        assert persistence.get_key_meta()[key_id]["role"] == "admin"
        (entry,) = _audit(detection_store, "admin_create_key")
        assert entry["operator"] == "ops"
        assert entry["target_id"] == key_id


# ---------------------------------------------------------------------------
# Key management: ceilings, self-protection of the master key, lifecycles
# ---------------------------------------------------------------------------


class TestKeyRoleCeilings:
    @pytest.mark.parametrize("caller", ["master", "admin-key"])
    def test_admins_cannot_assign_the_keymaster_role(
        self, bridge_app, persistence, detection_store, client, caller
    ):
        _add_key(persistence, _VICTIM, "viewer")
        if caller == "admin-key":
            client = _client(bridge_app, _add_key(persistence, "ops", "admin"))
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions", json={"role": "KeyMaster"}
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "Only KEYMASTER can assign the keymaster role"
        assert persistence.get_key_meta()[_VICTIM]["role"] == "viewer"
        assert _audit(detection_store, "admin_update_key_permissions") == []

    def test_keymaster_may_create_and_assign_keymaster(
        self, bridge_app, persistence, detection_store
    ):
        km = _client(bridge_app, _add_key(persistence, "km", "keymaster"))
        _add_key(persistence, _VICTIM, "viewer")
        resp = km.post("/api/admin/keys", json={"role": "keymaster"})
        assert resp.status_code == 201, resp.text
        assert persistence.get_key_meta()[resp.json()["key_id"]]["role"] == "keymaster"
        resp = km.put(
            f"/api/admin/keys/{_VICTIM}/permissions", json={"role": "keymaster"}
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["role"] == "keymaster"
        assert persistence.get_key_meta()[_VICTIM]["role"] == "keymaster"
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["operator"] == "km"
        assert entry["details"] == {
            "changes": [{"key": "role", "old": "viewer", "new": "keymaster"}]
        }

    def test_another_admin_cannot_touch_the_master_key(
        self, bridge_app, persistence, master_key, detection_store
    ):
        ops = _client(bridge_app, _add_key(persistence, "ops", "admin"))
        master_cred = persistence.get_key_store()["master"]
        assert ops.delete("/api/admin/keys/master").status_code == 403
        resp = ops.put("/api/admin/keys/master/permissions", json={"role": "viewer"})
        assert resp.status_code == 403
        resp = ops.post(f"{_HTTPS}/api/admin/keys/master/rotate", json={})
        assert resp.status_code == 403
        assert "master-rotate" in resp.json()["detail"]
        assert persistence.get_key_store()["master"] == master_cred
        assert _admin_audit(detection_store) == []
        master = _client(bridge_app, master_key)
        assert master.get("/api/admin/keys").status_code == 200


class TestKeyLifecycle:
    def test_demoted_admin_loses_admin_access_on_the_next_request(
        self, bridge_app, persistence, client, detection_store
    ):
        ops = _client(bridge_app, _add_key(persistence, "ops", "admin"))
        assert ops.get("/api/admin/keys").status_code == 200  # warms the auth cache
        resp = client.put("/api/admin/keys/ops/permissions", json={"role": "viewer"})
        assert resp.status_code == 200
        assert ops.get("/api/admin/keys").status_code == 403
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [{"key": "role", "old": "admin", "new": "viewer"}]
        }

    def test_rotation_invalidates_the_old_credential(
        self, bridge_app, persistence, client, detection_store
    ):
        old_raw = _add_key(persistence, _VICTIM, "viewer")
        assert _client(bridge_app, old_raw).get("/api/health").status_code == 200
        resp = client.post(f"{_HTTPS}/api/admin/keys/{_VICTIM}/rotate", json={})
        assert resp.status_code == 200, resp.text
        new_raw = resp.json()["raw_key"]
        assert _client(bridge_app, old_raw).get("/api/health").status_code == 401
        assert _client(bridge_app, new_raw).get("/api/health").status_code == 200
        meta = persistence.get_key_meta()[_VICTIM]
        assert meta["role"] == "viewer"  # rotation keeps the role
        assert meta["rotated_at"] == resp.json()["rotated_at"]
        (entry,) = _audit(detection_store, "admin_rotate_key")
        assert entry["operator"] == "master"
        assert entry["details"] == {
            "severity": "critical",
            "deployed": False,
            "deploy_node_id": None,
        }

    def test_a_revocation_during_rotation_stays_revoked(
        self, bridge_app, persistence, client, detection_store, monkeypatch
    ):
        """The key is revoked while the new credential is being hashed."""
        from sigrift.lib.security import credentials

        old_raw = _add_key(persistence, _VICTIM, "viewer")
        # The master key's first use re-hashes it (legacy upgrade); get that
        # done before the hook so the hook sees only the rotation's hashing.
        assert client.get("/api/admin/nodes").status_code == 200
        assert "master" in persistence.get_key_fast_index().values()
        real_hash = credentials.hash_credential

        def hash_while_revoked(*args, **kwargs):
            result = real_hash(*args, **kwargs)
            if len(args) < 2 and kwargs.get("salt") is None:  # a new credential
                persistence.remove_key(_VICTIM)  # a concurrent DELETE lands here
            return result

        monkeypatch.setattr(credentials, "hash_credential", hash_while_revoked)
        resp = client.post(f"{_HTTPS}/api/admin/keys/{_VICTIM}/rotate", json={})
        assert resp.status_code == 404
        assert "raw_key" not in resp.json()
        assert _VICTIM not in persistence.get_key_store()  # not re-created
        assert _VICTIM not in persistence.get_key_meta()
        assert _client(bridge_app, old_raw).get("/api/health").status_code == 401
        assert _audit(detection_store, "admin_rotate_key") == []

    def test_revocation_is_audited_and_refusals_are_not(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, _VICTIM, "viewer")
        assert client.delete("/api/admin/keys/no-such-key").status_code == 404
        assert client.delete("/api/admin/keys/master").status_code == 403
        assert _audit(detection_store, "admin_revoke_key") == []
        resp = client.delete(f"/api/admin/keys/{_VICTIM}")
        assert resp.status_code == 200
        assert _VICTIM not in persistence.get_key_store()
        assert _VICTIM not in persistence.get_key_meta()
        assert "master" in persistence.get_key_store()
        (entry,) = _audit(detection_store, "admin_revoke_key")
        assert (entry["target_id"], entry["operator"]) == (_VICTIM, "master")

    def test_listing_never_exposes_key_material(self, persistence, client):
        raw = _add_key(persistence, _VICTIM, "viewer")
        hash_hex, salt = persistence.get_key_store()[_VICTIM]
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200
        text = resp.text
        assert raw not in text
        assert hash_hex not in text
        assert salt.hex() not in text
        for entry in resp.json():
            assert set(entry) == {
                "key_id",
                "is_master",
                "role",
                "stored_role",
                "description",
                "created_at",
                "expires_at",
                "effective_expires_at",
                "expired",
                "node_id",
            }

    def test_raw_keys_never_reach_logs_or_audit(
        self, persistence, client, detection_store, caplog
    ):
        caplog.set_level(logging.DEBUG)
        resp = client.post("/api/admin/keys", json={"role": "viewer"})
        assert resp.status_code == 201
        created = resp.json()
        resp = client.post(
            f"{_HTTPS}/api/admin/keys/{created['key_id']}/rotate", json={}
        )
        assert resp.status_code == 200
        rotated = resp.json()["raw_key"]
        audit_text = json.dumps(_audit(detection_store))
        for secret in (created["raw_key"], rotated):
            assert secret not in caplog.text
            assert secret not in audit_text
        assert created["key_id"] in audit_text

    def test_listing_reports_the_role_a_legacy_key_really_has(
        self, bridge_app, persistence, client
    ):
        raw = _add_key(persistence, "legacy", role=None)
        legacy = _client(bridge_app, raw)
        assert legacy.get("/api/health").status_code == 200
        assert legacy.get("/api/admin/keys").status_code == 403  # not an admin
        listed = {k["key_id"]: k for k in client.get("/api/admin/keys").json()}
        assert listed["master"]["role"] == "admin"
        assert listed["legacy"]["role"] == "viewer"

    @pytest.mark.parametrize(
        ("meta", "listed_role"),
        [
            ({"role": "analyst", "enabled": False}, "analyst"),
            ({"role": "admin", "revoked": True}, "admin"),
            ({"role": "sensor", "expires_at": _now_iso(3600)}, "sensor"),
            ({"role": "Admin"}, "admin"),
            ({"role": "superuser"}, "viewer"),
            ({"role": None}, "viewer"),
        ],
        ids=["disabled", "revoked", "expired", "mixed-case", "unknown", "null"],
    )
    def test_listing_reports_the_stored_role_even_for_unusable_keys(
        self, persistence, client, meta, listed_role
    ):
        """Keys that cannot authenticate are still listed, with their role."""
        _add_key(persistence, "k", role=None)
        persistence.set_key_meta("k", meta)
        listed = {k["key_id"]: k for k in client.get("/api/admin/keys").json()}
        assert listed["k"]["role"] == listed_role
        assert listed["k"]["stored_role"] == meta["role"]

    @pytest.mark.parametrize(
        "stored",
        ["superuser", "Admin", 4, ["admin"], ""],
        ids=["unknown", "mixed-case", "number", "list", "empty"],
    )
    def test_listing_shows_a_stored_role_that_is_not_a_role_name(
        self, persistence, client, stored
    ):
        """The role is normalised to what the key authenticates with; the
        value keys.json really holds stays visible next to it."""
        _add_key(persistence, "k", role=None)
        persistence.set_key_meta("k", {"role": stored})
        listed = {k["key_id"]: k for k in client.get("/api/admin/keys").json()}
        assert listed["k"]["role"] == ("admin" if stored == "Admin" else "viewer")
        assert listed["k"]["stored_role"] == stored

    def test_listing_shows_no_stored_role_for_a_legacy_key(self, persistence, client):
        _add_key(persistence, "legacy", role=None)
        _add_key(persistence, "k", role="analyst")
        listed = {k["key_id"]: k for k in client.get("/api/admin/keys").json()}
        assert (listed["legacy"]["role"], listed["legacy"]["stored_role"]) == (
            "viewer",
            None,
        )
        assert (listed["k"]["role"], listed["k"]["stored_role"]) == (
            "analyst",
            "analyst",
        )

    @pytest.mark.parametrize(
        "meta",
        [
            {},
            {"role": None},
            {"role": ""},
            {"role": "Admin"},
            {"role": " admin"},
            {"role": 4},
            {"role": ["admin"]},
            {"role": "superuser"},
            {"role": "keymaster"},
            {"role": "node"},
        ],
    )
    @pytest.mark.parametrize("key_id", ["master", "k"])
    def test_listed_role_is_the_role_authentication_resolves(self, key_id, meta):
        from sigrift.bridge.dependencies import _resolve_key_role, stored_key_role

        assert _resolve_key_role(key_id, {key_id: meta}) == (
            key_id,
            stored_key_role(key_id, meta),
        )


class TestKeyCreationInput:
    @pytest.mark.parametrize(
        "body",
        [
            {"role": "viewer", "key_id": "master"},
            {"role": "viewer", "raw_key": "chosen-by-caller"},
            {"role": "viewer", "is_master": True},
            {"role": "viewer", "expires_at": None},
        ],
        ids=["key_id", "raw_key", "is_master", "expires_at"],
    )
    def test_unknown_fields_are_refused(
        self, persistence, client, master_key, detection_store, body
    ):
        before = sorted(persistence.get_key_store())
        resp = client.post("/api/admin/keys", json=body)
        assert resp.status_code == 422
        assert sorted(persistence.get_key_store()) == before
        assert _audit(detection_store, "admin_create_key") == []

    def test_role_is_normalised_and_expiry_computed(
        self, persistence, client, detection_store
    ):
        before = datetime.now(timezone.utc)
        resp = client.post(
            "/api/admin/keys",
            json={"role": "VIEWER", "description": "d", "expires_days": 30},
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["role"] == "viewer"
        expires = datetime.fromisoformat(data["expires_at"])
        assert timedelta(days=30) - timedelta(minutes=1) <= expires - before
        assert expires - before <= timedelta(days=30, minutes=1)
        meta = persistence.get_key_meta()[data["key_id"]]
        assert meta["role"] == "viewer"
        assert meta["expires_at"] == data["expires_at"]
        assert meta["node_id"] is None
        (entry,) = _audit(detection_store, "admin_create_key")
        assert entry["details"] == {
            "description": "d",
            "role": "viewer",
            "node_id": None,
        }

    @pytest.mark.parametrize(
        "expires_days",
        [0, -1, -30, -365, 3651, 3_000_000, 10**12],
        ids=["zero", "-1", "-30", "-365", "above-max", "overflow", "huge"],
    )
    def test_an_out_of_range_expiry_is_refused(
        self, persistence, client, detection_store, expires_days
    ):
        """A typo such as -30 is refused, not taken as the default lifetime."""
        keys_before = sorted(persistence.get_key_store())
        meta_before = sorted(persistence.get_key_meta())
        resp = client.post(
            "/api/admin/keys", json={"role": "viewer", "expires_days": expires_days}
        )
        assert resp.status_code == 422
        assert "raw_key" not in resp.text
        assert sorted(persistence.get_key_store()) == keys_before
        assert sorted(persistence.get_key_meta()) == meta_before
        assert _audit(detection_store, "admin_create_key") == []

    @pytest.mark.parametrize(
        ("body", "days"),
        [
            ({}, None),
            ({"expires_days": None}, None),
            ({"expires_days": _MAX_EXPIRES_DAYS}, _MAX_EXPIRES_DAYS),
        ],
        ids=["omitted", "null", "max"],
    )
    def test_omitted_expiry_gets_the_default_lifetime_and_the_maximum_is_accepted(
        self, bridge_app, client, body, days
    ):
        # SEC-M1: no key created here is left without an expiry; the
        # longest accepted request is capped to the max lifetime.
        before = datetime.now(timezone.utc)
        resp = client.post("/api/admin/keys", json={"role": "viewer", **body})
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["expires_at"] is not None
        lifetime = min(
            days or keys_mod._MAX_KEY_LIFETIME_DAYS, keys_mod._MAX_KEY_LIFETIME_DAYS
        )
        expires = datetime.fromisoformat(data["expires_at"])
        assert abs(expires - before - timedelta(days=lifetime)) < timedelta(minutes=1)
        new_key = _client(bridge_app, data["raw_key"])
        assert new_key.get("/api/health").status_code == 200

    def test_the_admin_ui_expiry_field_has_the_apis_range(self):
        """admin.js refuses anything outside 1 to the field's max before sending."""
        import re
        from pathlib import Path

        import sigrift.bridge
        from sigrift.bridge.routers.admin import _MAX_KEY_EXPIRY_DAYS

        template = Path(sigrift.bridge.__file__).parent / "templates" / "admin.html"
        (tag,) = re.findall(
            r'<input[^>]*id="new-key-expires"[^>]*>', template.read_text()
        )
        attrs = dict(re.findall(r'([\w-]+)="([^"]*)"', tag))
        assert (attrs["type"], attrs["min"], attrs["max"]) == (
            "number",
            "1",
            str(_MAX_KEY_EXPIRY_DAYS),
        )

    @pytest.mark.parametrize(
        ("days", "expected_days"),
        [
            (None, None),  # used to be stored as never expiring
            (366, None),  # longer than the maximum lifetime: capped
            (_MAX_EXPIRES_DAYS, None),
            (7, 7),
        ],
    )
    def test_expiry_defaults_to_and_is_capped_at_the_max_lifetime(
        self, persistence, client, days, expected_days
    ):
        # SEC-M1, as on POST /api/keys/: every created key expires.
        body: dict[str, Any] = {"role": "viewer"}
        if days is not None:
            body["expires_days"] = days
        before = datetime.now(timezone.utc)
        resp = client.post("/api/admin/keys", json=body)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        expires = datetime.fromisoformat(data["expires_at"])
        lifetime = timedelta(days=expected_days or keys_mod._MAX_KEY_LIFETIME_DAYS)
        assert abs((expires - before) - lifetime) < timedelta(minutes=1)
        assert (
            persistence.get_key_meta()[data["key_id"]]["expires_at"]
            == (data["expires_at"])
        )

    def test_a_huge_configured_maximum_falls_back_to_the_ceiling(
        self, client, monkeypatch
    ):
        # timedelta(days=10**9) overflows: the absolute ceiling applies.
        monkeypatch.setattr(keys_mod, "_MAX_KEY_LIFETIME_DAYS", 10**9)
        for body, hours in [
            ({}, MAX_KEY_EXPIRES_IN_HOURS),
            ({"expires_days": _MAX_EXPIRES_DAYS}, _MAX_EXPIRES_DAYS * 24),
        ]:
            before = datetime.now(timezone.utc)
            resp = client.post("/api/admin/keys", json={"role": "viewer", **body})
            assert resp.status_code == 201, resp.text
            expires = datetime.fromisoformat(resp.json()["expires_at"])
            assert abs((expires - before) - timedelta(hours=hours)) < timedelta(
                minutes=1
            )

    # Raw JSON text: the server's json.loads accepts bare NaN / Infinity.
    @pytest.mark.parametrize(
        ("days", "message"),
        [
            ("0", "greater than or equal to"),  # never taken as the default
            ("-3", "greater than or equal to"),
            (f"{_MAX_EXPIRES_DAYS + 1}", "less than or equal to"),
            ("416667", "less than or equal to"),  # past the hours ceiling too
            ("3000000", "less than or equal to"),  # used to overflow: a 500
            ("1000000000", "less than or equal to"),  # ditto
            ("1e9", "less than or equal to"),
            ("7.5", "valid integer"),
            ("Infinity", "finite number"),
            ("-Infinity", "finite number"),
            ("NaN", "finite number"),
        ],
    )
    def test_an_out_of_range_or_non_finite_expiry_is_refused(
        self, bridge_app, master_key, persistence, detection_store, days, message
    ):
        client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "Content-Type": "application/json"},
            raise_server_exceptions=False,
        )
        before = sorted(persistence.get_key_store())
        resp = client.post(
            "/api/admin/keys", content=f'{{"role": "viewer", "expires_days": {days}}}'
        )
        assert resp.status_code == 422, resp.text
        (error,) = resp.json()["detail"]
        assert error["loc"] == ["body", "expires_days"]
        assert message in error["msg"]
        assert sorted(persistence.get_key_store()) == before
        assert _audit(detection_store, "admin_create_key") == []

    @pytest.mark.parametrize(
        ("body", "loc", "echoed"),
        [
            ('{"role": NaN}', ["body", "role"], "NaN"),
            ('{"description": Infinity}', ["body", "description"], "Infinity"),
            ('{"node_id": -Infinity}', ["body", "node_id"], "-Infinity"),
            ('{"surplus": NaN}', ["body", "surplus"], "NaN"),
            ('{"expires_days": [NaN]}', ["body", "expires_days"], ["NaN"]),
        ],
    )
    def test_a_non_finite_number_anywhere_is_a_422_not_a_500(
        self, bridge_app, master_key, persistence, detection_store, body, loc, echoed
    ):
        # The 422 echoes the rejected input, which used to fail to encode.
        client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "Content-Type": "application/json"},
            raise_server_exceptions=False,
        )
        before = sorted(persistence.get_key_store())
        resp = client.post("/api/admin/keys", content=body)
        assert resp.status_code == 422, resp.text
        (error,) = resp.json()["detail"]
        assert error["loc"] == loc
        assert error["input"] == echoed
        assert sorted(persistence.get_key_store()) == before
        assert _audit(detection_store, "admin_create_key") == []

    def test_an_id_collision_never_replaces_the_existing_key(
        self, bridge_app, persistence, client, monkeypatch
    ):
        """A concurrent creator takes the drawn id: a new id is drawn."""
        real_add = persistence.async_add_key
        attempts: list[str] = []
        squatter: dict[str, str] = {}

        async def racing_add(key_id, *args, **kwargs):
            attempts.append(key_id)
            if len(attempts) == 1:
                squatter[key_id] = _add_key(persistence, key_id, "viewer")
            return await real_add(key_id, *args, **kwargs)

        monkeypatch.setattr(persistence, "async_add_key", racing_add)
        resp = client.post("/api/admin/keys", json={"role": "admin"})
        assert resp.status_code == 201, resp.text
        assert len(attempts) == 2
        taken, created = attempts
        assert resp.json()["key_id"] == created != taken
        # The squatter's credential and role are untouched ...
        assert persistence.get_key_meta()[taken]["role"] == "viewer"
        squat = _client(bridge_app, squatter[taken])
        assert squat.get("/api/health").status_code == 200
        assert squat.get("/api/admin/keys").status_code == 403
        # ... and the new credential belongs to the new id only.
        new = _client(bridge_app, resp.json()["raw_key"])
        assert new.get("/api/admin/keys").status_code == 200

    def test_creation_gives_up_after_repeated_collisions(
        self, bridge_app, persistence, client, detection_store, monkeypatch
    ):
        """Every drawn id is taken: 500, and the holder of that id is unharmed."""
        import uuid

        squatter_raw = _add_key(persistence, "key_deadbeef", "viewer")
        squatter_cred = persistence.get_key_store()["key_deadbeef"]
        before = sorted(persistence.get_key_store())
        fixed = uuid.UUID("deadbeef" + "0" * 24)
        monkeypatch.setattr(uuid, "uuid4", lambda: fixed)
        resp = client.post("/api/admin/keys", json={"role": "admin"})
        assert resp.status_code == 500
        assert resp.json()["detail"] == "Could not allocate a unique key ID"
        assert "raw_key" not in resp.json()
        assert sorted(persistence.get_key_store()) == before
        assert persistence.get_key_store()["key_deadbeef"] == squatter_cred
        assert persistence.get_key_meta()["key_deadbeef"]["role"] == "viewer"
        squat = _client(bridge_app, squatter_raw)
        assert squat.get("/api/admin/keys").status_code == 403  # still a viewer
        assert _audit(detection_store, "admin_create_key") == []


class TestKeyPermissionUpdates:
    def test_invalid_role_with_valid_node_changes_nothing(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, _VICTIM, "sensor")
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions",
            json={"role": "root", "node_id": "edge-5"},
        )
        assert resp.status_code == 400
        meta = persistence.get_key_meta()[_VICTIM]
        assert meta["role"] == "sensor"
        assert "node_id" not in meta
        assert _audit(detection_store, "admin_update_key_permissions") == []

    def test_role_and_binding_changes_are_diffed_in_the_audit(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, _VICTIM, "sensor", node_id="edge-4")
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions",
            json={"role": "Node", "node_id": "edge-5"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {
            "status": "ok",
            "key_id": _VICTIM,
            "role": "node",
            "node_id": "edge-5",
        }
        meta = persistence.get_key_meta()[_VICTIM]
        assert (meta["role"], meta["node_id"]) == ("node", "edge-5")
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [
                {"key": "role", "old": "sensor", "new": "node"},
                {"key": "node_id", "old": "edge-4", "new": "edge-5"},
            ]
        }

    def test_an_empty_node_id_unbinds_and_a_no_op_is_still_audited(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, _VICTIM, "sensor", node_id="edge-4")
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions", json={"node_id": ""}
        )
        assert resp.status_code == 200
        assert resp.json()["node_id"] is None
        assert "node_id" not in persistence.get_key_meta()[_VICTIM]
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions",
            json={"role": "sensor", "permissions": ["read"]},
        )
        assert resp.status_code == 200
        unbind, no_op = sorted(
            _audit(detection_store, "admin_update_key_permissions"),
            key=lambda e: e["id"],
        )
        assert unbind["details"] == {
            "changes": [{"key": "node_id", "old": "edge-4", "new": None}]
        }
        assert no_op["details"] == {"role": "sensor", "permissions": ["read"]}

    def test_a_key_revoked_after_the_checks_is_404(
        self, persistence, client, detection_store, monkeypatch
    ):
        _add_key(persistence, _VICTIM, "sensor")
        real_update = persistence.async_update_key_access

        async def revoked_then_update(key_id, **kwargs):
            await persistence.async_remove_key(key_id)  # a concurrent DELETE
            return await real_update(key_id, **kwargs)

        monkeypatch.setattr(persistence, "async_update_key_access", revoked_then_update)
        resp = client.put(
            f"/api/admin/keys/{_VICTIM}/permissions",
            json={"role": "node", "node_id": "edge-5"},
        )
        assert resp.status_code == 404
        # Neither the role nor the binding resurrects the revoked key.
        assert _VICTIM not in persistence.get_key_store()
        assert _VICTIM not in persistence.get_key_meta()
        assert _audit(detection_store, "admin_update_key_permissions") == []

    @pytest.mark.parametrize(
        "body",
        [{"role": "viewer", "is_master": True}, {"key_id": "master"}],
        ids=["is_master", "key_id"],
    )
    def test_unknown_fields_are_refused(self, persistence, client, body):
        _add_key(persistence, _VICTIM, "viewer")
        before = persistence.get_key_meta()
        resp = client.put(f"/api/admin/keys/{_VICTIM}/permissions", json=body)
        assert resp.status_code == 422
        assert persistence.get_key_meta() == before

    def test_promoting_a_legacy_key_is_audited_as_a_change(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, "legacy", role=None)
        resp = client.put(
            "/api/admin/keys/legacy/permissions", json={"role": "analyst"}
        )
        assert resp.status_code == 200
        assert persistence.get_key_meta()["legacy"]["role"] == "analyst"
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [{"key": "role", "old": "viewer", "new": "analyst"}]
        }

    @pytest.mark.parametrize(
        ("stored", "assigned"),
        [(None, "viewer"), ("viewer", "viewer"), ("analyst", "analyst")],
        ids=["legacy-as-viewer", "viewer", "analyst"],
    )
    def test_assigning_the_role_a_key_already_has_is_not_a_change(
        self, persistence, client, detection_store, stored, assigned
    ):
        _add_key(persistence, "k", role=None)
        if stored is not None:
            persistence.set_key_meta("k", {"role": stored})
        resp = client.put("/api/admin/keys/k/permissions", json={"role": assigned})
        assert resp.status_code == 200
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {"role": assigned, "permissions": []}

    @pytest.mark.parametrize(
        ("stored", "assigned", "changes"),
        [
            ("Admin", "admin", []),
            ("superuser", "viewer", []),
            (4, "viewer", []),
            (["admin"], "viewer", []),
            (
                "superuser",
                "analyst",
                [{"key": "role", "old": "viewer", "new": "analyst"}],
            ),
        ],
        ids=["mixed-case", "unknown-as-viewer", "number", "list", "unknown-promoted"],
    )
    def test_rewriting_a_stored_role_that_is_not_a_role_name_is_audited(
        self, persistence, client, detection_store, stored, assigned, changes
    ):
        """The key authenticates the same, but keys.json's value changes: the
        audit records the value that was there."""
        _add_key(persistence, "k", role=None)
        persistence.set_key_meta("k", {"role": stored})
        resp = client.put("/api/admin/keys/k/permissions", json={"role": assigned})
        assert resp.status_code == 200
        assert persistence.get_key_meta()["k"]["role"] == assigned
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [
                *changes,
                {"key": "stored_role", "old": stored, "new": assigned},
            ]
        }

    def test_a_binding_change_alone_does_not_audit_the_stored_role(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, "k", role=None)
        persistence.set_key_meta("k", {"role": "superuser"})
        resp = client.put("/api/admin/keys/k/permissions", json={"node_id": _NODE})
        assert resp.status_code == 200
        assert persistence.get_key_meta()["k"]["role"] == "superuser"
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [{"key": "node_id", "old": None, "new": _NODE}]
        }

    def test_role_and_binding_changes_are_diffed_role_first(
        self, persistence, client, detection_store
    ):
        _add_key(persistence, "legacy", role=None)
        resp = client.put(
            "/api/admin/keys/legacy/permissions",
            json={"role": "sensor", "node_id": _NODE},
        )
        assert resp.status_code == 200
        (entry,) = _audit(detection_store, "admin_update_key_permissions")
        assert entry["details"] == {
            "changes": [
                {"key": "role", "old": "viewer", "new": "sensor"},
                {"key": "node_id", "old": None, "new": _NODE},
            ]
        }


# ---------------------------------------------------------------------------
# Key rotation: SSH deployment guards
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes) -> None:
        self.returncode = returncode
        self._result = (stdout, stderr)

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._result


_REMOTE_TMP = "/tmp/mlrf_key_AbCdEfGh12"
_OK_STEPS = [(0, _REMOTE_TMP.encode() + b"\n", b""), (0, b"", b""), (0, b"", b"")]


@pytest.fixture
def fake_ssh(monkeypatch) -> SimpleNamespace:
    """Script ssh/scp results; record argv and the local key temp files."""
    state = SimpleNamespace(calls=[], steps=[], temp_files=[])

    async def fake_exec(*args: Any, **kwargs: Any) -> _FakeProc:
        state.calls.append([str(a) for a in args])
        return _FakeProc(*state.steps.pop(0))

    real_ntf = tempfile.NamedTemporaryFile

    def spy_ntf(*args: Any, **kwargs: Any):
        handle = real_ntf(*args, **kwargs)
        if os.path.basename(handle.name).startswith("mlrf_key_"):
            state.temp_files.append(handle.name)
        return handle

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", spy_ntf)
    return state


_PROXY_SECRET = "rotation-tls-test-proxy-secret-0123456789abcdef"


class TestRotationTLS:
    """X-Forwarded-Proto counts only from the gateway or a trusted proxy.

    Before, the TLS check read X-Forwarded-Proto from any client, and the
    middleware set the request scheme from it whenever X-Forwarded-Host
    was present, so a direct plaintext client could get a rotated raw key
    sent back in clear text by claiming https.
    """

    @pytest.mark.parametrize(
        "headers",
        [
            {"X-Forwarded-Proto": "https"},
            {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "bridge.example:443"},
            {"X-Forwarded-Proto": "HTTPS", "X-Forwarded-Host": "bridge.example"},
        ],
        ids=["proto", "proto-and-host", "upper-case"],
    )
    def test_a_direct_client_cannot_claim_tls(
        self, persistence, client, detection_store, headers
    ):
        _add_key(persistence, _VICTIM, "viewer")
        cred = persistence.get_key_store()[_VICTIM]
        resp = client.post(
            f"/api/admin/keys/{_VICTIM}/rotate", json={}, headers=headers
        )
        assert resp.status_code == 403
        assert "TLS" in resp.json()["detail"]
        assert "raw_key" not in resp.text
        assert persistence.get_key_store()[_VICTIM] == cred
        assert not _audit(detection_store, "admin_rotate_key")

    def test_a_direct_tls_connection_is_accepted(self, persistence, client):
        _add_key(persistence, _VICTIM, "viewer")
        resp = client.post(f"{_HTTPS}/api/admin/keys/{_VICTIM}/rotate", json={})
        assert resp.status_code == 200, resp.text

    @pytest.mark.parametrize(
        ("proto", "accepted"),
        [
            ("https", True),
            ("HTTPS", True),
            (" https ", True),
            ("http", False),
            ("ftp", False),
            ("", False),
        ],
    )
    def test_the_gateway_vouches_for_tls(
        self, persistence, bridge_app, master_key, monkeypatch, proto, accepted
    ):
        monkeypatch.setenv("UC_PROXY_SECRET", _PROXY_SECRET)
        _add_key(persistence, _VICTIM, "viewer")
        gateway = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "X-Rust-Proxy": _PROXY_SECRET},
        )
        resp = gateway.post(
            f"/api/admin/keys/{_VICTIM}/rotate",
            json={},
            headers={"X-Forwarded-Proto": proto, "X-Forwarded-Host": "bridge.example"},
        )
        assert (resp.status_code == 200) is accepted, resp.text

    def test_a_wrong_proxy_secret_does_not_vouch(
        self, persistence, bridge_app, master_key, monkeypatch
    ):
        monkeypatch.setenv("UC_PROXY_SECRET", _PROXY_SECRET)
        _add_key(persistence, _VICTIM, "viewer")
        spoof = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key, "X-Rust-Proxy": _PROXY_SECRET[:-1] + "x"},
        )
        resp = spoof.post(
            f"/api/admin/keys/{_VICTIM}/rotate",
            json={},
            headers={
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Host": "bridge.example",
            },
        )
        assert resp.status_code == 403

    @pytest.mark.parametrize(
        ("peer", "accepted"),
        [("127.0.0.1", True), ("::1", True), ("203.0.113.9", False)],
    )
    def test_a_trusted_proxy_peer_vouches_for_tls(
        self, persistence, bridge_app, master_key, peer, accepted
    ):
        # nginx in front of the bridge (DEPLOYMENT.md): loopback is always a
        # trusted proxy, any other peer only when listed in BRIDGE_TRUSTED_PROXIES.
        _add_key(persistence, _VICTIM, "viewer")
        proxied = TestClient(
            bridge_app, headers={"X-API-Key": master_key}, client=(peer, 40000)
        )
        resp = proxied.post(
            f"/api/admin/keys/{_VICTIM}/rotate",
            json={},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert (resp.status_code == 200) is accepted, resp.text


def _rotate_and_deploy(client: TestClient, key_id: str, **body: Any):
    return client.post(
        f"{_HTTPS}/api/admin/keys/{key_id}/rotate",
        json={"deploy_to_node": True, **body},
    )


class TestRotationDeployment:
    def test_key_named_after_its_node_is_deployed_with_the_chosen_user(
        self, persistence, client, detection_store, fake_ssh
    ):
        _add_key(persistence, "edge-9", "node")  # no node_id: legacy naming
        _add_node(persistence, "edge-9", host="10.0.0.9")
        fake_ssh.steps.extend(_OK_STEPS)
        resp = _rotate_and_deploy(client, "edge-9", ssh_user="deploy_user")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["deployed"] is True
        assert (data["deploy_host"], data["deploy_node_id"]) == ("10.0.0.9", "edge-9")
        assert "deploy_error" not in data
        mktemp, scp, apply = fake_ssh.calls
        assert mktemp[0] == "ssh" and "deploy_user@10.0.0.9" in mktemp
        assert scp[0] == "scp" and scp[-1] == f"deploy_user@10.0.0.9:{_REMOTE_TMP}"
        assert apply[0] == "ssh" and _REMOTE_TMP in apply[-1]
        for argv in fake_ssh.calls:
            assert data["raw_key"] not in " ".join(argv)
        (local_tmp,) = fake_ssh.temp_files
        assert not os.path.exists(local_tmp)
        (entry,) = _audit(detection_store, "admin_rotate_key")
        assert entry["details"] == {
            "severity": "critical",
            "deployed": True,
            "deploy_node_id": "edge-9",
        }

    def test_a_key_without_a_node_is_rotated_but_not_deployed(
        self, persistence, client, fake_ssh
    ):
        old_cred = (_add_key(persistence, _VICTIM, "viewer"),)
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200
        data = resp.json()
        assert data["deployed"] is False
        assert data["deploy_error"] == "No node_id associated with this key"
        assert data["raw_key"] not in old_cred
        assert fake_ssh.calls == []

    def test_a_node_without_a_host_is_not_contacted(
        self, persistence, client, fake_ssh
    ):
        _add_key(persistence, _VICTIM, "node", node_id="ghost-node")
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200
        assert resp.json()["deploy_error"] == "Node 'ghost-node' has no host address"
        assert fake_ssh.calls == []

    @pytest.mark.parametrize("host", [5, ["10.0.0.5"], {"ip": "10.0.0.5"}])
    def test_a_saved_host_that_is_not_text_is_not_contacted(
        self, persistence, client, fake_ssh, host
    ):
        # A record saved before heartbeat metrics were checked: the key is
        # rotated and returned, and the deploy reports the missing host.
        old = _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host=host)
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["deploy_error"] == "Node 'edge-7' has no host address"
        assert data["raw_key"] and data["raw_key"] != old
        assert fake_ssh.calls == []

    @pytest.mark.parametrize(
        "host",
        [
            "10.0.0.5;reboot",
            "$(id)",
            "`id`",
            "a b",
            "h|nc evil 1",
            "-oProxyCommand=x",
            "10.0.0.5\n",  # '$' with re.match also matches before a final \n
        ],
    )
    def test_a_host_with_shell_metacharacters_is_refused(
        self, persistence, client, fake_ssh, host
    ):
        _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host=host)
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200
        data = resp.json()
        assert data["deployed"] is False
        assert data["deploy_error"] == f"Invalid host address: {host!r}"
        assert fake_ssh.calls == []

    @pytest.mark.parametrize("user", ["pi\n", "pi;id", "a" * 33, ""])
    def test_the_ssh_user_is_rechecked_before_any_ssh(
        self, persistence, bridge_app, fake_ssh, user
    ):
        """Defence in depth: the deploy step checks the user itself.

        RotateKeyRequest's pattern already refuses these (a 422), so the
        handler is called with a model built past validation. 'pi\\n' is the
        case a '$'-anchored re.match would let through.
        """
        from starlette.requests import Request

        from sigrift.bridge.dependencies import Role
        from sigrift.bridge.routers import admin as admin_router

        _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host="10.0.0.7")
        request = Request(
            {
                "type": "http",
                "app": bridge_app,
                "scheme": "https",
                "server": ("testserver", 443),
                "method": "POST",
                "path": f"/api/admin/keys/{_VICTIM}/rotate",
                "headers": [],
                "query_string": b"",
            }
        )
        request.state.key_role = Role.KEYMASTER
        body = admin_router.RotateKeyRequest.model_construct(
            deploy_to_node=True, ssh_user=user
        )
        result = asyncio.run(
            admin_router.rotate_key(_VICTIM, body, request, _master="master")
        )
        assert result["deployed"] is False
        assert result["deploy_error"] == f"Invalid SSH user: {user!r}"
        assert fake_ssh.calls == []

    def test_an_ssh_user_with_a_trailing_newline_is_a_422(
        self, persistence, client, fake_ssh
    ):
        _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host="10.0.0.7")
        resp = _rotate_and_deploy(client, _VICTIM, ssh_user="pi\n")
        assert resp.status_code == 422
        assert fake_ssh.calls == []

    @pytest.mark.parametrize(
        "remote_tmp",
        [
            b"/tmp/mlrf_key_AbCdEfGh12; rm -rf /",
            b"/etc/systemd/system/rf-edge.service",
            b"/tmp/mlrf_key_$(id)xxxxx",
            b"",
        ],
        ids=["chained", "other-path", "subst", "empty"],
    )
    def test_an_unexpected_remote_temp_path_stops_the_deploy(
        self, persistence, client, fake_ssh, remote_tmp
    ):
        _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host="10.0.0.7")
        fake_ssh.steps.append((0, remote_tmp, b""))
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200
        data = resp.json()
        assert data["deployed"] is False
        assert data["deploy_error"].startswith("Unexpected remote temp path")
        assert len(fake_ssh.calls) == 1  # mktemp only: no scp, no apply
        (local_tmp,) = fake_ssh.temp_files
        assert not os.path.exists(local_tmp)

    @pytest.mark.parametrize(
        ("failing_step", "stderr", "expected"),
        [
            (0, b"", "Failed to create temp file on remote node"),
            (1, b"", "SCP transfer failed"),
            (2, b"", "SSH command failed"),
            (2, b"sudo: a password is required\n", "sudo: a password is required"),
        ],
        ids=["mktemp", "scp", "apply", "apply-stderr"],
    )
    def test_a_failing_step_is_reported_and_stops_the_deploy(
        self,
        persistence,
        client,
        detection_store,
        fake_ssh,
        failing_step,
        stderr,
        expected,
    ):
        _add_key(persistence, _VICTIM, "node", node_id="edge-7")
        _add_node(persistence, "edge-7", host="10.0.0.7")
        steps = list(_OK_STEPS[:failing_step]) + [(1, b"", stderr)]
        fake_ssh.steps.extend(steps)
        resp = _rotate_and_deploy(client, _VICTIM)
        assert resp.status_code == 200
        data = resp.json()
        assert data["deployed"] is False
        assert data["deploy_error"] == expected
        assert len(fake_ssh.calls) == failing_step + 1
        (local_tmp,) = fake_ssh.temp_files
        assert not os.path.exists(local_tmp)
        (entry,) = _audit(detection_store, "admin_rotate_key")
        assert entry["details"]["deployed"] is False

    def test_unknown_rotate_fields_are_refused(self, persistence, client):
        _add_key(persistence, _VICTIM, "viewer")
        cred = persistence.get_key_store()[_VICTIM]
        resp = client.post(
            f"{_HTTPS}/api/admin/keys/{_VICTIM}/rotate",
            json={"deploy_to_node": False, "ssh_host": "evil.example"},
        )
        assert resp.status_code == 422
        assert persistence.get_key_store()[_VICTIM] == cred


# ---------------------------------------------------------------------------
# End-to-end: an admin action, then its effect on the affected credential
# ---------------------------------------------------------------------------


def _login(app: FastAPI, store: Any, username: str, role: str) -> TestClient:
    password = "Adm1n-Pass-Word!"
    store.create_user(username=username, password=password, role=role)
    resp = TestClient(app).post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["session_token"]
    return TestClient(app, headers={"Authorization": f"Bearer {token}"})


class TestEndToEndFlows:
    def test_a_key_follows_what_the_admin_does_to_it(
        self, bridge_app, client, persistence, detection_store
    ):
        resp = client.post(
            "/api/admin/keys", json={"role": "viewer", "description": "x"}
        )
        assert resp.status_code == 201
        holder_id, raw = resp.json()["key_id"], resp.json()["raw_key"]
        holder = _client(bridge_app, raw)
        assert holder.get("/api/health").status_code == 200
        assert holder.get("/api/admin/keys").status_code == 403

        resp = client.put(
            f"/api/admin/keys/{holder_id}/permissions", json={"role": "admin"}
        )
        assert resp.status_code == 200
        listed = {k["key_id"]: k for k in holder.get("/api/admin/keys").json()}
        assert listed[holder_id]["role"] == "admin"
        resp = holder.post("/api/admin/keys", json={"role": "viewer"})
        assert resp.status_code == 201
        created = [e for e in _audit(detection_store, "admin_create_key")]
        assert {e["operator"] for e in created} == {"master", holder_id}

        assert client.delete(f"/api/admin/keys/{holder_id}").status_code == 200
        assert holder.get("/api/health").status_code == 401
        assert holder.get("/api/admin/keys").status_code == 401

    def test_an_admin_users_session_follows_the_account(
        self, bridge_app, client, persistence, detection_store
    ):
        alice = _login(bridge_app, detection_store, "alice", "admin")
        resp = alice.post("/api/admin/keys", json={"role": "viewer"})
        assert resp.status_code == 201, resp.text
        (entry,) = _audit(detection_store, "admin_create_key")
        assert entry["operator"] == "user:alice"
        # The role ceiling applies to sessions as to keys.
        resp = alice.post("/api/admin/keys", json={"role": "keymaster"})
        assert resp.status_code == 403
        assert len(persistence.get_key_store()) == 2  # master + alice's key

        # Demoted: the same session loses the admin routes at once.
        resp = client.put("/api/admin/users/alice", json={"role": "viewer"})
        assert resp.status_code == 200, resp.text
        assert alice.get("/api/admin/keys").status_code == 403
        assert alice.get("/api/health").status_code == 200
        # Disabled: the session ends.
        assert client.delete("/api/admin/users/alice").status_code == 200
        assert alice.get("/api/health").status_code == 401
        assert alice.get("/api/admin/keys").status_code == 401

    def test_a_node_collects_what_an_admin_queued_for_it(
        self, bridge_app, client, app_state
    ):
        raw: dict[str, str] = {}
        for node in ("edge-7", "edge-8"):
            resp = client.post(
                "/api/nodes/register", json={"node_id": node, "host": "10.0.0.7"}
            )
            assert resp.status_code == 200, resp.text
            resp = client.post(
                "/api/admin/keys", json={"role": "node", "node_id": node}
            )
            assert resp.status_code == 201, resp.text
            raw[node] = resp.json()["raw_key"]
        url = "/api/admin/nodes/edge-7"
        assert (
            client.put(f"{url}/config", json={"config": {"gain": 30}}).status_code
            == 200
        )
        assert (
            client.post(f"{url}/command", json={"command": "restart"}).status_code
            == 200
        )

        anon = TestClient(bridge_app)

        def heartbeat(key: str, node_id: str):
            return anon.post(
                "/api/nodes/heartbeat",
                json={"node_id": node_id},
                headers={"X-API-Key": key},
            )

        # Another node's key cannot collect edge-7's commands.
        assert heartbeat(raw["edge-8"], "edge-7").status_code == 403
        assert len(app_state.pending_commands["edge-7"]) == 2
        resp = heartbeat(raw["edge-7"], "edge-7")
        assert resp.status_code == 200, resp.text
        handed = [(c["command"], c["params"]) for c in resp.json()["pending_commands"]]
        assert handed == [("update_config", {"gain": 30}), ("restart", {})]
        assert heartbeat(raw["edge-7"], "edge-7").json()["pending_commands"] == []


# ---------------------------------------------------------------------------
# Node management
# ---------------------------------------------------------------------------


class TestNodeManagement:
    def test_deregistration_is_audited_and_refusals_are_not(
        self, persistence, client, detection_store
    ):
        _add_node(persistence)
        assert client.delete("/api/admin/nodes/no-such-node").status_code == 404
        assert _audit(detection_store, "admin_deregister_node") == []
        assert client.delete(f"/api/admin/nodes/{_NODE}").status_code == 200
        assert _NODE not in persistence.get_nodes()
        (entry,) = _audit(detection_store, "admin_deregister_node")
        assert (entry["target_id"], entry["operator"]) == (_NODE, "master")

    def test_config_and_commands_queue_in_order_and_are_audited(
        self, persistence, client, app_state, detection_store
    ):
        _add_node(persistence)
        url = f"/api/admin/nodes/{_NODE}"
        assert (
            client.put(f"{url}/config", json={"config": {"gain": 30}}).status_code
            == 200
        )
        assert (
            client.put(f"{url}/config", json={"config": {"gain": 40}}).status_code
            == 200
        )
        assert (
            client.post(f"{url}/command", json={"command": "restart"}).status_code
            == 200
        )
        resp = client.post(
            f"{url}/command", json={"command": "status", "params": {"verbose": True}}
        )
        assert resp.json() == {
            "status": "queued",
            "node_id": _NODE,
            "command": "status",
        }
        queued = app_state.pending_commands[_NODE]
        assert [(c["command"], c["params"]) for c in queued] == [
            ("update_config", {"gain": 30}),
            ("update_config", {"gain": 40}),
            ("restart", {}),
            ("status", {"verbose": True}),
        ]
        configs = _audit(detection_store, "admin_update_node_config")
        assert sorted(e["details"]["config"]["gain"] for e in configs) == [30, 40]
        commands = _audit(detection_store, "admin_queue_command")
        assert sorted(e["details"]["command"] for e in commands) == [
            "restart",
            "status",
        ]

    @pytest.mark.parametrize(
        "body",
        [{"params": {}}, {"command": "restart", "node_id": "other"}],
        ids=["missing-command", "unknown-field"],
    )
    def test_malformed_commands_queue_nothing(
        self, persistence, client, app_state, body
    ):
        _add_node(persistence)
        resp = client.post(f"/api/admin/nodes/{_NODE}/command", json=body)
        assert resp.status_code == 422
        assert _NODE not in app_state.pending_commands

    @pytest.mark.parametrize(
        ("method", "suffix", "body"),
        [
            ("POST", "command", {"command": "restart"}),
            ("PUT", "config", {"config": {"gain": 1}}),
        ],
        ids=["command", "config"],
    )
    def test_commands_for_an_unregistered_node_are_refused(
        self, client, app_state, detection_store, method, suffix, body
    ):
        resp = client.request(method, f"/api/admin/nodes/ghost/{suffix}", json=body)
        assert resp.status_code == 404
        assert resp.json()["detail"] == "Node 'ghost' not found"
        assert "ghost" not in app_state.pending_commands
        assert _admin_audit(detection_store) == []

    def test_the_per_node_command_queue_stays_bounded(
        self, persistence, client, app_state
    ):
        from sigrift.bridge.dependencies import Role
        from sigrift.bridge.routers.nodes import command_queue_limit

        limit = command_queue_limit(Role.ADMIN)
        _add_node(persistence)
        app_state.pending_commands[_NODE] = [
            {"command": "ping", "params": {}} for _ in range(limit)
        ]
        resp = client.post(
            f"/api/admin/nodes/{_NODE}/command", json={"command": "ping"}
        )
        assert resp.status_code == 429
        assert len(app_state.pending_commands[_NODE]) == limit

    @pytest.mark.parametrize(
        ("method", "suffix", "body"),
        [
            ("POST", "command", {"command": "ping"}),
            ("PUT", "config", {"config": {"gain": 1}}),
        ],
        ids=["command", "config"],
    )
    def test_a_full_queue_is_refused_like_the_node_router_and_not_audited(
        self, persistence, client, app_state, detection_store, method, suffix, body
    ):
        from sigrift.bridge.dependencies import Role
        from sigrift.bridge.routers.nodes import command_queue_limit

        limit = command_queue_limit(Role.ADMIN)
        _add_node(persistence)
        full = [{"command": "ping", "params": {}} for _ in range(limit)]
        app_state.pending_commands[_NODE] = copy.deepcopy(full)
        node_router = client.post(
            f"/api/nodes/{_NODE}/command", json={"command": "ping"}
        )
        assert node_router.status_code == 429
        resp = client.request(method, f"/api/admin/nodes/{_NODE}/{suffix}", json=body)
        assert resp.status_code == 429
        assert resp.json()["detail"] == node_router.json()["detail"]
        assert app_state.pending_commands[_NODE] == full
        assert _admin_audit(detection_store) == []

    @pytest.mark.parametrize(
        "command",
        [
            "restart_scanner",
            "run_diagnostics",
            "restart_sdr",
            "iq_capture",
            # No edge component handles these: the agent logged "Ignoring
            # unhandled command" while the bridge reported them queued and
            # then dispatched.
            "capture_start",
            "capture_stop",
            "rm -rf /",
            # The agent's dispatcher matches names exactly, so a case or
            # whitespace variant of an allowlisted name would be queued and
            # then dropped on the node just the same.
            "PING",
            "Restart",
            " ping",
            "ping ",
            "status\n",
        ],
    )
    def test_a_command_outside_the_allowlist_is_refused(
        self, persistence, client, app_state, detection_store, command
    ):
        """Same allowlist as POST /api/nodes/{id}/command: the node ignores others."""
        _add_node(persistence)
        resp = client.post(
            f"/api/admin/nodes/{_NODE}/command", json={"command": command}
        )
        assert resp.status_code == 422
        node_router = client.post(
            f"/api/nodes/{_NODE}/command", json={"command": command}
        )
        assert node_router.status_code == 422
        assert _NODE not in app_state.pending_commands
        assert _admin_audit(detection_store) == []

    def test_every_allowlisted_command_is_queued(self, persistence, client, app_state):
        from sigrift.lib.shiny.models import ALLOWED_COMMANDS

        _add_node(persistence)
        for command in sorted(ALLOWED_COMMANDS):
            resp = client.post(
                f"/api/admin/nodes/{_NODE}/command", json={"command": command}
            )
            assert resp.status_code == 200, (command, resp.text)
        queued = [c["command"] for c in app_state.pending_commands[_NODE]]
        assert queued == sorted(ALLOWED_COMMANDS)

    def test_every_allowlisted_command_has_an_edge_agent_handler(
        self, monkeypatch, caplog
    ):
        """The allowlist exists to refuse names the node cannot act on.

        A name the edge agent's ``_dispatch_command`` falls through on is
        queued, reported as queued and then dispatched, and silently
        dropped on the node, so it must not be in ``ALLOWED_COMMANDS``.
        """
        from sigrift.edge import node_agent, scanner_config
        from sigrift.lib.shiny.models import ALLOWED_COMMANDS

        handled: list[str] = []

        def _record(name):
            def _handler(*_args, **_kwargs):
                handled.append(name)
                return "/dev/null"

            return _handler

        monkeypatch.setattr(node_agent, "_handle_update", _record("update"))
        monkeypatch.setattr(node_agent, "_handle_restart", _record("restart"))
        monkeypatch.setattr(scanner_config, "write_config", _record("update_config"))
        monkeypatch.setattr(node_agent.urllib.request, "urlopen", _record("urlopen"))

        def _ignored(command: str) -> bool:
            caplog.clear()
            with caplog.at_level(logging.DEBUG, logger=node_agent.logger.name):
                node_agent._dispatch_command(
                    {"command": command, "command_id": "c-1", "params": {}}
                )
            return any(
                r.getMessage() == f"Ignoring unhandled command: {command}"
                for r in caplog.records
            )

        # The fall-through is detectable, so a pass below means something.
        assert _ignored("no_such_command")
        assert handled == []

        unhandled = sorted(c for c in ALLOWED_COMMANDS if _ignored(c))
        assert unhandled == []

    def test_the_api_reference_lists_exactly_the_allowlisted_commands(self):
        """The hand-written command list must not drift from ALLOWED_COMMANDS.

        Otherwise the reference advertises a name that gets a 422, or
        leaves out one the node acts on.
        """
        import re
        from pathlib import Path

        import sigrift.bridge
        from sigrift.lib.shiny.models import ALLOWED_COMMANDS

        page = Path(sigrift.bridge.__file__).parent / "static/docs/api_reference.html"
        endpoint = re.search(
            r'<div class="endpoint" id="nodes-command">(.*?)</div></div>',
            page.read_text(encoding="utf-8"),
            re.S,
        )
        assert endpoint, "nodes-command endpoint not found in the API reference"
        row = re.search(
            r"<tr><td><code>command</code></td><td>string</td><td>(.*?)</td></tr>",
            endpoint.group(1),
            re.S,
        )
        assert row, "CommandRequest.command row not found"
        listed = re.fullmatch(r"Command name: one of (.*?)\. Any other name .*", row[1])
        assert listed, row[1]
        names = re.findall(r"<code>([^<]*)</code>", listed[1])
        assert names, listed[1]
        assert sorted(names) == sorted(ALLOWED_COMMANDS)

    @pytest.mark.parametrize("limit", [0, 2])
    @pytest.mark.parametrize(
        ("method", "suffix", "body"),
        [
            ("POST", "command", {"command": "ping"}),
            ("PUT", "config", {"config": {"gain": 1}}),
        ],
        ids=["command", "config"],
    )
    def test_the_queue_limit_is_the_node_routers_and_checked_before_queuing(
        self,
        persistence,
        client,
        app_state,
        detection_store,
        monkeypatch,
        method,
        suffix,
        body,
        limit,
    ):
        """The node router's limit itself (not a copy of its value), checked
        before anything is queued: a refusal leaves no entry behind, not even
        an empty queue or a history entry for the node."""
        from sigrift.bridge.routers import nodes

        monkeypatch.setattr(nodes, "_MAX_PENDING_COMMANDS_PER_NODE", limit)
        _add_node(persistence)
        url = f"/api/admin/nodes/{_NODE}/{suffix}"
        for _ in range(limit):
            assert client.request(method, url, json=body).status_code == 200
        queued = copy.deepcopy(app_state.pending_commands.get(_NODE))
        history = copy.deepcopy(list(app_state.command_history))
        resp = client.request(method, url, json=body)
        assert resp.status_code == 429
        node_router = client.post(
            f"/api/nodes/{_NODE}/command", json={"command": "ping"}
        )
        assert node_router.status_code == 429
        assert resp.json()["detail"] == node_router.json()["detail"]
        assert app_state.pending_commands.get(_NODE) == queued
        if limit == 0:
            assert _NODE not in app_state.pending_commands
        assert list(app_state.command_history) == history
        assert len(_admin_audit(detection_store)) == limit

    @pytest.mark.parametrize(
        ("method", "suffix", "body", "command", "params"),
        [
            ("POST", "command", {"command": "restart"}, "restart", {}),
            ("PUT", "config", {"config": {"gain": 7}}, "update_config", {"gain": 7}),
        ],
        ids=["command", "config"],
    )
    def test_commands_are_queued_with_an_id_history_and_lease_like_the_node_router(
        self, persistence, client, app_state, method, suffix, body, command, params
    ):
        from sigrift.bridge.routers.nodes import _COMMAND_LEASE_MINUTES

        _add_node(persistence)
        before = datetime.now(timezone.utc)
        resp = client.request(method, f"/api/admin/nodes/{_NODE}/{suffix}", json=body)
        assert resp.status_code == 200
        (queued,) = app_state.pending_commands[_NODE]
        assert (queued["command"], queued["params"], queued["status"]) == (
            command,
            params,
            "queued",
        )
        lease = datetime.fromisoformat(queued["lease_expires_at"])
        expected = before + timedelta(minutes=_COMMAND_LEASE_MINUTES)
        assert abs(lease - expected) < timedelta(seconds=30)
        (history,) = app_state.command_history
        assert history["command_id"] == queued["command_id"]
        assert (history["node_id"], history["command"], history["status"]) == (
            _NODE,
            command,
            "queued",
        )

    def test_a_command_the_node_does_not_collect_in_time_is_dropped(
        self, persistence, client, app_state, monkeypatch
    ):
        """An offline node never runs a restart whenever it next checks in."""
        from sigrift.bridge.routers import nodes

        _add_node(persistence)
        for path, method, body in [
            ("command", "POST", {"command": "restart"}),
            ("config", "PUT", {"config": {"gain": 1}}),
        ]:
            resp = client.request(method, f"/api/admin/nodes/{_NODE}/{path}", json=body)
            assert resp.status_code == 200
        now = datetime.now(timezone.utc)
        lease = timedelta(minutes=nodes._COMMAND_LEASE_MINUTES)
        monkeypatch.setattr(
            nodes, "_utcnow", lambda: now + lease - timedelta(minutes=1)
        )
        assert nodes._reap_expired_commands(app_state) == 0
        assert len(app_state.pending_commands[_NODE]) == 2
        monkeypatch.setattr(
            nodes, "_utcnow", lambda: now + lease + timedelta(minutes=1)
        )
        assert nodes._reap_expired_commands(app_state) == 2
        assert _NODE not in app_state.pending_commands
        assert [e["status"] for e in app_state.command_history] == ["expired"] * 2

    @pytest.mark.parametrize(
        ("path", "status_code"),
        [(f"/api/admin/nodes/{_NODE}", 200), (f"/api/nodes/{_NODE}", 204)],
        ids=["admin", "nodes-router"],
    )
    def test_deregistering_a_node_drops_its_queued_commands(
        self, persistence, client, app_state, path, status_code
    ):
        """A node registering again under the id never gets them."""
        _add_node(persistence)
        _add_node(persistence, "other-node")
        for node_id in (_NODE, "other-node"):
            resp = client.post(
                f"/api/admin/nodes/{node_id}/command", json={"command": "restart"}
            )
            assert resp.status_code == 200
        other = copy.deepcopy(app_state.pending_commands["other-node"])
        assert client.delete(path).status_code == status_code
        assert _NODE not in app_state.pending_commands
        assert app_state.pending_commands["other-node"] == other
        statuses = {e["node_id"]: e["status"] for e in app_state.command_history}
        assert statuses == {_NODE: "cancelled", "other-node": "queued"}
        # Registered again, the node collects nothing on its heartbeat.
        _add_node(persistence)
        resp = client.post("/api/nodes/heartbeat", json={"node_id": _NODE})
        assert resp.status_code == 200, resp.text
        assert resp.json()["pending_commands"] == []


class TestNodeDiagnostics:
    def test_unknown_node_is_404(self, client):
        resp = client.get("/api/admin/nodes/no-such-node/diagnostics")
        assert resp.status_code == 404

    def test_full_report(self, persistence, client, app_state, detection_store):
        caps = {
            "device_type": "rtlsdr",
            "board_model": "rpi4",
            "accelerator": "hailo",
            "anomaly_enabled": True,
            "anomaly_count": 3,
            "scan_count": 42,
            "uptime_seconds": 1234,
            "heartbeat_latency_ms": 12.5,
        }
        summary = {
            "total_detections": 120,
            "period_seconds": 60,
            "class_counts": {f"c{i:02d}": i for i in range(12)},
            "avg_confidence": 0.87654,
            "dominant_class": "c11",
        }
        _add_node(
            persistence,
            capabilities=caps,
            detection_summary=summary,
            cpu_percent=20.0,
            memory_mb=512,
        )
        app_state.pending_commands[_NODE] = [{"command": "ping", "params": {}}]
        detection_store.log_audit(action="node_error", target_id="e1", node_id=_NODE)
        detection_store.log_audit(action="node_error", target_id="e2", node_id="other")
        resp = client.get(f"/api/admin/nodes/{_NODE}/diagnostics")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert (data["status"], data["health"], data["health_issues"]) == (
            "active",
            "green",
            [],
        )
        assert data["uptime_seconds"] == 1234
        assert data["latency_ms"] == 12.5
        assert data["sdr_info"]["type"] == "rtlsdr"
        assert data["system_info"]["platform"] == "rpi4"
        assert data["system_info"]["accelerator"] == "hailo"
        stats = data["detection_stats"]
        assert stats["rate_per_min"] == 120.0
        assert stats["avg_confidence"] == 0.877
        assert len(stats["top_classes"]) == 10
        assert stats["top_classes"][0] == {"class": "c11", "count": 11}
        assert data["scanners"] == [
            {"name": "RF Anomaly", "status": "active", "count": 3},
            {"name": "RF Scanner", "status": "active", "count": 42},
        ]
        assert data["pending_commands"] == [{"command": "ping", "params": {}}]
        assert [e["target_id"] for e in data["recent_errors"]] == ["e1"]

    def test_an_idle_node_without_stats(self, persistence, client):
        _add_node(persistence, last_seen=_now_iso(200), capabilities={"scan_count": 5})
        data = client.get(f"/api/admin/nodes/{_NODE}/diagnostics").json()
        assert data["scanners"] == [
            {"name": "RF Scanner", "status": "idle", "count": 5}
        ]
        assert data["detection_stats"]["rate_per_min"] == 0
        assert data["sdr_info"]["type"] == "Unknown"

    @pytest.mark.parametrize(
        ("fields", "health", "issue_prefixes"),
        [
            ({"cpu_percent": 95.0}, "red", ["CPU usage critical"]),
            ({"cpu_percent": 80.0}, "yellow", ["CPU usage elevated"]),
            ({"memory_mb": 4000}, "yellow", ["High memory usage"]),
            (
                {"cpu_percent": 95.0, "memory_mb": 4000},
                "red",
                ["CPU usage critical", "High memory usage"],
            ),
            ({"capabilities": {"cpu_temp": 85}}, "red", ["CPU temperature critical"]),
            (
                {"capabilities": {"cpu_temp": 75}},
                "yellow",
                ["CPU temperature elevated"],
            ),
            (
                {"cpu_percent": 95.0, "capabilities": {"cpu_temp": 75}},
                "red",
                ["CPU usage critical", "CPU temperature elevated"],
            ),
            ({"last_seen": 3600}, "red", ["Node status: offline"]),
            ({"last_seen": 200}, "yellow", ["Node status: stale"]),
            ({"last_seen": None}, "yellow", ["Node status: unknown"]),
        ],
        ids=[
            "cpu-critical",
            "cpu-elevated",
            "memory",
            "cpu-and-memory",
            "temp-critical",
            "temp-elevated",
            "cpu-and-temp",
            "offline",
            "stale",
            "unknown",
        ],
    )
    def test_health_assessment(
        self, persistence, client, fields, health, issue_prefixes
    ):
        fields = dict(fields)
        if isinstance(fields.get("last_seen"), int):  # seconds ago, as of now
            fields["last_seen"] = _now_iso(fields["last_seen"])
        _add_node(persistence, **fields)
        data = client.get(f"/api/admin/nodes/{_NODE}/diagnostics").json()
        assert data["health"] == health
        assert len(data["health_issues"]) == len(issue_prefixes)
        for issue, prefix in zip(data["health_issues"], issue_prefixes):
            assert issue.startswith(prefix)

    def test_a_stale_node_with_critical_cpu_stays_red(self, persistence, client):
        _add_node(persistence, last_seen=_now_iso(200), cpu_percent=95.0)
        data = client.get(f"/api/admin/nodes/{_NODE}/diagnostics").json()
        assert data["status"] == "stale"
        assert data["health"] == "red"

    @pytest.mark.parametrize(
        ("fields", "status", "health", "issue_prefixes"),
        [
            (
                {"last_seen": None, "cpu_percent": 95.0},
                "unknown",
                "red",
                ["CPU usage critical", "Node status: unknown"],
            ),
            (
                {"last_seen": 200, "capabilities": {"cpu_temp": 85}},
                "stale",
                "red",
                ["CPU temperature critical", "Node status: stale"],
            ),
            (
                {"last_seen": 200, "cpu_percent": 80.0},
                "stale",
                "yellow",
                ["CPU usage elevated", "Node status: stale"],
            ),
            (
                {"last_seen": 3600, "cpu_percent": 10.0},
                "offline",
                "red",
                ["Node status: offline"],
            ),
        ],
        ids=[
            "unknown-cpu-critical",
            "stale-temp-critical",
            "stale-elevated",
            "offline",
        ],
    )
    def test_node_status_never_downgrades_a_critical_metric(
        self, persistence, client, fields, status, health, issue_prefixes
    ):
        fields = dict(fields)
        if isinstance(fields.get("last_seen"), int):  # seconds ago, as of now
            fields["last_seen"] = _now_iso(fields["last_seen"])
        _add_node(persistence, **fields)
        data = client.get(f"/api/admin/nodes/{_NODE}/diagnostics").json()
        assert (data["status"], data["health"]) == (status, health)
        assert len(data["health_issues"]) == len(issue_prefixes)
        for issue, prefix in zip(data["health_issues"], issue_prefixes):
            assert issue.startswith(prefix)

    def test_an_audit_read_failure_still_reports(
        self, persistence, client, detection_store, monkeypatch
    ):
        _add_node(persistence)

        def broken(*args, **kwargs):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(detection_store, "get_audit_log", broken)
        resp = client.get(f"/api/admin/nodes/{_NODE}/diagnostics")
        assert resp.status_code == 200
        assert resp.json()["recent_errors"] == []


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


class TestAlertRules:
    def _seed(self, persistence: PersistenceManager) -> str:
        persistence.add_alert(
            {"alert_id": "a1", "name": "seed", "severity": "info", "message": ""}
        )
        return "a1"

    def test_updates_are_escaped_persisted_and_diffed(
        self, persistence, client, detection_store
    ):
        alert_id = self._seed(persistence)
        resp = client.put(
            f"/api/admin/alerts/{alert_id}",
            json={"name": "<b>x</b>", "message": "<script>alert(1)</script>"},
        )
        assert resp.status_code == 200
        (stored,) = persistence.get_alerts()
        assert stored["name"] == "&lt;b&gt;x&lt;/b&gt;"
        assert stored["message"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
        assert resp.json() == stored
        (entry,) = _audit(detection_store, "admin_update_alert")
        assert entry["details"]["changes"] == [
            {"key": "name", "old": "seed", "new": "&lt;b&gt;x&lt;/b&gt;"},
            {
                "key": "message",
                "old": "",
                "new": "&lt;script&gt;alert(1)&lt;/script&gt;",
            },
        ]

    def test_an_update_without_changes_audits_no_diff(
        self, persistence, client, detection_store
    ):
        alert_id = self._seed(persistence)
        resp = client.put(f"/api/admin/alerts/{alert_id}", json={"severity": "info"})
        assert resp.status_code == 200
        (entry,) = _audit(detection_store, "admin_update_alert")
        assert entry["details"] == {}

    @pytest.mark.parametrize(
        "body",
        [{"alert_id": "a2"}, {"acknowledged": True}, {"triggered_at": "2020"}],
        ids=["alert_id", "acknowledged", "triggered_at"],
    )
    def test_server_owned_fields_cannot_be_written(
        self, persistence, client, detection_store, body
    ):
        alert_id = self._seed(persistence)
        before = persistence.get_alerts()
        assert client.put(f"/api/admin/alerts/{alert_id}", json=body).status_code == 422
        assert (
            client.post("/api/admin/alerts", json={"name": "n", **body}).status_code
            == 422
        )
        assert persistence.get_alerts() == before
        assert _admin_audit(detection_store) == []

    def test_listing_and_deletion(self, persistence, client, detection_store):
        alert_id = self._seed(persistence)
        listed = client.get("/api/admin/alerts").json()
        assert [a["alert_id"] for a in listed] == [alert_id]
        assert client.delete("/api/admin/alerts/nope").status_code == 404
        assert _audit(detection_store, "admin_delete_alert") == []
        assert client.delete(f"/api/admin/alerts/{alert_id}").status_code == 200
        assert persistence.get_alerts() == []
        (entry,) = _audit(detection_store, "admin_delete_alert")
        assert entry["target_id"] == alert_id


# ---------------------------------------------------------------------------
# Audit log and log viewer queries
# ---------------------------------------------------------------------------


class TestAuditQueries:
    def test_filters_are_bound_parameters(self, client, detection_store):
        detection_store.log_audit(action="admin_create_key", target_id="k1")
        for params in (
            {"action": "x' OR '1'='1"},
            {"operator": "' OR 1=1 --"},
            {"target_id": "k1' --"},
            {"search": "%"},
        ):
            resp = client.get("/api/admin/audit", params=params)
            assert resp.status_code == 200, params
            assert (resp.json()["total"], resp.json()["entries"]) == (0, []), params
        resp = client.get("/api/admin/audit", params={"search": "create_key"})
        assert resp.json()["total"] == 1  # the table is intact

    def test_admin_actions_reach_the_filters_and_keep_the_chain(
        self, bridge_app, persistence, client
    ):
        ops = _client(bridge_app, _add_key(persistence, "ops", "admin"))
        assert ops.post("/api/admin/keys", json={"role": "viewer"}).status_code == 201
        assert client.post("/api/admin/alerts", json={"name": "n"}).status_code == 201
        actions = client.get("/api/admin/audit/actions").json()
        assert {"admin_create_key", "admin_create_alert"} <= set(actions)
        filters = client.get("/api/admin/audit/filters").json()
        assert set(filters) == {"actions", "operators", "node_ids"}
        assert set(filters["actions"]) == set(actions)
        assert {"ops", "master"} <= set(filters["operators"])
        verify = client.get("/api/admin/audit/verify")
        assert verify.status_code == 200
        assert verify.json()["valid"] is True

    @pytest.mark.parametrize(
        "params",
        [{"limit": 0}, {"limit": 1001}, {"offset": -1}],
        ids=["limit-0", "limit-1001", "offset-negative"],
    )
    def test_paging_bounds(self, client, params):
        assert client.get("/api/admin/audit", params=params).status_code == 422

    def test_severity_filter(self, bridge_app, master_key, detection_store):
        client = TestClient(
            bridge_app,
            headers={"X-API-Key": master_key},
            raise_server_exceptions=False,
        )
        detection_store.log_audit(
            action="admin_rotate_key", target_id="k1", details={"severity": "critical"}
        )
        detection_store.log_audit(action="admin_list_keys", target_id="keys")
        resp = client.get("/api/admin/audit", params={"severity": "critical"})
        assert resp.status_code == 200
        critical = resp.json()
        assert [e["action"] for e in critical["entries"]] == ["admin_rotate_key"]
        assert critical["total"] == 1
        info = client.get("/api/admin/audit", params={"severity": "info"}).json()
        assert "admin_rotate_key" not in [e["action"] for e in info["entries"]]
        assert "admin_list_keys" in [e["action"] for e in info["entries"]]

    @pytest.mark.parametrize("limit", [0, 2001])
    def test_log_viewer_limit_bounds(self, client, limit):
        assert client.get("/api/admin/logs", params={"limit": limit}).status_code == 422

    def test_log_viewer_filters_by_logger(self, client):
        from sigrift.bridge.log_buffer import get_log_buffer

        get_log_buffer()
        logging.getLogger("sigrift.test.admin_sec").warning("needle-7f3a")
        resp = client.get(
            "/api/admin/logs",
            params={"logger": "sigrift.test.admin_sec", "search": "needle-7f3a"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert {e["logger"] for e in data["entries"]} == {"sigrift.test.admin_sec"}
        assert "sigrift.test.admin_sec" in data["loggers"]


# ---------------------------------------------------------------------------
# Syslog forwarding targets
# ---------------------------------------------------------------------------


class TestSyslogTargets:
    @pytest.mark.parametrize(
        ("body", "status"),
        [
            ({"host": "127.0.0.1", "protocol": "http"}, 400),
            ({"host": "127.0.0.1", "facility": "bogus"}, 400),
            ({"host": "127.0.0.1", "port": 0}, 422),
            ({"host": "127.0.0.1", "port": 65536}, 422),
            ({"host": "127.0.0.1", "id": "chosen"}, 422),
            ({"port": 514}, 422),
        ],
        ids=["protocol", "facility", "port-0", "port-65536", "id", "no-host"],
    )
    def test_creation_validates_input(
        self, bridge_app, persistence, client, detection_store, body, status
    ):
        resp = client.post("/api/admin/syslog", json=body)
        assert resp.status_code == status, resp.text
        assert bridge_app.state.syslog_forwarder.targets == []
        assert persistence.get_syslog_targets() == []
        assert _admin_audit(detection_store) == []

    def test_creation_is_persisted_listed_and_audited(
        self, persistence, client, detection_store
    ):
        resp = client.post(
            "/api/admin/syslog",
            json={
                "host": "127.0.0.1",
                "port": 6514,
                "protocol": "TLS",
                "facility": "auth",
            },
        )
        assert resp.status_code == 201, resp.text
        target = resp.json()
        assert (target["protocol"], target["facility"]) == ("tls", "auth")
        assert [t["id"] for t in persistence.get_syslog_targets()] == [target["id"]]
        listed = client.get("/api/admin/syslog").json()["targets"]
        assert [t["id"] for t in listed] == [target["id"]]
        (entry,) = _audit(detection_store, "admin_create_syslog_target")
        assert entry["target_id"] == target["id"]
        assert entry["details"] == {
            "host": "127.0.0.1",
            "port": 6514,
            "protocol": "tls",
        }

    def test_updates_validate_persist_and_audit(
        self, bridge_app, persistence, client, detection_store
    ):
        fwd = bridge_app.state.syslog_forwarder
        target_id = fwd.add_target(host="127.0.0.1", port=5514)["id"]
        url = f"/api/admin/syslog/{target_id}"
        assert client.put(url, json={"protocol": "smtp"}).status_code == 400
        assert fwd.get_target(target_id)["protocol"] == "udp"
        assert (
            client.put("/api/admin/syslog/nope", json={"enabled": False}).status_code
            == 404
        )
        assert _admin_audit(detection_store) == []
        resp = client.put(url, json={"protocol": "TCP", "port": 1514, "enabled": False})
        assert resp.status_code == 200
        assert (resp.json()["protocol"], resp.json()["port"]) == ("tcp", 1514)
        (persisted,) = persistence.get_syslog_targets()
        assert (persisted["protocol"], persisted["enabled"]) == ("tcp", False)
        (entry,) = _audit(detection_store, "admin_update_syslog_target")
        assert sorted(entry["details"]["updates"]) == ["enabled", "port", "protocol"]

    def test_deletion_is_persisted_and_audited(
        self, bridge_app, persistence, client, detection_store
    ):
        fwd = bridge_app.state.syslog_forwarder
        target_id = fwd.add_target(host="127.0.0.1", port=5514)["id"]
        persistence.set_syslog_targets(fwd.targets)
        assert client.delete("/api/admin/syslog/nope").status_code == 404
        assert client.delete(f"/api/admin/syslog/{target_id}").status_code == 200
        assert fwd.targets == []
        assert persistence.get_syslog_targets() == []
        (entry,) = _audit(detection_store, "admin_delete_syslog_target")
        assert entry["target_id"] == target_id

    def test_test_message_is_delivered_and_counted(
        self, bridge_app, persistence, client, detection_store
    ):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5)
        try:
            port = receiver.getsockname()[1]
            fwd = bridge_app.state.syslog_forwarder
            target_id = fwd.add_target(host="127.0.0.1", port=port)["id"]
            assert client.post("/api/admin/syslog/nope/test").status_code == 404
            resp = client.post(f"/api/admin/syslog/{target_id}/test")
            assert resp.status_code == 200
            assert resp.json() == {"status": "delivered"}
            datagram, _ = receiver.recvfrom(65535)
        finally:
            receiver.close()
        assert b"SigRift syslog forwarding test message" in datagram
        (persisted,) = persistence.get_syslog_targets()
        assert persisted["delivery_count"] == 1
        (entry,) = _audit(detection_store, "admin_test_syslog_target")
        assert entry["details"] == {"result": "delivered"}

    def test_without_a_forwarder(self, bridge_app, client, monkeypatch):
        monkeypatch.setattr(bridge_app.state, "syslog_forwarder", None)
        assert client.get("/api/admin/syslog").json() == {"targets": []}
        calls = [
            ("POST", "/api/admin/syslog", {"host": "127.0.0.1"}),
            ("PUT", "/api/admin/syslog/t1", {"enabled": False}),
            ("DELETE", "/api/admin/syslog/t1", None),
            ("POST", "/api/admin/syslog/t1/test", None),
        ]
        for method, url, body in calls:
            resp = client.request(method, url, json=body)
            assert resp.status_code == 503, f"{method} {url}"
            assert resp.json()["detail"] == "Syslog forwarder not initialized"


# ---------------------------------------------------------------------------
# Runtime configuration
# ---------------------------------------------------------------------------

_RUNTIME_KEYS = {
    "BRIDGE_SKIP_INTEGRITY_CHECK",
    "BRIDGE_LOG_LEVEL",
    "BRIDGE_BACKGROUND_TASKS",
    "BRIDGE_MEMORY_LIMIT_MB",
    "BRIDGE_CLEANUP_INTERVAL",
    "BRIDGE_MATERIALIZER_INTERVAL",
    "BRIDGE_WAL_CHECKPOINT_INTERVAL",
    "BRIDGE_STALE_RESOLVE_INTERVAL",
    "BRIDGE_BASELINE_SAVE_INTERVAL",
}


class TestRuntimeConfig:
    def test_reading_exposes_only_the_allowlist(self, client, monkeypatch):
        monkeypatch.setenv("BRIDGE_MASTER_KEY", "s3cr3t-master-value")
        monkeypatch.setenv("BRIDGE_LOG_LEVEL", "WARNING")
        resp = client.get("/api/admin/runtime-config")
        assert resp.status_code == 200
        data = resp.json()
        assert set(data) == _RUNTIME_KEYS | {
            "SIGRIFT_PRESET",
            "_current_rss_mb",
            "_memory_limit_mb",
        }
        assert data["BRIDGE_LOG_LEVEL"] == "WARNING"
        assert "s3cr3t-master-value" not in resp.text

    @pytest.mark.parametrize(
        ("rlimit", "expected"),
        [((512 * 1024 * 1024, -1), 512), ((-1, -1), 0), (OSError("no"), 0)],
        ids=["limited", "unlimited", "error"],
    )
    def test_reading_survives_missing_probes(
        self, client, monkeypatch, rlimit, expected
    ):
        import resource

        def fake_getrlimit(which):
            if isinstance(rlimit, Exception):
                raise rlimit
            return rlimit

        monkeypatch.setattr(resource, "getrlimit", fake_getrlimit)
        monkeypatch.setitem(sys.modules, "psutil", None)  # import psutil fails
        data = client.get("/api/admin/runtime-config").json()
        assert data["_memory_limit_mb"] == expected
        assert data["_current_rss_mb"] == 0

    @pytest.mark.parametrize(
        "key",
        [
            "PATH",
            "LD_PRELOAD",
            "BRIDGE_MASTER_KEY",
            "SIGRIFT_PRESET",
            "bridge_log_level",
        ],
    )
    def test_keys_outside_the_allowlist_are_refused(
        self, client, detection_store, monkeypatch, key
    ):
        monkeypatch.setenv(key, "original")
        resp = client.put(f"/api/admin/runtime-config/{key}", json={"value": "1"})
        assert resp.status_code == 400
        assert "not configurable" in resp.json()["detail"]
        assert os.environ[key] == "original"
        assert _admin_audit(detection_store) == []

    @pytest.mark.parametrize(
        "value",
        [
            "INFO\nFAKE: admin logged in",
            "x\x00y",
            "x\x7f",
            "\x1b[31m",
            "x" * 257,
            None,
            [1],
        ],
        ids=["newline", "nul", "del", "escape", "too-long", "null", "list"],
    )
    def test_unsafe_values_are_refused(
        self, client, detection_store, monkeypatch, value
    ):
        monkeypatch.setenv("BRIDGE_LOG_LEVEL", "INFO")
        resp = client.put(
            "/api/admin/runtime-config/BRIDGE_LOG_LEVEL", json={"value": value}
        )
        assert resp.status_code == 400
        assert os.environ["BRIDGE_LOG_LEVEL"] == "INFO"
        assert _admin_audit(detection_store) == []

    @pytest.mark.parametrize(
        ("value", "stored"),
        [
            (True, "true"),
            (False, "false"),
            (1800, "1800"),
            (2.5, "2.5"),
            ("y" * 256, "y" * 256),
        ],
        ids=["true", "false", "int", "float", "256-chars"],
    )
    def test_values_are_normalised_and_audited(
        self, client, detection_store, monkeypatch, value, stored
    ):
        monkeypatch.setenv("BRIDGE_CLEANUP_INTERVAL", "1800")
        resp = client.put(
            "/api/admin/runtime-config/BRIDGE_CLEANUP_INTERVAL", json={"value": value}
        )
        assert resp.status_code == 200
        assert resp.json()["value"] == stored
        assert os.environ["BRIDGE_CLEANUP_INTERVAL"] == stored
        (entry,) = _audit(detection_store, "admin_set_runtime_config")
        assert (entry["target_id"], entry["operator"]) == (
            "BRIDGE_CLEANUP_INTERVAL",
            "master",
        )
        assert entry["details"] == {"value": stored, "persisted": False}

    def test_an_audit_failure_is_logged_not_500(
        self, client, detection_store, monkeypatch, caplog
    ):
        monkeypatch.setenv("BRIDGE_LOG_LEVEL", "INFO")

        def broken(*args, **kwargs):
            raise RuntimeError("disk full")

        monkeypatch.setattr(detection_store, "log_audit", broken)
        with caplog.at_level(logging.WARNING, logger="sigrift.bridge.routers.admin"):
            resp = client.put(
                "/api/admin/runtime-config/BRIDGE_LOG_LEVEL", json={"value": "DEBUG"}
            )
        assert resp.status_code == 200
        assert os.environ["BRIDGE_LOG_LEVEL"] == "DEBUG"
        assert (
            "Failed to audit runtime config change of BRIDGE_LOG_LEVEL" in caplog.text
        )


# ---------------------------------------------------------------------------
# _config_diff (audit diff helper shared with system_config)
# ---------------------------------------------------------------------------


class TestConfigDiff:
    def test_nested_dicts_diff_per_sub_key(self):
        old = {"weights": {"a": 1, "b": 2}, "x": 1, "same": True}
        new = {"weights": {"a": 1, "b": 3, "c": 4}, "x": 2, "same": True}
        changes = _config_diff(old, new)
        assert sorted(changes, key=lambda c: c["key"]) == [
            {"key": "weights.b", "old": 2, "new": 3},
            {"key": "weights.c", "old": None, "new": 4},
            {"key": "x", "old": 1, "new": 2},
        ]

    def test_explicit_keys_limit_the_diff(self):
        old = {"x": 1, "y": 1}
        new = {"x": 2, "y": 2, "z": 3}
        assert _config_diff(old, new, keys=["y"]) == [{"key": "y", "old": 1, "new": 2}]

    def test_added_and_removed_keys(self):
        changes = _config_diff({"gone": 1}, {"new": 2})
        assert sorted(changes, key=lambda c: c["key"]) == [
            {"key": "gone", "old": 1, "new": None},
            {"key": "new", "old": None, "new": 2},
        ]
        assert _config_diff({"a": {"b": 1}}, {"a": {"b": 1}}) == []
