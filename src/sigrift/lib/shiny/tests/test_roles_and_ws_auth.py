"""Roles, key expiry, WebSocket auth and secret hygiene (review finding B9).

Before: any valid key could register nodes and queue arbitrary node
commands; ``expires_at`` was kept in process memory only and never checked;
WebSockets accepted the key only as a ``?api_key=`` query parameter (which
lands in access logs); and the generated master key was logged in plain
text at WARNING.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from sigrift.lib.security.credentials import generate_api_key, hash_credential
from sigrift.lib.shiny.dependencies import (
    RedactQuerySecretsFilter,
    Role,
    _lookup_key,
    check_key,
    clear_fast_hash_index,
    key_expired,
    redact_query_secrets,
)
from sigrift.lib.shiny.persistence import PersistenceManager


def _log_text(caplog: pytest.LogCaptureFixture) -> str:
    """The captured log messages, one per line.

    Not ``caplog.text``: that is formatted by whatever formatter the handler
    carries, and an earlier test in the same xdist worker can install the
    app's JSON log formatter on every handler — which escapes the quotes in
    messages such as ``{"node_id": "<node>"}`` and breaks substring checks.
    """
    return "\n".join(r.getMessage() for r in caplog.records)


def _add_key(pm: PersistenceManager, key_id: str, **meta: Any) -> str:
    raw = generate_api_key()
    hash_hex, salt = hash_credential(raw)
    pm.set_key(key_id, hash_hex, salt, meta=meta or None)
    return raw


def _h(raw: str) -> dict[str, str]:
    return {"X-API-Key": raw}


def _past() -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


@pytest.fixture(autouse=True)
def _fresh_index():
    clear_fast_hash_index()
    yield
    clear_fast_hash_index()


# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------


class TestNodeAdministrationNeedsAdmin:
    pytestmark = pytest.mark.asyncio

    async def test_viewer_cannot_register_a_node(
        self, test_client: httpx.AsyncClient, api_key_header, sample_node
    ) -> None:
        resp = await test_client.post(
            "/api/nodes/register", headers=api_key_header, json=sample_node
        )
        assert resp.status_code == 403
        assert resp.json()["detail"] == "admin role required"

    async def test_analyst_cannot_register_a_node(
        self, test_client: httpx.AsyncClient, mock_persistence, sample_node
    ) -> None:
        raw = _add_key(mock_persistence, "analyst-1", role="analyst")
        resp = await test_client.post(
            "/api/nodes/register", headers=_h(raw), json=sample_node
        )
        assert resp.status_code == 403

    async def test_viewer_cannot_queue_node_commands(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        api_key_header,
        sample_node,
    ) -> None:
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        for command in ("ping", "update", "restart"):
            resp = await test_client.post(
                "/api/nodes/edge-01/command",
                headers=api_key_header,
                json={"command": command},
            )
            assert resp.status_code == 403, command

    async def test_admin_and_master_can(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        sample_node,
    ) -> None:
        for headers in (admin_key_header, master_key_header):
            resp = await test_client.post(
                "/api/nodes/register", headers=headers, json=sample_node
            )
            assert resp.status_code == 200
            resp = await test_client.post(
                "/api/nodes/edge-01/command", headers=headers, json={"command": "ping"}
            )
            assert resp.status_code == 200

    async def test_viewer_still_reads_and_heartbeats(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        api_key_header,
        node_key_header,
        sample_node,
    ) -> None:
        # A viewer reads the dashboard, and a viewer-role node key (the
        # default role) heartbeats for its node: heartbeats need no admin.
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        for headers in (api_key_header, node_key_header):
            listed = await test_client.get("/api/nodes/", headers=headers)
            assert listed.status_code == 200
        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=node_key_header,
            json={"node_id": "edge-01", "metrics": {"cpu_percent": 1.0}},
        )
        assert resp.status_code == 200

    async def test_unknown_role_is_rejected(
        self, test_client: httpx.AsyncClient, mock_persistence
    ) -> None:
        raw = _add_key(mock_persistence, "odd", role="superuser")
        resp = await test_client.get("/api/health", headers=_h(raw))
        assert resp.status_code == 401
        assert "unknown role" in resp.json()["detail"]


class TestBoundKeys:
    pytestmark = pytest.mark.asyncio

    async def test_bound_key_heartbeats_only_as_its_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        sample_node,
    ) -> None:
        for nid in ("edge-01", "edge-02"):
            await test_client.post(
                "/api/nodes/register",
                headers=admin_key_header,
                json={**sample_node, "node_id": nid},
            )
        raw = _add_key(mock_persistence, "edge-01-key", node_id="edge-01")
        ok = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert ok.status_code == 200
        other = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-02", "metrics": {}},
        )
        assert other.status_code == 403

    async def test_unbound_key_is_tofu_bound_and_cannot_impersonate_others(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
    ) -> None:
        # P12: an unbound viewer key must not be able to heartbeat as any node
        # and steal another node's admin-queued commands.
        for nid in ("edge-01", "edge-02"):
            await test_client.post(
                "/api/nodes/register",
                headers=admin_key_header,
                json={**sample_node, "node_id": nid},
            )
        # An admin queues a command for edge-01.
        queued = await test_client.post(
            "/api/nodes/edge-01/command",
            headers=admin_key_header,
            json={"command": "ping"},
        )
        assert queued.status_code == 200

        # An unbound node key (viewer role).
        raw = _add_key(mock_persistence, "node-key", purpose="node")
        # First heartbeat binds the key to the node it reports for (TOFU).
        first = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-02", "metrics": {}},
        )
        assert first.status_code == 200
        assert mock_persistence.get_key_meta("node-key")["node_id"] == "edge-02"

        # It can no longer speak for a different node -> edge-01's queued
        # command is not handed out to it.
        steal = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert steal.status_code == 403
        assert mock_app_state.pending_commands.get("edge-01")

    async def test_unbound_opt_out_restores_legacy_behaviour(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        sample_node,
        monkeypatch,
    ) -> None:
        monkeypatch.setenv("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "1")
        for nid in ("edge-01", "edge-02"):
            await test_client.post(
                "/api/nodes/register",
                headers=admin_key_header,
                json={**sample_node, "node_id": nid},
            )
        raw = _add_key(mock_persistence, "legacy-key")  # unbound viewer key
        for nid in ("edge-01", "edge-02"):
            resp = await test_client.post(
                "/api/nodes/heartbeat",
                headers=_h(raw),
                json={"node_id": nid, "metrics": {}},
            )
            assert resp.status_code == 200
        # Opt-out keeps the key unbound (no TOFU binding written).
        assert "node_id" not in mock_persistence.get_key_meta("legacy-key")

    async def _register_and_queue(self, client, admin_key_header, sample_node):
        await client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        queued = await client.post(
            "/api/nodes/edge-01/command",
            headers=admin_key_header,
            json={"command": "ping"},
        )
        assert queued.status_code == 200

    @pytest.mark.parametrize("legacy", [False, True], ids=["node-key", "legacy-tofu"])
    async def test_unbound_key_cannot_take_over_a_claimed_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
        monkeypatch,
        legacy: bool,
    ) -> None:
        # P12: edge-01's own key is bound; a fresh unbound key that has never
        # heartbeated must not bind itself to edge-01 by TOFU and take the
        # admin-queued command (the real node would never get it).  Holds for
        # a node key and for a legacy key under the migration opt-in.
        await self._register_and_queue(test_client, admin_key_header, sample_node)
        _add_key(mock_persistence, "edge-01-key", node_id="edge-01")
        if legacy:
            monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", "1")
            raw = _add_key(mock_persistence, "dash-viewer")  # no purpose
        else:
            raw = _add_key(mock_persistence, "dash-viewer", purpose="node")

        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-01", "metrics": {"cpu_percent": 99.0}},
        )
        assert resp.status_code == 403
        assert "bound to another API key" in resp.json()["detail"]
        # Command still queued, metrics untouched, no binding written.
        assert [c["command"] for c in mock_app_state.pending_commands["edge-01"]] == [
            "ping"
        ]
        assert mock_persistence.get_nodes()["edge-01"].get("cpu_percent") != 99.0
        assert "node_id" not in mock_persistence.get_key_meta("dash-viewer")

    async def test_tofu_claimed_node_cannot_be_taken_over(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
    ) -> None:
        # The node's (unbound) node key claims edge-01 on its first
        # heartbeat; a second unbound node key is then refused for edge-01.
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        node_raw = _add_key(mock_persistence, "node-key", purpose="node")
        first = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(node_raw),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert first.status_code == 200
        await test_client.post(
            "/api/nodes/edge-01/command",
            headers=admin_key_header,
            json={"command": "ping"},
        )
        other = _add_key(mock_persistence, "other-key", purpose="node")
        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(other),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert resp.status_code == 403
        assert mock_app_state.pending_commands["edge-01"]
        # The node itself still gets its command.
        ok = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(node_raw),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert [c["command"] for c in ok.json()["pending_commands"]] == ["ping"]

    async def test_dashboard_key_never_claims_a_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
    ) -> None:
        # The finding's scenario: a plain dashboard viewer key (created
        # without node_id, so purpose "dashboard") heartbeats for edge-01,
        # which no key has claimed yet.  It must not be bound to edge-01 or
        # receive its queued command.
        await self._register_and_queue(test_client, admin_key_header, sample_node)
        created = await test_client.post(
            "/api/keys/", headers=master_key_header, json={"key_id": "dash-viewer"}
        )
        assert created.json()["purpose"] == "dashboard"
        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(created.json()["raw_key"]),
            json={"node_id": "edge-01", "metrics": {"cpu_percent": 99.0}},
        )
        assert resp.status_code == 403
        assert mock_app_state.pending_commands["edge-01"]
        assert mock_persistence.get_key_meta("dash-viewer").get("node_id") is None
        # It still reads the dashboard.
        listed = await test_client.get(
            "/api/nodes/", headers=_h(created.json()["raw_key"])
        )
        assert listed.status_code == 200

    async def test_analyst_key_never_claims_a_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
    ) -> None:
        await self._register_and_queue(test_client, admin_key_header, sample_node)
        raw = _add_key(mock_persistence, "analyst-key", role="analyst")
        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(raw),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert resp.status_code == 403
        assert mock_app_state.pending_commands["edge-01"]
        assert "node_id" not in mock_persistence.get_key_meta("analyst-key")

    async def test_node_purpose_key_is_bound_on_first_heartbeat(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        sample_node,
    ) -> None:
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        created = await test_client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "provisioned", "purpose": "node"},
        )
        assert created.status_code == 201
        resp = await test_client.post(
            "/api/nodes/heartbeat",
            headers=_h(created.json()["raw_key"]),
            json={"node_id": "edge-01", "metrics": {}},
        )
        assert resp.status_code == 200
        assert mock_persistence.get_key_meta("provisioned")["node_id"] == "edge-01"


async def _heartbeat(client, raw: str, node_id: str, cpu: float = 1.0):
    return await client.post(
        "/api/nodes/heartbeat",
        headers=_h(raw),
        json={"node_id": node_id, "metrics": {"cpu_percent": cpu}},
    )


class TestLegacyKeys:
    """V6: keys with no ``purpose`` (created before purposes existed)."""

    pytestmark = pytest.mark.asyncio

    async def _offline_node_with_command(self, client, admin_key_header, sample_node):
        # edge-02 is registered but has not heartbeated since the upgrade
        # (offline), so no key is bound to it; an admin queues a command.
        await client.post(
            "/api/nodes/register",
            headers=admin_key_header,
            json={**sample_node, "node_id": "edge-02"},
        )
        queued = await client.post(
            "/api/nodes/edge-02/command",
            headers=admin_key_header,
            json={"command": "ping"},
        )
        assert queued.status_code == 200

    async def test_legacy_key_cannot_claim_an_unclaimed_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
    ) -> None:
        # The finding's scenario: the old shared dashboard viewer key (no
        # purpose, no node_id) heartbeats for offline edge-02.  It must not
        # get the queued ping, overwrite the metrics or claim the node.
        await self._offline_node_with_command(
            test_client, admin_key_header, sample_node
        )
        dash = _add_key(mock_persistence, "dashboard-viewer")
        edge02 = _add_key(mock_persistence, "edge-02-key")  # old node key

        resp = await _heartbeat(test_client, dash, "edge-02", cpu=99.0)
        assert resp.status_code == 403
        detail = resp.json()["detail"]
        assert "no purpose" in detail
        assert "PATCH /api/keys/dashboard-viewer" in detail
        assert "SHINY_LEGACY_KEY_TOFU" in detail
        assert [c["command"] for c in mock_app_state.pending_commands["edge-02"]] == [
            "ping"
        ]
        assert mock_persistence.get_nodes()["edge-02"].get("cpu_percent") != 99.0
        assert mock_persistence.get_key_meta("dashboard-viewer").get("node_id") is None
        assert mock_app_state.activity_log[-1]["event_type"] == "heartbeat_refused"

        # The real node is not locked out: once the admin binds its key to
        # it, it heartbeats and receives its command.
        bound = await test_client.patch(
            "/api/keys/edge-02-key",
            headers=master_key_header,
            json={"node_id": "edge-02"},
        )
        assert bound.status_code == 200
        ok = await _heartbeat(test_client, edge02, "edge-02")
        assert ok.status_code == 200
        assert [c["command"] for c in ok.json()["pending_commands"]] == ["ping"]

    @pytest.mark.parametrize("value", ["1", "true", "2999-01-01", "2999-01-01T00:00Z"])
    async def test_migration_opt_in_restores_first_use_binding_loudly(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
        monkeypatch,
        caplog: pytest.LogCaptureFixture,
        value: str,
    ) -> None:
        monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", value)
        await self._offline_node_with_command(
            test_client, admin_key_header, sample_node
        )
        raw = _add_key(mock_persistence, "edge-02-key")
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.routers.nodes"):
            resp = await _heartbeat(test_client, raw, "edge-02")
        assert resp.status_code == 200
        assert [c["command"] for c in resp.json()["pending_commands"]] == ["ping"]
        assert mock_persistence.get_key_meta("edge-02-key")["node_id"] == "edge-02"
        # The claim stands out: a warning log and a warning-level activity event.
        event = mock_app_state.activity_log[-1]
        assert event["event_type"] == "legacy_key_bound"
        assert event["details"]["level"] == "warning"
        assert event["node_id"] == "edge-02"
        assert "claimed node edge-02" in _log_text(caplog)

    @pytest.mark.parametrize("value", ["", "0", "off", "2000-01-01", "soon"])
    async def test_opt_in_off_expired_or_invalid_keeps_refusing(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
        monkeypatch,
        value: str,
    ) -> None:
        monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", value)
        await self._offline_node_with_command(
            test_client, admin_key_header, sample_node
        )
        raw = _add_key(mock_persistence, "dashboard-viewer")
        resp = await _heartbeat(test_client, raw, "edge-02")
        assert resp.status_code == 403
        assert mock_app_state.pending_commands["edge-02"]
        assert mock_persistence.get_key_meta("dashboard-viewer").get("node_id") is None

    async def test_bound_legacy_key_keeps_working(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        sample_node,
    ) -> None:
        # A key with no purpose that is already bound (by a first-use claim
        # before this change, or by an admin) is unaffected.
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        raw = _add_key(mock_persistence, "old-bound", node_id="edge-01")
        assert (await _heartbeat(test_client, raw, "edge-01")).status_code == 200

    async def test_unknown_purpose_never_claims_a_node(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        mock_persistence,
        sample_node,
        monkeypatch,
    ) -> None:
        # A hand-edited purpose that is not "node" fails closed, opt-in or not.
        monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", "1")
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        raw = _add_key(mock_persistence, "odd", purpose="sensor")
        assert (await _heartbeat(test_client, raw, "edge-01")).status_code == 403
        assert mock_persistence.get_key_meta("odd").get("node_id") is None


def test_legacy_key_tofu_setting(monkeypatch) -> None:
    from sigrift.lib.shiny.routers.nodes import legacy_key_tofu

    now = datetime(2026, 11, 6, 12, 0, tzinfo=timezone.utc)
    cases = {
        None: (False, None, None),
        "": (False, None, None),
        "no": (False, None, None),
        "ON": (True, None, None),
        "2026-11-07": (True, datetime(2026, 11, 7, tzinfo=timezone.utc), None),
        "2026-11-06T11:59:00Z": (
            False,
            datetime(2026, 11, 6, 11, 59, tzinfo=timezone.utc),
            None,
        ),
        "2026-11-06T13:00:00+02:00": (
            False,
            datetime(2026, 11, 6, 11, 0, tzinfo=timezone.utc),
            None,
        ),
        "next week": (False, None, "next week"),
    }
    for value, (active, until, invalid) in cases.items():
        if value is None:
            monkeypatch.delenv("SHINY_LEGACY_KEY_TOFU", raising=False)
        else:
            monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", value)
        got = legacy_key_tofu(now)
        assert (got.active, got.until, got.invalid) == (active, until, invalid), value


class TestKeyUpdate:
    """V6: ``PATCH /api/keys/{key_id}`` classifies, binds and unbinds keys."""

    pytestmark = pytest.mark.asyncio

    async def test_admin_undoes_a_wrong_claim_without_revoking_the_key(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        mock_app_state,
        sample_node,
        monkeypatch,
    ) -> None:
        # During the migration the shared dashboard key claimed edge-01
        # before the node's own key did.
        monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", "1")
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        dash = _add_key(mock_persistence, "dashboard-viewer")
        node = _add_key(mock_persistence, "edge-01-key")
        assert (await _heartbeat(test_client, dash, "edge-01")).status_code == 200
        assert (await _heartbeat(test_client, node, "edge-01")).status_code == 403

        resp = await test_client.patch(
            "/api/keys/dashboard-viewer",
            headers=master_key_header,
            json={"purpose": "dashboard", "node_id": None},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["purpose"] == "dashboard" and body["node_id"] is None
        assert body["key_id"] == "dashboard-viewer" and "raw_key" not in body
        event = mock_app_state.activity_log[-1]
        assert event["event_type"] == "key_updated"
        assert event["details"]["previous_node_id"] == "edge-01"
        assert "unbound from node edge-01" in event["message"]

        # The dashboard key still reads but can never heartbeat again; the
        # node's own key now claims its node.
        assert (await _heartbeat(test_client, dash, "edge-01")).status_code == 403
        listed = await test_client.get("/api/nodes/", headers=_h(dash))
        assert listed.status_code == 200
        assert (await _heartbeat(test_client, node, "edge-01")).status_code == 200
        assert mock_persistence.get_key_meta("edge-01-key")["node_id"] == "edge-01"

    async def test_binding_survives_a_restart_and_allows_extra_keys(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        sample_node,
        tmp_path: Path,
    ) -> None:
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        first = _add_key(mock_persistence, "edge-01-a", purpose="node")
        assert (await _heartbeat(test_client, first, "edge-01")).status_code == 200
        second = _add_key(mock_persistence, "edge-01-b")  # legacy, unbound
        assert (await _heartbeat(test_client, second, "edge-01")).status_code == 403

        # An explicit admin binding may add a second key to a claimed node,
        # and it makes the key a node key.
        resp = await test_client.patch(
            "/api/keys/edge-01-b",
            headers=master_key_header,
            json={"node_id": "edge-01"},
        )
        assert resp.status_code == 200
        assert resp.json()["purpose"] == "node"
        for raw in (first, second):
            assert (await _heartbeat(test_client, raw, "edge-01")).status_code == 200

        reloaded = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        reloaded.load_all()
        meta = reloaded.get_key_meta("edge-01-b")
        assert meta["node_id"] == "edge-01" and meta["purpose"] == "node"
        assert "updated_at" in meta

    async def test_classify_legacy_key_as_node_key(
        self,
        test_client: httpx.AsyncClient,
        admin_key_header,
        master_key_header,
        mock_persistence,
        sample_node,
    ) -> None:
        # purpose "node" without node_id: bound on its first heartbeat.
        await test_client.post(
            "/api/nodes/register", headers=admin_key_header, json=sample_node
        )
        raw = _add_key(mock_persistence, "old-node", role="viewer")
        resp = await test_client.patch(
            "/api/keys/old-node", headers=master_key_header, json={"purpose": "node"}
        )
        assert resp.status_code == 200 and resp.json()["node_id"] is None
        assert (await _heartbeat(test_client, raw, "edge-01")).status_code == 200
        meta = mock_persistence.get_key_meta("old-node")
        assert meta["node_id"] == "edge-01" and meta["role"] == "viewer"

    async def test_dashboard_purpose_on_a_bound_key_is_a_conflict(
        self, test_client: httpx.AsyncClient, master_key_header, mock_persistence
    ) -> None:
        _add_key(mock_persistence, "bound", purpose="node", node_id="edge-01")
        resp = await test_client.patch(
            "/api/keys/bound", headers=master_key_header, json={"purpose": "dashboard"}
        )
        assert resp.status_code == 409
        assert "node_id: null" in resp.json()["detail"]
        meta = mock_persistence.get_key_meta("bound")
        assert meta["purpose"] == "node" and meta["node_id"] == "edge-01"

    async def test_rejected_requests(
        self,
        test_client: httpx.AsyncClient,
        master_key_header,
        admin_key_header,
        api_key_header,
        mock_persistence,
    ) -> None:
        _add_key(mock_persistence, "k", role="viewer")
        for body in (
            {},
            {"purpose": None},
            {"purpose": "sensor"},
            {"purpose": "dashboard", "node_id": "edge-01"},
            {"node_id": "../etc"},
            {"role": "admin"},  # the role cannot be changed this way
            {"node_id": "edge-01", "role": "admin"},
        ):
            resp = await test_client.patch(
                "/api/keys/k", headers=master_key_header, json=body
            )
            assert resp.status_code == 422, body
        assert mock_persistence.get_key_meta("k") == {"role": "viewer"}

        ghost = await test_client.patch(
            "/api/keys/ghost", headers=master_key_header, json={"node_id": None}
        )
        assert ghost.status_code == 404
        master = await test_client.patch(
            "/api/keys/master", headers=master_key_header, json={"node_id": "edge-01"}
        )
        assert master.status_code == 400
        # Only the master key manages keys (as for create/rotate/revoke).
        for headers in (admin_key_header, api_key_header):
            resp = await test_client.patch(
                "/api/keys/k", headers=headers, json={"node_id": "edge-01"}
            )
            assert resp.status_code == 403
        assert "node_id" not in mock_persistence.get_key_meta("k")


def test_update_key_binding_keeps_unsent_fields(tmp_path: Path) -> None:
    from sigrift.lib.shiny.persistence import KEEP

    pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
    _add_key(pm, "a", role="analyst", purpose="node", node_id="edge-01")
    outcome, meta, previous = pm.update_key_binding("a", node_id=None)
    assert outcome == "updated"
    assert previous["node_id"] == "edge-01"
    assert meta == {**previous, "node_id": None}
    outcome, meta, _ = pm.update_key_binding("a", purpose="dashboard", node_id=KEEP)
    assert outcome == "updated" and meta["purpose"] == "dashboard"
    # A dashboard key cannot be bound: nothing is written.
    outcome, meta, _ = pm.update_key_binding("a", node_id="edge-02")
    assert outcome == "dashboard_bound"
    assert pm.get_key_meta("a")["node_id"] is None
    assert pm.update_key_binding("missing", node_id=None)[0] == "unknown_key"


def test_bind_key_to_node_is_first_come_and_atomic(tmp_path: Path) -> None:
    # Two unbound keys racing for one node: exactly one wins, the other is
    # told the node is claimed and stays unbound.
    import threading

    pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
    for kid in ("a", "b"):
        _add_key(pm, kid)
    _add_key(pm, "c")
    results: dict[str, str] = {}
    barrier = threading.Barrier(2)

    def claim(kid: str) -> None:
        barrier.wait()
        results[kid] = pm.bind_key_to_node(kid, "edge-01")

    threads = [threading.Thread(target=claim, args=(k,)) for k in ("a", "b")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results.values()) == ["bound", "node_claimed"]
    winner = next(k for k, v in results.items() if v == "bound")
    loser = next(k for k, v in results.items() if v == "node_claimed")
    assert pm.get_key_meta(winner)["node_id"] == "edge-01"
    assert "node_id" not in pm.get_key_meta(loser)
    # The winner re-binding to its node is a no-op; to another node it is not.
    assert pm.bind_key_to_node(winner, "edge-01") == "bound"
    assert pm.bind_key_to_node(winner, "edge-02") == "bound_elsewhere"
    assert pm.bind_key_to_node("missing", "edge-03") == "unknown_key"
    assert pm.bind_key_to_node("c", "edge-02") == "bound"


class TestKeyManagement:
    pytestmark = pytest.mark.asyncio

    async def test_created_key_role_is_enforced_and_persisted(
        self,
        test_client: httpx.AsyncClient,
        master_key_header,
        mock_persistence,
        sample_node,
        tmp_path: Path,
    ) -> None:
        resp = await test_client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "ops", "role": "admin", "node_id": "edge-01"},
        )
        assert resp.status_code == 201
        assert resp.json()["role"] == "admin"
        raw = resp.json()["raw_key"]
        reg = await test_client.post(
            "/api/nodes/register", headers=_h(raw), json=sample_node
        )
        assert reg.status_code == 200

        # The role (and binding) survive a restart: they are in keys.json.
        reloaded = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        reloaded.load_all()
        assert reloaded.get_key_meta("ops")["role"] == "admin"
        assert reloaded.get_key_meta("ops")["node_id"] == "edge-01"

        listed = await test_client.get("/api/keys/", headers=master_key_header)
        roles = {k["key_id"]: k["role"] for k in listed.json()}
        assert roles["ops"] == "admin" and roles["master"] == "admin"

    async def test_new_keys_default_to_viewer(
        self, test_client: httpx.AsyncClient, master_key_header, sample_node
    ) -> None:
        resp = await test_client.post(
            "/api/keys/", headers=master_key_header, json={"key_id": "plain"}
        )
        assert resp.json()["role"] == "viewer"
        reg = await test_client.post(
            "/api/nodes/register", headers=_h(resp.json()["raw_key"]), json=sample_node
        )
        assert reg.status_code == 403

    async def test_key_purpose_defaults_and_is_persisted(
        self, test_client: httpx.AsyncClient, master_key_header, mock_persistence
    ) -> None:
        for body, purpose in (
            ({"key_id": "dash"}, "dashboard"),
            ({"key_id": "bound", "node_id": "edge-01"}, "node"),
            ({"key_id": "prov", "purpose": "node"}, "node"),
        ):
            resp = await test_client.post(
                "/api/keys/", headers=master_key_header, json=body
            )
            assert resp.status_code == 201, body
            assert resp.json()["purpose"] == purpose
            assert mock_persistence.get_key_meta(body["key_id"])["purpose"] == purpose
        listed = await test_client.get("/api/keys/", headers=master_key_header)
        purposes = {k["key_id"]: k["purpose"] for k in listed.json()}
        assert purposes["dash"] == "dashboard" and purposes["prov"] == "node"

    async def test_invalid_role_or_node_id_rejected(
        self, test_client: httpx.AsyncClient, master_key_header
    ) -> None:
        for body in (
            {"key_id": "x1", "role": "keymaster"},
            {"key_id": "x2", "node_id": "../etc"},
            {"key_id": "x3", "purpose": "dashboard", "node_id": "edge-01"},
            {"key_id": "x4", "purpose": "sensor"},
        ):
            resp = await test_client.post(
                "/api/keys/", headers=master_key_header, json=body
            )
            assert resp.status_code == 422, body

    async def test_rotation_keeps_role_and_expiry(
        self, test_client: httpx.AsyncClient, master_key_header, mock_persistence
    ) -> None:
        await test_client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "rot", "role": "analyst", "expires_in_hours": 2},
        )
        before = mock_persistence.get_key_meta("rot")
        resp = await test_client.put("/api/keys/rot/rotate", headers=master_key_header)
        assert resp.status_code == 200
        after = mock_persistence.get_key_meta("rot")
        assert after["role"] == "analyst"
        assert after["expires_at"] == before["expires_at"]
        assert "rotated_at" in after


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    pytestmark = pytest.mark.asyncio

    async def test_expired_key_rejected(
        self, test_client: httpx.AsyncClient, mock_persistence
    ) -> None:
        raw = _add_key(mock_persistence, "old", expires_at=_past())
        resp = await test_client.get("/api/health", headers=_h(raw))
        assert resp.status_code == 401
        assert resp.json()["detail"] == "API key expired"

    async def test_unexpired_key_accepted(
        self, test_client: httpx.AsyncClient, mock_persistence
    ) -> None:
        raw = _add_key(mock_persistence, "fresh", expires_at=_future())
        assert (
            await test_client.get("/api/health", headers=_h(raw))
        ).status_code == 200

    async def test_unparseable_expiry_is_expired(
        self, test_client: httpx.AsyncClient, mock_persistence
    ) -> None:
        raw = _add_key(mock_persistence, "garbled", expires_at="next tuesday")
        assert (
            await test_client.get("/api/health", headers=_h(raw))
        ).status_code == 401

    async def test_api_created_expiry_is_enforced_after_restart(
        self,
        test_client: httpx.AsyncClient,
        master_key_header,
        mock_persistence,
        tmp_path: Path,
    ) -> None:
        resp = await test_client.post(
            "/api/keys/",
            headers=master_key_header,
            json={"key_id": "temp", "expires_in_hours": 1},
        )
        raw = resp.json()["raw_key"]
        assert (
            await test_client.get("/api/health", headers=_h(raw))
        ).status_code == 200
        # Time passes: the stored expiry is what counts, also after a reload.
        mock_persistence.update_key_meta("temp", expires_at=_past())
        reloaded = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        reloaded.load_all()
        assert key_expired(reloaded.get_key_meta("temp"))
        assert (
            await test_client.get("/api/health", headers=_h(raw))
        ).status_code == 401

    async def test_expired_master_key_cannot_manage_keys(
        self, test_client: httpx.AsyncClient, master_key_header, mock_persistence
    ) -> None:
        mock_persistence.update_key_meta("master", expires_at=_past())
        resp = await test_client.post(
            "/api/keys/", headers=master_key_header, json={"key_id": "nope"}
        )
        assert resp.status_code == 401


def test_key_expired_helper() -> None:
    assert not key_expired({})
    assert not key_expired({"expires_at": None})
    assert key_expired({"expires_at": "2000-01-01T00:00:00"})  # naive = UTC
    assert key_expired({"expires_at": "2000-01-01T00:00:00Z"})
    assert not key_expired({"expires_at": _future()})
    assert key_expired({"expires_at": 12345})


# ---------------------------------------------------------------------------
# WebSocket auth
# ---------------------------------------------------------------------------


_WS_ROUTES = [
    "/api/nodes/ws/status",
    "/api/alerts/ws/alerts",
    "/api/spectrum/ws/spectrum",
    "/api/training/ws/training",
]


class TestWebSocketAuth:
    @pytest.mark.parametrize("path", _WS_ROUTES)
    def test_subprotocol_auth_is_accepted_and_echoed(
        self, test_app: FastAPI, api_key: str, path: str
    ) -> None:
        with TestClient(test_app) as client:
            with client.websocket_connect(
                path, subprotocols=["bridge-v1", api_key]
            ) as ws:
                assert ws.accepted_subprotocol == "bridge-v1"

    def test_subprotocol_status_stream(self, test_app: FastAPI, api_key: str) -> None:
        with TestClient(test_app) as client:
            with client.websocket_connect(
                "/api/nodes/ws/status", subprotocols=["bridge-v1", api_key]
            ) as ws:
                assert ws.receive_json()["type"] == "snapshot"

    def test_header_auth_is_accepted(self, test_app: FastAPI, api_key: str) -> None:
        with TestClient(test_app) as client:
            with client.websocket_connect(
                "/api/nodes/ws/status", headers={"X-API-Key": api_key}
            ) as ws:
                assert ws.accepted_subprotocol is None
                assert ws.receive_json()["type"] == "snapshot"

    @pytest.mark.parametrize("path", _WS_ROUTES)
    def test_bad_subprotocol_key_refused_with_4001(
        self, test_app: FastAPI, path: str
    ) -> None:
        with TestClient(test_app) as client:
            with pytest.raises(WebSocketDisconnect) as exc:
                with client.websocket_connect(path, subprotocols=["bridge-v1", "nope"]):
                    pass
        assert exc.value.code == 4001

    @pytest.mark.parametrize("path", _WS_ROUTES)
    def test_no_key_refused_with_4001(self, test_app: FastAPI, path: str) -> None:
        with TestClient(test_app) as client:
            with pytest.raises(WebSocketDisconnect) as exc:
                with client.websocket_connect(path):
                    pass
        assert exc.value.code == 4001

    def test_expired_key_refused(self, test_app: FastAPI, mock_persistence) -> None:
        raw = _add_key(mock_persistence, "ws-old", expires_at=_past())
        with TestClient(test_app) as client:
            with pytest.raises(WebSocketDisconnect) as exc:
                with client.websocket_connect(
                    "/api/nodes/ws/status", subprotocols=["bridge-v1", raw]
                ):
                    pass
        assert exc.value.code == 4001

    def test_query_parameter_still_works(self, test_app: FastAPI, api_key: str) -> None:
        """Deprecated but kept for existing clients; the key is redacted in logs."""
        with TestClient(test_app) as client:
            with client.websocket_connect(
                f"/api/nodes/ws/status?api_key={api_key}"
            ) as ws:
                assert ws.receive_json()["type"] == "snapshot"

    def test_bundled_dashboard_never_puts_the_key_in_a_url(self) -> None:
        static = Path(__file__).resolve().parents[1] / "static"
        for name in ("dashboard.js", "spectrum.js"):
            js = (static / name).read_text()
            assert '"?api_key="' not in js and '"&api_key="' not in js, name
            assert '"bridge-v1"' in js, name


# ---------------------------------------------------------------------------
# Log hygiene
# ---------------------------------------------------------------------------


class TestQueryStringRedaction:
    def test_redact_helper(self) -> None:
        out = redact_query_secrets("/api/export/nodes?format=csv&api_key=SECRET123&x=1")
        assert "SECRET123" not in out
        assert "format=csv" in out and "x=1" in out and "api_key=[REDACTED]" in out

    def test_uvicorn_access_record(self) -> None:
        record = logging.LogRecord(
            "uvicorn.access",
            logging.INFO,
            __file__,
            1,
            '%s - "%s %s HTTP/%s" %d',
            ("127.0.0.1:5000", "GET", "/api/health?api_key=SECRET123", "1.1", 200),
            None,
        )
        RedactQuerySecretsFilter().filter(record)
        assert "SECRET123" not in record.getMessage()

    def test_uvicorn_websocket_record(self) -> None:
        record = logging.LogRecord(
            "uvicorn.error",
            logging.INFO,
            __file__,
            1,
            '%s - "WebSocket %s" [accepted]',
            ("127.0.0.1:5000", "/api/nodes/ws/status?api_key=SECRET123"),
            None,
        )
        RedactQuerySecretsFilter().filter(record)
        assert "SECRET123" not in record.getMessage()

    def test_app_installs_the_filter(self) -> None:
        import sigrift.lib.shiny.app  # noqa: F401  (installs on import)

        for name in ("uvicorn.access", "uvicorn.error"):
            filters = logging.getLogger(name).filters
            assert any(isinstance(f, RedactQuerySecretsFilter) for f in filters), name


# ---------------------------------------------------------------------------
# Initial master key
# ---------------------------------------------------------------------------


def _read_key_file(path: Path) -> str:
    lines = [
        ln for ln in path.read_text().splitlines() if ln and not ln.startswith("#")
    ]
    assert len(lines) == 1
    return lines[0]


class TestInitialMasterKey:
    def test_written_to_a_private_file_and_never_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from sigrift.lib.shiny.app import bootstrap_master_key

        pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        with caplog.at_level(logging.DEBUG):
            path = bootstrap_master_key(pm)
        assert path is not None and path.parent == tmp_path
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        raw = _read_key_file(path)
        assert raw not in _log_text(caplog)
        assert str(path) in _log_text(caplog)
        assert _lookup_key(raw, pm.get_key_store()) == "master"
        assert pm.get_key_meta("master")["role"] == "admin"
        assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]

    def test_unwritable_file_creates_no_key(self, tmp_path: Path) -> None:
        from sigrift.lib.shiny.app import INITIAL_MASTER_KEY_FILE, bootstrap_master_key

        blocker = tmp_path / INITIAL_MASTER_KEY_FILE
        blocker.mkdir()  # os.replace onto a dir fails
        pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        assert bootstrap_master_key(pm) is None
        assert pm.get_key_store() == {}
        # The temp file held the raw key: it is removed with the refusal.
        assert [p.name for p in tmp_path.iterdir()] == [INITIAL_MASTER_KEY_FILE]
        assert list(blocker.iterdir()) == []

    @pytest.mark.asyncio
    async def test_lifespan_does_not_log_the_key(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import sigrift.lib.shiny.app as shiny_app

        monkeypatch.setattr(
            shiny_app,
            "PersistenceManager",
            lambda: PersistenceManager(data_dir=tmp_path, auto_save_interval=0),
        )
        with caplog.at_level(logging.DEBUG):
            async with shiny_app.app.router.lifespan_context(shiny_app.app):
                pass
        raw = _read_key_file(tmp_path / shiny_app.INITIAL_MASTER_KEY_FILE)
        assert raw not in _log_text(caplog)
        assert Role.ADMIN > Role.VIEWER

    @pytest.mark.asyncio
    async def test_lifespan_restores_a_revoked_master_and_keeps_the_other_keys(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        # An install that revoked its master key before the API refused that
        # had no key left that can manage keys; a restart now fixes it
        # without dropping the node and dashboard keys.
        import sigrift.lib.shiny.app as shiny_app

        pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        edge_raw = _add_key(pm, "edge-1", role="viewer", node_id="edge-01")
        _add_key(pm, "dash", role="admin", purpose="dashboard")
        monkeypatch.setattr(
            shiny_app,
            "PersistenceManager",
            lambda: PersistenceManager(data_dir=tmp_path, auto_save_interval=0),
        )
        with caplog.at_level(logging.DEBUG):
            async with shiny_app.app.router.lifespan_context(shiny_app.app):
                pass
        path = tmp_path / shiny_app.INITIAL_MASTER_KEY_FILE
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        raw = _read_key_file(path)
        assert raw not in _log_text(caplog)
        assert "master key is missing" in _log_text(caplog)
        reloaded = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        reloaded.load_all()
        assert sorted(reloaded.get_key_store()) == ["dash", "edge-1", "master"]
        assert _lookup_key(raw, reloaded.get_key_store()) == "master"
        assert _lookup_key(edge_raw, reloaded.get_key_store()) == "edge-1"
        assert reloaded.get_key_meta("edge-1")["node_id"] == "edge-01"


# ---------------------------------------------------------------------------
# Upgrade: keys stored before roles existed
# ---------------------------------------------------------------------------


def _unclassified_store(tmp_path: Path) -> PersistenceManager:
    pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
    _add_key(pm, "master")
    _add_key(pm, "legacy-node")
    _add_key(pm, "legacy-viewer", role="viewer")
    _add_key(pm, "bound", node_id="edge-01")
    _add_key(pm, "dash", purpose="dashboard")
    _add_key(pm, "ops", role="admin")
    _add_key(pm, "lab", role="analyst")
    return pm


def test_unclassified_node_keys_warned_at_startup(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    # Keys that cannot heartbeat until classified (no node_id, no purpose,
    # not admin/analyst) are listed once at startup, with how to fix them.
    from sigrift.lib.shiny.app import warn_unclassified_node_keys

    pm = _unclassified_store(tmp_path)
    with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
        assert warn_unclassified_node_keys(pm) == ["legacy-node", "legacy-viewer"]
    assert "refused (403)" in _log_text(caplog)
    assert 'PATCH /api/keys/<key_id> {"node_id": "<node>"}' in _log_text(caplog)
    assert '{"purpose": "dashboard"}' in _log_text(caplog)
    assert "SHINY_LEGACY_KEY_TOFU=1" in _log_text(caplog)


def test_startup_warning_reflects_the_migration_opt_in(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch
) -> None:
    from sigrift.lib.shiny.app import warn_unclassified_node_keys

    pm = _unclassified_store(tmp_path)
    monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", "2999-01-01")
    with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
        warn_unclassified_node_keys(pm)
    assert "SHINY_LEGACY_KEY_TOFU is on until 2999-01-01" in _log_text(caplog)
    assert "logged as a warning" in _log_text(caplog)

    caplog.clear()
    monkeypatch.setenv("SHINY_LEGACY_KEY_TOFU", "eventually")
    with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
        warn_unclassified_node_keys(pm)
    [error] = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert "'eventually'" in error.getMessage() and "OFF" in error.getMessage()
    assert "refused (403)" in _log_text(caplog)


class TestLegacyKeysUpgradeNote:
    """Pre-role keys load as viewers; the operator is told so at startup."""

    def _legacy_store(self, tmp_path: Path) -> PersistenceManager:
        pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        _add_key(pm, "master")  # pre-role master: no meta, still admin
        _add_key(pm, "edge-1")  # pre-role node key: no meta
        _add_key(pm, "ops", role="admin")
        return pm

    def test_lists_only_roleless_non_master_keys(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from sigrift.lib.shiny.app import warn_legacy_viewer_keys

        pm = self._legacy_store(tmp_path)
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
            assert warn_legacy_viewer_keys(pm) == ["edge-1"]
        [record] = [r for r in caplog.records if "no stored role" in r.getMessage()]
        msg = record.getMessage()
        assert "'edge-1'" in msg and "'ops'" not in msg and "'master'" not in msg
        assert "viewers" in msg and "role 'admin'" in msg
        # Viewers no longer write alerts, jobs or schedules, or drive the
        # spectrum source: say what to use.
        assert "analyst key" in msg and "role 'analyst'" in msg
        assert "retuning the spectrum source" in msg
        assert str(tmp_path / "keys.json") in msg

    def test_no_warning_when_every_key_has_a_role(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        from sigrift.lib.shiny.app import warn_legacy_viewer_keys

        pm = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        _add_key(pm, "master")
        _add_key(pm, "viewer-1", role="viewer")
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
            assert warn_legacy_viewer_keys(pm) == []
        assert "no stored role" not in _log_text(caplog)

    def test_documented_keys_json_edit_restores_admin(self, tmp_path: Path) -> None:
        """Adding "role": "admin" to the entry in keys.json is honoured."""
        self._legacy_store(tmp_path)
        path = tmp_path / "keys.json"
        data = json.loads(path.read_text())
        data["keys"]["edge-1"]["role"] = "admin"
        path.write_text(json.dumps(data))
        reloaded = PersistenceManager(data_dir=tmp_path, auto_save_interval=0)
        reloaded.load_all()
        assert check_key(reloaded, "edge-1")[0] is Role.ADMIN

    @pytest.mark.asyncio
    async def test_lifespan_warns_about_legacy_keys(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        import sigrift.lib.shiny.app as shiny_app

        self._legacy_store(tmp_path)
        monkeypatch.setattr(
            shiny_app,
            "PersistenceManager",
            lambda: PersistenceManager(data_dir=tmp_path, auto_save_interval=0),
        )
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.shiny.app"):
            async with shiny_app.app.router.lifespan_context(shiny_app.app):
                pass
        assert "'edge-1'" in _log_text(caplog) and "no stored role" in _log_text(caplog)
        assert not (tmp_path / shiny_app.INITIAL_MASTER_KEY_FILE).exists()
