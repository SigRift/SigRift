"""Authenticated host checks remain separate from capture and stored data."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json

from fastapi.testclient import TestClient
import pytest
from pydantic import ValidationError

from sigrift.bridge.setup_readiness import SetupReadinessRequest, readiness_snapshot

from .test_setup_checklist import get, lease, register, setup_api as _setup_api

setup_api = _setup_api


def receipt():
    return {
        "sdr": {"adapter": "ready", "selection": "selected", "reason": "checked"},
        "wifi": {
            "adapter": "missing",
            "selection": "not_selected",
            "reason": "not_found",
        },
    }


def report(api, body=None, headers=None, node="quiet"):
    client, _, _, _, _, key = api
    if headers is None:
        headers = key("host-reporter", "node", node_id=node)
    return client.post(
        f"/api/nodes/{node}/setup-readiness",
        headers=headers,
        json=receipt() if body is None else body,
    )


def test_bound_receipt_expires_without_expiring_capture_or_inventing_data(setup_api):
    register(setup_api)
    response = report(setup_api)
    assert response.status_code == 200, response.text
    saved = response.json()
    assert saved["checked_at"] == setup_api[4][0].isoformat()
    assert saved["expires_in_seconds"] == 300
    assert saved["fresh"] is True
    row = get(setup_api)["nodes"][0]
    assert row["setup_readiness"] == saved
    assert row["scanner_status"] == {}
    assert row["observations"]["rf_record"]["status"] == "empty"
    setup_api[4][0] += timedelta(seconds=301)
    lease(setup_api, protocol="sdr")
    row = get(setup_api)["nodes"][0]
    assert row["setup_readiness"]["fresh"] is False
    assert row["setup_readiness"]["expires_in_seconds"] == 0
    assert row["setup_readiness"]["sdr"] == receipt()["sdr"]
    assert row["scanner_status"]["sdr"]["active"] is True


@pytest.mark.parametrize("role,bound", [("sensor", "quiet"), ("node", "quiet")])
def test_both_worker_roles_can_report_only_their_existing_bound_node(
    setup_api, role, bound
):
    register(setup_api)
    register(setup_api, "other")
    headers = setup_api[5]("worker", role, node_id=bound)
    assert report(setup_api, headers=headers).status_code == 200
    assert report(setup_api, headers=headers, node="other").status_code == 403
    assert get(setup_api)["nodes"][0]["setup_readiness"] is None  # other sorts first


@pytest.mark.parametrize("role", ["sensor", "node", "viewer", "analyst", "admin"])
def test_unbound_operator_and_legacy_permissive_keys_cannot_attest_host(
    setup_api, monkeypatch, role
):
    register(setup_api)
    monkeypatch.setenv("BRIDGE_ALLOW_UNBOUND_NODE_KEYS", "1")
    headers = setup_api[5]("unbound", role)
    assert report(setup_api, headers=headers).status_code == 403
    assert get(setup_api)["nodes"][0]["setup_readiness"] is None
    assert "node_id" not in setup_api[3].get_key_meta()["unbound"]


def test_foreign_tenant_and_revoked_credentials_cannot_change_receipt(setup_api):
    register(setup_api)
    foreign = setup_api[5]("foreign", "node", node_id="quiet", tenant_id="foreign")
    assert report(setup_api, headers=foreign).status_code == 403
    headers = setup_api[5]("worker", "sensor", node_id="quiet")
    assert report(setup_api, headers=headers).status_code == 200
    before = deepcopy(setup_api[3].get_nodes())
    setup_api[3].remove_key("worker")
    assert report(setup_api, headers=headers).status_code == 401
    assert setup_api[3].get_nodes() == before


@pytest.mark.parametrize(
    "change",
    [
        {"checked_at": "2099-01-01T00:00:00Z"},
        {"serial": "private-serial"},
        {
            "wifi": {
                "adapter": "ready",
                "selection": "selected",
                "reason": "SSID-private",
            }
        },
        {
            "wifi": {
                "adapter": "ready",
                "selection": "selected",
                "reason": "permissions",
            }
        },
        {"sdr": {"adapter": "unknown", "selection": "selected", "reason": "checked"}},
    ],
)
def test_extra_fields_free_text_and_contradictory_states_rejected(setup_api, change):
    register(setup_api)
    response = report(setup_api, receipt() | change)
    assert response.status_code == 422
    assert get(setup_api)["nodes"][0]["setup_readiness"] is None


def test_heartbeat_cannot_forge_or_extend_host_receipt(setup_api):
    register(setup_api)
    headers = setup_api[5]("worker", "node", node_id="quiet")
    assert report(setup_api, headers=headers).status_code == 200
    before = get(setup_api)["nodes"][0]["setup_readiness"]
    setup_api[4][0] += timedelta(seconds=30)
    response = setup_api[0].post(
        "/api/nodes/heartbeat",
        headers=headers,
        json={
            "node_id": "quiet",
            "metrics": {"_setup_readiness": receipt() | {"checked_at": "2099-01-01Z"}},
        },
    )
    assert response.status_code == 200, response.text
    after = get(setup_api)["nodes"][0]["setup_readiness"]
    assert after["checked_at"] == before["checked_at"]
    assert after["expires_in_seconds"] == 270
    assert "2099" not in json.dumps(after)


def test_missing_node_and_invalid_stored_receipt_do_not_claim_readiness(setup_api):
    assert report(setup_api).status_code == 404
    register(setup_api)
    data = setup_api[3].get_nodes()["quiet"]
    data["_setup_readiness"] = receipt() | {"checked_at": "future-secret"}
    setup_api[3].set_node("quiet", data)
    assert get(setup_api)["nodes"][0]["setup_readiness"] is None
    assert "future-secret" not in json.dumps(get(setup_api))


def test_retry_updates_only_host_check_and_survives_persistence_reload(setup_api):
    from sigrift.bridge.persistence import PersistenceManager

    register(setup_api)
    headers = setup_api[5]("worker", "node", node_id="quiet")
    missing = receipt()
    missing["sdr"].update(adapter="missing", reason="selected_absent")
    assert report(setup_api, missing, headers).status_code == 200
    before = deepcopy(setup_api[3].get_nodes()["quiet"])
    setup_api[4][0] += timedelta(seconds=20)
    assert report(setup_api, headers=headers).status_code == 200
    after = setup_api[3].get_nodes()["quiet"]
    assert (
        after["last_seen"] == before["last_seen"]
    )  # Host check is not capture or heartbeat.
    assert (
        after["_setup_readiness"]["checked_at"]
        != before["_setup_readiness"]["checked_at"]
    )
    setup_api[3].save_all()
    reopened = PersistenceManager(setup_api[3].data_dir, auto_save_interval=0)
    reopened.load_all()
    assert (
        reopened.get_nodes()["quiet"]["_setup_readiness"] == after["_setup_readiness"]
    )


@pytest.mark.parametrize(
    "age,fresh,remaining", [(299.5, True, 0.5), (300, False, 0), (301, False, 0)]
)
def test_host_check_freshness_has_exact_server_owned_boundary(age, fresh, remaining):
    now = datetime(2026, 11, 7, 15, tzinfo=timezone.utc)
    value = receipt() | {"checked_at": (now - timedelta(seconds=age)).isoformat()}
    result = readiness_snapshot(value, now)
    assert result["fresh"] is fresh
    assert result["expires_in_seconds"] == remaining
    assert result["sdr"] == receipt()["sdr"]


@pytest.mark.parametrize(
    "adapter,reason",
    [
        ("ready", "checked"),
        ("missing", "not_found"),
        ("missing", "selected_absent"),
        ("blocked", "driver_in_use"),
        ("blocked", "permissions"),
        ("blocked", "device_unavailable"),
        ("blocked", "management_interface"),
        ("blocked", "monitor_unsupported"),
        ("blocked", "radio_blocked"),
        ("blocked", "ambiguous"),
        ("unknown", "unsupported_host"),
        ("unknown", "probe_failed"),
        ("unknown", "selection_unavailable"),
        ("unknown", "not_checked"),
    ],
)
def test_sanitized_host_states_preserve_their_distinct_meanings(adapter, reason):
    now = datetime(2026, 11, 7, 15, tzinfo=timezone.utc)
    value = receipt() | {"checked_at": "2026-11-07T09:00:00-06:00"}
    selection = "selected" if reason == "selected_absent" else "unmanaged"
    value["sdr"] = {"adapter": adapter, "selection": selection, "reason": reason}
    result = readiness_snapshot(value, now)
    assert result["sdr"] == value["sdr"]
    assert result["checked_at"] == now.isoformat()
    assert result["expires_in_seconds"] == 300


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        [],
        {},
        receipt() | {"checked_at": "malformed-private-value"},
        receipt() | {"checked_at": "2026-11-07T15:00:00"},
        receipt() | {"checked_at": "2026-11-07T15:00:01Z"},
        receipt(),
        receipt() | {"checked_at": "2026-11-07T15:00:00Z", "serial": "private"},
        receipt()
        | {"checked_at": "2026-11-07T15:00:00Z", "sdr": {"adapter": "invented"}},
    ],
)
def test_invalid_or_future_persisted_report_cannot_claim_host_readiness(invalid):
    assert (
        readiness_snapshot(invalid, datetime(2026, 11, 7, 15, tzinfo=timezone.utc))
        is None
    )


@pytest.mark.parametrize("selection", ["not_selected", "unmanaged"])
def test_missing_saved_selection_cannot_be_reported_without_a_saved_selection(
    selection,
):
    value = receipt()
    value["sdr"] = {
        "adapter": "missing",
        "selection": selection,
        "reason": "selected_absent",
    }
    with pytest.raises(ValidationError, match="saved selection"):
        SetupReadinessRequest.model_validate(value)


def test_persistence_boundary_failure_returns_500_without_claiming_receipt(
    setup_api, monkeypatch
):
    register(setup_api)
    headers = setup_api[5]("worker", "sensor", node_id="quiet")
    before = deepcopy(setup_api[3].get_nodes())

    def unavailable(*_):
        raise OSError("private storage failure")

    # set_node is an in-memory persistence boundary, not a synchronous disk
    # commit. Inject its failure explicitly; do not claim a real disk-fault test.
    monkeypatch.setattr(setup_api[3], "set_node", unavailable)
    with TestClient(setup_api[0].app, raise_server_exceptions=False) as client:
        response = client.post(
            "/api/nodes/quiet/setup-readiness", headers=headers, json=receipt()
        )
    assert response.status_code == 500
    assert "private" not in response.text
    assert setup_api[3].get_nodes() == before


@pytest.mark.parametrize("role", ["sensor", "node"])
def test_full_bridge_app_allows_bound_worker_receipt_but_not_operator_key(
    client, registered_node, role
):
    created = client.post(
        "/api/admin/keys", json={"role": role, "node_id": registered_node}
    )
    assert created.status_code == 201, created.text
    raw = created.json()["raw_key"]
    # The normal fixture's default admin header must not win over this worker.
    response = client.post(
        f"/api/nodes/{registered_node}/setup-readiness",
        headers={"X-API-Key": raw},
        json=receipt(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["fresh"] is True
    denied = client.post(
        f"/api/nodes/{registered_node}/setup-readiness", json=receipt()
    )
    assert denied.status_code == 403
    checked = client.get("/api/nodes/setup-checklist")
    assert checked.status_code == 200
    assert (
        next(
            row for row in checked.json()["nodes"] if row["node_id"] == registered_node
        )["setup_readiness"]["sdr"]
        == receipt()["sdr"]
    )
