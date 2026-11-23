"""Real JSON/SQLite restoration through authenticated configuration endpoints."""

from __future__ import annotations

import json

import pytest

from sigrift.bridge import dependencies
from sigrift.bridge.persistence import PersistenceManager


@pytest.fixture(autouse=True)
def isolated_restore_limits(monkeypatch):
    monkeypatch.setattr(dependencies, "_rate_limiter", dependencies.RateLimiter())
    from sigrift.bridge.anomaly import wifi_scorer

    # update_weights intentionally replaces a module global; preserve suite state.
    monkeypatch.setattr(
        wifi_scorer, "_DIMENSION_WEIGHTS", dict(wifi_scorer._DIMENSION_WEIGHTS)
    )


def write_config(persistence, value):
    persistence.set_detection_config({"rf_min_learning_detections": value})


def snapshot(client):
    response = client.post(
        "/api/admin/config-snapshots", json={"description": "restore test"}
    )
    assert response.status_code == 201
    return response.json()["snapshot_id"]


def restore_audits(store):
    return (
        store.get_connection()
        .execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'admin_config_snapshot_restore'"
        )
        .fetchone()[0]
    )


def test_pre_restore_database_failure_preserves_current_configuration(
    client, persistence, detection_store
):
    write_config(persistence, 19)
    snapshot_id = snapshot(client)
    write_config(persistence, 43)
    before = (persistence.data_dir / "detection_config.json").read_bytes()
    conn = detection_store.get_connection()
    conn.execute(
        "CREATE TRIGGER reject_restore_backup BEFORE INSERT ON config_snapshots "
        "WHEN NEW.trigger = 'config_change' BEGIN "
        "SELECT RAISE(ABORT, 'injected backup storage failure'); END"
    )
    conn.commit()

    response = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")

    assert response.status_code == 500
    assert (persistence.data_dir / "detection_config.json").read_bytes() == before
    assert persistence.get_detection_config()["rf_min_learning_detections"] == 43
    assert restore_audits(detection_store) == 0
    assert len(PersistenceManager.list_config_snapshots(conn)) == 1
    conn.execute("DROP TRIGGER reject_restore_backup")
    conn.commit()
    retry = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
    assert retry.status_code == 200
    fresh = PersistenceManager(persistence.data_dir, auto_save_interval=0)
    fresh.load_all()
    assert fresh.get_detection_config()["rf_min_learning_detections"] == 19
    backup_id = PersistenceManager.list_config_snapshots(conn)[0]["id"]
    assert (
        PersistenceManager.get_config_snapshot(conn, backup_id)["files"][
            "detection_config.json"
        ]["config"]["rf_min_learning_detections"]
        == 43
    )
    assert restore_audits(detection_store) == 1


def test_unreadable_backup_does_not_overwrite_current_configuration(
    client, persistence, detection_store
):
    write_config(persistence, 19)
    snapshot_id = snapshot(client)
    path = persistence.data_dir / "detection_config.json"
    path.write_bytes(b'{"config": unfinished')
    before = path.read_bytes()

    response = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")

    assert response.status_code == 500
    assert path.read_bytes() == before
    assert restore_audits(detection_store) == 0
    assert (
        len(PersistenceManager.list_config_snapshots(detection_store.get_connection()))
        == 1
    )


@pytest.mark.parametrize("include_detection", [True, False])
def test_partial_destination_failure_is_not_reported_as_success(
    client, bridge_app, persistence, detection_store, include_detection
):
    if include_detection:
        write_config(persistence, 19)
    whitelist = persistence.data_dir / "wifi_whitelist.json"
    saved_whitelist = {"whitelist": [{"bssid": "AA:BB:CC:DD:EE:01"}]}
    current_whitelist = {"whitelist": [{"bssid": "AA:BB:CC:DD:EE:02"}]}
    whitelist.write_text(json.dumps(saved_whitelist))
    snapshot_id = snapshot(client)
    write_config(persistence, 43)
    whitelist.write_text(json.dumps(current_whitelist))
    conn = detection_store.get_connection()

    def obstruct_after_backup():
        whitelist.unlink()
        whitelist.mkdir()
        return 0

    # A real SQLite trigger establishes the failure after a complete backup:
    # no filesystem writer/restore function is mocked. The destination then
    # fails os.replace on both ordinary-user and root/container test runners.
    conn.execute(
        "CREATE TRIGGER block_restore_destination AFTER INSERT ON config_snapshots "
        "WHEN NEW.trigger = 'config_change' BEGIN "
        "SELECT obstruct_restore_destination(); END"
    )
    conn.commit()
    from fastapi.testclient import TestClient

    with TestClient(bridge_app, headers=client.headers) as restore_client:
        # DetectionStore connections are thread-local. Register the actual SQL
        # function on the request thread's connection, without overriding auth
        # or any route/storage implementation.
        restore_client.portal.call(
            lambda: detection_store.get_connection().create_function(
                "obstruct_restore_destination", 0, obstruct_after_backup
            )
        )
        response = restore_client.post(
            f"/api/admin/config-snapshots/{snapshot_id}/restore"
        )

    assert response.status_code == 500
    assert "incomplete" in response.json()["detail"]
    assert whitelist.is_dir()
    assert persistence.get_detection_config()["rf_min_learning_detections"] == (
        19 if include_detection else 43
    )
    assert bridge_app.state.detection_config == persistence.get_detection_config()
    assert bridge_app.state.rf_scorer.config.min_learning_detections == (
        19 if include_detection else 43
    )
    assert bridge_app.state.wifi_scorer._whitelisted_bssids == set()
    assert restore_audits(detection_store) == 0
    failed_backup = PersistenceManager.list_config_snapshots(conn)[0]["id"]
    backup = PersistenceManager.get_config_snapshot(conn, failed_backup)["files"]
    assert backup["detection_config.json"]["config"]["rf_min_learning_detections"] == 43
    assert backup["wifi_whitelist.json"] == current_whitelist
    assert list(persistence.data_dir.glob(".*.tmp")) == []
    conn.execute("DROP TRIGGER block_restore_destination")
    conn.commit()
    whitelist.rmdir()

    retry = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")

    assert retry.status_code == 200
    fresh = PersistenceManager(persistence.data_dir, auto_save_interval=0)
    fresh.load_all()
    assert fresh.get_detection_config()["rf_min_learning_detections"] == (
        19 if include_detection else 43
    )
    assert fresh.get_wifi_whitelist() == saved_whitelist["whitelist"]
    assert bridge_app.state.wifi_scorer._whitelisted_bssids == {"AA:BB:CC:DD:EE:01"}
    assert (
        PersistenceManager.get_config_snapshot(conn, failed_backup)["files"] == backup
    )
    assert restore_audits(detection_store) == 1


@pytest.mark.parametrize("content", [b"not JSON", b"\xff\xfe"])
def test_required_backup_rejects_unreadable_json_without_creating_snapshot(
    persistence, detection_store, content
):
    (persistence.data_dir / "detection_config.json").write_bytes(content)
    conn = detection_store.get_connection()
    assert (
        persistence.create_config_snapshot(
            "config_change", db_conn=conn, require_complete=True
        )
        is None
    )
    assert PersistenceManager.list_config_snapshots(conn) == []


def test_required_backup_rejects_existing_directory(persistence, detection_store):
    (persistence.data_dir / "webhooks.json").mkdir()
    conn = detection_store.get_connection()
    assert (
        persistence.create_config_snapshot(
            "config_change", db_conn=conn, require_complete=True
        )
        is None
    )
    assert PersistenceManager.list_config_snapshots(conn) == []


def test_optional_snapshot_keeps_legacy_best_effort_read_policy(
    persistence, detection_store
):
    write_config(persistence, 29)
    (persistence.data_dir / "webhooks.json").write_bytes(b"invalid JSON")
    conn = detection_store.get_connection()
    snapshot_id = persistence.create_config_snapshot("manual", db_conn=conn)
    assert snapshot_id is not None
    saved = PersistenceManager.get_config_snapshot(conn, snapshot_id)
    assert (
        saved["files"]["detection_config.json"]["config"]["rf_min_learning_detections"]
        == 29
    )
    assert "webhooks.json" not in saved["files"]


def test_missing_snapshot_does_not_create_backup_or_change_disk(
    client, persistence, detection_store
):
    write_config(persistence, 37)
    before = (persistence.data_dir / "detection_config.json").read_bytes()
    response = client.post("/api/admin/config-snapshots/999999/restore")
    assert response.status_code == 404
    assert (persistence.data_dir / "detection_config.json").read_bytes() == before
    assert (
        PersistenceManager.list_config_snapshots(detection_store.get_connection()) == []
    )
    assert restore_audits(detection_store) == 0
    assert (
        persistence.restore_config_snapshot(detection_store.get_connection(), 999999)
        == []
    )


def test_empty_snapshot_does_not_claim_success(client, persistence, detection_store):
    # App initialization now persists an empty webhook authority. Remove that
    # file explicitly so this fixture still represents a genuinely empty backup.
    (persistence.data_dir / "webhooks.json").unlink()
    snapshot_id = snapshot(client)
    assert (
        PersistenceManager.get_config_snapshot(
            detection_store.get_connection(), snapshot_id
        )["files"]
        == {}
    )
    write_config(persistence, 37)
    before = (persistence.data_dir / "detection_config.json").read_bytes()
    response = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
    assert response.status_code == 500
    assert response.json()["detail"] == "No files restored"
    assert (persistence.data_dir / "detection_config.json").read_bytes() == before
    assert restore_audits(detection_store) == 0
    backups = PersistenceManager.list_config_snapshots(detection_store.get_connection())
    assert len(backups) == 2
    assert (
        PersistenceManager.get_config_snapshot(
            detection_store.get_connection(), backups[0]["id"]
        )["files"]["detection_config.json"]["config"]["rf_min_learning_detections"]
        == 37
    )


@pytest.mark.parametrize("role", [None, "sensor", "node", "viewer", "analyst"])
def test_restore_requires_authenticated_admin(
    bridge_app, client, persistence, detection_store, role
):
    from fastapi.testclient import TestClient
    from sigrift.lib.security.credentials import generate_api_key, hash_credential

    write_config(persistence, 19)
    snapshot_id = snapshot(client)
    write_config(persistence, 43)
    before = (persistence.data_dir / "detection_config.json").read_bytes()
    headers = {}
    if role is not None:
        raw = generate_api_key(length=32)
        digest, salt = hash_credential(raw)
        persistence.set_key("restore-restricted", digest, salt)
        persistence.set_key_meta("restore-restricted", {"role": role})
        headers = {"X-API-Key": raw}
    with TestClient(bridge_app, headers=headers) as restricted:
        response = restricted.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
    assert response.status_code == (401 if role is None else 403)
    assert (persistence.data_dir / "detection_config.json").read_bytes() == before
    assert restore_audits(detection_store) == 0
    assert (
        len(PersistenceManager.list_config_snapshots(detection_store.get_connection()))
        == 1
    )


def test_restore_all_saved_configuration_and_live_consumers(
    client, bridge_app, persistence, detection_store
):
    from sigrift.bridge.anomaly.scorer import AnomalyDimension
    from sigrift.bridge.anomaly import wifi_scorer

    files = {
        "detection_config.json": {
            "config": {
                "rf_min_learning_detections": 17,
                "rf_dimension_weights": {"power_zscore": 0.37},
                "wifi_dimension_weights": {"new_network": 0.28},
            }
        },
        "alert_rules.json": {"rules": [{"id": "saved-rule", "enabled": False}]},
        "watch_bands.json": {"watch_bands": [{"id": "saved-band", "enabled": False}]},
        "webhooks.json": {
            "webhooks": [
                {
                    "id": "saved-hook",
                    "enabled": False,
                    "url": "https://example.invalid/hook",
                }
            ]
        },
        "syslog_targets.json": {
            "syslog_targets": [
                {"id": "saved-syslog", "enabled": False, "host": "example.invalid"}
            ]
        },
        "wifi_whitelist.json": {"whitelist": [{"bssid": "AA:BB:CC:DD:EE:01"}]},
        "bt_whitelist.json": {"whitelist": [{"device_addr": "AA:BB:CC:DD:EE:02"}]},
        "nodes.json": {"nodes": {"saved-node": {"node_id": "saved-node"}}},
        "schedules.json": {"schedules": {"saved-schedule": {"enabled": False}}},
    }
    assert set(files) == set(PersistenceManager._SNAPSHOT_FILES)
    for name, content in files.items():
        (persistence.data_dir / name).write_text(json.dumps(content), encoding="utf-8")
    snapshot_id = snapshot(client)
    for name in files:
        (persistence.data_dir / name).write_text("{}", encoding="utf-8")
    write_config(persistence, 43)
    before = {
        name: json.loads((persistence.data_dir / name).read_text()) for name in files
    }
    key_bytes = (persistence.data_dir / "keys.json").read_bytes()
    transient = persistence.data_dir / "history.json"
    transient.write_text(json.dumps({"history": {"keep": []}}))

    response = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")

    assert response.status_code == 200
    assert response.json() == {
        "status": "restored",
        "snapshot_id": snapshot_id,
        "restored_files": list(files),
    }
    for name, content in files.items():
        actual = json.loads((persistence.data_dir / name).read_text())
        if name == "webhooks.json":
            restored_hooks = actual["webhooks"]
            assert len(restored_hooks) == len(content["webhooks"])
            for restored, original in zip(restored_hooks, content["webhooks"]):
                assert len(restored["delivery_revision"]) == 32
                assert {
                    k: v for k, v in restored.items() if k != "delivery_revision"
                } == original
        else:
            assert actual == content
    assert (persistence.data_dir / "keys.json").read_bytes() == key_bytes
    assert json.loads(transient.read_text()) == {"history": {"keep": []}}
    config = persistence.get_detection_config()
    assert bridge_app.state.detection_config == config
    assert bridge_app.state.app_state._detection_config == config
    assert bridge_app.state.rf_scorer.config.min_learning_detections == 17
    assert (
        bridge_app.state.rf_scorer.config.weights[AnomalyDimension.POWER_ZSCORE] == 0.37
    )
    assert wifi_scorer._DIMENSION_WEIGHTS["new_network"] == 0.28
    assert bridge_app.state.wifi_scorer._whitelisted_bssids == {"AA:BB:CC:DD:EE:01"}
    assert (
        bridge_app.state.notifier.webhooks
        == json.loads((persistence.data_dir / "webhooks.json").read_text())["webhooks"]
    )
    assert bridge_app.state.notifier.delivery_log == []
    assert (
        bridge_app.state.syslog_forwarder.targets
        == files["syslog_targets.json"]["syslog_targets"]
    )
    fresh = PersistenceManager(persistence.data_dir, auto_save_interval=0)
    fresh.load_all()
    assert fresh.get_detection_config() == config
    for getter, name, field in [
        ("get_alert_rules", "alert_rules.json", "rules"),
        ("get_watch_bands", "watch_bands.json", "watch_bands"),
        ("get_webhooks", "webhooks.json", "webhooks"),
        ("get_syslog_targets", "syslog_targets.json", "syslog_targets"),
        ("get_wifi_whitelist", "wifi_whitelist.json", "whitelist"),
        ("get_bt_whitelist", "bt_whitelist.json", "whitelist"),
        ("get_nodes", "nodes.json", "nodes"),
        ("get_schedules", "schedules.json", "schedules"),
    ]:
        fresh_value = getattr(fresh, getter)()
        live_value = getattr(persistence, getter)()
        assert fresh_value == live_value
        if name == "webhooks.json":
            assert [
                {k: v for k, v in value.items() if k != "delivery_revision"}
                for value in fresh_value
            ] == files[name][field]
        else:
            assert fresh_value == files[name][field]
    conn = detection_store.get_connection()
    backups = PersistenceManager.list_config_snapshots(conn)
    assert len(backups) == 2
    assert (
        PersistenceManager.get_config_snapshot(conn, backups[0]["id"])["files"]
        == before
    )
    assert PersistenceManager.get_config_snapshot(conn, snapshot_id)["files"] == files
    assert restore_audits(detection_store) == 1
    assert (
        conn.execute(
            "SELECT operator FROM audit_log WHERE action = 'admin_config_snapshot_restore'"
        ).fetchone()[0]
        == "master"
    )


def test_restore_succeeds_without_optional_live_consumers(
    client, bridge_app, persistence, detection_store
):
    write_config(persistence, 19)
    snapshot_id = snapshot(client)
    write_config(persistence, 43)
    for name in [
        "app_state",
        "wifi_scorer",
        "rf_scorer",
        "notifier",
        "syslog_forwarder",
    ]:
        setattr(bridge_app.state, name, None)
    response = client.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
    assert response.status_code == 200
    assert bridge_app.state.detection_config["rf_min_learning_detections"] == 19
    assert restore_audits(detection_store) == 1


@pytest.mark.parametrize("scope", ["", "password_change_only", "mfa_setup_only"])
def test_admin_session_scope_is_enforced_before_backup(
    client, bridge_app, persistence, detection_store, scope
):
    from fastapi.testclient import TestClient

    write_config(persistence, 19)
    snapshot_id = snapshot(client)
    write_config(persistence, 43)
    before = (persistence.data_dir / "detection_config.json").read_bytes()
    detection_store.create_user(
        "restore-admin", "restore-session-test-password", role="admin"
    )
    user = detection_store.users.get_user("restore-admin")
    session = detection_store.create_session(user["id"])
    token = session["session_token"]
    if scope:
        detection_store.users.set_session_scope(token, scope)
    assert detection_store.users.get_session(token).get("scope", "") == scope
    with TestClient(bridge_app, headers={"Authorization": f"Bearer {token}"}) as admin:
        response = admin.post(f"/api/admin/config-snapshots/{snapshot_id}/restore")
    if scope:
        assert response.status_code == 403
        assert (persistence.data_dir / "detection_config.json").read_bytes() == before
        assert restore_audits(detection_store) == 0
        assert (
            len(
                PersistenceManager.list_config_snapshots(
                    detection_store.get_connection()
                )
            )
            == 1
        )
    else:
        assert response.status_code == 200
        assert persistence.get_detection_config()["rf_min_learning_detections"] == 19
        assert restore_audits(detection_store) == 1
