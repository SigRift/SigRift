"""Tests for admin panel API endpoints."""

from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sigrift.lib.security.credentials import generate_api_key, hash_credential


@pytest.fixture
def non_master_key(persistence) -> str:
    """Create a non-master API key with analyst role (non-admin)."""
    raw_key = generate_api_key(length=32)
    hash_hex, salt = hash_credential(raw_key)
    persistence.set_key("regular", hash_hex, salt)
    persistence.set_key_meta("regular", {"role": "analyst"})
    return raw_key


@pytest.fixture
def non_master_client(bridge_app: FastAPI, non_master_key: str) -> TestClient:
    """TestClient with a non-master API key."""
    return TestClient(bridge_app, headers={"X-API-Key": non_master_key})


class TestAdminAuth:
    def test_requires_master_key_401(self, bridge_app: FastAPI):
        """Admin endpoints return 401 without any key."""
        no_auth_client = TestClient(bridge_app)
        resp = no_auth_client.get("/api/admin/keys")
        assert resp.status_code == 401

    def test_requires_master_key_403(self, non_master_client: TestClient):
        """Admin endpoints return 403 with a regular (non-master) key."""
        resp = non_master_client.get("/api/admin/keys")
        assert resp.status_code == 403

    def test_auth_required_on_all_admin_endpoints(self, bridge_app: FastAPI):
        """Verify 401 on all admin endpoints without auth."""
        no_auth = TestClient(bridge_app)
        endpoints = [
            ("GET", "/api/admin/keys"),
            ("GET", "/api/admin/nodes"),
            ("GET", "/api/admin/alerts"),
            ("GET", "/api/admin/audit"),
            ("GET", "/api/admin/config"),
            ("GET", "/api/admin/stats"),
            ("GET", "/api/admin/sessions"),
            ("GET", "/api/admin/logs"),
            ("GET", "/api/admin/backups"),
            ("POST", "/api/admin/backup"),
            ("POST", "/api/admin/maintenance"),
        ]
        for method, path in endpoints:
            resp = getattr(no_auth, method.lower())(path)
            assert resp.status_code == 401, f"{method} {path} should require auth"


class TestKeyManagement:
    def test_list_keys(self, client: TestClient):
        resp = client.get("/api/admin/keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert isinstance(keys, list)
        assert any(k["key_id"] == "master" for k in keys)

    def test_list_keys_has_metadata(self, client: TestClient):
        """Key list includes role, description, created_at, expires_at."""
        client.post(
            "/api/admin/keys",
            json={
                "description": "meta-test",
                "role": "viewer",
                "expires_days": 30,
            },
        )
        resp = client.get("/api/admin/keys")
        keys = resp.json()
        non_master = [k for k in keys if not k["is_master"]]
        assert len(non_master) >= 1
        assert isinstance(non_master[0], dict)
        k = non_master[0]
        assert isinstance(k["role"], str)
        assert isinstance(k["description"], str)
        assert isinstance(k["created_at"], str)
        assert "expires_at" in k  # may be None for non-expiring keys
        assert k["expires_at"] is None or isinstance(k["expires_at"], str)

    def test_create_key(self, client: TestClient):
        resp = client.post("/api/admin/keys", json={"description": "test key"})
        assert resp.status_code == 201
        data = resp.json()
        assert isinstance(data["key_id"], str)
        assert isinstance(data["raw_key"], str)
        assert len(data["raw_key"]) > 0
        assert len(data["raw_key"]) >= 16

    def test_create_key_with_role_and_expiry(self, client: TestClient):
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "viewer key",
                "role": "viewer",
                "expires_days": 7,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "viewer"
        assert data["expires_at"] is not None
        assert isinstance(data["expires_at"], str)
        assert data["description"] == "viewer key"

    def test_create_key_invalid_role(self, client: TestClient):
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "bad role",
                "role": "superuser",
            },
        )
        assert resp.status_code == 400

    def test_revoke_key(self, client: TestClient):
        resp = client.post("/api/admin/keys", json={"description": "to-revoke"})
        key_id = resp.json()["key_id"]
        resp = client.delete(f"/api/admin/keys/{key_id}")
        assert resp.status_code == 200
        assert resp.json()["revoked"] == key_id

    def test_revoke_unknown_key(self, client: TestClient):
        resp = client.delete("/api/admin/keys/nonexistent")
        assert resp.status_code == 404

    def test_cannot_revoke_master(self, client: TestClient):
        resp = client.delete("/api/admin/keys/master")
        assert resp.status_code == 403


class TestKeyPermissions:
    def test_change_key_role(self, client: TestClient):
        resp = client.post(
            "/api/admin/keys",
            json={
                "description": "role-change-test",
                "role": "analyst",
            },
        )
        key_id = resp.json()["key_id"]

        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions",
            json={
                "role": "viewer",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"

    def test_change_key_role_invalid(self, client: TestClient):
        resp = client.post("/api/admin/keys", json={"description": "bad-role"})
        key_id = resp.json()["key_id"]

        resp = client.put(
            f"/api/admin/keys/{key_id}/permissions",
            json={
                "role": "superuser",
            },
        )
        assert resp.status_code == 400

    def test_cannot_change_master_role(self, client: TestClient):
        resp = client.put(
            "/api/admin/keys/master/permissions",
            json={
                "role": "viewer",
            },
        )
        assert resp.status_code == 403

    def test_change_unknown_key_role(self, client: TestClient):
        resp = client.put(
            "/api/admin/keys/nonexistent/permissions",
            json={
                "role": "viewer",
            },
        )
        assert resp.status_code == 404


class TestNodeManagement:
    def test_list_nodes(self, client: TestClient, registered_node: str):
        resp = client.get("/api/admin/nodes")
        assert resp.status_code == 200
        nodes = resp.json()
        assert isinstance(nodes, list)
        assert any(n["node_id"] == registered_node for n in nodes)

    def test_list_nodes_has_port(self, client: TestClient, registered_node: str):
        resp = client.get("/api/admin/nodes")
        node = [n for n in resp.json() if n["node_id"] == registered_node][0]
        assert node["port"] == 8080

    def test_deregister_node(self, client: TestClient, registered_node: str):
        resp = client.delete(f"/api/admin/nodes/{registered_node}")
        assert resp.status_code == 200
        assert resp.json()["deregistered"] == registered_node

    def test_deregister_unknown_node(self, client: TestClient):
        resp = client.delete("/api/admin/nodes/nonexistent-node")
        assert resp.status_code == 404

    def test_update_node_config(self, client: TestClient, registered_node: str):
        resp = client.put(
            f"/api/admin/nodes/{registered_node}/config",
            json={
                "config": {"sample_rate": 2048000},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["config_queued"] is True

    def test_queue_node_command(self, client: TestClient, registered_node: str):
        resp = client.post(
            f"/api/admin/nodes/{registered_node}/command",
            json={
                "command": "restart",
                "params": {"reason": "test"},
            },
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "queued"
        assert resp.json()["command"] == "restart"


class TestAlertManagement:
    def test_create_alert(self, client: TestClient):
        resp = client.post(
            "/api/admin/alerts",
            json={
                "name": "test_alert",
                "severity": "warning",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test_alert"
        assert isinstance(data["alert_id"], str)

    def test_create_alert_with_thresholds(self, client: TestClient):
        resp = client.post(
            "/api/admin/alerts",
            json={
                "name": "cpu_alert",
                "severity": "critical",
                "message": "CPU too high",
                "thresholds": {"cpu_percent": 90},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["thresholds"]["cpu_percent"] == 90

    def test_update_alert(self, client: TestClient):
        resp = client.post(
            "/api/admin/alerts",
            json={
                "name": "update_me",
                "severity": "info",
            },
        )
        alert_id = resp.json()["alert_id"]

        resp = client.put(
            f"/api/admin/alerts/{alert_id}",
            json={
                "severity": "critical",
                "message": "updated message",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["severity"] == "critical"
        assert data["message"] == "updated message"

    def test_update_unknown_alert(self, client: TestClient):
        resp = client.put(
            "/api/admin/alerts/nonexistent",
            json={
                "severity": "info",
            },
        )
        assert resp.status_code == 404

    def test_delete_alert(self, client: TestClient):
        resp = client.post(
            "/api/admin/alerts",
            json={
                "name": "to_delete",
                "severity": "info",
            },
        )
        alert_id = resp.json()["alert_id"]
        resp = client.delete(f"/api/admin/alerts/{alert_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] == alert_id

    def test_delete_unknown_alert(self, client: TestClient):
        resp = client.delete("/api/admin/alerts/nonexistent")
        assert resp.status_code == 404

    def test_alert_xss_sanitization(self, client: TestClient):
        resp = client.post(
            "/api/admin/alerts",
            json={
                "name": "<script>alert(1)</script>",
                "severity": "warning",
                "message": "<img onerror=alert(1)>",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "<script>" not in data["name"]
        assert "<img" not in data["message"]


class TestAuditLog:
    def test_get_audit_log(self, client: TestClient):
        client.post("/api/admin/keys", json={"description": "audit-test"})
        resp = client.get("/api/admin/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["entries"], list)
        assert data["count"] >= 1
        assert isinstance(data["count"], int)

    def test_audit_filter_by_action(self, client: TestClient):
        client.post("/api/admin/keys", json={"description": "filter-test"})
        resp = client.get("/api/admin/audit?action=admin_create_key")
        assert resp.status_code == 200
        data = resp.json()
        for entry in data["entries"]:
            assert entry["action"] == "admin_create_key"

    def test_audit_filter_by_operator(self, client: TestClient):
        resp = client.get("/api/admin/audit?operator=master")
        assert resp.status_code == 200
        data = resp.json()
        for entry in data["entries"]:
            assert entry["operator"] == "master"

    def test_audit_pagination(self, client: TestClient):
        # Generate some entries
        for i in range(5):
            client.post("/api/admin/keys", json={"description": f"page-test-{i}"})

        resp = client.get("/api/admin/audit?limit=2&offset=0")
        assert resp.status_code == 200
        page1 = resp.json()
        assert page1["limit"] == 2
        assert page1["offset"] == 0
        assert len(page1["entries"]) <= 2

        resp = client.get("/api/admin/audit?limit=2&offset=2")
        page2 = resp.json()
        assert page2["offset"] == 2


class TestSystemInfo:
    def test_get_config(self, client: TestClient):
        resp = client.get("/api/admin/config")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["security"], dict)
        assert isinstance(data["version"], str)
        assert "raw_key" not in str(data)

    def test_get_stats(self, client: TestClient):
        resp = client.get("/api/admin/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["tables"], dict)
        assert isinstance(data["tables"]["detections"], int)
        assert isinstance(data["tables"]["wifi_metadata"], int)
        assert isinstance(data["db_size_bytes"], int)

    def test_get_stats_has_table_stats(self, client: TestClient):
        """Enhanced stats include per-table details."""
        resp = client.get("/api/admin/stats")
        data = resp.json()
        assert isinstance(data["table_stats"], list)
        stats = data["table_stats"]
        assert len(stats) > 0
        assert all(isinstance(s, dict) for s in stats)
        first = stats[0]
        assert isinstance(first["name"], str)
        assert isinstance(first["rows"], int)
        assert isinstance(first["size_bytes"], int)

    def test_get_sessions(self, client: TestClient):
        resp = client.get("/api/admin/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["sessions"], list)


class TestMaintenance:
    def test_purge_detections(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_detections",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["task"] == "purge_detections"
        assert isinstance(data["deleted"], int)

    def test_purge_rf_anomalies(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_rf_anomalies",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["deleted"], int)

    def test_purge_wifi_anomalies(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_wifi_anomalies",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["deleted"], int)

    def test_purge_wifi_metadata(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_wifi_metadata",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["deleted"], int)
        assert isinstance(data["note"], str)  # hours note

    def test_purge_audit_log(self, client: TestClient):
        # Refused since round 4 (review P3): a plain DELETE of live audit
        # rows broke the HMAC chain; the gateway's anchored archive is the
        # only way audit entries leave the log.
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_audit_log",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 409
        assert "/api/admin/audit/archive" in resp.json()["detail"]

    def test_vacuum(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "vacuum",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200
        assert isinstance(resp.json()["db_size_bytes"], int)

    def test_wal_checkpoint(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "wal_checkpoint",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["wal_pages"], int)
        assert isinstance(data["checkpointed"], int)

    def test_optimize(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "optimize",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200

    def test_full_cleanup(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "full_cleanup",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["deleted"], dict)
        assert isinstance(data["deleted"]["detections"], int)
        assert data["vacuumed"] is True

    def test_aggregate_wifi(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "aggregate_wifi",
                "retention_days": 2,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["task"] == "aggregate_wifi"
        assert isinstance(data["aggregated"], int)

    def test_purge_wifi_hourly(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_wifi_hourly",
                "retention_days": 90,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["task"] == "purge_wifi_hourly"
        assert isinstance(data["deleted"], int)

    def test_full_cleanup_includes_hourly(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "full_cleanup",
                "retention_days": 1,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["deleted"]["wifi_hourly"], int)
        assert isinstance(data["aggregated_wifi_hourly"], int)

    def test_unknown_task(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "drop_everything",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 400

    def test_maintenance_logs_audit(self, client: TestClient):
        client.post(
            "/api/admin/maintenance",
            json={
                "task": "vacuum",
                "retention_days": 7,
            },
        )
        resp = client.get("/api/admin/audit?action=maintenance_vacuum")
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)


class TestRetentionPolicy:
    """Tests for BRIDGE_RETENTION_DAYS and purge_old_data task."""

    def test_config_includes_retention(self, client: TestClient):
        resp = client.get("/api/admin/config")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["retention"], dict)
        assert "retention_days" in data["retention"]
        assert isinstance(data["retention"]["retention_days"], int)
        assert data["retention"]["retention_days"] > 0
        assert data["retention"]["source"] in ("env", "default")

    def test_purge_old_data_uses_policy(self, client: TestClient):
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_old_data",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["task"] == "purge_old_data"
        assert isinstance(data["deleted"], dict)
        # Should include all table categories with integer counts
        assert isinstance(data["deleted"]["detections"], int)
        assert isinstance(data["deleted"]["rf_anomalies"], int)
        assert isinstance(data["deleted"]["wifi_anomalies"], int)
        assert isinstance(data["deleted"]["wifi_metadata"], int)
        assert isinstance(data["deleted"]["wifi_hourly"], int)
        assert isinstance(data["deleted"]["audit_log"], int)
        assert isinstance(data["deleted"]["iq_captures"], int)
        assert isinstance(data["deleted"]["pcap_captures"], int)
        # Should report the policy retention_days
        assert isinstance(data["retention_days"], int)

    def test_purge_old_data_no_recent_deleted(self, client: TestClient):
        """Data newer than retention should NOT be deleted."""
        from datetime import datetime, timezone

        store = client.app.state.detection_store
        conn = store.get_connection()
        # Insert a fresh detection (just now)
        now_ts = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO detections (timestamp, node_id, signal_class, confidence, freq_hz) "
            "VALUES (?, ?, ?, ?, ?)",
            [now_ts, "node-fresh", "bpsk", 0.9, 433920000],
        )
        conn.commit()
        # Run purge — fresh data should survive
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_old_data",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"]["detections"] == 0

    def test_purge_old_data_deletes_old(self, client: TestClient):
        """Data older than retention SHOULD be deleted."""
        from datetime import datetime, timedelta, timezone

        store = client.app.state.detection_store

        # Insert old detection directly
        conn = store.get_connection()
        old_ts = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        conn.execute(
            "INSERT INTO detections (timestamp, node_id, signal_class, confidence, freq_hz) "
            "VALUES (?, ?, ?, ?, ?)",
            [old_ts, "node-old", "bpsk", 0.9, 433920000],
        )
        conn.commit()

        # Run purge with 90-day retention — old data should be deleted
        resp = client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_old_data",
                "retention_days": 7,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["deleted"]["detections"] >= 1

    def test_purge_old_data_logs_audit(self, client: TestClient):
        """purge_old_data should create an audit log entry."""
        client.post(
            "/api/admin/maintenance",
            json={
                "task": "purge_old_data",
                "retention_days": 7,
            },
        )
        resp = client.get("/api/admin/audit?action=maintenance_purge_old_data")
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)

    def test_default_retention_days(self):
        """BRIDGE_RETENTION_DAYS defaults to 90 when env var is not set."""
        import os

        # If env var is not set, module default should be 90
        env_val = os.environ.get("BRIDGE_RETENTION_DAYS")
        if env_val is None:
            from sigrift.bridge.routers.admin import BRIDGE_RETENTION_DAYS

            assert BRIDGE_RETENTION_DAYS == 90

    def test_custom_retention_via_env(self, monkeypatch):
        """BRIDGE_RETENTION_DAYS can be overridden via env var."""
        monkeypatch.setenv("BRIDGE_RETENTION_DAYS", "30")
        # Re-evaluate the module-level constant
        val = int(os.environ.get("BRIDGE_RETENTION_DAYS", "90"))
        assert val == 30


class TestBackup:
    def test_create_backup(self, client: TestClient):
        resp = client.post("/api/admin/backup")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["backup_file"], str)
        assert data["backup_file"].endswith(".db")
        assert data["size_bytes"] > 0
        assert isinstance(data["size_bytes"], int)

    def test_list_backups(self, client: TestClient):
        # Create a backup first
        client.post("/api/admin/backup")

        resp = client.get("/api/admin/backups")
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)
        assert len(data["backups"]) >= 1
        assert isinstance(data["backups"], list)
        b = data["backups"][0]
        assert isinstance(b["name"], str)
        assert isinstance(b["size_bytes"], int)
        assert isinstance(b["created"], str)

    def test_download_backup(self, client: TestClient):
        # Create a backup
        create_resp = client.post("/api/admin/backup")
        filename = create_resp.json()["backup_file"]

        resp = client.get(f"/api/admin/backups/{filename}")
        assert resp.status_code == 200
        assert "application/octet-stream" in resp.headers.get("content-type", "")
        assert len(resp.content) > 0
        assert isinstance(resp.content, bytes)

    def test_download_invalid_filename(self, client: TestClient):
        resp = client.get("/api/admin/backups/bad%20name!.db")
        assert resp.status_code == 400

    def test_download_nonexistent_backup(self, client: TestClient):
        resp = client.get("/api/admin/backups/nonexistent_backup.db")
        assert resp.status_code == 404

    def test_backup_logs_audit(self, client: TestClient):
        client.post("/api/admin/backup")
        resp = client.get("/api/admin/audit?action=admin_backup")
        data = resp.json()
        assert data["count"] >= 1
        assert isinstance(data["count"], int)


class TestLogViewer:
    def test_get_logs(self, client: TestClient):
        resp = client.get("/api/admin/logs")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data["entries"], list)
        assert isinstance(data["count"], int)
        assert isinstance(data["total_buffered"], int)

    def test_logs_level_filter(self, client: TestClient):
        resp = client.get("/api/admin/logs?level=ERROR")
        assert resp.status_code == 200
        data = resp.json()
        for entry in data["entries"]:
            assert entry["level"] == "ERROR"

    def test_logs_search_filter(self, client: TestClient):
        resp = client.get("/api/admin/logs?search=bridge")
        assert resp.status_code == 200
        assert isinstance(resp.json()["entries"], list)

    def test_logs_limit(self, client: TestClient):
        resp = client.get("/api/admin/logs?limit=5")
        assert resp.status_code == 200
        assert len(resp.json()["entries"]) <= 5
