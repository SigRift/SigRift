"""Tests for the deployment status endpoint (GET /api/nodes/deployment).

Covers:
  - Authentication requirements (admin role needed)
  - Empty node list returns empty result
  - SSH audit parsing (structured output)
  - SSH failure handling (timeout, non-zero exit, exception)
  - Cache behavior (fresh vs cached responses)
  - Key hash comparison (_compute_key_hash uses SHA-256)
  - Cross-node key consistency annotations
  - Node with no host configured
  - Internal parser helpers (_parse_script_versions, _parse_old_scripts)
"""

from __future__ import annotations

import hashlib
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helper: build a realistic audit script output blob
# ---------------------------------------------------------------------------

def _make_audit_output(
    hostname: str = "edge-01",
    ip: str = "192.168.1.10",
    mac: str = "dc:a6:32:aa:bb:cc",
    key_status: str = "unified",
    key_hash: str = "abc123def456",
) -> str:
    return (
        f"===HOSTNAME===\n{hostname}\n"
        f"===IP===\n{ip}\n"
        f"===MAC===\n{mac}\n"
        "===LINK===\nethernet\neth0\n1000\nn/a\n"
        "===OS===\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nVERSION_ID=\"12\"\n"
        "===KERNEL===\n6.1.0-rpi7-rpi-v8\n"
        "===PYTHON===\n3.11.2\n"
        "===NUMPY===\n1.24.2\n"
        "===ONNXRUNTIME===\n1.17.0\n"
        "===BLEAK===\n0.21.1\n"
        "===SERVICES===\n"
        "rf-edge:active:enabled\n"
        "mlrf-agent:active:enabled\n"
        "mlrf-bt-scanner:active:enabled\n"
        "wifi-scan:inactive:disabled\n"
        "===FIREWALL===\nactive\ndrop\n"
        "===SSH===\nno\nno\n"
        "===DISK===\n 42% 12G\n"
        "===RAM===\n3906 1234\n"
        "===UPTIME===\n86400\n"
        "===MODEL===\n/home/pi/mlrf-agent/rf_classifier_v3.onnx\n2097152\n"
        "===RFSCAN_HASH===\nd41d8cd98f00b204e9800998ecf8427e\n"
        "===SCRIPT_VERSIONS===\n"
        "rf_scan.py:aaa111:1708012345\n"
        "node_agent.py:bbb222:1708012346\n"
        "bt_scanner.py:missing:0\n"
        "wifi_scan.py:ccc333:1708012347\n"
        "===OLD_SCRIPTS===\n"
        "monitor.py:/home/pi/monitor.py\n"
        f"===API_KEYS===\n{key_status}\n{key_hash}\n"
        "===END===\n"
    )


# ---------------------------------------------------------------------------
# Self-contained fixture for deployment endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture
def deploy_client(tmp_path, monkeypatch):
    """Create a minimal FastAPI app with nodes + deployment routers for testing."""
    from sigrift.bridge.routers import deployment, nodes
    from sigrift.bridge.dependencies import RateLimiter, set_rate_limiter
    from sigrift.lib.security.credentials import generate_api_key, hash_credential
    from sigrift.bridge.persistence import PersistenceManager
    from sigrift.bridge.state import AppState
    from sigrift.bridge.detection_store import DetectionStore

    set_rate_limiter(RateLimiter(max_requests=1000, window_seconds=60.0))

    app = FastAPI()

    mk = generate_api_key(length=32)
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    pm = PersistenceManager(data_dir=data_dir, auto_save_interval=0)
    pm.load_all()
    hash_hex, salt = hash_credential(mk)
    pm.set_key("master", hash_hex, salt)

    app.state.persistence = pm
    app.state.app_state = AppState()
    app.state.test_ssh_config = tmp_path / "ssh-targets.json"
    app.state.test_ssh_config.write_text("{}")
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(app.state.test_ssh_config))
    app.state.detection_store = DetectionStore(str(data_dir / "test.db"))

    # Deployment router MUST come before nodes router to avoid /{node_id}
    # catch-all shadowing the /deployment path.
    app.include_router(deployment.router, prefix="/api/nodes", tags=["nodes"])
    app.include_router(nodes.router, prefix="/api/nodes", tags=["nodes"])

    return TestClient(app, headers={"X-API-Key": mk}), app, mk


def _register_ssh_node(client, *, json):
    """Tests deliberately opt registered nodes into the new operator config."""
    import json as json_module

    response = client.post("/api/nodes/register", json=json)
    assert response.status_code == 200
    config = client.app.state.test_ssh_config
    targets = json_module.loads(config.read_text())
    targets[json["node_id"]] = {"host": json["host"], "user": "pi", "port": 22,
        "known_hosts_file": str(config.parent / "known_hosts"),
        "identity_file": str(config.parent / "identity")}
    config.write_text(json_module.dumps(targets))
    return response


# ---------------------------------------------------------------------------
# Unit tests: parsing helpers
# ---------------------------------------------------------------------------


class TestParseScriptVersions:
    def test_normal_lines(self):
        from sigrift.bridge.routers.deployment import _parse_script_versions

        lines = [
            "rf_scan.py:abc123:1708012345",
            "node_agent.py:def456:1708012346",
        ]
        result = _parse_script_versions(lines)
        assert isinstance(result, dict)
        assert isinstance(result["rf_scan.py"], dict)
        assert result["rf_scan.py"]["hash"] == "abc123"
        assert result["rf_scan.py"]["mtime"] == 1708012345
        assert result["node_agent.py"]["hash"] == "def456"

    def test_missing_script(self):
        from sigrift.bridge.routers.deployment import _parse_script_versions

        lines = ["bt_scanner.py:missing:0"]
        result = _parse_script_versions(lines)
        assert result["bt_scanner.py"]["hash"] == "missing"
        assert result["bt_scanner.py"]["mtime"] == 0

    def test_two_part_line(self):
        from sigrift.bridge.routers.deployment import _parse_script_versions

        lines = ["short.py:hashonly"]
        result = _parse_script_versions(lines)
        assert result["short.py"]["hash"] == "hashonly"
        assert result["short.py"]["mtime"] == 0

    def test_empty_input(self):
        from sigrift.bridge.routers.deployment import _parse_script_versions

        assert _parse_script_versions([]) == {}

    def test_invalid_timestamp_defaults_to_zero(self):
        from sigrift.bridge.routers.deployment import _parse_script_versions

        lines = ["script.py:hash123:notanumber"]
        result = _parse_script_versions(lines)
        assert result["script.py"]["mtime"] == 0


class TestParseOldScripts:
    def test_normal_lines(self):
        from sigrift.bridge.routers.deployment import _parse_old_scripts

        lines = [
            "monitor.py:/home/pi/monitor.py",
            "edge_node.py:/opt/rf-edge/edge_node.py",
        ]
        result = _parse_old_scripts(lines)
        assert len(result) == 2
        assert isinstance(result[0], dict)
        assert result[0]["name"] == "monitor.py"
        assert result[0]["path"] == "/home/pi/monitor.py"

    def test_empty_input(self):
        from sigrift.bridge.routers.deployment import _parse_old_scripts

        assert _parse_old_scripts([]) == []

    def test_blank_lines_skipped(self):
        from sigrift.bridge.routers.deployment import _parse_old_scripts

        result = _parse_old_scripts(["", "  ", "monitor.py:/home/pi/monitor.py"])
        assert len(result) == 1
        assert isinstance(result[0], dict)


class TestParseAuditOutput:
    def test_full_audit_output(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        raw = _make_audit_output()
        result = _parse_audit_output(raw)
        assert isinstance(result, dict)

        assert result["hostname"] == "edge-01"
        assert result["ip"] == "192.168.1.10"
        assert result["mac"] == "dc:a6:32:aa:bb:cc"
        assert result["os"] == "Debian GNU/Linux 12 (bookworm)"
        assert result["kernel"] == "6.1.0-rpi7-rpi-v8"
        assert result["python"] == "3.11.2"
        assert result["numpy"] == "1.24.2"
        assert result["onnxruntime"] == "1.17.0"
        assert result["bleak"] == "0.21.1"

    def test_services_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        svcs = result["services"]
        assert isinstance(svcs, dict)
        assert svcs["rf-edge"]["active"] is True
        assert svcs["rf-edge"]["enabled"] is True
        assert svcs["wifi-scan"]["active"] is False
        assert svcs["wifi-scan"]["enabled"] is False

    def test_firewall_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        fw = result["firewall"]
        assert isinstance(fw, dict)
        assert fw["active"] is True
        assert fw["policy"] == "drop"
        assert fw["backend"] == "nftables"

    def test_ssh_hardened_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        ssh = result["ssh"]
        assert isinstance(ssh, dict)
        assert ssh["password_auth"] is False
        assert ssh["root_login"] is False

    def test_disk_ram_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        assert result["disk_used_pct"] == 42
        assert result["disk_avail_gb"] == 12
        assert result["ram_total_mb"] == 3906
        assert result["ram_used_mb"] == 1234

    def test_model_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        assert isinstance(result["model"], dict)
        assert result["model"]["filename"] == "rf_classifier_v3.onnx"
        assert result["model"]["size_bytes"] == 2097152

    def test_link_ethernet(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        link = result["link"]
        assert isinstance(link, dict)
        assert link["type"] == "ethernet"
        assert link["interface"] == "eth0"

    def test_link_wifi(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        raw = (
            "===HOSTNAME===\nwifi-node\n===IP===\n10.0.0.5\n===MAC===\naa:bb:cc:dd:ee:ff\n"
            "===LINK===\nwifi\nwlan0\nMySSID\n-65\n"
            "===OS===\nunknown\n===KERNEL===\n6.1.0\n===PYTHON===\n3.11\n"
            "===NUMPY===\n1.24\n===ONNXRUNTIME===\nmissing\n===BLEAK===\nmissing\n"
            "===SERVICES===\n===FIREWALL===\nmissing\nn/a\n===SSH===\nunknown\nunknown\n"
            "===DISK===\n 10% 50G\n===RAM===\n8000 2000\n===UPTIME===\n3600\n"
            "===MODEL===\nnone\n0\n"
            "===RFSCAN_HASH===\nunknown\n===SCRIPT_VERSIONS===\n===OLD_SCRIPTS===\n"
            "===API_KEYS===\nunified\nhash123\n===END===\n"
        )
        result = _parse_audit_output(raw)
        assert result["link"]["type"] == "wifi"
        assert result["link"]["ssid"] == "MySSID"
        assert result["link"]["signal_dbm"] == -65

    def test_api_keys_unified(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output(key_status="unified"))
        assert result["api_keys_unified"] is True

    def test_api_keys_fragmented(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output(key_status="fragmented"))
        assert result["api_keys_unified"] is False

    def test_key_hash_extracted(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output(key_hash="deadbeef1234"))
        assert result["_key_hash"] == "deadbeef1234"

    def test_empty_output(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output("")
        assert result["hostname"] == "unknown"
        assert result["ip"] == "unknown"

    def test_uptime_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        assert result["uptime_seconds"] == 86400

    def test_script_versions_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        sv = result["script_versions"]
        assert isinstance(sv, dict)
        assert "rf_scan.py" in sv
        assert isinstance(sv["rf_scan.py"], dict)
        assert sv["rf_scan.py"]["hash"] == "aaa111"

    def test_old_scripts_parsed(self):
        from sigrift.bridge.routers.deployment import _parse_audit_output

        result = _parse_audit_output(_make_audit_output())
        assert len(result["old_scripts"]) == 1
        assert isinstance(result["old_scripts"][0], dict)
        assert result["old_scripts"][0]["name"] == "monitor.py"


# ---------------------------------------------------------------------------
# Unit tests: _compute_key_hash (SHA-256)
# ---------------------------------------------------------------------------


class TestComputeKeyHash:
    def test_sha256_from_env(self):
        from sigrift.bridge.routers.deployment import _compute_key_hash

        secret = "my-secret-master-key"
        expected = hashlib.sha256((secret + "\n").encode()).hexdigest()

        with patch.dict("os.environ", {"BRIDGE_MASTER_KEY": secret}):
            result = _compute_key_hash()

        assert result == expected
        assert len(result) == 64  # SHA-256 hex digest length

    def test_sha256_mismatch(self):
        from sigrift.bridge.routers.deployment import _compute_key_hash

        wrong_hash = hashlib.sha256(b"wrong-key\n").hexdigest()

        with patch.dict("os.environ", {"BRIDGE_MASTER_KEY": "correct-key"}):
            result = _compute_key_hash()

        assert result != wrong_hash

    def test_returns_none_when_no_key(self):
        from sigrift.bridge.routers.deployment import _compute_key_hash

        with patch.dict("os.environ", {"BRIDGE_MASTER_KEY": ""}, clear=False), \
             patch("sigrift.bridge.routers.deployment.Path") as mock_path:
            mock_file = MagicMock()
            mock_file.exists.return_value = False
            mock_path.return_value.resolve.return_value.parent.parent.__truediv__.return_value.__truediv__.return_value = mock_file
            result = _compute_key_hash()

        assert result is None  # no key configured

    def test_strips_whitespace_from_key(self):
        from sigrift.bridge.routers.deployment import _compute_key_hash

        secret = "  padded-key  "
        expected = hashlib.sha256((secret.strip() + "\n").encode()).hexdigest()

        with patch.dict("os.environ", {"BRIDGE_MASTER_KEY": secret}):
            result = _compute_key_hash()

        assert result == expected

    def test_sha256_not_md5(self):
        """Verify the hash is SHA-256, not MD5 (Sprint 2 fix)."""
        from sigrift.bridge.routers.deployment import _compute_key_hash

        secret = "test-key-for-hash-algo"
        md5_hash = hashlib.md5((secret + "\n").encode()).hexdigest()
        sha256_hash = hashlib.sha256((secret + "\n").encode()).hexdigest()

        with patch.dict("os.environ", {"BRIDGE_MASTER_KEY": secret}):
            result = _compute_key_hash()

        assert result == sha256_hash
        assert result != md5_hash
        # MD5 is 32 hex chars, SHA-256 is 64
        assert len(result) == 64


# ---------------------------------------------------------------------------
# Unit tests: _ssh_audit_node
# ---------------------------------------------------------------------------


class TestSSHAuditNode:
    def test_successful_audit(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        audit_output = _make_audit_output()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = audit_output

        with patch("sigrift.bridge.routers.deployment.subprocess.run", return_value=mock_result):
            result = _ssh_audit_node("192.168.1.10")

        assert isinstance(result, dict)
        assert result["reachable"] is True
        assert result["hostname"] == "edge-01"

    def test_ssh_nonzero_exit(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        mock_result = MagicMock()
        mock_result.returncode = 255
        mock_result.stderr = "Connection refused"

        with patch("sigrift.bridge.routers.deployment.subprocess.run", return_value=mock_result):
            result = _ssh_audit_node("10.0.0.1")

        assert isinstance(result, dict)
        assert result["reachable"] is False
        assert isinstance(result["error"], str)
        assert result["ssh_status"] == "unreachable"
        assert "connection" in result["error"].lower()

    def test_ssh_timeout(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        with patch(
            "sigrift.bridge.routers.deployment.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=10),
        ):
            result = _ssh_audit_node("10.0.0.2")

        assert isinstance(result, dict)
        assert result["reachable"] is False
        assert result["error"] == "SSH timeout"

    def test_ssh_generic_exception(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        with patch(
            "sigrift.bridge.routers.deployment.subprocess.run",
            side_effect=OSError("No such file or directory"),
        ):
            result = _ssh_audit_node("10.0.0.3")

        assert isinstance(result, dict)
        assert result["reachable"] is False
        assert result["ssh_status"] == "audit_error"
        assert "could not complete" in result["error"]

    def test_insecure_host_key_environment_does_not_override_strict_audit(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = _make_audit_output()

        with patch.dict("os.environ", {"BRIDGE_SSH_HOST_KEY_CHECKING": "accept-new"}), \
             patch("sigrift.bridge.routers.deployment.subprocess.run", return_value=mock_result) as mock_run:
            _ssh_audit_node("10.0.0.4")

        call_args = mock_run.call_args[0][0]
        assert "StrictHostKeyChecking=yes" in call_args
        assert "StrictHostKeyChecking=accept-new" not in call_args

    def test_default_user_is_pi(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = _make_audit_output()

        with patch("sigrift.bridge.routers.deployment.subprocess.run", return_value=mock_result) as mock_run:
            _ssh_audit_node("10.0.0.5")

        call_args = mock_run.call_args[0][0]
        assert call_args[call_args.index("-l") + 1] == "pi"
        assert call_args[call_args.index("--") + 1] == "10.0.0.5"

    def test_custom_user(self):
        from sigrift.bridge.routers.deployment import _ssh_audit_node

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = _make_audit_output()

        with patch("sigrift.bridge.routers.deployment.subprocess.run", return_value=mock_result) as mock_run:
            _ssh_audit_node("10.0.0.6", user="admin")

        call_args = mock_run.call_args[0][0]
        assert call_args[call_args.index("-l") + 1] == "admin"
        assert call_args[call_args.index("--") + 1] == "10.0.0.6"


# ---------------------------------------------------------------------------
# Endpoint tests: GET /api/nodes/deployment
# ---------------------------------------------------------------------------


class TestDeploymentEndpoint:
    def test_cached_ssh_status_keeps_actual_scanner_expiry_and_failure_current(self, deploy_client):
        from datetime import datetime, timedelta, timezone
        client, app, _ = deploy_client
        assert client.post("/api/nodes/register", json={"node_id": "wifi-node", "host": "edge"}).status_code == 200
        url = "/api/nodes/wifi-node/scanner-status"
        assert client.post(url, json={"protocol": "wifi", "state": "running"}).status_code == 200
        first = client.get("/api/nodes/deployment").json()
        assert first["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is True
        node = app.state.persistence.get_nodes()["wifi-node"]
        node["_scanner_reports"]["wifi"]["reported_at"] = (datetime.now(timezone.utc) - timedelta(seconds=121)).isoformat()
        app.state.persistence.set_node("wifi-node", node)
        expired = client.get("/api/nodes/deployment").json()
        assert expired["cached"] is True
        assert expired["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is False
        assert first["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is True
        for state in ("error", "stopped", "running"):
            assert client.post(url, json={"protocol": "wifi", "state": state}).status_code == 200
            response = client.get("/api/nodes/deployment").json()
            report = response["nodes"]["wifi-node"]["scanner_status"]["wifi"]
            assert response["cached"] is True and report["state"] == state
            assert report["active"] is (state == "running")

    def test_actual_api_invalid_ssh_file_does_not_hide_scanner_error(self, deploy_client):
        client, app, _ = deploy_client
        assert client.post("/api/nodes/register", json={"node_id": "sdr-node", "host": "edge"}).status_code == 200
        assert client.post("/api/nodes/sdr-node/scanner-status", json={"protocol": "sdr", "state": "error"}).status_code == 200
        app.state.test_ssh_config.write_text('{"invalid":')
        with patch("sigrift.bridge.routers.deployment._ssh_audit_node") as ssh:
            response = client.get("/api/nodes/deployment")
        assert response.status_code == 200
        node = response.json()["nodes"]["sdr-node"]
        assert node["ssh_status"] == "configuration_error"
        assert node["scanner_status"]["sdr"]["state"] == "error"
        assert node["scanner_status"]["sdr"]["active"] is False
        ssh.assert_not_called()

    def test_default_container_setup_reports_live_scanner_without_ssh(self, deploy_client, monkeypatch):
        client, _, _ = deploy_client
        monkeypatch.delenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", raising=False)
        registered = client.post("/api/nodes/register", json={"node_id": "local-edge", "host": "edge"})
        assert registered.status_code == 200
        report = client.post("/api/nodes/local-edge/scanner-status", json={"protocol": "sdr", "state": "running"})
        assert report.status_code == 200
        with patch("sigrift.bridge.routers.deployment._ssh_audit_node") as ssh:
            response = client.get("/api/nodes/deployment")
        assert response.status_code == 200
        node = response.json()["nodes"]["local-edge"]
        assert node["node_status"] == "active"
        assert node["scanner_status"]["sdr"]["active"] is True
        assert node["ssh_status"] == "not_configured"
        assert node["reachable"] is False
        ssh.assert_not_called()

    def test_foreign_admin_key_cannot_read_deployment_reports(self, deploy_client):
        from sigrift.lib.security.credentials import generate_api_key, hash_credential
        _, app, _ = deploy_client
        credential = generate_api_key(length=32)
        digest, salt = hash_credential(credential)
        app.state.persistence.set_key("foreign-admin", digest, salt)
        app.state.persistence.set_key_meta("foreign-admin", {"role": "admin", "tenant_id": "other"})
        with TestClient(app, headers={"X-API-Key": credential}) as client:
            with patch("sigrift.bridge.routers.deployment._ssh_audit_node") as ssh:
                assert client.get("/api/nodes/deployment").status_code == 403
        ssh.assert_not_called()

    def test_requires_auth(self, deploy_client):
        _, app, _ = deploy_client
        with TestClient(app) as tc:
            resp = tc.get("/api/nodes/deployment")
            assert resp.status_code in (401, 403)

    def test_requires_admin_role(self, deploy_client):
        """Viewer-level keys should be rejected with 403."""
        from sigrift.lib.security.credentials import generate_api_key, hash_credential

        _, app, _ = deploy_client
        viewer_key = generate_api_key(length=32)
        persistence = app.state.persistence
        h, s = hash_credential(viewer_key)
        persistence.set_key("viewer-key", h, s)
        persistence.set_key_meta("viewer-key", {"role": "viewer"})

        tc = TestClient(app, headers={"X-API-Key": viewer_key})
        resp = tc.get("/api/nodes/deployment")
        assert resp.status_code == 403

    def test_empty_nodes_returns_empty(self, deploy_client):
        client, _, _ = deploy_client
        resp = client.get("/api/nodes/deployment")
        assert resp.status_code == 200
        data = resp.json()
        assert data["nodes"] == {}
        assert data["cached"] is False

    def test_response_structure(self, deploy_client):
        client, _, _ = deploy_client
        resp = client.get("/api/nodes/deployment")
        data = resp.json()
        assert isinstance(data, dict)
        assert "cached" in data
        assert isinstance(data["cached"], bool)
        assert "cached_at" in data
        assert "cache_ttl_sec" in data
        assert isinstance(data["cache_ttl_sec"], int)
        assert "nodes" in data
        assert isinstance(data["nodes"], dict)
        assert data["cache_ttl_sec"] == 300

    def test_node_no_host_returns_unreachable(self, deploy_client):
        client, _, _ = deploy_client
        client.post("/api/nodes/register", json={
            "node_id": "node-no-host",
            "host": "",
            "port": 8080,
        })

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node") as mock_ssh:
            resp = client.get("/api/nodes/deployment")

        assert resp.status_code == 200
        node_info = resp.json()["nodes"].get("node-no-host", {})
        assert node_info["reachable"] is False
        assert node_info["ssh_status"] == "not_configured"
        assert "not configured" in node_info["error"]
        mock_ssh.assert_not_called()

    def test_successful_audit_with_registered_node(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "edge-01",
            "host": "192.168.1.10",
            "port": 8080,
        })

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output())
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh):
            resp = client.get("/api/nodes/deployment")

        assert resp.status_code == 200
        data = resp.json()
        assert data["cached"] is False
        assert "edge-01" in data["nodes"]
        node = data["nodes"]["edge-01"]
        assert isinstance(node, dict)
        assert node["reachable"] is True
        assert node["hostname"] == "edge-01"
        assert "_key_hash" not in node

    def test_ssh_failure_returns_unreachable_node(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "edge-fail",
            "host": "10.0.0.99",
            "port": 8080,
        })

        def fail_ssh(host, user="pi", **kwargs):
            return {"reachable": False, "error": "SSH timeout"}

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fail_ssh):
            resp = client.get("/api/nodes/deployment")

        assert resp.status_code == 200
        node = resp.json()["nodes"]["edge-fail"]
        assert node["reachable"] is False
        assert "SSH timeout" in node["error"]

    def test_cache_returns_cached_result(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "edge-cache",
            "host": "10.0.0.1",
            "port": 8080,
        })

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output())
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh) as mock_ssh:
            resp1 = client.get("/api/nodes/deployment")
            assert resp1.json()["cached"] is False
            assert mock_ssh.call_count == 1

            resp2 = client.get("/api/nodes/deployment")
            assert resp2.json()["cached"] is True
            assert mock_ssh.call_count == 1

    def test_refresh_bypasses_cache(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "edge-refresh",
            "host": "10.0.0.2",
            "port": 8080,
        })

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output())
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh) as mock_ssh:
            resp1 = client.get("/api/nodes/deployment")
            assert resp1.json()["cached"] is False

            resp2 = client.get("/api/nodes/deployment?refresh=true")
            assert resp2.json()["cached"] is False
            assert mock_ssh.call_count == 2

    def test_cross_node_key_consistency_all_match(self, deploy_client):
        client, _, _ = deploy_client
        for nid in ("n1", "n2"):
            _register_ssh_node(client, json={
                "node_id": nid,
                "host": f"10.0.0.{nid[-1]}",
                "port": 8080,
            })

        same_hash = "aabbccdd1122"

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output(key_hash=same_hash))
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh), \
             patch("sigrift.bridge.routers.deployment._compute_key_hash", return_value=same_hash):
            resp = client.get("/api/nodes/deployment")

        data = resp.json()
        for nid in ("n1", "n2"):
            assert data["nodes"][nid]["api_keys_consistent"] is True
            assert data["nodes"][nid]["api_key_bridge_valid"] is True

    def test_bridge_key_valid_false_when_no_match(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "bv1",
            "host": "10.0.2.1",
            "port": 8080,
        })

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output(key_hash="node_hash"))
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh), \
             patch("sigrift.bridge.routers.deployment._compute_key_hash", return_value="bridge_hash"):
            resp = client.get("/api/nodes/deployment")

        assert resp.json()["nodes"]["bv1"]["api_key_bridge_valid"] is False

    def test_key_hash_stripped_from_response(self, deploy_client):
        client, _, _ = deploy_client
        _register_ssh_node(client, json={
            "node_id": "strip-test",
            "host": "10.0.3.1",
            "port": 8080,
        })

        def fake_ssh(host, user="pi", **kwargs):
            from sigrift.bridge.routers.deployment import _parse_audit_output
            parsed = _parse_audit_output(_make_audit_output(key_hash="secret_hash"))
            parsed["reachable"] = True
            return parsed

        with patch("sigrift.bridge.routers.deployment._ssh_audit_node", side_effect=fake_ssh), \
             patch("sigrift.bridge.routers.deployment._compute_key_hash", return_value=None):
            resp = client.get("/api/nodes/deployment")

        node = resp.json()["nodes"]["strip-test"]
        assert "_key_hash" not in node
