"""Deployment status: what a node's audit output can and cannot make the Bridge claim.

The audit text comes from the audited host, so the parser must take it as
untrusted: stray, partial or non-numeric lines are dropped or read as zero,
never as a reason to fail the whole report. The Bridge-key comparison may only
report ``True``/``False`` when it actually compared; otherwise it is unknown.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone

from sigrift.bridge.routers import deployment

AUDIT = "===HOSTNAME===\nedge-01\n===API_KEYS===\nunified\nnode-key-digest\n===END===\n"


def test_malformed_values_read_as_zero_and_stray_lines_are_ignored():
    raw = (
        "banner printed before the first section\n"
        "===HOSTNAME===\nedge-07\n"
        "===LINK===\nwifi\nwlan0\nWorkshop\n-61dBm\n"
        "===DISK===\n 17% 3.5G\n"
        "===RAM===\nplenty used\n"
        "===UPTIME===\nforever\n"
        "===MODEL===\n/opt/rf-edge/model_v4.onnx\nlarge\n"
        "===API_KEYS===\nunified\ndigest-7\n"
        "===END===\n"
        "trailing text after the end marker\n"
    )
    parsed = deployment._parse_audit_output(raw)
    assert parsed["hostname"] == "edge-07"
    assert parsed["link"] == {
        "type": "wifi",
        "interface": "wlan0",
        "ssid": "Workshop",
        "signal_dbm": 0,
    }
    assert parsed["disk_used_pct"] == 17 and parsed["disk_avail_gb"] == 0
    assert parsed["ram_total_mb"] == 0 and parsed["ram_used_mb"] == 0
    assert parsed["uptime_seconds"] == 0
    assert parsed["model"] == {"filename": "model_v4.onnx", "size_bytes": 0}
    assert parsed["_key_hash"] == "digest-7"
    flattened = json.dumps(parsed)
    assert "banner" not in flattened and "trailing" not in flattened


def test_partial_list_lines_are_dropped_not_guessed():
    raw = (
        "===HOSTNAME===\nedge-08\n"
        "===SERVICES===\nrf-edge:active:enabled\nbroken-line\nreadsb:inactive\n"
        "===SCRIPT_VERSIONS===\nno-separator\nrf_scan.py:abc123:1708012345\n"
        "===OLD_SCRIPTS===\nmonitor.py\n\nnode.py:/home/pi/node.py\n"
        "===CONFIGS===\n\nrf-edge.service:0123456789abcdef\nno-hash-here\n"
        "===END===\n"
    )
    parsed = deployment._parse_audit_output(raw)
    assert parsed["services"] == {"rf-edge": {"active": True, "enabled": True}}
    assert parsed["script_versions"] == {
        "rf_scan.py": {"hash": "abc123", "mtime": 1708012345}
    }
    assert parsed["old_scripts"] == [{"name": "node.py", "path": "/home/pi/node.py"}]
    assert parsed["config_checksums"] == {"rf-edge.service": "0123456789abcdef"}


def test_missing_ssh_client_is_a_reported_state(monkeypatch):
    def no_client(*_args, **_kwargs):
        raise FileNotFoundError("ssh")

    monkeypatch.setattr(deployment.subprocess, "run", no_client)
    result = deployment._ssh_audit_node("192.0.2.10")
    assert result == {
        "reachable": False,
        "ssh_status": "client_missing",
        "error": "SSH client is unavailable.",
        "guidance": "Install the supported Bridge image with its OpenSSH client.",
    }


def test_unreadable_node_status_is_reported_unknown(monkeypatch):
    def unreadable(_data):
        raise ValueError("corrupt node record")

    monkeypatch.setattr(
        deployment.AppState, "get_node_status", staticmethod(unreadable)
    )
    snapshot = deployment._report_snapshot(
        {"last_seen": "2026-11-18T00:00:00+00:00"}, datetime.now(timezone.utc)
    )
    assert snapshot == {
        "node_status": "unknown",
        "last_seen": "2026-11-18T00:00:00+00:00",
        "scanner_status": {},
    }


def test_failed_bridge_key_check_is_unknown_never_valid(client, tmp_path, monkeypatch):
    config = tmp_path / "ssh-targets.json"
    target = {
        "host": "192.0.2.10",
        "user": "audit",
        "known_hosts_file": "/etc/sigrift/known_hosts",
        "identity_file": "/etc/sigrift/audit_id",
    }
    config.write_text(json.dumps({"edge-01": target}))
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(config))
    registered = client.post(
        "/api/nodes/register",
        json={"node_id": "edge-01", "host": "192.0.2.10", "port": 8080},
    )
    assert registered.status_code == 200
    audited = []

    def audit(host, **options):
        audited.append((host, options))
        return deployment._parse_audit_output(AUDIT) | {"reachable": True}

    def key_store_unavailable():
        raise RuntimeError("master key store unavailable")

    monkeypatch.setattr(deployment, "_ssh_audit_node", audit)
    monkeypatch.setattr(deployment, "_compute_key_hash", key_store_unavailable)
    response = client.get("/api/nodes/deployment")
    assert response.status_code == 200
    node = response.json()["nodes"]["edge-01"]
    assert node["reachable"] is True and node["ssh_status"] == "verified"
    assert node["api_keys_consistent"] is True
    assert node["api_key_bridge_valid"] is None
    assert "_key_hash" not in node and "node-key-digest" not in response.text
    # Only the operator's configured target is audited, with its exact options.
    assert audited == [
        (
            "192.0.2.10",
            {
                "user": "audit",
                "port": 22,
                "known_hosts_file": "/etc/sigrift/known_hosts",
                "identity_file": "/etc/sigrift/audit_id",
            },
        )
    ]


def test_timeout_names_the_bound(monkeypatch):
    def slow(*_args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="ssh", timeout=kwargs["timeout"])

    monkeypatch.setattr(deployment.subprocess, "run", slow)
    result = deployment._ssh_audit_node("192.0.2.11")
    assert result["ssh_status"] == "timeout" and result["reachable"] is False
    assert "10 seconds" in result["guidance"]
