"""Optional SSH auditing must not misrepresent ordinary scanner availability."""

from datetime import datetime, timedelta, timezone
import json
import os
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest
from starlette.requests import Request

from sigrift.bridge.routers import deployment


def request(nodes, state=None, refresh=False):
    state = state or SimpleNamespace(
        persistence=SimpleNamespace(get_nodes=lambda: nodes)
    )
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/deployment",
            "query_string": b"refresh=true" if refresh else b"",
            "headers": [],
            "app": SimpleNamespace(state=state),
        }
    )


@pytest.mark.asyncio
async def test_registered_container_host_does_not_implicitly_request_ssh(monkeypatch):
    monkeypatch.delenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", raising=False)
    calls = []
    monkeypatch.setattr(
        deployment,
        "_ssh_audit_node",
        lambda *a, **k: calls.append(a)
        or {"reachable": False, "error": "Could not resolve hostname edge"},
    )
    now = datetime.now(timezone.utc).isoformat()
    nodes = {
        "local-edge": {
            "host": "edge",
            "last_seen": now,
            "_scanner_reports": {"sdr": {"state": "running", "reported_at": now}},
        }
    }
    result = await deployment.get_deployment_status(request(nodes))
    assert calls == []
    node = result["nodes"]["local-edge"]
    assert node["ssh_status"] == "not_configured"
    assert node["reachable"] is False
    assert node["node_status"] == "active"
    assert node["scanner_status"]["sdr"]["active"] is True


@pytest.mark.asyncio
async def test_scanner_lease_expiry_is_not_hidden_by_ssh_cache(monkeypatch):
    monkeypatch.delenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", raising=False)
    monkeypatch.setattr(
        deployment,
        "_ssh_audit_node",
        lambda *a, **k: {"reachable": False, "error": "unconfigured"},
    )
    now = datetime.now(timezone.utc)
    nodes = {
        "wifi-node": {
            "host": "example.invalid",
            "last_seen": now.isoformat(),
            "_scanner_reports": {
                "wifi": {"state": "running", "reported_at": now.isoformat()}
            },
        }
    }
    req = request(nodes)
    first = await deployment.get_deployment_status(req)
    assert first["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is True
    nodes["wifi-node"]["_scanner_reports"]["wifi"]["reported_at"] = (
        now - timedelta(seconds=121)
    ).isoformat()
    second = await deployment.get_deployment_status(req)
    assert second["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is False
    assert first["nodes"]["wifi-node"]["scanner_status"]["wifi"]["active"] is True


@pytest.mark.asyncio
async def test_invalid_operator_configuration_is_visible_without_ssh(
    monkeypatch, tmp_path
):
    config = tmp_path / "audit.json"
    config.write_text('{"edge":')
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(config))
    calls = []
    monkeypatch.setattr(
        deployment,
        "_ssh_audit_node",
        lambda *a, **k: calls.append(a) or {"reachable": True},
    )
    result = await deployment.get_deployment_status(
        request({"edge": {"host": "example.invalid"}})
    )
    assert calls == []
    assert result["nodes"]["edge"]["ssh_status"] == "configuration_error"


@pytest.mark.asyncio
async def test_explicit_target_does_not_use_registration_host(monkeypatch, tmp_path):
    known_hosts, identity = tmp_path / "known_hosts", tmp_path / "identity"
    known_hosts.write_text("")
    identity.write_text("disposable boundary fixture; never passed to actual SSH")
    config = tmp_path / "audit.json"
    config.write_text(
        json.dumps(
            {
                "edge": {
                    "host": "127.0.0.1",
                    "user": "audit-user",
                    "port": 2222,
                    "known_hosts_file": str(known_hosts),
                    "identity_file": str(identity),
                }
            }
        )
    )
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(config))
    calls = []
    monkeypatch.setattr(
        deployment,
        "_ssh_audit_node",
        lambda *a, **k: calls.append((a, k)) or {"reachable": True},
    )
    result = await deployment.get_deployment_status(
        request({"edge": {"host": "untrusted.invalid"}})
    )
    assert result["nodes"]["edge"]["reachable"] is True
    assert calls[0][0][0] == "127.0.0.1"
    assert calls[0][1]["user"] == "audit-user"
    assert calls[0][1]["port"] == 2222


def write_config(tmp_path, monkeypatch, **changes):
    target = {
        "host": "127.0.0.1",
        "user": "audit",
        "port": 2222,
        "known_hosts_file": str(tmp_path / "known_hosts"),
        "identity_file": str(tmp_path / "identity"),
    }
    target.update(changes)
    config = tmp_path / "targets.json"
    config.write_text(json.dumps({"edge": target}))
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(config))
    return config, target


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "-oProxyCommand=echo"},
        {"host": "audit@host"},
        {"host": "host\nother"},
        {"host": "a..b"},
        {"host": "fe80::1%eth0"},
        {"user": "-root"},
        {"user": "user;echo"},
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"identity_file": "relative/key"},
        {"known_hosts_file": "/tmp/a\nother"},
        {"StrictHostKeyChecking": "no"},
        {"password": "must-not-be-echoed"},
    ],
)
def test_malformed_targets_are_refused_without_echoing_values(
    tmp_path, monkeypatch, changes
):
    write_config(tmp_path, monkeypatch, **changes)
    targets, _, error = deployment._load_ssh_targets()
    assert targets == {}
    assert error and "invalid" in error
    assert "must-not-be-echoed" not in error


def test_target_map_keys_must_be_plain_node_ids(tmp_path, monkeypatch):
    config, target = write_config(tmp_path, monkeypatch)
    for node_id in ("../edge", "edge node", "", "e" * 65, "edge\n", "edge;id"):
        config.write_text(json.dumps({node_id: target}))
        targets, _, error = deployment._load_ssh_targets()
        assert targets == {}, node_id
        assert error and "invalid" in error, node_id
    config.write_text(json.dumps({"e" * 64: target}))
    assert deployment._load_ssh_targets()[2] is None


def test_configured_trust_and_identity_are_the_only_ones_ssh_is_given(
    tmp_path, monkeypatch
):
    _, target = write_config(tmp_path, monkeypatch)
    (tmp_path / "known_hosts").write_text("")
    (tmp_path / "identity").write_text("disposable fixture; never passed to SSH")
    calls = []

    def boundary(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 255, stdout="", stderr="refused")

    monkeypatch.setattr(deployment.subprocess, "run", boundary)
    assert deployment._ssh_audit_node(**target)["ssh_status"] == "unreachable"
    [cmd] = calls
    assert cmd[0] == "ssh"
    end = cmd.index("--")
    assert cmd[end + 1 :] == ["127.0.0.1", "bash", "-s"]
    # Every option takes a value.  ssh keeps the first value given for an
    # -o option and tries every -i identity, so each option may appear
    # once only: no second identity, trust file or config source.
    options = cmd[1:end]
    assert len(options) % 2 == 0, options
    pairs = list(zip(options[::2], options[1::2]))
    names = [
        flag + value.split("=")[0] if flag == "-o" else flag for flag, value in pairs
    ]
    assert sorted(names) == sorted(
        [
            "-F",
            "-oBatchMode",
            "-oConnectTimeout",
            "-oStrictHostKeyChecking",
            "-oUserKnownHostsFile",
            "-oGlobalKnownHostsFile",
            "-oIdentitiesOnly",
            "-i",
            "-p",
            "-l",
        ]
    )
    for pair in [
        ("-F", "/dev/null"),
        ("-o", "BatchMode=yes"),
        ("-o", "StrictHostKeyChecking=yes"),
        ("-o", f"UserKnownHostsFile={tmp_path / 'known_hosts'}"),
        ("-o", "GlobalKnownHostsFile=/dev/null"),
        ("-o", "IdentitiesOnly=yes"),
        ("-i", str(tmp_path / "identity")),
        ("-p", "2222"),
        ("-l", "audit"),
    ]:
        assert pair in pairs, pair


@pytest.mark.parametrize(
    "body", ["[]", '{"edge":{},"edge":{}}', '{"edge":null}', "x" * 65537]
)
def test_invalid_or_ambiguous_file_is_not_treated_as_empty_setup(
    tmp_path, monkeypatch, body
):
    config, _ = write_config(tmp_path, monkeypatch)
    config.write_text(body)
    assert deployment._load_ssh_targets()[2] is not None


def test_fifo_configuration_does_not_block_a_refresh(tmp_path, monkeypatch):
    fifo = tmp_path / "operator-config"
    os.mkfifo(fifo)
    monkeypatch.setenv("BRIDGE_DEPLOYMENT_SSH_CONFIG", str(fifo))
    before = time.monotonic()
    assert deployment._load_ssh_targets()[2] is not None
    assert time.monotonic() - before < 1


@pytest.mark.parametrize(
    "host", ["127.0.0.1", "::1", "edge-host.example", "edge-host.example."]
)
def test_explicit_ipv4_ipv6_and_dns_targets_preserve_operator_identity(
    tmp_path, monkeypatch, host
):
    _, target = write_config(tmp_path, monkeypatch, host=host)
    targets, fingerprint, error = deployment._load_ssh_targets()
    assert error is None
    assert targets == {"edge": target}
    assert len(fingerprint) == 64


def test_missing_trust_and_identity_files_do_not_start_ssh(tmp_path, monkeypatch):
    _, target = write_config(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(deployment.subprocess, "run", lambda *a, **k: calls.append(a))
    assert deployment._ssh_audit_node(**target)["ssh_status"] == "host_key_unverified"
    (tmp_path / "known_hosts").write_text("")
    assert deployment._ssh_audit_node(**target)["ssh_status"] == "credentials_missing"
    assert calls == []


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        (
            "No ED25519 host key is known for example.invalid and you have requested strict checking.\nHost key verification failed.",
            "host_key_unverified",
        ),
        ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!", "host_key_changed"),
        (
            "audit@example.invalid: Permission denied (publickey).",
            "authentication_failed",
        ),
        (
            "ssh: Could not resolve hostname edge: Name or service not known",
            "host_unresolved",
        ),
        ("ssh: connect to host 127.0.0.1 port 2222: Connection refused", "unreachable"),
    ],
)
def test_ssh_failure_categories_preserve_strict_trust_and_hide_raw_output(
    monkeypatch, stderr, expected
):
    calls = []

    def boundary(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(
            cmd, 255, stdout="", stderr=stderr + "\nPRIVATE_REMOTE_BANNER"
        )

    monkeypatch.setattr(deployment.subprocess, "run", boundary)
    monkeypatch.setenv("BRIDGE_SSH_HOST_KEY_CHECKING", "no")
    result = deployment._ssh_audit_node("127.0.0.1", "audit", port=2222)
    assert result["ssh_status"] == expected and result["reachable"] is False
    assert "PRIVATE_REMOTE_BANNER" not in json.dumps(result)
    cmd, options = calls[0]
    assert "StrictHostKeyChecking=yes" in cmd and "StrictHostKeyChecking=no" not in cmd
    assert cmd[cmd.index("-F") + 1] == "/dev/null"
    assert cmd[cmd.index("--") + 1] == "127.0.0.1"
    assert options["timeout"] == 10 and options["env"]["LC_ALL"] == "C"
    assert not options.get("shell", False)


def test_successful_exit_without_audit_framing_is_not_verified(monkeypatch):
    monkeypatch.setattr(
        deployment.subprocess,
        "run",
        lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, 0, stdout="welcome\n", stderr=""
        ),
    )
    assert deployment._ssh_audit_node("127.0.0.1")["ssh_status"] == "invalid_response"


def test_actual_openssh_connection_refusal_does_not_claim_scanner_offline():
    # Keep the port bound, but never listen, so no unrelated service can take it.
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        result = deployment._ssh_audit_node("127.0.0.1", port=endpoint.getsockname()[1])
    assert result["ssh_status"] == "unreachable"
    assert "Scanner activity is reported separately" in result["guidance"]


def test_actual_stalled_ssh_process_is_killed_and_reaped(monkeypatch):
    children = []
    original = subprocess.Popen

    def record(*args, **kwargs):
        process = original(*args, **kwargs)
        children.append(process)
        return process

    monkeypatch.setattr(deployment.subprocess, "Popen", record)
    # Generous limits: on a loaded CI runner starting `ssh` and connecting can
    # take seconds, and a sub-second timeout killed it before it connected.
    monkeypatch.setattr(deployment, "_SSH_TIMEOUT", 5)
    accepted = threading.Event()
    with socket.socket() as endpoint:
        endpoint.bind(("127.0.0.1", 0))
        endpoint.listen(1)
        endpoint.settimeout(20)

        def stall():
            with endpoint.accept()[0] as connection:
                accepted.set()
                connection.settimeout(20)
                while connection.recv(4096):
                    pass

        server = threading.Thread(target=stall)
        server.start()
        try:
            result = deployment._ssh_audit_node(
                "127.0.0.1", port=endpoint.getsockname()[1]
            )
        finally:
            server.join(22)
    assert accepted.is_set() and not server.is_alive()
    assert result["ssh_status"] == "timeout"
    assert len(children) == 1 and children[0].poll() is not None


@pytest.mark.asyncio
async def test_changed_configuration_invalidates_cached_audit(tmp_path, monkeypatch):
    config, _ = write_config(tmp_path, monkeypatch)
    calls = []
    monkeypatch.setattr(
        deployment,
        "_ssh_audit_node",
        lambda host, **kwargs: calls.append(host) or {"reachable": True},
    )
    req = request({"edge": {"host": "ignored.invalid"}})
    await deployment.get_deployment_status(req)
    cached = await deployment.get_deployment_status(req)
    assert cached["cached"] is True and calls == ["127.0.0.1"]
    body = json.loads(config.read_text())
    body["edge"]["host"] = "::1"
    config.write_text(json.dumps(body))
    updated = await deployment.get_deployment_status(req)
    assert updated["cached"] is False and calls == ["127.0.0.1", "::1"]


@pytest.mark.asyncio
async def test_per_request_audit_concurrency_is_bounded(tmp_path, monkeypatch):
    config, target = write_config(tmp_path, monkeypatch)
    config.write_text(json.dumps({f"edge-{i}": target for i in range(8)}))
    lock = threading.Lock()
    active = 0
    maximum = 0

    def boundary(host, **kwargs):
        nonlocal active, maximum
        with lock:
            active += 1
            maximum = max(active, maximum)
        time.sleep(0.03)
        with lock:
            active -= 1
        return {"reachable": True}

    monkeypatch.setattr(deployment, "_ssh_audit_node", boundary)
    result = await deployment.get_deployment_status(
        request({f"edge-{i}": {} for i in range(8)})
    )
    assert len(result["nodes"]) == 8 and maximum == 4 and active == 0
