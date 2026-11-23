"""Real saved files, Compose rendering and TLS delivery of sanitized host facts."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest
import test_scanner_setup as planner

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "scanner_readiness_tested", ROOT / "scripts/scanner_readiness.py"
)
readiness = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {"scanner_setup": planner.setup}):
    spec.loader.exec_module(readiness)
setup = readiness.setup
clean = planner.clean


@pytest.fixture
def host(tmp_path, monkeypatch, clean):
    inventory = tmp_path / "usb-inventory"
    inventory.mkdir()
    monkeypatch.setattr(readiness, "USB_INVENTORY", inventory)
    monkeypatch.setattr(setup, "native_docker", lambda: None)
    monkeypatch.setattr(setup, "rtl_devices", lambda: [planner.SDR | {"reasons": []}])
    monkeypatch.setattr(setup, "wifi_devices", lambda: [planner.WIFI | {"reasons": []}])
    (tmp_path / setup.STATE).write_text(
        setup.render({"sdr": planner.SDR, "wifi": planner.WIFI})
    )
    return tmp_path


def test_saved_choice_survives_unplug_failure_and_retry(host, monkeypatch):
    original = (host / setup.STATE).read_bytes()
    assert readiness.host_receipt(host)["sdr"] == {
        "adapter": "ready",
        "selection": "selected",
        "reason": "checked",
    }
    monkeypatch.setattr(setup, "rtl_devices", lambda: [])
    assert readiness.host_receipt(host)["sdr"] == {
        "adapter": "missing",
        "selection": "selected",
        "reason": "selected_absent",
    }
    monkeypatch.setattr(
        setup,
        "rtl_devices",
        lambda: [planner.SDR | {"identity": "b" * 64, "reasons": []}],
    )
    assert readiness.host_receipt(host)["sdr"]["reason"] == "selected_absent"
    monkeypatch.setattr(setup, "rtl_devices", lambda: [planner.SDR | {"reasons": []}])
    assert readiness.host_receipt(host)["sdr"]["adapter"] == "ready"
    assert (host / setup.STATE).read_bytes() == original
    assert not (host / setup.PENDING).exists()


def test_probe_failures_are_unknown_and_do_not_copy_private_text(host, monkeypatch):
    def unavailable():
        raise setup.SetupError("secret-serial/private-interface/password")

    monkeypatch.setattr(setup, "rtl_devices", unavailable)
    result = readiness.host_receipt(host)
    assert result["sdr"] == {
        "adapter": "unknown",
        "selection": "selected",
        "reason": "probe_failed",
    }
    assert result["wifi"]["adapter"] == "ready"
    monkeypatch.setattr(setup, "native_docker", unavailable)
    result = readiness.host_receipt(host)
    assert all(item["reason"] == "unsupported_host" for item in result.values())
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize("reason,code", list(readiness.REASONS.items()))
def test_blocked_codes_do_not_disclose_hardware_identity(
    host, monkeypatch, reason, code
):
    monkeypatch.setattr(
        setup, "rtl_devices", lambda: [planner.SDR | {"reasons": [reason]}]
    )
    result = readiness.host_receipt(host)
    assert result["sdr"] == {
        "adapter": "blocked",
        "selection": "selected",
        "reason": code,
    }
    assert not any(
        value in json.dumps(result)
        for value in (
            planner.SDR["identity"],
            planner.SDR["device"],
            planner.WIFI["interface"],
        )
    )


def test_no_adapter_differs_from_no_selection_and_ambiguous_receivers(
    host, monkeypatch
):
    (host / setup.STATE).write_text(setup.render({}))
    result = readiness.host_receipt(host)
    assert (
        result["sdr"]["adapter"] == "ready"
        and result["sdr"]["selection"] == "not_selected"
    )
    monkeypatch.setattr(setup, "rtl_devices", lambda: [])
    assert readiness.host_receipt(host)["sdr"] == {
        "adapter": "missing",
        "selection": "not_selected",
        "reason": "not_found",
    }
    monkeypatch.setattr(
        setup,
        "rtl_devices",
        lambda: [
            planner.SDR | {"reasons": []},
            planner.SDR | {"usb": "1-3", "reasons": []},
        ],
    )
    assert readiness.host_receipt(host)["sdr"]["reason"] == "ambiguous"


@pytest.mark.parametrize("invalid", ["edited", "symlink", "conflicting-pending"])
def test_invalid_selection_is_unknown_and_unchanged(host, invalid):
    active = host / setup.STATE
    if invalid == "edited":
        active.write_text(active.read_text() + "# private edit\n")
    elif invalid == "symlink":
        active.rename(host / "operator-file")
        active.symlink_to(host / "operator-file")
    else:
        (host / setup.PENDING).write_text(setup.pending_text({}))
    before = active.read_bytes()
    assert all(
        item
        == {
            "adapter": "unknown",
            "selection": "unmanaged",
            "reason": "selection_unavailable",
        }
        for item in readiness.host_receipt(host).values()
    )
    assert active.read_bytes() == before


def test_dashboard_only_preserves_no_discovery_contract(host, monkeypatch):
    def forbidden():
        pytest.fail("Dashboard-only must not probe hardware")

    monkeypatch.setattr(setup, "native_docker", forbidden)
    monkeypatch.setattr(setup, "rtl_devices", forbidden)
    assert all(
        item
        == {"adapter": "unknown", "selection": "not_selected", "reason": "not_checked"}
        for item in readiness.host_receipt(host, dashboard_only=True).values()
    )


@pytest.fixture
def installed(tmp_path, monkeypatch, clean):
    shutil.copyfile(ROOT / "docker-compose.yml", tmp_path / "docker-compose.yml")
    (tmp_path / "tls").mkdir()
    (tmp_path / "tls/cert.pem").write_text("placeholder")
    (tmp_path / ".env").write_text(
        "BRIDGE_LOCAL_NODE_KEY='node-$private-key'\nMLRF_NODE_ID=private-node\nUC_TLS_CERT=/app/tls/cert.pem\n"
    )
    (tmp_path / "docker-compose.override.yml").write_text(
        "services:\n  gateway:\n    volumes:\n      - ./tls:/app/tls:ro\n"
    )
    monkeypatch.chdir(tmp_path)
    actual = setup.run

    def run(args, **kwargs):
        if args[-3:] == ["port", "gateway", "8444"]:
            return "0.0.0.0:9444\n[::]:9444\n"
        return actual(args, **kwargs)

    monkeypatch.setattr(setup, "run", run)
    return tmp_path


def test_real_compose_resolves_quoted_key_and_directory_tls_mount(installed, capsys):
    before = {
        name: (installed / name).read_bytes()
        for name in (".env", "docker-compose.override.yml")
    }
    assert readiness.installed_target(installed) == (
        "https://127.0.0.1:9444",
        "private-node",
        "node-$private-key",
        installed / "tls/cert.pem",
    )
    assert before == {name: (installed / name).read_bytes() for name in before}
    assert "private-key" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "change", ["other-key", "other-node", "other-cert", "missing-env", "env-symlink"]
)
def test_no_fallback_for_unverified_installed_inputs(installed, change):
    if change == "missing-env":
        (installed / ".env").unlink()
    elif change == "env-symlink":
        (installed / ".env").rename(installed / "secrets")
        (installed / ".env").symlink_to(installed / "secrets")
    else:
        extra = {
            "other-key": "  edge:\n    environment:\n      MLRF_API_KEY: other-secret\n",
            "other-node": "  edge:\n    environment:\n      MLRF_NODE_ID: other\n",
            "other-cert": "  gateway:\n    volumes:\n      - /unrelated:/app/tls:ro\n",
        }[change]
        if change == "other-cert":
            (installed / "docker-compose.override.yml").write_text(
                "services:\n" + extra
            )
        else:
            with (installed / "docker-compose.override.yml").open("a") as out:
                out.write(extra)
    with pytest.raises(setup.SetupError):
        readiness.installed_target(installed)


@pytest.fixture(scope="module")
def certificates(tmp_path_factory):
    root = tmp_path_factory.mktemp("readiness-tls")
    pairs = []
    for name in ("trusted", "other"):
        cert, key = root / (name + ".pem"), root / (name + ".key")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=IP:127.0.0.1,DNS:localhost",
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        pairs.append((cert, key))
    return pairs


@contextmanager
def server(certificates, status=200, malformed=False, stall=None):
    requests = []
    release = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, self.headers.get("X-API-Key"), body))
            if stall == "headers":
                release.wait(10)
                return
            result = body | {
                "checked_at": "2026-11-07T15:00:00Z",
                "fresh": True,
                "expires_in_seconds": 300,
            }
            encoded = (
                b"private-malformed-body" if malformed else json.dumps(result).encode()
            )
            self.send_response(status)
            self.send_header("Location", "https://127.0.0.1:9/private-redirect")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            if stall == "body":
                self.wfile.write(encoded[:1])
                self.wfile.flush()
                release.wait(10)
                return
            self.wfile.write(encoded)

        def log_message(self, *_):
            pass

    listener = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(*map(str, certificates[0]))
    listener.socket = context.wrap_socket(listener.socket, server_side=True)
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    try:
        yield "https://127.0.0.1:" + str(listener.server_port), requests
    finally:
        release.set()
        listener.shutdown()
        listener.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()


def test_real_tls_only_expected_key_ca_sanitized_body(
    host, certificates, monkeypatch, tmp_path
):
    keylog = tmp_path / "forbidden-keylog"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    monkeypatch.setenv("HTTPS_PROXY", "https://127.0.0.1:9")
    payload = readiness.host_receipt(host)
    with server(certificates) as (url, requests):
        readiness.send_receipt(
            url, "private-node", "node-private-key", certificates[0][0], payload
        )
    assert requests == [
        ("/api/nodes/private-node/setup-readiness", "node-private-key", payload)
    ]
    assert not keylog.exists()


@pytest.mark.parametrize(
    "status,malformed",
    [(429, False), (500, False), (302, False), (201, False), (200, True)],
)
def test_delivery_failure_never_retries_or_claims_success(
    host, certificates, status, malformed
):
    with server(certificates, status, malformed) as (url, requests):
        with pytest.raises((setup.SetupError, OSError, ValueError)):
            readiness.send_receipt(
                url,
                "private-node",
                "private-key",
                certificates[0][0],
                readiness.host_receipt(host),
            )
    assert len(requests) == 1


def test_wrong_ca_fails_before_credentials_reach_server(host, certificates):
    with server(certificates) as (url, requests):
        with pytest.raises(OSError):
            readiness.send_receipt(
                url,
                "private-node",
                "private-key",
                certificates[1][0],
                readiness.host_receipt(host),
            )
    assert requests == []


@pytest.mark.parametrize("stall", ["headers", "body"])
def test_real_tls_stall_is_bounded_without_retry(host, certificates, stall):
    with server(certificates, stall=stall) as (url, requests):
        started = time.monotonic()
        with pytest.raises(OSError):
            readiness.send_receipt(
                url,
                "private-node",
                "private-key",
                certificates[0][0],
                readiness.host_receipt(host),
            )
        assert 4 <= time.monotonic() - started < 9
    assert len(requests) == 1


def test_main_private_failures_do_not_change_configuration(host):
    before = (host / setup.STATE).read_bytes()
    # Missing installed inputs take the real CLI failure path without changing
    # this test process's SIGTERM/SIGALRM handlers.
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/scanner_readiness.py")],
        cwd=host,
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 1
    assert "not reported" in result.stderr
    assert str(host) not in result.stderr + result.stdout
    assert (host / setup.STATE).read_bytes() == before


@pytest.mark.parametrize("unavailable", ["missing", "not-directory"])
def test_unavailable_usb_inventory_is_unknown_not_no_adapter(
    host, monkeypatch, unavailable
):
    inventory = readiness.USB_INVENTORY
    inventory.rmdir()
    if unavailable == "not-directory":
        inventory.write_text("unavailable inventory")
    # Match the actual planner behavior: glob returns no matches for either
    # unusable path. The sender must not call that absence physical evidence.
    monkeypatch.setattr(setup, "rtl_devices", lambda: list(inventory.glob("*")))
    result = readiness.host_receipt(host)
    assert result["sdr"] == {
        "adapter": "unknown",
        "selection": "selected",
        "reason": "probe_failed",
    }
    assert result["wifi"]["adapter"] == "ready"


@pytest.mark.parametrize(
    "start_status,report_status,managed,mode",
    [
        (0, 1, 1, "auto"),
        (17, 0, 1, "auto"),
        (130, 0, 1, "auto"),
        (143, 0, 1, "auto"),
        (0, 0, 0, "dashboard-only"),
        (0, 130, 0, "dashboard-only"),
        (0, 143, 0, "dashboard-only"),
        (0, 130, 1, "auto"),
        (0, 143, 1, "auto"),
        (17, 130, 1, "auto"),
    ],
)
def test_shipped_startup_block_retains_install_result_and_dashboard_choice(
    tmp_path, start_status, report_status, managed, mode
):
    source = (ROOT / "scripts/quickstart.sh").read_text()
    block = source[
        source.index("# Only now start the chosen workers.") : source.index(
            "# ── Summary"
        )
    ]
    helper = source[
        source.index("# Optional host checks never undo setup") : source.index(
            "# Refuse ambiguous mode/device changes"
        )
    ]
    log = tmp_path / "calls"
    script = (
        """set -euo pipefail
python3() {
  printf '%s\\n' "$*" >> "$COMMANDS"
  case "$1" in
    scripts/scanner_setup.py) return "$START_STATUS";;
    scripts/scanner_readiness.py) return "$REPORT_STATUS";;
    *) return 98;;
  esac
}
"""
        + helper
        + block
        + '\nprintf "install-complete\\n"\n'
    )
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "COMMANDS": str(log),
            "SCANNER_MANAGED": str(managed),
            "QUICKSTART_MODE": mode,
            "START_STATUS": str(start_status),
            "REPORT_STATUS": str(report_status),
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    calls = log.read_text().splitlines()
    expected = (
        start_status
        if start_status in (130, 143)
        else report_status
        if report_status in (130, 143)
        else start_status
    )
    assert result.returncode == expected
    assert ("install-complete" in result.stdout) == (expected == 0)
    if start_status in (130, 143):
        assert len(calls) == 1
    elif managed:
        assert calls == [
            "scripts/scanner_setup.py start",
            "scripts/scanner_readiness.py",
        ]
    else:
        assert calls == ["scripts/scanner_readiness.py --dashboard-only"]


@pytest.mark.parametrize(
    "plan_status,installed", [(17, True), (130, True), (143, True), (17, False)]
)
def test_shipped_failed_plan_reports_only_existing_install_and_keeps_original_failure(
    tmp_path, plan_status, installed
):
    source = (ROOT / "scripts/quickstart.sh").read_text()
    block = source[
        source.index("# Optional host checks never undo setup") : source.index(
            'echo "==> Quickstart mode:'
        )
    ]
    (tmp_path / setup.STATE).write_text(setup.render({"sdr": planner.SDR}))
    if installed:
        (tmp_path / ".env").write_text("BRIDGE_LOCAL_NODE_KEY=private-never-printed\n")
        (tmp_path / "tls").mkdir()
        (tmp_path / "tls/cert.pem").write_text("certificate")
    before = {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    log = tmp_path / "calls"
    script = (
        """set -euo pipefail
quickstart_mode() { echo auto; }
python3() {
  printf '%s\\n' "$*" >> "$COMMANDS"
  case "$1" in
    scripts/scanner_setup.py) return "$PLAN_STATUS";;
    scripts/scanner_readiness.py) return 23;;
    *) return 98;;
  esac
}
"""
        + block
        + "\necho unexpected-completion\n"
    )
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=tmp_path,
        env={
            "PATH": "/usr/bin:/bin",
            "COMMANDS": str(log),
            "PLAN_STATUS": str(plan_status),
            "REQUESTED_MODE": "",
            "SCANNER_REQUEST": "",
            "WIFI_INTERFACE": "",
            "RENEW_TLS_ONLY": "0",
        },
        text=True,
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == plan_status
    assert "unexpected-completion" not in result.stdout
    assert "private-never-printed" not in result.stdout + result.stderr
    calls = log.read_text().splitlines()
    interrupted = plan_status in (130, 143)
    # A failed plan (not an interrupt) asks whether host preparation could fix
    # it. Here that check fails too, so the plan's own error stands alone: no
    # "Skipped host preparation" hint pointing the user at the wrong step.
    assert calls == ["scripts/scanner_setup.py plan --scanners saved"] + (
        []
        if interrupted
        else ["scripts/scanner_setup.py prepare --check --scanners saved"]
    ) + (["scripts/scanner_readiness.py"] if installed and not interrupted else [])
    assert "Skipped host preparation" not in result.stdout + result.stderr
    assert before == {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file() and path != log
    }


@pytest.mark.parametrize(
    "sent,expected", [(signal.SIGINT, 130), (signal.SIGTERM, 143), (signal.SIGALRM, 1)]
)
def test_real_cli_cancellation_and_deadline_reap_the_owned_probe(
    installed, sent, expected
):
    bindir = installed / "bin"
    bindir.mkdir()
    marker = installed / "probe-pid"
    docker = bindir / "docker"
    docker.write_text(
        f"#!{sys.executable}\nimport os,signal,time\nfrom pathlib import Path\n"
        f"Path({str(marker)!r}).write_text(str(os.getpid()))\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "while True: time.sleep(1)\n"
    )
    docker.chmod(0o700)
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "scripts/scanner_readiness.py")],
        cwd=installed,
        env=os.environ | {"PATH": str(bindir) + os.pathsep + os.environ["PATH"]},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 5
        while (
            not marker.exists()
            and process.poll() is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        assert marker.exists(), "Expected actual read-only Compose probe to start"
        probe_pid = int(marker.read_text())
        process.send_signal(sent)
        out, err = process.communicate(timeout=5)
        assert process.returncode == expected, (out, err)
        assert "Last host check reported" not in out
        with pytest.raises(ProcessLookupError):
            os.kill(probe_pid, 0)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        if marker.exists():
            try:
                os.killpg(int(marker.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
