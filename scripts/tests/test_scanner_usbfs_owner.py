"""Managed USB retries: real saved/sysfs files, bounded Docker response fixtures.

No physical receiver or Docker daemon is mutated by these tests.
"""

import copy
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import stat
import shutil
import socketserver
import subprocess
import tempfile
import threading
from types import SimpleNamespace

import pytest
import test_scanner_setup as planner
import test_scanner_readiness as readiness_tests

setup = planner.setup
SDR = planner.SDR
# The managed overlay maps the receiver's bus directory, not its single node.
BUS = "/dev/bus/usb/001"


@pytest.fixture
def owned(tmp_path, monkeypatch, clean):
    (tmp_path / setup.STATE).write_text(setup.render({"sdr": SDR}))
    usb = tmp_path / "sys/bus/usb/devices"
    interface = usb / "1-2:1.0"
    interface.mkdir(parents=True)
    (usb / "1-2").mkdir()
    (usb / "1-2/dev").write_text("189:3\n")
    driver = usb.parent / "drivers/usbfs"
    driver.mkdir(parents=True)
    (interface / "driver").symlink_to(driver)
    monkeypatch.setattr(setup, "USB_SYSFS", usb, raising=False)
    actual_lstat = Path.lstat
    major, minor = os.major, os.minor
    monkeypatch.setattr(
        os, "major", lambda value: 189 if value == 123 else major(value)
    )
    monkeypatch.setattr(os, "minor", lambda value: 3 if value == 123 else minor(value))
    device_stat = SimpleNamespace(st_mode=stat.S_IFCHR | 0o660, st_rdev=123, st_ino=123)
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: device_stat if str(path) == SDR["device"] else actual_lstat(path),
    )
    inventory = {
        "sdr": [SDR | {"reasons": ["kernel driver owns this receiver"]}],
        "wifi": [],
        "reasons": [],
    }
    monkeypatch.setattr(setup, "discover", lambda: copy.deepcopy(inventory))
    monkeypatch.setattr(setup, "compose_inputs", lambda root: None)
    owner = planner.container_owner(
        id="1" * 64,
        project="this-checkout",
        service="rtl-tcp",
        devices=[
            {
                "PathOnHost": BUS,
                "PathInContainer": BUS,
                "CgroupPermissions": "rw",
            }
        ],
    )
    state = {
        "id": owner["id"],
        "project": owner["project"],
        "service": "rtl-tcp",
        "running": True,
        "status": "running",
        "health": "healthy",
        "started": "2026-11-08T06:30:00Z",
        "pid": 1234,
        "restarts": 0,
        "pid_mode": "",
        "user": "appuser",
        "path": "python3",
        "args": ["-m", "sigrift.edge.rtl_tcp_supervisor"],
    }
    fixture = SimpleNamespace(
        root=tmp_path,
        owner=owner,
        state=state,
        inventory=inventory,
        calls=[],
        result="owned\n",
        after=None,
        usb=usb,
        device=SDR["device"],
        mode="supervised",
    )

    def command(args, **kwargs):
        fixture.calls.append(args)
        if args == ["docker", "compose", "config", "--format", "json"]:
            return json.dumps({"name": "this-checkout"})
        if args == ["docker", "compose", "ps", "--services", "--status", "running"]:
            return "rtl-tcp\nscan\n"
        if args == ["docker", "ps", "--quiet", "--no-trunc"]:
            return fixture.owner["id"] + "\n"
        if args[:2] == ["docker", "inspect"]:
            if args[3] == setup.OWNER_FORMAT:
                return json.dumps(fixture.owner)
            return json.dumps(fixture.state)
        if args[:2] == ["docker", "exec"]:
            assert args[2:5] == [owner["id"], "python3", "-c"]
            assert args[-4:] == [fixture.device, "189", "3", fixture.mode]
            assert kwargs.get("timeout") == 5
            if fixture.after:
                fixture.after()
            if isinstance(fixture.result, Exception):
                raise fixture.result
            return fixture.result
        if args[:2] == ["docker", "compose"] and "up" in args:
            assert args[-6:] == [
                "up",
                "-d",
                "--no-build",
                "--no-deps",
                "rtl-tcp",
                "scan",
            ]
            return ""
        if args[:2] == ["docker", "compose"] and args[-3:] == [
            "ps",
            "--format",
            "json",
        ]:
            return json.dumps(
                [
                    {"Service": name, "State": "running", "Health": "healthy"}
                    for name in ["rtl-tcp", "scan"]
                ]
            )
        raise AssertionError(args)

    monkeypatch.setattr(setup, "run", command)
    return fixture


clean = planner.clean


def test_final_revalidation_accepts_own_live_usbfs_and_preserves_selection(owned):
    before = (owned.root / setup.STATE).read_bytes()
    assert setup.check(owned.root) == {"sdr": SDR}
    assert (owned.root / setup.STATE).read_bytes() == before
    assert sum(call[:2] == ["docker", "exec"] for call in owned.calls) == 1


def test_plain_retry_rediscovers_saved_running_receiver(owned):
    assert setup.plan(owned.root, "saved") == {"sdr": SDR}
    setup.remember(owned.root, {"sdr": SDR})
    assert setup.pending_selection(owned.root) == {"sdr": SDR}
    assert all(call[1] not in {"stop", "restart", "start"} for call in owned.calls)


@pytest.mark.parametrize(
    "change",
    [
        {"project": "another-project"},
        {"service": "unrelated"},
        {"privileged": True},
        {"rules": ["c 189:* rwm"]},
        {
            "devices": [
                {
                    "PathOnHost": "/dev/bus/usb",
                    "PathInContainer": "/dev/bus/usb",
                    "CgroupPermissions": "rw",
                }
            ]
        },
        {
            "devices": [
                {
                    "PathOnHost": SDR["device"],
                    "PathInContainer": "/different",
                    "CgroupPermissions": "rw",
                }
            ]
        },
        # The older single-node shape is adopted only with its own command.
        {
            "devices": [
                {
                    "PathOnHost": SDR["device"],
                    "PathInContainer": SDR["device"],
                    "CgroupPermissions": "rw",
                }
            ]
        },
        {
            "devices": [
                {
                    "PathOnHost": "/dev/bus/usb/002",
                    "PathInContainer": BUS,
                    "CgroupPermissions": "rw",
                }
            ]
        },
    ],
)
def test_foreign_or_broad_owner_is_never_adopted(owned, change):
    owned.owner.update(change)
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


@pytest.mark.parametrize(
    "change",
    [
        {"running": False},
        {"health": "unhealthy"},
        {"health": None},
        {"pid_mode": "host"},
        {"user": "root"},
        {"path": "sh"},
        {"args": ["-c", "rtl_tcp"]},
        {"path": "rtl_tcp", "args": ["-a", "0.0.0.0", "-d", "0"]},
        {"project": "foreign"},
    ],
)
def test_unverified_process_scope_is_refused(owned, change):
    owned.state.update(change)
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


@pytest.mark.parametrize(
    "output",
    ["not-owned\n", "", "owned\nprivate-extra", setup.SetupError("probe unavailable")],
)
def test_unreadable_or_missing_actual_fd_is_refused(owned, output):
    owned.result = output
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)


@pytest.mark.parametrize(
    "key,value", [("started", "later"), ("pid", 5678), ("restarts", 1)]
)
def test_process_restart_during_probe_is_refused(owned, key, value):
    owned.after = lambda: owned.state.update({key: value})
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)


@pytest.mark.parametrize("mode", ["kernel", "mixed", "unsaved", "different-identity"])
def test_exception_never_weakens_global_or_other_device_discovery(owned, mode):
    if mode in {"kernel", "mixed"}:
        target = owned.usb.parent / "drivers/dvb_usb_rtl28xxu"
        target.mkdir()
        interface = owned.usb / ("1-2:1.1" if mode == "mixed" else "1-2:1.0")
        interface.mkdir(exist_ok=True)
        (interface / "driver").unlink(missing_ok=True)
        (interface / "driver").symlink_to(target)
    elif mode == "unsaved":
        (owned.root / setup.STATE).unlink()
    else:
        owned.inventory["sdr"][0]["identity"] = "c" * 64
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)
    assert setup.discover()["sdr"][0]["reasons"]


def test_post_smoke_start_is_safe_to_repeat(owned):
    setup.start(owned.root)
    setup.start(owned.root)
    assert sum(call[:2] == ["docker", "exec"] for call in owned.calls) == 2


def test_managed_readiness_reports_own_receiver_ready_but_foreign_unknown(
    owned, monkeypatch
):
    readiness = readiness_tests.readiness
    monkeypatch.setattr(setup, "native_docker", lambda: None)
    monkeypatch.setattr(
        setup, "rtl_devices", lambda: copy.deepcopy(owned.inventory["sdr"])
    )
    monkeypatch.setattr(setup, "wifi_devices", lambda: [])
    monkeypatch.setattr(readiness, "USB_INVENTORY", owned.usb)
    assert readiness.host_receipt(owned.root)["sdr"] == {
        "adapter": "ready",
        "selection": "selected",
        "reason": "checked",
    }
    owned.owner["project"] = "foreign"
    assert readiness.host_receipt(owned.root)["sdr"] == {
        "adapter": "unknown",
        "selection": "selected",
        "reason": "probe_failed",
    }


@pytest.mark.parametrize(
    "change",
    [
        "closed",
        "different-device",
        "wrong-executable",
        "wrong-command",
        "not-character",
        "missing-proc",
    ],
)
def test_embedded_process_probe_uses_real_device_stat_and_descriptor_links(
    tmp_path, change
):
    # Linux /proc layout is represented by real files/symlinks; /dev/null's
    # character-device stat is real. This is not a physical RTL capture proof.
    namespace = {"__name__": "probe_test"}
    exec(compile(setup.RTL_FD_PROBE, "<shipped RTL FD probe>", "exec"), namespace)
    proc = tmp_path / "1"
    (proc / "fd").mkdir(parents=True)
    (proc / "comm").write_text("rtl_tcp\n")
    (proc / "exe").symlink_to("/usr/bin/rtl_tcp")
    (proc / "cmdline").write_bytes(
        b"\0".join([b"rtl_tcp", b"-a", b"0.0.0.0", b"-d", b"0", b""])
    )
    (proc / "fd/5").symlink_to("/dev/null")
    device = Path("/dev/null")
    node = device.stat()
    expected = (os.major(node.st_rdev), os.minor(node.st_rdev))
    assert namespace["owns_device"](proc, device, expected)
    if change == "closed":
        (proc / "fd/5").unlink()
    elif change == "different-device":
        (proc / "fd/5").unlink()
        (proc / "fd/5").symlink_to("/dev/zero")
    elif change == "wrong-executable":
        (proc / "exe").unlink()
        (proc / "exe").symlink_to("/bin/sh")
    elif change == "wrong-command":
        (proc / "cmdline").write_bytes(b"rtl_tcp\0-d\01\0")
    elif change == "not-character":
        device = tmp_path / "ordinary"
        device.write_bytes(b"not a receiver")
    else:
        (proc / "comm").unlink()
        with pytest.raises(OSError):
            namespace["owns_device"](proc, device, expected)
        return
    assert not namespace["owns_device"](proc, device, expected)


def test_saved_selection_change_during_live_probe_is_not_overwritten(owned):
    owned.after = lambda: (owned.root / setup.STATE).write_text(setup.render({}))
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)
    assert setup.saved_selection(owned.root) == {}


def test_usb_kernel_claim_added_during_probe_is_refused(owned):
    def replace_driver():
        target = owned.usb.parent / "drivers/dvb_usb_rtl28xxu"
        target.mkdir()
        (owned.usb / "1-2:1.0/driver").unlink()
        (owned.usb / "1-2:1.0/driver").symlink_to(target)

    owned.after = replace_driver
    with pytest.raises(setup.SetupError):
        setup.check(owned.root)


def test_additional_receiver_retains_existing_index_zero_ambiguity_refusal(owned):
    owned.inventory["sdr"].append(
        SDR | {"usb": "1-3", "identity": "b" * 64, "reasons": []}
    )
    with pytest.raises(setup.SetupError, match="ambiguous"):
        setup.check(owned.root)
    assert not any(call[:2] == ["docker", "exec"] for call in owned.calls)


@pytest.fixture
def docker_format_cli(tmp_path):
    """Real Docker Go-template parser over an owned read-only Unix API fixture."""
    binary = shutil.which("docker")
    assert binary, "Docker CLI is required for the installer format contract"
    socket_root = Path(tempfile.mkdtemp(prefix="sigrift-usbfs-", dir="/tmp"))
    socket_path = socket_root / "api.sock"
    row = {
        "Id": "1" * 64,
        "Config": {
            "User": "appuser",
            "Labels": {
                "com.docker.compose.project": "this-checkout",
                "com.docker.compose.service": "rtl-tcp",
            },
        },
        "State": {
            "Running": True,
            "Status": "running",
            "StartedAt": "2026-11-08T06:30:00Z",
            "Pid": 1234,
        },
        "HostConfig": {"PidMode": ""},
        "RestartCount": 0,
        "Path": "rtl_tcp",
        "Args": ["-a", "0.0.0.0", "-d", "0"],
    }
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append(self.command)
            self.send_response(200)
            self.send_header("API-Version", "1.47")
            self.end_headers()

        def do_GET(self):
            requests.append(self.command)
            assert self.path.endswith("/containers/" + row["Id"] + "/json")
            encoded = json.dumps(row).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, *_):
            pass

    class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True

    try:
        server = Server(str(socket_path), Handler)
    except BaseException:
        socket_path.unlink(missing_ok=True)
        socket_root.rmdir()
        raise
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.05}
    )
    thread.start()
    config = tmp_path / "docker-config"
    config.mkdir()

    def invoke():
        return subprocess.run(
            [
                binary,
                "--host",
                "unix://" + str(socket_path),
                "inspect",
                "--format",
                setup.RTL_STATE_FORMAT,
                row["Id"],
            ],
            text=True,
            capture_output=True,
            timeout=10,
            env={
                "PATH": os.environ["PATH"],
                "DOCKER_API_VERSION": "1.47",
                "DOCKER_CONFIG": str(config),
            },
        )

    try:
        yield row, invoke
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        socket_path.unlink(missing_ok=True)
        socket_root.rmdir()
        assert not thread.is_alive()
        assert requests and set(requests) <= {"GET", "HEAD"}


@pytest.mark.parametrize("health", [None, {}, {"Status": "healthy"}])
def test_actual_docker_formats_health_presence_without_missing_key_failure(
    docker_format_cli, health
):
    row, invoke = docker_format_cli
    if health is not None:
        row["State"]["Health"] = health
    result = invoke()
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert json.loads(result.stdout) == {
        "id": row["Id"],
        "project": "this-checkout",
        "service": "rtl-tcp",
        "running": True,
        "status": "running",
        "health": health.get("Status") if health else None,
        "started": row["State"]["StartedAt"],
        "pid": 1234,
        "restarts": 0,
        "pid_mode": "",
        "user": "appuser",
        "path": "rtl_tcp",
        "args": ["-a", "0.0.0.0", "-d", "0"],
    }
