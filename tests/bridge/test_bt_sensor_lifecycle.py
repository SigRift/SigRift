"""Bluetooth scanner follows the sensor lifecycle (docs/sensor-lifecycle.md).

The adapter is waited for while absent, replaced or down, followed across
renumbering when selected by address, and every state is reported to the
bridge as a fixed category. Hardware is faked: a sysfs tree, the hci tools
and the adapter-address ioctl.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest

from sigrift.edge import sensor_presence
from sigrift.lib import bt_scanner
from sigrift.lib.bt_scanner import BtScanner

# The service tests drive a real scanner process with generous limits below.
# The project default of 30 s per test (pyproject.toml) is too short for them
# on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)

SELECTED = "aa:bb:cc:dd:ee:01"
OTHER = "aa:bb:cc:dd:ee:02"
SRC = Path(__file__).resolve().parents[2] / "src"


class FakeHci:
    """Fake /sys/class/bluetooth, adapter addresses and hci tools."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)
        self.addresses: dict[int, str] = {}
        self.down: set[str] = set()
        self.inq_rc = 0
        self.lescan_rc = 0
        self.calls: list[list[str]] = []
        # `bluetoothctl devices`: BlueZ's cache for the default controller.
        self.cached = ""
        # Called after each scan tool, to unplug mid-scan.
        self.after_tool = lambda: None

    def plug(self, hci: str, address: str = SELECTED) -> None:
        (self.root / hci).mkdir()
        self.addresses[int(hci[3:])] = address

    def unplug(self, hci: str) -> None:
        (self.root / hci).rmdir()
        self.addresses.pop(int(hci[3:]), None)

    def _present(self, hci: str) -> bool:
        return (self.root / hci).is_dir()

    def run(self, cmd, **_kwargs):
        self.calls.append(list(cmd))
        rc, out = 0, ""
        if cmd[0] == "hciconfig":
            hci = cmd[1]
            if not self._present(hci):
                rc = 1
            else:
                out = f"{hci}:\tType: Primary\n\t" + (
                    "DOWN \n" if hci in self.down else "UP RUNNING \n"
                )
        elif cmd[0] == "hcitool" and cmd[3] == "inq":
            self.after_tool()
            rc = self.inq_rc if self._present(cmd[2]) else 1
            out = "Inquiring ...\n"
        elif cmd[:2] == ["bluetoothctl", "devices"]:
            out = self.cached
        return subprocess.CompletedProcess(cmd, rc, stdout=out, stderr="")

    def popen(self, cmd, **_kwargs):
        self.calls.append(list(cmd))
        self.after_tool()
        proc = mock.Mock()
        proc.stdout.read.return_value = b""
        proc.stderr.read.return_value = b""
        proc.wait.return_value = self.lescan_rc if self._present(cmd[2]) else 1
        return proc

    def scanned_with(self) -> list[str]:
        return [c[2] for c in self.calls if c[0] == "hcitool"]


@pytest.fixture
def hci(tmp_path, monkeypatch):
    fake = FakeHci(tmp_path / "class/bluetooth")
    monkeypatch.setattr(bt_scanner, "_BT_SYSFS", fake.root)
    monkeypatch.setattr(sensor_presence, "_hci_address", fake.addresses.get)
    monkeypatch.setenv("MLRF_SCANNER_CONFIG_PATH", str(tmp_path / "none.json"))
    monkeypatch.setattr(bt_scanner.subprocess, "run", fake.run)
    monkeypatch.setattr(bt_scanner.subprocess, "Popen", fake.popen)
    monkeypatch.setattr(bt_scanner.shutil, "which", lambda _name: None)
    monkeypatch.setattr(bt_scanner.time, "sleep", lambda _s: None)
    return fake


def make(adapter: str) -> BtScanner:
    return BtScanner("https://127.0.0.1:8444", "k", "node", adapter=adapter)


def warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_starting_before_the_first_cycle(hci):
    assert make("hci0").capture_status() == ("error", "starting")


def test_absent_at_start_waits_without_scanning_and_logs_once(hci, caplog):
    scanner = make("hci0")
    with caplog.at_level(logging.INFO, logger="sigrift.lib.bt_scanner"):
        waits = [scanner._cycle() for _ in range(3)]

    assert scanner.capture_status() == ("error", "sensor_absent")
    assert hci.scanned_with() == []
    # Re-checked every few seconds, not every scan interval.
    assert waits == [5.0, 5.0, 5.0]
    assert warnings(caplog) == ["Bluetooth sensor absent; waiting for it to return"]

    hci.plug("hci0")
    assert scanner._cycle() == scanner.scan_interval
    assert scanner.capture_status() == ("running", None)
    assert set(hci.scanned_with()) == {"hci0"}


def test_by_address_follows_the_adapter_to_a_new_index(hci, caplog):
    hci.plug("hci0")
    scanner = make(SELECTED.upper())
    scanner._cycle()
    assert scanner.capture_status() == ("running", None)
    assert set(hci.scanned_with()) == {"hci0"}

    hci.unplug("hci0")
    scanner._cycle()
    assert scanner.capture_status() == ("error", "sensor_absent")

    hci.calls.clear()
    hci.plug("hci1")
    scanner._cycle()
    assert scanner.capture_status() == ("running", None)
    assert set(hci.scanned_with()) == {"hci1"}
    # Logs name the kernel interface, never the configured address.
    assert all(SELECTED not in r.getMessage().lower() for r in caplog.records)


def test_by_index_reports_absent_when_the_index_is_gone(hci):
    hci.plug("hci0")
    scanner = make("hci0")
    scanner._cycle()
    hci.unplug("hci0")
    hci.plug("hci1")
    hci.calls.clear()
    scanner._cycle()

    assert scanner.capture_status() == ("error", "sensor_absent")
    assert hci.scanned_with() == []


def test_by_address_refuses_another_adapter_at_the_same_index(hci, caplog):
    hci.plug("hci0")
    scanner = make(SELECTED)
    scanner._cycle()
    hci.unplug("hci0")
    hci.plug("hci0", OTHER)
    hci.calls.clear()
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="sigrift.lib.bt_scanner"):
        scanner._cycle()
        scanner._cycle()

    assert scanner.capture_status() == ("error", "sensor_changed")
    assert hci.scanned_with() == []
    assert warnings(caplog) == [
        "Bluetooth sensor replaced by a different device; not using it until "
        "it is selected again"
    ]

    # The selected adapter returning anywhere is used again.
    hci.plug("hci1")
    scanner._cycle()
    assert scanner.capture_status() == ("running", None)
    assert set(hci.scanned_with()) == {"hci1"}


def test_by_index_uses_whatever_adapter_is_there(hci):
    # Legacy setting: no identity to check, as before.
    hci.plug("hci0")
    scanner = make("hci0")
    scanner._cycle()
    hci.unplug("hci0")
    hci.plug("hci0", OTHER)
    scanner._cycle()
    assert scanner.capture_status() == ("running", None)


def test_down_adapter_is_waited_for_not_brought_up(hci, caplog):
    hci.plug("hci0")
    hci.down.add("hci0")
    scanner = make("hci0")
    with caplog.at_level(logging.INFO, logger="sigrift.lib.bt_scanner"):
        assert scanner._cycle() == 5.0
        scanner._cycle()

    assert scanner.capture_status() == ("error", "capture_failed")
    assert hci.scanned_with() == []
    assert not any(c[-1:] == ["up"] for c in hci.calls)
    assert warnings(caplog) == [
        "Bluetooth adapter hci0 is down; waiting for it to come up"
    ]

    hci.down.clear()
    scanner._cycle()
    assert scanner.capture_status() == ("running", None)


def test_zero_devices_from_a_working_scan_is_running(hci):
    hci.plug("hci0")
    scanner = make("hci0")
    with mock.patch.object(scanner, "_upload_summary") as upload:
        scanner._cycle()
    assert scanner.capture_status() == ("running", None)
    assert not upload.called


@pytest.mark.parametrize(
    ("inq_rc", "lescan_rc", "expected"),
    [
        (1, 1, ("error", "capture_failed")),
        # An LE-only dongle fails the Classic inquiry but still scans.
        (1, 0, ("running", None)),
        (0, 1, ("running", None)),
    ],
)
def test_scan_exit_codes_reach_the_status(hci, inq_rc, lescan_rc, expected):
    hci.plug("hci0")
    hci.inq_rc, hci.lescan_rc = inq_rc, lescan_rc
    scanner = make("hci0")
    scanner._cycle()
    assert scanner.capture_status() == expected


@pytest.mark.parametrize("leaves", [False, True])
def test_bluetoothctl_cache_is_not_proof_the_selected_adapter_scanned(hci, leaves):
    # A built-in hci0 is BlueZ's default controller; its cache lists devices
    # even when the selected adapter's own scans fail or it has just left.
    hci.plug("hci1")
    hci.cached = "Device 11:22:33:44:55:66 cached-by-default-controller\n"
    hci.inq_rc = hci.lescan_rc = 1
    if leaves:
        hci.inq_rc = 0
        hci.after_tool = lambda: hci._present("hci1") and hci.unplug("hci1")
    scanner = make("hci1")
    with mock.patch.object(scanner, "_upload"), mock.patch.object(
        scanner, "_upload_summary"
    ):
        scanner._cycle()
    expected = "sensor_absent" if leaves else "capture_failed"
    assert scanner.capture_status() == ("error", expected)


def test_classic_failure_logs_once_per_cause(hci, caplog):
    hci.plug("hci0")
    hci.inq_rc = 1
    scanner = make("hci0")
    with caplog.at_level(logging.WARNING, logger="sigrift.lib.bt_scanner"):
        for _ in range(3):
            scanner._scan_classic()
    assert [m for m in warnings(caplog) if m.startswith("Classic")] == [
        "Classic BT scan failed: Inquiring ..."
    ]


def test_adapter_leaving_mid_scan_is_reported_absent(hci):
    hci.plug("hci0")
    scanner = make("hci0")
    hci.after_tool = lambda: hci._present("hci0") and hci.unplug("hci0")
    scanner._cycle()
    assert scanner.capture_status() == ("error", "sensor_absent")


def test_dead_scan_thread_is_not_left_running(hci):
    scanner = make("hci0")
    scanner._status = ("running", None)
    scanner._thread = threading.Thread(target=lambda: None)
    scanner._thread.start()
    scanner._thread.join()
    assert scanner.capture_status() == ("error", "capture_failed")


# ---------------------------------------------------------------------------
# The real service: fake tools on PATH, a fake bridge, SIGTERM in each state
# ---------------------------------------------------------------------------

_WRAPPER = """
import functools, sys
from pathlib import Path
import sigrift.lib.bt_scanner as m
m._BT_SYSFS = Path(sys.argv[1])
m._BLE_SCAN_DURATION = float(sys.argv[2])
m.ScannerStatusReporter = functools.partial(m.ScannerStatusReporter, interval=0.2)
sys.argv = sys.argv[:1]
m.main()
"""


@pytest.fixture
def bridge():
    posts: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if self.path.endswith("/scanner-status"):
                posts.append(json.loads(body))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", posts
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=30)


def _tools(tmp_path: Path, sysfs: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    scripts = {
        "hciconfig": f"""#!/bin/sh
[ -d "{sysfs}/$1" ] || exit 1
if [ -f "{tmp_path}/$1.down" ]; then echo "DOWN"; else echo "UP RUNNING"; fi
""",
        # lescan runs until SIGINT, like hcitool, and exits 0 on it. A trap
        # interrupts `wait` at once; it gives up after LESCAN_LIMIT s.
        "hcitool": f"""#!/bin/sh
[ -d "{sysfs}/$2" ] || exit 1
if [ "$3" = lescan ]; then
  trap 'kill $sleeper 2>/dev/null; exit 0' INT
  trap 'kill $sleeper 2>/dev/null; exit 143' TERM
  echo $$ > "{tmp_path}/lescan.pid"
  sleep {LESCAN_LIMIT} >/dev/null 2>&1 &
  sleeper=$!
  touch "{tmp_path}/lescan"
  wait $sleeper
fi
exit 0
""",
        "bluetoothctl": "#!/bin/sh\nexit 0\n",
    }
    for name, text in scripts.items():
        path = bin_dir / name
        path.write_text(text)
        path.chmod(0o755)
    return bin_dir


# A state the service must REACH, or its exit after SIGTERM. Generous on
# purpose: the service and every tool stand-in are separate processes that can
# each take seconds to start on a loaded runner. The polls return as soon as
# the state is reached.
WAIT = 60.0
# The scan the service is in when SIGTERM arrives in state "mid_scan". It
# lasts several times WAIT, so an exit that waited for the scan to finish
# cannot pass for a prompt one.
MID_SCAN = 300
# The lescan stand-in gives up after this, so none outlives a failed test long.
LESCAN_LIMIT = MID_SCAN + 30


def _wait(predicate, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


@pytest.mark.parametrize("state", ["absent", "down", "running", "mid_scan"])
def test_service_reports_and_exits_zero_on_sigterm(tmp_path, bridge, state):
    url, posts = bridge
    sysfs = tmp_path / "sys"
    sysfs.mkdir()
    if state != "absent":
        (sysfs / "hci0").mkdir()
    if state == "down":
        (tmp_path / "hci0.down").touch()
    bin_dir = _tools(tmp_path, sysfs)
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "PYTHONPATH": str(SRC),
        "MLRF_SCANNER_CONFIG_PATH": str(tmp_path / "none.json"),
        "MLRF_BRIDGE_URL": url,
        "MLRF_API_KEY": "k",
        "MLRF_NODE_ID": "node",
        "MLRF_BT_ADAPTER": "hci0",
    }
    duration = str(MID_SCAN) if state == "mid_scan" else "0.2"
    child = subprocess.Popen(
        [sys.executable, "-c", _WRAPPER, str(sysfs), duration],
        env=env,
        cwd=tmp_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        expected = {
            "absent": {
                "protocol": "bluetooth",
                "state": "error",
                "reason": "sensor_absent",
            },
            "down": {
                "protocol": "bluetooth",
                "state": "error",
                "reason": "capture_failed",
            },
            "running": {"protocol": "bluetooth", "state": "running"},
            "mid_scan": {
                "protocol": "bluetooth",
                "state": "error",
                "reason": "starting",
            },
        }[state]
        assert _wait(lambda: expected in posts), posts
        if state == "mid_scan":
            assert _wait((tmp_path / "lescan").exists)
        child.send_signal(signal.SIGTERM)
        # Bounded well below the MID_SCAN scan: the scan is not waited out.
        output, _ = child.communicate(timeout=WAIT)
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate()
        # The service exits without its scan thread; end the orphaned lescan.
        # (In the other states the service itself ended lescan.)
        pid_file = tmp_path / "lescan.pid"
        if state == "mid_scan" and pid_file.exists():
            try:
                os.kill(int(pid_file.read_text()), signal.SIGINT)
            except (ProcessLookupError, ValueError):
                pass

    assert child.returncode == 0, output
    assert "Traceback" not in output
    assert posts[-1] == {"protocol": "bluetooth", "state": "stopped"}
    # Only the fixed fields ever reach the bridge.
    assert all(set(p) <= {"protocol", "state", "reason"} for p in posts)
