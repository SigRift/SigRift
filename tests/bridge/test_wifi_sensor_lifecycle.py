"""Wi-Fi sensor lifecycle (docs/sensor-lifecycle.md) on fake sysfs; never a radio."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import logging
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from unittest.mock import patch

import pytest

from sigrift.edge import sensor_presence as sp


# These tests drive real worker and stand-in processes. The project default of
# 30 s per test (pyproject.toml) is too short for them on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)

ROOT = Path(__file__).resolve().parents[2]
IFACE = "wlan9"
MAC_A = "02:11:22:33:44:55"
MAC_B = "02:66:77:88:99:aa"
# Runs the worker against a fake sysfs with short lifecycle and lease periods.
LAUNCH = (
    "import functools, sys; from pathlib import Path; "
    "import sigrift.edge.wifi_scan as w; "
    "w.NET_SYSFS = Path(sys.argv[1]); w.RETRY_INTERVAL = w.WATCH_INTERVAL = 0.1; "
    "w.ScannerStatusReporter = functools.partial("
    "w.ScannerStatusReporter, interval=0.05); "
    "sys.exit(w.main())"
)


@pytest.fixture(scope="module")
def wifi():
    # Importing the standalone worker installs its logger; no host log writes.
    with patch("pathlib.Path.mkdir", side_effect=PermissionError):
        return importlib.import_module("sigrift.edge.wifi_scan")


def plug(sysfs, *, phy="phy1", ifindex=7, mac=MAC_A, port="3-1"):
    """Real sysfs shape: class links resolve under /sys/devices."""
    device = sysfs / "devices/platform/usb3" / port / f"{port}:1.0"
    device.mkdir(parents=True, exist_ok=True)
    wiphy = device / "ieee80211" / phy
    wiphy.mkdir(parents=True)
    (wiphy / "macaddress").write_text(mac + "\n")
    (wiphy / "device").symlink_to(device, target_is_directory=True)
    classes = sysfs / "class/ieee80211"
    classes.mkdir(parents=True, exist_ok=True)
    (classes / phy).symlink_to(wiphy, target_is_directory=True)
    net = device / "net" / IFACE
    net.mkdir(parents=True)
    (net / "phy80211").symlink_to(wiphy, target_is_directory=True)
    (net / "ifindex").write_text(f"{ifindex}\n")
    (net / "type").write_text("1\n")  # A returning adapter is managed.
    netclass = sysfs / "class/net"
    netclass.mkdir(parents=True, exist_ok=True)
    (netclass / IFACE).symlink_to(net, target_is_directory=True)


def unplug(sysfs, *, phy="phy1"):
    (sysfs / "class/net" / IFACE).unlink()
    (sysfs / "class/ieee80211" / phy).unlink()
    for path in sorted((sysfs / "devices").rglob("*"), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            path.rmdir()


# Limits for a state the worker must REACH. They are generous on purpose: on a
# loaded CI runner the worker and every stand-in command are separate Python
# processes that can each take seconds to start. The polls return as soon as
# the state is reached, so a fast machine is not slowed down.
WAIT = 60.0
STOP = 60.0  # the worker must exit after SIGTERM; a hang is still caught
# Waits for a helper process or thread to end; returns as soon as it has.
REAP = 30.0


def wait_for(predicate, message, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(message)
        time.sleep(0.01)


# --- Capture child that this container cannot signal --------------------------


class OtherUserChild(subprocess.Popen):
    """tcpdump after dropping privileges, in a container without CAP_KILL."""

    signals: list

    def send_signal(self, sig):
        self.signals.append(sig)
        if self.poll() is None:
            raise PermissionError(1, "Operation not permitted")


def other_user_child(code):
    OtherUserChild.signals = []
    return OtherUserChild(
        [sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def test_unsignalable_writing_child_ends_through_its_closed_stdout(wifi, monkeypatch):
    # Like tcpdump on a busy channel: it writes, so a closed pipe ends it.
    child = other_user_child(
        "import sys,time\n"
        "while True: sys.stdout.buffer.write(b'x'*64); sys.stdout.flush(); "
        "time.sleep(.01)"
    )
    scanner = wifi.WifiScanner("unused-test-interface")
    # The product gives a refused child SIGNAL_DENIED_TIMEOUT (0.5 s) to end
    # from its closed stdout. On a loaded runner the stand-in may not reach
    # its next write in that time, so the waits are lengthened here; the wait
    # still returns as soon as the child has exited.
    monkeypatch.setattr(scanner, "STOP_TIMEOUT", 60.0)
    monkeypatch.setattr(scanner, "KILL_TIMEOUT", 60.0)
    monkeypatch.setattr(scanner, "SIGNAL_DENIED_TIMEOUT", 60.0)
    scanner._proc = child
    try:
        started = time.monotonic()
        scanner.stop()  # Must not raise PermissionError.
        elapsed = time.monotonic() - started
        # It ended by itself: the one signal tried was refused, nothing else
        # was sent, and stop() did not run out its wait.
        assert child.returncode is not None
        assert OtherUserChild.signals == [signal.SIGTERM]
        assert elapsed < scanner.SIGNAL_DENIED_TIMEOUT / 2
        assert scanner._proc is None
    finally:
        if child.poll() is None:
            os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=REAP)
        child.stderr.close()


def test_unsignalable_quiet_child_is_bounded_and_never_raises(
    wifi, monkeypatch, caplog
):
    child = other_user_child("import time; time.sleep(30)")
    scanner = wifi.WifiScanner("unused-test-interface")
    # The full waits would overrun Docker's 10 s stop window; once a signal
    # is refused, only the short wait for the closed stdout remains. The full
    # waits are made long here (60 s together), so that waiting them out
    # cannot pass the bound below even on a loaded runner.
    monkeypatch.setattr(scanner, "STOP_TIMEOUT", 30.0)
    monkeypatch.setattr(scanner, "KILL_TIMEOUT", 30.0)
    monkeypatch.setattr(scanner, "SIGNAL_DENIED_TIMEOUT", 0.2)
    scanner._proc = child
    try:
        with caplog.at_level(logging.WARNING, logger="wifi_scan"):
            started = time.monotonic()
            scanner.stop()
            elapsed = time.monotonic() - started
        assert elapsed < 15
        assert OtherUserChild.signals == [signal.SIGTERM]  # SIGKILL fails alike.
        assert "did not exit and cannot be signalled" in caplog.text
    finally:
        os.kill(child.pid, signal.SIGKILL)
        child.wait(timeout=REAP)
        child.stderr.close()


def test_unexpected_exit_logs_code_and_bounded_stderr_tail(
    wifi, tmp_path, monkeypatch, caplog
):
    (tmp_path / "net" / IFACE).mkdir(parents=True)  # Still there: a real failure.
    monkeypatch.setattr(wifi, "NET_SYSFS", tmp_path / "net")
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys\n"
            "for n in range(100): print('noise', n, 'z'*500, file=sys.stderr)\n"
            "print('tcpdump: wlan9: That device is not up', file=sys.stderr)\n"
            "sys.exit(1)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    scanner = wifi.WifiScanner("wlan9")
    scanner._proc = child
    scanner._stderr_thread = threading.Thread(
        target=scanner._drain_stderr, args=(child.stderr, scanner._stderr_stop)
    )
    scanner._stderr_thread.start()
    child.wait(timeout=REAP)
    # The reader keeps the tail; let it reach the end of the exited child's
    # output first. stop() itself gives the reader only 1 s, which a loaded
    # runner can outlast (that bound is the product's, not this test's).
    scanner._stderr_thread.join(timeout=REAP)
    assert not scanner._stderr_thread.is_alive()
    with caplog.at_level(logging.WARNING, logger="wifi_scan"):
        scanner.stop()
    [line] = [r.getMessage() for r in caplog.records if "exited" in r.getMessage()]
    assert line.startswith("tcpdump on wlan9 exited unexpectedly (code 1): ")
    assert line.endswith("tcpdump: wlan9: That device is not up")
    assert line.count(" | ") == 4  # Only the last five lines are kept.
    assert len(line) < 1200


@pytest.mark.parametrize("end_reason", [None, sp.SENSOR_ABSENT, sp.SENSOR_CHANGED])
def test_exit_with_its_interface_gone_is_not_a_second_warning(
    wifi, tmp_path, monkeypatch, caplog, end_reason
):
    netdir = tmp_path / "net"
    netdir.mkdir()
    if end_reason == sp.SENSOR_CHANGED:
        (netdir / IFACE).mkdir()  # Another adapter now holds the name.
    monkeypatch.setattr(wifi, "NET_SYSFS", netdir)
    child = subprocess.Popen(
        [sys.executable, "-c", "import sys; sys.exit(1)"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child.wait(timeout=REAP)
    child.stderr.close()
    scanner = wifi.WifiScanner(IFACE)
    scanner._proc = child
    scanner.end_reason = end_reason
    with caplog.at_level(logging.DEBUG, logger="wifi_scan"):
        scanner.stop()
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
    assert any("exited with its interface" in r.getMessage() for r in caplog.records)


# --- Watchdog -------------------------------------------------------------------


@pytest.fixture
def capturing(wifi, tmp_path, monkeypatch):
    """A scanner mid-round on a fake radio; restore commands are recorded."""
    sysfs = tmp_path / "sys"
    plug(sysfs)
    (sysfs / "class/net" / IFACE / "type").write_text("803\n")
    net = sysfs / "class/net"
    identity = sp.wifi_identity(IFACE, sysfs=net)
    commands = []
    monkeypatch.setattr(
        wifi.subprocess, "run", lambda command, **_: commands.append(command)
    )
    monkeypatch.setattr(wifi, "NET_SYSFS", net)
    scanner = wifi.WifiScanner(
        IFACE, probe=lambda: sp.find_wifi_sensor(IFACE, identity, sysfs=net)
    )
    scanner._monitor.enable()
    commands.clear()
    scanner._running = True
    scanner._started_at = time.monotonic()
    scanner._ifindex = 7
    return scanner, sysfs, commands


def test_watchdog_accepts_healthy_capture(capturing):
    scanner, _, _ = capturing
    assert scanner.health_problem() is None


def test_watchdog_vanished_interface_and_no_restore_touches_it(capturing):
    scanner, sysfs, commands = capturing
    unplug(sysfs)
    assert scanner.health_problem() == (sp.SENSOR_ABSENT, f"{IFACE} disappeared")
    scanner.stop()
    assert commands == []
    assert not scanner._monitor.pending


def test_watchdog_recreated_interface_is_a_stale_socket(capturing):
    scanner, sysfs, commands = capturing
    unplug(sysfs)
    plug(sysfs, phy="phy2", ifindex=8)
    reason, message = scanner.health_problem()
    assert reason == sp.SENSOR_ABSENT
    assert "re-created" in message
    scanner.stop()
    assert commands == []  # The new interface already starts managed.


def test_watchdog_swapped_adapter_is_changed_and_never_touched(capturing):
    scanner, sysfs, commands = capturing
    unplug(sysfs)
    plug(sysfs, phy="phy2", ifindex=8, mac=MAC_B)
    assert scanner.health_problem()[0] == sp.SENSOR_CHANGED
    scanner.stop()
    assert commands == []


def test_watchdog_managed_mode_ends_round_and_restore_runs(capturing):
    scanner, sysfs, commands = capturing
    (sysfs / "class/net" / IFACE / "type").write_text("1\n")
    assert scanner.health_problem() == (
        sp.CAPTURE_FAILED,
        f"{IFACE} left monitor mode",
    )
    scanner.stop()  # Same interface: restoring managed mode is still right.
    assert ["iw", "dev", IFACE, "set", "type", "managed"] in commands


def test_watchdog_channel_hopping_failing_too_long(capturing, wifi, monkeypatch):
    scanner, _, _ = capturing
    # A long limit, so that "just inside it" stays inside even when the
    # runner stalls between setting the time and the check.
    limit = 600.0
    monkeypatch.setattr(wifi, "HOP_FAILURE_LIMIT", limit)
    scanner._last_channel_success = time.monotonic() - (limit - 60)
    assert scanner.health_problem() is None
    scanner._last_channel_success = time.monotonic() - (limit + 1)
    assert scanner.health_problem()[0] == sp.CAPTURE_FAILED
    scanner._last_channel_success = None
    scanner._started_at = time.monotonic() - (limit + 1)  # Never hopped this round.
    assert "channel hopping" in scanner.health_problem()[1]


@pytest.mark.parametrize("cause", ["unplugged", "managed"])
def test_watchdog_thread_ends_round_once(capturing, wifi, monkeypatch, caplog, cause):
    scanner, sysfs, _ = capturing
    monkeypatch.setattr(wifi, "WATCH_INTERVAL", 0.01)
    if cause == "unplugged":
        unplug(sysfs)
    else:
        (sysfs / "class/net" / IFACE / "type").write_text("1\n")
    with caplog.at_level(logging.DEBUG, logger="wifi_scan"):
        scanner._watch()
    assert not scanner._running
    ended = [r for r in caplog.records if "Ending capture round" in r.getMessage()]
    assert len(ended) == 1
    if cause == "unplugged":
        # PresenceTracker logs the one WARNING for an absent sensor.
        assert scanner.end_reason == sp.SENSOR_ABSENT
        assert ended[0].levelno == logging.DEBUG
    else:
        assert scanner.end_reason == sp.CAPTURE_FAILED
        assert ended[0].levelno == logging.WARNING


# --- Start of a round: the adapter enable() configures -------------------------


@pytest.fixture
def starting(wifi, tmp_path, monkeypatch):
    """A scanner about to start on a fake radio; interface commands recorded."""
    sysfs = tmp_path / "sys"
    plug(sysfs)
    net = sysfs / "class/net"
    identity = sp.wifi_identity(IFACE, sysfs=net)
    commands, hooks = [], {}

    def run(command, **_):
        commands.append(command)
        hooks.pop(tuple(command), lambda: None)()

    monkeypatch.setattr(wifi.subprocess, "run", run)
    monkeypatch.setattr(wifi, "NET_SYSFS", net)

    def scanner(pinned=True):
        return wifi.WifiScanner(
            IFACE,
            probe=lambda: sp.find_wifi_sensor(
                IFACE, identity if pinned else None, sysfs=net
            ),
        )

    return scanner, sysfs, commands, hooks


@pytest.mark.parametrize(
    ("mac", "reason"), [(None, sp.SENSOR_ABSENT), (MAC_B, sp.SENSOR_CHANGED)]
)
def test_start_never_configures_an_adapter_swapped_after_the_check(
    wifi, starting, mac, reason
):
    make, sysfs, commands, _ = starting
    scanner = make()
    unplug(sysfs)  # Between wait_until_present and start().
    if mac is not None:
        plug(sysfs, phy="phy2", ifindex=8, mac=mac)
    with pytest.raises(wifi.SensorLost):
        scanner.start()
    assert scanner.end_reason == reason
    scanner.stop()
    assert commands == []


@pytest.mark.parametrize("pinned", [True, False])
def test_adapter_swapped_during_enable_is_refused_and_left_alone(
    wifi, starting, pinned
):
    make, sysfs, commands, hooks = starting
    scanner = make(pinned)

    def swap():
        unplug(sysfs)
        plug(sysfs, phy="phy2", ifindex=8, mac=MAC_B)

    hooks[("iw", "dev", IFACE, "set", "type", "monitor")] = swap
    with pytest.raises(wifi.SensorLost):
        scanner.start()
    assert scanner.end_reason == (sp.SENSOR_CHANGED if pinned else sp.SENSOR_ABSENT)
    configured = len(commands)
    scanner.stop()
    # The new adapter was not the one this round set up: no restore touches it.
    assert len(commands) == configured
    assert not scanner._monitor.pending


def test_unchanged_adapter_is_configured_and_restored(wifi, starting, monkeypatch):
    make, _, commands, _ = starting
    scanner = make()

    def no_tcpdump(*_args, **_kwargs):
        raise FileNotFoundError("tcpdump")

    monkeypatch.setattr(wifi.subprocess, "Popen", no_tcpdump)
    with pytest.raises(FileNotFoundError):
        scanner.start()
    assert scanner._ifindex == 7
    assert ["iw", "dev", IFACE, "set", "type", "monitor"] in commands
    scanner.stop()  # Same ifindex as before enable(): managed mode is restored.
    assert ["iw", "dev", IFACE, "set", "type", "managed"] in commands


# --- Whole worker, real signals ---------------------------------------------------


@contextmanager
def bridge_endpoint():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            received.append((self.path, json.loads(self.rfile.read(length))))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=REAP)


STANDIN = r"""
import json,os,struct,sys,time
from pathlib import Path
name=Path(sys.argv[0]).name
fd=os.open(os.environ['LIFECYCLE_COMMANDS'],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
try: os.write(fd,(json.dumps([name,os.getpid(),*sys.argv[1:]])+'\n').encode())
finally: os.close(fd)
radio=Path(os.environ['LIFECYCLE_SYSFS'])/os.environ['LIFECYCLE_IFACE']
if name=='tcpdump':
    # Quiet air: a radiotap pcap header, then nothing. Survives the interface
    # unless told to exit with it, as the real tcpdump does.
    sys.stdout.buffer.write(struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,512,127))
    sys.stdout.buffer.flush()
    while True:
        time.sleep(.05)
        if os.environ.get('LIFECYCLE_TCPDUMP_EXITS') and not radio.exists():
            print('tcpdump: The interface went down', file=sys.stderr); sys.exit(1)
if not radio.exists():
    print('Cannot find device', file=sys.stderr); sys.exit(1)
if name=='iw' and sys.argv[3:5]==['set','type']:
    if sys.argv[5]=='monitor' and os.environ.get('LIFECYCLE_FAIL_MONITOR'):
        print('Device or resource busy', file=sys.stderr); sys.exit(240)
    (radio/'type').write_text('803\n' if sys.argv[5]=='monitor' else '1\n')
"""


class Worker:
    """wifi_scan as a real process, with ip/iw/tcpdump stand-ins on PATH."""

    def __init__(self, tmp_path, url, received, **env):
        self.tmp_path = tmp_path
        self.received = received
        self.sysfs = tmp_path / "sys"
        (self.sysfs / "class/net").mkdir(parents=True, exist_ok=True)
        bindir = tmp_path / "bin"
        bindir.mkdir()
        for name in ("ip", "iw", "tcpdump"):
            (bindir / name).write_text(f"#!{sys.executable}\n{STANDIN}")
            (bindir / name).chmod(0o700)
        self.commands = tmp_path / "commands.jsonl"
        self.log = tmp_path / "worker.log"
        environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("MLRF_", "BRIDGE_", "SIGRIFT_", "PYTHON"))
            and key.upper()
            not in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSLKEYLOGFILE"}
        }
        environment.update(
            HOME=str(tmp_path),
            PATH=str(bindir) + os.pathsep + environment["PATH"],
            PYTHONPATH=str(ROOT / "src"),
            PYTHONDONTWRITEBYTECODE="1",
            MLRF_BRIDGE_URL=url,
            MLRF_BRIDGE_KEY="software-fixture-key",
            MLRF_NODE_ID="lifecycle-node",
            MLRF_WIFI_IFACE=IFACE,
            MLRF_WIFI_BANDS="2.4",
            MLRF_CHANNEL_DWELL="0.05",
            MLRF_FLUSH_INTERVAL="0.05",
            MLRF_SUMMARIZE="false",
            LIFECYCLE_COMMANDS=str(self.commands),
            LIFECYCLE_SYSFS=str(self.sysfs / "class/net"),
            LIFECYCLE_IFACE=IFACE,
            **env,
        )
        self._log_file = self.log.open("w")
        self.process = subprocess.Popen(
            [sys.executable, "-c", LAUNCH, str(self.sysfs / "class/net")],
            cwd=tmp_path,
            env=environment,
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def calls(self):
        if not self.commands.exists():
            return []
        return [json.loads(line) for line in self.commands.read_text().splitlines()]

    def text(self):
        return self.log.read_text()

    def statuses(self):
        return [
            body for path, body in self.received if path.endswith("/scanner-status")
        ]

    def captures(self):
        return [call for call in self.calls() if call[0] == "tcpdump"]

    def configures(self):
        """ip link / iw set type commands, which change the interface."""
        return [
            call
            for call in self.calls()
            if call[0] == "ip" or call[4:6] == ["set", "type"]
        ]

    def wait_log(self, text, count=1):
        wait_for(
            lambda: self.text().count(text) >= count, f"no {text!r}:\n" + self.text()
        )

    def wait_reason(self, reason):
        wait_for(
            lambda: any(s.get("reason") == reason for s in self.statuses()),
            f"no status reason {reason}",
        )

    def wait_capturing(self, rounds=1):
        wait_for(
            lambda: len(self.captures()) >= rounds
            and any(call[4:6] == ["set", "channel"] for call in self.calls()),
            "capture did not start:\n" + self.text(),
        )

    def sigterm(self):
        assert self.process.poll() is None, self.text()
        self.process.send_signal(signal.SIGTERM)
        try:
            result = self.process.wait(timeout=STOP)
        except subprocess.TimeoutExpired:
            pytest.fail("worker ignored SIGTERM:\n" + self.text())
        assert result == 0, self.text()
        assert self.statuses()[-1] == {"protocol": "wifi", "state": "stopped"}
        self.check_private()

    def check_private(self):
        text = self.text()
        assert "Traceback" not in text, text
        for mac in (MAC_A, MAC_B):
            assert mac not in text
        for body in self.statuses():
            assert set(body) <= {"protocol", "state", "reason"}
            assert body.get("reason") in {None, *sp.REASONS}
        for call in self.captures():
            # Every capture child is gone: none is left holding the radio.
            with pytest.raises(ProcessLookupError):
                os.kill(call[1], 0)

    def close(self):
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=REAP)
        self._log_file.close()


@contextmanager
def worker(tmp_path, **env):
    with bridge_endpoint() as (url, received):
        running = Worker(tmp_path, url, received, **env)
        try:
            yield running
        finally:
            running.close()


@pytest.mark.parametrize("child_exits", [False, True])
def test_absent_at_start_then_unplug_and_replug_with_new_numbers(
    tmp_path, child_exits
):
    env = {"LIFECYCLE_TCPDUMP_EXITS": "1"} if child_exits else {}
    with worker(tmp_path, **env) as w:
        w.wait_log("wifi sensor absent; waiting for it to return")
        w.wait_reason(sp.SENSOR_ABSENT)
        time.sleep(0.5)  # Several re-checks: still one line, nothing touched.
        assert w.text().count("sensor absent") == 1
        assert w.calls() == []
        assert w.process.poll() is None

        plug(w.sysfs)
        w.wait_capturing()
        w.wait_log("Capture running on wlan9")
        first = w.captures()[0][1]

        configured = len(w.configures())
        warned = w.text().count("[WARNING]")
        unplug(w.sysfs)
        w.wait_log("wifi sensor absent; waiting for it to return", count=2)
        w.wait_reason(sp.SENSOR_ABSENT)
        wait_for(lambda: _gone(first), "stale capture child left running")
        assert len(w.configures()) == configured  # Nothing to restore.
        time.sleep(0.3)  # Several re-checks: still one line for this change.
        assert w.text().count("[WARNING]") == warned + 1, w.text()

        # Same radio, new phy and ifindex, back in managed mode.
        plug(w.sysfs, phy="phy7", ifindex=12)
        w.wait_capturing(rounds=2)
        w.wait_log("Capture running on wlan9", count=2)
        monitor = ["dev", IFACE, "set", "type", "monitor"]
        assert [call[2:] for call in w.calls() if call[0] == "iw"].count(monitor) == 2
        assert w.text().count("sensor absent") == 2
        w.sigterm()
        assert w.calls()[-1][0] == "ip" and w.calls()[-1][2:] == [
            "link",
            "set",
            IFACE,
            "up",
        ]


def _gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    # A reaped child is gone; an unreaped zombie still answers signal 0.
    return False


def test_recreated_interface_is_picked_up_without_absence(tmp_path):
    with worker(tmp_path) as w:
        plug(w.sysfs)
        w.wait_capturing()
        w.wait_log("Capture running on wlan9")
        # Re-created between two watchdog checks: the old socket is stale.
        unplug(w.sysfs)
        plug(w.sysfs, phy="phy2", ifindex=8)
        w.wait_capturing(rounds=2)
        w.wait_log("Capture running on wlan9", count=2)
        w.sigterm()


def test_swapped_adapter_is_refused_until_the_selected_one_returns(tmp_path):
    sysfs = tmp_path / "sys"
    plug(sysfs)
    identity = sp.wifi_identity(IFACE, sysfs=sysfs / "class/net")
    unplug(sysfs)
    with worker(tmp_path, MLRF_WIFI_IDENTITY=identity) as w:
        plug(w.sysfs)
        w.wait_capturing()
        configured = len(w.configures())
        unplug(w.sysfs)
        plug(w.sysfs, phy="phy2", ifindex=8, mac=MAC_B)
        w.wait_log("replaced by a different device")
        w.wait_reason(sp.SENSOR_CHANGED)
        time.sleep(0.5)  # Several re-checks: one line, the new radio untouched.
        assert w.text().count("replaced by a different device") == 1
        assert len(w.configures()) == configured
        assert len(w.captures()) == 1

        unplug(w.sysfs, phy="phy2")
        plug(w.sysfs, phy="phy3", ifindex=9)
        w.wait_capturing(rounds=2)
        w.sigterm()


def test_without_identity_a_different_adapter_is_used(tmp_path):
    with worker(tmp_path) as w:
        plug(w.sysfs, mac=MAC_B, port="3-2")
        w.wait_capturing()
        w.sigterm()


def test_capture_failure_on_present_radio_backs_off_and_logs_once(tmp_path):
    with worker(tmp_path, LIFECYCLE_FAIL_MONITOR="1") as w:
        plug(w.sysfs)
        w.wait_reason(sp.CAPTURE_FAILED)
        wait_for(
            lambda: sum(call[4:7] == ["set", "type", "monitor"] for call in w.calls())
            >= 3,
            "failed round was not retried",
        )
        assert w.text().count("Could not enable monitor mode on wlan9") == 1
        assert w.captures() == []
        w.sigterm()


@pytest.mark.parametrize("state", ["absent", "changed", "capturing", "failing"])
def test_sigterm_exits_zero_in_every_sensor_state(tmp_path, state):
    env = {}
    if state == "changed":
        env["MLRF_WIFI_IDENTITY"] = "0" * 64
    if state == "failing":
        env["LIFECYCLE_FAIL_MONITOR"] = "1"
    with worker(tmp_path, **env) as w:
        if state != "absent":
            plug(w.sysfs)
        {
            "absent": lambda: w.wait_reason(sp.SENSOR_ABSENT),
            "changed": lambda: w.wait_reason(sp.SENSOR_CHANGED),
            "capturing": w.wait_capturing,
            "failing": lambda: w.wait_reason(sp.CAPTURE_FAILED),
        }[state]()
        w.sigterm()
        if state in {"absent", "changed"}:
            assert w.configures() == []


def test_status_reports_starting_before_the_first_round_runs(tmp_path):
    plug(tmp_path / "sys")  # Present from the start: never sensor_absent.
    with worker(tmp_path) as w:
        w.wait_capturing()
        w.sigterm()
        assert w.statuses()[0] == {
            "protocol": "wifi",
            "state": "error",
            "reason": "starting",
        }


def test_invalid_identity_is_a_clear_configuration_error(tmp_path):
    with worker(tmp_path, MLRF_WIFI_IDENTITY="not-an-identity") as w:
        assert w.process.wait(timeout=STOP) == 1
        assert "MLRF_WIFI_IDENTITY is invalid" in w.text()
        assert "Traceback" not in w.text()
        assert w.calls() == []
