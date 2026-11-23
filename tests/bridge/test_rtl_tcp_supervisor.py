"""rtl-tcp supervisor: absent, swapped, renumbered and failing receivers.

A fake rtl_tcp (a small Python script) stands in for the binary; fake sysfs
and /dev trees stand in for the receiver. No hardware is needed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from sigrift.edge import rtl_tcp_supervisor as sup
from sigrift.edge import sensor_presence as sp

# These tests drive a real supervisor thread or process and fake rtl_tcp
# processes, with generous limits below. The project default of 30 s per test
# (pyproject.toml) is too short for them on a loaded CI runner.
pytestmark = pytest.mark.timeout(180)

ROOT = Path(__file__).resolve().parents[2]
SERIAL = "SDRSERIAL42"
# Limit for a state the supervisor must REACH, or for it or a helper to end.
# Generous on purpose: on a loaded CI runner each fake rtl_tcp is a Python
# process that can take seconds to start. The polls return as soon as the
# state is reached, so a fast machine is not slowed down.
WAIT = 60.0

FAKE_RTL_TCP = textwrap.dedent(
    """
    import os, signal, sys, time
    from pathlib import Path

    work = Path(sys.argv[1])
    args = sys.argv[2:]
    mode = (work / "mode").read_text().strip()
    if mode != "ignore_term":
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    else:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    with open(work / "starts", "a") as out:
        out.write(" ".join(args) + "\\n")
    (work / "pid").write_text(str(os.getpid()))
    node = work / "node"
    if node.exists():
        # Like the real rtl_tcp: hold the USB node open (legacy watch).
        fd = work / "proc" / str(os.getpid()) / "fd"
        fd.mkdir(parents=True)
        (fd / "5").symlink_to(node.read_text().strip())
    print("Found 1 device(s):", flush=True)
    print("  0:  Realtek, RTL2838UHIDIR, SN: " + "%s", flush=True)
    if mode == "exit":
        print("usb_claim_interface error -6", flush=True)
        sys.exit(1)
    if mode == "flood":
        while True:
            print("rtlsdr_demod_read_reg failed with -4", flush=True)
            print("rtlsdr_demod_write_reg failed with -4", flush=True)
            time.sleep(0.01)
    print("Listening...", flush=True)
    while True:
        time.sleep(0.05)
    """
    % SERIAL
)


def usb_device(sysfs, port="3-1", *, busnum=1, devnum=4, serial=SERIAL, ids=None):
    entry = sysfs / port
    entry.mkdir(parents=True, exist_ok=True)
    vendor, product = ids or ("0bda", "2838")
    (entry / "idVendor").write_text(vendor + "\n")
    (entry / "idProduct").write_text(product + "\n")
    (entry / "busnum").write_text(f"{busnum}\n")
    (entry / "devnum").write_text(f"{devnum}\n")
    if serial is not None:
        (entry / "serial").write_text(serial + "\n")
    elif (entry / "serial").exists():
        (entry / "serial").unlink()
    return entry


def identity_of(serial=SERIAL):
    return hashlib.sha256(f"0bda:2838:{serial}".encode()).hexdigest()


def remove_device(sysfs, port="3-1"):
    for item in (sysfs / port).iterdir():
        item.unlink()
    (sysfs / port).rmdir()


def renumber(sysfs, port="3-1", devnum=5):
    (sysfs / port / "devnum").write_text(f"{devnum}\n")


class Rig:
    """Fake sysfs, /dev, /proc and rtl_tcp for one supervisor."""

    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.sysfs = tmp_path / "sys"
        self.sysfs.mkdir()
        self.dev = tmp_path / "dev-root"
        self.dev.mkdir()
        self.work = tmp_path / "work"
        self.work.mkdir()
        self.state_file = tmp_path / "state"
        self.script = tmp_path / "fake_rtl_tcp.py"
        self.script.write_text(FAKE_RTL_TCP)
        self.mode("run")
        self.supervisor = None
        self.thread = None
        self.result = []

    def mode(self, value):
        (self.work / "mode").write_text(value)

    def visible(self, busnum=1, devnum=4):
        node = self.dev / f"dev/bus/usb/{busnum:03d}/{devnum:03d}"
        node.parent.mkdir(parents=True, exist_ok=True)
        node.write_text("")
        return f"/dev/bus/usb/{busnum:03d}/{devnum:03d}"

    def hold_node(self, node):
        (self.work / "node").write_text(node)

    def identity(self, port="3-1"):
        return sp.usb_identity(self.sysfs / port)

    def make(self, usb_port=None, identity=None, **kwargs):
        options = dict(
            command=[sys.executable, str(self.script), str(self.work)],
            sysfs=self.sysfs,
            proc=self.work / "proc",
            dev_root=self.dev,
            state_file=self.state_file,
            status_port=0,
            poll=0.05,
        )
        options.update(kwargs)
        return sup.Supervisor(usb_port, identity, **options)

    def start(self, usb_port=None, identity=None, **kwargs):
        self.supervisor = self.make(usb_port, identity, **kwargs)
        self.thread = threading.Thread(
            target=lambda: self.result.append(self.supervisor.run()), daemon=True
        )
        self.thread.start()
        return self.supervisor

    def stop(self):
        self.supervisor.request_stop()
        return self.join()

    def join(self, timeout=WAIT):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "supervisor did not finish"
        return self.result[0]

    def starts(self):
        path = self.work / "starts"
        return path.read_text().splitlines() if path.exists() else []

    def query(self):
        server = self.supervisor._server
        if server is None:
            return ""  # not listening yet
        port = server.server_address[1]
        data = b""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=30) as conn:
                while chunk := conn.recv(64):
                    data += chunk
        except OSError:
            return ""  # stopped listening
        return data.decode()

    def child_pid(self):
        # "running" is published when rtl_tcp is spawned, before it starts.
        assert wait_for((self.work / "pid").exists)
        return int((self.work / "pid").read_text())


def wait_for(condition, timeout=WAIT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.02)
    return False


def gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    # A zombie is reaped by Popen.wait; still counts as stopped here.
    try:
        return Path(f"/proc/{pid}/status").read_text().count("zombie") > 0
    except OSError:
        return False


@pytest.fixture
def rig(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="rtl_tcp_supervisor")
    value = Rig(tmp_path)
    yield value
    if value.thread is not None and value.thread.is_alive():
        value.stop()
    # Never leave a fake rtl_tcp behind, even when a test failed.
    pid_file = value.work / "pid"
    if pid_file.exists():
        try:
            os.kill(int(pid_file.read_text()), signal.SIGKILL)
        except (ProcessLookupError, ValueError):
            pass


def messages(caplog, needle):
    return [r for r in caplog.records if needle in r.getMessage()]


# --- legacy -----------------------------------------------------------------


def test_legacy_runs_device_zero_and_reports_running(rig, caplog):
    rig.start()
    assert wait_for(lambda: rig.starts() == ["-d 0"])
    assert wait_for(lambda: rig.query() == "running\n")
    assert sup.check(rig.state_file) == 0
    pid = rig.child_pid()
    assert rig.stop() == 0
    assert wait_for(lambda: gone(pid))
    assert rig.state_file.read_text().strip() == "stopped"
    assert sup.check(rig.state_file) == 1


def test_legacy_receiver_lost_exits_75_for_a_new_mapping(rig):
    usb_device(rig.sysfs, "1-1.2", busnum=1, devnum=4)
    rig.hold_node(rig.visible(devnum=4))
    rig.start()
    assert wait_for(lambda: rig.query() == "running\n")
    pid = rig.child_pid()
    # Re-plugged: the kernel gave it a new device number.
    renumber(rig.sysfs, "1-1.2", devnum=9)
    assert rig.join() == sup.RESTART_EXIT
    assert gone(pid)
    assert sup.check(rig.state_file) == 1


def test_legacy_never_mapped_receiver_is_logged_once_and_ignored(rig, caplog):
    usb_device(rig.sysfs, "1-1.2", busnum=1, devnum=4)
    rig.visible(devnum=4)
    usb_device(rig.sysfs, "1-1.3", busnum=1, devnum=8, ids=("148f", "5370"))
    rig.mode("exit")
    supervisor = rig.make()
    original = supervisor._wait
    waits = []

    def quick(seconds):
        waits.append(seconds)
        if len(waits) == 1:
            # Plugged in after start, or left unmapped on purpose: restarting
            # cannot map it, so it must not cause an exit 75 loop.
            usb_device(rig.sysfs, "1-1.4", busnum=1, devnum=9, serial="LATE")
        if len(waits) >= 4:
            supervisor.request_stop()
        original(0.01)

    supervisor._wait = quick
    assert supervisor.run() == 0
    assert len(rig.starts()) == 4
    assert len(messages(caplog, "USB port 1-1.4 has no device node")) == 1
    assert not messages(caplog, "exiting so the service restarts")


def test_legacy_receiver_renumbered_before_a_restart_exits_75(rig, caplog):
    usb_device(rig.sysfs, "1-1.2", busnum=1, devnum=4)
    rig.visible(devnum=4)
    rig.mode("exit")
    rig.start()
    assert wait_for(lambda: len(rig.starts()) == 1)
    # rtl_tcp failed; meanwhile the receiver was re-plugged (new number).
    renumber(rig.sysfs, "1-1.2", devnum=9)
    assert rig.join() == sup.RESTART_EXIT
    assert len(rig.starts()) == 1
    assert len(messages(caplog, "exiting so the service restarts")) == 1
    # Remembered for the next start, which must map it again.
    ports = rig.state_file.with_name(rig.state_file.name + ".ports")
    assert ports.read_text().split() == ["1-1.2"]


def test_legacy_receiver_back_after_a_restart_exits_75_again(rig):
    # Unplugged at the last restart: this start could not map it. It is
    # back now, on a node the container cannot see.
    rig.state_file.with_name(rig.state_file.name + ".ports").write_text("1-1.2\n")
    usb_device(rig.sysfs, "1-1.2", busnum=1, devnum=9)
    rig.start()
    assert rig.join() == sup.RESTART_EXIT
    assert rig.starts() == []


def test_legacy_no_device_error_burst_exits_75(rig, caplog):
    rig.mode("flood")
    rig.start()
    assert rig.join() == sup.RESTART_EXIT
    assert messages(caplog, "USB no-device errors")
    # The flood itself is collapsed: each distinct line shows once.
    assert len(messages(caplog, "demod_read_reg failed with -4")) == 1
    assert len(messages(caplog, "demod_write_reg failed with -4")) == 1


def test_rtl_tcp_exit_is_restarted_with_growing_delay(rig, caplog, monkeypatch):
    rig.mode("exit")
    supervisor = rig.make()
    delays = []
    original = supervisor._wait

    def record(seconds):
        if seconds >= 1.0:
            delays.append(seconds)
            if len(delays) >= 7:
                supervisor.request_stop()
            seconds = 0.01
        original(seconds)

    monkeypatch.setattr(supervisor, "_wait", record)
    assert supervisor.run() == 0
    assert delays == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert len(rig.starts()) == 7
    # One line for the failure streak, and rtl_tcp's repeated output once.
    assert len(messages(caplog, "rtl_tcp exited (code 1)")) == 1
    assert len(messages(caplog, "usb_claim_interface error -6")) == 1


def test_serials_never_reach_the_log(rig, caplog):
    usb_device(rig.sysfs)
    rig.visible()
    rig.start("3-1", rig.identity())
    assert wait_for(lambda: rig.query() == "running\n")
    assert wait_for(lambda: messages(caplog, "Listening"))
    assert messages(caplog, "SN: <hidden>")
    assert rig.stop() == 0
    assert SERIAL not in caplog.text


# --- managed ----------------------------------------------------------------


def test_absent_at_start_waits_then_starts_on_return(rig, caplog):
    rig.start("3-1", identity_of())
    assert wait_for(lambda: rig.query() == "sensor_absent\n")
    time.sleep(0.3)  # several re-checks
    assert rig.starts() == []
    assert len(messages(caplog, "SDR sensor absent")) == 1
    assert sup.check(rig.state_file) == 1
    usb_device(rig.sysfs)
    rig.visible()
    assert wait_for(lambda: rig.query() == "running\n")
    assert wait_for(lambda: rig.starts() == [f"-d {SERIAL}"])
    assert len(messages(caplog, "SDR sensor present")) == 1
    assert rig.stop() == 0


def test_swapped_receiver_is_refused(rig, caplog):
    usb_device(rig.sysfs, serial="OTHER-RECEIVER")
    rig.visible()
    rig.start("3-1", "b" * 64)
    assert wait_for(lambda: rig.query() == "sensor_changed\n")
    time.sleep(0.3)
    assert rig.starts() == []
    assert len(messages(caplog, "replaced by a different device")) == 1
    assert rig.stop() == 0


def test_present_but_node_not_mapped_exits_75(rig, caplog):
    usb_device(rig.sysfs, devnum=7)
    rig.visible(devnum=4)  # the node mapped when the container started
    rig.start("3-1", rig.identity())
    assert rig.join() == sup.RESTART_EXIT
    assert rig.starts() == []
    assert len(messages(caplog, "cannot see")) == 1


def test_renumbered_while_running_stops_rtl_tcp_and_exits_75(rig):
    usb_device(rig.sysfs)
    rig.visible()
    rig.start("3-1", rig.identity())
    assert wait_for(lambda: rig.query() == "running\n")
    pid = rig.child_pid()
    renumber(rig.sysfs)
    assert rig.join() == sup.RESTART_EXIT
    assert gone(pid)


def test_unplugged_while_running_waits_and_resumes(rig, caplog):
    usb_device(rig.sysfs)
    identity = rig.identity()
    rig.visible()
    rig.start("3-1", identity)
    assert wait_for(lambda: rig.query() == "running\n")
    pid = rig.child_pid()
    remove_device(rig.sysfs)
    assert wait_for(lambda: rig.query() == "sensor_absent\n")
    assert wait_for(lambda: gone(pid))
    usb_device(rig.sysfs)  # back on the same node (e.g. after a restart)
    assert wait_for(lambda: len(rig.starts()) == 2)
    assert wait_for(lambda: rig.query() == "running\n")
    assert len(messages(caplog, "SDR sensor absent")) == 1
    assert rig.stop() == 0


def test_managed_no_device_burst_stops_and_rechecks(rig, caplog):
    usb_device(rig.sysfs)
    rig.visible()
    rig.mode("flood")
    rig.start("3-1", rig.identity())
    assert wait_for(lambda: messages(caplog, "USB no-device errors"))
    pid = rig.child_pid()
    assert wait_for(lambda: gone(pid))
    rig.mode("run")
    assert wait_for(lambda: len(rig.starts()) >= 2)
    assert wait_for(lambda: rig.query() == "running\n")
    assert rig.stop() == 0


@pytest.mark.parametrize(
    "usb_port, identity", [(None, "c" * 64), ("3-1", "not-hex"), ("bus 3", None)]
)
def test_invalid_selection_is_refused(rig, caplog, usb_port, identity):
    usb_device(rig.sysfs)
    rig.visible()
    rig.start(usb_port, identity)
    # Nothing took the receiver's place: not sensor_changed.
    assert wait_for(lambda: rig.query() == "capture_failed\n")
    time.sleep(0.2)
    assert rig.starts() == []
    assert len(messages(caplog, "selection is invalid")) == 1
    assert rig.stop() == 0


def test_port_without_identity_uses_whatever_is_there(rig):
    usb_device(rig.sysfs, serial="ANY-RECEIVER")
    rig.visible()
    rig.start("3-1", None)
    assert wait_for(lambda: rig.query() == "running\n")
    assert wait_for(lambda: rig.starts() == ["-d ANY-RECEIVER"])
    assert rig.stop() == 0


def test_rtl_tcp_on_another_receiver_is_stopped_as_sensor_changed(rig, caplog):
    usb_device(rig.sysfs)
    usb_device(rig.sysfs, "1-2", devnum=6, serial="OTHER-RECEIVER")
    rig.visible()
    # rtl_tcp ends up holding the other receiver's node (e.g. by a serial
    # suffix match after the selected one failed to open).
    rig.hold_node(rig.visible(devnum=6))
    rig.start("3-1", rig.identity())
    pid = rig.child_pid()
    assert wait_for(lambda: rig.query() == "sensor_changed\n")
    assert wait_for(lambda: gone(pid))
    assert sup.check(rig.state_file) == 1
    # Retried with the growing delay, logged once for the streak.
    assert wait_for(lambda: len(rig.starts()) >= 2)
    assert wait_for(lambda: rig.query() == "sensor_changed\n")
    assert len(messages(caplog, "opened a different SDR")) == 1
    assert rig.stop() == 0


def test_rtl_tcp_on_the_selected_receiver_keeps_running(rig, caplog):
    usb_device(rig.sysfs)
    usb_device(rig.sysfs, "1-2", devnum=6, serial="OTHER-RECEIVER")
    rig.visible(devnum=6)
    rig.hold_node(rig.visible())
    rig.start("3-1", rig.identity())
    rig.child_pid()
    assert wait_for(lambda: rig.query() == "running\n")
    time.sleep(0.4)  # several checks of the node rtl_tcp holds
    assert rig.query() == "running\n"
    assert len(rig.starts()) == 1
    assert not messages(caplog, "opened a different SDR")
    assert rig.stop() == 0


def test_node_the_container_may_not_open_waits_for_the_host_fix(rig, caplog):
    if os.geteuid() == 0:
        pytest.skip("root may open any node")
    usb_device(rig.sysfs)
    node = rig.dev / rig.visible().lstrip("/")
    # Measured after a re-plug: root:root 0664, so not writable for us.
    node.chmod(0o444)
    rig.start("3-1", rig.identity())
    assert wait_for(lambda: rig.query() == "sensor_unusable\n")
    time.sleep(0.4)  # several re-checks
    assert rig.starts() == []
    assert sup.check(rig.state_file) == 1
    hints = messages(caplog, "is not allowed to open it")
    assert len(hints) == 1
    assert (
        "sudo python3 scripts/scanner_setup.py prepare-rtl --usb=3-1"
        in hints[0].getMessage()
    )
    assert "QUICKSTART" in hints[0].getMessage()
    assert SERIAL not in caplog.text
    node.chmod(0o666)  # the operator ran prepare-rtl on the host
    assert wait_for(lambda: rig.query() == "running\n")
    assert wait_for(lambda: rig.starts() == [f"-d {SERIAL}"])
    assert len(messages(caplog, "can be opened now")) == 1
    assert rig.stop() == 0


# --- selector rules -----------------------------------------------------------


def selector(rig, *, serial=SERIAL, others=()):
    usb_device(rig.sysfs, serial=serial)
    for port, kwargs in others:
        usb_device(rig.sysfs, port, **kwargs)
    supervisor = rig.make("3-1", rig.identity())
    presence = sp.find_usb_sensor("3-1", rig.identity(), sysfs=rig.sysfs)
    return supervisor._selector(presence)


def test_selector_unique_serial(rig):
    other = ("1-1", {"busnum": 1, "devnum": 5, "serial": "SOMETHING-ELSE"})
    assert selector(rig, others=[other]) == SERIAL


def test_selector_single_receiver_without_usable_serial(rig):
    assert selector(rig, serial=None) == "0"


@pytest.mark.parametrize("serial", ["00000001", "0x1f", "12"])
def test_selector_never_passes_a_serial_librtlsdr_reads_as_an_index(rig, serial):
    assert selector(rig, serial=serial) == "0"
    other = ("2-1", {"busnum": 2, "devnum": 3, "serial": "X"})
    assert selector(rig, serial=serial, others=[other]) is None


def test_selector_refuses_identical_receivers(rig):
    twin = ("1-2", {"busnum": 1, "devnum": 6, "serial": SERIAL})
    assert selector(rig, others=[twin]) is None


@pytest.mark.parametrize(
    "other_serial",
    [SERIAL + "X", "X" + SERIAL, SERIAL[:-1], SERIAL[1:]],
    ids=["selected-is-prefix", "selected-is-suffix", "other-is-prefix", "suffix"],
)
def test_selector_refuses_serials_rtl_tcp_could_confuse(rig, other_serial):
    # rtl_tcp falls back to a prefix, then a suffix match: if the selected
    # receiver cannot be opened it would silently use this one.
    same_bus = ("1-2", {"busnum": 1, "devnum": 6, "serial": other_serial})
    assert selector(rig, others=[same_bus]) is None
    # On another bus (not mapped into the container) it cannot be opened.
    other_bus = ("2-2", {"busnum": 2, "devnum": 6, "serial": other_serial})
    remove_device(rig.sysfs, "1-2")
    assert selector(rig, others=[other_bus]) == SERIAL


@pytest.mark.parametrize("other_serial", ["", "SERIAL4", "OTHER"])
def test_selector_accepts_serials_that_do_not_overlap(rig, other_serial):
    same_bus = ("1-2", {"busnum": 1, "devnum": 6, "serial": other_serial})
    assert selector(rig, others=[same_bus]) == SERIAL


def test_selector_index_zero_needs_the_only_receiver_on_any_bus(rig):
    other = ("2-1", {"busnum": 2, "devnum": 3, "serial": None})
    assert selector(rig, serial="", others=[other]) is None
    # A non-RTL device (e.g. a Wi-Fi dongle) does not count.
    usb_device(rig.sysfs, "2-1", busnum=2, devnum=3, ids=("148f", "5370"))
    presence = sp.find_usb_sensor("3-1", rig.identity(), sysfs=rig.sysfs)
    assert rig.make("3-1", rig.identity())._selector(presence) == "0"


def test_identical_receivers_are_refused_once(rig, caplog):
    usb_device(rig.sysfs, serial=SERIAL)
    usb_device(rig.sysfs, "1-2", devnum=6, serial=SERIAL)
    rig.visible()
    rig.start("3-1", rig.identity())
    # The selected receiver is still there: capture_failed, not sensor_changed.
    assert wait_for(lambda: rig.query() == "capture_failed\n")
    time.sleep(0.3)
    assert rig.starts() == []
    assert len(messages(caplog, "cannot tell them apart")) == 1
    assert rig.stop() == 0


# --- output filter ------------------------------------------------------------


def test_output_filter_collapses_repeats_and_alternation(caplog):
    caplog.set_level(logging.INFO, logger="rtl_tcp_supervisor")
    clock = [0.0]
    out = sup._OutputFilter(clock=lambda: clock[0])
    out.new_process(frozenset())
    for _ in range(200):
        out.feed("rtlsdr_demod_read_reg failed with -4\n")
        out.feed("rtlsdr_demod_write_reg failed with -4\n")
        clock[0] += 0.5
    assert len(messages(caplog, "demod_read_reg")) == 1
    assert len(messages(caplog, "demod_write_reg")) == 1
    # A summary line now and then shows the flood goes on.
    summaries = messages(caplog, "repeated lines not shown")
    assert 1 <= len(summaries) <= 2
    out.flush()
    assert len(messages(caplog, "repeated lines not shown")) == len(summaries) + 1
    # A line seen long ago is shown again.
    clock[0] += 120
    out.feed("rtlsdr_demod_read_reg failed with -4")
    assert len(messages(caplog, "demod_read_reg")) == 2


def test_output_filter_detects_a_no_device_burst_only():
    clock = [0.0]
    out = sup._OutputFilter(clock=lambda: clock[0])
    out.new_process(frozenset())
    # Occasional -4 errors spread out are not device loss.
    for _ in range(10):
        assert not out.feed("rtlsdr_demod_read_reg failed with -4")
        clock[0] += 3.0
    burst = [out.feed("rtlsdr_demod_read_reg failed with -4") for _ in range(5)]
    assert burst == [False] * 4 + [True]
    out.new_process(frozenset())
    assert not out.feed("rtlsdr_demod_read_reg failed with -4")


def test_output_filter_redacts_serials(caplog):
    caplog.set_level(logging.INFO, logger="rtl_tcp_supervisor")
    out = sup._OutputFilter()
    out.new_process(frozenset({"ABCD1234"}))
    out.feed("  0:  Realtek, RTL2838UHIDIR, SN: 00000001")
    out.feed("Using device with serial ABCD1234")
    assert "00000001" not in caplog.text and "ABCD1234" not in caplog.text
    assert "SN: <hidden>" in caplog.text


# --- check and process --------------------------------------------------------


def test_check_needs_running(tmp_path):
    state = tmp_path / "state"
    assert sup.main(["--check"], state_file=state) == 1
    for value, code in [("running\n", 0), ("starting\n", 1), ("sensor_absent", 1)]:
        state.write_text(value)
        assert sup.main(["--check"], state_file=state) == code
    assert sup.main(["--bogus"]) == 2


def test_stale_running_state_file_is_rewritten_at_start(rig, monkeypatch):
    # /tmp survives a container restart; the old "running" must not count.
    rig.state_file.write_text("running\n")
    probing, release = threading.Event(), threading.Event()
    real_find = sp.find_usb_sensor

    def slow_find(*args, **kwargs):
        probing.set()
        release.wait(WAIT)
        return real_find(*args, **kwargs)

    monkeypatch.setattr(sup.sp, "find_usb_sensor", slow_find)
    rig.start("3-1", "d" * 64)
    assert probing.wait(WAIT)
    assert rig.state_file.read_text() == "starting\n"
    assert sup.check(rig.state_file) == 1
    release.set()
    assert rig.stop() == 0


def _spawn(rig, env_extra):
    paths = dict(
        sysfs=rig.sysfs,
        proc=rig.work / "proc",
        dev_root=rig.dev,
        state_file=rig.state_file,
    )
    options = dict(
        command=[sys.executable, str(rig.script), str(rig.work)],
        poll=0.05,
        **{key: str(value) for key, value in paths.items()},
    )
    code = (
        "import json, sys; from pathlib import Path; "
        "from sigrift.edge import rtl_tcp_supervisor as s; "
        "o = json.loads(sys.argv[1]); "
        f"o.update({{k: Path(o[k]) for k in {sorted(paths)!r}}}); "
        "sys.exit(s.main([], **o))"
    )
    env = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "MLRF_RTL_STATUS_PORT": "0",
        **env_extra,
    }
    for name in ("MLRF_SDR_USB", "MLRF_SDR_IDENTITY"):
        if name not in env_extra:
            env.pop(name, None)
    return subprocess.Popen(
        [sys.executable, "-c", code, json.dumps(options)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def test_stop_from_a_signal_handler_never_waits_for_a_lock(rig, monkeypatch):
    """A signal landing while the main thread holds a lock must not deadlock.

    Every lock the main thread takes raises SIGUSR1 while held; the handler
    is the one main() installs. A handler that takes such a lock again
    (threading.Event.set does) would wait forever: Docker then kills the
    supervisor and the exit code is 137, not 0.
    """
    real_lock = threading.Lock
    probe = SimpleNamespace(armed=False, in_handler=False, blocked=False)

    class SignalWhileHeld:
        def __init__(self):
            self._lock = real_lock()

        def acquire(self, blocking=True, timeout=-1):
            if probe.in_handler and blocking:
                # A handler waiting on a lock its own thread holds never gets
                # it; the limit only has to outlast another thread's brief
                # hold on a loaded runner.
                if not self._lock.acquire(timeout=30):
                    probe.blocked = True
                    raise RuntimeError("signal handler waited for a held lock")
                return True
            got = self._lock.acquire(blocking, timeout)
            if (
                got
                and probe.armed
                and not probe.in_handler
                and threading.current_thread() is threading.main_thread()
            ):
                signal.raise_signal(signal.SIGUSR1)  # runs the handler now
            return got

        def __enter__(self):
            return self.acquire()

        def __exit__(self, *_exc):
            self._lock.release()

        def release(self):
            self._lock.release()

        def locked(self):
            return self._lock.locked()

    monkeypatch.setattr(threading, "Lock", SignalWhileHeld)
    supervisor = rig.make("3-1", identity_of())  # absent: the polling loop

    def handler(*_):
        probe.in_handler = True
        try:
            supervisor.request_stop()
        finally:
            probe.in_handler = False

    previous = signal.signal(signal.SIGUSR1, handler)
    arm = threading.Timer(0.3, lambda: setattr(probe, "armed", True))
    try:
        arm.start()
        assert supervisor.run() == 0
    finally:
        arm.cancel()
        signal.signal(signal.SIGUSR1, previous)
    assert probe.armed and not probe.blocked


@pytest.mark.parametrize(
    "situation", ["running", "absent", "changed", "unusable", "stubborn"]
)
def test_sigterm_exits_zero_in_every_state(rig, situation):
    env = {}
    if situation in ("absent", "changed"):
        if situation == "changed":
            usb_device(rig.sysfs, serial="OTHER")
            rig.visible()
        env = {"MLRF_SDR_USB": "3-1", "MLRF_SDR_IDENTITY": "e" * 64}
    if situation == "unusable":
        if os.geteuid() == 0:
            pytest.skip("root may open any node")
        usb_device(rig.sysfs)
        (rig.dev / rig.visible().lstrip("/")).chmod(0o444)
        env = {"MLRF_SDR_USB": "3-1", "MLRF_SDR_IDENTITY": rig.identity()}
    if situation == "stubborn":
        rig.mode("ignore_term")  # rtl_tcp ignores SIGTERM: killed after a wait
    process = _spawn(rig, env)
    try:
        expected = {"running": "running", "stubborn": "running"}.get(
            situation, "sensor_" + situation
        )
        assert wait_for(
            lambda: rig.state_file.exists()
            and rig.state_file.read_text().strip() == expected
        )
        if situation in ("running", "stubborn"):
            pid = rig.child_pid()
        process.send_signal(signal.SIGTERM)
        output, _ = process.communicate(timeout=WAIT)
    finally:
        if process.poll() is None:
            process.kill()
    assert process.returncode == 0, output
    assert "Traceback" not in output
    if situation in ("running", "stubborn"):
        assert wait_for(lambda: gone(pid))
    assert rig.state_file.read_text().strip() == "stopped"
