"""Tests for the BLE scan fall-through logic in ``sigrift.lib.bt_scanner``.

Guards the 2026-06-10 staging regression where ``bluetoothctl`` failed
silently inside the container (host D-Bus policy), Method 1 returned an
empty list unconditionally, and the ``hcitool lescan`` fallback was
unreachable dead code — every scan reported 0 BLE devices.
"""

from __future__ import annotations

import logging
import signal
import subprocess
from unittest import mock

import pytest

from sigrift.lib.bt_scanner import BtScanner


@pytest.fixture()
def scanner() -> BtScanner:
    return BtScanner(
        server_url="https://127.0.0.1:8444",
        api_key="k",
        node_id="test-node",
        adapter="hci0",
    )


def _completed(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=0, stdout=stdout, stderr=stderr)


def _fake_lescan_proc(stdout_text: str) -> mock.Mock:
    proc = mock.Mock()
    proc.stdout.read.return_value = stdout_text.encode("utf-8")
    proc.stderr.read.return_value = b""
    proc.wait.return_value = 0
    return proc


class TestBleFallThrough:
    def test_empty_bluetoothctl_falls_through_to_lescan(self, scanner: BtScanner):
        """Method 1 yielding zero devices must still try hcitool lescan."""
        lescan_out = "AA:BB:CC:DD:EE:01 (unknown)\nAA:BB:CC:DD:EE:02 SomeBeacon\n"
        with (
            mock.patch.object(subprocess, "run", return_value=_completed()),
            mock.patch.object(
                subprocess, "Popen", return_value=_fake_lescan_proc(lescan_out)
            ) as popen,
            mock.patch("time.sleep"),
        ):
            devices = scanner._scan_ble()

        assert popen.called, "lescan fallback must run when bluetoothctl finds nothing"
        addrs = {d["device_addr"] for d in devices}
        assert addrs == {"AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"}
        assert all(d["device_type"] == "ble" for d in devices)

    def test_bluetoothctl_devices_skip_lescan(self, scanner: BtScanner):
        """When Method 1 finds devices the fallback is not invoked."""
        btctl_out = "Device AA:BB:CC:DD:EE:03 Govee_H6076\n"
        with (
            mock.patch.object(subprocess, "run", return_value=_completed(stdout=btctl_out)),
            mock.patch.object(subprocess, "Popen") as popen,
            mock.patch.object(scanner, "_get_rssi", return_value=-60.0),
        ):
            devices = scanner._scan_ble()

        assert not popen.called
        assert [d["device_addr"] for d in devices] == ["AA:BB:CC:DD:EE:03"]

    def test_bluetoothctl_exception_falls_through(self, scanner: BtScanner):
        """A bluetoothctl failure (missing binary, D-Bus error) reaches lescan."""
        with (
            mock.patch.object(subprocess, "run", side_effect=FileNotFoundError("bluetoothctl")),
            mock.patch.object(
                subprocess, "Popen", return_value=_fake_lescan_proc("AA:BB:CC:DD:EE:04 X\n")
            ) as popen,
            mock.patch("time.sleep"),
        ):
            devices = scanner._scan_ble()

        assert popen.called
        assert [d["device_addr"] for d in devices] == ["AA:BB:CC:DD:EE:04"]

    def test_lescan_uses_stdbuf_when_available(self, scanner: BtScanner):
        """hcitool block-buffers stdout to a pipe; stdbuf -oL must wrap it."""
        with (
            mock.patch.object(subprocess, "run", return_value=_completed()),
            mock.patch.object(
                subprocess, "Popen", return_value=_fake_lescan_proc("")
            ) as popen,
            mock.patch("sigrift.lib.bt_scanner.shutil.which", return_value="/usr/bin/stdbuf"),
            mock.patch("time.sleep"),
        ):
            scanner._scan_ble()

        cmd = popen.call_args[0][0]
        assert cmd[:2] == ["stdbuf", "-oL"]
        assert "lescan" in cmd

    def test_lescan_stopped_with_sigint(self, scanner: BtScanner):
        """lescan must be stopped with SIGINT, not SIGTERM.

        hcitool only installs a SIGINT handler; on SIGINT it stops the
        scan and exits normally, flushing its stdio buffer. SIGTERM
        default-kills it and discards buffered results. stdbuf cannot
        compensate in the container: the image setcaps hcitool, and
        secure-execution mode drops stdbuf's LD_PRELOAD.
        """
        proc = _fake_lescan_proc("AA:BB:CC:DD:EE:05 X\n")
        with (
            mock.patch.object(subprocess, "run", return_value=_completed()),
            mock.patch.object(subprocess, "Popen", return_value=proc),
            mock.patch("time.sleep"),
        ):
            devices = scanner._scan_ble()

        proc.send_signal.assert_called_once_with(signal.SIGINT)
        assert not proc.terminate.called
        assert [d["device_addr"] for d in devices] == ["AA:BB:CC:DD:EE:05"]

    def test_lescan_escalates_to_terminate_on_hung_sigint(self, scanner: BtScanner):
        """If the process ignores SIGINT, fall back to terminate()."""
        proc = _fake_lescan_proc("")
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="hcitool", timeout=3), 0]
        with (
            mock.patch.object(subprocess, "run", return_value=_completed()),
            mock.patch.object(subprocess, "Popen", return_value=proc),
            mock.patch("time.sleep"),
        ):
            scanner._scan_ble()

        proc.send_signal.assert_called_once_with(signal.SIGINT)
        proc.terminate.assert_called_once()

    def test_lescan_runs_bare_without_stdbuf(self, scanner: BtScanner):
        with (
            mock.patch.object(subprocess, "run", return_value=_completed()),
            mock.patch.object(
                subprocess, "Popen", return_value=_fake_lescan_proc("")
            ) as popen,
            mock.patch("sigrift.lib.bt_scanner.shutil.which", return_value=None),
            mock.patch("time.sleep"),
        ):
            scanner._scan_ble()

        cmd = popen.call_args[0][0]
        assert cmd[0] == "hcitool"


class TestBleFailureLogging:
    def test_persistent_failure_warns_once(self, scanner: BtScanner, caplog):
        """The same failure cause logs WARNING once, then DEBUG."""
        with caplog.at_level(logging.DEBUG, logger="sigrift.lib.bt_scanner"):
            scanner._note_ble_method_failure("hcitool lescan", "Operation not permitted")
            scanner._note_ble_method_failure("hcitool lescan", "Operation not permitted")

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(warnings) == 1
        assert len(debugs) == 1

    def test_new_cause_warns_again(self, scanner: BtScanner, caplog):
        with caplog.at_level(logging.WARNING, logger="sigrift.lib.bt_scanner"):
            scanner._note_ble_method_failure("bluetoothctl", "dbus error")
            scanner._note_ble_method_failure("hcitool lescan", "EPERM")

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2

    def test_alternating_method_failures_do_not_flood(self, scanner: BtScanner, caplog):
        """Both methods failing every cycle — the steady state on a
        misconfigured host — must warn once per method, not every scan."""
        with caplog.at_level(logging.DEBUG, logger="sigrift.lib.bt_scanner"):
            for _ in range(3):
                scanner._note_ble_method_failure("bluetoothctl", "dbus error")
                scanner._note_ble_method_failure("hcitool lescan", "EPERM")

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(warnings) == 2
        assert len(debugs) == 4
