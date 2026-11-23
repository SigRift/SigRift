"""Real command failures against an owned interface-state stand-in, never a radio."""

import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest


@pytest.fixture(scope="module")
def wifi():
    # Importing the standalone worker installs its logger; no host log writes.
    with patch("pathlib.Path.mkdir", side_effect=PermissionError):
        return importlib.import_module("sigrift.edge.wifi_scan")


@pytest.fixture
def interface(wifi, tmp_path, monkeypatch):
    # The interface exists in a fake sysfs; a missing one is a separate case.
    netdir = tmp_path / "sys/class/net"
    (netdir / "owned-fixture-radio").mkdir(parents=True)
    monkeypatch.setattr(wifi, "NET_SYSFS", netdir)
    state = tmp_path / "interface.json"
    state.write_text(json.dumps({"mode": "managed", "link": "up", "calls": []}))
    failure = tmp_path / "failure.json"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    program = (
        f"#!{sys.executable}\n"
        + r"""
import json, os, sys
from pathlib import Path
state_path=Path(os.environ['OWNED_INTERFACE_STATE'])
fault_path=Path(os.environ['OWNED_INTERFACE_FAULT'])
state=json.loads(state_path.read_text())
command=[Path(sys.argv[0]).name,*sys.argv[1:]]
assert command[3 if command[0]=='ip' else 2]=='owned-fixture-radio', command
state['calls'].append(command)
fault=json.loads(fault_path.read_text()) if fault_path.exists() else {}
matches=command==fault.get('command') or command in fault.get('also_fail', [])
if matches and not fault.get('after_mutation'):
    state_path.write_text(json.dumps(state)); sys.exit(23)
if command[0]=='ip': state['link']=command[-1]
else: state['mode']=command[-1]
state_path.write_text(json.dumps(state))
if matches:
    fault_path.unlink() # An interrupted/failed command may already have changed state.
    sys.exit(23)
"""
    )
    for command in ("ip", "iw"):
        target = bindir / command
        target.write_text(program)
        target.chmod(0o700)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("OWNED_INTERFACE_STATE", str(state))
    monkeypatch.setenv("OWNED_INTERFACE_FAULT", str(failure))

    def fail(command, *, after_mutation=False, also_fail=()):
        failure.write_text(
            json.dumps(
                {
                    "command": command,
                    "after_mutation": after_mutation,
                    "also_fail": also_fail,
                }
            )
        )

    def clear():
        failure.unlink(missing_ok=True)

    def read():
        return json.loads(state.read_text())

    return fail, clear, read


DOWN = ["ip", "link", "set", "owned-fixture-radio", "down"]
UP = ["ip", "link", "set", "owned-fixture-radio", "up"]
MONITOR = ["iw", "dev", "owned-fixture-radio", "set", "type", "monitor"]
MANAGED = ["iw", "dev", "owned-fixture-radio", "set", "type", "managed"]


@pytest.mark.parametrize("failed_command", [DOWN, MONITOR, UP])
def test_failed_monitor_entry_restores_mutated_interface(
    wifi, interface, failed_command
):
    fail, _, read = interface
    fail(failed_command, after_mutation=True)
    with pytest.raises(subprocess.CalledProcessError) as caught:
        with wifi.MonitorMode("owned-fixture-radio"):
            pytest.fail("Failed setup must not enter the capture body")
    assert caught.value.cmd == failed_command
    assert read()["mode"] == "managed"
    assert read()["link"] == "up"


@pytest.mark.parametrize("failed_command", [DOWN, MANAGED, UP])
def test_failed_restore_is_visible_and_retry_can_finish(
    wifi, interface, failed_command
):
    fail, clear, read = interface
    monitor = wifi.MonitorMode("owned-fixture-radio")
    monitor.enable()
    assert (read()["mode"], read()["link"]) == ("monitor", "up")
    fail(failed_command)
    with pytest.raises(subprocess.CalledProcessError) as caught:
        monitor.disable()
    assert caught.value.cmd == failed_command
    # Later independent recovery steps must still run after an earlier failure.
    assert read()["calls"][-1] == UP
    clear()
    monitor.disable()
    assert (read()["mode"], read()["link"]) == ("managed", "up")
    before = read()
    monitor.disable()
    assert read() == before


def test_unused_monitor_cleanup_does_not_touch_interface(wifi, interface):
    _, _, read = interface
    monitor = wifi.MonitorMode("owned-fixture-radio")
    before = read()
    monitor.disable()
    assert read() == before


def test_capture_body_exception_still_restores_interface(wifi, interface):
    _, _, read = interface
    with pytest.raises(ValueError, match="synthetic capture failure"):
        with wifi.MonitorMode("owned-fixture-radio"):
            assert read()["mode"] == "monitor"
            raise ValueError("synthetic capture failure")
    assert (read()["mode"], read()["link"]) == ("managed", "up")


def test_startup_and_restore_failures_preserve_both_errors_and_retry(wifi, interface):
    fail, clear, read = interface
    monitor = wifi.MonitorMode("owned-fixture-radio")
    fail(MONITOR, also_fail=[MANAGED])
    with pytest.raises(subprocess.CalledProcessError) as caught:
        monitor.enable()
    assert caught.value.cmd == MONITOR
    assert isinstance(caught.value.__cause__, subprocess.CalledProcessError)
    assert caught.value.__cause__.cmd == MANAGED
    assert read()["link"] == "up"
    clear()
    monitor.disable()
    assert (read()["mode"], read()["link"]) == ("managed", "up")


def test_body_and_restore_failures_preserve_both_errors_and_retry(wifi, interface):
    fail, clear, read = interface
    monitor = wifi.MonitorMode("owned-fixture-radio")
    with pytest.raises(ValueError, match="synthetic body failure") as caught:
        with monitor:
            fail(MANAGED)
            raise ValueError("synthetic body failure")
    assert isinstance(caught.value.__cause__, subprocess.CalledProcessError)
    assert caught.value.__cause__.cmd == MANAGED
    assert read()["link"] == "up"
    clear()
    monitor.disable()
    assert (read()["mode"], read()["link"]) == ("managed", "up")


def test_missing_mode_command_still_restores_link_and_can_retry(
    wifi, interface, monkeypatch
):
    _, _, read = interface
    bindir = Path(os.environ["PATH"].split(os.pathsep)[0])
    monkeypatch.setenv("PATH", str(bindir))
    (bindir / "iw").rename(bindir / "iw-disabled")
    monitor = wifi.MonitorMode("owned-fixture-radio")
    with pytest.raises(FileNotFoundError) as caught:
        monitor.enable()
    assert isinstance(caught.value.__cause__, FileNotFoundError)
    assert read()["link"] == "up"
    (bindir / "iw-disabled").rename(bindir / "iw")
    monitor.disable()
    assert (read()["mode"], read()["link"]) == ("managed", "up")


def unplug(wifi):
    (wifi.NET_SYSFS / "owned-fixture-radio").rmdir()


@pytest.mark.parametrize("failed_command", [DOWN, MANAGED, UP])
def test_restore_of_unplugged_interface_has_nothing_to_restore(
    wifi, interface, failed_command, caplog
):
    fail, _, read = interface
    monitor = wifi.MonitorMode("owned-fixture-radio")
    monitor.enable()
    unplug(wifi)
    fail(failed_command)
    monitor.disable()  # Gone: nothing to restore, so no error.
    assert not monitor.pending
    assert "Failed to restore" not in caplog.text
    before = read()
    monitor.disable()
    assert read() == before


def test_failed_entry_on_unplugged_interface_keeps_only_the_startup_error(
    wifi, interface
):
    fail, _, _ = interface
    unplug(wifi)
    fail(MONITOR, also_fail=[MANAGED])
    monitor = wifi.MonitorMode("owned-fixture-radio")
    with pytest.raises(subprocess.CalledProcessError) as caught:
        monitor.enable()
    assert caught.value.cmd == MONITOR
    assert caught.value.__cause__ is None
    assert not monitor.pending
