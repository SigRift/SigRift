"""Discovery and receiver release refuse what they cannot verify.

Real sysfs-like trees under tmp_path; ip/iw/nmcli/docker answers and
character-device metadata are explicit fixtures. Nothing here opens a real
device, changes a driver or needs root.
"""

from __future__ import annotations

import grp
import os
from pathlib import Path
import signal
import stat
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import test_host_prepare as prepared
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
host = prepared.host
BLUETOOTH = "Bluetooth is not enabled automatically; its readiness probe is not yet implemented."


def local_os(monkeypatch):
    """A copy of os for the module under test, so patches stay local to it."""
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )


# ── Command boundary ─────────────────────────────────────────────────


def test_failing_probe_names_the_tool_but_not_its_output():
    script = "import sys; print('probe-output-token'); sys.exit(3)"
    with pytest.raises(setup.SetupError) as raised:
        setup.run([sys.executable, "-c", script], timeout=120)
    assert str(raised.value) == (
        f"{sys.executable} probe failed; check that tool and retry."
    )
    assert "probe-output-token" not in str(raised.value)


def test_refused_group_kill_is_retried_and_the_probe_is_still_reaped(monkeypatch):
    local_os(monkeypatch)
    outcomes = [PermissionError("not permitted"), ProcessLookupError()]
    kills = []

    def killpg(pid, signum):
        kills.append((pid, signum))
        raise outcomes.pop(0)

    monkeypatch.setattr(setup.os, "killpg", killpg)
    assert setup.run([sys.executable, "-c", "print('ready')"], timeout=120) == "ready\n"
    assert len(kills) == 2 and kills[0] == kills[1]
    assert kills[0][1] == signal.SIGKILL
    assert outcomes == []


def test_invalid_json_from_a_probe_stops_discovery(monkeypatch):
    monkeypatch.setattr(setup, "run", lambda args: "<html>proxy error</html>")
    with pytest.raises(
        setup.SetupError, match="^ip returned invalid JSON; discovery is incomplete.$"
    ):
        setup.json_command(["ip", "-j", "address", "show"])


def test_non_linux_host_never_asks_docker(monkeypatch, clean):
    monkeypatch.setattr(setup.platform, "system", lambda: "Darwin")
    probe = Mock()
    monkeypatch.setattr(setup, "json_command", probe)
    with pytest.raises(setup.SetupError, match="require native Linux Docker"):
        setup.native_docker()
    probe.assert_not_called()


# ── Receiver discovery ───────────────────────────────────────────────


def test_unreadable_usb_metadata_stops_receiver_discovery(tmp_path):
    entry, _ = planner.usb_tree(tmp_path)
    (entry / "idProduct").unlink()
    (entry / "idProduct").mkdir()
    with pytest.raises(setup.SetupError, match="Hardware metadata is unreadable"):
        setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")


def test_other_usb_devices_are_not_reported(tmp_path):
    planner.usb_tree(tmp_path)
    keyboard = tmp_path / "sys/bus/usb/devices/1-3"
    keyboard.mkdir()
    (keyboard / "idVendor").write_text("046d\n")
    (keyboard / "idProduct").write_text("c52b\n")
    assert [
        item["usb"] for item in setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")
    ] == ["1-2"]


@pytest.mark.parametrize(
    "busnum,devnum", [("0", "4"), ("1", "1000"), ("1", "-4"), ("../1", "4")]
)
def test_out_of_range_bus_metadata_refuses_receiver_selection(tmp_path, busnum, devnum):
    entry, _ = planner.usb_tree(tmp_path)
    (entry / "busnum").write_text(busnum)
    (entry / "devnum").write_text(devnum)
    with pytest.raises(setup.SetupError, match="Invalid USB bus/device metadata"):
        setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")


@pytest.mark.parametrize("rdev,kernel", [((189, 7), "189:3"), ((1, 3), "1:3")])
def test_node_that_is_not_the_kernel_usb_device_is_not_ready(
    tmp_path, monkeypatch, rdev, kernel
):
    entry, node = planner.usb_tree(tmp_path)
    (entry / "dev").write_text(kernel)
    local_os(monkeypatch)
    monkeypatch.setattr(setup.os, "major", lambda _: rdev[0])
    monkeypatch.setattr(setup.os, "minor", lambda _: rdev[1])
    device = SimpleNamespace(
        st_mode=stat.S_IFCHR | 0o660, st_uid=0, st_gid=876, st_rdev=4242
    )
    real = Path.lstat
    monkeypatch.setattr(
        Path, "lstat", lambda path: device if path == node else real(path)
    )
    (receiver,) = setup.rtl_devices(tmp_path / "sys", tmp_path / "dev")
    assert receiver["reasons"] == [
        "USB device node does not match the kernel device identity"
    ]
    assert node.read_bytes().startswith(b"regular file")


def test_node_unplugged_during_the_group_check_grants_nothing(tmp_path, monkeypatch):
    bus = tmp_path / "dev/bus/usb/001"
    bus.mkdir(parents=True)
    device, regular, gone = bus / "004", bus / "005", bus / "006"
    for path in (device, regular, gone):
        path.write_bytes(b"")
    real = Path.lstat

    def lstat(path):
        if path == gone:
            raise FileNotFoundError(path)
        return real(path)

    monkeypatch.setattr(Path, "lstat", lstat)
    assert setup.shared_group(device, SimpleNamespace(st_gid=46)) is False


# ── Receiver release (prepare-rtl) ───────────────────────────────────


@pytest.mark.parametrize("usb", ["1-2;reboot", "../1-2", "1-2 ", "", None])
def test_release_refuses_a_name_that_is_not_a_usb_port(tmp_path, monkeypatch, usb):
    _, unbind, changes = planner.preparation_fixture(tmp_path, monkeypatch)
    with pytest.raises(setup.SetupError, match="Select one discovered USB topology"):
        setup.release_rtl(usb, sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []


def test_release_without_the_plugdev_group_changes_nothing(tmp_path, monkeypatch):
    node, unbind, changes = planner.preparation_fixture(tmp_path, monkeypatch)
    before = stat.S_IMODE(node.stat().st_mode)

    def missing(name):
        raise KeyError(name)

    monkeypatch.setattr(grp, "getgrnam", missing)
    with pytest.raises(setup.SetupError, match="plugdev group is missing"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []
    assert stat.S_IMODE(node.stat().st_mode) == before


def test_release_of_a_receiver_that_is_gone_changes_nothing(tmp_path, monkeypatch):
    _, unbind, changes = planner.preparation_fixture(tmp_path, monkeypatch)
    with pytest.raises(setup.SetupError, match="no longer present"):
        setup.release_rtl("1-3", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert unbind.read_text() == "" and changes == []


def test_unexpected_interface_name_on_the_driver_is_refused(tmp_path, monkeypatch):
    _, unbind, changes = planner.preparation_fixture(tmp_path, monkeypatch)
    odd = tmp_path / "sys/bus/usb/devices/1-2:x"
    odd.mkdir()
    (odd / "driver").symlink_to(tmp_path / "sys/bus/usb/drivers/dvb_usb_rtl28xxu")
    with pytest.raises(setup.SetupError, match="Unexpected USB interface identity"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    # Not even the valid interface listed before it was unbound.
    assert unbind.read_text() == "" and changes == []


def test_receiver_swapped_after_the_node_was_opened_is_not_changed(
    tmp_path, monkeypatch
):
    node, unbind, changes = planner.preparation_fixture(tmp_path, monkeypatch)
    before = stat.S_IMODE(node.stat().st_mode)
    real = setup.rtl_devices
    seen = []

    def rediscover(sysfs, dev):
        found = real(sysfs, dev)
        seen.append(found)
        if len(seen) == 2:
            found[0]["identity"] = "f" * 64  # another receiver, same port
        return found

    monkeypatch.setattr(setup, "rtl_devices", rediscover)
    with pytest.raises(setup.SetupError, match="USB identity changed"):
        setup.prepare_rtl("1-2", sysfs=tmp_path / "sys", dev=tmp_path / "dev")
    assert len(seen) == 2
    assert unbind.read_text() == "" and changes == []
    assert stat.S_IMODE(node.stat().st_mode) == before


# ── Wi-Fi discovery ──────────────────────────────────────────────────


@pytest.mark.parametrize(
    "routes,message",
    [
        ([["eth0"]], "Cannot verify routes"),
        ([{"dst": "default", "nexthops": [{"dev": 7}]}], "Cannot verify multipath"),
        ([{"dst": "default", "nexthops": ["wlan0"]}], "Cannot verify multipath"),
    ],
)
def test_malformed_routes_block_wifi_selection(routes, message):
    with pytest.raises(setup.SetupError, match=message):
        setup.route_devices(routes)


def test_radio_swapped_while_its_identity_was_read_is_not_identified(host, monkeypatch):
    topology, address = setup.wifi_hardware(host.sysfs, "wlan1", "phy1")
    assert address == "02:11:22:33:44:01" and topology
    answers = iter(["02:11:22:33:44:01\n", "02:11:22:33:44:99\n"])
    monkeypatch.setattr(Path, "read_text", lambda self, *a, **k: next(answers))
    with pytest.raises(setup.SetupError, match="hardware identity is unavailable"):
        setup.wifi_hardware(host.sysfs, "wlan1", "phy1")


def network(monkeypatch, sysfs, answers):
    """planner.wifi_commands with some answers replaced; returns the calls."""
    planner.wifi_commands(monkeypatch, sysfs=sysfs, routed="eth0", ssh="eth0")
    boundary = setup.run
    calls = []

    def command(args):
        calls.append(args)
        key = " ".join(args)
        return answers[key] if key in answers else boundary(args)

    monkeypatch.setattr(setup, "run", command)
    return calls


@pytest.mark.parametrize("addresses", ["{}", '[{"ifname": "wlan0"}]', '["wlan0"]'])
def test_unverifiable_interface_addresses_block_wifi_selection(
    tmp_path, monkeypatch, clean, addresses
):
    network(monkeypatch, tmp_path, {"ip -j address show": addresses})
    with pytest.raises(setup.SetupError, match="Cannot verify interface addresses"):
        setup.wifi_devices(tmp_path)


@pytest.mark.parametrize("client", ["192.0.2.5 22", "not-an-address", ""])
def test_unusable_ssh_client_option_blocks_wifi_selection(
    tmp_path, monkeypatch, clean, client
):
    network(monkeypatch, tmp_path, {})
    with pytest.raises(setup.SetupError, match="Cannot identify the SSH client route"):
        setup.wifi_devices(tmp_path, extra_ssh_clients=(client,))


def test_same_ssh_client_from_both_sources_is_checked_once(
    tmp_path, monkeypatch, clean
):
    calls = network(monkeypatch, tmp_path, {})
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.5 50123 192.0.2.6 22")
    setup.wifi_devices(tmp_path, extra_ssh_clients=("192.0.2.5",))
    assert calls.count(["ip", "-j", "route", "get", "192.0.2.5"]) == 1


def test_ssh_client_without_a_route_back_blocks_wifi_selection(
    tmp_path, monkeypatch, clean
):
    network(monkeypatch, tmp_path, {"ip -j route get 192.0.2.5": "[]"})
    with pytest.raises(
        setup.SetupError, match="Cannot identify the SSH client interface"
    ):
        setup.wifi_devices(tmp_path, extra_ssh_clients=("192.0.2.5",))


def test_other_iw_details_and_clear_rfkill_flags_leave_radios_ready(
    tmp_path, monkeypatch, clean
):
    iw = (
        "phy#0\n\tInterface wlan0\n\t\tifindex 3\n\t\twdev 0x1\n"
        "\t\taddr 02:11:22:33:44:00\n\t\ttype managed\n\t\ttxpower 20.00 dBm\n"
        "phy#1\n\tInterface wlan1\n\t\tifindex 4\n\t\ttype monitor\n"
    )
    network(monkeypatch, tmp_path, {"iw dev": iw})
    flags = tmp_path / "class/ieee80211/phy1/rfkill3"
    flags.mkdir(parents=True)
    (flags / "hard").write_text("0\n")
    (flags / "soft").write_text("0\n")
    (flags / "state").write_text("1\n")  # not a blocking flag
    result = setup.wifi_devices(tmp_path)
    assert [(item["interface"], item["reasons"]) for item in result] == [
        ("wlan0", []),
        ("wlan1", []),
    ]


# ── Discovery as a whole ─────────────────────────────────────────────


def test_without_native_docker_discovery_finds_nothing_and_says_why(monkeypatch, clean):
    reason = "Docker is not a verified native, rootful daemon on this host; hardware setup is unavailable."

    def refuse():
        raise setup.SetupError(reason)

    probe = Mock()
    monkeypatch.setattr(setup, "native_docker", refuse)
    monkeypatch.setattr(setup, "rtl_devices", probe)
    monkeypatch.setattr(setup, "wifi_devices", probe)
    assert setup.discover() == {
        "sdr": [],
        "wifi": [],
        "reasons": [BLUETOOTH, reason],
    }
    probe.assert_not_called()


@pytest.mark.parametrize(
    "clients,options",
    [((), {}), (("192.0.2.5",), {"extra_ssh_clients": ("192.0.2.5",)})],
)
def test_one_failing_probe_does_not_hide_the_other(
    monkeypatch, clean, clients, options
):
    monkeypatch.setattr(setup, "native_docker", lambda: None)

    def unreadable_usb():
        raise setup.SetupError(
            "Hardware metadata is unreadable; discovery is incomplete."
        )

    seen = []

    def wifi(**received):
        seen.append(received)
        return [
            {"interface": "wlan1", "phy": "phy1", "identity": "b" * 64, "reasons": []}
        ]

    nmcli = []

    def no_network_manager(args, **kwargs):
        nmcli.append(args)
        raise setup.SetupError("nmcli is unavailable")

    monkeypatch.setattr(setup, "rtl_devices", unreadable_usb)
    monkeypatch.setattr(setup, "wifi_devices", wifi)
    monkeypatch.setattr(setup, "run", no_network_manager)
    found = setup.discover(extra_ssh_clients=clients)
    assert found == {
        "sdr": [],
        "wifi": [
            {"interface": "wlan1", "phy": "phy1", "identity": "b" * 64, "reasons": []}
        ],
        "reasons": [
            BLUETOOTH,
            "sdr: Hardware metadata is unreadable; discovery is incomplete.",
        ],
    }
    assert seen == [options]
    assert nmcli == [["nmcli", "-t", "-f", "RUNNING", "general"]]
