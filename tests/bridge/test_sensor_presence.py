"""Sensor presence by stable identity, against fake sysfs trees.

Identities are also computed by scripts/scanner_setup.py from the same tree,
so setup and the running scanner cannot drift apart.
"""

from __future__ import annotations

import importlib.util
import logging
import threading
from pathlib import Path

import pytest

from sigrift.edge import sensor_presence as sp

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "scanner_setup_presence", ROOT / "scripts/scanner_setup.py"
)
setup = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(setup)

SERIAL = "00000001"


def usb_device(sysfs, port="3-1", *, busnum=1, devnum=4, serial=SERIAL):
    """A USB device directory like /sys/bus/usb/devices/<port>."""
    entry = sysfs / "bus/usb/devices" / port
    entry.mkdir(parents=True, exist_ok=True)
    (entry / "idVendor").write_text("0bda\n")
    (entry / "idProduct").write_text("2838\n")
    (entry / "busnum").write_text(f"{busnum}\n")
    (entry / "devnum").write_text(f"{devnum}\n")
    if serial is not None:
        (entry / "serial").write_text(serial + "\n")
    return entry


def setup_usb_identity(sysfs, port):
    (item,) = [i for i in setup.rtl_devices(sysfs, sysfs / "dev") if i["usb"] == port]
    return item["identity"]


def unreadable(path):
    """A path that exists but raises OSError on read (a directory)."""
    path.unlink()
    path.mkdir()


# --- USB --------------------------------------------------------------------


def test_usb_identity_matches_scanner_setup(tmp_path):
    entry = usb_device(tmp_path)
    assert sp.usb_identity(entry) == setup_usb_identity(tmp_path, "3-1")
    (entry / "serial").unlink()
    assert sp.usb_identity(entry) == setup_usb_identity(tmp_path, "3-1")


def test_usb_present_reports_current_node(tmp_path):
    entry = usb_device(tmp_path, busnum=1, devnum=4)
    root = tmp_path / "bus/usb/devices"
    presence = sp.find_usb_sensor("3-1", sp.usb_identity(entry), sysfs=root)
    assert presence.state == "present"
    assert presence.detail == {
        "busnum": 1,
        "devnum": 4,
        "node": "/dev/bus/usb/001/004",
        "serial": SERIAL,
    }
    assert SERIAL not in repr(presence)


def test_usb_renumbered_device_is_still_present(tmp_path):
    entry = usb_device(tmp_path, busnum=1, devnum=4)
    identity = sp.usb_identity(entry)
    usb_device(tmp_path, busnum=2, devnum=17)
    presence = sp.find_usb_sensor("3-1", identity, sysfs=tmp_path / "bus/usb/devices")
    assert presence.state == "present"
    assert presence.detail["node"] == "/dev/bus/usb/002/017"
    assert (presence.detail["busnum"], presence.detail["devnum"]) == (2, 17)


def test_usb_swapped_device_is_changed(tmp_path):
    identity = sp.usb_identity(usb_device(tmp_path))
    usb_device(tmp_path, serial="00000002")
    root = tmp_path / "bus/usb/devices"
    swapped = sp.find_usb_sensor("3-1", identity, sysfs=root)
    assert swapped.state == "changed"
    assert swapped.detail == {}
    # Legacy installs without an identity use whatever is present.
    assert sp.find_usb_sensor("3-1", sysfs=root).state == "present"


@pytest.mark.parametrize("port", ["3-2", "../3-1", "", None])
def test_usb_absent_or_invalid_port(tmp_path, port):
    usb_device(tmp_path)
    root = tmp_path / "bus/usb/devices"
    assert sp.find_usb_sensor(port, sysfs=root).state == "absent"


def test_usb_absent_when_sysfs_root_missing(tmp_path):
    assert sp.find_usb_sensor("3-1", sysfs=tmp_path / "missing").state == "absent"


@pytest.mark.parametrize("name", ["busnum", "devnum", "idProduct", "serial"])
def test_usb_unreadable_file_is_absent(tmp_path, name):
    entry = usb_device(tmp_path)
    unreadable(entry / name)
    root = tmp_path / "bus/usb/devices"
    assert sp.find_usb_sensor("3-1", sysfs=root).state == "absent"


@pytest.mark.parametrize("devnum", ["0", "1000", "x", ""])
def test_usb_invalid_numbers_are_absent(tmp_path, devnum):
    entry = usb_device(tmp_path)
    (entry / "devnum").write_text(devnum)
    root = tmp_path / "bus/usb/devices"
    assert sp.find_usb_sensor("3-1", sysfs=root).state == "absent"


# --- Wi-Fi --------------------------------------------------------------------


def wifi_radio(
    sysfs, *, phy="phy1", interface="wlan1", port="3-1", ifindex=7, monitor=True
):
    """Real sysfs shape: class links resolve under /sys/devices."""
    device = sysfs / "devices/platform/usb3" / port / f"{port}:1.0"
    device.mkdir(parents=True, exist_ok=True)
    wiphy = device / "ieee80211" / phy
    wiphy.mkdir(parents=True)
    (wiphy / "macaddress").write_text("02:11:22:33:44:55\n")
    (wiphy / "device").symlink_to(device, target_is_directory=True)
    classes = sysfs / "class/ieee80211"
    classes.mkdir(parents=True, exist_ok=True)
    (classes / phy).symlink_to(wiphy, target_is_directory=True)
    net = device / "net" / interface
    net.mkdir(parents=True)
    (net / "phy80211").symlink_to(wiphy, target_is_directory=True)
    (net / "ifindex").write_text(f"{ifindex}\n")
    (net / "type").write_text("803\n" if monitor else "1\n")
    (net / "address").write_text("02:99:99:99:99:99\n")
    netclass = sysfs / "class/net"
    netclass.mkdir(parents=True, exist_ok=True)
    (netclass / interface).symlink_to(net, target_is_directory=True)
    return wiphy


def unplug_wifi(sysfs, *, phy="phy1", interface="wlan1"):
    (sysfs / "class/net" / interface).unlink()
    (sysfs / "class/ieee80211" / phy).unlink()
    for path in sorted((sysfs / "devices").rglob("*"), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            path.rmdir()


def test_wifi_identity_matches_scanner_setup(tmp_path):
    wifi_radio(tmp_path)
    net = tmp_path / "class/net"
    expected = setup.wifi_identity(tmp_path, "wlan1", "phy1")
    assert sp.wifi_identity("wlan1", sysfs=net) == expected
    presence = sp.find_wifi_sensor("wlan1", expected, sysfs=net)
    assert presence == sp.Presence("present", {"ifindex": 7, "monitor": True})


def test_wifi_renumbered_phy_and_ifindex_is_still_present(tmp_path):
    wifi_radio(tmp_path, phy="phy1", ifindex=7)
    net = tmp_path / "class/net"
    identity = sp.wifi_identity("wlan1", sysfs=net)
    unplug_wifi(tmp_path, phy="phy1")
    assert sp.find_wifi_sensor("wlan1", identity, sysfs=net).state == "absent"
    wifi_radio(tmp_path, phy="phy4", ifindex=12, monitor=False)
    assert setup.wifi_identity(tmp_path, "wlan1", "phy4") == identity
    presence = sp.find_wifi_sensor("wlan1", identity, sysfs=net)
    assert presence == sp.Presence("present", {"ifindex": 12, "monitor": False})


def test_wifi_other_radio_or_port_is_changed(tmp_path):
    wifi_radio(tmp_path)
    net = tmp_path / "class/net"
    identity = sp.wifi_identity("wlan1", sysfs=net)
    unplug_wifi(tmp_path)
    # Same adapter in another USB port is a different selection, as in setup.
    wifi_radio(tmp_path, port="3-2")
    assert sp.find_wifi_sensor("wlan1", identity, sysfs=net).state == "changed"
    assert sp.find_wifi_sensor("wlan1", sysfs=net).state == "present"


def test_wifi_absent_interface(tmp_path):
    wifi_radio(tmp_path)
    net = tmp_path / "class/net"
    assert sp.find_wifi_sensor("wlan2", sysfs=net).state == "absent"
    assert sp.find_wifi_sensor("../x", sysfs=net).state == "absent"
    assert sp.wifi_identity("wlan2", sysfs=net) is None


@pytest.mark.parametrize("name", ["ifindex", "type"])
def test_wifi_unreadable_file_is_absent(tmp_path, name):
    wifi_radio(tmp_path)
    net = tmp_path / "class/net"
    unreadable(net / "wlan1" / name)
    assert sp.find_wifi_sensor("wlan1", sysfs=net).state == "absent"


def test_wifi_unreadable_identity_is_absent(tmp_path):
    wiphy = wifi_radio(tmp_path)
    net = tmp_path / "class/net"
    identity = sp.wifi_identity("wlan1", sysfs=net)
    unreadable(wiphy / "macaddress")
    assert sp.wifi_identity("wlan1", sysfs=net) is None
    assert sp.find_wifi_sensor("wlan1", identity, sysfs=net).state == "absent"
    # Without an identity, the readable interface still counts as present.
    assert sp.find_wifi_sensor("wlan1", sysfs=net).state == "present"


def test_wifi_non_wireless_interface_has_no_identity(tmp_path):
    net = tmp_path / "class/net/wlan1"
    net.mkdir(parents=True)
    (net / "ifindex").write_text("3\n")
    (net / "type").write_text("1\n")
    root = tmp_path / "class/net"
    assert sp.wifi_identity("wlan1", sysfs=root) is None
    assert sp.find_wifi_sensor("wlan1", "a" * 64, sysfs=root).state == "absent"


# --- Bluetooth ------------------------------------------------------------------


ADDRESS = "00:1A:7D:DA:71:13"


@pytest.fixture
def adapters(tmp_path, monkeypatch):
    root = tmp_path / "class/bluetooth"
    root.mkdir(parents=True)
    table = {}
    monkeypatch.setattr(sp, "_hci_address", lambda index: table.get(index))

    def plug(index, address):
        (root / f"hci{index}").mkdir()
        table[index] = address.lower()

    return root, plug


def test_bluetooth_by_name(adapters):
    root, plug = adapters
    assert sp.find_bluetooth_adapter("hci0", sysfs=root).state == "absent"
    plug(0, ADDRESS)
    assert sp.find_bluetooth_adapter("hci0", sysfs=root) == sp.Presence(
        "present", {"hci": "hci0"}
    )


def test_bluetooth_by_address_follows_renumbering(adapters):
    root, plug = adapters
    assert sp.find_bluetooth_adapter(ADDRESS, sysfs=root).state == "absent"
    plug(0, "00:11:22:33:44:55")
    assert sp.find_bluetooth_adapter(ADDRESS, sysfs=root).state == "absent"
    plug(3, ADDRESS)
    presence = sp.find_bluetooth_adapter(ADDRESS.lower(), sysfs=root)
    assert presence == sp.Presence("present", {"hci": "hci3"})
    assert ADDRESS.lower() not in repr(presence)


@pytest.mark.parametrize("adapter", ["hciX", "eth0", "00:11", None])
def test_bluetooth_invalid_adapter_is_absent(adapters, adapter):
    root, plug = adapters
    plug(0, ADDRESS)
    assert sp.find_bluetooth_adapter(adapter, sysfs=root).state == "absent"


def test_bluetooth_missing_sysfs_is_absent(tmp_path):
    assert sp.find_bluetooth_adapter(ADDRESS, sysfs=tmp_path / "none").state == "absent"


def test_hci_address_without_bluetooth_support_is_none(monkeypatch):
    monkeypatch.delattr(sp.socket, "AF_BLUETOOTH", raising=False)
    assert sp._hci_address(0) is None


class _FakeHciSocket:
    def __init__(self, *args):
        self.args = args

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def fileno(self):
        return 42


def _fake_hci(monkeypatch, ioctl):
    import fcntl

    sockets = []

    def make_socket(*args):
        sockets.append(_FakeHciSocket(*args))
        return sockets[-1]

    # The constants are absent off Linux; the fakes stand in for them.
    monkeypatch.setattr(sp.socket, "AF_BLUETOOTH", 31, raising=False)
    monkeypatch.setattr(sp.socket, "BTPROTO_HCI", 1, raising=False)
    monkeypatch.setattr(sp.socket, "socket", make_socket)
    monkeypatch.setattr(fcntl, "ioctl", ioctl)
    return sockets


def test_hci_address_decodes_hcigetdevinfo(monkeypatch):
    calls = []

    def ioctl(fd, request, buffer, mutate):
        calls.append((fd, request, len(buffer), bytes(buffer[:2]), mutate))
        buffer[2:10] = b"hci3\0\0\0\0"
        # bdaddr_t at bytes 10..16, least significant byte first.
        buffer[10:16] = bytes([0x66, 0x55, 0x44, 0x33, 0x1A, 0x00])
        return 0

    sockets = _fake_hci(monkeypatch, ioctl)
    assert sp._hci_address(3) == "00:1a:33:44:55:66"
    assert calls == [(42, 0x800448D3, 92, b"\x03\x00", True)]
    assert sockets[0].args == (31, sp.socket.SOCK_RAW, 1)


def test_hci_address_ioctl_error_or_zero_address_is_none(monkeypatch):
    def failing(fd, request, buffer, mutate):
        raise OSError(19, "No such device")

    _fake_hci(monkeypatch, failing)
    assert sp._hci_address(0) is None

    _fake_hci(monkeypatch, lambda fd, request, buffer, mutate: 0)
    assert sp._hci_address(0) is None


def test_hci_address_without_fcntl_is_none(monkeypatch):
    import sys

    _fake_hci(monkeypatch, lambda fd, request, buffer, mutate: 0)
    # A None entry makes "import fcntl" raise ImportError, as on Windows.
    monkeypatch.setitem(sys.modules, "fcntl", None)
    assert sp._hci_address(0) is None


# --- USB serial (Zigbee style) --------------------------------------------------


def serial_dongle(tmp_path, *, tty="ttyUSB0", port="1-1", devnum=5, serial=SERIAL):
    sysfs = tmp_path / "sys"
    device = sysfs / "devices/platform/usb1" / port
    device.mkdir(parents=True, exist_ok=True)
    for name, value in (
        ("idVendor", "10c4"),
        ("idProduct", "ea60"),
        ("busnum", "1"),
        ("devnum", str(devnum)),
        ("serial", serial),
    ):
        (device / name).write_text(value + "\n")
    interface = device / f"{port}:1.0"
    interface.mkdir(exist_ok=True)
    # ttyUSB hangs below a usb-serial port; ttyACM directly on the interface.
    target = interface / tty if tty.startswith("ttyUSB") else interface
    target.mkdir(exist_ok=True)
    classes = sysfs / "class/tty" / tty
    classes.mkdir(parents=True)
    (classes / "device").symlink_to(target, target_is_directory=True)
    dev = tmp_path / "dev"
    (dev / "serial/by-id").mkdir(parents=True, exist_ok=True)
    (dev / tty).write_text("")
    link = dev / "serial/by-id" / f"usb-Example_Dongle_{serial}-if00-port0"
    link.symlink_to(Path("../..") / tty)
    return sysfs / "class/tty", device, link


def unplug_serial(tmp_path):
    for path in sorted(tmp_path.rglob("*"), reverse=True):
        if path.is_symlink() or path.is_file():
            path.unlink()
        else:
            path.rmdir()


def test_serial_by_id_resolves_to_usb_device(tmp_path):
    root, device, link = serial_dongle(tmp_path)
    identity = sp.usb_identity(device)
    expected = {
        "busnum": 1,
        "devnum": 5,
        "node": "/dev/bus/usb/001/005",
        "serial": SERIAL,
        "tty": "ttyUSB0",
        "port": "1-1",
    }
    for path in (str(link), str(tmp_path / "dev/ttyUSB0"), "ttyUSB0"):
        assert sp.find_serial_sensor(path, identity, sysfs=root) == sp.Presence(
            "present", expected
        )


def test_serial_acm_dongle(tmp_path):
    root, device, _ = serial_dongle(tmp_path, tty="ttyACM0")
    presence = sp.find_serial_sensor("ttyACM0", sp.usb_identity(device), sysfs=root)
    assert presence.state == "present"
    assert presence.detail["tty"] == "ttyACM0"


def test_serial_renumbered_tty_is_still_present(tmp_path):
    root, device, link = serial_dongle(tmp_path, tty="ttyUSB0", devnum=5)
    identity = sp.usb_identity(device)
    unplug_serial(tmp_path)
    assert sp.find_serial_sensor(str(link), identity, sysfs=root).state == "absent"
    root, _, link = serial_dongle(tmp_path, tty="ttyUSB1", devnum=9)
    presence = sp.find_serial_sensor(str(link), identity, sysfs=root)
    assert presence.state == "present"
    assert (presence.detail["tty"], presence.detail["devnum"]) == ("ttyUSB1", 9)


def test_serial_swapped_dongle_is_changed(tmp_path):
    root, device, _ = serial_dongle(tmp_path)
    identity = sp.usb_identity(device)
    (device / "serial").write_text("OTHER\n")
    assert sp.find_serial_sensor("ttyUSB0", identity, sysfs=root).state == "changed"
    assert sp.find_serial_sensor("ttyUSB0", sysfs=root).state == "present"


@pytest.mark.parametrize("path", ["ttyUSB7", "/nonexistent/ttyUSB0", "../x", "", None])
def test_serial_absent_paths(tmp_path, path):
    root, _, _ = serial_dongle(tmp_path)
    assert sp.find_serial_sensor(path, sysfs=root).state == "absent"


def test_serial_unreadable_or_not_usb_is_absent(tmp_path):
    root, device, _ = serial_dongle(tmp_path)
    unreadable(device / "devnum")
    assert sp.find_serial_sensor("ttyUSB0", sysfs=root).state == "absent"
    # An on-board UART has no USB ancestor.
    uart = tmp_path / "sys/devices/platform/serial0/tty/ttyAMA0"
    uart.mkdir(parents=True)
    (root / "ttyAMA0").mkdir()
    (root / "ttyAMA0/device").symlink_to(uart, target_is_directory=True)
    assert sp.find_serial_sensor("ttyAMA0", sysfs=root).state == "absent"


# --- Tracker and wait loop ----------------------------------------------------------


def test_presence_rejects_unknown_state():
    with pytest.raises(ValueError):
        sp.Presence("missing")


def test_reasons_are_the_closed_list():
    assert sp.REASONS == {
        "starting",
        "sensor_absent",
        "sensor_changed",
        "sensor_unusable",
        "capture_failed",
    }
    assert sp.SENSOR_UNUSABLE == "sensor_unusable"


def test_tracker_logs_once_per_change(caplog):
    tracker = sp.PresenceTracker("sdr", logging.getLogger("presence-test"))
    assert tracker.reason == sp.STARTING
    caplog.set_level(logging.INFO, logger="presence-test")
    absent = sp.Presence("absent")
    present = sp.Presence("present", {"serial": SERIAL, "node": "/dev/bus/usb/1/4"})
    assert tracker.update(absent) is True
    assert tracker.update(absent) is False
    assert tracker.update(absent) is False
    assert tracker.reason == sp.SENSOR_ABSENT
    assert tracker.update(present) is True
    assert tracker.update(present) is False
    assert tracker.reason is None
    assert tracker.update(sp.Presence("changed")) is True
    assert tracker.reason == sp.SENSOR_CHANGED
    messages = [record.getMessage() for record in caplog.records]
    assert messages == [
        "sdr sensor absent; waiting for it to return",
        "sdr sensor present; capture can start",
        "sdr sensor replaced by a different device; not using it until it is "
        "selected again",
    ]
    assert not any(SERIAL in m or "/dev" in m for m in messages)


def test_wait_until_present_returns_when_sensor_returns(caplog):
    caplog.set_level(logging.INFO, logger="presence-wait")
    tracker = sp.PresenceTracker("zigbee", logging.getLogger("presence-wait"))
    results = iter(
        [sp.Presence("absent")] * 3
        + [sp.Presence("changed"), sp.Presence("present", {"tty": "ttyUSB1"})]
    )
    changes = []
    waits = []

    class Event(threading.Event):
        def wait(self, timeout=None):
            waits.append(timeout)
            return False

    found = sp.wait_until_present(
        lambda: next(results),
        Event(),
        tracker,
        interval=2.5,
        on_change=changes.append,
    )
    assert found == sp.Presence("present", {"tty": "ttyUSB1"})
    assert changes == [sp.SENSOR_ABSENT, sp.SENSOR_CHANGED, None]
    assert waits == [2.5] * 4
    assert len(caplog.records) == 3


def test_wait_until_present_stops_on_event():
    stop = threading.Event()
    tracker = sp.PresenceTracker("wifi", logging.getLogger("presence-stop"))
    calls = []

    setter = threading.Thread(target=stop.set)

    def probe():
        calls.append(1)
        if len(calls) == 2:
            # Set from another thread while the wait keeps re-checking; no
            # fixed time, so a loaded runner cannot end it before a re-check.
            setter.start()
        return sp.Presence("absent")

    try:
        assert sp.wait_until_present(probe, stop, tracker, interval=0.05) is None
    finally:
        if setter.is_alive():
            setter.join(timeout=30)
    assert len(calls) >= 2
    # Already stopped: no probe at all.
    calls.clear()
    assert sp.wait_until_present(probe, stop, tracker, interval=60) is None
    assert calls == []


def test_module_uses_only_the_standard_library():
    source = Path(sp.__file__).read_text()
    assert "sigrift.lib" not in source
    assert "subprocess" not in source
