"""Find a selected sensor by stable identity and wait for it to return.

Every scanner follows docs/sensor-lifecycle.md: an absent sensor is waited for,
the same sensor is resumed even when the kernel renumbers it, and a different
sensor in its place is refused while an identity is configured.

Only sysfs is read, never written, and no process is started. A missing or
unreadable file means "absent"; the finders never raise for one. Identities
match scripts/scanner_setup.py exactly (tests compare the two). ``detail``
holds local handles such as device nodes and serials: it is for opening the
device and is never reported to the bridge or logged.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import struct
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

STARTING = "starting"
SENSOR_ABSENT = "sensor_absent"
SENSOR_CHANGED = "sensor_changed"
# Attached and matching, but the host will not let the scanner open it (device
# node permissions, or a kernel driver holds it).
SENSOR_UNUSABLE = "sensor_unusable"
CAPTURE_FAILED = "capture_failed"
REASONS = frozenset(
    {STARTING, SENSOR_ABSENT, SENSOR_CHANGED, SENSOR_UNUSABLE, CAPTURE_FAILED}
)

_STATES = frozenset({"present", "absent", "changed"})
_USB_PORT = re.compile(r"[0-9]+-[0-9]+(?:\.[0-9]+)*\Z")
_INTERFACE = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
_HCI = re.compile(r"hci([0-9]{1,3})\Z")
_BDADDR = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\Z")
_TTY = re.compile(r"tty[A-Za-z]+[0-9]+\Z")
_IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
# Linux ARPHRD_IEEE80211_RADIOTAP: the interface is in monitor mode.
_ARPHRD_RADIOTAP = "803"
# <linux/bluetooth/hci.h>: _IOR('H', 211, int) and sizeof(struct hci_dev_info).
_HCIGETDEVINFO = 0x800448D3
_HCI_DEV_INFO_SIZE = 92


@dataclass(frozen=True)
class Presence:
    state: str
    # repr=False keeps serials and device nodes out of accidental log lines.
    detail: dict = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.state not in _STATES:
            raise ValueError("Invalid sensor presence state")


_ABSENT = Presence("absent")


def _read(path: Path) -> str:
    # Same normalization as scanner_setup.read_text, so identities agree.
    return path.read_text(encoding="utf-8").strip()


def _same(identity: str | None, current: str) -> bool:
    return identity is None or identity.strip().lower() == current


def usb_identity(device_dir: Path) -> str:
    """sha256 of "vendor:product:serial"; raises OSError/UnicodeError if unreadable."""
    vendor = _read(device_dir / "idVendor")
    product = _read(device_dir / "idProduct")
    serial = _read(device_dir / "serial") if (device_dir / "serial").exists() else ""
    return hashlib.sha256(f"{vendor}:{product}:{serial}".encode()).hexdigest()


def _usb_presence(entry: Path, identity: str | None, **extra) -> Presence:
    try:
        bus, number = _read(entry / "busnum"), _read(entry / "devnum")
        if not (bus.isdecimal() and number.isdecimal()):
            return _ABSENT
        busnum, devnum = int(bus), int(number)
        if not (1 <= busnum <= 999 and 1 <= devnum <= 999):
            return _ABSENT
        current = usb_identity(entry)
        serial = _read(entry / "serial") if (entry / "serial").exists() else ""
    except (OSError, UnicodeError):
        return _ABSENT
    if not _same(identity, current):
        return Presence("changed")
    return Presence(
        "present",
        {
            "busnum": busnum,
            "devnum": devnum,
            "node": f"/dev/bus/usb/{busnum:03d}/{devnum:03d}",
            "serial": serial,
            **extra,
        },
    )


def find_usb_sensor(
    port: str,
    identity: str | None = None,
    *,
    sysfs: Path = Path("/sys/bus/usb/devices"),
) -> Presence:
    """The USB device at ``port`` (for example "3-1"), checked against identity.

    The port is physical topology; the device number in ``detail`` is not and
    changes on every re-plug.
    """
    if not isinstance(port, str) or not _USB_PORT.fullmatch(port):
        return _ABSENT
    entry = sysfs / port
    try:
        if not (entry / "idVendor").is_file():
            return _ABSENT
    except OSError:
        return _ABSENT
    return _usb_presence(entry, identity)


def wifi_identity(
    interface: str, *, sysfs: Path = Path("/sys/class/net")
) -> str | None:
    """scripts/scanner_setup.py wifi_identity, keyed by interface; None if unavailable."""
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
        return None
    root = sysfs.parent.parent
    try:
        base = (root / "devices").resolve(strict=True)
        wiphy = (sysfs / interface / "phy80211").resolve(strict=True)
        phy_link = sysfs.parent / "ieee80211" / wiphy.name
        device = (wiphy / "device").resolve(strict=True)
        topology = device.relative_to(base)
        if (
            phy_link.resolve(strict=True) != wiphy
            or not device.is_dir()
            or not topology.parts
            or not wiphy.is_relative_to(device)
        ):
            return None
        address = (wiphy / "macaddress").read_text(encoding="ascii").strip().lower()
        if (
            not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", address)
            or address == "00:00:00:00:00:00"
            or int(address[:2], 16) & 1
        ):
            return None
        # A re-plug during the reads must not combine two radios' metadata.
        if (
            phy_link.resolve(strict=True) != wiphy
            or (sysfs / interface / "phy80211").resolve(strict=True) != wiphy
            or (wiphy / "device").resolve(strict=True) != device
            or (wiphy / "macaddress").read_text(encoding="ascii").strip().lower()
            != address
        ):
            return None
    except (OSError, UnicodeError, ValueError, RuntimeError):
        return None
    encoded = json.dumps(
        ["sigrift-wifi-identity-v1", topology.as_posix(), address],
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def find_wifi_sensor(
    interface: str,
    identity: str | None = None,
    *,
    sysfs: Path = Path("/sys/class/net"),
) -> Presence:
    """The named interface; with an identity, only on the selected radio.

    An interface whose identity cannot be read is "absent": it may be mid
    re-plug, or not a Wi-Fi radio at all.
    """
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface):
        return _ABSENT
    netdir = sysfs / interface
    try:
        ifindex = int(_read(netdir / "ifindex"))
        monitor = _read(netdir / "type") == _ARPHRD_RADIOTAP
    except (OSError, UnicodeError, ValueError):
        return _ABSENT
    if identity is not None:
        current = wifi_identity(interface, sysfs=sysfs)
        if current is None:
            return _ABSENT
        if not _same(identity, current):
            return Presence("changed")
    return Presence("present", {"ifindex": ifindex, "monitor": monitor})


def _hci_address(index: int) -> str | None:
    """The adapter's Bluetooth address via HCIGETDEVINFO; None if unavailable.

    Modern kernels expose no address in sysfs. This ioctl only reads.
    """
    try:
        import fcntl

        family = socket.AF_BLUETOOTH
        protocol = socket.BTPROTO_HCI
    except (ImportError, AttributeError):
        return None
    try:
        with socket.socket(family, socket.SOCK_RAW, protocol) as hci:
            request = bytearray(_HCI_DEV_INFO_SIZE)
            struct.pack_into("<H", request, 0, index)
            fcntl.ioctl(hci.fileno(), _HCIGETDEVINFO, request, True)
    except OSError:
        return None
    # bdaddr_t follows dev_id (2 bytes) and name[8], least significant byte first.
    raw = bytes(request[10:16])
    if raw == bytes(6):
        return None
    return ":".join(f"{byte:02x}" for byte in reversed(raw))


def bluetooth_address(hci: str) -> str | None:
    """The Bluetooth address adapter ``hciN`` has right now, or None."""
    if not hci.startswith("hci") or not hci[3:].isdigit():
        return None
    return _hci_address(int(hci[3:]))


def find_bluetooth_adapter(
    adapter: str, *, sysfs: Path = Path("/sys/class/bluetooth")
) -> Presence:
    """``adapter`` is "hciN" (legacy, kernel-numbered) or a stable address."""
    if not isinstance(adapter, str):
        return _ABSENT
    if _HCI.fullmatch(adapter):
        try:
            return (
                Presence("present", {"hci": adapter})
                if (sysfs / adapter).exists()
                else _ABSENT
            )
        except OSError:
            return _ABSENT
    if not _BDADDR.fullmatch(adapter):
        return _ABSENT
    wanted = adapter.lower()
    try:
        names = sorted(item.name for item in sysfs.iterdir())
    except OSError:
        return _ABSENT
    for name in names:
        if (match := _HCI.fullmatch(name)) and _hci_address(int(match[1])) == wanted:
            return Presence("present", {"hci": name})
    # An address is unique to one adapter: another adapter is not this one.
    return _ABSENT


def find_serial_sensor(
    path: str,
    identity: str | None = None,
    *,
    sysfs: Path = Path("/sys/class/tty"),
) -> Presence:
    """A USB serial dongle by /dev/serial/by-id path, /dev/ttyX path or tty name.

    Resolves the tty to its USB device through sysfs and applies the USB
    identity rule. ``detail`` adds "tty" (current name) and "port" (USB port).
    """
    if not isinstance(path, str) or not path:
        return _ABSENT
    try:
        name = Path(path).resolve(strict=True).name if "/" in path else path
        if not _TTY.fullmatch(name):
            return _ABSENT
        usb = (sysfs / name / "device").resolve(strict=True)
        # ttyACM's device is the USB interface; ttyUSB's is a usb-serial port
        # below it. The USB device is the nearest ancestor with busnum.
        for candidate in (usb, *usb.parents):
            if (candidate / "busnum").is_file() and (candidate / "idVendor").is_file():
                break
        else:
            return _ABSENT
    except (OSError, RuntimeError):
        return _ABSENT
    if not _USB_PORT.fullmatch(candidate.name):
        return _ABSENT
    return _usb_presence(candidate, identity, tty=name, port=candidate.name)


_MESSAGES = {
    "present": (logging.INFO, "%s sensor present; capture can start"),
    "absent": (logging.WARNING, "%s sensor absent; waiting for it to return"),
    "changed": (
        logging.WARNING,
        "%s sensor replaced by a different device; not using it until it is "
        "selected again",
    ),
}


class PresenceTracker:
    """Remember the last presence state and log one line per change.

    The wording is fixed: it names the sensor kind and state, never a serial
    or address. ``reason`` is read by the status thread while update runs.
    """

    def __init__(self, name: str, logger: logging.Logger) -> None:
        self._name = name
        self._logger = logger
        self._state: str | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> str | None:
        return self._state

    @property
    def reason(self) -> str | None:
        state = self._state
        if state == "present":
            return None
        if state == "changed":
            return SENSOR_CHANGED
        if state == "absent":
            return SENSOR_ABSENT
        return STARTING

    def update(self, presence: Presence) -> bool:
        with self._lock:
            if presence.state == self._state:
                return False
            self._state = presence.state
        level, message = _MESSAGES[presence.state]
        self._logger.log(level, message, self._name)
        return True


def wait_until_present(
    probe: Callable[[], Presence],
    stop_event: threading.Event,
    tracker: PresenceTracker,
    *,
    interval: float = 5.0,
    on_change: Callable[[str | None], None] | None = None,
) -> Presence | None:
    """Poll ``probe`` until it reports "present"; None once stop_event is set."""
    while not stop_event.is_set():
        presence = probe()
        if tracker.update(presence) and on_change is not None:
            on_change(tracker.reason)
        if presence.state == "present":
            return presence
        if stop_event.wait(interval):
            break
    return None
