"""One-command host preparation: scanner_setup.py prepare / unprepare.

sysfs-like trees and the files under a temporary /etc are real. Discovery,
nmcli, udevadm and the receiver's driver release are explicit fixtures, so
nothing here needs root or touches this machine's devices or configuration.
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace

import pytest
import test_scanner_setup as planner

setup = planner.setup
clean = planner.clean
project = planner.project
SERIAL = "synthetic-serial"
RECEIVER = {
    "usb": "1-1.3",
    "identity": "a" * 64,
    "device": "/dev/bus/usb/001/004",
    "gid": 0,
}
SPARE = {"interface": "wlan1", "phy": "phy1", "identity": "b" * 64}
MANAGEMENT = {"interface": "wlan0", "phy": "phy0", "identity": "c" * 64}
PROTECTED = "radio carries SSH, routed/addressed traffic or an active/unknown sibling"
UDEV = Path("udev/rules.d/70-sigrift-sdr.rules")
DROPIN = Path("NetworkManager/conf.d/90-sigrift-scanner.conf")
SPARE_ADDRESS = "02:11:22:33:44:01"


class Host:
    """A fake host: discovery result, nmcli/udevadm boundary and driver release."""

    def __init__(self, tmp_path, monkeypatch, *, nm="running", wlan1="disconnected"):
        import grp

        self.root = tmp_path / "checkout"
        self.root.mkdir(parents=True)
        self.sysfs = tmp_path / "sys"
        self.dev = tmp_path / "dev"
        self.etc = tmp_path / "etc"
        (self.etc / UDEV).parent.mkdir(parents=True)
        (self.etc / DROPIN).parent.mkdir(parents=True)
        entry = self.sysfs / "bus/usb/devices" / RECEIVER["usb"]
        entry.mkdir(parents=True)
        for name, value in {
            "idVendor": "0bda",
            "idProduct": "2838",
            "serial": SERIAL,
        }.items():
            (entry / name).write_text(value + "\n")
        for index, interface in ((0, "wlan0"), (1, "wlan1")):
            device = self.sysfs / "devices" / f"radio{index}"
            phy = device / "ieee80211" / f"phy{index}"
            phy.mkdir(parents=True)
            (phy / "macaddress").write_text(f"02:11:22:33:44:{index:02x}\n")
            for link, target in (
                (phy / "device", device),
                (self.sysfs / "class/ieee80211" / f"phy{index}", phy),
                (self.sysfs / "class/net" / interface / "phy80211", phy),
            ):
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target, target_is_directory=True)
            (self.sysfs / "class/net" / interface / "address").write_text(
                f"02:11:22:33:44:{index:02x}\n"
            )
        monkeypatch.setattr(grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=46))
        self.discovery = {
            "sdr": [RECEIVER | {"reasons": ["kernel driver owns this receiver"]}],
            "wifi": [
                MANAGEMENT | {"reasons": [PROTECTED]},
                SPARE | {"reasons": []},
            ],
            "reasons": [],
        }
        self.discover_options = []

        def discover(**options):
            self.discover_options.append(options)
            return copy.deepcopy(self.discovery)

        monkeypatch.setattr(setup, "discover", discover)
        for name in ("SSH_CONNECTION", "SUDO_USER", "SUDO_UID", "SUDO_COMMAND"):
            monkeypatch.delenv(name, raising=False)
        self.nm = nm
        # NetworkManager's own state per device; a device is unmanaged when a
        # runtime "managed no" or a loaded configuration file says so.
        self.states = {"wlan0": "connected", "wlan1": wlan1, "lo": "unmanaged"}
        self.runtime_unmanaged = set()
        self.config_unmanaged = set()
        self.honors_dropin = True
        self.stuck = False
        self.calls = []
        self.released = []
        self.root_user = True

    def current(self, name):
        if name in self.runtime_unmanaged or name in self.config_unmanaged:
            return "unmanaged"
        return self.states[name]

    def load_config(self):
        path = self.etc / DROPIN
        honored = (
            self.honors_dropin
            and path.is_file()
            and f"unmanaged-devices+=mac:{SPARE_ADDRESS}" in path.read_text()
        )
        self.config_unmanaged = {"wlan1"} if honored else set()

    def reboot(self):
        """NetworkManager starts again: runtime choices are gone, files are read."""
        self.runtime_unmanaged.clear()
        self.load_config()

    def run(self, args, **kwargs):
        self.calls.append(list(args))
        assert "timeout" not in kwargs or kwargs["timeout"] > 0
        if args[0] == "nmcli":
            if self.nm == "absent":
                raise setup.SetupError("nmcli is unavailable")
            if args == ["nmcli", "-t", "-f", "RUNNING", "general"]:
                if self.nm == "inactive":
                    raise setup.SetupError("nmcli probe failed")
                return "running\n"
            if args == ["nmcli", "-t", "-f", "DEVICE,STATE", "device"]:
                return "".join(f"{k}:{self.current(k)}\n" for k in self.states)
            if args == ["nmcli", "general", "reload"]:
                self.load_config()
                return ""
            if args[:3] == ["nmcli", "device", "set"] and args[4:] == [
                "managed",
                "no",
            ]:
                if not self.stuck:
                    self.runtime_unmanaged.add(args[3])
                return ""
        if args in (
            ["udevadm", "control", "--reload-rules"],
            ["udevadm", "trigger", "--subsystem-match=usb"],
        ):
            return ""
        raise AssertionError(args)

    def release(self, usb, *, sysfs, dev):
        assert sysfs == self.sysfs and dev == self.dev
        self.released.append(usb)
        for item in self.discovery["sdr"]:
            if item["usb"] == usb:
                item["reasons"] = []

    def prepare(self, **options):
        options.setdefault("mode", "apply")
        return setup.prepare(
            self.root,
            sysfs=self.sysfs,
            dev=self.dev,
            etc=self.etc,
            runner=self.run,
            is_root=lambda: self.root_user,
            release=self.release,
            owner=None,
            sleep=lambda _: None,
            **options,
        )

    def unprepare(self, **options):
        options.setdefault("mode", "apply")
        return setup.unprepare(
            etc=self.etc,
            runner=self.run,
            is_root=lambda: self.root_user,
            **options,
        )

    def files(self):
        return {
            path.relative_to(self.etc): path.read_bytes()
            for path in sorted(self.etc.rglob("*"))
            if path.is_file()
        }

    def mutations(self):
        return [
            call
            for call in self.calls
            if call[0] == "udevadm"
            or call[:2] == ["nmcli", "general"]
            or call[:3] == ["nmcli", "device", "set"]
        ]


@pytest.fixture
def host(tmp_path, monkeypatch, clean):
    return Host(tmp_path, monkeypatch)


def printed_rule(host, monkeypatch, capsys):
    real = setup.udev_rule
    monkeypatch.setattr(setup, "udev_rule", lambda usb: real(usb, sysfs=host.sysfs))
    monkeypatch.setattr(setup.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["scanner_setup.py", "prepare-rtl", "--usb=1-1.3", "--print-udev-rule"],
    )
    capsys.readouterr()
    assert setup.main() == 0
    monkeypatch.setattr(setup, "udev_rule", real)
    return capsys.readouterr().out.encode()


# ── Review path ──────────────────────────────────────────────────────


def test_print_changes_nothing_needs_no_root_and_lists_every_step(host, capsys):
    host.root_user = False
    host.prepare(mode="print")
    out = capsys.readouterr().out
    assert host.files() == {}
    assert host.released == [] and host.mutations() == []
    rule = setup.udev_rule("1-1.3", sysfs=host.sysfs) + "\n"
    dropin = setup.nm_dropin_text("wlan1", SPARE_ADDRESS)
    assert str(host.etc / UDEV) in out and str(host.etc / DROPIN) in out
    assert rule in out and dropin in out
    order = [
        "prepare-rtl --usb=1-1.3",
        str(host.etc / UDEV),
        "udevadm control --reload-rules",
        "udevadm trigger --subsystem-match=usb",
        str(host.etc / DROPIN),
        "nmcli general reload",
        "nmcli device set wlan1 managed no",
    ]
    positions = [out.index(item) for item in order]
    assert positions == sorted(positions)
    assert "sudo python3 scripts/scanner_setup.py unprepare" in out
    assert "wlan0" not in out  # the management radio is never a target


def test_check_reports_needed_then_nothing_after_prepare(host, capsys):
    host.root_user = False
    host.prepare(mode="check")
    # The targets quickstart passes to the root run, so it acts on these only.
    assert capsys.readouterr().out == "needed\nusb=1-1.3\nwifi-interface=wlan1\n"
    assert host.files() == {}
    host.root_user = True
    host.prepare()
    capsys.readouterr()
    host.root_user = False
    host.prepare(mode="check")
    assert capsys.readouterr().out == "not-needed\n"


def test_apply_without_root_is_refused_before_discovery(host, monkeypatch):
    host.root_user = False
    monkeypatch.setattr(
        setup, "discover", lambda: pytest.fail("no discovery without root")
    )
    with pytest.raises(setup.SetupError, match="--print"):
        host.prepare()
    assert host.files() == {} and host.released == []


# ── Receiver ─────────────────────────────────────────────────────────


def test_installed_rule_is_byte_equal_to_the_printed_rule(host, monkeypatch, capsys):
    printed = printed_rule(host, monkeypatch, capsys)
    host.prepare()
    out = capsys.readouterr().out
    path = host.etc / UDEV
    assert path.read_bytes() == printed
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert host.released == ["1-1.3"]
    assert host.mutations()[:2] == [
        ["udevadm", "control", "--reload-rules"],
        ["udevadm", "trigger", "--subsystem-match=usb"],
    ]
    assert not [p for p in path.parent.iterdir() if p.name != path.name]
    assert "sudo python3 scripts/scanner_setup.py unprepare" in out


def test_ready_receiver_still_gets_its_persistent_rule(host, capsys):
    host.discovery["sdr"][0]["reasons"] = []
    host.prepare(scanners="sdr")
    assert host.released == []
    assert (host.etc / UDEV).is_file()


@pytest.mark.parametrize("target", [UDEV, DROPIN])
@pytest.mark.parametrize("kind", ["foreign", "symlink", "other-device"])
def test_existing_file_that_is_not_ours_is_refused_and_untouched(
    host, capsys, target, kind
):
    path = host.etc / target
    if kind == "foreign":
        path.write_text("# operator rule\n")
    elif kind == "symlink":
        (host.etc / "elsewhere").write_text("operator\n")
        path.symlink_to(host.etc / "elsewhere")
    elif target == UDEV:
        other = setup.udev_rule("1-1.3", sysfs=host.sysfs).replace(
            SERIAL, "another-serial"
        )
        path.write_text(other + "\n")
    else:
        path.write_text(setup.nm_dropin_text("wlan1", "02:aa:bb:cc:dd:ee"))
    before = host.files()
    with pytest.raises(setup.SetupError, match=str(path)):
        host.prepare(mode="print")
    with pytest.raises(setup.SetupError, match=str(path)):
        host.prepare()
    assert host.files() == before
    assert path.is_symlink() == (kind == "symlink")
    # Nothing was changed before the refusal either.
    assert host.released == [] and host.mutations() == []


def test_older_marked_rule_for_the_same_receiver_is_updated(host, capsys):
    path = host.etc / UDEV
    current = setup.udev_rule("1-1.3", sysfs=host.sysfs) + "\n"
    path.write_text(current.replace("# To undo", "# An older comment. To undo"))
    host.prepare(scanners="sdr")
    assert path.read_text() == current


def test_receiver_without_serial_is_released_but_gets_no_rule(host, capsys):
    (host.sysfs / "bus/usb/devices/1-1.3/serial").unlink()
    host.prepare(scanners="sdr")
    out = capsys.readouterr().out
    assert host.released == ["1-1.3"]
    assert not (host.etc / UDEV).exists()
    assert "no serial" in out


def test_several_receivers_need_an_explicit_port(host, capsys):
    host.discovery["sdr"].append(
        RECEIVER | {"usb": "1-1.4", "reasons": ["kernel driver owns this receiver"]}
    )
    host.prepare(scanners="sdr")
    assert "--usb" in capsys.readouterr().out
    assert host.released == [] and host.files() == {}
    host.prepare(scanners="sdr", usb="1-1.3")
    assert host.released == ["1-1.3"]
    with pytest.raises(setup.SetupError, match="1-9"):
        host.prepare(scanners="sdr", usb="1-9")


def test_unfixable_receiver_is_not_touched(host, capsys):
    host.discovery["sdr"][0]["reasons"] = ["USB device node is unavailable"]
    host.prepare(scanners="sdr")
    assert host.released == [] and host.files() == {}
    assert "USB device node is unavailable" in capsys.readouterr().out


# ── Wi-Fi adapter ────────────────────────────────────────────────────


def test_dropin_matches_exactly_one_adapter_by_permanent_address(host, capsys):
    # The interface's current address is randomized; the permanent one counts.
    (host.sysfs / "class/net/wlan1/address").write_text("0a:99:88:77:66:55\n")
    host.prepare(scanners="wifi")
    path = host.etc / DROPIN
    text = path.read_text()
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    entries = [line for line in text.splitlines() if not line.startswith("#")]
    assert entries == ["[keyfile]", f"unmanaged-devices+=mac:{SPARE_ADDRESS}"]
    assert text.splitlines()[0].startswith(setup.NM_MARKER)
    assert "wlan1" in text.splitlines()[0]
    assert "*" not in text and "interface-name" not in text
    # The file did it: no runtime "managed no" was needed.
    assert host.mutations() == [["nmcli", "general", "reload"]]
    assert host.current("wlan1") == "unmanaged"
    assert host.current("wlan0") == "connected"
    host.reboot()
    assert host.current("wlan1") == "unmanaged"


def test_address_shared_with_another_device_is_refused(host, capsys):
    (host.sysfs / "class/net/br0").mkdir()
    (host.sysfs / "class/net/br0/address").write_text(SPARE_ADDRESS + "\n")
    with pytest.raises(setup.SetupError, match="another"):
        host.prepare(scanners="wifi")
    assert host.files() == {} and host.mutations() == []


@pytest.mark.parametrize("named", [None, "wlan0"])
def test_protected_interface_is_never_prepared(host, capsys, named):
    host.discovery["wifi"] = [MANAGEMENT | {"reasons": [PROTECTED]}]
    if named:
        with pytest.raises(setup.SetupError, match="wlan0"):
            host.prepare(scanners="wifi", wifi_interface=named)
        with pytest.raises(setup.SetupError, match="wlan0"):
            host.prepare(scanners="wifi", wifi_interface=named, mode="print")
    else:
        host.prepare(scanners="wifi")
    assert host.files() == {}
    assert not any("wlan0" in call for call in host.mutations())
    assert host.states["wlan0"] == "connected"


def test_undiscovered_interface_is_refused(host):
    with pytest.raises(setup.SetupError, match="wlan7"):
        host.prepare(wifi_interface="wlan7", mode="print")


@pytest.mark.parametrize("nm", ["absent", "inactive"])
def test_no_network_manager_means_no_dropin(tmp_path, monkeypatch, clean, nm, capsys):
    host = Host(tmp_path, monkeypatch, nm=nm)
    host.prepare(scanners="wifi")
    assert host.files() == {}
    assert host.mutations() == []
    host.prepare(scanners="wifi", mode="check")
    assert capsys.readouterr().out.endswith("not-needed\n")


def test_adapter_unknown_to_network_manager_gets_no_dropin(host):
    del host.states["wlan1"]
    host.prepare(scanners="wifi")
    assert host.files() == {}


def test_adapter_that_stays_managed_fails_loudly(host):
    host.honors_dropin = False
    host.stuck = True
    with pytest.raises(setup.SetupError, match="wlan1.*unmanaged|unmanaged.*wlan1"):
        host.prepare(scanners="wifi")


# Measured on a Pi: the adapter was unmanaged only because someone had run
# "nmcli device set wlan1 managed no", and a reboot handed it back.
def test_runtime_unmanaged_adapter_still_gets_the_persistent_dropin(host, capsys):
    host.runtime_unmanaged.add("wlan1")
    host.root_user = False
    host.prepare(scanners="wifi", mode="check")
    assert capsys.readouterr().out == "needed\nwifi-interface=wlan1\n"
    host.root_user = True
    host.prepare(scanners="wifi")
    assert (host.etc / DROPIN).is_file()
    assert ["nmcli", "general", "reload"] in host.mutations()
    host.reboot()
    assert host.current("wlan1") == "unmanaged"


def test_dropin_is_checked_before_the_runtime_setting(host, capsys):
    host.honors_dropin = False
    with pytest.raises(setup.SetupError) as raised:
        host.prepare(scanners="wifi")
    message = str(raised.value)
    assert "did not take effect" in message and "reboot" in message
    assert str(host.etc / DROPIN) in message
    # It is unmanaged for now, and only the runtime setting did that.
    assert host.mutations() == [
        ["nmcli", "general", "reload"],
        ["nmcli", "device", "set", "wlan1", "managed", "no"],
    ]
    assert host.current("wlan1") == "unmanaged"
    assert (host.etc / DROPIN).is_file()
    calls = host.calls
    reload_at = calls.index(["nmcli", "general", "reload"])
    set_at = calls.index(["nmcli", "device", "set", "wlan1", "managed", "no"])
    probes = [
        index
        for index, call in enumerate(calls)
        if call == ["nmcli", "-t", "-f", "DEVICE,STATE", "device"]
    ]
    assert any(reload_at < index < set_at for index in probes)


def test_cli_exits_non_zero_when_the_dropin_does_not_take_effect(
    host, monkeypatch, capsys
):
    host.honors_dropin = False
    real = setup.prepare

    def wired(_root, **options):
        return real(
            host.root,
            sysfs=host.sysfs,
            dev=host.dev,
            etc=host.etc,
            runner=host.run,
            is_root=lambda: True,
            release=host.release,
            owner=None,
            sleep=lambda _: None,
            **options,
        )

    monkeypatch.setattr(setup, "prepare", wired)
    monkeypatch.setattr(setup.signal, "signal", lambda *_: None)
    monkeypatch.setattr(sys, "argv", ["scanner_setup.py", "prepare", "--scanners=wifi"])
    assert setup.main() == 1
    assert "did not take effect" in capsys.readouterr().err


def test_dropin_in_place_but_managed_again_is_not_called_in_place(host, capsys):
    host.prepare(scanners="wifi")
    # After a reboot NetworkManager ignores the file (for example "+=" is not
    # honoured, or it matches a different address).
    host.honors_dropin = False
    host.reboot()
    assert host.current("wlan1") == "disconnected"
    capsys.readouterr()
    host.root_user = False
    host.prepare(scanners="wifi", mode="check")
    assert capsys.readouterr().out == "needed\nwifi-interface=wlan1\n"
    host.root_user = True
    with pytest.raises(setup.SetupError, match="did not take effect"):
        host.prepare(scanners="wifi")
    assert "Already in place" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "state",
    [
        "connecting (getting IP configuration)",
        "connected",
        "connected (externally)",
        "deactivating",
    ],
)
def test_adapter_in_use_by_network_manager_is_refused(
    tmp_path, monkeypatch, clean, state
):
    host = Host(tmp_path, monkeypatch, wlan1=state)
    for mode in ("print", "check", "apply"):
        with pytest.raises(setup.SetupError) as raised:
            host.prepare(scanners="wifi", mode=mode)
        assert state in str(raised.value) and "wlan1" in str(raised.value)
    assert host.files() == {} and host.mutations() == []


@pytest.mark.parametrize("state", ["disconnected", "unavailable", "unmanaged"])
def test_idle_adapter_states_are_prepared(tmp_path, monkeypatch, clean, state):
    host = Host(tmp_path, monkeypatch, wlan1=state)
    host.prepare(scanners="wifi")
    assert (host.etc / DROPIN).is_file()


# ── What the root run acts on ────────────────────────────────────────


def test_ssh_client_option_reaches_discovery(host, capsys):
    host.prepare(ssh_client="192.0.2.5")
    assert host.discover_options == [{"extra_ssh_clients": ("192.0.2.5",)}]
    host.discover_options.clear()
    host.prepare()
    assert host.discover_options == [{"extra_ssh_clients": ()}]


def test_ssh_client_option_only_protects_more(tmp_path, monkeypatch, clean):
    calls = planner.wifi_commands(
        monkeypatch, sysfs=tmp_path, routed="eth0", ssh="wlan1"
    )
    ready = setup.wifi_devices(tmp_path)
    assert "wlan1" in [item["interface"] for item in ready if not item["reasons"]]
    protected = setup.wifi_devices(tmp_path, extra_ssh_clients=("192.0.2.5",))
    assert all(item["reasons"] for item in protected if item["interface"] == "wlan1")
    assert ["ip", "-j", "route", "get", "192.0.2.5"] in calls
    # The environment's client is still protected as well.
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.9 50123 192.0.2.6 22")
    setup.wifi_devices(tmp_path, extra_ssh_clients=("192.0.2.5",))
    assert ["ip", "-j", "route", "get", "192.0.2.9"] in calls


@pytest.mark.parametrize("variable", ["SUDO_USER", "SUDO_UID", "SUDO_COMMAND"])
def test_under_sudo_without_ssh_details_wifi_needs_an_explicit_name(
    host, monkeypatch, capsys, variable
):
    monkeypatch.setenv(variable, "1000")
    host.prepare()
    out = capsys.readouterr().out
    assert not (host.etc / DROPIN).exists()
    assert (host.etc / UDEV).is_file()  # the receiver is still prepared
    assert "sudo" in out and "SSH" in out and "--wifi-interface" in out
    host.prepare(wifi_interface="wlan1")
    assert (host.etc / DROPIN).is_file()


def test_under_sudo_with_the_ssh_client_option_wifi_is_prepared(
    host, monkeypatch, capsys
):
    monkeypatch.setenv("SUDO_USER", "pi")
    host.prepare(ssh_client="192.0.2.5")
    assert (host.etc / DROPIN).is_file()


def test_ssh_connection_in_the_environment_needs_no_explicit_name(
    host, monkeypatch, capsys
):
    monkeypatch.setenv("SUDO_USER", "pi")
    monkeypatch.setenv("SSH_CONNECTION", "192.0.2.5 50123 192.0.2.6 22")
    host.prepare()
    assert (host.etc / DROPIN).is_file()


def test_named_receiver_that_discovery_would_not_accept_is_refused(host):
    host.discovery["sdr"][0]["reasons"] = ["USB device node is unavailable"]
    with pytest.raises(setup.SetupError, match="1-1.3.*unavailable"):
        host.prepare(scanners="sdr", usb="1-1.3")
    assert host.released == [] and host.files() == {}


def test_targeted_run_touches_only_the_named_kinds(host, capsys):
    host.prepare(scanners="sdr", usb="1-1.3")
    assert (host.etc / UDEV).is_file() and not (host.etc / DROPIN).exists()
    assert not any(call[0] == "nmcli" for call in host.mutations())


def test_several_ready_adapters_need_an_explicit_choice(host, capsys):
    host.discovery["wifi"].append(
        {"interface": "wlan2", "phy": "phy2", "identity": "d" * 64, "reasons": []}
    )
    host.states["wlan2"] = "disconnected"
    host.prepare(scanners="wifi")
    assert "--wifi-interface" in capsys.readouterr().out
    assert host.files() == {}
    host.prepare(scanners="wifi", wifi_interface="wlan1")
    assert (host.etc / DROPIN).is_file()


# ── Idempotence and undo ─────────────────────────────────────────────


def test_second_run_changes_nothing_and_says_so(host, capsys):
    host.prepare()
    first = host.files()
    calls = len(host.mutations())
    capsys.readouterr()
    host.prepare()
    out = capsys.readouterr().out
    assert host.files() == first
    assert len(host.mutations()) == calls
    assert host.released == ["1-1.3"]
    assert "already" in out.lower()
    assert "sudo python3 scripts/scanner_setup.py unprepare" in out


def test_unprepare_removes_only_marked_files(host, capsys):
    host.prepare()
    other = host.etc / "udev/rules.d/60-operator.rules"
    other.write_text("# operator\n")
    capsys.readouterr()
    host.unprepare(mode="print")
    assert (host.etc / UDEV).exists() and (host.etc / DROPIN).exists()
    host.root_user = False
    with pytest.raises(setup.SetupError, match="--print"):
        host.unprepare()
    host.root_user = True
    host.calls.clear()
    host.unprepare()
    out = capsys.readouterr().out
    assert not (host.etc / UDEV).exists() and not (host.etc / DROPIN).exists()
    assert other.read_text() == "# operator\n"
    assert ["udevadm", "control", "--reload-rules"] in host.calls
    assert ["nmcli", "general", "reload"] in host.calls
    assert "re-plug" in out and "reboot" in out
    host.calls.clear()
    host.unprepare()
    assert host.mutations() == []


@pytest.mark.parametrize("target", [UDEV, DROPIN])
def test_unprepare_never_removes_a_file_someone_else_wrote(host, capsys, target):
    path = host.etc / target
    path.write_text("# written by the operator\n")
    host.unprepare()
    assert path.read_text() == "# written by the operator\n"
    assert str(path) in capsys.readouterr().out
    assert host.mutations() == []


# ── NetworkManager policy ────────────────────────────────────────────


def test_policy_constant_defaults_to_warn():
    assert setup.NM_MANAGED_POLICY == "warn"
    assert setup.NM_MANAGED == "NetworkManager manages this adapter"


@pytest.mark.parametrize("policy", ["warn", "require"])
def test_both_policy_values(host, monkeypatch, capsys, policy):
    monkeypatch.setattr(setup, "NM_MANAGED_POLICY", policy)
    items = copy.deepcopy(host.discovery["wifi"])
    setup.annotate_network_manager(items, runner=host.run)
    management, spare = items
    assert management["reasons"] == [PROTECTED] and "notes" not in management
    inventory = {"sdr": [], "wifi": items, "reasons": []}
    if policy == "warn":
        assert spare["reasons"] == [] and spare["notes"] == [setup.NM_MANAGED]
        assert setup.selection_from(inventory, "auto") == {"wifi": SPARE}
    else:
        assert spare["reasons"] == [setup.NM_MANAGED] and "notes" not in spare
        assert setup.selection_from(inventory, "auto") == {}
    # Either way the adapter is the one prepare targets, and afterwards it
    # is ready with neither note nor reason.
    host.discovery["wifi"] = items
    host.prepare(scanners="wifi")
    after = copy.deepcopy(host.discovery["wifi"])
    for item in after:
        item["reasons"] = [r for r in item["reasons"] if r != setup.NM_MANAGED]
        item.pop("notes", None)
    setup.annotate_network_manager(after, runner=host.run)
    assert after[1] == SPARE | {"reasons": []}
    assert setup.selection_from({"sdr": [], "wifi": after, "reasons": []}, "auto") == {
        "wifi": SPARE
    }


def test_invalid_policy_value_is_refused(host, monkeypatch):
    monkeypatch.setattr(setup, "NM_MANAGED_POLICY", "maybe")
    with pytest.raises(setup.SetupError, match="NM_MANAGED_POLICY"):
        setup.annotate_network_manager(
            copy.deepcopy(host.discovery["wifi"]), runner=host.run
        )


# ── Plan output ──────────────────────────────────────────────────────


def plan_lines(project, monkeypatch, capsys, discovery, host_options):
    monkeypatch.setattr(setup, "discover", lambda: copy.deepcopy(discovery))
    capsys.readouterr()
    setup.plan(project, "auto", host=host_options)
    return capsys.readouterr().err.splitlines()


def test_plan_lines_are_unchanged_for_a_host_that_needs_nothing(
    project, monkeypatch, capsys, tmp_path
):
    host = Host(tmp_path / "h", monkeypatch, nm="absent")
    ready = {
        "sdr": [planner.SDR | {"reasons": []}],
        "wifi": [planner.WIFI | {"reasons": []}],
        "reasons": [],
    }
    lines = plan_lines(
        project,
        monkeypatch,
        capsys,
        ready,
        {"sysfs": host.sysfs, "etc": host.etc, "runner": host.run},
    )
    # Verbatim what the previous version printed for this host.
    assert lines == [
        "    sdr 1-2: ready",
        "    wifi wlan1: ready",
        "==> Selected scanners: sdr, wifi",
        "    SDR requires a readable ONNX model; setup will verify it before starting the worker.",
    ]


def test_plan_adds_one_prepare_line_and_keeps_the_existing_ones(
    project, monkeypatch, capsys, tmp_path
):
    host = Host(tmp_path / "h", monkeypatch)
    discovery = copy.deepcopy(host.discovery)
    setup.annotate_network_manager(discovery["wifi"], runner=host.run)
    lines = plan_lines(
        project,
        monkeypatch,
        capsys,
        discovery,
        {"sysfs": host.sysfs, "etc": host.etc, "runner": host.run},
    )
    assert lines == [
        "    sdr 1-1.3: kernel driver owns this receiver",
        "    Review and prepare this receiver only: sudo python3 scripts/scanner_setup.py prepare-rtl --usb=1-1.3",
        f"    wifi wlan0: {PROTECTED}",
        "    wifi wlan1: ready",
        "    wifi wlan1 note: " + setup.NM_NOTE,
        "    Prepare this host (one command; add --print to review): sudo python3 scripts/scanner_setup.py prepare",
        "==> Selected scanners: wifi",
    ]
    assert host.files() == {} and host.mutations() == []


def test_selection_never_carries_the_note(host):
    items = copy.deepcopy(host.discovery["wifi"])
    setup.annotate_network_manager(items, runner=host.run)
    selected = setup.selection_from({"sdr": [], "wifi": items, "reasons": []}, "wifi")
    assert setup.validate_selection(selected) == {"wifi": SPARE}


# ── Command line ─────────────────────────────────────────────────────


def test_cli_wires_prepare_and_unprepare(monkeypatch, capsys):
    seen = []
    monkeypatch.setattr(setup.signal, "signal", lambda *_: None)
    monkeypatch.setattr(
        setup, "prepare", lambda root, **options: seen.append(("prepare", options))
    )
    monkeypatch.setattr(
        setup, "unprepare", lambda **options: seen.append(("unprepare", options))
    )
    for argv in (
        ["prepare", "--print"],
        ["prepare", "--check", "--scanners", "wifi", "--wifi-interface", "wlan1"],
        ["prepare", "--usb", "1-2"],
        ["prepare", "--print", "--ssh-client", "2001:db8::5"],
        ["unprepare", "--print"],
        ["unprepare"],
    ):
        monkeypatch.setattr(sys, "argv", ["scanner_setup.py", *argv])
        assert setup.main() == 0, argv
    assert seen == [
        (
            "prepare",
            {
                "scanners": None,
                "usb": None,
                "wifi_interface": None,
                "mode": "print",
                "honor_profiles": False,
                "ssh_client": None,
            },
        ),
        (
            "prepare",
            {
                "scanners": "wifi",
                "usb": None,
                "wifi_interface": "wlan1",
                "mode": "check",
                "honor_profiles": False,
                "ssh_client": None,
            },
        ),
        (
            "prepare",
            {
                "scanners": None,
                "usb": "1-2",
                "wifi_interface": None,
                "mode": "apply",
                "honor_profiles": False,
                "ssh_client": None,
            },
        ),
        (
            "prepare",
            {
                "scanners": None,
                "usb": None,
                "wifi_interface": None,
                "mode": "print",
                "honor_profiles": False,
                "ssh_client": "2001:db8::5",
            },
        ),
        ("unprepare", {"mode": "print"}),
        ("unprepare", {"mode": "apply"}),
    ]
    for argv in (
        ["plan", "--print"],
        ["prepare", "--print", "--check"],
        ["prepare", "--wifi-interface", "bad name!"],
        ["prepare", "--usb", "1-2;x"],
        ["prepare", "--ssh-client", "not-an-address"],
        ["prepare", "--ssh-client", "192.0.2.5 22"],
        ["plan", "--ssh-client", "192.0.2.5"],
    ):
        monkeypatch.setattr(sys, "argv", ["scanner_setup.py", *argv])
        assert setup.main() == 1, argv
    capsys.readouterr()


def test_prepare_rtl_and_printed_rule_are_unchanged(host, monkeypatch, capsys):
    rule = printed_rule(host, monkeypatch, capsys).decode()
    assert rule.splitlines()[0] == (
        "# SigRift: let the scanner open the RTL-SDR receiver on USB port 1-1.3 after a re-plug or reboot."
    )
    assert rule.endswith('GROUP="plugdev", MODE="0660"\n')


def test_owner_is_root_by_default(host, monkeypatch, capsys):
    owners = []
    monkeypatch.setattr(
        setup, "os", SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    )
    monkeypatch.setattr(
        setup.os, "chown", lambda path, uid, gid: owners.append((uid, gid))
    )
    setup.prepare(
        host.root,
        scanners="sdr",
        mode="apply",
        sysfs=host.sysfs,
        dev=host.dev,
        etc=host.etc,
        runner=host.run,
        is_root=lambda: True,
        release=host.release,
        sleep=lambda _: None,
    )
    assert owners == [(0, 0)]


def test_note_says_preparation_is_recommended_not_required():
    note = setup.NM_NOTE
    assert note.startswith(setup.NM_MANAGED)
    assert "17 seconds" in note and "resumes by itself" in note
    assert "recommended, not required" in note
    assert "scanner_setup.py prepare" in note


# ── Locale ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("tool", ["nmcli", "udevadm"])
def test_nmcli_and_udevadm_run_in_the_c_locale(tmp_path, monkeypatch, tool):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / tool
    fake.write_text('#!/bin/sh\necho "LC_ALL=$LC_ALL LANG=$LANG"\n')
    fake.chmod(0o700)
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    monkeypatch.setenv("LANG", "de_DE.UTF-8")
    assert setup.run([tool]).split()[0] == "LC_ALL=C"
    # Other tools keep the caller's environment.
    other = bindir / "other-tool"
    other.write_text(fake.read_text())
    other.chmod(0o700)
    assert setup.run(["other-tool"]).split()[0] == "LC_ALL=de_DE.UTF-8"


# ── System tools outside PATH ────────────────────────────────────────


def test_system_tools_are_found_in_the_sbin_directories_when_path_lacks_them(
    tmp_path, monkeypatch
):
    # A non-login SSH command or a service often has no /usr/sbin in PATH,
    # which is where Debian keeps iw. Measured on a Pi: discovery then said
    # "iw is unavailable" although /usr/sbin/iw exists.
    sbin, bindir = tmp_path / "sbin", tmp_path / "bin"
    sbin.mkdir()
    bindir.mkdir()
    for directory, name, text in (
        (sbin, "iw", "from-sbin"),
        (sbin, "other-tool", "never"),
        (bindir, "nmcli", "from-path"),
    ):
        tool = directory / name
        tool.write_text(f"#!/bin/sh\necho {text}\n")
        tool.chmod(0o700)
    (sbin / "nmcli").write_text("#!/bin/sh\necho from-sbin\n")
    (sbin / "nmcli").chmod(0o700)
    monkeypatch.setattr(
        setup, "SYSTEM_TOOL_DIRS", (str(tmp_path / "missing"), str(sbin))
    )
    monkeypatch.setenv("PATH", f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin")
    assert setup.run(["iw"]).strip() == "from-sbin"
    # PATH wins when it has the tool.
    assert setup.run(["nmcli"]).strip() == "from-path"
    # Only the known system tools are looked up there, and the message keeps the plain name.
    with pytest.raises(setup.SetupError, match="^other-tool is unavailable"):
        setup.run(["other-tool"])
    # A non-executable or missing file is not used.
    (sbin / "iw").chmod(0o600)
    with pytest.raises(setup.SetupError, match="^iw is unavailable"):
        setup.run(["iw"])


# ── A plan that fails names the single command too ───────────────────


@pytest.mark.parametrize(
    "reasons",
    [
        ["kernel driver owns this receiver"],
        ["USB permissions do not grant read/write to the scanner"],
        [setup.SHARED_GROUP],
    ],
)
def test_failed_explicit_sdr_plan_adds_the_prepare_command(reasons):
    inventory = {
        "sdr": [RECEIVER | {"reasons": list(reasons)}],
        "wifi": [],
        "reasons": [],
    }
    with pytest.raises(setup.SetupError) as raised:
        setup.selection_from(inventory, "sdr")
    message = str(raised.value)
    # The existing sentence is unchanged and comes first.
    assert message.startswith(
        "Selected sdr is unavailable or ambiguous. " + "; ".join(reasons)
    )
    if setup.SHARED_GROUP in reasons:
        assert (
            ". Give this receiver its own group: sudo python3 "
            "scripts/scanner_setup.py prepare-rtl --usb=1-1.3"
        ) in message
    assert message.endswith(
        ". Or prepare this host in one step (add --print to review): "
        "sudo python3 scripts/scanner_setup.py prepare --scanners=sdr --usb=1-1.3"
    )


def test_failed_retry_of_the_saved_receiver_adds_the_prepare_command():
    inventory = {
        "sdr": [RECEIVER | {"reasons": ["kernel driver owns this receiver"]}],
        "wifi": [],
        "reasons": [],
    }
    previous = {"sdr": {key: RECEIVER[key] for key in ("usb", "identity")}}
    with pytest.raises(setup.SetupError, match="prepare --scanners=sdr --usb=1-1.3"):
        setup.selection_from(inventory, "sdr", previous)


def test_unfixable_receiver_failure_has_no_prepare_command():
    inventory = {
        "sdr": [RECEIVER | {"reasons": ["USB device node is unavailable"]}],
        "wifi": [],
        "reasons": [],
    }
    with pytest.raises(setup.SetupError) as raised:
        setup.selection_from(inventory, "sdr")
    assert "scanner_setup.py prepare " not in str(raised.value) + " "
