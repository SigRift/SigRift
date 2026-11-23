#!/usr/bin/env python3
"""Read-only hardware discovery and explicit, persisted local scanner selection.

Discovery never changes drivers, interfaces, permissions or exposure. The
explicit prepare-rtl action changes only its selected USB device; the explicit
prepare action (reviewable with --print, undone by unprepare) also installs the
receiver's udev rule and keeps NetworkManager off the spare Wi-Fi adapter. The
generated Compose overlay is separate from every operator-owned input.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

STATE = ".sigrift-scanners.yml"
PENDING = ".sigrift-scanners-pending.json"
HEADER = "# Managed by scripts/scanner_setup.py; edit choices with quickstart --scanners=...\n"
CORE = ["bridge", "gateway", "edge"]
SCANNERS = {"sdr": ["rtl-tcp", "scan"], "wifi": ["wifi-scan"]}
# Common Realtek IDs documented by upstream rtl-sdr.rules. Other models are not
# guessed compatible: they need an explicit supported-device follow-up.
RTL_IDS = {("0bda", "2832"), ("0bda", "2838")}
NAME = re.compile(r"[a-zA-Z0-9_.-]{1,15}\Z")
USB_NAME = re.compile(r"[0-9]+-[0-9]+(?:\.[0-9]+)*\Z")
SUPERVISOR = ["python3", "-m", "sigrift.edge.rtl_tcp_supervisor"]
LEGACY_RTL = ["rtl_tcp", "-a", "0.0.0.0", "-d", "0"]
# Overlay version = selection_version + this. Versions 1 and 2 are the older
# format (one USB node, rtl_tcp as PID 1); they are still read so a run can
# upgrade them instead of calling them operator edits.
OVERLAY_FORMAT = 2


class SetupError(Exception):
    """An actionable failure without raw command output or credentials."""


# Tools whose output is parsed for English words ("running", "unmanaged").
C_LOCALE_TOOLS = {"nmcli", "udevadm"}
# Debian keeps these in /usr/sbin, which a non-login SSH command or a service
# often lacks in PATH (measured on a Pi: discovery reported "iw is unavailable").
# Only these names are looked up there, and only when PATH does not have them.
SYSTEM_TOOLS = {"iw", "nmcli", "udevadm"}
SYSTEM_TOOL_DIRS = ("/usr/sbin", "/sbin", "/usr/local/sbin")


def system_tool(name):
    """The path to run for a bare tool name: PATH first, then the sbin
    directories for the known system tools; the name itself otherwise."""
    if os.sep in name or name not in SYSTEM_TOOLS or shutil.which(name):
        return name
    for directory in SYSTEM_TOOL_DIRS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return name


def run(args, *, timeout=10, input=None):
    """Bound owned CLI processes, including descendants of Docker contexts."""
    process = None
    env = None
    if args and os.path.basename(args[0]) in C_LOCALE_TOOLS:
        env = os.environ | {"LC_ALL": "C"}
    try:
        process = subprocess.Popen(
            [system_tool(args[0]), *args[1:]] if args else args,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            env=env,
        )
        output, _ = process.communicate(input=input, timeout=timeout)
        if process.returncode:
            raise SetupError(f"{args[0]} probe failed; check that tool and retry.")
        return output
    except (OSError, UnicodeError) as exc:
        raise SetupError(
            f"{args[0]} is unavailable or returned invalid text. Install/check this read-only discovery tool and retry."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise SetupError(f"{args[0]} exceeded its {timeout}-second deadline.") from exc
    finally:
        if process is not None:
            # Reap first, then kill any descendant retaining the process group.
            process.poll()
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                process.poll()
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=2)


def json_command(args):
    try:
        return json.loads(run(args))
    except (ValueError, TypeError) as exc:
        raise SetupError(
            f"{args[0]} returned invalid JSON; discovery is incomplete."
        ) from exc


def native_docker():
    if platform.system() != "Linux":
        raise SetupError(
            "Automatic scanners require native Linux Docker; this host can run the dashboard."
        )
    if os.environ.get("DOCKER_CONTEXT") or not os.environ.get("DOCKER_HOST"):
        endpoint = json_command(
            [
                "docker",
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ]
        )
    else:
        endpoint = os.environ["DOCKER_HOST"]
    if not isinstance(endpoint, str) or not endpoint.startswith("unix:///"):
        raise SetupError(
            "Scanner discovery requires a local Unix Docker socket, not a remote Docker context."
        )
    info = json_command(["docker", "info", "--format", "{{json .}}"])
    if (
        not isinstance(info, dict)
        or info.get("OSType") != "linux"
        or info.get("KernelVersion") != platform.release()
        or info.get("Name") != socket.gethostname()
        or "docker desktop" in str(info.get("OperatingSystem", "")).lower()
        or any("rootless" in str(item) for item in info.get("SecurityOptions", []))
    ):
        raise SetupError(
            "Docker is not a verified native, rootful daemon on this host; hardware setup is unavailable."
        )


def read_text(path):
    try:
        return path.read_text().strip()
    except (OSError, UnicodeError) as exc:
        raise SetupError(
            "Hardware metadata is unreadable; discovery is incomplete."
        ) from exc


SHARED_GROUP = "USB group is root or shared with another device on this bus"


def shared_group(device, status):
    """True when the receiver's group would also open other nodes on its bus.

    rtl-tcp maps the whole bus directory and joins this group, so the group
    must belong to the receiver alone. Stock udev leaves USB nodes at
    root:root 0664, which would give the container every node on the bus.
    """
    if status.st_gid == 0:
        return True
    try:
        others = [item for item in device.parent.iterdir() if item != device]
        for other in others[:256]:
            try:
                node = other.lstat()
            except OSError:
                continue  # Unplugged meanwhile: it grants nothing.
            if (
                stat.S_ISCHR(node.st_mode)
                and node.st_gid == status.st_gid
                and node.st_mode & 0o060
            ):
                return True
        return len(others) > 256
    except OSError:
        return True  # An unreadable bus cannot be shown to be safe.


def rtl_devices(sysfs=Path("/sys"), dev=Path("/dev")):
    result = []
    for entry in sorted((sysfs / "bus/usb/devices").glob("*")):
        if not USB_NAME.fullmatch(entry.name) or not (entry / "idVendor").exists():
            continue
        vendor, product = read_text(entry / "idVendor"), read_text(entry / "idProduct")
        if (vendor, product) not in RTL_IDS:
            continue
        bus, number = read_text(entry / "busnum"), read_text(entry / "devnum")
        if (
            not bus.isdecimal()
            or not number.isdecimal()
            or not 1 <= int(bus) <= 999
            or not 1 <= int(number) <= 999
        ):
            raise SetupError("Invalid USB bus/device metadata; refusing SDR selection.")
        device = dev / "bus/usb" / f"{int(bus):03d}" / f"{int(number):03d}"
        reasons = []
        drivers = [item / "driver" for item in entry.parent.glob(entry.name + ":*")]
        if any(driver.is_symlink() for driver in drivers):
            reasons.append("kernel driver owns this receiver")
        try:
            status = device.lstat()
        except OSError:
            reasons.append("USB device node is unavailable")
            status = None
        if status is not None:
            if not stat.S_ISCHR(status.st_mode):
                reasons.append("USB path is not a character device")
            elif (
                f"{os.major(status.st_rdev)}:{os.minor(status.st_rdev)}"
                != read_text(entry / "dev")
                or os.major(status.st_rdev) != 189
            ):
                reasons.append(
                    "USB device node does not match the kernel device identity"
                )
            # Docker adds the device's numeric group to uid1500, without chmod.
            readable = (
                (status.st_uid == 1500 and status.st_mode & 0o600 == 0o600)
                or status.st_mode & 0o060 == 0o060
                or status.st_mode & 0o006 == 0o006
            )
            if not readable:
                reasons.append("USB permissions do not grant read/write to the scanner")
            if shared_group(device, status):
                reasons.append(SHARED_GROUP)
        serial = read_text(entry / "serial") if (entry / "serial").exists() else ""
        identity = hashlib.sha256(f"{vendor}:{product}:{serial}".encode()).hexdigest()
        result.append(
            {
                "usb": entry.name,
                "identity": identity,
                "device": str(device),
                "gid": status.st_gid if status else 0,
                "reasons": reasons,
            }
        )
    return result


def prepare_rtl(usb, *, sysfs=Path("/sys"), dev=Path("/dev")):
    """Explicit, temporary per-device preparation; never called by discovery.

    There is no atomic transaction across sysfs unbind/chown/chmod. A failure
    after unbind leaves that interface released and is reported for retry.
    prepare-rtl installs no persistent rule and unloads no system-wide driver.
    """
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise SetupError(
            "RTL preparation requires native Linux root; review the command and invoke it explicitly with sudo."
        )
    release_rtl(usb, sysfs=sysfs, dev=dev)
    print(
        f"Prepared only RTL USB {usb}: driver released where present, root:plugdev 0660. Replug/reboot can reset this; rerun quickstart --scanners=auto now. To keep it across re-plugs, see prepare-rtl --usb={usb} --print-udev-rule."
    )


def release_rtl(usb, *, sysfs=Path("/sys"), dev=Path("/dev")):
    """The device work of prepare-rtl; the caller has checked for root."""
    import grp

    if not isinstance(usb, str) or not USB_NAME.fullmatch(usb):
        raise SetupError(
            "Select one discovered USB topology name with --usb (for example 1-2)."
        )
    try:
        group = grp.getgrnam("plugdev").gr_gid
    except KeyError as exc:
        raise SetupError(
            "The plugdev group is missing. Install your distribution's rtl-sdr/udev package first; no device was changed."
        ) from exc
    candidates = [item for item in rtl_devices(sysfs, dev) if item["usb"] == usb]
    if len(candidates) != 1:
        raise SetupError(
            "The selected supported RTL receiver is no longer present; rediscover before preparing it."
        )
    selected = candidates[0]
    entry = sysfs / "bus/usb/devices" / usb
    driver_root = sysfs / "bus/usb/drivers/dvb_usb_rtl28xxu"
    interfaces = []
    for interface in sorted(entry.parent.glob(usb + ":*")):
        driver = interface / "driver"
        if driver.is_symlink():
            if driver.resolve() != driver_root.resolve():
                raise SetupError(
                    "The selected receiver has an unexpected driver; no device was changed."
                )
            if not re.fullmatch(re.escape(usb) + r":[0-9]+\.[0-9]+", interface.name):
                raise SetupError(
                    "Unexpected USB interface identity; no device was changed."
                )
            interfaces.append(interface.name)
    node = Path(selected["device"])
    # O_NOFOLLOW plus fstat keeps chmod/chown on the verified open USB node,
    # never a path substituted after validation. USB device nodes use major189.
    descriptor = os.open(node, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    changed = False
    try:
        status = os.fstat(descriptor)
        expected_device = read_text(entry / "dev")
        if (
            not stat.S_ISCHR(status.st_mode)
            or os.major(status.st_rdev) != 189
            or f"{os.major(status.st_rdev)}:{os.minor(status.st_rdev)}"
            != expected_device
            or status.st_uid != 0
        ):
            raise SetupError(
                "The selected path is not a root-owned USB character device; no device was changed."
            )
        current = [item for item in rtl_devices(sysfs, dev) if item["usb"] == usb]
        if len(current) != 1 or any(
            current[0][key] != selected[key] for key in ("identity", "device")
        ):
            raise SetupError(
                "The USB identity changed; rediscover before preparing it."
            )
        for interface in interfaces:
            # Kernel sysfs validates this exact interface token. No shell and
            # no wildcard is passed to a privileged write.
            with (driver_root / "unbind").open("w") as output:
                output.write(interface)
            changed = True
        os.fchown(descriptor, -1, group)
        changed = True
        os.fchmod(descriptor, 0o660)
    except OSError as exc:
        suffix = (
            "The interface or permissions may already have changed; inspect and retry this same scoped command."
            if changed
            else "No preparation step completed."
        )
        raise SetupError("RTL preparation failed. " + suffix) from exc
    finally:
        os.close(descriptor)


UDEV_RULES = "/etc/udev/rules.d/70-sigrift-sdr.rules"
# Only characters a udev match string never treats specially; anything else
# is refused rather than escaped.
UDEV_SAFE = re.compile(r"[A-Za-z0-9._-]{1,126}\Z")


def udev_rule(usb, *, sysfs=Path("/sys")):
    """Print-only: the persistent form of prepare-rtl for one receiver.

    Needs no root and writes nothing. The serial appears only in this local
    output so the rule cannot match a different receiver on that port.
    """
    import grp

    if not isinstance(usb, str) or not USB_NAME.fullmatch(usb):
        raise SetupError(
            "Select one discovered USB topology name with --usb (for example 1-2)."
        )
    entry = sysfs / "bus/usb/devices" / usb
    vendor = read_text(entry / "idVendor") if (entry / "idVendor").exists() else ""
    product = read_text(entry / "idProduct") if vendor else ""
    if (vendor, product) not in RTL_IDS:
        raise SetupError(
            "No supported RTL receiver is at that USB port; rediscover and retry. No rule was printed."
        )
    serial = read_text(entry / "serial") if (entry / "serial").exists() else ""
    if not UDEV_SAFE.fullmatch(serial):
        raise SetupError(
            "This receiver has no serial, or one with characters a udev rule would need escaped. "
            "No rule was printed; run prepare-rtl again after each re-plug or reboot instead."
        )
    try:
        grp.getgrnam("plugdev")
    except KeyError as exc:
        raise SetupError(
            "The plugdev group is missing. Install your distribution's rtl-sdr/udev package first; no rule was printed."
        ) from exc
    return "\n".join(
        [
            f"# SigRift: let the scanner open the RTL-SDR receiver on USB port {usb} after a re-plug or reboot.",
            "# It sets group plugdev and mode 0660 on this one receiver (port, model and serial must all match).",
            "# The scanner releases the receiver's TV driver itself when it opens it.",
            f"# Save this file as {UDEV_RULES} (as root), then load it:",
            "#   sudo udevadm control --reload-rules",
            "#   then re-plug the receiver, or run: sudo udevadm trigger --subsystem-match=usb",
            "# To undo: delete that file and run the same two commands.",
            f'SUBSYSTEM=="usb", ENV{{DEVTYPE}}=="usb_device", KERNEL=="{usb}", '
            f'ATTR{{idVendor}}=="{vendor}", ATTR{{idProduct}}=="{product}", '
            f'ATTR{{serial}}=="{serial}", GROUP="plugdev", MODE="0660"',
        ]
    )


# ── Host preparation: one reviewed root step ─────────────────────────
#
# `prepare` does what a new host otherwise needs by hand: prepare-rtl, the
# udev rule above, and keeping NetworkManager off the spare Wi-Fi adapter.
# It targets only devices discovery found and would select once prepared,
# never a protected radio, and writes only files that carry its marker.

# Whether a spare Wi-Fi adapter that NetworkManager manages can be selected.
# "warn": it stays selectable; plan prints a note and `prepare` releases it.
# "require": it is reported as needing preparation and is not selected until
# `prepare` has released it. Measured on a Pi: when NetworkManager took the
# adapter during capture, capture stopped for about 17 seconds ("Ending capture
# round: wlan1 left monitor mode"), the scanner re-applied monitor mode and
# resumed by itself, and the next 56 minutes ran undisturbed with
# NetworkManager still managing it (releasing it again cost one more pause of
# about 15 seconds). So preparation is recommended, not
# required, and the policy stays "warn"; switching is this one line.
NM_MANAGED_POLICY = "warn"
NM_MANAGED = "NetworkManager manages this adapter"
# The plan's note line for such an adapter under "warn".
NM_NOTE = (
    NM_MANAGED + "; when it takes the adapter, capture pauses (about 17 seconds "
    "when measured) and resumes by itself. scanner_setup.py prepare stops that "
    "(recommended, not required)"
)
# NetworkManager device states in which the adapter is idle. Any other state
# (connecting, connected, deactivating, ...) means it may be in use, and the
# user releases it on purpose before `prepare` touches it.
NM_PREPARABLE = {"unmanaged", "disconnected", "unavailable"}
NM_DROPIN = "/etc/NetworkManager/conf.d/90-sigrift-scanner.conf"
NM_MARKER = "# Managed by scripts/scanner_setup.py prepare"
# The first line udev_rule prints; a file starting with it is this tool's.
UDEV_MARKER = "# SigRift: let the scanner open the RTL-SDR receiver on USB port "
PREPARE_COMMAND = "sudo python3 scripts/scanner_setup.py prepare"
UNPREPARE_COMMAND = "sudo python3 scripts/scanner_setup.py unprepare"
# Discovery reasons that release_rtl fixes. A receiver with any other reason
# is left alone.
SDR_FIXABLE = {
    "kernel driver owns this receiver",
    "USB permissions do not grant read/write to the scanner",
    SHARED_GROUP,
}
# The two commands the udev rule's own comment lines document.
UDEV_COMMANDS = (
    ("udevadm", "control", "--reload-rules"),
    ("udevadm", "trigger", "--subsystem-match=usb"),
)
NM_RELOAD = ("nmcli", "general", "reload")
HOST_COMMAND_TIMEOUT = 60


def native_root():
    return platform.system() == "Linux" and os.geteuid() == 0


def under(etc, path):
    """A fixed /etc path, below an injectable root for tests."""
    return Path(etc) / Path(path).relative_to("/etc")


def nm_device_states(runner=None):
    """Read-only: {device: state} while NetworkManager runs, else None.

    No nmcli, or NetworkManager not running, both mean there is nothing for
    host preparation to do about it.
    """
    runner = runner or run
    try:
        if runner(["nmcli", "-t", "-f", "RUNNING", "general"]).strip() != "running":
            return None
        output = runner(["nmcli", "-t", "-f", "DEVICE,STATE", "device"])
    except SetupError:
        return None
    states = {}
    for line in output.splitlines():
        # Terse output escapes ':' in a name as '\:', which NAME never matches.
        name, separator, state = line.partition(":")
        if separator and NAME.fullmatch(name):
            states[name] = state.strip()
    return states


def nm_manages(states, interface):
    return states is not None and states.get(interface, "unmanaged") != "unmanaged"


def annotate_network_manager(items, runner=None):
    """Mark otherwise-ready Wi-Fi adapters that NetworkManager manages.

    Protected or otherwise unready adapters are left as they are: they are
    never prepared, so a note about them would only be noise.
    """
    if NM_MANAGED_POLICY not in ("warn", "require"):
        raise SetupError("NM_MANAGED_POLICY must be 'warn' or 'require'.")
    candidates = [item for item in items if not item["reasons"]]
    if not candidates:
        return
    states = nm_device_states(runner)
    for item in candidates:
        if nm_manages(states, item["interface"]):
            if NM_MANAGED_POLICY == "require":
                item["reasons"].append(NM_MANAGED)
            else:
                item.setdefault("notes", []).append(NM_MANAGED)


def nm_dropin_text(interface, address):
    return (
        f"{NM_MARKER} for Wi-Fi adapter {interface} (permanent address {address}).\n"
        "# NetworkManager leaves this one adapter alone so the SigRift Wi-Fi scanner can use it.\n"
        f"# To undo: {UNPREPARE_COMMAND}\n"
        "[keyfile]\n"
        # += adds to an unmanaged-devices list set elsewhere instead of
        # replacing it, so other adapters the operator excluded stay excluded.
        # Tried on NetworkManager on Debian 13 (a Raspberry Pi): after "nmcli general
        # reload" the effective configuration listed the adapter and it became
        # unmanaged without any runtime command. verify_persistent still
        # checks this on every host.
        f"unmanaged-devices+=mac:{address}\n"
    )


def read_address(path):
    try:
        return path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError):
        return None


def wifi_address_is_unique(sysfs, phy, address):
    """True when no other radio or network device carries this address."""
    try:
        wiphy = (sysfs / "class/ieee80211" / phy).resolve(strict=True)
        for other in sorted((sysfs / "class/ieee80211").iterdir())[:256]:
            if other.name != phy and read_address(other / "macaddress") == address:
                return False
        net = sysfs / "class/net"
        for entry in sorted(net.iterdir())[:1024] if net.is_dir() else []:
            link = entry / "phy80211"
            if link.exists() and link.resolve() == wiphy:
                continue  # This radio's own interfaces.
            if read_address(entry / "address") == address:
                return False
    except (OSError, RuntimeError):
        return False
    return True


def owned_file_state(path, text, classify):
    """'absent', 'same', 'ours', 'other' (ours, another device) or 'foreign'."""
    if not path.is_symlink() and not path.exists():
        return "absent"
    if path.is_symlink() or not path.is_file():
        return "foreign"
    try:
        current = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return "foreign"
    return "same" if current == text else classify(current)


def udev_classifier(text):
    rule = text.rstrip("\n").splitlines()[-1]

    def classify(current):
        lines = current.splitlines()
        if not lines or not lines[0].startswith(UDEV_MARKER):
            return "foreign"
        rules = [line for line in lines if line.strip() and not line.startswith("#")]
        return "ours" if rules == [rule] else "other"

    return classify


def nm_classifier(address):
    entry = f"unmanaged-devices+=mac:{address}"

    def classify(current):
        lines = current.splitlines()
        if not lines or not lines[0].startswith(NM_MARKER):
            return "foreign"
        entries = [line for line in lines if line.startswith("unmanaged-devices")]
        return "ours" if entries == [entry] else "other"

    return classify


def refuse_existing(path, state, what):
    if state == "other":
        raise SetupError(
            f"{path} holds SigRift settings for a different {what}; it is left untouched. "
            f"If that {what} is gone, run {UNPREPARE_COMMAND} first. Nothing was changed."
        )
    raise SetupError(
        f"{path} already exists and was not written by this tool; it is left untouched. "
        "Review it and move it aside, then run prepare again. Nothing was changed."
    )


def receiver_steps(item, prep, *, sysfs, etc, named=False):
    port = item["usb"]
    blocking = [reason for reason in item["reasons"] if reason not in SDR_FIXABLE]
    if blocking:
        if named:
            raise SetupError(
                f"Receiver {port} is not prepared: "
                + "; ".join(blocking)
                + ". Nothing was changed."
            )
        prep["skipped"].append(f"receiver {port}: " + "; ".join(blocking))
        return
    target = ("usb", port)
    if item["reasons"]:
        prep["steps"].append(
            {
                "action": "release",
                "target": target,
                "usb": port,
                "label": f"Receiver {port}: release its TV driver and set root:plugdev 0660 on "
                f"{item['device']} (what prepare-rtl --usb={port} does)",
            }
        )
    else:
        prep["in_place"].append(f"receiver {port}: the scanner can open it")
    try:
        text = udev_rule(port, sysfs=sysfs) + "\n"
    except SetupError as exc:
        prep["skipped"].append(f"receiver {port}: no persistent udev rule. {exc}")
        return
    path = under(etc, UDEV_RULES)
    classify = udev_classifier(text)
    state = owned_file_state(path, text, classify)
    if state in ("foreign", "other"):
        refuse_existing(path, state, "receiver")
    if state == "same":
        prep["in_place"].append(f"receiver {port}: udev rule {path}")
        return
    prep["steps"].append(
        {
            "action": "write",
            "target": target,
            "path": path,
            "text": text,
            "classify": classify,
            "what": "receiver",
            "label": f"Receiver {port}: write {path} (root:root 0644), the rule "
            f"prepare-rtl --usb={port} --print-udev-rule prints",
        }
    )
    for argv in UDEV_COMMANDS:
        prep["steps"].append(
            {
                "action": "run",
                "target": target,
                "argv": list(argv),
                "label": "Run: " + " ".join(argv),
            }
        )


def adapter_steps(item, prep, *, sysfs, etc, runner):
    """Keep NetworkManager off one spare adapter, decided by persistent state.

    Whether the drop-in is needed depends on the file, not on the adapter's
    runtime state: an adapter that is unmanaged only because someone ran
    "nmcli device set <if> managed no" goes back to NetworkManager at the
    next reboot, so it still gets the drop-in.
    """
    name = item["interface"]
    states = nm_device_states(runner)
    if states is None:
        prep["in_place"].append(f"Wi-Fi {name}: NetworkManager is not running")
        return
    state = states.get(name)
    if state is None:
        prep["in_place"].append(f"Wi-Fi {name}: NetworkManager does not know it")
        return
    if state not in NM_PREPARABLE:
        raise SetupError(
            f"Wi-Fi {name}: NetworkManager reports it as '{state}', so it may be in use. "
            f"Release it on purpose first (for example: sudo nmcli device disconnect {name}), "
            "or prepare only the receiver with --scanners=sdr. Nothing was changed."
        )
    _, address = wifi_hardware(sysfs, name, item["phy"])
    if not wifi_address_is_unique(sysfs, item["phy"], address):
        raise SetupError(
            f"Wi-Fi {name}: its permanent address is also used by another network device, "
            "so a NetworkManager setting for it could match another adapter. Nothing was changed."
        )
    text = nm_dropin_text(name, address)
    path = under(etc, NM_DROPIN)
    classify = nm_classifier(address)
    file_state = owned_file_state(path, text, classify)
    if file_state in ("foreign", "other"):
        refuse_existing(path, file_state, "Wi-Fi adapter")
    if file_state == "same" and state == "unmanaged":
        prep["in_place"].append(f"Wi-Fi {name}: {path}")
        return
    target = ("wifi-interface", name)
    if file_state != "same":
        prep["steps"].append(
            {
                "action": "write",
                "target": target,
                "path": path,
                "text": text,
                "classify": classify,
                "what": "Wi-Fi adapter",
                "label": f"Wi-Fi {name}: write {path} (root:root 0644)",
            }
        )
    # Also when the file is in place but NetworkManager manages the adapter
    # again (after a reboot): the check below then reports that the file
    # does not work instead of calling it in place.
    argv = " ".join(("nmcli", "device", "set", name, "managed", "no"))
    prep["steps"] += [
        {
            "action": "run",
            "target": target,
            "argv": list(NM_RELOAD),
            "label": "Run: " + " ".join(NM_RELOAD),
        },
        {
            "action": "persist",
            "target": target,
            "interface": name,
            "path": path,
            "label": f"Check: nmcli -t -f DEVICE,STATE device shows {name} unmanaged "
            f"after the reload; if not, run {argv} for now and report that "
            "the persistent setting did not take effect",
        },
    ]


def host_preparation(
    discovery,
    *,
    kinds=("sdr", "wifi"),
    usb=None,
    wifi_interface=None,
    sysfs=Path("/sys"),
    etc=Path("/etc"),
    runner=None,
    wifi_needs_name=False,
):
    """Read-only: the ordered steps `prepare` would take on this host.

    Refusals (a file someone else wrote, a named device that is missing or
    not eligible) are raised here, before any step runs. wifi_needs_name:
    the SSH client route could not be checked, so a Wi-Fi adapter is
    prepared only when --wifi-interface names it.
    """
    prep = {"steps": [], "in_place": [], "skipped": []}
    if "sdr" in kinds:
        candidates = discovery["sdr"]
        if usb:
            candidates = [item for item in candidates if item["usb"] == usb]
            if not candidates:
                raise SetupError(
                    f"No supported RTL receiver was discovered at USB port {usb}; nothing was changed."
                )
        if len(candidates) > 1:
            prep["skipped"].append(
                "receivers: several are connected; choose one with --usb=<port> ("
                + ", ".join(item["usb"] for item in candidates)
                + ")"
            )
        elif candidates:
            receiver_steps(candidates[0], prep, sysfs=sysfs, etc=etc, named=bool(usb))
    if "wifi" in kinds:
        candidates = discovery["wifi"]
        if wifi_interface:
            candidates = [
                item for item in candidates if item["interface"] == wifi_interface
            ]
            if not candidates:
                raise SetupError(
                    f"Wi-Fi interface {wifi_interface} was not discovered; nothing was changed."
                )
        eligible = [
            item
            for item in candidates
            if all(reason == NM_MANAGED for reason in item["reasons"])
        ]
        if wifi_interface and not eligible:
            raise SetupError(
                f"Wi-Fi interface {wifi_interface} is not prepared: "
                + "; ".join(candidates[0]["reasons"])
                + ". Nothing was changed."
            )
        if len(eligible) > 1:
            prep["skipped"].append(
                "Wi-Fi: several adapters are ready; choose one with --wifi-interface=<name> ("
                + ", ".join(item["interface"] for item in eligible)
                + ")"
            )
        elif eligible and wifi_needs_name and not wifi_interface:
            prep["skipped"].append(
                f"Wi-Fi {eligible[0]['interface']}: this runs under sudo, which removed "
                "SSH_CONNECTION, so it cannot tell whether you are logged in over SSH "
                "or which adapter carries that session. Name the spare adapter "
                "explicitly with --wifi-interface=<name> (quickstart does this for you)"
            )
        elif eligible:
            adapter_steps(eligible[0], prep, sysfs=sysfs, etc=etc, runner=runner)
    for reason in discovery.get("reasons", []):
        if not reason.startswith("Bluetooth"):
            prep["skipped"].append("discovery: " + reason)
    return prep


def install_file(path, text, classify, what, *, owner=(0, 0)):
    """Atomically write one root:root 0644 file, re-checking the path first."""
    state = owned_file_state(path, text, classify)
    if state in ("foreign", "other"):
        refuse_existing(path, state, what)
    if state == "same":
        return
    path.parent.mkdir(mode=0o755, exist_ok=True)
    # The temporary name does not end in .rules/.conf, so neither udev nor
    # NetworkManager reads a partial file.
    descriptor, temporary = tempfile.mkstemp(
        prefix="." + path.name + ".", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        if owner is not None:
            os.chown(temporary, *owner)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def becomes_unmanaged(interface, runner, sleep, attempts=5):
    for attempt in range(attempts):
        if (nm_device_states(runner) or {}).get(interface) == "unmanaged":
            return True
        if attempt + 1 < attempts:
            sleep(1)
    return False


def verify_persistent(interface, path, runner, sleep):
    """After the reload: did the drop-in itself make the adapter unmanaged?

    Checked before any runtime "managed no", so a file NetworkManager ignores
    is reported instead of hidden. The adapter is then still released for
    now, and prepare exits non-zero.
    """
    if becomes_unmanaged(interface, runner, sleep):
        return
    runner(
        ["nmcli", "device", "set", interface, "managed", "no"],
        timeout=HOST_COMMAND_TIMEOUT,
    )
    if not becomes_unmanaged(interface, runner, sleep):
        raise SetupError(
            f"NetworkManager still manages {interface}; it did not become unmanaged."
        )
    raise SetupError(
        f"The persistent setting in {path} did not take effect: NetworkManager still "
        f"managed {interface} after nmcli general reload. {interface} is unmanaged now "
        f"(nmcli device set {interface} managed no), but only until the next reboot or "
        "NetworkManager restart. Check that NetworkManager reads that file "
        "(NetworkManager --print-config) and matches the adapter's permanent address."
    )


def apply_preparation(prep, *, runner, release, sysfs, dev, owner, sleep):
    done = []
    for step in prep["steps"]:
        try:
            if step["action"] == "release":
                release(step["usb"], sysfs=sysfs, dev=dev)
            elif step["action"] == "write":
                install_file(
                    step["path"],
                    step["text"],
                    step["classify"],
                    step["what"],
                    owner=owner,
                )
            elif step["action"] == "run":
                runner(step["argv"], timeout=HOST_COMMAND_TIMEOUT)
            else:
                verify_persistent(step["interface"], step["path"], runner, sleep)
        except (SetupError, OSError) as exc:
            detail = (
                str(exc)
                if isinstance(exc, SetupError)
                else (exc.strerror or type(exc).__name__) + "."
            )
            raise SetupError(
                f"Host preparation stopped at: {step['label']}. {detail} "
                f"Completed before it: {'; '.join(done) or 'nothing'}. "
                f"Fix the problem and run prepare again (it skips what is in place), or undo with {UNPREPARE_COMMAND}."
            ) from exc
        done.append(step["label"])
    return done


def print_preparation(prep, *, done=None):
    """The review (done is None) or the summary after applying."""
    if done is None:
        if prep["steps"]:
            print(
                "Host preparation, in order (--print changed nothing; "
                f"run {PREPARE_COMMAND} to apply):"
            )
        for number, step in enumerate(prep["steps"], 1):
            print(f"  {number}. {step['label']}")
            if step["action"] == "write":
                print(f"----- {step['path']} -----")
                print(step["text"], end="")
                print("----- end -----")
    elif done:
        print("Host preparation changed:")
        for label in done:
            print("  - " + label)
    if not prep["steps"]:
        print("Host preparation: nothing to change.")
    for line in prep["in_place"]:
        print("  Already in place: " + line)
    for line in prep["skipped"]:
        print("  Not prepared: " + line)
    print(f"Undo with: {UNPREPARE_COMMAND}")


def prepare_kinds(root, scanners):
    if scanners in (None, "auto"):
        return ("sdr", "wifi")
    if scanners == "none":
        return ()
    if scanners == "saved":
        wanted = pending_selection(root)
        return tuple(
            sorted(wanted if wanted is not None else saved_selection(root) or {})
        )
    kinds = set(scanners.split(","))
    if not kinds <= set(SCANNERS) or "" in kinds:
        raise SetupError("Choose --scanners=auto, none, sdr, wifi or sdr,wifi.")
    return tuple(sorted(kinds))


def prepare_command(request, wifi_interface=None):
    command = PREPARE_COMMAND
    if request not in (None, "auto"):
        command += f" --scanners={request}"
    if wifi_interface:
        command += f" --wifi-interface={wifi_interface}"
    return command


def prepare(
    root,
    *,
    scanners=None,
    usb=None,
    wifi_interface=None,
    mode="apply",
    honor_profiles=False,
    sysfs=Path("/sys"),
    dev=Path("/dev"),
    etc=Path("/etc"),
    runner=None,
    is_root=None,
    release=None,
    owner=(0, 0),
    sleep=time.sleep,
    ssh_client=None,
):
    """Prepare this host for the scanners discovery finds, in one root step.

    mode "print" reviews every file and command and changes nothing; "check"
    prints needed/not-needed for quickstart, and after "needed" one
    "usb=<port>" or "wifi-interface=<name>" line per target, which quickstart
    passes to the root run so it acts on exactly what was reviewed; "apply"
    needs root. ssh_client is the SSH client address quickstart passes on
    because sudo drops SSH_CONNECTION; it only protects more interfaces.
    """
    runner = runner or run
    if mode == "apply" and not (is_root or native_root)():
        raise SetupError(
            "Host preparation changes system files and needs root. Review it first with: "
            f"python3 scripts/scanner_setup.py prepare --print, then run: {PREPARE_COMMAND}"
        )
    kinds = prepare_kinds(root, scanners)
    if honor_profiles and scanners in (None, "auto") and hardware_disabled(root):
        kinds = ()
    discovery = (
        managed_discovery(root, extra_ssh_clients=(ssh_client,) if ssh_client else ())
        if kinds
        else {"sdr": [], "wifi": [], "reasons": []}
    )
    prep = host_preparation(
        discovery,
        kinds=kinds,
        usb=usb,
        wifi_interface=wifi_interface,
        sysfs=sysfs,
        etc=etc,
        runner=runner,
        wifi_needs_name=ssh_route_unknown(ssh_client),
    )
    if mode == "check":
        if not prep["steps"]:
            print("not-needed")
            return
        print("needed")
        targets = []
        for step in prep["steps"]:
            if step["target"] not in targets:
                targets.append(step["target"])
        for key, value in targets:
            print(f"{key}={value}")
        return
    if mode == "print" or not prep["steps"]:
        print_preparation(prep)
        return
    done = apply_preparation(
        prep,
        runner=runner,
        release=release or release_rtl,
        sysfs=sysfs,
        dev=dev,
        owner=owner,
        sleep=sleep,
    )
    print_preparation(prep, done=done)


def ssh_route_unknown(ssh_client):
    """True under sudo when nothing says whether the user came in over SSH.

    sudo's env_reset removes SSH_CONNECTION but leaves SUDO_*; without an
    explicit --ssh-client the route back to an SSH client cannot be checked.
    """
    if os.environ.get("SSH_CONNECTION") or ssh_client:
        return False
    return any(
        os.environ.get(name) for name in ("SUDO_USER", "SUDO_UID", "SUDO_COMMAND")
    )


def marked(path, marker):
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open(encoding="utf-8") as stream:
            return stream.readline().startswith(marker)
    except (OSError, UnicodeError):
        return False


def unprepare(*, mode="apply", etc=Path("/etc"), runner=None, is_root=None):
    """Remove only the files `prepare` wrote (they carry its marker)."""
    runner = runner or run
    if mode == "apply" and not (is_root or native_root)():
        raise SetupError(
            "Undoing host preparation changes system files and needs root. Review it first with: "
            f"python3 scripts/scanner_setup.py unprepare --print, then run: {UNPREPARE_COMMAND}"
        )
    removed, kept = [], []
    for path, marker in (
        (under(etc, UDEV_RULES), UDEV_MARKER),
        (under(etc, NM_DROPIN), NM_MARKER),
    ):
        if path.exists() or path.is_symlink():
            (removed if marked(path, marker) else kept).append(path)
    udev = under(etc, UDEV_RULES) in removed
    network_manager = under(etc, NM_DROPIN) in removed
    commands = list(UDEV_COMMANDS) if udev else []
    if network_manager and nm_device_states(runner) is not None:
        commands.append(NM_RELOAD)
    if mode == "print":
        for path in removed:
            print(f"Would remove: {path}")
        for argv in commands:
            print("Would run: " + " ".join(argv))
    else:
        for path in removed:
            path.unlink()
            print(f"Removed: {path}")
        for argv in commands:
            runner(list(argv), timeout=HOST_COMMAND_TIMEOUT)
            print("Ran: " + " ".join(argv))
    for path in kept:
        print(f"Left untouched (not written by this tool): {path}")
    if not removed:
        print(
            "Nothing to undo: no file written by scanner_setup.py prepare is installed."
        )
    if udev:
        print(
            "The receiver keeps its current permissions until it is re-plugged or the host "
            "reboots; then it returns to the default (root:root 0664, TV driver bound)."
        )
    if network_manager:
        print(
            "NetworkManager manages the Wi-Fi adapter again (on a Raspberry Pi it took it "
            "back right after the reload). The Wi-Fi scanner keeps running; its capture "
            "pauses briefly whenever NetworkManager takes the adapter."
        )


def route_devices(routes):
    if not isinstance(routes, list):
        raise SetupError("Cannot verify routes; Wi-Fi selection is blocked.")
    devices = set()
    for route in routes:
        if not isinstance(route, dict):
            raise SetupError("Cannot verify routes; Wi-Fi selection is blocked.")
        if route.get("dev"):
            devices.add(route["dev"])
        for hop in route.get("nexthops", []):
            if not isinstance(hop, dict) or not isinstance(hop.get("dev"), str):
                raise SetupError(
                    "Cannot verify multipath route; Wi-Fi selection is blocked."
                )
            devices.add(hop["dev"])
    return devices


def wifi_identity(sysfs, interface, phy):
    """Bind a radio to its permanent address and physical path, not its PHY index.

    Linux exposes wiphy.perm_addr as ieee80211/<phy>/macaddress. Interface
    addresses may be randomized. Physical topology is deliberately included:
    moving a USB adapter to another port requires explicit reselection.
    """
    topology, address = wifi_hardware(sysfs, interface, phy)
    encoded = json.dumps(
        ["sigrift-wifi-identity-v1", topology, address],
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def wifi_hardware(sysfs, interface, phy):
    """(physical topology, permanent address) of one radio, read twice."""
    try:
        base = (sysfs / "devices").resolve(strict=True)
        wiphy = (sysfs / "class/ieee80211" / phy).resolve(strict=True)
        device = (wiphy / "device").resolve(strict=True)
        interface_phy = (sysfs / "class/net" / interface / "phy80211").resolve(
            strict=True
        )
        topology = device.relative_to(base)
        if (
            interface_phy != wiphy
            or not device.is_dir()
            or not topology.parts
            or not wiphy.is_relative_to(device)
        ):
            raise ValueError
        address = (wiphy / "macaddress").read_text(encoding="ascii").strip().lower()
        if (
            not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", address)
            or address == "00:00:00:00:00:00"
            or int(address[:2], 16) & 1
        ):
            raise ValueError
        # A disconnect during discovery must not combine two devices' metadata.
        if (
            (sysfs / "class/ieee80211" / phy).resolve(strict=True) != wiphy
            or (sysfs / "class/net" / interface / "phy80211").resolve(strict=True)
            != wiphy
            or (wiphy / "device").resolve(strict=True) != device
            or (wiphy / "macaddress").read_text(encoding="ascii").strip().lower()
            != address
        ):
            raise ValueError
        return topology.as_posix(), address
    except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
        raise SetupError("Permanent Wi-Fi hardware identity is unavailable.") from exc


def matching_devices(kind, candidates, previous):
    """Match only verified saved identity; a PHY label is current routing data."""
    saved = previous[kind]
    if kind == "wifi" and "identity" not in saved:
        choices = ",".join(sorted(previous))
        raise SetupError(
            "The saved Wi-Fi choice needs hardware verification. Review the adapter "
            "and reselect explicitly with: bash scripts/quickstart.sh "
            f"--scanners={choices} --wifi-interface={saved['interface']}. "
            "Existing choices and configuration are preserved."
        )
    if kind == "wifi":
        candidates = [
            item for item in candidates if item["interface"] == saved["interface"]
        ]
        if any("identity" not in item for item in candidates):
            raise SetupError(
                "Selected Wi-Fi hardware identity is unavailable; check the adapter and retry."
            )
        fields = ("interface", "identity")
    else:
        fields = ("usb", "identity")
    matches = [
        item for item in candidates if all(item[key] == saved[key] for key in fields)
    ]
    if len(matches) > 1:
        raise SetupError(f"Selected {kind} hardware identity is ambiguous.")
    return matches


def wifi_devices(sysfs=Path("/sys"), *, extra_ssh_clients=()):
    # Protect every routed or addressed interface, plus the route back to SSH.
    # Taking a sibling virtual interface down can affect the same physical radio.
    # extra_ssh_clients (prepare --ssh-client, passed on by quickstart because
    # sudo drops SSH_CONNECTION) only ever adds protected interfaces.
    protected = set()
    for family in ("-4", "-6"):
        protected |= route_devices(
            json_command(["ip", "-j", family, "route", "show", "table", "all"])
        )
    addresses = json_command(["ip", "-j", "address", "show"])
    if not isinstance(addresses, list):
        raise SetupError(
            "Cannot verify interface addresses; Wi-Fi selection is blocked."
        )
    for entry in addresses:
        if not isinstance(entry, dict) or not isinstance(entry.get("addr_info"), list):
            raise SetupError(
                "Cannot verify interface addresses; Wi-Fi selection is blocked."
            )
        if any(item.get("scope") != "host" for item in entry["addr_info"]):
            protected.add(entry.get("ifname"))
    clients = []
    if os.environ.get("SSH_CONNECTION"):
        parts = os.environ["SSH_CONNECTION"].split()
        try:
            if len(parts) != 4:
                raise ValueError
            clients.append(ipaddress.ip_address(parts[0]))
        except ValueError as exc:
            raise SetupError(
                "Cannot identify the SSH client route; Wi-Fi selection is blocked."
            ) from exc
    for extra in extra_ssh_clients:
        try:
            client = ipaddress.ip_address(extra)
        except ValueError as exc:
            raise SetupError(
                "Cannot identify the SSH client route; Wi-Fi selection is blocked."
            ) from exc
        if client not in clients:
            clients.append(client)
    for client in clients:
        back = route_devices(json_command(["ip", "-j", "route", "get", str(client)]))
        if not back:
            raise SetupError(
                "Cannot identify the SSH client interface; Wi-Fi selection is blocked."
            )
        protected |= back
    interfaces = []
    types = {}
    protected_phys = set()
    phy = None
    interface = None
    unnamed = False
    type_seen = False
    for line in run(["iw", "dev"]).splitlines():
        line = line.strip()
        if match := re.fullmatch(r"phy#([0-9]+)", line):
            phy = "phy" + match[1]
            interface = None
            unnamed = type_seen = False
        elif match := re.fullmatch(r"Interface (\S+)", line):
            if (
                phy is None
                or not NAME.fullmatch(match[1])
                or any(name == match[1] for name, _ in interfaces)
            ):
                raise SetupError(
                    "Unrecognized Wi-Fi interface metadata; refusing selection."
                )
            interface = match[1]
            unnamed = type_seen = False
            interfaces.append((interface, phy))
        elif line == "Unnamed/non-netdev interface":
            if phy is None:
                raise SetupError(
                    "Unrecognized Wi-Fi interface metadata; refusing selection."
                )
            # iw emits this instead of Interface for devices without IFNAME.
            # They still belong to this radio, even if type metadata is absent.
            interface = None
            unnamed, type_seen = True, False
            protected_phys.add(phy)
        elif match := re.fullmatch(r"type (\S+)", line):
            if phy is None or (interface is None and not unnamed) or type_seen:
                raise SetupError(
                    "Unrecognized Wi-Fi interface metadata; refusing selection."
                )
            type_seen = True
            if interface:
                types[interface] = match[1]
        elif line.startswith(("phy#", "Interface", "Unnamed/non-netdev", "type")):
            raise SetupError(
                "Unrecognized Wi-Fi interface metadata; refusing selection."
            )
    protected_phys |= {phy for name, phy in interfaces if name in protected}
    for name, phy in interfaces:
        if types.get(name) == "managed":
            if run(["iw", "dev", name, "link"]).strip() != "Not connected.":
                protected_phys.add(phy)
        elif types.get(name) != "monitor":
            # AP/P2P/mesh siblings can carry another interface's traffic.
            protected_phys.add(phy)
    result = []
    for name, phy in interfaces:
        reasons = []
        if phy in protected_phys:
            reasons.append(
                "radio carries SSH, routed/addressed traffic or an active/unknown sibling"
            )
        info = run(["iw", "phy", phy, "info"])
        modes = info.partition("Supported interface modes:")[2].split("Band ", 1)[0]
        if not re.search(r"^\s*\* monitor\s*$", modes, re.M):
            reasons.append("driver does not advertise monitor mode")
        for flag in (sysfs / "class/ieee80211" / phy).glob("rfkill*/[hs]*"):
            if flag.name in {"hard", "soft"} and read_text(flag) != "0":
                reasons.append("radio is blocked by rfkill")
        item = {"interface": name, "phy": phy, "reasons": reasons}
        try:
            item["identity"] = wifi_identity(sysfs, name, phy)
        except SetupError:
            reasons.append("permanent Wi-Fi hardware identity is unavailable")
        result.append(item)
    return result


def discover(*, extra_ssh_clients=()):
    reasons = [
        "Bluetooth is not enabled automatically; its readiness probe is not yet implemented."
    ]
    try:
        native_docker()
    except SetupError as exc:
        return {"sdr": [], "wifi": [], "reasons": reasons + [str(exc)]}
    found = {}
    wifi_probe = wifi_devices
    if extra_ssh_clients:

        def wifi_probe():
            return wifi_devices(extra_ssh_clients=extra_ssh_clients)

    for kind, probe in (("sdr", rtl_devices), ("wifi", wifi_probe)):
        try:
            found[kind] = probe()
        except SetupError as exc:
            found[kind] = []
            reasons.append(f"{kind}: {exc}")
    annotate_network_manager(found["wifi"])
    return found | {"reasons": reasons}


def selection_from(discovery, request, previous=None, wifi_interface=None):
    wanted = (
        {"sdr", "wifi"}
        if request == "auto"
        else set()
        if request == "none"
        else set(request.split(","))
    )
    if not wanted <= set(SCANNERS) or "" in wanted:
        raise SetupError("Choose --scanners=auto, none, sdr, wifi or sdr,wifi.")
    selected = {}
    for kind in sorted(wanted):
        candidates = discovery[kind]
        if kind == "wifi" and wifi_interface:
            candidates = [
                item for item in candidates if item["interface"] == wifi_interface
            ]
        if previous and kind in previous:
            candidates = matching_devices(kind, candidates, previous)
        ready = [item for item in candidates if not item["reasons"]]
        # Multiple RTL receivers are not guessed by unstable librtlsdr index.
        ambiguous = len(discovery[kind]) > 1 if kind == "sdr" else len(ready) > 1
        if len(ready) == 1 and not ambiguous:
            selected[kind] = {
                key: value
                for key, value in ready[0].items()
                if key not in ("reasons", "notes")
            }
        elif request != "auto" or previous:
            detail = "; ".join(
                reason for item in candidates for reason in item["reasons"]
            )
            # Unattended check/start also lands here, where no plan output
            # has printed the preparation command yet.
            for item in candidates:
                if SHARED_GROUP in item["reasons"]:
                    detail += (
                        ". Give this receiver its own group: sudo python3 "
                        f"scripts/scanner_setup.py prepare-rtl --usb={item['usb']}"
                    )
            if not candidates:
                detail = "; ".join(discovery.get("reasons", []))
                if previous and kind in previous:
                    detail = swapped(kind, discovery[kind], previous) or detail
            message = f"Selected {kind} is unavailable or ambiguous. {detail or 'Check connected devices and rerun discovery.'}"
            if kind == "sdr":
                for item in candidates:
                    if item["reasons"] and set(item["reasons"]) <= SDR_FIXABLE:
                        message += (
                            ". Or prepare this host in one step (add --print to review): "
                            f"{PREPARE_COMMAND} --scanners=sdr --usb={item['usb']}"
                        )
            raise SetupError(message)
    return selected


def swapped(kind, discovered, previous):
    """Name a replaced device by its port or interface, never by its identity."""
    saved = previous[kind]
    key = "usb" if kind == "sdr" else "interface"
    if not any(
        item.get(key) == saved[key] and item.get("identity") != saved["identity"]
        for item in discovered
    ):
        return None
    where = f"USB port {saved[key]}" if kind == "sdr" else f"interface {saved[key]}"
    choices = ",".join(sorted(previous))
    command = f"bash scripts/quickstart.sh --scanners={choices}"
    if "wifi" in previous:
        command += f" --wifi-interface={previous['wifi']['interface']}"
    return (
        f"A different {kind} device is now at the saved {where}; it is not used "
        f"automatically. To use the new hardware, re-run: {command}"
    )


def render(selection):
    return render_format(selection, legacy=False)


def render_format(selection, *, legacy):
    # !override requires Compose >=2.24.4; actual config validation below is
    # authoritative. It replaces the broad legacy USB mount instead of merging.
    # legacy=True reproduces the previous format byte for byte, only so that
    # saved_overlay can recognise it; nothing writes it any more.
    version = selection_version(selection) + (0 if legacy else OVERLAY_FORMAT)
    metadata = {"version": version, "selection": selection}
    lines = [
        HEADER.rstrip(),
        "x-sigrift-scanner-setup: " + json.dumps(metadata, sort_keys=True),
        "services:",
    ]
    for service in ("rtl-tcp", "scan", "wifi-scan", "bt-scan"):
        lines += [f"  {service}:", "    profiles: !override [hardware]"]
        if service == "rtl-tcp" and "sdr" in selection and legacy:
            device = selection["sdr"]["device"]
            lines += [
                "    devices: !override " + json.dumps([f"{device}:{device}:rw"]),
                "    group_add: !override "
                + json.dumps([str(selection["sdr"]["gid"])]),
                "    command: " + json.dumps(LEGACY_RTL),
            ]
        elif service == "rtl-tcp" and "sdr" in selection:
            # Trade-off, stated plainly: the container now sees every device
            # node on the receiver's one USB bus, where it saw exactly one
            # node before. Access to the other devices on that bus is still
            # limited by their own node permissions (and the numeric group
            # below). This is far narrower than the legacy whole-/dev/bus/usb
            # mapping. It is what lets a re-plugged receiver, which gets a new
            # device number on the same bus, come back without an operator:
            # Docker re-reads a directory mapping on restart, but leaves the
            # container exited for good when a single mapped node vanished.
            bus = str(Path(selection["sdr"]["device"]).parent)
            lines += [
                "    devices: !override " + json.dumps([f"{bus}:{bus}:rw"]),
                "    group_add: !override "
                + json.dumps([str(selection["sdr"]["gid"])]),
                "    command: " + json.dumps(SUPERVISOR),
                "    environment:",
                "      MLRF_SDR_USB: " + json.dumps(selection["sdr"]["usb"]),
                "      MLRF_SDR_IDENTITY: " + json.dumps(selection["sdr"]["identity"]),
            ]
        if service == "scan" and "sdr" in selection:
            lines += [
                "    volumes:",
                "      - ./models:/app/models:ro",
                "      - ./tls/cert.pem:/app/tls/cert.pem:ro",
                "    environment:",
                "      MLRF_CA_CERT: /app/tls/cert.pem",
            ]
        if service == "wifi-scan" and "wifi" in selection:
            lines += [
                "    volumes:",
                "      - ./tls/cert.pem:/app/tls/cert.pem:ro",
                "    environment:",
                "      MLRF_CA_CERT: /app/tls/cert.pem",
                "      MLRF_WIFI_IFACE: " + json.dumps(selection["wifi"]["interface"]),
            ]
            if not legacy and "identity" in selection["wifi"]:
                # Lets the worker refuse a different adapter on the same name.
                lines.append(
                    "      MLRF_WIFI_IDENTITY: "
                    + json.dumps(selection["wifi"]["identity"])
                )
    return "\n".join(lines) + "\n"


def selection_version(selection):
    return 2 if "identity" in selection.get("wifi", {}) else 1


def validate_selection(selection):
    if not isinstance(selection, dict) or not set(selection) <= set(SCANNERS):
        raise SetupError("Invalid saved scanner selection; the file is preserved.")
    for kind, item in selection.items():
        if not isinstance(item, dict):
            raise SetupError("Invalid saved scanner identity.")
        if kind == "sdr":
            if (
                set(item) != {"usb", "identity", "device", "gid"}
                or not isinstance(item["usb"], str)
                or not USB_NAME.fullmatch(item["usb"])
                or not isinstance(item["identity"], str)
                or not re.fullmatch("[a-f0-9]{64}", item["identity"])
                or not isinstance(item["device"], str)
                or not re.fullmatch(r"/dev/bus/usb/[0-9]{3}/[0-9]{3}", item["device"])
                or type(item["gid"]) is not int
                or not 0 <= item["gid"] <= 2**32 - 2
            ):
                raise SetupError("Invalid saved SDR identity.")
        elif (
            set(item) not in ({"interface", "phy"}, {"interface", "phy", "identity"})
            or not isinstance(item["interface"], str)
            or not NAME.fullmatch(item["interface"])
            or not isinstance(item["phy"], str)
            or not re.fullmatch(r"phy[0-9]+", item["phy"])
            or "identity" in item
            and (
                not isinstance(item["identity"], str)
                or not re.fullmatch(r"[a-f0-9]{64}", item["identity"])
            )
        ):
            raise SetupError("Invalid saved Wi-Fi identity.")
    return selection


def saved_selection(root):
    overlay = saved_overlay(root)
    return None if overlay is None else overlay[0]


def saved_overlay(root):
    """Return (selection, current) for a managed overlay, or None if absent.

    current is False for an exact overlay of the older format, which the next
    publication upgrades. Anything else, including an older-format text with a
    current version number, is still an operator edit.
    """
    path = root / STATE
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise SetupError(
            "Scanner overlay must be a regular managed file; existing paths are preserved."
        )
    try:
        text = path.read_text()
        metadata = json.loads(
            text.splitlines()[1].removeprefix("x-sigrift-scanner-setup: ")
        )
        if set(metadata) != {"version", "selection"}:
            raise ValueError
        selection = validate_selection(metadata["selection"])
        version = metadata["version"]
        if type(version) is not int:
            raise ValueError
        if version == selection_version(selection) + OVERLAY_FORMAT:
            current = True
        elif version == selection_version(selection):
            current = False
        else:
            raise ValueError
        if text != render_format(selection, legacy=not current):
            raise ValueError
    except (OSError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise SetupError(
            "Scanner overlay was edited or is invalid; preserve it and reconcile it before retrying."
        ) from exc
    return selection, current


def pending_text(selection):
    return (
        json.dumps(
            {
                "version": selection_version(selection),
                "stage": "pending",
                "selection": selection,
            },
            sort_keys=True,
        )
        + "\n"
    )


def pending_selection(root):
    path = root / PENDING
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise SetupError(
            "Pending scanner intent must be a regular managed file; existing paths are preserved."
        )
    try:
        text = path.read_text()
        record = json.loads(text)
        if (
            set(record) != {"version", "stage", "selection"}
            or type(record["version"]) is not int
            or record["stage"] != "pending"
        ):
            raise ValueError
        selection = validate_selection(record["selection"])
        if record["version"] != selection_version(selection):
            raise ValueError
        if text != pending_text(selection):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SetupError(
            "Pending scanner intent was edited or is invalid; preserve it and reconcile it before retrying."
        ) from exc
    return selection


def remember(root, selection):
    """Persist intent before fallible model work, without changing active workers."""
    validate_selection(selection)
    saved_selection(root)
    previous = pending_selection(root)
    compose_inputs(root)
    if selection:
        current = selection_from(
            managed_discovery(root), ",".join(sorted(selection)), selection
        )
        if current != selection:
            raise SetupError(
                "Device metadata changed before saving intent; retry discovery."
            )
    verify_ownership(root, selection)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".sigrift-scanners-pending-", suffix=".json", dir=root
    )
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(pending_text(selection))
        if pending_selection(root) != previous:
            raise SetupError(
                "Pending scanner intent changed during setup; retry without overwriting it."
            )
        os.replace(temporary, root / PENDING)
    finally:
        Path(temporary).unlink(missing_ok=True)


def compose_override_capability():
    """Probe the installed parser with stdin only; never create/pull a service."""
    document = (
        "services:\n"
        "  probe:\n"
        "    image: scratch\n"
        "    profiles: !override [scanner-capability]\n"
    )
    try:
        output = run(
            [
                "docker",
                "compose",
                "--env-file",
                "/dev/null",
                "-p",
                "sigrift-scanner-capability",
                "-f",
                "-",
                "--profile",
                "scanner-capability",
                "config",
                "--format",
                "json",
            ],
            input=document,
        )
        config = json.loads(output)
        if config["services"]["probe"]["profiles"] != ["scanner-capability"]:
            raise ValueError
    except (SetupError, ValueError, KeyError, TypeError) as exc:
        raise SetupError(
            "Managed scanners require Docker Compose 2.24.4+ with working !override support. "
            "Upgrade the Compose plugin, or use --dashboard-only for a fresh hardware-free install. "
            "The read-only capability check changed no setup files."
        ) from exc


def compose_inputs(root):
    compose_override_capability()
    for name in (
        "compose.yml",
        "compose.yaml",
        "docker-compose.yaml",
        "compose.override.yml",
        "compose.override.yaml",
        "docker-compose.override.yaml",
    ):
        if (root / name).exists() or (root / name).is_symlink():
            raise SetupError(
                "Scanner setup requires the standard docker-compose.yml/override.yml filenames; custom files are preserved."
            )
    for name in ("docker-compose.yml", "docker-compose.override.yml"):
        path = root / name
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise SetupError(
                "Compose inputs must be regular files; custom paths are preserved."
            )
    output = run(["docker", "compose", "config", "--environment"])
    effective = dict(line.partition("=")[::2] for line in output.splitlines())
    if effective.get("COMPOSE_FILE") or effective.get("COMPOSE_PROFILES"):
        raise SetupError(
            "Unset COMPOSE_FILE and COMPOSE_PROFILES in the shell and .env before managed scanner setup; no files were changed."
        )
    config = json_command(
        ["docker", "compose", "--profile", "hardware", "config", "--format", "json"]
    )
    for service in CORE:
        if set(config["services"][service].get("depends_on", {})) - set(CORE):
            raise SetupError(
                "A custom core service depends on a scanner; reconcile that dependency before managed setup."
            )


def services(selection):
    return [service for kind in sorted(selection) for service in SCANNERS[kind]]


# Deliberately do not capture .Config.Env: it contains credentials. Only the
# scanner interface assignment is emitted, never API keys or other variables.
OWNER_FORMAT = (
    '{"id":{{json .Id}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"devices":{{json .HostConfig.Devices}},"rules":{{json .HostConfig.DeviceCgroupRules}},'
    '"privileged":{{json .HostConfig.Privileged}},"network":{{json .HostConfig.NetworkMode}},'
    '"caps":{{json .HostConfig.CapAdd}},"wifi":[{{range .Config.Env}}'
    '{{if eq (index (split . "=") 0) "MLRF_WIFI_IFACE"}}{{json .}}{{end}}{{end}}]}'
)


def verify_ownership(root, selection):
    """Reject other Docker workloads that already expose the selected radio.

    Docker cannot prove absence of arbitrary host processes. This detects the
    concrete multi-project conflict and conservatively rejects broad access.
    """
    if not selection:
        return
    configuration = json_command(["docker", "compose", "config", "--format", "json"])
    project = configuration.get("name")
    if not isinstance(project, str) or not project:
        raise SetupError(
            "Cannot identify the Compose project before checking radio ownership."
        )
    identifiers = run(["docker", "ps", "--quiet", "--no-trunc"]).splitlines()
    if len(identifiers) > 256 or any(
        not re.fullmatch(r"[a-f0-9]{64}", item) for item in identifiers
    ):
        raise SetupError(
            "Cannot bound/validate running-container discovery; refusing radio ownership guesses."
        )
    owners = []
    for offset in range(0, len(identifiers), 64):
        output = run(
            [
                "docker",
                "inspect",
                "--format",
                OWNER_FORMAT,
                *identifiers[offset : offset + 64],
            ]
        )
        try:
            rows = [json.loads(line) for line in output.splitlines()]
            if len(rows) != len(identifiers[offset : offset + 64]):
                raise ValueError
            for expected_id, row in zip(identifiers[offset : offset + 64], rows):
                if (
                    not isinstance(row, dict)
                    or set(row)
                    != {
                        "id",
                        "project",
                        "service",
                        "devices",
                        "rules",
                        "privileged",
                        "network",
                        "caps",
                        "wifi",
                    }
                    or row["id"] != expected_id
                    or type(row["privileged"]) is not bool
                    or not isinstance(row["network"], str)
                    or any(
                        row[key] is not None and not isinstance(row[key], str)
                        for key in ("project", "service")
                    )
                    or any(
                        row[key] is not None
                        and (
                            not isinstance(row[key], list)
                            or not all(isinstance(item, str) for item in row[key])
                        )
                        for key in ("rules", "caps")
                    )
                    or not isinstance(row["wifi"], list)
                    or not all(
                        isinstance(item, str) and item.startswith("MLRF_WIFI_IFACE=")
                        for item in row["wifi"]
                    )
                    or row["devices"] is not None
                    and not isinstance(row["devices"], list)
                ):
                    raise ValueError
                own = row["project"] == project
                devices = row["devices"] or []
                if any(
                    not isinstance(item, dict)
                    or not isinstance(item.get("PathOnHost"), str)
                    or not item["PathOnHost"].startswith("/")
                    for item in devices
                ):
                    raise ValueError
                if "sdr" in selection:
                    path = Path(selection["sdr"]["device"])
                    exposed = row["privileged"] or bool(row.get("rules"))
                    for device in devices:
                        source = Path(device["PathOnHost"])
                        exposed |= path == source or source in path.parents
                    if exposed and own and row.get("service") == "rtl-tcp":
                        owners.append(row)
                    if exposed and not (own and row.get("service") == "rtl-tcp"):
                        raise SetupError(
                            "Selected SDR is exposed to another running container. Stop/reconcile that owner explicitly; setup will not disrupt it."
                        )
                if "wifi" in selection and row.get("network") == "host":
                    caps = row.get("caps") or []
                    interfaces = row.get("wifi")
                    if not isinstance(caps, list) or not isinstance(interfaces, list):
                        raise ValueError
                    radio_capable = (
                        row["privileged"]
                        or bool(
                            set(caps)
                            & {
                                "NET_ADMIN",
                                "NET_RAW",
                                "CAP_NET_ADMIN",
                                "CAP_NET_RAW",
                                "ALL",
                            }
                        )
                        or bool(interfaces)
                    )
                    expected = ["MLRF_WIFI_IFACE=" + selection["wifi"]["interface"]]
                    if radio_capable and not (
                        own
                        and row.get("service") == "wifi-scan"
                        and interfaces == expected
                    ):
                        raise SetupError(
                            "A different or ambiguous host-network container can already control Wi-Fi. Stop/reconcile that owner explicitly; setup will not disrupt it."
                        )
        except (ValueError, KeyError, TypeError) as exc:
            raise SetupError(
                "Container radio ownership data is incomplete; refusing selection."
            ) from exc

    return owners


# This exception is only for an already saved, managed receiver. General
# discovery continues to report usbfs as occupied, just like other drivers.
USB_SYSFS = Path("/sys/bus/usb/devices")
RTL_STATE_FORMAT = (
    '{"id":{{json .Id}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},'
    '"service":{{json (index .Config.Labels "com.docker.compose.service")}},'
    '"running":{{json .State.Running}},"status":{{json .State.Status}},'
    '"health":{{if index .State "Health"}}{{json .State.Health.Status}}{{else}}null{{end}},'
    '"started":{{json .State.StartedAt}},"pid":{{json .State.Pid}},'
    '"restarts":{{json .RestartCount}},"pid_mode":{{json .HostConfig.PidMode}},'
    '"user":{{json .Config.User}},"path":{{json .Path}},"args":{{json .Args}}}'
)
# Runs as the image's default appuser in its private PID namespace. It does not
# open the USB device, read environment variables, or change hardware/processes.
# "legacy" checks the older format, where rtl_tcp itself was PID 1; otherwise
# PID 1 must be the supervisor and the holder its direct rtl_tcp child.
RTL_FD_PROBE = r"""
import os, stat, sys
from pathlib import Path

SUPERVISOR = [b'python3', b'-m', b'sigrift.edge.rtl_tcp_supervisor', b'']

def receiver(device, expected):
    node = device.lstat()
    if not stat.S_ISCHR(node.st_mode) or (os.major(node.st_rdev), os.minor(node.st_rdev)) != expected:
        return None
    return node

def is_rtl_tcp(proc, exact):
    if (proc / 'comm').read_text().strip() != 'rtl_tcp' or os.readlink(proc / 'exe') != '/usr/bin/rtl_tcp':
        return False
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    if exact:
        return argv == [b'rtl_tcp', b'-a', b'0.0.0.0', b'-d', b'0', b'']
    return argv[:3] == [b'rtl_tcp', b'-a', b'0.0.0.0'] and argv[-1] == b''

def holds(proc, node):
    descriptors = list((proc / 'fd').iterdir())
    if len(descriptors) > 4096:
        return False
    for descriptor in descriptors:
        try:
            opened = descriptor.stat()
        except FileNotFoundError:
            continue
        if stat.S_ISCHR(opened.st_mode) and opened.st_rdev == node.st_rdev:
            return True
    return False

def owns_device(proc, device, expected):
    node = receiver(device, expected)
    return node is not None and is_rtl_tcp(proc, True) and holds(proc, node)

def supervised_owns_device(procfs, device, expected):
    node = receiver(device, expected)
    if node is None or (procfs / '1/cmdline').read_bytes().split(b'\0') != SUPERVISOR:
        return False
    entries = [entry for entry in procfs.iterdir() if entry.name.isdecimal() and entry.name != '1']
    if len(entries) > 4096:
        return False
    for proc in entries:
        try:
            status = (proc / 'status').read_text().splitlines()
            if 'PPid:\t1' not in status or not is_rtl_tcp(proc, False):
                continue
            if holds(proc, node):
                return True
        except OSError:
            # Exited or unreadable: it proves nothing either way.
            continue
    return False

if __name__ == '__main__':
    try:
        device, expected = Path(sys.argv[1]), (int(sys.argv[2]), int(sys.argv[3]))
        if sys.argv[4:] == ['legacy']:
            owned = owns_device(Path('/proc/1'), device, expected)
        elif sys.argv[4:] == ['supervised']:
            owned = supervised_owns_device(Path('/proc'), device, expected)
        else:
            owned = False
    except (OSError, ValueError, IndexError):
        owned = False
    print('owned' if owned else 'not-owned')
"""


def usbfs_device_state(selected):
    """Return the exact character-device identity only for usbfs-only claims."""
    interfaces = sorted(USB_SYSFS.glob(selected["usb"] + ":*"))
    drivers = [item / "driver" for item in interfaces]
    claimed = [driver for driver in drivers if driver.is_symlink()]
    expected = USB_SYSFS.parent / "drivers/usbfs"
    if not claimed or any(driver.resolve() != expected.resolve() for driver in claimed):
        return None
    status = Path(selected["device"]).lstat()
    identity = (os.major(status.st_rdev), os.minor(status.st_rdev))
    if (
        not stat.S_ISCHR(status.st_mode)
        or identity[0] != 189
        or read_text(USB_SYSFS / selected["usb"] / "dev")
        != f"{identity[0]}:{identity[1]}"
    ):
        raise SetupError("Managed receiver device identity changed; retry discovery.")
    return identity, status.st_ino


def managed_rtl_devices(root, discovered):
    """Recognize the saved project's live rtl_tcp USB FD, never foreign usbfs.

    This is a point-in-time Docker/process check, not a proof that arbitrary
    host processes cannot also open this device. No host privileges are added.
    """
    overlay = saved_overlay(root)
    saved, current_format = overlay if overlay is not None else ({}, True)
    selected = saved.get("sdr")
    if not selected or len(discovered) != 1:
        return discovered
    candidate = discovered[0]
    # A re-plugged receiver keeps its port and identity but gets a new device
    # number (and maybe group) on the same bus, which the current format maps
    # as a directory. The older format mapped one node, so it must match.
    volatile = ("device", "gid") if current_format else ()
    if (
        set(candidate) != set(selected) | {"reasons"}
        or candidate["reasons"] != ["kernel driver owns this receiver"]
        or any(
            candidate[key] != selected[key] for key in selected if key not in volatile
        )
        or Path(candidate["device"]).parent != Path(selected["device"]).parent
    ):
        return discovered
    current = {key: candidate[key] for key in selected}
    # The running container's shape is checked on its own, whatever format
    # the saved overlay has: an upgrade writes the new overlay while the
    # previous container still holds the receiver, and only the next `up`
    # recreates it. The previous shape still needs its one exact node, which
    # verify_ownership below ties to the receiver's current node.
    shapes = {
        "supervised": (str(Path(selected["device"]).parent), SUPERVISOR),
        "legacy": (selected["device"], LEGACY_RTL),
    }
    try:
        device_state = usbfs_device_state(current)
        if device_state is None:
            return discovered
        owners = verify_ownership(root, {"sdr": current})
        if len(owners) != 1 or owners[0]["privileged"] or owners[0]["rules"]:
            raise ValueError
        owner = owners[0]
        modes = [
            mode
            for mode, (source, _) in shapes.items()
            if owner["devices"]
            == [
                {
                    "PathOnHost": source,
                    "PathInContainer": source,
                    "CgroupPermissions": "rw",
                }
            ]
        ]
        if len(modes) != 1:
            raise ValueError
        mode = modes[0]
        command_line = shapes[mode][1]
        command = ["docker", "inspect", "--format", RTL_STATE_FORMAT, owner["id"]]
        before = json.loads(run(command))
        expected = {
            "id": owner["id"],
            "project": owner["project"],
            "service": "rtl-tcp",
            "running": True,
            "status": "running",
            "health": "healthy",
            "pid_mode": "",
            "user": "appuser",
            "path": command_line[0],
            "args": command_line[1:],
        }
        if (
            set(before) != set(expected) | {"started", "pid", "restarts"}
            or any(
                type(before[key]) is not type(value) or before[key] != value
                for key, value in expected.items()
            )
            or type(before["pid"]) is not int
            or before["pid"] <= 0
            or type(before["restarts"]) is not int
            or before["restarts"] < 0
            or not isinstance(before["started"], str)
            or not before["started"]
        ):
            raise ValueError
        major, minor = device_state[0]
        result = run(
            [
                "docker",
                "exec",
                owner["id"],
                "python3",
                "-c",
                RTL_FD_PROBE,
                current["device"],
                str(major),
                str(minor),
                mode,
            ],
            timeout=5,
        )
        if (
            result != "owned\n"
            or json.loads(run(command)) != before
            or verify_ownership(root, {"sdr": current}) != owners
            or usbfs_device_state(current) != device_state
            or saved_overlay(root) != overlay
        ):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SetupError(
            "Cannot verify the saved rtl-tcp process owns this receiver; preserve the selection and check the scanner service."
        ) from exc
    return [current | {"reasons": []}]


def managed_discovery(root, **options):
    discovered = discover(**options)
    discovered["sdr"] = managed_rtl_devices(root, discovered["sdr"])
    return discovered


def hardware_disabled(root):
    """True when the operator's override leaves only the core services."""
    if not (root / "docker-compose.override.yml").exists():
        return False
    active = set(run(["docker", "compose", "config", "--services"]).splitlines())
    return active == set(CORE)


def host_needs_preparation(discovery, request, wifi_interface, host):
    kinds = ("sdr", "wifi") if request == "auto" else tuple(request.split(","))
    try:
        prep = host_preparation(
            discovery, kinds=kinds, wifi_interface=wifi_interface, **host
        )
    except SetupError:
        return True  # `prepare --print` shows the refusal.
    return bool(prep["steps"])


def plan(root, request, wifi_interface=None, *, honor_profiles=False, host=None):
    previous = saved_selection(root)
    pending = pending_selection(root)
    wanted_previous = pending if pending is not None else previous
    compose_inputs(root)
    if honor_profiles and request == "auto" and hardware_disabled(root):
        print(
            "    Existing hardware-disabled override is preserved; use --scanners=auto explicitly to select devices.",
            file=sys.stderr,
        )
        request = "none"
    retry = request == "saved"
    if retry:
        request = ",".join(sorted(wanted_previous)) if wanted_previous else "none"
    discovery = (
        managed_discovery(root)
        if request != "none"
        else {"sdr": [], "wifi": [], "reasons": []}
    )
    selected = selection_from(
        discovery, request, wanted_previous if retry else None, wifi_interface
    )
    for kind in ("sdr", "wifi"):
        for item in discovery[kind]:
            identity = item.get("usb", item.get("interface"))
            reason = "; ".join(item["reasons"]) or "ready"
            print(f"    {kind} {identity}: {reason}", file=sys.stderr)
            if kind == "sdr" and item["reasons"]:
                print(
                    f"    Review and prepare this receiver only: sudo python3 scripts/scanner_setup.py prepare-rtl --usb={item['usb']}",
                    file=sys.stderr,
                )
            for note in item.get("notes", []):
                print(
                    f"    {kind} {identity} note: "
                    + (NM_NOTE if note == NM_MANAGED else note),
                    file=sys.stderr,
                )
    if request != "none" and host_needs_preparation(
        discovery, request, wifi_interface, host or {}
    ):
        print(
            "    Prepare this host (one command; add --print to review): "
            + prepare_command(request, wifi_interface),
            file=sys.stderr,
        )
    for reason in discovery["reasons"]:
        print("    " + reason, file=sys.stderr)
    print(
        "==> Selected scanners: "
        + (", ".join(sorted(selected)) or "none (dashboard only)"),
        file=sys.stderr,
    )
    if "sdr" in selected:
        print(
            "    SDR requires a readable ONNX model; setup will verify it before starting the worker.",
            file=sys.stderr,
        )
    # Existing running scanners outside the managed selection are never stopped
    # or silently adopted. Ask the operator to reconcile that explicit conflict.
    running = set(
        run(
            ["docker", "compose", "ps", "--services", "--status", "running"]
        ).splitlines()
    )
    old_services = set(services(previous or {}))
    unmanaged = (
        (running & {"rtl-tcp", "scan", "wifi-scan", "bt-scan"})
        - old_services
        - set(services(selected))
    )
    if unmanaged:
        raise SetupError(
            "Unselected, unmanaged scanner services are running. Stop/reconcile those services explicitly before managed setup: "
            + ", ".join(sorted(unmanaged))
        )
    verify_ownership(root, selected)
    return selected


def compose_command(root, overlay):
    args = ["docker", "compose", "-f", str(root / "docker-compose.yml")]
    if (root / "docker-compose.override.yml").exists():
        args += ["-f", str(root / "docker-compose.override.yml")]
    return args + ["-f", str(overlay)]


def install(root, selection):
    validate_selection(selection)
    previous = saved_selection(root)
    pending = pending_selection(root)
    if pending is not None and pending != selection:
        raise SetupError(
            "Pending scanner intent differs from this selection; retry planning before activation."
        )
    compose_inputs(root)
    # Revalidate the same device identities immediately before publication.
    if selection:
        current = selection_from(
            managed_discovery(root), ",".join(sorted(selection)), selection
        )
        if current != selection:
            raise SetupError(
                "Device metadata changed during setup; retry to refresh the selection."
            )
    verify_ownership(root, selection)
    if "sdr" in selection:
        model = root / "models/open-default.onnx"
        if not model.is_file() or model.stat().st_size == 0:
            raise SetupError(
                "SDR model is missing or empty. Add a verified ONNX model to models/ and retry; no scanner was started."
            )
        # The scanner names its detections from this file and refuses to
        # start when the names do not fit the model, so check it here too
        # instead of starting a scanner that can only restart-loop.
        metadata = root / "models/open-default_metadata.json"
        if not metadata.is_file() or metadata.stat().st_size == 0:
            raise SetupError(
                "SDR model metadata (models/open-default_metadata.json) is missing or empty. Add the model's _metadata.json next to it and re-run quickstart; no scanner was started."
            )
    descriptor, temporary = tempfile.mkstemp(
        prefix=".sigrift-scanners-", suffix=".yml", dir=root
    )
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(render(selection))
        # Resolve profiles too: unsupported !override/invalid custom inputs fail
        # before replacing the managed overlay or starting any scanner.
        config = json_command(
            compose_command(root, temporary)
            + ["--profile", "hardware", "config", "--format", "json"]
        )
        baseline = json_command(
            ["docker", "compose", "--profile", "hardware", "config", "--format", "json"]
        )
        for service in CORE:
            if config["services"][service] != baseline["services"][service]:
                raise SetupError(
                    "Scanner overlay unexpectedly changes a core service; refusing publication."
                )
        if (
            "sdr" in selection
            and config["services"]["scan"]["environment"].get("MLRF_MODEL_PATH")
            != "/app/models/open-default.onnx"
        ):
            raise SetupError(
                "Managed SDR requires MLRF_MODEL_PATH=/app/models/open-default.onnx; custom model configuration is preserved."
            )
        if "wifi" in selection:
            gateway_ports = config["services"]["gateway"].get("ports", [])
            # Host-network worker uses only the existing loopback publication.
            ports = [
                item
                for item in gateway_ports
                if item.get("target") == 8444
                and item.get("host_ip", "0.0.0.0") in {"0.0.0.0", "127.0.0.1"}
            ]
            if len(ports) != 1 or not str(ports[0].get("published", "")).isdecimal():
                raise SetupError(
                    "Wi-Fi needs the gateway's existing IPv4 loopback/wildcard publication; setup never changes exposure."
                )
            expected = "https://127.0.0.1:" + str(ports[0]["published"])
            if (
                config["services"]["wifi-scan"]["environment"].get("MLRF_BRIDGE_URL")
                != expected
            ):
                raise SetupError(
                    "Wi-Fi bridge URL does not match the gateway publication; reconcile the custom configuration first."
                )
        # Detect operator edits between validation and replacement.
        if saved_selection(root) != previous:
            raise SetupError(
                "Scanner selection changed during setup; retry without overwriting it."
            )
        if pending_selection(root) != pending:
            raise SetupError(
                "Pending scanner intent changed before activation; retry without overwriting it."
            )
        removed = sorted(set(services(previous or {})) - set(services(selection)))
        if removed:
            run(compose_command(root, root / STATE) + ["stop", *removed], timeout=45)
        os.replace(temporary, root / STATE)
        # A failed unlink is an explicit retryable error. The next run sees the
        # same active+pending intent; it never falls back to different devices.
        if pending is not None:
            if pending_selection(root) != pending:
                raise SetupError(
                    "Selection activated but pending intent changed; reconcile it before retrying."
                )
            (root / PENDING).unlink()
    finally:
        Path(temporary).unlink(missing_ok=True)


STABLE = {"sdr": ("usb", "identity"), "wifi": ("interface", "identity")}


def check(root):
    overlay = saved_overlay(root)
    if overlay is None:
        raise SetupError("No managed scanner selection exists; run quickstart first.")
    selection, current_format = overlay
    if selection:
        current = selection_from(
            managed_discovery(root), ",".join(sorted(selection)), selection
        )
        if set(current) != set(selection) or any(
            current[kind].get(key) != selection[kind].get(key)
            for kind in selection
            for key in STABLE[kind]
        ):
            raise SetupError(
                "Selected hardware changed before startup; run ordinary quickstart to refresh it."
            )
        # Same port/interface and identity: only kernel-assigned details
        # (device node, group, phy) differ after a re-plug, or the overlay is
        # the older format. Republish through the guarded install path.
        if current != selection or not current_format:
            print(
                "==> Saved scanner hardware is the same; refreshing its device details in the managed overlay.",
                file=sys.stderr,
            )
            install(root, current)
            selection = current
    compose_inputs(root)
    verify_ownership(root, selection)
    return selection


def service_states(command):
    """{service: compose ps row} for the project's containers."""
    output = run(command + ["ps", "--format", "json"])
    try:
        rows = (
            json.loads(output)
            if output.lstrip().startswith("[")
            else [json.loads(line) for line in output.splitlines()]
        )
        return {row["Service"]: row for row in rows}
    except (ValueError, KeyError, TypeError) as exc:
        raise SetupError(
            "Cannot verify selected scanner containers; inspect their logs and retry."
        ) from exc


def stale_scanners(command, chosen):
    """Selected scanner containers that are running but unhealthy.

    check() has just confirmed on the host that the selected devices are
    usable. Docker copies device nodes into a container when it starts, so a
    container started before the host was prepared (prepare or prepare-rtl
    changed the receiver's owner and mode, measured on a Pi) keeps the old,
    unusable node and its health check fails until it is recreated."""
    try:
        states = service_states(command)
    except SetupError:
        return []
    return [
        name
        for name in chosen
        if states.get(name, {}).get("State") == "running"
        and states[name].get("Health") == "unhealthy"
    ]


def start(root, *, recreate=False):
    selection = check(root)
    if not selection:
        return
    command = compose_command(root, root / STATE)
    chosen = services(selection)
    # Core services already built the shared edge image; this does not build,
    # pull, alter host drivers, or recreate gateway/bridge dependencies.
    options = ["--force-recreate"] if recreate else []
    stale = [] if recreate else stale_scanners(command, chosen)
    if stale:
        print(
            "==> Recreating " + ", ".join(stale) + " so it sees the host's current "
            "device permissions (it started before the host was prepared)."
        )
        run(
            command
            + ["up", "-d", "--no-build", "--no-deps", "--force-recreate", *stale],
            timeout=90,
        )
    run(
        command + ["up", "-d", "--no-build", "--no-deps", *options, *chosen], timeout=90
    )
    deadline = time.monotonic() + 30
    while True:
        states = service_states(command)
        if any(
            states.get(name, {}).get("State") in {"exited", "dead", "restarting"}
            for name in chosen
        ):
            raise SetupError(
                "A selected scanner failed to stay running; inspect its logs and retry. Dashboard/data are preserved."
            )
        if all(
            states.get(name, {}).get("State") == "running"
            and states[name].get("Health", "") not in {"starting", "unhealthy"}
            for name in chosen
        ):
            print(
                "==> Selected scanner processes started. Live scanner tabs appear only after capture is reported."
            )
            return
        if time.monotonic() >= deadline:
            raise SetupError(
                "Selected scanner startup did not complete within 30 seconds; inspect its logs and retry."
            )
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "plan",
            "remember",
            "install",
            "start",
            "check",
            "prepare-rtl",
            "prepare",
            "unprepare",
        ),
    )
    # plan defaults to the saved choice; prepare to everything discovered.
    parser.add_argument("--scanners")
    parser.add_argument("--wifi-interface")
    parser.add_argument("--usb")
    parser.add_argument("--recreate", action="store_true")
    parser.add_argument("--honor-profiles", action="store_true")
    parser.add_argument("--print-udev-rule", action="store_true")
    parser.add_argument("--print", dest="print_only", action="store_true")
    parser.add_argument("--check", action="store_true")
    # SSH client address for prepare under sudo (which drops SSH_CONNECTION).
    parser.add_argument("--ssh-client")
    args = parser.parse_args()
    root = Path.cwd()

    def interrupted(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.print_udev_rule and args.action != "prepare-rtl":
            raise SetupError("--print-udev-rule works only with prepare-rtl.")
        if args.print_only and args.action not in ("prepare", "unprepare"):
            raise SetupError("--print works only with prepare and unprepare.")
        if args.check and args.action != "prepare":
            raise SetupError("--check works only with prepare.")
        if args.print_only and args.check:
            raise SetupError("Choose one of --print or --check.")
        if args.ssh_client is not None and args.action != "prepare":
            raise SetupError("--ssh-client works only with prepare.")
        if args.ssh_client is not None:
            try:
                ipaddress.ip_address(args.ssh_client)
            except ValueError as exc:
                raise SetupError("--ssh-client must be one IP address.") from exc
        if args.print_udev_rule:
            print(udev_rule(args.usb))
        elif args.action == "prepare":
            if args.wifi_interface and not NAME.fullmatch(args.wifi_interface):
                raise SetupError("Invalid Wi-Fi interface name.")
            if args.usb and not USB_NAME.fullmatch(args.usb):
                raise SetupError(
                    "Select one discovered USB topology name with --usb (for example 1-2)."
                )
            prepare(
                root,
                scanners=args.scanners,
                usb=args.usb,
                wifi_interface=args.wifi_interface,
                mode="print" if args.print_only else "check" if args.check else "apply",
                honor_profiles=args.honor_profiles,
                ssh_client=args.ssh_client,
            )
        elif args.action == "unprepare":
            unprepare(mode="print" if args.print_only else "apply")
        elif args.action == "plan":
            if args.wifi_interface and not NAME.fullmatch(args.wifi_interface):
                raise SetupError("Invalid Wi-Fi interface name.")
            print(
                json.dumps(
                    plan(
                        root,
                        args.scanners or "saved",
                        args.wifi_interface,
                        honor_profiles=args.honor_profiles,
                    ),
                    sort_keys=True,
                )
            )
        elif args.action == "remember":
            remember(root, json.load(sys.stdin))
        elif args.action == "install":
            install(root, json.load(sys.stdin))
        elif args.action == "prepare-rtl":
            prepare_rtl(args.usb)
        elif args.action == "check":
            check(root)
        else:
            start(root, recreate=args.recreate)
    except (SetupError, OSError, ValueError, KeyError, TypeError) as exc:
        if isinstance(exc, SetupError):
            print("Error: " + str(exc), file=sys.stderr)
        else:
            print(
                "Error: scanner configuration could not be validated; existing files are preserved where possible.",
                file=sys.stderr,
            )
        return 1
    except KeyboardInterrupt:
        print("Scanner setup cancelled; existing data is preserved.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
