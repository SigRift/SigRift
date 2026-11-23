# Sensor lifecycle

Scanners run unattended. Receivers get unplugged, re-plugged, swapped and
renumbered by the kernel. Every scanner kind (SDR, Wi-Fi, Bluetooth, and
agents such as Zigbee or ADS-B) handles this the same way. This page is the
contract for anyone adding a sensor.

## The five rules

1. **Absent sensor.** At start or while running, the scanner does not
   crash-loop and does not hang silently. It closes stale handles (sockets,
   subprocesses, file descriptors). It logs one line per state change, not one
   per retry. It keeps reporting status. It re-checks every few seconds.
2. **Same sensor returns.** Capture resumes without operator action, even when
   the kernel gave it new numbers (USB device number, ifindex, phy number,
   hciN). Identity is never a kernel-assigned number.
3. **Different sensor in its place.** When an identity is configured, the
   scanner refuses it, logs that once, and reports `sensor_changed`. An
   operator re-runs setup to select it. Without a configured identity (legacy
   installs), whatever is present is used. Bluetooth is the exception: it is
   not part of setup, a swap is noticed only when the adapter is configured by
   address, and the fix is to set `MLRF_BT_ADAPTER` to the adapter wanted and
   restart the Bluetooth scanner. Agents such as Zigbee or ADS-B select their
   sensor in their own configuration.
4. **Clean stop.** SIGTERM leads to exit code 0 in every sensor state.
5. **Status.** Reports carry a fixed state and, with `error` only, a fixed
   reason. Nothing else about the sensor is sent.

## Status states and reasons

States stay `running`, `stopped` and `error`. The optional `reason` field is
sent only with `error` and is one of:

| reason           | meaning                                             |
|------------------|-----------------------------------------------------|
| `starting`       | started, not capturing yet                          |
| `sensor_absent`  | the selected sensor is not there                    |
| `sensor_changed` | a different sensor is where the selected one was    |
| `sensor_unusable`| the selected sensor is there, but the host does not let the scanner open it (device node permissions, or a kernel driver holds it) |
| `capture_failed` | the sensor is there, but capture does not work for any other reason |

The list is closed: the scanner side (`sigrift.edge.scanner_status`) and the
bridge refuse any other value. The rtl-tcp supervisor's state port (TCP 1235)
answers `running`, `stopped`, `starting` or one of the reasons above; the `scan` service
passes `sensor_absent`, `sensor_changed` and `sensor_unusable` on, and reports
any other answer, or none, as `capture_failed`.

Never send or log serial numbers, MAC or Bluetooth addresses, SSIDs or raw
error text to the bridge. Local logs may name an interface or a USB port, but
not a serial or an address.

## Identity

| sensor          | identity                                                 |
|-----------------|----------------------------------------------------------|
| USB (SDR, ADS-B)| sha256 of `vendor:product:serial`, plus the USB port     |
| USB serial      | the same USB hash, found through the tty's USB parent    |
| Wi-Fi           | permanent address (wiphy `macaddress`) plus USB topology |
| Bluetooth       | adapter address (`MLRF_BT_ADAPTER=00:1A:...`), or `hciN` |

`scripts/scanner_setup.py` computes the USB and Wi-Fi identities at setup.
`sigrift.edge.sensor_presence` computes the same values at run time; tests
compare the two. A Bluetooth `hciN` name is a kernel number, kept for existing
installs; prefer the address.

## Mapping a device into a container

Do not map a single device node such as `/dev/bus/usb/001/004` or
`/dev/ttyUSB0`. After a re-plug that node is gone, and Docker refuses to start
the container again ("error gathering device information ... no such file or
directory").

- USB devices: map the bus directory (`/dev/bus/usb/001`). Docker re-reads a
  directory on restart. Then read the current node from
  `find_usb_sensor(...).detail["node"]`.
- When the scanner sees the sensor back but its new node is not in the
  container, exit with code 75. The service restarts and Docker reads the
  nodes again.
- When the node is in the container but the host does not let the scanner
  open it, a restart does not help. Report `sensor_unusable`, log once what to
  run on the host, and keep re-checking; capture starts by itself once the
  node can be opened. This is what a re-plugged RTL-SDR looks like on a host
  without a persistent udev rule: its node comes back as `root:root` mode
  `0664` with the `dvb_usb_rtl28xxu` TV driver bound, because
  `scanner_setup.py prepare-rtl` is deliberately temporary. `scanner_setup.py
  prepare` (which quickstart offers to run) also installs the receiver's rule
  as `/etc/udev/rules.d/70-sigrift-sdr.rules`; with it, a re-plugged receiver
  comes back as `root:plugdev` mode `0660` by itself.
- USB serial dongles: select by `/dev/serial/by-id/...`, never by
  `ttyUSBn`. Give the container the tty major numbers with
  `device_cgroup_rules` (`c 188:* rmw` for ttyUSB, `c 166:* rmw` for ttyACM)
  and bind-mount `/dev` so new nodes appear. This setup has not yet been
  checked on hardware.

## Worked example: a Zigbee dongle

```python
import logging, signal, threading
from sigrift.edge import sensor_presence as sp
from sigrift.edge.scanner_status import ScannerStatusReporter

log = logging.getLogger("zigbee")
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
tracker = sp.PresenceTracker("zigbee", log)
reason = [sp.STARTING]

def capture_state():
    return "running" if reason[0] is None else ("error", reason[0])

def on_change(new_reason):
    # None means "present": still not running until the radio is open.
    if new_reason is not None:
        reason[0] = new_reason

reporter = ScannerStatusReporter(url, node_id, "zigbee", tls, auth, capture_state)
reporter.start()
probe = lambda: sp.find_serial_sensor(DONGLE_PATH, DONGLE_IDENTITY)
while not stop.is_set():
    found = sp.wait_until_present(probe, stop, tracker, on_change=on_change)
    if found is None:
        break  # SIGTERM while waiting
    try:
        # detail["tty"] is the bare name, such as "ttyUSB0".
        with open_radio("/dev/" + found.detail["tty"]) as radio:  # your code
            reason[0] = None  # running only now that the radio is open
            while not stop.is_set() and probe().state == "present":
                read_frames(radio, timeout=1.0)
    except PermissionError:
        reason[0] = sp.SENSOR_UNUSABLE  # the host must prepare the node
        stop.wait(5)
    except OSError:
        reason[0] = sp.CAPTURE_FAILED  # local log may name the port only
        stop.wait(5)
reporter.stop()
raise SystemExit(0)
```

The capture loop re-checks presence, so a lost dongle ends capture, closes the
handle and goes back to waiting, where the tracker notices the change and
reports `sensor_absent`. `tracker.update` logs once per change.

## Notes on the built-in scanners

- **SDR.** The receiver container sees the receiver's whole USB bus
  directory, so a re-plugged receiver is found again after one automatic
  restart. If the host then does not let it open the receiver, the rtl-tcp
  supervisor reports `sensor_unusable`, logs the `scanner_setup.py
  prepare-rtl` command for that USB port once, and starts `rtl_tcp` by itself
  when the node can be opened. `scanner_setup.py prepare` makes the
  preparation persistent by installing the receiver's udev rule; QUICKSTART
  ("Preparing the host") says what it changes and how to undo it. That check looks at the device node's permissions only.
  Setup refuses a receiver whose node belongs to group root, or to a group
  that another device on the same bus shares, because the container could
  then open those devices too. Two receivers on one bus whose serials
  `rtl_tcp` cannot tell apart are refused and reported as `capture_failed`;
  if `rtl_tcp` is ever found holding another receiver, it is stopped and
  reported as `sensor_changed`. Without a configured receiver (legacy
  installs) the supervisor runs `rtl_tcp -d 0` and exits with code 75 when
  a receiver it had mapped is lost, so the service restart brings it back;
  a receiver that was never mapped into the container is ignored.
- **Wi-Fi.** An adapter that returns under a different interface name is
  reported as `sensor_absent` until setup is run again, because setup pins
  the name to protect the management interface. The scanner exits with an
  error when `ip`, `iw` or `tcpdump` is missing; waiting cannot fix that.
- **Bluetooth.** An adapter that is present but down is reported as
  `capture_failed` and waited for; the scanner never brings it up. A swap
  is noticed only when the adapter is configured by address
  (`MLRF_BT_ADAPTER`), and is fixed by changing that setting and restarting
  the Bluetooth scanner, not by setup.
