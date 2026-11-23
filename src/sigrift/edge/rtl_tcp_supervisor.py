"""Run rtl_tcp on the selected receiver and recover it after a re-plug.

Entry point of the rtl-tcp service (docs/sensor-lifecycle.md). Managed
installs set MLRF_SDR_USB (USB port, e.g. "3-1") and MLRF_SDR_IDENTITY (the
setup hash); rtl_tcp then only runs on that receiver. Without them (legacy)
it runs ``rtl_tcp -d 0`` as before.

The service maps the receiver's USB bus directory, which Docker reads when the
container starts. A receiver that comes back with a new device number has a
node this container cannot see, so the supervisor exits with 75 and Docker's
restart maps the directory again.

A one-line state ("running", "starting", "sensor_absent", "sensor_changed",
"sensor_unusable", "capture_failed") is served on MLRF_RTL_STATUS_PORT
(default 1235) for the scan service, and written to a state file for
``--check`` (the healthcheck). Serials are never logged: librtlsdr's own "SN:"
output is redacted.
"""

from __future__ import annotations

import logging
import os
import re
import select
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from sigrift.edge import sensor_presence as sp

logger = logging.getLogger("rtl_tcp_supervisor")

RESTART_EXIT = 75  # EX_TEMPFAIL: restart me so Docker re-reads the device nodes
POLL_SECONDS = 2.0
DEFAULT_STATUS_PORT = 1235
STATE_FILE = Path("/tmp/sigrift-rtl-tcp.state")
RTL_TCP = ("rtl_tcp", "-a", "0.0.0.0")
RUNNING = "running"
STOPPED = "stopped"

# Same IDs as scripts/scanner_setup.py RTL_IDS: librtlsdr counts these when it
# numbers devices, so they decide whether index 0 is unambiguous.
_RTL_IDS = frozenset({("0bda", "2832"), ("0bda", "2838")})
_USB_PORT = re.compile(r"[0-9]+-[0-9]+(?:\.[0-9]+)*\Z")
_USB_NODE = re.compile(r"/dev/bus/usb/([0-9]{3})/([0-9]{3})\Z")
_IDENTITY = re.compile(r"[0-9a-fA-F]{64}\Z")
# librtlsdr's -d parser tries strtol(s, 0) as a device index before matching
# serials, so a serial such as "00000001" would select device 1.
_INDEX_LIKE = re.compile(r"\s*[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)\Z")
# libusb -4 is LIBUSB_ERROR_NO_DEVICE; rtl_tcp prints it endlessly once the
# receiver is gone ("rtlsdr_demod_read_reg failed with -4").
_NO_DEVICE = re.compile(r"failed with -4\b|LIBUSB_ERROR_NO_DEVICE")
_NO_DEVICE_BURST = 5
_NO_DEVICE_WINDOW = 2.0
_SERIAL_TEXT = re.compile(r"(SN:\s*).+")
_REPEAT_WINDOW = 60.0
_RESTART_DELAY_MAX = 30.0
_STABLE_RUN = 60.0
_STOP_GRACE = 3.0


def check(state_file: Path = STATE_FILE) -> int:
    """Healthcheck: 0 only while rtl_tcp runs on the selected receiver."""
    try:
        return 0 if state_file.read_text(encoding="ascii").strip() == RUNNING else 1
    except (OSError, UnicodeError):
        return 1


class _StateBoard:
    """The current state, for the TCP service and the --check state file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._value = sp.STARTING
        self._write_failed = False

    @property
    def value(self) -> str:
        return self._value

    def set(self, value: str, *, force: bool = False) -> None:
        if value == self._value and not force:
            return
        self._value = value
        try:
            # Atomic replace: --check never reads a half-written file.
            with tempfile.NamedTemporaryFile(
                "w", dir=self._path.parent, prefix=".rtl-state-", delete=False
            ) as tmp:
                tmp.write(value + "\n")
            os.replace(tmp.name, self._path)
        except OSError:
            if not self._write_failed:
                logger.warning("Cannot write the rtl_tcp state file")
            self._write_failed = True


class _StateServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _serve_state(board: _StateBoard, port: int) -> _StateServer | None:
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                self.request.sendall((board.value + "\n").encode("ascii"))
            except OSError:
                pass

    try:
        server = _StateServer(("0.0.0.0", port), Handler)
    except OSError:
        logger.warning("State service cannot listen on port %d", port)
        return None
    threading.Thread(target=server.serve_forever, name="rtl-state", daemon=True).start()
    return server


class _OutputFilter:
    """Pass rtl_tcp output to the log without floods, serials or -4 storms."""

    def __init__(self, clock=time.monotonic) -> None:
        self._clock = clock
        self._seen: dict[str, float] = {}
        self._suppressed = 0
        self._summary_at = clock()
        self._no_device: list[float] = []
        self.secrets: frozenset[str] = frozenset()

    def new_process(self, secrets: frozenset[str]) -> None:
        self.secrets = secrets
        self._no_device = []

    def _redact(self, text: str) -> str:
        text = _SERIAL_TEXT.sub(r"\1<hidden>", text)
        for secret in self.secrets:
            text = text.replace(secret, "<hidden>")
        return text

    def feed(self, line: str) -> bool:
        """Log one output line; True once it completes a no-device burst."""
        text = self._redact(line.strip())
        if not text:
            return False
        now = self._clock()
        lost = False
        if _NO_DEVICE.search(text):
            self._no_device = [
                t for t in self._no_device if now - t <= _NO_DEVICE_WINDOW
            ] + [now]
            lost = len(self._no_device) >= _NO_DEVICE_BURST
        last = self._seen.get(text)
        self._seen = {
            seen: at for seen, at in self._seen.items() if now - at < _REPEAT_WINDOW
        }
        self._seen[text] = now
        if last is not None and now - last < _REPEAT_WINDOW:
            self._suppressed += 1
            if now - self._summary_at >= _REPEAT_WINDOW:
                self.flush()
        else:
            logger.info("rtl_tcp: %s", text)
        return lost

    def flush(self) -> None:
        if self._suppressed:
            logger.info("rtl_tcp: %d repeated lines not shown", self._suppressed)
        self._suppressed = 0
        self._summary_at = self._clock()


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def _usb_entries(sysfs: Path) -> list[dict] | None:
    """USB devices with readable numbers; None when sysfs cannot be listed."""
    found = []
    try:
        entries = sorted(sysfs.iterdir())
    except OSError:
        return None
    for entry in entries:
        if not _USB_PORT.fullmatch(entry.name):
            continue
        try:
            item = {
                "port": entry.name,
                "busnum": int(_read_text(entry / "busnum")),
                "devnum": int(_read_text(entry / "devnum")),
                "ids": (
                    _read_text(entry / "idVendor"),
                    _read_text(entry / "idProduct"),
                ),
                "serial": (
                    _read_text(entry / "serial") if (entry / "serial").exists() else ""
                ),
            }
        except (OSError, UnicodeError, ValueError):
            continue
        found.append(item)
    return found


def _node(busnum: int, devnum: int) -> str:
    return f"/dev/bus/usb/{busnum:03d}/{devnum:03d}"


def _opened_usb_node(pid: int, proc: Path) -> tuple[int, int] | None:
    """The (bus, device) number of the USB node a process holds open."""
    try:
        descriptors = list((proc / str(pid) / "fd").iterdir())
    except OSError:
        return None
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        if match := _USB_NODE.fullmatch(target):
            return int(match[1]), int(match[2])
    return None


class Supervisor:
    def __init__(
        self,
        usb_port: str | None,
        identity: str | None,
        *,
        command: tuple[str, ...] | list[str] = RTL_TCP,
        sysfs: Path = Path("/sys/bus/usb/devices"),
        proc: Path = Path("/proc"),
        dev_root: Path = Path("/"),
        state_file: Path = STATE_FILE,
        status_port: int = DEFAULT_STATUS_PORT,
        poll: float = POLL_SECONDS,
    ) -> None:
        self._port = usb_port
        self._identity = identity.lower() if identity else None
        # An identity without a port, or a malformed one, cannot select a
        # receiver; using whatever is present would break the swap rule.
        self._invalid = (
            identity is not None
            and (usb_port is None or not _IDENTITY.fullmatch(identity))
        ) or (usb_port is not None and not _USB_PORT.fullmatch(usb_port))
        self._command = list(command)
        self._sysfs = sysfs
        self._proc = proc
        self._dev_root = dev_root
        self._status_port = status_port
        self._poll = poll
        self._board = _StateBoard(state_file)
        self._tracker = sp.PresenceTracker("SDR", logger)
        self._filter = _OutputFilter()
        # A signal handler only sets this flag and writes to the pipe: a
        # threading.Event takes a lock the main thread may hold in wait().
        self._stopping = False
        self._wake_read, self._wake_write = os.pipe()
        os.set_blocking(self._wake_read, False)
        os.set_blocking(self._wake_write, False)
        self._child: subprocess.Popen | None = None
        self._exit_code: int | None = None
        self._ran = 0.0
        self._watched: tuple[int, int] | None = None
        self._mismatch = 0
        self._server: _StateServer | None = None
        # Legacy: USB port -> (bus, device) number of the receivers this
        # container could open, and the ports mapped before an earlier restart.
        self._ports_file = state_file.with_name(state_file.name + ".ports")
        self._mapped: dict[str, tuple[int, int]] = {}
        self._remembered: set[str] = set()
        self._ignored: set[str] = set()

    @property
    def managed(self) -> bool:
        return self._port is not None

    def request_stop(self) -> None:
        """Safe from a signal handler: sets a flag and writes a byte, no locks."""
        self._stopping = True
        self._notify()

    def _notify(self) -> None:
        try:
            os.write(self._wake_write, b"\0")
        except OSError:
            pass  # pipe full: a wake-up is already pending

    def _sleep(self, seconds: float) -> None:
        """Wait up to ``seconds``; ends early on _notify(). Call _drain first."""
        select.select([self._wake_read], [], [], max(seconds, 0.0))

    def _drain(self) -> None:
        try:
            while os.read(self._wake_read, 512):
                pass
        except OSError:
            pass  # empty

    def run(self) -> int:
        # Rewrite the state file: one left from before a restart may say running.
        self._board.set(sp.STARTING, force=True)
        if not self.managed:
            self._note_mapped()
        server = self._server = _serve_state(self._board, self._status_port)
        try:
            result = self._loop()
        finally:
            self._stop_child()
            if server is not None:
                server.shutdown()
                server.server_close()
            self._filter.flush()
            self._board.set(STOPPED)
        if self._stopping:
            logger.info("Stopped")
            return 0
        return result

    def _wait(self, seconds: float) -> None:
        self._drain()
        if not self._stopping:
            self._sleep(seconds)

    def _loop(self) -> int:
        delay = 0.0
        refused = invalid_logged = unusable_logged = wrong_logged = False
        while not self._stopping:
            if self._invalid:
                if not invalid_logged:
                    logger.error("SDR selection is invalid; re-run scanner setup")
                    invalid_logged = True
                # No other receiver took its place: the setting itself is wrong.
                self._board.set(sp.CAPTURE_FAILED)
                self._wait(self._poll)
                continue
            presence = None
            selector = "0"
            if self.managed:
                presence = sp.find_usb_sensor(
                    self._port, self._identity, sysfs=self._sysfs
                )
                self._tracker.update(presence)
                if presence.state != "present":
                    refused = unusable_logged = wrong_logged = False
                    delay = 0.0
                    self._board.set(self._tracker.reason)
                    self._wait(self._poll)
                    continue
                if not self._visible(presence.detail["node"]):
                    logger.warning(
                        "SDR on USB port %s has a device node this container "
                        "cannot see; exiting so the service restarts and maps it",
                        self._port,
                    )
                    return RESTART_EXIT
                if not self._usable(presence.detail["node"]):
                    # rtl_tcp would only fail and be restarted; waiting for the
                    # host to fix the node is quieter and starts by itself.
                    if not unusable_logged:
                        logger.error(
                            "SDR on USB port %s is connected, but this container "
                            "is not allowed to open it (device permissions, or a "
                            "kernel driver holds it); on the host run: sudo "
                            "python3 scripts/scanner_setup.py prepare-rtl --usb=%s "
                            "(QUICKSTART explains how to make this persistent)",
                            self._port,
                            self._port,
                        )
                        unusable_logged = True
                    self._board.set(sp.SENSOR_UNUSABLE)
                    self._wait(self._poll)
                    continue
                if unusable_logged:
                    logger.info("SDR on USB port %s can be opened now", self._port)
                    unusable_logged = False
                selector = self._selector(presence)
                if selector is None:
                    if not refused:
                        logger.error(
                            "Several SDRs are connected whose serials rtl_tcp "
                            "cannot tell them apart (the same, or one starts or "
                            "ends with the other); unplug the others or give "
                            "the selected one a unique serial, then re-run setup"
                        )
                        refused = True
                    # No different receiver took its place: the selected one
                    # is there but cannot be addressed.
                    self._board.set(sp.CAPTURE_FAILED)
                    self._wait(self._poll)
                    continue
                refused = False
            elif self._legacy_remap_needed():
                logger.warning(
                    "An SDR this container used is gone, renumbered or has a "
                    "device node this container cannot see; exiting so the "
                    "service restarts and maps it"
                )
                return RESTART_EXIT
            outcome = self._run_once(selector, presence)
            if outcome == "stop":
                break
            if outcome == "lost" and not self.managed:
                logger.warning(
                    "Exiting so the service restarts and maps the USB devices again"
                )
                return RESTART_EXIT
            if outcome == "changed":
                if not wrong_logged:
                    logger.warning(
                        "rtl_tcp opened a different SDR than the one at USB port "
                        "%s; stopped it, retrying with a growing delay",
                        self._port,
                    )
                    wrong_logged = True
            else:
                wrong_logged = False
            # Retry with a growing delay, so a receiver that keeps failing
            # neither spins nor floods the log. Presence is re-checked first.
            first = delay == 0.0 or self._ran >= _STABLE_RUN
            delay = 1.0 if first else min(delay * 2, _RESTART_DELAY_MAX)
            if outcome == "exited" and first:
                logger.warning(
                    "rtl_tcp exited (code %s); restarting it, waiting up to %.0f s "
                    "between attempts",
                    self._exit_code,
                    _RESTART_DELAY_MAX,
                )
            self._board.set(sp.SENSOR_CHANGED if outcome == "changed" else sp.STARTING)
            self._wait(delay)
        return 0

    def _path(self, node: str) -> Path:
        return self._dev_root / node.lstrip("/")

    def _visible(self, node: str) -> bool:
        return self._path(node).exists()

    def _usable(self, node: str) -> bool:
        # After a re-plug without a persistent udev rule the node is
        # root:root 0664 again (scanner_setup prepare-rtl is temporary).
        return os.access(self._path(node), os.R_OK | os.W_OK)

    def _note_mapped(self) -> None:
        """Legacy, at start: remember the receivers this container can open."""
        devices = _usb_entries(self._sysfs) or []
        self._mapped = {
            d["port"]: (d["busnum"], d["devnum"])
            for d in devices
            if d["ids"] in _RTL_IDS and self._visible(_node(d["busnum"], d["devnum"]))
        }
        try:
            lines = self._ports_file.read_text(encoding="ascii").split()
        except (OSError, UnicodeError):
            lines = []
        self._remembered = {p for p in lines if _USB_PORT.fullmatch(p)}
        self._remember(self._mapped)

    def _remember(self, ports) -> None:
        """Keep mapped ports across a restart (/tmp survives one)."""
        if set(ports) <= self._remembered:
            return
        self._remembered |= set(ports)
        try:
            self._ports_file.write_text(
                "".join(f"{port}\n" for port in sorted(self._remembered)),
                encoding="ascii",
            )
        except OSError:
            pass  # only a re-plug during an outage then needs a manual restart

    def _legacy_remap_needed(self) -> bool:
        """Legacy: a receiver this container used is gone, renumbered or unmapped.

        Only receivers mapped at start, held by rtl_tcp, or mapped before an
        earlier restart count. One that was never mapped (an override may map
        a single receiver) is logged once and ignored: restarting cannot map it.
        """
        devices = _usb_entries(self._sysfs)
        if devices is None:
            return False  # sysfs unreadable: no evidence
        current = {d["port"]: (d["busnum"], d["devnum"]) for d in devices}
        if any(current.get(port) != numbers for port, numbers in self._mapped.items()):
            return True
        for d in devices:
            port = d["port"]
            if (
                d["ids"] not in _RTL_IDS
                or port in self._mapped
                or self._visible(_node(d["busnum"], d["devnum"]))
            ):
                continue
            if port in self._remembered:
                return True  # back after a restart, on a node not mapped yet
            if port not in self._ignored:
                logger.warning(
                    "An SDR on USB port %s has no device node in this container; "
                    "ignoring it (map its USB bus to use it)",
                    port,
                )
                self._ignored.add(port)
        return False

    def _selector(self, presence: sp.Presence) -> str | None:
        """rtl_tcp's -d value for this receiver, or None if ambiguous."""
        devices = _usb_entries(self._sysfs) or []
        own = next((d for d in devices if d["port"] == self._port), None)
        if own is None:
            return None
        rtl = [d for d in devices if d["ids"] in _RTL_IDS | {own["ids"]}]
        serial = presence.detail["serial"]

        def confusable(other: str) -> bool:
            # rtl_tcp matches -d exactly, then as a prefix, then as a suffix
            # of a serial; the other way round is refused too, to be safe.
            return (
                other.startswith(serial)
                or other.endswith(serial)
                or bool(other)
                and (serial.startswith(other) or serial.endswith(other))
            )

        if (
            serial
            and not _INDEX_LIKE.fullmatch(serial)
            and not any(
                d["port"] != self._port
                and d["busnum"] == own["busnum"]
                and confusable(d["serial"])
                for d in rtl
            )
        ):
            return serial
        # librtlsdr numbers every receiver libusb lists, on any bus.
        if all(d["port"] == self._port for d in rtl):
            return "0"
        return None

    def _secrets(self) -> frozenset[str]:
        # Short serials would redact ordinary words; "SN:" covers librtlsdr.
        return frozenset(
            d["serial"]
            for d in _usb_entries(self._sysfs) or ()
            if len(d["serial"]) >= 4
        )

    def _still_there(self, presence: sp.Presence | None, pid: int) -> bool:
        if presence is not None:
            now = sp.find_usb_sensor(self._port, self._identity, sysfs=self._sysfs)
            return now.state == "present" and all(
                now.detail[key] == presence.detail[key] for key in ("busnum", "devnum")
            )
        # Legacy: no port is configured; watch the node rtl_tcp opened.
        if self._watched is None:
            self._watched = _opened_usb_node(pid, self._proc)
        if self._watched is None:
            return True
        devices = _usb_entries(self._sysfs)
        if devices is None:
            return True  # sysfs unreadable: no evidence of loss
        held = [
            d["port"] for d in devices if (d["busnum"], d["devnum"]) == self._watched
        ]
        if held and held[0] not in self._mapped:
            # Held by rtl_tcp: its loss or renumbering also needs a restart.
            self._mapped[held[0]] = self._watched
            self._remember(self._mapped)
        return bool(held)

    def _opened_selected(self, presence: sp.Presence, pid: int) -> bool:
        """False once rtl_tcp holds the USB node of a receiver not selected.

        rtl_tcp falls back from an exact serial match to a prefix or suffix
        match, so it can open another receiver when the selected one fails.
        """
        held = _opened_usb_node(pid, self._proc)
        if held is None or held == (
            presence.detail["busnum"],
            presence.detail["devnum"],
        ):
            self._mismatch = 0
            return True
        # librtlsdr briefly opens each receiver to read its serial: only a
        # node still held at the next check counts.
        self._mismatch += 1
        return self._mismatch < 2

    def _read_output(self, stream, lost: threading.Event) -> None:
        try:
            for line in stream:
                if self._filter.feed(line):
                    lost.set()
                    self._notify()
        except (OSError, ValueError):
            pass
        finally:
            self._notify()

    def _run_once(self, selector: str, presence: sp.Presence | None) -> str:
        """Run rtl_tcp until it stops; "stop", "lost", "changed" or "exited"."""
        self._filter.new_process(self._secrets())
        self._watched = None
        self._mismatch = 0
        self._ran = 0.0
        try:
            child = subprocess.Popen(
                [*self._command, "-d", selector],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            self._exit_code = None
            logger.error("Cannot start rtl_tcp: %s", exc.strerror or type(exc).__name__)
            return "exited"
        self._child = child
        started = time.monotonic()
        lost = threading.Event()
        reader = threading.Thread(
            target=self._read_output, args=(child.stdout, lost), daemon=True
        )
        reader.start()
        self._board.set(RUNNING)
        logger.info(
            "rtl_tcp started%s",
            f" on the SDR at USB port {self._port}" if self.managed else "",
        )
        try:
            while True:
                self._drain()
                if self._stopping:
                    return "stop"
                if lost.is_set():
                    logger.warning("rtl_tcp lost the SDR (USB no-device errors)")
                    return "lost"
                code = child.poll()
                if code is not None:
                    self._exit_code = code
                    reader.join(timeout=1)
                    return "exited"
                if not self._still_there(presence, child.pid):
                    logger.warning("SDR disconnected or renumbered; rtl_tcp stopped")
                    return "lost"
                if presence is not None and not self._opened_selected(
                    presence, child.pid
                ):
                    return "changed"
                self._sleep(self._poll)
        finally:
            self._ran = time.monotonic() - started
            self._stop_child()
            reader.join(timeout=2)
            if not reader.is_alive():
                # A reader still blocked on the pipe holds its lock.
                child.stdout.close()
            self._board.set(sp.STARTING)

    def _stop_child(self) -> None:
        child, self._child = self._child, None
        if child is None or child.poll() is not None:
            return
        child.terminate()
        try:
            child.wait(_STOP_GRACE)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def _status_port() -> int:
    raw = os.environ.get("MLRF_RTL_STATUS_PORT", "").strip()
    if not raw:
        return DEFAULT_STATUS_PORT
    if raw.isdecimal() and 0 <= int(raw) <= 65535:
        return int(raw)
    logger.error("MLRF_RTL_STATUS_PORT is invalid; using %d", DEFAULT_STATUS_PORT)
    return DEFAULT_STATUS_PORT


def main(argv: list[str] | None = None, **overrides) -> int:
    """``overrides`` are Supervisor keyword arguments, for tests."""
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--check"]:
        return check(overrides.get("state_file", STATE_FILE))
    if argv:
        print(
            "usage: python3 -m sigrift.edge.rtl_tcp_supervisor [--check]",
            file=sys.stderr,
        )
        return 2
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )
    usb_port = os.environ.get("MLRF_SDR_USB", "").strip() or None
    identity = os.environ.get("MLRF_SDR_IDENTITY", "").strip() or None
    supervisor = Supervisor(
        usb_port, identity, **{"status_port": _status_port(), **overrides}
    )
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: supervisor.request_stop())
    return supervisor.run()


if __name__ == "__main__":
    sys.exit(main())
