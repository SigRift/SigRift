"""The archive passphrase at a terminal (phase2-spec 2.4; crypto review
checklist item 5; 14.3 #35): lc_state_tool's Tty and pp_read under a pty.

The state tool's heredoc is loaded as a module (lifecycle_fakes'
load_state_tool) before each pty.fork, so the child runs the real reader on
the pty as its controlling terminal. Each test drives the prompts from the
parent side and reads what the terminal showed: echo stays off after a stop
(Ctrl-Z) and resume, and the prompt starts over; SIGQUIT puts echo back;
the generated passphrase's lines are erased by the rows they took at the
terminal's width; a terminal on fd 4 without a controlling terminal is
M-AR-PASSPHRASE-NEEDED, not an OSError. No sleeps: every wait is a select
on the pty with an overall deadline.
"""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "tests"))

from lifecycle_fakes import load_state_tool  # noqa: E402

pytestmark = [pytest.mark.timeout(60),
              pytest.mark.skipif(not hasattr(os, "fork"), reason="needs a pty")]
TOOL = load_state_tool()
SECRET = b"typed-secret-passphrase"


class Pty:
    """The parent side of pty.fork(): wait for text, write, signal."""

    def __init__(self, child, cols=80):
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            code = 0
            try:
                fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, cols, 0, 0))
                child()
            except BaseException as e:  # noqa: BLE001 - reported to the parent
                os.write(1, ("CHILD-ERROR %r\n" % (e,)).encode())
                code = 3
            os._exit(code)
        self.out = b""
        self.status = None

    def pump(self, until=None, deadline=20.0):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            if until is not None and until(self.out):
                return True
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                self.out += chunk
            if self.status is None:
                done, st = os.waitpid(self.pid, os.WNOHANG | os.WUNTRACED)
                if done and os.WIFSTOPPED(st):
                    os.kill(self.pid, signal.SIGCONT)  # fg
                elif done:
                    self.status = st
        return until is None or until(self.out)

    def wait_for(self, text, count=1):
        assert self.pump(lambda o: o.count(text) >= count), self.out
        return self.out

    def send(self, data):
        os.write(self.fd, data)

    def finish(self):
        self.pump(lambda o: self.status is not None)
        if self.status is None:
            os.kill(self.pid, signal.SIGKILL)
            _, self.status = os.waitpid(self.pid, 0)
        os.close(self.fd)
        return self.out


def echo_on(fd):
    return bool(termios.tcgetattr(fd)[3] & termios.ECHO)


def say(text):
    """The child's output, on the pty itself (pytest's capture replaced
    sys.stdout before the fork)."""
    os.write(1, (text + "\n").encode())


def test_a_stop_and_resume_keeps_echo_off_and_asks_again():
    """Ctrl-Z at the prompt, then fg: echo is turned off again before the
    next byte is read, the handler is back and the prompt starts over; the
    passphrase typed afterwards never appears on the terminal."""
    def child():
        t = TOOL.Tty()
        line = t.ask("P1: ")
        say("READ=%s ECHO=%d HANDLER=%d" % (line.decode(), echo_on(t.fd),
                                           signal.getsignal(signal.SIGTSTP) == t.on_signal))
        t.close()
    p = Pty(child)
    p.wait_for(b"P1: ")
    os.kill(p.pid, signal.SIGTSTP)
    p.wait_for(b"P1: ", 2)  # asked again after the resume
    p.send(SECRET + b"\n")
    out = p.finish()
    assert b"READ=%s ECHO=0 HANDLER=1" % SECRET in out, out
    assert out.count(SECRET) == 1, out  # only in READ=, never echoed
    assert os.waitstatus_to_exitcode(p.status) == 0


def test_sigquit_at_the_prompt_turns_echo_back_on():
    """Ctrl-\\ ends the reader with the terminal as it was (2.4: echo
    restored on every exit path); RLIMIT_CORE 0 keeps the default action
    from writing a core."""
    def child():
        gc = os.fork()
        if gc == 0:
            TOOL.ar_setrlimit()
            t = TOOL.Tty()
            t.ask("Q: ")
            os._exit(0)
        say("GC=%d" % gc)
        _, st = os.waitpid(gc, 0)
        say("ECHO-AFTER=%d SIGNALED=%d" % (echo_on(0), os.WIFSIGNALED(st)))
    p = Pty(child)
    out = p.wait_for(b"Q: ")
    gc = int(re.search(rb"GC=(\d+)", out).group(1))
    os.kill(gc, signal.SIGQUIT)
    out = p.finish()
    assert b"ECHO-AFTER=1 SIGNALED=1" in out, out


@pytest.mark.parametrize("cols,rows", [(80, 4), (200, 3)])
def test_the_generated_passphrase_is_erased_by_the_rows_it_took(cols, rows):
    """Enter at the export prompt generates one; its three lines take four
    rows on an 80-column terminal (the middle one is 91 characters) and are
    erased by exactly that many; typed back, it is the passphrase."""
    def child():
        got = TOOL.pp_read(0, True, {"project": "lab", "hostname": "h"})
        say("GOT=%s" % got.decode())
    p = Pty(child, cols=cols)
    p.wait_for(b"Enter generates one): ")
    p.send(b"\n")
    out = p.wait_for(b"Press Enter to continue.")
    gen = re.search(rb"Your archive passphrase: ([a-z2-7-]{29})", out).group(1)
    p.send(b"\n")
    out = p.wait_for(b"Type it back: ")
    assert b"\r\x1b[%dA\x1b[J" % rows in out, out
    p.send(gen.upper().replace(b"-", b" ") + b"\n")  # rule 4: capitals and spaces too
    out = p.finish()
    assert b"GOT=" + gen in out, out


@pytest.mark.parametrize("lines,cols,rows", [
    (["x" * 54, "x" * 91, "x" * 24], 80, 4), (["x" * 80], 80, 1), (["x" * 81], 80, 2),
    ([""], 80, 1), (["x" * 54, "x" * 91, "x" * 24], 0, 4)])
def test_pp_rows(lines, cols, rows):
    assert TOOL.pp_rows(lines, cols) == rows


def test_a_terminal_without_a_controlling_terminal_is_passphrase_needed():
    """fd 4 a terminal, /dev/tty unopenable (no controlling terminal): the
    refusal of 2.4, never an OSError the hook reduces to its type name."""
    master, slave = os.openpty()
    code = r"""
import sys
sys.path.insert(0, %r)
from lifecycle_fakes import load_state_tool
t = load_state_tool()
fd = int(sys.argv[1])
assert t.os.isatty(fd)
try:
    t.pp_read(fd, False, {"file": "x.sigrift-archive"})
except t.PassRefused as e:
    print("REFUSED", e.code, e.why)
    try:
        t.pp_refuse(e, {}, False)
    except SystemExit as x:
        print("EXIT", x.code)
""" % str(Path(__file__).resolve().parents[2] / "scripts" / "tests")
    try:
        r = subprocess.run([sys.executable, "-I", "-c", code, str(slave)], pass_fds=(slave,),
                           capture_output=True, text=True, timeout=30, start_new_session=True)
    finally:
        os.close(slave)
        os.close(master)
    assert "REFUSED NEEDED notty" in r.stdout and "EXIT 3" in r.stdout, (r.stdout, r.stderr)
    assert "this process has no controlling terminal (/dev/tty) to ask on" in r.stderr
    assert r.stderr.rstrip().endswith("Nothing was changed.")
